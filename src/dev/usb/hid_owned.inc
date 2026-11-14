; D3 class-owned orderly reconnect. Included only by dev/usb/hid. BSP resident
; context, like its existing binder; no IRQ/AP entry and no new power operation.
; Snapshot96: serial64,hc64,gen32,root32,topo16,descriptorSHA25632,traffic64,
; kind32,flags32,ordinal32,reserved32. Flags1known2consumed4retired8active16traffic.
; Hold112: original snapshot96,phase32 (1prepared/2spent),lab reject32,reserved8.
; Lab reject: 0unarmed/1armed/2actually consumed after all restore guards.
%ifndef PAOS_LAB_D8_HID_REJECT
%define PAOS_LAB_D8_HID_REJECT 0
%endif

; RDI exact state -> RAX sidecar, ECX ordinal0..3, or RAX0.
usb_hid_owned_record_ptr:
    lea rax,[rel usb_hid_states]
    mov rcx,rdi
    sub rcx,rax
    jc .none
    cmp rcx,USB_HID_MAX_STATES * usb_hid_state_size
    jae .none
    mov rax,rcx
    xor edx,edx
    mov ecx,usb_hid_state_size
    div rcx
    test edx,edx
    jnz .none
    mov ecx,eax
    imul rax,96
    lea rdx,[rel usb_hid_owned_records]
    add rax,rdx
    ret
.none:
    xor eax,eax
    ret

; RBX=actually queued successful state. Capture only real inventory binder
; provenance; direct configure/KAT calls cannot mint an incarnation.
usb_hid_owned_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rbx
    mov rdi,rbx
    call usb_hid_owned_record_ptr
    test rax,rax
    jz .out
    mov r13,rax
    mov r14d,ecx
    mov rdi,rax
    mov ecx,12
    xor eax,eax
    rep stosq
    cmp dword [rel usb_hid_obs_test_depth],0
    jne .out
    cmp byte [rel usb_hid_census_pending],1
    jne .out
    cmp byte [r12+usb_hid_state.kind],1
    jb .out
    cmp byte [r12+usb_hid_state.kind],2
    ja .out                         ; unsupported report-kind stays unknown
    mov r15d,[rel usb_hid_owned_enum_index]
    mov edi,r15d
    call usb_dev_hc
    cmp rax,[r12+usb_hid_state.hc]
    jne .out
    mov edi,r15d
    call usb_dev_addr
    cmp al,[r12+usb_hid_state.port]
    jne .out
    mov edi,r15d
    call usb_dev_topo_ptr
    test rax,rax
    jz .out
    mov rdx,[rax]
    mov [r13+24],rdx
    mov rdx,[rax+8]
    mov [r13+32],rdx
    mov edi,r15d
    call usb_dev_desc_ptr
    test rax,rax
    jz .out
    cmp word [rax],0x0112
    jne .out
    lea rdi,[r13+40]
    mov rsi,rax
    mov edx,18
    call sha256_hash
    test rax,rax
    jnz .out
    mov rax,[rel usb_hid_owned_serial]
    cmp rax,-1
    je .out                          ; exhaustion never breaks normal class bind
    inc rax
    mov [rel usb_hid_owned_serial],rax
    mov [r13],rax
    mov rax,[r12+usb_hid_state.hc]
    mov [r13+8],rax
    mov eax,[r12+usb_hid_state.generation]
    mov [r13+16],eax
    movzx eax,byte [r12+usb_hid_state.port]
    mov [r13+20],eax
    movzx eax,byte [r12+usb_hid_state.kind]
    mov [r13+80],eax
    mov dword [r13+84],9
    lea eax,[r14d+1]
    mov [r13+88],eax
    lea rdx,[rel usb_hid_owned_indices]
    mov [rdx+r14*4],r15d
    lea rdx,[rel usb_hid_owned_eligible]
    mov byte [rdx+r14],0
    cmp byte [rel usb_hid_config+4],1
    jne .out
    mov byte [rdx+r14],1             ; no composite sibling can lose its endpoint
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Accepted native completion only: exact real-poll bracket, no KAT or private
; direct submission. Never export reports or count a refusal/ZLP/ring pressure.
usb_hid_owned_traffic:
    cmp dword [rel usb_hid_obs_test_depth],0
    jne .out
    cmp [rel usb_hid_obs_live_state],rdi
    jne .out
    cmp byte [rdi+usb_hid_state.active],1
    jne .out
    sub rsp,8
    call usb_hid_owned_record_ptr
    add rsp,8
    test rax,rax
    jz .out
    cmp qword [rax],0
    je .out
    test dword [rax+84],2
    jnz .out
    cmp qword [rax+72],-1
    je .out
    inc qword [rax+72]
.out:
    ret

; EDI ordinal1..4, RSI out96 -> EAX0/-1. Cached data/getters only. Unknown
; output is zeroed; stale records remain identifiable without an active claim.
usb_hid_owned_snapshot:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edi
    test r12,r12
    jz .fail
    mov rdi,r12
    xor eax,eax
    mov ecx,12
    rep stosq
    dec r13d
    cmp r13d,USB_HID_MAX_STATES
    jae .fail
    imul eax,r13d,96
    lea rbx,[rel usb_hid_owned_records]
    add rbx,rax
    cmp qword [rbx],0
    je .fail
    mov rsi,rbx
    mov rdi,r12
    mov ecx,12
    rep movsq
    and dword [r12+84],~24          ; readonly projection, never mutate retained state
    imul eax,r13d,usb_hid_state_size
    lea rdx,[rel usb_hid_states]
    add rdx,rax
    cmp byte [rdx+usb_hid_state.active],1
    jne .copy
    mov rax,[rdx+usb_hid_state.hc]
    cmp rax,[rbx+8]
    jne .copy
    mov eax,[rdx+usb_hid_state.generation]
    cmp eax,[rbx+16]
    jne .copy
    mov rdi,[rbx+8]
    call xhci_hc_generation
    cmp eax,[rbx+16]
    jne .copy
    or dword [r12+84],8
    cmp qword [rbx+72],0
    je .copy
    or dword [r12+84],16
.copy:
    xor eax,eax
    jmp .out
.fail:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; EDI ordinal1..4, RSI retained serial64, RDX out96 ->0/-1. All cached joins
; precede consumption. After consumption even pending release denies reoffer.
usb_hid_owned_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi
    mov r13,rsi
    mov r14,rdx
    mov rsi,rdx
    call usb_hid_owned_snapshot
    test eax,eax
    jnz .fail
    dec r12d
    imul eax,r12d,96
    lea rbx,[rel usb_hid_owned_records]
    add rbx,rax
    cmp [rbx],r13
    jne .fail
    test r13,r13
    jz .fail
    mov eax,[r14+84]
    and eax,11
    cmp eax,9
    jne .fail
    lea rdx,[rel usb_hid_owned_eligible]
    cmp byte [rdx+r12],1
    jne .fail
    cmp byte [rbx+24+usb_topo.depth],0
    jne .fail
    cmp dword [rbx+24+usb_topo.parent_slot],0
    jne .fail
    cmp dword [rbx+24+usb_topo.route],0
    jne .fail
    cmp word [rbx+24+usb_topo.hub_ports],0
    jne .fail
    lea rdx,[rel usb_hid_owned_indices]
    mov edi,[rdx+r12*4]
    call usb_dev_hc
    cmp rax,[rbx+8]
    jne .fail
    lea rdx,[rel usb_hid_owned_indices]
    mov edi,[rdx+r12*4]
    call usb_dev_topo_ptr
    test rax,rax
    jz .fail
    mov rdx,[rax]
    cmp rdx,[rbx+24]
    jne .fail
    mov rdx,[rax+8]
    cmp rdx,[rbx+32]
    jne .fail
    ; Exactly this class on this root. No collateral retirement of another
    ; active interface or pending release (other controllers/ports continue).
    imul eax,r12d,usb_hid_state_size
    lea r15,[rel usb_hid_states]
    add r15,rax
    lea rdx,[rel usb_hid_states]
    mov ecx,USB_HID_MAX_STATES
.peer:
    cmp rdx,r15
    je .next
    cmp byte [rdx+usb_hid_state.active],0
    je .next
    mov rax,[rdx+usb_hid_state.hc]
    cmp rax,[rbx+8]
    jne .next
    movzx eax,byte [rdx+usb_hid_state.port]
    cmp eax,[rbx+20]
    je .fail
.next:
    add rdx,usb_hid_state_size
    loop .peer
    imul eax,r12d,112
    lea rdx,[rel usb_hid_owned_holds]
    cmp dword [rdx+rax+96],0
    jne .fail                        ; slot reuse cannot erase an uncertain root hold
    or dword [rbx+84],2             ; consume before any class quiescence
    imul eax,r12d,112
    lea r13,[rel usb_hid_owned_holds]
    add r13,rax
    mov rsi,rbx
    mov rdi,r13
    mov ecx,12
    rep movsq
    mov qword [r13+96],2            ; failed/pending prepare has no reprobe grant
    mov qword [r13+104],0
    mov rdi,r15
    call usb_hid_release_state      ; original whole-release custody, no HC I/O
    or dword [rbx+84],4
    and dword [rbx+84],~24
    mov rsi,rbx
    mov rdi,r14
    mov ecx,12
    rep movsq
    cmp byte [r15+usb_hid_state.active],0
    jne .fail
    mov dword [r13+96],1
    xor eax,eax
    jmp .out
.fail:
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI HC, ESI root -> EAX1 while exact consumed root is held. No I/O. A real
; controller generation change makes an obsolete hold irrelevant, never reuses
; an old serial. Ordinary reset does not clear serials or uncertain holds.
usb_hid_owned_block_root:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r12,rdi
    mov r13d,esi
    lea rbx,[rel usb_hid_owned_holds]
    mov r14d,USB_HID_MAX_STATES
.next:
    cmp dword [rbx+96],0
    je .advance
    cmp [rbx+8],r12
    jne .advance
    cmp [rbx+20],r13d
    jne .advance
    mov rdi,r12
    call xhci_hc_generation
    cmp eax,[rbx+16]
    je .blocked
    mov dword [rbx+96],0
.advance:
    add rbx,112
    dec r14d
    jnz .next
    xor eax,eax
    jmp .out
.blocked:
    mov eax,1
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; EDI original enum index. Gate binder before config I/O. Only a single exact
; reprobe's synchronous original binder may bypass the selected root hold.
usb_hid_owned_block_index:
    push rbx
    push r12
    sub rsp,8
    mov ebx,edi
    call usb_dev_hc
    mov r12,rax
    mov edi,ebx
    call usb_dev_addr
    mov esi,eax
    mov rdi,r12
    cmp [rel usb_hid_owned_allow_hc],r12
    jne .guard
    cmp [rel usb_hid_owned_allow_root],esi
    je .allowed
.guard:
    call usb_hid_owned_block_root
    test eax,eax
    jnz .out
.allowed:
    mov [rel usb_hid_owned_enum_index],ebx
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; EDI ordinal1..4, RSI original serial, EDX HC generation -> EAX0/-1.
; Internal BSP coordinator only, after actual prepare and power restoration.
; Arm exactly once for this retained hold. No I/O, reset, release or new serial.
usb_hid_owned_reject_arm:
%if PAOS_LAB_D8_HID_REJECT
    push rbx
    push r12
    sub rsp,8
    mov r12d,edx
    dec edi
    cmp edi,USB_HID_MAX_STATES
    jae .bad
    test rsi,rsi
    jz .bad
    imul eax,edi,112
    lea rbx,[rel usb_hid_owned_holds]
    add rbx,rax
    cmp dword [rbx+96],1
    jne .bad
    cmp [rbx],rsi
    jne .bad
    cmp [rbx+16],r12d
    jne .bad
    cmp dword [rbx+100],0
    jne .bad
    mov rdi,[rbx+8]
    test rdi,rdi
    jz .bad
    call xhci_hc_generation
    cmp eax,r12d
    jne .bad
    mov dword [rbx+100],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret
%else
    mov eax,-1
    ret
%endif

; Same exact original binding, readonly. 0unarmed/1armed/2consumed; -1 invalid
; or default-off. Reports historical consumption even when HC is now replaced;
; caller still binds the original request/receipt/generation, never a new grant.
usb_hid_owned_reject_status:
%if PAOS_LAB_D8_HID_REJECT
    dec edi
    cmp edi,USB_HID_MAX_STATES
    jae .bad
    test rsi,rsi
    jz .bad
    imul eax,edi,112
    lea rcx,[rel usb_hid_owned_holds]
    add rcx,rax
    cmp [rcx],rsi
    jne .bad
    cmp [rcx+16],edx
    jne .bad
    cmp dword [rcx+96],1
    jb .bad
    cmp dword [rcx+96],2
    ja .bad
    mov eax,[rcx+100]
    ret
.bad:
%endif
    mov eax,-1
    ret

; EDI original ordinal, RSI internal80B power receipt -> RAX fresh serial/0,
; EDX actual new ordinal/0. One offered reprobe, including malformed/uncertain.
usb_hid_owned_reprobe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13,rsi
    dec edi
    cmp edi,USB_HID_MAX_STATES
    jae .fail
    imul eax,edi,112
    lea rbx,[rel usb_hid_owned_holds]
    add rbx,rax
    cmp dword [rbx+96],1
    jne .fail
    mov dword [rbx+96],2            ; consume prior to receipt validation or I/O
    test r13,r13
    jz .fail
    cmp dword [r13],1
    jne .fail
    cmp dword [r13+4],80
    jne .fail
    cmp dword [r13+8],0
    jne .fail
    cmp dword [r13+12],63
    jne .fail
    mov r12,[rbx+8]
    cmp [r13+16],r12
    jne .fail
    mov r14d,[rbx+20]
    cmp [r13+24],r14d
    jne .fail
    mov eax,[rbx+16]
    cmp [r13+28],eax
    jne .fail
    mov rax,[rbx+24]
    cmp [r13+32],rax
    jne .fail
    mov rax,[rbx+32]
    cmp [r13+40],rax
    jne .fail
    cmp dword [r13+72],0
    jne .fail
    cmp dword [r13+76],0
    jne .fail
    mov eax,[r13+48]
    and eax,513
    cmp eax,513
    jne .fail
    test dword [r13+52],513
    jnz .fail
    mov eax,[r13+56]
    and eax,513
    cmp eax,513
    jne .fail
    test dword [r13+60],8
    jz .fail
    cmp dword [r13+64],1
    jb .fail
    cmp dword [r13+64],100
    ja .fail
    cmp dword [r13+68],1
    jb .fail
    cmp dword [r13+68],100
    ja .fail
    mov rdi,r12
    call xhci_hc_generation
    cmp eax,[rbx+16]
    jne .fail
    mov rdi,r12
    mov esi,r14d
    call usb_hid_port_owned
    test eax,eax
    jnz .fail                       ; no live/pending class can be overwritten
%if PAOS_LAB_D8_HID_REJECT
    ; The real prepare/power receipt and all identity/restore guards passed.
    ; A selected one-use rejection is not evidence of a successful refresh.
    cmp dword [rbx+100],1
    jne .normal_refresh
    mov dword [rbx+100],2
    jmp .fail                       ; retain spent phase2 and root containment
.normal_refresh:
%endif
    mov rdi,r12
    mov esi,r14d
    call usb_dev_refresh_root       ; exact original inventory entry, no scan
    test eax,eax
    jz .fail
    mov [rel usb_hid_owned_allow_hc],r12
    mov [rel usb_hid_owned_allow_root],r14d
    lea edi,[eax-1]
    call usb_hid_bind_device         ; actual configuration + endpoint queue
    mov qword [rel usb_hid_owned_allow_hc],0
    mov dword [rel usb_hid_owned_allow_root],0
    lea r13,[rel usb_hid_owned_records]
    lea r15,[rel usb_hid_states]
    xor r14d,r14d
.find:
    cmp byte [r15+usb_hid_state.active],1
    jne .advance
    cmp [r13+8],r12
    jne .advance
    mov eax,[r13+20]
    cmp eax,[rbx+20]
    jne .advance
    mov eax,[r13+16]
    cmp eax,[rbx+16]
    jne .advance
    mov eax,[r13+80]
    cmp eax,[rbx+80]
    jne .advance
    mov rax,[r13]
    cmp rax,[rbx]
    jbe .fail
    mov dword [rbx+96],0            ; only a real fresh bind permits next offer
    lea edx,[r14d+1]
    jmp .out
.advance:
    add r13,96
    add r15,usb_hid_state_size
    inc r14d
    cmp r14d,USB_HID_MAX_STATES
    jb .find
.fail:
    xor eax,eax
    xor edx,edx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
