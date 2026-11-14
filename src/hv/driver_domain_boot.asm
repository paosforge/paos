;; MODULE hv/driver_domain_boot
;; LAYER 5
;; EXPORTS nd_boot_start, nd_boot_record_tick
;; IMPORTS hv/driver_domain, hv/nic_selection, hv/vm_profile, bus/pci, bus/pci_bdf, core/csprng
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Normal verified Manager boots start the full built-in domain once. Hardware
; discovery uses the existing PCI iterator. An ambiguous choice is a failure,
; never evidence that passthrough is absent. The selector and nd_begin retain
; their exact reset/isolation/ownership checks; discovery grants no DMA rights.
nd_boot_start:
    push rbx
    push r12
    push r13
    cmp byte [rel nd_boot_attempted],0
    jne .bad
    mov byte [rel nd_boot_attempted],1
    mov dword [rel nd_boot_error],1
    cmp byte [rel pbm_manager_launch],1
    jne .bad
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .bad
    cmp byte [rel pbm_try_media],0
    jne .bad
    cmp byte [rel boot_hv_foundation_ready],1
    jne .bad
    mov dword [rel nd_boot_error],2
    call nd_clock
    test eax,eax
    jz .bad
    mov r13,[rel nd_clock_ms]
    lea rdi,[rel nd_boot_profile_name]
    call vm_profile_find
    mov dword [rel nd_boot_error],3
    test rax,rax
    jz .bad
    mov r12,rax
    ; The admitted built-in service selects one exact class before discovery.
    ; Full Ethernet stays default; the private-channel shape opts in to Wi-Fi.
    mov edx,0x020000
    cmp dword [r12+VP_DEVICES],0x8007
    je .profile_class
    mov edx,0x028000
    cmp dword [r12+VP_DEVICES],0x18007
    jne .bad
.profile_class:
    mov [rel nd_boot_class],edx
    mov dword [rel nd_boot_count],0
    lea rdi,[rel nd_boot_pci_cb]
    call pci_scan_with_filter
    mov dword [rel nd_boot_error],4
    cmp dword [rel nd_boot_count],1
    jne .bad
    call nd_boot_budget
    test eax,eax
    jz .bad
    mov edi,[rel nd_boot_bdf]
    lea rsi,[rel nd_boot_selection]
    mov edx,592
    call nic_select_snapshot
    mov [rel nd_boot_select_error],eax
    mov dword [rel nd_boot_error],5
    test eax,eax
    jnz .bad
    lea rdi,[rel nd_boot_random]
    mov esi,8
    call csprng_generate
    mov dword [rel nd_boot_error],6
    test eax,eax
    jnz .bad
    cmp qword [rel nd_boot_random],0
    je .bad
    lea rsi,[rel nd_boot_random]
    lea rdi,[rel nd_boot_nonce]
    lea rbx,[rel nd_boot_hex]
    mov ecx,8
.hex:
    lodsb
    movzx eax,al
    movzx edx,al
    shr eax,4
    mov al,[rbx+rax]
    stosb
    and edx,15
    mov al,[rbx+rdx]
    stosb
    loop .hex
    mov byte [rdi],0
    lea rdi,[rel nd_boot_nonce]
    call nd_nonce_valid
    test eax,eax
    jz .bad
    call nd_boot_budget
    test eax,eax
    jz .bad
    mov rdi,r12
    mov esi,[rel nd_boot_bdf]
    lea rdx,[rel nd_boot_nonce]
    call nd_begin
    mov dword [rel nd_boot_error],7
    test eax,eax
    jz .bad
    mov ebx,eax
    call nd_boot_budget
    test eax,eax
    jz .late
    mov eax,ebx
    mov [rel hv_linux_boot_gen],eax
    mov byte [rel hv_linux_boot_queued],1
    mov dword [rel nd_boot_error],0
    jmp .out
.late:
    mov edi,ebx
    lea rsi,[rel nd_boot_nonce]
    call nd_stop                  ; exact original START, never a replacement
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; R13=absolute start of discovery; charge the entire callback chain.
nd_boot_budget:
    sub rsp,8
    call nd_clock
    add rsp,8
    test eax,eax
    jz .bad
    mov rax,[rel nd_clock_ms]
    sub rax,r13
    cmp rax,ND_CALL_MS
    jae .bad
    mov eax,1
    ret
.bad:
    mov dword [rel nd_boot_error],2
    xor eax,eax
    ret

; Existing iterator ABI EDI=bus,ESI=device,EDX=function,ECX=vendor/device.
nd_boot_pci_cb:
    push rbx
    shl edi,8
    shl esi,3
    or edi,esi
    or edi,edx
    mov ebx,edi
    mov esi,8
    call pci_bdf_read
    shr eax,8
    cmp eax,[rel nd_boot_class]
    jne .out
    inc dword [rel nd_boot_count]
    mov [rel nd_boot_bdf],ebx
.out:
    pop rbx
    ret

; Network does not gate public health (spec rev 0.70), so a NIC that cannot
; come up leaves this one record once the domain's own deadline has passed.
; Evidence, never health or policy. A completed scan with no chip writes nothing.
; This is a standing condition and PFRI has one slot: it takes only an empty slot
; or a differing kind 9, so a real failure from the last boot stays readable.
nd_boot_record_tick:
    cmp byte [rel net_required],0
    jne .out
    cmp byte [rel nd_boot_recorded],0
    jne .out
    sub rsp,8
    call boot_ms_now
    add rsp,8
    cmp rax,ND_BOOT_MS
    jb .out
    mov byte [rel nd_boot_recorded],1
    cmp dword [rel nd_operational],1
    je .out
    cmp byte [rel nd_boot_attempted],0
    je .never_offered
    mov edx,[rel nd_boot_error]
    test edx,edx
    jz .no_ready
    cmp edx,4
    jne .refused
    cmp dword [rel nd_boot_count],0
    je .out
.refused:
    mov esi,1
    mov ecx,[rel nd_boot_select_error]
    mov r8d,[rel nd_boot_count]
    jmp .save
.no_ready:
    mov esi,2
    mov edx,[rel nd_state]
    mov ecx,[rel nd_fault]
    mov r8d,[rel nd_bdf]
    jmp .save
.never_offered:
    mov esi,3
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
.save:
    push rsi
    push rdx
    push rcx
    push r8
    call runtime_failure_snapshot
    pop r8
    pop rcx
    pop rdx
    pop rsi
    test eax,eax
    jz .write
    cmp eax,1
    jne .out
    lea r9,[rel runtime_failure_snapshot_bytes]
    cmp word [r9+8],RFR_NIC_BRINGUP
    jne .out
    cmp rsi,[r9+24]
    jne .write
    cmp rdx,[r9+136]
    jne .write
    cmp rcx,[r9+144]
    jne .write
    cmp r8,[r9+152]
    je .out
.write:
    mov edi,RFR_NIC_BRINGUP
    jmp runtime_failure_save
.out:
    ret

nd_boot_profile_name: db 'driver-domain',0
nd_boot_hex: db '0123456789abcdef'
%include "core/abi/wdata.inc"
%macro WDATA_driver_domain_boot 0
align 8
nd_boot_attempted: db 0
nd_boot_recorded: db 0
align 4
nd_boot_error: dd 0
nd_boot_select_error: dd 0
nd_boot_class: dd 0
nd_boot_count: dd 0
nd_boot_bdf: dd 0
align 8
nd_boot_random: dq 0
nd_boot_nonce: times 17 db 0
align 8
nd_boot_selection: times 592 db 0
%endmacro
WDATA_DEFER WDATA_driver_domain_boot
