;; MODULE hv/driver_domain_boot
;; LAYER 5
;; EXPORTS nd_boot_start, nd_boot_record_tick
;; IMPORTS hv/driver_domain, hv/nd_isolation, hv/nic_selection, hv/a1_nic_selection, hv/vm_profile, hv/amdvi, hv/vtd, bus/pci, bus/pci_bdf, bus/pci_claim, core/csprng
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Normal verified Manager boots start the full built-in domain once. Hardware
; discovery uses the existing PCI iterator and tries up to eight unclaimed
; exact-class functions in BDF order. No candidate or overflow is a failure,
; never evidence that passthrough is absent. The selector and nd_begin retain
; their exact reset/isolation/ownership checks; discovery grants no DMA rights.
%include "core/abi/pci_claim.inc"

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
    mov dword [rel nd_boot_mode],0
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    ; Immutable build policy selects the actual observation schema. nd_begin
    ; independently rechecks the signed policy before original START custody.
    mov rax,[rel native_driver_selected_policy]
    cmp rax,1
    jbe .mode_ready
    cmp rax,2
    jne .bad
    mov dword [rel nd_boot_mode],1
.mode_ready:
%endif
    mov dword [rel nd_boot_count],0
    call nd_boot_claim_snapshot
    test eax,eax
    jz .claims_bad
    lea rdi,[rel nd_boot_pci_cb]
    call pci_scan_with_filter
    mov dword [rel nd_boot_error],4
    cmp dword [rel nd_boot_count],0
    je .bad
    cmp dword [rel nd_boot_count],8
    ja .bad
    xor ebx,ebx                     ; sorted candidate ordinal
    mov dword [rel nd_boot_first_error],0
.candidate:
    lea rax,[rel nd_boot_candidates]
    mov eax,[rax+rbx*4]
    mov [rel nd_boot_bdf],eax
    call nd_boot_budget
    test eax,eax
    jz .bad
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    cmp dword [rel nd_boot_mode],1
    jne .legacy_candidate
    ; A1 retains shared host peers. Its pure observation needs no ACS changes
    ; and uses a separate A1NS608 record, never the singleton NICS592 buffer.
    mov rdi,r12
    mov esi,[rel nd_boot_bdf]
    lea rdx,[rel nd_boot_a1_selection]
    mov ecx,608
    call a1_nic_snapshot
    mov [rel nd_boot_select_error],eax
    ; An early policy/firmware refusal may have no fresh ISO facts. Do not
    ; pair it with a previous pcia_iso_record through the legacy NDISO rail.
    jmp .candidate_observed
.legacy_candidate:
%endif
    mov edi,[rel nd_boot_bdf]
    call nd_boot_acs_chain          ; W3: this candidate, before its first group gate
    mov edi,[rel nd_boot_bdf]
    lea rsi,[rel nd_boot_selection]
    mov edx,592
    call nic_select_snapshot
    mov [rel nd_boot_select_error],eax
    ; NDISO1 still captures only original ISO facts, immediately after their
    ; gate. Its write-once record names the first ISO refusal, even if another
    ; NIC later passes. It is never selection or assignment authority.
    mov esi,eax
    mov edi,[rel nd_boot_bdf]
    lea rdx,[rel nd_acs_record]
    call ndiso_capture
.candidate_observed:
    call nd_boot_budget            ; charge every failed and successful gate
    test eax,eax
    jz .bad
    mov eax,[rel nd_boot_select_error]
    mov dword [rel nd_boot_error],5
    test eax,eax
    jnz .candidate_refused
    ; A late FAILED bind is still a claim, never assignment permission.
    lea rdx,[rel nd_boot_selection]
    cmp dword [rel nd_boot_mode],1
    jne .claim_record
    lea rdx,[rel nd_boot_a1_selection]
.claim_record:
    cmp dword [rdx+48],0
    je .selected
    mov eax,14
    mov [rel nd_boot_select_error],eax
.candidate_refused:
    test ebx,ebx
    jnz .next_candidate
    mov [rel nd_boot_first_error],eax
.next_candidate:
    inc ebx
    cmp ebx,[rel nd_boot_count]
    jb .candidate
    mov eax,[rel nd_boot_first_error]
    mov [rel nd_boot_select_error],eax
    mov eax,[rel nd_boot_candidates]
    mov [rel nd_boot_bdf],eax       ; same first BDF as the retained code
    jmp .bad
.selected:
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
.claims_bad:
    mov dword [rel nd_boot_error],5
    mov dword [rel nd_boot_select_error],14
    jmp .bad
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

; Take one complete native-claim census under the recorder's existing lock.
; Reject malformed or incomplete telemetry globally, not merely at a candidate.
; BOUND and FAILED both exclude a function from automatic discovery.
nd_boot_claim_snapshot:
    sub rsp,8
    lea rdi,[rel nd_boot_claims]
    call pci_claim_snapshot
    add rsp,8
    test edx,edx
    jnz .bad
    cmp eax,32
    ja .bad
    mov [rel nd_boot_claim_n],eax
    lea r8,[rel nd_boot_claims]
    xor ecx,ecx
.next:
    cmp ecx,[rel nd_boot_claim_n]
    jae .ok
    mov r9d,[r8]
    cmp r9d,0xffff
    ja .bad
    cmp dword [r8+4],1
    jb .bad
    cmp dword [r8+4],PCI_DRV_LAST
    ja .bad
    mov edx,[r8+8]
    cmp edx,PCI_CLAIM_BOUND
    je .state_ok
    cmp edx,PCI_CLAIM_FAILED
    jne .bad
.state_ok:
    cmp dword [r8+12],0
    je .bad
    lea r10,[rel nd_boot_claims]
    xor edx,edx
.duplicate:
    cmp edx,ecx
    jae .unique
    cmp r9d,[r10]
    je .bad
    add r10,16
    inc edx
    jmp .duplicate
.unique:
    add r8,16
    inc ecx
    jmp .next
.ok:
    mov eax,1
    ret
.bad:
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
    lea rdx,[rel nd_boot_claims]
    mov ecx,[rel nd_boot_claim_n]
.claim:
    test ecx,ecx
    jz .unclaimed
    cmp ebx,[rdx]
    je .out
    add rdx,16
    dec ecx
    jmp .claim
.unclaimed:
    ; Bounded sorted insertion, independent of iterator order. A duplicate
    ; BDF is an incomplete census, as is overflow; neither can be truncated
    ; into an apparently valid prefix or write beyond the eight slots.
    mov ecx,[rel nd_boot_count]
    cmp ecx,8
    jae .overflow
    lea rdx,[rel nd_boot_candidates]
    xor eax,eax
.duplicate:
    cmp eax,ecx
    jae .insert
    cmp ebx,[rdx+rax*4]
    je .overflow
    inc eax
    jmp .duplicate
.insert:
    test ecx,ecx
    jz .store
    mov eax,[rdx+rcx*4-4]
    cmp eax,ebx
    jb .store
    mov [rdx+rcx*4],eax
    dec ecx
    jmp .insert
.store:
    mov [rdx+rcx*4],ebx
    inc dword [rel nd_boot_count]
    jmp .out
.overflow:
    mov dword [rel nd_boot_count],9
.out:
    pop rbx
    ret

; W3 (ROOT 109394, SEC 109421 C3/C4): once per boot, before the first group
; gate for the one discovered function and with AMD-Vi or native VT-d owned, turn
; ACS on along its chain: each Root Port (PCIe type 4) and Switch Downstream
; Port (type 6) between it and bus 0, only through pci_ecam_acs_enable.
; VT-d also checks/enables Switch Upstream Ports (5); if they lack the
; required ACS bits, admission refuses. AMD keeps its existing type-4/6 scope.
; PCI bridges and functions off the chain are never written. Parents are
; exact secondary-bus matches from one complete bridge census.
; A missing or duplicate parent, a chain deeper than ND_ACS_DEPTH or
; an overflowing census writes nothing. nd_acs_record keeps count u32, then
; per enabled port: bdf u16, port type u8, status u8, before u32, after u32,
; zero u32. Evidence only: each backend reads ACS fresh at admission.
ND_ACS_BRIDGES equ 32
ND_ACS_DEPTH equ 8
nd_boot_acs_chain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi
    mov dword [rel nd_acs_record],0
    cmp byte [rel amdvi_owned],1
    je .owned
    cmp byte [rel vtd_native_ready],1
    jne .out
.owned:
    mov dword [rel nd_acs_bridge_n],0
    mov byte [rel nd_acs_overflow],0
    lea rdi,[rel nd_acs_bridge_cb]
    call pci_scan_with_filter
    cmp byte [rel nd_acs_overflow],0
    jne .out
    xor r13d,r13d                   ; chain length
    mov ebx,r12d
    shr ebx,8                       ; bus whose parent is wanted
.up:
    test ebx,ebx
    jz .write
    cmp r13d,ND_ACS_DEPTH
    jae .out
    lea r8,[rel nd_acs_bridges]
    mov ecx,[rel nd_acs_bridge_n]
    mov r9d,-1
    xor r10d,r10d
.find:
    cmp r10d,ecx
    jae .found
    movzx eax,byte [r8+r10*8+2]     ; secondary bus
    cmp eax,ebx
    jne .find_next
    cmp r9d,-1
    jne .out                        ; two parents: ambiguous, no write
    mov r9d,r10d
.find_next:
    inc r10d
    jmp .find
.found:
    cmp r9d,-1
    je .out                         ; no parent: incomplete, no write
    cmp byte [rel amdvi_owned],1
    je .parent_valid
    ; VT-d: validate every window and port before the first enable store.
    mov eax,r12d
    shr eax,8
    movzx edx,byte [r8+r9*8+2]
    cmp eax,edx
    jb .out
    movzx edx,byte [r8+r9*8+3]
    cmp eax,edx
    ja .out
    cmp byte [r8+r9*8+1],0
    jne .switch_port
    cmp byte [r8+r9*8+4],4
    jne .out
    jmp .parent_valid
.switch_port:
    cmp byte [r8+r9*8+4],5
    je .parent_valid
    cmp byte [r8+r9*8+4],6
    jne .out
.parent_valid:
    lea rax,[rel nd_acs_chain]
    mov [rax+r13],r9b
    inc r13d
    movzx ebx,byte [r8+r9*8+1]      ; the parent's own bus
    jmp .up
.write:
    xor r14d,r14d
.port:
    cmp r14d,r13d
    jae .out
    lea rax,[rel nd_acs_chain]
    movzx r9d,byte [rax+r14]
    lea r15,[rel nd_acs_bridges]
    lea r15,[r15+r9*8]
    movzx eax,byte [r15+4]
    cmp eax,4                       ; Root Port
    je .enable
    cmp eax,6                       ; Switch Downstream Port
    je .enable
    cmp eax,5                       ; VT-d requires the whole chain, including upstream
    jne .next
    cmp byte [rel amdvi_owned],1
    je .next
.enable:
    movzx edi,word [r15]
    call pci_ecam_acs_enable
    mov r10d,[rel nd_acs_record]
    lea r11,[rel nd_acs_record+4]
    shl r10d,4
    add r11,r10
    movzx r8d,word [r15]
    mov [r11],r8w
    mov r8b,[r15+4]
    mov [r11+2],r8b
    mov [r11+3],al
    mov [r11+4],edx
    mov [r11+8],ecx
    mov dword [r11+12],0
    inc dword [rel nd_acs_record]
.next:
    inc r14d
    jmp .port
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Existing iterator ABI EDI=bus,ESI=device,EDX=function,ECX=vendor/device.
; Type-1 headers only: bdf, secondary, subordinate and PCIe port type (0xFF
; without a PCIe capability). Read-only; more than ND_ACS_BRIDGES marks overflow.
nd_acs_bridge_cb:
    push rbx
    push r12
    sub rsp,8
    shl edi,8
    shl esi,3
    or edi,esi
    or edi,edx
    mov ebx,edi
    mov esi,0x0C
    call pci_bdf_read
    shr eax,16
    and eax,0x7F
    cmp eax,1
    jne .out
    mov ecx,[rel nd_acs_bridge_n]
    cmp ecx,ND_ACS_BRIDGES
    jb .room
    mov byte [rel nd_acs_overflow],1
    jmp .out
.room:
    lea r12,[rel nd_acs_bridges]
    lea r12,[r12+rcx*8]
    inc dword [rel nd_acs_bridge_n]
    mov qword [r12],0
    mov [r12],bx
    mov byte [r12+4],0xFF
    mov edi,ebx
    mov esi,0x18
    call pci_bdf_read
    shr eax,8
    mov [r12+2],al                  ; secondary
    shr eax,8
    mov [r12+3],al                  ; subordinate
    mov edi,ebx
    mov esi,0x10                    ; PCI Express capability
    call pci_find_cap
    test eax,eax
    jz .out
    mov esi,eax
    mov edi,ebx
    call pci_bdf_read
    shr eax,20
    and eax,0xF
    mov [r12+4],al
.out:
    add rsp,8
    pop r12
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
nd_boot_first_error: dd 0
nd_boot_class: dd 0
nd_boot_mode: dd 0
nd_boot_count: dd 0
nd_boot_candidates: times 8 dd 0
nd_boot_bdf: dd 0
nd_boot_claim_n: dd 0
align 8
nd_boot_random: dq 0
nd_boot_nonce: times 17 db 0
align 8
nd_boot_selection: times 592 db 0
nd_boot_a1_selection: times 608 db 0
nd_boot_claims: times 512 db 0
align 4
nd_acs_bridge_n: dd 0
nd_acs_overflow: db 0
align 8
nd_acs_chain: times 8 db 0              ; ND_ACS_DEPTH
nd_acs_bridges: times 256 db 0          ; ND_ACS_BRIDGES*8
nd_acs_record: times 132 db 0           ; 4+ND_ACS_DEPTH*16
%endmacro
WDATA_DEFER WDATA_driver_domain_boot
