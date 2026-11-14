;; MODULE svc/guest_failure_record
;; LAYER 5
;; EXPORTS guest_failure_save
;; IMPORTS hv/driver_domain_failure, boot/header, boot/beacon, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, core/build_id
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Original post-ACK return only. Diagnostic missing/uncertain persistence never
; changes independent reset safety. Unknown previous bytes are preserved.
; One bounded write/readback attempt; no delete, alternative, key or retry.
guest_failure_save:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    cmp dword [rel ndf_phase],3
    jne .out
    cmp byte [rel guest_failure_once],0
    jne .out
    mov byte [rel guest_failure_once],1
    lea rbx,[rel guest_failure_bytes]
    mov rdi,rbx
    xor eax,eax
    mov ecx,640/8
    cld
    rep stosq
    mov rdi,rbx
    lea rsi,[rel nd_failure_record]
    mov ecx,640/8
    rep movsq
    mov rax,0x00314c494146444e
    cmp [rbx],rax
    jne .out
    cmp dword [rbx+8],1
    jne .out
    cmp dword [rbx+12],640
    jne .out
    cmp dword [rbx+44],7
    ja .out
    ; Missing diagnostic evidence does not change independent reset safety.
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    cmp byte [rel paos_build_state],BID_ST_MATCH
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    mov rax,[rel boot_tsc_start]
    mov [rbx+256],rax
    mov eax,[rel boot_nonce]
    mov [rbx+264],eax
    mov rax,[rel pbm_manager_sequence]
    mov [rbx+272],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [rbx+280],rax
    mov rax,[rel pbm_state_generation]
    mov [rbx+288],rax
    lea rdi,[rbx+296]
    lea rsi,[rel paos_build_measured]
    mov ecx,4
    rep movsq
    lea rsi,[rel pbm_payload_sha]
    mov ecx,4
    rep movsq
    mov al,[rel pbm_entry]
    mov [rbx+360],al
    mov byte [rbx+362],BID_ST_MATCH
    mov rdi,rbx
    mov esi,636
    call pbm_crc32
    mov [rbx+636],eax
    mov rdi,rbx
    call guest_failure_wire_ok
    test eax,eax
    jz .out
    call guest_failure_read
    mov rdx,0x800000000000000E
    cmp rax,rdx                    ; only confirmed NOT_FOUND is missing
    je .gate
    test rax,rax
    jnz .unknown
    cmp dword [rel guest_failure_attrs],7
    jne .unknown
    cmp qword [rel guest_failure_size],640
    jne .unknown
    lea rdi,[rel guest_failure_verify]
    call guest_failure_wire_ok
    test eax,eax
    jz .unknown                    ; preserve unknown existing diagnostic bytes
.gate:
    lea rdi,[rel guest_failure_guid]
    lea rsi,[rel guest_failure_name]
    xor edx,edx
    lea rcx,[rel guest_failure_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .out
    lea rcx,[rel guest_failure_name]
    lea rdx,[rel guest_failure_guid]
    mov r8d,7
    mov r9d,640
    sub rsp,48                    ; aligned UEFI home space + fifth argument
    mov [rsp+32],rbx
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .unknown
    call guest_failure_read
    test rax,rax
    jnz .unknown
    cmp dword [rel guest_failure_attrs],7
    jne .unknown
    cmp qword [rel guest_failure_size],640
    jne .unknown
    lea rdi,[rel guest_failure_verify]
    mov rsi,rbx
    mov ecx,640/8
    cld
    repe cmpsq
    jne .unknown
    mov byte [rel guest_failure_saved],1
.unknown:
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

guest_failure_wire_ok:
    push rbx
    mov rbx,rdi
    mov rax,0x00314c494146444e
    cmp [rbx],rax
    jne .bad
    cmp dword [rbx+8],1
    jne .bad
    cmp dword [rbx+12],640
    jne .bad
    cmp dword [rbx+44],7
    ja .bad
    cmp dword [rbx+76],0
    jne .bad
    mov rax,[rbx+232]
    or rax,[rbx+240]
    or rax,[rbx+248]
    jnz .bad
    lea rsi,[rbx+363]
    mov ecx,29
.reserved1:
    cmp byte [rsi],0
    jne .bad
    inc rsi
    loop .reserved1
    lea rsi,[rbx+520]
    mov ecx,116
.reserved2:
    cmp byte [rsi],0
    jne .bad
    inc rsi
    loop .reserved2
    cmp qword [rbx+256],0
    je .bad
    cmp dword [rbx+268],0
    jne .bad
    cmp qword [rbx+272],0
    je .bad
    cmp qword [rbx+280],0
    je .bad
    cmp qword [rbx+288],0
    je .bad
    mov rax,[rbx+296]
    or rax,[rbx+304]
    or rax,[rbx+312]
    or rax,[rbx+320]
    jz .bad
    mov rax,[rbx+328]
    or rax,[rbx+336]
    or rax,[rbx+344]
    or rax,[rbx+352]
    jz .bad
    cmp byte [rbx+360],1
    jb .bad
    cmp byte [rbx+360],2
    ja .bad
    cmp word [rbx+361],0x0100
    jne .bad
    mov rdi,rbx
    mov esi,636
    call pbm_crc32
    cmp eax,[rbx+636]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

guest_failure_read:
    mov qword [rel guest_failure_size],640
    mov dword [rel guest_failure_attrs],0
    lea rcx,[rel guest_failure_name]
    lea rdx,[rel guest_failure_guid]
    lea r8,[rel guest_failure_attrs]
    lea r9,[rel guest_failure_size]
    sub rsp,40
    lea rax,[rel guest_failure_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

guest_failure_guid: dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2
guest_failure_name: dw 'P','a','O','S','G','u','e','s','t','F','a','i','l','u','r','e','R','e','c','o','r','d',0
guest_failure_tag: db 'guest-failure-record',0
%include "core/abi/wdata.inc"
%macro WDATA_svc_guest_failure_record 0
guest_failure_once: db 0
guest_failure_saved: db 0
align 8
guest_failure_size: dq 0
guest_failure_attrs: dd 0
align 8
guest_failure_bytes: times 640 db 0
guest_failure_verify: times 640 db 0
%endmacro
WDATA_DEFER WDATA_svc_guest_failure_record
