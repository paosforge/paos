;; MODULE svc/guest_restart_record
;; LAYER 5
;; EXPORTS guest_restart_save
;; IMPORTS hv/driver_domain_restart, boot/header, boot/beacon, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, core/build_id
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Original post-ACK return only. Diagnostic missing/uncertain persistence never
; changes independent reset safety. Unknown previous bytes are preserved.
; One bounded write/readback attempt; no delete, alternative, key or retry.
guest_restart_save:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    cmp dword [rel ndr_phase],3
    jne .out
    cmp byte [rel guest_restart_once],0
    jne .out
    mov byte [rel guest_restart_once],1
    lea rbx,[rel guest_restart_bytes]
    mov rdi,rbx
    xor eax,eax
    mov ecx,1536/8
    cld
    rep stosq
    mov rdi,rbx
    lea rsi,[rel nd_restart_record]
    mov ecx,1536/8
    rep movsq
    mov rax,0x003152545352444e
    cmp [rbx],rax
    jne .out
    cmp dword [rbx+8],1
    je .version
    cmp dword [rbx+8],2
    je .version
    cmp dword [rbx+8],3
    je .version
    cmp dword [rbx+8],4
    jne .out
.version:
    cmp dword [rbx+12],1536
    jne .out
    cmp dword [rbx+44],8
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
    mov esi,1532
    call pbm_crc32
    mov [rbx+1532],eax
    mov rdi,rbx
    call guest_restart_wire_ok
    test eax,eax
    jz .out
    call guest_restart_read
    mov rdx,0x800000000000000E
    cmp rax,rdx                    ; only confirmed NOT_FOUND is missing
    je .gate
    test rax,rax
    jnz .unknown
    cmp dword [rel guest_restart_attrs],7
    jne .unknown
    cmp qword [rel guest_restart_size],1536
    jne .unknown
    lea rdi,[rel guest_restart_verify]
    call guest_restart_wire_ok
    test eax,eax
    jz .unknown                    ; preserve unknown existing diagnostic bytes
.gate:
    lea rdi,[rel guest_restart_guid]
    lea rsi,[rel guest_restart_name]
    xor edx,edx
    lea rcx,[rel guest_restart_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .out
    lea rcx,[rel guest_restart_name]
    lea rdx,[rel guest_restart_guid]
    mov r8d,7
    mov r9d,1536
    sub rsp,48                    ; aligned UEFI home space + fifth argument
    mov [rsp+32],rbx
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .unknown
    call guest_restart_read
    test rax,rax
    jnz .unknown
    cmp dword [rel guest_restart_attrs],7
    jne .unknown
    cmp qword [rel guest_restart_size],1536
    jne .unknown
    lea rdi,[rel guest_restart_verify]
    mov rsi,rbx
    mov ecx,1536/8
    cld
    repe cmpsq
    jne .unknown
    mov byte [rel guest_restart_saved],1
.unknown:
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

guest_restart_wire_ok:
    push rbx
    mov rbx,rdi
    mov rax,0x003152545352444e
    cmp [rbx],rax
    jne .bad
    cmp dword [rbx+8],1
    je .version
    cmp dword [rbx+8],4
    je .version
    cmp dword [rbx+8],3
    je .version
    cmp dword [rbx+8],2
    jne .bad
    cmp dword [rbx+224],1
    jne .bad
.version:
    cmp dword [rbx+12],1536
    jne .bad
    cmp dword [rbx+44],8
    ja .bad
    lea rsi,[rbx+224]
    mov ecx,32
    cmp dword [rbx+8],2
    jne .reserved0
    jmp .reserved0_done                ; T5-1.C10b-1b u2: owner 232..256 carry the clean-step fields
.reserved0:
    cmp byte [rsi],0
    jne .bad
    inc rsi
    loop .reserved0
.reserved0_done:
    cmp dword [rbx+268],0
    jne .bad
    lea rsi,[rbx+363]
    mov ecx,29
.reserved1:
    cmp byte [rsi],0
    jne .bad
    inc rsi
    loop .reserved1
    lea rsi,[rbx+1184]
    mov ecx,348
    cmp dword [rbx+8],4
    je .traffic
    cmp dword [rbx+8],3
    je .wired
    cmp dword [rbx+8],2
    jne .reserved2
    add rsi,64
    sub ecx,64
    jmp .reserved2
.traffic:
    add rsi,344
    sub ecx,344
    jmp .reserved2
.wired:
    add rsi,312
    sub ecx,312
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
    mov esi,1532
    call pbm_crc32
    cmp eax,[rbx+1532]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

guest_restart_read:
    mov qword [rel guest_restart_size],1536
    mov dword [rel guest_restart_attrs],0
    lea rcx,[rel guest_restart_name]
    lea rdx,[rel guest_restart_guid]
    lea r8,[rel guest_restart_attrs]
    lea r9,[rel guest_restart_size]
    sub rsp,40
    lea rax,[rel guest_restart_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

guest_restart_guid: dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2
guest_restart_name: dw 'P','a','O','S','G','u','e','s','t','R','e','s','t','a','r','t','R','e','c','o','r','d',0
guest_restart_tag: db 'guest-restart-record',0
%include "core/abi/wdata.inc"
%macro WDATA_svc_guest_restart_record 0
guest_restart_once: db 0
guest_restart_saved: db 0
align 8
guest_restart_size: dq 0
guest_restart_attrs: dd 0
align 8
guest_restart_bytes: times 1536 db 0
guest_restart_verify: times 1536 db 0
%endmacro
WDATA_DEFER WDATA_svc_guest_restart_record
