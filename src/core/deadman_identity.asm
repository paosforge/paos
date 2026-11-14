;; MODULE core/deadman_identity
;; LAYER 1
;; EXPORTS deadman_identity_capture, deadman_identity_project, deadman_identity_valid, deadman_identity_status
;; IMPORTS core/crash_identity, core/normal_deadman, core/build_id, boot/paging, boot/header, boot/beacon, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access
;; CAPS
;; OWNER rc-vm-claude
; Actual first-fatal D4 expiry only. Fixed retained memory, no alloc/locks/EFI.
; This is local diagnostic integrity, never signature/health/reset authority.
%include "core/abi/deadman_identity.inc"

; RDI=complete current first-fatal PBCI128. Invalidate the old extension on
; every new fatal before selecting the exact expiry, so unrelated faults do not
; acquire a prior deadman's full attempt. Preserve caller's nonvolatile state.
deadman_identity_capture:
    push rbp
    mov rbp,rsp
    push rbx
    push r12
    mov rbx,[rel crash_identity_base]
    test rbx,rbx
    jz .out
    add rbx,DMI_OFFSET
    mov dword [rbx+DMI_CRC],0
    clflush [rbx+DMI_CRC]
    mfence
    mov r12,rdi
    cmp byte [rel normal_deadman_state],2
    jne .out
    cmp byte [rel pbm_strong_health_published],1
    jne .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    cmp byte [r12+16],6                  ; actual embedded PBCR vector
    jne .out
    cmp dword [r12+20],0                ; actual embedded error
    jne .out
    test byte [r12+19],1                ; image-relative RIP qualified
    jz .out
    lea rax,[rel normal_deadman_fault]
    sub rax,[rel pbm_image_base]
    jc .out
    mov edx,[r12+24]
    cmp rax,rdx
    jne .out
    mov rdi,r12
    call crash_identity_valid
    test eax,eax
    jz .out
    mov rdi,rbx
    xor eax,eax
    mov ecx,DMI_BYTES/8
    rep stosq
    mov dword [rbx],DMI_MAGIC
    mov word [rbx+4],1
    mov word [rbx+6],DMI_BYTES
    lea rdi,[rbx+DMI_SOURCE]
    mov rsi,r12
    mov ecx,128/8
    rep movsq
    mov rax,[rel pbm_manager_sequence]
    mov [rbx+DMI_SEQUENCE],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [rbx+DMI_NONCE],rax
    mov rax,[rel pbm_state_generation]
    mov [rbx+DMI_GENERATION],rax
    mov rax,[rel boot_tsc_start]
    mov [rbx+DMI_BOOT],rax
    mov eax,[rel boot_nonce]
    mov [rbx+DMI_BOOT_NONCE],rax
    mov rax,[rel normal_deadman_last_tsc]
    mov [rbx+DMI_LAST],rax
    mov rax,[rel normal_deadman_expired_tsc]
    mov [rbx+DMI_EXPIRED],rax
    mov rax,[rel normal_deadman_interval_tsc]
    mov [rbx+DMI_INTERVAL],rax
    mov al,[rel pbm_entry]
    mov [rbx+DMI_ENTRY],al
    mov al,[rel pbm_profile]
    mov [rbx+DMI_PROFILE],al
    mov byte [rbx+DMI_STATE],2
    mov byte [rbx+DMI_HEALTH],1
    mov rdi,rbx
    mov esi,DMI_CRC
    call pbm_crc32
    mov [rbx+DMI_CRC],eax
    clflush [rbx]
    clflush [rbx+64]
    clflush [rbx+128]
    clflush [rbx+192]
    mfence
.out:
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; Strict fixed prior-source validator. Never reads THIS boot's image/identity,
; so a later projector cannot relabel an old source or repair absent scalars.
deadman_identity_valid:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],DMI_MAGIC
    jne .bad
    cmp dword [rbx+4],(DMI_BYTES << 16)|1
    jne .bad
    lea rdi,[rbx+DMI_SOURCE]
    call crash_identity_valid
    test eax,eax
    jz .bad
    cmp byte [rbx+DMI_SOURCE+16],6
    jne .bad
    cmp dword [rbx+DMI_SOURCE+20],0
    jne .bad
    test byte [rbx+DMI_SOURCE+19],1
    jz .bad
    cmp qword [rbx+DMI_SEQUENCE],0
    je .bad
    cmp qword [rbx+DMI_NONCE],0
    je .bad
    cmp qword [rbx+DMI_GENERATION],0
    je .bad
    cmp qword [rbx+DMI_BOOT],0
    je .bad
    cmp dword [rbx+DMI_BOOT_NONCE+4],0
    jne .bad
    movzx eax,byte [rbx+DMI_ENTRY]
    dec eax
    cmp eax,1
    ja .bad
    cmp byte [rbx+DMI_PROFILE],PBM_PROFILE_NORMAL
    jne .bad
    cmp word [rbx+DMI_STATE],0x0102
    jne .bad
    mov rcx,[rbx+DMI_INTERVAL]
    test rcx,rcx
    jle .bad
    mov rax,[rbx+DMI_EXPIRED]
    sub rax,[rbx+DMI_LAST]
    cmp rax,rcx
    jb .bad
    lea rdi,[rbx+204]
    mov ecx,48
    xor eax,eax
    repe scasb
    jne .bad
    mov rdi,rbx
    mov esi,DMI_CRC
    call pbm_crc32
    cmp eax,[rbx+DMI_CRC]
    jne .bad
    test eax,eax
    jz .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI=actual separately validated prior PBCI128. BSP task context after its
; original projection; exact embedded equality required. At most one offer
; per boot, unknown store preserved, no erase or uncertain write/readback retry.
deadman_identity_project:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    cmp byte [rel deadman_identity_attempted],0
    jne .out
    mov byte [rel deadman_identity_attempted],1
    mov rbx,rdi
    cmp byte [rel crash_identity_status],0 ; prior ring/PBCI binding succeeded
    je .out
    mov rsi,[rel crash_identity_base]
    test rsi,rsi
    jz .out
    add rsi,DMI_OFFSET
    lea rdi,[rel deadman_identity_record]
    mov ecx,DMI_BYTES/8
    rep movsq
    lea rdi,[rel deadman_identity_record]
    call deadman_identity_valid
    test eax,eax
    jz .out
    mov rdi,rbx
    lea rsi,[rel deadman_identity_record+DMI_SOURCE]
    mov ecx,128/8
    repe cmpsq
    jne .out
    mov byte [rel deadman_identity_status],2
    cmp byte [rel pbm_manager_launch],1
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    call deadman_identity_read
    mov rbx,0x800000000000000e
    cmp rax,rbx
    je .write
    test rax,rax
    jnz .out
    cmp dword [rel deadman_identity_attrs],7
    jne .out
    cmp qword [rel deadman_identity_size],DMI_BYTES
    jne .out
    lea rdi,[rel deadman_identity_verify]
    call deadman_identity_valid
    test eax,eax
    jz .out
    lea rdi,[rel deadman_identity_verify]
    lea rsi,[rel deadman_identity_record]
    mov ecx,DMI_BYTES/8
    repe cmpsq
    jne .write
    mov byte [rel deadman_identity_status],4
    jmp .out
.write:
    lea rdi,[rel deadman_identity_guid]
    lea rsi,[rel deadman_identity_name]
    xor edx,edx
    lea rcx,[rel deadman_identity_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .out
    mov byte [rel deadman_identity_status],3
    lea rcx,[rel deadman_identity_name]
    lea rdx,[rel deadman_identity_guid]
    mov r8d,7
    mov r9d,DMI_BYTES
    sub rsp,48
    lea rax,[rel deadman_identity_record]
    mov [rsp+32],rax
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .out
    call deadman_identity_read
    test rax,rax
    jnz .out
    cmp dword [rel deadman_identity_attrs],7
    jne .out
    cmp qword [rel deadman_identity_size],DMI_BYTES
    jne .out
    lea rdi,[rel deadman_identity_verify]
    lea rsi,[rel deadman_identity_record]
    mov ecx,DMI_BYTES/8
    repe cmpsq
    jne .out
    mov byte [rel deadman_identity_status],1
.out:
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

deadman_identity_read:
    mov qword [rel deadman_identity_size],DMI_BYTES
    mov dword [rel deadman_identity_attrs],0
    lea rcx,[rel deadman_identity_name]
    lea rdx,[rel deadman_identity_guid]
    lea r8,[rel deadman_identity_attrs]
    lea r9,[rel deadman_identity_size]
    sub rsp,40
    lea rax,[rel deadman_identity_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret


deadman_identity_guid:
    dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2
deadman_identity_name: dw 'P','a','O','S','D','e','a','d','m','a','n','I','d','e','n','t','i','t','y','R','e','c','o','r','d',0
deadman_identity_tag: db 'diag-deadman-identity',0
%include "core/abi/wdata.inc"
%macro WDATA_deadman_identity 0
deadman_identity_status: db 0
deadman_identity_attempted: db 0
align 8
deadman_identity_size: dq 0
deadman_identity_attrs: dd 0
align 8
deadman_identity_record: times DMI_BYTES db 0
deadman_identity_verify: times DMI_BYTES db 0
%endmacro
WDATA_DEFER WDATA_deadman_identity
