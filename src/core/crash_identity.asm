;; MODULE core/crash_identity
;; LAYER 1
;; EXPORTS crash_identity_valid, crash_identity_record, crash_identity_capture, crash_identity_project, crash_identity_status
;; IMPORTS core/deadman_identity, boot/paging, boot/boot_v2_handoff, boot/boot_v2_health, boot/header, boot/nvram_access, core/build_id
;; CAPS
;; OWNER saga:core
%include "core/abi/crash_identity.inc"
; Actual panic only, after the first-fatal claimant commits the legacy slot.
; RDI=legacy slot24, RSI=full ring boot ordinal. No allocation, locks, firmware,
; or raw addresses retained. Missing fixed reservation is explicitly unavailable.
crash_identity_capture:
    push rbp
    mov rbp,rsp
    push rbx
    push r12
    mov rbx,[rel crash_identity_base]
    test rbx,rbx
    jz .out
    add rbx,CRID_OFFSET
    mov dword [rbx+CRID_CRC],0 ; invalidate BEFORE touching a previous snapshot
    clflush [rbx+CRID_CRC]
    mfence
    mov r12,rdi
    mov [rbx+CRID_BOOT],rsi
    mov dword [rbx],CRID_MAGIC
    mov word [rbx+4],1
    mov word [rbx+6],CRID_BYTES
    mov dword [rbx+CRID_PBCR],0x52434250
    mov word [rbx+CRID_PBCR+4],1
    mov word [rbx+CRID_PBCR+6],32
    lea rdi,[rbx+CRID_PBCR+8]
    mov rsi,r12
    mov ecx,20
    rep movsb
    lea rdi,[rbx+CRID_PBCR]
    mov esi,28
    call pbm_crc32
    mov [rbx+CRID_PBCR+28],eax
    lea rdi,[rbx+CRID_BUILD]
    xor eax,eax
    mov ecx,9 ; zero both digests + state/flags/reserved[104,112)
    rep stosq
    mov dword [rbx+120],0
    cmp byte [rel paos_build_state],BID_ST_UNMEASURED
    je .seal
    mov al,[rel paos_build_state]
    mov [rbx+CRID_STATE],al
    mov byte [rbx+CRID_FLAGS],1
    lea rdi,[rbx+CRID_BUILD]
    lea rsi,[rel paos_build_measured]
    mov ecx,4
    rep movsq
    cmp byte [rel pbm_manager_launch],1
    jne .seal
    lea rsi,[rel pbm_payload_sha]
    mov rax,[rsi]
    or rax,[rsi+8]
    or rax,[rsi+16]
    or rax,[rsi+24]
    jz .seal
    lea rdi,[rbx+CRID_PAYLOAD]
    mov ecx,4
    rep movsq
    or byte [rbx+CRID_FLAGS],2
.seal:
    mov rdi,rbx
    mov esi,CRID_CRC
    call pbm_crc32
    mov [rbx+CRID_CRC],eax ; publish complete prior-fault source LAST
    clflush [rbx]
    clflush [rbx+64]
    mfence
    mov rdi,rbx
    call deadman_identity_capture       ; same first-fatal claimant, no firmware
.out:
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; RDI=PBCI128 -> EAX=1 valid FULL identity, else 0. Diagnostic integrity only.
; No key/health/policy authority: expected file digest is explicitly a Manager
; claim. The measured BID and captured fault context travel in the same record.
crash_identity_valid:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],CRID_MAGIC
    jne .bad
    cmp word [rbx+4],1
    jne .bad
    cmp word [rbx+6],CRID_BYTES
    jne .bad
    cmp dword [rbx+CRID_PBCR],0x52434250
    jne .bad
    cmp dword [rbx+CRID_PBCR+4],0x00200001
    jne .bad
    cmp byte [rbx+CRID_PBCR+8],31
    ja .bad
    movzx eax,byte [rbx+CRID_PBCR+9]
    cmp eax,255
    je .unknown
    cmp eax,8
    ja .bad
    cmp byte [rbx+CRID_PBCR+10],2
    ja .bad
    jmp .phase_ok
.unknown:
    cmp byte [rbx+CRID_PBCR+10],0
    jne .bad
.phase_ok:
    mov al,[rbx+CRID_PBCR+11]
    test al,0xf8
    jnz .bad
    and al,6 ; both independently measured prefix and Manager launch recorded
    cmp al,6
    jne .bad
    test byte [rbx+CRID_PBCR+11],1
    jnz .rip_known
    cmp dword [rbx+CRID_PBCR+16],0xffffffff
    jne .bad
    jmp .rip_ok
.rip_known:
    cmp dword [rbx+CRID_PBCR+16],0xffffffff
    je .bad
.rip_ok:
    cmp byte [rbx+CRID_FLAGS],3
    jne .bad
    movzx eax,byte [rbx+CRID_STATE]
    dec eax
    cmp eax,2
    ja .bad
    cmp word [rbx+106],0
    jne .bad
    cmp dword [rbx+108],0
    jne .bad
    cmp dword [rbx+120],0
    jne .bad
    mov eax,[rbx+CRID_BOOT]
    cmp eax,[rbx+CRID_PBCR+24]
    jne .bad
    mov eax,[rbx+CRID_BUILD]
    cmp eax,[rbx+CRID_PBCR+20]
    jne .bad
    mov rax,[rbx+CRID_BUILD]
    or rax,[rbx+CRID_BUILD+8]
    or rax,[rbx+CRID_BUILD+16]
    or rax,[rbx+CRID_BUILD+24]
    jz .bad
    mov rax,[rbx+CRID_PAYLOAD]
    or rax,[rbx+CRID_PAYLOAD+8]
    or rax,[rbx+CRID_PAYLOAD+16]
    or rax,[rbx+CRID_PAYLOAD+24]
    jz .bad
    lea rdi,[rbx+CRID_PBCR]
    mov esi,28
    call pbm_crc32
    cmp eax,[rbx+CRID_PBCR+28]
    jne .bad
    mov rdi,rbx
    mov esi,CRID_CRC
    call pbm_crc32
    cmp eax,[rbx+CRID_CRC]
    jne .bad
    cmp dword [rbx+CRID_CRC],0
    je .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Normal BSP next-boot task context ONLY. RDI=validated legacy PBCR32 prepared
; by diag_crash_record_project. It is zero on cold/invalid/missing prior ring.
; Exact embedded-PBCR equality is mandatory; NEVER consult this boot's image ID.
; Status0 absent/invalid,1saved,2refused,3uncertain,4identical. At most one bounded
; SetVariable per boot, no retry/erase, unknown existing variable preserved.
crash_identity_project:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    cmp byte [rel crash_identity_attempted],0
    jne .out
    mov byte [rel crash_identity_attempted],1
    mov rbx,rdi
    mov rsi,[rel crash_identity_base]
    test rsi,rsi
    jz .out
    add rsi,CRID_OFFSET
    lea rdi,[rel crash_identity_record]
    mov ecx,CRID_BYTES/8
    rep movsq
    lea rdi,[rel crash_identity_record]
    call crash_identity_valid
    test eax,eax
    jz .out
    mov rdi,rbx
    lea rsi,[rel crash_identity_record+CRID_PBCR]
    mov ecx,4
    repe cmpsq
    jne .out
    mov byte [rel crash_identity_status],2
    cmp byte [rel pbm_manager_launch],1
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    call crash_identity_read
    mov rbx,0x800000000000000e
    cmp rax,rbx
    je .write
    test rax,rax
    jnz .out
    cmp dword [rel crash_identity_attrs],7
    jne .out
    cmp qword [rel crash_identity_size],CRID_BYTES
    jne .out
    lea rdi,[rel crash_identity_verify]
    call crash_identity_valid
    test eax,eax
    jz .out
    lea rdi,[rel crash_identity_verify]
    lea rsi,[rel crash_identity_record]
    mov ecx,CRID_BYTES/8
    repe cmpsq
    jne .write
    mov byte [rel crash_identity_status],4
    jmp .out
.write:
    lea rdi,[rel crash_identity_guid]
    lea rsi,[rel crash_identity_name]
    xor edx,edx
    lea rcx,[rel crash_identity_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .out
    mov byte [rel crash_identity_status],3
    lea rcx,[rel crash_identity_name]
    lea rdx,[rel crash_identity_guid]
    mov r8d,7
    mov r9d,CRID_BYTES
    sub rsp,48
    lea rax,[rel crash_identity_record]
    mov [rsp+32],rax
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .out
    call crash_identity_read
    test rax,rax
    jnz .out
    cmp dword [rel crash_identity_attrs],7
    jne .out
    cmp qword [rel crash_identity_size],CRID_BYTES
    jne .out
    lea rdi,[rel crash_identity_verify]
    lea rsi,[rel crash_identity_record]
    mov ecx,CRID_BYTES/8
    repe cmpsq
    jne .out
    mov byte [rel crash_identity_status],1
.out:
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

crash_identity_read:
    mov qword [rel crash_identity_size],CRID_BYTES
    mov dword [rel crash_identity_attrs],0
    lea rcx,[rel crash_identity_name]
    lea rdx,[rel crash_identity_guid]
    lea r8,[rel crash_identity_attrs]
    lea r9,[rel crash_identity_size]
    sub rsp,40
    lea rax,[rel crash_identity_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

crash_identity_guid:
    dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
crash_identity_name: dw 'P','a','O','S','C','r','a','s','h','I','d','e','n','t','i','t','y','R','e','c','o','r','d',0
crash_identity_tag: db 'diag-crash-identity',0
%include "core/abi/wdata.inc"
%macro WDATA_crash_identity 0
crash_identity_status: db 0
crash_identity_attempted: db 0
align 8
crash_identity_size: dq 0
crash_identity_attrs: dd 0
align 8
crash_identity_record: times CRID_BYTES db 0
crash_identity_verify: times CRID_BYTES db 0
%endmacro
WDATA_DEFER WDATA_crash_identity
