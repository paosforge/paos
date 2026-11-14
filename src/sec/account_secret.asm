;; MODULE sec/account_secret
;; LAYER 5
;; EXPORTS account_secret_seal
;; IMPORTS sec/session, sec/principal, svc/command, core/smp, core/lib/hkdf_sha256, core/lib/mem, data/crypto_envelope
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Internal seal-only core. This function grants NO account/operation authority.
; No command, app transport, persistence, editor capture or plaintext-return API.
; A trusted native caller supplies scope from its current approved-app journey;
; it must independently establish actual app identity and owner approval before
; publishing an effective policy. See gauntlet_v2/docs/ACCOUNT_SECRET.md.

ACS_HEADER equ 160
ACS_RECORD equ ACS_HEADER+4*168
ACS_SCOPE equ 132                  ; digest32, account_len4, padded account96

; RDI=private native out832, RSI=832, RDX=native scope132,
; RCX=private native plaintext, R8=length1..128 -> EAX0 / 3 refused.
; Only ciphertext/header is returned. Exact-size output is zero on refusal.
; Buffers belong to native caller and must not overlap this module's scratch.
; Input buffers may overlap output: both inputs are copied before it is cleared.
; Caller retains responsibility for clearing its editor/input after the attempt.
account_secret_seal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    test r12, r12
    jz .bad_output
    cmp rsi, ACS_RECORD
    jne .bad_output
    ; The BSP gate precedes ownership of unlocked shared crypto scratch.
    call smp_current_logical
    test eax, eax
    jnz .zero_output
    xor eax, eax
    mov bl, 1
    lock cmpxchg byte [rel acs_busy], bl
    jne .zero_output
    test r13, r13
    jz .fail
    test r14, r14
    jz .fail
    test r15, r15
    jz .fail
    cmp r15, 128
    ja .fail
    lea rdi, [rel acs_scope]
    mov rsi, r13
    mov edx, ACS_SCOPE
    call memcpy
    lea rdi, [rel acs_secret]
    mov rsi, r14
    mov rdx, r15
    call memcpy
    mov [rel acs_length], r15d
    call acs_context
    test eax, eax
    jnz .fail
    mov [rel acs_epoch], rdx
    ; Exact bounded public account identity, with one canonical zero padding.
    mov ecx, [rel acs_scope+32]
    test ecx, ecx
    jz .fail
    cmp ecx, 96
    ja .fail
    lea rdi, [rel acs_scope+36]
    xor edx, edx
.account:
    mov al, [rdi+rdx]
    cmp al, 0x21
    jb .fail
    cmp al, 0x7e
    ja .fail
    inc edx
    cmp edx, ecx
    jb .account
.padding:
    cmp edx, 96
    jae .digest
    cmp byte [rdi+rdx], 0
    jne .fail
    inc edx
    jmp .padding
.digest:
    lea rdi, [rel acs_scope]
    xor eax, eax
    mov ecx, 32
.digest_byte:
    or al, [rdi]
    inc rdi
    loop .digest_byte
    test al, al
    jz .fail
    ; Never wrap or publish the saturated identity. Failed attempts burn serial.
    cmp qword [rel acs_serial], -2
    jae .fail
    inc qword [rel acs_serial]
    mov dword [rel acs_record], 'ACS1'
    mov word [rel acs_record+4], 1
    mov word [rel acs_record+6], ACS_RECORD
    mov rax, [rel acs_serial]
    mov [rel acs_record+8], rax
    lea rdi, [rel acs_record+16]
    lea rsi, [rel acs_scope]
    mov edx, 32
    call memcpy
    mov eax, [rel acs_scope+32]
    mov [rel acs_record+48], eax
    lea rdi, [rel acs_record+64]
    lea rsi, [rel acs_scope+36]
    mov edx, 96
    call memcpy
    ; The entire public header is authenticated through the full-scope HKDF
    ; credential, rather than relying on DSEC's 64-bit row-name selector.
    lea rdi, [rel acs_info]
    lea rsi, [rel acs_domain]
    mov edx, acs_domain.len
    call memcpy
    lea rdi, [rel acs_info+acs_domain.len]
    lea rsi, [rel acs_record]
    mov edx, ACS_HEADER
    call memcpy
    mov edi, PRIN_OWNER
    call principal_credential
    test rax, rax
    jz .fail
    cmp rdx, PRIN_CREDENTIAL_LEN
    jne .fail
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [rel acs_record+16]
    mov ecx, 32
    lea r8, [rel acs_info]
    mov r9d, acs_domain.len+ACS_HEADER
    sub rsp, 16
    lea rax, [rel acs_credential]
    mov [rsp], rax
    mov qword [rsp+8], 32
    call hkdf_sha256_derive
    add rsp, 16
    test eax, eax
    jnz .fail
    xor ebx, ebx
.chunk:
    mov dword [rel acs_chunk], 'ASC1'
    mov [rel acs_chunk+4], ebx
    mov rax, [rel acs_serial]
    mov [rel acs_chunk+8], rax
    mov eax, [rel acs_length]
    mov [rel acs_chunk+16], eax
    lea rdi, [rel acs_chunk+24]
    lea rsi, [rel acs_secret]
    mov eax, ebx
    shl eax, 5
    add rsi, rax
    mov edx, 32
    call memcpy
    mov eax, ebx
    imul eax, 168
    lea rdi, [rel acs_record+ACS_HEADER]
    add rdi, rax
    mov esi, PRIN_OWNER
    lea rdx, [rel acs_row]
    mov ecx, acs_row.len
    lea r8, [rel acs_chunk]
    mov r9d, 56
    sub rsp, 16
    lea rax, [rel acs_credential]
    mov [rsp], rax
    mov qword [rsp+8], 32
    call data_crypto_seal_record        ; live CSPRNG; never selftest fallback
    add rsp, 16
    test eax, eax
    jnz .fail
    inc ebx
    cmp ebx, 4
    jb .chunk
    call acs_current
    test eax, eax
    jnz .fail
    mov rdi, r12
    lea rsi, [rel acs_record]
    mov edx, ACS_RECORD
    call memcpy
    xor ebx, ebx
    jmp .clear_scratch
.fail:
    mov ebx, 3
    mov rdi, r12
    xor esi, esi
    mov edx, ACS_RECORD
    call memset
.clear_scratch:
    lea rdi, [rel acs_scratch]
    xor esi, esi
    mov edx, acs_scratch_end-acs_scratch
    call memset
    mov byte [rel acs_busy], 0
    mov eax, ebx
    jmp .out
.zero_output:
    mov rdi, r12
    xor esi, esi
    mov edx, ACS_RECORD
    call memset
.bad_output:
    mov eax, 3
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; No yield, callback, storage, guest entry or caller-supplied authority.
acs_context:
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp dword [rel cmd_dispatch_depth], 0
    jne .bad
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .bad
    test rdx, rdx
    jz .bad
    cmp rdx, -1
    je .bad
    xor eax, eax
    ret
.bad:
    mov eax, 3
    ret
acs_current:
    call acs_context
    test eax, eax
    jnz .out
    cmp rdx, [rel acs_epoch]
    jne acs_context.bad
.out:
    ret

acs_domain: db 'PaOS/account-secret/v1'
.len equ $-acs_domain
acs_row: db 'account-secret-v1'
.len equ $-acs_row

%include "core/abi/wdata.inc"
%macro WDATA_sec_account_secret 0
acs_busy: db 0
align 8, db 0
acs_serial: dq 0
acs_scratch:
acs_epoch: dq 0
acs_length: dd 0
acs_scope: times ACS_SCOPE db 0
acs_secret: times 128 db 0
acs_credential: times 32 db 0
acs_chunk: times 56 db 0
acs_info: times acs_domain.len+ACS_HEADER db 0
acs_record: times ACS_RECORD db 0
acs_scratch_end:
%endmacro
WDATA_DEFER WDATA_sec_account_secret
