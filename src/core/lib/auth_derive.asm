;; MODULE core/lib/auth_derive
;; LAYER 1
;; EXPORTS auth_derive_key
;; IMPORTS core/lib/hkdf_sha256
;; CAPS
;; OWNER saga:sec
; ============================================================================
; Canonical 1053 authentication-derive primitive.  Keeping the arithmetic at
; L1 lets both the public sec/principal seam and lower storage crypto reuse one
; RFC5869 definition without an upward dependency or a second KDF variant.
;
; auth_derive_key(RDI=salt,RSI=salt_len,RDX=credential,RCX=credential_len,
;                 R8=out,R9=out_len) -> 0/-1
; ============================================================================

auth_derive_key:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                          ; salt
    mov  r13, rsi                          ; salt length
    mov  r14, rdx                          ; credential / IKM
    mov  r15, rcx                          ; credential length
    mov  rbx, r8                           ; output
    sub  rsp, 16
    mov  [rsp], rbx                        ; HKDF stack arg7: output
    mov  [rsp + 8], r9                     ; HKDF stack arg8: output length
    mov  rdi, r14
    mov  rsi, r15
    mov  rdx, r12
    mov  rcx, r13
    lea  r8, [rel auth_derive_domain]
    mov  r9d, auth_derive_domain.len
    call hkdf_sha256_derive
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

auth_derive_domain: db "PaOS-auth-derive-v1"
.len equ $ - auth_derive_domain
