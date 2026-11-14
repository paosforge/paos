;; MODULE core/lib/pbkdf2_sha256
;; LAYER 1
;; EXPORTS pbkdf2_sha256, pbkdf2_sha256_selftest
;; IMPORTS core/lib/hmac_sha256, core/lib/mem
;; CAPS
;; OWNER saga:identity_foundation

; pbkdf2_sha256(out, out_len<=32, password, password_len, salt, salt_len,
;               stack iterations) -> 0/-1.
; One SHA-256 block is the complete Task2501 credential use case.  The loop is
; the proven monolith PBKDF2 sequence, ported to the canonical rework HMAC.
PBKDF2_U       equ 0
PBKDF2_T       equ 32
PBKDF2_SALT    equ 64
PBKDF2_FRAME   equ 144
PBKDF2_SALT_MAX equ 64

pbkdf2_sha256:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, PBKDF2_FRAME
    mov  r12, rdi                    ; output
    mov  r13, rsi                    ; output length
    mov  r14, rdx                    ; password
    mov  r15, rcx                    ; password length
    mov  rbx, r8                     ; salt
    mov  r10, r9                     ; salt length
    mov  r11d, [rbp + 16]            ; iterations
    test r12, r12
    jz   .fail
    test r13, r13
    jz   .fail
    cmp  r13, 32
    ja   .fail
    test r14, r14
    jz   .fail
    test r15, r15
    jz   .fail
    test rbx, rbx
    jz   .fail
    test r10, r10
    jz   .fail
    cmp  r10, PBKDF2_SALT_MAX
    ja   .fail
    test r11d, r11d
    jz   .fail

    ; U1 = PRF(P, S || INT_32_BE(1)).
    lea  rdi, [rsp + PBKDF2_SALT]
    mov  rsi, rbx
    mov  rcx, r10
    cld
    rep  movsb
    mov  byte [rdi], 0
    mov  byte [rdi + 1], 0
    mov  byte [rdi + 2], 0
    mov  byte [rdi + 3], 1
    mov  [rsp + 136], r10
    mov  [rsp + 132], r11d
    lea  rdi, [rsp + PBKDF2_U]
    mov  rsi, r14
    mov  rdx, r15
    lea  rcx, [rsp + PBKDF2_SALT]
    lea  r8, [r10 + 4]
    call hmac_sha256
    test eax, eax
    jnz  .fail
    lea  rdi, [rsp + PBKDF2_T]
    lea  rsi, [rsp + PBKDF2_U]
    mov  ecx, 32
    rep  movsb

    dec  dword [rsp + 132]
    jz   .copy
.iterate:
    lea  rdi, [rsp + PBKDF2_SALT]     ; temporary U_i output
    mov  rsi, r14
    mov  rdx, r15
    lea  rcx, [rsp + PBKDF2_U]
    mov  r8d, 32
    call hmac_sha256
    test eax, eax
    jnz  .fail
    xor  ecx, ecx
.xor:
    mov  al, [rsp + PBKDF2_SALT + rcx]
    mov  [rsp + PBKDF2_U + rcx], al
    xor  [rsp + PBKDF2_T + rcx], al
    inc  ecx
    cmp  ecx, 32
    jb   .xor
    dec  dword [rsp + 132]
    jnz  .iterate
.copy:
    mov  rdi, r12
    lea  rsi, [rsp + PBKDF2_T]
    mov  rcx, r13
    rep  movsb
    xor  ebx, ebx
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rsp]
    xor  esi, esi
    mov  edx, PBKDF2_FRAME
    call memset
    mov  eax, ebx
    add  rsp, PBKDF2_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Published PBKDF2-HMAC-SHA256 vector: password/salt, c=1.
pbkdf2_sha256_selftest:
    sub  rsp, 8
    mov  qword [rsp], 1
    lea  rdi, [rel pbkdf2_kat_actual]
    mov  esi, 32
    lea  rdx, [rel pbkdf2_kat_password]
    mov  ecx, 8
    lea  r8, [rel pbkdf2_kat_salt]
    mov  r9d, 4
    call pbkdf2_sha256
    add  rsp, 8
    test eax, eax
    jnz  .fail
    lea  rdi, [rel pbkdf2_kat_actual]
    lea  rsi, [rel pbkdf2_kat_expected]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

align 16
pbkdf2_kat_actual: times 32 db 0
pbkdf2_kat_password: db "password"
pbkdf2_kat_salt: db "salt"
pbkdf2_kat_expected:
    db 0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c
    db 0x43,0xe7,0x22,0x52,0x56,0xc4,0xf8,0x37
    db 0xa8,0x65,0x48,0xc9,0x2c,0xcc,0x35,0x48
    db 0x08,0x05,0x98,0x7c,0xb7,0x0b,0xe1,0x7b
