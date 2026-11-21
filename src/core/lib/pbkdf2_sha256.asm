;; MODULE core/lib/pbkdf2_sha256
;; LAYER 1
;; EXPORTS pbkdf2_sha256, pbkdf2_sha256_selftest
;; IMPORTS core/lib/sha256, core/lib/mem
;; CAPS
;; OWNER saga:identity_foundation
;; CONTEXT: bsp_only  (SEC-S10-ext: pbkdf2_sha256_selftest writes module-static pbkdf2_kat_actual and the module calls bsp_only core/lib/sha256; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)

; pbkdf2_sha256(out, out_len<=32, password, password_len, salt, salt_len,
;               stack iterations) -> 0/-1.
; One SHA-256 block is the complete Task2501 credential use case: RFC 8018
; PBKDF2 with PRF = HMAC-SHA256 (RFC 2104), dkLen <= 32, so T = T_1 only.
;
; SR-59 / track B L73: the HMAC key schedule is computed once.  K0 is the
; password zero-padded to one block, or SHA-256(password) when longer than a
; block.  The SHA-256 states after (K0 xor ipad) and after (K0 xor opad) are
; kept in the frame, and every round resumes copies of them:
;   U_1 = SHA256(opad state || SHA256(ipad state || salt || INT_32_BE(1)))
;   U_i = SHA256(opad state || SHA256(ipad state || U_{i-1}))
;   T   = U_1 xor ... xor U_c
; Same output and same rounds as HMAC per round, two SHA-256 compressions per
; round instead of four.  K0, both kept states, the working state, U and T live
; only in this frame, which is wiped with memset before every return.
; The salt is read from the caller's buffer (<= PBKDF2_SALT_MAX bytes).
; pbkdf2_sha256 uses no module static: a password longer than one block is
; hashed in the frame too (sha256_hash's shared context is never wiped).
;
; Frame (PBKDF2_FRAME bytes; 6 pushes + return + frame keep RSP 16-aligned at
; every call):
PBKDF2_ICTX     equ 0                          ; SHA-256 state after K0^ipad
PBKDF2_OCTX     equ PBKDF2_ICTX + S256_CTX_SZ  ; SHA-256 state after K0^opad
PBKDF2_WCTX     equ PBKDF2_OCTX + S256_CTX_SZ  ; working state of one hash
PBKDF2_KBLK     equ PBKDF2_WCTX                ; K0 block (64), used before WCTX
PBKDF2_U        equ PBKDF2_WCTX + S256_CTX_SZ  ; U_i, also the inner digest
PBKDF2_T        equ PBKDF2_U + 32              ; T accumulator
PBKDF2_ITER     equ PBKDF2_T + 32              ; dword: rounds left
PBKDF2_SLEN     equ PBKDF2_ITER + 4            ; dword: salt length
PBKDF2_FRAME    equ PBKDF2_SLEN + 4            ; 408
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
    mov  [rsp + PBKDF2_ITER], r11d
    mov  [rsp + PBKDF2_SLEN], r10d
    cld

    ; RFC 2104 section 2: K0 = password zero-padded; a key longer than one
    ; block is hashed first.
    lea  rdi, [rsp + PBKDF2_KBLK]
    xor  eax, eax
    mov  ecx, 8
    rep  stosq
    cmp  r15, 64
    jbe  .copy_key
    ; Long key: hash it in this frame (ICTX as scratch, digest into the K0
    ; block), never in sha256_hash's static context, which nothing wipes.
    lea  rdi, [rsp + PBKDF2_ICTX]
    call sha256_stream_init
    lea  rdi, [rsp + PBKDF2_ICTX]
    mov  rsi, r14
    mov  rdx, r15
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + PBKDF2_ICTX]
    lea  rsi, [rsp + PBKDF2_KBLK]
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + PBKDF2_ICTX]     ; drop the password tail from the scratch
    xor  eax, eax                     ; block: stream_init does not clear it
    mov  ecx, S256_CTX_SZ / 8
    rep  stosq
    jmp  .pads
.copy_key:
    lea  rdi, [rsp + PBKDF2_KBLK]
    mov  rsi, r14
    mov  rcx, r15
    rep  movsb
.pads:
    ; Inner state: SHA-256 over K0 xor ipad.
    lea  rdi, [rsp + PBKDF2_KBLK]
    mov  ecx, 64
.ipad_loop:
    xor  byte [rdi], 0x36
    inc  rdi
    dec  ecx
    jnz  .ipad_loop
    lea  rdi, [rsp + PBKDF2_ICTX]
    call sha256_stream_init
    lea  rdi, [rsp + PBKDF2_ICTX]
    lea  rsi, [rsp + PBKDF2_KBLK]
    mov  edx, 64
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    ; Outer state: turn K0 xor ipad into K0 xor opad in place.
    lea  rdi, [rsp + PBKDF2_KBLK]
    mov  ecx, 64
.opad_loop:
    xor  byte [rdi], (0x36 ^ 0x5c)
    inc  rdi
    dec  ecx
    jnz  .opad_loop
    lea  rdi, [rsp + PBKDF2_OCTX]
    call sha256_stream_init
    lea  rdi, [rsp + PBKDF2_OCTX]
    lea  rsi, [rsp + PBKDF2_KBLK]
    mov  edx, 64
    call sha256_stream_update
    test rax, rax
    jnz  .fail

    ; T = 0, so every round (the first included) folds U_i in by xor.
    lea  rdi, [rsp + PBKDF2_T]
    xor  eax, eax
    mov  ecx, 4
    rep  stosq

    ; U_1 inner message: salt || INT_32_BE(1).  The working copy of the
    ; inner state overwrites K0 here; K0 is not needed again.
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_ICTX]
    mov  ecx, S256_CTX_SZ
    rep  movsb
    lea  rdi, [rsp + PBKDF2_WCTX]
    mov  rsi, rbx
    mov  edx, [rsp + PBKDF2_SLEN]
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rel pbkdf2_block_index]
    mov  edx, 4
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    jmp  .inner_final
.iterate:
    ; U_i inner message: U_{i-1}.
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_ICTX]
    mov  ecx, S256_CTX_SZ
    rep  movsb
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_U]
    mov  edx, 32
    call sha256_stream_update
    test rax, rax
    jnz  .fail
.inner_final:
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_U]        ; inner digest
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_OCTX]
    mov  ecx, S256_CTX_SZ
    rep  movsb
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_U]
    mov  edx, 32
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + PBKDF2_WCTX]
    lea  rsi, [rsp + PBKDF2_U]        ; U_i
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    mov  rax, [rsp + PBKDF2_U]
    xor  [rsp + PBKDF2_T], rax
    mov  rax, [rsp + PBKDF2_U + 8]
    xor  [rsp + PBKDF2_T + 8], rax
    mov  rax, [rsp + PBKDF2_U + 16]
    xor  [rsp + PBKDF2_T + 16], rax
    mov  rax, [rsp + PBKDF2_U + 24]
    xor  [rsp + PBKDF2_T + 24], rax
    dec  dword [rsp + PBKDF2_ITER]
    jnz  .iterate

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
; INT_32_BE(1): PBKDF2 block index; dkLen <= 32 is always the one block T_1.
pbkdf2_block_index: db 0x00,0x00,0x00,0x01
