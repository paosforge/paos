;; MODULE core/lib/hmac_sha256
;; LAYER 1
;; EXPORTS hmac_sha256, hmac_sha256_selftest
;; IMPORTS core/lib/sha256, core/lib/mem
;; CAPS
;; OWNER saga:crypto
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; ============================================================================
; RFC 2104 HMAC over the shared SHA-256 implementation. Transient key material
; lives on the caller's stack and is wiped before return.
;
; hmac_sha256(out32, key, key_len, data, data_len)
;   RDI=out32, RSI=key, RDX=key_len, RCX=data, R8=data_len
;   returns RAX=0, or -1 if the bounded SHA stream rejects a length.
; ============================================================================

HMAC_KEY_BLOCK equ 0
HMAC_SHA_CTX   equ 64
HMAC_INNER     equ 176
HMAC_FRAME     equ 216

hmac_sha256:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HMAC_FRAME
    cld
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbp, r8

    ; RFC 2104 section 2: zero-pad K0; hash keys longer than one block.
    lea  rdi, [rsp + HMAC_KEY_BLOCK]
    xor  eax, eax
    mov  ecx, 8
    rep  stosq
    cmp  r14, 64
    jbe  .copy_key
    lea  rdi, [rsp + HMAC_KEY_BLOCK]
    mov  rsi, r13
    mov  rdx, r14
    call sha256_hash
    test rax, rax
    jnz  .fail
    jmp  .make_ipad
.copy_key:
    test r14, r14
    jz   .make_ipad
    lea  rdi, [rsp + HMAC_KEY_BLOCK]
    mov  rsi, r13
    mov  rcx, r14
    rep  movsb

.make_ipad:
    lea  rdi, [rsp + HMAC_KEY_BLOCK]
    mov  ecx, 64
.ipad_loop:
    xor  byte [rdi], 0x36
    inc  rdi
    dec  ecx
    jnz  .ipad_loop

    ; inner = SHA256((K0 xor ipad) || message)
    lea  rdi, [rsp + HMAC_SHA_CTX]
    call sha256_stream_init
    lea  rdi, [rsp + HMAC_SHA_CTX]
    lea  rsi, [rsp + HMAC_KEY_BLOCK]
    mov  edx, 64
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HMAC_SHA_CTX]
    mov  rsi, r15
    mov  rdx, rbp
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HMAC_SHA_CTX]
    lea  rsi, [rsp + HMAC_INNER]
    call sha256_stream_final
    test rax, rax
    jnz  .fail

    ; Turn K0 xor ipad into K0 xor opad in place.
    lea  rdi, [rsp + HMAC_KEY_BLOCK]
    mov  ecx, 64
.opad_loop:
    xor  byte [rdi], (0x36 ^ 0x5c)
    inc  rdi
    dec  ecx
    jnz  .opad_loop

    ; output = SHA256((K0 xor opad) || inner)
    lea  rdi, [rsp + HMAC_SHA_CTX]
    call sha256_stream_init
    lea  rdi, [rsp + HMAC_SHA_CTX]
    lea  rsi, [rsp + HMAC_KEY_BLOCK]
    mov  edx, 64
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HMAC_SHA_CTX]
    lea  rsi, [rsp + HMAC_INNER]
    mov  edx, 32
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HMAC_SHA_CTX]
    mov  rsi, r12
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rsp]
    xor  eax, eax
    mov  ecx, HMAC_FRAME / 8
    rep  stosq
    mov  eax, ebx
    add  rsp, HMAC_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RFC 4231 section 4.2, test case 1.
hmac_sha256_selftest:
    lea  rdi, [rel hmac_kat_actual]
    lea  rsi, [rel hmac_kat_key]
    mov  edx, 20
    lea  rcx, [rel hmac_kat_data]
    mov  r8d, 8
    call hmac_sha256
    test rax, rax
    jnz  .fail
    lea  rdi, [rel hmac_kat_actual]
    lea  rsi, [rel hmac_kat_expected]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

align 16
hmac_kat_actual: times 32 db 0
hmac_kat_key:    times 20 db 0x0b
hmac_kat_data:   db "Hi There"
hmac_kat_expected:
    db 0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53
    db 0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b
    db 0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7
    db 0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
