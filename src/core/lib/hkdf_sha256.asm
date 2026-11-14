;; MODULE core/lib/hkdf_sha256
;; LAYER 1
;; EXPORTS hkdf_sha256_derive, hkdf_sha256_extract, hkdf_sha256_expand_one, hkdf_sha256_selftest, hmac256_init, hmac256_update, hmac256_final, HMAC256_CTX_SZ
;; IMPORTS core/lib/sha256, core/lib/mem, boot/serial
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; ============================================================================
; RFC 5869 HKDF-SHA256, built on the shared FIPS SHA-256 stream primitive.
;
; Public ABI:
;   hkdf_sha256_derive(RDI=ikm, RSI=ikm_len, RDX=salt, RCX=salt_len,
;                      R8=info, R9=info_len,
;                      stack arg7=out, stack arg8=out_len) -> RAX
;   RAX=0 on success, -1 for a null/invalid input or an RFC 5869 length
;   violation.  out_len is 1..255*HashLen.  A zero-length salt is the RFC
;   default (HashLen zero bytes); a zero-length info field is valid.
;
; The HMAC context and PRK/T blocks live on the caller's stack.  No key material
; is stored in static data, and all key-dependent comparisons in this module's
; KAT use the canonical byte comparator only after the derivation is complete.
; ============================================================================

HMAC256_SHA_CTX equ 0
HMAC256_OPAD    equ S256_CTX_SZ
HMAC256_CTX_SZ  equ S256_CTX_SZ + 64

; hmac256_init(RDI=ctx, RSI=key, RDX=key_len) -> 0/-1
; Leaves the inner SHA-256 stream initialized with K xor ipad and retains
; K xor opad in the context for hmac256_final.
hmac256_init:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 32
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test r14, r14
    jz   .make_pad
    test r13, r13
    jz   .fail
.make_pad:
    lea  rdi, [r12 + HMAC256_OPAD]
    xor  esi, esi
    mov  edx, 64
    call memset
    cmp  r14, 64
    jbe  .copy_short_key

    ; RFC 2104: keys longer than the hash block are first hashed.
    mov  rdi, r12
    call sha256_stream_init
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, rsp
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + HMAC256_OPAD]
    mov  rsi, rsp
    mov  edx, 32
    call memcpy
    jmp  .ipad

.copy_short_key:
    test r14, r14
    jz   .ipad
    lea  rdi, [r12 + HMAC256_OPAD]
    mov  rsi, r13
    mov  rdx, r14
    call memcpy

.ipad:
    lea  rdi, [r12 + HMAC256_OPAD]
    mov  ecx, 64
.ipad_loop:
    xor  byte [rdi], 0x36
    inc  rdi
    dec  ecx
    jnz  .ipad_loop
    mov  rdi, r12
    call sha256_stream_init
    mov  rdi, r12
    lea  rsi, [r12 + HMAC256_OPAD]
    mov  edx, 64
    call sha256_stream_update
    test rax, rax
    jnz  .fail

    ; ipad xor opad = 0x36 xor 0x5c = 0x6a.
    lea  rdi, [r12 + HMAC256_OPAD]
    mov  ecx, 64
.opad_loop:
    xor  byte [rdi], 0x6a
    inc  rdi
    dec  ecx
    jnz  .opad_loop
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    ; Erase the temporary long-key digest before returning.
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 32
    push rax
    call memset
    pop  rax
    add  rsp, 32
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hmac256_update(RDI=ctx, RSI=data, RDX=len) -> 0/-1
hmac256_update:
    test rdx, rdx
    jz   .empty
    test rsi, rsi
    jz   .bad
    jmp  sha256_stream_update
.empty:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; hmac256_final(RDI=ctx, RSI=out32) -> 0/-1
hmac256_final:
    push r12
    push r13
    sub  rsp, 32
    mov  r12, rdi
    mov  r13, rsi
    test r13, r13
    jz   .fail
    mov  rdi, r12
    mov  rsi, rsp
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call sha256_stream_init
    mov  rdi, r12
    lea  rsi, [r12 + HMAC256_OPAD]
    mov  edx, 64
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, rsp
    mov  edx, 32
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, r13
    call sha256_stream_final
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .wipe
.fail:
    mov  eax, -1
.wipe:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 32
    push rax
    call memset
    pop  rax
    add  rsp, 32
    pop  r13
    pop  r12
    ret

; Canonical split HKDF seams for protocols with staged key schedules.
; hkdf_sha256_extract(RDI=salt, RSI=salt_len, RDX=ikm, RCX=ikm_len,
;                     R8=out32) -> 0/-1.
hkdf_sha256_extract:
    push rbx
    push r12
    push r13
    sub  rsp, HMAC256_CTX_SZ
    mov  r12, rdx
    mov  r13, rcx
    mov  rbx, r8
    test rbx, rbx
    jz   .fail
    mov  rdx, rsi
    mov  rsi, rdi
    mov  rdi, rsp
    call hmac256_init
    test rax, rax
    jnz  .fail
    mov  rdi, rsp
    mov  rsi, r12
    mov  rdx, r13
    call hmac256_update
    test rax, rax
    jnz  .fail
    mov  rdi, rsp
    mov  rsi, rbx
    call hmac256_final
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, HMAC256_CTX_SZ
    call memset
    mov  eax, ebx
    add  rsp, HMAC256_CTX_SZ
    pop  r13
    pop  r12
    pop  rbx
    ret

; hkdf_sha256_expand_one(RDI=prk, RSI=prk_len, RDX=info, RCX=info_len,
;                        R8=out, R9=out_len<=32) -> 0/-1.
hkdf_sha256_expand_one:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HMAC256_CTX_SZ + 32
    mov  r12, rdx
    mov  r13, rcx
    mov  r14, r8
    mov  r15, r9
    test r14, r14
    jz   .fail
    test r15, r15
    jz   .fail
    cmp  r15, 32
    ja   .fail
    mov  rdx, rsi
    mov  rsi, rdi
    mov  rdi, rsp
    call hmac256_init
    test rax, rax
    jnz  .fail
    mov  rdi, rsp
    mov  rsi, r12
    mov  rdx, r13
    call hmac256_update
    test rax, rax
    jnz  .fail
    mov  byte [rsp + HMAC256_CTX_SZ], 1
    mov  rdi, rsp
    lea  rsi, [rsp + HMAC256_CTX_SZ]
    mov  edx, 1
    call hmac256_update
    test rax, rax
    jnz  .fail
    mov  rdi, rsp
    lea  rsi, [rsp + HMAC256_CTX_SZ]
    call hmac256_final
    test rax, rax
    jnz  .fail
    mov  rdi, r14
    lea  rsi, [rsp + HMAC256_CTX_SZ]
    mov  rdx, r15
    call memcpy
    xor  ebx, ebx
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, HMAC256_CTX_SZ + 32
    call memset
    mov  eax, ebx
    add  rsp, HMAC256_CTX_SZ + 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Stack-local layout for hkdf_sha256_derive.
HKDF_L_CTX      equ 0
HKDF_L_PRK      equ HMAC256_CTX_SZ
HKDF_L_T        equ HKDF_L_PRK + 32
HKDF_L_COUNTER  equ HKDF_L_T + 32
HKDF_L_IKM      equ 248
HKDF_L_IKM_LEN  equ 256
HKDF_L_SALT     equ 264
HKDF_L_SALT_LEN equ 272
HKDF_L_INFO     equ 280
HKDF_L_INFO_LEN equ 288
HKDF_L_DONE     equ 296
HKDF_LOCAL_SZ   equ 320

hkdf_sha256_derive:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HKDF_LOCAL_SZ
    mov  [rsp + HKDF_L_IKM], rdi
    mov  [rsp + HKDF_L_IKM_LEN], rsi
    mov  [rsp + HKDF_L_SALT], rdx
    mov  [rsp + HKDF_L_SALT_LEN], rcx
    mov  [rsp + HKDF_L_INFO], r8
    mov  [rsp + HKDF_L_INFO_LEN], r9
    mov  r15, [rbp + 16]                ; stack arg7: output pointer
    mov  rbx, [rbp + 24]                ; stack arg8: requested length

    test r15, r15
    jz   .fail
    test rbx, rbx
    jz   .fail
    cmp  rbx, 255 * 32
    ja   .fail
    cmp  qword [rsp + HKDF_L_IKM_LEN], 0
    je   .ikm_ok
    cmp  qword [rsp + HKDF_L_IKM], 0
    je   .fail
.ikm_ok:
    cmp  qword [rsp + HKDF_L_SALT_LEN], 0
    je   .salt_ok
    cmp  qword [rsp + HKDF_L_SALT], 0
    je   .fail
.salt_ok:
    cmp  qword [rsp + HKDF_L_INFO_LEN], 0
    je   .info_ok
    cmp  qword [rsp + HKDF_L_INFO], 0
    je   .fail
.info_ok:
    ; HKDF-Extract: PRK = HMAC(salt, IKM).  An empty salt naturally becomes
    ; a zero-padded HMAC key of HashLen bytes as required by RFC 5869 section 2.2.
    lea  rdi, [rsp + HKDF_L_CTX]
    mov  rsi, [rsp + HKDF_L_SALT]
    mov  rdx, [rsp + HKDF_L_SALT_LEN]
    call hmac256_init
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HKDF_L_CTX]
    mov  rsi, [rsp + HKDF_L_IKM]
    mov  rdx, [rsp + HKDF_L_IKM_LEN]
    call hmac256_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HKDF_L_CTX]
    lea  rsi, [rsp + HKDF_L_PRK]
    call hmac256_final
    test rax, rax
    jnz  .fail

    mov  qword [rsp + HKDF_L_DONE], 0
    mov  byte [rsp + HKDF_L_COUNTER], 1
.expand:
    lea  rdi, [rsp + HKDF_L_CTX]
    lea  rsi, [rsp + HKDF_L_PRK]
    mov  edx, 32
    call hmac256_init
    test rax, rax
    jnz  .fail
    cmp  qword [rsp + HKDF_L_DONE], 0
    je   .no_previous_t
    lea  rdi, [rsp + HKDF_L_CTX]
    lea  rsi, [rsp + HKDF_L_T]
    mov  edx, 32
    call hmac256_update
    test rax, rax
    jnz  .fail
.no_previous_t:
    lea  rdi, [rsp + HKDF_L_CTX]
    mov  rsi, [rsp + HKDF_L_INFO]
    mov  rdx, [rsp + HKDF_L_INFO_LEN]
    call hmac256_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HKDF_L_CTX]
    lea  rsi, [rsp + HKDF_L_COUNTER]
    mov  edx, 1
    call hmac256_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HKDF_L_CTX]
    lea  rsi, [rsp + HKDF_L_T]
    call hmac256_final
    test rax, rax
    jnz  .fail

    mov  r12, [rsp + HKDF_L_DONE]
    mov  r14, rbx
    sub  r14, r12
    cmp  r14, 32
    jbe  .copy_t
    mov  r14, 32
.copy_t:
    lea  rdi, [r15 + r12]
    lea  rsi, [rsp + HKDF_L_T]
    mov  rdx, r14
    call memcpy
    add  [rsp + HKDF_L_DONE], r14
    cmp  qword [rsp + HKDF_L_DONE], rbx
    jae  .success
    inc  byte [rsp + HKDF_L_COUNTER]
    jz   .fail                           ; impossible after the 8160-byte bound
    jmp  .expand

.success:
    xor  r12d, r12d
    jmp  .wipe
.fail:
    mov  r12d, -1
.wipe:
    lea  rdi, [rsp + HKDF_L_CTX]
    xor  esi, esi
    mov  edx, HKDF_L_COUNTER + 1
    call memset
    mov  eax, r12d
    add  rsp, HKDF_LOCAL_SZ
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Published RFC 5869 Appendix A.1 KAT.  The serial receipt is emitted only
; after all 42 OKM bytes compare byte-for-byte with the RFC value.
hkdf_sha256_selftest:
    sub  rsp, 16
    lea  rax, [rel hkdf_kat_okm]
    push qword 42
    push rax
    lea  rdi, [rel hkdf_kat_ikm]
    mov  esi, 22
    lea  rdx, [rel hkdf_kat_salt]
    mov  ecx, 13
    lea  r8, [rel hkdf_kat_info]
    mov  r9d, 10
    call hkdf_sha256_derive
    add  rsp, 16
    test rax, rax
    jnz  .fail
    lea  rdi, [rel hkdf_kat_okm]
    lea  rsi, [rel hkdf_kat_expected]
    mov  edx, 42
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_hkdf_kat_detail]
    call serial_string
    lea  rdi, [rel str_hkdf_kat_marker]
    call serial_string
    xor  eax, eax
    add  rsp, 16
    ret
.fail:
    lea  rdi, [rel str_hkdf_kat_fail]
    call serial_string
    mov  eax, -1
    add  rsp, 16
    ret

align 16
hkdf_kat_ikm:      times 22 db 0x0b
hkdf_kat_salt:     db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
hkdf_kat_info:     db 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
hkdf_kat_expected:
    db 0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36
    db 0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56
    db 0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
hkdf_kat_okm:      times 42 db 0
str_hkdf_kat_detail: db "CRYPTO_KAT HKDF_SHA256_RFC5869_CASE1 okm=3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865 PASS",13,10,0
str_hkdf_kat_marker: db "[PAOS64] P2 crypto: RFC5869 HKDF-SHA256 KAT PASS [crypto.hkdf.kat]",13,10,0
str_hkdf_kat_fail:   db "[PAOS64] P2 crypto: RFC5869 HKDF-SHA256 KAT FAIL",13,10,0
