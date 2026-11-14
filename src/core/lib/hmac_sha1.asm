;; MODULE core/lib/hmac_sha1
;; LAYER 1
;; EXPORTS hmac_sha1
;; IMPORTS core/lib/sha1
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: any  (stack scratch, caller-owned buffers; no static state)
; ============================================================================
; RFC 2104 HMAC over the shared SHA-1 implementation. Transient key material
; lives on the caller's stack and is wiped before return. RFC 4226/6238 and WPA2 PBKDF2 interoperability
; only; no new artifact/signature hashing. Valid disjoint output/key/data ranges
; are a caller obligation. Output is untouched on invalid lengths. Derived from
; the project's HMAC-SHA256 implementation; SHA1 has no static scratch.
;
; hmac_sha1(out20, key, key_len, data, data_len)
;   RDI=out20, RSI=key, RDX=key_len, RCX=data, R8=data_len
;   returns EAX=0, or -1 if the bounded SHA stream rejects a length.
; ============================================================================

HM1_KEY_BLOCK equ 0
HM1_SHA_CTX   equ 64
HM1_INNER     equ 168
HM1_FRAME     equ 200

hmac_sha1:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HM1_FRAME
    cld
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbp, r8

    ; RFC 2104 section 2: zero-pad K0; hash keys longer than one block.
    lea  rdi, [rsp + HM1_KEY_BLOCK]
    xor  eax, eax
    mov  ecx, 8
    rep  stosq
    cmp  r14, 64
    jbe  .copy_key
    lea  rdi, [rsp + HM1_KEY_BLOCK]
    mov  rsi, r13
    mov  rdx, r14
    call sha1_hash
    test rax, rax
    jnz  .fail
    jmp  .make_ipad
.copy_key:
    test r14, r14
    jz   .make_ipad
    lea  rdi, [rsp + HM1_KEY_BLOCK]
    mov  rsi, r13
    mov  rcx, r14
    rep  movsb

.make_ipad:
    lea  rdi, [rsp + HM1_KEY_BLOCK]
    mov  ecx, 64
.ipad_loop:
    xor  byte [rdi], 0x36
    inc  rdi
    dec  ecx
    jnz  .ipad_loop

    ; inner = SHA1((K0 xor ipad) || message)
    lea  rdi, [rsp + HM1_SHA_CTX]
    call sha1_stream_init
    lea  rdi, [rsp + HM1_SHA_CTX]
    lea  rsi, [rsp + HM1_KEY_BLOCK]
    mov  edx, 64
    call sha1_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HM1_SHA_CTX]
    mov  rsi, r15
    mov  rdx, rbp
    call sha1_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HM1_SHA_CTX]
    lea  rsi, [rsp + HM1_INNER]
    call sha1_stream_final
    test rax, rax
    jnz  .fail

    ; Turn K0 xor ipad into K0 xor opad in place.
    lea  rdi, [rsp + HM1_KEY_BLOCK]
    mov  ecx, 64
.opad_loop:
    xor  byte [rdi], (0x36 ^ 0x5c)
    inc  rdi
    dec  ecx
    jnz  .opad_loop

    ; output = SHA1((K0 xor opad) || inner)
    lea  rdi, [rsp + HM1_SHA_CTX]
    call sha1_stream_init
    lea  rdi, [rsp + HM1_SHA_CTX]
    lea  rsi, [rsp + HM1_KEY_BLOCK]
    mov  edx, 64
    call sha1_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HM1_SHA_CTX]
    lea  rsi, [rsp + HM1_INNER]
    mov  edx, 20
    call sha1_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rsp + HM1_SHA_CTX]
    mov  rsi, r12
    call sha1_stream_final
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rsp]
    xor  eax, eax
    mov  ecx, HM1_FRAME / 8
    rep  stosq
    mov  eax, ebx
    add  rsp, HM1_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
