;; MODULE core/lib/crypto
;; LAYER 1
;; EXPORTS crypto_hash64, crypto_mix64, crypto_kdf, crypto_keystream_xor
;; IMPORTS
;; CAPS
;; OWNER saga:sec
; ============================================================================
; core/lib/crypto.asm — legacy deterministic mixing utilities retained only for
; non-security compatibility checks while old callers migrate.  FNV-1a,
; SplitMix64, and XOR output are NOT encryption, authentication, a password KDF,
; or a security boundary.  New security callers must use hkdf_sha256_derive and
; aes256_gcm_{seal,open,wrap_dek,unwrap_dek} from the contract-1237 foundation.
;
; SysV internal ABI. crypto_kdf / crypto_keystream_xor preserve rbx,r12-r15 (they
; save them); crypto_hash64 / crypto_mix64 are leaf and clobber only rax,rcx (+ the
; arg/scratch regs noted per-function).
; ============================================================================

CRYPTO_GOLDEN equ 0x9e3779b97f4a7c15   ; 2^64/phi — block-index stride (well-spread)

; crypto_hash64(RDI=ptr, RSI=len) -> RAX = 64-bit FNV-1a hash.
;   Legacy FNV-1a-64 fingerprint.  It is deterministic, not cryptographic.
;   len==0 -> the offset basis (non-zero).
;   clobbers: RAX,RCX,R8,RDI,RSI.
crypto_hash64:
    mov  rax, 0xcbf29ce484222325         ; FNV-1a 64 offset basis
    mov  r8,  0x100000001b3              ; FNV-1a 64 prime
    test rsi, rsi
    jz   .done
.loop:
    movzx rcx, byte [rdi]
    xor  rax, rcx
    imul rax, r8
    inc  rdi
    dec  rsi
    jnz  .loop
.done:
    ret

; crypto_mix64(RDI=x) -> RAX = legacy SplitMix64 avalanche of x.
;   clobbers: RAX,RCX.
crypto_mix64:
    mov  rax, rdi
    mov  rcx, rax
    shr  rcx, 30
    xor  rax, rcx
    mov  rcx, 0xbf58476d1ce4e5b9
    imul rax, rcx
    mov  rcx, rax
    shr  rcx, 27
    xor  rax, rcx
    mov  rcx, 0x94d049bb133111eb
    imul rax, rcx
    mov  rcx, rax
    shr  rcx, 31
    xor  rax, rcx
    ret

; crypto_kdf(RDI=cred_ptr, RSI=cred_len, RDX=salt_ptr, RCX=salt_len,
;            R8=out_ptr, R9=out_len)
;   Produce legacy deterministic test material from (cred, salt). seed =
;   mix64(hash(cred) ^ hash(salt)); each 8-byte output block j = mix64(seed +
;   j*GOLDEN). This is not a password KDF and must not protect stored data. Reads
;   exactly the given lengths (no OOB on a zero-length salt). Preserves rbx,r12-r15.
crypto_kdf:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, r8                         ; out_ptr
    mov  r13, r9                         ; out_len
    mov  r14, rdx                        ; salt_ptr
    mov  r15, rcx                        ; salt_len
    call crypto_hash64                   ; RAX = hash(cred)  (RDI/RSI = cred already)
    mov  rbx, rax                        ; seed accumulator
    mov  rdi, r14
    mov  rsi, r15
    call crypto_hash64                   ; RAX = hash(salt)
    xor  rbx, rax
    mov  rdi, rbx
    call crypto_mix64                    ; seed = mix64(hash(cred) ^ hash(salt))
    mov  rbx, rax
    xor  r14, r14                        ; j = block index (salt_ptr no longer needed)
.fill:
    mov  rax, r14
    shl  rax, 3                          ; byte offset = j*8
    cmp  rax, r13
    jae  .done
    mov  rdi, rbx                        ; seed
    mov  rcx, CRYPTO_GOLDEN
    mov  r10, r14
    imul r10, rcx                        ; j*GOLDEN
    add  rdi, r10
    call crypto_mix64                    ; RAX = key-material block
    mov  r10, r14
    shl  r10, 3                          ; offset
    lea  r11, [r12 + r10]                ; dst
    mov  rcx, r13
    sub  rcx, r10                        ; remaining bytes
    cmp  rcx, 8
    jbe  .tail
    mov  rcx, 8
.tail:
    mov  [r11], al                       ; write min(8,remaining) little-endian bytes
    shr  rax, 8
    inc  r11
    dec  rcx
    jnz  .tail
    inc  r14
    jmp  .fill
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; crypto_keystream_xor(RDI=key_ptr, RSI=key_len, RDX=nonce, RCX=data_ptr,
;                      R8=data_len)
;   Legacy reversible XOR transform for compatibility KATs only.  It provides no
;   confidentiality or authenticity and must never be used for stored data.
;   Preserves rbx,r12-r15.
crypto_keystream_xor:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdx                        ; nonce
    mov  r13, rcx                        ; data_ptr
    mov  r14, r8                         ; data_len
    call crypto_hash64                   ; RAX = hash(key)  (RDI/RSI = key already)
    xor  rax, r12                        ; ^ nonce
    mov  rdi, rax
    call crypto_mix64                    ; seed
    mov  rbx, rax
    xor  r15, r15                        ; j = block index
.blk:
    mov  rax, r15
    shl  rax, 3
    cmp  rax, r14
    jae  .done
    mov  rdi, rbx
    mov  rcx, CRYPTO_GOLDEN
    mov  r10, r15
    imul r10, rcx                        ; j*GOLDEN
    add  rdi, r10
    call crypto_mix64                    ; RAX = keystream block
    mov  r10, r15
    shl  r10, 3
    lea  r11, [r13 + r10]                ; dst
    mov  rcx, r14
    sub  rcx, r10                        ; remaining
    cmp  rcx, 8
    jbe  .kt
    mov  rcx, 8
.kt:
    mov  dl, [r11]                       ; data byte
    xor  dl, al                          ; ^ keystream byte
    mov  [r11], dl
    shr  rax, 8
    inc  r11
    dec  rcx
    jnz  .kt
    inc  r15
    jmp  .blk
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
