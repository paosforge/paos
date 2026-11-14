;; MODULE core/lib/aes256_gcm
;; LAYER 1
;; EXPORTS aes256_gcm_seal, aes256_gcm_open, aes256_gcm_wrap_dek, aes256_gcm_unwrap_dek, crypto_standard_selftest, aes256_sbox, aes256_rcon, aes256_shift_rows_local, aes256_gcm_validate, gcm_tag_local, constant_time_tag_diff
;; IMPORTS core/lib/mem, core/lib/hkdf_sha256, boot/serial
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; ============================================================================
; Portable AES-256-GCM (FIPS 197 + NIST SP 800-38D).  The AES-256 key schedule,
; encrypt-round sequence, and GHASH bit order are ports of the proven Classic
; PaOS implementation; the API and hostile-case checks are additive here.
; This table-based baseline is functionally reviewed, not side-channel qualified;
; authenticate-before-release and the fixed-work tag comparison still apply.
;
; aes256_gcm_seal/open take RDI -> aead_request:
;   +0 key32, +8 nonce12, +16 aad, +24 aad_len,
;   +32 input, +40 input_len, +48 output, +56 tag16.
; Seal writes ciphertext and tag.  Open authenticates the complete ciphertext
; before writing any plaintext; tag failure returns -2 and leaves output untouched.
; Invalid pointers/lengths return -1.
;
; DEK wrapping uses the same authenticated construction, not raw AES key-wrap:
; aes256_gcm_wrap_dek(RDI=owner_nonce_state, RSI=request) requires input_len=32
; and a strictly increasing 96-bit nonce for that envelope owner.  The owner
; state is {valid byte at +0, last_nonce[12] at +8}; reuse/rollback returns -3.
; The envelope owner must serialize access and persist this state with its key.
; aes256_gcm_unwrap_dek(RDI=request) authenticates a 32-byte wrapped DEK.
; ============================================================================

AEAD_KEY       equ 0
AEAD_NONCE     equ 8
AEAD_AAD       equ 16
AEAD_AAD_LEN   equ 24
AEAD_INPUT     equ 32
AEAD_INPUT_LEN equ 40
AEAD_OUTPUT    equ 48
AEAD_TAG       equ 56
AEAD_REQ_SZ    equ 64

AEAD_OWNER_VALID equ 0
AEAD_OWNER_NONCE equ 8
AEAD_OWNER_SZ    equ 24

GCM_RKEYS   equ 0
GCM_H       equ 240
GCM_J0      equ 256
GCM_TAGMASK equ 272
GCM_COUNTER equ 288
GCM_ACC     equ 304
GCM_TMP     equ 320
GCM_LENBLK  equ 336
GCM_TAGCALC equ 352
GCM_CTX_SZ  equ 368

; aes256_key_expand_local(RDI=key32, RSI=round_keys240)
; Proven FIPS-197 AES-256 schedule: Nk=8, Nr=14.
aes256_key_expand_local:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, [r12]
    mov  [r13], rax
    mov  rax, [r12 + 8]
    mov  [r13 + 8], rax
    mov  rax, [r12 + 16]
    mov  [r13 + 16], rax
    mov  rax, [r12 + 24]
    mov  [r13 + 24], rax
    lea  r14, [rel aes256_sbox]
    lea  r15, [rel aes256_rcon]
    mov  ecx, 8
.loop:
    mov  eax, ecx
    shl  eax, 2
    mov  rbx, rax
    sub  eax, 4
    movzx r8d,  byte [r13 + rax]
    movzx r9d,  byte [r13 + rax + 1]
    movzx r10d, byte [r13 + rax + 2]
    movzx r11d, byte [r13 + rax + 3]
    mov  eax, ecx
    and  eax, 7
    test eax, eax
    jz   .rot_sub
    cmp  eax, 4
    je   .sub_word
    jmp  .xor_store
.rot_sub:
    movzx eax, r9b
    movzx eax, byte [r14 + rax]
    mov  dil, al
    movzx eax, r10b
    movzx eax, byte [r14 + rax]
    mov  r9b, al
    movzx eax, r11b
    movzx eax, byte [r14 + rax]
    mov  r10b, al
    movzx eax, r8b
    movzx eax, byte [r14 + rax]
    mov  r11b, al
    mov  eax, ecx
    shr  eax, 3
    dec  eax
    movzx eax, byte [r15 + rax]
    xor  dil, al
    mov  r8b, dil
    jmp  .xor_store
.sub_word:
    movzx eax, r8b
    movzx eax, byte [r14 + rax]
    mov  r8b, al
    movzx eax, r9b
    movzx eax, byte [r14 + rax]
    mov  r9b, al
    movzx eax, r10b
    movzx eax, byte [r14 + rax]
    mov  r10b, al
    movzx eax, r11b
    movzx eax, byte [r14 + rax]
    mov  r11b, al
.xor_store:
    mov  rdi, rbx
    sub  rdi, 32
    movzx eax, byte [r13 + rdi]
    xor  al, r8b
    mov  [r13 + rbx], al
    movzx eax, byte [r13 + rdi + 1]
    xor  al, r9b
    mov  [r13 + rbx + 1], al
    movzx eax, byte [r13 + rdi + 2]
    xor  al, r10b
    mov  [r13 + rbx + 2], al
    movzx eax, byte [r13 + rdi + 3]
    xor  al, r11b
    mov  [r13 + rbx + 3], al
    inc  ecx
    cmp  ecx, 60
    jb   .loop
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; aes256_encrypt_block_local(RDI=inout16, RSI=round_keys240)
aes256_encrypt_block_local:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 16
    mov  r12, rdi
    mov  r13, rsi
    lea  r14, [rel aes256_sbox]
    mov  rax, [r12]
    xor  rax, [r13]
    mov  [r12], rax
    mov  rax, [r12 + 8]
    xor  rax, [r13 + 8]
    mov  [r12 + 8], rax
    mov  r15d, 1
.round:
    xor  ecx, ecx
.sub_bytes:
    movzx eax, byte [r12 + rcx]
    movzx eax, byte [r14 + rax]
    mov  [r12 + rcx], al
    inc  ecx
    cmp  ecx, 16
    jb   .sub_bytes
    call aes256_shift_rows_local

    xor  ebp, ebp
.mix_columns:
    movzx eax, byte [r12 + rbp]
    movzx ebx, byte [r12 + rbp + 1]
    movzx ecx, byte [r12 + rbp + 2]
    movzx edx, byte [r12 + rbp + 3]
    mov  r8d, eax
    xor  r8d, ebx
    xor  r8d, ecx
    xor  r8d, edx
    mov  r9d, eax

    mov  dil, al
    xor  dil, bl
    movzx r10d, dil
    shl  r10b, 1
    jnc  .mc0
    xor  r10b, 0x1b
.mc0:
    xor  al, r10b
    xor  al, r8b
    mov  [rsp], al
    mov  dil, bl
    xor  dil, cl
    movzx r10d, dil
    shl  r10b, 1
    jnc  .mc1
    xor  r10b, 0x1b
.mc1:
    xor  bl, r10b
    xor  bl, r8b
    mov  [rsp + 1], bl
    mov  dil, cl
    xor  dil, dl
    movzx r10d, dil
    shl  r10b, 1
    jnc  .mc2
    xor  r10b, 0x1b
.mc2:
    xor  cl, r10b
    xor  cl, r8b
    mov  [rsp + 2], cl
    mov  dil, dl
    xor  dil, r9b
    movzx r10d, dil
    shl  r10b, 1
    jnc  .mc3
    xor  r10b, 0x1b
.mc3:
    xor  dl, r10b
    xor  dl, r8b
    mov  [rsp + 3], dl
    mov  al, [rsp]
    mov  [r12 + rbp], al
    mov  al, [rsp + 1]
    mov  [r12 + rbp + 1], al
    mov  al, [rsp + 2]
    mov  [r12 + rbp + 2], al
    mov  al, [rsp + 3]
    mov  [r12 + rbp + 3], al
    add  ebp, 4
    cmp  ebp, 16
    jb   .mix_columns

    mov  eax, r15d
    shl  eax, 4
    lea  rcx, [r13 + rax]
    mov  rax, [r12]
    xor  rax, [rcx]
    mov  [r12], rax
    mov  rax, [r12 + 8]
    xor  rax, [rcx + 8]
    mov  [r12 + 8], rax
    inc  r15d
    cmp  r15d, 14
    jb   .round

    xor  ecx, ecx
.final_sub:
    movzx eax, byte [r12 + rcx]
    movzx eax, byte [r14 + rax]
    mov  [r12 + rcx], al
    inc  ecx
    cmp  ecx, 16
    jb   .final_sub
    call aes256_shift_rows_local
    mov  rax, [r12]
    xor  rax, [r13 + 224]
    mov  [r12], rax
    mov  rax, [r12 + 8]
    xor  rax, [r13 + 232]
    mov  [r12 + 8], rax
    add  rsp, 16
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Internal row permutation.  R12 is the in-place AES state.
aes256_shift_rows_local:
    mov  al, [r12 + 1]
    mov  bl, [r12 + 5]
    mov  [r12 + 1], bl
    mov  bl, [r12 + 9]
    mov  [r12 + 5], bl
    mov  bl, [r12 + 13]
    mov  [r12 + 9], bl
    mov  [r12 + 13], al
    mov  al, [r12 + 2]
    mov  bl, [r12 + 10]
    mov  [r12 + 2], bl
    mov  [r12 + 10], al
    mov  al, [r12 + 6]
    mov  bl, [r12 + 14]
    mov  [r12 + 6], bl
    mov  [r12 + 14], al
    mov  al, [r12 + 15]
    mov  bl, [r12 + 11]
    mov  [r12 + 15], bl
    mov  bl, [r12 + 7]
    mov  [r12 + 11], bl
    mov  bl, [r12 + 3]
    mov  [r12 + 7], bl
    mov  [r12 + 3], al
    ret

; gcm_mul_local(RDI=X in/out, RSI=H), big-endian GCM bit order.
gcm_mul_local:
    push rbx
    push r12
    mov  rax, [rdi]
    bswap rax
    mov  rbx, [rdi + 8]
    bswap rbx
    mov  r8, [rsi]
    bswap r8
    mov  r9, [rsi + 8]
    bswap r9
    xor  r10, r10
    xor  r11, r11
    mov  r12, 0xe100000000000000
    mov  ecx, 128
.bit:
    test rax, rax
    jns  .skip_xor
    xor  r10, r8
    xor  r11, r9
.skip_xor:
    shl  rbx, 1
    rcl  rax, 1
    mov  edx, r9d
    and  edx, 1
    shr  r8, 1
    rcr  r9, 1
    test edx, edx
    jz   .no_reduce
    xor  r8, r12
.no_reduce:
    dec  ecx
    jnz  .bit
    bswap r10
    bswap r11
    mov  [rdi], r10
    mov  [rdi + 8], r11
    pop  r12
    pop  rbx
    ret

; gcm_prep_local(RDI=ctx, RSI=key32, RDX=nonce12)
gcm_prep_local:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx
    mov  rdi, rsi
    lea  rsi, [r12 + GCM_RKEYS]
    call aes256_key_expand_local
    lea  rdi, [r12 + GCM_H]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    lea  rsi, [r12 + GCM_RKEYS]
    call aes256_encrypt_block_local
    mov  rax, [r13]
    mov  [r12 + GCM_J0], rax
    mov  eax, [r13 + 8]
    mov  [r12 + GCM_J0 + 8], eax
    mov  dword [r12 + GCM_J0 + 12], 0x01000000
    mov  rax, [r12 + GCM_J0]
    mov  [r12 + GCM_TAGMASK], rax
    mov  rax, [r12 + GCM_J0 + 8]
    mov  [r12 + GCM_TAGMASK + 8], rax
    lea  rdi, [r12 + GCM_TAGMASK]
    lea  rsi, [r12 + GCM_RKEYS]
    call aes256_encrypt_block_local
    pop  r13
    pop  r12
    ret

; gcm_ctr_local(RDI=ctx, RSI=input, RDX=len, RCX=output)
gcm_ctr_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    xor  r15, r15
    mov  ebx, 2
.block:
    cmp  r15, r13
    jae  .done
    mov  rax, [rbp + GCM_J0]
    mov  [rbp + GCM_COUNTER], rax
    mov  eax, [rbp + GCM_J0 + 8]
    mov  [rbp + GCM_COUNTER + 8], eax
    mov  eax, ebx
    bswap eax
    mov  [rbp + GCM_COUNTER + 12], eax
    lea  rdi, [rbp + GCM_COUNTER]
    lea  rsi, [rbp + GCM_RKEYS]
    call aes256_encrypt_block_local
    mov  rcx, r13
    sub  rcx, r15
    cmp  rcx, 16
    jbe  .count_ok
    mov  ecx, 16
.count_ok:
    lea  r8, [r12 + r15]
    lea  r9, [r14 + r15]
    lea  r10, [rbp + GCM_COUNTER]
    xor  edx, edx
.xor:
    mov  al, [r8 + rdx]
    xor  al, [r10 + rdx]
    mov  [r9 + rdx], al
    inc  rdx
    cmp  rdx, rcx
    jb   .xor
    add  r15, 16
    inc  ebx
    jmp  .block
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; gcm_ghash_update_local(RDI=ctx, RSI=data, RDX=len)
gcm_ghash_update_local:
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
.next:
    test r14, r14
    jz   .done
    lea  rdi, [r12 + GCM_TMP]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  r15, 16
    cmp  r14, 16
    jae  .copy
    mov  r15, r14
.copy:
    mov  rsi, r13
    mov  rdx, r15
    call memcpy
    mov  rax, [r12 + GCM_TMP]
    xor  [r12 + GCM_ACC], rax
    mov  rax, [r12 + GCM_TMP + 8]
    xor  [r12 + GCM_ACC + 8], rax
    lea  rdi, [r12 + GCM_ACC]
    lea  rsi, [r12 + GCM_H]
    call gcm_mul_local
    add  r13, r15
    sub  r14, r15
    jmp  .next
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; gcm_tag_local(RDI=ctx, RSI=ct, RDX=ct_len, RCX=aad, R8=aad_len, R9=tag_out)
gcm_tag_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
    mov  rbx, r9
    xor  eax, eax
    mov  [rbp + GCM_ACC], rax
    mov  [rbp + GCM_ACC + 8], rax
    mov  rdi, rbp
    mov  rsi, r14
    mov  rdx, r15
    call gcm_ghash_update_local
    mov  rdi, rbp
    mov  rsi, r12
    mov  rdx, r13
    call gcm_ghash_update_local
    mov  rax, r15
    shl  rax, 3
    bswap rax
    mov  [rbp + GCM_LENBLK], rax
    mov  rax, r13
    shl  rax, 3
    bswap rax
    mov  [rbp + GCM_LENBLK + 8], rax
    mov  rdi, rbp
    lea  rsi, [rbp + GCM_LENBLK]
    mov  edx, 16
    call gcm_ghash_update_local
    mov  rax, [rbp + GCM_ACC]
    xor  rax, [rbp + GCM_TAGMASK]
    mov  [rbx], rax
    mov  rax, [rbp + GCM_ACC + 8]
    xor  rax, [rbp + GCM_TAGMASK + 8]
    mov  [rbx + 8], rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; constant_time_tag_diff(RDI=a, RSI=b) -> 0 equal, nonzero different.
constant_time_tag_diff:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    mov  dl, [rdi + rcx]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

; Validate all lengths before any data access.  The data cap is the GCM inc32
; counter limit: at most (2^32-2) 16-byte payload blocks.
aes256_gcm_validate:
    test rdi, rdi
    jz   .bad
    cmp  qword [rdi + AEAD_KEY], 0
    je   .bad
    cmp  qword [rdi + AEAD_NONCE], 0
    je   .bad
    cmp  qword [rdi + AEAD_OUTPUT], 0
    je   .bad
    cmp  qword [rdi + AEAD_TAG], 0
    je   .bad
    mov  rax, [rdi + AEAD_INPUT_LEN]
    mov  rdx, 0x0000000fffffffe0
    cmp  rax, rdx
    ja   .bad
    test rax, rax
    jz   .input_ok
    cmp  qword [rdi + AEAD_INPUT], 0
    je   .bad
.input_ok:
    mov  rax, [rdi + AEAD_AAD_LEN]
    mov  rdx, 0x1fffffffffffffff
    cmp  rax, rdx
    ja   .bad
    test rax, rax
    jz   .ok
    cmp  qword [rdi + AEAD_AAD], 0
    je   .bad
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

aes256_gcm_seal:
    push r12
    push r13
    sub  rsp, GCM_CTX_SZ
    mov  r12, rdi
    mov  r13, rsp
    call aes256_gcm_validate
    test rax, rax
    jnz  .invalid
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_KEY]
    mov  rdx, [r12 + AEAD_NONCE]
    call gcm_prep_local
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_INPUT]
    mov  rdx, [r12 + AEAD_INPUT_LEN]
    mov  rcx, [r12 + AEAD_OUTPUT]
    call gcm_ctr_local
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_OUTPUT]
    mov  rdx, [r12 + AEAD_INPUT_LEN]
    mov  rcx, [r12 + AEAD_AAD]
    mov  r8,  [r12 + AEAD_AAD_LEN]
    mov  r9,  [r12 + AEAD_TAG]
    call gcm_tag_local
    xor  r12d, r12d
    jmp  .wipe
.invalid:
    mov  r12d, -1
.wipe:
    mov  rdi, r13
    xor  esi, esi
    mov  edx, GCM_CTX_SZ
    call memset
    mov  eax, r12d
    add  rsp, GCM_CTX_SZ
    pop  r13
    pop  r12
    ret

aes256_gcm_open:
    push r12
    push r13
    sub  rsp, GCM_CTX_SZ
    mov  r12, rdi
    mov  r13, rsp
    call aes256_gcm_validate
    test rax, rax
    jnz  .invalid
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_KEY]
    mov  rdx, [r12 + AEAD_NONCE]
    call gcm_prep_local
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_INPUT]
    mov  rdx, [r12 + AEAD_INPUT_LEN]
    mov  rcx, [r12 + AEAD_AAD]
    mov  r8,  [r12 + AEAD_AAD_LEN]
    lea  r9,  [r13 + GCM_TAGCALC]
    call gcm_tag_local
    lea  rdi, [r13 + GCM_TAGCALC]
    mov  rsi, [r12 + AEAD_TAG]
    call constant_time_tag_diff
    test eax, eax
    jnz  .auth_fail
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_INPUT]
    mov  rdx, [r12 + AEAD_INPUT_LEN]
    mov  rcx, [r12 + AEAD_OUTPUT]
    call gcm_ctr_local
    xor  r12d, r12d
    jmp  .wipe
.invalid:
    mov  r12d, -1
    jmp  .wipe
.auth_fail:
    mov  r12d, -2
.wipe:
    mov  rdi, r13
    xor  esi, esi
    mov  edx, GCM_CTX_SZ
    call memset
    mov  eax, r12d
    add  rsp, GCM_CTX_SZ
    pop  r13
    pop  r12
    ret

aes256_gcm_wrap_dek:
    push r12
    push r13
    push r14
    mov  r12, rdi                       ; envelope-owner nonce state
    mov  r13, rsi                       ; request
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    cmp  qword [r13 + AEAD_INPUT_LEN], 32
    jne  .invalid
    mov  rdi, r13
    call aes256_gcm_validate
    test rax, rax
    jnz  .invalid
    cmp  byte [r12 + AEAD_OWNER_VALID], 0
    je   .seal
    mov  r14, [r13 + AEAD_NONCE]
    xor  ecx, ecx
.nonce_cmp:
    movzx eax, byte [r14 + rcx]
    movzx edx, byte [r12 + AEAD_OWNER_NONCE + rcx]
    cmp  eax, edx
    ja   .seal                           ; strictly greater: new monotonic nonce
    jb   .reuse
    inc  ecx
    cmp  ecx, 12
    jb   .nonce_cmp
.reuse:
    mov  eax, -3
    jmp  .out
.seal:
    mov  rdi, r13
    call aes256_gcm_seal
    test rax, rax
    jnz  .out
    lea  rdi, [r12 + AEAD_OWNER_NONCE]
    mov  rsi, [r13 + AEAD_NONCE]
    mov  edx, 12
    call memcpy
    mov  byte [r12 + AEAD_OWNER_VALID], 1
    xor  eax, eax
    jmp  .out
.invalid:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

aes256_gcm_unwrap_dek:
    test rdi, rdi
    jz   .invalid
    cmp  qword [rdi + AEAD_INPUT_LEN], 32
    jne  .invalid
    jmp  aes256_gcm_open
.invalid:
    mov  eax, -1
    ret

; Boot KAT: published AES-256-GCM values, authentication negatives, length
; rejection, nonce-owner enforcement, and authenticated DEK wrap/unwrap.
crypto_standard_selftest:
    call hkdf_sha256_selftest
    test rax, rax
    jnz  .fail

    ; NIST/CAVP AES-256-GCM: all-zero key/IV/plaintext, 128-bit payload.
    lea  rax, [rel gcm_kat_key]
    mov  [rel gcm_test_req + AEAD_KEY], rax
    lea  rax, [rel gcm_kat_nonce]
    mov  [rel gcm_test_req + AEAD_NONCE], rax
    mov  qword [rel gcm_test_req + AEAD_AAD], 0
    mov  qword [rel gcm_test_req + AEAD_AAD_LEN], 0
    lea  rax, [rel gcm_kat_plain]
    mov  [rel gcm_test_req + AEAD_INPUT], rax
    mov  qword [rel gcm_test_req + AEAD_INPUT_LEN], 16
    lea  rax, [rel gcm_test_ct]
    mov  [rel gcm_test_req + AEAD_OUTPUT], rax
    lea  rax, [rel gcm_test_tag]
    mov  [rel gcm_test_req + AEAD_TAG], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_seal
    test rax, rax
    jnz  .fail
    lea  rdi, [rel gcm_test_ct]
    lea  rsi, [rel gcm_kat_ct_expected]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel gcm_test_tag]
    lea  rsi, [rel gcm_kat_tag_expected]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_gcm_kat_detail]
    call serial_string
    lea  rdi, [rel str_gcm_kat_marker]
    call serial_string

    ; Positive open of the published ciphertext.
    lea  rax, [rel gcm_kat_ct_expected]
    mov  [rel gcm_test_req + AEAD_INPUT], rax
    lea  rax, [rel gcm_test_plain_out]
    mov  [rel gcm_test_req + AEAD_OUTPUT], rax
    lea  rax, [rel gcm_kat_tag_expected]
    mov  [rel gcm_test_req + AEAD_TAG], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_open
    test rax, rax
    jnz  .fail
    lea  rdi, [rel gcm_test_plain_out]
    lea  rsi, [rel gcm_kat_plain]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .fail

    ; Tag tamper: authentication fails and plaintext buffer remains untouched.
    lea  rdi, [rel gcm_bad_tag]
    lea  rsi, [rel gcm_kat_tag_expected]
    mov  edx, 16
    call memcpy
    xor  byte [rel gcm_bad_tag], 1
    lea  rdi, [rel gcm_reject_out]
    mov  esi, 0xa5
    mov  edx, 32
    call memset
    lea  rax, [rel gcm_bad_tag]
    mov  [rel gcm_test_req + AEAD_TAG], rax
    lea  rax, [rel gcm_reject_out]
    mov  [rel gcm_test_req + AEAD_OUTPUT], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_open
    cmp  eax, -2
    jne  .fail
    lea  rdi, [rel gcm_reject_out]
    lea  rsi, [rel gcm_reject_canary]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .fail

    ; Ciphertext tamper.
    lea  rdi, [rel gcm_bad_ct]
    lea  rsi, [rel gcm_kat_ct_expected]
    mov  edx, 16
    call memcpy
    xor  byte [rel gcm_bad_ct + 7], 0x80
    lea  rax, [rel gcm_bad_ct]
    mov  [rel gcm_test_req + AEAD_INPUT], rax
    lea  rax, [rel gcm_kat_tag_expected]
    mov  [rel gcm_test_req + AEAD_TAG], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_open
    cmp  eax, -2
    jne  .fail

    ; Wrong AES key.
    lea  rax, [rel gcm_kat_ct_expected]
    mov  [rel gcm_test_req + AEAD_INPUT], rax
    lea  rax, [rel gcm_wrong_key]
    mov  [rel gcm_test_req + AEAD_KEY], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_open
    cmp  eax, -2
    jne  .fail

    ; Length beyond the inc32 counter domain must fail before reading input.
    lea  rax, [rel gcm_kat_key]
    mov  [rel gcm_test_req + AEAD_KEY], rax
    mov  rax, 0x0000000fffffffe1
    mov  [rel gcm_test_req + AEAD_INPUT_LEN], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_seal
    cmp  eax, -1
    jne  .fail

    ; Authenticated DEK wrap and duplicate rejection while this caller-owned
    ; state remains initialized. Production callers currently clear that state,
    ; so this is not a persisted nonce-reuse guarantee.
    lea  rdi, [rel gcm_owner_state]
    xor  esi, esi
    mov  edx, AEAD_OWNER_SZ
    call memset
    lea  rax, [rel gcm_wrap_kek]
    mov  [rel gcm_test_req + AEAD_KEY], rax
    lea  rax, [rel gcm_wrap_nonce]
    mov  [rel gcm_test_req + AEAD_NONCE], rax
    lea  rax, [rel gcm_wrap_aad]
    mov  [rel gcm_test_req + AEAD_AAD], rax
    mov  qword [rel gcm_test_req + AEAD_AAD_LEN], 16
    lea  rax, [rel gcm_dek]
    mov  [rel gcm_test_req + AEAD_INPUT], rax
    mov  qword [rel gcm_test_req + AEAD_INPUT_LEN], 32
    lea  rax, [rel gcm_wrapped]
    mov  [rel gcm_test_req + AEAD_OUTPUT], rax
    lea  rax, [rel gcm_wrap_tag]
    mov  [rel gcm_test_req + AEAD_TAG], rax
    lea  rdi, [rel gcm_owner_state]
    lea  rsi, [rel gcm_test_req]
    call aes256_gcm_wrap_dek
    test rax, rax
    jnz  .fail
    lea  rdi, [rel gcm_owner_state]
    lea  rsi, [rel gcm_test_req]
    call aes256_gcm_wrap_dek
    cmp  eax, -3
    jne  .fail

    lea  rax, [rel gcm_wrapped]
    mov  [rel gcm_test_req + AEAD_INPUT], rax
    lea  rax, [rel gcm_unwrapped]
    mov  [rel gcm_test_req + AEAD_OUTPUT], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_unwrap_dek
    test rax, rax
    jnz  .fail
    lea  rdi, [rel gcm_unwrapped]
    lea  rsi, [rel gcm_dek]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .fail

    ; Wrong KEK refuses unwrap and still releases no plaintext.
    lea  rdi, [rel gcm_reject_out]
    mov  esi, 0xa5
    mov  edx, 32
    call memset
    lea  rax, [rel gcm_wrong_key]
    mov  [rel gcm_test_req + AEAD_KEY], rax
    lea  rax, [rel gcm_reject_out]
    mov  [rel gcm_test_req + AEAD_OUTPUT], rax
    lea  rdi, [rel gcm_test_req]
    call aes256_gcm_unwrap_dek
    cmp  eax, -2
    jne  .fail
    lea  rdi, [rel gcm_reject_out]
    lea  rsi, [rel gcm_reject_canary]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .fail

    lea  rdi, [rel str_dek_wrap_detail]
    call serial_string
    lea  rdi, [rel str_aead_reject_detail]
    call serial_string
    lea  rdi, [rel str_aead_reject_marker]
    call serial_string
    xor  eax, eax
    ret
.fail:
    lea  rdi, [rel str_crypto_standard_fail]
    call serial_string
    mov  eax, -1
    ret

align 16
aes256_sbox:
    db 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
    db 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0
    db 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
    db 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
    db 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84
    db 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf
    db 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8
    db 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
    db 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73
    db 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb
    db 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79
    db 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08
    db 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a
    db 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e
    db 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf
    db 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
; AES-256 consumes the first seven entries; the canonical table includes all
; ten so the AES-128 key schedule can reuse it without reading alignment bytes.
aes256_rcon: db 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36

align 16
gcm_kat_key:           times 32 db 0
gcm_kat_nonce:         times 12 db 0
gcm_kat_plain:         times 16 db 0
gcm_kat_ct_expected:   db 0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18
gcm_kat_tag_expected:  db 0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19
gcm_wrong_key:         times 31 db 0
                       db 1
gcm_wrap_kek:          db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
                       db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
gcm_wrap_nonce:        times 11 db 0
                       db 1
gcm_wrap_aad:          db "PAOS-DEK-WRAP-v1"
gcm_dek:               db 0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f
                       db 0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
gcm_reject_canary:     times 32 db 0xa5

align 16
gcm_test_req:          times AEAD_REQ_SZ db 0
gcm_owner_state:       times AEAD_OWNER_SZ db 0
gcm_test_ct:           times 16 db 0
gcm_test_tag:          times 16 db 0
gcm_test_plain_out:    times 16 db 0
gcm_bad_tag:           times 16 db 0
gcm_bad_ct:            times 16 db 0
gcm_reject_out:        times 32 db 0
gcm_wrapped:           times 32 db 0
gcm_wrap_tag:          times 16 db 0
gcm_unwrapped:         times 32 db 0

str_gcm_kat_detail:      db "CRYPTO_KAT AES256_GCM_NIST ciphertext=cea7403d4d606b6e074ec5d3baf39d18 tag=d0d1c8a799996bf0265b98b5d48ab919 PASS",13,10,0
str_gcm_kat_marker:      db "[PAOS64] P2 crypto: NIST AES-256-GCM KAT PASS [crypto.aesgcm.kat]",13,10,0
str_dek_wrap_detail:     db "CRYPTO_KAT DEK_WRAP roundtrip=1 wrong_kek=refused PASS",13,10,0
str_aead_reject_detail:  db "CRYPTO_KAT AEAD_REJECT tag_tamper=1 ciphertext_tamper=1 wrong_key=1 invalid_length=1 same_state_duplicate=refused PASS",13,10,0
str_aead_reject_marker:  db "[PAOS64] P2 crypto: AEAD hostile cases rejected [crypto.aead.reject]",13,10,0
str_crypto_standard_fail: db "[PAOS64] P2 crypto: standard AEAD/key-wrap KAT FAIL",13,10,0
