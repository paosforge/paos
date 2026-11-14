;; MODULE core/lib/aes128_gcm
;; LAYER 1
;; EXPORTS aes128_gcm_seal, aes128_gcm_open
;; IMPORTS core/lib/aes256_gcm, core/lib/mem
;; CAPS
;; OWNER saga:net
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; AES-128-GCM for TLS_AES_128_GCM_SHA256.  GHASH, request validation, the
; constant-work tag comparator, and the counter-starts-at-2 contract are reused
; from the canonical AES-GCM module. The AES-128 round-by-round key schedule is
; ported from Classic PaOS task 9105, which ran this sequence on the same Lenovo;
; the block rounds retain the rework's already-proven canonical AES shape.

; aes128_key_expand_local(RDI=key16, RSI=round_keys176).
aes128_key_expand_local:
    push rbx
    push rbp
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
    lea  r14, [rel aes256_sbox]
    lea  r15, [rel aes256_rcon]
    xor  ebp, ebp                        ; round 0..9
.round:
    mov  ebx, ebp
    shl  ebx, 4                          ; previous round offset
    ; temp = SubWord(RotWord(previous[12..15])) XOR Rcon[round].
    movzx eax, byte [r13 + rbx + 13]
    movzx eax, byte [r14 + rax]
    mov  r8b, al
    movzx eax, byte [r13 + rbx + 14]
    movzx eax, byte [r14 + rax]
    mov  r9b, al
    movzx eax, byte [r13 + rbx + 15]
    movzx eax, byte [r14 + rax]
    mov  r10b, al
    movzx eax, byte [r13 + rbx + 12]
    movzx eax, byte [r14 + rax]
    mov  r11b, al
    movzx eax, byte [r15 + rbp]
    xor  r8b, al
    mov  edx, ebx
    add  edx, 16                         ; destination round offset
    mov  al, [r13 + rbx]
    xor  al, r8b
    mov  [r13 + rdx], al
    mov  al, [r13 + rbx + 1]
    xor  al, r9b
    mov  [r13 + rdx + 1], al
    mov  al, [r13 + rbx + 2]
    xor  al, r10b
    mov  [r13 + rdx + 2], al
    mov  al, [r13 + rbx + 3]
    xor  al, r11b
    mov  [r13 + rdx + 3], al
    lea  r8, [r13 + rbx]
    lea  r9, [r13 + rdx]
    mov  ecx, 4
.chain:
    mov  al, [r8 + rcx]
    xor  al, [r9 + rcx - 4]
    mov  [r9 + rcx], al
    inc  ecx
    cmp  ecx, 16
    jb   .chain
    inc  ebp
    cmp  ebp, 10
    jb   .round
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; aes128_encrypt_block_local(RDI=inout16, RSI=round_keys176).
aes128_encrypt_block_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
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
.sub:
    movzx eax, byte [r12 + rcx]
    movzx eax, byte [r14 + rax]
    mov  [r12 + rcx], al
    inc  ecx
    cmp  ecx, 16
    jb   .sub
    call aes256_shift_rows_local
    xor  ebp, ebp
.column:
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
    jnc  .m0
    xor  r10b, 0x1b
.m0:
    xor  al, r10b
    xor  al, r8b
    mov  [rsp], al
    mov  dil, bl
    xor  dil, cl
    movzx r10d, dil
    shl  r10b, 1
    jnc  .m1
    xor  r10b, 0x1b
.m1:
    xor  bl, r10b
    xor  bl, r8b
    mov  [rsp + 1], bl
    mov  dil, cl
    xor  dil, dl
    movzx r10d, dil
    shl  r10b, 1
    jnc  .m2
    xor  r10b, 0x1b
.m2:
    xor  cl, r10b
    xor  cl, r8b
    mov  [rsp + 2], cl
    mov  dil, dl
    xor  dil, r9b
    movzx r10d, dil
    shl  r10b, 1
    jnc  .m3
    xor  r10b, 0x1b
.m3:
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
    jb   .column
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
    cmp  r15d, 10
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
    xor  rax, [r13 + 160]
    mov  [r12], rax
    mov  rax, [r12 + 8]
    xor  rax, [r13 + 168]
    mov  [r12 + 8], rax
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Same GCM context geometry as the shared AES-256 implementation.
aes128_gcm_prep:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx
    mov  rdi, rsi
    lea  rsi, [r12 + GCM_RKEYS]
    call aes128_key_expand_local
    lea  rdi, [r12 + GCM_H]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    lea  rsi, [r12 + GCM_RKEYS]
    call aes128_encrypt_block_local
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
    call aes128_encrypt_block_local
    pop  r13
    pop  r12
    ret

aes128_gcm_ctr:
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
    mov  ebx, 2                          ; SP 800-38D inc32(J0), first data block
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
    call aes128_encrypt_block_local
    mov  rcx, r13
    sub  rcx, r15
    cmp  rcx, 16
    jbe  .count
    mov  ecx, 16
.count:
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

aes128_gcm_seal:
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
    call aes128_gcm_prep
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_INPUT]
    mov  rdx, [r12 + AEAD_INPUT_LEN]
    mov  rcx, [r12 + AEAD_OUTPUT]
    call aes128_gcm_ctr
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

aes128_gcm_open:
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
    call aes128_gcm_prep
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
    jnz  .auth
    mov  rdi, r13
    mov  rsi, [r12 + AEAD_INPUT]
    mov  rdx, [r12 + AEAD_INPUT_LEN]
    mov  rcx, [r12 + AEAD_OUTPUT]
    call aes128_gcm_ctr
    xor  r12d, r12d
    jmp  .wipe
.invalid:
    mov  r12d, -1
    jmp  .wipe
.auth:
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
