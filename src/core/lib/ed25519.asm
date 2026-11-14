;; MODULE core/lib/ed25519
;; LAYER 1
;; EXPORTS ed25519_public_from_seed_context, ed25519_sign_context, ed25519_verify_context, ed_wipe_secret_scratch, ed25519_public_from_seed, ed25519_sign, ed25519_verify, ed25519_selftest
;; IMPORTS core/lib/mem, boot/serial
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; ============================================================================
; RFC 8032 Ed25519.  The field/group sequence is a line-for-line assembly port
; of the compact, public-domain TweetNaCl ref implementation; SHA-512 is the
; FIPS 180-4 compression sequence.  The public ABI is deliberately length-
; bearing and fail-closed:
;
;   ed25519_public_from_seed(seed, seed_len=32, public_out32) -> 0/-1
;   ed25519_sign(seed, seed_len=32, msg, msg_len, sig_out64, sig_len=64) -> 0/-1
;   ed25519_verify(public, public_len=32, msg, msg_len,
;                  signature, sig_len=64) -> 0/-1
;
; Messages are bounded to ED25519_MAX_MESSAGE bytes.  Verification additionally
; requires canonical point encodings, S < group order L, and refuses small-
; order public keys and R points.  Secret hash/scalar scratch is wiped before
; returning.  Static scratch makes this baseline serialized/non-reentrant; the
; shared keep identity service is its serialized owner. Private-context entries
; reuse this identical algorithm with an owned RBP-relative scratch span; see
; gauntlet_v2/docs/ed25519_private_context.md. They are not a cancellation,
; deadline, generation-authorization or secret-work service by themselves.
; ============================================================================

ED25519_MAX_MESSAGE equ 1024
ED25519_CONTEXT_BYTES equ ed_context_end - ed_sha_state
ED_GF_BYTES          equ 128
ED_POINT_BYTES       equ 512

; ---------------------------------------------------------------------------
; SHA-512
; ---------------------------------------------------------------------------

; ed_sha512_compress(RDI=128-byte block), state in ed_sha_state.
ed_sha512_compress:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r12, [rbp + ed_sha_w - ed_sha_state]
    xor  r13d, r13d
.load:
    mov  rax, [rdi + r13*8]
    bswap rax
    mov  [r12 + r13*8], rax
    inc  r13d
    cmp  r13d, 16
    jb   .load
.expand:
    mov  r8, [r12 + r13*8 - 15*8]
    mov  r9, r8
    ror  r8, 1
    ror  r9, 8
    xor  r8, r9
    mov  r9, [r12 + r13*8 - 15*8]
    shr  r9, 7
    xor  r8, r9
    mov  r10, [r12 + r13*8 - 2*8]
    mov  r11, r10
    ror  r10, 19
    ror  r11, 61
    xor  r10, r11
    mov  r11, [r12 + r13*8 - 2*8]
    shr  r11, 6
    xor  r10, r11
    add  r8, [r12 + r13*8 - 16*8]
    add  r8, [r12 + r13*8 - 7*8]
    add  r8, r10
    mov  [r12 + r13*8], r8
    inc  r13d
    cmp  r13d, 80
    jb   .expand

    lea  rsi, [rbp + ed_sha_state - ed_sha_state]
    lea  rdi, [rbp + ed_sha_work - ed_sha_state]
    mov  edx, 64
    call memcpy
    lea  r14, [rbp + ed_sha_work - ed_sha_state]
    lea  r15, [rel ed_sha_k]
    xor  r13d, r13d
.round:
    ; T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
    mov  r8, [r14 + 4*8]
    mov  r9, r8
    ror  r8, 14
    ror  r9, 18
    xor  r8, r9
    mov  r9, [r14 + 4*8]
    ror  r9, 41
    xor  r8, r9
    mov  r9, [r14 + 4*8]
    and  r9, [r14 + 5*8]
    mov  r10, [r14 + 4*8]
    not  r10
    and  r10, [r14 + 6*8]
    xor  r9, r10
    add  r8, r9
    add  r8, [r14 + 7*8]
    add  r8, [r15 + r13*8]
    add  r8, [r12 + r13*8]              ; r8 = T1

    ; T2 = Sigma0(a) + Maj(a,b,c)
    mov  r9, [r14]
    mov  r10, r9
    ror  r9, 28
    ror  r10, 34
    xor  r9, r10
    mov  r10, [r14]
    ror  r10, 39
    xor  r9, r10
    mov  r10, [r14]
    and  r10, [r14 + 8]
    mov  r11, [r14]
    and  r11, [r14 + 16]
    xor  r10, r11
    mov  r11, [r14 + 8]
    and  r11, [r14 + 16]
    xor  r10, r11
    add  r9, r10                        ; r9 = T2

    mov  rax, [r14 + 6*8]
    mov  [r14 + 7*8], rax
    mov  rax, [r14 + 5*8]
    mov  [r14 + 6*8], rax
    mov  rax, [r14 + 4*8]
    mov  [r14 + 5*8], rax
    mov  rax, [r14 + 3*8]
    add  rax, r8
    mov  [r14 + 4*8], rax
    mov  rax, [r14 + 2*8]
    mov  [r14 + 3*8], rax
    mov  rax, [r14 + 1*8]
    mov  [r14 + 2*8], rax
    mov  rax, [r14]
    mov  [r14 + 1*8], rax
    lea  rax, [r8 + r9]
    mov  [r14], rax
    inc  r13d
    cmp  r13d, 80
    jb   .round

    lea  rsi, [rbp + ed_sha_state - ed_sha_state]
    xor  ecx, ecx
.feed:
    mov  rax, [r14 + rcx*8]
    add  [rsi + rcx*8], rax
    inc  ecx
    cmp  ecx, 8
    jb   .feed
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ed_sha512_hash(RDI=input, RSI=len, RDX=out64) -> 0/-1.
ed_sha512_hash:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test r14, r14
    jz   .bad
    test r13, r13
    jz   .ptr_ok
    test r12, r12
    jz   .bad
.ptr_ok:
    lea  rdi, [rbp + ed_sha_state - ed_sha_state]
    lea  rsi, [rel ed_sha_iv]
    mov  edx, 64
    call memcpy
    mov  r15, r13
.blocks:
    cmp  r15, 128
    jb   .tail
    mov  rdi, r12
    call ed_sha512_compress
    add  r12, 128
    sub  r15, 128
    jmp  .blocks
.tail:
    lea  rdi, [rbp + ed_sha_tail - ed_sha_state]
    xor  esi, esi
    mov  edx, 256
    call memset
    test r15, r15
    jz   .pad
    lea  rdi, [rbp + ed_sha_tail - ed_sha_state]
    mov  rsi, r12
    mov  rdx, r15
    call memcpy
.pad:
    lea  rax, [rbp + ed_sha_tail - ed_sha_state]
    mov  byte [rax + r15], 0x80
    mov  ebx, 128
    cmp  r15, 112
    jb   .length
    mov  ebx, 256
.length:
    mov  rax, r13
    shl  rax, 3
    bswap rax
    lea  rcx, [rbp + ed_sha_tail - ed_sha_state]
    mov  [rcx + rbx - 8], rax
    mov  rdi, rcx
    call ed_sha512_compress
    cmp  ebx, 128
    je   .output
    lea  rdi, [rbp + ed_sha_tail - ed_sha_state + 128]
    call ed_sha512_compress
.output:
    lea  rsi, [rbp + ed_sha_state - ed_sha_state]
    xor  ecx, ecx
.out_loop:
    mov  rax, [rsi + rcx*8]
    bswap rax
    mov  [r14 + rcx*8], rax
    inc  ecx
    cmp  ecx, 8
    jb   .out_loop
    xor  eax, eax
    jmp  .done
.bad:
    mov  eax, -1
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Field arithmetic modulo 2^255-19 (16 little-endian 16-bit limbs in qwords).
; ---------------------------------------------------------------------------

ed_gf_copy:
    mov  edx, ED_GF_BYTES
    jmp  memcpy

ed_gf_add:
    xor  ecx, ecx
.loop:
    mov  rax, [rsi + rcx*8]
    add  rax, [rdx + rcx*8]
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

ed_gf_sub:
    xor  ecx, ecx
.loop:
    mov  rax, [rsi + rcx*8]
    sub  rax, [rdx + rcx*8]
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

ed_gf_carry:
    xor  ecx, ecx
.loop:
    mov  rax, [rdi + rcx*8]
    add  rax, 65536
    mov  rdx, rax
    sar  rdx, 16
    mov  r8, rdx
    shl  r8, 16
    sub  rax, r8
    mov  [rdi + rcx*8], rax
    dec  rdx
    cmp  ecx, 15
    je   .last
    add  [rdi + rcx*8 + 8], rdx
    jmp  .next
.last:
    imul rdx, rdx, 38
    add  [rdi], rdx
.next:
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

; Constant-work conditional swap, RDX bit.
ed_gf_select:
    and  edx, 1
    movsxd rdx, edx
    neg  rdx
    xor  ecx, ecx
.loop:
    mov  rax, [rdi + rcx*8]
    xor  rax, [rsi + rcx*8]
    and  rax, rdx
    xor  [rdi + rcx*8], rax
    xor  [rsi + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

ed_gf_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    lea  rdi, [rbp + ed_mul_t - ed_sha_state]
    xor  esi, esi
    mov  edx, 31*8
    call memset
    xor  r8d, r8d
.outer:
    xor  r9d, r9d
.inner:
    mov  rax, [r13 + r8*8]
    imul rax, [r14 + r9*8]
    lea  ecx, [r8d + r9d]
    lea  r10, [rbp + ed_mul_t - ed_sha_state]
    add  [r10 + rcx*8], rax
    inc  r9d
    cmp  r9d, 16
    jb   .inner
    inc  r8d
    cmp  r8d, 16
    jb   .outer
    lea  r10, [rbp + ed_mul_t - ed_sha_state]
    xor  ecx, ecx
.fold:
    mov  rax, [r10 + rcx*8 + 16*8]
    imul rax, rax, 38
    add  [r10 + rcx*8], rax
    inc  ecx
    cmp  ecx, 15
    jb   .fold
    mov  rdi, r12
    mov  rsi, r10
    mov  edx, ED_GF_BYTES
    call memcpy
    mov  rdi, r12
    call ed_gf_carry
    mov  rdi, r12
    call ed_gf_carry
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ed_gf_square:
    mov  rdx, rsi
    jmp  ed_gf_mul

ed_gf_inverse:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_pow_c - ed_sha_state]
    mov  rsi, r13
    call ed_gf_copy
    mov  r14d, 253
.loop:
    lea  rdi, [rbp + ed_pow_c - ed_sha_state]
    mov  rsi, rdi
    call ed_gf_square
    cmp  r14d, 2
    je   .next
    cmp  r14d, 4
    je   .next
    lea  rdi, [rbp + ed_pow_c - ed_sha_state]
    mov  rsi, rdi
    mov  rdx, r13
    call ed_gf_mul
.next:
    dec  r14d
    jns  .loop
    mov  rdi, r12
    lea  rsi, [rbp + ed_pow_c - ed_sha_state]
    call ed_gf_copy
    pop  r14
    pop  r13
    pop  r12
    ret

ed_gf_pow2523:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_pow_c - ed_sha_state]
    mov  rsi, r13
    call ed_gf_copy
    mov  r14d, 250
.loop:
    lea  rdi, [rbp + ed_pow_c - ed_sha_state]
    mov  rsi, rdi
    call ed_gf_square
    cmp  r14d, 1
    je   .next
    lea  rdi, [rbp + ed_pow_c - ed_sha_state]
    mov  rsi, rdi
    mov  rdx, r13
    call ed_gf_mul
.next:
    dec  r14d
    jns  .loop
    mov  rdi, r12
    lea  rsi, [rbp + ed_pow_c - ed_sha_state]
    call ed_gf_copy
    pop  r14
    pop  r13
    pop  r12
    ret

ed_gf_pack:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_pack_t - ed_sha_state]
    mov  rsi, r13
    call ed_gf_copy
    lea  rdi, [rbp + ed_pack_t - ed_sha_state]
    call ed_gf_carry
    lea  rdi, [rbp + ed_pack_t - ed_sha_state]
    call ed_gf_carry
    lea  rdi, [rbp + ed_pack_t - ed_sha_state]
    call ed_gf_carry
    xor  ebx, ebx
.reduce:
    lea  r14, [rbp + ed_pack_m - ed_sha_state]
    lea  r10, [rbp + ed_pack_t - ed_sha_state]
    mov  rax, [r10]
    sub  rax, 0xffed
    mov  [r14], rax
    mov  ecx, 1
.borrow:
    mov  rdx, [r14 + rcx*8 - 8]
    sar  rdx, 16
    and  edx, 1
    and  qword [r14 + rcx*8 - 8], 0xffff
    mov  rax, [r10 + rcx*8]
    sub  rax, 0xffff
    sub  rax, rdx
    mov  [r14 + rcx*8], rax
    inc  ecx
    cmp  ecx, 15
    jb   .borrow
    mov  rdx, [r14 + 14*8]
    sar  rdx, 16
    and  edx, 1
    and  qword [r14 + 14*8], 0xffff
    mov  rax, [r10 + 15*8]
    sub  rax, 0x7fff
    sub  rax, rdx
    mov  [r14 + 15*8], rax
    sar  rax, 16
    and  eax, 1
    xor  eax, 1
    lea  rdi, [rbp + ed_pack_t - ed_sha_state]
    lea  rsi, [rbp + ed_pack_m - ed_sha_state]
    mov  edx, eax
    call ed_gf_select
    inc  ebx
    cmp  ebx, 2
    jb   .reduce
    lea  r10, [rbp + ed_pack_t - ed_sha_state]
    xor  ecx, ecx
.emit:
    mov  rax, [r10 + rcx*8]
    mov  [r12 + rcx*2], al
    shr  rax, 8
    mov  [r12 + rcx*2 + 1], al
    inc  ecx
    cmp  ecx, 16
    jb   .emit
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ed_gf_unpack:
    xor  ecx, ecx
.loop:
    movzx eax, byte [rsi + rcx*2]
    movzx edx, byte [rsi + rcx*2 + 1]
    shl  edx, 8
    or   eax, edx
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    and  qword [rdi + 15*8], 0x7fff
    ret

ed_verify32:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    movzx edx, byte [rdi + rcx]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 32
    jb   .loop
    movzx eax, al
    neg  eax
    sbb  eax, eax
    ret                                  ; 0 equal, -1 unequal

ed_gf_equal:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_equal_a - ed_sha_state]
    mov  rsi, r12
    call ed_gf_pack
    lea  rdi, [rbp + ed_equal_b - ed_sha_state]
    mov  rsi, r13
    call ed_gf_pack
    lea  rdi, [rbp + ed_equal_a - ed_sha_state]
    lea  rsi, [rbp + ed_equal_b - ed_sha_state]
    call ed_verify32
    test eax, eax
    setz al
    movzx eax, al
    pop  r13
    pop  r12
    ret

ed_gf_parity:
    lea  rax, [rbp + ed_parity_tmp - ed_sha_state]
    xchg rdi, rax
    mov  rsi, rax
    call ed_gf_pack
    movzx eax, byte [rbp + ed_parity_tmp - ed_sha_state]
    and  eax, 1
    ret

; ---------------------------------------------------------------------------
; Edwards group operations. Point layout: X,Y,Z,T, four gf values.
; ---------------------------------------------------------------------------

ed_point_add:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_add_a - ed_sha_state]
    lea  rsi, [r12 + ED_GF_BYTES]
    mov  rdx, r12
    call ed_gf_sub
    lea  rdi, [rbp + ed_add_b - ed_sha_state]
    lea  rsi, [r12 + ED_GF_BYTES]
    mov  rdx, r12
    call ed_gf_add
    lea  rdi, [rbp + ed_add_c - ed_sha_state]
    lea  rsi, [r13 + ED_GF_BYTES]
    mov  rdx, r13
    call ed_gf_add
    lea  rdi, [rbp + ed_add_d - ed_sha_state]
    lea  rsi, [r13 + ED_GF_BYTES]
    mov  rdx, r13
    call ed_gf_sub
    lea  rdi, [rbp + ed_add_a - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_add_d - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_add_b - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_add_c - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_add_c - ed_sha_state]
    lea  rsi, [r12 + 3*ED_GF_BYTES]
    lea  rdx, [r13 + 3*ED_GF_BYTES]
    call ed_gf_mul
    lea  rdi, [rbp + ed_add_c - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rel ed_const_d2]
    call ed_gf_mul
    lea  rdi, [rbp + ed_add_d - ed_sha_state]
    lea  rsi, [r12 + 2*ED_GF_BYTES]
    lea  rdx, [r13 + 2*ED_GF_BYTES]
    call ed_gf_mul
    lea  rdi, [rbp + ed_add_d - ed_sha_state]
    mov  rsi, rdi
    mov  rdx, rdi
    call ed_gf_add
    lea  rdi, [rbp + ed_add_e - ed_sha_state]
    lea  rsi, [rbp + ed_add_b - ed_sha_state]
    lea  rdx, [rbp + ed_add_a - ed_sha_state]
    call ed_gf_sub
    lea  rdi, [rbp + ed_add_f - ed_sha_state]
    lea  rsi, [rbp + ed_add_d - ed_sha_state]
    lea  rdx, [rbp + ed_add_c - ed_sha_state]
    call ed_gf_sub
    lea  rdi, [rbp + ed_add_g - ed_sha_state]
    lea  rsi, [rbp + ed_add_d - ed_sha_state]
    lea  rdx, [rbp + ed_add_c - ed_sha_state]
    call ed_gf_add
    lea  rdi, [rbp + ed_add_h - ed_sha_state]
    lea  rsi, [rbp + ed_add_b - ed_sha_state]
    lea  rdx, [rbp + ed_add_a - ed_sha_state]
    call ed_gf_add
    mov  rdi, r12
    lea  rsi, [rbp + ed_add_e - ed_sha_state]
    lea  rdx, [rbp + ed_add_f - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [r12 + ED_GF_BYTES]
    lea  rsi, [rbp + ed_add_h - ed_sha_state]
    lea  rdx, [rbp + ed_add_g - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [r12 + 2*ED_GF_BYTES]
    lea  rsi, [rbp + ed_add_g - ed_sha_state]
    lea  rdx, [rbp + ed_add_f - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [r12 + 3*ED_GF_BYTES]
    lea  rsi, [rbp + ed_add_e - ed_sha_state]
    lea  rdx, [rbp + ed_add_h - ed_sha_state]
    call ed_gf_mul
    pop  r13
    pop  r12
    ret

ed_point_cswap:
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    xor  r15d, r15d
.loop:
    mov  eax, r15d
    shl  rax, 7
    lea  rdi, [r12 + rax]
    lea  rsi, [r13 + rax]
    mov  rdx, r14
    call ed_gf_select
    inc  r15d
    cmp  r15d, 4
    jb   .loop
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

ed_point_scalarmult:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rdi, r12
    lea  rsi, [rel ed_const_zero]
    call ed_gf_copy
    lea  rdi, [r12 + ED_GF_BYTES]
    lea  rsi, [rel ed_const_one]
    call ed_gf_copy
    lea  rdi, [r12 + 2*ED_GF_BYTES]
    lea  rsi, [rel ed_const_one]
    call ed_gf_copy
    lea  rdi, [r12 + 3*ED_GF_BYTES]
    lea  rsi, [rel ed_const_zero]
    call ed_gf_copy
    mov  r15d, 255
.loop:
    mov  eax, r15d
    shr  eax, 3
    movzx ebx, byte [r14 + rax]
    mov  ecx, r15d
    and  ecx, 7
    shr  ebx, cl
    and  ebx, 1
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebx
    call ed_point_cswap
    mov  rdi, r13
    mov  rsi, r12
    call ed_point_add
    mov  rdi, r12
    mov  rsi, r12
    call ed_point_add
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebx
    call ed_point_cswap
    dec  r15d
    jns  .loop
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ed_point_scalarbase:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_point_base - ed_sha_state]
    lea  rsi, [rel ed_const_x]
    call ed_gf_copy
    lea  rdi, [rbp + ed_point_base - ed_sha_state + ED_GF_BYTES]
    lea  rsi, [rel ed_const_y]
    call ed_gf_copy
    lea  rdi, [rbp + ed_point_base - ed_sha_state + 2*ED_GF_BYTES]
    lea  rsi, [rel ed_const_one]
    call ed_gf_copy
    lea  rdi, [rbp + ed_point_base - ed_sha_state + 3*ED_GF_BYTES]
    lea  rsi, [rel ed_const_x]
    lea  rdx, [rel ed_const_y]
    call ed_gf_mul
    mov  rdi, r12
    lea  rsi, [rbp + ed_point_base - ed_sha_state]
    mov  rdx, r13
    call ed_point_scalarmult
    pop  r13
    pop  r12
    ret

ed_point_pack:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rbp + ed_point_zi - ed_sha_state]
    lea  rsi, [r13 + 2*ED_GF_BYTES]
    call ed_gf_inverse
    lea  rdi, [rbp + ed_point_x - ed_sha_state]
    mov  rsi, r13
    lea  rdx, [rbp + ed_point_zi - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_point_y - ed_sha_state]
    lea  rsi, [r13 + ED_GF_BYTES]
    lea  rdx, [rbp + ed_point_zi - ed_sha_state]
    call ed_gf_mul
    mov  rdi, r12
    lea  rsi, [rbp + ed_point_y - ed_sha_state]
    call ed_gf_pack
    lea  rdi, [rbp + ed_point_x - ed_sha_state]
    call ed_gf_parity
    shl  al, 7
    xor  [r12 + 31], al
    pop  r13
    pop  r12
    ret

; Decode and return the NEGATIVE point, matching the RFC verification equation.
; Strict re-encoding rejects y>=p and the x=0/sign=1 ambiguity.
ed_point_unpackneg:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [r12 + 2*ED_GF_BYTES]
    lea  rsi, [rel ed_const_one]
    call ed_gf_copy
    lea  rdi, [r12 + ED_GF_BYTES]
    mov  rsi, r13
    call ed_gf_unpack
    lea  rdi, [rbp + ed_u_num - ed_sha_state]
    lea  rsi, [r12 + ED_GF_BYTES]
    call ed_gf_square
    lea  rdi, [rbp + ed_u_den - ed_sha_state]
    lea  rsi, [rbp + ed_u_num - ed_sha_state]
    lea  rdx, [rel ed_const_d]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_num - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [r12 + 2*ED_GF_BYTES]
    call ed_gf_sub
    lea  rdi, [rbp + ed_u_den - ed_sha_state]
    lea  rsi, [r12 + 2*ED_GF_BYTES]
    mov  rdx, rdi
    call ed_gf_add
    lea  rdi, [rbp + ed_u_den2 - ed_sha_state]
    lea  rsi, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_square
    lea  rdi, [rbp + ed_u_den4 - ed_sha_state]
    lea  rsi, [rbp + ed_u_den2 - ed_sha_state]
    call ed_gf_square
    lea  rdi, [rbp + ed_u_den6 - ed_sha_state]
    lea  rsi, [rbp + ed_u_den4 - ed_sha_state]
    lea  rdx, [rbp + ed_u_den2 - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_t - ed_sha_state]
    lea  rsi, [rbp + ed_u_den6 - ed_sha_state]
    lea  rdx, [rbp + ed_u_num - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_t - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_t - ed_sha_state]
    mov  rsi, rdi
    call ed_gf_pow2523
    lea  rdi, [rbp + ed_u_t - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_u_num - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_t - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_t - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_mul
    mov  rdi, r12
    lea  rsi, [rbp + ed_u_t - ed_sha_state]
    lea  rdx, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_chk - ed_sha_state]
    mov  rsi, r12
    call ed_gf_square
    lea  rdi, [rbp + ed_u_chk - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_chk - ed_sha_state]
    lea  rsi, [rbp + ed_u_num - ed_sha_state]
    call ed_gf_equal
    test eax, eax
    jnz  .root_ok
    mov  rdi, r12
    mov  rsi, r12
    lea  rdx, [rel ed_const_i]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_chk - ed_sha_state]
    mov  rsi, r12
    call ed_gf_square
    lea  rdi, [rbp + ed_u_chk - ed_sha_state]
    mov  rsi, rdi
    lea  rdx, [rbp + ed_u_den - ed_sha_state]
    call ed_gf_mul
    lea  rdi, [rbp + ed_u_chk - ed_sha_state]
    lea  rsi, [rbp + ed_u_num - ed_sha_state]
    call ed_gf_equal
    test eax, eax
    jz   .fail
.root_ok:
    mov  rdi, r12
    call ed_gf_parity
    movzx ecx, byte [r13 + 31]
    shr  ecx, 7
    cmp  eax, ecx
    jne  .sign_ok
    mov  rdi, r12
    lea  rsi, [rel ed_const_zero]
    mov  rdx, r12
    call ed_gf_sub
.sign_ok:
    lea  rdi, [r12 + 3*ED_GF_BYTES]
    mov  rsi, r12
    lea  rdx, [r12 + ED_GF_BYTES]
    call ed_gf_mul

    ; Reconstruct +A from returned -A and demand byte-for-byte canonical input.
    lea  rdi, [rbp + ed_point_chk - ed_sha_state]
    lea  rsi, [rel ed_const_zero]
    mov  rdx, r12
    call ed_gf_sub
    lea  rdi, [rbp + ed_point_chk - ed_sha_state + ED_GF_BYTES]
    lea  rsi, [r12 + ED_GF_BYTES]
    call ed_gf_copy
    lea  rdi, [rbp + ed_point_chk - ed_sha_state + 2*ED_GF_BYTES]
    lea  rsi, [r12 + 2*ED_GF_BYTES]
    call ed_gf_copy
    lea  rdi, [rbp + ed_point_chk - ed_sha_state + 3*ED_GF_BYTES]
    lea  rsi, [rel ed_const_zero]
    lea  rdx, [r12 + 3*ED_GF_BYTES]
    call ed_gf_sub
    lea  rdi, [rbp + ed_encoded_chk - ed_sha_state]
    lea  rsi, [rbp + ed_point_chk - ed_sha_state]
    call ed_point_pack
    lea  rdi, [rbp + ed_encoded_chk - ed_sha_state]
    mov  rsi, r13
    call ed_verify32
    test eax, eax
    jnz  .fail
    xor  eax, eax
    jmp  .done
.fail:
    mov  eax, -1
.done:
    pop  r14
    pop  r13
    pop  r12
    ret

ed_point_small_order:
    push r12
    mov  r12, rdi
    lea  rdi, [rbp + ed_point_tmp - ed_sha_state]
    mov  rsi, r12
    mov  edx, ED_POINT_BYTES
    call memcpy
    lea  rdi, [rbp + ed_point_tmp - ed_sha_state]
    mov  rsi, rdi
    call ed_point_add
    lea  rdi, [rbp + ed_point_tmp - ed_sha_state]
    mov  rsi, rdi
    call ed_point_add
    lea  rdi, [rbp + ed_point_tmp - ed_sha_state]
    mov  rsi, rdi
    call ed_point_add
    lea  rdi, [rbp + ed_encoded_chk - ed_sha_state]
    lea  rsi, [rbp + ed_point_tmp - ed_sha_state]
    call ed_point_pack
    lea  rdi, [rbp + ed_encoded_chk - ed_sha_state]
    lea  rsi, [rel ed_identity_encoding]
    call ed_verify32
    test eax, eax
    setz al
    movzx eax, al
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Scalar reduction modulo group order L.
; ---------------------------------------------------------------------------

ed_mod_l:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                       ; output bytes
    mov  r13, rsi                       ; signed qword x[64]
    lea  r15, [rel ed_order_l]
    mov  r14d, 63
.outer:
    xor  ebx, ebx                       ; scalar-reduction carry
    mov  ecx, r14d
    sub  ecx, 32                        ; j
    mov  r8d, r14d
    sub  r8d, 12                        ; k (exclusive)
.inner:
    movsxd rbx, ebx
    mov  rax, [r13 + rcx*8]
    add  rax, rbx
    mov  r9, [r13 + r14*8]
    mov  edx, ecx
    sub  edx, r14d
    add  edx, 32
    movzx r10d, byte [r15 + rdx]
    imul r9, r10
    shl  r9, 4
    sub  rax, r9
    mov  r11, rax
    add  r11, 128
    sar  r11, 8
    mov  ebx, r11d
    shl  r11, 8
    sub  rax, r11
    mov  [r13 + rcx*8], rax
    inc  ecx
    cmp  ecx, r8d
    jl   .inner
    movsxd rbx, ebx
    add  [r13 + rcx*8], rbx
    mov  qword [r13 + r14*8], 0
    dec  r14d
    cmp  r14d, 32
    jge  .outer

    xor  ebx, ebx
    mov  r14, [r13 + 31*8]
    sar  r14, 4
    xor  ecx, ecx
.fold:
    movsxd rbx, ebx
    mov  rax, [r13 + rcx*8]
    add  rax, rbx
    movzx edx, byte [r15 + rcx]
    imul rdx, r14
    sub  rax, rdx
    mov  rbx, rax
    sar  rbx, 8
    and  eax, 255
    mov  [r13 + rcx*8], rax
    inc  ecx
    cmp  ecx, 32
    jb   .fold
    xor  ecx, ecx
.subtract:
    movzx eax, byte [r15 + rcx]
    imul rax, rbx
    sub  [r13 + rcx*8], rax
    inc  ecx
    cmp  ecx, 32
    jb   .subtract
    xor  ecx, ecx
.emit:
    mov  rax, [r13 + rcx*8]
    mov  rdx, rax
    sar  rdx, 8
    add  [r13 + rcx*8 + 8], rdx
    mov  [r12 + rcx], al
    inc  ecx
    cmp  ecx, 32
    jb   .emit
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ed_reduce:
    push r12
    mov  r12, rdi
    lea  rdi, [rbp + ed_scalar_x - ed_sha_state]
    xor  esi, esi
    mov  edx, 64*8
    call memset
    lea  r8, [rbp + ed_scalar_x - ed_sha_state]
    xor  ecx, ecx
.copy:
    movzx eax, byte [r12 + rcx]
    mov  [r8 + rcx*8], rax
    inc  ecx
    cmp  ecx, 64
    jb   .copy
    mov  rdi, r12
    lea  rsi, [rbp + ed_scalar_x - ed_sha_state]
    call ed_mod_l
    pop  r12
    ret

ed_scalar_canonical:
    mov  ecx, 31
    lea  rdx, [rel ed_order_l]
.loop:
    movzx eax, byte [rdi + rcx]
    movzx r8d, byte [rdx + rcx]
    cmp  eax, r8d
    jb   .yes
    ja   .no
    dec  ecx
    jns  .loop
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; ---------------------------------------------------------------------------
; Public API
; ---------------------------------------------------------------------------

; Private trusted-kernel ABI: the ordinary API inputs plus RAX=context,
; R10=ED25519_CONTEXT_BYTES. The caller owns the entire mapped span exclusively.
; Refuse malformed/aliased spans before touching memory; once admitted, wipe
; ALL private scratch on every ordinary return. No shared context pointer or
; mutable global selector is installed. BSP-only ownership remains required.
;
; RAX=context and R11=context end survive validation. Ordinary ABI args survive.
ed_context_validate:
    test rax, rax
    jz   .bad
    test al, 15
    jnz  .bad
    cmp  r10, ED25519_CONTEXT_BYTES
    jne  .bad
    mov  r11, rax
    add  r11, ED25519_CONTEXT_BYTES
    jc   .bad
    lea  r10, [rel ed_context_end]
    cmp  rax, r10
    jae  .ok
    lea  r10, [rel ed_sha_state]
    cmp  r11, r10
    ja   .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; R10=buffer start, RBX=length, RAX/R11=context [start,end).
; Zero-length messages may be NULL; nonempty spans must not wrap or alias.
ed_context_disjoint:
    test rbx, rbx
    jz   .ok
    test r10, r10
    jz   .bad
    add  rbx, r10
    jc   .bad
    cmp  r10, r11
    jae  .ok
    cmp  rbx, rax
    ja   .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

ed25519_public_from_seed_context:
    push rbx
    push rbp
    sub  rsp, 8
    mov  rbp, rax
    call ed_context_validate
    jc   .bad
    cmp  rsi, 32
    jne  .bad
    mov  r10, rdi
    mov  ebx, 32
    call ed_context_disjoint
    jc   .bad
    mov  r10, rdx
    mov  ebx, 32
    call ed_context_disjoint
    jc   .bad
    call ed25519_public_from_seed_impl
    ; The result is public/status only. The caller's seed/input remain its
    ; property; the future work owner must erase its seed and abandoned stack
    ; before cancellation ACK or any public result commit.
    mov  r10d, eax
    mov  rdi, rbp
    mov  ecx, ED25519_CONTEXT_BYTES
    xor  eax, eax
    cld
    rep  stosb
    mov  eax, r10d
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  rbp
    pop  rbx
    ret

ed25519_sign_context:
    push rbx
    push rbp
    sub  rsp, 8
    mov  rbp, rax
    call ed_context_validate
    jc   .bad
    cmp  rsi, 32
    jne  .bad
    cmp  r9, 64
    jne  .bad
    cmp  rcx, ED25519_MAX_MESSAGE
    ja   .bad
    mov  r10, rdi
    mov  ebx, 32
    call ed_context_disjoint
    jc   .bad
    mov  r10, rdx
    mov  rbx, rcx
    call ed_context_disjoint
    jc   .bad
    mov  r10, r8
    mov  ebx, 64
    call ed_context_disjoint
    jc   .bad
    call ed25519_sign_impl
    ; The result is public/status only. The caller's seed/input remain its
    ; property; the future work owner must erase its seed and abandoned stack
    ; before cancellation ACK or any public result commit.
    mov  r10d, eax
    mov  rdi, rbp
    mov  ecx, ED25519_CONTEXT_BYTES
    xor  eax, eax
    cld
    rep  stosb
    mov  eax, r10d
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  rbp
    pop  rbx
    ret

ed25519_verify_context:
    push rbx
    push rbp
    sub  rsp, 8
    mov  rbp, rax
    call ed_context_validate
    jc   .bad
    cmp  rsi, 32
    jne  .bad
    cmp  r9, 64
    jne  .bad
    cmp  rcx, ED25519_MAX_MESSAGE
    ja   .bad
    mov  r10, rdi
    mov  ebx, 32
    call ed_context_disjoint
    jc   .bad
    mov  r10, rdx
    mov  rbx, rcx
    call ed_context_disjoint
    jc   .bad
    mov  r10, r8
    mov  ebx, 64
    call ed_context_disjoint
    jc   .bad
    call ed25519_verify_impl
    ; The result is public/status only. The caller's seed/input remain its
    ; property; the future work owner must erase its seed and abandoned stack
    ; before cancellation ACK or any public result commit.
    mov  r10d, eax
    mov  rdi, rbp
    mov  ecx, ED25519_CONTEXT_BYTES
    xor  eax, eax
    cld
    rep  stosb
    mov  eax, r10d
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  rbp
    pop  rbx
    ret


ed25519_public_from_seed:
    push rbp
    lea  rbp, [rel ed_sha_state]
    call ed25519_public_from_seed_impl
    pop  rbp
    ret

ed25519_public_from_seed_impl:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx
    test r12, r12
    jz   .bad
    cmp  rsi, 32
    jne  .bad
    test r13, r13
    jz   .bad
    mov  rdi, r12
    mov  esi, 32
    lea  rdx, [rbp + ed_secret_hash - ed_sha_state]
    call ed_sha512_hash
    test eax, eax
    jnz  .bad
    and  byte [rbp + ed_secret_hash - ed_sha_state], 248
    and  byte [rbp + ed_secret_hash - ed_sha_state + 31], 127
    or   byte [rbp + ed_secret_hash - ed_sha_state + 31], 64
    lea  rdi, [rbp + ed_point_p - ed_sha_state]
    lea  rsi, [rbp + ed_secret_hash - ed_sha_state]
    call ed_point_scalarbase
    mov  rdi, r13
    lea  rsi, [rbp + ed_point_p - ed_sha_state]
    call ed_point_pack
    call ed_wipe_secret_scratch_impl
    xor  eax, eax
    jmp  .done
.bad:
    mov  eax, -1
.done:
    pop  r13
    pop  r12
    ret

ed25519_sign:
    push rbp
    lea  rbp, [rel ed_sha_state]
    call ed25519_sign_impl
    pop  rbp
    ret

ed25519_sign_impl:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                       ; seed
    mov  r13, rdx                       ; message
    mov  r14, rcx                       ; message length
    mov  r15, r8                        ; signature
    test r12, r12
    jz   .bad
    cmp  rsi, 32
    jne  .bad
    test r14, r14
    jz   .msg_ok
    test r13, r13
    jz   .bad
.msg_ok:
    cmp  r14, ED25519_MAX_MESSAGE
    ja   .bad
    test r15, r15
    jz   .bad
    cmp  r9, 64
    jne  .bad
    mov  rdi, r12
    mov  esi, 32
    lea  rdx, [rbp + ed_secret_hash - ed_sha_state]
    call ed_sha512_hash
    test eax, eax
    jnz  .bad
    and  byte [rbp + ed_secret_hash - ed_sha_state], 248
    and  byte [rbp + ed_secret_hash - ed_sha_state + 31], 127
    or   byte [rbp + ed_secret_hash - ed_sha_state + 31], 64
    lea  rdi, [rbp + ed_point_p - ed_sha_state]
    lea  rsi, [rbp + ed_secret_hash - ed_sha_state]
    call ed_point_scalarbase
    lea  rdi, [rbp + ed_public_tmp - ed_sha_state]
    lea  rsi, [rbp + ed_point_p - ed_sha_state]
    call ed_point_pack

    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    lea  rsi, [rbp + ed_secret_hash - ed_sha_state + 32]
    mov  edx, 32
    call memcpy
    test r14, r14
    jz   .nonce_hash
    lea  rdi, [rbp + ed_hash_input - ed_sha_state + 32]
    mov  rsi, r13
    mov  rdx, r14
    call memcpy
.nonce_hash:
    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    lea  rsi, [r14 + 32]
    lea  rdx, [rbp + ed_scalar_r - ed_sha_state]
    call ed_sha512_hash
    lea  rdi, [rbp + ed_scalar_r - ed_sha_state]
    call ed_reduce
    lea  rdi, [rbp + ed_point_p - ed_sha_state]
    lea  rsi, [rbp + ed_scalar_r - ed_sha_state]
    call ed_point_scalarbase
    mov  rdi, r15
    lea  rsi, [rbp + ed_point_p - ed_sha_state]
    call ed_point_pack

    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    mov  rsi, r15
    mov  edx, 32
    call memcpy
    lea  rdi, [rbp + ed_hash_input - ed_sha_state + 32]
    lea  rsi, [rbp + ed_public_tmp - ed_sha_state]
    mov  edx, 32
    call memcpy
    test r14, r14
    jz   .challenge
    lea  rdi, [rbp + ed_hash_input - ed_sha_state + 64]
    mov  rsi, r13
    mov  rdx, r14
    call memcpy
.challenge:
    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    lea  rsi, [r14 + 64]
    lea  rdx, [rbp + ed_scalar_h - ed_sha_state]
    call ed_sha512_hash
    lea  rdi, [rbp + ed_scalar_h - ed_sha_state]
    call ed_reduce

    lea  rdi, [rbp + ed_scalar_x - ed_sha_state]
    xor  esi, esi
    mov  edx, 64*8
    call memset
    lea  r10, [rbp + ed_scalar_r - ed_sha_state]
    lea  r11, [rbp + ed_scalar_x - ed_sha_state]
    xor  ecx, ecx
.copy_r:
    movzx eax, byte [r10 + rcx]
    mov  [r11 + rcx*8], rax
    inc  ecx
    cmp  ecx, 32
    jb   .copy_r
    lea  r10, [rbp + ed_scalar_h - ed_sha_state]
    lea  r11, [rbp + ed_secret_hash - ed_sha_state]
    lea  rsi, [rbp + ed_scalar_x - ed_sha_state]
    xor  ecx, ecx
.mul_i:
    xor  edx, edx
.mul_j:
    movzx eax, byte [r10 + rcx]
    movzx r8d, byte [r11 + rdx]
    imul rax, r8
    lea  r9d, [ecx + edx]
    add  [rsi + r9*8], rax
    inc  edx
    cmp  edx, 32
    jb   .mul_j
    inc  ecx
    cmp  ecx, 32
    jb   .mul_i
    lea  rdi, [r15 + 32]
    lea  rsi, [rbp + ed_scalar_x - ed_sha_state]
    call ed_mod_l
    call ed_wipe_secret_scratch_impl
    xor  eax, eax
    jmp  .done
.bad:
    mov  eax, -1
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ed25519_verify:
    push rbp
    lea  rbp, [rel ed_sha_state]
    call ed25519_verify_impl
    pop  rbp
    ret

ed25519_verify_impl:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                       ; public
    mov  r13, rdx                       ; message
    mov  r14, rcx                       ; message length
    mov  r15, r8                        ; signature
    test r12, r12
    jz   .bad
    cmp  rsi, 32
    jne  .bad
    test r14, r14
    jz   .msg_ok
    test r13, r13
    jz   .bad
.msg_ok:
    cmp  r14, ED25519_MAX_MESSAGE
    ja   .bad
    test r15, r15
    jz   .bad
    cmp  r9, 64
    jne  .bad
    lea  rdi, [rbp + ed_point_q - ed_sha_state]
    mov  rsi, r12
    call ed_point_unpackneg
    test eax, eax
    jnz  .bad
    lea  rdi, [rbp + ed_point_q - ed_sha_state]
    call ed_point_small_order
    test eax, eax
    jnz  .bad
    lea  rdi, [rbp + ed_point_r - ed_sha_state]
    mov  rsi, r15
    call ed_point_unpackneg
    test eax, eax
    jnz  .bad
    lea  rdi, [rbp + ed_point_r - ed_sha_state]
    call ed_point_small_order
    test eax, eax
    jnz  .bad
    lea  rdi, [r15 + 32]
    call ed_scalar_canonical
    test eax, eax
    jz   .bad

    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    mov  rsi, r15
    mov  edx, 32
    call memcpy
    lea  rdi, [rbp + ed_hash_input - ed_sha_state + 32]
    mov  rsi, r12
    mov  edx, 32
    call memcpy
    test r14, r14
    jz   .hash
    lea  rdi, [rbp + ed_hash_input - ed_sha_state + 64]
    mov  rsi, r13
    mov  rdx, r14
    call memcpy
.hash:
    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    lea  rsi, [r14 + 64]
    lea  rdx, [rbp + ed_scalar_h - ed_sha_state]
    call ed_sha512_hash
    lea  rdi, [rbp + ed_scalar_h - ed_sha_state]
    call ed_reduce
    lea  rdi, [rbp + ed_point_p - ed_sha_state]
    lea  rsi, [rbp + ed_point_q - ed_sha_state]
    lea  rdx, [rbp + ed_scalar_h - ed_sha_state]
    call ed_point_scalarmult
    lea  rdi, [rbp + ed_point_q - ed_sha_state]
    lea  rsi, [r15 + 32]
    call ed_point_scalarbase
    lea  rdi, [rbp + ed_point_p - ed_sha_state]
    lea  rsi, [rbp + ed_point_q - ed_sha_state]
    call ed_point_add
    lea  rdi, [rbp + ed_encoded_chk - ed_sha_state]
    lea  rsi, [rbp + ed_point_p - ed_sha_state]
    call ed_point_pack
    lea  rdi, [rbp + ed_encoded_chk - ed_sha_state]
    mov  rsi, r15
    call ed_verify32
    test eax, eax
    jnz  .bad
    xor  ebx, ebx
    jmp  .done
.bad:
    mov  ebx, -1
.done:
    lea  rdi, [rbp + ed_scalar_h - ed_sha_state]
    xor  esi, esi
    mov  edx, 64
    call memset
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ed_wipe_secret_scratch:
    push rbp
    lea  rbp, [rel ed_sha_state]
    call ed_wipe_secret_scratch_impl
    pop  rbp
    ret

ed_wipe_secret_scratch_impl:
    ; SHA-512's final state and schedule contain the expanded seed digest after
    ; public-key derivation/signing; treat them as secret scratch too.
    lea  rdi, [rbp + ed_sha_state - ed_sha_state]
    xor  esi, esi
    mov  edx, 1024                     ; state + work + W[80] + two tail blocks
    call memset
    lea  rdi, [rbp + ed_mul_t - ed_sha_state]
    xor  esi, esi
    mov  edx, ed_secret_hash - ed_mul_t ; field/point intermediates
    call memset
    lea  rdi, [rbp + ed_secret_hash - ed_sha_state]
    xor  esi, esi
    mov  edx, 64
    call memset
    lea  rdi, [rbp + ed_scalar_r - ed_sha_state]
    xor  esi, esi
    mov  edx, 64
    call memset
    lea  rdi, [rbp + ed_scalar_h - ed_sha_state]
    xor  esi, esi
    mov  edx, 64
    call memset
    lea  rdi, [rbp + ed_scalar_x - ed_sha_state]
    xor  esi, esi
    mov  edx, 64*8
    call memset
    lea  rdi, [rbp + ed_hash_input - ed_sha_state]
    xor  esi, esi
    mov  edx, ED25519_MAX_MESSAGE + 64
    call memset
    ret

; ---------------------------------------------------------------------------
; RFC 8032 published-vector and hostile-input proof.
; ---------------------------------------------------------------------------

ed25519_selftest:
    push r12
    ; RFC 8032 section 7.1 TEST 1 (empty message).
    lea  r12, [rel str_ed_stage_pub1_api]
    lea  rdi, [rel ed_test_seed1]
    mov  esi, 32
    lea  rdx, [rel ed_test_public]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_pub1_exact]
    lea  rdi, [rel ed_test_public]
    lea  rsi, [rel ed_test_public1]
    call ed_verify32
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_sig1_api]
    lea  rdi, [rel ed_test_seed1]
    mov  esi, 32
    xor  edx, edx
    xor  ecx, ecx
    lea  r8, [rel ed_test_signature]
    mov  r9d, 64
    call ed25519_sign
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_sig1_exact]
    lea  rdi, [rel ed_test_signature]
    lea  rsi, [rel ed_test_signature1]
    mov  edx, 64
    call memcmp
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_verify1]
    lea  rdi, [rel ed_test_public1]
    mov  esi, 32
    xor  edx, edx
    xor  ecx, ecx
    lea  r8, [rel ed_test_signature1]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jnz  .fail

    ; RFC 8032 section 7.1 TEST 2 (one-byte message), independently exact.
    lea  r12, [rel str_ed_stage_pub2_api]
    lea  rdi, [rel ed_test_seed2]
    mov  esi, 32
    lea  rdx, [rel ed_test_public]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_pub2_exact]
    lea  rdi, [rel ed_test_public]
    lea  rsi, [rel ed_test_public2]
    call ed_verify32
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_sig2_api]
    lea  rdi, [rel ed_test_seed2]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature]
    mov  r9d, 64
    call ed25519_sign
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_sig2_exact]
    lea  rdi, [rel ed_test_signature]
    lea  rsi, [rel ed_test_signature2]
    mov  edx, 64
    call memcmp
    test eax, eax
    jnz  .fail
    lea  r12, [rel str_ed_stage_verify2]
    lea  rdi, [rel ed_test_public2]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature2]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jnz  .fail

    ; Message tamper.
    lea  r12, [rel str_ed_stage_message_tamper]
    mov  byte [rel ed_test_message], 0x73
    lea  rdi, [rel ed_test_public2]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature2]
    mov  r9d, 64
    call ed25519_verify
    mov  byte [rel ed_test_message], 0x72
    test eax, eax
    jz   .fail
    ; Signature tamper.
    lea  r12, [rel str_ed_stage_signature_tamper]
    lea  rdi, [rel ed_test_signature]
    lea  rsi, [rel ed_test_signature2]
    mov  edx, 64
    call memcpy
    not  byte [rel ed_test_signature + 17]
    lea  rdi, [rel ed_test_public2]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jz   .fail
    ; Wrong public key.
    lea  r12, [rel str_ed_stage_wrong_public]
    lea  rdi, [rel ed_test_public1]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature2]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jz   .fail
    ; Non-canonical S == L.
    lea  r12, [rel str_ed_stage_noncanonical_s]
    lea  rdi, [rel ed_test_signature]
    lea  rsi, [rel ed_test_signature2]
    mov  edx, 64
    call memcpy
    lea  rdi, [rel ed_test_signature + 32]
    lea  rsi, [rel ed_order_l]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel ed_test_public2]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jz   .fail
    ; Small-order identity public key.
    lea  r12, [rel str_ed_stage_small_order]
    lea  rdi, [rel ed_identity_encoding]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature2]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jz   .fail
    ; Malformed signature length.
    lea  r12, [rel str_ed_stage_malformed_length]
    lea  rdi, [rel ed_test_public2]
    mov  esi, 32
    lea  rdx, [rel ed_test_message]
    mov  ecx, 1
    lea  r8, [rel ed_test_signature2]
    mov  r9d, 63
    call ed25519_verify
    test eax, eax
    jz   .fail

    lea  rdi, [rel str_ed_kat_detail]
    call serial_string
    lea  rdi, [rel str_ed_kat2_detail]
    call serial_string
    lea  rdi, [rel str_ed_kat_marker]
    call serial_string
    lea  rdi, [rel str_ed_reject_detail]
    call serial_string
    lea  rdi, [rel str_ed_reject_marker]
    call serial_string
    xor  eax, eax
    jmp  .done
.fail:
    lea  rdi, [rel str_ed_fail_stage]
    call serial_string
    mov  rdi, r12
    call serial_string
    call serial_newline
    lea  rdi, [rel str_ed_fail]
    call serial_string
    mov  eax, -1
.done:
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Constants and serialized scratch.
; ---------------------------------------------------------------------------

align 16
ed_const_zero: times 16 dq 0
ed_const_one:  dq 1
               times 15 dq 0
ed_const_d:    dq 0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070
               dq 0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203
ed_const_d2:   dq 0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0
               dq 0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406
ed_const_x:    dq 0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c
               dq 0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169
ed_const_y:    dq 0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666
               dq 0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666
ed_const_i:    dq 0xa0b0,0x4a0e,0x1b27,0xc4ee,0xe478,0xad2f,0x1806,0x2f43
               dq 0xd7a7,0x3dfb,0x0099,0x2b4d,0xdf0b,0x4fc1,0x2480,0x2b83

ed_order_l: db 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58
            db 0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14
            db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
ed_identity_encoding: db 1
                      times 31 db 0

align 16
ed_sha_iv: dq 0x6a09e667f3bcc908,0xbb67ae8584caa73b
           dq 0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1
           dq 0x510e527fade682d1,0x9b05688c2b3e6c1f
           dq 0x1f83d9abfb41bd6b,0x5be0cd19137e2179
ed_sha_k:
    dq 0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
    dq 0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118
    dq 0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694
    dq 0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
    dq 0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5
    dq 0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4
    dq 0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70
    dq 0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df
    dq 0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b
    dq 0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30
    dq 0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
    dq 0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
    dq 0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec
    dq 0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b
    dq 0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
    dq 0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b
    dq 0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
    dq 0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable scratch: deferred to the page-isolated WDATA region (core/abi/wdata.inc)
; so the field/SHA loops never store into a page that holds their own code.
%macro WDATA_ed25519 0
align 16
ed_sha_state: times 8 dq 0
ed_sha_work:  times 8 dq 0
ed_sha_w:     times 80 dq 0
ed_sha_tail:  times 256 db 0
ed_mul_t:     times 31 dq 0
ed_pack_t:    times 16 dq 0
ed_pack_m:    times 16 dq 0
ed_pow_c:     times 16 dq 0
ed_equal_a:   times 32 db 0
ed_equal_b:   times 32 db 0
ed_parity_tmp: times 32 db 0

ed_add_a: times 16 dq 0
ed_add_b: times 16 dq 0
ed_add_c: times 16 dq 0
ed_add_d: times 16 dq 0
ed_add_e: times 16 dq 0
ed_add_f: times 16 dq 0
ed_add_g: times 16 dq 0
ed_add_h: times 16 dq 0
ed_u_num:  times 16 dq 0
ed_u_den:  times 16 dq 0
ed_u_den2: times 16 dq 0
ed_u_den4: times 16 dq 0
ed_u_den6: times 16 dq 0
ed_u_t:    times 16 dq 0
ed_u_chk:  times 16 dq 0
ed_point_zi: times 16 dq 0
ed_point_x:  times 16 dq 0
ed_point_y:  times 16 dq 0

ed_point_p:    times ED_POINT_BYTES db 0
ed_point_q:    times ED_POINT_BYTES db 0
ed_point_r:    times ED_POINT_BYTES db 0
ed_point_base: times ED_POINT_BYTES db 0
ed_point_tmp:  times ED_POINT_BYTES db 0
ed_point_chk:  times ED_POINT_BYTES db 0
ed_encoded_chk: times 32 db 0

ed_secret_hash: times 64 db 0
ed_scalar_r:    times 64 db 0
ed_scalar_h:    times 64 db 0
ed_scalar_x:    times 64 dq 0
ed_public_tmp:  times 32 db 0
ed_hash_input:  times ED25519_MAX_MESSAGE + 64 db 0
ed_context_end:
%endmacro
WDATA_DEFER WDATA_ed25519

ed_test_seed1: db 0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4
               db 0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
ed_test_public1: db 0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a
                 db 0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
ed_test_signature1:
    db 0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a
    db 0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55
    db 0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b
    db 0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
ed_test_seed2: db 0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f
               db 0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb
ed_test_public2: db 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc
                 db 0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c
ed_test_signature2:
    db 0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40
    db 0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda
    db 0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c
    db 0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
ed_test_message:   db 0x72
ed_test_public:    times 32 db 0
ed_test_signature: times 64 db 0

str_ed_kat_detail: db "SIG_KAT ED25519_RFC8032_CASE1 pub=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a sig=e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b PASS",13,10,0
str_ed_kat2_detail: db "SIG_KAT ED25519_RFC8032_CASE2 exact=1 verify=1 PASS",13,10,0
str_ed_kat_marker: db "[PAOS64] P2 crypto: RFC8032 Ed25519 KAT PASS [crypto.ed25519.kat]",13,10,0
str_ed_reject_detail: db "SIG_KAT ED25519_REJECT message_tamper=1 signature_tamper=1 wrong_pub=1 noncanonical_s=1 small_order=1 malformed_length=1 PASS",13,10,0
str_ed_reject_marker: db "[PAOS64] P2 crypto: Ed25519 hostile encodings rejected [crypto.ed25519.reject]",13,10,0
str_ed_fail_stage: db "ED25519_DIAG fail_stage=",0
str_ed_stage_pub1_api: db "rfc8032_case1_public_api",0
str_ed_stage_pub1_exact: db "rfc8032_case1_public_exact",0
str_ed_stage_sig1_api: db "rfc8032_case1_sign_api",0
str_ed_stage_sig1_exact: db "rfc8032_case1_signature_exact",0
str_ed_stage_verify1: db "rfc8032_case1_verify",0
str_ed_stage_pub2_api: db "rfc8032_case2_public_api",0
str_ed_stage_pub2_exact: db "rfc8032_case2_public_exact",0
str_ed_stage_sig2_api: db "rfc8032_case2_sign_api",0
str_ed_stage_sig2_exact: db "rfc8032_case2_signature_exact",0
str_ed_stage_verify2: db "rfc8032_case2_verify",0
str_ed_stage_message_tamper: db "message_tamper_reject",0
str_ed_stage_signature_tamper: db "signature_tamper_reject",0
str_ed_stage_wrong_public: db "wrong_public_reject",0
str_ed_stage_noncanonical_s: db "noncanonical_s_reject",0
str_ed_stage_small_order: db "small_order_reject",0
str_ed_stage_malformed_length: db "malformed_length_reject",0
str_ed_fail: db "[PAOS64] P2 crypto: RFC8032 Ed25519 KAT FAIL (markers withheld)",13,10,0
