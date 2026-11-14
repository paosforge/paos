;; MODULE bootmgr/rsa2048_verify
;; LAYER 0
;; EXPORTS rsa2048_verify_sha256, rsa2048_verify_pss_sha256, rsa4096_verify_sha256, rsa_verify_reentrancy_selftest
;; IMPORTS boot/serial, core/lib/sha256, core/lib/mem
;; CAPS
;; OWNER saga:boot
;; LOCK: rsa_verify_lock PROTECTS rsa_add_tmp, rsa_add_top, rsa_mul_result, rsa_mul_x, rsa_mul_tmp, rsa_signature, rsa_pow, rsa_pow_tmp, rsa_em, rsa_message_hash, rsa_pss_em, rsa_pss_db, rsa_pss_mhash, rsa_pss_mgf_input, rsa_pss_mask, rsa_pss_verify_input, rsa_pss_hprime, rsa4096_add_tmp, rsa4096_add_top, rsa4096_mul_result, rsa4096_mul_x, rsa4096_mul_tmp, rsa4096_signature, rsa4096_pow, rsa4096_pow_tmp, rsa4096_em
; Fixed-exponent RSA-2048 PKCS#1 v1.5/SHA-256 verifier for Boot Manager.
; Public numbers and all arithmetic are 32 little-endian 64-bit limbs. The
; detached signature is the conventional 256-byte big-endian representation.
; This verifier has no allocator, I/O, or private-key operation.
;
; caller_inventory: the lock is inside every exported entry, so it covers the
; AUTH1, both PMOD, and all TLS RSA-2048/RSA-4096/PSS paths. The Manager is an
; independent link unit and wraps both of its calls with its own declared lock.
; declaration_check: modlint binds rsa_verify_lock to every mutable production
; RSA scratch label below and requires a live acquire call site.

RSA_LIMBS equ 32
RSA_BYTES equ 256

; Layer-0 verification runs before core/lock is available, so this bounded
; bit-lock is local to the crypto module. Entry arguments are first copied to
; callee-saved registers. The release store leaves the verifier verdict intact.
rsa_verify_lock_acquire:
.spin:
    lock bts qword [rel rsa_verify_lock], 0
    jnc  .acquired
    pause
    jmp  .spin
.acquired:
    ret

rsa_verify_lock_try_acquire:
    xor  eax, eax
    lock bts qword [rel rsa_verify_lock], 0
    setnc al
    ret

rsa_verify_lock_release:
    mov  qword [rel rsa_verify_lock], 0
    ret

; rsa_bn_zero(RDI=dest)
rsa_bn_zero:
    xor  eax, eax
    mov  ecx, RSA_LIMBS
    rep  stosq
    ret

; rsa_bn_copy(RDI=dest, RSI=source)
rsa_bn_copy:
    mov  ecx, RSA_LIMBS
    rep  movsq
    ret

; rsa_bn_cmp(RDI=a, RSI=b) -> EAX=-1/0/1
rsa_bn_cmp:
    mov  ecx, RSA_LIMBS - 1
.loop:
    mov  rax, [rdi + rcx*8]
    cmp  rax, [rsi + rcx*8]
    ja   .greater
    jb   .less
    dec  ecx
    jns  .loop
    xor  eax, eax
    ret
.greater:
    mov  eax, 1
    ret
.less:
    mov  eax, -1
    ret

; rsa_bn_add_mod(RDI=dest, RSI=a, RDX=b, RCX=modulus).
; a,b < modulus, so one subtraction reduces their 2049-bit sum.
rsa_bn_add_mod:
    push rbx
    push r12
    mov  r12, rcx
    lea  rbx, [rel rsa_add_tmp]
    xor  r9d, r9d
    mov  r8d, RSA_LIMBS
    clc
.add:
    mov  rax, [rsi + r9*8]
    adc  rax, [rdx + r9*8]
    mov  [rbx + r9*8], rax
    inc  r9d                         ; INC/DEC preserve carry
    dec  r8d
    jnz  .add
    setc byte [rel rsa_add_top]

    cmp  byte [rel rsa_add_top], 0
    jne  .subtract
    push rdi
    mov  rdi, rbx
    mov  rsi, r12
    call rsa_bn_cmp
    pop  rdi
    cmp  eax, -1
    je   .copy
.subtract:
    xor  r9d, r9d
    mov  r8d, RSA_LIMBS
    clc
.sub:
    mov  rax, [rbx + r9*8]
    sbb  rax, [r12 + r9*8]
    mov  [rbx + r9*8], rax
    inc  r9d
    dec  r8d
    jnz  .sub
.copy:
    mov  rsi, rbx
    mov  ecx, RSA_LIMBS
    rep  movsq
    pop  r12
    pop  rbx
    ret

; rsa_bn_mul_mod(RDI=dest, RSI=a, RDX=b, RCX=modulus).
; Bounded double-and-add over exactly 2048 bits avoids truncated products.
rsa_bn_mul_mod:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    lea  rdi, [rel rsa_mul_result]
    call rsa_bn_zero
    lea  rdi, [rel rsa_mul_x]
    mov  rsi, r13
    call rsa_bn_copy
    xor  ebp, ebp
.bit:
    mov  eax, ebp
    mov  ecx, eax
    shr  eax, 6
    and  ecx, 63
    bt   [r14 + rax*8], rcx
    jnc  .double
    lea  rdi, [rel rsa_mul_tmp]
    lea  rsi, [rel rsa_mul_result]
    lea  rdx, [rel rsa_mul_x]
    mov  rcx, r15
    call rsa_bn_add_mod
    lea  rdi, [rel rsa_mul_result]
    lea  rsi, [rel rsa_mul_tmp]
    call rsa_bn_copy
.double:
    inc  ebp
    cmp  ebp, RSA_BYTES * 8
    jae  .done
    lea  rdi, [rel rsa_mul_tmp]
    lea  rsi, [rel rsa_mul_x]
    lea  rdx, [rel rsa_mul_x]
    mov  rcx, r15
    call rsa_bn_add_mod
    lea  rdi, [rel rsa_mul_x]
    lea  rsi, [rel rsa_mul_tmp]
    call rsa_bn_copy
    jmp  .bit
.done:
    mov  rdi, r12
    lea  rsi, [rel rsa_mul_result]
    call rsa_bn_copy
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; rsa_fixed_65537(RDI=dest, RSI=signature_bn, RDX=modulus)
rsa_fixed_65537:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
    lea  rdi, [rel rsa_pow]
    mov  rsi, r13
    call rsa_bn_copy
    mov  ecx, 16
.square:
    push rcx
    lea  rdi, [rel rsa_pow_tmp]
    lea  rsi, [rel rsa_pow]
    lea  rdx, [rel rsa_pow]
    mov  rcx, rbx
    call rsa_bn_mul_mod
    lea  rdi, [rel rsa_pow]
    lea  rsi, [rel rsa_pow_tmp]
    call rsa_bn_copy
    pop  rcx
    dec  ecx
    jnz  .square
    mov  rdi, r12
    lea  rsi, [rel rsa_pow]
    mov  rdx, r13
    mov  rcx, rbx
    call rsa_bn_mul_mod                ; signature^(2^16+1)
    pop  r13
    pop  r12
    pop  rbx
    ret

; ISRG Root X1 is RSA-4096. Keep its arithmetic in this canonical RSA module
; rather than cloning a private TLS primitive. The sequence is the same proven
; fixed-e=65537 double-and-add verifier above, widened to 64 limbs.
RSA4096_LIMBS equ 64
RSA4096_BYTES equ 512

rsa4096_bn_zero:
    xor  eax, eax
    mov  ecx, RSA4096_LIMBS
    rep  stosq
    ret

rsa4096_bn_copy:
    mov  ecx, RSA4096_LIMBS
    rep  movsq
    ret

rsa4096_bn_cmp:
    mov  ecx, RSA4096_LIMBS - 1
.loop:
    mov  rax, [rdi + rcx*8]
    cmp  rax, [rsi + rcx*8]
    ja   .greater
    jb   .less
    dec  ecx
    jns  .loop
    xor  eax, eax
    ret
.greater:
    mov  eax, 1
    ret
.less:
    mov  eax, -1
    ret

rsa4096_bn_add_mod:
    push rbx
    push r12
    mov  r12, rcx
    lea  rbx, [rel rsa4096_add_tmp]
    xor  r9d, r9d
    mov  r8d, RSA4096_LIMBS
    clc
.add:
    mov  rax, [rsi + r9*8]
    adc  rax, [rdx + r9*8]
    mov  [rbx + r9*8], rax
    inc  r9d
    dec  r8d
    jnz  .add
    setc byte [rel rsa4096_add_top]
    cmp  byte [rel rsa4096_add_top], 0
    jne  .subtract
    push rdi
    mov  rdi, rbx
    mov  rsi, r12
    call rsa4096_bn_cmp
    pop  rdi
    cmp  eax, -1
    je   .copy
.subtract:
    xor  r9d, r9d
    mov  r8d, RSA4096_LIMBS
    clc
.sub:
    mov  rax, [rbx + r9*8]
    sbb  rax, [r12 + r9*8]
    mov  [rbx + r9*8], rax
    inc  r9d
    dec  r8d
    jnz  .sub
.copy:
    mov  rsi, rbx
    mov  ecx, RSA4096_LIMBS
    rep  movsq
    pop  r12
    pop  rbx
    ret

rsa4096_bn_mul_mod:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    lea  rdi, [rel rsa4096_mul_result]
    call rsa4096_bn_zero
    lea  rdi, [rel rsa4096_mul_x]
    mov  rsi, r13
    call rsa4096_bn_copy
    xor  ebp, ebp
.bit:
    mov  eax, ebp
    mov  ecx, eax
    shr  eax, 6
    and  ecx, 63
    bt   [r14 + rax*8], rcx
    jnc  .double
    lea  rdi, [rel rsa4096_mul_tmp]
    lea  rsi, [rel rsa4096_mul_result]
    lea  rdx, [rel rsa4096_mul_x]
    mov  rcx, r15
    call rsa4096_bn_add_mod
    lea  rdi, [rel rsa4096_mul_result]
    lea  rsi, [rel rsa4096_mul_tmp]
    call rsa4096_bn_copy
.double:
    inc  ebp
    cmp  ebp, RSA4096_BYTES * 8
    jae  .done
    lea  rdi, [rel rsa4096_mul_tmp]
    lea  rsi, [rel rsa4096_mul_x]
    lea  rdx, [rel rsa4096_mul_x]
    mov  rcx, r15
    call rsa4096_bn_add_mod
    lea  rdi, [rel rsa4096_mul_x]
    lea  rsi, [rel rsa4096_mul_tmp]
    call rsa4096_bn_copy
    jmp  .bit
.done:
    mov  rdi, r12
    lea  rsi, [rel rsa4096_mul_result]
    call rsa4096_bn_copy
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

rsa4096_fixed_65537:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
    lea  rdi, [rel rsa4096_pow]
    mov  rsi, r13
    call rsa4096_bn_copy
    mov  ecx, 16
.square:
    push rcx
    lea  rdi, [rel rsa4096_pow_tmp]
    lea  rsi, [rel rsa4096_pow]
    lea  rdx, [rel rsa4096_pow]
    mov  rcx, rbx
    call rsa4096_bn_mul_mod
    lea  rdi, [rel rsa4096_pow]
    lea  rsi, [rel rsa4096_pow_tmp]
    call rsa4096_bn_copy
    pop  rcx
    dec  ecx
    jnz  .square
    mov  rdi, r12
    lea  rsi, [rel rsa4096_pow]
    mov  rdx, r13
    mov  rcx, rbx
    call rsa4096_bn_mul_mod
    pop  r13
    pop  r12
    pop  rbx
    ret

; rsa4096_verify_sha256(RDI=signature_be512, RSI=message, RDX=len,
;                       RCX=modulus_le512) -> EAX=0 valid, 1 rejected.
rsa4096_verify_sha256:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    call rsa_verify_lock_acquire
    test r12, r12
    jz   .bad
    test r15, r15
    jz   .bad
    test r14, r14
    jz   .message_ready
    test r13, r13
    jz   .bad
.message_ready:
    test byte [r15], 1
    jz   .bad
    test byte [r15 + RSA4096_BYTES - 1], 0x80
    jz   .bad
    lea  rbx, [rel rsa4096_signature]
    xor  ecx, ecx
.reverse:
    movzx eax, byte [r12 + rcx]
    mov  edx, RSA4096_BYTES - 1
    sub  edx, ecx
    mov  [rbx + rdx], al
    inc  ecx
    cmp  ecx, RSA4096_BYTES
    jb   .reverse
    mov  rdi, rbx
    mov  rsi, r15
    call rsa4096_bn_cmp
    cmp  eax, -1
    jne  .bad
    lea  rdi, [rel rsa_message_hash]
    mov  rsi, r13
    mov  rdx, r14
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel rsa4096_em]
    lea  rsi, [rel rsa4096_signature]
    mov  rdx, r15
    call rsa4096_fixed_65537
    lea  rbx, [rel rsa4096_em]
    cmp  byte [rbx + RSA4096_BYTES - 1], 0
    jne  .bad
    cmp  byte [rbx + RSA4096_BYTES - 2], 1
    jne  .bad
    mov  ecx, RSA4096_BYTES - 3
.ff:
    cmp  byte [rbx + rcx], 0xff
    jne  .bad
    dec  ecx
    cmp  ecx, 51
    ja   .ff
    cmp  byte [rbx + 51], 0
    jne  .bad
    lea  rbp, [rel rsa_sha256_digestinfo]
    xor  ecx, ecx
.der:
    mov  eax, 50
    sub  eax, ecx
    mov  dl, [rbx + rax]
    cmp  dl, [rbp + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 19
    jb   .der
    lea  r13, [rel rsa_message_hash]
    xor  ecx, ecx
.digest:
    mov  eax, 31
    sub  eax, ecx
    mov  dl, [rbx + rax]
    cmp  dl, [r13 + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 32
    jb   .digest
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    call rsa_verify_lock_release
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; rsa2048_verify_sha256(RDI=signature_be, RSI=message, RDX=length,
;                       RCX=modulus_le) -> EAX=0 valid, 1 rejected.
rsa2048_verify_sha256:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    call rsa_verify_lock_acquire
    test r12, r12                      ; detached signature is mandatory
    jz   .bad
    test r15, r15                      ; enrolled modulus is mandatory
    jz   .bad
    test r14, r14
    jz   .message_ready                ; SHA-256 of an empty message is valid
    test r13, r13                      ; non-empty messages require storage
    jz   .bad
.message_ready:
    test byte [r15], 1                ; RSA modulus must be odd
    jz   .bad
    test byte [r15 + RSA_BYTES - 1], 0x80
    jz   .bad                         ; require a full-width 2048-bit modulus

    lea  rbx, [rel rsa_signature]
    xor  ecx, ecx
.reverse:
    movzx eax, byte [r12 + rcx]
    mov  edx, RSA_BYTES - 1
    sub  edx, ecx
    mov  [rbx + rdx], al
    inc  ecx
    cmp  ecx, RSA_BYTES
    jb   .reverse
    mov  rdi, rbx
    mov  rsi, r15
    call rsa_bn_cmp
    cmp  eax, -1
    jne  .bad                         ; signature representative must be < n

    lea  rdi, [rel rsa_message_hash]
    mov  rsi, r13
    mov  rdx, r14
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel rsa_em]
    lea  rsi, [rel rsa_signature]
    mov  rdx, r15
    call rsa_fixed_65537

    ; Strict EMSA-PKCS1-v1_5 encoding for a 2048-bit SHA-256 signature:
    ; 00 01 | 202 bytes FF | 00 | 19-byte DigestInfo | 32-byte digest.
    lea  rbx, [rel rsa_em]
    cmp  byte [rbx + 255], 0
    jne  .bad
    cmp  byte [rbx + 254], 1
    jne  .bad
    mov  ecx, 253
.ff:
    cmp  byte [rbx + rcx], 0xFF
    jne  .bad
    dec  ecx
    cmp  ecx, 51
    ja   .ff
    cmp  byte [rbx + 51], 0
    jne  .bad

    lea  rbp, [rel rsa_sha256_digestinfo]
    xor  ecx, ecx
.der:
    mov  eax, 50
    sub  eax, ecx
    mov  dl, [rbx + rax]
    cmp  dl, [rbp + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 19
    jb   .der
    lea  r13, [rel rsa_message_hash]
    xor  ecx, ecx
.digest:
    mov  eax, 31
    sub  eax, ecx
    mov  dl, [rbx + rax]
    cmp  dl, [r13 + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 32
    jb   .digest
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    call rsa_verify_lock_release
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; rsa2048_verify_pss_sha256(RDI=signature_be, RSI=message, RDX=length,
;                           RCX=modulus_le) -> EAX=0 valid, 1 rejected.
; TLS 1.3 CertificateVerify uses rsa_pss_rsae_sha256 with saltLen=HashLen.
rsa2048_verify_pss_sha256:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    call rsa_verify_lock_acquire
    test r12, r12
    jz   .bad
    test r15, r15
    jz   .bad
    test r14, r14
    jz   .msg_ok
    test r13, r13
    jz   .bad
.msg_ok:
    test byte [r15], 1
    jz   .bad
    test byte [r15 + RSA_BYTES - 1], 0x80
    jz   .bad
    lea  rbx, [rel rsa_signature]
    xor  ecx, ecx
.reverse_sig:
    movzx eax, byte [r12 + rcx]
    mov  edx, RSA_BYTES - 1
    sub  edx, ecx
    mov  [rbx + rdx], al
    inc  ecx
    cmp  ecx, RSA_BYTES
    jb   .reverse_sig
    mov  rdi, rbx
    mov  rsi, r15
    call rsa_bn_cmp
    cmp  eax, -1
    jne  .bad
    lea  rdi, [rel rsa_em]
    lea  rsi, [rel rsa_signature]
    mov  rdx, r15
    call rsa_fixed_65537
    ; rsa_em is the internal little-endian representative; PSS is specified
    ; over the conventional big-endian encoded message EM.
    lea  r8, [rel rsa_em]
    lea  r9, [rel rsa_pss_em]
    xor  ecx, ecx
.reverse_em:
    mov  eax, RSA_BYTES - 1
    sub  eax, ecx
    mov  dl, [r8 + rax]
    mov  [r9 + rcx], dl
    inc  ecx
    cmp  ecx, RSA_BYTES
    jb   .reverse_em
    cmp  byte [rel rsa_pss_em + 255], 0xbc
    jne  .bad
    test byte [rel rsa_pss_em], 0x80     ; emBits = 2047 for full RSA-2048
    jnz  .bad
    lea  rdi, [rel rsa_pss_mhash]
    mov  rsi, r13
    mov  rdx, r14
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel rsa_pss_db]
    lea  rsi, [rel rsa_pss_em]
    mov  edx, 223
    call memcpy
    xor  ebp, ebp
.mgf_block:
    lea  rdi, [rel rsa_pss_mgf_input]
    lea  rsi, [rel rsa_pss_em + 223]
    mov  edx, 32
    call memcpy
    mov  eax, ebp
    bswap eax
    mov  [rel rsa_pss_mgf_input + 32], eax
    lea  rdi, [rel rsa_pss_mask]
    lea  rsi, [rel rsa_pss_mgf_input]
    mov  edx, 36
    call sha256_hash
    test rax, rax
    jnz  .bad
    mov  eax, ebp
    shl  eax, 5
    mov  r12d, 223
    sub  r12d, eax
    cmp  r12d, 32
    jbe  .mgf_count
    mov  r12d, 32
.mgf_count:
    lea  r8, [rel rsa_pss_mask]
    lea  r9, [rel rsa_pss_db]
    xor  ecx, ecx
.mgf_xor:
    mov  dl, [r8 + rcx]
    mov  r11d, eax
    add  r11d, ecx
    xor  [r9 + r11], dl
    inc  ecx
    cmp  ecx, r12d
    jb   .mgf_xor
    inc  ebp
    cmp  ebp, 7
    jb   .mgf_block
    and  byte [rel rsa_pss_db], 0x7f
    lea  r8, [rel rsa_pss_db]
    xor  ecx, ecx
.ps_zero:
    cmp  byte [r8 + rcx], 0
    jne  .bad
    inc  ecx
    cmp  ecx, 190
    jb   .ps_zero
    cmp  byte [rel rsa_pss_db + 190], 1
    jne  .bad
    lea  rdi, [rel rsa_pss_verify_input]
    xor  esi, esi
    mov  edx, 72
    call memset
    lea  rdi, [rel rsa_pss_verify_input + 8]
    lea  rsi, [rel rsa_pss_mhash]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel rsa_pss_verify_input + 40]
    lea  rsi, [rel rsa_pss_db + 191]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel rsa_pss_hprime]
    lea  rsi, [rel rsa_pss_verify_input]
    mov  edx, 72
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel rsa_pss_hprime]
    lea  rsi, [rel rsa_pss_em + 223]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    call rsa_verify_lock_release
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Build a strict little-endian EMSA-PKCS1-v1_5 representative for a message.
; The representative is the verifier state produced by a correct signature
; after modular exponentiation. RDI=EM[256], RSI=message, EDX=length,
; RCX=hash[32] -> EAX=0/1.
rsa_reentrant_test_build_pair:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  rbx, rcx
    mov  rdi, r12
    xor  esi, esi
    mov  edx, RSA_BYTES
    call memset
    mov  byte [r12 + 254], 1
    lea  rdi, [r12 + 52]
    mov  esi, 0xff
    mov  edx, 202
    call memset
    lea  rsi, [rel rsa_sha256_digestinfo]
    xor  ecx, ecx
.digestinfo:
    mov  eax, 50
    sub  eax, ecx
    mov  dl, [rsi + rcx]
    mov  [r12 + rax], dl
    inc  ecx
    cmp  ecx, 19
    jb   .digestinfo
    mov  rdi, rbx
    mov  rsi, r13
    mov  edx, r14d
    call sha256_hash
    test rax, rax
    jnz  .bad
    xor  ecx, ecx
.hash:
    mov  eax, 31
    sub  eax, ecx
    mov  dl, [rbx + rcx]
    mov  [r12 + rax], dl
    inc  ecx
    cmp  ecx, 32
    jb   .hash
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Stage one logical verifier's decrypted signature representative and message
; hash in the exact module-static buffers used by the production entries.
; RDI=EM[256], RSI=hash[32].
rsa_reentrant_test_load_pair:
    push rbx
    mov  rbx, rsi
    mov  rsi, rdi
    lea  rdi, [rel rsa_em]
    mov  edx, RSA_BYTES
    call memcpy
    lea  rdi, [rel rsa_message_hash]
    mov  rsi, rbx
    mov  edx, 32
    call memcpy
    pop  rbx
    ret

; RDI=EM[256]. Used only by the must-fail schedule to stop logical worker B
; between its EM write and hash write, exactly where shared scratch corrupts A.
rsa_reentrant_test_load_em:
    mov  rsi, rdi
    lea  rdi, [rel rsa_em]
    mov  edx, RSA_BYTES
    jmp  memcpy

; Grade the production scratch using the same strict PKCS#1 structure and hash
; comparisons as rsa2048_verify_sha256. EAX=0 valid, 1 rejected.
rsa_reentrant_test_grade:
    push rbx
    push rbp
    lea  rbx, [rel rsa_em]
    cmp  byte [rbx + 255], 0
    jne  .bad
    cmp  byte [rbx + 254], 1
    jne  .bad
    mov  ecx, 253
.ff:
    cmp  byte [rbx + rcx], 0xff
    jne  .bad
    dec  ecx
    cmp  ecx, 51
    ja   .ff
    cmp  byte [rbx + 51], 0
    jne  .bad
    lea  rbp, [rel rsa_sha256_digestinfo]
    xor  ecx, ecx
.der:
    mov  eax, 50
    sub  eax, ecx
    mov  dl, [rbx + rax]
    cmp  dl, [rbp + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 19
    jb   .der
    lea  rbp, [rel rsa_message_hash]
    xor  ecx, ecx
.digest:
    mov  eax, 31
    sub  eax, ecx
    mov  dl, [rbx + rax]
    cmp  dl, [rbp + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 32
    jb   .digest
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  rbp
    pop  rbx
    ret

; QEMU-only deterministic instruction-stage oracle for S10.
; caller_inventory: production entries own the lock and Manager owns its copy.
; interleaved_valid_pairs: B attempts entry while A owns every scratch byte;
; both distinct valid encodings then grade correctly in serialized order.
; crossed_pair_refusals: A/B, B/A, and a damaged encoding all refuse.
; isolation_removed_control: B overwrites only EM before A resumes, making A's
; otherwise-valid pair return the wrong verdict. Repeated schedules must agree.
rsa_verify_reentrancy_selftest:
    push rbx
    push rbp
    push r12
    mov  qword [rel rsa_verify_lock], 0
    lea  rdi, [rel rsa_reentrant_pair_a_em]
    lea  rsi, [rel rsa_reentrant_msg_a]
    mov  edx, rsa_reentrant_msg_a_end - rsa_reentrant_msg_a
    lea  rcx, [rel rsa_reentrant_pair_a_hash]
    call rsa_reentrant_test_build_pair
    test eax, eax
    jnz  .fail
    lea  rdi, [rel rsa_reentrant_pair_b_em]
    lea  rsi, [rel rsa_reentrant_msg_b]
    mov  edx, rsa_reentrant_msg_b_end - rsa_reentrant_msg_b
    lea  rcx, [rel rsa_reentrant_pair_b_hash]
    call rsa_reentrant_test_build_pair
    test eax, eax
    jnz  .fail
    lea  rdi, [rel rsa_reentrant_pair_a_hash]
    lea  rsi, [rel rsa_reentrant_pair_b_hash]
    mov  edx, 32
    call memcmp
    test rax, rax
    jz   .fail                         ; messages must be observably distinct

    mov  ebp, 4                        ; stable: repeat the forced schedule
.interleaved_valid_pairs:
    call rsa_verify_lock_acquire       ; logical verifier A owns all scratch
    lea  rdi, [rel rsa_reentrant_pair_a_em]
    lea  rsi, [rel rsa_reentrant_pair_a_hash]
    call rsa_reentrant_test_load_pair
    call rsa_verify_lock_try_acquire   ; B reaches the same entry lock now
    test eax, eax
    jnz  .fail_locked                  ; B must observe contention
    call rsa_reentrant_test_grade
    test eax, eax
    jnz  .fail_locked
    call rsa_verify_lock_release

    call rsa_verify_lock_acquire       ; B proceeds only after A's verdict
    lea  rdi, [rel rsa_reentrant_pair_b_em]
    lea  rsi, [rel rsa_reentrant_pair_b_hash]
    call rsa_reentrant_test_load_pair
    call rsa_reentrant_test_grade
    test eax, eax
    jnz  .fail_locked
    call rsa_verify_lock_release
    dec  ebp
    jnz  .interleaved_valid_pairs

.crossed_pair_refusals:
    call rsa_verify_lock_acquire
    lea  rdi, [rel rsa_reentrant_pair_a_em]
    lea  rsi, [rel rsa_reentrant_pair_b_hash]
    call rsa_reentrant_test_load_pair
    call rsa_reentrant_test_grade
    cmp  eax, 1
    jne  .fail_locked
    call rsa_verify_lock_release

    call rsa_verify_lock_acquire
    lea  rdi, [rel rsa_reentrant_pair_b_em]
    lea  rsi, [rel rsa_reentrant_pair_a_hash]
    call rsa_reentrant_test_load_pair
    call rsa_reentrant_test_grade
    cmp  eax, 1
    jne  .fail_locked
    call rsa_verify_lock_release

    call rsa_verify_lock_acquire
    lea  rdi, [rel rsa_reentrant_pair_a_em]
    lea  rsi, [rel rsa_reentrant_pair_a_hash]
    call rsa_reentrant_test_load_pair
    xor  byte [rel rsa_em + 32], 1
    call rsa_reentrant_test_grade
    cmp  eax, 1
    jne  .fail_locked
    call rsa_verify_lock_release

.isolation_removed_control:
    ; A begins with a correct pair. With isolation deliberately absent from
    ; this control only, B writes its different EM before A's verdict resumes.
    lea  rdi, [rel rsa_reentrant_pair_a_em]
    lea  rsi, [rel rsa_reentrant_pair_a_hash]
    call rsa_reentrant_test_load_pair
    lea  rdi, [rel rsa_reentrant_pair_b_em]
    call rsa_reentrant_test_load_em
    call rsa_reentrant_test_grade
    cmp  eax, 1
    jne  .fail                         ; schedule must expose A's wrong verdict

    lea  rdi, [rel str_rsa_reentrant_pass]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail_locked:
    call rsa_verify_lock_release
.fail:
    lea  rdi, [rel str_rsa_reentrant_fail]
    call serial_string
    mov  eax, 1
.out:
    mov  qword [rel rsa_verify_lock], 0
    pop  r12
    pop  rbp
    pop  rbx
    ret

rsa_sha256_digestinfo:
    db 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01
    db 0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_rsa2048 0
align 8
rsa_verify_lock:    dq 0
rsa_add_tmp:       times (RSA_LIMBS + 1) dq 0
rsa_add_top:       db 0
align 8
rsa_mul_result:    times RSA_BYTES db 0
rsa_mul_x:         times RSA_BYTES db 0
rsa_mul_tmp:       times RSA_BYTES db 0
rsa_signature:     times RSA_BYTES db 0
rsa_pow:           times RSA_BYTES db 0
rsa_pow_tmp:       times RSA_BYTES db 0
rsa_em:            times RSA_BYTES db 0
rsa_message_hash:  times 32 db 0
rsa_pss_em:           times 256 db 0
rsa_pss_db:           times 223 db 0
rsa_pss_mhash:        times 32 db 0
rsa_pss_mgf_input:    times 36 db 0
rsa_pss_mask:         times 32 db 0
rsa_pss_verify_input: times 72 db 0
rsa_pss_hprime:       times 32 db 0
align 8
rsa4096_add_tmp:    times (RSA4096_LIMBS + 1) dq 0
rsa4096_add_top:    db 0
align 8
rsa4096_mul_result: times RSA4096_BYTES db 0
rsa4096_mul_x:      times RSA4096_BYTES db 0
rsa4096_mul_tmp:    times RSA4096_BYTES db 0
rsa4096_signature:  times RSA4096_BYTES db 0
rsa4096_pow:        times RSA4096_BYTES db 0
rsa4096_pow_tmp:    times RSA4096_BYTES db 0
rsa4096_em:         times RSA4096_BYTES db 0

align 8
rsa_reentrant_pair_a_em:   times RSA_BYTES db 0
rsa_reentrant_pair_b_em:   times RSA_BYTES db 0
rsa_reentrant_pair_a_hash: times 32 db 0
rsa_reentrant_pair_b_hash: times 32 db 0
%endmacro
WDATA_DEFER WDATA_rsa2048
rsa_reentrant_msg_a:       db "AUTH1 bounded remote command"
rsa_reentrant_msg_a_end:
rsa_reentrant_msg_b:       db "TLS13 distinct certificate verify"
rsa_reentrant_msg_b_end:
str_rsa_reentrant_pass: db "[PAOS64] M6 security: concurrent RSA verification isolation PASS [security.rsa.reentrant]",13,10,0
str_rsa_reentrant_fail: db "[PAOS64] M6 security: concurrent RSA verification isolation FAIL",13,10,0
