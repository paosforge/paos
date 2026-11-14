;; MODULE bootmgr/pax1_loader
;; LAYER 0
;; EXPORTS pax1_prepare_verified_paos, pax1_start_prepared_paos, pax1_release_verified_source, pax1_discard_prepared_paos, sha256_stream_init, sha256_stream_update, sha256_stream_final, sha256_hash, sha256_selftest, rsa2048_verify_sha256
;; IMPORTS boot/boot_v2_contract
;; CAPS
;; OWNER saga:boot

; The Manager PE has one honest RX code section.  The shared, proven
; SHA-256 and RSA-2048 instruction sequences are ported verbatim here so
; their constants and writable scratch can be emitted later by the RO/RW
; layout macros.  Keeping the original mixed code/data includes in .text
; would merely relabel writable state as RX, repeating PaOS's known flag debt.
; ============================================================================
; Incremental SHA-256 (FIPS 180-4).  The compression sequence and constants are
; ported from the proven Classic PaOS sha256_transform implementation.  The
; additive stream context is what lets filesystem consumers hash bounded chunks
; without allocating an entire large file.
;
; struct sha256_stream_ctx (112 bytes):
;   +0   state[8] (native-endian dwords)
;   +32  total bytes (qword)
;   +40  buffered bytes, 0..63 (qword)
;   +48  partial block[64]
; ============================================================================

S256_STATE  equ 0
S256_TOTAL  equ 32
S256_USED   equ 40
S256_BLOCK  equ 48
S256_CTX_SZ equ 112

; sha256_stream_init(RDI=ctx) -> RAX=0
sha256_stream_init:
    mov  dword [rdi + S256_STATE],      0x6a09e667
    mov  dword [rdi + S256_STATE + 4],  0xbb67ae85
    mov  dword [rdi + S256_STATE + 8],  0x3c6ef372
    mov  dword [rdi + S256_STATE + 12], 0xa54ff53a
    mov  dword [rdi + S256_STATE + 16], 0x510e527f
    mov  dword [rdi + S256_STATE + 20], 0x9b05688c
    mov  dword [rdi + S256_STATE + 24], 0x1f83d9ab
    mov  dword [rdi + S256_STATE + 28], 0x5be0cd19
    mov  qword [rdi + S256_TOTAL], 0
    mov  qword [rdi + S256_USED], 0
    xor  eax, eax
    ret

; sha256_stream_update(RDI=ctx,RSI=data,RDX=len) -> RAX=0/-1 (length overflow)
sha256_stream_update:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rax, [r12 + S256_TOTAL]
    add  rax, r14
    jc   .fail
    mov  [r12 + S256_TOTAL], rax

    mov  rbx, [r12 + S256_USED]
    test rbx, rbx
    jz   .full_blocks
    mov  rcx, 64
    sub  rcx, rbx                         ; room in partial block
    cmp  rcx, r14
    jbe  .fill_partial
    mov  rcx, r14
.fill_partial:
    lea  rdi, [r12 + S256_BLOCK]
    add  rdi, rbx
    mov  rsi, r13
    push rcx
    rep  movsb
    pop  rcx
    add  rbx, rcx
    add  r13, rcx
    sub  r14, rcx
    mov  [r12 + S256_USED], rbx
    cmp  rbx, 64
    jne  .ok
    lea  rdi, [r12 + S256_STATE]
    lea  rsi, [r12 + S256_BLOCK]
    call sha256_transform
    mov  qword [r12 + S256_USED], 0

.full_blocks:
    cmp  r14, 64
    jb   .tail
    lea  rdi, [r12 + S256_STATE]
    mov  rsi, r13
    call sha256_transform
    add  r13, 64
    sub  r14, 64
    jmp  .full_blocks

.tail:
    test r14, r14
    jz   .ok
    lea  rdi, [r12 + S256_BLOCK]
    mov  rsi, r13
    mov  rcx, r14
    rep  movsb
    mov  [r12 + S256_USED], r14
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; sha256_stream_final(RDI=ctx,RSI=out32) -> RAX=0/-1
sha256_stream_final:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, [r12 + S256_TOTAL]
    mov  rcx, 0x1FFFFFFFFFFFFFFF
    cmp  rax, rcx                         ; byte length must fit after *8
    ja   .fail
    mov  rbx, [r12 + S256_USED]
    cmp  rbx, 63
    ja   .fail
    lea  rdi, [r12 + S256_BLOCK]
    mov  byte [rdi + rbx], 0x80
    inc  rbx
    cmp  rbx, 56
    jbe  .one_block
    mov  rcx, 64
    sub  rcx, rbx
    xor  eax, eax
    add  rdi, rbx
    rep  stosb
    lea  rdi, [r12 + S256_STATE]
    lea  rsi, [r12 + S256_BLOCK]
    call sha256_transform
    lea  rdi, [r12 + S256_BLOCK]
    xor  eax, eax
    mov  ecx, 64
    rep  stosb
    jmp  .put_len
.one_block:
    mov  rcx, 56
    sub  rcx, rbx
    xor  eax, eax
    add  rdi, rbx
    rep  stosb
.put_len:
    mov  rax, [r12 + S256_TOTAL]
    shl  rax, 3
    bswap rax
    mov  [r12 + S256_BLOCK + 56], rax
    lea  rdi, [r12 + S256_STATE]
    lea  rsi, [r12 + S256_BLOCK]
    call sha256_transform
    lea  rdi, [r12 + S256_STATE]
    mov  rsi, r13
    mov  ecx, 8
.digest:
    mov  eax, [rdi]
    bswap eax
    mov  [rsi], eax
    add  rdi, 4
    add  rsi, 4
    dec  ecx
    jnz  .digest
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; sha256_hash(RDI=out32,RSI=data,RDX=len) -> RAX=0/-1
sha256_hash:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    lea  rdi, [rel sha256_one_ctx]
    call sha256_stream_init
    lea  rdi, [rel sha256_one_ctx]
    mov  rsi, r13
    mov  rdx, r14
    call sha256_stream_update
    test rax, rax
    jnz  .out
    lea  rdi, [rel sha256_one_ctx]
    mov  rsi, r12
    call sha256_stream_final
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; sha256_selftest -> RAX=0 only for SHA256("abc") known answer.
sha256_selftest:
    lea  rdi, [rel sha256_test_digest]
    lea  rsi, [rel sha256_test_abc]
    mov  edx, 3
    call sha256_hash
    test rax, rax
    jnz  .fail
    lea  rdi, [rel sha256_test_digest]
    lea  rsi, [rel sha256_test_expected]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_sha256_stream_ok]
    call serial_string
    xor  eax, eax
    ret
.fail:
    lea  rdi, [rel str_sha256_stream_fail]
    call serial_string
    mov  eax, -1
    ret

; sha256_transform(RDI=state,RSI=64-byte block). Proven Classic sequence.
sha256_transform:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    lea  r12, [rel sha256_work]
    mov  ecx, 16
.load_w:
    mov  eax, [rsi]
    bswap eax
    mov  [r12], eax
    add  rsi, 4
    add  r12, 4
    dec  ecx
    jnz  .load_w
    lea  r12, [rel sha256_work]
    mov  ecx, 48
    lea  rsi, [r12 + 64]
.expand_w:
    mov  eax, [rsi - 8]
    mov  edx, eax
    mov  ebx, eax
    ror  eax, 17
    ror  edx, 19
    shr  ebx, 10
    xor  eax, edx
    xor  eax, ebx
    add  eax, [rsi - 28]
    mov  edx, [rsi - 60]
    mov  ebx, edx
    mov  ebp, edx
    ror  edx, 7
    ror  ebx, 18
    shr  ebp, 3
    xor  edx, ebx
    xor  edx, ebp
    add  eax, edx
    add  eax, [rsi - 64]
    mov  [rsi], eax
    add  rsi, 4
    dec  ecx
    jnz  .expand_w
    sub  rsp, 32
    mov  eax, [rdi]
    mov  [rsp], eax
    mov  eax, [rdi + 4]
    mov  [rsp + 4], eax
    mov  eax, [rdi + 8]
    mov  [rsp + 8], eax
    mov  eax, [rdi + 12]
    mov  [rsp + 12], eax
    mov  eax, [rdi + 16]
    mov  [rsp + 16], eax
    mov  eax, [rdi + 20]
    mov  [rsp + 20], eax
    mov  eax, [rdi + 24]
    mov  [rsp + 24], eax
    mov  eax, [rdi + 28]
    mov  [rsp + 28], eax
    lea  r12, [rel sha256_work]
    lea  r13, [rel sha256_k]
    xor  r14d, r14d
.round:
    mov  eax, [rsp + 16]
    mov  ecx, eax
    mov  edx, eax
    ror  eax, 6
    ror  ecx, 11
    ror  edx, 25
    xor  eax, ecx
    xor  eax, edx
    mov  ecx, [rsp + 16]
    mov  edx, ecx
    and  ecx, [rsp + 20]
    not  edx
    and  edx, [rsp + 24]
    xor  ecx, edx
    add  eax, ecx
    add  eax, [rsp + 28]
    add  eax, [r13 + r14*4]
    add  eax, [r12 + r14*4]
    mov  ebx, eax
    mov  eax, [rsp]
    mov  ecx, eax
    mov  edx, eax
    ror  eax, 2
    ror  ecx, 13
    ror  edx, 22
    xor  eax, ecx
    xor  eax, edx
    mov  ecx, [rsp]
    mov  edx, ecx
    and  ecx, [rsp + 4]
    and  edx, [rsp + 8]
    xor  ecx, edx
    mov  edx, [rsp + 4]
    and  edx, [rsp + 8]
    xor  ecx, edx
    add  eax, ecx
    mov  ebp, eax
    mov  eax, [rsp + 24]
    mov  [rsp + 28], eax
    mov  eax, [rsp + 20]
    mov  [rsp + 24], eax
    mov  eax, [rsp + 16]
    mov  [rsp + 20], eax
    mov  eax, [rsp + 12]
    add  eax, ebx
    mov  [rsp + 16], eax
    mov  eax, [rsp + 8]
    mov  [rsp + 12], eax
    mov  eax, [rsp + 4]
    mov  [rsp + 8], eax
    mov  eax, [rsp]
    mov  [rsp + 4], eax
    mov  eax, ebx
    add  eax, ebp
    mov  [rsp], eax
    inc  r14d
    cmp  r14d, 64
    jb   .round
    mov  rdi, [rsp + 32]
    mov  eax, [rsp]
    add  [rdi], eax
    mov  eax, [rsp + 4]
    add  [rdi + 4], eax
    mov  eax, [rsp + 8]
    add  [rdi + 8], eax
    mov  eax, [rsp + 12]
    add  [rdi + 12], eax
    mov  eax, [rsp + 16]
    add  [rdi + 16], eax
    mov  eax, [rsp + 20]
    add  [rdi + 20], eax
    mov  eax, [rsp + 24]
    add  [rdi + 24], eax
    mov  eax, [rsp + 28]
    add  [rdi + 28], eax
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret


; Fixed-exponent RSA-2048 PKCS#1 v1.5/SHA-256 verifier for Boot Manager.
; Public numbers and all arithmetic are 32 little-endian 64-bit limbs. The
; detached signature is the conventional 256-byte big-endian representation.
; This verifier has no allocator, I/O, or private-key operation.

RSA_LIMBS equ 32
RSA_BYTES equ 256

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
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret


; ---------------------------------------------------------------------------
; PAX1: one bounded data loader for today's PaOS A/B/Rescue PE profile.
;
; Trust is earned before this seam by verify_payload_file: the external owner-
; signed manifest (or independent Rescue descriptor) supplies the exact path,
; size, and SHA-256, and the file is read exactly once. This loader still
; validates every PE range before allocation/copy and accepts only the frozen
; one-section current-PaOS identity. In particular, 0x60000020 is checked as
; an identity byte pattern only: current PaOS writes in-image state, so the
; section flag is not treated as a W^X or memory-safety claim.
;
; Windows and Linux are rejected before this file is called. They continue
; through firmware LoadImage/StartImage and firmware db/dbx policy.
; ---------------------------------------------------------------------------

PAX1_EFI_LOAD_ERROR  equ 0x8000000000000001
PAX1_EFI_UNSUPPORTED equ 0x8000000000000003

%if PAX1_ABI_VERSION != 1
%error "PAX1 loader implements only direct-entry ABI version 1"
%endif

; Manager entry parity has historically differed between firmware paths.
; Normalize locally instead of inheriting that ambiguity: RBP retains the
; exact post-save stack while RSP is rounded down for every firmware call.
;
; pax1_prepare_verified_paos(R15D=entry) -> RAX=EFI_STATUS
; On success the fixed-address image and compatibility LoadedImage handle are
; ready, but no durable attempt has yet been armed and no child code has run.
pax1_prepare_verified_paos:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32

    mov  dword [rel pax1_placement_size], 0
    mov  qword [rel pax1_alloc_status_1m], -1   ; -1 = not attempted
    mov  qword [rel pax1_alloc_status_max], -1
    mov  qword [rel pax1_alloc_max_base], 0
    cmp  qword [rel pax1_image_base], 0
    jne  .bad
    cmp  qword [rel pax1_child_handle], 0
    jne  .bad
    cmp  byte [rel payload_verify_ok], 1
    jne  .bad
    cmp  r15d, PBM_ENTRY_PAOS_A
    jb   .unsupported
    cmp  r15d, PBM_ENTRY_RESCUE
    ja   .unsupported

    ; Reassert the authenticated trust root at the loader seam. Normal A/B
    ; and Rescue use the owner manifest; descriptor-only recovery may name
    ; Rescue and no other entry.
    cmp  byte [rel manifest_verified], 1
    je   .trust_ready
    cmp  byte [rel recovery_descriptor_verified], 1
    jne  .bad
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .bad
.trust_ready:
    cmp  byte [rel verified_payload_entry], r15b
    jne  .bad
    mov  r12, [rel verified_source_buffer]
    test r12, r12
    jz   .bad
    mov  r13d, [rel verified_payload_size]
    cmp  r13d, PAX1_FILE_ALIGNMENT
    jb   .bad
    cmp  r13d, PAX1_MAX_IMAGE_SIZE
    ja   .bad

    ; DOS/COFF/optional-header bounds. Each subtraction is guarded by the
    ; minimum file size, so no attacker-controlled addition can wrap.
    cmp  word [r12], 0x5A4D
    jne  .bad
    mov  r14d, [r12 + 0x3C]
    cmp  r14d, 0x40                  ; exact current PaOS DOS/PE placement
    jne  .bad
    mov  eax, r13d
    sub  eax, 304                    ; PE+COFF+optional+one section header
    cmp  r14d, eax
    ja   .bad
    cmp  dword [r12 + r14], 0x00004550
    jne  .bad
    cmp  word [r12 + r14 + 4], 0x8664
    jne  .bad
    cmp  word [r12 + r14 + 6], 1
    jne  .bad
    cmp  dword [r12 + r14 + 8], 0  ; reproducible: no COFF timestamp
    jne  .bad
    cmp  qword [r12 + r14 + 12], 0 ; no symbol table or symbols
    jne  .bad
    cmp  word [r12 + r14 + 20], 0x00F0
    jne  .bad
    cmp  word [r12 + r14 + 22], 0x0022
    jne  .bad
    lea  rbx, [r12 + r14 + 24]      ; PE32+ optional header
    cmp  word [rbx], 0x020B
    jne  .bad
    cmp  word [rbx + 2], 1          ; exact linker-version identity: 1.0
    jne  .bad
    cmp  qword [rbx + 8], 0         ; no initialized/uninitialized data claim
    jne  .bad
    cmp  dword [rbx + 20], 0x1000   ; exact BaseOfCode
    jne  .bad
    cmp  qword [rbx + 40], 0        ; OS/image versions are all zero
    jne  .bad
    cmp  dword [rbx + 48], 0        ; subsystem version is zero
    jne  .bad
    cmp  dword [rbx + 52], 0        ; reserved Win32VersionValue
    jne  .bad
    cmp  dword [rbx + 64], 0        ; unsigned fluid payload has no checksum
    jne  .bad
    cmp  dword [rbx + 68], 10       ; EFI application, DllCharacteristics=0
    jne  .bad
    cmp  dword [rbx + 16], 0x1000   ; exact direct-entry RVA
    jne  .bad
    cmp  qword [rbx + 24], PAX1_IMAGE_BASE
    jne  .bad
    cmp  dword [rbx + 32], PAX1_SECTION_ALIGNMENT
    jne  .bad
    cmp  dword [rbx + 36], PAX1_FILE_ALIGNMENT
    jne  .bad
    cmp  qword [rbx + 72], 0        ; no stack/heap reservation profile
    jne  .bad
    cmp  qword [rbx + 80], 0
    jne  .bad
    cmp  qword [rbx + 88], 0
    jne  .bad
    cmp  qword [rbx + 96], 0
    jne  .bad
    cmp  dword [rbx + 104], 0       ; LoaderFlags
    jne  .bad
    cmp  dword [rbx + 108], 16
    jne  .bad
    ; The frozen PaOS has no imports, relocations, resources, certificates,
    ; TLS, or other PE directories. Checking the entire table also prevents a
    ; future generalized loader from entering through an unexamined directory.
    lea  rdi, [rbx + 112]
    mov  ecx, 16
    xor  eax, eax
    repe scasq
    jne  .bad

    mov  eax, [rbx + 56]            ; SizeOfImage
    test eax, eax
    jz   .bad
    cmp  eax, PAX1_MAX_IMAGE_SIZE
    ja   .bad
    test eax, PAX1_SECTION_ALIGNMENT - 1
    jnz  .bad

    ; SizeOfHeaders is exactly align(end of the one-entry table, 512).
    mov  eax, r14d
    add  eax, 304
    add  eax, PAX1_FILE_ALIGNMENT - 1
    jc   .bad
    and  eax, ~(PAX1_FILE_ALIGNMENT - 1)
    cmp  [rbx + 60], eax
    jne  .bad

    lea  r15, [rbx + 0xF0]          ; sole section header
    cmp  dword [r15], '.tex'
    jne  .bad
    cmp  byte [r15 + 4], 't'
    jne  .bad
    cmp  word [r15 + 5], 0
    jne  .bad
    cmp  byte [r15 + 7], 0
    jne  .bad
    cmp  dword [r15 + 12], 0x1000   ; exact current placement
    jne  .bad
    cmp  dword [r15 + 20], 0x200
    jne  .bad
    cmp  qword [r15 + 24], 0        ; no relocation/line-number tables
    jne  .bad
    cmp  dword [r15 + 32], 0        ; no relocation/line-number entries
    jne  .bad
    cmp  dword [r15 + 36], PAX1_CURRENT_SECTION_FLAGS
    jne  .bad

    mov  esi, [r15 + 16]            ; SizeOfRawData
    test esi, esi
    jz   .bad
    test esi, PAX1_FILE_ALIGNMENT - 1
    jnz  .bad
    cmp  esi, r13d
    ja   .bad
    mov  eax, [r15 + 20]
    cmp  eax, [rbx + 60]
    jb   .bad
    mov  edx, r13d
    sub  edx, esi                    ; sole raw section ends at signed EOF
    cmp  eax, edx
    jne  .bad

    ; The virtual range uses max(VirtualSize, SizeOfRawData), checked in 32
    ; bits. Exact SizeOfImage equality closes wrap, truncation, hidden virtual
    ; tails, and every overlap outside the exact one-section profile.
    mov  ecx, [r15 + 8]
    test ecx, ecx
    jz   .bad
    cmp  ecx, esi
    cmovb ecx, esi
    mov  eax, [r15 + 12]
    add  eax, ecx
    jc   .bad
    cmp  dword [rbx + 16], eax
    jae  .bad                        ; entry must be strictly inside range
    add  eax, PAX1_SECTION_ALIGNMENT - 1
    jc   .bad
    and  eax, ~(PAX1_SECTION_ALIGNMENT - 1)
    cmp  eax, [rbx + 56]
    jne  .bad

    ; The image goes at its 1 MiB ImageBase when firmware has that range free.
    ; PaOS needs no relocation anywhere: it is assembled org 0 without absolute
    ; self-pointers (tools/abs_ptr_check.py), maps the LoadedImage range it is
    ; given (boot/boot_v2_handoff.asm, boot/paging.asm) and keeps the AP
    ; trampoline page at 0x8000 executable wherever the image lands (paging.asm
    ; split PDE0, 06f7a1d2b; before it a non-1 MiB base faulted APs). So when firmware
    ; owns part of that range (OVMF from 8 MiB) the same bytes go below 1 GiB
    ; (the PMOD sandbox CR3 hides 1-2 GiB, see PAX1_PLACE_CEILING; this also
    ; keeps the AP trampoline CR3 and 32-bit DMA below 4 GiB), above 1 MiB and
    ; clear of PaOS's fixed reservations; anything else is refused. The entire image is zeroed before
    ; bounded header/section copies, so virtual tails cannot expose stale
    ; firmware memory.
    mov  eax, [rbx + 56]
    mov  [rel pax1_placement_size], eax ; diagnostic: SizeOfImage being placed
    shr  eax, 12
    mov  [rel pax1_image_pages], rax
    mov  qword [rel pax1_image_base], PAX1_IMAGE_BASE
    mov  rax, [rel boot_services]
    mov  ecx, 2                     ; AllocateAddress
    mov  edx, 1                     ; EfiLoaderCode
    mov  r8, [rel pax1_image_pages]
    lea  r9, [rel pax1_image_base]
    call [rax + 0x28]               ; AllocatePages
    mov  [rel pax1_alloc_status_1m], rax ; diagnostic: firmware's answer at 1 MiB
    test rax, rax
    jz   .validate_placement
    mov  eax, PAX1_PLACE_CEILING
    mov  [rel pax1_image_base], rax
    mov  rax, [rel boot_services]
    mov  ecx, 1                     ; AllocateMaxAddress
    mov  edx, 1                     ; EfiLoaderCode
    mov  r8, [rel pax1_image_pages]
    lea  r9, [rel pax1_image_base]
    call [rax + 0x28]               ; AllocatePages
    mov  [rel pax1_alloc_status_max], rax ; diagnostic: fallback answer
    test rax, rax
    jnz  .bad_reset
    mov  rcx, [rel pax1_image_base]
    mov  [rel pax1_alloc_max_base], rcx ; diagnostic: base firmware returned, even if refused below
.validate_placement:
    ; Even a successful preferred-address allocation can span fixed retained
    ; memory as SizeOfImage grows. Validate either result before zeroing it.
    mov  rax, [rel pax1_image_base]
    mov  rdx, [rel pax1_image_pages]
    shl  rdx, 12
    add  rdx, rax                   ; exclusive end; pages <= 64 MiB, no wrap
    cmp  rax, PAX1_IMAGE_BASE
    jb   .free_pages
    lea  rcx, [rdx - 1]
    cmp  rcx, PAX1_PLACE_CEILING
    ja   .free_pages                ; last byte above PAX1_PLACE_CEILING
    cmp  rax, PAX1_KEEP_OUT_END
    jae  .placed
    cmp  rdx, PAX1_KEEP_OUT_START
    ja   .free_pages
.placed:

    mov  rdi, [rel pax1_image_base]
    mov  rcx, [rel pax1_image_pages]
    shl  rcx, 9                     ; pages * 4096 / 8
    xor  eax, eax
    rep  stosq
    mov  rdi, [rel pax1_image_base]
    mov  rsi, r12
    mov  ecx, [rbx + 60]
    rep  movsb
    mov  rdi, [rel pax1_image_base]
    mov  eax, [r15 + 12]
    add  rdi, rax
    mov  rsi, r12
    mov  eax, [r15 + 20]
    add  rsi, rax
    mov  ecx, [r15 + 16]
    rep  movsb
    mov  rax, [rel pax1_image_base]
    mov  edx, [rbx + 16]
    add  rax, rdx
    mov  [rel pax1_entry_address], rax

    ; Current PaOS asks BootServices for LoadedImage before EBS. Install a
    ; bounded synthetic instance on a fresh handle; it carries only the
    ; Manager's boot device, exact loaded range, and PBH1 handoff.
    lea  rdi, [rel pax1_loaded_image]
    mov  ecx, 96 / 8
    xor  eax, eax
    rep  stosq
    mov  qword [rel pax1_loaded_image], PAX1_EFI_LOADED_IMAGE_REVISION
    mov  rax, [rel image_handle]
    mov  [rel pax1_loaded_image + 8], rax
    mov  rax, [rel system_table]
    mov  [rel pax1_loaded_image + 16], rax
    mov  rax, [rel self_loaded_image]
    test rax, rax
    jz   .free_pages
    mov  rax, [rax + 24]
    mov  [rel pax1_loaded_image + 24], rax
    mov  dword [rel pax1_loaded_image + 48], PBM_HANDOFF_SIZE
    lea  rax, [rel handoff]
    mov  [rel pax1_loaded_image + 56], rax
    mov  rax, [rel pax1_image_base]
    mov  [rel pax1_loaded_image + 64], rax
    mov  eax, [rbx + 56]
    mov  [rel pax1_loaded_image + 72], rax
    mov  dword [rel pax1_loaded_image + 80], 1 ; EfiLoaderCode
    mov  dword [rel pax1_loaded_image + 84], 2 ; EfiLoaderData

    mov  qword [rel pax1_child_handle], 0
    mov  rax, [rel boot_services]
    lea  rcx, [rel pax1_child_handle]
    lea  rdx, [rel loaded_image_guid]
    xor  r8d, r8d                   ; EFI_NATIVE_INTERFACE
    lea  r9, [rel pax1_loaded_image]
    call [rax + 0x80]               ; InstallProtocolInterface
    test rax, rax
    jnz  .free_pages
    xor  eax, eax
    jmp  .out

.free_pages:
    mov  rax, [rel boot_services]
    mov  rcx, [rel pax1_image_base]
    mov  rdx, [rel pax1_image_pages]
    call [rax + 0x30]               ; FreePages
    test rax, rax
    jnz  .cleanup_failed
.bad_reset:
    mov  qword [rel pax1_image_base], 0
    mov  qword [rel pax1_image_pages], 0
    mov  qword [rel pax1_entry_address], 0
    mov  qword [rel pax1_child_handle], 0
.bad:
    mov  rax, PAX1_EFI_LOAD_ERROR
    jmp  .out
.cleanup_failed:
    ; Retain the allocation identity if firmware refuses to release it. Losing
    ; the pointer and trying another payload would turn a bounded refusal into
    ; an overlap hazard.
    mov  byte [rel fatal_policy_failure], 1
    mov  rax, PAX1_EFI_LOAD_ERROR
    jmp  .out
.unsupported:
    mov  rax, PAX1_EFI_UNSUPPORTED
.out:
    mov  rsp, rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret

; pax1_start_prepared_paos -> RAX=EFI_STATUS only if the child returned.
; Normalize independently of try_payload before releasing the source or
; entering the direct-entry bridge.
pax1_start_prepared_paos:
    push rbx
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    mov  rbx, [rel pax1_entry_address]
    test rbx, rbx
    jz   .not_ready
    cmp  qword [rel pax1_child_handle], 0
    je   .not_ready

    ; The verified source buffer is no longer authoritative after the bounded
    ; copy. Release it before the child obtains a fresh memory-map key.
    call pax1_release_verified_source
    mov  rcx, [rel system_table]
    lea  rdx, [rel handoff]
    mov  r8d, PBM_HANDOFF_SIZE
    mov  r9, [rel pax1_child_handle]
    mov  r10, rbx
    call pax1_current_paos_entry_bridge

    ; Any return is failure. Do not call BootServices here: the child may have
    ; exited them before violating the direct-entry no-return contract.
    mov  rax, PAX1_EFI_LOAD_ERROR
    jmp  .out
.not_ready:
    call pax1_release_verified_source
    mov  rax, PAX1_EFI_LOAD_ERROR
.out:
    mov  rsp, rbp
    pop  rbp
    pop  rbx
    ret

; Normalize locally because both prepared-start and refusal paths call here.
pax1_release_verified_source:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    call free_verified_source_buffer
    mov  rsp, rbp
    pop  rbp
    ret

; Exact version-1 Manager-to-bridge ABI:
;   RCX=EFI_SYSTEM_TABLE*, RDX=PBM_HANDOFF*, R8D=128.
; R9/R10 are private compatibility inputs for today's PaOS UEFI entry.
pax1_current_paos_entry_bridge:
    ; Normalize independently of the Manager's historical internal residue.
    ; Before CALL the x64 ABI requires RSP mod 16 == 0, so the child observes
    ; the standard callee residue RSP mod 16 == 8. RBP restores the exact
    ; Manager stack even when alignment discarded one word.
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32                    ; x64 shadow space
    cmp  r8d, PBM_HANDOFF_SIZE
    jne  .reject
    cmp  rcx, [rel system_table]
    jne  .reject
    lea  rax, [rel handoff]
    cmp  rdx, rax
    jne  .reject
    cmp  dword [rdx + PBM_HANDOFF_MAGIC_OFF], PBM_HANDOFF_MAGIC
    jne  .reject
    cmp  word [rdx + PBM_HANDOFF_VERSION_OFF], PBM_CONTRACT_VERSION
    jne  .reject
    cmp  word [rdx + PBM_HANDOFF_SIZE_OFF], PBM_HANDOFF_SIZE
    jne  .reject
    mov  [rel pax1_loaded_image + 56], rdx
    PAOS_NATIVE_TRACE 3          ; v2 direct intent, real synthetic handle/PBH1
    mov  rax, rcx                   ; preserve SystemTable
    mov  rcx, r9                    ; current PaOS: synthetic ImageHandle
    mov  rdx, rax                   ; current PaOS: real SystemTable
    call r10
    jmp  .out
.reject:
    ; Nothing has run yet: tell the Manager this is not a child return.
    mov  byte [rel pax1_bridge_rejected], 1
    mov  rax, PAX1_EFI_LOAD_ERROR
.out:
    mov  rsp, rbp
    pop  rbp
    ret

; Release a prepared-but-unstarted image with the same residue-independent
; firmware-call normalization as preparation.
pax1_discard_prepared_paos:
    push rbx
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    mov  rbx, [rel pax1_child_handle]
    test rbx, rbx
    jz   .pages
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    lea  rdx, [rel loaded_image_guid]
    lea  r8, [rel pax1_loaded_image]
    call [rax + 0x90]               ; UninstallProtocolInterface
    test rax, rax
    jz   .uninstalled
    ; Never free image pages while firmware still exposes a protocol pointing
    ; into preparation state. Stop this boot and retain the allocation.
    mov  byte [rel fatal_policy_failure], 1
    jmp  .out
.uninstalled:
    mov  qword [rel pax1_child_handle], 0
.pages:
    mov  rcx, [rel pax1_image_base]
    test rcx, rcx
    jz   .reset
    mov  rdx, [rel pax1_image_pages]
    mov  rax, [rel boot_services]
    call [rax + 0x30]               ; FreePages
    test rax, rax
    jnz  .free_failed
.reset:
    mov  qword [rel pax1_image_base], 0
    mov  qword [rel pax1_image_pages], 0
    mov  qword [rel pax1_entry_address], 0
    jmp  .out
.free_failed:
    mov  byte [rel fatal_policy_failure], 1
.out:
    mov  rsp, rbp
    pop  rbp
    pop  rbx
    ret

; Emit bytes owned by the proven crypto routines into the PE permissions
; they actually require.  These macros are invoked once by paos_bootmgr.asm
; after the RX code boundary.
%macro PBM_CRYPTO_RDATA 0
align 4
sha256_k:
    dd 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
    dd 0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    dd 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
    dd 0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    dd 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
    dd 0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    dd 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
    dd 0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    dd 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
    dd 0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    dd 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
    dd 0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    dd 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
    dd 0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    dd 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
    dd 0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

sha256_test_abc:     db "abc"
sha256_test_expected:
    db 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea
    db 0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23
    db 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c
    db 0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
str_sha256_stream_ok:   db "[PAOS64] L1 SHA-256 streaming KAT abc=ba7816bf PASS [sha256.stream.kat]",13,10,0
str_sha256_stream_fail: db "[PAOS64] L1 SHA-256 streaming KAT FAIL",13,10,0
rsa_sha256_digestinfo:
    db 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01
    db 0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20

%endmacro

%macro PBM_CRYPTO_MUTABLE 0
sha256_work:         times 64 dd 0
sha256_one_ctx:      times S256_CTX_SZ db 0
sha256_test_digest:  times 32 db 0
align 8
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
%endmacro
