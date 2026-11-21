;; MODULE core/lib/sha256
;; LAYER 1
;; EXPORTS sha256_stream_init, sha256_stream_update, sha256_stream_final, sha256_hash, sha256_selftest, S256_CTX_SZ
;; IMPORTS boot/serial, core/lib/mem
;; CAPS
;; OWNER saga:guest_artifact_stream_reader
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
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
    ; trackb L74 (SEC, track A 122062; rc-root ROOT-3f77642b6f12): the one-shot
    ; context is a module static that kept this call's input tail (partial
    ; block) and final state after return: a long PBKDF2 password's
    ; K0 = SHA256(pw) and its plaintext tail, the setup password. Wipe all of it
    ; on every path; the digest is already in [r12]. (The compression schedule
    ; and round state live in sha256_transform's own frame, wiped there.)
    ; Inline (no new import): RDI/RCX are caller-saved, R12 holds the result.
    mov  r12, rax                       ; result; the output pointer is done with
    lea  rdi, [rel sha256_one_ctx]
    xor  eax, eax
    mov  ecx, S256_CTX_SZ
    cld
    rep  stosb
    mov  rax, r12
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
; Each stream owns its compression schedule and round state on its stack.
; Wipe this entire private frame before ordinary return. Interrupt/cancel stack
; retirement remains the caller/fence's responsibility; the legacy one-shot
; context is still shared and retains its existing BSP/serialization contract.
SHA256_TRANSFORM_PRIVATE_BYTES equ 288 ; 256-byte schedule + 32-byte round state
sha256_transform:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    sub  rsp, 256
    lea  r12, [rsp]
    mov  ecx, 16
.load_w:
    mov  eax, [rsi]
    bswap eax
    mov  [r12], eax
    add  rsi, 4
    add  r12, 4
    dec  ecx
    jnz  .load_w
    lea  r12, [rsp]
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
    lea  r12, [rsp + 32]
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
    mov  rdi, [rsp + SHA256_TRANSFORM_PRIVATE_BYTES]
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
    mov  rdi, rsp
    mov  ecx, SHA256_TRANSFORM_PRIVATE_BYTES / 8
    xor  eax, eax
    cld
    rep  stosq
    add  rsp, SHA256_TRANSFORM_PRIVATE_BYTES
    pop  rdi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_core_lib_sha256_0 0
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

sha256_work:         times 64 dd 0
sha256_one_ctx:      times S256_CTX_SZ db 0
sha256_test_digest:  times 32 db 0
sha256_test_abc:     db "abc"
sha256_test_expected:
    db 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea
    db 0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23
    db 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c
    db 0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
str_sha256_stream_ok:   db "[PAOS64] L1 SHA-256 streaming KAT abc=ba7816bf PASS [sha256.stream.kat]",13,10,0
str_sha256_stream_fail: db "[PAOS64] L1 SHA-256 streaming KAT FAIL",13,10,0
%endmacro
WDATA_DEFER WDATA_core_lib_sha256_0
