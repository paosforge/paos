;; MODULE hv/vcpu_ap_hash
;; LAYER 5
;; EXPORTS vcpu_ap_sha256_hash
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; AP-private SHA256 helper. Reuses core/lib/sha256.asm's
; streaming and compression sequences, with a stack-private 112B context
; and 256B schedule. Only algorithm constants are shared. No BSP scratch,
; allocation, SIMD or privileged operations; callee-saved GPRs preserved.
; Creator: Codex, rc-vm-claude. Source 1acc77653; original file SHA256:
; 5d77d2516e2ba156332fa36616b5f5e1a0f436aa2841754188388515a34c1480
VAP_S256_STATE  equ 0
VAP_S256_TOTAL  equ 32
VAP_S256_USED   equ 40
VAP_S256_BLOCK  equ 48
VAP_S256_CTX_SZ equ 112

; vcpu_ap_sha256_stream_init(RDI=ctx) -> RAX=0
vcpu_ap_sha256_stream_init:
    mov  dword [rdi + VAP_S256_STATE],      0x6a09e667
    mov  dword [rdi + VAP_S256_STATE + 4],  0xbb67ae85
    mov  dword [rdi + VAP_S256_STATE + 8],  0x3c6ef372
    mov  dword [rdi + VAP_S256_STATE + 12], 0xa54ff53a
    mov  dword [rdi + VAP_S256_STATE + 16], 0x510e527f
    mov  dword [rdi + VAP_S256_STATE + 20], 0x9b05688c
    mov  dword [rdi + VAP_S256_STATE + 24], 0x1f83d9ab
    mov  dword [rdi + VAP_S256_STATE + 28], 0x5be0cd19
    mov  qword [rdi + VAP_S256_TOTAL], 0
    mov  qword [rdi + VAP_S256_USED], 0
    xor  eax, eax
    ret

; vcpu_ap_sha256_stream_update(RDI=ctx,RSI=data,RDX=len) -> RAX=0/-1 (length overflow)
vcpu_ap_sha256_stream_update:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rax, [r12 + VAP_S256_TOTAL]
    add  rax, r14
    jc   .fail
    mov  [r12 + VAP_S256_TOTAL], rax

    mov  rbx, [r12 + VAP_S256_USED]
    test rbx, rbx
    jz   .full_blocks
    mov  rcx, 64
    sub  rcx, rbx                         ; room in partial block
    cmp  rcx, r14
    jbe  .fill_partial
    mov  rcx, r14
.fill_partial:
    lea  rdi, [r12 + VAP_S256_BLOCK]
    add  rdi, rbx
    mov  rsi, r13
    push rcx
    rep  movsb
    pop  rcx
    add  rbx, rcx
    add  r13, rcx
    sub  r14, rcx
    mov  [r12 + VAP_S256_USED], rbx
    cmp  rbx, 64
    jne  .ok
    lea  rdi, [r12 + VAP_S256_STATE]
    lea  rsi, [r12 + VAP_S256_BLOCK]
    call vcpu_ap_sha256_transform
    mov  qword [r12 + VAP_S256_USED], 0

.full_blocks:
    cmp  r14, 64
    jb   .tail
    lea  rdi, [r12 + VAP_S256_STATE]
    mov  rsi, r13
    call vcpu_ap_sha256_transform
    add  r13, 64
    sub  r14, 64
    jmp  .full_blocks

.tail:
    test r14, r14
    jz   .ok
    lea  rdi, [r12 + VAP_S256_BLOCK]
    mov  rsi, r13
    mov  rcx, r14
    rep  movsb
    mov  [r12 + VAP_S256_USED], r14
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

; vcpu_ap_sha256_stream_final(RDI=ctx,RSI=out32) -> RAX=0/-1
vcpu_ap_sha256_stream_final:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, [r12 + VAP_S256_TOTAL]
    mov  rcx, 0x1FFFFFFFFFFFFFFF
    cmp  rax, rcx                         ; byte length must fit after *8
    ja   .fail
    mov  rbx, [r12 + VAP_S256_USED]
    cmp  rbx, 63
    ja   .fail
    lea  rdi, [r12 + VAP_S256_BLOCK]
    mov  byte [rdi + rbx], 0x80
    inc  rbx
    cmp  rbx, 56
    jbe  .one_block
    mov  rcx, 64
    sub  rcx, rbx
    xor  eax, eax
    add  rdi, rbx
    rep  stosb
    lea  rdi, [r12 + VAP_S256_STATE]
    lea  rsi, [r12 + VAP_S256_BLOCK]
    call vcpu_ap_sha256_transform
    lea  rdi, [r12 + VAP_S256_BLOCK]
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
    mov  rax, [r12 + VAP_S256_TOTAL]
    shl  rax, 3
    bswap rax
    mov  [r12 + VAP_S256_BLOCK + 56], rax
    lea  rdi, [r12 + VAP_S256_STATE]
    lea  rsi, [r12 + VAP_S256_BLOCK]
    call vcpu_ap_sha256_transform
    lea  rdi, [r12 + VAP_S256_STATE]
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

vcpu_ap_sha256_hash:
    push r12
    push r13
    push r14
    sub  rsp, VAP_S256_CTX_SZ
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rdi, rsp
    call vcpu_ap_sha256_stream_init
    mov  rdi, rsp
    mov  rsi, r13
    mov  rdx, r14
    call vcpu_ap_sha256_stream_update
    test rax, rax
    jnz  .out
    mov  rdi, rsp
    mov  rsi, r12
    call vcpu_ap_sha256_stream_final
.out:
    add  rsp, VAP_S256_CTX_SZ
    pop  r14
    pop  r13
    pop  r12
    ret

vcpu_ap_sha256_transform:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    sub  rsp, 256
    mov  r15, rsp                     ; private message schedule
    mov  r12, r15
    mov  ecx, 16
.load_w:
    mov  eax, [rsi]
    bswap eax
    mov  [r12], eax
    add  rsi, 4
    add  r12, 4
    dec  ecx
    jnz  .load_w
    mov  r12, r15
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
    mov  r12, r15
    lea  r13, [rel vcpu_ap_sha256_k]
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
    mov  rdi, [rsp + 288]
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
    add  rsp, 296
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

vcpu_ap_sha256_k:
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
