;; MODULE core/lib/x25519
;; LAYER 1
;; EXPORTS x25519
;; IMPORTS core/lib/mem
;; CAPS
;; OWNER saga:net
; RFC 7748 X25519, ported from the proven public-domain TweetNaCl 16x16-bit
; field representation.  Inputs and output are the RFC little-endian 32-byte
; strings.  The scalar is clamped internally.  Field multiplication carries in
; signed 64-bit limbs; the maximum intermediate is far below 2^63.

X25_FE_BYTES equ 16 * 8

x25519_fe_zero:
    xor  esi, esi
    mov  edx, X25_FE_BYTES
    jmp  memset

x25519_fe_one:
    push rdi
    call x25519_fe_zero
    pop  rdi
    mov  qword [rdi], 1
    ret

; RDI=dst, RSI=src.
x25519_fe_copy:
    mov  edx, X25_FE_BYTES
    jmp  memcpy

; Carry exactly as TweetNaCl car25519. RDI=field element.
x25519_car:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.limb:
    mov  rax, [r12 + rbx*8]
    add  rax, 1 << 16
    mov  [r12 + rbx*8], rax
    sar  rax, 16                         ; c
    mov  rdx, rax
    shl  rdx, 16
    sub  [r12 + rbx*8], rdx
    dec  rax                             ; c-1
    cmp  ebx, 15
    je   .wrap
    add  [r12 + rbx*8 + 8], rax
    jmp  .next
.wrap:
    imul rax, rax, 38
    add  [r12], rax
.next:
    inc  ebx
    cmp  ebx, 16
    jb   .limb
    pop  r12
    pop  rbx
    ret

; Constant-work conditional swap. RDI=a, RSI=b, EDX=0/1.
x25519_cswap:
    movsxd rdx, edx
    neg  rdx                             ; mask = 0 or -1
    xor  ecx, ecx
.loop:
    mov  r8, [rdi + rcx*8]
    mov  r9, [rsi + rcx*8]
    mov  r10, r8
    xor  r10, r9
    and  r10, rdx
    xor  r8, r10
    xor  r9, r10
    mov  [rdi + rcx*8], r8
    mov  [rsi + rcx*8], r9
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

; RDI=out, RSI=a, RDX=b.
x25519_add:
    xor  ecx, ecx
.loop:
    mov  rax, [rsi + rcx*8]
    add  rax, [rdx + rcx*8]
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

x25519_sub:
    xor  ecx, ecx
.loop:
    mov  rax, [rsi + rcx*8]
    sub  rax, [rdx + rcx*8]
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .loop
    ret

; RDI=out, RSI=a, RDX=b. Schoolbook product followed by 2^255=19 folding.
x25519_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32 * 8
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rsp
    mov  rdi, r15
    xor  esi, esi
    mov  edx, 32 * 8
    call memset
    xor  r8d, r8d
.outer:
    xor  r9d, r9d
.inner:
    mov  rax, [r13 + r8*8]
    imul rax, [r14 + r9*8]
    mov  r10d, r8d
    add  r10d, r9d
    add  [r15 + r10*8], rax
    inc  r9d
    cmp  r9d, 16
    jb   .inner
    inc  r8d
    cmp  r8d, 16
    jb   .outer
    xor  ecx, ecx
.fold:
    mov  rax, [r15 + rcx*8 + 16*8]
    imul rax, rax, 38
    add  [r15 + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .fold
    xor  ecx, ecx
.copy:
    mov  rax, [r15 + rcx*8]
    mov  [r12 + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .copy
    mov  rdi, r12
    call x25519_car
    mov  rdi, r12
    call x25519_car
    add  rsp, 32 * 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

x25519_sq:
    mov  rdx, rsi
    jmp  x25519_mul

; RDI=out, RSI=in. Fermat inversion z^(p-2), fixed 254-square chain.
x25519_inv:
    push rbx
    push r12
    push r13
    sub  rsp, 2 * X25_FE_BYTES
    mov  r12, rdi
    lea  r13, [rsp + X25_FE_BYTES]       ; base
    mov  rdi, r13
    call x25519_fe_copy
    mov  rdi, rsp                        ; accumulator
    mov  rsi, r13
    call x25519_fe_copy
    mov  ebx, 253
.exp:
    mov  rdi, rsp
    mov  rsi, rsp
    call x25519_sq
    cmp  ebx, 2
    je   .next
    cmp  ebx, 4
    je   .next
    mov  rdi, rsp
    mov  rsi, rsp
    mov  rdx, r13
    call x25519_mul
.next:
    dec  ebx
    jns  .exp
    mov  rdi, r12
    mov  rsi, rsp
    call x25519_fe_copy
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 2 * X25_FE_BYTES
    call memset
    add  rsp, 2 * X25_FE_BYTES
    pop  r13
    pop  r12
    pop  rbx
    ret

; Unpack 16 little-endian 16-bit limbs. RDI=fe, RSI=bytes32.
x25519_unpack:
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

; Canonical RFC little-endian packing. RDI=bytes32, RSI=fe.
x25519_pack:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 2 * X25_FE_BYTES
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rsp                        ; t; m follows it
    mov  rdi, r14
    mov  rsi, r13
    call x25519_fe_copy
    mov  rdi, r14
    call x25519_car
    mov  rdi, r14
    call x25519_car
    mov  rdi, r14
    call x25519_car
    mov  ebx, 2                         ; TweetNaCl performs two reductions
.reduce:
    xor  ecx, ecx
    xor  r8d, r8d                        ; borrow
.subp:
    mov  rax, [r14 + rcx*8]
    mov  rdx, 0xffff
    test ecx, ecx
    jnz  .not0
    mov  edx, 0xffed
.not0:
    cmp  ecx, 15
    jne  .pready
    mov  edx, 0x7fff
.pready:
    sub  rax, rdx
    sub  rax, r8
    xor  r8d, r8d
    test rax, rax
    jns  .nonneg
    add  rax, 1 << 16
    mov  r8d, 1
.nonneg:
    mov  [r14 + X25_FE_BYTES + rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .subp
    test r8d, r8d
    jnz  .reduce_next                    ; underflow: retain original t
    mov  rdi, r14
    lea  rsi, [r14 + X25_FE_BYTES]
    call x25519_fe_copy
.reduce_next:
    dec  ebx
    jnz  .reduce
    xor  ecx, ecx
.write:
    mov  eax, [r14 + rcx*8]
    mov  [r12 + rcx*2], al
    shr  eax, 8
    mov  [r12 + rcx*2 + 1], al
    inc  ecx
    cmp  ecx, 16
    jb   .write
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 2 * X25_FE_BYTES
    call memset
    add  rsp, 2 * X25_FE_BYTES
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; x25519(RDI=out32, RSI=scalar32, RDX=u32) -> 0/-1.
x25519:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 944
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test r12, r12
    jz   .fail
    test r13, r13
    jz   .fail
    test r14, r14
    jz   .fail
    ; Locals: z32, x/a/b/c/d/e/f each 128 bytes at aligned offsets.
    lea  rdi, [rsp]
    mov  rsi, r13
    mov  edx, 32
    call memcpy
    and  byte [rsp], 248
    and  byte [rsp + 31], 127
    or   byte [rsp + 31], 64
    lea  rdi, [rsp + 32]                ; x
    mov  rsi, r14
    call x25519_unpack
    lea  rdi, [rsp + 160]               ; a=1
    call x25519_fe_one
    lea  rdi, [rsp + 288]               ; b=x
    lea  rsi, [rsp + 32]
    call x25519_fe_copy
    lea  rdi, [rsp + 416]               ; c=0
    call x25519_fe_zero
    lea  rdi, [rsp + 544]               ; d=1
    call x25519_fe_one
    mov  ebx, 254
.ladder:
    mov  eax, ebx
    mov  ecx, eax
    shr  eax, 3
    and  ecx, 7
    movzx edx, byte [rsp + rax]
    shr  edx, cl
    and  edx, 1
    mov  ebp, edx
    lea  rdi, [rsp + 160]
    lea  rsi, [rsp + 288]
    call x25519_cswap
    lea  rdi, [rsp + 416]
    lea  rsi, [rsp + 544]
    mov  edx, ebp
    call x25519_cswap
    lea  rdi, [rsp + 672]               ; e=a+c
    lea  rsi, [rsp + 160]
    lea  rdx, [rsp + 416]
    call x25519_add
    lea  rdi, [rsp + 160]               ; a=a-c
    lea  rsi, [rsp + 160]
    lea  rdx, [rsp + 416]
    call x25519_sub
    lea  rdi, [rsp + 416]               ; c=b+d
    lea  rsi, [rsp + 288]
    lea  rdx, [rsp + 544]
    call x25519_add
    lea  rdi, [rsp + 288]               ; b=b-d
    lea  rsi, [rsp + 288]
    lea  rdx, [rsp + 544]
    call x25519_sub
    lea  rdi, [rsp + 544]               ; d=e^2
    lea  rsi, [rsp + 672]
    call x25519_sq
    lea  rdi, [rsp + 800]               ; f=a^2
    lea  rsi, [rsp + 160]
    call x25519_sq
    lea  rdi, [rsp + 160]               ; a=c*a
    lea  rsi, [rsp + 416]
    lea  rdx, [rsp + 160]
    call x25519_mul
    lea  rdi, [rsp + 416]               ; c=b*e
    lea  rsi, [rsp + 288]
    lea  rdx, [rsp + 672]
    call x25519_mul
    lea  rdi, [rsp + 672]               ; e=a+c
    lea  rsi, [rsp + 160]
    lea  rdx, [rsp + 416]
    call x25519_add
    lea  rdi, [rsp + 160]               ; a=a-c
    lea  rsi, [rsp + 160]
    lea  rdx, [rsp + 416]
    call x25519_sub
    lea  rdi, [rsp + 288]               ; b=a^2
    lea  rsi, [rsp + 160]
    call x25519_sq
    lea  rdi, [rsp + 416]               ; c=d-f
    lea  rsi, [rsp + 544]
    lea  rdx, [rsp + 800]
    call x25519_sub
    lea  rdi, [rsp + 160]               ; a=c*121665
    lea  rsi, [rsp + 416]
    lea  rdx, [rel x25519_121665]
    call x25519_mul
    lea  rdi, [rsp + 160]               ; a=a+d
    lea  rsi, [rsp + 160]
    lea  rdx, [rsp + 544]
    call x25519_add
    lea  rdi, [rsp + 416]               ; c=c*a
    lea  rsi, [rsp + 416]
    lea  rdx, [rsp + 160]
    call x25519_mul
    lea  rdi, [rsp + 160]               ; a=d*f
    lea  rsi, [rsp + 544]
    lea  rdx, [rsp + 800]
    call x25519_mul
    lea  rdi, [rsp + 544]               ; d=b*x
    lea  rsi, [rsp + 288]
    lea  rdx, [rsp + 32]
    call x25519_mul
    lea  rdi, [rsp + 288]               ; b=e^2
    lea  rsi, [rsp + 672]
    call x25519_sq
    lea  rdi, [rsp + 160]
    lea  rsi, [rsp + 288]
    mov  edx, ebp
    call x25519_cswap
    lea  rdi, [rsp + 416]
    lea  rsi, [rsp + 544]
    mov  edx, ebp
    call x25519_cswap
    dec  ebx
    jns  .ladder
    lea  rdi, [rsp + 416]
    lea  rsi, [rsp + 416]
    call x25519_inv
    lea  rdi, [rsp + 160]
    lea  rsi, [rsp + 160]
    lea  rdx, [rsp + 416]
    call x25519_mul
    mov  rdi, r12
    lea  rsi, [rsp + 160]
    call x25519_pack
    xor  r15d, r15d
    jmp  .wipe
.fail:
    mov  r15d, -1
.wipe:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 944
    call memset
    mov  eax, r15d
    add  rsp, 944
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

align 8
x25519_121665:
    dq 0xdb41,1
    times 14 dq 0
