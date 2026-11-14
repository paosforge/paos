;; MODULE cognition/matmul_u8s8
;; LAYER 6
;; EXPORTS cog_matmul_u8s8_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Native classifier encoder dependency: scalar integer matrix multiplication.
; No model, authority, I/O, allocation or CPU/OS AVX2 admission/dispatch.
; The included upstream kernel has an internal AVX2 entry, never called here.
;
; SysV RDI=A uint8[rows][inner], RSI=B int8[cols][inner] (packed transpose),
; RDX=C int32[rows][cols], RCX=config (40 bytes, 8-aligned):
;   u32 rows,inner,cols; u8 a_zp; i8 b_zp; u16 reserved=0;
;   u64 a_bytes,b_bytes,c_bytes (exact shape lengths required).
; Return EAX=0 success, 1 invalid; invalid leaves all caller buffers untouched.
; C is 4-aligned and disjoint from A, B and the original config. Every range
; end is carry-checked. Config is snapshotted before validation; the kernel
; reads only that snapshot. Rows1..512, inner/cols1..1536, at most 2^24 scalar
; multiply-adds per call. Larger jobs must be divided by rows/columns upstream.
; This work cap is a finite operation bound, not a measured latency promise.
; |dot| <=1536*255*255=99,878,400 fits int32 even at zero-point extremes.
; Caller authenticates immutable weights and holds mapped buffers alive; range
; checks do not establish page permissions or provide concurrency ownership.
; Callee-saved registers preserved. Stack use including kernel <208 bytes.

COG_MATMUL_MAX_WORK equ 16777216

cog_matmul_u8s8_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56                  ; 40-byte config snapshot; aligned kernel call
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 40
    jc   .invalid
    mov  rax, [r15]
    mov  [rsp], rax
    mov  rax, [r15+8]
    mov  [rsp+8], rax
    mov  rax, [r15+16]
    mov  [rsp+16], rax
    mov  rax, [r15+24]
    mov  [rsp+24], rax
    mov  rax, [r15+32]
    mov  [rsp+32], rax
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  ecx, [rsp+4]
    test ecx, ecx
    jz   .invalid
    cmp  ecx, 1536
    ja   .invalid
    mov  edx, [rsp+8]
    test edx, edx
    jz   .invalid
    cmp  edx, 1536
    ja   .invalid
    cmp  word [rsp+14], 0
    jne  .invalid
    mov  r8, rax
    imul r8, rcx                  ; A bytes (rows*inner)
    mov  r9, rdx
    imul r9, rcx                  ; B bytes (cols*inner)
    mov  r10, rax
    imul r10, rdx
    shl  r10, 2                   ; C bytes (rows*cols*4)
    imul rax, r9                  ; work = rows*cols*inner (bounded u32 inputs)
    cmp  rax, COG_MATMUL_MAX_WORK
    ja   .invalid
    cmp  [rsp+16], r8
    jne  .invalid
    cmp  [rsp+24], r9
    jne  .invalid
    cmp  [rsp+32], r10
    jne  .invalid
    mov  rbx, r14
    add  rbx, r10                 ; output end
    jc   .invalid
    mov  rdi, r15
    mov  esi, 40
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, r8
    call .range_ok
    jnz  .invalid
    mov  rdi, r13
    mov  rsi, r9
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, rsp
    call paos_matmul_u8s8         ; scalar entry; snapshot stays immutable
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 56
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=input base, RSI=nonzero bytes; R14=output start, RBX=output end.
; ZF=1 iff range does not wrap and is disjoint. Only RAX/flags clobbered.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r14
    jbe  .range_good
    cmp  rdi, rbx
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret

%include "cognition/matmul_u8s8_kernel.inc"
