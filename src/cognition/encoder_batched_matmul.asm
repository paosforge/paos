;; MODULE cognition/encoder_batched_matmul
;; LAYER 6
;; EXPORTS cog_encoder_batched_matmul_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Bounded scalar float32 batched MatMul for native encoder QK and PV operations.
; SysV RDI A[heads,rows,inner], RSI B[heads,inner,cols], RDX C[heads,rows,cols],
; RCX config40(8-aligned): u32 heads,rows,inner,cols; u64 a_bytes,b_bytes,c_bytes.
; Heads1..12, rows/inner/cols1..512. Exact shape extents; dimensions prove every
; product fits u64 (<=12MiB per tensor, <=12*512^3 scalar multiply-adds).
; All arrays nonnull/4-aligned; range ends checked; C disjoint from A/B/original
; config; read-only A/B may alias. Metadata snapshotted before kernel execution.
; Inputs finite abs<=65536; both entire tensors preflighted before any C write.
; All admitted dot outputs finite: magnitude<=512*65536^2=2^41 before rounding.
; Sequential f32 multiply then f32 add; no FMA/transposition/scaling/broadcast.
; EAX0 success/1 invalid; invalid leaves all caller buffers untouched. No hidden
; scratch/allocation/I/O/authentication/authority. Caller owns stable mapped
; data and any model authentication/admission; spans do not prove permissions.
; Standard temporary MXCSR gives nearest-even/noDAZ/noFTZ with full caller state
; restored even on numeric refusal. Full64 SysV nonvolatile GPR/RSP/DF/x87 state
; preserved. Internal AVX2 entry unused. Total nested stack<208 bytes.
; Partial attention primitive, not whole encoder/model/runtime qualification.

cog_encoder_batched_matmul_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56                  ; config40 + caller/standard MXCSR8, aligned call
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r12, r12
    jz   .invalid
    test r12b, 3
    jnz  .invalid
    test r13, r13
    jz   .invalid
    test r13b, 3
    jnz  .invalid
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
    mov  eax, [rsp]            ; heads/batches
    test eax, eax
    jz   .invalid
    cmp  eax, 12
    ja   .invalid
    mov  ecx, [rsp+4]             ; rows
    test ecx, ecx
    jz   .invalid
    cmp  ecx, 512
    ja   .invalid
    mov  edx, [rsp+8]             ; inner
    test edx, edx
    jz   .invalid
    cmp  edx, 512
    ja   .invalid
    mov  r11d, [rsp+12]           ; columns
    test r11d, r11d
    jz   .invalid
    cmp  r11d, 512
    ja   .invalid
    mov  r8, rax
    imul r8, rcx
    imul r8, rdx
    shl  r8, 2                    ; A bytes (heads*rows*inner*4)
    mov  r9, rax
    imul r9, rdx
    imul r9, r11
    shl  r9, 2                    ; B bytes (heads*inner*cols*4)
    mov  r10, rax
    imul r10, rcx
    imul r10, r11
    shl  r10, 2                   ; C bytes (heads*rows*cols*4)
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
    stmxcsr [rsp+40]
    mov  dword [rsp+44], 0x1f80
    ldmxcsr [rsp+44]
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, rsp
    call paos_batched_matmul_f32   ; scalar entry; snapshot stays immutable
    ldmxcsr [rsp+40]
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

%include "cognition/encoder_batched_matmul_kernel.inc"
