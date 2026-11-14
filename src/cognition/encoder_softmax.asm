;; MODULE cognition/encoder_softmax
;; LAYER 6
;; EXPORTS cog_encoder_softmax_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Bounded last-axis attention Softmax, scalar SSE2. SysV: RDI input f32,
; RSI output f32, RDX config24 (8-aligned): u32 rows,width; u64 input_bytes,
; output_bytes, exact rows*width*4. Rows1..6144 width1..512 (BGE12 heads).
; Accept finite |score|<=1e6 or exact -FLT_MAX mask sentinel. Input fully
; preflighted; EAX0 success/1 invalid, invalid leaves output unchanged.
; Arrays nonnull/4-aligned/nonwrapping; output disjoint from input and original
; config. Metadata snapshotted. Caller owns stable mapped buffers; checks do
; not prove page permissions. No allocation, I/O, authentication or authority.
; Polynomial stable exp(score-row_max); differences below -80 become zero.
; Approximate probabilities: host oracle tolerance2e-6 abs +2e-5 relative.
; An entirely masked row yields uniform probabilities, preserving upstream
; finite-sentinel behavior. Caller must exclude empty attention when needed.
; Full MXCSR saved/standardized/restored; callee-saved registers preserved.
; Internal AVX2 entry unused. Total nested stack <176 bytes. Not model proof.

cog_encoder_softmax_f32_advisory:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 40                  ; config24 + saved/temporary MXCSR8, aligned
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
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
    test r14b, 7
    jnz  .invalid
    mov  rax, r14
    add  rax, 24
    jc   .invalid
    mov  rax, [r14]
    mov  [rsp], rax
    mov  rax, [r14+8]
    mov  [rsp+8], rax
    mov  rax, [r14+16]
    mov  [rsp+16], rax
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 6144
    ja   .invalid
    mov  ecx, [rsp+4]
    test ecx, ecx
    jz   .invalid
    cmp  ecx, 512
    ja   .invalid
    imul eax, ecx
    shl  rax, 2
    cmp  [rsp+8], rax
    jne  .invalid
    cmp  [rsp+16], rax
    jne  .invalid
    mov  rbx, rax
    mov  r11, r13
    add  r11, rax                 ; output end
    jc   .invalid
    mov  rdi, r14
    mov  esi, 24
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, rbx
    call .range_ok
    jnz  .invalid
    stmxcsr [rsp+24]
    mov  dword [rsp+28], 0x1f80
    ldmxcsr [rsp+28]
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rsp
    call paos_softmax_f32        ; scalar entry, config snapshot
    ldmxcsr [rsp+24]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ZF=1 iff [RDI,RDI+RSI) is non-wrapping/disjoint from output [R13,R11).
; Only RAX/flags clobbered.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r13
    jbe  .range_good
    cmp  rdi, r11
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret

%include "cognition/encoder_softmax_kernel.inc"
