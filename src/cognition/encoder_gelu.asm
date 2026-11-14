;; MODULE cognition/encoder_gelu
;; LAYER 6
;; EXPORTS cog_encoder_gelu_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Feed-forward erf-form GELU: 0.5*x*(1+erf(x/sqrt(2))). Scalar SSE2 path.
; Upstream polynomial approximation, with identity/+0 tails for x>=12/x<=-12.
; All finite f32 inputs supported; approximation error checked at 2e-6 absolute.
; This differs from GPT-2's tanh-form gelu_new; its accepted path is unchanged.
; SysV: RDI float32 input, RSI float32 output, RDX config24 bytes, 8-aligned:
; u32 count,reserved=0; u64 input_bytes,output_bytes (exact count*4).
; Count1..786432; arrays nonnull, 4-aligned; no wrapping ranges. Output disjoint
; from input and original config. Metadata snapshotted, input fully preflighted
; before writes. EAX0 success/1 invalid; invalid leaves output untouched.
; Caller owns mapped stable buffers; range checks do not prove page permissions.
; No allocation/I/O/authority. Internal AVX2 entry unused. Temporary standard
; MXCSR provides nearest-even conversion; full caller state restored afterward.
; SysV callee-saved registers preserved; total local stack <144 bytes.

cog_encoder_gelu_f32_advisory:
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
    cmp  eax, 786432
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
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
    call paos_gelu_erf_f32        ; scalar entry, config snapshot
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

%include "cognition/encoder_gelu_kernel.inc"
