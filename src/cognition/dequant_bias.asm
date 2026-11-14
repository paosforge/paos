;; MODULE cognition/dequant_bias
;; LAYER 6
;; EXPORTS cog_dequant_bias_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Native integer encoder postprocess: float32(int32) * (a_scale*w_scale) + bias.
; SysV: RDI int32 accumulators, RSI float32 bias, RDX float32 output, RCX config.
; Config (40 bytes, 8-aligned): u32 rows,cols; f32 a_scale,w_scale;
; u64 accum_bytes,bias_bytes,output_bytes, each exactly the shape requirement.
; Rows1..512, cols384 or1536. At most786432 elements; no allocation/I/O/authority.
; Return EAX0 success/1 invalid, invalid output untouched. All float/int arrays
; are4-aligned. Output disjoint from inputs and original config; ends checked.
; Config snapshot prevents changing dimensions/lengths during kernel execution.
; Pinned scalar kernel preflights scale bounds and every finite bounded bias.
; SSE2 baseline only; internal upstream AVX2 entry is never called. Temporary
; MXCSR0x1f80 gives nearest-even, masked exceptions, no FTZ/DAZ; the complete
; caller MXCSR (including sticky flags) is restored after success or refusal.
; Caller authenticates/holds immutable scales/bias and mapped stable buffers.
; Structural range checks do not establish page mappings or model admission.
; Preserves SysV callee-saved registers; stack including kernel <192 bytes.

cog_dequant_bias_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56                  ; config40 + saved/temporary MXCSR8; aligned
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
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  ecx, [rsp+4]
    cmp  ecx, 384
    je   .shape_ok
    cmp  ecx, 1536
    jne  .invalid
.shape_ok:
    imul rax, rcx
    shl  rax, 2
    mov  r8, rax                  ; accumulator and output bytes
    shl  rcx, 2
    mov  r9, rcx                  ; bias bytes
    cmp  [rsp+16], r8
    jne  .invalid
    cmp  [rsp+24], r9
    jne  .invalid
    cmp  [rsp+32], r8
    jne  .invalid
    mov  rbx, r14
    add  rbx, r8                  ; output end
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
    call paos_dequant_bias_f32    ; scalar entry with immutable config snapshot
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

; ZF=1 iff [RDI,RDI+RSI) is non-wrapping and disjoint from [R14,RBX).
; Only RAX/flags clobbered.
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

%include "cognition/dequant_bias_kernel.inc"
