;; MODULE cognition/quantize_f32
;; LAYER 6
;; EXPORTS cog_quantize_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Native DynamicQuantizeLinear activation stage, SSE2 baseline.
; SysV: RDI float32 input, RSI uint8 output, RDX float32 scale output,
; RCX uint8 zero-point output, R8 config (24 bytes, 8-aligned):
; u32 count,reserved=0; u64 input_bytes,output_bytes (exact count*4,count).
; Count1..786432. Input and scale4-aligned. Return0 success/1 invalid;
; invalid leaves ALL outputs untouched. Outputs are mutually disjoint and
; disjoint from input and original config; range ends checked before reads.
; Caller provides mapped, stable buffers. No model, allocation/I/O or authority.
; Config snapshot bounds the call. The kernel scans all input for NaN/Inf and
; rejects overflowed range or a nonzero range whose scale rounds to zero.
; All-zero input returns scale1,zp0,y0. Input range includes zero; scale is
; float32((max-min)/255), zp and y round nearest-even then saturate to uint8.
; Two upstream SSE4.1 roundss/cvttss2si pairs become SSE2 cvtss2si under
; temporary MXCSR0x1f80. Full caller MXCSR restored on success/refusal.
; Preserves SysV callee-saved registers. Stack including kernel <160 bytes.

cog_quantize_f32_advisory:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32                  ; config24 + saved/temporary MXCSR8
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    test r12, r12
    jz   .invalid
    test r12b, 3
    jnz  .invalid
    test r13, r13
    jz   .invalid
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    test r15, r15
    jz   .invalid
    test rbx, rbx
    jz   .invalid
    test bl, 7
    jnz  .invalid
    mov  r11, rbx
    add  r11, 24
    jc   .invalid
    mov  rax, [rbx]
    mov  [rsp], rax
    mov  rax, [rbx+8]
    mov  [rsp+8], rax
    mov  rax, [rbx+16]
    mov  [rsp+16], rax
    mov  ecx, [rsp]
    test ecx, ecx
    jz   .invalid
    cmp  ecx, 786432
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
    mov  eax, ecx
    shl  rax, 2
    cmp  [rsp+8], rax
    jne  .invalid
    cmp  [rsp+16], rcx
    jne  .invalid
    add  rax, r12                 ; input end checked before kernel scan
    jc   .invalid
    mov  rdi, r13
    mov  rsi, rcx
    call .config_range_ok
    jnz  .invalid
    mov  rdi, r14
    mov  esi, 4
    call .config_range_ok
    jnz  .invalid
    mov  rdi, r15
    mov  esi, 1
    call .config_range_ok
    jnz  .invalid
    stmxcsr [rsp+24]
    mov  dword [rsp+28], 0x1f80
    ldmxcsr [rsp+28]
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, rsp
    call paos_dynamic_quantize_f32
    ldmxcsr [rsp+24]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ZF=1 iff [RDI,RDI+RSI) does not wrap or overlap original [RBX,R11) config.
; Only RAX/flags clobbered. Kernel checks all remaining input/output pairs.
.config_range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, rbx
    jbe  .range_good
    cmp  rdi, r11
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret

%include "cognition/quantize_f32_kernel.inc"
