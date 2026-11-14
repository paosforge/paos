;; MODULE cognition/encoder_residual_norm
;; LAYER 6
;; EXPORTS cog_encoder_residual_norm_f32_advisory
;; IMPORTS cog_encoder_layernorm_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native residual Add -> accepted row LayerNorm, no hidden allocation/scheduler.
; SysV RDI=A, RSI=B, RDX=gamma, RCX=beta, R8=final output, R9=config72 bytes:
; u32 rows,width=384; f32 epsilon; u32 reserved=0;
; u64 a_bytes,b_bytes,gamma_bytes,beta_bytes,output_bytes,workspace_ptr,workspace_bytes.
; Rows1..512; exact extents (rows*1536, rows*1536,1536,1536,rows*1536,rows*1536).
; All tensors4-aligned/non-null, config8-aligned; no wrapping ranges. Final
; output and workspace mutually disjoint and disjoint from all read-only inputs
; and original config. Read-only inputs may alias each other. Metadata snapshotted.
; EAX0 success/1 invalid. Final output is unchanged on any refusal; inputs/model
; operands/config never written. Workspace is caller-owned scratch and may hold
; full residual sums if subsequent normalization refuses. Numeric Add failure
; leaves workspace unchanged because every sum is preflighted before stores.
; Residual sums round to float32 before LayerNorm; nonfinite operands or sums
; refuse. Finite positive epsilon and affine/output rules match the accepted
; LayerNorm. Stable mapped buffers and authenticated immutable model operands
; remain caller obligations. No I/O, global numeric scratch or authority grant.
; SSE2 nearest-even with complete caller MXCSR restoration after nested call.
; Preserves SysV callee-saved registers; total local+nested stack <384 bytes.

cog_encoder_residual_norm_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 152                 ; config72 + norm config48 + MXCSR8 + state
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8                  ; final output
    mov  rbp, r9                  ; original config until snapshot complete
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
    test r15b, 3
    jnz  .invalid
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 72
    jc   .invalid
    mov  [rsp+136], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 9
    jb   .snapshot
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+4], 384
    jne  .invalid
    cmp  dword [rsp+12], 0
    jne  .invalid
    mov  edx, [rsp+8]
    test edx, edx
    jle  .invalid
    cmp  edx, 0x7f800000
    jae  .invalid
    imul rax, 1536
    mov  [rsp+128], rax
    cmp  [rsp+16], rax
    jne  .invalid
    cmp  [rsp+24], rax
    jne  .invalid
    cmp  qword [rsp+32], 1536
    jne  .invalid
    cmp  qword [rsp+40], 1536
    jne  .invalid
    cmp  [rsp+48], rax
    jne  .invalid
    cmp  [rsp+64], rax
    jne  .invalid
    mov  rbp, [rsp+56]            ; workspace
    test rbp, rbp
    jz   .invalid
    test bpl, 3
    jnz  .invalid
    mov  r9, rsp                  ; fixed metadata/scratch base for helpers
    mov  r10, rbx
    mov  r11, rbx
    add  r11, rax                 ; final output end
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, rbp
    mov  rsi, [r9+128]
    call .range_ok                ; final output/workspace must be disjoint
    jnz  .invalid
    mov  r10, rbp
    mov  r11, rbp
    add  r11, [r9+128]
    jc   .invalid
    call .check_sources           ; workspace must preserve every input/model
    jnz  .invalid
    stmxcsr [rsp+120]
    mov  dword [rsp+124], 0x1f80
    ldmxcsr [rsp+124]
    mov  r8, [r9+128]
    shr  r8, 2
    xor  ecx, ecx
.preflight_sum:
    mov  eax, [r12+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .numeric_invalid
    mov  eax, [r13+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .numeric_invalid
    movss xmm0, [r12+rcx*4]
    addss xmm0, [r13+rcx*4]
    movd eax, xmm0
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .numeric_invalid
    inc  ecx
    cmp  rcx, r8
    jb   .preflight_sum
    xor  ecx, ecx
.write_sum:
    movss xmm0, [r12+rcx*4]
    addss xmm0, [r13+rcx*4]
    movss [rbp+rcx*4], xmm0
    inc  ecx
    cmp  rcx, r8
    jb   .write_sum
    mov  rax, [r9]
    mov  [r9+72], rax
    mov  rax, [r9+8]
    mov  [r9+80], rax
    mov  rax, [r9+128]
    mov  [r9+88], rax
    mov  qword [r9+96], 1536
    mov  qword [r9+104], 1536
    mov  [r9+112], rax
    mov  rdi, rbp
    mov  rsi, r14
    mov  rdx, r15
    mov  rcx, rbx
    lea  r8, [r9+72]
    call cog_encoder_layernorm_f32_advisory
    ldmxcsr [rsp+120]
    jmp  .out
.numeric_invalid:
    ldmxcsr [rsp+120]
.invalid:
    mov  eax, 1
.out:
    add  rsp, 152
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Validate every immutable range against mutable [R10,R11). R9=metadata base.
; Only RAX,RDI,RSI/flags clobbered. ZF=1 success.
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+128]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+128]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r14
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r15
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+136]
    mov  esi, 72
    call .range_ok
    jnz  .sources_bad
    xor  eax, eax
    ret
.sources_bad:
    or   eax, 1
    ret

.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r10
    jbe  .range_good
    cmp  rdi, r11
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret
