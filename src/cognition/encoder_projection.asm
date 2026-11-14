;; MODULE cognition/encoder_projection
;; LAYER 6
;; EXPORTS cog_encoder_projection_f32_advisory, cog_encoder_projection_prequant_advisory
;; IMPORTS cog_quantize_f32_advisory cog_matmul_u8s8_auto_advisory cog_dequant_bias_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native dynamic quantization -> integer projection -> float dequantization/bias.
; SysV RDI Xf32[rows,inner], RSI packed i8 weights[cols,inner], RDX biasf32[cols],
; RCX outputf32[rows,cols], R8 config72(8-aligned):
; u32 rows,inner,cols,reserved0; f32 weight_scale; i8 weight_zero; u8 reserved[3]=0;
; u64 x_bytes,weight_bytes,bias_bytes,out_bytes,workspace_ptr,workspace_bytes.
; Rows1..512, inner/cols each384or1536. Exact extents R*I*4,C*I,C*4,R*C*4,
; workspaceR*I+R*C*4, holding u8 quantizedX then aligned i32 accumulators.
; Quantize the WHOLE X once; preserve one activation scale/zero for all rows.
; Matrix row batches respect accepted2^24 work bound (113/28/7 rows depending
; on shape). No altered kernel bound, per-batch requantization or hidden memory.
; X,bias,out,workspace nonnull4-aligned; weights nonnull byte-aligned; checked
; ends. Both mutable ranges mutually disjoint and disjoint from all immutable
; arrays/original config. Immutable sources may alias. Metadata snapshotted.
; EAX0 success/1 invalid. Final output unchanged on every refusal. Workspace
; unchanged on metadata/quantizer preflight refusal; later refusal may retain
; complete quantized input/partial or complete accumulators. Caller owns mapped
; stable data and authenticates model parameters; spans do not prove permissions.
; Numerical domains inherit accepted quantizer/dequant: finite X, representable
; positive quantization scale; dequant each scale[1e-20,1000], product[1e-20,1e6],
; bias finite abs<=65536. Admission of X does not guarantee dequant scale admission.
; No I/O/allocation/global numeric scratch/authority grant. Guarded integer AVX2
; with exact scalar fallback; float stages stay SSE2. Complete
; caller MXCSR restored through all nested success/refusal paths. SysV nonvolatile
; GPR/RSP/DF/x87 preserved, nested stack<432 bytes (auto path416:216+8+104+8+80).
; Numerical projection only,
; not whole model/layer/encoder or runtime/quality qualification.

cog_encoder_projection_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 168                 ; snapshot72, stage40, FP8, quant outputs/state
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
    test r15b, 3
    jnz  .invalid
    test rbx, rbx
    jz   .invalid
    test bl, 7
    jnz  .invalid
    mov  rax, rbx
    add  rax, 72
    jc   .invalid
    mov  [rsp+152], rbx
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbx+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 9
    jb   .snapshot
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  ecx, [rsp+4]
    cmp  ecx, 384
    je   .inner_ok
    cmp  ecx, 1536
    jne  .invalid
.inner_ok:
    mov  edx, [rsp+8]
    cmp  edx, 384
    je   .cols_ok
    cmp  edx, 1536
    jne  .invalid
.cols_ok:
    cmp  dword [rsp+12], 0
    jne  .invalid
    test dword [rsp+20], 0xffffff00
    jnz  .invalid
    imul rax, rcx
    mov  [rsp+128], rax           ; quantized byte count
    shl  rax, 2
    cmp  [rsp+24], rax
    jne  .invalid
    mov  rax, rcx
    imul rax, rdx
    cmp  [rsp+32], rax
    jne  .invalid
    shl  rdx, 2
    cmp  [rsp+40], rdx
    jne  .invalid
    mov  eax, [rsp]
    imul rax, rdx
    cmp  [rsp+48], rax
    jne  .invalid
    add  rax, [rsp+128]
    cmp  [rsp+64], rax
    jne  .invalid
    mov  rbx, [rsp+56]            ; accumulator-only workspace start
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r15
    mov  r11, r15
    add  r11, [rsp+48]
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rsp+64]
    call .range_ok                ; final output/workspace disjoint
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rsp+64]
    jc   .invalid
    call .check_sources           ; workspace preserves immutable data
    jnz  .invalid
    mov  rax, rbx
    add  rax, [rsp+128]
    mov  [rsp+136], rax           ; accumulator workspace section
    mov  eax, 16777216
    xor  edx, edx
    div  dword [rsp+32]           ; weight bytes=inner*cols, never zero
    mov  [rsp+144], eax           ; max rows within accepted matrix work bound
    stmxcsr [rsp+112]
    mov  dword [rsp+116], 0x1f80
    ldmxcsr [rsp+116]
    mov  rax, [rsp+128]
    mov  [rsp+72], rax            ; quant config count,reserved0
    mov  rax, [rsp+24]
    mov  [rsp+80], rax
    mov  rax, [rsp+128]
    mov  [rsp+88], rax
    mov  rdi, r12
    mov  rsi, rbx
    lea  rdx, [rsp+120]           ; single activation scale
    lea  rcx, [rsp+124]           ; single activation zero point
    lea  r8, [rsp+72]
    call cog_quantize_f32_advisory
    test eax, eax
    jnz  .restore                 ; quantizer atomic refusal
    xor  ebp, ebp                ; first row of next matrix batch
.batch:
    mov  eax, [rsp]
    sub  eax, ebp
    cmp  eax, [rsp+144]
    cmova eax, [rsp+144]
    mov  [rsp+148], eax           ; current batch rows
    mov  [rsp+72], eax
    mov  eax, [rsp+4]
    mov  [rsp+76], eax
    mov  eax, [rsp+8]
    mov  [rsp+80], eax
    mov  al, [rsp+124]
    mov  [rsp+84], al
    mov  al, [rsp+20]
    mov  [rsp+85], al
    mov  word [rsp+86], 0
    mov  eax, [rsp+148]
    imul eax, [rsp+4]
    mov  [rsp+88], rax
    mov  rax, [rsp+32]
    mov  [rsp+96], rax
    mov  eax, [rsp+148]
    imul eax, [rsp+8]
    shl  rax, 2
    mov  [rsp+104], rax
    mov  eax, ebp
    imul eax, [rsp+4]
    mov  rdi, rbx
    add  rdi, rax                ; quantized row offset
    mov  rsi, r13
    mov  eax, ebp
    imul eax, [rsp+8]
    shl  rax, 2
    mov  rdx, [rsp+136]
    add  rdx, rax                ; accumulator row offset
    lea  rcx, [rsp+72]
    call cog_matmul_u8s8_auto_advisory
    test eax, eax
    jnz  .restore
    add  ebp, [rsp+148]
    cmp  ebp, [rsp]
    jb   .batch
    mov  eax, [rsp]
    mov  [rsp+72], eax
    mov  eax, [rsp+8]
    mov  [rsp+76], eax
    mov  eax, [rsp+120]
    mov  [rsp+80], eax
    mov  eax, [rsp+16]
    mov  [rsp+84], eax
    mov  rax, [rsp+48]
    mov  [rsp+88], rax
    mov  [rsp+104], rax
    mov  rax, [rsp+40]
    mov  [rsp+96], rax
    mov  rdi, [rsp+136]
    mov  rsi, r14
    mov  rdx, r15
    lea  rcx, [rsp+72]
    call cog_dequant_bias_f32_advisory
.restore:
    ldmxcsr [rsp+112]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 168
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; All immutable ranges vs mutable[R10,R11), fixed metadata base R9.
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+24]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+32]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r14
    mov  rsi, [r9+40]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+152]
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

; Narrow synchronous prequantized projection, used by layer Q/K/V only.
; Same five arguments as above EXCEPT RDI=u8[rows,inner], config80:
; original shape/weight scale/zero fields; q_bytes at24=rows*inner; exact weight/
; bias/output bytes at32/40/48; accumworkspace at56/64=rows*cols*4; tail72:f32
; activation_scale[1e-20,1000],76:u8activation_zero,77..79:reserved0.
; Snapshot80, full64 ends and bothmutable/source/config ownership before writes.
; Quantized bytes/scale/zero are borrowed caller-owned stable values for this
; call, not an admission token or reusable cache. This helper cannot prove they
; came from a particular float tensor; layer owns that one-wholeX derivation.
; Input bytes may be unaligned; f32bias/out/accum4aligned/config8aligned. Same
; rows/shapes/workcap, accepted dequant scales/product/bias domain, outputatomic
; refusal and completeFP/DF/GPR preservation. Early metadata/scale refusal also
; accumatomic; late failure mayretain accumulators. Stack<432bytes, no allocation.
cog_encoder_projection_prequant_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 168                 ; snapshot80, stage40, sizes/state, FP8
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
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
    test r15b, 3
    jnz  .invalid
    test rbx, rbx
    jz   .invalid
    test bl, 7
    jnz  .invalid
    mov  rax, rbx
    add  rax, 80
    jc   .invalid
    mov  [rsp+152], rbx
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbx+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 10
    jb   .snapshot
    mov  eax, [rsp+72]           ;same accepted activation-scale domain
    cmp  eax, 0x1e3ce508
    jb   .invalid
    cmp  eax, 0x447a0000
    ja   .invalid
    test dword [rsp+76], 0xffffff00
    jnz  .invalid
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  ecx, [rsp+4]
    cmp  ecx, 384
    je   .inner_ok
    cmp  ecx, 1536
    jne  .invalid
.inner_ok:
    mov  edx, [rsp+8]
    cmp  edx, 384
    je   .cols_ok
    cmp  edx, 1536
    jne  .invalid
.cols_ok:
    cmp  dword [rsp+12], 0
    jne  .invalid
    test dword [rsp+20], 0xffffff00
    jnz  .invalid
    imul rax, rcx
    mov  [rsp+128], rax           ; quantized byte count
    cmp  [rsp+24], rax
    jne  .invalid
    mov  rax, rcx
    imul rax, rdx
    cmp  [rsp+32], rax
    jne  .invalid
    shl  rdx, 2
    cmp  [rsp+40], rdx
    jne  .invalid
    mov  eax, [rsp]
    imul rax, rdx
    cmp  [rsp+48], rax
    jne  .invalid
    cmp  [rsp+64], rax
    jne  .invalid
    mov  rbx, [rsp+56]            ; accumulator-only workspace start
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r15
    mov  r11, r15
    add  r11, [rsp+48]
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rsp+64]
    call .range_ok                ; final output/workspace disjoint
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rsp+64]
    jc   .invalid
    call .check_sources           ; workspace preserves immutable data
    jnz  .invalid
    mov  rax, rbx
    mov  [rsp+136], rax           ; accumulator workspace section
    mov  eax, 16777216
    xor  edx, edx
    div  dword [rsp+32]           ; weight bytes=inner*cols, never zero
    mov  [rsp+144], eax           ; max rows within accepted matrix work bound
    stmxcsr [rsp+160]
    mov  dword [rsp+164], 0x1f80
    ldmxcsr [rsp+164]
    xor  ebp, ebp                ; first row of next matrix batch
.batch:
    mov  eax, [rsp]
    sub  eax, ebp
    cmp  eax, [rsp+144]
    cmova eax, [rsp+144]
    mov  [rsp+148], eax           ; current batch rows
    mov  [rsp+80], eax
    mov  eax, [rsp+4]
    mov  [rsp+84], eax
    mov  eax, [rsp+8]
    mov  [rsp+88], eax
    mov  al, [rsp+76]
    mov  [rsp+92], al
    mov  al, [rsp+20]
    mov  [rsp+93], al
    mov  word [rsp+94], 0
    mov  eax, [rsp+148]
    imul eax, [rsp+4]
    mov  [rsp+96], rax
    mov  rax, [rsp+32]
    mov  [rsp+104], rax
    mov  eax, [rsp+148]
    imul eax, [rsp+8]
    shl  rax, 2
    mov  [rsp+112], rax
    mov  eax, ebp
    imul eax, [rsp+4]
    mov  rdi, r12
    add  rdi, rax                ; quantized row offset
    mov  rsi, r13
    mov  eax, ebp
    imul eax, [rsp+8]
    shl  rax, 2
    mov  rdx, [rsp+136]
    add  rdx, rax                ; accumulator row offset
    lea  rcx, [rsp+80]
    call cog_matmul_u8s8_auto_advisory
    test eax, eax
    jnz  .restore
    add  ebp, [rsp+148]
    cmp  ebp, [rsp]
    jb   .batch
    mov  eax, [rsp]
    mov  [rsp+80], eax
    mov  eax, [rsp+8]
    mov  [rsp+84], eax
    mov  eax, [rsp+72]
    mov  [rsp+88], eax
    mov  eax, [rsp+16]
    mov  [rsp+92], eax
    mov  rax, [rsp+48]
    mov  [rsp+96], rax
    mov  [rsp+112], rax
    mov  rax, [rsp+40]
    mov  [rsp+104], rax
    mov  rdi, [rsp+136]
    mov  rsi, r14
    mov  rdx, r15
    lea  rcx, [rsp+80]
    call cog_dequant_bias_f32_advisory
.restore:
    ldmxcsr [rsp+160]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 168
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; All immutable ranges vs mutable[R10,R11), fixed metadata base R9.
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+24]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+32]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r14
    mov  rsi, [r9+40]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+152]
    mov  esi, 80
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
