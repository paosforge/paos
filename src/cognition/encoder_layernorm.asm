;; MODULE cognition/encoder_layernorm
;; LAYER 6
;; EXPORTS cog_encoder_layernorm_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Caller-owned 384-wide encoder LayerNorm. Same population mean/variance,
; inverse-sqrt and affine sequence as GPT-2's accepted layernorm; that routine
; is unchanged. SSE2 double intermediates avoid fp32 variance overflow and
; preserve near-equal rows. This is a numerical seam, not model admission.
;
; SysV: RDI=x, RSI=gamma, RDX=beta, RCX=output, R8=config.
; Arrays contiguous float32, 4-aligned, nonnull. Config48 bytes, 8-aligned:
; u32 rows,width=384; f32 epsilon; u32 reserved=0;
; u64 x_bytes,gamma_bytes,beta_bytes,output_bytes (exact extents).
; Rows1..512; all input/affine values finite; epsilon any finite positive f32.
; Output disjoint from all inputs and original config. Range ends checked;
; metadata snapshotted. Caller authenticates immutable model operands and owns
; mapped stable buffer lifetimes; range checks do not establish page mappings.
; EAX0 success/1 invalid. All rows/affine outputs preflight before any write;
; finite mathematical results outside [-FLT_MAX,FLT_MAX] refuse atomically.
; Successful conversion rounds to f32, including gradual underflow to zero.
; A second pass recomputes row stats, requiring stable inputs throughout.
; No shared mutable numeric scratch, allocation, I/O or authority grant.
; Temporary MXCSR0x1f80; full caller state restored on success/numeric refusal.
; Preserves RBX,RBP,R12..R15; total local stack <160 bytes, no recursion.

cog_encoder_layernorm_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 88                  ; config48, MXCSR8, row mean/invstd16, state
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
    test bl, 7
    jnz  .invalid
    mov  rax, rbx
    add  rax, 48
    jc   .invalid
    mov  rax, [rbx]
    mov  [rsp], rax
    mov  rax, [rbx+8]
    mov  [rsp+8], rax
    mov  rax, [rbx+16]
    mov  [rsp+16], rax
    mov  rax, [rbx+24]
    mov  [rsp+24], rax
    mov  rax, [rbx+32]
    mov  [rsp+32], rax
    mov  rax, [rbx+40]
    mov  [rsp+40], rax
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
    jle  .invalid                 ; zero or negative epsilon
    cmp  edx, 0x7f800000
    jae  .invalid                 ; positive infinity or NaN
    imul rax, 1536
    mov  r8, rax                  ; x/output exact bytes
    cmp  [rsp+16], rax
    jne  .invalid
    cmp  qword [rsp+24], 1536
    jne  .invalid
    cmp  qword [rsp+32], 1536
    jne  .invalid
    cmp  [rsp+40], rax
    jne  .invalid
    mov  r11, r15
    add  r11, rax                 ; output end
    jc   .invalid
    mov  rdi, rbx
    mov  esi, 48
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, r8
    call .range_ok
    jnz  .invalid
    mov  rdi, r13
    mov  esi, 1536
    call .range_ok
    jnz  .invalid
    mov  rdi, r14
    mov  esi, 1536
    call .range_ok
    jnz  .invalid
    shr  r8, 2
    xor  ecx, ecx
.scan_x:
    mov  eax, [r12+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    inc  ecx
    cmp  rcx, r8
    jb   .scan_x
    xor  ecx, ecx
.scan_affine:
    mov  eax, [r13+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    mov  eax, [r14+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    inc  ecx
    cmp  ecx, 384
    jb   .scan_affine
    stmxcsr [rsp+48]
    mov  dword [rsp+52], 0x1f80
    ldmxcsr [rsp+52]
    mov  r9, rsp                  ; fixed scratch base across local calls
    mov  dword [r9+80], 0         ; preflight pass; no output stores
    xor  ebp, ebp
.row:
    mov  eax, ebp
    imul rax, 1536
    lea  r10, [r12+rax]
    lea  r8, [r15+rax]
    call .row_stats
    xor  ecx, ecx
.affine:
    cvtss2sd xmm3, [r10+rcx*4]
    subsd xmm3, xmm0
    mulsd xmm3, xmm2
    cvtss2sd xmm4, [r13+rcx*4]
    mulsd xmm3, xmm4
    cvtss2sd xmm4, [r14+rcx*4]
    addsd xmm3, xmm4
    cmp  dword [r9+80], 0
    jne  .write
    movq rax, xmm3
    btr  rax, 63
    movq xmm4, rax
    ucomisd xmm4, [rel .max_f32]
    jp   .numeric_invalid
    ja   .numeric_invalid
    jmp  .next_column
.write:
    cvtsd2ss xmm3, xmm3
    movss [r8+rcx*4], xmm3
.next_column:
    inc  ecx
    cmp  ecx, 384
    jb   .affine
    inc  ebp
    cmp  ebp, [r9]
    jb   .row
    cmp  dword [r9+80], 0
    jne  .success
    mov  dword [r9+80], 1         ; all values fit; second pass may write
    xor  ebp, ebp
    jmp  .row
.success:
    ldmxcsr [rsp+48]
    xor  eax, eax
    jmp  .out
.numeric_invalid:
    ldmxcsr [rsp+48]
.invalid:
    mov  eax, 1
.out:
    add  rsp, 88
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Population statistics over one row. R10=x row, R9=scratch/config base.
; Return XMM0=mean, XMM2=invstd, also stored in caller-local row scratch.
.row_stats:
    xorpd xmm0, xmm0
    xor  ecx, ecx
.mean_loop:
    cvtss2sd xmm1, [r10+rcx*4]
    addsd xmm0, xmm1
    inc  ecx
    cmp  ecx, 384
    jb   .mean_loop
    divsd xmm0, [rel .width]
    movsd [r9+56], xmm0
    xorpd xmm1, xmm1
    xor  ecx, ecx
.variance_loop:
    cvtss2sd xmm3, [r10+rcx*4]
    subsd xmm3, xmm0
    mulsd xmm3, xmm3
    addsd xmm1, xmm3
    inc  ecx
    cmp  ecx, 384
    jb   .variance_loop
    divsd xmm1, [rel .width]
    cvtss2sd xmm3, [r9+8]
    addsd xmm1, xmm3
    sqrtsd xmm1, xmm1
    movsd xmm2, [rel .one]
    divsd xmm2, xmm1
    movsd [r9+64], xmm2
    ret

; ZF=1 iff nonempty [RDI,RDI+RSI) is non-wrapping/disjoint from [R15,R11).
; Only RAX/flags clobbered.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r15
    jbe  .range_good
    cmp  rdi, r11
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret
.width: dq 384.0
.one: dq 1.0
.max_f32: dq 3.40282346638528859811704183484516925440e38
