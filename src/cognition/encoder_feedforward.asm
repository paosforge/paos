;; MODULE cognition/encoder_feedforward
;; LAYER 6
;; EXPORTS cog_encoder_feedforward_f32_advisory
;; IMPORTS cog_encoder_projection_f32_advisory cog_encoder_gelu_f32_advisory cog_encoder_residual_norm_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native BGE feed-forward block on caller X[rows,384]: projection384->1536,
; erf-GELU, projection1536->384, Add original X, row LayerNorm. Scalar SSE2.
; SysV RDI X,RSI final output,RDX config152(8-aligned):
; u32 rows,width384; f32 epsilon,weight_scale1,weight_scale2; i8 wzp1,wzp2;
; u16 reserved0; u64 x_bytes,out_bytes; then pointer,bytes pairs for packedW1,
; bias1,packedW2,bias2,gamma,beta,workspace. Rows1..512, N=rows*1536.
; Exact model lengths589824,6144,589824,1536,1536,1536; input/output N;
; exact workspace rows*20352 =53N/4, sections hidden4N,activation4N,projectedN,
; sharedscratch17N/4. Shared scratch is reused: projection1 requires17N/4,
; projection2 uses2N, residual normalization usesN. No hidden allocation/globals.
; All nonnull; f32 data/workspace4-aligned, packed weights byte-aligned. Checked
; nonwrapping ends; both mutable ranges mutually disjoint and disjoint from all
; immutable arrays/original config. Immutable arrays may alias. Config snapshot.
; EAX0 success/1 invalid. Final output untouched on every refusal. Scratch
; unchanged on metadata or first quantizer input refusal; later refusal may leave
; completed stages, including scratch reuse. Caller owns stable mapped buffers,
; authenticated model parameters/admission; spans do not prove permissions.
; Positive finite epsilon, stage numeric domains and weight scales/zero points
; retain accepted primitive semantics. No FMA/alternate GELU/normalization.
; Standard temporary MXCSR restored fully through nested successes/refusals.
; SysV nonvolatile GPR/RSP/DF/x87 preserved; nested stack<768 bytes.
; No I/O/authority grant/model acquisition. FFN only, not whole layer/encoder,
; authenticated loader, model quality or runtime qualification.

cog_encoder_feedforward_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 280                 ; snapshot152, stage config72, FP8, pointers32
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
    add  rax, 152
    jc   .invalid
    mov  [rsp+256], r14
    xor  ecx, ecx
.snapshot:
    mov  rax, [r14+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 19
    jb   .snapshot
    mov  ebx, [rsp]
    test ebx, ebx
    jz   .invalid
    cmp  ebx, 512
    ja   .invalid
    cmp  dword [rsp+4], 384
    jne  .invalid
    cmp  word [rsp+22], 0
    jne  .invalid
    mov  eax, [rsp+8]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  ebp, ebx
    imul rbp, 1536                ; N
    cmp  [rsp+24], rbp
    jne  .invalid
    cmp  [rsp+32], rbp
    jne  .invalid
    cmp  qword [rsp+48], 589824
    jne  .invalid
    cmp  qword [rsp+64], 6144
    jne  .invalid
    cmp  qword [rsp+80], 589824
    jne  .invalid
    cmp  qword [rsp+96], 1536
    jne  .invalid
    cmp  qword [rsp+112], 1536
    jne  .invalid
    cmp  qword [rsp+128], 1536
    jne  .invalid
    mov  eax, ebx
    imul rax, 20352
    cmp  [rsp+144], rax
    jne  .invalid
    mov  ecx, 40
.model_pointer:
    mov  rdi, [rsp+rcx]
    test rdi, rdi
    jz   .invalid
    cmp  ecx, 40
    je   .model_next
    cmp  ecx, 72
    je   .model_next
    test dil, 3
    jnz  .invalid
.model_next:
    add  ecx, 16
    cmp  ecx, 136
    jb   .model_pointer
    mov  r15, [rsp+136]
    test r15, r15
    jz   .invalid
    test r15b, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r13
    mov  r11, r13
    add  r11, rbp
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [rsp+144]
    call .range_ok                ; final/workspace disjoint
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, [rsp+144]
    jc   .invalid
    call .check_sources           ; workspace preserves every model/input
    jnz  .invalid
    lea  rax, [r15+rbp*4]
    mov  [rsp+232], rax           ; activated hidden
    lea  rax, [rax+rbp*4]
    mov  [rsp+240], rax           ; projected output before residual
    add  rax, rbp
    mov  [rsp+248], rax           ; shared projection/residual scratch
    stmxcsr [rsp+224]
    mov  dword [rsp+228], 0x1f80
    ldmxcsr [rsp+228]
    mov  [rsp+152], ebx
    mov  dword [rsp+156], 384
    mov  dword [rsp+160], 1536
    mov  dword [rsp+164], 0
    mov  eax, [rsp+12]
    mov  [rsp+168], eax
    mov  dword [rsp+172], 0
    mov  al, [rsp+20]
    mov  [rsp+172], al
    mov  [rsp+176], rbp
    mov  qword [rsp+184], 589824
    mov  qword [rsp+192], 6144
    lea  rax, [rbp*4]
    mov  [rsp+200], rax
    mov  rax, [rsp+248]
    mov  [rsp+208], rax
    mov  eax, ebx
    imul rax, 6528
    mov  [rsp+216], rax
    mov  rdi, r12
    mov  rsi, [rsp+40]
    mov  rdx, [rsp+56]
    mov  rcx, r15
    lea  r8, [rsp+152]
    call cog_encoder_projection_f32_advisory
    test eax, eax
    jnz  .restore
    mov  [rsp+152], rbp            ; GELU count=rows*1536=N, reserved0
    lea  rax, [rbp*4]
    mov  [rsp+160], rax
    mov  [rsp+168], rax
    mov  rdi, r15
    mov  rsi, [rsp+232]
    lea  rdx, [rsp+152]
    call cog_encoder_gelu_f32_advisory
    test eax, eax
    jnz  .restore
    mov  [rsp+152], ebx
    mov  dword [rsp+156], 1536
    mov  dword [rsp+160], 384
    mov  dword [rsp+164], 0
    mov  eax, [rsp+16]
    mov  [rsp+168], eax
    mov  dword [rsp+172], 0
    mov  al, [rsp+21]
    mov  [rsp+172], al
    lea  rax, [rbp*4]
    mov  [rsp+176], rax
    mov  qword [rsp+184], 589824
    mov  qword [rsp+192], 1536
    mov  [rsp+200], rbp
    mov  rax, [rsp+248]
    mov  [rsp+208], rax
    lea  rax, [rbp*2]
    mov  [rsp+216], rax
    mov  rdi, [rsp+232]
    mov  rsi, [rsp+72]            ; second projection weights
    mov  rdx, [rsp+88]
    mov  rcx, [rsp+240]
    lea  r8, [rsp+152]
    call cog_encoder_projection_f32_advisory
    test eax, eax
    jnz  .restore                 ; second projection refusal
    mov  [rsp+152], ebx
    mov  dword [rsp+156], 384
    mov  eax, [rsp+8]
    mov  [rsp+160], eax
    mov  dword [rsp+164], 0
    mov  [rsp+168], rbp
    mov  [rsp+176], rbp
    mov  qword [rsp+184], 1536
    mov  qword [rsp+192], 1536
    mov  [rsp+200], rbp
    mov  rax, [rsp+248]
    mov  [rsp+208], rax
    mov  [rsp+216], rbp
    mov  rdi, [rsp+240]
    mov  rsi, r12                ; original residual input
    mov  rdx, [rsp+104]           ; gamma
    mov  rcx, [rsp+120]
    mov  r8, r13
    lea  r9, [rsp+152]
    call cog_encoder_residual_norm_f32_advisory
.restore:
    ldmxcsr [rsp+224]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 280
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Every immutable range vs mutable[R10,R11), fixed metadata R9.
.check_sources:
    mov  rdi, r12
    mov  rsi, rbp
    call .range_ok
    jnz  .sources_bad
    mov  edx, 40
.model_range:
    mov  rdi, [r9+rdx]
    mov  rsi, [r9+rdx+8]
    call .range_ok
    jnz  .sources_bad
    add  edx, 16
    cmp  edx, 136
    jb   .model_range
    mov  rdi, [r9+256]
    mov  esi, 152
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
