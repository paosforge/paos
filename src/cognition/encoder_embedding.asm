;; MODULE cognition/encoder_embedding
;; LAYER 6
;; EXPORTS cog_encoder_embedding_f32_advisory
;; IMPORTS cog_encoder_layernorm_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native PEM1 token-ID boundary: roundf32(roundf32(word+type)+position),
; then accepted 384-wide LayerNorm with epsilon f32(1e-12). Pinned graph:
; classifier4850e3f1 tools/native_bge_host.py/native/paos_embedding_sum_f32.asm.
; SysV RDI=u32 ids, RSI=u32 types, RDX=PEM1, RCX=final output, R8=config88:
; u32 L1..512,reserved0; u64 ids_bytes,types_bytes,pem_bytes,output_bytes;
; u64 gamma_ptr,gamma_bytes,beta_ptr,beta_bytes,workspace_ptr,workspace_bytes.
; Exact extents: IDs/types L*4; PEM47671320; output/workspace L*1536;
; gamma/beta1536 each. Tensors4-aligned/non-null; config8-aligned. PEM header
; <4sIIIII> is exactly (PEM1,384,30522,512,2,24), contiguous word30522 rows,
; position512 rows, type2 rows. IDs<30522, types<2; position=row index.
; Caller authenticates PEM and affine parameters and owns stable mappings.
; No model loader, admission/authority grant, allocation, I/O or global scratch.
; Complete config snapshot; full64 exact lengths, range ends and all output/
; workspace ownership checked before input dereferences. Immutable inputs may
; alias each other; both mutable ranges disjoint from all inputs/model/config
; and each other. Entire PEM float payload and affine arrays must be finite.
; Every selected rounded intermediate/final sum preflighted before scratch
; writes. EAX0 success/1 refusal. Final output unchanged on every refusal;
; workspace unchanged on metadata/index/nonfinite/sum failure, full summed
; embedding may remain if LayerNorm rejects finite out-of-f32-range outputs.
; Full caller MXCSR restored, x87/DF and SysV nonvolatile GPR/stack preserved.
; Internal RN with gradual underflow; stack including nested norm <416 bytes.

cog_encoder_embedding_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 184                 ; snapshot88, norm48, FP8, lengths/state
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbp, r8
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
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 88
    jc   .invalid
    mov  [rsp+160], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 11
    jb   .snapshot
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
    mov  edx, eax
    shl  rdx, 2
    mov  [rsp+144], rdx
    cmp  [rsp+8], rdx
    jne  .invalid
    cmp  [rsp+16], rdx
    jne  .invalid
    cmp  qword [rsp+24], 47671320
    jne  .invalid
    imul rax, 1536
    mov  [rsp+152], rax
    cmp  [rsp+32], rax
    jne  .invalid
    cmp  [rsp+80], rax
    jne  .invalid
    cmp  qword [rsp+48], 1536
    jne  .invalid
    cmp  qword [rsp+64], 1536
    jne  .invalid
    mov  rdi, [rsp+40]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    mov  rdi, [rsp+56]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    mov  rbx, [rsp+72]
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r15
    mov  r11, r15
    add  r11, [r9+152]
    jc   .invalid
    call .check_sources           ; final preserves all input/model/config
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [r9+152]
    call .range_ok                ; final and workspace mutually disjoint
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [r9+152]
    jc   .invalid
    call .check_sources           ; workspace preserves all input/model/config
    jnz  .invalid
    cmp  dword [r14], 'PEM1'
    jne  .invalid
    cmp  dword [r14+4], 384
    jne  .invalid
    cmp  dword [r14+8], 30522
    jne  .invalid
    cmp  dword [r14+12], 512
    jne  .invalid
    cmp  dword [r14+16], 2
    jne  .invalid
    cmp  dword [r14+20], 24
    jne  .invalid
    xor  ecx, ecx
.indices:
    cmp  dword [r12+rcx*4], 30522
    jae  .invalid
    cmp  dword [r13+rcx*4], 2
    jae  .invalid
    inc  ecx
    cmp  ecx, [rsp]
    jb   .indices
    xor  ecx, ecx
.model_finite:
    mov  eax, [r14+rcx*4+24]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    inc  ecx
    cmp  ecx, 11917824
    jb   .model_finite
    mov  rdi, [rsp+40]
    mov  rsi, [rsp+56]
    xor  ecx, ecx
.affine_finite:
    mov  eax, [rdi+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    mov  eax, [rsi+rcx*4]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    inc  ecx
    cmp  ecx, 384
    jb   .affine_finite
    stmxcsr [rsp+136]
    mov  dword [rsp+140], 0x1f80
    ldmxcsr [rsp+140]
    mov  dword [rsp+168], 0        ; preflight sums before any scratch store
.pass:
    xor  ebp, ebp
.row:
    mov  eax, [r12+rbp*4]
    imul rax, 1536
    lea  r9, [r14+rax+24]         ; word[token]
    mov  eax, [r13+rbp*4]
    imul rax, 1536
    lea  r11, [r14+rax+47668248]  ; type[type]
    mov  eax, ebp
    imul rax, 1536
    lea  r10, [r14+rax+46881816]  ; position[row]
    lea  rdx, [rbx+rax]
    xor  ecx, ecx
.feature:
    movss xmm0, [r9+rcx*4]
    addss xmm0, [r11+rcx*4]       ; graph order: word + type first
    movd eax, xmm0
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .numeric_invalid
    addss xmm0, [r10+rcx*4]       ; then position, second f32 rounding
    movd eax, xmm0
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .numeric_invalid
    cmp  dword [rsp+168], 0
    je   .next_feature
    movss [rdx+rcx*4], xmm0
.next_feature:
    inc  ecx
    cmp  ecx, 384
    jb   .feature
    inc  ebp
    cmp  ebp, [rsp]
    jb   .row
    cmp  dword [rsp+168], 0
    jne  .normalize
    mov  dword [rsp+168], 1
    jmp  .pass
.normalize:
    mov  eax, [rsp]
    mov  [rsp+88], eax
    mov  dword [rsp+92], 384
    mov  dword [rsp+96], 0x2b8cbccc ; f32(1e-12), pinned embedding epsilon
    mov  dword [rsp+100], 0
    mov  rax, [rsp+152]
    mov  [rsp+104], rax
    mov  qword [rsp+112], 1536
    mov  qword [rsp+120], 1536
    mov  [rsp+128], rax
    mov  rdi, rbx
    mov  rsi, [rsp+40]
    mov  rdx, [rsp+56]
    mov  rcx, r15
    lea  r8, [rsp+88]
    call cog_encoder_layernorm_f32_advisory
.restore:
    ldmxcsr [rsp+136]
    jmp  .out
.numeric_invalid:
    mov  eax, 1
    jmp  .restore
.invalid:
    mov  eax, 1
.out:
    add  rsp, 184
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; R9=fixed frame, R10/R11=mutable interval. Only RAX/RDI/RSI clobbered.
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+144]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+144]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r14
    mov  esi, 47671320
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+40]
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+56]
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+160]
    mov  esi, 88
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
