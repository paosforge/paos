;; MODULE cognition/encoder_attention
;; LAYER 6
;; EXPORTS cog_encoder_attention_f32_advisory
;; IMPORTS cog_encoder_qkv_layout_f32_advisory cog_encoder_batched_matmul_f32_advisory cog_encoder_masked_softmax_f32_advisory cog_encoder_attention_unlayout_f32_advisory
;; CAPS
;; OWNER saga:cognition
; One native batch-one attention core on caller-owned Q/K/V projections[L,384].
; SysV RDI Q,RSI K,RDX V,RCX u8 mask[L],R8 final f32 context[L,384],R9 config64:
; u32 L,reserved0; u64 q_bytes,k_bytes,v_bytes,mask_bytes,out_bytes,workspace_ptr,
; workspace_bytes. L1..512, N=L*1536,S=12*L*L*4; exact lengths N,N,N,L,N,4*N+3*S.
; Workspace <=39MiB, sections: QKV bundle3N, scoresS, maskedS, probabilitiesS,
; contextN. No hidden allocation/global scratch. Inputs/output/workspace nonnull,
; f32 arrays4-aligned/config8-aligned, checked nonwrapping ranges. Both mutable
; ranges mutually disjoint and disjoint from Q/K/V/mask/original config. Immutable
; inputs may alias. Snapshot metadata, stable mapped buffers required; spans do
; not prove permissions. Model authentication/admission stays with caller.
; Q/K/V finite abs<=65536; mask0/1. Native layout pins Q/K scale0x3ed744fd and
; twelve-head transforms. Then QK -> native mask/Softmax -> PV -> inverse context.
; No causal substitution or double scaling. All-masked rows yield uniform weights.
; Score domain abs<=1e6 and context domain abs<=65536 remain enforced downstream;
; layout input admission does not guarantee their admission for arbitrary data.
; EAX0 success/1 invalid. Final output untouched on EVERY refusal. Workspace
; untouched on metadata/mask/QKV input preflight refusal; a later numeric refusal
; may leave completed stage data. On success all sections contain their results.
; Standard temporary MXCSR restored completely through nested calls, including
; refusals. SysV nonvolatile GPR/RSP/DF/x87 preserved; nested stack<600 bytes.
; No I/O/authentication/authority grant. Core only, not whole layer/encoder/model
; quality/runtime qualification. Approximation inherits accepted Softmax envelope.

cog_encoder_attention_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 184                 ; snapshot64, stage config48, FP8, sizes/pointers
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    mov  rbp, r9
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
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 64
    jc   .invalid
    mov  [rsp+168], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 8
    jb   .snapshot
    mov  ebp, [rsp]
    test ebp, ebp
    jz   .invalid
    cmp  ebp, 512
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
    mov  eax, ebp
    imul rax, 1536
    mov  [rsp+120], rax           ; N bytes per projection/context
    cmp  [rsp+8], rax
    jne  .invalid
    cmp  [rsp+16], rax
    jne  .invalid
    cmp  [rsp+24], rax
    jne  .invalid
    cmp  [rsp+40], rax
    jne  .invalid
    cmp  [rsp+32], rbp
    jne  .invalid
    mov  ecx, ebp
    imul rcx, rbp
    imul rcx, 48
    mov  [rsp+128], rcx           ; S bytes per score/probability tensor
    imul rcx, 3
    lea  rax, [rcx+rax*4]         ; exact workspace4N+3S
    cmp  [rsp+56], rax
    jne  .invalid
    mov  rdi, [rsp+48]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rsp+120]
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, [rsp+48]
    mov  rsi, [rsp+56]
    call .range_ok                ; output/workspace disjoint
    jnz  .invalid
    mov  r10, [rsp+48]
    mov  r11, r10
    add  r11, [rsp+56]
    jc   .invalid
    call .check_sources           ; workspace preserves immutable inputs
    jnz  .invalid
    xor  ecx, ecx
.scan_mask:
    cmp  byte [r15+rcx], 1
    ja   .invalid
    inc  ecx
    cmp  ecx, [rsp]
    jb   .scan_mask
    mov  rax, [rsp+120]
    imul rax, 3
    add  rax, [rsp+48]
    mov  [rsp+136], rax           ; scores
    add  rax, [rsp+128]
    mov  [rsp+144], rax           ; masked scores, mask workspace
    add  rax, [rsp+128]
    mov  [rsp+152], rax           ; probabilities
    add  rax, [rsp+128]
    mov  [rsp+160], rax           ; context in head layout
    stmxcsr [rsp+112]
    mov  dword [rsp+116], 0x1f80
    ldmxcsr [rsp+116]
    mov  [rsp+64], rbp            ; local QKV config40
    mov  rax, [rsp+120]
    mov  [rsp+72], rax
    mov  [rsp+80], rax
    mov  [rsp+88], rax
    imul rax, 3
    mov  [rsp+96], rax
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, [rsp+48]
    lea  r8, [rsp+64]
    call cog_encoder_qkv_layout_f32_advisory
    test eax, eax
    jnz  .restore                 ; QKV full-input preflight refusal
    mov  dword [rsp+64], 12       ; local QK matmul config40
    mov  [rsp+68], ebp
    mov  dword [rsp+72], 32
    mov  [rsp+76], ebp
    mov  rax, [rsp+120]
    mov  [rsp+80], rax
    mov  [rsp+88], rax
    mov  rax, [rsp+128]
    mov  [rsp+96], rax
    mov  rdi, [rsp+48]
    mov  rsi, rdi
    add  rsi, [rsp+120]           ; K bundle section
    mov  rdx, [rsp+136]
    lea  rcx, [rsp+64]
    call cog_encoder_batched_matmul_f32_advisory
    test eax, eax
    jnz  .restore
    mov  [rsp+64], rbp            ; local masked-softmax config48
    mov  rax, [rsp+128]
    mov  [rsp+72], rax
    mov  [rsp+80], rbp
    mov  [rsp+88], rax
    mov  rcx, [rsp+144]
    mov  [rsp+96], rcx
    mov  [rsp+104], rax
    mov  rdi, [rsp+136]
    mov  rsi, r15                ; caller key mask
    mov  rdx, [rsp+152]
    lea  rcx, [rsp+64]
    call cog_encoder_masked_softmax_f32_advisory
    test eax, eax
    jnz  .restore                 ; mask/softmax refusal
    mov  dword [rsp+64], 12       ; local PV matmul config40
    mov  [rsp+68], ebp
    mov  [rsp+72], ebp
    mov  dword [rsp+76], 32
    mov  rax, [rsp+128]
    mov  [rsp+80], rax
    mov  rax, [rsp+120]
    mov  [rsp+88], rax
    mov  [rsp+96], rax
    mov  rdi, [rsp+152]
    mov  rsi, [rsp+48]
    lea  rsi, [rsi+rax*2]         ; V bundle section
    mov  rdx, [rsp+160]
    lea  rcx, [rsp+64]
    call cog_encoder_batched_matmul_f32_advisory
    test eax, eax
    jnz  .restore
    mov  [rsp+64], rbp            ; local inverse context config24
    mov  rax, [rsp+120]
    mov  [rsp+72], rax
    mov  [rsp+80], rax
    mov  rdi, [rsp+160]
    mov  rsi, rbx
    lea  rdx, [rsp+64]
    call cog_encoder_attention_unlayout_f32_advisory
.restore:
    ldmxcsr [rsp+112]
    jmp  .out
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

; Validate every immutable range vs mutable[R10,R11); R9 fixed metadata base.
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+120]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+120]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r14
    mov  rsi, [r9+120]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r15
    mov  rsi, rbp
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+168]
    mov  esi, 64
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
