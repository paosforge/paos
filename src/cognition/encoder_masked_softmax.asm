;; MODULE cognition/encoder_masked_softmax
;; LAYER 6
;; EXPORTS cog_encoder_masked_softmax_f32_advisory
;; IMPORTS cog_encoder_softmax_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Actual native attention-mask -> row Softmax for scores[12,L,L], mask[L].
; SysV RDI scores f32, RSI mask u8 (0 masked/1 visible), RDX final f32 output,
; RCX config48 (8-aligned): u32 L,reserved=0;
; u64 score_bytes,mask_bytes,output_bytes,workspace_ptr,workspace_bytes.
; L1..512; exact extents12*L*L*4,L,12*L*L*4,12*L*L*4. Scores/output/workspace
; nonnull4-aligned; mask nonnull; all checked nonwrapping ranges. Snapshot config.
; Final output and workspace mutually disjoint and disjoint from scores/mask/
; original config. Immutable inputs may alias. Caller owns mapped stable buffers.
; Scores finite |score|<=1e6, including scores at masked positions; every mask
; byte must be0/1. Mask writes exact -FLT_MAX into scratch for masked keys,
; repeating the key mask for every query row/head. No causal-mask substitution.
; Q/K scaling/layout belongs to the preceding stage (upstream Q/K scale
; bits0x3ed744fd); this function does not rescale scores. All-masked rows yield
; uniform probabilities. Softmax approximation/cutoff match standalone seam.
; EAX0 success/1 invalid. Refusal leaves final output AND workspace unchanged:
; native mask scans all inputs before scratch writes; its successful output is
; always in the softmax domain. On success workspace holds full masked scores.
; No allocation/I/O/global numeric scratch/model acquisition/authority grant.
; Full MXCSR and SysV nonvolatile registers/DF/x87 state preserved. Scalar SSE2.
; Total local+nested stack <352 bytes. Partial attention only; no quality claim.

cog_encoder_masked_softmax_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 136                 ; snapshot48, mask32, softmax24, FP8, state16
    mov  r12, rdi                 ; scores
    mov  r13, rsi                 ; mask
    mov  r14, rdx                 ; final output
    mov  r15, rcx                 ; original config, then workspace
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
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 48
    jc   .invalid
    mov  [rsp+112], r15
    xor  ecx, ecx
.snapshot:
    mov  rax, [r15+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 6
    jb   .snapshot
    mov  ebp, [rsp]
    test ebp, ebp
    jz   .invalid
    cmp  ebp, 512
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
    mov  eax, ebp
    imul eax, ebp
    imul eax, 48                  ;12 heads, float32
    mov  rbx, rax
    cmp  [rsp+8], rax
    jne  .invalid
    cmp  [rsp+16], rbp
    jne  .invalid
    cmp  [rsp+24], rax
    jne  .invalid
    cmp  [rsp+40], rax
    jne  .invalid
    mov  r15, [rsp+32]
    test r15, r15
    jz   .invalid
    test r15b, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r14
    mov  r11, r14
    add  r11, rbx
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, rbx
    call .range_ok                ; output and scratch must be disjoint
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, rbx
    jc   .invalid
    call .check_sources           ; scratch preserves every immutable input
    jnz  .invalid
    stmxcsr [rsp+104]
    mov  dword [rsp+108], 0x1f80
    ldmxcsr [rsp+108]
    mov  [rsp+48], rbp            ; L + reserved0, mask config32
    mov  [rsp+56], rbx
    mov  [rsp+64], rbp
    mov  [rsp+72], rbx
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r15
    lea  rcx, [rsp+48]
    call paos_attention_mask_f32
    test eax, eax
    jnz  .restore
    mov  eax, ebp
    imul eax, 12
    mov  [rsp+80], eax            ; rows12*L
    mov  [rsp+84], ebp            ; widthL
    mov  [rsp+88], rbx
    mov  [rsp+96], rbx
    mov  rdi, r15
    mov  rsi, r14
    lea  rdx, [rsp+80]
    call cog_encoder_softmax_f32_advisory
.restore:
    ldmxcsr [rsp+104]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 136
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Check all immutable ranges against mutable[R10,R11). R9 fixed metadata base.
.check_sources:
    mov  rdi, r12
    mov  rsi, rbx
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, rbp
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+112]
    mov  esi, 48
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

%include "cognition/encoder_attention_mask_kernel.inc"
