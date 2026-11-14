;; MODULE cognition/encoder_token_cls
;; LAYER 6
;; EXPORTS cog_encoder_token_cls_f32_advisory
;; IMPORTS cog_encoder_embedding_f32_advisory cog_encoder_stack_f32_advisory
;; CAPS
;; OWNER saga:cognition
; One native token-ID -> embedding -> ordered encoder -> first-token CLS call.
; Pinned classifier4850 native_bge_host.py embedding_boundary/run_layers and
; run_ascii_text row[0]. Tokenization remains an independent accepted boundary.
; SysV RDI=u32 IDs,RSI=u32 types,RDX=u8 mask,RCX=CLS f32[384],R8=config120.
; Config8-aligned: u32 L1..512,count1..12; u64 ids_bytes,types_bytes,mask_bytes,
; cls_bytes; u64 PEM_ptr,PEM_bytes,gamma_ptr,gamma_bytes,beta_ptr,beta_bytes,
; models_ptr,models_bytes,workspace_ptr,workspace_bytes. Exact extents L4,L4,L,
; 1536,47671320,1536,1536,count312. Models use encoder_stack compact312 layout.
; For the complete BGE graph caller supplies all12 admitted model descriptors.
; Smaller counts expose bounded prefix arithmetic only, not full graph quality.
; N=L1536,Wstack=8N+max(4N+144L^2,53N/4); workspace exact2N+Wstack (max46.5MiB):
; normalized embeddingN, full encoded tensorN, shared stack scratchWstack.
; Embedding sum scratchN reuses prefix of shared scratch before stack begins.
; CLS is exact row0, no pooling/extra L2 normalization/score/class decision.
; Caller authenticates PEM/affines/layers and owns stable immutable mapped inputs.
; Whole header snapshot; structural model metadata/full64 ends and cross-stage mutable
; aliases preflight before embedding writes. CLS and entire workspace mutually
; disjoint and disjoint from IDs/types/mask/PEM/affines/models/config. Immutable
; inputs may alias. All source tensors4-aligned except byte mask/packed weights;
; model array8-aligned. Range checks do not authenticate or establish mappings.
; EAX0 success/1 invalid. CLS unchanged on every refusal; structural/ownership/mask/
; embedding preflight failures leave whole workspace unchanged. Later failure
; may retain successful embedding and prior layer states. Failed stages never
; consume stale workspace. Accepted numeric domains/all-masked arithmetic retained;
; caller inference admission policy remains separate. No allocations/global
; numeric scratch/I/O/loader/authority. Full caller MXCSR/x87/DF/nonvolatile
; GPR/RSP preserved. Including nested stack <2496bytes. Source, not quality proof.

cog_encoder_token_cls_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 280                 ; header120, child88, FP8, geometry/state
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
    test r15, r15
    jz   .invalid
    test r15b, 3
    jnz  .invalid
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 120
    jc   .invalid
    mov  [rsp+240], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 15
    jb   .snapshot
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  edx, [rsp+4]
    test edx, edx
    jz   .invalid
    cmp  edx, 12
    ja   .invalid
    imul rdx, 312
    cmp  [rsp+96], rdx
    jne  .invalid
    mov  ecx, eax
    shl  rcx, 2
    cmp  [rsp+8], rcx
    jne  .invalid
    cmp  [rsp+16], rcx
    jne  .invalid
    cmp  [rsp+24], rax
    jne  .invalid
    cmp  qword [rsp+32], 1536
    jne  .invalid
    cmp  qword [rsp+48], 47671320
    jne  .invalid
    cmp  qword [rsp+64], 1536
    jne  .invalid
    cmp  qword [rsp+80], 1536
    jne  .invalid
    mov  ebp, eax
    imul rbp, 1536
    mov  [rsp+216], rbp
    imul rax, rax
    imul rax, 144
    lea  rax, [rax+rbp*4]
    mov  ecx, [rsp]
    imul rcx, 20352
    cmp  rax, rcx
    cmovb rax, rcx
    imul rcx, rbp, 8
    add  rax, rcx
    mov  [rsp+224], rax           ; exact native stack scratch
    lea  rax, [rax+rbp*2]
    mov  [rsp+232], rax
    cmp  [rsp+112], rax
    jne  .invalid
    mov  ecx, 40
.embedding_pointers:
    mov  rdi, [rsp+rcx]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    add  ecx, 16
    cmp  ecx, 88
    jb   .embedding_pointers
    mov  r8, [rsp+88]
    test r8, r8
    jz   .invalid
    test r8b, 7
    jnz  .invalid
    mov  rax, r8
    add  rax, [rsp+96]
    jc   .invalid
    mov  rbx, [rsp+104]
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    mov  r9, rsp
    xor  edx, edx
.model_metadata:
    mov  eax, [r8]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    cmp  dword [r8+4], 0
    jne  .invalid
    mov  eax, [r8+200]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    cmp  word [r8+214], 0
    jne  .invalid
    mov  ecx, 8
.projection_metadata:
    cmp  qword [r8+rcx+8], 147456
    jne  .invalid
    cmp  qword [r8+rcx+24], 1536
    jne  .invalid
    cmp  qword [r8+rcx], 0
    je   .invalid
    mov  rdi, [r8+rcx+16]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    test dword [r8+rcx+36], 0xffffff00
    jnz  .invalid
    add  ecx, 40
    cmp  ecx, 168
    jb   .projection_metadata
    mov  ecx, 168
.attention_affine_metadata:
    cmp  qword [r8+rcx+8], 1536
    jne  .invalid
    mov  rdi, [r8+rcx]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    add  ecx, 16
    cmp  ecx, 200
    jb   .attention_affine_metadata
    cmp  qword [r8+224], 589824
    jne  .invalid
    cmp  qword [r8+240], 6144
    jne  .invalid
    cmp  qword [r8+256], 589824
    jne  .invalid
    cmp  qword [r8+272], 1536
    jne  .invalid
    cmp  qword [r8+288], 1536
    jne  .invalid
    cmp  qword [r8+304], 1536
    jne  .invalid
    mov  ecx, 216
.ffn_metadata:
    mov  rdi, [r8+rcx]
    test rdi, rdi
    jz   .invalid
    cmp  ecx, 216
    je   .ffn_next
    cmp  ecx, 248
    je   .ffn_next
    test dil, 3
    jnz  .invalid
.ffn_next:
    add  ecx, 16
    cmp  ecx, 312
    jb   .ffn_metadata
    add  r8, 312
    inc  edx
    cmp  edx, [rsp+4]
    jb   .model_metadata
    mov  r10, r15
    mov  r11, r15
    add  r11, 1536
    jc   .invalid
    call .check_sources           ; CLS preserves every source across stages
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [r9+232]
    call .range_ok                ; CLS/workspace mutually disjoint
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [r9+232]
    jc   .invalid
    call .check_sources           ; embedding may not overwrite later models
    jnz  .invalid
    xor  ecx, ecx
.mask:
    cmp  byte [r14+rcx], 1
    ja   .invalid
    inc  ecx
    cmp  ecx, [rsp]
    jb   .mask
    lea  rax, [rbx+rbp]
    mov  [rsp+256], rax           ; full encoded output
    lea  rax, [rbx+rbp*2]
    mov  [rsp+264], rax           ; shared caller scratch
    stmxcsr [rsp+208]
    mov  dword [rsp+212], 0x1f80
    ldmxcsr [rsp+212]
    mov  eax, [rsp]
    mov  [rsp+120], eax
    mov  dword [rsp+124], 0
    mov  rax, [rsp+8]
    mov  [rsp+128], rax
    mov  rax, [rsp+16]
    mov  [rsp+136], rax
    mov  rax, [rsp+48]
    mov  [rsp+144], rax
    mov  [rsp+152], rbp
    mov  rax, [rsp+56]
    mov  [rsp+160], rax
    mov  rax, [rsp+64]
    mov  [rsp+168], rax
    mov  rax, [rsp+72]
    mov  [rsp+176], rax
    mov  rax, [rsp+80]
    mov  [rsp+184], rax
    mov  rax, [rsp+264]
    mov  [rsp+192], rax
    mov  [rsp+200], rbp
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, [rsp+40]
    mov  rcx, rbx                 ; normalized embedding output
    lea  r8, [rsp+120]
    call cog_encoder_embedding_f32_advisory
    test eax, eax
    jnz  .restore                 ; embedding refusal cannot use stale X
    mov  rax, [rsp]
    mov  [rsp+120], rax
    mov  [rsp+128], rbp
    mov  eax, [rsp]
    mov  [rsp+136], rax
    mov  [rsp+144], rbp
    mov  rax, [rsp+88]
    mov  [rsp+152], rax
    mov  rax, [rsp+96]
    mov  [rsp+160], rax
    mov  rax, [rsp+264]
    mov  [rsp+168], rax
    mov  rax, [rsp+224]
    mov  [rsp+176], rax
    mov  rdi, rbx                 ; successful normalized embedding
    mov  rsi, r14                 ; original key mask
    mov  rdx, [rsp+256]
    lea  rcx, [rsp+120]
    call cog_encoder_stack_f32_advisory
    test eax, eax
    jnz  .restore                 ; failed encoder cannot publish stale CLS
    mov  rsi, [rsp+256]           ; encoded row0, exact first-token CLS
    xor  ecx, ecx
.cls:
    mov  eax, [rsi+rcx*4]
    mov  [r15+rcx*4], eax
    inc  ecx
    cmp  ecx, 384
    jb   .cls
    xor  eax, eax
.restore:
    ldmxcsr [rsp+208]
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

; Fixed R9 frame and R10/R11 mutable interval. Clobbers volatile helper GPRs.
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+8]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+16]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r14
    mov  rsi, [r9+24]
    call .range_ok
    jnz  .sources_bad
    mov  ecx, 40
.embedding_sources:
    mov  rdi, [r9+rcx]
    mov  rsi, [r9+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 88
    jb   .embedding_sources
    mov  rdi, [r9+240]
    mov  esi, 120
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+88]
    mov  rsi, [r9+96]
    call .range_ok
    jnz  .sources_bad
    mov  r8, [r9+88]
    xor  edx, edx
.model_sources:
    mov  ecx, 8
.projection_sources:
    mov  rdi, [r8+rcx]
    mov  rsi, [r8+rcx+8]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r8+rcx+16]
    mov  rsi, [r8+rcx+24]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 40
    cmp  ecx, 168
    jb   .projection_sources
    mov  ecx, 168
.affine_sources:
    mov  rdi, [r8+rcx]
    mov  rsi, [r8+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 200
    jb   .affine_sources
    mov  ecx, 216
.ffn_sources:
    mov  rdi, [r8+rcx]
    mov  rsi, [r8+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 312
    jb   .ffn_sources
    add  r8, 312
    inc  edx
    cmp  edx, [r9+4]
    jb   .model_sources
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
