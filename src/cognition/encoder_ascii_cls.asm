;; MODULE cognition/encoder_ascii_cls
;; LAYER 6
;; EXPORTS cog_encoder_ascii_cls_f32_advisory
;; IMPORTS cog_tokenize_ascii_advisory cog_encoder_token_cls_f32_advisory
;; CAPS
;; OWNER saga:cognition
; One synchronous native ASCII request -> pinned tokenizer -> token encoder -> CLS.
; Pinned classifier4850 native_bge_host.py run_ascii_text: lowercase WordPiece,
; special CLS/SEP IDs, zero token types, all-visible keys, exact encoded row0.
; SysV RDI=text,RSI=CLS f32[384],RDX=config120(8-aligned):
; u32 max_sequence=512,layer_count1..12; u64 text_bytes0..4096,PVT_ptr,PVT_bytes,
; CLS_bytes1536,PEM_ptr,PEM_bytes47671320,gamma_ptr,gamma_bytes1536,
; beta_ptr,beta_bytes1536,models_ptr,models_bytes=count312,work_ptr,work_bytes.
; PVT20..8MiB is accepted tokenizer's authenticated immutable vocabulary format;
; model312 is accepted encoder_stack layout. Complete BGE graph needs all12
; caller-admitted layers. Caller owns/authenticates all immutable mapped inputs;
; structural checks grant no model/policy authority and do not load artifacts.
; Exact fixed workspace48763392: IDs2048,types2048,mask512,token workspace48758784
; (maximum46.5MiB plus4608). This bounds storage before text's token count is known.
; Only successful tokenizer count2..512 determines child shape/exact used scratch;
; unused type/mask slots and child capacity remain caller scratch, never consumed.
; Output and entire caller arena mutually disjoint and disjoint from text/PVT/
; PEM/affines/every layer operand/descriptor/originalconfig. Full64 lengths/ends,
; structural metadata and all cross-stage aliases preflight before token writes.
; Empty text is admitted/non-null and yields CLS+SEP; empty source spans may touch.
; Input text/PVT byte aligned; float arrays/work4-aligned, model/config8-aligned.
; Whole header snapshot plus child config snapshot. EAX0 success/1 refusal; final
; CLS unchanged on every refusal. Structural/tokenizer refusal leaves workspace
; unchanged; later failure may retain IDs/types/mask/embedding/layer states.
; Failed tokenizer/encoder never uses stale values. No allocation/global numeric
; scratch/I/O/authority. Full caller MXCSR/x87/nonvolatile GPR/RSP preserved;
; DF explicitly restored even though accepted tokenizer lookup clears it.
; Nested stack<4096bytes. ASCII arithmetic only, not model/runtime/quality proof.

cog_encoder_ascii_cls_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 296                 ; header120, child120, FP8, flags/state48
    pushfq
    pop  rax
    mov  [rsp+248], rax
    mov  r12, rdi
    mov  r15, rsi
    mov  rbp, rdx
    test r12, r12
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
    mov  [rsp+256], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 15
    jb   .snapshot
    cmp  dword [rsp], 512
    jne  .invalid
    mov  eax, [rsp+4]
    test eax, eax
    jz   .invalid
    cmp  eax, 12
    ja   .invalid
    imul rax, 312
    cmp  [rsp+96], rax
    jne  .invalid
    cmp  qword [rsp+8], 4096
    ja   .invalid
    cmp  qword [rsp+24], 20
    jb   .invalid
    cmp  qword [rsp+24], 8388608
    ja   .invalid
    cmp  qword [rsp+32], 1536
    jne  .invalid
    cmp  qword [rsp+48], 47671320
    jne  .invalid
    cmp  qword [rsp+64], 1536
    jne  .invalid
    cmp  qword [rsp+80], 1536
    jne  .invalid
    cmp  qword [rsp+112], 48763392
    jne  .invalid
    mov  r13, [rsp+16]
    test r13, r13
    jz   .invalid
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
    mov  esi, 48763392
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, 48763392
    jc   .invalid
    call .check_sources           ; tokenizer arena preserves later model inputs
    jnz  .invalid
    stmxcsr [rsp+240]
    mov  dword [rsp+244], 0x1f80
    ldmxcsr [rsp+244]
    mov  rdi, r12
    mov  rsi, [rsp+8]
    mov  rdx, r13
    mov  rcx, [rsp+24]
    mov  r8, rbx
    mov  r9d, 512
    call cog_tokenize_ascii_advisory
    cmp  eax, 2
    jb   .token_invalid
    cmp  eax, 512
    ja   .token_invalid           ; negative tokenizer statuses are not counts
    mov  [rsp+264], eax
    xor  ecx, ecx
.types_mask:
    mov  dword [rbx+rcx*4+2048], 0 ; exact successful count of zero token types
    mov  byte [rbx+rcx+4096], 1   ; all-visible attention keys
    inc  ecx
    cmp  ecx, [rsp+264]
    jb   .types_mask
    mov  eax, [rsp+264]
    mov  ebp, eax
    imul rbp, 1536
    mov  [rsp+272], rbp
    imul rax, rax
    imul rax, 144
    lea  rax, [rax+rbp*4]
    mov  ecx, [rsp+264]
    imul rcx, 20352
    cmp  rax, rcx
    cmovb rax, rcx
    imul rcx, rbp, 10
    add  rax, rcx
    mov  [rsp+280], rax           ; exact used token encoder workspace
    xor  ecx, ecx
.child_snapshot:
    mov  rax, [rsp+rcx*8]
    mov  [rsp+rcx*8+120], rax
    inc  ecx
    cmp  ecx, 15
    jb   .child_snapshot
    mov  eax, [rsp+264]
    mov  [rsp+120], eax           ; actual token sequence; layer_count retained
    mov  [rsp+144], rax           ; mask bytes
    shl  rax, 2
    mov  [rsp+128], rax           ; token IDs bytes
    mov  [rsp+136], rax           ; type IDs bytes
    lea  rax, [rbx+4608]
    mov  [rsp+224], rax
    mov  rax, [rsp+280]
    mov  [rsp+232], rax
    mov  rdi, rbx
    lea  rsi, [rbx+2048]
    lea  rdx, [rbx+4096]
    mov  rcx, r15
    lea  r8, [rsp+120]
    call cog_encoder_token_cls_f32_advisory
    jmp  .restore
.token_invalid:
    mov  eax, 1
.restore:
    ldmxcsr [rsp+240]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    bt   qword [rsp+248], 10
    jnc  .clear_df
    std                           ; restore caller DF even after tokenizer CLD
    jmp  .leave
.clear_df:
    cld
.leave:
    add  rsp, 296
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

.check_sources:
    mov  rdi, r12
    mov  rsi, [r9+8]
    test rsi, rsi
    jz   .empty_text              ; empty text range cannot overlap
    call .range_ok
    jnz  .sources_bad
.empty_text:
    mov  rdi, r13
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
    mov  rdi, [r9+256]
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
