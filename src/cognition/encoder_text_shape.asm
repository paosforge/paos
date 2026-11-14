;; MODULE cognition/encoder_text_shape
;; LAYER 6
;; EXPORTS cog_encoder_ascii_cls_shape_prepare_advisory, cog_encoder_ascii_cls_shape_f32_advisory
;; IMPORTS cog_tokenize_ascii_advisory, cog_encoder_token_cls_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Optional two-phase native ASCII inference; fixed encoder_ascii_cls API unchanged.
; Preparation SysV RDI=text,RSI=PVT1,RDX=record2096,RCX=config24(8aligned):
; u64 text_bytes0..4096,PVT_bytes20..8MiB,record_bytes2096. Record8aligned:
; u32 L2..512,reserved0; u64 arena_bytes,text_ptr,text_bytes,PVT_ptr,PVT_bytes;
; u32 IDs[512] reserved capacity. Only header+used IDs need readable/writable
; mappings; full capacity is reserved for ownership. Success writes header48
; and ONLY L used IDs, leaving tail intact.
; EAX0/1; every refused preparation leaves entire record untouched. No inference
; arena/model needed to determine shape. Private stack stages tokenizer output.
;
; Execution SysV RDI=text,RSI=CLS f32[384],RDX=config120,RCX=prepared record2096.
; Config is fixed ASCII layout: u32 maximum512,count1..12; u64 text_bytes,PVTptr,
; PVTbytes,CLSbytes1536,PEMptr,PEMbytes47671320,gammaptr/gammabytes1536,betaptr/
; betabytes1536,modelsptr/modelsbytes=count312,workptr/workbytes=exact arena(L).
; Full BGE inference always needs all12 caller-admitted layers, regardless of L.
; Both phases borrow authenticated immutable mapped text/PVT; execution also
; borrows immutable prepared record/PEM/affines/models held stable for the call.
; Preparation is caller-owned data, NOT an admission token/cache/authentication.
; Header/identity/length snapshot, bound L then exact64bit sizing; privately
; re-tokenize current text/PVT and compare count/used IDs before any arena write.
; This pins actual tokens across phases, consumes no unused capacity and rejects
; stale shape/content. The private current IDs, not unchecked record data, feed
; inference. Caller still owns authentication, mapped lifetimes and serialization.
;
; N=L1536,T=10N+max(4N+144L^2,20352L); prefix=align4(9L),arena=prefix+T.
; L2 yields71444bytes,L51248763392. Bounded L<=512 makes all64bit products safe.
; Arena holds exact IDs4L/types4L/maskL, untouched alignment0..3, then exact token
; encoder T. Fixed public API/layout/bytes unchanged. Entire caller arena and
; CLS disjoint from each other and every source, every layer operand, original
; config120 and full prepared2096. Full64 ends/lengths/structural metadata before
; numeric writes. Empty text nonnull/zero-span admitted; no permissions inferred.
; EAX0 success/1 refusal. Final CLS unchanged on every refusal. Structural/shape/
; tokenizer/mismatch refusal leaves arena unchanged; later child refusal may
; retain token/type/mask and successful numeric states. Prepared record immutable
; on execution; unused prepared IDs/prefix alignment bytes never read/written.
; Uses existing PEM/PVT/stack/guarded projection/sharedQKV/scalar fallback, no new
; model format/allocator/global scratch or policy. Complete MXCSR/x87/DF/GPR/RSP
; preserved. Prepare nested stack<5264bytes; execution<5632bytes (own2472 plus
; max tokenizer<3072 +8; numeric child<2496 +8). No runtime/speed/quality claim.

cog_encoder_ascii_cls_shape_prepare_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 2120               ; IDs2048, snapshot24, flags/FP/shape state
    pushfq
    pop  rax
    mov  [rsp+2072], rax
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    test r14, r14
    jz   .invalid
    test r14b, 7
    jnz  .invalid
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 24
    jc   .invalid
    mov  rax, [r15]
    mov  [rsp+2048], rax
    mov  rax, [r15+8]
    mov  [rsp+2056], rax
    mov  rax, [r15+16]
    mov  [rsp+2064], rax
    cmp  qword [rsp+2048], 4096
    ja   .invalid
    cmp  qword [rsp+2056], 20
    jb   .invalid
    cmp  qword [rsp+2056], 8388608
    ja   .invalid
    cmp  qword [rsp+2064], 2096
    jne  .invalid
    mov  rbx, r14
    add  rbx, 2096
    jc   .invalid
    mov  rdi, r12
    mov  rsi, [rsp+2048]
    test rsi, rsi
    jz   .empty_text
    call .range_ok
    jnz  .invalid
.empty_text:
    mov  rdi, r13
    mov  rsi, [rsp+2056]
    call .range_ok
    jnz  .invalid
    mov  rdi, r15
    mov  esi, 24
    call .range_ok
    jnz  .invalid
    stmxcsr [rsp+2088]
    mov  dword [rsp+2092], 0x1f80
    ldmxcsr [rsp+2092]
    mov  rdi, r12
    mov  rsi, [rsp+2048]
    mov  rdx, r13
    mov  rcx, [rsp+2056]
    mov  r8, rsp
    mov  r9d, 512
    call cog_tokenize_ascii_advisory
    cmp  eax, 2
    jb   .token_invalid
    cmp  eax, 512
    ja   .token_invalid
    mov  [rsp+2096], eax
    call cog_encoder_text_shape_size
    mov  [r14+8], rax
    mov  eax, [rsp+2096]
    mov  [r14], eax
    mov  dword [r14+4], 0
    mov  [r14+16], r12
    mov  rax, [rsp+2048]
    mov  [r14+24], rax
    mov  [r14+32], r13
    mov  rax, [rsp+2056]
    mov  [r14+40], rax
    xor  ecx, ecx
.copy:
    mov  eax, [rsp+rcx*4]
    mov  [r14+48+rcx*4], eax
    inc  ecx
    cmp  ecx, [rsp+2096]
    jb   .copy
    xor  eax, eax
    jmp  .restore
.token_invalid:
    mov  eax, 1
.restore:
    ldmxcsr [rsp+2088]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    bt   qword [rsp+2072], 10
    jnc  .clear_df
    std
    jmp  .leave
.clear_df:
    cld
.leave:
    add  rsp, 2120
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
; R14/RBX whole mutable record; input RDI/RSI, only RAX/flags clobbered.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    cmp  rax, r14
    jbe  .good
    cmp  rdi, rbx
    jae  .good
.bad:
    or   eax, 1
    ret
.good:
    xor  eax, eax
    ret

cog_encoder_ascii_cls_shape_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 2424                ; header/child/FP/state296, shape48, privateIDs2048, refs
    pushfq
    pop  rax
    mov  [rsp+248], rax
    mov  r12, rdi
    mov  r15, rsi
    mov  rbp, rdx
    mov  [rsp+2392], rcx          ; original preparation record, immutable source
    test rcx, rcx
    jz   .invalid
    test cl, 7
    jnz  .invalid
    mov  rax, rcx
    add  rax, 2096
    jc   .invalid
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
    mov  rdx, [rsp+2392]
    xor  ecx, ecx
.shape_snapshot:
    mov  rax, [rdx+rcx*8]
    mov  [rsp+296+rcx*8], rax
    inc  ecx
    cmp  ecx, 6
    jb   .shape_snapshot
    mov  eax, [rsp+296]
    cmp  eax, 2
    jb   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+300], 0
    jne  .invalid
    mov  [rsp+264], eax           ; pin admitted L before shape arithmetic
    call cog_encoder_text_shape_size
    cmp  [rsp+304], rax
    jne  .invalid
    cmp  [rsp+112], rax           ; exact true arena, full64 comparison
    jne  .invalid
    mov  [rsp+280], rdx           ; exact token encoder workspace
    mov  [rsp+2400], rcx          ; aligned compact token/type/mask prefix
    mov  eax, [rsp+264]
    imul rax, 1536
    mov  [rsp+272], rax
    cmp  [rsp+312], r12           ; same live text/table identity and lengths
    jne  .invalid
    mov  rax, [rsp+8]
    cmp  [rsp+320], rax
    jne  .invalid
    mov  rax, [rsp+16]
    cmp  [rsp+328], rax
    jne  .invalid
    mov  rax, [rsp+24]
    cmp  [rsp+336], rax
    jne  .invalid
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
    mov  rsi, [r9+112]
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [r9+112]
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
    lea  r8, [rsp+344]           ; private staging, no inference writes yet
    mov  r9d, 512
    call cog_tokenize_ascii_advisory
    cmp  eax, 2
    jb   .token_invalid
    cmp  eax, 512
    ja   .token_invalid           ; negative tokenizer statuses are not counts
    cmp  eax, [rsp+264]
    jne  .token_invalid           ; shape cannot change between phases
    mov  rdx, [rsp+2392]
    xor  ecx, ecx
.compare_tokens:
    mov  eax, [rsp+344+rcx*4]
    cmp  eax, [rdx+48+rcx*4]
    jne  .token_invalid           ; stale/corrupted preparation is not admission
    inc  ecx
    cmp  ecx, [rsp+264]
    jb   .compare_tokens
    mov  r10d, [rsp+264]
    shl  r10, 2                  ; types begin after L IDs, not capacity512
    mov  r11, r10
    shl  r11, 1                  ; mask after L IDs and L types
    xor  ecx, ecx
.publish_tokens:
    mov  eax, [rsp+344+rcx*4]
    mov  [rbx+rcx*4], eax
    lea  rdx, [rbx+r10]
    mov  dword [rdx+rcx*4], 0
    lea  rdx, [rbx+r11]
    mov  byte [rdx+rcx], 1
    inc  ecx
    cmp  ecx, [rsp+264]
    jb   .publish_tokens
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
    mov  rax, [rsp+2400]
    add  rax, rbx
    mov  [rsp+224], rax
    mov  rax, [rsp+280]
    mov  [rsp+232], rax
    mov  rdi, rbx
    mov  esi, [rsp+264]
    shl  rsi, 2
    lea  rdx, [rbx+rsi*2]
    add  rsi, rbx
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
    add  rsp, 2424
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
    mov  rdi, [r9+2392]
    mov  esi, 2096               ; protect entire preparation record capacity
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

; Private arithmetic: EAX already admitted2..512; returns RAXarena,RDXtoken,
; RCXaligned prefix. All other clobbers volatile; no state/cache/caller writes.
cog_encoder_text_shape_size:
    mov  r10d, eax
    imul r10, 1536
    mov  edx, eax
    imul rdx, rdx
    imul rdx, 144
    lea  rdx, [rdx+r10*4]
    mov  r11d, eax
    imul r11, 20352
    cmp  rdx, r11
    cmovb rdx, r11
    imul r11, r10, 10
    add  rdx, r11
    lea  ecx, [eax+eax*8]
    add  rcx, 3
    and  rcx, -4
    lea  rax, [rdx+rcx]
    ret
