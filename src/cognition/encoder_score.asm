;; MODULE cognition/encoder_score
;; LAYER 6
;; EXPORTS cog_encoder_score_f32_advisory, cog_encoder_packed_rank_f32_advisory
;; IMPORTS cog_encoder_packed_ascii_cls_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native caller-owned384-wide normalized query dot caller-prepared f32 prototypes.
; Trace classifier4850 benchmark_native_{encoder,ascii}_decision_drift.py:
; normalized CLS, prototypes @ CLS, stable descending top2. Prototypes are NOT
; renormalized here. Arithmetic is explicit: ordered double sum(q*q), sqrt with
; norm floor1e-12, denominator rounded f32, f32 division, ordered f32 mul/add dots
; (no FMA/BLAS equivalence claim). All numeric work under RN, gradual underflow;
; complete caller MXCSR restored, x87/DF/nonvolatile GPR/RSP untouched.
;
; SysV RDI=query[384],RSI=prototypes[count,384],RDX=result20,RCX=config64.
; Config8-aligned: u32 count2..256,width384; f32 min_score, min_margin>=0;
; u64 querybytes1536,prototypebytes=count*1536,resultbytes20,workspace_ptr,
; workspacebytes1536+4*count,reserved0. Buffers nonnull4-aligned, full64 ends.
; Finite abs(query/prototypes)<=65536; thresholds finite, -0 margin allowed.
; Output and entire scratch mutually disjoint and disjoint originalconfig/query/
; prototypes. Immutable inputs may alias. Complete metadata and numeric preflight
; precedes first scratch write. All invalid returns leave result/scratch unchanged.
; Workspace: normalized384f32 followed by count f32 scores. No allocation/globals.
; Result <IIfff>: status,best_index,best_score,second_score,margin(best-second).
; EAX0 choose when best>=min_score AND margin>=min_margin (inclusive),1 abstain,
; 2 invalid. Stable ties keep first index; runnerup may equal best. Valid abstain
; retains candidate/scores. Zero query normalizes tozero under floor semantics.
; Scores are uncalibrated advice, never authority/probabilities. Caller owns
; authenticated immutable mapped lifetimes, prototype preparation/labels and
; policy thresholds. No model acquisition/loading/authentication/calibration.
; Stack<192bytes; full FP/DF/ABI preserved on every path.
cog_encoder_score_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 120
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
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
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 64
    jc   .invalid
    mov  [rsp+104], r15
    xor  ecx, ecx
.snapshot:
    mov  rax, [r15+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 8
    jb   .snapshot
    mov  ebp, [rsp]
    cmp  ebp, 2
    jb   .invalid
    cmp  ebp, 256
    ja   .invalid
    cmp  dword [rsp+4], 384
    jne  .invalid
    mov  eax, [rsp+8]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [rsp+12]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    test eax, eax
    jz   .margin_valid
    test dword [rsp+12], 0x80000000
    jnz  .invalid
.margin_valid:
    cmp  qword [rsp+16], 1536
    jne  .invalid
    imul rax, rbp, 1536
    cmp  [rsp+24], rax
    jne  .invalid
    cmp  qword [rsp+32], 20
    jne  .invalid
    lea  rax, [rbp*4+1536]
    cmp  [rsp+48], rax
    jne  .invalid
    cmp  qword [rsp+56], 0
    jne  .invalid
    mov  rbx, [rsp+40]
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r14
    mov  r11, r14
    add  r11, 20
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rsp+48]
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rsp+48]
    jc   .invalid
    call .check_sources
    jnz  .invalid
    xor  ecx, ecx
.query_domain:
    mov  eax, [r12+rcx*4]
    and  eax, 0x7fffffff
    cmp  eax, 0x47800000
    ja   .invalid
    inc  ecx
    cmp  ecx, 384
    jb   .query_domain
    mov  rdx, [rsp+24]
    shr  rdx, 2
    xor  ecx, ecx
.prototype_domain:
    mov  eax, [r13+rcx*4]
    and  eax, 0x7fffffff
    cmp  eax, 0x47800000
    ja   .invalid
    inc  ecx
    cmp  rcx, rdx
    jb   .prototype_domain
    stmxcsr [rsp+64]
    mov  dword [rsp+68], 0x1f80
    ldmxcsr [rsp+68]
    pxor xmm0, xmm0
    xor  ecx, ecx
.norm_sum:
    cvtss2sd xmm1, [r12+rcx*4]
    mulsd xmm1, xmm1
    addsd xmm0, xmm1
    inc  ecx
    cmp  ecx, 384
    jb   .norm_sum
    sqrtsd xmm0, xmm0
    mov  rax, 0x3d719799812dea11 ;double1e-12
    mov  [rsp+88], rax
    maxsd xmm0, [rsp+88]
    cvtsd2ss xmm0, xmm0
    xor  ecx, ecx
.normalize:
    movss xmm1, [r12+rcx*4]
    divss xmm1, xmm0
    movss [rbx+rcx*4], xmm1
    inc  ecx
    cmp  ecx, 384
    jb   .normalize
    mov  dword [rsp+72], 0xff7fffff ;best=-FLT_MAX
    mov  dword [rsp+76], 0xff7fffff ;second=-FLT_MAX
    mov  dword [rsp+80], 0
    xor  r8d, r8d
.score_row:
    pxor xmm0, xmm0
    imul rdx, r8, 1536
    add  rdx, r13
    xor  ecx, ecx
.dot:
    movss xmm1, [rbx+rcx*4]
    mulss xmm1, [rdx+rcx*4]
    addss xmm0, xmm1
    inc  ecx
    cmp  ecx, 384
    jb   .dot
    movss [rbx+r8*4+1536], xmm0
    ucomiss xmm0, [rsp+72]
    ja   .new_best                ;strict: ties keep first index
    ucomiss xmm0, [rsp+76]
    jbe  .next_row
    movss [rsp+76], xmm0
    jmp  .next_row
.new_best:
    mov  eax, [rsp+72]
    mov  [rsp+76], eax
    movss [rsp+72], xmm0
    mov  [rsp+80], r8d
.next_row:
    inc  r8d
    cmp  r8d, ebp
    jb   .score_row
    movss xmm0, [rsp+72]
    subss xmm0, [rsp+76]
    xor  eax, eax
    movss xmm1, [rsp+72]
    ucomiss xmm1, [rsp+8]
    jb   .abstain
    ucomiss xmm0, [rsp+12]
    jae  .publish                 ;inclusive caller thresholds
.abstain:
    mov  eax, 1
.publish:
    mov  [r14], eax
    mov  edx, [rsp+80]
    mov  [r14+4], edx
    mov  rdx, [rsp+72]
    mov  [r14+8], rdx
    movss [r14+16], xmm0
    ldmxcsr [rsp+64]
    jmp  .out
.invalid:
    mov  eax, 2
.out:
    add  rsp, 120
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.check_sources:
    mov  rdi, r12
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, [r9+24]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+104]
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

; Coherent packedASCII->CLS->prototype score. SysV RDI=text,RSI=result20,
; RDX=config128(8-aligned). First96bytes match packedASCII config EXCEPT field72
; is resultbytes20 and workspacebytes=48770208+4*count. Tail: u64 prototype_ptr,
; prototype_bytes=count1536; u32 count2..256,width384; f32 min_score,min_margin.
; Exact caller arena: CLS1536 + packedASCII48767136 + score1536+4count.
; Whole arena/final disjoint each other and all complete packs/text/prototypes/
; originalconfig BEFORE any encoder write; metadata snapshot/full64 guards.
; Invalid EAX2 leaves final unchanged; early metadata also scratch unchanged.
; Failed packed stage maps toinvalid2, never abstain1 or stale CLS consumption.
; Later numeric prototype refusal may retain encoded CLS/scratch. Caller has
; same authenticated mapped lifetime/policy obligations as both accepted stages.
; Full FP/x87/DF/nonvolatile ABI retained; nested stack<5120bytes.
cog_encoder_packed_rank_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 248
    mov  r12, rdi
    mov  r13, rsi
    mov  rbp, rdx
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    test r13b, 3
    jnz  .invalid
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 128
    jc   .invalid
    mov  [rsp+224], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 16
    jb   .snapshot
    cmp  qword [rsp], 4096
    ja   .invalid
    cmp  qword [rsp+16], 20
    jb   .invalid
    cmp  qword [rsp+16], 8388608
    ja   .invalid
    cmp  qword [rsp+32], 47671320
    jne  .invalid
    cmp  qword [rsp+48], 21234832
    jne  .invalid
    cmp  qword [rsp+64], 243376
    jne  .invalid
    cmp  qword [rsp+72], 20
    jne  .invalid
    mov  ebx, [rsp+112]
    cmp  ebx, 2
    jb   .invalid
    cmp  ebx, 256
    ja   .invalid
    cmp  dword [rsp+116], 384
    jne  .invalid
    imul rax, rbx, 1536
    cmp  [rsp+104], rax
    jne  .invalid
    lea  rax, [rbx*4+48770208]
    cmp  [rsp+88], rax
    jne  .invalid
    mov  eax, [rsp+120]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [rsp+124]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    test eax, eax
    jz   .margin_valid
    test dword [rsp+124], 0x80000000
    jnz  .invalid
.margin_valid:
    cmp  qword [rsp+8], 0
    je   .invalid
    mov  ecx, 24
.pack_pointers:
    mov  rdi, [rsp+rcx]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    add  ecx, 16
    cmp  ecx, 72
    jb   .pack_pointers
    mov  r14, [rsp+96]
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    mov  r15, [rsp+80]
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r13
    mov  r11, r13
    add  r11, 20
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [rsp+88]
    call .range_ok
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, [rsp+88]
    jc   .invalid
    call .check_sources           ;whole arena protects prototypes before encoder
    jnz  .invalid
    xor  ecx, ecx
.packed_config:
    mov  rax, [rsp+rcx*8]
    mov  [rsp+rcx*8+128], rax
    inc  ecx
    cmp  ecx, 12
    jb   .packed_config
    mov  qword [rsp+200], 1536
    lea  rax, [r15+1536]
    mov  [rsp+208], rax
    mov  qword [rsp+216], 48767136
    mov  rdi, r12
    mov  rsi, r15
    lea  rdx, [rsp+128]
    call cog_encoder_packed_ascii_cls_f32_advisory
    test eax, eax
    jnz  .invalid                 ;failed encoder never becomes abstain/stale score
    mov  rax, [rsp+112]
    mov  [rsp+128], rax
    mov  rax, [rsp+120]
    mov  [rsp+136], rax
    mov  qword [rsp+144], 1536
    mov  rax, [rsp+104]
    mov  [rsp+152], rax
    mov  qword [rsp+160], 20
    lea  rax, [r15+48768672]
    mov  [rsp+168], rax
    lea  rax, [rbx*4+1536]
    mov  [rsp+176], rax
    mov  qword [rsp+184], 0
    mov  rdi, r15
    mov  rsi, r14
    mov  rdx, r13
    lea  rcx, [rsp+128]
    call cog_encoder_score_f32_advisory
    jmp  .out
.invalid:
    mov  eax, 2
.out:
    add  rsp, 248
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9]
    test rsi, rsi
    jz   .empty_text
    call .range_ok
    jnz  .sources_bad
.empty_text:
    mov  ecx, 8
.packs:
    mov  rdi, [r9+rcx]
    mov  rsi, [r9+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 72
    jb   .packs
    mov  rdi, r14
    mov  rsi, [r9+104]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+224]
    mov  esi, 128
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
