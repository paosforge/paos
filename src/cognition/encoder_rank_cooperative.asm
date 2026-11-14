;; MODULE cognition/encoder_rank_cooperative
;; LAYER 6
;; EXPORTS cog_encoder_rank_coop_begin_advisory, cog_encoder_rank_coop_step_advisory, cog_encoder_rank_coop_cancel_advisory
;; IMPORTS cog_encoder_coop_begin_advisory, cog_encoder_coop_step_advisory, cog_encoder_coop_cancel_advisory, cog_encoder_coop_validate, cog_encoder_coop_terminal, cog_encoder_score_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Optional caller-owned cooperative ASCII text -> prototype choose/abstain.
; Begin(RDI=request224,RSI=context4320) ->3 PENDING/2 REFUSED. No numeric stage.
; Step(RDI=request224,RSI=context4320,RDX=expected ordinal u64) ->3 PENDING,
; 0 CHOOSE,1 ABSTAIN,2 REFUSED. Ordinal0 embedding,1..12 ordered layers0..11,
; 13 one bounded accepted scalar score stage (count2..256,width384). Exactly
; one stage per step, no implicit encoder loop/score on final-layer call.
; Cancel(request,context)->4 CANCELLED/2 REFUSED; no numeric stage.
;
; Immutable request224/8aligned: first168 same as cooperative encoder EXCEPT
; +8 points to final result20 and +32 is contextbytes4320. +168 prototype ptr,
; +176 prototypebytes=count1536; u32 count184,width188; f32 minscore192,
; minmargin196; +200 scorework ptr,+208 exact1536+4count bytes,+216 resultbytes20.
; Original ASCII config120 at48 is unchanged, including outputbytes1536 and
; exact encoder arena A(L), prepared L2..512 at40, reserved44 zero, owner16 and
; generation24 nonzero. Whole encoder work is accepted shape arena A(L):
; align4(9L)+15360L+max(6144L+144L^2,20352L). Separate scorework8aligned,
; result/prototypes4aligned. Count/threshold/tie/numeric semantics unchanged.
;
; Context4320/8aligned initially allzero: magic0,self8,requestidentity16,owner24,
; generation32; u32 phase40,next44,completed48,reserved52; reserved qword56;
; frozen request224 at64; private child request168 at288, child context2304 at456,
; private CLS1536 at2760, staged advice20 at4296,reserved dword4316. Phase1
; encoding(next0..12),2 score(next13),3 chosen,4 abstained,5 cancelled,6 refused.
; Next/completed equal expected ordinal. Child final-layer publishes only private
; CLS. Score writes only staged advice; final20 bytes copy ONLY on rc0/1.
; Valid cancellation/refusal/completion clears all4320 bytes except original
; identity/owner/generation/terminal phase. Numeric arenas may retain residuals.
; Terminal step/cancel refuse without reading retired request/model mappings.
; Begin never silently restarts: terminal reuse needs same owner and strictly
; greater generation; active begin revokes/refuses. Calls serialized by caller.
;
; Full64 sizes/ends/ownership cover whole original224 request, all text/PVT/PEM/
; affines/descriptors/every model operand/prototypes versus whole context/result/
; both work arenas, pairwise mutable disjointness. Parent validates canonical model
; metadata; wrapper composes cross-child spans before any write. Changed request,
; identity/generation/stage/prefix refuses, never resumes using frozen operands.
; Frozen values used ONLY for validated bounded revocation on malformed current
; metadata. Unsafe/unmapped claims do not authorize a cleanup write.
; Caller retains admitted immutable mapped model/prototype/request data and stable
; trusted execution context/arenas throughout operation. Owner/generation are
; execution identity, NOT authority or admission. This continuation is NOT digest
; admission; existing digest-bound APIs and trusted admission remain unchanged.
; No new authentication/cache/allocator/global scratch/scheduler/AP/callback/I/O.
; Complete MXCSR/x87/DF/nonvolatile GPR/RSP preserved. Own dispatcher<160 bytes,
; nested begin<8320,step<2720; one stage is not a wall-clock responsiveness promise.
; No model quality/calibration/probability/runtime/fullRC/authorization claim.
COG_RANK_COOP_MAGIC equ 0x314b4e4152474f43

cog_encoder_rank_coop_begin_advisory:
    xor  ecx, ecx
    jmp  cog_encoder_rank_coop_dispatch
cog_encoder_rank_coop_step_advisory:
    mov  ecx, 1
    jmp  cog_encoder_rank_coop_dispatch
cog_encoder_rank_coop_cancel_advisory:
    mov  ecx, 2
cog_encoder_rank_coop_dispatch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 88
    pushfq
    pop  qword [rsp+64]
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx
    test r15d, r15d
    jz   .validate
    mov  rdi, r13
    call cog_encoder_rank_coop_terminal
    test eax, eax
    jnz  .unsafe                 ; no retired operand reads
.validate:
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r12
    call cog_encoder_rank_coop_validate
    test eax, eax
    jnz  .revoke
    test r15d, r15d
    jz   .begin
    cmp  r15d, 2
    jne  .expected_ready
    mov  r14d, [r13+44]          ; cancellation consumes current boundary
.expected_ready:
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call cog_encoder_rank_coop_state_ok
    test eax, eax
    jnz  .refuse
    cmp  r15d, 2
    je   .cancel
    cmp  r14, 13
    je   .score
    lea  rdi, [r13+288]
    lea  rsi, [r13+456]
    mov  rdx, r14
    call cog_encoder_coop_step_advisory
    cmp  r14, 12
    je   .last_layer
    cmp  eax, 1
    jne  .refuse                 ; no failed encoder state consumed
    jmp  .advance
.last_layer:
    test eax, eax
    jnz  .refuse                 ; final layer must complete, not merely yield
    mov  dword [r13+40], 2       ; private CLS ready, score remains separate
.advance:
    inc  dword [r13+44]
    inc  dword [r13+48]
    mov  eax, 3
    jmp  .out
.score:
    mov  rax, [r12+184]
    mov  [rsp], rax
    mov  rax, [r12+192]
    mov  [rsp+8], rax
    mov  qword [rsp+16], 1536
    mov  rax, [r12+176]
    mov  [rsp+24], rax
    mov  qword [rsp+32], 20
    mov  rax, [r12+200]
    mov  [rsp+40], rax
    mov  rax, [r12+208]
    mov  [rsp+48], rax
    mov  qword [rsp+56], 0
    lea  rdi, [r13+2760]
    mov  rsi, [r12+168]
    lea  rdx, [r13+4296]
    mov  rcx, rsp
    call cog_encoder_score_f32_advisory
    cmp  eax, 1
    ja   .refuse                 ; failed/stale advice never reaches caller
    mov  ebx, eax
    mov  rdi, [r12+8]
    xor  ecx, ecx
.publish:
    mov  eax, [r13+4296+rcx*4]
    mov  [rdi+rcx*4], eax
    inc  ecx
    cmp  ecx, 5
    jb   .publish
    lea  edx, [rbx+3]
    mov  rdi, r13
    mov  rsi, r12
    call cog_encoder_rank_coop_clear
    mov  eax, ebx
    jmp  .out
.cancel:
    cmp  r14, 13
    je   .cancel_clear
    lea  rdi, [r13+288]
    lea  rsi, [r13+456]
    call cog_encoder_coop_cancel_advisory
    test eax, eax
    jnz  .refuse
.cancel_clear:
    mov  edx, 5
    mov  rdi, r13
    mov  rsi, r12
    call cog_encoder_rank_coop_clear
    mov  eax, 4
    jmp  .out
.begin:
    mov  rdi, r13
    call cog_encoder_rank_coop_envelope
    test eax, eax
    jnz  .existing
    xor  ecx, ecx
.fresh:
    cmp  qword [r13+rcx*8], 0
    jne  .refuse
    inc  ecx
    cmp  ecx, 540
    jb   .fresh
    jmp  .initialize
.existing:
    mov  rdi, r13
    call cog_encoder_rank_coop_terminal
    test eax, eax
    jz   .refuse                 ; active begin cannot silently restart
    mov  rax, [r12+16]
    cmp  [r13+24], rax
    jne  .refuse
    mov  rax, [r12+24]
    cmp  rax, [r13+32]
    jbe  .refuse                 ; explicit strictly newer generation
.initialize:
    mov  rdi, r13
    xor  eax, eax
    mov  ecx, 540
    cld
    rep  stosq
    mov  rax, COG_RANK_COOP_MAGIC
    mov  [r13], rax
    mov  [r13+8], r13
    mov  [r13+16], r12
    mov  rax, [r12+16]
    mov  [r13+24], rax
    mov  rax, [r12+24]
    mov  [r13+32], rax
    mov  dword [r13+40], 1
    xor  ecx, ecx
.snapshot:
    mov  rax, [r12+rcx*8]
    mov  [r13+64+rcx*8], rax
    cmp  ecx, 21
    jae  .next
    cmp  ecx, 1
    jne  .child_context_bytes
    lea  rax, [r13+2760]
.child_context_bytes:
    cmp  ecx, 4
    jne  .child_snapshot
    mov  eax, 2304
.child_snapshot:
    mov  [r13+288+rcx*8], rax
.next:
    inc  ecx
    cmp  ecx, 28
    jb   .snapshot
    lea  rdi, [r13+288]
    lea  rsi, [r13+456]
    call cog_encoder_coop_begin_advisory
    cmp  eax, 1
    jne  .refuse
    mov  eax, 3
    jmp  .out
.revoke:
    mov  rdi, r13
    call cog_encoder_rank_coop_envelope
    test eax, eax
    jz   .unsafe
    lea  rdi, [r13+64]
    mov  rsi, r13
    mov  rdx, [r13+16]
    call cog_encoder_rank_coop_validate
    test eax, eax
    jnz  .unsafe                 ; frozen values validate cleanup only
.refuse:
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 6
    call cog_encoder_rank_coop_clear
.unsafe:
    mov  eax, 2
.out:
    test qword [rsp+64], 0x400
    jz   .df_clear
    std
    jmp  .leave
.df_clear:
    cld
.leave:
    add  rsp, 88
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

cog_encoder_rank_coop_envelope:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    test dil, 7
    jnz  .out
    mov  rax, rdi
    add  rax, 4320
    jc   .bad
    mov  rax, COG_RANK_COOP_MAGIC
    cmp  [rdi], rax
    jne  .bad
    cmp  [rdi+8], rdi
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

cog_encoder_rank_coop_terminal:
    sub  rsp, 8
    call cog_encoder_rank_coop_envelope
    add  rsp, 8
    test eax, eax
    jz   .out
    mov  eax, [rdi+40]
    cmp  eax, 3
    jb   .bad
    cmp  eax, 6
    ja   .bad
    cmp  qword [rdi+44], 0
    jne  .bad
    cmp  dword [rdi+52], 0
    jne  .bad
    cmp  qword [rdi+56], 0
    jne  .bad
    mov  ecx, 8
.tail:
    cmp  qword [rdi+rcx*8], 0
    jne  .bad
    inc  ecx
    cmp  ecx, 540
    jb   .tail
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

cog_encoder_rank_coop_clear:
    mov  r8, rdi
    mov  rax, COG_RANK_COOP_MAGIC
    cmp  [rdi], rax
    jne  .from_request
    cmp  [rdi+8], rdi
    jne  .from_request
    mov  r9, [rdi+24]
    mov  r10, [rdi+32]
    mov  r11, [rdi+16]
    jmp  .clear
.from_request:
    mov  r9, [rsi+16]
    mov  r10, [rsi+24]
    mov  r11, rsi
.clear:
    xor  eax, eax
    mov  ecx, 540
    cld
    rep  stosq
    mov  rax, COG_RANK_COOP_MAGIC
    mov  [r8], rax
    mov  [r8+8], r8
    mov  [r8+16], r11
    mov  [r8+24], r9
    mov  [r8+32], r10
    mov  [r8+40], edx
    ret

cog_encoder_rank_coop_state_ok:
    mov  rax, COG_RANK_COOP_MAGIC
    cmp  [rsi], rax
    jne  .bad
    cmp  [rsi+8], rsi
    jne  .bad
    cmp  [rsi+16], rdi
    jne  .bad
    mov  rax, [rdi+16]
    cmp  [rsi+24], rax
    jne  .bad
    mov  rax, [rdi+24]
    cmp  [rsi+32], rax
    jne  .bad
    mov  eax, [rsi+44]
    cmp  rdx, rax
    jne  .bad
    cmp  eax, 13
    ja   .bad
    cmp  [rsi+48], eax
    jne  .bad
    mov  ecx, 1
    cmp  eax, 13
    jb   .phase_ready
    mov  ecx, 2
.phase_ready:
    cmp  [rsi+40], ecx
    jne  .bad
    cmp  dword [rsi+52], 0
    jne  .bad
    cmp  qword [rsi+56], 0
    jne  .bad
    cmp  dword [rsi+4316], 0
    jne  .bad
    xor  ecx, ecx
.request:
    mov  rax, [rdi+rcx*8]
    cmp  [rsi+64+rcx*8], rax
    jne  .bad
    cmp  ecx, 21
    jae  .next
    cmp  ecx, 1
    jne  .child_context_bytes
    lea  rax, [rsi+2760]
.child_context_bytes:
    cmp  ecx, 4
    jne  .child_compare
    mov  eax, 2304
.child_compare:
    cmp  [rsi+288+rcx*8], rax
    jne  .bad
.next:
    inc  ecx
    cmp  ecx, 28
    jb   .request
    cmp  edx, 13
    jb   .good
    lea  rdi, [rsi+456]
    sub  rsp, 8
    call cog_encoder_coop_terminal
    add  rsp, 8
    test eax, eax
    jz   .bad
    cmp  dword [rsi+496], 3
    jne  .bad
    lea  rax, [rsi+288]
    cmp  [rsi+472], rax
    jne  .bad
    mov  rax, [rsi+24]
    cmp  [rsi+480], rax
    jne  .bad
    mov  rax, [rsi+32]
    cmp  [rsi+488], rax
    jne  .bad
.good:
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; RDI values,RSI whole context,RDX original immutable request span. Frozen values
; are accepted only for revocation validation, not execution. EAX0 valid/1 bad.
cog_encoder_rank_coop_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 168
    mov  rbp, rdi
    mov  r13, rsi
    mov  r12, rdx
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 224
    jc   .invalid
    test r12, r12
    jz   .invalid
    test r12b, 7
    jnz  .invalid
    mov  rax, r12
    add  rax, 224
    jc   .invalid
    test r13, r13
    jz   .invalid
    test r13b, 7
    jnz  .invalid
    mov  rax, r13
    add  rax, 4320
    jc   .invalid
    cmp  qword [rbp+32], 4320
    jne  .invalid
    cmp  qword [rbp+216], 20
    jne  .invalid
    mov  ebx, [rbp+184]
    cmp  ebx, 2
    jb   .invalid
    cmp  ebx, 256
    ja   .invalid
    cmp  dword [rbp+188], 384
    jne  .invalid
    imul rax, rbx, 1536
    cmp  [rbp+176], rax
    jne  .invalid
    lea  rax, [rbx*4+1536]
    cmp  [rbp+208], rax
    jne  .invalid
    mov  eax, [rbp+192]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [rbp+196]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    test eax, eax
    jz   .margin_ready
    test dword [rbp+196], 0x80000000
    jnz  .invalid
.margin_ready:
    mov  rax, [rbp+168]
    test rax, rax
    jz   .invalid
    test al, 3
    jnz  .invalid
    mov  r14, [rbp+8]
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    mov  r15, [rbp+200]
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    xor  ecx, ecx
.child_request:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 21
    jb   .child_request
    lea  rax, [r13+2760]
    mov  [rsp+8], rax
    mov  qword [rsp+32], 2304
    mov  rdi, rsp
    lea  rsi, [r13+456]
    lea  rdx, [r13+288]
    call cog_encoder_coop_validate
    test eax, eax
    jnz  .invalid
    mov  rbx, [rbp+152]
    mov  r9, rbp
    mov  r10, r13
    lea  r11, [r13+4320]
    call .check_sources           ; whole wrapper state vs every immutable source
    jnz  .invalid
    mov  rdi, r14
    mov  esi, 20
    call .range_ok
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [rbp+208]
    call .range_ok
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rbp+160]
    call .range_ok
    jnz  .invalid
    mov  r10, r14
    mov  r11, r14
    add  r11, 20
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [rbp+208]
    call .range_ok
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rbp+160]
    call .range_ok
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, [rbp+208]
    jc   .invalid
    call .check_sources           ; scorework cannot destroy later model/text input
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rbp+160]
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rbp+160]
    jc   .invalid
    call .check_sources           ; encoder work cannot destroy prototypes/request
    jnz  .invalid
    xor  eax, eax
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
.check_sources:
    mov  rdi, [r9]
    mov  rsi, [r9+56]
    test rsi, rsi
    jz   .empty_text
    call .range_ok
    jnz  .sources_bad
.empty_text:
    mov  rdi, [r9+64]
    mov  rsi, [r9+72]
    call .range_ok
    jnz  .sources_bad
    mov  ecx, 88
.embedding_sources:
    mov  rdi, [r9+rcx]
    mov  esi, 1536
    cmp  ecx, 88
    jne  .embedding_extent_ready
    mov  esi, 47671320
.embedding_extent_ready:
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 136
    jb   .embedding_sources
    mov  rdi, r12
    mov  esi, 224
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+168]
    mov  rsi, [r9+176]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+136]
    mov  esi, 3744
    call .range_ok
    jnz  .sources_bad
    mov  r8, [r9+136]
    xor  edx, edx
.model_sources:
    mov  ecx, 8
.projection_sources:
    mov  rdi, [r8+rcx]
    mov  esi, 147456
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r8+rcx+16]
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    add  ecx, 40
    cmp  ecx, 168
    jb   .projection_sources
    mov  ecx, 168
.affine_sources:
    mov  rdi, [r8+rcx]
    mov  esi, 1536
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 200
    jb   .affine_sources
    mov  ecx, 216
.ffn_sources:
    mov  rdi, [r8+rcx]
    mov  esi, 1536
    cmp  ecx, 216
    je   .ffn_weight_extent
    cmp  ecx, 248
    je   .ffn_weight_extent
    cmp  ecx, 232
    jne  .ffn_extent_ready
    mov  esi, 6144
    jmp  .ffn_extent_ready
.ffn_weight_extent:
    mov  esi, 589824
.ffn_extent_ready:
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 312
    jb   .ffn_sources
    add  r8, 312
    inc  edx
    cmp  edx, 12
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
