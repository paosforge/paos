;; MODULE cognition/encoder_cooperative
;; LAYER 6
;; EXPORTS cog_encoder_coop_begin_advisory, cog_encoder_coop_step_advisory, cog_encoder_coop_cancel_advisory
;; IMPORTS cog_encoder_ascii_cls_shape_prepare_advisory, cog_encoder_embedding_f32_advisory, cog_encoder_layer_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Optional cooperative ASCII->CLS, no changes to any synchronous interface.
; Begin(request168,context2304)->EAX1 PENDING/2 REFUSED; no numeric stage.
; Step(request168,context2304,expected_ordinal u64)->EAX1 PENDING/0 DONE/2 REFUSED.
; Ordinal0 is embedding,1..12 are encoder layers0..11. At most ONE such stage
; per step; final successful layer additionally publishes row0. No scheduler/AP
; dispatch, callbacks, global scratch, I/O, allocator or timing guarantee.
; Cancel(request168,context2304)->EAX0 CANCELLED/2 REFUSED; no numeric stage.
;
; Immutable request8aligned: u64 text_ptr,CLS_ptr,owner_id,generation,ctx_bytes2304;
; u32 prepared_L2..512,reserved0; then existing ASCII config120 at48 (max512,
; layer_count MUST12, all existing exact text/PVT/PEM/affine/model spans and true
; shape-sized workbytes). Caller obtains L/arena via accepted shape preparation.
; Owner/generation are caller execution identity, NOT authorization/model pins.
; Every pointer/span remains caller-owned/authenticated/mapped and stable across
; the active operation. External model/digest admission and quality NO-GO remain
; unchanged. Context is trusted writable execution state, NEVER attacker-serialized
; data/admission token. Caller serializes calls and retains numeric arena states.
;
; Context8aligned/all2304bytes mapped writable, initially allzero. Layout:
; 0 magic,8 self,16 request identity,24 owner,32 generation; u32phase40,next44,
; completed48,reserved52; u64reserved56; request snapshot168 at64; reserved232/240;
; private used token IDs at248 (capacity2048); reserved2296. Phases1 embedding,
; 2 layer,3 done,4 cancelled,5 refused. next=completed=expected ordinal0..12.
; Begin privately uses accepted native shape preparation, checks actual count,
; size and IDs, then copies fixed IDs/types0/mask1 into exact caller arena.
; Each step rechecks current request identity/owner/generation/snapshot, full64
; metadata/ranges/phase/index and fixed token/type/mask prefix before consumption.
; Numerical retained tensors are caller-stable scratch, not authenticated by state.
;
; N=1536L; prefix=align4(9L); T=10N+max(4N+144L²,20352L); arena=prefix+T,
; exactly accepted shape API. Base=work+prefix. Embedding=base, reservedencoded
; region=base+N, ping=base+2N,pong=base+3N, layer scratch=base+4N. Embedding sums
; reuse ping before layers. Layer k reads embedding if0 else prior ping/pong,
; writes parity-selected ping/pong; scratch6N+max(...) reused. All12 layers run.
;
; CLS/context/wholearena pairwise disjoint and disjoint from text/PVT/PEM/affines/
; every model operand/model descriptors/whole original request. Bounds/snapshots
; and canonical span checks precede stage writes. Invalid/cancel/late child
; refusal never publishes CLS; failed stage never advances/feeds retained state.
; Validated refusal/cancel/completion clears entire bounded2304-byte context,
; retaining only identity/generation/terminal tombstone. No large arena scan:
; IDs/types/mask and numeric residuals remain caller-owned until caller erases.
; Initial unsafe pointer/ownership refusal writes nothing; no cleanup write is
; authorized by a malformed claim. On active refusal, frozen request is used
; solely to validate safe revocation if current metadata is malformed. A caller
; violating mapped immutable lifetimes must discard the operation, not resume it.
; Terminal steps/cancels refuse without touching retired operands. Begin never
; silently restarts; terminal reuse requires explicit greater nonzero generation
; and same owner. Active begin refuses/revokes. Identity is not a security grant.
; Full MXCSR/x87/DF/nonvolatileGPR/RSP preserved. Stack begin<7520,step<1920,
; cancel<864 bytes including children. Whole-stage work bound, not wall-clock
; responsiveness, native runtime, semantic classifier quality or authority proof.
COG_COOP_MAGIC equ 0x314f4f4345474243

cog_encoder_coop_begin_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 2184
    stmxcsr [rsp+2120]
    mov  dword [rsp+2124], 0x1f80
    pushfq
    pop  rax
    mov  [rsp+2128], rax
    mov  r12, rdi                ; immutable request
    mov  r13, rsi                ; writable continuation
    mov  rdx, rdi
    call cog_encoder_coop_validate
    test eax, eax
    jnz  .bad_validation
    mov  rax, COG_COOP_MAGIC
    cmp  [r13], rax
    je   .existing
    xor  ecx, ecx
.fresh:
    cmp  qword [r13+rcx*8], 0
    jne  .refuse
    inc  ecx
    cmp  ecx, 288
    jb   .fresh
    jmp  .prepare
.existing:
    mov  rdi, r13
    call cog_encoder_coop_terminal
    test eax, eax
    jz   .refuse                 ; active/forged context cannot silently restart
    mov  rax, [r12+16]
    cmp  [r13+24], rax
    jne  .refuse
    mov  rax, [r12+24]
    cmp  rax, [r13+32]
    jbe  .refuse                 ; explicit strictly newer generation only
.prepare:
    mov  rax, [r12+56]
    mov  [rsp+2096], rax
    mov  rax, [r12+72]
    mov  [rsp+2104], rax
    mov  qword [rsp+2112], 2096
    mov  rdi, [r12]
    mov  rsi, [r12+64]
    mov  rdx, rsp
    lea  rcx, [rsp+2096]
    ldmxcsr [rsp+2124]
    call cog_encoder_ascii_cls_shape_prepare_advisory
    test eax, eax
    jnz  .refuse                 ; failed preparation cannot supply stale IDs
    mov  eax, [rsp]
    cmp  eax, [r12+40]
    jne  .refuse
    mov  rax, [rsp+8]
    cmp  rax, [r12+160]
    jne  .refuse
    mov  rdi, r13
    xor  eax, eax
    mov  ecx, 288
    cld
    rep  stosq
    mov  rax, COG_COOP_MAGIC
    mov  [r13], rax
    mov  [r13+8], r13
    mov  [r13+16], r12
    mov  rax, [r12+16]
    mov  [r13+24], rax
    mov  rax, [r12+24]
    mov  [r13+32], rax
    mov  dword [r13+40], 1
    xor  ecx, ecx
.request_snapshot:
    mov  rax, [r12+rcx*8]
    mov  [r13+64+rcx*8], rax
    inc  ecx
    cmp  ecx, 21
    jb   .request_snapshot
    mov  rbx, [r12+152]
    mov  r10d, [r12+40]
    shl  r10, 2
    lea  r11, [rbx+r10*2]
    add  r10, rbx
    xor  ecx, ecx
.tokens:
    mov  eax, [rsp+48+rcx*4]
    mov  [r13+248+rcx*4], eax
    mov  [rbx+rcx*4], eax
    mov  dword [r10+rcx*4], 0
    mov  byte [r11+rcx], 1
    inc  ecx
    cmp  ecx, [r12+40]
    jb   .tokens
    mov  eax, 1
    jmp  .out
.bad_validation:
    test edx, edx
    jz   .unsafe
.refuse:
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 5
    call cog_encoder_coop_clear
.unsafe:
    mov  eax, 2
.out:
    ldmxcsr [rsp+2120]
    bt   qword [rsp+2128], 10
    jnc  .df_clear
    std
    jmp  .leave
.df_clear:
    cld
.leave:
    add  rsp, 2184
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

cog_encoder_coop_step_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 424                ; stage360, FP/flags, geometry/output
    stmxcsr [rsp+360]
    mov  dword [rsp+364], 0x1f80
    pushfq
    pop  rax
    mov  [rsp+368], rax
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx                ; exact expected ordinal, all64bits
    mov  rdi, r13
    call cog_encoder_coop_terminal
    test eax, eax
    jnz  .unsafe                 ; no retired model/request dereference
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r12
    call cog_encoder_coop_validate
    test eax, eax
    jnz  .bad_validation
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call cog_encoder_coop_state_ok
    test eax, eax
    jnz  .refuse
    mov  eax, [r12+40]
    call cog_encoder_coop_size
    mov  [rsp+376], rcx
    mov  [rsp+392], rdx
    mov  ebp, [r12+40]
    imul rbp, 1536
    mov  [rsp+384], rbp
    mov  rbx, [r12+152]
    add  rbx, [rsp+376]           ; normalized embedding/base of token arena
    ldmxcsr [rsp+364]
    test r14d, r14d
    jnz  .layer
    mov  eax, [r12+40]
    mov  [rsp], eax
    mov  dword [rsp+4], 0
    shl  rax, 2
    mov  [rsp+8], rax
    mov  [rsp+16], rax
    mov  qword [rsp+24], 47671320
    mov  [rsp+32], rbp
    mov  rax, [r12+104]
    mov  [rsp+40], rax
    mov  qword [rsp+48], 1536
    mov  rax, [r12+120]
    mov  [rsp+56], rax
    mov  qword [rsp+64], 1536
    lea  rax, [rbx+rbp*2]
    mov  [rsp+72], rax
    mov  [rsp+80], rbp
    mov  rdi, [r12+152]
    mov  esi, [r12+40]
    shl  rsi, 2
    add  rsi, rdi
    mov  rdx, [r12+88]
    mov  rcx, rbx
    mov  r8, rsp
    call cog_encoder_embedding_f32_advisory
    test eax, eax
    jnz  .refuse                 ; no failed embedding state is consumed
    jmp  .advance
.layer:
    mov  eax, r14d
    dec  eax
    imul rax, 312
    add  rax, [r12+136]
    mov  r8, rax                 ; one exact ordered model descriptor
    mov  eax, [r12+40]
    mov  [rsp], eax
    mov  dword [rsp+4], 384
    mov  rax, [r8]
    mov  [rsp+8], rax
    mov  [rsp+16], rbp
    mov  eax, [r12+40]
    mov  [rsp+24], rax
    mov  [rsp+32], rbp
    lea  rax, [rbx+rbp*4]
    mov  [rsp+40], rax
    mov  rax, [rsp+392]
    imul rcx, rbp, 4
    sub  rax, rcx
    mov  [rsp+48], rax           ; exact layer scratch T-4N
    xor  ecx, ecx
.layer_snapshot:
    mov  rax, [r8+rcx+8]
    mov  [rsp+56+rcx], rax
    add  ecx, 8
    cmp  ecx, 304
    jb   .layer_snapshot
    mov  eax, r14d
    dec  eax
    and  eax, 1
    imul rax, rbp
    lea  r15, [rbx+rbp*2]
    add  r15, rax
    mov  [rsp+400], r15
    mov  rdi, rbx                ; first layer reads normalized embedding
    cmp  r14d, 1
    je   .layer_input_ready
    mov  eax, r14d
    sub  eax, 2
    and  eax, 1
    imul rax, rbp
    lea  rdi, [rbx+rbp*2]
    add  rdi, rax
.layer_input_ready:
    mov  esi, [r12+40]
    shl  rsi, 3
    add  rsi, [r12+152]
    mov  rdx, r15
    mov  rcx, rsp
    call cog_encoder_layer_f32_advisory
    test eax, eax
    jnz  .refuse                 ; failed layer never advances or publishes
    cmp  r14d, 12
    jb   .advance
    mov  rsi, [rsp+400]
    mov  rdi, [r12+8]
    xor  ecx, ecx
.publish:
    mov  eax, [rsi+rcx*4]
    mov  [rdi+rcx*4], eax
    inc  ecx
    cmp  ecx, 384
    jb   .publish
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 3
    call cog_encoder_coop_clear
    xor  eax, eax
    jmp  .out
.advance:
    inc  dword [r13+44]
    inc  dword [r13+48]
    mov  dword [r13+40], 2
    mov  eax, 1
    jmp  .out
.bad_validation:
    test edx, edx
    jnz  .refuse
    ; A malformed current request cannot revive the accepted frozen operation.
    ; Validate frozen values only for bounded cleanup, never for numeric resume.
    mov  rdi, r13
    call cog_encoder_coop_envelope
    test eax, eax
    jz   .unsafe
    lea  rdi, [r13+64]
    mov  rsi, r13
    mov  rdx, [r13+16]            ; original identity; current request may be invalid
    call cog_encoder_coop_validate
    test edx, edx
    jz   .unsafe
.refuse:
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 5
    call cog_encoder_coop_clear
.unsafe:
    mov  eax, 2
.out:
    ldmxcsr [rsp+360]
    bt   qword [rsp+368], 10
    jnc  .df_clear
    std
    jmp  .leave
.df_clear:
    cld
.leave:
    add  rsp, 424
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

cog_encoder_coop_cancel_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    stmxcsr [rsp]
    pushfq
    pop  rax
    mov  [rsp+8], rax
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, r13
    call cog_encoder_coop_terminal
    test eax, eax
    jnz  .unsafe
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r12
    call cog_encoder_coop_validate
    test eax, eax
    jnz  .bad_validation
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, [r13+44]
    call cog_encoder_coop_state_ok
    test eax, eax
    jnz  .refuse
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 4
    call cog_encoder_coop_clear
    xor  eax, eax
    jmp  .out
.bad_validation:
    test edx, edx
    jnz  .refuse
    mov  rdi, r13
    call cog_encoder_coop_envelope
    test eax, eax
    jz   .unsafe
    lea  rdi, [r13+64]
    mov  rsi, r13
    mov  rdx, [r13+16]            ; original identity; current request may be invalid
    call cog_encoder_coop_validate
    test edx, edx
    jz   .unsafe
.refuse:
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 5
    call cog_encoder_coop_clear
.unsafe:
    mov  eax, 2
.out:
    ldmxcsr [rsp]
    bt   qword [rsp+8], 10
    jnc  .df_clear
    std
    jmp  .leave
.df_clear:
    cld
.leave:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Bounded physical envelope only; no authentication or source dereference.
cog_encoder_coop_envelope:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    test dil, 7
    jnz  .out
    mov  rax, rdi
    add  rax, 2304
    jc   .bad
    mov  rax, COG_COOP_MAGIC
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

; Terminal tombstones allow retries to refuse without retired operand reads.
cog_encoder_coop_terminal:
    sub  rsp, 8
    call cog_encoder_coop_envelope
    add  rsp, 8
    test eax, eax
    jz   .out
    mov  eax, [rdi+40]
    cmp  eax, 3
    jb   .bad
    cmp  eax, 5
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
    cmp  ecx, 288
    jb   .tail
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

; RDIrequest,RSIcontext,RDXexpected stage. Full range validator precedes this.
cog_encoder_coop_state_ok:
    mov  rax, COG_COOP_MAGIC
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
    cmp  eax, 12
    ja   .bad
    cmp  [rsi+48], eax
    jne  .bad
    mov  ecx, 1
    test eax, eax
    jz   .phase_ready
    mov  ecx, 2
.phase_ready:
    cmp  [rsi+40], ecx
    jne  .bad
    cmp  dword [rsi+52], 0
    jne  .bad
    cmp  qword [rsi+56], 0
    jne  .bad
    cmp  qword [rsi+232], 0
    jne  .bad
    cmp  qword [rsi+240], 0
    jne  .bad
    cmp  qword [rsi+2296], 0
    jne  .bad
    xor  ecx, ecx
.request:
    mov  rax, [rdi+rcx*8]
    cmp  [rsi+64+rcx*8], rax
    jne  .bad
    inc  ecx
    cmp  ecx, 21
    jb   .request
    mov  edx, [rdi+40]
    mov  r8, [rdi+152]
    lea  r9, [r8+rdx*4]
    lea  r10, [r8+rdx*8]
    xor  ecx, ecx
.tokens:
    mov  eax, [rsi+248+rcx*4]
    cmp  [r8+rcx*4], eax
    jne  .bad
    cmp  dword [r9+rcx*4], 0
    jne  .bad
    cmp  byte [r10+rcx], 1
    jne  .bad
    inc  ecx
    cmp  ecx, edx
    jb   .tokens
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; Clear only a validated owned context. Preserve original operation tombstone.
cog_encoder_coop_clear:
    mov  r8, rdi
    mov  rax, COG_COOP_MAGIC
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
    mov  ecx, 288
    cld
    rep  stosq
    mov  rax, COG_COOP_MAGIC
    mov  [r8], rax
    mov  [r8+8], r8
    mov  [r8+16], r11
    mov  [r8+24], r9
    mov  [r8+32], r10
    mov  [r8+40], edx
    ret

; Request values RDI, context RSI, original immutable request span RDX.
; Frozen values may reside inside context only for SAFE revocation validation.
; EAX0/1; EDX1 iff whole context ownership proved and bounded clearing is safe.
cog_encoder_coop_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 312
    mov  qword [rsp+304], 0
    mov  [rsp+256], rdx
    mov  [rsp+288], rsi
    test rdi, rdi
    jz   .invalid
    test dil, 7
    jnz  .invalid
    mov  rax, rdi
    add  rax, 168
    jc   .invalid
    test rdx, rdx
    jz   .invalid
    test dl, 7
    jnz  .invalid
    mov  rax, rdx
    add  rax, 168
    jc   .invalid
    test rsi, rsi
    jz   .invalid
    test sil, 7
    jnz  .invalid
    mov  rax, rsi
    add  rax, 2304
    jc   .invalid
    mov  r12, [rdi]
    mov  r15, [rdi+8]
    test r12, r12
    jz   .invalid
    test r15, r15
    jz   .invalid
    test r15b, 3
    jnz  .invalid
    mov  eax, [rdi+40]
    cmp  eax, 2
    jb   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  [rsp+264], eax
    lea  rbp, [rdi+48]
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 15
    jb   .snapshot
    cmp  dword [rsp], 512
    jne  .invalid
    cmp  dword [rsp+4], 12
    jne  .invalid
    cmp  qword [rsp+8], 4096
    ja   .invalid
    cmp  qword [rsp+24], 20
    jb   .invalid
    cmp  qword [rsp+24], 8388608
    ja   .invalid
    mov  r13, [rsp+16]
    test r13, r13
    jz   .invalid
    mov  r8, [rsp+88]
    test r8, r8
    jz   .invalid
    test r8b, 7
    jnz  .invalid
    mov  rax, r8
    add  rax, 3744
    jc   .invalid
    mov  rbx, [rsp+104]
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    mov  eax, [rsp+264]
    call cog_encoder_coop_size
    mov  [rsp+240], rax           ; canonical whole arena
    mov  [rsp+280], rdx
    mov  [rsp+296], rcx
    mov  eax, [rsp+264]
    imul rax, 1536
    mov  [rsp+272], rax
    mov  r9, rsp
    mov  r10, [rsp+288]
    lea  r11, [r10+2304]
    call .check_sources           ; canonical whole context vs ALL immutable spans
    jnz  .invalid
    mov  rdi, r15
    mov  esi, 1536
    call .range_ok
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rsp+240]
    call .range_ok
    jnz  .invalid
    mov  qword [rsp+304], 1        ; safe revocation even on later malformed metadata
    cmp  qword [rbp-32], 0        ; request owner
    je   .invalid
    cmp  qword [rbp-24], 0        ; request generation
    je   .invalid
    cmp  qword [rbp-16], 2304
    jne  .invalid
    cmp  dword [rbp-4], 0
    jne  .invalid
    cmp  qword [rsp+32], 1536
    jne  .invalid
    cmp  qword [rsp+48], 47671320
    jne  .invalid
    cmp  qword [rsp+64], 1536
    jne  .invalid
    cmp  qword [rsp+80], 1536
    jne  .invalid
    cmp  qword [rsp+96], 3744
    jne  .invalid
    mov  rax, [rsp+240]
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
    mov  r9, rsp
    mov  r10, r15
    mov  r11, r15
    add  r11, 1536
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rsp+240]
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rsp+240]
    jc   .invalid
    call .check_sources
    jnz  .invalid
    xor  eax, eax
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    mov  rdx, [rsp+304]
    add  rsp, 312
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
    mov  esi, 1536
    cmp  ecx, 40
    jne  .embedding_extent_ready
    mov  esi, 47671320
.embedding_extent_ready:
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 88
    jb   .embedding_sources
    mov  rdi, [r9+256]
    mov  esi, 168
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+88]
    mov  esi, 3744
    call .range_ok
    jnz  .sources_bad
    mov  r8, [r9+88]
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

cog_encoder_coop_size:
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
