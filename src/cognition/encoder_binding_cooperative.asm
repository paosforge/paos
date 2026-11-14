;; MODULE cognition/encoder_binding_cooperative
;; LAYER 6
;; EXPORTS cog_encoder_bound_coop_begin_advisory, cog_encoder_bound_coop_step_advisory, cog_encoder_bound_coop_cancel_advisory
;; IMPORTS core/lib/sha256, cog_encoder_pack_models_advisory, cog_encoder_rank_coop_begin_advisory, cog_encoder_rank_coop_step_advisory, cog_encoder_rank_coop_cancel_advisory
;; CAPS
;; OWNER saga:cognition
;; CONTEXT: bsp_only (canonical SHA256 unlocked static compression scratch; never AP/IRQ)
; Optional five-artifact trusted-digest-bound cooperative ASCII classification.
; SysV Begin(RDI=request336,RSI=context7224)->3 PENDING/2 REFUSED, no hashes,
; descriptors, tokenization or numerical stages. Step(request,context,RDX=u64
; expected ordinal)->3 PENDING/0 CHOOSE/1 ABSTAIN/2 REFUSED. Cancel(request,ctx)
; ->4 CANCELLED/2 REFUSED, no hashes/numerical stages. Caller serializes all calls.
;
; Immutable8-aligned request336: text0,result20 pointer8,nonzero owner16,generation24,
; exact contextbytes7224 at32, prepared2096 pointer40; accepted digest-shape config288
; at48, unchanged: textbytes0,PVTptr/bytes8/16,PEM24/32,PMW40/48,BLP56/64,
; resultbytes20 at72,arena80/bytes88,prototype96/bytes104,count2..256 at112,
; width384 at116,minscore120,minmargin124, five32-byte TRUSTED pins128..287.
; All full spans incl unused artifact tails are hashed in PVT,PEM,PMW,BLP,prototype
; order. Each hash step updates ONE finite min(remaining,65536) chunk OR finalizes
; and compares ONE complete32-byte digest, never both update+final in one step.
; Begin only initializes SHA112. A final step may initialize the next SHA context.
; After ALL5 pins match, separate steps build descriptors and prepare the existing
; cooperative rank child, then14 separate child stages: embedding,12 layers,score.
; No full-artifact/multi-artifact loop or hidden full inference in begin/step.
; Hash steps H=sum(ceil(artifactbytes/65536)+1); ordinalH builder,H+1 preparation,
; H+2..H+15 embedding/layers/scoring. Stable scalar ties/thresholds/status unchanged.
;
; Context7224/8aligned initially allzero: magic0,self8,original request16,owner24,
; generation32; u32 phase40,next44,completed48,reserved52; reservedqword56;
; frozen request336 at64; frozen WHOLE preparation2096 at400; SHA112 at2496;
; digest32 at2608; u32 artifact2640,numeric2644; u64 offset2648; private rank
; request224 at2656, rankcontext4320 at2880, staged final20 at7200,reserved7220.
; Phases1hash,2builder,3preparation,4numeric,5choose,6abstain,7cancel,8refuse.
; At every call full metadata/spans, original identity, full64 owner/generation,
; frozen request/preparation and derived stage ordinal/offset/SHA counters checked.
; Child request rederived/compared before numeric consumption. Context/retained
; tensors are trusted stable execution state, never an attacker serialization.
; Terminal tombstones clear ALL7224 except identity/owner/generation/phase;
; step/cancel refuse without reading retired request/artifact mappings. Reuse
; requires same owner and strictly newer generation. Active begin revokes/refuses.
; Frozen metadata validates bounded cleanup only, never resumes an operation.
; Unsafe claims refuse without cleanup writes; broken mapped immutable lifetimes
; require discarding the operation.
;
; Exact arena align8(A(L))+6816+4count: reservedCLS1536,
; descriptors3744, whole encoder A(L),0..4 padding, scorework1536+4count. L2..512;
; A(L)=align4(9L)+15360L+max(6144L+144L^2,20352L). Empty/count2=78272;
; maximum/count256=48771232. Both whole work arenas,
; descriptors and reservedCLS covered by aggregate ownership. Context/hash/digest/
; child state/result/whole arena pairwise disjoint and disjoint from text,all5
; complete artifacts,whole request incl pins and whole prepared capacity2096.
; All full64 ends/exact sizes checked BEFORE any caller write or artifact parsing.
; Immutable inputs may alias. No mapping rights inferred from integer span checks.
; Preparation header binds text/PVT/shape; child retokenizes actual used IDs and
; compares frozen preparation before any embedding. All5 digests precede even
; descriptor reads/writes. Only accepted final child choose/abstain copies20 bytes
; to caller result; pending/cancel/refusal leaves prior advice unchanged. Numeric
; work may retain residuals on late refusal. Publication is caller-serialized,
; failure-atomic, not a cross-thread20-byte atomic store.
;
; Pins/models/prototype labels/policy MUST already come from trusted admission;
; attacker-chosen matching pins grant NO authority. Caller retains all admitted
; immutable mapped artifacts/config/preparation/prototypes throughout hash+execute.
; Owner/generation are execution identity only. No trust cache/key store/loader/
; policy/model format/global scratch/allocator/scheduler/callback/AP/IRQ work.
; Canonical SHA256 and all existing numerical/digest/cooperative APIs unchanged.
; Complete MXCSR/x87/DF/nonvolatile GPR/RSP preserved. Ownstack<512 bytes; nested
; begin/prepare<8600, numeric<3000. A bounded step is not a wall-clock promise.
; SOURCE/inert only; no quality/calibration/probability/runtime/fullRC claim.
COG_BOUND_COOP_MAGIC equ 0x31444e554f424743

cog_encoder_bound_coop_begin_advisory:
    xor ecx,ecx
    jmp cog_encoder_bound_coop_dispatch
cog_encoder_bound_coop_step_advisory:
    mov ecx,1
    jmp cog_encoder_bound_coop_dispatch
cog_encoder_bound_coop_cancel_advisory:
    mov ecx,2
cog_encoder_bound_coop_dispatch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,248
    pushfq
    pop qword [rsp+224]
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15d,ecx
    test ecx,ecx
    jz .validate
    mov rdi,r13
    call cog_encoder_bound_coop_terminal
    test eax,eax
    jnz .unsafe
.validate:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r12
    call cog_encoder_bound_coop_validate
    test eax,eax
    jnz .revoke
    test r15d,r15d
    jz .begin
    cmp r15d,2
    jne .expected
    mov r14d,[r13+44]
.expected:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    call cog_encoder_bound_coop_state_ok
    test eax,eax
    jnz .refuse
    cmp r15d,2
    je .cancel
    mov eax,[r13+40]
    cmp eax,1
    je .hash
    cmp eax,2
    je .builder
    cmp eax,3
    je .prepare
    lea rdi,[r13+2656]
    lea rsi,[r13+2880]
    mov edx,[r13+2644]
    call cog_encoder_rank_coop_step_advisory
    cmp dword [r13+2644],13
    je .final_advice
    cmp eax,3
    jne .refuse                 ; failed numeric stage cannot advance
    inc dword [r13+2644]
    jmp .advance
.final_advice:
    cmp eax,1
    ja .refuse                  ; failed child never publishes stale advice
    mov ebx,eax
    mov rdi,[r12+8]
    xor ecx,ecx
.publish:
    mov eax,[r13+7200+rcx*4]
    mov [rdi+rcx*4],eax
    inc ecx
    cmp ecx,5
    jb .publish
    lea edx,[rbx+5]
    mov rdi,r13
    mov rsi,r12
    call cog_encoder_bound_coop_clear
    mov eax,ebx
    jmp .out
.hash:
    mov rdi,r12
    mov ecx,[r13+2640]
    call cog_encoder_bound_coop_artifact
    mov rbx,[r13+2648]
    cmp rbx,rdx
    je .final_hash
    sub rdx,rbx
    cmp rdx,65536
    jbe .chunk
    mov edx,65536               ; hard per-step byte cap
.chunk:
    add rsi,rbx
    mov [rsp+232],rdx
    lea rdi,[r13+2496]
    cld
    call sha256_stream_update
    test rax,rax
    jnz .refuse                 ; failed update cannot advance hash state
    mov rax,[rsp+232]
    add [r13+2648],rax
    jmp .advance
.final_hash:
    lea rdi,[r13+2496]
    lea rsi,[r13+2608]
    cld
    call sha256_stream_final
    test rax,rax
    jnz .refuse                 ; stale digest never consumed on failure
    mov eax,[r13+2640]
    shl eax,5
    lea rdx,[r12+rax+176]
    xor r8d,r8d
    xor ecx,ecx
.compare_digest:
    mov rax,[r13+2608+rcx*8]
    xor rax,[rdx+rcx*8]
    or r8,rax
    inc ecx
    cmp ecx,4
    jb .compare_digest
    test r8,r8
    jnz .refuse                 ; all32 bytes, all5 artifacts
    lea rdi,[r13+2496]
    xor eax,eax
    mov ecx,18
    rep stosq                  ; clear SHA112+digest32 before next artifact
    mov qword [r13+2648],0
    inc dword [r13+2640]
    cmp dword [r13+2640],5
    je .hashes_ready
    lea rdi,[r13+2496]
    call sha256_stream_init
    test rax,rax
    jnz .refuse
    jmp .advance
.hashes_ready:
    mov dword [r13+40],2
    jmp .advance
.builder:
    mov qword [rsp],21234832
    mov qword [rsp+8],243376
    mov qword [rsp+16],3744
    mov qword [rsp+24],0
    mov rdi,[r12+88]
    mov rsi,[r12+104]
    mov rdx,[r12+128]
    add rdx,1536
    mov rcx,rsp
    call cog_encoder_pack_models_advisory
    test eax,eax
    jnz .refuse                 ; descriptors cannot be consumed on failure
    mov dword [r13+40],3
    jmp .advance
.prepare:
    mov rdi,r12
    mov rsi,r13
    lea rdx,[r13+2656]
    call cog_encoder_bound_coop_child_request
    lea rdi,[r13+2656]
    lea rsi,[r13+2880]
    call cog_encoder_rank_coop_begin_advisory
    cmp eax,3
    jne .refuse                 ; failed preparation never supplies valid IDs
    mov rdx,[r12+128]
    add rdx,5280
    mov ecx,[r13+400]
    xor eax,eax
.prepared_tokens:
    mov ebx,[rdx+rax*4]
    cmp ebx,[r13+448+rax*4]
    jne .refuse
    inc eax
    cmp eax,ecx
    jb .prepared_tokens
    mov dword [r13+40],4
    jmp .advance
.advance:
    inc dword [r13+44]
    inc dword [r13+48]
    mov eax,3
    jmp .out
.cancel:
    cmp dword [r13+40],4
    jne .cancel_clear
    lea rdi,[r13+2656]
    lea rsi,[r13+2880]
    call cog_encoder_rank_coop_cancel_advisory
    cmp eax,4
    jne .refuse
.cancel_clear:
    mov edx,7
    mov rdi,r13
    mov rsi,r12
    call cog_encoder_bound_coop_clear
    mov eax,4
    jmp .out
.begin:
    mov rdi,r13
    call cog_encoder_bound_coop_envelope
    test eax,eax
    jnz .existing
    xor ecx,ecx
.fresh:
    cmp qword [r13+rcx*8],0
    jne .refuse
    inc ecx
    cmp ecx,903
    jb .fresh
    jmp .initialize
.existing:
    mov rdi,r13
    call cog_encoder_bound_coop_terminal
    test eax,eax
    jz .refuse
    mov rax,[r12+16]
    cmp [r13+24],rax
    jne .refuse
    mov rax,[r12+24]
    cmp rax,[r13+32]
    jbe .refuse                 ; no silent same-generation reuse
.initialize:
    mov rdi,r13
    xor eax,eax
    mov ecx,903
    cld
    rep stosq
    mov rax,COG_BOUND_COOP_MAGIC
    mov [r13],rax
    mov [r13+8],r13
    mov [r13+16],r12
    mov rax,[r12+16]
    mov [r13+24],rax
    mov rax,[r12+24]
    mov [r13+32],rax
    mov dword [r13+40],1
    lea rdi,[r13+64]
    mov rsi,r12
    mov ecx,42
    rep movsq
    lea rdi,[r13+400]
    mov rsi,[r12+40]
    mov ecx,262
    rep movsq
    lea rdi,[r13+2496]
    call sha256_stream_init
    test rax,rax
    jnz .refuse
    mov eax,3
    jmp .out
.revoke:
    mov rdi,r13
    call cog_encoder_bound_coop_envelope
    test eax,eax
    jz .unsafe
    lea rdi,[r13+64]
    mov rsi,r13
    mov rdx,[r13+16]
    call cog_encoder_bound_coop_validate
    test eax,eax
    jnz .unsafe
.refuse:
    mov rdi,r13
    mov rsi,r12
    mov edx,8
    call cog_encoder_bound_coop_clear
.unsafe:
    mov eax,2
.out:
    test qword [rsp+224],0x400
    jz .df_clear
    std
    jmp .leave
.df_clear:
    cld
.leave:
    add rsp,248
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Artifact slot from immutable request. ECX0..4 -> RSI pointer,RDX full length.
cog_encoder_bound_coop_artifact:
    mov eax,ecx
    shl eax,4
    add eax,56
    cmp ecx,4
    jne .slot
    mov eax,144
.slot:
    mov rsi,[rdi+rax]
    mov rdx,[rdi+rax+8]
    ret

; Build exact unchanged accepted rank request from already validated metadata.
; RDI outer request,RSI outer context,RDX destination224; no numerical stage.
cog_encoder_bound_coop_child_request:
    mov rax,[rdi]
    mov [rdx],rax
    lea rax,[rsi+7200]
    mov [rdx+8],rax
    mov rax,[rdi+16]
    mov [rdx+16],rax
    mov rax,[rdi+24]
    mov [rdx+24],rax
    mov qword [rdx+32],4320
    mov eax,[rsi+400]
    mov [rdx+40],eax
    mov dword [rdx+44],0
    mov rax,0x0000000c00000200
    mov [rdx+48],rax
    mov rax,[rdi+48]
    mov [rdx+56],rax
    mov rax,[rdi+56]
    mov [rdx+64],rax
    mov rax,[rdi+64]
    mov [rdx+72],rax
    mov qword [rdx+80],1536
    mov rax,[rdi+72]
    mov [rdx+88],rax
    mov qword [rdx+96],47671320
    mov rax,[rdi+104]
    add rax,16
    mov [rdx+104],rax
    mov qword [rdx+112],1536
    add rax,1536
    mov [rdx+120],rax
    mov qword [rdx+128],1536
    mov rax,[rdi+128]
    add rax,1536
    mov [rdx+136],rax
    mov qword [rdx+144],3744
    mov rax,[rdi+128]
    add rax,5280
    mov [rdx+152],rax
    mov rcx,[rsi+408]
    mov [rdx+160],rcx
    add rcx,7
    and rcx,-8                 ; accepted rank scorework requires8 alignment
    add rax,rcx
    mov [rdx+200],rax
    mov ecx,[rdi+160]
    lea rcx,[rcx*4+1536]
    mov [rdx+208],rcx
    mov rax,[rdi+144]
    mov [rdx+168],rax
    mov rax,[rdi+152]
    mov [rdx+176],rax
    mov rax,[rdi+160]
    mov [rdx+184],rax
    mov rax,[rdi+168]
    mov [rdx+192],rax
    mov qword [rdx+216],20
    ret

cog_encoder_bound_coop_envelope:
    xor eax,eax
    test rdi,rdi
    jz .out
    test dil,7
    jnz .out
    mov rax,rdi
    add rax,7224
    jc .bad
    mov rax,COG_BOUND_COOP_MAGIC
    cmp [rdi],rax
    jne .bad
    cmp [rdi+8],rdi
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
.out:
    ret

cog_encoder_bound_coop_terminal:
    sub rsp,8
    call cog_encoder_bound_coop_envelope
    add rsp,8
    test eax,eax
    jz .out
    mov eax,[rdi+40]
    cmp eax,5
    jb .bad
    cmp eax,8
    ja .bad
    cmp qword [rdi+44],0
    jne .bad
    cmp dword [rdi+52],0
    jne .bad
    cmp qword [rdi+56],0
    jne .bad
    mov ecx,8
.tail:
    cmp qword [rdi+rcx*8],0
    jne .bad
    inc ecx
    cmp ecx,903
    jb .tail
    mov eax,1
    ret
.bad:
    xor eax,eax
.out:
    ret

cog_encoder_bound_coop_clear:
    mov r8,rdi
    mov rax,COG_BOUND_COOP_MAGIC
    cmp [rdi],rax
    jne .from_request
    cmp [rdi+8],rdi
    jne .from_request
    mov r9,[rdi+24]
    mov r10,[rdi+32]
    mov r11,[rdi+16]
    jmp .clear
.from_request:
    mov r9,[rsi+16]
    mov r10,[rsi+24]
    mov r11,rsi
.clear:
    xor eax,eax
    mov ecx,903
    cld
    rep stosq
    mov rax,COG_BOUND_COOP_MAGIC
    mov [r8],rax
    mov [r8+8],r8
    mov [r8+16],r11
    mov [r8+24],r9
    mov [r8+32],r10
    mov [r8+40],edx
    ret

cog_encoder_bound_coop_state_ok:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,232
    mov r12,rdi
    mov r13,rsi
    mov rax,COG_BOUND_COOP_MAGIC
    cmp [rsi],rax
    jne .bad
    cmp [rsi+8],rsi
    jne .bad
    cmp [rsi+16],rdi
    jne .bad
    mov rax,[rdi+16]
    cmp [rsi+24],rax
    jne .bad
    mov rax,[rdi+24]
    cmp [rsi+32],rax
    jne .bad
    mov eax,[rsi+44]
    cmp rdx,rax
    jne .bad
    cmp [rsi+48],eax
    jne .bad
    cmp dword [rsi+52],0
    jne .bad
    cmp qword [rsi+56],0
    jne .bad
    cmp dword [rsi+7220],0
    jne .bad
    xor ecx,ecx
.snapshot:
    mov rax,[rdi+rcx*8]
    cmp [rsi+64+rcx*8],rax
    jne .bad
    inc ecx
    cmp ecx,42
    jb .snapshot
    mov rdx,[rdi+40]
    xor ecx,ecx
.preparation:
    mov rax,[rdx+rcx*8]
    cmp [rsi+400+rcx*8],rax
    jne .bad
    inc ecx
    cmp ecx,262
    jb .preparation
    mov ebx,[rsi+40]
    cmp ebx,1
    jb .bad
    cmp ebx,4
    ja .bad
    mov ebp,[rsi+2640]
    cmp ebx,1
    jne .after_hash
    cmp ebp,5
    jae .bad
    cmp dword [rsi+2644],0
    jne .bad
    mov rdi,r12
    mov ecx,ebp
    call cog_encoder_bound_coop_artifact
    mov rax,[r13+2648]
    cmp rax,rdx
    ja .bad
    je .offset_ready
    test eax,65535
    jnz .bad
.offset_ready:
    cmp [r13+2528],rax
    jne .bad
    mov edx,eax
    and edx,63
    cmp [r13+2536],rdx
    jne .bad
    add rax,65535
    shr rax,16
    mov ebx,eax
    jmp .prior_artifacts
.after_hash:
    cmp ebp,5
    jne .bad
    cmp qword [r13+2648],0
    jne .bad
    xor ecx,ecx
.zero_hash:
    cmp qword [r13+2496+rcx*8],0
    jne .bad
    inc ecx
    cmp ecx,18
    jb .zero_hash
    sub ebx,2
    cmp ebx,2
    jne .no_numeric
    mov eax,[r13+2644]
    cmp eax,13
    ja .bad
    add ebx,eax
    mov rdi,r12
    mov rsi,r13
    mov rdx,rsp
    call cog_encoder_bound_coop_child_request
    xor ecx,ecx
.child_request:
    mov rax,[rsp+rcx*8]
    cmp [r13+2656+rcx*8],rax
    jne .bad
    inc ecx
    cmp ecx,28
    jb .child_request
    jmp .prior_artifacts
.no_numeric:
    cmp dword [r13+2644],0
    jne .bad
.prior_artifacts:
    xor ecx,ecx
.count:
    cmp ecx,ebp
    jae .ordinal
    mov rdi,r12
    call cog_encoder_bound_coop_artifact
    add rdx,65535
    shr rdx,16
    inc edx
    add ebx,edx
    inc ecx
    jmp .count
.ordinal:
    cmp [r13+44],ebx
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    add rsp,232
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Full64 metadata/span-only preflight. RDI values,RSI context,RDX original
; request identity; frozen values may validate clearing, never execute. No writes.
cog_encoder_bound_coop_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,408
    mov [rsp+392],rsi
    mov [rsp+400],rdx
    test rdi,rdi
    jz .invalid
    test dil,7
    jnz .invalid
    mov rax,rdi
    add rax,336
    jc .invalid
    test rdx,rdx
    jz .invalid
    test dl,7
    jnz .invalid
    mov rax,rdx
    add rax,336
    jc .invalid
    test rsi,rsi
    jz .invalid
    test sil,7
    jnz .invalid
    mov rax,rsi
    add rax,7224
    jc .invalid
    cmp qword [rdi+16],0
    je .invalid
    cmp qword [rdi+24],0
    je .invalid
    cmp qword [rdi+32],7224
    jne .invalid
    mov r12,[rdi]
    mov r13,[rdi+8]
    mov rax,[rdi+40]
    mov [rsp+336],rax
    lea rbp,[rdi+48]
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
    add  rax, 288
    jc   .invalid
    mov  rax,[rsp+400]
    mov  [rsp+328],rax
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 36
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
    mov  rax, [rsp+336]
    test rax, rax
    jz   .invalid
    test al, 7
    jnz  .invalid
    mov  rdx, rax
    add  rdx, 2096
    jc   .invalid
    xor  ecx, ecx
.shape_snapshot:
    mov  rdx, [rax+rcx*8]
    mov  [rsp+344+rcx*8], rdx
    inc  ecx
    cmp  ecx, 6
    jb   .shape_snapshot
    mov  eax, [rsp+344]
    cmp  eax, 2
    jb   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+348], 0
    jne  .invalid
    call .size                    ; bounded full64 arithmetic, never record trust
    cmp  [rsp+352], rax
    jne  .invalid
    add rax,7
    and rax,-8                 ; whole exact aligned aggregate arena
    lea  rax, [rax+rbx*4+6816]
    cmp  [rsp+88], rax            ; exact whole classifier arena, full64
    jne  .invalid
    mov  rax, [rsp+360]
    cmp  rax, r12
    jne  .invalid
    mov  rax, [rsp+368]
    cmp  rax, [rsp]
    jne  .invalid
    mov  rax, [rsp+376]
    cmp  rax, [rsp+8]
    jne  .invalid
    mov  rax, [rsp+384]
    cmp  rax, [rsp+16]
    jne  .invalid
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
    call .check_sources           ;whole arena protects pins and every artifact
    jnz  .invalid
    mov r10,[rsp+392]
    lea r11,[r10+7224]
    call .check_sources           ; whole context including SHA/digest/private child
    jnz .invalid
    mov rdi,r13
    mov esi,20
    call .range_ok
    jnz .invalid
    mov rdi,r15
    mov rsi,[rsp+88]
    call .range_ok
    jnz .invalid
    xor eax,eax
    jmp .out
.invalid:
    mov eax,1
.out:
    add rsp,408
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
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
    mov  rdi, [r9+328]
    mov  esi, 336
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+336]
    mov  esi, 2096               ; protect whole prepared capacity
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

.size:
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
