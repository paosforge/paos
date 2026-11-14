;; MODULE cognition/encoder_score_batch
;; LAYER 6
;; EXPORTS cog_encoder_score_batch_f32_advisory
;; IMPORTS cog_encoder_score_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Optional caller-owned batch of independent CLS prototype decisions.
; SysV RDI=queries[rows,384], RSI=prototypes[count,384], RDX=results[rows,20],
; RCX=config80 (8-aligned): u32 rows1..64,count2..256,width384,reserved0;
; f32 min_score,min_margin; u64 querybytes=1536rows,prototypebytes=1536count,
; resultbytes=20rows,workspace_ptr,workspacebytes=20rows+1536+4count,0,0.
; All buffers nonnull4-aligned/full64 ends. Complete config snapshot, ownership
; and abs(query/prototype)<=65536 finite preflight BEFORE first scratch write.
; Result and WHOLE workspace pairwise disjoint and disjoint all input/config
; spans; immutable input spans may alias. Exact adjacent extents are permitted.
; Workspace: 20rows staged decisions then unchanged scalar scorer scratch.
; ALL rows must return choose0/abstain1 before any final result is published.
; This is failure atomicity, not a concurrent atomic store. Caller serializes
; result access during the final bounded copy.
; EAX0 all choose,1 at least one abstain,2 invalid. Per-row <IIfff> results have
; unchanged scalar tie order, threshold, norm/rounding and scores. No batch
; confidence semantics: results are uncalibrated advice and confer no authority.
; Early metadata/numeric refusal leaves workspace/results unchanged. Child
; refusal leaves ALL results unchanged; partial staged/scratch residuals remain
; caller-owned. No failed row is published or interpreted as abstention.
; Caller retains admitted immutable mapped inputs/config throughout the call;
; this is neither a loader nor model authentication. No global scratch, I/O,
; allocator, dispatch, callbacks or parallel/timing/quality claim. MXCSR/x87/DF,
; nonvolatile GPR/RSP retained on every path, including child refusals. Own stack
; 240bytes including saved GPR/return; scalar child adds its existing bound.
cog_encoder_score_batch_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 184
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 80
    jc   .invalid
    xor  ecx, ecx
.snapshot:
    mov  rax, [r15+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 10
    jb   .snapshot
    mov  ebp, [rsp]
    cmp  ebp, 1
    jb   .invalid
    cmp  ebp, 64
    ja   .invalid
    mov  eax, [rsp+4]
    cmp  eax, 2
    jb   .invalid
    cmp  eax, 256
    ja   .invalid
    cmp  dword [rsp+8], 384
    jne  .invalid
    cmp  dword [rsp+12], 0
    jne  .invalid
    cmp  qword [rsp+64], 0
    jne  .invalid
    cmp  qword [rsp+72], 0
    jne  .invalid
    mov  eax, [rsp+16]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [rsp+20]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    test eax, eax
    jz   .thresholds_ready
    test dword [rsp+20], 0x80000000
    jnz  .invalid
.thresholds_ready:
    imul rax, rbp, 1536
    cmp  [rsp+24], rax
    jne  .invalid
    mov  eax, [rsp+4]
    imul rax, 1536
    cmp  [rsp+32], rax
    jne  .invalid
    imul rax, rbp, 20
    cmp  [rsp+40], rax
    jne  .invalid
    mov  ecx, [rsp+4]
    lea  rax, [rax+rcx*4+1536]
    cmp  [rsp+56], rax
    jne  .invalid
    mov  rbx, [rsp+48]
    mov  rdi, r12
    call .pointer_ok
    jnz  .invalid
    mov  rdi, r13
    call .pointer_ok
    jnz  .invalid
    mov  rdi, r14
    call .pointer_ok
    jnz  .invalid
    mov  rdi, rbx
    call .pointer_ok
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r14
    mov  r11, r14
    add  r11, [rsp+40]
    jc   .invalid
    call .sources_ok
    jnz  .invalid
    mov  rdi, rbx
    mov  rsi, [rsp+56]
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, [rsp+56]
    jc   .invalid
    call .sources_ok
    jnz  .invalid
    mov  rdx, [rsp+24]
    shr  rdx, 2
    xor  ecx, ecx
.query_domain:
    mov  eax, [r12+rcx*4]
    and  eax, 0x7fffffff
    cmp  eax, 0x47800000
    ja   .invalid
    inc  ecx
    cmp  rcx, rdx
    jb   .query_domain
    mov  rdx, [rsp+32]
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
    mov  eax, [rsp+4]
    mov  [rsp+80], eax
    mov  dword [rsp+84], 384
    mov  rax, [rsp+16]
    mov  [rsp+88], rax
    mov  qword [rsp+96], 1536
    mov  rax, [rsp+32]
    mov  [rsp+104], rax
    mov  qword [rsp+112], 20
    mov  rax, [rsp+40]
    add  rax, rbx
    mov  [rsp+120], rax
    mov  eax, [rsp+4]
    lea  rax, [rax*4+1536]
    mov  [rsp+128], rax
    mov  qword [rsp+136], 0
    mov  qword [rsp+152], 0       ; any abstention
    mov  qword [rsp+160], 0       ; current independent row
.row:
    mov  rax, [rsp+160]
    imul rdi, rax, 1536
    add  rdi, r12
    mov  rsi, r13
    imul rdx, rax, 20
    add  rdx, rbx
    lea  rcx, [rsp+80]
    call cog_encoder_score_f32_advisory
    cmp  eax, 1
    ja   .invalid                ; failed row never publishes earlier decisions
    or   [rsp+152], eax
    inc  qword [rsp+160]
    cmp  [rsp+160], rbp
    jb   .row
    mov  rdx, [rsp+40]
    shr  rdx, 2
    xor  ecx, ecx
.publish:
    mov  eax, [rbx+rcx*4]
    mov  [r14+rcx*4], eax
    inc  ecx
    cmp  rcx, rdx
    jb   .publish
    mov  eax, [rsp+152]
    jmp  .out
.invalid:
    mov  eax, 2
.out:
    add  rsp, 184
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

.pointer_ok:
    test rdi, rdi
    jz   .bad
    test dil, 3
    jnz  .bad
    xor  eax, eax
    ret
.sources_ok:
    mov  rdi, r12
    mov  rsi, [r9+24]
    call .range_ok
    jnz  .bad
    mov  rdi, r13
    mov  rsi, [r9+32]
    call .range_ok
    jnz  .bad
    mov  rdi, r15
    mov  esi, 80
    call .range_ok
    ret
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    cmp  rax, r10
    jbe  .good
    cmp  rdi, r11
    jae  .good
.bad:
    or   eax, 1
    ret
.good:
    xor  eax, eax
    ret
