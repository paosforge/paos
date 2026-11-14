;; MODULE cognition/encoder_stack
;; LAYER 6
;; EXPORTS cog_encoder_stack_f32_advisory
;; IMPORTS cog_encoder_layer_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native ordered composition of 1..12 accepted BGE encoder layers. Input is
; admitted normalized embeddings; caller authenticates immutable model operands.
; SysV RDI=Xf32[L,384], RSI=u8 keymask[L]0/1, RDX=finalf32[L,384], RCX=config64.
; Config8-aligned: u32 L1..512,count1..12; u64 Xbytes,maskbytes,outbytes,
; models_ptr,models_bytes,workspace_ptr,workspace_bytes. All exact spans.
; Models is an 8-aligned count*312 array, in execution order. Each model312:
; 0:f32 attention_epsilon,4:u32 reserved0;
; 8,48,88,128:Q/K/V/O descriptors40 (same as encoder_layer config56..215);
; 168/176:attention_gamma_ptr/bytes,184/192:beta_ptr/bytes;
; 200:f32 FFN_epsilon,204:scale1,208:scale2,212:i8 zero1,213:i8 zero2,
; 214:u16 reserved0;216,232,248,264,280,296:FFN ptr/length pairs
; weight1,bias1,weight2,bias2,gamma,beta (same as layer config264..359).
; N=L1536,S=48L^2,Wlayer=6N+max(4N+3S,53N/4). Workspace exact2N+Wlayer,
; maximum45MiB. Prefix two N-byte ping-pong states; remaining Wlayer reused.
; Final and workspace mutually disjoint and disjoint from X, mask, original
; config, entire models array and EVERY model operand of EVERY layer, including
; later stages. All ends checked/full64 lengths/alignment/nulls. Immutable
; operands may alias. Header snapshotted; all model metadata validated before
; any stage writes, each layer descriptor snapshotted into its private call
; config before use. Stable mapped immutable model/input lifetimes are caller
; obligations; checks do not authenticate models or establish page mappings.
; First input is X, then each successful layer's output. Only after all stages
; succeed is the final ping-pong state copied to final output, preserving every
; final byte on ANY refusal, including failed last layer and stale scratch.
; Metadata/ownership/mask refusal leaves workspace unchanged. Later numerical
; failure may retain complete prior layer states and child scratch. Existing
; primitive domains and all-masked arithmetic retained; caller inference policy
; is separate. No allocation, global scratch, I/O, model loader or authority.
; EAX0 success/1 invalid. Full MXCSR/x87/DF/nonvolatile GPR/RSP preserved.
; Internal RN/gradual underflow; nested stack <2112 bytes. Not model quality or
; runtime acceptance. Pinned graph classifier4850 tools/native_bge_host.py run_layers.

cog_encoder_stack_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 520                 ; header64, layer360, FP8, geometry/state
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
    mov  [rsp+456], r15
    xor  ecx, ecx
.snapshot:
    mov  rax, [r15+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 8
    jb   .snapshot
    mov  ebx, [rsp]
    test ebx, ebx
    jz   .invalid
    cmp  ebx, 512
    ja   .invalid
    mov  eax, [rsp+4]
    test eax, eax
    jz   .invalid
    cmp  eax, 12
    ja   .invalid
    imul rax, 312
    mov  [rsp+448], rax
    cmp  [rsp+40], rax
    jne  .invalid
    mov  rbp, rbx
    imul rbp, 1536
    cmp  [rsp+8], rbp
    jne  .invalid
    cmp  [rsp+16], rbx
    jne  .invalid
    cmp  [rsp+24], rbp
    jne  .invalid
    mov  eax, ebx
    imul rax, rbx
    imul rax, 144
    lea  rax, [rax+rbp*4]         ; attention scratch4N+3S
    imul rcx, rbx, 20352
    cmp  rax, rcx
    cmovb rax, rcx
    imul rcx, rbp, 6
    add  rax, rcx
    mov  [rsp+432], rax           ; layer scratch exact
    lea  rax, [rax+rbp*2]
    mov  [rsp+440], rax           ; stack scratch exact
    cmp  [rsp+56], rax
    jne  .invalid
    mov  r8, [rsp+32]
    test r8, r8
    jz   .invalid
    test r8b, 7
    jnz  .invalid
    mov  rax, r8
    add  rax, [rsp+448]
    jc   .invalid
    mov  r15, [rsp+48]
    test r15, r15
    jz   .invalid
    test r15b, 3
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
    mov  r10, r14
    mov  r11, r14
    add  r11, rbp
    jc   .invalid
    call .check_sources           ; final protects every layer model
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [r9+440]
    call .range_ok
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, [r9+440]
    jc   .invalid
    call .check_sources           ; entire workspace protects later models too
    jnz  .invalid
    xor  ecx, ecx
.mask:
    cmp  byte [r13+rcx], 1
    ja   .invalid
    inc  ecx
    cmp  rcx, rbx
    jb   .mask
    stmxcsr [rsp+424]
    mov  dword [rsp+428], 0x1f80
    ldmxcsr [rsp+428]
    mov  [rsp+472], r12           ; first layer input is normalized X
    mov  [rsp+480], r15           ; first layer writes ping state0
    lea  rax, [r15+rbp*2]
    mov  [rsp+488], rax           ; shared child scratch
    mov  dword [rsp+464], 0
.layer:
    mov  eax, [rsp+464]
    imul rax, 312
    add  rax, [rsp+32]
    mov  r8, rax
    mov  [rsp+64], ebx
    mov  dword [rsp+68], 384
    mov  rax, [r8]
    mov  [rsp+72], rax            ; attention epsilon/reserved
    mov  [rsp+80], rbp
    mov  [rsp+88], rbx
    mov  [rsp+96], rbp
    mov  rax, [rsp+488]
    mov  [rsp+104], rax
    mov  rax, [rsp+432]
    mov  [rsp+112], rax
    xor  ecx, ecx
.layer_snapshot:
    mov  rax, [r8+rcx+8]
    mov  [rsp+rcx+120], rax       ; remaining model bytes -> layer56..359
    add  ecx, 8
    cmp  ecx, 304
    jb   .layer_snapshot
    mov  rdi, [rsp+472]
    mov  rsi, r13
    mov  rdx, [rsp+480]
    lea  rcx, [rsp+64]
    call cog_encoder_layer_f32_advisory
    test eax, eax
    jnz  .restore                 ; never consume failed/stale ping state
    mov  rax, [rsp+480]
    mov  [rsp+472], rax           ; only successful output becomes next input
    inc  dword [rsp+464]
    mov  edx, [rsp+464]
    cmp  edx, [rsp+4]
    jae  .publish
    and  edx, 1
    imul rdx, rbp
    lea  rdx, [r15+rdx]
    mov  [rsp+480], rdx           ; alternate state0/state1
    jmp  .layer
.publish:
    mov  rsi, [rsp+472]
    mov  rdx, rbp
    shr  rdx, 2
    xor  ecx, ecx
.copy:
    mov  eax, [rsi+rcx*4]
    mov  [r14+rcx*4], eax         ; only final mutation, after all success
    inc  ecx
    cmp  rcx, rdx
    jb   .copy
    xor  eax, eax
.restore:
    ldmxcsr [rsp+424]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 520
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; R9=fixed frame, R10/R11 mutable interval. Clobbers RAX/RDI/RSI/RCX/RDX/R8.
.check_sources:
    mov  rdi, r12
    mov  rsi, rbp
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, rbx
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+456]
    mov  esi, 64
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+32]
    mov  rsi, [r9+448]
    call .range_ok
    jnz  .sources_bad
    mov  r8, [r9+32]
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
