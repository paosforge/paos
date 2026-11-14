;; MODULE cognition/encoder_layer
;; LAYER 6
;; EXPORTS cog_encoder_layer_f32_advisory
;; IMPORTS cog_quantize_f32_advisory cog_encoder_projection_prequant_advisory cog_encoder_projection_f32_advisory cog_encoder_attention_f32_advisory cog_encoder_residual_norm_f32_advisory cog_encoder_feedforward_f32_advisory
;; CAPS
;; OWNER saga:cognition
; One complete batch-one BGE layer, guarded integer AVX2/scalar, SSE2 float stages.
; SysV RDI Xf32[L,384], RSI u8 mask[L]0/1, RDX finalf32[L,384], RCX config360.
; Caller supplies mapped/stable buffers and authenticated/admitted model data;
; checks below prove spans/ownership, not mappings or model admission/authority.
; Config360(8-aligned), offsets:
; 0:u32 L,width384;8:f32 attention_epsilon;12:u32 reserved0;
; 16/24/32:u64 x_bytes,mask_bytes,out_bytes;40/48:workspace_ptr,workspace_bytes.
; 56,96,136,176:Q/K/V/output projection descriptors40:
;   u64 weight_ptr,weight_bytes,bias_ptr,bias_bytes;f32 scale;i8 zero;u8 reserved[3]=0.
; Each packed weight[384,384]147456bytes, bias384f32=1536bytes.
; 216/224:attention_gamma_ptr,bytes;232/240:attention_beta_ptr,bytes (each1536).
; 248:f32 FFN_epsilon,scale1,scale2;260:i8 zero1,zero2;262:u16 reserved0.
; 264,280,296,312,328,344:FFN weight1,bias1,weight2,bias2,gamma,beta ptr/bytes pairs;
; exact lengths589824,6144,589824,1536,1536,1536.
; L1..512,N=L*1536,S=48*L*L; exact input/outputN,maskL; workspace exact
; 6N+max(4N+3S,53N/4), maximum43.5MiB. Prefix Q,K,V,context,attention_projection,
; attention_norm eachN. Shared scratch then used by projections, attention,
; attention residual norm and FFN with their exact individual workspace sizes.
; All pointers nonnull; f32 arrays/workspace4-aligned, packed weights/mask byte-
; aligned. Ends checked; final/workspace mutually disjoint and disjoint from X,
; mask, every immutable model array and original config. Immutable arrays may
; alias. Entire descriptor snapshotted before validation/stage calls.
; Graph order: whole-input Q/K/V projections -> pinned scaled12-head attention ->
; output projection -> Add original X/LayerNorm -> FFN with attention_norm residual.
; One whole-X quantization supplies borrowed u8/scale/zero to three Q/K/V helpers.
; Shared scratch keeps quantizedN/4 prefix alive and reuses nextN accumulators
; until all3 projections complete; attention then reuses that scratch. O and FFN
; each quantize their own actual input; no reusable token/global cache is created.
; No per-row quantization, extra scaling, causal mask or alternate normalization.
; Native all-masked arithmetic yields uniform weights; inference admission policy
; remains caller-owned. Accepted primitive numeric domains/approximations retained.
; EAX0 success/1 invalid. Final output unchanged on EVERY refusal. Workspace
; unchanged on metadata/mask/first quantizer input refusal; later failure may leave
; completed/reused stage data. Failed stages stop; stale scratch is never consumed.
; Full MXCSR restored through nested calls; SysV nonvolatile GPR/RSP/DF/x87
; preserved, nested stack<1424bytes (FFN path1408:648+8+328+8+416).
; No I/O/model acquisition/authority grant.
; Layer arithmetic only; not whole encoder/loading/model quality/runtime proof.

cog_encoder_layer_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 600                 ; snapshot360, stage152, FP8, geometry and sharedquant outputs
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
    add  rax, 360
    jc   .invalid
    mov  [rsp+576], r15
    xor  ecx, ecx
.snapshot:
    mov  rax, [r15+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 45
    jb   .snapshot
    mov  ebx, [rsp]
    test ebx, ebx
    jz   .invalid
    cmp  ebx, 512
    ja   .invalid
    cmp  dword [rsp+4], 384
    jne  .invalid
    cmp  dword [rsp+12], 0
    jne  .invalid
    mov  eax, [rsp+8]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [rsp+248]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    cmp  word [rsp+262], 0
    jne  .invalid
    mov  ebp, ebx
    imul rbp, 1536                ; N
    cmp  [rsp+16], rbp
    jne  .invalid
    cmp  [rsp+24], rbx
    jne  .invalid
    cmp  [rsp+32], rbp
    jne  .invalid
    mov  eax, ebx
    imul rax, rbx
    imul rax, 48
    mov  [rsp+520], rax           ; S
    imul rax, 3
    lea  rax, [rax+rbp*4]
    mov  [rsp+528], rax           ; attention workspace4N+3S
    mov  ecx, ebx
    imul rcx, 20352
    mov  [rsp+536], rcx           ; FFN workspace53N/4
    cmp  rax, rcx
    cmovb rax, rcx
    imul rcx, rbp, 6
    add  rax, rcx
    cmp  [rsp+48], rax
    jne  .invalid
    mov  ecx, 56
.projection_metadata:
    cmp  qword [rsp+rcx+8], 147456
    jne  .invalid
    cmp  qword [rsp+rcx+24], 1536
    jne  .invalid
    test dword [rsp+rcx+36], 0xffffff00
    jnz  .invalid
    cmp  qword [rsp+rcx], 0
    je   .invalid
    mov  rdi, [rsp+rcx+16]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    add  ecx, 40
    cmp  ecx, 216
    jb   .projection_metadata
    mov  ecx, 216
.attention_affine_metadata:
    cmp  qword [rsp+rcx+8], 1536
    jne  .invalid
    mov  rdi, [rsp+rcx]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    add  ecx, 16
    cmp  ecx, 248
    jb   .attention_affine_metadata
    cmp  qword [rsp+272], 589824
    jne  .invalid
    cmp  qword [rsp+288], 6144
    jne  .invalid
    cmp  qword [rsp+304], 589824
    jne  .invalid
    cmp  qword [rsp+320], 1536
    jne  .invalid
    cmp  qword [rsp+336], 1536
    jne  .invalid
    cmp  qword [rsp+352], 1536
    jne  .invalid
    mov  ecx, 264
.ffn_pointer_metadata:
    mov  rdi, [rsp+rcx]
    test rdi, rdi
    jz   .invalid
    cmp  ecx, 264
    je   .ffn_pointer_next
    cmp  ecx, 296
    je   .ffn_pointer_next
    test dil, 3
    jnz  .invalid
.ffn_pointer_next:
    add  ecx, 16
    cmp  ecx, 360
    jb   .ffn_pointer_metadata
    mov  r15, [rsp+40]
    test r15, r15
    jz   .invalid
    test r15b, 3
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r14
    mov  r11, r14
    add  r11, rbp
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [rsp+48]
    call .range_ok                ; final/workspace disjoint
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, [rsp+48]
    jc   .invalid
    call .check_sources           ; workspace preserves model/input/config
    jnz  .invalid
    xor  ecx, ecx
.mask_preflight:
    cmp  byte [r13+rcx], 1
    ja   .invalid
    inc  ecx
    cmp  rcx, rbx
    jb   .mask_preflight
    imul rax, rbp, 6
    add  rax, r15
    mov  [rsp+544], rax           ; shared workspace
    lea  rax, [rbp+rbp*2]
    add  rax, r15
    mov  [rsp+552], rax           ; context
    lea  rax, [r15+rbp*4]
    mov  [rsp+560], rax           ; attention output projection
    lea  rax, [rbp+rbp*4]
    add  rax, r15
    mov  [rsp+568], rax           ; attention norm, FFN input
    stmxcsr [rsp+512]
    mov  dword [rsp+516], 0x1f80
    ldmxcsr [rsp+516]
    mov  rax, rbp
    shr  rax, 2
    mov  [rsp+360], rax           ;one whole-X quantizer config24 count/reserved0
    mov  [rsp+368], rbp
    mov  [rsp+376], rax
    mov  dword [rsp+596], 0       ;activationzero plus reserved bytes
    mov  rdi, r12
    mov  rsi, [rsp+544]
    lea  rdx, [rsp+592]           ;shared activation scale, local lifetime
    lea  rcx, [rsp+596]           ;shared activation zero point
    lea  r8, [rsp+360]
    call cog_quantize_f32_advisory
    test eax, eax
    jnz  .restore                 ;failed quantizer never consumes stale sharedQ
    mov  dword [rsp+584], 0       ; first Q/K/V projection
.qkv_projection:
    mov  r10d, [rsp+584]
    imul r10d, 40
    add  r10d, 56
    mov  r9, rsp
    call .projection_config
    mov  rax, rbp
    shr  rax, 2
    mov  [rsp+384], rax           ;prequant q_bytes=L*384, not floatXbytes
    add  rax, [rsp+544]
    mov  [rsp+416], rax           ;accumulators after live sharedQ prefix
    mov  [rsp+424], rbp           ;accumworkspaceN, exact old arena unchanged
    mov  eax, [rsp+592]
    mov  [rsp+432], eax
    mov  eax, [rsp+596]
    mov  [rsp+436], eax           ;zero point and reserved0 from quantization
    mov  rdi, [rsp+544]
    mov  rsi, [rsp+r10]
    mov  rdx, [rsp+r10+16]
    mov  eax, [rsp+584]
    imul rax, rbp
    lea  rcx, [r15+rax]
    lea  r8, [rsp+360]
    call cog_encoder_projection_prequant_advisory
    test eax, eax
    jnz  .restore                 ; Q/K/V projection refusal
    inc  dword [rsp+584]
    cmp  dword [rsp+584], 3
    jb   .qkv_projection
    mov  [rsp+360], rbx            ; attention config64 L,reserved0
    mov  [rsp+368], rbp
    mov  [rsp+376], rbp
    mov  [rsp+384], rbp
    mov  [rsp+392], rbx
    mov  [rsp+400], rbp
    mov  rax, [rsp+544]
    mov  [rsp+408], rax
    mov  rax, [rsp+528]
    mov  [rsp+416], rax
    mov  rdi, r15
    lea  rsi, [r15+rbp]           ; K projection
    lea  rdx, [r15+rbp*2]
    mov  rcx, r13
    mov  r8, [rsp+552]
    lea  r9, [rsp+360]
    call cog_encoder_attention_f32_advisory
    test eax, eax
    jnz  .restore
    mov  r10d, 176                ; attention output projection descriptor
    mov  r9, rsp
    call .projection_config
    mov  rdi, [rsp+552]
    mov  rsi, [rsp+176]
    mov  rdx, [rsp+192]
    mov  rcx, [rsp+560]
    lea  r8, [rsp+360]
    call cog_encoder_projection_f32_advisory
    test eax, eax
    jnz  .restore
    mov  [rsp+360], ebx
    mov  dword [rsp+364], 384
    mov  eax, [rsp+8]
    mov  [rsp+368], eax
    mov  dword [rsp+372], 0
    mov  [rsp+376], rbp
    mov  [rsp+384], rbp
    mov  qword [rsp+392], 1536
    mov  qword [rsp+400], 1536
    mov  [rsp+408], rbp
    mov  rax, [rsp+544]
    mov  [rsp+416], rax
    mov  [rsp+424], rbp
    mov  rdi, [rsp+560]
    mov  rsi, r12                ; original layer residual X
    mov  rdx, [rsp+216]
    mov  rcx, [rsp+232]
    mov  r8, [rsp+568]
    lea  r9, [rsp+360]
    call cog_encoder_residual_norm_f32_advisory
    test eax, eax
    jnz  .restore                 ; attention norm refusal
    mov  [rsp+360], ebx            ; FFN config152
    mov  dword [rsp+364], 384
    mov  eax, [rsp+248]
    mov  [rsp+368], eax
    mov  eax, [rsp+252]
    mov  [rsp+372], eax
    mov  eax, [rsp+256]
    mov  [rsp+376], eax
    mov  ax, [rsp+260]
    mov  [rsp+380], ax
    mov  word [rsp+382], 0
    mov  [rsp+384], rbp
    mov  [rsp+392], rbp
    xor  ecx, ecx
.ffn_model_snapshot:
    mov  rax, [rsp+rcx+264]
    mov  [rsp+rcx+400], rax
    add  ecx, 8
    cmp  ecx, 96
    jb   .ffn_model_snapshot
    mov  rax, [rsp+544]
    mov  [rsp+496], rax
    mov  rax, [rsp+536]
    mov  [rsp+504], rax
    mov  rdi, [rsp+568]           ; attention-normalized FFN input
    mov  rsi, r14
    lea  rdx, [rsp+360]
    call cog_encoder_feedforward_f32_advisory
.restore:
    ldmxcsr [rsp+512]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 600
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Build exact384->384 projection config at[R9+360]. R10 descriptor offset.
; Only RAX/flags clobbered. R9 fixed frame base; RBX=L,RBP=N.
.projection_config:
    mov  [r9+360], ebx
    mov  dword [r9+364], 384
    mov  dword [r9+368], 384
    mov  dword [r9+372], 0
    mov  eax, [r9+r10+32]
    mov  [r9+376], eax
    mov  dword [r9+380], 0
    mov  al, [r9+r10+36]
    mov  [r9+380], al
    mov  [r9+384], rbp
    mov  qword [r9+392], 147456
    mov  qword [r9+400], 1536
    mov  [r9+408], rbp
    mov  rax, [r9+544]
    mov  [r9+416], rax
    mov  eax, ebx
    imul rax, 1920
    mov  [r9+424], rax
    ret

; Every immutable span against mutable[R10,R11), R9 fixed frame base.
; RAX,RDI,RSI,RCX/flags clobbered; preserved geometry/nonvolatile state.
.check_sources:
    mov  rdi, r12
    mov  rsi, rbp
    call .range_ok
    jnz  .sources_bad
    mov  rdi, r13
    mov  rsi, rbx
    call .range_ok
    jnz  .sources_bad
    mov  ecx, 56
.projection_ranges:
    mov  rdi, [r9+rcx]
    mov  rsi, [r9+rcx+8]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+rcx+16]
    mov  rsi, [r9+rcx+24]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 40
    cmp  ecx, 216
    jb   .projection_ranges
    mov  ecx, 216
.affine_ranges:
    mov  rdi, [r9+rcx]
    mov  rsi, [r9+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 248
    jb   .affine_ranges
    mov  ecx, 264
.ffn_ranges:
    mov  rdi, [r9+rcx]
    mov  rsi, [r9+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 360
    jb   .ffn_ranges
    mov  rdi, [r9+576]
    mov  esi, 360
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
