;; MODULE cognition/encoder_pack
;; LAYER 6
;; EXPORTS cog_encoder_pack_models_advisory, cog_encoder_packed_ascii_cls_f32_advisory
;; IMPORTS cog_encoder_ascii_cls_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Native structural PMW1/BLP1 decoder and coherent packed ASCII->CLS consumer.
; Trace: classifier4850 native_bge_host.py and build_bge_{matmul_pack,layer_parameters}.
; CALLER authenticates the complete PMW/BLP pair, PEM/PVT and source-model identity
; and owns immutable mapped lifetimes. No manifest/digest authentication, model
; loading/I/O, authority grant or quality/calibration claim occurs here.
;
; Builder SysV RDI=PMW,RSI=BLP,RDX=outModels[3744],RCX=config32:
; u64 PMWbytes21234832,BLPbytes243376,outbytes3744,reserved0. Config/output8-
; aligned, packs4-aligned, all nonnull/full64 nonwrapping. Output disjoint packs/
; original config; read-only packs may alias. Header snapshotted. EAX0/1; entire
; output unchanged on any refusal. No numeric scratch/allocation/FP instructions.
; PMW header(PMW1,72,1168,21233664),72 entries<IHHII> contiguous/nonoverlapping
; in table order, exact size and one of384x384/384x1536/1536x384, reserved0.
; BLP header(BLP1,12,3088,20024); embedding gamma/beta at16/1552; records contain
; six indices, six f32 weight scales, two f32 LN epsilons, then six bias and four
; affine vectors. Indices are a bijection0..71 and shape-correct per projection
; role. Scales[1e-20,1000], eps positive finite, biases finite abs<=65536,
; all embedding/layer affine values finite. Quantized weight zero point is0 as
; pinned exporter proves; no silent alternate point or transposition.
; Output12 compact312 descriptors in layer order matches encoder_stack exactly.
; Descriptors borrow pack pointers: packs must outlive every synchronous use.
; Full caller FP/DF/nonvolatile GPR/RSP preserved; stack<256bytes.

cog_encoder_pack_models_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 104
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
    test r14b, 7
    jnz  .invalid
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 32
    jc   .invalid
    mov  [rsp+40], r15
    xor  ecx, ecx
.snapshot:
    mov  rax, [r15+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 4
    jb   .snapshot
    cmp  qword [rsp], 21234832
    jne  .invalid
    cmp  qword [rsp+8], 243376
    jne  .invalid
    cmp  qword [rsp+16], 3744
    jne  .invalid
    cmp  qword [rsp+24], 0
    jne  .invalid
    mov  r10, r14
    lea  r11, [r14+3744]
    cmp  r11, r14
    jb   .invalid
    mov  rdi, r12
    mov  esi, 21234832
    call .range_ok
    jnz  .invalid
    mov  rdi, r13
    mov  esi, 243376
    call .range_ok
    jnz  .invalid
    mov  rdi, r15
    mov  esi, 32
    call .range_ok
    jnz  .invalid
    cmp  dword [r12], 'PMW1'
    jne  .invalid
    cmp  dword [r12+4], 72
    jne  .invalid
    cmp  dword [r12+8], 1168
    jne  .invalid
    cmp  dword [r12+12], 21233664
    jne  .invalid
    cmp  dword [r13], 'BLP1'
    jne  .invalid
    cmp  dword [r13+4], 12
    jne  .invalid
    cmp  dword [r13+8], 3088
    jne  .invalid
    cmp  dword [r13+12], 20024
    jne  .invalid
    xor  ecx, ecx
    xor  r8d, r8d
.matrix_entries:
    mov  edi, ecx
    shl  edi, 4
    lea  rdi, [r12+rdi+16]
    cmp  [rdi], r8d               ; canonical contiguous packed weight offsets
    jne  .invalid
    cmp  dword [rdi+12], 0
    jne  .invalid
    mov  eax, [rdi+4]
    mov  edx, 147456
    cmp  eax, 0x01800180
    je   .entry_size
    mov  edx, 589824
    cmp  eax, 0x06000180
    je   .entry_size
    cmp  eax, 0x01800600
    jne  .invalid
.entry_size:
    cmp  [rdi+8], edx
    jne  .invalid
    add  r8d, edx
    cmp  r8d, 21233664
    ja   .invalid
    inc  ecx
    cmp  ecx, 72
    jb   .matrix_entries
    cmp  r8d, 21233664
    jne  .invalid
    xor  ecx, ecx
.embedding_affine:
    mov  eax, [r13+rcx*4+16]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    inc  ecx
    cmp  ecx, 768
    jb   .embedding_affine
    mov  qword [rsp+80], 0
    mov  qword [rsp+88], 0
    xor  ebx, ebx
.record_preflight:
    imul r15, rbx, 20024
    lea  r15, [r13+r15+3088]
    xor  ecx, ecx
.indices_scales:
    mov  edx, [r15+rcx*4]
    cmp  edx, 72
    jae  .invalid
    bts  qword [rsp+80], rdx      ;72-bit global bijection, two metadata qwords
    jc   .invalid
    mov  edi, edx
    shl  edi, 4
    lea  rdi, [r12+rdi+16]
    mov  eax, 0x01800180
    cmp  ecx, 4
    jb   .role_shape
    mov  eax, 0x06000180
    je   .role_shape
    mov  eax, 0x01800600
.role_shape:
    cmp  [rdi+4], eax
    jne  .invalid
    mov  eax, [r15+rcx*4+24]
    cmp  eax, 0x1e3ce508          ; f32(1e-20), accepted weight-scale domain
    jb   .invalid
    cmp  eax, 0x447a0000          ;1000.0
    ja   .invalid
    inc  ecx
    cmp  ecx, 6
    jb   .indices_scales
    mov  eax, [r15+48]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [r15+52]
    test eax, eax
    jle  .invalid
    cmp  eax, 0x7f800000
    jae  .invalid
    xor  ecx, ecx
.bias_domain:
    mov  eax, [r15+rcx*4+56]
    and  eax, 0x7fffffff
    cmp  eax, 0x47800000          ; finite abs<=65536, accepted dequant bias
    ja   .invalid
    inc  ecx
    cmp  ecx, 3456
    jb   .bias_domain
    xor  ecx, ecx
.layer_affine:
    mov  eax, [r15+rcx*4+13880]
    and  eax, 0x7f800000
    cmp  eax, 0x7f800000
    je   .invalid
    inc  ecx
    cmp  ecx, 1536
    jb   .layer_affine
    inc  ebx
    cmp  ebx, 12
    jb   .record_preflight
    xor  ebx, ebx
.record_build:
    imul r15, rbx, 20024
    lea  r15, [r13+r15+3088]
    mov  eax, [r15+48]
    mov  [r14], eax
    mov  dword [r14+4], 0
    xor  ecx, ecx
.projection_build:
    mov  edi, [r15+rcx*4]
    call .matrix_pointer
    imul r10, rcx, 40
    lea  r10, [r14+r10+8]
    mov  [r10], rax
    mov  [r10+8], rdx
    imul rdi, rcx, 1536
    lea  rdi, [r15+rdi+56]
    mov  [r10+16], rdi
    mov  qword [r10+24], 1536
    mov  eax, [r15+rcx*4+24]
    mov  [r10+32], eax
    mov  dword [r10+36], 0        ; zero point0 and all reserved bytes0
    inc  ecx
    cmp  ecx, 4
    jb   .projection_build
    lea  rax, [r15+13880]
    mov  [r14+168], rax
    mov  qword [r14+176], 1536
    lea  rax, [r15+15416]
    mov  [r14+184], rax
    mov  qword [r14+192], 1536
    mov  eax, [r15+52]
    mov  [r14+200], eax
    mov  eax, [r15+40]
    mov  [r14+204], eax
    mov  eax, [r15+44]
    mov  [r14+208], eax
    mov  dword [r14+212], 0
    mov  edi, [r15+16]
    call .matrix_pointer
    mov  [r14+216], rax
    mov  [r14+224], rdx
    lea  rax, [r15+6200]
    mov  [r14+232], rax
    mov  qword [r14+240], 6144
    mov  edi, [r15+20]
    call .matrix_pointer
    mov  [r14+248], rax
    mov  [r14+256], rdx
    lea  rax, [r15+12344]
    mov  [r14+264], rax
    mov  qword [r14+272], 1536
    lea  rax, [r15+16952]
    mov  [r14+280], rax
    mov  qword [r14+288], 1536
    lea  rax, [r15+18488]
    mov  [r14+296], rax
    mov  qword [r14+304], 1536
    add  r14, 312
    inc  ebx
    cmp  ebx, 12
    jb   .record_build
    xor  eax, eax
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 104
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Validated matrix indexEDI -> borrowed weight pointerRAX, exact bytesRDX.
; Only RAX/RDX/RDI clobbered; shape/layout/offset preflight already completed.
.matrix_pointer:
    shl  edi, 4
    lea  rdi, [r12+rdi+16]
    mov  edx, [rdi+8]
    mov  eax, [rdi]
    lea  rax, [r12+rax+1168]
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

; Packed consumer SysV RDI=text,RSI=CLS,RDX=config96(8-aligned), all u64:
; text_bytes,PVTptr,PVTbytes,PEMptr,PEMbytes,PMWptr,PMWbytes,BLPptr,BLPbytes,
; CLSbytes1536,workspace_ptr,workspace_bytes48767136. Text0..4096/PVT20..8MiB,
; other exact extents above. Packs/PEM4-aligned, workspace8-aligned, CLS4-aligned.
; Workspace3744 model descriptors +48763392 accepted ASCII arena. Entire mutable
; arena/final protected against whole caller packs/text/PVT/originalconfig before
; builder writes. Invalid builder leaves all scratch unchanged; later refusal may
; retain descriptors/stages. EVERY refusal leaves final CLS unchanged. All12 layers
; run natively on successful parse/tokenization. Full caller FP/DF/ABI preserved;
; nested stack<4608bytes. Stable authenticated pack pair is caller responsibility.
cog_encoder_packed_ascii_cls_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 232                 ; header96, child120, originalconfig8
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
    add  rax, 96
    jc   .invalid
    mov  [rsp+216], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 12
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
    cmp  qword [rsp+72], 1536
    jne  .invalid
    cmp  qword [rsp+88], 48767136
    jne  .invalid
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
    mov  r14, [rsp+40]
    mov  r15, [rsp+56]
    mov  rbx, [rsp+80]
    test rbx, rbx
    jz   .invalid
    test bl, 7
    jnz  .invalid
    mov  r9, rsp
    mov  r10, r13
    mov  r11, r13
    add  r11, 1536
    jc   .invalid
    call .check_sources           ; final preserves entire immutable packs
    jnz  .invalid
    mov  rdi, rbx
    mov  esi, 48767136
    call .range_ok
    jnz  .invalid
    mov  r10, rbx
    mov  r11, rbx
    add  r11, 48767136
    jc   .invalid
    call .check_sources           ; descriptor writes preserve every pack/source
    jnz  .invalid
    mov  qword [rsp+96], 21234832
    mov  qword [rsp+104], 243376
    mov  qword [rsp+112], 3744
    mov  qword [rsp+120], 0
    mov  rdi, r14
    mov  rsi, r15
    mov  rdx, rbx
    lea  rcx, [rsp+96]
    call cog_encoder_pack_models_advisory
    test eax, eax
    jnz  .out                     ; never consume failed/stale descriptors
    mov  rax, 0x0000000c00000200 ; max sequence512, all12 admitted layers
    mov  [rsp+96], rax
    mov  rax, [rsp]
    mov  [rsp+104], rax
    mov  rax, [rsp+8]
    mov  [rsp+112], rax
    mov  rax, [rsp+16]
    mov  [rsp+120], rax
    mov  qword [rsp+128], 1536
    mov  rax, [rsp+24]
    mov  [rsp+136], rax
    mov  rax, [rsp+32]
    mov  [rsp+144], rax
    lea  rax, [r15+16]
    mov  [rsp+152], rax           ; authenticated BLP embedding gamma
    mov  qword [rsp+160], 1536
    lea  rax, [r15+1552]
    mov  [rsp+168], rax           ; authenticated BLP embedding beta
    mov  qword [rsp+176], 1536
    mov  [rsp+184], rbx
    mov  qword [rsp+192], 3744
    lea  rax, [rbx+3744]
    mov  [rsp+200], rax
    mov  qword [rsp+208], 48763392
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rsp+96]
    call cog_encoder_ascii_cls_f32_advisory
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 232
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
    mov  rdi, [r9+216]
    mov  esi, 96
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
