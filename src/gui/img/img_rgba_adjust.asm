;; MODULE gui/img/img_rgba_adjust
;; LAYER 6
;; EXPORTS img_rgba_adjust
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_adjust(RDI=request72) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=span/0.
; Immutable little-endian request: src:u64@0, src_len:u64@8, dst:u64@16,
; dst_cap:u64@24, width:u32@32, height:u32@36, src_stride:u64@40,
; dst_stride:u64@48, brightness:i32@56, contrast:i32@60,
; saturation:i32@64, warmth:i32@68. Top-down straight RGBA8888; alpha unchanged.
; Brightness/warmth -255..255; contrast/saturation -256..256; all zero = identity.
; For RGB channel c: t=clamp(128+floor((c-128)*(256+contrast)/256)+brightness).
; luma=floor((77*tR+150*tG+29*tB+128)/256).
; o=luma+floor((t-luma)*(256+saturation)/256), then add warmth to R,
; subtract warmth from B and clamp to 0..255. G gets no warmth offset.
; This deterministic integer sRGB adjustment is not an ICC/linear-light transform.
; Dimensions 1..4096, area <=4194304; strides >=width*4. Required spans
; exclude padding after the final row. Success span includes between-row padding;
; padding is unwritten. Complete declared source/destination spans must be
; disjoint; destination must not overlap request72. Caller supplies mapped spans.
; All validation precedes writes; refusal changes neither buffer nor request.
; No allocation, retained pointer, I/O, FP or SIMD. RBX/RBP/R12-R15 and all
; flags (including DF) preserved. No metadata copied; original remains intact.

img_rgba_adjust:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,48
    test rdi,rdi
    jz   .bounds
    mov  rax,rdi
    add  rax,72
    jc   .bounds
    mov  r11,rdi
    mov  r12,[rdi]
    mov  r8,[rdi+8]
    mov  r13,[rdi+16]
    mov  r9,[rdi+24]
    mov  r14d,[rdi+32]
    mov  r15d,[rdi+36]
    mov  rbx,[rdi+40]
    mov  rbp,[rdi+48]
    test r12,r12
    jz   .bounds
    test r13,r13
    jz   .bounds
    test r14d,r14d
    jz   .bounds
    test r15d,r15d
    jz   .bounds
    cmp  r14d,4096
    ja   .bounds
    cmp  r15d,4096
    ja   .bounds
    mov  rax,r14
    imul rax,r15
    cmp  rax,4194304
    ja   .bounds
    mov  rax,r12
    add  rax,r8
    jc   .bounds
    mov  rax,r13
    add  rax,r9
    jc   .bounds
    lea  r10,[r14*4]
    cmp  rbx,r10
    jb   .bounds
    cmp  rbp,r10
    jb   .bounds
    mov  rax,r15
    dec  rax
    mul  rbx
    test rdx,rdx
    jnz  .bounds
    add  rax,r10
    jc   .bounds
    cmp  r8,rax
    jb   .bounds
    mov  rax,r15
    dec  rax
    mul  rbp
    test rdx,rdx
    jnz  .bounds
    add  rax,r10
    jc   .bounds
    cmp  r9,rax
    jb   .bounds
    mov  [rsp+16],rax
    lea  rax,[r12+r8]
    cmp  r13,rax
    jae  .source_disjoint
    lea  rax,[r13+r9]
    cmp  r12,rax
    jb   .bounds
.source_disjoint:
    lea  rax,[r11+72]
    cmp  r13,rax
    jae  .descriptor_disjoint
    lea  rax,[r13+r9]
    cmp  r11,rax
    jb   .bounds
.descriptor_disjoint:
    mov  eax,[r11+56]
    cmp  eax,-255
    jl   .bounds
    cmp  eax,255
    jg   .bounds
    mov  [rsp+24],eax
    mov  eax,[r11+60]
    cmp  eax,-256
    jl   .bounds
    cmp  eax,256
    jg   .bounds
    add  eax,256
    mov  [rsp+28],eax
    mov  eax,[r11+64]
    cmp  eax,-256
    jl   .bounds
    cmp  eax,256
    jg   .bounds
    add  eax,256
    mov  [rsp+32],eax
    mov  eax,[r11+68]
    cmp  eax,-255
    jl   .bounds
    cmp  eax,255
    jg   .bounds
    mov  [rsp+36],eax
    mov  r10d,255
.row:
    mov  rsi,r12
    mov  rdi,r13
    mov  r8d,r14d
.pixel:
    xor  ecx,ecx
.contrast:
    movzx eax,byte [rsi+rcx]
    sub  eax,128
    imul eax,[rsp+28]
    sar  eax,8
    add  eax,128
    add  eax,[rsp+24]
    xor  edx,edx
    test eax,eax
    cmovs eax,edx
    cmp  eax,r10d
    cmovg eax,r10d
    mov  [rsp+rcx+40],al
    inc  ecx
    cmp  ecx,3
    jb   .contrast
    movzx r9d,byte [rsp+40]
    imul r9d,77
    movzx eax,byte [rsp+41]
    imul eax,150
    add  r9d,eax
    movzx eax,byte [rsp+42]
    imul eax,29
    add  r9d,eax
    add  r9d,128
    shr  r9d,8
    xor  ecx,ecx
.saturation:
    movzx eax,byte [rsp+rcx+40]
    sub  eax,r9d
    imul eax,[rsp+32]
    sar  eax,8
    add  eax,r9d
    test ecx,ecx
    jnz  .blue
    add  eax,[rsp+36]
    jmp  .clamp
.blue:
    cmp  ecx,2
    jne  .clamp
    sub  eax,[rsp+36]
.clamp:
    xor  edx,edx
    test eax,eax
    cmovs eax,edx
    cmp  eax,r10d
    cmovg eax,r10d
    mov  [rdi+rcx],al
    inc  ecx
    cmp  ecx,3
    jb   .saturation
    mov  al,[rsi+3]
    mov  [rdi+3],al
    add  rsi,4
    add  rdi,4
    dec  r8d
    jnz  .pixel
    dec  r15d
    jz   .ok
    add  r12,rbx
    add  r13,rbp
    jmp  .row
.ok:
    xor  eax,eax
    mov  rdx,[rsp+16]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
