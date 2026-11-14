;; MODULE gui/img/img_rgba_paint
;; LAYER 6
;; EXPORTS img_rgba_paint
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_paint(RDI=request80) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=span/0.
; Immutable LE request: src:u64@0,src_len:u64@8,dst:u64@16,dst_cap:u64@24,
; width:u32@32,height:u32@36,src_stride:u64@40,dst_stride:u64@48,
; rect_x:u32@56,rect_y:u32@60,rect_w:u32@64,rect_h:u32@68,
; color:RGBA8888-u32@72,mode:u32@76. Mapped caller-owned straight RGBA8888.
; Dimensions1..4096,area<=4194304,strides>=width*4; rectangle positive and
; contained. Required spans exclude final-row padding. Entire declared src/dst
; spans nonwrapping and disjoint, destination disjoint from request80.
; Read-only source/request alias allowed. All validation before writes;
; refusal leaves everything unchanged. Copies all pixels, then paints rectangle.
; Original, outside-rectangle pixels, destination padding/slack untouched.
;
; Mode0 replace: exact color RGBA, including invisible RGB.
; Mode1 source-over: Sa=color alpha,Da=original alpha,I=255-Sa;
; D=255*Sa+Da*I; output alpha=round(D/255),
; output channel=round((255*Sc*Sa+Dc*Da*I)/D). All rounding half-up.
; Sa0 is exact identity including hidden RGB; Sa255 exact replacement.
; Max D65025, channel numerator16581375, fits32 bits. Encoded sRGB math,
; no ICC/linear-light claim. Mode2 erase: RGB unchanged including hidden RGB;
; output alpha=round(Da*I/255). Sa0 identity,Sa255 fully transparent.
;
; O(area), no scratch/allocation, retained state, I/O, FP or SIMD.
; Full64 RBX/RBP/R12-R15 and flags/DF preserved. Pure editor backend;
; no UI/file authority or history/save workflow added.

img_rgba_paint:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,80
    test rdi,rdi
    jz   .bounds
    mov  rax,rdi
    add  rax,80
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
    lea  rax,[r11+80]
    cmp  r13,rax
    jae  .descriptor_disjoint
    lea  rax,[r13+r9]
    cmp  r11,rax
    jb   .bounds
.descriptor_disjoint:
    mov  eax,[r11+56]
    mov  [rsp],eax
    mov  ecx,[r11+64]
    test ecx,ecx
    jz   .bounds
    mov  [rsp+8],ecx
    add  rax,rcx
    cmp  rax,r14
    ja   .bounds
    mov  eax,[r11+60]
    mov  [rsp+4],eax
    mov  ecx,[r11+68]
    test ecx,ecx
    jz   .bounds
    mov  [rsp+12],ecx
    add  rax,rcx
    cmp  rax,r15
    ja   .bounds
    mov  eax,[r11+72]
    mov  [rsp+24],eax
    shr  eax,24
    mov  [rsp+32],eax
    mov  ecx,255
    sub  ecx,eax
    mov  [rsp+36],ecx
    mov  eax,[r11+76]
    cmp  eax,2
    ja   .bounds
    mov  [rsp+28],eax
    cld
    mov  r8,r12
    mov  r9,r13
    mov  r10d,r15d
.copy_row:
    mov  rsi,r8
    mov  rdi,r9
    mov  ecx,r14d
    rep  movsd
    dec  r10d
    jz   .copied
    add  r8,rbx
    add  r9,rbp
    jmp  .copy_row
.copied:
    mov  eax,[rsp+4]
    imul rax,rbp
    add  r13,rax
    mov  eax,[rsp]
    lea  r13,[r13+rax*4]
    mov  r9d,[rsp+12]
    cmp  dword [rsp+28],0
    je   .replace_row
    cmp  dword [rsp+32],0
    je   .ok
    mov  r10d,255
    cmp  dword [rsp+28],2
    je   .erase_row
    cmp  dword [rsp+32],255
    je   .replace_row
.blend_row:
    mov  rdi,r13
    mov  r8d,[rsp+8]
.blend_pixel:
    movzx eax,byte [rdi+3]
    imul eax,[rsp+36]
    mov  [rsp+40],eax
    mov  edx,[rsp+32]
    imul edx,255
    add  eax,edx
    mov  [rsp+44],eax
    mov  edx,eax
    shr  edx,1
    mov  [rsp+52],edx
    add  eax,127
    xor  edx,edx
    div  r10d
    mov  [rsp+48],eax
    xor  ecx,ecx
.blend_channel:
    movzx eax,byte [rsp+rcx+24]
    imul eax,[rsp+32]
    imul eax,255
    movzx edx,byte [rdi+rcx]
    imul edx,[rsp+40]
    add  eax,edx
    add  eax,[rsp+52]
    xor  edx,edx
    div  dword [rsp+44]
    mov  [rdi+rcx],al
    inc  ecx
    cmp  ecx,3
    jb   .blend_channel
    mov  eax,[rsp+48]
    mov  [rdi+3],al
    add  rdi,4
    dec  r8d
    jnz  .blend_pixel
    dec  r9d
    jz   .ok
    add  r13,rbp
    jmp  .blend_row
.erase_row:
    mov  rdi,r13
    mov  r8d,[rsp+8]
.erase_pixel:
    movzx eax,byte [rdi+3]
    imul eax,[rsp+36]
    add  eax,127
    xor  edx,edx
    div  r10d
    mov  [rdi+3],al
    add  rdi,4
    dec  r8d
    jnz  .erase_pixel
    dec  r9d
    jz   .ok
    add  r13,rbp
    jmp  .erase_row
.replace_row:
    mov  rdi,r13
    mov  ecx,[rsp+8]
    mov  eax,[rsp+24]
    rep  stosd
    dec  r9d
    jz   .ok
    add  r13,rbp
    jmp  .replace_row
.ok:
    xor  eax,eax
    mov  rdx,[rsp+16]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
