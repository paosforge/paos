;; MODULE gui/img/img_rgba_brush
;; LAYER 6
;; EXPORTS img_rgba_brush
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_brush(RDI=request88) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2),RDX=span/0.
; Immutable LE request: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; width:u32@32,height:u32@36,src_stride:u64@40,dst_stride:u64@48,
; x0/y0/x1/y1:u32@56/60/64/68,radius:u32@72,color:RGBA8888-u32@76,
; mode:u32@80,reserved:u32@84=0. Mapped caller-owned straight RGBA8888.
; Dimensions1..4096,area<=4194304,strides>=width*4; both endpoints within
; canvas,radius1..4096. Required spans exclude final-row padding. Complete
; declared spans nonwrapping/disjoint; destination disjoint from request88.
; Readonly source/request alias permitted. All validation before any write.
;
; Copies all canvas pixels, then changes pixels whose integer centres have
; Euclidean distance <=radius from the closed endpoint segment (round caps).
; The finite canvas clips coverage. Degenerate segment is a filled disk.
; No antialiasing, fractional coordinates, off-canvas endpoints or Bresenham
; claim. Reversed endpoints have identical coverage. Radius1 gives3px diameter.
; Original, outside-stroke pixels,destination padding/slack unchanged.
; Mode0 exact RGBA replacement incl invisible RGB. Mode1 encoded-sRGB straight
; alpha source-over: I=255-Sa,D=255*Sa+Da*I,Ao=round(D/255),
; Co=round((255*Sc*Sa+Dc*Da*I)/D),half-up. Sa0 exact identity,Sa255 replace.
; Mode2 alpha-only erase: Ao=round(Da*I/255),RGB retained incl invisible RGB.
;
; Integer bounds: abs(dx/dy/vx/vy)<=4095,L=dx^2+dy^2<=33538050,
; abs(cross)<=33538050,cross^2<2^50,radius^2*L<2^49; signed64 ample.
; D<=65025,channel numerator<=16581375 fits32; Sa0 skips division.
; O(area),no scratch/allocation/state/I/O/FP/SIMD; full64 nonvolatiles and
; incoming flags/DF restored. Pure backend; no UI/save/file authority added.

img_rgba_brush:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,144
    test rdi,rdi
    jz   .bounds
    mov  rax,rdi
    add  rax,88
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
    lea  rax,[r11+88]
    cmp  r13,rax
    jae  .descriptor_disjoint
    lea  rax,[r13+r9]
    cmp  r11,rax
    jb   .bounds
.descriptor_disjoint:
    mov  eax,[r11+56]
    cmp  eax,r14d
    jae  .bounds
    mov  [rsp+56],rax
    mov  eax,[r11+60]
    cmp  eax,r15d
    jae  .bounds
    mov  [rsp+64],rax
    mov  eax,[r11+64]
    cmp  eax,r14d
    jae  .bounds
    sub  rax,[rsp+56]
    mov  [rsp+72],rax
    imul rax,rax
    mov  rcx,rax
    mov  eax,[r11+68]
    cmp  eax,r15d
    jae  .bounds
    sub  rax,[rsp+64]
    mov  [rsp+80],rax
    imul rax,rax
    add  rcx,rax
    mov  [rsp+88],rcx
    mov  eax,[r11+72]
    test eax,eax
    jz   .bounds
    cmp  eax,4096
    ja   .bounds
    imul rax,rax
    mov  [rsp+96],rax
    imul rax,rcx
    mov  [rsp+104],rax
    mov  eax,[r11+76]
    mov  [rsp+24],eax
    shr  eax,24
    mov  [rsp+32],eax
    mov  ecx,255
    sub  ecx,eax
    mov  [rsp+36],ecx
    mov  eax,[r11+80]
    cmp  eax,2
    ja   .bounds
    mov  [rsp+28],eax
    cmp  dword [r11+84],0
    jne  .bounds
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
    xor  r9d,r9d
    mov  r10d,255
.stroke_row:
    xor  r8d,r8d
.stroke_pixel:
    mov  rax,r8
    sub  rax,[rsp+56]
    mov  rdx,r9
    sub  rdx,[rsp+64]
    mov  rcx,rax
    imul rcx,[rsp+72]
    mov  rsi,rdx
    imul rsi,[rsp+80]
    add  rcx,rsi
    test rcx,rcx
    jle  .endpoint_distance
    cmp  rcx,[rsp+88]
    jge  .second_endpoint
    imul rax,[rsp+80]
    imul rdx,[rsp+72]
    sub  rax,rdx
    imul rax,rax
    cmp  rax,[rsp+104]
    ja   .next_pixel
    jmp  .covered
.second_endpoint:
    sub  rax,[rsp+72]
    sub  rdx,[rsp+80]
.endpoint_distance:
    imul rax,rax
    imul rdx,rdx
    add  rax,rdx
    cmp  rax,[rsp+96]
    ja   .next_pixel
.covered:
    lea  rdi,[r13+r8*4]
    cmp  dword [rsp+28],0
    je   .replace
    cmp  dword [rsp+32],0
    je   .next_pixel
    cmp  dword [rsp+28],2
    je   .erase
    cmp  dword [rsp+32],255
    je   .replace
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
    jmp  .next_pixel
.erase:
    movzx eax,byte [rdi+3]
    imul eax,[rsp+36]
    add  eax,127
    xor  edx,edx
    div  r10d
    mov  [rdi+3],al
    jmp  .next_pixel
.replace:
    mov  eax,[rsp+24]
    mov  [rdi],eax
.next_pixel:
    inc  r8d
    cmp  r8d,r14d
    jb   .stroke_pixel
    inc  r9d
    cmp  r9d,r15d
    jae  .ok
    add  r13,rbp
    jmp  .stroke_row
.ok:
    xor  eax,eax
    mov  rdx,[rsp+16]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,144
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
