;; MODULE gui/img/img_rgba_arrow
;; LAYER 6
;; EXPORTS img_rgba_arrow
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_arrow(RDI=request96) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2),RDX=span/0.
; Immutable LE request: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; width:u32@32,height:u32@36,src_stride:u64@40,dst_stride:u64@48,
; tail_x/y,tip_x/y:u32@56/60/64/68,shaft_halfwidth:u32@72,
; head_length:u32@76,head_halfwidth:u32@80,color:RGBA8888-u32@84,
; mode:u32@88(0replace,1sourceover),reserved:u32@92=0.
; Caller owns/maps and keeps request/source stable throughout.
; Dimensions1..4096,area<=4194304,strides>=width*4; distinct endpoints
; within canvas. All widths/length1..4096,head_halfwidth>=shaft_halfwidth,
; head_length<=Euclidean segment length. Finite canvas clips arrow coverage.
; Full declared src/dst spans nonwrapping/disjoint,dst disjoint request96;
; readonly request/src alias allowed. Required row spans omit final padding.
; All validation before writes. Copies image pixels then paints covered ones;
; originals,outside pixels,destination padding/slack unchanged. Refusal2/0
; changes no caller memory. No UI,history/save or authority added.
;
; Integer pixel centres,hard edges,inclusive boundaries. Arrow is union of
; butt-tail rectangular shaft (ends at head base) and isosceles triangular
; head (base width2*head_halfwidth,length head_length,apex at tip).
; For d=tip-tail,L=d.d,t=(p-tail).d,c=cross(p-tail,d),s=L-t:
; require0<=t<=L. Shaft:s^2>=head_length^2*L,c^2<=shaft_halfwidth^2*L.
; Head:s^2<=head_length^2*L,abs(c)*head_length<=head_halfwidth*s.
; At shared base head contains shaft; testing head on equality is equivalent.
; No sqrt or geometric rounding; arbitrary direction,clipped side edges.
;
; Mode0 exact RGBA replacement incl invisible RGB. Mode1 encoded-sRGB straight
; sourceover:Sa=color alpha,Da=original alpha,I=255-Sa,D=255Sa+DaI;
; Ao=halfup(D/255),Co=halfup((255ScSa+DcDaI)/D). Sa0 exact identity including
; hidden RGB;Sa255 exact replacement. D<=65025,numerator<=16581375.
; abs(dx/dy/vx/vy)<=4095,L<=33538050,abs(c)<=33538050; squares<2^50,
; squared-width/length*L<2^49,abs(c)*head_length and head_halfwidth*s<2^37.
; O(area),144B local stack,no scratch/alloc/state/I/O/FP/SIMD.
; Full64 RBX/RBP/R12-R15 and incoming flags/DF restored on every exit.

img_rgba_arrow:
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
    add  rax,96
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
    lea  rax,[r11+96]
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
    test rcx,rcx
    jz   .bounds
    mov  eax,[r11+72]
    test eax,eax
    jz   .bounds
    cmp  eax,4096
    ja   .bounds
    mov  [rsp+128],eax
    imul rax,rax
    imul rax,rcx
    mov  [rsp+96],rax
    mov  eax,[r11+76]
    test eax,eax
    jz   .bounds
    cmp  eax,4096
    ja   .bounds
    mov  [rsp+112],rax
    imul rax,rax
    cmp  rax,rcx
    ja   .bounds
    imul rax,rcx
    mov  [rsp+104],rax
    mov  eax,[r11+80]
    cmp  eax,[rsp+128]
    jb   .bounds
    cmp  eax,4096
    ja   .bounds
    mov  [rsp+120],rax
    mov  eax,[r11+84]
    mov  [rsp+24],eax
    shr  eax,24
    mov  [rsp+32],eax
    mov  ecx,255
    sub  ecx,eax
    mov  [rsp+36],ecx
    mov  eax,[r11+88]
    cmp  eax,1
    ja   .bounds
    mov  [rsp+28],eax
    cmp  dword [r11+92],0
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
.arrow_row:
    xor  r8d,r8d
.arrow_pixel:
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
    js   .next_pixel
    cmp  rcx,[rsp+88]
    ja   .next_pixel
    neg  rcx
    add  rcx,[rsp+88]
    imul rax,[rsp+80]
    imul rdx,[rsp+72]
    sub  rax,rdx
    mov  rsi,rcx
    imul rsi,rsi
    cmp  rsi,[rsp+104]
    jbe  .head
    imul rax,rax
    cmp  rax,[rsp+96]
    ja   .next_pixel
    jmp  .covered
.head:
    mov  rdx,rax
    neg  rdx
    cmovs rdx,rax
    imul rdx,[rsp+112]
    imul rcx,[rsp+120]
    cmp  rdx,rcx
    ja   .next_pixel
.covered:
    lea  rdi,[r13+r8*4]
    cmp  dword [rsp+28],0
    je   .replace
    cmp  dword [rsp+32],0
    je   .next_pixel
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
.replace:
    mov  eax,[rsp+24]
    mov  [rdi],eax
.next_pixel:
    inc  r8d
    cmp  r8d,r14d
    jb   .arrow_pixel
    inc  r9d
    cmp  r9d,r15d
    jae  .ok
    add  r13,rbp
    jmp  .arrow_row
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
