;; MODULE gui/img/img_rgba_shape
;; LAYER 6
;; EXPORTS img_rgba_shape
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_shape(RDI=request88) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2),RDX=span/0.
; Immutable LE request: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; width:u32@32,height:u32@36,src_stride:u64@40,dst_stride:u64@48,
; box_x/y/w/h:u32@56/60/64/68,color:RGBA8888-u32@72,shape:u32@76,
; inset:u32@80,reserved:u32@84=0. Shape0 rectangle,1ellipse. Inset0 fills;
; inset1..4096 outlines by subtracting concentric inset shape. If twice
; inset >=either box dimension, inner shape is empty, outer shape is filled.
; Mapped caller-owned straight RGBA8888. Exact RGBA replacement including
; invisible RGB; no alpha blending or antialiasing. Original retained.
;
; Dimensions1..4096,area<=4194304,strides>=width*4,positive contained box.
; Full declared spans nonwrapping/disjoint,destination disjoint request88;
; readonly source/request alias allowed. Every check before first write.
; Required spans exclude final-row padding. Copies canvas pixel rows, then
; replaces covered shape pixels; outside pixels/padding/slack unchanged.
;
; Ellipse: local pixel centres x/y,dx=2*x+1-box_w,dy=2*y+1-box_h;
; dx^2/box_w^2+dy^2/box_h^2<=1 (inclusive outer boundary). Inner ellipse
; same centre,axes box_w-2*inset/box_h-2*inset; its inclusive boundary is
; removed. Inset is along bounding-box axes, not uniform normal distance.
; Rectangle uses equivalent bounding-box subtraction. Single-pixel axes valid.
; Since box area<=4194304,box_w^2*box_h^2<=2^44; each weighted squared
; coordinate<2^44,sum<2^45. Inner shape never larger. All arithmetic64bit.
;
; O(area),bounded96B local stack,no scratch/allocation/state/I/O/FP/SIMD.
; Full64 RBX/RBP/R12-R15 and incoming flags/DF restored on every exit.
; Pure Paint backend; no UI,history/save or file authority added.

img_rgba_shape:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,96
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
    mov  eax,[r11+76]
    cmp  eax,1
    ja   .bounds
    mov  [rsp+28],eax
    mov  eax,[r11+80]
    cmp  eax,4096
    ja   .bounds
    mov  [rsp+32],eax
    cmp  dword [r11+84],0
    jne  .bounds
    mov  eax,[rsp+8]
    imul rax,rax
    mov  [rsp+40],rax
    mov  eax,[rsp+12]
    imul rax,rax
    mov  [rsp+48],rax
    imul rax,[rsp+40]
    mov  [rsp+56],rax
    mov  dword [rsp+88],0
    mov  ecx,[rsp+32]
    test ecx,ecx
    jz   .validated
    add  ecx,ecx
    mov  eax,[rsp+8]
    sub  eax,ecx
    jbe  .validated
    imul rax,rax
    mov  [rsp+64],rax
    mov  eax,[rsp+12]
    sub  eax,ecx
    jbe  .validated
    imul rax,rax
    mov  [rsp+72],rax
    imul rax,[rsp+64]
    mov  [rsp+80],rax
    mov  dword [rsp+88],1
.validated:
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
    xor  r9d,r9d
.shape_row:
    xor  r8d,r8d
.shape_pixel:
    cmp  dword [rsp+28],1
    je   .ellipse
    cmp  dword [rsp+88],0
    je   .paint
    cmp  r8d,[rsp+32]
    jb   .paint
    mov  eax,[rsp+8]
    sub  eax,[rsp+32]
    cmp  r8d,eax
    jae  .paint
    cmp  r9d,[rsp+32]
    jb   .paint
    mov  eax,[rsp+12]
    sub  eax,[rsp+32]
    cmp  r9d,eax
    jae  .paint
    jmp  .next_pixel
.ellipse:
    lea  rax,[r8*2+1]
    mov  ecx,[rsp+8]
    sub  rax,rcx
    imul rax,rax
    lea  rdx,[r9*2+1]
    mov  ecx,[rsp+12]
    sub  rdx,rcx
    imul rdx,rdx
    mov  rcx,rax
    imul rcx,[rsp+48]
    mov  rsi,rdx
    imul rsi,[rsp+40]
    add  rcx,rsi
    cmp  rcx,[rsp+56]
    ja   .next_pixel
    cmp  dword [rsp+88],0
    je   .paint
    imul rax,[rsp+72]
    imul rdx,[rsp+64]
    add  rax,rdx
    cmp  rax,[rsp+80]
    jbe  .next_pixel
.paint:
    mov  eax,[rsp+24]
    mov  [r13+r8*4],eax
.next_pixel:
    inc  r8d
    cmp  r8d,[rsp+8]
    jb   .shape_pixel
    inc  r9d
    cmp  r9d,[rsp+12]
    jae  .ok
    add  r13,rbp
    jmp  .shape_row
.ok:
    xor  eax,eax
    mov  rdx,[rsp+16]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,96
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
