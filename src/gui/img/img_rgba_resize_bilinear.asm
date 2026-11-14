;; MODULE gui/img/img_rgba_resize_bilinear
;; LAYER 6
;; EXPORTS img_rgba_resize_bilinear
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_rgba_resize_bilinear(RDI=immutable LE request64)->EAX=0/2,RDX=span/0.
; Same field layout as img_rgba_resize (point/cache entry remains unchanged):
; src:u64@0,len:u64@8,dst:u64@16,capacity:u64@24,src_w:u32@32,
; src_h:u32@36,dst_w:u32@40,dst_h:u32@44,src_stride:u64@48,dst_stride:u64@56.
; Top-down straight RGBA8888; both dimensions1..4096, both areas<=4194304.
; Strides>=width*4; checked (height-1)*stride+width*4 fits declared span.
; Full declared src/dst spans must be nonwrapping and disjoint. Destination
; cannot overlap request64; read-only source/request alias is allowed. Stable
; mapped caller-owned spans for complete call. All validation before writes.
;
; Each axis maps destination d to source pixel-center coordinate
; q=clamp(floor((2*d+1)*src*32768/dst)-32768,0,(src-1)*65536).
; Integer/fraction portions select edge-clamped neighbors and 16-bit weights.
; Four unsigned64 weights sum2^32. A=sum(weight*alpha); RGB numerator is
; sum(weight*alpha*channel). If A=0 output RGBA=0 (hidden RGB canonicalized).
; Otherwise RGB=round-half-up(numerator/A),alpha=round-half-up(A/2^32).
; Interpolates encoded sRGB integers; no ICC/linear light or area anti-aliasing.
; Alpha weighting prevents invisible source colors from creating edge fringes.
; No transparent identity-byte promise: use existing point resize when needed.
;
; Success writes pixels only, preserving source/request and rowpadding/slack.
; Refusal2/0 writes nothing. No allocations, retained pointers, global state,
; IO, FP/SIMD, cache/default/UI policy or authority. O(destination area),
; initialized/wiped144B frame+56B saves; private accumulator adds8B return.
; Full64 RBX/RBP/R12-R15 and incoming flags/DF/FP preserved.

img_rgba_resize_bilinear:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,144
    cld
    mov  r11,rdi
    mov  rdi,rsp
    xor  eax,eax
    mov  ecx,18
    rep  stosq
    test r11,r11
    jz   .bounds
    mov  rax,r11
    add  rax,64
    jc   .bounds
    mov  r12,[r11]
    mov  r8,[r11+8]
    mov  r13,[r11+16]
    mov  r9,[r11+24]
    mov  r14d,[r11+32]
    mov  r15d,[r11+36]
    mov  ebx,[r11+40]
    mov  ebp,[r11+44]
    mov  rax,[r11+48]
    mov  [rsp],rax
    mov  rax,[r11+56]
    mov  [rsp+8],rax
    test r12,r12
    jz   .bounds
    test r13,r13
    jz   .bounds
    test r14d,r14d
    jz   .bounds
    test r15d,r15d
    jz   .bounds
    test ebx,ebx
    jz   .bounds
    test ebp,ebp
    jz   .bounds
    cmp  r14d,4096
    ja   .bounds
    cmp  r15d,4096
    ja   .bounds
    cmp  ebx,4096
    ja   .bounds
    cmp  ebp,4096
    ja   .bounds
    mov  rax,r14
    imul rax,r15
    cmp  rax,4194304
    ja   .bounds
    mov  rax,rbx
    imul rax,rbp
    cmp  rax,4194304
    ja   .bounds
    mov  rax,r12
    add  rax,r8
    jc   .bounds
    mov  rax,r13
    add  rax,r9
    jc   .bounds
    lea  r10,[r14*4]
    cmp  [rsp],r10
    jb   .bounds
    mov  rax,r15
    dec  rax
    mul  qword [rsp]
    test rdx,rdx
    jnz  .bounds
    add  rax,r10
    jc   .bounds
    cmp  r8,rax
    jb   .bounds
    lea  r10,[rbx*4]
    cmp  [rsp+8],r10
    jb   .bounds
    mov  rax,rbp
    dec  rax
    mul  qword [rsp+8]
    test rdx,rdx
    jnz  .bounds
    add  rax,r10
    jc   .bounds
    cmp  r9,rax
    jb   .bounds
    mov  [rsp+16],rax
    lea  rax,[r12+r8]
    cmp  r13,rax
    jae  .source_clear
    lea  rax,[r13+r9]
    cmp  r12,rax
    jb   .bounds
.source_clear:
    lea  rax,[r11+64]
    cmp  r13,rax
    jae  .request_clear
    lea  rax,[r13+r9]
    cmp  r11,rax
    jb   .bounds
.request_clear:
    ; y=0,x=0 already initialized. Coordinate numerators <=2^40.
.row:
    mov  rax,[rsp+40]
    lea  rax,[rax*2+1]
    imul rax,r15
    shl  rax,15
    xor  edx,edx
    div  rbp
    sub  rax,32768
    jns  .y_nonnegative
    xor  eax,eax
.y_nonnegative:
    lea  r8,[r15-1]
    shl  r8,16
    cmp  rax,r8
    cmova rax,r8
    movzx r8d,ax
    mov  [rsp+64],r8
    shr  rax,16
    lea  rdx,[rax+1]
    cmp  rdx,r15
    cmovae rdx,rax
    imul rax,[rsp]
    add  rax,r12
    mov  [rsp+48],rax
    imul rdx,[rsp]
    add  rdx,r12
    mov  [rsp+56],rdx
    mov  qword [rsp+32],0
.pixel:
    mov  rax,[rsp+32]
    lea  rax,[rax*2+1]
    imul rax,r14
    shl  rax,15
    xor  edx,edx
    div  rbx
    sub  rax,32768
    jns  .x_nonnegative
    xor  eax,eax
.x_nonnegative:
    lea  r8,[r14-1]
    shl  r8,16
    cmp  rax,r8
    cmova rax,r8
    movzx r9d,ax                    ; fx
    shr  rax,16
    lea  r11,[rax+1]
    cmp  r11,r14
    cmovae r11,rax
    lea  r10,[rax*4]                ; left byte offset
    shl  r11,2                      ; right byte offset
    mov  r8d,65536
    sub  r8,r9                      ; 1-fx
    mov  ecx,65536
    sub  rcx,[rsp+64]               ; 1-fy
    mov  rax,r8
    imul rax,rcx
    mov  [rsp+72],rax               ; w00 (can be exactly2^32)
    imul rcx,r9
    mov  [rsp+80],rcx               ; w10
    imul r8,[rsp+64]
    mov  [rsp+88],r8                ; w01
    imul r9,[rsp+64]
    mov  [rsp+96],r9                ; w11
    mov  qword [rsp+104],0          ; weighted alpha
    mov  qword [rsp+112],0          ; weighted red*alpha
    mov  qword [rsp+120],0          ; weighted green*alpha
    mov  qword [rsp+128],0          ; weighted blue*alpha
    mov  rdi,[rsp+48]
    mov  rsi,[rsp+56]
    mov  eax,[rdi+r10]
    mov  rcx,[rsp+72]
    call .accumulate
    mov  eax,[rdi+r11]
    mov  rcx,[rsp+80]
    call .accumulate
    mov  eax,[rsi+r10]
    mov  rcx,[rsp+88]
    call .accumulate
    mov  eax,[rsi+r11]
    mov  rcx,[rsp+96]
    call .accumulate
    mov  rcx,[rsp+104]
    test rcx,rcx
    jz   .transparent
    mov  r8,rcx
    shr  r8,1                      ; half divisor for half-up rounding
    mov  rax,[rsp+112]
    add  rax,r8
    xor  edx,edx
    div  rcx
    mov  [rsp+136],eax
    mov  rax,[rsp+120]
    add  rax,r8
    xor  edx,edx
    div  rcx
    shl  eax,8
    or   [rsp+136],eax
    mov  rax,[rsp+128]
    add  rax,r8
    xor  edx,edx
    div  rcx
    shl  eax,16
    or   [rsp+136],eax
    mov  rax,rcx
    mov  r8d,0x80000000
    add  rax,r8
    shr  rax,32
    shl  eax,24
    or   eax,[rsp+136]
    jmp  .write
.transparent:
    xor  eax,eax
.write:
    mov  rcx,[rsp+32]
    mov  [r13+rcx*4],eax
    inc  qword [rsp+32]
    cmp  [rsp+32],rbx
    jb   .pixel
    inc  qword [rsp+40]
    cmp  [rsp+40],rbp
    jae  .ok
    add  r13,[rsp+8]                ; never advance unused last-row stride
    jmp  .row
.ok:
    xor  eax,eax
    mov  rdx,[rsp+16]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    mov  r8d,eax
    mov  r9,rdx
    mov  rdi,rsp
    xor  eax,eax
    mov  ecx,18
    rep  stosq
    mov  eax,r8d
    mov  rdx,r9
    add  rsp,144
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret

; Private accumulator: EAX=RGBA,RCX=unsigned64 weight. Caller frame offsets
; include this call's8B return address. Only RAX,RCX,R8,R9 and flags clobbered.
; Max alpha sum255*2^32, RGB-alpha sum65025*2^32, safely below2^48.
.accumulate:
    mov  r9d,eax
    mov  r8d,eax
    shr  r8d,24
    imul r8,rcx
    add  [rsp+112],r8
    movzx eax,r9b
    imul rax,r8
    add  [rsp+120],rax
    mov  eax,r9d
    shr  eax,8
    and  eax,255
    imul rax,r8
    add  [rsp+128],rax
    mov  eax,r9d
    shr  eax,16
    and  eax,255
    imul rax,r8
    add  [rsp+136],rax
    ret
