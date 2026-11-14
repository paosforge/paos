;; MODULE gui/img/img_rgba_straighten
;; LAYER 6
;; EXPORTS img_rgba_straighten
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Creator: rc-ai-claude running on OpenAI Codex.
; img_rgba_straighten(RDI=request64) -> EAX=0/IMG_E_BOUNDS(2), RDX=span/0.
; Immutable little-endian request: src:u64@0, src_len:u64@8, dst:u64@16,
; dst_cap:u64@24, width:u32@32, height:u32@36, src_stride:u64@40,
; dst_stride:u64@48, angle:i32@56 (tenths of clockwise degree, -150..150),
; reserved:u32@60=0. Top-down straight-alpha RGBA8888, fixed-size canvas.
; Dimensions 1..4096, area<=4194304, strides>=width*4. Required spans omit
; final-row padding. Success RDX includes inter-row padding, which is unwritten.
; Full declared source/destination spans must not wrap or overlap. Destination
; must not overlap request64. All validation precedes writes; refusal leaves
; buffers/request untouched. Caller maps all spans for the whole call.
;
; Zero angle copies exactly, including hidden RGB. Other angles inverse-map
; destination pixel centers about ((w-1)/2,(h-1)/2), using the nearest Q16
; sin/cos table below. Source coordinates floor to Q16 (arithmetic shift /2).
; Bilinear weights are exact Q32 products; out-of-image samples are transparent.
; A=round(sum(weight*a)/2^32); RGB=round(sum(weight*a*c)/sum(weight*a)).
; Rounding is half up; output A=0 implies RGB=0. This avoids hidden-color halos.
; Interpolation is in encoded sRGB bytes, not a linear-light color transform.
; Sum(alpha)<=255*2^32, sum(color)<=65025*2^32, all in u64. O(width*height),
; no allocation, scratch, IO, retained state, FP/SIMD or source modification.
; Preserves RBX/RBP/R12-R15 and flags including DF. Not JPEG lossless rotation.

img_rgba_straighten:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 176
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 64
    jc   .bounds
    mov  rbp, rdi
    mov  r12, [rdi]
    mov  r8, [rdi + 8]
    mov  r13, [rdi + 16]
    mov  r9, [rdi + 24]
    mov  r14d, [rdi + 32]
    mov  r15d, [rdi + 36]
    mov  rax, [rdi + 40]
    mov  [rsp], rax
    mov  rax, [rdi + 48]
    mov  [rsp + 8], rax
    movsxd rax, dword [rdi + 56]
    cmp  rax, -150
    jl   .bounds
    cmp  rax, 150
    jg   .bounds
    mov  [rsp + 24], rax
    cmp  dword [rdi + 60], 0
    jne  .bounds
    test r12, r12
    jz   .bounds
    test r13, r13
    jz   .bounds
    test r14d, r14d
    jz   .bounds
    test r15d, r15d
    jz   .bounds
    cmp  r14d, 4096
    ja   .bounds
    cmp  r15d, 4096
    ja   .bounds
    mov  rax, r14
    imul rax, r15
    cmp  rax, 4194304
    ja   .bounds
    mov  rax, r12
    add  rax, r8
    jc   .bounds
    mov  rax, r13
    add  rax, r9
    jc   .bounds
    lea  r10, [r14 * 4]
    cmp  [rsp], r10
    jb   .bounds
    cmp  [rsp + 8], r10
    jb   .bounds
    mov  rax, r15
    dec  rax
    mul  qword [rsp]
    test rdx, rdx
    jnz  .bounds
    add  rax, r10
    jc   .bounds
    cmp  r8, rax
    jb   .bounds
    mov  rax, r15
    dec  rax
    mul  qword [rsp + 8]
    test rdx, rdx
    jnz  .bounds
    add  rax, r10
    jc   .bounds
    cmp  r9, rax
    jb   .bounds
    mov  [rsp + 16], rax
    lea  rax, [r12 + r8]
    cmp  r13, rax
    jae  .source_disjoint
    lea  rax, [r13 + r9]
    cmp  r12, rax
    jb   .bounds
.source_disjoint:
    lea  rax, [rbp + 64]
    cmp  r13, rax
    jae  .descriptor_disjoint
    lea  rax, [r13 + r9]
    cmp  rbp, rax
    jb   .bounds
.descriptor_disjoint:
    mov  rax, [rsp + 24]
    test eax, eax
    jnz  .rotate
    cld
    mov  rsi, r12
    mov  rdi, r13
    mov  r10d, r15d
.copy_row:
    mov  ecx, r14d
    rep  movsd
    dec  r10d
    jz   .ok
    lea  rax, [r14 * 4]
    add  rsi, [rsp]
    sub  rsi, rax
    add  rdi, [rsp + 8]
    sub  rdi, rax
    jmp  .copy_row
.rotate:
    mov  rcx, rax
    neg  rax
    test rcx, rcx
    cmovns rax, rcx
    lea  rdx, [rel img_straighten_trig]
    mov  ebx, [rdx + rax * 8]
    mov  [rsp + 32], rbx                  ; cosine, always positive
    mov  ebx, [rdx + rax * 8 + 4]
    test rcx, rcx
    jns  .positive
    neg  rbx
.positive:
    mov  [rsp + 40], rbx                  ; signed sine
    mov  qword [rsp + 56], 0             ; destination y
.row:
    mov  rax, [rsp + 56]
    imul rax, [rsp + 8]
    add  rax, r13
    mov  [rsp + 160], rax
    mov  qword [rsp + 48], 0             ; destination x
.pixel:
    mov  r8, [rsp + 48]
    add  r8, r8
    sub  r8, r14
    inc  r8                              ; centered doubled dx
    mov  r9, [rsp + 56]
    add  r9, r9
    sub  r9, r15
    inc  r9                              ; centered doubled dy
    mov  rax, r8
    imul rax, [rsp + 32]
    mov  rcx, r9
    imul rcx, [rsp + 40]
    add  rax, rcx
    lea  rcx, [r14 - 1]
    shl  rcx, 16
    add  rax, rcx
    sar  rax, 1                          ; source x in signed Q16
    movzx ecx, ax
    mov  [rsp + 80], rcx
    sar  rax, 16
    mov  [rsp + 64], rax
    mov  rax, r9
    imul rax, [rsp + 32]
    imul r8, [rsp + 40]
    sub  rax, r8
    lea  rcx, [r15 - 1]
    shl  rcx, 16
    add  rax, rcx
    sar  rax, 1                          ; source y in signed Q16
    movzx ecx, ax
    mov  [rsp + 88], rcx
    sar  rax, 16
    mov  [rsp + 72], rax
    mov  qword [rsp + 96], 0             ; alpha and three premultiplied sums
    mov  qword [rsp + 104], 0
    mov  qword [rsp + 112], 0
    mov  qword [rsp + 120], 0
    mov  qword [rsp + 136], 0
.sample_row:
    mov  rax, [rsp + 88]
    cmp  qword [rsp + 136], 0
    jne  .wy
    neg  rax
    add  rax, 65536
.wy:
    mov  [rsp + 128], rax
    mov  qword [rsp + 144], 0
.sample:
    mov  r8, [rsp + 80]
    cmp  qword [rsp + 144], 0
    jne  .wx
    neg  r8
    add  r8, 65536
.wx:
    imul r8, [rsp + 128]
    mov  rdi, [rsp + 64]
    add  rdi, [rsp + 144]
    mov  rsi, [rsp + 72]
    add  rsi, [rsp + 136]
    call .accumulate
    inc  qword [rsp + 144]
    cmp  qword [rsp + 144], 2
    jb   .sample
    inc  qword [rsp + 136]
    cmp  qword [rsp + 136], 2
    jb   .sample_row
    mov  rax, [rsp + 96]
    mov  edx, 0x80000000
    add  rax, rdx
    shr  rax, 32
    xor  ebx, ebx
    test eax, eax
    jz   .store
    mov  ebx, eax
    shl  ebx, 24
    mov  r8, [rsp + 96]
    shr  r8, 1
    mov  rax, [rsp + 104]
    add  rax, r8
    xor  edx, edx
    div  qword [rsp + 96]
    or   ebx, eax
    mov  rax, [rsp + 112]
    add  rax, r8
    xor  edx, edx
    div  qword [rsp + 96]
    shl  eax, 8
    or   ebx, eax
    mov  rax, [rsp + 120]
    add  rax, r8
    xor  edx, edx
    div  qword [rsp + 96]
    shl  eax, 16
    or   ebx, eax
.store:
    mov  rdi, [rsp + 160]
    mov  rcx, [rsp + 48]
    mov  [rdi + rcx * 4], ebx
    inc  qword [rsp + 48]
    cmp  [rsp + 48], r14
    jb   .pixel
    inc  qword [rsp + 56]
    cmp  [rsp + 56], r15
    jb   .row
.ok:
    xor  eax, eax
    mov  rdx, [rsp + 16]
    jmp  .out
.bounds:
    mov  eax, 2
    xor  edx, edx
.out:
    add  rsp, 176
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret

; RDI/RSI signed source x/y, R8 Q32 weight. Stack +8 is the caller frame.
.accumulate:
    cmp  rdi, r14
    jae  .sample_out
    cmp  rsi, r15
    jae  .sample_out
    test r8, r8
    jz   .sample_out
    imul rsi, [rsp + 8]
    lea  rsi, [rsi + rdi * 4]
    mov  ecx, [r12 + rsi]
    mov  eax, ecx
    shr  eax, 24
    imul r8, rax
    add  [rsp + 104], r8
    movzx eax, cl
    imul rax, r8
    add  [rsp + 112], rax
    movzx eax, ch
    imul rax, r8
    add  [rsp + 120], rax
    shr  ecx, 16
    movzx eax, cl
    imul rax, r8
    add  [rsp + 128], rax
.sample_out:
    ret

; (cos, sin) for 0..150 tenths of a degree: floor(trig(a*pi/1800)*65536+0.5).
; Generated constants, independently checked by the host floating-point oracle.
align 4
img_straighten_trig:
    dd 65536, 0 ; 0/10 degree
    dd 65536, 114 ; 1/10 degree
    dd 65536, 229 ; 2/10 degree
    dd 65535, 343 ; 3/10 degree
    dd 65534, 458 ; 4/10 degree
    dd 65534, 572 ; 5/10 degree
    dd 65532, 686 ; 6/10 degree
    dd 65531, 801 ; 7/10 degree
    dd 65530, 915 ; 8/10 degree
    dd 65528, 1029 ; 9/10 degree
    dd 65526, 1144 ; 10/10 degree
    dd 65524, 1258 ; 11/10 degree
    dd 65522, 1372 ; 12/10 degree
    dd 65519, 1487 ; 13/10 degree
    dd 65516, 1601 ; 14/10 degree
    dd 65514, 1716 ; 15/10 degree
    dd 65510, 1830 ; 16/10 degree
    dd 65507, 1944 ; 17/10 degree
    dd 65504, 2059 ; 18/10 degree
    dd 65500, 2173 ; 19/10 degree
    dd 65496, 2287 ; 20/10 degree
    dd 65492, 2401 ; 21/10 degree
    dd 65488, 2516 ; 22/10 degree
    dd 65483, 2630 ; 23/10 degree
    dd 65479, 2744 ; 24/10 degree
    dd 65474, 2859 ; 25/10 degree
    dd 65469, 2973 ; 26/10 degree
    dd 65463, 3087 ; 27/10 degree
    dd 65458, 3201 ; 28/10 degree
    dd 65452, 3316 ; 29/10 degree
    dd 65446, 3430 ; 30/10 degree
    dd 65440, 3544 ; 31/10 degree
    dd 65434, 3658 ; 32/10 degree
    dd 65427, 3773 ; 33/10 degree
    dd 65421, 3887 ; 34/10 degree
    dd 65414, 4001 ; 35/10 degree
    dd 65407, 4115 ; 36/10 degree
    dd 65399, 4229 ; 37/10 degree
    dd 65392, 4343 ; 38/10 degree
    dd 65384, 4457 ; 39/10 degree
    dd 65376, 4572 ; 40/10 degree
    dd 65368, 4686 ; 41/10 degree
    dd 65360, 4800 ; 42/10 degree
    dd 65352, 4914 ; 43/10 degree
    dd 65343, 5028 ; 44/10 degree
    dd 65334, 5142 ; 45/10 degree
    dd 65325, 5256 ; 46/10 degree
    dd 65316, 5370 ; 47/10 degree
    dd 65306, 5484 ; 48/10 degree
    dd 65296, 5598 ; 49/10 degree
    dd 65287, 5712 ; 50/10 degree
    dd 65277, 5826 ; 51/10 degree
    dd 65266, 5940 ; 52/10 degree
    dd 65256, 6054 ; 53/10 degree
    dd 65245, 6167 ; 54/10 degree
    dd 65234, 6281 ; 55/10 degree
    dd 65223, 6395 ; 56/10 degree
    dd 65212, 6509 ; 57/10 degree
    dd 65201, 6623 ; 58/10 degree
    dd 65189, 6737 ; 59/10 degree
    dd 65177, 6850 ; 60/10 degree
    dd 65165, 6964 ; 61/10 degree
    dd 65153, 7078 ; 62/10 degree
    dd 65140, 7192 ; 63/10 degree
    dd 65128, 7305 ; 64/10 degree
    dd 65115, 7419 ; 65/10 degree
    dd 65102, 7533 ; 66/10 degree
    dd 65088, 7646 ; 67/10 degree
    dd 65075, 7760 ; 68/10 degree
    dd 65061, 7873 ; 69/10 degree
    dd 65048, 7987 ; 70/10 degree
    dd 65033, 8100 ; 71/10 degree
    dd 65019, 8214 ; 72/10 degree
    dd 65005, 8327 ; 73/10 degree
    dd 64990, 8441 ; 74/10 degree
    dd 64975, 8554 ; 75/10 degree
    dd 64960, 8668 ; 76/10 degree
    dd 64945, 8781 ; 77/10 degree
    dd 64930, 8894 ; 78/10 degree
    dd 64914, 9008 ; 79/10 degree
    dd 64898, 9121 ; 80/10 degree
    dd 64882, 9234 ; 81/10 degree
    dd 64866, 9347 ; 82/10 degree
    dd 64850, 9461 ; 83/10 degree
    dd 64833, 9574 ; 84/10 degree
    dd 64816, 9687 ; 85/10 degree
    dd 64799, 9800 ; 86/10 degree
    dd 64782, 9913 ; 87/10 degree
    dd 64765, 10026 ; 88/10 degree
    dd 64747, 10139 ; 89/10 degree
    dd 64729, 10252 ; 90/10 degree
    dd 64711, 10365 ; 91/10 degree
    dd 64693, 10478 ; 92/10 degree
    dd 64675, 10591 ; 93/10 degree
    dd 64656, 10704 ; 94/10 degree
    dd 64637, 10817 ; 95/10 degree
    dd 64618, 10929 ; 96/10 degree
    dd 64599, 11042 ; 97/10 degree
    dd 64580, 11155 ; 98/10 degree
    dd 64560, 11268 ; 99/10 degree
    dd 64540, 11380 ; 100/10 degree
    dd 64520, 11493 ; 101/10 degree
    dd 64500, 11605 ; 102/10 degree
    dd 64480, 11718 ; 103/10 degree
    dd 64459, 11831 ; 104/10 degree
    dd 64439, 11943 ; 105/10 degree
    dd 64418, 12055 ; 106/10 degree
    dd 64397, 12168 ; 107/10 degree
    dd 64375, 12280 ; 108/10 degree
    dd 64354, 12393 ; 109/10 degree
    dd 64332, 12505 ; 110/10 degree
    dd 64310, 12617 ; 111/10 degree
    dd 64288, 12729 ; 112/10 degree
    dd 64266, 12842 ; 113/10 degree
    dd 64243, 12954 ; 114/10 degree
    dd 64220, 13066 ; 115/10 degree
    dd 64197, 13178 ; 116/10 degree
    dd 64174, 13290 ; 117/10 degree
    dd 64151, 13402 ; 118/10 degree
    dd 64128, 13514 ; 119/10 degree
    dd 64104, 13626 ; 120/10 degree
    dd 64080, 13738 ; 121/10 degree
    dd 64056, 13849 ; 122/10 degree
    dd 64032, 13961 ; 123/10 degree
    dd 64007, 14073 ; 124/10 degree
    dd 63983, 14185 ; 125/10 degree
    dd 63958, 14296 ; 126/10 degree
    dd 63933, 14408 ; 127/10 degree
    dd 63907, 14519 ; 128/10 degree
    dd 63882, 14631 ; 129/10 degree
    dd 63856, 14742 ; 130/10 degree
    dd 63830, 14854 ; 131/10 degree
    dd 63804, 14965 ; 132/10 degree
    dd 63778, 15077 ; 133/10 degree
    dd 63752, 15188 ; 134/10 degree
    dd 63725, 15299 ; 135/10 degree
    dd 63698, 15410 ; 136/10 degree
    dd 63671, 15521 ; 137/10 degree
    dd 63644, 15633 ; 138/10 degree
    dd 63617, 15744 ; 139/10 degree
    dd 63589, 15855 ; 140/10 degree
    dd 63562, 15966 ; 141/10 degree
    dd 63534, 16076 ; 142/10 degree
    dd 63505, 16187 ; 143/10 degree
    dd 63477, 16298 ; 144/10 degree
    dd 63449, 16409 ; 145/10 degree
    dd 63420, 16520 ; 146/10 degree
    dd 63391, 16630 ; 147/10 degree
    dd 63362, 16741 ; 148/10 degree
    dd 63332, 16851 ; 149/10 degree
    dd 63303, 16962 ; 150/10 degree
