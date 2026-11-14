;; MODULE gui/img/img_rgba_text
;; LAYER 6
;; EXPORTS img_rgba_text
;; IMPORTS font_8x16
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_text(RDI=request96) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2),RDX=span/0.
; Immutable LE request: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; width:u32@32,height:u32@36,src_stride:u64@40,dst_stride:u64@48,
; text:u64@56,count:u32@64,scale:u32@68,x:u32@72,y:u32@76,
; color:RGBA8888-u32@80,mode:u32@84,reserved:u64@88=0.
; Caller owns/maps and keeps request, source and UTF32LE text stable throughout.
; Count1..512,scale1..32. Single line, existing Spleen font_8x16 cells scaled
; by nearest-neighbour integer replication; MSB left,8x16. Only U+0020..007E
; and U+00A0..017F accepted: unsupported/control scalar refuses before copy,
; never truncates or silently substitutes. This is partial Latin coverage;
; full language/shaping/layout and UI annotation are separate work.
;
; Dimensions1..4096,area<=4194304,strides>=width*4. Entire text cell box
; count*8*scale by16*scale must fit at unsigned x/y. Source/destination full
; declared spans nonwrapping/disjoint; destination disjoint request96 and
; required text count*4 bytes. Readonly source/request/text may alias.
; Required image spans exclude final-row padding. Every check before writes.
; Copies image pixel rows then paints set glyph bits. Original/read-only
; spans, blank cells/unset bits,outside pixels and destination padding/slack
; untouched. Invalid returns2/0 without changing any caller memory.
;
; Mode0 replaces exact color RGBA including hidden RGB. Mode1 source-over:
; Sa=color alpha,Da=original alpha,I=255-Sa,D=255*Sa+Da*I;
; Ao=round(D/255),Co=round((255*Sc*Sa+Dc*Da*I)/D),half-up.
; Sa0 exact identity including hidden RGB;Sa255 exact replacement.
; MaxD65025,maxchannelnumerator16581375. Encoded sRGB,no linear-light claim.
; O(area+textpixels),bounded112B stack,no scratch/alloc/state/I/O/FP/SIMD.
; Full64 RBX/RBP/R12-R15 and incoming flags/DF restored on every exit.

img_rgba_text:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,112
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
    cmp  qword [r11+88],0
    jne  .bounds
    mov  eax,[r11+84]
    cmp  eax,1
    ja   .bounds
    mov  [rsp+28],eax
    mov  eax,[r11+80]
    mov  [rsp+24],eax
    shr  eax,24
    mov  [rsp+32],eax
    mov  ecx,255
    sub  ecx,eax
    mov  [rsp+36],ecx
    mov  eax,[r11+64]
    test eax,eax
    jz   .bounds
    cmp  eax,512
    ja   .bounds
    mov  [rsp+8],eax
    mov  ecx,[r11+68]
    test ecx,ecx
    jz   .bounds
    cmp  ecx,32
    ja   .bounds
    mov  [rsp+12],ecx
    imul eax,ecx
    shl  eax,3
    mov  [rsp+64],eax
    mov  edx,[r11+72]
    mov  [rsp],edx
    add  rax,rdx
    cmp  rax,r14
    ja   .bounds
    shl  ecx,4
    mov  eax,[r11+76]
    mov  [rsp+4],eax
    add  rax,rcx
    cmp  rax,r15
    ja   .bounds
    mov  rsi,[r11+56]
    test rsi,rsi
    jz   .bounds
    mov  [rsp+56],rsi
    mov  ecx,[rsp+8]
    lea  rax,[rsi+rcx*4]
    cmp  rax,rsi
    jb   .bounds
    cmp  r13,rax
    jae  .text_disjoint
    lea  rax,[r13+r9]
    cmp  rsi,rax
    jb   .bounds
.text_disjoint:
    ; Validate the complete run, including its tail, before copying any pixel.
.validate_scalar:
    mov  eax,[rsi]
    add  rsi,4
    cmp  eax,0x20
    jb   .bounds
    cmp  eax,0x7e
    jbe  .scalar_ok
    cmp  eax,0xa0
    jb   .bounds
    cmp  eax,0x17f
    ja   .bounds
.scalar_ok:
    dec  ecx
    jnz  .validate_scalar
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
    cmp  dword [rsp+28],0
    je   .draw
    cmp  dword [rsp+32],0
    je   .ok
.draw:
    mov  eax,[rsp+4]
    imul rax,rbp
    add  r13,rax
    mov  eax,[rsp]
    lea  r13,[r13+rax*4]
    mov  dword [rsp+72],0
.glyph:
    mov  rsi,[rsp+56]
    mov  eax,[rsp+72]
    mov  eax,[rsi+rax*4]
    shl  eax,4
    lea  r12,[rel font_8x16]
    add  r12,rax
    xor  r14d,r14d
    mov  rsi,r13
.glyph_row:
    mov  r15d,[rsp+12]
.scaled_row:
    movzx ebx,byte [r12+r14]
    mov  rdi,rsi
    mov  r8d,8
.column:
    mov  r9d,[rsp+12]
    test ebx,0x80
    jz   .skip_column
.scaled_pixel:
    cmp  dword [rsp+28],0
    je   .replace
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
    mov  ecx,255
    div  ecx
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
    jmp  .pixel_done
.replace:
    mov  eax,[rsp+24]
    mov  [rdi],eax
.pixel_done:
    add  rdi,4
    dec  r9d
    jnz  .scaled_pixel
    jmp  .column_done
.skip_column:
    lea  rdi,[rdi+r9*4]
.column_done:
    shl  ebx,1
    dec  r8d
    jnz  .column
    add  rsi,rbp
    dec  r15d
    jnz  .scaled_row
    inc  r14d
    cmp  r14d,16
    jb   .glyph_row
    mov  eax,[rsp+12]
    shl  eax,5
    add  r13,rax
    inc  dword [rsp+72]
    mov  eax,[rsp+72]
    cmp  eax,[rsp+8]
    jb   .glyph
.ok:
    xor  eax,eax
    mov  rdx,[rsp+16]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,112
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
