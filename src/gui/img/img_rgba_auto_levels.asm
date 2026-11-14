;; MODULE gui/img/img_rgba_auto_levels
;; LAYER 6
;; EXPORTS img_rgba_auto_levels
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_auto_levels(RDI=request72) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2),
; RDX=required destination span/0. Immutable request: src:u64@0, src_len:u64@8,
; dst:u64@16, dst_cap:u64@24, width:u32@32, height:u32@36,
; src_stride:u64@40, dst_stride:u64@48, scratch:u64@56, scratch_cap:u64@64.
; Top-down straight RGBA8888. Build a 256-bin opacity-weighted histogram of
; Y=(77R+150G+29B+128)>>8. Each pixel contributes its alpha (0..255).
; With total weight T>0, black/white are the first luminances whose cumulative
; weights reach ceil(T/100) / ceil(99*T/100). If black<white, each RGB channel
; becomes clamp(floor((channel-black)*255/(white-black))). Alpha is unchanged;
; alpha-zero pixels retain their hidden RGB. No visible weight or equal endpoints
; gives an exact identity copy. Explicit integer sRGB levels, no model or ICC.
; Dimensions 1..4096, area<=4194304, strides>=width*4. Required source/dst spans
; exclude final-row padding. Success span includes unwritten between-row padding.
; Scratch requires 1024 bytes, cleared on success; excess capacity is untouched.
; All three complete declared spans must be pairwise disjoint. Both writable
; spans must also be disjoint from request72. Caller maps/owns all declared spans
; throughout the call. All validation precedes writes; refusal changes nothing.
; Two image passes, O(area+256); maximum weight4194304*255=1069547520 fits u32.
; No allocation, I/O, retained pointers, global state, FP or SIMD. Preserve
; full RBX/RBP/R12-R15 and flags including DF. The original remains intact.

img_rgba_auto_levels:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,32
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
    mov  [rsp],rax                    ; return span
    mov  [rsp+8],rbx                  ; source stride
    mov  [rsp+16],rbp                 ; destination stride
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
    mov  r10,[r11+56]
    test r10,r10
    jz   .bounds
    mov  rcx,[r11+64]
    cmp  rcx,1024
    jb   .bounds
    mov  rax,r10
    add  rax,rcx
    jc   .bounds
    cmp  r12,rax
    jae  .scratch_source_disjoint
    lea  rdx,[r12+r8]
    cmp  r10,rdx
    jb   .bounds
.scratch_source_disjoint:
    cmp  r13,rax
    jae  .scratch_dest_disjoint
    lea  rdx,[r13+r9]
    cmp  r10,rdx
    jb   .bounds
.scratch_dest_disjoint:
    cmp  r11,rax
    jae  .scratch_request_disjoint
    lea  rdx,[r11+72]
    cmp  r10,rdx
    jb   .bounds
.scratch_request_disjoint:
    ; Complete validation precedes histogram or destination writes.
    mov  ebp,r15d                    ; height
    mov  r15d,r14d                   ; width
    mov  r14,r10                     ; histogram pointer
    cld
    mov  rdi,r14
    mov  ecx,256
    xor  eax,eax
    rep  stosd
    xor  r8d,r8d                     ; total opacity weight
    mov  r9d,ebp
    mov  rsi,r12
.hist_row:
    mov  ecx,r15d
.hist_pixel:
    movzx r11d,byte [rsi+3]
    movzx eax,byte [rsi]
    imul eax,77
    movzx edx,byte [rsi+1]
    imul edx,150
    add  eax,edx
    movzx edx,byte [rsi+2]
    imul edx,29
    add  eax,edx
    add  eax,128
    shr  eax,8
    add  [r14+rax*4],r11d
    add  r8d,r11d
    add  rsi,4
    dec  ecx
    jnz  .hist_pixel
    dec  r9d
    jz   .hist_done
    lea  rax,[r15*4]
    add  rsi,rbx
    sub  rsi,rax
    jmp  .hist_row
.hist_done:
    test r8d,r8d
    jz   .identity
    mov  eax,r8d
    add  rax,99
    xor  edx,edx
    mov  ecx,100
    div  rcx
    mov  r9d,eax                     ; ceil(T/100)
    mov  eax,r8d
    imul rax,99
    add  rax,99
    xor  edx,edx
    div  rcx
    mov  r10d,eax                    ; ceil(99*T/100)
    xor  ecx,ecx                     ; luminance bucket
    xor  r8d,r8d                     ; cumulative opacity weight
.find_black:
    add  r8d,[r14+rcx*4]
    cmp  r8d,r9d
    jae  .black_found
    inc  ecx
    jmp  .find_black
.black_found:
    mov  [rsp+24],ecx
    cmp  r8d,r10d
    jae  .white_found
.find_white:
    inc  ecx
    add  r8d,[r14+rcx*4]
    cmp  r8d,r10d
    jb   .find_white
.white_found:
    mov  [rsp+28],ecx
    mov  r11d,[rsp+24]
    mov  r10d,ecx
    sub  r10d,r11d
    jz   .identity
    mov  rsi,r12
    mov  rdi,r13
    mov  r9d,ebp
.row:
    mov  r8d,r15d
.pixel:
    cmp  byte [rsi+3],0
    je   .copy_pixel
    xor  ecx,ecx
.channel:
    movzx eax,byte [rsi+rcx]
    sub  eax,r11d
    jbe  .black
    cmp  eax,r10d
    jae  .white
    imul eax,255
    xor  edx,edx
    div  r10d
    jmp  .write
.black:
    xor  eax,eax
    jmp  .write
.white:
    mov  eax,255
.write:
    mov  [rdi+rcx],al
    inc  ecx
    cmp  ecx,3
    jb   .channel
    mov  al,[rsi+3]
    mov  [rdi+3],al
    jmp  .advance
.copy_pixel:
    mov  eax,[rsi]
    mov  [rdi],eax
.advance:
    add  rsi,4
    add  rdi,4
    dec  r8d
    jnz  .pixel
    dec  r9d
    jz   .clear
    lea  rax,[r15*4]
    add  rsi,[rsp+8]
    sub  rsi,rax
    add  rdi,[rsp+16]
    sub  rdi,rax
    jmp  .row
.identity:
    mov  rsi,r12
    mov  rdi,r13
    mov  r9d,ebp
.copy_row:
    mov  ecx,r15d
    rep  movsd
    dec  r9d
    jz   .clear
    lea  rax,[r15*4]
    add  rsi,[rsp+8]
    sub  rsi,rax
    add  rdi,[rsp+16]
    sub  rdi,rax
    jmp  .copy_row
.clear:
    mov  rdi,r14
    mov  ecx,256
    xor  eax,eax
    rep  stosd
    xor  eax,eax
    mov  rdx,[rsp]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
