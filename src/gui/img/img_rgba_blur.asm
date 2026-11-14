;; MODULE gui/img/img_rgba_blur
;; LAYER 6
;; EXPORTS img_rgba_blur
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_blur(RDI=request96) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=span/0.
; Immutable request: src:u64@0, src_len:u64@8, dst:u64@16, dst_cap:u64@24,
; width:u32@32, height:u32@36, src_stride:u64@40, dst_stride:u64@48,
; x:u32@56, y:u32@60, rect_w:u32@64, rect_h:u32@68, radius:u32@72,
; reserved:u32@76 (zero), scratch:u64@80, scratch_cap:u64@88.
; Top-down straight RGBA8888. The nonempty rectangle must fit the image.
; Radius 0..32; zero copies exactly. Otherwise each selected pixel gets
; floor(sum(channel*alpha)/sum(alpha)) over its square radius neighborhood,
; clipped to the selection. Zero sum(alpha) yields RGB zero. Alpha and pixels
; outside the rectangle stay unchanged. This is integer sRGB box filtering.
; Dimensions 1..4096, area <=4194304. Strides >=width*4. Required source/dst
; spans exclude final-row padding; success span includes between-row padding,
; which is unwritten. Scratch needs rect_w*16 bytes (<=65536), is cleared on
; success and has no retained pointers. Extra scratch capacity is untouched.
; All three complete declared spans must be disjoint; both writable spans must
; be disjoint from request96. All checks precede writes; refusals change nothing.
; Caller provides mapped memory for all declared spans throughout the call.
; Rolling column/window sums give O(image area) work, independent of radius.
; Max RGB accumulator 65*65*255*255=274730625 fits u32. No allocation, I/O,
; global state, FP or SIMD. RBX/RBP/R12-R15 and all flags including DF preserved.

img_rgba_blur:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp,64
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
    mov  [rsp],rax                    ; destination return span
    mov  [rsp+8],rbx                  ; source stride
    mov  [rsp+16],rbp                 ; destination stride
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
    mov  eax,[r11+64]
    test eax,eax
    jz   .bounds
    mov  edx,[r11+56]
    add  rax,rdx
    cmp  rax,r14
    ja   .bounds
    mov  eax,[r11+68]
    test eax,eax
    jz   .bounds
    mov  edx,[r11+60]
    add  rax,rdx
    cmp  rax,r15
    ja   .bounds
    cmp  dword [r11+72],32
    ja   .bounds
    cmp  dword [r11+76],0
    jne  .bounds
    mov  eax,[r11+72]
    mov  [rsp+24],rax                 ; radius
    mov  r10,[r11+80]                 ; scratch begin
    test r10,r10
    jz   .bounds
    mov  rcx,[r11+88]                 ; complete scratch length
    mov  eax,[r11+64]
    shl  rax,4
    cmp  rcx,rax
    jb   .bounds
    mov  [rsp+56],rax                 ; used scratch bytes
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
    lea  rdx,[r11+96]
    cmp  r10,rdx
    jb   .bounds
.scratch_request_disjoint:
    ; Validation is complete. Save rectangle state before the whole-image copy.
    mov  [rsp+32],r10                 ; scratch pointer
    mov  eax,[r11+60]
    imul rax,rbx
    mov  edx,[r11+56]
    lea  rax,[rax+rdx*4]
    add  rax,r12
    mov  [rsp+40],rax                 ; source rectangle origin
    mov  eax,[r11+60]
    imul rax,rbp
    lea  rax,[rax+rdx*4]
    add  rax,r13
    mov  [rsp+48],rax                 ; destination rectangle origin
    mov  rsi,r12
    mov  rdi,r13
    mov  r10d,r15d
    cld
.copy_row:
    mov  ecx,r14d
    rep  movsd
    dec  r10d
    jz   .copied
    lea  rax,[r14*4]
    add  rsi,rbx
    sub  rsi,rax
    add  rdi,rbp
    sub  rdi,rax
    jmp  .copy_row
.copied:
    mov  r14,[rsp+32]
    mov  rdi,r14
    mov  rcx,[rsp+56]
    shr  rcx,2
    xor  eax,eax
    rep  stosd
    cmp  qword [rsp+24],0
    je   .ok
    mov  r12,[rsp+40]
    mov  r13,[rsp+48]
    mov  r15d,[r11+64]
    mov  ebp,[r11+68]
    xor  ebx,ebx                     ; initial column accumulation row
.initial_columns:
    mov  rsi,r12
    mov  rax,rbx
    imul rax,[rsp+8]
    add  rsi,rax
    mov  edx,1
    call .columns_update
    inc  ebx
    cmp  ebx,ebp
    jae  .initialized
    cmp  rbx,[rsp+24]
    jbe  .initial_columns
.initialized:
    xor  ebx,ebx                     ; output rectangle y
.row:
    xor  r8d,r8d                     ; red*alpha window sum
    xor  r9d,r9d                     ; green*alpha window sum
    xor  r10d,r10d                   ; blue*alpha window sum
    xor  r11d,r11d                   ; alpha window sum
    xor  ecx,ecx
    mov  rsi,r14
.initial_window:
    add  r8d,[rsi]
    add  r9d,[rsi+4]
    add  r10d,[rsi+8]
    add  r11d,[rsi+12]
    add  rsi,16
    inc  ecx
    cmp  ecx,r15d
    jae  .window_ready
    cmp  rcx,[rsp+24]
    jbe  .initial_window
.window_ready:
    mov  rdi,r13
    xor  ecx,ecx                     ; output rectangle x
.pixel:
    test r11d,r11d
    jz   .transparent
    mov  eax,r8d
    xor  edx,edx
    div  r11d
    mov  [rdi],al
    mov  eax,r9d
    xor  edx,edx
    div  r11d
    mov  [rdi+1],al
    mov  eax,r10d
    xor  edx,edx
    div  r11d
    mov  [rdi+2],al
    jmp  .advance
.transparent:
    mov  word [rdi],0
    mov  byte [rdi+2],0
.advance:
    ; Move from x's clipped window to x+1's window.
    cmp  rcx,[rsp+24]
    jb   .no_remove_column
    mov  rax,rcx
    sub  rax,[rsp+24]
    shl  rax,4
    lea  rsi,[r14+rax]
    sub  r8d,[rsi]
    sub  r9d,[rsi+4]
    sub  r10d,[rsi+8]
    sub  r11d,[rsi+12]
.no_remove_column:
    mov  rax,rcx
    add  rax,[rsp+24]
    inc  rax
    cmp  rax,r15
    jae  .no_add_column
    shl  rax,4
    lea  rsi,[r14+rax]
    add  r8d,[rsi]
    add  r9d,[rsi+4]
    add  r10d,[rsi+8]
    add  r11d,[rsi+12]
.no_add_column:
    add  rdi,4
    inc  ecx
    cmp  ecx,r15d
    jb   .pixel
    inc  ebx
    cmp  ebx,ebp
    jae  .clear
    ; Column sums move down one source row, clipped to the selection.
    cmp  rbx,[rsp+24]
    jbe  .no_remove_row
    mov  rax,rbx
    sub  rax,[rsp+24]
    dec  rax
    imul rax,[rsp+8]
    lea  rsi,[r12+rax]
    mov  edx,-1
    call .columns_update
.no_remove_row:
    mov  rax,rbx
    add  rax,[rsp+24]
    cmp  rax,rbp
    jae  .no_add_row
    imul rax,[rsp+8]
    lea  rsi,[r12+rax]
    mov  edx,1
    call .columns_update
.no_add_row:
    add  r13,[rsp+16]
    jmp  .row
.clear:
    mov  rdi,r14
    mov  rcx,[rsp+56]
    shr  rcx,2
    xor  eax,eax
    rep  stosd
.ok:
    xor  eax,eax
    mov  rdx,[rsp]
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    add  rsp,64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret

; Internal RSI=source ROI row, EDX=+1/-1; update each weighted column.
; Preserves nonvolatiles and EDX; clobbers RAX/RCX/RSI/RDI/R8.
.columns_update:
    mov  rdi,r14
    mov  ecx,r15d
.column:
    movzx r8d,byte [rsi+3]
    movzx eax,byte [rsi]
    imul eax,r8d
    imul eax,edx
    add  [rdi],eax
    movzx eax,byte [rsi+1]
    imul eax,r8d
    imul eax,edx
    add  [rdi+4],eax
    movzx eax,byte [rsi+2]
    imul eax,r8d
    imul eax,edx
    add  [rdi+8],eax
    imul r8d,edx
    add  [rdi+12],r8d
    add  rsi,4
    add  rdi,16
    dec  ecx
    jnz  .column
    ret
