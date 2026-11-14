;; MODULE gui/img/img_rgba_fill
;; LAYER 6
;; EXPORTS img_rgba_fill
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_fill(RDI=request88) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=span/0.
; Immutable LE request: src:u64@0, src_len:u64@8, dst:u64@16, dst_cap:u64@24,
; width:u32@32, height:u32@36, src_stride:u64@40, dst_stride:u64@48,
; seed_x:u32@56, seed_y:u32@60, replacement:RGBA8888-u32@64, reserved0:u32@68,
; scratch:u64@72, scratch_cap:u64@80. Caller supplies mapped top-down straight
; RGBA8888 spans. Dimensions 1..4096, area<=4194304, strides>=width*4,
; seed inside canvas, scratch_cap>=area*4 (at most16MiB). Padding after the
; final row is not required. Success returns required destination span.
;
; Copies all source pixels, then replaces precisely the seed's four-connected
; component of identical four-byte RGBA pixels. Alpha/hidden RGB participate
; in matching; replacement is exact, with no blending or tolerance. Equal
; replacement is identity. Other pixels and original source remain unchanged.
; Entire declared destination and scratch spans must be disjoint from each
; other, source and request88. Read-only source/request alias is allowed.
; All validation precedes writes. Refusal leaves every span unchanged.
; Success clears exactly area*4 scratch bytes, including on identity; extra
; scratch capacity and destination padding/slack remain untouched.
;
; Queue stores each changed pixel index once: mark on enqueue and replacement
; differs from target, so at most area entries, O(area) time and caller scratch.
; No allocation, retained state, I/O, FP or SIMD. Full RBX/RBP/R12-R15 and
; flags including DF preserved. Pure editor backend, no file/UI authority.

img_rgba_fill:
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
    add  rax,88
    jc   .bounds
    mov  [rsp],rdi
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
    mov  [rsp+32],eax
    shl  rax,2
    mov  [rsp+16],rax
    mov  rax,r12
    add  rax,r8
    jc   .bounds
    mov  [rsp+56],rax
    mov  rax,r13
    add  rax,r9
    jc   .bounds
    mov  [rsp+64],rax
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
    mov  [rsp+24],rax
    mov  eax,[r11+56]
    cmp  eax,r14d
    jae  .bounds
    mov  ecx,[r11+60]
    cmp  ecx,r15d
    jae  .bounds
    imul ecx,r14d
    add  eax,ecx
    mov  [rsp+44],eax
    mov  eax,[r11+64]
    mov  [rsp+40],eax
    cmp  dword [r11+68],0
    jne  .bounds
    mov  rsi,[r11+72]
    mov  rcx,[r11+80]
    test rsi,rsi
    jz   .bounds
    cmp  rcx,[rsp+16]
    jb   .bounds
    mov  rax,rsi
    add  rax,rcx
    jc   .bounds
    mov  [rsp+8],rsi
    mov  [rsp+72],rax
    cmp  r13,[rsp+56]
    jae  .dst_source_disjoint
    cmp  r12,[rsp+64]
    jb   .bounds
.dst_source_disjoint:
    lea  rax,[r11+88]
    cmp  r13,rax
    jae  .dst_request_disjoint
    cmp  r11,[rsp+64]
    jb   .bounds
.dst_request_disjoint:
    cmp  rsi,[rsp+56]
    jae  .scratch_source_disjoint
    cmp  r12,[rsp+72]
    jb   .bounds
.scratch_source_disjoint:
    cmp  rsi,[rsp+64]
    jae  .scratch_dst_disjoint
    cmp  r13,[rsp+72]
    jb   .bounds
.scratch_dst_disjoint:
    lea  rax,[r11+88]
    cmp  rsi,rax
    jae  .validated
    cmp  r11,[rsp+72]
    jb   .bounds
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
    mov  r12,rsp
    mov  rbx,[r12+8]
    mov  eax,[r12+44]
    xor  edx,edx
    div  r14d
    imul rax,rbp
    lea  rdi,[r13+rax]
    lea  rdi,[rdi+rdx*4]
    mov  eax,[rdi]
    mov  [r12+36],eax
    cmp  eax,[r12+40]
    je   .clear
    mov  eax,[r12+44]
    mov  [rbx],eax
    mov  eax,[r12+40]
    mov  [rdi],eax
    mov  dword [r12+48],0
    mov  dword [r12+52],1
.pop:
    mov  ecx,[r12+48]
    cmp  ecx,[r12+52]
    jae  .clear
    mov  r8d,[rbx+rcx*4]
    inc  ecx
    mov  [r12+48],ecx
    mov  eax,r8d
    xor  edx,edx
    div  r14d
    mov  r9d,eax
    mov  r10d,edx
    imul rax,rbp
    lea  r11,[r13+rax]
    lea  r11,[r11+rdx*4]
    test r10d,r10d
    jz   .right
    lea  eax,[r8-1]
    lea  rdi,[r11-4]
    call .visit
.right:
    lea  eax,[r10+1]
    cmp  eax,r14d
    jae  .up
    lea  eax,[r8+1]
    lea  rdi,[r11+4]
    call .visit
.up:
    test r9d,r9d
    jz   .down
    mov  eax,r8d
    sub  eax,r14d
    mov  rdi,r11
    sub  rdi,rbp
    call .visit
.down:
    lea  eax,[r9+1]
    cmp  eax,r15d
    jae  .pop
    mov  eax,r8d
    add  eax,r14d
    lea  rdi,[r11+rbp]
    call .visit
    jmp  .pop
.visit:
    mov  ecx,[r12+36]
    cmp  [rdi],ecx
    jne  .visited
    mov  edx,[r12+40]
    mov  [rdi],edx
    mov  ecx,[r12+52]
    mov  [rbx+rcx*4],eax
    inc  ecx
    mov  [r12+52],ecx
.visited:
    ret
.clear:
    mov  rdi,rbx
    mov  ecx,[r12+32]
    xor  eax,eax
    rep  stosd
    mov  rdx,[r12+24]
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
