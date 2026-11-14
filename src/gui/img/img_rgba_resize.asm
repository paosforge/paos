;; MODULE gui/img/img_rgba_resize
;; LAYER 6
;; EXPORTS img_rgba_resize, img_rgba_scale_packed
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_resize(RDI=request64) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=bytes/0.
; Immutable little-endian request: src_ptr:u64@0, src_len:u64@8,
; dst_ptr:u64@16, dst_cap:u64@24, src_w:u32@32, src_h:u32@36,
; dst_w:u32@40, dst_h:u32@44, src_stride:u64@48, dst_stride:u64@56.
; Top-down RGBA8888, exact nearest-neighbor floor(dst*src/out), alpha unchanged.
; Source dimensions 1..4096, area <=4194304; destination 1..65535, area
; <=6291456 (the existing 24 MiB cache ceiling). Strides >= width*4.
; Required spans exclude padding after the final row. Success RDX is the
; required destination span, including padding between rows; padding is unwritten.
; Complete declared source/destination spans must be disjoint, and destination
; must not overlap request64. All validation precedes writes; refusal changes
; neither buffer nor request. Caller supplies mapped spans for the whole call.
; No allocation, retained pointer, filesystem, paint, FP or SIMD operations.
; RBX/RBP/R12-R15 and flags (including DF) are preserved.

img_rgba_resize:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 64
    jc   .bounds
    mov  r11, rdi
    mov  r12, [rdi]
    mov  r8,  [rdi + 8]
    mov  r13, [rdi + 16]
    mov  r9,  [rdi + 24]
    mov  r14d, [rdi + 32]
    mov  r15d, [rdi + 36]
    mov  ebp, [rdi + 40]
    mov  ebx, [rdi + 44]
    mov  rax, [rdi + 48]
    mov  [rsp], rax
    mov  rax, [rdi + 56]
    mov  [rsp + 8], rax
    test r12, r12
    jz   .bounds
    test r13, r13
    jz   .bounds
    test r14d, r14d
    jz   .bounds
    test r15d, r15d
    jz   .bounds
    test ebp, ebp
    jz   .bounds
    test ebx, ebx
    jz   .bounds
    cmp  r14d, 4096
    ja   .bounds
    cmp  r15d, 4096
    ja   .bounds
    cmp  ebp, 65535
    ja   .bounds
    cmp  ebx, 65535
    ja   .bounds
    mov  rax, r14
    imul rax, r15
    cmp  rax, 4194304
    ja   .bounds
    mov  rax, rbp
    imul rax, rbx
    cmp  rax, 6291456
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
    mov  rax, r15
    dec  rax
    mul  qword [rsp]
    test rdx, rdx
    jnz  .bounds
    add  rax, r10
    jc   .bounds
    cmp  r8, rax
    jb   .bounds
    lea  r10, [rbp * 4]
    cmp  [rsp + 8], r10
    jb   .bounds
    mov  rax, rbx
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
    lea  rax, [r11 + 64]
    cmp  r13, rax
    jae  .descriptor_disjoint
    lea  rax, [r13 + r9]
    cmp  r11, rax
    jb   .bounds
.descriptor_disjoint:
    cmp  r14d, ebp
    jne  .scaled
    cmp  r15d, ebx
    jne  .scaled
    ; Identity remains a row copy, avoiding per-pixel divides on cache misses.
    cld
    mov  rsi, r12
    mov  rdi, r13
    mov  r10d, ebx
.copy_row:
    mov  ecx, ebp
    rep  movsd
    dec  r10d
    jz   .ok
    lea  rax, [rbp * 4]
    add  rsi, [rsp]
    sub  rsi, rax
    add  rdi, [rsp + 8]
    sub  rdi, rax
    jmp  .copy_row
.scaled:
    xor  r10d, r10d                   ; destination y
.row:
    mov  eax, r10d
    mul  r15d
    div  ebx                          ; source y = floor(dy*src_h/dst_h)
    imul rax, [rsp]
    lea  rsi, [r12 + rax]
    mov  eax, r10d
    imul rax, [rsp + 8]
    lea  rdi, [r13 + rax]
    xor  r11d, r11d                   ; destination x
.pixel:
    mov  eax, r11d
    mul  r14d
    div  ebp                          ; source x = floor(dx*src_w/dst_w)
    mov  eax, [rsi + rax * 4]
    mov  [rdi + r11 * 4], eax
    inc  r11d
    cmp  r11d, ebp
    jb   .pixel
    inc  r10d
    cmp  r10d, ebx
    jb   .row
.ok:
    xor  eax, eax
    mov  rdx, [rsp + 16]
    jmp  .out
.bounds:
    mov  eax, 2
    xor  edx, edx
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret

; Internal packed-cache entry, with the original img_cache_scale register ABI.
; RDI=src, RSI=dst, EDX=src_w, ECX=src_h, R8D=dst_w, R9D=dst_h.
; PRECONDITION: caller has qualified positive dimensions, disjoint mapped packed
; RGBA spans and their sizes. img_cache_bind owns those checks and its arena.
; This entry retains the old internal scaler's domain (also used by the
; natural-blit host reference beyond the arena); it is NOT the bounded request API.
; Both entries run the same pixel kernel, including the identity-copy fast path.
img_rgba_scale_packed:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  r15d, ecx
    mov  ebp, r8d
    mov  ebx, r9d
    lea  rax, [r14 * 4]
    mov  [rsp], rax
    lea  rax, [rbp * 4]
    mov  [rsp + 8], rax
    imul rax, rbx
    mov  [rsp + 16], rax
    jmp  img_rgba_resize.descriptor_disjoint
