;; MODULE gui/img/img_rgba_crop
;; LAYER 6
;; EXPORTS img_rgba_crop
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Shared image-editor crop and clockwise quarter-turn memory backend.
; img_rgba_crop(RDI=request80) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=span/0.
; Immutable little-endian request: src_ptr:u64@0, src_len:u64@8,
; dst_ptr:u64@16, dst_cap:u64@24, src_w:u32@32, src_h:u32@36,
; src_stride:u64@40, crop_x:u32@48, crop_y:u32@52, crop_w:u32@56,
; crop_h:u32@60, dst_stride:u64@64, clockwise_turns:u32@72, reserved:u32@76.
; Top-down RGBA8888; crop first, then rotate 0/90/180/270 degrees (turns0..3).
; Source dimensions 1..4096, area <=4194304. Crop must be a nonempty rectangle
; entirely inside that source. Odd turns swap crop width/height in the output.
; Both strides are bytes, >= respective raster width*4. Required spans exclude
; padding after the last row; success RDX includes unwritten inter-row padding.
; Complete declared source/destination spans must be disjoint. Destination must
; also be disjoint from request80. All arithmetic, bounds and overlap validation
; precedes writes: refusal changes neither buffer nor descriptor. Caller supplies
; mapped spans for the whole synchronous call. No pointers retained, allocation,
; metadata, I/O, paint or FP/SIMD. Original RGBA and alpha remain exact.
; RBX/RBP/R12-R15 and flags (including DF) are preserved.

img_rgba_crop:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 80
    jc   .bounds
    mov  r11, rdi
    mov  r12, [rdi]                   ; source, later crop origin
    mov  r8, [rdi + 8]
    mov  r13, [rdi + 16]              ; destination
    mov  r9, [rdi + 24]
    mov  ebx, [rdi + 32]              ; source width
    mov  ebp, [rdi + 36]              ; source height
    mov  rax, [rdi + 40]
    mov  [rsp], rax                   ; source stride
    mov  r14d, [rdi + 56]             ; crop width
    mov  r15d, [rdi + 60]             ; crop height
    mov  rax, [rdi + 64]
    mov  [rsp + 8], rax               ; destination stride
    mov  eax, [rdi + 72]
    mov  [rsp + 24], eax              ; clockwise turns
    cmp  eax, 3
    ja   .bounds
    cmp  dword [rdi + 76], 0
    jne  .bounds
    test r12, r12
    jz   .bounds
    test r13, r13
    jz   .bounds
    test ebx, ebx
    jz   .bounds
    test ebp, ebp
    jz   .bounds
    cmp  ebx, 4096
    ja   .bounds
    cmp  ebp, 4096
    ja   .bounds
    mov  rax, rbx
    imul rax, rbp
    cmp  rax, 4194304
    ja   .bounds
    test r14d, r14d
    jz   .bounds
    test r15d, r15d
    jz   .bounds
    mov  eax, [rdi + 48]
    cmp  eax, ebx
    jae  .bounds
    mov  edx, ebx
    sub  edx, eax
    cmp  r14d, edx                    ; subtract, so crop endpoint cannot wrap
    ja   .bounds
    mov  eax, [rdi + 52]
    cmp  eax, ebp
    jae  .bounds
    mov  edx, ebp
    sub  edx, eax
    cmp  r15d, edx
    ja   .bounds
    mov  rax, r12
    add  rax, r8
    jc   .bounds
    mov  rax, r13
    add  rax, r9
    jc   .bounds
    lea  r10, [rbx * 4]
    cmp  [rsp], r10
    jb   .bounds
    mov  rax, rbp
    dec  rax
    mul  qword [rsp]
    test rdx, rdx
    jnz  .bounds
    add  rax, r10
    jc   .bounds
    cmp  r8, rax
    jb   .bounds
    mov  ebx, r14d                    ; output dimensions
    mov  ebp, r15d
    test byte [rsp + 24], 1
    jz   .output_dims
    xchg ebx, ebp
.output_dims:
    lea  r10, [rbx * 4]
    cmp  [rsp + 8], r10
    jb   .bounds
    mov  rax, rbp
    dec  rax
    mul  qword [rsp + 8]
    test rdx, rdx
    jnz  .bounds
    add  rax, r10
    jc   .bounds
    cmp  r9, rax
    jb   .bounds
    mov  [rsp + 16], rax              ; successful destination span
    lea  rax, [r12 + r8]
    cmp  r13, rax
    jae  .source_disjoint
    lea  rax, [r13 + r9]
    cmp  r12, rax
    jb   .bounds
.source_disjoint:
    lea  rax, [r11 + 80]
    cmp  r13, rax
    jae  .descriptor_disjoint
    lea  rax, [r13 + r9]
    cmp  r11, rax
    jb   .bounds
.descriptor_disjoint:
    ; Crop coordinates lie inside the fully qualified source raster. The
    ; multiplication and addition cannot exceed its already checked last row.
    mov  eax, [r11 + 52]
    imul rax, [rsp]
    add  r12, rax
    mov  eax, [r11 + 48]
    lea  r12, [r12 + rax * 4]
    cmp  dword [rsp + 24], 0
    jne  .rotated
    cld
    mov  rsi, r12
    mov  rdi, r13
    mov  r10d, ebp
.copy_row:
    mov  ecx, ebx
    rep  movsd
    dec  r10d
    jz   .ok
    lea  rax, [rbx * 4]
    add  rsi, [rsp]
    sub  rsi, rax
    add  rdi, [rsp + 8]
    sub  rdi, rax
    jmp  .copy_row
.rotated:
    xor  r10d, r10d                   ; output y
.row:
    mov  rax, r10
    imul rax, [rsp + 8]
    lea  rdi, [r13 + rax]
    xor  ecx, ecx                     ; output x
.pixel:
    cmp  dword [rsp + 24], 1
    je   .clockwise
    cmp  dword [rsp + 24], 2
    je   .half_turn
    ; 270 clockwise: source(cx,cy)=(crop_w-1-y,x).
    mov  eax, ecx
    mov  edx, r14d
    dec  edx
    sub  edx, r10d
    jmp  .sample
.clockwise:
    ; 90 clockwise: source(cx,cy)=(y,crop_h-1-x).
    mov  eax, r15d
    dec  eax
    sub  eax, ecx
    mov  edx, r10d
    jmp  .sample
.half_turn:
    mov  eax, r15d
    dec  eax
    sub  eax, r10d
    mov  edx, r14d
    dec  edx
    sub  edx, ecx
.sample:
    imul rax, [rsp]
    lea  rsi, [r12 + rax]
    mov  eax, [rsi + rdx * 4]
    mov  [rdi + rcx * 4], eax
    inc  ecx
    cmp  ecx, ebx
    jb   .pixel
    inc  r10d
    cmp  r10d, ebp
    jb   .row
.ok:
    xor  eax, eax
    mov  rdx, [rsp + 16]
    jmp  .out
.bounds:
    mov  eax, 2
    xor  edx, edx
.out:
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
