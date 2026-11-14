;; MODULE gui/img/img_bmp_encode
;; LAYER 6
;; EXPORTS img_bmp_encode
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Shared image-service memory export. No allocator, metadata, filesystem or I/O.
; img_bmp_encode(RDI=request48) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=bytes/0.
; Request, little endian: src_ptr:u64@0, src_len:u64@8, dst_ptr:u64@16,
; dst_cap:u64@24, width:u32@32, height:u32@36, src_stride:u64@40.
; Source is top-down RGBA8888. Only (height-1)*stride + width*4 source bytes
; are required; rows may have padding. Dimensions <=4096, pixels <=4194304.
; Destination is top-down BGRA32 BMP V4, explicit RGBA masks and sRGB. Alpha
; is preserved; no source metadata is copied. Required bytes=122+width*height*4.
; Declared source/destination spans must be disjoint; the destination must also
; be disjoint from the request. All validation precedes the first write, so a
; refused call modifies neither buffer nor request. Caller supplies mapped spans
; and retains them for the call. The synchronous encoder retains no pointer.
; RBX/RBP/R12-R15, flags (including DF) and FP/SIMD state are preserved.

img_bmp_encode:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 48
    jc   .bounds
    mov  r11, rdi                     ; immutable descriptor span
    mov  rbx, [rdi]                   ; source
    mov  r8,  [rdi + 8]               ; source capacity
    mov  rbp, [rdi + 16]              ; destination
    mov  r9,  [rdi + 24]              ; destination capacity
    mov  r12d, [rdi + 32]             ; width, then row bytes
    mov  r13d, [rdi + 36]             ; remaining rows
    mov  r14, [rdi + 40]              ; source stride
    test rbx, rbx
    jz   .bounds
    test rbp, rbp
    jz   .bounds
    test r12d, r12d
    jz   .bounds
    test r13d, r13d
    jz   .bounds
    cmp  r12d, 4096
    ja   .bounds
    cmp  r13d, 4096
    ja   .bounds
    mov  r15, r12
    imul r15, r13
    cmp  r15, 4194304
    ja   .bounds
    shl  r15, 2                      ; output pixel bytes
    add  r15, 122                    ; complete BMP file bytes
    cmp  r9, r15
    jb   .bounds
    mov  rax, rbx
    add  rax, r8
    jc   .bounds
    mov  rax, rbp
    add  rax, r9
    jc   .bounds
    shl  r12, 2                      ; width*4 cannot overflow after dimension cap
    cmp  r14, r12
    jb   .bounds
    mov  rax, r13
    dec  rax
    mul  r14                         ; qualify the final source row, not its padding
    test rdx, rdx
    jnz  .bounds
    add  rax, r12
    jc   .bounds
    cmp  r8, rax
    jb   .bounds

    ; Check complete declared spans, including unused source padding/capacity.
    lea  rax, [rbx + r8]
    cmp  rbp, rax
    jae  .source_disjoint
    lea  rax, [rbp + r9]
    cmp  rbx, rax
    jb   .bounds
.source_disjoint:
    lea  rax, [r11 + 48]
    cmp  rbp, rax
    jae  .descriptor_disjoint
    lea  rax, [rbp + r9]
    cmp  r11, rax
    jb   .bounds
.descriptor_disjoint:
    ; Header reserved fields, colour endpoints and gamma are deterministic zero.
    cld
    mov  rdi, rbp
    xor  eax, eax
    mov  ecx, 122
    rep  stosb
    mov  word  [rbp], 'BM'
    mov  [rbp + 2], r15d
    mov  dword [rbp + 10], 122
    mov  dword [rbp + 14], 108        ; BITMAPV4HEADER
    mov  eax, r12d
    shr  eax, 2
    mov  [rbp + 18], eax
    mov  eax, r13d
    neg  eax
    mov  [rbp + 22], eax             ; top-down raster
    mov  word  [rbp + 26], 1
    mov  word  [rbp + 28], 32
    mov  dword [rbp + 30], 3          ; BI_BITFIELDS
    lea  rax, [r15 - 122]
    mov  [rbp + 34], eax
    mov  dword [rbp + 54], 0x00ff0000
    mov  dword [rbp + 58], 0x0000ff00
    mov  dword [rbp + 62], 0x000000ff
    mov  dword [rbp + 66], 0xff000000
    mov  dword [rbp + 70], 0x73524742 ; LCS_sRGB
    mov  rsi, rbx
.row:
    mov  rcx, r12
    shr  rcx, 2
.pixel:
    mov  eax, [rsi]                  ; little-endian RGBA -> BGRA, alpha unchanged
    bswap eax
    ror  eax, 8
    mov  [rdi], eax
    add  rsi, 4
    add  rdi, 4
    dec  rcx
    jnz  .pixel
    dec  r13
    jz   .ok
    add  rsi, r14
    sub  rsi, r12
    jmp  .row
.ok:
    xor  eax, eax
    mov  rdx, r15
    jmp  .out
.bounds:
    mov  eax, 2
    xor  edx, edx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
