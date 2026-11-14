; IBM OS/2 PM Reference II Appendix D single-size IC/PT/CI/CP image admission.
; Finite raw CORE12/full64, planes1, canonical B/W masks, color1/4/8/24.
; Mask raster contains XOR then AND, each bottom-up at DWORD stride. Color
; header/palette follows the mask header/palette, before either raster. Both
; DWORD offBits are absolute. Screen inversion is unrepresentable by RGBA.
; Hotspots are checked inside the visible image; this ABI returns image pixels,
; not cursor registration/anchoring. No BA selection or compressed icon profile.
; One owned allocation: RGBA at base, aligned immutable whole-source snapshot
; after it. Descriptors are invocation-local. No normalized BM relabeling.

; Private descriptor64: width,height,depth,palstep (dwords), palette,count,
; pixels,stride,end offset,header/table end offset (qwords). Caller span checked.
; RDI=source RSI=len RDX=header offset R9=descriptor. Nonvolatile regs untouched.
img_bmp_icon_header:
    mov  r8, rdx
    lea  rax, [rdx + 26]
    cmp  rax, rsi
    ja   .truncated
    mov  ax, [rdi + r8]
    cmp  ax, [rdi]
    jne  .corrupt
    mov  eax, [rdi + r8 + 14]
    cmp  eax, 12
    je   .core
    cmp  eax, 64
    jne  .unsupported
    lea  rax, [r8 + 78]
    cmp  rax, rsi
    ja   .truncated
    cmp  dword [rdi + r8 + 2], 78
    jne  .corrupt
    cmp  word [rdi + r8 + 26], 1
    jne  .unsupported
    cmp  dword [rdi + r8 + 30], 0
    jne  .unsupported
    cmp  word [rdi + r8 + 54], 0
    jne  .unsupported
    cmp  word [rdi + r8 + 56], 0
    jne  .unsupported
    cmp  word [rdi + r8 + 58], 0
    jne  .unsupported
    cmp  word [rdi + r8 + 60], 3
    ja   .unsupported
    cmp  dword [rdi + r8 + 70], 0
    jne  .unsupported
    mov  eax, [rdi + r8 + 18]
    mov  [r9], eax
    mov  eax, [rdi + r8 + 22]
    mov  [r9 + 4], eax
    movzx eax, word [rdi + r8 + 28]
    mov  [r9 + 8], eax
    mov  dword [r9 + 12], 4
    mov  r10d, [rdi + r8 + 46]
    lea  r11, [r8 + 78]
    jmp  .dimensions
.core:
    cmp  dword [rdi + r8 + 2], 26
    jne  .corrupt
    cmp  word [rdi + r8 + 22], 1
    jne  .unsupported
    movzx eax, word [rdi + r8 + 18]
    mov  [r9], eax
    movzx eax, word [rdi + r8 + 20]
    mov  [r9 + 4], eax
    movzx eax, word [rdi + r8 + 24]
    mov  [r9 + 8], eax
    mov  dword [r9 + 12], 3
    xor  r10d, r10d
    lea  r11, [r8 + 26]
.dimensions:
    cmp  dword [r9], 0
    je   .bounds
    cmp  dword [r9], IMG_MAX_DIM
    ja   .bounds
    cmp  dword [r9 + 4], 0
    je   .bounds
    cmp  dword [r9 + 4], IMG_MAX_DIM * 2
    ja   .bounds
    mov  eax, [r9]
    mov  ecx, [r9 + 4]
    imul rax, rcx
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    mov  ecx, [r9 + 8]
    cmp  ecx, 24
    je   .table
    cmp  ecx, 1
    je   .indexed
    cmp  ecx, 4
    je   .indexed
    cmp  ecx, 8
    jne  .unsupported
.indexed:
    mov  eax, 1
    shl  eax, cl
    test r10, r10
    jnz  .count
    mov  r10d, eax
.count:
    cmp  r10d, eax
    ja   .corrupt
.table:
    cmp  dword [rdi + r8 + 14], 64
    jne  .table_span
    mov  eax, [rdi + r8 + 50]
    cmp  rax, r10
    ja   .corrupt
.table_span:
    lea  rax, [rdi + r11]
    mov  [r9 + 16], rax
    mov  [r9 + 24], r10
    mov  eax, [r9 + 12]
    imul rax, r10
    add  r11, rax
    cmp  r11, rsi
    ja   .truncated
    mov  [r9 + 56], r11
    mov  eax, [rdi + r8 + 10]
    cmp  rax, r11
    jb   .corrupt
    mov  r10, rax
    add  rax, rdi
    mov  [r9 + 32], rax
    mov  eax, [r9]
    mov  ecx, [r9 + 8]
    imul rax, rcx
    add  rax, 31
    shr  rax, 5
    shl  rax, 2                      ; icon DWORD stride, independently of offset
    mov  [r9 + 40], rax
    mov  ecx, [r9 + 4]
    imul rax, rcx
    cmp  dword [rdi + r8 + 14], 64
    jne  .extent
    mov  ecx, [rdi + r8 + 34]
    test ecx, ecx
    jz   .extent
    cmp  rcx, rax
    jne  .corrupt
.extent:
    add  rax, r10
    cmp  rax, rsi
    ja   .truncated
    mov  [r9 + 48], rax
    xor  eax, eax
    ret
.bounds:
    mov  eax, IMG_E_BOUNDS
    ret
.truncated:
    mov  eax, IMG_E_TRUNCATED
    ret
.corrupt:
    mov  eax, IMG_E_CORRUPT
    ret
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    ret

; Same complete dry/write grammar. R9=0 dry, otherwise disjoint owned RGBA.
; All descriptors and scan cursors are private, never caller-persistent state.
img_bmp_icon_pass:
    cld
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 176
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, r9
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds
    cmp  rsi, 33554432
    ja   .bounds
    cmp  rsi, 26
    jb   .truncated
    xor  edx, edx
    mov  r9, rsp
    call img_bmp_icon_header
    test eax, eax
    jnz  .refused
    cmp  dword [rsp + 8], 1
    jne  .unsupported
    mov  r15d, [rsp + 4]
    test r15d, 1
    jnz  .corrupt
    shr  r15d, 1                     ; visible height, never stored double height
    cmp  qword [rsp + 24], 2
    jne  .unsupported
    mov  rax, [rsp + 16]
    cmp  word [rax], 0
    jne  .unsupported
    cmp  byte [rax + 2], 0
    jne  .unsupported
    mov  ecx, [rsp + 12]
    add  rax, rcx
    cmp  word [rax], 0xffff
    jne  .unsupported
    cmp  byte [rax + 2], 0xff
    jne  .unsupported
    mov  dword [rsp + 132], 0
    cmp  word [r12], 'CI'
    je   .color
    cmp  word [r12], 'CP'
    je   .color
    cmp  word [r12], 'IC'
    je   .mono
    cmp  word [r12], 'PT'
    jne  .unsupported
.mono:
    mov  qword [rsp + 96], 0
    mov  qword [rsp + 104], 0
    mov  rax, [rsp + 48]
    cmp  rax, r13
    jne  .corrupt                    ; never ignore trailing structures/data
    jmp  .hotspots
.color:
    mov  dword [rsp + 132], 1
    mov  rdx, [rsp + 56]
    lea  r9, [rsp + 64]
    call img_bmp_icon_header
    test eax, eax
    jnz  .refused
    mov  eax, [rsp]
    cmp  eax, [rsp + 64]
    jne  .corrupt
    cmp  r15d, [rsp + 68]
    jne  .corrupt
    mov  ecx, r15d
    imul rax, rcx
    imul rax, rax, 3                 ; aggregate visible+two mask pixel work
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    mov  rax, [rsp + 120]            ; both tables before either raster
    add  rax, r12
    cmp  [rsp + 32], rax
    jb   .corrupt
    cmp  [rsp + 96], rax
    jb   .corrupt
    mov  rax, [rsp + 48]
    add  rax, r12
    cmp  rax, [rsp + 96]
    jbe  .disjoint
    mov  rax, [rsp + 112]
    add  rax, r12
    cmp  rax, [rsp + 32]
    ja   .corrupt                    ; complete raw intervals, padding included
.disjoint:
    mov  rax, [rsp + 48]
    cmp  rax, [rsp + 112]
    cmovb rax, [rsp + 112]
    cmp  rax, r13
    jne  .corrupt
.hotspots:
    movsx eax, word [r12 + 6]
    cmp  eax, [rsp]
    jae  .corrupt                    ; signed negative also fails unsigned range
    movsx eax, word [r12 + 8]
    cmp  eax, r15d
    jae  .corrupt
    cmp  dword [rsp + 132], 0
    je   .walk
    mov  rax, [rsp + 56]
    movsx ecx, word [r12 + rax + 6]
    cmp  ecx, [rsp]
    jae  .corrupt
    movsx ecx, word [r12 + rax + 8]
    cmp  ecx, r15d
    jae  .corrupt                    ; secondary hotspot checked, not assumed equal
.walk:
    mov  dword [rsp + 136], 0
.row:
    mov  eax, r15d
    dec  eax
    sub  eax, [rsp + 136]            ; top-down output, bottom-up input halves
    mov  ecx, eax
    imul rax, [rsp + 40]
    add  rax, [rsp + 32]
    mov  [rsp + 144], rax
    mov  edx, r15d
    imul rdx, [rsp + 40]
    add  rax, rdx
    mov  [rsp + 152], rax
    mov  eax, ecx
    imul rax, [rsp + 104]
    add  rax, [rsp + 96]
    mov  [rsp + 160], rax             ; unused for mono, never dereferenced
    mov  dword [rsp + 140], 0
.pixel:
    mov  ebp, 1
    mov  ecx, [rsp + 140]
    mov  rsi, [rsp + 144]
    call img_bmp_index
    mov  edx, eax
    mov  rsi, [rsp + 152]
    call img_bmp_index
    mov  [rsp + 168], eax
    test eax, edx
    jnz  .unsupported                ; destination-dependent inversion refused dry
    cmp  dword [rsp + 132], 0
    jne  .color_pixel
    neg  edx
    mov  eax, edx
    or   eax, 0xff000000             ; canonical mono black/white, not mask palette
    jmp  .alpha
.color_pixel:
    mov  ebp, [rsp + 72]
    mov  rsi, [rsp + 160]
    cmp  ebp, 24
    je   .rgb24
    call img_bmp_index
    cmp  rax, [rsp + 88]
    jae  .corrupt                    ; validate even fully transparent color pixels
    mov  ecx, [rsp + 76]
    imul rax, rcx
    add  rax, [rsp + 80]
    jmp  .rgb
.rgb24:
    lea  eax, [rcx + rcx*2]
    add  rax, rsi
.rgb:
    movzx ecx, byte [rax + 2]
    movzx edx, byte [rax + 1]
    shl  edx, 8
    or   ecx, edx
    movzx eax, byte [rax]
    shl  eax, 16
    or   eax, ecx
    or   eax, 0xff000000
.alpha:
    cmp  dword [rsp + 168], 0
    je   .write
    xor  eax, eax                    ; transparent is canonical zero RGBA
.write:
    test r14, r14
    jz   .advance
    mov  ecx, [rsp + 136]
    imul ecx, [rsp]
    add  ecx, [rsp + 140]
    mov  [r14 + rcx*4], eax
.advance:
    inc  dword [rsp + 140]
    mov  eax, [rsp + 140]
    cmp  eax, [rsp]
    jb   .pixel
    inc  dword [rsp + 136]
    cmp  [rsp + 136], r15d
    jb   .row
    mov  ecx, [rsp]
    mov  edx, r15d
    mov  r8d, 1
    cmp  dword [rsp + 132], 0
    je   .success
    mov  r8d, [rsp + 72]
.success:
    mov  ebx, IMG_FMT_BMP
    xor  eax, eax
    jmp  .out
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .refused
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  .refused
.corrupt:
    mov  eax, IMG_E_CORRUPT
    jmp  .refused
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
.refused:
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
.out:
    add  rsp, 176
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

img_bmp_icon_probe:
    xor  r9d, r9d
    jmp  img_bmp_icon_pass

img_bmp_icon_decode:
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 96
    mov  r12, rdi
    mov  r13, rsi
    call img_bmp_icon_probe
    test eax, eax
    jnz  .refused
    mov  [rsp + 64], ecx
    mov  [rsp + 68], edx
    mov  eax, ecx
    imul rax, rdx
    shl  rax, 2
    add  rax, 15
    and  rax, -16
    mov  [rsp + 72], rax             ; RGBA and snapshot never overlap
    lea  rdi, [rsp]
    mov  rsi, r12
    mov  rdx, r13
    call sha256_hash
    test rax, rax
    jnz  .changed
    mov  rdi, [rsp + 72]
    add  rdi, r13
    call img_output_alloc
    test rax, rax
    jz   .oom
    mov  r14, rax
    add  rax, [rsp + 72]
    mov  r15, rax
    mov  rdi, r15
    mov  rsi, r12
    mov  rcx, r13
    rep  movsb                       ; entire source, including paired/trailing data
    lea  rdi, [rsp + 32]
    mov  rsi, r15
    mov  rdx, r13
    call sha256_hash
    test rax, rax
    jnz  .owned_changed
    xor  ecx, ecx
.digest:
    mov  rax, [rsp + rcx]
    cmp  rax, [rsp + rcx + 32]
    jne  .owned_changed              ; allocation-time changes never reach pixels
    add  ecx, 8
    cmp  ecx, 32
    jb   .digest
    mov  rdi, r15
    mov  rsi, r13
    call img_bmp_icon_probe          ; privately requalify before any pixel writes
    test eax, eax
    jnz  .owned_refused
    cmp  ecx, [rsp + 64]
    jne  .owned_changed
    cmp  edx, [rsp + 68]
    jne  .owned_changed
    mov  rdi, r15
    mov  rsi, r13
    mov  r9, r14
    call img_bmp_icon_pass
    test eax, eax
    jnz  .owned_refused
    mov  rbx, r14
    mov  r8d, IMG_FMT_BMP
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    jmp  .out
.owned_changed:
    mov  eax, IMG_E_CORRUPT
.owned_refused:
    mov  [rsp + 80], eax
    call img_output_release          ; exactly one canonical allocation is retired
    mov  eax, [rsp + 80]
    jmp  .refused
.oom:
    mov  eax, IMG_E_OOM
    jmp  .refused
.changed:
    mov  eax, IMG_E_CORRUPT
.refused:
    call img_refusal_clear
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
.out:
    add  rsp, 96
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
