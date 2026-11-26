;; MODULE gui/img/img_png
;; LAYER 6
;; EXPORTS img_png_probe, img_png_probe_exact, img_png_decode, img_png_probe_surface, img_png_decode_surface
;; IMPORTS core/heap, core/lib/crc32, core/lib/sha256
;; CAPS
;; OWNER saga:gui_image_pipeline

%include "gui/img/img_cold_hooks.inc"

; PNG non-interlaced and Adam7 subset: gray1/2/4/8/16, indexed1/2/4/8,
; gray-alpha/RGB/RGBA8/16. PNG3 13.12 rounded linear16->8 conversion;
; tRNS compares every original sample bit, colors remain unassociated.
; eXIf primary orientation1..8 is applied to returned dimensions and RGBA.
; One allocation
; owns RGBA, filtered rows, a SHA-bound whole-file snapshot and concatenated
; IDAT. Palette/alpha and compressed bytes come only from that snapshot.
; Static per-call metadata is retired at the public boundary; no partial output
; is published. Resource caps and the frozen core/cache ABI remain shared.

PNG_SIG0 equ 0x474E5089
PNG_SIG1 equ 0x0A1A0A0D

PNG_SOURCE_MAX equ 33554432
PNG_SURFACE_SOURCE_MAX equ 67141632 ; 64MiB+32KiB: includes max surface PNG export

; Surface policy is invocation-local, never a global limit change. Internal
; surface probe/decode retain the core ABI and BSP-only singleton contract.
; Call img_png_decode_surface_into for busy preservation and atomic caller copy.
; At16M pixels, eight-byte samples and Adam7 descriptors still fit32-bit sums;
; one bounded allocation owns RGBA<=64MiB, filtered rows<129MiB, two source
; spans<=128MiB+64KiB and orientation scratch<=64MiB. OOM refuses normally.

; Probe uses invocation-local metadata. No borrowed palette pointer is published.
; R8D is packed bits/pixel (up to64), not sample depth or output stride.
img_png_probe_surface:
    IMG_COLD_PUBLIC_GUARD
    cld
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  qword [rsp + 40], 16384
    mov  qword [rsp + 48], 16777216
    mov  qword [rsp + 56], PNG_SURFACE_SOURCE_MAX
    jmp  img_png_probe.admit
img_png_probe:
    IMG_COLD_PUBLIC_GUARD
    cld
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  qword [rsp + 40], IMG_MAX_DIM
    mov  qword [rsp + 48], IMG_MAX_PIXELS
    mov  qword [rsp + 56], PNG_SOURCE_MAX
.admit:
    mov  r12, rdi
    mov  r13, rsi
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
    mov  r15, rdi
    add  r15, rsi
    jc   .bounds
    cmp  r13, [rsp + 56]
    ja   .bounds
    cmp  r13, 33
    jb   .truncated
    cmp  dword [r12], PNG_SIG0
    jne  .bad_magic
    cmp  dword [r12 + 4], PNG_SIG1
    jne  .bad_magic
    cmp  dword [r12 + 8], 0x0D000000
    jne  .unsupported
    cmp  dword [r12 + 12], 'IHDR'
    jne  .unsupported
    mov  qword [rsp + 8], 0             ; bpp, palette entries
    mov  qword [rsp + 16], 0            ; tRNS seen, IDAT state
    mov  qword [rsp + 24], 0            ; total compressed bytes
    mov  dword [rsp + 32], 1            ; invocation-local primary orientation
    mov  dword [rsp + 36], 0            ; eXIf occurrence
    lea  r14, [r12 + 8]
.chunk:
    mov  rax, r15
    sub  rax, r14
    cmp  rax, 12
    jb   .truncated
    mov  r11d, [r14]
    bswap r11d
    test r11d, r11d
    js   .bounds                        ; PNG integers are at most 2^31-1
    sub  rax, 12
    cmp  r11, rax
    ja   .truncated
    ; Chunk names are four ASCII letters; the reserved third byte is uppercase.
    xor  ecx, ecx
.type_byte:
    movzx eax, byte [r14 + 4 + rcx]
    or   al, 0x20
    sub  al, 'a'
    cmp  al, 25
    ja   .corrupt
    inc  ecx
    cmp  ecx, 4
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .type_byte
    test byte [r14 + 6], 0x20
    jnz  .corrupt
    lea  rdi, [r14 + 4]
    lea  esi, [r11 + 4]
    IMG_COLD_CRC
    mov  edi, [r14 + 8 + r11]
    bswap edi
    cmp  eax, edi
    jne  .crc
    cmp  dword [r14 + 4], 'IHDR'
    jne  .not_ihdr
    lea  rax, [r12 + 8]
    cmp  r14, rax
    jne  .corrupt
    mov  eax, [r14 + 8]
    bswap eax
    mov  [rsp], eax
    test eax, eax
    jz   .bounds
    cmp  rax, [rsp + 40]
    ja   .bounds
    mov  edx, [r14 + 12]
    bswap edx
    mov  [rsp + 4], edx
    test edx, edx
    jz   .bounds
    cmp  rdx, [rsp + 40]
    ja   .bounds
    imul rax, rdx
    cmp  rax, [rsp + 48]
    ja   .bounds
    movzx eax, byte [r14 + 16]
    cmp  eax, 16
    je   .depth16
    cmp  byte [r14 + 17], 0
    je   .indexed                       ; same legal packed depths as indexed
    cmp  byte [r14 + 17], 3
    je   .indexed
    cmp  eax, 8
    jne  .unsupported
    mov  eax, 16
    cmp  byte [r14 + 17], 4
    je   .profile                       ; depth8 gray + depth8 unassociated alpha
    mov  eax, 24
    cmp  byte [r14 + 17], 2
    je   .profile
    mov  eax, 32
    cmp  byte [r14 + 17], 6
    jne  .unsupported
    jmp  .profile
.indexed:
    cmp  eax, 1
    je   .profile
    cmp  eax, 2
    je   .profile
    cmp  eax, 4
    je   .profile
    cmp  eax, 8
    jne  .unsupported
    jmp  .profile
.depth16:
    mov  eax, 16
    cmp  byte [r14 + 17], 0
    je   .profile
    mov  eax, 32
    cmp  byte [r14 + 17], 4
    je   .profile
    mov  eax, 48
    cmp  byte [r14 + 17], 2
    je   .profile
    mov  eax, 64
    cmp  byte [r14 + 17], 6
    jne  .unsupported
.profile:
    mov  [rsp + 8], eax
    cmp  byte [r14 + 18], 0
    jne  .unsupported
    cmp  byte [r14 + 19], 0
    jne  .unsupported
    cmp  byte [r14 + 20], 1
    ja   .unsupported
    jmp  .advance
.not_ihdr:
    cmp  dword [r14 + 4], 'IDAT'
    je   .idat
    cmp  dword [rsp + 20], 1
    jne  .not_idat
    mov  dword [rsp + 20], 2            ; IDAT sequence has closed
.not_idat:
    cmp  dword [r14 + 4], 'PLTE'
    je   .palette
    cmp  dword [r14 + 4], 'tRNS'
    je   .alpha
    cmp  dword [r14 + 4], 'IEND'
    je   .end
    cmp  dword [r14 + 4], 'eXIf'
    je   .exif
    test byte [r14 + 4], 0x20
    jz   .unsupported                   ; unknown critical chunk
    cmp  dword [r14 + 4], 'acTL'
    je   .unsupported                   ; animation remains outside this profile
    jmp  .advance                       ; CRC-checked ignored ancillary chunk
.exif:
    cmp  dword [rsp + 36], 0
    jne  .corrupt                       ; PNG3 permits exactly one eXIf
    mov  dword [rsp + 36], 1
    lea  rdi, [r14 + 8]                 ; PNG carries TIFF, no JPEG Exif prefix
    mov  rsi, r11
    push r11
    call img_png_exif
    pop  r11
    test eax, eax
    jnz  .out
    mov  [rsp + 32], edx
    jmp  .advance
.palette:
    cmp  dword [rsp + 16], 0
    jne  .corrupt                       ; optional truecolor PLTE precedes tRNS
    cmp  byte [r12 + 25], 0
    je   .corrupt                       ; PLTE is forbidden for both gray types
    cmp  byte [r12 + 25], 4
    je   .corrupt
    cmp  dword [rsp + 20], 0
    jne  .corrupt
    cmp  dword [rsp + 12], 0
    jne  .corrupt
    test r11d, r11d
    jz   .corrupt
    cmp  r11d, 768
    ja   .corrupt
    mov  eax, r11d
    xor  edx, edx
    mov  ecx, 3
    div  ecx
    test edx, edx
    jnz  .corrupt
    cmp  dword [rsp + 8], 8
    ja   .palette_valid
    mov  ecx, [rsp + 8]
    mov  edx, 1
    shl  edx, cl
    cmp  eax, edx
    ja   .corrupt
.palette_valid:
    mov  [rsp + 12], eax
    jmp  .advance
.alpha:
    cmp  dword [rsp + 20], 0
    jne  .corrupt
    cmp  dword [rsp + 16], 0
    jne  .corrupt
    cmp  byte [r12 + 25], 0
    je   .gray_alpha
    cmp  byte [r12 + 25], 4
    je   .corrupt                       ; full-alpha types cannot carry tRNS
    cmp  byte [r12 + 25], 6
    je   .corrupt
    cmp  byte [r12 + 25], 2
    je   .rgb_alpha
    cmp  dword [rsp + 8], 8
    ja   .unsupported                   ; indexed alpha exceeds supported depth
    cmp  dword [rsp + 12], 0
    je   .corrupt
    cmp  r11d, [rsp + 12]
    ja   .corrupt
    mov  dword [rsp + 16], 1            ; empty indexed alpha is all opaque
    jmp  .advance
.rgb_alpha:
    cmp  r11d, 6
    jne  .corrupt                       ; exactly three original BE16 keys
    mov  dword [rsp + 16], 1
    jmp  .advance
.gray_alpha:
    cmp  r11d, 2
    jne  .corrupt                       ; exactly one BE16 gray key
    ; PNG3 requires masking unused high bits, not rejecting them. The owned
    ; collector retains the two bytes; conversion compares original precision.
    mov  dword [rsp + 16], 1
    jmp  .advance
.idat:
    cmp  dword [rsp + 20], 2
    je   .corrupt
    cmp  byte [r12 + 25], 3
    jne  .idat_valid
    cmp  dword [rsp + 12], 0
    je   .corrupt
.idat_valid:
    mov  dword [rsp + 20], 1
    add  [rsp + 24], r11
    jmp  .advance
.end:
    test r11d, r11d
    jnz  .corrupt
    cmp  qword [rsp + 24], 0
    je   .truncated
    cmp  byte [r12 + 28], 1
    je   .whole_file                     ; every Adam7 profile owns exact span
    cmp  byte [r12 + 24], 16
    je   .whole_file
    cmp  byte [r12 + 25], 2
    je   .success                       ; retained native truecolor suffix policy
    cmp  byte [r12 + 25], 6
    je   .success
.whole_file:
    lea  rax, [r14 + 12]
    cmp  rax, r15
    jne  .corrupt                       ; gray/indexed admit the whole file
.success:
    mov  ecx, [rsp]
    mov  edx, [rsp + 4]
    mov  r9d, [rsp + 32]                ; private decoder also binds orientation
    cmp  r9d, 5
    jb   .dimensions
    xchg ecx, edx
.dimensions:
    mov  r8d, [rsp + 8]
    mov  ebx, IMG_FMT_PNG
    xor  eax, eax
    jmp  .out
.advance:
    lea  r14, [r14 + 12 + r11]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .chunk
.bad_magic:
    mov  eax, IMG_E_BAD_MAGIC
    jmp  .out
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .out
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  .out
.crc:
    mov  eax, IMG_E_CRC
    jmp  .out
.corrupt:
    mov  eax, IMG_E_CORRUPT
    jmp  .out
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; Exact-span adapter entry: same native profile/CRC checks, IEND at supplied end.
img_png_probe_exact:
    IMG_COLD_PUBLIC_GUARD
    cld
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds
    push rdi
    push rsi
    call img_png_probe
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .out
    lea  r9, [rdi + 8]
    lea  r10, [rdi + rsi]
.chunk:
    mov  rax, r9
    add  rax, 12
    jc   .bounds
    cmp  rax, r10
    ja   .truncated
    mov  r11d, [r9]
    bswap r11d
    add  rax, r11                     ; recheck every read even on caller bytes
    jc   .bounds
    cmp  rax, r10
    ja   .truncated
    mov  r11d, [r9 + 4]
    mov  r9, rax
    cmp  r11d, 'IEND'
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .chunk
    xor  eax, eax
    cmp  r9, r10
    je   .out
    mov  eax, IMG_E_CORRUPT
.out:
    ret
.bounds:
    mov  eax, IMG_E_BOUNDS
    ret
.truncated:
    mov  eax, IMG_E_TRUNCATED
    ret

; Bounded TIFF parser adapted from the accepted native JPEG primary IFD.
; Unknown tag payloads and next-IFD pointers are never dereferenced.
img_png_exif:
    push rbx
    mov  ebx, 1                       ; absent Orientation means identity
    mov  r9, rdi
    mov  r10, rsi
    cmp  r10, 8
    jb   .truncated
    xor  r8d, r8d                     ; II
    cmp  word [rdi], 0x4949
    je   .header
    inc  r8d                          ; MM
    cmp  word [rdi], 0x4D4D
    jne  .corrupt
.header:
    add  rdi, 2
    call .u16
    cmp  eax, 42
    jne  .corrupt
    lea  rdi, [r9 + 4]
    call .u32
    cmp  eax, 8
    jb   .corrupt                     ; no overlap with TIFF header
    test al, 1
    jnz  .corrupt                     ; TIFF word-aligned IFD
    mov  edx, eax
    add  rdx, 2
    cmp  rdx, r10
    ja   .truncated
    lea  rdi, [r9 + rax]
    call .u16
    mov  r11d, eax
    imul eax, 12                      ; <=65535*12, wide span arithmetic
    add  rdx, rax
    add  rdx, 4                       ; include next-IFD field, never follow it
    cmp  rdx, r10
    ja   .truncated
    lea  rsi, [rdi + 2]
    xor  ecx, ecx                     ; Orientation occurrence count
.entry:
    test r11d, r11d
    jz   .ok
    mov  rdi, rsi
    call .u16
    cmp  eax, 274
    jne  .next
    test ecx, ecx
    jnz  .corrupt
    inc  ecx
    lea  rdi, [rsi + 2]
    call .u16
    cmp  eax, 3                       ; SHORT
    jne  .unsupported
    lea  rdi, [rsi + 4]
    call .u32
    cmp  eax, 1
    jne  .unsupported
    lea  rdi, [rsi + 8]
    call .u16                         ; left-justified in both endian forms
    cmp  eax, 1
    jb   .unsupported
    cmp  eax, 8
    ja   .unsupported
    mov  ebx, eax
.next:
    add  rsi, 12
    dec  r11d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .entry
.ok:
    mov  edx, ebx
    xor  eax, eax
    pop  rbx
    ret
.u16:
    movzx eax, word [rdi]
    test r8d, r8d
    jz   .read
    rol  ax, 8
.read:
    ret
.u32:
    mov  eax, [rdi]
    test r8d, r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .read
    bswap eax
    ret
.truncated:
    mov  eax, IMG_E_TRUNCATED
    pop  rbx
    ret
.corrupt:
    mov  eax, IMG_E_CORRUPT
    pop  rbx
    ret
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    pop  rbx
    ret

; RDI=RGBA, RSI=private RGBA-sized scratch, ECX=stored W, EDX=stored H,
; R8D=qualified primary orientation2..8. Same pixel count for every mapping.
img_png_orient:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, ecx
    mov  r15d, edx
    mov  ebp, r8d
    mov  r10d, ecx
    cmp  ebp, 5
    jb   .start
    mov  r10d, edx                     ; transposed output stride
.start:
    xor  r8d, r8d                     ; source y
.row:
    xor  r9d, r9d                     ; source x
.pixel:
    mov  edi, r9d
    mov  esi, r8d
    cmp  ebp, 5
    jae  .transpose
    cmp  ebp, 2
    je   .mirror_x
    cmp  ebp, 3
    jne  .mirror_y
.mirror_x:
    mov  edi, r14d
    dec  edi
    sub  edi, r9d
    cmp  ebp, 2
    je   .store
.mirror_y:
    mov  esi, r15d
    dec  esi
    sub  esi, r8d
    jmp  .store
.transpose:
    mov  edi, r8d
    mov  esi, r9d
    cmp  ebp, 5
    je   .store
    cmp  ebp, 8
    je   .transpose_y
    mov  edi, r15d
    dec  edi
    sub  edi, r8d
    cmp  ebp, 6
    je   .store
.transpose_y:
    mov  esi, r14d
    dec  esi
    sub  esi, r9d
.store:
    imul esi, r10d
    add  esi, edi
    mov  eax, [r12]
    mov  [r13 + rsi * 4], eax
    add  r12, 4
    inc  r9d
    cmp  r9d, r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .pixel
    inc  r8d
    cmp  r8d, r15d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .row
    mov  ecx, r14d
    imul ecx, r15d
    mov  rdi, r12
    mov  eax, ecx
    shl  rax, 2
    sub  rdi, rax
    mov  rsi, r13
    IMG_COLD_MEMORY movsd                        ; publish canonical RGBA at allocation base
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Re-scan only the SHA-bound, privately re-probed snapshot. Copy consecutive
; IDAT bytes into RDX (capacity >= source length); return RAX=compressed length.
img_png_collect:
    lea  r8, [rdi + 8]
    mov  r9, rdx
    mov  qword [rel img_png_palette], 0
    mov  qword [rel img_png_alpha], 0
    mov  dword [rel img_png_alpha_n], 0
.loop:
    mov  r11d, [r8]
    bswap r11d
    lea  rsi, [r8 + 8]
    cmp  dword [r8 + 4], 'PLTE'
    jne  .alpha
    mov  [rel img_png_palette], rsi
    mov  eax, r11d
    xor  edx, edx
    mov  ecx, 3
    div  ecx
    mov  [rel img_png_palette_n], eax
.alpha:
    cmp  dword [r8 + 4], 'tRNS'
    jne  .idat
    mov  [rel img_png_alpha], rsi
    mov  [rel img_png_alpha_n], r11d
.idat:
    cmp  dword [r8 + 4], 'IDAT'
    jne  .next
    mov  rdi, r9
    mov  ecx, r11d
    IMG_COLD_MEMORY movsb
    mov  r9, rdi
.next:
    cmp  dword [r8 + 4], 'IEND'
    je   .done
    lea  r8, [r8 + 12 + r11]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .loop
.done:
    mov  rax, r9
    sub  rax, [rel img_png_compressed]
    ret

img_png_decode_surface:
    IMG_COLD_PUBLIC_GUARD
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 400
    mov  dword [rsp + 384], 1
    jmp  img_png_decode.admit
img_png_decode:
    IMG_COLD_PUBLIC_GUARD
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 400
    mov  dword [rsp + 384], 0
.admit:
    mov  r12, rdi
    mov  r13, rsi
    cmp  dword [rsp + 384], 0
    jne  .surface_probe
    call img_png_probe
    jmp  .probed
.surface_probe:
    call img_png_probe_surface
.probed:
    test eax, eax
    jnz  .out
    mov  [rsp + 376], r9d               ; displayed probe geometry is not IHDR
    mov  r14d, ecx                      ; size only from qualified probe outputs
    mov  r15d, edx
    cmp  r9d, 5
    jb   .stored_geometry
    xchg r14d, r15d                     ; undo displayed axes for pass layout
.stored_geometry:
    mov  ebp, r8d                         ; actual packed bits/pixel, GA=16
    ; Invocation-local pass descriptors: width,height,stride,x0,y0,dx,dy,bytes.
    ; Full-image caps imply each product and the seven-pass sum fit32 bits.
    mov  [rsp + 80], r14d
    mov  [rsp + 84], r15d
    movzx eax, byte [r12 + 28]
    mov  [rsp + 100], eax
    mov  dword [rsp + 88], 0
    mov  dword [rsp + 92], 7
    test eax, eax
    jnz  .layout_start
    mov  dword [rsp + 88], 7            ; identity pass for non-interlaced PNG
    mov  dword [rsp + 92], 8
.layout_start:
    mov  eax, [rsp + 88]
    mov  [rsp + 96], eax
    mov  qword [rel img_png_filtered_len], 0
.layout:
    mov  eax, [rsp + 96]
    mov  edi, r14d
    mov  esi, r15d
    call img_png_pass_layout
    mov  ebx, [rsp + 96]
    shl  ebx, 5
    lea  rdi, [rsp + 112 + rbx]
    mov  [rdi], eax
    mov  [rdi + 4], ecx
    mov  [rdi + 8], edx
    mov  [rdi + 12], r8d
    mov  [rdi + 16], r9d
    mov  [rdi + 20], r10d
    mov  [rdi + 24], r11d
    test eax, eax
    jz   .empty_pass
    test ecx, ecx
    jz   .empty_pass
    lea  eax, [rdx + 1]
    imul eax, ecx
    jmp  .layout_bytes
.empty_pass:
    xor  eax, eax                       ; no filter byte for either empty axis
.layout_bytes:
    mov  [rdi + 28], eax
    add  [rel img_png_filtered_len], rax
    jc   .bounds
    inc  dword [rsp + 96]
    mov  eax, [rsp + 96]
    cmp  eax, [rsp + 92]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .layout
    mov  r11, [rel img_png_filtered_len]
    mov  eax, r14d
    imul rax, r15
    shl  rax, 2
    mov  [rel img_png_raw_offset], rax   ; canonical RGBA byte count
    add  rax, r11                        ; RGBA + filtered scratch
    add  rax, 15
    and  rax, -16
    mov  [rsp + 64], rax                 ; private source offset
    add  rax, r13
    mov  [rsp + 72], rax                 ; concatenated IDAT offset
    add  rax, r13                        ; source length also bounds IDAT sum
    cmp  dword [rsp + 376], 1
    je   .allocation_size
    add  rax, [rel img_png_raw_offset]   ; private orientation scratch, <=64MiB
.allocation_size:
    mov  [rel img_png_total_alloc], rax
    lea  rdi, [rsp]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST                     ; admission digest before allocator seam
    mov  rdi, [rel img_png_total_alloc]
    call img_output_alloc
    test rax, rax
    jz   .oom
    mov  rdi, rax
    add  rdi, [rsp + 64]
    mov  rsi, r12
    mov  rcx, r13
    IMG_COLD_MEMORY movsb
    mov  r12, [rel img_active_out]
    add  r12, [rsp + 64]
    lea  rdi, [rsp + 32]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    lea  rdi, [rsp]
    lea  rsi, [rsp + 32]
    mov  ecx, 32
    repe cmpsb
    jne  .corrupt_release
    mov  rdi, r12
    mov  rsi, r13
    cmp  dword [rsp + 384], 0
    jne  .private_surface_probe
    call img_png_probe                   ; private grammar revalidation
    jmp  .private_probed
.private_surface_probe:
    call img_png_probe_surface
.private_probed:
    test eax, eax
    jnz  .corrupt_release
    cmp  r9d, [rsp + 376]
    jne  .corrupt_release
    mov  eax, [r12 + 16]
    bswap eax
    cmp  eax, r14d
    jne  .corrupt_release
    mov  eax, [r12 + 20]
    bswap eax
    cmp  eax, r15d
    jne  .corrupt_release
    cmp  r8d, ebp
    jne  .corrupt_release
    movzx eax, byte [r12 + 28]
    cmp  eax, [rsp + 100]
    jne  .corrupt_release                 ; layout belongs to private IHDR
    mov  [rel img_active_src], r12
    mov  [rel img_active_len], r13
    mov  rdx, [rel img_active_out]
    add  rdx, [rsp + 72]
    mov  [rel img_png_compressed], rdx
    mov  rdi, r12
    mov  rsi, r13
    call img_png_collect
    mov  rsi, rax
    mov  rdi, [rel img_png_compressed]
    ; Inflate into scratch, never over RGBA, source, palette, alpha or IDAT.
    mov  rdx, [rel img_active_out]
    add  rdx, [rel img_png_raw_offset]   ; inflate only into the scratch span
    mov  rcx, [rel img_png_filtered_len]
    call img_zlib_inflate
    jc   .corrupt_release
    cmp  rax, [rel img_png_filtered_len]
    jne  .corrupt_release
    mov  rax, [rel img_active_out]
    add  rax, [rel img_png_raw_offset]
    mov  [rsp + 104], rax                ; next pass's filtered bytes
    mov  eax, [rsp + 88]
    mov  [rsp + 96], eax
.pass_begin:
    mov  eax, [rsp + 96]
    cmp  eax, [rsp + 92]
    jae  .passes_done
    shl  eax, 5
    lea  rbx, [rsp + 112 + rax]
    cmp  dword [rbx + 28], 0
    je   .pass_done
    mov  r14d, [rbx]
    mov  r15d, [rbx + 4]
    mov  r10d, [rbx + 8]
    mov  eax, [rbx + 20]
    shl  eax, 2
    mov  [rsp + 368], eax                ; canonical destination pixel step
    mov  r9, [rsp + 104]
    xor  r8d, r8d                       ; previous row resets for every pass
.filter_row:
    cmp  r8d, r15d
    jae  .convert
    mov  eax, r10d
    inc  eax
    imul eax, r8d
    lea  rsi, [r9 + rax]
    movzx eax, byte [rsi]
    inc  rsi                              ; row data
    cmp  eax, 0
    je   .filter_next
    cmp  eax, 1
    je   .sub
    cmp  eax, 2
    je   .up
    cmp  eax, 3
    je   .avg
    cmp  eax, 4
    je   .paeth
    jmp  .corrupt_release
.sub:
    xor  ecx, ecx
.sub_loop:
    cmp  ecx, r10d
    jae  .filter_next
    mov  edx, ebp
    add  edx, 7
    shr  edx, 3
    cmp  ecx, edx
    jb   .sub_store
    mov  eax, ecx
    sub  eax, edx
    mov  al, [rsi + rax]
    add  [rsi + rcx], al
.sub_store:
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .sub_loop
.up:
    test r8d, r8d
    jz   .filter_next
    xor  ecx, ecx
.up_loop:
    cmp  ecx, r10d
    jae  .filter_next
    mov  eax, r10d
    inc  eax
    lea  rdi, [rsi + rcx]
    sub  rdi, rax
    mov  dl, [rdi]
    add  [rsi + rcx], dl
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .up_loop
.avg:
    xor  ecx, ecx
.avg_loop:
    cmp  ecx, r10d
    jae  .filter_next
    xor  eax, eax                         ; left
    mov  edx, ebp
    add  edx, 7
    shr  edx, 3
    cmp  ecx, edx
    jb   .avg_no_left
    mov  eax, ecx
    sub  eax, edx
    movzx eax, byte [rsi + rax]
.avg_no_left:
    mov  ebx, eax                         ; preserve left while locating prior row
    xor  edx, edx                         ; up
    test r8d, r8d
    jz   .avg_have
    mov  edi, r10d
    inc  edi
    lea  rax, [rsi + rcx]
    sub  rax, rdi
    movzx edx, byte [rax]
.avg_have:
    mov  eax, ebx
    add  eax, edx
    shr  eax, 1
    add  [rsi + rcx], al
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .avg_loop
.paeth:
    xor  ecx, ecx
.paeth_loop:
    cmp  ecx, r10d
    jae  .filter_next
    xor  eax, eax                         ; a
    mov  edx, ebp
    add  edx, 7
    shr  edx, 3
    cmp  ecx, edx
    jb   .pa_no_a
    mov  eax, ecx
    sub  eax, edx
    movzx eax, byte [rsi + rax]
.pa_no_a:
    push rax                              ; preserve a while locating b/c
    xor  edi, edi                         ; b
    xor  r11d, r11d                       ; c
    test r8d, r8d
    jz   .pa_choose
    mov  r12d, r10d
    inc  r12d
    lea  rax, [rsi + rcx]
    sub  rax, r12
    movzx edi, byte [rax]
    cmp  ecx, edx
    jb   .pa_choose
    mov  r13d, ecx
    sub  r13d, edx
    lea  rax, [rsi + r13]
    sub  rax, r12
    movzx r11d, byte [rax]
.pa_choose:
    pop  rax
    push rax                              ; keep predictor a across abs scratch
    ; predictor p=a+b-c; choose nearest with pa<=pb && pa<=pc.
    mov  r12d, eax
    add  r12d, edi
    sub  r12d, r11d
    mov  r13d, r12d
    sub  r13d, eax
    call img_abs_r13d
    mov  edx, r13d                         ; pa
    mov  r13d, r12d
    sub  r13d, edi
    call img_abs_r13d
    mov  ebx, r13d                         ; pb
    mov  r13d, r12d
    sub  r13d, r11d
    call img_abs_r13d                     ; pc
    pop  rax                              ; restore a for the winning-a path
    cmp  edx, ebx
    jg   .pa_not_a
    cmp  edx, r13d
    jg   .pa_not_a
    jmp  .pa_add
.pa_not_a:
    mov  eax, edi
    cmp  ebx, r13d
    jle  .pa_add
    mov  eax, r11d
.pa_add:
    add  [rsi + rcx], al
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .paeth_loop
.filter_next:
    inc  r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .filter_row

.convert:
    ; Restore caller-owned source registers overwritten by Paeth scratch, then
    ; port the proven monolith's forward per-row conversion.  The raw scanlines
    ; live after the RGBA span, so writes cannot corrupt unread source bytes.
    mov  r12, [rel img_active_src]
    mov  r13, [rel img_active_len]
    mov  r11, r9                          ; filtered scratch base
    mov  r9, [rel img_active_out]         ; canonical RGBA base
    xor  r8d, r8d                          ; y
.convert_row:
    cmp  r8d, r15d
    jae  .pass_done
    mov  eax, r10d
    inc  eax
    imul eax, r8d
    inc  eax
    lea  rsi, [r11 + rax]                 ; reconstructed source row
    mov  eax, [rsp + 96]
    shl  eax, 5
    lea  rbx, [rsp + 112 + rax]
    mov  eax, [rbx + 24]
    imul eax, r8d
    add  eax, [rbx + 16]
    imul eax, [rsp + 80]                ; full destination width, not pass width
    add  eax, [rbx + 12]
    shl  eax, 2
    lea  rdi, [r9 + rax]                  ; scatter row origin in canonical RGBA
    xor  ecx, ecx
.convert_pixel:
    cmp  ecx, r14d
    jae  .convert_next_row
    cmp  byte [r12 + 24], 16             ; private IHDR distinguishes G16/GA8
    je   .pixel16
    cmp  ebp, 16
    je   .gray_alpha_pixel
    cmp  ebp, 8
    jbe  .indexed_pixel
    mov  al, [rsi]
    mov  [rdi], al
    mov  al, [rsi + 1]
    mov  [rdi + 1], al
    mov  al, [rsi + 2]
    mov  [rdi + 2], al
    mov  byte [rdi + 3], 0xFF
    cmp  ebp, 32
    jne  .rgb8_key
    mov  al, [rsi + 3]
    mov  [rdi + 3], al
    jmp  .convert_advance
.rgb8_key:
    cmp  dword [rel img_png_alpha_n], 6
    jne  .convert_advance
    ; PNG3 tRNS: compare all original RGB8 samples with the low byte of
    ; each BE16 key. Keep straight RGB, even when the resulting alpha is zero.
    ; Both the key and samples belong to the verified private snapshot.
    mov  rax, [rel img_png_alpha]
    mov  dl, [rsi]
    cmp  dl, [rax + 1]
    jne  .convert_advance
    mov  dl, [rsi + 1]
    cmp  dl, [rax + 3]
    jne  .convert_advance
    mov  dl, [rsi + 2]
    cmp  dl, [rax + 5]
    jne  .convert_advance
    mov  byte [rdi + 3], 0
.convert_advance:
    mov  eax, ebp
    shr  eax, 3
    add  rsi, rax
    mov  eax, [rsp + 368]
    add  rdi, rax
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .convert_pixel
.pixel16:
    mov  byte [rdi + 3], 255
    cmp  byte [r12 + 25], 4
    je   .pixel16_ga_alpha
    cmp  byte [r12 + 25], 6
    je   .pixel16_rgba_alpha
    cmp  dword [rel img_png_alpha_n], 0
    je   .pixel16_color
    mov  rax, [rel img_png_alpha]        ; owned original key, before reduction
    movzx edx, word [rsi]
    xor  dx, [rax]                      ; equality of both network-order bytes
    cmp  byte [r12 + 25], 0
    je   .pixel16_key_compare
    movzx ebx, word [rsi + 2]
    xor  bx, [rax + 2]
    or   edx, ebx
    movzx ebx, word [rsi + 4]
    xor  bx, [rax + 4]
    or   edx, ebx                       ; all three original channels must match
.pixel16_key_compare:
    test edx, edx
    jnz  .pixel16_color
    mov  byte [rdi + 3], 0
    jmp  .pixel16_color
.pixel16_ga_alpha:
    movzx eax, word [rsi + 2]
    jmp  .pixel16_alpha
.pixel16_rgba_alpha:
    movzx eax, word [rsi + 6]
.pixel16_alpha:
    call img_png_reduce16
    mov  [rdi + 3], al                  ; straight alpha, including zero
.pixel16_color:
    movzx eax, word [rsi]
    call img_png_reduce16
    mov  [rdi], al
    cmp  byte [r12 + 25], 0
    je   .pixel16_gray
    cmp  byte [r12 + 25], 4
    je   .pixel16_gray
    movzx eax, word [rsi + 2]
    call img_png_reduce16
    mov  [rdi + 1], al
    movzx eax, word [rsi + 4]
    call img_png_reduce16
    mov  [rdi + 2], al
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .convert_advance
.pixel16_gray:
    mov  [rdi + 1], al
    mov  [rdi + 2], al
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .convert_advance
.indexed_pixel:
    ; MSB-first packed index, independently restarted at each scanline.
    mov  eax, ecx
    imul eax, ebp
    mov  edx, eax
    shr  eax, 3
    movzx ebx, byte [rsi + rax]
    and  edx, 7
    push rcx
    mov  ecx, 8
    sub  ecx, ebp
    sub  ecx, edx
    shr  ebx, cl
    mov  ecx, ebp
    mov  eax, 1
    shl  eax, cl
    dec  eax
    and  ebx, eax
    pop  rcx
    cmp  byte [r12 + 25], 0
    je   .gray_pixel                    ; EBX=original sample, EAX=sample mask
    cmp  ebx, [rel img_png_palette_n]
    jae  .corrupt_release                 ; even fully transparent pixels validate
    lea  rax, [rbx + rbx*2]
    add  rax, [rel img_png_palette]
    mov  dl, [rax]
    mov  [rdi], dl
    mov  dl, [rax + 1]
    mov  [rdi + 1], dl
    mov  dl, [rax + 2]
    mov  [rdi + 2], dl
    mov  byte [rdi + 3], 255
    cmp  ebx, [rel img_png_alpha_n]
    jae  .indexed_next
    mov  rax, [rel img_png_alpha]
    mov  dl, [rax + rbx]
    mov  [rdi + 3], dl
.gray_next:
.indexed_next:
    mov  eax, [rsp + 368]
    add  rdi, rax
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .convert_pixel
.gray_alpha_pixel:
    mov  al, [rsi]
    mov  [rdi], al
    mov  [rdi + 1], al
    mov  [rdi + 2], al
    mov  al, [rsi + 1]
    mov  [rdi + 3], al                  ; straight alpha, including zero
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .convert_advance
.gray_pixel:
    ; All supported max samples divide255 exactly (1,3,15,255).
    push rcx
    mov  ecx, eax                       ; original precision maximum
    imul eax, ebx, 255
    xor  edx, edx
    div  ecx                           ; exact linear expansion to8-bit
    pop  rcx
    mov  [rdi], al
    mov  [rdi + 1], al
    mov  [rdi + 2], al
    mov  byte [rdi + 3], 255
    cmp  dword [rel img_png_alpha_n], 2
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .gray_next
    mov  rax, [rel img_png_alpha]        ; SHA-owned tRNS, never caller bytes
    movzx edx, word [rax]
    rol  dx, 8                         ; BE16 -> native, then mask per PNG3
    push rcx
    mov  ecx, ebp
    mov  eax, 1
    shl  eax, cl
    dec  eax
    and  edx, eax
    pop  rcx
    cmp  edx, ebx                       ; compare before sample expansion
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .gray_next
    mov  byte [rdi + 3], 0
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .gray_next
.convert_next_row:
    inc  r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .convert_row
.pass_done:
    mov  eax, [rsp + 96]
    shl  eax, 5
    mov  eax, [rsp + 112 + rax + 28]
    add  [rsp + 104], rax
    inc  dword [rsp + 96]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .pass_begin
.passes_done:
    mov  rax, [rel img_active_out]
    add  rax, [rel img_png_raw_offset]
    add  rax, [rel img_png_filtered_len]
    cmp  rax, [rsp + 104]
    jne  .corrupt_release
    mov  r14d, [rsp + 80]
    mov  r15d, [rsp + 84]
    cmp  dword [rsp + 376], 1
    je   .success
    mov  rdi, [rel img_active_out]
    mov  rsi, rdi
    add  rsi, [rel img_png_total_alloc]
    sub  rsi, [rel img_png_raw_offset]   ; after all snapshot/IDAT storage
    mov  ecx, r14d
    mov  edx, r15d
    mov  r8d, [rsp + 376]
    call img_png_orient
    cmp  dword [rsp + 376], 5
    jb   .success
    xchg r14d, r15d
.success:
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    call img_codec_state_clear
    mov  rbx, [rel img_active_out]
    mov  ecx, r14d
    mov  edx, r15d
    mov  r8d, IMG_FMT_PNG
    xor  eax, eax
    jmp  .out
.corrupt_release:
    call img_output_release
    mov  eax, IMG_E_CORRUPT
    jmp  .out
.oom:
    mov  eax, IMG_E_OOM
    jmp  .out
.bounds:
    mov  eax, IMG_E_BOUNDS
.out:
    test eax, eax
    jz   .ret
    call img_refusal_clear
.ret:
    add  rsp, 400
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; PNG3 8.1/13.10: x0,y0,log2(dx),log2(dy), followed by identity pass.
; Read-only geometry; no mutable cross-call pass state.
img_png_passes:
    db 0,0,3,3
    db 4,0,3,3
    db 0,4,2,3
    db 2,0,2,2
    db 0,2,1,2
    db 1,0,1,1
    db 0,1,0,1
    db 0,0,0,0

; EAX=pass, EDI/ESI=full dimensions, EBP=bits/pixel.
; EAX/ECX=pass dimensions, EDX=stride, R8/R9=origin, R10/R11=steps.
; Preserves R12..R15 and EBP. All arithmetic follows admitted full-image caps.
img_png_pass_layout:
    lea  rbx, [rel img_png_passes]
    lea  rbx, [rbx + rax*4]
    movzx r8d, byte [rbx]
    movzx r9d, byte [rbx + 1]
    movzx ecx, byte [rbx + 2]
    mov  r10d, 1
    shl  r10d, cl
    xor  eax, eax
    cmp  edi, r8d
    jbe  .width_ready
    sub  edi, r8d
    lea  eax, [rdi + r10 - 1]
    shr  eax, cl
.width_ready:
    movzx ecx, byte [rbx + 3]
    mov  r11d, 1
    shl  r11d, cl
    xor  edx, edx
    cmp  esi, r9d
    jbe  .height_ready
    sub  esi, r9d
    lea  edx, [rsi + r11 - 1]
    shr  edx, cl
.height_ready:
    mov  ecx, edx
    mov  edx, eax
    imul edx, ebp
    add  edx, 7
    shr  edx, 3
    ret

; EAX=zero-extended network-order word; EAX=result8. Clobbers EBX/EDX only.
; round(v*255/65535) = floor((v+128)/257); no half-way ties for integer v.
img_png_reduce16:
    rol  ax, 8
    add  eax, 128
    xor  edx, edx
    mov  ebx, 257
    div  ebx
    ret

img_abs_r13d:
    mov  eax, r13d
    sar  eax, 31
    xor  r13d, eax
    sub  r13d, eax
    ret

; img_zlib_inflate(RDI=zlib, ESI=len, RDX=out, RCX=cap) -> RAX=len, CF error.
img_zlib_inflate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    ; Preserve the output span before the CMF/FLG modulus check uses EDX:EAX.
    ; Saving RDX after DIV loses the caller's pointer (EDX is the remainder).
    mov  r14, rdx
    mov  r15, r14
    add  r15, rcx
    cmp  rsi, 7
    jb   .error
    cmp  byte [rdi], 0x80
    jae  .error
    movzx eax, byte [rdi]
    and  eax, 0x0F
    cmp  eax, 8
    jne  .error
    movzx eax, byte [rdi]
    shl  eax, 8
    movzx ebx, byte [rdi + 1]
    or   eax, ebx
    xor  edx, edx
    mov  ebx, 31
    div  ebx
    test edx, edx
    jnz  .error
    test byte [rdi + 1], 0x20
    jnz  .error
    movzx ecx, byte [rdi]
    shr  ecx, 4
    add  ecx, 8
    mov  eax, 1
    shl  eax, cl
    mov  [rel img_df_window], eax
    lea  r12, [rdi + 2]
    lea  r13, [rdi + rsi - 4]
    mov  [rel img_df_out_start], r14
    xor  ebp, ebp
    xor  ebx, ebx
.block:
    mov  ecx, 1
    call img_df_bits
    jc   .error
    mov  [rel img_df_final], eax
    mov  ecx, 2
    call img_df_bits
    jc   .error
    test eax, eax
    jz   .stored
    cmp  eax, 1
    je   .fixed
    cmp  eax, 2
    je   .dynamic
    jmp  .error
.stored:
    xor  ebp, ebp
    xor  ebx, ebx
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .error
    movzx ecx, word [r12]
    movzx eax, word [r12 + 2]
    xor  eax, 0xFFFF
    cmp  eax, ecx
    jne  .error
    add  r12, 4
    lea  rax, [r12 + rcx]
    cmp  rax, r13
    ja   .error
    lea  rax, [r14 + rcx]
    cmp  rax, r15
    ja   .error
    mov  rsi, r12
    mov  rdi, r14
    IMG_COLD_MEMORY movsb
    mov  r12, rsi
    mov  r14, rdi
    cmp  dword [rel img_df_final], 1
    je   .finish
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.fixed:
    mov  dword [rel img_df_lit_n], 288
    mov  dword [rel img_df_dist_n], 32
    lea  rdi, [rel img_df_lens]
    xor  ecx, ecx
.fx:
    mov  al, 8
    cmp  ecx, 144
    jb   .fx_store
    mov  al, 9
    cmp  ecx, 256
    jb   .fx_store
    mov  al, 7
    cmp  ecx, 280
    jb   .fx_store
    mov  al, 8
.fx_store:
    mov  [rdi + rcx], al
    inc  ecx
    cmp  ecx, 288
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .fx
    lea  rdi, [rel img_df_lens]
    mov  esi, 288
    lea  rdx, [rel img_df_lit_codes]
    lea  rcx, [rel img_df_lit_bits]
    call img_df_build
    jc   .error
    lea  rdi, [rel img_df_lens]
    mov  ecx, 32
.fxd:
    mov  byte [rdi + rcx - 1], 5
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    loop .fxd
    lea  rdi, [rel img_df_lens]
    mov  esi, 32
    lea  rdx, [rel img_df_dist_codes]
    lea  rcx, [rel img_df_dist_bits]
    call img_df_build
    jc   .error
    jmp  .codes
.dynamic:
    mov  ecx, 5
    call img_df_bits
    jc   .error
    add  eax, 257
    cmp  eax, 286
    ja   .error
    mov  [rel img_df_hlit], eax
    mov  ecx, 5
    call img_df_bits
    jc   .error
    inc  eax
    cmp  eax, 32
    ja   .error
    mov  [rel img_df_hdist], eax
    mov  ecx, 4
    call img_df_bits
    jc   .error
    add  eax, 4
    mov  [rel img_df_hclen], eax
    lea  rdi, [rel img_df_cl_lens]
    xor  eax, eax
    mov  ecx, 19
    IMG_COLD_MEMORY stosb
    xor  esi, esi
.read_cl:
    cmp  esi, [rel img_df_hclen]
    jae  .build_cl
    mov  ecx, 3
    call img_df_bits
    jc   .error
    lea  rdi, [rel img_df_cl_order]
    movzx edx, byte [rdi + rsi]
    lea  rdi, [rel img_df_cl_lens]
    mov  [rdi + rdx], al
    inc  esi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .read_cl
.build_cl:
    lea  rdi, [rel img_df_cl_lens]
    mov  esi, 19
    lea  rdx, [rel img_df_cl_codes]
    lea  rcx, [rel img_df_cl_bits]
    call img_df_build
    jc   .error
    mov  eax, [rel img_df_hlit]
    add  eax, [rel img_df_hdist]
    mov  [rel img_df_total], eax
    xor  esi, esi
.read_lens:
    cmp  esi, [rel img_df_total]
    jae  .build_dyn
    lea  rdi, [rel img_df_cl_codes]
    lea  rdx, [rel img_df_cl_bits]
    mov  ecx, 19
    call img_df_symbol
    jc   .error
    cmp  eax, 16
    jb   .literal_len
    cmp  eax, 16
    je   .repeat_prev
    cmp  eax, 17
    je   .repeat_zero3
    cmp  eax, 18
    jne  .error
    mov  ecx, 7
    call img_df_bits
    jc   .error
    add  eax, 11
    xor  edx, edx
    jmp  .repeat
.repeat_zero3:
    mov  ecx, 3
    call img_df_bits
    jc   .error
    add  eax, 3
    xor  edx, edx
    jmp  .repeat
.repeat_prev:
    test esi, esi
    jz   .error
    mov  ecx, 2
    call img_df_bits
    jc   .error
    add  eax, 3
    lea  rdi, [rel img_df_lens]
    movzx edx, byte [rdi + rsi - 1]
.repeat:
    mov  ecx, eax
    mov  eax, esi
    add  eax, ecx
    cmp  eax, [rel img_df_total]
    ja   .error
    lea  rdi, [rel img_df_lens]
.rep_loop:
    mov  [rdi + rsi], dl
    inc  esi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    loop .rep_loop
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .read_lens
.literal_len:
    lea  rdi, [rel img_df_lens]
    mov  [rdi + rsi], al
    inc  esi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .read_lens
.build_dyn:
    cmp  byte [rel img_df_lens + 256], 0
    je   .error                         ; literal tree must contain end-of-block
    mov  eax, [rel img_df_hlit]
    mov  [rel img_df_lit_n], eax
    mov  eax, [rel img_df_hdist]
    mov  [rel img_df_dist_n], eax
    lea  rdi, [rel img_df_lens]
    mov  esi, [rel img_df_hlit]
    lea  rdx, [rel img_df_lit_codes]
    lea  rcx, [rel img_df_lit_bits]
    call img_df_build
    jc   .error
    lea  rdi, [rel img_df_lens]
    mov  eax, [rel img_df_hlit]
    add  rdi, rax
    mov  esi, [rel img_df_hdist]
    lea  rdx, [rel img_df_dist_codes]
    lea  rcx, [rel img_df_dist_bits]
    call img_df_build
    jc   .error
.codes:
    lea  rdi, [rel img_df_lit_codes]
    lea  rdx, [rel img_df_lit_bits]
    mov  ecx, [rel img_df_lit_n]
    call img_df_symbol
    jc   .error
    cmp  eax, 256
    jb   .emit_literal
    je   .eob
    sub  eax, 257
    cmp  eax, 28
    ja   .error
    mov  esi, eax
    lea  rdi, [rel img_df_len_base]
    movzx edi, word [rdi + rsi * 2]
    lea  rdx, [rel img_df_len_extra]
    movzx ecx, byte [rdx + rsi]
    test ecx, ecx
    jz   .len_ready
    push rdi
    call img_df_bits
    pop  rdi
    jc   .error
    add  edi, eax
.len_ready:
    push rdi
    lea  rdi, [rel img_df_dist_codes]
    lea  rdx, [rel img_df_dist_bits]
    mov  ecx, [rel img_df_dist_n]
    call img_df_symbol
    jc   .pop_error
    cmp  eax, 29
    ja   .pop_error
    mov  esi, eax
    lea  rdi, [rel img_df_dist_base]
    movzx edi, word [rdi + rsi * 2]
    lea  rdx, [rel img_df_dist_extra]
    movzx ecx, byte [rdx + rsi]
    test ecx, ecx
    jz   .dist_ready
    push rdi
    call img_df_bits
    pop  rdi
    jc   .pop_error
    add  edi, eax
.dist_ready:
    cmp  edi, [rel img_df_window]
    ja   .pop_error
    pop  rcx                              ; length
    test edi, edi
    jz   .error
    mov  rsi, r14
    sub  rsi, rdi
    cmp  rsi, [rel img_df_out_start]
    jb   .error
.copy_match:
    test ecx, ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .codes
    cmp  r14, r15
    jae  .error
    mov  al, [rsi]
    mov  [r14], al
    inc  rsi
    inc  r14
    dec  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .copy_match
.pop_error:
    pop  rax
    jmp  .error
.emit_literal:
    cmp  r14, r15
    jae  .error
    mov  [r14], al
    inc  r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .codes
.eob:
    cmp  dword [rel img_df_final], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .block
.finish:
    cmp  r12, r13                       ; bounded profile: no extra DEFLATE bytes
    jne  .error
    ; Adler-32 over output must match the zlib trailer.
    mov  rdi, [rel img_df_out_start]
    mov  rsi, r14
    sub  rsi, rdi
    call img_adler32
    mov  edx, [r13]
    bswap edx
    cmp  eax, edx
    jne  .error
    mov  rax, r14
    sub  rax, [rel img_df_out_start]
    clc
    jmp  .out
.error:
    xor  eax, eax
    stc
.out:
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bit reader, LSB-first. State is R12/R13 + EBP/EBX owned by inflater.
img_df_bits:
    push rdx
    mov  edx, ecx
.fill:
    cmp  ebx, edx
    jae  .take
    cmp  r12, r13
    jae  .eof
    movzx eax, byte [r12]
    inc  r12
    mov  ecx, ebx
    shl  eax, cl
    or   ebp, eax
    add  ebx, 8
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .fill
.take:
    mov  eax, 1
    mov  ecx, edx
    shl  eax, cl
    dec  eax
    and  eax, ebp
    shr  ebp, cl
    sub  ebx, edx
    clc
    pop  rdx
    ret
.eof:
    xor  eax, eax
    stc
    pop  rdx
    ret

; Build reversed canonical codes. RDI=lens, ESI=n, RDX=codes(dw), RCX=bits(db).
img_df_build:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  rbx, rcx
    lea  rdi, [rel img_df_counts]
    xor  eax, eax
    mov  ecx, 16
    IMG_COLD_MEMORY stosw
    xor  esi, esi
.count:
    cmp  esi, r13d
    jae  .next
    movzx eax, byte [r12 + rsi]
    test eax, eax
    jz   .count_next
    cmp  eax, 15
    ja   .bad
    lea  rdi, [rel img_df_counts]
    inc  word [rdi + rax * 2]
.count_next:
    inc  esi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .count
.next:
    mov  eax, 1
    mov  edx, 1
.tree_space:
    shl  eax, 1
    lea  rdi, [rel img_df_counts]
    movzx ecx, word [rdi + rdx*2]
    sub  eax, ecx
    js   .bad
    inc  edx
    cmp  edx, 16
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .tree_space
    test eax, eax
    jz   .tree_valid
    cmp  eax, 32768
    jne  .nonempty_tree
    lea  rdi, [rel img_df_dist_codes]
    cmp  r14, rdi
    je   .tree_valid                   ; no distance codes when no matches occur
.nonempty_tree:
    lea  rdi, [rel img_df_counts]
    cmp  word [rdi + 2], 1
    jne  .bad
    cmp  eax, 16384
    jne  .bad
    lea  rdi, [rel img_df_cl_lens]
    cmp  r12, rdi
    je   .bad
.tree_valid:
    xor  eax, eax
    mov  edx, 1
.next_loop:
    cmp  edx, 16
    jae  .assign
    lea  rdi, [rel img_df_counts]
    movzx ecx, word [rdi + rdx * 2 - 2]
    add  eax, ecx
    shl  eax, 1
    lea  rdi, [rel img_df_next]
    mov  [rdi + rdx * 2], ax
    inc  edx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .next_loop
.assign:
    xor  esi, esi
.assign_loop:
    cmp  esi, r13d
    jae  .ok
    movzx ecx, byte [r12 + rsi]
    mov  [rbx + rsi], cl
    test ecx, ecx
    jz   .zero
    lea  rdi, [rel img_df_next]
    movzx eax, word [rdi + rcx * 2]
    inc  word [rdi + rcx * 2]
    xor  edi, edi
    xor  edx, edx
.reverse:
    bt   eax, edx
    adc  edi, edi
    inc  edx
    cmp  edx, ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .reverse
    mov  [r14 + rsi * 2], di
    jmp  .assigned
.zero:
    mov  word [r14 + rsi * 2], 0
.assigned:
    inc  esi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .assign_loop
.bad:
    stc
    jmp  .out
.ok:
    clc
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Decode one symbol from reversed-code arrays. RDI=codes, RDX=bits, ECX=n.
; EBX is deliberately not preserved here: it is the inflater's live bit count,
; and img_df_bits must commit every consumed Huffman bit back to that state.
img_df_symbol:
    push rsi
    push r8
    push r9
    mov  r8d, ecx
    xor  r9d, r9d
    mov  esi, 1
.bit:
    push rdi
    push rdx
    mov  ecx, 1
    call img_df_bits
    pop  rdx
    pop  rdi
    jc   .error
    mov  ecx, esi
    dec  ecx
    shl  eax, cl
    or   r9d, eax
    xor  ecx, ecx
.scan:
    cmp  ecx, r8d
    jae  .next_bit
    cmp  byte [rdx + rcx], sil
    jne  .scan_next
    cmp  word [rdi + rcx * 2], r9w
    je   .found
.scan_next:
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .scan
.next_bit:
    inc  esi
    cmp  esi, 15
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jbe  .bit
.error:
    xor  eax, eax
    stc
    jmp  .out
.found:
    mov  eax, ecx
    clc
.out:
    pop  r9
    pop  r8
    pop  rsi
    ret

img_adler32:
    push rbx
    mov  eax, 1
    xor  ebx, ebx
.byte:
    test rsi, rsi
    jz   .done
    movzx ecx, byte [rdi]
    add  eax, ecx
    cmp  eax, 65521
    jb   .a_ok
    sub  eax, 65521
.a_ok:
    add  ebx, eax
    cmp  ebx, 65521
    jb   .b_ok
    sub  ebx, 65521
.b_ok:
    inc  rdi
    dec  rsi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .byte
.done:
    shl  ebx, 16
    or   eax, ebx
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_img_img_png_0 0
img_df_len_base:   dw 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
img_df_len_extra:  db 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
img_df_dist_base:  dw 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
img_df_dist_extra: db 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
img_df_cl_order:   db 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15

align 8
; img_png_state_begin..img_png_state_end moved to WDATA_gui_img_img_png_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_gui_img_img_png_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_img_img_png_0_bss1 0
resb 8                 ; keeps img_png_state_begin at its WDATA offset mod 64
alignb 8
img_png_state_begin:
img_df_out_start: resq 1
img_df_final:     resd 1
img_df_window:    resd 1
img_df_hlit:      resd 1
img_df_hdist:     resd 1
img_df_hclen:     resd 1
img_df_total:     resd 1
img_df_lit_n:     resd 1
img_df_dist_n:    resd 1
img_df_counts:    resw 16
img_df_next:      resw 16
img_df_cl_lens:   resb 19
img_df_cl_codes:  resw 19
img_df_cl_bits:   resb 19
img_df_lens:      resb 320
img_df_lit_codes: resw 288
img_df_lit_bits:  resb 288
img_df_dist_codes: resw 32
img_df_dist_bits: resb 32
img_png_stride:       resd 1
alignb 8
img_png_filtered_len: resq 1
img_png_raw_offset:   resq 1
img_png_palette:      resq 1
img_png_alpha:        resq 1
img_png_compressed:   resq 1
img_png_total_alloc:  resq 1
img_png_palette_n:    resd 1
img_png_alpha_n:      resd 1
img_png_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_gui_img_img_png_0_bss1
