;; MODULE gui/img/img_gif
;; LAYER 6
;; EXPORTS img_gif_probe, img_gif_decode, img_gif_clear
;; IMPORTS core/heap, core/lib/sha256
;; CAPS
;; OWNER saga:gui_image_pipeline

%include "gui/img/img_cold_hooks.inc"
;
; Native GIF87a/89a still slice: one image, global/local RGB
; table, GCE transparency, sequential/interlaced LZW (2..8 initial bits).
; Opaque subrectangles use logical-screen GCT background. Transparent or
; local-only partial canvases, animation, user-input, plain text,
; unknown application extensions and non-square pixel aspect unsupported.
; NETSCAPE2.0/ANIMEXTS1.0 loop metadata is inert for the sole still image.
; Grammar: exact trailer, initial clear, exact pixel count, EOI as last code
; followed by the sub-block terminator (unused final byte bits are ignored).
; Probe validates the complete LZW stream without allocation or pixel writes.
; Decode hashes before allocation and owns/requalifies a private file before
; any RGBA writes. All source/table/chain/output work is bounded; no partial
; output publishes. The dictionary freezes at4096 until the next clear.
; Reference: https://www.w3.org/Graphics/GIF/spec-gif89a.txt (CompuServe).

GIF_MAX_SOURCE equ 33554432

img_gif_clear:
    IMG_COLD_OWNER_ONLY
    push rax
    push rdi
    push rcx
    cld
    lea  rdi, [rel img_gif_state_begin]
    mov  ecx, img_gif_state_end - img_gif_state_begin
    xor  eax, eax
    IMG_COLD_MEMORY stosb
    pop  rcx
    pop  rdi
    pop  rax
    ret

img_gif_probe:
    IMG_COLD_PUBLIC_GUARD
    xor  edx, edx
    call img_gif_parse
    test eax, eax
    jnz  .bad
    mov  ebx, IMG_FMT_GIF
    mov  ecx, [rel img_gif_w]
    mov  edx, [rel img_gif_h]
    mov  r8d, [rel img_gif_depth]
    call img_gif_clear
    ret
.bad:
    jmp  img_refusal_clear

img_gif_decode:
    IMG_COLD_PUBLIC_GUARD
    push r12
    push r13
    push r14
    push rbp
    sub  rsp, 80                      ; two digests, width/height, RGBA tail
    cld
    mov  r12, rdi
    mov  r13, rsi
    mov  [rel img_active_src], rdi
    mov  [rel img_active_len], rsi
    xor  edx, edx
    call img_gif_parse
    test eax, eax
    jnz  .refuse
    mov  eax, [rel img_gif_w]
    mov  [rsp + 64], eax
    mov  ecx, [rel img_gif_h]
    mov  [rsp + 68], ecx
    imul eax, ecx
    shl  rax, 2
    add  rax, 15
    and  rax, -16
    mov  [rsp + 72], rax
    mov  rdi, rsp
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    mov  rdi, [rsp + 72]
    add  rdi, r13
    call img_output_alloc
    test rax, rax
    jz   .oom
    mov  r14, rax
    add  r14, [rsp + 72]
    mov  rdi, r14
    mov  rsi, r12
    mov  rcx, r13
    IMG_COLD_MEMORY movsb
    lea  rdi, [rsp + 32]
    mov  rsi, r14
    mov  rdx, r13
    IMG_COLD_DIGEST
    mov  rdi, rsp
    lea  rsi, [rsp + 32]
    mov  ecx, 32
    repe cmpsb
    jne  .changed
    ; Requalify the owned geometry BEFORE the output-writing parse. This also
    ; handles caller changes between the initial parse and initial digest.
    mov  rdi, r14
    mov  rsi, r13
    xor  edx, edx
    call img_gif_parse
    test eax, eax
    jnz  .release
    mov  eax, [rsp + 64]
    cmp  eax, [rel img_gif_w]
    jne  .changed
    mov  eax, [rsp + 68]
    cmp  eax, [rel img_gif_h]
    jne  .changed
    mov  rdi, r14
    mov  rsi, r13
    mov  rdx, [rel img_active_out]
    call img_gif_parse
    test eax, eax
    jnz  .release
    mov  [rel img_active_src], r14
    mov  rbx, [rel img_active_out]
    mov  ecx, [rsp + 64]
    mov  edx, [rsp + 68]
    mov  r8d, IMG_FMT_GIF
    call img_gif_clear
    xor  eax, eax
    jmp  .out
.changed:
    mov  eax, IMG_E_CORRUPT
.release:
    push rax
    call img_output_release
    pop  rax
    jmp  .refuse
.oom:
    mov  eax, IMG_E_OOM
.refuse:
    call img_refusal_clear
.out:
    add  rsp, 80
    pop  rbp
    pop  r14
    pop  r13
    pop  r12
    ret

; RDI/RSI = complete file; RDX = RGBA or0 (validate only).
img_gif_parse:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cld
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bounds
    cmp  rsi, GIF_MAX_SOURCE
    ja   .bounds
    cmp  rsi, 6
    jb   .truncated
    cmp  dword [r12], 'GIF8'
    jne  .magic
    cmp  word [r12 + 4], '7a'
    je   .version
    cmp  word [r12 + 4], '9a'
    jne  .magic
.version:
    cmp  rsi, 13
    jb   .truncated
    mov  r15, rdx
    call img_gif_clear
    mov  dword [rel img_gif_trans], -1
    movzx eax, byte [r12 + 4]
    mov  [rel img_gif_version], eax
    movzx eax, word [r12 + 6]
    test eax, eax
    jz   .bounds
    cmp  eax, IMG_MAX_DIM
    ja   .bounds
    mov  [rel img_gif_w], eax
    movzx ecx, word [r12 + 8]
    test ecx, ecx
    jz   .bounds
    cmp  ecx, IMG_MAX_DIM
    ja   .bounds
    mov  [rel img_gif_h], ecx
    imul eax, ecx
    cmp  eax, IMG_MAX_PIXELS
    ja   .bounds
    mov  [rel img_gif_canvas_pixels], eax
    cmp  byte [r12 + 12], 0
    jne  .unsupported
    xor  r14d, r14d
    movzx ebp, byte [r12 + 10]
    movzx ebx, byte [r12 + 11]
    add  r12, 13
    test ebp, 128
    jz   .block
    call img_gif_palette
    jc   .truncated
    cmp  ebx, [rel img_gif_colors]
    jae  .corrupt
    ; Snapshot the global background before a local table replaces R14. Read
    ; exactly three bytes: the last palette entry may touch the source bound.
    lea  edx, [ebx + ebx * 2]
    movzx eax, byte [r14 + rdx + 2]
    shl  eax, 8
    mov  al, [r14 + rdx + 1]
    shl  eax, 8
    mov  al, [r14 + rdx]
    or   eax, 0xff000000
    mov  [rel img_gif_background], eax
.block:
    cmp  r12, r13
    jae  .truncated
    movzx eax, byte [r12]
    inc  r12
    cmp  eax, 0x3b
    je   .trailer
    cmp  eax, 0x2c
    je   .image
    cmp  eax, 0x21
    jne  .corrupt
    cmp  dword [rel img_gif_version], '9'
    jne  .unsupported
    cmp  r12, r13
    jae  .truncated
    movzx eax, byte [r12]
    inc  r12
    cmp  eax, 0xfe
    je   .comment
    cmp  eax, 0xff
    je   .application
    cmp  eax, 0xf9
    jne  .unsupported                 ; no unimplemented rendering semantics
    cmp  dword [rel img_gif_gce], 0
    jne  .corrupt
    cmp  dword [rel img_gif_frames], 0
    jne  .corrupt
    lea  rax, [r12 + 6]
    cmp  rax, r13
    ja   .truncated
    cmp  byte [r12], 4
    jne  .corrupt
    cmp  byte [r12 + 5], 0
    jne  .corrupt
    movzx eax, byte [r12 + 1]
    test eax, 0xe0
    jnz  .corrupt
    test eax, 2
    jnz  .unsupported
    mov  ecx, eax
    shr  ecx, 2
    cmp  ecx, 3
    ja   .unsupported
    test eax, 1
    jz   .gce_done
    movzx ecx, byte [r12 + 4]
    mov  [rel img_gif_trans], ecx
.gce_done:
    mov  dword [rel img_gif_gce], 1
    add  r12, 6
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.application:
    ; A loop count has no observable effect for a single still image. Accept
    ; only the two known identifiers and their fixed 3-byte loop sub-block.
    ; Never iterate by this count, skip arbitrary application payloads, or
    ; permit metadata to license publication of the first animated frame.
    cmp  dword [rel img_gif_frames], 0
    jne  .unsupported
    cmp  dword [rel img_gif_loop], 0
    jne  .corrupt
    mov  rax, r13
    sub  rax, r12
    cmp  rax, 17
    jb   .truncated
    cmp  byte [r12], 11
    jne  .corrupt
    cmp  dword [r12 + 1], 'NETS'
    jne  .animexts
    cmp  dword [r12 + 5], 'CAPE'
    jne  .unsupported
    cmp  word [r12 + 9], '2.'
    jne  .unsupported
    jmp  .loop_suffix
.animexts:
    cmp  dword [r12 + 1], 'ANIM'
    jne  .unsupported
    cmp  dword [r12 + 5], 'EXTS'
    jne  .unsupported
    cmp  word [r12 + 9], '1.'
    jne  .unsupported
.loop_suffix:
    cmp  byte [r12 + 11], '0'
    jne  .unsupported
    cmp  byte [r12 + 12], 3
    jne  .corrupt
    cmp  byte [r12 + 13], 1
    jne  .corrupt
    cmp  byte [r12 + 16], 0
    jne  .corrupt
    mov  dword [rel img_gif_loop], 1
    add  r12, 17
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.comment:
    cmp  r12, r13
    jae  .truncated
    movzx eax, byte [r12]
    inc  r12
    test eax, eax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .block
    add  r12, rax
    cmp  r12, r13
    ja   .truncated
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comment
.image:
    cmp  dword [rel img_gif_frames], 0
    jne  .unsupported                 ; animation never publishes its first frame
    lea  rax, [r12 + 9]
    cmp  rax, r13
    ja   .truncated
    ; The logical screen owns allocation/stride. The image owns LZW count,
    ; row wrapping and interlace. Widen all u16 operands before addition.
    movzx eax, word [r12]
    mov  [rel img_gif_left], eax
    movzx ecx, word [r12 + 4]
    test ecx, ecx
    jz   .bounds
    mov  [rel img_gif_frame_w], ecx
    add  eax, ecx
    cmp  eax, [rel img_gif_w]
    ja   .bounds
    movzx eax, word [r12 + 2]
    mov  [rel img_gif_top], eax
    movzx edx, word [r12 + 6]
    test edx, edx
    jz   .bounds
    mov  [rel img_gif_frame_h], edx
    add  eax, edx
    cmp  eax, [rel img_gif_h]
    ja   .bounds
    imul ecx, edx
    mov  [rel img_gif_pixels], ecx
    cmp  ecx, [rel img_gif_canvas_pixels]
    je   .rectangle_ready             ; bounded equal area is full screen
    ; Partial RGBA compositing with transparency or no global background is
    ; outside this still slice. Full-screen transparency/local-only is retained.
    cmp  dword [rel img_gif_trans], -1
    jne  .unsupported
    cmp  dword [rel img_gif_background], 0
    je   .unsupported
.rectangle_ready:
    movzx ebp, byte [r12 + 8]
    test ebp, 0x18
    jnz  .corrupt
    mov  eax, ebp
    and  eax, 64
    mov  [rel img_gif_interlace], eax
    add  r12, 9
    test ebp, 128
    jz   .table_ready
    call img_gif_palette
    jc   .truncated
.table_ready:
    test r14, r14
    jz   .corrupt
    mov  eax, [rel img_gif_trans]
    cmp  eax, -1
    je   .min_bits
    cmp  eax, [rel img_gif_colors]
    jae  .corrupt
.min_bits:
    test r15, r15
    jz   .background_ready
    mov  ecx, [rel img_gif_canvas_pixels]
    cmp  ecx, [rel img_gif_pixels]
    je   .background_ready
    mov  rdi, r15
    mov  eax, [rel img_gif_background]
    IMG_COLD_MEMORY stosd
.background_ready:
    cmp  r12, r13
    jae  .truncated
    movzx ecx, byte [r12]
    inc  r12
    cmp  ecx, 2
    jb   .corrupt
    cmp  ecx, 8
    ja   .corrupt
    mov  eax, 1
    shl  eax, cl
    mov  [rel img_gif_clearcode], eax
    inc  eax
    mov  [rel img_gif_endcode], eax
    inc  ecx
    mov  [rel img_gif_initial_bits], ecx
    mov  [rel img_gif_bitsize], ecx
    call img_gif_code
    jc   .truncated
    cmp  eax, [rel img_gif_clearcode]
    jne  .corrupt
.reset:
    mov  eax, [rel img_gif_clearcode]
    add  eax, 2
    mov  [rel img_gif_next], eax
    mov  eax, [rel img_gif_initial_bits]
    mov  [rel img_gif_bitsize], eax
    mov  dword [rel img_gif_old], -1
.code:
    call img_gif_code
    jc   .truncated
    cmp  eax, [rel img_gif_clearcode]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .reset
    cmp  eax, [rel img_gif_endcode]
    je   .endcode
    mov  [rel img_gif_in], eax
    xor  r9d, r9d                     ; reversed expansion stack length
    mov  r10d, eax
    cmp  eax, [rel img_gif_next]
    jb   .chain
    jne  .corrupt
    cmp  dword [rel img_gif_old], -1
    je   .corrupt
    lea  rsi, [rel img_gif_stack]
    mov  eax, [rel img_gif_first]
    mov  [rsi], al                    ; KwKwK: expand old, then its first byte
    inc  r9d
    mov  r10d, [rel img_gif_old]
.chain:
    cmp  r10d, [rel img_gif_clearcode]
    jb   .literal
    cmp  r10d, [rel img_gif_endcode]
    jbe  .corrupt
    cmp  r10d, [rel img_gif_next]
    jae  .corrupt
    cmp  r9d, 4095
    jae  .corrupt
    lea  rsi, [rel img_gif_suffix]
    movzx eax, byte [rsi + r10]
    lea  rsi, [rel img_gif_stack]
    mov  [rsi + r9], al
    inc  r9d
    lea  rsi, [rel img_gif_prefix]
    movzx eax, word [rsi + r10 * 2]
    cmp  eax, r10d                    ; constructed prefixes always precede entry
    jae  .corrupt
    mov  r10d, eax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .chain
.literal:
    mov  [rel img_gif_first], r10d
    lea  rsi, [rel img_gif_stack]
    mov  [rsi + r9], r10b
    inc  r9d
.emit:
    dec  r9d
    lea  rsi, [rel img_gif_stack]
    movzx eax, byte [rsi + r9]
    cmp  eax, [rel img_gif_colors]
    jae  .corrupt
    mov  ecx, [rel img_gif_count]
    cmp  ecx, [rel img_gif_pixels]
    jae  .corrupt
    inc  dword [rel img_gif_count]
    test r15, r15
    jz   .emitted
    mov  r11d, [rel img_gif_y]
    add  r11d, [rel img_gif_top]
    imul r11d, dword [rel img_gif_w]
    add  r11d, [rel img_gif_x]
    add  r11d, [rel img_gif_left]
    lea  rdi, [r15 + r11 * 4]
    lea  edx, [eax + eax * 2]
    movzx ecx, byte [r14 + rdx]
    mov  [rdi], cl
    movzx ecx, byte [r14 + rdx + 1]
    mov  [rdi + 1], cl
    movzx ecx, byte [r14 + rdx + 2]
    mov  [rdi + 2], cl
    mov  byte [rdi + 3], 255
    cmp  eax, [rel img_gif_trans]
    jne  .emitted
    mov  byte [rdi + 3], 0             ; straight alpha; RGB remains palette RGB
.emitted:
    inc  dword [rel img_gif_x]
    mov  eax, [rel img_gif_x]
    cmp  eax, [rel img_gif_frame_w]
    jb   .next_pixel
    mov  dword [rel img_gif_x], 0
    cmp  dword [rel img_gif_interlace], 0
    jne  .interlaced
    inc  dword [rel img_gif_y]
    jmp  .next_pixel
.interlaced:
    mov  eax, [rel img_gif_pass]
    lea  rsi, [rel img_gif_steps]
    movzx ecx, byte [rsi + rax]
    add  [rel img_gif_y], ecx
.pass:
    mov  eax, [rel img_gif_y]
    cmp  eax, [rel img_gif_frame_h]
    jb   .next_pixel
    inc  dword [rel img_gif_pass]
    mov  eax, [rel img_gif_pass]
    cmp  eax, 4
    jae  .next_pixel                 ; pixel cap rejects any subsequent write
    lea  rsi, [rel img_gif_starts]
    movzx ecx, byte [rsi + rax]
    mov  [rel img_gif_y], ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .pass
.next_pixel:
    test r9d, r9d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .emit
    cmp  dword [rel img_gif_old], -1
    je   .old
    mov  eax, [rel img_gif_next]
    cmp  eax, 4096
    jae  .old                         ; deferred clear: frozen full dictionary
    lea  rsi, [rel img_gif_prefix]
    mov  ecx, [rel img_gif_old]
    mov  [rsi + rax * 2], cx
    lea  rsi, [rel img_gif_suffix]
    mov  ecx, [rel img_gif_first]
    mov  [rsi + rax], cl
    inc  eax
    mov  [rel img_gif_next], eax
    mov  ecx, [rel img_gif_bitsize]
    cmp  ecx, 12
    jae  .old
    mov  edx, 1
    shl  edx, cl
    cmp  eax, edx
    jne  .old
    inc  dword [rel img_gif_bitsize]
.old:
    mov  eax, [rel img_gif_in]
    mov  [rel img_gif_old], eax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .code
.endcode:
    mov  eax, [rel img_gif_count]
    cmp  eax, [rel img_gif_pixels]
    jne  .corrupt
    cmp  dword [rel img_gif_subleft], 0
    jne  .corrupt
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], 0
    jne  .corrupt
    inc  r12
    mov  dword [rel img_gif_frames], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.trailer:
    cmp  r12, r13
    jne  .corrupt
    cmp  dword [rel img_gif_frames], 1
    jne  .corrupt
    xor  eax, eax
    jmp  .out
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .out
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  .out
.magic:
    mov  eax, IMG_E_BAD_MAGIC
    jmp  .out
.corrupt:
    mov  eax, IMG_E_CORRUPT
    jmp  .out
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EBP packed table flags -> R14 selected RGB table; advances bounded cursor.
img_gif_palette:
    mov  ecx, ebp
    and  ecx, 7
    inc  ecx
    mov  [rel img_gif_depth], ecx
    mov  eax, 1
    shl  eax, cl
    mov  [rel img_gif_colors], eax
    lea  eax, [eax + eax * 2]
    lea  rdx, [r12 + rax]
    cmp  rdx, r13
    ja   .bad
    mov  r14, r12
    mov  r12, rdx
    clc
    ret
.bad:
    stc
    ret

; Bounded LSB-first code stream; sub-block framing is not part of the bitstream.
; Preserves palette/output and all parser nonvolatiles except advancing R12.
img_gif_code:
.fill:
    mov  ecx, [rel img_gif_nbits]
    cmp  ecx, [rel img_gif_bitsize]
    jae  .ready
    cmp  dword [rel img_gif_subleft], 0
    jne  .byte
    cmp  r12, r13
    jae  .bad
    movzx eax, byte [r12]
    inc  r12
    test eax, eax
    jz   .bad
    lea  rdx, [r12 + rax]
    cmp  rdx, r13
    ja   .bad
    mov  [rel img_gif_subleft], eax
.byte:
    movzx eax, byte [r12]
    inc  r12
    dec  dword [rel img_gif_subleft]
    shl  eax, cl
    or   [rel img_gif_bitbuf], eax
    add  dword [rel img_gif_nbits], 8
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .fill
.ready:
    mov  ecx, [rel img_gif_bitsize]
    mov  edx, 1
    shl  edx, cl
    dec  edx
    mov  eax, [rel img_gif_bitbuf]
    and  eax, edx
    shr  dword [rel img_gif_bitbuf], cl
    sub  [rel img_gif_nbits], ecx
    clc
    ret
.bad:
    stc
    ret

img_gif_steps:  db 8,8,4,2
img_gif_starts: db 0,4,2,1
%include "core/abi/wdata.inc"
%macro WDATA_gui_img_gif_bss 0
alignb 8
img_gif_state_begin:
img_gif_w:            resd 1
img_gif_h:            resd 1
img_gif_canvas_pixels: resd 1
img_gif_background:   resd 1
img_gif_left:         resd 1
img_gif_top:          resd 1
img_gif_frame_w:      resd 1
img_gif_frame_h:      resd 1
img_gif_pixels:       resd 1
img_gif_colors:       resd 1
img_gif_depth:        resd 1
img_gif_version:      resd 1
img_gif_trans:        resd 1
img_gif_gce:          resd 1
img_gif_loop:         resd 1
img_gif_frames:       resd 1
img_gif_interlace:    resd 1
img_gif_clearcode:    resd 1
img_gif_endcode:      resd 1
img_gif_initial_bits: resd 1
img_gif_bitsize:      resd 1
img_gif_next:         resd 1
img_gif_old:          resd 1
img_gif_in:           resd 1
img_gif_first:        resd 1
img_gif_count:        resd 1
img_gif_x:            resd 1
img_gif_y:            resd 1
img_gif_pass:         resd 1
img_gif_subleft:      resd 1
img_gif_bitbuf:       resd 1
img_gif_nbits:        resd 1
img_gif_prefix:       resw 4096
img_gif_suffix:       resb 4096
img_gif_stack:        resb 4096
img_gif_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_gui_img_gif_bss
