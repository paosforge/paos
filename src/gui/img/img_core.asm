;; MODULE gui/img/img_core
;; LAYER 6
;; EXPORTS img_probe, img_decode, img_declare, img_selftest, img_out_buf, img_out_ready, img_out_cur
;; IMPORTS boot/serial, core/heap, core/time, core/lib/crc32, core/lib/fmt, core/lib/str, svc/command, svc/command_udp
;; CAPS
;; OWNER saga:gui_image_pipeline
; Contract 2120: one pure, non-painting image decode contract.  Every decoder
; returns canonical top-down RGBA8888 and uses the frozen refusal vocabulary.

IMG_MAX_DIM    equ 4096
IMG_MAX_PIXELS equ 4194304
; One retained high-memory decoder scratch slab: RGBA16MiB + owned JPEG32MiB
; + progressive coefficients64MiB + alignment. Small decodes retain the exact
; ordinary-heap allocation/release seam and its contention/leak oracle.
IMG_LARGE_CAP equ 117440544

IMG_OK             equ 0
IMG_E_BAD_MAGIC    equ 1
IMG_E_BOUNDS       equ 2
IMG_E_TRUNCATED    equ 3
IMG_E_CRC          equ 4
IMG_E_CORRUPT      equ 5
IMG_E_UNSUPPORTED  equ 6
IMG_E_OOM          equ 7

IMG_FMT_NONE equ 0
IMG_FMT_BMP  equ 1
IMG_FMT_PNG  equ 2
IMG_FMT_JPEG equ 3
IMG_FMT_GIF  equ 4

IMG_OUT_MAX  equ 1180
IMG_PAGE_N   equ 4

%include "gui/img/img_bmp.asm"
%include "gui/img/img_png.asm"
%include "gui/img/img_jpeg.asm"
%include "gui/img/img_gif.asm"
%include "gui/img/img_bmp_encode.asm"
; The product PE maps one flat section; keep JPEG read-only tables in it.
; Standalone ELF includes retain .rodata, as for the SILK product binding.
%define .rodata .text
%include "gui/img/img_jpeg_encode.asm"
%undef .rodata
%include "gui/img/img_exif_locate.asm"
%include "gui/img/img_rgba_thumbnail.asm"
%include "gui/img/img_rgba_resize_bilinear.asm"
%include "gui/img/img_rgba_digest.asm"
%include "gui/img/img_decode_thumbnail.asm"
%include "gui/img/img_decode_digest.asm"
%include "gui/img/img_photo_duplicates.asm"
%include "gui/img/img_photo_file_digest.asm"
%include "gui/img/img_photo_import_plan.asm"
%include "gui/img/img_png_encode.asm"
%include "gui/img/img_png_surface_decode.asm"
%include "gui/img/img_capture_rgba.asm"
%include "gui/img/img_share_png.asm"
%include "gui/img/img_share_jpeg.asm"
%include "gui/img/img_rgba_crop.asm"
%include "gui/img/img_decode_crop.asm"
%include "gui/img/img_rgba_adjust.asm"
%include "gui/img/img_rgba_blur.asm"
%include "gui/img/img_rgba_auto_levels.asm"
%include "gui/img/img_rgba_straighten.asm"
%include "gui/img/img_rgba_fill.asm"
%include "gui/img/img_rgba_paint.asm"
%include "gui/img/img_rgba_brush.asm"
%include "gui/img/img_rgba_shape.asm"
%include "gui/img/img_rgba_text.asm"
%include "gui/img/img_rgba_viewport.asm"
%include "gui/img/img_decode_viewport.asm"
%include "gui/img/img_exif_info.asm"
%include "gui/img/img_metadata_info.asm"
%include "gui/img/img_photo_timeline.asm"
%include "gui/img/img_jpeg_rotate.asm"
%include "gui/img/img_rgba_arrow.asm"
%include "gui/img/img_rgba_canvas.asm"
%include "gui/img/img_edit.asm"
%include "gui/img/img_edit_export.asm"
%include "gui/img/img_viewer_sequence.asm"

; Keep the fixture catalog local to this implementation because the shared-tree
; img_assets.inc is owned by an earlier transaction.  Explicit incbin operands
; are intentional: NASM does not interpolate a macro's %2 inside a quoted path.
IMG_ASSET_COUNT equ 11
IMG_ASSET_NAME  equ 0
IMG_ASSET_PTR   equ 8
IMG_ASSET_LEN   equ 16
IMG_ASSET_ENTSZ equ 24

img_blob_kat_quad16:   incbin "gui/img/assets/kat_quad16.bmp"
img_blob_kat_quad16_end:
img_blob_kat_grad12:   incbin "gui/img/assets/kat_grad12.bmp"
img_blob_kat_grad12_end:
img_blob_kat_grad48:   incbin "gui/img/assets/kat_grad48.png"
img_blob_kat_grad48_end:
img_blob_kat_alpha16:  incbin "gui/img/assets/kat_alpha16.png"
img_blob_kat_alpha16_end:
img_blob_kat_photo444: incbin "gui/img/assets/kat_photo444.jpg"
img_blob_kat_photo444_end:
img_blob_kat_photo420: incbin "gui/img/assets/kat_photo420.jpg"
img_blob_kat_photo420_end:
img_blob_bad_magic:    incbin "gui/img/assets/bad_magic.bin"
img_blob_bad_magic_end:
img_blob_bad_trunc:    incbin "gui/img/assets/bad_trunc.png"
img_blob_bad_trunc_end:
img_blob_bad_crc:      incbin "gui/img/assets/bad_crc.png"
img_blob_bad_crc_end:
img_blob_bad_huff:     incbin "gui/img/assets/bad_huff.jpg"
img_blob_bad_huff_end:
img_blob_bad_hugedim:  incbin "gui/img/assets/bad_hugedim.bmp"
img_blob_bad_hugedim_end:

img_assets_init:
%macro IMG_ROW 2
    lea  rax, [rel img_name_%1]
    mov  [rel img_assets + (%2 * IMG_ASSET_ENTSZ) + IMG_ASSET_NAME], rax
    lea  rax, [rel img_blob_%1]
    mov  [rel img_assets + (%2 * IMG_ASSET_ENTSZ) + IMG_ASSET_PTR], rax
    mov  qword [rel img_assets + (%2 * IMG_ASSET_ENTSZ) + IMG_ASSET_LEN], img_blob_%1_end - img_blob_%1
%endmacro
    IMG_ROW kat_quad16,    0
    IMG_ROW kat_grad12,    1
    IMG_ROW kat_grad48,    2
    IMG_ROW kat_alpha16,   3
    IMG_ROW kat_photo444,  4
    IMG_ROW kat_photo420,  5
    IMG_ROW bad_magic,     6
    IMG_ROW bad_trunc,     7
    IMG_ROW bad_crc,       8
    IMG_ROW bad_huff,      9
    IMG_ROW bad_hugedim,  10
    ret

img_name_kat_quad16:   db "kat_quad16.bmp",0
img_name_kat_grad12:   db "kat_grad12.bmp",0
img_name_kat_grad48:   db "kat_grad48.png",0
img_name_kat_alpha16:  db "kat_alpha16.png",0
img_name_kat_photo444: db "kat_photo444.jpg",0
img_name_kat_photo420: db "kat_photo420.jpg",0
img_name_bad_magic:    db "bad_magic.bin",0
img_name_bad_trunc:    db "bad_trunc.png",0
img_name_bad_crc:      db "bad_crc.png",0
img_name_bad_huff:     db "bad_huff.jpg",0
img_name_bad_hugedim:  db "bad_hugedim.bmp",0
align 8
img_assets: times (IMG_ASSET_COUNT * IMG_ASSET_ENTSZ) db 0

%undef IMG_ROW

; img_probe(RDI=src,RSI=len) -> EAX=status, EBX=fmt, ECX=w, EDX=h, R8D=bpp.
; Public probe/decode refusal preserves EAX and zeros all result fields.
; Full structural lint and caps happen here; no allocation is reachable.
img_probe:
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_PUBLIC_GUARD
%endif
    mov  [rel img_active_src], rdi
    mov  [rel img_active_len], rsi
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds                     ; qualify caller span before signature dispatch
    cmp  rsi, 2
    jb   .truncated
    cmp  word [rdi], 'BA'
    je   .bmp
    cmp  word [rdi], 'IC'
    je   .bmp
    cmp  word [rdi], 'PT'
    je   .bmp
    cmp  word [rdi], 'CI'
    je   .bmp
    cmp  word [rdi], 'CP'
    je   .bmp
    cmp  word [rdi], 'BM'
    je   .bmp
    cmp  word [rdi], 0xD8FF
    je   .jpeg
    cmp  word [rdi], 'GI'
    je   .gif
    cmp  rsi, 8
    jb   .bad_magic
    cmp  dword [rdi], PNG_SIG0
    jne  .bad_magic
    cmp  dword [rdi + 4], PNG_SIG1
    jne  .bad_magic
    call img_png_probe
    jmp  .checked
.bmp:
    call img_bmp_probe
    jmp  .checked
.jpeg:
    call img_jpeg_probe
    jmp  .checked
.gif:
    call img_gif_probe
.checked:
    test eax, eax
    jnz  .refused
    call img_codec_state_clear
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    ret
.refused:
    call img_refusal_clear
.ret:
    ret
.bad_magic:
    mov  eax, IMG_E_BAD_MAGIC
    jmp  img_refusal_clear
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  img_refusal_clear
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  img_refusal_clear

; img_decode(RDI=src,RSI=len) -> EAX=status, RBX=RGBA ptr, ECX=w, EDX=h, R8D=fmt.
img_decode:
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_PUBLIC_GUARD
%endif
    mov  [rel img_active_src], rdi
    mov  [rel img_active_len], rsi
    mov  qword [rel img_active_out], 0
    mov  qword [rel img_alloc_before], 0
    mov  qword [rel img_alloc_after], 0
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds                     ; signature reads share probe's pointer guard
    cmp  rsi, 2
    jb   .truncated
    cmp  word [rdi], 'BA'
    je   .bmp
    cmp  word [rdi], 'IC'
    je   .bmp
    cmp  word [rdi], 'PT'
    je   .bmp
    cmp  word [rdi], 'CI'
    je   .bmp
    cmp  word [rdi], 'CP'
    je   .bmp
    cmp  word [rdi], 'BM'
    je   .bmp
    cmp  word [rdi], 0xD8FF
    je   .jpeg
    cmp  word [rdi], 'GI'
    je   .gif
    cmp  rsi, 8
    jb   .bad_magic
    cmp  dword [rdi], PNG_SIG0
    jne  .bad_magic
    cmp  dword [rdi + 4], PNG_SIG1
    jne  .bad_magic
    call img_png_decode
    jmp  .checked
.bmp:
    call img_bmp_decode
    jmp  .checked
.jpeg:
    call img_jpeg_decode
    jmp  .checked
.gif:
    call img_gif_decode
.checked:
    test eax, eax
    jz   .ret
    call img_refusal_clear
.ret:
    ret
.bad_magic:
    mov  eax, IMG_E_BAD_MAGIC
    jmp  img_refusal_clear
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  img_refusal_clear

.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  img_refusal_clear

img_refusal_clear:
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_OWNER_ONLY
%endif
    push rax
    call img_codec_state_clear
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    mov  qword [rel img_active_out], 0
    mov  qword [rel img_alloc_before], 0
    mov  qword [rel img_alloc_after], 0
    mov  qword [rel img_alloc_size], 0
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
    pop  rax
    ret

; Codec parsers use bounded static workspaces so img_probe can remain
; allocation-free. Clear them at every public boundary: no source pointer,
; Huffman table, or partial parse survives a probe/refusal/release.
img_codec_state_clear:
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_OWNER_ONLY
%endif
    push rax
    push rdi
    push rcx
    call img_jpeg_clear
    call img_gif_clear
    lea  rdi, [rel img_png_state_begin]
    lea  rcx, [rel img_png_state_end]
    sub  rcx, rdi
    xor  eax, eax
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_stosb
%else
    rep  stosb
%endif
    pop  rcx
    pop  rdi
    pop  rax
    ret

; Exactly-one allocation seam. The decoders use only bounded static metadata and
; place raw/final pixels in this allocation. img_output_release calls kfree and
; atomically rolls the bump back only if this remains the allocator's LIFO tip.
img_output_alloc:
%ifdef PAOS_IMG_COLD_WORK
    cmp byte [rel img_cold_running],1
    je .cold
%endif
    mov  [rel img_alloc_size], rdi
    mov  rax, [rel heap_next]
    mov  [rel img_alloc_before], rax
    ; Route a known capacity miss without asking kmalloc to record an OOM.
    ; Match its 16-byte rounding, including size zero. Invalid size/state
    ; still reaches kmalloc so genuine wrap/guard diagnostics remain visible.
    mov  rdx, rdi
    add  rdx, 15
    jc   .ordinary
    and  rdx, -16
    jnz  .rounded
    mov  edx, 16
.rounded:
    test rax, rax
    jz   .ordinary
    cmp  rax, [rel heap_base]
    jb   .ordinary
    test al, 15
    jnz  .ordinary
    mov  rdi, [rel heap_end]
    sub  rdi, rax
    jc   .ordinary
    cmp  rdx, rdi
    ja   .fallback
.ordinary:
    mov  rdi, [rel img_alloc_size]
    call kmalloc
    test rax, rax
    jnz  .ordinary_ready
    ; The ordinary heap also holds the live desktop. An output may not fit
    ; its remaining space; only then use the bounded retained slab. Callers
    ; with a larger ordinary heap retain their existing allocation contract.
    ; kmalloc rounds/clobbers RDI, so recover the exact requested size.
.fallback:
    mov  rdi, [rel img_alloc_size]
    jmp  .large
.ordinary_ready:
    mov  [rel img_active_out], rax
    mov  rdx, [rel heap_next]
    mov  [rel img_alloc_after], rdx
    ret
.large:
    ; Never enlarge or swap the ordinary heap. kmalloc_model enforces the
    ; boot-reserved high-memory bounds. Retain one slab and reuse only after
    ; its exact output is released; no foreign kfree or unbounded bump leak.
    cmp  rdi, IMG_LARGE_CAP
    ja   .refuse
    cmp  qword [rel img_large_busy], 0
    jne  .refuse
    mov  [rel img_alloc_size], rdi
    mov  rax, [rel img_large_base]
    test rax, rax
    jnz  .large_ready
    mov  edi, IMG_LARGE_CAP
    call kmalloc_model
    test rax, rax
    jz   .refuse
    mov  [rel img_large_base], rax
.large_ready:
    mov  qword [rel img_large_busy], 1
    mov  [rel img_active_out], rax
    mov  qword [rel img_alloc_before], 0
    mov  qword [rel img_alloc_after], 0
    ret
.refuse:
    xor  eax, eax
    ret
%ifdef PAOS_IMG_COLD_WORK
.cold:
    mov [rel img_alloc_size],rdi
    call img_cold_heap_now
    mov [rel img_alloc_before],rax
    call img_cold_heap_alloc
    test rax,rax
    jz .refuse
    mov [rel img_active_out],rax
    push rax
    call img_cold_heap_now
    mov [rel img_alloc_after],rax
    pop rax
    ret
%endif

img_output_release:
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_OWNER_ONLY
%endif
    push rbx
    mov  rbx, [rel img_active_out]
    test rbx, rbx
    jz   .done
    cmp  rbx, [rel img_large_base]
    je   .large
    mov  rdi, rbx
%ifdef PAOS_IMG_COLD_WORK
    mov  rax, [rel img_alloc_after]
    mov  rdx, [rel img_alloc_before]
    call img_cold_heap_rewind
%else
    call kfree                             ; canonical free API (M1 is a no-op)
    mov  rax, [rel img_alloc_after]        ; expected current tip
    mov  rdx, [rel img_alloc_before]       ; desired prior tip
    lock cmpxchg [rel heap_next], rdx      ; safe only when no intervening alloc
%endif
    jne  .done                             ; honest leak oracle reports contention
    jmp  .clear
.large:
    mov  qword [rel img_large_busy], 0
.clear:
    mov  qword [rel img_active_out], 0
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    mov  qword [rel img_alloc_before], 0
    mov  qword [rel img_alloc_after], 0
    mov  qword [rel img_alloc_size], 0
    call img_codec_state_clear
.done:
    pop  rbx
    ret

img_heap_now:
    mov  rax, [rel heap_next]
    sub  rax, [rel heap_base]
    ret

; Find an exact embedded name. RDI=name (or 0 for absent) -> RAX=row or 0.
img_asset_find:
    push rbx
    push r12
    push r13
    test rdi, rdi
    jz   .miss
    cmp  byte [rdi], 0
    je   .miss
    mov  r12, rdi
    lea  rbx, [rel img_assets]
    xor  r13d, r13d
.scan:
    cmp  r13d, IMG_ASSET_COUNT
    jae  .miss
    mov  rdi, [rbx + IMG_ASSET_NAME]
    mov  rsi, r12
    call strcmp                           ; RCX is caller-clobbered
    test rax, rax
    jz   .hit
    add  rbx, IMG_ASSET_ENTSZ
    inc  r13d
    jmp  .scan
.hit:
    mov  rax, rbx
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

img_asset_row:
    imul rax, rdi, IMG_ASSET_ENTSZ
    lea  rdx, [rel img_assets]
    add  rax, rdx
    ret

; RDI=asset row -> RAX=frozen catalog format string. The catalog owns the
; JPEG subsampling label, so codec workspace can still be zero at return.
img_asset_row_fmt_name:
    lea  rax, [rel img_assets]
    sub  rdi, rax
    mov  rax, rdi
    xor  edx, edx
    mov  ecx, IMG_ASSET_ENTSZ
    div  rcx
    mov  edi, eax
    jmp  img_asset_fmt_name

; Expected catalog format strings are asset metadata, independent of whether a
; corrupt fixture's header probe refuses before it can return a format.
img_asset_fmt_name:
    cmp  edi, 0
    je   .bmp24
    cmp  edi, 1
    je   .bmp32
    cmp  edi, 2
    je   .png_rgb
    cmp  edi, 3
    je   .png_rgba
    cmp  edi, 4
    je   .jpg444
    cmp  edi, 5
    je   .jpg420
    cmp  edi, 6
    je   .none
    cmp  edi, 9
    je   .jpg444
    cmp  edi, 10
    je   .bmp24
    jmp  .png_rgb
.bmp24:   lea rax, [rel str_img_fmt_bmp24]
          ret
.bmp32:   lea rax, [rel str_img_fmt_bmp32]
          ret
.png_rgb: lea rax, [rel str_img_fmt_png_rgb]
          ret
.png_rgba: lea rax, [rel str_img_fmt_png_rgba]
           ret
.jpg444:  lea rax, [rel str_img_fmt_jpeg444]
          ret
.jpg420:  lea rax, [rel str_img_fmt_jpeg420]
          ret
.none:    lea rax, [rel str_img_fmt_none]
          ret

img_probe_fmt_name:
    cmp  ebx, IMG_FMT_BMP
    jne  .png
    cmp  r8d, 32
    je   img_asset_fmt_name.bmp32
    jmp  img_asset_fmt_name.bmp24
.png:
    cmp  ebx, IMG_FMT_PNG
    jne  .jpeg
    cmp  r8d, 32
    je   img_asset_fmt_name.png_rgba
    jmp  img_asset_fmt_name.png_rgb
.jpeg:
    cmp  ebx, IMG_FMT_JPEG
    jne  img_asset_fmt_name.none
    ; Sampling metadata was populated by the JPEG header lint.
    cmp  byte [rel img_jpg_max_h], 2
    je   img_asset_fmt_name.jpg420
    jmp  img_asset_fmt_name.jpg444

img_reason_name:
    cmp  eax, IMG_E_BAD_MAGIC
    je   .bad_magic
    cmp  eax, IMG_E_BOUNDS
    je   .bounds
    cmp  eax, IMG_E_TRUNCATED
    je   .truncated
    cmp  eax, IMG_E_CRC
    je   .crc
    cmp  eax, IMG_E_CORRUPT
    je   .corrupt
    cmp  eax, IMG_E_UNSUPPORTED
    je   .unsupported
    jmp  .oom
.bad_magic:   lea rax, [rel str_img_bad_magic]
              ret
.bounds:      lea rax, [rel str_img_bounds]
              ret
.truncated:   lea rax, [rel str_img_truncated]
              ret
.crc:         lea rax, [rel str_img_crc]
              ret
.corrupt:     lea rax, [rel str_img_corrupt]
              ret
.unsupported: lea rax, [rel str_img_unsupported]
              ret
.oom:         lea rax, [rel str_img_oom]
              ret

%macro IMG_REGISTER 2
    lea  rdi, [rel %1]
    lea  rsi, [rel %2]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    or   ebx, eax
%endmacro

img_declare:
    push rbx
    call img_assets_init
    xor  ebx, ebx
    IMG_REGISTER str_verb_imglist, cmd_verb_imglist
    IMG_REGISTER str_verb_imginfo, cmd_verb_imginfo
    IMG_REGISTER str_verb_imgdec,  cmd_verb_imgdec
    test ebx, ebx
    js   .fail
    lea  rdi, [rel str_img_verbs_marker]
    call serial_string
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_img_verbs_fail]
    call serial_string
    pop  rbx
    ret

cmd_verb_imglist:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call img_parse_page
    cmp  eax, 2
    jbe  .page_ok
    mov  eax, 2
.page_ok:
    mov  r14d, eax
    call img_out_reset
    lea  rdi, [rel str_img_list_page]
    call img_out_str
    mov  edi, r14d
    inc  edi
    call img_out_dec
    lea  rdi, [rel str_img_slash3]
    call img_out_str
    lea  rdi, [rel str_img_n11]
    call img_out_str
    mov  eax, r14d
    imul eax, IMG_PAGE_N
    mov  ebx, eax
    lea  r14d, [eax + IMG_PAGE_N]
    cmp  r14d, IMG_ASSET_COUNT
    jbe  .rows
    mov  r14d, IMG_ASSET_COUNT
.rows:
    cmp  ebx, r14d
    jae  .ready
    mov  edi, ebx
    call img_asset_row
    mov  r15, rax
    lea  rdi, [rel str_img_name]
    call img_out_str
    mov  rdi, [r15 + IMG_ASSET_NAME]
    call img_out_str
    lea  rdi, [rel str_img_fmt]
    call img_out_str
    mov  edi, ebx
    call img_asset_fmt_name
    mov  rdi, rax
    call img_out_str
    lea  rdi, [rel str_img_bytes]
    call img_out_str
    mov  rdi, [r15 + IMG_ASSET_LEN]
    call img_out_dec
    inc  ebx
    jmp  .rows
.ready:
    mov  byte [rel img_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_imginfo:
    call cmd_handler_prologue
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call img_asset_find
    test rax, rax
    jz   .missing
    mov  r14, rax
    mov  rdi, [r14 + IMG_ASSET_PTR]
    mov  rsi, [r14 + IMG_ASSET_LEN]
    call img_probe
    mov  [rel img_last_status], eax
    mov  [rel img_last_fmt], ebx
    mov  [rel img_last_w], ecx
    mov  [rel img_last_h], edx
    mov  [rel img_last_bpp], r8d
    call img_out_reset
    mov  eax, [rel img_last_status]
    test eax, eax
    jnz  .refused
    lea  rdi, [rel str_img_info_ok]
    call img_out_str
    mov  rdi, [r14 + IMG_ASSET_NAME]
    call img_out_str
    lea  rdi, [rel str_img_fmt]
    call img_out_str
    mov  rdi, r14
    call img_asset_row_fmt_name
    mov  rdi, rax
    call img_out_str
    lea  rdi, [rel str_img_w]
    call img_out_str
    mov  edi, [rel img_last_w]
    call img_out_dec
    lea  rdi, [rel str_img_h]
    call img_out_str
    mov  edi, [rel img_last_h]
    call img_out_dec
    lea  rdi, [rel str_img_bpp]
    call img_out_str
    mov  edi, [rel img_last_bpp]
    call img_out_dec
    jmp  .ready
.refused:
    push rax
    lea  rdi, [rel str_img_info_refused]
    call img_out_str
    pop  rax
    call img_reason_name
    mov  rdi, rax
    call img_out_str
    jmp  .ready
.missing:
    call img_out_reset
    lea  rdi, [rel str_img_info_missing]
    call img_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .finish
.ready:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.finish:
    mov  byte [rel img_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    pop  r14
    pop  r13
    pop  r12
    ret

cmd_verb_imgdec:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call img_asset_find
    test rax, rax
    jz   .missing
    mov  r14, rax
    call img_heap_now
    mov  r15, rax                        ; live before
    call boot_ms_now
    mov  [rel img_decode_ms0], rax
    mov  rdi, [r14 + IMG_ASSET_PTR]
    mov  rsi, [r14 + IMG_ASSET_LEN]
    call img_decode
    mov  [rel img_last_status], eax
    mov  [rel img_last_ptr], rbx
    mov  [rel img_last_w], ecx
    mov  [rel img_last_h], edx
    mov  [rel img_last_fmt], r8d
    call boot_ms_now
    sub  rax, [rel img_decode_ms0]
    mov  [rel img_last_ms], rax
    cmp  dword [rel img_last_status], 0
    jne  .after_decode
    mov  eax, [rel img_last_w]
    imul eax, [rel img_last_h]
    shl  eax, 2
    mov  esi, eax
    mov  rdi, [rel img_last_ptr]
    call hotpatch_crc32
    mov  [rel img_last_crc], eax
    call img_output_release
.after_decode:
    call img_heap_now
    mov  [rel img_last_heap], rax
    mov  rdx, rax
    sub  rdx, r15
    mov  [rel img_last_delta], rdx
    call img_out_reset
    cmp  dword [rel img_last_status], 0
    jne  .decode_refused
    lea  rdi, [rel str_img_dec_ok]
    call img_out_str
    mov  rdi, [r14 + IMG_ASSET_NAME]
    call img_out_str
    lea  rdi, [rel str_img_fmt]
    call img_out_str
    mov  rdi, r14
    call img_asset_row_fmt_name
    mov  rdi, rax
    call img_out_str
    lea  rdi, [rel str_img_w]
    call img_out_str
    mov  edi, [rel img_last_w]
    call img_out_dec
    lea  rdi, [rel str_img_h]
    call img_out_str
    mov  edi, [rel img_last_h]
    call img_out_dec
    lea  rdi, [rel str_img_crc32]
    call img_out_str
    mov  edi, [rel img_last_crc]
    call img_out_hex8
    lea  rdi, [rel str_img_ms]
    call img_out_str
    mov  rdi, [rel img_last_ms]
    call img_out_dec
    jmp  .heap_tail
.decode_refused:
    lea  rdi, [rel str_img_dec_refused]
    call img_out_str
    mov  eax, [rel img_last_status]
    call img_reason_name
    mov  rdi, rax
    call img_out_str
.heap_tail:
    lea  rdi, [rel str_img_heap_delta]
    call img_out_str
    mov  rdi, [rel img_last_delta]
    call img_out_dec
    lea  rdi, [rel str_img_heap_now]
    call img_out_str
    mov  rdi, [rel img_last_heap]
    call img_out_dec
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.missing:
    call img_out_reset
    lea  rdi, [rel str_img_dec_missing]
    call img_out_str
    lea  rdi, [rel str_img_heap_now]
    call img_out_str
    call img_heap_now
    mov  rdi, rax
    call img_out_dec
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.ready:
    mov  byte [rel img_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

img_parse_page:
    test rdi, rdi
    jz   .zero
    xor  eax, eax
.digit:
    movzx ecx, byte [rdi]
    test ecx, ecx
    jz   .done
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .zero
    imul eax, eax, 10
    add  eax, ecx
    inc  rdi
    jmp  .digit
.zero:
    xor  eax, eax
.done:
    test eax, eax                        ; wire pages are 1-based; empty/0 => first
    jz   .ret
    dec  eax
.ret:
    ret

img_out_reset:
    lea  rax, [rel img_out_buf]
    mov  [rel img_out_cur], rax
    mov  byte [rax], 0
    ret
img_out_str:
    mov  rsi, [rel img_out_cur]
    lea  rdx, [rel img_out_buf + IMG_OUT_MAX - 1]
.copy:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel img_out_cur], rsi
    ret
img_out_dec:
    mov  rsi, [rel img_out_cur]
    lea  rax, [rel img_out_buf + IMG_OUT_MAX - 24]
    cmp  rsi, rax
    jae  .skip
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel img_out_cur], rsi
.skip:
    ret
img_out_hex8:
    mov  rsi, [rel img_out_cur]
    lea  rax, [rel img_out_buf + IMG_OUT_MAX - 16]
    cmp  rsi, rax
    jae  .skip
    mov  edx, 8
    push rsi
    call fmt_hex
    pop  rsi
    mov  ecx, 8
.uppercase:
    mov  al, [rsi]
    cmp  al, 'a'
    jb   .next
    cmp  al, 'f'
    ja   .next
    sub  byte [rsi], 0x20
.next:
    inc  rsi
    dec  ecx
    jnz  .uppercase
    mov  [rel img_out_cur], rsi
.skip:
    ret

; Boot KAT: four exact lossless CRCs, both JPEG dimensions, two exact refusals,
; and allocator-tip equality around every call.  On failure the diagnostic mask
; is BMP24/BMP32/PNG-RGB/PNG-RGBA/JPEG444/JPEG420/bounds/magic/heap in bits 0..8.
img_selftest:
    push rbx
    push r12
    push r13
    mov  r12, [rel heap_next]
    xor  r13d, r13d
    mov  edi, 0
    mov  esi, 0x88143CD9
    call img_kat_crc
    test eax, eax
    jz   .bmp24_ok
    or   r13d, 0x001
.bmp24_ok:
    mov  edi, 1
    mov  esi, 0x712B9F6B
    call img_kat_crc
    test eax, eax
    jz   .bmp32_ok
    or   r13d, 0x002
.bmp32_ok:
    mov  edi, 2
    mov  esi, 0x960E7685
    call img_kat_crc
    test eax, eax
    jz   .png_rgb_ok
    or   r13d, 0x004
.png_rgb_ok:
    mov  edi, 3
    mov  esi, 0x218AC414
    call img_kat_crc
    test eax, eax
    jz   .png_rgba_ok
    or   r13d, 0x008
.png_rgba_ok:
    mov  edi, 4
    call img_kat_jpeg
    test eax, eax
    jz   .jpeg444_ok
    or   r13d, 0x010
.jpeg444_ok:
    mov  edi, 5
    call img_kat_jpeg
    test eax, eax
    jz   .jpeg420_ok
    or   r13d, 0x020
.jpeg420_ok:
    mov  edi, 10
    mov  esi, IMG_E_BOUNDS
    call img_kat_refusal
    test eax, eax
    jz   .bounds_ok
    or   r13d, 0x040
.bounds_ok:
    mov  edi, 6
    mov  esi, IMG_E_BAD_MAGIC
    call img_kat_refusal
    test eax, eax
    jz   .magic_ok
    or   r13d, 0x080
.magic_ok:
    cmp  [rel heap_next], r12
    je   .heap_ok
    or   r13d, 0x100
.heap_ok:
    test r13d, r13d
    jnz  .fail
    lea  rdi, [rel str_img_kat_marker]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_img_kat_fail]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    call serial_newline
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

img_kat_crc:
    push rbx
    push r12
    push r13
    mov  r12d, esi
    call img_asset_row
    mov  r13, rax
    mov  rdi, [r13 + IMG_ASSET_PTR]
    mov  rsi, [r13 + IMG_ASSET_LEN]
    call img_decode
    test eax, eax
    jnz  .decode_bad
    mov  eax, ecx
    imul eax, edx
    shl  eax, 2
    mov  esi, eax
    mov  rdi, rbx
    call hotpatch_crc32
    cmp  eax, r12d
    jne  .crc_bad
    call img_output_release
    xor  eax, eax
    jmp  .out
.crc_bad:
    mov  ebx, eax
    lea  rdi, [rel str_img_kat_crc_diag]
    call serial_string
    mov  rdi, [r13 + IMG_ASSET_NAME]
    call serial_string
    lea  rdi, [rel str_img_kat_actual]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_img_kat_expected]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    call serial_newline
    call img_output_release
    jmp  .bad
.decode_bad:
    mov  ebx, eax
    lea  rdi, [rel str_img_kat_decode_diag]
    call serial_string
    mov  rdi, [r13 + IMG_ASSET_NAME]
    call serial_string
    lea  rdi, [rel str_img_kat_status]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    call serial_newline
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

img_kat_jpeg:
    call img_asset_row
    mov  rdi, [rax + IMG_ASSET_PTR]
    mov  rsi, [rax + IMG_ASSET_LEN]
    call img_decode
    test eax, eax
    jnz  .bad
    cmp  ecx, 64
    jne  .release_bad
    cmp  edx, 48
    jne  .release_bad
    call img_output_release
    xor  eax, eax
    ret
.release_bad:
    call img_output_release
.bad:
    mov  eax, 1
    ret

img_kat_refusal:
    push r12
    mov  r12d, esi
    call img_asset_row
    mov  rdi, [rax + IMG_ASSET_PTR]
    mov  rsi, [rax + IMG_ASSET_LEN]
    call img_decode
    cmp  eax, r12d
    jne  .bad
    cmp  qword [rel img_active_out], 0
    jne  .bad
    xor  eax, eax
    pop  r12
    ret
.bad:
    mov  eax, 1
    pop  r12
    ret

align 8
img_active_src:   dq 0
img_active_len:   dq 0
img_active_out:   dq 0
img_alloc_before: dq 0
img_alloc_after:  dq 0
img_alloc_size:   dq 0
img_out_cur:      dq 0
img_out_ready:    db 0
align 8
img_out_buf:      times IMG_OUT_MAX db 0
img_decode_ms0:   dq 0
img_last_ptr:     dq 0
img_last_ms:      dq 0
img_last_heap:    dq 0
img_last_delta:   dq 0
img_last_status:  dd 0
img_last_w:       dd 0
img_last_h:       dd 0
img_last_fmt:     dd 0
img_last_bpp:     dd 0
img_last_crc:     dd 0

str_verb_imglist: db "IMGLIST",0
str_verb_imginfo: db "IMGINFO",0
str_verb_imgdec:  db "IMGDEC",0
str_img_list_page: db " IMGLIST page=",0
str_img_slash3: db "/3",0
str_img_n11: db " n=11",0
str_img_name: db " name=",0
str_img_fmt: db " fmt=",0
str_img_bytes: db " bytes=",0
str_img_info_ok: db " imginfo=ok name=",0
str_img_info_refused: db " imginfo=refused reason=",0
str_img_info_missing: db " imginfo=refused reason=bad_magic",0
str_img_dec_ok: db " imgdec=ok name=",0
str_img_dec_refused: db " imgdec=ERR reason=",0
str_img_dec_missing: db " imgdec=ERR reason=bad_magic heap_delta=0",0
str_img_w: db " w=",0
str_img_h: db " h=",0
str_img_bpp: db " bpp=",0
str_img_crc32: db " rgba_crc32=",0
str_img_ms: db " ms=",0
str_img_heap_delta: db " heap_delta=",0
str_img_heap_now: db " heap_now=",0
str_img_fmt_bmp24: db "bmp24",0
str_img_fmt_bmp32: db "bmp32",0
str_img_fmt_png_rgb: db "png_rgb",0
str_img_fmt_png_rgba: db "png_rgba",0
str_img_fmt_jpeg444: db "jpeg_444",0
str_img_fmt_jpeg420: db "jpeg_420",0
str_img_fmt_none: db "none",0
str_img_bad_magic: db "bad_magic",0
str_img_bounds: db "bounds",0
str_img_truncated: db "truncated",0
str_img_crc: db "crc",0
str_img_corrupt: db "corrupt_stream",0
str_img_unsupported: db "unsupported_variant",0
str_img_oom: db "oom",0
str_img_kat_marker: db "[PAOS64] M6 img: decode KAT (4 lossless exact CRC, 2 jpeg ok, 2 refusals exact, heap_delta=0) [gui.img.decode.kat]",13,10,0
str_img_kat_fail: db "[PAOS64] M6 img: decode KAT FAIL mask=",0
str_img_kat_crc_diag: db "[PAOS64] M6 img: KAT crc mismatch name=",0
str_img_kat_actual: db " actual=",0
str_img_kat_expected: db " expected=",0
str_img_kat_decode_diag: db "[PAOS64] M6 img: KAT decode refused name=",0
str_img_kat_status: db " status=",0
str_img_verbs_marker: db "[PAOS64] M6 img: IMGLIST/IMGINFO/IMGDEC registered (11 assets, paged) [gui.img.verbs]",13,10,0
str_img_verbs_fail: db "[PAOS64] M6 img: verb registration FAILED",13,10,0

%undef IMG_REGISTER

%include "core/abi/wdata.inc"
%macro WDATA_gui_img_large 0
align 8, db 0
img_large_base: dq 0
img_large_busy: dq 0
%endmacro
WDATA_DEFER WDATA_gui_img_large
