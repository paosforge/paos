;; MODULE gui/font_aa
;; LAYER 6
;; EXPORTS fb_draw_glyph_aa, fb_draw_str_aa_n, font_aa_kat
;; IMPORTS gui/compose_idle, gui/compose_glyph, gui/window, boot/serial
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/font_aa.asm — D2 anti-aliased monospace text (PETER RULING 2026-09-29 13:50).
;
; The 9x19 atlas (font_aa9x19.inc, generated from DejaVu Sans Mono by
; gauntlet_v2/tools/gen_font_aa9x19.py) holds 8-bit coverage per pixel. Like
; fb_draw_char this paints a SOLID cell: each pixel is fg and a known bg
; blended per channel as (fg*a + bg*(255-a) + 127) / 255, so text never reads
; the framebuffer back (GOP memory is write-combined/uncached on metal). A cell
; that would cross any screen edge is refused whole, as fb_draw_char.
;
; gui ESSENCE E5: the fast row-pointer path has a naive reference that paints
; the same cell through 1x1 fb_fill_rect calls; font_aa_kat drives both into
; separate scratch screens and requires byte equality, intact 0xDEADBEEF
; sentinels and a host-computed FNV-1a of 'A'. No framebuffer -> honest skip.
; ============================================================================

%include "gui/font_aa9x19.inc"

FONT_AA_CELL      equ FONT_AA_W * FONT_AA_H
FAKAT_W           equ 16
FAKAT_H           equ 24
FAKAT_PIX         equ FAKAT_W * FAKAT_H
FAKAT_X           equ 3
FAKAT_Y           equ 2
FAKAT_SENTINEL    equ 0xDEADBEEF
FAKAT_FG          equ 0x00FFFFFF
FAKAT_BG          equ 0x000C0C0C
FAKAT_GOLDEN_FNV  equ 0xE28477FE  ; host: 'A', fg FFFFFF, bg 0C0C0C, BGRX bytes

; font_aa_glyph_ptr(edi=char) -> RSI = 171-byte coverage cell ('?' if unmapped)
font_aa_glyph_ptr:
    movzx eax, dil
    cmp  eax, FONT_AA_FIRST
    jb   .unmapped
    cmp  eax, FONT_AA_LAST
    jbe  .mapped
.unmapped:
    mov  eax, '?'
.mapped:
    sub  eax, FONT_AA_FIRST
    imul eax, eax, FONT_AA_CELL
    lea  rsi, [rel font_aa9x19]
    add  rsi, rax
    ret

; font_aa_blend(eax=coverage 0..255, ebx=fg, ecx=bg) -> EDX = blended 0x00RRGGBB.
; Clobbers r10/r11 only.
font_aa_blend:
    push rax
    push rdi
    mov  edi, eax                       ; a
    xor  edx, edx
    mov  r11d, 0                        ; channel shift
.chan:
    mov  eax, ebx
    push rcx
    mov  ecx, r11d
    shr  eax, cl
    pop  rcx
    and  eax, 0xFF
    imul eax, edi                       ; fg * a
    mov  r10d, ecx
    push rcx
    mov  ecx, r11d
    shr  r10d, cl
    pop  rcx
    and  r10d, 0xFF
    push rdx
    mov  edx, 255
    sub  edx, edi
    imul r10d, edx                      ; bg * (255 - a)
    pop  rdx
    add  eax, r10d
    add  eax, 127
    push rdx
    xor  edx, edx
    mov  r10d, 255
    div  r10d
    pop  rdx
    push rcx
    mov  ecx, r11d
    shl  eax, cl
    pop  rcx
    or   edx, eax
    add  r11d, 8
    cmp  r11d, 24
    jb   .chan
    pop  rdi
    pop  rax
    ret

; fb_draw_glyph_aa(edi=char, r8d=x, r9d=y, ebx=fg, ecx=bg). Preserves r8..r11/
; ebx/ecx (the fb_draw_char contract), clobbers rax/rdx/rsi/rdi.
fb_draw_glyph_aa:
    push r10
    push r11
    push r12
    push r13
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done
    ; Solid cells are refused whole at every edge, before address arithmetic.
    test r8d, r8d
    js   .done
    test r9d, r9d
    js   .done
    mov  eax, r8d
    add  eax, FONT_AA_W
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, FONT_AA_H
    cmp  eax, [rel fb_height]
    ja   .done
    call font_aa_glyph_ptr              ; rsi = coverage
    cmp byte [rel fb_compose_clip_active],0
    je .whole_cell
    xor edx,edx
    mov r10d,FONT_AA_W
    mov r11d,FONT_AA_H
    call fb_compose_glyph
    jmp .done
.whole_cell:
    ; Coordinates and pitch are 32-bit inputs; retain the full pixel index.
    mov  eax, [rel fb_stride]
    mov  r10d, r9d
    imul rax, r10
    mov  r10d, r8d
    add  rax, r10
    mov  rdi, [rel fb_base]
    lea  rdi, [rdi + rax*4]
    mov  r12d, FONT_AA_H
.row:
    mov  r13d, FONT_AA_W
    push rdi
.px:
    movzx eax, byte [rsi]
    inc  rsi
    mov  edx, ecx
    test eax, eax
    jz   .store
    mov  edx, ebx
    cmp  eax, 255
    je   .store
    call font_aa_blend
.store:
    mov  [rdi], edx
    add  rdi, 4
    dec  r13d
    jnz  .px
    pop  rdi
    mov  eax, [rel fb_stride]
    lea  rdi, [rdi + rax*4]
    dec  r12d
    jnz  .row
.done:
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    ret

; fb_draw_glyph_aa_ref — the naive reference: same cell through 1x1 fills.
fb_draw_glyph_aa_ref:
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done
    ; Solid cells are refused whole at every edge, before address arithmetic.
    test r8d, r8d
    js   .done
    test r9d, r9d
    js   .done
    mov  eax, r8d
    add  eax, FONT_AA_W
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, FONT_AA_H
    cmp  eax, [rel fb_height]
    ja   .done
    call font_aa_glyph_ptr
    mov  r14d, ebx                      ; fg (ebx becomes the fill colour)
    mov  r12d, FONT_AA_H
.row:
    mov  r13d, FONT_AA_W
    push r8
.px:
    movzx eax, byte [rsi]
    inc  rsi
    push rbx
    mov  ebx, r14d
    call font_aa_blend                  ; a == 0 / 255 blend exactly to bg / fg
    pop  rbx
    mov  ebx, edx
    mov  r10d, 1
    mov  r11d, 1
    push rsi
    call fb_fill_rect
    pop  rsi
    inc  r8d
    dec  r13d
    jnz  .px
    pop  r8
    inc  r9d
    dec  r12d
    jnz  .row
.done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    ret

; fb_draw_str_aa_n(rdi=cstr, r8d=x, r9d=y, ebx=fg, ecx=bg, r11d=max cells)
; 9 px advance. Preserves r8..r11/ebx/ecx.
fb_draw_str_aa_n:
    push r8
    push r11
    push r12
    mov  r12, rdi
.next:
    test r11d, r11d
    jz   .done
    movzx edi, byte [r12]
    test edi, edi
    jz   .done
    push r11
    call fb_draw_glyph_aa
    pop  r11
    inc  r12
    add  r8d, FONT_AA_W
    dec  r11d
    jmp  .next
.done:
    pop  r12
    pop  r11
    pop  r8
    ret

; font_aa_kat — boot E5 oracle (see header). Marker only on a double pass.
font_aa_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  qword [rel fb_base], 0
    je   .skip
    lea  r12, [rel fakat_fast]
    lea  r13, [rel fakat_ref]
    ; plant sentinels in both screens
    mov  rdi, r12
    mov  ecx, FAKAT_PIX
    mov  eax, FAKAT_SENTINEL
    cld
    rep  stosd
    mov  rdi, r13
    mov  ecx, FAKAT_PIX
    rep  stosd
    ; redirect the fb globals to each scratch screen in turn
    mov  rax, [rel fb_base]
    push rax
    mov  eax, [rel fb_width]
    push rax
    mov  eax, [rel fb_height]
    push rax
    mov  eax, [rel fb_stride]
    push rax
    mov  dword [rel fb_width], FAKAT_W
    mov  dword [rel fb_height], FAKAT_H
    mov  dword [rel fb_stride], FAKAT_W
    mov  ebx, FAKAT_FG
    mov  ecx, FAKAT_BG
    mov  r8d, FAKAT_X
    mov  r9d, FAKAT_Y
    mov  [rel fb_base], r12
    mov  edi, 'A'
    call fb_draw_glyph_aa
    mov  [rel fb_base], r13
    mov  edi, 'A'
    call fb_draw_glyph_aa_ref
    ; an out-of-bounds cell must be refused whole (sentinels survive)
    mov  [rel fb_base], r12
    mov  r8d, FAKAT_W - FONT_AA_W + 1
    mov  edi, 'W'
    call fb_draw_glyph_aa
    pop  rax
    mov  dword [rel fb_stride], eax
    pop  rax
    mov  dword [rel fb_height], eax
    pop  rax
    mov  dword [rel fb_width], eax
    pop  rax
    mov  [rel fb_base], rax
    ; 1) fast == reference, byte for byte
    mov  rsi, r12
    mov  rdi, r13
    mov  ecx, FAKAT_PIX
    repe cmpsd
    jne  .fail
    ; 2) sentinels intact outside the cell, cell pixels never the sentinel
    xor  ecx, ecx
    xor  r14d, r14d                     ; sentinel count
.scan:
    mov  eax, [r12 + rcx*4]
    cmp  eax, FAKAT_SENTINEL
    jne  .scan_next
    inc  r14d
.scan_next:
    inc  ecx
    cmp  ecx, FAKAT_PIX
    jb   .scan
    cmp  r14d, FAKAT_PIX - FONT_AA_CELL
    jne  .fail
    ; 3) golden FNV-1a over the cell's BGRX bytes, row by row
    mov  r15d, 0x811C9DC5
    mov  r14d, 0                        ; row
.frow:
    mov  eax, r14d
    add  eax, FAKAT_Y
    imul eax, eax, FAKAT_W
    add  eax, FAKAT_X
    lea  rsi, [r12 + rax*4]
    mov  ecx, FONT_AA_W * 4
.fbyte:
    movzx eax, byte [rsi]
    xor  r15d, eax
    imul r15d, r15d, 0x01000193
    inc  rsi
    dec  ecx
    jnz  .fbyte
    inc  r14d
    cmp  r14d, FONT_AA_H
    jb   .frow
    cmp  r15d, FAKAT_GOLDEN_FNV
    jne  .fail
    lea  rdi, [rel str_fakat_pass]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_fakat_fail]
    call serial_string
    jmp  .out
.skip:
    lea  rdi, [rel str_fakat_skip]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_font_aa_0 0
str_fakat_pass: db "[PAOS64] M6 GUI: AA 9x19 glyph fast==naive, sentinels intact, golden 'A' FNV match [gui.font.aa.kat]", 13, 10, 0
str_fakat_fail: db "[PAOS64] M6 GUI: AA 9x19 glyph KAT FAIL [gui.font.aa.kat.fail]", 13, 10, 0
str_fakat_skip: db "[PAOS64] M6 GUI: AA glyph KAT skipped (no framebuffer)", 13, 10, 0
align 16
; fakat_fast..fakat_ref moved to WDATA_gui_font_aa_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_gui_font_aa_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_font_aa_0_bss1 0
resb 48                 ; keeps fakat_fast at its WDATA offset mod 64
alignb 16
fakat_fast: resd FAKAT_PIX
fakat_ref:  resd FAKAT_PIX
%endmacro
WDATA_BSS_DEFER WDATA_gui_font_aa_0_bss1
