;; MODULE gui/vt/vt_engine
;; LAYER 6
;; EXPORTS vt_mem_required, vt_init, vt_reset, vt_feed, vt_resize, vt_cell_ptr, vt_wcwidth, vt_set_scrollback, vt_scrollback_line, vt_palette_rgb, vt_key_encode, vt_char_encode, vt_paste_prefix, vt_paste_suffix, vt_set_reflow
;; IMPORTS
;; OWNER saga:msi_terminal_input_ux
;; vt_engine.asm -- xterm-compatible VT emulation engine for the PaOS Terminal.
;;
;; Peter 2026-09-29: '+ Terminal' must be a real terminal that renders like
;; Windows Terminal. This module is the emulation core only: no globals, no
;; kernel calls, SysV ABI (RDI = VT context), so the identical source is
;; %included by PaOS and assembled as an elf64 object for the host grader
;; (gauntlet_v2/tools/vt), which compares it cell-by-cell with libvterm.
;;
;; Parser: VT500-style state machine; OSC/DCS/SOS/PM/APC strings are consumed
;; and dispatched, never printed. UTF-8 decoding in GROUND. Replies to
;; capability queries go to VT.reply for the host application to send back
;; on the channel (never into local input).
;;
;; Screen model: primary + alternate screens of VT_CELL-byte cells, addressed
;; through per-screen row maps so scrolling rotates row indices.
;;   cell: +0 u32 codepoint (0 = erased), +4 u32 fg, +8 u32 bg,
;;         +12 u16 flags, +14 u8 width (1, 2; 0 = right half of a wide char),
;;         +15 u8 wrap: 1 on a row's last cell when a glyph auto-wrapped onto
;;         the next row (soft wrap); writing or erasing that cell clears it
;;         +16 four ordered u32 nonspacing/enclosing marks (zero terminates).
;;         First 16 bytes retain their offsets; ALL storage uses VT_CELL.
;;   colour: 0 = default, 0x01000000|index, 0x02000000|0xRRGGBB
;;
;; Exported: vt_mem_required, vt_init, vt_reset, vt_feed, vt_resize,
;;           vt_cell_ptr, vt_wcwidth, vt_set_scrollback, vt_scrollback_line.
;;
;; Scrollback (optional, host-supplied): lines that scroll off the top of the
;; primary screen are kept in a ring; ED 3 clears it. The alternate screen
;; never feeds it. It has no effect on the visible grid.

VT_MAX_COLS     equ 256
VT_MAX_ROWS     equ 128
VT_CELL         equ 32
VT_MARK_MAX     equ 4
VT_NPARAMS      equ 32
VT_STRMAX       equ 512
VT_REPLYMAX     equ 1024
VT_UTF8_POISON  equ 0x8000              ; partial value whose completion is > U+10FFFF (-> U+FFFD)

VTC_MARKS       equ 16                  ; four ordered u32 Mn/Me scalars, zero = unused
VTF_MARK_LOSS   equ 0x0100              ; per-cell overflow is also visibly rendered

VTC_CP          equ 0
VTC_FG          equ 4
VTC_BG          equ 8
VTC_FL          equ 12
VTC_W           equ 14
VTC_WRAP        equ 15                  ; spare byte: 1 on a row's last cell = the row soft-wrapped

VT_COL_IDX      equ 0x01000000
VT_COL_RGB      equ 0x02000000

VTF_BOLD        equ 0x0001
VTF_UL          equ 0x0002
VTF_ITALIC      equ 0x0004
VTF_REVERSE     equ 0x0008
VTF_STRIKE      equ 0x0010
VTF_BLINK       equ 0x0020
VTF_CONCEAL     equ 0x0040
VTF_DIM         equ 0x0080

; mode bits (VT.modes)
VTM_DECCKM      equ 0
VTM_DECOM       equ 1
VTM_DECAWM      equ 2
VTM_DECTCEM     equ 3
VTM_IRM         equ 4
VTM_LNM         equ 5
VTM_BPASTE      equ 6
VTM_ALT         equ 7
VTM_M1000       equ 8
VTM_M1002       equ 9
VTM_M1003       equ 10
VTM_M1006       equ 11
VTM_FOCUS       equ 12
VTM_SYNC        equ 13
VTM_DECKPAM     equ 14
VTM_DECSCNM     equ 15
VTM_BLINKCUR    equ 16
VTM_M1005       equ 17
VTM_M1015       equ 18

; parser states
VTS_GROUND      equ 0
VTS_ESC         equ 1
VTS_ESC_INTER   equ 2
VTS_CSI         equ 3
VTS_CSI_IGNORE  equ 4
VTS_STRING      equ 5

; string kinds
VTK_OSC         equ 1
VTK_DCS         equ 2
VTK_IGNORE      equ 3

; saved-cursor slot layout (32 bytes)
VTSV_CX         equ 0
VTSV_CY         equ 4
VTSV_FG         equ 8
VTSV_BG         equ 12
VTSV_FL         equ 16
VTSV_CHARSET    equ 20
VTSV_WRAP       equ 21
VTSV_ORIGIN     equ 22
VTSV_VALID      equ 23

struc VT
    .cols:      resd 1
    .rows:      resd 1
    .maxcols:   resd 1
    .maxrows:   resd 1
    .cx:        resd 1
    .cy:        resd 1
    .top:       resd 1
    .bot:       resd 1
    .modes:     resq 1
    .fg:        resd 1
    .bg:        resd 1
    .fl:        resd 1
    .wrap:      resb 1
    .state:     resb 1
    .charset:   resb 1          ; bit0 G0=DEC, bit1 G1=DEC, bit2 shifted-out (GL=G1)
    .private:   resb 1
    .ninter:    resb 1
    .inter:     resb 3
    .nparams:   resd 1
    .params:    resd VT_NPARAMS
    .colon:     resd 1          ; bit i: params[i] was introduced by ':'
    .pdigit:    resb 1
    .utf_need:  resb 1
    .strkind:   resb 1
    .str_esc:   resb 1
    .utf_cp:    resd 1
    .last_cp:   resd 1
    .saved:     resb 64         ; [0] primary, [32] alternate
    .tabs:      resb 32         ; 256 tab-stop bits
    .strlen:    resd 1
    .strbuf:    resb VT_STRMAX
    .replylen:  resd 1
    .reply:     resb VT_REPLYMAX
    .titlelen:  resd 1
    .title:     resb 256
    .cells:     resq 2          ; primary, alternate cell arrays
    .rowmap:    resq 2          ; u16 row maps
    .dirty:     resb 16         ; 128 row bits
    .cursor_style: resd 1
    .sb_lines:  resd 1          ; scrollback capacity (0 = none: the default)
    .sb_count:  resd 1          ; lines held
    .sb_head:   resd 1          ; next ring slot
    .sb_total:  resd 1          ; lines ever pushed (a viewer anchors on it)
    .sb_base:   resq 1          ; sb_lines x maxcols cells, oldest overwritten
    .mark_overflow: resq 1      ; saturating count of excess Mn/Me scalars since RIS
    .mark_orphan: resq 1        ; marks with no preceding written base
    .rf_base: resq 1            ; caller-owned workspace, default third arena grid
    .rf_bytes: resq 1
    .rf_points: resb 6 * 32     ; inrow(q),incol(d),kind(d),outrow(q),outcol(d),gap(d)
    .rf_screen: resq 1          ; absolute first live output row, for caller anchor mapping
    .rf_oldest: resq 1          ; absolute oldest retained output row
    .rf_dropped: resq 1         ; saturating physical history-row eviction count
    .rf_refused: resq 1         ; saturating atomic resize-refusal count
    .rf_pending: resd 1         ; Terminal painting waits after an atomic resize refusal
    .rf_done: resd 1
    .rf_primary_fixed: resd 1   ; primary policy captured at actual alternate entry
    .rf_pad: resd 1
endstruc

;; ---------------------------------------------------------------------------
;; vt_mem_required(EDI=maxcols, ESI=maxrows) -> RAX bytes for vt_init's arena
vt_mem_required:
    mov  eax, edi
    test eax, eax
    jnz  .cols
    inc  eax
.cols:
    mov  ecx, VT_MAX_COLS
    cmp  eax, ecx
    cmova eax, ecx
    mov  ecx, esi
    test ecx, ecx
    jnz  .rows
    inc  ecx
.rows:
    mov  edx, VT_MAX_ROWS
    cmp  ecx, edx
    cmova ecx, edx
    imul rax, rcx
    imul rax, VT_CELL * 3
    lea  rax, [rax + rcx*4 + 64]
    ret

;; vt_init(RDI=vt, RSI=arena, EDX=maxcols, ECX=maxrows, R8D=cols, R9D=rows)
;; Clears the context, lays out both screens in the arena and resets.
vt_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15d, r8d
    push r9
    ; zero the context
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, VT_size
    cld
    rep  stosb
    pop  r9
    test r13d, r13d
    jnz  .cols_nonzero
    inc  r13d
.cols_nonzero:
    test r14d, r14d
    jnz  .rows_nonzero
    inc  r14d
.rows_nonzero:
    cmp  r13d, VT_MAX_COLS
    jbe  .c_ok
    mov  r13d, VT_MAX_COLS
.c_ok:
    cmp  r14d, VT_MAX_ROWS
    jbe  .r_ok
    mov  r14d, VT_MAX_ROWS
.r_ok:
    mov  [rbx + VT.maxcols], r13d
    mov  [rbx + VT.maxrows], r14d
    ; arena: cells0, cells1, rowmap0, rowmap1
    mov  eax, r13d
    imul eax, r14d
    imul rax, rax, VT_CELL
    mov  [rbx + VT.cells], r12
    lea  rdx, [r12 + rax]
    mov  [rbx + VT.cells + 8], rdx
    lea  rdx, [rdx + rax]
    mov  [rbx + VT.rowmap], rdx
    mov  ecx, r14d
    lea  rdx, [rdx + rcx*2]
    mov  [rbx + VT.rowmap + 8], rdx
    lea  rdx, [rdx + rcx*2 + 63]
    and  rdx, -64
    mov  [rbx + VT.rf_base], rdx
    mov  [rbx + VT.rf_bytes], rax
    ; clamp requested size
    mov  eax, r15d
    call .clamp_cols
    mov  [rbx + VT.cols], eax
    mov  eax, r9d
    call .clamp_rows
    mov  [rbx + VT.rows], eax
    ; identity row maps
    xor  ecx, ecx
.rm:
    cmp  ecx, r14d
    jae  .rm_done
    mov  rdx, [rbx + VT.rowmap]
    mov  [rdx + rcx*2], cx
    mov  rdx, [rbx + VT.rowmap + 8]
    mov  [rdx + rcx*2], cx
    inc  ecx
    jmp  .rm
.rm_done:
    mov  rdi, rbx
    call vt_reset
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.clamp_cols:
    cmp  eax, 1
    jge  .cc1
    mov  eax, 1
.cc1:
    cmp  eax, r13d
    jle  .cc2
    mov  eax, r13d
.cc2:
    ret
.clamp_rows:
    cmp  eax, 1
    jge  .cr1
    mov  eax, 1
.cr1:
    cmp  eax, r14d
    jle  .cr2
    mov  eax, r14d
.cr2:
    ret

;; vt_reset(RDI=vt) -- RIS: both screens blank, modes, tabs, pen, cursor home.
vt_reset:
    push rbx
    mov  rbx, rdi
    mov  qword [rbx + VT.modes], (1 << VTM_DECAWM) | (1 << VTM_DECTCEM)
    mov  dword [rbx + VT.fg], 0
    mov  dword [rbx + VT.bg], 0
    mov  dword [rbx + VT.fl], 0
    mov  byte [rbx + VT.wrap], 0
    mov  byte [rbx + VT.state], VTS_GROUND
    mov  byte [rbx + VT.charset], 0
    mov  byte [rbx + VT.utf_need], 0
    mov  dword [rbx + VT.cx], 0
    mov  dword [rbx + VT.cy], 0
    mov  dword [rbx + VT.top], 0
    mov  eax, [rbx + VT.rows]
    dec  eax
    mov  [rbx + VT.bot], eax
    mov  qword [rbx + VT.rf_dropped], 0
    mov  qword [rbx + VT.rf_refused], 0
    mov  dword [rbx + VT.rf_pending], 0
    mov  dword [rbx + VT.rf_done], 0
    mov  dword [rbx + VT.rf_primary_fixed], 0
    lea  rdi, [rbx + VT.rf_points]
    mov  rcx, 6 * 4
    mov  rax, -1
    rep  stosq
    mov  dword [rbx + VT.rf_points + 92], 0
    mov  dword [rbx + VT.rf_points + 124], 0
    mov  qword [rbx + VT.mark_overflow], 0
    mov  qword [rbx + VT.mark_orphan], 0
    mov  dword [rbx + VT.last_cp], 0
    mov  dword [rbx + VT.cursor_style], 0
    ; saved slots invalid
    lea  rdi, [rbx + VT.saved]
    xor  eax, eax
    mov  ecx, 64
    rep  stosb
    call vt_default_tabs_rbx
    ; clear alternate then primary (clear uses the active screen)
    or   qword [rbx + VT.modes], 1 << VTM_ALT
    call vt_clear_screen_rbx
    and  qword [rbx + VT.modes], ~(1 << VTM_ALT)
    call vt_clear_screen_rbx
    pop  rbx
    ret

vt_default_tabs_rbx:
    lea  rdi, [rbx + VT.tabs]
    mov  al, 0x01                       ; bit0 of every byte = columns 0, 8, 16...
    mov  ecx, 32
    rep  stosb
    ret

;; ---------------------------------------------------------------------------
;; Cell addressing. RBX = vt throughout the internal helpers.

;; row_ptr: ECX = logical row -> RAX = first cell of that row (active screen)
vt_row_ptr_rbx:
    push rdx
    mov  rdx, [rbx + VT.modes]
    bt   rdx, VTM_ALT
    setc dl
    movzx edx, dl
    mov  rax, [rbx + VT.rowmap + rdx*8]
    movzx eax, word [rax + rcx*2]
    imul eax, [rbx + VT.maxcols]
    imul rax, rax, VT_CELL
    add  rax, [rbx + VT.cells + rdx*8]
    pop  rdx
    ret

;; cell_ptr: ECX = row, EDX = col -> RAX
vt_cell_ptr_rbx:
    call vt_row_ptr_rbx
    push rdx
    imul rdx, rdx, VT_CELL
    add  rax, rdx
    pop  rdx
    ret

;; Public: vt_cell_ptr(RDI=vt, ESI=row, EDX=col) -> RAX (active screen)
vt_cell_ptr:
    push rbx
    mov  rbx, rdi
    mov  ecx, esi
    call vt_cell_ptr_rbx
    pop  rbx
    ret

;; blank one cell at RAX with the current background (BCE)
vt_blank_cell_rbx:
    mov  dword [rax + VTC_CP], 0
    mov  dword [rax + VTC_FG], 0
    mov  r10d, [rbx + VT.bg]
    mov  [rax + VTC_BG], r10d
    mov  word [rax + VTC_FL], 0
    mov  byte [rax + VTC_W], 1
    mov  byte [rax + VTC_WRAP], 0
    mov  qword [rax + VTC_MARKS], 0
    mov  qword [rax + VTC_MARKS + 8], 0
    ret

;; vt_mark_wrap_rbx: the cursor row is about to continue on the next row (a real
;; auto-wrap, not a merely pending one): mark its last cell. Copy joins it.
vt_mark_wrap_rbx:
    push rax
    push rcx
    push rdx
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cols]
    dec  edx
    call vt_cell_ptr_rbx
    mov  byte [rax + VTC_WRAP], 1
    pop  rdx
    pop  rcx
    pop  rax
    ret

;; vt_row_wrap_take_rbx(ECX=row) -> R11B = the row's continuation mark; clears
;; every mark on the row so a shift (ICH/DCH) cannot move one into mid-row.
vt_row_wrap_take_rbx:
    push rax
    push rdx
    mov  edx, [rbx + VT.cols]
    dec  edx
    call vt_cell_ptr_rbx
    mov  r11b, [rax + VTC_WRAP]
.clear:
    mov  byte [rax + VTC_WRAP], 0
    sub  rax, VT_CELL
    dec  edx
    jns  .clear
    pop  rdx
    pop  rax
    ret

;; vt_row_wrap_put_rbx(ECX=row, R11B=mark): restore the row's continuation mark.
vt_row_wrap_put_rbx:
    push rax
    push rdx
    mov  edx, [rbx + VT.cols]
    dec  edx
    call vt_cell_ptr_rbx
    mov  [rax + VTC_WRAP], r11b
    pop  rdx
    pop  rax
    ret

;; erase cells [EDX, R8D) of logical row ECX with the current background
vt_erase_span_rbx:
    push rdx
    cmp  r8d, [rbx + VT.cols]
    jle  .ok
    mov  r8d, [rbx + VT.cols]
.ok:
    call vt_mark_dirty_rbx
.loop:
    cmp  edx, r8d
    jge  .done
    push rax
    call vt_fix_wide_overwrite_rbx
    call vt_cell_ptr_rbx
    call vt_blank_cell_rbx
    pop  rax
    inc  edx
    jmp  .loop
.done:
    pop  rdx
    ret

;; mark logical row ECX dirty
vt_mark_dirty_rbx:
    cmp  ecx, 128
    jae  .out
    bts  dword [rbx + VT.dirty], ecx
.out:
    ret

vt_clear_screen_rbx:
    push rcx
    push rdx
    push r8
    xor  ecx, ecx
.row:
    cmp  ecx, [rbx + VT.rows]
    jge  .done
    xor  edx, edx
    mov  r8d, [rbx + VT.cols]
    call vt_erase_span_rbx
    inc  ecx
    jmp  .row
.done:
    pop  r8
    pop  rdx
    pop  rcx
    ret

;; scroll rows [ECX=top, EDX=bot] up by R8D lines (content moves up), blank bottom
vt_scroll_up_rbx:
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov  r9d, edx
    sub  r9d, ecx
    inc  r9d                            ; region height
    cmp  r8d, r9d
    jle  .n_ok
    mov  r8d, r9d
.n_ok:
    test r8d, r8d
    jle  .out
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_ALT
    setc al
    movzx eax, al
    mov  r10, [rbx + VT.rowmap + rax*8]
    ; scrollback: rows leaving the top of the primary screen, oldest first
    test eax, eax
    jnz  .rot
    test ecx, ecx
    jnz  .rot
    cmp  dword [rbx + VT.sb_lines], 0
    je   .rot
    push rdi
    xor  r9d, r9d
.sb:
    cmp  r9d, r8d
    jge  .sb_done
    movzx edi, word [r10 + r9*2]
    call vt_sb_push_rbx
    inc  r9d
    jmp  .sb
.sb_done:
    pop  rdi
.rot:                                   ; rotate map left by one, r8 times
    test r8d, r8d
    jz   .blank
    movzx r11d, word [r10 + rcx*2]
    push rcx
.shift:
    cmp  ecx, edx
    jge  .shift_done
    mov  ax, [r10 + rcx*2 + 2]
    mov  [r10 + rcx*2], ax
    inc  ecx
    jmp  .shift
.shift_done:
    mov  [r10 + rdx*2], r11w
    pop  rcx
    dec  r8d
    jmp  .rot
.blank:
    mov  r8d, [rsp + 24]                ; original n (after clamp? recompute)
    mov  r9d, edx
    sub  r9d, ecx
    inc  r9d
    cmp  r8d, r9d
    jle  .b_ok
    mov  r8d, r9d
.b_ok:
    mov  r11d, edx
    sub  r11d, r8d
    inc  r11d                           ; first blanked row
.bl:
    cmp  r11d, edx
    jg   .dirty
    push rcx
    push rdx
    push r8
    mov  ecx, r11d
    xor  edx, edx
    mov  r8d, [rbx + VT.cols]
    call vt_erase_span_rbx
    pop  r8
    pop  rdx
    pop  rcx
    inc  r11d
    jmp  .bl
.dirty:
    mov  r11d, ecx
.dl:
    cmp  r11d, edx
    jg   .out
    push rcx
    mov  ecx, r11d
    call vt_mark_dirty_rbx
    pop  rcx
    inc  r11d
    jmp  .dl
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    ret

;; vt_sb_push_rbx(EDI = physical primary row): copy it into the scrollback
;; ring (cols cells, blank to maxcols). Preserves everything but RAX.
vt_sb_push_rbx:
    push rcx
    push rdx
    push rsi
    push rdi
    mov  eax, [rbx + VT.sb_head]
    imul eax, [rbx + VT.maxcols]
    imul rax, rax, VT_CELL
    mov  rdx, [rbx + VT.sb_base]
    add  rdx, rax                       ; destination line
    mov  eax, edi
    imul eax, [rbx + VT.maxcols]
    imul rax, rax, VT_CELL
    mov  rsi, [rbx + VT.cells]
    add  rsi, rax                       ; source row (primary screen)
    mov  rdi, rdx
    mov  ecx, [rbx + VT.cols]
    imul ecx, VT_CELL / 4
    cld
    rep  movsd
    mov  ecx, [rbx + VT.maxcols]
    sub  ecx, [rbx + VT.cols]
    jle  .copied
    mov  rax, 0x0001000000000000        ; blank cell: width 1 in byte 14
.blank:
    mov  qword [rdi], 0
    mov  [rdi + 8], rax
    mov  qword [rdi + VTC_MARKS], 0
    mov  qword [rdi + VTC_MARKS + 8], 0
    add  rdi, VT_CELL
    dec  ecx
    jnz  .blank
.copied:
    mov  eax, [rbx + VT.sb_head]
    inc  eax
    cmp  eax, [rbx + VT.sb_lines]
    jb   .head_ok
    xor  eax, eax
.head_ok:
    mov  [rbx + VT.sb_head], eax
    mov  eax, [rbx + VT.sb_count]
    cmp  eax, [rbx + VT.sb_lines]
    jae  .full
    inc  dword [rbx + VT.sb_count]
.full:
    inc  dword [rbx + VT.sb_total]
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    ret

;; vt_set_scrollback(RDI vt, RSI buffer, EDX lines): buffer holds
;; lines x maxcols cells (VT_CELL bytes each); 0 lines disables it.
vt_set_scrollback:
    mov  [rdi + VT.sb_base], rsi
    mov  [rdi + VT.sb_lines], edx
    mov  dword [rdi + VT.sb_count], 0
    mov  dword [rdi + VT.sb_head], 0
    mov  dword [rdi + VT.sb_total], 0
    ret

;; vt_scrollback_line(RDI vt, ESI back = 1 newest .. sb_count oldest)
;; -> RAX = first cell of that saved line, or 0
vt_scrollback_line:
    xor  eax, eax
    test esi, esi
    jz   .out
    cmp  esi, [rdi + VT.sb_count]
    ja   .out
    mov  eax, [rdi + VT.sb_head]
    sub  eax, esi
    jns  .idx
    add  eax, [rdi + VT.sb_lines]
.idx:
    imul eax, [rdi + VT.maxcols]
    imul rax, rax, VT_CELL
    add  rax, [rdi + VT.sb_base]
.out:
    ret

;; scroll rows [ECX=top, EDX=bot] down by R8D lines (content moves down), blank top
vt_scroll_down_rbx:
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov  r9d, edx
    sub  r9d, ecx
    inc  r9d
    cmp  r8d, r9d
    jle  .n_ok
    mov  r8d, r9d
.n_ok:
    test r8d, r8d
    jle  .out
    mov  [rsp + 24], r8                 ; remember clamped n in saved r8 slot
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_ALT
    setc al
    movzx eax, al
    mov  r10, [rbx + VT.rowmap + rax*8]
.rot:
    test r8d, r8d
    jz   .blank
    movzx r11d, word [r10 + rdx*2]
    push rdx
.shift:
    cmp  edx, ecx
    jle  .shift_done
    mov  ax, [r10 + rdx*2 - 2]
    mov  [r10 + rdx*2], ax
    dec  edx
    jmp  .shift
.shift_done:
    mov  [r10 + rcx*2], r11w
    pop  rdx
    dec  r8d
    jmp  .rot
.blank:
    mov  r8, [rsp + 24]
    mov  r11d, ecx
    add  r8d, ecx                       ; one past last blanked row
.bl:
    cmp  r11d, r8d
    jge  .dirty
    push rcx
    push rdx
    push r8
    mov  ecx, r11d
    xor  edx, edx
    mov  r8d, [rbx + VT.cols]
    call vt_erase_span_rbx
    pop  r8
    pop  rdx
    pop  rcx
    inc  r11d
    jmp  .bl
.dirty:
    mov  r11d, ecx
.dl:
    cmp  r11d, edx
    jg   .out
    push rcx
    mov  ecx, r11d
    call vt_mark_dirty_rbx
    pop  rcx
    inc  r11d
    jmp  .dl
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    ret

;; line feed / index: at the bottom margin scroll the region, else move down
vt_index_rbx:
    mov  eax, [rbx + VT.cy]
    cmp  eax, [rbx + VT.bot]
    jne  .down
    push rcx
    push rdx
    push r8
    mov  ecx, [rbx + VT.top]
    mov  edx, [rbx + VT.bot]
    mov  r8d, 1
    call vt_scroll_up_rbx
    pop  r8
    pop  rdx
    pop  rcx
    ret
.down:
    mov  ecx, [rbx + VT.rows]
    dec  ecx
    cmp  eax, ecx
    jge  .out
    inc  dword [rbx + VT.cy]
.out:
    ret

vt_reverse_index_rbx:
    mov  eax, [rbx + VT.cy]
    cmp  eax, [rbx + VT.top]
    jne  .up
    push rcx
    push rdx
    push r8
    mov  ecx, [rbx + VT.top]
    mov  edx, [rbx + VT.bot]
    mov  r8d, 1
    call vt_scroll_down_rbx
    pop  r8
    pop  rdx
    pop  rcx
    ret
.up:
    test eax, eax
    jz   .out
    dec  dword [rbx + VT.cy]
.out:
    ret

;; ---------------------------------------------------------------------------
;; Unicode width: 0, 1 or 2 for EDI = codepoint -> EAX
vt_wcwidth:
    cmp  edi, 0x20
    jb   .zero
    cmp  edi, 0x7f
    jb   .one
    cmp  edi, 0xa0
    jb   .zero
    cmp  edi, 0x300
    jb   .one
    lea  rsi, [rel vt_width0]
    mov  ecx, [rel vt_width0_count]
    call .search
    jc   .zero
    lea  rsi, [rel vt_width2]
    mov  ecx, [rel vt_width2_count]
    call .search
    jc   .two
.one:
    mov  eax, 1
    ret
.zero:
    xor  eax, eax
    ret
.two:
    mov  eax, 2
    ret
;; binary search sorted [lo,hi] pairs at RSI (ECX pairs) for EDI; CF=1 if inside
.search:
    xor  edx, edx                       ; lo index
.s_loop:
    cmp  edx, ecx
    jae  .s_no
    mov  eax, edx
    add  eax, ecx
    shr  eax, 1                         ; mid
    cmp  edi, [rsi + rax*8]
    jb   .s_left
    cmp  edi, [rsi + rax*8 + 4]
    jbe  .s_yes
    lea  edx, [eax + 1]
    jmp  .s_loop
.s_left:
    mov  ecx, eax
    jmp  .s_loop
.s_yes:
    stc
    ret
.s_no:
    clc
    ret

;; ---------------------------------------------------------------------------
;; Output: vt_feed(RDI=vt, RSI=bytes, EDX=len)
vt_feed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    xor  r14d, r14d
.next:
    cmp  r14d, r13d
    jae  .done
    movzx edi, byte [r12 + r14]
    inc  r14d
    ; A query emits its complete answer during the byte that dispatches it.
    ; Roll back that unit if the bounded reply batch cannot hold all of it.
    mov  eax, [rbx + VT.replylen]
    cmp  eax, VT_REPLYMAX
    jbe  .reply_valid
    xor  eax, eax
    mov  [rbx + VT.replylen], eax
.reply_valid:
    push rax
    call vt_byte_rbx
    pop  rax
    cmp  dword [rbx + VT.replylen], VT_REPLYMAX
    jbe  .next
    mov  [rbx + VT.replylen], eax
    jmp  .next
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; process one byte EDI (RBX = vt)
vt_byte_rbx:
    movzx eax, byte [rbx + VT.state]
    cmp  eax, VTS_STRING
    je   vt_string_byte_rbx
    cmp  edi, 0x18                      ; CAN
    je   .abort
    cmp  edi, 0x1a                      ; SUB
    je   .abort
    cmp  byte [rbx + VT.utf_need], 0
    je   .no_partial
    cmp  edi, 0x80
    jae  .no_partial                    ; continuation/lead bytes decide themselves
    push rdi
    mov  byte [rbx + VT.utf_need], 0
    mov  edi, 0xfffd
    call vt_print_cp_rbx
    pop  rdi
    movzx eax, byte [rbx + VT.state]
.no_partial:
    cmp  edi, 0x1b
    je   .esc
    cmp  eax, VTS_GROUND
    jne  .in_seq
    cmp  edi, 0x20
    jb   vt_control_rbx
    cmp  edi, 0x7f
    je   .ignore
    cmp  edi, 0x80
    jb   .ascii
    jmp  vt_utf8_byte_rbx
.ascii:
    mov  byte [rbx + VT.utf_need], 0
    jmp  vt_print_ascii_rbx
.ignore:
    ret
.abort:
    mov  byte [rbx + VT.state], VTS_GROUND
    mov  byte [rbx + VT.utf_need], 0
    ret
.esc:
    mov  byte [rbx + VT.utf_need], 0
    mov  byte [rbx + VT.state], VTS_ESC
    mov  byte [rbx + VT.ninter], 0
    ret
.in_seq:
    cmp  edi, 0x20
    jb   vt_control_rbx                 ; C0 inside a sequence executes
    cmp  edi, 0x7f
    je   .ignore
    cmp  eax, VTS_ESC
    je   vt_esc_byte_rbx
    cmp  eax, VTS_ESC_INTER
    je   vt_esc_inter_byte_rbx
    cmp  eax, VTS_CSI
    je   vt_csi_byte_rbx
    ; CSI_IGNORE: wait for a final byte
    cmp  edi, 0x40
    jb   .ignore
    cmp  edi, 0x7e
    ja   .ignore
    mov  byte [rbx + VT.state], VTS_GROUND
    ret

;; UTF-8 decoding in GROUND
vt_utf8_byte_rbx:
    movzx eax, byte [rbx + VT.utf_need]
    test eax, eax
    jnz  .cont
    cmp  edi, 0xc2
    jb   .bad
    cmp  edi, 0xe0
    jb   .two
    cmp  edi, 0xf0
    jb   .three
    cmp  edi, 0xf5
    jb   .four
.bad:
    mov  byte [rbx + VT.utf_need], 0
    mov  edi, 0xfffd
    jmp  vt_print_cp_rbx
.two:
    and  edi, 0x1f
    mov  [rbx + VT.utf_cp], edi
    mov  byte [rbx + VT.utf_need], 1
    ret
.three:
    and  edi, 0x0f
    mov  [rbx + VT.utf_cp], edi
    mov  byte [rbx + VT.utf_need], 2
    ret
.four:
    and  edi, 0x07
    mov  [rbx + VT.utf_cp], edi
    mov  byte [rbx + VT.utf_need], 3
    ret
.cont:
    cmp  edi, 0x80
    jb   .bad
    cmp  edi, 0xbf
    ja   .restart
    mov  eax, [rbx + VT.utf_cp]
    shl  eax, 6
    and  edi, 0x3f
    or   eax, edi
    ; RCQ-22: an overlong 3/4-byte form shows at its first continuation byte
    ; (code point >> 6 < 0x20 for three bytes, >> 12 < 0x10 for four). Poison
    ; the value so the completed sequence is one U+FFFD, as a surrogate or a
    ; value above U+10FFFF already is -- never ASCII, a control or a lookalike.
    ; (need 2 also covers a 4-byte form's second continuation, whose value is
    ; then >= 0x400 or already poisoned.)
    movzx ecx, byte [rbx + VT.utf_need]
    cmp  ecx, 2
    jne  .min_four
    cmp  eax, 0x20
    jb   .overlong
    jmp  .min_ok
.min_four:
    cmp  ecx, 3
    jne  .min_ok
    cmp  eax, 0x10
    jae  .min_ok
.overlong:
    mov  eax, VT_UTF8_POISON
.min_ok:
    mov  [rbx + VT.utf_cp], eax
    dec  byte [rbx + VT.utf_need]
    jnz  .wait
    mov  edi, eax
    cmp  edi, 0x10ffff
    ja   .repl
    mov  eax, edi
    and  eax, 0xfffff800
    cmp  eax, 0xd800
    je   .repl
    jmp  vt_print_cp_rbx
.repl:
    mov  edi, 0xfffd
    jmp  vt_print_cp_rbx
.wait:
    ret
.restart:                               ; a new lead byte interrupts the sequence
    push rdi
    mov  byte [rbx + VT.utf_need], 0
    mov  edi, 0xfffd
    call vt_print_cp_rbx
    pop  rdi
    jmp  vt_utf8_byte_rbx

;; C0 controls
vt_control_rbx:
    cmp  edi, 0x08
    je   .bs
    cmp  edi, 0x09
    je   .ht
    cmp  edi, 0x0a
    je   .lf
    cmp  edi, 0x0b
    je   .lf
    cmp  edi, 0x0c
    je   .lf
    cmp  edi, 0x0d
    je   .cr
    cmp  edi, 0x0e
    je   .so
    cmp  edi, 0x0f
    je   .si
    ret                                 ; BEL and the rest: no screen effect
.bs:
    mov  byte [rbx + VT.wrap], 0
    mov  eax, [rbx + VT.cx]
    test eax, eax
    jz   .out
    dec  dword [rbx + VT.cx]
.out:
    ret
.ht:
    mov  edi, 1
    jmp  vt_tab_forward_rbx
.lf:
    mov  byte [rbx + VT.wrap], 0
    call vt_index_rbx
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_LNM
    jnc  .out
.cr:
    mov  dword [rbx + VT.cx], 0
    mov  byte [rbx + VT.wrap], 0
    ret
.so:
    or   byte [rbx + VT.charset], 4
    ret
.si:
    and  byte [rbx + VT.charset], ~4
    ret

;; move to the next tab stop EDI times (stops at the last column)
vt_tab_forward_rbx:
    ; a pending wrap sits on the last column: HT has no stop to reach and
    ; leaves the wrap pending (libvterm, tmux), so the next glyph wraps
    cmp  byte [rbx + VT.wrap], 0
    jne  .done
.each:
    test edi, edi
    jz   .done
    mov  eax, [rbx + VT.cx]
.scan:
    inc  eax
    mov  ecx, [rbx + VT.cols]
    dec  ecx
    cmp  eax, ecx
    jge  .last
    bt   dword [rbx + VT.tabs], eax
    jnc  .scan
    mov  [rbx + VT.cx], eax
    dec  edi
    jmp  .each
.last:
    mov  [rbx + VT.cx], ecx
.done:
    ret

vt_tab_back_rbx:
    mov  byte [rbx + VT.wrap], 0
.each:
    test edi, edi
    jz   .done
    mov  eax, [rbx + VT.cx]
.scan:
    test eax, eax
    jz   .first
    dec  eax
    bt   dword [rbx + VT.tabs], eax
    jnc  .scan
    mov  [rbx + VT.cx], eax
    dec  edi
    jmp  .each
.first:
    mov  dword [rbx + VT.cx], 0
.done:
    ret

;; ---------------------------------------------------------------------------
;; Printing
vt_print_ascii_rbx:
    ; DEC special graphics when the active G set is DEC
    movzx eax, byte [rbx + VT.charset]
    test eax, 4
    jz   .g0
    test eax, 2
    jz   vt_print_cp_rbx
    jmp  .dec
.g0:
    test eax, 1
    jz   vt_print_cp_rbx
.dec:
    cmp  edi, 0x5f
    jb   vt_print_cp_rbx
    cmp  edi, 0x7e
    ja   vt_print_cp_rbx
    lea  rax, [rel vt_dec_graphics]
    mov  edi, [rax + rdi*4 - 0x5f*4]
    jmp  vt_print_cp_rbx

;; print codepoint EDI at the cursor
vt_print_cp_rbx:
    push r12
    push r13
    mov  r12d, edi
    call vt_wcwidth
    mov  r13d, eax
    test r13d, r13d
    jz   .mark                          ; Mn/Me retained; format/Jamo keep existing width-zero behavior
    mov  [rbx + VT.last_cp], r12d
    ; pending wrap
    cmp  byte [rbx + VT.wrap], 0
    je   .nowrap
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_DECAWM
    jnc  .nowrap
    mov  byte [rbx + VT.wrap], 0
    call vt_mark_wrap_rbx               ; a glyph really continues on the next row
    mov  dword [rbx + VT.cx], 0
    call vt_index_rbx
.nowrap:
    ; wide char that does not fit in the last column
    cmp  r13d, 2
    jne  .fits
    cmp  dword [rbx + VT.cols], 1
    je   .narrow                       ; no second cell exists, even with auto-wrap
    mov  eax, [rbx + VT.cx]
    inc  eax
    cmp  eax, [rbx + VT.cols]
    jl   .fits
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_DECAWM
    jnc  .narrow
    ; blank the last column then wrap
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cx]
    mov  r8d, edx
    inc  r8d
    call vt_erase_span_rbx
    call vt_mark_wrap_rbx
    mov  dword [rbx + VT.cx], 0
    call vt_index_rbx
    jmp  .fits
.narrow:
    mov  r13d, 1
.fits:
    ; insert mode shifts the tail right
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_IRM
    jnc  .write
    mov  edi, r13d
    call vt_insert_chars_rbx
.write:
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cx]
    call vt_mark_dirty_rbx
    call vt_fix_wide_overwrite_rbx
    call vt_cell_ptr_rbx
    mov  qword [rax + VTC_MARKS], 0
    mov  qword [rax + VTC_MARKS + 8], 0
    mov  [rax + VTC_CP], r12d
    mov  r8d, [rbx + VT.fg]
    mov  [rax + VTC_FG], r8d
    mov  r8d, [rbx + VT.bg]
    mov  [rax + VTC_BG], r8d
    mov  r8d, [rbx + VT.fl]
    mov  [rax + VTC_FL], r8w
    mov  [rax + VTC_W], r13b
    mov  byte [rax + VTC_WRAP], 0       ; an overwritten last cell ends the continuation
    cmp  r13d, 2
    jne  .advance
    ; right half of a wide character
    inc  edx
    cmp  edx, [rbx + VT.cols]
    jge  .advance
    call vt_fix_wide_overwrite_rbx
    lea  r9, [rax + VT_CELL]
    mov  qword [r9 + VTC_MARKS], 0
    mov  qword [r9 + VTC_MARKS + 8], 0
    mov  dword [r9 + VTC_CP], 0
    mov  r8d, [rbx + VT.fg]
    mov  [r9 + VTC_FG], r8d
    mov  r8d, [rbx + VT.bg]
    mov  [r9 + VTC_BG], r8d
    mov  r8d, [rbx + VT.fl]
    mov  [r9 + VTC_FL], r8w
    mov  byte [r9 + VTC_W], 0
    mov  byte [r9 + VTC_WRAP], 0
.advance:
    mov  eax, [rbx + VT.cx]
    add  eax, r13d
    mov  ecx, [rbx + VT.cols]
    cmp  eax, ecx
    jl   .set
    dec  ecx
    mov  [rbx + VT.cx], ecx
    ; Remember the printed right edge even with DECAWM off: marks attach here.
    ; The next spacing glyph still consults DECAWM before any actual wrap.
    mov  byte [rbx + VT.wrap], 1
    jmp  .out
.set:
    mov  [rbx + VT.cx], eax
    jmp  .out
.mark:
    ; wcwidth's zero set ALSO includes Cf and medial/final Hangul Jamo.
    ; Only Unicode Mn/Me attach. VS are retained, not interpreted as shaping.
    mov  edi, r12d
    lea  rsi, [rel vt_marks]
    mov  ecx, [rel vt_marks_count]
    call vt_wcwidth.search
    jnc  .out
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cx]
    cmp  byte [rbx + VT.wrap], 0
    jne  .mark_cell                     ; pending wrap still belongs to this row
    test edx, edx
    jz   .orphan
    dec  edx
.mark_cell:
    call vt_cell_ptr_rbx
    cmp  byte [rax + VTC_W], 0
    jne  .mark_base
    test edx, edx
    jz   .orphan
    dec  edx
    call vt_cell_ptr_rbx
    cmp  byte [rax + VTC_W], 2
    jne  .orphan
.mark_base:
    cmp  dword [rax + VTC_CP], 0
    je   .orphan
    xor  edx, edx
.mark_slot:
    cmp  dword [rax + VTC_MARKS + rdx*4], 0
    je   .mark_store
    inc  edx
    cmp  edx, VT_MARK_MAX
    jb   .mark_slot
    or   word [rax + VTC_FL], VTF_MARK_LOSS
    cmp  qword [rbx + VT.mark_overflow], -1
    je   .mark_dirty
    inc  qword [rbx + VT.mark_overflow]
    jmp  .mark_dirty
.mark_store:
    mov  [rax + VTC_MARKS + rdx*4], r12d
.mark_dirty:
    call vt_mark_dirty_rbx
    jmp  .out
.orphan:
    cmp  qword [rbx + VT.mark_orphan], -1
    je   .out
    inc  qword [rbx + VT.mark_orphan]
.out:
    pop  r13
    pop  r12
    ret

;; Before writing cell (ECX=row, EDX=col): if it is half of a wide pair, blank
;; the other half so no orphaned half remains. Preserves ECX/EDX.
vt_fix_wide_overwrite_rbx:
    push rax
    call vt_cell_ptr_rbx
    cmp  byte [rax + VTC_W], 0
    jne  .lead
    test edx, edx
    jz   .check_lead
    push rdx
    dec  edx
    call vt_cell_ptr_rbx
    cmp  byte [rax + VTC_W], 2
    jne  .no_left
    call vt_blank_cell_rbx
.no_left:
    pop  rdx
    jmp  .check_lead_restore
.check_lead_restore:
.check_lead:
    call vt_cell_ptr_rbx
.lead:
    cmp  byte [rax + VTC_W], 2
    jne  .done
    push rdx
    inc  edx
    cmp  edx, [rbx + VT.cols]
    jge  .skip
    push rax
    call vt_cell_ptr_rbx
    cmp  byte [rax + VTC_W], 0
    jne  .keep
    call vt_blank_cell_rbx
.keep:
    pop  rax
.skip:
    pop  rdx
.done:
    pop  rax
    ret

;; After cell shifts/truncation, remove broken wide pairs and their marks.
;; ECX row; keeps all registers except RAX, just as blank-cell uses R10.
vt_repair_row_rbx:
    push rdx
    push r10
    push r12
    push r13
    call vt_row_ptr_rbx
    mov  r12, rax
    xor  r13d, r13d
.next:
    cmp  r13d, [rbx + VT.cols]
    jae  .done
    mov  rax, r12
    cmp  byte [rax + VTC_W], 0
    je   .blank                        ; unmatched continuation
    cmp  byte [rax + VTC_W], 2
    jne  .advance
    lea  edx, [r13d + 1]
    cmp  edx, [rbx + VT.cols]
    jae  .blank
    cmp  byte [rax + VT_CELL + VTC_W], 0
    jne  .blank
    add  r12, VT_CELL                  ; matched pair: skip continuation
    inc  r13d
    jmp  .advance
.blank:
    call vt_blank_cell_rbx
.advance:
    add  r12, VT_CELL
    inc  r13d
    jmp  .next
.done:
    pop  r13
    pop  r12
    pop  r10
    pop  rdx
    ret

;; ICH: insert EDI blank cells at the cursor (tail shifts right, drops off)
vt_insert_chars_rbx:
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, [rbx + VT.cols]
    mov  eax, [rbx + VT.cx]
    sub  r13d, eax                      ; cells from cursor to end
    cmp  r12d, r13d
    jle  .n_ok
    mov  r12d, r13d
.n_ok:
    mov  ecx, [rbx + VT.cy]
    call vt_mark_dirty_rbx
    push r11
    call vt_row_wrap_take_rbx           ; the continuation is a row attribute
    mov  edx, [rbx + VT.cx]
    call vt_cell_ptr_rbx
    mov  r14, rax                       ; cursor cell
    ; memmove(cursor + n, cursor, (count - n) cells) backwards
    mov  ecx, r13d
    sub  ecx, r12d
    imul rcx, rcx, VT_CELL
    lea  rsi, [r14 + rcx - 1]
    mov  eax, r12d
    imul rax, rax, VT_CELL
    lea  rdi, [rsi + rax]
    std
    rep  movsb
    cld
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cx]
    lea  r8d, [edx + r12d]
    call vt_erase_span_rbx
    call vt_repair_row_rbx
    call vt_row_wrap_put_rbx
    pop  r11
    pop  r14
    pop  r13
    pop  r12
    ret

;; DCH: delete EDI cells at the cursor (tail shifts left, blanks fill the end)
vt_delete_chars_rbx:
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, [rbx + VT.cols]
    mov  eax, [rbx + VT.cx]
    sub  r13d, eax
    cmp  r12d, r13d
    jle  .n_ok
    mov  r12d, r13d
.n_ok:
    mov  ecx, [rbx + VT.cy]
    call vt_mark_dirty_rbx
    push r11
    call vt_row_wrap_take_rbx
    mov  edx, [rbx + VT.cx]
    call vt_cell_ptr_rbx
    mov  r14, rax
    mov  ecx, r13d
    sub  ecx, r12d
    imul rcx, rcx, VT_CELL
    mov  rdi, r14
    mov  eax, r12d
    imul rax, rax, VT_CELL
    lea  rsi, [r14 + rax]
    cld
    rep  movsb
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cols]
    sub  edx, r12d
    mov  r8d, [rbx + VT.cols]
    call vt_erase_span_rbx
    call vt_repair_row_rbx
    call vt_row_wrap_put_rbx
    pop  r11
    pop  r14
    pop  r13
    pop  r12
    ret

;; ---------------------------------------------------------------------------
;; ESC sequences
vt_esc_byte_rbx:
    cmp  edi, 0x2f
    jbe  .inter
    cmp  edi, '['
    je   .csi
    cmp  edi, ']'
    je   .osc
    cmp  edi, 'P'
    je   .dcs
    cmp  edi, 'X'
    je   .ign
    cmp  edi, '^'
    je   .ign
    cmp  edi, '_'
    je   .ign
    mov  byte [rbx + VT.state], VTS_GROUND
    jmp  vt_esc_dispatch_rbx
.inter:
    mov  byte [rbx + VT.inter], dil
    mov  byte [rbx + VT.ninter], 1
    mov  byte [rbx + VT.state], VTS_ESC_INTER
    ret
.csi:
    mov  byte [rbx + VT.state], VTS_CSI
    mov  dword [rbx + VT.nparams], 0
    mov  dword [rbx + VT.colon], 0
    mov  byte [rbx + VT.pdigit], 0
    mov  byte [rbx + VT.private], 0
    mov  byte [rbx + VT.ninter], 0
    mov  dword [rbx + VT.params], 0
    ret
.osc:
    mov  byte [rbx + VT.strkind], VTK_OSC
    jmp  .string
.dcs:
    mov  byte [rbx + VT.strkind], VTK_DCS
    jmp  .string
.ign:
    mov  byte [rbx + VT.strkind], VTK_IGNORE
.string:
    mov  byte [rbx + VT.state], VTS_STRING
    mov  dword [rbx + VT.strlen], 0
    mov  byte [rbx + VT.str_esc], 0
    ret

vt_esc_inter_byte_rbx:
    cmp  edi, 0x2f
    ja   .final
    movzx eax, byte [rbx + VT.ninter]
    cmp  eax, 3
    jae  .skip
    mov  [rbx + VT.inter + rax], dil
    inc  byte [rbx + VT.ninter]
.skip:
    ret
.final:
    mov  byte [rbx + VT.state], VTS_GROUND
    movzx eax, byte [rbx + VT.inter]
    cmp  eax, '('
    je   .g0
    cmp  eax, ')'
    je   .g1
    cmp  eax, '#'
    je   .hash
    ret                                 ; ESC SP F, ESC % G, ... ignored
.g0:
    and  byte [rbx + VT.charset], ~1
    cmp  edi, '0'
    jne  .out
    or   byte [rbx + VT.charset], 1
.out:
    ret
.g1:
    and  byte [rbx + VT.charset], ~2
    cmp  edi, '0'
    jne  .out
    or   byte [rbx + VT.charset], 2
    ret
.hash:
    cmp  edi, '8'
    jne  .out
    ; DECALN: fill the screen with 'E', reset margins, home
    push r12
    xor  r12d, r12d
.aln_row:
    cmp  r12d, [rbx + VT.rows]
    jge  .aln_done
    mov  ecx, r12d
    call vt_mark_dirty_rbx
    xor  edx, edx
.aln_col:
    cmp  edx, [rbx + VT.cols]
    jge  .aln_next
    call vt_cell_ptr_rbx
    mov  qword [rax + VTC_MARKS], 0
    mov  qword [rax + VTC_MARKS + 8], 0
    mov  dword [rax + VTC_CP], 'E'
    mov  dword [rax + VTC_FG], 0
    mov  dword [rax + VTC_BG], 0
    mov  word [rax + VTC_FL], 0
    mov  byte [rax + VTC_W], 1
    mov  byte [rax + VTC_WRAP], 0
    inc  edx
    jmp  .aln_col
.aln_next:
    inc  r12d
    jmp  .aln_row
.aln_done:
    pop  r12
    mov  dword [rbx + VT.top], 0
    mov  eax, [rbx + VT.rows]
    dec  eax
    mov  [rbx + VT.bot], eax
    mov  dword [rbx + VT.cx], 0
    mov  dword [rbx + VT.cy], 0
    mov  byte [rbx + VT.wrap], 0
    ret

vt_esc_dispatch_rbx:
    cmp  edi, '7'
    je   .decsc
    cmp  edi, '8'
    je   .decrc
    cmp  edi, 'D'
    je   .ind
    cmp  edi, 'E'
    je   .nel
    cmp  edi, 'H'
    je   .hts
    cmp  edi, 'M'
    je   .ri
    cmp  edi, 'c'
    je   .ris
    cmp  edi, '='
    je   .deckpam
    cmp  edi, '>'
    je   .deckpnm
    ret
.decsc:
    jmp  vt_save_cursor_rbx
.decrc:
    jmp  vt_restore_cursor_rbx
.ind:
    mov  byte [rbx + VT.wrap], 0
    jmp  vt_index_rbx
.nel:
    mov  byte [rbx + VT.wrap], 0
    mov  dword [rbx + VT.cx], 0
    jmp  vt_index_rbx
.hts:
    mov  eax, [rbx + VT.cx]
    bts  dword [rbx + VT.tabs], eax
    ret
.ri:
    mov  byte [rbx + VT.wrap], 0
    jmp  vt_reverse_index_rbx
.ris:
    mov  rdi, rbx
    jmp  vt_reset
.deckpam:
    bts  qword [rbx + VT.modes], VTM_DECKPAM
    ret
.deckpnm:
    btr  qword [rbx + VT.modes], VTM_DECKPAM
    ret

;; saved-cursor slot for the active screen -> RAX
vt_saved_slot_rbx:
    lea  rax, [rbx + VT.saved]
    mov  rcx, [rbx + VT.modes]
    bt   rcx, VTM_ALT
    jnc  .p
    add  rax, 32
.p:
    ret

vt_save_cursor_rbx:
    call vt_saved_slot_rbx
    mov  ecx, [rbx + VT.cx]
    mov  [rax + VTSV_CX], ecx
    mov  ecx, [rbx + VT.cy]
    mov  [rax + VTSV_CY], ecx
    mov  ecx, [rbx + VT.fg]
    mov  [rax + VTSV_FG], ecx
    mov  ecx, [rbx + VT.bg]
    mov  [rax + VTSV_BG], ecx
    mov  ecx, [rbx + VT.fl]
    mov  [rax + VTSV_FL], ecx
    mov  cl, [rbx + VT.charset]
    mov  [rax + VTSV_CHARSET], cl
    mov  cl, [rbx + VT.wrap]
    mov  [rax + VTSV_WRAP], cl
    mov  rcx, [rbx + VT.modes]
    bt   rcx, VTM_DECOM
    setc cl
    mov  [rax + VTSV_ORIGIN], cl
    mov  byte [rax + VTSV_VALID], 1
    ret

vt_restore_cursor_rbx:
    call vt_saved_slot_rbx
    cmp  byte [rax + VTSV_VALID], 0
    jne  .valid
    ; nothing saved: home, default pen
    mov  dword [rbx + VT.cx], 0
    mov  dword [rbx + VT.cy], 0
    mov  dword [rbx + VT.fg], 0
    mov  dword [rbx + VT.bg], 0
    mov  dword [rbx + VT.fl], 0
    btr  qword [rbx + VT.modes], VTM_DECOM
    mov  byte [rbx + VT.wrap], 0
    ret
.valid:
    mov  ecx, [rax + VTSV_CX]
    mov  edx, [rbx + VT.cols]
    dec  edx
    cmp  ecx, edx
    jle  .cx_ok
    mov  ecx, edx
.cx_ok:
    mov  [rbx + VT.cx], ecx
    mov  ecx, [rax + VTSV_CY]
    mov  edx, [rbx + VT.rows]
    dec  edx
    cmp  ecx, edx
    jle  .cy_ok
    mov  ecx, edx
.cy_ok:
    mov  [rbx + VT.cy], ecx
    mov  ecx, [rax + VTSV_FG]
    mov  [rbx + VT.fg], ecx
    mov  ecx, [rax + VTSV_BG]
    mov  [rbx + VT.bg], ecx
    mov  ecx, [rax + VTSV_FL]
    mov  [rbx + VT.fl], ecx
    mov  cl, [rax + VTSV_CHARSET]
    mov  [rbx + VT.charset], cl
    mov  cl, [rax + VTSV_WRAP]
    mov  [rbx + VT.wrap], cl
    btr  qword [rbx + VT.modes], VTM_DECOM
    cmp  byte [rax + VTSV_ORIGIN], 0
    je   .out
    bts  qword [rbx + VT.modes], VTM_DECOM
.out:
    ret

;; ---------------------------------------------------------------------------
;; CSI collection
vt_csi_byte_rbx:
    cmp  edi, 0x30
    jb   .inter
    cmp  edi, 0x39
    jbe  .digit
    cmp  edi, ';'
    je   .semi
    cmp  edi, ':'
    je   .colon
    cmp  edi, 0x3f
    jbe  .private
    cmp  edi, 0x7e
    ja   .ignore
    ; final byte 0x40..0x7e
    mov  byte [rbx + VT.state], VTS_GROUND
    call .close_param
    jmp  vt_csi_dispatch_rbx
.inter:
    ; 0x20..0x2f
    movzx eax, byte [rbx + VT.ninter]
    cmp  eax, 2
    jae  .ignore
    mov  [rbx + VT.inter + rax], dil
    inc  byte [rbx + VT.ninter]
    ret
.digit:
    cmp  byte [rbx + VT.ninter], 0
    jne  .ignore                        ; parameters after intermediates
    mov  byte [rbx + VT.pdigit], 1
    mov  eax, [rbx + VT.nparams]
    cmp  eax, VT_NPARAMS
    jae  .ret
    mov  edx, VT_NPARAMS - 1
    cmp  eax, edx
    cmova eax, edx                     ; constant 32-slot address bound
    lea  rcx, [rbx + VT.params]
    mov  edx, [rcx + rax*4]
    imul edx, edx, 10
    sub  edi, '0'
    add  edx, edi
    cmp  edx, 65535
    jbe  .d_ok
    mov  edx, 65535
.d_ok:
    mov  [rcx + rax*4], edx
.ret:
    ret
.semi:
    call .close_param
    ret
.colon:
    call .close_param
    mov  eax, [rbx + VT.nparams]
    cmp  eax, 32
    jae  .ret
    mov  ecx, VT_NPARAMS - 1
    cmp  eax, ecx
    cmova eax, ecx                     ; memory BTS also uses an address index
    bts  dword [rbx + VT.colon], eax
    ret
.private:
    ; '<' '=' '>' '?' valid only before any parameter byte
    cmp  dword [rbx + VT.nparams], 0
    jne  .ignore
    cmp  byte [rbx + VT.pdigit], 0
    jne  .ignore
    cmp  byte [rbx + VT.private], 0
    jne  .ignore
    mov  [rbx + VT.private], dil
    ret
.ignore:
    mov  byte [rbx + VT.state], VTS_CSI_IGNORE
    ret
;; finish the current parameter slot (a missing value stays 0 = default)
.close_param:
    mov  eax, [rbx + VT.nparams]
    cmp  eax, VT_NPARAMS
    jae  .cp_out
    inc  eax
    mov  [rbx + VT.nparams], eax
    cmp  eax, VT_NPARAMS
    jae  .cp_out
    mov  ecx, VT_NPARAMS - 1
    cmp  eax, ecx
    cmova eax, ecx                     ; do not wrap the saved logical count
    lea  rcx, [rbx + VT.params]
    mov  dword [rcx + rax*4], 0
.cp_out:
    mov  byte [rbx + VT.pdigit], 0
    ret

;; param(i=ECX) -> EAX (0 if absent)
vt_param_rbx:
    xor  eax, eax
    cmp  ecx, [rbx + VT.nparams]
    jae  .out
    mov  eax, VT_NPARAMS - 1
    cmp  ecx, eax
    cmovb eax, ecx                     ; preserve ECX for parameter-list callers
    mov  eax, [rbx + VT.params + rax*4]
.out:
    ret

;; param(i=ECX) with 0/absent -> 1
vt_param1_rbx:
    call vt_param_rbx
    test eax, eax
    jnz  .out
    mov  eax, 1
.out:
    ret

;; ---------------------------------------------------------------------------
;; CSI dispatch: EDI = final byte
vt_csi_dispatch_rbx:
    movzx eax, byte [rbx + VT.private]
    test eax, eax
    jnz  vt_csi_private_rbx
    cmp  byte [rbx + VT.ninter], 0
    jne  vt_csi_inter_rbx
    ; SGR, DSR and DA keep a pending wrap (xterm, libvterm). Clearing it made the next
    ; character overwrite the last column of a line that a per-cell colour run had just
    ; filled (ls --color, htop meters, a 256-colour table).
    cmp  edi, 'm'
    je   .wrap_kept
    cmp  edi, 'n'
    je   .wrap_kept
    cmp  edi, 'c'
    je   .wrap_kept
    mov  byte [rbx + VT.wrap], 0
.wrap_kept:
    cmp  edi, '@'
    je   .ich
    cmp  edi, 'A'
    je   .cuu
    cmp  edi, 'B'
    je   .cud
    cmp  edi, 'C'
    je   .cuf
    cmp  edi, 'D'
    je   .cub
    cmp  edi, 'E'
    je   .cnl
    cmp  edi, 'F'
    je   .cpl
    cmp  edi, 'G'
    je   .cha
    cmp  edi, 'H'
    je   .cup
    cmp  edi, 'I'
    je   .cht
    cmp  edi, 'J'
    je   .ed
    cmp  edi, 'K'
    je   .el
    cmp  edi, 'L'
    je   .il
    cmp  edi, 'M'
    je   .dl
    cmp  edi, 'P'
    je   .dch
    cmp  edi, 'S'
    je   .su
    cmp  edi, 'T'
    je   .sd
    cmp  edi, 'X'
    je   .ech
    cmp  edi, 'Z'
    je   .cbt
    cmp  edi, '`'
    je   .cha
    cmp  edi, 'a'
    je   .cuf
    cmp  edi, 'b'
    je   .rep
    cmp  edi, 'c'
    je   .da1
    cmp  edi, 'd'
    je   .vpa
    cmp  edi, 'e'
    je   .cud
    cmp  edi, 'f'
    je   .cup
    cmp  edi, 'g'
    je   .tbc
    cmp  edi, 'h'
    je   .sm
    cmp  edi, 'l'
    je   .rm
    cmp  edi, 'm'
    je   vt_sgr_rbx
    cmp  edi, 'n'
    je   .dsr
    cmp  edi, 'r'
    je   .decstbm
    cmp  edi, 's'
    je   .scosc
    cmp  edi, 't'
    je   .winops
    cmp  edi, 'u'
    je   .scorc
    ret
.ich:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  edi, eax
    jmp  vt_insert_chars_rbx
.dch:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  edi, eax
    jmp  vt_delete_chars_rbx
.cuu:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.top]
    cmp  ecx, edx
    jge  .cuu_lim                       ; inside/below region: stop at top margin
    xor  edx, edx
.cuu_lim:
    sub  ecx, eax
    cmp  ecx, edx
    jge  .cuu_set
    mov  ecx, edx
.cuu_set:
    mov  [rbx + VT.cy], ecx
    ret
.cud:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.bot]
    cmp  ecx, edx
    jle  .cud_lim
    mov  edx, [rbx + VT.rows]
    dec  edx
.cud_lim:
    add  ecx, eax
    cmp  ecx, edx
    jle  .cud_set
    mov  ecx, edx
.cud_set:
    mov  [rbx + VT.cy], ecx
    ret
.cuf:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  ecx, [rbx + VT.cx]
    add  ecx, eax
    mov  edx, [rbx + VT.cols]
    dec  edx
    cmp  ecx, edx
    jle  .cuf_set
    mov  ecx, edx
.cuf_set:
    mov  [rbx + VT.cx], ecx
    ret
.cub:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  ecx, [rbx + VT.cx]
    sub  ecx, eax
    jge  .cub_set
    xor  ecx, ecx
.cub_set:
    mov  [rbx + VT.cx], ecx
    ret
.cnl:
    call .cud
    mov  dword [rbx + VT.cx], 0
    ret
.cpl:
    call .cuu
    mov  dword [rbx + VT.cx], 0
    ret
.cha:
    xor  ecx, ecx
    call vt_param1_rbx
    dec  eax
    mov  edx, [rbx + VT.cols]
    dec  edx
    cmp  eax, edx
    jle  .cha_set
    mov  eax, edx
.cha_set:
    mov  [rbx + VT.cx], eax
    ret
.vpa:
    xor  ecx, ecx
    call vt_param1_rbx
    dec  eax
    call vt_origin_row_rbx
    mov  [rbx + VT.cy], eax
    ret
.cup:
    xor  ecx, ecx
    call vt_param1_rbx
    dec  eax
    call vt_origin_row_rbx
    mov  [rbx + VT.cy], eax
    mov  ecx, 1
    call vt_param1_rbx
    jmp  .cha_from_eax
.cha_from_eax:
    dec  eax
    mov  edx, [rbx + VT.cols]
    dec  edx
    cmp  eax, edx
    jle  .cup_x
    mov  eax, edx
.cup_x:
    mov  [rbx + VT.cx], eax
    ret
.cht:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  edi, eax
    jmp  vt_tab_forward_rbx
.cbt:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  edi, eax
    jmp  vt_tab_back_rbx
.ed:
    xor  ecx, ecx
    call vt_param_rbx
    cmp  eax, 0
    je   .ed0
    cmp  eax, 1
    je   .ed1
    cmp  eax, 2
    je   .ed2
    cmp  eax, 3
    jne  .ret
    mov  dword [rbx + VT.sb_count], 0   ; 3: clear the saved lines (xterm)
    mov  dword [rbx + VT.sb_head], 0
    ret
.ed0:
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cx]
    mov  r8d, [rbx + VT.cols]
    call vt_erase_span_rbx
    inc  ecx
.ed0_rows:
    cmp  ecx, [rbx + VT.rows]
    jge  .ret
    xor  edx, edx
    call vt_erase_span_rbx
    inc  ecx
    jmp  .ed0_rows
.ed1:
    xor  ecx, ecx
.ed1_rows:
    cmp  ecx, [rbx + VT.cy]
    jge  .ed1_last
    xor  edx, edx
    mov  r8d, [rbx + VT.cols]
    call vt_erase_span_rbx
    inc  ecx
    jmp  .ed1_rows
.ed1_last:
    xor  edx, edx
    mov  r8d, [rbx + VT.cx]
    inc  r8d
    call vt_erase_span_rbx
    ret
.ed2:
    jmp  vt_clear_screen_rbx
.el:
    xor  ecx, ecx
    call vt_param_rbx
    mov  ecx, [rbx + VT.cy]
    cmp  eax, 0
    je   .el0
    cmp  eax, 1
    je   .el1
    cmp  eax, 2
    je   .el2
    ret
.el0:
    mov  edx, [rbx + VT.cx]
    mov  r8d, [rbx + VT.cols]
    jmp  vt_erase_span_rbx
.el1:
    xor  edx, edx
    mov  r8d, [rbx + VT.cx]
    inc  r8d
    jmp  vt_erase_span_rbx
.el2:
    xor  edx, edx
    mov  r8d, [rbx + VT.cols]
    jmp  vt_erase_span_rbx
.il:
    mov  eax, [rbx + VT.cy]
    cmp  eax, [rbx + VT.top]
    jl   .ret
    cmp  eax, [rbx + VT.bot]
    jg   .ret
    xor  ecx, ecx
    call vt_param1_rbx
    mov  r8d, eax
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.bot]
    call vt_scroll_down_rbx
    mov  dword [rbx + VT.cx], 0
    ret
.dl:
    mov  eax, [rbx + VT.cy]
    cmp  eax, [rbx + VT.top]
    jl   .ret
    cmp  eax, [rbx + VT.bot]
    jg   .ret
    xor  ecx, ecx
    call vt_param1_rbx
    mov  r8d, eax
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.bot]
    call vt_scroll_up_rbx
    mov  dword [rbx + VT.cx], 0
    ret
.su:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  r8d, eax
    mov  ecx, [rbx + VT.top]
    mov  edx, [rbx + VT.bot]
    jmp  vt_scroll_up_rbx
.sd:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  r8d, eax
    mov  ecx, [rbx + VT.top]
    mov  edx, [rbx + VT.bot]
    jmp  vt_scroll_down_rbx
.ech:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  ecx, [rbx + VT.cy]
    mov  edx, [rbx + VT.cx]
    lea  r8d, [edx + eax]
    jmp  vt_erase_span_rbx
.rep:
    xor  ecx, ecx
    call vt_param1_rbx
    mov  ecx, eax
    cmp  ecx, 65535
    jbe  .rep_loop
    mov  ecx, 65535
.rep_loop:
    cmp  dword [rbx + VT.last_cp], 0
    je   .ret
    test ecx, ecx
    jz   .ret
    push rcx
    mov  edi, [rbx + VT.last_cp]
    call vt_print_cp_rbx
    pop  rcx
    dec  ecx
    jmp  .rep_loop
.da1:
    xor  ecx, ecx
    call vt_param_rbx
    test eax, eax
    jnz  .ret
    lea  rsi, [rel vt_str_da1]
    jmp  vt_reply_cstr_rbx
.tbc:
    xor  ecx, ecx
    call vt_param_rbx
    test eax, eax
    jz   .tbc0
    cmp  eax, 3
    jne  .ret
    lea  rdi, [rbx + VT.tabs]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    ret
.tbc0:
    mov  eax, [rbx + VT.cx]
    btr  dword [rbx + VT.tabs], eax
    ret
.sm:
    mov  r9d, 1
    jmp  .ansi_modes
.rm:
    xor  r9d, r9d
.ansi_modes:
    xor  ecx, ecx
.am_loop:
    cmp  ecx, [rbx + VT.nparams]
    jae  .ret
    push rcx
    call vt_param_rbx
    mov  edx, VTM_IRM
    cmp  eax, 4
    je   .am_set
    mov  edx, VTM_LNM
    cmp  eax, 20
    je   .am_set
    jmp  .am_next
.am_set:
    test r9d, r9d
    jz   .am_clear
    bts  qword [rbx + VT.modes], rdx
    jmp  .am_next
.am_clear:
    btr  qword [rbx + VT.modes], rdx
.am_next:
    pop  rcx
    inc  ecx
    jmp  .am_loop
.dsr:
    xor  ecx, ecx
    call vt_param_rbx
    cmp  eax, 5
    je   .dsr5
    cmp  eax, 6
    je   .dsr6
    ret
.dsr5:
    lea  rsi, [rel vt_str_dsr_ok]
    jmp  vt_reply_cstr_rbx
.dsr6:
    xor  r9d, r9d
    jmp  vt_reply_cpr_rbx
.decstbm:
    xor  ecx, ecx
    call vt_param1_rbx
    dec  eax
    mov  r8d, eax
    mov  ecx, 1
    call vt_param_rbx
    test eax, eax
    jnz  .stbm_b
    mov  eax, [rbx + VT.rows]
.stbm_b:
    dec  eax
    mov  edx, [rbx + VT.rows]
    dec  edx
    cmp  eax, edx
    jle  .stbm_c
    mov  eax, edx
.stbm_c:
    cmp  r8d, eax
    jge  .ret                           ; top must be above bottom
    mov  [rbx + VT.top], r8d
    mov  [rbx + VT.bot], eax
    ; home (origin-aware)
    mov  dword [rbx + VT.cx], 0
    xor  eax, eax
    call vt_origin_row_rbx
    mov  [rbx + VT.cy], eax
    ret
.scosc:
    jmp  vt_save_cursor_rbx
.scorc:
    jmp  vt_restore_cursor_rbx
.winops:
    xor  ecx, ecx
    call vt_param_rbx
    cmp  eax, 18
    je   .win18
    cmp  eax, 14
    je   .win14
    cmp  eax, 16
    je   .win16
    ret
.win18:
    lea  rsi, [rel vt_str_csi8]
    call vt_reply_cstr_rbx
    mov  eax, [rbx + VT.rows]
    call vt_reply_dec_rbx
    mov  al, ';'
    call vt_reply_byte_rbx
    mov  eax, [rbx + VT.cols]
    call vt_reply_dec_rbx
    mov  al, 't'
    jmp  vt_reply_byte_rbx
.win14:
    lea  rsi, [rel vt_str_csi4]
    call vt_reply_cstr_rbx
    mov  eax, [rbx + VT.rows]
    shl  eax, 4
    call vt_reply_dec_rbx
    mov  al, ';'
    call vt_reply_byte_rbx
    mov  eax, [rbx + VT.cols]
    shl  eax, 3
    call vt_reply_dec_rbx
    mov  al, 't'
    jmp  vt_reply_byte_rbx
.win16:
    lea  rsi, [rel vt_str_cellsize]
    jmp  vt_reply_cstr_rbx
.ret:
    ret

;; clamp a 0-based row EAX to the screen, applying DECOM offset/limits -> EAX
vt_origin_row_rbx:
    mov  rcx, [rbx + VT.modes]
    bt   rcx, VTM_DECOM
    jnc  .abs
    add  eax, [rbx + VT.top]
    cmp  eax, [rbx + VT.bot]
    jle  .ok
    mov  eax, [rbx + VT.bot]
    ret
.abs:
    mov  ecx, [rbx + VT.rows]
    dec  ecx
    cmp  eax, ecx
    jle  .ok
    mov  eax, ecx
.ok:
    ret

;; CSI with intermediates (no private marker)
vt_csi_inter_rbx:
    movzx eax, byte [rbx + VT.inter]
    cmp  eax, ' '
    je   .space
    cmp  eax, '!'
    je   .bang
    ret
.space:
    cmp  edi, 'q'
    jne  .out
    xor  ecx, ecx
    call vt_param_rbx
    mov  [rbx + VT.cursor_style], eax
.out:
    ret
.bang:
    cmp  edi, 'p'
    jne  .out
    ; DECSTR soft reset
    and  qword [rbx + VT.modes], ~((1 << VTM_DECCKM) | (1 << VTM_DECOM) | (1 << VTM_IRM) | (1 << VTM_DECKPAM))
    bts  qword [rbx + VT.modes], VTM_DECAWM
    bts  qword [rbx + VT.modes], VTM_DECTCEM
    mov  dword [rbx + VT.fg], 0
    mov  dword [rbx + VT.bg], 0
    mov  dword [rbx + VT.fl], 0
    mov  byte [rbx + VT.charset], 0
    mov  dword [rbx + VT.top], 0
    mov  eax, [rbx + VT.rows]
    dec  eax
    mov  [rbx + VT.bot], eax
    lea  rax, [rbx + VT.saved]
    mov  byte [rax + VTSV_VALID], 0
    mov  byte [rax + 32 + VTSV_VALID], 0
    ret

;; CSI with a private marker ('?', '>', '=', '<')
vt_csi_private_rbx:
    cmp  eax, '?'
    je   .q
    cmp  eax, '>'
    je   .gt
    ret
.gt:
    cmp  byte [rbx + VT.ninter], 0
    jne  .out
    cmp  edi, 'c'
    je   .da2
    cmp  edi, 'q'
    je   .xtversion
    ret                                 ; '>m' XTMODKEYS etc. accepted, no effect
.da2:
    xor  ecx, ecx
    call vt_param_rbx
    test eax, eax
    jnz  .out
    lea  rsi, [rel vt_str_da2]
    jmp  vt_reply_cstr_rbx
.xtversion:
    lea  rsi, [rel vt_str_xtversion]
    jmp  vt_reply_cstr_rbx
.q:
    cmp  byte [rbx + VT.ninter], 0
    jne  .q_inter
    cmp  edi, 'h'
    je   .decset
    cmp  edi, 'l'
    je   .decrst
    cmp  edi, 'n'
    je   .decdsr
    ret                                 ; '?u' (kitty query) deliberately unanswered
.q_inter:
    movzx eax, byte [rbx + VT.inter]
    cmp  eax, '$'
    jne  .out
    cmp  edi, 'p'
    jne  .out
    ; DECRQM: CSI ? Ps $ p -> CSI ? Ps ; Pm $ y
    xor  ecx, ecx
    call vt_param_rbx
    mov  r8d, eax
    mov  edi, eax
    call vt_dec_mode_bit
    mov  r9d, 0                         ; not recognized
    cmp  eax, -1
    je   .rqm_reply
    mov  r9d, 4
    cmp  eax, -2
    je   .rqm_reply                     ; recognized, permanently reset
    mov  r9d, 2
    mov  rcx, [rbx + VT.modes]
    bt   rcx, rax
    jnc  .rqm_reply
    mov  r9d, 1
.rqm_reply:
    lea  rsi, [rel vt_str_csiq]
    call vt_reply_cstr_rbx
    mov  eax, r8d
    call vt_reply_dec_rbx
    mov  al, ';'
    call vt_reply_byte_rbx
    mov  eax, r9d
    call vt_reply_dec_rbx
    lea  rsi, [rel vt_str_rqm_tail]
    jmp  vt_reply_cstr_rbx
.decdsr:
    xor  ecx, ecx
    call vt_param_rbx
    cmp  eax, 6
    jne  .out
    mov  r9d, 1
    jmp  vt_reply_cpr_rbx
.decset:
    mov  r9d, 1
    jmp  .dec_loop_start
.decrst:
    xor  r9d, r9d
.dec_loop_start:
    xor  ecx, ecx
.dec_loop:
    cmp  ecx, [rbx + VT.nparams]
    jae  .out
    push rcx
    call vt_param_rbx
    mov  edi, eax
    call vt_dec_set_one_rbx
    pop  rcx
    inc  ecx
    jmp  .dec_loop
.out:
    ret

;; DEC private mode number EDI -> mode bit in EAX; -1 unknown; -2 known but fixed-off
vt_dec_mode_bit:
    mov  eax, VTM_DECCKM
    cmp  edi, 1
    je   .r
    mov  eax, VTM_DECSCNM
    cmp  edi, 5
    je   .r
    mov  eax, VTM_DECOM
    cmp  edi, 6
    je   .r
    mov  eax, VTM_DECAWM
    cmp  edi, 7
    je   .r
    mov  eax, VTM_BLINKCUR
    cmp  edi, 12
    je   .r
    mov  eax, VTM_DECTCEM
    cmp  edi, 25
    je   .r
    mov  eax, VTM_ALT
    cmp  edi, 47
    je   .r
    cmp  edi, 1047
    je   .r
    cmp  edi, 1049
    je   .r
    mov  eax, VTM_M1000
    cmp  edi, 1000
    je   .r
    mov  eax, VTM_M1002
    cmp  edi, 1002
    je   .r
    mov  eax, VTM_M1003
    cmp  edi, 1003
    je   .r
    mov  eax, VTM_FOCUS
    cmp  edi, 1004
    je   .r
    mov  eax, VTM_M1005
    cmp  edi, 1005
    je   .r
    mov  eax, VTM_M1006
    cmp  edi, 1006
    je   .r
    mov  eax, VTM_M1015
    cmp  edi, 1015
    je   .r
    mov  eax, VTM_BPASTE
    cmp  edi, 2004
    je   .r
    mov  eax, VTM_SYNC
    cmp  edi, 2026
    je   .r
    mov  eax, -2
    cmp  edi, 3                         ; DECCOLM: fixed 80/132 switching unsupported
    je   .r
    cmp  edi, 1048
    je   .r
    mov  eax, -1
.r:
    ret

;; set (R9D=1) or reset (R9D=0) DEC private mode EDI
vt_dec_set_one_rbx:
    cmp  edi, 1049
    je   .m1049
    cmp  edi, 1047
    je   .m1047
    cmp  edi, 47
    je   .m47
    cmp  edi, 1048
    je   .m1048
    push rdi
    call vt_dec_mode_bit
    pop  rdi
    cmp  eax, 0
    jl   .out
    test r9d, r9d
    jz   .clear
    bts  qword [rbx + VT.modes], rax
    jmp  .after
.clear:
    btr  qword [rbx + VT.modes], rax
.after:
    cmp  edi, 6
    jne  .out
    ; DECOM change homes the cursor
    mov  dword [rbx + VT.cx], 0
    xor  eax, eax
    call vt_origin_row_rbx
    mov  [rbx + VT.cy], eax
    mov  byte [rbx + VT.wrap], 0
.out:
    ret
.m1048:
    test r9d, r9d
    jz   vt_restore_cursor_rbx
    jmp  vt_save_cursor_rbx
.m47:
    test r9d, r9d
    jz   .to_primary
    jmp  .to_alt
.m1047:
    test r9d, r9d
    jz   .1047_off
    jmp  .to_alt
.1047_off:
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_ALT
    jnc  .out
    call vt_clear_screen_rbx
    jmp  .to_primary
.m1049:
    test r9d, r9d
    jz   .1049_off
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_ALT
    jc   .out
    call vt_primary_policy_save_rbx
    call vt_save_cursor_rbx             ; saved into the primary slot
    bts  qword [rbx + VT.modes], VTM_ALT
    call vt_clear_screen_rbx
    call vt_all_dirty_rbx
    ret
.1049_off:
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_ALT
    jnc  .out
    btr  qword [rbx + VT.modes], VTM_ALT
    call vt_restore_cursor_rbx
    call vt_all_dirty_rbx
    ret
.to_alt:
    call vt_primary_policy_save_rbx
    bts  qword [rbx + VT.modes], VTM_ALT
    jmp  vt_all_dirty_rbx
.to_primary:
    btr  qword [rbx + VT.modes], VTM_ALT
    jmp  vt_all_dirty_rbx

;; Snapshot only a primary -> alternate transition. Alternate margin/origin
;; changes and DEC cursor saves belong to that application, not this policy.
vt_primary_policy_save_rbx:
    bt   qword [rbx + VT.modes], VTM_ALT
    jc   .out                       ; repeated/mixed alternate sets keep the snapshot
    cmp  dword [rbx + VT.top], 0
    jne  .fixed
    mov  eax, [rbx + VT.rows]
    dec  eax
    cmp  [rbx + VT.bot], eax
    jne  .fixed
    bt   qword [rbx + VT.modes], VTM_DECOM
    jc   .fixed
    xor  eax, eax
    jmp  .save
.fixed:
    mov  eax, 1
.save:
    mov  [rbx + VT.rf_primary_fixed], eax
.out:
    ret

vt_all_dirty_rbx:
    mov  qword [rbx + VT.dirty], -1
    mov  qword [rbx + VT.dirty + 8], -1
    ret

;; ---------------------------------------------------------------------------
;; SGR
vt_sgr_rbx:
    push r12
    push r13
    xor  r12d, r12d                     ; index
    cmp  dword [rbx + VT.nparams], 0
    jne  .loop
    mov  dword [rbx + VT.nparams], 1    ; CSI m == CSI 0 m
.loop:
    cmp  r12d, [rbx + VT.nparams]
    jae  .done
    mov  ecx, r12d
    call vt_param_rbx
    mov  r13d, eax
    inc  r12d
    test r13d, r13d
    jz   .reset
    cmp  r13d, 1
    je   .bold
    cmp  r13d, 2
    je   .dim
    cmp  r13d, 3
    je   .italic
    cmp  r13d, 4
    je   .underline
    cmp  r13d, 5
    je   .blink
    cmp  r13d, 6
    je   .blink
    cmp  r13d, 7
    je   .reverse
    cmp  r13d, 8
    je   .conceal
    cmp  r13d, 9
    je   .strike
    cmp  r13d, 21
    je   .dbl_ul
    cmp  r13d, 22
    je   .normal
    cmp  r13d, 23
    je   .no_italic
    cmp  r13d, 24
    je   .no_ul
    cmp  r13d, 25
    je   .no_blink
    cmp  r13d, 27
    je   .no_reverse
    cmp  r13d, 28
    je   .no_conceal
    cmp  r13d, 29
    je   .no_strike
    cmp  r13d, 30
    jb   .skip_sub
    cmp  r13d, 37
    jbe  .fg8
    cmp  r13d, 38
    je   .fgext
    cmp  r13d, 39
    je   .fgdef
    cmp  r13d, 47
    jbe  .bg8
    cmp  r13d, 48
    je   .bgext
    cmp  r13d, 49
    je   .bgdef
    cmp  r13d, 58
    je   .ulcolor
    cmp  r13d, 90
    jb   .skip_sub
    cmp  r13d, 97
    jbe  .fg16
    cmp  r13d, 100
    jb   .skip_sub
    cmp  r13d, 107
    jbe  .bg16
    jmp  .skip_sub
.reset:
    mov  dword [rbx + VT.fg], 0
    mov  dword [rbx + VT.bg], 0
    mov  dword [rbx + VT.fl], 0
    jmp  .skip_sub
.bold:
    or   dword [rbx + VT.fl], VTF_BOLD
    jmp  .skip_sub
.dim:
    or   dword [rbx + VT.fl], VTF_DIM
    jmp  .skip_sub
.italic:
    or   dword [rbx + VT.fl], VTF_ITALIC
    jmp  .skip_sub
.underline:
    ; 4:0 turns underline off; other styles on
    mov  ecx, r12d
    cmp  ecx, 32
    jae  .ul_on
    bt   dword [rbx + VT.colon], ecx
    jnc  .ul_on
    call vt_param_rbx
    inc  r12d
    test eax, eax
    jz   .no_ul
.ul_on:
    or   dword [rbx + VT.fl], VTF_UL
    jmp  .skip_sub
.dbl_ul:
    or   dword [rbx + VT.fl], VTF_UL
    jmp  .skip_sub
.blink:
    or   dword [rbx + VT.fl], VTF_BLINK
    jmp  .skip_sub
.reverse:
    or   dword [rbx + VT.fl], VTF_REVERSE
    jmp  .skip_sub
.conceal:
    or   dword [rbx + VT.fl], VTF_CONCEAL
    jmp  .skip_sub
.strike:
    or   dword [rbx + VT.fl], VTF_STRIKE
    jmp  .skip_sub
.normal:
    and  dword [rbx + VT.fl], ~(VTF_BOLD | VTF_DIM)
    jmp  .skip_sub
.no_italic:
    and  dword [rbx + VT.fl], ~VTF_ITALIC
    jmp  .skip_sub
.no_ul:
    and  dword [rbx + VT.fl], ~VTF_UL
    jmp  .skip_sub
.no_blink:
    and  dword [rbx + VT.fl], ~VTF_BLINK
    jmp  .skip_sub
.no_reverse:
    and  dword [rbx + VT.fl], ~VTF_REVERSE
    jmp  .skip_sub
.no_conceal:
    and  dword [rbx + VT.fl], ~VTF_CONCEAL
    jmp  .skip_sub
.no_strike:
    and  dword [rbx + VT.fl], ~VTF_STRIKE
    jmp  .skip_sub
.fg8:
    lea  eax, [r13d - 30 + VT_COL_IDX]
    mov  [rbx + VT.fg], eax
    jmp  .skip_sub
.bg8:
    lea  eax, [r13d - 40 + VT_COL_IDX]
    mov  [rbx + VT.bg], eax
    jmp  .skip_sub
.fg16:
    lea  eax, [r13d - 90 + 8 + VT_COL_IDX]
    mov  [rbx + VT.fg], eax
    jmp  .skip_sub
.bg16:
    lea  eax, [r13d - 100 + 8 + VT_COL_IDX]
    mov  [rbx + VT.bg], eax
    jmp  .skip_sub
.fgdef:
    mov  dword [rbx + VT.fg], 0
    jmp  .skip_sub
.bgdef:
    mov  dword [rbx + VT.bg], 0
    jmp  .skip_sub
.fgext:
    call .ext_colour
    cmp  eax, -1
    je   .loop
    mov  [rbx + VT.fg], eax
    jmp  .loop
.bgext:
    call .ext_colour
    cmp  eax, -1
    je   .loop
    mov  [rbx + VT.bg], eax
    jmp  .loop
.ulcolor:
    call .ext_colour                    ; parsed and consumed, not rendered
    jmp  .loop
;; skip any ':' sub-parameters that belong to the code just handled
.skip_sub:
    cmp  r12d, [rbx + VT.nparams]
    jae  .loop
    cmp  r12d, 32
    jae  .loop
    bt   dword [rbx + VT.colon], r12d
    jnc  .loop
    inc  r12d
    jmp  .skip_sub
.done:
    pop  r13
    pop  r12
    ret
;; extended colour after 38/48/58 at index R12D -> EAX colour or -1; advances R12D
.ext_colour:
    cmp  r12d, [rbx + VT.nparams]
    jae  .ec_none
    mov  ecx, r12d
    xor  r8d, r8d                       ; colon form?
    cmp  ecx, 32
    jae  .ec_semi
    bt   dword [rbx + VT.colon], ecx
    jnc  .ec_semi
    mov  r8d, 1
.ec_semi:
    call vt_param_rbx
    inc  r12d
    cmp  eax, 5
    je   .ec_idx
    cmp  eax, 2
    je   .ec_rgb
    ; unknown selector: in colon form skip its group
    test r8d, r8d
    jz   .ec_none
    jmp  .ec_skip_group
.ec_idx:
    mov  ecx, r12d
    call vt_param_rbx
    inc  r12d
    and  eax, 0xff
    or   eax, VT_COL_IDX
    ret
.ec_rgb:
    test r8d, r8d
    jz   .ec_rgb3
    ; colon form: 2:[cs]:r:g:b -- count the remaining colon group
    mov  ecx, r12d
    xor  edx, edx
.ec_count:
    cmp  ecx, [rbx + VT.nparams]
    jae  .ec_counted
    cmp  ecx, 32
    jae  .ec_counted
    bt   dword [rbx + VT.colon], ecx
    jnc  .ec_counted
    inc  edx
    inc  ecx
    jmp  .ec_count
.ec_counted:
    cmp  edx, 4
    jb   .ec_rgb3
    inc  r12d                           ; skip the colour-space id
.ec_rgb3:
    mov  ecx, r12d
    call vt_param_rbx
    and  eax, 0xff
    shl  eax, 16
    mov  r9d, eax
    inc  r12d
    mov  ecx, r12d
    call vt_param_rbx
    and  eax, 0xff
    shl  eax, 8
    or   r9d, eax
    inc  r12d
    mov  ecx, r12d
    call vt_param_rbx
    and  eax, 0xff
    or   r9d, eax
    inc  r12d
    lea  eax, [r9d + VT_COL_RGB]
    ret
.ec_skip_group:
    cmp  r12d, [rbx + VT.nparams]
    jae  .ec_none
    cmp  r12d, 32
    jae  .ec_none
    bt   dword [rbx + VT.colon], r12d
    jnc  .ec_none
    inc  r12d
    jmp  .ec_skip_group
.ec_none:
    mov  eax, -1
    ret

;; ---------------------------------------------------------------------------
;; Strings (OSC / DCS / SOS / PM / APC)
vt_string_byte_rbx:
    cmp  edi, 0x18                      ; CAN cancels even after a pending ESC
    je   .abort
    cmp  edi, 0x1a                      ; SUB
    je   .abort
    cmp  byte [rbx + VT.str_esc], 0
    jne  .after_esc
    cmp  edi, 0x07
    je   .bel
    cmp  edi, 0x1b
    je   .esc
    mov  eax, [rbx + VT.strlen]
    cmp  eax, VT_STRMAX
    jae  .full
    mov  [rbx + VT.strbuf + rax], dil
    inc  dword [rbx + VT.strlen]
.full:
    ret
.esc:
    mov  byte [rbx + VT.str_esc], 1
    ret
.after_esc:
    mov  byte [rbx + VT.str_esc], 0
    cmp  edi, '\'
    je   .end
    ; ESC + something else: end the string, then treat as a new ESC sequence
    push rdi
    call .end
    pop  rdi
    mov  byte [rbx + VT.state], VTS_ESC
    mov  byte [rbx + VT.ninter], 0
    jmp  vt_esc_byte_rbx
.bel:
    cmp  byte [rbx + VT.strkind], VTK_OSC
    jne  .full                          ; BEL only terminates OSC
.end:
    mov  byte [rbx + VT.state], VTS_GROUND
    cmp  byte [rbx + VT.strkind], VTK_OSC
    je   vt_osc_dispatch_rbx
    cmp  byte [rbx + VT.strkind], VTK_DCS
    je   vt_dcs_dispatch_rbx
    ret
.abort:
    mov  byte [rbx + VT.str_esc], 0
    mov  byte [rbx + VT.state], VTS_GROUND
    ret

;; parse a decimal prefix of strbuf at RSI (length ECX) -> EAX value, RSI/ECX advanced past ';'
vt_str_number:
    xor  eax, eax
    xor  edx, edx                       ; digits seen
.l:
    test ecx, ecx
    jz   .end
    movzx r8d, byte [rsi]
    cmp  r8d, '0'
    jb   .stop
    cmp  r8d, '9'
    ja   .stop
    imul eax, eax, 10
    lea  eax, [eax + r8d - '0']
    inc  rsi
    dec  ecx
    inc  edx
    jmp  .l
.stop:
    cmp  r8d, ';'
    jne  .end
    inc  rsi
    dec  ecx
.end:
    ret

vt_osc_dispatch_rbx:
    push r12
    push r13
    lea  rsi, [rbx + VT.strbuf]
    mov  ecx, [rbx + VT.strlen]
    call vt_str_number
    mov  r12, rsi
    mov  r13d, ecx
    cmp  eax, 2
    jbe  .title
    cmp  eax, 10
    je   .fgq
    cmp  eax, 11
    je   .bgq
    cmp  eax, 4
    je   .palq
    jmp  .out
.title:
    mov  ecx, r13d
    cmp  ecx, 255
    jbe  .t_len
    mov  ecx, 255
.t_len:
    mov  [rbx + VT.titlelen], ecx
    mov  rsi, r12
    lea  rdi, [rbx + VT.title]
    cld
    rep  movsb
    jmp  .out
.fgq:
    cmp  r13d, 1
    jne  .out
    cmp  byte [r12], '?'
    jne  .out
    lea  rsi, [rel vt_str_osc10]
    call vt_reply_cstr_rbx
    jmp  .out
.bgq:
    cmp  r13d, 1
    jne  .out
    cmp  byte [r12], '?'
    jne  .out
    lea  rsi, [rel vt_str_osc11]
    call vt_reply_cstr_rbx
    jmp  .out
.palq:
    ; OSC 4 ; n ; ? -> OSC 4 ; n ; rgb:rrrr/gggg/bbbb ST
    mov  rsi, r12
    mov  ecx, r13d
    call vt_str_number
    cmp  ecx, 1
    jne  .out
    cmp  byte [rsi], '?'
    jne  .out
    cmp  eax, 255
    ja   .out
    push rax
    lea  rsi, [rel vt_str_osc4]
    call vt_reply_cstr_rbx
    pop  rax
    push rax
    call vt_reply_dec_rbx
    lea  rsi, [rel vt_str_rgb]
    call vt_reply_cstr_rbx
    pop  rax
    mov  edi, eax
    call vt_palette_rgb
    mov  r12d, eax
    mov  ecx, 16
    call .hex2x
    mov  al, '/'
    call vt_reply_byte_rbx
    mov  ecx, 8
    call .hex2x
    mov  al, '/'
    call vt_reply_byte_rbx
    xor  ecx, ecx
    call .hex2x
    lea  rsi, [rel vt_str_st]
    call vt_reply_cstr_rbx
.out:
    pop  r13
    pop  r12
    ret
;; emit component (R12D >> ECX) & 0xff as 4 hex digits "xxxx" (byte doubled)
.hex2x:
    mov  eax, r12d
    shr  eax, cl
    and  eax, 0xff
    push rax
    call .hex8
    pop  rax
    call .hex8
    ret
.hex8:
    push rax
    shr  eax, 4
    call .nib
    pop  rax
    and  eax, 0xf
.nib:
    and  eax, 0xf
    lea  rcx, [rel vt_hexdigits]
    mov  al, [rcx + rax]
    jmp  vt_reply_byte_rbx

vt_dcs_dispatch_rbx:
    ; XTGETTCAP (DCS + q ... ST) and DECRQSS (DCS $ q ... ST): report invalid
    mov  ecx, [rbx + VT.strlen]
    cmp  ecx, 2
    jb   .out
    cmp  byte [rbx + VT.strbuf + 1], 'q'
    jne  .out
    cmp  byte [rbx + VT.strbuf], '+'
    je   .xtgettcap
    cmp  byte [rbx + VT.strbuf], '$'
    jne  .out
    lea  rsi, [rel vt_str_decrqss_bad]
    jmp  vt_reply_cstr_rbx
.xtgettcap:
    lea  rsi, [rel vt_str_xtgettcap_bad]
    jmp  vt_reply_cstr_rbx
.out:
    ret

;; xterm 256-colour palette index EDI -> EAX 0xRRGGBB
vt_palette_rgb:
    cmp  edi, 16
    jae  .cube
    lea  rax, [rel vt_ansi16]
    mov  eax, [rax + rdi*4]
    ret
.cube:
    cmp  edi, 232
    jae  .grey
    lea  eax, [edi - 16]
    xor  edx, edx
    mov  ecx, 36
    div  ecx                            ; eax = r, edx = rest
    mov  r8d, eax
    mov  eax, edx
    xor  edx, edx
    mov  ecx, 6
    div  ecx                            ; eax = g, edx = b
    mov  r9d, eax
    mov  r10d, edx
    mov  eax, r8d
    call .level
    shl  eax, 16
    mov  r11d, eax
    mov  eax, r9d
    call .level
    shl  eax, 8
    or   r11d, eax
    mov  eax, r10d
    call .level
    or   eax, r11d
    ret
.level:
    test eax, eax
    jz   .l0
    imul eax, eax, 40
    add  eax, 55
.l0:
    ret
.grey:
    lea  eax, [edi - 232]
    imul eax, eax, 10
    add  eax, 8
    mov  ecx, eax
    shl  eax, 8
    or   eax, ecx
    shl  eax, 8
    or   eax, ecx
    ret

;; ---------------------------------------------------------------------------
;; Replies
vt_reply_byte_rbx:
    push rcx
    mov  ecx, [rbx + VT.replylen]
    cmp  ecx, VT_REPLYMAX
    jae  .full
    mov  [rbx + VT.reply + rcx], al
    inc  dword [rbx + VT.replylen]
    pop  rcx
    ret
.full:
    mov  dword [rbx + VT.replylen], -1 ; vt_feed rolls back the whole generated unit
    pop  rcx
    ret

;; append NUL-terminated string at RSI
vt_reply_cstr_rbx:
.l:
    mov  al, [rsi]
    test al, al
    jz   .out
    call vt_reply_byte_rbx
    inc  rsi
    jmp  .l
.out:
    ret

;; append unsigned decimal EAX
vt_reply_dec_rbx:
    push rbx
    push r12
    sub  rsp, 16
    mov  r12, rbx
    xor  ecx, ecx
    mov  ebx, 10
.div:
    xor  edx, edx
    div  ebx
    add  dl, '0'
    mov  [rsp + rcx], dl
    inc  ecx
    test eax, eax
    jnz  .div
    mov  rbx, r12
.emit:
    dec  ecx
    mov  al, [rsp + rcx]
    call vt_reply_byte_rbx
    test ecx, ecx
    jnz  .emit
    add  rsp, 16
    pop  r12
    pop  rbx
    ret

;; CPR: R9D=1 for the DEC form (CSI ? row ; col R)
vt_reply_cpr_rbx:
    mov  al, 0x1b
    call vt_reply_byte_rbx
    mov  al, '['
    call vt_reply_byte_rbx
    test r9d, r9d
    jz   .row
    mov  al, '?'
    call vt_reply_byte_rbx
.row:
    mov  eax, [rbx + VT.cy]
    mov  rcx, [rbx + VT.modes]
    bt   rcx, VTM_DECOM
    jnc  .abs
    sub  eax, [rbx + VT.top]
.abs:
    inc  eax
    call vt_reply_dec_rbx
    mov  al, ';'
    call vt_reply_byte_rbx
    mov  eax, [rbx + VT.cx]
    inc  eax
    call vt_reply_dec_rbx
    mov  al, 'R'
    jmp  vt_reply_byte_rbx

;; ---------------------------------------------------------------------------
;; vt_set_reflow(RDI vt, RSI caller-owned buffer, RDX actual allocated bytes).
;; The resize transaction validates full extents and all source disjointness.
;; Passing zero restores neither allocation nor history: it disables reflow.
vt_set_reflow:
    mov  [rdi + VT.rf_base], rsi
    mov  [rdi + VT.rf_bytes], rdx
    ret

%include "gui/vt/vt_reflow.inc"

;; vt_resize(RDI=vt, ESI=cols, EDX=rows): primary logical reflow on column
;; changes; alternate stays fixed-grid. EAX 1 accepted / 0 atomic refusal.
vt_resize:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  eax, esi
    cmp  eax, 1
    jge  .c1
    mov  eax, 1
.c1:
    cmp  eax, [rbx + VT.maxcols]
    jle  .c2
    mov  eax, [rbx + VT.maxcols]
.c2:
    mov  r12d, eax
    mov  eax, edx
    cmp  eax, 1
    jge  .r1
    mov  eax, 1
.r1:
    cmp  eax, [rbx + VT.maxrows]
    jle  .r2
    mov  eax, [rbx + VT.maxrows]
.r2:
    mov  r13d, eax
    mov  dword [rbx + VT.rf_done], 0
    ; Primary logical mode reflows height changes too, preserving caller anchors.
    ; A primary application using a scroll region/origin mode keeps a fixed grid.
    bt   qword [rbx + VT.modes], VTM_ALT
    jnc  .primary_policy
    cmp  dword [rbx + VT.rf_primary_fixed], 0
    jne  .fixed_resize
    jmp  .logical_resize
.primary_policy:
    cmp  dword [rbx + VT.top], 0
    jne  .fixed_resize
    mov  eax, [rbx + VT.rows]
    dec  eax
    cmp  [rbx + VT.bot], eax
    jne  .fixed_resize
    bt   qword [rbx + VT.modes], VTM_DECOM
    jc   .fixed_resize
.logical_resize:
    call vt_primary_reflow_rbx
    test eax, eax
    jz   .refused
.fixed_resize:
    ; 2026-10-01 (MSI soak1): a shrink while the ALTERNATE screen is active must
    ; keep the PRIMARY screen's saved cursor line, as xterm does: scroll the
    ; primary content up by the overflow (into scrollback) and move the saved
    ; row with it. Clamping alone put the shell's next prompt on the line above,
    ; over the old command line, after the full-screen program exited.
    cmp  dword [rbx + VT.rf_done], 0
    jne  .primary_kept
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_ALT
    jnc  .primary_kept
    cmp  byte [rbx + VT.saved + VTSV_VALID], 0
    je   .primary_kept
    mov  eax, [rbx + VT.saved + VTSV_CY]
    cmp  eax, r13d
    jl   .primary_kept
    mov  r8d, eax
    sub  r8d, r13d
    inc  r8d                            ; primary lines to scroll off the top
    btr  qword [rbx + VT.modes], VTM_ALT
    xor  ecx, ecx
    mov  edx, [rbx + VT.rows]
    dec  edx
    call vt_scroll_up_rbx               ; the primary screen (ALT cleared)
    bts  qword [rbx + VT.modes], VTM_ALT
    mov  eax, r13d
    dec  eax
    mov  [rbx + VT.saved + VTSV_CY], eax
.primary_kept:
    cmp  dword [rbx + VT.rf_done], 0
    je   .active_scroll
    bt   qword [rbx + VT.modes], VTM_ALT
    jnc  .no_scroll
.active_scroll:
    ; if the cursor would fall off the bottom, scroll the active content up
    mov  eax, [rbx + VT.cy]
    cmp  eax, r13d
    jl   .no_scroll
    mov  r8d, eax
    sub  r8d, r13d
    inc  r8d
    xor  ecx, ecx
    mov  edx, [rbx + VT.rows]
    dec  edx
    call vt_scroll_up_rbx
    mov  eax, r13d
    dec  eax
    mov  [rbx + VT.cy], eax
.no_scroll:
    ; Newly exposed columns/rows must be blank on BOTH screens. While a
    ; full-screen program shows the alternate screen, the primary still holds
    ; the text a shrink truncated; it would reappear at DECRST 1049/47 (and the
    ; alternate likewise when DECSET 47 shows it without clearing).
    mov  r14d, [rbx + VT.cols]          ; old size: callee-saved (vt_blank_cell_rbx clobbers r10)
    mov  r15d, [rbx + VT.rows]
    mov  [rbx + VT.cols], r12d
    mov  [rbx + VT.rows], r13d
    cmp  dword [rbx + VT.rf_done], 0
    je   .fixed_both
    ; Primary was committed already; only the alternate grid may be blanked.
    bt   qword [rbx + VT.modes], VTM_ALT
    jc   .fixed_alt
    btc  qword [rbx + VT.modes], VTM_ALT
    call .blank_cols
    call .blank_rows
    call .repair_rows
    btc  qword [rbx + VT.modes], VTM_ALT
    jmp  .grids_done
.fixed_alt:
    call .blank_cols
    call .blank_rows
    call .repair_rows
    jmp  .grids_done
.fixed_both:
    call .blank_cols
    call .blank_rows
    call .repair_rows
    btc  qword [rbx + VT.modes], VTM_ALT
    call .blank_cols
    call .blank_rows
    call .repair_rows
    btc  qword [rbx + VT.modes], VTM_ALT
.grids_done:
    mov  dword [rbx + VT.top], 0
    mov  eax, r13d
    dec  eax
    mov  [rbx + VT.bot], eax
    mov  eax, [rbx + VT.cx]
    cmp  eax, r12d
    jl   .cx_ok
    mov  eax, r12d
    dec  eax
    mov  [rbx + VT.cx], eax
.cx_ok:
    cmp  dword [rbx + VT.rf_done], 0
    je   .clear_wrap
    bt   qword [rbx + VT.modes], VTM_ALT
    jnc  .keep_wrap
.clear_wrap:
    mov  byte [rbx + VT.wrap], 0
.keep_wrap:
    call vt_all_dirty_rbx
    mov  dword [rbx + VT.rf_pending], 0
    mov  eax, 1
    jmp  .resize_out
.refused:
    mov  dword [rbx + VT.rf_pending], 1
    xor  eax, eax
.resize_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.repair_rows:
    xor  ecx, ecx
.repair_next:
    cmp  ecx, r13d
    jae  .repair_done
    call vt_repair_row_rbx
    inc  ecx
    jmp  .repair_next
.repair_done:
    ret
; clear [old_cols, new_cols) in each old row of the screen VTM_ALT selects
.blank_cols:
    cmp  r12d, r14d
    jle  .cols_done
    xor  ecx, ecx
.clr_cols:
    cmp  ecx, r15d
    jge  .cols_done
    mov  edx, r14d
    mov  r8d, r12d
    call vt_erase_span_rbx
    inc  ecx
    jmp  .clr_cols
.cols_done:
    ret
; clear rows [old_rows, new_rows) of the screen VTM_ALT selects
.blank_rows:
    cmp  r13d, r15d
    jle  .rows_done
    mov  ecx, r15d
.clr_rows:
    cmp  ecx, r13d
    jge  .rows_done
    xor  edx, edx
    mov  r8d, r12d
    call vt_erase_span_rbx
    inc  ecx
    jmp  .clr_rows
.rows_done:
    ret

;; ---------------------------------------------------------------------------
;; Input encoding (keyboard -> bytes for the application)
;; keys: VTK_* below; mods: bit0 shift, bit1 alt, bit2 ctrl.
VTKEY_ENTER     equ 1
VTKEY_TAB       equ 2
VTKEY_BACKSPACE equ 3
VTKEY_ESCAPE    equ 4
VTKEY_UP        equ 5
VTKEY_DOWN      equ 6
VTKEY_LEFT      equ 7
VTKEY_RIGHT     equ 8
VTKEY_INSERT    equ 9
VTKEY_DELETE    equ 10
VTKEY_HOME      equ 11
VTKEY_END       equ 12
VTKEY_PGUP      equ 13
VTKEY_PGDN      equ 14
VTKEY_F1        equ 21                  ; F1..F12 = 21..32

;; vt_key_encode(RDI=vt, ESI=key, EDX=mods, RCX=out[16]) -> EAX length
vt_key_encode:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rcx                       ; out
    xor  r13d, r13d                     ; length
    mov  r8d, edx                       ; mods
    ; xterm modifier parameter: 1 + shift + 2*alt + 4*ctrl
    mov  r9d, edx
    and  r9d, 7
    inc  r9d
    cmp  esi, VTKEY_ENTER
    je   .enter
    cmp  esi, VTKEY_TAB
    je   .tab
    cmp  esi, VTKEY_BACKSPACE
    je   .bs
    cmp  esi, VTKEY_ESCAPE
    je   .esc
    cmp  esi, VTKEY_UP
    je   .cur_a
    cmp  esi, VTKEY_DOWN
    je   .cur_b
    cmp  esi, VTKEY_RIGHT
    je   .cur_c
    cmp  esi, VTKEY_LEFT
    je   .cur_d
    cmp  esi, VTKEY_HOME
    je   .home
    cmp  esi, VTKEY_END
    je   .end
    cmp  esi, VTKEY_INSERT
    je   .ins
    cmp  esi, VTKEY_DELETE
    je   .del
    cmp  esi, VTKEY_PGUP
    je   .pgup
    cmp  esi, VTKEY_PGDN
    je   .pgdn
    cmp  esi, VTKEY_F1
    jb   .done
    cmp  esi, VTKEY_F1 + 11
    ja   .done
    lea  eax, [esi - VTKEY_F1]
    cmp  eax, 4
    jb   .f1_4
    lea  rcx, [rel vt_fkey_codes]
    movzx eax, byte [rcx + rax - 4]
    jmp  .tilde_eax
.f1_4:
    lea  eax, [eax + 'P']
    mov  edi, eax
    jmp  .ss3_or_mod
.enter:
    test r8d, 2
    jz   .enter_cr
    mov  al, 0x1b
    call .put
.enter_cr:
    mov  al, 0x0d
    call .put
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_LNM
    jnc  .done
    mov  al, 0x0a
    call .put
    jmp  .done
.tab:
    test r8d, 1
    jz   .tab_plain
    mov  al, 0x1b
    call .put
    mov  al, '['
    call .put
    mov  al, 'Z'
    call .put
    jmp  .done
.tab_plain:
    mov  al, 0x09
    call .alt_put
    jmp  .done
.bs:
    mov  al, 0x7f
    test r8d, 4
    jz   .bs_put
    mov  al, 0x08
.bs_put:
    call .alt_put
    jmp  .done
.esc:
    mov  al, 0x1b
    call .alt_put
    jmp  .done
.cur_a:
    mov  edi, 'A'
    jmp  .cursor
.cur_b:
    mov  edi, 'B'
    jmp  .cursor
.cur_c:
    mov  edi, 'C'
    jmp  .cursor
.cur_d:
    mov  edi, 'D'
    jmp  .cursor
.home:
    mov  edi, 'H'
    jmp  .cursor
.end:
    mov  edi, 'F'
.cursor:
    cmp  r9d, 1
    jne  .csi_1_mod
    mov  rax, [rbx + VT.modes]
    bt   rax, VTM_DECCKM
    jnc  .csi_plain
    mov  al, 0x1b
    call .put
    mov  al, 'O'
    call .put
    mov  eax, edi
    call .put
    jmp  .done
.csi_plain:
    mov  al, 0x1b
    call .put
    mov  al, '['
    call .put
    mov  eax, edi
    call .put
    jmp  .done
.ss3_or_mod:                            ; F1-F4: SS3 P..S, modified CSI 1;m P..S
    cmp  r9d, 1
    jne  .csi_1_mod
    mov  al, 0x1b
    call .put
    mov  al, 'O'
    call .put
    mov  eax, edi
    call .put
    jmp  .done
.csi_1_mod:
    mov  al, 0x1b
    call .put
    mov  al, '['
    call .put
    mov  al, '1'
    call .put
    mov  al, ';'
    call .put
    mov  eax, r9d
    call .put_dec
    mov  eax, edi
    call .put
    jmp  .done
.ins:
    mov  eax, 2
    jmp  .tilde_eax
.del:
    mov  eax, 3
    jmp  .tilde_eax
.pgup:
    mov  eax, 5
    jmp  .tilde_eax
.pgdn:
    mov  eax, 6
.tilde_eax:
    push rax
    mov  al, 0x1b
    call .put
    mov  al, '['
    call .put
    pop  rax
    call .put_dec
    cmp  r9d, 1
    je   .tilde_end
    mov  al, ';'
    call .put
    mov  eax, r9d
    call .put_dec
.tilde_end:
    mov  al, '~'
    call .put
.done:
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret
.alt_put:                               ; AL with an ESC prefix when Alt is held
    test r8d, 2
    jz   .put
    push rax
    mov  al, 0x1b
    call .put
    pop  rax
.put:
    cmp  r13d, 15
    jae  .put_full
    mov  [r12 + r13], al
    inc  r13d
.put_full:
    ret
.put_dec:                               ; EAX < 100
    cmp  eax, 10
    jb   .one_digit
    push rax
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    add  al, '0'
    call .put
    pop  rax
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    mov  eax, edx
.one_digit:
    add  al, '0'
    jmp  .put

;; vt_char_encode(RDI=vt, ESI=codepoint, EDX=mods, RCX=out[16]) -> EAX length
;; Ctrl maps to C0 (letters, @[\]^_ space ?); Alt prefixes ESC; UTF-8 otherwise.
vt_char_encode:
    xor  eax, eax
    mov  r8, rcx
    xor  r9d, r9d                       ; length
    test edx, 2
    jz   .no_alt
    mov  byte [r8], 0x1b
    inc  r9d
.no_alt:
    test edx, 4
    jz   .utf8
    mov  eax, esi
    cmp  eax, 'a'
    jb   .ctrl_upper
    cmp  eax, 'z'
    ja   .ctrl_upper
    sub  eax, 0x20
.ctrl_upper:
    cmp  eax, ' '
    jne  .c1
    xor  eax, eax
    jmp  .ctrl_put
.c1:
    cmp  eax, '?'
    jne  .c2
    mov  eax, 0x7f
    jmp  .ctrl_put
.c2:
    cmp  eax, '@'
    jb   .utf8
    cmp  eax, '_'
    ja   .utf8
    sub  eax, '@'
.ctrl_put:
    mov  [r8 + r9], al
    inc  r9d
    mov  eax, r9d
    ret
.utf8:
    mov  eax, esi
    cmp  eax, 0x80
    jae  .u2
    mov  [r8 + r9], al
    inc  r9d
    jmp  .out
.u2:
    cmp  eax, 0x800
    jae  .u3
    mov  ecx, eax
    shr  ecx, 6
    or   cl, 0xc0
    mov  [r8 + r9], cl
    and  al, 0x3f
    or   al, 0x80
    mov  [r8 + r9 + 1], al
    add  r9d, 2
    jmp  .out
.u3:
    cmp  eax, 0x10000
    jae  .u4
    mov  ecx, eax
    shr  ecx, 12
    or   cl, 0xe0
    mov  [r8 + r9], cl
    mov  ecx, eax
    shr  ecx, 6
    and  cl, 0x3f
    or   cl, 0x80
    mov  [r8 + r9 + 1], cl
    and  al, 0x3f
    or   al, 0x80
    mov  [r8 + r9 + 2], al
    add  r9d, 3
    jmp  .out
.u4:
    mov  ecx, eax
    shr  ecx, 18
    or   cl, 0xf0
    mov  [r8 + r9], cl
    mov  ecx, eax
    shr  ecx, 12
    and  cl, 0x3f
    or   cl, 0x80
    mov  [r8 + r9 + 1], cl
    mov  ecx, eax
    shr  ecx, 6
    and  cl, 0x3f
    or   cl, 0x80
    mov  [r8 + r9 + 2], cl
    and  al, 0x3f
    or   al, 0x80
    mov  [r8 + r9 + 3], al
    add  r9d, 4
.out:
    mov  eax, r9d
    ret

;; vt_paste_prefix/suffix(RDI=vt, RSI=out[8]) -> EAX length (0 unless mode 2004)
vt_paste_prefix:
    lea  rdx, [rel vt_str_paste_on]
    jmp  vt_paste_mark
vt_paste_suffix:
    lea  rdx, [rel vt_str_paste_off]
vt_paste_mark:
    xor  eax, eax
    mov  rcx, [rdi + VT.modes]
    bt   rcx, VTM_BPASTE
    jnc  .out
.l:
    mov  cl, [rdx + rax]
    test cl, cl
    jz   .out
    mov  [rsi + rax], cl
    inc  eax
    jmp  .l
.out:
    ret

;; ---------------------------------------------------------------------------
;; constant data
vt_fkey_codes:      db 15, 17, 18, 19, 20, 21, 23, 24     ; F5..F12
vt_str_paste_on:    db 0x1b, "[200~", 0
vt_str_paste_off:   db 0x1b, "[201~", 0
vt_str_da1:         db 0x1b, "[?62;22c", 0
vt_str_da2:         db 0x1b, "[>0;10;1c", 0
vt_str_xtversion:   db 0x1b, "P>|PaOS Terminal 1.0", 0x1b, "\", 0
vt_str_dsr_ok:      db 0x1b, "[0n", 0
vt_str_csi8:        db 0x1b, "[8;", 0
vt_str_csi4:        db 0x1b, "[4;", 0
vt_str_cellsize:    db 0x1b, "[6;16;8t", 0
vt_str_csiq:        db 0x1b, "[?", 0
vt_str_rqm_tail:    db "$y", 0
vt_str_osc10:       db 0x1b, "]10;rgb:cccc/cccc/cccc", 0x1b, "\", 0
vt_str_osc11:       db 0x1b, "]11;rgb:0c0c/0c0c/0c0c", 0x1b, "\", 0
vt_str_osc4:        db 0x1b, "]4;", 0
vt_str_rgb:         db ";rgb:", 0
vt_str_st:          db 0x1b, "\", 0
vt_str_decrqss_bad: db 0x1b, "P0$r", 0x1b, "\", 0
vt_str_xtgettcap_bad: db 0x1b, "P0+r", 0x1b, "\", 0
vt_hexdigits:       db "0123456789abcdef"
align 4
;; Campbell (Windows Terminal default) 16-colour palette
vt_ansi16:
    dd 0x0c0c0c, 0xc50f1f, 0x13a10e, 0xc19c00, 0x0037da, 0x881798, 0x3a96dd, 0xcccccc
    dd 0x767676, 0xe74856, 0x16c60c, 0xf9f1a5, 0x3b78ff, 0xb4009e, 0x61d6d6, 0xf2f2f2
align 4
%include "gui/vt/vt_tables.inc"
