;; MODULE gui/text_view
;; LAYER 6
;; EXPORTS tv_unit, tv_paint_unit, text_view_close_hook, text_view_init, text_view_open, text_view_draw, text_view_hit, text_view_key, text_view_click, text_view_set, text_view_get, text_view_type, tv_ids, tv_slot, tv_live
;; IMPORTS gui/widget, gui/l10n_paint, gui/form_loader, gui/start_programs, gui/img/img_source, gui/window_mgmt, fs/vfs, core/heap, sec/session
;; CAPS CAP_GUI
;; OWNER rc-live-claude
;; CONTEXT: bsp_only
; ============================================================================
; gui/text_view.asm: the Text Viewer (T5-15, Peter 88568; root 88576).
;
; One read-only window (gui/forms/text_viewer.frm): a `textview` view plus
; Previous and Next. File Explorer opens a text file here. There is no edit,
; save, file write, verb or network path.
;
; READ ONCE. text_view_open reads the file into one reusable slab, at most
; TV_CAP bytes, and never touches the file again. A longer file shows its first
; TV_CAP bytes and says so; its cut tail never ends inside a UTF-8 sequence.
; kmalloc is a bump heap, so the slab is allocated once and kept.
;
; UNTRUSTED BYTES. File bytes and names are data. They reach the screen only
; one cell at a time through tv_unit: a scalar l10n_scalar_at gives a cell, or a
; single '?' for malformed UTF-8, control, bidi, combining and missing glyphs.
; Nothing is interpreted, and no byte can move the pen outside its row. WIDGETGET
; returns only counts (tv_get), never file text or the file's name.
;
; ROWS. tv_next is the only layout: a row breaks at LF, CRLF, the last space or
; tab that fits, or the row's edge. A row start is an offset into the slab and
; every scroll walks tv_next from a line start, so no index can go stale and
; no row table grows with the file.
;
; MARKDOWN (a .md or .markdown name) is line-level and paint-only, so it never
; changes layout: a heading's marker is hidden and its rows are accented, a list
; marker paints as '-', and fence lines and the lines between them get the
; control background. Nothing else in the line is parsed.
;
; KEYS (focus on a button; the view is not a focus stop): Up/Down one row,
; PgUp/PgDn one view less a row, Home/End. Enter and Space press the focused button.
; N toggles a view-only line-number gutter (default on .sh/.frm, off otherwise).
; Five mono digits plus a gap are reserved; wrapped continuations are blank.
; Lines above99999 use ##### within those five cells. No editing or file write.
; A key or click only changes the view, so an injected one needs no origin gate.
; ============================================================================

TV_CAP          equ 0x100000            ; the read-once cap, 1 MiB
TV_CHUNK        equ 65536               ; one bounded VFS read step
TV_NAME_MAX     equ 80                  ; the name kept for the status row
TV_W_VIEW       equ 0                   ; tv_ids: text_viewer.frm declaration order
TV_W_PREV       equ 1
TV_W_NEXT       equ 2
TV_W_COUNT      equ 3
TV_INSET_X      equ 8
TV_INSET_Y      equ 4
TV_MIN_CELLS    equ 8                   ; narrower shows the fill only; the widest unit is a tab of 4
TV_TAB          equ 4
TV_NUMBER_CELLS equ 6                   ; five mono digits plus one blank gap
TV_ST_EMPTY     equ 0                   ; no file yet
TV_ST_LOADED    equ 1
TV_ST_UNREADABLE equ 2
TV_ST_NOMEM     equ 3
TV_K_PLAIN      equ 0                   ; line kinds
TV_K_HEADING    equ 1
TV_K_LIST       equ 2
TV_K_FENCE      equ 3
TV_K_CODE       equ 4
TV_FG           equ GUI_TOK_LABEL_TEXT
TV_BG           equ GUI_TOK_WINDOW_BODY
TV_HEAD_FG      equ GUI_TOK_ACCENT
TV_CODE_BG      equ GUI_TOK_CONTROL_BG

; ---------------------------------------------------------------------------
; text_view_init(): register the `textview` type, after every shipped type.
; Called once from start_programs_init. -> EAX 0, or 1 when the table is full
; (the viewer then never loads: unknown_widget). Clobbers caller-saved.
; ---------------------------------------------------------------------------
text_view_init:
    sub  rsp, 8
    lea  rdi, [rel tv_str_type]
    lea  rsi, [rel text_view_draw]
    lea  rdx, [rel text_view_hit]
    lea  rcx, [rel text_view_set]
    lea  r8,  [rel text_view_get]
    mov  r9, (348 << 32) | 568
    call wgt_type_register
    mov  [rel text_view_type], eax
    add  rsp, 8
    cmp  eax, -1
    je   .full
    xor  eax, eax
    ret
.full:
    mov  eax, 1
    ret

; text_view_set: WIDGETSET on the view is refused (read-only). -> EAX 1
text_view_set:
    mov  eax, 1
    ret

text_view_hit:
    jmp  wgt_rect_hittest

; Counts belong to the instance that accepted the open, not a reusable widget
; or WM slot. Native birth and stamped WM identity are passive observations;
; they grant no source authority and never read the file or change widget RAM.
; tv_counts_identity(EDI view id) -> RAX birth, EDX stamped host, or both zero.
tv_counts_identity:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12d, edi
    cmp  byte [rel tv_live], 1
    jne  .bad
    cmp  edi, [rel tv_ids + TV_W_VIEW * 4]
    jne  .bad
    call wgt_birth_lifetime
    test rax, rax
    jz   .bad
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rel text_view_type]
    cmp  ecx, -1
    je   .bad
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .bad
    mov  edi, [rel tv_slot]
    cmp  [rax + WGI_WIN], edi
    jne  .bad
    call wmx_window_id
    test eax, eax
    jz   .bad
    mov  edx, eax
    mov  rax, rbx
    jmp  .out
.bad:
    xor  eax, eax
    xor  edx, edx
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Capture only after an explicit open has loaded the document and located its
; whole form. A failed capture retains no old counts binding.
tv_counts_bind:
    push rbx
    mov  ebx, edi
    call tv_counts_identity
    mov  [rel tv_counts_birth], rax
    mov  [rel tv_counts_host], edx
    test rax, rax
    jz   .bad
    inc  ebx
    mov  [rel tv_counts_view], ebx
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel tv_counts_view], 0
    mov  eax, 1
.out:
    pop  rbx
    ret

; EDI queried view -> EAX 1 only for the exact captured live instance. Refusal
; is read-only: even the counts scratch buffer keeps its prior bytes.
tv_counts_current:
    push rbx
    mov  ebx, edi
    call tv_counts_identity
    test rax, rax
    jz   .bad
    inc  ebx
    cmp  ebx, [rel tv_counts_view]
    jne  .bad
    cmp  rax, [rel tv_counts_birth]
    jne  .bad
    cmp  edx, [rel tv_counts_host]
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

; text_view_get(EDI id, RSI field) -> RAX the counts line for a field the kit
; knows on the exact opened instance, 0 otherwise. Counts only: never file
; text/name. Existing source policy and outer WIDGETGET exclusions still apply.
text_view_get:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    mov  r12, rsi
    call tv_counts_current
    test eax, eax
    jz   .out
    mov  edi, ebx
    mov  rsi, r12
    call wgt_label_get
    test rax, rax
    jz   .out
    lea  rbx, [rel tv_get_buf]
    mov  rdi, rbx
    lea  rsi, [rel tv_s_state]
    call tv_put_str
    mov  eax, [rel tv_state]
    lea  rsi, [rel tv_s_empty]
    cmp  eax, TV_ST_EMPTY
    je   .state
    lea  rsi, [rel tv_s_loaded]
    cmp  eax, TV_ST_LOADED
    je   .state
    lea  rsi, [rel tv_s_unreadable]
    cmp  eax, TV_ST_UNREADABLE
    je   .state
    lea  rsi, [rel tv_s_nomem]
.state:
    call tv_put_str
    lea  rsi, [rel tv_s_bytes]
    call tv_put_str
    mov  eax, [rel tv_len]
    call tv_put_dec
    lea  rsi, [rel tv_s_rows]
    call tv_put_str
    mov  eax, [rel tv_total]
    call tv_put_dec
    lea  rsi, [rel tv_s_first]
    call tv_put_str
    mov  eax, [rel tv_row]
    call tv_put_dec
    lea  rsi, [rel tv_s_trunc]
    call tv_put_str
    movzx eax, byte [rel tv_trunc]
    call tv_put_dec
    lea  rsi, [rel tv_s_md]
    call tv_put_str
    movzx eax, byte [rel tv_md]
    call tv_put_dec
    mov  byte [rdi], 0
    mov  rax, rbx
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; tv_put_str(RDI out, RSI NUL-terminated) -> RDI advanced. Clobbers RAX, RSI.
tv_put_str:
    mov  al, [rsi]
    test al, al
    jz   .out
    mov  [rdi], al
    inc  rsi
    inc  rdi
    jmp  tv_put_str
.out:
    ret

; tv_put_dec(RDI out, EAX value) -> RDI advanced. Clobbers RAX, RCX, RDX, R8.
tv_put_dec:
    mov  r8d, 10
    xor  ecx, ecx
.div:
    xor  edx, edx
    div  r8d
    add  dl, '0'
    push rdx
    inc  ecx
    test eax, eax
    jnz  .div
.put:
    pop  rdx
    mov  [rdi], dl
    inc  rdi
    dec  ecx
    jnz  .put
    ret

; ---------------------------------------------------------------------------
; tv_unit(RDI text, ESI bytes, EDX offset < bytes) -> EAX cells, ECX bytes, EDX
; the scalar to draw, R10 its 16x16 bitmap when wide (else 0). Anything without
; a cell is one '?' cell, and a whole malformed or missing sequence is one unit.
; Preserves RBX, RDI, RSI, R8, R9, R11-R15.
; ---------------------------------------------------------------------------
tv_unit:
    movzx eax, byte [rdi + rdx]
    cmp  eax, 0x20
    jb   .slow
    cmp  eax, 0x7F
    jae  .slow
    mov  edx, eax
    mov  eax, 1
    mov  ecx, 1
    xor  r10d, r10d
    ret
.slow:
    push rbx
    mov  ebx, edx
    call l10n_scalar_at
    test eax, eax
    js   .none
    xchg eax, edx                       ; EAX cells, EDX scalar
    pop  rbx
    ret
.none:
    movzx eax, byte [rdi + rbx]
    mov  edx, 1                         ; the sequence the lead byte announces
    cmp  eax, 0xC2
    jb   .count
    cmp  eax, 0xF5
    jae  .count
    mov  edx, 2
    cmp  eax, 0xE0
    jb   .count
    mov  edx, 3
    cmp  eax, 0xF0
    jb   .count
    mov  edx, 4
.count:
    mov  ecx, 1
.more:
    cmp  ecx, edx
    jae  .bad
    lea  eax, [rbx + rcx]
    cmp  eax, esi
    jae  .bad
    movzx eax, byte [rdi + rax]
    and  eax, 0xC0
    cmp  eax, 0x80
    jne  .bad
    inc  ecx
    jmp  .more
.bad:
    mov  eax, 1
    mov  edx, '?'
    xor  r10d, r10d
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; tv_next(EDI row start, ESI cells) -> EAX the next row's start, in (start, len].
; The one layout rule. Clobbers caller-saved registers.
; ---------------------------------------------------------------------------
tv_next:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbx, [rel tv_buf]
    mov  ebp, edi
    mov  r12d, edi                      ; offset
    xor  r13d, r13d                     ; column
    mov  r14d, esi
    xor  r15d, r15d                     ; the offset after the last space or tab
.loop:
    mov  eax, [rel tv_len]
    cmp  r12d, eax
    jae  .out
    movzx ecx, byte [rbx + r12]
    cmp  ecx, 10
    je   .lf
    cmp  ecx, 13
    jne  .not_cr
    lea  edx, [r12 + 1]
    cmp  edx, eax
    jae  .not_cr
    cmp  byte [rbx + rdx], 10
    jne  .not_cr
    lea  eax, [r12 + 2]
    jmp  .out
.lf:
    lea  eax, [r12 + 1]
    jmp  .out
.not_cr:
    cmp  ecx, 9
    jne  .unit
    mov  eax, r13d
    and  eax, TV_TAB - 1
    neg  eax
    add  eax, TV_TAB
    mov  ecx, 1
    jmp  .place
.unit:
    mov  rdi, rbx
    mov  esi, eax
    mov  edx, r12d
    call tv_unit
.place:
    lea  edx, [r13 + rax]
    cmp  edx, r14d
    ja   .wrap
    mov  r13d, edx
    movzx edx, byte [rbx + r12]
    add  r12d, ecx
    cmp  edx, ' '
    je   .break
    cmp  edx, 9
    jne  .loop
.break:
    mov  r15d, r12d
    jmp  .loop
.wrap:
    mov  eax, r15d
    cmp  eax, ebp
    ja   .out
    mov  eax, r12d
    cmp  eax, ebp
    ja   .out
    lea  eax, [rbp + rcx]               ; a unit wider than the row: never reached at TV_MIN_CELLS
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; tv_prev(EDI row start > 0, ESI cells) -> EAX the row before it: walks tv_next
; from the line start. Clobbers caller-saved registers.
tv_prev:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    mov  rax, [rel tv_buf]
    lea  ecx, [rdi - 1]
    cmp  byte [rax + rcx], 10
    jne  .back
    test ecx, ecx
    jz   .found0
    dec  ecx
.back:
    cmp  byte [rax + rcx], 10
    je   .found
    test ecx, ecx
    jz   .found0
    dec  ecx
    jmp  .back
.found:
    lea  ebx, [rcx + 1]
    jmp  .walk
.found0:
    xor  ebx, ebx
.walk:
    mov  edi, ebx
    mov  esi, r13d
    call tv_next
    cmp  eax, r12d
    jae  .done
    mov  ebx, eax
    jmp  .walk
.done:
    mov  eax, ebx
    pop  r13
    pop  r12
    pop  rbx
    ret

; tv_layout(ESI cells): a new width, or a new file. tv_total is recounted and
; tv_top moves to the row that holds its byte. Clobbers caller-saved.
tv_layout:
    cmp  esi, [rel tv_cells]
    je   .same
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, esi
    mov  [rel tv_cells], esi
    xor  ebx, ebx                       ; row start
    xor  r13d, r13d                     ; rows
    xor  r14d, r14d                     ; the new top
    xor  r15d, r15d                     ; and its row
.walk:
    cmp  ebx, [rel tv_len]
    jae  .done
    cmp  ebx, [rel tv_top]
    ja   .past
    mov  r14d, ebx
    mov  r15d, r13d
.past:
    mov  edi, ebx
    mov  esi, r12d
    call tv_next
    mov  ebx, eax
    inc  r13d
    jmp  .walk
.done:
    mov  [rel tv_total], r13d
    mov  [rel tv_top], r14d
    mov  [rel tv_row], r15d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.same:
    ret

; tv_max_row(void; tv_grows, tv_total) -> EAX the last first row.
tv_max_row:
    mov  eax, [rel tv_total]
    sub  eax, [rel tv_grows]
    jns  .out
    xor  eax, eax
.out:
    ret

; tv_down(EDI rows) / tv_up(EDI rows): move the first row, clamped.
; Clobbers caller-saved registers.
tv_down:
    push rbx
    mov  ebx, edi
.next:
    test ebx, ebx
    jz   .out
    call tv_max_row
    cmp  [rel tv_row], eax
    jae  .out
    mov  edi, [rel tv_top]
    mov  esi, [rel tv_cells]
    call tv_next
    mov  [rel tv_top], eax
    inc  dword [rel tv_row]
    dec  ebx
    jmp  .next
.out:
    pop  rbx
    ret

tv_up:
    push rbx
    mov  ebx, edi
.next:
    test ebx, ebx
    jz   .out
    cmp  dword [rel tv_row], 0
    je   .out
    mov  edi, [rel tv_top]
    mov  esi, [rel tv_cells]
    call tv_prev
    mov  [rel tv_top], eax
    dec  dword [rel tv_row]
    dec  ebx
    jmp  .next
.out:
    pop  rbx
    ret

; tv_clamp(): after a resize the view may have room past the end.
; Clobbers caller-saved registers.
tv_clamp:
    call tv_max_row
    mov  edi, [rel tv_row]
    sub  edi, eax
    jle  .out
    jmp  tv_up
.out:
    ret

; tv_geom(EDI view id) -> EAX 1 and tv_gx/gy, tv_acells, tv_arows, tv_grows
; (rows less the status row); EAX 0 when too small for text. From the LIVE
; rectangle. Clobbers caller-saved registers.
tv_geom:
    sub  rsp, 8
    call wgt_slot_ptr
    add  rsp, 8
    mov  ecx, [rax + WGI_X]
    add  ecx, TV_INSET_X
    mov  [rel tv_gx], ecx
    mov  ecx, [rax + WGI_Y]
    add  ecx, TV_INSET_Y
    mov  [rel tv_gy], ecx
    mov  ecx, [rax + WGI_W]
    sub  ecx, 2 * TV_INSET_X
    jle  .small
    shr  ecx, 3
    mov  edx, [rel tv_gx]
    mov  [rel tv_num_gx], edx
    cmp  byte [rel tv_numbers], 0
    je   .text_width
    cmp  dword [rel tv_state], TV_ST_LOADED
    jne  .text_width
    sub  ecx, TV_NUMBER_CELLS
    add  dword [rel tv_gx], TV_NUMBER_CELLS*8
.text_width:
    cmp  ecx, TV_MIN_CELLS
    jl   .small
    mov  [rel tv_acells], ecx
    mov  ecx, [rax + WGI_H]
    sub  ecx, 2 * TV_INSET_Y
    jle  .small
    shr  ecx, 4
    mov  [rel tv_arows], ecx
    dec  ecx
    cmp  ecx, 1
    jl   .small
    mov  [rel tv_grows], ecx
    mov  eax, 1
    ret
.small:
    xor  eax, eax
    ret

; ---- line-level Markdown ----

; tv_kind(EDI line start) -> EAX kind, ECX the marker's bytes (a heading) or the
; list marker's offset in the line. Never reads past tv_len.
; Clobbers RAX, RCX, RDX, RSI, R8.
tv_kind:
    mov  rsi, [rel tv_buf]
    mov  edx, [rel tv_len]
    xor  ecx, ecx
.hashes:
    lea  eax, [rdi + rcx]
    cmp  eax, edx
    jae  .no_heading
    cmp  byte [rsi + rax], '#'
    jne  .hash_end
    inc  ecx
    cmp  ecx, 6
    jbe  .hashes
    jmp  .no_heading
.hash_end:
    test ecx, ecx
    jz   .no_heading
    cmp  byte [rsi + rax], ' '
    jne  .no_heading
    inc  ecx
    mov  eax, TV_K_HEADING
    ret
.no_heading:
    xor  ecx, ecx
.spaces:
    lea  eax, [rdi + rcx]
    cmp  eax, edx
    jae  .plain
    cmp  byte [rsi + rax], ' '
    jne  .marker
    inc  ecx
    cmp  ecx, 3
    jbe  .spaces
    jmp  .plain
.marker:
    movzx r8d, byte [rsi + rax]
    cmp  r8d, '`'
    je   .fence
    cmp  r8d, '-'
    je   .bullet
    cmp  r8d, '*'
    je   .bullet
    cmp  r8d, '+'
    jne  .plain
.bullet:
    inc  eax
    cmp  eax, edx
    jae  .plain
    cmp  byte [rsi + rax], ' '
    jne  .plain
    mov  eax, TV_K_LIST
    ret
.fence:
    lea  r8d, [rax + 2]
    cmp  r8d, edx
    jae  .plain
    cmp  byte [rsi + rax + 1], '`'
    jne  .plain
    cmp  byte [rsi + rax + 2], '`'
    jne  .plain
    mov  eax, TV_K_FENCE
    ret
.plain:
    xor  eax, eax
    ret

; tv_enter_line(EDI line start): tv_lkind, tv_lmark and the fence state for that
; line. Clobbers RAX, RCX, RDX, RSI, R8.
tv_enter_line:
    call tv_kind
    cmp  eax, TV_K_FENCE
    jne  .not_fence
    xor  byte [rel tv_fence], 1
    jmp  .set
.not_fence:
    cmp  byte [rel tv_fence], 0
    je   .set
    mov  eax, TV_K_CODE
.set:
    mov  [rel tv_lkind], eax
    mov  [rel tv_lmark], ecx
    mov  dword [rel tv_lbullet], -1
    cmp  eax, TV_K_LIST
    jne  .out
    add  ecx, edi
    mov  [rel tv_lbullet], ecx
.out:
    ret

; tv_style_to(EDI offset): the Markdown state for the line that holds a first
; row: a walk over line starts from the top of the file, so no state can go
; stale across a scroll. Plain text is always plain. Clobbers caller-saved.
tv_style_to:
    mov  dword [rel tv_lkind], TV_K_PLAIN
    mov  dword [rel tv_lmark], 0
    mov  dword [rel tv_lbullet], -1
    mov  byte [rel tv_fence], 0
    cmp  byte [rel tv_md], 0
    je   .out
    push rbx
    push r12
    mov  r12d, edi
    xor  ebx, ebx
.line:
    mov  edi, ebx
    call tv_enter_line
    mov  rsi, [rel tv_buf]
    mov  edx, [rel tv_len]
    mov  eax, ebx
.eol:
    cmp  eax, edx
    jae  .done
    inc  eax
    cmp  byte [rsi + rax - 1], 10
    jne  .eol
    cmp  eax, r12d
    ja   .done
    mov  ebx, eax
    jmp  .line
.done:
    pop  r12
    pop  rbx
.out:
    ret

; ---- painting ----

; tv_paint_unit(EDX scalar, EAX cells, R10 bitmap, R8D x, R9D y, EBX fg, ECX bg).
; Preserves the callee-saved registers.
tv_paint_unit:
    cmp  eax, 2
    je   .wide
    cmp  edx, 0x80
    jae  .scalar
    jmp  wgt_draw_glyph
.scalar:
    jmp  fb_draw_scalar
.wide:
    mov  rsi, r10
    jmp  fb_draw_wide16

; tv_paint_row(EDI start, ESI next row's start, R9D y): the row's cells, in the
; current line's style. Clobbers caller-saved registers.
tv_paint_row:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r15d, r9d
    mov  ebx, TV_FG
    mov  ebp, TV_BG
    xor  r14d, r14d                     ; column
    mov  eax, [rel tv_lkind]
    cmp  eax, TV_K_FENCE
    je   .code
    cmp  eax, TV_K_CODE
    je   .code
    cmp  eax, TV_K_HEADING
    jne  .marks
    mov  ebx, TV_HEAD_FG
    jmp  .marks
.code:
    mov  r8d, [rel tv_gx]
    mov  r10d, [rel tv_acells]
    shl  r10d, 3
    mov  r11d, 16
    mov  r9d, r15d
    push rbx
    mov  ebx, TV_CODE_BG
    call wgt_fill_rect
    pop  rbx
    mov  ebp, TV_CODE_BG
.marks:
    cmp  byte [rel tv_md], 0
    je   .loop
    mov  rax, [rel tv_buf]
    test r12d, r12d
    jz   .line_start
    cmp  byte [rax + r12 - 1], 10
    jne  .loop
.line_start:
    cmp  dword [rel tv_lkind], TV_K_HEADING
    jne  .loop
    add  r12d, [rel tv_lmark]           ; the marker is hidden; the layout still counts it
.loop:
    cmp  r12d, r13d
    jae  .out
    mov  rdi, [rel tv_buf]
    movzx eax, byte [rdi + r12]
    cmp  eax, 10
    je   .out
    cmp  eax, 13
    jne  .not_cr
    lea  edx, [r12 + 1]
    cmp  edx, [rel tv_len]
    jae  .not_cr
    cmp  byte [rdi + rdx], 10
    je   .out
.not_cr:
    cmp  eax, 9
    jne  .unit
    mov  eax, r14d
    and  eax, TV_TAB - 1
    neg  eax
    lea  r14d, [r14 + rax + TV_TAB]
    inc  r12d
    jmp  .loop
.unit:
    mov  esi, [rel tv_len]
    mov  edx, r12d
    call tv_unit
    lea  esi, [r14 + rax]
    cmp  esi, [rel tv_acells]
    ja   .out                           ; tv_next's bound: never taken
    cmp  r12d, [rel tv_lbullet]
    jne  .plain_unit
    mov  edx, '-'                       ; a list marker paints as '-'
.plain_unit:
    add  r12d, ecx
.draw:
    mov  r8d, r14d
    shl  r8d, 3
    add  r8d, [rel tv_gx]
    mov  r9d, r15d
    add  r14d, eax
    mov  ecx, ebp
    call tv_paint_unit
    jmp  .loop
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Logical file-line number at a bounded row offset. One scan per compose,
; independent of wraps; no row table or allocation and never past tv_len.
; EDI=offset -> EAX=1+preceding LF count, clobbers RCX,RDX,RSI.
tv_line_number:
    mov  esi, [rel tv_len]
    cmp  edi, esi
    cmova edi, esi
    mov  rdx, [rel tv_buf]
    mov  eax, 1
    xor  ecx, ecx
.walk:
    cmp  ecx, edi
    jae  .out
    cmp  byte [rdx+rcx], 10
    jne  .next
    inc  eax
.next:
    inc  ecx
    jmp  .walk
.out:
    ret

; EAX=logical line, R9D=y. Right-aligned five-cell mono gutter. Existing
; tv_paint_unit paints printable ASCII only here (digits or overflow '#').
tv_paint_number:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  r14d, r9d
    lea  r13, [rel tv_number_buf]
    cmp  eax, 99999
    ja   .overflow
    mov  rdi, r13
    call tv_put_dec
    sub  rdi, r13
    mov  r12d, edi
    jmp  .paint
.overflow:
    mov  dword [r13], '####'
    mov  byte [r13+4], '#'
    mov  r12d, 5
.paint:
    mov  r8d, 5
    sub  r8d, r12d
    shl  r8d, 3
    add  r8d, [rel tv_num_gx]
.digit:
    movzx edx, byte [r13]
    mov  eax, 1
    mov  r9d, r14d
    mov  ebx, TV_FG
    mov  ecx, TV_BG
    call tv_paint_unit
    add  r8d, 8
    inc  r13
    dec  r12d
    jnz  .digit
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; tv_paint_status(R9D y): "<name>   n of N", and the cut when there is one.
; Clobbers caller-saved registers.
tv_paint_status:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, r9d
    lea  rdi, [rel tv_status]
    mov  eax, [rel tv_row]
    cmp  dword [rel tv_total], 0
    je   .first
    inc  eax
.first:
    call tv_put_dec
    lea  rsi, [rel tv_s_of]
    call tv_put_str
    mov  eax, [rel tv_total]
    call tv_put_dec
    cmp  byte [rel tv_trunc], 0
    je   .terminated
    lea  rsi, [rel tv_s_cut]
    call tv_put_str
.terminated:
    lea  rsi, [rel tv_s_numbers_off]
    cmp  byte [rel tv_numbers], 0
    je   .numbers_hint
    lea  rsi, [rel tv_s_numbers_on]
.numbers_hint:
    call tv_put_str
    lea  rax, [rel tv_status]
    sub  rdi, rax
    mov  r12d, edi                      ; its cells: ASCII
    cmp  r12d, [rel tv_acells]
    jbe  .bounded
    mov  r12d, [rel tv_acells]          ; never past the view
.bounded:
    mov  ebx, TV_FG
    mov  r8d, [rel tv_acells]
    sub  r8d, r12d
    jns  .fits
    xor  r8d, r8d
.fits:
    mov  r14d, r8d                      ; the name's room, a gap kept below
    shl  r8d, 3
    add  r8d, [rel tv_gx]
    mov  r9d, r13d
    lea  rax, [rel tv_status]
    push r12
    push rax
.status:
    test r12d, r12d
    jz   .status_done
    mov  rax, [rsp]
    movzx edx, byte [rax]
    inc  qword [rsp]
    mov  ecx, TV_BG
    call wgt_draw_glyph
    add  r8d, 8
    dec  r12d
    jmp  .status
.status_done:
    add  rsp, 16
    ; the name, one checked unit at a time, never into the gap
    sub  r14d, 2
    jle  .out
    xor  r12d, r12d                     ; offset
    mov  ebx, TV_FG
    mov  r8d, [rel tv_gx]
    mov  r9d, r13d
.name:
    cmp  r12d, [rel tv_name_len]
    jae  .out
    lea  rdi, [rel tv_name]
    mov  esi, [rel tv_name_len]
    mov  edx, r12d
    call tv_unit
    cmp  eax, r14d
    ja   .out
    sub  r14d, eax
    add  r12d, ecx
    mov  ecx, TV_BG
    push rax
    call tv_paint_unit
    pop  rax
    shl  eax, 3
    add  r8d, eax
    jmp  .name
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; text_view_draw(EDI widget id): the type's WT_DRAW. Everything it paints lies
; inside the view. Preserves the callee-saved registers (the kit's DRAW ABI).
; ---------------------------------------------------------------------------
text_view_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, edi
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    mov  r9d, [rax + WGI_Y]
    mov  r10d, [rax + WGI_W]
    mov  r11d, [rax + WGI_H]
    mov  ebx, TV_BG
    call wgt_fill_rect
    mov  edi, r12d
    call tv_geom
    test eax, eax
    jz   .out
    mov  eax, [rel tv_state]
    cmp  eax, TV_ST_LOADED
    jne  .line
    mov  esi, [rel tv_acells]
    call tv_layout
    call tv_clamp
    mov  edi, [rel tv_top]
    call tv_style_to
    cmp  byte [rel tv_numbers], 0
    je   .number_ready
    mov  edi, [rel tv_top]
    call tv_line_number
    mov  [rel tv_number_line], eax
.number_ready:
    mov  r13d, [rel tv_top]             ; row start
    xor  r14d, r14d                     ; rows painted
.row:
    cmp  r14d, [rel tv_grows]
    jae  .rows_done
    cmp  r13d, [rel tv_len]
    jae  .rows_done
    test r14d, r14d
    jz   .styled
    cmp  byte [rel tv_md], 0
    je   .styled
    mov  rax, [rel tv_buf]
    cmp  byte [rax + r13 - 1], 10
    jne  .styled
    mov  edi, r13d
    call tv_enter_line
.styled:
    mov  edi, r13d
    mov  esi, [rel tv_acells]
    call tv_next
    mov  r15d, eax
    cmp  byte [rel tv_numbers], 0
    je   .content
    test r13d, r13d
    jz   .number
    mov  rax, [rel tv_buf]
    cmp  byte [rax+r13-1], 10
    jne  .content                      ; continuation of the same file line
.number:
    mov  eax, [rel tv_number_line]
    mov  r9d, r14d
    shl  r9d, 4
    add  r9d, [rel tv_gy]
    call tv_paint_number
.content:
    mov  edi, r13d
    mov  esi, r15d
    mov  r9d, r14d
    shl  r9d, 4
    add  r9d, [rel tv_gy]
    call tv_paint_row
    cmp  byte [rel tv_numbers], 0
    je   .next_row
    mov  rax, [rel tv_buf]
    cmp  byte [rax+r15-1], 10          ; tv_next always advances inside tv_len
    jne  .next_row
    inc  dword [rel tv_number_line]
.next_row:
    mov  r13d, r15d
    inc  r14d
    jmp  .row
.rows_done:
    mov  r9d, [rel tv_grows]
    shl  r9d, 4
    add  r9d, [rel tv_gy]
    call tv_paint_status
    jmp  .out
.line:
    lea  rsi, [rel tv_s_open]
    cmp  eax, TV_ST_EMPTY
    je   .say
    lea  rsi, [rel tv_s_cannot]
    cmp  eax, TV_ST_UNREADABLE
    je   .say
    lea  rsi, [rel tv_s_memory]
.say:
    xor  edi, edi                       ; no catalog id: the escaped English
    mov  r8d, [rel tv_gx]
    mov  r9d, [rel tv_gy]
    mov  ebx, TV_FG
    mov  ecx, TV_BG
    mov  r10d, [rel tv_acells]
    mov  r11d, [rel tv_arows]
    call l10n_paint_wrap
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; tv_ready() -> EAX 1 when the view can scroll: loaded, measured at its live
; size. Clobbers caller-saved registers.
tv_ready:
    sub  rsp, 8
    xor  eax, eax
    cmp  dword [rel tv_state], TV_ST_LOADED
    jne  .out
    mov  edi, [rel tv_ids + TV_W_VIEW * 4]
    call tv_geom
    test eax, eax
    jz   .out
    mov  esi, [rel tv_acells]
    call tv_layout
    call tv_clamp
    mov  eax, 1
.out:
    add  rsp, 8
    ret

; tv_page_rows() -> EAX one view less a row, at least one.
tv_page_rows:
    mov  eax, [rel tv_grows]
    dec  eax
    jg   .out
    mov  eax, 1
.out:
    ret

; tv_button(EDI widget id) -> EAX 1 when it is Previous or Next (and it acted).
; Clobbers caller-saved registers.
tv_button:
    push rbx
    mov  ebx, edi
    cmp  ebx, [rel tv_ids + TV_W_PREV * 4]
    je   .mine
    cmp  ebx, [rel tv_ids + TV_W_NEXT * 4]
    je   .mine
    xor  eax, eax
    jmp  .out
.mine:
    call tv_ready
    test eax, eax
    jz   .taken
    call tv_page_rows
    mov  edi, eax
    cmp  ebx, [rel tv_ids + TV_W_PREV * 4]
    je   .prev
    call tv_down
    jmp  .taken
.prev:
    call tv_up
.taken:
    mov  eax, 1
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; text_view_key(EDI focused widget id, EAX key) -> EAX 1 taken. From
; start_programs' key filter after sp_text_scan. Clobbers caller-saved.
; ---------------------------------------------------------------------------
text_view_key:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    mov  r12d, eax
    cmp  byte [rel tv_live], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    cmp  ebx, [rel wgt_count]
    jae  .no
    mov  edi, ebx
    call wgt_slot_ptr
    mov  ecx, [rel tv_slot]
    cmp  [rax + WGI_WIN], ecx
    jne  .no
    call tv_authorized
    test eax, eax
    jnz  .no
    cmp  r12d, 'n'
    je   .numbers
    cmp  r12d, 'N'
    je   .numbers
    cmp  r12d, ' '
    je   .press
    cmp  r12d, GUI_KEY_ENTER
    je   .press
    cmp  r12d, GUI_KEY_UP
    je   .nav
    cmp  r12d, GUI_KEY_DOWN
    je   .nav
    cmp  r12d, GUI_KEY_PGUP
    je   .nav
    cmp  r12d, GUI_KEY_PGDN
    je   .nav
    cmp  r12d, GUI_KEY_HOME
    je   .nav
    cmp  r12d, GUI_KEY_END
    jne  .no
.nav:
    call tv_ready
    test eax, eax
    jz   .taken
    cmp  r12d, GUI_KEY_UP
    je   .up1
    cmp  r12d, GUI_KEY_DOWN
    je   .down1
    cmp  r12d, GUI_KEY_PGUP
    je   .pgup
    cmp  r12d, GUI_KEY_PGDN
    je   .pgdn
    cmp  r12d, GUI_KEY_HOME
    je   .home
    call tv_max_row
    mov  edi, eax
    sub  edi, [rel tv_row]
    call tv_down
    jmp  .changed
.numbers:
    xor  byte [rel tv_numbers], 1
    mov  dword [rel tv_cells], 0        ; reflow from the same visible byte
    call tv_ready
    jmp  .changed
.home:
    mov  dword [rel tv_top], 0
    mov  dword [rel tv_row], 0
    jmp  .changed
.up1:
    mov  edi, 1
    call tv_up
    jmp  .changed
.down1:
    mov  edi, 1
    call tv_down
    jmp  .changed
.pgup:
    call tv_page_rows
    mov  edi, eax
    call tv_up
    jmp  .changed
.pgdn:
    call tv_page_rows
    mov  edi, eax
    call tv_down
    jmp  .changed
.press:
    mov  edi, ebx
    call tv_button
    test eax, eax
    jz   .taken
.changed:
    mov  edi, [rel tv_ids + TV_W_VIEW * 4]
    call wgt_draw_id
.taken:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; text_view_click(EDI widget id) -> EAX 1 handled. The kit's click hook route.
; Clobbers caller-saved registers.
text_view_click:
    push rbx
    mov  ebx, edi
    cmp  byte [rel tv_live], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    call tv_authorized
    test eax, eax
    jnz  .no
    mov  eax, 1
    cmp  ebx, [rel tv_ids + TV_W_VIEW * 4]
    je   .out                           ; a click on the text selects nothing
    mov  edi, ebx
    call tv_button
    test eax, eax
    jz   .out
    mov  edi, [rel tv_ids + TV_W_VIEW * 4]
    call wgt_draw_id
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; ---- opening a file ----

; tv_type(RSI path, EDX bytes) -> EAX 0 not a text type, 1 text, 2 Markdown, from
; the name's last extension, any case. Clobbers RAX, RCX, RDX, RDI, R8, R9, R10.
tv_type:
    mov  ecx, edx
.back:
    test ecx, ecx
    jz   .no
    dec  ecx
    mov  al, [rsi + rcx]
    cmp  al, '/'
    je   .no
    cmp  al, '.'
    jne  .back
    inc  ecx
    lea  r8, [rsi + rcx]                ; the extension
    mov  r9d, edx
    sub  r9d, ecx                       ; its bytes
    lea  rdi, [rel tv_types]
.row:
    movzx r10d, byte [rdi]              ; {kind, NUL-terminated lower-case name}
    test r10d, r10d
    jz   .no
    inc  rdi
    xor  ecx, ecx
.cmp:
    mov  al, [rdi + rcx]
    test al, al
    jz   .row_end
    cmp  ecx, r9d
    jae  .skip
    mov  dl, [r8 + rcx]
    cmp  dl, 'A'
    jb   .cased
    cmp  dl, 'Z'
    ja   .cased
    add  dl, 32
.cased:
    cmp  al, dl
    jne  .skip
    inc  ecx
    jmp  .cmp
.row_end:
    cmp  ecx, r9d
    jne  .next_row
    mov  eax, r10d
    ret
.skip:
    cmp  byte [rdi + rcx], 0
    je   .next_row
    inc  ecx
    jmp  .skip
.next_row:
    lea  rdi, [rdi + rcx + 1]
    jmp  .row
.no:
    xor  eax, eax
    ret

; Accepted text name's final extension only, case-insensitive. Bounded byte
; reads also permit short names ending immediately at an unmapped guard page.
; RSI=path, EDX=length -> EAX=1 for .sh/.frm, otherwise0.
tv_default_numbers:
    lea  rcx, [rsi+rdx]
    cmp  edx, 3
    jb   .off
    cmp  byte [rcx-3], '.'
    jne  .frm
    movzx eax, word [rcx-2]
    or   eax, 0x2020
    cmp  eax, 'sh'
    je   .on
.frm:
    cmp  edx, 4
    jb   .off
    mov  eax, [rcx-4]
    or   eax, 0x20202000
    cmp  eax, '.frm'
    je   .on
.off:
    xor  eax, eax
    ret
.on:
    mov  eax, 1
    ret

; tv_keep_name(RSI path, EDX bytes): its last component, for the status row.
; Clobbers RAX, RCX, RDI, RSI.
tv_keep_name:
    mov  ecx, edx
.back:
    test ecx, ecx
    jz   .found
    cmp  byte [rsi + rcx - 1], '/'
    je   .found
    dec  ecx
    jmp  .back
.found:
    add  rsi, rcx
    neg  ecx
    add  ecx, edx
    cmp  ecx, TV_NAME_MAX
    jbe  .fits
    mov  ecx, TV_NAME_MAX
.fits:
    mov  [rel tv_name_len], ecx
    lea  rdi, [rel tv_name]
    rep  movsb
    ret

; tv_load(EDI mount handle, RSI path, EDX bytes): read once into the slab. Sets
; tv_state and resets the view. A failed read keeps no part of the file.
; Clobbers caller-saved registers.
tv_load:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24                        ; fs_stat (16 B)
    mov  r12d, edi
    mov  r13, rsi
    mov  r14d, edx
    mov  dword [rel tv_top], 0
    mov  dword [rel tv_row], 0
    mov  dword [rel tv_total], 0
    mov  dword [rel tv_len], 0
    mov  dword [rel tv_cells], 0        ; measured at the next paint or key
    mov  byte [rel tv_trunc], 0
    mov  rax, [rel tv_slab]
    test rax, rax
    jnz  .slab
    mov  edi, TV_CAP
    call kmalloc_model
    mov  [rel tv_slab], rax
    test rax, rax
    jnz  .slab
    mov  dword [rel tv_state], TV_ST_NOMEM
    jmp  .out
.slab:
    mov  [rel tv_buf], rax
    mov  rbx, rax
    mov  edi, r12d
    mov  rsi, r13
    mov  edx, r14d
    mov  rcx, rsp
    call vfs_stat_path
    test eax, eax
    jnz  .unreadable
    mov  rax, [rsp]                     ; fs_stat.size
    mov  ebp, TV_CAP
    cmp  rax, rbp
    jbe  .small
    mov  byte [rel tv_trunc], 1
    jmp  .read_from
.small:
    mov  ebp, eax                       ; the bytes wanted
.read_from:
    xor  r15d, r15d                     ; read so far
.read:
    mov  r9d, ebp
    sub  r9d, r15d
    jz   .read_done
    cmp  r9d, TV_CHUNK
    jbe  .step
    mov  r9d, TV_CHUNK
.step:
    mov  edi, r12d
    mov  rsi, r13
    mov  edx, r14d
    mov  ecx, r15d
    lea  r8, [rbx + r15]
    push r9
    sub  rsp, 8
    call vfs_read_at_path
    add  rsp, 8
    pop  r9
    test rax, rax
    js   .unreadable
    jz   .read_done                     ; the file ended sooner than it said
    cmp  rax, r9
    ja   .unreadable
    add  r15d, eax
    jmp  .read
.read_done:
    ; a cut tail never ends inside a sequence
    cmp  byte [rel tv_trunc], 0
    je   .bom
    mov  ecx, 1
.tail:
    cmp  ecx, 4
    ja   .bom
    cmp  ecx, r15d
    ja   .bom
    mov  eax, r15d
    sub  eax, ecx
    movzx eax, byte [rbx + rax]
    mov  edx, eax
    and  edx, 0xC0
    cmp  edx, 0x80
    jne  .lead
    inc  ecx
    jmp  .tail
.lead:
    cmp  eax, 0xC0
    jb   .bom                           ; ASCII: whole
    mov  edx, 2
    cmp  eax, 0xE0
    jb   .need
    mov  edx, 3
    cmp  eax, 0xF0
    jb   .need
    mov  edx, 4
.need:
    cmp  ecx, edx
    jae  .bom
    sub  r15d, ecx
.bom:
    cmp  r15d, 3
    jb   .loaded
    cmp  byte [rbx], 0xEF
    jne  .loaded
    cmp  byte [rbx + 1], 0xBB
    jne  .loaded
    cmp  byte [rbx + 2], 0xBF
    jne  .loaded
    add  rbx, 3
    mov  [rel tv_buf], rbx
    sub  r15d, 3
.loaded:
    mov  [rel tv_len], r15d
    mov  dword [rel tv_state], TV_ST_LOADED
    jmp  .out
.unreadable:
    mov  dword [rel tv_state], TV_ST_UNREADABLE
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; text_view_close_hook(EDI slot): the document does not outlive its window.
; Clobbers caller-saved registers.
text_view_close_hook:
    cmp  edi, [rel tv_slot]             ; tv_live may be 0: a lock hides the window
    jne  .out
    mov  byte [rel tv_live], 0
    jmp  tv_wipe
.out:
    ret

; tv_wipe(): no document in memory. Clobbers RAX, RCX, RDI.
tv_wipe:
    mov  qword [rel tv_counts_birth], 0
    mov  dword [rel tv_counts_view], 0
    mov  dword [rel tv_counts_host], 0
    mov  dword [rel tv_state], TV_ST_EMPTY
    mov  dword [rel tv_len], 0
    mov  dword [rel tv_name_len], 0
    mov  dword [rel tv_row], 0
    mov  dword [rel tv_total], 0
    mov  byte [rel tv_trunc], 0
    mov  byte [rel tv_md], 0
    mov  byte [rel tv_numbers], 0
    lea  rdi, [rel tv_name]
    mov  ecx, TV_NAME_MAX
    xor  eax, eax
    rep  stosb
    mov  rdi, [rel tv_slab]
    test rdi, rdi
    jz   .out
    mov  ecx, TV_CAP
    xor  eax, eax
    rep  stosb
.out:
    ret

; tv_authorized() -> EAX 0, or 1 after wiping the document: the owner-bound
; desktop only, the rule images use (SEC 89711). Never from paint. Clobbers
; caller-saved registers.
tv_authorized:
    sub  rsp, 8
    call img_source_authority
    test eax, eax
    jz   .out
    call tv_wipe
    mov  edi, [rel tv_ids + TV_W_VIEW * 4]
    call wgt_draw_id
    mov  eax, 1
.out:
    add  rsp, 8
    ret

; ---------------------------------------------------------------------------
; text_view_open(EDI mount handle, RSI path, EDX bytes) -> EAX 0 the viewer took
; it, 1 not a text type (nothing changed), 2 its window did not open, 3 not the
; owner's desktop (nothing read, any earlier document wiped). File Explorer's
; open hook; the same
; disarm as every FORMLOAD. Clobbers caller-saved registers.
; ---------------------------------------------------------------------------
text_view_open:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    call tv_type
    test eax, eax
    jnz  .text
    mov  eax, 1
    jmp  .out
.text:
    push rax
    sub  rsp, 8
    call img_source_authority
    add  rsp, 8
    test eax, eax
    pop  rax
    jz   .allowed
    call tv_wipe
    mov  eax, 3
    jmp  .out
.allowed:
    cmp  eax, 2
    sete byte [rel tv_md]
    mov  rsi, r12
    mov  edx, r13d
    call tv_default_numbers
    mov  [rel tv_numbers], al
    mov  rsi, r12
    mov  edx, r13d
    call tv_keep_name
    mov  edi, ebx
    mov  rsi, r12
    mov  edx, r13d
    call tv_load
    call start_programs_open_text
    call sp_text_scan                   ; a window already open keeps its slot: repaint it
    cmp  byte [rel tv_live], 1
    jne  .no_window
    mov  edi, [rel tv_ids + TV_W_VIEW * 4]
    call tv_counts_bind
    test eax, eax
    jz   .shown
.no_window:
    call tv_wipe                        ; no window to close, so no close hook
    mov  eax, 2                         ; the caller says so
    jmp  .out
.shown:
    mov  edi, [rel tv_ids + TV_W_VIEW * 4]
    call wgt_draw_id
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

tv_str_type:     db "textview", 0
tv_s_open:       db "Open a text file from File Explorer.", 0
tv_s_cannot:     db "This file could not be read.", 0
tv_s_memory:     db "There is not enough memory to open this file.", 0
tv_s_of:         db " of ", 0
tv_s_cut:        db " (first 1 MiB)", 0
tv_s_numbers_on: db "  N: lines on",0
tv_s_numbers_off: db "  N: lines off",0
tv_s_state:      db "textview state=", 0
tv_s_empty:      db "empty", 0
tv_s_loaded:     db "loaded", 0
tv_s_unreadable: db "unreadable", 0
tv_s_nomem:      db "nomem", 0
tv_s_bytes:      db " bytes=", 0
tv_s_rows:       db " rows=", 0
tv_s_first:      db " first=", 0
tv_s_trunc:      db " trunc=", 0
tv_s_md:         db " md=", 0
tv_types:
    db 1, "txt", 0
    db 2, "md", 0
    db 2, "markdown", 0
    db 1, "log", 0
    db 1, "csv", 0
    db 1, "json", 0
    db 1, "sh", 0
    db 1, "frm", 0
    db 0

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_text_view 0
alignb 8
tv_counts_birth: resq 1                 ; full native birth captured at open
tv_counts_view:  resd 1                 ; widget id+1, zero unbound
tv_counts_host:  resd 1                 ; original wmx_window_id at open
tv_slab:         resq 1                 ; the one read-once slab, TV_CAP bytes
tv_buf:          resq 1                 ; the text in it (past a BOM)
text_view_type:  resd 1                 ; the registered type index (-1: none)
tv_ids:          resd TV_W_COUNT        ; the live window's widgets (sp_text_scan)
tv_slot:         resd 1
tv_state:        resd 1
tv_len:          resd 1
tv_top:          resd 1                 ; the first row's start
tv_row:          resd 1                 ; and its number
tv_total:        resd 1                 ; rows at tv_cells
tv_cells:        resd 1                 ; the width they were measured at; 0 stale
tv_gx:           resd 1                 ; tv_geom
tv_gy:           resd 1
tv_acells:       resd 1
tv_arows:        resd 1
tv_grows:        resd 1
tv_lkind:        resd 1                 ; the current line's Markdown kind
tv_lmark:        resd 1                 ; a heading marker's bytes
tv_lbullet:      resd 1                 ; a list marker's offset, -1 none
tv_name_len:     resd 1
tv_name:         resb TV_NAME_MAX
tv_status:       resb 48                ; counts, optional cap marker, N line-number hint (<=45 bytes)
tv_get_buf:      resb 96                ; the counts line
tv_live:         resb 1                 ; 1 while the whole form is open
tv_md:           resb 1
tv_trunc:        resb 1
tv_fence:        resb 1
tv_numbers:      resb 1
tv_num_gx:       resd 1
tv_number_line:  resd 1
tv_number_buf:   resb 5
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_text_view
