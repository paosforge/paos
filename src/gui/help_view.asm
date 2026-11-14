;; MODULE gui/help_view
;; LAYER 6
;; EXPORTS help_view_init, help_view_draw, help_view_hit, help_view_key, help_view_click, help_view_type, hv_ids, hv_slot, hv_live
;; IMPORTS gui/widget, gui/l10n_paint, gui/res_pack_boot, sec/session, boot/serial
;; CAPS CAP_GUI
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; ============================================================================
; gui/help_view.asm — RCQ-38 offline help H2: the native Help surface
; (PLAN_HELP_H2_SURFACE_20261011.md 6b546dd5; root 2026-10-11 04:24:42).
;
; One read-only window, Help (gui/forms/help.frm, registry row offline_help):
; a `helptext` view plus three .frm buttons, Contents, Previous and Next. The
; view shows the Contents (the help's page titles) or one page (its title and
; blocks, scrolled a whole block at a time). Start/Summon lists the row; Win+F1
; opens it on the owner's hand (gui/input_route). There is no Help on the lock
; screen in RC1 (root Q1).
;
; PAINTING (t6). Help text reaches the screen only through rc-boot's two H1b
; entries, l10n_help_paint / l10n_help_rows (gui/l10n_paint): this module
; passes (page, block) and never holds a pointer to help text or a parameter
; value. l10n_help_rows is the same wrap with nothing drawn, so the layout here
; and the paint never disagree.
;
; WHOLE PAGES. A page is shown only when every one of its blocks can be shown
; whole at the view's live width and height; otherwise the view shows one native
; line, hv_s_unavailable, and nothing of that page. The same line shows while no
; valid help exists (l10n_help_page_count 0). A page never shows a cut block.
;
; READ-ONLY. The view writes only its own hv_* state: no setting, file, verb or
; network. A key or a click only navigates, so an injected one needs no origin
; gate (rc-sec classifies the start_programs route). WIDGETSET on the view is
; refused.
;
; KEYS (the Help window focused; the view itself is not a focus stop, so focus
; rests on the buttons and these keys act from any of them; Tab stays the kit's):
;   Contents: Up/Down move the selection, PgUp/Home the first title, PgDn/End
;             the last, Enter opens the selected page
;   Page:     Up/Down scroll one block, PgUp/PgDn one view, Home the title, End
;             the last position that shows the final block, Left/Right the
;             previous/next page (clamped, no wrap), Esc/Backspace the Contents
;             with the selection on this page
;   Enter (on a page) and Space activate the focused button.
; Buttons: Contents shows the Contents; Previous/Next turn the page, or on the
; Contents move the selection. A click on a Contents title opens that page.
; ============================================================================

HV_W_VIEW       equ 0                   ; hv_ids: help.frm declaration order
HV_W_CONTENTS   equ 1
HV_W_PREV       equ 2
HV_W_NEXT       equ 3
HV_W_COUNT      equ 4
HV_INSET_X      equ 8                   ; text inset inside the view, left and right
HV_INSET_Y      equ 4                   ; top and bottom
HV_CELL_PX      equ 8                   ; an 8x16 cell (l10n_paint's L10N_ROW_PX rows)
HV_ROW_PX       equ 16
HV_MARK_CELLS   equ 2                   ; the right column for the ^ / v markers, and a gap
HV_PREFIX_CELLS equ 3                   ; "1. " before a Contents title
HV_MIN_CELLS    equ HV_PREFIX_CELLS + 8 ; narrower than this shows only the native line
HV_ITEMS_MAX    equ 16                  ; a page's title + blocks; more is never laid out
HV_FG           equ GUI_TOK_LABEL_TEXT
HV_BG           equ GUI_TOK_WINDOW_BODY
HV_SEL_FG       equ GUI_TOK_CONTROL_TEXT
HV_SEL_BG       equ GUI_TOK_SELECTION
; The native line's message id. Its catalog record (relops DATA, provisional id
; 4055, key site.2167fdac08f9b6b6169d078c) lands with H2; until then 0 resolves
; to nothing and l10n_paint_wrap paints the English below, escaped and wrapped.
HV_UNAVAILABLE_ID equ L10N_ID_hv_s_unavailable

%if L10N_HELP_PAGES > 9
%error "the page indicator and the Contents numbers are one digit"
%endif

; ---------------------------------------------------------------------------
; help_view_init(): register the `helptext` type (after every shipped type, so
; no type number moves). Called once from start_programs_init. -> EAX 0, or 1
; when the type table is full (Help then never loads: unknown_widget).
; Clobbers caller-saved registers.
; ---------------------------------------------------------------------------
help_view_init:
    sub  rsp, 8
    lea  rdi, [rel hv_str_type]
    lea  rsi, [rel help_view_draw]
    lea  rdx, [rel help_view_hit]
    lea  rcx, [rel help_view_set]
    lea  r8,  [rel wgt_label_get]       ; WIDGETGET text: the form's token
    mov  r9, (348 << 32) | 568
    call wgt_type_register
    mov  [rel help_view_type], eax
    add  rsp, 8
    cmp  eax, -1
    je   .full
    xor  eax, eax
    ret
.full:
    mov  eax, 1
    ret

; help_view_set: WIDGETSET on the view is refused (read-only). -> EAX 1
help_view_set:
    mov  eax, 1
    ret

; ---------------------------------------------------------------------------
; help_view_hit(EDI widget id, ESI x, EDX y) -> EAX 1 inside its rectangle.
; The kit's WT_HIT: it records the point, which the click hook that follows
; the hit (wgt_pointer_hit_dispatch) maps to a Contents title.
; ---------------------------------------------------------------------------
help_view_hit:
    mov  [rel hv_hit_x], esi
    mov  [rel hv_hit_y], edx
    jmp  wgt_rect_hittest

; hv_bind(EDI view widget id): a view the state does not belong to starts on
; the Contents, first title selected. Touches memory only.
hv_bind:
    lea  eax, [rdi + 1]
    cmp  eax, [rel hv_view]
    je   .out
    mov  [rel hv_view], eax
    mov  dword [rel hv_page], -1
    mov  dword [rel hv_first], 0
    mov  dword [rel hv_sel], 0
.out:
    ret

; hv_geom(EDI view widget id) -> EAX 1 and hv_gx/gy (text origin), hv_gcells /
; hv_grows (the text area: cells less the marker column, rows less the status
; row), hv_acells/hv_arows (the whole inset area); EAX 0 when the view is too
; small for any text. From the LIVE rectangle on every call. Clobbers
; caller-saved registers.
hv_geom:
    call wgt_slot_ptr
    mov  rdx, rax
    mov  ecx, [rdx + WGI_X]
    add  ecx, HV_INSET_X
    mov  [rel hv_gx], ecx
    mov  ecx, [rdx + WGI_Y]
    add  ecx, HV_INSET_Y
    mov  [rel hv_gy], ecx
    mov  eax, [rdx + WGI_W]
    sub  eax, 2 * HV_INSET_X
    jle  .small
    shr  eax, 3                         ; / HV_CELL_PX
    mov  [rel hv_acells], eax
    sub  eax, HV_MARK_CELLS
    cmp  eax, HV_MIN_CELLS
    jl   .small
    mov  [rel hv_gcells], eax
    mov  eax, [rdx + WGI_H]
    sub  eax, 2 * HV_INSET_Y
    jle  .small
    shr  eax, 4                         ; / HV_ROW_PX
    mov  [rel hv_arows], eax
    dec  eax                            ; the status row
    cmp  eax, 1
    jl   .small
    mov  [rel hv_grows], eax
    mov  eax, 1
    ret
.small:
    xor  eax, eax
    ret

; hv_measure(EDI page) -> EAX the page's items (title + blocks) with their rows
; at hv_gcells in hv_h[]; -1 when an item cannot be shown whole at the view's
; size (l10n_help_rows -1, or taller than hv_grows) or the page is out of range.
; Clobbers caller-saved registers.
hv_measure:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    call l10n_help_page                 ; EAX title id, ECX blocks (0, 0: none)
    test eax, eax
    jz   .bad
    lea  r13d, [rcx + 1]                ; items
    cmp  r13d, HV_ITEMS_MAX
    ja   .bad
    xor  ebx, ebx
.item:
    cmp  ebx, r13d
    jae  .done
    mov  edi, r12d
    lea  esi, [rbx - 1]                 ; item 0 is the title (-1)
    mov  r10d, [rel hv_gcells]
    call l10n_help_rows
    test eax, eax
    jle  .bad                           ; -1, or a record of no rows
    cmp  eax, [rel hv_grows]
    jg   .bad                           ; taller than the view: never whole
    lea  rcx, [rel hv_h]
    mov  [rcx + rbx * 4], eax
    inc  ebx
    jmp  .item
.done:
    mov  eax, r13d
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hv_fit(EDI first item, EDX items) -> EAX the item after the last one that fits
; whole in hv_grows rows from that first item (a blank row after each). Uses
; hv_h[]. Clobbers RAX, RCX, RSI, R8.
hv_fit:
    xor  ecx, ecx                       ; rows used
    mov  eax, edi
    lea  r8, [rel hv_h]
.next:
    cmp  eax, edx
    jae  .out
    mov  esi, ecx
    add  esi, [r8 + rax * 4]
    cmp  esi, [rel hv_grows]
    jg   .out
    lea  ecx, [rsi + 1]
    inc  eax
    jmp  .next
.out:
    ret

; hv_last_first(EDX items) -> EAX the smallest first item that still shows the
; final one (End, and the clamp for every scroll). Uses hv_h[]. Clobbers RAX,
; RCX, RSI.
hv_last_first:
    lea  eax, [rdx - 1]
    lea  rsi, [rel hv_h]
    mov  ecx, [rsi + rax * 4]           ; rows from the first shown to the end
.back:
    test eax, eax
    jz   .out
    push rcx
    add  ecx, [rsi + rax * 4 - 4]
    inc  ecx                            ; the blank row between
    cmp  ecx, [rel hv_grows]
    pop  rcx
    jg   .out
    add  ecx, [rsi + rax * 4 - 4]
    inc  ecx
    dec  eax
    jmp  .back
.out:
    ret

; hv_contents(void) -> EAX 1 and hv_crow[r] / hv_cn[r] (first row, rows) of each
; title at hv_gcells - HV_PREFIX_CELLS; EAX 0 when there is no valid help or the
; titles do not fit whole in hv_grows. Clobbers caller-saved registers.
hv_contents:
    push rbx
    push r12
    push r13
    call l10n_help_page_count
    mov  r13d, eax
    test eax, eax
    jz   .bad
    xor  ebx, ebx                       ; title
    xor  r12d, r12d                     ; row
.title:
    cmp  ebx, r13d
    jae  .ok
    mov  edi, ebx
    mov  esi, -1
    mov  r10d, [rel hv_gcells]
    sub  r10d, HV_PREFIX_CELLS
    call l10n_help_rows
    test eax, eax
    jle  .bad
    lea  ecx, [r12 + rax]
    cmp  ecx, [rel hv_grows]
    jg   .bad
    lea  rdx, [rel hv_crow]
    mov  [rdx + rbx * 4], r12d
    lea  rdx, [rel hv_cn]
    mov  [rdx + rbx * 4], eax
    mov  r12d, ecx
    inc  ebx
    jmp  .title
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; help_view_draw(EDI widget id): the type's WT_DRAW, inside the kit's window
; draw. Fills its rectangle, then the Contents, the page, or the native line.
; Everything it paints lies inside the view. Preserves the callee-saved
; registers (the kit's DRAW ABI).
; ---------------------------------------------------------------------------
help_view_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12d, edi
    call hv_bind
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    mov  r9d, [rax + WGI_Y]
    mov  r10d, [rax + WGI_W]
    mov  r11d, [rax + WGI_H]
    mov  ebx, HV_BG
    call wgt_fill_rect
    mov  edi, r12d
    call hv_geom
    test eax, eax
    jz   .out                           ; too small for one line: the fill only
    cmp  dword [rel hv_page], -1
    je   .contents
    ; ---- a page ----
    mov  edi, [rel hv_page]
    call hv_measure
    test eax, eax
    js   .unavailable
    mov  r13d, eax                      ; items
    mov  edx, r13d
    call hv_last_first
    cmp  [rel hv_first], eax
    jle  .first_ok
    mov  [rel hv_first], eax            ; re-clamped after a resize
.first_ok:
    mov  r14d, [rel hv_first]           ; item
    xor  r15d, r15d                     ; row
.paint:
    cmp  r14d, r13d
    jae  .painted
    lea  rcx, [rel hv_h]
    mov  ebp, [rcx + r14 * 4]           ; its rows
    lea  eax, [r15 + rbp]
    cmp  eax, [rel hv_grows]
    jg   .painted                       ; the first one that does not fit whole
    mov  edi, [rel hv_page]
    lea  esi, [r14 - 1]
    mov  r8d, [rel hv_gx]
    mov  r9d, r15d
    shl  r9d, 4
    add  r9d, [rel hv_gy]
    mov  ebx, HV_FG
    mov  ecx, HV_BG
    mov  r10d, [rel hv_gcells]
    mov  r11d, ebp
    call l10n_help_paint
    test eax, eax
    jz   .unavailable_refill            ; measured whole, not painted: never a partial page
    lea  r15d, [r15 + rbp + 1]
    inc  r14d
    jmp  .paint
.painted:
    mov  [rsp], r14d                    ; the first item not shown
    ; markers in the right column: ^ above, v below
    mov  r8d, [rel hv_acells]
    dec  r8d
    shl  r8d, 3
    add  r8d, [rel hv_gx]
    cmp  dword [rel hv_first], 0
    je   .no_up
    mov  r9d, [rel hv_gy]
    mov  edx, '^'
    mov  ebx, HV_FG
    mov  ecx, HV_BG
    call wgt_draw_glyph
.no_up:
    cmp  [rsp], r13d
    jae  .no_down
    mov  r9d, [rel hv_grows]
    dec  r9d
    shl  r9d, 4
    add  r9d, [rel hv_gy]
    mov  edx, 'v'
    mov  ebx, HV_FG
    mov  ecx, HV_BG
    call wgt_draw_glyph
.no_down:
    ; the page indicator "p/N", right-aligned on the status row
    mov  r9d, [rel hv_grows]
    shl  r9d, 4
    add  r9d, [rel hv_gy]
    mov  r8d, [rel hv_acells]
    sub  r8d, 3
    shl  r8d, 3
    add  r8d, [rel hv_gx]
    mov  ebx, HV_FG
    mov  ecx, HV_BG
    mov  edx, [rel hv_page]
    add  edx, '1'
    call wgt_draw_glyph
    add  r8d, HV_CELL_PX
    mov  edx, '/'
    call wgt_draw_glyph
    add  r8d, HV_CELL_PX
    call l10n_help_page_count
    lea  edx, [rax + '0']
    mov  ebx, HV_FG
    mov  ecx, HV_BG
    call wgt_draw_glyph
    jmp  .out

.contents:
    call hv_contents
    test eax, eax
    jz   .unavailable
    call l10n_help_page_count
    mov  r13d, eax
    mov  eax, [rel hv_sel]
    cmp  eax, r13d
    jb   .sel_ok
    lea  eax, [r13 - 1]
    mov  [rel hv_sel], eax
.sel_ok:
    xor  r14d, r14d                     ; title
.title:
    cmp  r14d, r13d
    jae  .out
    lea  rax, [rel hv_crow]
    mov  r9d, [rax + r14 * 4]
    shl  r9d, 4
    add  r9d, [rel hv_gy]
    lea  rax, [rel hv_cn]
    mov  ebp, [rax + r14 * 4]           ; its rows
    mov  ebx, HV_FG
    mov  r15d, HV_BG
    cmp  r14d, [rel hv_sel]
    jne  .colours
    mov  r8d, [rel hv_gx]               ; the selected title: the selection strip
    mov  r10d, [rel hv_gcells]
    shl  r10d, 3
    mov  r11d, ebp
    shl  r11d, 4
    mov  ebx, HV_SEL_BG
    call wgt_fill_rect
    mov  ebx, HV_SEL_FG
    mov  r15d, HV_SEL_BG
.colours:
    mov  r8d, [rel hv_gx]
    lea  edx, [r14 + '1']
    mov  ecx, r15d
    call wgt_draw_glyph
    add  r8d, HV_CELL_PX
    mov  edx, '.'
    call wgt_draw_glyph
    add  r8d, 2 * HV_CELL_PX
    mov  edi, r14d
    mov  esi, -1
    mov  ecx, r15d
    mov  r10d, [rel hv_gcells]
    sub  r10d, HV_PREFIX_CELLS
    mov  r11d, ebp
    call l10n_help_paint
    test eax, eax
    jz   .unavailable_refill
    inc  r14d
    jmp  .title

.unavailable_refill:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    mov  r9d, [rax + WGI_Y]
    mov  r10d, [rax + WGI_W]
    mov  r11d, [rax + WGI_H]
    mov  ebx, HV_BG
    call wgt_fill_rect
.unavailable:
    mov  edi, HV_UNAVAILABLE_ID
    lea  rsi, [rel hv_s_unavailable]
    mov  r8d, [rel hv_gx]
    mov  r9d, [rel hv_gy]
    mov  ebx, HV_FG
    mov  ecx, HV_BG
    mov  r10d, [rel hv_acells]
    mov  r11d, [rel hv_arows]
    call l10n_paint_wrap
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; hv_repaint(): the view, after a key or click changed what it shows.
; Clobbers caller-saved registers.
hv_repaint:
    mov  edi, [rel hv_ids + HV_W_VIEW * 4]
    jmp  wgt_draw_id

; hv_open_page(EDI page): show that page from its title. Touches memory only.
hv_open_page:
    mov  [rel hv_page], edi
    mov  dword [rel hv_first], 0
    ret

; hv_to_contents(): the Contents, the selection on the page that was shown.
; Touches memory only.
hv_to_contents:
    mov  eax, [rel hv_page]
    cmp  eax, -1
    je   .out
    mov  [rel hv_sel], eax
    mov  dword [rel hv_page], -1
.out:
    ret

; hv_step(ESI -1 or +1): Previous / Next. A page turns (clamped, no wrap, from
; its title); on the Contents the selection moves. Clobbers caller-saved.
hv_step:
    push rbx
    mov  ebx, esi
    call l10n_help_page_count
    mov  ecx, [rel hv_page]
    cmp  ecx, -1
    jne  .page
    mov  ecx, [rel hv_sel]
    add  ecx, ebx
    js   .out
    cmp  ecx, eax
    jae  .out
    mov  [rel hv_sel], ecx
    jmp  .out
.page:
    add  ecx, ebx
    js   .out
    cmp  ecx, eax
    jae  .out
    mov  edi, ecx
    call hv_open_page
.out:
    pop  rbx
    ret

; hv_button(EDI widget id) -> EAX 1 when it is one of Help's buttons (and it
; acted). Clobbers caller-saved registers.
hv_button:
    cmp  edi, [rel hv_ids + HV_W_CONTENTS * 4]
    je   .contents
    mov  esi, -1
    cmp  edi, [rel hv_ids + HV_W_PREV * 4]
    je   .step
    mov  esi, 1
    cmp  edi, [rel hv_ids + HV_W_NEXT * 4]
    je   .step
    xor  eax, eax
    ret
.contents:
    call hv_to_contents
    mov  eax, 1
    ret
.step:
    sub  rsp, 8
    call hv_step
    add  rsp, 8
    mov  eax, 1
    ret

; ---------------------------------------------------------------------------
; help_view_key(EDI focused widget id, EAX key) -> EAX 1 taken. Called from
; start_programs' key filter after sp_help_scan; a key acts only while Help is
; live, the session is unlocked and the focused widget is in Help's window.
; Clobbers caller-saved registers.
; ---------------------------------------------------------------------------
help_view_key:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, eax
    cmp  byte [rel hv_live], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    cmp  ebx, [rel wgt_count]
    jae  .no
    mov  edi, ebx
    call wgt_slot_ptr
    mov  ecx, [rel hv_slot]
    cmp  [rax + WGI_WIN], ecx
    jne  .no
    mov  edi, [rel hv_ids + HV_W_VIEW * 4]
    call hv_bind
    cmp  r12d, ' '
    je   .press
    cmp  dword [rel hv_page], -1
    jne  .page
    ; ---- Contents ----
    call l10n_help_page_count
    lea  r13d, [rax - 1]                ; the last title (-1: no help, navigation does nothing)
    mov  ecx, [rel hv_sel]
    cmp  r12d, GUI_KEY_UP
    je   .sel_up
    cmp  r12d, GUI_KEY_DOWN
    je   .sel_down
    cmp  r12d, GUI_KEY_HOME
    je   .sel_first
    cmp  r12d, GUI_KEY_PGUP
    je   .sel_first
    cmp  r12d, GUI_KEY_END
    je   .sel_last
    cmp  r12d, GUI_KEY_PGDN
    je   .sel_last
    cmp  r12d, GUI_KEY_ENTER
    je   .sel_open
    jmp  .nav_keys
.sel_up:
    test ecx, ecx
    jz   .nav_taken
    dec  ecx
    jmp  .sel_set
.sel_down:
    cmp  ecx, r13d
    jge  .nav_taken
    inc  ecx
    jmp  .sel_set
.sel_first:
    xor  ecx, ecx
    jmp  .sel_set
.sel_last:
    test r13d, r13d
    js   .nav_taken
    mov  ecx, r13d
.sel_set:
    mov  [rel hv_sel], ecx
    jmp  .changed
.sel_open:
    test r13d, r13d
    js   .nav_taken
    mov  edi, ecx
    call hv_open_page
    jmp  .changed
    ; ---- a page ----
.page:
    cmp  r12d, GUI_KEY_ENTER
    je   .press
    cmp  r12d, GUI_KEY_LEFT
    je   .prev
    cmp  r12d, GUI_KEY_RIGHT
    je   .next
    cmp  r12d, GUI_KEY_ESC
    je   .back
    cmp  r12d, GUI_KEY_BACKSPACE
    je   .back
    cmp  r12d, GUI_KEY_UP
    je   .scroll
    cmp  r12d, GUI_KEY_DOWN
    je   .scroll
    cmp  r12d, GUI_KEY_PGUP
    je   .scroll
    cmp  r12d, GUI_KEY_PGDN
    je   .scroll
    cmp  r12d, GUI_KEY_HOME
    je   .scroll
    cmp  r12d, GUI_KEY_END
    je   .scroll
    jmp  .no
.prev:
    mov  esi, -1
    call hv_step
    jmp  .changed
.next:
    mov  esi, 1
    call hv_step
    jmp  .changed
.back:
    call hv_to_contents
    jmp  .changed
.scroll:
    mov  edi, [rel hv_ids + HV_W_VIEW * 4]
    call hv_geom
    test eax, eax
    jz   .nav_taken
    mov  edi, [rel hv_page]
    call hv_measure
    test eax, eax
    js   .nav_taken                     ; the native line: nothing to scroll
    mov  r13d, eax                      ; items
    mov  edi, r12d
    mov  esi, r13d
    call hv_scroll
    jmp  .changed
.press:
    mov  edi, ebx
    call hv_button
    test eax, eax
    jz   .nav_taken                     ; Space / Enter elsewhere in Help: nothing
    jmp  .changed
.nav_keys:
    cmp  r12d, GUI_KEY_LEFT             ; on the Contents these navigate nothing
    je   .nav_taken
    cmp  r12d, GUI_KEY_RIGHT
    je   .nav_taken
    cmp  r12d, GUI_KEY_ESC
    je   .nav_taken
    cmp  r12d, GUI_KEY_BACKSPACE
    je   .nav_taken
    jmp  .no
.changed:
    call hv_repaint
.nav_taken:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hv_scroll(EDI key, ESI items; hv_h[] measured at the live size): move
; hv_first, always inside [0, the last first]. Clobbers caller-saved.
hv_scroll:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  edx, r12d
    call hv_last_first
    mov  r13d, eax                      ; the last first
    mov  ecx, [rel hv_first]
    cmp  ebx, GUI_KEY_HOME
    je   .home
    cmp  ebx, GUI_KEY_END
    je   .end
    cmp  ebx, GUI_KEY_UP
    je   .up
    cmp  ebx, GUI_KEY_DOWN
    je   .down
    cmp  ebx, GUI_KEY_PGDN
    je   .pgdn
    ; PgUp: the earliest first from which the view still reaches the item
    ; just above the current first
.pgup:
    test ecx, ecx
    jz   .set
    mov  ebx, ecx                       ; the current first
    lea  r13d, [rcx - 1]                ; must stay shown
.pgup_back:
    test r13d, r13d
    jz   .pgup_done
    lea  edi, [r13 - 1]
    mov  edx, r12d
    call hv_fit
    cmp  eax, ebx
    jb   .pgup_done                     ; from one earlier it would not reach that item
    dec  r13d
    jmp  .pgup_back
.pgup_done:
    mov  ecx, r13d
    jmp  .set
.pgdn:
    mov  edi, ecx
    mov  edx, r12d
    call hv_fit                         ; the first item not shown
    mov  ecx, eax
    jmp  .clamp
.home:
    xor  ecx, ecx
    jmp  .set
.end:
    mov  ecx, r13d
    jmp  .set
.up:
    test ecx, ecx
    jz   .set
    dec  ecx
    jmp  .set
.down:
    inc  ecx
.clamp:
    cmp  ecx, r13d
    jle  .set
    mov  ecx, r13d
.set:
    mov  [rel hv_first], ecx
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; help_view_click(EDI widget id) -> EAX 1 handled. The kit's click hook route
; (start_programs_click, after sp_help_scan): a Contents title opens its page;
; Contents / Previous / Next act. Clobbers caller-saved registers.
; ---------------------------------------------------------------------------
help_view_click:
    push rbx
    mov  ebx, edi
    cmp  byte [rel hv_live], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    mov  edi, [rel hv_ids + HV_W_VIEW * 4]
    call hv_bind
    cmp  ebx, [rel hv_ids + HV_W_VIEW * 4]
    je   .view
    mov  edi, ebx
    call hv_button
    test eax, eax
    jz   .out
    jmp  .changed
.view:
    cmp  dword [rel hv_page], -1
    jne  .taken                         ; a page: a click selects nothing
    mov  edi, ebx
    call hv_geom
    test eax, eax
    jz   .taken
    call hv_contents
    test eax, eax
    jz   .taken
    mov  eax, [rel hv_hit_y]
    sub  eax, [rel hv_gy]
    js   .taken
    shr  eax, 4                         ; the row under the press
    mov  r8d, eax
    mov  eax, [rel hv_hit_x]
    sub  eax, [rel hv_gx]
    js   .taken
    shr  eax, 3
    cmp  eax, [rel hv_gcells]
    jae  .taken                         ; the marker column is no title
    call l10n_help_page_count
    xor  ecx, ecx
.find:
    cmp  ecx, eax
    jae  .taken
    lea  rdx, [rel hv_crow]
    mov  esi, r8d
    sub  esi, [rdx + rcx * 4]
    jb   .find_next
    lea  rdx, [rel hv_cn]
    cmp  esi, [rdx + rcx * 4]
    jb   .hit
.find_next:
    inc  ecx
    jmp  .find
.hit:
    mov  [rel hv_sel], ecx
    mov  edi, ecx
    call hv_open_page
.changed:
    call hv_repaint
.taken:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

hv_str_type:       db "helptext", 0
hv_s_unavailable:  db "Offline help is not available in this build.", 0

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_help_view 0
alignb 8
help_view_type:    resd 1               ; the registered type index (-1: none)
hv_ids:            resd HV_W_COUNT      ; the live Help window's widgets (sp_help_scan)
hv_slot:           resd 1               ; its WM slot
hv_view:           resd 1               ; the view id + 1 the state belongs to, 0 none
hv_page:           resd 1               ; -1 the Contents, else the page shown
hv_first:          resd 1               ; the first item shown (0 = the title)
hv_sel:            resd 1               ; the selected Contents title
hv_hit_x:          resd 1               ; the last press inside the view
hv_hit_y:          resd 1
hv_gx:             resd 1               ; hv_geom
hv_gy:             resd 1
hv_gcells:         resd 1
hv_grows:          resd 1
hv_acells:         resd 1
hv_arows:          resd 1
hv_h:              resd HV_ITEMS_MAX    ; rows of each item of the measured page
hv_crow:           resd L10N_HELP_PAGES ; each Contents title's first row
hv_cn:             resd L10N_HELP_PAGES ; and its rows
hv_live:           resb 1               ; 1 while the whole Help form is open
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_help_view
