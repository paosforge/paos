;; MODULE gui/widget_tabstrip
;; LAYER 6
;; EXPORTS wgt_menu_type, wgt_tabstrip_register, wgt_menu_dismiss_outside, wgt_menu_hover, wgt_menu_shown_at, wgt_menu_overlay_press, wgt_menu_key, wgt_tabstrip_state, wgt_tabstrip_active_tag, wgt_tabstrip_has_tag, wgt_tabstrip_key, wgt_tabstrip_middle, wgt_tabstrip_release_window, ts_close_request
;; IMPORTS gui/window, gui/widget, gui/window_mgmt, gui/font_aa, gui/chat_app, gui/wm_pointer, boot/serial, core/lib/str
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/widget_tabstrip.asm — Phase-1 shared UI wave (PETER RULING 2026-09-29 13:50)
;
; Two vtable types, registered additively (gui ESSENCE E6), painting only via
; the shared primitives (fb_fill_rect, fb_draw_glyph_aa, fb_draw_str_aa_n):
;
;   tabstrip  Windows Terminal style tab strip for chrome=tabs windows. The form
;             places it in the title band (x=1 y=1 h=39, left of the caption
;             buttons). Tabs carry an icon, an AA title and a close glyph; the
;             active tab is the body colour with rounded top corners and runs
;             through the separator row into the body. A new-tab button (+) and
;             a dropdown button (v) follow the tabs; when tabs no longer fit at
;             TS_TAB_MIN they scroll to keep the active tab visible and an
;             overflow button (...) steps through the hidden ones. WT_HIT
;             performs the action and returns 0 on empty strip space, which the
;             WM keeps as the title drag area.
;   menu      a small flyout (Windows 11 style) opened by the dropdown button.
;             Items come from the widget text, '|' separated. It paints only
;             while open, in the overlay pass (WGI_LAYER 1); a press outside
;             closes it (wgt_menu_dismiss_outside, called by wm_pointer).
;
; Apps adopt both through wgt_tabstrip_state (tab count/active/titles/last event)
; and the menu's recorded selection -- Terminal multi-tab, Start and Settings
; bind their own content to these events; the widgets own no app behaviour.
; Form text cannot hold spaces, so '_' renders as a space in titles and items.
; ============================================================================

TS_MAX_INST     equ 4
TS_MAX_TABS     equ 8
TS_TITLE_MAX    equ 24
TS_TITLE_DISP_MAX equ 64              ; RCQ-38 L3a: the escaped title painted (stack copy)
TS_WID          equ 0            ; dd widget id, -1 free
TS_WIN          equ 4            ; dd host slot at bind time
TS_COUNT        equ 8
TS_ACTIVE       equ 12
TS_FIRST        equ 16           ; first visible tab (overflow scroll)
TS_NEXTN        equ 20           ; next new-tab ordinal
TS_MENU         equ 24           ; dd menu widget id, -1 none
TS_EV_KIND      equ 28
TS_EV_INDEX     equ 32
TS_EV_SEQ       equ 36
TS_BIRTH        equ 40           ; dq widget WGI_ID pointer at bind time
TS_BASE         equ 48           ; UI wave 2 B6c: the bound widget text, the new-tab title base
TS_TITLES       equ 72
TS_HOST         equ TS_TITLES + TS_MAX_TABS * TS_TITLE_MAX   ; T4: host label ('_' for ' ')
TS_TAGS         equ TS_HOST + TS_TITLE_MAX   ; B5: per-tab stable identity (dd each), shifts with the titles
TS_TAGSEQ       equ TS_TAGS + 4 * TS_MAX_TABS ; B5: last issued tag (a tag is never 0)
TS_SZ           equ TS_TAGSEQ + 4

TS_KEY_NEW      equ 1            ; wgt_tabstrip_key actions (G3 keyboard tab control)
TS_KEY_NEXT     equ 2
TS_KEY_PREV     equ 3
TS_KEY_CLOSE    equ 4

TS_EV_NONE      equ 0
TS_EV_SELECT    equ 1
TS_EV_CLOSE     equ 2
TS_EV_NEW       equ 3
TS_EV_MENU      equ 4
TS_EV_OVERFLOW  equ 5
TS_EV_MENUITEM  equ 6

; geometry, relative to the widget origin (window x+1, y+1): reference
; peter-windows-terminal-reference-20260929.png measured at 100 %.
TS_TAB_LEFT     equ GUI_TAB_LEFT      ; E10: theme_tokens.inc
TS_TAB_W        equ GUI_TAB_W
TS_TAB_MIN      equ GUI_TAB_MIN
TS_TAB_TOP      equ GUI_TAB_TOP
TS_BTN_W        equ GUI_TAB_BTN_W
TS_ICON_X       equ 10
TS_ICON_Y       equ 17
TS_TEXT_X       equ GUI_TAB_TEXT_X
TS_TEXT_Y       equ 17
TS_CLOSE_DX     equ GUI_TAB_CLOSE_DX ; close glyph at tab_w - 25
TS_CLOSE_Y      equ 20
TS_GLYPH        equ 9

TS_COL_ACTIVE_TEXT equ GUI_TOK_TAB_ACTIVE_TEXT
TS_COL_TEXT     equ GUI_TOK_TAB_TEXT
TS_COL_GLYPH    equ GUI_TOK_TAB_GLYPH
TS_COL_DIVIDER  equ GUI_TOK_TAB_DIVIDER
TS_COL_ICON     equ GUI_TOK_TAB_ICON

MENU_ITEM_H     equ GUI_MENU_ITEM_H
MENU_PAD        equ GUI_MENU_PAD
MENU_MAX_ITEMS  equ 6
MENU_BG         equ GUI_TOK_MENU_BG
MENU_BORDER     equ GUI_TOK_MENU_BORDER
MENU_TEXT       equ GUI_TOK_MENU_TEXT
MENU_HOVER      equ GUI_TOK_MENU_HOVER
MENU_HOT        equ WGI_SCROLL   ; menu: highlighted item + 1 (0 = none); reset on open/close

wgt_tabstrip_register:
    lea  rdi, [rel ts_inst]
    mov  ecx, TS_MAX_INST
.clear:
    mov  dword [rdi + TS_WID], -1
    add  rdi, TS_SZ
    loop .clear
    lea  rdi, [rel str_wt_tabstrip]
    lea  rsi, [rel wgt_tabstrip_draw]
    lea  rdx, [rel wgt_tabstrip_hit]
    lea  rcx, [rel wgt_label_set]
    lea  r8,  [rel wgt_label_get]
    mov  r9, (39 << 32) | 600
    call wgt_type_register
    mov  [rel wgt_tabstrip_type], eax
    lea  rdi, [rel str_wt_menu]
    lea  rsi, [rel wgt_menu_draw]
    lea  rdx, [rel wgt_menu_hit]
    lea  rcx, [rel wgt_label_set]
    lea  r8,  [rel wgt_label_get]
    mov  r9, (104 << 32) | 220
    call wgt_type_register
    mov  [rel wgt_menu_type], eax
    call ts_kat                             ; UI wave 2 B6b/B6c state KAT
    ret

; wgt_tabstrip_release_window(EDI=slot) -- B7a (2026-09-30, usage suite ROB-06/
; STM-04): a closed window's tab-strip instances return to the TS_MAX_INST pool.
; Without this every close/relaunch of a chrome=tabs window leaked one instance,
; and a recycled widget id in the same slot (same WGI_ID storage) could rebind a
; dead window's tab state. Clobbers RAX, RCX, RDX.
wgt_tabstrip_release_window:
    cmp  edi, WM_MAX
    jae  .rel_scan
    mov  eax, edi
    lea  rcx, [rel wm_app_title]
    mov  qword [rcx + rax*8], 0         ; T4: the slot's next window starts on wm_title
.rel_scan:
    lea  rax, [rel ts_inst]
    mov  ecx, TS_MAX_INST
.rel_loop:
    cmp  dword [rax + TS_WID], -1
    je   .rel_next
    cmp  [rax + TS_WIN], edi
    jne  .rel_next
    mov  dword [rax + TS_WID], -1
.rel_next:
    add  rax, TS_SZ
    dec  ecx
    jnz  .rel_loop
    ret

; ts_bind(edi=widget id) -> R12 = instance (allocated/rebound lazily), RBX =
; widget ptr. CF=1 when no instance is free. Clobbers rax/rcx/rdx/rsi/rdi.
ts_bind:
    push rdi
    call wgt_slot_ptr
    mov  rbx, rax
    pop  rdi
    lea  r12, [rel ts_inst]
    mov  ecx, TS_MAX_INST
.find:
    cmp  [r12 + TS_WID], edi
    jne  .find_next
    mov  eax, [rbx + WGI_WIN]
    cmp  [r12 + TS_WIN], eax
    jne  .rebind
    mov  rax, [rbx + WGI_ID]
    cmp  [r12 + TS_BIRTH], rax
    jne  .rebind
    clc
    ret
.find_next:
    add  r12, TS_SZ
    loop .find
    lea  r12, [rel ts_inst]
    mov  ecx, TS_MAX_INST
.free:
    cmp  dword [r12 + TS_WID], -1
    je   .rebind
    add  r12, TS_SZ
    loop .free
    stc
    ret
.rebind:
    ; fresh state: one tab titled by the widget text, the window's menu bound
    mov  [r12 + TS_WID], edi
    mov  eax, [rbx + WGI_WIN]
    mov  [r12 + TS_WIN], eax
    mov  rax, [rbx + WGI_ID]
    mov  [r12 + TS_BIRTH], rax
    mov  dword [r12 + TS_COUNT], 1
    mov  dword [r12 + TS_ACTIVE], 0
    mov  dword [r12 + TS_FIRST], 0
    mov  dword [r12 + TS_NEXTN], 2
    mov  dword [r12 + TS_EV_KIND], TS_EV_NONE
    mov  dword [r12 + TS_EV_INDEX], 0
    mov  dword [r12 + TS_EV_SEQ], 0
    mov  dword [r12 + TS_TAGSEQ], 1         ; B5: the first tab is tag 1
    mov  dword [r12 + TS_TAGS], 1
    mov  eax, [rbx + WGI_WIN]
    cmp  eax, WM_MAX
    jae  .no_host_label
    lea  rcx, [rel wm_app_title]
    mov  qword [rcx + rax*8], 0         ; T4: one fresh tab = the window's own title
.no_host_label:
    lea  rsi, [rbx + WGI_VAL]
    lea  rdi, [r12 + TS_BASE]
    call ts_copy_title
    lea  rsi, [rbx + WGI_VAL]
    lea  rdi, [r12 + TS_TITLES]
    call ts_copy_title
    call ts_find_menu
    mov  [r12 + TS_MENU], eax
    clc
    ret

; ts_copy_title(rsi=src cstr, rdi=dst TS_TITLE_MAX) — '_' becomes ' '.
ts_copy_title:
    mov  ecx, TS_TITLE_MAX - 1
.loop:
    mov  al, [rsi]
    test al, al
    jz   .end
    cmp  al, '_'
    jne  .store
    mov  al, ' '
.store:
    mov  [rdi], al
    inc  rsi
    inc  rdi
    loop .loop
.end:
    mov  byte [rdi], 0
    ret

; ts_find_menu(RBX=tabstrip widget) -> EAX = menu widget id in the same window or -1
ts_find_menu:
    push rbx
    push r13
    mov  r13d, [rbx + WGI_WIN]
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel wgt_count]
    jae  .none
    imul rax, rcx, WGI_SZ
    lea  rdx, [rel wgt_tbl]
    add  rdx, rax
    mov  eax, [rel wgt_menu_type]
    inc  eax
    cmp  [rdx + WGI_TYPE], eax
    jne  .next
    cmp  [rdx + WGI_WIN], r13d
    jne  .next
    mov  dword [rdx + WGI_LAYER], 1     ; the flyout always paints above windows
    mov  dword [rdx + WGI_SEL_LO], 0    ; closed
    mov  eax, ecx
    jmp  .out
.next:
    inc  ecx
    jmp  .scan
.none:
    mov  eax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ts_layout(R12=inst, RBX=widget) -> ECX = tab width, EDX = visible tabs,
; updates TS_FIRST so the active tab is visible. Clobbers rax.
ts_layout:
    mov  eax, [rbx + WGI_W]
    sub  eax, TS_TAB_LEFT + TS_BTN_W * 3   ; + and v, and room for the overflow button
    jg   .avail
    mov  eax, TS_TAB_MIN
.avail:
    mov  r8d, eax                          ; avail
    mov  ecx, TS_TAB_W
    mov  eax, [r12 + TS_COUNT]
    imul eax, ecx
    cmp  eax, r8d
    jbe  .widths_ok
    mov  eax, r8d
    xor  edx, edx
    div  dword [r12 + TS_COUNT]
    mov  ecx, eax
    cmp  ecx, TS_TAB_MIN
    jae  .widths_ok
    mov  ecx, TS_TAB_MIN
.widths_ok:
    mov  eax, r8d
    xor  edx, edx
    div  ecx
    mov  edx, eax                          ; tabs that fit
    cmp  edx, [r12 + TS_COUNT]
    jbe  .fit
    mov  edx, [r12 + TS_COUNT]
.fit:
    test edx, edx
    jnz  .first
    mov  edx, 1
.first:
    mov  eax, [r12 + TS_ACTIVE]
    cmp  eax, [r12 + TS_FIRST]
    jae  .not_before
    mov  [r12 + TS_FIRST], eax
.not_before:
    mov  eax, [r12 + TS_FIRST]
    add  eax, edx
    cmp  [r12 + TS_ACTIVE], eax
    jb   .clamp
    mov  eax, [r12 + TS_ACTIVE]
    sub  eax, edx
    inc  eax
    mov  [r12 + TS_FIRST], eax
.clamp:
    mov  eax, [r12 + TS_COUNT]
    sub  eax, edx
    cmp  [r12 + TS_FIRST], eax
    jbe  .out
    mov  [r12 + TS_FIRST], eax
.out:
    ret

; ts_strip_bg(RBX=widget) -> EAX = the title strip token behind the widget
ts_strip_bg:
    mov  eax, GUI_TOK_TITLE_UNFOCUSED
    mov  ecx, [rbx + WGI_WIN]
    cmp  ecx, [rel wm_focus]
    jne  .out
    mov  eax, GUI_TOK_TITLE_FOCUSED
.out:
    ret

; ---------------------------------------------------------------------------
wgt_tabstrip_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    call ts_bind
    jc   .out
    call ts_layout
    mov  r13d, ecx                          ; tab width
    mov  r14d, edx                          ; visible
    call ts_strip_bg
    mov  ebp, eax                           ; strip colour
    xor  r15d, r15d                         ; visible ordinal
.tab:
    cmp  r15d, r14d
    jae  .buttons
    mov  eax, [r12 + TS_FIRST]
    add  eax, r15d
    mov  r9d, eax                           ; tab index (kept in r9 across the call)
    mov  r8d, r15d
    imul r8d, r13d
    add  r8d, [rbx + WGI_X]
    add  r8d, TS_TAB_LEFT
    mov  edi, r9d
    call ts_draw_tab
    inc  r15d
    jmp  .tab
.buttons:
    ; x after the visible tabs
    mov  r8d, r14d
    imul r8d, r13d
    add  r8d, [rbx + WGI_X]
    add  r8d, TS_TAB_LEFT + 2
    mov  eax, [r12 + TS_COUNT]
    cmp  eax, r14d
    jbe  .plus
    ; overflow button: three AA dots
    mov  r9d, [rbx + WGI_Y]
    add  r9d, TS_TEXT_Y
    push r8
    add  r8d, 2
    mov  ebx, TS_COL_GLYPH
    mov  ecx, ebp
    lea  rdi, [rel str_ts_overflow]
    mov  r11d, 3
    call fb_draw_str_aa_n
    pop  r8
    mov  edi, [r12 + TS_WID]
    push r8
    call wgt_slot_ptr
    mov  rbx, rax
    pop  r8
    add  r8d, TS_BTN_W
.plus:
    ; + : 10 px cross at +16, y+19
    push r8
    add  r8d, 16
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 23
    mov  r10d, 10
    mov  r11d, 1
    push rbx
    mov  ebx, TS_COL_GLYPH
    call fb_fill_rect
    add  r8d, 4
    sub  r9d, 4
    mov  r10d, 1
    mov  r11d, 10
    call fb_fill_rect
    pop  rbx
    pop  r8
    ; divider between + and v
    add  r8d, TS_BTN_W
    push r8
    dec  r8d
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 15
    mov  r10d, 1
    mov  r11d, 12
    push rbx
    mov  ebx, TS_COL_DIVIDER
    call fb_fill_rect
    pop  rbx
    pop  r8
    ; v : 8x4 chevron at +9, y+22
    add  r8d, 9
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 22
    mov  r10d, 1
    mov  r11d, 1
    push rbx
    mov  ebx, TS_COL_GLYPH
    xor  ecx, ecx
.chev:
    push r8
    push r9
    add  r8d, ecx
    mov  eax, ecx
    cmp  eax, 4
    jb   .chev_down
    mov  eax, 7
    sub  eax, ecx
.chev_down:
    add  r9d, eax
    call fb_fill_rect
    pop  r9
    pop  r8
    inc  ecx
    cmp  ecx, 8
    jb   .chev
    pop  rbx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ts_draw_tab(edi=index, r8d=x, R12=inst, RBX=widget, r13d=tab width, ebp=strip)
ts_draw_tab:
    push rbx
    push r14
    push r15
    mov  r15d, edi
    mov  r14d, ebp                           ; this tab's fill (strip when inactive)
    cmp  edi, [r12 + TS_ACTIVE]
    jne  .content
    ; active tab: body colour from the tab top through the separator row,
    ; top corners rounded (row insets 3,2,1,1).
    mov  r14d, GUI_TOK_WINDOW_BODY
    mov  r9d, [rbx + WGI_Y]
    add  r9d, TS_TAB_TOP
    xor  ecx, ecx
.round:
    lea  rax, [rel ts_round_inset]
    movzx eax, byte [rax + rcx]
    push r8
    add  r8d, eax
    mov  r10d, r13d
    sub  r10d, eax
    sub  r10d, eax
    mov  r11d, 1
    push rbx
    mov  ebx, r14d
    call fb_fill_rect
    pop  rbx
    pop  r8
    inc  r9d
    inc  ecx
    cmp  ecx, 4
    jb   .round
    mov  r10d, r13d
    mov  r11d, [rbx + WGI_Y]
    add  r11d, [rbx + WGI_H]
    sub  r11d, r9d
    push rbx
    mov  ebx, r14d
    call fb_fill_rect
    pop  rbx
    jmp  .content
.content:
    ; divider on the right of an inactive tab that is not next to the active one
    cmp  r15d, [r12 + TS_ACTIVE]
    je   .icon
    mov  eax, r15d
    inc  eax
    cmp  eax, [r12 + TS_ACTIVE]
    je   .icon
    push r8
    add  r8d, r13d
    dec  r8d
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 14
    mov  r10d, 1
    mov  r11d, 16
    push rbx
    mov  ebx, TS_COL_DIVIDER
    call fb_fill_rect
    pop  rbx
    pop  r8
.icon:
    ; terminal icon: 16x12 accent tile with a white prompt chevron
    push r8
    add  r8d, TS_ICON_X
    mov  r9d, [rbx + WGI_Y]
    add  r9d, TS_ICON_Y + 1
    mov  r10d, 16
    mov  r11d, 12
    push rbx
    mov  ebx, TS_COL_ICON
    call fb_fill_rect
    mov  ebx, 0x00FFFFFF
    mov  r10d, 1
    mov  r11d, 1
    xor  ecx, ecx
.prompt:
    push r8
    push r9
    add  r8d, 3
    add  r8d, ecx
    add  r9d, 3
    mov  eax, ecx
    cmp  eax, 3
    jb   .prompt_down
    mov  eax, 6
    sub  eax, ecx
.prompt_down:
    add  r9d, eax
    call fb_fill_rect
    pop  r9
    pop  r8
    inc  ecx
    cmp  ecx, 7
    jb   .prompt
    push r8
    push r9
    add  r8d, 9
    add  r9d, 8
    mov  r10d, 4
    call fb_fill_rect
    pop  r9
    pop  r8
    pop  rbx
    pop  r8
    ; title (AA), cells up to the close glyph
    push r8
    add  r8d, TS_TEXT_X
    mov  r9d, [rbx + WGI_Y]
    add  r9d, TS_TEXT_Y
    mov  eax, r13d
    sub  eax, TS_TEXT_X + TS_CLOSE_DX + 4
    jle  .no_text
    xor  edx, edx
    mov  ecx, FONT_AA_W
    div  ecx
    mov  r11d, eax
    mov  eax, r15d
    imul eax, eax, TS_TITLE_MAX
    push rsi
    push rdx
    sub  rsp, TS_TITLE_DISP_MAX
    lea  rsi, [r12 + TS_TITLES + rax]
    mov  rdi, rsp
    mov  edx, TS_TITLE_MAX
    mov  ecx, TS_TITLE_DISP_MAX
    call sec_text_escape                ; RCQ-38 L3a (rc-sec N1): a tab title is a window title
    push rbx
    mov  ebx, TS_COL_TEXT
    cmp  r15d, [r12 + TS_ACTIVE]
    jne  .text_col
    mov  ebx, TS_COL_ACTIVE_TEXT
.text_col:
    mov  ecx, r14d
    call fb_draw_str_aa_n
    pop  rbx
    add  rsp, TS_TITLE_DISP_MAX
    pop  rdx
    pop  rsi
.no_text:
    pop  r8
    ; close glyph: 9 px diagonals
    push r8
    add  r8d, r13d
    sub  r8d, TS_CLOSE_DX
    mov  r9d, [rbx + WGI_Y]
    add  r9d, TS_CLOSE_Y
    mov  r10d, 1
    mov  r11d, 1
    push rbx
    mov  ebx, TS_COL_GLYPH
    xor  ecx, ecx
.x:
    push r8
    add  r8d, ecx
    call fb_fill_rect
    pop  r8
    push r8
    add  r8d, TS_GLYPH - 1
    sub  r8d, ecx
    call fb_fill_rect
    pop  r8
    inc  r9d
    inc  ecx
    cmp  ecx, TS_GLYPH
    jb   .x
    pop  rbx
    pop  r8
    pop  r15
    pop  r14
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; wgt_tabstrip_hit(edi=id, esi=px, edx=py) -> EAX 1 = an interactive part was
; pressed and handled, 0 = empty strip (the WM's drag area).
wgt_tabstrip_hit:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r15d, esi
    mov  ebp, edx
    call ts_bind
    jc   .miss
    ; inside the widget rect?
    mov  eax, [rbx + WGI_Y]
    add  eax, TS_TAB_TOP
    cmp  ebp, eax
    jl   .miss
    mov  eax, [rbx + WGI_Y]
    add  eax, [rbx + WGI_H]
    cmp  ebp, eax
    jge  .miss
    call ts_layout
    mov  r13d, ecx
    mov  r14d, edx
    mov  eax, r15d
    sub  eax, [rbx + WGI_X]
    sub  eax, TS_TAB_LEFT
    jl   .miss
    mov  ecx, r14d
    imul ecx, r13d
    cmp  eax, ecx
    jge  .after_tabs
    xor  edx, edx
    div  r13d                               ; eax = visible ordinal, edx = x in tab
    add  eax, [r12 + TS_FIRST]
    cmp  byte [rel ts_hit_middle], 0
    jne  .close_tab                         ; G11: a middle press anywhere on a tab closes it
    mov  ecx, r13d
    sub  ecx, TS_CLOSE_DX + 4
    cmp  edx, ecx
    jb   .select
    mov  ecx, r13d
    sub  ecx, TS_CLOSE_DX - TS_GLYPH - 4
    cmp  edx, ecx
    jae  .select
.close_tab:
    ; SEC-winmove (C2) (rc-sec 15:33:38): closing a tab (its x, or a middle
    ; press) is a window action on the strip's window. This hit runs only inside
    ; wm_pointer_event's dispatch, so the current pointer event's origin is
    ; asked: an injected press in a window the injector may not act on is
    ; consumed before any state change (no event, no removal, no
    ; ts_close_request). Selecting a tab stays any origin.
    push rax
    mov  edi, [rbx + WGI_WIN]
    call wm_pointer_act_ok
    test eax, eax
    pop  rax
    jnz  .handled
    mov  edi, eax
    mov  esi, TS_EV_CLOSE
    call ts_event
    cmp  dword [r12 + TS_COUNT], 1
    ja   .close_one
    ; B6d (2026-09-30, usage suite TAB-04): closing the LAST tab closes the
    ; window (Windows Terminal). The widget only records the request; the WM
    ; pointer path that dispatched this hit performs wmx_close_slot after the
    ; dispatch returns (never while this widget and its instance are in use).
    mov  eax, [rbx + WGI_WIN]
    mov  [rel ts_close_request], eax
    jmp  .handled
.close_one:
    call ts_remove_tab
    jmp  .handled
.select:
    mov  [r12 + TS_ACTIVE], eax
    mov  edi, eax
    mov  esi, TS_EV_SELECT
    call ts_event
    jmp  .handled
.after_tabs:
    cmp  byte [rel ts_hit_middle], 0
    jne  .miss                              ; middle press: only tabs react
    sub  eax, ecx                           ; x after the tabs
    sub  eax, 2
    jl   .miss
    mov  ecx, [r12 + TS_COUNT]
    cmp  ecx, r14d
    jbe  .no_overflow
    cmp  eax, TS_BTN_W
    jge  .past_overflow
    ; overflow: step the view right, wrapping to the first tab
    mov  eax, [r12 + TS_ACTIVE]
    inc  eax
    cmp  eax, [r12 + TS_COUNT]
    jb   .ov_set
    xor  eax, eax
.ov_set:
    mov  [r12 + TS_ACTIVE], eax
    mov  edi, eax
    mov  esi, TS_EV_OVERFLOW
    call ts_event
    jmp  .handled
.past_overflow:
    sub  eax, TS_BTN_W
.no_overflow:
    cmp  eax, TS_BTN_W
    jge  .dropdown
    ; + new tab
    mov  eax, [r12 + TS_COUNT]
    cmp  eax, TS_MAX_TABS
    jae  .handled
    call ts_new_tab
    jmp  .handled
.dropdown:
    cmp  eax, TS_BTN_W * 2
    jge  .miss
    mov  eax, [r12 + TS_MENU]
    cmp  eax, -1
    je   .handled
    mov  edi, eax
    call wgt_slot_ptr
    xor  dword [rax + WGI_SEL_LO], 1        ; toggle the flyout
    mov  dword [rax + MENU_HOT], 0          ; opens (or closes) with no item highlighted
    ; anchor it under the dropdown button, kept inside the host window
    mov  ecx, r14d
    imul ecx, r13d
    add  ecx, [rbx + WGI_X]
    add  ecx, TS_TAB_LEFT + 2 + TS_BTN_W
    mov  edx, [r12 + TS_COUNT]
    cmp  edx, r14d
    jbe  .anchor_x
    add  ecx, TS_BTN_W
.anchor_x:
    mov  edx, [rbx + WGI_WIN]
    lea  rsi, [rel wm_x]
    mov  r8d, [rsi + rdx*4]
    lea  rsi, [rel wm_w]
    add  r8d, [rsi + rdx*4]
    ; 2026-09-30 (usage suite MNU-04): a host dragged past the right screen
    ; edge must not carry the flyout off-screen; the overlay gate refuses an
    ; escaped overlay, so the menu vanished. Clip the host's right edge to the
    ; framebuffer before placing the menu.
    cmp  r8d, [rel fb_width]
    jbe  .anchor_right
    mov  r8d, [rel fb_width]
.anchor_right:
    sub  r8d, [rax + WGI_W]
    dec  r8d                                ; rightmost x that keeps it inside
    cmp  ecx, r8d
    jle  .anchor_set
    mov  ecx, r8d
.anchor_set:
    mov  [rax + WGI_X], ecx
    mov  ecx, [rbx + WGI_Y]
    add  ecx, [rbx + WGI_H]
    add  ecx, 2
    mov  [rax + WGI_Y], ecx
    xor  edi, edi
    mov  esi, TS_EV_MENU
    call ts_event
.handled:
    call ts_sync_host_label
    call wmx_draw_all
    mov  eax, 1
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; wgt_tabstrip_middle(EDI=window slot, ESI=x, EDX=y) -> EAX=1 when a middle
;   press landed on a tab of the window's tab strip and closed it (Windows
;   Terminal / browsers; G11, usage suite TAB-07), else 0. The same transition
;   as the tab's x: the last tab records ts_close_request and the WM pointer
;   path closes the window after this returns. Preserves RBX, R12-R15.
wgt_tabstrip_middle:
    push rsi
    push rdx
    call wgt_tabstrip_state                 ; RAX = bound instance or 0 (clobbers RCX)
    pop  rdx
    pop  rsi
    test rax, rax
    jz   .no
    mov  edi, [rax + TS_WID]
    mov  byte [rel ts_hit_middle], 1
    call wgt_tabstrip_hit
    mov  byte [rel ts_hit_middle], 0
    ret
.no:
    xor  eax, eax
    ret

; wgt_tabstrip_key(EDI=window slot, ESI=TS_KEY_*) -> EAX=1 when the window
;   owns a bound tab strip and the action ran, else 0 (the key is not consumed).
;   G3 (2026-09-30, usage suite TAB-06): Ctrl+T new tab, Ctrl+Tab / Ctrl+Shift+Tab
;   next / previous tab, Ctrl+W close the active tab (the last tab closes the
;   window, like its x). The same state transitions as the pointer parts
;   (ts_new_tab / ts_remove_tab / select). Called from the input-route tick,
;   never inside a widget dispatch, so closing the window here is safe.
;   Preserves RBX, R12-R15.
wgt_tabstrip_key:
    push rbx
    push r12
    push r13
    mov  r13d, esi
    cmp  edi, WM_MAX
    jae  .no
    mov  ebx, edi                           ; slot
    call wgt_tabstrip_state                 ; RAX = bound instance or 0 (clobbers RCX)
    test rax, rax
    jz   .no
    mov  r12, rax
    cmp  dword [r12 + TS_COUNT], 0
    je   .no
    cmp  r13d, TS_KEY_NEW
    je   .new
    cmp  r13d, TS_KEY_NEXT
    je   .next
    cmp  r13d, TS_KEY_PREV
    je   .prev
    cmp  r13d, TS_KEY_CLOSE
    jne  .no
    cmp  dword [r12 + TS_COUNT], 1
    ja   .close_one
    mov  edi, [r12 + TS_ACTIVE]
    mov  esi, TS_EV_CLOSE
    call ts_event
    mov  edi, ebx
    call wmx_close_slot                     ; last tab: the window closes
    jmp  .yes
.close_one:
    mov  edi, [r12 + TS_ACTIVE]
    mov  esi, TS_EV_CLOSE
    call ts_event
    mov  eax, [r12 + TS_ACTIVE]
    call ts_remove_tab
    jmp  .done
.new:
    cmp  dword [r12 + TS_COUNT], TS_MAX_TABS
    jae  .done                              ; full: consumed, nothing to add (as "+")
    call ts_new_tab
    jmp  .done
.next:
    mov  eax, [r12 + TS_ACTIVE]
    inc  eax
    cmp  eax, [r12 + TS_COUNT]
    jb   .select
    xor  eax, eax
    jmp  .select
.prev:
    mov  eax, [r12 + TS_ACTIVE]
    test eax, eax
    jnz  .prev_dec
    mov  eax, [r12 + TS_COUNT]
.prev_dec:
    dec  eax
.select:
    mov  [r12 + TS_ACTIVE], eax
    mov  edi, eax
    mov  esi, TS_EV_SELECT
    call ts_event
.done:
    call ts_sync_host_label
    call wmx_draw_all
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ts_sync_host_label(R12=inst) -- T4 (2026-09-30, usage suite TAB-08): the
; host window's shell label (taskbar button + TASKBAR readout) follows the
; ACTIVE tab, as in Windows Terminal. While the active tab is the base tab the
; app title is cleared, so a one-tab window keeps exactly its declared title;
; otherwise the active tab's title is published with ' ' stored as '_' (the
; form-title convention the painters render back as spaces). wm_title (the
; window's identity) is never touched. Clobbers RAX, RCX, RDX, RSI, RDI.
ts_sync_host_label:
    mov  edx, [r12 + TS_WIN]
    cmp  edx, WM_MAX
    jae  .out
    mov  eax, [r12 + TS_ACTIVE]
    cmp  eax, [r12 + TS_COUNT]
    jae  .out
    imul eax, eax, TS_TITLE_MAX
    lea  rsi, [r12 + TS_TITLES + rax]
    lea  rdi, [r12 + TS_BASE]
    xor  ecx, ecx
.cmp:
    mov  al, [rsi + rcx]
    cmp  al, [rdi + rcx]
    jne  .publish
    test al, al
    jz   .base
    inc  ecx
    cmp  ecx, TS_TITLE_MAX
    jb   .cmp
.base:
    lea  rcx, [rel wm_app_title]
    mov  qword [rcx + rdx*8], 0
.out:
    ret
.publish:
    lea  rdi, [r12 + TS_HOST]
    xor  ecx, ecx
.copy:
    mov  al, [rsi + rcx]
    cmp  al, ' '
    jne  .store
    mov  al, '_'
.store:
    mov  [rdi + rcx], al
    test al, al
    jz   .set
    inc  ecx
    cmp  ecx, TS_TITLE_MAX - 1
    jb   .copy
    mov  byte [rdi + rcx], 0
.set:
    lea  rcx, [rel wm_app_title]
    mov  [rcx + rdx*8], rdi
    ret

; ts_event(edi=index, esi=kind, R12=inst)
ts_event:
    mov  [r12 + TS_EV_KIND], esi
    mov  [r12 + TS_EV_INDEX], edi
    inc  dword [r12 + TS_EV_SEQ]
    ret

; ts_new_tab(R12=inst): "<bound base title> <n>" (UI wave 2 B6c: the base is
; TS_BASE, not whatever tab 0 is now; n is decimal 1-3 digits, clamped at 999),
; becomes active. The caller bounds TS_COUNT < TS_MAX_TABS. Clobbers rax, rcx,
; rdx, rsi, rdi, r8.
ts_new_tab:
    mov  eax, [r12 + TS_COUNT]
    imul eax, eax, TS_TITLE_MAX
    lea  rdi, [r12 + TS_TITLES + rax]
    lea  rsi, [r12 + TS_BASE]
    mov  ecx, TS_TITLE_MAX - 5              ; room for " 999" + NUL
.copy:
    mov  al, [rsi]
    test al, al
    jz   .num
    mov  [rdi], al
    inc  rsi
    inc  rdi
    loop .copy
.num:
    mov  byte [rdi], ' '
    inc  rdi
    mov  eax, [r12 + TS_NEXTN]
    cmp  eax, 999
    jbe  .utoa
    mov  eax, 999
.utoa:
    ; local 3-digit utoa: digits pushed low-first, stored high-first
    xor  r8d, r8d                            ; digit count
    mov  ecx, 10
.div:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    push rdx
    inc  r8d
    test eax, eax
    jnz  .div
.store:
    pop  rdx
    mov  [rdi], dl
    inc  rdi
    dec  r8d
    jnz  .store
    mov  byte [rdi], 0
    cmp  dword [r12 + TS_NEXTN], 999
    jae  .nextn_kept
    inc  dword [r12 + TS_NEXTN]
.nextn_kept:
    inc  dword [r12 + TS_TAGSEQ]            ; B5: a fresh identity for the new tab
    jnz  .tag_ok
    inc  dword [r12 + TS_TAGSEQ]            ; never issue tag 0 (0 = no tab)
.tag_ok:
    mov  eax, [r12 + TS_COUNT]
    mov  ecx, [r12 + TS_TAGSEQ]
    mov  [r12 + TS_TAGS + rax*4], ecx
    mov  [r12 + TS_ACTIVE], eax
    inc  dword [r12 + TS_COUNT]
    mov  edi, eax
    mov  esi, TS_EV_NEW
    call ts_event
    ret

; ts_remove_tab(eax=index, R12=inst). UI wave 2 B6b: the active tab keeps
; pointing at the same tab when one to its LEFT closes; active and the first
; visible tab are then clamped to the shrunk count. Clobbers rax, rcx, rdx,
; rsi, rdi, r8 (r8 is dead in the caller: ts_layout clobbers it).
ts_remove_tab:
    mov  r8d, eax                            ; removed index
    mov  ecx, eax                            ; index
.shift:
    mov  edx, ecx
    inc  edx
    cmp  edx, [r12 + TS_COUNT]
    jae  .shrunk
    imul eax, edx, TS_TITLE_MAX
    lea  rsi, [r12 + TS_TITLES + rax]
    imul eax, ecx, TS_TITLE_MAX
    lea  rdi, [r12 + TS_TITLES + rax]
    push rcx
    mov  ecx, TS_TITLE_MAX
    rep  movsb
    pop  rcx
    mov  eax, [r12 + TS_TAGS + rdx*4]       ; B5: the tag moves with its tab
    mov  [r12 + TS_TAGS + rcx*4], eax
    inc  ecx
    jmp  .shift
.shrunk:
    dec  dword [r12 + TS_COUNT]
    mov  eax, [r12 + TS_ACTIVE]
    cmp  r8d, eax
    jae  .clamp
    dec  eax                                 ; follow the same tab
    mov  [r12 + TS_ACTIVE], eax
.clamp:
    mov  eax, [r12 + TS_COUNT]
    cmp  [r12 + TS_ACTIVE], eax
    jb   .first
    dec  eax
    mov  [r12 + TS_ACTIVE], eax
.first:
    mov  eax, [r12 + TS_FIRST]
    test eax, eax
    jz   .out
    cmp  eax, [r12 + TS_COUNT]
    jb   .out
    dec  dword [r12 + TS_FIRST]
.out:
    ret

; ts_kat — UI wave 2 B6b/B6c boot KAT. State only: a scratch instance that is
; never in ts_inst, no widget, no pixels (E2-safe). Serial
; "[gui.tabstrip.kat] ok" or "[gui.tabstrip.kat.fail] stage=<n>".
;   1  new,new, select 1, remove 0 -> count 2, active 0, title[0]="PaOS Console 2"
;   2  remove 0, new               -> title[1]="PaOS Console 4" (base, not tab 0)
;   3  8x (remove 0, new)          -> title[1]="PaOS Console 12" (no 9 cap)
;   4  NEXTN=999, new              -> "PaOS Console 999", NEXTN stays 999
;   5  first=2 active=2, remove 2  -> active 1, first 1
; Clobbers caller-saved; preserves rbx/r12.
ts_kat:
    push rbx
    push r12
    lea  r12, [rel ts_kat_inst]
    mov  dword [r12 + TS_WID], -1
    mov  dword [r12 + TS_WIN], -1
    mov  dword [r12 + TS_COUNT], 1
    mov  dword [r12 + TS_ACTIVE], 0
    mov  dword [r12 + TS_FIRST], 0
    mov  dword [r12 + TS_NEXTN], 2
    mov  dword [r12 + TS_MENU], -1
    mov  dword [r12 + TS_TAGSEQ], 1
    mov  dword [r12 + TS_TAGS], 1
    lea  rsi, [rel str_ts_kat_base]
    lea  rdi, [r12 + TS_BASE]
    call ts_copy_title
    lea  rsi, [rel str_ts_kat_base]
    lea  rdi, [r12 + TS_TITLES]
    call ts_copy_title
    mov  ebx, 1
    call ts_new_tab
    call ts_new_tab
    mov  dword [r12 + TS_ACTIVE], 1
    xor  eax, eax
    call ts_remove_tab
    cmp  dword [r12 + TS_COUNT], 2
    jne  .fail
    cmp  dword [r12 + TS_ACTIVE], 0
    jne  .fail
    cmp  dword [r12 + TS_TAGS], 2           ; B5: tags 1,2,3 -> remove tab 0 -> 2,3
    jne  .fail
    cmp  dword [r12 + TS_TAGS + 4], 3
    jne  .fail
    lea  rdi, [r12 + TS_TITLES]
    lea  rsi, [rel str_ts_kat_t2]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  ebx, 2
    xor  eax, eax
    call ts_remove_tab
    call ts_new_tab
    lea  rdi, [r12 + TS_TITLES + TS_TITLE_MAX]
    lea  rsi, [rel str_ts_kat_t4]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  ebx, 3
    push r13
    mov  r13d, 8
.cycle:
    xor  eax, eax
    call ts_remove_tab
    call ts_new_tab
    dec  r13d
    jnz  .cycle
    pop  r13
    cmp  dword [r12 + TS_COUNT], 2
    jne  .fail
    cmp  dword [r12 + TS_ACTIVE], 1
    jne  .fail
    lea  rdi, [r12 + TS_TITLES + TS_TITLE_MAX]
    lea  rsi, [rel str_ts_kat_t12]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  ebx, 4
    mov  dword [r12 + TS_NEXTN], 999
    call ts_new_tab
    cmp  dword [r12 + TS_NEXTN], 999
    jne  .fail
    lea  rdi, [r12 + TS_TITLES + TS_TITLE_MAX * 2]
    lea  rsi, [rel str_ts_kat_t999]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  ebx, 5
    cmp  dword [r12 + TS_COUNT], 3
    jne  .fail
    mov  dword [r12 + TS_FIRST], 2
    mov  dword [r12 + TS_ACTIVE], 2
    mov  eax, 2
    call ts_remove_tab
    cmp  dword [r12 + TS_ACTIVE], 1
    jne  .fail
    cmp  dword [r12 + TS_FIRST], 1
    jne  .fail
    lea  rdi, [rel str_ts_kat_ok]
    call serial_string
    mov  byte [rel ts_kat_ok], 1
    jmp  .out
.fail:
    lea  rdi, [rel str_ts_kat_fail]
    call serial_string
    lea  eax, [ebx + '0']
    mov  [rel ts_kat_stage], al
    lea  rdi, [rel ts_kat_stage]
    call serial_string
    call serial_newline
.out:
    pop  r12
    pop  rbx
    ret

; wgt_tabstrip_state(edi=host slot) -> RAX = instance pointer (TS_* layout) or 0.
; The adoption seam for apps: count, active, titles and the last event+seq.
wgt_tabstrip_state:
    lea  rax, [rel ts_inst]
    mov  ecx, TS_MAX_INST
.scan:
    cmp  dword [rax + TS_WID], -1
    je   .next
    cmp  [rax + TS_WIN], edi
    je   .out
.next:
    add  rax, TS_SZ
    loop .scan
    xor  eax, eax
.out:
    ret

; wgt_tabstrip_active_tag(EDI=host slot) -> EAX = stable tag of the active tab
;   (0 = the slot has no bound tab strip), ECX = tab count. B5 (usage suite
;   TAB-02/TAB-03): the identity an app keys its per-tab content on; tags follow
;   their tab across closes and are never reused while the strip is bound.
;   Clobbers RDX.
wgt_tabstrip_active_tag:
    call wgt_tabstrip_state
    test rax, rax
    jz   .none
    mov  ecx, [rax + TS_COUNT]
    mov  edx, [rax + TS_ACTIVE]
    cmp  edx, ecx
    jae  .none
    cmp  edx, TS_MAX_TABS
    jae  .none
    mov  eax, [rax + TS_TAGS + rdx*4]
    ret
.none:
    xor  eax, eax
    xor  ecx, ecx
    ret

; wgt_tabstrip_has_tag(EDI=host slot, ESI=tag) -> EAX = 1 when a present tab of
;   the slot's strip carries the tag, else 0. Clobbers RCX, RDX.
wgt_tabstrip_has_tag:
    call wgt_tabstrip_state
    test rax, rax
    jz   .no
    test esi, esi
    jz   .no
    mov  ecx, [rax + TS_COUNT]
    cmp  ecx, TS_MAX_TABS
    jbe  .bounded
    mov  ecx, TS_MAX_TABS
.bounded:
    xor  edx, edx
.scan:
    cmp  edx, ecx
    jae  .no
    cmp  [rax + TS_TAGS + rdx*4], esi
    je   .yes
    inc  edx
    jmp  .scan
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; menu: paints only while open (WGI_SEL_LO = 1); items from WGI_VAL.
wgt_menu_draw:
    push rbx
    push r12
    push r13
    push r14
    call wgt_slot_ptr
    mov  rbx, rax
    mov  dword [rbx + WGI_LAYER], 1
    cmp  dword [rbx + WGI_SEL_LO], 1
    jne  .out
    ; flyout body + 1 px border
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    push rbx
    mov  ebx, MENU_BORDER
    call fb_fill_rect
    pop  rbx
    inc  r8d
    inc  r9d
    sub  r10d, 2
    sub  r11d, 2
    push rbx
    mov  ebx, MENU_BG
    call fb_fill_rect
    pop  rbx
    ; items: the same count the hit test bounds by (menu_item_count)
    mov  rax, rbx
    call menu_item_count
    mov  r14d, r8d
    lea  r12, [rbx + WGI_VAL]
    xor  r13d, r13d
.item:
    cmp  r13d, r14d
    jae  .out
    cmp  byte [r12], 0
    je   .out
    ; copy one item into menu_item_buf ('_' -> ' ')
    lea  rdi, [rel menu_item_buf]
    mov  ecx, TS_TITLE_MAX - 1
.copy:
    mov  al, [r12]
    test al, al
    jz   .copied
    inc  r12
    cmp  al, '|'
    je   .copied
    cmp  al, '_'
    jne  .store
    mov  al, ' '
.store:
    mov  [rdi], al
    inc  rdi
    loop .copy
.copied:
    mov  byte [rdi], 0
    ; G3/G11 (2026-10-01, usage suite MNU-03): the highlighted item (arrow
    ; keys or pointer hover) gets the Windows 11 rounded-row fill.
    mov  ecx, MENU_BG
    mov  eax, [rbx + MENU_HOT]
    dec  eax
    cmp  eax, r13d
    jne  .text
    mov  r8d, [rbx + WGI_X]
    add  r8d, 4
    mov  r9d, r13d
    imul r9d, r9d, MENU_ITEM_H
    add  r9d, [rbx + WGI_Y]
    add  r9d, MENU_PAD + 2
    mov  r10d, [rbx + WGI_W]
    sub  r10d, 8
    mov  r11d, MENU_ITEM_H - 4
    push rbx
    mov  ebx, MENU_HOVER
    call fb_fill_rect
    pop  rbx
    mov  ecx, MENU_HOVER
.text:
    mov  r8d, [rbx + WGI_X]
    add  r8d, 12
    mov  r9d, r13d
    imul r9d, r9d, MENU_ITEM_H
    add  r9d, [rbx + WGI_Y]
    add  r9d, MENU_PAD + (MENU_ITEM_H - FONT_AA_H) / 2
    mov  r11d, [rbx + WGI_W]
    sub  r11d, 24
    shr  r11d, 3
    push rbx
    mov  ebx, MENU_TEXT
    lea  rdi, [rel menu_item_buf]
    call fb_draw_str_aa_n
    pop  rbx
    inc  r13d
    jmp  .item
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_menu_hit(edi=id, esi=px, edx=py) -> 1 when the press lands inside an open
; menu. An item row chooses the item and closes; the pad rows and any row past
; the real item count (UI wave 2 B6a: h may exceed the items) are consumed
; with no choice and the flyout stays open -- a press inside the open flyout
; never falls through to the widgets under it. 0 = closed menu or outside.
wgt_menu_hit:
    push rbx
    mov  ebx, edx
    push rsi
    mov  [rel menu_hit_id], edi
    call wgt_slot_ptr
    pop  rsi
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .miss
    mov  ecx, [rax + WGI_X]
    cmp  esi, ecx
    jl   .miss
    add  ecx, [rax + WGI_W]
    cmp  esi, ecx
    jge  .miss
    mov  ecx, ebx
    sub  ecx, [rax + WGI_Y]
    jl   .miss
    cmp  ecx, [rax + WGI_H]
    jge  .miss
    sub  ecx, MENU_PAD
    jl   .consume
    push rax
    mov  eax, ecx
    xor  edx, edx
    mov  ecx, MENU_ITEM_H
    div  ecx
    mov  ecx, eax
    pop  rax
    push rax
    call menu_item_count                    ; r8d = items (the painter's rule)
    pop  rax
    cmp  ecx, r8d
    jae  .consume                           ; pad/phantom row: no choice, stays open
    mov  edi, [rel menu_hit_id]
    call menu_choose
    mov  eax, 1
    pop  rbx
    ret
.consume:
    mov  eax, 1
    pop  rbx
    ret
.miss:
    xor  eax, eax
    pop  rbx
    ret

; menu_choose(RAX=menu widget, EDI=its id, ECX=item): record the choice and
; close (the selection generation apps adopt), then repaint. B5 (2026-10-01,
; usage suite MNU-02): a tab strip's bound menu performs its "New_Tab" item
; itself, exactly like the strip's + button; every other item stays app-owned
; through the recorded selection. Clobbers caller-saved registers.
menu_choose:
    push rbx
    push r12
    mov  rbx, rax
    mov  [rbx + WGI_SEL_HI], ecx            ; chosen item
    inc  dword [rbx + WGI_SUBMITS]          ; selection generation
    mov  dword [rbx + WGI_SEL_LO], 0        ; close
    mov  dword [rbx + MENU_HOT], 0
    mov  [rel menu_last_item], ecx
    ; the item's text: skip ECX '|' separators (menu_item_count's walk)
    lea  rsi, [rbx + WGI_VAL]
.skip:
    test ecx, ecx
    jz   .item
.skip_ch:
    mov  al, [rsi]
    test al, al
    jz   .draw
    inc  rsi
    cmp  al, '|'
    jne  .skip_ch
    dec  ecx
    jmp  .skip
.item:
    lea  rdx, [rel str_menu_new_tab]
.cmp:
    mov  al, [rdx]
    test al, al
    jz   .cmp_end
    cmp  al, [rsi]
    jne  .draw
    inc  rdx
    inc  rsi
    jmp  .cmp
.cmp_end:
    mov  al, [rsi]
    test al, al
    jz   .new_tab
    cmp  al, '|'
    jne  .draw
.new_tab:
    lea  r12, [rel ts_inst]
    mov  ecx, TS_MAX_INST
.find:
    cmp  dword [r12 + TS_WID], -1
    je   .find_next
    cmp  [r12 + TS_MENU], edi
    je   .found
.find_next:
    add  r12, TS_SZ
    loop .find
    jmp  .draw
.found:
    cmp  dword [r12 + TS_COUNT], TS_MAX_TABS
    jae  .draw                              ; full: as "+", nothing to add
    call ts_new_tab
    call ts_sync_host_label
.draw:
    call wmx_draw_all
    pop  r12
    pop  rbx
    ret

; menu_open_at(EDI=window slot, -1 for any, or -2 for one that is painted:
; wgt_flyout_painted) -> RAX = the first open menu widget (hosted by that window),
; or 0; EDX = its id. Clobbers RCX, R10.
menu_open_at:
    xor  edx, edx
.scan:
    cmp  edx, [rel wgt_count]
    jae  .none
    imul rax, rdx, WGI_SZ
    lea  r10, [rel wgt_tbl]
    add  rax, r10
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .next
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .next
    cmp  edi, -1
    je   .out
    cmp  edi, -2
    jne  .host
    call wgt_flyout_painted
    jc   .next
    jmp  .out
.host:
    cmp  [rax + WGI_WIN], edi
    je   .out
.next:
    inc  edx
    jmp  .scan
.none:
    xor  eax, eax
.out:
    ret

; wgt_menu_shown_at(EDI=x, ESI=y) -> EAX = id+1 of the open flyout painted at
; the point, 0 none. Only a layer-1 flyout the overlay pass paints
; (wgt_flyout_painted) counts; ids are scanned from the highest, the overlay pass's paint order
; within one host. Clobbers RCX, RDX.
wgt_menu_shown_at:
    mov  edx, [rel wgt_count]
.scan:
    test edx, edx
    jz   .none
    dec  edx
    imul rax, rdx, WGI_SZ
    lea  rcx, [rel wgt_tbl]
    add  rax, rcx
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .scan
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .scan
    cmp  dword [rax + WGI_LAYER], 1
    jne  .scan
    test dword [rax + WGI_FLAGS], 1
    jz   .scan
    call wgt_flyout_painted
    jc   .scan
    mov  ecx, [rax + WGI_X]
    cmp  edi, ecx
    jl   .scan
    add  ecx, [rax + WGI_W]
    cmp  edi, ecx
    jge  .scan
    mov  ecx, [rax + WGI_Y]
    cmp  esi, ecx
    jl   .scan
    add  ecx, [rax + WGI_H]
    cmp  esi, ecx
    jge  .scan
    lea  eax, [rdx + 1]
    ret
.none:
    xor  eax, eax
    ret

; wgt_menu_overlay_press(EDI=x, ESI=y) -> EAX=1 when an open flyout painted at
; the point took the press. RCQ-16 F5-R1: a flyout paints in the overlay pass,
; above every window, and can escape its host's rectangle, so it owns the press
; before the window hit test (as listview dropdowns do), and the click hook
; sees it as wgt_pointer_hit_dispatch would report it. Clobbers caller-saved
; registers.
wgt_menu_overlay_press:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call wgt_menu_shown_at
    test eax, eax
    jz   .out
    lea  ebx, [rax - 1]
    mov  edi, ebx
    mov  esi, r12d
    mov  edx, r13d
    call wgt_menu_hit                       ; an item is chosen, or the pad/phantom row consumes it
    mov  rax, [rel wgt_click_hook]
    test rax, rax
    jz   .taken
    mov  edi, ebx
    call rax
.taken:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_menu_hover(EDI=x, ESI=y): pointer motion with no button. Over an item row
; of an open flyout that item is highlighted (G11 hover, usage suite MNU-03);
; leaving the flyout drops a pointer highlight (an arrow-key one stays).
; Repaints only on a change. Clobbers caller-saved registers.
wgt_menu_hover:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    mov  edi, -2                            ; F5-R1: only a flyout that is painted
    call menu_open_at
    test rax, rax
    jz   .out
    mov  rbx, rax
    xor  edx, edx                           ; new hot (0 = none)
    mov  eax, r12d
    sub  eax, [rbx + WGI_X]
    jl   .outside
    cmp  eax, [rbx + WGI_W]
    jge  .outside
    mov  eax, r13d
    sub  eax, [rbx + WGI_Y]
    cmp  eax, [rbx + WGI_H]
    jge  .outside
    sub  eax, MENU_PAD
    jl   .outside
    xor  edx, edx
    mov  ecx, MENU_ITEM_H
    div  ecx
    mov  ecx, eax
    mov  rax, rbx
    call menu_item_count                    ; r8d = items (clobbers r9, rdx)
    xor  edx, edx
    cmp  ecx, r8d
    jae  .outside
    lea  edx, [ecx + 1]
    mov  byte [rel menu_hot_pointer], 1
    jmp  .set
.outside:
    xor  edx, edx
    cmp  byte [rel menu_hot_pointer], 0
    je   .out                               ; keyboard highlight: kept
    mov  byte [rel menu_hot_pointer], 0
.set:
    cmp  [rbx + MENU_HOT], edx
    je   .out
    mov  [rbx + MENU_HOT], edx
    call wmx_draw_all
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_menu_key(EAX=GUI key) -> EAX=1 when an open flyout of the focused window
; took the key. Down/Up move the highlight (wrapping; the first Down lands on
; the first item), Enter chooses the highlighted item, Esc closes the flyout
; (G3 + B9, usage suite MNU-02/MNU-03, Windows menus). Any other key is not
; consumed. Clobbers caller-saved registers; preserves RBX, R12-R15.
wgt_menu_key:
    push rbx
    push r12
    push r13
    mov  r12d, eax
    mov  edi, [rel wm_focus]
    call menu_open_at
    test rax, rax
    jz   .no
    mov  rbx, rax
    mov  r13d, edx                          ; menu id
    call menu_item_count                    ; r8d = items
    mov  byte [rel menu_hot_pointer], 0
    cmp  r12d, GUI_KEY_ESC
    je   .close
    cmp  r12d, GUI_KEY_ENTER
    je   .enter
    test r8d, r8d
    jz   .no
    mov  eax, [rbx + MENU_HOT]
    cmp  r12d, GUI_KEY_DOWN
    je   .down
    cmp  r12d, GUI_KEY_UP
    jne  .no
    dec  eax                                ; up: 0/1 -> last
    jg   .hot
    mov  eax, r8d
    jmp  .hot
.down:
    inc  eax
    cmp  eax, r8d
    jbe  .hot
    mov  eax, 1
.hot:
    mov  [rbx + MENU_HOT], eax
    call wmx_draw_all
    jmp  .yes
.enter:
    mov  ecx, [rbx + MENU_HOT]
    dec  ecx
    js   .yes                               ; nothing highlighted: consumed, stays open
    cmp  ecx, r8d
    jae  .yes
    mov  rax, rbx
    mov  edi, r13d
    call menu_choose
    jmp  .yes
.close:
    mov  dword [rbx + WGI_SEL_LO], 0
    mov  dword [rbx + MENU_HOT], 0
    call wmx_draw_all
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; menu_item_count(RAX=menu widget) -> R8D = items in WGI_VAL ('|' separated,
; at most MENU_MAX_ITEMS), counted exactly as wgt_menu_draw walks them (an item
; is cut after TS_TITLE_MAX-1 characters). Clobbers R8, R9, RDX.
menu_item_count:
    xor  r8d, r8d
    lea  r9, [rax + WGI_VAL]
.item:
    cmp  r8d, MENU_MAX_ITEMS
    jae  .out
    cmp  byte [r9], 0
    je   .out
    inc  r8d
    mov  edx, TS_TITLE_MAX - 1
.scan:
    cmp  byte [r9], 0
    je   .item
    cmp  byte [r9], '|'
    je   .sep
    inc  r9
    dec  edx
    jnz  .scan
    jmp  .item
.sep:
    inc  r9
    jmp  .item
.out:
    ret

; wgt_menu_dismiss_outside(edi=x, esi=y): close every open flyout the press is
; outside of; repaint once. The press continues to its normal target.
wgt_menu_dismiss_outside:
    push rbx
    push r12
    xor  r12d, r12d                          ; closed any?
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel wgt_count]
    jae  .done
    imul rax, rcx, WGI_SZ
    lea  rbx, [rel wgt_tbl]
    add  rbx, rax
    mov  eax, [rel wgt_menu_type]
    inc  eax
    cmp  [rbx + WGI_TYPE], eax
    jne  .next
    cmp  dword [rbx + WGI_SEL_LO], 1
    jne  .next
    mov  eax, [rbx + WGI_X]
    cmp  edi, eax
    jl   .close
    add  eax, [rbx + WGI_W]
    cmp  edi, eax
    jge  .close
    mov  eax, [rbx + WGI_Y]
    cmp  esi, eax
    jl   .close
    add  eax, [rbx + WGI_H]
    cmp  esi, eax
    jl   .next
.close:
    ; the dropdown button toggles its own menu; leave presses on it alone
    call ts_press_on_dropdown
    test eax, eax
    jnz  .next
    mov  dword [rbx + WGI_SEL_LO], 0
    mov  dword [rbx + MENU_HOT], 0
    mov  r12d, 1
.next:
    inc  ecx
    jmp  .scan
.done:
    test r12d, r12d
    jz   .out
    call wmx_draw_all
.out:
    pop  r12
    pop  rbx
    ret

; ts_press_on_dropdown(edi=x, esi=y, RBX=menu widget) -> EAX=1 when the press
; is inside the host window's title band (where the dropdown button toggles the
; flyout itself); 0 otherwise. Preserves rcx/rdi/rsi.
ts_press_on_dropdown:
    push rcx
    mov  eax, [rbx + WGI_WIN]
    cmp  eax, WM_MAX
    jae  .no
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    cmp  esi, edx
    jl   .no
    add  edx, GUI_TITLE_H
    cmp  esi, edx
    jge  .no
    lea  rcx, [rel wm_x]
    mov  edx, [rcx + rax*4]
    cmp  edi, edx
    jl   .no
    lea  rcx, [rel wm_w]
    add  edx, [rcx + rax*4]
    cmp  edi, edx
    jge  .no
    mov  eax, 1
    pop  rcx
    ret
.no:
    xor  eax, eax
    pop  rcx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_widget_tabstrip_0 0
ts_round_inset: db 3, 2, 1, 1
str_wt_tabstrip: db "tabstrip", 0
str_wt_menu:     db "menu", 0
str_ts_overflow: db "...", 0
align 4
wgt_tabstrip_type: dd -1
wgt_menu_type:     dd -1
menu_last_item:    dd -1
menu_hit_id:       dd -1                    ; wgt_menu_hit's widget id (menu_choose)
menu_hot_pointer:  db 0                     ; 1 = the highlight follows the pointer (hover)
str_menu_new_tab:  db "New_Tab", 0
ts_close_request:  dd -1                    ; B6d: slot whose last tab was closed (-1 none), consumed by wm_pointer
ts_hit_middle:     db 0                     ; G11: wgt_tabstrip_hit runs for a middle press (tabs close)
menu_item_buf:     times TS_TITLE_MAX db 0
str_ts_kat_base:   db "PaOS_Console", 0
str_ts_kat_t2:     db "PaOS Console 2", 0
str_ts_kat_t4:     db "PaOS Console 4", 0
str_ts_kat_t12:    db "PaOS Console 12", 0
str_ts_kat_t999:   db "PaOS Console 999", 0
str_ts_kat_ok:     db "[PAOS64] tabstrip state KAT: active follows its tab on a left close, titles from the bound base [gui.tabstrip.kat] ok", 13, 10, 0
str_ts_kat_fail:   db "[PAOS64] tabstrip state KAT FAILED [gui.tabstrip.kat.fail] stage=", 0
ts_kat_stage:      db 0, 0
; ts_kat_ok..ts_kat_inst moved to WDATA_gui_widget_tabstrip_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_gui_widget_tabstrip_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_widget_tabstrip_0_bss1 0
resb 22                 ; keeps ts_kat_ok at its WDATA offset mod 64
ts_kat_ok:         resb 1
alignb 8
ts_inst:           resb (TS_MAX_INST * TS_SZ)
alignb 8
ts_kat_inst:       resb TS_SZ
%endmacro
WDATA_BSS_DEFER WDATA_gui_widget_tabstrip_0_bss1
