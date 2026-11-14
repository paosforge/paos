;; MODULE gui/widget
;; LAYER 6
;; EXPORTS wgt_form_event_hook, wgt_secret_owner, wgt_text_paint_hook, wgt_secret_human, wgt_secret_revision, wgt_secret_hidden, str_wgt_withheld, wgt_focus_visible, wgt_reserve_run, wgt_alloc_next, wgt_library_init, wgt_declare, wgt_type_register, wgt_type_bind_capture, wgt_type_capture_buttons, wgt_type_capture_motion, wgt_pointer_motion, wgt_pointer_capture_press, wgt_pointer_capture_press_button, wgt_pointer_capture_find, wgt_pointer_capture_event, wgt_type_headroom_report, wgt_create, wgt_slot_ptr, wgt_draw_id, wgt_draw_desktop, wgt_desktop_erase_rect, wgt_draw_glyph, wgt_rect_hittest, wgt_focus_window, wgt_focus_at, wgt_textfield_key, wgt_tab_reverse, wgt_textfield_event_hook, wgt_textfield_event_hook2, wgt_textfield_clip_get, wgt_textfield_clip_set, wgt_focus_id, wgt_count, wgt_out_buf, wgt_out_ready, wgt_m_library, wgt_m_registry, wgt_fill_rect, wgt_draw_text, wgt_pointer_hit_dispatch, wgt_type_name_of, wgt_shift_window, wgt_resize_window, wgt_secret_register, wgt_secret_clear, wgt_secret_selftest, wgt_secret_type, wgt_secret_bytes, wgt_secret_len, wgt_key_filter, wgt_click_hook, wgt_button_open_hook, wgt_button_get_hook, wgt_action_hook, wgt_hot_id, wgt_press_id, wgt_state_of, wgt_focus_ring_draw, wgt_hover_at, wgt_press_set, wgt_row_shown, wgt_overlay_host_shown, wgt_flyout_painted, wgt_mark_sectext, wgt_mark_formtext, wgt_mark_ascii, wgt_text_buf, wgt_text_len, wgt_text_refused, wgt_textfield_preedit, wgt_tf_buf, wgt_tf_long_free, wgt_textfield_long
;; IMPORTS gui/calendar, boot/serial, core/unicode_edit, gui/window, gui/window_mgmt, gui/widget_containers, gui/chat_app, gui/cadence_mark, svc/command, svc/clipboard, core/lib/fmt, core/lib/str, dev/input/ps2, sec/keyprov, sec/session, gui/widget_scalar_inputs, gui/lock_screen
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/widget.asm — 1110: the shared widget/ELEMENT library (M6 GUI keystone).
;
; The seam this module proves (DESKTOP.md §3.5 + COMMANDS.md §1, degenerate-2):
;   1. MODULAR/additive: ONE widget struct + ONE type VTABLE (draw / hit-test /
;      set-field / get-field per type) with TWO concrete types registered
;      through it — `button` and `textfield`. A 3rd type (1110b+) is a pure
;      wgt_type_register call, no core edit. Widgets render ONLY via the shared
;      primitives (fb_fill_rect from gui/window, fb_draw_str_n/fb_draw_char from
;      gui/chat_app) inside the C17 wm_* window slots — no bespoke pixel path.
;   2. AI-NATIVE element addressability: every element's state is reachable by
;      name through the ONE 1077 registry (COMMANDS.md §1 — "a widget field's
;      setter must BE a SET command, no side-doors"):
;        WIDGETTYPES                -> the registered types (proves the vtable)
;        WIDGETNEW <type> [win]     -> instantiate, returns id=<n>
;        WIDGETSET <id> <field> <v> -> THE registered per-element setter
;        WIDGETGET <id> <field>     -> read the element field back
;        WIDGETLIST                 -> enumerate live widgets + state
;        CATALOG                    -> the verb registry, GENERATED from the
;                                      registry self-description (§9.4b) — the
;                                      no-side-door witness (WIDGETSET listed)
;      A per-app verb can't fake per-element state; the probe SETs a random
;      nonce on one element and GETs it back byte-for-byte.
;   3. Widget struct PORTED (M16) from ../paos/recipes/desktop_compositor/
;      ESSENCE.md: the 64-byte visual base was extended to 80 bytes for role and
;      selection; F2 adds a 40-byte declarative/typed-state tail without moving
;      that prefix. Button h=32 / textfield h=28 and pitch 40 remain stable.
;
; Placement: widgets attach to a C17 wm_* slot (default 0 = window A @100,100
; 360x260); x = slot x+16, y = slot y+64 + id*40 — BELOW the 44px title bar
; (verify_gui samples A's title at (150,130) — untouched) and clear of the
; double-buffer tile (8,64 128x96, bottom y=160) and window B (x>=320; widest
; widget right edge = 116+200 = 316). Draws clip to the host slot rect and
; skip when the slot is not WM_VISIBLE — state stays addressable without
; pixels (the probe's element gates don't need a framebuffer).
;
; Markers (earned, serial at boot + BOOTLOG-gated tokens in command_udp):
;   ui.widget.library   both types registered through the vtable + both demo
;                       widgets created and drawn via the shared primitives
;   ui.widget.registry  all 6 element verbs registered (no slot-full failure)
;
; Replies stage into wgt_out_buf (bounded) and take command_udp's LEAN path
; (same as 1027b BLK): a widget reply carries no marker tokens, so WIDGETLIST/
; CATALOG's longer lines fit the datagram.
; ============================================================================

; --- the type VTABLE: one row per registered widget type (additive seam) ---
WTYPE_MAX   equ 32                     ; UI wave 2 G2: HEAD filled all 20 rows; append-order indices stay stable
WTYPE_HEADROOM_MIN equ 4               ; the boot KAT refuses its marker below this many free rows

; L1 widgets use this kit-owned seam to reach the existing font8x16 renderer.
; Keeping the primitive call here preserves the closed GUI painter inventory;
; this is delegation to chat_app::fb_draw_char, not a second text engine.
wgt_draw_glyph:
    jmp fb_draw_char
wgt_fill_rect:
    jmp fb_fill_rect
wgt_draw_text:
    jmp fb_draw_str_n
WT_NAME     equ 0                     ; ptr to NUL-terminated type name
WT_DRAW     equ 8                     ; draw(edi=id)
WT_HIT      equ 16                    ; hittest(edi=id, esi=px, edx=py) -> eax 0/1
WT_SET      equ 24                    ; set(edi=id, rsi=field, rdx=value) -> eax 0 ok / 1 bad_field
WT_GET      equ 32                    ; get(edi=id, rsi=field) -> rax = value ptr, 0 bad_field
WT_DEFW     equ 40                    ; dd default width
WT_DEFH     equ 44                    ; dd default height
WT_SZ       equ 48

; --- the widget base contract. F2 extends the additive tail for declarative
; form identity/layout and typed list/progress state. The clipboard-sized value
; keeps every established offset stable; only the role pointer moves from the
; reclaimed adjacent word to the new additive tail. ---
WGT_MAX     equ 64                     ; retain the sign-in form while its workspace is hidden; G9 (0.0.53): 48 -> 64
                                       ; with WK-B7B (boot uses 36: 28 free at the tail + the reusable B18 run)
WGI_TYPE    equ 0                     ; dd: 0 = free, else vtable index + 1
WGI_WIN     equ 4                     ; dd: host wm_* slot (0=A 1=B 2=chat)
WGI_X       equ 8                     ; dd absolute x
WGI_Y       equ 12                    ; dd absolute y
WGI_W       equ 16                    ; dd width
WGI_H       equ 20                    ; dd height
WGI_FLAGS   equ 24                    ; dd bit0 = visible
WGI_VLEN    equ 28                    ; dd live field-text length
WGI_VAL     equ 32                    ; 40-byte inline field text (label/value)
WGI_VAL_MAX equ 31                    ; legacy button/label + keyboard-edit bound
WGT_TEXTFIELD_VAL_MAX equ 39           ; includes the required 32-byte clipboard token + NUL
WGI_SEL_LO  equ 72                    ; dd: selection start
WGI_SEL_HI  equ 76                    ; dd: selection end
WGI_ID      equ 80                    ; dq: stable form-local widget id cstr
WGI_PARENT  equ 88                    ; dd: parent widget id, -1 = top level
WGI_SCROLL  equ 92                    ; dd: bounded list scroll offset
WGI_NUM     equ 96                    ; dq: typed numeric value (progress)
WGI_MAXVAL  equ 104                   ; dq: typed numeric maximum (progress)
WGI_BIND    equ 112                   ; dd: live-state binding class (form loader)
WGI_RSVD    equ 116                   ; dd: additive tail reservation
WGI_CARET   equ 120                   ; dd: edit caret in WGI_VAL
WGI_SUBMITS equ 124                   ; dd: widget-local Enter generations
WGI_EDIT    equ 128                   ; dd: additive edit-state flags
WGI_EDITPAD equ 132
WGI_INTENT  equ 136                   ; dd: slot-8 latest interaction-intent event (Task3367)
WGI_INTPAD  equ 140                   ; dd: pad so the scalar qwords stay 8-aligned
WGI_MINVAL  equ 144                   ; dq: scalar lower bound
WGI_STEP    equ 152                   ; dq: scalar increment (never zero)
WGI_LABEL   equ 160                   ; dq: slot-9 accessibility label cstr
WGI_INTENT_SEQ equ 168                ; dq: monotonic slot-8 publication sequence
WGI_ROLE    equ 176                   ; dq: accessibility role cstr (additive relocation)
WGI_ROWS    equ 184                   ; immutable declared grid dimensions
WGI_COLS    equ 188
WGI_CELL    equ 192                   ; declaration-order cell ordinal
WGI_LAYER   equ 196                   ; 1 only from a linted overlay declaration
WGI_SZ      equ 200
; wgt_rz_tbl record (one per widget id): see wgt_resize_window.
WRZ_VALID    equ 0                      ; dd 1 = record describes the widget's current rect
WRZ_WIN      equ 4                      ; dd host slot at record time
WRZ_TYPE     equ 8                      ; dd WGI_TYPE at record time
WRZ_RX       equ 12                     ; dd x - wm_x after the last resize
WRZ_RY       equ 16                     ; dd y - wm_y after the last resize
WRZ_W        equ 20                     ; dd w after the last resize
WRZ_H        equ 24                     ; dd h after the last resize
WRZ_DEBTW    equ 28                     ; dd signed <= 0: logical w - stored w (8 px floor)
WRZ_DEBTH    equ 32                     ; dd signed <= 0: logical h - stored h
WRZ_MODE     equ 36                     ; dd anchor bits below
WRZ_SZ       equ 40
WRZ_X_STRETCH equ 1
WRZ_X_MOVE    equ 2
WRZ_Y_STRETCH equ 4
WRZ_Y_MOVE    equ 8

GUI_KEY_ENTER     equ 0x100
GUI_KEY_BACKSPACE equ 0x101
GUI_KEY_LEFT      equ 0x102
GUI_KEY_RIGHT     equ 0x103
GUI_KEY_HOME      equ 0x104
GUI_KEY_END       equ 0x105
GUI_KEY_UP        equ 0x106
GUI_KEY_DOWN      equ 0x107
GUI_KEY_TAB       equ 0x108
GUI_KEY_ESC       equ 0x109
GUI_KEY_DELETE    equ 0x10A               ; G3 (usage suite KBM-01): E0 53
GUI_KEY_PGUP      equ 0x10B               ; hub packet 0009 (MSI conflict map rule 6): one key-code table.
GUI_KEY_PGDN      equ 0x10C               ;   The router does not decode these yet; the Terminal maps them
GUI_KEY_INSERT    equ 0x10D               ;   to xterm sequences once it does.
GUI_KEY_F1        equ 0x110               ; F1..F12 = 0x110..0x11B
GUI_KEY_TEXT      equ 0x120               ; RCQ-38 L3b: text >= U+0080, its UTF-8 in wgt_text_buf/wgt_text_len; it
                                          ;   takes the ordinary key delivery (modal hook, key filters, editor)

; Modal hooks normally return 0 (fall through) or 1 (fully handled).  Returning
; this shared result asks input_route to deliver the original key to the
; canonical focused textfield after the modal callback has unwound.
GUI_INPUT_MODAL_EDIT equ 2

WGT_PAD_X   equ 16                    ; left inset inside the host slot
WGT_PAD_Y   equ 64                    ; top inset (clears title bar + BB tile row)
WGT_PITCH   equ 40                    ; vertical stacking pitch (proven 32+8 spacing)
WGT_OUT_MAX equ 1152                  ; staged-reply capacity (bounded appends)
WGT_HOST_DESKTOP equ WM_MAX
WGT_EDIT_OPEN     equ 0x0001
WGT_EDIT_DISABLED equ 0x0002
WGT_EDIT_ACCENT   equ 0x0100
WGT_EDIT_SECTEXT  equ 0x0200            ; RCQ-38 L3a: paints through sec_text_escape (wgt_mark_sectext)
WGT_EDIT_ASCII    equ 0x0400            ; RCQ-38 L3b: the field holds 0x20..0x7E only (wgt_mark_ascii)
WGT_EDIT_FORMTEXT equ 0x0800            ; label/button text is still the form's declaration: '_' paints as ' ' (wgt_mark_formtext)
WGT_EDIT_ARROW    equ 0x1000            ; button: right arrow; public name/intent remain unchanged
WGT_EDIT_INSET_ACTION equ 0x2000        ; field: reserve trailing 40px; EDITPAD = button id + 1
WGT_EDIT_HELP_ICON equ 0x4000           ; button: question glyph; public name on hover/keyboard focus
WGT_EDIT_WARNING equ 0x8000           ; label only: red warning, paired with explicit text
WGT_TEXT_CAP      equ 196               ; RCQ-38 L3b: one GUI_KEY_TEXT payload / the pre-edit (= I3a IME_VIEW_CAP)
WGT_LONG_N        equ 4                 ; RCQ-38 L3c: long textfield value buffers (wgt_long_pool)
WGT_LONG_MAX      equ 255               ; a long field's value bytes (+ NUL in a 256 B entry)
WGT_SEC_TEXT_MAX  equ 168               ; escaped WGI_VAL: 39 bytes x '\xNN' + NUL, rounded so the frame + RSI is 16n
WGT_BUTTON_INTENT_VERB_SET equ 4

WGT_BTN_BG  equ GUI_TOK_CONTROL_BG     ; button body (D2 control fill, distinct from body)
WGT_BTN_FG  equ GUI_TOK_CONTROL_TEXT   ; button label text
WGT_BTN_BRD equ GUI_TOK_CONTROL_BORDER ; 1 px button outline inside the slot (RCQ-16 S3: 3:1 boundary)
WGT_TF_BG   equ 0x001F1F1F            ; D2 textfield field strip (dark input)
WGT_TF_FG   equ 0x00FFFFFF            ; textfield value text
WGT_TF_BRD  equ GUI_TOK_FIELD_BORDER  ; textfield 1px border (RCQ-16: 3:1 boundary)
WGT_TYPE_TEXTFIELD equ 2               ; WGI_TYPE stores vtable index + 1
WGT_TYPE_BUTTON   equ 1                ; wgt_library_init registration order: button, textfield, label
WGT_TYPE_LABEL    equ 3
; RCQ-16 S4: the shared control-state model (wgt_state_of). DISABLED masks every other bit.
WGT_ST_DISABLED equ 0x01               ; WGI_EDIT holds WGT_EDIT_DISABLED
WGT_ST_HOT      equ 0x02               ; the pointer rests on it (wgt_hot_id)
WGT_ST_PRESSED  equ 0x04               ; a held left press landed on it (wgt_press_id)
WGT_ST_FOCUSED  equ 0x08               ; keyboard focus, in a window that holds focus (the caret rule)
WGT_ST_RING     equ 0x10               ; focused, and focus came by keyboard (wgt_focus_visible)

; ---------------------------------------------------------------------------
; wgt_type_register(RDI=name, RSI=draw, RDX=hittest, RCX=set, R8=get,
;   R9 = default_w | (default_h << 32)) -> EAX = type index, or -1 if full.
;   THE additive seam: a new widget type is ONE call here (mirrors
;   command_register_verb's shape). Filled at RUNTIME via lea — a static
;   `dq symbol` table bakes the RVA, not the VA (the monolith populate_*
;   lesson). clobbers: RAX, R10, R11
; ---------------------------------------------------------------------------
wgt_type_register:
    mov  eax, [rel wgt_type_count]
    cmp  eax, WTYPE_MAX
    jae  .full
    imul r10, rax, WT_SZ
    lea  r11, [rel wgt_types]
    add  r11, r10
    mov  [r11 + WT_NAME], rdi
    mov  [r11 + WT_DRAW], rsi
    mov  [r11 + WT_HIT], rdx
    mov  [r11 + WT_SET], rcx
    mov  [r11 + WT_GET], r8
    mov  [r11 + WT_DEFW], r9d
    mov  r10, r9
    shr  r10, 32
    mov  [r11 + WT_DEFH], r10d
    inc  eax
    mov  [rel wgt_type_count], eax
    dec  eax
    ret
.full:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; Typed pointer capture (2026-10-06). A type that owns a press/drag/release
; gesture (the Terminal's text selection, scrollbar and xterm mouse reports)
; binds ONE callback for its type; the WM delivers the gesture through
; wgt_pointer_capture_press/_event below. The callback contract is the MSI
; tree's wgt_bind_capture_hook one, kept per type here so no other widget's
; press reaches it:
;   fn(EDI = widget id, ESI = x, EDX = y, ECX = WGT_CAPTURE_PRESS/DRAG/RELEASE)
;   -> EAX 1 consumed.
; ---------------------------------------------------------------------------
WGT_CAPTURE_PRESS   equ 0
WGT_CAPTURE_DRAG    equ 1
WGT_CAPTURE_RELEASE equ 2
WGT_CAPTURE_MOTION  equ 3               ; buttonless motion, no capture or focus change

; wgt_type_bind_capture(EDI = type index from wgt_type_register, RSI = fn)
;   -> EAX 0 bound, -1 refused (no such registered type). clobbers: RAX, R10
wgt_type_bind_capture:
    cmp  edi, [rel wgt_type_count]
    jae  .refused
    mov  eax, edi
    lea  r10, [rel wgt_type_capture]
    mov  [r10 + rax*8], rsi
    xor  eax, eax
    ret
.refused:
    mov  eax, -1
    ret

; wgt_type_capture_buttons(EDI = type index) -> EAX 0 / -1: the type's bound
;   capture also takes middle and right presses (RCQ-22; the Terminal's xterm
;   mouse reporting). Types that never opt in only ever see the left button.
;   clobbers: RAX, R10
wgt_type_capture_buttons:
    cmp  edi, [rel wgt_type_count]
    jae  .refused
    mov  eax, edi
    lea  r10, [rel wgt_type_capture_btns]
    mov  byte [r10 + rax], 1
    xor  eax, eax
    ret
.refused:
    mov  eax, -1
    ret

; wgt_type_capture_motion(EDI = registered type): opt its capture callback in
; to WGT_CAPTURE_MOTION. Other types keep their press/drag/release contract.
wgt_type_capture_motion:
    cmp  edi, [rel wgt_type_count]
    jae  .refused
    lea  r10, [rel wgt_type_capture_moves]
    mov  byte [r10 + rdi], 1
    xor  eax, eax
    ret
.refused:
    mov  eax, -1
    ret

; wgt_pointer_motion(EDI = hot widget, ESI x, EDX y) -> EAX consumed.
; Caller supplies the pure hover scan's top painted widget, never a hit hook.
; No gesture is started and no capture identity or keyboard focus is changed.
wgt_pointer_motion:
    push rbx
    mov  ebx, edi
    call wgt_capture_hook_of
    test rax, rax
    jz   .out
    push rax
    mov  edi, ebx
    call wgt_slot_ptr
    test dword [rax + WGI_FLAGS], 1
    jz   .no
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .no
    mov  ecx, [rax + WGI_TYPE]
    lea  r10, [rel wgt_type_capture_moves]
    cmp  byte [r10 + rcx - 1], 0
    je   .no
    mov  edi, ebx
    mov  ecx, WGT_CAPTURE_MOTION
    mov  r8d, 3                        ; xterm's no-button code
    pop  rax
    call rax
    jmp  .out
.no:
    pop  rax
    xor  eax, eax
.out:
    pop  rbx
    ret

; wgt_pointer_capture_press(EDI = widget id, ESI = x, EDX = y) -> EAX 1 when
;   the widget's type bound a capture and its callback consumed the press: the
;   widget (id, type, host slot) is then captured until the release. EAX 0
;   (nothing captured) for an out-of-range or free id, an unbound type, or a
;   press the callback declined. The left button. clobbers: caller-saved.
;   Every capture callback gets EDI widget, ESI x, EDX y, ECX phase and
;   R8D = the button of the gesture (0 left, 1 middle, 2 right).
wgt_pointer_capture_press:
    xor  ecx, ecx
    jmp  wgt_pointer_capture_press_button

; wgt_pointer_capture_press_button(EDI id, ESI x, EDX y, ECX button 0 left /
;   1 middle / 2 right) -> EAX as above. A middle or right press reaches only a
;   type that opted in (wgt_type_capture_buttons). clobbers: caller-saved.
wgt_pointer_capture_press_button:
    push rbx
    push r12
    push r13
    mov  dword [rel wgt_capture_id], -1
    mov  r12d, edi
    mov  r13d, ecx
    call wgt_capture_hook_of
    test rax, rax
    jz   .no
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_TYPE]
    mov  [rel wgt_capture_type], ecx
    test r13d, r13d
    jz   .button_ok
    lea  r10, [rel wgt_type_capture_btns]
    cmp  byte [r10 + rcx - 1], 0        ; WGI_TYPE is type + 1 (hook_of checked it)
    je   .no
.button_ok:
    mov  [rel wgt_capture_btn], r13b
    mov  ecx, [rax + WGI_WIN]
    mov  [rel wgt_capture_win], ecx
    mov  edi, r12d
    mov  ecx, WGT_CAPTURE_PRESS
    mov  r8d, r13d
    call rbx
    test eax, eax
    jz   .no
    mov  [rel wgt_capture_id], r12d
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_pointer_capture_event(ESI = x, EDX = y, ECX = WGT_CAPTURE_DRAG/RELEASE)
;   -> EAX 1 delivered to the captured widget, 0 when nothing is captured or
;   the capture went stale (the widget was retired or recreated -- see
;   wgt_capture_forget -- or its id now holds another type or window): a stale
;   capture is dropped, never delivered to whatever took the id. A release
;   always ends the capture. clobbers: caller-saved.
wgt_pointer_capture_event:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, esi
    mov  r14d, edx
    mov  ebx, ecx
    mov  r12d, [rel wgt_capture_id]
    cmp  ebx, WGT_CAPTURE_RELEASE
    jne  .held
    mov  dword [rel wgt_capture_id], -1
.held:
    cmp  r12d, -1
    je   .no
    mov  edi, r12d
    call wgt_capture_hook_of
    test rax, rax
    jz   .stale
    push rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, rax
    pop  rax
    mov  ecx, [rdi + WGI_TYPE]
    cmp  ecx, [rel wgt_capture_type]
    jne  .stale
    mov  ecx, [rdi + WGI_WIN]
    cmp  ecx, [rel wgt_capture_win]
    jne  .stale
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, ebx
    movzx r8d, byte [rel wgt_capture_btn]   ; the button that took the press
    call rax
    mov  eax, 1
    jmp  .out
.stale:
    mov  dword [rel wgt_capture_id], -1
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_capture_forget(EDI = widget id): the object at that id is going away or
;   being replaced, so a gesture it captured ends here. The (id, type, window)
;   check alone cannot tell a same-type widget recreated in the same slot and
;   window from the one that took the press. wgt_create calls this for the id
;   it is about to fill, so retirement through any path followed by reuse is
;   cancelled; wgt_retire_window_widgets calls it as it frees each slot.
;   clobbers: flags
wgt_capture_forget:
    cmp  edi, [rel wgt_capture_id]
    jne  .keep
    mov  dword [rel wgt_capture_id], -1
.keep:
    ret

; wgt_capture_hook_of(EDI = widget id) -> RAX = its type's bound capture fn, 0
;   for an out-of-range or free id or an unbound type. clobbers: RAX, RCX, R10
wgt_capture_hook_of:
    xor  eax, eax
    cmp  edi, [rel wgt_count]
    jae  .out
    cmp  edi, WGT_MAX
    jae  .out
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_TYPE]
    xor  eax, eax
    test ecx, ecx
    jz   .out
    dec  ecx
    cmp  ecx, [rel wgt_type_count]
    jae  .out
    lea  r10, [rel wgt_type_capture]
    mov  rax, [r10 + rcx*8]
.out:
    ret

; wgt_type_headroom_report — UI wave 2 G2 boot KAT. Called once after the last
;   boot-time registration (lock_screen_desktop_start, after the console grid).
;   Serial "[gui.wtype.headroom] free=<n> used=<m> max=<M>"; the marker is
;   refused (".fail") when fewer than WTYPE_HEADROOM_MIN rows remain, so a
;   new app type (MSI vt_view) cannot silently get eax=-1. clobbers: RAX, RCX,
;   RDX, RDI.
wgt_type_headroom_report:
    lea  rdi, [rel str_wtype_headroom]
    mov  eax, WTYPE_MAX
    sub  eax, [rel wgt_type_count]
    cmp  eax, WTYPE_HEADROOM_MIN
    jge  .ok
    lea  rdi, [rel str_wtype_headroom_fail]
.ok:
    call serial_string
    mov  eax, WTYPE_MAX
    sub  eax, [rel wgt_type_count]
    lea  rdi, [rel wtype_dec_buf]
    call wgt_dec2
    lea  rdi, [rel str_wtype_used]
    call serial_string
    mov  eax, [rel wgt_type_count]
    lea  rdi, [rel wtype_dec_buf]
    call wgt_dec2
    lea  rdi, [rel str_wtype_max]
    call serial_string
    mov  eax, WTYPE_MAX
    lea  rdi, [rel wtype_dec_buf]
    call wgt_dec2
    call serial_newline
    ret

; wgt_dec2(EAX=0..99, RDI=3-byte buffer) — print EAX as 1-2 decimal digits.
;   clobbers: RAX, RCX, RDX, RDI.
wgt_dec2:
    xor  edx, edx
    mov  ecx, 10
    div  ecx                            ; eax = tens, edx = ones
    test eax, eax
    jz   .ones
    add  al, '0'
    mov  [rdi], al
    inc  rdi
.ones:
    add  dl, '0'
    mov  [rdi], dl
    mov  byte [rdi + 1], 0
    lea  rdi, [rel wtype_dec_buf]
    call serial_string
    ret

; wgt_slot_ptr(EDI=id) -> RAX = widget struct ptr. No bounds check (callers
;   validated id < wgt_count). clobbers: RAX, R10
wgt_slot_ptr:
    mov  eax, edi
    imul rax, rax, WGI_SZ
    lea  r10, [rel wgt_tbl]
    add  rax, r10
    ret

; ---------------------------------------------------------------------------
; wgt_create(EDI=type index, ESI=win slot) -> EAX = widget id, or -1 if full.
;   Fills the struct (geometry = host slot inset + stacked pitch, dims from the
;   type's vtable defaults), then draws it through the vtable. clobbers:
;   caller-saved.
; ---------------------------------------------------------------------------
; wgt_reserve_run(EDI = n) -> EAX = WK-B7B (2026-10-02, rides 0.0.53 with G9): the base of the LOWEST run of n
; consecutive free entries (WGI_TYPE == 0) below wgt_count, else wgt_count when wgt_count + n <= WGT_MAX, else -1.
; It only chooses (nothing is marked), so a refusal leaves the table untouched. Leaf: wgt_tbl / wgt_count only.
; Clobbers EAX, ECX, EDX, R8, R9. (test_wk_b7b_alloc_host assembles exactly this body.)
wgt_reserve_run:
    mov  r8d, edi
    test r8d, r8d
    jz   .tail                         ; n = 0 allocates nothing: answer the append point
    xor  ecx, ecx
    xor  edx, edx
    lea  r9, [rel wgt_tbl]
.scan:
    cmp  ecx, [rel wgt_count]
    jae  .tail
    imul eax, ecx, WGI_SZ
    cmp  dword [r9 + rax + WGI_TYPE], 0
    jne  .used
    inc  edx
    cmp  edx, r8d
    jae  .hit
    jmp  .next
.used:
    xor  edx, edx
.next:
    inc  ecx
    jmp  .scan
.hit:
    mov  eax, ecx
    sub  eax, r8d
    inc  eax
    ret
.tail:
    mov  eax, [rel wgt_count]
    add  eax, r8d
    cmp  eax, WGT_MAX
    ja   .full
    mov  eax, [rel wgt_count]
    ret
.full:
    mov  eax, -1
    ret

wgt_create:
    push rbx
    push r12
    push r13
    mov  eax, [rel wgt_count]
    mov  ecx, [rel wgt_alloc_next]     ; WK-B7B: a form loader reservation places this id inside its run
    cmp  ecx, -1
    je   .append
    cmp  ecx, WGT_MAX
    jae  .full
    cmp  ecx, [rel wgt_count]          ; at/above the tail every entry is free: boot KATs restore wgt_count
    jae  .reserved_free                ; without clearing the WGI_TYPE they wrote there
    imul edx, ecx, WGI_SZ
    lea  r8, [rel wgt_tbl]
    cmp  dword [r8 + rdx + WGI_TYPE], 0
    jne  .full                         ; never overwrite a live entry
.reserved_free:
    inc  dword [rel wgt_alloc_next]
    mov  eax, ecx
    jmp  .have_id
.append:
    cmp  eax, WGT_MAX
    jae  .full
.have_id:
    mov  r12d, eax                     ; r12d = new id
    mov  r13d, edi                     ; r13d = type index
    ; --- struct base ---
    mov  edi, r12d
    call wgt_capture_forget            ; a new object never inherits a held pointer gesture
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, r13d
    inc  eax
    mov  [rbx + WGI_TYPE], eax
    mov  [rbx + WGI_WIN], esi
    ; --- geometry: x = wm_x[win]+16, y stacks by this window's ordinal. ---
    xor  r11d, r11d
    xor  ecx, ecx
.ordinal:
    cmp  ecx, r12d
    jae  .ordinal_done
    mov  edi, ecx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .ordinal_next
    cmp  [rax + WGI_WIN], esi
    jne  .ordinal_next
    inc  r11d
.ordinal_next:
    inc  ecx
    jmp  .ordinal
.ordinal_done:
    mov  eax, esi
    lea  r10, [rel wm_x]
    mov  ecx, [r10 + rax*4]
    add  ecx, WGT_PAD_X
    mov  [rbx + WGI_X], ecx
    lea  r10, [rel wm_y]
    mov  ecx, [r10 + rax*4]
    add  ecx, WGT_PAD_Y
    mov  eax, r11d
    imul eax, eax, WGT_PITCH
    add  ecx, eax
    mov  [rbx + WGI_Y], ecx
    ; --- dims from the type's vtable defaults ---
    mov  eax, r13d
    imul rax, rax, WT_SZ
    lea  r10, [rel wgt_types]
    add  rax, r10
    mov  ecx, [rax + WT_DEFW]
    mov  [rbx + WGI_W], ecx
    mov  ecx, [rax + WT_DEFH]
    mov  [rbx + WGI_H], ecx
    mov  dword [rbx + WGI_FLAGS], 1
    mov  dword [rbx + WGI_VLEN], 0
    mov  byte [rbx + WGI_VAL], 0
    mov  eax, r13d
    imul rax, rax, WT_SZ
    lea  r10, [rel wgt_types]
    mov  rax, [r10 + rax + WT_NAME]
    mov  [rbx + WGI_ROLE], rax
    mov  dword [rbx + WGI_SEL_LO], 0
    mov  dword [rbx + WGI_SEL_HI], 0
    mov  qword [rbx + WGI_ID], 0
    mov  dword [rbx + WGI_PARENT], -1
    mov  dword [rbx + WGI_SCROLL], 0
    mov  qword [rbx + WGI_NUM], 0
    mov  qword [rbx + WGI_MAXVAL], 100
    mov  dword [rbx + WGI_BIND], 0
    xchg rax, rbx
    call wgt_tf_long_free               ; RCQ-38 L3c: a recycled slot's long value is wiped
    xchg rax, rbx                       ; RAX = the type name again (WGI_LABEL below)
    mov  dword [rbx + WGI_RSVD], 0
    mov  dword [rbx + WGI_CARET], 0
    mov  dword [rbx + WGI_SUBMITS], 0
    mov  dword [rbx + WGI_EDIT], 0
    mov  dword [rbx + WGI_EDITPAD], 0
    mov  dword [rel wgt_preedit_id], 0  ; RCQ-38 L3b: no pre-edit outlives a create
    mov  dword [rbx + WGI_INTENT], 0
    mov  qword [rbx + WGI_MINVAL], 0
    mov  qword [rbx + WGI_STEP], 1
    mov  [rbx + WGI_LABEL], rax
    mov  qword [rbx + WGI_INTENT_SEQ], 0
    mov  qword [rbx + WGI_ROWS], 0
    mov  qword [rbx + WGI_CELL], 0
    cmp  r12d, [rel wgt_hot_id]         ; RCQ-16 S4: a reused id inherits no hover / pressed paint
    jne  .hot_clear
    mov  dword [rel wgt_hot_id], -1
.hot_clear:
    cmp  r12d, [rel wgt_press_id]
    jne  .press_clear
    mov  dword [rel wgt_press_id], -1
.press_clear:
    imul ecx, r12d, WRZ_SZ              ; a new widget has no resize anchor record yet
    lea  r10, [rel wgt_rz_tbl]
    mov  dword [r10 + rcx + WRZ_VALID], 0
    lea  eax, [r12d + 1]               ; WK-B7B: an interior id leaves wgt_count alone; append grows it by one
    cmp  eax, [rel wgt_count]
    jbe  .count_ok
    mov  [rel wgt_count], eax
.count_ok:
    ; --- first paint through the vtable ---
    mov  edi, r12d
    call wgt_draw_id
    mov  eax, r12d
    jmp  .out
.full:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; wgt_set_text(EDI=id, RSI=cstr) — store the element's field text (bounded
;   WGI_VAL_MAX) + repaint through the vtable. The ONE store path both the
;   boot demo and the registered WIDGETSET verb use. An id >= wgt_count
;   (unsigned: -1 included) is refused, nothing stored or drawn, and one
;   serial line carries [gui.widget.set_text.refused] (STM-02; the r2 grade
;   requires zero). clobbers: caller-saved.
; ---------------------------------------------------------------------------
wgt_set_text:
    mov  edx, WGI_VAL_MAX
wgt_set_text_cap:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, edx
    cmp  edi, [rel wgt_count]
    jae  .refused_id                    ; STM-02: an id outside the table is refused, never a fault
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rel wgt_secret_type]
    inc  eax
    cmp  [rbx + WGI_TYPE], eax
    jne  .copy_public
    ; Only the transient editor can change a secret's public mask.
.refused:
    pop  r13
    pop  r12
    pop  rbx
    ret
.refused_id:                            ; no allocation: this can run inside a paint path
    lea  rdi, [rel str_wgt_set_text_refused]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_wgt_set_text_refused_tag]
    call serial_string
    jmp  .refused
.copy_public:
    cmp  dword [rbx + WGI_TYPE], WGT_TYPE_BUTTON
    je   .runtime_text
    cmp  dword [rbx + WGI_TYPE], WGT_TYPE_LABEL
    jne  .cp_buffer
.runtime_text:
    and  dword [rbx + WGI_EDIT], ~WGT_EDIT_FORMTEXT ; set text is shown as given
.cp_buffer:
    lea  rdi, [rbx + WGI_VAL]
    cmp  dword [rbx + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .cp_start
    mov  rax, rbx
    call wgt_tf_buf                     ; RCQ-38 L3c: a textfield stores through its accessor
    mov  rdi, rax
    cmp  r13d, ecx
    jbe  .cp_start
    mov  r13d, ecx                      ; never past the field's buffer
.cp_start:
    xor  ecx, ecx
.cp:
    cmp  ecx, r13d
    jae  .done
    mov  al, [rsi + rcx]
    test al, al
    jz   .done
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .cp
.done:
    mov  byte [rdi + rcx], 0
    mov  [rbx + WGI_VLEN], ecx
    mov  [rbx + WGI_CARET], ecx
    mov  edi, r12d
    call wgt_draw_id
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; wgt_draw_id(EDI=id) — validate + clip + dispatch the type's DRAW through the
;   vtable. Skips (state stays addressable, no pixels) when: id invalid, host
;   slot not WM_VISIBLE, or the widget rect leaves the host slot rect. Outside
;   a composition (wgt_paint_depth 0) a widget that something painted later
;   overlaps (wgt_state_occluded: a window above its host, the taskbar band)
;   is never painted alone: the desktop recomposes instead (RCQ-16 F6).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
wgt_draw_id:
    push rbx
    push r12
    cmp  byte [rel wgt_paint_suspended], 0
    jne  .out
    mov  eax, edi
    cmp  eax, [rel wgt_count]
    jae  .out
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [rbx + WGI_TYPE]
    test ecx, ecx
    jz   .out
    test dword [rbx + WGI_FLAGS], 1
    jz   .out
    dec  ecx                           ; ecx = vtable index
    mov  r12d, ecx
    ; Standalone widget refreshes must recompose when an overlay is live.
    ; The compositor sets depth before calling any widget painter.
    cmp  byte [rel wgt_paint_depth], 0
    jne  .layer
    push rdi
    call wgt_has_overlay
    pop  rdi
    test eax, eax
    jz   .layer
    call wmx_draw_all
    jmp  .out                         ; retain DRAW's callee-saved register ABI
.layer:
    cmp  dword [rbx + WGI_LAYER], 1
    je   .overlay_layer
    cmp  byte [rel wgt_overlay_pass], 0
    jne  .out
    jmp  .host
.overlay_layer:
    cmp  byte [rel wgt_overlay_pass], 1
    jne  .out
    mov  rax, rbx
    call wgt_row_shown                ; F5-R1: no other window's overlay above the focused one
    jc   .out
.host:
    ; --- host slot visible? ---
    mov  eax, [rbx + WGI_WIN]
    cmp  eax, WGT_HOST_DESKTOP
    je   .desktop_host
    ja   .out
    lea  r10, [rel wm_state]
    cmp  dword [r10 + rax*4], WM_VISIBLE
    jne  .out
.desktop_host:
    call wgt_rect_allowed_draw
    jc   .out
    jmp  .dispatch
    ; The one rectangle gate is shared with atomic geometry mutation.
.dispatch:
    ; RCQ-16 F6 (root 15:47:57; srcreview S4 R1 F6): a standalone repaint (an
    ; app's WIDGETSET, a SET path) must not paint over the window above its host
    ; or the taskbar band (the guardian indicator cell lives there).
    cmp  byte [rel wgt_paint_depth], 0
    jne  .vtable
    push rdi
    call wgt_state_occluded             ; preserves RBX, R12
    pop  rdi
    test eax, eax
    jz   .vtable
    call wmx_draw_all
    jmp  .out
.vtable:
    ; --- vtable dispatch ---
    mov  eax, r12d
    imul rax, rax, WT_SZ
    lea  r10, [rel wgt_types]
    mov  rax, [r10 + rax + WT_DRAW]
    test rax, rax
    jz   .out
    call rax                           ; edi = id (preserved above)
.out:
    pop  r12
    pop  rbx
    ret

; RBX=row, CF=1 refusal. All four edges and overflow are checked, including
; for the only sanctioned escape: a linted overlay within the framebuffer.
; wgt_rect_allowed is the geometry-mutation gate (WIDGETSET rect): unchanged.
; wgt_rect_allowed_draw is the paint gate: an ordinary child that lies inside
; its host window is painted even where that window crosses the right/bottom
; screen edge (a dragged window may legally hang off-screen). Every widget
; painter goes through the clipped fb primitives (fill/char/AA glyph/blit), so
; the framebuffer clip is the only clip needed. Desktop hosts and overlays keep
; the full on-screen requirement. 2026-09-30 (usage suite MNU-04: the console's
; tab strip and transcript vanished once its window crossed the right edge).
wgt_rect_allowed_draw:
    push rsi
    mov  esi, 1
    call wgt_rect_allowed_core
    pop  rsi                          ; pop preserves CF
    ret

wgt_rect_allowed:
    push rsi
    xor  esi, esi
    call wgt_rect_allowed_core
    pop  rsi
    ret

; ESI = 1 draw gate, 0 mutation gate.
wgt_rect_allowed_core:
    mov  eax, [rbx + WGI_TYPE]
    call wgt_geometry_min
    cmp  [rbx + WGI_W], r8d
    jb   .bad
    cmp  [rbx + WGI_H], r11d
    jb   .bad
    mov  r8d, r10d                    ; proud textfield border is part of paint
    cmp  [rbx + WGI_X], r8d
    jb   .bad
    cmp  [rbx + WGI_Y], r8d
    jb   .bad
    mov  eax, [rbx + WGI_WIN]
    cmp  eax, WGT_HOST_DESKTOP
    je   .desktop_bounds
    ja   .bad
    xor  r11d, r11d
    jmp  .edge_bounds
.desktop_bounds:
    mov  r11d, 1
.edge_bounds:
    mov  edx, [rbx + WGI_W]
    test edx, edx
    jz   .bad
    add  edx, [rbx + WGI_X]
    jc   .bad
    add  edx, r8d
    jc   .bad
    mov  r9d, [rbx + WGI_H]
    test r9d, r9d
    jz   .bad
    add  r9d, [rbx + WGI_Y]
    jc   .bad
    add  r9d, r8d
    jc   .bad
    test r11d, r11d
    jnz  .screen
    cmp  dword [rbx + WGI_LAYER], 1
    je   .screen
    lea  r10, [rel wm_x]
    mov  ecx, [r10 + rax*4]
    add  ecx, r8d
    cmp  [rbx + WGI_X], ecx
    jb   .bad
    sub  ecx, r8d
    lea  r10, [rel wm_w]
    add  ecx, [r10 + rax*4]            ; slot right edge
    jc   .bad
    cmp  edx, ecx
    ja   .bad
    lea  r10, [rel wm_y]
    mov  ecx, [r10 + rax*4]
    add  ecx, r8d
    cmp  [rbx + WGI_Y], ecx
    jb   .bad
    sub  ecx, r8d
    lea  r10, [rel wm_h]
    add  ecx, [r10 + rax*4]            ; slot bottom edge
    jc   .bad
    cmp  r9d, ecx
    ja   .bad
    test esi, esi                     ; paint gate: inside the host is enough,
    jnz  .ok                          ; the fb primitives clip the screen edge
.screen:
    cmp  edx, [rel fb_width]
    ja   .bad
    cmp  r9d, [rel fb_height]
    ja   .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; Stored type EAX -> minimum paint-safe W/H in R8D/R11D, outset R10D.
; These are the existing painters' insets, not new visual defaults. Reused
; by form lint so an undersized glyph surface refuses before allocation.
wgt_geometry_min:
    mov  r8d, 1
    mov  r11d, 1
    xor  r10d, r10d
    cmp  eax, 1
    je   .button
    cmp  eax, 2
    je   .field
    dec  eax
    cmp  eax, [rel wgt_secret_type]
    je   .field
    inc  eax
    cmp  eax, 3
    je   .label
    cmp  eax, 4
    je   .list
    cmp  eax, 5
    je   .progress
    cmp  eax, 8
    je   .status
    cmp  eax, 9
    je   .scalar
    cmp  eax, 11
    je   .scalar
    cmp  eax, 10
    jne  .out
    mov  r8d, 5
    mov  r11d, 6
    ret
.button:
    mov  r8d, 20
    mov  r11d, 24
    ret
.field:
    mov  r8d, 12
    mov  r11d, 22
    mov  r10d, 1
    ret
.label:
    mov  r11d, 16
    ret
.list:
    mov  r8d, 12
    mov  r11d, 23
    ret
.progress:
    mov  r11d, 3
    ret
.status:
    mov  r8d, 10
    mov  r11d, 20
    ret
.scalar:
    mov  r8d, 48
    mov  r11d, 21
.out:
    ret

; WIDGETSET rect uses absolute coordinates. Validate a private candidate with
; the same gate as DRAW, then erase/commit/recompose. Declared container layout
; is immutable here: it can only be replaced through the linted form path.
wgt_set_rect:
    push rbx
    push r12
    push r13
    push r14
    mov  r14, rsi
    call wgt_slot_ptr
    mov  r12, rax
    mov  eax, 1
    cmp  dword [r12 + WGI_LAYER], 0
    jne  .out
    cmp  dword [r12 + WGI_ROWS], 0
    jne  .out
    cmp  dword [r12 + WGI_PARENT], -1
    jne  .out
    ; Containers own child geometry, so moving them needs a new form plan.
    cmp  dword [r12 + WGI_TYPE], 6
    je   .out
    cmp  dword [r12 + WGI_TYPE], 7
    je   .out
    cmp  dword [r12 + WGI_TYPE], 8
    je   .out
    sub  rsp, WGI_SZ
    mov  rbx, rsp
    mov  rdi, rsp
    mov  rsi, r12
    mov  ecx, WGI_SZ/8
    cld
    rep  movsq
    xor  r13d, r13d
.field:
    mov  rdi, r14
    call wgt_parse_dec
    test ecx, ecx
    jz   .bad
    cmp  ecx, 5                       ; bounded before accepting wrapped values
    ja   .bad
    cmp  eax, 65535
    ja   .bad
    mov  [rbx + WGI_X + r13*4], eax
    mov  r14, rdx
    inc  r13d
    cmp  r13d, 4
    je   .last
    cmp  byte [r14], ','
    jne  .bad
    inc  r14
    jmp  .field
.last:
    cmp  byte [r14], 0
    jne  .bad
    call wgt_rect_allowed
    jc   .bad
    mov  edi, [r12 + WGI_WIN]
    push rbx
    call wm_erase_slot
    pop  rbx
    mov  rax, [rbx + WGI_X]
    mov  [r12 + WGI_X], rax
    mov  rax, [rbx + WGI_W]
    mov  [r12 + WGI_W], rax
    call wmx_draw_all
    xor  eax, eax
    jmp  .free
.bad:
    mov  eax, 1
.free:
    add  rsp, WGI_SZ
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_row_shown(RAX = widget row) -> CF clear when the row may show: a layer-0
;   widget, or an overlay whose host may show one (wgt_overlay_host_shown).
;   CF set: an overlay of any other window. It never paints above the focused
;   window, so nothing hovers or presses it either (RCQ-16 F5-R1, root
;   18:14:29: an overlay owned by a non-focused window must never paint above
;   the focused window). Preserves every register.
wgt_row_shown:
    cmp  dword [rax + WGI_LAYER], 1
    jne  .shown
    push rcx
    mov  ecx, [rax + WGI_WIN]
    call wgt_overlay_host_shown
    pop  rcx                          ; pop preserves CF
    ret
.shown:
    clc
    ret

; wgt_overlay_host_shown(ECX = host) -> CF clear when an overlay of that host
;   is painted: the desktop (PaOS system chrome), or the focused window while
;   it is WM_VISIBLE (F5-R2: a minimised focused window paints nothing, so its
;   menu or dropdown takes no hover or press either). Under the session lock
;   surface wmx_draw_all paints no overlay at all, so none shows. The one
;   predicate for paint, hover and press. Preserves every register.
wgt_overlay_host_shown:
    cmp  byte [rel lock_surface_ready], 1
    jne  .unlocked
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .hidden
.unlocked:
    cmp  ecx, WGT_HOST_DESKTOP
    je   .shown
    cmp  ecx, [rel wm_focus]
    jne  .hidden
    cmp  ecx, WM_MAX
    jae  .hidden
    push rcx
    push rdx
    mov  ecx, ecx
    lea  rdx, [rel wm_state]
    cmp  dword [rdx + rcx*4], WM_VISIBLE
    pop  rdx
    pop  rcx
    je   .shown
.hidden:
    stc
    ret
.shown:
    clc
    ret

; wgt_flyout_painted(RAX = row) -> CF clear when the row may take hover or
;   press: a layer-0 widget, or an overlay the overlay pass paints (it may show,
;   wgt_row_shown, and its rectangle passes the paint gate wgt_rect_allowed_draw,
;   as wgt_draw_id requires). F5-R2 (srcreview L-a): an edge-crossing flyout
;   that is not painted takes no hover or press. Preserves every register.
wgt_flyout_painted:
    call wgt_row_shown
    jc   .out
    cmp  dword [rax + WGI_LAYER], 1
    jne  .layer0
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov  rbx, rax
    call wgt_rect_allowed_draw
    pop  r11                          ; pops preserve CF
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.out:
    ret
.layer0:
    clc
    ret

wgt_has_overlay:
    xor  ecx, ecx
.loop:
    cmp  ecx, [rel wgt_count]
    jae  .no
    imul rax, rcx, WGI_SZ
    lea  rdx, [rel wgt_tbl]
    add  rdx, rax
    cmp  dword [rdx + WGI_TYPE], 0
    je   .next
    cmp  dword [rdx + WGI_LAYER], 1
    jne  .next
    test dword [rdx + WGI_FLAGS], 1
    jz   .next
    mov  rax, rdx
    call wgt_row_shown
    jc   .next
    mov  eax, [rdx + WGI_WIN]
    cmp  eax, WGT_HOST_DESKTOP
    je   .yes
    ja   .next
    lea  rdx, [rel wm_state]
    cmp  dword [rdx + rax*4], WM_VISIBLE
    je   .yes
.next:
    inc  ecx
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Desktop widgets use the ordinary vtable and late-overlay pass without a window slot.
wgt_draw_desktop:
    push r12
    xor  r12d, r12d
.loop:
    cmp  r12d, [rel wgt_count]
    jae  .done
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .next
    cmp  dword [rax + WGI_WIN], WGT_HOST_DESKTOP
    jne  .next
    mov  edi, r12d
    call wgt_draw_id
.next:
    inc  r12d
    jmp  .loop
.done:
    pop  r12
    ret

wgt_desktop_erase_rect:
    push rbx
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    call wallpaper_paint_rect
    pop  rbx
    ret

; wgt_draw_window(edi=wm slot) — redraw all live widgets owned by one window.
;   Occluded widgets (F6) ask for one composition, run after the loop.
wgt_draw_window:
    push r12
    push r13
    mov  r13d, edi
    call wmx_draw_defer_begin           ; RCQ-16 F6: one composition, not one per occluded widget
    call ps2_cursor_hide                ; 2026-09-08: lift the sprite before painting the window
    xor  r12d, r12d
.dw_loop:
    cmp  r12d, [rel wgt_count]
    jae  .dw_done
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .dw_next
    cmp  [rax + WGI_WIN], r13d
    jne  .dw_next
    mov  edi, r12d
    call wgt_draw_id
.dw_next:
    inc  r12d
    jmp  .dw_loop
.dw_done:
    call wmx_draw_defer_end
    cmp  byte [rel wgt_paint_depth], 0
    jne  .dw_return
    call wmx_draw_flush_deferred        ; the composition an occluded widget asked for
    call ps2_cursor_show                ; 2026-09-08: sprite back on top
.dw_return:
    pop  r13
    pop  r12
    ret

; Recompute absolute widget geometry after the owning window moves/restores.
; wgt_shift_window(EDI=slot, ESI=dx, EDX=dy) — move every widget of a window by the
; window's own delta so a form keeps its layout (2026-09-08: the move path used to
; re-stack widgets at pitch 40, which collapsed the console's grid/input/status rows).
wgt_shift_window:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13d, edi
    mov  r14d, esi
    mov  r15d, edx
    xor  r12d, r12d
.sh_loop:
    cmp  r12d, [rel wgt_count]
    jae  .sh_done
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], 0
    je   .sh_next
    cmp  [rbx + WGI_WIN], r13d
    jne  .sh_next
    add  [rbx + WGI_X], r14d
    add  [rbx + WGI_Y], r15d
.sh_next:
    inc  r12d
    jmp  .sh_loop
.sh_done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_resize_window(EDI=slot, ESI=old_w, EDX=old_h) — the window's w/h already hold the new
; size. Each widget is anchored by which half of the OLD window it lived in: a widget that
; starts in the right/bottom half moves with that edge; one that starts in the left/top half
; but reaches past the middle stretches; small top-left widgets stay. 2026-09-08 (Peter:
; "it resized but its window inside did not").
;
; 2026-09-30 (usage suite CHR-08): the anchoring must be reversible. It used to be
; re-derived from the widget's CURRENT position on every resize step and a stretched
; size was floored at 8 px with the lost amount discarded, so a shrink far below the
; design size (no window minimum yet, B4) re-classified the console's rows and lost
; their size: after a regrow the transcript grid came back 728x446 and overlapped the
; input/status rows, leaving a blank panel that maximize/restore could not repair.
; Now each widget's anchor mode is decided once (the same half rule, applied the first
; time its window resizes) and kept in wgt_rz_tbl together with the px the 8 px floor
; swallowed ("debt"), so any sequence of resizes back to a size restores the exact
; layout. The record is only trusted while the widget still sits exactly where the
; last resize left it (same window, type, window-relative x/y, w/h); any other
; geometry writer (form load, WIDGETSET rect, dock-fit) makes it re-classify fresh,
; which is the previous behaviour.
wgt_resize_window:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  r13d, edi                      ; slot
    mov  eax, r13d
    lea  rcx, [rel wm_w]
    mov  r14d, [rcx + rax*4]
    sub  r14d, esi                      ; dw
    lea  rcx, [rel wm_h]
    mov  r15d, [rcx + rax*4]
    sub  r15d, edx                      ; dh
    mov  ebp, esi
    shr  ebp, 1
    lea  rcx, [rel wm_x]
    add  ebp, [rcx + rax*4]             ; old mid x (absolute)
    mov  ecx, edx
    shr  ecx, 1
    lea  rdx, [rel wm_y]
    add  ecx, [rdx + rax*4]             ; old mid y (absolute)
    push rcx                            ; [rsp] = mid y
    xor  r12d, r12d
.rz_loop:
    cmp  r12d, [rel wgt_count]
    jae  .rz_done
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], 0
    je   .rz_next
    cmp  [rbx + WGI_WIN], r13d
    jne  .rz_next
    ; GK1-3 grids have explicit fixed cell geometry; overlays have an explicit
    ; envelope. Preserve those declarations across host resize, just as host
    ; move preserves relative geometry. The draw gate refuses escaped ordinary
    ; children if the host is made smaller than their declared grid.
    cmp  dword [rbx + WGI_LAYER], 1
    je   .rz_next
    mov  rax, rbx
.rz_container:
    cmp  dword [rax + WGI_ROWS], 0
    jne  .rz_next
    mov  edi, [rax + WGI_PARENT]
    cmp  edi, [rel wgt_count]
    jae  .rz_ordinary
    call wgt_slot_ptr
    jmp  .rz_container
.rz_ordinary:
    imul r8d, r12d, WRZ_SZ
    lea  r9, [rel wgt_rz_tbl]
    add  r8, r9                         ; r8 = this widget's anchor record
    mov  eax, r13d
    lea  rcx, [rel wm_x]
    mov  r10d, [rcx + rax*4]            ; host x (already moved)
    lea  rcx, [rel wm_y]
    mov  r11d, [rcx + rax*4]            ; host y
    cmp  dword [r8 + WRZ_VALID], 1
    jne  .rz_classify
    cmp  [r8 + WRZ_WIN], r13d
    jne  .rz_classify
    mov  eax, [rbx + WGI_TYPE]
    cmp  [r8 + WRZ_TYPE], eax
    jne  .rz_classify
    mov  eax, [rbx + WGI_W]
    cmp  [r8 + WRZ_W], eax
    jne  .rz_classify
    mov  eax, [rbx + WGI_H]
    cmp  [r8 + WRZ_H], eax
    jne  .rz_classify
    mov  eax, [rbx + WGI_X]
    sub  eax, r10d
    cmp  [r8 + WRZ_RX], eax
    jne  .rz_classify
    mov  eax, [rbx + WGI_Y]
    sub  eax, r11d
    cmp  [r8 + WRZ_RY], eax
    je   .rz_apply
.rz_classify:
    ; horizontal: right half moves, straddling the middle stretches
    xor  r9d, r9d
    mov  eax, [rbx + WGI_X]
    cmp  eax, ebp
    jge  .rz_cx_move
    add  eax, [rbx + WGI_W]
    cmp  eax, ebp
    jle  .rz_cy
    or   r9d, WRZ_X_STRETCH
    jmp  .rz_cy
.rz_cx_move:
    or   r9d, WRZ_X_MOVE
.rz_cy:
    mov  ecx, [rsp]                     ; mid y
    mov  eax, [rbx + WGI_Y]
    cmp  eax, ecx
    jge  .rz_cy_move
    add  eax, [rbx + WGI_H]
    cmp  eax, ecx
    jle  .rz_cstore
    or   r9d, WRZ_Y_STRETCH
    jmp  .rz_cstore
.rz_cy_move:
    or   r9d, WRZ_Y_MOVE
.rz_cstore:
    mov  [r8 + WRZ_MODE], r9d
    mov  dword [r8 + WRZ_DEBTW], 0
    mov  dword [r8 + WRZ_DEBTH], 0
.rz_apply:
    mov  r9d, [r8 + WRZ_MODE]
    test r9d, WRZ_X_MOVE
    jz   .rz_x_stretch
    add  [rbx + WGI_X], r14d
    jmp  .rz_vert
.rz_x_stretch:
    test r9d, WRZ_X_STRETCH
    jz   .rz_vert
    mov  eax, [rbx + WGI_W]
    add  eax, [r8 + WRZ_DEBTW]
    add  eax, r14d                      ; logical width
    mov  ecx, eax
    cmp  eax, 8
    jge  .rz_store_w
    mov  eax, 8
.rz_store_w:
    sub  ecx, eax                       ; what the floor swallowed (<= 0)
    mov  [r8 + WRZ_DEBTW], ecx
    mov  [rbx + WGI_W], eax
.rz_vert:
    test r9d, WRZ_Y_MOVE
    jz   .rz_y_stretch
    add  [rbx + WGI_Y], r15d
    jmp  .rz_record
.rz_y_stretch:
    test r9d, WRZ_Y_STRETCH
    jz   .rz_record
    mov  eax, [rbx + WGI_H]
    add  eax, [r8 + WRZ_DEBTH]
    add  eax, r15d                      ; logical height
    mov  ecx, eax
    cmp  eax, 8
    jge  .rz_store_h
    mov  eax, 8
.rz_store_h:
    sub  ecx, eax
    mov  [r8 + WRZ_DEBTH], ecx
    mov  [rbx + WGI_H], eax
.rz_record:
    mov  [r8 + WRZ_WIN], r13d
    mov  eax, [rbx + WGI_TYPE]
    mov  [r8 + WRZ_TYPE], eax
    mov  eax, [rbx + WGI_X]
    sub  eax, r10d
    mov  [r8 + WRZ_RX], eax
    mov  eax, [rbx + WGI_Y]
    sub  eax, r11d
    mov  [r8 + WRZ_RY], eax
    mov  eax, [rbx + WGI_W]
    mov  [r8 + WRZ_W], eax
    mov  eax, [rbx + WGI_H]
    mov  [r8 + WRZ_H], eax
    mov  dword [r8 + WRZ_VALID], 1
.rz_next:
    inc  r12d
    jmp  .rz_loop
.rz_done:
    pop  rcx
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_reflow_window:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, edi
    xor  r12d, r12d
    xor  r14d, r14d
.rf_loop:
    cmp  r12d, [rel wgt_count]
    jae  .rf_done
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], 0
    je   .rf_next
    cmp  [rbx + WGI_WIN], r13d
    jne  .rf_next
    mov  eax, r13d
    lea  rcx, [rel wm_x]
    mov  edx, [rcx + rax*4]
    add  edx, WGT_PAD_X
    mov  [rbx + WGI_X], edx
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    add  edx, WGT_PAD_Y
    mov  eax, r14d
    imul eax, WGT_PITCH
    add  edx, eax
    mov  [rbx + WGI_Y], edx
    inc  r14d
.rf_next:
    inc  r12d
    jmp  .rf_loop
.rf_done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Retire boot-proof widgets when the old A/B floor slots enter the F1 pool.
wgt_retire_window_widgets:
    push r12
    push r13
    mov  r13d, edi
    xor  r12d, r12d
.rw_loop:
    cmp  r12d, [rel wgt_count]
    jae  .rw_done
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  [rax + WGI_WIN], r13d
    jne  .rw_next
    call wgt_tf_long_free               ; RCQ-38 L3c: RAX = the slot; its long value is wiped
    mov  dword [rax + WGI_TYPE], 0
    call wgt_capture_forget            ; EDI = the retired id
.rw_next:
    inc  r12d
    jmp  .rw_loop
.rw_done:
    ; B7a (2026-09-30, usage suite ROB-06/STM-04): reclaim. The table is
    ; append-only (form ids are contiguous from wgt_count), so a closed window's
    ; entries used to stay dead for the rest of the boot and the next FORMLOAD
    ; hit widget_capacity. Every free entry at the tail is returned to the
    ; allocator (the same compaction form_ephemeral_reap already performs); a
    ; free entry below a live one is reclaimed once everything above it closes.
    ; wgt_create re-initialises every field of a recycled entry.
.rw_shrink:
    mov  eax, [rel wgt_count]
    test eax, eax
    jz   .rw_focus
    dec  eax
    mov  edi, eax
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    jne  .rw_focus
    dec  dword [rel wgt_count]
    jmp  .rw_shrink
.rw_focus:
    ; the closed window's keyboard-focus record must not name a recycled id
    cmp  r13d, WM_MAX
    jae  .rw_out
    lea  rax, [rel wgt_focus_by_win]
    mov  dword [rax + r13*4], -1
.rw_out:
    pop  r13
    pop  r12
    ret

; ---------------------------------------------------------------------------
; wgt_button_draw(EDI=id) — button = filled body (h=32 default) + centered-ish
;   label, ALL via the shared primitives (fb_fill_rect + fb_draw_str_n).
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; RCQ-16 S4: shared control states. One kit-owned model that every stateful
; painter reads (button, textfield, toggle, slider, numeric), instead of a
; per-kind copy of the focus-ring rule. Hover and press are paint state only:
; they never move keyboard focus or window focus (no focus theft); focus moves
; only by Tab / Shift+Tab, a pointer press that takes it (wgt_focus_at), or a
; window focus change. Colours are the PROVISIONAL design-neutral S3/S4 tokens.
; ---------------------------------------------------------------------------

; wgt_state_of(EDI=id) -> EAX = WGT_ST_* bits. clobbers: RAX, RCX, RDX, R10
wgt_state_of:
    call wgt_slot_ptr
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jz   .enabled
    mov  eax, WGT_ST_DISABLED
    ret
.enabled:
    mov  rdx, rax
    xor  eax, eax
    cmp  edi, [rel wgt_hot_id]
    jne  .not_hot
    or   eax, WGT_ST_HOT
.not_hot:
    cmp  edi, [rel wgt_press_id]
    jne  .not_pressed
    or   eax, WGT_ST_PRESSED
.not_pressed:
    cmp  edi, [rel wgt_focus_id]
    jne  .out
    mov  ecx, [rdx + WGI_WIN]
    cmp  ecx, WGT_HOST_DESKTOP
    je   .focused
    cmp  ecx, [rel wm_focus]
    jne  .out
.focused:
    or   eax, WGT_ST_FOCUSED
    cmp  byte [rel wgt_focus_visible], 0
    je   .out
    or   eax, WGT_ST_RING
.out:
    ret

; wgt_stateful_type(ECX = WGI_TYPE) -> EAX 1 when the kind paints the S4
;   states and takes Tab (button, textfield, toggle, slider, numeric), else 0.
;   clobbers: EAX, EDX
wgt_stateful_type:
    mov  eax, 1
    cmp  ecx, 1                         ; button
    je   .out
    cmp  ecx, WGT_TYPE_TEXTFIELD
    je   .out
    mov  edx, [rel wgt_scalar_toggle_type]
    inc  edx                            ; an unregistered kind (-1) becomes 0: never a live WGI_TYPE
    cmp  ecx, edx
    je   .out
    mov  edx, [rel wgt_scalar_slider_type]
    inc  edx
    cmp  ecx, edx
    je   .out
    mov  edx, [rel wgt_scalar_numeric_type]
    inc  edx
    cmp  ecx, edx
    je   .out
    xor  eax, eax
.out:
    ret

; wgt_state_repaint(EDI = id, or -1): repaint a stateful widget (a no-op for
;   -1, an id past wgt_count or a stateless kind). A widget that a window above
;   its host overlaps is never painted alone (wgt_draw_id clips to its host
;   only, so it would cover that window): the whole desktop recomposes in z
;   order instead (srcreview S4 F1). clobbers: caller-saved.
wgt_state_repaint:
    cmp  edi, [rel wgt_count]
    jae  .out
    push rdi
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_TYPE]
    call wgt_stateful_type
    test eax, eax
    jz   .drop
    mov  edi, [rsp]
    call wgt_slot_ptr
    test dword [rax + WGI_EDIT], WGT_EDIT_HELP_ICON
    jnz  .hint_full
    call wgt_state_occluded
    pop  rdi
    test eax, eax
    jz   wgt_draw_id
.full:
    cmp  byte [rel wgt_paint_suspended], 0
    jne  .out
    jmp  wmx_draw_all
.hint_full:
    ; The public-name hint is outside the hit box. Recompose both on enter
    ; and leave, including the old backdrop, in the normal desktop z order.
    pop  rdi
    jmp  .full
.drop:
    pop  rdi
.out:
    ret

; wgt_state_occluded(EDI = id) -> EAX = 1 when something wmx_draw_all paints
;   after the widget's host overlaps the widget's painted rect (the WGI rect
;   grown by its kind's outset, wgt_geometry_min: a textfield's border is 1 px
;   proud), else 0. Painted later: the taskbar band (unless the lock surface
;   holds the session, wmx_draw_all's own test), the IME candidate window
;   (RCQ-38 I3b-1 (c), gui/window's ime_popup_overlaps), and a visible window
;   above the host. Paint order: unfocused windows by ascending z stamp (equal
;   stamps: the lower slot first), then the focused window; a desktop-hosted
;   widget is under every window. clobbers: RAX, RCX, RDX, R8, R9, R10.
wgt_state_occluded:
    push rbx
    push r12
    push r11
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + WGI_TYPE]
    call wgt_geometry_min               ; R10D = the outset painted beyond the rect
    ; RCQ-16 S4c (srcreview F2-R1): the taskbar is painted after every window
    cmp  byte [rel lock_surface_ready], 1
    jne  .band
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .windows                       ; locked: wmx_draw_all paints no taskbar
.band:
    mov  edx, [rbx + WGI_Y]
    add  edx, [rbx + WGI_H]
    add  edx, r10d                      ; painted bottom (exclusive)
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H                 ; the band's top row
    cmp  edx, eax
    jg   .hit                           ; reaches into the band
    mov  ecx, [rbx + WGI_X]             ; RCQ-38 I3b-1 (c): the IME candidate window
    add  ecx, [rbx + WGI_W]
    add  ecx, r10d                      ; painted right (exclusive)
    mov  r8d, [rbx + WGI_X]
    sub  r8d, r10d
    mov  r9d, [rbx + WGI_Y]
    sub  r9d, r10d
    call calendar_overlaps              ; month panel covers direct widget paints too
    test eax, eax
    jnz  .hit
    call ime_popup_overlaps             ; EDX is still the painted bottom; preserves all but RAX
    test eax, eax
    jnz  .hit
.windows:
    mov  r12d, [rbx + WGI_WIN]
    cmp  r12d, WM_MAX
    jb   .host
    mov  r12d, -1                       ; the desktop (or no window): every visible window is above
    jmp  .scan
.host:
    cmp  r12d, [rel wm_focus]
    je   .clear                         ; the focused window is painted last
.scan:
    xor  ecx, ecx
.next:
    cmp  ecx, WM_MAX
    jae  .clear
    cmp  ecx, r12d
    je   .skip
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .skip
    cmp  r12d, -1
    je   .above
    cmp  ecx, [rel wm_focus]
    je   .above
    lea  rax, [rel wm_zstamp]
    mov  edx, [rax + rcx*4]
    cmp  edx, [rax + r12*4]
    jb   .skip
    ja   .above
    cmp  ecx, r12d
    jb   .skip
.above:
    lea  rax, [rel wm_x]
    mov  edx, [rax + rcx*4]             ; window left
    mov  r8d, [rbx + WGI_X]
    mov  r9d, r8d
    add  r9d, [rbx + WGI_W]
    add  r9d, r10d                      ; painted right (exclusive)
    sub  r8d, r10d                      ; painted left (RCQ-16 S4c, srcreview F1-R1)
    cmp  edx, r9d
    jge  .skip                          ; window starts right of the widget
    lea  rax, [rel wm_w]
    add  edx, [rax + rcx*4]
    cmp  r8d, edx
    jge  .skip                          ; widget starts right of the window
    lea  rax, [rel wm_y]
    mov  edx, [rax + rcx*4]
    mov  r8d, [rbx + WGI_Y]
    mov  r9d, r8d
    add  r9d, [rbx + WGI_H]
    add  r9d, r10d                      ; painted bottom (exclusive)
    sub  r8d, r10d                      ; painted top
    cmp  edx, r9d
    jge  .skip                          ; window starts below the widget
    lea  rax, [rel wm_h]
    add  edx, [rax + rcx*4]
    cmp  r8d, edx
    jge  .skip                          ; widget starts below the window
.hit:
    mov  eax, 1
    jmp  .out
.skip:
    inc  ecx
    jmp  .next
.clear:
    xor  eax, eax
.out:
    pop  r11
    pop  r12
    pop  rbx
    ret

; wgt_hover_at(EDI = top window slot or -1, ESI = x, EDX = y) -> EAX = the hot
;   widget id, -1 none. wm_pointer's no-button motion. A pure rect scan, front
;   to back, of that window's visible widgets: no WT_HIT callback (a hit test
;   may act), no click hook, no focus change. On a change the old and the new
;   hot widget repaint. clobbers: caller-saved.
wgt_hover_at:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, -1
    cmp  r12d, WM_MAX
    jae  .found
    mov  ebx, [rel wgt_count]
.scan:
    test ebx, ebx
    jz   .found
    dec  ebx
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .scan
    cmp  [rax + WGI_WIN], r12d
    jne  .scan
    test dword [rax + WGI_FLAGS], 1
    jz   .scan
    call wgt_flyout_painted             ; F5-R1/R2: an overlay that is not painted is never hot
    jc   .scan
    mov  ecx, [rax + WGI_X]
    cmp  r13d, ecx
    jl   .scan
    add  ecx, [rax + WGI_W]
    cmp  r13d, ecx
    jge  .scan
    mov  ecx, [rax + WGI_Y]
    cmp  r14d, ecx
    jl   .scan
    add  ecx, [rax + WGI_H]
    cmp  r14d, ecx
    jge  .scan
    mov  r15d, ebx
.found:
    mov  eax, [rel wgt_hot_id]
    cmp  eax, r15d
    je   .out
    mov  [rel wgt_hot_id], r15d
    mov  edi, eax
    call wgt_state_repaint
    mov  edi, r15d
    call wgt_state_repaint
.out:
    mov  eax, r15d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_press_set(EDI = widget id, or -1): the widget a left press landed on
;   (wm_pointer's body press), until its release (-1). Paint state only. On a
;   change both widgets repaint. clobbers: caller-saved.
wgt_press_set:
    push rbx
    mov  eax, [rel wgt_press_id]
    cmp  eax, edi
    je   .out
    mov  ebx, edi
    mov  [rel wgt_press_id], edi
    mov  edi, eax
    call wgt_state_repaint
    mov  edi, ebx
    call wgt_state_repaint
.out:
    pop  rbx
    ret

; wgt_focus_ring_draw(EDI = id): the shared keyboard-focus ring (RCQ-16 VQ-02,
;   first the button's): GUI_FOCUS_RING_W px of GUI_TOK_FOCUS_RING inside the
;   control's rect, painted only in WGT_ST_RING (Tab gave it focus and its
;   window holds focus). clobbers: RAX, RCX, RDX.
wgt_focus_ring_draw:
    push rbx
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    call wgt_state_of
    test eax, WGT_ST_RING
    jz   .done
    call wgt_slot_ptr
    mov  r12, rax
    mov  ebx, GUI_TOK_FOCUS_RING
    mov  r8d, [r12 + WGI_X]
    mov  r9d, [r12 + WGI_Y]
    mov  r10d, [r12 + WGI_W]
    mov  r11d, GUI_FOCUS_RING_W
    call fb_fill_rect                   ; top
    add  r9d, [r12 + WGI_H]
    sub  r9d, GUI_FOCUS_RING_W
    call fb_fill_rect                   ; bottom
    mov  r9d, [r12 + WGI_Y]
    mov  r10d, GUI_FOCUS_RING_W
    mov  r11d, [r12 + WGI_H]
    call fb_fill_rect                   ; left
    add  r8d, [r12 + WGI_W]
    sub  r8d, GUI_FOCUS_RING_W
    call fb_fill_rect                   ; right
.done:
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rbx
    ret

; wgt_button_palette(EDI = id) -> EBX outline, ECX fill, EDX label colour for
;   the button's state: disabled > pressed > hover > normal; EAX = its WGT_ST_*
;   bits. clobbers: RAX.
wgt_button_palette:
    push r10
    call wgt_state_of
    mov  ebx, WGT_BTN_BRD
    mov  ecx, WGT_BTN_BG
    mov  edx, WGT_BTN_FG
    test eax, WGT_ST_DISABLED
    jz   .enabled
    mov  ebx, GUI_TOK_DISABLED_BORDER
    mov  edx, GUI_TOK_DISABLED_TEXT
    jmp  .out
.enabled:
    test eax, WGT_ST_PRESSED
    jz   .not_pressed
    mov  ecx, GUI_TOK_CONTROL_PRESSED
    jmp  .out
.not_pressed:
    test eax, WGT_ST_HOT
    jz   .out
    mov  ebx, GUI_TOK_CONTROL_BORDER_HOVER
    mov  ecx, GUI_TOK_CONTROL_HOVER
.out:
    pop  r10
    ret

wgt_button_draw:
    push rbx
    push rcx
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    call wgt_slot_ptr
    mov  r12, rax
    call wgt_button_palette             ; RCQ-16 S4: EBX outline, ECX fill, EDX label for the state
    mov  r8d, [r12 + WGI_X]
    mov  r9d, [r12 + WGI_Y]
    mov  r10d, [r12 + WGI_W]
    mov  r11d, [r12 + WGI_H]
    call fb_fill_rect                   ; RCQ-16 S3: outline, then the body 1 px inside it
    cmp  r10d, 2                        ; a slot under 3 px stays all outline (no u32 wrap)
    jbe  .body_done
    cmp  r11d, 2
    jbe  .body_done
    inc  r8d
    inc  r9d
    sub  r10d, 2
    sub  r11d, 2
    mov  edi, [rsp + 40]
    call wgt_button_palette
    mov  ebx, ecx                       ; the state's fill
    call fb_fill_rect
.body_done:
    test dword [r12 + WGI_EDIT], WGT_EDIT_HELP_ICON
    jnz  .help_icon
    test dword [r12 + WGI_EDIT], WGT_EDIT_ARROW
    jz   .accent
    mov  edi, [rsp + 40]
    call wgt_button_palette
    mov  ebx, edx
    call wgt_button_arrow_draw
    jmp  .focus_ring
.accent:
    test dword [r12 + WGI_EDIT], WGT_EDIT_ACCENT
    jz   .label
    mov  r8d, [r12 + WGI_X]
    mov  eax, [r12 + WGI_W]
    sub  eax, 8
    shr  eax, 1
    add  r8d, eax
    mov  r9d, [r12 + WGI_Y]
    mov  eax, [r12 + WGI_H]
    sub  eax, 12
    shr  eax, 1
    add  r9d, eax
    mov  r10d, 8
    mov  r11d, 12
    mov  ebx, GUI_TOK_ACCENT
    call fb_fill_rect
    mov  r8d, [r12 + WGI_X]
    mov  eax, [r12 + WGI_W]
    sub  eax, 12
    shr  eax, 1
    add  r8d, eax
    mov  r9d, [r12 + WGI_Y]
    mov  eax, [r12 + WGI_H]
    sub  eax, 8
    shr  eax, 1
    add  r9d, eax
    mov  r10d, 12
    mov  r11d, 8
    mov  ebx, GUI_TOK_ACCENT
    call fb_fill_rect
    jmp  .focus_ring                    ; RCQ-16 F2: an icon button shows keyboard focus too
.help_icon:
    mov  edi, [rsp + 40]
    call wgt_button_palette
    mov  ebx, edx
    call wgt_button_help_icon_draw
    mov  edi, [rsp + 40]
    call wgt_state_of
    test eax, WGT_ST_DISABLED
    jnz  .focus_ring
    test eax, WGT_ST_HOT | WGT_ST_RING
    jz   .focus_ring
    mov  edi, [rsp + 40]
    call wgt_button_palette
    mov  r8d, [r12 + WGI_X]
    sub  r8d, 128
    mov  r9d, [r12 + WGI_Y]
    add  r9d, 36
    mov  r10d, 288
    mov  r11d, 28
    call fb_fill_rect
    inc  r8d
    inc  r9d
    sub  r10d, 2
    sub  r11d, 2
    mov  ebx, ecx
    call fb_fill_rect
    mov  edi, [rsp + 40]
    call wgt_button_palette
    mov  ebx, edx
    mov  r8d, [r12 + WGI_X]
    sub  r8d, 118                       ; panel + 10
    mov  r9d, [r12 + WGI_Y]
    add  r9d, 42                        ; panel + 6
    mov  r11d, 33
    jmp  .label_text
.label:
    mov  edi, [rsp + 40]
    call wgt_button_palette
    mov  ebx, edx                       ; label colour on the state's fill (ECX)
    mov  r8d, [r12 + WGI_X]
    add  r8d, 10
    mov  r9d, [r12 + WGI_Y]
    add  r9d, 8
    mov  r11d, [r12 + WGI_W]
    sub  r11d, 20
    shr  r11d, 3                       ; max chars that fit the body
.label_text:
    lea  rdi, [r12 + WGI_VAL]
    push rsi
    sub  rsp, WGT_SEC_TEXT_MAX
    mov  rsi, rsp
    call wgt_sec_text                   ; RCQ-38 L3a: a security surface paints the escaped copy
    call wgt_public_text_draw
    add  rsp, WGT_SEC_TEXT_MAX
    pop  rsi
.focus_ring:
    ; RCQ-16 VQ-02: keyboard focus on a button is visible (the shared ring, S4).
    mov  edi, [rsp + 40]
    call wgt_focus_ring_draw
.done:
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rcx
    pop  rbx
    ret

; R12 = button row, EBX/ECX = state foreground/background. No input or
; authority transition; the inline public name remains available unchanged.
wgt_button_help_icon_draw:
    cmp  dword [r12 + WGI_W], 8
    jb   .out
    cmp  dword [r12 + WGI_H], 16
    jb   .out
    mov  r8d, [r12 + WGI_W]
    shr  r8d, 1
    add  r8d, [r12 + WGI_X]
    sub  r8d, 4
    mov  r9d, [r12 + WGI_H]
    shr  r9d, 1
    add  r9d, [r12 + WGI_Y]
    sub  r9d, 8
    mov  edx, '?'
    call wgt_draw_glyph
.out:
    ret

; ---------------------------------------------------------------------------
; R12 = button row, EBX = state foreground. The shared pixel primitive keeps
; the icon on the same logical grid as its hit rectangle and focus ring.
wgt_button_arrow_draw:
    push r13
    push r14
    push r15
    cmp  dword [r12 + WGI_W], 20
    jb   .out
    cmp  dword [r12 + WGI_H], 20
    jb   .out
    mov  r14d, [r12 + WGI_W]
    shr  r14d, 1
    add  r14d, [r12 + WGI_X]
    mov  r15d, [r12 + WGI_H]
    shr  r15d, 1
    add  r15d, [r12 + WGI_Y]
    lea  r8d, [r14d - 8]
    mov  r9d, r15d
    mov  r10d, 15
    mov  r11d, 2
    call fb_fill_rect
    xor  r13d, r13d
.head:
    lea  r8d, [r14d + 6]
    sub  r8d, r13d
    mov  r9d, r15d
    sub  r9d, r13d
    mov  r10d, 2
    mov  r11d, 2
    call fb_fill_rect
    mov  r9d, r15d
    add  r9d, r13d
    call fb_fill_rect
    inc  r13d
    cmp  r13d, 7
    jb   .head
.out:
    pop  r15
    pop  r14
    pop  r13
    ret

; wgt_textfield_draw(EDI=id) — textfield = 1px border + light field strip
;   (h=28 default) + value text, via the SAME shared primitives.
; ---------------------------------------------------------------------------
wgt_textfield_draw:
    push rbx
    push rcx
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    call wgt_slot_ptr
    mov  r12, rax
    ; border (one pixel proud on every side). RCQ-16 S4: hover brightens it, disabled fades it
    call wgt_state_of
    mov  ebx, WGT_TF_BRD
    test eax, WGT_ST_DISABLED
    jz   .border_enabled
    mov  ebx, GUI_TOK_DISABLED_BORDER
    jmp  .border
.border_enabled:
    test eax, WGT_ST_HOT
    jz   .border
    mov  ebx, GUI_TOK_CONTROL_BORDER_HOVER
.border:
    mov  r8d, [r12 + WGI_X]
    dec  r8d
    mov  r9d, [r12 + WGI_Y]
    dec  r9d
    mov  r10d, [r12 + WGI_W]
    add  r10d, 2
    mov  r11d, [r12 + WGI_H]
    add  r11d, 2
    call fb_fill_rect
    ; field strip
    mov  r8d, [r12 + WGI_X]
    mov  r9d, [r12 + WGI_Y]
    mov  r10d, [r12 + WGI_W]
    mov  r11d, [r12 + WGI_H]
    mov  ebx, WGT_TF_BG
    call fb_fill_rect
    ; value text (field repaint above clears stale glyphs on shrink)
    mov  r8d, [r12 + WGI_X]
    add  r8d, 6
    mov  r9d, [r12 + WGI_Y]
    add  r9d, 6
    mov  ebx, WGT_TF_FG
    test dword [r12 + WGI_EDIT], WGT_EDIT_DISABLED
    jz   .value_colour
    mov  ebx, GUI_TOK_DISABLED_TEXT     ; RCQ-16 S4: an inactive field's value
.value_colour:
    mov  rax, r12
    call wgt_tf_buf                     ; RCQ-38 L3c: the value through its accessor
    mov  rdi, rax
    mov  ecx, WGT_TF_BG
    mov  r11d, [r12 + WGI_W]
    sub  r11d, 12
    test dword [r12 + WGI_EDIT], WGT_EDIT_INSET_ACTION
    jz   .value_width
    sub  r11d, 40
    jns  .value_width
    xor  r11d, r11d
.value_width:
    shr  r11d, 3
    mov  edx, [rsp + 40]
    call wgt_tf_unicode_draw            ; RCQ-38 L3b: text >= U+0080 or a pre-edit -> painted there, caret too
    test eax, eax
    jnz  .no_caret
    call fb_draw_str_n
    ; Inverted glyph cell through the shared text engine; WGI_VAL remains the
    ; sole text state. A disabled field shows no caret (it takes no edit).
    test dword [r12 + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .no_caret
    mov  eax, [rel wgt_focus_id]
    cmp  eax, [rsp + 40]
    jne  .no_caret
    cmp  dword [r12 + WGI_WIN], WGT_HOST_DESKTOP
    je   .caret_owner_ok
    mov  eax, [rel wm_focus]
    cmp  eax, [r12 + WGI_WIN]
    jne  .no_caret
.caret_owner_ok:
    mov  eax, [r12 + WGI_W]
    sub  eax, 12
    test dword [r12 + WGI_EDIT], WGT_EDIT_INSET_ACTION
    jz   .caret_width
    sub  eax, 40
    js   .no_caret
.caret_width:
    shr  eax, 3
    mov  edx, [r12 + WGI_CARET]
    cmp  edx, eax
    jae  .no_caret
    mov  r8d, [r12 + WGI_X]
    add  r8d, 6
    mov  eax, edx
    shl  eax, 3
    add  r8d, eax
    mov  r9d, [r12 + WGI_Y]
    add  r9d, 6
    mov  rax, r12
    call wgt_tf_buf
    movzx edx, byte [rax + rdx]
    test dl, dl
    jnz  .caret_char
    mov  dl, ' '
.caret_char:
    mov  ebx, WGT_TF_BG
    mov  ecx, WGT_TF_FG
    call wgt_draw_glyph
.no_caret:
    mov  edi, [rsp + 40]
    call wgt_textfield_action_draw
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rcx
    pop  rbx
    ret

; R12 = field row, EDI = field id. An inset button remains an ordinary named
; button with its own hit/focus/activation. Repaint it after EVERY field draw,
; including typing, caret, hover and partial presents. Never inspect a secret.
; Malformed associations cannot paint another host or outside the field lane.
wgt_textfield_action_draw:
    test dword [r12 + WGI_EDIT], WGT_EDIT_INSET_ACTION
    jz   .out
    call wgt_focus_ring_draw
    mov  edi, [r12 + WGI_EDITPAD]
    sub  edi, 1
    jc   .out
    cmp  edi, [rel wgt_count]
    jae  .out
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_BUTTON
    jne  .out
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, [r12 + WGI_WIN]
    jne  .out
    mov  ecx, [r12 + WGI_X]
    add  ecx, [r12 + WGI_W]
    mov  edx, ecx
    sub  edx, 40
    cmp  [rax + WGI_X], edx
    jl   .out
    mov  edx, [rax + WGI_W]
    test edx, edx
    jle  .out
    add  edx, [rax + WGI_X]
    jo   .out
    cmp  edx, ecx
    jg   .out
    mov  ecx, [r12 + WGI_Y]
    cmp  [rax + WGI_Y], ecx
    jl   .out
    add  ecx, [r12 + WGI_H]
    mov  edx, [rax + WGI_H]
    test edx, edx
    jle  .out
    add  edx, [rax + WGI_Y]
    jo   .out
    cmp  edx, ecx
    jg   .out
    jmp  wgt_draw_id
.out:
    ret

; wgt_tf_caret_shown(R12 = textfield slot, EDX = its id) -> EAX 1 when the field
;   shows its caret: enabled, the focused widget, and on the desktop or in the
;   focused window (wgt_textfield_draw's rule). RCQ-38 L3b. Clobbers EAX only.
wgt_tf_caret_shown:
    xor  eax, eax
    test dword [r12 + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .out
    cmp  edx, [rel wgt_focus_id]
    jne  .out
    cmp  dword [r12 + WGI_WIN], WGT_HOST_DESKTOP
    je   .yes
    mov  eax, [rel wm_focus]
    cmp  eax, [r12 + WGI_WIN]
    mov  eax, 0
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; wgt_tf_preedit_live(R12 = textfield slot, EDX = its id) -> EAX = the pre-edit
;   length this field shows, 0 none. It shows only while the field is the one
;   that took it, has the caret, and no lock or unlock happened since
;   (session_authority_epoch); otherwise the pre-edit is dropped here. Clobbers
;   EAX only.
wgt_tf_preedit_live:
    lea  eax, [rdx + 1]
    cmp  eax, [rel wgt_preedit_id]
    jne  .none
    call wgt_tf_caret_shown
    test eax, eax
    jz   .drop
    push rcx
    mov  rcx, [rel session_authority_epoch]
    cmp  rcx, [rel wgt_preedit_epoch]
    pop  rcx
    jne  .drop
    mov  eax, [rel wgt_preedit_len]
    ret
.drop:
    mov  dword [rel wgt_preedit_id], 0
.none:
    xor  eax, eax
    ret

TFD_X     equ 0                         ; wgt_tf_unicode_draw's frame
TFD_Y     equ 4
TFD_FG    equ 8
TFD_BG    equ 12
TFD_LEFT  equ 16                        ; cells left
TFD_OFF   equ 20                        ; display offset of the next scalar
TFD_CARET equ 24                        ; display offset of the caret, -1 none
TFD_CX    equ 28                        ; the caret cell's x, -1 not reached
TFD_CCP   equ 32                        ; the scalar under the caret
TFD_CW    equ 36                        ; its cells
TFD_DEC   equ 40                        ; ue_utf8_decode {scalar, bytes}
TFD_UL    equ 48                        ; 1 = the run is the pre-edit (underlined)
TFD_VAL   equ 56                        ; the value bytes (wgt_tf_buf), RCQ-38 L3c
TFD_SZ    equ 72                        ; 12 pushes + TFD_SZ keep RSP 16-aligned for ue_*

; wgt_tf_unicode_draw(R12 = textfield slot, EDX = its id, R8D/R9D = text x/y,
;   EBX = fg, ECX = bg, R11D = cells) -> EAX 0: WGI_VAL is ASCII and no pre-edit
;   shows, nothing drawn, every other register kept (the caller paints the
;   plain way). EAX 1: the value painted scalar by scalar: U+0000..U+017F from
;   the font, a wider scalar as a boxed placeholder of its ue_cell_width cells,
;   width 0 marks drawn as nothing; the pre-edit, underlined, at the caret; the
;   caret as the inverted cell(s) of the cluster under it. RCQ-38 L3b, DESIGN B2.
;   Preserves every register but RAX.
wgt_tf_unicode_draw:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r13
    push r14
    push rbp
    sub  rsp, TFD_SZ
    mov  rbp, rsp
    mov  [rbp + TFD_X], r8d
    mov  [rbp + TFD_Y], r9d
    mov  [rbp + TFD_FG], ebx
    mov  [rbp + TFD_BG], ecx
    mov  [rbp + TFD_LEFT], r11d
    mov  r13d, edx                      ; id
    mov  rax, r12
    call wgt_tf_buf
    mov  [rbp + TFD_VAL], rax
    call wgt_tf_preedit_live
    mov  r14d, eax                      ; pre-edit bytes shown
    test eax, eax
    jnz  .paint
    mov  ecx, [r12 + WGI_VLEN]
    mov  rsi, [rbp + TFD_VAL]
    xor  eax, eax
.scan:
    cmp  eax, ecx
    jae  .plain
    cmp  byte [rsi + rax], 0x80
    jae  .paint
    inc  eax
    jmp  .scan
.plain:
    xor  eax, eax
    jmp  .out
.paint:
    xor  eax, eax
    mov  [rbp + TFD_OFF], eax
    mov  dword [rbp + TFD_CX], -1
    mov  dword [rbp + TFD_CARET], -1
    mov  ebx, [r12 + WGI_CARET]         ; EBX = the value's split point
    cmp  ebx, [r12 + WGI_VLEN]
    jbe  .split
    mov  ebx, [r12 + WGI_VLEN]
.split:
    mov  edx, r13d
    call wgt_tf_caret_shown
    test eax, eax
    jz   .runs
    mov  eax, ebx
    test r14d, r14d
    jz   .caret_at
    add  eax, [rel wgt_preedit_caret]   ; with a pre-edit the caret is the IME's
.caret_at:
    mov  [rbp + TFD_CARET], eax
.runs:
    mov  rsi, [rbp + TFD_VAL]
    mov  edx, ebx
    xor  ecx, ecx
    call wgt_tf_run                     ; value before the caret
    lea  rsi, [rel wgt_preedit_buf]
    mov  edx, r14d
    mov  ecx, 1
    call wgt_tf_run                     ; the pre-edit
    mov  esi, ebx
    add  rsi, [rbp + TFD_VAL]
    mov  edx, [r12 + WGI_VLEN]
    sub  edx, ebx
    xor  ecx, ecx
    call wgt_tf_run                     ; the rest of the value
    cmp  dword [rbp + TFD_CARET], -1
    je   .done
    cmp  dword [rbp + TFD_CX], -1
    jne  .caret
    cmp  dword [rbp + TFD_LEFT], 1      ; the caret after the text: a blank cell, if one is left
    jb   .done
    mov  eax, [rbp + TFD_X]
    mov  [rbp + TFD_CX], eax
    mov  dword [rbp + TFD_CCP], ' '
    mov  dword [rbp + TFD_CW], 1
.caret:
    mov  r8d, [rbp + TFD_CX]
    mov  r9d, [rbp + TFD_Y]
    mov  edx, [rbp + TFD_CCP]
    cmp  edx, FONT8X16_SCALARS
    jae  .caret_box
    mov  ebx, [rbp + TFD_BG]            ; inverted cell
    mov  ecx, [rbp + TFD_FG]
    call fb_draw_scalar
    jmp  .done
.caret_box:
    mov  r10d, [rbp + TFD_CW]
    shl  r10d, 3
    mov  r11d, 16
    mov  ebx, [rbp + TFD_FG]
    call fb_fill_rect
.done:
    mov  eax, 1
.out:
    add  rsp, TFD_SZ
    pop  rbp
    pop  r14
    pop  r13
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; wgt_tf_run(RBP = wgt_tf_unicode_draw's frame, RSI = UTF-8, EDX = length,
;   ECX = 1 underlined): paints the run's scalars at TFD_X while cells are left
;   (a scalar that does not fit ends the field: TFD_LEFT becomes 0), records the
;   caret's cell when TFD_OFF reaches TFD_CARET, advances TFD_OFF by every byte
;   (bytes that are not UTF-8 draw one placeholder cell each). Clobbers
;   caller-saved.
wgt_tf_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  [rbp + TFD_UL], ecx
    xor  r14d, r14d                     ; offset in the run
.next:
    cmp  r14d, r13d
    jae  .out
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r14d
    lea  rcx, [rbp + TFD_DEC]
    call ue_utf8_decode
    cmp  eax, 1
    je   .decoded
    mov  dword [rbp + TFD_DEC], 0xFFFD  ; not UTF-8: one byte, one boxed cell
    mov  dword [rbp + TFD_DEC + 4], 1
.decoded:
    mov  ebx, [rbp + TFD_DEC]           ; EBX = scalar
    mov  r15d, 1                        ; R15D = cells
    cmp  ebx, 0x80
    jb   .width
    mov  edi, ebx
    call ue_cell_width
    mov  r15d, eax
    test eax, eax
    jns  .width
    mov  r15d, 1                        ; no width class: one boxed cell
.width:
    mov  eax, r15d
    test eax, eax
    jnz  .fit
    inc  eax                            ; a width-0 mark under the caret shows one cell
.fit:
    cmp  eax, [rbp + TFD_LEFT]
    jbe  .caret
    mov  dword [rbp + TFD_LEFT], 0      ; the field is full
    mov  eax, [rbp + TFD_OFF]
    cmp  eax, [rbp + TFD_CARET]
    ja   .out                           ; the caret's cell is already recorded
    mov  dword [rbp + TFD_CARET], -1    ; a caret past the visible cells is not shown
    jmp  .out
.caret:
    mov  ecx, [rbp + TFD_OFF]
    cmp  ecx, [rbp + TFD_CARET]
    jne  .drawn
    cmp  dword [rbp + TFD_CX], -1
    jne  .drawn
    mov  ecx, [rbp + TFD_X]
    mov  [rbp + TFD_CX], ecx
    mov  [rbp + TFD_CCP], ebx
    mov  [rbp + TFD_CW], eax
.drawn:
    test r15d, r15d
    jz   .advance                       ; a width-0 mark: kept in the value, not drawn
.draw:
    mov  r8d, [rbp + TFD_X]
    mov  r9d, [rbp + TFD_Y]
    cmp  ebx, FONT8X16_SCALARS
    jae  .box
    mov  edx, ebx
    mov  ebx, [rbp + TFD_FG]
    mov  ecx, [rbp + TFD_BG]
    call fb_draw_scalar
    jmp  .underline
.box:
    ; a hollow box of the scalar's cells: fg 1 px proud of a bg core
    lea  r10d, [r15*8 - 2]
    inc  r8d
    add  r9d, 2
    mov  r11d, 12
    mov  ebx, [rbp + TFD_FG]
    call fb_fill_rect
    lea  r10d, [r15*8 - 4]
    inc  r8d
    inc  r9d
    mov  r11d, 10
    mov  ebx, [rbp + TFD_BG]
    call fb_fill_rect
.underline:
    cmp  dword [rbp + TFD_UL], 0
    je   .moved
    mov  r8d, [rbp + TFD_X]
    mov  r9d, [rbp + TFD_Y]
    add  r9d, 15
    lea  r10d, [r15*8]
    mov  r11d, 1
    mov  ebx, [rbp + TFD_FG]
    call fb_fill_rect
.moved:
    lea  eax, [r15*8]
    add  [rbp + TFD_X], eax
    sub  [rbp + TFD_LEFT], r15d
.advance:
    mov  eax, [rbp + TFD_DEC + 4]
    add  r14d, eax
    add  [rbp + TFD_OFF], eax
    jmp  .next
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_textfield_preedit(EDI = textfield id, RSI = UTF-8, EDX = length, ECX =
;   the IME caret's byte offset in it) -> EAX 0 shown (length 0: cleared) /
;   1 refused. RCQ-38 L3b, DESIGN B2: the seam the IME (I3b) drives. The
;   composition shows at the field's caret, underlined, and is never stored in
;   WGI_VAL. One field holds it; it shows only while that field has the caret
;   and no lock or unlock happened since (wgt_tf_preedit_live), and a commit
;   into the field (GUI_KEY_TEXT) or wgt_create of the id drops it. Refused: an
;   id outside the table, not the focused widget, not a textfield, disabled,
;   WGT_EDIT_ASCII, length > WGT_TEXT_CAP, bytes that are not UTF-8 or hold a
;   control, or a caret off their grapheme boundaries. Clobbers caller-saved.
wgt_textfield_preedit:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rsi
    mov  r14d, edx
    mov  ebx, ecx
    test r14d, r14d
    jnz  .check
    lea  eax, [r12 + 1]
    cmp  eax, [rel wgt_preedit_id]
    jne  .ok
    mov  dword [rel wgt_preedit_id], 0
    jmp  .repaint
.check:
    cmp  r12d, [rel wgt_count]
    jae  .bad
    cmp  r12d, [rel wgt_focus_id]
    jne  .bad
    cmp  r14d, WGT_TEXT_CAP
    ja   .bad
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .bad
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED | WGT_EDIT_ASCII
    jnz  .bad
    mov  rdi, r13
    mov  esi, r14d
    mov  edx, ebx
    call ue_grapheme_next               ; -1: not UTF-8, or the caret is not a boundary
    test rax, rax
    js   .bad
    mov  rsi, r13
    mov  ecx, r14d
    call wgt_utf8_controls
    jnz  .bad
    lea  rdi, [rel wgt_preedit_buf]
    mov  rsi, r13
    mov  ecx, r14d
    rep  movsb
    mov  [rel wgt_preedit_len], r14d
    mov  [rel wgt_preedit_caret], ebx
    mov  rax, [rel session_authority_epoch]
    mov  [rel wgt_preedit_epoch], rax
    lea  eax, [r12 + 1]
    mov  [rel wgt_preedit_id], eax
.repaint:
    mov  edi, r12d
    call wgt_draw_id
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; label: transparent/body-token text, registered as the third ordinary type.
wgt_label_draw:
    push rbx
    push rcx
    push rdi
    push r8
    push r9
    push r11
    push r12
    call wgt_slot_ptr
    mov  r12, rax
    mov  r8d, [r12 + WGI_X]
    mov  r9d, [r12 + WGI_Y]
    mov  ebx, GUI_TOK_LABEL_TEXT
    test dword [r12 + WGI_EDIT], WGT_EDIT_WARNING
    jz .ordinary_label
    mov  ebx, GUI_TOK_WARNING_TEXT
.ordinary_label:
    mov  ecx, GUI_TOK_LABEL_BG
    mov  r11d, [r12 + WGI_W]
    shr  r11d, 3
    lea  rdi, [r12 + WGI_VAL]
    push rsi
    sub  rsp, WGT_SEC_TEXT_MAX
    mov  rsi, rsp
    call wgt_sec_text                   ; RCQ-38 L3a: a security surface paints the escaped copy
    call wgt_public_text_draw
    add  rsp, WGT_SEC_TEXT_MAX
    pop  rsi
    pop  r12
    pop  r11
    pop  r9
    pop  r8
    pop  rdi
    pop  rcx
    pop  rbx
    ret

; Only stock label/button paint reaches this native callback, AFTER escaping
; and form-space conversion. A standalone kit retains its ordinary painter.
; The callback must admit fixed public records; it cannot confer trust on an
; arbitrary inline value. Secret fields never pass through this entry.
wgt_public_text_draw:
    mov  rax, [rel wgt_text_paint_hook]
    test rax, rax
    jz   .native
    jmp  rax
.native:
    jmp  fb_draw_str_n

; wgt_sec_text(R12 = widget slot, RDI = its text, RSI = WGT_SEC_TEXT_MAX bytes)
;   -> RDI = the text to paint. RCQ-38 L3a (rc-sec N1, 2026-10-10 10:56:48): a
;   label or button on a security surface paints sec_text_escape's copy (built
;   at RSI): any widget whose host slot is WM_OWNER_CHROME (the lock form, the
;   owner action card, every chrome form) and any widget marked
;   WGT_EDIT_SECTEXT (the Power confirmation, start_programs). Other surfaces
;   keep their bytes (N1 (4)). A label or button still showing its form
;   declaration (WGT_EDIT_FORMTEXT) paints a copy with every '_' as a space
;   (escaped first only where the rule above escapes; otherwise the bytes are
;   copied unchanged): form text cannot hold spaces, so Sign_in_to_your_keep reads as words,
;   the rule window titles already follow (wmx_title_display, B3). WGI_VAL,
;   WINTREE and every readout keep the declared bytes; only pixels change.
;   Preserves every register except RDI and RAX.
wgt_sec_text:
    test dword [r12 + WGI_EDIT], WGT_EDIT_SECTEXT
    jnz  .escape
    mov  eax, [r12 + WGI_WIN]
    cmp  eax, WM_MAX
    jae  .plain                         ; the desktop host is not chrome
    push rcx
    lea  rcx, [rel wm_owner]
    cmp  qword [rcx + rax*8], WM_OWNER_CHROME
    pop  rcx
    jne  .plain
.escape:
    push rcx
    push rdx
    push rsi
    xchg rsi, rdi                       ; RSI = the text, RDI = the copy
    mov  edx, WGT_TEXTFIELD_VAL_MAX + 1 ; WGI_VAL is NUL-ended inside its 40 bytes
    mov  ecx, WGT_SEC_TEXT_MAX
    call sec_text_escape                ; EAX = bytes before the NUL
    jmp  .form_spaces
.plain:
    test dword [r12 + WGI_EDIT], WGT_EDIT_FORMTEXT
    jz   .out                           ; RDI stays the text itself
    push rcx
    push rdx
    push rsi
    xchg rsi, rdi                       ; RSI = the text, RDI = the copy (bytes unchanged)
    xor  eax, eax
.copy:
    cmp  eax, WGT_TEXTFIELD_VAL_MAX
    jae  .copied
    mov  cl, [rsi + rax]
    test cl, cl
    jz   .copied
    mov  [rdi + rax], cl
    inc  eax
    jmp  .copy
.copied:
    mov  byte [rdi + rax], 0            ; EAX = bytes before the NUL
.form_spaces:
    test dword [r12 + WGI_EDIT], WGT_EDIT_FORMTEXT
    jz   .escaped
    xor  ecx, ecx
.space:
    cmp  ecx, eax
    jae  .escaped
    cmp  byte [rdi + rcx], '_'
    jne  .space_next
    mov  byte [rdi + rcx], ' '
.space_next:
    inc  ecx
    jmp  .space
.escaped:
    pop  rsi
    pop  rdx
    pop  rcx
.out:
    ret

; wgt_mark_sectext(EDI = widget id): its label/button text is a security
;   surface from now on (wgt_sec_text). wgt_create clears WGI_EDIT, so the mark
;   never outlives the widget. Preserves every register.
wgt_mark_sectext:
    cmp  edi, [rel wgt_count]
    jae  .out
    push rax
    push r10
    call wgt_slot_ptr
    or   dword [rax + WGI_EDIT], WGT_EDIT_SECTEXT
    pop  r10
    pop  rax
.out:
    ret

; wgt_mark_formtext(EDI = widget id): the form loader's declared text is on a
;   label or button; it paints with '_' as a space until runtime text replaces
;   it (wgt_set_text clears the mark). Other types keep WGI_EDIT for their own
;   state (progress rate, chart slot), so they are never marked. wgt_create
;   clears WGI_EDIT. Preserves every register.
wgt_mark_formtext:
    cmp  edi, [rel wgt_count]
    jae  .out
    push rax
    push r10
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_BUTTON
    je   .mark
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_LABEL
    jne  .done
.mark:
    or   dword [rax + WGI_EDIT], WGT_EDIT_FORMTEXT
.done:
    pop  r10
    pop  rax
.out:
    ret

; wgt_mark_ascii(EDI = textfield id): the field holds 0x20..0x7E only; text
;   >= U+0080 is refused (counted) and a WIDGETSET of it is a bad value.
;   RCQ-38 L3b (console.input, the sign-in user name). Preserves every register.
wgt_mark_ascii:
    cmp  edi, [rel wgt_count]
    jae  .out
    push rax
    push r10
    call wgt_slot_ptr
    or   dword [rax + WGI_EDIT], WGT_EDIT_ASCII
    pop  r10
    pop  rax
.out:
    ret

; ---------------------------------------------------------------------------
; wgt_rect_hittest(EDI=id, ESI=px, EDX=py) -> EAX = 1 inside / 0 outside.
;   The rect hit-test both v1 types share (each type's WT_HIT slot points here;
;   a sprite/irregular type overrides with its own fn — the vtable seam).
; ---------------------------------------------------------------------------
wgt_rect_hittest:
    push rbx
    call wgt_slot_ptr
    mov  rbx, rax
    xor  eax, eax
    mov  ecx, [rbx + WGI_X]
    cmp  esi, ecx
    jl   .out
    add  ecx, [rbx + WGI_W]
    cmp  esi, ecx
    jge  .out
    mov  ecx, [rbx + WGI_Y]
    cmp  edx, ecx
    jl   .out
    add  ecx, [rbx + WGI_H]
    cmp  edx, ecx
    jge  .out
    mov  eax, 1
.out:
    pop  rbx
    ret

; Body-pointer hit testing is deliberately table-driven: scan the selected
; window's widgets front-to-back and invoke the registered WT_HIT callback.
; EAX returns widget-id+1 for the topmost hit, zero for empty body space.  The
; WM owns interaction dispatch so this base registry stays type-agnostic.
wgt_pointer_hit_dispatch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, [rel wgt_count]
.scan:
    test r15d, r15d
    jz   .empty
    dec  r15d
    mov  edi, r15d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], 0
    je   .scan
    cmp  dword [rbx + WGI_WIN], r12d
    jne  .scan
    test dword [rbx + WGI_FLAGS], 1
    jz   .scan
    cmp  r12d, WGT_HOST_DESKTOP          ; the palette paints above windows: never under this path
    jne  .hit_layer
    cmp  dword [rbx + WGI_LAYER], 0
    jne  .scan
.hit_layer:
    mov  rax, rbx
    call wgt_flyout_painted             ; F5-R1/R2: an overlay that is not painted takes no press
    jc   .scan
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    imul rax, rax, WT_SZ
    lea  rcx, [rel wgt_types]
    mov  rax, [rcx + rax + WT_HIT]
    test rax, rax
    jz   .scan
    mov  edi, r15d
    mov  esi, r13d
    mov  edx, r14d
    call rax
    test eax, eax
    jz   .scan
    mov  rax, [rel wgt_form_event_hook]
    test rax, rax
    jz   .stock_click
    mov  edi, r15d
    call rax
.stock_click:
    mov  rax, [rel wgt_click_hook]
    test rax, rax
    jz   .no_click_hook
    mov  edi, r15d
    call rax
.no_click_hook:
    mov  eax, r15d
    inc  eax
    jmp  .out
.empty:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_pointer_capture_find(EDI = window slot, ESI = x, EDX = y) -> EAX widget
;   id+1 of the topmost widget there whose type opted in to middle/right
;   capture (wgt_type_capture_buttons) and bound a capture, 0 none. Side-effect
;   free for a non-left press: only such a type's WT_HIT runs, and never
;   wgt_click_hook (that is wgt_pointer_hit_dispatch's left-click path).
wgt_pointer_capture_find:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, [rel wgt_count]
.scan:
    test r15d, r15d
    jz   .none
    dec  r15d
    mov  edi, r15d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + WGI_TYPE]
    test eax, eax
    jz   .scan
    cmp  dword [rbx + WGI_WIN], r12d
    jne  .scan
    test dword [rbx + WGI_FLAGS], 1
    jz   .scan
    push rax
    mov  rax, rbx
    call wgt_flyout_painted             ; F5-R1/R2
    pop  rax
    jc   .scan
    dec  eax
    cmp  eax, [rel wgt_type_count]
    jae  .scan
    lea  rcx, [rel wgt_type_capture_btns]
    cmp  byte [rcx + rax], 0
    je   .scan                          ; left-only type: never offered a middle/right press
    lea  rcx, [rel wgt_type_capture]
    cmp  qword [rcx + rax*8], 0
    je   .scan
    imul rax, rax, WT_SZ
    lea  rcx, [rel wgt_types]
    mov  rax, [rcx + rax + WT_HIT]
    test rax, rax
    jz   .scan
    mov  edi, r15d
    mov  esi, r13d
    mov  edx, r14d
    call rax
    test eax, eax
    jz   .scan
    mov  eax, r15d
    inc  eax
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- per-type SET-field: validate the field name, then the ONE store path.
;     textfield accepts value|text; button accepts label|value. -> EAX 0/1.
wgt_textfield_set:
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rdx
    mov  r14, rsi
    lea  rdi, [rel str_wf_value]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .store
    lea  rdi, [rel str_wf_disabled]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .disabled
    lea  rdi, [rel str_wf_text]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jnz  .bad
.store:
    mov  edi, r12d
    mov  rsi, r13
    call wgt_tf_value_ok                ; RCQ-38 L3b: never store bytes the editor cannot walk
    test eax, eax
    jz   .bad
    mov  edi, r12d
    call wgt_slot_ptr
    call wgt_tf_buf
    mov  r14d, ecx                      ; RCQ-38 L3c: 255 for a long field, else 39
    mov  edi, r12d
    call keyprov_field_write            ; GA0-K: a remote/tainted writer is remembered for line adoption
    mov  rsi, r13
    mov  edx, r14d
    call wgt_set_text_cap
    mov  rax, [rel wgt_textfield_event_hook2]
    test rax, rax
    jz   .stored
    mov  edi, r12d
    xor  esi, esi
    call rax
.stored:
    xor  eax, eax
    jmp  .out
.disabled:
    mov  edi, r12d
    mov  rsi, r13
    call wgt_set_disabled
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; wgt_tf_value_ok(EDI = widget id, RSI = value cstr) -> EAX 1 when the bytes
;   wgt_set_text_cap would store (up to the field's wgt_tf_buf cap) are UTF-8,
;   and ASCII (< 0x80) for a WGT_EDIT_ASCII field. Only a textfield is checked:
;   wgt_textfield_set is also the setter of labels, containers, tabstrips and
;   listviews, whose byte painters keep taking any bytes (srcreview C1
;   20:13:43). RCQ-38 L3b. Clobbers caller-saved.
wgt_tf_value_ok:
    push rbx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .any                           ; not a textfield: its bytes as before
    mov  ebx, [rax + WGI_EDIT]
    call wgt_tf_buf
    mov  r8d, ecx                       ; RCQ-38 L3c: the field's own cap
    xor  ecx, ecx
.len:
    cmp  ecx, r8d
    jae  .counted
    movzx eax, byte [rsi + rcx]
    test eax, eax
    jz   .counted
    test ebx, WGT_EDIT_ASCII
    jz   .next
    cmp  eax, 0x80
    jae  .no
.next:
    inc  ecx
    jmp  .len
.counted:
    mov  rdi, rsi
    mov  esi, ecx
    call ue_utf8_validate
    jmp  .out
.any:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; wgt_set_disabled(EDI = id, RSI = "0" | "1") -> EAX 0 stored / 1 bad value.
;   RCQ-16 S4: the one `disabled` field of the stateful kinds (button,
;   textfield, toggle, slider, numeric): WGT_EDIT_DISABLED, then a repaint. It
;   never moves focus; a disabled control takes no key (wgt_textfield_key), no
;   scalar press (wgt_scalar_pointer_press), no Tab stop and no state paint.
;   clobbers: caller-saved.
wgt_set_disabled:
    cmp  byte [rsi + 1], 0
    jne  .bad
    movzx ecx, byte [rsi]
    sub  ecx, '0'
    cmp  ecx, 1
    ja   .bad
    push rdi
    call wgt_slot_ptr
    and  dword [rax + WGI_EDIT], ~WGT_EDIT_DISABLED
    test ecx, ecx
    jz   .stored
    or   dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
.stored:
    pop  rdi
    call wgt_draw_id
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; wgt_get_disabled(EDI = id) -> RAX = "0" / "1" (wgt_bool_buf). clobbers: RAX, EDX, R10
wgt_get_disabled:
    call wgt_slot_ptr
    xor  edx, edx
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    setnz dl
    add  dl, '0'
    mov  [rel wgt_bool_buf], dl
    mov  byte [rel wgt_bool_buf + 1], 0
    lea  rax, [rel wgt_bool_buf]
    ret

wgt_button_set:
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rdx
    mov  r14, rsi
    lea  rdi, [rel str_wf_open]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .set_open
    lea  rdi, [rel str_wf_action]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .action
    lea  rdi, [rel str_wf_disabled]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .disabled
    lea  rdi, [rel str_wf_label]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .store
    lea  rdi, [rel str_wf_value]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jnz  .bad
.store:
    mov  edi, r12d
    mov  rsi, r13
    call wgt_set_text
    xor  eax, eax
    jmp  .out
.set_open:
    cmp  byte [r13 + 1], 0
    jne  .bad
    movzx r14d, byte [r13]
    sub  r14d, '0'
    cmp  r14d, 1
    ja   .bad
    mov  rax, [rel wgt_button_open_hook]
    test rax, rax
    jz   .open_store
    mov  edi, r12d
    mov  esi, r14d
    call rax
    test eax, eax
    jnz  .bad
.open_store:
    mov  edi, r12d
    call wgt_slot_ptr
    and  dword [rax + WGI_EDIT], ~WGT_EDIT_OPEN
    test r14d, r14d
    jz   .open_draw
    or   dword [rax + WGI_EDIT], WGT_EDIT_OPEN
.open_draw:
    mov  dword [rax + WGI_INTENT], WGT_BUTTON_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    call wmx_draw_all
    xor  eax, eax
    jmp  .out
.disabled:
    mov  edi, r12d
    mov  rsi, r13
    call wgt_set_disabled
    jmp  .out
.action:
    mov  rax, [rel wgt_action_hook]
    test rax, rax
    jz   .bad
    mov  edi, r12d
    mov  rsi, r13
    call rax
    test eax, eax
    jnz  .out
    mov  edi, r12d
    call wgt_slot_ptr
    mov  dword [rax + WGI_INTENT], WGT_BUTTON_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; --- per-type GET-field: validate the field name -> RAX = live value ptr
;     (the SAME bytes the draw renders), or 0 on an unknown field.
wgt_textfield_get:
    push r12
    push r14
    mov  r12d, edi
    mov  r14, rsi
    lea  rdi, [rel str_wf_value]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .ok
    lea  rdi, [rel str_wf_text]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .ok
    lea  rdi, [rel str_wf_submits]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .get_submits
    lea  rdi, [rel str_wf_disabled]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jnz  .bad
    mov  edi, r12d
    call wgt_get_disabled               ; RCQ-16 S4
    jmp  .out
.ok:
    mov  edi, r12d
    call wgt_slot_ptr
    call wgt_tf_buf                     ; RCQ-38 L3c
    jmp  .out
.get_submits:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_SUBMITS]
    lea  rsi, [rel wgt_sel_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel wgt_sel_buf]
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r12
    ret

; Restore keyboard focus for EDI=focused window. Pointer selection is sticky;
; a window without history defaults to its first visible textfield.
wgt_focus_window:
    push rbx
    push r12
    mov  r12d, edi
    cmp  r12d, WM_MAX
    jae  .none_global
    lea  rax, [rel wgt_focus_by_win]
    mov  ebx, [rax + r12*4]
    cmp  ebx, -2
    je   .none_global
    cmp  ebx, 0
    jl   .scan
    cmp  ebx, [rel wgt_count]
    jae  .scan
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .scan
    cmp  [rax + WGI_WIN], r12d
    jne  .scan
    test dword [rax + WGI_FLAGS], 1
    jz   .scan
    mov  [rel wgt_focus_id], ebx
    mov  eax, ebx
    jmp  .out
.scan:
    xor  ebx, ebx
.next:
    cmp  ebx, [rel wgt_count]
    jae  .none
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 2
    jne  .advance
    cmp  [rax + WGI_WIN], r12d
    jne  .advance
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .advance                       ; RCQ-16 S4 R1 (F3): a disabled textfield is no default focus
    test dword [rax + WGI_FLAGS], 1
    jnz  .found
.advance:
    inc  ebx
    jmp  .next
.found:
    lea  rax, [rel wgt_focus_by_win]
    mov  [rax + r12*4], ebx
    mov  [rel wgt_focus_id], ebx
    mov  eax, ebx
    jmp  .out
.none:
    lea  rax, [rel wgt_focus_by_win]
    mov  dword [rax + r12*4], -1
.none_global:
    mov  dword [rel wgt_focus_id], -1
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; wgt_type_name_of(EDI=widget id) -> RAX = the registered type name cstr, 0 if the
; slot is free or the id is out of range. Lets the WM classify a hit without
; touching vtable internals (2026-09-08).
wgt_type_name_of:
    cmp  edi, [rel wgt_count]
    jae  .tn_none
    call wgt_slot_ptr
    mov  eax, [rax + WGI_TYPE]
    test eax, eax
    jz   .tn_none
    dec  eax
    imul rax, rax, WT_SZ
    lea  rcx, [rel wgt_types]
    mov  rax, [rcx + rax + WT_NAME]
    ret
.tn_none:
    xor  eax, eax
    ret

; Select the topmost visible widget at ESI,EDX within EDI=window. Clicking a
; non-text widget deliberately prevents keys leaking to a textfield.
wgt_focus_at:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  byte [rel wgt_focus_visible], 0    ; RCQ-16: pointer focus shows no ring
    cmp  r12d, WM_MAX
    jae  .at_none_global
    mov  ebx, [rel wgt_count]
.at_next:
    test ebx, ebx
    jz   .at_none
    dec  ebx
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .at_next
    cmp  [rax + WGI_WIN], r12d
    jne  .at_next
    test dword [rax + WGI_FLAGS], 1
    jz   .at_next
    ; Native menus paint and hit only while open. Their retained rectangle
    ; must not steal keyboard focus from the control beneath a closed flyout.
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .at_rect
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .at_next
.at_rect:
    mov  ecx, [rax + WGI_X]
    cmp  r13d, ecx
    jl   .at_next
    add  ecx, [rax + WGI_W]
    cmp  r13d, ecx
    jge  .at_next
    mov  ecx, [rax + WGI_Y]
    cmp  r14d, ecx
    jl   .at_next
    add  ecx, [rax + WGI_H]
    cmp  r14d, ecx
    jge  .at_next
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .at_none                       ; RCQ-16 S4 R1 (F3): the press lands on a disabled control: no focus, as empty space
    lea  rax, [rel wgt_focus_by_win]
    mov  [rax + r12*4], ebx
    mov  [rel wgt_focus_id], ebx
    mov  eax, ebx
    jmp  .at_out
.at_none:
    lea  rax, [rel wgt_focus_by_win]
    mov  dword [rax + r12*4], -2
.at_none_global:
    mov  dword [rel wgt_focus_id], -1
    mov  eax, -1
.at_out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Edit WGI_VAL in place: these are exactly the bytes painted and returned by
; WIDGETGET. EDI=id, EAX=GUI_KEY_* or printable ASCII; EAX=1 if handled.
wgt_textfield_key:
    ; Form-level navigation precedes an ordinary edit. It never sees secret bytes.
    push rdi
    push rax
    mov  rdx, [rel wgt_key_filter]
    test rdx, rdx
    jz   .filter_done
    call rdx
    test eax, eax
    jz   .filter_done
    add  rsp, 16
    mov  eax, 1
    ret
.filter_done:
    pop  rax
    pop  rdi
    cmp  eax, GUI_KEY_TAB
    je   wgt_focus_tab_step             ; G3: Tab moves focus between controls
    mov  edx, [rel wgt_secret_type]
    inc  edx
    push rax
    push rdi
    call wgt_slot_ptr
    cmp  [rax + WGI_TYPE], edx
    pop  rdi
    pop  rax
    je   wgt_secret_key
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, eax
    call wgt_slot_ptr
    mov  rbx, rax
    test dword [rbx + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .ignored                       ; RCQ-16 S4: a disabled control takes no key
    mov  ecx, [rbx + WGI_TYPE]
    cmp  ecx, WGT_TYPE_TEXTFIELD
    je   .textfield
    cmp  ecx, 1
    je   .ignored                       ; a button's activation stays with its form (key filter / pointer)
    call wgt_stateful_type
    test eax, eax
    jz   .ignored
    mov  edi, r12d                      ; toggle / slider / numeric: their keyboard operation
    mov  eax, r13d
    call wgt_scalar_key
    jmp  .key_out
.textfield:
    cmp  r13d, GUI_KEY_BACKSPACE
    je   .backspace
    cmp  r13d, GUI_KEY_DELETE
    je   .delete
    cmp  r13d, GUI_KEY_LEFT
    je   .left
    cmp  r13d, GUI_KEY_RIGHT
    je   .right
    cmp  r13d, GUI_KEY_HOME
    je   .home
    cmp  r13d, GUI_KEY_END
    je   .end
    cmp  r13d, GUI_KEY_ENTER
    je   .submit
    cmp  r13d, GUI_KEY_TEXT
    je   .text
    cmp  r13d, 0x20
    jb   .handled
    cmp  r13d, 0x7E
    ja   .handled
    call wgt_tf_edit_buf                ; RCQ-38 L3c: R11 = the value, ECX = its typed cap
    cmp  [rbx + WGI_VLEN], ecx
    jae  .handled
    mov  ecx, [rbx + WGI_VLEN]
    mov  edx, [rbx + WGI_CARET]
    cmp  edx, ecx
    jbe  .insert_pos_ok
    mov  edx, ecx
.insert_pos_ok:
    mov  eax, ecx
.shift_right:
    cmp  eax, edx
    jl   .insert
    mov  r10b, [r11 + rax]
    mov  [r11 + rax + 1], r10b
    dec  eax
    jmp  .shift_right
.insert:
    mov  [r11 + rdx], r13b
    inc  edx
    inc  ecx
    mov  [rbx + WGI_CARET], edx
    mov  [rbx + WGI_VLEN], ecx
    jmp  .redraw
.text:
    ; RCQ-38 L3b: text >= U+0080 is inserted at the caret whole (every scalar of
    ; wgt_text_buf) or not at all: an ASCII-only field, invalid UTF-8 or no room
    ; is refused and counted, and the key is still handled (the hooks below run).
    call wgt_tf_edit_buf
    mov  r8d, ecx                       ; RCQ-38 L3c: the field's typed cap
    mov  ecx, [rel wgt_text_len]
    test dword [rbx + WGI_EDIT], WGT_EDIT_ASCII
    jnz  .text_refused
    lea  eax, [rcx - 1]
    cmp  eax, WGT_TEXT_CAP - 1
    jae  .text_refused                  ; empty or longer than one payload
    add  ecx, [rbx + WGI_VLEN]
    cmp  ecx, r8d
    ja   .text_refused
    lea  rdi, [rel wgt_text_buf]
    mov  esi, [rel wgt_text_len]
    call ue_utf8_validate               ; SysV: caller-saved clobbered
    test eax, eax
    jz   .text_refused
    lea  rsi, [rel wgt_text_buf]
    mov  ecx, [rel wgt_text_len]
    call wgt_utf8_controls              ; no C0, DEL or C1 control (the key path types 0x20..0x7E)
    jnz  .text_refused
    call wgt_tf_edit_buf                ; R11 = the value (the calls above clobbered it)
    mov  ecx, [rbx + WGI_VLEN]
    mov  r8d, [rel wgt_text_len]
    mov  edx, [rbx + WGI_CARET]
    cmp  edx, ecx
    jbe  .text_pos_ok
    mov  edx, ecx
.text_pos_ok:
    mov  eax, ecx                       ; shift [caret, VLEN] (the NUL too) right by the payload
.text_shift:
    cmp  eax, edx
    jl   .text_copy
    mov  r10b, [r11 + rax]
    lea  r9d, [rax + r8]
    mov  [r11 + r9], r10b
    dec  eax
    jmp  .text_shift
.text_copy:
    lea  rsi, [rel wgt_text_buf]
    xor  eax, eax
.text_byte:
    mov  r10b, [rsi + rax]
    lea  r9d, [rdx + rax]
    mov  [r11 + r9], r10b
    inc  eax
    cmp  eax, r8d
    jb   .text_byte
    add  edx, r8d
    add  ecx, r8d
    mov  [rbx + WGI_CARET], edx
    mov  [rbx + WGI_VLEN], ecx
    lea  eax, [r12 + 1]
    cmp  eax, [rel wgt_preedit_id]
    jne  .redraw
    mov  dword [rel wgt_preedit_id], 0  ; a commit replaces the field's pre-edit
    jmp  .redraw
.text_refused:
    lock inc qword [rel wgt_text_refused]
    jmp  .handled
.backspace:
    ; RCQ-38 L3b: Backspace removes the grapheme cluster before the caret,
    ; Delete the one under it, Left/Right step over a whole cluster (one byte
    ; for ASCII, as before). A value that is not UTF-8 is cleared (wgt_tf_step).
    cmp  dword [rbx + WGI_CARET], 0
    je   .handled
    xor  r8d, r8d
    call wgt_tf_step
    js   .corrupt
    mov  edx, eax
    mov  r9d, [rbx + WGI_CARET]
    call wgt_tf_cut
    mov  [rbx + WGI_CARET], edx
    jmp  .redraw
.delete:
    ; G3 (2026-09-30, usage suite KBM-01): Delete removes the character UNDER
    ; the caret (the caret stays); a no-op at the end of the text.
    mov  edx, [rbx + WGI_CARET]
    cmp  edx, [rbx + WGI_VLEN]
    jae  .handled
    mov  r8d, 1
    call wgt_tf_step
    js   .corrupt
    mov  r9d, eax
    mov  edx, [rbx + WGI_CARET]
    call wgt_tf_cut
    jmp  .redraw
.left:
    cmp  dword [rbx + WGI_CARET], 0
    je   .handled
    xor  r8d, r8d
    call wgt_tf_step
    js   .corrupt
    mov  [rbx + WGI_CARET], eax
    jmp  .redraw
.right:
    mov  eax, [rbx + WGI_CARET]
    cmp  eax, [rbx + WGI_VLEN]
    jae  .handled
    mov  r8d, 1
    call wgt_tf_step
    js   .corrupt
    mov  [rbx + WGI_CARET], eax
    jmp  .redraw
.corrupt:
    call wgt_tf_edit_buf
    mov  byte [r11], 0
    xor  eax, eax
    mov  [rbx + WGI_VLEN], eax
    mov  [rbx + WGI_CARET], eax
    jmp  .redraw
.home:
    mov  dword [rbx + WGI_CARET], 0
    jmp  .redraw
.end:
    mov  eax, [rbx + WGI_VLEN]
    mov  [rbx + WGI_CARET], eax
    jmp  .redraw
.submit:
    inc  dword [rbx + WGI_SUBMITS]
    jmp  .redraw
.redraw:
    mov  edi, r12d
    call wgt_draw_id
.handled:
    mov  rax, [rel wgt_textfield_event_hook]
    test rax, rax
    jz   .secondary_event
    mov  edi, r12d
    mov  esi, r13d
    call rax                           ; generic post-edit/submit event seam
.secondary_event:
    mov  rax, [rel wgt_textfield_event_hook2]
    test rax, rax
    jz   .handled_done
    mov  edi, r12d
    mov  esi, r13d
    call rax
.handled_done:
    mov  eax, 1
    jmp  .key_out
.ignored:
    xor  eax, eax
.key_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_tf_step(RBX = textfield slot, R8D = 0 previous / 1 next) -> EAX = the
;   grapheme boundary before / after WGI_CARET, SF set (EAX -1) when WGI_VAL is
;   not UTF-8 or the caret is inside a cluster; a caret past WGI_VLEN is first
;   set to WGI_VLEN. RCQ-38 L3b. Keeps RBX/R12/R13;
;   clobbers caller-saved (core/unicode_edit is SysV).
wgt_tf_step:
    call wgt_tf_edit_buf
    mov  rdi, r11
    mov  esi, [rbx + WGI_VLEN]
    mov  edx, [rbx + WGI_CARET]
    cmp  edx, esi
    jbe  .caret_in
    mov  edx, esi                       ; a caret past the end steps from the end:
    mov  [rbx + WGI_CARET], esi         ; it is the end (Backspace cuts up to WGI_CARET)
.caret_in:
    test r8d, r8d
    jnz  .next
    call ue_grapheme_prev
    jmp  .out
.next:
    call ue_grapheme_next
.out:
    test eax, eax
    ret

; wgt_utf8_controls(RSI = valid UTF-8, ECX = length) -> ZF clear when it holds a
;   control: a byte < 0x20, 0x7F, or U+0080..U+009F (C2 80..C2 9F). RCQ-38 L3b.
;   Clobbers EAX, ECX, RSI.
wgt_utf8_controls:
.byte:
    test ecx, ecx
    jz   .none
    movzx eax, byte [rsi]
    cmp  eax, 0x20
    jb   .control
    cmp  eax, 0x7F
    je   .control
    cmp  eax, 0xC2
    jne  .next
    cmp  byte [rsi + 1], 0xA0           ; valid UTF-8: a C2 lead has its continuation
    jb   .control
.next:
    inc  rsi
    dec  ecx
    jmp  .byte
.none:
    xor  eax, eax                       ; ZF set: no control
    ret
.control:
    or   eax, 1                         ; ZF clear
    ret

; wgt_tf_cut(RBX = textfield slot, EDX = from, R9D = to): removes WGI_VAL
;   [from, to) and its NUL moves with it. RCQ-38 L3b. Keeps EDX/RBX; clobbers
;   EAX, ECX, R8, R9D, R10D, R11.
wgt_tf_cut:
    call wgt_tf_edit_buf
    mov  ecx, [rbx + WGI_VLEN]
    mov  eax, edx
    mov  r10d, r9d
.move:
    cmp  r10d, ecx
    ja   .moved
    mov  r8b, [r11 + r10]
    mov  [r11 + rax], r8b
    inc  eax
    inc  r10d
    jmp  .move
.moved:
    sub  r9d, edx
    sub  ecx, r9d
    mov  [rbx + WGI_VLEN], ecx
    ret

; wgt_tf_buf(RAX = widget slot) -> RAX = its value bytes, ECX = the bytes a
;   store may write (NUL excluded): a long textfield's wgt_long_pool entry and
;   WGT_LONG_MAX, else WGI_VAL and WGT_TEXTFIELD_VAL_MAX. RCQ-38 L3c: THE one
;   accessor every textfield value reader and writer uses (census row in
;   test_rcq38_l3c_long_field_host). An entry counts only while wgt_long_owner
;   names this slot, so a stale or foreign WGI_RSVD (progress, grids) reads
;   WGI_VAL. Clobbers RAX, RCX only.
wgt_tf_buf:
    mov  ecx, [rax + WGI_RSVD]
    dec  ecx
    cmp  ecx, WGT_LONG_N
    jae  .inline
    push rdx
    lea  rdx, [rel wgt_long_owner]
    cmp  [rdx + rcx*8], rax
    pop  rdx
    jne  .inline
    shl  ecx, 8                         ; * (WGT_LONG_MAX + 1)
    lea  rax, [rel wgt_long_pool]
    add  rax, rcx
    mov  ecx, WGT_LONG_MAX
    ret
.inline:
    add  rax, WGI_VAL
    mov  ecx, WGT_TEXTFIELD_VAL_MAX
    ret

; wgt_tf_edit_buf(RBX = textfield slot) -> R11 = its value bytes, ECX = the
;   length typing may grow it to: WGT_LONG_MAX for a long field, WGI_VAL_MAX
;   inline (unchanged by L3c). The editor's form of wgt_tf_buf. Clobbers RAX,
;   RCX, R11.
wgt_tf_edit_buf:
    mov  rax, rbx
    call wgt_tf_buf
    mov  r11, rax
    cmp  ecx, WGT_LONG_MAX
    je   .out
    mov  ecx, WGI_VAL_MAX
.out:
    ret

; wgt_tf_long_free(RAX = widget slot): when the slot holds a long entry, the
;   entry's 256 bytes are zeroed and it is free again; WGI_RSVD is left to the
;   caller. Preserves every register. RCQ-38 L3c.
wgt_tf_long_free:
    push rax
    push rcx
    push rdx
    mov  ecx, [rax + WGI_RSVD]
    dec  ecx
    cmp  ecx, WGT_LONG_N
    jae  .out
    lea  rdx, [rel wgt_long_owner]
    cmp  [rdx + rcx*8], rax
    jne  .out
    mov  qword [rdx + rcx*8], 0
    shl  ecx, 8
    lea  rax, [rel wgt_long_pool]
    add  rax, rcx
    xor  ecx, ecx
.wipe:
    mov  qword [rax + rcx], 0
    add  ecx, 8
    cmp  ecx, WGT_LONG_MAX + 1
    jb   .wipe
.out:
    pop  rdx
    pop  rcx
    pop  rax
    ret

; wgt_textfield_long(EDI = textfield id) -> EAX 0 the field now holds up to
;   WGT_LONG_MAX bytes (its value moves into a free wgt_long_pool entry; a field
;   that is long already stays as it is), 1 refused (no such textfield, or the
;   pool is full). A field opts in by code, never by .frm. RCQ-38 L3c (root
;   18:16:22: the 255 B search field). Clobbers caller-saved.
wgt_textfield_long:
    cmp  edi, [rel wgt_count]
    jae  .refused
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .refused
    mov  r8, rax                        ; the slot
    call wgt_tf_buf
    cmp  ecx, WGT_LONG_MAX
    je   .ok                            ; long already
    lea  rdx, [rel wgt_long_owner]
    xor  ecx, ecx
.free:
    cmp  qword [rdx + rcx*8], 0
    je   .bind
    inc  ecx
    cmp  ecx, WGT_LONG_N
    jb   .free
.refused:
    mov  eax, 1
    ret
.bind:
    mov  [rdx + rcx*8], r8
    lea  eax, [rcx + 1]
    mov  [r8 + WGI_RSVD], eax
    shl  ecx, 8
    lea  rdi, [rel wgt_long_pool]
    add  rdi, rcx                       ; the entry is zero (BSS, or wiped on free)
    mov  ecx, [r8 + WGI_VLEN]
    cmp  ecx, WGT_TEXTFIELD_VAL_MAX
    jbe  .copy
    mov  ecx, WGT_TEXTFIELD_VAL_MAX
    mov  [r8 + WGI_VLEN], ecx
.copy:
    xor  eax, eax
.byte:
    cmp  eax, ecx
    jae  .copied
    mov  dl, [r8 + WGI_VAL + rax]
    mov  [rdi + rax], dl
    inc  eax
    jmp  .byte
.copied:
    mov  byte [rdi + rax], 0
    mov  byte [r8 + WGI_VAL], 0         ; the inline copy is dead: never read again
    mov  dword [r8 + WGI_VLEN], ecx
.ok:
    xor  eax, eax
    ret

; wgt_focus_tab_step(EDI=focused widget id) -> EAX=1. G3 (2026-09-30, usage
;   suite WIN-02): Tab moves keyboard focus to the next focusable control of
;   the SAME window in declaration order (Shift+Tab: previous; input_route sets
;   wgt_tab_reverse), wrapping; a window with one control keeps it. Focusable =
;   a visible button, textfield, secret input, toggle, slider or numeric
;   (RCQ-16 S4: the scalars take their keys, wgt_scalar_key) that is not
;   disabled. Labels, grids, lists, menus and tab strips are skipped. Both
;   widgets repaint (caret/ring).
;   Reached by a tail jump from wgt_textfield_key after the form key filter
;   (the sign-in form keeps its own Tab rule). Clobbers caller-saved.
wgt_focus_tab_step:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    cmp  r12d, [rel wgt_count]
    jae  .done
    call wgt_slot_ptr
    mov  r13d, [rax + WGI_WIN]
    cmp  r13d, WM_MAX
    jae  .done
    mov  r14d, [rel wgt_count]          ; at most one full lap
    mov  ebx, r12d
.step:
    dec  r14d
    js   .done
    cmp  byte [rel wgt_tab_reverse], 0
    jne  .back
    inc  ebx
    cmp  ebx, [rel wgt_count]
    jb   .probe
    xor  ebx, ebx
    jmp  .probe
.back:
    dec  ebx
    jns  .probe
    mov  ebx, [rel wgt_count]
    dec  ebx
.probe:
    cmp  ebx, r12d
    je   .done                          ; lapped: the current control is the only one
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  [rax + WGI_WIN], r13d
    jne  .step
    test dword [rax + WGI_FLAGS], 1
    jz   .step
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .step
    mov  ecx, [rax + WGI_TYPE]
    call wgt_stateful_type              ; button, textfield, toggle, slider, numeric
    test eax, eax
    jnz  .take
    mov  edx, [rel wgt_secret_type]
    inc  edx
    cmp  ecx, edx
    jne  .step
.take:
    lea  rax, [rel wgt_focus_by_win]
    mov  [rax + r13*4], ebx
    mov  [rel wgt_focus_id], ebx
    mov  byte [rel wgt_focus_visible], 1    ; RCQ-16: keyboard focus shows its ring
    mov  edi, r12d
    call wgt_draw_id
    mov  edi, ebx
    call wgt_draw_id
.done:
    mov  byte [rel wgt_tab_reverse], 0
    mov  eax, 1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_button_get:
    push r12
    push r14
    mov  r12d, edi
    mov  r14, rsi
    lea  rdi, [rel str_wf_open]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .open
    lea  rdi, [rel str_wf_disabled]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .disabled
    lea  rdi, [rel str_wf_label]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .ok
    lea  rdi, [rel str_wf_value]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jnz  .hook
.ok:
    mov  edi, r12d
    call wgt_slot_ptr
    lea  rax, [rax + WGI_VAL]
    jmp  .out
.open:
    mov  edi, r12d
    call wgt_slot_ptr
    xor  edx, edx
    test dword [rax + WGI_EDIT], WGT_EDIT_OPEN
    setnz dl
    add  dl, '0'
    mov  [rel wgt_bool_buf], dl
    mov  byte [rel wgt_bool_buf + 1], 0
    lea  rax, [rel wgt_bool_buf]
    jmp  .out
.disabled:
    mov  edi, r12d
    call wgt_slot_ptr
    xor  edx, edx
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    setnz dl
    add  dl, '0'
    mov  [rel wgt_bool_buf], dl
    mov  byte [rel wgt_bool_buf + 1], 0
    lea  rax, [rel wgt_bool_buf]
    jmp  .out
.hook:
    mov  rax, [rel wgt_button_get_hook]
    test rax, rax
    jz   .bad
    mov  edi, r12d
    mov  rsi, r14
    call rax
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r12
    ret

wgt_label_set:
    jmp  wgt_textfield_set

wgt_label_get:
    push r12
    push r14
    mov  r12d, edi
    mov  r14, rsi
    lea  rdi, [rel str_wf_value]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .value
    lea  rdi, [rel str_wf_text]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jnz  .bad
.value:
    mov  edi, r12d
    call wgt_slot_ptr
    lea  rax, [rax + WGI_VAL]
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r12
    ret

; Clipboard's explicit bridge is narrower than the general widget vtable:
; only the stock textfield may cross it. Future secret-input types necessarily
; use another row and therefore refuse here under every capability. Selection
; and caret state remain inert.
; wgt_textfield_clip_get(EDI=id) -> RAX=value, ECX=len, EDX=0; EDX=1 refuses.
wgt_textfield_clip_get:
    push rbx
    push r12
    mov  r12d, edi
    cmp  edi, [rel wgt_count]
    jae  .bad
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .bad
    mov  edi, r12d
    lea  rsi, [rel str_wf_value]
    call wgt_textfield_get              ; existing WIDGETGET value path
    test rax, rax
    jz   .bad
    mov  ecx, [rbx + WGI_VLEN]
    xor  edx, edx
    jmp  .out
.bad:
    xor  eax, eax
    xor  ecx, ecx
    mov  edx, 1
.out:
    pop  r12
    pop  rbx
    ret

; wgt_textfield_clip_set(EDI=id, RSI=value, EDX=len) -> EAX=0 or 1 refusal.
wgt_textfield_clip_set:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    cmp  edi, [rel wgt_count]
    jae  .bad
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .bad
    mov  rax, rbx
    call wgt_tf_buf                     ; RCQ-38 L3c: the field's own cap (255 long)
    cmp  edx, ecx
    ja   .bad
    mov  edi, r12d
    lea  rsi, [rel str_wf_value]
    mov  rdx, r13
    call wgt_textfield_set              ; existing WIDGETSET value path
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; wgt_library_init — register the three F1 types through the vtable, then create
;   + draw one demo widget of EACH type in window A (the boot proof the library
;   renders via the shared primitives). Marker ui.widget.library is EARNED:
;   both registrations AND both creates must succeed. clobbers: caller-saved.
; ---------------------------------------------------------------------------
wgt_library_init:
    ; type 0: button (proven monolith dims: h=32)
    lea  rdi, [rel str_wt_button]
    lea  rsi, [rel wgt_button_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_button_set]
    lea  r8,  [rel wgt_button_get]
    mov  r9, (32 << 32) | 120
    call wgt_type_register
    ; type 1: textfield (proven monolith dims: h=28) — the degenerate-2nd:
    ; SAME call, no core edit
    lea  rdi, [rel str_wt_textfield]
    lea  rsi, [rel wgt_textfield_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_textfield_set]
    lea  r8,  [rel wgt_textfield_get]
    mov  r9, (28 << 32) | 200
    call wgt_type_register
    ; type 2: label — additive registration only (ESSENCE E6).
    lea  rdi, [rel str_wt_label]
    lea  rsi, [rel wgt_label_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8,  [rel wgt_label_get]
    mov  r9, (24 << 32) | 220
    call wgt_type_register
    cmp  dword [rel wgt_type_count], 3
    jne  .fail
    ; demo button "OK" (id 0, window A)
    xor  edi, edi
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  edi, eax
    lea  rsi, [rel str_wt_demo_ok]
    call wgt_set_text
    ; demo textfield "ready" (id 1, window A)
    mov  edi, 1
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  edi, eax
    lea  rsi, [rel str_wt_demo_ready]
    call wgt_set_text
    lea  rdi, [rel str_wgt_m_lib]
    call serial_string
    lea  rdi, [rel str_wgt_label]
    call serial_string
    mov  byte [rel wgt_m_library], 1
    ret
.fail:
    lea  rdi, [rel str_wgt_m_libfail]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; wgt_declare — register the 6 element verbs through the SAME
;   command_register_verb (additive, no registry-core edit). Marker
;   ui.widget.registry is EARNED: every registration must land a slot.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
wgt_declare:
    ; Register the damage-ring reads before the long widget/catalog tail so the
    ; generated bounded CATALOG cannot truncate their discoverability.
    call cadence_mark_declare
    push rbx
    xor  ebx, ebx                      ; goes negative if any register returns -1
    lea  rdi, [rel str_verb_widgettypes]
    lea  rsi, [rel cmd_verb_widgettypes]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_widgetnew]
    lea  rsi, [rel cmd_verb_widgetnew]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                         ; mutates GUI state
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_widgetset]
    lea  rsi, [rel cmd_verb_widgetset]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                         ; THE element setter (mutates)
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_widgetget]
    lea  rsi, [rel cmd_verb_widgetget]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_widgetlist]
    lea  rsi, [rel cmd_verb_widgetlist]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_catalog]
    lea  rsi, [rel cmd_verb_catalog]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only (registry projection)
    call command_register_verb
    or   ebx, eax
    test ebx, ebx
    js   .fail
    lea  rdi, [rel str_wgt_m_reg]
    call serial_string
    mov  byte [rel wgt_m_registry], 1
    pop  rbx
    ; Bind exact stock-textfield callbacks after its value seam exists. The L5
    ; service holds no GUI symbol and cannot address future secret widgets.
    lea  rdi, [rel wgt_textfield_clip_get]
    lea  rsi, [rel wgt_textfield_clip_set]
    call clipboard_bind_textfield
    call clipboard_init
    ret
.fail:
    lea  rdi, [rel str_wgt_m_regfail]
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; arg parsing helpers (handlers copy the raw REQ_ARG text into wgt_parse_buf
; and tokenize the COPY — the live udp_line stays intact for the ARG= echo).
; ---------------------------------------------------------------------------

; wgt_arg_copy(RSI=src) — bounded copy into wgt_parse_buf. clobbers RAX,RCX,RSI
wgt_arg_copy:
    lea  rax, [rel wgt_parse_buf]
    xor  ecx, ecx
.cp:
    cmp  ecx, 158
    jae  .done
    mov  r10b, [rsi + rcx]
    test r10b, r10b
    jz   .done
    mov  [rax + rcx], r10b
    inc  ecx
    jmp  .cp
.done:
    mov  byte [rax + rcx], 0
    ret

; wgt_skip_sp(RDI=ptr) -> RAX = first non-space. clobbers RAX
wgt_skip_sp:
    mov  rax, rdi
.sk:
    cmp  byte [rax], ' '
    jne  .done
    inc  rax
    jmp  .sk
.done:
    ret

; wgt_tok_split(RDI=token start) -> RAX = ptr past the token (trailing space
;   NUL-split + spaces skipped; points at the NUL when the line ends). RDI
;   preserved = the now-NUL-terminated token. clobbers RAX,RCX
wgt_tok_split:
    mov  rax, rdi
.scan:
    mov  cl, [rax]
    test cl, cl
    jz   .done
    cmp  cl, ' '
    je   .split
    inc  rax
    jmp  .scan
.split:
    mov  byte [rax], 0
    inc  rax
.sk:
    cmp  byte [rax], ' '
    jne  .done
    inc  rax
    jmp  .sk
.done:
    ret

; wgt_parse_dec(RDI=ptr) -> RAX = value, RCX = digit count, RDX = ptr past the
;   digits. clobbers RAX,RCX,RDX,R10
wgt_parse_dec:
    xor  eax, eax
    xor  ecx, ecx
    mov  rdx, rdi
.next:
    movzx r10d, byte [rdx]
    sub  r10d, '0'
    cmp  r10d, 9
    ja   .done
    imul rax, rax, 10
    add  rax, r10
    inc  ecx
    inc  rdx
    jmp  .next
.done:
    ret

; ---------------------------------------------------------------------------
; VERB: WIDGETTYPES — list the registered types FROM the vtable (generated,
;   not hand-kept): " widget types: button textfield n=2 vtable=1"
; ---------------------------------------------------------------------------
cmd_verb_widgettypes:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    call wgt_out_reset
    lea  rdi, [rel str_wo_types]
    call wgt_out_str
    xor  r12d, r12d
.loop:
    cmp  r12d, [rel wgt_type_count]
    jae  .done
    lea  rdi, [rel str_wo_sp]
    call wgt_out_str
    mov  eax, r12d
    imul rax, rax, WT_SZ
    lea  rbx, [rel wgt_types]
    mov  rdi, [rbx + rax + WT_NAME]
    call wgt_out_str
    inc  r12d
    jmp  .loop
.done:
    lea  rdi, [rel str_wo_n]
    call wgt_out_str
    mov  edi, [rel wgt_type_count]
    call wgt_out_dec
    lea  rdi, [rel str_wo_vt]
    call wgt_out_str
    mov  byte [rel wgt_out_ready], 1
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; VERB: WIDGETNEW <type> [win] — instantiate through the vtable (type resolved
;   by TABLE WALK, never hardcoded): " widget new type=<t> id=<n> win=<w>"
;   RCQ-16 F2 (rc-sec 9e24b1ef): before any state change, the desktop session
;   gate (refused while locked, and M1's ticket-bound principal) and then the
;   host slot's owner (wmx_principal_may_act on the request's own principal).
; ---------------------------------------------------------------------------
cmd_verb_widgetnew:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    mov  rsi, [rdi + REQ_ARG]
    call wgt_arg_copy
    call wgt_out_reset
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    lea  rdi, [rel wgt_parse_buf]
    cmp  byte [rdi], 0
    je   .badtype
    call wgt_tok_split                 ; rdi = type token, rax = rest
    mov  r13, rax
    xor  r12d, r12d
.match:
    cmp  r12d, [rel wgt_type_count]
    jae  .badtype
    mov  eax, r12d
    imul rax, rax, WT_SZ
    lea  rbx, [rel wgt_types]
    mov  rsi, [rbx + rax + WT_NAME]
    lea  rdi, [rel wgt_parse_buf]
    call strcmp
    test rax, rax
    jz   .found
    inc  r12d
    jmp  .match
.found:
    cmp  r12d, [rel wgt_overlay_type]
    je   .badtype                     ; overlays require a linted declaration
    cmp  r12d, [rel wgt_grid_type]
    je   .badtype                     ; grids require bounded dimensions
    xor  ebx, ebx                      ; default host slot 0 (window A)
    cmp  byte [r13], 0
    je   .nowin
    mov  rdi, r13
    call wgt_parse_dec
    test rcx, rcx
    jz   .nowin
    mov  ebx, eax
.nowin:
    cmp  ebx, WM_MAX
    jae  .badwin
    lea  rcx, [rel wm_state]
    mov  ecx, [rcx + rbx*4]
    cmp  ecx, WM_VISIBLE
    je   .winlive
    cmp  ecx, WM_MIN
    jne  .badwin
.winlive:
    mov  rdi, [rsp + 32]               ; the request
    call session_shell_request_principal
    mov  rsi, rax
    mov  edi, ebx
    call wmx_principal_may_act
    test eax, eax
    jnz  .not_owner
    mov  edi, r12d
    mov  esi, ebx
    call wgt_create
    cmp  eax, -1
    je   .full
    mov  r13d, eax                     ; new id
    lea  rdi, [rel str_wo_new]         ; " widget new type="
    call wgt_out_str
    mov  eax, r12d
    imul rax, rax, WT_SZ
    lea  rcx, [rel wgt_types]
    mov  rdi, [rcx + rax + WT_NAME]
    call wgt_out_str
    lea  rdi, [rel str_wo_id]          ; " id="
    call wgt_out_str
    mov  edi, r13d
    call wgt_out_dec
    lea  rdi, [rel str_wo_win]         ; " win="
    call wgt_out_str
    mov  edi, ebx
    call wgt_out_dec
    jmp  .stage
.badtype:
    lea  rdi, [rel str_wo_e_type]
    call wgt_out_str
    jmp  .stage
.badwin:
    lea  rdi, [rel str_wo_e_win]
    call wgt_out_str
    jmp  .stage
.full:
    lea  rdi, [rel str_wo_e_full]
    call wgt_out_str
.stage:
    mov  byte [rel wgt_out_ready], 1
    mov  ebx, CMDE_OK
    jmp  .reply
.locked:
    call wgt_refuse_locked             ; EBX = the reply code
    jmp  .reply
.not_owner:
    call wgt_refuse_owner
.reply:
    mov  eax, ebx
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rcx, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rcx
    mov  [rsi + RSP_CODE], rax
    ret

; F2 refusals of the element verbs: stage the reply, EBX = its code. Nothing
; else changes (no widget, no repaint).
wgt_refuse_locked:
    lea  rdi, [rel str_wo_e_locked]
    mov  ebx, CMDE_DESKTOP_LOCKED
    jmp  wgt_refuse_stage
wgt_refuse_owner:
    lea  rdi, [rel str_wo_e_owner]
    mov  ebx, CMDE_AUTHDENY
wgt_refuse_stage:
    call wgt_out_str
    mov  byte [rel wgt_out_ready], 1
    ret

; ---------------------------------------------------------------------------
; VERB: WIDGETSET <id> <field> <value> — THE registered per-element setter
;   (COMMANDS.md §1: the setter IS a command, no side-door). Field validation
;   + store + repaint dispatch through the element's TYPE vtable.
; ---------------------------------------------------------------------------
cmd_verb_widgetset:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    push r14
    mov  rsi, [rdi + REQ_ARG]
    call wgt_arg_copy
    call wgt_out_reset
    call session_shell_require_unlocked ; F2 (a): before any parse or state
    test eax, eax
    jnz  .locked
    lea  rdi, [rel wgt_parse_buf]
    call wgt_parse_dec                 ; rax=id rcx=ndigits rdx=after
    test rcx, rcx
    jz   .badid
    cmp  eax, [rel wgt_count]
    jae  .badid
    mov  r12d, eax                     ; r12d = id
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .badid
    ; F2 (c): a live widget, then its host slot's owner (RDX survives both)
    mov  ebx, [rax + WGI_WIN]
    mov  rdi, [rsp + 40]               ; the request
    call session_shell_request_principal
    mov  rsi, rax
    mov  edi, ebx
    call wmx_principal_may_act
    test eax, eax
    jnz  .not_owner
    mov  rdi, rdx
    call wgt_skip_sp
    mov  r13, rax                      ; r13 = field token start
    cmp  byte [r13], 0
    je   .badfield
    mov  rdi, r13
    call wgt_tok_split                 ; r13 token NUL-split, rax = value start
    mov  r14, rax                      ; r14 = value (rest of line)
    mov  rdi, r13
    lea  rsi, [rel wgt_field_rect]
    call strcmp
    test eax, eax
    jnz  .ordinary_set
    mov  edi, r12d
    mov  rsi, r14
    call wgt_set_rect
    test eax, eax
    jnz  .badfield
    jmp  .set_ok
.ordinary_set:
    ; Selection is base state, shared by every type.
    lea  rdi, [rel str_wf_sel]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_sel
    ; Value fields are bounded atomically: stock textfields own the extended
    ; clipboard-safe capacity; every other widget preserves the legacy bound.
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ebx, WGI_VAL_MAX
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .have_value_bound
    call wgt_tf_buf                     ; RCQ-38 L3c: 39, or 255 for a long field
    mov  ebx, ecx
.have_value_bound:
    mov  rdi, r14
    call strlen
    cmp  rax, rbx
    ja   .oversize
    ; --- vtable SET dispatch ---
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_TYPE]
    dec  ecx
    imul rcx, rcx, WT_SZ
    lea  rbx, [rel wgt_types]
    mov  rbx, [rbx + rcx + WT_SET]
    mov  edi, r12d
    mov  rsi, r13
    mov  rdx, r14
    call rbx
    test eax, eax
    jnz  .badfield
    jmp  .set_ok
.set_sel:
    mov  rdi, r14
    call wgt_parse_dec
    test rcx, rcx
    jz   .badfield
    mov  ebx, eax
    mov  rdi, rdx
    cmp  byte [rdi], ','
    jne  .badfield
    inc  rdi
    call wgt_parse_dec
    test rcx, rcx
    jz   .badfield
    cmp  eax, ebx
    jb   .badfield
    mov  edx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], ebx
    mov  [rax + WGI_SEL_HI], edx
.set_ok:
    lea  rdi, [rel str_wo_set]         ; " widget set id="
    call wgt_out_str
    mov  edi, r12d
    call wgt_out_dec
    lea  rdi, [rel str_wo_field]       ; " field="
    call wgt_out_str
    mov  rdi, r13
    call wgt_out_str
    lea  rdi, [rel str_wo_len]         ; " len="
    call wgt_out_str
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_VLEN]
    call wgt_out_dec
    jmp  .stage
.badid:
    lea  rdi, [rel str_wo_e_id]
    call wgt_out_str
    jmp  .stage
.badfield:
    lea  rdi, [rel str_wo_e_field]
    call wgt_out_str
    jmp  .stage
.oversize:
    lea  rdi, [rel str_wo_e_size]
    call wgt_out_str
.stage:
    mov  byte [rel wgt_out_ready], 1
    mov  ebx, CMDE_OK
    jmp  .reply
.locked:
    call wgt_refuse_locked             ; EBX = the reply code
    jmp  .reply
.not_owner:
    call wgt_refuse_owner
.reply:
    mov  eax, ebx
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rcx, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rcx
    mov  [rsi + RSP_CODE], rax
    ret

; ---------------------------------------------------------------------------
; VERB: WIDGETGET <id> <field> — read the element field back through the TYPE
;   vtable: " widget get id=N <field>=<live bytes>" (the SAME bytes the draw
;   renders — the probe's nonce round-trip grades this).
; ---------------------------------------------------------------------------
cmd_verb_widgetget:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    mov  rsi, [rdi + REQ_ARG]
    call wgt_arg_copy
    call wgt_out_reset
    lea  rdi, [rel wgt_parse_buf]
    call wgt_parse_dec
    test rcx, rcx
    jz   .badid
    cmp  eax, [rel wgt_count]
    jae  .badid
    mov  r12d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .badid
    mov  rdi, rdx
    call wgt_skip_sp
    mov  r13, rax
    cmp  byte [r13], 0
    je   .badfield
    mov  rdi, r13
    call wgt_tok_split                 ; NUL-terminate the field token
    lea  rdi, [rel str_wf_role]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .get_role
    lea  rdi, [rel str_wf_label]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .get_label
    lea  rdi, [rel str_wf_intent]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .get_intent
    lea  rdi, [rel str_wf_intent_seq]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .get_intent_seq
    ; RCQ-16 F2b root (4): every value-derived field (the selection, and each
    ; type's own GET) of a secret field reads as one fixed word for a remote or
    ; non-owner request. Role, label and intent stay readable.
    mov  edi, r12d
    mov  rsi, [rsp + 32]               ; the request
    call wgt_secret_hidden
    test eax, eax
    jz   .readable
    lea  rbx, [rel str_wgt_withheld]
    jmp  .emit
.readable:
    lea  rdi, [rel str_wf_sel]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .get_sel
    ; --- vtable GET dispatch ---
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_TYPE]
    dec  ecx
    imul rcx, rcx, WT_SZ
    lea  rbx, [rel wgt_types]
    mov  rbx, [rbx + rcx + WT_GET]
    mov  edi, r12d
    mov  rsi, r13
    call rbx
    test rax, rax
    jz   .badfield
    mov  rbx, rax                      ; live value ptr
    jmp  .emit
.get_role:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, [rax + WGI_ROLE]
    test rbx, rbx
    jz   .badfield
    jmp  .emit
.get_label:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, [rax + WGI_LABEL]
    test rbx, rbx
    jz   .badfield
    jmp  .emit
.get_intent:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_INTENT]
    lea  rsi, [rel wgt_intent_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rbx, [rel wgt_intent_buf]
    jmp  .emit
.get_intent_seq:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, [rax + WGI_INTENT_SEQ]
    lea  rsi, [rel wgt_intent_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rbx, [rel wgt_intent_buf]
    jmp  .emit
.get_sel:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    lea  rsi, [rel wgt_sel_buf]
    mov  edi, [rbx + WGI_SEL_LO]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], ','
    inc  rsi
    mov  edi, [rbx + WGI_SEL_HI]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    lea  rbx, [rel wgt_sel_buf]
.emit:
    lea  rdi, [rel str_wo_get]         ; " widget get id="
    call wgt_out_str
    mov  edi, r12d
    call wgt_out_dec
    lea  rdi, [rel str_wo_sp]
    call wgt_out_str
    mov  rdi, r13
    call wgt_out_str
    lea  rdi, [rel str_wo_eq]          ; "="
    call wgt_out_str
    mov  rdi, rbx
    call wgt_out_str
    jmp  .stage
.badid:
    lea  rdi, [rel str_wo_e_id]
    call wgt_out_str
    jmp  .stage
.badfield:
    lea  rdi, [rel str_wo_e_field]
    call wgt_out_str
.stage:
    mov  byte [rel wgt_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; wgt_secret_hidden(EDI=widget id, RSI=request or 0 for the in-flight frame)
; -> EAX 1 = this read must not return the widget's value: a secret-class
; widget (the kit's secret type, or role "password") read in a remote frame
; (any principal, OWNER too) or by a principal other than OWNER. Else 0.
; RCQ-16 F2b (root 23:40:56 (4), rc-sec 23:50:07). Clobbers caller-saved
; registers.
wgt_secret_hidden:
    push rsi
    call wgt_slot_ptr
    mov  ecx, [rel wgt_secret_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    je   .secret
    mov  rdi, [rax + WGI_ROLE]
    test rdi, rdi
    jz   .open
    lea  rsi, [rel str_wgt_role_password]
    call strcmp
    test eax, eax
    jnz  .open
.secret:
    call session_shell_remote_context
    test eax, eax
    jnz  .hidden
    mov  rdi, [rsp]                    ; the request
    call session_shell_request_principal
    cmp  rax, PRIN_OWNER
    jne  .hidden
.open:
    xor  eax, eax
    pop  rsi
    ret
.hidden:
    mov  eax, 1
    pop  rsi
    ret

; VERB: WIDGETLIST — enumerate live widgets + state (the element-tree read the
;   Portal/remote-render follow-on binds to): one " WGT[i] ..." group per slot.
; ---------------------------------------------------------------------------
cmd_verb_widgetlist:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    call wgt_out_reset
    lea  rdi, [rel str_wo_list]        ; " widgets n="
    call wgt_out_str
    xor  ebx, ebx
    xor  r12d, r12d
.count:
    cmp  r12d, [rel wgt_count]
    jae  .count_done
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .count_next
    inc  ebx
.count_next:
    inc  r12d
    jmp  .count
.count_done:
    mov  edi, ebx
    call wgt_out_dec
    xor  r12d, r12d
.loop:
    cmp  r12d, [rel wgt_count]
    jae  .done
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .next
    lea  rdi, [rel str_wo_l_open]      ; " WGT["
    call wgt_out_str
    mov  edi, r12d
    call wgt_out_dec
    lea  rdi, [rel str_wo_l_type]      ; "] type="
    call wgt_out_str
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    imul rax, rax, WT_SZ
    lea  rcx, [rel wgt_types]
    mov  rdi, [rcx + rax + WT_NAME]
    call wgt_out_str
    lea  rdi, [rel str_wo_win]         ; " win="
    call wgt_out_str
    mov  edi, [rbx + WGI_WIN]
    call wgt_out_dec
    lea  rdi, [rel str_wo_x]           ; " x="
    call wgt_out_str
    mov  edi, [rbx + WGI_X]
    call wgt_out_dec
    lea  rdi, [rel str_wo_y]           ; " y="
    call wgt_out_str
    mov  edi, [rbx + WGI_Y]
    call wgt_out_dec
    lea  rdi, [rel str_wo_val]         ; " val="
    call wgt_out_str
    mov  edi, r12d
    mov  rsi, [rsp + 24]               ; the request
    call wgt_secret_hidden
    mov  r8d, eax
    mov  rax, rbx
    call wgt_tf_buf                    ; RCQ-38 L3c: a long field's value
    mov  rdi, rax
    test r8d, r8d
    jz   .val
    lea  rdi, [rel str_wgt_withheld]   ; F2b root (4): a fixed word, never the mask
.val:
    call wgt_out_str
.next:
    inc  r12d
    jmp  .loop
.done:
    mov  byte [rel wgt_out_ready], 1
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; VERB: CATALOG — the command registry, GENERATED from the registry's own
;   self-description accessors (COMMANDS.md §9.4b: never hand-kept). The
;   no-side-door witness: WIDGETSET/WIDGETGET appear here because they ARE
;   registered verbs. " CATALOG verbs=N: PING STATUS ... WIDGETSET ..."
; ---------------------------------------------------------------------------
cmd_verb_catalog:
    call cmd_handler_prologue
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .legacy
    cmp  byte [rax], 0
    je   .legacy
    cmp  dword [rax], 'PAGE'
    je   wgt_catalog_page
    cmp  dword [rax], 'META'
    je   wgt_catalog_page
.legacy:
    push rdi
    push rsi
    push rbx
    push r12
    call wgt_out_reset
    lea  rdi, [rel str_wo_cat]         ; " CATALOG verbs="
    call wgt_out_str
    call command_verb_count
    mov  edi, eax
    call wgt_out_dec
    lea  rdi, [rel str_wo_colon]       ; ":"
    call wgt_out_str
    xor  r12d, r12d
.loop:
    call command_verb_count
    cmp  r12d, eax
    jae  .done
    lea  rdi, [rel str_wo_sp]
    call wgt_out_str
    mov  edi, r12d
    call command_verb_name
    mov  rdi, rax
    call wgt_out_str
    inc  r12d
    jmp  .loop
.done:
    mov  byte [rel wgt_out_ready], 1
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; Additive complete census: CATALOG PAGE <canonical decimal slot>. Registry
; slots (including vacancies) are the cursor, not a second maintained list.
; META uses the same cursor with <=8 whole name:argt:cap:destr rows. The
; three full-width registry accessors are also used by the serial AI catalog.
; Preflight whole names before formatting: at most 16 slots / 900 name bytes,
; leaving ample metadata and formatter headroom in WGT_OUT_MAX. No partial
; name, silent clamp, or nonterminal page without progress is successful.
wgt_catalog_page:
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    xor  ebp, ebp
    mov  byte [rel wgt_out_ready], 0
    cmp  dword [rax], 'META'
    jne  .page
    mov  ebp, 1
    jmp  .operation
.page:
    cmp  dword [rax], 'PAGE'
    jne  .bad
.operation:
    cmp  byte [rax + 4], ' '
    jne  .bad
    add  rax, 5
    xor  r12d, r12d
    cmp  byte [rax], '0'
    jne  .digits
    cmp  byte [rax + 1], 0
    jne  .bad
    jmp  .cursor
.digits:
    movzx edx, byte [rax]
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    imul r12d, r12d, 10
    add  r12d, edx
    cmp  r12d, VERB_MAX              ; actual monolithic allocation/admission bound
    ja   .bad
    inc  rax
    cmp  byte [rax], 0
    jne  .digits
.cursor:
    call command_verb_count
    mov  r14d, eax
    cmp  r14d, VERB_MAX
    ja   .bad
    cmp  r12d, r14d
    ja   .bad
    mov  r13d, r12d
    xor  r15d, r15d
.measure:
    cmp  r13d, r14d
    jae  .format
    mov  eax, r13d
    sub  eax, r12d
    test ebp, ebp
    jz   .page_limit
    cmp  eax, 8
    jae  .format
.page_limit:
    cmp  eax, 16
    jae  .format
    mov  edi, r13d
    call command_verb_name
    xor  ecx, ecx
.length:
    cmp  byte [rax + rcx], 0
    je   .length_done
    inc  ecx
    cmp  ecx, 900
    jbe  .length
    jmp  .budget
.length_done:
    test ecx, ecx
    jnz  .nonempty
    inc  ecx                        ; vacancy is exactly '-'
.nonempty:
    test ebp, ebp
    jz   .separator
    add  ecx, 64                    ; 3 full u64 decimals + colons; never clamp metadata
.separator:
    cmp  r13d, r12d
    je   .first
    inc  ecx                        ; comma
.first:
    add  ecx, r15d
    cmp  ecx, 900
    ja   .budget
    mov  r15d, ecx
    inc  r13d
    jmp  .measure
.budget:
    cmp  r13d, r12d
    je   .bad                       ; a single oversized name cannot progress
.format:
    call wgt_out_reset
    lea  rdi, [rel str_wo_cat_page]
    test ebp, ebp
    jz   .prefix
    lea  rdi, [rel str_wo_cat_meta]
.prefix:
    call wgt_out_str
    mov  edi, r14d
    call wgt_out_dec
    lea  rdi, [rel str_wo_cat_from]
    call wgt_out_str
    mov  edi, r12d
    call wgt_out_dec
    lea  rdi, [rel str_wo_cat_next]
    call wgt_out_str
    mov  edi, r13d
    call wgt_out_dec
    lea  rdi, [rel str_wo_cat_more]
    call wgt_out_str
    xor  edi, edi
    cmp  r13d, r14d
    setb dil
    call wgt_out_dec
    lea  rdi, [rel str_wo_cat_names]
    test ebp, ebp
    jz   .columns
    lea  rdi, [rel str_wo_cat_rows]
.columns:
    call wgt_out_str
    mov  ebx, r12d
.emit:
    cmp  ebx, r13d
    jae  .end
    cmp  ebx, r12d
    je   .name
    lea  rdi, [rel str_wo_cat_comma]
    call wgt_out_str
.name:
    mov  edi, ebx
    call command_verb_name
    mov  rdi, rax
    cmp  byte [rdi], 0
    jne  .append
    lea  rdi, [rel str_wo_cat_vacant]
.append:
    call wgt_out_str
    test ebp, ebp
    jz   .advance
    lea  rdi, [rel str_wo_colon]
    call wgt_out_str
    mov  edi, ebx
    call command_verb_argt
    mov  rdi, rax
    call wgt_out_dec
    lea  rdi, [rel str_wo_colon]
    call wgt_out_str
    mov  edi, ebx
    call command_verb_cap
    mov  rdi, rax
    call wgt_out_dec
    lea  rdi, [rel str_wo_colon]
    call wgt_out_str
    mov  edi, ebx
    call command_verb_destr
    mov  rdi, rax
    call wgt_out_dec
.advance:
    inc  ebx
    jmp  .emit
.end:
    lea  rdi, [rel str_wo_cat_end]
    call wgt_out_str
    mov  byte [rel wgt_out_ready], 1
    xor  eax, eax
    jmp  .return
.bad:
    mov  eax, CMDE_BADARG
.return:
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  [rsi + RSP_CODE], rax
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    ret

; --- staged-reply buffer helpers (bm_out_* shape, BOUNDED: WIDGETLIST/CATALOG
;     lines grow with live state, so every append clamps at WGT_OUT_MAX) ---
wgt_out_reset:
    lea  rax, [rel wgt_out_buf]
    mov  [rel wgt_out_cur], rax
    ret
wgt_out_str:
    mov  rsi, [rel wgt_out_cur]
    lea  rdx, [rel wgt_out_buf + WGT_OUT_MAX - 1]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel wgt_out_cur], rsi
    ret
wgt_out_dec:
    mov  rsi, [rel wgt_out_cur]
    lea  rax, [rel wgt_out_buf + WGT_OUT_MAX - 24]
    cmp  rsi, rax
    jae  .skip                         ; <24 bytes headroom: clamp (fmt_dec needs room)
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel wgt_out_cur], rsi
.skip:
    ret

; --- gui/widget data ---------------------------------------------------------
align 8
; Stock secret input: its public WGI_VAL is ALWAYS a mask. The one focused
; editor's transient bytes live only in this kit-owned buffer, never in a form,
; selection, clipboard, tree or WIDGETGET. Changing focus/owner wipes it.
wgt_secret_register:
    lea  rdi, [rel str_wgt_secret]
    lea  rsi, [rel wgt_textfield_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_secret_set]
    lea  r8, [rel wgt_textfield_get]
    mov  r9, (28 << 32) | 320
    call wgt_type_register
    mov  [rel wgt_secret_type], eax
    ret

wgt_secret_set:
    ; Secret input is local ingress only; remote field mutation cannot write it.
    mov  eax, 1
    ret

wgt_secret_clear:
    push rdi
    push rcx
    push rax
    lea  rdi, [rel wgt_secret_bytes]
    xor  eax, eax
    mov  ecx, 128
    cld
    rep  stosb
    mov  dword [rel wgt_secret_len], 0
    mov  byte [rel wgt_secret_tainted], 0
    call wgt_secret_revise
    mov  edi, [rel wgt_secret_owner]
    cmp  edi, [rel wgt_count]
    jae  .cleared
    call wgt_slot_ptr
    mov  dword [rax + WGI_VLEN], 0
    mov  dword [rax + WGI_CARET], 0
    lea  rdi, [rax + WGI_VAL]
    xor  eax, eax
    mov  ecx, 40
    rep  stosb
.cleared:
    mov  dword [rel wgt_secret_owner], -1
    pop  rax
    pop  rcx
    pop  rdi
    ret

wgt_secret_key:
    push rbx
    push r12
    mov  r12d, edi
    mov  ebx, eax
    cmp  edi, [rel wgt_secret_owner]
    je   .owned
    call wgt_secret_clear
    mov  [rel wgt_secret_owner], r12d
.owned:
    mov  ecx, [rel wgt_secret_len]
    lea  rdx, [rel wgt_secret_bytes]
    cmp  ebx, GUI_KEY_BACKSPACE
    je   .back
    cmp  ebx, GUI_KEY_ESC
    je   .erase
    cmp  ebx, 0x20
    jb   .done
    cmp  ebx, 0x7e
    ja   .high
    cmp  ecx, 128
    jae  .done
    mov  [rdx + rcx], bl
    inc  ecx
    jmp  .mask
.back:
    test ecx, ecx
    jz   .done
    dec  ecx
    mov  byte [rdx + rcx], 0
.mask:
    ; Sticky across edits, even deletion to empty. Only an explicit full clear
    ; starts a clean buffer. A final HUMAN Enter never sanitizes prior input.
    cmp  byte [rel input_key_origin], KO_HUMAN
    je   .origin
    mov  byte [rel wgt_secret_tainted], 1
.origin:
    call wgt_secret_revise
    mov  [rel wgt_secret_len], ecx
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  ecx, WGI_VAL_MAX
    jbe  .mask_length
    mov  ecx, WGI_VAL_MAX
.mask_length:
    mov  [rax + WGI_VLEN], ecx
    mov  [rax + WGI_CARET], ecx
    lea  rdi, [rax + WGI_VAL]
    mov  byte [rdi + rcx], 0
    mov  al, '*'
    cld
    rep  stosb
    jmp  .draw
.high:
    cmp  ebx, GUI_KEY_TEXT
    jne  .done
    lock inc qword [rel wgt_text_refused] ; RCQ-38 L3b: a secret is ASCII; text is refused, counted
    jmp  .done
.erase:
    call wgt_secret_clear
.draw:
    mov  edi, r12d
    call wgt_draw_id
.done:
    mov  eax, 1
    pop  r12
    pop  rbx
    ret

; Non-secret custody metadata only. Saturation invalidates deferred gestures
; forever this boot rather than permitting revision wrap/ABA.
wgt_secret_revise:
    cmp  qword [rel wgt_secret_revision], -1
    je   .out
    inc  qword [rel wgt_secret_revision]
.out:
    ret

wgt_secret_human:
    xor  eax, eax
    cmp  dword [rel wgt_secret_len], 0
    je   .out
    cmp  dword [rel wgt_secret_len], 128
    ja   .out
    cmp  byte [rel wgt_secret_tainted], 0
    jne  .out
    mov  eax, 1
.out:
    ret

; Exercise the real secret editor and its public/clipboard refusal paths.
; EDI=empty secret widget -> EAX=0 pass / -1 fail. No credential is enrolled
; or compared; the synthetic character is erased before the surface is shown.
wgt_secret_selftest:
    push rbx
    push r12
    mov  r12d, edi
    mov  ebx, -1
    call wgt_secret_clear
    mov  edi, r12d
    mov  eax, 'x'
    call wgt_textfield_key             ; same type dispatch used by physical input
    cmp  dword [rel wgt_secret_len], 1
    jne  .clear
    cmp  byte [rel wgt_secret_bytes], 'x'
    jne  .clear
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  word [rax + WGI_VAL], '*'
    jne  .clear
    cmp  dword [rax + WGI_VLEN], 1
    jne  .clear
    mov  edi, r12d
    call wgt_textfield_clip_get
    cmp  edx, 1
    jne  .clear
    mov  edi, r12d
    call wgt_secret_set
    test eax, eax
    jz   .clear
    ; Public setters cannot replace the mask with plaintext, even when a
    ; caller bypasses the type's own refusing setter and uses the shared API.
    mov  edi, r12d
    lea  rsi, [rel str_wgt_secret]
    call wgt_set_text
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  word [rax + WGI_VAL], '*'
    jne  .clear
    mov  edi, r12d
    mov  eax, GUI_KEY_BACKSPACE
    call wgt_textfield_key
    cmp  dword [rel wgt_secret_len], 0
    jne  .clear
    cmp  byte [rel wgt_secret_bytes], 0
    jne  .clear
    xor  ebx, ebx
.clear:
    call wgt_secret_clear
    cmp  dword [rel wgt_secret_len], 0
    jne  .bad
    lea  rdx, [rel wgt_secret_bytes]
    mov  ecx, 128
.zero:
    cmp  byte [rdx], 0
    jne  .bad
    inc  rdx
    loop .zero
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + WGI_VAL], 0
    jne  .bad
    cmp  dword [rax + WGI_VLEN], 0
    jne  .bad
    mov  eax, ebx
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_widget_0 0
str_wgt_secret: db "secret",0
wgt_secret_type: dd -1
wgt_secret_owner: dd -1
wgt_secret_len: dd 0
wgt_secret_tainted: db 0
align 8
wgt_secret_revision: dq 0
wgt_secret_bytes: times 128 db 0
wgt_key_filter: dq 0
wgt_click_hook: dq 0
wgt_form_event_hook: dq 0              ; trusted data-event observer, independent of click chain
wgt_text_paint_hook: dq 0               ; boot-installed public label/button adapter
wgt_button_open_hook: dq 0
wgt_button_get_hook: dq 0
wgt_action_hook: dq 0

wgt_types:      times (WTYPE_MAX * WT_SZ) db 0
wgt_type_count: dd 0
str_wtype_headroom:      db "[PAOS64] widget type table headroom [gui.wtype.headroom] free=",0
str_wtype_headroom_fail: db "[PAOS64] widget type table headroom FAILED [gui.wtype.headroom.fail] free=",0
str_wtype_used:          db " used=",0
str_wtype_max:           db " max=",0
wtype_dec_buf:           db 0,0,0,0
wgt_field_rect: db "rect",0
wgt_paint_depth: db 0
wgt_overlay_pass: db 0
wgt_paint_suspended: db 0
align 8
wgt_type_capture: times WTYPE_MAX dq 0  ; per-type pointer capture fn (wgt_type_bind_capture), 0 none
wgt_capture_id:   dd -1                 ; the widget holding the pointer capture, -1 none
wgt_capture_type: dd 0                  ; its WGI_TYPE and WGI_WIN at the press (stale check)
wgt_capture_win:  dd -1
wgt_type_capture_btns: times WTYPE_MAX db 0 ; 1 = the type's capture takes middle/right (wgt_type_capture_buttons)
wgt_type_capture_moves: times WTYPE_MAX db 0 ; opt-in buttonless motion
wgt_capture_btn:  db 0                  ; button of the captured gesture: 0 left, 1 middle, 2 right
align 8
wgt_tbl:       times (WGT_MAX * WGI_SZ) db 0
wgt_count:      dd 0
wgt_alloc_next: dd -1                  ; WK-B7B: next id of an active form reservation, -1 = append
align 8
wgt_rz_tbl:     times (WGT_MAX * WRZ_SZ) db 0   ; per-widget resize anchor records (wgt_resize_window)
align 8
wgt_textfield_event_hook: dq 0
wgt_textfield_event_hook2: dq 0
wgt_out_cur:    dq 0
wgt_out_ready:  db 0                   ; 1 = wgt_out_buf holds a staged reply (LEAN path)
wgt_m_library:  db 0                   ; earned: vtable(2 types) + both demo widgets drawn
wgt_m_registry: db 0                   ; earned: all 6 element verbs registered
align 4
wgt_focus_id:   dd -1
wgt_tab_reverse: db 0                   ; G3: 1 = the pending Tab is Shift+Tab (set by input_route)
wgt_focus_visible: db 0                 ; RCQ-16: 1 = focus last moved by Tab; one global modality flag, cleared by any pointer press edge (wm_pointer_event) and by wgt_focus_at
align 4
wgt_hot_id:     dd -1                   ; RCQ-16 S4: the widget under the pointer (no-button motion), -1 none. Paint state only
wgt_press_id:   dd -1                   ; RCQ-16 S4: the widget a held left press landed on, -1 none. Paint state only
wgt_focus_by_win: times WM_MAX dd -1
align 8
wgt_out_buf:    times WGT_OUT_MAX db 0
wgt_parse_buf:  times 160 db 0
wgt_sel_buf:    times 32 db 0
wgt_intent_buf: times 24 db 0
wgt_bool_buf: times 2 db 0

; --- type + field names (matched by table walk / strcmp, never hardcoded ids) ---
str_wt_button:    db "button", 0
str_wt_textfield: db "textfield", 0
str_wt_label:     db "label", 0
str_wf_value:     db "value", 0
str_wf_text:      db "text", 0
str_wf_open:      db "open", 0
str_wf_action:    db "action", 0
str_wf_disabled:  db "disabled", 0
str_wf_label:     db "label", 0
str_wf_role:      db "role", 0
str_wf_intent:    db "intent", 0
str_wf_intent_seq: db "intent_seq", 0
str_wf_sel:       db "sel", 0
str_wf_submits:   db "submits", 0
str_wt_demo_ok:   db "OK", 0
str_wt_demo_ready: db "ready", 0

; --- verb names (matched verbatim by command_lookup) ---
str_verb_widgettypes: db "WIDGETTYPES", 0
str_verb_widgetnew:   db "WIDGETNEW", 0
str_verb_widgetset:   db "WIDGETSET", 0
str_verb_widgetget:   db "WIDGETGET", 0
str_verb_widgetlist:  db "WIDGETLIST", 0
str_verb_catalog:     db "CATALOG", 0

; --- staged reply fragments ---
str_wo_types:   db " widget types:", 0
str_wgt_withheld: db "withheld", 0  ; F2b: a secret field's value, caret and mask
str_wgt_role_password: db "password", 0
str_wgt_set_text_refused: db "[PAOS64] wgt_set_text refused id=", 0      ; STM-02: + serial_hex64 of the id
str_wgt_set_text_refused_tag: db " [gui.widget.set_text.refused]", 13, 10, 0
str_wo_sp:      db " ", 0
str_wo_eq:      db "=", 0
str_wo_colon:   db ":", 0
str_wo_n:       db " n=", 0
str_wo_vt:      db " vtable=1", 0
str_wo_new:     db " widget new type=", 0
str_wo_id:      db " id=", 0
str_wo_win:     db " win=", 0
str_wo_set:     db " widget set id=", 0
str_wo_field:   db " field=", 0
str_wo_len:     db " len=", 0
str_wo_get:     db " widget get id=", 0
str_wo_list:    db " widgets n=", 0
str_wo_l_open:  db " WGT[", 0
str_wo_l_type:  db "] type=", 0
str_wo_x:       db " x=", 0
str_wo_y:       db " y=", 0
str_wo_val:     db " val=", 0
str_wo_cat:     db " CATALOG verbs=", 0
str_wo_cat_meta: db " CATALOG meta=1 slots=", 0
str_wo_cat_rows: db " rows=", 0
str_wo_cat_page: db " CATALOG page=1 slots=", 0
str_wo_cat_from: db " from=", 0
str_wo_cat_next: db " next=", 0
str_wo_cat_more: db " more=", 0
str_wo_cat_names: db " names=", 0
str_wo_cat_comma: db ",", 0
str_wo_cat_vacant: db "-", 0
str_wo_cat_end: db " end=1", 0
str_wo_e_type:  db " widget new=ERR bad_type expected=button|textfield|label", 0
str_wo_e_win:   db " widget new=ERR bad_win max=8", 0
str_wo_e_full:  db " widget new=ERR full max=48", 0
str_wo_e_id:    db " widget op=ERR bad_id (WIDGETLIST enumerates live ids)", 0
str_wo_e_field: db " widget op=ERR bad_field expected=value|text|label|role|sel", 0
str_wo_e_size:  db " widget set=ERR oversize max=31", 0
str_wo_e_locked: db " widget op=ERR locked", 0
str_wo_e_owner: db " widget op=ERR not_owner", 0

; --- boot markers (serial; the QEMU regression + BOOTLOG tokens grade these) ---
str_wgt_m_lib:     db "[PAOS64] M6 widget: library up — button+textfield through ONE vtable, drawn via shared fb primitives in wm slot 0 [ui.widget.library]", 13, 10, 0
str_wgt_label:     db "[PAOS64] M6 widget: label type registered through the vtable (3 types, no core edit) [ui.widget.label]", 13, 10, 0
str_wgt_m_libfail: db "[PAOS64] M6 widget: library init FAILED (type/demo registration)", 13, 10, 0
str_wgt_m_reg:     db "[PAOS64] M6 widget: element verbs WIDGETTYPES/WIDGETNEW/WIDGETSET/WIDGETGET/WIDGETLIST + CATALOG registered [ui.widget.registry]", 13, 10, 0
str_wgt_m_regfail: db "[PAOS64] M6 widget: verb registration FAILED (registry full?)", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_gui_widget_0
; RCQ-38 L3b: zero-initialised text-entry state (core/abi/wdata.inc WDATA_BSS_DEFER).
%macro WDATA_BSS_gui_widget_text 0
alignb 8
wgt_text_refused:  resq 1               ; text a focused textfield refused (ASCII-only, no room, not UTF-8, control)
wgt_preedit_epoch: resq 1               ; session_authority_epoch when the pre-edit was set
wgt_text_len:      resd 1               ; GUI_KEY_TEXT's payload: bytes in wgt_text_buf
wgt_preedit_id:    resd 1               ; the textfield id + 1 that holds the pre-edit, 0 none
wgt_preedit_len:   resd 1
wgt_preedit_caret: resd 1               ; the IME caret's byte offset in the pre-edit
wgt_text_buf:      resb WGT_TEXT_CAP
wgt_preedit_buf:   resb WGT_TEXT_CAP
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_widget_text
; RCQ-38 L3c: the long textfield values (wgt_textfield_long). An entry is the
; value of the slot named in wgt_long_owner AND whose WGI_RSVD is its index + 1;
; it is wiped when that slot is created again, retired or rolled back.
%macro WDATA_BSS_gui_widget_long 0
alignb 8
wgt_long_owner:    resq WGT_LONG_N      ; the owning slot's address, 0 = free
wgt_long_pool:     resb WGT_LONG_N * (WGT_LONG_MAX + 1)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_widget_long
