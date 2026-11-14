;; MODULE gui/input_route
;; LAYER 6
;; EXPORTS input_modifiers_are_human, input_route_live_hook, input_route_live_no_kbd, input_ai_key_pop, input_ai_counts, input_ai_refused, input_ai_locked, input_ai_cancelled, input_ai_dropped, gui_input_route_init, gui_input_route_tick, input_route_tl_live, input_kbd_routed, input_kbd_submits, input_kbd_mods, input_kbd_caps, gui_input_global_key_hook, gui_input_modal_key_hook, input_win_down, input_win_chord, input_layout_set, input_layout_id, input_text_dropped, input_layout_selectable, input_layout_tags, input_kbd_ctx_other, input_dead_origin_other, input_ime_ops, input_ime_lq_scalar, input_ime_tray, input_ime_pop, input_layout_focus_check
;; IMPORTS gui/calendar, core/log, core/time, core/keyboard_layout, core/unicode_edit, dev/usb/hid, dev/input/ps2, gui/window_mgmt, gui/widget, gui/widget_tabstrip, gui/summon_palette, gui/chat_app, gui/start_programs, boot/serial, sec/session
;; CAPS CAP_GUI
;; OWNER saga:verb_console
; Contract 2151. IRQ1 is enqueue-only; this bounded idle hook ports the proven
; E0-aware Set-1 shape and routes each translated event to one focus snapshot.

INPUT_ROUTE_BUDGET equ 16
INPUT_LOCK_NUM       equ 1
INPUT_LOCK_CAPS      equ 2
INPUT_LOCK_CAPS_HAND equ 4
; RCQ-09: private per-side modifier bits; input_kbd_mods keeps its consumer
; layout (1 Shift, 2 Ctrl, 4 Alt) and is derived from these.
INPUT_SIDE_LSHIFT equ 0x01
INPUT_SIDE_RSHIFT equ 0x02
INPUT_SIDE_LCTRL  equ 0x04
INPUT_SIDE_RCTRL  equ 0x08
INPUT_SIDE_LALT   equ 0x10
INPUT_SIDE_RALT   equ 0x20
; RCQ-38 L1: a non-US layout goes through core/keyboard_layout (HID usage in,
; Unicode scalars out). Layout 0 (en-US) keeps the ASCII tables below.
INPUT_LAYOUT_COUNT equ 4
INPUT_LQ_MAX       equ 4                ; flushed mark + two scalars per key
INPUT_KBD_PENDING  equ 28               ; KEYBOARD_LAYOUT.md: pending dead ID (u32)
                                        ; read by sec/keyprov (dead-key slot pin): PENDING != 0 is a contract
INPUT_HID_SPACE    equ 0x2C
; RCQ-38 L2 (root 12:30:39, relops 12:31:21): a non-US layout is selectable only
; in a build that carries every consumer of its scalars >= 0x80. A build
; constant, not boot state: L3 (the UTF-8 text field) and L4 (Terminal) each
; set their bit here in their own diff.
INPUT_TC_TEXTFIELD equ 1
INPUT_TC_TERMINAL  equ 2
INPUT_TC_ALL       equ INPUT_TC_TEXTFIELD | INPUT_TC_TERMINAL
INPUT_TEXT_CONSUMERS_BUILT equ INPUT_TC_ALL ; RCQ-38 L3b: the UTF-8 text field; L4: the Terminal
INPUT_LAYOUT_TAG_SLOT equ 3              ; input_layout_tags: 'US' 'ES' 'FR' 'DE', NUL-ended
; RCQ-38 I3b-1 (root 15:25 Q1): whether paos.asm links the IME (gui/ime_core, ime_view, ime_dict_absent and
; ime_route). One value for every build and floor, never keyed to PAOS_PUBLIC_FLOOR or a lab profile; %assign,
; not equ, because it gates %include. The router names no IME symbol but ime_route_init: gui/ime_route fills
; input_ime_ops there, and an empty table leaves every path below as it was without the IME.
%assign IME_BUILT 1
INPUT_IME_STAGE    equ 0                ; input_ime_ops: stage(EDI key) -> EAX 1 the IME took it, 0 deliver it
INPUT_IME_PUMP     equ 8                ; pump() -> EAX the next key the IME releases (its commit, then the key
                                        ;   it passed), -1 none; its origin is in input_key_origin
INPUT_IME_TOGGLE   equ 16               ; toggle() -> EAX 1 toggled, 0 no IME target: Ctrl+Space from the owner's hand
INPUT_IME_RESET    equ 24               ; reset(): every dead-key cancel (a focus, session, lock or layout
                                        ;   change); after a session or lock change the method is OFF
INPUT_IME_TRAY_NODICT equ 0x80000000    ; input_ime_tray: 0 = the method is OFF (no cell), else ime_view_mode's
                                        ;   scalar, | this bit while no dictionary is bound (root 16:01:48 (2)(a))
INPUT_IME_POP_KIND  equ 0               ; input_ime_pop, the candidate window gui/window paints (I3b-1 (c)), u32 fields:
INPUT_IME_POP_X     equ 4               ;   KIND 0 hidden, else INPUT_IME_POP_CANDS or one of the notices;
INPUT_IME_POP_Y     equ 8               ;   X Y W H its screen rect; WIN the window that hosts the field;
INPUT_IME_POP_W     equ 12              ;   ROWS candidate rows, SEL the selected one, MARKS 1 = the '<' '>' line;
INPUT_IME_POP_H     equ 16              ;   per row: u32 entries, then INPUT_IME_POP_CELLS u32 entries, each a
INPUT_IME_POP_WIN   equ 20              ;   scalar | its cells (1 or 2) << 24, the cut mark '>' included
INPUT_IME_POP_ROWS  equ 24
INPUT_IME_POP_SEL   equ 28
INPUT_IME_POP_MARKS equ 32
INPUT_IME_POP_ROW0  equ 36
INPUT_IME_POP_PAGE  equ 9               ; = gui/ime_view's IMV_PAGE (census-pinned)
INPUT_IME_POP_CELLS equ 40              ; = gui/ime_view's IMV_COLS (census-pinned)
INPUT_IME_POP_ROW_SIZE equ 4 + 4 * INPUT_IME_POP_CELLS
INPUT_IME_POP_SIZE  equ INPUT_IME_POP_ROW0 + INPUT_IME_POP_PAGE * INPUT_IME_POP_ROW_SIZE
INPUT_IME_POP_PADX  equ 8               ; one 8-px cell either side (gui/ime_view's IMV_PADX: 2 cells in all)
INPUT_IME_POP_PADY  equ 2               ; = gui/ime_view's IMV_PADY
INPUT_IME_POP_LABEL equ 24              ; = gui/ime_view's IMV_LABEL cells x 8 px: "k." and a gap
INPUT_IME_POP_NOTICE equ 13             ; the longest notice in cells ("no candidates", "no dictionary")
INPUT_IME_POP_CANDS equ 1               ; KIND
INPUT_IME_POP_NODICT equ 2              ;   Space with no dictionary bound (root 16:01:48 (2)(a))
INPUT_IME_POP_UNAVAIL equ 3             ;   a bound dictionary that cannot answer
INPUT_IME_POP_NOCANDS equ 4             ;   no candidate for the reading
; RCQ-51 (root 19:23:15): the AI key. The Copilot key sends Win+Shift+F23 (Set-1 E0 5B, 2A, 6E); Win+Space is
; its fallback chord on every keyboard. Either chord from the owner's hand, unlocked, is one gesture machine
; that reports typed events into input_ai_ring, never a typed key: TAP (released before HOLD and no second press
; within DOUBLE of the release), DOUBLE (a second press within DOUBLE; its release reports nothing), HOLD_START
; (still down at HOLD) and HOLD_END (its release). Without a monotonic clock every press is a TAP. A chord that
; is not wholly the owner's hand counts in input_ai_refused, one on the sign-in surface in input_ai_locked;
; neither reports. A lock ends a gesture: a held press reports HOLD_END if it had started, a pending tap is
; dropped (input_ai_cancelled). Owner Esc also retires pending/held gestures via that counter,
; with no later tap/hold record. The consumer polls input_ai_key_pop; INPUT owns no AI action.
INPUT_AI_HOLD_US   equ 400000
INPUT_AI_DOUBLE_US equ 300000
INPUT_AI_TAP        equ 1               ; record kind
INPUT_AI_DOUBLE     equ 2
INPUT_AI_HOLD_START equ 3
INPUT_AI_HOLD_END   equ 4
INPUT_AI_SRC_COPILOT  equ 1             ; record source: Win+(Shift+)F23
INPUT_AI_SRC_FALLBACK equ 2             ;   Win+Space
INPUT_AI_DOWN_HELD   equ 1              ; input_ai_down: a reporting press is held
INPUT_AI_DOWN_DOUBLE equ 2              ;   the second press of a DOUBLE is held
INPUT_AI_DOWN_VOID   equ 3              ;   a refused/locked/cancelled press: nothing until Win is up
INPUT_AI_RING      equ 8                ; records (a power of two)
INPUT_AI_REC       equ 16               ; u8 kind, u8 source, u8 origin, u8 0, u32 seq, u64 t_us (monotonic)

gui_input_route_tick:
    call input_route_timeline_tick       ; measurement only: boot.input.{kbd,ptr}.live
    call input_route_live_hook_tick      ; boot audit (2): after the kbd mark, never before
    call guest_desktop_tick              ; RCQ-23: guest window open/close/refresh; no-op without one
    call input_layout_watch              ; RCQ-38 L1: a lock or unlock cancels dead keys
    call input_ai_tick                   ; RCQ-51: AI-key hold / tap deadlines, lock cancel
    push rbx
    push r12
    push r13
    mov  r12d, INPUT_ROUTE_BUDGET
.next:
    mov  rax, [rel input_ime_ops + INPUT_IME_PUMP] ; RCQ-38 I3b-1: an IME commit goes before any later key
    test rax, rax
    jz   .no_ime_pump
    call rax
    cmp  eax, -1
    jne  .deliver                       ; its own output: the stage lets it pass
.no_ime_pump:
    mov  eax, [rel input_lq_head]        ; RCQ-38 L1: scalars of the last key go first
    cmp  eax, [rel input_lq_tail]
    jne  .lq_pop
    test r12d, r12d
    jz   .out
    call ps2_kbd_dequeue
    cmp  eax, -1
    je   .out
    dec  r12d
    mov  bl, al
    movzx edi, al
    call guest_desktop_key_byte          ; RCQ-23: a captured guest takes the raw byte
    test eax, eax
    jnz  .next
    ; GA0-K: input_key_origin is the origin of the key being built. A byte
    ; after an E0/E1 prefix merges with the prefix's origin, so one injected
    ; byte makes the whole key injected. Every delivery below reads it.
    movzx eax, byte [rel ps2_kbd_last_origin]
    cmp  byte [rel input_kbd_e0], 0
    jne  .origin_merge
    cmp  byte [rel input_kbd_e1], 0
    je   .origin_set
.origin_merge:
    movzx edx, byte [rel input_key_origin]
    call ps2_kbd_origin_merge
.origin_set:
    mov  [rel input_key_origin], al
    cmp  al, KO_HUMAN
    je   .origin_noted
    inc  dword [rel input_other_origin_seq]  ; T5-15.4: ends an Explorer HUMAN latch
.origin_noted:
    cmp  byte [rel input_kbd_e1], 0
    je   .no_e1
    dec  byte [rel input_kbd_e1]        ; Pause: E1 1D 45 / E1 9D C5 is not Ctrl/NumLock
    jmp  .next
.no_e1:
    cmp  byte [rel input_kbd_e0], 0
    jne  .extended
    cmp  bl, 0xE1
    jne  .not_e1
    mov  byte [rel input_kbd_e1], 2
    jmp  .next
.not_e1:
    cmp  bl, 0xE0
    jne  .ordinary
    mov  byte [rel input_kbd_e0], 1
    jmp  .next
.extended:
    mov  byte [rel input_kbd_e0], 0
    test bl, 0x80
    jnz  .extended_release
    mov  byte [rel input_altshift], 0   ; RCQ-51: an extended make (Win, RAlt, RCtrl, navigation) ends Alt+Shift
    cmp  bl, 0x5B
    je   .win_on
    cmp  bl, 0x5C                       ; right Win (USB HID maps it to E0 5C too)
    je   .win_on
    cmp  bl, 0x1D                       ; Right Ctrl / Right Alt update modifier
    je   .rctrl_on                      ; state even while Win is held
    cmp  bl, 0x38
    je   .ralt_on
    cmp  bl, 0x2A                       ; PS/2 fake shift (E0 2A / E0 36) around
    je   .next                          ; Num-pad-mode navigation: never a Shift
    cmp  bl, 0x36
    je   .next
    cmp  byte [rel input_win_down], 1   ; Win+<extended key> is a shell chord
    je   .win_chord
    cmp  bl, 0x1C                       ; keypad Enter
    je   .key_enter
    cmp  bl, 0x35                       ; keypad /
    je   .key_slash
.nav_scan:                              ; E0 navigation, and the NumLock-off keypad
    cmp  bl, 0x48
    je   .key_up
    cmp  bl, 0x50
    je   .key_down
    cmp  bl, 0x4B
    je   .key_left
    cmp  bl, 0x4D
    je   .key_right
    cmp  bl, 0x47
    je   .key_home
    cmp  bl, 0x4F
    je   .key_end
    cmp  bl, 0x49
    je   .key_pgup
    cmp  bl, 0x51
    je   .key_pgdn
    cmp  bl, 0x52
    je   .key_insert
    cmp  bl, 0x53                       ; G3: Delete (E0 53)
    je   .key_delete
    jmp  .next
.extended_release:
    and  bl, 0x7F
    cmp  bl, 0x5B
    je   .win_off
    cmp  bl, 0x5C
    je   .win_off
    cmp  bl, 0x1D
    je   .rctrl_off
    cmp  bl, 0x38
    je   .ralt_off
    jmp  .next                          ; fake-shift E0 AA/B6 and key releases: no state
.ordinary:
    test bl, 0x80
    jnz  .release
    mov  byte [rel input_altshift], 0   ; RCQ-51: any make ends an Alt+Shift chord (a modifier make re-arms below)
    cmp  bl, 0x2A
    je   .shift_on
    cmp  bl, 0x36
    je   .rshift_on
    cmp  bl, 0x1D
    je   .ctrl_on
    cmp  bl, 0x38
    je   .alt_on
    cmp  bl, 0x3A
    je   .caps
    cmp  bl, 0x45
    je   .numlock
    ; RCQ-51: retire AI intent before Win/modal/IME delivery can consume Esc.
    ; Guest capture already took its raw byte above; no guest key is stolen.
    cmp  bl, 0x01
    jne  .not_ai_escape
    call input_ai_escape
.not_ai_escape:
    ; UI wave 2 B10: with Win held, an ordinary make is a shell chord and is
    ; never typed (modifier makes above keep updating the modifier state).
    cmp  byte [rel input_win_down], 1
    je   .win_chord
    cmp  bl, 0x39                       ; RCQ-51: Ctrl+Space, the IME toggle on an IME textfield
    je   .ctrl_space
.ordinary_route:
    ; SEC R1 K1b (rc-sec 03:11:24): a shell shortcut acts only on the owner's
    ; hand, the key and every held modifier. An injected chord (KBINJ,
    ; TERMFEED, HOOK INPUT) is an ordinary key for the focused window.
    call input_key_is_hand
    jne  .not_shortcut
    cmp  byte [rel input_kbd_sides_inj], 0
    jne  .not_shortcut
    cmp  byte [rel input_layout_id], 0  ; RCQ-38 L1: on a non-US layout right Alt
    je   .shortcut_mods                 ; is AltGr: no Alt or Ctrl shortcut with it
    test byte [rel input_kbd_sides], INPUT_SIDE_RALT
    jnz  .not_shortcut
.shortcut_mods:
    ; G3 (2026-09-30, usage suite TAB-06/WIN-03): shell shortcuts on the
    ; focused window, never while the Summon palette (the one modal keyboard
    ; surface; its hook stays installed while closed) owns the keyboard, and
    ; never under the lock (RCQ-16 F2b-1): the sign-in form has no windows.
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .no_shortcut
    cmp  byte [rel summon_palette_open], 1
    je   .no_shortcut
    test byte [rel input_kbd_mods], 4   ; Alt+F4 closes the focused window
    jz   .no_alt_f4
    cmp  bl, 0x3E
    jne  .no_shortcut
    cmp  byte [rel input_key_origin], KO_HUMAN
    jne  .next                          ; SEC-winmove (C) (root 14:55:23): a key that is not KO_HUMAN takes
    call input_close_focused            ; no window shortcut; consumed as a no-op (queued keys have no principal)
    jmp  .next
.no_alt_f4:
    test byte [rel input_kbd_mods], 2   ; Ctrl+T / Ctrl+W / Ctrl+(Shift+)Tab: tabs
    jz   .no_shortcut
    cmp  byte [rel input_layout_id], 0
    jne  .tab_shortcut_layout
    mov  esi, 1                         ; TS_KEY_NEW
    cmp  bl, 0x14
    je   .tab_shortcut
    mov  esi, 4                         ; TS_KEY_CLOSE
    cmp  bl, 0x11
    je   .tab_close
    cmp  bl, 0x0F
    jne  .no_shortcut
.tab_cycle:
    mov  esi, 2                         ; TS_KEY_NEXT
    test byte [rel input_kbd_mods], 1
    jz   .tab_shortcut
    mov  esi, 3                         ; TS_KEY_PREV
    jmp  .tab_shortcut
.tab_shortcut_layout:                   ; RCQ-38 L1: Ctrl+T/W by the layout's letter
    cmp  bl, 0x0F                       ; Tab stays a position
    je   .tab_cycle
    movzx edi, bl
    call input_layout_letter
    mov  esi, 1                         ; TS_KEY_NEW
    cmp  eax, 't'
    je   .tab_shortcut
    mov  esi, 4                         ; TS_KEY_CLOSE
    cmp  eax, 'w'
    jne  .no_shortcut
.tab_close:                             ; Ctrl+W, US position AND layout letter: HUMAN only, as Alt+F4
    cmp  byte [rel input_key_origin], KO_HUMAN
    jne  .next
.tab_shortcut:
    mov  edi, [rel wm_focus]
    call wgt_tabstrip_key               ; EAX=1: the focused window's tab strip took it
    test eax, eax
    jnz  .next
.no_shortcut:
    cmp  bl, 0x0F
    jne  .control
    test byte [rel input_kbd_mods], 4
    jz   .key_tab
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .next                          ; F2b-1: Alt+Tab under the lock is a no-op
    call wmx_alttab_do
    jmp  .next
.not_shortcut:                          ; K1b: Tab stays Tab, F4 stays F4, Ctrl+W stays ^W
    cmp  bl, 0x0F
    je   .key_tab
.control:
    cmp  bl, 0x01
    je   .key_esc
    cmp  bl, 0x0E
    je   .key_backspace
    cmp  bl, 0x1C
    je   .key_enter
    ; Set-1 F1..F10 are contiguous; F11/F12 follow the keypad range.
    ; Shell/modal ownership and Alt+F4 have already been checked above.
    cmp  bl, 0x3B
    jb   .layout
    cmp  bl, 0x44
    jbe  .key_f1_f10
    cmp  bl, 0x57
    je   .key_f11
    cmp  bl, 0x58
    je   .key_f12
.layout:
    cmp  byte [rel input_kbd_numlock], 0
    jne  .layout_table
    cmp  bl, 0x47                       ; NumLock off: keypad 7..9/4..6/1..3/0/. are
    jb   .layout_table                  ; Home/Up/PgUp/Left/Right/End/Down/PgDn/Ins/Del
    cmp  bl, 0x53                       ; (keypad 5 is silent); - and + keep the layout
    ja   .layout_table
    cmp  bl, 0x4A
    je   .layout_table
    cmp  bl, 0x4E
    je   .layout_table
    jmp  .nav_scan
.layout_table:
    movzx eax, bl
    cmp  eax, 0x59
    jae  .next
    cmp  byte [rel input_layout_id], 0
    jne  .layout_unit
    test byte [rel input_kbd_mods], 1
    jnz  .shift_table
    lea  rdx, [rel input_us_plain]
    movzx eax, byte [rdx + rax]
    test al, al
    jz   .next
    test byte [rel input_kbd_mods], 2
    jz   .plain_caps
    cmp  al, 'a'
    jb   .plain_caps
    cmp  al, 'z'
    ja   .plain_caps
    sub  al, 96
    jmp  .deliver
.plain_caps:
    test byte [rel input_kbd_caps], 1
    jz   .deliver
    cmp  al, 'a'
    jb   .deliver
    cmp  al, 'z'
    ja   .deliver
    sub  al, 32
    jmp  .deliver
.shift_table:
    lea  rdx, [rel input_us_shift]
    movzx eax, byte [rdx + rax]
    test al, al
    jz   .next
    test byte [rel input_kbd_mods], 2
    jz   .shift_caps
    cmp  al, 'A'
    jb   .shift_caps
    cmp  al, 'Z'
    ja   .shift_caps
    sub  al, 64
    jmp  .deliver
.shift_caps:
    test byte [rel input_kbd_caps], 1
    jz   .deliver
    cmp  al, 'A'
    jb   .deliver
    cmp  al, 'Z'
    ja   .deliver
    add  al, 32
    jmp  .deliver
.layout_unit:
    movzx edi, bl
    call input_layout_key               ; queues the key's scalars for .next
    jmp  .next
.lq_pop:
    ; RCQ-38 L1: deliver one queued scalar with its own origin. ASCII takes the
    ; key path below. L3b: so does a scalar >= 0x80, as GUI_KEY_TEXT with its
    ; UTF-8 in wgt_text_buf (it never shares the key ABI: GUI_KEY_* is
    ; 0x100..0x11B), so the lock assert, the modal hook, the menu and the
    ; focused widget's key filters judge it exactly as they judge 'a'.
    lea  rdx, [rel input_lq_origin]
    mov  cl, [rdx + rax]
    mov  [rel input_key_origin], cl
    cmp  cl, KO_HUMAN
    je   .lq_noted
    inc  dword [rel input_other_origin_seq]
.lq_noted:
    lea  rdx, [rel input_lq_scalar]
    mov  ebx, [rdx + rax*4]
    inc  eax
    cmp  eax, [rel input_lq_tail]
    jne  .lq_keep
    xor  eax, eax
    mov  [rel input_lq_tail], eax
.lq_keep:
    mov  [rel input_lq_head], eax
    mov  eax, ebx
    cmp  eax, 0x80
    jb   .deliver
    mov  [rel input_ime_lq_scalar], ebx ; I3b-1: the scalar behind this GUI_KEY_TEXT, for the IME stage
    mov  edi, ebx
    lea  rsi, [rel wgt_text_buf]
    mov  edx, WGT_TEXT_CAP
    call ue_utf8_encode                 ; SysV; nothing caller-saved is live here
    test eax, eax
    jle  .text_dropped
    mov  [rel wgt_text_len], eax
    mov  eax, GUI_KEY_TEXT
    jmp  .deliver
.text_dropped:
    lock inc qword [rel input_text_dropped]
    jmp  .next
.release:
    and  bl, 0x7F
    cmp  bl, 0x39                       ; a Space release re-arms Ctrl+Space and ends Win+Space
    je   .space_off
    cmp  bl, 0x6E                       ; RCQ-51: F23, the Copilot key
    je   .ai_off_copilot
    cmp  bl, 0x2A
    je   .shift_off
    cmp  bl, 0x36
    je   .rshift_off
    cmp  bl, 0x1D
    je   .ctrl_off
    cmp  bl, 0x38
    je   .alt_off
    cmp  bl, 0x3A
    je   .caps_off
    cmp  bl, 0x45
    jne  .next
    and  byte [rel input_kbd_numlock_down], ~INPUT_LOCK_NUM
    jmp  .next
.caps_off:
    ; A synthetic break cannot re-arm a human's held Caps Lock. Detach
    ; retires that press even when its ordinary physical break is absent.
    cmp  byte [rel input_key_origin], KO_RETIRED
    je   .caps_clear
    call input_key_is_hand
    je   .caps_clear
    test byte [rel input_kbd_numlock_down], INPUT_LOCK_CAPS_HAND
    jnz  .next
.caps_clear:
    and  byte [rel input_kbd_numlock_down], ~(INPUT_LOCK_CAPS | INPUT_LOCK_CAPS_HAND)
    jmp  .next
.shift_on:
    mov  al, INPUT_SIDE_LSHIFT
    jmp  .side_on
.rshift_on:
    mov  al, INPUT_SIDE_RSHIFT
    jmp  .side_on
.ctrl_on:
    mov  al, INPUT_SIDE_LCTRL
    jmp  .side_on
.rctrl_on:
    mov  al, INPUT_SIDE_RCTRL
    jmp  .side_on
.alt_on:
    mov  al, INPUT_SIDE_LALT
    jmp  .side_on
.ralt_on:
    mov  al, INPUT_SIDE_RALT
    jmp  .side_on
.shift_off:
    mov  al, INPUT_SIDE_LSHIFT
    jmp  .side_off
.rshift_off:
    mov  al, INPUT_SIDE_RSHIFT
    jmp  .side_off
.ctrl_off:
    mov  al, INPUT_SIDE_LCTRL
    jmp  .side_off
.rctrl_off:
    mov  al, INPUT_SIDE_RCTRL
    jmp  .side_off
.alt_off:
    mov  al, INPUT_SIDE_LALT
    jmp  .side_off
.ralt_off:
    mov  al, INPUT_SIDE_RALT
.side_off:
    mov  cl, 1
    jmp  .side_update
.side_on:
    xor  ecx, ecx
.side_update:
    ; A combined bit cleared outside the router (lock_screen resets
    ; input_kbd_mods while it drains the ring) forgets both of its sides, so a
    ; later modifier event never resurrects a key released while unobserved.
    xor  edx, edx
    test byte [rel input_kbd_mods], 1
    jz   .keep_ctrl
    or   dl, INPUT_SIDE_LSHIFT | INPUT_SIDE_RSHIFT
.keep_ctrl:
    test byte [rel input_kbd_mods], 2
    jz   .keep_alt
    or   dl, INPUT_SIDE_LCTRL | INPUT_SIDE_RCTRL
.keep_alt:
    test byte [rel input_kbd_mods], 4
    jz   .kept
    or   dl, INPUT_SIDE_LALT | INPUT_SIDE_RALT
.kept:
    and  [rel input_kbd_sides], dl
    and  [rel input_kbd_sides_inj], dl
    and  [rel input_kbd_sides_hand], dl
    test cl, cl
    jnz  .side_release
    or   [rel input_kbd_sides], al
    call input_key_is_hand              ; K1b: a side made by an injected key
    je   .side_hand                     ; taints every chord while it is held
    or   [rel input_kbd_sides_inj], al
    jmp  .side_derive
.side_hand:
    or   [rel input_kbd_sides_hand], al
    not  al
    and  [rel input_kbd_sides_inj], al
    jmp  .side_derive
.side_release:
    ; RCQ-51: the first release of an armed Alt+Shift, by the owner's hand, switches the layout for this session.
    ; It completes the chord only while the chord still stands (srcreview RCQ51-ALT-SHIFT-SESSION-CUSTODY): this
    ; side is held, and left Alt and a Shift are still held. A side forgotten above (the lock screen clears
    ; input_kbd_mods while it drains the ring) breaks it; a lock, unlock or session change disarms it outright
    ; (input_layout_watch).
    cmp  byte [rel input_altshift], 0
    je   .side_release_held
    mov  byte [rel input_altshift], 0
    call input_key_is_hand
    jne  .side_release_held
    mov  dl, [rel input_kbd_sides]
    test dl, al
    jz   .side_release_held             ; this side is no longer held: no chord to complete
    test dl, INPUT_SIDE_LALT
    jz   .side_release_held
    test dl, INPUT_SIDE_LSHIFT | INPUT_SIDE_RSHIFT
    jz   .side_release_held
    push rax                            ; AL: the side being released
    push rcx                            ; CL: 1, a release (read again at .side_derive)
    call input_layout_cycle
    pop  rcx
    pop  rax
.side_release_held:
    ; K1b L2 (rc-sec 07:37:53): a hand release always clears the side. A
    ; non-hand release of a side the hand holds leaves the router's state as it is.
    ; RCQ-09 (root 13:30:07): a retired keyboard's release (KO_RETIRED, native
    ; dev/usb/hid only) clears the side its device held; it is still no hand's.
    cmp  byte [rel input_key_origin], KO_RETIRED
    je   .side_clear                    ; RCQ-09: the device that held it is gone
    call input_key_is_hand
    je   .side_clear
    test [rel input_kbd_sides_hand], al
    jnz  .side_derive
.side_clear:
    not  al
    and  [rel input_kbd_sides], al
    and  [rel input_kbd_sides_inj], al
    and  [rel input_kbd_sides_hand], al
.side_derive:
    mov  dl, [rel input_kbd_mods]
    and  dl, 0xF8
    mov  al, [rel input_kbd_sides]
    test al, INPUT_SIDE_LSHIFT | INPUT_SIDE_RSHIFT
    jz   .no_shift
    or   dl, 1
.no_shift:
    test al, INPUT_SIDE_LCTRL | INPUT_SIDE_RCTRL
    jz   .no_ctrl
    or   dl, 2
.no_ctrl:
    test al, INPUT_SIDE_LALT | INPUT_SIDE_RALT
    jz   .no_alt
    or   dl, 4
.no_alt:
    mov  [rel input_kbd_mods], dl
    test cl, cl
    jnz  .next                          ; a release
    ; RCQ-51: a modifier make that leaves no side down but left Alt and the Shifts, every held side the owner's
    ; hand (this key's own side included: a non-hand make marks it in input_kbd_sides_inj above) and Win up,
    ; arms Alt+Shift (right Alt is AltGr on a non-US layout: never part of it). The release completes it only
    ; while left Alt AND a Shift are held (.side_release), so Alt or Shift alone arms nothing that can fire.
    test al, ~(INPUT_SIDE_LALT | INPUT_SIDE_LSHIFT | INPUT_SIDE_RSHIFT) & 0xFF
    jnz  .next
    cmp  byte [rel input_kbd_sides_inj], 0
    jne  .next
    cmp  byte [rel input_win_down], 0
    jne  .next
    mov  byte [rel input_altshift], 1
    jmp  .next
.numlock:
    test byte [rel input_kbd_numlock_down], INPUT_LOCK_NUM
    jne  .next                          ; typematic repeat of a held NumLock
    or   byte [rel input_kbd_numlock_down], INPUT_LOCK_NUM
    xor  byte [rel input_kbd_numlock], 1
    jmp  .next
.win_on:
    ; UI wave 2 B10: Start opens on the Win RELEASE of a lone tap (Windows
    ; behaviour), never on the make; a chord in between cancels it. RCQ-09:
    ; left/right Win are separate held keys behind the existing boolean ABI.
    ; An external reset of input_win_down (lock/init) discards both private
    ; sides on the next make; no stale side can resurrect across that reset.
    mov  al, 1
    cmp  bl, 0x5B
    je   .win_make_side
    shl  al, 1
.win_make_side:
    cmp  byte [rel input_win_down], 1
    je   .win_add_side
    mov  byte [rel input_win_sides], 0
    mov  byte [rel input_win_hand], 0
    mov  byte [rel input_win_chord], 0
    call input_key_is_hand              ; K1b: whose hand holds Win
    setne byte [rel input_win_inj]
    jmp  .win_record_side
.win_add_side:
    test [rel input_win_sides], al
    jnz  .next                          ; typematic of this side retains its origin
    call input_key_is_hand
    je   .win_record_side
    mov  byte [rel input_win_inj], 1    ; a mixed gesture stays tainted until all up
.win_record_side:
    or   [rel input_win_sides], al
    mov  byte [rel input_win_down], 1
    call input_key_is_hand
    jne  .next
    or   [rel input_win_hand], al
    jmp  .next
.win_chord:
    ; Win+<key>: a shell chord, never typed. Win+L locks (usage suite LOG-02);
    ; Win+F1 opens Help (RCQ-38 H2, root 2026-10-11 Q2), on every layout.
    mov  byte [rel input_win_chord], 1
    cmp  bl, 0x3B                       ; F1 make (Set-1)
    je   .win_help
    cmp  bl, 0x39                       ; RCQ-51: Win+Space, the AI key's fallback chord (Space has
    je   .win_space                     ; one position on every layout)
    cmp  bl, 0x6E                       ; RCQ-51: F23 under Win, the Copilot key (Win+Shift+F23)
    je   .win_ai
    cmp  byte [rel input_layout_id], 0
    jne  .win_chord_layout
    cmp  bl, 0x26                       ; L make (Set-1)
    jne  .next
.win_l:
    call input_key_is_hand              ; K1b: L and Win both the owner's hand
    jne  .next
    cmp  byte [rel input_win_inj], 0
    jne  .next
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .next                          ; already on the sign-in surface: no relock
    ; The same authority transition as the LOCK verb (sec/session). Stop this
    ; pass: the idle loop's lock_screen_sync drains the ring (and the Win state)
    ; and paints the sign-in surface before any further key is consumed.
    call session_shell_lock
    mov  byte [rel input_win_down], 0
    mov  byte [rel input_win_chord], 0
    jmp  .out
.win_help:
    call input_key_is_hand              ; K1b: F1 and Win both the owner's hand
    jne  .next
    cmp  byte [rel input_win_inj], 0
    jne  .next
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .next                          ; root Q1: no Help on the sign-in surface
    call start_programs_open_help
    jmp  .next
.win_space:
    mov  esi, INPUT_AI_SRC_FALLBACK
    jmp  .ai_make
.win_ai:
    mov  esi, INPUT_AI_SRC_COPILOT
.ai_make:                               ; RCQ-51: an AI chord's make, ESI its source
    cmp  byte [rel input_ai_down], 0
    jne  .next                          ; typematic, or the other chord while one is down
    mov  [rel input_ai_src], sil
    call input_key_is_hand              ; K1b: the key, Win and every held side the owner's hand
    jne  .ai_refused
    cmp  byte [rel input_win_inj], 0
    jne  .ai_refused
    cmp  byte [rel input_kbd_sides_inj], 0
    jne  .ai_refused
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .ai_locked                     ; the sign-in surface takes no AI gesture
    call time_monotonic_now_us
    mov  rsi, rax
    movzx edi, byte [rel input_ai_src]
    call input_ai_press
    jmp  .next
.ai_refused:
    inc  qword [rel input_ai_refused]
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
    jmp  .next
.ai_locked:
    inc  qword [rel input_ai_locked]
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
    jmp  .next
.space_off:
    mov  byte [rel input_ime_space_held], 0
    mov  edi, INPUT_AI_SRC_FALLBACK
    jmp  .ai_break
.ai_off_copilot:
    mov  edi, INPUT_AI_SRC_COPILOT
.ai_break:                              ; RCQ-51: an AI chord key's break, EDI its source
    cmp  byte [rel input_ai_down], 0
    je   .next
    cmp  [rel input_ai_src], dil
    jne  .next                          ; not the key that is down
    cmp  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
    je   .ai_void_off
    cmp  byte [rel input_key_origin], KO_RETIRED
    je   .ai_up                         ; its keyboard left: the gesture ends
    call input_key_is_hand              ; K1b L2: a non-hand break leaves the owner's press down
    jne  .next
.ai_up:
    call time_monotonic_now_us
    mov  rdi, rax
    xor  esi, esi
    cmp  qword [rel tsc_khz], 0
    setne sil                           ; no monotonic clock: the release is a tap
    call input_ai_release
    jmp  .next
.ai_void_off:
    mov  byte [rel input_ai_down], 0
    jmp  .next
.ctrl_space:                            ; RCQ-51: Ctrl+Space toggles the IME on an IME textfield only
    cmp  byte [rel input_kbd_mods], 2   ; Ctrl alone: Shift/Alt/AltGr+Ctrl+Space stay keys
    jne  .ordinary_route
    cmp  byte [rel input_ime_space_held], 1
    je   .next                          ; typematic of a press that toggled: one toggle per press
    ja   .ordinary_route                ; typematic of a press that was the field's: still the field's
    mov  byte [rel input_ime_space_held], 2
    call input_key_is_hand              ; K1b: Space and Ctrl both the owner's hand
    jne  .ordinary_route
    cmp  byte [rel input_kbd_sides_inj], 0
    jne  .ordinary_route
    mov  rax, [rel input_ime_ops + INPUT_IME_TOGGLE]
    test rax, rax
    jz   .ordinary_route
    call rax                            ; EAX 0: no IME target (Terminal NUL, a secret field, the lock)
    test eax, eax
    jz   .ordinary_route
    mov  byte [rel input_ime_space_held], 1
    jmp  .next
.win_chord_layout:                      ; RCQ-38 L1: Win+L by the layout's letter
    movzx edi, bl
    call input_layout_letter
    cmp  eax, 'l'
    jne  .next
    jmp  .win_l
.win_off:                               ; release of 0x5B or 0x5C
    cmp  byte [rel input_win_down], 1
    jne  .next
    mov  al, 1
    cmp  bl, 0x5B
    je   .win_break_side
    shl  al, 1
.win_break_side:
    test [rel input_win_sides], al
    jz   .next                          ; an unheld side cannot release the other
    cmp  byte [rel input_key_origin], KO_RETIRED
    jne  .win_custody
    mov  byte [rel input_win_chord], 1  ; RCQ-09: its keyboard left: the Win gesture is
    jmp  .win_release                   ; cancelled (no Start), the side is released
.win_custody:
    call input_key_is_hand              ; K1b L2: a non-hand release of the
    je   .win_release                   ; hand's Win leaves Win held
    test [rel input_win_hand], al
    jnz  .next                          ; custody belongs to this held side
.win_release:
    not  al
    and  [rel input_win_sides], al
    and  [rel input_win_hand], al
    cmp  byte [rel input_win_sides], 0
    jne  .next                          ; no Start while either Win is still down
    mov  byte [rel input_win_down], 0
    cmp  byte [rel input_win_chord], 0
    jne  .next
    cmp  byte [rel input_win_inj], 0    ; K1b: Start opens on the owner's tap only (a
    jne  .next                          ; non-hand release got here only if inj is set)
    mov  rax, [rel gui_input_global_key_hook]
    test rax, rax
    jz   .next
    call rax
    jmp  .next
.caps:
    ; Claim the press before checking repeats: a human make following a
    ; synthetic make must also survive a later synthetic break.
    call input_key_is_hand
    jne  .caps_latch
    or   byte [rel input_kbd_numlock_down], INPUT_LOCK_CAPS_HAND
.caps_latch:
    test byte [rel input_kbd_numlock_down], INPUT_LOCK_CAPS
    jnz  .next
    or   byte [rel input_kbd_numlock_down], INPUT_LOCK_CAPS
    xor  byte [rel input_kbd_caps], 1
    jmp  .next
.key_slash:
    mov  eax, '/'
    jmp  .deliver
.key_enter:
    mov  eax, GUI_KEY_ENTER
    jmp  .deliver
.key_backspace:
    mov  eax, GUI_KEY_BACKSPACE
    jmp  .deliver
.key_left:
    mov  eax, GUI_KEY_LEFT
    jmp  .deliver
.key_right:
    mov  eax, GUI_KEY_RIGHT
    jmp  .deliver
.key_home:
    mov  eax, GUI_KEY_HOME
    jmp  .deliver
.key_end:
    mov  eax, GUI_KEY_END
    jmp  .deliver
.key_up:
    mov  eax, GUI_KEY_UP
    jmp  .deliver
.key_down:
    mov  eax, GUI_KEY_DOWN
    jmp  .deliver
.key_tab:
    mov  al, [rel input_kbd_mods]
    and  al, 1                          ; Shift+Tab steps focus backwards
    mov  [rel wgt_tab_reverse], al
    mov  eax, GUI_KEY_TAB
    jmp  .deliver
.key_delete:
    mov  eax, GUI_KEY_DELETE
    jmp  .deliver
.key_pgup:
    mov  eax, GUI_KEY_PGUP
    jmp  .deliver
.key_pgdn:
    mov  eax, GUI_KEY_PGDN
    jmp  .deliver
.key_insert:
    mov  eax, GUI_KEY_INSERT
    jmp  .deliver
.key_f1_f10:
    movzx eax, bl
    add  eax, GUI_KEY_F1 - 0x3B
    jmp  .deliver
.key_f11:
    mov  eax, GUI_KEY_F1 + 10
    jmp  .deliver
.key_f12:
    mov  eax, GUI_KEY_F1 + 11
    jmp  .deliver
.key_esc:
    call calendar_escape
    test eax, eax
    jnz  .next
    call input_layout_esc               ; RCQ-38 L1: Escape cancels its own class's dead key
    mov  eax, GUI_KEY_ESC
.deliver:
    mov  ebx, eax
    ; RCQ-16 F2b-1 (rc-sec 23:50:07): while locked the sign-in form owns the
    ; keyboard. A key that finds it away is dropped here, before the modal hook,
    ; the flyout keys and every chained key filter can see it.
    call lock_screen_focus_assert
    test eax, eax
    jnz  .dropped
    ; RCQ-38 I3b-1: the IME stage, after the lock assert and before the modal
    ; hook, the menu and the field: a key it takes goes no further; its commit
    ; comes back through the pump as GUI_KEY_TEXT and takes this same path.
    mov  rax, [rel input_ime_ops + INPUT_IME_STAGE]
    test rax, rax
    jz   .ime_passed
    mov  edi, ebx
    call rax
    test eax, eax
    jnz  .next
.ime_passed:
    ; Keep the callback outside RAX: EAX carries the translated key ABI.
    ; Loading the hook into RAX and then writing EAX would zero the upper
    ; address bits and turn the key itself (for example 'a' = 0x61) into the
    ; call target.
    mov  rdx, [rel gui_input_modal_key_hook]
    test rdx, rdx
    jz   .ordinary_delivery
    mov  eax, ebx
    call rdx
    cmp  eax, GUI_INPUT_MODAL_EDIT
    je   .modal_edit
    test eax, eax
    jz   .ordinary_delivery
    cmp  ebx, GUI_KEY_ENTER
    jne  .modal_routed
    inc  qword [rel input_kbd_submits]
.modal_routed:
    inc  qword [rel input_kbd_routed]
    jmp  .next
.modal_edit:
    ; The modal hook selects the shared focus target; the router performs the
    ; actual edit.  This keeps wgt_textfield_key out of a nested modal callback
    ; while retaining the one editor, event hooks and list binding path.
    mov  edi, [rel wgt_focus_id]
    inc  byte [rel wgt_paint_suspended]
    mov  eax, ebx
    call wgt_textfield_key
    dec  byte [rel wgt_paint_suspended]
    test eax, eax
    jz   .dropped
    call wmx_draw_all
    inc  qword [rel input_kbd_routed]
    jmp  .next
.ordinary_delivery:
    ; G3/B9 (2026-10-01, usage suite MNU-02/MNU-03): an open flyout of the
    ; focused window takes Up/Down/Enter/Esc before its window's widgets.
    mov  eax, ebx
    call wgt_menu_key
    test eax, eax
    jz   .menu_not_open
    inc  qword [rel input_kbd_routed]
    jmp  .next
.menu_not_open:
    pushfq
    cli
    mov  edi, [rel wm_focus]
    cmp  edi, WM_MAX
    jae  .snapshot_none
    call wgt_focus_window
    mov  r13d, eax
    jmp  .snapshot_done
.snapshot_none:
    mov  r13d, -1
.snapshot_done:
    popfq
    cmp  r13d, -1
    je   .dropped
    mov  edi, r13d
    mov  eax, ebx
    call wgt_textfield_key
    test eax, eax
    jz   .dropped
    cmp  ebx, GUI_KEY_ENTER
    jne  .routed
    inc  qword [rel input_kbd_submits]
.routed:
    inc  qword [rel input_kbd_routed]
    jmp  .next
.dropped:
    cmp  ebx, GUI_KEY_TEXT
    je   .text_dropped                  ; L3b: text nobody took (no focus, not a textfield, locked away)
    lock inc qword [rel kbd_dropped_count]
    jmp  .next
.out:
    ; Publish accepted host state, including the initial NumLock-on default.
    ; Guest capture and provenance decisions above remain the only authority.
    ; This lower-layer seam only stores a snapshot; no USB I/O in the router.
    movzx edi, byte [rel input_kbd_caps]
    and  edi, 1
    shl  edi, 1
    movzx eax, byte [rel input_kbd_numlock]
    and  eax, 1
    or   edi, eax
    call usb_hid_keyboard_locks
    pop  r13
    pop  r12
    pop  rbx
    ret

; input_modifiers_are_human -> EAX 1 when every held modifier belongs to
; the native hand. Use alongside keyprov_key_is_human at human-action
; boundaries: the trigger's provenance alone says nothing about a held chord.
; These are the same per-side custody bits used by the router's shortcuts.
; Released Win may retain its old taint; only a held Win participates.
input_modifiers_are_human:
    xor  eax, eax
    cmp  byte [rel input_kbd_sides_inj], 0
    jne  .out
    cmp  byte [rel input_win_down], 0
    je   .yes
    cmp  byte [rel input_win_inj], 0
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; input_key_is_hand -> ZF=1 when the key being routed is the owner's hand:
; KO_HUMAN, or KO_INTERNAL while the router's own boot KAT drives it
; (input_route_tl_kat). Never KBINJ/TERMFEED/HOOK (slot-bound) or untethered.
; SEC R1 K1b. Clobbers flags only.
input_key_is_hand:
    cmp  byte [rel input_key_origin], KO_HUMAN
    je   .out
    cmp  byte [rel input_key_origin], KO_INTERNAL
    jne  .out
    cmp  byte [rel input_route_tl_kat], 1
.out:
    ret

; ---- RCQ-51: the AI key's gesture machine -----------------------------------
; Router context only (gui_input_route_tick); the deadlines run on the monotonic clock.

; input_ai_escape(): ordinary Esc make in router context. Same native hand,
; held-modifier and unlocked floor as AI gestures. Normal Esc routing continues.
; Increment even without a pending press: the cognition consumer may own intent
; after the producer goes quiet. Its existing mismatch path masks immediately
; and drains the ring on the next BSP tick. Void a down press until release;
; clear pending/hold so a later deadline or break cannot restart cancelled AI.
input_ai_escape:
    sub  rsp, 8
    call input_key_is_hand
    lea  rsp, [rsp + 8]                 ; preserve the native hand check flags
    jne  .out
    cmp  byte [rel input_win_down], 0
    je   .win_ok                       ; released Win may retain stale taint
    cmp  byte [rel input_win_inj], 0
    jne  .out
.win_ok:
    cmp  byte [rel input_kbd_sides_inj], 0
    jne  .out
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    inc  qword [rel input_ai_cancelled]
    mov  byte [rel input_ai_pending], 0
    mov  byte [rel input_ai_hold], 0
    cmp  byte [rel input_ai_down], 0
    je   .out
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
.out:
    ret

; input_ai_press(EDI = INPUT_AI_SRC_*, RSI = now us): the owner's AI chord went down. Clobbers caller-saved.
input_ai_press:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    mov  r12, rsi
    mov  [rel input_ai_src], bl
    movzx eax, byte [rel input_key_origin]
    mov  [rel input_ai_origin], al
    cmp  byte [rel input_ai_pending], 0
    je   .fresh
    mov  byte [rel input_ai_pending], 0
    cmp  bl, [rel input_ai_src_up]
    jne  .flush                         ; the other chord: the earlier press was a tap
    mov  rax, r12
    sub  rax, [rel input_ai_t_up]
    cmp  rax, INPUT_AI_DOUBLE_US
    ja   .flush
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_DOUBLE
    mov  edi, INPUT_AI_DOUBLE
    mov  rsi, r12
    call input_ai_emit
    jmp  .out
.flush:                                 ; its window passed before a tick saw it
    mov  edi, INPUT_AI_TAP
    mov  rsi, r12
    movzx eax, byte [rel input_ai_src]
    push rax
    mov  al, [rel input_ai_src_up]
    mov  [rel input_ai_src], al
    call input_ai_emit
    pop  rax
    mov  [rel input_ai_src], al
.fresh:
    mov  [rel input_ai_t_down], r12
    mov  byte [rel input_ai_hold], 0
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_HELD
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; input_ai_release(RDI = now us, ESI = 0 when there is no monotonic clock): the held press went up.
; Clobbers caller-saved.
input_ai_release:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    movzx ebx, byte [rel input_ai_down]
    mov  byte [rel input_ai_down], 0
    cmp  ebx, INPUT_AI_DOWN_DOUBLE
    je   .out                           ; the DOUBLE was reported on its second press
    cmp  byte [rel input_ai_hold], 0
    jne  .hold_end
    test esi, esi
    jz   .tap                           ; no monotonic clock: every press is a tap
    mov  rax, r12
    sub  rax, [rel input_ai_t_down]
    cmp  rax, INPUT_AI_HOLD_US
    jb   .pend
    mov  edi, INPUT_AI_HOLD_START       ; held past HOLD between two ticks
    mov  rsi, r12
    call input_ai_emit
.hold_end:
    mov  byte [rel input_ai_hold], 0
    mov  edi, INPUT_AI_HOLD_END
    jmp  .emit
.tap:
    mov  edi, INPUT_AI_TAP
.emit:
    mov  rsi, r12
    call input_ai_emit
    jmp  .out
.pend:
    mov  [rel input_ai_t_up], r12
    mov  al, [rel input_ai_src]
    mov  [rel input_ai_src_up], al
    mov  byte [rel input_ai_pending], 1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; input_ai_tick(): the deadlines on the monotonic clock, a lock's cancel, a void press's end once Win is up.
; Clobbers caller-saved.
input_ai_tick:
    cmp  byte [rel input_ai_down], 0
    jne  .work
    cmp  byte [rel input_ai_pending], 0
    jne  .work
    ret
.work:
    push r12
    cmp  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
    jne  .live
    cmp  byte [rel input_win_down], 0
    jne  .live
    mov  byte [rel input_ai_down], 0    ; every AI chord needs Win: its break is no longer owed
.live:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .cancel
    cmp  qword [rel tsc_khz], 0
    je   .out
    call time_monotonic_now_us
    mov  rdi, rax
    call input_ai_deadlines
    jmp  .out
.cancel:
    cmp  byte [rel input_ai_pending], 0
    je   .cancel_down
    mov  byte [rel input_ai_pending], 0
    inc  qword [rel input_ai_cancelled]
.cancel_down:
    cmp  byte [rel input_ai_down], INPUT_AI_DOWN_HELD
    je   .cancel_held
    cmp  byte [rel input_ai_down], INPUT_AI_DOWN_DOUBLE
    jne  .out
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
    jmp  .out
.cancel_held:
    mov  byte [rel input_ai_down], INPUT_AI_DOWN_VOID
    inc  qword [rel input_ai_cancelled]
    cmp  byte [rel input_ai_hold], 0
    je   .out
    mov  byte [rel input_ai_hold], 0
    call time_monotonic_now_us
    mov  rsi, rax
    mov  edi, INPUT_AI_HOLD_END         ; a started hold always reports its end
    call input_ai_emit
.out:
    pop  r12
    ret

; input_ai_deadlines(RDI = now us): HOLD_START once the held press reaches HOLD, TAP once a released press's
; DOUBLE window has passed. Clobbers caller-saved.
input_ai_deadlines:
    push r12
    mov  r12, rdi
    cmp  byte [rel input_ai_down], INPUT_AI_DOWN_HELD
    jne  .pending
    cmp  byte [rel input_ai_hold], 0
    jne  .pending
    mov  rax, r12
    sub  rax, [rel input_ai_t_down]
    cmp  rax, INPUT_AI_HOLD_US
    jb   .pending
    mov  byte [rel input_ai_hold], 1
    mov  edi, INPUT_AI_HOLD_START
    mov  rsi, r12
    call input_ai_emit
.pending:
    cmp  byte [rel input_ai_pending], 0
    je   .out
    mov  rax, r12
    sub  rax, [rel input_ai_t_up]
    cmp  rax, INPUT_AI_DOUBLE_US
    jbe  .out
    mov  byte [rel input_ai_pending], 0
    mov  al, [rel input_ai_src]
    push rax
    mov  al, [rel input_ai_src_up]
    mov  [rel input_ai_src], al
    mov  edi, INPUT_AI_TAP
    mov  rsi, r12
    call input_ai_emit
    pop  rax
    mov  [rel input_ai_src], al
.out:
    pop  r12
    ret

; input_ai_emit(EDI = INPUT_AI_* kind, RSI = t_us): count it and queue one record of input_ai_src; a full ring
; counts a drop. Clobbers RAX, RCX, RDX.
input_ai_emit:
    lea  rdx, [rel input_ai_counts]
    lea  eax, [rdi - 1]
    inc  qword [rdx + rax * 8]
    inc  dword [rel input_ai_seq]
    mov  eax, [rel input_ai_head]
    mov  ecx, eax
    sub  ecx, [rel input_ai_tail]
    cmp  ecx, INPUT_AI_RING
    jae  .drop
    and  eax, INPUT_AI_RING - 1
    shl  eax, 4
    lea  rdx, [rel input_ai_ring]
    add  rdx, rax
    mov  [rdx], dil
    mov  al, [rel input_ai_src]
    mov  [rdx + 1], al
    mov  al, [rel input_ai_origin]
    mov  [rdx + 2], al
    mov  byte [rdx + 3], 0
    mov  eax, [rel input_ai_seq]
    mov  [rdx + 4], eax
    mov  [rdx + 8], rsi
    inc  dword [rel input_ai_head]
    ret
.drop:
    inc  qword [rel input_ai_dropped]
    ret

; input_ai_key_pop(RDI = INPUT_AI_REC bytes out) -> EAX 1 the oldest record copied and removed, 0 none. One
; consumer, router context (the idle loop). Clobbers RAX, RCX, RDX.
input_ai_key_pop:
    mov  eax, [rel input_ai_tail]
    cmp  eax, [rel input_ai_head]
    je   .none
    and  eax, INPUT_AI_RING - 1
    shl  eax, 4
    lea  rdx, [rel input_ai_ring]
    mov  rcx, [rdx + rax]
    mov  [rdi], rcx
    mov  rcx, [rdx + rax + 8]
    mov  [rdi + 8], rcx
    inc  dword [rel input_ai_tail]
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; input_ai_kat() -> EAX 0 pass / 1 fail (RCQ-51): input_ai_press / _release / _deadlines at exact times give
; TAP (up at 100 ms: none at 400 ms, one at 400.001 ms), DOUBLE (a second press 300 ms after the first release)
; and HOLD_START (at 400 ms, none at 399.999) / HOLD_END; the four records pop in order and the four counts are 1.
; It starts from the boot zero and every outcome leaves it there. Clobbers caller-saved.
input_ai_kat:
    push rbx
    push r12
    sub  rsp, 24                        ; one INPUT_AI_REC, the call alignment
    mov  ebx, 1                         ; fail until proven
    call input_ai_reset                 ; KAT: from the boot zero
    mov  edi, INPUT_AI_SRC_FALLBACK
    xor  esi, esi
    call input_ai_press
    mov  edi, 100000
    mov  esi, 1
    call input_ai_release
    mov  edi, 400000
    call input_ai_deadlines
    cmp  dword [rel input_ai_seq], 0
    jne  .out
    mov  edi, 400001
    call input_ai_deadlines
    cmp  dword [rel input_ai_seq], 1
    jne  .out
    mov  edi, INPUT_AI_SRC_FALLBACK
    mov  esi, 1000000
    call input_ai_press
    mov  edi, 1050000
    mov  esi, 1
    call input_ai_release
    mov  edi, INPUT_AI_SRC_FALLBACK
    mov  esi, 1350000
    call input_ai_press
    mov  edi, 1420000
    mov  esi, 1
    call input_ai_release
    mov  edi, 9000000
    call input_ai_deadlines
    cmp  dword [rel input_ai_seq], 2
    jne  .out
    mov  edi, INPUT_AI_SRC_FALLBACK
    mov  esi, 10000000
    call input_ai_press
    mov  edi, 10399999
    call input_ai_deadlines
    cmp  dword [rel input_ai_seq], 2
    jne  .out
    mov  edi, 10400000
    call input_ai_deadlines
    cmp  dword [rel input_ai_seq], 3            ; HOLD_START at the deadline, not made up at the release
    jne  .out
    mov  edi, 12000000
    mov  esi, 1
    call input_ai_release
    cmp  dword [rel input_ai_seq], 4
    jne  .out
    xor  r12d, r12d
.rec:                                   ; record i: kind i + 1, seq i + 1, the fallback source
    mov  rdi, rsp
    call input_ai_key_pop
    test eax, eax
    jz   .out
    lea  eax, [r12 + 1]
    cmp  [rsp], al
    jne  .out
    cmp  [rsp + 4], eax
    jne  .out
    cmp  byte [rsp + 1], INPUT_AI_SRC_FALLBACK
    jne  .out
    lea  rdx, [rel input_ai_counts]
    cmp  qword [rdx + r12 * 8], 1
    jne  .out
    inc  r12d
    cmp  r12d, 4
    jb   .rec
    mov  rdi, rsp
    call input_ai_key_pop
    test eax, eax
    jnz  .out                           ; exactly four
    xor  ebx, ebx
.out:
    call input_ai_reset                 ; KAT: back to the boot zero
    mov  eax, ebx
    add  rsp, 24
    pop  r12
    pop  rbx
    ret

; input_ai_reset(): the AI state's boot zero, nothing down, pending, queued or counted. Clobbers RAX, RCX, RDI.
input_ai_reset:
    lea  rdi, [rel input_ai_counts]
    lea  rcx, [rel input_ai_pending + 1]
    sub  rcx, rdi
    xor  eax, eax
    rep  stosb
    ret

; ---- RCQ-38 L1: the Latin layout unit behind the router --------------------
; Three contexts borrow kbd_builtin_data: the owner's hand (KO_HUMAN, or the
; boot KAT), every other origin, and a probe that never holds a dead key. A
; dead key composes only within its class (rc-sec 10:37:44). A hand key flushes
; a pending non-hand dead key as its spacing mark, with that key's origin. A
; focus change, a lock or unlock, or a layout change cancels both classes.

; input_layout_set(EDI = layout id) -> EAX 1 selected / 0 refused (layout 0
; kept). The only setter; L2's preference owns when it runs, and the owner's
; Alt+Shift (input_layout_cycle, RCQ-51) for the session. Clobbers
; caller-saved.
input_layout_set:
    cmp  edi, INPUT_LAYOUT_COUNT
    jae  .refuse
    push rbx
    mov  ebx, edi
    lea  rdi, [rel input_kbd_ctx_hand]
    call .select
    jz   .fail
    lea  rdi, [rel input_kbd_ctx_other]
    call .select
    jz   .fail
    lea  rdi, [rel input_kbd_ctx_probe]
    call .select
    jz   .fail
    mov  [rel input_layout_id], bl
    mov  rax, [rel input_ime_ops + INPUT_IME_RESET] ; RCQ-38 I3b-1: a layout change
    test rax, rax                       ; cancels the IME composition
    jz   .set
    call rax
.set:
    mov  eax, 1
    pop  rbx
    ret
.fail:
    mov  byte [rel input_layout_id], 0
    pop  rbx
.refuse:
    xor  eax, eax
    ret
.select:                                ; RDI context, EBX id -> ZF=1 refused
    lea  rsi, [rel kbd_builtin_data]
    mov  edx, [rsi + 4]
    mov  ecx, ebx
    call kbd_layout_select
    test eax, eax
    ret

; The layout ids as shown to the owner (Settings status, the sign-in tag).
input_layout_tags: db "US", 0, "ES", 0, "FR", 0, "DE", 0
str_input_layout_switch:     db "[PAOS64] keyboard layout ", 0
str_input_layout_switch_end: db " (Alt+Shift, this session; Settings keeps the saved layout) [input.layout.altshift]", 13, 10, 0

; input_layout_cycle() -> EAX 1 switched / 0 not: RCQ-51 Alt+Shift (root 2026-10-17 00:08:00). The next
; selectable layout after the one in force, wrapping to en-US, for this session only: gui/kbd_prefs's saved
; choice is unchanged and the next boot applies it. Never while locked or under the Summon palette. One serial
; marker per switch. Router context only. Clobbers caller-saved.
input_layout_cycle:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .no
    cmp  byte [rel summon_palette_open], 1
    je   .no
    push rbx
    movzx ebx, byte [rel input_layout_id]
.try:
    inc  ebx
    cmp  ebx, INPUT_LAYOUT_COUNT
    jb   .probe
    xor  ebx, ebx
.probe:
    cmp  bl, [rel input_layout_id]
    je   .none                          ; back where it started: no other layout is selectable
    mov  edi, ebx
    call input_layout_selectable
    test eax, eax
    jz   .try
    mov  edi, ebx
    call input_layout_set               ; refused: en-US (its own rule)
    inc  qword [rel input_layout_switches]
    lea  rdi, [rel str_input_layout_switch]
    call serial_string
    movzx eax, byte [rel input_layout_id]
    lea  rdi, [rel input_layout_tags]
    lea  rdi, [rdi + rax*2]
    add  rdi, rax                       ; 3 bytes per tag
    call serial_string
    lea  rdi, [rel str_input_layout_switch_end]
    call serial_string
    mov  eax, 1
    pop  rbx
    ret
.none:
    pop  rbx
.no:
    xor  eax, eax
    ret

; input_layout_selectable(EDI = layout id) -> EAX 1 when a user may choose it:
; en-US always; another layout only when this build carries all its text
; consumers (root 12:04:44). Clobbers RAX, RCX.
input_layout_selectable:
    xor  eax, eax
    test edi, edi
    jz   .yes
    cmp  edi, INPUT_LAYOUT_COUNT
    jae  .out
    mov  ecx, INPUT_TEXT_CONSUMERS_BUILT
    cmp  ecx, INPUT_TC_ALL
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; input_layout_reselect(RDI = context): cancel its dead key if one is pending.
input_layout_reselect:
    cmp  dword [rdi + INPUT_KBD_PENDING], 0
    je   .out
    lea  rsi, [rel kbd_builtin_data]
    mov  edx, [rsi + 4]
    movzx ecx, byte [rel input_layout_id]
    call kbd_layout_select
.out:
    ret

input_layout_cancel_all:
    mov  rax, [rel input_ime_ops + INPUT_IME_RESET] ; RCQ-38 I3b-1: every dead-key cancel
    test rax, rax                       ; cancels the IME composition too (never a commit)
    jz   .layout
    call rax
.layout:
    cmp  byte [rel input_layout_id], 0
    je   .out
    lea  rdi, [rel input_kbd_ctx_hand]
    call input_layout_reselect
    lea  rdi, [rel input_kbd_ctx_other]
    call input_layout_reselect
.out:
    ret

; input_layout_watch: a lock, an unlock or a session change since the last
; pass cancels both classes, else a focus change does. Called once per router
; pass. Clobbers caller-saved.
input_layout_watch:
    ; RCQ-38 L1 C1: a session change cancels too. session_authority_epoch moves
    ; on every lock and every unlock, so a lock+unlock between two passes (a
    ; new principal) is seen even when session_locked looks unchanged.
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel input_layout_epoch]
    je   .locked
    mov  [rel input_layout_epoch], rax
    mov  al, [rel session_locked]
    mov  [rel input_layout_locked], al
    jmp  .session
.locked:
    mov  al, [rel session_locked]
    cmp  al, [rel input_layout_locked]
    je   .out
    mov  [rel input_layout_locked], al
.session:
    ; RCQ-51 (srcreview RCQ51-ALT-SHIFT-SESSION-CUSTODY): a lock, an unlock or a session change ends an armed
    ; Alt+Shift; a release in the next session never completes a chord made in the last one. (A focus change
    ; does not: the switch is the session's, not the window's.)
    mov  byte [rel input_altshift], 0
    jmp  input_layout_cancel_all
.out:
    jmp  input_layout_focus_check

; input_layout_esc: Escape cancels the dead key of its own class only.
input_layout_esc:
    cmp  byte [rel input_layout_id], 0
    je   .out
    lea  rdi, [rel input_kbd_ctx_hand]
    call input_key_is_hand
    je   .reselect
    lea  rdi, [rel input_kbd_ctx_other]
.reselect:
    jmp  input_layout_reselect
.out:
    ret

; input_layout_letter(EDI = Set-1 make) -> EAX = the layout's level-0 scalar
; for that key, 0 = none. Non-US layouts only (shortcut letters).
input_layout_letter:
    xor  esi, esi
    call usb_hid_set1_to_usage
    test eax, eax
    jz   .out
    lea  rdi, [rel input_kbd_ctx_probe]
    mov  esi, eax
    xor  edx, edx
    lea  rcx, [rel input_layout_pout]
    call kbd_key_event
    cmp  eax, 1
    jne  .none
    mov  eax, [rel input_layout_pout]
    ret
.none:
    lea  rdi, [rel input_kbd_ctx_probe] ; a dead key at level 0: keep the probe clean
    call input_layout_reselect
    xor  eax, eax
.out:
    ret

; input_layout_queue(EDI = scalar, ESI = origin). At most INPUT_LQ_MAX per key.
input_layout_queue:
    mov  eax, [rel input_lq_tail]
    cmp  eax, INPUT_LQ_MAX
    jae  .out
    lea  rdx, [rel input_lq_scalar]
    mov  [rdx + rax*4], edi
    lea  rdx, [rel input_lq_origin]
    mov  [rdx + rax], sil
    inc  dword [rel input_lq_tail]
.out:
    ret

; input_layout_focus_check: a focus change (window, widget or z-order) since
; the last stamp cancels both classes. Run at every pass (input_layout_watch)
; and before every layout key, so an injected dead key never outlives the
; focus it was typed into, and keyprov's slot pin on it (RCQ-38 L1 C1) lapses
; at the next pass without waiting for a key. Clobbers caller-saved.
input_layout_focus_check:
    mov  eax, [rel wm_focus]
    cmp  eax, [rel input_layout_st_focus]
    jne  .restamp
    mov  eax, [rel wgt_focus_id]
    cmp  eax, [rel input_layout_st_widget]
    jne  .restamp
    mov  eax, [rel wm_zcounter]
    cmp  eax, [rel input_layout_st_z]
    je   .stamped
.restamp:
    mov  eax, [rel wm_focus]
    mov  [rel input_layout_st_focus], eax
    mov  eax, [rel wgt_focus_id]
    mov  [rel input_layout_st_widget], eax
    mov  eax, [rel wm_zcounter]
    mov  [rel input_layout_st_z], eax
    call input_layout_cancel_all
.stamped:
    ret

; input_layout_key(EDI = Set-1 make, no prefix): translate one text key on a
; non-US layout and queue its scalars. Clobbers caller-saved.
input_layout_key:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    ; A focus change (window, widget or z-order) since the last key cancels
    ; both classes before this key is read (a key earlier in this pass may
    ; have moved the focus; the pass start checks too).
    call input_layout_focus_check
    mov  edi, ebx
    xor  esi, esi
    call usb_hid_set1_to_usage
    test eax, eax
    jz   .done
    mov  r12d, eax                      ; HID usage
    movzx r15d, byte [rel input_key_origin]
    ; Ctrl without AltGr makes a control code from the layout's letter (US:
    ; Ctrl+A on the A key); any other Ctrl key types as if Ctrl were up.
    test byte [rel input_kbd_mods], 2
    jz   .mods
    test byte [rel input_kbd_sides], INPUT_SIDE_RALT
    jnz  .mods
    mov  edi, ebx
    call input_layout_letter
    cmp  eax, 'a'
    jb   .mods
    cmp  eax, 'z'
    ja   .mods
    lea  edi, [rax - 96]
    mov  esi, r15d
    call input_layout_queue
    jmp  .done
.mods:
    movzx r14d, byte [rel input_kbd_mods]
    and  r14d, 1                        ; Shift
    test byte [rel input_kbd_caps], 1
    jz   .no_caps
    or   r14d, 2
.no_caps:
    test byte [rel input_kbd_sides], INPUT_SIDE_RALT
    jz   .no_altgr                      ; AltGr is the RIGHT Alt only
    or   r14d, 4
.no_altgr:
    cmp  byte [rel input_kbd_numlock], 0
    je   .class
    or   r14d, 8
.class:
    lea  r13, [rel input_kbd_ctx_other]
    call input_key_is_hand
    jne  .read
    ; A hand key flushes a pending non-hand dead key as its spacing mark, with
    ; the dead key's origin, and composes only in the hand's own context.
    cmp  dword [r13 + INPUT_KBD_PENDING], 0
    je   .hand
    mov  rdi, r13
    mov  esi, INPUT_HID_SPACE
    xor  edx, edx
    lea  rcx, [rel input_layout_out]
    call kbd_key_event
    cmp  eax, 1
    jne  .flushed
    mov  edi, [rel input_layout_out]
    movzx esi, byte [rel input_dead_origin_other]
    call input_layout_queue
.flushed:
    mov  rdi, r13
    call input_layout_reselect
.hand:
    lea  r13, [rel input_kbd_ctx_hand]
.read:
    ; The scalars' origin: this key's, merged with the pending dead key's.
    cmp  dword [r13 + INPUT_KBD_PENDING], 0
    je   .origin_key
    lea  rax, [rel input_kbd_ctx_hand]
    lea  rdx, [rel input_dead_origin_hand]
    cmp  r13, rax
    je   .origin_dead
    lea  rdx, [rel input_dead_origin_other]
.origin_dead:
    movzx eax, byte [rdx]
    mov  edx, r15d
    call ps2_kbd_origin_merge
    mov  ebx, eax
    jmp  .event
.origin_key:
    mov  ebx, r15d
.event:
    mov  rdi, r13
    mov  esi, r12d
    mov  edx, r14d
    lea  rcx, [rel input_layout_out]
    call kbd_key_event
    mov  r12d, eax
    cmp  dword [r13 + INPUT_KBD_PENDING], 0
    je   .emit
    ; RCQ-38 L1 C2 (srcreview 14:53:52): only a key that made the pending dead
    ; key takes it over: 3 a new one, 1 one over a pending one (its mark goes
    ; out). A key with no output (0, e.g. es-ES AltGr+7) or an invalid one (-1)
    ; leaves the earlier dead key, so its origin stays.
    test r12d, r12d
    jle  .emit
    lea  rax, [rel input_kbd_ctx_hand]  ; the new dead key carries this key's origin
    lea  rdx, [rel input_dead_origin_hand]
    cmp  r13, rax
    je   .dead_origin
    lea  rdx, [rel input_dead_origin_other]
.dead_origin:
    mov  [rdx], r15b
.emit:
    cmp  r12d, 1
    jl   .done
    cmp  r12d, 2
    jg   .done
    mov  edi, [rel input_layout_out]
    mov  esi, ebx
    call input_layout_queue
    cmp  r12d, 2
    jne  .done
    mov  edi, [rel input_layout_out + 4]
    mov  esi, ebx
    call input_layout_queue
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; input_close_focused — G3 (usage suite WIN-03): Alt+F4 closes the focused,
; visible desktop window through the caption-x path (wmx_close_slot). Never the
; sign-in surface, never while locked. Clobbers caller-saved; preserves RBX.
input_close_focused:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    mov  edi, [rel wm_focus]
    cmp  edi, WM_MAX
    jae  .out
    cmp  edi, LOCK_SLOT
    je   .out
    lea  rax, [rel wm_state]
    cmp  dword [rax + rdi*4], WM_VISIBLE
    jne  .out
    call wmx_close_slot
.out:
    ret

; input_route_live_hook_tick — boot audit (2), spec 7.6.5 ("keyboard live before the
; sign-in paint, or hold the paint until it is"). Runs the one-shot input_route_live_hook
; (lock_screen_boot_release) on the first non-KAT pass, right after the timeline
; tick below. A keyboard present at boot (PS/2 armed, or USB HID bound with
; its consumer dispatching, which usb_hid_start_task proves before lock_screen_init) has
; latched boot.input.kbd.live on this same pass, so BOOTCLOCK kbd <= BG6. No time bound: a
; keyboard bound later (reconnect/rescan) cannot be waited for without slowing every boot
; that has none (MSI, unattached Beelink), so the pass releases anyway and counts it in
; input_route_live_no_kbd. Preserves all registers.
input_route_live_hook_tick:
    cmp  byte [rel input_route_tl_kat], 0
    jne  .out
    cmp  qword [rel input_route_live_hook], 0
    je   .out
    push rax
    test byte [rel input_route_tl_live], 1
    jnz  .run
    inc  qword [rel input_route_live_no_kbd]
.run:
    mov  rax, [rel input_route_live_hook]
    mov  qword [rel input_route_live_hook], 0
    call rax
    pop  rax
.out:
    ret

; Boot-timeline input marks (measurement only: reads producer facts, never
; reads, consumes or injects input; no serial, no wait). The idle loop runs this
; router and then ps2_pointer_pump back to back (boot/header.asm .halt), and is
; the only runtime consumer of the shared scancode ring and pointer post ring.
; The first non-KAT router pass is therefore the first moment a producer's
; events reach the desktop (focused window, or the sign-in field while
; locked). A mark latches on that pass once its producer is armed:
;   kbd: PS/2 IRQ1 installed on a responding 8042, or an active USB HID boot
;        keyboard interface with the resident HID consumer task dispatching;
;   ptr: PS/2 IRQ12 with an aux device that ACKed set-defaults, or an active
;        USB HID boot mouse with that task dispatching.
; A later hot-plugged producer still latches on its first live pass. CLI
; presentation has no desktop router, so it never latches these marks.
input_route_timeline_tick:
    cmp  byte [rel input_route_tl_kat], 0
    jne  .out                           ; boot routing KAT feeds synthetic bytes
    cmp  byte [rel input_route_tl_live], 3
    je   .out
    push rax
    push rcx
    push rdi
    test byte [rel input_route_tl_live], 1
    jnz  .ptr
    cmp  byte [rel ps2_kbd_armed], 1
    je   .kbd_live
    mov  edi, USB_HID_KIND_KBD
    call usb_hid_kind_live
    test eax, eax
    jz   .ptr
.kbd_live:
    or   byte [rel input_route_tl_live], 1
    mov  edi, BOOT_TIMELINE_ID_INPUT_KBD_LIVE
    call boot_timeline_latch
.ptr:
    test byte [rel input_route_tl_live], 2
    jnz  .done
    cmp  byte [rel ps2_mouse_armed], 1
    je   .ptr_live
    mov  edi, USB_HID_KIND_MOUSE
    call usb_hid_kind_live
    test eax, eax
    jz   .done
.ptr_live:
    or   byte [rel input_route_tl_live], 2
    mov  edi, BOOT_TIMELINE_ID_INPUT_PTR_LIVE
    call boot_timeline_latch
.done:
    pop  rdi
    pop  rcx
    pop  rax
.out:
    ret

; Boot KAT plus the two live textfields used by the metal acceptance probe.
gui_input_route_init:
    push rbx
    push r12
    push r13
    push r14
    mov  qword [rel input_kbd_routed], 0 ; a typed sign-in's keys are not the KAT's three
    movzx eax, byte [rel input_layout_id] ; RCQ-38 L2: the KAT types en-US bytes; the
    mov  [rel input_layout_kat_id], al  ; owner's saved layout (applied at boot) returns after it
    xor  edi, edi
    call input_layout_set
    mov  byte [rel input_route_tl_kat], 1
    call gui_input_route_tick
    lea  rax, [rel wm_state]
    cmp  dword [rax], WM_VISIBLE
    jne  .fail
    cmp  dword [rax + 4], WM_VISIBLE
    jne  .fail
    mov  edi, 1
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  r12d, eax
    mov  edi, 1
    mov  esi, 1
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  r13d, eax
    lea  rsi, [rel input_empty]
    mov  edi, r12d
    call wgt_set_text
    lea  rsi, [rel input_empty]
    mov  edi, r13d
    call wgt_set_text
    lea  rax, [rel wgt_focus_by_win]
    mov  [rax], r12d
    mov  [rax + 4], r13d
    mov  ebx, [rel wm_focus]
    mov  dword [rel wm_focus], 0
    mov  edi, 0
    call wgt_focus_window

    mov  al, 0x1E
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + WGI_VAL], 'a'
    jne  .restore_fail
    cmp  byte [rax + WGI_VAL + 1], 0
    jne  .restore_fail
    mov  edi, r13d
    call wgt_slot_ptr
    cmp  byte [rax + WGI_VAL], 0
    jne  .restore_fail
    mov  al, 0x0E
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + WGI_VAL], 0
    jne  .restore_fail
    cmp  dword [rax + WGI_CARET], 0
    jne  .restore_fail
    mov  al, 0x1C
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_SUBMITS], 1
    jne  .restore_fail
    cmp  qword [rel input_kbd_routed], 3
    jne  .restore_fail

    ; UI wave 2 B10 KAT (same ring as physical input): a Win make alone does
    ; not fire the global key; its release does; Win+D fires nothing and types
    ; nothing into the focused field; the right Win key behaves the same.
    call input_win_kat
    lea  rdi, [rel str_win_kat_ok]
    test eax, eax
    jz   .win_kat_report
    lea  rdi, [rel str_win_kat_fail]
.win_kat_report:
    call serial_string
    ; RCQ-51: the AI key's gesture machine at exact times (tap, double, hold), then its boot zero again.
    call input_ai_kat
    lea  rdi, [rel str_ai_kat_ok]
    test eax, eax
    jz   .ai_kat_report
    lea  rdi, [rel str_ai_kat_fail]
.ai_kat_report:
    call serial_string

    ; Ring overflow is exercised only under a hypervisor, never on metal.
    push rbx
    mov  eax, 1
    cpuid
    test ecx, 0x80000000
    pop  rbx
    jz   .overflow_done
    mov  r14, [rel kbd_dropped_count]
    mov  ecx, KBD_RING_LEN
.fill_ring:
    mov  al, 0x9E
    call ps2_kbd_enqueue_internal
    dec  ecx
    jnz  .fill_ring
    cmp  byte [rel kbd_count], KBD_RING_LEN
    jne  .restore_fail
    mov  al, 0x9E
    call ps2_kbd_enqueue_internal
    mov  rax, [rel kbd_dropped_count]
    sub  rax, r14
    cmp  rax, 1
    jne  .restore_fail
    call gui_input_route_tick
    call gui_input_route_tick
    call gui_input_route_tick
    call gui_input_route_tick
    cmp  byte [rel kbd_count], 0
    jne  .restore_fail
    cmp  qword [rel input_kbd_routed], 3
    jne  .restore_fail
.overflow_done:
    lea  rax, [rel wgt_focus_by_win]
    mov  dword [rax], -2
    mov  dword [rel wgt_focus_id], -1
    mov  r14, [rel kbd_dropped_count]
    mov  al, 0x1E
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    mov  rax, [rel kbd_dropped_count]
    sub  rax, r14
    cmp  rax, 1
    jne  .restore_fail
    cmp  qword [rel input_kbd_routed], 3
    jne  .restore_fail

    lea  rdi, [rel str_input_route_marker]
    call serial_string
    lea  rdi, [rel str_textfield_edit_marker]
    call serial_string
    mov  edi, r12d
    call wgt_slot_ptr
    mov  dword [rax + WGI_SUBMITS], 0
    lea  rsi, [rel input_empty]
    mov  edi, r12d
    call wgt_set_text
    mov  qword [rel input_kbd_submits], 0
    mov  qword [rel input_kbd_routed], 0
    mov  qword [rel kbd_dropped_count], 0
    mov  byte [rel input_kbd_mods], 0
    mov  byte [rel input_kbd_sides], 0
    mov  byte [rel input_kbd_sides_inj], 0
    mov  byte [rel input_kbd_sides_hand], 0
    mov  byte [rel input_kbd_caps], 0
    mov  byte [rel input_kbd_e0], 0
    mov  byte [rel input_kbd_e1], 0
    mov  byte [rel input_win_down], 0
    mov  byte [rel input_win_chord], 0
    mov  byte [rel input_win_inj], 0
    lea  rax, [rel wgt_focus_by_win]
    mov  [rax], r12d
    mov  [rax + 4], r13d
    mov  [rel wm_focus], ebx
    mov  edi, ebx
    call wgt_focus_window
    call summon_palette_init
    call wmx_draw_all
    jmp  .out_init
.restore_fail:
    mov  [rel wm_focus], ebx
    lea  rax, [rel wgt_focus_by_win]
    mov  [rax], r12d
    mov  [rax + 4], r13d
    mov  edi, ebx
    call wgt_focus_window
.fail:
    lea  rdi, [rel str_input_route_fail]
    call serial_string
.out_init:
    mov  byte [rel input_route_tl_kat], 0
    movzx edi, byte [rel input_layout_kat_id]
    call input_layout_set
%if IME_BUILT
    call ime_route_init                 ; RCQ-38 I3b-1: after the KAT, which runs without the IME
%endif
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; input_win_kat(R12=focused empty textfield id) -> EAX 0 pass / 1 fail.
; Temporarily owns gui_input_global_key_hook (0 at this boot point; restored to
; 0). Clobbers caller-saved.
input_win_kat:
    push rbx
    lea  rax, [rel input_win_kat_hook]
    mov  [rel gui_input_global_key_hook], rax
    mov  dword [rel input_win_kat_calls], 0
    mov  ebx, 1                         ; fail until proven
    mov  al, 0xE0
    call ps2_kbd_enqueue_internal
    mov  al, 0x5B
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    cmp  dword [rel input_win_kat_calls], 0     ; make alone: no Start
    jne  .out
    mov  al, 0xE0
    call ps2_kbd_enqueue_internal
    mov  al, 0xDB
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    cmp  dword [rel input_win_kat_calls], 1     ; lone-tap release: Start
    jne  .out
    lea  rsi, [rel input_win_kat_chord]
.chord:
    lodsb
    test al, al
    jz   .chord_done
    push rsi
    call ps2_kbd_enqueue_internal
    pop  rsi
    jmp  .chord
.chord_done:
    call gui_input_route_tick
    cmp  dword [rel input_win_kat_calls], 1     ; Win+D: no Start
    jne  .out
    cmp  qword [rel input_kbd_routed], 3        ; 'd' was not delivered
    jne  .out
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + WGI_VAL], 0                ; and nothing was typed
    jne  .out
    mov  al, 0xE0
    call ps2_kbd_enqueue_internal
    mov  al, 0x5C
    call ps2_kbd_enqueue_internal
    mov  al, 0xE0
    call ps2_kbd_enqueue_internal
    mov  al, 0xDC
    call ps2_kbd_enqueue_internal
    call gui_input_route_tick
    cmp  dword [rel input_win_kat_calls], 2     ; right Win tap: Start
    jne  .out
    cmp  byte [rel input_win_down], 0
    jne  .out
    xor  ebx, ebx
.out:
    mov  qword [rel gui_input_global_key_hook], 0
    mov  byte [rel input_win_down], 0
    mov  byte [rel input_win_chord], 0
    mov  eax, ebx
    pop  rbx
    ret

input_win_kat_hook:
    inc  dword [rel input_win_kat_calls]
    ret

align 8
input_kbd_routed:  dq 0
input_kbd_submits: dq 0
input_kbd_mods:    db 0
input_kbd_caps:    db 0
input_kbd_e0:      db 0
input_kbd_e1:      db 0                 ; bytes left of an E1 (Pause) sequence
input_kbd_sides:   db 0                 ; private INPUT_SIDE_* bits behind input_kbd_mods
input_kbd_sides_inj: db 0               ; K1b: held sides whose make was not the owner's hand
input_kbd_sides_hand: db 0              ; K1b L2: held sides whose make was the owner's hand
input_kbd_numlock: db 1                 ; boot default on: keypad digits as before
; Retain the guest reset ABI: zeroing this byte forgets both held lock keys,
; without changing their toggle modes. Each lock's break clears only its bits.
input_kbd_numlock_down: db 0            ; INPUT_LOCK_* held-press flags
input_win_down:    db 0
input_win_chord:   db 0                 ; a key/click arrived while Win was held
input_win_inj:     db 0                 ; K1b: the held Win's make was not the owner's hand
input_win_sides:   db 0                 ; RCQ-09: 1 left Win, 2 right Win; down is their boolean
input_win_hand:    db 0                 ; K1b L2: side-specific hand release custody
input_win_kat_chord: db 0xE0, 0x5B, 0x20, 0xA0, 0xE0, 0xDB, 0
align 4
input_win_kat_calls: dd 0
align 8
gui_input_global_key_hook: dq 0
input_route_live_hook: dq 0             ; one-shot, run once the keyboard is live (lock_screen_init stores it)
input_route_live_no_kbd: dq 0           ; sign-in released with no live keyboard (none at boot)
gui_input_modal_key_hook: dq 0
input_empty:       db 0

; Layout data is deliberately swappable without translator changes.
align 16
input_us_plain:
    db 0,27,'1','2','3','4','5','6','7','8','9','0','-','=',8,9
    db 'q','w','e','r','t','y','u','i','o','p','[',']',13,0,'a','s'
    db 'd','f','g','h','j','k','l',';',39,'`',0,92,'z','x','c','v'
    db 'b','n','m',',','.','/',0,'*',0,' ',0,0,0,0,0,0
    db 0,0,0,0,0,0,0,'7','8','9','-','4','5','6','+','1'
    db '2','3','0','.',0,0,92,0,0       ; 56: ISO B00 (RCQ-38 L0, CLDR en-windows)
input_us_shift:
    db 0,27,'!','@','#','$','%','^','&','*','(',')','_','+',8,9
    db 'Q','W','E','R','T','Y','U','I','O','P','{','}',13,0,'A','S'
    db 'D','F','G','H','J','K','L',':',34,'~',0,'|','Z','X','C','V'
    db 'B','N','M','<','>','?',0,'*',0,' ',0,0,0,0,0,0
    db 0,0,0,0,0,0,0,'7','8','9','-','4','5','6','+','1'
    db '2','3','0','.',0,0,'|',0,0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_input_route_tl 0
input_route_tl_live: resb 1             ; bit0 kbd / bit1 ptr boot-timeline mark latched
input_route_tl_kat:  resb 1             ; 1 while gui_input_route_init drives the router
%endmacro
WDATA_BSS_DEFER WDATA_gui_input_route_tl
; RCQ-38 L1: layout state. Zero = en-US with unselected contexts.
%macro WDATA_gui_input_layout 0
alignb 8
input_text_dropped:    resq 1           ; scalars >= 0x80 no consumer took (L3b: GUI_KEY_TEXT dropped)
input_layout_epoch:    resq 1           ; C1: session_authority_epoch at the last pass
input_kbd_ctx_hand:    resb 32          ; core/keyboard_layout contexts (KEYBOARD_LAYOUT.md)
input_kbd_ctx_other:   resb 32          ; read by sec/keyprov (dead-key slot pin): its PENDING != 0 is a contract
input_kbd_ctx_probe:   resb 32
input_layout_out:      resd 2
input_layout_pout:     resd 2
input_lq_scalar:       resd INPUT_LQ_MAX
input_lq_head:         resd 1
input_lq_tail:         resd 1
input_layout_st_focus: resd 1           ; focus stamp at the last layout key
input_layout_st_widget: resd 1
input_layout_st_z:     resd 1
input_lq_origin:       resb INPUT_LQ_MAX
input_layout_id:       resb 1           ; 0 en-US, 1 es-ES, 2 fr-FR, 3 de-DE
input_layout_locked:   resb 1           ; session_locked at the last pass
input_dead_origin_hand: resb 1
input_dead_origin_other: resb 1         ; read by sec/keyprov (dead-key slot pin): the KO_* origin byte is a contract
input_layout_kat_id: resb 1             ; L2: the layout in force across the boot routing KAT
alignb 8                                ; RCQ-38 I3b-1: the IME seam; zero = no IME, every path is unchanged
input_ime_ops:         resq 4           ; INPUT_IME_*: filled once by gui/ime_route's ime_route_init
input_ime_lq_scalar:   resd 1           ; the scalar of the last layout GUI_KEY_TEXT
input_ime_tray:        resd 1           ; the taskbar mode cell (INPUT_IME_TRAY_NODICT): written only by gui/ime_route,
                                        ;   read by gui/window's taskbar_ime_paint and gui/taskbar; 0 without the IME
input_ime_space_held:  resb 1           ; Ctrl+Space since the last Space release: 1 toggled, 2 the field's
alignb 4
input_ime_pop:         resb INPUT_IME_POP_SIZE ; the candidate window (INPUT_IME_POP_*): written only by gui/ime_route,
                                        ;   read by gui/window's ime_popup_*; KIND 0 without the IME
alignb 8                                ; RCQ-51: the AI key. Zero = nothing down, nothing pending, an empty ring
input_ai_counts:    resq 4              ; TAP, DOUBLE, HOLD_START, HOLD_END reported
input_ai_refused:   resq 1              ; chords whose key, Win or a held side was not the owner's hand
input_ai_locked:    resq 1              ; chords on the sign-in surface
input_ai_cancelled: resq 1              ; lock-ended gestures and owner Esc retirements
input_ai_dropped:   resq 1              ; events the full ring could not keep
input_ai_t_down:    resq 1              ; monotonic us of the held press
input_ai_t_up:      resq 1              ;   of the release a pending tap waits from
input_ai_ring:      resb INPUT_AI_RING * INPUT_AI_REC
input_ai_head:      resd 1              ; records produced
input_ai_tail:      resd 1              ; records popped
input_ai_seq:       resd 1              ; events reported (dropped ones included)
input_ai_down:      resb 1              ; INPUT_AI_DOWN_*, 0 none
input_ai_src:       resb 1              ; INPUT_AI_SRC_* of the press that is down
input_ai_src_up:    resb 1              ;   of the press a pending tap belongs to
input_ai_origin:    resb 1              ; KO_* of the reporting press (KO_HUMAN, or KO_INTERNAL in the boot KAT)
input_ai_hold:      resb 1              ; HOLD_START reported for the held press
input_ai_pending:   resb 1              ; a released press waits out DOUBLE
%endmacro
WDATA_BSS_DEFER WDATA_gui_input_layout
; RCQ-51: Alt+Shift. Its own block (split WDATA blocks are pinned).
%macro WDATA_gui_input_altshift 0
alignb 8
input_layout_switches: resq 1           ; Alt+Shift layout switches this boot
input_altshift:        resb 1           ; 1: left Alt and a Shift are down from the owner's hand, nothing else since
%endmacro
WDATA_BSS_DEFER WDATA_gui_input_altshift

str_input_route_marker: db "[PAOS64] verb-console rung 1: kbd_ring consumer live — scancode->ASCII, focus-routed delivery selftest [input.kbd.route]",13,10,0
str_textfield_edit_marker: db "[PAOS64] verb-console rung 1: textfield edit ops (caret/insert/backspace/enter submit event) selftest [gui.textfield.edit]",13,10,0
str_win_kat_ok: db "[PAOS64] Win key: Start on the lone-tap release, Win+key chords never typed [input.win.release.kat]",13,10,0
str_win_kat_fail: db "[PAOS64] Win key release/chord KAT FAILED [input.win.release.kat.fail]",13,10,0
str_ai_kat_ok: db "[PAOS64] AI key: tap, double and hold at exact times, typed events in order [input.ai.key.kat]",13,10,0
str_ai_kat_fail: db "[PAOS64] AI key gesture KAT FAILED [input.ai.key.kat.fail]",13,10,0
str_input_route_fail: db "[PAOS64] verb-console rung 1: keyboard routing/textfield selftest FAILED",13,10,0
