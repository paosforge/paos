;; MODULE gui/card_surface
;; LAYER 6
;; EXPORTS card_surface_init, card_surface_tick
;; IMPORTS gui/calendar, svc/command_card, svc/command, core/time, gui/form_loader, gui/widget, gui/window_mgmt, gui/window, gui/chat_app, gui/wm_pointer, gui/start_programs, dev/input/ps2, sec/session, boot/gop
;; CAPS CAP_GUI
;; OWNER saga:command
; ============================================================================
; gui/card_surface.asm -- RCQ-40 J2b: the owner action card's surface, and the
; owner's Confirm (root GRANT 10:15:35, PLAN 3f5d0be6; DESIGN_J2_CARD ba1dd804
; s4-s5 with rc-sec's C1-C8). svc/command_card keeps the record and the one
; dispatch path; this file only shows the card and carries the owner's answer.
;
; Show: CARDPROPOSE's dispatch only records that a card is owed. The idle tick
; builds it at dispatch depth 0, in no request frame: form row 21 ("card",
; loadable only while form_card_loading is set), stamped WM_OWNER_CHROME and
; labelled before its first paint (P1). The card never takes the keyboard; the
; owner gives it (C1). Its keyboard rests on Deny.
;
; Confirm by key: the owner's own Tab (KO_HUMAN) reaches Confirm, then the
; owner's Enter or Space (KO_HUMAN) records it, with the local authority
; snapshot taken at that key (C1). Any pointer press, any key that is not
; KO_HUMAN, a raise that changes stacking, an open or Alt+Tab (wm_zcounter), or
; the card losing the keyboard spends the Tab; a blur also puts the card's
; keyboard back on Deny.
; Confirm by pointer (J2b-P, rc-input Q1: start_programs' SP_ARM_CARD row, the
; SEC R1 F1 arm): a press alone never confirms. A HUMAN press on Confirm only
; latches, and only while the row is armed (the cursor came in physically from
; outside, on this screen, with nothing on top at each point), cs_ok_op
; answers yes (nothing painted over the card window), the C7 inert window
; (CARD_ARM_US after show/re-arm) has passed and the local authority is live
; (snapshot at the press, with card_armed_us: rc-sec P1). The tick turns it into the Confirm only on its
; own release: exactly one HUMAN left release since the press, at a point
; inside Confirm above the taskbar band (srcreview F4), the row still armed
; (every injected event disarms it; the release's own note disarms it when
; covered there), no re-arm and no non-HUMAN pointer event since the press
; (an injected button-up could hide the owner's release: srcreview F1),
; and cs_ok_op again. The card is built disarmed
; (sp_disarm), and a closed card arms nothing (sp_arm_card_wid -1).
; Esc, or Enter/Space on Deny, or a HUMAN press on Deny, denies; an injected
; one does nothing.
;
; The tick acts: card_confirm runs here (card_surface_tick's .answer, not
; cs_build: srcreview J2b F5), in the idle loop at depth 0, never in
; an IRQ and never under a dns_wire/netdev lock (srcreview J6 F1: J6's rule
; re-reads NETCHECK). 0 = dispatched, 1 = withdrawn (J6), -1 = refused; the
; record closes the window itself through card_surface_close_op on 0 and 1.
; C7: a move, a resize, a screen change or a change in cs_ok_op's answer
; (focus, cover, minimize) re-arms the 750 ms delay, so a cover appearing over
; the card and going again never gives an instant Confirm (F4 (b)). An agent
; FORMLOAD of the Summon palette while a card is shown is refused card_shown
; (form_summon_gate, F4 (c)). A card whose window is
; gone (its caption close: any pointer may press it) is a system cancel.
; C8 / FA2-lock: a lock or rebind ends the card in card_tick; its window is
; closed even while the lock hides it, so an unlock never revives it.
; ============================================================================

CS_PEND_NONE    equ 0
CS_PEND_CONFIRM equ 1
CS_PEND_DENY    equ 2
CS_W_WHO        equ 0                   ; form row 21's widgets, declaration order
CS_W_VERB       equ 1
CS_W_ARG0       equ 2
CS_ARG_ROWS     equ 7
CS_W_NOTE       equ (CS_W_ARG0 + CS_ARG_ROWS)
CS_W_DENY       equ (CS_W_NOTE + 1)
CS_W_CONFIRM    equ (CS_W_DENY + 1)
CS_W_COUNT      equ (CS_W_CONFIRM + 1)
CS_GEOM_N       equ 7                   ; x, y, w, h, fb_width, fb_height, cs_ok_op's answer
%if CS_ARG_ROWS * WGI_VAL_MAX < CARD_ARG_MAX
%error "card_surface: the argument rows cannot show CARD_ARG_MAX bytes (term 1)"
%endif

;; card_surface_init(): installs the record's three surface ops and heads the
;; kit's key filter and click hook (card -> start_programs -> lock screen).
card_surface_init:
    lea  rax, [rel cs_show_op]
    mov  [rel card_surface_show_op], rax
    lea  rax, [rel cs_close_op]
    mov  [rel card_surface_close_op], rax
    lea  rax, [rel cs_ok_op]
    mov  [rel card_surface_ok_op], rax
    lea  rax, [rel cs_summon_gate]
    mov  [rel form_summon_gate], rax
    mov  rax, [rel wgt_click_hook]
    mov  [rel cs_click_prev], rax
    lea  rax, [rel cs_click]
    mov  [rel wgt_click_hook], rax
    mov  rax, [rel wgt_key_filter]
    mov  [rel cs_key_prev], rax
    lea  rax, [rel cs_key_filter]
    mov  [rel wgt_key_filter], rax
    mov  byte [rel cs_live], 1
    ret

;; cs_show_op(): card_surface_show_op, inside CARDPROPOSE's dispatch. Only
;; records that a card is owed; the tick builds it outside any request frame.
cs_show_op:
    mov  byte [rel cs_show], 1
    ret

;; cs_close_op(): card_surface_close_op. The record ended (Confirm, withdrawn,
;; Deny, expiry, cancel, lock): its window goes, hidden by a lock or not.
;; Clobbers caller-saved registers.
cs_close_op:
    mov  byte [rel cs_show], 0
    mov  byte [rel cs_pending], CS_PEND_NONE
    mov  byte [rel cs_tab], 0
    mov  byte [rel cs_ptr], 0
    mov  dword [rel sp_arm_card_wid], -1    ; J2b-P: a closed card arms nothing
    call cs_scan
    cmp  eax, -1
    je   .out
    mov  edi, eax
    call wmx_close_slot
.out:
    ret

;; cs_scan() -> EAX the card window's slot with cs_ids filled (declaration
;; order), or -1 when row 21 has no open window with all its widgets. Open is
;; any state but free/closed (visible, minimized, hidden by the lock); the slot
;; is the card's only while it carries row 21's form-owned title (a closed
;; card's slot number is reused). Clobbers caller-saved registers.
cs_scan:
    push rbx
    push r12
    push r13
    mov  r12d, [rel form_active_slot + FORM_CARD_INDEX*4]
    cmp  r12d, WM_MAX
    jae  .none                          ; -1: never built, or closed
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_FREE
    je   .none
    cmp  eax, WM_CLOSED
    je   .none
    lea  rax, [rel wm_title]
    lea  rcx, [rel form_titles + FORM_CARD_INDEX*FORM_TITLE_MAX]
    cmp  [rax + r12*8], rcx
    jne  .none
    xor  ebx, ebx
    xor  r13d, r13d
.scan:
    cmp  ebx, [rel wgt_count]
    jae  .scanned
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .next
    cmp  [rax + WGI_WIN], r12d
    jne  .next
    lea  rcx, [rel cs_ids]
    mov  [rcx + r13*4], ebx
    inc  r13d
    cmp  r13d, CS_W_COUNT
    jae  .scanned
.next:
    inc  ebx
    jmp  .scan
.scanned:
    cmp  r13d, CS_W_COUNT
    jb   .none
    mov  eax, r12d
    jmp  .out
.none:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

;; cs_ok_op() -> EAX 0 when Confirm may count now (card_surface_ok_op, C8):
;; the card is a visible PaOS-chrome window with the keyboard (the focused
;; window paints last in every pass, so no window is above it), wholly on the
;; screen (term 1) and wholly above the taskbar band (F4 r1: the taskbar
;; paints after every window; WINMOVE / WINRESIZE can put the card's bottom
;; rows there), at the size it was built (F4 r1: WINRESIZE acts on any slot,
;; and a smaller card clips or squeezes its rows), and no widget painted after the windows covers any pixel
;; of the card WINDOW (srcreview + rc-sec F4 (a),
;; key and pointer alike): no shown overlay (layer 1: menus, dropdowns,
;; Summon) and no painted desktop-host widget (wmx_draw_all paints them after
;; every window: the Start button, Summon's panel, flyouts). Else -1.
;; Clobbers caller-saved registers.
cs_ok_op:
    push rbx
    call cs_scan
    cmp  eax, -1
    je   .no
    mov  ebx, eax
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rbx*4], WM_VISIBLE
    jne  .no
    lea  rcx, [rel wm_owner]
    cmp  qword [rcx + rbx*8], WM_OWNER_CHROME
    jne  .no
    cmp  ebx, [rel wm_focus]
    jne  .no
    lea  rcx, [rel wm_x]
    mov  eax, [rcx + rbx*4]
    test eax, eax
    js   .no
    lea  rcx, [rel wm_w]
    add  eax, [rcx + rbx*4]
    cmp  eax, [rel fb_width]
    jg   .no
    lea  rcx, [rel wm_y]
    mov  eax, [rcx + rbx*4]
    test eax, eax
    js   .no
    lea  rcx, [rel wm_h]
    add  eax, [rcx + rbx*4]
    mov  ecx, [rel fb_height]
    sub  ecx, TASKBAR_H                 ; the taskbar's own top (gui/window's taskbar paint)
    cmp  eax, ecx
    jg   .no                            ; F4 r1: the taskbar band paints above every window
    lea  rcx, [rel wm_w]
    mov  eax, [rcx + rbx*4]
    cmp  eax, [rel cs_built_w]
    jne  .no                            ; F4 r1 (srcreview 14:26:35 (b)): at its built size,
    lea  rcx, [rel wm_h]
    mov  eax, [rcx + rbx*4]
    cmp  eax, [rel cs_built_h]
    jne  .no                            ;   or a WINRESIZE has clipped or squeezed its rows
    lea  rcx, [rel wm_x]
    mov  r8d, [rcx + rbx*4]             ; the card window: x0, y0, x1, y1
    lea  rcx, [rel wm_y]
    mov  r9d, [rcx + rbx*4]
    lea  rcx, [rel wm_w]
    mov  r10d, [rcx + rbx*4]
    add  r10d, r8d
    lea  rcx, [rel wm_h]
    mov  r11d, [rcx + rbx*4]
    add  r11d, r9d
    mov  ecx, r10d
    mov  edx, r11d
    call calendar_overlaps
    test eax, eax
    jnz  .no

    xor  ecx, ecx
    lea  rdx, [rel wgt_tbl]
.overlay:
    cmp  ecx, [rel wgt_count]
    jae  .yes
    cmp  dword [rdx + WGI_TYPE], 0
    je   .overlay_next
    test dword [rdx + WGI_FLAGS], 1
    jz   .overlay_next                  ; not painted (a closed Summon row keeps its rect)
    mov  rax, rdx                       ; the one predicate for paint, hover and press: an
    call wgt_row_shown                  ;   overlay of an unfocused window paints nothing here
    jc   .overlay_next
    cmp  dword [rdx + WGI_LAYER], 1
    je   .cover
    cmp  dword [rdx + WGI_WIN], WGT_HOST_DESKTOP
    jne  .overlay_next                  ; a window's own widget: under the focused card
.cover:
    mov  eax, [rdx + WGI_X]
    cmp  eax, r10d
    jge  .overlay_next
    add  eax, [rdx + WGI_W]
    cmp  eax, r8d
    jle  .overlay_next
    mov  eax, [rdx + WGI_Y]
    cmp  eax, r11d
    jge  .overlay_next
    add  eax, [rdx + WGI_H]
    cmp  eax, r9d
    jg   .no                            ; it overlaps the card window
.overlay_next:
    add  rdx, WGI_SZ
    inc  ecx
    jmp  .overlay
.yes:
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  rbx
    ret

;; cs_key_filter(EDI = focused widget id, EAX = key) -> EAX 1 taken: the kit's
;; key filter (chained). Every key for the card is the card's; only the
;; owner's Tab goes on to the kit, to step between Deny and Confirm.
cs_key_filter:
    push rdi
    push rax
    call cs_scan
    cmp  eax, -1
    je   .other
    mov  ecx, eax
    mov  edi, [rsp + 8]
    push rcx
    call wgt_slot_ptr
    pop  rcx
    cmp  [rax + WGI_WIN], ecx
    jne  .other
    pop  rax
    pop  rdi
    cmp  byte [rel input_key_origin], KO_HUMAN
    jne  .foreign
    cmp  eax, GUI_KEY_TAB
    je   .tab
    cmp  eax, GUI_KEY_ESC
    je   .deny
    cmp  eax, GUI_KEY_ENTER
    je   .press
    cmp  eax, ' '
    jne  .taken                         ; anything else does nothing here
.press:
    cmp  edi, [rel cs_ids + CS_W_DENY*4]
    je   .deny
    cmp  edi, [rel cs_ids + CS_W_CONFIRM*4]
    jne  .taken
    cmp  byte [rel cs_tab], 1
    jne  .taken                         ; Confirm reached by a press or a restored focus is inert
    cmp  byte [rel wgt_focus_visible], 1
    jne  .taken                         ; a pointer press since the Tab (it may have moved the focus here)
    mov  eax, [rel wm_zcounter]
    cmp  eax, [rel cs_tab_z]
    jne  .taken                         ; a raise, open or Alt+Tab since the Tab
    call session_shell_local_authority  ; C1: the snapshot at the event
    test rax, rax
    jz   .taken
    mov  [rel cs_pid], rax
    mov  [rel cs_token], rdx
    mov  byte [rel cs_pending], CS_PEND_CONFIRM
    jmp  .taken
.deny:
    mov  byte [rel cs_pending], CS_PEND_DENY
    jmp  .taken
.tab:
    mov  byte [rel cs_tab], 1
    mov  eax, [rel wm_zcounter]
    mov  [rel cs_tab_z], eax
    xor  eax, eax                       ; the owner's Tab stays the kit's
    ret
.foreign:
    mov  byte [rel cs_tab], 0           ; not the owner's hand: taken, and the Tab is spent
.taken:
    mov  eax, 1
    ret
.other:
    pop  rax
    pop  rdi
    mov  rdx, [rel cs_key_prev]
    test rdx, rdx
    jz   .none
    jmp  rdx
.none:
    xor  eax, eax
    ret

;; cs_click(EDI = widget id): the kit's click hook (chained), on the press
;; edge. Any press spends the owner's Tab and any earlier latch. A HUMAN press
;; on Deny denies; a press on Confirm at most latches (J2b-P).
cs_click:
    mov  byte [rel cs_tab], 0
    mov  byte [rel cs_ptr], 0
    push rdi
    call cs_scan
    pop  rdi
    cmp  eax, -1
    je   .chain
    cmp  edi, [rel cs_ids + CS_W_CONFIRM*4]
    je   .confirm
    cmp  edi, [rel cs_ids + CS_W_DENY*4]
    jne  .chain
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .out
    mov  byte [rel cs_pending], CS_PEND_DENY
.out:
    ret
.chain:
    mov  rax, [rel cs_click_prev]
    test rax, rax
    jz   .out
    jmp  rax
.confirm:
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .out                           ; an injected or remote press never latches
    mov  esi, SP_ARM_CARD
    call sp_arm_holds                   ; EDI = Confirm
    test eax, eax
    jz   .out                           ; not steered onto Confirm since the last injection
    call cs_ok_op                       ; F4 (a): desktop-host cover included
    test eax, eax
    jnz  .out
    call time_monotonic_now_us
    mov  rcx, [rel card_armed_us]
    add  rcx, CARD_ARM_US
    cmp  rax, rcx
    jb   .out                           ; C7 (rc-sec P1): a press in the inert window never latches
    call session_shell_local_authority  ; C1: the snapshot at the press
    test rax, rax
    jz   .out
    mov  [rel cs_ptr_pid], rax
    mov  [rel cs_ptr_token], rdx
    mov  rax, [rel card_armed_us]
    mov  [rel cs_ptr_armed], rax
    mov  eax, [rel sp_ptr_up_seq]
    mov  [rel cs_ptr_seq], eax
    mov  eax, [rel sp_ptr_inj_seq]
    mov  [rel cs_ptr_inj], eax
    mov  byte [rel cs_ptr], 1
    ret

;; cs_ptr_release(): a latched press on Confirm becomes the owner's Confirm
;; only on its own release: exactly one HUMAN left release since the press,
;; inside Confirm and above the taskbar band (srcreview F4), the SP_ARM_CARD
;; row still armed, cs_ok_op and no desktop cover. An answer already recorded
;; (Deny) is kept. Clobbers caller-saved registers.
cs_ptr_release:
    cmp  byte [rel cs_ptr], 1
    jne  .out
    mov  eax, [rel sp_ptr_inj_seq]
    cmp  eax, [rel cs_ptr_inj]
    jne  .spent                         ; srcreview F1: a non-HUMAN event during the hold (a hidden release)
    mov  eax, [rel sp_ptr_up_seq]
    cmp  eax, [rel cs_ptr_seq]
    je   .out                           ; still held
    mov  byte [rel cs_ptr], 0
    dec  eax
    cmp  eax, [rel cs_ptr_seq]
    jne  .out                           ; more than one release since the press
    mov  rax, [rel card_armed_us]
    cmp  rax, [rel cs_ptr_armed]
    jne  .out                           ; C7 (rc-sec P1): a re-arm during the hold spends the latch
    cmp  byte [rel cs_pending], CS_PEND_NONE
    jne  .out
    mov  edi, [rel cs_ids + CS_W_CONFIRM*4]
    call wgt_slot_ptr
    mov  ecx, [rel sp_ptr_up_x]
    sub  ecx, [rax + WGI_X]
    cmp  ecx, [rax + WGI_W]
    jae  .out                           ; released outside Confirm: a cancel
    mov  ecx, [rel sp_ptr_up_y]
    sub  ecx, [rax + WGI_Y]
    cmp  ecx, [rax + WGI_H]
    jae  .out
    mov  ecx, [rel fb_height]
    sub  ecx, TASKBAR_H
    cmp  [rel sp_ptr_up_y], ecx
    jge  .out                           ; F4: the taskbar band paints above every window
    mov  edi, [rel cs_ids + CS_W_CONFIRM*4]
    mov  esi, SP_ARM_CARD
    call sp_arm_holds
    test eax, eax
    jz   .out
    call cs_ok_op                       ; F4 (a): desktop-host cover included
    test eax, eax
    jnz  .out
    mov  rax, [rel cs_ptr_pid]
    mov  [rel cs_pid], rax
    mov  rax, [rel cs_ptr_token]
    mov  [rel cs_token], rax
    mov  byte [rel cs_pending], CS_PEND_CONFIRM
.out:
    ret
.spent:
    mov  byte [rel cs_ptr], 0
    ret

;; cs_summon_gate() -> EAX 1 when this FORMLOAD of the Summon palette is
;; refused: a card is shown and the frame is not the owner's console (the same
;; test summon_palette_form_load uses for the user's intent: a dispatch whose
;; source is CMD_SOURCE_CONSOLE). The palette is a desktop-host overlay an
;; agent could lay over the card's verb and argument rows (srcreview + rc-sec
;; F4 (c)). form_loader's form_summon_gate. Clobbers RAX.
cs_summon_gate:
    xor  eax, eax
    cmp  byte [rel card_state], CS_SHOWN
    jne  .out
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .refuse
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_CONSOLE
    je   .out
.refuse:
    mov  eax, 1
.out:
    ret

;; card_surface_tick(): the idle loop (boot/header, after start_programs_tick).
card_surface_tick:
    cmp  byte [rel cs_live], 1
    jne  .out                           ; no GUI composition: J2a's no-surface card
    call card_tick                      ; expiry / lock / rebind end the card and close it
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .idle                          ; rc-input (2): never builds or acts locked; a pending answer is spent
    cmp  byte [rel card_state], CS_SHOWN
    jne  .idle
    cmp  byte [rel cs_show], 0
    jne  cs_build
    push rbx
    call cs_scan
    cmp  eax, -1
    je   .gone
    mov  ebx, eax
    cmp  ebx, [rel wm_focus]
    je   .focused
    mov  byte [rel cs_tab], 0           ; blur: the Tab is spent, the keyboard goes back to Deny
    mov  eax, [rel cs_ids + CS_W_DENY*4]
    lea  rcx, [rel wgt_focus_by_win]
    mov  [rcx + rbx*4], eax
.focused:
    mov  edi, ebx
    call cs_geom_changed
    test eax, eax
    jz   .answer
    call card_rearm                     ; C7
.answer:
    call cs_ptr_release                 ; J2b-P: a latched press decided by its release
    movzx eax, byte [rel cs_pending]
    mov  byte [rel cs_pending], CS_PEND_NONE
    cmp  eax, CS_PEND_DENY
    je   .deny
    cmp  eax, CS_PEND_CONFIRM
    jne  .done
    mov  byte [rel cs_tab], 0           ; one Tab, one Confirm
    mov  rdi, [rel cs_pid]
    mov  rsi, [rel cs_token]
    call card_confirm                   ; depth 0, the idle loop (srcreview J6 F1)
    jmp  .done
.deny:
    call card_deny
    jmp  .done
.gone:
    call card_cancel                    ; shown with no window: a system cancel
.done:
    pop  rbx
.out:
    ret
.idle:
    mov  byte [rel cs_show], 0
    mov  byte [rel cs_pending], CS_PEND_NONE
    mov  byte [rel cs_ptr], 0               ; J2b-P: no card, or locked: no latch, nothing armed
    mov  dword [rel sp_arm_card_wid], -1
    ret

;; cs_geom_changed(EDI = card slot) -> EAX 1 when the card's rectangle, the
;; screen, or cs_ok_op's answer differs from the last look (then remembered).
;; Clobbers caller-saved registers.
cs_geom_changed:
    push rbx
    mov  ebx, edi
    call cs_ok_op
    lea  rdx, [rel cs_geom_now]
    mov  [rdx + 24], eax
    lea  rcx, [rel wm_x]
    mov  eax, [rcx + rbx*4]
    mov  [rdx], eax
    lea  rcx, [rel wm_y]
    mov  eax, [rcx + rbx*4]
    mov  [rdx + 4], eax
    lea  rcx, [rel wm_w]
    mov  eax, [rcx + rbx*4]
    mov  [rdx + 8], eax
    lea  rcx, [rel wm_h]
    mov  eax, [rcx + rbx*4]
    mov  [rdx + 12], eax
    mov  eax, [rel fb_width]
    mov  [rdx + 16], eax
    mov  eax, [rel fb_height]
    mov  [rdx + 20], eax
    lea  rsi, [rel cs_geom_now]
    lea  rdi, [rel cs_geom]
    xor  ecx, ecx
    xor  eax, eax
.cmp:
    mov  r8d, [rsi + rcx*4]
    cmp  r8d, [rdi + rcx*4]
    je   .same
    mov  [rdi + rcx*4], r8d
    mov  eax, 1
.same:
    inc  ecx
    cmp  ecx, CS_GEOM_N
    jb   .cmp
    pop  rbx
    ret

;; cs_build(): the owed card, built in the tick (tail-jumped from it). A
;; previous card's window never carries new text; a card that cannot be shown
;; is a system cancel, so its proposer is not held for its whole TTL.
cs_build:
    push rbx
    push r12
    mov  byte [rel cs_show], 0
    mov  byte [rel cs_pending], CS_PEND_NONE
    mov  byte [rel cs_tab], 0
    mov  byte [rel cs_ptr], 0
    mov  dword [rel sp_arm_card_wid], -1
    call cs_scan
    cmp  eax, -1
    je   .open
    mov  edi, eax
    call wmx_close_slot
.open:
    mov  byte [rel form_card_loading], 1
    mov  edi, FORM_CARD_INDEX
    xor  edx, edx                       ; never takes the keyboard (C1)
    call form_load_internal
    mov  byte [rel form_card_loading], 0
    test eax, eax
    jnz  .fail
    call cs_scan
    cmp  eax, -1
    je   .fail
    mov  r12d, eax
    lea  rcx, [rel wm_owner]
    mov  qword [rcx + r12*8], WM_OWNER_CHROME   ; P1: no request acts on it, the owner's included
    ; F4 r1 (rc-sec 14:21:20 (3)): a fresh card opens wholly above the taskbar
    ; band, or cs_ok_op would refuse it until the owner dragged it up. The
    ; loader keeps a window on the screen only: at 640x480 and 800x600 the
    ; card's bottom rows open under the taskbar. Nothing is painted yet (the
    ; loader's card seam), so the window and its widgets move without a paint.
    lea  rcx, [rel wm_h]
    mov  edx, [rel fb_height]
    sub  edx, TASKBAR_H
    sub  edx, [rcx + r12*4]             ; the lowest y wholly above the band
    jns  .band_y
    xor  edx, edx                       ; taller than the work area: the top stays visible
.band_y:
    lea  rcx, [rel wm_y]
    mov  eax, [rcx + r12*4]
    cmp  eax, edx
    jle  .placed
    mov  [rcx + r12*4], edx
    sub  edx, eax                       ; dy (up)
    xor  esi, esi
    mov  edi, r12d
    call wgt_shift_window
.placed:
    lea  rcx, [rel wm_w]
    mov  eax, [rcx + r12*4]
    mov  [rel cs_built_w], eax          ; cs_ok_op: Confirm counts only at this size
    lea  rcx, [rel wm_h]
    mov  eax, [rcx + r12*4]
    mov  [rel cs_built_h], eax
    inc  byte [rel wgt_paint_suspended]
    mov  edi, [rel cs_ids + CS_W_WHO*4]
    lea  rsi, [rel cs_str_who]
    call wgt_set_text
    lea  rsi, [rel cs_str_unknown]
    mov  rax, [rel card_verb_id]
    mov  ecx, [rel verb_count]
    cmp  rax, rcx
    jae  .verb
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    mov  rsi, [rcx + rax + VERB_NAME]
.verb:
    mov  edi, [rel cs_ids + CS_W_VERB*4]
    call wgt_set_text
    xor  ebx, ebx                       ; term 1: every byte, WGI_VAL_MAX per row, never re-flowed
.arg_row:
    imul eax, ebx, WGI_VAL_MAX
    mov  ecx, [rel card_args_len]
    sub  ecx, eax
    jg   .some
    xor  ecx, ecx
.some:
    cmp  ecx, WGI_VAL_MAX
    jbe  .fits
    mov  ecx, WGI_VAL_MAX
.fits:
    lea  rsi, [rel card_args]
    add  rsi, rax
    lea  rdi, [rel cs_line]
    rep  movsb
    mov  byte [rdi], 0
    lea  rcx, [rel cs_ids]
    mov  edi, [rcx + rbx*4 + CS_W_ARG0*4]
    lea  rsi, [rel cs_line]
    call wgt_set_text
    inc  ebx
    cmp  ebx, CS_ARG_ROWS
    jb   .arg_row
    mov  edi, [rel cs_ids + CS_W_NOTE*4]
    lea  rsi, [rel cs_str_note]
    call wgt_set_text
    dec  byte [rel wgt_paint_suspended]
    mov  eax, [rel cs_ids + CS_W_DENY*4]
    lea  rcx, [rel wgt_focus_by_win]
    mov  [rcx + r12*4], eax             ; the card's keyboard rests on Deny
    call sp_disarm                      ; J2b-P (rc-input (4)): opened under a resting cursor, every row disarmed
    mov  eax, [rel cs_ids + CS_W_CONFIRM*4]
    mov  [rel sp_arm_card_wid], eax     ; armed like Yes from the next clean HUMAN move
    mov  edi, r12d
    call cs_geom_changed                ; the build is the first look
    call card_rearm                     ; C7: the delay starts at the first paint
    call wmx_draw_all
    jmp  .out
.fail:
    call card_cancel
.out:
    pop  r12
    pop  rbx
    ret

cs_str_who:     db "The AI asks you to run:", 0
cs_str_unknown: db "?", 0
cs_str_note:    db "Tab to Confirm, Enter runs it", 0

align 8
cs_key_prev:    dq 0
cs_click_prev:  dq 0
cs_pid:         dq 0
cs_token:       dq 0
cs_ptr_pid:     dq 0                    ; J2b-P: the authority snapshot at the latched press
cs_ptr_token:   dq 0
cs_ptr_armed:   dq 0                    ; J2b-P (rc-sec P1): card_armed_us at the latched press
cs_ids:         times CS_W_COUNT dd -1
cs_geom:        times CS_GEOM_N dd -1
cs_geom_now:    times CS_GEOM_N dd 0
cs_tab_z:       dd 0
cs_ptr_seq:     dd 0                    ; J2b-P: sp_ptr_up_seq at the latched press
cs_ptr_inj:     dd 0                    ; J2b-P (srcreview F1): sp_ptr_inj_seq at the latched press
cs_built_w:     dd 0                    ; F4 r1: the card window's size at its build
cs_built_h:     dd 0
cs_live:        db 0
cs_show:        db 0
cs_pending:     db 0
cs_tab:         db 0
cs_ptr:         db 0                    ; J2b-P: a HUMAN press on Confirm waits for its release
cs_line:        times WGI_VAL_MAX + 1 db 0
