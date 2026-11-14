;; MODULE gui/wm_pointer
%include "core/abi/build_profile.inc"
;; LAYER 6
;; EXPORTS wm_pointer_origin, wm_pointer_event, wm_pointer_act_ok, wm_pointer_last_btn_inj, wm_pointer_gesture_origin, wm_pointer_init, wm_pointer_wheel, wm_pointer_wheels, wm_pointer_last_intent, wm_pointer_resize_edges
;; IMPORTS gui/calendar, gui/guest_desktop, gui/window, gui/chat_app, gui/window_mgmt, gui/taskbar, gui/widget, gui/widget_scalar_inputs, gui/widget_listview, gui/input_route, gui/widget_tabstrip, gui/widget_console_grid, dev/input/ps2, gui/guardian_indicator
;; CAPS
;; OWNER saga:gui_foundation_ladder

WM_PTR_ORIGIN_HUMAN    equ 0
WM_DBLCLICK_MS         equ 500      ; CHR-07: Windows' default double-click time
WM_DBLCLICK_PX         equ 4        ; ... and its SM_CXDOUBLECLK/2 slop
WM_PTR_ORIGIN_INJECTED equ 1
WM_PTR_ORIGIN_RETIRED  equ 2        ; RCQ-09: a retired device's buttons-up; never HUMAN
WM_PTR_RETIRED         equ (1 << 17) ; RCQ-09: its EDX mark (dev/usb/hid hid_pointer_retire via ps2)
WM_PTR_INTENT_NONE     equ 0
WM_PTR_INTENT_FOCUS    equ 1
WM_PTR_INTENT_MOVE     equ 2
WM_PTR_INTENT_RESIZE   equ 3
WM_PTR_INTENT_MIN      equ 4
WM_PTR_INTENT_MAX      equ 5
WM_PTR_INTENT_CLOSE    equ 6
WM_PTR_INTENT_TASKBAR  equ 7
WM_PTR_INTENT_WIDGET   equ 8
WM_PTR_INTENT_RAISE    equ 9        ; 2026-09-08: body press on a non-scalar widget raised its window
WM_GRIP_PX             equ GUI_CHROME_RESIZE_GRIP ; E10 (theme_tokens.inc); corner resize zone (2026-09-08: was the 8 px bottom-right grip; drawn by the chrome painter)
WM_EDGE_PX             equ GUI_CHROME_RESIZE_BAND ; E10 (theme_tokens.inc); edge resize band inside every window edge (Peter: "drag from any part of the border")
WM_EDGE_L              equ 1
WM_EDGE_R              equ 2
WM_EDGE_T              equ 4
WM_EDGE_B              equ 8

; EDI=slot ESI=x EDX=y -> eax=1 iff point is in the live window.
wm_pointer_inside_slot:
    push rbx
    mov  eax, edi
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rax*4], WM_VISIBLE
    jne  .outside
    lea  rcx, [rel wm_x]
    mov  ebx, [rcx + rax*4]
    cmp  esi, ebx
    jl   .outside
    lea  rcx, [rel wm_w]
    add  ebx, [rcx + rax*4]
    cmp  esi, ebx
    jge  .outside
    lea  rcx, [rel wm_y]
    mov  ebx, [rcx + rax*4]
    cmp  edx, ebx
    jl   .outside
    lea  rcx, [rel wm_h]
    add  ebx, [rcx + rax*4]
    cmp  edx, ebx
    jge  .outside
    mov  eax, 1
    pop  rbx
    ret
.outside:
    xor  eax, eax
    pop  rbx
    ret

; EDI=x ESI=y -> eax=slot or -1: the window the user sees at the point, in
;   wmx_draw_all's paint order. The focused window is painted last, so it wins
;   whenever it contains the point; otherwise the highest z stamp wins (ties:
;   the higher slot, painted later). RCQ-16 S4 F5 (root 15:47:57): an
;   agent-opened window takes the top stamp without focus (form_loader), and a
;   stamp-only hit test sent the user's click on the focused window to it.
wm_pointer_top_slot:
    call calendar_hit                  ; shell panel covers every window here
    test eax, eax
    jz   .calendar_clear
    mov  eax, -1
    ret
.calendar_clear:
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  eax, [rel wm_focus]
    cmp  eax, WM_MAX
    jae  .by_stamp                      ; no focused window
    mov  edi, eax
    mov  esi, r12d
    mov  edx, r13d
    push rax
    call wm_pointer_inside_slot         ; refuses a non-visible slot
    mov  ecx, eax
    pop  rax
    test ecx, ecx
    jz   .by_stamp
    mov  r14d, eax                      ; painted last: on top wherever it is
    jmp  .top_out
.by_stamp:
    ; 2026-09-08 real z-order: of the visible windows under the point, the highest z stamp wins
    ; (ties: the higher slot). wm_pointer_inside_slot already refuses non-visible slots.
    mov  r14d, -1                       ; best slot
    xor  r15d, r15d                     ; best stamp
    mov  eax, WM_MAX - 1
.scan_loop:
    cmp  eax, -1
    je   .top_out
    mov  edi, eax
    mov  esi, r12d
    mov  edx, r13d
    push rax
    call wm_pointer_inside_slot
    mov  ecx, eax
    pop  rax
    test ecx, ecx
    jz   .scan_next
    lea  rcx, [rel wm_zstamp]
    mov  ecx, [rcx + rax*4]
    cmp  r14d, -1
    je   .take
    cmp  ecx, r15d
    jbe  .scan_next
.take:
    mov  r15d, ecx
    mov  r14d, eax
.scan_next:
    dec  eax
    jmp  .scan_loop
.top_out:
    mov  eax, r14d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; wm_pointer_edge_zone(EDI=slot, ESI=x, EDX=y) -> EAX = edge flags (WM_EDGE_L/R/T/B), 0 = not
; on a border. Edges: a WM_EDGE_PX band inside each side. Corners: within WM_GRIP_PX of two
; sides (the drawn bottom-right grip included) -> both flags. Clobbers RCX, RDI.
wm_pointer_edge_zone:
    push rbx
    push r8
    push r9
    mov  eax, edi
    lea  rcx, [rel wm_x]
    mov  r8d, [rcx + rax*4]             ; left
    lea  rcx, [rel wm_w]
    mov  ecx, [rcx + rax*4]
    add  ecx, r8d                       ; right (exclusive)
    lea  rbx, [rel wm_y]
    mov  r9d, [rbx + rax*4]             ; top
    lea  rbx, [rel wm_h]
    mov  ebx, [rbx + rax*4]
    add  ebx, r9d                       ; bottom (exclusive)
    xor  eax, eax
    mov  edi, r8d
    add  edi, WM_EDGE_PX
    cmp  esi, edi
    jge  .ez_not_l
    or   eax, WM_EDGE_L
.ez_not_l:
    mov  edi, ecx
    sub  edi, WM_EDGE_PX
    cmp  esi, edi
    jl   .ez_not_r
    or   eax, WM_EDGE_R
.ez_not_r:
    mov  edi, r9d
    add  edi, WM_EDGE_PX
    cmp  edx, edi
    jge  .ez_not_t
    or   eax, WM_EDGE_T
.ez_not_t:
    mov  edi, ebx
    sub  edi, WM_EDGE_PX
    cmp  edx, edi
    jl   .ez_not_b
    or   eax, WM_EDGE_B
.ez_not_b:
    ; corner bands (WM_GRIP_PX): near-left 0x10, near-right 0x20, near-top 0x40, near-bottom 0x80
    mov  edi, r8d
    add  edi, WM_GRIP_PX
    cmp  esi, edi
    jge  .ez_no_nl
    or   eax, 0x10
.ez_no_nl:
    mov  edi, ecx
    sub  edi, WM_GRIP_PX
    cmp  esi, edi
    jl   .ez_no_nr
    or   eax, 0x20
.ez_no_nr:
    mov  edi, r9d
    add  edi, WM_GRIP_PX
    cmp  edx, edi
    jge  .ez_no_nt
    or   eax, 0x40
.ez_no_nt:
    mov  edi, ebx
    sub  edi, WM_GRIP_PX
    cmp  edx, edi
    jl   .ez_no_nb
    or   eax, 0x80
.ez_no_nb:
    mov  edi, eax
    and  edi, 0x30
    jz   .ez_strip
    mov  ebx, eax
    and  ebx, 0xC0
    jz   .ez_strip
    shr  edi, 4                         ; 0x10 -> L, 0x20 -> R
    or   eax, edi
    shr  ebx, 4                         ; 0x40 -> T, 0x80 -> B
    or   eax, ebx
.ez_strip:
    and  eax, 0x0F
    pop  r9
    pop  r8
    pop  rbx
    ret

; wm_pointer_shape_for_edges(EDI=edge flags) -> EAX = GUI_CURSOR_* for that border.
wm_pointer_shape_for_edges:
    mov  eax, edi
    cmp  eax, WM_EDGE_L | WM_EDGE_T
    je   .sh_diag
    cmp  eax, WM_EDGE_R | WM_EDGE_B
    je   .sh_diag
    cmp  eax, WM_EDGE_R | WM_EDGE_T
    je   .sh_diag2
    cmp  eax, WM_EDGE_L | WM_EDGE_B
    je   .sh_diag2
    test eax, WM_EDGE_L | WM_EDGE_R
    jnz  .sh_h
    test eax, WM_EDGE_T | WM_EDGE_B
    jnz  .sh_v
    mov  eax, GUI_CURSOR_ARROW
    ret
.sh_diag:
    mov  eax, GUI_CURSOR_RESIZE
    ret
.sh_diag2:
    mov  eax, GUI_CURSOR_RESIZE2
    ret
.sh_h:
    mov  eax, GUI_CURSOR_HRESIZE
    ret
.sh_v:
    mov  eax, GUI_CURSOR_VRESIZE
    ret

; wm_pointer_grip_hit(EDI=slot, ESI=x, EDX=y) -> EAX=1 iff the point is in the slot's
; bottom-right WM_GRIP_PX x WM_GRIP_PX resize grip. (Kept for callers/probes; the dispatcher
; uses wm_pointer_edge_zone.)
wm_pointer_grip_hit:
    mov  eax, edi
    lea  rcx, [rel wm_x]
    mov  ecx, [rcx + rax*4]
    lea  rdi, [rel wm_w]
    add  ecx, [rdi + rax*4]
    sub  ecx, WM_GRIP_PX
    cmp  esi, ecx
    jl   .no
    lea  rcx, [rel wm_y]
    mov  ecx, [rcx + rax*4]
    lea  rdi, [rel wm_h]
    add  ecx, [rdi + rax*4]
    sub  ecx, WM_GRIP_PX
    cmp  edx, ecx
    jl   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; EDI=x ESI=y EDX=button mask ECX=origin -> EAX=intent tag.
; SEC-winmove-no-owner-check (B) (root 14:41:32 / 14:44:22, rc-sec 14:41:46 (4)):
; wm_pointer_act_ok(EDI=slot) -> EAX 0 = this event may take a window-management
; action (move, resize, max/restore, minimize, close) on the slot, -1 = refused.
; A HUMAN event (IRQ12/USB/I2C) always may. An INJECTED one (MOUSEINJ/PTRINJ)
; needs the in-flight frame principal's right to the slot (wmx_req_may_act:
; chrome never, the owner any other slot, another principal only its own).
; Asked at the press that would start a gesture AND per event at every action
; call. Clobbers RAX only.
wm_pointer_act_ok:
    xor  eax, eax
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    je   .out
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  esi, edi
    xor  edi, edi                       ; the in-flight frame (the injector's ticket or request)
    call wmx_req_may_act
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
.out:
    ret

; Press/motion/release from both IRQ12 and MOUSEINJ enter here.
wm_pointer_event:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi                      ; x
    mov  r13d, esi                      ; y
    mov  r14d, edx                      ; buttons
    and  r14d, ~WM_PTR_RETIRED          ; RCQ-09: the mark is no button
    mov  byte [rel wm_pointer_retire], 0
    cmp  cl, WM_PTR_ORIGIN_HUMAN
    jne  .retire_noted                  ; RCQ-09: only the native ring's own events
    test edx, WM_PTR_RETIRED
    jz   .retire_noted
    mov  byte [rel wm_pointer_retire], 1
    mov  cl, WM_PTR_ORIGIN_RETIRED      ; the device left: no hand made this event
.retire_noted:
    mov  [rel wm_pointer_origin], cl
    cmp  cl, WM_PTR_ORIGIN_HUMAN
    jne  .marks_kept
    call wmx_clear_boot_marks           ; 2026-09-08: the first human pointer event retires the boot proofs
.marks_kept:
    mov  edi, r12d                      ; SEC-GA0: the Guardian cell's pointer provenance sees EVERY event
    mov  esi, r13d
%if !PAOS_PUBLIC_BUILD
    call guardian_indicator_pointer_note
%endif
    call lock_screen_focus_assert       ; RCQ-16 F2b-1: under the lock only the form is left to hit
    mov  rax, [rel wm_pointer_note_hook] ; SEC R1 F1: gui/start_programs' confirm arm sees EVERY event too
    test rax, rax
    jz   .noted
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d                      ; RCQ-40 J2b-P: the buttons (wm_pointer_last_btn is still the previous)
    call rax
.noted:
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_NONE
    ; Out-of-framebuffer points are observable no-ops.
    cmp  r12d, [rel fb_width]
    jae  .finish
    cmp  r13d, [rel fb_height]
    jae  .finish
    test r12d, r12d
    js   .finish
    test r13d, r13d
    js   .finish
    ; SEC-winmove (C2) (rc-sec 15:20:04): one previous-button state per origin. A HUMAN
    ; event edges against the human stream, an injected one against its own, and an
    ; injected event never writes the human stream (else an injected UP turns the
    ; human's next held event into a press edge the human never made).
    cmp  byte [rel wm_pointer_retire], 0
    jne  .human_stream                  ; RCQ-09: a retirement ends the human stream's buttons
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .inj_stream
.human_stream:
    mov  ebx, [rel wm_pointer_last_btn]
    mov  [rel wm_pointer_last_btn], r14d
    jmp  .stream_set
.inj_stream:
    mov  ebx, [rel wm_pointer_last_btn_inj]
    mov  [rel wm_pointer_last_btn_inj], r14d
.stream_set:
    cmp  byte [rel wm_pointer_retire], 0
    jne  .retired
    ; Gesture ownership: while a gesture holds (mode != 0) only the origin that
    ; started it drives it. An other-origin event is consumed: no mode change, no
    ; release, no hover. Except that the HUMAN wins: a HUMAN press edge ends an
    ; injected gesture first (.gesture_end), then runs as an ordinary press.
    cmp  byte [rel wm_pointer_mode], 0
    je   .owned
    movzx eax, byte [rel wm_pointer_origin]
    cmp  al, [rel wm_pointer_gesture_origin]
    je   .owned
    cmp  al, WM_PTR_ORIGIN_HUMAN
    jne  .finish                        ; injected, during a HUMAN gesture
    mov  eax, ebx
    not  eax
    and  eax, r14d
    test eax, 7
    jz   .finish                        ; HUMAN, during an injected gesture, no press edge
    call .gesture_end
.owned:
    movzx eax, byte [rel wm_pointer_origin]
    mov  [rel wm_pointer_gesture_origin], al ; any gesture this event starts or continues is its origin's
    mov  edi, r12d                      ; RCQ-23: a captured guest consumes its own events
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, ebx                       ; previous buttons of this event's own stream: no phantom edge either way
    call guest_desktop_pointer
    test eax, eax
    jnz  .finish
    ; RCQ-16 F1: any button's press edge ends keyboard focus-visible modality,
    ; whatever it lands on (control, title bar, taskbar, desktop). A ring already
    ; on screen goes with the press: the focused widget repaints without it.
    mov  eax, ebx
    not  eax
    and  eax, r14d
    test eax, 7
    jz   .fv_kept
    cmp  byte [rel wgt_focus_visible], 0
    je   .fv_kept
    mov  byte [rel wgt_focus_visible], 0
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  edi, [rel wgt_focus_id]
    cmp  edi, -1
    je   .fv_restore
    call wgt_draw_id
.fv_restore:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.fv_kept:
    ; G11 (2026-10-01, usage suite TAB-07): a middle-button press edge with the
    ; left button up all along is its own gesture (a middle click on a tab
    ; closes it); it never starts a left-button press/drag.
    ; RCQ-22: middle and right gestures may instead be captured by a widget
    ; whose type opted in (the Terminal's xterm mouse reporting); mode 6 holds
    ; such a capture. Any left involvement ends it and runs the left machine.
    mov  eax, r14d
    or   eax, ebx
    test eax, 1
    jnz  .left_involved
    cmp  byte [rel wm_pointer_mode], 6
    je   .other_held
    test r14d, 4
    jz   .no_middle_edge
    test ebx, 4
    jz   .middle_press
.no_middle_edge:
    test r14d, 2
    jz   .left_machine
    test ebx, 2
    jz   .right_press
    jmp  .left_machine
.left_involved:
    cmp  byte [rel wm_pointer_mode], 6
    jne  .left_machine
    call .other_end                     ; the left button takes over: the held one is released
.left_machine:
    test ebx, 1
    jz   .was_up
    test r14d, 1
    jz   .release
    jmp  .drag
.was_up:
    test r14d, 1
    jz   .hover
    jmp  .press
.release:
    mov  edi, -1
    call wgt_press_set                  ; RCQ-16 S4: any left release ends the pressed paint
    cmp  byte [rel wm_pointer_mode], 4
    je   .release_caption
    cmp  byte [rel wm_pointer_mode], 5
    je   .release_typed
    cmp  byte [rel wm_pointer_mode], 3
    jne  .release_clear
    mov  edi, [rel wm_pointer_widget_id]
    call wgt_scalar_pointer_release
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
.release_clear:
    mov  byte [rel wm_pointer_mode], 0
    mov  byte [rel gui_cursor_shape], GUI_CURSOR_ARROW
    jmp  .finish
.release_typed:
    ; the captured widget gets its release at the pointer; a stale capture
    ; (widget retired or its id reused) is dropped by the kit, not delivered
    mov  esi, r12d
    mov  edx, r13d
    mov  ecx, WGT_CAPTURE_RELEASE
    call wgt_pointer_capture_event
    test eax, eax
    jz   .release_clear
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .release_clear
.release_caption:
    ; 2026-09-30 (usage suite CHR-02/CHR-03, F-PRESSFIRES): a caption action
    ; fires on RELEASE, and only when the release lands inside the SAME button
    ; of the SAME (still live) window that took the press -- press, drag off,
    ; release is a cancel (Windows). The hover is dropped before the action so
    ; its repaint never shows a stale highlight, then re-derived at the release
    ; point (.hover).
    mov  byte [rel wm_pointer_mode], 0
    mov  byte [rel gui_cursor_shape], GUI_CURSOR_ARROW
    mov  r15d, [rel wm_pointer_slot]
    cmp  r15d, WM_MAX
    jae  .hover
    lea  rax, [rel wm_state]
    cmp  dword [rax + r15*4], WM_VISIBLE
    jne  .hover
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wmx_caption_part_at
    movzx ecx, byte [rel wm_pointer_caption_part]
    cmp  eax, ecx
    jne  .hover
    push rax
    mov  edi, -1
    xor  esi, esi
    call wmx_hover_update
    pop  rax
    cmp  eax, WMX_PART_CLOSE
    je   .do_close
    cmp  eax, WMX_PART_MAX
    je   .do_max
    cmp  eax, WMX_PART_MIN
    je   .do_min
    jmp  .hover

.press:
    mov  edi, r12d
    mov  esi, r13d
    call calendar_pointer_press         ; panel or outside-close consumes this press
    test eax, eax
    jz   .calendar_done
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.calendar_done:
    call wm_pointer_count_click         ; CHR-07: 1/2/3 = single/double/triple press
    mov  eax, [rel wm_click_title_slot] ; CHR-07: the slot whose title band took the previous press
    mov  [rel wm_click_prev_title], eax
    mov  dword [rel wm_click_title_slot], -1
    mov  byte [rel input_win_chord], 1  ; UI wave 2 B10: Win+click cancels the Start tap
    mov  edi, r12d
    mov  esi, r13d
    call wgt_menu_dismiss_outside       ; D2 flyouts close on an outside press
    mov  edi, r12d
    mov  esi, r13d
    call summon_palette_pointer_press
    test eax, eax
    jz   .dropdown_press
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.dropdown_press:
    ; A declared popup can escape its host rectangle, so it owns the press
    ; before ordinary window/chrome hit-testing. Outside-close is consumed and
    ; cannot synthesize a click in the newly exposed surface underneath.
    mov  edi, r12d
    mov  esi, r13d
    call wgt_listview_dropdown_press
    test eax, eax
    jz   .ime_popup_press
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.ime_popup_press:
    ; RCQ-38 I3b-1 (c): the IME candidate window is painted above every window and takes no input in RC, so a press
    ; on it is consumed by the same rule: no pick, and no click on the surface it covers.
    mov  edi, r12d
    mov  esi, r13d
    call ime_popup_hit
    test eax, eax
    jz   .taskbar_press
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_NONE
    jmp  .finish
.taskbar_press:
    ; Taskbar is outside every window and consumes the same press edge.
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    cmp  r13d, eax
    jb   .menu_press
    mov  edi, r12d
    mov  esi, r13d
    call taskbar_pointer_press
    test eax, eax
    jz   .finish
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_TASKBAR
    jmp  .finish

.middle_press:
    call calendar_other_press
    test eax, eax
    jnz  .popup_other
    mov  edi, r12d
    mov  esi, r13d
    call wgt_menu_dismiss_outside       ; any press outside an open flyout closes it
    mov  edi, r12d
    mov  esi, r13d
    call ime_popup_hit                  ; RCQ-38 I3b-1 (c) SRC-I3B1C-01: the IME window covers it, as a left press
    test eax, eax
    jnz  .popup_other
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    cmp  r13d, eax
    jae  .finish                        ; the taskbar takes no middle gesture
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    cmp  eax, -1
    je   .finish
    mov  r15d, eax
    lea  rax, [rel wm_y]
    mov  eax, [rax + r15*4]
    add  eax, GUI_TITLE_H
    cmp  r13d, eax
    jge  .middle_body                   ; only the title band's tabs; the body may capture it
    lea  rax, [rel wm_chrome]
    cmp  byte [rax + r15], WM_CHROME_TABS
    jne  .finish
    mov  dword [rel ts_close_request], -1
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wgt_tabstrip_middle
    test eax, eax
    jz   .finish
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    mov  eax, [rel ts_close_request]
    mov  dword [rel ts_close_request], -1
    cmp  eax, r15d
    jne  .finish
    mov  edi, -1                        ; its last tab: the window closes (as the tab's x)
    xor  esi, esi
    call wmx_hover_update
    jmp  .do_close
.middle_body:
    mov  ecx, 1                         ; xterm/SGR button 1
    call .other_press
    jmp  .finish

.right_press:
    call calendar_other_press
    test eax, eax
    jnz  .popup_other
    ; A right press on a painted native flyout keeps its current target and
    ; cannot reach a capture-bound control covered by that overlay.
    mov  edi, r12d
    mov  esi, r13d
    call wgt_menu_shown_at
    test eax, eax
    jnz  .popup_other
    ; RCQ-22: a right press goes only to a capture-bound widget under it that
    ; takes the button; otherwise it stays a hover (no drag, focus or raise).
    mov  edi, r12d
    mov  esi, r13d
    call ime_popup_hit                  ; RCQ-38 I3b-1 (c) SRC-I3B1C-01: none through the IME window
    test eax, eax
    jnz  .popup_other
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    cmp  r13d, eax
    jae  .hover
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    cmp  eax, -1
    je   .hover
    mov  r15d, eax
    lea  rax, [rel wm_y]
    mov  eax, [rax + r15*4]
    add  eax, GUI_TITLE_H
    cmp  r13d, eax
    jl   .hover                         ; the title band is chrome
    mov  ecx, 2                         ; xterm/SGR button 2
    call .other_press
    test eax, eax
    jz   .hover
    jmp  .finish

.popup_other:
    ; a middle or right press on the IME window is consumed like a left one: nothing under it sees the button
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_NONE
    jmp  .finish

.other_held:
    ; mode 6: motion with the captured middle/right button held, or its release
    movzx eax, byte [rel wm_pointer_other_mask]
    test r14d, eax
    jz   .other_release
    mov  esi, r12d
    mov  edx, r13d
    mov  ecx, WGT_CAPTURE_DRAG
    call wgt_pointer_capture_event
    test eax, eax
    jz   .other_lost
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.other_lost:
    mov  byte [rel wm_pointer_mode], 0  ; the captured widget is gone: the gesture ends here
    jmp  .finish
.other_release:
    call .other_end
    jmp  .finish

; .other_press: R15D = window slot under (R12D, R13D) in its body, ECX = xterm
; button (1 middle, 2 right) -> EAX 1 when a widget there captured the press.
; No raise, no focus, no WM drag: an unclaimed press changes nothing.
.other_press:
    push rcx
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_capture_find       ; opted-in capture types only; never the left-click hook
    pop  rcx
    test eax, eax
    jz   .other_none
    dec  eax                            ; the kit tracks the captured id itself
    push rcx
    mov  edi, eax
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_capture_press_button
    pop  rcx
    test eax, eax
    jz   .other_none
    mov  byte [rel wm_pointer_mode], 6
    mov  eax, 2                         ; mask of the held button: right 2, middle 4
    cmp  ecx, 2
    je   .other_mask
    mov  eax, 4
.other_mask:
    mov  [rel wm_pointer_other_mask], al
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    mov  eax, 1
    ret
.other_none:
    xor  eax, eax
    ret

; .other_end: deliver the release of a held middle/right capture at the pointer.
.other_end:
    mov  esi, r12d
    mov  edx, r13d
    mov  ecx, WGT_CAPTURE_RELEASE
    call wgt_pointer_capture_event
    test eax, eax
    jz   .other_ended
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
.other_ended:
    mov  byte [rel wm_pointer_mode], 0
    mov  byte [rel wm_pointer_other_mask], 0
    ret

; .gesture_end (SEC-winmove (C2), rc-sec 15:20:04 (3)): a HUMAN press edge ends an
; INJECTED gesture before it runs, as the left button takes over a held
; middle/right capture (.other_end). Nothing fires: a move/resize just stops, a
; caption capture is a cancel, a widget or typed capture gets its release at the
; pointer, delivered under the gesture's (injected) origin. Preserves RBX, R12-R15.
.gesture_end:
    ; rc-sec 15:53:40: the injected gesture ends under ITS OWN origin, so a
    ; release-side consumer that tests wm_pointer_origin never takes the
    ; injector's finish for a HUMAN act; the HUMAN origin is back before the
    ; HUMAN press runs.
    movzx eax, byte [rel wm_pointer_origin]
    push rax
    movzx eax, byte [rel wm_pointer_gesture_origin]
    mov  [rel wm_pointer_origin], al
    cmp  byte [rel wm_pointer_mode], 6
    jne  .gesture_end_kit
    call .other_end
    jmp  .gesture_end_out
.gesture_end_kit:
    mov  edi, -1
    call wgt_press_set
    cmp  byte [rel wm_pointer_mode], 3
    jne  .gesture_end_typed
    mov  edi, [rel wm_pointer_widget_id]
    call wgt_scalar_pointer_release
    jmp  .gesture_ended
.gesture_end_typed:
    cmp  byte [rel wm_pointer_mode], 5
    jne  .gesture_ended
    mov  esi, r12d
    mov  edx, r13d
    mov  ecx, WGT_CAPTURE_RELEASE
    call wgt_pointer_capture_event
.gesture_ended:
    mov  byte [rel wm_pointer_mode], 0
    mov  byte [rel gui_cursor_shape], GUI_CURSOR_ARROW
.gesture_end_out:
    pop  rax
    mov  [rel wm_pointer_origin], al    ; the current (HUMAN) event's origin again
    ret

; .retired (RCQ-09, root 13:30:07): a device left with buttons held. They are
; up, but no hand released them. The held gesture whose button went up ends as
; .gesture_end ends an injected one (a caption press is a cancel, a move or
; resize stops, a capture gets its release at the pointer), under
; WM_PTR_ORIGIN_RETIRED, so no release-side consumer takes it for a HUMAN act;
; nothing fires. A button a peer device still holds keeps its gesture, and an
; injected gesture is not this device's to end.
.retired:
    mov  eax, r14d
    not  eax
    and  eax, ebx                       ; the buttons this retirement released
    test eax, 1
    jz   .retired_gesture
    push rax
    mov  edi, -1
    call wgt_press_set                  ; the pressed paint ends with the left button
    pop  rax
.retired_gesture:
    cmp  byte [rel wm_pointer_mode], 0
    je   .finish
    cmp  byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne  .finish
    movzx ecx, byte [rel wm_pointer_other_mask]
    cmp  byte [rel wm_pointer_mode], 6
    je   .retired_mask
    mov  ecx, 1                         ; modes 1..5 hold the left button
.retired_mask:
    test eax, ecx
    jz   .finish                        ; a peer device still holds it
    mov  byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_RETIRED
    call .gesture_end
    jmp  .finish

.menu_press:
    ; RCQ-16 F5-R1: an open flyout is painted above every window (the overlay
    ; pass) and under the taskbar, so above the band it owns the press before
    ; the window hit test. One that is not painted (another window's: root
    ; 18:14:29) takes nothing, and the press reaches the window the user sees.
    mov  edi, r12d
    mov  esi, r13d
    call wgt_menu_overlay_press
    test eax, eax
    jz   .window_press
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.window_press:
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    cmp  eax, -1
    je   .desktop_press
    mov  r15d, eax                      ; slot
    ; Common geometry.
    lea  rcx, [rel wm_x]
    mov  eax, [rcx + r15*4]
    mov  [rel wm_pointer_orig_x], eax
    lea  rcx, [rel wm_y]
    mov  eax, [rcx + r15*4]
    mov  [rel wm_pointer_orig_y], eax
    lea  rcx, [rel wm_w]
    mov  eax, [rcx + r15*4]
    mov  [rel wm_pointer_orig_w], eax
    lea  rcx, [rel wm_h]
    mov  eax, [rcx + r15*4]
    mov  [rel wm_pointer_orig_h], eax
    mov  [rel wm_pointer_slot], r15d
    mov  [rel wm_pointer_start_x], r12d
    mov  [rel wm_pointer_start_y], r13d

    ; UI wave 2 B1: the caption buttons own their exact rectangles before any
    ; resize band -- one rule shared with the hover (wmx_caption_part_at), so a
    ; press on the red-hovered close always closes. The NE diagonal resize is
    ; left on the 1 px frame row and the rightmost column only (Windows 11).
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wmx_caption_part_at
    test eax, eax
    jnz  .caption_press
    lea  rax, [rel wm_maximized]
    cmp  byte [rax + r15], 1
    je   .current_chrome                ; a maximized window has no resize border
    lea  rax, [rel wm_resizable]
    cmp  byte [rax + r15], 0
    je   .current_chrome                ; B4: a resizable=0 form has no resize border
    ; Any edge or corner owns resize before the title/body (2026-09-08, Peter: "drag from
    ; any part of the outer window border"): the pressed edges follow the pointer, the
    ; others stay anchored.
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wm_pointer_edge_zone
    test eax, eax
    jz   .current_chrome
    mov  ecx, eax
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): an injected press starts no resize it may not do
    test eax, eax
    jnz  .finish
    mov  eax, ecx
    mov  [rel wm_pointer_resize_edges], al
    mov  byte [rel wm_pointer_mode], 2
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_RESIZE
    mov  edi, eax
    call wm_pointer_shape_for_edges
    mov  [rel gui_cursor_shape], al
    mov  edi, r15d
    call wmx_raise_slot
    jmp  .finish

.desktop_press:
    ; No window here: only what lies on the wallpaper can take it (the launcher entry).
    mov  edi, WGT_HOST_DESKTOP
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_hit_dispatch
    test eax, eax
    jz   .finish
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish

.current_chrome:
    ; UI wave 2 B2: no saved pre-maximize hot rectangle any more -- after the
    ; geometry expansion the old maximize button lies in the body and a press
    ; there belongs to the body (widgets), never to RESTORE.
    mov  eax, [rel wm_pointer_orig_y]
    add  eax, GUI_TITLE_H
    cmp  r13d, eax
    jge  .body
    ; The rest of the title strip is the drag target (chrome=tabs: after the
    ; tab-strip parts).
    jmp  .title_drag
.caption_press:
    ; F-PRESSFIRES: the press only captures the button (mode 4); .release_caption
    ; fires it. The pressed button keeps its hover fill while the pointer stays on it.
    mov  ecx, eax
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): no capture a later release could fire for it
    test eax, eax
    jnz  .finish
    mov  eax, ecx
    mov  [rel wm_pointer_caption_part], al
    mov  byte [rel wm_pointer_mode], 4
    jmp  .finish
.do_close:
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): per event, at the action
    test eax, eax
    jnz  .hover
    mov  edi, r15d
    call wmx_close_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_CLOSE
    jmp  .hover
.do_max:
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): per event, at the action
    test eax, eax
    jnz  .hover
    mov  edi, r15d
    call wmx_toggle_max_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_MAX
    jmp  .hover
.do_min:
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): per event, at the action
    test eax, eax
    jnz  .hover
    mov  edi, r15d
    call wmx_minimize_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_MIN
    jmp  .hover
.title_drag:
    ; chrome=tabs: interactive tab-strip parts own their pixels in the title
    ; band; everything else in the band stays the drag area.
    lea  rax, [rel wm_chrome]
    cmp  byte [rax + r15], WM_CHROME_TABS
    jne  .title_drag_go
    mov  dword [rel ts_close_request], -1
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_hit_dispatch
    test eax, eax
    jz   .title_drag_go
    ; B6d (2026-09-30, usage suite TAB-04): the tab strip asked to close its
    ; window (its last tab was closed) -- same path as the caption close.
    mov  eax, [rel ts_close_request]
    mov  dword [rel ts_close_request], -1
    cmp  eax, r15d
    jne  .title_widget
    mov  edi, -1
    xor  esi, esi
    call wmx_hover_update
    jmp  .do_close
.title_widget:
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    mov  edi, r15d
    call wmx_raise_slot
    jmp  .finish
.title_drag_go:
    ; CHR-07 (2026-09-30, usage suite; G11 double-click): a double-click on the
    ; title band toggles maximize/restore (Windows). The MSI tree's rule and
    ; names (wm_pointer_count_click, WM_DBLCLICK_MS/PX) so the unified WM keeps
    ; one implementation; tab-strip parts consumed the press above.
    ; Both presses must land on the SAME window's title band: the second click
    ; of a maximize-button click lands on the band of the now-maximized window
    ; and must not restore it (UI wave 2 B2 / P-A s2_max).
    cmp  dword [rel wm_pointer_clicks], 2
    jne  .title_single
    cmp  [rel wm_click_prev_title], r15d
    jne  .title_single
    mov  dword [rel wm_pointer_clicks], 0
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): per event, at the action
    test eax, eax
    jnz  .finish
    mov  edi, r15d
    call wmx_toggle_max_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_MAX
    jmp  .finish
.title_single:
    mov  [rel wm_click_title_slot], r15d
    ; M-MAXDRAG (2026-10-02, MSI spoke 0013 MWN-01; ADMIN 03:5x): a maximized
    ; window stays put. Its title band is not a move handle (the move kept the
    ; maximized size and pushed the caption buttons off screen); the press only
    ; raises it. Double-click (above) and the maximize button still restore it.
    lea  rax, [rel wm_maximized]
    cmp  byte [rax + r15], 1
    jne  .title_move
    mov  edi, r15d
    call wmx_raise_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_RAISE
    jmp  .finish
.title_move:
    mov  edi, r15d
    call wm_pointer_act_ok              ; SEC-winmove (B): an injected press starts no move it may not do
    test eax, eax
    jnz  .finish
    mov  byte [rel wm_pointer_mode], 1
    mov  byte [rel gui_cursor_shape], GUI_CURSOR_MOVE
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_MOVE
    mov  edi, r15d
    call wmx_raise_slot
    jmp  .finish
.body:
    ; A real widget hit must first pass its registered WT_HIT callback; only a
    ; consumed scalar hit enters widget capture mode. Empty body space raises an
    ; unfocused window (.body_empty) and is a strict no-op on the focused one.
    mov  edi, r15d
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_hit_dispatch
    test eax, eax
    jz   .body_empty
    dec  eax
    mov  [rel wm_pointer_widget_id], eax
    mov  edi, eax
    call wgt_press_set                  ; RCQ-16 S4: pressed paint until the release (never focus)
    mov  edi, [rel wm_pointer_widget_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_listview_pointer_press
    test eax, eax
    jnz  .dropdown_consumed
    mov  edi, [rel wm_pointer_widget_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_scalar_pointer_press
    test eax, eax
    jz   .typed_capture
    mov  byte [rel wm_pointer_mode], 3
    mov  edi, r15d
    call wmx_raise_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.typed_capture:
    ; 2026-10-06: a type that bound a pointer capture (wgt_type_bind_capture;
    ; the Terminal's selection) owns this press and its drag and release
    ; (mode 5). Unbound types decline and keep the raise/focus rule below.
    mov  edi, [rel wm_pointer_widget_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_capture_press
    test eax, eax
    jz   .body_not_consumed
    mov  byte [rel wm_pointer_mode], 5
    mov  edi, r15d
    call wmx_raise_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.dropdown_consumed:
    mov  dword [rel wm_pointer_widget_id], -1
    mov  edi, r15d
    call wmx_raise_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.body_empty:
    ; --- 2026-09-08 (Peter: "clicking some parts of an obscured window does not bring it
    ;     into focus"): empty body space RAISES an unfocused window (GUI_FOUNDATION
    ;     click-to-raise) and nothing else: no widget intent, no capture, no widget-tree
    ;     change. On the focused window the press stays a strict no-op (Task3367). ---
    cmp  r15d, [rel wm_focus]
    je   .finish
    mov  edi, r15d
    call wmx_raise_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_RAISE
    jmp  .finish
.body_not_consumed:
    ; --- 2026-09-08 (Peter: "click a window to highlight it", "cannot type anywhere"):
    ;     a press on a non-scalar widget RAISES its window (GUI_FOUNDATION click-to-raise);
    ;     a textfield hit also takes keyboard focus (the caller runs wgt_focus_at on
    ;     INTENT_FOCUS). Empty body space stays a strict no-op (Task3367). ---
    mov  eax, [rel wm_pointer_widget_id]
    mov  [rel wm_pointer_hit_id], eax
    mov  dword [rel wm_pointer_widget_id], -1
    mov  edi, r15d
    call wmx_raise_slot
    mov  edi, [rel wm_pointer_hit_id]
    call wgt_type_name_of
    test rax, rax
    jz   .raise_only
    lea  rsi, [rel str_wmp_textfield]
.tf_cmp:
    mov  cl, [rax]
    cmp  cl, [rsi]
    jne  .raise_only
    test cl, cl
    jz   .textfield_hit
    inc  rax
    inc  rsi
    jmp  .tf_cmp
.textfield_hit:
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_FOCUS
    jmp  .finish
.raise_only:
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_RAISE
    jmp  .finish

.drag:
    movzx eax, byte [rel wm_pointer_mode]
    cmp  eax, 1
    je   .drag_move
    cmp  eax, 2
    je   .drag_resize
    cmp  eax, 3
    je   .drag_widget
    cmp  eax, 4
    je   .drag_caption
    cmp  eax, 5
    je   .drag_typed
    jmp  .finish
.drag_typed:
    mov  esi, r12d
    mov  edx, r13d
    mov  ecx, WGT_CAPTURE_DRAG
    call wgt_pointer_capture_event
    test eax, eax
    jz   .drag_typed_lost
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
    jmp  .finish
.drag_typed_lost:
    mov  byte [rel wm_pointer_mode], 0  ; the captured widget is gone: the gesture ends here
    jmp  .finish
.drag_caption:
    ; the captured button shows its hover only while the pointer is on it
    mov  edi, [rel wm_pointer_slot]
    mov  esi, r12d
    mov  edx, r13d
    call wmx_caption_part_at
    movzx ecx, byte [rel wm_pointer_caption_part]
    mov  edi, [rel wm_pointer_slot]
    mov  esi, ecx
    cmp  eax, ecx
    je   .drag_caption_set
    mov  edi, -1
    xor  esi, esi
.drag_caption_set:
    call wmx_hover_update
    test eax, eax
    jz   .finish
    call wmx_draw_all
    jmp  .finish
.drag_move:
    ; SEC-winmove (B): per event. A refused event is consumed and the capture
    ; kept, so injected motion neither steers nor ends a HUMAN drag.
    mov  edi, [rel wm_pointer_slot]
    call wm_pointer_act_ok
    test eax, eax
    jnz  .finish
    mov  edi, [rel wm_pointer_slot]
    mov  esi, r12d
    sub  esi, [rel wm_pointer_start_x]
    add  esi, [rel wm_pointer_orig_x]
    mov  edx, r13d
    sub  edx, [rel wm_pointer_start_y]
    add  edx, [rel wm_pointer_orig_y]
    call wmx_move_slot
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_MOVE
    jmp  .finish
.drag_resize:
    mov  edi, [rel wm_pointer_slot]
    call wm_pointer_act_ok              ; SEC-winmove (B): per event, as .drag_move
    test eax, eax
    jnz  .finish
    ; the pressed edges follow the pointer; the opposite edges stay put; minimum size honoured.
    ; B4 (2026-09-30, usage suite CHR-08): the floor is the window's own minimum
    ; (wm_min_w/wm_min_h: the form's min_w/min_h, never below the caption-button
    ; floor WMX_USER_MIN_W/H), on every dragged edge -- right/bottom included.
    mov  r11d, [rel wm_pointer_slot]
    lea  rax, [rel wm_min_w]
    mov  r15d, [rax + r11*4]                ; minimum w
    lea  rax, [rel wm_min_h]
    mov  ebx, [rax + r11*4]                 ; minimum h
    mov  eax, r12d
    sub  eax, [rel wm_pointer_start_x]      ; dx
    mov  ecx, r13d
    sub  ecx, [rel wm_pointer_start_y]      ; dy
    mov  esi, [rel wm_pointer_orig_x]       ; new x
    mov  edx, [rel wm_pointer_orig_y]       ; new y
    mov  r8d, [rel wm_pointer_orig_w]       ; new w
    mov  r9d, [rel wm_pointer_orig_h]       ; new h
    movzx r10d, byte [rel wm_pointer_resize_edges]
    test r10d, WM_EDGE_L
    jz   .rz_right
    add  esi, eax
    sub  r8d, eax
    cmp  r8d, r15d
    jge  .rz_right
    mov  esi, [rel wm_pointer_orig_x]
    add  esi, [rel wm_pointer_orig_w]
    sub  esi, r15d                          ; the right edge stays anchored at the minimum
    mov  r8d, r15d
.rz_right:
    test r10d, WM_EDGE_R
    jz   .rz_top
    add  r8d, eax
    cmp  r8d, r15d
    jge  .rz_top
    mov  r8d, r15d                          ; the left edge stays anchored at the minimum
.rz_top:
    test r10d, WM_EDGE_T
    jz   .rz_bottom
    add  edx, ecx
    sub  r9d, ecx
    cmp  r9d, ebx
    jge  .rz_bottom
    mov  edx, [rel wm_pointer_orig_y]
    add  edx, [rel wm_pointer_orig_h]
    sub  edx, ebx
    mov  r9d, ebx
.rz_bottom:
    test r10d, WM_EDGE_B
    jz   .rz_apply
    add  r9d, ecx
    cmp  r9d, ebx
    jge  .rz_apply
    mov  r9d, ebx                           ; the top edge stays anchored at the minimum
.rz_apply:
    mov  edi, [rel wm_pointer_slot]
    mov  ecx, r8d
    mov  r8d, r9d
    call wmx_set_geom_slot                  ; EDI=slot ESI=x EDX=y ECX=w R8D=h
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_RESIZE
    jmp  .finish
.drag_widget:
    mov  edi, [rel wm_pointer_widget_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_scalar_pointer_drag
    test eax, eax
    jnz  .drag_widget_moved
    mov  byte [rel wm_pointer_mode], 0  ; RCQ-16 S4 R1 (F2): disabled mid-drag: the capture ends (no release intent)
    jmp  .finish
.drag_widget_moved:
    mov  byte [rel wm_pointer_last_intent], WM_PTR_INTENT_WIDGET
.hover:
    mov  r15d, r14d                    ; preserve buttons before flyout hover uses R14
    mov  edi, r12d
    mov  esi, r13d
    call wgt_menu_hover                 ; G11: an open flyout highlights the item under the pointer
    mov  edi, r12d
    mov  esi, r13d
    call wgt_menu_shown_at              ; F5-R1: a painted flyout covers every window there
    mov  r14d, eax                      ; (r14 = buttons is spent on this path)
    call calendar_hit
    or   r14d, eax
    ; --- 2026-09-08 (Peter: "I do not see a resize pointer"): motion with no button sets the
    ;     cursor shape from what is under the pointer: the bottom-right grip of the topmost
    ;     window -> diagonal resize; anything else -> arrow. ---
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    test r14d, r14d
    jz   .hover_top
    mov  eax, -1                        ; no caption, widget or grip under a flyout
.hover_top:
    mov  byte [rel gui_cursor_shape], GUI_CURSOR_ARROW
    push rax
    mov  edi, eax
    mov  esi, r12d
    mov  edx, r13d
    call wmx_caption_hover              ; D2 caption hover (repaints on change)
    mov  edi, [rsp]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_hover_at                   ; RCQ-16 S4: the kit's hot widget (paint state; never focus)
    test r15d, 7
    jnz  .hover_paint_done              ; held-button motion belongs to its gesture
    mov  ebx, eax                      ; hot widget, not the window slot on stack
    mov  edi, r12d
    mov  esi, r13d
    call calendar_hit
    test eax, eax
    jnz  .hover_paint_done
    call ime_popup_hit                 ; the painted IME overlay covers the grid
    test eax, eax
    jnz  .hover_paint_done
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    cmp  r13d, eax
    jae  .hover_paint_done
    mov  edi, ebx
    mov  esi, r12d
    mov  edx, r13d
    call wgt_pointer_motion            ; opt-in callback only; no focus/press/raise
.hover_paint_done:
    pop  rax
    cmp  eax, -1
    je   .finish
    ; UI wave 2 B1: over a caption button, or anywhere on a maximized window,
    ; the arrow stays (same order as the press path).
    mov  ebx, eax
    mov  edi, eax
    mov  esi, r12d
    mov  edx, r13d
    call wmx_caption_part_at
    test eax, eax
    jnz  .finish
    lea  rax, [rel wm_maximized]
    cmp  byte [rax + rbx], 1
    je   .finish
    lea  rax, [rel wm_resizable]
    cmp  byte [rax + rbx], 0
    je   .finish                        ; B4: no resize cursor on a resizable=0 form
    mov  edi, ebx
    mov  esi, r12d
    mov  edx, r13d
    call wm_pointer_edge_zone
    test eax, eax
    jz   .finish
    mov  edi, eax
    call wm_pointer_shape_for_edges
    mov  [rel gui_cursor_shape], al
    jmp  .finish
.finish:
    movzx eax, byte [rel wm_pointer_last_intent]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; wm_pointer_wheel(EDI notches, + = away from the user; ESI x; EDX y): the
; window under the pointer takes the wheel (Windows 10+), not the focused one.
; Registered as the pointer seam's wheel hook (the MSI tree's name and rule).
; 2026-10-01 (usage suite CON-02, G11 wheel): a console transcript scrolls.
wm_pointer_wheel:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  r13d, edx
    inc  qword [rel wm_pointer_wheels]
    mov  edi, esi
    mov  esi, edx
    call calendar_hit
    test eax, eax
    jnz  .out
    call ime_popup_hit                  ; the IME popup owns its covered point
    test eax, eax
    jnz  .out
    call wm_pointer_top_slot
    cmp  eax, -1
    je   .out
    cmp  eax, [rel gd_slot]
    jne  .console
    mov  edi, ebx
    mov  esi, r12d
    mov  edx, r13d
    call guest_desktop_wheel            ; requires existing human capture; no focus change
    jmp  .out                          ; a refused guest wheel cannot scroll a host console
.console:
    mov  edi, eax
    mov  esi, ebx
    call console_grid_wheel
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

wm_pointer_init:
    lea  rdi, [rel wm_pointer_wheel]
    call ps2_pointer_set_wheel_hook
    call wgt_scalar_kat
    call wgt_listview_dropdown_kat
    ; Task3433: prove shared registry/input seams on the locked presentation
    ; path without allocating desktop widget identities.  The authenticated
    ; desktop transition constructs the real palette later.
    call summon_palette_selftest
    test eax, eax
    jnz  .summon_palette_kat_fail
    lea  rdi, [rel summon_marker]
    call serial_string
    jmp  .pointer_ready
.summon_palette_kat_fail:
    lea  rdi, [rel summon_kat_fail]
    call serial_string
.pointer_ready:
    lea  rdi, [rel str_pointer_marker]
    call serial_string
    ret

; wm_pointer_count_click(R12D x, R13D y): wm_pointer_clicks = 1, 2, 3 for a
; press that continues a multi-click (same spot within WM_DBLCLICK_PX, within
; WM_DBLCLICK_MS of the previous press); anything else starts over at 1. Ported
; from the MSI tree (catalogue WIN-04 there, CHR-07 here). SEC-winmove (C2): a
; multi-click is one origin's, so an injected press never pairs with a HUMAN one
; into a HUMAN double click. Clobbers RAX, RCX, RDX.
wm_pointer_count_click:
    call boot_ms_now
    mov  rcx, rax
    movzx edx, byte [rel wm_pointer_origin]
    cmp  dl, [rel wm_click_last_origin]
    mov  [rel wm_click_last_origin], dl
    jne  .first
    sub  rax, [rel wm_click_last_ms]
    cmp  rax, WM_DBLCLICK_MS
    ja   .first
    mov  eax, r12d
    sub  eax, [rel wm_click_last_x]
    cdq
    xor  eax, edx
    sub  eax, edx
    cmp  eax, WM_DBLCLICK_PX
    ja   .first
    mov  eax, r13d
    sub  eax, [rel wm_click_last_y]
    cdq
    xor  eax, edx
    sub  eax, edx
    cmp  eax, WM_DBLCLICK_PX
    ja   .first
    mov  eax, [rel wm_pointer_clicks]
    inc  eax
    cmp  eax, 3
    jbe  .store
.first:
    mov  eax, 1
.store:
    mov  [rel wm_pointer_clicks], eax
    mov  [rel wm_click_last_ms], rcx
    mov  [rel wm_click_last_x], r12d
    mov  [rel wm_click_last_y], r13d
    ret

wm_pointer_last_btn:   dd 0
wm_pointer_clicks:     dd 0            ; CHR-07: 1 single, 2 double, 3 triple press
wm_click_last_x:       dd 0
wm_click_last_y:       dd 0
wm_click_title_slot:   dd -1           ; CHR-07: slot whose title band took the last press (-1 none)
wm_click_prev_title:   dd -1           ; ... as it was before the current press
align 8
wm_click_last_ms:      dq 0
wm_pointer_wheels:     dq 0            ; wheel events dispatched
wm_pointer_start_x:    dd 0
wm_pointer_start_y:    dd 0
wm_pointer_orig_x:     dd 0
wm_pointer_orig_y:     dd 0
wm_pointer_orig_w:     dd 0
wm_pointer_orig_h:     dd 0
wm_pointer_slot:       dd 0
wm_pointer_widget_id:  dd -1
wm_pointer_hit_id:     dd -1            ; the non-scalar widget under the last body press
wm_pointer_note_hook:  dq 0             ; SEC R1 F1: (EDI x, ESI y, EDX buttons) after the origin store; set once by start_programs_init
wm_pointer_resize_edges: db 0            ; WM_EDGE_* flags of the active resize drag
str_wmp_textfield:     db "textfield", 0
wm_pointer_mode:       db 0             ; 0 none, 1 move, 2 resize, 3 widget capture, 4 caption button capture, 5 typed widget capture, 6 typed capture by middle/right
wm_pointer_other_mask: db 0             ; mode 6: the held button's mask (2 right, 4 middle)
wm_pointer_caption_part: db 0            ; WMX_PART_* captured by the mode-4 press (fires on release)
wm_pointer_origin:     db WM_PTR_ORIGIN_INJECTED ; fail closed until the first real event
wm_pointer_last_intent: db 0
wm_pointer_gesture_origin: db WM_PTR_ORIGIN_HUMAN ; SEC-winmove (C2): the origin driving the held gesture (mode != 0)
wm_pointer_last_btn_inj: dd 0           ; SEC-winmove (C2): the injected stream's previous buttons
wm_click_last_origin:  db WM_PTR_ORIGIN_HUMAN ; SEC-winmove (C2): the origin of the previous press
wm_pointer_retire:     db 0             ; RCQ-09: the current event is a device retirement's buttons-up

str_pointer_marker: db "[PAOS64] M6 wm: pointer dispatcher routes press/release to hit-tested window (raise/drag/resize/buttons) via the ONE state machine [wm.pointer.routing]",13,10,0
