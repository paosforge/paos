;; MODULE gui/guest_desktop
;; LAYER 6
;; EXPORTS guest_desktop_wheel, guest_desktop_show, guest_desktop_tick, guest_desktop_key_byte, guest_desktop_pointer, guest_desktop_draw_body, gd_slot, gd_capture, gd_blits, gd_keys_sent, gd_ptr_sent, gd_releases
;; IMPORTS gui/calendar, boot/gop, boot/paging, core/heap, core/time, core/smp, gui/window, gui/cadence_mark, gui/window_mgmt, gui/lock_screen, gui/wm_pointer, gui/input_route, gui/summon_palette, gui/widget, gui/widget_tabstrip, gui/widget_listview, sec/session, hv/vmx, hv/hv_ops, hv/vm_profile, hv/guestinput, hv/guestdisplay
;; CAPS CAP_GUI
;; OWNER saga:hv
; ============================================================================
; RCQ-23 S1: the PaOS desktop window of the desktop-linux guest (a port of the
; HP spoke's guest_window to the integration window manager and compositor).
;
; Window. When a START maps a DISPLAY, the idle tick opens one window titled
; "Linux_desktop", initially 802x641 and resizable through existing WM gestures.
; Its fixed guest framebuffer fits the client with a centered nearest-neighbor
; raster and PaOS-owned letterbox margins. The title
; and chrome are PaOS's own: the guest controls only the fitted viewport.
; Guest pixels reach the compositor's shadow buffer
; (both are x8r8g8b8) and presented through fb_damage_rect:
;   - inside the ordinary composition (wmx_draw_one -> guest_desktop_draw_body),
;     so overlapping windows keep their z-order;
;   - by the idle tick every GD_REFRESH_MS, but only while the guest window is
;     the top visible window, the session is unlocked and nothing PaOS paints
;     above windows is open (RCQ-23 C1: palette, flyout, dropdown, overlay).
; Every copy is clipped above the taskbar band, so the guest can never paint
; the taskbar or its GUARD cell (SEC-GA0-lite).
; The window closes when the guest stops; closed by the user, it stays closed
; for that START until an explicit RAISE GUEST / HOOK SET window:guest show.
; Show never restarts the workload or captures input. It is never restored
; across a reboot (WM_RESTORE_NEVER).
;
; Input capture. A human left press inside fitted content, where the guest
; window is topmost and no PaOS pointer gesture is in progress, captures the
; keyboard and pointer for the guest (and is delivered). The taskbar band and
; an open palette, flyout, dropdown or overlay always stay PaOS's: there the
; guest takes no press, captured or not (RCQ-23 C1). While captured, raw
; Set-1 bytes are translated to Linux key codes and posted to the guest's
; virtio-input device instead of entering PaOS routing; human pointer events
; inside the client area (and a drag the guest started, until every button is
; up) become absolute pointer events. Both Ctrl keys together release the
; capture; so do losing focus, closing or minimizing the window, a session
; lock, an open Summon palette and the guest's input driver going away. On
; every release, every key and button the guest believes is held is released.
; Seams agreed with rc-input (2026-10-08 17:22, K1-K4, P1-P3, D1):
;   K1 capture starts and ends only between whole scan-code sequences;
;   K2 PaOS's modifier and Win state is forgotten when capture starts and ends;
;   K3 the router's RBX/R12/R13 survive guest_desktop_key_byte;
;   K4 Win is never captured: a Win press ends the capture and reaches PaOS as
;      its own E0 sequence, so Win+L (and every Win chord) stays PaOS's;
;   P1/P2 only human events with no PaOS gesture in progress; the WM has
;      already recorded the buttons, so its edge machine never sees a phantom.
; ============================================================================

GD_REFRESH_MS    equ 50
GD_CLIENT_DX     equ GUI_CHROME_BORDER
GD_CLIENT_DY     equ GUI_TITLE_H
GD_WIN_W         equ VP_FB_WIDTH + 2 * GUI_CHROME_BORDER
GD_WIN_H         equ VP_FB_HEIGHT + GUI_TITLE_H + GUI_CHROME_BORDER
GD_WIN_Y         equ 16

; guest_desktop_tick — idle context. Opens/closes the window with the guest,
; keeps capture honest, refreshes the client area.
guest_desktop_tick:
    cld
    mov  byte [rel gd_stage_worked], 0      ; one phase per idle tick
    push rbx
    call guestinput_release_retry           ; bounded release progress even uncaptured/locked
    call guest_frame_measure_tick           ; optional owner measurement retains frozen S
    test eax, eax
    jnz .out
    call gd_stage_housekeep                 ; RCQ-12: retire or scrub the staging pair
    ; RCQ-23 C2 (N1): while the session is locked the tick opens, forgets and
    ; closes nothing; it only keeps the capture dropped. The lock owns focus and
    ; the top of the stack; the window opens or closes on the first unlocked tick.
    call gd_locked
    test eax, eax
    jnz  .locked
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .gone
    cmp  byte [rel hv_linux_running], 1
    jne  .gone
    call guestdisplay_hva
    test rax, rax
    jz   .gone
    mov  ebx, [rel gd_slot]
    cmp  ebx, -1
    jne  .have_window
    mov  eax, [rel hv_linux_start_consumed]
    cmp  byte [rel gd_opened], 1
    jne  .open
    cmp  eax, [rel gd_opened_gen]
    je   .out                               ; closed by the user for this START
.open:
    call gd_open
    jmp  .out
.have_window:
    call gd_window_ours
    test eax, eax
    jz   .forget
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gd_opened_gen]
    je   .check_capture
    ; STOP/START can occur between desktop ticks. Retire only our old slot.
    call gd_retire_window
    call gd_open
    jmp  .out
.forget:
    mov  dword [rel gd_slot], -1            ; closed by the user: forget it
    call gd_drop_capture
    jmp  .out
.check_capture:
    call gd_capture_valid
    ; Refresh: only as the top visible window, unlocked, at most every 50 ms.
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rbx*4], WM_VISIBLE
    jne  .out
    call gd_locked
    test eax, eax
    jnz  .out
    call wmx_paint_top_slot                 ; RCQ-16 F5-R1 L1: the window painted last
    cmp  eax, ebx
    jne  .out
    call gd_overlay_open                    ; C1: never paint over a PaOS overlay
    test eax, eax
    jnz  .out
    call boot_ms_now
    mov  rcx, rax
    sub  rcx, [rel gd_last_refresh_ms]
    cmp  rcx, GD_REFRESH_MS
    jb   .out
    mov  [rel gd_last_refresh_ms], rax
    mov  edi, ebx
    call gd_stage_tick                      ; RCQ-12: prepare or publish; never serial fallback
    jmp  .out
.gone:
    call gd_retire_window
    jmp  .out
.locked:
    call gd_drop_capture
.out:
    pop  rbx
    ret

; Explicit native GUI action, after the caller's owner/session admission.
; EAX=0 shown, 1 unavailable, 2 no free WM slot. No scheduler yield, START,
; STOP, synthetic input or display creation. WM helpers keep the native focus
; policy. The current display helper binds the consumed START and reservation.
; Preserve full callee-saved registers, DF and FP state; no shared command scratch.
guest_desktop_show:
    pushfq
    cld
    push rbx
    call gd_locked
    test eax, eax
    jnz  .unavailable
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .unavailable
    cmp  byte [rel hv_linux_running], 1
    jne  .unavailable
    call guestdisplay_hva
    test rax, rax
    jz   .unavailable
    call gd_window_ours
    test eax, eax
    jz   .replace
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gd_opened_gen]
    jne  .replace
    call gd_drop_capture                  ; show cannot grant human input custody
    mov  edi, [rel gd_slot]
    call wmx_raise_slot                   ; restore MIN or raise visible, no duplicate
    xor  eax, eax
    jmp  .out
.replace:
    call gd_retire_window                 ; never close an unrelated reused slot
    call gd_open
    cmp  dword [rel gd_slot], -1
    je   .full
    xor  eax, eax
    jmp  .out
.unavailable:
    mov  eax, 1
    jmp  .out
.full:
    mov  eax, 2
.out:
    pop  rbx
    popfq
    ret

; Forget stale custody and close only a slot with our private title identity.
; Shared by STOP/no-display, a new START missed between ticks and explicit show.
gd_retire_window:
    push rbx
    mov  ebx, [rel gd_slot]
    call gd_drop_capture
    call gd_window_ours
    mov  dword [rel gd_slot], -1
    test eax, eax
    jz   .out
    mov  edi, ebx
    call wmx_close_slot
.out:
    pop  rbx
    ret

gd_open:
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gd_opened_gen], eax
    mov  byte [rel gd_opened], 1
    mov  esi, [rel fb_width]
    sub  esi, GD_WIN_W
    sar  esi, 1
    jns  .x_ok
    xor  esi, esi
.x_ok:
    lea  rdi, [rel str_gd_title]
    mov  edx, GD_WIN_Y
    mov  ecx, GD_WIN_W
    mov  r8d, GD_WIN_H
    mov  r9d, WM_RESTORE_NEVER
    call wmx_open_window
    cmp  eax, -1
    je   .out
    mov  [rel gd_slot], eax
    inc  qword [rel gd_window_epoch]        ; distinguish same-START same-slot reopen
    lea  rcx, [rel wm_resizable]
    mov  byte [rcx + rax], 1                ; existing WM resize gestures
    mov  byte [rel gd_capture], 0
    mov  byte [rel gd_ptr_owner], 0
    call wmx_draw_all
.out:
    ret

; gd_window_ours -> EAX=1 while gd_slot still holds the guest window (not
; closed, and not reused by another window since). A window the lock hid is
; still ours (RCQ-23 C2, N2): the lock restores it on unlock.
gd_window_ours:
    xor  eax, eax
    mov  ecx, [rel gd_slot]
    cmp  ecx, WM_MAX
    jae  .out
    lea  rdx, [rel wm_state]
    mov  edx, [rdx + rcx*4]
    cmp  edx, WM_VISIBLE
    je   .title
    cmp  edx, WM_MIN
    je   .title
    cmp  edx, LOCK_HIDDEN
    jne  .out
.title:
    lea  rdx, [rel wm_title]
    mov  rdx, [rdx + rcx*8]
    lea  r8, [rel str_gd_title]
    cmp  rdx, r8
    jne  .out
    mov  eax, 1
.out:
    ret

; gd_locked -> EAX=1 while the session is locked.
gd_locked:
    xor  eax, eax
    cmp  byte [rel session_locked], SESSION_LOCKED
    sete al
    ret

; gd_capture_valid — drop the capture when any of its conditions is gone.
gd_capture_valid:
    cmp  byte [rel gd_capture], 1
    jne  .out
    call guestinput_release_blocked
    test eax, eax
    jnz  .drop
    mov  eax, [rel gd_slot]
    cmp  eax, [rel wm_focus]
    jne  .drop
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rax*4], WM_VISIBLE
    jne  .drop
    call gd_locked
    test eax, eax
    jnz  .drop
    call gd_overlay_open                    ; the palette, a flyout, a dropdown
    test eax, eax
    jnz  .drop
    cmp  byte [rel gi_live], 1
    jne  .drop
    mov  eax, 1
    ret
.drop:
    call gd_drop_capture
.out:
    xor  eax, eax
    ret

gd_drop_capture:
    cmp  byte [rel gd_capture], 0
    jne  .drop
    cmp  byte [rel gd_ptr_owner], 0
    je   .out
.drop:
    mov  byte [rel gd_capture], 0
    mov  byte [rel gd_ptr_owner], 0
    mov  byte [rel gd_lctrl], 0
    mov  byte [rel gd_rctrl], 0
    mov  byte [rel gd_pause_valid], 0       ; never finish a tap across a capture boundary
    ; gd_e0/gd_e1 survive: a sequence the guest began is still the guest's (K1)
    call guestinput_release_all
    call gd_forget_paos_mods
    inc  dword [rel gd_releases]
.out:
    ret

; gd_forget_paos_mods — K2: no PaOS modifier or Win state crosses a capture
; boundary (a Shift held at the capturing click and released inside the guest
; must not stay down in PaOS). The router forgets both sides of a combined bit
; cleared outside it, as it does for lock_screen.
gd_forget_paos_mods:
    mov  byte [rel input_kbd_mods], 0
    mov  byte [rel input_win_down], 0
    mov  byte [rel input_win_chord], 0
    mov  byte [rel input_kbd_numlock_down], 0   ; F6: a NumLock held across the edge
    ret

; gd_overlay_open -> EAX=1 while PaOS paints anything above windows besides the
; taskbar: the Summon palette, an open flyout, an open dropdown popup or any
; other declared overlay. This follows wgt_has_overlay, except that a closed
; flyout or dropdown paints nothing and does not count. RCQ-23 C1.
gd_overlay_open:
    mov  eax, 1
    cmp  byte [rel calendar_open], 1
    je   .out                         ; guest frames never cover the month panel
    cmp  byte [rel summon_palette_open], 1
    je   .out
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel wgt_count]
    jae  .none
    cmp  ecx, WGT_MAX
    jae  .none
    imul rdx, rcx, WGI_SZ
    lea  rax, [rel wgt_tbl]
    add  rdx, rax
    mov  eax, [rdx + WGI_TYPE]
    test eax, eax
    jz   .next
    cmp  dword [rdx + WGI_LAYER], 1
    jne  .next
    test dword [rdx + WGI_FLAGS], 1
    jz   .next
    mov  r8d, [rdx + WGI_WIN]
    cmp  r8d, WGT_HOST_DESKTOP
    je   .kind
    ja   .next
    lea  r9, [rel wm_state]
    cmp  dword [r9 + r8*4], WM_VISIBLE
    jne  .next
    cmp  r8d, [rel wm_focus]                ; RCQ-16 F5-R1: only the focused window's
    jne  .next                              ; overlays paint (wgt_row_shown)
.kind:
    mov  r8d, [rel wgt_menu_type]
    inc  r8d
    cmp  eax, r8d
    jne  .not_menu
    cmp  dword [rdx + WGI_SEL_LO], 1        ; a flyout paints only while open
    je   .yes
    jmp  .next
.not_menu:
    mov  r8d, [rel wgt_listview_type]
    inc  r8d
    cmp  eax, r8d
    jne  .yes
    cmp  byte [rdx + LV_MODE], LV_MODE_DROPDOWN
    jne  .yes
    cmp  byte [rdx + LV_OPEN], 1            ; a dropdown paints only its live popup
    je   .yes
.next:
    inc  ecx
    jmp  .scan
.none:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
.out:
    ret

; gd_band_bottom -> EAX = the first screen row the guest may not touch (the
; taskbar band and below).
gd_band_bottom:
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    ret

; Common viewport contract, caller-owned 128B (no mutable shared scratch).
; Signed WM origins/extents widen BEFORE arithmetic. Products are bounded by
; INT32_MAX*800; DIV denominators are positive. The discrete fit rounds down,
; with a minimum one pixel in either dimension. Odd letterbox remainder is
; on the right/bottom. WM's GUI_TOK_WINDOW_BODY owns all letterbox pixels.
GV_CX equ 0
GV_CY equ 8
GV_CW equ 16
GV_CH equ 24
GV_VX equ 32
GV_VY equ 40
GV_VW equ 48
GV_VH equ 56
GV_OX equ 64
GV_OY equ 72
GV_OW equ 80
GV_OH equ 88
GV_SX equ 96
GV_SY equ 104
GV_SW equ 112
GV_SH equ 120
GV_BYTES equ 128
; gd_view(EDI=slot, RSI=descriptor). Invalid/empty visible fields are zero.
; Preserves all nonvolatile registers. No display/private pointers are read.
gd_view:
    push rbx
    push r12
    mov  rbx, rsi
    mov  r12d, edi
    mov  rdi, rsi
    xor  eax, eax
    mov  ecx, GV_BYTES/8
    cld
    rep  stosq
    cmp  r12d, WM_MAX
    jae  .out
    lea  rax, [rel wm_x]
    movsxd r8, dword [rax + r12*4]
    add  r8, GD_CLIENT_DX
    mov  [rbx + GV_CX], r8
    lea  rax, [rel wm_y]
    movsxd r9, dword [rax + r12*4]
    add  r9, GD_CLIENT_DY
    mov  [rbx + GV_CY], r9
    lea  rax, [rel wm_w]
    movsxd r10, dword [rax + r12*4]
    sub  r10, 2 * GUI_CHROME_BORDER
    jle  .out
    lea  rax, [rel wm_h]
    movsxd r11, dword [rax + r12*4]
    sub  r11, GUI_TITLE_H + GUI_CHROME_BORDER
    jle  .out
    mov  [rbx + GV_CW], r10
    mov  [rbx + GV_CH], r11
    imul rax, r10, VP_FB_HEIGHT
    imul rcx, r11, VP_FB_WIDTH
    cmp  rax, rcx
    ja   .height
    xor  edx, edx
    mov  ecx, VP_FB_WIDTH
    div  rcx
    mov  r11, rax
    jmp  .fit
.height:
    mov  rax, rcx
    xor  edx, edx
    mov  ecx, VP_FB_HEIGHT
    div  rcx
    mov  r10, rax
.fit:
    mov  eax, 1
    cmp  r10, rax
    cmovb r10, rax
    cmp  r11, rax
    cmovb r11, rax
    mov  [rbx + GV_VW], r10
    mov  [rbx + GV_VH], r11
    mov  rax, [rbx + GV_CW]
    sub  rax, r10
    shr  rax, 1
    add  r8, rax
    mov  [rbx + GV_VX], r8
    mov  rax, [rbx + GV_CH]
    sub  rax, r11
    shr  rax, 1
    add  r9, rax
    mov  [rbx + GV_VY], r9
    add  r10, r8                            ; exclusive fitted right/bottom
    add  r11, r9
    movsxd rax, dword [rel fb_width]
    cmp  r10, rax
    cmovg r10, rax
    movsxd rax, dword [rel fb_height]
    sub  rax, TASKBAR_H
    cmp  r11, rax
    cmovg r11, rax
    xor  eax, eax
    cmp  r8, rax
    cmovl r8, rax
    cmp  r9, rax
    cmovl r9, rax
    sub  r10, r8
    jle  .out
    sub  r11, r9
    jle  .out
    mov  [rbx + GV_OX], r8
    mov  [rbx + GV_OY], r9
    mov  [rbx + GV_OW], r10
    mov  [rbx + GV_OH], r11
    ; Bounding source rectangle of all visible nearest-neighbor samples.
    mov  rdi, r8
    mov  rsi, [rbx + GV_VX]
    mov  rdx, [rbx + GV_VW]
    mov  ecx, VP_FB_WIDTH
    call gd_axis
    mov  [rbx + GV_SX], rax
    mov  rdi, [rbx + GV_OX]
    add  rdi, [rbx + GV_OW]
    dec  rdi
    call gd_axis
    inc  rax
    sub  rax, [rbx + GV_SX]
    mov  [rbx + GV_SW], rax
    mov  rdi, [rbx + GV_OY]
    mov  rsi, [rbx + GV_VY]
    mov  rdx, [rbx + GV_VH]
    mov  ecx, VP_FB_HEIGHT
    call gd_axis
    mov  [rbx + GV_SY], rax
    mov  rdi, [rbx + GV_OY]
    add  rdi, [rbx + GV_OH]
    dec  rdi
    call gd_axis
    inc  rax
    sub  rax, [rbx + GV_SY]
    mov  [rbx + GV_SH], rax
.out:
    pop  r12
    pop  rbx
    ret

; Single inverse axis shared by geometry, raster and input. Coordinates and
; origin are signed64, extent positive; output clamps to [0, guest_extent-1].
; Preserves RSI/RDX/RCX and all nonvolatiles. No FP/SIMD state is touched.
gd_axis:
    xor  eax, eax
    sub  rdi, rsi
    jle  .out
    lea  rax, [rcx - 1]
    cmp  rdi, rdx
    jae  .out
    push rdx
    mov  rax, rdi
    imul rax, rcx
    xor  edx, edx
    div  qword [rsp]
    pop  rdx
.out:
    ret

; gd_render(RDI=view, RSI=source, RDX=pitch, RCX=source x, R8=source y,
; R9=linear output cursor). One contiguous row fragment, <=800 pixels.
; The caller proves full surface/source custody and the immutable plan.
; Returns RAX=count, R8/R9=damage origin, R10=count, R11=1. No damage here.
gd_render:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  rbx, rdi
    mov  [rsp], rsi
    mov  [rsp + 8], rdx
    mov  [rsp + 16], rcx
    mov  [rsp + 24], r8
    xor  eax, eax
    mov  rcx, [rbx + GV_OW]
    test rcx, rcx
    jz   .out
    mov  rax, r9
    xor  edx, edx
    div  rcx
    cmp  rax, [rbx + GV_OH]
    jae  .empty
    sub  rcx, rdx
    mov  r15d, VP_FB_WIDTH
    cmp  r15, rcx
    cmova r15, rcx
    mov  r12, [rbx + GV_OX]
    add  r12, rdx
    mov  r13, [rbx + GV_OY]
    add  r13, rax
    mov  [rsp + 32], r12
    mov  rax, r13
    mov  edx, [rel fb_stride]
    imul rax, rdx
    add  rax, r12
    mov  r14, [rel fb_base]
    lea  r14, [r14 + rax*4]
    mov  rdi, r13
    mov  rsi, [rbx + GV_VY]
    mov  rdx, [rbx + GV_VH]
    mov  ecx, VP_FB_HEIGHT
    call gd_axis
    sub  rax, [rsp + 24]
    imul rax, [rsp + 8]
    add  rax, [rsp]
    mov  [rsp + 40], rax                   ; proven source row
    xor  r8d, r8d
.pixel:
    mov  rdi, r12
    mov  rsi, [rbx + GV_VX]
    mov  rdx, [rbx + GV_VW]
    mov  ecx, VP_FB_WIDTH
    call gd_axis
    sub  rax, [rsp + 16]
    mov  rsi, [rsp + 40]
    mov  eax, [rsi + rax*4]
    mov  [r14 + r8*4], eax                 ; bounded production raster store
    inc  r12
    inc  r8
    cmp  r8, r15
    jb   .pixel
    mov  r8, [rsp + 32]
    mov  r9, r13
    mov  r10, r15
    mov  r11d, 1
    mov  rax, r15
    jmp  .out
.empty:
    xor  eax, eax
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Ordinary composition uses exactly the same fitted raster and inverse axes.
; WM already fills the client with GUI_TOK_WINDOW_BODY: deterministic PaOS
; letterbox margins; only fitted content is guest-owned. Idle never calls this.
gd_blit:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, GV_BYTES
    mov  ebx, edi
    call guestdisplay_capture_span          ; full DISPLAY reservation/leaf proof
    jc   .out
    cmp  rdx, GD_STAGE_LEN
    jne  .out
    mov  r15, rax
    ; Share the surface validator without modifying the active staged plan.
    mov  rdi, r15
    call gd_draw_surface_ok
    test eax, eax
    jz   .out
    mov  edi, ebx
    mov  rsi, rsp
    call gd_view
    mov  r14, [rsp + GV_OW]
    imul r14, [rsp + GV_OH]
    xor  r12d, r12d
.row:
    cmp  r12, r14
    jae  .present
    mov  rdi, rsp
    mov  rsi, r15
    mov  edx, VP_FB_STRIDE
    xor  ecx, ecx
    xor  r8d, r8d
    mov  r9, r12
    call gd_render
    test rax, rax
    jz   .out
    add  r12, rax
    jmp  .row
.present:
    mov  r8, [rsp + GV_OX]
    mov  r9, [rsp + GV_OY]
    mov  r10, [rsp + GV_OW]
    mov  r11, [rsp + GV_OH]
    test r10, r10
    jz   .out
    call fb_damage_rect
    inc  dword [rel gd_blits]
.out:
    add  rsp, GV_BYTES
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; guest_desktop_draw_body(EDI=slot) — the compositor's per-window body hook.
guest_desktop_draw_body:
    cmp  edi, [rel gd_slot]
    jne  .out
    cmp  byte [rel lock_surface_ready], 1
    jne  .unlocked
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out                               ; the lock surface owns the screen
.unlocked:
    cmp  byte [rel hv_linux_running], 1
    jne  .out
    jmp  gd_blit
.out:
    ret

; ============================================================================
; RCQ-12: the idle refresh staged through the AP parallel-for lane (contract
; RCQ12_GUEST_DESKTOP_STAGING_SOURCE_HOST_20261012; plan 9d31ba78, A1-A4).
;
; Only guest_desktop_tick stages. Composition (draw_body -> gd_blit) uses
; the common fitted raster. One persistent pair, allocated once and never freed:
;   [guard][S 1,920,000][guard][guard][D 1,920,000][guard]  (16 B canaries)
; Capture samples at most8192B per later tick, each inside its own noyield
; live DISPLAY bracket. The guest can run between samples: S is a temporal
; sample, NOT an atomic guest-produced frame (the DISPLAY ABI has no frame fence).
; Once all S is captured it freezes, then a later tick begins private COPY S->D.
; BSP copy steps are <=8192B; AP pulls write one private chunk. COMPLETE and
; actual retirement/release precede a later revalidated presentation. Final
; presentation is progressive, <=one clipped row/6464 write bytes per tick.
; Cancel pins until actual retirement, then scrubs <=8192B per tick before reuse. Invalid private custody disables
; writes. Idle refresh never falls back to a whole live guest blit.
; ============================================================================
GD_STAGE_LEN      equ VP_FB_STRIDE * VP_FB_HEIGHT   ; the whole guest frame
GD_STAGE_BUDGET_US equ 5000000            ; finite owner lifetime, not measured speed
GD_STAGE_TICK_BYTES equ 8192             ; capture/scrub <=8192, presentation <=6464
GD_STAGE_CHUNK    equ 2048
GD_STAGE_CHUNKS   equ (GD_STAGE_LEN + GD_STAGE_CHUNK - 1) / GD_STAGE_CHUNK
GD_STAGE_GUARD    equ 16
GD_STAGE_S_OFF    equ GD_STAGE_GUARD
GD_STAGE_D_OFF    equ GD_STAGE_S_OFF + GD_STAGE_LEN + 2 * GD_STAGE_GUARD
GD_STAGE_BYTES    equ GD_STAGE_D_OFF + GD_STAGE_LEN + GD_STAGE_GUARD
GD_STAGE_CANARY   equ 0x6B5A3C1E9D8F7A26
%if GD_STAGE_TICK_BYTES <= 0 || GD_STAGE_TICK_BYTES > 8192 || (GD_STAGE_TICK_BYTES & 7) != 0
%error "capture/scrub budget must be positive qwords and at most8192 bytes"
%endif
%if GD_STAGE_LEN != 1920000 || GD_STAGE_LEN > VP_FB_BYTES
%error "the staged frame is 800x600x4, inside the DISPLAY reservation"
%endif
%if GD_STAGE_CHUNKS != 938 || GD_STAGE_LEN - (GD_STAGE_CHUNKS - 1) * GD_STAGE_CHUNK != 1024
%error "the staged copy is 938 chunks of 2048 B with a 1024 B tail"
%endif
%if GD_STAGE_BYTES != 3840064 || (GD_STAGE_LEN / 8) * 8 != GD_STAGE_LEN
%error "the staging pair is 3,840,064 B with qword-sized halves"
%endif

GD_ST_EMPTY       equ 0     ; not allocated yet (the zero-fill default)
GD_ST_IDLE        equ 1     ; allocated and private, no job
GD_ST_RUNNING     equ 2     ; S frozen, D unpublished, cooperative job owned
GD_ST_READY       equ 3     ; D complete and released, not yet revalidated or shown
GD_ST_QUARANTINED equ 4     ; CF=1: a late AP may still own a chunk
GD_ST_DISABLED    equ 5     ; custody/allocation refused; no idle refresh
GD_ST_CAPTURE     equ 6     ; partial temporal sample, no AP owner
GD_ST_SCRUB       equ 7     ; retired private pair cleanup, no publication
GD_ST_PRESENT     equ 9     ; immutable retired D, one clipped row per idle tick
GD_ST_BEGIN       equ 8     ; complete immutable S; begin on a later tick
%if GD_ST_EMPTY != 0
%error "the zero-fill tail must start the staging owner EMPTY"
%endif

GD_WHY_NO_HEAP    equ 1     ; kmalloc refused the pair (disabled)
GD_WHY_OWED       equ 2     ; another caller's generation is owed (defer)
GD_WHY_PAIR       equ 3     ; the pair is not provably this owner's (disabled)
GD_WHY_SPAN       equ 4     ; VM's capture predicate refused (dropped)
GD_WHY_GUEST      equ 5     ; the pair overlaps the guest reservation (disabled)
GD_WHY_REENTRY    equ 6     ; entered RUNNING/READY (dropped)
GD_WHY_STALE      equ 7     ; revalidation failed after CF=0 (dropped)
GD_WHY_CF1        equ 8     ; the lane refused or timed out (quarantined)

; gd_stage_tick(EDI=slot) — the idle refresh's draw. The tick has already
; proved the window is the guest's, top, visible, unlocked and overlay-free,
; and throttled it. Preserves RBX, R12-R15; DF stays clear.
gd_stage_tick:
    cld
    push rbx
    push r12
    push r13
    mov  ebx, edi
    cmp  ebx, WM_MAX
    jae  .out
    cmp  byte [rel gd_stage_worked], 0
    jne  .out                              ; housekeeping already advanced a phase
    movzx eax, byte [rel gd_stage_state]
    cmp  eax, GD_ST_READY
    je   .ready
    cmp  eax, GD_ST_IDLE
    je   .prepare
    cmp  eax, GD_ST_EMPTY
    jne  .out                              ; active/quarantined/scrub/disabled: defer
.prepare:
    cmp  ebx, [rel gd_slot]
    jne  .out
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .out
    call gd_locked
    test eax, eax
    jnz  .out
    call gd_window_ours
    test eax, eax
    jz   .out
    lea  rax, [rel wm_state]
    cmp  dword [rax + rbx*4], WM_VISIBLE
    jne  .out
    call wmx_paint_top_slot
    cmp  eax, ebx
    jne  .out
    call gd_overlay_open
    test eax, eax
    jnz  .out
    call smp_par_for_retired
    test eax, eax
    jz   .owed
    call guestdisplay_capture_span
    test rax, rax
    jz   .out
    cmp  rdx, GD_STAGE_LEN
    jne  .out
    mov  r12, rax
    mov  r13d, ecx
    cmp  byte [rel gd_stage_state], GD_ST_EMPTY
    jne  .snapshot
    mov  edi, GD_STAGE_BYTES
    call kmalloc                            ; existing once-only bump; no memset
    test rax, rax
    jz   .no_heap
    mov  [rel gd_stage_blk], rax
    lea  rdx, [rax + GD_STAGE_S_OFF]
    mov  [rel gd_stage_s], rdx
    lea  rdx, [rax + GD_STAGE_D_OFF]
    mov  [rel gd_stage_d], rdx
    call gd_stage_pair_span                 ; before even the guard writes
    test eax, eax
    jz   .poisoned
    mov  rdi, r12
    call gd_stage_guest_apart
    test eax, eax
    jz   .poisoned
    mov  rax, [rel gd_stage_blk]
    mov  rdx, GD_STAGE_CANARY
    mov  [rax], rdx
    mov  [rax + 8], rdx
    mov  [rax + GD_STAGE_S_OFF + GD_STAGE_LEN], rdx
    mov  [rax + GD_STAGE_S_OFF + GD_STAGE_LEN + 8], rdx
    mov  [rax + GD_STAGE_D_OFF - 16], rdx
    mov  [rax + GD_STAGE_D_OFF - 8], rdx
    mov  [rax + GD_STAGE_D_OFF + GD_STAGE_LEN], rdx
    mov  [rax + GD_STAGE_D_OFF + GD_STAGE_LEN + 8], rdx
    mov  byte [rel gd_stage_state], GD_ST_IDLE
.snapshot:
    mov  [rel gd_stage_src], r12
    mov  [rel gd_stage_start], r13d
    mov  [rel gd_stage_slot], ebx
    mov  eax, [rel gd_opened_gen]
    mov  [rel gd_stage_gen], eax
    mov  rax, [rel gd_window_epoch]
    mov  [rel gd_stage_window_epoch], rax
    mov  rax, [rel session_authority_epoch]
    mov  [rel gd_stage_epoch], rax
    mov  rax, [rel fb_base]
    mov  [rel gd_stage_fb], rax
    mov  rax, [rel fb_size]
    mov  [rel gd_stage_fbsize], rax
    mov  rax, [rel fb_shadow_base]
    mov  [rel gd_stage_shadow], rax
    mov  rax, [rel fb_scanout_base]
    mov  [rel gd_stage_scanout], rax
    mov  rax, [rel fb_shadow_cap]
    mov  [rel gd_stage_shadow_cap], rax
    mov  rax, [rel vm_profile_active]
    mov  [rel gd_stage_profile], rax
    mov  rax, [rel hv_ops_active]
    mov  [rel gd_stage_backend], rax
    mov  rax, [rel hv_linux_region]
    mov  [rel gd_stage_region], rax
    mov  rax, [rel hv_linux_region_capacity]
    mov  [rel gd_stage_capacity], rax
    mov  rax, [rel hv_linux_ram]
    mov  [rel gd_stage_ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rel gd_stage_ram_bytes], rax
    mov  eax, [rel fb_width]
    mov  [rel gd_stage_fbw], eax
    mov  eax, [rel fb_height]
    mov  [rel gd_stage_fbh], eax
    mov  eax, [rel fb_stride]
    mov  [rel gd_stage_fbs], eax
    mov  eax, [rel vm_profile_dev_mask]
    mov  [rel gd_stage_devices], eax
    mov  al, [rel keep_presentation_target]
    mov  [rel gd_stage_target], al
    lea  rdx, [rel wm_owner]
    mov  rax, [rdx + rbx*8]
    mov  [rel gd_stage_win_owner], rax
    lea  rdx, [rel wm_x]
    mov  eax, [rdx + rbx*4]
    mov  [rel gd_stage_wx], eax
    lea  rdx, [rel wm_y]
    mov  eax, [rdx + rbx*4]
    mov  [rel gd_stage_wy], eax
    lea  rdx, [rel wm_w]
    mov  eax, [rdx + rbx*4]
    mov  [rel gd_stage_ww], eax
    lea  rdx, [rel wm_h]
    mov  eax, [rdx + rbx*4]
    mov  [rel gd_stage_wh], eax
    ; Admit a packed rectangle only after validating both complete surfaces.
    call gd_stage_surface_ok
    test eax, eax
    jz   .discard
    mov  edi, ebx
    lea  rsi, [rel gd_stage_view]
    call gd_view
    call gd_stage_shape
    mov  [rel gd_stage_len], rax
    mov  [rel gd_stage_px], r8
    mov  [rel gd_stage_py], r9
    mov  [rel gd_stage_pw], r10
    mov  [rel gd_stage_ph], r11
    mov  [rel gd_stage_sx], rcx
    mov  [rel gd_stage_sy], rdx
    mov  rdx, [rel gd_stage_view + GV_SW]
    shl  rdx, 2
    mov  [rel gd_stage_pitch], rdx
    lea  rdx, [rax + GD_STAGE_CHUNK - 1]
    shr  rdx, 11
    mov  [rel gd_stage_chunks], rdx
    mov  rdx, rax
    and  edx, GD_STAGE_CHUNK - 1
    test rdx, rdx
    jnz  .tail
    test rax, rax
    jz   .tail
    mov  edx, GD_STAGE_CHUNK
.tail:
    mov  [rel gd_stage_tail], rdx
    mov  rax, [rel fb_surface_epoch]
    mov  [rel gd_stage_pub_epoch], rax
    mov  edi, ebx
    call gd_stage_still_ours                 ; complete context before entering CAPTURE
    test eax, eax
    jz   .discard
    cmp  qword [rel gd_stage_len], 0
    je   .empty                             ; no pixel read, COPY job or damage
    mov  qword [rel gd_stage_cursor], 0
    mov  byte [rel gd_stage_state], GD_ST_CAPTURE
    jmp  .out                              ; no pixel capture on preparation tick
.empty:
    inc  qword [rel gd_stage_published]       ; successful no-op refresh, no pixels
    inc  dword [rel gd_blits]
    mov  byte [rel gd_stage_state], GD_ST_IDLE
    mov  byte [rel gd_stage_worked], 1
    jmp  .out
.ready:
    mov  edi, ebx
    call gd_stage_still_ours
    test eax, eax
    jz   .discard
    mov  byte [rel gd_stage_worked], 1
    mov  edi, ebx
    call gd_stage_surface_ok
    test eax, eax
    jz   .discard
    mov  rax, [rel fb_surface_epoch]
    cmp  rax, -1
    je   .discard                           ; saturated epoch cannot establish a plan
    mov  [rel gd_stage_pub_epoch], rax
    mov  qword [rel gd_stage_pub_row], 0
    mov  byte [rel gd_stage_state], GD_ST_PRESENT ; no pixels until a later tick
    jmp  .out
.discard:
    call gd_stage_discard
    jmp  .out
.no_heap:
    mov  byte [rel gd_stage_why], GD_WHY_NO_HEAP
    jmp  .disable
.poisoned:
    mov  byte [rel gd_stage_why], GD_WHY_PAIR
.disable:
    mov  byte [rel gd_stage_state], GD_ST_DISABLED
    inc  qword [rel gd_stage_dropped]
    jmp  .out
.owed:
    mov  byte [rel gd_stage_why], GD_WHY_OWED
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; gd_stage_still_ours(EDI=slot) -> EAX=1 when D may still be shown: the same
; START (VM's helper returns the same span and generation, VM-C2), the same
; window and session, unlocked, still the top visible window with no overlay,
; the same framebuffer, and the pair intact. Nothing here yields.
gd_stage_still_ours:
    push rbx
    mov  ebx, edi
    call guestdisplay_capture_span
    test rax, rax
    jz   .no
    cmp  rdx, GD_STAGE_LEN
    jne  .no
    cmp  rax, [rel gd_stage_src]
    jne  .no
    cmp  ecx, [rel gd_stage_start]
    jne  .no
    cmp  ebx, [rel gd_stage_slot]
    jne  .no
    cmp  ebx, [rel gd_slot]
    jne  .no
    mov  eax, [rel gd_opened_gen]
    cmp  eax, [rel gd_stage_gen]
    jne  .no
    mov  rax, [rel gd_window_epoch]
    cmp  rax, [rel gd_stage_window_epoch]
    jne  .no
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel gd_stage_epoch]
    jne  .no
    mov  rax, [rel vm_profile_active]
    cmp  rax, [rel gd_stage_profile]
    jne  .no
    mov  rax, [rel hv_ops_active]
    cmp  rax, [rel gd_stage_backend]
    jne  .no
    mov  rax, [rel hv_linux_region]
    cmp  rax, [rel gd_stage_region]
    jne  .no
    mov  rax, [rel hv_linux_region_capacity]
    cmp  rax, [rel gd_stage_capacity]
    jne  .no
    mov  rax, [rel hv_linux_ram]
    cmp  rax, [rel gd_stage_ram]
    jne  .no
    mov  rax, [rel hv_linux_ram_bytes]
    cmp  rax, [rel gd_stage_ram_bytes]
    jne  .no
    mov  eax, [rel vm_profile_dev_mask]
    cmp  eax, [rel gd_stage_devices]
    jne  .no
    mov  al, [rel keep_presentation_target]
    cmp  al, [rel gd_stage_target]
    jne  .no
    cmp  al, PRESENTATION_CLI
    je   .no
    call gd_locked
    test eax, eax
    jnz  .no
    call gd_window_ours
    test eax, eax
    jz   .no
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rbx*4], WM_VISIBLE
    jne  .no
    call wmx_paint_top_slot
    cmp  eax, ebx
    jne  .no
    call gd_overlay_open
    test eax, eax
    jnz  .no
    mov  rax, [rel fb_base]
    cmp  rax, [rel gd_stage_fb]
    jne  .no
    mov  rax, [rel fb_size]
    cmp  rax, [rel gd_stage_fbsize]
    jne  .no
    mov  rax, [rel fb_shadow_base]
    cmp  rax, [rel gd_stage_shadow]
    jne  .no
    mov  rax, [rel fb_scanout_base]
    cmp  rax, [rel gd_stage_scanout]
    jne  .no
    mov  rax, [rel fb_shadow_cap]
    cmp  rax, [rel gd_stage_shadow_cap]
    jne  .no
    mov  eax, [rel fb_width]
    cmp  eax, [rel gd_stage_fbw]
    jne  .no
    mov  eax, [rel fb_height]
    cmp  eax, [rel gd_stage_fbh]
    jne  .no
    mov  eax, [rel fb_stride]
    cmp  eax, [rel gd_stage_fbs]
    jne  .no
    lea  rdx, [rel wm_owner]
    mov  rax, [rdx + rbx*8]
    cmp  rax, [rel gd_stage_win_owner]
    jne  .no
    lea  rdx, [rel wm_x]
    mov  eax, [rdx + rbx*4]
    cmp  eax, [rel gd_stage_wx]
    jne  .no
    lea  rdx, [rel wm_y]
    mov  eax, [rdx + rbx*4]
    cmp  eax, [rel gd_stage_wy]
    jne  .no
    lea  rdx, [rel wm_w]
    mov  eax, [rdx + rbx*4]
    cmp  eax, [rel gd_stage_ww]
    jne  .no
    lea  rdx, [rel wm_h]
    mov  eax, [rdx + rbx*4]
    cmp  eax, [rel gd_stage_wh]
    jne  .no
    call gd_stage_pair_ok
    test eax, eax
    jz   .no
    mov  rdi, [rel gd_stage_src]
    call gd_stage_guest_apart
    test eax, eax
    jz   .no
    call gd_stage_surface_ok
    test eax, eax
    jz   .no
    mov  rax, [rel fb_surface_epoch]
    cmp  rax, -1
    je   .no
    cmp  rax, [rel gd_stage_pub_epoch]
    jne  .no                               ; foreign composition revokes EVERY phase
    call gd_stage_plan_ok
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; Packed bounding source shape derived from the common fitted viewport.
gd_stage_shape:
    mov  r8, [rel gd_stage_view + GV_OX]
    mov  r9, [rel gd_stage_view + GV_OY]
    mov  r10, [rel gd_stage_view + GV_OW]
    mov  r11, [rel gd_stage_view + GV_OH]
    mov  rcx, [rel gd_stage_view + GV_SX]
    mov  rdx, [rel gd_stage_view + GV_SY]
    mov  rax, [rel gd_stage_view + GV_SW]
    imul rax, [rel gd_stage_view + GV_SH]
    shl  rax, 2
    ret

; Re-derive instead of trusting writable lengths, pitches or coordinates.
; Full64 equality rejects truncated/corrupt plans before capture/COPY/display.
gd_stage_plan_ok:
    sub  rsp, GV_BYTES
    mov  edi, [rel gd_stage_slot]
    mov  rsi, rsp
    call gd_view
    mov  rsi, rsp
    lea  rdi, [rel gd_stage_view]
    mov  ecx, GV_BYTES/8
    cld
    repe cmpsq
    lea  rsp, [rsp + GV_BYTES]
    jne  .no
    call gd_stage_shape
    cmp  rax, [rel gd_stage_len]
    jne  .no
    cmp  r8, [rel gd_stage_px]
    jne  .no
    cmp  r9, [rel gd_stage_py]
    jne  .no
    cmp  r10, [rel gd_stage_pw]
    jne  .no
    cmp  r11, [rel gd_stage_ph]
    jne  .no
    cmp  rcx, [rel gd_stage_sx]
    jne  .no
    cmp  rdx, [rel gd_stage_sy]
    jne  .no
    mov  rdx, [rel gd_stage_view + GV_SW]
    shl  rdx, 2
    cmp  rdx, [rel gd_stage_pitch]
    jne  .no
    lea  rdx, [rax + GD_STAGE_CHUNK - 1]
    shr  rdx, 11
    cmp  rdx, [rel gd_stage_chunks]
    jne  .no
    mov  rdx, rax
    and  edx, GD_STAGE_CHUNK - 1
    test rdx, rdx
    jnz  .tail
    test rax, rax
    jz   .tail
    mov  edx, GD_STAGE_CHUNK
.tail:
    cmp  rdx, [rel gd_stage_tail]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Progressive publication: at most ONE clipped row fragment <=800 pixels. The
; composed write <=3200B, immediate scanout copy <=3200B, cursor <=16 pixels
; (64B): <=6464 payload-write bytes/tick, one damage call, no union/flush loop.
; READY sets up a plan; PRESENT advances every idle tick. D remains immutable.
; All checks and both writes are in one BSP noyield bracket. Another painter's
; damage/attach/full present invalidates the plan before its next row. Completed
; rows are already current-owner pixels, not deferred damage from a former owner.
; Existing WM close/move/lock redraw owns erasure; no old plan is resumed.
gd_stage_publish:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    call gd_stage_still_ours
    test eax, eax
    jz   .discard
    call gd_stage_surface_ok
    test eax, eax
    jz   .discard
    mov  rax, [rel fb_surface_epoch]
    cmp  rax, -1
    je   .discard
    cmp  rax, [rel gd_stage_pub_epoch]
    jne  .discard
    cmp  byte [rel cadence_batch_depth], 0
    jne  .out                              ; never add a row to a larger batch union
    cmp  byte [rel fb_present_valid], 0
    jne  .out                              ; leave another painter's pending damage alone
    cmp  byte [rel dpms_blanked], 0
    jne  .out                              ; do not accumulate unpresented staged rows
    mov  r14, [rel gd_stage_pw]
    imul r14, [rel gd_stage_ph]             ; full64 output pixel count
    mov  r15, [rel gd_stage_pub_row]         ; linear output cursor, not a row index
    cmp  r15, r14
    jae  .discard
    lea  rdi, [rel gd_stage_view]
    mov  rsi, [rel gd_stage_d]
    mov  rdx, [rel gd_stage_pitch]
    mov  rcx, [rel gd_stage_sx]
    mov  r8, [rel gd_stage_sy]
    mov  r9, r15
    call gd_render                         ; <=800 pixels even for a huge scaled row
    test rax, rax
    jz   .discard
    add  r15, rax
    mov  [rel gd_stage_pub_row], r15
    call fb_damage_rect                    ; immediate bounded fragment, no batch union
    mov  rax, [rel fb_surface_epoch]
    mov  [rel gd_stage_pub_epoch], rax
    cmp  r15, r14
    jne  .out
.complete:
    inc  qword [rel gd_stage_published]
    inc  dword [rel gd_blits]
    mov  byte [rel gd_stage_why], 0
    mov  byte [rel gd_stage_state], GD_ST_IDLE
    jmp  .out
.discard:
    call gd_stage_discard                  ; later bounded scrub, no publication debt
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate actual current direct/attached surfaces before any staged row.
; Existing fb_present_rect/cursor use 32-bit pixel indices: conservatively refuse
; modes with >UINT32_MAX pixels rather than silently truncating those consumers.
; Exact identities/capacities were captured with the window context. Allocation
; and mapping custody comes from the existing GOP/shadow owners, not these bounds.
gd_stage_surface_ok:
    mov  rdi, [rel gd_stage_src]
; RDI=proven live DISPLAY base; no staged scratch mutation for composition.
gd_draw_surface_ok:
    push r13
    mov  r13, rdi
    push rbx
    push r12
    mov  eax, [rel fb_width]
    test eax, eax
    jle  .no
    mov  ecx, [rel fb_height]
    test ecx, ecx
    jle  .no
    mov  ebx, [rel fb_stride]
    cmp  ebx, eax
    jb   .no
    imul rbx, rcx
    mov  eax, 0xFFFFFFFF
    cmp  rbx, rax
    ja   .no
    shl  rbx, 2
    cmp  rbx, [rel fb_size]
    ja   .no
    mov  rdi, [rel fb_base]
    mov  rsi, rbx
    call gd_stage_surface_span
    test eax, eax
    jz   .no
    cmp  qword [rel fb_scanout_base], 0
    je   .yes                             ; existing direct-mode owner
    mov  rax, [rel fb_base]
    cmp  rax, [rel fb_shadow_base]
    jne  .no                              ; scratch/redirection is not a display grant
    cmp  rbx, [rel fb_shadow_cap]
    ja   .no
    call .front_bytes
    mov  rdi, [rel fb_scanout_base]
    mov  rsi, rax
    call gd_stage_surface_span
    test eax, eax
    jz   .no
    call .front_bytes
    add  rax, [rel fb_scanout_base]
    cmp  rax, [rel fb_base]
    jbe  .yes
    mov  rax, [rel fb_base]
    add  rax, rbx
    cmp  rax, [rel fb_scanout_base]
    ja   .no                              ; attached front/shadow must be disjoint
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    pop  r13
    ret
; RAX = bytes of the attached scanout: the surface (RBX), or the whole mode while the
; GUI composes 2x (RCQ-16 fb_scale=2). Clobbers RCX.
.front_bytes:
    mov  rax, rbx
    cmp  byte [rel fb_scale], 2
    jne  .front_out
    mov  eax, [rel fb_out_stride]
    mov  ecx, [rel fb_out_height]
    imul rax, rcx
    shl  rax, 2
.front_out:
    ret

; RDI/RSI surface span: canonical endpoints in one half, no wrap, apart from
; private staging and both the VM reservation and its raw control/RAM/DISPLAY.
gd_stage_surface_span:
    test rdi, rdi
    jz   .no
    mov  rax, rdi
    add  rax, rsi
    jc   .no
    mov  r12, rax                          ; exclusive surface end
    dec  rax
    mov  rcx, rax
    shl  rcx, 16
    sar  rcx, 16
    cmp  rcx, rax
    jne  .no
    xor  rax, rdi
    bt   rax, 47
    jc   .no
    mov  rax, rdi
    shl  rax, 16
    sar  rax, 16
    cmp  rax, rdi
    jne  .no
    call gd_stage_apart
    test eax, eax
    jz   .no
    mov  rax, [rel hv_linux_region]
    mov  rcx, rax
    add  rcx, [rel hv_linux_region_capacity]
    jc   .no
    cmp  r12, rax
    jbe  .raw
    cmp  rdi, rcx
    jb   .no
.raw:
    mov  rax, [rel hv_linux_ram]
    sub  rax, HV_LINUX_CTRL_BYTES
    jc   .no
    mov  rcx, r13
    add  rcx, [rel hv_linux_fb_bytes]
    jc   .no
    cmp  r12, rax
    jbe  .yes
    cmp  rdi, rcx
    jb   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; gd_stage_pair_ok -> EAX=1 while the pair is still the one block kmalloc gave
; this owner: S and D at their fixed offsets, the whole block inside the native
; heap, all four canaries intact, and apart from the framebuffer and its shadow
; region. (Other heap owners, the GWS slab among them, hold other kmalloc
; blocks, which the bump allocator never overlaps.)
gd_stage_pair_ok:
    call gd_stage_pair_span
    test eax, eax
    jz   .out
    mov  rdx, [rel gd_stage_blk]
    xor  eax, eax
    mov  r8, GD_STAGE_CANARY
    cmp  [rdx], r8
    jne  .out
    cmp  [rdx + 8], r8
    jne  .out
    cmp  [rdx + GD_STAGE_S_OFF + GD_STAGE_LEN], r8
    jne  .out
    cmp  [rdx + GD_STAGE_S_OFF + GD_STAGE_LEN + 8], r8
    jne  .out
    cmp  [rdx + GD_STAGE_D_OFF - 16], r8
    jne  .out
    cmp  [rdx + GD_STAGE_D_OFF - 8], r8
    jne  .out
    cmp  [rdx + GD_STAGE_D_OFF + GD_STAGE_LEN], r8
    jne  .out
    cmp  [rdx + GD_STAGE_D_OFF + GD_STAGE_LEN + 8], r8
    jne  .out
    mov  eax, 1
.out:
    ret

; Full64 bounds BEFORE any dereference, including guard initialization.
; Native heap custody is trusted bump allocation; geometry alone is not a grant.
gd_stage_pair_span:
    xor  eax, eax
    mov  rdx, [rel gd_stage_blk]
    test rdx, rdx
    jz   .no
    lea  rcx, [rdx + GD_STAGE_S_OFF]
    cmp  rcx, [rel gd_stage_s]
    jne  .no
    lea  rcx, [rdx + GD_STAGE_D_OFF]
    cmp  rcx, [rel gd_stage_d]
    jne  .no
    cmp  rdx, [rel heap_base]
    jb   .no
    mov  rcx, rdx
    add  rcx, GD_STAGE_BYTES
    jc   .no
    mov  r8, [rel heap_base]
    add  r8, [rel heap_size]                ; reject extent wrap before using its end
    jc   .no
    cmp  rcx, r8
    ja   .no
    mov  r8, rdx
    shl  r8, 16
    sar  r8, 16
    cmp  r8, rdx
    jne  .no
    dec  rcx                               ; last byte, same canonical half
    mov  r8, rcx
    shl  r8, 16
    sar  r8, 16
    cmp  r8, rcx
    jne  .no
    xor  rcx, rdx
    bt   rcx, 47
    jc   .no
    mov  eax, [rel fb_stride]               ; pixels
    mov  ecx, [rel fb_height]
    imul rax, rcx
    mov  r8, rax
    shr  r8, 62
    jnz  .no
    shl  rax, 2
    mov  rsi, rax
    mov  rdi, [rel fb_base]
    call gd_stage_apart
    test eax, eax
    jz   .no
    mov  rdi, [rel fb_scanout_base]
    test rdi, rdi
    jz   .shadow
    cmp  byte [rel fb_scale], 2
    jne  .front_apart
    mov  eax, [rel fb_out_stride]          ; RCQ-16 2x GUI: the scanout keeps the whole mode
    mov  esi, [rel fb_out_height]
    imul rsi, rax
    shl  rsi, 2
.front_apart:
    call gd_stage_apart                    ; no private scrub/capture may alias front
    test eax, eax
    jz   .no
.shadow:
    mov  rdi, [rel fb_shadow_base]
    mov  rsi, [rel fb_shadow_cap]
    call gd_stage_apart
    test eax, eax
    jz   .no
    mov  rdi, [rel fb_shadow_region_base]
    mov  rsi, [rel fb_shadow_region_size]
    jmp  gd_stage_apart
.no:
    xor  eax, eax
.out:
    ret

; gd_stage_guest_apart(RDI=DISPLAY base) -> EAX=1 when the pair is apart from
; the whole guest reservation: control pages, guest RAM and the DISPLAY carve,
; [hv_linux_ram - HV_LINUX_CTRL_BYTES, DISPLAY + hv_linux_fb_bytes). Every
; RAM-backed EPT/NPT leaf of a START the helper accepts maps inside it (VM census).
gd_stage_guest_apart:
    mov  eax, 1
    cmp  qword [rel hv_linux_region], 0     ; RC-speed-reserve: no span held, nothing to overlap
    je   .out
    push rdi
    mov  rdi, [rel hv_linux_region]
    mov  rsi, [rel hv_linux_region_capacity]
    call gd_stage_apart
    pop  rdi
    test eax, eax
    jz   .no
    mov  rax, [rel hv_linux_ram]
    sub  rax, HV_LINUX_CTRL_BYTES
    jc   .no
    mov  rsi, rdi
    add  rsi, [rel hv_linux_fb_bytes]
    jc   .no
    sub  rsi, rax
    jc   .no
    mov  rdi, rax
    jmp  gd_stage_apart
.no:
    xor  eax, eax
.out:
    ret

; gd_stage_apart(RDI=base, RSI=bytes) -> EAX=1 when [base, base+bytes) does not
; overlap the staging block. An empty range is apart; a range that wraps is not.
; The block end has no carry (gd_stage_pair_ok).
gd_stage_apart:
    mov  eax, 1
    test rsi, rsi
    jz   .out
    mov  rcx, rdi
    add  rcx, rsi
    jc   .no
    mov  rdx, [rel gd_stage_blk]
    cmp  rcx, rdx
    jbe  .out                               ; ends before the block
    add  rdx, GD_STAGE_BYTES
    cmp  rdi, rdx
    jae  .out                               ; starts after it
.no:
    xor  eax, eax
.out:
    ret

; Housekeeping advances ONE phase; gd_stage_worked also blocks refresh on this
; tick. No loop polls retirement. Abandoned context never reaches publication.
gd_stage_housekeep:
    cld
    movzx eax, byte [rel gd_stage_state]
    cmp  eax, GD_ST_PRESENT
    je   .present
    cmp  eax, GD_ST_SCRUB
    je   gd_stage_scrub
    cmp  eax, GD_ST_QUARANTINED
    je   .quarantined
    cmp  eax, GD_ST_RUNNING
    je   .running
    cmp  eax, GD_ST_CAPTURE
    je   .capture
    cmp  eax, GD_ST_BEGIN
    je   .begin
    cmp  eax, GD_ST_READY
    je   .check
    cmp  eax, GD_ST_IDLE
    jne  .out
    cmp  byte [rel gd_stage_dirty], 0
    je   .out
.check:
    mov  edi, [rel gd_stage_slot]
    call gd_stage_still_ours
    test eax, eax
    jz   gd_stage_discard
.out:
    ret
.present:
    mov  byte [rel gd_stage_worked], 1
    mov  edi, [rel gd_stage_slot]
    jmp  gd_stage_publish                   ; one row, no refresh throttle or phase stacking
.capture:
    mov  byte [rel gd_stage_worked], 1
    mov  edi, [rel gd_stage_slot]
    call gd_stage_still_ours                 ; all leaf checks through the read: no yield
    test eax, eax
    jz   gd_stage_discard
    mov  r8, [rel gd_stage_cursor]           ; packed byte offset, full64
    cmp  r8, [rel gd_stage_len]
    jae  gd_stage_discard
    mov  rcx, [rel gd_stage_pitch]           ; independently checked positive row bytes
    test rcx, rcx
    jz   gd_stage_discard
    mov  rax, r8
    xor  edx, edx
    div  rcx
    test rdx, rdx
    jnz  gd_stage_discard                   ; cursor must begin an exact packed row
    cmp  rax, [rel gd_stage_view + GV_SH]
    jae  gd_stage_discard
    add  rax, [rel gd_stage_sy]
    imul rax, VP_FB_STRIDE
    mov  rdx, [rel gd_stage_sx]
    lea  rsi, [rax + rdx*4]                 ; full source row pitch stays3200B
    lea  rax, [rsi + rcx]
    cmp  rax, GD_STAGE_LEN
    ja   gd_stage_discard
    add  rsi, [rel gd_stage_src]            ; full source mapping proven every tick
    mov  rdi, [rel gd_stage_s]
    add  rdi, r8
    add  r8, rcx
    cmp  r8, [rel gd_stage_len]
    ja   gd_stage_discard
    mov  [rel gd_stage_cursor], r8
    shr  rcx, 2
    cld
    rep  movsd                              ; one packed row <=3200B, no tiny-row loop
    mov  byte [rel gd_stage_dirty], 1
    mov  rax, [rel gd_stage_cursor]
    cmp  rax, [rel gd_stage_len]
    jne  .out
    mov  byte [rel gd_stage_state], GD_ST_BEGIN  ; freeze S, no COPY on this tick
    ret
.begin:
    mov  byte [rel gd_stage_worked], 1
    mov  edi, [rel gd_stage_slot]
    call gd_stage_still_ours
    test eax, eax
    jz   gd_stage_discard
    sub  rsp, SMP_PF_CTX_SZ + 8
    mov  rax, [rel gd_stage_d]
    mov  [rsp + SMP_PF_CTX_DST], rax
    mov  rax, [rel gd_stage_s]
    mov  [rsp + SMP_PF_CTX_SRC], rax
    mov  rax, [rel gd_stage_len]
    mov  [rsp + SMP_PF_CTX_LEN], rax
    mov  qword [rsp + SMP_PF_CTX_CHUNK], GD_STAGE_CHUNK
    mov  qword [rsp + SMP_PF_CTX_FILL], 0
    call time_monotonic_now_us
    mov  r8, rax
    mov  r9, rax
    add  r9, GD_STAGE_BUDGET_US
    jc   .begin_refused
    lea  rcx, [rel gd_stage_blk]
    mov  edi, SMP_PF_BODY_COPY
    mov  rsi, rsp
    mov  rdx, [rel gd_stage_chunks]
    call smp_par_begin
    jc   .begin_refused
    mov  [rel gd_stage_job], rax
    inc  qword [rel gd_stage_jobs]
    mov  byte [rel gd_stage_state], GD_ST_RUNNING
    add  rsp, SMP_PF_CTX_SZ + 8
    ret
.begin_refused:
    add  rsp, SMP_PF_CTX_SZ + 8
    jmp  gd_stage_discard                   ; acquired no job; later bounded cleanup
.running:
    mov  byte [rel gd_stage_worked], 1
    mov  edi, [rel gd_stage_slot]
    call gd_stage_still_ours
    test eax, eax
    jz   .cancel
    call time_monotonic_now_us
    mov  rdx, rax
    mov  rdi, [rel gd_stage_job]
    lea  rsi, [rel gd_stage_blk]
    call smp_par_step                       ; <=4 chunks/8192B, no join/yield
    cmp  eax, SMP_PC_PENDING
    je   .out
    cmp  eax, SMP_PC_COMPLETE
    jne  .cancel
    cmp  edx, 1
    jne  .cancel
    mov  rdi, [rel gd_stage_job]
    lea  rsi, [rel gd_stage_blk]
    call smp_par_release
    test eax, eax
    jz   .cancel
    mov  byte [rel gd_stage_state], GD_ST_READY
    ret                                    ; presentation on a later tick
.cancel:
    mov  rdi, [rel gd_stage_job]
    lea  rsi, [rel gd_stage_blk]
    call smp_par_cancel
    mov  byte [rel gd_stage_state], GD_ST_QUARANTINED
    mov  byte [rel gd_stage_why], GD_WHY_CF1
    inc  qword [rel gd_stage_dropped]
    ret                                    ; even immediate retirement handled later
.quarantined:
    mov  byte [rel gd_stage_worked], 1
    mov  rdi, [rel gd_stage_job]
    lea  rsi, [rel gd_stage_blk]
    call smp_par_status
    cmp  edx, 1
    jne  .out
    mov  rdi, [rel gd_stage_job]
    lea  rsi, [rel gd_stage_blk]
    call smp_par_release
    test eax, eax
    jz   .out
    jmp  gd_stage_discard                   ; actual retirement precedes any scrub

; No outstanding owned job may enter this transition. Caller cancels/releases
; RUNNING first. Invalidating capture/READY/IDLE never writes a private byte.
gd_stage_discard:
    mov  byte [rel gd_stage_worked], 1
    mov  byte [rel gd_stage_state], GD_ST_SCRUB
    mov  byte [rel gd_stage_why], GD_WHY_STALE
    mov  qword [rel gd_stage_cursor], 0
    inc  qword [rel gd_stage_dropped]
    ret

; Cleanup uses current private custody and disjointness, not the abandoned
; presentation identity. Thus lock/STOP/new START can be scrubbed safely. A live
; mapping is checked if present; raw current reservation is checked even after
; reset/failed map. Malformed custody/alias refuses ALL writes and pins forever.
gd_stage_scrub:
    mov  byte [rel gd_stage_worked], 1
    call gd_stage_pair_ok
    test eax, eax
    jz   .not_ours
    call guestdisplay_capture_span          ; current mapped authority, may be revoked
    test rax, rax
    jnz  .guest
    mov  rax, [rel hv_linux_ram]
    add  rax, [rel hv_linux_ram_bytes]
    jc   .not_ours
.guest:
    mov  rdi, rax
    call gd_stage_guest_apart
    test eax, eax
    jz   .not_ours
    mov  rdx, [rel gd_stage_cursor]
    cmp  rdx, 2 * GD_STAGE_LEN
    jae  .not_ours
    test dl, 7
    jnz  .not_ours
    mov  rdi, [rel gd_stage_s]
    mov  ecx, GD_STAGE_LEN
    cmp  rdx, GD_STAGE_LEN
    jb   .half
    sub  rdx, GD_STAGE_LEN
    mov  rdi, [rel gd_stage_d]
.half:
    sub  rcx, rdx
    cmp  rcx, GD_STAGE_TICK_BYTES
    jbe  .size
    mov  ecx, GD_STAGE_TICK_BYTES
.size:
    add  [rel gd_stage_cursor], rcx
    add  rdi, rdx
    shr  rcx, 3
    xor  eax, eax
    cld
    rep  stosq                              ; ONE half's <=8192B, guard cells untouched
    cmp  qword [rel gd_stage_cursor], 2 * GD_STAGE_LEN
    jne  .out
    inc  qword [rel gd_stage_scrubs]
    mov  byte [rel gd_stage_dirty], 0
    mov  byte [rel gd_stage_state], GD_ST_IDLE
    mov  qword [rel gd_stage_job], 0
    mov  qword [rel gd_stage_src], 0         ; cannot accidentally present discarded data
.out:
    ret
.not_ours:
    mov  byte [rel gd_stage_state], GD_ST_DISABLED
    mov  byte [rel gd_stage_why], GD_WHY_PAIR
    ret

; guest_desktop_pointer(EDI=x, ESI=y, EDX=buttons, ECX=previous buttons as the
; WM recorded them) -> EAX=1 when the guest consumed the event (the WM must not
; act on it). Preserves RBX, R12-R15.
guest_desktop_pointer:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, GV_BYTES
    movsxd r12, edi
    movsxd r13, esi
    mov  r14d, edx
    mov  ebx, ecx
    movzx r15d, byte [rel gd_ptr_owner]
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .no                                ; injected events cannot release human custody
    cmp  byte [rel wm_pointer_mode], 0
    jne  .no                                ; existing PaOS gestures take precedence
    call gd_window_ours
    test eax, eax
    jz   .revoke
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .revoke
    cmp  byte [rel hv_linux_running], 1
    jne  .revoke
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gd_opened_gen]
    jne  .revoke
    call guestinput_release_blocked
    test eax, eax
    jnz  .revoke
    cmp  byte [rel gi_live], 1
    jne  .revoke
    call gd_locked
    test eax, eax
    jnz  .revoke
    call gd_overlay_open
    test eax, eax
    jnz  .revoke
    cmp  byte [rel gd_capture], 1
    jne  .geometry
    call gd_capture_valid
    test eax, eax
    jz   .revoke
.geometry:
    mov  edi, [rel gd_slot]
    lea  rax, [rel wm_state]
    cmp  dword [rax + rdi*4], WM_VISIBLE
    jne  .revoke
    mov  rsi, rsp
    call gd_view
    cmp  qword [rsp + GV_OW], 0
    je   .revoke
    test r15d, r15d
    jz   .hit
    ; The original human drag owns motion/all-up, including outside content,
    ; but never survives a resize/move, owner, START, authority or occlusion.
    mov  rsi, rsp
    lea  rdi, [rel gd_ptr_view]
    mov  ecx, GV_BYTES/8
    cld
    repe cmpsq
    jne  .revoke
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gd_ptr_start]
    jne  .revoke
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel gd_ptr_epoch]
    jne  .revoke
    mov  ecx, [rel gd_slot]
    lea  rax, [rel wm_owner]
    mov  rax, [rax + rcx*8]
    cmp  rax, [rel gd_ptr_win_owner]
    jne  .revoke
    call wmx_paint_top_slot
    cmp  eax, [rel gd_slot]
    jne  .revoke
    jmp  .deliver
.hit:
    ; Only clipped fitted pixels are guest authority. Letterbox, taskbar and
    ; chrome cannot start capture, even when keyboard capture already exists.
    mov  rax, r12
    sub  rax, [rsp + GV_OX]
    js   .no
    cmp  rax, [rsp + GV_OW]
    jae  .no
    mov  rax, r13
    sub  rax, [rsp + GV_OY]
    js   .no
    cmp  rax, [rsp + GV_OH]
    jae  .no
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    cmp  eax, [rel gd_slot]
    jne  .no
    ; A new human left press belongs to existing PaOS caption/resize chrome
    ; before guest delivery, including when keyboard capture is already set.
    ; Owned drags bypass .hit above: they retain motion/all-up at the border.
    test r14d, 1
    jz   .content
    test ebx, 1
    jnz  .content
    mov  edi, [rel gd_slot]
    mov  esi, r12d
    mov  edx, r13d
    call wmx_caption_part_at
    test eax, eax
    jnz  .no
    mov  ecx, [rel gd_slot]
    lea  rax, [rel wm_maximized]
    cmp  byte [rax + rcx], 1
    je   .content
    lea  rax, [rel wm_resizable]
    cmp  byte [rax + rcx], 0
    je   .content
    mov  edi, ecx
    mov  esi, r12d
    mov  edx, r13d
    call wm_pointer_edge_zone
    test eax, eax
    jnz  .no
.content:
    cmp  byte [rel gd_capture], 1
    je   .deliver
    test r14d, 1
    jz   .no
    test ebx, 1
    jnz  .no
    mov  edi, [rel gd_slot]
    cmp  edi, [rel wm_focus]
    je   .focused
    call wmx_raise_slot
.focused:
    mov  byte [rel gd_capture], 1
    inc  dword [rel gd_captures]
    call gd_forget_paos_mods
.deliver:
    mov  rdi, r12
    mov  rsi, [rsp + GV_VX]
    mov  rdx, [rsp + GV_VW]
    mov  ecx, VP_FB_WIDTH
    call gd_axis
    mov  ebx, eax
    mov  rdi, r13
    mov  rsi, [rsp + GV_VY]
    mov  rdx, [rsp + GV_VH]
    mov  ecx, VP_FB_HEIGHT
    call gd_axis
    mov  edi, ebx
    mov  esi, eax
    mov  edx, r14d
    call guestinput_post_pointer
    test eax, eax
    jz   .failed                            ; queue refusal must not invent button custody
    add  [rel gd_ptr_sent], eax
    xor  eax, eax
    test r14d, 7
    setnz al
    mov  [rel gd_ptr_owner], al
    test eax, eax
    jz   .consumed
    mov  rsi, rsp
    lea  rdi, [rel gd_ptr_view]
    mov  ecx, GV_BYTES/8
    cld
    rep  movsq
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gd_ptr_start], eax
    mov  rax, [rel session_authority_epoch]
    mov  [rel gd_ptr_epoch], rax
    mov  ecx, [rel gd_slot]
    lea  rax, [rel wm_owner]
    mov  rax, [rax + rcx*8]
    mov  [rel gd_ptr_win_owner], rax
    jmp  .consumed
.failed:
    call gd_drop_capture                    ; existing whole release/retry owns queue pressure
.consumed:
    mov  eax, 1
    jmp  .out
.revoke:
    call gd_drop_capture
    mov  eax, r15d                          ; consume a revoked drag's terminating event
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, GV_BYTES
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; guest_desktop_wheel(EDI=signed32 notches, ESI=x, EDX=y) -> EAX=1 posted.
; The human wheel uses the existing signed8 notch range (+ away/up). High32
; argument bits have no meaning under this EDI ABI; no negation/ABS or loops.
; Unlike a left press, wheel never grants capture/focus. Require the existing
; human capture and its last successful pointer snapshot, even after all-up.
; A drag does not extend wheel authority beyond the current fitted content.
; Preserve full callee-saved registers, flags/DF and FP state.
guest_desktop_wheel:
    pushfq
    cld
    push rbx
    push r12
    push r13
    sub  rsp, GV_BYTES
    mov  ebx, edi
    movsxd r12, esi
    movsxd r13, edx
    test ebx, ebx
    jz   .no
    cmp  ebx, -128
    jl   .no
    cmp  ebx, 127
    jg   .no
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .no                            ; injected input cannot revoke human custody
    cmp  byte [rel wm_pointer_mode], 0
    jne  .no                            ; existing host gestures retain their input
    cmp  byte [rel gd_capture], 1
    jne  .no
    call gd_window_ours
    test eax, eax
    jz   .revoke
    cmp  byte [rel hv_linux_running], 1
    jne  .revoke
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .revoke
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gd_opened_gen]
    jne  .revoke
    cmp  eax, [rel gd_ptr_start]
    jne  .revoke
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel gd_ptr_epoch]
    jne  .revoke
    mov  ecx, [rel gd_slot]
    lea  rax, [rel wm_owner]
    mov  rax, [rax + rcx*8]
    cmp  rax, [rel gd_ptr_win_owner]
    jne  .revoke
    call gd_capture_valid               ; focus, visibility, lock, overlay, live, release
    test eax, eax
    jz   .no
    call guestdisplay_hva               ; actual current START/display/power reservation
    test rax, rax
    jz   .revoke
    mov  edi, [rel gd_slot]
    mov  rsi, rsp
    call gd_view
    mov  rsi, rsp
    lea  rdi, [rel gd_ptr_view]
    mov  ecx, GV_BYTES/8
    repe cmpsq
    jne  .revoke
    mov  rax, r12
    sub  rax, [rsp + GV_OX]
    js   .no
    cmp  rax, [rsp + GV_OW]
    jae  .no
    mov  rax, r13
    sub  rax, [rsp + GV_OY]
    js   .no
    cmp  rax, [rsp + GV_OH]
    jae  .no
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    cmp  eax, [rel gd_slot]
    jne  .no
    mov  edi, ebx
    call guestinput_post_wheel          ; whole REL_WHEEL+SYN, no retained wheel retry
    jmp  .out
.revoke:
    call gd_drop_capture               ; existing bounded all-up obligation owns release
.no:
    xor  eax, eax
.out:
    add  rsp, GV_BYTES
    pop  r13
    pop  r12
    pop  rbx
    popfq
    ret

; guest_desktop_key_byte(EDI=raw Set-1 byte) -> EAX=1 when the guest took it.
; Preserves RBX, R12, R13 (the router's byte and budget, K3).
guest_desktop_key_byte:
    push rbx
    movzx ebx, dil
    ; K1: a sequence the guest began is the guest's to finish, whatever happens
    ; to the capture meanwhile; the guest never starts inside one the router began.
    cmp  byte [rel gd_e0], 0
    jne  .in_sequence
    cmp  byte [rel gd_e1], 0
    jne  .in_sequence
    cmp  byte [rel gd_capture], 1
    jne  .no
    cmp  byte [rel input_kbd_e0], 0
    jne  .no
    cmp  byte [rel input_kbd_e1], 0
    jne  .no
    call gd_capture_valid
    test eax, eax
    jz   .no
    jmp  .decode
.in_sequence:
    call gd_capture_valid
    test eax, eax
    jnz  .decode
    cmp  byte [rel gd_e1], 0                ; capture ended mid-sequence: finish it unseen
    je   .end_e0
    mov  byte [rel gd_pause_valid], 0
    dec  byte [rel gd_e1]
    jmp  .took
.end_e0:
    mov  byte [rel gd_e0], 0
    ; F5: a Win press after a guest-taken E0 is still Win (K4): the router gets
    ; it as the E0 sequence it is, so Win+L never degrades into a bare 'l'.
    test ebx, 0x80
    jnz  .took
    mov  ecx, ebx
    cmp  ecx, 0x5B
    je   .win_to_router
    cmp  ecx, 0x5C
    jne  .took
.win_to_router:
    mov  byte [rel input_kbd_e0], 1
    jmp  .no
.decode:
    cmp  byte [rel gd_e1], 0
    je   .no_e1
    ; Exactly five suffix bytes belong to the guest after E1, even if
    ; malformed or capture is lost. They never become Ctrl/NumLock/Win input.
    movzx ecx, byte [rel gd_e1]
    lea  rdx, [rel gd_pause_suffix - 1]
    cmp  bl, [rdx + rcx]
    je   .pause_byte
    mov  byte [rel gd_pause_valid], 0
.pause_byte:
    dec  byte [rel gd_e1]
    jnz  .took
    cmp  byte [rel gd_pause_valid], 1
    jne  .took
    mov  byte [rel gd_pause_valid], 0       ; no retained tap or retry
    call gd_pause_current
    test eax, eax
    jz   .took
    call guestinput_post_pause
    add  eax, eax                          ; two key transitions in one accepted tap
    add  [rel gd_keys_sent], eax
    jmp  .took
.no_e1:
    cmp  ebx, 0xE1
    jne  .not_e1
    mov  byte [rel gd_e1], 5
    call gd_pause_pin
    jmp  .took
.not_e1:
    cmp  ebx, 0xE0
    jne  .not_e0
    mov  byte [rel gd_e0], 1
    jmp  .took
.not_e0:
    mov  ecx, ebx
    and  ecx, 0x7F                          ; scan code
    cmp  byte [rel gd_e0], 0
    je   .plain
    mov  byte [rel gd_e0], 0
    cmp  ecx, 0x5B
    je   .win
    cmp  ecx, 0x5C
    je   .win
    lea  rdx, [rel gd_e0_map]
    movzx eax, byte [rdx + rcx]             ; 0: no Linux key (incl. fake shifts)
    cmp  ecx, 0x1D
    jne  .mapped
    lea  rdx, [rel gd_rctrl]
    jmp  .ctrl
.plain:
    cmp  ecx, 0x54                         ; plain SysRq (Alt+PrintScreen), not KEY_84
    je   .sysrq
    xor  eax, eax
    cmp  ecx, 0x58                          ; Set-1 1..0x58 == Linux KEY_ESC..KEY_F12
    ja   .mapped
    mov  eax, ecx
    cmp  ecx, 0x1D
    jne  .mapped
    lea  rdx, [rel gd_lctrl]
    jmp  .ctrl
.sysrq:
    mov  eax, 99                           ; same KEY_SYSRQ as E0 37 / B7
    jmp  .mapped
.ctrl:
    xor  r8d, r8d
    test ebx, 0x80
    setz r8b
    mov  [rdx], r8b
.mapped:
    test eax, eax
    jz   .took
    mov  edi, eax
    xor  esi, esi                           ; release
    test ebx, 0x80
    jnz  .post
    mov  esi, 1                             ; press, or 2 if the guest has it held
    lea  rdx, [rel gi_keys_down]
    bt   [rdx], eax
    jnc  .post
    mov  esi, 2
.post:
    call guestinput_post_key
    add  [rel gd_keys_sent], eax
    ; Release chord: both Ctrl keys held. The guest sees both go up.
    cmp  byte [rel gd_lctrl], 1
    jne  .took
    cmp  byte [rel gd_rctrl], 1
    jne  .took
    call gd_drop_capture
.took:
    mov  eax, 1
    pop  rbx
    ret
.win:
    ; K4: Win is PaOS's. A press ends the capture and goes to the router as the
    ; E0 sequence it is: the router's prefix state is set exactly as if it had
    ; read the E0 itself, so this byte is Win, never a bare scan code. A release
    ; is one the guest never saw pressed (PaOS forgot Win at capture start).
    test ebx, 0x80
    jnz  .took
    call gd_drop_capture
    mov  byte [rel input_kbd_e0], 1
.no:
    xor  eax, eax
    pop  rbx
    ret

; Only one bounded E1 sequence is retained; no guest pointer is dereferenced.
gd_pause_pin:
    mov  byte [rel gd_pause_valid], 0
    call gd_window_ours
    test eax, eax
    jz   .out
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gd_pause_start], eax
    mov  eax, [rel gd_slot]
    mov  [rel gd_pause_slot], eax
    mov  rax, [rel gi_owner_epoch]
    mov  [rel gd_pause_input_epoch], rax
    mov  rax, [rel gd_window_epoch]
    mov  [rel gd_pause_window_epoch], rax
    mov  rax, [rel session_authority_epoch]
    mov  [rel gd_pause_authority], rax
    mov  rax, [rel hv_linux_region]
    mov  [rel gd_pause_region], rax
    mov  rax, [rel hv_linux_ram]
    mov  [rel gd_pause_ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rel gd_pause_bytes], rax
    mov  rax, [rel vm_profile_active]
    mov  [rel gd_pause_profile], rax
    mov  rax, [rel hv_ops_active]
    mov  [rel gd_pause_backend], rax
    mov  ecx, [rel gd_slot]
    lea  rdx, [rel wm_owner]
    mov  rax, [rdx + rcx*8]
    mov  [rel gd_pause_owner], rax
    mov  byte [rel gd_pause_valid], 1
.out:
    ret

gd_pause_current:
    call gd_window_ours
    test eax, eax
    jz   .no
    cmp  byte [rel hv_linux_running], 1
    jne  .no
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gd_pause_start]
    jne  .no
    mov  eax, [rel gd_slot]
    cmp  eax, [rel gd_pause_slot]
    jne  .no
    mov  rax, [rel gi_owner_epoch]
    cmp  rax, [rel gd_pause_input_epoch]
    jne  .no
    mov  rax, [rel gd_window_epoch]
    cmp  rax, [rel gd_pause_window_epoch]
    jne  .no
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel gd_pause_authority]
    jne  .no
    mov  rax, [rel hv_linux_region]
    cmp  rax, [rel gd_pause_region]
    jne  .no
    mov  rax, [rel hv_linux_ram]
    cmp  rax, [rel gd_pause_ram]
    jne  .no
    mov  rax, [rel hv_linux_ram_bytes]
    cmp  rax, [rel gd_pause_bytes]
    jne  .no
    mov  rax, [rel vm_profile_active]
    cmp  rax, [rel gd_pause_profile]
    jne  .no
    mov  rax, [rel hv_ops_active]
    cmp  rax, [rel gd_pause_backend]
    jne  .no
    mov  ecx, [rel gd_slot]
    lea  rdx, [rel wm_owner]
    mov  rax, [rdx + rcx*8]
    cmp  rax, [rel gd_pause_owner]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Index by remaining suffix count (5..1), hence reversed wire order.
gd_pause_suffix: db 0xC5, 0x9D, 0xE1, 0x45, 0x1D

; E0-prefixed Set-1 scan code -> Linux key code (0 = none).
gd_e0_map:
    times 0x1C db 0
    db 96                                   ; 1C KP Enter
    db 97                                   ; 1D Right Ctrl
    times 0x35 - 0x1E db 0
    db 98                                   ; 35 KP /
    db 0
    db 99                                   ; 37 PrtSc / SysRq
    db 100                                  ; 38 Right Alt
    times 0x47 - 0x39 db 0
    db 102, 103, 104, 0                     ; 47 Home, 48 Up, 49 PgUp, 4A -
    db 105, 0, 106, 0                       ; 4B Left, 4C -, 4D Right, 4E -
    db 107, 108, 109, 110, 111              ; 4F End, 50 Down, 51 PgDn, 52 Ins, 53 Del
    times 0x5B - 0x54 db 0
    db 125, 126, 127                        ; 5B LMeta, 5C RMeta, 5D Menu
    times 0x80 - 0x5E db 0
%if $ - gd_e0_map != 0x80
    %error "gd_e0_map must cover every scan code"
%endif

str_gd_title: db "Linux_desktop", 0

%include "core/abi/wdata.inc"
%macro WDATA_gui_guest_desktop_0 0
align 8
gd_last_refresh_ms: dq 0
gd_window_epoch:    dq 0               ; every successful window open, including explicit show
gd_slot:            dd -1
gd_opened_gen:      dd 0
gd_blits:           dd 0
gd_keys_sent:       dd 0
gd_ptr_sent:        dd 0
gd_captures:        dd 0
gd_releases:        dd 0
gd_opened:          db 0
gd_capture:         db 0
gd_ptr_owner:       db 0
gd_lctrl:           db 0
gd_rctrl:           db 0
gd_e0:              db 0
gd_e1:              db 0
gd_pause_valid:    db 0
align 8
gd_pause_start: dd 0
gd_pause_slot: dd 0
gd_pause_input_epoch: dq 0
gd_pause_window_epoch: dq 0
gd_pause_authority: dq 0
gd_pause_region: dq 0
gd_pause_ram: dq 0
gd_pause_bytes: dq 0
gd_pause_profile: dq 0
gd_pause_backend: dq 0
gd_pause_owner: dq 0
%endmacro
WDATA_DEFER WDATA_gui_guest_desktop_0

; RCQ-12 staging owner: zero-fill tail, never reset by a GUI, session or guest
; path. The pair itself is one kmalloc block that is never freed.
%macro WDATA_gui_guest_desktop_stage 0
alignb 8
gd_stage_blk:       resq 1              ; the kmalloc block (0 until allocated)
gd_stage_s:         resq 1              ; S = blk + GD_STAGE_S_OFF
gd_stage_d:         resq 1              ; D = blk + GD_STAGE_D_OFF
gd_stage_src:       resq 1              ; captured DISPLAY base
gd_stage_window_epoch: resq 1          ; window lifetime at staged capture
gd_stage_epoch:     resq 1              ; session_authority_epoch at capture
gd_stage_fbsize:    resq 1
gd_stage_shadow:    resq 1
gd_stage_scanout:   resq 1
gd_stage_shadow_cap: resq 1
gd_stage_pub_epoch: resq 1
gd_stage_len:       resq 1              ; packed logical LEN; allocation stays full
gd_stage_pitch:     resq 1              ; packed row bytes, 4..3200 (0 for empty)
gd_stage_chunks:    resq 1              ; ceil(logical LEN/2048), 0 for empty
gd_stage_tail:      resq 1              ; final chunk bytes, 0 only for empty
gd_stage_px:        resq 1
gd_stage_py:        resq 1
gd_stage_pw:        resq 1
gd_stage_ph:        resq 1
gd_stage_sx:        resq 1
gd_stage_sy:        resq 1
gd_ptr_view:        resb GV_BYTES
gd_ptr_start:       resd 1
alignb 8
gd_ptr_epoch:       resq 1
gd_ptr_win_owner:   resq 1
gd_stage_view:      resb GV_BYTES         ; immutable common viewport plan
gd_stage_pub_row:   resq 1              ; full64 linear output pixel cursor
gd_stage_fb:        resq 1              ; fb_base at capture
gd_stage_cursor:    resq 1              ; phase byte cursor, full64 checked before use
gd_stage_profile:   resq 1
gd_stage_backend:   resq 1
gd_stage_region:    resq 1
gd_stage_capacity:  resq 1
gd_stage_ram:       resq 1
gd_stage_ram_bytes: resq 1
gd_stage_win_owner: resq 1
gd_stage_job:       resq 1              ; exact returned cooperative generation
gd_stage_jobs:      resq 1              ; lane calls made
gd_stage_published: resq 1              ; refreshes presented from D
gd_stage_dropped:   resq 1              ; refreshes dropped (GD_WHY_*)
gd_stage_scrubs:    resq 1
gd_stage_start:     resd 1              ; hv_linux_start_consumed at capture
gd_stage_slot:      resd 1
gd_stage_gen:       resd 1              ; gd_opened_gen at capture
gd_stage_fbw:       resd 1
gd_stage_fbh:       resd 1
gd_stage_fbs:       resd 1
gd_stage_devices:   resd 1
gd_stage_wx:        resd 1
gd_stage_wy:        resd 1
gd_stage_ww:        resd 1
gd_stage_wh:        resd 1
gd_stage_target:    resb 1
gd_stage_worked:    resb 1              ; reset only at entry to actual idle tick
gd_stage_state:     resb 1              ; GD_ST_*
gd_stage_dirty:     resb 1              ; S/D hold a captured frame
gd_stage_why:       resb 1              ; GD_WHY_* of the last refresh not shown from D
%endmacro
WDATA_BSS_DEFER WDATA_gui_guest_desktop_stage
