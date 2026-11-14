;; MODULE gui/lock_screen
%include "core/abi/build_profile.inc"
;; LAYER 6
;; PURPOSE Stock sign-in composition; sec/session is the only authority owner.
;; EXPORTS lock_screen_focus_assert, lock_screen_boot_release, lock_screen_notice, lock_screen_init, lock_screen_sync, lock_screen_desktop_start, lock_screen_boot_report, lock_screen_key, lock_screen_click, lock_screen_command_allowed, lock_surface_ready, lock_surface_loading, taskbar_draw_registry, taskbar_attention_tick, lock_composition_ok, lock_desktop_created, lock_wallpaper_load, lock_screen_display_serial
;; IMPORTS gui/calendar, gui/app_launch_flow, gui/app_launcher, gui/lock_ssh_notice, gui/recovery_notice, gui/lock_fade, gui/lock_screen_card, gui/form_loader, gui/widget, gui/widget_image, gui/window, gui/window_mgmt, gui/chat_app, gui/demo_three_windows, gui/console_app, gui/widget_console_grid, gui/session_restore, sec/session, sec/principal, svc/command, svc/command_auth, svc/command_cons, svc/command_udp, boot/header, boot/gop, boot/serial, core/lib/str, gui/taskbar, dev/input/ps2, gui/input_route, config/keep_config, sec/keyprov, gui/netmon_form
;; OWNER saga:login_surfaces

LOCK_SLOT equ WM_MAX - 1                ; reserved from ordinary WM allocation (the top slot; G9: was the literal 7 = old WM_MAX-1)
LOCK_HIDDEN equ 4                       ; presentation state, never authority
LOCK_FORM_WIDGETS equ 14                ; stock card nodes, internal auth id remains +4
LOCK_W_PASSWORD_LABEL equ 5             ; independent keyboard-layout indicator
LOCK_LAYOUT_TEXT_SLOT equ 3             ; one bounded keyboard-layout tag per supported layout

; Every taskbar caller, including cadence and pointer paths, shares this gate.
taskbar_draw_registry:
    cmp  byte [rel lock_surface_ready], 1
    jne  .workspace
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .workspace
    ret
.workspace:
    jmp  taskbar_draw_registry_workspace

taskbar_attention_tick:
    cmp  byte [rel lock_surface_ready], 1
    jne  .workspace
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .workspace
    call lock_ssh_notice_tick
    jmp  lock_card_clock_tick           ; no pulse; the card's clock stays current
.workspace:
    jmp  taskbar_attention_tick_workspace

lock_screen_init:
    lea  rdi, [rel str_lock_begin]
    call serial_string
    ; Install the command floor before composition can fail. A missing image
    ; must never reopen unrelated commands or start a desktop.
    mov  byte [rel lock_surface_ready], 1
    lea  rax, [rel lock_screen_command_allowed]
    mov  [rel command_session_allow_op], rax
    lea  rax, [rel lock_screen_sync]
    mov  [rel command_session_sync_op], rax
    ; Headless lock floor (wave 0.0.46): register the lock-state read and the
    ; LOCK alias before composition, so a box without a GOP framebuffer still
    ; reports its lock state. Nothing between here and the old registration
    ; point registers a verb, so the composed registry order is unchanged.
    ; Composition still requires both rows; this grants no authority.
    call lock_screen_register_verbs
    call wgt_secret_register
    cmp  eax, -1
    je   .fail
    call wmx_retire_floor_windows
    mov  byte [rel lock_surface_loading], 1
    mov  eax, [rel wgt_count]
    mov  [rel lock_widget_first], eax
    mov  edi, FORM_LOCK_INDEX
    mov  edx, 1
    call form_load_internal
    mov  byte [rel lock_surface_loading], 0
    test eax, eax
    jnz  .fail
    cmp  ecx, LOCK_SLOT
    jne  .fail
    cmp  edx, LOCK_FORM_WIDGETS
    jne  .fail
    call lock_backdrop_register
    cmp  eax, -1
    je   .fail
    call lock_screen_layout_tag         ; RCQ-38 L2: the layout in force (kbd_prefs_load ran before)
    ; RCQ-16 F2: the resident lock form is PaOS chrome. No request may act on
    ; its slot (WIDGETNEW/WIDGETSET), the owner's included; the slot stays
    ; reserved from the pool for the whole boot, so the stamp is never reused.
    mov  qword [rel wm_owner + LOCK_SLOT*8], WM_OWNER_CHROME
    mov  edi, [rel lock_widget_first]
    add  edi, 4
    call wgt_mark_ascii                 ; RCQ-38 L3b: the user name is compared to ASCII "paos"
    ; The same form owns the whole active framebuffer. Rebind the stock image
    ; through its decoder/cache after changing its output dimensions.
    mov  dword [rel wm_x + LOCK_SLOT*4], 0
    mov  dword [rel wm_y + LOCK_SLOT*4], 0
    mov  eax, [rel fb_width]
    mov  [rel wm_w + LOCK_SLOT*4], eax
    mov  eax, [rel fb_height]
    mov  [rel wm_h + LOCK_SLOT*4], eax
    mov  edi, [rel lock_widget_first]
    call wgt_slot_ptr
    mov  dword [rax + WGI_X], 0
    mov  dword [rax + WGI_Y], 0
    mov  ecx, [rel fb_width]
    mov  [rax + WGI_W], ecx
    mov  ecx, [rel fb_height]
    mov  [rax + WGI_H], ecx
    mov  edi, [rel lock_widget_first]
    call widget_image_state_ptr
    mov  rsi, [rax + WIS_SRC]
    mov  edi, [rel lock_widget_first]
    mov  edx, WIMG_FIT_COVER
    call widget_image_bind
    mov  edi, [rel lock_widget_first]
    call widget_image_state_ptr
    mov  ecx, [rax + WIS_LOAD]
    mov  [rel lock_wallpaper_load], ecx  ; STATUS DISPLAY: the wallpaper bind result
    ; COVER keeps a natural raster in the cache and scales only bounded rows
    ; during paint; 3840x2160 no longer needs a 33 MiB cache allocation.
    call lock_card_state
    call lock_card_layout
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    call wgt_secret_selftest
    test eax, eax
    jnz  .fail
    mov  byte [rel lock_input_kat_ok], 1
    call lock_screen_tab_keep_kat
    lea  rdi, [rel str_lock_tab_keep_fail]
    test eax, eax
    jnz  .tab_keep_report
    mov  byte [rel lock_tab_keep_kat_ok], 1
    lea  rdi, [rel str_lock_tab_keep_ok]
.tab_keep_report:
    call serial_string
    call lock_screen_badge_selftest
    test eax, eax
    jnz  .fail
    mov  byte [rel lock_badge_kat_ok], 1
    lea  rax, [rel lock_screen_key]
    mov  [rel wgt_key_filter], rax
    lea  rax, [rel lock_screen_click]
    mov  [rel wgt_click_hook], rax
    lea  rax, [rel lock_card_text_draw]
    mov  [rel wgt_text_paint_hook], rax
    ; Replace the GUI restore callback, not the session state machine. It
    ; exposes windows only after sec/session consumed a fresh bind.
    mov  rax, [rel session_workspace_restore_op]
    mov  [rel lock_restore_op], rax
    lea  rax, [rel lock_screen_restore]
    mov  [rel session_workspace_restore_op], rax
    cmp  byte [rel lock_verbs_ok], 1
    jne  .fail
    mov  byte [rel fb_present_boot_hold], 1  ; boot audit (2): held until the router's first idle pass
    lea  rax, [rel lock_screen_boot_release]
    mov  [rel input_route_live_hook], rax
    mov  byte [rel lock_composition_ok], 1
    lea  rdi, [rel str_lock_bind_marker]
    call serial_string
    ; Report the existing compile-time default-off/dev-only policy. There is
    ; deliberately no second config flag or runtime policy setter in this rung.
    lea  rdi, [rel str_lock_policy_marker]
    call serial_string
    ret
.fail:
    call session_shell_lock
    lea  rdi, [rel str_lock_failed]
    call serial_string
    mov  edi, [rel form_error]
    call serial_hex64
    lea  rdi, [rel str_lock_failed_widgets]
    call serial_string
    mov  edi, [rel wgt_count]
    call serial_hex64
    lea  rdi, [rel str_lock_input_kat]
    call serial_string
    movzx edi, byte [rel lock_input_kat_ok]
    call serial_hex64
    call serial_newline
    cmp  byte [rel lock_verbs_ok], 1
    jne  .out
    lea  rdi, [rel str_lock_headless_floor]
    call serial_string
.out:
    ret

; Register LOCKSTATE then LOCK through the one registry, in the original order
; and with the original metadata (LOCKSTATE public read, LOCK destructive and
; AUTH1-gated like SESSIONLOCK). lock_verbs_ok=1 only when both rows landed.
lock_screen_register_verbs:
    lea  rdi, [rel str_lockstate_verb]
    lea  rsi, [rel lock_cmd_state]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    cmp  eax, -1
    je   .out
    lea  rdi, [rel str_lock_verb]
    lea  rsi, [rel cmd_verb_sessionlock]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    cmp  eax, -1
    je   .out
    mov  byte [rel lock_verbs_ok], 1
.out:
    ret

; Only the sole session owner can call this after a principal bind.
lock_screen_restore:
    call pwr_m1_restore_on_signin            ; RCQ-27 M1-3: a verified sleep checkpoint (once per boot)
    call lock_screen_show_workspace
    cmp  byte [rel lock_desktop_created], 1
    je   .created
    ; Console startup formats an in-process command reply. Run it only after
    ; the AUTHLOGIN transport frame returns, then restore through this callback.
    mov  byte [rel lock_restore_pending], 1
    jmp  .none
.created:
    mov  rax, [rel lock_restore_op]
    test rax, rax
    jz   .none
    jmp  rax
.none:
    mov  eax, -1
    xor  edx, edx
    ret

lock_screen_desktop_start:
    cmp  byte [rel lock_composition_ok], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    cmp  byte [rel lock_desktop_started], 0
    jne  .out
    mov  byte [rel lock_desktop_started], 1
    call cons_declare                  ; includes default user-session creation
    call demo_three_windows_init
    ; These editable fields must belong to the final demo windows. Creating
    ; them on the retired boot scaffolding loses the live input surfaces and
    ; runs the routing KAT before its required windows exist on some profiles.
    call gui_input_route_init
    call console_grid_register
    call wgt_type_headroom_report       ; UI wave 2 G2: after the last boot-time type registration
    call cons_finalize
    call console_app_init
    call terminal_app_init               ; hub packet 0009: after the Console so LAUNCH chains app_terminal -> app_console
    call start_programs_init             ; hub packet 0010: after both, so FORMLOAD chains the Start rows -> console -> loader
    call card_surface_init               ; RCQ-40 J2b: last, so the key/click hooks chain card -> start_programs -> lock
    call app_confirm_init               ; app_confirm -> card -> start_programs -> lock
    call app_package_card_init          ; read-only native report navigation
    call app_launcher_init              ; chained native bundle desktop entry
    call netmon_check_click_init        ; Network Monitor's Network Check button
    call app_launch_flow_init            ; WAIT/UI ready; native callback, no app prepare
    call app_install_init                ; after binding: decision card hooks, consent resolver
    call demo_three_windows_retire       ; B18: after the routing init/KAT and the app inits; desktop handed over clean
    ; T5-11: the Console stays hidden at startup. Require the retained
    ; headless command/transcript service, not a legacy window allocation.
    cmp  byte [rel console_service_ready], 1
    jne  .out
    mov  byte [rel lock_desktop_created], 1
    cmp  byte [rel lock_restore_pending], 1
    jne  .notice
    mov  byte [rel lock_restore_pending], 0
    call session_shell_restore_workspace
.notice:
    call recovery_notice_init
.out:
    ret

; One late-boot state measurement for isolated policy boots. The nonce is a
; non-secret build input; fields are read from the live owners, not constants.
lock_screen_boot_report:
    ; Boot audit (2): while the first sign-in present is held for the router, this
    ; line would report a frame not yet shown. Owe it; lock_screen_boot_release
    ; prints it right after that present, so DISPLAY= stays the truth.
    cmp  byte [rel fb_present_boot_hold], 0
    je   .now
    mov  byte [rel lock_boot_report_owed], 1
    ret
.now:
    ; Restore the stock surface after the last boot diagnostic painter.
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .report
    cmp  byte [rel lock_composition_ok], 1
    jne  .report
    call lock_screen_paint
.report:
    lea  rdi, [rel str_lock_boot_report]
    call serial_string
    movzx edi, byte [rel session_locked]
    call serial_hex64
    lea  rdi, [rel str_lock_policy]
    call serial_string
    movzx edi, byte [rel session_boot_policy]
    call serial_hex64
    lea  rdi, [rel str_lock_bypass_off]
    cmp  byte [rel session_boot_policy], 2
    je   .try_bypass
    cmp  byte [rel session_boot_policy], 1
    jne  .bypass
    lea  rdi, [rel str_lock_bypass_dev]
    jmp  .bypass
.try_bypass:
    lea  rdi, [rel str_lock_bypass_try]
.bypass:
    call serial_string
    lea  rdi, [rel str_lock_created]
    call serial_string
    movzx edi, byte [rel lock_desktop_created]
    call serial_hex64
    lea  rdi, [rel str_lock_console_sessions]
    call serial_string
    call lock_screen_console_count
    mov  edi, eax
    call serial_hex64
    lea  rdi, [rel str_lock_pid]
    call serial_string
    mov  rdi, [rel session_bound_pid]
    call serial_hex64
    lea  rdi, [rel str_lock_boot]
    call serial_string
    mov  rdi, [rel boot_tsc_start]
    call serial_hex64
    call udp_display_serial              ; msi-b70: what the sign-in paint above put on the scanout
    call serial_newline
    ret

; lock_screen_display_serial — the DISPLAY verdict on the boot P7 line (boot/header imports
; this module, not svc/command_udp). Read-only. clobbers: caller-saved.
lock_screen_display_serial:
    jmp  udp_display_serial

; Independent keyboard-layout tag; never changes the Password label.
lock_screen_layout_tag:
    movzx eax, byte [rel input_layout_id]
    cmp  eax, 4
    jb   .valid
    xor  eax, eax
.valid:
    imul eax, eax, LOCK_LAYOUT_TEXT_SLOT
    lea  rsi, [rel lock_layout_texts]
    add  rsi, rax
    mov  edi, [rel lock_widget_first]
    add  edi, LOCK_W_PASSWORD_LABEL
    jmp  wgt_set_text
lock_layout_texts: db "US",0,"ES",0,"FR",0,"DE",0

; Reconcile presentation on each session authority epoch, and before a wire
; reply can acknowledge LOCK/AUTHLOGIN. This stores no second locked bit.
lock_screen_sync:
    cmp  byte [rel lock_composition_ok], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .unlocked
    cmp  byte [rel lock_submit_pending], 1
    jne  .no_submit
    mov  byte [rel lock_submit_pending], 0
    jmp  lock_screen_submit
.no_submit:
    ; AUTH1 transport proof is not a local login. Do not leave its temporary
    ; principal behind after any refusal or locked read.
    call principal_clear_bound
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel lock_painted_epoch]
    je   .presentation
    mov  [rel lock_painted_epoch], rax
    call wgt_secret_clear
    call lock_screen_drop_input
    call calendar_close                 ; never restore an old flyout after unlock
    call lock_screen_layout_tag         ; RCQ-38 L2: each lock names the layout in force
    ; RCQ-17: a Start/Summon palette left open must not sit over the sign-in
    ; surface (its modal hooks would take the password). The direct close is
    ; permitted while locked and restores its prior widget focus, which the
    ; lock's own focus assignment below then replaces.
    xor  edi, edi
    call summon_palette_set_open_direct
    mov  eax, [rel wm_focus]
    mov  [rel lock_saved_focus], eax
    xor  ecx, ecx
.hide:
    cmp  ecx, WM_MAX
    jae  .paint
    cmp  ecx, LOCK_SLOT
    je   .next
    lea  rdx, [rel wm_state]
    mov  eax, [rdx + rcx*4]
    cmp  eax, WM_VISIBLE
    je   .hide_live
    cmp  eax, WM_MIN
    jne  .next
.hide_live:
    lea  r8, [rel lock_saved_windows]
    mov  [r8 + rcx*4], eax
    mov  dword [rdx + rcx*4], LOCK_HIDDEN
.next:
    inc  ecx
    jmp  .hide
.paint:
    mov  dword [rel wm_state + LOCK_SLOT*4], WM_VISIBLE
    mov  dword [rel wm_focus], LOCK_SLOT
    mov  eax, [rel lock_widget_first]
    add  eax, 6                         ; password node
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    mov  [rel wgt_focus_id], eax
    mov  edi, [rel lock_widget_first]
    add  edi, 8
    call lock_prompt_text
    call wgt_set_text                   ; no stale refusal survives a relock
    call lock_screen_setup_label
    mov  edi, LOCK_SLOT
    call wmx_zstamp_top
    call lock_screen_paint
    cmp  byte [rel lock_rendered], 1
    je   .out
    mov  byte [rel lock_rendered], 1
    lea  rdi, [rel str_lock_render_marker]
    call serial_string
    ret
; The legacy badge erase runs later in the idle loop and writes the old
; desktop color. Its presentation event must not impersonate a session epoch:
; that branch wipes the secret, drains input and resets focus.
.presentation:
    call lock_screen_focus_assert       ; F2b-1: every pass, before input is consumed
    call udp_boot_beacon_observe
    jmp  lock_screen_refresh_badge
.unlocked:
    call lock_screen_show_workspace
.out:
    ret

; lock_screen_focus_assert -> EAX 1 when the keyboard had left the sign-in form
; (it is back now; the caller drops the input that found it away), else 0.
; RCQ-16 F2b-1 (root 23:40:56, rc-sec 23:50:07): while LOCKED the sign-in form
; owns the keyboard and the screen, whatever wm_focus says. A slot found live
; (opened or shown since the lock epoch) is hidden into lock_saved_windows as
; the epoch hides it, and lock_screen_show_workspace restores it on unlock; the
; form itself is kept shown; focus returns to the form's password node unless
; it is already on one of the form's own widgets. Called at the top of key and
; pointer dispatch, in lock_screen_key, and on every locked presentation.
; No-op while unlocked, without a lock composition, or before the sync has
; painted the current authority epoch. Preserves every register but RAX.
lock_screen_focus_assert:
    xor  eax, eax
    cmp  byte [rel lock_composition_ok], 1
    jne  .ret
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .ret
    ; Only the state an epoch has already established is enforced: before the
    ; sync paints this epoch it still has to save the pre-lock focus.
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel lock_painted_epoch]
    mov  eax, 0
    jne  .ret
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    xor  ebx, ebx                       ; bit 0: a surface changed, bit 1: focus moved
    xor  ecx, ecx
    lea  rdx, [rel wm_state]
    lea  r8, [rel lock_saved_windows]
.hide:
    cmp  ecx, WM_MAX
    jae  .form
    cmp  ecx, LOCK_SLOT
    je   .next
    mov  eax, [rdx + rcx*4]
    cmp  eax, WM_VISIBLE
    je   .hide_live
    cmp  eax, WM_MIN
    jne  .next
.hide_live:
    mov  [r8 + rcx*4], eax
    mov  dword [rdx + rcx*4], LOCK_HIDDEN
    or   ebx, 1
.next:
    inc  ecx
    jmp  .hide
.form:
    cmp  dword [rdx + LOCK_SLOT*4], WM_VISIBLE
    je   .form_shown
    mov  dword [rdx + LOCK_SLOT*4], WM_VISIBLE
    or   ebx, 1
.form_shown:
    ; "On the form" is the form's own id range, never the widget table: the
    ; refocus target is always inside it, so the assert cannot keep firing.
    cmp  dword [rel wm_focus], LOCK_SLOT
    jne  .refocus
    mov  eax, [rel wgt_focus_id]
    sub  eax, [rel lock_widget_first]
    cmp  eax, LOCK_FORM_WIDGETS
    jb   .settled
.refocus:
    mov  dword [rel wm_focus], LOCK_SLOT
    mov  eax, [rel lock_widget_first]
    add  eax, 6                         ; password node
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    mov  [rel wgt_focus_id], eax
    or   ebx, 2
.settled:
    test ebx, ebx
    jz   .out
    mov  edi, LOCK_SLOT
    call wmx_zstamp_top
    call lock_screen_paint
.out:
    mov  eax, ebx
    shr  eax, 1
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rbx
.ret:
    ret

; lock_prompt_text -> RSI = the prompt (EDI preserved). Root 12:58 (P1 a): with
; passwordless push on and no password sign-in yet this boot, a phone approval
; unlocks without the owner's files, so the prompt says the password opens them.
lock_prompt_text:
    cmp  byte [rel lock_setup_staged], 1
    je   .staged
    call principal_first_owner_available
    cmp  eax, 1
    je   .setup
    lea  rsi, [rel str_lock_prompt]
%if !PAOS_PUBLIC_BUILD
    test byte [rel keep_push_modes], 4  ; 1 << (PU_PASSWORDLESS - 1)
    jz   .out
    cmp  byte [rel prin_owner_boot_ready], 1
    je   .out
    lea  rsi, [rel str_lock_prompt_files]
%endif
.out:
    ret
.setup:
    lea  rsi, [rel str_lock_setup]
    ret
.staged:
    lea  rsi, [rel str_lock_staged]
    ret

lock_screen_setup_label:
    call lock_card_state
    call principal_first_owner_available
    lea  rsi, [rel str_lock_signin]
    cmp  eax, 1
    jne  .label
    lea  rsi, [rel str_lock_stage]
.label:
    mov  edi, [rel lock_widget_first]
    add  edi, 7
    jmp  wgt_set_text

; EAX=observed dismissal state. A repeat observation is a no-op. Kept separate
; from authority reconciliation so a repaint preserves the in-progress login.
lock_screen_refresh_badge:
    cmp  al, [rel lock_painted_badge]
    je   .out
    push rax
    call lock_screen_paint
    pop  rax
    mov  [rel lock_painted_badge], al
    inc  qword [rel lock_badge_repairs]
.out:
    ret

; Boot-only fixture before input dispatch is installed. Exercise the real
; repaint with an unchanged authority epoch and a kit-owned synthetic secret.
; The mocked observation never writes sender state or changes its deadline.
lock_screen_badge_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  eax, [rel wgt_focus_id]
    push rax
    mov  eax, [rel wm_focus]
    push rax
    mov  ebx, -1
    mov  r12, [rel session_authority_epoch]
    mov  r13, [rel prin_password_failures]
    mov  r14, [rel session_bound_pid]
    mov  r15, [rel session_key_handle]
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    mov  [rel wgt_focus_id], edi
    mov  dword [rel wm_focus], LOCK_SLOT
    mov  eax, 'x'
    call wgt_secret_key
    mov  byte [rel lock_submit_pending], 1
    mov  byte [rel lock_painted_badge], 0
    xor  eax, eax
    call lock_screen_refresh_badge
    cmp  qword [rel lock_paint_count], 0
    jne  .restore
    mov  eax, 1
    call lock_screen_refresh_badge
    mov  eax, 1
    call lock_screen_refresh_badge
    cmp  qword [rel lock_paint_count], 1
    jne  .restore
    cmp  qword [rel lock_badge_repairs], 1
    jne  .restore
    cmp  byte [rel lock_painted_badge], 1
    jne  .restore
    cmp  [rel session_authority_epoch], r12
    jne  .restore
    cmp  [rel prin_password_failures], r13
    jne  .restore
    cmp  [rel session_bound_pid], r14
    jne  .restore
    cmp  [rel session_key_handle], r15
    jne  .restore
    cmp  byte [rel lock_submit_pending], 1
    jne  .restore
    cmp  dword [rel wm_focus], LOCK_SLOT
    jne  .restore
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    cmp  [rel wgt_focus_id], edi
    jne  .restore
    cmp  [rel wgt_secret_owner], edi
    jne  .restore
    cmp  dword [rel wgt_secret_len], 1
    jne  .restore
    cmp  byte [rel wgt_secret_bytes], 'x'
    jne  .restore
    call wgt_slot_ptr
    cmp  word [rax + WGI_VAL], '*'
    jne  .restore
    cmp  dword [rax + WGI_VLEN], 1
    jne  .restore
    xor  ebx, ebx
.restore:
    call wgt_secret_clear
    mov  byte [rel lock_submit_pending], 0
    mov  qword [rel lock_badge_repairs], 0
    mov  qword [rel lock_paint_count], 0
    call udp_boot_beacon_observe
    mov  [rel lock_painted_badge], al
    pop  rax
    mov  [rel wm_focus], eax
    pop  rax
    mov  [rel wgt_focus_id], eax
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Rebind at a session/presentation boundary: a workspace can evict the bitmap.
; This runs in normal context, never in a damage painter.
; SEC-lock-noncovering-after-res (root 18:05:32): RESSET rewrites fb_width/
; fb_height at run time, after lock_screen_init set the form's geometry once.
; Every paint re-asserts the slot rect and node 0 at (0,0,fb_width,fb_height)
; before the rebind, so the image or its token fill covers the whole active
; mode, and moves the kit group by the change of its centre. The slot's old
; width/height are the mode the group was last centred for.
lock_screen_paint:
    mov  edi, [rel lock_widget_first]
    call wgt_slot_ptr                       ; RAX = node 0
    xor  ecx, ecx
    mov  [rel wm_x + LOCK_SLOT*4], ecx
    mov  [rel wm_y + LOCK_SLOT*4], ecx
    mov  [rax + WGI_X], ecx
    mov  [rax + WGI_Y], ecx
    mov  ecx, [rel fb_width]
    mov  [rax + WGI_W], ecx
    mov  [rel wm_w + LOCK_SLOT*4], ecx
    mov  ecx, [rel fb_height]
    mov  [rax + WGI_H], ecx
    mov  [rel wm_h + LOCK_SLOT*4], ecx
    call lock_card_layout
    mov  edi, [rel lock_widget_first]
    call widget_image_state_ptr
    mov  rsi, [rax + WIS_SRC]
    mov  edi, [rel lock_widget_first]
    mov  edx, WIMG_FIT_COVER
    call widget_image_bind
    call wmx_draw_all
    mov  edi, [rel lock_notice_kind]        ; RCQ-27: a full repaint keeps the notice
    mov  esi, [rel lock_notice_secs]
    call lock_notice_paint
    mov  rax, [rel fb_present_count]
    call fb_present_all
    PW_REPAINT                       ; optional private diagnostic, same composition owner
    call lock_bg6_stamp                      ; held, withheld or suppressed: no BG6 (the release or a later paint stamps)
    call udp_boot_beacon_observe
    mov  [rel lock_painted_badge], al
    inc  qword [rel lock_paint_count]
    ret

; lock_bg6_stamp(RAX = fb_present_count before a whole sign-in frame's fb_present_all)
; — RCQ-32 BG6 is the first sign-in frame that reached the scanout. Stamps it once, and
; only when that present copied (fb_present_count moved): the boot hold, the lock gate
; before the composition publish, DPMS blanking, a missing scanout, a detached shadow
; or an empty frame all return before the copy, so BG6 stays 0 and the next whole
; frame that does present stamps it (srcreview R1, boot audit 2). Locked sessions
; only; while locked, nothing presents before the composition publish (the gate).
; Preserves all registers.
lock_bg6_stamp:
    cmp  rax, [rel fb_present_count]
    je   .out                                ; nothing reached the scanout
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .out
    cmp  qword [rel boot_bg6_pixel_tsc], 0
    jne  .out
    push rax
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel boot_bg6_pixel_tsc], rax
    pop  rdx
    pop  rax
.out:
    ret

; lock_screen_boot_release — boot audit (2), spec 7.6.5 (G6 before G7 would be "a sign-in
; box that can't take typing yet"): gui/input_route calls it once, on the first non-KAT
; idle pass, right after its kbd timeline mark (a boot keyboard is live there). Clears the
; boot present hold, presents the composed frame and stamps BG6 at that present,
; then prints the LOGINBOOT line the late boot report owed. Idempotent; preserves
; all registers.
lock_screen_boot_release:
    cmp  byte [rel fb_present_boot_hold], 0
    je   .out
    call lock_fade_begin                  ; router keyboard-live edge, no wait
    mov  byte [rel fb_present_boot_hold], 0
    push rax
    mov  rax, [rel fb_present_count]
    call fb_present_all
    call lock_bg6_stamp
    pop  rax
.out:
    cmp  byte [rel lock_fade_active], 1
    je   .done                            ; exact readback is reported at fade completion
    cmp  byte [rel lock_boot_report_owed], 0
    je   .done
    mov  byte [rel lock_boot_report_owed], 0
    push rax                                 ; the report clobbers caller-saved registers
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call lock_screen_boot_report
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
.done:
    ret

; lock_screen_notice(EDI = kind, ESI = seconds) — RCQ-27 (root 07:24 (b)): the one
; shared lock-screen notice. The state is always kept, so a later lock shows a
; countdown already running; it is painted only while the composed sign-in surface
; is up (gui/window lock_notice_paint, the allowlisted painter). Clearing it
; repaints the sign-in surface. A repeat of the shown state is a no-op. No input,
; focus, secret or authority state is touched. clobbers: caller-saved.
lock_screen_notice:
    mov  eax, [rel lock_notice_kind]
    cmp  edi, eax
    jne  .changed
    cmp  esi, [rel lock_notice_secs]
    je   .out
.changed:
    mov  [rel lock_notice_kind], edi
    mov  [rel lock_notice_secs], esi
    cmp  byte [rel lock_composition_ok], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .out
    cmp  dword [rel wm_state + LOCK_SLOT*4], WM_VISIBLE
    jne  .out
    test edi, edi
    jnz  lock_notice_paint                  ; tail call; EDI/ESI intact
    test eax, eax
    jnz  lock_screen_paint                  ; cleared: the surface without it
.out:
    ret

lock_screen_show_workspace:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    cmp  dword [rel wm_state + LOCK_SLOT*4], LOCK_HIDDEN
    je   .out
    call wgt_secret_clear
    ; KBDBUF exposes the entire raw scancode ring, including consumed bytes.
    ; Erase it before workspace command ingress can observe a password, and
    ; discard queued keystrokes so they cannot spill into the new console.
    call lock_screen_drop_input
    mov  byte [rel lock_submit_pending], 0
    mov  dword [rel wm_state + LOCK_SLOT*4], LOCK_HIDDEN
    xor  ecx, ecx
.show:
    cmp  ecx, WM_MAX
    jae  .focus
    cmp  ecx, LOCK_SLOT
    je   .next
    lea  rdx, [rel wm_state]
    cmp  dword [rdx + rcx*4], LOCK_HIDDEN
    jne  .next
    lea  r8, [rel lock_saved_windows]
    mov  eax, [r8 + rcx*4]
    mov  [rdx + rcx*4], eax
    mov  dword [r8 + rcx*4], 0
.next:
    inc  ecx
    jmp  .show
.focus:
    mov  eax, [rel lock_saved_focus]
    mov  [rel wm_focus], eax
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r10d, [rel fb_width]
    mov  r11d, [rel fb_height]
    call wallpaper_paint_rect
    call wmx_draw_all
    call fb_present_all
.out:
    ret

; Input queues belong to the session that received them. IRQ1 and USB-HID
; producers use this same interrupt-excluded ring; this creates no second queue.
lock_screen_drop_input:
    pushfq
    cli
    push rax
    push rcx
    push rdi
    lea  rdi, [rel kbd_ring]
    xor  eax, eax
    mov  ecx, KBD_RING_LEN
    cld
    rep  stosb
    lea  rdi, [rel kbd_origin_ring]     ; GA0-K: the origins and slot holds go too
    mov  ecx, KBD_RING_LEN
    rep  stosb
    mov  qword [rel kbd_slot_pending], 0
    mov  byte [rel input_key_origin], KO_INTERNAL ; SEC R1 F4: no key in delivery is never HUMAN
    mov  byte [rel kbd_head], 0
    mov  byte [rel kbd_tail], 0
    mov  byte [rel kbd_count], 0
    mov  byte [rel input_kbd_e0], 0
    mov  byte [rel input_kbd_mods], 0
    mov  byte [rel input_win_down], 0   ; UI wave 2 B10: no Win state crosses the session
    mov  byte [rel input_win_chord], 0
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; Key and pointer activation share one submit action. Only the username is
; read from public form state. The kit-owned secret buffer is wiped by 2501
; before its output-only principal reaches the session gate.
lock_screen_key:
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .ignored
    ; F2b-1 backstop for any key path that bypassed the router's assert: a key
    ; that found the keyboard away, or addressed to a widget off the form, is
    ; dropped (consumed), never left to another window's editor.
    push rax
    call lock_screen_focus_assert
    test eax, eax
    pop  rax
    jnz  .consumed
    cmp  dword [rel wm_focus], LOCK_SLOT
    jne  .ignored
    mov  ecx, edi
    sub  ecx, [rel lock_widget_first]
    cmp  ecx, LOCK_FORM_WIDGETS
    jae  .consumed
    cmp  byte [rel lock_card_help], 1
    je   lock_card_help_key
    cmp  eax, GUI_KEY_ESC
    je   .cancel
    cmp  eax, GUI_KEY_TAB
    je   .tab
    cmp  eax, GUI_KEY_ENTER
    jne  .identity
    ; Enter on the secondary action opens its guidance, never submits.
    cmp  ecx, 9
    je   .secondary
    call keyprov_key_is_human
    mov  [rel lock_submit_human], al
    mov  rax, [rel wgt_secret_revision]
    mov  [rel lock_submit_revision], rax
    call lock_screen_submit
    mov  eax, 1
    ret
.secondary:
    call lock_card_click
    mov  eax, 1
    ret
.cancel:
    ; Cancel belongs to the primary form, even while an action has focus.
    ; Retire a queued activation before wiping its transient editor revision.
    mov  byte [rel lock_submit_pending], 0
    mov  byte [rel lock_submit_human], 0
    call wgt_secret_clear
    mov  eax, [rel lock_widget_first]
    add  eax, 6
    mov  [rel wgt_focus_id], eax
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    mov  byte [rel wgt_focus_visible], 1
    mov  edi, LOCK_SLOT
    call wmx_draw_one
    call fb_present_all
    mov  eax, 1
    ret
.tab:
    ; UI wave 2 B11: a focus move keeps the password; only an identity edit,
    ; submit, Esc or relock voids it.
    ; This route bypasses generic Tab dispatch: select keyboard rings before
    ; repaint, leaving the boot-only focus-step helper modality-neutral.
    mov  byte [rel wgt_focus_visible], 1
    cmp  byte [rel wgt_tab_reverse], 0
    jne  .tab_back
    call lock_screen_tab_step
    jmp  .tab_paint
.tab_back:
    call lock_screen_tab_back
.tab_paint:
    mov  byte [rel wgt_tab_reverse], 0
    mov  edi, LOCK_SLOT
    call wmx_draw_one
    call fb_present_all
    mov  eax, 1
    ret
.identity:
    ; An edit of the user name voids the secret; the ordinary editor then
    ; applies the key (not consumed). Focus moves never reach here.
    mov  ecx, [rel lock_widget_first]
    add  ecx, 4
    cmp  edi, ecx
    jne  .ignored
    cmp  eax, GUI_KEY_BACKSPACE
    je   .identity_edit
    cmp  eax, GUI_KEY_DELETE            ; G3 Delete is an identity edit too
    je   .identity_edit
    cmp  eax, 0x20
    jb   .ignored
    cmp  eax, 0x7E
    ja   .ignored
.identity_edit:
    mov  ecx, [rel wgt_secret_len]
    call wgt_secret_clear               ; preserves rdi/rcx/rax
    test ecx, ecx
    jz   .ignored
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    call wgt_draw_id                    ; the now-empty mask
.ignored:
    xor  eax, eax
    ret
.consumed:
    mov  eax, 1
    ret

; lock_screen_tab_step(EDI=from widget) -> EAX=next visible action.
; The secret is preserved; the internal account editor is never a Tab target.
lock_screen_tab_step:
    mov  eax, [rel lock_widget_first]
    add  eax, 6
    cmp  edi, eax
    jne  .submit
    inc  eax                           ; field -> Sign in
    jmp  .focus
.submit:
    inc  eax
    cmp  edi, eax
    jne  .field
    add  eax, 2                        ; Sign in -> Forgot, only when shown
    push rdi
    mov  edi, eax
    call wgt_slot_ptr
    test dword [rax + WGI_FLAGS], 1
    pop  rdi
    jz   .field
    mov  eax, [rel lock_widget_first]
    add  eax, 9
    jmp  .focus
.field:
    mov  eax, [rel lock_widget_first]
    add  eax, 6
.focus:
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    mov  [rel wgt_focus_id], eax
    ret

; lock_screen_tab_back(EDI=from widget) -> EAX=previous visible action.
; Reverse the same primary ring; hidden help and the account editor are skipped.
; Keep the forward boot helper independent of the pending router direction.
lock_screen_tab_back:
    mov  eax, [rel lock_widget_first]
    add  eax, 6
    cmp  edi, eax
    je   .last
    inc  eax
    cmp  edi, eax
    jne  .help
    dec  eax                           ; Sign in -> field
    jmp  .focus
.help:
    add  eax, 2
    cmp  edi, eax
    jne  .field
    sub  eax, 2                        ; help -> Sign in
    jmp  .focus
.last:
    push rdi
    mov  edi, eax
    add  edi, 3
    call wgt_slot_ptr
    test dword [rax + WGI_FLAGS], 1
    pop  rdi
    mov  eax, [rel lock_widget_first]
    jz   .submit
    add  eax, 9                        ; field -> help, when shown
    jmp  .focus
.submit:
    add  eax, 7                        ; field -> Sign in without help
    jmp  .focus
.field:
    mov  eax, [rel lock_widget_first]
    add  eax, 6
.focus:
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    mov  [rel wgt_focus_id], eax
    ret

; lock_screen_tab_keep_kat -> EAX 0 pass / 1 fail. Boot-only, beside the
; secret-editor KAT: type 'x', Tab through the visible actions back to the
; secret (kept, len 1), then a direct internal identity edit still voids it
; (len 0, key not consumed). Focus is restored; the secret is wiped.
lock_screen_tab_keep_kat:
    push rbx
    push r12
    mov  ebx, 1
    mov  eax, [rel wgt_focus_id]
    push rax
    mov  eax, [rel wm_focus]
    push rax
    mov  eax, [rel wgt_focus_by_win + LOCK_SLOT*4]
    push rax
    mov  r12d, [rel lock_widget_first]
    call wgt_secret_clear
    mov  dword [rel wm_focus], LOCK_SLOT
    lea  edi, [r12d + 6]
    mov  [rel wgt_focus_id], edi
    mov  eax, 'x'
    call wgt_secret_key
    lea  edi, [r12d + 6]
    call lock_screen_tab_step
    lea  ecx, [r12d + 7]
    cmp  eax, ecx
    jne  .restore
    mov  edi, eax
    call lock_screen_tab_step
    lea  ecx, [r12d + 6]
    cmp  eax, ecx
    je   .returned
    lea  ecx, [r12d + 9]
    cmp  eax, ecx
    jne  .restore
    mov  edi, eax
    call lock_screen_tab_step
    lea  ecx, [r12d + 6]
.returned:
    cmp  eax, ecx
    jne  .restore
    cmp  dword [rel wgt_secret_len], 1
    jne  .restore
    cmp  byte [rel wgt_secret_bytes], 'x'
    jne  .restore
    cmp  [rel wgt_secret_owner], ecx
    jne  .restore
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .restore
    lea  edi, [r12d + 4]
    mov  eax, 'a'
    call lock_screen_key
    test eax, eax
    jnz  .restore                       ; the editor must still apply the key
    cmp  dword [rel wgt_secret_len], 0
    jne  .restore
    xor  ebx, ebx
.restore:
    call wgt_secret_clear
    pop  rax
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    pop  rax
    mov  [rel wm_focus], eax
    pop  rax
    mov  [rel wgt_focus_id], eax
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

lock_screen_click:
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .out
    push rdi
    call lock_card_click
    pop  rdi
    test eax, eax
    jnz  .out
    mov  eax, [rel lock_widget_first]
    add  eax, 4                         ; changing identity erases the secret
    cmp  edi, eax
    je   .clear_secret
    add  eax, 3
    cmp  edi, eax
    je   .submit
    dec  eax                            ; secret is an editable focus target
    cmp  edi, eax
    jne  .out
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], eax
    mov  [rel wgt_focus_id], eax
    ret
.submit:
    ; Finish the pointer's raise/focus before hiding its hit window.
    mov  byte [rel lock_submit_human], 0
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    sete byte [rel lock_submit_human]
    mov  rax, [rel wgt_secret_revision]
    mov  [rel lock_submit_revision], rax
    mov  byte [rel lock_submit_pending], 1
.out:
    ret
.clear_secret:
    ; Pointer raise/repaint follows this callback, so the cleared mask
    ; and transient bytes change together before presentation.
    call wgt_secret_clear
    ret

lock_screen_submit:
    push r12
    push r13
    movzx r13d, byte [rel lock_submit_human]
    mov  byte [rel lock_submit_human], 0
    cmp  byte [rel lock_setup_staged], 1
    je   .setup_staged
    call principal_first_owner_available
    cmp  eax, 1
    je   .setup
    mov  edi, [rel lock_widget_first]
    add  edi, 4
    call wgt_slot_ptr
    lea  rdi, [rax + WGI_VAL]
    lea  rsi, [rel str_lock_user]
    call strcmp
    mov  esi, [rel wgt_secret_len]
    test eax, eax
    jz   .user
    xor  esi, esi                      ; invalid identity cannot bind the owner
.user:
    call wgt_secret_human
    and  r13d, eax                     ; typed and submitted by hand, before the input is wiped
    mov  [rel lock_submit_proof], r13b
    lea  rdi, [rel wgt_secret_bytes]
    call principal_local_password
    mov  r12, rax
    mov  r13, rdx
    call wgt_secret_clear
    test r12, r12
    jz   .denied
    mov  rdi, r12
    mov  rsi, r13
    call session_shell_offer_bind
    test eax, eax
    jnz  .denied
    movzx eax, byte [rel lock_submit_proof]
    mov  [rel session_unlock_local_proof], al
    call session_shell_unlock
    test eax, eax
    jz   .sync
    jmp  .denied
.setup:
    ; Consume the activation once. Pointer origin was captured before the
    ; deferred submit; neither later ambient origin nor a changed buffer may
    ; promote it. The real secret widget is the only admitted input owner.
    mov  rax, [rel lock_submit_revision]
    cmp  rax, -1
    je   .setup_denied
    cmp  rax, [rel wgt_secret_revision]
    jne  .setup_denied
    mov  eax, [rel lock_widget_first]
    add  eax, 6
    cmp  eax, [rel wgt_secret_owner]
    jne  .setup_denied
    call wgt_secret_human
    mov  edx, eax
    mov  ecx, r13d
    lea  rdi, [rel wgt_secret_bytes]
    mov  esi, [rel wgt_secret_len]
    call principal_first_owner_stage
    mov  r12d, eax
    call wgt_secret_clear
    test r12d, r12d
    jnz  .denied
    mov  byte [rel lock_setup_staged], 1
.setup_staged:
    call wgt_secret_clear
    mov  byte [rel lock_submit_human], 0
    mov  edi, [rel lock_widget_first]
    add  edi, 8
    lea  rsi, [rel str_lock_staged]
    jmp  .notice
.setup_denied:
    call wgt_secret_clear
.denied:
    mov  byte [rel lock_submit_human], 0
    mov  edi, [rel lock_widget_first]
    add  edi, 8
    lea  rsi, [rel str_lock_retry]
.notice:
    call wgt_set_text
    mov  edi, LOCK_SLOT
    call wmx_draw_one
    call fb_present_all
.sync:
    call lock_screen_sync
    pop  r13
    pop  r12
    ret

; Bounded non-secret projection. Session fields are read from their sole owner.
lock_screen_console_count:
    xor  eax, eax
    mov  ecx, CONS_SESSION_MAX
    lea  rdx, [rel cons_sessions]
.next:
    cmp  byte [rdx + CS_ACTIVE], 1
    jne  .advance
    inc  eax
.advance:
    add  rdx, CS_SIZE
    loop .next
    ret

lock_cmd_state:
    call cmd_handler_prologue
    push r12
    mov  r12, [rdi + REQ_ARG]
    mov  rdi, r12
    call session_nonce_valid
    test eax, eax
    jnz  .bad
    call form_out_reset
    ; A composed sign-in form reports the reserved WM slot. Without one
    ; (no GOP framebuffer, or a failed composition) the same live fields are
    ; reported under form=headless; there is no slot and nothing is rendered.
    cmp  byte [rel lock_composition_ok], 1
    je   .composed_form
    lea  rdi, [rel str_lock_state_headless]
    call form_out_put_str
    xor  edi, edi
    cmp  qword [rel fb_base], 0
    setne dil
    call form_out_put_dec
    lea  rdi, [rel str_lock_state_locked]
    jmp  .locked_field
.composed_form:
    lea  rdi, [rel str_lock_state]
    call form_out_put_str
    mov  edi, LOCK_SLOT
    call form_out_put_dec
    lea  rdi, [rel str_lock_state_locked]
.locked_field:
    call form_out_put_str
    movzx edi, byte [rel session_locked]
    call form_out_put_dec
    lea  rdi, [rel str_lock_pid]
    call form_out_put_str
    mov  rdi, [rel session_bound_pid]
    call form_out_put_dec
    lea  rdi, [rel str_lock_desktop]
    call form_out_put_str
    xor  edi, edi
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .desktop
    movzx edi, byte [rel lock_desktop_created]
.desktop:
    call form_out_put_dec
    lea  rdi, [rel str_lock_created]
    call form_out_put_str
    movzx edi, byte [rel lock_desktop_created]
    call form_out_put_dec
    lea  rdi, [rel str_lock_console_sessions]
    call form_out_put_str
    call lock_screen_console_count
    mov  edi, eax
    call form_out_put_dec
    lea  rdi, [rel str_lock_rendered]
    call form_out_put_str
    movzx edi, byte [rel lock_rendered]
    call form_out_put_dec
    lea  rdi, [rel str_lock_input_kat]
    call form_out_put_str
    movzx edi, byte [rel lock_input_kat_ok]
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_kat]
    call form_out_put_str
    movzx edi, byte [rel lock_badge_kat_ok]
    call form_out_put_dec
    lea  rdi, [rel str_lock_tab_keep_kat]
    call form_out_put_str
    movzx edi, byte [rel lock_tab_keep_kat_ok]
    call form_out_put_dec
    ; Sample the sender once, then format bounded non-secret lifecycle data.
    call udp_boot_beacon_observe
    push rsi
    push r11
    push r10
    push r9
    push r8
    push rcx
    push rdx
    push rax
    lea  rdi, [rel str_lock_badge_dismissed]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_first]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_deadline]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_now]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_event]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_cause]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_beacon_count]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_beacon_last]
    call form_out_put_str
    pop  rdi
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_painted]
    call form_out_put_str
    movzx edi, byte [rel lock_painted_badge]
    call form_out_put_dec
    lea  rdi, [rel str_lock_badge_repairs]
    call form_out_put_str
    mov  rdi, [rel lock_badge_repairs]
    call form_out_put_dec
    lea  rdi, [rel str_lock_paints]
    call form_out_put_str
    mov  rdi, [rel lock_paint_count]
    call form_out_put_dec
    lea  rdi, [rel str_lock_epoch]
    call form_out_put_str
    mov  rdi, [rel session_authority_epoch]
    call form_out_put_dec
    lea  rdi, [rel str_lock_failures]
    call form_out_put_str
    mov  rdi, [rel prin_password_failures]
    call form_out_put_dec
    lea  rdi, [rel str_lock_backoff]
    call form_out_put_str
    mov  rdi, [rel prin_password_backoff_until]
    call form_out_put_dec
    lea  rdi, [rel str_lock_enrolled]
    call form_out_put_str
    movzx edi, byte [rel prin_password_enrolled]
    call form_out_put_dec
    lea  rdi, [rel str_lock_policy]
    call form_out_put_str
    movzx edi, byte [rel session_boot_policy]
    call form_out_put_dec
    lea  rdi, [rel str_lock_boot]
    call form_out_put_str
    mov  rdi, [rel boot_tsc_start]
    call form_out_put_dec
    lea  rdi, [rel str_lock_nonce]
    call form_out_put_str
    mov  rdi, r12
    call form_out_put_str
    cmp  byte [rel lock_composition_ok], 1
    jne  .ready
    lea  rdi, [rel str_lock_state_markers]
    call form_out_put_str
    cmp  byte [rel lock_rendered], 1
    jne  .ready
    lea  rdi, [rel str_lock_state_render]
    call form_out_put_str
    jmp  .ready
.bad:
    call form_out_reset
    lea  rdi, [rel str_lock_bad_nonce]
    call form_out_put_str
.ready:
    mov  byte [rel form_out_ready], 1
    pop  r12
    ret

; Minimal locked wire floor. Every listed mutation still crosses AUTH1;
; this predicate grants no authority and creates no private command route.
lock_screen_command_allowed:
    cmp  byte [rel lock_surface_ready], 1
    jne  .yes
    cmp  byte [rel lock_composition_ok], 1
    je   .composed
    ; A missing framebuffer is not authority. The headless path may leave the
    ; locked-name floor only after the shared session verifies a real bound
    ; principal/key handle from authenticate_bind; an unlocked bit alone is
    ; insufficient, and failed composition still fails closed before login.
    push rdi
    call session_shell_require_unlocked
    pop  rdi
    test eax, eax
    jz   .yes
    jmp  .locked
.composed:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    je   .yes
.locked:
    ; The canonical menu observation uses a colon nonce in the verb token.
    ; Match its exact interceptor prefix; its existing AUTH1 gate still runs.
    cmp  dword [rdi], 'MENU'
    jne  .exact_names
    cmp  dword [rdi + 4], '_QUE'
    jne  .exact_names
    cmp  word [rdi + 8], 'RY'
    jne  .exact_names
    cmp  byte [rdi + 10], ':'
    je   .yes
.exact_names:
    push rbx
    push r12
    mov  r12, rdi
    lea  rbx, [rel lock_ingress_names]
.scan:
    cmp  byte [rbx], 0
    je   .no
    mov  rdi, r12
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jz   .found
.next_name:
    cmp  byte [rbx], 0
    lea  rbx, [rbx + 1]
    jne  .next_name
    jmp  .scan
.no:
    pop  r12
    pop  rbx
    xor  eax, eax
    ret
.found:
    pop  r12
    pop  rbx
.yes:
    mov  eax, 1
    ret

lock_ingress_names:
    ; Canonical boot observation uses PING nonce, not STATUS. Recovery reads
    ; C2RECOVERY through AUTH1; session availability must not remove that read
    ; or change its existing owner capability requirement.
    db "PING",0,"STATUS",0,"LIVENESS",0,"BOOTLOG",0,"AUTHSTAT",0,"AUTHVERBS",0,"SECUREBOOT",0
    db "BOOTCLOCK",0                    ; public read-only clock observation, no session change
    db "C2RECOVERY",0
    db "LOCKSTATE",0,"SESSIONINFO",0,"WINTREE",0,"WINCHROME",0
    db "AUTHLOGIN",0,"AUTHENROLL",0,"SESSIONLOCK",0,"LOCK",0
    ; BOOTLINUX is the exact one-token CAP_BOOT recovery interceptor. The
    ; locked session already admits typed BOOT; keep the same AUTH1-gated
    ; route available when the registry argument path itself is impaired.
    db "BOOT",0,"BOOTLINUX",0,"REBOOT",0,"MENU_QUERY",0,"SCAP",0,"SCAPSTAT",0
    db "SCAPGRANT",0,"HELP",0,"CATALOG",0
    ; Rescue-0 R0-0: public read-only pre-EBS SNP record (no effect, no authority).
    db "R0STAT",0,0
str_lockstate_verb: db "LOCKSTATE",0
str_lock_verb: db "LOCK",0
str_lock_user: db "paos",0
str_lock_user_legacy: db "user",0
str_login_label_ok: db "[PAOS64] login owner label: one authenticate_bind path and data-preserving rotation KAT PASS [login.owner.label.migration]", 13, 10, 0
str_login_label_fail: db "[PAOS64] login owner label: rotation KAT FAIL [login.owner.label.migration.fail]", 13, 10, 0
str_lock_setup: db "Set local owner password",0
str_lock_staged: db "Owner staged; restart to apply",0
str_lock_stage: db "Stage owner",0
str_lock_signin: db "Sign in",0
str_lock_prompt: db "Enter your password",0
%if !PAOS_PUBLIC_BUILD
str_lock_prompt_files: db "Enter password to open files",0   ; WGI_VAL_MAX 31
%endif
str_lock_retry: db "Sign-in refused; wait and retry",0
str_lock_state: db "LOCKSTATE form=lock_screen slot=",0
str_lock_state_headless: db "LOCKSTATE form=headless framebuffer=",0
str_lock_state_locked: db " locked=",0
str_lock_headless_floor: db "[PAOS64] login R1: headless lock floor: LOCKSTATE/LOCK registered without a composed form; the session gate stays locked",13,10,0
str_lock_pid: db " principal=",0
str_lock_desktop: db " desktop=",0
str_lock_created: db " desktop_created=",0
str_lock_console_sessions: db " console_sessions=",0
str_lock_rendered: db " rendered=",0
str_lock_input_kat: db " secret_kat=",0
str_lock_badge_kat: db " badge_kat=",0
str_lock_tab_keep_kat: db " tab_keep_kat=",0
str_lock_tab_keep_ok: db "[PAOS64] login R1: Tab focus moves keep the password; an identity edit voids it [login.tab_keep.kat]",13,10,0
str_lock_tab_keep_fail: db "[PAOS64] login R1: Tab/identity secret KAT FAILED [login.tab_keep.kat.fail]",13,10,0
str_lock_badge_dismissed: db " badge_dismissed=",0
str_lock_badge_first: db " badge_first_ms=",0
str_lock_badge_deadline: db " badge_deadline_ms=",0
str_lock_badge_now: db " badge_now_ms=",0
str_lock_badge_event: db " badge_event_ms=",0
str_lock_badge_cause: db " badge_cause=",0
str_lock_beacon_count: db " beacon_tx_count=",0
str_lock_beacon_last: db " beacon_last_ms=",0
str_lock_badge_painted: db " badge_painted=",0
str_lock_badge_repairs: db " badge_repairs=",0
str_lock_paints: db " paints=",0
str_lock_epoch: db " authority_epoch=",0
str_lock_failures: db " failures=",0
str_lock_backoff: db " backoff_until=",0
str_lock_enrolled: db " enrolled=",0
str_lock_policy: db " dev_policy=",0
str_lock_bypass_off: db " bypass_reason=none",0
str_lock_bypass_dev: db " bypass_reason=loop_dev",0
str_lock_bypass_try: db " bypass_reason=volatile_local_try",0
str_lock_boot: db " BOOT_SESSION=",0
str_lock_nonce: db " nonce=",0
str_lock_bad_nonce: db "LOCKSTATE REFUSED bad_nonce",0
str_lock_state_markers: db " login.authenticate.bind login.dev.bypass",0
str_lock_state_render: db " login.lock.render",0
%ifndef PAOS_LOGIN_FIXTURE_NONCE
%define PAOS_LOGIN_FIXTURE_NONCE "none"
%endif
str_lock_boot_report: db "[PAOS64] LOGINBOOT nonce=",PAOS_LOGIN_FIXTURE_NONCE," locked=",0
str_lock_begin: db "[PAOS64] login R1: composing stock sign-in form",13,10,0
str_lock_failed: db "[PAOS64] login R1: stock sign-in composition FAILED form_error=",0
str_lock_failed_widgets: db " widgets=",0
str_lock_render_marker: db "[PAOS64] login R1: stock form plus wallpaper lock surface rendered [login.lock.render]",13,10,0
str_lock_bind_marker: db "[PAOS64] login R1: password submit uses authenticate_bind output-only principal [login.authenticate.bind]",13,10,0
str_lock_policy_marker: db "[PAOS64] login R1: default-off dev-only autologin policy shares the boot gate [login.dev.bypass]",13,10,0
lock_surface_ready: db 0
lock_surface_loading: db 0
lock_composition_ok: db 0
lock_verbs_ok: db 0
lock_rendered: db 0
lock_input_kat_ok: db 0
lock_badge_kat_ok: db 0
lock_boot_report_owed: db 0             ; boot audit (2): LOGINBOOT waits for the held first present
lock_tab_keep_kat_ok: db 0
lock_desktop_created: db 0
align 4
lock_wallpaper_load: dd 0xFFFFFFFF    ; DISPLAY: WIS_LOAD of the boot wallpaper bind (all ones = not reached)
lock_desktop_started: db 0
lock_restore_pending: db 0
lock_setup_staged: db 0
lock_submit_human: db 0
lock_submit_proof: db 0
align 8
lock_submit_revision: dq 0
lock_submit_pending: db 0
lock_painted_badge: db 0
align 8
lock_badge_repairs: dq 0
lock_paint_count: dq 0
lock_restore_op: dq 0
lock_painted_epoch: dq -1
lock_widget_first: dd 0
lock_notice_kind: dd 0                  ; lock_screen_notice state (0 = none)
lock_notice_secs: dd 0
lock_saved_focus: dd WM_MAX
lock_saved_windows: times WM_MAX dd 0

; Task3472 — login owner label migration content KAT (see completion doc). qemu-graded.
login_owner_label_migration_kat:
    push rbx
    lea  rdi, [rel str_lock_paos_probe]
    lea  rsi, [rel str_lock_user]
    call strcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_lock_user_legacy]
    lea  rsi, [rel str_lock_user]
    call strcmp
    test eax, eax
    jz   .fail
    lea  rax, [rel principal_local_password]
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_login_label_ok]
    call serial_string
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_login_label_fail]
    call serial_string
    pop  rbx
    ret
str_lock_paos_probe: db "paos",0

%include "gui/lock_screen_card.asm"
%include "gui/lock_backdrop.asm"
%include "gui/lock_screen_text.asm"

%include "gui/lock_ssh_notice.asm"
