;; MODULE gui/start_programs
;; LAYER 6
;; EXPORTS start_programs_open_update_restart, start_programs_init, start_programs_open_help, start_programs_tick, start_programs_cmd_formload, start_programs_click, start_programs_key_filter, sp_arm_holds, sp_disarm, sp_disarm_settings, sp_arm_card_wid, sp_ptr_up_x, sp_ptr_up_y, sp_ptr_up_seq, sp_ptr_inj_seq, sp_form_widgets_n
;; IMPORTS gui/settings_terminal_network, gui/settings_updates, gui/settings_update_backend, gui/app_reader, gui/form_loader, gui/widget, gui/window_mgmt, gui/terminal_app, gui/power_exec, gui/settings_prefs, gui/help_view, gui/wifi_local, gui/wm_pointer, dev/input/ps2, boot/gop, svc/command, svc/command_cons, boot/serial
;; CAPS CAP_GUI
;; OWNER saga:msi_start_programs_settings
; ============================================================================
; gui/start_programs.asm — the MSI Start menu's programs and power entries as
; rows of the hub's own Start/Summon catalogue (hub packet 0010).
;
; Peter 2026-09-29 (Task3475): Start lists Terminal, Settings and the three
; ways to leave PaOS (Restart, Shut down, Return to Windows), and each way to
; leave asks first. On the hub the Summon palette is Start (MSI conflict map:
; the hub wins in Start/Summon), so nothing here draws a menu. The entries are
; form-registry rows from index 15 up (form_loader.asm), pinned and listed by
; the palette exactly like sysprops:
;   terminal            FORMLOAD terminal -> a Terminal window (gui/terminal_app)
;   settings            a real form: the live machine facts + the display time
;                       zone preference (apply/cancel/reset: gui/settings_prefs.asm)
;   restart, shut_down, return_to_windows
;                       FORMLOAD -> the shared power confirmation (row 17),
;                       labelled for that action, the keyboard on Cancel
; The confirmation keeps the MSI semantics: nothing happens without an explicit
; confirm (the action button, or Y). Cancel, N, Esc, and Enter on the default
; focus cancel. Its clicks and keys only record a pending answer; the idle tick
; acts after the pointer/key path has unwound (as lock_screen defers its
; submit). power_execute (gui/power_exec.asm) returns only when nothing
; happened, and the dialog then says why, in place.
; SEC R1 (root 19:34:46): only local hands confirm. A Yes click counts only when
; wm_pointer_origin is HUMAN, and Y or Enter on Yes only when input_key_origin is
; KO_HUMAN. Injected ones (MOUSEINJ, PTRINJ, KBINJ) are ignored, not taken as a
; cancel; an injected Cancel, N or Esc still cancels.
; SEC R1 F1 (srcreview 20:37:58, the guardian_indicator arm): MOUSEINJ also moves
; the cursor, so a physical click that never moved could land on a Yes an
; injection parked it on. Yes, and Settings' Apply and Reset, count a HUMAN press
; only while ARMED: wm_pointer_event shows start_programs_pointer_note every
; event. An injected one disarms all three; a physical one OUTSIDE a live
; button arms it at that button's rectangle (absolute, so a moved or resized
; window no longer matches); a physical one inside while another window is on
; top there disarms it (a raise or uncover under a resting cursor); inside and
; on top leaves it. Every FORMLOAD (opening or raising a form) disarms.
; Return 22:42:47: a row also binds the screen (fb_width/fb_height, as the
; guardian's gi_armed_w/h), so a RESSET that clamps a resting cursor onto the
; button never confirms (FA); a shown overlay (layer 1: menus, dropdowns, the
; Summon palette) at an inside point is cover, like another window (FB).
; FORMLOAD power (row 17 by name) is refused: it has no action of its own.
; RCQ-40 J2b-P (rc-input Q1 10:20:04): a 4th row arms the owner action card's
; Confirm (gui/card_surface writes sp_arm_card_wid; -1 = no card) by the same
; rules as Yes. The note also records each HUMAN left release (its raw point
; and a count, after the row notes) so the card can require press + release.
; ============================================================================

SP_PEND_NONE        equ 0
SP_PEND_CONFIRM     equ 1
SP_PEND_CANCEL      equ 2
SP_ARM_YES          equ 0               ; sp_arm_rect rows: x, y, w, h, fb_width, fb_height, 0, 0 (x -1 = disarmed)
SP_ARM_APPLY        equ 1
SP_ARM_RESET        equ 2
SP_ARM_CARD         equ 3               ; RCQ-40 J2b-P: the owner action card's Confirm
SP_ARM_SHIFT        equ 5               ; 32-byte rows
SP_ARM_WIFI_NEXT    equ 4
SP_ARM_WIFI_SAVE    equ 5
SP_ARM_WIFI_CONNECT equ 6
SP_ARM_WALL         equ 7
SP_ARM_APP_REMOVE   equ 18              ; Settings > Apps confirm; after eleven wallpaper choices
SP_ARM_ROWS         equ 25

start_programs_init:
    ; FORMLOAD: extend the row in place (outside the Console's own wrapper);
    ; every other form name tail-dispatches to the handler that was there.
    lea  rdi, [rel sp_str_formload]
    call command_lookup
    cmp  eax, -1
    je   .no_formload
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rcx, rax
    mov  rax, [rcx + VERB_HANDLER]
    mov  [rel sp_formload_fallback], rax
    lea  rax, [rel start_programs_cmd_formload]
    mov  [rcx + VERB_HANDLER], rax
.no_formload:
    ; the kit's single click hook and key filter, chained (lock screen first)
    mov  rax, [rel wgt_click_hook]
    mov  [rel sp_click_prev], rax
    lea  rax, [rel start_programs_click]
    mov  [rel wgt_click_hook], rax
    mov  rax, [rel wgt_key_filter]
    mov  [rel sp_key_prev], rax
    lea  rax, [rel start_programs_key_filter]
    mov  [rel wgt_key_filter], rax
    lea  rax, [rel start_programs_pointer_note]
    mov  [rel wm_pointer_note_hook], rax ; SEC R1 F1
    call help_view_init                 ; RCQ-38 H2: the helptext type, after every shipped type
    call text_view_init                 ; T5-15: the textview type, after it
    call app_reader_init                ; G37: separate bounded app reader
    lea  rdi, [rel sp_ready_text]
    call serial_string
    ret

;; start_programs_open_help(): RCQ-38 H2, Win+F1 (gui/input_route, the owner's
;; hand, unlocked): open Help, or raise it, with the keyboard. The same
;; disarm as every FORMLOAD (SEC R1 F1). Clobbers caller-saved registers.
start_programs_open_help:
    sub  rsp, 8
    call sp_disarm
    mov  edi, FORM_HELP_INDEX
    mov  edx, 1
    call form_load_internal
    add  rsp, 8
    ret

;; start_programs_open_text(): T5-15, File Explorer's open hook: open the Text
;; Viewer, or raise it. The same disarm as every FORMLOAD (SEC R1 F1).
;; Clobbers caller-saved registers.
start_programs_open_text:
    sub  rsp, 8
    call sp_disarm
    mov  edi, FORM_TEXT_INDEX
    mov  edx, 1
    call form_load_internal
    add  rsp, 8
    ret

;; start_programs_open_apps(): Settings' Apps button, from its idle tick. Opens
;; or raises the window, with the same disarm as every FORMLOAD (SEC R1 F1).
;; -> EAX 1 the whole window is there, 0 the loader refused it.
;; Clobbers caller-saved registers.
start_programs_open_apps:
    sub  rsp, 8
    call sp_disarm
    mov  edi, FORM_APPS_INDEX
    mov  edx, 1
    call form_load_internal
    call sp_apps_scan
    call settings_apps_show
    movzx eax, byte [rel sa_live]
    add  rsp, 8
    ret

;; start_programs_open_about(): Settings' About button, from its idle tick.
;; Opens or raises the existing About this PC (form 3) with the same disarm as
;; every FORMLOAD. -> EAX 1 opened, 0 the loader refused it.
start_programs_open_about:
    sub  rsp, 8
    call sp_disarm
    mov  edi, 3                         ; existing About this PC, not a new form
    mov  edx, 1
    call form_load_internal
    xor  eax, eax
    cmp  dword [rel form_error], FORM_ERR_NONE
    sete al
    add  rsp, 8
    ret

; Updates only reaches this after an explicit current-owner Restart press.
; Original power confirmation still owns confirmation/quiesce/reset/return.
start_programs_open_update_restart:
    sub rsp, 8
    call sp_disarm
    mov edi, FORM_POWER_INDEX
    mov edx, 1
    call form_load_internal
    cmp dword [rel form_error], FORM_ERR_NONE
    jne .out
    mov edi, POWER_RESTART
    call sp_dialog_label
.out:
    add rsp, 8
    ret

;; sp_token_is(RDI arg, RSI lower-case keyword) -> EAX 1 when the first token
;; of arg is exactly keyword (followed by NUL or a space)
sp_token_is:
.l:
    mov  al, [rsi]
    test al, al
    jz   .end
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    inc  rsi
    jmp  .l
.end:
    mov  al, [rdi]
    test al, al
    jz   .yes
    cmp  al, ' '
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

;; start_programs_cmd_formload(RDI = req, RSI = rsp)
start_programs_cmd_formload:
    call form_verb_unlocked             ; RCQ-16 F2b-1: refused under the lock, first
    test eax, eax
    jz   .unlocked
    ret
.unlocked:
    call sp_disarm                      ; SEC R1 F1: a form opened or raised under a resting cursor
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .fallback
    push rdi
    push rsi
    mov  rdi, rax
    lea  rsi, [rel sp_name_terminal]
    call sp_token_is
    test eax, eax
    jnz  .terminal
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_restart]
    call sp_token_is
    mov  ecx, POWER_RESTART
    test eax, eax
    jnz  .power
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_shutdown]
    call sp_token_is
    mov  ecx, POWER_SHUTDOWN
    test eax, eax
    jnz  .power
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_windows]
    call sp_token_is
    mov  ecx, POWER_WINDOWS
    test eax, eax
    jnz  .power
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_power]
    call sp_token_is
    test eax, eax
    jnz  .power_bare
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_settings]
    call sp_token_is
    test eax, eax
    jnz  .settings
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_apps]
    call sp_token_is
    test eax, eax
    jnz  .apps
%ifdef WIFI_LOCAL_GUI_BUILT
    mov  rdi, [rsp + 8]
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel sp_name_wifi]
    call sp_token_is
    test eax, eax
    jnz .wifi
%endif
    pop  rsi
    pop  rdi
.fallback:
    jmp  qword [rel sp_formload_fallback]

%ifdef WIFI_LOCAL_GUI_BUILT
.wifi:
    pop rsi
    pop rdi
    call qword [rel sp_formload_fallback]
    push rax
    cmp dword [rel form_error], FORM_ERR_NONE
    jne .wifi_out
    call wifi_local_show
.wifi_out:
    pop rax
    ret
%endif
.apps:
    pop  rsi
    pop  rdi
    call qword [rel sp_formload_fallback]
    push rax
    call sp_apps_scan
    call settings_apps_show
    pop  rax
    ret
.settings:
    ; the established handler loads (or raises) it; then the Preferences show
    ; the zone in force (form text cannot hold spaces, so the status line gets
    ; its readable wording here, as lock_screen does)
    pop  rsi
    pop  rdi
    call qword [rel sp_formload_fallback]
    push rax
    cmp  dword [rel form_error], FORM_ERR_NONE
    jne  .settings_out
    call sp_settings_scan
    call settings_prefs_show                ; nothing unless the whole form is there
.settings_out:
    pop  rax
    ret

.terminal:
    pop  rsi
    pop  rdi
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rsi
    call terminal_open                  ; -> EAX WM slot or -1
    mov  r13d, eax
    call form_out_reset
    cmp  r13d, -1
    je   .terminal_refused
    mov  dword [rel form_error], FORM_ERR_NONE
    lea  rdi, [rel sp_str_formload_ok]
    call form_out_put_str
    lea  rdi, [rel sp_name_terminal]
    call form_out_put_str
    lea  rdi, [rel sp_str_win]
    call form_out_put_str
    mov  edi, r13d
    call form_out_put_dec
    lea  rdi, [rel sp_str_app_terminal]
    call form_out_put_str
    mov  [r12 + RSP_VAL], r13
    jmp  .terminal_stage
.terminal_refused:
    mov  dword [rel form_error], FORM_ERR_NO_SLOT
    lea  rdi, [rel sp_str_terminal_err]
    call form_out_put_str
    mov  qword [r12 + RSP_VAL], 0
.terminal_stage:
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    ret

.power_bare:
    ; row 17 by name has no action: refuse, nothing opens
    pop  rsi
    pop  rdi
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call form_out_reset
    mov  dword [rel form_error], FORM_ERR_MISSING
    lea  rdi, [rel sp_str_power_err]
    call form_out_put_str
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_VAL], 0
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    ret

.power:
    ; ECX kind: load row 17 through the established handler
    ; (its parser, single-instance rule and canonical reply), then label it.
    pop  rsi
    pop  rdi
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, ecx
    ; "power" + the caller's options (title=, focus=) after the row name
    mov  rax, [rbx + REQ_ARG]
    mov  r14, rax
.skip_name:
    mov  cl, [rax]
    test cl, cl
    jz   .name_done
    cmp  cl, ' '
    je   .name_done
    inc  rax
    jmp  .skip_name
.name_done:
    lea  rdi, [rel sp_formload_arg]
    lea  rsi, [rel sp_name_power]
.cp_power:
    mov  cl, [rsi]
    test cl, cl
    jz   .cp_rest
    mov  [rdi], cl
    inc  rsi
    inc  rdi
    jmp  .cp_power
.cp_rest:
    lea  rdx, [rel sp_formload_arg + SP_ARG_MAX - 1]
.cp_rest_l:
    cmp  rdi, rdx
    jae  .cp_end
    mov  cl, [rax]
    test cl, cl
    jz   .cp_end
    mov  [rdi], cl
    inc  rax
    inc  rdi
    jmp  .cp_rest_l
.cp_end:
    mov  byte [rdi], 0
    lea  rax, [rel sp_formload_arg]
    mov  [rbx + REQ_ARG], rax
    mov  rdi, rbx
    mov  rsi, r12
    push rbx                            ; the loader's painters do not preserve RBX
    call qword [rel sp_formload_fallback]
    pop  rcx
    mov  [rcx + REQ_ARG], r14
    push rax
    cmp  dword [rel form_error], FORM_ERR_NONE
    jne  .power_out
    mov  edi, r13d
    call sp_dialog_label
.power_out:
    pop  rax
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; sp_dialog_scan() -> EAX the confirmation's WM slot or -1; on a live dialog
;; sp_w_question / sp_w_yes / sp_w_cancel hold its widget ids (declaration
;; order). Clobbers caller-saved registers.
sp_dialog_scan:
    mov  edi, FORM_POWER_INDEX
    call sp_form_widgets
    cmp  eax, 3
    jb   .none
    ; RCQ-38 L3a (rc-sec N1): the confirmation's question and buttons are a
    ; security surface; they paint through sec_text_escape (wgt_sec_text).
    mov  edi, [rel sp_w_question]
    call wgt_mark_sectext
    mov  edi, [rel sp_w_yes]
    call wgt_mark_sectext
    mov  edi, [rel sp_w_cancel]
    call wgt_mark_sectext
    mov  eax, ecx
    ret
.none:
    mov  eax, -1
    ret

;; sp_form_widgets(EDI form index) -> EAX widgets found (0..3) of that form's
;; live window, their ids in sp_w_question/_yes/_cancel (declaration order),
;; ECX its WM slot. Clobbers caller-saved registers.
sp_form_widgets:
    mov  esi, 3
    lea  rdx, [rel sp_w_question]       ; dd[3]: sp_w_question, sp_w_yes, sp_w_cancel (adjacent in WDATA)
;; sp_form_widgets_n(EDI form index, ESI max, RDX dd[max]) -> EAX widgets found
;; (0..max) of that form's live window, their ids at RDX (declaration order),
;; ECX its WM slot. Clobbers caller-saved registers.
;; form_active_slot outlives a closed window and the slot number is reused (a
;; closed Power dialog's slot 0 becomes Settings'), so the slot is that form's
;; window only while it carries the form-owned title, the loader's own
;; single-instance identity (form_loader .validate_existing).
sp_form_widgets_n:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, esi
    mov  r15, rdx
    xor  r13d, r13d                     ; widgets of this window found
    lea  rax, [rel form_active_slot]
    mov  r12d, [rax + rdi*4]
    cmp  r12d, 0
    jl   .none
    cmp  r12d, WM_MAX
    jae  .none
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .owned
    cmp  eax, WM_MIN
    jne  .none
.owned:
    imul eax, edi, FORM_TITLE_MAX
    lea  rcx, [rel form_titles]
    add  rax, rcx
    lea  rcx, [rel wm_title]
    cmp  [rcx + r12*8], rax
    jne  .none                          ; another window now holds the slot
.live:
    xor  ebx, ebx                       ; widget id
    xor  r13d, r13d                     ; widgets of this window found
.scan:
    cmp  ebx, [rel wgt_count]
    jae  .scanned
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .next
    cmp  [rax + WGI_WIN], r12d
    jne  .next
    mov  [r15 + r13*4], ebx
    inc  r13d
    cmp  r13d, r14d
    jae  .scanned
.next:
    inc  ebx
    jmp  .scan
.scanned:
.none:
    mov  eax, r13d
    mov  ecx, r12d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; sp_settings_scan(): RCQ-17. The live Settings window's widgets -> stp_ids
;; and stp_slot; stp_live 1 only when the whole form is there.
;; Clobbers caller-saved registers.
sp_settings_scan:
    mov  byte [rel stp_live], 0
    mov  edi, FORM_SETTINGS_INDEX
    mov  esi, STP_W_COUNT
    lea  rdx, [rel stp_ids]
    call sp_form_widgets_n
    cmp  eax, STP_W_COUNT
    jb   .out
    mov  [rel stp_slot], ecx
    mov  byte [rel stp_live], 1
.out:
    ret

;; sp_help_scan(): RCQ-38 H2. The live Help window's widgets -> hv_ids and
;; hv_slot (gui/help_view); hv_live 1 only when the whole form is there.
;; Clobbers caller-saved registers.
sp_help_scan:
    mov  byte [rel hv_live], 0
    mov  edi, FORM_HELP_INDEX
    mov  esi, HV_W_COUNT
    lea  rdx, [rel hv_ids]
    call sp_form_widgets_n
    cmp  eax, HV_W_COUNT
    jb   .out
    mov  [rel hv_slot], ecx
    mov  byte [rel hv_live], 1
.out:
    ret

;; sp_text_scan(): T5-15, as sp_help_scan for the Text Viewer window.
;; Clobbers caller-saved registers.
sp_text_scan:
    mov  byte [rel tv_live], 0
    mov  edi, FORM_TEXT_INDEX
    mov  esi, TV_W_COUNT
    lea  rdx, [rel tv_ids]
    call sp_form_widgets_n
    cmp  eax, TV_W_COUNT
    jb   .out
    mov  [rel tv_slot], ecx
    mov  byte [rel tv_live], 1
.out:
    ret

;; sp_apps_scan(): the live Settings > Apps window's widgets -> sa_ids; sa_live
;; 1 only when the whole form is there. Clobbers caller-saved registers.
sp_apps_scan:
    mov  byte [rel sa_live], 0
    mov  edi, FORM_APPS_INDEX
    mov  esi, SA_W_COUNT
    lea  rdx, [rel sa_ids]
    call sp_form_widgets_n
    cmp  eax, SA_W_COUNT
    jb   .out
    mov  byte [rel sa_live], 1
.out:
    ret

;; sp_apps_tick(): Settings > Apps has something to do this tick.
sp_apps_tick:
    mov  eax, [rel sa_state]
    or   al, [rel sa_listing]
    cmp  qword [rel sa_ticket], 0
    jne  .work
    test eax, eax
    jz   .out
.work:
    sub  rsp, 8
    call sp_apps_scan
    call settings_apps_tick
    add  rsp, 8
.out:
    ret

;; sp_dialog_label(EDI kind): the opened (or raised) confirmation asks about
;; this action, its button names it, and the keyboard rests on Cancel.
sp_dialog_label:
    push rbx
    push r12
    mov  ebx, edi
    call sp_dialog_scan
    cmp  eax, -1
    je   .out
    mov  r12d, eax
    mov  [rel sp_kind], ebx
    mov  byte [rel sp_pending], SP_PEND_NONE
    lea  rsi, [rel sp_q_restart]
    lea  rdx, [rel sp_b_restart]
    lea  r8, [rel sp_open_restart]
    cmp  ebx, POWER_RESTART
    je   .set
    lea  rsi, [rel sp_q_shutdown]
    lea  rdx, [rel sp_b_shutdown]
    lea  r8, [rel sp_open_shutdown]
    cmp  ebx, POWER_SHUTDOWN
    je   .set
    lea  rsi, [rel sp_q_windows]
    lea  rdx, [rel sp_b_windows]
    lea  r8, [rel sp_open_windows]
.set:
    mov  [rel sp_open_marker], r8
    push rdx
    mov  edi, [rel sp_w_question]
    call wgt_set_text
    pop  rsi
    mov  edi, [rel sp_w_yes]
    call wgt_set_text
    mov  eax, [rel sp_w_cancel]
    lea  rcx, [rel wgt_focus_by_win]
    mov  [rcx + r12*4], eax
    cmp  r12d, [rel wm_focus]
    jne  .said
    mov  [rel wgt_focus_id], eax
.said:
    mov  rdi, [rel sp_open_marker]
    call serial_string
    call wmx_draw_all
.out:
    pop  r12
    pop  rbx
    ret

;; start_programs_click(EDI = widget id): the kit's click hook (chained)
start_programs_click:
    push rdi
    call sp_dialog_scan
    pop  rdi
    cmp  eax, -1
    je   .settings
    cmp  edi, [rel sp_w_yes]
    je   .confirm
    cmp  edi, [rel sp_w_cancel]
    je   .cancel
.settings:
    push rdi
    call settings_terminal_network_click
    test eax,eax
    jnz .settings_out
    mov edi,[rsp]
    call settings_updates_click
    test eax, eax
    jnz .settings_out
    mov edi, [rsp]
    call wallpaper_prefs_click
    test eax, eax
    jnz .settings_out
    call sp_settings_scan
    mov  edi, [rsp]
    call sp_settings_press_counts       ; SEC R1 F1: Apply / Reset only from an armed local press
    test eax, eax
    jz   .ignored
    mov  edi, [rsp]
    call settings_prefs_click           ; Apply / Cancel / Reset of Settings
    test eax, eax
    jnz  .settings_out
%ifdef WIFI_LOCAL_GUI_BUILT
    mov edi, [rsp]
    call wifi_local_click
    test eax, eax
    jnz .settings_out
%endif
    call sp_apps_scan                   ; Settings > Apps: a coming row
    mov  edi, [rsp]
    call settings_apps_click
    test eax, eax
    jnz  .settings_out
    call sp_help_scan                   ; RCQ-38 H2: a click in Help (read-only navigation)
    mov  edi, [rsp]
    call help_view_click
    test eax, eax
    jnz  .settings_out
    call sp_text_scan                   ; T5-15: a click in the Text Viewer (read-only)
    mov  edi, [rsp]
    call text_view_click
.settings_out:
    pop  rdi
    test eax, eax
    jnz  .out
.chain:
    mov  rax, [rel sp_click_prev]
    test rax, rax
    jz   .out
    jmp  rax
.confirm:
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .out                           ; SEC R1: an injected click on Yes is ignored
    mov  esi, SP_ARM_YES
    call sp_arm_holds
    test eax, eax
    jz   .out                           ; SEC R1 F1: not steered onto Yes since the last injection
    mov  byte [rel sp_pending], SP_PEND_CONFIRM
    ret
.ignored:
    pop  rdi
    ret
.cancel:
    mov  byte [rel sp_pending], SP_PEND_CANCEL
.out:
    ret

;; sp_settings_press_counts(EDI hit widget) -> EAX 0 when a press on Settings'
;; Apply or Reset must be ignored: not HUMAN, or not armed (SEC R1 F1). Any
;; other widget, or no live Settings, counts (EAX 1). Clobbers caller-saved.
sp_settings_press_counts:
    mov  eax, 1
    cmp  byte [rel stp_live], 1
    jne  .out
    mov  esi, SP_ARM_APPLY
    cmp  edi, [rel stp_ids + STP_W_APPLY*4]
    je   .armed
    mov  esi, SP_ARM_RESET
    cmp  edi, [rel stp_ids + STP_W_RESET*4]
    jne  .out
.armed:
    xor  eax, eax
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .out
    jmp  sp_arm_holds
.out:
    ret

;; sp_arm_holds(EDI widget id, ESI SP_ARM_* row) -> EAX 1 when that row is armed
;; at the widget's current rectangle. Clobbers caller-saved.
sp_arm_holds:
    shl  esi, SP_ARM_SHIFT
    lea  rdx, [rel sp_arm_rect]
    add  rdx, rsi
    call wgt_slot_ptr
    mov  rcx, [rax + WGI_X]             ; x, y
    cmp  rcx, [rdx]
    jne  .no
    mov  rcx, [rax + WGI_W]             ; w, h
    cmp  rcx, [rdx + 8]
    jne  .no
    mov  rcx, [rel fb_width]            ; FA: the screen it was earned on (fb_width, fb_height adjacent)
    cmp  rcx, [rdx + 16]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

;; sp_disarm(): every row disarmed (x -1; a widget's x is never negative).
;; Touches memory only.
sp_disarm:
    mov dword [rel sp_arm_rect+(24 << SP_ARM_SHIFT)],-1
    push rcx
    push rdx
    lea rdx, [rel sp_arm_rect + (SP_ARM_WALL << SP_ARM_SHIFT)]
    mov ecx, 11
.wall:
    mov dword [rdx], -1
    add rdx, 1 << SP_ARM_SHIFT
    loop .wall
    mov  dword [rel sp_arm_rect + (SP_ARM_YES << SP_ARM_SHIFT)], -1
    mov  dword [rel sp_arm_rect + (SP_ARM_APPLY << SP_ARM_SHIFT)], -1
    mov  dword [rel sp_arm_rect + (SP_ARM_RESET << SP_ARM_SHIFT)], -1
    mov  dword [rel sp_arm_rect + (SP_ARM_CARD << SP_ARM_SHIFT)], -1
    mov  dword [rel sp_arm_rect + (SP_ARM_APP_REMOVE << SP_ARM_SHIFT)], -1
%assign upd_arm 19
%rep 5
    mov dword [rel sp_arm_rect + (upd_arm << SP_ARM_SHIFT)], -1
%assign upd_arm upd_arm+1
%endrep
%ifdef WIFI_LOCAL_GUI_BUILT
    mov dword [rel sp_arm_rect + (SP_ARM_WIFI_NEXT << SP_ARM_SHIFT)], -1
    mov dword [rel sp_arm_rect + (SP_ARM_WIFI_SAVE << SP_ARM_SHIFT)], -1
    mov dword [rel sp_arm_rect + (SP_ARM_WIFI_CONNECT << SP_ARM_SHIFT)], -1
%endif
    pop rdx
    pop rcx
    ret

;; sp_disarm_settings(): T5-14.C4a. Only Settings' Apply and Reset rows
;; disarmed: a page switch shows them under a cursor that rested there while
;; they were hidden (arming ignores visibility). Touches memory only.
sp_disarm_settings:
    mov  dword [rel sp_arm_rect + (SP_ARM_APPLY << SP_ARM_SHIFT)], -1
    mov  dword [rel sp_arm_rect + (SP_ARM_RESET << SP_ARM_SHIFT)], -1
    ret

;; start_programs_pointer_note(EDI x, ESI y, EDX buttons): wm_pointer_event's
;; note hook, for EVERY pointer event after wm_pointer_origin is set (header,
;; SEC R1 F1), before wm_pointer_last_btn takes EDX. Clobbers caller-saved.
start_programs_pointer_note:
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    setne al
    movzx eax, al
    add  [rel sp_ptr_inj_seq], eax      ; J2b-P (srcreview F1): every non-HUMAN event counted (spends a card latch)
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  sp_disarm
    mov  eax, [rel wm_pointer_last_btn]  ; J2b-P: a left release edge, judged before any call
    not  edx
    and  eax, edx
    and  eax, 1
    mov  [rel sp_ptr_up_now], al
    mov  rax, [rel fb_width]            ; FA2: every row armed on another screen is spent
    lea  rdx, [rel sp_arm_rect]         ; first, live dialog or not, so a refused click or a
    mov  ecx, SP_ARM_ROWS               ; clamp there cannot be restored by a RESSET back
    ; Wi-Fi rows are included in SP_ARM_ROWS.
.spend:
    cmp  rax, [rdx + 16]
    je   .kept
    mov  dword [rdx], -1
.kept:
    add  rdx, 1 << SP_ARM_SHIFT
    loop .spend
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call sp_dialog_scan                 ; the ids as of now: click / key / tick rescan, a motion must too
    cmp  eax, -1
    je   .settings                      ; no live dialog (sp_w_yes may be a closed one's)
    mov  ebx, SP_ARM_YES
    mov  edi, [rel sp_w_yes]
    call sp_arm_note
.settings:
    call sp_settings_scan
    cmp  byte [rel stp_live], 1
    jne  .done
    mov  ebx, SP_ARM_APPLY
    mov  edi, [rel stp_ids + STP_W_APPLY*4]
    call sp_arm_note
    mov  ebx, SP_ARM_RESET
    mov  edi, [rel stp_ids + STP_W_RESET*4]
    call sp_arm_note
.done:
    call wallpaper_prefs_scan
    cmp byte [rel wp_live], 1
    jne .wall_noted
    xor ebx, ebx
.wall_note:
    push rbx
    lea rax, [rel wp_ids+4]
    mov edi, [rax+rbx*4]
    add ebx, SP_ARM_WALL
    call sp_arm_note
    pop rbx
    inc ebx
    cmp ebx, 11
    jb .wall_note
.wall_noted:
%ifdef WIFI_LOCAL_GUI_BUILT
    call wifi_local_scan
    cmp byte [rel wfl_live], 1
    jne .wifi_noted
    mov ebx, SP_ARM_WIFI_NEXT
    mov edi, [rel wfl_ids + WFL_NEXT*4]
    call sp_arm_note
    mov ebx, SP_ARM_WIFI_SAVE
    mov edi, [rel wfl_ids + WFL_SAVE*4]
    call sp_arm_note
    mov ebx, SP_ARM_WIFI_CONNECT
    mov edi, [rel wfl_ids + WFL_CONNECT*4]
    call sp_arm_note
.wifi_noted:
%endif
    call updates_scan
    cmp eax, UPD_W_COUNT
    jne .updates_noted
    mov ebx, UPD_ARM_FIRST
.updates_note:
    mov ecx, ebx
    sub ecx, UPD_ARM_FIRST
    lea rax, [rel upd_ids+2*4]
    cmp ecx, 4
    jne .updates_widget
    lea rax, [rel upd_ids+UPD_DAILY_INDEX*4]
    xor ecx, ecx
.updates_widget:
    mov edi, [rax+rcx*4]
    push rbx
    call sp_arm_note
    pop rbx
    inc ebx
    cmp ebx, UPD_ARM_FIRST+5
    jb .updates_note
.updates_noted:
    call settings_terminal_network_pointer_note
    call settings_apps_confirm_id
    mov  edi, eax
    mov  ebx, SP_ARM_APP_REMOVE
    call sp_arm_note
    mov  ebx, SP_ARM_CARD               ; J2b-P: the card's Confirm, like Yes (-1: nothing)
    mov  edi, [rel sp_arm_card_wid]
    call sp_arm_note
    cmp  byte [rel sp_ptr_up_now], 1    ; after the notes: the release's own note decided row 3
    jne  .noted
    mov  [rel sp_ptr_up_x], r12d        ; the raw point, never clamped
    mov  [rel sp_ptr_up_y], r13d
    inc  dword [rel sp_ptr_up_seq]
.noted:
    pop  r13
    pop  r12
    pop  rbx
    ret

;; sp_arm_note(EDI widget id or -1, EBX row; R12D/R13D the physical cursor):
;; outside the live widget -> arm the row at its rectangle; inside with another
;; window on top there -> disarm; inside and on top -> unchanged.
sp_arm_note:
    cmp  edi, [rel wgt_count]
    jae  .out                           ; -1 or a stale id: nothing to arm
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .out
    mov  ecx, r12d
    sub  ecx, [rax + WGI_X]
    cmp  ecx, [rax + WGI_W]
    jae  .arm
    mov  ecx, r13d
    sub  ecx, [rax + WGI_Y]
    cmp  ecx, [rax + WGI_H]
    jae  .arm
    xor  ecx, ecx                       ; FB: a shown overlay (layer 1) at the point is cover
    lea  r8, [rel wgt_tbl]
.overlay:
    cmp  ecx, [rel wgt_count]
    jae  .window
    cmp  dword [r8 + WGI_TYPE], 0
    je   .overlay_next
    cmp  dword [r8 + WGI_LAYER], 1
    jne  .overlay_next
    test dword [r8 + WGI_FLAGS], 1
    jz   .overlay_next
    mov  r9d, r12d
    sub  r9d, [r8 + WGI_X]
    cmp  r9d, [r8 + WGI_W]
    jae  .overlay_next
    mov  r9d, r13d
    sub  r9d, [r8 + WGI_Y]
    cmp  r9d, [r8 + WGI_H]
    jb   .disarm
.overlay_next:
    add  r8, WGI_SZ
    inc  ecx
    jmp  .overlay
.window:
    push rax
    mov  edi, r12d
    mov  esi, r13d
    call wm_pointer_top_slot
    pop  rcx
    cmp  eax, [rcx + WGI_WIN]
    je   .out
.disarm:
    mov  eax, ebx
    shl  eax, SP_ARM_SHIFT
    lea  rdx, [rel sp_arm_rect]
    mov  dword [rdx + rax], -1
    ret
.arm:
    mov  ecx, ebx
    shl  ecx, SP_ARM_SHIFT
    lea  rdx, [rel sp_arm_rect]
    add  rdx, rcx
    mov  rcx, [rax + WGI_X]
    mov  [rdx], rcx
    mov  rcx, [rax + WGI_W]
    mov  [rdx + 8], rcx
    mov  rcx, [rel fb_width]            ; FA: fb_width, fb_height
    mov  [rdx + 16], rcx
.out:
    ret

;; start_programs_key_filter(EDI = focused widget id, EAX = key) -> EAX 1
;; handled. Only a key for the confirmation is taken; the owner's Tab stays
;; the kit's. SEC R1 K2: a key that is not KO_HUMAN may only cancel.
start_programs_key_filter:
    push rdi
    push rax
    call sp_dialog_scan
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
    cmp  eax, GUI_KEY_TAB
    jne  .key
    cmp  byte [rel input_key_origin], KO_HUMAN
    je   .pass                          ; the owner's Tab stays the kit's
    jmp  .taken                         ; SEC R1 K2: an injected Tab never moves the dialog's focus
.key:
    cmp  eax, GUI_KEY_ESC
    je   .cancel
    cmp  eax, 'n'
    je   .cancel
    cmp  eax, 'N'
    je   .cancel
    cmp  eax, 'y'
    je   .confirm
    cmp  eax, 'Y'
    je   .confirm
    cmp  eax, GUI_KEY_ENTER
    jne  .taken                         ; anything else does nothing here
    cmp  edi, [rel sp_w_yes]
    je   .confirm
.cancel:
    mov  byte [rel sp_pending], SP_PEND_CANCEL
    jmp  .taken
.confirm:
    cmp  byte [rel input_key_origin], KO_HUMAN
    jne  .taken                         ; SEC R1: an injected Y / Enter is taken and ignored
    mov  byte [rel sp_pending], SP_PEND_CONFIRM
.taken:
    mov  eax, 1
    ret
.pass:
    xor  eax, eax
    ret
.other:
    mov edi,[rsp+8]
    mov eax,[rsp]
    call settings_terminal_network_key
    test eax,eax
    jnz .other_taken
    mov edi, [rsp+8]
    mov eax, [rsp]
    call wallpaper_prefs_key
    test eax, eax
    jnz .other_taken
    mov edi, [rsp+8]
    mov eax, [rsp]
    call settings_updates_key
    test eax, eax
    jnz .other_taken
    call sp_settings_scan               ; RCQ-17: a key for the Settings Preferences
    mov  edi, [rsp + 8]
    mov  eax, [rsp]
    call settings_prefs_key
    test eax, eax
    jnz  .other_taken
%ifdef WIFI_LOCAL_GUI_BUILT
    mov edi, [rsp + 8]
    mov eax, [rsp]
    call wifi_local_key
    test eax, eax
    jnz .other_taken
%endif
    call sp_apps_scan                   ; Settings > Apps: Remove and its confirm
    mov  edi, [rsp + 8]
    mov  eax, [rsp]
    call settings_apps_key
    test eax, eax
    jnz  .other_taken
    call sp_help_scan                   ; RCQ-38 H2: a key for Help (read-only navigation)
    mov  edi, [rsp + 8]
    mov  eax, [rsp]
    call help_view_key
    test eax, eax
    jnz  .other_taken
    call sp_text_scan                   ; T5-15: a key for the Text Viewer (read-only)
    mov  edi, [rsp + 8]
    mov  eax, [rsp]
    call text_view_key
    test eax, eax
    jnz  .other_taken
    pop  rax
    pop  rdi
    mov  rdx, [rel sp_key_prev]
    test rdx, rdx
    jz   .none
    jmp  rdx
.none:
    xor  eax, eax
    ret
.other_taken:
    add  rsp, 16
    mov  eax, 1
    ret

;; start_programs_tick(): the idle loop. Acts on a pending answer once the
;; pointer/key path that recorded it has returned.
start_programs_tick:
    push rbx
    call settings_terminal_network_tick
    call settings_updates_tick
    call settings_update_backend_tick ; one bounded BSP/reentry-guarded native step
    pop rbx
    call wallpaper_prefs_tick
%ifdef WIFI_LOCAL_GUI_BUILT
    call wifi_local_tick
%endif
    call sp_apps_tick
    cmp  byte [rel stp_pending], 0
    je   .power
    call sp_settings_scan               ; RCQ-17: a recorded Settings action
    call settings_prefs_tick
.power:
    movzx eax, byte [rel sp_pending]
    test eax, eax
    jnz  .answer
    push rbx
    call sp_power_watch_tick            ; read-only outcome of this dialog's managed request
    pop rbx
    jmp  .out
.answer:
    mov  byte [rel sp_pending], SP_PEND_NONE
    push rbx
    mov  ebx, eax
    call sp_dialog_scan
    cmp  eax, -1
    je   .done
    cmp  ebx, SP_PEND_CANCEL
    jne  .confirm
    call sp_power_watch_cancel         ; same original dialog/plan; before resident power step
    cmp eax,-1
    je .done                           ; never dismiss a replacement observed during cancel
    push rax
    lea  rdi, [rel sp_cancel_text]
    call serial_string
    pop  rdi
    call wmx_close_slot
    jmp  .done
.confirm:
    call sp_power_watch_begin           ; capture the original window and widget lifetime
    mov  edi, [rel sp_kind]
    call power_execute_desktop          ; confirmed local OWNER opt-in; returns only when nothing happened: RAX = why
    call power_failure_label            ; same actual reason, bounded public cause
    mov  rsi, rax
    sub rsp,16                         ; preserve the text and nested-call alignment
    mov [rsp],rsi
    call sp_power_watch_arm             ; only the actual managed pending result can arm
    call sp_power_watch_same            ; no write into a reused window or widget
    mov rsi,[rsp]
    add rsp,16
    cmp  eax, -1
    je   .done
    push r12
    mov  r12d, eax                      ; the slot, kept clear of RBX across the kit's paint
    mov  edi, [rel sp_w_question]
    call wgt_set_text
    mov  eax, [rel sp_w_cancel]
    lea  rcx, [rel wgt_focus_by_win]
    mov  [rcx + r12*4], eax
    cmp  r12d, [rel wm_focus]
    jne  .drawn
    mov  [rel wgt_focus_id], eax
.drawn:
    pop  r12
    call wmx_draw_all
.done:
    pop  rbx
.out:
    ret

; Observe only the managed request returned by this confirmed dialog. The
; resident power tick owns stepping, recovery and commit. Cancel may request
; the original plan's existing pre-commit recovery, never another power action.
; No hardware rollback or readiness is inferred from a cancellation request.
sp_power_watch_begin:
    push rbx
    mov byte [rel sp_power_watch],0
    mov dword [rel sp_power_slot],-1
    mov ebx,eax                         ; sp_dialog_scan already bounded the live slot
    lea rcx,[rel wm_gen]
    mov eax,[rcx+rbx*4]
    test eax,eax
    jz .out
    cmp eax,-1
    je .out
    mov [rel sp_power_gen],eax
    mov edi,[rel sp_w_question]
    mov [rel sp_power_widget],edi
    call wgt_birth_lifetime             ; rejects zero and saturated/recycled births
    test rax,rax
    jz .out
    cmp rax,-1
    je .out
    mov [rel sp_power_birth],rax
    mov [rel sp_power_slot],ebx
.out:
    pop rbx
    ret

sp_power_watch_same:
    push rbx
    call sp_dialog_scan
    cmp eax,-1
    je .bad
    cmp eax,[rel sp_power_slot]
    jne .bad
    mov ebx,eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+rbx*4]
    cmp eax,[rel sp_power_gen]
    jne .bad
    mov edi,[rel sp_w_question]
    cmp edi,[rel sp_power_widget]
    jne .bad
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel sp_power_birth]
    jne .bad
    mov eax,ebx
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

sp_power_watch_arm:
    cmp dword [rel sp_power_slot],0
    jl .out
    lea rax,[rel power_label_pending]
    cmp rsi,rax                         ; the actual returned bounded result, no mutable-state guess
    jne .out
    push rbx
    call power_s5_status
    dec eax
    cmp eax,2                           ; WAIT / RECOVER / COMMIT only
    ja .done
    test rcx,rcx
    jz .done
    cmp rcx,-1
    je .done
    mov [rel sp_power_token],rcx         ; full64, never truncate to a slot/counter
    mov byte [rel sp_power_watch],1
.done:
    pop rbx
.out:
    ret

 ; The key/click callback has unwound. A cancellation recorded for this watched
; dialog is processed before power_events_tick in the original idle loop. The
; native boundary independently rechecks owner and the full64 parent token.
; EAX retains the original live slot, or -1 if its lifetime was replaced.
sp_power_watch_cancel:
    cmp byte [rel sp_power_watch],1
    jne .out                           ; ordinary unconfirmed dialog dismissal
    push rbx
    call sp_power_watch_same
    cmp eax,-1
    je .retire
    call power_s5_status
    cmp eax,1                          ; WAIT only; recovery/commit cannot be cancelled again
    jne .same
    cmp rcx,[rel sp_power_token]
    jne .same
    mov rdi,rcx
    call power_s5_cancel_desktop        ; returns request outcome, never a restoration promise
.same:
    call sp_power_watch_same            ; native callback may invalidate the public window
.retire:
    mov byte [rel sp_power_watch],0     ; request at most once; normal resident recovery continues
    pop rbx
.out:
    ret

sp_power_watch_tick:
    cmp byte [rel sp_power_watch],1
    jne .out
    push rbx
    call sp_power_watch_same            ; retire on disappearance, even during recovery
    cmp eax,-1
    je .retire
    call power_s5_status                ; read-only, same idle-loop producer as the power tick
    cmp rcx,[rel sp_power_token]
    jne .retire
    dec eax
    cmp eax,2
    jbe .done                           ; active/recovering: retain progress, no repeated paint
    mov byte [rel sp_power_watch],0      ; one terminal outcome, before any UI callback
    call power_s5_failure_label         ; existing bounded labels; actual offline/commit facts
    sub rsp,16
    mov [rsp],rax
    call sp_power_watch_same
    mov rsi,[rsp]
    add rsp,16
    cmp eax,-1
    je .done
    mov edi,[rel sp_w_question]
    call wgt_set_text
    call wmx_draw_all
    jmp .done
.retire:
    mov byte [rel sp_power_watch],0
.done:
    pop rbx
.out:
    ret

SP_ARG_MAX          equ 96
sp_str_formload:    db "FORMLOAD", 0
sp_name_terminal:   db "terminal", 0
sp_name_restart:    db "restart", 0
sp_name_shutdown:   db "shut_down", 0
sp_name_windows:    db "return_to_windows", 0
sp_name_power:      db "power", 0
sp_name_wifi: db "wifi_local",0
sp_name_settings:   db "settings", 0
sp_name_apps:       db "settings_apps", 0
sp_str_formload_ok: db " formload=ok name=", 0
sp_str_win:         db " win=", 0
sp_str_app_terminal: db " widgets=1 app=app_terminal", 0
sp_str_terminal_err: db " FORMLOAD formload=ERR terminal_limit", 0
sp_str_power_err:   db " FORMLOAD formload=ERR power_needs_an_action (restart, shut_down, return_to_windows)", 0
; questions and button names stay within the kit's 31-byte field
sp_q_restart:       db "Restart PaOS now?", 0
sp_q_shutdown:      db "Shut down (power off) now?", 0
sp_q_windows:       db "Return to Windows now?", 0
sp_b_restart:       db "Restart", 0
sp_b_shutdown:      db "Shut down", 0
sp_b_windows:       db "Return to Windows", 0
sp_f_windows:       db "Refused: no Windows entry", 0
sp_f_shutdown:      db "Power-off failed; still on", 0
sp_f_restart:       db "Restart failed; still running", 0
sp_f_other:         db "Not done; still running", 0
sp_ready_text:      db "[PAOS64] start.programs.ready (Summon rows terminal, settings, restart, shut_down, return_to_windows)", 13, 10, 0
sp_open_restart:    db "[PAOS64] start.power.dialog action=restart (asks first; Cancel has the keyboard)", 13, 10, 0
sp_open_shutdown:   db "[PAOS64] start.power.dialog action=shut_down (asks first; Cancel has the keyboard)", 13, 10, 0
sp_open_windows:    db "[PAOS64] start.power.dialog action=return_to_windows (asks first; Cancel has the keyboard)", 13, 10, 0
sp_cancel_text:     db "[PAOS64] start.power.cancel (nothing was done)", 13, 10, 0

%include "core/abi/wdata.inc"
%macro WDATA_gui_start_programs_0 0
align 8, db 0
sp_formload_fallback: dq 0
sp_click_prev:      dq 0
sp_open_marker:     dq 0
sp_key_prev:        dq 0
sp_kind:            dd 0
sp_w_question:      dd -1               ; dd[3] question/yes/cancel, filled by sp_form_widgets as ONE array:
sp_w_yes:           dd -1               ;   keep the three adjacent (STM-02: a field between them left
sp_w_cancel:        dd -1               ;   sp_w_yes -1 and faulted wgt_set_text)
sp_arm_rect:        times SP_ARM_ROWS dd -1, 0, 0, 0, 0, 0, 0, 0  ; SEC R1 F1: Yes, Apply, Reset, Card (x -1 = disarmed; boot is disarmed)

sp_arm_card_wid:    dd -1               ; J2b-P: the live card's Confirm id (gui/card_surface), -1 = none
sp_ptr_up_x:        dd 0                ; J2b-P: the last HUMAN left release, raw point and count
sp_ptr_up_y:        dd 0
sp_ptr_up_seq:      dd 0
sp_ptr_inj_seq:     dd 0                ; J2b-P (srcreview F1): non-HUMAN pointer events seen
; Same-dialog managed shutdown outcome; data only, never an authorization.
align 8, db 0
sp_power_token:     dq 0
sp_power_birth:     dq 0
sp_power_slot:      dd -1
sp_power_gen:       dd 0
sp_power_widget:    dd -1
sp_power_watch:     db 0
sp_pending:         db 0
sp_ptr_up_now:      db 0                ; J2b-P: this event is a HUMAN left release edge
align 8, db 0
sp_formload_arg:    times SP_ARG_MAX db 0
%endmacro
WDATA_DEFER WDATA_gui_start_programs_0
