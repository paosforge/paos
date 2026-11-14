;; MODULE gui/settings_prefs
;; LAYER 6
;; EXPORTS settings_prefs_show, settings_prefs_click, settings_prefs_key, settings_prefs_tick, stp_ids, stp_slot, stp_live, stp_pending
;; IMPORTS gui/widget, gui/wm_pointer, gui/window, gui/command_gui, gui/clock_prefs, gui/kbd_prefs, gui/lang_prefs, gui/config_prefs, gui/input_route, sec/session, sec/principal, svc/command, svc/command_auth, dev/input/ps2
;; CAPS CAP_GUI
;; OWNER saga:msi_start_programs_settings
; ============================================================================
; gui/settings_prefs.asm — RCQ-17: the Settings Preferences area applies,
; cancels and resets the display time zone, and the choice is saved.
;
; Settings (form row 16, gui/forms/settings.frm) shows one radio list: the
; pinned named zones in window.asm clock_zone_names id order (UTC, Phoenix,
; New_York), then Fixed, the legacy fixed offset (TZSET <minutes>; shipped
; default -420). Apply, Cancel and Reset follow it. gui/start_programs.asm finds
; the live window's widgets (declaration order -> stp_ids, stp_live) and chains
; its click hook, key filter and idle tick here. This module is the behaviour:
;   Apply   the chosen zone takes effect through the check TZSET uses
;           (clock_zone_select: a seeded wall outside the pinned rule interval
;           refuses and nothing changes) and is saved the way TZSET saves it
;           (clock_prefs_persist: the MACed PaOSClockPrefs record, written only
;           when the zone changed, then read back). Fixed keeps the fixed offset
;           already in force.
;   Cancel  the list shows the zone in force again. Nothing is written.
;   Reset   the shipped default (fixed UTC-07:00) is applied and saved.
; The status line says what happened: Current / Saved / Unchanged <zone>, or
; that the zone applies until restart only (no store this boot), or that the
; save failed (the zone still applies), or the refusal.
; Clicks and keys only record the action. The idle tick performs it after the
; input path has unwound, as the power confirmation does. Nothing is recorded
; or performed while the session is locked, and only the owner changes the
; zone (TZSET is owner-signed). Apply and Reset carry the authority of the
; local login session that pressed them, never the execution principal:
; principal_current is the identity of whatever request or frame is running
; (an SSH or SYSTEM frame; before fe22ce76e also every owner-signed AUTH1
; request, RCQ-17 QEMU be387a90), so it says nothing about who is at the
; keyboard. The click records the login's PID and authority token
; (session_shell_local_authority; the token changes on every lock and bind),
; and records none for a click made inside a command dispatch, an injected
; line or a remote request. The tick waits while a remote request is in
; flight, then acts only if a fresh snapshot is the same login, unlocked, and
; that login is the owner. Anyone may Cancel; it writes nothing. Up/Down move the choice from any
; Settings control, because the kit's Tab reaches only buttons and text fields.
; Enter or Space presses the focused button; opening Settings focuses Apply.
; SEC R1: KBINJ keys are delivered after their request returns, outside any
; dispatch, so only their origin tells them apart. An injected Enter or Space
; never presses Apply or Reset (it may still press Cancel).
; RCQ-38 L2: a second list chooses the keyboard layout (en-US, es, fr, de),
; separate from the zone. Left/Right move it from any Settings control, as
; Up/Down move the zone. Apply applies the zone, then the layout
; (kbd_prefs_select: the same captured login, saved only when it changed);
; Reset also returns to en-US; Cancel shows both in force. A layout this build
; has no text consumers for is refused visibly (root 12:04:44).
; RCQ-38 L3: a third list chooses the display language (English, Spanish,
; French, German: rows 0..3 are lang_prefs ordinals 0..3). Page Up/Page Down
; move it, and only a HUMAN pick applies, as for the layout. Apply applies the
; zone, then the layout, then the language (lang_prefs_select: the same captured
; login, written only when it changed); Reset also returns to English and
; rewrites a damaged (POISONED) record; Cancel shows all three in force. A saved
; language the list cannot show (ja, zh-Hans) marks no row and is kept until a
; human picks another. This build carries only the English catalog, so a saved
; choice says so. No pick outlives a Show, a Cancel or an Apply/Reset.
; Design-neutral seam: the wording and layout are placeholders until Peter
; hands over his Settings design (charter: design simulators).
; ============================================================================

STP_W_FACTS     equ 0                   ; settings.frm declaration order
STP_W_HEADING   equ 1
STP_W_STATUS    equ 2
STP_W_ZONE      equ 3
STP_W_APPLY     equ 4
STP_W_CANCEL    equ 5
STP_W_RESET     equ 6
STP_W_KBD       equ 7                   ; RCQ-38 L2: declared last, so 0..6 keep their places
STP_W_LANG      equ 8                   ; RCQ-38 L3: declared last, so 0..7 keep their places
STP_W_APPS      equ 9                   ; declared last, so 0..8 keep
STP_W_COUNT     equ 10
STP_LANG_LAST   equ 3                   ; rows 0..3 = lang_prefs ordinals en, es, fr, de
STP_LANG_TAG_LEN equ 2                  ; stp_lang_tags slot, passed as the tag length
STP_LANG_NONE   equ 2                   ; no select call (lang_prefs_select answers 1..-4)
STP_KBD_LAST    equ INPUT_LAYOUT_COUNT - 1
STP_ROW_FIXED   equ CLOCK_ZONE_COUNT    ; rows 0..COUNT-1 are zone ids 1..COUNT
STP_DEFAULT_MIN equ -420                ; window.asm clock_tz_min as shipped
STP_TEXT_MAX    equ WGI_VAL_MAX         ; the status label's bound

STP_NONE        equ 0
STP_APPLY       equ 1
STP_CANCEL      equ 2
STP_RESET       equ 3
STP_APPS        equ 4

;; settings_prefs_show(): the Settings window was just opened or raised. Its
;; list marks the zone in force, the status line names it, and the keyboard
;; rests on Apply (a form without a text field has no focus of its own, so its
;; keys would be dropped). Needs stp_live.
settings_prefs_show:
    cmp  byte [rel stp_live], 1
    jne  .out
    call stp_unpin                      ; a re-created form starts with no pick
    mov  byte [rel stp_pending], STP_NONE
    mov  eax, [rel stp_ids + STP_W_APPLY*4]
    mov  ecx, [rel stp_slot]
    lea  rdx, [rel wgt_focus_by_win]
    mov  [rdx + rcx*4], eax
    cmp  ecx, [rel wm_focus]
    jne  .focused
    mov  [rel wgt_focus_id], eax
.focused:
    mov  edi, eax
    call wgt_draw_id
    call stp_zone_row
    call stp_mark_row
    call stp_lang_mark_in_force
    call stp_kbd_mark_in_force
    lea  rsi, [rel stp_s_current]
    jmp  stp_say_zone
.out:
    ret

;; settings_prefs_click(EDI = widget id) -> EAX 1 when it is Apply, Cancel or
;; Reset of the live Settings window: the action is recorded for the tick.
settings_prefs_click:
    xor  eax, eax
    cmp  byte [rel stp_live], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out
    cmp  edi, [rel stp_ids + STP_W_KBD*4]
    je   .kbd_click
    cmp  edi, [rel stp_ids + STP_W_LANG*4]
    je   .lang_click
    cmp  edi, [rel stp_ids + STP_W_APPS*4]
    jne  .buttons
    mov  byte [rel stp_pending], STP_APPS ; only opens a read-only window
    mov  eax, 1
    ret
.buttons:
    mov  ecx, STP_APPLY
    cmp  edi, [rel stp_ids + STP_W_APPLY*4]
    je   .take
    mov  ecx, STP_CANCEL
    cmp  edi, [rel stp_ids + STP_W_CANCEL*4]
    je   .take
    mov  ecx, STP_RESET
    cmp  edi, [rel stp_ids + STP_W_RESET*4]
    jne  .out
.take:
    mov  [rel stp_pending], cl
    ; Who pressed it: the local login, for local input only. A click made
    ; inside a dispatch records none and is refused; the snapshot itself
    ; refuses injected and remote contexts.
    xor  eax, eax
    xor  edx, edx
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .who
    call session_shell_local_authority  ; at the click: RAX=PID, RDX=token
.who:
    mov  [rel stp_pending_pid], rax
    mov  [rel stp_pending_authority], rdx
    mov  eax, 1
.out:
    ret
.kbd_click:
    ; RCQ-38 L2-F3 (rc-sec 14:26:16): the kit's row hit set the choice before
    ; this hook. Only a HUMAN pointer outside a dispatch makes it a pick; any
    ; other click un-picks, so the next Apply asks for the layout again.
    mov  dword [rel stp_kbd_pick_row], -1
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .not_action
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .not_action
    call stp_kbd_picked
.not_action:
    xor  eax, eax                       ; a choice, not an action: the chain goes on
    ret
.lang_click:
    ; RCQ-38 L3 (SEC R11): as the layout list, only a HUMAN pointer outside a
    ; dispatch picks a language; any other click un-picks.
    mov  dword [rel stp_lang_pick_row], -1
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .not_action
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .not_action
    call stp_lang_picked
    jmp  .not_action

;; settings_prefs_key(EDI = focused widget id, EAX = key) -> EAX 1 handled.
;; Only a key on a control of the live Settings window: Up/Down move the zone
;; choice, Left/Right the layout choice and Page Up/Page Down the language
;; choice (bounded, no wrap), Enter/Space press the focused button. SEC R1 K2: a
;; key that is not KO_HUMAN may only press Cancel; every other one on a Settings
;; control (Tab, Up/Down, Enter/Space on Apply or Reset) is taken and ignored.
settings_prefs_key:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, eax
    cmp  byte [rel stp_live], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    cmp  ebx, [rel wgt_count]
    jae  .no
    mov  edi, ebx
    call wgt_slot_ptr
    mov  ecx, [rel stp_slot]
    cmp  [rax + WGI_WIN], ecx
    jne  .no
    cmp  byte [rel input_key_origin], KO_HUMAN
    je   .human
    cmp  ebx, [rel stp_ids + STP_W_CANCEL*4]
    jne  .taken                         ; SEC R1 K2: an injected key may only cancel, so no
    cmp  r12d, GUI_KEY_ENTER            ; Tab, zone/layout row or Apply/Reset from it
    je   .pressed
    cmp  r12d, ' '
    je   .pressed
    jmp  .taken
.human:
    cmp  r12d, GUI_KEY_UP
    je   .up
    cmp  r12d, GUI_KEY_DOWN
    je   .down
    cmp  r12d, GUI_KEY_LEFT
    je   .left
    cmp  r12d, GUI_KEY_RIGHT
    je   .right
    cmp  r12d, GUI_KEY_PGUP
    je   .pgup
    cmp  r12d, GUI_KEY_PGDN
    je   .pgdn
    cmp  r12d, GUI_KEY_ENTER
    je   .pressed
    cmp  r12d, ' '
    jne  .no
.pressed:
    cmp  ebx, [rel stp_ids + STP_W_KBD*4]
    je   .no                            ; L2-F3: a key on the list is not a pointer pick
    cmp  ebx, [rel stp_ids + STP_W_LANG*4]
    je   .no                            ; L3 (R4): nor on the language list
    mov  edi, ebx
    call settings_prefs_click
    jmp  .out
.up:
    call stp_sel
    test eax, eax
    jle  .first                         ; the first row, or none chosen
    dec  eax
    jmp  .mark
.down:
    call stp_sel
    test eax, eax
    js   .first
    cmp  eax, STP_ROW_FIXED
    jae  .mark                          ; the last row stays
    inc  eax
    jmp  .mark
.first:
    xor  eax, eax
.mark:
    call stp_mark_row
    jmp  .taken
.left:
    call stp_kbd_sel
    test eax, eax
    jle  .kbd_first
    dec  eax
    jmp  .kbd_mark
.right:
    call stp_kbd_sel
    test eax, eax
    js   .kbd_first
    cmp  eax, STP_KBD_LAST
    jae  .kbd_mark                      ; the last row stays
    inc  eax
    jmp  .kbd_mark
.kbd_first:
    xor  eax, eax
.kbd_mark:
    call stp_kbd_mark
    call stp_kbd_picked                 ; L2-F3: a HUMAN Left/Right is a pick
    jmp  .taken
.pgup:
    call stp_lang_sel
    test eax, eax
    jle  .lang_first                    ; the first row, or none chosen
    dec  eax
    jmp  .lang_mark
.pgdn:
    call stp_lang_sel
    test eax, eax
    js   .lang_first
    cmp  eax, STP_LANG_LAST
    jae  .lang_mark                     ; the last row stays (the table's, not the kit's count)
    inc  eax
    jmp  .lang_mark
.lang_first:
    xor  eax, eax
.lang_mark:
    call stp_lang_mark
    call stp_lang_picked                ; L3: a HUMAN Page Up/Page Down is a pick
.taken:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

;; settings_prefs_tick(): the idle loop performs a recorded action, once.
settings_prefs_tick:
    movzx eax, byte [rel stp_pending]
    test eax, eax
    jz   .out
    mov  byte [rel stp_pending], STP_NONE
    cmp  byte [rel stp_live], 1
    jne  .out                           ; the window closed since: nothing
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out
    cmp  eax, STP_CANCEL
    je   .cancel
    cmp  eax, STP_APPS
    je   .apps
    cmp  byte [rel command_auth_remote_active], 0
    jne  .wait                          ; never inside a remote request: later
    push rax
    call session_shell_local_authority  ; now: RAX=PID, RDX=token (0/0 refused)
    mov  ecx, 1
    cmp  rax, PRIN_OWNER
    jne  .judged                        ; the zone is the owner's setting
    cmp  rax, [rel stp_pending_pid]
    jne  .judged                        ; not the login that clicked
    cmp  rdx, [rel stp_pending_authority]
    jne  .judged                        ; that login has locked or rebound since
    xor  ecx, ecx
.judged:
    pop  rax
    test ecx, ecx
    jnz  .not_owner
    cmp  eax, STP_RESET
    je   .reset
    call stp_kbd_unpicked               ; L2-F3: before the zone, so a refusal changes nothing
    jc   .repick
    call stp_lang_unpicked              ; L3 (SEC R12): the language too, before the zone
    jc   .lang_repick
    call stp_unpin                      ; both picks are spent once Apply has read them
    call stp_sel                        ; Apply
    test eax, eax
    js   .choose
    cmp  eax, STP_ROW_FIXED
    je   .fixed
    lea  edi, [rax + 1]
    call clock_zone_select
    jc   .refused
    jmp  .applied
.fixed:
    mov  byte [rel clock_tz_zone], 0    ; the fixed offset in force stays
    jmp  .applied
.reset:
    mov  dword [rel clock_tz_min], STP_DEFAULT_MIN
    mov  byte [rel clock_tz_zone], 0
    xor  eax, eax                       ; L2: and the layout list to en-US
    call stp_kbd_mark
    xor  eax, eax                       ; L3: and the language list to English,
    call stp_lang_mark
    mov  byte [rel stp_lang_reset], 1   ; which also repairs a POISONED record (set here only)
    call stp_unpin
.applied:
    mov  word [rel clock_last_hhmm], 0xFFFF ; the next taskbar tick repaints, as after TZSET
    call clock_prefs_persist            ; EAX -1: the write or its readback failed
    push rax
    call stp_zone_row
    call stp_mark_row
    call stp_kbd_apply                  ; RCQ-38 L2: then the layout -> ECX its answer
    push rcx
    call stp_lang_apply                 ; RCQ-38 L3: then the language -> EDX its answer
    pop  rcx
    pop  rax
    lea  rsi, [rel stp_s_kbd_refused]
    cmp  ecx, -5
    je   stp_say                        ; this build has no text consumers for it
    lea  rsi, [rel stp_s_kbd_failed]
    cmp  ecx, -1
    jl   stp_say                        ; refused: the layout in force stays
    ; -1/1 are legacy NVRAM persistence outcomes: the choice applied. DATA
    ; persistence is independent and must work without firmware variables.
    lea  rsi, [rel stp_s_lang_refused]
    cmp  edx, -3
    je   stp_say                        ; L3: refused (stale login), nothing changes
    cmp  edx, -2
    je   stp_say                        ; a tag lang_prefs does not know
    lea  rsi, [rel stp_s_lang_failed]
    cmp  edx, -4
    je   stp_say                        ; no arena: the language in force stays
    mov  rdi, [rel stp_pending_pid]
    mov  rsi, [rel stp_pending_authority]
    call config_prefs_save              ; provider rechecks this local owner at effects
    lea  rsi, [rel stp_s_data_uncertain]
    cmp  eax, -3
    je   stp_say
    lea  rsi, [rel stp_s_data_pending]
    cmp  eax, 1
    je   stp_say
    lea  rsi, [rel stp_s_data_failed]
    test eax, eax
    jnz  stp_say
    lea  rsi, [rel stp_s_data_saved]
    jmp  stp_say
.refused:
    call stp_unpin_shown
    lea  rsi, [rel stp_s_refused]
    jmp  stp_say
.not_owner:
    call stp_unpin_shown
    lea  rsi, [rel stp_s_not_owner]
    jmp  stp_say
.choose:
    call stp_unpin_shown
    lea  rsi, [rel stp_s_choose]
    jmp  stp_say
.repick:
    call stp_unpin_shown
    lea  rsi, [rel stp_s_kbd_repick]
    jmp  stp_say
.lang_repick:
    call stp_unpin_shown
    lea  rsi, [rel stp_s_lang_repick]
    jmp  stp_say
.apps:
    sub  rsp, 8
    call start_programs_open_apps
    add  rsp, 8
    test eax, eax
    jnz  .apps_open
    lea  rsi, [rel stp_s_apps_refused]  ; past the widget or window cap: say so
    jmp  stp_say
.apps_open:
    ret
.cancel:
    call stp_unpin
    call stp_zone_row
    call stp_mark_row
    call stp_lang_mark_in_force
    call stp_kbd_mark_in_force
    lea  rsi, [rel stp_s_unchanged]
    jmp  stp_say_zone
.wait:
    mov  [rel stp_pending], al          ; the same action, on a later tick
.out:
    ret

; stp_zone_row -> EAX the list row of the zone in force.
stp_zone_row:
    movzx eax, byte [rel clock_tz_zone]
    dec  eax
    cmp  eax, CLOCK_ZONE_COUNT
    jb   .out
    mov  eax, STP_ROW_FIXED
.out:
    ret

; stp_sel -> EAX the chosen row 0..STP_ROW_FIXED, or -1 when none is.
stp_sel:
    mov  edi, [rel stp_ids + STP_W_ZONE*4]
    call wgt_slot_ptr
    mov  eax, [rax + WGI_SEL_LO]
    cmp  eax, STP_ROW_FIXED
    jbe  .out
    mov  eax, -1
.out:
    ret

; stp_mark_row(EAX row): the list marks that row and repaints.
stp_mark_row:
    push rbx
    mov  ebx, eax
    mov  edi, [rel stp_ids + STP_W_ZONE*4]
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], ebx
    mov  edi, [rel stp_ids + STP_W_ZONE*4]
    call wgt_draw_id
    pop  rbx
    ret

; stp_kbd_apply -> ECX kbd_prefs_select's answer for the layout list's choice,
; 0 when it is the layout in force (or none is chosen): then nothing is
; selected or written, so a saved layout this build cannot use is kept. The
; list then shows the layout in force. The login is the one the tick judged.
stp_kbd_apply:
    call stp_kbd_sel
    xor  ecx, ecx
    test eax, eax
    js   .shown
    cmp  al, [rel input_layout_id]
    je   .shown
    mov  edi, eax
    mov  rsi, [rel stp_pending_pid]
    mov  rdx, [rel stp_pending_authority]
    call kbd_prefs_select
    mov  ecx, eax
.shown:
    push rcx
    call stp_kbd_mark_in_force
    pop  rcx
    ret

; stp_kbd_picked: the layout list's choice now is a HUMAN pick, pinned to the
; kit's change counter (WGI_INTENT_SEQ moves on every kit write: WIDGETSET, a
; pointer row hit, a list key), so any later change the human did not make
; unpins it. Settings' own marks do not move the counter.
stp_kbd_picked:
    mov  edi, [rel stp_ids + STP_W_KBD*4]
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_SEL_LO]
    mov  [rel stp_kbd_pick_row], ecx
    mov  rcx, [rax + WGI_INTENT_SEQ]
    mov  [rel stp_kbd_pick_seq], rcx
    ret

; stp_kbd_unpicked -> CF 1 when the list holds a layout other than the one in
; force that is not the HUMAN's last pick (rc-sec 14:26:16: Apply applies only a
; layout the human picked). No choice, or the layout in force, is no change.
stp_kbd_unpicked:
    mov  edi, [rel stp_ids + STP_W_KBD*4]
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_SEL_LO]
    cmp  ecx, STP_KBD_LAST
    ja   .picked                        ; none chosen: the layout in force stays
    cmp  cl, [rel input_layout_id]
    je   .picked
    cmp  ecx, [rel stp_kbd_pick_row]
    jne  .unpicked
    mov  rcx, [rax + WGI_INTENT_SEQ]
    cmp  rcx, [rel stp_kbd_pick_seq]
    jne  .unpicked
.picked:
    clc
    ret
.unpicked:
    stc
    ret

; stp_kbd_sel -> EAX the chosen layout row 0..STP_KBD_LAST, or -1 when none is.
stp_kbd_sel:
    mov  edi, [rel stp_ids + STP_W_KBD*4]
    call wgt_slot_ptr
    mov  eax, [rax + WGI_SEL_LO]
    cmp  eax, STP_KBD_LAST
    jbe  .out
    mov  eax, -1
.out:
    ret

; stp_kbd_mark_in_force / stp_kbd_mark(EAX row): the layout list marks the
; layout in force, or that row, and repaints.
stp_kbd_mark_in_force:
    movzx eax, byte [rel input_layout_id]
stp_kbd_mark:
    push rbx
    mov  ebx, eax
    mov  edi, [rel stp_ids + STP_W_KBD*4]
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], ebx
    mov  edi, [rel stp_ids + STP_W_KBD*4]
    call wgt_draw_id
    pop  rbx
    ret

; stp_unpin: no pick outlives a Show, a Cancel or an Apply/Reset the tick has
; judged (rc-sec L26895). A later WIDGETSET "sel" (it moves no counter) or a
; counter replayed after the form is re-created can never match a spent pick.
stp_unpin:
    mov  dword [rel stp_kbd_pick_row], -1
    mov  dword [rel stp_lang_pick_row], -1
    ret

; stp_unpin_shown: stp_unpin, and both lists show what is in force again. An
; Apply the tick stopped (not the owner, a list to pick again, no zone, a zone
; refused) wrote neither, so no spent row stays on screen for the next Apply to
; refuse again (srcreview SR-L3-1).
stp_unpin_shown:
    call stp_unpin
    call stp_kbd_mark_in_force
    jmp  stp_lang_mark_in_force

; stp_lang_apply -> EDX lang_prefs_select's answer for the language list's
; choice, or STP_LANG_NONE when none is chosen or it is the language in force:
; then nothing is selected or written, so a saved tag the list cannot show is
; kept. Reset alone (stp_lang_reset) also rewrites a POISONED record as English.
; The tag comes from stp_lang_tags, never from the widget's text. The list then
; shows the language in force. The login is the one the tick judged.
stp_lang_apply:
    push rbx
    call stp_lang_sel                   ; bounded by STP_LANG_LAST here, not by the kit
    mov  ebx, eax
    mov  edx, STP_LANG_NONE
    test ebx, ebx
    js   .shown
    jnz  .compare
    cmp  byte [rel stp_lang_reset], 0
    je   .compare
    cmp  byte [rel lang_prefs_state], LGP_ST_POISONED
    je   .select                        ; Reset repairs a damaged record
.compare:
    call lang_prefs_get                 ; EAX the ordinal in force (clobbers RDX)
    mov  edx, STP_LANG_NONE
    cmp  eax, ebx
    je   .shown
.select:
    lea  rdi, [rel stp_lang_tags]
    lea  rdi, [rdi + rbx*STP_LANG_TAG_LEN]
    mov  esi, STP_LANG_TAG_LEN
    mov  rdx, [rel stp_pending_pid]
    mov  rcx, [rel stp_pending_authority]
    call lang_prefs_select
    mov  edx, eax
.shown:
    mov  byte [rel stp_lang_reset], 0   ; never outlives this Apply or Reset
    push rdx
    call stp_lang_mark_in_force
    pop  rdx
    pop  rbx
    ret

; stp_lang_picked: the language list's choice now is a HUMAN pick, pinned to the
; kit's change counter and its row, as stp_kbd_picked.
stp_lang_picked:
    mov  edi, [rel stp_ids + STP_W_LANG*4]
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_SEL_LO]
    mov  [rel stp_lang_pick_row], ecx
    mov  rcx, [rax + WGI_INTENT_SEQ]
    mov  [rel stp_lang_pick_seq], rcx
    ret

; stp_lang_unpicked -> CF 1 when the list holds a language other than the one in
; force that is not the HUMAN's last pick, by row and counter (a WIDGETSET "sel"
; moves the row without the counter). No choice, or the language in force, is no
; change.
stp_lang_unpicked:
    push rbx
    mov  edi, [rel stp_ids + STP_W_LANG*4]
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [rbx + WGI_SEL_LO]
    cmp  ecx, STP_LANG_LAST
    ja   .picked                        ; none chosen (unsigned): the language in force stays
    push rcx
    call lang_prefs_get
    pop  rcx
    cmp  ecx, eax
    je   .picked
    cmp  ecx, [rel stp_lang_pick_row]
    jne  .unpicked
    mov  rcx, [rbx + WGI_INTENT_SEQ]
    cmp  rcx, [rel stp_lang_pick_seq]
    jne  .unpicked
.picked:
    pop  rbx
    clc
    ret
.unpicked:
    pop  rbx
    stc
    ret

; stp_lang_sel -> EAX the chosen language row 0..STP_LANG_LAST, or -1 when none
; is. The bound is this module's (unsigned), never the kit's option count: a
; WIDGETSET may give the list more options, or "sel" any number.
stp_lang_sel:
    mov  edi, [rel stp_ids + STP_W_LANG*4]
    call wgt_slot_ptr
    mov  eax, [rax + WGI_SEL_LO]
    cmp  eax, STP_LANG_LAST
    jbe  .out
    mov  eax, -1
.out:
    ret

; stp_lang_mark_in_force / stp_lang_mark(EAX row or -1): the language list marks
; the language in force, or that row, and repaints. A language in force that
; has no row (ja, zh-Hans) marks none.
stp_lang_mark_in_force:
    call lang_prefs_get
    cmp  eax, STP_LANG_LAST
    jbe  stp_lang_mark
    mov  eax, -1
stp_lang_mark:
    push rbx
    mov  ebx, eax
    mov  edi, [rel stp_ids + STP_W_LANG*4]
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], ebx
    mov  edi, [rel stp_ids + STP_W_LANG*4]
    call wgt_draw_id
    pop  rbx
    ret

; stp_say(RSI line) / stp_say_zone(RSI prefix): the status line becomes the
; line, or the prefix plus the zone and the layout in force.
stp_say:
    mov  dword [rel stp_text_len], 0
    call stp_put
    jmp  stp_show
stp_say_zone:
    mov  dword [rel stp_text_len], 0
    call stp_put
    call stp_put_zone
    lea  rsi, [rel stp_s_kbd_sep]
    call stp_put
    movzx eax, byte [rel input_layout_id]
    imul eax, eax, INPUT_LAYOUT_TAG_SLOT
    lea  rsi, [rel input_layout_tags]
    add  rsi, rax
    call stp_put
stp_show:
    mov  edi, [rel stp_ids + STP_W_STATUS*4]
    lea  rsi, [rel stp_text]
    jmp  wgt_set_text

; stp_put(RSI cstr): append to stp_text, at most STP_TEXT_MAX bytes in all.
stp_put:
    lea  rdx, [rel stp_text]
    mov  ecx, [rel stp_text_len]
.copy:
    cmp  ecx, STP_TEXT_MAX
    jae  .end
    mov  al, [rsi]
    test al, al
    jz   .end
    mov  [rdx + rcx], al
    inc  rsi
    inc  ecx
    jmp  .copy
.end:
    mov  byte [rdx + rcx], 0
    mov  [rel stp_text_len], ecx
    ret

; stp_put_zone: append the zone in force - its pinned name, or
; "fixed UTC+HH:MM" from clock_tz_min (|minutes| <= 840, TZSET's clamp).
stp_put_zone:
    movzx eax, byte [rel clock_tz_zone]
    dec  eax
    cmp  eax, CLOCK_ZONE_COUNT
    jae  .fixed
    imul eax, eax, CLOCK_ZONE_NAME_SLOT
    lea  rsi, [rel clock_zone_names]
    add  rsi, rax
    jmp  stp_put
.fixed:
    lea  rsi, [rel stp_s_fixed]
    call stp_put
    mov  eax, [rel clock_tz_min]
    lea  rsi, [rel stp_s_plus]
    test eax, eax
    jns  .sign
    neg  eax
    lea  rsi, [rel stp_s_minus]
.sign:
    cmp  eax, 840
    jbe  .bounded
    mov  eax, 840
.bounded:
    push rax
    call stp_put
    pop  rax
    xor  edx, edx
    mov  ecx, 60
    div  ecx                            ; EAX hours (<= 14), EDX minutes
    push rdx
    call stp_put_2d
    lea  rsi, [rel stp_s_colon]
    call stp_put
    pop  rax
    jmp  stp_put_2d

; stp_put_2d(EAX 0..99): append two decimal digits.
stp_put_2d:
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    add  al, '0'
    add  dl, '0'
    lea  rsi, [rel stp_digits]
    mov  [rsi], al
    mov  [rsi + 1], dl
    mov  byte [rsi + 2], 0
    jmp  stp_put

; Status wording stays within the label's 31 bytes with the longest zone name
; and the layout tag ("Unchanged: America/New_York; FR" is 31).
stp_s_current:     db "Current: ", 0
stp_s_saved:       db "Saved: ", 0
stp_s_unchanged:   db "Unchanged: ", 0
stp_s_not_saved:   db "Applied until restart only", 0
stp_s_save_failed: db "Applied; saving failed", 0
stp_s_data_saved: db "Saved on DATA; locale next boot", 0
stp_s_data_pending: db "Applied; DATA unavailable", 0
stp_s_data_failed: db "Applied; DATA save failed", 0
stp_s_data_uncertain: db "DATA uncertain; restart needed", 0
stp_s_refused:     db "Refused: outside zone rules", 0
stp_s_choose:      db "Choose a time zone first", 0
stp_s_not_owner:   db "Only the owner can change this", 0
stp_s_kbd_refused: db "Layout needs text entry", 0
stp_s_kbd_failed:  db "Layout not changed", 0
stp_s_kbd_repick:  db "Select the layout again", 0
stp_s_lang_saved:  db "Saved; applies after restart", 0
stp_s_lang_not_saved: db "Language not saved", 0
stp_s_lang_refused: db "Language refused", 0
stp_s_lang_failed: db "Language not changed", 0
stp_s_lang_repick: db "Select the language again", 0
stp_s_apps_refused: db "Close a window to open Apps", 0
stp_lang_tags:     db "en", "es", "fr", "de" ; row i = lang_prefs ordinal i (lang_prefs_tags order)
stp_s_kbd_sep:     db "; ", 0
stp_s_fixed:       db "fixed UTC", 0
stp_s_plus:        db "+", 0
stp_s_minus:       db "-", 0
stp_s_colon:       db ":", 0

%include "core/abi/wdata.inc"
%macro WDATA_gui_settings_prefs 0
align 4, db 0
stp_ids:          times STP_W_COUNT dd -1
stp_slot:         dd -1
stp_text_len:     dd 0
stp_live:         db 0
stp_pending:      db 0
align 8, db 0
stp_pending_pid:  dq 0                  ; the clicking login's PID; 0 = none
stp_pending_authority: dq 0             ; and its authority token; 0 = none
stp_digits:       times 4 db 0
stp_text:         times STP_TEXT_MAX + 1 db 0
align 8, db 0
stp_kbd_pick_seq: dq 0                  ; L2-F3: the kit's change counter at the HUMAN's pick
stp_kbd_pick_row: dd -1                 ; and the row picked; -1 = none
stp_lang_pick_row: dd -1                ; RCQ-38 L3: the language list's pin, as the layout's
stp_lang_pick_seq: dq 0
stp_lang_reset:   db 0                  ; set only by the tick's Reset, spent by stp_lang_apply
%endmacro
WDATA_DEFER WDATA_gui_settings_prefs
