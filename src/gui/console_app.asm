;; MODULE gui/console_app
;; LAYER 6
;; EXPORTS console_app_init, console_app_tick, console_app_textfield_event, console_service_ready
;; IMPORTS sec/session, sec/principal, core/log, gui/input_route, gui/form_loader, gui/widget_console_grid, gui/widget_tabstrip, gui/widget, gui/cadence_mark, svc/command, svc/command_cons, svc/command_udp, svc/hw_report, boot/serial, boot/boot_v2_handoff, sec/keyprov
;; CAPS CAP_GUI
;; OWNER saga:verb_console
; Contract 2152: a form-backed local projection of the one command registry.
; The only handler invocation in this module is the indirect LAUNCH fallback;
; every submitted verb crosses command_dispatch at the single call below.

CONSOLE_FORM_INDEX  equ 7             ; borrowed only during a console load, then restored
CONSOLE_HISTORY_MAX equ 8
CONSOLE_HISTORY_SZ  equ 256           ; F-CON31 option C: one console line (was 32 = the old 31-char wall)
CONSOLE_LINE_MAX    equ 240           ; F-CON31 option C: explicit console input cap; a key past it is dropped + counted
CONSOLE_LINE_VIS    equ WGI_VAL_MAX   ; the window of the line shown in the input textfield (the field's own bound)
CONSOLE_TAB_STORE   equ GRID_RAW_BYTES ; B5: one parked tab transcript (the grid's own history bound)

form_blob_console_runtime:
    incbin "gui/forms/console.frm"
form_blob_console_runtime_end:
    db 0

; Initialize the retained command/transcript service without creating a user
; window. Explicit owner-gated recovery FORMLOAD/LAUNCH stays available until
; Terminal parity permits deletion of the legacy view (T5-11).
console_app_init:
    cmp  byte [rel console_service_ready], 1
    je   .out
    cmp  byte [rel console_kf_installed], 0   ; F-CON31 option C: the console owns its input line
    jne  .kf_done
    mov  byte [rel console_kf_installed], 1
    mov  rax, [rel wgt_key_filter]
    mov  [rel console_kf_prev], rax
    lea  rax, [rel console_key_filter]
    mov  [rel wgt_key_filter], rax
.kf_done:
    ; The generated table is owned by the form compiler and its eighth row is
    ; a live negative fixture. Preserve that row, borrowing it only while the
    ; generic loader parses/materializes console.frm.
    mov  edi, CONSOLE_FORM_INDEX
    call form_table_ptr
    mov  rcx, [rax + FORM_NAME]
    mov  [rel console_form_saved_name], rcx
    mov  rcx, [rax + FORM_BLOB_PTR]
    mov  [rel console_form_saved_blob], rcx
    mov  rcx, [rax + FORM_LEN]
    mov  [rel console_form_saved_len], rcx

    ; The console grid implementation is intentionally singleton at rung 2.
    ; Remember rung 0's Demo-C binding so CLOSE can return that shared widget
    ; to its original owner instead of leaving the cadence slot pointed at a
    ; widget that the form loader just retired.
    mov  eax, [rel grid_widget_id]
    mov  [rel console_saved_grid_id], eax
    mov  al, [rel grid_dock_owner]
    mov  [rel console_saved_grid_dock_owner], al
    mov  al, [rel grid_mode]
    mov  [rel console_saved_grid_mode], al

    ; Register app_console by extending the existing LAUNCH row in place. All
    ; other app names tail-dispatch to the original form-app handler.
    lea  rdi, [rel str_console_launch]
    call command_lookup
    cmp  eax, -1
    je   .fail
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rcx, rax
    mov  rax, [rcx + VERB_HANDLER]
    mov  [rel console_launch_fallback], rax
    lea  rax, [rel console_cmd_launch]
    mov  [rcx + VERB_HANDLER], rax

    ; FORMLOAD console uses the same signed generic form surface. The wrapper
    ; only lends the loader a table row; all other form names tail-dispatch.
    lea  rdi, [rel str_console_formload]
    call command_lookup
    cmp  eax, -1
    je   .fail
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rcx, rax
    mov  rax, [rcx + VERB_HANDLER]
    mov  [rel console_formload_fallback], rax
    lea  rax, [rel console_cmd_formload]
    mov  [rcx + VERB_HANDLER], rax

    lea  rdi, [rel str_console_forminfo]
    call command_lookup
    cmp  eax, -1
    je   .fail
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rcx, rax
    mov  rax, [rcx + VERB_HANDLER]
    mov  [rel console_forminfo_fallback], rax
    lea  rax, [rel console_cmd_forminfo]
    mov  [rcx + VERB_HANDLER], rax

    lea  rdi, [rel str_console_formlist]
    call command_lookup
    cmp  eax, -1
    je   .fail
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rcx, rax
    lea  rax, [rel console_cmd_formlist]
    mov  [rcx + VERB_HANDLER], rax

    lea  rax, [rel console_app_textfield_event]
    mov  [rel wgt_textfield_event_hook], rax
    lea  rdi, [rel console_session_render]
    call cons_bind_render
    mov  dword [rel console_history_count], 0
    mov  dword [rel console_history_cursor], 0

    ; Readiness belongs to the initialized service, never to a visible form.
    ; No synthetic Console STATUS request or paint proves Terminal usability.
    mov  byte [rel console_service_ready], 1
    lea  rdi, [rel str_console_service_marker]
    call serial_string
.out:
    ret

.fail:
    mov  byte [rel console_service_ready], 0
    lea  rdi, [rel str_console_init_fail]
    call serial_string
    ret

; Cheap idle reconciliation makes direct FORMLOAD console and close/relaunch use
; the newly allocated widgets without teaching the generic form loader app lore.
; Enter is a latched textfield generation, consumed here on the next idle frame:
; registry dispatch and transcript formatting never run nested inside key routing.
console_app_tick:
    ; Window reconciliation only; command_idle_service owns model progress and
    ; bounded calibration independently of this optional recovery view.
    mov  eax, [rel form_active_slot + CONSOLE_FORM_INDEX*4]
    cmp  eax, WM_MAX
    jae  .not_live
    lea  rcx, [rel wm_state]
    mov  edx, [rcx + rax*4]
    cmp  edx, WM_VISIBLE
    je   .check_bound
    cmp  edx, WM_MIN
    jne  .not_live
.check_bound:
    cmp  eax, [rel console_bound_slot]
    jne  .bind
    mov  edi, [rel console_input_id]
    cmp  edi, 0
    jl   .bind
    cmp  edi, [rel wgt_count]
    jae  .bind
    call console_session_refresh         ; the status label follows a binding transition
    call console_tabs_sync               ; B5: the grid shows the ACTIVE tab's transcript
    call console_try_hardware_report
    mov  edi, [rel console_input_id]
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 2
    jne  .bind
    call console_timeline_tick           ; measurement only: boot.terminal.usable
    mov  edx, [rax + WGI_SUBMITS]
    cmp  edx, [rel console_submit_seen]
    je   .ret
    mov  [rel console_submit_seen], edx
    call console_submit
.ret:
    ret
.bind:
    call console_bind_window
    ret
.not_live:
    cmp  dword [rel console_bound_slot], -1
    je   .ret
    mov  edi, [rel console_bound_slot]
    call cons_window_unbind
    mov  dword [rel console_bound_slot], -1
    mov  dword [rel console_input_id], -1
    mov  edi, [rel console_saved_grid_id]
    movzx esi, byte [rel console_saved_grid_dock_owner]
    movzx edx, byte [rel console_saved_grid_mode]
    call console_grid_restore_owner
    ret

; Boot-timeline mark boot.terminal.usable (measurement only; no input, no
; serial, no wait). The Terminal in this desktop is the PaOS_Console window
; (console.frm, chrome=tabs). Its only caller is console_app_tick's bound path,
; which the idle loop runs only for GUI presentation with the session unlocked
; and the desktop created, and reaches only when the console window is bound
; to its input textfield. This adds: the window is WM_VISIBLE (not minimized)
; and the desktop keyboard path is already live (input_route_tl_live bit0).
; So it marks the first idle frame in which a key typed into the Terminal is
; routed to its input line and Enter is dispatched; it does not require focus.
; On a locked boot this is after the first successful sign-in (it includes
; the human or fixture login time). The session lock is checked HERE too, not
; only by the idle-loop caller: the mark can never latch while locked, whoever
; calls it (0.0.48 metal-order review). Preserves all registers except flags.
console_timeline_tick:
    cmp  byte [rel console_tl_latched], 1
    je   .out
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out
    test byte [rel input_route_tl_live], 1
    jz   .out
    push rax
    push rcx
    push rdi
    mov  eax, [rel form_active_slot + CONSOLE_FORM_INDEX*4]
    cmp  eax, WM_MAX
    jae  .pop
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rax*4], WM_VISIBLE
    jne  .pop
    mov  byte [rel console_tl_latched], 1
    mov  edi, BOOT_TIMELINE_ID_TERMINAL_USABLE
    call boot_timeline_latch
.pop:
    pop  rdi
    pop  rcx
    pop  rax
.out:
    ret

; Install/restore the console declaration around exactly one generic loader
; call. This keeps bad_unknown_key live for its ordinary negative surface.
console_form_install:
    mov  edi, CONSOLE_FORM_INDEX
    call form_table_ptr
    lea  rcx, [rel form_name_console_runtime]
    mov  [rax + FORM_NAME], rcx
    lea  rcx, [rel form_blob_console_runtime]
    mov  [rax + FORM_BLOB_PTR], rcx
    mov  qword [rax + FORM_LEN], form_blob_console_runtime_end - form_blob_console_runtime
    ret

console_form_restore:
    mov  edi, CONSOLE_FORM_INDEX
    call form_table_ptr
    mov  rcx, [rel console_form_saved_name]
    mov  [rax + FORM_NAME], rcx
    mov  rcx, [rel console_form_saved_blob]
    mov  [rax + FORM_BLOB_PTR], rcx
    mov  rcx, [rel console_form_saved_len]
    mov  [rax + FORM_LEN], rcx
    ret

; Same ABI as form_load_index. Preserve its complete result across restoration.
console_form_load:
    push r12
    push r13
    mov  r12, rsi
    mov  r13d, edx
    call console_form_install
    mov  edi, CONSOLE_FORM_INDEX
    mov  rsi, r12
    mov  edx, r13d
    call form_load_index
    push rax
    push rcx
    push rdx
    call console_form_restore
    pop  rdx
    pop  rcx
    pop  rax
    pop  r13
    pop  r12
    ret

; FORMLOAD wrapper: for `console [options]`, let the established handler parse
; title/focus and produce its canonical response while the console row is
; installed. The wrapper itself is not a second handler entry, so the registry
; dispatch_count == handler_runs census remains exact.
console_cmd_formload:
    call form_verb_unlocked             ; RCQ-16 F2b-1: refused under the lock, first
    test eax, eax
    jz   .unlocked
    ret
.unlocked:
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .fallback
    cmp  dword [rax], 'cons'
    jne  .fallback
    cmp  word [rax + 4], 'ol'
    jne  .fallback
    cmp  byte [rax + 6], 'e'
    jne  .fallback
    mov  cl, [rax + 7]
    test cl, cl
    jz   .console
    cmp  cl, ' '
    jne  .fallback
.console:
    push rdi
    push rsi
    call console_form_install
    pop  rsi
    pop  rdi
    call qword [rel console_formload_fallback]
    push rax
    call console_form_restore
    call console_bind_window
    pop  rax
    ret
.fallback:
    jmp  qword [rel console_formload_fallback]

; FORMINFO has the same first-token shape as FORMLOAD. Temporarily exposing
; the row lets its established bounded pager return the declaration verbatim.
console_cmd_forminfo:
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .fallback
    cmp  dword [rax], 'cons'
    jne  .fallback
    cmp  word [rax + 4], 'ol'
    jne  .fallback
    cmp  byte [rax + 6], 'e'
    jne  .fallback
    mov  cl, [rax + 7]
    test cl, cl
    jz   .console
    cmp  cl, ' '
    jne  .fallback
.console:
    push rdi
    push rsi
    call console_form_install
    pop  rsi
    pop  rdi
    call qword [rel console_forminfo_fallback]
    push rax
    call console_form_restore
    pop  rax
    ret
.fallback:
    jmp  qword [rel console_forminfo_fallback]

; Preserve the registered T0 FORMLIST row while truthfully inventorying the
; public declarations; the retained recovery Console is deliberately hidden.
console_cmd_formlist:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call form_out_reset
    lea  rdi, [rel str_console_formlist_reply]
    call form_out_put_str
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 0
    pop  r12
    ret

; LAUNCH app_console compatibility over the ordinary form slot. The registry's
; existing destructiveness=1 metadata remains the owner gate for every app.
console_cmd_launch:
    call form_verb_unlocked             ; RCQ-16 F2b-1: refused under the lock, first
    test eax, eax
    jz   .unlocked
    ret
.unlocked:
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .fallback
    push rdi
    push rsi
    mov  rdi, rax
    lea  rsi, [rel str_app_console]
    call strcmp
    pop  rsi
    pop  rdi
    test rax, rax
    jnz  .fallback
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rsi
    mov  edi, CONSOLE_FORM_INDEX
    xor  esi, esi
    xor  edx, edx
    call console_form_load
    test eax, eax
    jnz  .load_fail
    mov  r13d, ecx
    call console_bind_window
    test eax, eax
    jnz  .load_fail
    call form_out_reset
    lea  rdi, [rel str_console_launch_ok]
    call form_out_put_str
    mov  edi, r13d
    call form_out_put_dec
    mov  [r12 + RSP_VAL], r13
    jmp  .stage
.load_fail:
    call form_out_reset
    lea  rdi, [rel str_console_launch_err]
    call form_out_put_str
    mov  qword [r12 + RSP_VAL], 0
.stage:
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    ret
.fallback:
    jmp  qword [rel console_launch_fallback]

; Resolve the form's stable widget ids to live global ids. Returns EAX=0/1.
console_bind_window:
    push rbx
    push r12
    push r13
    mov  r13d, [rel form_active_slot + CONSOLE_FORM_INDEX*4]
    cmp  r13d, WM_MAX
    jae  .bad
    mov  dword [rel console_found_grid], -1
    mov  dword [rel console_found_input], -1
    mov  dword [rel console_found_session], -1
    mov  dword [rel console_found_verbs], -1
    mov  dword [rel console_found_last], -1
    xor  r12d, r12d
.scan:
    cmp  r12d, [rel wgt_count]
    jae  .scanned
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_TYPE], 0
    je   .next
    cmp  [rbx + WGI_WIN], r13d
    jne  .next
    mov  rdi, [rbx + WGI_ID]
    test rdi, rdi
    jz   .next
    lea  rsi, [rel str_console_id_grid]
    call strcmp
    test eax, eax
    jz   .is_grid
    mov  rdi, [rbx + WGI_ID]
    lea  rsi, [rel str_console_id_input]
    call strcmp
    test eax, eax
    jz   .is_input
    mov  rdi, [rbx + WGI_ID]
    lea  rsi, [rel str_console_id_session]
    call strcmp
    test eax, eax
    jz   .is_session
    mov  rdi, [rbx + WGI_ID]
    lea  rsi, [rel str_console_id_verbs]
    call strcmp
    test eax, eax
    jz   .is_verbs
    mov  rdi, [rbx + WGI_ID]
    lea  rsi, [rel str_console_id_last]
    call strcmp
    test eax, eax
    jnz  .next
    mov  [rel console_found_last], r12d
    jmp  .next
.is_grid:
    mov  [rel console_found_grid], r12d
    jmp  .next
.is_input:
    mov  [rel console_found_input], r12d
    jmp  .next
.is_session:
    mov  [rel console_found_session], r12d
    jmp  .next
.is_verbs:
    mov  [rel console_found_verbs], r12d
.next:
    inc  r12d
    jmp  .scan
.scanned:
    cmp  dword [rel console_found_grid], 0
    jl   .bad
    cmp  dword [rel console_found_input], 0
    jl   .bad
    cmp  dword [rel console_found_session], 0
    jl   .bad
    cmp  dword [rel console_found_verbs], 0
    jl   .bad
    cmp  dword [rel console_found_last], 0
    jl   .bad
    xor  ebx, ebx
    cmp  r13d, [rel console_bound_slot]
    jne  .fresh
    mov  eax, [rel console_found_grid]
    cmp  eax, [rel console_grid_id]
    je   .store
.fresh:
    mov  ebx, 1
.store:
    mov  [rel console_bound_slot], r13d
    mov  eax, [rel console_found_grid]
    mov  [rel console_grid_id], eax
    mov  edi, eax
    xor  esi, esi
    call console_grid_claim_plain
    mov  eax, [rel console_found_input]
    mov  [rel console_input_id], eax
    mov  edi, eax
    call wgt_mark_ascii                 ; RCQ-38 L3b: the local-shell line is ASCII (DESIGN B2)
    call wgt_slot_ptr
    mov  eax, [rax + WGI_SUBMITS]
    mov  [rel console_submit_seen], eax
    mov  eax, [rel console_found_session]
    mov  [rel console_session_id], eax
    mov  eax, [rel console_found_verbs]
    mov  [rel console_verbs_id], eax
    mov  eax, [rel console_found_last]
    mov  [rel console_last_id], eax
    lea  rax, [rel wgt_focus_by_win]
    mov  ecx, [rel console_input_id]
    mov  [rax + r13*4], ecx
    test ebx, ebx
    jz   .ok
    call console_tabs_reset              ; B5: a fresh binding starts with no parked tabs
    mov  edi, [rel console_input_id]
    lea  rsi, [rel str_console_empty]
    call wgt_set_text
    call grid_clear
    mov  edi, r13d
    call cons_window_bind_default
    mov  [rel console_bound_session_noun], eax
    test edx, edx
    jnz  .have_transcript
    lea  rdi, [rel str_console_welcome]
    call console_append_cstr
    mov  byte [rel console_try_hw_pending], 1
    call console_try_hardware_report
.have_transcript:
    mov  dword [rel console_history_count], 0
    mov  dword [rel console_history_cursor], 0
    call console_update_status
.ok:
    call console_session_label           ; a rebound form's label starts from its .frm text
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; First local Try welcome: project the existing read-only boot inventory into
; the Console transcript. No command is submitted and no authority is borrowed.
; The private buffer cannot race the boot serial buffer or a remote HW request.
; Existing transcripts and later tabs keep their own content; one boot displays
; this snapshot once. Renderer refusal is visible, never stale inventory text.
console_try_hardware_report:
    cmp  byte [rel console_try_hw_pending], 1
    jne  .out
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out
    cmp  byte [rel pbm_try_media], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    cmp  qword [rel session_bound_pid], PRIN_TRY
    jne  .out
    cmp  byte [rel console_try_hw_shown], 0
    jne  .out
    push rbx
    call hw_report_boot_ready
    test eax, eax
    jz   .wait
    mov  byte [rel console_try_hw_shown], 1
    mov  byte [rel console_try_hw_pending], 0
    lea  rdi, [rel str_console_try_hw]
    call console_append_cstr
    mov  ebx, HW_C_CPU
.class:
    mov  edi, ebx
    lea  rsi, [rel console_try_hw_buf]
    mov  edx, HW_LOG_CAP
    call hw_report_render
    lea  rdi, [rel console_try_hw_buf]
    test eax, eax
    jz   .append
    lea  rdi, [rel str_console_try_hw_fail]
.append:
    call console_append_cstr
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
    inc  ebx
    cmp  ebx, HW_C_BATTERY
    jbe  .class
.wait:
    pop  rbx
.out:
    ret

; Generic widget post-edit callback. Enter is consumed from its durable submit
; generation by console_app_tick; only lightweight history navigation runs here.
; ---------------------------------------------------------------------------
; B5 (2026-10-01, usage suite TAB-02/TAB-03): every console tab is its own
; transcript. The tab strip gives each tab a stable tag (widget_tabstrip
; TS_TAGS); when the ACTIVE tag changes, the live transcript is parked in its
; tab's store, the grid gets a fresh view instance (new handle, empty history)
; and the selected tab's transcript is replayed into it. A tab seen for the
; first time starts with its own banner and the welcome. Stores of closed tabs
; are dropped. Typed lines dispatch exactly as before (one owner command
; session remains the audit authority); only the view follows the tab.
console_tabs_sync:
    push rbx
    push r12
    push r13
    mov  edi, [rel console_bound_slot]
    call wgt_tabstrip_active_tag
    test eax, eax
    jz   .out                             ; no bound tab strip (yet)
    mov  r12d, eax                        ; tag now active
    mov  ebx, [rel console_tab_live]      ; tag whose transcript the grid shows
    cmp  r12d, ebx
    je   .out
    test ebx, ebx
    jz   .adopt                           ; first sight: the grid already is this tab
    call console_tabs_prune
    mov  edi, [rel console_bound_slot]
    mov  esi, ebx
    call wgt_tabstrip_has_tag
    test eax, eax
    jz   .switch                          ; the outgoing tab was closed: nothing to park
    mov  edi, ebx
    call console_tab_store_for
    cmp  eax, -1
    je   .switch
    mov  r13d, eax
    imul rdi, r13, CONSOLE_TAB_STORE
    lea  rax, [rel console_tab_store]
    add  rdi, rax
    mov  esi, CONSOLE_TAB_STORE
    call grid_claim_snapshot
    lea  rcx, [rel console_tab_len]
    mov  [rcx + r13*4], eax
.switch:
    mov  edi, [rel console_grid_id]
    call console_grid_reclaim
    mov  edi, r12d
    call console_tab_find
    cmp  eax, -1
    je   .new_tab
    mov  r13d, eax
    lea  rcx, [rel console_tab_len]
    mov  esi, [rcx + r13*4]
    test esi, esi
    jz   .adopt
    imul rdi, r13, CONSOLE_TAB_STORE
    lea  rax, [rel console_tab_store]
    add  rdi, rax
    call grid_append
    jmp  .adopt
.new_tab:
    mov  edi, r12d
    call console_tab_store_for            ; reserve the new tab's store
    lea  rdi, [rel str_console_tab_banner]
    call console_append_cstr
    lea  rdi, [rel str_console_welcome]
    call console_append_cstr
.adopt:
    mov  [rel console_tab_live], r12d
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; console_tab_find(EDI=tag) -> EAX = store index or -1. Tag 0 finds a free store.
; Preserves RDI. Clobbers RCX.
console_tab_find:
    xor  eax, eax
    lea  rcx, [rel console_tab_tag]
.scan:
    cmp  eax, TS_MAX_TABS
    jae  .none
    cmp  [rcx + rax*4], edi
    je   .out
    inc  eax
    jmp  .scan
.none:
    mov  eax, -1
.out:
    ret

; console_tab_store_for(EDI=tag) -> EAX = the tag's store index, a free one
; claimed (empty) when the tag has none yet, or -1 when every store is held.
console_tab_store_for:
    call console_tab_find
    cmp  eax, -1
    jne  .out
    push rdi
    xor  edi, edi
    call console_tab_find
    pop  rdi
    cmp  eax, -1
    je   .out
    lea  rcx, [rel console_tab_tag]
    mov  [rcx + rax*4], edi
    lea  rcx, [rel console_tab_len]
    mov  dword [rcx + rax*4], 0
.out:
    ret

; console_tabs_prune: release the store of every tab the strip no longer has.
console_tabs_prune:
    push rbx
    xor  ebx, ebx
.loop:
    cmp  ebx, TS_MAX_TABS
    jae  .out
    lea  rax, [rel console_tab_tag]
    mov  esi, [rax + rbx*4]
    test esi, esi
    jz   .next
    mov  edi, [rel console_bound_slot]
    call wgt_tabstrip_has_tag
    test eax, eax
    jnz  .next
    lea  rax, [rel console_tab_tag]
    mov  dword [rax + rbx*4], 0
.next:
    inc  ebx
    jmp  .loop
.out:
    pop  rbx
    ret

console_tabs_reset:
    lea  rdi, [rel console_tab_tag]
    xor  eax, eax
    mov  ecx, TS_MAX_TABS
    cld
    rep  stosd
    mov  dword [rel console_tab_live], 0
    ret

console_app_textfield_event:
    push rbx
    mov  ebx, esi
    cmp  edi, [rel console_input_id]
    jne  .out
    cmp  ebx, GUI_KEY_UP
    je   .up
    cmp  ebx, GUI_KEY_DOWN
    je   .down
    jmp  .out
.up:
    call console_history_up
    jmp  .out
.down:
    call console_history_down
.out:
    pop  rbx
    ret

console_submit:
    push rbx
    call console_line_sync            ; F-CON31 option C: the console line is the source of truth
    mov  ebx, [rel console_llen]
    test ebx, ebx
    jz   .out                         ; empty line is an exact no-op
    lea  rsi, [rel console_lbuf]
    lea  rdi, [rel console_line]
    xor  ecx, ecx
.copy:
    cmp  ecx, CONSOLE_HISTORY_SZ - 1
    jae  .copied
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .copied
    mov  [rdi + rcx], dl
    inc  ecx
    jmp  .copy
.copied:
    mov  byte [rdi + rcx], 0
    lea  rdi, [rel console_line]
    call cons_line_class                ; recall stores raw lines: only SAFE may enter it
    cmp  eax, CONS_CLASS_SAFE
    jne  .no_history
    call console_history_push
.no_history:
    lea  rdi, [rel console_line]
    call cons_keyboard_begin
    lea  rdi, [rel console_line]
    call console_dispatch_line
    mov  rdx, rax
    mov  rdi, [rel console_capture_ptr]
    mov  esi, [rel console_capture_len]
    mov  rcx, [rel console_rsp + RSP_JOBID]
    mov  r8, [rel console_rsp + RSP_ACCEPTED]
    call cons_keyboard_finish
    mov  edi, [rel console_input_id]
    lea  rsi, [rel str_console_empty]
    call wgt_set_text
    call console_line_reset
.out:
    pop  rbx
    ret

; Parse a verb line, marshal by registry metadata, dispatch once, and append the
; canonical structured reply. Leading '/' is presentation-only and is stripped.
console_dispatch_line:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    lea  rdi, [rel str_console_prompt]
    call console_append_cstr
    mov  rdi, r12
    call cons_line_class
    cmp  eax, CONS_CLASS_SECRET
    jne  .echo_plain
    lea  rdi, [rel str_console_secret_line]
    jmp  .echo_line
.echo_plain:
    mov  rdi, r12
.echo_line:
    call console_append_cstr
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
    mov  r14, r12
    cmp  byte [r14], '/'
    jne  .skip_spaces
    inc  r14
.skip_spaces:
    cmp  byte [r14], ' '
    jne  .verb_ready
    inc  r14
    jmp  .skip_spaces
.verb_ready:
    cmp  byte [r14], 0
    je   .empty
    mov  rbx, r14
.find_space:
    cmp  byte [rbx], 0
    je   .no_arg
    cmp  byte [rbx], ' '
    je   .has_arg
    inc  rbx
    jmp  .find_space
.has_arg:
    mov  byte [rbx], 0
    inc  rbx
.arg_spaces:
    cmp  byte [rbx], ' '
    jne  .arg_ready
    inc  rbx
    jmp  .arg_spaces
.no_arg:
.arg_ready:
    mov  r15, rbx
    mov  r13, -1

    mov  qword [rel console_req + REQ_VERB], 0
    mov  qword [rel console_req + REQ_CAP], -1
    mov  qword [rel console_req + REQ_IDEM], 0
    mov  qword [rel console_req + REQ_SEL], 0
    mov  qword [rel console_req + REQ_ARG], 0
    mov  qword [rel console_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    lea  rdi, [rel console_req]
    call session_shell_prepare_local_request
    mov  rdi, r14
    call command_lookup
    cmp  eax, -1
    jne  .known
    ; F-CONCASE (2026-10-01, usage suite CON-01): verbs are upper-case names;
    ; a miss retries the token upper-cased (ASCII a-z only), as the UDP verb
    ; path already answers `ping`. An exact name always wins first.
    lea  rdi, [rel console_verb_upper]
    xor  ecx, ecx
.upper:
    cmp  ecx, CONSOLE_HISTORY_SZ - 1
    jae  .upper_done
    mov  al, [r14 + rcx]
    test al, al
    jz   .upper_done
    cmp  al, 'a'
    jb   .upper_store
    cmp  al, 'z'
    ja   .upper_store
    sub  al, 'a' - 'A'
.upper_store:
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .upper
.upper_done:
    mov  byte [rdi + rcx], 0
    call command_lookup
    cmp  eax, -1
    je   .unknown
    lea  r14, [rel console_verb_upper]
    jmp  .known
.unknown:
    call command_verb_count
    mov  [rel console_req + REQ_VERB], rax
    mov  [rel console_req + REQ_ARG], r15
    jmp  .dispatch
.known:
    mov  r13, rax
    mov  [rel console_req + REQ_VERB], rax
    mov  rdi, r13
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .text_arg
    mov  rdi, r15
    call console_parse_u64
    mov  [rel console_req + REQ_ARG], rax
    jmp  .dispatch
.text_arg:
    mov  [rel console_req + REQ_ARG], r15
.dispatch:
    lea  rdi, [rel console_req]
    lea  rsi, [rel console_rsp]
    lea  rdx, [rel console_line_taint]
    mov  ecx, KP_SURFACE_CONSOLE
    call keyprov_dispatch                 ; THE one console-local registry entry; a tainted line runs as its injector (GA0-K)

    mov  rdi, r14
    mov  rsi, r15
    lea  rdx, [rel console_rsp]
    call command_udp_capture_reply
    mov  [rel console_capture_ptr], rax
    mov  [rel console_capture_len], edx
    mov  byte [rel console_capture_prefix_ok], 0
    cmp  edx, str_console_canonical_prefix.len
    jb   .append_reply
    mov  rbx, rax
    lea  rdi, [rel str_console_canonical_prefix]
    mov  esi, str_console_canonical_prefix.len
.prefix:
    mov  cl, [rbx]
    cmp  cl, [rdi]
    jne  .append_reply
    inc  rbx
    inc  rdi
    dec  esi
    jnz  .prefix
    mov  byte [rel console_capture_prefix_ok], 1
.append_reply:
    mov  esi, [rel console_capture_len]
    cmp  esi, 2
    jb   .reply_bytes
    cmp  word [rax + rsi - 2], 0x0a0d
    jne  .reply_bytes
    sub  esi, 2
.reply_bytes:
    mov  rdi, rax
    call grid_append
    cmp  qword [rel console_rsp + RSP_ACCEPTED], 1
    jne  .status_job
    mov  rdi, [rel console_rsp + RSP_JOBID]
    test rdi, rdi
    jz   .status_job
    lea  rdi, [rel str_console_job_accepted]
    call console_append_cstr
    mov  rdi, [rel console_rsp + RSP_JOBID]
    call console_append_dec
    lea  rdi, [rel str_console_job_est]
    call console_append_cstr
    mov  rdi, SLOWJOB_EST_SEC
    call console_append_dec
    jmp  .reply_end
.status_job:
    cmp  r13d, [rel verb_id_status]
    jne  .reply_end
    cmp  qword [rel console_rsp + RSP_CODE], CMDE_OK
    jne  .reply_end
    cmp  qword [rel console_req + REQ_ARG], 0
    je   .reply_end
    lea  rdi, [rel str_console_job_state]
    call console_append_cstr
    mov  rax, [rel console_rsp + RSP_VAL]
    cmp  rax, JOB_ST_RUN
    jne  .status_done
    lea  rdi, [rel str_console_job_running]
    call console_append_cstr
    jmp  .reply_end
.status_done:
    cmp  rax, JOB_ST_DONE
    jne  .status_number
    lea  rdi, [rel str_console_job_done]
    call console_append_cstr
    jmp  .reply_end
.status_number:
    mov  rdi, rax
    call console_append_dec
.reply_end:
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
    mov  rbx, [rel console_rsp + RSP_CODE]
    test rbx, rbx
    jz   .status
    lea  rdi, [rel str_console_err_code]
    call console_append_cstr
    mov  rdi, rbx
    call console_append_dec
    lea  rdi, [rel str_console_err_expected]
    call console_append_cstr
    mov  rdi, [rel console_rsp + RSP_EXPECTED]
    call console_append_dec
    lea  rdi, [rel str_console_err_hint]
    call console_append_cstr
    mov  rdi, [rel console_rsp + RSP_HINT]
    test rdi, rdi
    jnz  .hint
    lea  rdi, [rel str_console_none]
.hint:
    call console_append_cstr
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
.status:
    mov  rdi, rbx
    call console_update_last
    mov  rax, rbx
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

; L6 half of the session callback. Replays and UDP submits use the exact same
; grid append path as keyboard dispatch; no parallel text renderer exists.
console_session_render:
    mov  eax, [rel console_bound_slot]
    cmp  eax, WM_MAX
    jae  .ret
    lea  r9, [rel wm_state]
    mov  eax, [r9 + rax*4]
    cmp  eax, WM_VISIBLE
    je   .live
    cmp  eax, WM_MIN
    jne  .ret
.live:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, ecx
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  r15, r8
    cmp  ebx, CONS_ORIGIN_JOB
    je   .job
    lea  rdi, [rel str_console_prompt]
    call console_append_cstr
    mov  rdi, r12
    call console_append_cstr
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
    mov  rdi, r13
    mov  esi, r14d
    call grid_append
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
    jmp  .last
.job:
    mov  rdi, r13
    mov  esi, r14d
    call grid_append
    lea  rdi, [rel str_console_nl]
    call console_append_cstr
.last:
    mov  rdi, r15
    call console_update_last
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.ret:
    ret

console_history_push:
    push rbx
    mov  ebx, [rel console_history_count]
    cmp  ebx, CONSOLE_HISTORY_MAX
    jb   .slot
    lea  rsi, [rel console_history + CONSOLE_HISTORY_SZ]
    lea  rdi, [rel console_history]
    mov  ecx, (CONSOLE_HISTORY_MAX - 1) * CONSOLE_HISTORY_SZ
    cld
    rep  movsb
    mov  ebx, CONSOLE_HISTORY_MAX - 1
    jmp  .copy
.slot:
    inc  dword [rel console_history_count]
.copy:
    mov  eax, ebx
    imul eax, CONSOLE_HISTORY_SZ
    lea  rdi, [rel console_history]
    add  rdi, rax
    lea  rsi, [rel console_line]
    mov  ecx, CONSOLE_HISTORY_SZ
    cld
    rep  movsb
    mov  eax, [rel console_history_count]
    mov  [rel console_history_cursor], eax
    pop  rbx
    ret

console_history_up:
    mov  eax, [rel console_history_count]
    test eax, eax
    jz   .ret
    mov  ecx, [rel console_history_cursor]
    test ecx, ecx
    jz   .recall
    dec  ecx
    mov  [rel console_history_cursor], ecx
.recall:
    jmp  console_history_recall
.ret:
    ret

console_history_down:
    mov  eax, [rel console_history_count]
    test eax, eax
    jz   .ret
    mov  ecx, [rel console_history_cursor]
    inc  ecx
    cmp  ecx, eax
    jb   .recall
    mov  [rel console_history_cursor], eax
    mov  edi, [rel console_input_id]
    lea  rsi, [rel str_console_empty]
    call wgt_set_text
    ret
.recall:
    mov  [rel console_history_cursor], ecx
    jmp  console_history_recall
.ret:
    ret

console_history_recall:
    mov  eax, [rel console_history_cursor]
    imul eax, CONSOLE_HISTORY_SZ
    lea  rsi, [rel console_history]
    add  rsi, rax
    lea  rdi, [rel console_lbuf]         ; F-CON31 option C: the entry becomes the console line
    xor  ecx, ecx
.cp:
    cmp  ecx, CONSOLE_LINE_MAX
    jae  .cp_done
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .cp_done
    mov  [rdi + rcx], dl
    inc  ecx
    jmp  .cp
.cp_done:
    mov  byte [rdi + rcx], 0
    mov  [rel console_llen], ecx
    mov  [rel console_lcaret], ecx       ; caret at its end, as the textfield did
    mov  dword [rel console_lview], 0
    jmp  console_line_render             ; replaces the visible WIDGETGET window

; ---------------------------------------------------------------------------
; F-CON31 option C (ADMIN 2026-10-02): a console-owned, bounded input line.
; The generic 200-byte widget record (WGI_VAL inline 40 bytes, WGI_VAL_MAX 31) is
; unchanged. The console keeps the line in console_lbuf (CONSOLE_LINE_MAX bytes) and
; shows a CONSOLE_LINE_VIS window around the caret in its input textfield. Edits
; mirror wgt_textfield_key exactly (insert at caret, Backspace, Delete, Left/Right,
; Home/End). Enter, Up/Down and Tab stay on their existing paths (submit generation,
; history, focus). A printable key at CONSOLE_LINE_MAX is dropped and counted in
; console_loverflow. Anything else that writes the field (history recall, submit clear,
; WIDGETSET, paste) is adopted by console_line_sync.
; ---------------------------------------------------------------------------

; console_key_filter(EDI = focused widget id, EAX = key) -> EAX 1 when the line took it.
console_key_filter:
    cmp  edi, [rel console_input_id]
    jne  .chain
    push rdi                             ; GA0-K: every key aimed at the line, the
    lea  rdi, [rel console_line_taint]   ; submitting Enter included, folds its
    call keyprov_line_note               ; origin into the line's taint
    pop  rdi
    cmp  eax, GUI_KEY_BACKSPACE
    je   .mine
    cmp  eax, GUI_KEY_DELETE
    je   .mine
    cmp  eax, GUI_KEY_LEFT
    je   .mine
    cmp  eax, GUI_KEY_RIGHT
    je   .mine
    cmp  eax, GUI_KEY_HOME
    je   .mine
    cmp  eax, GUI_KEY_END
    je   .mine
    cmp  eax, 0x20
    jb   .chain
    cmp  eax, 0x7E
    ja   .chain
.mine:
    push rbx
    push r12
    mov  r12d, eax
    call console_line_sync
    mov  eax, r12d
    call console_line_edit
    call console_line_render
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.chain:
    mov  rdx, [rel console_kf_prev]
    test rdx, rdx
    jz   .not_mine
    jmp  rdx                             ; EDI / EAX unchanged
.not_mine:
    xor  eax, eax
    ret

; console_line_sync — adopt the field's text when something other than this line wrote it.
console_line_sync:
    push rbx
    mov  edi, [rel console_input_id]
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [rbx + WGI_VLEN]
    cmp  ecx, [rel console_lrender_len]
    jne  .adopt
    lea  r8, [rel console_lrender]
    xor  edx, edx
.same:
    cmp  edx, ecx
    jae  .in_sync
    mov  al, [rbx + WGI_VAL + rdx]
    cmp  al, [r8 + rdx]
    jne  .adopt
    inc  edx
    jmp  .same
.adopt:
    mov  ecx, [rbx + WGI_VLEN]
    cmp  ecx, WGT_TEXTFIELD_VAL_MAX
    jbe  .len_ok
    mov  ecx, WGT_TEXTFIELD_VAL_MAX
.len_ok:
    lea  rdi, [rel console_lbuf]
    xor  edx, edx
.copy:
    cmp  edx, ecx
    jae  .copied
    mov  al, [rbx + WGI_VAL + rdx]
    mov  [rdi + rdx], al
    inc  edx
    jmp  .copy
.copied:
    mov  byte [rdi + rdx], 0
    mov  [rel console_llen], ecx
    push rdi                             ; GA0-K: text a request wrote (WIDGETSET,
    push rsi                             ; CLIPGET) carries that request's context
    mov  edi, [rel console_input_id]
    lea  rsi, [rel console_line_taint]
    call keyprov_field_take
    pop  rsi
    pop  rdi
    mov  eax, [rbx + WGI_CARET]
    cmp  eax, ecx
    jbe  .caret_ok
    mov  eax, ecx
.caret_ok:
    mov  [rel console_lcaret], eax
    mov  dword [rel console_lview], 0
    mov  [rel console_lrender_len], ecx   ; the field now shows exactly the adopted text
    lea  rsi, [rel console_lbuf]
    lea  rdi, [rel console_lrender]
    xor  edx, edx
.mirror:
    cmp  edx, ecx
    ja   .in_sync
    mov  al, [rsi + rdx]
    mov  [rdi + rdx], al
    inc  edx
    jmp  .mirror
.in_sync:
    pop  rbx
    ret

; console_line_edit(EAX = key) — one edit of console_lbuf, the wgt_textfield_key semantics.
console_line_edit:
    mov  ecx, [rel console_llen]
    mov  edx, [rel console_lcaret]
    lea  rdi, [rel console_lbuf]
    cmp  eax, GUI_KEY_BACKSPACE
    je   .bs
    cmp  eax, GUI_KEY_DELETE
    je   .del_at
    cmp  eax, GUI_KEY_LEFT
    je   .left
    cmp  eax, GUI_KEY_RIGHT
    je   .right
    cmp  eax, GUI_KEY_HOME
    je   .home
    cmp  eax, GUI_KEY_END
    je   .end
    cmp  ecx, CONSOLE_LINE_MAX            ; printable: insert at the caret
    jb   .ins
    inc  dword [rel console_loverflow]    ; the line is full: the key is dropped, counted
    ret
.ins:
    mov  r8d, ecx
.shr:
    cmp  r8d, edx
    jle  .put
    mov  r9b, [rdi + r8 - 1]
    mov  [rdi + r8], r9b
    dec  r8d
    jmp  .shr
.put:
    mov  [rdi + rdx], al
    inc  ecx
    inc  edx
    mov  byte [rdi + rcx], 0
    jmp  .store
.bs:
    test edx, edx
    jz   .out
    dec  edx
.del_at:
    cmp  edx, ecx
    jae  .store
    mov  r8d, edx
.shl:
    lea  r9d, [r8d + 1]
    cmp  r9d, ecx
    jae  .shl_done
    mov  r10b, [rdi + r9]
    mov  [rdi + r8], r10b
    inc  r8d
    jmp  .shl
.shl_done:
    dec  ecx
    mov  byte [rdi + rcx], 0
    jmp  .store
.left:
    test edx, edx
    jz   .out
    dec  edx
    jmp  .store
.right:
    cmp  edx, ecx
    jae  .out
    inc  edx
    jmp  .store
.home:
    xor  edx, edx
    jmp  .store
.end:
    mov  edx, ecx
.store:
    mov  [rel console_llen], ecx
    mov  [rel console_lcaret], edx
.out:
    ret

; console_line_render — show the CONSOLE_LINE_VIS window that holds the caret; remember it.
console_line_render:
    push rbx
    push r12
    mov  ecx, [rel console_llen]
    mov  edx, [rel console_lcaret]
    mov  eax, [rel console_lview]
    cmp  edx, eax
    jae  .not_left
    mov  eax, edx                          ; caret left of the window: scroll left
.not_left:
    lea  r8d, [rax + CONSOLE_LINE_VIS]
    cmp  edx, r8d
    jbe  .not_right
    mov  eax, edx                          ; caret right of the window: scroll right
    sub  eax, CONSOLE_LINE_VIS
.not_right:
    cmp  ecx, CONSOLE_LINE_VIS
    ja   .long
    xor  eax, eax                          ; a short line is always shown whole
    jmp  .view_ok
.long:
    mov  r8d, ecx
    sub  r8d, CONSOLE_LINE_VIS
    cmp  eax, r8d
    jbe  .view_ok
    mov  eax, r8d                          ; never leave blank space after the line's end
.view_ok:
    mov  [rel console_lview], eax
    mov  r9d, ecx
    sub  r9d, eax
    cmp  r9d, CONSOLE_LINE_VIS
    jbe  .n_ok
    mov  r9d, CONSOLE_LINE_VIS
.n_ok:
    lea  rsi, [rel console_lbuf]
    add  rsi, rax
    lea  rdi, [rel console_lrender]
    xor  r10d, r10d
.cp:
    cmp  r10d, r9d
    jae  .cp_done
    mov  r11b, [rsi + r10]
    mov  [rdi + r10], r11b
    inc  r10d
    jmp  .cp
.cp_done:
    mov  byte [rdi + r10], 0
    mov  [rel console_lrender_len], r9d
    mov  ebx, edx
    sub  ebx, eax                          ; caret inside the window
    mov  edi, [rel console_input_id]
    lea  rsi, [rel console_lrender]
    call wgt_set_text
    mov  edi, [rel console_input_id]
    call wgt_slot_ptr
    mov  [rax + WGI_CARET], ebx
    call wmx_draw_all                      ; the caret moved after wgt_set_text painted
    pop  r12
    pop  rbx
    ret

; console_line_reset — an empty line after submit (the field was cleared with it).
; The submitted bytes are wiped, not only terminated (srcreview NIT on the
; transcript slice): console_line is a copy, history already holds what it keeps.
console_line_reset:
    lea  rdi, [rel console_line_taint]   ; GA0-K: the line and its taint go together
    call keyprov_line_clear
    xor  eax, eax
    mov  [rel console_llen], eax
    mov  [rel console_lcaret], eax
    mov  [rel console_lview], eax
    mov  [rel console_lrender_len], eax
    lea  rdi, [rel console_lbuf]
    xor  esi, esi
    mov  edx, CONSOLE_LINE_MAX + 1
    call memset
    lea  rdi, [rel console_lrender]
    xor  esi, esi
    mov  edx, CONSOLE_LINE_VIS + 1
    call memset
    lea  rdi, [rel console_line]
    xor  esi, esi
    mov  edx, CONSOLE_HISTORY_SZ
    jmp  memset

console_update_status:
    call console_session_label
    call command_verb_count
    mov  rdi, rax
    lea  rsi, [rel console_verbs_buf + 6]
    call fmt_dec
    lea  rcx, [rel console_verbs_buf + 6]
    mov  byte [rcx + rax], 0
    mov  edi, [rel console_verbs_id]
    lea  rsi, [rel console_verbs_buf]
    call wgt_set_text
    xor  edi, edi
    call console_update_last
    ret

; Status-strip session label: names the principal actually bound to the
; console session (session_bound_pid, the value SESSIONINFO reports as
; principal=), never a constant: owner/system/try, none while unbound, unknown
; for any other value. Text only; no authority decision reads it.
console_session_refresh:
    mov  rax, [rel session_bound_pid]
    cmp  rax, [rel console_session_shown]
    jne  console_session_label
    ret

console_session_label:
    mov  rax, [rel session_bound_pid]
    mov  [rel console_session_shown], rax
    lea  rsi, [rel str_console_session_none]
    test rax, rax
    jz   .set
    lea  rsi, [rel str_console_session_owner]
    cmp  rax, PRIN_OWNER
    je   .set
    lea  rsi, [rel str_console_session_system]
    cmp  rax, PRIN_SYSTEM
    je   .set
    lea  rsi, [rel str_console_session_try]
    cmp  rax, PRIN_TRY
    je   .set
    lea  rsi, [rel str_console_session_unknown]
.set:
    mov  edi, [rel console_session_id]
    jmp  wgt_set_text                    ; refuses an id outside the widget table

console_update_last:
    push rbx
    mov  rbx, rdi
    mov  edi, [rel console_last_id]
    test rbx, rbx
    jnz  .err
    lea  rsi, [rel str_console_last_ok]
    call wgt_set_text
    pop  rbx
    ret
.err:
    mov  rdi, rbx
    lea  rsi, [rel console_last_buf + 9]
    call fmt_dec
    lea  rcx, [rel console_last_buf + 9]
    mov  byte [rcx + rax], 0
    mov  edi, [rel console_last_id]
    lea  rsi, [rel console_last_buf]
    call wgt_set_text
    pop  rbx
    ret

console_append_cstr:
    push rdi
    call strlen
    mov  rsi, rax
    pop  rdi
    call grid_append
    ret

console_append_dec:
    lea  rsi, [rel console_num_buf]
    push rsi
    call fmt_dec
    pop  rdi
    mov  rsi, rax
    call grid_append
    ret

console_parse_u64:
    xor  eax, eax
.next:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul rax, rax, 10
    add  rax, rcx
    inc  rdi
    jmp  .next
.done:
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_console_app_tl 0
console_tl_latched: resb 1              ; boot.terminal.usable already latched
%endmacro
WDATA_BSS_DEFER WDATA_gui_console_app_tl
%macro WDATA_gui_console_app_tabs 0
alignb 8
console_tab_live:  resd 1               ; B5: tag whose transcript the grid shows (0 = none adopted)
console_tab_tag:   resd TS_MAX_TABS         ; B5: store owner tag (0 = free)
console_tab_len:   resd TS_MAX_TABS
console_tab_store: resb (TS_MAX_TABS * CONSOLE_TAB_STORE)
%endmacro
WDATA_BSS_DEFER WDATA_gui_console_app_tabs
%macro WDATA_gui_console_try_hw 0
console_try_hw_shown: resb 1
console_try_hw_pending: resb 1
console_try_hw_buf: resb HW_LOG_CAP
%endmacro
WDATA_BSS_DEFER WDATA_gui_console_try_hw

align 8
console_launch_fallback: dq 0
console_formload_fallback: dq 0
console_forminfo_fallback: dq 0
console_form_saved_name: dq 0
console_form_saved_blob: dq 0
console_form_saved_len: dq 0
console_req: times REQ_SZ db 0
console_rsp: times RSP_SZ db 0
console_bound_slot: dd -1
console_saved_grid_id: dd -1
console_grid_id: dd -1
console_input_id: dd -1
console_session_id: dd -1
console_bound_session_noun: dd -1
console_verbs_id: dd -1
console_last_id: dd -1
console_found_grid: dd -1
console_found_input: dd -1
console_found_session: dd -1
console_found_verbs: dd -1
console_found_last: dd -1
console_history_count: dd 0
console_history_cursor: dd 0
console_submit_seen: dd 0
console_capture_len: dd 0
console_service_ready: db 0
console_capture_prefix_ok: db 0
console_saved_grid_dock_owner: db 1
console_saved_grid_mode: db 0
align 8
console_capture_ptr: dq 0
console_line: times CONSOLE_HISTORY_SZ db 0
console_lbuf:        times (CONSOLE_LINE_MAX + 1) db 0   ; F-CON31 option C: the console-owned input line
console_lrender:     times (CONSOLE_LINE_VIS + 1) db 0   ; the window last written to the input textfield
align 8
console_line_taint:  times KT_SIZE db 0   ; GA0-K: sec/keyprov taint of console_lbuf
align 4
console_llen:        dd 0
console_lcaret:      dd 0
console_lview:       dd 0
console_lrender_len: dd 0
console_loverflow:   dd 0       ; printable keys dropped at CONSOLE_LINE_MAX
align 8
console_kf_prev:     dq 0
console_kf_installed: db 0
console_verb_upper: times CONSOLE_HISTORY_SZ db 0   ; F-CONCASE: upper-cased retry token
console_history: times (CONSOLE_HISTORY_MAX * CONSOLE_HISTORY_SZ) db 0
console_num_buf: times 24 db 0
console_verbs_buf: db "verbs="
                   times 25 db 0
console_last_buf: db "last=ERR:"
                  times 22 db 0
align 8
console_session_shown: dq -1    ; session_bound_pid the label last named

form_name_console_runtime: db "console",0
str_console_launch: db "LAUNCH",0
str_console_formload: db "FORMLOAD",0
str_console_forminfo: db "FORMINFO",0
str_console_formlist: db "FORMLIST",0
str_app_console: db "app_console",0
str_console_id_grid: db "transcript",0
str_console_id_input: db "input",0
str_console_id_session: db "session",0
str_console_id_verbs: db "verb_count",0
str_console_id_last: db "last_status",0
str_console_empty: db 0
str_console_prompt: db "> ",0
str_console_nl: db 10,0
str_console_tab_banner: db "PaOS Console - new tab: its own transcript",10,0
str_console_welcome: db "PaOS Console - registered verbs are the command language",10,"Type STATUS or WINTREE; prefixing a verb with / is optional",10,0
str_console_try_hw: db "Try hardware snapshot: detected devices and bound drivers",10,"none=unclaimed; unusable=driver failed; bound is not a live test",10,0
str_console_try_hw_fail: db " hardware report unavailable",0
str_console_session_owner: db "session=owner",0
str_console_session_system: db "session=system",0
str_console_session_try: db "session=try",0
str_console_session_none: db "session=none",0
str_console_session_unknown: db "session=unknown",0
str_console_last_ok: db "last=OK",0
str_console_launch_ok: db " launch=ok app=app_console idx=",0
str_console_launch_err: db " launch=ERR app=app_console",0
str_console_formlist_reply: db " FORMLIST n=14 names=demo_a,demo_b,demo_c,sysprops,netmon,bad_rawcolor,bad_unknown_widget,bad_unknown_key,explorer,terminal,settings,restart,shut_down,return_to_windows",0 ; 0010: + the Start rows (power is opened only through them)
str_console_err_code: db "ERR code=",0
str_console_err_expected: db " expected=",0
str_console_err_hint: db " hint=",0
str_console_none: db "none",0
str_console_job_accepted: db " accepted job=",0
str_console_job_est: db " est=",0
str_console_job_state: db " state=",0
str_console_job_running: db "running",0
str_console_job_done: db "done",0
str_console_canonical_prefix: db "PAOS VERSION="
.len equ $ - str_console_canonical_prefix
str_console_service_marker: db "[PAOS64] Console command/transcript service ready; recovery view hidden [console.service.ready]",13,10,0
str_console_init_fail: db "[PAOS64] verb-console rung 2: console form/app initialization FAIL",13,10,0

str_console_secret_line: db "<credential command redacted>",0
