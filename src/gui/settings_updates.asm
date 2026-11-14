;; MODULE gui/settings_updates
;; LAYER 6
;; EXPORTS updates_scan, settings_updates_loaded, settings_updates_click, settings_updates_key, settings_updates_tick, settings_updates_status_text, settings_updates_backend_set, settings_updates_take, settings_updates_complete, settings_updates_current, settings_updates_discovery_loaded, settings_updates_checked_text, settings_updates_daily_enqueue, settings_updates_daily_attempt_age
;; IMPORTS sec/update_request, gui/form_loader, gui/start_programs, gui/widget, gui/window_mgmt, sec/session, svc/command, svc/command_auth, core/time
;; CAPS CAP_GUI
;; OWNER rc-input-claude
; BSP-only Updates front door, driven by the EXISTING start_programs tick.
; This is an internal PaOS API, not a command/guest/network result injection API.
; No backend is installed by this module. Rescue's physical-VT C importer cannot
; be called from this kernel: ADMIN must supply an authenticated worker bridge.
; Never infer Current/Downloaded/Applied from an unavailable service or feed.
;
; Trusted backend ABI (no untrusted pointer or string enters the UI):
; backend_set(EDI=0/1): detach/attach; invalidates every outstanding request.
; take(RDI=writable 40 bytes) -> EAX=1 exactly once, else0. Record:
;   +0 u64 request, +8 u32 operation, +12 u32 version=1,
;   +16 u64 owner PID, +24 u64 owner session token, +32 u64 boot_ms deadline.
; current(RDI=private exact original40) -> EAX=1 while live, else0; read-only.
; complete(RDI=request, ESI=result, EDX=saved automatic policy0/1 for CHECK) -> EAX=1 accepted else0. Result pairs:
;   CHECK: CURRENT/AVAILABLE + read-back saved owner automatic policy in EDX; DOWNLOAD: STAGED; AUTO_ON/OFF: corresponding SAVED.
;   REFUSED/UNAVAILABLE accepted for any current request. No arbitrary text.
; Backend must verify signed full image, numeric/security/revocation/owner/slot
; guards with the existing engine BEFORE STAGED, and persist owner policy BEFORE
; SAVED. It must revalidate session/deadline at any effect; take is NOT authority
; to act later on a stale owner. Auto may download/stage, NEVER restart.
; Restart is ONLY this UI's explicit physical/key press -> original confirmation.
; No transport/signature verification/slot write/reboot lives in this module.
; Preference residual (ROOT110520): an older genuine owner-signed choice may
; return after reboot or one-slot DATA A->B->A; no durable floor is claimed.
; Payload signature, rollback/revocation guards and explicit restart remain.

%include "core/abi/wdata.inc"
%include "sec/update_request.asm"
UPD_CHECK equ 1
UPD_DOWNLOAD equ 2
UPD_AUTO_ON equ 3
UPD_AUTO_OFF equ 4
UPD_RESTART equ 5
UPD_CURRENT equ 1
UPD_AVAILABLE equ 2
UPD_STAGED equ 3
UPD_SAVED_ON equ 4
UPD_SAVED_OFF equ 5
UPD_REFUSED equ 6
UPD_UNAVAILABLE equ 7
UPD_W_COUNT equ 10
UPD_HOME_COUNT equ 11
UPD_ABOUT_COUNT equ 8
UPD_ARM_FIRST equ 19

; Called on every actual open/raise through the normal form loader. The tick
; takes a fresh local owner for this READ-ONLY automatic check after dispatch.
settings_updates_loaded:
    call settings_updates_discovery_loaded
    call updates_scan
    cmp eax, UPD_W_COUNT
    jne .out
    mov eax, [rel upd_ids+2*4]
    mov ecx, [rel upd_slot]
    lea rdx, [rel wgt_focus_by_win]
    mov [rdx+rcx*4], eax
    cmp ecx, [rel wm_focus]
    jne .out
    mov [rel wgt_focus_id], eax
.out:
    ret

; Updates or recovery opened successfully. Queue only the ordinary read-only
; CHECK for the existing idle tick, never a download, focus change or reboot.
settings_updates_discovery_loaded:
    cmp dword [rel upd_phase], 0
    jne .out
    cmp dword [rel upd_action], 0
    jne .out
    call updates_attempt_context
    test eax, eax
    jz .check
    cmp rdx, 600000
    jb .out
.check:
    mov byte [rel upd_auto_check], 1
    mov dword [rel upd_action], UPD_CHECK
.out:
    ret

; Private D seam: only enqueue the existing read-only CHECK. No take/effect or
; policy save occurs here. D first reads its genuine daily-disable policy; this
; native boundary independently requires an eligible current local owner.
; EAX1 queued (not dispatched/completed),0 deferred; no stale job is revived.
settings_updates_daily_enqueue:
    sub rsp, 8
    cmp byte [rel upd_backend], 1
    jne .no
    cmp dword [rel upd_phase], 0
    jne .no
    cmp dword [rel upd_action], 0
    jne .no
    cmp byte [rel session_locked], SESSION_LOCKED
    je .no
    cmp byte [rel cmd_in_dispatch], 0
    jne .no
    cmp byte [rel command_auth_remote_active], 0
    jne .no
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .no
    test rdx, rdx
    jz .no
    call updates_attempt_context
    test eax, eax
    jz .queue
    cmp rdx, 600000
    jb .no
.queue:
    mov byte [rel upd_auto_check], 1
    mov dword [rel upd_action], UPD_CHECK
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    ret

; EAX1/RDX elapsed only for the current local owner's actual CHECK attempt.
; Unknown/stale/clock-regressed context returns0, never a fabricated schedule.
settings_updates_daily_attempt_age:
    jmp updates_attempt_context

; Attempt freshness and successful checked-age are deliberately separate. A
; refused/timed-out CHECK is still an attempt; only verified success is checked.
updates_attempt_context:
    cmp byte [rel upd_attempt_valid], 1
    jne updates_context_absent
    lea rdi, [rel upd_attempt_ms]
    jmp updates_discovery_context
updates_checked_context:
    cmp byte [rel upd_checked_valid], 1
    jne updates_context_absent
    lea rdi, [rel upd_checked_ms]
; RDI -> {boot_ms,owner,token}; EAX=1 and RDX=elapsed only in the same live
; native session/backend. Neither stale identity nor clock regression is fresh.
updates_discovery_context:
    push rbx
    mov rbx, rdi
    cmp byte [rel upd_backend], 1
    jne .no
    cmp byte [rel session_locked], SESSION_LOCKED
    je .no
    cmp byte [rel cmd_in_dispatch], 0
    jne .no
    cmp byte [rel command_auth_remote_active], 0
    jne .no
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .no
    cmp rax, [rbx+8]
    jne .no
    test rdx, rdx
    jz .no
    cmp rdx, [rbx+16]
    jne .no
    call boot_ms_now
    cmp rax, [rbx]
    jb .no
    sub rax, [rbx]
    mov rdx, rax
    mov eax, 1
    pop rbx
    ret
.no:
    pop rbx
updates_context_absent:
    xor eax, eax
    ret

; Stock31B label; never a completed-check claim from request dispatch/fetch.
settings_updates_checked_text:
    call updates_checked_context
    test eax, eax
    jz .unknown
    mov rax, rdx
    xor edx, edx
    mov ecx, 60000
    div rcx
    cmp rax, 999999
    ja .old
    lea rsi, [rel upd_checked_buf+31]
    mov byte [rsi], 0
    mov ecx, 10
.digit:
    xor edx, edx
    div rcx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    test rax, rax
    jnz .digit
    mov r8, rsi
    lea rdi, [rel upd_checked_buf]
    lea rsi, [rel upd_checked_prefix]
    mov ecx, 8
    rep movsb
.copy:
    mov al, [r8]
    inc r8
    test al, al
    jz .suffix
    stosb
    jmp .copy
.suffix:
    lea rsi, [rel upd_checked_suffix]
    mov ecx, 9
    rep movsb
    lea rax, [rel upd_checked_buf]
    ret
.unknown:
    lea rax, [rel upd_not_checked]
    ret
.old:
    lea rax, [rel upd_checked_old]
    ret

updates_scan:
    mov edi, FORM_UPDATES_INDEX
    mov esi, UPD_W_COUNT
    lea rdx, [rel upd_ids]
    call sp_form_widgets_n
    mov [rel upd_slot], ecx
    ret

; Same shared summary in Settings, About, and Updates. Strings fit stock31B.
settings_updates_status_text:
    mov eax, [rel upd_status]
    cmp eax, 2
    je .success
    cmp eax, 3
    je .success
    cmp eax, 5
    jne .animation
.success:
    ; About can read before idle tick notices lock/logout. Reuse the same
    ; genuine completed-check context as checked age and the Settings badge.
    sub rsp, 8
    call updates_checked_context
    add rsp, 8
    test eax, eax
    jnz .reload
    lea rax, [rel upd_expired]
    ret
.reload:
    mov eax, [rel upd_status]
.animation:
    cmp eax, 1
    jne .static
    ; Bounded two-frame check animation on the existing idle/clock cadence.
    call boot_ms_now
    test eax, 512
    lea rax, [rel upd_checking]
    lea rdx, [rel upd_checking_alt]
    cmovnz rax, rdx
    ret
.static:
    cmp eax, 8
    jbe .valid
    mov eax, 7
.valid:
    lea rdx, [rel upd_texts]
    movsxd rax, dword [rdx+rax*4]
    add rax, rdx
    ret

; Settings' entry always names its read-only navigation action. A text badge
; distinguishes an available download from staged/ready-to-apply bytes. Neither
; cached status alone nor dispatch is a witness: use the existing authenticated
; CHECK context, including live backend/owner/session/clock guards, even before
; the idle tick invalidates an old session. No request/effect authority changes.
updates_entry_text:
    call updates_checked_context
    test eax, eax
    jz .plain
    cmp dword [rel upd_status], 3
    je .available
    cmp dword [rel upd_status], 5
    je .ready
.plain:
    lea rax, [rel upd_entry]
    ret
.available:
    lea rax, [rel upd_entry_available]
    ret
.ready:
    lea rax, [rel upd_entry_ready]
    ret

; EDI live widget -> action1..5, or0; stock form scan verifies title identity.
updates_action_of:
    push rbx
    mov ebx, edi
    call updates_scan
    cmp eax, UPD_W_COUNT
    jne .none
    mov edx, [rel upd_slot]
    cmp edx, [rel wm_focus]
    jne .none
    xor ecx, ecx
.find:
    lea rax, [rel upd_ids+2*4]
    cmp ebx, [rax+rcx*4]
    je .found
    inc ecx
    cmp ecx, 4
    jb .find
.none:
    xor eax, eax
    pop rbx
    ret
.found:
    mov edi, ebx
    push rcx
    call wgt_slot_ptr
    pop rcx
    cmp dword [rax+WGI_TYPE], WGT_TYPE_BUTTON
    jne .none
    test dword [rax+WGI_FLAGS], 1
    jz .none
    test dword [rax+WGI_EDIT], WGT_EDIT_DISABLED
    jnz .none
    lea eax, [rcx+1]
    cmp ecx, 2
    jne .auto
    mov eax, UPD_RESTART
.auto:
    cmp ecx, 3
    jne .out
    mov eax, UPD_AUTO_ON
    cmp byte [rel upd_auto_enabled], 0
    je .out
    mov eax, UPD_AUTO_OFF
.out:
    pop rbx
    ret

settings_updates_click:
    ; Settings and the existing About form3 share read-only navigation. Their
    ; stock live title/focus/button guards do not grant CHECK/Download/Restart.
    ; Mutations below still require the original physical armed press.
    push rbx
    mov ebx, edi
    mov edi, FORM_SETTINGS_INDEX
    mov esi, UPD_HOME_COUNT
    lea rdx, [rel upd_home_ids]
    call sp_form_widgets_n
    cmp eax, UPD_HOME_COUNT
    jne .about
    cmp ebx, [rel upd_home_ids+10*4]
    je .navigation
.about:
    mov edi, 3                         ; existing About this PC, not a new form
    mov esi, UPD_ABOUT_COUNT
    lea rdx, [rel upd_about_ids]
    call sp_form_widgets_n
    cmp eax, UPD_ABOUT_COUNT
    jne .page
    cmp ebx, [rel upd_about_ids+7*4]
    jne .page
.navigation:
    cmp ecx, [rel wm_focus]
    jne .page
    lea rax, [rel wm_state]
    cmp dword [rax+rcx*4], WM_VISIBLE
    jne .no
    cmp byte [rel session_locked], SESSION_LOCKED
    je .no
    mov edi, ebx
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE], WGT_TYPE_BUTTON
    jne .no
    test dword [rax+WGI_FLAGS], 1
    jz .no
    test dword [rax+WGI_EDIT], WGT_EDIT_DISABLED
    jnz .no
    mov byte [rel upd_open], 1
    mov eax, 1
    jmp .out
.page:
    mov edi, ebx
    call daily_live_widget
    test rax, rax
    jz .ordinary
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .no
    cmp byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne .no
    mov edi, ebx
    mov esi, UPD_DAILY_ARM
    call sp_arm_holds
    test eax, eax
    jz .no
    mov edi, ebx
    call settings_update_daily_capture
    jmp .out
.ordinary:
    mov edi, ebx
    call updates_action_of
    test eax, eax
    jz .out
    push rax
    mov edi, ebx
    ; ECX is declaration index0..3 from updates_action_of.
    lea esi, [rcx+UPD_ARM_FIRST]
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .reject
    cmp byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne .reject
    call sp_arm_holds
    test eax, eax
    jz .reject
    pop rdi
    call updates_queue
    mov eax, 1
    jmp .out
.reject:
    pop rax
.no:
    xor eax, eax
.out:
    pop rbx
    ret

settings_updates_key:
    cmp eax, GUI_KEY_ENTER
    je .press
    cmp eax, ' '
    jne .no
.press:
    cmp byte [rel input_key_origin], KO_HUMAN
    jne .no
    push rdi
    call daily_live_widget
    pop rdi
    test rax, rax
    jz .ordinary
    cmp edi, [rel wgt_focus_id]
    jne .no
    jmp settings_update_daily_capture
.ordinary:
    push rdi
    call updates_action_of
    pop rdi
    test eax, eax
    jz .navigate
    mov edi, eax
    call updates_queue
    mov eax, 1
.out:
    ret
.navigate:
    jmp settings_updates_click           ; same read-only Settings/About links
.no:
    xor eax, eax
    ret

updates_queue:
    push rbx
    mov ebx, edi
    cmp byte [rel session_locked], SESSION_LOCKED
    je .out
    cmp byte [rel cmd_in_dispatch], 0
    jne .out
    cmp byte [rel command_auth_remote_active], 0
    jne .out
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .out
    test rdx, rdx
    jz .out
    mov [rel upd_action_pid], rax
    mov [rel upd_action_token], rdx
    mov eax, [rel upd_slot]
    mov [rel upd_action_slot], eax
    lea rcx, [rel wm_gen]
    mov eax, [rcx+rax*4]
    mov [rel upd_action_gen], eax
    mov [rel upd_action], ebx
    mov byte [rel upd_auto_check], 0
.out:
    pop rbx
    ret

; EDI=0/1, internal trusted backend registration only. No command route.
settings_updates_backend_set:
    mov byte [rel upd_backend], 0
    cmp edi, 1
    jne .invalidate
    mov byte [rel upd_backend], 1
.invalidate:
    mov dword [rel upd_phase], 0
    mov dword [rel upd_action], 0
    mov byte [rel upd_checked_valid], 0
    mov byte [rel upd_attempt_valid], 0
    mov byte [rel upd_auto_enabled], 0 ; unknown persistence never shown enabled
    mov dword [rel upd_status], 7
    ret

; EAX=1 only while exact original owner/session, service and deadline remain.
updates_valid:
    jmp update_request_valid

; Begin only from idle tick; full image I/O remains asynchronous in worker.
updates_begin:
    cmp dword [rel upd_phase], 0
    jne .out
    push rbx
    mov ebx, edi
    cmp ebx, UPD_CHECK
    jb .refused
    cmp ebx, UPD_AUTO_OFF
    ja .refused
    cmp byte [rel session_locked], SESSION_LOCKED
    je .refused
    cmp byte [rel cmd_in_dispatch], 0
    jne .refused
    cmp byte [rel command_auth_remote_active], 0
    jne .refused
    cmp byte [rel upd_backend], 1
    jne .unavailable
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .refused
    test rdx, rdx
    jz .refused
    mov [rel upd_pid], rax
    mov [rel upd_token], rdx
    cmp qword [rel upd_serial], -1
    je .refused                         ; no wrapping request identity
    inc qword [rel upd_serial]
    mov [rel upd_op], ebx
    call boot_ms_now
    mov ecx, 30000
    cmp ebx, UPD_DOWNLOAD
    jne .deadline
    mov ecx, 600000
.deadline:
    add rax, rcx
    jc .refused
    mov [rel upd_deadline], rax
    mov dword [rel upd_phase], 1
    cmp ebx, UPD_CHECK
    jne .status
    ; Original CHECK start, never extended by page reopen or a failed reply.
    sub rax, 30000
    mov [rel upd_attempt_ms], rax
    mov rax, [rel upd_pid]
    mov [rel upd_attempt_pid], rax
    mov rax, [rel upd_token]
    mov [rel upd_attempt_token], rax
    mov byte [rel upd_attempt_valid], 1
    call settings_update_daily_note_attempt
.status:
    mov dword [rel upd_status], 1
    cmp ebx, UPD_DOWNLOAD
    jne .done
    mov dword [rel upd_status], 4
    jmp .done
.unavailable:
    mov dword [rel upd_status], 7
    jmp .done
.refused:
    mov dword [rel upd_status], 6
.done:
    pop rbx
.out:
    ret

settings_updates_take:
    jmp update_request_take

settings_updates_current:
    jmp update_request_current

settings_updates_complete:
    cmp dword [rel upd_phase], 2
    jne .no
    cmp rdi, [rel upd_serial]
    jne .no
    push rsi
    push rdx
    call updates_valid
    pop rdx
    pop rsi
    test eax, eax
    jz .expire
    cmp esi, UPD_REFUSED
    je .refused
    cmp esi, UPD_UNAVAILABLE
    je .unavailable
    mov eax, [rel upd_op]
    cmp eax, UPD_CHECK
    jne .download
    cmp edx, 1
    ja .no
    cmp esi, UPD_CURRENT
    je .current
    cmp esi, UPD_AVAILABLE
    jne .no
    mov [rel upd_auto_enabled], dl
    mov dword [rel upd_status], 3
    jmp .checked
.current:
    mov [rel upd_auto_enabled], dl
    mov dword [rel upd_status], 2
.checked:
    call boot_ms_now
    mov [rel upd_checked_ms], rax
    mov rax, [rel upd_pid]
    mov [rel upd_checked_pid], rax
    mov rax, [rel upd_token]
    mov [rel upd_checked_token], rax
    mov byte [rel upd_checked_valid], 1
    jmp .accepted
.download:
    cmp eax, UPD_DOWNLOAD
    jne .policy
    cmp esi, UPD_STAGED
    jne .no
    mov dword [rel upd_status], 5
    jmp .accepted
.policy:
    cmp eax, UPD_AUTO_ON
    jne .off
    cmp esi, UPD_SAVED_ON
    jne .no
    mov byte [rel upd_auto_enabled], 1
    mov dword [rel upd_status], 0
    jmp .accepted
.off:
    cmp eax, UPD_AUTO_OFF
    jne .no
    cmp esi, UPD_SAVED_OFF
    jne .no
    mov byte [rel upd_auto_enabled], 0
    mov dword [rel upd_status], 0
    jmp .accepted
.refused:
    mov dword [rel upd_status], 6
    jmp .accepted
.unavailable:
    mov dword [rel upd_status], 7
.accepted:
    mov dword [rel upd_phase], 0
    mov eax, 1
    ret
.expire:
    mov dword [rel upd_phase], 0
    mov dword [rel upd_status], 8
.no:
    xor eax, eax
    ret

settings_updates_tick:
    push rbx
    cmp qword [rel upd_token], 0
    je .open
    call session_shell_local_authority
    cmp rax, [rel upd_pid]
    jne .lost_session
    cmp rdx, [rel upd_token]
    jne .lost_session
    cmp byte [rel session_locked], SESSION_LOCKED
    jne .open
.lost_session:
    mov dword [rel upd_phase], 0
    mov dword [rel upd_status], 8
    mov qword [rel upd_token], 0
    mov byte [rel upd_checked_valid], 0
    mov byte [rel upd_attempt_valid], 0
    mov byte [rel upd_auto_enabled], 0
.open:
    call settings_update_daily_tick
    cmp byte [rel upd_open], 0
    je .pending
    mov byte [rel upd_open], 0
    cmp byte [rel session_locked], SESSION_LOCKED
    je .pending
    call sp_disarm
    mov edi, FORM_UPDATES_INDEX
    mov edx, 1
    call form_load_internal
.pending:
    cmp dword [rel upd_phase], 0
    je .action
    call updates_valid
    test eax, eax
    jnz .paint
    mov dword [rel upd_phase], 0
    mov dword [rel upd_status], 8
.action:
    mov ebx, [rel upd_action]
    test ebx, ebx
    jz .paint
    mov dword [rel upd_action], 0
    cmp byte [rel upd_auto_check], 1
    je .local_authority
    call updates_scan
    cmp eax, UPD_W_COUNT
    jne .paint
.local_authority:
    cmp byte [rel session_locked], SESSION_LOCKED
    je .paint
    cmp byte [rel cmd_in_dispatch], 0
    jne .paint
    cmp byte [rel command_auth_remote_active], 0
    jne .paint
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .paint
    test rdx, rdx
    jz .paint
    cmp byte [rel upd_auto_check], 1
    je .authorized
    cmp rax, [rel upd_action_pid]
    jne .paint
    cmp rdx, [rel upd_action_token]
    jne .paint
    mov eax, [rel upd_slot]
    cmp eax, [rel upd_action_slot]
    jne .paint
    lea rcx, [rel wm_gen]
    mov eax, [rcx+rax*4]
    cmp eax, [rel upd_action_gen]
    jne .paint
.authorized:
    mov byte [rel upd_auto_check], 0
    cmp ebx, UPD_RESTART
    je .restart
    cmp ebx, UPD_DOWNLOAD
    jne .begin
    cmp dword [rel upd_status], 3
    jne .paint                         ; no invented available/download state
.begin:
    mov edi, ebx
    call updates_begin
    jmp .paint
.restart:
    cmp dword [rel upd_status], 5
    jne .paint
    ; Always open original guarded restart confirmation, never power_execute.
    call start_programs_open_update_restart
.paint:
    call updates_paint
    pop rbx
    ret

updates_paint:
    call updates_scan
    cmp eax, UPD_W_COUNT
    jne .home
    call settings_updates_status_text
    mov rsi, rax
    mov edi, [rel upd_ids+4]
    call updates_set_text
    lea rsi, [rel upd_auto_off]
    cmp byte [rel upd_auto_enabled], 0
    je .auto
    lea rsi, [rel upd_auto_on]
.auto:
    mov edi, [rel upd_ids+5*4]
    call updates_set_text
    call settings_updates_checked_text
    mov rsi, rax
    mov edi, [rel upd_ids+8*4]
    call updates_set_text
    call settings_update_daily_text
    mov rsi, rax
    mov edi, [rel upd_ids+UPD_DAILY_INDEX*4]
    call updates_set_text
.home:
    mov edi, FORM_SETTINGS_INDEX
    mov esi, UPD_HOME_COUNT
    lea rdx, [rel upd_home_ids]
    call sp_form_widgets_n
    cmp eax, UPD_HOME_COUNT
    jne .out
    call updates_entry_text
    mov rsi, rax
    mov edi, [rel upd_home_ids+10*4]
    call updates_set_text
.out:
    ret

 ; Compare the bounded stock value before repainting on the existing idle tick.
updates_set_text:
    push rdi
    push rsi
    call wgt_slot_ptr
    pop rsi
    pop rdi
    xor ecx, ecx
.compare:
    mov dl, [rsi+rcx]
    cmp dl, [rax+WGI_VAL+rcx]
    jne .changed
    test dl, dl
    jz .out
    inc ecx
    cmp ecx, WGI_VAL_MAX
    jbe .compare
.changed:
    jmp wgt_set_text
.out:
    ret

upd_not_checked: db 'Not checked',0
upd_checked_prefix: db 'Checked '
upd_checked_suffix: db ' min ago',0
upd_checked_old: db 'Checked >999999 min ago',0
upd_entry: db 'Updates: Update now',0
upd_entry_available: db 'Updates [available]: Update now',0
upd_entry_ready: db 'Updates [ready]: Update now',0

; Signed deltas from the loaded table anchor, with no image relocation needed.
upd_texts: dd upd_unknown-upd_texts, upd_checking-upd_texts, upd_current-upd_texts, upd_available-upd_texts, upd_downloading-upd_texts, upd_staged-upd_texts, upd_refused-upd_texts, upd_unavailable-upd_texts, upd_expired-upd_texts
upd_unknown: db 'Updates: open to check',0
upd_checking: db 'Checking for signed updates .',0
upd_checking_alt: db 'Checking for signed updates ..',0
upd_current: db 'PaOS is up to date',0
upd_available: db 'Update available - Download',0
upd_downloading: db 'Downloading signed full image',0
upd_staged: db 'Ready - Restart to apply',0
upd_refused: db 'Update refused - try checking',0
upd_unavailable: db 'Update service unavailable',0
upd_expired: db 'Update interrupted; check again',0
upd_auto_off: db 'Enable auto download/apply',0
upd_auto_on: db 'Disable auto download/apply',0

%macro WDATA_gui_settings_updates 0
align 8, db 0
upd_attempt_ms: dq 0
upd_attempt_pid: dq 0
upd_attempt_token: dq 0
upd_checked_ms: dq 0
upd_checked_pid: dq 0
upd_checked_token: dq 0
upd_action_pid: dq 0
upd_action_token: dq 0
upd_ids: times UPD_W_COUNT dd -1
upd_home_ids: times UPD_HOME_COUNT dd -1
upd_about_ids: times UPD_ABOUT_COUNT dd -1
upd_slot: dd -1
upd_action: dd 0
upd_action_slot: dd -1
upd_action_gen: dd 0
upd_attempt_valid: db 0
upd_checked_valid: db 0
upd_checked_buf: times 32 db 0
upd_auto_check: db 0
upd_auto_enabled: db 0
upd_open: db 0
%endmacro
WDATA_DEFER WDATA_gui_settings_updates

%include "gui/settings_update_daily.asm"
