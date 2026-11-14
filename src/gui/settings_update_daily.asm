;; MODULE gui/settings_update_daily
;; LAYER 6
;; EXPORTS settings_update_daily_tick, settings_update_daily_note_attempt, settings_update_daily_capture, settings_update_daily_text, settings_updates_daily_consent_take, settings_updates_daily_consent_current, settings_updates_daily_consent_finish
;; IMPORTS sec/session, core/time, gui/widget
;; CAPS CAP_GUI
;; OWNER rc-ai-claude
; Private part of the native Updates front door. P alone supplies signed
; UPDAILY.CFG/PUDC persistence, independently current at every DATA effect.
; Define SETTINGS_UPDATE_DAILY_POLICY_BUILT BEFORE this include only with the
; actual P module linked. Without it, every read/save is unavailable (-2),
; never confirmed absence, enabled scheduling or a successful save.
;
; ROOT110520 accepts an older genuine owner choice after reboot or a one-slot
; DATA A->B->A swap. No durable replay floor is claimed. Payload signature,
; rollback/revocation and explicit restart remain unchanged. This module only
; schedules the existing read-only CHECK; it cannot download or restart.

%ifndef GUI_SETTINGS_UPDATE_DAILY_ASM
%define GUI_SETTINGS_UPDATE_DAILY_ASM 1

DAILY_INTERVAL_MS equ 86400000
DAILY_RETRY_MS equ 600000
DAILY_CONSENT_MS equ 30000
UPD_DAILY_INDEX equ 9
UPD_DAILY_ARM equ UPD_ARM_FIRST+4

; Internal ABI is choice only, never a caller grant or a saved-result upload.
daily_policy_read:
%ifdef SETTINGS_UPDATE_DAILY_POLICY_BUILT
    jmp settings_update_daily_policy_read
%else
    mov eax, -2
    ret
%endif
daily_policy_save:
%ifdef SETTINGS_UPDATE_DAILY_POLICY_BUILT
    jmp settings_update_daily_policy_save
%else
    mov eax, -2
    ret
%endif

daily_authority:
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
    ret
.no:
    xor eax, eax
    xor edx, edx
    ret

; EDI exact widget -> RAX native creation lifetime, or0. Both capture and
; per-effect currentness independently scan the genuine form, not copied IDs.
daily_live_widget:
    push rbx
    mov ebx, edi
    call updates_scan
    cmp eax, UPD_W_COUNT
    jne .no
    cmp ebx, [rel upd_ids+UPD_DAILY_INDEX*4]
    jne .no
    mov ecx, [rel upd_slot]
    cmp ecx, [rel wm_focus]
    jne .no
    lea rax, [rel wm_state]
    cmp dword [rax+rcx*4], WM_VISIBLE
    jne .no
    mov edi, ebx
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE], WGT_TYPE_BUTTON
    jne .no
    test dword [rax+WGI_FLAGS], 1
    jz .no
    test dword [rax+WGI_EDIT], WGT_EDIT_DISABLED
    jnz .no
    mov edi, ebx
    call wgt_birth_lifetime
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret

; EDI policy result, RSI/RDX the owner/session from BEFORE the actual read or
; save. A changed session cannot borrow that result for display or scheduling.
; EAX result, or-1 on context loss. Never substitutes for a fresh due read.
daily_cache:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
    call daily_authority
    test rax, rax
    jz .unknown
    cmp rax, r12
    jne .unknown
    cmp rdx, r13
    jne .unknown
    mov [rel daily_policy_owner], rax
    mov [rel daily_policy_session], rdx
    mov [rel daily_policy_state], ebx
    jmp .out
.unknown:
    mov dword [rel daily_policy_state], -1
    mov ebx, -1
.out:
    mov eax, ebx
    pop r13
    pop r12
    pop rbx
    ret

; Called ONLY after the real Updates CHECK start stamps its attempt. This
; includes page/manual attempts, even failed replies; checked-age is separate.
settings_update_daily_note_attempt:
    mov rax, [rel upd_attempt_ms]
    mov [rel daily_last_attempt_ms], rax
    mov byte [rel daily_has_attempt], 1
    cmp rax, [rel daily_clock_high]
    jb .out
    mov [rel daily_clock_high], rax
.out:
    ret

; One existing CHECK after an actual 24h interval. Unknown boot history permits
; one initial eligible attempt. No wall clock, missed-day catchup or reboot
; once-per-calendar-day promise. A lost queued action stamps no fake attempt.
settings_update_daily_tick:
    push rbx
    cmp byte [rel daily_phase], 1
    je .save
    cmp byte [rel daily_phase], 0
    jne .out                         ; P owns any taken consent until finish
    cmp byte [rel upd_backend], 1
    jne .out
    cmp dword [rel upd_phase], 0
    jne .out
    cmp dword [rel upd_action], 0
    jne .out                         ; preserve manual/page work unchanged
    call daily_authority
    test rax, rax
    jz .out
    mov [rel daily_probe_owner], rax
    mov [rel daily_probe_session], rdx
    call boot_ms_now
    cmp rax, [rel daily_clock_high]
    jb .out
    mov [rel daily_clock_high], rax
    mov rbx, rax
    add rax, DAILY_CONSENT_MS
    jc .out                          ; ordinary CHECK deadline cannot overflow
    cmp byte [rel daily_has_attempt], 1
    jne .probe
    mov rax, rbx
    sub rax, [rel daily_last_attempt_ms]
    jc .out
    cmp rax, DAILY_INTERVAL_MS
    jb .out
.probe:
    cmp byte [rel daily_probe_valid], 1
    jne .read
    mov rax, rbx
    sub rax, [rel daily_probe_ms]
    jc .out
    cmp rax, DAILY_RETRY_MS
    jb .out
.read:
    mov [rel daily_probe_ms], rbx
    mov byte [rel daily_probe_valid], 1
    call daily_policy_read
    mov edi, eax
    mov rsi, [rel daily_probe_owner]
    mov rdx, [rel daily_probe_session]
    call daily_cache
    test eax, eax
    jz .queue
    cmp eax, 2                       ; independently confirmed absence only
    jne .out                         ; disabled/refused/busy/uncertain defer
.queue:
    call settings_updates_daily_enqueue
    jmp .out
.save:
    call daily_consent_context
    test eax, eax
    jz .stale
    mov edi, [rel daily_original+8]
    call daily_policy_save           ; P takes/validates/finishes exact consent
    test eax, eax
    js .result
    cmp eax, 1
    ja .stale                        ; read's absent2 is NOT a save success
    cmp byte [rel daily_taken], 1
    jne .stale
    cmp byte [rel daily_finished], 1
    jne .stale
    cmp eax, [rel daily_original+8]
    jne .stale
    mov ebx, eax
    call daily_consent_context
    test eax, eax
    jz .stale
    mov eax, ebx
.result:
    ; Retire this UI gesture after one save attempt, including errors before
    ; take. This never clears P's native issued-uncertainty/custody state.
    mov dword [rel daily_phase], 0
    mov edi, eax
    mov rsi, [rel daily_original+16]
    mov rdx, [rel daily_original+24]
    call daily_cache
    call boot_ms_now
    mov [rel daily_probe_ms], rax
    mov byte [rel daily_probe_valid], 1
    jmp .out                         ; never fall through to background CHECK
.stale:
    mov eax, -3
    jmp .result
.out:
    pop rbx
    ret

; Called only after the existing physical arm or human-key dispatch guards.
; EDI daily widget. The record is private and distinct from CHECK original40.
settings_update_daily_capture:
    push rbx
    push r12
    push r13
    mov ebx, edi
    cmp dword [rel daily_phase], 0
    jne .no
    cmp qword [rel daily_generation], -1
    je .no
    ; Retain the gesture's interval BEFORE any potentially delayed P read.
    ; Returning from I/O cannot renew consent or hide a clock regression.
    call boot_ms_now
    cmp rax, [rel daily_clock_high]
    jb .no
    mov [rel daily_started_ms], rax
    mov [rel daily_seen_ms], rax
    mov [rel daily_clock_high], rax
    add rax, DAILY_CONSENT_MS
    jc .no
    mov [rel daily_original+32], rax
    call daily_live_widget
    test rax, rax
    jz .no
    mov r13, rax
    mov eax, [rel upd_slot]
    mov [rel daily_window], eax
    lea rdx, [rel wm_gen]
    mov eax, [rdx+rax*4]
    mov [rel daily_window_gen], eax
    call daily_authority
    test rax, rax
    jz .no
    mov [rel daily_original+16], rax
    mov [rel daily_original+24], rdx
    call daily_policy_read
    mov edi, eax
    mov rsi, [rel daily_original+16]
    mov rdx, [rel daily_original+24]
    call daily_cache
    mov r12d, 1                      ; currently enabled/default -> disable
    test eax, eax
    jz .choice
    cmp eax, 2
    je .choice
    cmp eax, 1
    jne .no
    xor r12d, r12d                   ; currently disabled -> explicit enable
.choice:
    call daily_authority
    test rax, rax
    jz .no
    cmp rax, [rel daily_original+16]
    jne .no
    cmp rdx, [rel daily_original+24]
    jne .no
    mov edi, ebx
    call daily_live_widget
    cmp rax, r13
    jne .no
    mov [rel daily_widget_birth], rax
    mov [rel daily_widget], ebx
    mov eax, [rel upd_slot]
    cmp eax, [rel daily_window]
    jne .no
    lea rdx, [rel wm_gen]
    mov eax, [rdx+rax*4]
    cmp eax, [rel daily_window_gen]
    jne .no
    call boot_ms_now
    cmp rax, [rel daily_started_ms]
    jb .no
    cmp rax, [rel daily_clock_high]
    jb .no
    cmp rax, [rel daily_original+32]
    jae .no
    mov [rel daily_seen_ms], rax
    mov [rel daily_clock_high], rax
    inc qword [rel daily_generation]
    mov rax, [rel daily_generation]
    mov [rel daily_original], rax
    mov [rel daily_original+8], r12d
    mov dword [rel daily_original+12], 1
    mov byte [rel daily_taken], 0
    mov byte [rel daily_finished], 0
    mov byte [rel daily_invalid], 0
    mov dword [rel daily_phase], 1
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Per-effect native currentness, without a copied-byte grant. A context failure
; latches invalid until retirement; lock/expiry/clock regression cannot revive.
daily_consent_context:
    push rbx
    cmp byte [rel daily_invalid], 0
    jne .no
    call daily_authority
    test rax, rax
    jz .no
    cmp rax, [rel daily_original+16]
    jne .no
    cmp rdx, [rel daily_original+24]
    jne .no
    mov edi, [rel daily_widget]
    call daily_live_widget
    test rax, rax
    jz .no
    cmp rax, [rel daily_widget_birth]
    jne .no
    mov eax, [rel upd_slot]
    cmp eax, [rel daily_window]
    jne .no
    lea rdx, [rel wm_gen]
    mov eax, [rdx+rax*4]
    cmp eax, [rel daily_window_gen]
    jne .no
    call boot_ms_now
    cmp rax, [rel daily_seen_ms]
    jb .no
    cmp rax, [rel daily_clock_high]
    jb .no
    cmp rax, [rel daily_original+32]
    jae .no
    mov [rel daily_seen_ms], rax
    mov [rel daily_clock_high], rax
    mov eax, 1
    pop rbx
    ret
.no:
    mov byte [rel daily_invalid], 1
    xor eax, eax
    pop rbx
    ret

; RDI native private writable40. Refuse overlap with retained original; no
; untrusted/public pointer API exists. Exact bytes alone never authorize P.
settings_updates_daily_consent_take:
    push rbx
    mov rbx, rdi
    test rdi, rdi
    jz .no
    lea rax, [rdi+40]
    cmp rax, rdi
    jb .no
    lea rdx, [rel daily_original]
    cmp rax, rdx
    jbe .pointer_ok
    add rdx, 40
    cmp rdi, rdx
    jb .no
.pointer_ok:
    cmp dword [rel daily_phase], 1
    jne .no
    call daily_consent_context
    test eax, eax
    jz .no
    lea rsi, [rel daily_original]
    mov rdi, rbx
    mov ecx, 5
    rep movsq
    mov dword [rel daily_phase], 2
    mov byte [rel daily_taken], 1
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret

daily_original_matches:
    test rdi, rdi
    jz .no
    lea rsi, [rel daily_original]
    mov ecx, 5
    repe cmpsq
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

settings_updates_daily_consent_current:
    cmp dword [rel daily_phase], 2
    jne .no
    call daily_original_matches
    test eax, eax
    jz .no
    jmp daily_consent_context
.no:
    xor eax, eax
    ret

; Retirement deliberately does NOT require still-current authority/time/window.
; It grants no effect and cannot consume a different generation or untaken job.
settings_updates_daily_consent_finish:
    cmp dword [rel daily_phase], 2
    jne .no
    call daily_original_matches
    test eax, eax
    jz .no
    mov dword [rel daily_phase], 0
    mov byte [rel daily_finished], 1
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

settings_update_daily_text:
    sub rsp, 8
    call daily_authority
    add rsp, 8
    test rax, rax
    jz .unknown
    cmp rax, [rel daily_policy_owner]
    jne .unknown
    cmp rdx, [rel daily_policy_session]
    jne .unknown
    cmp dword [rel daily_policy_state], 1
    je .disabled
    cmp dword [rel daily_policy_state], 0
    je .enabled
    cmp dword [rel daily_policy_state], 2
    jne .unknown
.enabled:
    lea rax, [rel daily_enabled_text]
    ret
.disabled:
    lea rax, [rel daily_disabled_text]
    ret
.unknown:
    lea rax, [rel daily_unknown_text]
    ret

daily_enabled_text: db 'Disable daily update checks',0
daily_disabled_text: db 'Enable daily update checks',0
daily_unknown_text: db 'Daily check unavailable',0

%macro WDATA_gui_settings_update_daily 0
align 8, db 0
daily_original: times 5 dq 0
daily_generation: dq 0
daily_started_ms: dq 0
daily_seen_ms: dq 0
daily_clock_high: dq 0
daily_last_attempt_ms: dq 0
daily_probe_ms: dq 0
daily_probe_owner: dq 0
daily_probe_session: dq 0
daily_widget_birth: dq 0
daily_policy_owner: dq 0
daily_policy_session: dq 0
daily_window: dd -1
daily_window_gen: dd 0
daily_widget: dd -1
daily_policy_state: dd -1
daily_phase: dd 0
daily_has_attempt: db 0
daily_probe_valid: db 0
daily_invalid: db 0
daily_taken: db 0
daily_finished: db 0
%endmacro
WDATA_DEFER WDATA_gui_settings_update_daily
%endif
