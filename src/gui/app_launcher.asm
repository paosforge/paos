;; MODULE gui/app_launcher
;; LAYER 6
;; PURPOSE Checked bundle desktop entry and app-owned native form projection.
;; EXPORTS app_launcher_ended, app_launcher_stopped, app_launcher_init, app_launcher_configure, app_launcher_publish, app_launcher_clear, app_launcher_form, app_launcher_tick, app_launcher_status, app_launcher_complete, app_launcher_chat_target, app_launcher_form_staged, app_launcher_failed, app_launcher_timings
;; IMPORTS cognition/ai_intent_controller, svc/app_script, svc/command, sec/session, gui/widget, gui/window_mgmt, gui/form_loader, gui/wm_pointer, boot/gop, core/time
;; OWNER saga:app_launcher
; This is checked native data/UI, never a guest executor or binding validator.
; Actual isolated VM lifecycle/resolver composition installs the native callback.
; NULL by default: a click cannot launch through the driver guest/root PIO.
AL_DESC equ 384
AL_INDEX_MAX equ 1280
AL_FORM_MAX equ 1535
AL_IDLE equ 0
AL_QUEUED equ 1
AL_NO_EXECUTOR equ 2
AL_REFUSED equ 3
AL_STARTED equ 4
AL_STARTING equ 5
AL_STOPPED equ 6

app_launcher_init:
    cmp byte [rel al_initialized], 0
    jne .out
    mov rax, [rel wgt_click_hook]
    mov [rel al_click_prev], rax
    lea rax, [rel al_click]
    mov [rel wgt_click_hook], rax
    mov byte [rel al_initialized], 1
.out:
    ret

; Native lifecycle composition only, depth0. Does not assert VM proof, configure
; grants, dispatch a verb, or expose a guest setter. Callback(handle,attempt)
; ->1 only after actual activation, 2 pending, otherwise refusal. Completion is
; native-only, exact attempt, and never a guest-supplied success indication.
app_launcher_configure:
    cmp byte [rel cmd_in_dispatch], 0
    jne al_bad
    mov qword [rel al_active_attempt], 0
    mov qword [rel al_chat_attempt],0
    mov [rel al_launch], rdi
    mov qword [rel al_pending], 0
    mov dword [rel al_status], AL_IDLE
    mov qword [rel al_lifecycle_attempt],0
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    mov eax, 1
    ret

; Publish one current verified signed snapshot as a stock desktop button.
; RDI=opaque native app_script handle. No launch or effective grant occurs.
; One checked form is supported by the existing one-ephemeral-form loader.
; Multi-form/oversize forms refuse, never truncate or silently omit a form.
app_launcher_publish:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp qword [rel al_handle], 0
    jne .bad
    cmp byte [rel al_initialized], 1
    jne .bad
    call session_shell_require_unlocked
    test eax, eax
    jnz .bad
    test r12, r12
    jz .bad
    mov rdi, r12
    lea rsi, [rel al_scratch]
    mov edx, AL_DESC
    call app_script_descriptor
    cmp eax, 1
    jne .bad
    cmp qword [rel al_scratch], 1
    jne .bad
    cmp [rel al_scratch+8], r12
    jne .bad
    cmp qword [rel al_scratch+24], 2
    jb .bad
    cmp qword [rel al_scratch+24], 16
    ja .bad
    cmp qword [rel al_scratch+336], 320
    jne .bad
    mov rax, [rel al_scratch+24]
    imul rax, 80
    cmp [rel al_scratch+344], rax
    jne .bad
    add rax, 320
    cmp [rel al_scratch+352], rax
    jne .bad
    cmp qword [rel al_scratch+368], 1
    jne .bad
    cmp qword [rel al_scratch+376], 0
    jne .bad
    mov rdi, r12
    mov esi, 320
    lea rdx, [rel al_index]
    mov rcx, [rel al_scratch+344]
    call app_script_copy
    cmp eax, 1
    jne .bad
    xor ebx, ebx
    xor r13d, r13d                     ; exact form count
    xor r14d, r14d                     ; selected asset-relative offset
    xor r15d, r15d                     ; exact form byte length
.scan:
    mov eax, ebx
    imul eax, 80
    lea rdx, [rel al_index]
    add rdx, rax
    cmp dword [rdx], 2
    jne .next
    inc r13d
    cmp r13d, 1
    jne .bad
    mov r14d, [rdx+4]
    mov r15d, [rdx+8]
    test r15d, r15d
    jz .bad
    cmp r15d, AL_FORM_MAX
    ja .bad
.next:
    inc ebx
    cmp rbx, [rel al_scratch+24]
    jb .scan
    cmp r13d, 1
    jne .bad
    mov rsi, [rel al_scratch+352]
    add rsi, r14
    jc .bad
    mov rdi, r12
    lea rdx, [rel al_form]
    mov rcx, r15
    call app_script_copy
    cmp eax, 1
    jne .bad
    ; Extract only the stable declaration name; actual loader owns syntax lint.
    ; Never pass a stale index pointer as form_lint_blob's expected-name input.
    call al_form_name_copy
    cmp eax, 1
    jne .bad
    lea rdi, [rel al_form]
    mov rsi, r15
    lea rdx, [rel al_form_name]
    call form_lint_blob
    test eax, eax
    jnz .bad
    ; Copy bounded checked bundle id. Descriptor is verified native data, but
    ; never permit an unterminated id to escape into widget text/title storage.
    lea rsi, [rel al_scratch+96]        ; manifest80 + bundle-id16
    lea rdi, [rel al_name]
    mov ecx, 64
.name:
    lodsb
    stosb
    test al, al
    jz .name_done
    loop .name
    jmp .bad
.name_done:
    cmp byte [rel al_name], 0
    je .bad
    ; Re-read after lint before publishing: handle/trust/session must still be
    ; current and the whole immutable descriptor must be exactly unchanged.
    mov rdi, r12
    lea rsi, [rel al_current]
    mov edx, AL_DESC
    call app_script_descriptor
    cmp eax, 1
    jne .bad
    lea rdi, [rel al_scratch]
    lea rsi, [rel al_current]
    mov ecx, AL_DESC/8
    repe cmpsq
    jne .bad
    cmp dword [rel fb_width], 160
    jb .bad
    cmp dword [rel fb_height], 120
    jb .bad
    mov edi, 1
    call wgt_reserve_run
    cmp eax, -1
    je .bad
    mov [rel wgt_alloc_next], eax
    xor edi, edi                       ; maintained button type 0
    xor esi, esi                       ; create using real WM slot0 geometry
    call wgt_create
    mov dword [rel wgt_alloc_next], -1
    cmp eax, -1
    je .bad
    mov ebx, eax
    mov edi, eax
    call wgt_slot_ptr
    mov dword [rax+WGI_WIN], WGT_HOST_DESKTOP
    mov dword [rax+WGI_LAYER], 0
    mov dword [rax+WGI_FLAGS], 1
    mov dword [rax+WGI_EDIT], 0
    mov dword [rax+WGI_X], 16
    mov dword [rax+WGI_Y], 16
    mov dword [rax+WGI_W], 128
    mov dword [rax+WGI_H], 40
    lea rdx, [rel al_widget_id]
    mov [rax+WGI_ID], rdx
    lea rdx, [rel al_role]
    mov [rax+WGI_ROLE], rdx
    lea rdx, [rel al_name]
    mov [rax+WGI_LABEL], rdx
    mov edi, ebx
    lea rsi, [rel al_name]
    call wgt_set_text
    mov [rel al_widget], ebx
    mov [rel al_form_len], r15
    lea rsi, [rel al_scratch]
    lea rdi, [rel al_descriptor]
    mov ecx, AL_DESC/8
    rep movsq
    mov [rel al_handle], r12            ; commit only after all checked data/UI
    mov dword [rel al_status], AL_IDLE
    mov qword [rel al_lifecycle_attempt],0
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    call wmx_draw_all
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Bounded metadata extraction from copied form bytes. This recognizes only
; the first declaration name; form_lint_blob remains the complete grammar gate.
; R15=exact byte length, output private64B name. No caller pointers escape.
al_form_name_copy:
    cmp r15, 8
    jb al_bad
    cmp dword [rel al_form], 'form'
    jne al_bad
    cmp byte [rel al_form+4], ' '
    jne al_bad
    mov ecx, 5
    xor edx, edx
    lea rsi, [rel al_form]
    lea rdi, [rel al_form_name]
.loop:
    cmp rcx, r15
    jae al_bad
    movzx eax, byte [rsi+rcx]
    cmp al, ' '
    je .end
    cmp al, '!'
    jb al_bad
    cmp al, '~'
    ja al_bad
    cmp edx, 63
    jae al_bad
    mov [rdi+rdx], al
    inc edx
    inc ecx
    jmp .loop
.end:
    test edx, edx
    jz al_bad
    mov byte [rdi+rdx], 0
    mov eax, 1
    ret

; No authority return: exact currently trusted snapshot equality only.
al_current_snapshot:
    mov rdi, [rel al_handle]
    test rdi, rdi
    jz al_bad
    lea rsi, [rel al_current]
    mov edx, AL_DESC
    call app_script_descriptor
    cmp eax, 1
    jne al_bad
    lea rdi, [rel al_descriptor]
    lea rsi, [rel al_current]
    mov ecx, AL_DESC/8
    repe cmpsq
    jne al_bad
    mov eax, 1
    ret

; Original native launcher owns VM retirement and form close before uninstall.
; Clearing this UI entry alone does not report or simulate execution teardown.
app_launcher_clear:
    cmp byte [rel cmd_in_dispatch], 0
    jne al_bad
    cmp byte [rel al_form_created], 0
    je .no_live_form
    call form_ephemeral_busy
    test eax, eax
    jnz al_bad                         ; storage still backs a live form
.no_live_form:
    mov byte [rel al_form_created], 0
    mov qword [rel al_active_attempt], 0
    mov qword [rel al_chat_attempt],0
    mov qword [rel al_handle], 0
    mov qword [rel al_pending], 0
    mov qword [rel al_form_len], 0
    mov dword [rel al_status], AL_IDLE
    mov qword [rel al_lifecycle_attempt],0
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    mov edi, [rel al_widget]
    mov dword [rel al_widget], -1
    cmp edi, [rel wgt_count]
    jae .done
    call wgt_slot_ptr
    lea rdx, [rel al_widget_id]
    cmp [rax+WGI_ID], rdx
    jne .done                          ; never retire a reused widget
    cmp dword [rax+WGI_WIN], WGT_HOST_DESKTOP
    jne .done
    mov dword [rax+WGI_FLAGS], 0
    mov dword [rax+WGI_TYPE], 0
.done:
    mov eax, 1
    ret

; Native real-VM composition invokes only after it has an enforced principal.
; RDI=exact handle, RSI=actual principal; returns original loader EAX/ECX/EDX.
; No invented VM binding, grants or script execution is performed here.
app_launcher_form_staged:
    mov r8d,1
    jmp al_form_entry
app_launcher_form:
    xor r8d,r8d
al_form_entry:
    push r12
    mov r12d,r8d
    push rbx
    mov rbx, rsi
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp rdi, [rel al_handle]
    jne .bad
    call al_current_snapshot
    cmp eax, 1
    jne .bad
    lea rdi, [rel al_form]
    mov rsi, [rel al_form_len]
    lea rdx, [rel al_form_name]
    mov rcx, rbx
    test r12d,r12d
    jz .ordinary
    call form_load_app_staged_blob
    jmp .loaded
.ordinary:
    call form_load_app_blob
.loaded:
    test eax, eax
    jnz .returned
    mov byte [rel al_form_created], 1
.returned:
    pop rbx
    pop r12
    ret
.bad:
    mov eax, 1
    pop rbx
    pop r12
    ret

al_click:
    cmp edi, [rel al_widget]
    jne .chain
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .done
    cmp byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne .done                           ; an injected press with a human release
    cmp edi, [rel wgt_count]
    jae .done
    call wgt_slot_ptr
    lea rdx, [rel al_widget_id]
    cmp [rax+WGI_ID], rdx
    jne .done
    cmp dword [rax+WGI_WIN], WGT_HOST_DESKTOP
    jne .done
    cmp dword [rax+WGI_TYPE], 1          ; exact maintained button type
    jne .done
    test dword [rax+WGI_FLAGS], 1
    jz .done
    call session_shell_require_unlocked
    test eax, eax
    jnz .done
    mov rax, [rel al_handle]
    test rax, rax
    jz .done
    cmp qword [rel al_active_attempt], 0
    jne .done
    cmp qword [rel al_pending],0
    jne .done                          ; first queued intent/timestamp wins
    cmp dword [rel al_status],AL_STARTED
    je .done                           ; preserve the running instance/target
    mov [rel al_pending], rax           ; no dispatch/VM effect inside input
    mov dword [rel al_status], AL_QUEUED
    call al_queued_feedback
.done:
    mov eax, 1
    ret
.chain:
    mov rax, [rel al_click_prev]
    test rax, rax
    jz .none
    jmp rax
.none:
    xor eax, eax
    ret

app_launcher_tick:
    cmp byte [rel cmd_in_dispatch], 0
    jne .out
    ; Peter87189: the existing sole consumer projects one fresh Win+Space TAP.
    ; Spend it even if no designated chat bundle is installed; never remember
    ; a press for a later install, replay persistent intent, or launch any other
    ; current bundle. The original owner-policy/VM callback still owns launch.
    call cog_ai_intent_take_tap
    cmp eax,2                          ; Copilot/voice gestures stay deferred
    jne .pending
    cmp byte [rel al_initialized],1
    jne .pending
    cmp qword [rel al_active_attempt],0
    jne .pending
    cmp dword [rel al_status],AL_STARTED
    je .pending                        ; another press cannot rebind a live chat
    cmp qword [rel al_pending],0
    jne .pending                       ; retain an already queued pointer intent
    cmp dword [rel al_name],0x736f6170  ; exact canonical "paos.chat", NUL included
    jne .pending
    cmp dword [rel al_name+4],0x6168632e
    jne .pending
    cmp word [rel al_name+8],0x0074
    jne .pending
    mov rax,[rel al_handle]
    test rax,rax
    jz .pending
    mov [rel al_pending],rax
    mov dword [rel al_status],AL_QUEUED
    call al_queued_feedback
.pending:
    cmp qword [rel al_pending], 0
    je .out
    mov rax, [rel al_pending]
    mov qword [rel al_pending], 0        ; spend input intent before callback
    cmp rax, [rel al_handle]
    jne .refused
    call session_shell_require_unlocked
    test eax, eax
    jnz .refused
    call al_current_snapshot
    cmp eax, 1
    jne .refused
    mov rax, [rel al_launch]
    test rax, rax
    jz .missing
    cmp qword [rel al_attempt_serial], -1
    je .refused
    inc qword [rel al_attempt_serial]
    mov rsi, [rel al_attempt_serial]
    mov [rel al_active_attempt], rsi
    mov [rel al_lifecycle_attempt],rsi
    mov dword [rel al_status], AL_STARTING
    call al_chat_capture_target        ; before the native policy panel changes focus
    mov rax,[rel al_launch]
    mov rdi, [rel al_handle]
    mov rsi,[rel al_active_attempt]
    call rax                           ; actual owned lifecycle, no fallback
    cmp eax, 2
    je .out                            ; pending is never reported STARTED
    mov edx, eax
    mov rdi, [rel al_handle]
    mov rsi, [rel al_active_attempt]
    jmp app_launcher_complete
.out:
    ret
.missing:
    mov dword [rel al_status], AL_NO_EXECUTOR
    jmp al_feedback
.refused:
    mov dword [rel al_status], AL_REFUSED
    jmp al_feedback

; Exact nonreused attempt; invalidate before accepting a terminal native result.
; RDI handle, RSI attempt, EDX=1 actual activated, otherwise refusal ->1/0.
; This is not a command/guest setter. Original lifecycle owns cleanup.
app_launcher_complete:
    cmp byte [rel cmd_in_dispatch], 0
    jne al_bad
    test rsi, rsi
    jz al_bad
    cmp rsi, [rel al_active_attempt]
    jne al_bad
    cmp rdi, [rel al_handle]
    jne al_bad
    mov qword [rel al_active_attempt], 0
    mov dword [rel al_status], AL_REFUSED
    cmp edx, 1
    je .started
    mov qword [rel al_chat_attempt],0
    jmp .done
.started:
    mov dword [rel al_status], AL_STARTED
.done:
    call al_feedback
    mov eax, 1
    ret

; Capture the active target's native identity before opening the policy/chat
; window. No widget/text read or grant. No active window means no target; never
; reinterpret a missing/reused target as desktop or whatever later has focus.
al_chat_capture_target:
    mov qword [rel al_chat_attempt],0
    cmp dword [rel al_name],0x736f6170
    jne .out
    cmp dword [rel al_name+4],0x6168632e
    jne .out
    cmp word [rel al_name+8],0x0074
    jne .out
    mov edi,[rel wm_focus]
    cmp edi,WM_MAX
    jae .out
    lea rax,[rel wm_state]
    cmp dword [rax+rdi*4],WM_VISIBLE
    jne .out
    call wmx_window_id
    test eax,eax
    jz .out
    mov [rel al_chat_target_id],eax
    lea rax,[rel wm_gen]
    mov eax,[rax+rdi*4]
    mov [rel al_chat_target_gen],eax
    lea rax,[rel wm_owner]
    mov rax,[rax+rdi*8]
    mov [rel al_chat_target_owner],rax
    mov rax,[rel al_active_attempt]
    mov [rel al_chat_attempt],rax
.out:
    ret

; Native-only target observation, not gui.read or a guest endpoint.
; RDI exact published handle, RSI exact original launch attempt, RDX trusted
; mapped disjoint out32 ->1/0, refusal leaves output untouched. Four qwords:
; version1, captured window id, full raw generation, full owner principal.
; Revalidate snapshot/session and original window lifetime; later focus never
; substitutes the chat window. The future scoped adapter must independently
; resolve the app principal, gui.read, privacy and invocation/START lifetime.
app_launcher_chat_target:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rdx,rdx
    jz al_bad
    mov rax,rdx
    add rax,32
    jc al_bad
    test rsi,rsi
    jz al_bad
    cmp rsi,[rel al_chat_attempt]
    jne al_bad
    cmp rdi,[rel al_handle]
    jne al_bad
    push r12
    mov r12,rdx
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    call al_current_snapshot
    cmp eax,1
    jne .bad
    mov edi,[rel al_chat_target_id]
    movzx edi,dil
    call wmx_window_id
    cmp eax,[rel al_chat_target_id]
    jne .bad
    lea rax,[rel wm_gen]
    mov ecx,[rax+rdi*4]
    cmp ecx,[rel al_chat_target_gen]
    jne .bad
    lea rax,[rel wm_owner]
    mov rdx,[rax+rdi*8]
    cmp rdx,[rel al_chat_target_owner]
    jne .bad
    mov qword [r12],1
    mov eax,[rel al_chat_target_id]
    mov [r12+8],rax
    mov [r12+16],rcx
    mov [r12+24],rdx
    mov eax,1
    pop r12
    ret
.bad:
    xor eax,eax
    pop r12
    ret

; Original lifecycle may report a later VM fault after activation. Native only,
; exact attempt/handle; never repaint another published/reused widget.
app_launcher_failed:
    mov edx,AL_REFUSED
    jmp al_attempt_end

; The app had shown, then its VM stopped on its own.
app_launcher_stopped:
    mov edx,AL_STOPPED
    jmp al_attempt_end

; Exact attempt ended without failure: the shown app was closed or its session
; or bundle changed, or the human declined. The button returns to its name and can launch.
app_launcher_ended:
    mov edx,AL_IDLE
al_attempt_end:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rsi,rsi
    jz al_bad
    cmp rdi,[rel al_handle]
    jne al_bad
    cmp rsi,[rel al_lifecycle_attempt]
    jne al_bad
    mov qword [rel al_active_attempt],0
    mov qword [rel al_chat_attempt],0
    mov [rel al_status],edx
    call al_feedback
    mov eax,1
    ret

al_queued_feedback:
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    cmp qword [rel tsc_khz],0
    je .paint
    call time_monotonic_now_us
    mov [rel al_request_us],rax
.paint:
    call al_feedback
    cmp qword [rel tsc_khz],0
    je .out
    call time_monotonic_now_us
    mov [rel al_feedback_us],rax         ; after actual text/paint request
.out:
    ret

; Pure UI, never a VM/grant effect. Called synchronously at queue acceptance.
al_feedback:
    push rbx
    lea rbx,[rel al_launching]
    mov eax,[rel al_status]
    cmp eax,AL_QUEUED
    je .paint
    cmp eax,AL_STARTING
    je .paint
    lea rbx,[rel al_running]
    cmp eax,AL_STARTED
    je .paint
    lea rbx,[rel al_name]
    cmp eax,AL_IDLE
    je .paint
    lea rbx,[rel al_stopped]
    cmp eax,AL_STOPPED
    je .paint
    lea rbx,[rel al_failed]
.paint:
    mov edi,[rel al_widget]
    cmp edi,[rel wgt_count]
    jae .out
    call wgt_slot_ptr
    lea rdx,[rel al_widget_id]
    cmp [rax+WGI_ID],rdx
    jne .out
    cmp dword [rax+WGI_WIN],WGT_HOST_DESKTOP
    jne .out
    cmp dword [rax+WGI_TYPE],1
    jne .out
    test dword [rax+WGI_FLAGS],1
    jz .out
    mov edi,[rel al_widget]
    mov rsi,rbx
    call wgt_set_text
    call wmx_draw_all
.out:
    pop rbx
    ret

; Native trusted mapped disjoint out32. Monotonic request/feedback times are
; observations, not a 100ms claim; REL measures actual QEMU/metal latency.
app_launcher_timings:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rdi,rdi
    jz al_bad
    cmp esi,32
    jne al_bad
    mov qword [rdi],1
    mov rax,[rel al_lifecycle_attempt]
    mov [rdi+8],rax
    mov rax,[rel al_request_us]
    mov [rdi+16],rax
    mov rax,[rel al_feedback_us]
    mov [rdi+24],rax
    mov eax,1
    ret

app_launcher_status:
    mov eax, [rel al_status]
    ret
al_bad:
    xor eax, eax
    ret

; Native constants share the image section; mutable state uses original WDATA.
al_widget_id: db 'app_launcher_entry',0
al_role: db 'button',0
al_launching: db 'Launching...',0
al_running: db 'Running',0
al_failed: db 'Launch failed',0
al_stopped: db 'App stopped',0
%macro WDATA_gui_app_launcher_0 0
al_initialized: db 0
al_form_created: db 0
al_widget: dd -1
al_status: dd AL_IDLE
al_launch: dq 0
al_click_prev: dq 0
al_pending: dq 0
al_attempt_serial: dq 0
al_active_attempt: dq 0
al_lifecycle_attempt: dq 0
al_request_us: dq 0
al_feedback_us: dq 0
al_handle: dq 0
al_form_len: dq 0
al_chat_attempt: dq 0
al_chat_target_id: dd 0
al_chat_target_gen: dd 0
al_chat_target_owner: dq 0
%endmacro
WDATA_DEFER WDATA_gui_app_launcher_0
%macro WDATA_BSS_gui_app_launcher 0
al_descriptor: resb AL_DESC
al_scratch: resb AL_DESC
al_current: resb AL_DESC
al_index: resb AL_INDEX_MAX
al_form: resb AL_FORM_MAX+1
al_name: resb 64
al_form_name: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_launcher
