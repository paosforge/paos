;; MODULE gui/app_launch_flow
;; LAYER 6
;; PURPOSE Native owner policy and bounded isolated-app launch composition.
;; EXPORTS app_launch_flow_click_observe, app_launch_flow_init, app_launch_flow_tick, app_launch_flow_begin, app_launch_flow_available, app_launch_flow_observe, app_launch_flow_quiesce
;; IMPORTS gui/form_loader, gui/calendar, gui/chat_send, gui/form_events, gui/app_launcher, sec/app_binding, sec/session, svc/app_script, hv/app_vm, gui/widget, gui/window_mgmt, gui/wm_pointer, svc/command, core/time, core/smp, hv/vmx, hv/app_vm_memory, boot/gop
;; OWNER saga:app_launch_flow
;; CONTEXT: bsp_only
; Native-only. One original VM lifecycle, no guest command/setter/executor.
AF_IDLE equ 0
AF_POLICY equ 1
AF_PREPARING equ 2
AF_RUNNING equ 3
AF_RETIRING equ 4
AF_WIDTH equ 560
AF_HEIGHT equ 370
AF_TOP equ 64                       ; actual desktop entry ends at y=56
AF_WIDGETS equ 13
AF_UI_BOUND_US equ 30000000
AF_DWELL_US equ 400000
AF_POLICY_US equ 300000000
AF_FALLBACK_US equ 400000

; Called once after WAIT registration and launcher init. Missing WAIT refuses.
; Real producer include/init is wired only with the actual app VM implementation.
app_launch_flow_init:
    cmp byte [rel af_initialized],0
    jne .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    xor ecx,ecx
    lea rdx,[rel verb_table]
.find:
    cmp ecx,[rel verb_count]
    jae .out
    cmp ecx,VERB_MAX
    jae .out
    mov rax,[rdx+VERB_NAME]
    test rax,rax
    jz .next
    cmp dword [rax],0x54494157         ; exact "WAIT\0", maintained registration
    jne .next
    cmp byte [rax+4],0
    jne .next
    cmp qword [rdx+VERB_HANDLER],0
    je .out
    cmp qword [rdx+VERB_DESTR],0
    jne .out
    mov edi,ecx
    call app_binding_configure
    cmp eax,1
    jne .out
    call app_binding_snapshot_configure
    cmp eax,1
    sete byte [rel af_gui_configured]
    mov rax,[rel wgt_click_hook]
    mov [rel af_click_prev],rax
    lea rax,[rel af_click]
    mov [rel wgt_click_hook],rax
    lea rdi,[rel app_launch_flow_begin]
    call app_launcher_configure
    cmp eax,1
    jne .out
    call chat_send_init
    mov byte [rel af_initialized],1
.out:
    ret
.next:
    add rdx,VERB_ENT_SZ
    inc ecx
    jmp .find

; Read-only native admission for owner ingress. No policy/execution effect.
app_launch_flow_available:
    cmp byte [rel af_initialized],1
    jne .bad
    cmp dword [rel af_state],AF_IDLE
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Callback(handle, nonreused launch attempt) ->2 pending /0 refused.
; Actual activation is reported later, never implied by UI or prepare acceptance.
app_launch_flow_begin:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    cmp byte [rel af_initialized],1
    jne .bad
    cmp dword [rel af_state],AF_IDLE
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    test rbx,rbx
    jz .bad
    test r12,r12
    jz .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    mov [rel af_epoch],rdx
    mov rdi,rbx
    mov rsi,r12
    call app_launcher_terminal_current
    cmp eax,1
    jne .bad
    mov rax,[rel session_key_handle]
    mov [rel af_key],rax
    mov rdi,rbx
    lea rsi,[rel af_descriptor]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .bad
    call af_notice_close
    mov [rel af_handle],rbx
    mov [rel af_attempt],r12
    mov [rel af_observe_attempt],r12
    mov byte [rel af_notice_attempted],0
    mov byte [rel af_gui_policy],0
    mov byte [rel af_gui_available],0
    lea rdi,[rel af_gui_target]
    xor eax,eax
    mov ecx,4
    rep stosq
    cmp byte [rel af_gui_configured],1
    jne .no_gui
    mov rdi,rbx
    mov rsi,r12
    lea rdx,[rel af_gui_target]
    call app_launcher_chat_target     ; original capture, before this panel
    cmp eax,1
    sete byte [rel af_gui_available]
.no_gui:
    mov dword [rel af_policy],0         ; all four default DENY, no manifest policy
    mov qword [rel af_instance],0
    mov dword [rel af_form_slot],-1
    mov byte [rel af_answer],0
    call af_start_clock_clear
    lea rdi,[rel af_times]
    xor eax,eax
    mov ecx,6
    rep stosq
    call af_new_deadline
    cmp eax,1
    jne .bad
    call af_build
    cmp eax,1
    jne .bad_close
    call time_monotonic_now_us
    mov [rel af_panel_shown_us],rax
    mov dword [rel af_state],AF_POLICY
    mov eax,2
    jmp .out
.bad_close:
    call af_panel_close
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Native REMOVE: RDI mapped/disjoint bundle SHA256[32], RSI current owner epoch.
; 1 exact UI and VM confirmed retired/absent,2 pending,0 refused. INPUT owns
; prior durable REMOVING denial and physical confirmation, FS owns bytes and
; INPUT owns grants. This leaf never reports durable removal success. Poll
; from the ordinary depth-zero native turn; no spin or hidden VM tick here.
; Pending digest/session/entry/flow identity is immutable. Terminal1 ends it;
; the caller stops polling and needs a fresh confirmed REMOVING for a new call.
app_launch_flow_quiesce:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    xor r13d, r13d
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp byte [rel af_remove_busy], 0
    jne .bad
    call smp_current_logical
    test eax, eax
    jnz .bad
    test rbx, rbx
    jz .bad
    mov rax, rbx
    add rax, 32
    jc .bad
    mov rcx, rbx
    shl rcx, 16
    sar rcx, 16
    cmp rcx, rbx
    jne .bad
    lea rdx, [rax-1]
    mov rcx, rdx
    shl rcx, 16
    sar rcx, 16
    cmp rcx, rdx
    jne .bad
    ; Validate before the first read, including a partial VM-memory overlap.
    mov rcx, [rel avm_base]
    mov rdx, [rel avm_capacity]
    test rcx, rcx
    jz .no_vm_base
    test rdx, rdx
    jz .bad
    add rdx, rcx
    jc .bad
    cmp rax, rcx
    jbe .linux_vm
    cmp rbx, rdx
    jb .bad                         ; app VM span
    jmp .linux_vm
.no_vm_base:
    test rdx, rdx
    jnz .bad
.linux_vm:
    mov rcx, [rel hv_linux_region]
    mov rdx, [rel hv_linux_region_capacity]
    test rdx, rdx
    jz .native
    test rcx, rcx
    jz .bad
    add rdx, rcx
    jc .bad
    cmp rax, rcx
    jbe .native
    cmp rbx, rdx
    jb .bad                         ; Linux guest span
.native:
    lea rcx, [rel af_private_end]
    cmp rbx, rcx
    jae .bss
    lea rcx, [rel af_click_prev]
    cmp rax, rcx
    ja .bad
.bss:
    lea rcx, [rel af_private_bss_end]
    cmp rbx, rcx
    jae .authority
    lea rcx, [rel af_gui_target]
    cmp rax, rcx
    ja .bad
.authority:
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .bad
    test r12, r12
    jz .bad
    cmp rdx, r12
    jne .bad
    cmp byte [rel af_remove_active], 0
    je .capture
    cmp r12, [rel af_remove_epoch]
    jne .bad
    mov rax, [rel session_key_handle]
    cmp rax, [rel af_remove_key]
    jne .bad
    mov rsi, rbx
    lea rdi, [rel af_remove_digest]
    mov ecx, 4
    cld
    repe cmpsq
    jne .bad                        ; one immutable pending operation
    jmp .original_flow
.capture:
    mov rsi, rbx
    lea rdi, [rel af_remove_digest]
    mov ecx, 4
    cld
    rep movsq
    mov [rel af_remove_epoch], r12
    mov rax, [rel session_key_handle]
    mov [rel af_remove_key], rax
    mov byte [rel af_remove_flow], 0
    mov byte [rel af_remove_vm_done], 0
    mov qword [rel af_remove_entry], 0
    cmp dword [rel af_state], AF_IDLE
    je .captured
    cmp r12, [rel af_epoch]
    jne .captured
    lea rsi, [rel af_remove_digest]
    lea rdi, [rel af_descriptor+32]
    mov ecx, 4
    repe cmpsq
    jne .captured
    mov byte [rel af_remove_flow], 1
    mov rax, [rel af_observe_attempt]
    mov [rel af_remove_attempt], rax
    mov rax, [rel af_instance]
    mov [rel af_remove_instance], rax
    mov rax, [rel af_handle]
    mov [rel af_remove_handle], rax
.captured:
    mov byte [rel af_remove_active], 1
.original_flow:
    cmp byte [rel af_remove_flow], 0
    je .entry
    ; Ordinary tick may finish the old flow; it may never substitute a new one.
    mov rax, [rel af_observe_attempt]
    cmp rax, [rel af_remove_attempt]
    jne .bad
    mov rax, [rel af_handle]
    cmp rax, [rel af_remove_handle]
    jne .bad
    cmp dword [rel af_state], AF_IDLE
    je .entry
    mov rax, [rel af_instance]
    cmp rax, [rel af_remove_instance]
    jne .bad
    mov r13d, 1
.entry:
    mov byte [rel af_remove_busy], 1
    lea rdi, [rel af_remove_digest]
    mov rsi, r12
    mov rdx, [rel af_remove_entry]
    call app_launcher_quiesce
    test eax, eax
    jz .unlock_bad
    mov [rel af_remove_entry], rdx
    test r13d, r13d
    jz .vm
    cmp dword [rel af_state], AF_RETIRING
    je .vm
    mov byte [rel af_end_ordinary], 1
    call af_retire
    mov dword [rel af_state], AF_RETIRING
.vm:
    cmp byte [rel af_remove_vm_done], 0
    jne .ui
    lea rdi, [rel af_remove_digest]
    mov rsi, r12
    call app_vm_quiesce              ; stop acceptance alone is never1
    cmp eax, 1
    je .vm_done
    cmp eax, 2
    je .pending
    jmp .unlock_bad
.vm_done:
    mov byte [rel af_remove_vm_done], 1 ; do not reopen VM's terminal capsule
.ui:
    lea rdi, [rel af_remove_digest]
    mov rsi, r12
    mov rdx, [rel af_remove_entry]
    call app_launcher_quiesce
    cmp eax, 1
    jne .ui_pending
    test r13d, r13d
    jz .done
    mov qword [rel af_instance], 0
    mov dword [rel af_state], AF_IDLE
.done:
    mov byte [rel af_remove_active], 0 ; terminal1 ends operation; caller stops polling
    mov eax, 1
    jmp .unlock
.ui_pending:
    cmp eax, 2
    jne .unlock_bad
.pending:
    mov eax, 2
    jmp .unlock
.unlock_bad:
    xor eax, eax
.unlock:
    mov byte [rel af_remove_busy], 0
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Real owner session and whole immutable object, independent of UI summaries.
af_current:
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rel af_epoch]
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel af_key]
    jne .bad
    mov rdi,[rel af_handle]
    lea rsi,[rel af_descriptor_check]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .bad
    lea rdi,[rel af_descriptor]
    lea rsi,[rel af_descriptor_check]
    mov ecx,48
    repe cmpsq
    jne .bad
    mov rdi,[rel af_handle]
    mov rsi,[rel af_attempt]
    jmp app_launcher_terminal_current
.bad:
    xor eax,eax
    ret

af_new_deadline:
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    add rax,AF_UI_BOUND_US
    jc .bad
    mov [rel af_deadline],rax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

af_in_time:
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel af_deadline]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Clear only new diagnostics for a newly accepted original flow.
af_start_clock_clear:
    mov qword [rel af_start_candidate_us],0
    mov qword [rel af_start_candidate_attempt],0
    mov qword [rel af_start_spent_us],0
    mov qword [rel af_start_spent_attempt],0
    mov qword [rel af_start_us],0
    ret

; Pointer-only native widget callback. No grant/VM work inside input delivery.
af_click:
    push rbx
    mov ebx,edi
    cmp dword [rel af_state],AF_POLICY
    jne .chain
    xor ecx,ecx
    lea rdx,[rel af_ids]
.find:
    cmp ebx,[rdx+rcx*4]
    je .ours
    inc ecx
    cmp ecx,AF_WIDGETS
    jb .find
.chain:
    pop rbx
    mov rax,[rel af_click_prev]
    test rax,rax
    jz .none
    jmp rax
.none:
    xor eax,eax
    ret
.ours:
    cmp ecx,3
    jb .taken
    mov [rel af_click_index],ecx
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    call af_dwelled
    cmp eax,1
    jne .disarm
    call af_current
    cmp eax,1
    jne .disarm
    call af_panel_ok
    test eax,eax
    jnz .disarm
    call af_widget_current
    cmp eax,1
    jne .disarm
    call af_geometry
    mov [rel af_click_xy],rax
    mov [rel af_click_fb],rdx
    mov eax,[rel wm_zcounter]
    mov [rel af_click_z],eax
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel af_click_inj],eax
    mov qword [rel af_start_candidate_us],0
    mov qword [rel af_start_candidate_attempt],0
    cmp dword [rel af_click_index],12
    jne .answer
    cmp qword [rel tsc_khz],0
    je .answer
    call time_monotonic_now_us
    mov [rel af_start_candidate_us],rax
    mov rax,[rel af_attempt]
    mov [rel af_start_candidate_attempt],rax
.answer:
    mov eax,[rel af_click_index]
    inc eax
    mov [rel af_answer],al
    jmp .taken
.disarm:
    mov qword [rel af_start_candidate_us],0
    mov qword [rel af_start_candidate_attempt],0
    mov byte [rel af_answer],0
.taken:
    mov eax,1
    pop rbx
    ret

; SEC ruling 89821: a press meant for the opener must not land on a decision control.
af_dwelled:
    cmp qword [rel af_panel_shown_us],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    sub rax,[rel af_panel_shown_us]
    jb .bad
    cmp rax,AF_DWELL_US
    jb .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

af_widget_current:
    mov ecx,[rel af_click_index]
    cmp ecx,AF_WIDGETS
    jae .bad
    lea rdx,[rel af_ids]
    mov edi,[rdx+rcx*4]
    cmp edi,[rel wgt_count]
    jae .bad
    call wgt_slot_ptr
    mov ecx,[rel af_click_index]
    lea rdx,[rel af_tokens]
    lea rdx,[rdx+rcx*8]
    cmp [rax+WGI_ID],rdx
    jne .bad
    mov ecx,[rel af_slot]
    cmp [rax+WGI_WIN],ecx
    jne .bad
    cmp dword [rax+WGI_TYPE],1
    jne .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

app_launch_flow_tick:
    push rbx
    call af_idle_turn
    pop rbx
    ret

af_idle_turn:
    cmp byte [rel af_initialized],1
    jne .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel af_state],AF_IDLE
    je app_vm_tick                      ; original bounded lifecycle only
    cmp dword [rel af_state],AF_RETIRING
    je .retiring
    call af_current
    cmp eax,1
    jne af_abort
    cmp dword [rel af_state],AF_RUNNING
    jne .native_turn
    call af_running_current
    cmp eax,1
    jne af_abort                        ; revoke before any next guest CPU turn
.native_turn:
    call app_vm_tick                    ; sole original app VM bounded idle turn
    call af_current
    cmp eax,1
    jne af_abort
    cmp dword [rel af_state],AF_RUNNING
    jne .not_running
    call chat_send_tick                 ; sole human Send turn, identity rechecked
    jmp .running
.not_running:
    call af_in_time
    cmp eax,1
    jne af_abort
    cmp dword [rel af_state],AF_PREPARING
    je .preparing
    call af_panel_scan
    cmp eax,-1
    je af_decline                       ; panel closed before any Start
    cmp eax,[rel wm_focus]
    je .in_front
    call time_monotonic_now_us          ; SEC 90151: a cover can close by itself, so the dwell
    mov [rel af_panel_shown_us],rax     ; counts only from when the panel is back in front
.in_front:
    movzx eax,byte [rel af_answer]
    mov byte [rel af_answer],0           ; spend before any decision/effect
    mov rdx,[rel af_start_candidate_us]
    mov [rel af_start_spent_us],rdx
    mov rdx,[rel af_start_candidate_attempt]
    mov [rel af_start_spent_attempt],rdx
    mov qword [rel af_start_candidate_us],0 ; spent with the original answer
    mov qword [rel af_start_candidate_attempt],0
    test eax,eax
    jz .out
    dec eax
    mov [rel af_click_index],eax
    call af_panel_ok
    test eax,eax
    jnz .out
    call af_widget_current
    cmp eax,1
    jne .out
    mov eax,[rel wm_zcounter]
    cmp eax,[rel af_click_z]
    jne .out
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel af_click_inj]
    jne .out
    call af_geometry
    cmp rax,[rel af_click_xy]
    jne .out
    cmp rdx,[rel af_click_fb]
    jne .out
    mov ebx,[rel af_click_index]
    cmp ebx,11
    je af_decline
    cmp ebx,12
    je .prepare
    cmp ebx,7
    je .gui_policy
    cmp ebx,3
    jb .out
    cmp ebx,6
    ja .out
    sub ebx,3
    lea rdx,[rel af_policy]
    movzx eax,byte [rdx+rbx]
    inc eax
    cmp eax,3
    jb .policy
    xor eax,eax
.policy:
    mov [rdx+rbx],al
    add ebx,3
    mov edi,ebx
    call af_text
    lea rdx,[rel af_ids]
    mov edi,[rdx+rbx*4]
    call wgt_set_text
    ret
.gui_policy:
    cmp byte [rel af_gui_available],1
    jne .out
    movzx eax,byte [rel af_gui_policy]
    inc eax
    cmp eax,3
    jb .gui_choice
    xor eax,eax
.gui_choice:
    mov [rel af_gui_policy],al
    mov edi,7
    call af_text
    mov edi,[rel af_ids+7*4]
    call wgt_set_text
    ret
.prepare:
    ; All original idle-turn click checks passed. Missing clock never refuses Start.
    cmp qword [rel af_start_us],0
    jne .start_clock_done
    mov rax,[rel af_start_spent_attempt]
    test rax,rax
    jz .start_clock_done
    cmp rax,[rel af_attempt]
    jne .start_clock_done
    mov rax,[rel af_start_spent_us]
    mov [rel af_start_us],rax
.start_clock_done:
    call af_panel_close
    call af_new_deadline
    cmp eax,1
    jne af_abort
    call time_monotonic_now_us
    mov [rel af_prepare_us],rax
    mov rdi,[rel af_handle]
    xor esi,esi                         ; actual signed runtime/bundle auto RAM
    call app_vm_prepare
    test rax,rax
    jz af_abort
    mov [rel af_instance],rax
    mov dword [rel af_state],AF_PREPARING
    ret
.preparing:
    mov rdi,[rel af_instance]
    call app_vm_status
    cmp eax,AVM_READY
    je af_activate
    cmp eax,AVM_PREPARING
    je af_launch_feedback
    cmp eax,AVM_LOADING
    je af_launch_feedback
    jmp af_abort
.running:
    mov rdi,[rel af_instance]
    call app_vm_status
    cmp eax,AVM_RUNNING
    jne af_abort
    call af_running_current
    cmp eax,1
    jne af_abort
    jmp af_launch_feedback
.out:
    ret
.retiring:
    call app_vm_tick
    mov rdi,[rel af_instance]
    call app_vm_status
    cmp eax,AVM_EMPTY
    jne .out                           ; not-ready/-1 is not scrub completion
    mov qword [rel af_instance],0
    mov dword [rel af_state],AF_IDLE
    ret

; One atomic native READY->form->binding->explicit policy->activation turn.
af_activate:
    push rbx
    mov rdi,[rel af_instance]
    lea rsi,[rel af_vm]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    cmp qword [rel af_vm],1
    jne .bad
    mov rax,[rel af_instance]
    cmp rax,[rel af_vm+56]
    jne .bad
    mov rax,[rel af_handle]
    cmp rax,[rel af_vm+96]
    jne .bad
    mov rdi,rax
    mov rsi,[rel af_vm+8]
    call app_launcher_form_staged
    test eax,eax
    jnz .bad
    cmp ecx,WM_MAX
    jae .bad
    mov [rel af_form_slot],ecx
    mov ebx,ecx
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    mov [rel af_form_gen],eax
    mov edi,ebx
    call wmx_window_id
    test rax,rax
    jz .bad
    mov [rel af_window],rax
    mov edi,eax
    call form_events_lifetime
    test rax,rax
    jz .bad
    mov [rel af_reset],rax
    mov rdi,[rel af_instance]
    mov rsi,[rel af_handle]
    mov rdx,[rel af_window]
    call app_binding_install
    cmp eax,1
    jne .bad
    xor ebx,ebx
.policies:
    lea rax,[rel af_policy]
    movzx esi,byte [rax+rbx]
    lea edi,[ebx+1]
    mov edx,AF_POLICY_US
    call app_binding_policy
    cmp eax,1
    jne .bad
    inc ebx
    cmp ebx,4
    jb .policies
    cmp byte [rel af_gui_available],1
    jne .gui_done
    lea rdi,[rel af_gui_target]
    movzx esi,byte [rel af_gui_policy]
    mov edx,AF_POLICY_US
    call app_binding_gui_policy
    cmp eax,1
    jne .bad
.gui_done:
    call af_current
    cmp eax,1
    jne .bad
    mov rdi,[rel af_handle]
    mov rsi,[rel af_attempt]
    call app_launcher_terminal_activation_begin
    cmp eax,1
    jne .bad
    mov rdi,[rel af_instance]
    call app_vm_activate
    cmp eax,1
    jne .bad
    mov rdi,[rel af_handle]
    mov rsi,[rel af_attempt]
    mov edx,1
    call app_launcher_complete
    cmp eax,1
    jne .bad
    mov dword [rel af_state],AF_RUNNING
    call time_monotonic_now_us
    mov [rel af_ready_us],rax
    ; Only the signed paos.chat bundle binds; a refusal leaves Send unavailable.
    mov rdi,[rel af_handle]
    mov rsi,[rel af_attempt]
    mov rdx,[rel af_window]
    mov rcx,[rel af_reset]
    mov r8,[rel af_instance]
    call chat_send_bind
    pop rbx
    ret
.bad:
    pop rbx
    jmp af_abort

af_running_current:
    mov rdi,[rel af_window]
    call form_events_lifetime
    cmp rax,[rel af_reset]
    jne .bad
    jmp af_form_current
.bad:
    xor eax,eax
    ret

; Only an actual accepted guest BEGIN for this enforced form can reveal it.
; Status/local WAIT/BUSY/refusal are not readiness. A stock MIN window is
; already bound so no new hidden state, widget flag or guest authority exists.
af_launch_feedback:
    cmp qword [rel af_prepare_us],0
    je .out
    cmp qword [rel af_first_wait_us],0
    jne .out
    cmp dword [rel af_state],AF_RUNNING
    jne .fallback
    mov rdi,[rel af_window]
    mov rsi,[rel af_reset]
    mov rdx,[rel af_vm+8]
    call form_events_first_begin
    test rax,rax
    jz .fallback
    cmp rax,[rel af_prepare_us]
    jb .fallback
    mov [rel af_first_wait_us],rax
    call af_running_current
    cmp eax,1
    jne af_abort
    call af_notice_close
    mov edi,[rel af_form_slot]
    call wmx_raise_slot
    call time_monotonic_now_us
    mov [rel af_shown_us],rax
    ret
.fallback:
    call time_monotonic_now_us
    sub rax,[rel af_prepare_us]
    jc .out
    cmp rax,AF_FALLBACK_US
    jb .out
    cmp byte [rel af_notice_attempted],1
    je .out
    mov byte [rel af_notice_attempted],1
    mov edi,1
    call af_notice                       ; honest UI only, never VM READY proof
    call time_monotonic_now_us
    mov [rel af_fallback_us],rax
.out:
    ret

; New separate native mapped disjoint out64, depth0. Raw diagnostic only;
; downstream must join exact original handle/attempt and fresh native custody.
; schema,handle,attempt,accepted Start,first BEGIN,prepare,state,0. Same clock.
app_launch_flow_click_observe:
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    test rdi,rdi
    jz .bad
    cmp esi,64
    jne .bad
    mov qword [rdi],1
    mov rax,[rel af_handle]
    mov [rdi+8],rax
    mov rax,[rel af_observe_attempt]
    mov [rdi+16],rax
    mov rax,[rel af_start_us]
    mov [rdi+24],rax
    mov rax,[rel af_first_wait_us]
    mov [rdi+32],rax
    mov rax,[rel af_prepare_us]
    mov [rdi+40],rax
    mov eax,[rel af_state]
    mov [rdi+48],rax
    mov qword [rdi+56],0
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Bounded native read-only observation, trusted mapped disjoint out80.
; version, handle, attempt, prepare, ready/activation, first guest BEGIN,
; first app show, fallback card, failure, current lifecycle state.
app_launch_flow_observe:
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    test rdi,rdi
    jz .bad
    cmp esi,80
    jne .bad
    mov qword [rdi],1
    mov rax,[rel af_handle]
    mov [rdi+8],rax
    mov rax,[rel af_observe_attempt]
    mov [rdi+16],rax
    lea rsi,[rel af_times]
    add rdi,24
    mov ecx,6
    rep movsq
    mov eax,[rel af_state]
    mov [rdi],rax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native status card with no approval button or callback. Fully labelled
; before first draw, CHROME stamped, ordinary close control. Exact identity
; protects both user-closed/reused slots and a subsequent unrelated window.
af_notice:
    push rbx
    push r12
    push r13
    push r14
    mov r13d,edi
    mov r14d,[rel wm_focus]
    cmp dword [rel fb_width],400
    jb .out
    cmp dword [rel fb_height],200
    jb .out
    lea rdi,[rel af_starting_title]
    cmp r13d,1
    je .open
    lea rdi,[rel af_error_title]
    cmp r13d,2
    je .open
    lea rdi,[rel af_stopped_title]
.open:
    mov [rel af_notice_title],rdi
    mov esi,32
    mov edx,80
    mov ecx,360
    mov r8d,100
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .out
    mov r12d,eax
    mov [rel af_notice_slot],eax
    lea rdx,[rel wm_gen]
    mov eax,[rdx+r12*4]
    mov [rel af_notice_gen],eax
    lea rdx,[rel wm_owner]
    mov qword [rdx+r12*8],WM_OWNER_CHROME
    mov [rel wm_focus],r14d
    mov edi,1
    call wgt_reserve_run
    test eax,eax
    js .close
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    mov edi,2
    mov esi,r12d
    call wgt_create
    mov dword [rel wgt_alloc_next],-1
    cmp eax,-1
    je .unwind
    mov ebx,eax
    mov edi,eax
    call wgt_slot_ptr
    lea rdx,[rel af_notice_widget]
    mov [rax+WGI_ID],rdx
    mov [rax+WGI_LABEL],rdx
    mov dword [rax+WGI_FLAGS],1
    lea rdx,[rel wm_x]
    mov ecx,[rdx+r12*4]
    add ecx,12
    mov [rax+WGI_X],ecx
    lea rdx,[rel wm_y]
    mov ecx,[rdx+r12*4]
    add ecx,40
    mov [rax+WGI_Y],ecx
    mov dword [rax+WGI_W],336
    mov dword [rax+WGI_H],24
    mov edi,ebx
    lea rsi,[rel af_starting_text]
    cmp r13d,1
    je .text
    lea rsi,[rel af_error_text]
    cmp r13d,2
    je .text
    lea rsi,[rel af_stopped_text]
.text:
    call wgt_set_text
    dec byte [rel wgt_paint_suspended]
    call wmx_draw_all
    jmp .out
.unwind:
    dec byte [rel wgt_paint_suspended]
.close:
    call af_notice_close
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

af_notice_close:
    mov edi,[rel af_notice_slot]
    mov dword [rel af_notice_slot],-1
    cmp edi,WM_MAX
    jae .out
    lea rax,[rel wm_owner]
    cmp qword [rax+rdi*8],WM_OWNER_CHROME
    jne .out
    lea rax,[rel wm_gen]
    mov edx,[rel af_notice_gen]
    cmp [rax+rdi*4],edx
    jne .out
    lea rax,[rel wm_title]
    mov rdx,[rel af_notice_title]
    cmp [rax+rdi*8],rdx
    jne .out
    jmp wmx_close_slot
.out:
    ret

; Exact form identity before close: no stale slot ownership or raw-gen aliases.
af_form_current:
    mov edi,[rel af_form_slot]
    cmp edi,WM_MAX
    jae .bad
    lea rdx,[rel wm_gen]
    mov eax,[rel af_form_gen]
    cmp [rdx+rdi*4],eax
    jne .bad
    lea rdx,[rel wm_owner]
    mov rax,[rel af_vm+8]
    cmp [rdx+rdi*8],rax
    jne .bad
    call wmx_window_id
    cmp rax,[rel af_window]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Invalidate grant authority first, then original stop/closers, then observe scrub.
; A shown app whose VM is still RUNNING ended from outside it: form closed, or
; session or bundle changed. Any other VM state here is VM-initiated, because
; app_vm_stop only runs below, and VM failures retire through RETIRING and
; SCRUBBING. No clean guest exit exists, so those report a stopped app.
af_abort:
    mov byte [rel af_end_ordinary],0
    cmp qword [rel af_shown_us],0
    je af_retire
    mov rdi,[rel af_instance]
    call app_vm_status
    cmp rax,AVM_RUNNING
    jne af_retire
.ordinary:
    mov byte [rel af_end_ordinary],1
    jmp af_retire

; The human declined before Start: nothing failed.
af_decline:
    mov byte [rel af_end_ordinary],1
af_retire:
    mov dword [rel af_state],AF_RETIRING
    mov byte [rel af_answer],0
    mov qword [rel af_start_candidate_us],0
    mov qword [rel af_start_candidate_attempt],0
    mov qword [rel af_start_spent_us],0
    mov qword [rel af_start_spent_attempt],0
    call chat_send_retire
    call app_binding_retire
    mov rdi,[rel af_handle]
    mov rsi,[rel af_attempt]
    cmp byte [rel af_end_ordinary],1
    jne .failed
    call app_launcher_ended
    jmp .stop
.failed:
    xor edx,edx
    call app_launcher_complete
    mov rdi,[rel af_handle]
    mov rsi,[rel af_attempt]
    cmp qword [rel af_shown_us],0
    jne .stopped
    call app_launcher_failed
    jmp .failed_time
.stopped:
    call app_launcher_stopped
.failed_time:
    call time_monotonic_now_us
    mov [rel af_failed_us],rax
.stop:
    mov qword [rel af_attempt],0
    mov rdi,[rel af_instance]
    test rdi,rdi
    jz .form
    ; Binding is retired above. Close only the package's exact native member
    ; lifetimes for the captured actual VM principal, before stopping its VM.
    mov rdi,[rel af_vm+8]
    call form_app_members_close
    mov rdi,[rel af_instance]
    call app_vm_stop
.form:
    call af_form_current
    cmp eax,1
    jne .panel
    mov edi,[rel af_form_slot]
    call wmx_close_slot
.panel:
    mov dword [rel af_form_slot],-1
    call af_panel_close
    call af_notice_close
    cmp byte [rel af_end_ordinary],1
    je .no_notice
    cmp qword [rel af_prepare_us],0
    je .no_notice                      ; cancelling policy is not a VM failure
    call af_current
    cmp eax,1
    jne .no_notice
    mov edi,2
    cmp qword [rel af_shown_us],0
    je .notice
    mov edi,3
.notice:
    call af_notice
.no_notice:
    cmp qword [rel af_instance],0
    jne .out
    mov dword [rel af_state],AF_IDLE
.out:
    ret

af_panel_scan:
    mov eax, [rel af_slot]
    cmp eax, WM_MAX
    jae .bad
    lea rcx, [rel wm_title]
    lea rdx, [rel af_title]
    cmp [rcx + rax*8], rdx
    jne .bad
    lea rcx, [rel wm_owner]
    cmp qword [rcx + rax*8], WM_OWNER_CHROME
    jne .bad
    lea rcx, [rel wm_gen]
    mov edx, [rel af_gen]
    cmp [rcx + rax*4], edx
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rax*4], WM_FREE
    je .bad
    cmp dword [rcx + rax*4], WM_CLOSED
    je .bad
    ret
.bad:
    mov eax, -1
    ret


af_panel_ok:
    call af_panel_scan
    cmp eax, -1
    je .bad
    mov edx, eax
    cmp eax, [rel wm_focus]
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rdx*4], WM_VISIBLE
    jne .bad
    lea rcx, [rel wm_w]
    cmp dword [rcx + rdx*4], AF_WIDTH
    jne .bad
    lea rcx, [rel wm_h]
    cmp dword [rcx + rdx*4], AF_HEIGHT
    jne .bad
    lea rcx, [rel wm_x]
    mov r8d, [rcx + rdx*4]
    test r8d, r8d
    js .bad
    lea rcx, [rel wm_y]
    mov r9d, [rcx + rdx*4]
    test r9d, r9d
    js .bad
    lea r10d, [r8d + AF_WIDTH]
    lea r11d, [r9d + AF_HEIGHT]
    cmp r10d, [rel fb_width]
    jg .bad
    mov ecx, [rel fb_height]
    sub ecx, TASKBAR_H
    cmp r11d, ecx
    jg .bad
    mov ecx, r10d
    mov edx, r11d
    call calendar_overlaps
    test eax, eax
    jnz .bad

    xor ecx, ecx
    lea rdx, [rel wgt_tbl]
.loop:
    cmp ecx, [rel wgt_count]
    jae .yes
    cmp dword [rdx + WGI_TYPE], 0
    je .next
    test dword [rdx + WGI_FLAGS], 1
    jz .next
    mov rax, rdx                        ; Q 90205: the one predicate for paint, hover and press.
    call wgt_row_shown                  ; An unfocused window's closed menu paints nothing here.
    jc .next
    cmp dword [rdx + WGI_LAYER], 1
    je .cover
    cmp dword [rdx + WGI_WIN], WGT_HOST_DESKTOP
    jne .next
.cover:
    mov eax, [rdx + WGI_X]
    cmp eax, r10d
    jge .next
    add eax, [rdx + WGI_W]
    cmp eax, r8d
    jle .next
    mov eax, [rdx + WGI_Y]
    cmp eax, r11d
    jge .next
    add eax, [rdx + WGI_H]
    cmp eax, r9d
    jg .bad
.next:
    add rdx, WGI_SZ
    inc ecx
    jmp .loop
.yes:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; Pointer-choice geometry is captured at delivery and rechecked before effect.

af_geometry:
    mov edx, [rel af_slot]
    lea rcx, [rel wm_x]
    mov eax, [rcx + rdx*4]
    shl rax, 32
    lea rcx, [rel wm_y]
    mov edx, [rcx + rdx*4]
    or rax, rdx
    mov edx, [rel fb_width]
    shl rdx, 32
    mov ecx, [rel fb_height]
    or rdx, rcx
    ret

; Close only the exact private panel; discard any queued choice first.
af_panel_close:
    mov byte [rel af_answer],0
    call af_panel_scan
    mov dword [rel af_slot],-1
    cmp eax,-1
    je .out
    mov edi,eax
    jmp wmx_close_slot
.out:
    ret

; Stock widgets only. Private CHROME identity, fully labelled before first draw.
; No permission is created by building this editor. It does not steal focus.
af_build:
    push rbx
    push r12
    push r13
    push r14
    cmp dword [rel fb_width],AF_WIDTH
    jb .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    jc .bad
    cmp eax,AF_TOP+AF_HEIGHT
    jb .bad
    call af_format_identity
    cmp eax,1
    jne .bad
    lea rdi,[rel af_title]
    xor esi,esi
    mov edx,AF_TOP                    ; never cover the still-visible launcher
    mov ecx,AF_WIDTH
    mov r8d,AF_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .bad
    mov r12d,eax
    mov [rel af_slot],eax
    lea rdx,[rel wm_gen]
    mov eax,[rdx+r12*4]
    mov [rel af_gen],eax
    lea rdx,[rel wm_owner]
    mov qword [rdx+r12*8],WM_OWNER_CHROME
    ; Keeps the focus wmx_open_window gave it: the owner's own click opened this, and a
    ; focused opener would paint over Start (VM 90137). The dwell guards the first press.
    mov edi,AF_WIDGETS
    call wgt_reserve_run
    test eax,eax
    js .bad
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    mov edi,2
    cmp ebx,3
    jb .type
    cmp ebx,8
    jb .button
    cmp ebx,10
    jbe .type
.button:
    xor edi,edi
.type:
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .widgets_failed
    lea rdx,[rel af_ids]
    mov [rdx+rbx*4],eax
    mov edi,eax
    call wgt_slot_ptr
    mov r13,rax
    lea rdx,[rel af_tokens]
    lea rdx,[rdx+rbx*8]
    mov [rax+WGI_ID],rdx
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_EDIT],0
    mov dword [rax+WGI_LAYER],0
    lea rdx,[rel wm_x]
    mov eax,[rdx+r12*4]
    add eax,8
    mov [r13+WGI_X],eax
    mov dword [r13+WGI_W],544
    mov dword [r13+WGI_H],24          ; native button minimum; labels also fit
    mov eax,ebx
    imul eax,24
    add eax,28
    lea rdx,[rel wm_y]
    add eax,[rdx+r12*4]                ; WGI coordinates are absolute
    mov [r13+WGI_Y],eax
    mov edi,ebx
    call af_text
    lea rdx,[rel af_ids]
    mov edi,[rdx+rbx*4]
    call wgt_set_text
    inc ebx
    cmp ebx,AF_WIDGETS
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    call wmx_draw_all
    mov eax,1
    jmp .out
.widgets_failed:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI0..12 -> RSI private bounded NUL text. No untrusted format strings.
af_text:
    lea rsi,[rel af_hash]
    test edi,edi
    jz .out
    lea rsi,[rel af_hash+33]
    cmp edi,1
    je .out
    lea rsi,[rel af_identity]
    cmp edi,2
    je .out
    lea rsi,[rel af_cancel]
    cmp edi,11
    je .out
    lea rsi,[rel af_start]
    cmp edi,12
    je .out
    cmp edi,7
    je .gui
    cmp edi,8
    jae .target
    sub edi,3
    lea rax,[rel af_operations]
    movsxd rdx,dword [rax+rdi*4]
    lea rsi,[rax+rdx]
    lea rdx,[rel af_policy]
    movzx r8d,byte [rdx+rdi]
    lea rdi,[rel af_line]
.copy:
    lodsb
    stosb
    test al,al
    jnz .copy
    dec rdi
    lea rax,[rel af_choices]
    movsxd rdx,dword [rax+r8*4]
    lea rsi,[rax+rdx]
.choice:
    lodsb
    stosb
    test al,al
    jnz .choice
    lea rsi,[rel af_line]
.out:
    ret
.gui:
    lea rsi,[rel af_gui_missing]
    cmp byte [rel af_gui_available],1
    jne .out
    movzx eax,byte [rel af_gui_policy]
    lea rdx,[rel af_gui_choices]
    movsxd rax,dword [rdx+rax*4]
    lea rsi,[rdx+rax]
    ret
.target:
    lea rsi,[rel af_gui_no_target]
    cmp byte [rel af_gui_available],1
    jne .out
    sub edi,8
    mov ecx,edi
    lea rdx,[rel af_gui_prefixes]
    movsxd rax,dword [rdx+rdi*4]
    lea rsi,[rdx+rax]
    lea rdi,[rel af_line]
.prefix:
    lodsb
    test al,al
    jz .hex
    stosb
    jmp .prefix
.hex:
    lea rdx,[rel af_gui_target+8]
    mov r8,[rdx+rcx*8]
    mov ecx,16
    lea r10,[rel af_hex]
.digit:
    rol r8,4
    mov eax,r8d
    and eax,15
    mov al,[r10+rax]
    stosb
    loop .digit
    mov byte [rdi],0
    lea rsi,[rel af_line]
    ret

af_format_identity:
    lea rsi,[rel af_descriptor+32]
    lea rdi,[rel af_hash]
    lea r10,[rel af_hex]
    xor ecx,ecx
.hash:
    movzx eax,byte [rsi+rcx]
    mov edx,eax
    shr eax,4
    mov al,[r10+rax]
    stosb
    and edx,15
    mov al,[r10+rdx]
    stosb
    inc ecx
    cmp ecx,16
    jne .next
    mov byte [rdi],0
    inc rdi
.next:
    cmp ecx,32
    jb .hash
    mov byte [rdi],0
    lea rdi,[rel af_identity]
    lea rsi,[rel af_descriptor+96]        ; checked manifest's complete bundle ID
    mov ecx,64
.id:
    lodsb
    stosb
    test al,al
    jz .good
    loop .id
    xor eax,eax                         ; no clipped or unterminated identity
    ret
.good:
    mov eax,1
    ret

; Keep constants in the native image's single section; writable state is
; deferred below to the original page-isolated WDATA regions.
af_title: db 'App permissions (five minutes)',0
af_starting_title: db 'Starting app',0
af_error_title: db 'App launch failed',0
af_starting_text: db 'Starting... waiting for the app',0
af_error_text: db 'The app stopped or could not start.',0
af_stopped_title: db 'App stopped',0
af_stopped_text: db 'The app stopped unexpectedly.',0
af_notice_widget: db 'app_launch_status',0
af_cancel: db 'Cancel',0
af_start: db 'Start with these permissions',0
af_hex: db '0123456789abcdef'
align 8
af_tokens:
    db 'af_0',0,0,0,0,'af_1',0,0,0,0,'af_2',0,0,0,0
    db 'af_3',0,0,0,0,'af_4',0,0,0,0,'af_5',0,0,0,0
    db 'af_6',0,0,0,0,'af_7',0,0,0,0,'af_8',0,0,0,0
    db 'af_9',0,0,0,0,'af10',0,0,0,0,'af11',0,0,0,0
    db 'af12',0,0,0,0
align 4
af_operations: dd af_status-af_operations,af_begin-af_operations,af_poll-af_operations,af_cancel_op-af_operations
af_status: db 'WAIT STATUS: ',0
af_begin: db 'WAIT BEGIN+window text: ',0
af_poll: db 'WAIT POLL: ',0
af_cancel_op: db 'WAIT CANCEL: ',0
align 4
af_gui_prefixes: dd af_target_id-af_gui_prefixes,af_target_gen-af_gui_prefixes,af_target_owner-af_gui_prefixes
af_target_id: db 'Window: ',0
af_target_gen: db 'Generation: ',0
af_target_owner: db 'Owner: ',0
align 4
af_gui_choices: dd af_gui_deny-af_gui_choices,af_gui_allow-af_gui_choices,af_gui_ask-af_gui_choices
af_gui_deny: db 'Read original window: DENY',0
af_gui_allow: db 'Read original window: ALLOW',0
af_gui_ask: db 'Read window: ASK (no read)',0
af_gui_missing: db 'Read window: unavailable',0
af_gui_no_target: db 'Original window unavailable',0
align 4
af_choices: dd af_deny-af_choices,af_allow-af_choices,af_ask-af_choices
af_deny: db 'DENY',0
af_allow: db 'ALLOW',0
af_ask: db 'ASK',0
%include "core/abi/wdata.inc"
%macro WDATA_app_launch_flow 0
align 8
af_click_prev: dq 0
af_handle: dq 0
af_attempt: dq 0
af_epoch: dq 0
af_key: dq 0
af_deadline: dq 0
af_instance: dq 0
af_window: dq 0
af_reset: dq 0
af_click_xy: dq 0
af_click_fb: dq 0
af_observe_attempt: dq 0
af_panel_shown_us: dq 0
af_start_candidate_us: dq 0
af_start_candidate_attempt: dq 0
af_start_spent_us: dq 0
af_start_spent_attempt: dq 0
af_start_us: dq 0
af_times:
af_prepare_us: dq 0
af_ready_us: dq 0
af_first_wait_us: dq 0
af_shown_us: dq 0
af_fallback_us: dq 0
af_failed_us: dq 0
af_notice_title: dq 0
af_notice_slot: dd -1
af_notice_gen: dd 0
af_notice_attempted: db 0
af_end_ordinary: db 0
af_remove_busy: db 0
af_remove_active: db 0
af_remove_flow: db 0
af_remove_vm_done: db 0
align 8
af_remove_digest: times 32 db 0
af_remove_epoch: dq 0
af_remove_key: dq 0
af_remove_entry: dq 0
af_remove_attempt: dq 0
af_remove_instance: dq 0
af_remove_handle: dq 0
align 4
af_state: dd AF_IDLE
af_slot: dd -1
af_gen: dd 0
af_form_slot: dd -1
af_form_gen: dd 0
af_click_z: dd 0
af_click_inj: dd 0
af_click_index: dd 0
af_ids: times AF_WIDGETS dd -1
af_policy: times 4 db 0
af_initialized: db 0
af_answer: db 0
af_gui_configured: db 0
af_gui_available: db 0
af_gui_policy: db 0
af_private_end:
%endmacro
WDATA_DEFER WDATA_app_launch_flow
%macro WDATA_app_launch_flow_bss 0
af_gui_target: resb 32
af_descriptor: resb 384
af_descriptor_check: resb 384
af_vm: resb 128
af_hash: resb 66
af_identity: resb 64
af_line: resb 40
af_private_bss_end:
%endmacro
WDATA_BSS_DEFER WDATA_app_launch_flow_bss
