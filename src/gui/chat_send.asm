;; MODULE gui/chat_send
;; LAYER 6
;; PURPOSE Native human exact-question confirmation for the isolated chat app.
;; EXPORTS chat_send_owns_window, chat_send_init, chat_send_bind, chat_send_tick, chat_send_retire, chat_send_pending, chat_send_descriptor, chat_send_question, chat_send_validate, chat_send_consume, chat_send_spent_current, chat_send_release
;; IMPORTS gui/calendar, gui/widget, gui/window, gui/window_mgmt, gui/wm_pointer, gui/start_programs, gui/form_events, sec/session, svc/app_script, hv/app_vm, hv/guest_request, svc/command, core/smp, core/time, core/lib/str, boot/gop
;; OWNER saga:chat_send
;; CONTEXT: bsp_only
; No guest entry/command, provider client, egress permit or result publication.
; The native SEC owner consumes this human intent before its actual VM offer.
CHS_DESC equ 320
CHS_QUESTION equ 255                  ; real stock long field's inherited bound
CHS_US equ 30000000
CHS_DWELL_US equ 400000
CHS_ROWS equ 8
CHS_PREV equ 11
CHS_NEXT equ 12
CHS_CANCEL equ 13
CHS_CONFIRM equ 14
CHS_COUNT equ 15
CHS_SOURCES equ 6
CHS_A_LOCAL equ 16                    ; source actions, chs_source_names order
CHS_A_CLAUDE equ 17
CHS_A_CODEX equ 18
CHS_A_SEND equ 19
CHS_A_CANCEL equ 20
CHS_TOP equ 64                        ; below the published desktop entry
CHS_WIDTH equ 560
CHS_HEIGHT equ 340
; chs_state:0 idle,1 panel,2 confirmed,3 spent. Each id is permanently burned.

chs_native:
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

chat_send_init:
    cmp byte [rel chs_initialized],0
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    mov rax,[rel wgt_click_hook]
    mov [rel chs_previous_click],rax
    lea rax,[rel chs_click]
    mov [rel wgt_click_hook],rax
    lea rax,[rel chs_local_name]
    mov [rel chs_source_names+0],rax
    lea rax,[rel chs_claude_name]
    mov [rel chs_source_names+8],rax
    lea rax,[rel chs_codex_name]
    mov [rel chs_source_names+16],rax
    lea rax,[rel chs_send_name]
    mov [rel chs_source_names+24],rax
    lea rax,[rel chs_cancel_name]
    mov [rel chs_source_names+32],rax
    lea rax,[rel chs_screen_name]
    mov [rel chs_source_names+40],rax
    mov byte [rel chs_initialized],1
.out:
    ret

; RDI handle, RSI launch attempt, RDX owned packed form, RCX reset lifetime,
; R8 actual app instance. Called by original native lifecycle AFTER activation.
chat_send_bind:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov r15,r8
    call chat_send_retire
    cmp byte [rel chs_initialized],1
    jne .bad
    call chs_native
    cmp eax,1
    jne .bad
    test r12,r12
    jz .bad
    test r14,r14
    jz .bad
    mov [rel chs_owner_handle],rdx    ; actual owner epoch returned by gate
    mov rax,[rel session_key_handle]
    mov [rel chs_session_handle],rax
    mov rdi,rbx
    lea rsi,[rel chs_script]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .bad
    cmp dword [rel chs_script+96],0x736f6170
    jne .bad
    cmp dword [rel chs_script+100],0x6168632e
    jne .bad
    cmp word [rel chs_script+104],0x0074
    jne .bad
    mov rdi,r15
    lea rsi,[rel chs_vm]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    cmp qword [rel chs_vm],1
    jne .bad
    cmp [rel chs_vm+56],r15
    jne .bad
    cmp [rel chs_vm+96],rbx
    jne .bad
    cmp qword [rel chs_vm+112],0
    jne .bad
    cmp qword [rel chs_vm+120],0
    jne .bad
    mov rdi,[rel chs_vm+16]
    mov esi,[rel chs_vm+24]
    lea rdx,[rel chs_binding]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .bad
    cmp qword [rel chs_binding+8],0
    je .bad
    mov rax,[rel chs_vm+8]
    cmp [rel chs_binding],rax
    jne .bad
    lea rdi,[rel chs_binding+16]
    lea rsi,[rel chs_vm+16]
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    mov [rel chs_handle],rbx
    mov [rel chs_attempt],r12
    mov [rel chs_window],r13
    mov [rel chs_reset],r14
    mov [rel chs_instance],r15
    movzx ebx,r13b
    cmp ebx,WM_MAX
    jae .bad
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    mov [rel chs_rawgen],rax
    mov dword [rel chs_route],2        ; initial cloud choice is UNAVAILABLE
    mov byte [rel chs_live],1
    call chs_current
    cmp eax,1
    jne .bad
    lea rdi,[rel chs_prompt_id]
    call chs_find
    cmp eax,-1
    je .long_done
    mov r12d,eax
    mov edi,eax
    call wgt_textfield_long              ; full pool leaves the disclosed 39 B
    ; paos_chat.frm declares text=_ for this field. Turn that placeholder into
    ; an empty field before any human or guest turn, so
    ; an untouched field stays blank and typed text has no stray '_'.
    mov edi,r12d
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],WGT_TYPE_TEXTFIELD
    jne .long_done
    cmp dword [rax+WGI_VLEN],1
    jne .long_done
    call wgt_tf_buf
    cmp byte [rax],'_'
    jne .long_done
    mov edi,r12d
    lea rsi,[rel chs_empty]
    call wgt_set_text
.long_done:
    mov eax,1
    jmp .out
.bad:
    call chat_send_retire
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Full original session, immutable bundle, VM128, binding48, form ID/rawgen,
; full owner and reset lifetime on every use; no low-bit identity comparison.
chs_current:
    call chs_native
    cmp eax,1
    jne .bad
    cmp byte [rel chs_live],1
    jne .bad
    cmp rdx,[rel chs_owner_handle]
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel chs_session_handle]
    jne .bad
    mov rdi,[rel chs_instance]
    call app_vm_status
    cmp eax,AVM_RUNNING
    jne .bad
    mov rdi,[rel chs_instance]
    lea rsi,[rel chs_vm_check]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    lea rsi,[rel chs_vm]
    lea rdi,[rel chs_vm_check]
    mov ecx,16
    repe cmpsq
    jne .bad
    mov rdi,[rel chs_handle]
    lea rsi,[rel chs_script_check]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .bad
    lea rsi,[rel chs_script]
    lea rdi,[rel chs_script_check]
    mov ecx,48
    repe cmpsq
    jne .bad
    mov rdi,[rel chs_vm+16]
    mov esi,[rel chs_vm+24]
    lea rdx,[rel chs_binding_check]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .bad
    lea rsi,[rel chs_binding]
    lea rdi,[rel chs_binding_check]
    mov ecx,6
    repe cmpsq
    jne .bad
    mov edi,[rel chs_window]
    movzx edi,dil
    call wmx_window_id
    cmp rax,[rel chs_window]
    jne .bad
    movzx ecx,al
    lea rdx,[rel wm_gen]
    mov eax,[rdx+rcx*4]
    cmp rax,[rel chs_rawgen]
    jne .bad
    lea rdx,[rel wm_owner]
    mov rax,[rel chs_vm+8]
    cmp [rdx+rcx*8],rax
    jne .bad
    mov edi,[rel chs_window]
    call form_events_lifetime
    cmp rax,[rel chs_reset]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native outputs must already be mapped. Reject null/wrap and all private state.
; RDI ptr RSI extent ->1/0. Callers also reject overlapping output operands.
chs_range:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel chs_private_end]
    cmp rdi,rdx
    jae .yes
    lea rdx,[rel chs_live_data]
    cmp rax,rdx
    ja .bad
.yes:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI slot -> EAX1 while this slot hosts the live chat form, else0.
chat_send_owns_window:
    xor eax,eax
    cmp byte [rel chs_live],1
    jne .out
    movzx ecx,byte [rel chs_window]
    cmp ecx,edi
    sete al
.out:
    ret

; Locate one exact original form widget by stable ID, no duplicate accepted.
; RDI name ->EAX id/-1. Geometry, visible/enabled and type checked separately.
chs_find:
    push rbx
    push r12
    push r13
    mov r12,rdi
    xor ebx,ebx
    mov r13d,-1
.loop:
    cmp ebx,[rel wgt_count]
    jae .done
    cmp ebx,WGT_MAX
    jae .bad
    mov edi,ebx
    call wgt_slot_ptr
    movzx ecx,byte [rel chs_window]
    cmp [rax+WGI_WIN],ecx
    jne .next
    cmp dword [rax+WGI_TYPE],0
    je .next
    mov rdi,[rax+WGI_ID]
    test rdi,rdi
    jz .next
    mov rsi,r12
    call strcmp
    test eax,eax
    jnz .next
    cmp r13d,-1
    jne .bad
    mov r13d,ebx
.next:
    inc ebx
    jmp .loop
.done:
    mov eax,r13d
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Exact stock question bytes, not guest JSON, clipboard or a command operand.
; EAX1/0, RDX bytes, ECX length. Maximum is the real field capacity, <=255.
chs_question_live:
    lea rdi,[rel chs_prompt_id]
    call chs_find
    cmp eax,-1
    je .bad
    mov [rel chs_prompt_widget],eax
    mov edi,eax
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],WGT_TYPE_TEXTFIELD
    jne .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    mov r8d,[rax+WGI_VLEN]
    test r8d,r8d
    jz .bad
    cmp r8d,CHS_QUESTION
    ja .bad
    call wgt_tf_buf
    cmp r8d,ecx
    ja .bad
    cmp byte [rax+r8],0
    jne .bad
    xor ecx,ecx
    xor r9d,r9d
.scan:
    cmp ecx,r8d
    jae .yes
    cmp byte [rax+rcx],0
    je .bad
    cmp byte [rax+rcx],' '
    je .blank
    mov r9d,1
.blank:
    inc ecx
    jmp .scan
.yes:
    test r9d,r9d
    jz .bad                             ; empty or only spaces is no question
    mov rdx,rax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Revalidate original identity, and before the spend also the frozen question
; and human deadline. A spent intent lives on identity alone: an answer may take
; far longer than the decision did, and later edits are not part of that request.
chs_intent_current:
    call chs_current
    cmp eax,1
    jne .bad
    cmp dword [rel chs_state],0
    je .bad
    cmp dword [rel chs_state],3
    je .yes
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel chs_descriptor+48]
    jae .bad
    call chs_question_live
    cmp eax,1
    jne .bad
    cmp rcx,[rel chs_descriptor+32]
    jne .bad
    mov rsi,rdx
    lea rdi,[rel chs_question]
    repe cmpsb
    jne .bad
.yes:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

chat_send_pending:
    call chs_intent_current
    cmp eax,1
    jne .bad
    cmp dword [rel chs_state],2
    jne .bad
    mov rax,[rel chs_descriptor+8]
    ret
.bad:
    xor eax,eax
    ret

; RDI original intent, RSI trusted disjoint out320, RDX exact320 ->1/0.
chat_send_descriptor:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    cmp rdx,CHS_DESC
    jne .bad
    mov rdi,r12
    mov esi,CHS_DESC
    call chs_range
    cmp eax,1
    jne .bad
    call chs_intent_current
    cmp eax,1
    jne .bad
    cmp dword [rel chs_state],2
    jb .bad
    cmp [rel chs_descriptor+8],rbx
    jne .bad
    mov rdi,r12
    lea rsi,[rel chs_descriptor]
    mov ecx,CHS_DESC/8
    rep movsq
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; RDI original intent, RSI offset, RDX trusted disjoint out, RCX count ->1/0.
chat_send_question:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov rdi,r13
    mov rsi,r14
    call chs_range
    cmp eax,1
    jne .bad
    call chs_intent_current
    cmp eax,1
    jne .bad
    cmp dword [rel chs_state],2
    jb .bad
    cmp [rel chs_descriptor+8],rbx
    jne .bad
    mov rax,r12
    add rax,r14
    jc .bad
    cmp rax,[rel chs_descriptor+32]
    ja .bad
    lea rsi,[rel chs_question]
    add rsi,r12
    mov rdi,r13
    mov rcx,r14
    rep movsb
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI original intent, RSI exact descriptor320, RDX exact question, RCX len.
; Equality grants only human intent. It is neither SEC privacy nor egress.
chat_send_validate:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov rdi,r12
    mov esi,CHS_DESC
    call chs_range
    cmp eax,1
    jne .bad
    mov rdi,r13
    mov rsi,r14
    call chs_range
    cmp eax,1
    jne .bad
    call chs_intent_current
    cmp eax,1
    jne .bad
    cmp dword [rel chs_state],2
    jb .bad
    cmp [rel chs_descriptor+8],rbx
    jne .bad
    cmp [rel chs_descriptor+32],r14
    jne .bad
    mov rdi,r12
    lea rsi,[rel chs_descriptor]
    mov ecx,CHS_DESC/8
    repe cmpsq
    jne .bad
    mov rdi,r13
    lea rsi,[rel chs_question]
    mov rcx,r14
    repe cmpsb
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI original intent ->1 while this spent intent still has its original identity.
; 0 means the delivery owner must cancel: owner cancelled, released or retired.
chat_send_spent_current:
    push rbx
    mov rbx,rdi
    call chs_current
    cmp eax,1
    jne .bad
    cmp dword [rel chs_state],3
    jne .bad
    cmp [rel chs_descriptor+8],rbx
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; RDI original intent ->1/0. The finished spent request ends so Send can run again.
chat_send_release:
    call chat_send_spent_current
    cmp eax,1
    jne .out
    call chs_clear_intent
    mov eax,1
.out:
    ret

; Same operands. Spend exactly once BEFORE actual SEC/VM delivery. No refund.
chat_send_consume:
    call chat_send_validate
    cmp eax,1
    jne .out
    cmp dword [rel chs_state],2
    jne .bad
    mov dword [rel chs_state],3
    mov eax,1
.out:
    ret
.bad:
    xor eax,eax
    ret

; A source click is merely a request to open native confirmation. The form's
; own event hook also sees it; that event reaches only the guest's WAIT queue and
; nothing the guest sends can produce the later CHROME human confirmation. Only
; these widgets are ever answered here; any other click, stale or not, chains.
; SEC ruling 89821: a press meant for the opener must not land on a decision control.
chs_dwelled:
    cmp qword [rel chs_panel_shown_us],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    sub rax,[rel chs_panel_shown_us]
    jb .bad
    cmp rax,CHS_DWELL_US
    jb .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

chs_click:
    push rbx
    push r12
    push r13
    mov ebx,edi
    cmp byte [rel chs_live],1
    jne .chain
    cmp dword [rel chs_state],1
    je .panel
    cmp ebx,[rel wgt_count]
    jae .chain
    mov edi,ebx
    call wgt_slot_ptr
    mov r12,rax
    movzx ecx,byte [rel chs_window]
    cmp [rax+WGI_WIN],ecx
    jne .chain
    cmp dword [rax+WGI_TYPE],WGT_TYPE_BUTTON
    jne .chain
    test dword [rax+WGI_FLAGS],1
    jz .chain
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .chain
    cmp qword [rax+WGI_ID],0
    je .chain
    xor r13d,r13d
.match:
    lea rax,[rel chs_source_names]
    mov rsi,[rax+r13*8]
    mov rdi,[r12+WGI_ID]
    call strcmp
    test eax,eax
    jz .source
    inc r13d
    cmp r13d,CHS_SOURCES
    jb .match
    jmp .chain
.source:
    call chs_current
    cmp eax,1
    jne .disarm
    movzx edi,byte [rel chs_window]
    cmp edi,[rel wm_focus]
    jne .disarm
    mov [rel chs_click_slot],edi
    ; Only a fully shown on-screen native form supplies this source edge.
    call chs_source_visible
    cmp eax,1
    jne .disarm
    lea edi,[r13+CHS_A_LOCAL]
    jmp .queue
.panel:
    xor r13d,r13d
.panel_find:
    lea rax,[rel chs_ids]
    cmp ebx,[rax+r13*4]
    je .panel_found
    inc r13d
    cmp r13d,CHS_COUNT
    jb .panel_find
    jmp .chain
.panel_found:
    cmp r13d,CHS_PREV
    jb .taken
    call chs_current
    cmp eax,1
    jne .disarm
    call chs_panel_ok
    cmp eax,1
    jne .disarm
    call chs_dwelled
    cmp eax,1
    jne .disarm
    mov edi,r13d
.queue:
    mov [rel chs_action],edi
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    call chs_geometry
    mov [rel chs_click_xy],rax
    mov [rel chs_click_fb],rdx
    mov eax,[rel wm_zcounter]
    mov [rel chs_click_z],eax
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel chs_click_inj],eax
.taken:
    mov eax,1
    jmp .out
.disarm:
    mov dword [rel chs_action],0
    jmp .taken
.chain:
    mov edi,ebx
    pop r13
    pop r12
    pop rbx
    cmp qword [rel chs_previous_click],0
    je .none
    jmp [rel chs_previous_click]
.none:
    xor eax,eax
    ret
.out:
    pop r13
    pop r12
    pop rbx
    ret

chs_source_visible:
    mov ecx,[rel chs_click_slot]
    lea rdx,[rel wm_state]
    cmp dword [rdx+rcx*4],WM_VISIBLE
    jne .bad
    lea rdx,[rel wm_x]
    mov eax,[rdx+rcx*4]
    test eax,eax
    js .bad
    lea rdx,[rel wm_w]
    add eax,[rdx+rcx*4]
    jc .bad
    cmp eax,[rel fb_width]
    ja .bad
    lea rdx,[rel wm_y]
    mov eax,[rdx+rcx*4]
    test eax,eax
    js .bad
    lea rdx,[rel wm_h]
    add eax,[rdx+rcx*4]
    jc .bad
    mov edx,[rel fb_height]
    sub edx,TASKBAR_H
    cmp eax,edx
    ja .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

chs_geometry:
    mov ecx,[rel chs_click_slot]
    lea rdx,[rel wm_x]
    mov eax,[rdx+rcx*4]
    shl rax,32
    lea rdx,[rel wm_y]
    mov ecx,[rdx+rcx*4]
    or rax,rcx
    mov edx,[rel fb_width]
    shl rdx,32
    mov ecx,[rel fb_height]
    or rdx,rcx
    ret

; Sole idle turn, from the running launch flow. Locked: keep state, every use
; refuses. A moved identity retires; a stale intent alone clears that intent.
chat_send_tick:
    push rbx
    cmp byte [rel chs_live],1
    jne .out
    call chs_native
    cmp eax,1
    jne .out
    call chs_current
    cmp eax,1
    jne .retire
    cmp dword [rel chs_state],0
    je .action
    call chs_intent_current
    cmp eax,1
    jne .stale
    cmp dword [rel chs_state],1
    jne .action
    call chs_panel_scan
    cmp eax,-1
    je .cancel                          ; owner closed it from its own chrome
    cmp eax,[rel wm_focus]
    je .action
    call time_monotonic_now_us          ; SEC 90151: as app_launch_flow, from back in front
    mov [rel chs_panel_shown_us],rax
.action:
    mov ebx,[rel chs_action]
    mov dword [rel chs_action],0         ; spend before effect/possible refusal
    test ebx,ebx
    jz .out
    mov eax,[rel wm_zcounter]
    cmp eax,[rel chs_click_z]
    jne .out
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel chs_click_inj]
    jne .out
    mov eax,[rel chs_click_slot]
    cmp eax,[rel wm_focus]
    jne .out
    call chs_geometry
    cmp rax,[rel chs_click_xy]
    jne .out
    cmp rdx,[rel chs_click_fb]
    jne .out
    cmp ebx,CHS_A_LOCAL
    jb .panel_action
    cmp ebx,CHS_A_CANCEL
    je .source_cancel
    ; No live confirmed/spent intent can be silently replaced by another Send.
    cmp dword [rel chs_state],0
    jne .out
    cmp ebx,CHS_A_LOCAL
    je .local
    cmp ebx,CHS_A_CLAUDE
    je .cloud1
    cmp ebx,CHS_A_CODEX
    je .cloud2
    cmp ebx,CHS_A_SEND
    je .send
    ; Include_screen is explicitly unavailable, not a native read id.
    lea rsi,[rel chs_no_screen]
    jmp .status
.local:
    mov dword [rel chs_route],1
    lea rsi,[rel chs_local_text]
    call chs_provider
    lea rsi,[rel chs_local_text]
    jmp .status
.cloud1:
    mov dword [rel chs_route],2
    lea rsi,[rel chs_claude_text]
    jmp .cloud
.cloud2:
    mov dword [rel chs_route],3
    lea rsi,[rel chs_codex_text]
.cloud:
    call chs_provider
    lea rsi,[rel chs_cloud_text]
    jmp .status
.send:
    cmp dword [rel chs_route],1
    jne .unavailable
    call chs_begin
    cmp eax,1
    je .out
    lea rsi,[rel chs_refused_text]
    jmp .status
.unavailable:
    lea rsi,[rel chs_cloud_text]
.status:
    call chs_status
    jmp .out
.panel_action:
    cmp dword [rel chs_state],1
    jne .out
    call chs_panel_ok
    cmp eax,1
    jne .out
    cmp ebx,CHS_CANCEL
    je .cancel
    cmp ebx,CHS_PREV
    je .prev
    cmp ebx,CHS_NEXT
    je .next
    cmp ebx,CHS_CONFIRM
    jne .out
    mov eax,[rel chs_seen]
    cmp eax,[rel chs_pages]
    jb .out                         ; every exact-question page must be visited
    mov dword [rel chs_state],2
    call chs_panel_close
    lea rsi,[rel chs_not_sent]
    jmp .status
.prev:
    cmp dword [rel chs_page],0
    je .out
    dec dword [rel chs_page]
    jmp .render
.next:
    mov eax,[rel chs_page]
    inc eax
    cmp eax,[rel chs_pages]
    jae .out
    mov [rel chs_page],eax
.render:
    call chs_render
    jmp .out
.source_cancel:
    cmp dword [rel chs_state],0
    je .out                             ; clearing a spent intent fences delivery
.cancel:
    call chs_clear_intent
    lea rsi,[rel chs_cancelled]
    jmp .status
.stale:
    call chs_clear_intent
    lea rsi,[rel chs_expired]
    jmp .status
.retire:
    call chat_send_retire
.out:
    pop rbx
    ret

; Native status is disclosure only, never a result, grant or success assertion.
chs_status:
    push r12
    mov r12,rsi
    lea rdi,[rel chs_status_id]
    call chs_find
    cmp eax,-1
    je .out
    mov edi,eax
    mov rsi,r12
    call wgt_set_text
.out:
    pop r12
    ret

; Status names the actual choice; a cloud label never means a cloud route ran.
chs_provider:
    push r12
    mov r12,rsi
    lea rdi,[rel chs_provider_id]
    call chs_find
    cmp eax,-1
    je .out
    mov edi,eax
    mov rsi,r12
    call wgt_set_text
.out:
    pop r12
    ret

chs_begin:
    cmp qword [rel chs_floor],-2
    jae .bad
    call chs_question_live
    cmp eax,1
    jne .bad
    mov rsi,rdx
    lea rdi,[rel chs_question]
    mov [rel chs_question_len],rcx
    rep movsb
    lea rdi,[rel chs_descriptor]
    xor eax,eax
    mov ecx,CHS_DESC/8
    rep stosq
    mov qword [rel chs_descriptor],1
    inc qword [rel chs_floor]
    mov rax,[rel chs_floor]
    mov [rel chs_descriptor+8],rax
    mov qword [rel chs_descriptor+16],1 ; local route only, no remote fallback
    mov qword [rel chs_descriptor+24],1 ; actual maintained local model choice
    mov rax,[rel chs_question_len]
    mov [rel chs_descriptor+32],rax
    ; +40 read_id=0; screen attachment unavailable in this finite component.
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    add rax,CHS_US
    jc .bad
    mov [rel chs_descriptor+48],rax
    mov rax,[rel chs_owner_handle]
    mov [rel chs_descriptor+56],rax
    mov rax,[rel chs_handle]
    mov [rel chs_descriptor+64],rax
    mov rax,[rel chs_attempt]
    mov [rel chs_descriptor+72],rax
    mov rax,[rel chs_window]
    mov [rel chs_descriptor+80],rax
    mov rax,[rel chs_rawgen]
    mov [rel chs_descriptor+88],rax
    mov rax,[rel chs_reset]
    mov [rel chs_descriptor+96],rax
    mov rax,[rel chs_instance]
    mov [rel chs_descriptor+104],rax
    lea rsi,[rel chs_binding]
    lea rdi,[rel chs_descriptor+112]
    mov ecx,6
    rep movsq
    lea rsi,[rel chs_vm]
    lea rdi,[rel chs_descriptor+160]
    mov ecx,16
    rep movsq
    call chs_escape_question
    mov qword [rel chs_panel_shown_us],0
    mov dword [rel chs_state],1
    call chs_panel_build
    cmp eax,1
    jne .bad
    call time_monotonic_now_us
    mov [rel chs_panel_shown_us],rax
    mov eax,1
    ret
.bad:
    call chs_clear_intent
    xor eax,eax
    ret

; Lossless byte disclosure: all nonplain ASCII and \\ < > & become \\xHH.
; Lines have 31 characters; no untrusted renderer controls/markup are emitted.
chs_escape_question:
    lea rdi,[rel chs_lines]
    xor eax,eax
    mov ecx,CHS_QUESTION*4+64
    rep stosb
    lea rsi,[rel chs_question]
    lea rdi,[rel chs_lines]
    xor ecx,ecx
    xor r8d,r8d
.loop:
    cmp rcx,[rel chs_question_len]
    jae .done
    movzx eax,byte [rsi+rcx]
    cmp al,32
    jb .escape
    cmp al,126
    ja .escape
    cmp al,92
    je .escape
    cmp al,'<'
    je .escape
    cmp al,'>'
    je .escape
    cmp al,'&'
    je .escape
    call chs_emit
    jmp .next
.escape:
    mov edx,eax
    mov al,92
    call chs_emit
    mov al,'x'
    call chs_emit
    mov eax,edx
    shr eax,4
    call chs_hex
    call chs_emit
    mov eax,edx
    and eax,15
    call chs_hex
    call chs_emit
.next:
    inc ecx
    jmp .loop
.done:
    mov eax,r8d
    add eax,30
    xor edx,edx
    mov ecx,31
    div ecx
    test eax,eax
    jnz .lines
    inc eax
.lines:
    mov [rel chs_line_count],eax
    add eax,CHS_ROWS-1
    xor edx,edx
    mov ecx,CHS_ROWS
    div ecx
    mov [rel chs_pages],eax
    mov dword [rel chs_page],0
    mov dword [rel chs_seen],0
    ret
chs_hex:
    add al,'0'
    cmp al,'9'
    jbe .out
    add al,39
.out:
    ret
chs_emit:
    mov [rdi],al
    inc rdi
    inc r8d
    push rax
    push rdx
    mov eax,r8d
    xor edx,edx
    push rcx
    mov ecx,31
    div ecx
    pop rcx
    test edx,edx
    jnz .out
    inc rdi                            ; each physical line has NUL at byte31
.out:
    pop rdx
    pop rax
    ret

chs_panel_scan:
    mov eax,[rel chs_panel]
    cmp eax,WM_MAX
    jae .bad
    lea rcx,[rel wm_gen]
    mov edx,[rel chs_panel_gen]
    cmp [rcx+rax*4],edx
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+rax*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_title]
    lea rdx,[rel chs_title]
    cmp [rcx+rax*8],rdx
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+rax*4],WM_VISIBLE
    jne .bad
    ret
.bad:
    mov eax,-1
    ret

chs_panel_ok:
    call chs_panel_scan
    cmp eax,-1
    je .bad
    cmp eax,[rel wm_focus]
    jne .bad
    mov [rel chs_click_slot],eax
    mov edx,eax
    lea rcx,[rel wm_w]
    cmp dword [rcx+rdx*4],CHS_WIDTH
    jne .bad
    lea rcx,[rel wm_h]
    cmp dword [rcx+rdx*4],CHS_HEIGHT
    jne .bad
    call chs_source_visible
    cmp eax,1
    jne .bad
    ; Overlays/desktop widgets cannot cover this human decision surface.
    mov edx,[rel chs_panel]
    lea rcx,[rel wm_x]
    mov r8d,[rcx+rdx*4]
    lea rcx,[rel wm_y]
    mov r9d,[rcx+rdx*4]
    lea r10d,[r8d+CHS_WIDTH]
    lea r11d,[r9d+CHS_HEIGHT]
    mov ecx, r10d
    mov edx, r11d
    call calendar_overlaps
    test eax, eax
    jnz .bad

    xor ecx,ecx
    lea rdx,[rel wgt_tbl]
.loop:
    cmp ecx,[rel wgt_count]
    jae .widgets
    cmp ecx,WGT_MAX
    jae .bad
    cmp dword [rdx+WGI_TYPE],0
    je .next
    test dword [rdx+WGI_FLAGS],1
    jz .next
    mov rax,rdx                          ; Q 90205: the one predicate for paint, hover and press.
    call wgt_row_shown                   ; An unfocused window's closed menu paints nothing here.
    jc .next
    cmp dword [rdx+WGI_LAYER],1
    je .cover
    cmp dword [rdx+WGI_WIN],WGT_HOST_DESKTOP
    jne .next
.cover:
    mov eax,[rdx+WGI_X]
    cmp eax,r10d
    jge .next
    add eax,[rdx+WGI_W]
    cmp eax,r8d
    jle .next
    mov eax,[rdx+WGI_Y]
    cmp eax,r11d
    jge .next
    add eax,[rdx+WGI_H]
    cmp eax,r9d
    jg .bad
.next:
    add rdx,WGI_SZ
    inc ecx
    jmp .loop
.widgets:
    xor ecx,ecx
.check:
    lea rax,[rel chs_ids]
    mov eax,[rax+rcx*4]
    cmp eax,[rel wgt_count]
    jae .bad
    imul rax,WGI_SZ
    lea rdx,[rel wgt_tbl]
    add rax,rdx
    mov edx,[rel chs_panel]
    cmp [rax+WGI_WIN],edx
    jne .bad
    mov edx,WGT_TYPE_LABEL
    cmp ecx,CHS_PREV
    jb .type
    mov edx,WGT_TYPE_BUTTON
.type:
    cmp [rax+WGI_TYPE],edx
    jne .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    lea rdx,[rel chs_tokens]
    lea rdx,[rdx+rcx*8]
    cmp [rax+WGI_ID],rdx
    jne .bad
    inc ecx
    cmp ecx,CHS_COUNT
    jb .check
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Stock widgets, private tokens, every text set before the first widget paint.
; Opening focuses this panel; its decision buttons require that focus.
chs_panel_build:
    push rbx
    push r12
    cmp dword [rel fb_width],CHS_WIDTH
    jb .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    jc .bad
    cmp eax,CHS_TOP+CHS_HEIGHT
    jb .bad
    lea rdi,[rel chs_title]
    xor esi,esi
    mov edx,CHS_TOP
    mov ecx,CHS_WIDTH
    mov r8d,CHS_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .bad
    mov r12d,eax
    mov [rel chs_panel],eax
    mov [rel chs_click_slot],eax
    lea rdx,[rel wm_gen]
    mov ecx,[rdx+r12*4]
    mov [rel chs_panel_gen],ecx
    lea rdx,[rel wm_owner]
    mov qword [rdx+r12*8],WM_OWNER_CHROME
    mov edi,CHS_COUNT
    call wgt_reserve_run
    test eax,eax
    js .bad
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    mov edi,WGT_TYPE_LABEL-1
    cmp ebx,CHS_PREV
    jb .type
    mov edi,WGT_TYPE_BUTTON-1
.type:
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .fail
    lea rdx,[rel chs_ids]
    mov [rdx+rbx*4],eax
    mov edi,eax
    call wgt_slot_ptr
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_EDIT],0
    mov dword [rax+WGI_LAYER],0
    lea rdx,[rel chs_tokens]
    lea rdx,[rdx+rbx*8]
    mov [rax+WGI_ID],rdx
    lea rdx,[rel wm_x]                  ; WGI coordinates are absolute
    mov edx,[rdx+r12*4]
    add edx,16
    mov [rax+WGI_X],edx
    lea rdx,[rel wm_y]
    mov edx,[rdx+r12*4]
    cmp ebx,CHS_PREV
    jb .row
    add edx,290
    mov [rax+WGI_Y],edx
    mov dword [rax+WGI_W],120
    mov dword [rax+WGI_H],30
    mov ecx,ebx
    sub ecx,CHS_PREV
    imul ecx,132
    add [rax+WGI_X],ecx
    jmp .next
.row:
    mov ecx,ebx
    imul ecx,20
    lea edx,[rdx+rcx+32]
    mov [rax+WGI_Y],edx
    mov dword [rax+WGI_W],520
    mov dword [rax+WGI_H],18
.next:
    inc ebx
    cmp ebx,CHS_COUNT
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    call chs_render
    cmp dword [rel chs_seen],1           ; the first page was actually presented
    jb .bad
    mov eax,1
    jmp .out
.fail:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; A page is credited only while the checked focused panel shows it. A row past
; the question is empty: never a read beyond the disclosed lines.
chs_render:
    push rbx
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    lea rsi,[rel chs_local_text]
    cmp ebx,0
    je .text
    lea rsi,[rel chs_scope_text]
    cmp ebx,1
    je .text
    lea rsi,[rel chs_pages_text]
    cmp ebx,2
    je .text
    cmp ebx,CHS_PREV
    jae .footer
    mov eax,[rel chs_page]
    imul eax,CHS_ROWS
    lea eax,[rax+rbx-3]
    lea rsi,[rel chs_empty]
    cmp eax,[rel chs_line_count]
    jae .text
    shl eax,5
    lea rsi,[rel chs_lines]
    add rsi,rax
    jmp .text
.footer:
    lea rsi,[rel chs_previous_text]
    cmp ebx,CHS_PREV
    je .text
    lea rsi,[rel chs_next_text]
    cmp ebx,CHS_NEXT
    je .text
    lea rsi,[rel chs_cancel_text]
.text:
    lea rax,[rel chs_ids]
    mov edi,[rax+rbx*4]
    call wgt_set_text
    inc ebx
    cmp ebx,CHS_CONFIRM
    jb .loop
    call chs_panel_ok
    cmp eax,1
    jne .confirm
    mov eax,[rel chs_page]
    inc eax
    cmp eax,[rel chs_seen]
    jbe .confirm
    mov [rel chs_seen],eax
.confirm:
    lea rsi,[rel chs_review_text]
    mov eax,[rel chs_seen]
    cmp eax,[rel chs_pages]
    jb .button
    lea rsi,[rel chs_confirm_text]
.button:
    lea rax,[rel chs_ids]
    mov edi,[rax+CHS_CONFIRM*4]
    call wgt_set_text
    dec byte [rel wgt_paint_suspended]
    call wmx_draw_all
    pop rbx
    ret

chs_panel_close:
    call chs_panel_scan
    mov dword [rel chs_panel],-1
    cmp eax,-1
    je .out
    mov edi,eax
    jmp wmx_close_slot
.out:
    ret

chs_clear_intent:
    mov dword [rel chs_state],0
    mov dword [rel chs_action],0
    call chs_panel_close
    lea rdi,[rel chs_descriptor]
    xor eax,eax
    mov ecx,(CHS_DESC+256+1088)/8
    cld
    rep stosq
    ret

chat_send_retire:
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    mov byte [rel chs_live],0
    call chs_clear_intent
    lea rdi,[rel chs_live_data]
    xor eax,eax
    mov ecx,(chs_live_end-chs_live_data)/8
    rep stosq
.out:
    ret

%include "core/abi/wdata.inc"
%macro WDATA_chat_send 0
align 8
chs_initialized: db 0
align 8
chs_previous_click: dq 0
chs_panel_shown_us: dq 0
chs_floor: dq 0
chs_panel: dd -1
chs_panel_gen: dd 0
chs_title: db 'Confirm chat request',0
chs_prompt_id: db 'chat_prompt',0
chs_status_id: db 'chat_status',0
chs_provider_id: db 'chat_provider',0
chs_local_name: db 'chat_local',0
chs_claude_name: db 'chat_claude',0
chs_codex_name: db 'chat_codex',0
chs_send_name: db 'chat_send',0
chs_cancel_name: db 'chat_cancel',0
chs_screen_name: db 'chat_snapshot',0
chs_local_text: db 'Local model; no cloud fallback',0
chs_cloud_text: db 'Cloud route unavailable',0
chs_no_screen: db 'Screen attach unavailable',0
chs_claude_text: db 'Cloud: Claude',0
chs_codex_text: db 'Cloud: Codex',0
chs_empty: db 0
chs_scope_text: db 'Question only; no screen sent',0
chs_pages_text: db 'Review every question page',0
chs_previous_text: db 'Previous',0
chs_next_text: db 'Next',0
chs_cancel_text: db 'Cancel',0
chs_confirm_text: db 'Confirm request',0
chs_review_text: db 'Review all pages',0
chs_not_sent: db 'Confirmed; not sent yet',0
chs_cancelled: db 'Request cancelled',0
chs_expired: db 'Request expired; nothing sent',0
chs_refused_text: db 'Nothing sent: check question',0
chs_tokens: times CHS_COUNT dq 0
chs_source_names: times CHS_SOURCES dq 0
%endmacro
WDATA_DEFER WDATA_chat_send
%macro WDATA_chat_send_bss 0
alignb 8
chs_live_data:
chs_live: resq 1
chs_owner_handle: resq 1
chs_session_handle: resq 1
chs_handle: resq 1
chs_attempt: resq 1
chs_window: resq 1
chs_reset: resq 1
chs_instance: resq 1
chs_rawgen: resq 1
chs_route: resd 1
chs_state: resd 1
chs_action: resd 1
chs_click_slot: resd 1
chs_click_z: resd 1
chs_click_inj: resd 1
chs_prompt_widget: resd 1
chs_click_xy: resq 1
chs_click_fb: resq 1
chs_question_len: resq 1
chs_page: resd 1
chs_pages: resd 1
chs_seen: resd 1
chs_line_count: resd 1
chs_ids: resd CHS_COUNT
alignb 8
chs_vm: resb 128
chs_vm_check: resb 128
chs_binding: resb 48
chs_binding_check: resb 48
chs_script: resb 384
chs_script_check: resb 384
chs_live_end:
chs_descriptor: resb CHS_DESC
chs_question: resb 256
chs_lines: resb 1088
chs_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_chat_send_bss
