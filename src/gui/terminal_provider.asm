;; MODULE gui/terminal_provider
;; LAYER 6
;; PURPOSE Finite native GUI Terminal planner and original-request handler delegation.
;; EXPORTS terminal_gui_provider_init, terminal_gui_provider_table
;; IMPORTS gui/snapshot, gui/window_mgmt, gui/chat_app, gui/widget, gui/form_events, gui/summon_palette, gui/terminal_app, gui/app_launcher, gui/app_launch_flow, sec/session, sec/terminal_command, sec/terminal_policy, svc/command, svc/command_auth, core/lib/sha256, core/smp, core/csprng
;; CAPS CAP_GUI
;; OWNER saga:live_terminal_consent
;; CONTEXT: bsp_only
; Codex / rc-live-claude. Native pointers only. No guest-selected pointer,
; borrowed app authority, OWNER substitution, retry or generic GUI evaluator.
%include "core/abi/wdata.inc"

; Called by SEC native composition after runtime initialization, before restore.
; RAX table48 or0. SEC alone registers kind1 in its fanout.
terminal_gui_provider_init:
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp qword [rel tg_initialized],1
    je .key_ready
    lea rdi,[rel tg_window_key+32]
    mov esi,32
    call csprng_generate
    test eax,eax
    jnz .bad
    mov qword [rel tg_initialized],1
.key_ready:
    lea rdi,[rel terminal_policy_copyout]
    call snapshot_terminal_configure
    cmp eax,1
    jne .bad
    lea rax,[rel tg_snapshot_handler]
    mov [rel snapshot_terminal_handler_op],rax
    lea rax,[rel tg_move_handler]
    mov [rel wmx_terminal_move_op],rax
    lea rax,[rel tg_close_handler]
    mov [rel chat_terminal_close_op],rax
    lea rax,[rel tg_fill_handler]
    mov [rel wgt_terminal_fill_op],rax
    lea rax,[rel tg_launch_handler]
    mov [rel terminal_terminal_launch_op],rax
    ; org0 images relocate without data fixups. Publish actual runtime
    ; pointers only after every idle/configuration guard has succeeded.
    lea rax,[rel tg_plan]
    mov [rel terminal_gui_provider_table],rax
    lea rax,[rel tg_validate]
    mov [rel terminal_gui_provider_table+8],rax
    lea rax,[rel tg_execute]
    mov [rel terminal_gui_provider_table+16],rax
    lea rax,[rel tg_prepare]
    mov [rel terminal_gui_provider_table+24],rax
    lea rax,[rel tg_restore]
    mov [rel terminal_gui_provider_table+32],rax
    lea rax,[rel tg_retire]
    mov [rel terminal_gui_provider_table+40],rax
    lea rax,[rel terminal_gui_provider_table]
    ret
.bad:
    xor eax,eax
    ret

; RSI input, RDI exact literal prefix ->1 and advanced RSI, else0.
tg_prefix:
    mov al,[rdi]
    test al,al
    jz .ok
    cmp al,[rsi]
    jne .bad
    inc rdi
    inc rsi
    jmp tg_prefix
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Strict unsigned canonical decimal <=65535, no sign/leading zero/junk.
; RSI advances to separator or NUL; EAX value, EDX1 success/0 refusal.
tg_number:
    xor eax,eax
    cmp byte [rsi],'0'
    jne .nonzero
    inc rsi
    cmp byte [rsi],'0'
    jb .done
    cmp byte [rsi],'9'
    jbe .bad
    jmp .done
.nonzero:
    cmp byte [rsi],'1'
    jb .bad
    cmp byte [rsi],'9'
    ja .bad
.loop:
    movzx edx,byte [rsi]
    sub edx,'0'
    cmp edx,9
    ja .done
    imul eax,eax,10
    add eax,edx
    cmp eax,65535
    ja .bad
    inc rsi
    jmp .loop
.done:
    mov edx,1
    ret
.bad:
    xor edx,edx
    ret

; RDI frame1088, RSI desc256 ->1/0. SEC has privately copied/checked frame.
; Canonical text remains exact: no aliases, hooks, suffixes or coercion.
tg_plan:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    call tg_retire
    cmp dword [r12+4],1
    jne .bad
    mov ecx,[r12+28]
    test ecx,ecx
    jz .bad
    cmp ecx,1023
    ja .bad
    lea rsi,[r12+64]
    lea rdi,[rel tg_command]
    rep movsb
    cmp byte [rsi],0
    jne .bad
    lea rsi,[rel tg_command]
    lea rdi,[rel tg_snapshot_prefix]
    call tg_prefix
    test eax,eax
    jz .move
    mov qword [rel tg_op],16
    push rsi
    lea rdi,[rel tg_desktop]
    call tg_prefix
    test eax,eax
    pop rsi
    jz .active
    cmp byte [rsi+7],0
    jne .bad
    mov qword [rel tg_slot],WM_MAX
    jmp .registry
.active:
    mov qword [rel tg_op],17
    push rsi
    lea rdi,[rel tg_active]
    call tg_prefix
    test eax,eax
    pop rsi
    jz .window
    cmp byte [rsi+6],0
    jne .bad
    mov eax,[rel wm_focus]
    mov [rel tg_slot],rax
    jmp .registry
.window:
    mov qword [rel tg_op],18
    push rsi
    lea rdi,[rel tg_window]
    call tg_prefix
    test eax,eax
    jnz .window_number
    pop rsi
    mov qword [rel tg_op],19
    lea rdi,[rel tg_ui]
    call tg_prefix
    test eax,eax
    jz .bad
    jmp .slot_number
.window_number:
    add rsp,8
.slot_number:
    call tg_number
    test edx,edx
    jz .bad
    mov [rel tg_slot],rax
    cmp byte [rsi],0
    jne .bad
    jmp .registry
.move:
    lea rsi,[rel tg_command]
    lea rdi,[rel tg_move_prefix]
    call tg_prefix
    test eax,eax
    jz .close
    mov qword [rel tg_op],34
    call tg_number
    test edx,edx
    jz .bad
    mov [rel tg_slot],rax
    cmp byte [rsi],' '
    jne .bad
    inc rsi
    call tg_number
    test edx,edx
    jz .bad
    mov [rel tg_x],rax
    cmp byte [rsi],' '
    jne .bad
    inc rsi
    call tg_number
    test edx,edx
    jz .bad
    mov [rel tg_y],rax
    cmp byte [rsi],0
    jne .bad
    jmp .registry
.close:
    lea rsi,[rel tg_command]
    lea rdi,[rel tg_close_prefix]
    call tg_prefix
    test eax,eax
    jz .fill
    mov qword [rel tg_op],35
    jmp .slot_number
.fill:
    lea rsi,[rel tg_command]
    lea rdi,[rel tg_fill_prefix]
    call tg_prefix
    test eax,eax
    jz .launch
    mov qword [rel tg_op],32
    call tg_number
    test edx,edx
    jz .bad
    mov [rel tg_widget],rax
    push rsi
    lea rdi,[rel tg_clear_suffix]
    call tg_prefix
    test eax,eax
    jz .ordinary_fill
    cmp byte [rsi],0
    jne .ordinary_fill
    pop rsi
    mov edi,[rel tg_widget]
    call wgt_sensitive_current
    test rax,rax
    jz .bad
    mov [rel tg_field],rax
    mov qword [rel tg_clear],1
    mov rdx,[rel wgt_secret_revision]
    cmp rdx,-2                       ; saturating revisions cannot bind a result
    jae .bad
    mov [rel tg_clear_revision],rdx
    jmp .field_common
.ordinary_fill:
    pop rsi
    lea rdi,[rel tg_value_prefix]
    call tg_prefix
    test eax,eax
    jz .bad
    mov [rel tg_value],rsi
    xor ecx,ecx
.value:
    movzx eax,byte [rsi+rcx]
    test eax,eax
    jz .value_end
    cmp eax,32
    jb .bad
    cmp eax,126
    ja .bad
    inc ecx
    cmp ecx,39
    jbe .value
    jmp .bad
.value_end:
    test ecx,ecx
    jz .bad
    mov [rel tg_value_length],rcx
    mov edi,[rel tg_widget]
    call tg_field_current
    test rax,rax
    jnz .field_admitted
    ; Passive original pre-consent refusal only. Never plans, grants or fills.
    mov edi,[rel tg_widget]
    mov rsi,r12                    ; SEC's actual privately copied frame
    call wgt_guard_provider_refused
    jmp .bad
.field_admitted:
    mov [rel tg_field],rax
.field_common:
    mov rcx,[rel wgt_textfield_event_hook2]
    mov [rel tg_field_hook],rcx
    mov ecx,[rax+WGI_WIN]
    mov [rel tg_slot],rcx
    mov ecx,[rax+WGI_EDIT]
    mov [rel tg_edit],rcx
    cmp qword [rel tg_clear],1
    je .field_birth
    call wgt_tf_buf
    mov [rel tg_value_buffer],rax
    mov [rel tg_value_capacity],rcx
.field_birth:
    mov edi,[rel tg_widget]
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    mov [rel tg_birth],rax
    jmp .registry
.launch:
    lea rsi,[rel tg_command]
    lea rdi,[rel tg_launch_prefix]
    call tg_prefix
    test eax,eax
    jz .bad
    push rsi
    call app_launch_flow_available
    cmp eax,1
    pop rsi
    jne .bad
    push rsi
    lea rdi,[rel tg_launch_operand]
    call app_launcher_terminal_snapshot
    cmp eax,1
    pop rsi
    jne .bad
    lea rax,[rel app_launch_flow_begin]
    cmp [rel tg_launch_operand+392],rax
    jne .bad                         ; only the actual native owner-policy flow
    lea rdi,[rel tg_launch_operand+96]
    xor ecx,ecx
.bundle:
    mov al,[rdi+rcx]
    cmp al,[rsi+rcx]
    jne .bad
    test al,al
    jz .bundle_end
    inc ecx
    cmp ecx,63
    jbe .bundle
    jmp .bad
.bundle_end:
    test ecx,ecx
    jz .bad
    mov rax,[rel session_key_handle]
    test rax,rax
    jz .bad
    mov [rel tg_launch_session_key],rax
    mov qword [rel tg_op],33
    mov rax,[rel tg_launch_operand+8]
    mov [rel tg_target],rax
    mov rax,[rel tg_launch_operand+384]
    mov [rel tg_gen],rax
    ; Key64 = boot nonce24 + full verified digest32 + attempt8. No scope
    ; persistence: op33 is always the original physical one-action authority.
    lea rsi,[rel tg_window_key+32]
    lea rdi,[rel tg_launch_key]
    mov ecx,3
    rep movsq
    lea rsi,[rel tg_launch_operand+32]
    mov ecx,4
    rep movsq
    mov rax,[rel tg_gen]
    stosq
.registry:
    call tg_registry
    test eax,eax
    jz .bad
    mov [rel tg_verb],rdx
    cmp qword [rel tg_op],33
    je .identity
    cmp qword [rel tg_op],16
    je .identity
    mov edi,[rel tg_slot]
    call tg_window_current
    test eax,eax
    jz .bad
    mov [rel tg_target],rax
    mov ecx,[rel tg_slot]
    lea rax,[rel wm_gen]
    mov eax,[rax+rcx*4]
    mov [rel tg_gen],rax
    lea rax,[rel wm_owner]
    mov rax,[rax+rcx*8]
    mov [rel tg_owner],rax
    lea rax,[rel wm_w]
    mov eax,[rax+rcx*4]
    mov [rel tg_width],rax
    lea rax,[rel wm_h]
    mov eax,[rax+rcx*4]
    mov [rel tg_height],rax
    mov edi,[rel tg_slot]
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    mov [rel tg_lifetime],rax
    cmp qword [rel tg_op],32
    jne .identity
    cmp qword [rel tg_clear],1
    je .identity
    ; Read the nonsecret preimage only after native host protection checks.
    mov rax,[rel tg_value_buffer]
    mov rcx,[rel tg_value_capacity]
    cmp ecx,255
    ja .bad
    mov rdx,[rel tg_field]
    mov edx,[rdx+WGI_VLEN]
    cmp rdx,rcx
    ja .bad
    cmp byte [rax+rdx],0
    jne .bad
    mov [rel tg_before_length],rdx
    mov rsi,rax
    lea rdi,[rel tg_before]
    lea rcx,[rdx+1]
    rep movsb
.identity:
    mov rax,[rel tg_op]
    mov [r13+56],rax
    call tg_scope_id
    mov [r13+64],rax          ; disjoint native scope identity, not input label
    mov rax,[rel tg_target]
    mov [r13+72],rax
    mov rax,[rel tg_gen]
    mov [r13+80],rax
    mov qword [r13+88],0
    lea rdi,[r13+136]
    call tg_key
    mov ecx,8
    rep movsq
    cmp qword [rel tg_op],33
    je .hash
    cmp qword [rel tg_op],18
    jb .hash
    mov rax,[rel tg_lifetime]
    mov [r13+192],rax         ; last8 key bytes bind saturating slot lifetime
    cmp qword [rel tg_op],32
    jne .hash
    mov [r13+184],rax         ; fill binds both window and widget lifetimes
    mov rax,[rel tg_birth]
    mov [r13+192],rax
.hash:
    mov edx,[r12+28]
    mov [rel tg_length],rdx
    lea rdi,[rel tg_hash]
    lea rsi,[rel tg_command]
    call sha256_hash
    test rax,rax
    jnz .bad
    mov qword [rel tg_ready],1
    cmp qword [rel tg_op],32
    jne .observed_plan
    mov edi,[rel tg_widget]
    mov rsi,r12
    cmp qword [rel tg_clear],1
    jne .public_plan
    call wgt_sensitive_plan
    jmp .observed_plan
.public_plan:
    call wgt_provider_plan
.observed_plan:
    mov eax,1
    jmp .out
.bad:
    call tg_retire
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Exact-window grants include a native random boot lifetime. Repeated slot/gen
; values in a later boot cannot resurrect an old saved window selection.
tg_key:
    lea rsi,[rel tg_launch_key]
    cmp qword [rel tg_op],33
    je .out
    lea rsi,[rel tg_root_key]
    cmp qword [rel tg_op],18
    jb .out
    lea rsi,[rel tg_window_key]
.out:
    ret

tg_scope_id:
    mov rax,[rel tg_gen]
    cmp qword [rel tg_op],33
    je .out
    xor eax,eax
    cmp qword [rel tg_op],18
    jb .root
    mov rax,[rel tg_target]
    shl rax,8
.root:
    or rax,[rel tg_op]
    cmp qword [rel tg_op],32
    jne .out
    mov rdx,[rel tg_widget]
    shl rdx,40
    or rax,rdx
.out:
    ret

; Resolve the actual registered handler and its text/destructive contract.
; Same-named substituted native handler is not an approved operation.
tg_registry:
    push rbx
    push r12
    push r13
    mov rax,[rel tg_op]
    lea rdi,[rel tg_snapshot_name]
    lea r12,[rel snapshot_native_handler]
    xor ebx,ebx
    cmp eax,19
    jbe .lookup
    mov ebx,1
    cmp eax,33
    jne .fill
    lea rdi,[rel tg_launch_name]
    lea r12,[rel terminal_cmd_launch]
    jmp .lookup
.fill:
    cmp eax,32
    jne .move
    lea rdi,[rel tg_fill_name]
    lea r12,[rel cmd_verb_widgetset]
    jmp .lookup
.move:
    lea rdi,[rel tg_move_name]
    lea r12,[rel cmd_verb_winmove]
    cmp eax,34
    je .lookup
    lea rdi,[rel tg_close_name]
    lea r12,[rel cmd_verb_close]
.lookup:
    call command_lookup
    cmp rax,-1
    je .bad
    mov r13,rax
    imul rax,48
    lea rcx,[rel verb_table]
    add rcx,rax
    cmp [rcx+8],r12
    jne .bad
    cmp qword [rcx+16],0
    jne .bad
    cmp qword [rcx+24],ARGT_TEXT
    jne .bad
    cmp [rcx+40],rbx
    jne .bad
    mov rdx,r13
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Native lifetime/protected class before any title/widget getter or mutation.
tg_window_current:
    cmp edi,WM_MAX-1
    jae .bad
    lea rax,[rel wm_no_history]
    cmp byte [rax+rdi],0
    jne .bad
    lea rax,[rel wm_owner]
    cmp qword [rax+rdi*8],WM_OWNER_CHROME
    je .bad
    jmp wmx_window_id
.bad:
    xor eax,eax
    ret

; Resolve only a live, visible, enabled stock textfield and its exact stock
; setter/name/role. No custom setter, label/secret/password or generic property.
; EDI id -> native widget pointer/0. Does not read the field's value bytes.
tg_field_current:
    push rbx
    mov ebx,edi
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    mov edi,ebx
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],WGT_TYPE_TEXTFIELD
    jne .bad
    mov ecx,[rel wgt_secret_type]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    je .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    cmp dword [rax+WGI_BIND],0
    jne .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED | WGT_EDIT_SECTEXT
    jnz .bad
    mov rcx,[rel wgt_textfield_event_hook2]
    test rcx,rcx
    jz .hook_ok
    lea rdx,[rel summon_palette_text_event]
    cmp rcx,rdx
    jne .bad
.hook_ok:
    lea rcx,[rel str_wt_textfield]
    cmp [rax+WGI_ROLE],rcx
    jne .bad
    lea rdx,[rel wgt_types+WT_SZ]
    cmp [rdx+WT_NAME],rcx
    jne .bad
    lea rcx,[rel wgt_textfield_set]
    cmp [rdx+WT_SET],rcx
    jne .bad
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Validate repeatedly at pending, approval, handler, copyout and result paging.
; Private plan remains until SEC retires it; no guest field can replace it.
tg_validate:
    push rbx
    push r12
    mov rbx,rdi
    cmp qword [rel tg_ready],1
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rbx+88],0
    jne .bad
    mov rax,[rel tg_op]
    cmp rax,[rbx+56]
    jne .bad
    call tg_scope_id
    cmp [rbx+64],rax
    jne .bad
    mov rax,[rel tg_target]
    cmp rax,[rbx+72]
    jne .bad
    mov rax,[rel tg_gen]
    cmp rax,[rbx+80]
    jne .bad
    mov rax,[rel tg_length]
    cmp rax,[rbx+96]
    jne .bad
    lea rsi,[rel tg_hash]
    lea rdi,[rbx+104]
    mov ecx,4
    repe cmpsq
    jne .bad
    call tg_key
    lea rdi,[rbx+136]
    mov ecx,8
    cmp qword [rel tg_op],33
    je .compare_key
    cmp qword [rel tg_op],18
    jb .compare_key
    mov ecx,7
    cmp qword [rel tg_op],32
    jne .compare_key
    mov ecx,6
.compare_key:
    repe cmpsq
    jne .bad
    cmp qword [rel tg_op],33
    je .registry
    cmp qword [rel tg_op],18
    jb .registry
    mov rax,[rel tg_lifetime]
    cmp qword [rel tg_op],32
    jne .window_key
    cmp [rbx+184],rax
    jne .bad
    mov rax,[rel tg_birth]
.window_key:
    cmp [rbx+192],rax
    jne .bad
.registry:
    call tg_registry
    test eax,eax
    jz .bad
    cmp rdx,[rel tg_verb]
    jne .bad
    cmp qword [rel tg_op],33
    je .launch
    cmp qword [rel tg_done],2
    je .closed_receipt
    cmp qword [rel tg_op],16
    je .records
    mov edi,[rel tg_slot]
    call tg_window_current
    cmp rax,[rel tg_target]
    jne .bad
    mov ecx,[rel tg_slot]
    lea rax,[rel wm_gen]
    mov eax,[rax+rcx*4]
    cmp rax,[rel tg_gen]
    jne .bad
    lea rax,[rel wm_owner]
    mov rax,[rax+rcx*8]
    cmp rax,[rel tg_owner]
    jne .bad
    mov edi,[rel tg_slot]
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    cmp rax,[rel tg_lifetime]
    jne .bad
    mov ecx,[rel tg_slot]
    cmp qword [rel tg_op],17
    jne .geometry
    cmp ecx,[rel wm_focus]
    jne .bad
.geometry:
    cmp qword [rel tg_op],34
    jne .records
    lea rax,[rel wm_w]
    mov eax,[rax+rcx*4]
    cmp rax,[rel tg_width]
    jne .bad
    lea rax,[rel wm_h]
    mov eax,[rax+rcx*4]
    cmp rax,[rel tg_height]
    jne .bad
.records:
    cmp qword [rel tg_op],32
    jne .snapshot
    call tg_validate_field
    test eax,eax
    jz .bad
.snapshot:
    cmp qword [rel tg_done],3
    jne .ok
    xor r12d,r12d
.lifetimes:
    mov edi,r12d
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    lea rdx,[rel tg_snapshot_lifetimes]
    cmp rax,[rdx+r12*8]
    jne .bad
    inc r12d
    cmp r12d,WM_MAX
    jb .lifetimes
    lea rdi,[rel tg_result]
    mov rsi,[rel tg_result_length]
    call snapshot_terminal_records_current
    test eax,eax
    jnz .bad
    jmp .ok
.launch:
    mov rax,[rel session_key_handle]
    test rax,rax
    jz .bad
    cmp rax,[rel tg_launch_session_key]
    jne .bad
    cmp qword [rel tg_done],0
    jne .launch_receipt
    call app_launch_flow_available
    cmp eax,1
    jne .bad
    jmp .launch_native
.launch_receipt:
    cmp qword [rel tg_done],5
    jne .bad
    cmp qword [rel tg_launch_minted],1
    jne .bad
    lea rdi,[rel tg_launch_desc]
    mov rsi,rbx
    mov ecx,32
    repe cmpsq
    jne .bad
.launch_native:
    lea rdi,[rel tg_launch_operand]
    call app_launcher_terminal_validate
    cmp eax,1
    jne .bad
    jmp .ok
.closed_receipt:
    ; Only the exact action which executed may read its closed tombstone.
    ; A reopened slot, changed full generation or replacement owner denies.
    mov rsi,rbx
    lea rdi,[rel tg_executed_desc]
    mov ecx,32
    repe cmpsq
    jne .bad
    mov ecx,[rel tg_slot]
    lea rax,[rel wm_state]
    cmp dword [rax+rcx*4],WM_CLOSED
    jne .bad
    lea rax,[rel wm_owner]
    cmp qword [rax+rcx*8],0
    jne .bad
    lea rax,[rel wm_gen]
    mov eax,[rax+rcx*4]
    cmp rax,[rel tg_closed_gen]
    jne .bad
    mov edi,[rel tg_slot]
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    mov rdx,[rel tg_lifetime]
    inc rdx
    jz .bad
    cmp rax,rdx
    jne .bad
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; The exact field birth, buffer and edit policy stay fixed through effect and
; receipt. A user edit after completion invalidates the receipt, not a retry.
tg_validate_field:
    push rbx
    mov edi,[rel tg_widget]
    cmp qword [rel tg_clear],1
    jne .public_field
    call wgt_sensitive_current
    jmp .field_resolved
.public_field:
    call tg_field_current
.field_resolved:
    test rax,rax
    jz .bad
    cmp rax,[rel tg_field]
    jne .bad
    mov rcx,[rel wgt_textfield_event_hook2]
    cmp rcx,[rel tg_field_hook]
    jne .bad
    mov ecx,[rax+WGI_WIN]
    cmp rcx,[rel tg_slot]
    jne .bad
    mov ecx,[rax+WGI_EDIT]
    cmp rcx,[rel tg_edit]
    jne .bad
    mov rbx,rax
    cmp qword [rel tg_clear],1
    je .clear_field
    call wgt_tf_buf
    cmp rax,[rel tg_value_buffer]
    jne .bad
    cmp rcx,[rel tg_value_capacity]
    jne .bad
    mov edi,[rel tg_widget]
    call wgt_birth_lifetime
    cmp rax,[rel tg_birth]
    jne .bad
    cmp qword [rel tg_done],4
    je .after
    mov eax,[rbx+WGI_VLEN]
    cmp rax,[rel tg_before_length]
    jne .bad
    mov rcx,rax
    inc rcx
    mov rdi,[rel tg_value_buffer]
    lea rsi,[rel tg_before]
    repe cmpsb
    jne .bad
    jmp .ok
.clear_field:
    mov edi,[rel tg_widget]
    call wgt_birth_lifetime
    cmp rax,[rel tg_birth]
    jne .bad
    mov rax,[rel tg_clear_revision]
    cmp qword [rel tg_done],4
    jne .clear_before
    inc rax
    cmp rax,[rel wgt_secret_revision]
    jne .bad
    cmp dword [rel wgt_secret_owner],-1
    jne .bad
    cmp dword [rel wgt_secret_len],0
    jne .bad
    cmp dword [rbx+WGI_VLEN],0
    jne .bad
    jmp .ok
.clear_before:
    cmp rax,[rel wgt_secret_revision]
    jne .bad
    jmp .ok
.after:
    mov eax,[rbx+WGI_VLEN]
    cmp rax,[rel tg_value_length]
    jne .bad
    mov rdi,[rel tg_value_buffer]
    mov rsi,[rel tg_value]
    mov rcx,[rel tg_value_length]
    inc rcx
    repe cmpsb
    jne .bad
.ok:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI desc, RSI private output, RDX original frozen frame, ECX capacity.
tg_execute:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    cmp ecx,65536
    jne .bad
    cmp qword [rel tg_dispatching],0
    jne .bad
    cmp qword [rel tg_done],0
    jne .bad
    call tg_validate
    cmp eax,1
    jne .bad
    lea rdi,[rel tg_command]
    lea rsi,[r13+64]
    mov ecx,1024
    repe cmpsb
    jne .bad
    lea rdi,[rel tg_executed_desc]
    mov rsi,rbx
    mov ecx,32
    rep movsq
    lea rdi,[rel tg_req]
    xor eax,eax
    mov ecx,13
    rep stosq
    mov rax,[rel tg_verb]
    mov [rel tg_req],rax
    lea rax,[rel tg_command]
.find_arg:
    cmp byte [rax],' '
    je .arg
    cmp byte [rax],0
    je .bad
    inc rax
    jmp .find_arg
.arg:
    inc rax
    mov [rel tg_req+32],rax
    mov qword [rel tg_dispatching],1
    mov rdi,rbx
    lea rsi,[rel tg_req]
    lea rdx,[rel tg_rsp]
    call terminal_policy_command_dispatch
    mov qword [rel tg_dispatching],0
    test eax,eax
    jnz .error
    cmp qword [rel tg_done],0
    je .bad
    mov rdi,rbx
    call terminal_policy_copyout
    cmp eax,1
    jne .bad
    mov rcx,[rel tg_result_length]
    mov r13,rcx
    mov rdi,r12
    lea rsi,[rel tg_result]
    rep movsb
    mov rdi,rbx
    call terminal_policy_copyout
    cmp eax,1
    jne .wipe
    mov edx,r13d
    xor eax,eax
    jmp .out
.wipe:
    mov rdi,r12
    mov rcx,r13
    xor eax,eax
    rep stosb
.bad:
    mov eax,CMDE_AUTHDENY
.error:
    xor edx,edx
.out:
    lea rsi,[rel tg_executed_desc]
    call wgt_provider_result
    pop r13
    pop r12
    pop rbx
    ret

; Actual SNAPSHOT registry leaf, original Terminal CMDREQ only. Read authority
; remains checked by SEC at the original request and by the snapshot bridge.
tg_snapshot_handler:
    mov edx,0
    jmp tg_handler
; MOVE/CLOSE callbacks return -1 to retain every ordinary handler's old gate.
tg_move_handler:
    cmp qword [rel tg_dispatching],1
    jne tg_unhandled
    mov edx,34
    jmp tg_handler
tg_close_handler:
    cmp qword [rel tg_dispatching],1
    jne tg_unhandled
    mov edx,35
    jmp tg_handler
tg_launch_handler:
    cmp qword [rel tg_dispatching],1
    jne tg_unhandled
    mov edx,33
    jmp tg_handler
tg_fill_handler:
    cmp qword [rel tg_dispatching],1
    jne tg_unhandled
    mov edx,32
    jmp tg_handler
tg_unhandled:
    mov eax,-1
    ret

tg_handler:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    cmp qword [rel tg_dispatching],1
    jne .bad
    cmp qword [rel tg_done],0
    jne .bad
    test edx,edx
    jz .read
    cmp rdx,[rel tg_op]
    jne .bad
    ; This exact original-request check also revalidates every native operand.
    call terminal_policy_command_effect
    cmp eax,1
    jne .bad
    mov r13,[rel tg_slot]
    mov r14,[rel tg_gen]
    mov edi,r13d
    cmp qword [rel tg_op],33
    je .launch
    cmp qword [rel tg_op],32
    je .fill
    cmp qword [rel tg_op],35
    je .close
    mov esi,[rel tg_x]
    mov edx,[rel tg_y]
    call wmx_move_slot
    mov qword [rel tg_done],1
    jmp .receipt
.launch:
    ; The original AUTH11 leaf just consumed the exact approved effect. This
    ; private capsule derives continuation from that one effect, not a ticket
    ; alias, ambient OWNER, a new command or a copied request.
    lea rdi,[rel tg_launch_desc]
    lea rsi,[rel tg_executed_desc]
    mov ecx,32
    rep movsq
    mov qword [rel tg_launch_minted],1
    lea rdi,[rel tg_launch_operand]
    lea rsi,[rel tg_launch_current]
    call app_launcher_terminal_queue
    cmp eax,1
    jne .launch_failed
    mov qword [rel tg_done],5
    lea rsi,[rel tg_pending_receipt]
    lea rdi,[rel tg_result]
    mov ecx,tg_pending_receipt_end-tg_pending_receipt
    rep movsb
    mov qword [rel tg_result_length],tg_pending_receipt_end-tg_pending_receipt
    jmp .copyout
.launch_failed:
    mov qword [rel tg_launch_minted],0
    jmp .bad
.fill:
    cmp qword [rel tg_clear],1
    jne .public_fill
    ; SEC has consumed the exact original approved action above. No byte read,
    ; setter bypass, scope mint, stored grant, network or credential operation.
    call wgt_secret_clear
    mov edi,[rel tg_widget]
    call wgt_draw_id
    xor eax,eax
    lea rsi,[rel tg_executed_desc]
    call wgt_sensitive_set_result
    mov qword [rel tg_done],4
    jmp .receipt
.public_fill:
    mov edi,[rel tg_widget]
    lea rsi,[rel str_wf_value]
    mov rdx,[rel tg_value]
    call wgt_textfield_set
    lea rsi,[rel tg_executed_desc]
    call wgt_provider_set_result
    test eax,eax
    jnz .bad
    mov qword [rel tg_done],4
    jmp .receipt
.close:
    call wmx_close_slot
    ; Preserve the real CLOSE handler's living Chat tile behavior.
    cmp r13d,CHAT_SLOT
    jne .closed
    call boot_ms_now
    mov [rel chat_closed_ms],rax
.closed:
    mov eax,r14d
    inc eax
    and eax,0xFFFFFF
    jnz .generation
    inc eax
.generation:
    mov [rel tg_closed_gen],rax
    mov qword [rel tg_done],2
.receipt:
    lea rsi,[rel tg_receipt]
    lea rdi,[rel tg_result]
    mov ecx,tg_receipt_end-tg_receipt
    rep movsb
    mov qword [rel tg_result_length],tg_receipt_end-tg_receipt
    jmp .copyout
.read:
    cmp qword [rel tg_op],16
    jb .bad
    cmp qword [rel tg_op],19
    ja .bad
    call terminal_policy_command_copyout
    cmp eax,1
    jne .bad
    xor r13d,r13d
.capture_lifetimes:
    mov edi,r13d
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    lea rdx,[rel tg_snapshot_lifetimes]
    mov [rdx+r13*8],rax
    inc r13d
    cmp r13d,WM_MAX
    jb .capture_lifetimes
    lea rdi,[rel tg_executed_desc]
    lea rsi,[rel tg_result]
    mov edx,65536
    call snapshot_terminal_read
    test eax,eax
    jnz .bad
    mov [rel tg_result_length],rdx
    mov qword [rel tg_done],3
.copyout:
    mov rdi,rbx
    call terminal_policy_command_copyout
    cmp eax,1
    jne .bad
    mov qword [r12],CMDE_OK
    mov qword [r12+8],0              ; no private pointer in response scalars
    xor eax,eax
    jmp .out
.bad:
    lea rdi,[rel tg_result]
    xor eax,eax
    mov ecx,65536/8
    rep stosq
    mov qword [rel tg_result_length],0
    mov qword [r12],CMDE_AUTHDENY
    mov eax,CMDE_AUTHDENY
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

 ; Native continuation only, no new admission or retry. The original SEC
; invocation/result and its original deadline must still be current. Provider
; validation above never calls this helper or SEC (no validation recursion).
tg_launch_current:
    cmp qword [rel tg_launch_minted],1
    jne .bad
    cmp qword [rel tg_done],5
    jne .bad
    cmp rdi,[rel tg_launch_operand+8]
    jne .bad
    cmp rsi,[rel tg_launch_operand+384]
    jne .bad
    cmp qword [rel tg_dispatching],0
    jne .cancel
    cmp byte [rel cmd_in_dispatch],0
    jne .cancel
    cmp dword [rel cmd_dispatch_depth],0
    jne .cancel
    cmp byte [rel command_auth_remote_active],0
    jne .cancel
    call smp_current_logical
    test eax,eax
    jnz .cancel
    lea rdi,[rel tg_launch_desc]
    call terminal_policy_check
    cmp eax,1
    jne .cancel
    mov eax,1
    ret
.cancel:
    mov qword [rel tg_launch_minted],0
.bad:
    xor eax,eax
    ret

; Scope preparer reads native tables only. The UI's slot/full generation are
; selectors, never class assertions. Desktop/active bind the GUI root; explicit
; window/UI additionally bind the exact native full window lifetime.
tg_prepare:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12,rcx
    mov r13d,edx
    cmp ebx,16
    jb .bad
    cmp ebx,19
    ja .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel tg_initialized],1
    jne .bad
    mov rdi,r12
    xor eax,eax
    mov ecx,16
    rep stosq
    cmp ebx,18
    jb .root
    mov edi,esi
    call tg_window_current
    test eax,eax
    jz .bad
    mov [r12+24],rax
    movzx ecx,al
    lea rax,[rel wm_gen]
    mov eax,[rax+rcx*4]
    cmp eax,r13d
    jne .bad
    mov [r12+32],rax
    mov edi,ecx
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    mov r13,rax
.root:
    mov qword [r12],1
    mov [r12+8],rbx
    mov rax,[r12+24]
    shl rax,8
    or rax,rbx
    mov [r12+16],rax
    lea rdi,[r12+48]
    lea rsi,[rel tg_root_key]
    cmp ebx,18
    jb .scope_key
    lea rsi,[rel tg_window_key]
.scope_key:
    mov ecx,8
    rep movsq
    cmp ebx,18
    jb .success
    mov [r12+104],r13
.success:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Recreate an expected scope from current native state, compare full128.
tg_restore:
    push rbx
    mov rbx,rdi
    mov edi,[rbx+8]
    movzx esi,byte [rbx+24]
    mov edx,[rbx+32]
    lea rcx,[rel tg_scope_check]
    call tg_prepare
    cmp eax,1
    jne .bad
    mov rsi,rbx
    lea rdi,[rel tg_scope_check]
    mov ecx,16
    repe cmpsq
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; No recursive SEC calls here. SEC's preserving retire wrapper owns fencing.
tg_retire:
    mov qword [rel tg_launch_minted],0 ; synchronous cancel; no depth0 work here
    lea rdi,[rel tg_private]
    mov ecx,(tg_private_end-tg_private)/8
    xor eax,eax
    rep stosq
    ret

%macro WDATA_gui_terminal_provider 0
align 8
tg_initialized: dq 0
tg_window_key: db 'PaOS native GUI window v1',0
    times 64-($-tg_window_key) db 0
terminal_gui_provider_table: times 6 dq 0
tg_root_key: db 'PaOS native ordinary desktop GUI root v1',0
    times 64-($-tg_root_key) db 0
tg_snapshot_name: db 'SNAPSHOT',0
tg_move_name: db 'WINMOVE',0
tg_close_name: db 'CLOSE',0
tg_fill_name: db 'WIDGETSET',0
tg_launch_name: db 'LAUNCH',0
tg_snapshot_prefix: db 'SNAPSHOT ',0
tg_move_prefix: db 'WINMOVE ',0
tg_close_prefix: db 'CLOSE ',0
tg_fill_prefix: db 'WIDGETSET ',0
tg_launch_prefix: db 'LAUNCH ',0
tg_value_prefix: db ' value ',0
tg_clear_suffix: db ' clear 1',0
tg_desktop: db 'desktop',0
tg_active: db 'active',0
tg_window: db 'window ',0
tg_ui: db 'ui ',0
tg_receipt: db 'GUI action completed',10
tg_receipt_end:
tg_pending_receipt: db 'Launch queued; existing owner policy and native activation pending',10
tg_pending_receipt_end:
align 8
tg_scope_check: times 128 db 0
%endmacro
WDATA_DEFER WDATA_gui_terminal_provider
%macro BSS_gui_terminal_provider 0
align 8
tg_private:
tg_launch_minted: resq 1
tg_launch_session_key: resq 1
tg_launch_desc: resb 256
tg_launch_operand: resb 400
tg_launch_key: resb 64
tg_ready: resq 1
tg_op: resq 1
tg_slot: resq 1
tg_target: resq 1
tg_gen: resq 1
tg_lifetime: resq 1
tg_owner: resq 1
tg_x: resq 1
tg_y: resq 1
tg_width: resq 1
tg_height: resq 1
tg_widget: resq 1
tg_clear: resq 1
tg_clear_revision: resq 1
tg_birth: resq 1
tg_field: resq 1
tg_before_length: resq 1
tg_before: resb 256
tg_field_hook: resq 1
tg_edit: resq 1
tg_value: resq 1
tg_value_length: resq 1
tg_value_buffer: resq 1
tg_value_capacity: resq 1
tg_verb: resq 1
tg_length: resq 1
tg_hash: resb 32
tg_command: resb 1024
tg_executed_desc: resb 256
tg_closed_gen: resq 1
tg_done: resq 1
tg_dispatching: resq 1
tg_result_length: resq 1
tg_snapshot_lifetimes: resq 16
tg_req: resb 56
tg_rsp: resb 48
align 8
tg_result: resb 65536
tg_private_end:
%endmacro
WDATA_BSS_DEFER BSS_gui_terminal_provider
