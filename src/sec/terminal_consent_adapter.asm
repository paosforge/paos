;; MODULE sec/terminal_consent_adapter
;; LAYER 6
;; PURPOSE Native GUI copy APIs and honest optional durable store integration.
;; EXPORTS terminal_policy_ui_configure, terminal_policy_ui_approve, terminal_policy_state, terminal_policy_ui_pending, terminal_policy_deny, terminal_policy_ui_revoke, terminal_policy_prepare_scope, terminal_policy_ui_grant
;; IMPORTS sec/terminal_policy
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
; configure(RDI table[prepare_scope,save,load,clear,validate_saved]); zero denies.
; Native scope preparer(EDI op,ESI slot,EDX fullgen,RCX out128)->1 proves the
; actual chosen non-secret object/root. save(rows1024,count,owner token)->1 only
; verified saved. No persistent PID/click or load of unverified selections.
terminal_policy_ui_configure:
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    test rdi,rdi
    jz .bad
    mov rax,[rdi]
    mov [rel tp_prepare_op],rax
    mov rax,[rdi+8]
    mov [rel tp_save_op],rax
    mov rax,[rdi+16]
    mov [rel tp_load_op],rax
    mov rax,[rdi+24]
    mov [rel tp_clear_op],rax
    mov rax,[rdi+32]
    mov [rel tp_restore_validate_op],rax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; state(out1088)->1. No state changes, store IO, auto-bind or grant restoration
; from indicator recursion. Stable full generation enables present/visible gate.
terminal_policy_state:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    call tp_binding_live
    test eax,eax
    jz .bad
    mov rdi,rbx
    xor eax,eax
    mov ecx,1088/8
    rep stosq
    mov qword [rbx],1
    mov rax,[rel tp_session]
    mov [rbx+8],rax
    mov rax,[rel tp_generation]
    mov [rbx+16],rax
    mov rax,[rel tp_saved]
    mov [rbx+32],rax
    lea r8,[rel tp_scopes]
    lea r9,[rbx+64]
    mov r10d,TP_SCOPE_MAX
    xor r11d,r11d
.scan:
    cmp qword [r8],1
    jne .next
    mov rsi,r8
    mov rdi,r9
    mov ecx,TP_SCOPE_BYTES/8
    rep movsq
    add r9,TP_SCOPE_BYTES
    inc r11d
.next:
    add r8,TP_SCOPE_BYTES
    dec r10d
    jnz .scan
    mov [rbx+24],r11
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; UI pending supplies entire immutable descriptor AND printable canonical final
; action. Planner owns canonical text in tp_request; handler must not reinterpret
; it after approval. Never display protected operands: tp_validate runs first.
terminal_policy_ui_pending:
    push rbx
    push r12
    mov rbx,rsi
    mov r12d,edx
    cmp r12d,1024
    jne .bad
    test rbx,rbx
    jz .bad
    call terminal_policy_pending
    test rax,rax
    jz .bad
    push rax
    lea rsi,[rel tp_pending_request+64]
    mov rdi,rbx
    mov ecx,1024/8
    rep movsq
    pop rax
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; LIVE's one physical Approve callback continues the frozen invocation here.
; The UI closes its offer before this call; no retry, new arguments or ambient
; OWNER frame. The public core approve API remains a mark-only native primitive.
terminal_policy_ui_approve:
    call terminal_policy_approve
    cmp eax,1
    jne .bad
    call terminal_policy_resume
    test eax,eax
    jnz .bad                         ; retain honest failure; never replay effect
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Exact native denial. It never spends approval or invokes the continuation.
terminal_policy_deny:
    cmp rdi,[rel tp_pending_id]
    jne .out
    call terminal_policy_retire
.out:
    ret

terminal_policy_prepare_scope:
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp qword [rel tp_prepare_op],0
    je .bad
    ; Native preparer independently proves owner selection, current object,
    ; full lifetime and protected class. GUI labels alone prove nothing.
    jmp [rel tp_prepare_op]
.bad:
    xor eax,eax
    ret

; Compact rows for BOOT, no native pointers, tickets or cached content.
; Synchronous, bounded native save/readback. Failing persistence cannot revive
; RAM permissions and cannot produce a permanent/saved UI success label.
tp_save_selections:
    push rbx
    push r12
    mov r12,rdi
    mov qword [rel tp_saved],0
    cmp qword [rel tp_save_op],0
    je .session
    lea rdi,[rel tp_save_rows]
    xor eax,eax
    mov ecx,TP_SCOPE_MAX*TP_SCOPE_BYTES/8
    rep stosq
    lea r8,[rel tp_scopes]
    lea r9,[rel tp_save_rows]
    mov r10d,TP_SCOPE_MAX
    xor ebx,ebx
.scan:
    cmp qword [r8],1
    jne .next
    mov rsi,r8
    mov rdi,r9
    mov ecx,TP_SCOPE_BYTES/8
    rep movsq
    add r9,TP_SCOPE_BYTES
    inc ebx
.next:
    add r8,TP_SCOPE_BYTES
    dec r10d
    jnz .scan
    lea rdi,[rel tp_save_rows]
    mov esi,ebx
    mov rdx,r12
    call [rel tp_save_op]
    cmp eax,1
    jne .failed
    mov qword [rel tp_saved],1
    mov ebx,1
    jmp .wipe
.failed:
    mov qword [rel tp_saved],2
.session:
    mov ebx,2
.wipe:
    lea rdi,[rel tp_save_rows]
    xor eax,eax
    mov ecx,TP_SCOPE_MAX*TP_SCOPE_BYTES/8
    rep stosq
    mov eax,ebx
    pop r12
    pop rbx
    ret

terminal_policy_ui_grant:
    push rbx
    mov rbx,rsi
    call terminal_policy_grant
    cmp eax,1
    jne .out
    mov rdi,rbx
    call tp_save_selections
.out:
    pop rbx
    ret

; revoke(RDI local owner token)->1 saved,2 session-only,0 rejected caller.
; Fence FIRST; BOOT clear also blocks same-boot restore before uncertain IO.
terminal_policy_ui_revoke:
    push rbx
    mov rbx,rdi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,rbx
    jne .bad
    call terminal_policy_revoke
    mov rax,[rel tp_serial]
    mov [rel tp_restore_binding],rax
    cmp qword [rel tp_clear_op],0
    je .session
    mov rdi,rbx
    call [rel tp_clear_op]
    cmp eax,1
    jne .failed
    mov qword [rel tp_saved],1
    mov eax,1
    jmp .out
.failed:
    mov qword [rel tp_saved],2
.session:
    mov eax,2
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; restore(owner token)->1 authenticated + independently validated selections,
; 0 unavailable/refused. Explicit native init/unlock path, NEVER indicator or
; guest dispatch. One attempt per fresh binding; no saved PID/click resurrection.
; Saved exact-window lifetimes which cannot be proved current simply refuse.
terminal_policy_restore:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,r12
    jne .bad
    call tp_binding_live
    test eax,eax
    jz .bad
    mov rax,[rel tp_serial]
    cmp rax,[rel tp_restore_binding]
    je .bad
    mov [rel tp_restore_binding],rax ; burn attempt before IO, success or not
    lea rdi,[rel tp_scopes]
    mov ecx,TP_SCOPE_MAX*TP_SCOPE_BYTES/8
    xor eax,eax
.scan_empty:
    or rax,[rdi]
    add rdi,8
    loop .scan_empty
    test rax,rax
    jnz .bad
    cmp qword [rel tp_load_op],0
    je .bad
    cmp qword [rel tp_restore_validate_op],0
    je .bad
    lea rdi,[rel tp_save_rows]
    xor eax,eax
    mov ecx,TP_SCOPE_MAX*TP_SCOPE_BYTES/8
    rep stosq
    lea rdi,[rel tp_save_rows]
    mov rsi,r12
    call [rel tp_load_op]
    cmp eax,1
    jne .wipe_bad
    cmp edx,TP_SCOPE_MAX
    ja .wipe_bad
    mov r13d,edx
    xor r14d,r14d
    xor r15d,r15d ; optional picked folder count
.validate:
    cmp r14d,r13d
    jae .validated
    mov ebx,r14d
    imul ebx,TP_SCOPE_BYTES
    lea rax,[rel tp_save_rows]
    add rbx,rax
    mov rdi,rbx
    call tp_scope_valid
    test eax,eax
    jz .wipe_bad
    cmp qword [rbx+TP_S_OP],TP_FOLDER_READ
    jne .ids
    inc r15d
    cmp r15d,1
    ja .wipe_bad
.ids:
    lea rdi,[rel tp_save_rows]
    mov ecx,r14d
.unique:
    test ecx,ecx
    jz .prove
    mov rax,[rbx+TP_S_ID]
    cmp rax,[rdi+TP_S_ID]
    je .wipe_bad
    add rdi,TP_SCOPE_BYTES
    dec ecx
    jmp .unique
.prove:
    mov rdi,rbx
    call [rel tp_restore_validate_op] ; actual native current scope, never text
    cmp eax,1
    jne .wipe_bad
    inc r14d
    jmp .validate
.validated:
    call tp_binding_live
    test eax,eax
    jz .wipe_bad
    cmp qword [rel tp_generation],-2
    jae .wipe_bad
    call terminal_policy_retire
    lea rdi,[rel tp_scopes]
    lea rsi,[rel tp_save_rows]
    mov ecx,r13d
    imul ecx,TP_SCOPE_BYTES/8
    rep movsq
    inc qword [rel tp_generation]
    mov qword [rel tp_saved],1
    mov ebx,1
    jmp .wipe
.wipe_bad:
    xor ebx,ebx
.wipe:
    lea rdi,[rel tp_save_rows]
    xor eax,eax
    mov ecx,TP_SCOPE_MAX*TP_SCOPE_BYTES/8
    rep stosq
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Native BSP init: optional preserving staging canceller (FS). Registration
; retires old staging first. No guest callback pointer is ever decoded.
terminal_policy_provider_retire_configure:
    push rbx
    mov rbx,rdi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call terminal_policy_retire
    mov [rel tp_provider_retire_op],rbx
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret
