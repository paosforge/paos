; C5 passive observation of one completed original empty-secret form lifetime.
; No observer invokes a getter/setter, creates a widget, fills or grants.
; Equality covers native mask/selection/caret/intent and private editor revision;
; no secret bytes, private lengths, pointer or digest leaves this module.
wgt_guard_current:
    push rbx
    mov ebx,edi
    cmp byte [rel guard_origin],1
    je .shipped
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
%if PAOS_PUBLICITY_LAB_PROFILE
    call form_lab_guard_matches
    jmp .matched
%else
    jmp .bad
%endif
.shipped:
    call form_wifi_guard_matches
.matched:
    test eax,eax
    jz .bad
    mov edi,ebx
    call wgt_slot_ptr
    mov rbx,rax
    mov ecx,[rel wgt_secret_type]
    cmp ecx,WTYPE_MAX
    jae .bad
    mov edx,ecx
    inc edx
    cmp [rbx+WGI_TYPE],edx
    jne .bad
    imul ecx,WT_SZ
    lea rdx,[rel wgt_types]
    add rdx,rcx
    lea rcx,[rel wgt_secret_set]
    cmp [rdx+WT_SET],rcx
    jne .bad
    lea rcx,[rel wgt_textfield_get]
    cmp [rdx+WT_GET],rcx
    jne .bad
    lea rcx,[rel str_wgt_secret]
    cmp [rdx+WT_NAME],rcx
    jne .bad
    lea rcx,[rel str_wgt_role_password]
    mov rdi,[rbx+WGI_ROLE]
    test rdi,rdi
    jz .bad
    mov rsi,rcx
    call strcmp
    test eax,eax
    jnz .bad
    test dword [rbx+WGI_FLAGS],1
    jz .bad
    test dword [rbx+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    cmp dword [rbx+WGI_BIND],0
    jne .bad
    cmp byte [rel session_locked],0
    jne .bad
    mov ecx,[rbx+WGI_WIN]
    cmp ecx,WM_MAX-1
    jae .bad
    lea rdx,[rel wm_state]
    cmp dword [rdx+rcx*4],WM_VISIBLE
    jne .bad
    lea rdx,[rel wm_owner]
    cmp qword [rdx+rcx*8],WM_OWNER_CHROME
    je .bad
    lea rdx,[rel wm_no_history]
    cmp byte [rdx+rcx],0
    jne .bad
    ; An unrelated private editor's state is never inspected for this record.
    cmp dword [rel wgt_secret_owner],-1
    je .ok
    mov edi,[rel guard_id]
    cmp edi,[rel wgt_secret_owner]
    jne .bad
.ok:
    mov rax,rbx
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Called only by completed original FORMLOAD, not a read or planner.
wgt_guard_bind:
    push rbx
    mov byte [rel guard_ready],0
    mov [rel guard_origin],sil
    mov [rel guard_id],edi
    cmp dword [rel wgt_secret_owner],-1
    jne .out
    cmp dword [rel wgt_secret_len],0
    jne .out
    cmp qword [rel wgt_secret_revision],-1
    je .out
    call wgt_guard_current
    test rax,rax
    jz .out
    mov rbx,rax
    lea rsi,[rbx+WGI_VLEN]        ; 52B native mask/selection, no secret payload
    lea rdi,[rel guard_baseline]
    mov ecx,52
    rep movsb
    mov rax,[rbx+WGI_CARET]
    mov [rel guard_caret],rax
    mov eax,[rbx+WGI_INTENT]
    mov [rel guard_intent],eax
    mov rax,[rbx+WGI_INTENT_SEQ]
    mov [rel guard_intent_seq],rax
    mov rax,[rel wgt_secret_revision]
    mov [rel guard_revision],rax
    mov qword [rel guard_pid],0
    mov qword [rel guard_start],0
    mov qword [rel guard_session],0
    mov qword [rel guard_binding],0
    mov qword [rel guard_epoch],0
    mov qword [rel guard_policy],0
    mov qword [rel guard_count],0
    mov qword [rel guard_sequence],0
    mov byte [rel guard_ready],1
.out:
    pop rbx
    ret

; EDI actual target, RSI SEC's original privately copied request. Called only
; after the original native tg_field_current rejects, before .bad/retirement.
; Does not change refusal, descriptor, request, consent or dispatch outcome.
wgt_guard_provider_refused:
    push rbx
    push r12
    mov r12,rsi
    cmp byte [rel guard_ready],1
    jne .out
    cmp edi,[rel guard_id]
    jne .out
    call wgt_guard_current
    test rax,rax
    jz .out
    cmp dword [r12+4],1
    jne .out
    mov rax,[r12+8]
    test rax,rax
    jz .out
    cmp byte [rel guard_origin],1
    jne .record
    ; SEC invokes the planner only after original probe/replay/busy admission.
    ; Principal comes from native SEC binding, never guest wire fields. No
    ; descriptor, scope grant or consent deadline exists for this early refusal.
    lea rdx,[rel tp_request]
    cmp r12,rdx
    jne .out
    cmp byte [rel tp_busy],1
    jne .out
    cmp rax,[rel tp_floor]
    jne .out
    cmp qword [rel tp_pid],0
    je .out
    cmp dword [rel tp_start],0
    je .out
    cmp qword [rel tp_session],0
    je .out
    cmp qword [rel tp_serial],0
    je .out
    cmp qword [rel tp_epoch],0
    je .out
    cmp qword [rel tp_generation],0
    je .out
    mov rdx,[rel tp_pid]
    mov [rel guard_pid],rdx
    mov edx,[rel tp_start]
    mov [rel guard_start],rdx
    mov rdx,[rel tp_session]
    mov [rel guard_session],rdx
    mov rdx,[rel tp_serial]
    mov [rel guard_binding],rdx
    mov rdx,[rel tp_epoch]
    mov [rel guard_epoch],rdx
    mov rdx,[rel tp_generation]
    mov [rel guard_policy],rdx
.record:
    cmp qword [rel guard_count],2
    jae .multiple
    inc qword [rel guard_count]
.multiple:
    mov [rel guard_sequence],rax
.out:
    pop r12
    pop rbx
    ret

; Native read only. Source1 has no original admission; no fallback authority.
; Unfocused host is allowed here: the public Terminal owns focus during the
; denied command. The original fixture must remain public, visible, unlocked.
wgt_guard_emit:
    push rbx
    push r12
    push r13
    mov r12d,edi
    test rsi,rsi
    jz .withheld
    cmp qword [rsi+REQ_SOURCE],1
    je .withheld
    cmp byte [rel guard_ready],1
    jne .withheld
    cmp edi,[rel guard_id]
    jne .withheld
    call wgt_guard_current
    test rax,rax
    jz .withheld
    mov rbx,rax
    cmp byte [rel guard_origin],1
    jne .context_ready
    cmp qword [rel guard_count],0
    je .context_ready
    mov rax,[rel tp_pid]
    cmp rax,[rel guard_pid]
    jne .withheld
    mov eax,[rel tp_start]
    cmp rax,[rel guard_start]
    jne .withheld
    mov rax,[rel tp_session]
    cmp rax,[rel guard_session]
    jne .withheld
    mov rax,[rel tp_serial]
    cmp rax,[rel guard_binding]
    jne .withheld
    mov rax,[rel tp_epoch]
    cmp rax,[rel guard_epoch]
    jne .withheld
    mov rax,[rel tp_generation]
    cmp rax,[rel guard_policy]
    jne .withheld
.context_ready:
    lea r13,[rel str_guard_unchanged]
    mov rax,[rel wgt_secret_revision]
    cmp rax,-1
    je .withheld
    cmp rax,[rel guard_revision]
    je .revision_same
    mov eax,[rel guard_id]
    cmp eax,[rel wgt_secret_owner]
    jne .withheld                    ; foreign/retired editor history is unknown
    jmp .changed
.revision_same:
    cmp dword [rel wgt_secret_len],0
    je .editor_same
    mov eax,[rel guard_id]
    cmp eax,[rel wgt_secret_owner]
    jne .withheld
    jmp .changed
.editor_same:
    lea rsi,[rbx+WGI_VLEN]
    lea rdi,[rel guard_baseline]
    mov ecx,52
    repe cmpsb
    jne .changed
    mov rax,[rbx+WGI_CARET]
    cmp rax,[rel guard_caret]
    jne .changed
    mov eax,[rbx+WGI_INTENT]
    cmp eax,[rel guard_intent]
    jne .changed
    mov rax,[rbx+WGI_INTENT_SEQ]
    cmp rax,[rel guard_intent_seq]
    je .emit
.changed:
    lea r13,[rel str_guard_changed]
.emit:
    lea rdi,[rel str_guard_start]
    call wgt_out_str
    mov edi,r12d
    call wgt_out_dec
    lea rdi,[rel str_guard_life]
    call wgt_out_str
    mov edi,r12d
    call wgt_birth_lifetime
    mov rdi,rax
    call wgt_out_dec
    lea rdi,[rel str_guard_win]
    call wgt_out_str
    mov edi,[rbx+WGI_WIN]
    call wgt_out_dec
    lea rdi,[rel str_guard_gen]
    call wgt_out_str
    mov eax,[rbx+WGI_WIN]
    lea rdx,[rel wm_gen]
    mov edi,[rdx+rax*4]
    call wgt_out_dec
    cmp byte [rel guard_origin],1
    jne .origin_ready
    lea rdi,[rel str_guard_origin]
    call wgt_out_str
    mov rdi,[rel guard_pid]
    call wgt_out_dec
    lea rdi,[rel str_guard_startgen]
    call wgt_out_str
    mov rdi,[rel guard_start]
    call wgt_out_dec
    lea rdi,[rel str_guard_session]
    call wgt_out_str
    mov rdi,[rel guard_session]
    call wgt_out_dec
    lea rdi,[rel str_guard_binding]
    call wgt_out_str
    mov rdi,[rel guard_binding]
    call wgt_out_dec
    lea rdi,[rel str_guard_epoch]
    call wgt_out_str
    mov rdi,[rel guard_epoch]
    call wgt_out_dec
    lea rdi,[rel str_guard_policy]
    call wgt_out_str
    mov rdi,[rel guard_policy]
    call wgt_out_dec
.origin_ready:
    lea rdi,[rel str_guard_count]
    call wgt_out_str
    mov rdi,[rel guard_count]
    call wgt_out_dec
    lea rdi,[rel str_guard_sequence]
    call wgt_out_str
    mov rdi,[rel guard_sequence]
    call wgt_out_dec
    mov rdi,r13
    call wgt_out_str
    lea rdi,[rel str_guard_attempted]
    cmp qword [rel guard_count],0
    jne .provider
    lea rdi,[rel str_guard_not_attempted]
.provider:
    call wgt_out_str
    jmp .out
.withheld:
    lea rdi,[rel str_guard_withheld]
    call wgt_out_str
.out:
    mov eax,1
    pop r13
    pop r12
    pop rbx
    ret

%macro WDATA_gui_widget_guard 0
align 8
guard_pid: dq 0
guard_start: dq 0
guard_session: dq 0
guard_binding: dq 0
guard_epoch: dq 0
guard_policy: dq 0
guard_origin: db 0
align 8
guard_revision: dq 0
guard_sequence: dq 0
guard_count: dq 0
guard_caret: dq 0
guard_intent_seq: dq 0
guard_intent: dd 0
guard_id: dd -1
guard_baseline: times 52 db 0
guard_ready: db 0
str_guard_start: db " widget guard v=1 id=",0
str_guard_life: db " life=",0
str_guard_win: db " win=",0
str_guard_gen: db " gen=",0
str_guard_origin: db " origin=wifi_local pid=",0
str_guard_startgen: db " start=",0
str_guard_session: db " session=",0
str_guard_binding: db " binding=",0
str_guard_epoch: db " epoch=",0
str_guard_policy: db " policy=",0
str_guard_count: db " class=secret attempts=",0
str_guard_sequence: db " sequence=",0
str_guard_unchanged: db " effect=unchanged",0
str_guard_changed: db " effect=changed",0
str_guard_attempted: db " provider=protected_class consent=not_requested end=1",0
str_guard_not_attempted: db " provider=not_attempted consent=not_requested end=1",0
str_guard_withheld: db " widget guard v=1 state=withheld end=1",0
%endmacro
WDATA_DEFER WDATA_gui_widget_guard
