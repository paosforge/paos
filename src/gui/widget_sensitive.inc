; Original shipped transient-editor clear, and passive consent/result witness.
; Never reads/copies/hashes secret bytes. No synthetic approval or reusable grant.
wgt_sensitive_current:
    push rbx
    mov ebx,edi
    call form_wifi_guard_matches
    cmp eax,1
    jne .bad
    mov edi,ebx
    call wgt_slot_ptr
    mov rbx,rax
    mov ecx,[rel wgt_secret_type]
    cmp ecx,WTYPE_MAX
    jae .bad
    lea edx,[ecx+1]
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
    mov rdi,[rbx+WGI_ROLE]
    test rdi,rdi
    jz .bad
    lea rsi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jnz .bad
    cmp dword [rbx+WGI_BIND],0
    jne .bad
    test dword [rbx+WGI_FLAGS],1
    jz .bad
    test dword [rbx+WGI_EDIT],WGT_EDIT_DISABLED | WGT_EDIT_SECTEXT
    jnz .bad
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
    cmp dword [rel wgt_secret_owner],-1
    je .ok
    mov eax,[rel form_wifi_guard_first]
    inc eax
    cmp eax,[rel wgt_secret_owner]
    jne .bad
.ok:
    mov rax,rbx
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; EDI original id. Native current identity must match the first original plan.
wss_bound:
    cmp edi,[rel wss_id]
    jne .bad
    call wgt_sensitive_current
    test rax,rax
    jz .bad
    mov ecx,[rax+WGI_WIN]
    cmp ecx,[rel wss_win]
    jne .bad
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rcx*4]
    cmp rdx,[rel wss_gen]
    jne .bad
    mov edi,[rel wss_id]
    call wgt_birth_lifetime
    cmp rax,[rel wss_life]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

wgt_sensitive_plan:
    WPR_SAVE
    mov r12,rsi
    mov ebx,edi
    call wgt_sensitive_current
    test rax,rax
    jz .out
    cmp dword [r12+4],1
    jne .out
    mov edi,ebx
    call wss_bound
    test eax,eax
    jnz .same
    lea rdi,[rel wss_record]
    xor eax,eax
    mov ecx,(wss_record_end-wss_record)/8
    rep stosq
    mov [rel wss_id],ebx
    mov edi,ebx
    call wgt_birth_lifetime
    mov [rel wss_life],rax
    mov edi,ebx
    call wgt_slot_ptr
    mov ecx,[rax+WGI_WIN]
    mov [rel wss_win],rcx
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rcx*4]
    mov [rel wss_gen],rdx
    mov qword [rel wss_setrc],256
    mov qword [rel wss_code],256
.same:
    cmp qword [rel wss_requests],2
    jae .out
    inc qword [rel wss_requests]
    cmp qword [rel wss_requests],1
    jne .out
    mov rax,[r12+8]
    mov [rel wss_sequence],rax
    mov rax,[rel wgt_secret_revision]
    mov [rel wss_revision],rax
    mov edi,ebx
    call wgt_slot_ptr
    mov rbx,rax
    lea rsi,[rbx+WGI_VLEN]
    lea rdi,[rel wss_mask]
    mov ecx,52
    rep movsb
    mov rax,[rbx+WGI_CARET]
    mov [rel wss_caret],rax
    mov eax,[rbx+WGI_INTENT]
    mov [rel wss_intent],rax
    mov rax,[rbx+WGI_INTENT_SEQ]
    mov [rel wss_intent_seq],rax
.out:
    WPR_RETURN

; Every subsequent callback must carry exactly the original frozen descriptor.
wss_descriptor:
    cmp qword [rel wss_requests],1
    jne .bad
    cmp qword [r12+56],32
    jne .bad
    cmp qword [r12+88],0
    jne .bad
    mov rax,[r12+200]
    cmp rax,[rel wss_sequence]
    jne .bad
    mov rax,[r12+192]
    cmp rax,[rel wss_life]
    jne .bad
    mov rax,[r12+80]
    cmp rax,[rel wss_gen]
    jne .bad
    mov edi,[rel wss_id]
    call wss_bound
    test eax,eax
    jz .bad
    lea rsi,[rel wss_desc]
    mov rdi,r12
    mov ecx,32
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

wgt_sensitive_pending:
    WPR_SAVE
    mov r12,rsi
    cmp qword [rel wss_decision],0
    jne .out
    cmp qword [rel wss_requests],1
    jne .out
    cmp qword [r12+56],32
    jne .out
    mov rax,[r12+200]
    cmp rax,[rel wss_sequence]
    jne .out
    mov rax,[r12+192]
    cmp rax,[rel wss_life]
    jne .out
    mov edi,[rel wss_id]
    call wss_bound
    test eax,eax
    jz .out
    mov rsi,r12
    lea rdi,[rel wss_desc]
    mov ecx,32
    rep movsq
    mov qword [rel wss_decision],1
.out:
    WPR_RETURN

wgt_sensitive_decision:
    WPR_SAVE
    mov ebx,edi
    mov r12,rsi
    call wss_descriptor
    test eax,eax
    jz .out
    cmp qword [rel wss_decision],1
    jne .out
    cmp ebx,1
    jb .out
    cmp ebx,3
    ja .out
    inc ebx
    mov [rel wss_decision],rbx
.out:
    WPR_RETURN

wgt_sensitive_set_result:
    WPR_SAVE
    mov ebx,eax
    mov r12,rsi
    call wss_descriptor
    test eax,eax
    jz .out
    cmp qword [rel wss_setcalls],2
    jae .out
    inc qword [rel wss_setcalls]
    mov [rel wss_setrc],rbx
.out:
    WPR_RETURN

wgt_sensitive_result:
    WPR_SAVE
    mov ebx,eax
    mov r12,rsi
    call wss_descriptor
    test eax,eax
    jz .out
    mov [rel wss_code],rbx
.out:
    WPR_RETURN

; Original WIDGETGET uses the normal native admission. Source1 is withheld;
; record is passive and discloses no value/mask/length/revision/digest/pointer.
wgt_sensitive_emit:
    push rbx
    push r12
    mov r12d,edi
    test rsi,rsi
    jz .withheld
    cmp qword [rsi+REQ_SOURCE],1
    je .withheld
    call wgt_sensitive_current
    test rax,rax
    jz .withheld
    lea rdi,[rel str_wss_begin]
    call wgt_out_str
    mov edi,r12d
    call wgt_out_dec
    lea rdi,[rel str_wc_life]
    call wgt_out_str
    mov edi,r12d
    call wgt_birth_lifetime
    mov rdi,rax
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_win]
    call wgt_out_str
    mov edi,r12d
    call wgt_slot_ptr
    mov ebx,[rax+WGI_WIN]
    mov edi,ebx
    call wgt_out_dec
    lea rdi,[rel str_wss_gen]
    call wgt_out_str
    lea rdx,[rel wm_gen]
    mov edi,[rdx+rbx*4]
    call wgt_out_dec
    mov edi,r12d
    call wss_bound
    test eax,eax
    jz .unused
    lea rdi,[rel str_wss_requests]
    call wgt_out_str
    mov rdi,[rel wss_requests]
    call wgt_out_dec
    lea rdi,[rel str_wss_sequence]
    call wgt_out_str
    mov rdi,[rel wss_sequence]
    call wgt_out_dec
    lea rdi,[rel str_wss_pid]
    call wgt_out_str
    mov rdi,[rel wss_desc+8]
    call wgt_out_dec
    lea rdi,[rel str_wss_start]
    call wgt_out_str
    mov rdi,[rel wss_desc+24]
    call wgt_out_dec
    lea rdi,[rel str_wss_session]
    call wgt_out_str
    mov rdi,[rel wss_desc+40]
    call wgt_out_dec
    lea rdi,[rel str_wss_policy]
    call wgt_out_str
    mov rdi,[rel wss_desc+48]
    call wgt_out_dec
    lea rdi,[rel str_wss_binding]
    call wgt_out_str
    mov rdi,[rel wss_desc+16]
    call wgt_out_dec
    lea rdi,[rel str_wss_decision]
    call wgt_out_str
    mov rdi,[rel wss_decision]
    call wgt_out_dec
    lea rdi,[rel str_wss_setcalls]
    call wgt_out_str
    mov rdi,[rel wss_setcalls]
    call wgt_out_dec
    lea rdi,[rel str_wss_setrc]
    call wgt_out_str
    mov rdi,[rel wss_setrc]
    call wgt_out_dec
    lea rdi,[rel str_wss_code]
    call wgt_out_str
    mov rdi,[rel wss_code]
    call wgt_out_dec
    lea rdi,[rel str_wss_end]
    call wgt_out_str
    jmp .out
.unused:
    lea rdi,[rel str_wss_unused]
    call wgt_out_str
    jmp .out
.withheld:
    lea rdi,[rel str_wss_withheld]
    call wgt_out_str
.out:
    mov eax,1
    pop r12
    pop rbx
    ret

%macro WDATA_widget_sensitive 0
align 8
wss_record:
wss_id: dq -1
wss_life: dq 0
wss_win: dq 0
wss_gen: dq 0
wss_requests: dq 0
wss_sequence: dq 0
wss_decision: dq 0
wss_setcalls: dq 0
wss_setrc: dq 256
wss_code: dq 256
wss_desc: times 256 db 0
wss_record_end:
str_wf_sensitive_state: db 'sensitive_state',0
str_wss_begin: db ' widget sensitive v=1 id=',0
str_wss_gen: db ' gen=',0
str_wss_end: db ' end=1',0
str_wss_unused: db ' requests=0 sequence=0 pid=0 start=0 session=0 policy=0 binding=0 decision=0 setcalls=0 setrc=256 code=256 end=1',0
str_wss_withheld: db ' widget sensitive v=1 state=withheld end=1',0
str_wss_requests: db ' requests=',0
str_wss_sequence: db ' sequence=',0
str_wss_pid: db ' pid=',0
str_wss_start: db ' start=',0
str_wss_session: db ' session=',0
str_wss_policy: db ' policy=',0
str_wss_binding: db ' binding=',0
str_wss_decision: db ' decision=',0
str_wss_setcalls: db ' setcalls=',0
str_wss_setrc: db ' setrc=',0
str_wss_code: db ' code=',0
; Relocation-safe emission uses runtime LEAs, never linked data pointers.
%endmacro
WDATA_DEFER WDATA_widget_sensitive

; Live native equality/result effect, separate from SEC/provider result receipt.
; Snapshot contains public mask/editor metadata and revision only, no secret bytes.
wgt_sensitive_effect:
    push rbx
    push r12
    push r13
    mov r12d,edi
    test rsi,rsi
    jz .withheld
    cmp qword [rsi+REQ_SOURCE],1
    je .withheld
    call wss_bound
    test eax,eax
    jz .withheld
    mov edi,r12d
    call wgt_slot_ptr
    mov rbx,rax
    lea r13,[rel str_wss_changed]
    mov rax,[rel wss_revision]
    cmp qword [rel wss_setcalls],0
    jne .cleared
    cmp rax,[rel wgt_secret_revision]
    jne .emit
    lea rsi,[rbx+WGI_VLEN]
    lea rdi,[rel wss_mask]
    mov ecx,52
    repe cmpsb
    jne .emit
    mov rax,[rbx+WGI_CARET]
    cmp rax,[rel wss_caret]
    jne .emit
    mov eax,[rbx+WGI_INTENT]
    cmp eax,[rel wss_intent]
    jne .emit
    mov rax,[rbx+WGI_INTENT_SEQ]
    cmp rax,[rel wss_intent_seq]
    jne .emit
    lea r13,[rel str_wss_unchanged]
    jmp .emit
.cleared:
    cmp qword [rel wss_setcalls],1
    jne .emit
    inc rax
    cmp rax,[rel wgt_secret_revision]
    jne .emit
    cmp dword [rel wgt_secret_owner],-1
    jne .emit
    cmp dword [rel wgt_secret_len],0
    jne .emit
    cmp dword [rbx+WGI_VLEN],0
    jne .emit
    cmp byte [rbx+WGI_VAL],0
    jne .emit
    lea r13,[rel str_wss_cleared]
.emit:
    lea rdi,[rel str_wss_effect_begin]
    call wgt_out_str
    mov edi,r12d
    call wgt_out_dec
    lea rdi,[rel str_wc_life]
    call wgt_out_str
    mov rdi,[rel wss_life]
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_win]
    call wgt_out_str
    mov rdi,[rel wss_win]
    call wgt_out_dec
    lea rdi,[rel str_wss_gen]
    call wgt_out_str
    mov rdi,[rel wss_gen]
    call wgt_out_dec
    mov rdi,r13
    call wgt_out_str
    lea rdi,[rel str_wss_end]
    call wgt_out_str
    jmp .out
.withheld:
    lea rdi,[rel str_wss_effect_withheld]
    call wgt_out_str
.out:
    mov eax,1
    pop r13
    pop r12
    pop rbx
    ret

%macro WDATA_widget_sensitive_effect 0
align 8
wss_revision: dq 0
wss_mask: times 52 db 0
align 8
wss_caret: dq 0
wss_intent: dq 0
wss_intent_seq: dq 0
str_wf_sensitive_effect: db 'sensitive_effect',0
str_wss_effect_begin: db ' widget sensitive_effect v=1 id=',0
str_wss_effect_withheld: db ' widget sensitive_effect v=1 state=withheld end=1',0
str_wss_changed: db ' effect=changed',0
str_wss_unchanged: db ' effect=unchanged',0
str_wss_cleared: db ' effect=cleared',0
%endmacro
WDATA_DEFER WDATA_widget_sensitive_effect
