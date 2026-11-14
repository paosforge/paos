; Finite passive C5 observation of the completed lab_provider public stock field.
; No authority, callback invocation, payload copy, descriptor copy or IO here.
; The original planner, physical consent and actual setter/result call us.
%macro WPR_SAVE 0
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
%endmacro
%macro WPR_RETURN 0
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
%endmacro

wgt_provider_current:
%if !PAOS_PUBLICITY_LAB_PROFILE
    xor eax,eax
    ret
%endif
    push rbx
    mov ebx,edi
    call form_lab_provider_matches
    test eax,eax
    jz .bad
    mov edi,ebx
    call wgt_slot_ptr
    mov rbx,rax
    cmp dword [rax+WGI_TYPE],WGT_TYPE_TEXTFIELD
    jne .bad
    mov ecx,[rel wgt_secret_type]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    je .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED | WGT_EDIT_SECTEXT
    jnz .bad
    cmp dword [rax+WGI_BIND],0
    jne .bad
    lea rcx,[rel str_wt_textfield]
    cmp [rax+WGI_ROLE],rcx
    jne .bad
    cmp [rel wgt_types+WT_SZ+WT_NAME],rcx
    jne .bad
    lea rcx,[rel wgt_textfield_set]
    cmp [rel wgt_types+WT_SZ+WT_SET],rcx
    jne .bad
    lea rcx,[rel wgt_textfield_get]
    cmp [rel wgt_types+WT_SZ+WT_GET],rcx
    jne .bad
    cmp byte [rel session_locked],0
    jne .bad
    mov ecx,[rax+WGI_WIN]
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
    mov rax,[rel wgt_textfield_event_hook2]
    test rax,rax
    jz .ok
    lea rcx,[rel summon_palette_text_event]
    cmp rax,rcx
    jne .bad
.ok:
    mov rax,rbx
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Only original completed materialization initializes the record.
wgt_provider_bind:
    WPR_SAVE
    mov [rel wpr_id],edi
    mov byte [rel wpr_ready],0
    call wgt_provider_current
    test rax,rax
    jz .out
    lea rdi,[rel wpr_record]
    xor eax,eax
    mov ecx,(wpr_record_end-wpr_record)/8
    rep stosq
    mov qword [rel wpr_setrc],256
    mov qword [rel wpr_code],256
    mov byte [rel wpr_ready],1
.out:
    WPR_RETURN

; EDI actual planned widget, RSI original SEC-copied frame. Successful native
; planning is admission to planning only. It is never an approved decision.
wgt_provider_plan:
    WPR_SAVE
    mov r12,rsi
    cmp byte [rel wpr_ready],1
    jne .out
    cmp edi,[rel wpr_id]
    jne .out
    call wgt_provider_current
    test rax,rax
    jz .out
    cmp dword [r12+4],1
    jne .out
    mov rax,[r12+8]
    test rax,rax
    jz .out
    cmp qword [rel wpr_count],2
    jae .out
    inc qword [rel wpr_count]
    cmp qword [rel wpr_count],1
    jne .out                       ; replacement never rewrites first identity
    mov [rel wpr_sequence],rax
.out:
    WPR_RETURN

; RSI original frozen native UI descriptor, not guest principal words.
; Both request sequence and original native birth/generation/lifetime match.
wpr_descriptor:
    cmp byte [rel wpr_ready],1
    jne .bad
    cmp qword [rel wpr_count],1
    jne .bad
    cmp qword [r12+56],32
    jne .bad
    cmp qword [r12+88],0
    jne .bad
    mov rax,[r12+200]
    cmp rax,[rel wpr_sequence]
    jne .bad
    mov edi,[rel wpr_id]
    call wgt_provider_current
    test rax,rax
    jz .bad
    mov ecx,[rax+WGI_WIN]
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rcx*4]
    cmp rdx,[r12+80]
    jne .bad
    mov edi,ecx
    call form_events_slot_lifetime
    test rax,rax
    jz .bad
    cmp rax,[r12+184]
    jne .bad
    mov edi,[rel wpr_id]
    call wgt_birth_lifetime
    cmp rax,[r12+192]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

wgt_provider_pending:
    call wgt_sensitive_pending
    WPR_SAVE
    mov r12,rsi
    call wpr_descriptor
    test eax,eax
    jz .out
    cmp qword [rel wpr_decision],0
    jne .out
    mov rax,[r12+8]
    mov [rel wpr_pid],rax
    mov rax,[r12+24]
    mov [rel wpr_start],rax
    mov rax,[r12+40]
    mov [rel wpr_session],rax
    mov rax,[r12+48]
    mov [rel wpr_policy],rax
    mov qword [rel wpr_decision],1   ; actual native prompt seen, no approval
.out:
    WPR_RETURN

; EDI1 actual successful approval callback,2 exact Deny callback completed,
; 3 actual approval callback failed. Neither generic cancellation nor expiry
; earns a human denial. We preserve original callback result and all flags.
wgt_provider_decision:
    call wgt_sensitive_decision
    WPR_SAVE
    mov ebx,edi
    mov r12,rsi
    call wpr_descriptor
    test eax,eax
    jz .out
    cmp qword [rel wpr_decision],1
    jne .out
    mov rax,[r12+8]
    cmp rax,[rel wpr_pid]
    jne .out
    mov rax,[r12+24]
    cmp rax,[rel wpr_start]
    jne .out
    mov rax,[r12+40]
    cmp rax,[rel wpr_session]
    jne .out
    mov rax,[r12+48]
    cmp rax,[rel wpr_policy]
    jne .out
    cmp ebx,1
    jb .out
    cmp ebx,3
    ja .out
    inc ebx
    mov [rel wpr_decision],rbx
.out:
    WPR_RETURN

; EAX exact original setter return, RSI actual executed native descriptor.
wgt_provider_set_result:
    WPR_SAVE
    mov ebx,eax
    mov r12,rsi
    call wpr_descriptor
    test eax,eax
    jz .out
    cmp qword [rel wpr_setcalls],2
    jae .out
    inc qword [rel wpr_setcalls]
    mov [rel wpr_setrc],rbx
.out:
    WPR_RETURN

; EAX exact original provider return, not final SEC completion or pixels.
wgt_provider_result:
    call wgt_sensitive_result
    WPR_SAVE
    mov ebx,eax
    mov r12,rsi
    call wpr_descriptor
    test eax,eax
    jz .out
    mov [rel wpr_code],rbx
.out:
    WPR_RETURN

; Passive original WIDGETGET; no getter/callback/consent/plan invocation.
wgt_provider_emit:
    push rbx
    push r12
    mov r12d,edi
    test rsi,rsi
    jz .withheld
    cmp qword [rsi+REQ_SOURCE],1
    je .withheld
    cmp byte [rel wpr_ready],1
    jne .withheld
    cmp edi,[rel wpr_id]
    jne .withheld
    call wgt_provider_current
    test rax,rax
    jz .withheld
    mov rbx,rax
    lea rdi,[rel str_wpr_begin]
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
    mov edi,[rbx+WGI_WIN]
    call wgt_out_dec
    lea rdi,[rel str_wpr_gen]
    call wgt_out_str
    mov ecx,[rbx+WGI_WIN]
    lea rax,[rel wm_gen]
    mov edi,[rax+rcx*4]
    call wgt_out_dec
%macro WPR_EMIT 2
    lea rdi,[rel %1]
    call wgt_out_str
    mov rdi,[rel %2]
    call wgt_out_dec
%endmacro
    WPR_EMIT str_wpr_count,wpr_count
    WPR_EMIT str_wpr_seq,wpr_sequence
    WPR_EMIT str_wpr_pid,wpr_pid
    WPR_EMIT str_wpr_start,wpr_start
    WPR_EMIT str_wpr_session,wpr_session
    WPR_EMIT str_wpr_policy,wpr_policy
    WPR_EMIT str_wpr_decision,wpr_decision
    WPR_EMIT str_wpr_setcalls,wpr_setcalls
    WPR_EMIT str_wpr_setrc,wpr_setrc
    WPR_EMIT str_wpr_code,wpr_code
    lea rdi,[rel str_wpr_end]
    call wgt_out_str
    jmp .out
.withheld:
    lea rdi,[rel str_wpr_withheld]
    call wgt_out_str
.out:
    mov eax,1
    pop r12
    pop rbx
    ret

%macro WDATA_widget_provider 0
align 8
wpr_record:
wpr_count: dq 0
wpr_sequence: dq 0
wpr_pid: dq 0
wpr_start: dq 0
wpr_session: dq 0
wpr_policy: dq 0
wpr_decision: dq 0
wpr_setcalls: dq 0
wpr_setrc: dq 256
wpr_code: dq 256
wpr_record_end:
wpr_id: dd -1
wpr_ready: db 0
str_wf_provider_state: db 'provider_state',0
str_wpr_begin: db ' widget provider v=1 id=',0
str_wpr_gen: db ' gen=',0
str_wpr_count: db ' requests=',0
str_wpr_seq: db ' sequence=',0
str_wpr_pid: db ' pid=',0
str_wpr_start: db ' start=',0
str_wpr_session: db ' session=',0
str_wpr_policy: db ' policy=',0
str_wpr_decision: db ' decision=',0
str_wpr_setcalls: db ' setcalls=',0
str_wpr_setrc: db ' setrc=',0
str_wpr_code: db ' code=',0
str_wpr_end: db ' end=1',0
str_wpr_withheld: db ' widget provider v=1 state=withheld end=1',0
%endmacro
WDATA_DEFER WDATA_widget_provider
