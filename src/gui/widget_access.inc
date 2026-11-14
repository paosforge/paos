; Passive current WIDGETSET desktop/session/window-owner gate observation.
; This is neither a field-specific permission nor a grant. No callbacks run.
; EDI live widget id, RSI original nested request; out buffer belongs to GET.
wgt_access_emit:
    xor edx,edx
    jmp wgt_access_emit_mode

; Supported conditional value field only. Same original request/gates and the
; setter's exact public-form predicate; snapshots do not execute or grant SET.
wgt_value_access_emit:
    mov edx,1
wgt_access_emit_mode:
    push rbx
    push r12
    sub rsp,96
    mov [rsp+64],rdx
    mov ebx,edi
    mov r12,rsi
    mov [rsp],rdi
    call wgt_birth_lifetime
    test rax,rax
    jz .withheld
    mov [rsp+8],rax
    mov edi,ebx
    call wgt_slot_ptr
    mov ecx,[rax+WGI_TYPE]
    mov [rsp+24],rcx
    mov edi,[rax+WGI_WIN]
    cmp edi,WM_MAX
    jae .withheld
    mov [rsp+16],rdi
    lea rax,[rel wm_state]
    cmp dword [rax+rdi*4],WM_VISIBLE
    je .live
    cmp dword [rax+rdi*4],WM_MIN
    jne .withheld
.live:
    lea rax,[rel wm_gen]
    mov eax,[rax+rdi*4]
    test eax,eax
    jz .withheld
    mov [rsp+32],rax
    call form_events_slot_lifetime
    test rax,rax
    jz .withheld
    mov [rsp+40],rax
    test r12,r12
    jz .withheld
    mov rax,[r12+REQ_SOURCE]
    mov [rsp+48],rax
    mov rdi,r12
    call session_shell_request_principal
    mov [rsp+56],rax
    ; The real mutation gate latches a desktop refusal for dispatcher use.
    ; Preserve that byte on this read, including an already-latched refusal.
    movzx ebx,byte [rel cmd_desktop_refused]
    call session_shell_require_unlocked
    mov [rel cmd_desktop_refused],bl
    lea rbx,[rel str_access_locked]
    test eax,eax
    jnz .emit
    mov edi,[rsp+16]
    mov rsi,[rsp+56]
    call wmx_principal_may_act
    lea rbx,[rel str_access_not_owner]
    test eax,eax
    jnz .emit
    lea rbx,[rel str_access_allowed]
.emit:
    cmp qword [rsp+64],0
    je .header
    lea rax,[rel str_access_allowed]
    cmp rbx,rax
    jne .withheld
    mov edi,[rsp]
    call wgt_toggle_value_permission
    test eax,eax
    jnz .withheld
.header:
    lea rdi,[rel str_access_start]
    cmp qword [rsp+64],0
    je .start
    lea rdi,[rel str_value_access_start]
.start:
    call wgt_out_str
    mov rdi,[rsp+0]
    call wgt_out_dec
    lea rdi,[rel str_access_life]
    call wgt_out_str
    mov rdi,[rsp+8]
    call wgt_out_dec
    lea rdi,[rel str_access_win]
    call wgt_out_str
    mov rdi,[rsp+16]
    call wgt_out_dec
    lea rdi,[rel str_access_type]
    call wgt_out_str
    mov rdi,[rsp+24]
    call wgt_out_dec
    lea rdi,[rel str_access_gen]
    call wgt_out_str
    mov rdi,[rsp+32]
    call wgt_out_dec
    lea rdi,[rel str_access_lifetime]
    call wgt_out_str
    mov rdi,[rsp+40]
    call wgt_out_dec
    lea rdi,[rel str_access_source]
    call wgt_out_str
    mov rdi,[rsp+48]
    call wgt_out_dec
    lea rdi,[rel str_access_principal]
    call wgt_out_str
    mov rdi,[rsp+56]
    call wgt_out_dec
    lea rdi,[rel str_access_gate]
    call wgt_out_str
    mov rdi,rbx
    call wgt_out_str
    lea rdi,[rel str_access_end]
    cmp qword [rsp+64],0
    je .end
    lea rdi,[rel str_value_access_end]
.end:
    call wgt_out_str
    jmp .out
.withheld:
    lea rdi,[rel str_access_withheld]
    cmp qword [rsp+64],0
    je .unavailable
    lea rdi,[rel str_value_access_withheld]
.unavailable:
    call wgt_out_str
.out:
    add rsp,96
    pop r12
    pop rbx
    mov eax,1
    ret

; Shared read-only eligibility of the existing conditional public value SET.
; Caller owns session/principal gate. No callback, store, grant or receipt runs.
; EDI id -> EAX 0 eligible, 1 unsupported. Preserve nonvolatile registers.
wgt_toggle_value_permission:
    push rbx
    push r12
    mov r12d,edi
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
%if PAOS_PUBLICITY_LAB_PROFILE
    mov edi,r12d
    call form_lab_toggle_matches
    test eax,eax
    jz .bad
    mov edi,r12d
    call wgt_slot_ptr
    mov rbx,rax
    mov eax,[rbx+WGI_TYPE]
    dec eax
    cmp eax,[rel wgt_scalar_toggle_type]
    jne .bad
    cmp eax,[rel wgt_secret_type]
    je .bad
    cmp eax,WTYPE_MAX
    jae .bad
    imul eax,WT_SZ
    lea rdx,[rel wgt_types]
    add rdx,rax
    lea rax,[rel wgt_scalar_get]
    cmp rax,[rdx+WT_GET]
    jne .bad
    lea rax,[rel wgt_scalar_set]
    cmp rax,[rdx+WT_SET]
    jne .bad
    mov rdi,[rdx+WT_NAME]
    test rdi,rdi
    jz .bad
    lea rsi,[rel str_wc_guard_type]
    call strcmp
    test eax,eax
    jnz .bad
    test dword [rbx+WGI_FLAGS],1
    jz .bad
    test dword [rbx+WGI_EDIT],WGT_EDIT_SECTEXT | WGT_EDIT_DISABLED
    jnz .bad
    mov rdi,[rbx+WGI_ROLE]
    test rdi,rdi
    jz .bad
    lea rsi,[rel str_wc_guard_role]
    call strcmp
    test eax,eax
    jnz .bad
    ; This public binary field promises exact 0/1, not clamped/stepped effects.
    cmp qword [rbx+WGI_NUM],1
    ja .bad
    cmp qword [rbx+WGI_MINVAL],0
    jne .bad
    cmp qword [rbx+WGI_MAXVAL],1
    jne .bad
    cmp qword [rbx+WGI_STEP],1
    jne .bad
    ; Native content guard also requires a public visible focused host.
    mov ecx,[rbx+WGI_WIN]
    call wgt_overlay_host_shown
    jc .bad
    mov eax,[rbx+WGI_WIN]
    cmp eax,[rel wm_focus]
    jne .bad
    xor eax,eax
    jmp .out
%endif
.bad:
    mov eax,1
.out:
    pop r12
    pop rbx
    ret

%macro WDATA_gui_widget_access 0
str_wf_value_gate: db "value_gate",0
str_value_access_start: db " widget value_gate v=1 id=",0
str_value_access_end: db " field=value values=0,1 condition=birth,window,before consent=not_required action=not_attempted end=1",0
str_value_access_withheld: db " widget value_gate v=1 state=withheld end=1",0
str_wf_mutation_gate: db "mutation_gate",0
str_access_start: db " widget mutation_gate v=1 id=",0
str_access_life: db " life=",0
str_access_win: db " win=",0
str_access_type: db " type=",0
str_access_gen: db " gen=",0
str_access_lifetime: db " lifetime=",0
str_access_source: db " source=",0
str_access_principal: db " principal=",0
str_access_gate: db " gate=",0
str_access_allowed: db "allowed",0
str_access_locked: db "locked",0
str_access_not_owner: db "not_owner",0
str_access_end: db " field=unchecked consent=unchecked action=not_attempted end=1",0
str_access_withheld: db " widget mutation_gate v=1 state=withheld end=1",0
%endmacro
WDATA_DEFER WDATA_gui_widget_access
