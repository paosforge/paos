; Private native dispatch below the original AN wire. No guest config/setter.
; Ordinary LIVE callback ABI is unchanged. Updater role never falls through to
; LIVE, including missing installed policy, unknown role or cancelled original.
; RDI current128, RSI zeroed out256, EDX256, ECXport, R8 requested zeroed host256.
an_select_policy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    mov r13d,ecx
    mov r14,r8
    mov qword [rel an_evaluated_deadline],0
    call app_vm_updater_role
    test eax,eax
    jz .live
    cmp eax,1
    jne .bad
%ifdef PAOS_UPDATER_CHANNEL_POLICY_INC
    mov rdi,rbx
    mov rsi,r12
    mov ecx,r13d
    mov r8,r14
    call unc_policy
    cmp eax,1
    jne .bad
    mov [rel an_evaluated_deadline],r8
    jmp .out
%else
    jmp .bad
%endif
.live:
    cmp qword [rel an_policy],0
    je .bad
    mov rdi,rbx
    mov rsi,r12
    mov edx,256
    mov ecx,r13d
    call [rel an_policy]
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%ifdef PAOS_UPDATER_CHANNEL_POLICY_INC
; Same immutable validated installed channel as C. Missing include denies above.
; ADMIN binds this include/config/policy identity to the qualified native build.
%include PAOS_UPDATER_CHANNEL_POLICY_INC
%ifndef PAOS_UPDATER_CHANNEL_NATIVE_V1
%error "qualified updater channel policy schema absent"
%endif
; Nested current getter copies only into the native stack. Native service checks
; original128 runtime/exit + original40 UI request/session/cancel/deadline itself.
unc_policy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,176
    mov rbx,rdi
    mov r12,rsi
    mov r13d,ecx
    mov r14,r8
    mov rdi,rsp
    mov esi,40
    lea rdx,[rsp+40]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .bad
    cmp edx,3
    jne .bad
    lea rdi,[rsp+40]
    mov rsi,rbx
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    cmp dword [rsp+12],1
    jne .bad
    cmp qword [rsp],0
    je .bad
    mov eax,[rsp+8]
    cmp eax,1
    je .feed
    cmp eax,2
    jne .bad
    cmp r13d,unc_asset_port
    jne .feed
    lea rdi,[rel unc_asset_host]
    mov rsi,r14
    mov ecx,32
    repe cmpsq
    jne .feed
    lea r15,[rel unc_asset_host]
    jmp .selected
.feed:
    cmp r13d,unc_feed_port
    jne .bad
    lea rdi,[rel unc_feed_host]
    mov rsi,r14
    mov ecx,32
    cld
    repe cmpsq
    jne .bad
    lea r15,[rel unc_feed_host]
.selected:
    mov rax,[rsp+32]
    mov ecx,1000
    mul rcx                           ; native boot_ms -> us, never Linux epoch
    test rdx,rdx
    jnz .bad
    test rax,rax
    jz .bad
    mov r14,rax
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,r14
    jae .bad
    mov rdi,r12
    mov rsi,r15
    mov ecx,32
    cld
    rep movsq
    mov rdx,[rsp]
    mov r8,r14
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
    xor r8d,r8d
.out:
    add rsp,176
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endif
