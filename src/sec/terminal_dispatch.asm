;; MODULE sec/terminal_dispatch
;; LAYER 6
;; PURPOSE Original typed request, single dispatch and frozen result paging.
;; EXPORTS terminal_policy_submit, terminal_policy_read_guard, terminal_policy_retire, terminal_policy_resume
;; IMPORTS sec/terminal_policy
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
; VM owns scalar framing/structural checks; SEC independently validates copied
; native frame and burns its floor before any planner, refusal or side effect.
; All retained private bytes are wiped synchronously on retire/revoke/lock.
terminal_policy_retire:
    TP_SAVE_VOL
    cmp qword [rel tp_provider_retire_op],0
    je .provider_retired
    call [rel tp_provider_retire_op] ; preserving, nonrecursive native FS staging
.provider_retired:
    call tp_command_retire
    mov byte [rel tp_result_valid],0
    mov byte [rel tp_result_spent],0
    mov byte [rel tp_pending_state],0
    mov byte [rel tp_effect_spent],0
    mov qword [rel tp_pending_id],0
    mov qword [rel tp_result_id],0
    mov qword [rel tp_result_len],0
    lea rdi,[rel tp_desc]
    xor eax,eax
    mov ecx,TP_DESC_BYTES/8
    rep stosq
    lea rdi,[rel tp_request]
    mov ecx,TP_WIRE_BYTES/8
    rep stosq
    lea rdi,[rel tp_pending_desc]
    mov ecx,TP_DESC_BYTES/8
    rep stosq
    lea rdi,[rel tp_pending_request]
    mov ecx,TP_WIRE_BYTES/8
    rep stosq
    lea rdi,[rel tp_result_desc]
    mov ecx,TP_DESC_BYTES/8
    rep stosq
    lea rdi,[rel tp_result]
    mov ecx,TP_RESULT_BYTES/8
    rep stosq
    TP_RESTORE_VOL
    ret

; RDI native frame ->1/0. Does not burn or bind by itself.
tp_wire_valid:
    cmp dword [rdi],1
    jne .bad
    mov eax,[rdi+4]
    cmp eax,1
    jb .bad
    cmp eax,3
    ja .bad
    cmp qword [rdi+8],0
    je .bad
    mov rax,[rdi+32]
    or rax,[rdi+40]
    or rax,[rdi+48]
    or rax,[rdi+56]
    jnz .bad
    cmp dword [rdi+4],3
    je .page
    cmp qword [rdi+16],0
    jne .bad
    cmp dword [rdi+24],0
    jne .bad
    mov ecx,[rdi+28]
    test ecx,ecx
    jz .bad
    cmp ecx,1023
    ja .bad
    xor edx,edx
.text:
    movzx eax,byte [rdi+rdx+64]
    cmp eax,0x20
    jb .bad
    cmp eax,0x7e
    ja .bad
    inc edx
    cmp edx,ecx
    jb .text
    jmp .tail
.page:
    cmp qword [rdi+16],0
    je .bad
    cmp dword [rdi+28],0
    jne .bad
    mov eax,[rdi+24]
    cmp eax,TP_RESULT_BYTES
    jae .bad
    test eax,1023
    jnz .bad
    xor edx,edx
.tail:
    cmp byte [rdi+rdx+64],0
    jne .bad
    inc edx
    cmp edx,1024
    jb .tail
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Fill only canonical TRM1 reply from frozen result. Does not run a handler.
; RDI reply1088, RSI request1088 ->0 or CMDE. Caller has revalidated result.
tp_page:
    push rbx
    mov rbx,rdi
    mov r9,rsi
    xor eax,eax
    mov ecx,TP_WIRE_BYTES/8
    rep stosq
    mov dword [rbx],1
    mov rax,[r9+8]
    mov [rbx+8],rax
    mov rax,[rel tp_result_id]
    mov [rbx+16],rax
    xor r10d,r10d
    cmp dword [r9+4],3
    jne .offset
    mov r10d,[r9+24]
.offset:
    mov [rbx+24],r10d
    mov rax,[rel tp_result_len]
    mov [rbx+32],eax
    cmp r10,rax
    ja .bad
    je .empty
    sub rax,r10
    cmp rax,1024
    jbe .length
    mov eax,1024
.length:
    mov [rbx+28],eax
    lea rcx,[rax+r10]
    cmp rcx,[rel tp_result_len]
    jae .last
    mov dword [rbx+36],1
.last:
    mov ecx,eax
    lea rsi,[rel tp_result]
    add rsi,r10
    lea rdi,[rbx+64]
    rep movsb
.empty:
    xor eax,eax
    jmp .out
.bad:
    mov rdi,rbx
    xor eax,eax
    mov ecx,TP_WIRE_BYTES/8
    rep stosq
    mov eax,CMDE_BADARG
.out:
    pop rbx
    ret

terminal_policy_submit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdx
    mov r13,r8
    mov r14d,ecx
    ; Refuse reentry without destroying the original in-flight state.
    cmp byte [rel tp_busy],0
    jne .denied
    test r12,r12
    jz .clear_denied
    test r13,r13
    jz .clear_denied
    cmp r14d,TP_WIRE_BYTES
    jne .clear_denied
    call terminal_policy_probe
    test rax,rax
    jz .clear_denied
    mov rax,[r12+8]
    cmp rax,[rel tp_floor]
    jbe .clear_denied
    mov [rel tp_floor],rax              ; burned before parser/planner/dispatch
    mov rdi,r12
    call tp_wire_valid
    test eax,eax
    jz .badarg
    cmp dword [r12+4],3
    je .page
    cmp byte [rel tp_pending_state],0
    jne .denied                        ; no replacement of one pending action
    call terminal_policy_retire
    mov byte [rel tp_busy],1
    mov rsi,r12
    lea rdi,[rel tp_request]
    mov ecx,TP_WIRE_BYTES/8
    rep movsq
    cmp qword [rel tp_ops],0
    je .finish_denied
    lea rdi,[rel tp_request]
    lea rsi,[rel tp_desc]
    call [rel tp_ops]                   ; native canonical final operation only
    cmp eax,1
    jne .finish_denied
    ; Planner may expand HOOK into the canonical final native command, but
    ; cannot change framing, sequence or principal. Freeze and hash actual text.
    lea rdi,[rel tp_request]
    call tp_wire_valid
    test eax,eax
    jz .finish_denied
    mov rax,[rel tp_request+8]
    cmp rax,[rel tp_floor]
    jne .finish_denied
    cmp dword [rel tp_request+4],3
    je .finish_denied
    mov edx,[rel tp_request+28]
    mov [rel tp_desc+TP_D_ARGLEN],rdx
    lea rdi,[rel tp_desc+TP_D_ARGHASH]
    lea rsi,[rel tp_request+64]
    call sha256_hash
    test rax,rax
    jnz .finish_denied
    ; Mint identity, generation, sequence and deadline ourselves. A planner
    ; supplies final operation/operand facts, never principal or session proof.
    mov qword [rel tp_desc+TP_D_VERSION],1
    mov rax,[rel tp_pid]
    mov [rel tp_desc+TP_D_PID],rax
    mov rax,[rel tp_serial]
    mov [rel tp_desc+TP_D_BIND],rax
    mov eax,[rel tp_start]
    mov [rel tp_desc+TP_D_START],rax
    mov rax,[rel tp_epoch]
    mov [rel tp_desc+TP_D_VM],rax
    mov rax,[rel tp_session]
    mov [rel tp_desc+TP_D_SESSION],rax
    mov rax,[rel tp_generation]
    mov [rel tp_desc+TP_D_POLICY],rax
    mov rax,[rel tp_floor]
    mov [rel tp_desc+TP_D_SEQ],rax
    call time_monotonic_now_us
    test rax,rax
    jz .finish_denied
    add rax,TP_BUDGET_US
    jc .finish_denied
    mov [rel tp_desc+TP_D_UNTIL],rax
    lea rdi,[rel tp_desc]
    call tp_validate
    test eax,eax
    jz .finish_denied
    lea rdi,[rel tp_desc]
    call tp_tier
    cmp eax,3
    je .ask
    lea rdi,[rel tp_desc]
    call terminal_policy_check
    test eax,eax
    jz .finish_denied
    call tp_execute
    mov ebx,eax
    mov byte [rel tp_busy],0
    test ebx,ebx
    jnz .returned_error
    lea rdi,[rel tp_result_desc]
    call terminal_policy_copyout
    test eax,eax
    jz .clear_denied
    mov rdi,r13
    mov rsi,r12
    call tp_page
    jmp .out
.ask:
    cmp qword [rel tp_pending_serial],-1
    je .finish_denied
    call time_monotonic_now_us
    test rax,rax
    jz .finish_denied
    add rax,TP_CLICK_US
    jc .finish_denied
    mov [rel tp_desc+TP_D_UNTIL],rax
    lea rsi,[rel tp_desc]
    lea rdi,[rel tp_pending_desc]
    mov ecx,TP_DESC_BYTES/8
    rep movsq
    lea rsi,[rel tp_request]
    lea rdi,[rel tp_pending_request]
    mov ecx,TP_WIRE_BYTES/8
    rep movsq
    inc qword [rel tp_pending_serial]
    mov rax,[rel tp_pending_serial]
    mov [rel tp_pending_id],rax
    mov byte [rel tp_pending_state],1
    mov byte [rel tp_busy],0
    ; AUTHDENY honestly reports no effect yet. UI owns original continuation;
    ; polling PAGE never executes a mutation, nor does a higher-seq resubmit.
    jmp .denied
.page:
    cmp byte [rel tp_result_valid],1
    jne .denied
    mov rax,[r12+16]
    cmp rax,[rel tp_result_id]
    jne .clear_denied
    lea rdi,[rel tp_result_desc]
    call terminal_policy_copyout
    test eax,eax
    jz .clear_denied
    mov rdi,r13
    mov rsi,r12
    call tp_page
    jmp .out
.returned_error:
    mov eax,ebx
    jmp .out
.finish_denied:
    mov byte [rel tp_busy],0
.clear_denied:
    call terminal_policy_retire
.denied:
    mov edi,TP_EV_REFUSE
    xor esi,esi
    mov edx,CMDE_AUTHDENY
    xor ecx,ecx
    call tp_audit
    mov eax,CMDE_AUTHDENY
    jmp .out
.badarg:
    call terminal_policy_retire
    mov eax,CMDE_BADARG
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Run an original frozen invocation once. No caller-provided executable target.
; Adapter must call terminal_policy_effect before every state change. A tier3
; adapter which reports success without consuming is refused, never accepted.
tp_execute:
    push rbx
    cmp qword [rel tp_ops+16],0
    je .deny
    lea rdi,[rel tp_desc]
    call terminal_policy_check
    test eax,eax
    jz .deny
    lea rdi,[rel tp_desc]
    lea rsi,[rel tp_result]
    lea rdx,[rel tp_request]
    mov ecx,TP_RESULT_BYTES
    call [rel tp_ops+16]
    cmp eax,255
    ja .deny
    test eax,eax
    jnz .error
    cmp edx,TP_RESULT_BYTES
    ja .deny
    mov [rel tp_result_len],rdx
    lea rdi,[rel tp_desc]
    call tp_tier
    cmp eax,3
    jne .recheck
    cmp byte [rel tp_effect_spent],1
    jne .deny
.recheck:
    lea rdi,[rel tp_desc]
    call terminal_policy_check
    test eax,eax
    jz .deny
    lea rdi,[rel tp_result_desc]
    lea rsi,[rel tp_desc]
    mov ecx,TP_DESC_BYTES/8
    rep movsq
    mov rax,[rel tp_desc+TP_D_SEQ]
    mov [rel tp_result_id],rax
    mov al,[rel tp_effect_spent]
    mov [rel tp_result_spent],al
    mov byte [rel tp_result_valid],1
    mov edi,TP_EV_ALLOW
    mov rsi,[rel tp_desc+TP_D_OP]
    mov rcx,[rel tp_desc+TP_D_SCOPE]
    xor edx,edx
    call tp_audit
    xor eax,eax
    jmp .out
.deny:
    mov eax,CMDE_AUTHDENY
.error:
    mov ebx,eax
    call terminal_policy_retire
    mov eax,ebx
.out:
    pop rbx
    ret

; LIVE calls at depth0 after physical approval; original private request only.
; Result belongs original seq. Lost reply cannot cause an automatic execution.
terminal_policy_resume:
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp byte [rel tp_pending_state],2
    jne .bad
    lea rdi,[rel tp_pending_desc]
    call tp_validate
    test eax,eax
    jz .cancel
    mov byte [rel tp_busy],1
    mov byte [rel tp_effect_spent],0
    lea rdi,[rel tp_desc]
    lea rsi,[rel tp_pending_desc]
    mov ecx,TP_DESC_BYTES/8
    rep movsq
    lea rdi,[rel tp_request]
    lea rsi,[rel tp_pending_request]
    mov ecx,TP_WIRE_BYTES/8
    rep movsq
    call tp_execute
    push rax
    mov byte [rel tp_busy],0
    mov byte [rel tp_pending_state],0
    mov qword [rel tp_pending_id],0
    lea rdi,[rel tp_pending_request]
    xor eax,eax
    mov ecx,TP_WIRE_BYTES/8
    rep stosq
    lea rdi,[rel tp_pending_desc]
    mov ecx,TP_DESC_BYTES/8
    rep stosq
    pop rax
    ret
.cancel:
    call terminal_policy_retire
.bad:
    mov eax,CMDE_AUTHDENY
    ret

; A result word must match the frozen original content and current authority.
; Errors contain no bytes; PAGE never inherits authority from the new seq.
terminal_policy_read_guard:
    push rbx
    push r12
    push r13
    mov rbx,rdx
    mov r12,r8
    mov r13d,ecx
    call tp_driver_live
    test eax,eax
    jz .bad
    cmp r13d,TP_WIRE_BYTES-4
    ja .bad
    test r13d,3
    jnz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    test rbx,rbx
    jz .bad
    test r12,r12
    jz .bad
    mov rdi,rbx
    call tp_wire_valid
    test eax,eax
    jz .bad
    mov rax,[rbx+8]
    cmp rax,[rel tp_floor]
    jne .bad
    cmp dword [r12],1
    jne .bad
    cmp [r12+8],rax
    jne .bad
    cmp dword [r12+4],0
    jne .error_reply
    cmp byte [rel tp_result_valid],1
    jne .bad
    mov rax,[rel tp_result_id]
    cmp rax,[r12+16]
    jne .bad
    cmp dword [rbx+4],3
    je .page
    cmp rax,[rbx+8]
    jne .bad
    cmp dword [r12+24],0
    jne .bad
    jmp .authorized
.page:
    cmp rax,[rbx+16]
    jne .bad
    mov eax,[rbx+24]
    cmp eax,[r12+24]
    jne .bad
.authorized:
    lea rdi,[rel tp_result_desc]
    call terminal_policy_copyout
    test eax,eax
    jz .bad
    ; Check canonical page bounds before native memcmp of this one payload
    ; word. The transport freezes header/zero-padding; security owns content.
    mov eax,[r12+24]
    add eax,[r12+28]
    jc .bad
    cmp rax,[rel tp_result_len]
    ja .bad
    cmp dword [r12+28],1024
    ja .bad
    mov rax,[rel tp_result_len]
    cmp [r12+32],eax
    jne .bad
    cmp r13d,64
    jb .yes
    mov edx,r13d
    sub edx,64
    cmp edx,[r12+28]
    jae .padding
    mov ecx,[r12+24]
    add ecx,edx
    lea rsi,[rel tp_result]
    mov eax,[rsi+rcx]
    cmp eax,[r12+r13]
    jne .bad
    jmp .yes
.padding:
    cmp dword [r12+r13],0
    jne .bad
    jmp .yes
.error_reply:
    cmp dword [r12+4],255
    ja .bad
    ; Header only/zeroed bytes16..1087, never private result authority.
    lea rdi,[r12+16]
    mov ecx,(TP_WIRE_BYTES-16)/8
    xor eax,eax
.zeros:
    or rax,[rdi]
    add rdi,8
    loop .zeros
    test rax,rax
    jnz .bad
.yes:
    mov eax,1
    jmp .out
.bad:
    call terminal_policy_retire
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
