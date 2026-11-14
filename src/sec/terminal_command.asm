;; MODULE sec/terminal_command
;; LAYER 6
;; PURPOSE Exact native TERMINAL ticket through the one command registry.
;; EXPORTS terminal_policy_command_dispatch, terminal_policy_authorize, terminal_policy_command_effect, terminal_policy_command_copyout
;; IMPORTS svc/command, svc/command_auth, sec/terminal_policy
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
; Private native helper ABI deliberately uses fixed copies of CMDREQ56/CMDRSP48
; and the shared AUTH_T_SIZE ticket. INPUT adds state11 routing only; no legacy state or OWNER gate
; changes. The planner owns all typed argument/selector marshalling and the
; final object validator. No payload pointer is ever accepted as native memory.
TP_AUTH_TERMINAL equ 11

; command_dispatch(desc256, native req56, native out_rsp48)->CMDE.
; Exactly one registry entry, original TERM principal. No recursive dispatch,
; idempotency-cache reuse, internal cap fallback, OWNER swap or automatic retry.
terminal_policy_command_dispatch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r13,rsi
    mov r12,rdx
    cmp byte [rel tp_cmd_active],0
    jne .deny
    cmp byte [rel tp_busy],1
    jne .deny
    cmp dword [rel cmd_dispatch_depth],0
    jne .deny
    cmp byte [rel command_auth_remote_active],0
    jne .deny
    test r13,r13
    jz .deny
    test r12,r12
    jz .deny
    call terminal_policy_check
    test eax,eax
    jz .deny
    mov rdi,[r13]                       ; exact native registry id
    call command_verb_count
    cmp [r13],rax
    jae .deny
    mov rdi,[r13]
    call command_verb_name
    mov r14,rax
    test rax,rax
    jz .deny
    ; Actual canonical command first token must equal the registry's name.
    ; HOOK planners expand to this final command before freezing/displaying.
    lea rsi,[rel tp_request+64]
    mov rdi,r14
    xor ecx,ecx
.name:
    mov al,[rdi+rcx]
    test al,al
    jz .name_end
    cmp ecx,63
    jae .deny
    cmp al,[rsi+rcx]
    jne .deny
    inc ecx
    jmp .name
.name_end:
    test ecx,ecx
    jz .deny
    cmp byte [rsi+rcx],0
    je .name_ok
    cmp byte [rsi+rcx],' '
    jne .deny
.name_ok:
    mov rdi,[r13]
    call command_verb_cap
    mov r15,rax
    mov rdi,[r13]
    call command_verb_destr
    mov rdi,r14
    mov rsi,r15
    mov rdx,rax
    call command_auth_required_cap
    mov r15,rax
    mov rsi,r13
    lea rdi,[rel tp_cmd_request]
    mov ecx,7
    rep movsq
    mov [rel tp_cmd_request+8],r15
    mov qword [rel tp_cmd_request+16],0 ; no generic replay cache admission
    mov qword [rel tp_cmd_request+40],8 ; CMD_SOURCE_GUEST
    mov rax,[rel tp_pid]
    mov [rel tp_cmd_request+48],rax
    mov [rel tp_cmd_ticket+48],rax
    mov [rel tp_cmd_ticket],r15
    mov rax,[rbx+TP_D_SEQ]
    mov [rel tp_cmd_ticket+8],rax
    mov qword [rel tp_cmd_ticket+16],0
    mov rax,[rbx+TP_D_UNTIL]
    mov [rel tp_cmd_ticket+24],rax
    mov [rel tp_cmd_ticket+32],r14
    mov qword [rel tp_cmd_ticket+40],TP_AUTH_TERMINAL
    mov [rel tp_cmd_desc],rbx
    mov byte [rel tp_cmd_active],1
    lea rdi,[rel tp_cmd_ticket]
    call command_auth_remote_begin
    lea rdi,[rel tp_cmd_request]
    lea rsi,[rel tp_cmd_response]
    call command_dispatch
    mov r13,rax
    call command_auth_remote_end
    mov rdi,rbx
    call terminal_policy_check
    test eax,eax
    jz .clear_deny
    mov rdi,r12
    lea rsi,[rel tp_cmd_response]
    mov ecx,6
    rep movsq
    mov byte [rel tp_cmd_active],0
    call tp_command_retire
    mov rax,r13
    jmp .out
.clear_deny:
    call tp_command_retire
.deny:
    test r12,r12
    jz .code
    mov rdi,r12
    xor eax,eax
    mov ecx,6
    rep stosq
    mov qword [r12],CMDE_AUTHDENY
.code:
    mov eax,CMDE_AUTHDENY
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; command_auth_authorize native state11 branch calls exactly this function.
; EAX0 means authorized; -1 denied. A copied/forged ticket is never authority.
terminal_policy_authorize:
    push rbx
    lea rax,[rel tp_cmd_ticket]
    cmp rdi,rax
    jne .bad
    cmp byte [rel tp_cmd_active],1
    jne .bad
    cmp byte [rel tp_busy],1
    jne .bad
    cmp dword [rel cmd_dispatch_depth],1
    jne .bad
    cmp byte [rel command_auth_remote_active],1
    jne .bad
    cmp rdi,[rel command_auth_remote_ticket]
    jne .bad
    cmp rsi,[rdi]
    jne .bad
    cmp rdx,[rdi+32]
    jne .bad
    cmp qword [rdi+40],TP_AUTH_TERMINAL
    jne .bad
    mov rax,[rel tp_pid]
    cmp rax,[rdi+48]
    jne .bad
    cmp rax,[rel tp_cmd_request+48]
    jne .bad
    cmp qword [rel tp_cmd_request+40],8
    jne .bad
    cmp qword [rel tp_cmd_request+16],0
    jne .bad
    mov rax,[rdi]
    cmp rax,[rel tp_cmd_request+8]
    jne .bad
    mov rbx,[rel tp_cmd_desc]
    test rbx,rbx
    jz .bad
    mov rax,[rdi+8]
    cmp rax,[rbx+TP_D_SEQ]
    jne .bad
    mov rax,[rdi+24]
    cmp rax,[rbx+TP_D_UNTIL]
    jne .bad
    mov rdi,rbx
    call terminal_policy_check
    test eax,eax
    jz .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret

; Native final handler delegation: its exact original req, not ambient OWNER.
; Call effect immediately before ONE actual mutation, with no intervening yield.
tp_command_current:
    lea rax,[rel tp_cmd_request]
    cmp rdi,rax
    jne .bad
    lea rdi,[rel tp_cmd_ticket]
    mov rsi,[rdi]
    mov rdx,[rdi+32]
    jmp terminal_policy_authorize
.bad:
    mov eax,-1
    ret
terminal_policy_command_effect:
    call tp_command_current
    test eax,eax
    jnz .bad
    mov rdi,[rel tp_cmd_desc]
    jmp terminal_policy_effect
.bad:
    xor eax,eax
    ret
terminal_policy_command_copyout:
    call tp_command_current
    test eax,eax
    jnz .bad
    mov rdi,[rel tp_cmd_desc]
    jmp terminal_policy_copyout
.bad:
    xor eax,eax
    ret

; Called under the policy preserving retire wrapper, and after registry return.
tp_command_retire:
    mov byte [rel tp_cmd_active],0
    mov qword [rel tp_cmd_desc],0
    lea rdi,[rel tp_cmd_ticket]
    xor eax,eax
    mov ecx,(AUTH_T_SIZE+56+48)/8
    rep stosq
    ret
%macro WDATA_terminal_command 0
align 8
tp_cmd_desc: dq 0
tp_cmd_active: db 0
align 8
tp_cmd_ticket: times AUTH_T_SIZE db 0
tp_cmd_request: times 56 db 0
tp_cmd_response: times 48 db 0
%endmacro
WDATA_DEFER WDATA_terminal_command
