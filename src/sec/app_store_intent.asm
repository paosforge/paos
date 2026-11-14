;; MODULE sec/app_store_intent
;; LAYER 6
;; PURPOSE Fixed native app write scope with live physical intent at every effect.
;; EXPORTS app_store_intent_write, app_store_effect_check
;; IMPORTS gui/app_install, gui/app_remove, sec/app_store_authority, sec/app_store_seal, sec/session, svc/command, fs/data_config_provider, core/smp
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
; This module never manufactures or consumes the GUI's human intent. It holds
; only a synchronous write scope. GUI consumes its original intent once across
; the complete install/remove operation, including an uncertain result.
; No caller-selected checker/path, no guest entry and no IO before seal+intent.
; Native caller owns mapped lifetimes. No callback can change the private clone.
; write(token112,record,len,intent,op1INSTALL/2REMOVE)->provider0/-1/-2/-3.
app_store_intent_write:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov ebx,r8d
    ; Full-width operation and all native ranges before entering scratch.
    cmp r8,1
    je .operation
    cmp r8,2
    jne .refuse
.operation:
    test r15,r15
    jz .refuse
    cmp r14,ASL_PAYLOAD
    jb .refuse
    cmp r14,ASL_MAX
    ja .refuse
    mov esi,112
    call asi_disjoint
    test eax,eax
    jz .refuse
    mov rdi,r13
    mov rsi,r14
    call asi_disjoint
    test eax,eax
    jz .refuse
    ; Token and source must not overlap each other.
    lea rax,[r12+112]
    cmp r13,rax
    jae .ranges
    lea rax,[r13+r14]
    cmp r12,rax
    jb .refuse
.ranges:
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel asi_busy],0
    jne .busy
    mov byte [rel asi_busy],1
    call asi_owner
    test eax,eax
    jz .fail
    mov [rel asi_epoch],rdx
    mov [rel asi_id],r15
    mov [rel asi_operation],rbx
    mov [rel asi_length],r14
    lea rdi,[rel asi_token]
    mov rsi,r12
    mov ecx,14
    cld
    rep movsq
    lea rdi,[rel asi_image]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    lea rdi,[rel asi_image]
    mov rsi,r14
    call app_store_seal_open
    cmp eax,1
    jne .fail
    mov byte [rel asi_active],1
    mov rdi,r15
    mov esi,ebx
    lea rdx,[rel asi_token]
    call app_store_effect_check
    test rax,rax
    jnz .fail
    lea rdi,[rel asi_token]
    lea rsi,[rel asi_image]
    mov rdx,r14
    mov rcx,r15
    mov r8d,ebx
    call app_store_data_write
    mov r12,rax
    test rax,rax
    jnz .result
    ; A lost authority after an already durable effect is still uncertain to
    ; this caller, never a pre-effect refusal and never automatic retry.
    mov rdi,r15
    mov esi,ebx
    lea rdx,[rel asi_token]
    call app_store_effect_check
    test rax,rax
    jz .result
    mov r12,-3
    jmp .result
.fail:
    mov r12,-1
.result:
    mov byte [rel asi_active],0
    lea rdi,[rel asi_scope]
    xor eax,eax
    mov ecx,asi_scope_end-asi_scope
    cld
    rep stosb
    mov byte [rel asi_busy],0
    mov rax,r12
    jmp .out
.busy:
    mov rax,-2
    jmp .out
.refuse:
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Fixed FS callback: RDI=original GUI intent, RSI=full-width op, RDX=fresh
; canonical DATA token112. Returns0 current /-1 refused. Never consumes.
; FS independently freshly checks sealed role before and after every invocation.
app_store_effect_check:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov rbx,rdx
    call smp_current_logical
    test eax,eax
    jnz .no
    cmp byte [rel asi_busy],1
    jne .no
    cmp byte [rel asi_active],1
    jne .no
    test r12,r12
    jz .no
    cmp r12,[rel asi_id]
    jne .no
    cmp r13,[rel asi_operation]
    jne .no
    test rbx,rbx
    jz .no
    mov rax,rbx
    add rax,112
    jc .no
    call asi_owner
    test eax,eax
    jz .no
    cmp rdx,[rel asi_epoch]
    jne .no
    lea rsi,[rel asi_token]
    mov rdi,rbx
    mov ecx,14
    cld
    repe cmpsq
    jne .no
    mov rdi,rbx
    call data_config_current
    test rax,rax
    jnz .no
    mov rdi,r12
    cmp r13,1
    je .install
    cmp r13,2
    jne .no
    call app_remove_intent_check
    jmp .checked
.install:
    call app_install_intent_check
.checked:
    cmp eax,1
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

asi_owner:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .no
    cmp rdx,-1
    je .no
    mov eax,1
    ret
.no:
    xor eax,eax
    xor edx,edx
    ret

asi_disjoint:
    test rdi,rdi
    jz .no
    mov rax,rdi
    add rax,rsi
    jc .no
    lea rdx,[rel asi_private_end]
    cmp rdi,rdx
    jae .yes
    lea rdx,[rel asi_private_begin]
    cmp rax,rdx
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_app_store_intent 0
alignb 8
asi_private_begin:
asi_busy: resb 1
asi_active: resb 1
alignb 8
asi_scope:
asi_id: resq 1
asi_operation: resq 1
asi_epoch: resq 1
asi_length: resq 1
asi_token: resb 112
asi_image: resb ASL_MAX
asi_scope_end:
asi_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_app_store_intent
