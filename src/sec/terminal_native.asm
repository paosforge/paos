;; MODULE sec/terminal_native
;; LAYER 6
;; PURPOSE Native registry projection, fail-closed provider composition and boot wiring.
;; EXPORTS terminal_policy_runtime_init, terminal_policy_native_configure
;; IMPORTS svc/command, svc/command_auth, svc/command_udp, hv/terminal_transport, svc/command_documents, gui/terminal_provider, gui/terminal_consent, sec/terminal_grants_store
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
; Native optional provider table: plan,validate,execute,prepare_scope,
; validate_saved_scope,retire. No guest-supplied pointer or filename label.
; Native GUI/FS slots register separately through terminal_policy_provider_register.
; Each provider must independently prove final operation/operands,
; exclusions and custody; use command helper/effect/copyout at actual handlers.
terminal_policy_native_configure:
    push rbx
    mov rbx,rdi
    call tp_native_idle
    test eax,eax
    jz .bad
    call terminal_policy_invalidate
    lea rdi,[rel tpn_provider]
    xor eax,eax
    mov ecx,6
    rep stosq
    test rbx,rbx
    jz .ok                         ; zero uninstalls, never enables reads
    mov rsi,rbx
    lea rdi,[rel tpn_provider]
    mov ecx,6
    rep movsq
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Actual GUI initialization after terminal_consent_init, once all modules are
; included. No target IO, store write, human impersonation or automatic action.
terminal_policy_runtime_init:
    call tp_native_idle
    test eax,eax
    jz .bad
    call tpn_tables_init             ; org0 image: publish actual relocated pointers
    lea rdi,[rel terminal_request_endpoint]
    call terminal_policy_init
    cmp eax,1
    jne .bad
    lea rdi,[rel terminal_policy_invalidate]
    call guest_request_configure_terminal_lifecycle
    cmp eax,1
    jne .bad
    lea rdi,[rel tpn_ops]
    call terminal_policy_configure
    cmp eax,1
    jne .bad
    lea rdi,[rel tpn_ui_ops]
    call terminal_policy_ui_configure
    cmp eax,1
    jne .bad
    lea rdi,[rel tpn_retire]
    call terminal_policy_provider_retire_configure
    cmp eax,1
    jne .bad
    lea rdi,[rel tpn_consent_ops]
    call terminal_consent_configure
    cmp eax,1
    jne .bad
    lea rdi,[rel tpn_transport_ops]
    call terminal_transport_configure
    cmp eax,1
    jne .bad
    ; Actual native GUI table, after consent/transport setup and before any
    ; fresh binding can restore saved scopes. Zero removes stale GUI authority
    ; on initializer refusal; public reads and an independent FS slot survive.
    call terminal_gui_provider_init
    mov rsi,rax
    mov edi,1
    call terminal_policy_provider_register
    cmp eax,1
    jne .bad
    ; Register the real Documents provider in its independent FS slot too.
    ; A refused initializer removes stale FS authority; GUI remains installed.
    ; Both actual slots must be settled before a fresh binding restores scopes.
    call terminal_documents_provider_init
    mov rsi,rax
    mov edi,2
    call terminal_policy_provider_register
    cmp eax,1
    jne .bad
    mov byte [rel tpn_auto_restore],1
    ret
.bad:
    mov byte [rel tpn_auto_restore],0
    call terminal_policy_invalidate
    xor eax,eax
    ret

; Native pointer ABI is unchanged. These writable tables start at zero; LEA
; materializes this image mapping, never an org0 image offset or guest pointer.
; Only the existing idle runtime initializer publishes them to consumers.
tpn_tables_init:
    lea rax,[rel tpn_plan]
    mov [rel tpn_ops],rax
    lea rax,[rel tpn_validate]
    mov [rel tpn_ops+8],rax
    lea rax,[rel tpn_execute]
    mov [rel tpn_ops+16],rax
    lea rax,[rel tpn_indicator]
    mov [rel tpn_ops+24],rax
    lea rax,[rel tpn_prepare]
    mov [rel tpn_ui_ops],rax
    lea rax,[rel terminal_grants_store_save]
    mov [rel tpn_ui_ops+8],rax
    lea rax,[rel terminal_grants_store_load]
    mov [rel tpn_ui_ops+16],rax
    lea rax,[rel terminal_grants_store_clear]
    mov [rel tpn_ui_ops+24],rax
    lea rax,[rel tpn_restore_validate]
    mov [rel tpn_ui_ops+32],rax
    lea rax,[rel terminal_policy_state]
    mov [rel tpn_consent_ops],rax
    lea rax,[rel terminal_policy_ui_pending]
    mov [rel tpn_consent_ops+8],rax
    lea rax,[rel terminal_policy_ui_approve]
    mov [rel tpn_consent_ops+16],rax
    lea rax,[rel terminal_policy_deny]
    mov [rel tpn_consent_ops+24],rax
    lea rax,[rel terminal_policy_ui_revoke]
    mov [rel tpn_consent_ops+32],rax
    lea rax,[rel terminal_policy_prepare_scope]
    mov [rel tpn_consent_ops+40],rax
    lea rax,[rel terminal_policy_ui_grant]
    mov [rel tpn_consent_ops+48],rax
    lea rax,[rel terminal_policy_probe]
    mov [rel tpn_transport_ops],rax
    lea rax,[rel terminal_policy_submit]
    mov [rel tpn_transport_ops+8],rax
    lea rax,[rel terminal_policy_read_guard]
    mov [rel tpn_transport_ops+16],rax
    lea rax,[rel terminal_policy_retire]
    mov [rel tpn_transport_ops+24],rax
    lea rax,[rel command_catalog_help_verb]
    mov [rel tpn_safe+0],rax
    lea rax,[rel tpn_help]
    mov [rel tpn_safe+8],rax
    lea rax,[rel cmd_verb_catalog]
    mov [rel tpn_safe+24],rax
    lea rax,[rel tpn_catalog]
    mov [rel tpn_safe+32],rax
    lea rax,[rel cmd_verb_status]
    mov [rel tpn_safe+48],rax
    lea rax,[rel tpn_status]
    mov [rel tpn_safe+56],rax
    lea rax,[rel cmd_verb_netcheck]
    mov [rel tpn_safe+72],rax
    lea rax,[rel tpn_netcheck]
    mov [rel tpn_safe+80],rax
    lea rax,[rel cmd_verb_tcpstat]
    mov [rel tpn_safe+96],rax
    lea rax,[rel tpn_tcpstat]
    mov [rel tpn_safe+104],rax
    ret

; Parse only a finite safe set of exact native handler identities. Registry
; registration/cap=0 alone NEVER grants permission. Native marshalling uses
; strings for HELP/CATALOG and checked decimal u64 for STATUS, no selectors.
; RDI frame1088 -> EAX op or0, RDX verb id, R8 typed argument, R9 arg text.
tpn_parse:
    push rbx
    push r12
    push r13
    push r14
    mov r12,rdi
    cmp dword [r12+4],1
    jne .bad                        ; raw hooks need native final-plan provider
    lea rsi,[r12+64]
    lea rdi,[rel tpn_name]
    xor ecx,ecx
.name:
    cmp ecx,63
    jae .bad
    mov al,[rsi+rcx]
    test al,al
    jz .end_name
    cmp al,' '
    je .end_name
    cmp al,'A'
    jb .bad
    cmp al,'Z'
    ja .bad
    mov [rdi+rcx],al
    inc ecx
    jmp .name
.end_name:
    test ecx,ecx
    jz .bad
    mov byte [rdi+rcx],0
    lea r13,[rsi+rcx]
    cmp byte [r13],0
    je .argument
    inc r13
    cmp byte [r13],0
    je .bad                         ; no ambiguous empty/trailing-space field
.argument:
    lea rdi,[rel tpn_name]
    call command_lookup
    cmp rax,-1
    je .bad
    mov r14,rax
    call command_verb_count
    cmp r14,rax
    jae .bad
    imul rbx,r14,48
    lea rax,[rel verb_table]
    add rbx,rax
    cmp qword [rbx+16],0
    jne .bad
    cmp qword [rbx+40],0
    jne .bad
    lea r12,[rel tpn_safe]
    mov ecx,5
.safe:
    mov rax,[r12]
    cmp rax,[rbx+8]
    je .found
    add r12,24
    loop .safe
    jmp .bad
.found:
    ; A handler alias cannot substitute another name or argument contract.
    mov rdi,[rbx]
    mov rsi,[r12+8]
    xor ecx,ecx
.exact_name:
    mov al,[rdi+rcx]
    cmp al,[rsi+rcx]
    jne .bad
    test al,al
    jz .typed
    inc ecx
    cmp ecx,63
    jb .exact_name
    jmp .bad
.typed:
    mov r8,r13
    cmp dword [r12+20],0
    je .no_arg
    cmp dword [r12+20],1
    je .ok                          ; bounded printable literal, no parser exec
    xor r8d,r8d                     ; checked STATUS job id, empty means0
    mov rsi,r13
.number:
    movzx eax,byte [rsi]
    test al,al
    jz .ok
    sub eax,'0'
    cmp eax,9
    ja .bad
    mov rdx,0x1999999999999999
    cmp r8,rdx
    ja .bad
    jne .mul
    cmp eax,5
    ja .bad
.mul:
    imul r8,r8,10
    add r8,rax
    inc rsi
    jmp .number
.no_arg:
    cmp byte [r13],0
    jne .bad
    xor r8d,r8d
.ok:
    mov eax,[r12+16]
    mov rdx,r14
    mov r9,r13
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

tpn_plan:
    push rbx
    push r12
    mov rbx,rsi
    mov r12,rdi
    call tpn_parse
    test eax,eax
    jz .provider
    mov [rbx+TP_D_OP],rax
    mov eax,1
    jmp .out
.provider:
    cmp qword [rel tpn_provider],0
    je .bad
    mov rdi,r12
    mov rsi,rbx
    call [rel tpn_provider]
    cmp eax,1
    jne .bad
    ; Providers may add explicitly classified values/read/action operations,
    ; never reclassify arbitrary commands as one of the fixed public handlers.
    cmp qword [rbx+TP_D_OP],TP_PUBLIC_VALUE
    jb .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

tpn_validate:
    push rbx
    mov rbx,rdi
    cmp qword [rbx+TP_D_OP],TP_PUBLIC_VALUE
    jae .provider
    lea rdi,[rel tp_request]
    call tpn_parse
    test eax,eax
    jz .bad
    cmp rax,[rbx+TP_D_OP]
    jne .bad
    mov rax,[rbx+TP_D_SCOPE]
    or rax,[rbx+TP_D_TARGET]
    or rax,[rbx+TP_D_TARGETGEN]
    jnz .bad
    lea rdi,[rbx+TP_D_SCOPEKEY]
    xor eax,eax
    mov ecx,8
.key:
    or rax,[rdi]
    add rdi,8
    loop .key
    test rax,rax
    jnz .bad
    mov eax,1
    jmp .out
.provider:
    cmp qword [rel tpn_provider+8],0
    je .bad
    mov rdi,rbx
    call [rel tpn_provider+8]
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

tpn_execute:
    cmp qword [rdi+TP_D_OP],TP_PUBLIC_VALUE
    jae .provider
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    lea rdi,[rel tp_request]
    call tpn_parse
    test eax,eax
    jz .deny
    cmp rax,[rbx+TP_D_OP]
    jne .deny
    mov r13,r9
    mov r14,rdx
    lea rdi,[rel tpn_request]
    xor eax,eax
    mov ecx,7+6
    rep stosq
    mov [rel tpn_request],r14
    mov [rel tpn_request+32],r8
    mov rdi,rbx
    lea rsi,[rel tpn_request]
    lea rdx,[rel tpn_response]
    call terminal_policy_command_dispatch
    test eax,eax
    jnz .error
    mov rdi,r14
    call command_verb_name
    mov rdi,rax
    mov rsi,r13
    lea rdx,[rel tpn_response]
    call command_udp_capture_reply   ; canonical formatter, NEVER network TX
    test rax,rax
    jz .deny
    test edx,edx
    jz .deny
    cmp edx,TP_RESULT_BYTES
    ja .deny
    mov r13,rax
    mov r14d,edx
    mov rdi,rbx
    call terminal_policy_copyout
    test eax,eax
    jz .deny
    mov rdi,r12
    mov rsi,r13
    mov ecx,r14d
    rep movsb
    mov edx,r14d
    xor eax,eax
    jmp .out
.deny:
    mov eax,CMDE_AUTHDENY
.error:
    xor edx,edx
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.provider:
    cmp qword [rel tpn_provider+16],0
    je .missing
    jmp [rel tpn_provider+16]
.missing:
    mov eax,CMDE_AUTHDENY
    xor edx,edx
    ret

tpn_indicator:
    call terminal_consent_present
    cmp eax,1
    jne .bad
    jmp terminal_consent_visible
.bad:
    xor eax,eax
    ret
tpn_prepare:
    cmp qword [rel tpn_provider+24],0
    je .bad
    jmp [rel tpn_provider+24]
.bad:
    xor eax,eax
    ret
tpn_restore_validate:
    cmp qword [rel tpn_provider+32],0
    je .bad
    jmp [rel tpn_provider+32]
.bad:
    xor eax,eax
    ret
; Preserving, nonrecursive and bounded. Cancel actual provider staging first.
tpn_retire:
    TP_SAVE_VOL
    cmp qword [rel tpn_provider+40],0
    je .wipe
    call [rel tpn_provider+40]
.wipe:
    lea rdi,[rel tpn_name]
    xor eax,eax
    mov ecx,(64+56+48)/8
    rep stosq
    TP_RESTORE_VOL
    ret

%include "sec/terminal_providers.asm"

%macro WDATA_terminal_native 0
align 8
tpn_auto_restore: db 0
align 8
tpn_provider: times 6 dq 0
tpn_ops: times 4 dq 0
tpn_ui_ops: times 5 dq 0
tpn_consent_ops: times 7 dq 0
tpn_transport_ops: times 4 dq 0
tpn_safe: dq 0,0
    dd TP_HELP,1
    dq 0,0
    dd TP_CATALOG,1
    dq 0,0
    dd TP_STATUS,2
    dq 0,0
    dd TP_NETWORK,0
    dq 0,0
    dd TP_NETWORK,0
tpn_help: db 'HELP',0
tpn_catalog: db 'CATALOG',0
tpn_status: db 'STATUS',0
tpn_netcheck: db 'NETCHECK',0
tpn_tcpstat: db 'TCPSTAT',0
align 8
tpn_name: times 64 db 0
tpn_request: times 56 db 0
tpn_response: times 48 db 0
%endmacro
WDATA_DEFER WDATA_terminal_native
