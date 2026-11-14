; T5-11: raw in-process observations through existing owner-gated FORMINFO.
; No registration, dispatch, policy change or synthetic PASS field.
; The actual Start consumer reads form_launcher_flags/form_table_ptr too.
console_observation_authorize:
    push rax
    push rcx
    push rdx
    mov eax,[rel console_bound_slot]
    cmp eax,WM_MAX
    jae .out
    lea rcx,[rel wm_gen]
    mov ecx,[rcx+rax*4]
    test ecx,ecx
    jz .out
    lea rdx,[rel console_observation_generations]
    mov [rdx+rax*4],ecx
    bts qword [rel console_observation_authorized],rax
    inc dword [rel console_observation_opens]
.out:
    pop rdx
    pop rcx
    pop rax
    ret

; Return actual visible/minimized Console slots and those without a successful
; explicit recovery request. Binding identity survives a user title change.
console_observation_windows:
    push rbx
    push r12
    xor ebx,ebx
    xor r12d,r12d
    mov dword [rel console_observation_visible],0
    mov dword [rel console_observation_unexpected],0
    mov dword [rel console_observation_authorized_live],0
.loop:
    cmp ebx,WM_MAX
    jae .done
    lea rax,[rel wm_state]
    mov eax,[rax+rbx*4]
    cmp eax,WM_VISIBLE
    je .live
    cmp eax,WM_MIN
    je .live
    btr qword [rel console_observation_authorized],rbx
    jmp .next
.live:
    cmp ebx,[rel console_bound_slot]
    je .console
    lea rax,[rel wm_title]
    mov rdi,[rax+rbx*8]
    test rdi,rdi
    jz .next
    call sess_recovery_console_title
    test eax,eax
    jz .next
.console:
    inc dword [rel console_observation_visible]
    bt qword [rel console_observation_authorized],rbx
    jnc .unexpected
    ; Native owner open/clear bumps wm_gen. Even an unsampled close/reuse
    ; cannot inherit the request attached to the prior window in this slot.
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    test eax,eax
    jz .stale
    lea rdx,[rel console_observation_generations]
    cmp eax,[rdx+rbx*4]
    jne .stale
    inc dword [rel console_observation_authorized_live]
    jmp .next
.stale:
    btr qword [rel console_observation_authorized],rbx
.unexpected:
    inc dword [rel console_observation_unexpected]
.next:
    inc ebx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

console_observe_init:
    call console_observation_windows
    inc dword [rel console_observation_inits]
    mov eax,[rel console_observation_visible]
    add [rel console_observation_init_windows],eax
    ret

console_observe_unlock:
    cmp byte [rel console_service_ready],1
    jne .out
    call console_observation_windows
    inc dword [rel console_observation_unlocks]
    mov eax,[rel console_observation_unexpected]
    add [rel console_observation_unlock_windows],eax
.out:
    ret

; Return an order-sensitive 32-bit fold of EVERY live native registry row's
; name, handler pointer and security/type/selector metadata, not a catalog copy.
console_observation_registry:
    push rbx
    push r12
    push r13
    call command_verb_count
    mov r12d,eax
    xor ebx,ebx
    mov r13d,2166136261
.row:
    cmp ebx,r12d
    jae .done
    mov edi,ebx
    imul edi,VERB_ENT_SZ
    lea rdx,[rel verb_table]
    add rdx,rdi
    mov rdi,[rdx+VERB_NAME]
    test rdi,rdi
    jnz .name
    lea rdi,[rel console_observation_empty]
.name:
    movzx eax,byte [rdi]
    inc rdi
    xor r13d,eax
    imul r13d,r13d,16777619
    test eax,eax
    jnz .name
    mov ecx,VERB_ENT_SZ-8
    add rdx,8
.meta:
    movzx eax,byte [rdx]
    inc rdx
    xor r13d,eax
    imul r13d,r13d,16777619
    dec ecx
    jnz .meta
    inc ebx
    jmp .row
.done:
    mov eax,r13d
    pop r13
    pop r12
    pop rbx
    ret

; The FORMINFO handler remains a normal registry handler with original metadata.
console_observation_reply:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov r12,rsi
    call console_observation_windows
    call form_out_reset
    lea rdi,[rel console_observation_head]
    call form_out_put_str
%macro CS_OBS 2
    lea rdi,[rel %1]
    call form_out_put_str
    mov edi,[rel %2]
    call form_out_put_dec
%endmacro
    lea rdi,[rel console_observation_ready_key]
    call form_out_put_str
    movzx edi,byte [rel console_service_ready]
    call form_out_put_dec
    CS_OBS console_observation_init_key,console_observation_inits
    CS_OBS console_observation_init_windows_key,console_observation_init_windows
    CS_OBS console_observation_unlocks_key,console_observation_unlocks
    CS_OBS console_observation_unlock_windows_key,console_observation_unlock_windows
    CS_OBS console_observation_visible_key,console_observation_visible
    CS_OBS console_observation_authorized_key,console_observation_authorized_live
    CS_OBS console_observation_opens_key,console_observation_opens
    CS_OBS console_observation_slot_key,console_bound_slot
    CS_OBS console_observation_session_key,console_bound_session_noun
    xor ebx,ebx
    xor r13d,r13d
.forms:
    cmp ebx,FORM_COUNT
    jae .forms_done
    lea rax,[rel form_launcher_flags]
    test byte [rax+rbx],FORM_LAUNCHABLE
    jz .next_form
    mov edi,ebx
    call form_table_ptr
    cmp qword [rax+FORM_LEN],0
    je .next_form
    mov rdi,[rax+FORM_NAME]
    test rdi,rdi
    jz .next_form
    lea rsi,[rel form_name_console_runtime]
    call strcmp
    test eax,eax
    jz .exposed
    mov edi,ebx
    call form_table_ptr
    mov rax,[rax+FORM_BLOB_PTR]
    lea rdx,[rel form_blob_console_runtime]
    cmp rax,rdx
    jne .next_form
.exposed:
    inc r13d
.next_form:
    inc ebx
    jmp .forms
.forms_done:
    lea rdi,[rel console_observation_public_key]
    call form_out_put_str
    mov edi,r13d
    call form_out_put_dec
    lea rdi,[rel console_observation_terminal_key]
    call form_out_put_str
    mov edi,FORM_TERMINAL_INDEX
    call form_table_ptr
    xor edi,edi
    cmp qword [rax+FORM_LEN],0
    je .terminal_flags
    cmp qword [rax+FORM_NAME],0
    je .terminal_flags
    movzx edi,byte [rel form_launcher_flags+FORM_TERMINAL_INDEX]
.terminal_flags:
    call form_out_put_dec
    lea rdi,[rel console_observation_registry_n_key]
    call form_out_put_str
    call command_verb_count
    mov edi,eax
    call form_out_put_dec
    call console_observation_registry
    mov ebx,eax
    lea rdi,[rel console_observation_registry_hash_key]
    call form_out_put_str
    mov edi,ebx
    call form_out_put_dec
    lea rdi,[rel console_observation_launch_key]
    call form_out_put_str
    lea rdi,[rel str_console_launch]
    call command_lookup
    mov edi,eax
    call command_verb_destr
    mov edi,eax
    call form_out_put_dec
    lea rdi,[rel console_observation_formload_key]
    call form_out_put_str
    lea rdi,[rel str_console_formload]
    call command_lookup
    mov edi,eax
    call command_verb_destr
    mov edi,eax
    call form_out_put_dec
    mov byte [rel form_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    mov qword [r12+RSP_VAL],0
    pop r13
    pop r12
    pop rbx
    ret
%unmacro CS_OBS 2

%macro WDATA_console_observation 0
alignb 8
console_observation_authorized: resq 1
console_observation_generations: resd WM_MAX
console_observation_inits: resd 1
console_observation_init_windows: resd 1
console_observation_unlocks: resd 1
console_observation_unlock_windows: resd 1
console_observation_visible: resd 1
console_observation_unexpected: resd 1
console_observation_authorized_live: resd 1
console_observation_opens: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_console_observation
console_observation_arg: db 'console @state',0
console_observation_head: db 'CSOBS v=1',0
console_observation_ready_key: db ' ready=',0
console_observation_init_key: db ' init=',0
console_observation_init_windows_key: db ' init_console=',0
console_observation_unlocks_key: db ' unlocks=',0
console_observation_unlock_windows_key: db ' unlock_console=',0
console_observation_visible_key: db ' visible=',0
console_observation_authorized_key: db ' authorized=',0
console_observation_opens_key: db ' opens=',0
console_observation_slot_key: db ' slot=',0
console_observation_session_key: db ' session=',0
console_observation_public_key: db ' public_console=',0
console_observation_terminal_key: db ' terminal_flags=',0
console_observation_registry_n_key: db ' registry_n=',0
console_observation_registry_hash_key: db ' registry_hash=',0
console_observation_launch_key: db ' launch_destr=',0
console_observation_formload_key: db ' formload_destr=',0

console_observation_empty: db 0
