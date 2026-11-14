;; MODULE hv/driver_domain_command
;; LAYER 5
;; EXPORTS nd_register_verbs, nd_token, nd_number, nd_info_number
;; IMPORTS hv/driver_domain, hv/driver_domain_boot, hv/vm_profile, hv/vmx, svc/command_auth, fs/storage_access, core/lib/fmt
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Existing command/auth transport only. Inputs are bounded tokens; native
; identity, snapshot and STOP are bound to exact START+nonce. No target sender.
nd_register_verbs:
    push rbx
    lea rdi,[rel nd_verb_start]
    lea rsi,[rel nd_command_start]
    mov rdx,CMD_AUTH_CAP_MUTATE
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel nd_verb_stop]
    lea rsi,[rel nd_command_stop]
    mov rdx,CMD_AUTH_CAP_MUTATE
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel nd_verb_stat]
    lea rsi,[rel nd_command_stat]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    lea rdi,[rel nd_verb_info]
    lea rsi,[rel nd_command_info]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    pop rbx
    ret
nd_command_start:
    xor edx,edx
    jmp nd_command
nd_command_stop:
    mov edx,1
    jmp nd_command
nd_command_stat:
    mov edx,2
    jmp nd_command
nd_command_info:
    mov edx,3
nd_command:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r13d,edx
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    call hv_out_reset
    mov r14d,1
    cmp r13d,2
    jae .parse
    call storage_access_request_owner
    cmp eax,1
    jne .auth
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .auth
.parse:
    cmp r13d,3
    je .info
    mov rdi,rbx
    lea rsi,[rel nd_arg0]
    mov edx,24
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel nd_arg1]
    mov edx,17
    call nd_token
    test rax,rax
    jz .syntax
    mov rbx,rax
    test r13d,r13d
    jnz .two_tokens
    mov rdi,rbx
    lea rsi,[rel nd_arg2]
    mov edx,17
    call nd_token
    test rax,rax
    jz .syntax
    cmp byte [rax],0
    jne .syntax
    lea rdi,[rel nd_arg1]
    mov esi,16
    mov edx,4
    call nd_number
    jc .syntax
    mov r14d,eax
    lea rdi,[rel nd_arg0]
    call vm_profile_find
    test rax,rax
    jz .start_bad
    mov rdi,rax
    mov esi,r14d
    lea rdx,[rel nd_arg2]
    call nd_begin
    test eax,eax
    jz .start_bad
    mov r14d,eax
    mov dword [rel nd_cache_valid],0
    lea rdi,[rel nd_start_ok]
    call hv_out_str
    jmp .identity_reply
.two_tokens:
    cmp byte [rbx],0
    jne .syntax
    lea rdi,[rel nd_arg1]
    call nd_nonce_valid
    test eax,eax
    jz .syntax
    lea rdi,[rel nd_arg0]
    mov esi,10
    mov edx,10
    call nd_number
    jc .syntax
    mov r14d,eax
    cmp r13d,2
    je .stat
    mov edi,r14d
    lea rsi,[rel nd_arg1]
    call nd_stop
    test eax,eax
    jnz .stop_bad
    lea rdi,[rel nd_stop_ok]
    call hv_out_str
.identity_reply:
    mov eax,r14d
    call hv_out_dec
    lea rdi,[rel nd_space]
    call hv_out_str
    lea rdi,[rel nd_arg1]
    test r13d,r13d
    jnz .nonce_reply
    lea rdi,[rel nd_arg2]
.nonce_reply:
    call hv_out_str
    jmp .ready
.info:
    ; Read-only discovery for native EVERYBOOT admission. The authenticated
    ; caller supplies a fresh probe; observing this tuple grants no authority.
    mov rdi,rbx
    lea rsi,[rel nd_arg0]
    mov edx,17
    call nd_token
    test rax,rax
    jz .syntax
    cmp byte [rax],0
    jne .syntax
    lea rdi,[rel nd_arg0]
    call nd_nonce_valid
    test eax,eax
    jz .syntax
    lea rdi,[rel nd_info_ok]
    call hv_out_str
    lea rdi,[rel nd_arg0]
    call hv_out_str
    mov edi,[rel nd_state]
    call nd_info_number
    mov rdi,[rel nd_generation]
    call nd_info_number
    lea rdi,[rel nd_space]
    call hv_out_str
    lea rdi,[rel nd_zero_nonce]
    cmp qword [rel nd_generation],0
    je .info_nonce
    lea rdi,[rel nd_nonce]
.info_nonce:
    call hv_out_str
    mov edi,[rel nd_bdf]
    cmp qword [rel nd_generation],0
    jne .info_bdf
    mov edi,[rel nd_boot_bdf]
.info_bdf:
    call nd_info_number
    call boot_ms_now
    mov rdi,rax
    call nd_info_number
    mov edi,[rel nd_boot_error]
    call nd_info_number
    mov edi,[rel nd_boot_select_error]
    call nd_info_number
    jmp .ready
.stat:
    cmp r14d,8
    jae .syntax
    test r14d,r14d
    jnz .cached
    lea rdi,[rel nd_arg1]
    lea rsi,[rel nd_cache]
    mov edx,2048
    call nd_snapshot
    cmp eax,2048
    jne .stat_bad
    mov dword [rel nd_cache_valid],1
.cached:
    cmp dword [rel nd_cache_valid],1
    jne .stat_bad
    lea rdi,[rel nd_cache+32]
    lea rsi,[rel nd_arg1]
    mov ecx,16
    cld
    repe cmpsb
    jne .stat_bad
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_cache+24]
    jne .stat_bad
    lea rdi,[rel nd_stat_ok]
    call hv_out_str
    mov eax,[rel nd_cache+8]
    call hv_out_dec
    lea rdi,[rel nd_space]
    call hv_out_str
    mov eax,r14d
    call hv_out_dec
    lea rdi,[rel nd_space]
    call hv_out_str
    shl r14,8
    lea rbx,[rel nd_cache]
    add rbx,r14
    lea r13,[rbx+256]
.hex:
    lea rdx,[rel nd_hex]
    movzx eax,byte [rbx]
    shr eax,4
    mov al,[rdx+rax]
    call hv_out_putc
    lea rdx,[rel nd_hex]
    movzx eax,byte [rbx]
    and eax,15
    mov al,[rdx+rax]
    call hv_out_putc
    inc rbx
    cmp rbx,r13
    jb .hex
    jmp .ready
.syntax:
    mov r14d,1
    jmp .error
.auth:
    mov r14d,2
    jmp .error
.start_bad:
    mov r14d,3
    jmp .error
.stat_bad:
    mov r14d,4
    jmp .error
.stop_bad:
    mov r14d,5
.error:
    lea rdi,[rel nd_error]
    call hv_out_str
    mov eax,r14d
    call hv_out_dec
.ready:
    mov byte [rel hv_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Full-width diagnostic value; no uptime truncation through hv_out_dec's u32.
nd_info_number:
    push rbx
    mov rbx,rdi
    lea rdi,[rel nd_space]
    call hv_out_str
    mov rdi,rbx
    lea rsi,[rel nd_info_dec]
    call fmt_dec
    lea rdi,[rel nd_info_dec]
    call hv_out_str
    pop rbx
    ret

; RDI=cursor,RSI=buffer,EDX=capacityinclNUL ->next nonspace/0.
nd_token:
    test rdi,rdi
    jz .bad
    cmp edx,2
    jb .bad
    xor ecx,ecx
.skip:
    cmp byte [rdi],' '
    jne .copy
    inc rdi
    jmp .skip
.copy:
    mov al,[rdi]
    test al,al
    jz .end
    cmp al,' '
    je .end
    cmp al,33
    jb .bad
    cmp al,126
    ja .bad
    inc ecx
    cmp ecx,edx
    jae .bad
    mov [rsi],al
    inc rsi
    inc rdi
    jmp .copy
.end:
    mov byte [rsi],0
    test ecx,ecx
    jz .bad
.after:
    cmp byte [rdi],' '
    jne .done
    inc rdi
    jmp .after
.done:
    mov rax,rdi
    ret
.bad:
    xor eax,eax
    ret

; RDI=lowercase numeric token,ESI=10or16,EDX=maxdigits ->EAXu32,CFrefusal.
nd_number:
    xor eax,eax
    xor ecx,ecx
.loop:
    movzx r8d,byte [rdi]
    test r8d,r8d
    jz .end
    inc ecx
    cmp ecx,edx
    ja .bad
    sub r8d,'0'
    cmp r8d,9
    jbe .digit
    sub r8d,39
    cmp r8d,10
    jb .bad
.digit:
    cmp r8d,esi
    jae .bad
    imul rax,rsi
    add rax,r8
    mov r9d,0xffffffff
    cmp rax,r9
    ja .bad
    inc rdi
    jmp .loop
.end:
    test ecx,ecx
    jz .bad
    clc
    ret
.bad:
    stc
    ret
nd_verb_start: db 'NDSTART',0
nd_verb_stop: db 'NDSTOP',0
nd_verb_stat: db 'NDSTAT',0
nd_verb_info: db 'NDINFO',0
nd_start_ok: db 'NDSTART1 ',0
nd_stop_ok: db 'NDSTOP1 ',0
nd_stat_ok: db 'NDSTAT1 ',0
nd_info_ok: db 'NDINFO1 ',0
nd_zero_nonce: db '0000000000000000',0
nd_error: db 'NDERR ',0
nd_space: db ' ',0
%include "core/abi/wdata.inc"
%macro WDATA_hv_driver_domain_command 0
align 16
nd_arg0: times 24 db 0
nd_arg1: times 17 db 0
nd_arg2: times 17 db 0
nd_info_dec: times 24 db 0
nd_cache_valid: dd 0
align 16
nd_cache: times 2048 db 0
%endmacro
WDATA_DEFER WDATA_hv_driver_domain_command
