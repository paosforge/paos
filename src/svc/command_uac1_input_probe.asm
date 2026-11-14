;; MODULE svc/command_uac1_input_probe
;; LAYER 5
;; EXPORTS command_uac1_input_probe_init, uipcmd_hex
;; IMPORTS svc/command, svc/uac1_input_probe, snd/uac1_input_sound
;; CAPS
;; OWNER rc-codex-av
; Explicit finite owner capture; normal registry mutation/session admission.
; Readback is owner-only, immutable after all completions and transport drain.
; No raw pointer arguments, reset/retry, boot capture or partial PCM exposure.
; 48k default / explicit UAC2 bit24=44.1k S16; separate stereo/mono admissions share the retained lifetime.
; IINFO value=actual_bytes<<8|channels; IREAD arg=byte_offset32|count16<<32.
; ISTAT arg0 normal snapshot,1 first fault,2 raw value,3 ISO event,4 identity.
; IREAD count1..128. Actual collector validates frame/range/phase before copy.
; Only an exact successful copy publishes a NUL-terminated hex RSP_HINT.
command_uac1_input_probe_init:
    sub rsp,8
    lea rdi,[rel uipcmd_cap_verb]
    lea rsi,[rel uipcmd_input_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel uipcmd_cmono_verb]
    lea rsi,[rel uipcmd_mono_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel uipcmd_cstat_verb]
    lea rsi,[rel uipcmd_stat_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel uipcmd_cinfo_verb]
    lea rsi,[rel uipcmd_info_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel uipcmd_cread_verb]
    lea rsi,[rel uipcmd_read_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel uipcmd_cap2_verb]
    lea rsi,[rel uipcmd_input2_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel uipcmd_cmono2_verb]
    lea rsi,[rel uipcmd_mono2_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel uipcmd_cstat2_verb]
    lea rsi,[rel uipcmd_stat_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel uipcmd_cinfo2_verb]
    lea rsi,[rel uipcmd_info_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel uipcmd_cread2_verb]
    lea rsi,[rel uipcmd_read_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    add rsp,8
    ret
uipcmd_input2_handler:
    mov edx,5
    jmp uipcmd_handler
uipcmd_mono2_handler:
    mov edx,6
    jmp uipcmd_handler
uipcmd_input_handler:
    mov edx,0
    jmp uipcmd_handler
uipcmd_mono_handler:
    mov edx,1
    jmp uipcmd_handler
uipcmd_stat_handler:
    mov edx,2
    jmp uipcmd_handler
uipcmd_info_handler:
    mov edx,3
    jmp uipcmd_handler
uipcmd_read_handler:
    mov edx,4
    jmp uipcmd_handler
uipcmd_handler:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov ebx,edx
    mov r12,rdi
    mov r13,rsi
    call cmd_handler_prologue
    mov qword [r13+RSP_CODE],CMDE_BADARG
    mov qword [r13+RSP_ACCEPTED],0
    mov qword [r13+RSP_VAL],0
    mov qword [r13+RSP_HINT],0
    cmp qword [r12+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
    jne .out
    mov r14,[r12+REQ_ARG]
    cmp ebx,5
    jae .start2
    cmp ebx,2
    jb .start
    cmp ebx,4
    je .read
    cmp ebx,2
    jne .info_arg
    cmp r14,4
    ja .out
    test r14,r14
    jz .stat
    lea rdi,[r14-1]
    call uaci_diagnostic
    jmp .ok
.stat:
    call uip_status
    jmp .ok
.info_arg:
    test r14,r14
    jnz .out
    jmp .info
.start2:
    mov rdi,r14
    cmp ebx,5
    jne .mono2
    call uip2_start
    jmp .started
.mono2:
    call uip2_start_mono
    jmp .started
.start:
    mov rdi,r14
    test ebx,ebx
    jnz .mono
    call uip_start
    jmp .started
.mono:
    call uip_start_mono
.started:
    test rax,rax
    jnz .out
    call uip_status
    jmp .ok
.info:
    call uip_channels
    cmp rax,1
    jb .out
    cmp rax,2
    ja .out
    mov ebp,eax
    call uip_bytes
    cmp rax,49152
    ja .out
    shl rax,8
    or rax,rbp
    jmp .ok
.read:
    mov rax,r14
    shr rax,48
    jnz .out
    mov rbp,r14
    shr rbp,32
    test ebp,ebp
    jz .out
    cmp ebp,128
    ja .out
    mov edi,r14d
    lea rsi,[rel uipcmd_packet]
    mov rdx,rbp
    call uip_read
    cmp rax,rbp
    jne .out
    lea rsi,[rel uipcmd_packet]
    lea rdi,[rel uipcmd_hex]
    lea rdx,[rel uipcmd_digits]
    mov rcx,rbp
.hex:
    movzx eax,byte [rsi]
    mov ebx,eax
    shr ebx,4
    mov bl,[rdx+rbx]
    mov [rdi],bl
    and eax,15
    mov al,[rdx+rax]
    mov [rdi+1],al
    inc rsi
    add rdi,2
    loop .hex
    mov byte [rdi],0
    lea rax,[rel uipcmd_hex]
    mov [r13+RSP_HINT],rax
    mov rax,rbp
.ok:
    mov [r13+RSP_VAL],rax
    mov qword [r13+RSP_CODE],CMDE_OK
    mov qword [r13+RSP_ACCEPTED],1
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

align 8
uipcmd_hex: times 257 db 0
uipcmd_packet: times 128 db 0
uipcmd_digits: db '0123456789abcdef'
uipcmd_cap_verb: db 'UAC1_INPUT',0
uipcmd_cmono_verb: db 'UAC1_IMONO',0
uipcmd_cstat_verb: db 'UAC1_ISTAT',0
uipcmd_cinfo_verb: db 'UAC1_IINFO',0
uipcmd_cread_verb: db 'UAC1_IREAD',0

uipcmd_cap2_verb: db "UAC2_INPUT",0
uipcmd_cmono2_verb: db "UAC2_IMONO",0
uipcmd_cstat2_verb: db "UAC2_ISTAT",0
uipcmd_cinfo2_verb: db "UAC2_IINFO",0
uipcmd_cread2_verb: db "UAC2_IREAD",0
