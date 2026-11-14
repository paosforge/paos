;; MODULE svc/command_uac1_capture
;; LAYER 5
;; EXPORTS command_uac1_capture_init, ucap_hex
;; IMPORTS svc/command, svc/uac1_capture
;; CAPS
;; OWNER rc-codex-av
; Explicit finite owner capture; normal registry mutation/session admission.
; Readback is owner-only, immutable after all completions and transport drain.
; No raw pointer arguments, reset/retry, boot capture or partial PCM exposure.
; Fixed48k S16; separate stereo/mono admissions share the retained lifetime.
; CINFO value=actual_bytes<<8|channels; CREAD arg=byte_offset32|count16<<32.
; CREAD count1..128. Actual collector validates frame/range/phase before copy.
; Only an exact successful copy publishes a NUL-terminated hex RSP_HINT.
command_uac1_capture_init:
    sub rsp,8
    lea rdi,[rel ucap_cap_verb]
    lea rsi,[rel uac1_cap_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel ucap_cmono_verb]
    lea rsi,[rel uac1_cmono_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel ucap_cstat_verb]
    lea rsi,[rel uac1_cstat_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel ucap_cinfo_verb]
    lea rsi,[rel uac1_cinfo_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    lea rdi,[rel ucap_cread_verb]
    lea rsi,[rel uac1_cread_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,0
    call command_register_verb
    add rsp,8
    ret
uac1_cap_handler:
    mov edx,0
    jmp ucap_handler
uac1_cmono_handler:
    mov edx,1
    jmp ucap_handler
uac1_cstat_handler:
    mov edx,2
    jmp ucap_handler
uac1_cinfo_handler:
    mov edx,3
    jmp ucap_handler
uac1_cread_handler:
    mov edx,4
    jmp ucap_handler
ucap_handler:
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
    cmp ebx,2
    jb .start
    cmp ebx,4
    je .read
    test r14,r14
    jnz .out
    cmp ebx,2
    jne .info
    call uac1_capture_status
    jmp .ok
.start:
    mov rdi,r14
    test ebx,ebx
    jnz .mono
    call uac1_capture_start
    jmp .started
.mono:
    call uac1_capture_start_mono
.started:
    test rax,rax
    jnz .out
    call uac1_capture_status
    jmp .ok
.info:
    call uac1_capture_channels
    cmp rax,1
    jb .out
    cmp rax,2
    ja .out
    mov ebp,eax
    call uac1_capture_bytes
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
    lea rsi,[rel ucap_packet]
    mov rdx,rbp
    call uac1_capture_read
    cmp rax,rbp
    jne .out
    lea rsi,[rel ucap_packet]
    lea rdi,[rel ucap_hex]
    lea rdx,[rel ucap_digits]
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
    lea rax,[rel ucap_hex]
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
ucap_hex: times 257 db 0
ucap_packet: times 128 db 0
ucap_digits: db '0123456789abcdef'
ucap_cap_verb: db 'UAC1_CAPTURE',0
ucap_cmono_verb: db 'UAC1_CMONO',0
ucap_cstat_verb: db 'UAC1_CSTAT',0
ucap_cinfo_verb: db 'UAC1_CINFO',0
ucap_cread_verb: db 'UAC1_CREAD',0
