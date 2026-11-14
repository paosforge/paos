; Explicit, owner-gated AXSTAT <16 lowercase hex nonce>. Uses the existing
; staged diagnostic reply rail. No STATUS or boot probe and no new auth path.
axstat_register:
    lea rdi,[rel str_verb_axstat]
    lea rsi,[rel cmd_verb_axstat]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    ret

cmd_verb_axstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12,[rdi+REQ_ARG]
    test r12,r12
    jz .bad
    xor ecx,ecx
.nonce:
    movzx eax,byte [r12+rcx]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .next
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
.next:
    inc ecx
    cmp ecx,16
    jb .nonce
    cmp byte [r12+16],0
    jne .bad
    lea rdi,[rel axstat_snapshot]
    call ax88179_observation_snapshot
    call tcpdiag_out_reset
    lea rdi,[rel str_axstat_prefix]
    call tcpdiag_out_text
    mov rdi,r12
    call tcpdiag_out_text
    lea r13,[rel axstat_fields]
.fields:
    mov eax,[r13]
    cmp eax,-1
    je .done
    lea rdi,[r13+4]
    call tcpdiag_out_text
    mov eax,[r13]
    lea rdx,[rel axstat_snapshot]
    mov edi,[rdx+rax]
    cmp eax,16
    je .qword
    cmp eax,24
    jne .value
.qword:
    mov rdi,[rdx+rax]
.value:
    call tcpdiag_out_u64
    add r13,20
    jmp .fields
.done:
    mov byte [rel tcpdiag_out_ready],1
    mov qword [rbx+RSP_ACCEPTED],1
    mov qword [rbx+RSP_CODE],CMDE_OK
    jmp .out
.bad:
    mov qword [rbx+RSP_CODE],CMDE_BADARG
.out:
    pop r13
    pop r12
    pop rbx
    ret

align 8
axstat_snapshot: times 88 db 0
str_verb_axstat: db 'AXSTAT',0
str_axstat_prefix: db ' AXSTAT rev=1 nonce=',0
; Fixed labels <=15 bytes plus NUL, each record exactly20 bytes. Worst case
; all integers at their maximum is <560 bytes including prefix+nonce (640B rail).
%macro AXSTAT_FIELD 2
    dd %1
%%label: db %2,0
    times 16-($-%%label) db 0
%endmacro
axstat_fields:
    AXSTAT_FIELD 0,  ' present='
    AXSTAT_FIELD 4,  ' slot='
    AXSTAT_FIELD 8,  ' nic_health='
    AXSTAT_FIELD 12, ' frames='
    AXSTAT_FIELD 16, ' rx='
    AXSTAT_FIELD 24, ' tx='
    AXSTAT_FIELD 32, ' hc_observed='
    AXSTAT_FIELD 36, ' hc='
    AXSTAT_FIELD 40, ' bdf='
    AXSTAT_FIELD 44, ' root_port='
    AXSTAT_FIELD 48, ' generation='
    AXSTAT_FIELD 52, ' usbcmd='
    AXSTAT_FIELD 56, ' usbsts='
    AXSTAT_FIELD 60, ' portsc='
    AXSTAT_FIELD 64, ' hc_health='
    AXSTAT_FIELD 68, ' root_ports='
    AXSTAT_FIELD 72, ' vidpid='
    AXSTAT_FIELD 76, ' bcd='
    AXSTAT_FIELD 80, ' port='
    dd -1
%unmacro AXSTAT_FIELD 2
