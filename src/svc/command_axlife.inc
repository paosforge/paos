; Explicit, owner-gated AXLIFE <16 lowercase hex nonce> <backend0|1>. Uses the existing
; staged diagnostic reply rail. No STATUS or boot probe and no new auth path.
axlife_register:
    lea rdi,[rel str_verb_axlife]
    lea rsi,[rel cmd_verb_axlife]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    ret

cmd_verb_axlife:
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
    cmp byte [r12+16],32
    jne .bad
    movzx edi,byte [r12+17]
    sub edi,48
    cmp edi,1
    ja .bad
    cmp byte [r12+18],0
    jne .bad
    lea rsi,[rel axlife_snapshot]
    call ax_lifetime_snapshot
    call tcpdiag_out_reset
    lea rdi,[rel str_axlife_prefix]
    call tcpdiag_out_text
    mov rdi,r12
    call axlife_out_nonce
    lea r13,[rel axlife_fields]
.fields:
    mov eax,[r13]
    cmp eax,-1
    je .done
    lea rdi,[r13+4]
    call tcpdiag_out_text
    mov eax,[r13]
    lea rdx,[rel axlife_snapshot]
    mov edi,[rdx+rax]
    cmp eax,24
    jb .value
    cmp eax,72
    ja .value
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

; Copy the already validated exact16B nonce without echoing selector text.
axlife_out_nonce:
    mov rsi,[rel tcpdiag_out_cur]
    mov ecx,16
.copy:
    mov al,[rdi]
    mov [rsi],al
    inc rdi
    inc rsi
    loop .copy
    mov byte [rsi],0
    mov [rel tcpdiag_out_cur],rsi
    ret

align 8
axlife_snapshot: times 136 db 0
str_verb_axlife: db 'AXLIFE',0
str_axlife_prefix: db ' AXLIFE rev=1 nonce=',0
; Fixed labels <=15 bytes plus NUL, each record exactly20 bytes. Worst case
; all integers at their maximum is <640 bytes including prefix+nonce (640B rail).
%macro AXLIFE_FIELD 2
    dd %1
%%label: db %2,0
    times 16-($-%%label) db 0
%endmacro
axlife_fields:
    AXLIFE_FIELD 0, ' status='
    AXLIFE_FIELD 4, ' backend='
    AXLIFE_FIELD 8, ' health='
    AXLIFE_FIELD 12, ' phase='
    AXLIFE_FIELD 16, ' root='
    AXLIFE_FIELD 20, ' gen='
    AXLIFE_FIELD 24, ' inc='
    AXLIFE_FIELD 32, ' retired='
    AXLIFE_FIELD 40, ' rebound='
    AXLIFE_FIELD 48, ' refused='
    AXLIFE_FIELD 56, ' rx='
    AXLIFE_FIELD 64, ' tx='
    AXLIFE_FIELD 72, ' mac='
    AXLIFE_FIELD 80, ' vidpid='
    AXLIFE_FIELD 84, ' bcd='
    AXLIFE_FIELD 88, ' hc_observed='
    AXLIFE_FIELD 92, ' hc='
    AXLIFE_FIELD 96, ' bdf='
    AXLIFE_FIELD 100, ' hc_root='
    AXLIFE_FIELD 104, ' hc_gen='
    AXLIFE_FIELD 128, ' speed='
    dd -1
%unmacro AXLIFE_FIELD 2
