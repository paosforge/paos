; SSHPRETRACE arm|off|<two lowercase hex digits>. Consumed owner AUTH1 only.
; A bounded RAM diagnostic; no listener, key, auth, timeout or custody changes.
cmd_verb_sshpretrace:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    sub  rsp, 80
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .owner
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .owner
    cmp  qword [r12 + REQ_PRINCIPAL], PRIN_OWNER
    jne  .owner
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_UDP
    jne  .owner
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .owner
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .grammar
    ; Do not read past the first NUL, including short rejected arguments.
    movzx eax, byte [rbx]
    test al, al
    jz   .grammar
    cmp  al, 'a'
    je   .arm_or_index
    cmp  al, 'o'
    je   .off
.index:
    mov  edi, eax
    call ssh_pretrace_nibble
    test eax, eax
    js   .grammar
    shl  eax, 4
    mov  r12d, eax
    movzx edi, byte [rbx + 1]
    call ssh_pretrace_nibble
    test eax, eax
    js   .grammar
    cmp  byte [rbx + 2], 0
    jne  .grammar
    lea  edi, [r12 + rax + 2]
    jmp  .control
.arm_or_index:
    cmp  byte [rbx + 1], 'r'
    jne  .index
    cmp  byte [rbx + 2], 'm'
    jne  .grammar
    cmp  byte [rbx + 3], 0
    jne  .grammar
    mov  edi, 1
    jmp  .control
.off:
    cmp  byte [rbx + 1], 'f'
    jne  .grammar
    cmp  byte [rbx + 2], 'f'
    jne  .grammar
    cmp  byte [rbx + 3], 0
    jne  .grammar
    xor  edi, edi
.control:
    mov  rsi, rsp
    call tcp_ssh_trace_control
    test eax, eax
    jnz  .clock
    lea  rdi, [rel str_sshpretrace_head]
    call ssh_txt_put_str
    mov  rdi, rsp
    mov  esi, 80
    call ssh_profile_put_hex
    lea  rdi, [rel str_sshpretrace_end]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.owner:
    lea  rdi, [rel str_sshpretrace_owner]
    jmp  .error
.grammar:
    lea  rdi, [rel str_sshpretrace_usage]
    jmp  .error
.clock:
    lea  rdi, [rel str_sshpretrace_clock]
.error:
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 80
    call memset
    add  rsp, 80
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_pretrace_nibble:
    mov  eax, edi
    sub  eax, '0'
    cmp  eax, 9
    jbe  .out
    mov  eax, edi
    sub  eax, 'a'
    cmp  eax, 5
    ja   .bad
    add  eax, 10
.out:
    ret
.bad:
    mov  eax, -1
    ret

str_sshpretrace_head: db "SSHPRETRACE v=1 data=",0
str_sshpretrace_end: db " END",0
str_sshpretrace_owner: db "ERR SSHPRETRACE signed-owner-required",0
str_sshpretrace_usage: db "ERR SSHPRETRACE arm|off|00..ff",0
str_sshpretrace_clock: db "ERR SSHPRETRACE monotonic-clock-unavailable",0
