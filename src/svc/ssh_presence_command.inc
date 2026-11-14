; SSHPRESENCE <16lowerhex nonce> <enrolled-slot0..3>. Consumed owner AUTH1 only.
; Public bounded live identity, existing audit and actual presentation observation.
; Destructive registry metadata obtains existing AUTH1 MUTATE authority; this
; observer itself never issues a mutation or adds public observation authority.
cmd_verb_sshpresence:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 280
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .owner
    mov  r14, [r12 + REQ_ARG]
    test r14, r14
    jz   .grammar
    xor  ecx, ecx
.parse:
    movzx eax, byte [r14 + rcx]
    cmp  al, '0'
    jb   .grammar
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .grammar
    cmp  al, 'f'
    ja   .grammar
.digit:
    inc  ecx
    cmp  ecx, 16
    jb   .parse
    cmp  byte [r14 + 16], ' '
    jne  .grammar
    movzx ebx, byte [r14 + 17]
    sub  ebx, '0'
    cmp  ebx, 3
    ja   .grammar
    cmp  byte [r14 + 18], 0
    jne  .grammar
    mov  edi, ebx
    mov  rsi, rsp
    call ssh_presence_snapshot
    test eax, eax
    jnz  .unavailable
    ; An existing store-warning callback may have staged other output. Start
    ; this command's formatter only AFTER the public snapshot is complete.
    call ssh_keyverb_out_begin
    lea  rdi, [rel str_sshpresence_head]
    call ssh_txt_put_str
    mov  rdi, r14
    mov  esi, 16
    call ssh_txt_put_bytes
    lea  rdi, [rel str_sshpresence_slot]
    call ssh_txt_put_str
    mov  edi, ebx
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshpresence_data]
    call ssh_txt_put_str
    mov  rdi, rsp
    mov  esi, 280
    call ssh_profile_put_hex
    lea  rdi, [rel str_sshpresence_end]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.owner:
    lea  rdi, [rel str_sshpresence_owner]
    jmp  .error
.grammar:
    lea  rdi, [rel str_sshpresence_usage]
    jmp  .error
.unavailable:
    lea  rdi, [rel str_sshpresence_unavailable]
.error:
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 280
    call memset
    add  rsp, 280
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

str_sshpresence_head: db "SSHPRESENCE v=1 nonce=",0
str_sshpresence_slot: db " slot=",0
str_sshpresence_data: db " data=",0
str_sshpresence_end: db " END",0
str_sshpresence_owner: db "ERR SSHPRESENCE signed-owner-required",0
str_sshpresence_usage: db "ERR SSHPRESENCE nonce16 slot0..3",0
str_sshpresence_unavailable: db "ERR SSHPRESENCE unavailable",0
