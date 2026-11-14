; SSHCLIPROFILE <16lowerhex nonce> <page0..7>. Consumed owner AUTH1 only.
; Native page contains public state, public keys and exact4pin entries only.
; Destructive registry metadata obtains existing AUTH1 MUTATE authority; this
; observer itself never issues a mutation or adds public observation authority.
cmd_verb_sshcliprofile:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 248
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .owner
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
    cmp  byte [rel ssh_profile_fault_active], 0
    jne  .fault_active
%endif
%endif
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
    cmp  ebx, 7
    ja   .grammar
    cmp  byte [r14 + 18], 0
    jne  .grammar
    mov  edi, ebx
    mov  rsi, rsp
    call ssh_cli_profile_snapshot
    test eax, eax
    jnz  .unavailable
    ; An existing store-warning callback may have staged other output. Start
    ; this command's formatter only AFTER the public snapshot is complete.
    call ssh_keyverb_out_begin
    lea  rdi, [rel str_sshprofile_head]
    call ssh_txt_put_str
    mov  rdi, r14
    mov  esi, 16
    call ssh_txt_put_bytes
    lea  rdi, [rel str_sshprofile_page]
    call ssh_txt_put_str
    mov  edi, ebx
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshprofile_data]
    call ssh_txt_put_str
    mov  rdi, rsp
    mov  esi, 240
    call ssh_profile_put_hex
    lea  rdi, [rel str_sshprofile_end]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.owner:
    lea  rdi, [rel str_sshprofile_owner]
    jmp  .error
.grammar:
    lea  rdi, [rel str_sshprofile_usage]
    jmp  .error
.unavailable:
    lea  rdi, [rel str_sshprofile_unavailable]
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
    jmp  .error
.fault_active:
    lea  rdi, [rel str_sshprofile_fault_active]
%endif
%endif
.error:
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 240
    call memset
    add  rsp, 248
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Public source bytes -> bounded formatter, exactly2lowerhex per byte.
ssh_profile_put_hex:
    push rbx
    push r12
    push r13
    sub  rsp, 16
    mov  r12, rdi
    mov  r13d, esi
    xor  ebx, ebx
.loop:
    cmp  ebx, r13d
    jae  .done
    movzx eax, byte [r12 + rbx]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    lea  rcx, [rel str_sshprofile_hex]
    mov  al, [rcx + rax]
    mov  dl, [rcx + rdx]
    mov  [rsp], al
    mov  [rsp + 1], dl
    mov  rdi, rsp
    mov  esi, 2
    call ssh_txt_put_bytes
    inc  ebx
    jmp  .loop
.done:
    add  rsp, 16
    pop  r13
    pop  r12
    pop  rbx
    ret

str_sshprofile_head: db " SSHCLIPROFILE v=1 nonce=",0
str_sshprofile_page: db " page=",0
str_sshprofile_data: db " data=",0
str_sshprofile_end: db " end=1",0
str_sshprofile_hex: db "0123456789abcdef"
str_sshprofile_owner: db " SSHCLIPROFILE REFUSED owner_auth1_required",0
str_sshprofile_usage: db " SSHCLIPROFILE REFUSED usage: SSHCLIPROFILE <16lowerhex> <page0..7>",0
str_sshprofile_unavailable: db " SSHCLIPROFILE REFUSED owner_state_unavailable",0
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
str_sshprofile_fault_active: db " SSHCLIPROFILE REFUSED injected_fault_active no_persistence_credit",0
%endif
%endif
