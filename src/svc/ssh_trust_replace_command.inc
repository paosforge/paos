; Separate deliberate action, never a retry of a changed-key connection.
; SSHKHREPLACE <IPv4>:<port> <old64lowerhex> <new64lowerhex>.
cmd_verb_sshkhreplace:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    sub  rsp, 80                       ; two public endpoint/digest records
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .owner
    mov  rdi, [r12 + REQ_ARG]
    mov  rsi, rsp
    call ssh_khreplace_parse
    test eax, eax
    jnz  .grammar
    mov  edi, [rsp]
    mov  esi, [rsp + 4]
    lea  rdx, [rsp + 8]
    lea  rcx, [rsp + 48]
    call ssh_cli_replace_host
    test eax, eax
    jnz  .refused
    lea  rdi, [rel str_sshkhreplace_ok]
    call ssh_txt_put_str
    mov  rdi, [r12 + REQ_ARG]           ; grammar bounded to151 public bytes
    call ssh_txt_put_str
    lea  rdi, [rel str_sshkhreplace_committed]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.owner:
    lea  rdi, [rel str_sshkhreplace_owner]
    jmp  .err
.grammar:
    lea  rdi, [rel str_sshkhreplace_usage]
    jmp  .err
.refused:
    lea  rdi, [rel str_sshkhreplace_unavailable]
    cmp  eax, -2
    je   .uncertain
    cmp  eax, -3
    jne  .err
    lea  rdi, [rel str_sshkhreplace_conflict]
    jmp  .err
.uncertain:
    lea  rdi, [rel str_sshkhreplace_uncertain]
.err:
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

; RDI=NUL argument, RSI=80B output. Existing strict trust grammar is applied
; to each digest with the same endpoint. Finite stack copy; no partial parse
; reaches the store and no additional global writable state is introduced.
ssh_khreplace_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 160
    mov  r13, rsi
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.copy:
    cmp  ecx, 152
    jae  .bad
    mov  al, [rdi + rcx]
    mov  [rsp + rcx], al
    inc  ecx
    test al, al
    jnz  .copy
    mov  r15d, ecx
    xor  ebx, ebx
.endpoint:
    cmp  ebx, 22
    jae  .bad
    cmp  ebx, r15d
    jae  .bad
    cmp  byte [rsp + rbx], ' '
    je   .split
    inc  ebx
    jmp  .endpoint
.split:
    ; Endpoint then exactly64 old hex, one space,64 new hex,NUL.
    inc  ebx                           ; first digest offset
    lea  r14d, [rbx + 64]
    cmp  byte [rsp + r14], ' '
    jne  .bad
    lea  eax, [r14 + 66]
    cmp  eax, r15d
    jne  .bad
    mov  byte [rsp + r14], 0
    mov  rdi, rsp
    mov  rsi, r13
    call ssh_khtrust_parse
    test eax, eax
    jnz  .bad
    lea  rdi, [rsp + rbx]
    lea  rsi, [rsp + r14 + 1]
    mov  edx, 64
    call memcpy
    mov  rdi, rsp
    lea  rsi, [r13 + 40]
    call ssh_khtrust_parse
    test eax, eax
    jnz  .bad
    xor  ebx, ebx
    jmp  .out
.bad:
    mov  ebx, -1
.out:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 160
    call memset
    mov  eax, ebx
    add  rsp, 160
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

str_sshkhreplace_ok: db "SSHKHREPLACE ok endpoint_old_new=",0
str_sshkhreplace_committed: db " durable=exact_authenticated_store peer_authentication=not_attempted (other pins retained; reconnect verifies the independently selected new fingerprint)",0
str_sshkhreplace_owner: db "ERR SSHKHREPLACE owner_signed_auth1_required",0
str_sshkhreplace_usage: db "ERR SSHKHREPLACE usage=<IPv4>:<port> <old64lowerhexSHA256> <new64lowerhexSHA256>",0
str_sshkhreplace_unavailable: db "ERR SSHKHREPLACE trust_unavailable (no pin changed; repair damaged or uncertain storage)",0
str_sshkhreplace_conflict: db "ERR SSHKHREPLACE old_pin_mismatch_or_identical_new (no pin changed; independently verify endpoint and both fingerprints)",0

str_sshkhreplace_uncertain: db "ERR SSHKHREPLACE commit_uncertain (trust revoked; inspect durable outcome before explicit owner repair; no retry)",0
