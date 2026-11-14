; Deliberate owner action only: EDI IPv4 memory order, ESI port, RDX old32,
; RCX independently selected new32. Caller owns consumed OWNER AUTH1 MUTATE.
; EAX0 exact durable commit, -1 proved no-write/unavailable, -2 uncertain,
; -3 old mismatch/absent/identical. No credential, signature or connection.
; Stages only, then reuses the existing single SetVariable/exact readback;
; no RAM pin is replaced before exact durable confirmation.
ssh_cli_replace_host:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12d, edi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    test edi, edi
    jz   .refused
    test esi, esi
    jz   .refused
    cmp  esi, 65535
    ja   .refused
    test rdx, rdx
    jz   .refused
    test rcx, rcx
    jz   .refused
    call principal_current
    test rax, rax
    jz   .owner
    cmp  rax, PRIN_OWNER
    jne  .refused
.owner:
    call ssh_cli_kh_load
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    jne  .refused
    cmp  qword [rel ssh_cli_kh_epoch], -1
    je   .refused                       ; never wrap into an earlier admission
    lea  rbx, [rel ssh_cli_pins]
    xor  ecx, ecx
.scan:
    cmp  ecx, SSH_CLI_PINS
    jae  .conflict
    cmp  byte [rbx + 6], 1
    jne  .next
    cmp  [rbx], r12d
    jne  .next
    cmp  [rbx + 4], r13w
    jne  .next
    lea  rdi, [rbx + 8]
    mov  rsi, r14
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .conflict                     ; stale intent never replaces a newer pin
    mov  rdi, r14
    mov  rsi, r15
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .conflict                     ; this action must name a changed key
    mov  r13d, [rel ssh_cli_kh_floor]
    inc  r13d
    jz   .refused                       ; never reuse a durable generation
    call ssh_cli_kh_derive
    test eax, eax
    jnz  .refused
    mov  rdi, rbx
    mov  esi, r13d
    mov  rdx, r15
    call ssh_cli_kh_persist.build        ; stage old table, replace one digest
    lea  rdi, [rel ssh_cli_kh_stage]
    mov  esi, SSH_KH_REC_SIZE
    call ssh_cli_kh_setvar              ; guards/revocation/one write/readback
    test eax, eax
    jnz  .out                          ; never retry or restore assumed bytes
    ; The shared publication helper merges saved claims/generations only:
    ; ordinary peer saves never change a digest. Publish this one deliberate
    ; digest only after the complete replacement record read back exactly.
    lea  rdi, [rbx + 8]
    mov  rsi, r15
    mov  edx, 32
    call memcpy
    call ssh_cli_kh_commit_saved
    mov  [rel ssh_cli_kh_gen], r13d
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    xor  eax, eax
    jmp  .out
.next:
    add  rbx, SSH_CLI_PIN_SZ
    inc  ecx
    jmp  .scan
.refused:
    mov  eax, -1
    jmp  .out
.conflict:
    mov  eax, -3
.out:
    mov  [rsp], rax
    call ssh_cli_kh_cleanup
    mov  rax, [rsp]
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
