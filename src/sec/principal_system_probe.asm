;; MODULE sec/principal_system_probe
;; LAYER 5
;; EXPORTS principal_probe_system
;; IMPORTS sec/principal, svc/command, svc/command_aihook
;; CAPS
;; OWNER saga:sec
; Optional AUTHSYS suffix: PRINREAD <pid> or PRINWRITE <pid> <token>.
; Only these existing operational verbs can be selected. The caller has already
; passed AUTHSYS's original owner permission, SYSTEM_KEY bind, KV and BOOT gates.
; RDI points to the suffix. No credential, handle or ticket bytes are serialized.
principal_probe_system:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    call principal_execution_snapshot
    mov  r12, rax
    mov  r13, rdx
    lea  rsi, [rel str_probe_read]
    mov  ecx, 9
    call principal_probe_prefix
    test eax, eax
    jnz  .read
    mov  rdi, rbx
    lea  rsi, [rel str_probe_write]
    mov  ecx, 10
    call principal_probe_prefix
    test eax, eax
    jz   .invalid
    lea  r14, [rbx + 10]
    lea  rdi, [rel str_verb_prinwrite]
    jmp  .lookup
.read:
    lea  r14, [rbx + 9]
    lea  rdi, [rel str_verb_prinread]
.lookup:
    call command_lookup
    cmp  eax, -1
    je   .invalid
    mov  edi, eax
    mov  rsi, r14
    ; Clear stale staged outcome. A gate refusal cannot look like a leaf reply.
    mov  byte [rel prin_out_ready], 0
    call command_aihook_submit_authorized
    mov  r14, rdx
    cmp  byte [rel prin_out_ready], 1
    je   .outcome
    call prin_out_reset
    lea  rdi, [rel str_probe_gate]
    call prin_out_str
.outcome:
    lea  rdi, [rel str_probe_code]
    call prin_out_str
    mov  rdi, r14
    call prin_out_dec
    lea  rdi, [rel str_probe_incoming]
    call prin_out_str
    mov  rdi, r12
    call prin_out_dec
    lea  rdi, [rel str_probe_epoch_before]
    call prin_out_str
    mov  rdi, r13
    call prin_out_dec
    call principal_execution_snapshot
    mov  rbx, rax
    mov  r14, rdx
    lea  rdi, [rel str_probe_restored]
    call prin_out_str
    mov  rdi, rbx
    call prin_out_dec
    lea  rdi, [rel str_probe_epoch_after]
    call prin_out_str
    mov  rdi, r14
    call prin_out_dec
    jmp  .done
.invalid:
    call prin_out_reset
    lea  rdi, [rel str_probe_invalid]
    call prin_out_str
.done:
    mov  byte [rel prin_out_ready], 1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded literal match, RDI/RSI byte strings, ECX length; EAX boolean.
principal_probe_prefix:
    xor  eax, eax
.loop:
    mov  dl, [rdi]
    cmp  dl, [rsi]
    jne  .out
    inc  rdi
    inc  rsi
    dec  ecx
    jnz  .loop
    mov  eax, 1
.out:
    ret
str_probe_read: db "PRINREAD ",0
str_probe_write: db "PRINWRITE ",0
str_probe_gate: db "AUTHSYS PROBE gate_refused",0
str_probe_invalid: db "AUTHSYS PROBE invalid_operation",0
str_probe_code: db " aihook_code=",0
str_probe_incoming: db " incoming_principal=",0
str_probe_epoch_before: db " incoming_epoch=",0
str_probe_restored: db " restored_principal=",0
str_probe_epoch_after: db " restored_epoch=",0
