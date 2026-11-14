; Actual completed SYN_SENT timeout, exact never-reused receive incarnation.
; Poll alone calls this internal helper after its real deadline/retry checks,
; under tcp_live_lock and with SERVICE_ACTIVE != 1. No other free path records.
; RDI=validated TCB. Timestamp is sampled AFTER the actual full free completes.
tcp_client_syn_timeout_free_locked:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    call tcp_rx_ptr
    test rax, rax
    jz   .unrecorded
    mov  r12, [rax + OO_EPOCH]
    test r12, r12
    jz   .unrecorded
    lea  r13, [rel tcp_tcbs]
    sub  rbx, r13
    shr  rbx, 7
    shl  rbx, 4
    lea  r13, [rel tcp_syn_retirements]
    add  r13, rbx
    call tcp_tcb_free
    call boot_ms_now
    mov  [r13 + 8], rax
    mov  [r13], r12                    ; publish exact epoch after completion
    jmp  .out
.unrecorded:
    call tcp_tcb_free
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=handle, RSI=nonzero epoch, RDX=8-byte caller-owned completion timestamp.
; RAX=0 actual timeout observed, -1 busy, -2 no retained matching event/invalid.
; Failure clears output. Membership checked before dereference; one bounded
; try-lock, no poll, TX, callback, timer change, or inference from stale state.
; At most one event per slot is retained. Epochs never reset/reuse; overwriting
; an older event loses evidence, never manufactures evidence for another open.
tcp_client_epoch_retirement:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  qword [rdx], 0
    call tcp_live_try_acquire
    test rax, rax
    jnz  .busy
    mov  rdi, rbx
    call tcp_rx_ptr
    test rax, rax
    jz   .missing
    test r12, r12
    jz   .missing
    lea  rax, [rel tcp_tcbs]
    sub  rbx, rax
    shr  rbx, 7
    shl  rbx, 4
    lea  rax, [rel tcp_syn_retirements]
    add  rbx, rax
    cmp  [rbx], r12
    jne  .missing
    mov  rax, [rbx + 8]
    mov  [r13], rax
    xor  r12d, r12d
    jmp  .unlock
.missing:
    mov  r12, -2
.unlock:
    call tcp_live_lock_release
    mov  rax, r12
    jmp  .out
.busy:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
