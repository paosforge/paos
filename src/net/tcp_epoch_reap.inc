; Common actual-free observation. Called only after tcp_tcb_free has excluded a
; running callback. No policy/lock/I/O/allocator changes; original clear body is
; executed exactly once. A cancel/close/RST is also a free, NOT timeout proof.
tcp_tcb_free_observed:
    push rbx
    push r12
    push r13
    sub  rsp, 32
    mov  rbx, rdi
    xor  r12d, r12d
    call tcp_rx_ptr                     ; validates membership before any read
    test rax, rax
    jz   .clear
    mov  r13, [rax + OO_EPOCH]
    test r13, r13
    jz   .clear
    movzx eax, byte [rbx + TCB_STATE]
    test eax, eax
    jz   .clear                         ; freeing an empty slot is no event
    mov  [rsp], rax
    mov  rax, [rbx + TCB_LAST_ACTIVITY]
    mov  [rsp + 8], rax
    mov  rax, [rbx + TCB_DEADLINE]
    mov  [rsp + 16], rax
    movzx eax, byte [rbx + TCB_RETRIES]
    mov  [rsp + 24], rax
    lea  rax, [rel tcp_tcbs]
    mov  r12, rbx
    sub  r12, rax
    shr  r12, 7
    imul r12, r12, 48
    lea  rax, [rel tcp_reap_completions]
    add  r12, rax
.clear:
    mov  rdi, rbx
    call tcp_tcb_clear
    test r12, r12
    jz   .out
    call boot_ms_now                    ; after route/RX/persist/TCB full clear
    mov  [r12 + 8], rax
    mov  rax, [rsp]
    mov  [r12 + 16], rax
    mov  rax, [rsp + 8]
    mov  [r12 + 24], rax
    mov  rax, [rsp + 16]
    mov  [r12 + 32], rax
    mov  rax, [rsp + 24]
    mov  [r12 + 40], rax
    mov  [r12], r13                     ; publish exact never-reused epoch last
.out:
    mov  rax, rbx                      ; original memset/free return value
    add  rsp, 32
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=handle, RSI=epoch, RDX=caller out40 (non-null).
; RAX=0 retained actual free, -1 busy, -2 invalid/missing. Output qwords:
; completed_ms, prior_state, last_activity_ms, final_deadline_ms, retries.
; One bounded table try-lock, no poll or other state advance. Last event/slot
; only: overwrite loses older evidence, and bulk init creates no event.
tcp_client_epoch_reap:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, rdx
    xor  esi, esi
    mov  edx, 40
    call memset
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
    imul rbx, rbx, 48
    lea  rax, [rel tcp_reap_completions]
    add  rbx, rax
    cmp  [rbx], r12
    jne  .missing
    mov  rax, [rbx + 8]
    mov  [r13], rax
    mov  rax, [rbx + 16]
    mov  [r13 + 8], rax
    mov  rax, [rbx + 24]
    mov  [r13 + 16], rax
    mov  rax, [rbx + 32]
    mov  [r13 + 24], rax
    mov  rax, [rbx + 40]
    mov  [r13 + 32], rax
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
