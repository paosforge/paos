; Exact-incarnation, read-only observation of a client connection.
; RDI=handle, RSI=nonzero epoch, RDX=72-byte caller-owned output.
; RAX=0 observed, -1 table busy, -2 stale/invalid. Failure clears all output.
; Nine qwords: state, retries, deadline_ms, RTO_ms, retry_limit, local IPv4
; (wire representation), remote IPv4, local host-order port, remote port.
; Membership is checked before dereferencing the handle. The incarnation and
; all fields share the same bounded try-lock; this never sends or polls TCP.
tcp_client_epoch_snapshot:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, rdx
    xor  esi, esi
    mov  edx, 72
    call memset
    call tcp_live_try_acquire
    test rax, rax
    jnz  .busy
    mov  rdi, rbx
    call tcp_rx_ptr
    test rax, rax
    jz   .stale
    test r12, r12
    jz   .stale
    cmp  [rax + OO_EPOCH], r12
    jne  .stale
    movzx eax, byte [rbx + TCB_STATE]
    test eax, eax
    jz   .stale
    mov  [r13], rax
    movzx eax, byte [rbx + TCB_RETRIES]
    mov  [r13 + 8], rax
    mov  rax, [rbx + TCB_DEADLINE]
    mov  [r13 + 16], rax
    mov  qword [r13 + 24], TCP_RTO_MS
    mov  qword [r13 + 32], TCP_MAX_RETRIES
    mov  eax, [rbx + TCB_LOCAL_IP]
    mov  [r13 + 40], rax
    mov  eax, [rbx + TCB_REMOTE_IP]
    mov  [r13 + 48], rax
    movzx eax, word [rbx + TCB_LOCAL_PORT]
    mov  [r13 + 56], rax
    movzx eax, word [rbx + TCB_REMOTE_PORT]
    mov  [r13 + 64], rax
    xor  r12d, r12d
    jmp  .unlock
.stale:
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
