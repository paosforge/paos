; Client-owned no-PTY exec. Default empty stdin; opt-in copied stream/control.
; Private v2 trailer follows the original command bytes; shared SSH ABI is exact.
; canonical slot retirement/reset/reuse wipes command and accepted-send state.
SSH_CLI_EXEC_CAP       equ 768
SSH_CLI_EXEC_LEN       equ 0
SSH_CLI_EXEC_SENT      equ 4
SSH_CLI_EXEC_WANT      equ 8
SSH_CLI_EXEC_EOF       equ 12
SSH_CLI_EXEC_EOF_SENT  equ 16
SSH_CLI_EXEC_ACK_BY    equ 24
SSH_CLI_EXEC_ACK_US    equ 20000000
SSH_CLI_EXEC_CMD       equ 32
SSH_CLI_EXEC_VERSION   equ SSH_CLI_EXEC_CMD + SSH_CLI_EXEC_CAP
SSH_CLI_EXEC_STREAM    equ SSH_CLI_EXEC_VERSION + 4
SSH_CLI_EXEC_TOKEN     equ SSH_CLI_EXEC_VERSION + 8
SSH_CLI_EXEC_PRINCIPAL equ SSH_CLI_EXEC_VERSION + 16
SSH_CLI_EXEC_LOCAL     equ SSH_CLI_EXEC_VERSION + 24
SSH_CLI_EXEC_REMOTE    equ SSH_CLI_EXEC_VERSION + 28
SSH_CLI_EXEC_CLOSE     equ SSH_CLI_EXEC_VERSION + 32
SSH_CLI_EXEC_SIGNAL    equ SSH_CLI_EXEC_VERSION + 36
SSH_CLI_EXEC_SIG_SENT  equ SSH_CLI_EXEC_VERSION + 40
SSH_CLI_EXEC_SIZE      equ SSH_CLI_EXEC_VERSION + 48

; PUBLIC read-only mode query for the selected session. No session selection.
ssh_cli_is_exec_impl:
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .no
    cmp  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN], 0
    setne al
    movzx eax, al
    ret
.no:
    xor  eax, eax
    ret

; PUBLIC read-only: an accepted exec still awaiting its ordered acknowledgement.
ssh_cli_exec_pending_impl:
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .no
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_EXEC
    jne  .no
    cmp  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SENT], 1
    sete al
    movzx eax, al
    ret
.no:
    xor  eax, eax
    ret

; PUBLIC configure exactly one length-delimited command before channel work.
; RDI=owned command bytes, ESI=length;0 configured,-1 refused atomically.
; Only the just-started owner TCP session can accept it. No send/store/signing.
ssh_cli_exec_configure_impl:
    cld
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    mov  rbx, [rel ssh_cli_ctx_ptr]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_TCP
    jne  .bad
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .bad
    cmp  byte [rel ssh_cli_owner_armed], 1
    jne  .bad
    mov  eax, [rel ssh_sess_active]
    cmp  eax, SSH_SESS_MAX
    jae  .bad
    lea  rdx, [rel ssh_sess_busy]
    cmp  byte [rdx + rax], 0
    jne  .bad
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN], 0
    jne  .bad
    cmp  dword [rel ssh_cli_txq_len], 0
    jne  .bad
    cmp  qword [rel ssh_cli_exec_epoch], -1
    je   .bad                          ; saturated for this boot, never reuse a caller token
    test r12, r12
    jz   .bad
    test r13d, r13d
    jz   .bad
    cmp  r13d, SSH_CLI_EXEC_CAP
    ja   .bad
    mov  rax, r12
    add  rax, r13
    jc   .bad
    cmp  byte [r12], ' '
    je   .bad
    cmp  byte [rax - 1], ' '
    je   .bad
    xor  ecx, ecx
.scan:
    mov  al, [r12 + rcx]
    cmp  al, 32
    jb   .bad
    cmp  al, 126
    ja   .bad
    inc  ecx
    cmp  ecx, r13d
    jb   .scan
    call principal_current
    test rax, rax
    jz   .principal
    cmp  rax, PRIN_OWNER
    jne  .bad
.principal:
    mov  [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_PRINCIPAL], rax
    inc  qword [rel ssh_cli_exec_epoch]
    mov  rax, [rel ssh_cli_exec_epoch]
    mov  [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_TOKEN], rax
    mov  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_VERSION], 2
    lea  rdi, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CMD]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    mov  [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN], r13d
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_cli_exec_reset:
    mov  rdi, [rel ssh_cli_ctx_ptr]
    test rdi, rdi
    jz   .out
    add  rdi, SSH_CLI_SLOT_EXEC
    xor  esi, esi
    mov  edx, SSH_CLI_EXEC_SIZE
    jmp  memset
.out:
    ret

ssh_cli_exec_clear_request:
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .out
    mov  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_WANT], 0
    mov  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF], 0
.out:
    ret

; Serialize exec behind channel confirmation, using the existing authenticated
; owner/identity/trust bind. A TCP accepted send is never retried waiting for ACK.
ssh_cli_send_exec:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    jne  .bad
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    jne  .bp
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .bad
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_WANT], 1
    jne  .bad
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SENT], 0
    jne  .bad
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .bad
    mov  byte [rel ssh_cli_chpkt], SSH_MSG_CHANNEL_REQUEST
    lea  rdi, [rel ssh_cli_chpkt + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_chpkt + 5]
    mov  esi, 4
    call ssh_be32_store
    mov  dword [rel ssh_cli_chpkt + 9], 'exec'
    mov  byte [rel ssh_cli_chpkt + 13], 1
    lea  rdi, [rel ssh_cli_chpkt + 14]
    mov  esi, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN]
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_chpkt + 18]
    lea  rsi, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CMD]
    mov  edx, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN]
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_chpkt]
    mov  edx, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN]
    add  edx, 18
    call ssh_cli_gcm_send
    test eax, eax
    js   .uncertain
    jnz  .bp
    mov  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SENT], 1
    mov  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_WANT], 0
    mov  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_EXEC
    call time_monotonic_now_us
    add  rax, SSH_CLI_EXEC_ACK_US
    jc   .late
    mov  [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_ACK_BY], rax
    lea  rdi, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CMD]
    xor  esi, esi
    mov  edx, SSH_CLI_EXEC_CAP
    call memset                         ; bytes no longer needed, never rebuild an accepted request
    xor  eax, eax
    pop  rbx
    ret
.bp:
    mov  eax, 1
    pop  rbx
    ret
.late:
    mov  edi, 23
    jmp  .fault
.uncertain:
    mov  edi, 25
    jmp  .fault
.bad:
    mov  edi, 24
.fault:
    call ssh_cli_exec_fault
    pop  rbx
    ret

; Retire/abort only this tuple. An active receive consumer defers the abort,
; keeping its exact TCB until return; no pointer is dropped before that boundary.
ssh_cli_exec_fault:
    mov  byte [rel ssh_cli_error], dil
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_retire_abort], 1
    call ssh_cli_retire
    mov  eax, -1
    ret

; An accepted exec is an uncertain remote action until its ordered ACK arrives.
; Check the same total ACK bound on idle ticks and before consuming a late ACK.
; Preserve the caller's decrypted packet arguments and pending phase register.
ssh_cli_exec_check:
    push rdi
    push rsi
    push rdx
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_EXEC
    je   .pending
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    jne  .ok
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .ok                            ; peer CLOSE owns ordered retirement/close echo
    call ssh_cli_exec_identity
    test eax, eax
    jnz  .revoked
    jmp  .ok
.pending:
    call ssh_cli_exec_identity
    test eax, eax
    jnz  .revoked
    call time_monotonic_now_us
    mov  rdx, [rel ssh_cli_ctx_ptr]
    cmp  rax, [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_ACK_BY]
    jae  .late
.ok:
    xor  eax, eax
    jmp  .out
.revoked:
    mov  edi, 24
    jmp  .fault
.late:
    mov  edi, 23
.fault:
    call ssh_cli_exec_fault
.out:
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; After peer SUCCESS, drain copied stdin then the exactly-once EOF intent.
; Transport pressure/rekey retains intents; output continues until EOF/CLOSE.
ssh_cli_exec_poll:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    test rbx, rbx
    jz   .idle
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    jne  .idle
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], 0
    jne  .signal
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_STREAM], 1
    jne  .eof
    cmp  dword [rel ssh_cli_txq_len], 0
    je   .eof
    call ssh_cli_exec_drain
    jmp  .consumed                     ; EOF never overtakes admitted bytes, even window0
.signal:
    call ssh_cli_exec_send_signal
    jmp  .consumed                     ; out-of-band control may bypass a blocked stdin window
.eof:
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF], 1
    jne  .idle
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    jne  .bad
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .bad
    mov  byte [rel ssh_cli_chpkt], SSH_MSG_CHANNEL_EOF
    lea  rdi, [rel ssh_cli_chpkt + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_chpkt]
    mov  edx, 5
    call ssh_cli_gcm_send
    test eax, eax
    js   .bad
    jnz  .consumed
    mov  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF], 0
    mov  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF_SENT], 1
.consumed:
    mov  eax, 1
    pop  rbx
    ret
.bad:
    mov  edi, 25
    call ssh_cli_exec_fault
    jmp  .consumed
.idle:
    xor  eax, eax
    pop  rbx
    ret

; Fresh configure only; preserves the accepted default configure API exactly.
ssh_cli_exec_configure_stream_impl:
    call ssh_cli_exec_configure_impl
    test eax, eax
    jnz  .out
    mov  rdx, [rel ssh_cli_ctx_ptr]
    mov  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_STREAM], 1
.out:
    ret

ssh_cli_exec_handle_impl:
    cld
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .out
    mov  rax, [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_TOKEN]
.out:
    ret

; Same per-session owner/identity/trust binding as rekey, plus captured principal.
; Channel binding becomes final only at the acknowledged EXEC transition.
ssh_cli_exec_identity:
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .out
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_VERSION], 2
    jne  .bad
    call principal_current
    cmp  rax, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_PRINCIPAL]
    jne  .bad
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    jne  .ok
    mov  eax, [rel ssh_cli_local_chan]
    cmp  eax, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LOCAL]
    jne  .bad
    mov  eax, [rel ssh_cli_remote_chan]
    cmp  eax, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_REMOTE]
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .done
.bad:
    mov  eax, -1
.done:
    pop  rbx
.out:
    ret

; Trusted typed caller: RDI=nonzero token from configure's selected session.
; This checks identity, not input provenance; Terminal judges the original event.
ssh_cli_exec_admit:
    cld
    push rdi
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .bad
    test rdi, rdi
    jz   .bad
    cmp  rdi, [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_TOKEN]
    jne  .bad
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    jne  .bad
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .bad
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .bad
    mov  eax, [rel ssh_sess_active]
    cmp  eax, SSH_SESS_MAX
    jae  .bad
    lea  rdx, [rel ssh_sess_used]
    cmp  byte [rdx + rax], 1
    jne  .bad
    lea  rdx, [rel ssh_sess_busy]
    cmp  byte [rdx + rax], 0
    jne  .bad
    call ssh_cli_exec_identity
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rdi
    ret

; PUBLIC stdin(token, owned bytes, length):0 whole copy queued,1 full,2 closed,
; -1 refused. No borrowed pointer persists; no prefix on any refusal.
ssh_cli_exec_stdin_impl:
    cld
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13d, edx
    call ssh_cli_exec_admit
    test eax, eax
    jnz  .out
    mov  rbx, [rel ssh_cli_ctx_ptr]
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_STREAM], 1
    jne  .closed
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CLOSE], 0
    jne  .closed
    test r12, r12
    jz   .bad
    test r13d, r13d
    jz   .bad
    cmp  r13d, SSH_TXQ_CAP
    ja   .bad
    mov  rax, r12
    add  rax, r13
    jc   .bad
    mov  eax, SSH_TXQ_CAP
    sub  eax, [rel ssh_cli_txq_len]
    jb   .bad
    cmp  eax, r13d
    jb   .full
    lea  rbx, [rbx + SSH_CLI_SLOT_TXQ]
    mov  eax, [rel ssh_cli_txq_tail]
    xor  ecx, ecx
.copy:
    mov  dl, [r12 + rcx]
    mov  [rbx + rax], dl
    inc  eax
    and  eax, SSH_TXQ_CAP - 1
    inc  ecx
    cmp  ecx, r13d
    jb   .copy
    mov  [rel ssh_cli_txq_tail], eax
    add  [rel ssh_cli_txq_len], r13d
    xor  eax, eax
    jmp  .out
.full:
    mov  eax, 1
    jmp  .out
.closed:
    mov  eax, 2
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; PUBLIC close_stdin(token):0 intent queued,2 already/default closed,-1 refused.
ssh_cli_exec_close_stdin_impl:
    call ssh_cli_exec_admit
    test eax, eax
    jnz  .out
    mov  rdx, [rel ssh_cli_ctx_ptr]
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_STREAM], 1
    jne  .closed
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CLOSE], 0
    jne  .closed
    mov  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CLOSE], 1
    mov  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF], 1
    xor  eax, eax
.out:
    ret
.closed:
    mov  eax, 2
    ret

; PUBLIC signal(token,1 INT/2 TERM):0 queued,1 pending slot full,-1 refused.
; want_reply=0: accepted ciphertext proves neither remote support nor effect.
ssh_cli_exec_signal_impl:
    cld
    push rbx
    mov  ebx, esi
    cmp  ebx, 1
    jb   .bad
    cmp  ebx, 2
    ja   .bad
    call ssh_cli_exec_admit
    test eax, eax
    jnz  .out
    mov  rdx, [rel ssh_cli_ctx_ptr]
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], 0
    jne  .full
    mov  [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], ebx
    mov  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIG_SENT], 0
    xor  eax, eax
    jmp  .out
.full:
    mov  eax, 1
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; PUBLIC status(token):bit0stream,1ready,2close requested,3EOF accepted,
; 4signal pending,5signal ciphertext accepted/unconfirmed. -1 refused.
ssh_cli_exec_status_impl:
    call ssh_cli_exec_admit
    test eax, eax
    jnz  .out
    mov  rdx, [rel ssh_cli_ctx_ptr]
    mov  eax, [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_STREAM]
    or   eax, 2
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_CLOSE], 0
    je   .eof
    or   eax, 4
.eof:
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF_SENT], 0
    je   .signal
    or   eax, 8
.signal:
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], 0
    je   .sent
    or   eax, 16
.sent:
    cmp  dword [rdx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIG_SENT], 0
    je   .out
    or   eax, 32
.out:
    ret

; PUBLIC cancel(token): local cancellation only, including pre-ACK. A matching
; token revokes this tuple through existing consumer-safe disconnect/retirement.
ssh_cli_exec_cancel_impl:
    cld
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .bad
    test rdi, rdi
    jz   .bad
    cmp  rdi, [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_TOKEN]
    jne  .bad
    call ssh_client_disconnect
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

ssh_cli_exec_send_signal:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  byte [rel ssh_cli_chpkt], SSH_MSG_CHANNEL_REQUEST
    lea  rdi, [rel ssh_cli_chpkt + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_chpkt + 5]
    mov  esi, 6
    call ssh_be32_store
    mov  dword [rel ssh_cli_chpkt + 9], 'sign'
    mov  word [rel ssh_cli_chpkt + 13], 'al'
    mov  byte [rel ssh_cli_chpkt + 15], 0
    mov  esi, 3
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], 1
    je   .length
    mov  esi, 4
.length:
    lea  rdi, [rel ssh_cli_chpkt + 16]
    call ssh_be32_store
    mov  edx, 23
    mov  dword [rel ssh_cli_chpkt + 20], 'INT'
    cmp  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], 1
    je   .send
    mov  dword [rel ssh_cli_chpkt + 20], 'TERM'
    inc  edx
.send:
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_chpkt]
    call ssh_cli_gcm_send
    test eax, eax
    js   .bad
    jnz  .out
    mov  eax, [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL]
    mov  [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIG_SENT], eax
    mov  dword [rbx + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIGNAL], 0
    xor  eax, eax
    jmp  .out
.bad:
    mov  edi, 25
    call ssh_cli_exec_fault
.out:
    pop  rbx
    ret

; One bounded copied-ring fragment. Only accepted ciphertext consumes bytes and
; peer credit; any unknown acceptance retires without rebuilding/replaying it.
ssh_cli_exec_drain:
    push rbx
    push r12
    push r13
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  r13d, [rel ssh_cli_txq_len]
    cmp  r13d, 180
    jbe  .peer
    mov  r13d, 180
.peer:
    cmp  r13d, [rel ssh_cli_remote_max_packet]
    jbe  .window
    mov  r13d, [rel ssh_cli_remote_max_packet]
.window:
    cmp  r13d, [rel ssh_cli_remote_window]
    jbe  .size
    mov  r13d, [rel ssh_cli_remote_window]
.size:
    test r13d, r13d
    jz   .out
    mov  eax, [rel ssh_cli_txq_head]
    xor  ecx, ecx
    lea  rdi, [rel ssh_cli_chpkt]
    mov  byte [rdi], SSH_MSG_CHANNEL_DATA
    lea  r12, [rbx + SSH_CLI_SLOT_TXQ]
.copy:
    mov  dl, [r12 + rax]
    mov  [rdi + rcx + 9], dl
    inc  eax
    and  eax, SSH_TXQ_CAP - 1
    inc  ecx
    cmp  ecx, r13d
    jb   .copy
    lea  rdi, [rel ssh_cli_chpkt + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_chpkt + 5]
    mov  esi, r13d
    call ssh_be32_store
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_chpkt]
    lea  edx, [r13 + 9]
    call ssh_cli_gcm_send
    test eax, eax
    js   .bad
    jnz  .out
    mov  eax, [rel ssh_cli_txq_head]
    add  eax, r13d
    and  eax, SSH_TXQ_CAP - 1
    mov  [rel ssh_cli_txq_head], eax
    sub  [rel ssh_cli_txq_len], r13d
    sub  [rel ssh_cli_remote_window], r13d
    call ssh_cli_rearm_keepalive
    jmp  .out
.bad:
    mov  edi, 25
    call ssh_cli_exec_fault
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
