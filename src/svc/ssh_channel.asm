;; MODULE svc/ssh_channel
;; LAYER 5
;; EXPORTS ssh_connection_packet, ssh_exec_run, ssh_channel_selftest, ssh_exec_status, ssh_exec_out, ssh_exec_out_len, ssh_exec_response_step
;; IMPORTS svc/ssh, svc/ssh_auth, svc/command, svc/command_auth, svc/command_audit, svc/command_udp, svc/command_ssh, sec/principal, sec/session, core/lib/mem, core/lib/str, boot/serial, net/tcp
;; CAPS
;; OWNER saga:ssh_server
; ============================================================================
; SSH rung 3 (Task2143): RFC 4254 connection layer on a 2142-authenticated
; connection. One `session` channel per connection; `exec` is the only way to
; run anything and it is a ONE-SHOT verb line:
;
;   ssh -i <enrolled key> paos@<host> "STATUS"
;
; The exec string is parsed as a verb line (leading '/' optional) and enters
; the SAME command_dispatch every projection uses, with REQ_SOURCE=ssh and
; REQ_PRINCIPAL = the connection's bound principal. Authority is a
; request-scoped AUTH_TS_SSH ticket (principal + current enrolled-key mask,
; bounded by the original connection grant). Enrollment is rechecked by exact
; authenticated public key for each new command; the ONE
; network-access gate admits it as NET_SVC_SSH whether or not the local
; console is locked, and every verb's own capability check still applies.
; The reply is the canonical lean UDP envelope (command_udp_capture_reply),
; streamed as CHANNEL_DATA; the SSH exit-status comes from the envelope
; (0 ok, the CMDE_* code otherwise); then EOF + CLOSE. There is no shell,
; no pty, no subsystem: single dispatch census = exactly one command_dispatch.
;
; SSH exit-status table (ADMIN 2026-09-30 06:22 item 5: every desktop/lock
; refusal exits NON-ZERO):
;   0  ok                         4  CMDE_BADSEL
;   1  CMDE_NOVERB, or an OK-coded  5  CMDE_BADARG (malformed/empty exec,
;      reply that is a refusal         reset staged by an exec)
;      (AUTH_REFUSED / ERR prefix)  6  CMDE_AUTHDENY (capability/principal)
;   2  CMDE_CAPDENY               7  CMDE_DESKTOP_LOCKED: desktop_locked
;   3  CMDE_BADJOB                    (injection verb) or a desktop handler's
;                                     session=locked refusal
;   255 is the OpenSSH client's own transport/auth failure, never PaOS.
;
; Remote-unlock split (ADMIN 2026-09-30 06:22, ADOPTED): an SSH exec carries
; its own authority and never unlocks the local console implicitly —
; sec/session's unlock core refuses (and audits) every unlock inside a remote
; request unless the verb armed the EXPLICIT owner-unlock grant (AUTHLOGIN
; with the owner password, PUSHAUTH approve; unrestricted OWNER key only,
; audited `UNLOCK explicit source=ssh ...`). Input-injection verbs stay
; refused `desktop_locked` over SSH while the console is locked (test-only
; instruments, never a human). The local-session principal is restored if a
; handler moved it without a lock-state transition.
; ============================================================================

SSH_CH_OUR_WINDOW   equ 0x8000
SSH_CH_OUR_MAXPKT   equ 1024
SSH_CH_DATA_CHUNK   equ 1024
SSH_EXEC_LINE_CAP   equ 1024
SSH_EXEC_OUT_CAP    equ SSH_EXEC_RESPONSE_CAP
SSH_CH_PKT_CAP      equ 1280
%if SSH_C_EXEC_REPLY + SSH_EXEC_OUT_CAP > SSH_CTX_SIZE
    %error "SSH exec reply exceeds connection custody"
%endif
SSCRUB_SSH_PAYLOAD_CAP equ 128

; --- tiny payload writer over ssh_ch_pkt ---
ssh_w_begin:
    lea  rax, [rel ssh_ch_pkt]
    mov  [rel ssh_w_cur], rax
    ret

ssh_w_byte:                                  ; EDI = byte
    mov  rax, [rel ssh_w_cur]
    mov  [rax], dil
    inc  rax
    mov  [rel ssh_w_cur], rax
    ret

ssh_w_u32:                                   ; EDI = host-order value
    mov  rax, [rel ssh_w_cur]
    bswap edi
    mov  [rax], edi
    add  rax, 4
    mov  [rel ssh_w_cur], rax
    ret

ssh_w_string:                                ; RSI = bytes, EDX = len
    push rbx
    push r12
    mov  rbx, rsi
    mov  r12d, edx
    mov  edi, edx
    call ssh_w_u32
    mov  rdi, [rel ssh_w_cur]
    mov  rsi, rbx
    mov  edx, r12d
    call memcpy
    mov  rax, [rel ssh_w_cur]
    add  rax, r12
    mov  [rel ssh_w_cur], rax
    pop  r12
    pop  rbx
    ret

ssh_w_send:                                  ; RDI = ctx -> EAX 0/-1
    mov  rdx, [rel ssh_w_cur]
    lea  rsi, [rel ssh_ch_pkt]
    sub  rdx, rsi
    jmp  ssh_queue_gcm

; ssh_w_simple(RDI=ctx, ESI=msg, EDX=recipient) — [msg][u32 recipient]
ssh_w_simple:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    call ssh_w_begin
    mov  edi, r12d
    call ssh_w_byte
    mov  edi, r13d
    call ssh_w_u32
    mov  rdi, rbx
    call ssh_w_send
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=cursor, RSI=end -> EAX value (host order), RDX=next; CF set if short.
ssh_rd_u32:
    lea  rdx, [rdi + 4]
    cmp  rdx, rsi
    ja   .short
    mov  eax, [rdi]
    bswap eax
    clc
    ret
.short:
    stc
    ret

; ---------------------------------------------------------------------------
; ssh_connection_packet(RDI=ctx, RSI=payload, EDX=len) -> EAX 0 / -1 close.
; The payload lives in ctx PLAIN, which sealing a reply overwrites: every
; field is read before the first queued reply.
; ---------------------------------------------------------------------------
ssh_connection_packet:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    lea  r13, [rsi + rdx]
    movzx eax, byte [r12]
    cmp  eax, SSH_MSG_DISCONNECT
    je   .fatal
    cmp  eax, SSH_MSG_KEXINIT
    je   .fatal                            ; transport consumes rekey; never a connection message
    cmp  eax, SSH_MSG_GLOBAL_REQUEST
    je   .global
    cmp  eax, SSH_MSG_CHANNEL_OPEN
    je   .open
    cmp  eax, SSH_MSG_CHANNEL_WINDOW_ADJUST
    je   .adjust
    cmp  eax, SSH_MSG_CHANNEL_CLOSE
    je   .close
    cmp  eax, SSH_MSG_CHANNEL_REQUEST
    je   .request
    ; IGNORE/DEBUG/UNIMPLEMENTED, client DATA/EOF (no stdin consumer), replies
    ; to requests we never send, and post-success USERAUTH are all ignored.
    jmp  .ok
.global:
    lea  rdi, [r12 + 1]
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    cmp  r8, r13
    jae  .fatal
    cmp  byte [r8], 0
    je   .ok
    mov  byte [rel ssh_ch_onebyte], SSH_MSG_REQUEST_FAILURE
    mov  rdi, rbx
    lea  rsi, [rel ssh_ch_onebyte]
    mov  edx, 1
    call ssh_queue_gcm
    jmp  .queued
.open:
    lea  rdi, [r12 + 1]
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    mov  r14, rax
    mov  r15d, edx
    mov  rdi, r8
    mov  rsi, r13
    call ssh_rd_u32
    jc   .fatal
    mov  [rel ssh_ch_sender], eax
    mov  rdi, rdx
    call ssh_rd_u32
    jc   .fatal
    mov  [rel ssh_ch_window], eax
    mov  rdi, rdx
    call ssh_rd_u32
    jc   .fatal
    mov  [rel ssh_ch_maxpkt], eax
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_ssh_ch_session]
    mov  ecx, 7
    call ssh_bytes_eq
    mov  ecx, 3                            ; SSH_OPEN_UNKNOWN_CHANNEL_TYPE
    test eax, eax
    jz   .open_refuse
    mov  ecx, 4                            ; SSH_OPEN_RESOURCE_SHORTAGE: one session
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_NONE
    jne  .open_refuse
    mov  eax, [rel ssh_ch_sender]
    mov  [rbx + SSH_C_PEER_CHAN], eax
    mov  eax, [rel ssh_ch_window]
    mov  [rbx + SSH_C_PEER_WINDOW], eax
    mov  eax, [rel ssh_ch_maxpkt]
    mov  [rbx + SSH_C_PEER_MAXPKT], eax
    mov  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    call ssh_w_begin
    mov  edi, SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    call ssh_w_byte
    mov  edi, [rel ssh_ch_sender]
    call ssh_w_u32
    xor  edi, edi                          ; our channel id is always 0
    call ssh_w_u32
    mov  edi, SSH_CH_OUR_WINDOW
    call ssh_w_u32
    mov  edi, SSH_CH_OUR_MAXPKT
    call ssh_w_u32
    mov  rdi, rbx
    call ssh_w_send
    jmp  .queued
.open_refuse:
    mov  [rel ssh_ch_reason], ecx
    call ssh_w_begin
    mov  edi, SSH_MSG_CHANNEL_OPEN_FAILURE
    call ssh_w_byte
    mov  edi, [rel ssh_ch_sender]
    call ssh_w_u32
    mov  edi, [rel ssh_ch_reason]
    call ssh_w_u32
    xor  edi, edi                          ; empty description
    call ssh_w_u32
    xor  edi, edi                          ; empty language tag
    call ssh_w_u32
    mov  rdi, rbx
    call ssh_w_send
    jmp  .queued
.adjust:
    lea  rdi, [r12 + 1]
    mov  rsi, r13
    call ssh_rd_u32
    jc   .fatal
    mov  r14d, eax
    mov  rdi, rdx
    call ssh_rd_u32
    jc   .fatal
    test r14d, r14d
    jnz  .ok
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    jne  .ok
    add  eax, [rbx + SSH_C_PEER_WINDOW]
    jc   .fatal                            ; RFC4254: never invent overflow credit
.window_ok:
    mov  [rbx + SSH_C_PEER_WINDOW], eax
    jmp  .resume
.close:
    lea  rdi, [r12 + 1]
    mov  rsi, r13
    call ssh_rd_u32
    jc   .fatal
    test eax, eax
    jnz  .ok
    movzx eax, byte [rbx + SSH_C_CHAN_STATE]
    mov  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_CLOSED
    cmp  eax, SSH_CH_OPEN
    jne  .ok                               ; our CLOSE already went out
    mov  rdi, rbx
    call ssh_exec_response_scrub            ; peer cancellation revokes plaintext now
    mov  byte [rbx + SSH_C_EXEC_PHASE], 5    ; CLOSE echo can wait for queue space
    jmp  .resume
.request:
    lea  rdi, [r12 + 1]
    mov  rsi, r13
    call ssh_rd_u32
    jc   .fatal
    mov  r14d, eax                         ; recipient
    mov  rdi, rdx
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    cmp  r8, r13
    jae  .fatal
    movzx ecx, byte [r8]
    mov  [rel ssh_ch_want_reply], cl
    lea  r15, [r8 + 1]                     ; request-specific data
    mov  [rel ssh_ch_req_type], rax
    mov  [rel ssh_ch_req_type_len], edx
    test r14d, r14d
    jnz  .request_fail
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    jne  .request_fail
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel str_ssh_ch_exec]
    mov  ecx, 4
    call ssh_bytes_eq
    test eax, eax
    jnz  .exec
    mov  rdi, [rel ssh_ch_req_type]
    mov  esi, [rel ssh_ch_req_type_len]
    lea  rdx, [rel str_ssh_ch_env]
    mov  ecx, 3
    call ssh_bytes_eq
    test eax, eax
    jz   .request_fail                     ; pty-req/shell/subsystem/...: no shell exists
    cmp  byte [rel ssh_ch_want_reply], 0
    je   .ok
    mov  rdi, rbx
    mov  esi, SSH_MSG_CHANNEL_SUCCESS
    mov  edx, [rbx + SSH_C_PEER_CHAN]
    call ssh_w_simple
    jmp  .queued
.request_fail:
    cmp  byte [rel ssh_ch_want_reply], 0
    je   .ok
    mov  rdi, rbx
    mov  esi, SSH_MSG_CHANNEL_FAILURE
    mov  edx, [rbx + SSH_C_PEER_CHAN]
    call ssh_w_simple
    jmp  .queued
.exec:
    cmp  byte [rbx + SSH_C_EXEC_USED], 0
    jne  .request_fail                     ; at most one admitted exec, even at window zero
    mov  rdi, r15
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    ; Copy the command out of PLAIN before any reply is sealed.
    mov  byte [rel ssh_exec_too_long], 0
    cmp  edx, SSH_EXEC_LINE_CAP - 1
    jbe  .len_ok
    mov  byte [rel ssh_exec_too_long], 1
    mov  edx, SSH_EXEC_LINE_CAP - 1
.len_ok:
    mov  r14d, edx
    lea  rdi, [rel ssh_exec_line]
    mov  rsi, rax
    call memcpy
    lea  rax, [rel ssh_exec_line]
    mov  byte [rax + r14], 0
    ; An embedded NUL would hide a tail from the audit/dispatch parse.
    xor  ecx, ecx
.nul_scan:
    cmp  ecx, r14d
    jae  .nul_done
    lea  rax, [rel ssh_exec_line]
    cmp  byte [rax + rcx], 0
    jne  .nul_next
    mov  byte [rel ssh_exec_too_long], 1
.nul_next:
    inc  ecx
    jmp  .nul_scan
.nul_done:
    ; Admit once before calling the registry. Queue pressure cannot replay
    ; either the request's authority or its effects. Reply/status belong to
    ; this context before any other connection reuses the global scratch.
    mov  byte [rbx + SSH_C_EXEC_USED], 1
    mov  byte [rbx + SSH_C_EXEC_PHASE], 2
    cmp  byte [rel ssh_ch_want_reply], 0
    je   .run
    mov  byte [rbx + SSH_C_EXEC_PHASE], 1
.run:
    mov  rdi, rbx
    call ssh_exec_run
    call ssh_exec_scrub_line
    mov  edx, [rel ssh_exec_out_len]
    cmp  edx, SSH_EXEC_OUT_CAP
    ja   .fatal                            ; producer contract, never an out-of-bounds copy
    mov  [rbx + SSH_C_EXEC_LEN], edx
    mov  eax, [rel ssh_exec_status]
    mov  [rbx + SSH_C_EXEC_STATUS], eax
    lea  rdi, [rbx + SSH_C_EXEC_REPLY]
    lea  rsi, [rel ssh_exec_out]
    call memcpy
    lea  rdi, [rel ssh_exec_out]
    xor  esi, esi
    mov  edx, SSH_EXEC_OUT_CAP + 8
    call memset                            ; only connection-owned plaintext may wait
    mov  dword [rel ssh_exec_out_len], 0
    mov  dword [rel ssh_exec_status], 0
.resume:
    mov  rdi, rbx
    call ssh_exec_response_step
    test eax, eax
    js   .fatal
    jmp  .ok
.queued:
    test eax, eax
    jnz  .fatal
.ok:
    xor  eax, eax
    jmp  .out
.fatal:
    mov  rdi, rbx
    call ssh_exec_response_scrub
    call ssh_exec_scrub_line                   ; a failed exec may have copied its line already
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Wipe this context's complete response custody. Full transport retirement
; already wipes SSH_CTX_SIZE, including this tail, on EOF/reuse/error.
ssh_exec_response_scrub:
    add  rdi, SSH_C_EXEC_PHASE
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE - SSH_C_EXEC_PHASE
    jmp  memset

; RDI=ctx -> EAX 1 queued progress / 0 blocked or idle / -1 fatal.
; At most eight immutable records per call. Window zero, queue pressure and
; rekey return immediately; the existing cooperative SSH/TCP tick resumes.
; Only accepted enqueue advances phase/frontier/credit. RFC4254 sections
; 5.2/5.3/6.10: all DATA precedes status, EOF and CLOSE, exactly once.
ssh_exec_response_step:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    xor  r12d, r12d                        ; progress this pass
    mov  r15d, 8
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .out                             ; never interleave application records with KEX
    cmp  dword [rbx + SSH_C_RK_DEFER_LEN], 0
    jne  .out                             ; replay deferred input in transport order first
.next:
    movzx r14d, byte [rbx + SSH_C_EXEC_PHASE]
    test r14d, r14d
    jz   .out
    cmp  r14d, 5
    ja   .bad
    cmp  r14d, 2
    jne  .control
    mov  r13d, [rbx + SSH_C_EXEC_LEN]
    cmp  r13d, SSH_EXEC_OUT_CAP
    ja   .bad
    sub  r13d, [rbx + SSH_C_EXEC_OFF]
    jc   .bad
    jz   .status_phase
    cmp  r13d, SSH_CH_DATA_CHUNK
    jbe  .maxpkt
    mov  r13d, SSH_CH_DATA_CHUNK
.maxpkt:
    cmp  r13d, [rbx + SSH_C_PEER_MAXPKT]
    jbe  .window
    mov  r13d, [rbx + SSH_C_PEER_MAXPKT]
.window:
    cmp  r13d, [rbx + SSH_C_PEER_WINDOW]
    jbe  .chunk
    mov  r13d, [rbx + SSH_C_PEER_WINDOW]
.chunk:
    test r13d, r13d
    jz   .out
    lea  edx, [r13d + 9]                   ; DATA header + string
    jmp  .room
.status_phase:
    mov  byte [rbx + SSH_C_EXEC_PHASE], 3
    mov  r14d, 3
.control:
    mov  edx, 5                            ; SUCCESS / EOF / CLOSE
    cmp  r14d, 3
    jne  .room
    mov  edx, 25                           ; exit-status request
.room:
    mov  rdi, rbx
    call ssh_queue_gcm_room                 ; before writer/PLAIN/seal/entropy
    test eax, eax
    jz   .out
    call ssh_w_begin
    cmp  r14d, 1
    je   .ack
    cmp  r14d, 2
    je   .data
    cmp  r14d, 3
    je   .status
    mov  edi, SSH_MSG_CHANNEL_EOF
    cmp  r14d, 4
    je   .simple
    mov  edi, SSH_MSG_CHANNEL_CLOSE
    jmp  .simple
.ack:
    mov  edi, SSH_MSG_CHANNEL_SUCCESS
.simple:
    call ssh_w_byte
    mov  edi, [rbx + SSH_C_PEER_CHAN]
    call ssh_w_u32
    jmp  .send
.data:
    mov  edi, SSH_MSG_CHANNEL_DATA
    call ssh_w_byte
    mov  edi, [rbx + SSH_C_PEER_CHAN]
    call ssh_w_u32
    mov  eax, [rbx + SSH_C_EXEC_OFF]
    lea  rsi, [rbx + SSH_C_EXEC_REPLY]
    add  rsi, rax
    mov  edx, r13d
    call ssh_w_string
    jmp  .send
.status:
    mov  edi, SSH_MSG_CHANNEL_REQUEST
    call ssh_w_byte
    mov  edi, [rbx + SSH_C_PEER_CHAN]
    call ssh_w_u32
    lea  rsi, [rel str_ssh_ch_exit_status]
    mov  edx, 11
    call ssh_w_string
    xor  edi, edi
    call ssh_w_byte
    mov  edi, [rbx + SSH_C_EXEC_STATUS]
    call ssh_w_u32
.send:
    mov  rdi, rbx
    call ssh_w_send
    test eax, eax
    jnz  .bad                             ; real crypto failure closes, never retries sealing
    mov  r12d, 1
    cmp  r14d, 2
    jne  .advance
    ; Sealed FIFO now irrevocably owns these bytes. Retire the plaintext prefix.
    mov  eax, [rbx + SSH_C_EXEC_OFF]
    lea  rdi, [rbx + SSH_C_EXEC_REPLY]
    add  rdi, rax
    xor  esi, esi
    mov  edx, r13d
    call memset
    add  [rbx + SSH_C_EXEC_OFF], r13d
    sub  [rbx + SSH_C_PEER_WINDOW], r13d
    jmp  .scratch
.advance:
    inc  byte [rbx + SSH_C_EXEC_PHASE]
    cmp  r14d, 5
    jne  .scratch
    mov  rdi, rbx
    call ssh_exec_response_scrub
    mov  byte [rbx + SSH_C_EXEC_USED], 1
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_CLOSED
    je   .scratch                         ; peer CLOSE echo, already terminal
    mov  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_CLOSE_SENT
.scratch:
    lea  rdi, [rel ssh_ch_pkt]
    xor  esi, esi
    mov  edx, SSH_CH_PKT_CAP
    call memset
    dec  r15d
    jnz  .next
.out:
    mov  eax, r12d
    jmp  .return
.bad:
    mov  rdi, rbx
    call ssh_exec_response_scrub
    lea  rdi, [rel ssh_ch_pkt]
    xor  esi, esi
    mov  edx, SSH_CH_PKT_CAP
    call memset
    mov  r12d, -1
    jmp  .out
.return:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_exec_scrub_line — wipe the exec command copies (w045, SSHUNLOCK_REPORT
; risk 5): ssh_exec_line (verb + argument as received) and ssh_exec_arg (the
; request-owned text argument; a handler scrubs only its own token, and a verb
; refused before its handler scrubs nothing). Canonical core/lib memset.
; clobbers: RAX,RCX,RDX,RSI,RDI.
ssh_exec_scrub_line:
    lea  rdi, [rel ssh_exec_line]
    xor  esi, esi
    mov  edx, SSH_EXEC_LINE_CAP
    call memset
    lea  rdi, [rel ssh_exec_arg]
    xor  esi, esi
    mov  edx, SSH_EXEC_LINE_CAP
    call memset
    ret

; RDI = verb cstr -> EAX 1 when the verb exercises LOCAL desktop/console
; authority (typed password login or local input injection). While the
; console is locked such verbs are refused to every SSH caller.
ssh_exec_desktop_verb:
    push rbx
    push r12
    mov  r12, rdi
    lea  rbx, [rel ssh_exec_desktop_names]
.scan:
    cmp  byte [rbx], 0
    je   .no
    mov  rdi, r12
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jz   .yes
.skip:
    inc  rbx
    cmp  byte [rbx - 1], 0
    jne  .skip
    jmp  .scan
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RSI = cstr appended to ssh_exec_out (bounded).
ssh_exec_out_append:
    mov  eax, [rel ssh_exec_out_len]
    lea  rdi, [rel ssh_exec_out]
.loop:
    mov  cl, [rsi]
    test cl, cl
    jz   .done
    cmp  eax, SSH_EXEC_OUT_CAP
    jae  .done
    mov  [rdi + rax], cl
    inc  eax
    inc  rsi
    jmp  .loop
.done:
    mov  [rel ssh_exec_out_len], eax
    ret

; ---------------------------------------------------------------------------
; ssh_exec_run(RDI=ctx) — run the NUL-terminated ssh_exec_line as ONE verb
; through THE registry with the connection's principal. Produces
; ssh_exec_out/_len (the canonical envelope) and ssh_exec_status.
; ---------------------------------------------------------------------------
ssh_exec_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    inc  qword [rel ssh_exec_count]
    mov  dword [rel ssh_exec_out_len], 0
    mov  byte [rel ssh_exec_hint_noverb], 0
    mov  byte [rel ssh_exec_note_reboot], 0
    cmp  byte [rel ssh_exec_too_long], 1
    je   .malformed
    ; trim leading spaces and one presentation '/'
    lea  r12, [rel ssh_exec_line]
.lead:
    cmp  byte [r12], ' '
    jne  .lead_done
    inc  r12
    jmp  .lead
.lead_done:
    cmp  byte [r12], '/'
    jne  .trail
    inc  r12
.trail:
    mov  rdi, r12
    call strlen
    lea  rcx, [r12 + rax]
.trim:
    cmp  rcx, r12
    jbe  .trim_done
    cmp  byte [rcx - 1], ' '
    ja   .trim_done
    dec  rcx
    mov  byte [rcx], 0
    jmp  .trim
.trim_done:
    cmp  byte [r12], 0
    je   .empty
    ; split verb / argument exactly like the console + UDP parsers
    mov  r13, r12
.find_space:
    cmp  byte [r13], 0
    je   .split_done
    cmp  byte [r13], ' '
    je   .split
    inc  r13
    jmp  .find_space
.split:
    mov  byte [r13], 0
    inc  r13
.arg_spaces:
    cmp  byte [r13], ' '
    jne  .split_done
    inc  r13
    jmp  .arg_spaces
.split_done:
    mov  rdi, r13
    call strlen
    mov  r15d, eax                         ; argument bytes (audit counts, never copies)

    ; request-scoped authority: the SSH-bound principal, never the console's
    lea  rdi, [rel ssh_exec_ticket]
    xor  esi, esi
    mov  edx, AUTH_T_SIZE
    call memset
    mov  rdi, rbx
    call ssh_auth_command_caps            ; before ticket publication or any handler
    test eax, eax
    jnz  .authority_refused
    mov  r14, rdx
    mov  qword [rel ssh_exec_ticket + AUTH_T_STATE], AUTH_TS_SSH
    mov  rax, [rbx + SSH_C_PID]
    mov  [rel ssh_exec_ticket + AUTH_T_PRINCIPAL], rax
    mov  [rel ssh_exec_ticket + AUTH_T_CAP], r14
    mov  [rel ssh_exec_ticket + AUTH_T_COMMAND], r12
    lea  rdi, [rel ssh_exec_rsp]
    xor  esi, esi
    mov  edx, RSP_SZ
    call memset
    call command_udp_reset_request_state
    lea  rdi, [rel ssh_exec_ticket]
    call command_auth_remote_begin
    mov  byte [rel command_auth_ssh_active], 1
    call principal_current
    mov  [rel ssh_exec_saved_pid], rax
    mov  al, [rel session_locked]
    mov  [rel ssh_exec_saved_locked], al

    mov  rdi, r12
    call command_lookup
    cmp  eax, -1
    je   .unknown
    mov  r14, rax
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .build
    mov  rdi, r12
    call ssh_exec_desktop_verb
    test eax, eax
    jnz  .desktop_locked
.build:
    lea  rdi, [rel ssh_exec_req]
    mov  [rdi + REQ_VERB], r14
    mov  qword [rdi + REQ_CAP], 0
    mov  qword [rdi + REQ_IDEM], 0
    mov  qword [rdi + REQ_SEL], 0
    mov  qword [rdi + REQ_ARG], 0
    mov  qword [rdi + REQ_SOURCE], CMD_SOURCE_SSH
    mov  rax, [rbx + SSH_C_PID]
    mov  [rdi + REQ_PRINCIPAL], rax
    mov  rdi, r14
    call command_verb_argt
    cmp  rax, ARGT_TEXT
    je   .arg_text
    mov  rdi, r13
    call udp_parse_u64
    test edx, edx
    jnz  .badarg
    mov  [rel ssh_exec_req + REQ_ARG], rax
    jmp  .dispatch
.arg_text:
    ; the handler owns a private copy; the echo keeps the raw token
    lea  rdi, [rel ssh_exec_arg]
    mov  rsi, r13
    mov  edx, SSH_EXEC_LINE_CAP
    call strcpy_s
    lea  rax, [rel ssh_exec_arg]
    mov  [rel ssh_exec_req + REQ_ARG], rax
.dispatch:
    lea  rdi, [rel ssh_exec_req]
    lea  rsi, [rel ssh_exec_rsp]
    call command_dispatch                  ; THE single registry entry (census: one call)
    jmp  .capture
.unknown:
    mov  edi, AUTHR_UNKNOWN
    mov  rsi, r12
    lea  rdx, [rel ssh_exec_ticket]
    xor  ecx, ecx
    call command_auth_refuse
    mov  qword [rel ssh_exec_rsp + RSP_CODE], CMDE_NOVERB
    mov  byte [rel ssh_exec_hint_noverb], 1
    jmp  .capture
.desktop_locked:
    mov  edi, AUTHR_DESKTOP_LOCKED
    mov  rsi, r12
    lea  rdx, [rel ssh_exec_ticket]
    xor  ecx, ecx
    call command_auth_refuse
    mov  qword [rel ssh_exec_rsp + RSP_CODE], CMDE_DESKTOP_LOCKED
    jmp  .capture
.badarg:
    mov  qword [rel ssh_exec_rsp + RSP_CODE], CMDE_BADARG
.capture:
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rel ssh_exec_rsp]
    call command_udp_capture_reply
    mov  ecx, edx
    cmp  ecx, SSH_EXEC_OUT_CAP - 160
    jbe  .copy_ok
    mov  ecx, SSH_EXEC_OUT_CAP - 160
.copy_ok:
    mov  [rel ssh_exec_out_len], ecx
    lea  rdi, [rel ssh_exec_out]
    mov  rsi, rax
    mov  edx, ecx
    call memcpy
    ; exit-status from the envelope
    mov  rax, [rel ssh_exec_rsp + RSP_CODE]
    mov  [rel ssh_exec_status], eax
    test eax, eax
    jnz  .status_done
    ; An OK-coded envelope that is itself a refusal receipt still exits 1.
    ; Match the full `AUTH_REFUSED` token: AUTHSTAT / AUTHLOGIN OK / AUTHENROLL
    ; OK replies also begin with `AUTH` and are successes.
    cmp  dword [rel ssh_exec_out_len], 4
    jb   .status_done
    cmp  dword [rel ssh_exec_out], 'ERR '
    je   .status_err
    cmp  dword [rel ssh_exec_out_len], 12
    jb   .status_done
    mov  rax, 'AUTH_REF'
    cmp  [rel ssh_exec_out], rax
    jne  .status_done
    cmp  dword [rel ssh_exec_out + 8], 'USED'
    jne  .status_done
.status_err:
    mov  dword [rel ssh_exec_status], 1
.status_done:
    cmp  byte [rel ssh_exec_hint_noverb], 1
    jne  .reboot_check
    lea  rsi, [rel str_ssh_exec_noverb_hint]
    call ssh_exec_out_append
.reboot_check:
    ; Warm-reset staging is owned by the UDP projection's ack-then-reset path.
    ; An SSH exec must never leave a reset armed for an unrelated later datagram.
    xor  eax, eax
    xchg al, [rel bm_reboot_pending]
    xor  ecx, ecx
    xchg cl, [rel kv_reboot_pending]
    or   al, cl
    jz   .teardown
    lea  rsi, [rel str_ssh_exec_reboot_note]
    call ssh_exec_out_append
    mov  dword [rel ssh_exec_status], CMDE_BADARG
.teardown:
    ; rule 3 audit: capture the network gate's verdict for this exec's row
    ; before the request-scoped refusal state is reset.
    mov  dword [rel ssh_exec_net_res], AUDIT_NRES_ADMIT
    mov  qword [rel ssh_exec_net_reason], 0
    cmp  byte [rel command_auth_refusal_ready], 1
    jne  .teardown_clear
    call net_audit_refusal_meta
    mov  [rel ssh_exec_net_res], eax
    mov  [rel ssh_exec_net_reason], rdx
.teardown_clear:
    mov  byte [rel command_auth_refusal_ready], 0
    mov  byte [rel command_auth_out_ready], 0
    call command_auth_remote_end
    mov  byte [rel command_auth_ssh_active], 0
    ; An explicit owner unlock (or a SESSIONLOCK) is a real session-owner
    ; transition that already set the principal consistently; restore only
    ; when the lock state did not change.
    mov  al, [rel session_locked]
    cmp  al, [rel ssh_exec_saved_locked]
    jne  .audit
    call principal_current
    cmp  rax, [rel ssh_exec_saved_pid]
    je   .audit
    mov  rdi, [rel ssh_exec_saved_pid]
    call principal_restore_active
.audit:
    cmp  dword [rel ssh_exec_status], 0
    je   .audit_put
    inc  qword [rel ssh_exec_refused]
.audit_put:
    mov  rdi, r12
    mov  rsi, [rbx + SSH_C_PID]
    mov  edx, [rel ssh_exec_status]
    mov  ecx, r15d
    mov  r8, [rel ssh_exec_net_reason]
    mov  r9d, [rel ssh_exec_net_res]
    call ssh_auth_audit_exec
    jmp  .out
.authority_refused:
    ; No remote frame was begun, so leave principal/session/scope untouched.
    lea  rsi, [rel str_ssh_exec_key_refused]
    call ssh_exec_out_append
    mov  dword [rel ssh_exec_status], CMDE_AUTHDENY
    inc  qword [rel ssh_exec_refused]
    mov  edi, AUTHR_PRINCIPAL
    call net_audit_reason_name
    mov  r8, rax
    mov  r9d, AUDIT_NRES_REFUSED
    mov  rdi, r12
    mov  rsi, [rbx + SSH_C_PID]
    mov  edx, CMDE_AUTHDENY
    mov  ecx, r15d
    call ssh_auth_audit_exec
    jmp  .out
.empty:
    lea  r12, [rel str_ssh_exec_empty_verb]
    xor  r15d, r15d
    lea  rsi, [rel str_ssh_exec_empty]
    jmp  .local_err
.malformed:
    lea  r12, [rel str_ssh_exec_empty_verb]
    xor  r15d, r15d
    lea  rsi, [rel str_ssh_exec_malformed]
.local_err:
    call ssh_exec_out_append
    mov  dword [rel ssh_exec_status], CMDE_BADARG
    inc  qword [rel ssh_exec_refused]
    mov  edi, AUTHR_MALFORMED
    call net_audit_reason_name
    mov  r8, rax
    mov  r9d, AUDIT_NRES_REFUSED
    mov  rdi, r12
    mov  rsi, [rbx + SSH_C_PID]
    mov  edx, CMDE_BADARG
    mov  ecx, r15d
    call ssh_auth_audit_exec
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Boot KATs: session channel open/refuse/window, exec -> ONE registry
; dispatch (census + content), and capability enforcement against the bound
; principal (a key without the scope is refused before any handler runs).
; ---------------------------------------------------------------------------
ssh_channel_selftest:
    push rbx
    push r12
    push r13
    mov  byte [rel ssh_selftest_mode], 1
    call ssh_channel_kat_authority_begin
    call ssh_channel_kat_ctx
    mov  rbx, rax
    ; OPEN session (sender 7, window 2 MiB, maxpkt 32 KiB)
    lea  rsi, [rel ssh_ch_kat_open]
    mov  edx, SSH_CH_KAT_OPEN_LEN
    call ssh_channel_kat_feed
    test eax, eax
    jnz  .fail
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    jne  .fail
    cmp  dword [rbx + SSH_C_PEER_CHAN], 7
    jne  .fail
    mov  r12d, [rbx + SSH_C_OUTQ_LEN]
    test r12d, r12d
    jz   .fail
    ; a second session is refused (OPEN_FAILURE), the first stays open
    lea  rsi, [rel ssh_ch_kat_open]
    mov  edx, SSH_CH_KAT_OPEN_LEN
    call ssh_channel_kat_feed
    test eax, eax
    jnz  .fail
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    jne  .fail
    cmp  [rbx + SSH_C_OUTQ_LEN], r12d
    jbe  .fail
    ; WINDOW_ADJUST(+16)
    lea  rsi, [rel ssh_ch_kat_adjust]
    mov  edx, SSH_CH_KAT_ADJUST_LEN
    call ssh_channel_kat_feed
    cmp  dword [rbx + SSH_C_PEER_WINDOW], 0x200010
    jne  .fail
    lea  rdi, [rel str_ssh_channel_marker]
    call serial_string

    ; Hold the response at the real queue-pressure boundary. Exec retires its
    ; global scratch immediately; the pending reply belongs to this context.
    ; Inspect that custody before resuming the normal seal/scrub/close path.
    ; exec "PING 4242" -> exactly one dispatch, zero bypass, nonce in stdout
    mov  dword [rbx + SSH_C_OUTQ_LEN], SSH_C_OUTQ_CAP
    mov  r13, [rel cmd_dispatch_count]
    lea  rsi, [rel ssh_ch_kat_exec_ping]
    mov  edx, SSH_CH_KAT_EXEC_PING_LEN
    call ssh_channel_kat_feed
    test eax, eax
    jnz  .fail
    mov  rax, [rel cmd_dispatch_count]
    sub  rax, r13
    cmp  rax, 1
    jne  .fail
    cmp  byte [rel cmd_bypass_flag], 0
    jne  .fail
    cmp  dword [rbx + SSH_C_EXEC_STATUS], 0
    jne  .fail
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    jne  .fail
    mov  eax, [rbx + SSH_C_EXEC_LEN]
    cmp  eax, SSH_EXEC_OUT_CAP
    jae  .fail                         ; reserve the terminator inside this context
    lea  rcx, [rbx + SSH_C_EXEC_REPLY]
    mov  byte [rcx + rax], 0
    mov  rdi, rcx
    lea  rsi, [rel str_ssh_ch_kat_nonce]
    call str_find
    test rax, rax
    jz   .fail
    call ssh_channel_kat_finish_reply
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_ssh_exec_marker]
    call serial_string

    ; capability: a key restricted to public verbs cannot run a MUTATE verb;
    ; the refusal happens before the handler and exit-status is non-zero.
    call ssh_channel_kat_ctx
    mov  rbx, rax
    mov  qword [rbx + SSH_C_CAPMASK], 0
    lea  rsi, [rel ssh_ch_kat_open]
    mov  edx, SSH_CH_KAT_OPEN_LEN
    call ssh_channel_kat_feed
    mov  r13, [rel cmd_handler_runs]
    mov  dword [rbx + SSH_C_OUTQ_LEN], SSH_C_OUTQ_CAP
    lea  rsi, [rel ssh_ch_kat_exec_gated]
    mov  edx, SSH_CH_KAT_EXEC_GATED_LEN
    call ssh_channel_kat_feed
    test eax, eax
    jnz  .fail
    cmp  [rel cmd_handler_runs], r13
    jne  .fail
    cmp  dword [rbx + SSH_C_EXEC_STATUS], 0
    je   .fail
    cmp  dword [rbx + SSH_C_EXEC_REPLY], 'AUTH'
    jne  .fail
    call ssh_channel_kat_finish_reply
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_ssh_capability_marker]
    call serial_string
    xor  eax, eax
    jmp  .done
.fail:
    lea  rdi, [rel str_ssh_channel_kat_fail]
    call serial_string
    mov  eax, -1
.done:
    push rax
    call ssh_channel_kat_authority_end
    call ssh_contexts_base
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    mov  qword [rel ssh_exec_count], 0
    mov  qword [rel ssh_exec_refused], 0
    mov  byte [rel ssh_selftest_mode], 0
    pop  rax
    pop  r13
    pop  r12
    pop  rbx
    ret

; RBX = private KAT context with a reply held by queue pressure. Retire the
; synthetic full queue, resume the actual response writer, then require the
; terminal state and zero plaintext custody. No live queue is touched here.
ssh_channel_kat_finish_reply:
    cmp  dword [rel ssh_exec_out_len], 0
    jne  .bad
    cmp  dword [rel ssh_exec_status], 0
    jne  .bad
    cmp  byte [rbx + SSH_C_EXEC_PHASE], 1
    jne  .bad
    mov  dword [rbx + SSH_C_OUTQ_LEN], 0
    mov  rdi, rbx
    call ssh_exec_response_step
    cmp  eax, 1
    jne  .bad
    cmp  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_CLOSE_SENT
    jne  .bad
    cmp  byte [rbx + SSH_C_EXEC_PHASE], 0
    jne  .bad
    cmp  dword [rbx + SSH_C_OUTQ_LEN], 0
    je   .bad
    lea  rdi, [rbx + SSH_C_EXEC_REPLY]
    mov  ecx, SSH_EXEC_OUT_CAP
    xor  eax, eax
    repe scasb
    jne  .bad
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; ssh_secret_scrub_kat -> RAX=0 clean, else the name of the first buffer that
; still holds the synthetic credential (w045 [auth.secret.scrub.kat], driven
; by command_udp_secret_scrub_kat). Each case seals ONE RFC5647 exec packet
; with the connection's own AEAD (ssh_queue_gcm), feeds it back as received
; ciphertext and runs the real ssh_process_one: decrypt into PLAIN -> exec ->
; ssh_exec_line/arg -> THE registry -> reply sealed into OUTQ. The TCB is a
; private stand-in whose busy TX slot keeps every reply queued (no wire).
;   case 1  owner key, unrestricted: AUTHLOGIN <cred> nonce=zz -- the handler
;           runs and refuses the malformed nonce BEFORE any bind (no hammer,
;           no audit, no session change)
;   case 2  key with no capabilities: AUTHLOGIN <cred> -- refused before any
;           handler, so only the transport scrub can remove the copies
; ---------------------------------------------------------------------------
ssh_secret_scrub_kat:
    push rbx
    push r12
    push r13
    mov  rax, [rel ssh_exec_count]
    mov  [rel sscrub_ssh_saved_count], rax
    mov  rax, [rel ssh_exec_refused]
    mov  [rel sscrub_ssh_saved_refused], rax
    mov  byte [rel ssh_selftest_mode], 1      ; deterministic padding, no audit records
    call ssh_channel_kat_authority_begin
    mov  rdi, -1
    lea  rsi, [rel str_sscrub_ssh_nonce]
    call ssh_sscrub_case
    test rax, rax
    jnz  .done
    xor  edi, edi
    lea  rsi, [rel str_sscrub_ssh_end]
    call ssh_sscrub_case
.done:
    push rax
    call ssh_channel_kat_authority_end
    call ssh_contexts_base
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    lea  rdi, [rel sscrub_ssh_payload]
    xor  esi, esi
    mov  edx, SSCRUB_SSH_PAYLOAD_CAP
    call memset
    mov  rax, [rel sscrub_ssh_saved_count]
    mov  [rel ssh_exec_count], rax
    mov  rax, [rel sscrub_ssh_saved_refused]
    mov  [rel ssh_exec_refused], rax
    mov  byte [rel ssh_selftest_mode], 0
    pop  rax
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=capability mask, RSI=cstr suffix after the credential -> RAX 0 / name.
ssh_sscrub_case:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call ssh_channel_kat_ctx
    mov  rbx, rax
    test rax, rax
    jz   .not_run
    mov  [rbx + SSH_C_CAPMASK], r12
    mov  byte [rbx + SSH_C_CHAN_STATE], SSH_CH_OPEN
    mov  dword [rbx + SSH_C_PEER_CHAN], 7
    mov  dword [rbx + SSH_C_PEER_WINDOW], 0x200000
    mov  dword [rbx + SSH_C_PEER_MAXPKT], 0x8000
    lea  rax, [rel sscrub_ssh_tcb]
    mov  [rbx + SSH_C_TCB], rax
    mov  dword [rax + TCB_TX_LEN], 1          ; a flight is "in progress": replies stay queued
    ; CHANNEL_REQUEST(recipient 0, "exec", want_reply=1, command)
    lea  rdi, [rel sscrub_ssh_payload]
    lea  rsi, [rel ssh_sscrub_exec_head]
    mov  edx, SSH_SSCRUB_EXEC_HEAD_LEN
    call memcpy
    lea  rdi, [rel sscrub_ssh_payload + SSH_SSCRUB_EXEC_HEAD_LEN + 4]
    lea  rsi, [rel str_sscrub_authlogin]
    mov  edx, 10
    call memcpy
    lea  rdi, [rel sscrub_ssh_payload + SSH_SSCRUB_EXEC_HEAD_LEN + 4 + 10]
    lea  rsi, [rel sscrub_marker]
    mov  edx, SSCRUB_MARKER_LEN
    call memcpy
    lea  rdi, [rel sscrub_ssh_payload + SSH_SSCRUB_EXEC_HEAD_LEN + 4 + 10 + SSCRUB_MARKER_LEN]
    mov  ecx, 10 + SSCRUB_MARKER_LEN          ; command length so far
.suffix:
    mov  al, [r13]
    test al, al
    jz   .suffix_done
    mov  [rdi], al
    inc  rdi
    inc  r13
    inc  ecx
    jmp  .suffix
.suffix_done:
    mov  eax, ecx
    bswap eax
    mov  [rel sscrub_ssh_payload + SSH_SSCRUB_EXEC_HEAD_LEN], eax
    lea  edx, [ecx + SSH_SSCRUB_EXEC_HEAD_LEN + 4]
    ; seal with the S2C direction, then present it as the next C2S record
    ; (both directions start from the same zero key/IV in the zeroed context)
    mov  rdi, rbx
    lea  rsi, [rel sscrub_ssh_payload]
    call ssh_queue_gcm
    test eax, eax
    jnz  .not_run
    lea  rdi, [rel sscrub_ssh_payload]
    xor  esi, esi
    mov  edx, SSCRUB_SSH_PAYLOAD_CAP
    call memset
    mov  edx, [rbx + SSH_C_OUTQ_LEN]
    mov  [rbx + SSH_C_RX_LEN], edx
    lea  rdi, [rbx + SSH_C_RX]
    lea  rsi, [rbx + SSH_C_OUTQ]
    call memcpy
    mov  dword [rbx + SSH_C_OUTQ_LEN], 0
    mov  r12, [rel ssh_exec_count]
    mov  rdi, rbx
    call ssh_process_one
    cmp  eax, 1
    jne  .not_run
    mov  rax, [rel ssh_exec_count]
    sub  rax, r12
    cmp  rax, 1
    jne  .not_run                             ; the exec never reached the registry path
%macro SSH_SSCRUB_CHECK 3
    lea  rdi, %1
    mov  esi, %2
    call command_udp_scrub_scan
    lea  rdx, [rel %3]
    test eax, eax
    jnz  .hit
%endmacro
    SSH_SSCRUB_CHECK [rbx + SSH_C_PLAIN], SSH_C_PLAIN_CAP, str_sscrub_n_plain
    SSH_SSCRUB_CHECK [rbx + SSH_C_OUT], SSH_C_OUT_CAP, str_sscrub_n_out
    SSH_SSCRUB_CHECK [rbx + SSH_C_RX], SSH_C_RX_CAP, str_sscrub_n_rx
    SSH_SSCRUB_CHECK [rbx + SSH_C_OUTQ], SSH_C_OUTQ_CAP, str_sscrub_n_outq
    SSH_SSCRUB_CHECK [rel ssh_exec_line], SSH_EXEC_LINE_CAP, str_sscrub_n_exec_line
    SSH_SSCRUB_CHECK [rel ssh_exec_arg], SSH_EXEC_LINE_CAP, str_sscrub_n_exec_arg
    SSH_SSCRUB_CHECK [rel ssh_exec_out], SSH_EXEC_OUT_CAP, str_sscrub_n_exec_out
    SSH_SSCRUB_CHECK [rel ssh_ch_pkt], SSH_CH_PKT_CAP, str_sscrub_n_ch_pkt
%unmacro SSH_SSCRUB_CHECK 3
    call command_udp_scrub_scan_common        ; shared line/verifier/audit buffers
    jmp  .out
.hit:
    mov  rax, rdx
    jmp  .out
.not_run:
    lea  rax, [rel str_sscrub_n_ssh_ran]
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; These existing fabricated channel contexts now use a genuinely enrolled
; public fixture key. Save/restore the serialized live store; never bypass the
; new admission check or touch firmware. Only the two boot KATs call this pair.
ssh_channel_kat_authority_begin:
    sub  rsp, 8
    mov  al, [rel ssh_keys_state]
    mov  [rel ssh_ch_kat_keys_state], al
    lea  rdi, [rel ssh_ch_kat_keys_saved]
    lea  rsi, [rel ssh_keys_record]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    lea  rdi, [rel ssh_ch_kat_stage_saved]
    lea  rsi, [rel ssh_keys_stage]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    lea  rdi, [rel ssh_keys_stage]
    xor  esi, esi
    mov  edx, SSHK_REC_SIZE
    call memset
    lea  rdi, [rel ssh_keys_stage + SSHK_REC_ENTRIES]
    lea  rsi, [rel ssh_transport_kat_host_public]
    mov  edx, 32
    call memcpy
    mov  qword [rel ssh_keys_stage + SSHK_REC_ENTRIES + SSHK_ENT_CAPS], -1
    mov  dword [rel ssh_keys_stage + SSHK_REC_ENTRIES + SSHK_ENT_FLAGS], 1
    mov  byte [rel ssh_keys_state], SSHK_ST_RAM
    call ssh_keystore_commit_stage
    add  rsp, 8
    ret

ssh_channel_kat_authority_end:
    sub  rsp, 8
    lea  rdi, [rel ssh_keys_record]
    lea  rsi, [rel ssh_ch_kat_keys_saved]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    lea  rdi, [rel ssh_keys_stage]
    lea  rsi, [rel ssh_ch_kat_stage_saved]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    mov  al, [rel ssh_ch_kat_keys_state]
    mov  [rel ssh_keys_state], al
    add  rsp, 8
    ret

ssh_channel_kat_ctx:
    call ssh_contexts_base
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    call ssh_contexts_base
    mov  byte [rax + SSH_C_STATE], SSH_STATE_CONNECTION
    mov  qword [rax + SSH_C_PID], PRIN_OWNER
    mov  qword [rax + SSH_C_CAPMASK], -1
    push rax
    lea  rdi, [rax + SSH_C_AUTH_PUB]
    lea  rsi, [rel ssh_transport_kat_host_public]
    mov  edx, 32
    call memcpy
    pop  rax
    mov  byte [rax + SSH_C_AUTH_BOUND], 1
    ret

; RSI=fixture, EDX=len: copy into ctx PLAIN+1 (where the wire parser leaves
; a decrypted payload) and run the connection-layer handler on slot 0.
ssh_channel_kat_feed:
    push rbx
    push r12
    mov  r12d, edx
    call ssh_contexts_base
    mov  rbx, rax
    lea  rdi, [rbx + SSH_C_PLAIN + 1]
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_PLAIN + 1]
    mov  edx, r12d
    call ssh_connection_packet
    pop  r12
    pop  rbx
    ret

; ---- data -------------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_ssh_channel_0 0
align 8
times 8 db 0                  ; ssh_exec_net_reason..sscrub_ssh_payload moved to WDATA_svc_ssh_channel_0_bss1: keeps the labels below at their offset mod 64

ssh_exec_desktop_names:
    ; AUTHLOGIN left this list with the remote-unlock split: it is the explicit
    ; owner unlock, admitted for an unrestricted OWNER key and audited.
    db "KBINJ",0,"MOUSEINJ",0,"PTRINJ",0,0

ssh_sscrub_exec_head:                    ; CHANNEL_REQUEST 0 "exec" want_reply=1 ; then u32 len + command
    db SSH_MSG_CHANNEL_REQUEST
    dd 0
    dd 0x04000000
    db "exec"
    db 1
SSH_SSCRUB_EXEC_HEAD_LEN equ $ - ssh_sscrub_exec_head
str_sscrub_ssh_nonce:   db " nonce=zz",0
str_sscrub_ssh_end:     db 0
str_sscrub_n_ssh_ran:   db "ssh_path_not_exercised",0
str_sscrub_n_plain:     db "ssh_ctx_plain",0
str_sscrub_n_out:       db "ssh_ctx_out",0
str_sscrub_n_rx:        db "ssh_ctx_rx",0
str_sscrub_n_outq:      db "ssh_ctx_outq",0
str_sscrub_n_exec_line: db "ssh_exec_line",0
str_sscrub_n_exec_arg:  db "ssh_exec_arg",0
str_sscrub_n_exec_out:  db "ssh_exec_out",0
str_sscrub_n_ch_pkt:    db "ssh_ch_pkt",0
ssh_ch_kat_open:
    db SSH_MSG_CHANNEL_OPEN
    dd 0x07000000
    db "session"
    dd 0x07000000                       ; sender channel 7
    dd 0x00002000                       ; initial window 0x200000
    dd 0x00800000                       ; max packet 0x8000
SSH_CH_KAT_OPEN_LEN equ $ - ssh_ch_kat_open
ssh_ch_kat_adjust:
    db SSH_MSG_CHANNEL_WINDOW_ADJUST
    dd 0
    dd 0x10000000
SSH_CH_KAT_ADJUST_LEN equ $ - ssh_ch_kat_adjust
ssh_ch_kat_exec_ping:
    db SSH_MSG_CHANNEL_REQUEST
    dd 0
    dd 0x04000000
    db "exec"
    db 1
    dd 0x0a000000
    db "/PING 4242"
SSH_CH_KAT_EXEC_PING_LEN equ $ - ssh_ch_kat_exec_ping
ssh_ch_kat_exec_gated:
    db SSH_MSG_CHANNEL_REQUEST
    dd 0
    dd 0x04000000
    db "exec"
    db 1
    dd 0x0b000000
    db "SSHKEYADD x"
SSH_CH_KAT_EXEC_GATED_LEN equ $ - ssh_ch_kat_exec_gated

str_ssh_ch_session:     db "session"
str_ssh_ch_exec:        db "exec"
str_ssh_ch_env:         db "env"
str_ssh_ch_exit_status: db "exit-status"
str_ssh_ch_kat_nonce:   db "4242",0
str_ssh_exec_key_refused: db "ERR SSH exec refused=authenticated_key_no_longer_authorized",13,10,0
str_ssh_exec_empty_verb: db "-",0
str_ssh_exec_empty:     db "ERR SSH exec expected='<VERB> [args]' hint=CATALOG",13,10,0
str_ssh_exec_malformed: db "ERR SSH exec line_too_long_or_nul max=1023",13,10,0
str_ssh_exec_noverb_hint: db "ERR code=unknown_verb expected=registered_verb hint=CATALOG",13,10,0
str_ssh_exec_reboot_note: db "ERR ssh reboot_not_performed hint='warm reset is UDP-ack-owned; use the UDP projection'",13,10,0
str_ssh_channel_marker: db "[PAOS64] SSH rung 3: RFC 4254 session channel open/close + window handling selftest [ssh.channel.session]",13,10,0
str_ssh_exec_marker:    db "[PAOS64] SSH rung 3: exec -> ONE registry dispatch (ssh STATUS == udp STATUS) single-dispatch census [ssh.exec.dispatch]",13,10,0
str_ssh_capability_marker: db "[PAOS64] SSH rung 3: gated verb over SSH enforces principal capability + exit-status from envelope [ssh.exec.capability]",13,10,0
str_ssh_channel_kat_fail: db "[PAOS64] SSH rung 3: channel/exec selftest FAIL [ssh.channel.fail]",13,10,0
%endmacro
WDATA_DEFER WDATA_svc_ssh_channel_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_ssh_channel_0_bss1 0
alignb 8
ssh_exec_net_reason: resq 1              ; rule 3: gate refusal reason for this exec's audit row
ssh_exec_net_res:    resd 1
alignb 8
ssh_w_cur:            resq 1
ssh_ch_req_type:      resq 1
ssh_exec_saved_pid:   resq 1
ssh_exec_status:      resd 1
ssh_exec_out_len:     resd 1
ssh_ch_sender:        resd 1
ssh_ch_window:        resd 1
ssh_ch_maxpkt:        resd 1
ssh_ch_reason:        resd 1
ssh_ch_chunk:         resd 1
ssh_ch_req_type_len:  resd 1
ssh_ch_want_reply:    resb 1
ssh_ch_onebyte:       resb 1
ssh_exec_too_long:    resb 1
ssh_exec_hint_noverb: resb 1
ssh_exec_note_reboot: resb 1
ssh_exec_saved_locked: resb 1
alignb 8
ssh_ch_kat_keys_state: resb 1
ssh_ch_kat_keys_saved: resb SSHK_REC_SIZE
ssh_ch_kat_stage_saved: resb SSHK_REC_SIZE
alignb 8
ssh_exec_ticket:      resb AUTH_T_SIZE
ssh_exec_req:         resb REQ_SZ
ssh_exec_rsp:         resb RSP_SZ
ssh_ch_pkt:           resb SSH_CH_PKT_CAP
ssh_exec_line:        resb SSH_EXEC_LINE_CAP
ssh_exec_arg:         resb SSH_EXEC_LINE_CAP
ssh_exec_out:         resb SSH_EXEC_OUT_CAP + 8
; w045 [auth.secret.scrub.kat] scratch (wiped after use)
alignb 8
sscrub_ssh_saved_count:   resq 1
sscrub_ssh_saved_refused: resq 1
sscrub_ssh_tcb:           resb TCP_TCB_SIZE
sscrub_ssh_payload:       resb SSCRUB_SSH_PAYLOAD_CAP
%endmacro
WDATA_BSS_DEFER WDATA_svc_ssh_channel_0_bss1
