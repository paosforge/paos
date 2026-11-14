;; MODULE svc/ssh_client
;; LAYER 5
;; EXPORTS ssh_session_bind_deadlines, ssh_cli_fault_owner, ssh_cli_fault_status, ssh_cli_fault_arm, ssh_cli_fault_retire, ssh_cli_replace_host, ssh_cli_profile_snapshot, ssh_cli_trust_host, ssh_cli_known_hosts_clear, ssh_cli_identity_enroll, ssh_session_begin, ssh_session_use, ssh_session_end, ssh_sessions_poll, ssh_sess_active, ssh_client_connect_start, ssh_client_disconnect, ssh_cli_poll, ssh_cli_state, ssh_cli_error, ssh_cli_chan_ready, ssh_cli_chan_closed, ssh_cli_data_sink, ssh_cli_enqueue_input, ssh_cli_send_window_change, ssh_cli_target_ip, ssh_cli_term_cols, ssh_cli_term_rows, ssh_cli_txq_len, ssh_cli_identity_text, ssh_cli_exit_kind, ssh_cli_exit_status, ssh_cli_exit_core, ssh_cli_exit_signal_len, ssh_cli_exit_message_len, ssh_cli_exit_language_len, ssh_cli_exit_signal, ssh_cli_exit_message, ssh_cli_exit_language, ssh_cli_request_failures, ssh_cli_want_close, ssh_cli_exec_configure, ssh_cli_is_exec, ssh_cli_exec_pending, ssh_cli_exec_configure_stream, ssh_cli_exec_handle, ssh_cli_exec_stdin, ssh_cli_exec_close_stdin, ssh_cli_exec_signal, ssh_cli_exec_status, ssh_cli_exec_cancel
;; IMPORTS svc/command, svc/command_auth, svc/ssh, net/tcp, net/arp_cache, core/csprng, core/heap, core/time, core/lib/mem, core/lib/sha256, core/lib/hmac_sha256, core/lib/hkdf_sha256, core/lib/x25519, core/lib/ed25519, core/lib/ssh_crypto_work, core/lib/aes256_gcm, sec/principal, fs/storage_access, boot/nvram_access, boot/boot_v2_health, boot/header, boot/serial
;; CAPS PMCAP_NET
;; OWNER saga:ssh_client
; ============================================================================
; svc/ssh_client — the outbound SSH CLIENT behind the Terminal's `ssh` command
; (hub packet 0014: the MSI spoke's Task3494 client, ported as its own module;
; svc/ssh.asm, the hub's server, is unchanged).
;
;   ssh USER@A.B.C.D[:PORT]        (in a Terminal; PORT defaults to 22)
;
; RFC 4253 transport (curve25519-sha256, ssh-ed25519 host key, aes256-gcm@
; openssh.com), RFC 4252 publickey userauth (ssh-ed25519), and one RFC 4254
; `session` channel with pty-req (xterm-256color) + shell, window-change,
; flow-control windows and keepalives. The primitives are the server's own
; (svc/ssh.asm: ssh_derive_keys, ssh_packet_clear_build, the exchange-hash
; buffer, ssh_rx_consume, the GCM request; core/lib: x25519, ed25519,
; aes256_gcm; sha256_hash), byte-identical to the spoke's. The client offers
; exactly the server's algorithm set (ssh_kex_suffix).
;
; What differs from the spoke's client (paos_msi svc/ssh.asm 2107..4644):
; * No embedded client key. The spoke carried one ed25519 seed that one host
;   authorizes; the hub image carries none. SSHCLIKEY shows the client key's
;   authorized_keys line (only the public line ever leaves PaOS).
;   Without an authenticated stored identity, inspection and authentication
;   refuse; neither silently creates a temporary key. The owner's explicit
;   SSHCLIKEY ENROLL creates the persistent identity. The seed is HKDF(machine
;   secret, "PaOS/SSH/client-identity/v1" ||
;   be32(generation)), derived just before each signature and wiped after it;
;   no secret is stored. PaOSSshClientId (the known_hosts variable pattern:
;   NV|BS|RT, storage gate, one SetVariable, exact readback) holds only the
;   generation and the public key, MACed with HKDF(machine secret,
;   "PaOS/SSH/client-id-record/v1"). At the first ssh use of a boot the record
;   is checked and the key re-derived; a record that is malformed, not
;   authentic, or names another key (the machine secret changed: a reinstall)
;   is refused, never replaced by a silent new key, and ssh is refused until
;   the owner enrolls again. SSHCLIKEY RESET steps the generation (a new key).
;   Only an owner session signs with the client key (ssh_cli_owner_armed: the
;   Terminal's GA0-K gated ssh builtin); SYSTEM and the AI never do.
; * No QEMU autodial and no default host: a session starts only from `ssh`.
; * Host keys: the server's signature over H proves it holds the key in K_S,
;   but that key is not trusted until owner-signed SSHKHTRUST provisions the
;   endpoint/fingerprint. Unknown hosts stop before USERAUTH; the Terminal shows
;   the public fingerprint and explicit provisioning instructions. A changed key on
;   the same address:port is refused (error 15). Pins are never evicted; a full
;   table refuses new hosts (c19630bda).
; * known_hosts (RCQ-07b): a pin whose endpoint completed USERAUTH_SUCCESS is
;   saved in the dedicated UEFI variable PaOSSshKnownHosts (SSH PaOS vendor
;   GUID, NV|BS|RT, NV_CLASS_PAOS through the storage gate), HMAC-SHA256 keyed
;   HKDF(machine secret, "PaOS/SSH/known_hosts/v1"). It is loaded once, at the
;   first ssh use of a boot. A record that is malformed or not authentic loads
;   no pins and refuses new trust/authentication until the owner clears it
;   (SSHKHCLEAR). An uncertain save revokes future trust, with
;   no automatic retry. Never the kvstore: its one 35-byte DATA slot belongs to the owner.
; * The hub's TCP client API (net/tcp.asm, unchanged here) takes the local
;   port from the caller, records no open error or end reason, and idle-reaps
;   any tuple after TCP_IDLE_MS (60 s). So: ssh_cli_pick_port steps through
;   49152..65535 from a per-boot random start; failures are classified here
;   (stack down / no ARP entry / could not open; refused before the handshake,
;   lost after it); keepalives every 15 s keep an idle session inside the
;   reaper's 60 s. Proposal 0014a lists the spoke's TCP client lifecycle fixes
;   (end reasons, SYN retransmit, RTO backoff, client idle exemption).
; * A session owns its TCP tuple by the local port it opened with
;   (ssh_cli_lport): a freed TCB slot reused by another connection is never
;   closed, aborted or written to by the session that used it before.
; * State layout: the per-session SSH context (SSH_CTX_SIZE), the server's
;   KEXINIT (I_S) and the input ring live in one zeroed heap slot per session
;   (core/abi/heap_once.inc: no image bytes); the swapped region holds only
;   the small per-session fields, and scratch buffers are shared (every caller
;   is serialized on the idle loop: tcp_poll's callbacks and terminal_app_tick).
;
; Sessions: up to SSH_SESS_MAX at once, one per Terminal window. A session's
; fields live in the region at fixed labels; ssh_session_use swaps a session in
; (parking the one before). TCP callbacks route by TCB + local port.
; terminal_app_tick drives ssh_sessions_poll.
; ============================================================================
%define PAOS_TERMINAL_SSH 1             ; gui/terminal_app.asm: the ssh command is live
%include "core/abi/wdata.inc"
%include "core/abi/heap_once.inc"

; OpenSSH's server KEXINIT payload (I_S for the exchange hash) is far larger than
; the 512-byte shared SSH_C_IS field, so the client keeps its own bounded buffer.
SSH_CLI_IS_CAP          equ 4096
SSH_CLI_ST_IDLE         equ 0
SSH_CLI_ST_TCP          equ 1
SSH_CLI_ST_WAIT_BANNER  equ 2
SSH_CLI_ST_WAIT_KEXINIT equ 3
SSH_CLI_ST_GOT_KEXINIT  equ 4
SSH_CLI_ST_SENT_ECDH    equ 5      ; sent KEX_ECDH_INIT, awaiting KEX_ECDH_REPLY
SSH_CLI_ST_WAIT_NEWKEYS equ 6      ; verified + keys derived + our NEWKEYS sent
SSH_CLI_ST_ENC          equ 7      ; encrypted transport up; SERVICE_REQUEST sent
SSH_CLI_ST_SVC_OK       equ 8      ; SERVICE_ACCEPT decrypted over the real GCM seam
SSH_CLI_ST_FAILED       equ 9
SSH_CLI_ST_AUTHED       equ 11     ; USERAUTH_SUCCESS (publickey) over the encrypted seam
SSH_CLI_ST_CH_OPEN_SENT equ 12     ; CHANNEL_OPEN("session") sent, awaiting CONFIRM
SSH_CLI_ST_CH_OPEN      equ 13     ; channel confirmed; pty-req/shell pending
SSH_CLI_ST_SHELL        equ 14     ; peer acknowledged shell; interactive input may flow
SSH_CLI_ST_EXEC         equ 15     ; acknowledged no-PTY exec; stdin is closed
SSH_CLI_REQ_EXEC        equ 3
SSH_CLI_REQ_NONE        equ 0
SSH_CLI_REQ_PTY         equ 1
SSH_CLI_REQ_SHELL       equ 2
; ssh_cli_error: 1 bad target, 2 could not open, 3 KEX send, 4 KEX reply bad,
; 5 entropy, 6 transport lost on a send, 7 inbound packet failed to open,
; 8 DISCONNECT, 9 publickey refused, 10 refused (reset before the handshake),
; 13 connection lost, 15 the host key changed (refused), 16 the client key
; signs only in an owner session (refused), 17 the client identity is not
; verified (refused until the owner enrolls again), 18 channel protocol violation,
; 19 PTY request refused, 20 shell request refused, 21 transport rekey failed

; Interactive channel window bookkeeping (RFC4254). We advertise the local
; window and top the server back up whenever it drains below the low-water mark.
; 2026-09-29 (catalogue SSH-04): 64 KiB, not 1 MiB. Everything the server may
; still send after Ctrl+C is this window; at the Terminal's flood rate 1 MiB
; took ~12 s to drain before the prompt came back. The 4-KiB TCP receive window
; bounds throughput long before 64 KiB does.
SSH_CH_INIT_WINDOW      equ 65536
; Task3499: the largest CHANNEL_DATA payload the server may send. Every inbound
; packet must fit SSH_C_PLAIN_CAP (1460) once decrypted, so data <= 1400 keeps
; packet_length = data + 9 + 1 + padding(<=19) inside it. At 16384 a burst
; (a full-screen Claude Code repaint) arrived as one >1460-byte packet that
; ssh_cli_gcm_read refused as bad, and the transport died [ssh.cli.encfail].
SSH_CH_MAX_PACKET       equ 1400
SSH_EXIT_SIGNAL_CAP     equ 64
SSH_EXIT_MESSAGE_CAP    equ 160
SSH_EXIT_LANGUAGE_CAP   equ 32
SSH_REQUEST_FAILURE_CAP equ 32         ; identical ordered replies, bounded per session
SSH_CH_LOW_WATER        equ 32768
SSH_TXQ_CAP             equ 1024        ; interactive input ring (power of two)
SSH_KA_INTERVAL_US      equ 15000000    ; monotonic time; also keeps the hub TCP idle reaper (60 s) away

; 2026-09-29 (Peter eval 3: only ONE ssh session could exist): up to
; SSH_SESS_MAX independent sessions.
SSH_SESS_MAX            equ 6
SSH_SESS_POLL_US        equ 1000        ; a parked session is polled at least this often
SSH_SESS_DRAIN_US       equ 3000000     ; an ended session lets its CHANNEL_CLOSE leave for up to 3 s

; One zeroed heap slot per session: its SSH context, the server's KEXINIT, its input ring.
SSH_CLI_SLOT_IS         equ SSH_CTX_SIZE
SSH_CLI_SLOT_TXQ        equ SSH_CLI_SLOT_IS + SSH_CLI_IS_CAP
SSH_CLI_SLOT_RK         equ (SSH_CLI_SLOT_TXQ + SSH_TXQ_CAP + 15) & ~15
SSH_CLI_SLOT_EXEC       equ (SSH_CLI_SLOT_RK + SSH_CLI_RK_SIZE + SSH_CLI_RK_PLAIN_CAP + 15) & ~15
SSH_CLI_SLOT_SIZE       equ (SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SIZE + 15) & ~15

; Local ports for outbound connections: 49152 + (0..16383).
SSH_CLI_PORT_BASE       equ 49152
SSH_CLI_PORT_SPAN       equ 16384

; Host keys pinned (endpoint -> SHA256 of K_S); never evicted.
SSH_CLI_PINS            equ 32          ; static, never evicted within a boot
SSH_CLI_PIN_SZ          equ 44          ; dd ip,dw port,db used,db claim(0 unconfirmed,1 saved,2 boot-confirmed),digest32,dd first-gen
; RCQ-07b known_hosts record (PaOSSshKnownHosts). Entries share the pin layout,
; with +6 = key type (1 ssh-ed25519) and +7 = valid (1) instead of used/saved.
SSH_KH_MAGIC            equ 0x31484B50  ; "PKH1"
SSH_KH_VERSION          equ 1
SSH_KH_REC_COUNT        equ 8           ; dd valid entries
SSH_KH_REC_GEN          equ 12          ; dd generation: +1 per saved table
SSH_KH_REC_ENTRIES      equ 16
SSH_KH_REC_MAC          equ SSH_KH_REC_ENTRIES + SSH_CLI_PINS * SSH_CLI_PIN_SZ
SSH_KH_REC_SIZE         equ SSH_KH_REC_MAC + 32
SSH_KH_KEY_ED25519      equ 1
SSH_KH_ST_UNLOADED      equ 0           ; not read yet this boot
SSH_KH_ST_NVRAM         equ 1           ; loaded (or absent): pins are saved after login
SSH_KH_ST_BOOT          equ 2           ; no runtime services: boot-only pins, as before
SSH_KH_ST_POISONED      equ 3           ; malformed / not authentic: fail closed until the owner clears it
SSH_KH_ST_UNCERTAIN     equ 5           ; issued mutation: no future host trust until owner disposition
SSH_KH_ST_NOKEY         equ 4           ; no machine secret: boot-only pins, warned
SSH_KH_EFI_NOT_FOUND    equ 0x800000000000000E
%if SSH_KH_REC_SIZE > 2048
    %error "PaOSSshKnownHosts must stay within 2 KiB"
%endif
; RCQ-08 client identity record (PaOSSshClientId): public, MACed, no secret.
SSH_CID_MAGIC           equ 0x31444950  ; "PID1"
SSH_CID_VERSION         equ 1
SSH_CID_REC_GEN         equ 8           ; dd generation (>= 1): the seed's HKDF info suffix
SSH_CID_REC_ENROLLED    equ 12          ; dd 1
SSH_CID_REC_PUB         equ 16          ; the ed25519 public key of that generation
SSH_CID_REC_MAC         equ 48          ; HMAC-SHA256(record key, record[0:48])
SSH_CID_REC_SIZE        equ 80
SSH_CID_ST_UNLOADED     equ 0           ; not read yet this boot
SSH_CID_ST_NONE         equ 1           ; no record: this boot's random key, unenrolled
SSH_CID_ST_ENROLLED     equ 2           ; verified record: the derived key
SSH_CID_ST_UNVERIFIED   equ 3           ; no admission until authenticated reload/owner repair
SSH_CID_ST_BOOT         equ 4           ; no runtime services: identity unavailable

; "ssh-ed25519 " + base64(51-byte public key blob: 68 chars) + " paos-client"
SSH_CLI_ID_TEXT_LEN     equ 12 + 68 + 12

%include "svc/ssh_profile_fault_lifecycle.inc"

; The expected prefixes of an ssh-ed25519 public key blob (32-byte key) and
; signature blob (64-byte signature): string("ssh-ed25519") || uint32 length.
%macro SSHCLI_ED25519_PREFIX 1
    db 0, 0, 0, 11, "ssh-ed25519", 0, 0, 0, %1
%endmacro


; Bounded duration custody: RDI -> {remaining_us, last_sample_us}, RAX=now.
; Zero means unavailable. First/repeated/backward samples earn no duration;
; zero invalidates the baseline, and a backward sample rebases it. Saturate
; at expiry without adding an absolute deadline (including near U64_MAX).
; RAX=remaining, EDX=1 only for a usable forward sample; clobbers RCX.
ssh_cli_timer_step:
    mov  rcx, [rdi]
    mov  rdx, [rdi + 8]
    mov  [rdi + 8], rax
    test rax, rax
    jz   .no_elapsed
    test rdx, rdx
    jz   .no_elapsed
    cmp  rax, rdx
    jbe  .no_elapsed
    sub  rax, rdx
    cmp  rax, rcx
    jae  .expired
    sub  rcx, rax
    mov  [rdi], rcx
    mov  rax, rcx
    mov  edx, 1
    ret
.expired:
    mov  qword [rdi], 0
    xor  eax, eax
    mov  edx, 1
    ret
.no_elapsed:
    mov  rax, rcx
    xor  edx, edx
    ret

; Traffic restarts only this session's idle interval, never another session's.
ssh_cli_rearm_keepalive:
    call time_monotonic_now_us
    mov  qword [rel ssh_cli_ka_left], SSH_KA_INTERVAL_US
    mov  [rel ssh_cli_ka_last], rax
    ret

; One bounded control drain per lifecycle. Duplicate CLOSE/detach cannot renew
; its authority or duration, even after elapsed budget reaches zero.
ssh_cli_arm_control:
    cmp  byte [rel ssh_cli_control_armed], 0
    jne  .out
    mov  byte [rel ssh_cli_control_armed], 1
    call time_monotonic_now_us
    mov  qword [rel ssh_cli_control_left], SSH_SESS_DRAIN_US
    mov  [rel ssh_cli_control_last], rax
.out:
    ret

; Build the client KEXINIT into ssh_cli_ctx SSH_C_IC (msg byte + 16 cookie + shared name-lists).
ssh_cli_build_kexinit:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  byte [rbx + SSH_C_IC], SSH_MSG_KEXINIT
    lea  rdi, [rbx + SSH_C_IC + 1]
    mov  esi, 16
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_IC + 17]
    lea  rsi, [rel ssh_kex_suffix]
    mov  edx, SSH_KEX_SUFFIX_LEN
    call memcpy
    mov  dword [rbx + SSH_C_IC_LEN], SSH_KEX_PAYLOAD_LEN
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret

; RDI = "USER@A.B.C.D[:PORT]" (PORT 22 when omitted), or the spoke's older
; "A.B.C.D:PORT USER". -> EAX = wire IPv4 (-1: malformed), EDX = port. The user
; (1..62 bytes) is copied to ssh_cli_user. A user is required: PaOS has no
; local user name to default to. IPv4 only (no resolver yet).
ssh_cli_parse_arg:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    test r12, r12
    jz   .bad
    mov  dword [rel ssh_cli_user_len], 0
    mov  byte [rel ssh_cli_user], 0
    xor  ecx, ecx
.at_scan:                               ; USER@ ends before the first blank
    mov  al, [r12 + rcx]
    test al, al
    jz   .no_at
    cmp  al, ' '
    je   .no_at
    cmp  al, '@'
    je   .at
    inc  ecx
    cmp  ecx, 63
    jb   .at_scan
    jmp  .no_at
.at:
    test ecx, ecx
    jz   .bad                           ; "@host": no user
    lea  rdi, [rel ssh_cli_user]
    xor  r9d, r9d
.at_copy:
    mov  al, [r12 + r9]
    mov  [rdi + r9], al
    inc  r9d
    cmp  r9d, ecx
    jb   .at_copy
    mov  byte [rdi + r9], 0
    mov  [rel ssh_cli_user_len], ecx
    lea  r12, [r12 + rcx + 1]
.no_at:
    xor  ebx, ebx
    xor  r8d, r8d
.oct:
    xor  eax, eax
    xor  r9d, r9d
.dig:
    movzx ecx, byte [r12]
    cmp  cl, '0'
    jb   .octdone
    cmp  cl, '9'
    ja   .octdone
    cmp  r9d, 3
    jae  .bad
    imul eax, eax, 10
    sub  ecx, '0'
    add  eax, ecx
    cmp  eax, 255
    ja   .bad
    inc  r12
    inc  r9d
    jmp  .dig
.octdone:
    test r9d, r9d
    jz   .bad
    mov  ecx, r8d
    shl  ecx, 3
    shl  eax, cl
    or   ebx, eax
    cmp  r8d, 3
    je   .port
    cmp  byte [r12], '.'
    jne  .bad
    inc  r12
    inc  r8d
    jmp  .oct
.port:
    mov  r13d, 22
    cmp  byte [r12], ':'
    jne  .after_port
    inc  r12
    xor  r13d, r13d
    xor  r9d, r9d
.pdig:
    movzx ecx, byte [r12]
    cmp  cl, '0'
    jb   .pdone
    cmp  cl, '9'
    ja   .pdone
    cmp  r9d, 5
    jae  .bad
    imul r13d, r13d, 10
    sub  ecx, '0'
    add  r13d, ecx
    cmp  r13d, 65535
    ja   .bad
    inc  r12
    inc  r9d
    jmp  .pdig
.pdone:
    test r9d, r9d
    jz   .bad
    test r13d, r13d
    jz   .bad                           ; port 0
.after_port:
    cmp  byte [r12], ' '
    jne  .end
    cmp  dword [rel ssh_cli_user_len], 0
    jne  .bad                           ; a user twice (USER@HOST USER)
    inc  r12
    lea  rdi, [rel ssh_cli_user]
    xor  r9d, r9d
.ucopy:
    mov  al, [r12]
    test al, al
    jz   .userdone
    cmp  al, ' '
    je   .bad
    cmp  r9d, 62
    jae  .bad
    mov  [rdi + r9], al
    inc  r12
    inc  r9d
    jmp  .ucopy
.userdone:
    mov  byte [rdi + r9], 0
    mov  [rel ssh_cli_user_len], r9d
.end:
    cmp  byte [r12], 0
    jne  .bad
    cmp  dword [rel ssh_cli_user_len], 0
    je   .bad
    mov  eax, ebx
    mov  edx, r13d
    jmp  .out
.bad:
    mov  dword [rel ssh_cli_user_len], 0
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI = arg text, ESI = 1 when the owner started it (the Terminal's GA0-K gated
; ssh builtin), else 0. Launch the outbound SSH client. Returns 0 launched,
; <0 failure (-4 absent/busy session, -9 not owner, -10 identity refused).
ssh_client_connect_start:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    cmp  qword [rel ssh_cli_ctx_ptr], 0
    je   .nosess                        ; no session loaded (ssh_session_begin first)
    mov  eax, [rel ssh_sess_active]
    cmp  eax, SSH_SESS_MAX
    jae  .nosess
    lea  rcx, [rel ssh_sess_busy]
    cmp  byte [rcx + rax], 0
    jne  .nosess                        ; a sink cannot redial over its live plaintext
    lea  rcx, [rel ssh_sess_work_busy]
    cmp  byte [rcx + rax], 0
    jne  .nosess                        ; work/cleanup hold cannot be bypassed
    call ssh_cli_kh_load                ; RCQ-07b: known_hosts, read once at the first ssh use
    call ssh_cli_drop_tcb               ; a redial ends this session's own old tuple only
    mov  byte [rel ssh_cli_retiring], 0
    xor  eax, eax
    test ebx, ebx
    setnz al
    mov  [rel ssh_cli_owner_armed], al  ; new owner grant follows old-session retirement
    mov  rdi, [rel ssh_cli_ctx_ptr]
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    call ssh_cli_flow_reset
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_IDLE
    mov  byte [rel ssh_cli_error], 0
    ; Public, per-dial evidence only. Never reused across a new connection.
    lea  rdi, [rel ssh_cli_key_check]
    xor  eax, eax
    mov  ecx, 6
    rep  stosq
    mov  byte [rel ssh_cli_tcp_seen], 0
    mov  byte [rel ssh_cli_banner_seen], 0
    mov  byte [rel ssh_cli_kexinit_seen], 0
    mov  byte [rel ssh_cli_publickey_ok], 0
    mov  byte [rel ssh_cli_want_ecdh], 0
    mov  byte [rel ssh_cli_want_svcreq], 0
    mov  byte [rel ssh_cli_want_userauth], 0
    mov  byte [rel ssh_cli_want_chanopen], 0
    mov  byte [rel ssh_cli_want_pty], 0
    mov  byte [rel ssh_cli_want_shell], 0
    mov  byte [rel ssh_cli_want_winadj], 0
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 0
    mov  dword [rel ssh_cli_local_window], 0
    mov  dword [rel ssh_cli_remote_window], 0
    mov  dword [rel ssh_cli_term_cols], 80
    mov  dword [rel ssh_cli_term_rows], 24
    mov  qword [rel ssh_cli_ka_left], 0
    mov  qword [rel ssh_cli_ka_last], 0
    mov  dword [rel ssh_cli_keepalive_count], 0
    mov  dword [rel ssh_cli_txq_head], 0
    mov  dword [rel ssh_cli_txq_tail], 0
    mov  dword [rel ssh_cli_txq_len], 0
    mov  dword [rel ssh_cli_vs_len], 0
    mov  dword [rel ssh_cli_is_len], 0
    cmp  byte [rel ssh_cli_owner_armed], 1
    jne  .not_owner
    call ssh_cli_cid_load               ; RCQ-08: the client identity, read once at the first ssh use
    test eax, eax
    jnz  .not_owner
    cmp  byte [rel ssh_cli_cid_state], SSH_CID_ST_UNVERIFIED
    je   .unverified
    mov  rdi, r12
    call ssh_cli_parse_arg
    cmp  eax, -1
    je   .arg
    mov  ebx, eax
    mov  r13d, edx
    mov  [rel ssh_cli_target_ip], ebx
    mov  [rel ssh_cli_target_port], r13w
    ; A reconnect is a new cryptographic session, not a continuation of the
    ; preceding channel.  Refresh the DRBG from the health-tested hardware
    ; provider before minting its KEX cookie/ephemeral material; this also
    ; recovers only through the canonical reseed path if the prior long-lived
    ; interactive stream left the service degraded.
    call csprng_reseed
    test eax, eax
    jnz  .entropy
    mov  rbx, [rel ssh_cli_ctx_ptr]
    lea  rdi, [rbx + SSH_C_VC]
    lea  rsi, [rel ssh_server_version]
    mov  edx, ssh_server_version.len
    call memcpy
    mov  dword [rbx + SSH_C_VC_LEN], ssh_server_version.len
    call ssh_cli_build_kexinit
    test eax, eax
    jnz  .entropy
    mov edi, [rel ssh_sess_active]
    call ssh_cli_work_binding
    mov r13, rax
    call tcp_client_cookie_alloc
    test rax, rax
    jz .entropy
    mov [r13 + 32], rax
    mov qword [r13 + 16], 0
    mov qword [r13 + 24], 0
    mov qword [r13 + 40], 0
    mov qword [r13 + 48], 0
    mov qword [r13 + 56], 0
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_TCP
    call ssh_cli_pick_port
    test eax, eax
    jz   .entropy                       ; no CSPRNG start draw: fail closed
    mov  [rel ssh_cli_lport], eax       ; this session's tuple is the one with this port
    mov  edx, eax
    mov  edi, [rel ssh_cli_target_ip]
    movzx esi, word [rel ssh_cli_target_port]
    lea  rcx, [rel ssh_cli_on_connected]
    lea  r8, [rel ssh_cli_on_receive]
    lea  r9, [r13 + 16]                  ; tracked pair published before callbacks
    call tcp_client_open_tracked
    test rax, rax
    jz   .route
    mov  [rel ssh_cli_tcb], rax
    call ssh_sess_note_tcb
    xor  eax, eax
    jmp  .out
.arg:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 1
    mov  eax, -1
    jmp  .out
.entropy:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 5
    mov  eax, -3
    jmp  .out
.nosess:
    mov  eax, -4
    jmp  .out
.not_owner:
    lea  rdi, [rel str_sshcli_cid_owner_only_serial]
    call serial_string
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 16
    mov  eax, -9
    jmp  .out
.unverified:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 17
    mov  eax, -10
    jmp  .out
.route:
    ; The hub's tcp_client_open answers 0 without a reason, so classify here:
    ; -7 the TCP stack is not up, -2 no ARP entry for the peer yet (the
    ; Terminal asks and redials), -8 every TCB is live or the SYN was not sent.
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 2
    mov  dword [rel ssh_cli_lport], 0
    mov  eax, -7
    cmp  byte [rel tcp_m_listen], 1
    jne  .out
    mov  edi, [rel ssh_cli_target_ip]
    call arp_cache_lookup
    test rax, rax
    mov  eax, -2
    jz   .out
    mov  eax, -8
.out:
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    jne  .return
    push rax
    call ssh_cli_retire
    pop  rax
.return:
    pop  r13
    pop  r12
    pop  rbx
    ret

; PUBLIC (Task3499): the owner closed the terminal that held the session, so
; the remote shell must end now, not at the next dial. CHANNEL_CLOSE makes sshd
; release the pty (the shell gets SIGHUP) and then close the connection; the
; tuple stays until then (tcp_client_send transmits from the poll, so freeing
; it here would discard the close). If the close cannot be queued the tuple is
; dropped instead. GUI tick normally owns this; a sink-triggered detach defers
; sealing/abort until its receive consumer returns.
ssh_client_disconnect:
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .normal
    cmp  byte [rax + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    jne  .drop                          ; cancel incomplete directional exchange, never send a stale-key close
    mov  eax, [rel ssh_sess_active]
    cmp  eax, SSH_SESS_MAX
    jae  .normal
    lea  rcx, [rel ssh_sess_work_busy]
    cmp  byte [rcx + rax], 0
    jne  .work_deferred
    lea  rcx, [rel ssh_sess_busy]
    cmp  byte [rcx + rax], 0
    je   .normal
.work_deferred:
    ; A sink may detach while still reading PLAIN. Neither seal into that
    ; buffer nor abort its callback-owned TCP tuple until it returns.
    cmp  byte [rel ssh_cli_close_sent], 1
    je   .deferred_idle
    cmp  byte [rel ssh_cli_chan_ready], 1
    je   .deferred_close
    cmp  byte [rel ssh_cli_want_close], 1
    je   .deferred_idle
    mov  byte [rel ssh_cli_retire_abort], 1
    jmp  .deferred_idle
.deferred_close:
    mov  byte [rel ssh_cli_want_close], 1
    call ssh_cli_arm_control
.deferred_idle:
    call ssh_cli_outcome_clear
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_IDLE
    jmp  ssh_cli_retire
.normal:
    cmp  byte [rel ssh_cli_close_sent], 1
    je   .idle                          ; accepted echo must drain, not be aborted by detach
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .drop
    lea  rdi, [rel ssh_cli_chpkt]
    mov  byte [rdi], SSH_MSG_CHANNEL_CLOSE
    inc  rdi
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    mov  rdi, [rel ssh_cli_ctx_ptr]
    lea  rsi, [rel ssh_cli_chpkt]
    mov  edx, 5
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .drop
    mov  byte [rel ssh_cli_close_sent], 1
    jmp  .idle                          ; queued: sshd ends the session
.drop:
    call ssh_cli_drop_tcb
.idle:
    call ssh_cli_outcome_clear           ; Terminal snapshots completion before teardown
    mov  dword [rel ssh_cli_request_failures], 0
    mov  dword [rel ssh_cli_global_failures], 0
    mov  byte [rel ssh_cli_want_close], 0
    call ssh_cli_handshake_clear
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_IDLE
    mov  dword [rel ssh_cli_txq_head], 0
    mov  dword [rel ssh_cli_txq_tail], 0
    mov  dword [rel ssh_cli_txq_len], 0
    jmp  ssh_cli_retire

; Canonical loaded-session retirement. Revoke new signing/input/receive work
; immediately. Active receive/sink consumers keep their bytes until return.
; Only pending ordered controls may retain C2S key/nonce/counter; accepted TCP
; ciphertext is independently owned and never wiped or re-sent by this path.
ssh_cli_retire:
    ; Application retirement cannot cancel transport ordering. If either
    ; NEWKEYS boundary is unfinished, abort only the owned tuple, after any
    ; active plaintext consumer returns. Never retain stale-key owed controls.
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .revoke
    cmp  byte [rax + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    je   .revoke
    mov  byte [rel ssh_cli_retire_abort], 1
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .revoke                        ; retain an already typed failure
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 21
.revoke:
    sub rsp, 8
    call ssh_cli_work_cancel
    add rsp, 8
    mov  byte [rel ssh_cli_retiring], 1
    mov  byte [rel ssh_cli_scrub_shared_pending], 1
    mov  byte [rel ssh_cli_owner_armed], 0
    mov  byte [rel ssh_cli_want_ecdh], 0
    mov  byte [rel ssh_cli_want_svcreq], 0
    mov  byte [rel ssh_cli_want_userauth], 0
    mov  byte [rel ssh_cli_want_chanopen], 0
    mov  byte [rel ssh_cli_want_winadj], 0
    sub  rsp, 8
    call ssh_cli_handshake_clear
    add  rsp, 8
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  dword [rel ssh_cli_txq_head], 0
    mov  dword [rel ssh_cli_txq_tail], 0
    mov  dword [rel ssh_cli_txq_len], 0
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .discard_controls
    cmp  qword [rel ssh_cli_tcb], 0
    jne  ssh_cli_retire_apply
.discard_controls:
    mov  dword [rel ssh_cli_request_failures], 0
    mov  dword [rel ssh_cli_global_failures], 0
    mov  byte [rel ssh_cli_want_close], 0
    jmp  ssh_cli_retire_apply

ssh_cli_retire_apply:
    push rbx
    push r12
    push r13
    sub  rsp, 80                        ; live C2S key, nonce, sequence and per-key accounting
    cmp  byte [rel ssh_cli_retiring], 1
    jne  .shared
    mov  r12d, [rel ssh_sess_active]
    cmp  r12d, SSH_SESS_MAX
    jae  .shared
    lea  rax, [rel ssh_sess_busy]
    cmp  byte [rax + r12], 0
    jne  .out                           ; caller still owns heap/region plaintext
    lea  rax, [rel ssh_sess_work_busy]
    cmp  byte [rax + r12], 0
    jne  .out                           ; private work still owns this heap/region
    cmp  byte [rel ssh_cli_retire_abort], 1
    jne  .slot
    mov  byte [rel ssh_cli_retire_abort], 0
    call ssh_cli_abort_owned
    mov  dword [rel ssh_cli_request_failures], 0
    mov  dword [rel ssh_cli_global_failures], 0
    mov  byte [rel ssh_cli_want_close], 0
.slot:
    mov  rbx, [rel ssh_cli_ctx_ptr]
    test rbx, rbx
    jz   .region
    xor  r13d, r13d
    cmp  dword [rel ssh_cli_global_failures], 0
    jne  .save_controls
    cmp  dword [rel ssh_cli_request_failures], 0
    jne  .save_controls
    cmp  byte [rel ssh_cli_want_close], 1
    jne  .wipe_slot
.save_controls:
    mov  r13d, 1
    lea  rdi, [rsp]
    lea  rsi, [rbx + SSH_C_C2S_KEY]
    mov  edx, 32
    call memcpy
    lea  rdi, [rsp + 32]
    lea  rsi, [rbx + SSH_C_C2S_IV]
    mov  edx, 12
    call memcpy
    mov  eax, [rbx + SSH_C_TX_PACKETS]
    mov  [rsp + 44], eax
    mov  eax, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_KEY_PKTS]
    mov  [rsp + 48], eax
    mov  rax, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_BYTES]
    mov  [rsp + 56], rax
    mov  rax, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_TOTAL]
    mov  [rsp + 64], rax
.wipe_slot:
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, SSH_CLI_SLOT_SIZE          ; context, server transcript and input ring
    call memset
    test r13d, r13d
    jz   .region
    lea  rdi, [rbx + SSH_C_C2S_KEY]
    lea  rsi, [rsp]
    mov  edx, 32
    call memcpy
    lea  rdi, [rbx + SSH_C_C2S_IV]
    lea  rsi, [rsp + 32]
    mov  edx, 12
    call memcpy
    mov  eax, [rsp + 44]
    mov  [rbx + SSH_C_TX_PACKETS], eax
    mov  eax, [rsp + 48]
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_KEY_PKTS], eax
    mov  rax, [rsp + 56]
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_BYTES], rax
    mov  rax, [rsp + 64]
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_TOTAL], rax
.region:
    lea  rdi, [rel ssh_cli_ephemeral]
    xor  esi, esi
    mov  edx, ssh_cli_region_end - ssh_cli_ephemeral
    call memset
    mov  dword [rel ssh_cli_vs_len], 0
    mov  dword [rel ssh_cli_is_len], 0
    mov  dword [rel ssh_cli_user_len], 0
    ; The loaded region is authoritative; erase its obsolete parked duplicate.
    mov  ecx, r12d
    call ssh_sess_ptr
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CLI_REGION_SIZE
    call memset
.shared:
    cmp  byte [rel ssh_cli_scrub_shared_pending], 1
    jne  .out
    xor  ecx, ecx
    lea  rax, [rel ssh_sess_busy]
.consumer:
    cmp  byte [rax + rcx], 0
    jne  .out                           ; shared scratch may belong to another sink
    lea  rdx, [rel ssh_sess_work_busy]
    cmp  byte [rdx + rcx], 0
    jne  .out
    inc  ecx
    cmp  ecx, SSH_SESS_MAX
    jb   .consumer
    lea  rdi, [rel ssh_cli_ks_len]
    xor  esi, esi
    mov  edx, ssh_cli_pins - ssh_cli_ks_len
    call memset                         ; transient scratch only, never identity/pins
    mov  byte [rel ssh_cli_scrub_shared_pending], 0
.out:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 80
    call memset
    xor  eax, eax
    add  rsp, 80
    pop  r13
    pop  r12
    pop  rbx
    ret

; Called after the bounded drain/tuple transition, only with no active consumer.
ssh_cli_retire_final:
    push rbx
    mov  ebx, [rel ssh_sess_active]
    call ssh_cli_retire
    mov  ecx, ebx
    call ssh_sess_ptr
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CLI_REGION_SIZE
    call memset
    lea  rdi, [rel ssh_cli_region_begin]
    xor  esi, esi
    mov  edx, SSH_CLI_REGION_SIZE
    call memset
    lea  rax, [rel ssh_sess_used]
    mov  byte [rax + rbx], 0
    lea  rax, [rel ssh_sess_tcb]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel ssh_sess_lport]
    mov  dword [rax + rbx*4], 0
    mov  ecx, ebx
    shl  ecx, 4
    lea  rax, [rel ssh_sess_poll_timers]
    mov  qword [rax + rcx], 0
    mov  qword [rax + rcx + 8], 0
    lea  rax, [rel ssh_sess_drain_timers]
    mov  qword [rax + rcx], 0
    mov  qword [rax + rcx + 8], 0
    mov  dword [rel ssh_sess_active], -1
    pop  rbx
    ret

; ============================ ssh sessions (2026-09-29) ============================
; The client is written against one state region. Sessions keep their own copy
; of that region and swap it in on use: every public entry point, TCP callback
; and poll first loads the session it belongs to. Callers outside a TCP
; callback select a session with ssh_session_use before touching ssh_cli_*.

; ssh_sess_ptr(ECX = index) -> RAX = its parked region (heap; allocated by
; ssh_session_begin before any session exists). Clobbers RAX, RDX.
ssh_sess_ptr:
    call ssh_sess_save_base
    push rax
    mov  eax, ecx
    mov  edx, SSH_CLI_REGION_SIZE
    imul rax, rdx
    pop  rdx
    add  rax, rdx
    ret

; ssh_session_use(EDI = index): load that session's state into the region
; (parking the one loaded before). No-op when already loaded or out of range.
; Preserves all general registers.
ssh_session_use:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    cmp  edi, SSH_SESS_MAX
    jae  .out
    cmp  edi, [rel ssh_sess_active]
    je   .out
    push rdi
    call ssh_sess_park
    pop  rdi
    mov  ecx, edi
    call ssh_sess_ptr
    mov  rsi, rax
    lea  rdi, [rel ssh_cli_region_begin]
    mov  ecx, SSH_CLI_REGION_SIZE
    cld
    rep  movsb
    pop  rdi
    push rdi
    mov  [rel ssh_sess_active], edi
.out:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; ssh_sess_park: copy the loaded session back to its slot; none is loaded after.
; Clobbers RAX, RCX, RDX, RSI, RDI.
ssh_sess_park:
    mov  ecx, [rel ssh_sess_active]
    cmp  ecx, SSH_SESS_MAX
    jae  .none
    mov  rax, [rel ssh_cli_tcb]
    lea  rdx, [rel ssh_sess_tcb]
    mov  [rdx + rcx*8], rax
    call ssh_sess_ptr
    mov  rdi, rax
    lea  rsi, [rel ssh_cli_region_begin]
    mov  ecx, SSH_CLI_REGION_SIZE
    cld
    rep  movsb
.none:
    mov  dword [rel ssh_sess_active], -1
    ret

; ssh_session_begin() -> EAX = a new session index (loaded, with no connection
; and no sink), or -1 when all SSH_SESS_MAX are in use. The caller then runs
; ssh_client_connect_start on it exactly as before.
ssh_session_begin:
    push rbx
    call ssh_cli_slots_base             ; both heap blocks exist before any session does
    test rax, rax
    jz   .full
    call ssh_sess_save_base
    test rax, rax
    jz   .full
    xor  ebx, ebx
.find:
    cmp  ebx, SSH_SESS_MAX
    jae  .full
    lea  rax, [rel ssh_sess_used]
    cmp  byte [rax + rbx], 0
    jne .occupied
    lea rax, [rel ssh_sess_work_busy]
    cmp byte [rax + rbx], 0
    je .take
.occupied:
    inc  ebx
    jmp  .find
.take:
    call tcp_client_cookie_alloc
    test rax, rax
    jz .full
    push rax
    mov edi, ebx
    call ssh_cli_work_binding
    mov rdi, rax
    xor esi, esi
    mov edx, 64
    call memset
    mov edi, ebx
    call ssh_cli_work_binding
    pop rdx
    mov [rax], rbx
    mov [rax + 8], rdx
    lea rax, [rel ssh_sess_used]
    mov  byte [rax + rbx], 1
    call ssh_sess_park                  ; the region now belongs to the new session
    mov  ecx, ebx
    call ssh_sess_ptr
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CLI_REGION_SIZE
    call memset                         ; retire a reused slot's parked copy too
    lea  rdi, [rel ssh_cli_region_begin]
    xor  esi, esi
    mov  edx, SSH_CLI_REGION_SIZE
    call memset                         ; never inherit a former loaded region
    mov  [rel ssh_sess_active], ebx
    mov  [rel ssh_sess_last], ebx
    ; never inherit the previous session's connection or sink: connect_start
    ; aborts ssh_cli_tcb, which would kill the other session
    mov  qword [rel ssh_cli_tcb], 0
    mov  qword [rel ssh_cli_data_sink], 0
    call ssh_cli_flow_reset
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_IDLE
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 0
    mov  dword [rel ssh_cli_lport], 0
    ; this session's heap slot: SSH context, server KEXINIT (I_S), input ring
    call ssh_cli_slots_base
    mov  ecx, ebx
    mov  edx, SSH_CLI_SLOT_SIZE
    imul rcx, rdx
    add  rax, rcx
    mov  [rel ssh_cli_ctx_ptr], rax
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CLI_SLOT_SIZE
    call memset                         ; complete bounded heap wipe on reuse
    lea  rax, [rel ssh_sess_tcb]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel ssh_sess_lport]
    mov  dword [rax + rbx*4], 0
    mov  ecx, ebx
    shl  ecx, 4
    lea  rax, [rel ssh_sess_poll_timers]
    mov  qword [rax + rcx], 0
    mov  qword [rax + rcx + 8], 0
    lea  rax, [rel ssh_sess_drain_timers]
    mov  qword [rax + rcx], 0
    mov  qword [rax + rcx + 8], 0
    mov  eax, ebx
    pop  rbx
    ret
.full:
    mov  eax, -1
    pop  rbx
    ret

; ssh_sess_note_tcb: record the loaded session's connection for callback routing:
; its TCB and the local port it was opened with (never re-read from the TCB: a
; freed slot may hold another connection by now). Clobbers RAX, RCX, RDX.
ssh_sess_note_tcb:
    mov  ecx, [rel ssh_sess_active]
    cmp  ecx, SSH_SESS_MAX
    jae  .out
    mov  rax, [rel ssh_cli_tcb]
    lea  rdx, [rel ssh_sess_tcb]
    mov  [rdx + rcx*8], rax
    mov  edx, [rel ssh_cli_lport]
    lea  rax, [rel ssh_sess_lport]
    mov  [rax + rcx*4], edx
.out:
    ret

; ssh_cli_tcb_owned -> RDI = the loaded session's TCB while it still carries
; this session's connection (same local port, not free), else 0 with
; ssh_cli_tcb cleared. Clobbers RAX, RDI.
ssh_cli_tcb_owned:
    mov  rdi, [rel ssh_cli_tcb]
    test rdi, rdi
    jz   .out
    cmp  byte [rdi + TCB_STATE], 0
    je   .stale
    movzx eax, word [rdi + TCB_LOCAL_PORT]
    cmp  eax, [rel ssh_cli_lport]
    jne  .stale
.out:
    ret
.stale:
    xor  edi, edi
    mov  qword [rel ssh_cli_tcb], 0
    ret

; ssh_cli_drop_tcb: abort the loaded session's own tuple (if it still has one)
; and forget it. Clobbers caller-saved registers.
ssh_cli_drop_tcb:
    mov  eax, [rel ssh_sess_active]
    cmp  eax, SSH_SESS_MAX
    jae  .abort
    lea  rcx, [rel ssh_sess_work_busy]
    cmp  byte [rcx + rax], 0
    jne  .defer
    lea  rcx, [rel ssh_sess_busy]
    cmp  byte [rcx + rax], 0
    je   .abort
.defer:
    mov  byte [rel ssh_cli_retire_abort], 1
    jmp  ssh_cli_retire
.abort:
    call ssh_cli_abort_owned
    jmp  ssh_cli_retire

ssh_cli_abort_owned:
    call ssh_cli_tcb_owned
    test rdi, rdi
    jz   .out
    call tcp_client_abort
.out:
    mov  qword [rel ssh_cli_tcb], 0
    ret

; ssh_sess_route(RDI = TCB) -> EAX 1 and that session loaded, 0 when no live
; session owns this connection (a stale callback). Preserves RDI, RSI, RDX.
ssh_sess_route:
    push rdx
    push rsi
    push rdi
    push rbx
    mov  ecx, [rel ssh_sess_active]
    cmp  ecx, SSH_SESS_MAX
    jae  .scan_all
    cmp  [rel ssh_cli_tcb], rdi         ; the loaded session (its region is current)
    jne  .scan_all
    movzx eax, word [rdi + TCB_LOCAL_PORT]
    cmp  eax, [rel ssh_cli_lport]
    je   .hit_loaded                    ; the same slot still holds its connection
.scan_all:
    xor  ebx, ebx
.scan:
    cmp  ebx, SSH_SESS_MAX
    jae  .miss
    cmp  ebx, [rel ssh_sess_active]
    je   .next
    lea  rax, [rel ssh_sess_used]
    cmp  byte [rax + rbx], 0
    je   .next
    lea  rax, [rel ssh_sess_tcb]
    cmp  [rax + rbx*8], rdi
    jne  .next
    movzx eax, word [rdi + TCB_LOCAL_PORT]
    lea  rdx, [rel ssh_sess_lport]
    cmp  eax, [rdx + rbx*4]
    jne  .next                          ; the slot was reused by another connection
    mov  edi, ebx
    call ssh_session_use
    jmp  .hit
.next:
    inc  ebx
    jmp  .scan
.hit_loaded:
    mov  ebx, ecx
    lea  rax, [rel ssh_sess_used]
    cmp  byte [rax + rbx], 0
    je   .miss
.hit:
    mov  eax, 1
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  rbx
    pop  rdi
    pop  rsi
    pop  rdx
    ret

; ssh_session_end(EDI = index): the owner (a Terminal) is done with it. The
; channel is closed as ssh_client_disconnect does; the session drains for up to
; 3 s of measured forward time so CLOSE leaves, then the poll frees it.
; No finite wall-clock drain is claimed while the clock is unavailable.
ssh_session_end:
    cmp  edi, SSH_SESS_MAX
    jae  .out
    lea  rax, [rel ssh_sess_used]
    cmp  byte [rax + rdi], 1
    jne  .out
    ; Claim retirement before callbacks, so reentrant/duplicate end cannot
    ; extend the drain. Keep its timer outside the loaded/parked region.
    mov  byte [rax + rdi], 2
    push rdi
    call ssh_session_use
    call time_monotonic_now_us
    mov  rcx, [rsp]
    shl  ecx, 4
    lea  rdx, [rel ssh_sess_drain_timers]
    mov  qword [rdx + rcx], SSH_SESS_DRAIN_US
    mov  [rdx + rcx + 8], rax
    mov  qword [rel ssh_cli_data_sink], 0
    call ssh_client_disconnect
    call ssh_sess_note_tcb
    pop  rdi
.out:
    ret

; ssh_sessions_poll: drive every session (replaces the single ssh_cli_poll).
; The loaded session is polled every call; parked ones at most every
; SSH_SESS_POLL_US under usable forward time. Repeated/unavailable/rebased
; samples permit parked progress; each channel still owns its idle/drain budget.
ssh_sessions_poll:
    push rbx
    push r12
    call time_monotonic_now_us
    mov  r12, rax
    xor  ebx, ebx
.each:
    cmp  ebx, SSH_SESS_MAX
    jae  .done
    lea  rax, [rel ssh_sess_busy]
    cmp  byte [rax + rbx], 0
    jne  .next                          ; a reentrant sink cannot free its live bytes
    lea  rax, [rel ssh_sess_work_busy]
    cmp  byte [rax + rbx], 0
    jne  .next                          ; deferred compute has not actually returned
    lea  rax, [rel ssh_sess_used]
    movzx eax, byte [rax + rbx]
    test eax, eax
    jz   .next
    cmp  eax, 2
    je   .draining
    cmp  ebx, [rel ssh_sess_active]
    je   .poll
    mov  ecx, ebx
    shl  ecx, 4
    lea  rdi, [rel ssh_sess_poll_timers]
    add  rdi, rcx
    mov  rax, r12
    call ssh_cli_timer_step
    test rax, rax
    jz   .poll
    test edx, edx
    jnz  .next
    ; Unknown/repeated/rebased time cannot starve parked controls. Poll once per outer
    ; call; independent keepalive/drain custody still earns no elapsed time.
.poll:
    mov  ecx, ebx
    shl  ecx, 4
    lea  rax, [rel ssh_sess_poll_timers]
    mov  qword [rax + rcx], SSH_SESS_POLL_US
    mov  [rax + rcx + 8], r12
    mov  edi, ebx
    call ssh_session_use
    call ssh_cli_poll
    call ssh_sess_note_tcb
    jmp  .next
.draining:
    mov  edi, ebx
    call ssh_session_use
    mov  ecx, ebx
    shl  ecx, 4
    lea  rdi, [rel ssh_sess_drain_timers]
    add  rdi, rcx
    mov  rax, r12
    call ssh_cli_timer_step
    test rax, rax
    jz   .free
    call ssh_cli_tcb_owned
    test rdi, rdi
    jz   .freed                         ; the peer already closed it (or the slot moved on)
    call ssh_cli_poll                   ; lets the queued CHANNEL_CLOSE leave
    jmp  .next
.free:
    call ssh_cli_tcb_owned
    test rdi, rdi
    jz   .freed
    call tcp_close                      ; FIN (falls back to the TCP reaper)
    test rax, rax
    jz   .freed
    call ssh_cli_drop_tcb
.freed:
    mov  qword [rel ssh_cli_tcb], 0
    call ssh_cli_retire_final
.next:
    inc  ebx
    jmp  .each
.done:
    pop  r12
    pop  rbx
    ret

; TCP connected callback (RDI=tcb): record, send our version banner.
ssh_cli_on_connected:
    call ssh_sess_route                  ; load the session that owns this connection
    test eax, eax
    jnz  .owned
    xor  eax, eax
    ret
.owned:
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .retired
    push rbx
    mov  rbx, rdi
    mov  [rel ssh_cli_tcb], rbx
    mov  byte [rel ssh_cli_tcp_seen], 1
    lea  rdi, [rel str_sshcli_tcp]
    call serial_string
    mov  rdi, rbx
    lea  rsi, [rel ssh_server_banner]
    mov  edx, ssh_server_version.len + 2
    call tcp_client_send
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_BANNER
    pop  rbx
.retired:
    ret

; Consume one CRLF-terminated line from SSH_C_RX. If it is the "SSH-..." server
; banner, record V_S, send our KEXINIT, advance to WAIT_KEXINIT. EAX=1 if a line
; was consumed (re-pump), 0 if no full line yet.
ssh_cli_take_banner:
    push rbx
    push r12
    push r13
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  ecx, [rbx + SSH_C_RX_LEN]
    xor  r12d, r12d
.scan:
    cmp  r12d, ecx
    jae  .none
    cmp  byte [rbx + SSH_C_RX + r12], 10
    je   .found
    inc  r12d
    jmp  .scan
.found:
    mov  r13d, r12d
    test r13d, r13d
    jz   .consume0
    mov  eax, r12d
    dec  eax
    cmp  byte [rbx + SSH_C_RX + rax], 13
    jne  .checkpfx
    dec  r13d
.checkpfx:
    cmp  r13d, 4
    jb   .consume0
    mov  eax, [rbx + SSH_C_RX]
    cmp  eax, 'SSH-'
    jne  .consume0
    cmp  r13d, 255
    ja   .consume0
    lea  rdi, [rel ssh_cli_vs]
    lea  rsi, [rbx + SSH_C_RX]
    mov  edx, r13d
    call memcpy
    mov  [rel ssh_cli_vs_len], r13d
    lea  rax, [rel ssh_cli_vs]
    mov  ecx, [rel ssh_cli_vs_len]
    mov  byte [rax + rcx], 0
    mov  byte [rel ssh_cli_banner_seen], 1
    mov  rdi, rbx
    lea  esi, [r12 + 1]
    call ssh_rx_consume
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_IC]
    mov  edx, [rbx + SSH_C_IC_LEN]
    call ssh_packet_clear_build
    test eax, eax
    js   .prog
    mov  edx, eax
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  rdi, [rel ssh_cli_tcb]
    lea  rsi, [rbx + SSH_C_OUT]
    call tcp_client_send
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_KEXINIT
    lea  rdi, [rel str_sshcli_banner]
    call serial_string
    lea  rdi, [rel ssh_cli_vs]
    call serial_string
    lea  rdi, [rel str_sshcli_crlf]
    call serial_string
.prog:
    mov  eax, 1
    jmp  .out
.consume0:
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  rdi, rbx
    lea  esi, [r12 + 1]
    call ssh_rx_consume
    mov  eax, 1
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; TCP receive callback (RSI=data, EDX=len): accumulate + pump the handshake.
ssh_cli_on_receive:
    cld                                 ; including retired/unowned callback returns
    call ssh_sess_route                  ; load the session that owns this connection
    test eax, eax
    jnz  .owned
    xor  eax, eax                        ; nobody owns it any more: discard
    ret
.owned:
    cmp  byte [rel ssh_cli_retiring], 0
    je   .consumer
    xor  eax, eax
    ret
.consumer:
    mov  eax, [rel ssh_sess_active]
    lea  rcx, [rel ssh_sess_busy]
    cmp  byte [rcx + rax], 0
    je   .enter
    mov  eax, 1                         ; same-session nested consumer must retry
    ret
.enter:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  r12d, [rel ssh_sess_active]
    lea  rax, [rel ssh_sess_busy]
    inc  byte [rax + r12]
    mov  r14, rsi
    mov  r13d, edx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  eax, [rbx + SSH_C_RX_LEN]
    mov  ecx, eax
    add  ecx, r13d
    cmp  ecx, SSH_C_RX_CAP
    ja   .full
    lea  rdi, [rbx + SSH_C_RX]
    add  rdi, rax
    mov  rsi, r14
    mov  edx, r13d
    call memcpy
    add  dword [rbx + SSH_C_RX_LEN], r13d
.pump:
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .out
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_BANNER
    jne  .pkts
    call ssh_cli_take_banner
    test eax, eax
    jnz  .pump
    jmp  .out
.pkts:
    ; Once the transport is encrypted (state >= ENC), packets are AES-GCM: the
    ; 4-byte length stays clear (AAD) but the body is sealed, so use the GCM read.
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_ENC
    jae  .enc_loop
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_KEXINIT
    jb   .out
.nextpkt:
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  eax, [rbx + SSH_C_RX_LEN]
    cmp  eax, 6
    jb   .out
    mov  ecx, [rbx + SSH_C_RX]
    bswap ecx
    cmp  ecx, 6
    jb   .out
    cmp  ecx, SSH_MAX_PACKET
    ja   .out
    mov  edx, ecx
    add  edx, 4
    cmp  eax, edx
    jb   .out
    movzx r8d, byte [rbx + SSH_C_RX + 4]
    mov  r9d, ecx
    sub  r9d, r8d
    dec  r9d                                     ; r9d = payload length
    cmp  r9d, 1
    jb   .consume
    movzx eax, byte [rbx + SSH_C_RX + 5]         ; message type
    ; --- WAIT_KEXINIT: capture server KEXINIT (I_S) and open the ECDH exchange ---
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_KEXINIT
    jne  .chk_reply
    cmp  eax, SSH_MSG_KEXINIT
    jne  .consume
    cmp  r9d, SSH_CLI_IS_CAP
    ja   .consume
    mov  [rel ssh_cli_is_len], r9d
    lea  rdi, [rbx + SSH_CLI_SLOT_IS]
    lea  rsi, [rbx + SSH_C_RX + 5]
    mov  edx, r9d
    call memcpy
    mov  byte [rel ssh_cli_kexinit_seen], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_GOT_KEXINIT
    lea  rdi, [rel str_sshcli_kexinit]
    call serial_string
    mov  rdi, [rel ssh_cli_ctx_ptr]
    call ssh_cli_send_ecdh_init
    jmp  .consume
.chk_reply:
    ; --- SENT_ECDH: process KEX_ECDH_REPLY (verify host key, derive keys, NEWKEYS) ---
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_SENT_ECDH
    jne  .chk_newkeys
    cmp  eax, SSH_MSG_KEX_ECDH_REPLY
    jne  .consume
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_RX + 5]
    mov  edx, r9d
    call ssh_cli_process_ecdh_reply
    jmp  .consume
.chk_newkeys:
    ; --- WAIT_NEWKEYS: server NEWKEYS flips us to the encrypted transport ---
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_NEWKEYS
    jne  .consume
    cmp  eax, SSH_MSG_NEWKEYS
    jne  .consume
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_ENC
    call time_monotonic_now_us
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_STARTED], rax
    ; Defer SERVICE_REQUEST to ssh_cli_poll: our NEWKEYS is still the single
    ; in-flight segment, so an inline encrypted send would hit backpressure.
    mov  byte [rel ssh_cli_want_svcreq], 1
    lea  rdi, [rel str_sshcli_newkeys]
    call serial_string
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  ecx, [rbx + SSH_C_RX]
    bswap ecx
    add  ecx, 4
    mov  rdi, rbx
    mov  esi, ecx
    call ssh_rx_consume
    jmp  .enc_loop
.consume:
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  ecx, [rbx + SSH_C_RX]
    bswap ecx
    add  ecx, 4
    mov  rdi, rbx
    mov  esi, ecx
    call ssh_rx_consume
    jmp  .nextpkt
.enc_loop:
    mov  rbx, [rel ssh_cli_ctx_ptr]
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_NEW], 0
    je   .enc_running
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    jne  .out                           ; retain post-NEWKEYS ciphertext until our NEWKEYS queues
.enc_running:
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .out
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .out                                    ; a channel violation retires this connection
    mov  rdi, [rel ssh_cli_ctx_ptr]
    call ssh_cli_gcm_read                        ; RAX=payload ptr (0=incomplete,-1=bad), EDX=len
    test rax, rax
    jz   .out
    cmp  rax, -1
    je   .encfail
    mov  r13, rax                                 ; r13 = payload ptr
    mov  r14d, edx                                ; r14d = payload length
    test r14d, r14d
    jnz  .enc_type
    call ssh_cli_channel_fault                    ; authenticated empty payload has no message
    jmp  .out
.enc_type:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_rekey_packet
    test eax, eax
    js   .out
    jnz  .enc_loop
    movzx ecx, byte [r13]                         ; message type
    mov  [rel ssh_cli_last_enc_msg], cl
    cmp  ecx, SSH_MSG_SERVICE_ACCEPT
    je   .svc_ok
    cmp  ecx, SSH_MSG_USERAUTH_SUCCESS
    je   .auth_ok
    cmp  ecx, SSH_MSG_USERAUTH_FAILURE
    je   .auth_fail
    ; --- post-auth channel-layer messages (RFC4254) ---
    cmp  ecx, SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    je   .ch_confirm
    cmp  ecx, SSH_MSG_CHANNEL_OPEN_FAILURE
    je   .ch_openfail
    cmp  ecx, SSH_MSG_CHANNEL_DATA
    je   .ch_data
    cmp  ecx, SSH_MSG_CHANNEL_EXTENDED_DATA
    je   .ch_extdata
    cmp  ecx, SSH_MSG_CHANNEL_WINDOW_ADJUST
    je   .ch_winadj
    cmp  ecx, SSH_MSG_CHANNEL_EOF
    je   .ch_eof
    cmp  ecx, SSH_MSG_CHANNEL_CLOSE
    je   .ch_close
    cmp  ecx, SSH_MSG_GLOBAL_REQUEST
    je   .global_req
    cmp  ecx, SSH_MSG_CHANNEL_REQUEST
    je   .ch_request
    cmp  ecx, SSH_MSG_CHANNEL_SUCCESS
    je   .ch_reply
    cmp  ecx, SSH_MSG_CHANNEL_FAILURE
    je   .ch_reply
    cmp  ecx, SSH_MSG_DISCONNECT
    je   .disconnect
    jmp  .enc_loop                                ; USERAUTH_BANNER / IGNORE / DEBUG etc: ignore
.ch_reply:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_reply
    jmp  .enc_loop
.ch_request:
    ; 2026-09-29: a server request that wants a reply (sshd's own keepalive when
    ; ClientAliveInterval is set) must be answered, or sshd drops the session.
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_request
    jmp  .enc_loop
.disconnect:
    ; the server ended the connection: publish it at once (was ignored and only
    ; noticed at the next failed send)
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 8
    jmp  .enc_loop
.svc_ok:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_SVC_OK
    mov  byte [rel ssh_cli_want_userauth], 1      ; defer publickey userauth to ssh_cli_poll
    lea  rdi, [rel str_sshcli_svc]
    call serial_string
    jmp  .enc_loop
.auth_ok:
    call ssh_cli_kh_admission_current
    test eax, eax
    jz   .auth_trusted
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 15
    jmp  .enc_loop
.auth_trusted:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_AUTHED
    mov  byte [rel ssh_cli_publickey_ok], 1       ; only USERAUTH_SUCCESS earns this
    call ssh_cli_kh_confirm                       ; RCQ-07b: this endpoint's pin is saved only now
    mov  byte [rel ssh_cli_want_chanopen], 1      ; defer CHANNEL_OPEN to ssh_cli_poll
    lea  rdi, [rel str_sshcli_auth]
    call serial_string
    jmp  .enc_loop
.auth_fail:
    lea  rdi, [rel str_sshcli_authfail]
    call serial_string
    ; our only method (publickey) was refused: fail now instead of letting the
    ; Terminal wait out its 20-s dial budget
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 9
    jmp  .enc_loop
.ch_confirm:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_confirm                  ; record remote chan + window, arm pty/shell
    jmp  .enc_loop
.ch_openfail:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    lea  rdi, [rel str_sshcli_chfail]
    call serial_string
    jmp  .enc_loop
.ch_data:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_data                     ; deliver to sink + local window accounting
    jmp  .enc_loop
.ch_extdata:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_extdata                  ; stderr: skip the uint32 data_type_code
    jmp  .enc_loop
.ch_winadj:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_winadjust                ; grow the server-side send window
    jmp  .enc_loop
.ch_eof:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_eof
    jmp  .enc_loop
.ch_close:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_channel_closed
    jmp  .enc_loop
.global_req:
    mov  rdi, r13
    mov  esi, r14d
    call ssh_cli_global_request                   ; answer want_reply=1 with REQUEST_FAILURE
    jmp  .enc_loop
.encfail:
    lea  rdi, [rel str_sshcli_encfail]           ; DIAG: an inbound encrypted packet failed to open
    call serial_string
    ; Task3499: the GCM stream cannot resynchronise. Publish the closed channel
    ; so the terminal detaches instead of waiting forever; the next dial aborts
    ; this tuple (ssh_client_connect_start).
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 7
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  dword [rbx + SSH_C_RX_LEN], 0
    jmp  .out
.out:
    mov  edi, r12d
    call ssh_session_use                ; a sink may have selected another session
    lea  rax, [rel ssh_sess_busy]
    dec  byte [rax + r12]
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    jne  .retire_ready
    call ssh_cli_retire
.retire_ready:
    call ssh_cli_retire_apply            ; plaintext consumer has now returned
    ; 2026-09-29: the bytes were appended to the SSH receive buffer, so report
    ; them consumed. RAX used to leak whatever the last step left (RX_LEN of an
    ; incomplete packet, memcpy's result) and tcp_poll re-delivered the same
    ; bytes, duplicating KEX/auth data (intermittent connect failures).
    xor  eax, eax
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.full:
    lea  rax, [rel ssh_sess_busy]
    dec  byte [rax + r12]
    mov  eax, 1                                  ; no room yet: TCP keeps the bytes queued
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "svc/ssh_client_rekey.inc"
; PUBLIC exec APIs: configure(RDI=owned bytes,ESI=len)->0/-1 before channel;
; is_exec()/exec_pending()->1/0 for the selected session. No wire/store action.
ssh_cli_exec_configure:
    jmp  ssh_cli_exec_configure_impl
ssh_cli_is_exec:
    jmp  ssh_cli_is_exec_impl
ssh_cli_exec_pending:
    jmp  ssh_cli_exec_pending_impl
ssh_cli_exec_configure_stream:
    jmp  ssh_cli_exec_configure_stream_impl
ssh_cli_exec_handle:
    jmp  ssh_cli_exec_handle_impl
ssh_cli_exec_stdin:
    jmp  ssh_cli_exec_stdin_impl
ssh_cli_exec_close_stdin:
    jmp  ssh_cli_exec_close_stdin_impl
ssh_cli_exec_signal:
    jmp  ssh_cli_exec_signal_impl
ssh_cli_exec_status:
    jmp  ssh_cli_exec_status_impl
ssh_cli_exec_cancel:
    jmp  ssh_cli_exec_cancel_impl
%include "svc/ssh_client_exec.inc"

; ===================== Task3494 client KEX (curve25519-sha256) =====================
; Generate the client ephemeral, send KEX_ECDH_INIT (byte 30 + string Q_C). RDI=ctx.
ssh_cli_send_ecdh_init:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel ssh_cli_ephemeral]
    mov  esi, 32
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    lea  rsi, [rel ssh_cli_ephemeral]
    lea  rdx, [rel ssh_x25519_base]
    call x25519
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_pkt]
    mov  byte [rdi], SSH_MSG_KEX_ECDH_INIT
    lea  rdi, [rel ssh_cli_pkt + 1]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_pkt + 5]
    lea  rsi, [rbx + SSH_C_CLIENT_Q]
    mov  edx, 32
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_pkt]
    mov  edx, 37
    call ssh_packet_clear_build
    test eax, eax
    js   .bad
    mov  edx, eax
    mov  rdi, [rel ssh_cli_tcb]
    lea  rsi, [rbx + SSH_C_OUT]
    call tcp_client_send
    ; tcp keeps one segment in flight: if our KEXINIT is still unacked this send
    ; is refused (-1). Do NOT advance state — defer to ssh_cli_poll and retry so
    ; the ECDH_INIT actually reaches the server (else the handshake wedges).
    test rax, rax
    jnz  .ecdh_backpressure
    mov  byte [rel ssh_cli_want_ecdh], 0
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_SENT_ECDH
    lea  rdi, [rel str_sshcli_ecdh]
    call serial_string
    xor  eax, eax
    jmp  .out
.ecdh_backpressure:
    mov  byte [rel ssh_cli_want_ecdh], 1
    mov  eax, 1
    jmp  .out
.bad:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 3
    mov  eax, -1
.out:
    pop  rbx
    ret

; RFC8731 exchange hash over RECEIVED transcript: V_C,V_S,I_C,I_S,K_S,Q_C,Q_S,K.
; RDI=ctx -> SSH_C_H = SHA256(transcript), EAX=0/-1.
ssh_cli_compute_exchange_hash:
    push rbx
    mov  rbx, rdi
    mov  dword [rel ssh_exchange_len], 0
    lea  rdi, [rbx + SSH_C_VC]                    ; V_C (our version)
    mov  esi, [rbx + SSH_C_VC_LEN]
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_vs]                    ; V_S (server banner)
    mov  esi, [rel ssh_cli_vs_len]
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_IC]                    ; I_C (our KEXINIT)
    mov  esi, [rbx + SSH_C_IC_LEN]
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_CLI_SLOT_IS]            ; I_S (server KEXINIT)
    mov  esi, [rel ssh_cli_is_len]
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_ks_buf]               ; K_S (server host key blob)
    mov  esi, [rel ssh_cli_ks_len]
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_CLIENT_Q]             ; Q_C
    mov  esi, 32
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_SERVER_Q]             ; Q_S
    mov  esi, 32
    call ssh_exchange_append_string
    test eax, eax
    jnz  .bad
    mov  rdi, rbx                                 ; K (mpint of shared secret)
    call ssh_build_k_mpint
    lea  rdi, [rel ssh_k_mpint]
    mov  esi, eax
    call ssh_exchange_append_raw
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_H]
    lea  rsi, [rel ssh_exchange_buf]
    mov  edx, [rel ssh_exchange_len]
    call sha256_hash
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; Process KEX_ECDH_REPLY: extract K_S/Q_S/signature, derive the shared secret,
; compute + verify H against the server ed25519 host key against owner-provisioned trust, derive session
; keys, and send NEWKEYS. RDI=ctx, RSI=payload (from msg byte), EDX=payload len.
ssh_cli_process_ecdh_reply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rsi
    add  r13, rdx                                 ; r13 = payload end
    jc   .bad
    test edx, edx
    jz   .bad
    inc  r12                                      ; skip the message byte
    ; --- string K_S ---
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .bad
    mov  r15d, [r12]
    bswap r15d
    add  r12, 4
    lea  rax, [r12 + r15]
    cmp  rax, r13
    ja   .bad
    cmp  r15d, 128
    ja   .bad
    mov  [rel ssh_cli_ks_len], r15d
    lea  rdi, [rel ssh_cli_ks_buf]
    mov  rsi, r12
    mov  edx, r15d
    call memcpy
    add  r12, r15
    ; --- string Q_S (must be 32) ---
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .bad
    mov  r15d, [r12]
    bswap r15d
    cmp  r15d, 32
    jne  .bad
    add  r12, 4
    lea  rax, [r12 + 32]
    cmp  rax, r13
    ja   .bad
    lea  rdi, [rbx + SSH_C_SERVER_Q]
    mov  rsi, r12
    mov  edx, 32
    call memcpy
    add  r12, 32
    ; --- string signature ---
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .bad
    mov  r15d, [r12]
    bswap r15d
    add  r12, 4
    lea  rax, [r12 + r15]
    cmp  rax, r13
    ja   .bad
    cmp  r15d, 128
    ja   .bad
    mov  [rel ssh_cli_sig_len], r15d
    lea  rdi, [rel ssh_cli_sig_buf]
    mov  rsi, r12
    mov  edx, r15d
    call memcpy
    add  r12, r15
    cmp  r12, r13
    jne  .bad                           ; complete reply, no trailing fields
    ; --- shared secret = x25519(ephemeral, Q_S) ---
    lea  rdi, [rbx + SSH_C_SHARED]
    lea  rsi, [rel ssh_cli_ephemeral]
    lea  rdx, [rbx + SSH_C_SERVER_Q]
    call x25519
    test eax, eax
    jnz  .bad
    xor  eax, eax
    xor  ecx, ecx
.zchk:
    or   al, [rbx + SSH_C_SHARED + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .zchk
    test al, al
    jz   .bad
    ; --- exchange hash + session id ---
    mov  rdi, rbx
    call ssh_cli_compute_exchange_hash
    test eax, eax
    jnz  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    jne  .session_id_kept
    lea  rdi, [rbx + SSH_C_SESSION_ID]
    lea  rsi, [rbx + SSH_C_H]
    mov  edx, 32
    call memcpy
.session_id_kept:
    ; --- verify server signature over H (ssh-ed25519 blob layout: pubkey at
    ;     +19 = 4 + len("ssh-ed25519")=11 + 4; raw sig at +19 likewise). ---
    cmp  dword [rel ssh_cli_ks_len], 51
    jne  .bad
    cmp  dword [rel ssh_cli_sig_len], 83
    jne  .bad
    lea  rsi, [rel ssh_cli_ks_buf]
    lea  rdi, [rel ssh_cli_ed25519_key_prefix]
    mov  ecx, 19
    cld
    repe cmpsb
    jne  .bad
    lea  rsi, [rel ssh_cli_sig_buf]
    lea  rdi, [rel ssh_cli_ed25519_sig_prefix]
    mov  ecx, 19
    repe cmpsb
    jne  .bad
    lea  rdi, [rel ssh_cli_ks_buf + 19]
    mov  esi, 32
    lea  rdx, [rbx + SSH_C_H]
    mov  ecx, 32
    lea  r8, [rel ssh_cli_sig_buf + 19]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jnz  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    je   .initial_host
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .hostkey_changed
    lea  rdi, [rel ssh_cli_hk_digest]
    lea  rsi, [rel ssh_cli_ks_buf]
    mov  edx, [rel ssh_cli_ks_len]
    call sha256_hash
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_hk_digest]
    lea  rsi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_HOST]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .hostkey_changed
    mov  rdi, rbx
    call ssh_cli_rekey_derive
    jmp  .out
.initial_host:
    call ssh_cli_hostkey_check          ; pinned this boot: a changed key is refused
    test eax, eax
    jz   .hostkey_ok
    cmp  eax, -2
    je   .hostkey_full
    cmp  eax, -3
    je   .hostkey_untrusted
    jmp  .hostkey_changed
.hostkey_ok:
    call ssh_cli_rekey_bind
    test eax, eax
    jnz  .bad
    ; --- derive keys, send NEWKEYS ---
    mov  rdi, rbx
    call ssh_derive_keys
    test eax, eax
    jnz  .bad
    mov  byte [rel ssh_cli_pkt], SSH_MSG_NEWKEYS
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_pkt]
    mov  edx, 1
    call ssh_packet_clear_build
    test eax, eax
    js   .bad
    mov  edx, eax
    mov  rdi, [rel ssh_cli_tcb]
    lea  rsi, [rbx + SSH_C_OUT]
    call tcp_client_send
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_WAIT_NEWKEYS
    lea  rdi, [rel str_sshcli_kex]
    call serial_string
    xor  eax, eax
    jmp  .out
.hostkey_changed:
    lea  rdi, [rel str_sshcli_hostkey_changed]
    call serial_string
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 15
    mov  eax, -1
    jmp  .out
.hostkey_untrusted:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 4    ; sink already explained explicit provisioning
    mov  eax, -1
    jmp  .out
.hostkey_full:                          ; no free pin: never trust without one
    lea  rdi, [rel str_sshcli_hostkey_full]
    call serial_string
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 4    ; generic "connection failed"; the sink got the reason
    mov  eax, -1
    jmp  .out
.bad:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 4
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Seal + send one RFC5647 AES256-GCM packet from the CLIENT (C2S key/iv), then
; commit the C2S nonce. RDI=ctx, RSI=payload, EDX=len -> EAX=0/-1.
ssh_cli_gcm_send:
    cld
    cmp  byte [rdi + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    je   .admitted
    cmp  edx, 1
    jb   .paused
    cmp  byte [rsi], SSH_MSG_KEXINIT
    je   .admitted
    cmp  byte [rsi], SSH_MSG_KEX_ECDH_INIT
    je   .admitted
    cmp  byte [rsi], SSH_MSG_NEWKEYS
    je   .admitted
.paused:
    mov  eax, 1
    ret
.admitted:
    cmp  qword [rdi + SSH_C_C2S_IV + 4], -1
    je   .retired
    cmp  dword [rdi + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_KEY_PKTS], 0x40000000
    jae  .retired
    cmp  byte [rel ssh_cli_retiring], 1
    jne  .send
    mov  eax, [rel ssh_sess_active]
    cmp  eax, SSH_SESS_MAX
    jae  .retired
    lea  rcx, [rel ssh_sess_busy]
    cmp  byte [rcx + rax], 0
    je   .send
    mov  eax, 1                         ; do not overwrite a retiring sink's PLAIN
    ret
.retired:
    mov  eax, -1
    ret
.send:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    cmp  r13d, SSH_C_OUT_CAP - 32
    ja   .bad
    lea  eax, [r13d + 1]
    and  eax, 15
    mov  r14d, 16
    sub  r14d, eax
    cmp  r14d, 4
    jae  .pad_ok
    add  r14d, 16
.pad_ok:
    lea  eax, [r13d + r14d + 21]
    cmp  eax, SSH_C_OUT_CAP
    ja   .bad
    lea  eax, [r13d + r14d + 1]
    lea  rdi, [rbx + SSH_C_OUT]
    mov  esi, eax
    call ssh_be32_store
    mov  byte [rbx + SSH_C_PLAIN], r14b
    lea  rdi, [rbx + SSH_C_PLAIN + 1]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  rdi, [rbx + SSH_C_PLAIN + 1]
    add  rdi, r13
    mov  esi, r14d
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rax, [rel ssh_aead_req]
    lea  rcx, [rbx + SSH_C_C2S_KEY]
    mov  [rax + AEAD_KEY], rcx
    lea  rcx, [rbx + SSH_C_C2S_IV]
    mov  [rax + AEAD_NONCE], rcx
    lea  rcx, [rbx + SSH_C_OUT]
    mov  [rax + AEAD_AAD], rcx
    mov  qword [rax + AEAD_AAD_LEN], 4
    lea  rcx, [rbx + SSH_C_PLAIN]
    mov  [rax + AEAD_INPUT], rcx
    lea  ecx, [r13d + r14d + 1]
    mov  [rax + AEAD_INPUT_LEN], rcx
    lea  rcx, [rbx + SSH_C_OUT + 4]
    mov  [rax + AEAD_OUTPUT], rcx
    add  rcx, [rax + AEAD_INPUT_LEN]
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes256_gcm_seal
    test eax, eax
    jnz  .bad
    cmp byte [rel ssh_cli_work_busy], 1
    jne .legacy_tuple
    mov eax, [rel ssh_sess_active]
    cmp eax, [rel ssh_cli_work_slot]
    jne .legacy_tuple
    ; USERAUTH's private work owns this original slot through GCM admission.
    ; Recheck original D/service bound/authority after sealing; TCP validates
    ; incarnation atomically with enqueue before a provisional result is sent.
    call ssh_cli_work_current
    test eax, eax
    jnz .dead
    mov rdi, [rel ssh_cli_work_snapshot + 16]
    mov rsi, [rel ssh_cli_work_snapshot + 24]
    lea rdx, [rbx + SSH_C_OUT]
    lea ecx, [r13d + r14d + 21]
    mov r8d, 1
    call tcp_client_epoch_io
    jmp .tuple_result
.legacy_tuple:
    call ssh_cli_tcb_owned              ; hub tcp_client_send: -1 is backpressure OR a dead tuple
    test rdi, rdi
    jz   .dead
    cmp  byte [rdi + TCB_STATE], TCP_ESTABLISHED
    jne  .dead
    lea  edx, [r13d + r14d + 21]
    lea  rsi, [rbx + SSH_C_OUT]
    call tcp_client_send
.tuple_result:
    ; tcp_send keeps exactly one segment in flight: on backpressure (-1) NOTHING
    ; was queued, so DON'T burn the GCM nonce — the caller re-seals + retries.
    test rax, rax
    jz   .accepted
    cmp  rax, -1
    je   .backpressure                 ; canonical TCP proves nothing queued only for -1
    jmp  .dead                         ; unknown acceptance is terminal, never replay
.accepted:
    lea  rdi, [rbx + SSH_C_C2S_IV]
    call ssh_nonce_inc
    inc  dword [rbx + SSH_C_TX_PACKETS]       ; implicit transport sequence never resets at rekey
    inc  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_KEY_PKTS]
    inc  qword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_TOTAL]
    lea  eax, [r13d + r14d + 21]
    add  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_BYTES], rax
    xor  eax, eax
    jmp  .out
.backpressure:
    mov  eax, 1
    jmp  .out
.dead:
    mov  eax, -1
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Open one RFC5647 AES256-GCM packet at the CLIENT (S2C key/iv), consume it, and
; commit the S2C nonce. RDI=ctx -> RAX=payload ptr (0 incomplete, -1 bad), EDX=len.
ssh_cli_gcm_read:
    cld
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    cmp  qword [rbx + SSH_C_S2C_IV + 4], -1
    je   .bad
    cmp  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_KEY_PKTS], 0x40000000
    jae  .bad
    mov  ecx, [rbx + SSH_C_RX_LEN]
    cmp  ecx, 4
    jb   .more
    mov  r12d, [rbx + SSH_C_RX]
    bswap r12d
    cmp  r12d, 6
    jb   .bad
    cmp  r12d, SSH_MAX_PACKET
    ja   .bad
    cmp  r12d, SSH_CLI_RK_PLAIN_CAP
    ja   .bad
    lea  eax, [r12d + 20]
    cmp  ecx, eax
    jb   .more
    lea  r14, [rbx + SSH_C_PLAIN]
    cmp  r12d, SSH_C_PLAIN_CAP
    jbe  .plain_ready
    lea  r14, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PLAIN]
.plain_ready:
    lea  rax, [rel ssh_aead_req]
    lea  rcx, [rbx + SSH_C_S2C_KEY]
    mov  [rax + AEAD_KEY], rcx
    lea  rcx, [rbx + SSH_C_S2C_IV]
    mov  [rax + AEAD_NONCE], rcx
    lea  rcx, [rbx + SSH_C_RX]
    mov  [rax + AEAD_AAD], rcx
    mov  qword [rax + AEAD_AAD_LEN], 4
    lea  rcx, [rbx + SSH_C_RX + 4]
    mov  [rax + AEAD_INPUT], rcx
    mov  [rax + AEAD_INPUT_LEN], r12
    mov  [rax + AEAD_OUTPUT], r14
    lea  rcx, [rbx + SSH_C_RX + 4]
    add  rcx, r12
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes256_gcm_open
    test eax, eax
    jnz  .bad
    movzx ecx, byte [r14]
    cmp  ecx, 4
    jb   .bad
    cmp  ecx, r12d
    jae  .bad
    mov  r13d, r12d
    sub  r13d, ecx
    dec  r13d
    lea  rdi, [rbx + SSH_C_S2C_IV]
    call ssh_nonce_inc
    test eax, eax
    jnz  .bad
    lea  esi, [r12d + 20]
    mov  rdi, rbx
    call ssh_rx_consume
    inc  dword [rbx + SSH_C_RX_PACKETS]       ; implicit transport sequence never resets at rekey
    inc  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_KEY_PKTS]
    inc  qword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_TOTAL]
    lea  eax, [r12d + 20]
    add  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_BYTES], rax
    mov  edx, r13d
    lea  rax, [r14 + 1]
    jmp  .out
.more:
    xor  eax, eax
    xor  edx, edx
    jmp  .out
.bad:
    mov  rax, -1
    xor  edx, edx
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Send SERVICE_REQUEST("ssh-userauth") over the encrypted transport. RDI=ctx.
ssh_cli_send_service_request:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel ssh_cli_pkt]
    mov  byte [rdi], SSH_MSG_SERVICE_REQUEST
    lea  rdi, [rel ssh_cli_pkt + 1]
    mov  esi, 12
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_pkt + 5]
    lea  rsi, [rel str_ssh_userauth]
    mov  edx, 12
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_pkt]
    mov  edx, 17
    call ssh_cli_gcm_send                        ; EAX: 0 sent / 1 backpressure / -1 error
    pop  rbx
    ret

; Build + send a publickey USERAUTH_REQUEST signed by the PaOS client ed25519
; key (RFC4252 §7). The signature covers string(session_id) || the request
; up to (not including) the signature field. RDI=ctx -> EAX 0 sent / 1 bp / -1 err.
; A refused identity (not an owner session, not verified) fails the session
; with its typed error (16, 17) instead of retrying.
ssh_cli_send_userauth:
    ; Count entry attempts, including guard refusals. Saturation cannot wrap to
    ; zero; zero proves this dial never entered USERAUTH, not just never sent it.
    cmp  qword [rel ssh_cli_userauth_calls], -1
    je   .entry_observed
    inc  qword [rel ssh_cli_userauth_calls]
.entry_observed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r15d, [rel ssh_sess_active]
    mov  edi, r15d
    call ssh_cli_work_begin
    test eax, eax
    jnz  .work_busy
    call ssh_cli_kh_admission_current
    test eax, eax
    jnz  .trust_refused
    cmp  byte [rel ssh_cli_owner_armed], 1
    jne  .identity_not_owner
    call principal_current
    test rax, rax
    jz   .identity_owner
    cmp  rax, PRIN_OWNER
    jne  .identity_not_owner
.identity_owner:
    call ssh_cli_identity_ensure        ; the client key's 51-byte blob ssh_cli_id_blob
    test eax, eax
    jnz  .id_refused
    ; --- CORE: 50 | str(user) | str("ssh-connection") | str("publickey")
    ;           | bool 1 | str("ssh-ed25519") | str(pkblob 51) ---
    lea  r13, [rel ssh_cli_authcore]
    mov  r12, r13
    mov  byte [r12], SSH_MSG_USERAUTH_REQUEST
    inc  r12
    mov  rdi, r12
    mov  esi, [rel ssh_cli_user_len]
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel ssh_cli_user]
    mov  edx, [rel ssh_cli_user_len]
    call memcpy
    mov  eax, [rel ssh_cli_user_len]
    add  r12, rax
    mov  rdi, r12
    mov  esi, 14
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel str_ssh_connection]
    mov  edx, 14
    call memcpy
    add  r12, 14
    mov  rdi, r12
    mov  esi, 9
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel str_ssh_publickey]
    mov  edx, 9
    call memcpy
    add  r12, 9
    mov  byte [r12], 1                            ; boolean TRUE (signature present)
    inc  r12
    mov  rdi, r12
    mov  esi, 11
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel str_ssh_ed25519]
    mov  edx, 11
    call memcpy
    add  r12, 11
    mov  rdi, r12
    mov  esi, 51
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel ssh_cli_id_blob]
    mov  edx, 51
    call memcpy
    add  r12, 51
    mov  r14, r12
    sub  r14, r13                                 ; r14 = core length
    ; --- signed data = string(session_id 32) || CORE ---
    lea  rdi, [rel ssh_cli_signbuf]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_signbuf + 4]
    lea  rsi, [rbx + SSH_C_SESSION_ID]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel ssh_cli_signbuf + 36]
    lea  rsi, [rel ssh_cli_authcore]
    mov  edx, r14d
    call memcpy
    lea  esi, [r14d + 36]
    call ssh_cli_work_sign
    test eax, eax
    jnz  .work_refused
    ; --- signature blob: string("ssh-ed25519") || string(sig64) -> ssh_cli_sigblob (83) ---
    lea  rdi, [rel ssh_cli_sigblob]
    mov  esi, 11
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_sigblob + 4]
    lea  rsi, [rel str_ssh_ed25519]
    mov  edx, 11
    call memcpy
    lea  rdi, [rel ssh_cli_sigblob + 15]
    mov  esi, 64
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_sigblob + 19]
    lea  rsi, [rel ssh_cli_sig64]
    mov  edx, 64
    call memcpy
    ; --- append string(sigblob 83) to CORE ---
    mov  rdi, r12
    mov  esi, 83
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel ssh_cli_sigblob]
    mov  edx, 83
    call memcpy
    add  r12, 83
    mov  rax, r12
    lea  rcx, [rel ssh_cli_authcore]
    sub  rax, rcx                                 ; total request payload length
    push rax
    call ssh_cli_work_current            ; final live authority before packet use
    test eax, eax
    pop rdx
    jnz .work_refused
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_authcore]
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .out
    xor  eax, eax
    jmp  .out
.trust_refused:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 15
    jmp  .err
.identity_not_owner:
    mov  eax, -1
.id_refused:                                      ; -1 owner/context, -2 unverified, -4 empty, -5 runtime
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 16
    cmp  eax, -1
    je   .id_serial
    mov  byte [rel ssh_cli_error], 17
    cmp  eax, -2
    je   .err
    mov  byte [rel ssh_cli_error], 26
    cmp  eax, -4
    je   .err
    mov  byte [rel ssh_cli_error], 27
    cmp  eax, -5
    je   .err
    mov  byte [rel ssh_cli_error], 5
    jmp  .err
.id_serial:
    lea  rdi, [rel str_sshcli_cid_owner_only_serial]
    call serial_string
    jmp .err
.work_refused:
    mov byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov byte [rel ssh_cli_error], 5
.err:
    mov  eax, -1
.out:
    push rax
    call ssh_cli_cid_cleanup              ; no transient identity material outlives request
    call ssh_cli_work_end
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

.work_busy:
    mov eax, 1                           ; reentrant owner keeps actual custody
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; GAP05: slot-owned generations and original deadlines never travel through
; the loaded/parked region. The crypto result is provisional until this caller
; revalidates its original owner, key, tuple, trust epoch and unchanged D.
; EDI=slot -> RAX=64-byte binding. Caller validates slot first.
ssh_cli_work_binding:
    mov eax, edi
    shl rax, 6
    lea rcx, [rel ssh_sess_bindings]
    add rax, rcx
    ret

; Bind exactly once after Terminal has applied its existing hostname ceiling.
; EDI=slot, RSI=original effective TCP D, RDX=original channel D, RCX=origin.
; No clock sample, renewal or inferred/default budget. EAX0 /-1.
ssh_session_bind_deadlines:
    cmp edi, SSH_SESS_MAX
    jae .bad
    lea rax, [rel ssh_sess_used]
    cmp byte [rax + rdi], 1
    jne .bad
    test rcx, rcx
    jz .bad
    cmp rsi, rcx
    jbe .bad
    cmp rdx, rsi
    jb .bad
    push rbx
    mov rbx, rcx
    call ssh_cli_work_binding
    cmp qword [rax + 8], 0
    je .reject
    cmp qword [rax + 16], 0
    je .reject
    cmp qword [rax + 24], 0
    je .reject
    cmp qword [rax + 32], 0
    je .reject
    cmp qword [rax + 56], 0
    jne .reject
    mov [rax + 48], rsi
    mov [rax + 56], rdx
    lea rax, [rel ssh_sess_clock]
    mov [rax + rdi*8], rbx
    xor eax, eax
    pop rbx
    ret
.reject:
    pop rbx
.bad:
    mov eax, -1
    ret

; EDI=original selected live slot. Exclusive shared USERAUTH builder ownership
; and a separate slot hold last until normal crypto return + caller cleanup.
ssh_cli_work_begin:
    cmp edi, SSH_SESS_MAX
    jae .bad
    cmp byte [rel ssh_cli_work_busy], 0
    jne .bad
    lea rax, [rel ssh_sess_used]
    cmp byte [rax + rdi], 1
    jne .bad
    lea rax, [rel ssh_sess_work_busy]
    cmp byte [rax + rdi], 0
    jne .bad
    push rbx
    mov ebx, edi
    call tcp_client_cookie_alloc
    test rax, rax
    jz .failed
    mov r8, rax
    mov edi, ebx
    call ssh_cli_work_binding
    mov [rax + 40], r8
    lea rcx, [rel ssh_sess_cancel]
    mov edx, ebx
    shl edx, 4
    mov [rcx + rdx], r8
    mov qword [rcx + rdx + 8], 0
    lea rcx, [rel ssh_sess_work_busy]
    mov byte [rcx + rbx], 1
    mov [rel ssh_cli_work_slot], ebx
    mov byte [rel ssh_cli_work_busy], 1
    xor eax, eax
    pop rbx
    ret
.failed:
    pop rbx
.bad:
    mov eax, -1
    ret

; Revoke only this generation; never ACK cancellation or clear live custody.
ssh_cli_work_cancel:
    mov edi, [rel ssh_sess_active]
    cmp edi, SSH_SESS_MAX
    jae .out
    call ssh_cli_work_binding
    mov rdx, [rax + 40]
    mov ecx, edi
    shl ecx, 4
    lea rax, [rel ssh_sess_cancel]
    mov [rax + rcx], rdx
    mov qword [rax + rcx + 8], 1
.out:
    ret

; Forward known monotonic samples only. RAX=current /0 unknown or backward.
ssh_cli_work_clock:
    sub rsp, 8
    call time_monotonic_now_us
    add rsp, 8
    test rax, rax
    jz .bad
    mov ecx, [rel ssh_cli_work_slot]
    lea rdx, [rel ssh_sess_clock]
    cmp rax, [rdx + rcx*8]
    jb .bad
    mov [rdx + rcx*8], rax
    ret
.bad:
    xor eax, eax
    ret

; Exact current original work authority. Independent of the compute component.
; Only bounded read-only TCP observation; no raw TCB pointer dereference here.
ssh_cli_work_current:
    push rbx
    mov ebx, [rel ssh_cli_work_slot]
    cmp ebx, SSH_SESS_MAX
    jae .bad
    cmp ebx, [rel ssh_sess_active]
    jne .bad
    lea rax, [rel ssh_sess_used]
    cmp byte [rax + rbx], 1
    jne .bad
    cmp byte [rel ssh_cli_retiring], 0
    jne .bad
    cmp byte [rel ssh_cli_owner_armed], 1
    jne .bad
    call principal_current
    test rax, rax
    jz .owner
    cmp rax, PRIN_OWNER
    jne .bad
.owner:
    cmp byte [rel ssh_cli_cid_state], SSH_CID_ST_ENROLLED
    jne .bad
    mov eax, [rel ssh_cli_cid_gen]
    cmp rax, [rel ssh_cli_work_cid_gen]
    jne .bad
    lea rdi, [rel ssh_cli_cid_pub]
    lea rsi, [rel ssh_cli_work_public]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    mov rax, [rel ssh_cli_ctx_ptr]
    cmp rax, [rel ssh_cli_work_ctx]
    jne .bad
    mov rax, [rel ssh_cli_kh_epoch]
    cmp rax, [rel ssh_cli_work_kh_epoch]
    jne .bad
    call ssh_cli_kh_admission_current
    test eax, eax
    jnz .bad
    mov edi, ebx
    call ssh_cli_work_binding
    mov rdi, rax
    lea rsi, [rel ssh_cli_work_snapshot]
    mov edx, 64
    call memcmp
    test eax, eax
    jnz .bad
    mov ecx, ebx
    shl ecx, 4
    lea rax, [rel ssh_sess_cancel]
    mov rdx, [rel ssh_cli_work_snapshot + 40]
    cmp rdx, [rax + rcx]
    jne .cancel_ok                     ; another generation cannot cancel us
    cmp qword [rax + rcx + 8], 0
    jne .bad
.cancel_ok:
    mov rdi, [rel ssh_cli_work_snapshot + 16]
    cmp rdi, [rel ssh_cli_tcb]
    jne .bad
    mov rsi, [rel ssh_cli_work_snapshot + 24]
    lea rdx, [rel ssh_cli_work_tcp]
    call tcp_client_epoch_snapshot
    test rax, rax
    jnz .bad
    cmp qword [rel ssh_cli_work_tcp], TCP_ESTABLISHED
    jne .bad
    mov eax, [rel ssh_cli_lport]
    cmp rax, [rel ssh_cli_work_tcp + 56]
    jne .bad
    mov eax, [rel ssh_cli_target_ip]
    cmp rax, [rel ssh_cli_work_tcp + 48]
    jne .bad
    movzx eax, word [rel ssh_cli_target_port]
    cmp rax, [rel ssh_cli_work_tcp + 64]
    jne .bad
    call ssh_cli_work_clock
    test rax, rax
    jz .bad
    cmp rax, [rel ssh_cli_work_snapshot + 56]
    jae .bad
    ; Pre-accounting checks have no earned lease yet. Once earned, keep the
    ; same S/B through result use, final USERAUTH and post-seal publication.
    ; Forward time before D is necessary but does not renew this work's B.
    cmp qword [rel ssh_cli_work_earned_lease_ms], 0
    je .current
    mov rdx, [rel ssh_cli_work_service_bound_us]
    test rdx, rdx
    jz .bad
    sub rax, [rel ssh_cli_work_start_us]
    jc .bad
    cmp rax, rdx
    ja .bad                            ; equality remains eligible
.current:
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, -1
    pop rbx
    ret

; Derived caller accounting, not a new deadline. The two core operands
; are ROOT105740's selected measured-twin policy, not a new caller default.
; They are not a proven metal IRQ/whole-cleanup bound. Zero validity refuses.
; RAX=earned lease ms /0 unavailable; RDX=independently finite service bound us.
ssh_cli_work_account:
    sub rsp, 8
    cmp qword [rel ssh_cli_core_facts_valid], 1
    jne .bad
    call ssh_cli_work_clock
    test rax, rax
    jz .bad
    mov [rel ssh_cli_work_start_us], rax
    mov rdx, [rel ssh_cli_core_interrupt_us]
    add rdx, [rel ssh_cli_core_cleanup_us]
    jc .bad
    test rdx, rdx
    jz .bad                         ; new full-fit entry requires a real reserve
    mov [rel ssh_cli_work_reserve_us], rdx
    mov rcx, [rel ssh_cli_work_snapshot + 56]
    sub rcx, rax
    jbe .bad
    sub rcx, rdx
    jc .bad
    ; ROOT105682/SEC105677: one work earns the existing 100ms ABI ceiling
    ; only when the entire service fits. Never shrink it, renew D or add grace.
    cmp rcx, 100000
    jb .bad
    mov eax, 100
    mov [rel ssh_cli_work_earned_lease_ms], rax
    add rdx, 100000
    jc .bad
    mov [rel ssh_cli_work_service_bound_us], rdx
    add rsp, 8
    ret
.bad:
    xor eax, eax
    xor edx, edx
    add rsp, 8
    ret

; ESI=actual signed message length. Only this caller acquires SYSTEM seed
; material. Public derivation/enrolled comparison/sign all occur in SEC's
; exclusive sensitive fence; no legacy/unfenced fallback.
ssh_cli_work_sign:
    push rbx
    push r12
    push r13
    mov r12d, esi
    cmp r12d, 36
    jb .bad
    cmp r12d, 256
    ja .bad
    mov edi, [rel ssh_cli_work_slot]
    call ssh_cli_work_binding
    mov rsi, rax
    lea rdi, [rel ssh_cli_work_snapshot]
    mov edx, 64
    call memcpy
    mov eax, [rel ssh_cli_cid_gen]
    mov [rel ssh_cli_work_cid_gen], rax
    mov rax, [rel ssh_cli_ctx_ptr]
    mov [rel ssh_cli_work_ctx], rax
    mov rax, [rel ssh_cli_kh_epoch]
    mov [rel ssh_cli_work_kh_epoch], rax
    lea rdi, [rel ssh_cli_work_public]
    lea rsi, [rel ssh_cli_cid_pub]
    mov edx, 32
    call memcpy
    call ssh_cli_work_current
    test eax, eax
    jnz .bad
    lea rdi, [rel ssh_cli_work_capsule]
    lea rsi, [rel ssh_cli_work_snapshot]
    mov edx, 64
    call memcpy
    mov rax, [rel ssh_cli_work_cid_gen]
    mov [rel ssh_cli_work_capsule + SW_CID_GEN], rax
    mov [rel ssh_cli_work_capsule + SW_MSG_LEN], r12
    lea rdi, [rel ssh_cli_work_capsule + SW_EXPECTED]
    lea rsi, [rel ssh_cli_work_public]
    mov edx, 32
    call memcpy
    lea rdi, [rel ssh_cli_work_capsule + SW_MESSAGE]
    lea rsi, [rel ssh_cli_signbuf]
    mov edx, r12d
    call memcpy
    ; Keep the exact public request independently of reentrant shared builders.
    lea rdi, [rel ssh_cli_work_request]
    lea rsi, [rel ssh_cli_signbuf + 36]
    lea edx, [r12d - 36]
    call memcpy
    mov edi, [rel ssh_cli_cid_gen]
    call ssh_cli_cid_derive_seed
    mov ebx, eax
    ; A provider/interrupt may select another session. Restore before touching
    ; its loaded fields; the separate hold prohibits cleanup/reuse meanwhile.
    mov edi, [rel ssh_cli_work_slot]
    call ssh_session_use
    test ebx, ebx
    jnz .bad
    lea rdi, [rel ssh_cli_work_capsule + SW_SEED]
    lea rsi, [rel ssh_cli_cid_seed]
    mov edx, 32
    call memcpy
    call ssh_cli_identity_seed_done       ; source seed wiped BEFORE private compute
    call ssh_cli_work_current
    test eax, eax
    jnz .bad
    call ssh_cli_work_account
    test rax, rax
    jz .bad
    mov r9, rax
    mov edi, [rel ssh_cli_work_slot]
    call ssh_cli_work_binding
    mov rdx, rax
    mov ecx, [rel ssh_cli_work_slot]
    shl ecx, 4
    lea rax, [rel ssh_sess_cancel]
    add rcx, rax
    lea rdi, [rel ssh_cli_work_capsule]
    mov esi, SW_BYTES
    lea r8, [rel ssh_cli_work_result]
    ; SEC's additive ABI: unchanged six arguments plus the exact earned
    ; post-cutoff reserve as seventh SysV argument. Keep call-site alignment.
    sub rsp, 16
    mov rax, [rel ssh_cli_work_reserve_us]
    mov [rsp], rax
    call ssh_crypto_work_fullfit
    add rsp, 16
    mov ebx, eax
    mov r13, rdx
    mov edi, [rel ssh_cli_work_slot]
    call ssh_session_use
    test ebx, ebx
    jnz .bad
    cmp r13, 1                       ; strict delivery observation is necessary,
    jne .bad                         ; never sufficient for the numeric facts
    call ssh_cli_work_current
    test eax, eax
    jnz .bad
    lea rdi, [rel ssh_cli_work_result]
    lea rsi, [rel ssh_cli_work_snapshot]
    mov edx, 64
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel ssh_cli_work_result + 64]
    lea rsi, [rel ssh_cli_work_public]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel ssh_cli_sig64]
    lea rsi, [rel ssh_cli_work_result + 96]
    mov edx, 64
    call memcpy
    lea rdi, [rel ssh_cli_authcore]
    lea rsi, [rel ssh_cli_work_request]
    lea edx, [r12d - 36]
    call memcpy
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual normal return and full caller cleanup precede slot-hold release.
; No peer busy state, persistent identity, pin or shared crypto arena is reset.
ssh_cli_work_end:
    push rbx
    mov ebx, [rel ssh_cli_work_slot]
    mov edi, ebx
    call ssh_session_use
    call ssh_cli_identity_seed_done
    lea rdi, [rel ssh_cli_work_private_begin]
    xor esi, esi
    mov edx, ssh_cli_work_private_end - ssh_cli_work_private_begin
    call memset
    lea rdi, [rel ssh_cli_sigblob]
    xor esi, esi
    mov edx, ssh_cli_hk_digest - ssh_cli_sigblob
    call memset
    lea rax, [rel ssh_sess_work_busy]
    mov byte [rax + rbx], 0
    mov byte [rel ssh_cli_work_busy], 0
    call ssh_cli_retire_apply
    pop rbx
    ret

; ===================== Task3494 interactive channel layer (RFC4254) =====================
; All channel packets ride the encrypted GCM transport via ssh_cli_gcm_send; each
; sender returns EAX 0=sent / 1=backpressure / -1=error so ssh_cli_poll can retry
; without desync (one TCP segment in flight at a time).

; CHANNEL_OPEN("session"): byte90 | str "session" | u32 local_chan | u32 window | u32 maxpkt.
ssh_cli_send_channel_open:
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_CHANNEL_OPEN
    lea  rdi, [rbx + 1]
    mov  esi, 7
    call ssh_be32_store
    lea  rdi, [rbx + 5]
    lea  rsi, [rel str_ch_session]
    mov  edx, 7
    call memcpy
    lea  rdi, [rbx + 12]
    mov  esi, [rel ssh_cli_local_chan]
    call ssh_be32_store
    lea  rdi, [rbx + 16]
    mov  esi, SSH_CH_INIT_WINDOW
    call ssh_be32_store
    lea  rdi, [rbx + 20]
    mov  esi, SSH_CH_MAX_PACKET
    call ssh_be32_store
    mov  rdi, [rel ssh_cli_ctx_ptr]
    mov  rsi, rbx
    mov  edx, 24
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .out
    mov  dword [rel ssh_cli_local_window], SSH_CH_INIT_WINDOW
.out:
    pop  rbx
    ret

; Reset flow state on a new/reused slot and redial, never inherit another
; session's peer limit, credits, EOF or queued interactive bytes.
ssh_cli_flow_reset:
    call ssh_cli_exec_reset
    call ssh_cli_rekey_reset
    call ssh_cli_outcome_clear
    mov  dword [rel ssh_cli_request_failures], 0
    mov  dword [rel ssh_cli_global_failures], 0
    mov  byte [rel ssh_cli_want_close], 0
    mov  byte [rel ssh_cli_close_sent], 0
    mov  qword [rel ssh_cli_control_left], 0
    mov  qword [rel ssh_cli_control_last], 0
    mov  byte [rel ssh_cli_control_armed], 0
    mov  qword [rel ssh_cli_ka_left], 0
    mov  qword [rel ssh_cli_ka_last], 0
    call ssh_cli_handshake_clear
    mov  dword [rel ssh_cli_shell_count], 0
    mov  dword [rel ssh_cli_local_chan], 0
    mov  dword [rel ssh_cli_remote_chan], 0
    mov  dword [rel ssh_cli_local_window], 0
    mov  dword [rel ssh_cli_remote_window], 0
    mov  dword [rel ssh_cli_remote_max_packet], 0
    mov  byte [rel ssh_cli_peer_eof], 0
    mov  byte [rel ssh_cli_want_winadj], 0
    mov  dword [rel ssh_cli_txq_head], 0
    mov  dword [rel ssh_cli_txq_tail], 0
    mov  dword [rel ssh_cli_txq_len], 0
    ret

; RFC4254 section 5: channel IDs are recipient IDs and credits are uint32.
; Invalid framing/identity/lifecycle/limits fail this connection locally with
; error18; the Terminal retires it and normal disconnect/redial drops the tuple.
; No malformed packet earns delivery, credit or keepalive activity. We support
; only EXTENDED_DATA_STDERR; unknown extended types also fail explicitly.
ssh_cli_channel_fault:
    mov  dword [rel ssh_cli_request_failures], 0
    mov  dword [rel ssh_cli_global_failures], 0
    mov  byte [rel ssh_cli_want_close], 0
    call ssh_cli_handshake_clear
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 18
    mov  byte [rel ssh_cli_want_winadj], 0
    call ssh_cli_retire
    mov  eax, -1
    ret

; RDI=packet, ESI=length (at least5 checked by caller). Preserve arguments;
; EAX=0 only for the current confirmed live channel. No state mutation here.
ssh_cli_channel_live:
    cmp  qword [rel ssh_cli_ctx_ptr], 0
    je   .bad
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .bad
    movzx eax, byte [rel ssh_cli_state]
    cmp  eax, SSH_CLI_ST_CH_OPEN
    je   .identity
    cmp  eax, SSH_CLI_ST_SHELL
    je   .identity
    cmp  eax, SSH_CLI_ST_EXEC
    jne  .bad
.identity:
    mov  eax, [rdi + 1]
    bswap eax
    cmp  eax, [rel ssh_cli_local_chan]
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Parse fixed session CHANNEL_OPEN_CONFIRMATION (no type-specific fields).
; Any nonzero uint32 peer maximum is valid, including above our send capacity;
; outgoing chunks are bounded by both that maximum and our local builder.
ssh_cli_channel_confirm:
    push rbx
    mov  rbx, rdi
    cmp  esi, 17
    jne  .bad
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN_SENT
    jne  .bad
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .bad
    cmp  qword [rel ssh_cli_ctx_ptr], 0
    je   .bad
    mov  eax, [rbx + 1]
    bswap eax
    cmp  eax, [rel ssh_cli_local_chan]
    jne  .bad
    mov  eax, [rbx + 13]
    bswap eax
    test eax, eax
    jz   .bad
    mov  [rel ssh_cli_remote_max_packet], eax
    mov  eax, [rbx + 5]
    bswap eax
    mov  [rel ssh_cli_remote_chan], eax
    mov  eax, [rbx + 9]
    bswap eax
    mov  [rel ssh_cli_remote_window], eax
    call ssh_cli_handshake_clear
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    call ssh_cli_is_exec
    test eax, eax
    jz   .interactive
    mov  rax, [rel ssh_cli_ctx_ptr]
    mov  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_WANT], 1
    jmp  .confirmed
.interactive:
    mov  byte [rel ssh_cli_want_pty], 1
.confirmed:
    lea  rdi, [rel str_sshcli_chopen]
    call serial_string
    jmp  .done
.bad:
    call ssh_cli_channel_fault
.done:
    pop  rbx
    ret

; Outstanding channel requests are untagged on the wire (RFC4254 5.4).
; Serialize them per saved session; only the currently awaited reply can advance
; the handshake. A response cannot prove a request-specific identity beyond that
; ordered phase: no invented wire ID or cross-connection authority is introduced.
ssh_cli_handshake_clear:
    call ssh_cli_exec_clear_request
    mov  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    mov  byte [rel ssh_cli_want_pty], 0
    mov  byte [rel ssh_cli_want_shell], 0
    ret

; Exact CHANNEL_SUCCESS/FAILURE for this confirmed channel and outstanding phase.
; No response is allowed before an accepted send or after completion/retirement.
ssh_cli_channel_reply:
    cmp  esi, 5
    jne  ssh_cli_channel_fault
    call ssh_cli_channel_live
    test eax, eax
    jnz  ssh_cli_channel_fault
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    jne  ssh_cli_channel_fault
    cmp  byte [rel ssh_cli_chan_ready], 0
    jne  ssh_cli_channel_fault
    movzx edx, byte [rel ssh_cli_request_pending]
    cmp  edx, SSH_CLI_REQ_PTY
    je   .phase
    cmp  edx, SSH_CLI_REQ_SHELL
    je   .phase
    cmp  edx, SSH_CLI_REQ_EXEC
    jne  ssh_cli_channel_fault
    mov  rax, [rel ssh_cli_ctx_ptr]
    cmp  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_SENT], 1
    jne  ssh_cli_channel_fault
    call ssh_cli_exec_check
    test eax, eax
    js   .out
.phase:
    cmp  byte [rdi], SSH_MSG_CHANNEL_FAILURE
    je   .refused
    cmp  byte [rdi], SSH_MSG_CHANNEL_SUCCESS
    jne  ssh_cli_channel_fault
    mov  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    cmp  edx, SSH_CLI_REQ_EXEC
    je   .exec
    cmp  edx, SSH_CLI_REQ_PTY
    jne  .shell
    mov  byte [rel ssh_cli_want_shell], 1
    xor  eax, eax
    ret
.shell:
    mov  byte [rel ssh_cli_chan_ready], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_SHELL
    inc  dword [rel ssh_cli_shell_count]  ; accepted shells, never transport attempts
    call ssh_cli_rearm_keepalive
    lea  rdi, [rel str_sshcli_shell]
    call serial_string
    xor  eax, eax
    ret
.exec:
    mov  rax, [rel ssh_cli_ctx_ptr]
    mov  edx, [rel ssh_cli_local_chan]
    mov  [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LOCAL], edx
    mov  edx, [rel ssh_cli_remote_chan]
    mov  [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_REMOTE], edx
    cmp  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_STREAM], 1
    je   .exec_ready
    mov  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_EOF], 1
.exec_ready:
    mov  byte [rel ssh_cli_chan_ready], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    call ssh_cli_rearm_keepalive
    xor  eax, eax
    ret
.refused:
    push rdx
    call ssh_cli_channel_fault
    pop  rdx
    mov  byte [rel ssh_cli_error], 19
    cmp  edx, SSH_CLI_REQ_PTY
    je   .out
    mov  byte [rel ssh_cli_error], 20
    cmp  edx, SSH_CLI_REQ_EXEC
    jne  .out
    mov  byte [rel ssh_cli_error], 22
.out:
    mov  eax, -1
    ret

; CHANNEL_REQUEST "pty-req": byte98 | u32 rchan | str "pty-req" | bool0 | str TERM | u32 cols|rows|wpx|hpx | str modes(empty).
ssh_cli_send_pty_req:
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    jne  .bp
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    jne  .err
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .err
    cmp  byte [rel ssh_cli_want_pty], 1
    jne  .err
    push rbx
    push r12
    lea  rbx, [rel ssh_cli_chpkt]
    mov  r12, rbx
    mov  byte [r12], SSH_MSG_CHANNEL_REQUEST
    inc  r12
    mov  rdi, r12
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    mov  esi, 7
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel str_ch_ptyreq]
    mov  edx, 7
    call memcpy
    add  r12, 7
    mov  byte [r12], 1                 ; require a peer PTY acknowledgment
    inc  r12
    mov  rdi, r12
    mov  esi, 14
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel str_ch_term]
    mov  edx, 14
    call memcpy
    add  r12, 14
    mov  rdi, r12
    mov  esi, [rel ssh_cli_term_cols]
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    mov  esi, [rel ssh_cli_term_rows]
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    xor  esi, esi
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    xor  esi, esi
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    xor  esi, esi
    call ssh_be32_store                          ; modes: empty string
    add  r12, 4
    mov  rax, r12
    lea  rcx, [rel ssh_cli_chpkt]
    sub  rax, rcx
    mov  rdi, [rel ssh_cli_ctx_ptr]
    lea  rsi, [rel ssh_cli_chpkt]
    mov  edx, eax
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .out
    mov  byte [rel ssh_cli_want_pty], 0
    mov  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_PTY
.out:
    pop  r12
    pop  rbx
    ret
.bp:
    mov  eax, 1                         ; one request already awaits its reply
    ret
.err:
    mov  eax, -1
    ret

; CHANNEL_REQUEST "shell": byte98 | u32 rchan | str "shell" | bool0.
ssh_cli_send_shell:
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    jne  .bp
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    jne  .err
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .err
    cmp  byte [rel ssh_cli_want_shell], 1
    jne  .err
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_CHANNEL_REQUEST
    lea  rdi, [rbx + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    lea  rdi, [rbx + 5]
    mov  esi, 5
    call ssh_be32_store
    lea  rdi, [rbx + 9]
    lea  rsi, [rel str_ch_shell]
    mov  edx, 5
    call memcpy
    mov  byte [rbx + 14], 1             ; require a peer shell acknowledgment
    mov  rdi, [rel ssh_cli_ctx_ptr]
    mov  rsi, rbx
    mov  edx, 15
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .out
    mov  byte [rel ssh_cli_want_shell], 0
    mov  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_SHELL
.out:
    pop  rbx
    ret
.bp:
    mov  eax, 1                         ; one request already awaits its reply
    ret
.err:
    mov  eax, -1
    ret

; Deliver inbound channel bytes (RDI=data, ESI=len): to the registered sink, else serial.
ssh_cli_deliver_data:
    mov  rax, [rel ssh_cli_data_sink]
    test rax, rax
    jz   .serialdump
    push rbx
    mov  ebx, [rel ssh_sess_active]
    call rax                                      ; sink may end/switch its session
    mov  edi, ebx
    call ssh_session_use                          ; caller resumes in its own region
    pop  rbx
    ret
.serialdump:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
.sd_loop:
    test r12d, r12d
    jz   .sd_out
    movzx edi, byte [rbx]
    call serial_char
    inc  rbx
    dec  r12d
    jmp  .sd_loop
.sd_out:
    pop  r12
    pop  rbx
    ret

; Debit only fully admitted data. Guard again at this seam: unsigned
; underflow must never turn a refused packet into fresh receive credit.
ssh_cli_window_consume:
    mov  eax, [rel ssh_cli_local_window]
    cmp  eax, edi
    jb   ssh_cli_channel_fault
    sub  eax, edi
    mov  [rel ssh_cli_local_window], eax
    cmp  eax, SSH_CH_LOW_WATER
    jae  .ok
    mov  byte [rel ssh_cli_want_winadj], 1
.ok:
    xor  eax, eax
    ret

; Credit is advertised only after the adjustment is accepted by transport.
; Backpressure leaves both debit and retry flag truthful; poll retries the
; current deficit, including any additional accepted packets in the meantime.
ssh_cli_replenish_window:
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .out
    cmp  byte [rel ssh_cli_peer_eof], 0
    jne  .out
    movzx eax, byte [rel ssh_cli_state]
    cmp  eax, SSH_CLI_ST_CH_OPEN
    je   .live
    cmp  eax, SSH_CLI_ST_SHELL
    je   .live
    cmp  eax, SSH_CLI_ST_EXEC
    jne  .out
.live:
    mov  edi, SSH_CH_INIT_WINDOW
    cmp  [rel ssh_cli_local_window], edi
    jae  .out
    sub  edi, [rel ssh_cli_local_window]
    call ssh_cli_send_window_adjust
    test eax, eax
    js   ssh_cli_channel_fault
    jnz  .defer
    mov  dword [rel ssh_cli_local_window], SSH_CH_INIT_WINDOW
    mov  byte [rel ssh_cli_want_winadj], 0
    ret
.defer:
    mov  byte [rel ssh_cli_want_winadj], 1
.out:
    ret

; CHANNEL_WINDOW_ADJUST send: byte93 | u32 rchan | u32 bytes_to_add. EDI=bytes.
ssh_cli_send_window_adjust:
    push rbx
    push r12
    mov  r12d, edi
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_CHANNEL_WINDOW_ADJUST
    lea  rdi, [rbx + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    lea  rdi, [rbx + 5]
    mov  esi, r12d
    call ssh_be32_store
    mov  rdi, [rel ssh_cli_ctx_ptr]
    mov  rsi, rbx
    mov  edx, 9
    call ssh_cli_gcm_send
    pop  r12
    pop  rbx
    ret

; Parse CHANNEL_DATA: byte94 | u32 recipient | u32 datalen | data.
ssh_cli_channel_data:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r13d, esi
    cmp  r13d, 9
    jb   .bad
    call ssh_cli_channel_live
    test eax, eax
    jnz  .bad
    cmp  byte [rel ssh_cli_peer_eof], 0
    jne  .bad
    mov  r12d, [rbx + 5]
    bswap r12d
    lea  rax, [r12 + 9]           ; hostile uint32 length cannot wrap
    cmp  rax, r13
    jne  .bad                          ; exact payload, no trailing fields
    cmp  r12d, SSH_CH_MAX_PACKET
    ja   .bad
    mov  edi, r12d
    call ssh_cli_window_consume
    test eax, eax
    jnz  .done
    lea  rdi, [rbx + 9]
    mov  esi, r12d
    call ssh_cli_deliver_data
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .done
    call ssh_cli_rearm_keepalive
    ; GCM sends overwrite SSH_C_PLAIN: replenish only after sink delivery.
    cmp  byte [rel ssh_cli_want_winadj], 1
    jne  .done
    call ssh_cli_replenish_window
    jmp  .done
.bad:
    call ssh_cli_channel_fault
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Parse CHANNEL_EXTENDED_DATA: byte95 | u32 recipient | u32 type | u32 datalen | data (stderr).
ssh_cli_channel_extdata:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r13d, esi
    cmp  r13d, 13
    jb   .bad
    call ssh_cli_channel_live
    test eax, eax
    jnz  .bad
    cmp  byte [rel ssh_cli_peer_eof], 0
    jne  .bad
    cmp  dword [rbx + 5], 0x01000000   ; SSH_EXTENDED_DATA_STDERR (network order)
    jne  .bad
    mov  r12d, [rbx + 9]
    bswap r12d
    lea  rax, [r12 + 13]           ; hostile uint32 length cannot wrap
    cmp  rax, r13
    jne  .bad                          ; exact payload, no trailing fields
    cmp  r12d, SSH_CH_MAX_PACKET
    ja   .bad
    mov  edi, r12d
    call ssh_cli_window_consume
    test eax, eax
    jnz  .done
    lea  rdi, [rbx + 13]
    mov  esi, r12d
    call ssh_cli_deliver_data
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .done
    call ssh_cli_rearm_keepalive
    ; GCM sends overwrite SSH_C_PLAIN: replenish only after sink delivery.
    cmp  byte [rel ssh_cli_want_winadj], 1
    jne  .done
    call ssh_cli_replenish_window
    jmp  .done
.bad:
    call ssh_cli_channel_fault
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Remote outcome is observational only: it never closes the channel, changes
; authority or cancels queued output. First valid outcome publishes kind last;
; any duplicate/conflict is a protocol failure, retaining the original record
; for diagnostics but never presenting it as a clean completion after an error.
; RFC4254 6.10 requires want_reply=FALSE for both exit notifications.
ssh_cli_channel_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48                        ; validated string spans, never partial global state
    mov  rbx, rdi
    mov  r12d, esi
    cmp  esi, 10
    jb   .bad
    call ssh_cli_channel_live
    test eax, eax
    jnz  .bad
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_SHELL
    je   .running
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_EXEC
    jne  .bad
.running:
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .bad
    mov  eax, [rbx + 5]
    bswap eax
    lea  r13, [rax + 10]                ; uint32 name extent cannot wrap
    cmp  r13, r12
    ja   .bad
    cmp  byte [rbx + r13 - 1], 1
    ja   .bad
    cmp  eax, 11
    jne  .unknown
    lea  rdi, [rbx + 9]
    lea  rsi, [rel str_ch_exit_status]
    mov  edx, 11
    call memcmp
    test eax, eax
    jz   .status
    lea  rdi, [rbx + 9]
    lea  rsi, [rel str_ch_exit_signal]
    mov  edx, 11
    call memcmp
    test eax, eax
    jz   .signal
.unknown:
    cmp  byte [rbx + r13 - 1], 0
    je   .done                          ; unknown no-reply notification is ignored
    cmp  dword [rel ssh_cli_request_failures], SSH_REQUEST_FAILURE_CAP
    jae  .bad                           ; bounded refusal, never silent reply loss
    inc  dword [rel ssh_cli_request_failures]
    call ssh_cli_flush_control
    jmp  .done
.status:
    cmp  byte [rbx + r13 - 1], 0
    jne  .bad
    add  r13, 4
    cmp  r13, r12
    jne  .bad
    cmp  dword [rel ssh_cli_exit_kind], 0
    jne  .bad
    mov  eax, [rbx + r13 - 4]
    bswap eax
    mov  [rel ssh_cli_exit_status], eax
    mov  dword [rel ssh_cli_exit_kind], 1
    jmp  .done
.signal:
    cmp  byte [rbx + r13 - 1], 0
    jne  .bad
    lea  rdi, [rbx + r13]
    add  r12, rbx                       ; end pointer for all checked spans
    mov  rdx, r12
    mov  ecx, SSH_EXIT_SIGNAL_CAP
    call ssh_cli_exit_string
    jc   .bad
    test r8d, r8d
    jz   .bad                           ; no empty signal name
    mov  [rsp], rax
    mov  [rsp + 8], r8d
    cmp  rdi, r12
    jae  .bad
    movzx eax, byte [rdi]
    cmp  eax, 1
    ja   .bad
    mov  [rsp + 12], eax
    inc  rdi
    mov  rdx, r12
    mov  ecx, SSH_EXIT_MESSAGE_CAP
    call ssh_cli_exit_string
    jc   .bad
    mov  [rsp + 16], rax
    mov  [rsp + 24], r8d
    mov  rdx, r12
    mov  ecx, SSH_EXIT_LANGUAGE_CAP
    call ssh_cli_exit_string
    jc   .bad
    mov  [rsp + 32], rax
    mov  [rsp + 40], r8d
    cmp  rdi, r12
    jne  .bad                           ; complete exact request, no trailing data
    cmp  dword [rel ssh_cli_exit_kind], 0
    jne  .bad
    lea  rdi, [rel ssh_cli_exit_signal]
    mov  rsi, [rsp]
    mov  edx, [rsp + 8]
    mov  [rel ssh_cli_exit_signal_len], edx
    call memcpy
    lea  rdi, [rel ssh_cli_exit_message]
    mov  rsi, [rsp + 16]
    mov  edx, [rsp + 24]
    mov  [rel ssh_cli_exit_message_len], edx
    call memcpy
    lea  rdi, [rel ssh_cli_exit_language]
    mov  rsi, [rsp + 32]
    mov  edx, [rsp + 40]
    mov  [rel ssh_cli_exit_language_len], edx
    call memcpy
    mov  eax, [rsp + 12]
    mov  [rel ssh_cli_exit_core], eax
    mov  dword [rel ssh_cli_exit_kind], 2 ; publish only after every field is validated/copied
    jmp  .done
.bad:
    call ssh_cli_channel_fault
.done:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=cursor, RDX=end, ECX=owned capacity -> CF=0, RAX=bytes, R8D=len,
; RDI=next. No data read until its exact span is checked; uint32 addition in64.
ssh_cli_exit_string:
    lea  rax, [rdi + 4]
    cmp  rax, rdx
    ja   .bad
    mov  r8d, [rdi]
    bswap r8d
    cmp  r8d, ecx
    ja   .bad
    lea  r9, [rax + r8]
    cmp  r9, rdx
    ja   .bad
    mov  rdi, r9
    clc
    ret
.bad:
    stc
    ret

; A final record survives EOF/CLOSE until its owner reads it, then teardown,
; reconnect and reused slots wipe the complete bounded record, including bytes.
ssh_cli_outcome_clear:
    lea  rdi, [rel ssh_cli_exit_begin]
    mov  ecx, ssh_cli_exit_end - ssh_cli_exit_begin
    xor  eax, eax
    cld
    rep  stosb
    ret

; Ordered CHANNEL_FAILURE responses share one recipient/message shape, so a
; bounded count is sufficient. They precede the CLOSE echo even under pressure.
; On peer CLOSE, three seconds bounds drain; expiry/transport failure is an
; explicit connection error, never reported as clean remote completion.
ssh_cli_flush_control:
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .none
    cmp  byte [rel ssh_cli_want_close], 1
    jne  .pending
    call time_monotonic_now_us
    lea  rdi, [rel ssh_cli_control_left]
    call ssh_cli_timer_step
    test rax, rax
    jz   ssh_cli_channel_fault
.pending:
    cmp  dword [rel ssh_cli_global_failures], 0
    jne  .global_failure
    cmp  dword [rel ssh_cli_request_failures], 0
    jne  .failure
    cmp  byte [rel ssh_cli_want_close], 1
    jne  .none
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_CHANNEL_CLOSE
    jmp  .send
.global_failure:
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_REQUEST_FAILURE
    mov  edx, 1
    jmp  .send_record
.failure:
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_CHANNEL_FAILURE
.send:
    lea  rdi, [rbx + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    mov  edx, 5
.send_record:
    mov  rdi, [rel ssh_cli_ctx_ptr]
    mov  rsi, rbx
    call ssh_cli_gcm_send
    pop  rbx
    test eax, eax
    js   ssh_cli_channel_fault
    jnz  .out                           ; accepted-send counters only
    cmp  dword [rel ssh_cli_global_failures], 0
    je   .channel_control
    dec  dword [rel ssh_cli_global_failures]
    jmp  ssh_cli_retire_apply
.channel_control:
    cmp  dword [rel ssh_cli_request_failures], 0
    je   .closed
    dec  dword [rel ssh_cli_request_failures]
    jmp  ssh_cli_retire_apply
.closed:
    mov  byte [rel ssh_cli_want_close], 0
    mov  byte [rel ssh_cli_close_sent], 1
    call ssh_cli_retire_apply
.none:
    xor  eax, eax
.out:
    push rax
    call ssh_cli_retire_apply
    pop  rax
    ret

; Parse CHANNEL_WINDOW_ADJUST: byte93 | u32 recipient | u32 bytes_to_add -> grow send window.
ssh_cli_channel_winadjust:
    cmp  esi, 9
    jne  ssh_cli_channel_fault
    call ssh_cli_channel_live
    test eax, eax
    jnz  ssh_cli_channel_fault
    mov  eax, [rdi + 5]
    bswap eax
    add  eax, [rel ssh_cli_remote_window]
    jc   ssh_cli_channel_fault          ; RFC4254: MUST NOT exceed uint32
    mov  [rel ssh_cli_remote_window], eax
    ret

; EOF closes only the incoming direction; output and WINDOW_ADJUST remain
; valid. Its identity/length must pass before marking this session half-closed.
ssh_cli_channel_eof:
    cmp  esi, 5
    jne  ssh_cli_channel_fault
    call ssh_cli_channel_live
    test eax, eax
    jnz  ssh_cli_channel_fault
    mov  byte [rel ssh_cli_peer_eof], 1
    mov  byte [rel ssh_cli_want_winadj], 0
    ret

; Peer CLOSE: stop new data now, but drain ordered request responses and the
; close echo before Terminal teardown. A local CLOSE acknowledgement is inert.
ssh_cli_channel_closed:
    cmp  esi, 5
    jne  ssh_cli_channel_fault
    cmp  byte [rel ssh_cli_chan_closed], 1
    jne  .live
    mov  eax, [rdi + 1]
    bswap eax
    cmp  eax, [rel ssh_cli_local_chan]
    jne  ssh_cli_channel_fault
    ret
.live:
    call ssh_cli_channel_live
    test eax, eax
    jnz  ssh_cli_channel_fault
    call ssh_cli_handshake_clear
    mov  byte [rel ssh_cli_want_winadj], 0
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  byte [rel ssh_cli_want_close], 1
    call ssh_cli_arm_control
    call ssh_cli_retire                  ; block new work, preserve ordered close key
    call ssh_cli_flush_control
    lea  rdi, [rel str_sshcli_chclose]
    call serial_string
    ret

; Answer a GLOBAL_REQUEST that set want_reply=1 with REQUEST_FAILURE (keeps the peer in step).
ssh_cli_global_request:
    push rbx
    mov  rbx, rdi
    cmp  esi, 5
    jb   .done
    mov  eax, [rbx + 1]
    bswap eax                                     ; request-name length
    lea  rdx, [rax + 5]                           ; 64-bit: a hostile length cannot wrap
    mov  ecx, esi
    cmp  rdx, rcx
    jae  .done
    mov  r8, rbx
    add  r8, 5
    add  r8, rax                                  ; -> want_reply byte
    cmp  byte [r8], 1
    jne  .done
    mov  rbx, [rel ssh_cli_ctx_ptr]
    cmp  dword [rel ssh_cli_global_failures], SSH_REQUEST_FAILURE_CAP
    jae  .overflow
    inc  dword [rel ssh_cli_global_failures]
    jmp  .done
.overflow:
    call ssh_cli_rekey_fault
.done:
    pop  rbx
    ret

; PUBLIC: send interactive bytes to the remote shell. RDI=data, ESI=len.
; EAX 0=sent / 1=backpressure(retry) / -1=error/not-ready. Respects the send window.
ssh_cli_send_channel_data:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .err
    cmp  byte [rel ssh_cli_chan_closed], 0
    jne  .err
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_SHELL
    jne  .err
    test r13d, r13d
    jz   .err
    cmp  r13d, 200
    ja   .err
    cmp  r13d, [rel ssh_cli_remote_max_packet]
    ja   .bp
    mov  eax, [rel ssh_cli_remote_window]
    cmp  eax, r13d
    jb   .bp
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_CHANNEL_DATA
    lea  rdi, [rbx + 1]
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    lea  rdi, [rbx + 5]
    mov  esi, r13d
    call ssh_be32_store
    lea  rdi, [rbx + 9]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  r8d, [r13d + 9]
    mov  rdi, [rel ssh_cli_ctx_ptr]
    mov  rsi, rbx
    mov  edx, r8d
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .out
    sub  [rel ssh_cli_remote_window], r13d
    call ssh_cli_rearm_keepalive
    xor  eax, eax
    jmp  .out
.bp:
    mov  eax, 1
    jmp  .out
.err:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; PUBLIC: SIGWINCH -> CHANNEL_REQUEST "window-change". EDI=cols, ESI=rows.
ssh_cli_send_window_change:
    call ssh_cli_is_exec
    test eax, eax
    jz   .interactive
    mov  eax, 1
    ret
.interactive:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, edi
    mov  r14d, esi
    mov  [rel ssh_cli_term_cols], r13d
    mov  [rel ssh_cli_term_rows], r14d
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .err
    lea  rbx, [rel ssh_cli_chpkt]
    mov  r12, rbx
    mov  byte [r12], SSH_MSG_CHANNEL_REQUEST
    inc  r12
    mov  rdi, r12
    mov  esi, [rel ssh_cli_remote_chan]
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    mov  esi, 13
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    lea  rsi, [rel str_ch_winch]
    mov  edx, 13
    call memcpy
    add  r12, 13
    mov  byte [r12], 0
    inc  r12
    mov  rdi, r12
    mov  esi, r13d
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    mov  esi, r14d
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    xor  esi, esi
    call ssh_be32_store
    add  r12, 4
    mov  rdi, r12
    xor  esi, esi
    call ssh_be32_store
    add  r12, 4
    mov  rax, r12
    lea  rcx, [rel ssh_cli_chpkt]
    sub  rax, rcx
    mov  rdi, [rel ssh_cli_ctx_ptr]
    lea  rsi, [rel ssh_cli_chpkt]
    mov  edx, eax
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .out
    inc  dword [rel ssh_cli_winch_count]
    xor  eax, eax
    jmp  .out
.err:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; PUBLIC: queue interactive input bytes (RDI=data, ESI=len) for the remote shell.
; ssh_cli_poll drains this respecting one-segment-in-flight TCP pacing, so no
; keystroke is dropped during rapid typing. Bounded ring; overflow drops tail.
ssh_cli_enqueue_input:
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .retired
    cmp  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_LEN], 0
    jne  .retired
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .retired
    cmp  qword [rel ssh_cli_ctx_ptr], 0
    je   .retired
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    mov  ebx, [rel ssh_cli_txq_len]
    mov  r8, [rel ssh_cli_ctx_ptr]        ; the ring is in this session's heap slot
    add  r8, SSH_CLI_SLOT_TXQ
.q:
    test r13d, r13d
    jz   .done
    cmp  ebx, SSH_TXQ_CAP
    jae  .done
    mov  eax, [rel ssh_cli_txq_tail]
    mov  cl, [r12]
    mov  [r8 + rax], cl
    inc  eax
    and  eax, SSH_TXQ_CAP - 1
    mov  [rel ssh_cli_txq_tail], eax
    inc  ebx
    inc  r12
    dec  r13d
    jmp  .q
.done:
    mov  [rel ssh_cli_txq_len], ebx
    pop  r13
    pop  r12
    pop  rbx
.retired:
    ret

; Drain one chunk of queued input to the remote shell (called each poll tick).
ssh_cli_drain_txq:
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .out
    mov  ecx, [rel ssh_cli_txq_len]
    test ecx, ecx
    jz   .out
    cmp  ecx, 180
    jbe  .n_ok
    mov  ecx, 180
.n_ok:
    cmp  ecx, [rel ssh_cli_remote_max_packet]
    jbe  .peer_ok
    mov  ecx, [rel ssh_cli_remote_max_packet]
.peer_ok:
    cmp  ecx, [rel ssh_cli_remote_window]
    jbe  .window_ok
    mov  ecx, [rel ssh_cli_remote_window]
.window_ok:
    test ecx, ecx
    jz   .out
    push rbx
    push r12
    push r13
    mov  r13d, ecx
    mov  eax, [rel ssh_cli_txq_head]
    xor  r12d, r12d
    mov  r8, [rel ssh_cli_ctx_ptr]        ; the ring is in this session's heap slot
    add  r8, SSH_CLI_SLOT_TXQ
    lea  r9, [rel ssh_cli_txtmp]
.cp:
    cmp  r12d, r13d
    jae  .cpd
    mov  cl, [r8 + rax]
    mov  [r9 + r12], cl
    inc  eax
    and  eax, SSH_TXQ_CAP - 1
    inc  r12d
    jmp  .cp
.cpd:
    lea  rdi, [rel ssh_cli_txtmp]
    mov  esi, r13d
    call ssh_cli_send_channel_data
    test eax, eax
    jz   .sent
    jns  .cp_out                                 ; bounded backpressure: keep queued
    call ssh_cli_transport_lost
    jmp  .cp_out
.sent:
    mov  eax, [rel ssh_cli_txq_head]
    add  eax, r13d
    and  eax, SSH_TXQ_CAP - 1
    mov  [rel ssh_cli_txq_head], eax
    sub  [rel ssh_cli_txq_len], r13d
.cp_out:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; Idle keepalive (F24 stability): periodically send GLOBAL_REQUEST
; "keepalive@openssh.com" want_reply=1; the server's REQUEST_SUCCESS proves the
; link is alive over long idle periods. Driven by bounded monotonic duration so
; a fast bare-metal poll loop cannot flood encrypted transport packets.
ssh_cli_send_keepalive:
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  byte [rbx], SSH_MSG_GLOBAL_REQUEST
    lea  rdi, [rbx + 1]
    mov  esi, 21
    call ssh_be32_store
    lea  rdi, [rbx + 5]
    lea  rsi, [rel str_ka_name]
    mov  edx, 21
    call memcpy
    mov  byte [rbx + 26], 1                       ; want_reply = true
    mov  rdi, [rel ssh_cli_ctx_ptr]
    mov  rsi, rbx
    mov  edx, 27
    call ssh_cli_gcm_send
    test eax, eax
    jnz  .done
    inc  dword [rel ssh_cli_keepalive_count]
.done:
    pop  rbx
    ret

; A dead TCP tuple cannot deliver CHANNEL_CLOSE. Publish the equivalent local
; channel lifecycle edge so the console can detach and a fresh dial can start.
; The dead tuple has already left ESTABLISHED; never dereference/abort its slot.
ssh_cli_transport_lost:
    mov  dword [rel ssh_cli_request_failures], 0
    mov  dword [rel ssh_cli_global_failures], 0
    mov  byte [rel ssh_cli_want_close], 0
    call ssh_cli_handshake_clear
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 6
    mov  qword [rel ssh_cli_tcb], 0
    mov  dword [rel ssh_cli_txq_head], 0
    mov  dword [rel ssh_cli_txq_tail], 0
    mov  dword [rel ssh_cli_txq_len], 0
    call ssh_cli_retire
    lea  rdi, [rel str_sshcli_transport_lost]
    call serial_string
    ret

; ssh_cli_check_tcb: 2026-09-29 (catalogue SSH-08). The loaded session's TCP
; connection ended underneath it (refused, reset, reaped: TCP freed the TCB, or
; it now holds another connection): fail at once instead of waiting out the
; Terminal's dial budget or the next keepalive. Errors: 10 not established, 13 lost.
ssh_cli_check_tcb:
    mov  rax, [rel ssh_cli_tcb]
    test rax, rax
    jz   .out
    cmp  byte [rel ssh_cli_chan_closed], 1
    je   .out                           ; the channel already closed in order
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .out
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_IDLE
    je   .out
    cmp  byte [rax + TCB_STATE], 0
    je   .lost                          ; freed
    movzx ecx, word [rax + TCB_LOCAL_PORT]
    cmp  ecx, [rel ssh_cli_lport]
    jne  .lost                          ; freed and reused by another connection
    cmp  byte [rax + TCB_STATE], TCP_REAP_PENDING
    je   .lost
    cmp  byte [rax + TCB_STATE], TCP_ESTABLISHED
    je   .out
    cmp  byte [rax + TCB_STATE], TCP_SYN_SENT
    je   .out
.lost:
    ; Hub TCP frees a tuple without recording why. Before the handshake this
    ; can include SYN retry exhaustion or reset: error10 means not established,
    ; with no supported refusal/server diagnosis. After handshake: lost (13).
    mov  qword [rel ssh_cli_tcb], 0     ; never touch that slot again
    mov  ecx, 13
    cmp  byte [rel ssh_cli_tcp_seen], 1
    je   .coded
    mov  ecx, 10
.coded:
    push rcx
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .connect_phase
    call ssh_cli_transport_lost         ; an open session: the Terminal reports it closed
    jmp  .code
.connect_phase:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  dword [rel ssh_cli_txq_head], 0
    mov  dword [rel ssh_cli_txq_tail], 0
    mov  dword [rel ssh_cli_txq_len], 0
.code:
    pop  rcx
    mov  [rel ssh_cli_error], cl
    call ssh_cli_retire
    lea  rdi, [rel str_sshcli_tcp_ended]
    call serial_string
.out:
    ret

; Idle-tick driver for deferred client sends (ssh_sessions_poll, per session).
; Retries the encrypted SERVICE_REQUEST until tcp_send accepts it (no nonce burn
; on backpressure), so it is never wedged behind the in-flight NEWKEYS segment.
ssh_cli_poll:
    cld
    call ssh_cli_check_tcb
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    jne  .retirement
    call ssh_cli_retire
.retirement:
    call ssh_cli_exec_check
    test eax, eax
    js   .out
    call ssh_cli_rekey_poll
    test eax, eax
    jnz  .out
    cmp  byte [rel ssh_cli_retiring], 1
    je   .controls                      ; only owed controls, never sign/input/receive
    cmp  dword [rel ssh_cli_global_failures], 0
    jne  .controls
    cmp  dword [rel ssh_cli_request_failures], 0
    jne  .controls
    cmp  byte [rel ssh_cli_want_close], 1
    jne  .input
.controls:
    call ssh_cli_flush_control
    jmp  .out                           ; ordered controls precede new interactive data
.input:
    call ssh_cli_exec_poll
    test eax, eax
    jnz  .out
    call ssh_cli_drain_txq
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .no_ka
    cmp  qword [rel ssh_cli_ka_left], 0
    je   .arm_ka
    call time_monotonic_now_us
    lea  rdi, [rel ssh_cli_ka_left]
    call ssh_cli_timer_step
    test rax, rax
    jnz  .no_ka
    call ssh_cli_rearm_keepalive
    call ssh_cli_send_keepalive
    test eax, eax
    jns  .no_ka
    call ssh_cli_transport_lost
    jmp  .no_ka
.arm_ka:
    call ssh_cli_rearm_keepalive
.no_ka:
    cmp  byte [rel ssh_cli_want_ecdh], 1
    jne  .chk_svcreq
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_GOT_KEXINIT
    jne  .chk_svcreq
    mov  rdi, [rel ssh_cli_ctx_ptr]
    call ssh_cli_send_ecdh_init                  ; sets want_ecdh=0 + state on success
    jmp  .out
.chk_svcreq:
    cmp  byte [rel ssh_cli_want_svcreq], 1
    jne  .chk_auth
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_ENC
    jne  .chk_auth
    mov  rdi, [rel ssh_cli_ctx_ptr]
    call ssh_cli_send_service_request
    test eax, eax
    jnz  .out                                    ; backpressure/error -> retry next tick
    mov  byte [rel ssh_cli_want_svcreq], 0
    lea  rdi, [rel str_sshcli_svcreq]
    call serial_string
    jmp  .out
.chk_auth:
    cmp  byte [rel ssh_cli_want_userauth], 1
    jne  .chk_chanopen
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_SVC_OK
    jne  .chk_chanopen
    mov  rdi, [rel ssh_cli_ctx_ptr]
    call ssh_cli_send_userauth
    test eax, eax
    jnz  .out                                    ; backpressure/error -> retry next tick
    mov  byte [rel ssh_cli_want_userauth], 0
    lea  rdi, [rel str_sshcli_authreq]
    call serial_string
    jmp  .out
.chk_chanopen:
    cmp  byte [rel ssh_cli_want_chanopen], 1
    jne  .chk_exec
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_AUTHED
    jne  .chk_pty
    call ssh_cli_send_channel_open
    test eax, eax
    jnz  .out
    mov  byte [rel ssh_cli_want_chanopen], 0
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN_SENT
    lea  rdi, [rel str_sshcli_chreq]
    call serial_string
    jmp  .out
.chk_exec:
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .chk_pty
    cmp  dword [rax + SSH_CLI_SLOT_EXEC + SSH_CLI_EXEC_WANT], 1
    jne  .chk_pty
    call ssh_cli_send_exec
    test eax, eax
    js   .out
    jmp  .out
.chk_pty:
    cmp  byte [rel ssh_cli_want_pty], 1
    jne  .chk_shell
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    jne  .chk_shell
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    jne  .out
    call ssh_cli_send_pty_req
    test eax, eax
    js   .channel_send_lost
    jnz  .out
    lea  rdi, [rel str_sshcli_pty]
    call serial_string
    jmp  .out
.chk_shell:
    cmp  byte [rel ssh_cli_want_shell], 1
    jne  .chk_winadj
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_CH_OPEN
    jne  .chk_winadj
    cmp  byte [rel ssh_cli_request_pending], SSH_CLI_REQ_NONE
    jne  .out
    call ssh_cli_send_shell
    test eax, eax
    js   .channel_send_lost
    jmp  .out                           ; wait for SUCCESS; transport acceptance is not ready
.channel_send_lost:
    call ssh_cli_transport_lost
    jmp  .out
.chk_winadj:
    cmp  byte [rel ssh_cli_want_winadj], 1
    jne  .out
    call ssh_cli_replenish_window
.out:
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   ssh_cli_retire                  ; a deferred handshake send can fail this tick
    jmp  ssh_cli_retire_apply

; ======================= hub port additions (packet 0014) =======================

; ssh_cli_pick_port -> EAX = the local port for a new outbound connection, or 0
; when the CSPRNG cannot supply the start (the caller fails closed; the next dial
; draws again). The hub's tcp_client_open takes the port from the caller and does
; not compare it with live tuples, so: a per-boot start in SSH_CLI_PORT_BASE +
; 0..16383 drawn from the keep's CSPRNG (RFC 6056; never the TSC), then one step
; per connection (a recent connection's port, perhaps still in TIME_WAIT, comes
; back only after 16384 more), never a live session's port.
; Clobbers RCX, RDX, RSI, RDI, R8-R11.
ssh_cli_pick_port:
    push rbx
    sub  rsp, 16
    mov  ebx, [rel ssh_cli_port_next]   ; next offset + 1 (0: not started)
    test ebx, ebx
    jnz  .start
    mov  rdi, rsp
    mov  esi, 2
    call csprng_generate
    test rax, rax
    jnz  .no_entropy
    movzx eax, word [rsp]
    and  eax, SSH_CLI_PORT_SPAN - 1
    lea  ebx, [rax + 1]
.start:
    mov  r8d, SSH_CLI_PORT_SPAN
.try:
    lea  eax, [rbx - 1]
    and  eax, SSH_CLI_PORT_SPAN - 1
    add  eax, SSH_CLI_PORT_BASE
    inc  ebx
    cmp  ebx, SSH_CLI_PORT_SPAN
    jbe  .stepped
    mov  ebx, 1
.stepped:
    xor  ecx, ecx
.sess:
    cmp  ecx, SSH_SESS_MAX
    jae  .ok
    lea  rdx, [rel ssh_sess_used]
    cmp  byte [rdx + rcx], 0
    je   .sess_next
    lea  rdx, [rel ssh_sess_lport]
    cmp  eax, [rdx + rcx*4]
    je   .busy
.sess_next:
    inc  ecx
    jmp  .sess
.busy:
    dec  r8d
    jnz  .try
.ok:
    mov  [rel ssh_cli_port_next], ebx
    add  rsp, 16
    pop  rbx
    ret
.no_entropy:
    xor  eax, eax                       ; ssh_cli_port_next stays 0: redraw next dial
    add  rsp, 16
    pop  rbx
    ret

; ssh_cli_identity_ensure -> EAX0 with the enrolled public key blob;
; -1 principal/context refused, -2 unverified identity, -4 empty store needs
; explicit owner ENROLL, -5 runtime storage unavailable. Default operation
; never generates or adopts a temporary identity. An explicit disposable
; lifecycle is not implemented by this path.
ssh_cli_identity_ensure:
    push rbx
    call ssh_cli_cid_load
    test eax, eax
    jnz  .unloaded
    movzx eax, byte [rel ssh_cli_cid_state]
    cmp  eax, SSH_CID_ST_ENROLLED
    je   .enrolled
    cmp  eax, SSH_CID_ST_NONE
    je   .empty
    cmp  eax, SSH_CID_ST_BOOT
    je   .runtime
    mov  eax, -2
    jmp  .out
.enrolled:
    lea  rsi, [rel ssh_cli_cid_pub]
    call ssh_cli_identity_blob
    xor  eax, eax
    jmp  .out
.empty:
    mov  eax, -4
    jmp  .out
.runtime:
    mov  eax, -5
    jmp  .out
.unloaded:
    mov  eax, -1
.out:
    pop  rbx
    ret

; ssh_cli_identity_blob(RSI = 32-byte public key): ssh_cli_id_blob = its blob.
ssh_cli_identity_blob:
    push rsi
    lea  rdi, [rel ssh_cli_id_blob]
    lea  rsi, [rel ssh_cli_ed25519_key_prefix]
    mov  edx, 19
    call memcpy
    pop  rsi
    lea  rdi, [rel ssh_cli_id_blob + 19]
    mov  edx, 32
    jmp  memcpy

; ssh_cli_identity_seed -> RAX = the seed that signs this session's
; USERAUTH_REQUEST, -1 refused (not an owner session, or a principal other than
; the owner is bound), -2 refused (no verified key). Enrolled: derived now into
; ssh_cli_cid_seed and checked against the enrolled public key (a machine
; secret replaced since the load refuses, never signs with another key); the
; caller wipes it with ssh_cli_identity_seed_done right after signing.
; Unenrolled or unavailable: refuse even if an old boot seed is marked ready.
ssh_cli_identity_seed:
    push rbx
    cmp  byte [rel ssh_cli_owner_armed], 1
    jne  .not_owner                     ; SYSTEM / the AI never sign with the client key
    call principal_current
    test rax, rax
    jz   .principal_ok
    cmp  rax, PRIN_OWNER
    jne  .not_owner                     ; only owner context may derive the enrolled key
.principal_ok:
    cmp  byte [rel ssh_cli_cid_state], SSH_CID_ST_ENROLLED
    je   .enrolled
    jmp  .unavailable                   ; only authenticated enrolled identity signs
.enrolled:
    mov  edi, [rel ssh_cli_cid_gen]
    call ssh_cli_cid_derive_seed
    cmp  eax, -2
    je   .not_owner                     ; another principal is bound: the seed was not derived
    test eax, eax
    jnz  .wipe
    lea  rdi, [rel ssh_cli_cid_seed]
    mov  esi, 32
    lea  rdx, [rel ssh_cli_cid_check]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .wipe
    lea  rdi, [rel ssh_cli_cid_check]
    lea  rsi, [rel ssh_cli_cid_pub]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .changed
    lea  rax, [rel ssh_cli_cid_seed]
    jmp  .out
.changed:
    mov  byte [rel ssh_cli_cid_state], SSH_CID_ST_UNVERIFIED
    lea  rdi, [rel str_sshcli_cid_unverified_serial]
    call serial_string
.wipe:
    call ssh_cli_identity_seed_done
.unavailable:
    mov  rax, -2
    jmp  .out
.not_owner:
    mov  rax, -1
.out:
    pop  rbx
    ret

; ssh_cli_identity_seed_done: wipe the derived signing seed.
ssh_cli_identity_seed_done:
    lea  rdi, [rel ssh_cli_cid_seed]
    xor  esi, esi
    mov  edx, 32
    jmp  memset

; ssh_cli_identity_text(RDI = out, ESI = capacity) -> EAX = length of the
; NUL-terminated authorized_keys line "ssh-ed25519 <base64> paos-client"
; (SSH_CLI_ID_TEXT_LEN), -2 unverified, -4 empty, -5 storage unavailable, or
; another negative value (no key, or capacity too small). Public bytes only.
ssh_cli_identity_text:
    push rbx
    mov  rbx, rdi
    cmp  esi, SSH_CLI_ID_TEXT_LEN + 1
    jb   .bad
    call ssh_cli_identity_ensure
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_ed25519_key_prefix + 4]
    mov  edx, 11
    call memcpy
    mov  byte [rbx + 11], ' '
    lea  rdi, [rel ssh_cli_id_blob]
    mov  esi, 51
    lea  rdx, [rbx + 12]
    call ssh_cli_b64                    ; 68 characters
    mov  rdi, rax
    lea  rsi, [rel str_sshcli_id_comment]
    mov  edx, str_sshcli_id_comment.len ; with its NUL
    call memcpy
    mov  eax, SSH_CLI_ID_TEXT_LEN
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
%include "svc/ssh_client_profile.inc"
; ---------------------------------------------------------------------------

; ssh_cli_identity_enroll(EDI=0 ENROLL,1 RESET) -> EAX0 exact commit,
; 1 already enrolled/authenticated reload, -1 proved no-write refusal,
; -2 issued write with uncertain outcome (new identity admission revoked).
; Owner policy is unchanged. New generations advance only authenticated/local
; attempted high-water and refuse wrap. Authenticated public history survives
; restart; joint loss of both records is undetectable. No rollback protection.
ssh_cli_identity_enroll:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    call ssh_cli_cid_load
    test eax, eax
    jnz  .refused
    movzx eax, byte [rel ssh_cli_cid_state]
    cmp  eax, SSH_CID_ST_BOOT
    je   .refused
    test ebx, ebx
    jnz  .reset
    cmp  eax, SSH_CID_ST_ENROLLED
    je   .already
    cmp  eax, SSH_CID_ST_UNVERIFIED
    jne  .generation
    ; Explicit owner repair first tries an authenticated current durable reload.
    ; A malformed record's raw generation is never an allocation authority.
    call ssh_cli_cid_reload
    test eax, eax
    jz   .already
    cmp  dword [rel ssh_cli_cid_floor], 0
    je   .refused                       ; no trusted generation history this boot
    jmp  .generation
.reset:
    cmp  eax, SSH_CID_ST_ENROLLED
    jne  .refused
.generation:
    mov  r12d, [rel ssh_cli_cid_floor]
    inc  r12d
    jz   .refused                       ; saturation, never wrap to a reused key
    lea  rdi, [rel ssh_cli_cid_stage]
    xor  esi, esi
    mov  edx, SSH_CID_REC_SIZE
    call memset
    mov  dword [rel ssh_cli_cid_stage], SSH_CID_MAGIC
    mov  word [rel ssh_cli_cid_stage + 4], SSH_CID_VERSION
    mov  word [rel ssh_cli_cid_stage + 6], SSH_CID_REC_SIZE
    mov  [rel ssh_cli_cid_stage + SSH_CID_REC_GEN], r12d
    mov  dword [rel ssh_cli_cid_stage + SSH_CID_REC_ENROLLED], 1
    mov  edi, r12d
    lea  rsi, [rel ssh_cli_cid_stage + SSH_CID_REC_PUB]
    call ssh_cli_cid_derive_pub
    test eax, eax
    jnz  .refused
    lea  rdi, [rel ssh_cli_cid_stage]
    call ssh_cli_cid_mac
    test eax, eax
    jnz  .refused
    lea  rdi, [rel ssh_cli_cid_stage + SSH_CID_REC_MAC]
    lea  rsi, [rel ssh_cli_cid_mac_out]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel ssh_cli_cid_stage]
    mov  esi, SSH_CID_REC_SIZE
    call ssh_cli_cid_setvar
    cmp  eax, -2
    je   .failed                        ; issued write: identity already revoked
    test eax, eax
    jnz  .refused                       ; proved no-write preflight refusal
    call ssh_cli_cid_publish
    lea  rdi, [rel str_sshcli_cid_enrolled_serial]
    call serial_string
    xor  eax, eax
    jmp  .out
.already:
    mov  eax, 1
    jmp  .out
.failed:
    mov  eax, -2
    jmp  .out
.refused:
    mov  eax, -1
.out:
    mov  [rsp], rax
    call ssh_cli_cid_cleanup
    mov  rax, [rsp]
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

%macro SSHCLI_B64_PUT 2                 ; sextet (ECX >> %1) & 63 -> [RAX + %2]
    mov  r8d, ecx
    shr  r8d, %1
    and  r8d, 63
    movzx r9d, byte [r11 + r8]
    mov  [rax + %2], r9b
%endmacro

; ssh_cli_b64(RDI = bytes, ESI = n, RDX = out) -> RAX = end of the text
; (RFC 4648 base64 with '=' padding, no NUL). Clobbers RCX, RSI, RDI, R8-R11.
ssh_cli_b64:
    lea  r11, [rel ssh_b64]
    mov  rax, rdx
.tri:
    cmp  esi, 3
    jb   .tail
    movzx ecx, byte [rdi]
    shl  ecx, 8
    mov  cl, [rdi + 1]
    shl  ecx, 8
    mov  cl, [rdi + 2]
    SSHCLI_B64_PUT 18, 0
    SSHCLI_B64_PUT 12, 1
    SSHCLI_B64_PUT 6, 2
    SSHCLI_B64_PUT 0, 3
    add  rdi, 3
    sub  esi, 3
    add  rax, 4
    jmp  .tri
.tail:
    test esi, esi
    jz   .done
    movzx ecx, byte [rdi]
    shl  ecx, 16
    mov  byte [rax + 2], '='
    mov  byte [rax + 3], '='
    cmp  esi, 2
    jb   .one
    movzx r10d, byte [rdi + 1]
    shl  r10d, 8
    or   ecx, r10d
    SSHCLI_B64_PUT 6, 2
.one:
    SSHCLI_B64_PUT 18, 0
    SSHCLI_B64_PUT 12, 1
    add  rax, 4
.done:
    ret

; ssh_cli_hostkey_check -> EAX0 matching owner-provisioned/saved key,
; -1 changed/invalid trust, -2 table full, -3 unknown (no pin/admission).
; The server's signature over H has already proved it holds the key in K_S; the
; owner-provisioned pin turns that into an authenticated peer. Pins are
; never evicted or automatically replaced. Only the separate authenticated
; owner old/new action can deliberately change a pinned endpoint's digest.
ssh_cli_hostkey_check:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  qword [rel ssh_cli_kh_admitted_epoch], 0
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    je   .changed
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_POISONED
    je   .poisoned                     ; damaged durable trust is not fresh TOFU
    mov  r14, [rel ssh_cli_kh_epoch]
    lea  rdi, [rel ssh_cli_hk_digest]
    lea  rsi, [rel ssh_cli_ks_buf]
    mov  edx, [rel ssh_cli_ks_len]
    call sha256_hash
    test eax, eax
    jnz  .changed                       ; cannot hash it: fail closed
    lea  rbx, [rel ssh_cli_pins]
    xor  r12d, r12d
    xor  r13d, r13d                     ; first free slot (0 = none yet)
.scan:
    cmp  r12d, SSH_CLI_PINS
    jae  .new
    cmp  byte [rbx + 6], 0
    jne  .used
    test r13, r13
    jnz  .next
    mov  r13, rbx
    jmp  .next
.used:
    mov  eax, [rbx]
    cmp  eax, [rel ssh_cli_target_ip]
    jne  .next
    movzx eax, word [rbx + 4]
    movzx ecx, word [rel ssh_cli_target_port]
    cmp  eax, ecx
    jne  .next
    lea  rsi, [rbx + 8]
    lea  rdi, [rel ssh_cli_hk_digest]
    mov  ecx, 32
    cld
    repe cmpsb
    ; Observe this actual signed initial KEX key versus its selected endpoint.
    ; Preserve comparison flags and registers so the trust decision is exact.
    ; Rekey does not call this initial host-key function.
    pushfq
    push rax
    push rcx
    push rsi
    push rdi
    setne al
    movzx eax, al
    inc  eax                           ; 1 exact, 2 changed
    mov  [rel ssh_cli_key_check], rax
    lea  rsi, [rel ssh_cli_hk_digest]
    lea  rdi, [rel ssh_cli_checked_digest]
    mov  ecx, 4
    rep  movsq
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rax
    popfq
    jne  .changed
    xor  eax, eax
    jmp  .out
.next:
    add  rbx, SSH_CLI_PIN_SZ
    inc  r12d
    jmp  .scan
.new:
    ; Public witness of this actual signed initial key, not owner trust.
    mov  qword [rel ssh_cli_key_check], 3 ; unknown endpoint, provisioning required
    lea  rsi, [rel ssh_cli_hk_digest]
    lea  rdi, [rel ssh_cli_checked_digest]
    mov  ecx, 4
    cld
    rep  movsq
    ; Capacity refusal still observes the signed key without changing any pin.
    test r13, r13
    jz   .full
    ; Seeing a signed host key proves possession, never owner trust. Unknown
    ; endpoints cannot publish a pin or an admission epoch, even for this boot.
    call ssh_cli_kh_warn
    call ssh_cli_show_fingerprint
    mov  eax, -3                       ; explicit provisioning required
    jmp  .out
.full:
    ; First contact still exposes the actual signed key to the owner at capacity.
    call ssh_cli_show_fingerprint
    lea  rdi, [rel str_sshcli_pins_full]
    mov  esi, str_sshcli_pins_full.len
    call ssh_cli_deliver_data
    mov  eax, -2
    jmp  .out
.poisoned:
    call ssh_cli_kh_warn                ; actionable refusal before credentials
.changed:
    mov  eax, -1
.out:
    test eax, eax
    jnz  .return
    cmp  r14, [rel ssh_cli_kh_epoch]
    jne  .changed
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    je   .changed
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_POISONED
    je   .poisoned                     ; sink callbacks cannot reopen admission
    mov  [rel ssh_cli_kh_admitted_epoch], r14
.return:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "svc/ssh_trust_replace.inc"

; ssh_cli_trust_host(EDI=IPv4 memory order, ESI=port, RDX=SHA25632) ->
; 0 provisioned in RAM,1 already exact,-1 invalid/unavailable,-2 full,-3 conflict.
; Caller MUST own a consumed owner-signed request; this is the narrow store
; operation, not an alternate authentication gate. Never replace/evict/clear,
; write EFI, admit a connection or claim persistence. Existing USERAUTH_SUCCESS
; attempts the existing authenticated durable commit exactly once.
ssh_cli_trust_host:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14, rdx
    test edi, edi
    jz   .refused
    test esi, esi
    jz   .refused
    cmp  esi, 65535
    ja   .refused
    test rdx, rdx
    jz   .refused
    call principal_current
    test rax, rax
    jz   .principal_ok
    cmp  rax, PRIN_OWNER
    jne  .refused
.principal_ok:
    call ssh_cli_kh_load
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_POISONED
    je   .refused
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    je   .refused
    xor  r15d, r15d
    lea  rbx, [rel ssh_cli_pins]
    xor  ecx, ecx
.scan:
    cmp  ecx, SSH_CLI_PINS
    jae  .new
    cmp  byte [rbx + 6], 0
    jne  .used
    test r15, r15
    jnz  .next
    mov  r15, rbx
    jmp  .next
.used:
    cmp  [rbx], r12d
    jne  .next
    cmp  [rbx + 4], r13w
    jne  .next
    lea  rdi, [rbx + 8]
    mov  rsi, r14
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .conflict
    mov  eax, 1
    jmp  .out
.next:
    add  rbx, SSH_CLI_PIN_SZ
    inc  ecx
    jmp  .scan
.new:
    test r15, r15
    jz   .full
    ; New pin bytes are entirely public. Publish used last. No new admission:
    ; a future real server signature must independently match this digest.
    mov  [r15], r12d
    mov  [r15 + 4], r13w
    mov  byte [r15 + 7], 0
    mov  dword [r15 + 40], 0
    lea  rdi, [r15 + 8]
    mov  rsi, r14
    mov  edx, 32
    call memcpy
    mov  byte [r15 + 6], 1
    xor  eax, eax
    jmp  .out
.refused:
    mov  eax, -1
    jmp  .out
.full:
    mov  eax, -2
    jmp  .out
.conflict:
    mov  eax, -3
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_cli_show_fingerprint: "ssh: host key SHA256:<43 base64> (...)" to the
; session's sink (the Terminal), as OpenSSH shows a key it has not seen before.
ssh_cli_show_fingerprint:
    push rbx
    lea  rbx, [rel ssh_cli_chpkt]
    mov  rdi, rbx
    lea  rsi, [rel str_sshcli_fp_head]
    mov  edx, str_sshcli_fp_head.len
    call memcpy
    lea  rdi, [rel ssh_cli_hk_digest]
    mov  esi, 32
    lea  rdx, [rbx + str_sshcli_fp_head.len]
    call ssh_cli_b64                    ; 44 characters, the last one '='
    lea  rdi, [rax - 1]                 ; OpenSSH prints it without the padding
    push rdi
    lea  rsi, [rel str_sshcli_fp_tail]
    mov  edx, str_sshcli_fp_tail.len
    call memcpy
    pop  rax
    add  rax, str_sshcli_fp_tail.len
    sub  rax, rbx
.tail_done:
    ; Existing buffer holds the base64 fingerprint + actionable refusal. Add
    ; its exact public digest, not a second hash or an internal key pointer.
    lea  rdi, [rbx + rax]
    lea  rsi, [rel ssh_cli_hk_digest]
    xor  ecx, ecx
.hex:
    movzx edx, byte [rsi + rcx]
    mov  r8d, edx
    shr  edx, 4
    and  r8d, 15
    lea  r9, [rel ssh_cli_trust_hex]
    mov  dl, [r9 + rdx]
    mov  [rdi], dl
    mov  dl, [r9 + r8]
    mov  [rdi + 1], dl
    add  rdi, 2
    inc  ecx
    cmp  ecx, 32
    jb   .hex
    mov  word [rdi], 0x0a0d
    add  rax, 66
    mov  rdi, rbx
    mov  esi, eax
    call ssh_cli_deliver_data
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; RCQ-07b known_hosts (PaOSSshKnownHosts). All callers are serialized on the
; idle loop (connect_start, USERAUTH_SUCCESS, SSHKHTRUST/SSHKHCLEAR).
; ---------------------------------------------------------------------------
; ssh_cli_kh_load -> EAX 0. Once per boot: derive the MAC key, read the
; variable, and restore its pins before explicit provisioning or a session.
; Afterwards only re-warns.
ssh_cli_kh_load:
    push rbx
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNLOADED
    jne  .done
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_BOOT
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .done
    call ssh_cli_kh_derive
    test eax, eax
    jnz  .nokey
    call ssh_cli_kh_history_load
    test eax, eax
    js   .poison
    call ssh_cli_kh_getvar
    cmp  eax, 1
    je   .empty
    test eax, eax
    jnz  .poison
    lea  rdi, [rel ssh_cli_kh_stage]
    call ssh_cli_kh_valid
    test eax, eax
    jz   .poison
    call ssh_cli_kh_restore
    mov  edi, [rel ssh_cli_kh_stage + SSH_KH_REC_GEN]
    mov  [rel ssh_cli_kh_gen], edi
    call ssh_cli_kh_note_floor
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    jmp  .done
.empty:
    ; Authenticated durable history or a local attempted write makes missing
    ; trust an existing-store loss; history never restores/adopts its pins.
    cmp  dword [rel ssh_cli_kh_floor], 0
    jne  .poison
    mov  dword [rel ssh_cli_kh_gen], 0
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    jmp  .done
.nokey:
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NOKEY
    jmp  .done
.poison:
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_POISONED
    lea  rdi, [rel str_sshcli_kh_poisoned_serial]
    call serial_string
.done:
    call ssh_cli_kh_cleanup
    call ssh_cli_kh_warn
    xor  eax, eax
    pop  rbx
    ret

; ssh_cli_kh_warn: the store's standing warning to this session's Terminal.
ssh_cli_kh_warn:
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    je   .uncertain
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_POISONED
    je   .poisoned
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_NOKEY
    jne  .out
    lea  rdi, [rel str_sshcli_kh_nokey]
    mov  esi, str_sshcli_kh_nokey.len
    jmp  ssh_cli_deliver_data
.uncertain:
    lea  rdi, [rel str_sshcli_kh_uncertain]
    mov  esi, str_sshcli_kh_uncertain.len
    jmp  ssh_cli_deliver_data
.poisoned:
    lea  rdi, [rel str_sshcli_kh_poisoned]
    mov  esi, str_sshcli_kh_poisoned.len
    jmp  ssh_cli_deliver_data
.out:
    ret

; ssh_cli_kh_derive -> EAX 0 with ssh_cli_kh_key = HKDF-SHA256(machine secret,
; info "PaOS/SSH/known_hosts/v1"), nonzero otherwise (ssh_cli_y_hkdf).
ssh_cli_kh_derive:
    lea  rdi, [rel ssh_cli_kh_info]
    mov  esi, ssh_cli_kh_info.len
    lea  rdx, [rel ssh_cli_kh_key]
    jmp  ssh_cli_y_hkdf

; ssh_cli_y_hkdf(RDI = info, ESI = info length, RDX = 32-byte out) -> EAX 0 with
; out = HKDF-SHA256(machine secret, zero salt, info); -1 (out zeroed) when the
; secret or the derivation failed; -2 (out untouched) when a principal other
; than the owner is bound. The same SYSTEM-credential seam and state restore as
; the server's host key (svc/ssh.asm); every caller has its own info string.
ssh_cli_y_hkdf:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 24
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    call principal_current
    mov  rbx, rax
    test rax, rax
    jz   .enter
    cmp  rax, PRIN_OWNER
    jne  .unbound                       ; only the owner or the locked state, as svc/ssh
.enter:
    call principal_enter_system
    call principal_system_auth_credential
    test rax, rax
    jz   .bad
    cmp  edx, 32
    jne  .bad
    mov  rdi, rax
    mov  esi, 32
    xor  edx, edx                       ; RFC 5869 zero-salt extract
    xor  ecx, ecx
    mov  r8, r12
    mov  r9d, r13d
    mov  [rsp], r14
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .restore
.bad:
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
.restore:
    mov  [rsp + 16], rax
    cmp  rbx, PRIN_OWNER
    je   .owner
    call principal_clear_bound
    jmp  .restored
.owner:
    call principal_leave_system
.restored:
    mov  rax, [rsp + 16]
    jmp  .out
.unbound:
    mov  eax, -2
.out:
    add  rsp, 24
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "svc/ssh_profile_fault_boundary.inc"

; ssh_cli_kh_getvar -> EAX 0 read (NV|BS|RT, exact size) into ssh_cli_kh_stage,
; 1 absent, -1 unreadable / wrong attributes / wrong size.
ssh_cli_kh_getvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    mov  qword [rel ssh_cli_kh_size], SSH_KH_REC_SIZE
    mov  dword [rel ssh_cli_kh_attrs], 0
    lea  rcx, [rel ssh_cli_kh_var_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    lea  r8, [rel ssh_cli_kh_attrs]
    lea  r9, [rel ssh_cli_kh_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_cli_kh_stage]
    mov  [rsp + 32], rbx
%ifdef SSH_PROFILE_FAULT_ENABLED
    call ssh_cli_fault_getvar
%else
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
%endif
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, SSH_KH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    mov  eax, 1
    jmp  .out
.read:
    cmp  dword [rel ssh_cli_kh_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  qword [rel ssh_cli_kh_size], SSH_KH_REC_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_cli_kh_mac(RDI=record) -> ssh_cli_kh_mac_out = HMAC-SHA256(key, record[0:MAC]).
ssh_cli_kh_mac:
    mov  rcx, rdi
    lea  rdi, [rel ssh_cli_kh_mac_out]
    lea  rsi, [rel ssh_cli_kh_key]
    mov  edx, 32
    mov  r8d, SSH_KH_REC_MAC
    jmp  hmac_sha256

; ssh_cli_kh_valid(RDI=record) -> EAX 1/0: magic, version, size, count bound,
; MAC, then every entry (valid in {0,1}; a valid one is ssh-ed25519 and first
; seen no later than the record's generation; count matches).
ssh_cli_kh_valid:
    push rbx
    push r12
    mov  rbx, rdi
    cmp  dword [rbx], SSH_KH_MAGIC
    jne  .no
    cmp  word [rbx + 4], SSH_KH_VERSION
    jne  .no
    cmp  word [rbx + 6], SSH_KH_REC_SIZE
    jne  .no
    cmp  dword [rbx + SSH_KH_REC_COUNT], SSH_CLI_PINS
    ja   .no
    cmp  dword [rbx + SSH_KH_REC_GEN], 0
    je   .no
    mov  rdi, rbx
    call ssh_cli_kh_mac
    lea  rsi, [rel ssh_cli_kh_mac_out]
    lea  rdi, [rbx + SSH_KH_REC_MAC]
    mov  ecx, 32
    cld
    repe cmpsb
    jne  .no
.mac_ok:
    xor  r12d, r12d
    xor  ecx, ecx
.entry:
    cmp  ecx, SSH_CLI_PINS
    jae  .counted
    imul eax, ecx, SSH_CLI_PIN_SZ
    lea  rdx, [rbx + SSH_KH_REC_ENTRIES + rax]
    movzx eax, byte [rdx + 7]
    cmp  eax, 1
    ja   .no
    jb   .next
    cmp  byte [rdx + 6], SSH_KH_KEY_ED25519
    jne  .no
    cmp  dword [rdx], 0
    je   .no
    cmp  word [rdx + 4], 0
    je   .no
    mov  eax, [rdx + 40]
    test eax, eax
    jz   .no
    cmp  eax, [rbx + SSH_KH_REC_GEN]
    ja   .no
    ; Every authenticated endpoint is unique, regardless of digest.
    xor  r8d, r8d
.duplicates:
    cmp  r8d, ecx
    jae  .unique
    imul eax, r8d, SSH_CLI_PIN_SZ
    lea  r9, [rbx + SSH_KH_REC_ENTRIES + rax]
    cmp  byte [r9 + 7], 1
    jne  .dup_next
    mov  eax, [r9]
    cmp  eax, [rdx]
    jne  .dup_next
    mov  ax, [r9 + 4]
    cmp  ax, [rdx + 4]
    je   .no
.dup_next:
    inc  r8d
    jmp  .duplicates
.unique:
    inc  r12d
.next:
    inc  ecx
    jmp  .entry
.counted:
    cmp  [rbx + SSH_KH_REC_COUNT], r12d
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ssh_cli_kh_restore: the valid entries of ssh_cli_kh_stage become saved pins.
ssh_cli_kh_restore:
    push rbx
    push r12
    lea  rbx, [rel ssh_cli_pins]
    xor  r12d, r12d
.entry:
    cmp  r12d, SSH_CLI_PINS
    jae  .out
    imul eax, r12d, SSH_CLI_PIN_SZ
    lea  rsi, [rel ssh_cli_kh_stage + SSH_KH_REC_ENTRIES]
    add  rsi, rax
    cmp  byte [rsi + 7], 1
    jne  .next
    mov  rdi, rbx
    mov  edx, SSH_CLI_PIN_SZ
    call memcpy
    mov  byte [rbx + 6], 1              ; used
    mov  byte [rbx + 7], 1              ; saved
    add  rbx, SSH_CLI_PIN_SZ
.next:
    inc  r12d
    jmp  .entry
.out:
    pop  r12
    pop  rbx
    ret

; ssh_cli_kh_confirm: after current-epoch USERAUTH_SUCCESS, attempt one save.
; Only exact durable commit earns claim1; claim2 is boot-confirmed, not saved.
ssh_cli_kh_confirm:
    push rbx
    push r12
    sub  rsp, 8
    call ssh_cli_kh_admission_current
    test eax, eax
    jnz  .out
    lea  rbx, [rel ssh_cli_pins]
    xor  r12d, r12d
.scan:
    cmp  r12d, SSH_CLI_PINS
    jae  .out
    cmp  byte [rbx + 6], 0
    je   .next
    mov  eax, [rbx]
    cmp  eax, [rel ssh_cli_target_ip]
    jne  .next
    mov  ax, [rbx + 4]
    cmp  ax, [rel ssh_cli_target_port]
    je   .found
.next:
    add  rbx, SSH_CLI_PIN_SZ
    inc  r12d
    jmp  .scan
.found:
    cmp  byte [rbx + 7], 0
    jne  .out                         ; saved1 or boot-confirmed2: never automatically retry
    mov  byte [rbx + 7], 2             ; authenticated this boot, not durably saved
    mov  rdi, rbx
    call ssh_cli_kh_persist
.out:
    call ssh_cli_kh_cleanup
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ssh_cli_kh_persist: write the saved pins as a new generation (one SetVariable,
; exact readback). Only a live store writes: a poisoned one is never replaced.
; A proved no-write refusal preserves trust. Issued uncertainty revokes future
; trust for the complete table. Neither outcome automatically retries.
; RDI = confirmed pin. Stage existing saved pins plus this one; do not publish
; saved or first-seen generation until exact durable commit. No automatic retry.
ssh_cli_kh_persist:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    jne  .out
    mov  eax, [rel ssh_cli_kh_floor]
    inc  eax
    jz   .failed                       ; refuse generation wrap, retain boot pin
    mov  r13d, eax
    call ssh_cli_kh_derive
    test eax, eax
    jnz  .failed
    mov  rdi, r15
    mov  esi, r13d
    xor  edx, edx                       ; normal successful-peer save
    call .build
    lea  rdi, [rel ssh_cli_kh_stage]
    mov  esi, SSH_KH_REC_SIZE
    call ssh_cli_kh_setvar
    test eax, eax
    jnz  .failed
    call ssh_cli_kh_commit_saved        ; merge; never evict unsaved boot pins
    mov  [rel ssh_cli_kh_gen], r13d
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    jmp  .out
.failed:
    call ssh_cli_kh_cleanup             ; no secret/staging bytes cross the sink callback
    lea  rdi, [rel str_sshcli_kh_notsaved]
    mov  esi, str_sshcli_kh_notsaved.len
    call ssh_cli_deliver_data
.out:
    call ssh_cli_kh_cleanup
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Private staged-record builder shared with deliberate owner replacement.
; RDI existing selected pin, ESI next authenticated generation, RDX optional
; independently provisioned new digest (0 leaves the normal peer path exact).
; Derive the existing record MAC key before calling. Never publish RAM pins.
.build:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  [rsp], rdx
    mov  r15, rdi
    mov  r13d, esi
    lea  rdi, [rel ssh_cli_kh_stage]
    xor  esi, esi
    mov  edx, SSH_KH_REC_SIZE
    call memset
    lea  rbx, [rel ssh_cli_pins]
    lea  r14, [rel ssh_cli_kh_stage + SSH_KH_REC_ENTRIES]
    xor  r12d, r12d
.entry:
    cmp  r12d, SSH_CLI_PINS
    jae  .built
    cmp  byte [rbx + 6], 0
    je   .skip
    cmp  rbx, r15
    je   .copy
    cmp  byte [rbx + 7], 1
    jne  .skip
.copy:
    mov  rdi, r14
    mov  rsi, rbx
    mov  edx, SSH_CLI_PIN_SZ
    call memcpy
    cmp  rbx, r15
    jne  .copy_original
    mov  rsi, [rsp]
    test rsi, rsi
    jz   .copy_original
    lea  rdi, [r14 + 8]
    mov  edx, 32
    call memcpy
.copy_original:
    mov  byte [r14 + 6], SSH_KH_KEY_ED25519
    mov  byte [r14 + 7], 1
    cmp  rbx, r15
    jne  .copied
    mov  [r14 + 40], r13d
.copied:
    inc  dword [rel ssh_cli_kh_stage + SSH_KH_REC_COUNT]
    add  r14, SSH_CLI_PIN_SZ
.skip:
    add  rbx, SSH_CLI_PIN_SZ
    inc  r12d
    jmp  .entry
.built:
    mov  dword [rel ssh_cli_kh_stage], SSH_KH_MAGIC
    mov  word [rel ssh_cli_kh_stage + 4], SSH_KH_VERSION
    mov  word [rel ssh_cli_kh_stage + 6], SSH_KH_REC_SIZE
    mov  [rel ssh_cli_kh_stage + SSH_KH_REC_GEN], r13d
    lea  rdi, [rel ssh_cli_kh_stage]
    call ssh_cli_kh_mac
    lea  rdi, [rel ssh_cli_kh_stage + SSH_KH_REC_MAC]
    lea  rsi, [rel ssh_cli_kh_mac_out]
    mov  edx, 32
    call memcpy
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_cli_kh_setvar(RDI=data or0,RSI=extent;0 deletes) -> EAX0 exact,-1 no-write,-2 uncertain. Through the
; NVRAM storage gate; exact attributes/size/bytes verify a write, and a
; bounded GetVariable must report NOT_FOUND to verify deletion.
ssh_cli_kh_setvar:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsp
    mov  r14, rdi
    mov  r15, rsi
    ; Only the complete fixed record may be written. Validate the caller's
    ; full extent before the storage gate or firmware can inspect its bytes.
    test r15, r15
    jz   .extent_ok
    cmp  r15, SSH_KH_REC_SIZE
    jne  .bad
    test r14, r14
    jz   .bad
.extent_ok:
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    cmp  qword [r12 + 0x58], 0
    je   .bad
    cmp  qword [rel ssh_cli_kh_epoch], -1
    je   .bad                         ; no admission token wrap
    test r15, r15
    jz   .gate
    call ssh_cli_kh_derive
    test eax, eax
    jnz  .bad
    mov  rdi, r14
    call ssh_cli_kh_valid
    test eax, eax
    jz   .bad
    mov  eax, [r14 + SSH_KH_REC_GEN]
    cmp  eax, [rel ssh_cli_kh_floor]
    jbe  .bad
.gate:
    call storage_access_request_intent  ; storage canon: PaOS-namespace NVRAM = NORMAL
    mov  edx, eax
    lea  rdi, [rel ssh_cli_kh_var_guid]
    lea  rsi, [rel ssh_cli_kh_var_name]
    lea  rcx, [rel str_sshcli_kh_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    test r15, r15
    jz   .issue_delete
    mov  rdi, r14
    call ssh_cli_kh_history_prepare    ; revokes once before durable attempt
    test eax, eax
    jnz  .out                         ; preserve no-write/uncertain distinction
    jmp  .issue
.issue_delete:
    call ssh_cli_kh_revoke             ; issued mutation covers the complete trust table
.issue:
    lea  rcx, [rel ssh_cli_kh_var_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, r15d
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], r14
%ifdef SSH_PROFILE_FAULT_ENABLED
    call ssh_cli_fault_setvar
%else
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
%endif
    mov  rsp, r13
    test r15d, r15d
    jz   .deleted
    test rax, rax
    jnz  .uncertain
    mov  qword [rel ssh_cli_kh_size], SSH_KH_REC_SIZE
    mov  dword [rel ssh_cli_kh_attrs], 0
    lea  rcx, [rel ssh_cli_kh_var_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    lea  r8, [rel ssh_cli_kh_attrs]
    lea  r9, [rel ssh_cli_kh_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_cli_kh_verify]
    mov  [rsp + 32], rbx
%ifdef SSH_PROFILE_FAULT_ENABLED
    call ssh_cli_fault_getvar
%else
    call [r12 + 0x48]                   ; exact readback
%endif
    mov  rsp, r13
    test rax, rax
    jnz  .uncertain
    cmp  dword [rel ssh_cli_kh_attrs], AUTH_EFI_ATTRS
    jne  .uncertain
    cmp  qword [rel ssh_cli_kh_size], r15
    jne  .uncertain
    mov  rdi, r14
    lea  rsi, [rel ssh_cli_kh_verify]
    mov  edx, r15d
    call memcmp
    test eax, eax
    jnz  .uncertain
    xor  eax, eax
    jmp  .out
.deleted:
    test rax, rax
    jz   .verify_absent
    mov  rdx, SSH_KH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .uncertain
.verify_absent:
    ; A delete acknowledgement (including NOT_FOUND) is not absence proof.
    ; The existing reader uses a fixed owned buffer and returns 1 only for
    ; definitive EFI_NOT_FOUND. Existing, malformed or unreadable all refuse.
    call ssh_cli_kh_getvar
    cmp  eax, 1
    jne  .uncertain
    call ssh_cli_kh_history_retire     ; only after verified primary absence
    test eax, eax
    jnz  .uncertain                   ; primary was already issued: never -1
.ok:
    xor  eax, eax
    jmp  .out
.uncertain:
    mov  eax, -2
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    push rax
    call ssh_cli_kh_key_done
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_cli_known_hosts_clear -> RAX0 verified clear,-1 no-write refusal,-2 issued
; uncertainty. Owner-signed SSHKHCLEAR deletes durable trust before forgetting
; pins. No-write retains trust; uncertain pins carry no saved/admission claim.
; Existing owner-signed SSHKHCLEAR is explicit recovery/disposition. A fresh
; verified absence is required even after a prior uncertain delete. Never
; downgrade uncertain/persistent trust to boot-only when runtime is unavailable.
ssh_cli_known_hosts_clear:
    push rbx
    cmp  byte [rel pbm_runtime_code_mapped], 1
    je   .delete
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_BOOT
    je   .boot_clear
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNLOADED
    je   .boot_clear                    ; no runtime and no mutation ever issued
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_NOKEY
    jne  .refused
.boot_clear:
    cmp  qword [rel ssh_cli_kh_epoch], -1
    je   .refused
    call ssh_cli_kh_revoke
    jmp  .forget
.delete:
    xor  edi, edi
    xor  esi, esi
    call ssh_cli_kh_setvar
    test eax, eax
    jnz  .failed
.forget:
    lea  rdi, [rel ssh_cli_pins]
    xor  esi, esi
    mov  edx, SSH_CLI_PINS * SSH_CLI_PIN_SZ
    call memset
    mov  dword [rel ssh_cli_kh_gen], 0
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_BOOT
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .ok
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NOKEY
    call ssh_cli_kh_derive
    test eax, eax
    jnz  .ok
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
.ok:
    lea  rdi, [rel str_sshcli_kh_cleared_serial]
    call serial_string
    xor  ebx, ebx
    jmp  .out
.refused:
    mov  ebx, -1
    jmp  .out
.failed:
    mov  ebx, eax
.out:
    call ssh_cli_kh_cleanup
    movsxd rax, ebx
    pop  rbx
    ret


; Exact KEX admission is per saved session; store authority/epoch is global.
; Established transports never call this again. Deferred or late handshake
; work fails with existing host-key error15 if trust changed in the meantime.
ssh_cli_kh_admission_current:
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    je   .bad
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_POISONED
    je   .bad                          ; includes saved/deferred KEX admissions
    mov  rax, [rel ssh_cli_kh_admitted_epoch]
    test rax, rax
    jz   .bad
    cmp  rax, [rel ssh_cli_kh_epoch]
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

ssh_cli_kh_note_floor:
    cmp  edi, [rel ssh_cli_kh_floor]
    jbe  .out
    mov  [rel ssh_cli_kh_floor], edi
.out:
    ret

; Caller proved epoch increment cannot wrap. Preserve in-boot hashes for
; strict changed-key checks after explicit recovery, but revoke every saved
; claim and all future trust admission while the durable table is uncertain.
ssh_cli_kh_revoke:
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    inc  qword [rel ssh_cli_kh_epoch]
    lea  rdx, [rel ssh_cli_pins]
    mov  ecx, SSH_CLI_PINS
.pin:
    cmp  byte [rdx + 7], 1
    jne  .next
    mov  byte [rdx + 7], 2
.next:
    add  rdx, SSH_CLI_PIN_SZ
    loop .pin
    ret

; Staged record was read back exactly. Match its entries into the live cache
; without discarding any other endpoint's strict boot-only pin.
ssh_cli_kh_commit_saved:
    push rbx
    push r12
    push r13
    lea  rbx, [rel ssh_cli_kh_stage + SSH_KH_REC_ENTRIES]
    mov  r12d, SSH_CLI_PINS
.entry:
    cmp  byte [rbx + 7], 1
    jne  .next
    lea  r13, [rel ssh_cli_pins]
    mov  ecx, SSH_CLI_PINS
.scan:
    cmp  byte [r13 + 6], 0
    je   .scan_next
    mov  eax, [rbx]
    cmp  eax, [r13]
    jne  .scan_next
    mov  ax, [rbx + 4]
    cmp  ax, [r13 + 4]
    jne  .scan_next
    ; No callbacks or concurrent writers between stage and publication.
    mov  byte [r13 + 7], 1
    mov  eax, [rbx + 40]
    mov  [r13 + 40], eax
    jmp  .next
.scan_next:
    add  r13, SSH_CLI_PIN_SZ
    loop .scan
.next:
    add  rbx, SSH_CLI_PIN_SZ
    dec  r12d
    jnz  .entry
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_cli_kh_key_done:
    lea  rdi, [rel ssh_cli_kh_key]
    xor  esi, esi
    mov  edx, 64
    jmp  memset

ssh_cli_kh_cleanup:
    sub  rsp, 8
    call ssh_cli_kh_key_done
    lea  rdi, [rel ssh_cli_kh_stage]
    xor  esi, esi
    mov  edx, SSH_KH_REC_SIZE
    call memset
    lea  rdi, [rel ssh_cli_kh_verify]
    xor  esi, esi
    mov  edx, ssh_cli_kh_history_verify + SSH_KH_REC_SIZE - ssh_cli_kh_verify
    call memset
    add  rsp, 8
    ret

; Public known_hosts history records attempted saves, never pin authority.
; Caller holds the derived known_hosts MAC key. EAX0 authenticated/floor only,
; 1 absent,-1 invalid/unreadable. No read performs a hidden write or restore.
ssh_cli_kh_history_load:
    push rbx
    lea  rdi, [rel ssh_cli_kh_history]
    call ssh_cli_kh_history_get
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_cli_kh_history]
    call ssh_cli_kh_valid
    test eax, eax
    jz   .bad
    mov  edi, [rel ssh_cli_kh_history + SSH_KH_REC_GEN]
    call ssh_cli_kh_note_floor
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; RDI=owned fixed-size output. Exact attributes/size;0 read,1 absent,-1 other.
; Lab primary-store fault selection does not select this separate variable.
ssh_cli_kh_history_get:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  rbx, rdi
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    mov  qword [rel ssh_cli_kh_size], SSH_KH_REC_SIZE
    mov  dword [rel ssh_cli_kh_attrs], 0
    lea  rcx, [rel ssh_cli_kh_history_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    lea  r8, [rel ssh_cli_kh_attrs]
    lea  r9, [rel ssh_cli_kh_size]
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], rbx
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, SSH_KH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    mov  eax, 1
    jmp  .out
.read:
    cmp  dword [rel ssh_cli_kh_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  qword [rel ssh_cli_kh_size], SSH_KH_REC_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=authenticated complete candidate. Existing history must authenticate,
; and the candidate must exceed its floor. Independently gate history, then
; revoke all future admission once before its first possibly durable write.
; EAX0 exact history,-1 no write,-2 issued history uncertainty.
ssh_cli_kh_history_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsp
    mov  r14, rdi
    mov  r12, [rel runtime_services]      ; caller checked both function pointers
    call ssh_cli_kh_history_load
    test eax, eax
    js   .bad
    mov  eax, [r14 + SSH_KH_REC_GEN]
    cmp  eax, [rel ssh_cli_kh_floor]
    jbe  .bad
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel ssh_cli_kh_var_guid]
    lea  rsi, [rel ssh_cli_kh_history_name]
    lea  rcx, [rel str_sshcli_kh_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    mov  edi, [r14 + SSH_KH_REC_GEN]
    call ssh_cli_kh_note_floor
    call ssh_cli_kh_revoke
    lea  rcx, [rel ssh_cli_kh_history_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, SSH_KH_REC_SIZE
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], r14
    call [r12 + 0x58]
    mov  rsp, r13
    test rax, rax
    jnz  .uncertain
    lea  rdi, [rel ssh_cli_kh_history_verify]
    call ssh_cli_kh_history_get
    test eax, eax
    jnz  .uncertain
    mov  rdi, r14
    lea  rsi, [rel ssh_cli_kh_history_verify]
    mov  edx, SSH_KH_REC_SIZE
    call memcmp
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel ssh_cli_kh_history_verify]
    call ssh_cli_kh_valid
    test eax, eax
    jz   .uncertain
    xor  eax, eax
    jmp  .out
.uncertain:
    mov  eax, -2
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Owner CLEAR has already revoked admission and verified primary absence.
; Retire history last, through its own storage gate and exact absence check.
; Malformed history can be deliberately cleared; it never supplies authority.
; EAX0 verified absent,-1 otherwise. Caller maps all failure to issued -2.
ssh_cli_kh_history_retire:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel ssh_cli_kh_var_guid]
    lea  rsi, [rel ssh_cli_kh_history_name]
    lea  rcx, [rel str_sshcli_kh_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel ssh_cli_kh_history_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    mov  r8d, AUTH_EFI_ATTRS
    xor  r9d, r9d
    and  rsp, -16
    sub  rsp, 48
    mov  qword [rsp + 32], 0
    call [r12 + 0x58]
    mov  rsp, r13
    test rax, rax
    jz   .verify
    mov  rdx, SSH_KH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
.verify:
    lea  rdi, [rel ssh_cli_kh_history_verify]
    call ssh_cli_kh_history_get
    cmp  eax, 1
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; RCQ-08 client identity record: PaOSSshClientId {magic, version, size, gen,
; enrolled, public key, MAC}. No secret: the seed is re-derived from the
; machine secret and the generation. Serialized on the idle loop, as known_hosts.
; ---------------------------------------------------------------------------
; ssh_cli_cid_load -> EAX 0 (ssh_cli_cid_state decided), -1 not decided: a
; principal other than the owner is bound (it never sets the state). Once per
; boot: no runtime services BOOT; no record NONE; a valid record whose key the
; machine secret still derives ENROLLED; anything else UNVERIFIED (refused, and
; owner repair needs authenticated reload or trusted local generation history).
ssh_cli_cid_load:
    push rbx
    cmp  byte [rel ssh_cli_cid_state], SSH_CID_ST_UNLOADED
    jne  .ok
    call principal_current
    test rax, rax
    jz   .bound_ok
    cmp  rax, PRIN_OWNER
    jne  .other_principal
.bound_ok:
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .boot
    call ssh_cli_cid_history_load
    test eax, eax
    js   .unverified
    call ssh_cli_cid_read_valid
    cmp  eax, 1
    je   .none
    test eax, eax
    jnz  .unverified
    call ssh_cli_cid_publish
    jmp  .ok
.none:
    ; Authenticated durable history or a local attempted write makes absence
    ; an existing-store loss, never first-run enrollment.
    cmp  dword [rel ssh_cli_cid_floor], 0
    jne  .unverified
    mov  byte [rel ssh_cli_cid_state], SSH_CID_ST_NONE
    jmp  .ok
.boot:
    mov  byte [rel ssh_cli_cid_state], SSH_CID_ST_BOOT
    jmp  .ok
.unverified:
    mov  dword [rel ssh_cli_cid_gen], 0 ; never adopt an unauthenticated generation
    call ssh_cli_cid_revoke
    lea  rdi, [rel str_sshcli_cid_unverified_serial]
    call serial_string
.ok:
    call ssh_cli_cid_cleanup
    xor  eax, eax
    pop  rbx
    ret
.other_principal:
    call ssh_cli_cid_cleanup
    mov  eax, -1
    pop  rbx
    ret

; Explicit recovery only: no state reset, absent-record/per-boot fallback or
; automatic retry. Exact authenticated durable identity restores admission.
ssh_cli_cid_reload:
    push rbx
    call principal_current
    test rax, rax
    jz   .owner
    cmp  rax, PRIN_OWNER
    jne  .refused
.owner:
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .refused
    call ssh_cli_cid_history_load
    test eax, eax
    js   .invalid
    call ssh_cli_cid_read_valid
    test eax, eax
    jnz  .invalid
    call ssh_cli_cid_publish
    xor  ebx, ebx
    jmp  .out
.invalid:
    call ssh_cli_cid_revoke
.refused:
    mov  ebx, -1
.out:
    call ssh_cli_cid_cleanup
    mov  eax, ebx
    pop  rbx
    ret

; EAX0 valid staged record,1 observed absence,-1 invalid/unreadable.
; MAC and machine-derived public key must both match before any publication.
ssh_cli_cid_read_valid:
    push rbx
    call ssh_cli_cid_getvar
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_cli_cid_stage]
    call ssh_cli_cid_valid
    test eax, eax
    jz   .bad
    mov  edi, [rel ssh_cli_cid_stage + SSH_CID_REC_GEN]
    lea  rsi, [rel ssh_cli_cid_check]
    call ssh_cli_cid_derive_pub
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_cid_check]
    lea  rsi, [rel ssh_cli_cid_stage + SSH_CID_REC_PUB]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; High-water mark from authenticated primary/history records and our own MACed
; write attempts. Durable history carries attempts across restart, without
; rollback protection. Unvalidated firmware bytes never supply this floor.
ssh_cli_cid_note_floor:
    cmp  edi, [rel ssh_cli_cid_floor]
    jbe  .out
    mov  [rel ssh_cli_cid_floor], edi
.out:
    ret

ssh_cli_cid_publish:
    sub  rsp, 8
    call ssh_cli_cid_revoke
    lea  rdi, [rel ssh_cli_cid_pub]
    lea  rsi, [rel ssh_cli_cid_stage + SSH_CID_REC_PUB]
    mov  edx, 32
    call memcpy
    mov  edi, [rel ssh_cli_cid_stage + SSH_CID_REC_GEN]
    mov  [rel ssh_cli_cid_gen], edi
    call ssh_cli_cid_note_floor
    mov  byte [rel ssh_cli_cid_state], SSH_CID_ST_ENROLLED ; publish last
    add  rsp, 8
    ret

; Revoke global identity admission/cache only, never another transport context,
; known-host pins, enrolled-system credentials or persistent machine secret.
ssh_cli_cid_revoke:
    sub  rsp, 8
    mov  byte [rel ssh_cli_cid_state], SSH_CID_ST_UNVERIFIED
    mov  byte [rel ssh_cli_id_ready], 0
    lea  rdi, [rel ssh_cli_id_seed]
    xor  esi, esi
    mov  edx, ssh_cli_id_blob + 64 - ssh_cli_id_seed
    call memset
    lea  rdi, [rel ssh_cli_cid_pub]
    xor  esi, esi
    mov  edx, 32
    call memset
    call ssh_cli_identity_seed_done
    add  rsp, 8
    ret

ssh_cli_cid_cleanup:
    sub  rsp, 8
    lea  rdi, [rel ssh_cli_cid_seed]
    xor  esi, esi
    mov  edx, ssh_cli_cid_pub - ssh_cli_cid_seed
    call memset
    lea  rdi, [rel ssh_cli_cid_check]
    xor  esi, esi
    mov  edx, ssh_cli_cid_history_verify + SSH_CID_REC_SIZE - ssh_cli_cid_check
    call memset
    add  rsp, 8
    ret

ssh_cli_cid_derive_seed:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel ssh_cli_cid_info]
    lea  rsi, [rel ssh_cli_cid_seed_info]
    mov  edx, ssh_cli_cid_seed_info.len
    call memcpy
    bswap ebx
    mov  [rel ssh_cli_cid_info + ssh_cli_cid_seed_info.len], ebx
    lea  rdi, [rel ssh_cli_cid_info]
    mov  esi, ssh_cli_cid_seed_info.len + 4
    lea  rdx, [rel ssh_cli_cid_seed]
    call ssh_cli_y_hkdf
    pop  rbx
    ret

; ssh_cli_cid_derive_pub(EDI = generation, RSI = 32-byte out) -> EAX 0 with out =
; that generation's public key; nonzero otherwise. The seed is wiped either way.
ssh_cli_cid_derive_pub:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rsi
    call ssh_cli_cid_derive_seed
    mov  r12d, eax
    test eax, eax
    jnz  .wipe
    lea  rdi, [rel ssh_cli_cid_seed]
    mov  esi, 32
    mov  rdx, rbx
    call ed25519_public_from_seed
    mov  r12d, eax
.wipe:
    call ssh_cli_identity_seed_done
    mov  eax, r12d
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ssh_cli_cid_mac(RDI = record) -> EAX 0 with ssh_cli_cid_mac_out =
; HMAC-SHA256(HKDF(machine secret, "PaOS/SSH/client-id-record/v1"), record[0:48]),
; nonzero otherwise. The key is derived for this MAC and wiped after it.
ssh_cli_cid_mac:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel ssh_cli_cid_mac_info]
    mov  esi, ssh_cli_cid_mac_info.len
    lea  rdx, [rel ssh_cli_cid_key]
    call ssh_cli_y_hkdf
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_cli_cid_mac_out]
    lea  rsi, [rel ssh_cli_cid_key]
    mov  edx, 32
    mov  rcx, rbx
    mov  r8d, SSH_CID_REC_MAC
    call hmac_sha256
    lea  rdi, [rel ssh_cli_cid_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    xor  eax, eax
.out:
    pop  rbx
    ret

; ssh_cli_cid_valid(RDI = record) -> EAX 1/0: magic, version, size, a nonzero
; generation, enrolled, and the MAC (compared in constant time).
ssh_cli_cid_valid:
    push rbx
    mov  rbx, rdi
    cmp  dword [rbx], SSH_CID_MAGIC
    jne  .no
    cmp  word [rbx + 4], SSH_CID_VERSION
    jne  .no
    cmp  word [rbx + 6], SSH_CID_REC_SIZE
    jne  .no
    cmp  dword [rbx + SSH_CID_REC_GEN], 0
    je   .no
    cmp  dword [rbx + SSH_CID_REC_ENROLLED], 1
    jne  .no
    mov  rdi, rbx
    call ssh_cli_cid_mac
    test eax, eax
    jnz  .no
    lea  rsi, [rel ssh_cli_cid_mac_out]
    xor  eax, eax
    xor  ecx, ecx
.tag:
    movzx edx, byte [rbx + SSH_CID_REC_MAC + rcx]
    xor  dl, [rsi + rcx]
    or   eax, edx
    inc  ecx
    cmp  ecx, 32
    jb   .tag
    test eax, eax
    jnz  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; ssh_cli_cid_getvar -> EAX 0 read (NV|BS|RT, exact size) into
; ssh_cli_cid_stage, 1 absent, -1 unreadable / wrong attributes / wrong size.
ssh_cli_cid_getvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    mov  qword [rel ssh_cli_cid_size], SSH_CID_REC_SIZE
    mov  dword [rel ssh_cli_cid_attrs], 0
    lea  rcx, [rel ssh_cli_cid_var_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    lea  r8, [rel ssh_cli_cid_attrs]
    lea  r9, [rel ssh_cli_cid_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_cli_cid_stage]
    mov  [rsp + 32], rbx
%ifdef SSH_PROFILE_FAULT_ENABLED
    call ssh_cli_fault_getvar
%else
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
%endif
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, SSH_KH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    mov  eax, 1
    jmp  .out
.read:
    cmp  dword [rel ssh_cli_cid_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  qword [rel ssh_cli_cid_size], SSH_CID_REC_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_cli_cid_setvar(RDI=record,ESI=size) -> EAX0 exact / -1 no write / -2 uncertain. One SetVariable
; through the NVRAM storage gate, then an exact readback compare.
ssh_cli_cid_setvar:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsp
    mov  r14, rdi
    mov  r15d, esi
    cmp  r15, SSH_CID_REC_SIZE
    jne  .bad
    test r14, r14
    jz   .bad
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    cmp  qword [r12 + 0x58], 0
    je   .bad
    mov  rdi, r14
    call ssh_cli_cid_valid
    test eax, eax
    jz   .bad
    mov  edi, [r14 + SSH_CID_REC_GEN]
    lea  rsi, [rel ssh_cli_cid_check]
    call ssh_cli_cid_derive_pub
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_cid_check]
    lea  rsi, [r14 + SSH_CID_REC_PUB]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    mov  eax, [r14 + SSH_CID_REC_GEN]
    cmp  eax, [rel ssh_cli_cid_floor]
    jbe  .bad                           ; never reuse an attempted generation
    call storage_access_request_intent  ; storage canon: PaOS-namespace NVRAM = NORMAL
    mov  edx, eax
    lea  rdi, [rel ssh_cli_kh_var_guid]
    lea  rsi, [rel ssh_cli_cid_var_name]
    lea  rcx, [rel str_sshcli_cid_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    mov  rdi, r14
    call ssh_cli_cid_history_prepare     ; durable attempt before primary write
    test eax, eax
    jnz  .out                           ; preserve no-write/uncertain distinction
    mov  edi, [r14 + SSH_CID_REC_GEN]
    call ssh_cli_cid_note_floor
    call ssh_cli_cid_revoke              ; possible write: no cached signing authority
    lea  rcx, [rel ssh_cli_cid_var_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, r15d
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], r14
%ifdef SSH_PROFILE_FAULT_ENABLED
    call ssh_cli_fault_setvar
%else
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
%endif
    mov  rsp, r13
    test rax, rax
    jnz  .uncertain
    mov  qword [rel ssh_cli_cid_size], SSH_CID_REC_SIZE
    mov  dword [rel ssh_cli_cid_attrs], 0
    lea  rcx, [rel ssh_cli_cid_var_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    lea  r8, [rel ssh_cli_cid_attrs]
    lea  r9, [rel ssh_cli_cid_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_cli_cid_verify]
    mov  [rsp + 32], rbx
%ifdef SSH_PROFILE_FAULT_ENABLED
    call ssh_cli_fault_getvar
%else
    call [r12 + 0x48]                   ; exact readback
%endif
    mov  rsp, r13
    test rax, rax
    jnz  .uncertain
    cmp  dword [rel ssh_cli_cid_attrs], AUTH_EFI_ATTRS
    jne  .uncertain
    cmp  qword [rel ssh_cli_cid_size], r15
    jne  .uncertain
    mov  rdi, r14
    lea  rsi, [rel ssh_cli_cid_verify]
    mov  edx, r15d
    call memcmp
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel ssh_cli_cid_verify]
    call ssh_cli_cid_valid
    test eax, eax
    jz   .uncertain
    xor  eax, eax
    jmp  .out
.uncertain:
    mov  eax, -2
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Public attempted-generation history uses the same authenticated record format,
; a distinct PaOS variable, and no signing authority. Reads never write it.
; EAX0 valid and floor hydrated,1 absent,-1 unreadable/inauthentic.
ssh_cli_cid_history_load:
    push rbx
    lea  rdi, [rel ssh_cli_cid_history]
    call ssh_cli_cid_history_get
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_cli_cid_history]
    call ssh_cli_cid_valid
    test eax, eax
    jz   .bad
    mov  edi, [rel ssh_cli_cid_history + SSH_CID_REC_GEN]
    lea  rsi, [rel ssh_cli_cid_check]
    call ssh_cli_cid_derive_pub
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_cli_cid_check]
    lea  rsi, [rel ssh_cli_cid_history + SSH_CID_REC_PUB]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    mov  edi, [rel ssh_cli_cid_history + SSH_CID_REC_GEN]
    call ssh_cli_cid_note_floor
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; RDI=80-byte output. Exact NV|BS|RT/size; 0 read,1 absent,-1 otherwise.
; The lab primary-record fault selector does not select this separate variable.
ssh_cli_cid_history_get:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  rbx, rdi
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    mov  qword [rel ssh_cli_cid_size], SSH_CID_REC_SIZE
    mov  dword [rel ssh_cli_cid_attrs], 0
    lea  rcx, [rel ssh_cli_cid_history_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    lea  r8, [rel ssh_cli_cid_attrs]
    lea  r9, [rel ssh_cli_cid_size]
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], rbx
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, SSH_KH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    mov  eax, 1
    jmp  .out
.read:
    cmp  dword [rel ssh_cli_cid_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  qword [rel ssh_cli_cid_size], SSH_CID_REC_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=already authenticated/derived candidate from cid_setvar. Authenticate the
; current history before replacing it; candidate must exceed its floor too.
; EAX0 exact durable attempt,-1 no write,-2 issued history write uncertain.
; A verified history never publishes identity, including after a primary fault.
ssh_cli_cid_history_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsp
    mov  r14, rdi
    mov  r12, [rel runtime_services]       ; caller verified Get/Set availability
    call ssh_cli_cid_history_load
    test eax, eax
    js   .bad
    mov  eax, [r14 + SSH_CID_REC_GEN]
    cmp  eax, [rel ssh_cli_cid_floor]
    jbe  .bad
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel ssh_cli_kh_var_guid]
    lea  rsi, [rel ssh_cli_cid_history_name]
    lea  rcx, [rel str_sshcli_cid_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    mov  edi, [r14 + SSH_CID_REC_GEN]
    call ssh_cli_cid_note_floor
    call ssh_cli_cid_revoke               ; before first potentially durable write
    lea  rcx, [rel ssh_cli_cid_history_name]
    lea  rdx, [rel ssh_cli_kh_var_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, SSH_CID_REC_SIZE
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], r14
    call [r12 + 0x58]
    mov  rsp, r13
    test rax, rax
    jnz  .uncertain
    lea  rdi, [rel ssh_cli_cid_history_verify]
    call ssh_cli_cid_history_get
    test eax, eax
    jnz  .uncertain
    mov  rdi, r14
    lea  rsi, [rel ssh_cli_cid_history_verify]
    mov  edx, SSH_CID_REC_SIZE
    call memcmp
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel ssh_cli_cid_history_verify]
    call ssh_cli_cid_valid
    test eax, eax
    jz   .uncertain
    xor  eax, eax
    jmp  .out
.uncertain:
    mov  eax, -2
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

HEAP_ONCE_ACCESSOR ssh_cli_slots_base, ssh_cli_slots_ptr, SSH_SESS_MAX * SSH_CLI_SLOT_SIZE, str_sshcli_heap_fail
HEAP_ONCE_ACCESSOR ssh_sess_save_base, ssh_sess_save_ptr, SSH_SESS_MAX * SSH_CLI_REGION_SIZE, str_sshcli_heap_fail

; ----------------------------- read-only data -----------------------------
ssh_cli_ed25519_key_prefix: SSHCLI_ED25519_PREFIX 32
ssh_cli_ed25519_sig_prefix: SSHCLI_ED25519_PREFIX 64
str_ssh_userauth:     db "ssh-userauth"
str_ssh_ed25519:      db "ssh-ed25519"
str_ssh_connection:   db "ssh-connection"
str_ssh_publickey:    db "publickey"
str_ka_name:          db "keepalive@openssh.com"    ; 21 bytes, no terminator
str_ch_session:       db "session"
str_ch_ptyreq:        db "pty-req"
str_ch_term:          db "xterm-256color"
str_ch_shell:         db "shell"
str_ch_exit_status: db "exit-status"
str_ch_exit_signal: db "exit-signal"
str_ch_winch:         db "window-change"
str_sshcli_id_comment: db " paos-client", 0
.len equ $ - str_sshcli_id_comment
str_sshcli_fp_head:   db "ssh: host key SHA256:"
.len equ $ - str_sshcli_fp_head
ssh_cli_trust_hex: db "0123456789abcdef"
str_sshcli_fp_tail:   db " (untrusted). REFUSED: verify independently, then owner-signed SSHKHTRUST <IPv4>:<port> <SHA256-hex>. SHA256-hex="
.len equ $ - str_sshcli_fp_tail
str_sshcli_fp_tail_saved: db " (untrusted; owner provisioning required)", 13, 10
.len equ $ - str_sshcli_fp_tail_saved
str_sshcli_kh_poisoned: db "ssh: REFUSED: saved known_hosts is damaged or not authentic; host trust and authentication require owner-signed SSHKHCLEAR", 13, 10
.len equ $ - str_sshcli_kh_poisoned
str_sshcli_kh_uncertain: db "ssh: REFUSED: known_hosts commit uncertain; owner-signed SSHKHCLEAR required",13,10
.len equ $ - str_sshcli_kh_uncertain
str_sshcli_kh_nokey:  db "ssh: WARNING: known_hosts unavailable (no machine secret): host keys are trusted for this boot only", 13, 10
.len equ $ - str_sshcli_kh_nokey
str_sshcli_kh_notsaved: db "ssh: WARNING: host pin not saved; if commit is uncertain new trust is refused until owner SSHKHCLEAR", 13, 10
.len equ $ - str_sshcli_kh_notsaved
str_sshcli_kh_poisoned_serial: db "[PAOS64] ssh.cli: known_hosts record refused (malformed or not authentic); fail closed [ssh.cli.known_hosts.poisoned]",13,10,0
str_sshcli_kh_cleared_serial: db "[PAOS64] ssh.cli: known_hosts cleared by the owner [ssh.cli.known_hosts.cleared]",13,10,0
str_sshcli_kh_nvg_tag: db "ssh_cli_kh_setvar",0
str_sshcli_cid_nvg_tag: db "ssh_cli_cid_setvar",0
ssh_cli_cid_seed_info: db "PaOS/SSH/client-identity/v1"      ; || be32(generation)
.len equ $ - ssh_cli_cid_seed_info
ssh_cli_cid_mac_info: db "PaOS/SSH/client-id-record/v1"
.len equ $ - ssh_cli_cid_mac_info
str_sshcli_cid_unverified_serial: db "[PAOS64] ssh.cli: client identity refused (record malformed or not authentic, or the machine secret changed); ssh refused until authenticated reload or owner repair from trusted history [ssh.cli.client_id.unverified]",13,10,0
str_sshcli_cid_owner_only_serial: db "[PAOS64] ssh.cli: REFUSED: the client key signs only in an owner session [ssh.cli.client_id.owner_only]",13,10,0
str_sshcli_cid_enrolled_serial: db "[PAOS64] ssh.cli: client identity enrolled by the owner [ssh.cli.client_id.enrolled]",13,10,0
ssh_cli_kh_info:      db "PaOS/SSH/known_hosts/v1"
.len equ $ - ssh_cli_kh_info
align 8, db 0                         ; EFI_GUID 8-aligned; the CHAR16 name after it even (char16_align_check)
; 7268a9b4-3f8a-45a0-9f8d-1b73e9ac2142: the svc/ssh PaOS vendor GUID (nvg_paos_guids[1]).
ssh_cli_kh_var_guid:
    dd 0x7268a9b4
    dw 0x3f8a,0x45a0
    db 0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x21,0x42
ssh_cli_kh_var_name:
    dw 'P','a','O','S','S','s','h','K','n','o','w','n','H','o','s','t','s',0
ssh_cli_kh_history_name:
    dw 'P','a','O','S','S','s','h','K','n','o','w','n','H','o','s','t','s','H','i','s','t','o','r','y',0
ssh_cli_cid_var_name:                   ; RCQ-08: same vendor GUID (ssh_cli_kh_var_guid)
    dw 'P','a','O','S','S','s','h','C','l','i','e','n','t','I','d',0
ssh_cli_cid_history_name:
    dw 'P','a','O','S','S','s','h','C','l','i','e','n','t','I','d','H','i','s','t','o','r','y',0
str_sshcli_pins_full: db "ssh: REFUSED: no free host-key pin slot; existing pins are retained across restart; review owner-managed trust before adding a host (pinned hosts still work)", 13, 10
.len equ $ - str_sshcli_pins_full
str_sshcli_heap_fail: db "[PAOS64] ssh.cli: no heap for the ssh sessions [ssh.cli.heap]",13,10,0
str_sshcli_hostkey_changed: db "[PAOS64] ssh.cli: REFUSED: the host key conflicts with the owner-provisioned/saved pin [ssh.cli.hostkey_changed]",13,10,0
str_sshcli_hostkey_full: db "[PAOS64] ssh.cli: REFUSED: host-key pin table full; new host not trusted [ssh.cli.hostkey_full]",13,10,0
str_sshcli_ecdh:      db "[PAOS64] ssh.cli: KEX_ECDH_INIT sent [ssh.cli.ecdh]",13,10,0
str_sshcli_kex:       db "[PAOS64] ssh.cli: ECDH reply verified, keys derived, NEWKEYS sent [ssh.cli.kex]",13,10,0
str_sshcli_newkeys:   db "[PAOS64] ssh.cli: server NEWKEYS received, transport encrypted [ssh.cli.newkeys]",13,10,0
str_sshcli_svc:       db "[PAOS64] ssh.cli: SERVICE_ACCEPT decrypted over GCM [ssh.cli.svc]",13,10,0
str_sshcli_svcreq:    db "[PAOS64] ssh.cli: SERVICE_REQUEST(ssh-userauth) sent (GCM) [ssh.cli.svcreq]",13,10,0
str_sshcli_authreq:   db "[PAOS64] ssh.cli: USERAUTH_REQUEST(publickey ssh-ed25519) sent [ssh.cli.authreq]",13,10,0
str_sshcli_auth:      db "[PAOS64] ssh.cli: USERAUTH_SUCCESS -- authenticated [ssh.cli.auth]",13,10,0
str_sshcli_authfail:  db "[PAOS64] ssh.cli: USERAUTH_FAILURE from server [ssh.cli.authfail]",13,10,0
str_sshcli_encfail:   db "[PAOS64] ssh.cli: DIAG inbound encrypted packet FAILED to open [ssh.cli.encfail]",13,10,0
str_sshcli_chreq:     db "[PAOS64] ssh.cli: CHANNEL_OPEN(session) sent [ssh.cli.chopen.req]",13,10,0
str_sshcli_chopen:    db "[PAOS64] ssh.cli: CHANNEL_OPEN_CONFIRMATION -- interactive channel up [ssh.cli.chopen]",13,10,0
str_sshcli_pty:       db "[PAOS64] ssh.cli: pty-req sent [ssh.cli.pty]",13,10,0
str_sshcli_shell:     db "[PAOS64] ssh.cli: shell accepted -- interactive session live [ssh.cli.shell]",13,10,0
str_sshcli_chfail:    db "[PAOS64] ssh.cli: CHANNEL_OPEN_FAILURE [ssh.cli.chfail]",13,10,0
str_sshcli_chclose:   db "[PAOS64] ssh.cli: CHANNEL_CLOSE received [ssh.cli.chclose]",13,10,0
str_sshcli_transport_lost: db "[PAOS64] ssh.cli: TCP transport lost; channel retired [ssh.cli.transport_lost]",13,10,0
str_sshcli_tcp_ended: db "[PAOS64] ssh client: the TCP connection ended under the session (see ssh_cli_error)", 13, 10, 0
str_sshcli_tcp:       db "[PAOS64] ssh.cli: TCP connected to peer [ssh.cli.tcp]",13,10,0
str_sshcli_banner:    db "[PAOS64] ssh.cli: server banner + our KEXINIT sent, V_S=",0
str_sshcli_kexinit:   db "[PAOS64] ssh.cli: server KEXINIT received [ssh.cli.kexinit]",13,10,0
str_sshcli_crlf:      db 13,10,0

; ----------------------------- writable state -----------------------------
; Deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_ssh_client_0 0
align 16
ssh_cli_region_begin:                  ; one session's own fields (swapped per session)
ssh_cli_ctx_ptr:      dq 0             ; its heap slot: SSH context, then I_S, then the input ring
ssh_cli_tcb:          dq 0
ssh_cli_data_sink:    dq 0             ; optional callback(rdi=data, esi=len); 0 = serial dump
ssh_cli_kh_admitted_epoch: dq 0         ; exact trust epoch checked during KEX
ssh_cli_ka_left:      dq 0
ssh_cli_ka_last:      dq 0
ssh_cli_lport:        dd 0             ; the local port its tuple was opened with
ssh_cli_target_ip:    dd 0
ssh_cli_target_port:  dw 0
ssh_cli_state:        db 0
ssh_cli_error:        db 0
ssh_cli_tcp_seen:     db 0
ssh_cli_banner_seen:  db 0
ssh_cli_kexinit_seen: db 0
ssh_cli_publickey_ok: db 0
ssh_cli_last_enc_msg: db 0
ssh_cli_want_ecdh:    db 0
ssh_cli_want_svcreq:  db 0
ssh_cli_want_userauth: db 0
ssh_cli_want_chanopen: db 0
ssh_cli_want_pty:     db 0
ssh_cli_want_shell:   db 0
ssh_cli_want_winadj:  db 0
ssh_cli_chan_ready:   db 0
ssh_cli_chan_closed:  db 0
ssh_cli_request_pending: db 0          ; NONE/PTY/SHELL; part of the saved session region
ssh_cli_peer_eof:     db 0             ; receive direction only, saved per session
ssh_cli_owner_armed:  db 0             ; RCQ-08: the owner started it (signs with the client key)
ssh_cli_retiring:     db 0             ; revoked; only already owed controls may drain
ssh_cli_retire_abort: db 0             ; tuple abort deferred until consumer return
align 4, db 0
ssh_cli_vs_len:       dd 0
ssh_cli_is_len:       dd 0
ssh_cli_user_len:     dd 0
ssh_cli_local_chan:   dd 0
ssh_cli_remote_chan:  dd 0
ssh_cli_local_window: dd 0
ssh_cli_remote_window: dd 0
ssh_cli_remote_max_packet: dd 0       ; peer uint32 limit, saved with this session
ssh_cli_term_cols:    dd 80
ssh_cli_term_rows:    dd 24
ssh_cli_shell_count:  dd 0
ssh_cli_winch_count:  dd 0
ssh_cli_keepalive_count: dd 0
ssh_cli_txq_head:     dd 0
ssh_cli_txq_tail:     dd 0
ssh_cli_txq_len:      dd 0
ssh_cli_request_failures: dd 0
ssh_cli_want_close:   db 0
ssh_cli_close_sent:   db 0
align 8, db 0
ssh_cli_control_left: dq 0
ssh_cli_control_last: dq 0
ssh_cli_control_armed: db 0
align 8, db 0
ssh_cli_global_failures: dd 0         ; owed identical REQUEST_FAILURE records, saved across retirement
align 8, db 0
ssh_cli_exit_begin:
ssh_cli_exit_kind:    dd 0             ; 0 unknown, 1 exit-status, 2 exit-signal
ssh_cli_exit_status:  dd 0             ; full unsigned remote status, only valid for kind1
ssh_cli_exit_core:    dd 0
ssh_cli_exit_signal_len: dd 0
ssh_cli_exit_message_len: dd 0
ssh_cli_exit_language_len: dd 0
ssh_cli_exit_signal:  times SSH_EXIT_SIGNAL_CAP db 0
ssh_cli_exit_message: times SSH_EXIT_MESSAGE_CAP db 0
ssh_cli_exit_language: times SSH_EXIT_LANGUAGE_CAP db 0
ssh_cli_exit_end:
; Public initial-key witness, parked with the actual session. No credential,
; private scalar or store bytes are exported. Cleared on every new dial.
align 8, db 0
ssh_cli_key_check:     dq 0            ; 0 no comparison, 1 exact, 2 changed, 3 unknown
ssh_cli_userauth_calls: dq 0           ; saturating entry count, including refusals
ssh_cli_checked_digest: times 32 db 0
ssh_cli_ephemeral:    times 32 db 0    ; client x25519 private scalar (KEX)
ssh_cli_vs:           times 256 db 0   ; V_S, the server's version line
ssh_cli_user:         times 64 db 0
ssh_cli_region_end:
align 8
ssh_cli_exec_epoch:   dq 0             ; caller token high-water; never parked/restored or reused
ssh_sess_tcb:         times SSH_SESS_MAX dq 0   ; the session's connection (routing)
; Independent slot-owned {remaining, baseline} pairs; never swapped as globals.
ssh_sess_poll_timers: times SSH_SESS_MAX*2 dq 0
ssh_sess_drain_timers: times SSH_SESS_MAX*2 dq 0
ssh_cli_slots_ptr:    dq 0
ssh_sess_save_ptr:    dq 0
ssh_sess_lport:       times SSH_SESS_MAX dd 0
ssh_sess_active:      dd -1                     ; session loaded in the region (-1 none)
ssh_sess_last:        dd -1                     ; most recently begun (diagnostics)
ssh_cli_port_next:    dd 0
ssh_sess_used:        times SSH_SESS_MAX db 0   ; 0 free, 1 live, 2 draining after end
ssh_sess_busy:        times SSH_SESS_MAX db 0   ; active receive/sink consumer, not swapped
ssh_cli_scrub_shared_pending: db 0
ssh_cli_id_ready:     db 0
align 8, db 0
; GAP05 caller-only custody. ROOT105740 explicitly selects I2119/C369 us
; from TARGET105735 for the next candidate, no margin/silent widening. Actual
; twin maxima were 2119.285/369.463 us; this exact integer policy is retained.
; The measured core C excludes its final XOR/RET and SEC/AV return tails.
; Metal fence/service coverage is UNOBSERVED; an overrun is FAIL, not a new D.
align 16, db 0
ssh_sess_bindings: times SSH_SESS_MAX*8 dq 0
ssh_sess_cancel: times SSH_SESS_MAX*2 dq 0
ssh_sess_clock: times SSH_SESS_MAX dq 0
ssh_sess_work_busy: times SSH_SESS_MAX db 0
ssh_cli_work_busy: db 0
align 8, db 0
ssh_cli_work_slot: dd 0
align 8, db 0
ssh_cli_core_interrupt_us: dq 2119
ssh_cli_core_cleanup_us: dq 369
ssh_cli_core_facts_valid: dq 1
align 16, db 0
ssh_cli_work_private_begin:
ssh_cli_work_capsule: times SW_BYTES db 0
ssh_cli_work_result: times SW_RESULT_BYTES db 0
ssh_cli_work_snapshot: times 64 db 0
ssh_cli_work_public: times 32 db 0
ssh_cli_work_request: times 256 db 0
ssh_cli_work_tcp: times 72 db 0
ssh_cli_work_cid_gen: dq 0
ssh_cli_work_ctx: dq 0
ssh_cli_work_kh_epoch: dq 0
ssh_cli_work_start_us: dq 0
ssh_cli_work_earned_lease_ms: dq 0
ssh_cli_work_reserve_us: dq 0
ssh_cli_work_service_bound_us: dq 0
ssh_cli_work_private_end:
; shared scratch: every user finishes within one serialized call
ssh_cli_ks_len:       dd 0
ssh_cli_sig_len:      dd 0
ssh_cli_ks_buf:       times 128 db 0   ; received server host key blob (K_S)
ssh_cli_sig_buf:      times 128 db 0   ; received server signature blob
ssh_cli_pkt:          times 128 db 0   ; clear-text KEX payload builder
ssh_cli_chpkt:        times SSH_CLI_EXEC_CAP + 32 db 0   ; channel/transport payload builder
ssh_cli_txtmp:        times 256 db 0
ssh_cli_sigblob:      times 96 db 0
ssh_cli_sig64:        times 64 db 0
ssh_cli_authcore:     times 320 db 0
ssh_cli_signbuf:      times 256 db 0
ssh_cli_hk_digest:    times 32 db 0
ssh_cli_pins:         times SSH_CLI_PINS * SSH_CLI_PIN_SZ db 0
; RCQ-07b known_hosts store
align 8, db 0
ssh_cli_kh_size:      dq 0
ssh_cli_kh_attrs:     dd 0
align 8, db 0
ssh_cli_kh_epoch:     dq 1              ; volatile admission token, never wraps
ssh_cli_kh_floor:     dd 0              ; authenticated/attempted generation high-water
ssh_cli_kh_gen:       dd 0
ssh_cli_kh_state:     db 0
align 8, db 0
ssh_cli_kh_key:       times 32 db 0
ssh_cli_kh_mac_out:   times 32 db 0
ssh_cli_kh_stage:     times SSH_KH_REC_SIZE db 0
ssh_cli_kh_verify:    times SSH_KH_REC_SIZE db 0
ssh_cli_kh_history:   times SSH_KH_REC_SIZE db 0
ssh_cli_kh_history_verify: times SSH_KH_REC_SIZE db 0
; this boot's client identity (never in the image, never persisted)
ssh_cli_id_seed:      times 32 db 0
ssh_cli_id_pub:       times 32 db 0
ssh_cli_id_blob:      times 64 db 0
; RCQ-08 client identity (PaOSSshClientId)
ssh_cli_cid_size:     dq 0
ssh_cli_cid_attrs:    dd 0
ssh_cli_cid_gen:      dd 0              ; last authenticated published generation
ssh_cli_cid_floor:    dd 0              ; authenticated primary/history and local attempts
ssh_cli_cid_state:    db 0
align 4, db 0
ssh_cli_cid_seed:     times 32 db 0     ; a derived seed: wiped right after its use
ssh_cli_cid_key:      times 32 db 0     ; the record MAC key: wiped right after its use
ssh_cli_cid_mac_out:  times 32 db 0
ssh_cli_cid_pub:      times 32 db 0     ; the enrolled public key
ssh_cli_cid_check:    times 32 db 0     ; a derived public key under comparison
ssh_cli_cid_info:     times 32 db 0     ; the seed's HKDF info
ssh_cli_cid_stage:    times SSH_CID_REC_SIZE db 0
ssh_cli_cid_verify:   times SSH_CID_REC_SIZE db 0
ssh_cli_cid_history:  times SSH_CID_REC_SIZE db 0
ssh_cli_cid_history_verify: times SSH_CID_REC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_svc_ssh_client_0
SSH_CLI_REGION_SIZE   equ ssh_cli_region_end - ssh_cli_region_begin
