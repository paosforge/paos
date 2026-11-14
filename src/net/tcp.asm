;; MODULE net/tcp
%include "core/abi/build_profile.inc"
;; LAYER 4
;; EXPORTS tcp_options_validate, tcp_options_validate_kat, tcp_handshake_selftest, tcp_build_synack_kat, tcp_build_synack_fault_battery, tcp_live_init, tcp_client_bind, tcp_client_unbind, tcp_public_ssh_bind, tcp_client_alias_bind, tcp_client_alias_unbind, tcp_client_ready, tcp_client_open, tcp_client_open_tracked, tcp_client_open_tracked_try, tcp_client_epoch_io, tcp_client_epoch_snapshot, tcp_client_open_routed, tcp_client_io_owned, tcp_client_send, tcp_client_abort, tcp_listener_register, tcp_send, tcp_close, tcp_poll, tcp_diag_snapshot, tcp4_ingress, TCP_SERVER_DATA_REV, TCPD_LISTENERS, TCPD_USED, TCPD_MAX, TCPD_SYN, TCPD_EST, TCPD_CLOSING, TCPD_TIMEWAIT, TCPD_ACCEPTS, TCPD_RX_BYTES, TCPD_TX_BYTES, TCPD_RETRANSMITS, TCPD_REAPED, TCPD_FULL_RSTS, TCPD_RSTS, TCPD_CLOSES, TCPD_LOCK_BUSY, TCPD_LAST_STAGE, TCPD_SIZE, tcp_m_listen, tcp_m_syn_rx, tcp_m_synack_tx, tcp_m_established, tcp_client_epoch_retirement, tcp_client_epoch_reap
;; IMPORTS boot/serial, core/time, core/lib/fmt, core/lib/cksum, core/lib/mem, lib/safe_buffer, core/lock, net/netdev, net/arp_cache, core/heap, net/dns, net/udp, core/csprng, core/lib/hmac_sha256
;; CAPS
;; OWNER saga:net
;; LOCK: tcp_live_lock PROTECTS tcp_public_ssh_callback, tcp_client_alias_ip, tcp_client_alias_ready, tcp_client_public, tcp_live_ip, tcp_live_mac, tcp_listeners, tcp_tcbs, tcp_client_routes, tcp_persist_state, tcp_persist_epoch_next, tcp_rx_ooo, tcp_rx_epoch_next, tcp_isn_secret, tcp_isn_secret_ready, tcp_isn_count, tcp_syn_retirements, tcp_reap_completions
;; LOCK: tcp_tx_lock PROTECTS tcp_tx_frame
;; LOCK: tcp_cksum_lock PROTECTS tcp_cksum_wire
; ============================================================================
; net/tcp.asm — the TCP 3-way-handshake state machine LOGIC (contract 1044 /
; C10c, the qemu rung of the bare-metal 1026 net_tcp_handshake_seam). TCP rides
; ON TOP of the ipv4 layer proven in 1042 (net/stack.asm); here we prove the
; SYN -> SYN-ACK -> ACK -> ESTABLISHED sequence-number arithmetic at boot over
; CANNED in-memory segments — no NIC, no host `nc` (the live-wire connect is
; 1026/bare_metal). The selftest is CONTENT-graded: it drives a listener TCB
; LISTEN -> SYN_RCVD -> ESTABLISHED and PRINTS the emitted SYN-ACK's ack number,
; flag byte, and TCP checksum plus the final state; the probe re-checks that
; ack == SYN.seq+1, flags == 0x12 (SYN|ACK), checksum non-zero, state ==
; ESTABLISHED. A stub that emits the marker without running the state machine
; FAILS the KAT (the printed ack/checksum are read back OUT OF the built segment,
; not literals).
;
;   * tcp.handshake.logic — build the SYN-ACK REPLY for a canned SYN: swap the
;                           ports, our ISN as seq=Y, ack = SYN.seq+1, flags
;                           SYN|ACK, and a correct TCP checksum computed over the
;                           TCP pseudo-header (src/dst IP, proto=6, TCP length) +
;                           the TCP header (a classic off-by-scope bug is summing
;                           the TCP header alone). Self-verifying: re-summing the
;                           reply WITH the checksum inserted folds to 0 (RFC1071).
;                           Then a canned ACK (ack == Y+1) advances SYN_RCVD ->
;                           ESTABLISHED.
;   * NEGATIVE GATE        — a short/truncated segment (len < 20) is bounds-checked
;                           and REJECTED by tcp_build_synack (no OOB, no crash);
;                           a segment without the SYN bit does not open the TCB.
;
; All checksum math goes through core/lib/cksum (G1: one one's-complement routine
; for the whole stack — the pseudo-header is prepended by the caller, per that
; module's contract).
; ============================================================================

; --- TCP header field offsets (RFC 793, no options: 20-byte header) ------------
TCP_SRCPORT   equ 0
TCP_DSTPORT   equ 2
TCP_SEQ       equ 4
TCP_ACK       equ 8
TCP_DATAOFF   equ 12       ; data-offset (high nibble) + reserved
TCP_FLAGS     equ 13
TCP_WINDOW    equ 14
TCP_CKSUM     equ 16
TCP_URG       equ 18
TCP_HDR_LEN   equ 20

; tcp_options_validate(RDI=segment, ESI=header bytes) -> EAX=0/-1,
; R8D=effective peer MSS candidate (only committed by qualified SYN admission).
; Walk TCP options without touching payload or retained connection state. Every
; option length is read once, must be >=2, and is checked against remaining
; header bytes before cursor advancement. EOL stops; NOP consumes one byte.
; RFC 9293 3.1/3.7.1: MSS length 4, SYN only, IPv4 absent default 536,
; effective send MSS <= local IP limit. Conservative admission policy rejects
; zero or duplicate SYN MSS (ambiguous/unusable offer); no minimum is inflated.
tcp_options_validate:
    test rdi, rdi
    jz   .bad
    cmp  esi, TCP_HDR_LEN
    jb   .bad
    cmp  esi, 60
    ja   .bad
    mov  r8d, TCP_DEFAULT_MSS
    xor  r9d, r9d                       ; one unambiguous SYN offer
    mov  edx, TCP_HDR_LEN
.walk:
    cmp  edx, esi
    jae  .ok
    movzx eax, byte [rdi + rdx]           ; kind read once
    test al, al
    jz   .ok                              ; EOL
    cmp  al, 1
    je   .nop                             ; NOP has no length byte
    mov  ecx, esi
    sub  ecx, edx                         ; remaining header bytes
    cmp  ecx, 2
    jb   .bad                             ; kind without length byte
    movzx eax, byte [rdi + rdx + 1]       ; declared length read exactly once
    cmp  eax, 2
    jb   .bad                             ; zero/one would livelock or backtrack
    cmp  eax, ecx
    ja   .bad                             ; option exceeds remaining header
    cmp  byte [rdi + rdx], 2
    jne  .advance
    cmp  eax, 4
    jne  .bad                             ; MSS has exactly two value octets
    test byte [rdi + TCP_FLAGS], TCP_F_SYN
    jz   .advance                         ; established options cannot negotiate
    test r9d, r9d
    jnz  .bad
    inc  r9d
    movzx ecx, word [rdi + rdx + 2]
    xchg cl, ch
    test ecx, ecx
    jz   .bad
    mov  r8d, TCP_WIRE_MAX_PAYLOAD
    cmp  ecx, r8d
    cmovb r8d, ecx
.advance:
    add  edx, eax                         ; bounded by <=60 after comparison
    jmp  .walk
.nop:
    inc  edx
    jmp  .walk
.ok:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

tcp_options_validate_kat:
    lea  rdi, [rel tcp_options_kat_good]
    mov  esi, 24
    call tcp_options_validate
    test eax, eax
    jnz  .fail
    lea  rdi, [rel tcp_options_kat_nolen]
    mov  esi, 21
    call tcp_options_validate
    cmp  rax, -1
    jne  .fail
    lea  rdi, [rel tcp_options_kat_zero]
    mov  esi, 22
    call tcp_options_validate
    cmp  rax, -1
    jne  .fail
    lea  rdi, [rel tcp_options_kat_overrun]
    mov  esi, 22
    call tcp_options_validate
    cmp  rax, -1
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

TCP_F_SYN     equ 0x02
TCP_F_FIN     equ 0x01
TCP_F_RST     equ 0x04
TCP_F_PSH     equ 0x08
TCP_F_ACK     equ 0x10
TCP_F_SYNACK  equ 0x12     ; SYN|ACK

TCP_LISTEN      equ 0
TCP_SYN_RCVD    equ 1
TCP_ESTABLISHED equ 2

TCP_OUR_ISN   equ 0xA0000001   ; our initial send sequence (host-order value)

; tcp_checksum(RDI=tcp segment ptr, RSI=tcp len) -> AX = RFC1071 checksum over
;   the TCP pseudo-header (constant tcp_pseudo_hdr: src/dst IP + proto + len) FOLLOWED
;   by the TCP header. The segment's own checksum field must already hold either 0
;   (when computing) or the inserted value (when re-validating -> folds to 0).
;   clobbers: RAX,RCX,RDX,RDI ; preserves RBX,R12,RSI
tcp_checksum:
    push rbx
    push r12
    mov  r12, rdi                        ; seg
    mov  rbx, rsi                        ; len
    lea  rdi, [rel tcp_cksum_buf]         ; pseudo-header first
    lea  rsi, [rel tcp_pseudo_hdr]
    mov  rdx, 12
    call memcpy
    lea  rdi, [rel tcp_cksum_buf + 12]    ; then the TCP segment
    mov  rsi, r12
    mov  rdx, rbx
    call memcpy
    lea  rdi, [rel tcp_cksum_buf]
    lea  rsi, [rbx + 12]                  ; sum pseudo(12) + segment(len)
    call net_cksum16                      ; AX = network-order checksum
    pop  r12
    pop  rbx
    ret

; tcp_build_synack(RDI=reply buf, RSI=syn seg, RDX=syn len) -> RAX = 0 on success
;   (SYN-ACK built in reply), RAX = -1 on REJECT (bounds-safe, nothing written).
;   Accepts a non-NULL SYN whose supplied length covers its 20..60-byte header and
;   fits TCP's 16-bit segment envelope. Swaps ports, sets our seq = ISN, ack =
;   SYN.seq+1, flags SYN|ACK, window, and checksum. Records our ISN + advances
;   state to SYN_RCVD. clobbers: RAX,RCX,RDX,RSI,RDI,R8..R11
tcp_build_synack:
    push r12
    test rdi, rdi
    jz   .reject                          ; NULL reply -> reject before any write
    test rsi, rsi
    jz   .reject                          ; NULL SYN -> reject before any read
    cmp  rdx, TCP_HDR_LEN
    jb   .reject                          ; too short for a full TCP header
    cmp  rdx, 0xFFFF
    ja   .reject                          ; impossible TCP segment length
    movzx eax, byte [rsi + TCP_DATAOFF]
    shr  eax, 4                           ; advertised header size in dwords
    cmp  eax, 5
    jb   .reject                          ; malformed data offset (< 20 bytes)
    shl  eax, 2
    cmp  rax, rdx
    ja   .reject                          ; options/header truncated by supplied len
    push rdi
    push rsi
    push rdx
    mov  rdi, rsi
    mov  esi, eax
    call tcp_options_validate
    mov  ecx, eax
    pop  rdx
    pop  rsi
    pop  rdi
    test ecx, ecx
    jnz  .reject                          ; malformed TCP option length/refusal
    test byte [rsi + TCP_FLAGS], TCP_F_SYN
    jz   .reject                          ; never answer a non-SYN with a SYN-ACK
    mov  r12, rdi                         ; reply
    ; ports: reply.src = syn.dst ; reply.dst = syn.src (server answers the client)
    mov  ax, [rsi + TCP_DSTPORT]
    mov  [r12 + TCP_SRCPORT], ax
    mov  ax, [rsi + TCP_SRCPORT]
    mov  [r12 + TCP_DSTPORT], ax
    ; our seq = ISN (write network-order)
    mov  eax, TCP_OUR_ISN
    bswap eax
    mov  [r12 + TCP_SEQ], eax
    ; ack = syn.seq + 1  (read network-order -> +1 -> write network-order)
    mov  eax, [rsi + TCP_SEQ]
    bswap eax
    add  eax, 1
    bswap eax
    mov  [r12 + TCP_ACK], eax
    mov  byte [r12 + TCP_DATAOFF], 0x50   ; data offset = 5 dwords (20-byte header)
    mov  byte [r12 + TCP_FLAGS], TCP_F_SYNACK
    mov  word [r12 + TCP_WINDOW], 0xFFFF
    mov  word [r12 + TCP_CKSUM], 0        ; zero before summing
    mov  word [r12 + TCP_URG], 0
    ; TCP checksum over pseudo-header + segment
    mov  rdi, r12
    mov  rsi, TCP_HDR_LEN
    call tcp_checksum                     ; AX = network-order checksum
    mov  edx, eax
    shr  edx, 8
    mov  [r12 + TCP_CKSUM], dl            ; insert network order: high byte first
    mov  [r12 + TCP_CKSUM + 1], al
    mov  dword [rel tcp_our_seq], TCP_OUR_ISN
    mov  byte [rel tcp_state], TCP_SYN_RCVD
    xor  eax, eax                         ; success
    pop  r12
    ret
.reject:
    mov  rax, -1
    pop  r12
    ret

; tcp_recv_ack(RSI=ack seg) -> RAX = 0 if the ACK completes the handshake
;   (has ACK flag AND ack == our_seq+1: state -> ESTABLISHED), -1 otherwise.
;   clobbers: RAX,RDX
tcp_recv_ack:
    test byte [rsi + TCP_FLAGS], TCP_F_ACK
    jz   .bad                             ; no ACK bit -> not a handshake completion
    mov  eax, [rsi + TCP_ACK]
    bswap eax                             ; their ack (host-order)
    mov  edx, [rel tcp_our_seq]
    add  edx, 1                           ; we expect ack == our_seq + 1
    cmp  eax, edx
    jne  .bad
    mov  byte [rel tcp_state], TCP_ESTABLISHED
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; tcp_handshake_selftest — THE 1044 acceptance gate. Drive a listener TCB through
;   LISTEN -> SYN_RCVD -> ESTABLISHED over canned SYN/ACK segments, content-validate
;   the emitted SYN-ACK, PRINT the KAT (syn seq, synack ack, flags, checksum, final
;   state) READ BACK OUT of the built segment, then earn the marker. Also proves the
;   negative gate (a truncated segment is rejected; a non-SYN segment does not open
;   the TCB). clobbers: caller-saved; preserves rbx,r12-r15 (saved here).
tcp_handshake_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  byte [rel tcp_state], TCP_LISTEN

    ; ---------- LISTEN: recv canned SYN (must have the SYN bit) ----------
    lea  rsi, [rel tcp_syn_seg]
    test byte [rsi + TCP_FLAGS], TCP_F_SYN
    jz   .done                            ; not a SYN -> do not open the TCB

    ; ---------- SYN_RCVD: build + emit the SYN-ACK ----------
    lea  rdi, [rel tcp_synack_seg]
    lea  rsi, [rel tcp_syn_seg]
    mov  rdx, TCP_HDR_LEN
    call tcp_build_synack
    test rax, rax
    jnz  .done                            ; a full SYN must build a SYN-ACK

    lea  rbx, [rel tcp_synack_seg]
    ; flags must be exactly SYN|ACK (0x12)
    cmp  byte [rbx + TCP_FLAGS], TCP_F_SYNACK
    jne  .done
    ; ack == syn.seq + 1
    mov  eax, [rbx + TCP_ACK]
    bswap eax
    mov  r13d, eax                        ; R13 = synack ack (host) — for KAT
    lea  rsi, [rel tcp_syn_seg]
    mov  ecx, [rsi + TCP_SEQ]
    bswap ecx
    mov  r14d, ecx                        ; R14 = syn seq (host) — for KAT
    add  ecx, 1
    cmp  r13d, ecx
    jne  .done
    ; validity: re-summing the reply WITH the checksum inserted folds to 0 (RFC1071)
    mov  rdi, rbx
    mov  rsi, TCP_HDR_LEN
    call tcp_checksum
    test ax, ax
    jnz  .done
    ; checksum field must be NON-ZERO (a stub emitting 0 fails the probe)
    movzx r15d, byte [rbx + TCP_CKSUM]
    shl   r15d, 8
    movzx eax,  byte [rbx + TCP_CKSUM + 1]
    or    r15d, eax                       ; R15 = synack checksum (host 16-bit)
    test  r15d, r15d
    jz    .done

    ; ---------- ESTABLISHED: recv canned ACK (ack == our_seq+1) ----------
    lea  rsi, [rel tcp_ack_seg]
    call tcp_recv_ack
    test rax, rax
    jnz  .done
    cmp  byte [rel tcp_state], TCP_ESTABLISHED
    jne  .done

    ; ---------- negative gate: reject short + non-SYN, no crash ----------
    lea  rdi, [rel tcp_synack_seg]
    lea  rsi, [rel tcp_syn_seg]
    mov  rdx, 8                           ; truncated (< TCP_HDR_LEN)
    call tcp_build_synack
    cmp  rax, -1
    jne  .done                            ; a short segment MUST be rejected
    lea  rsi, [rel tcp_ack_seg]           ; ACK-only carries no SYN bit
    test byte [rsi + TCP_FLAGS], TCP_F_SYN
    jnz  .done                            ; must not be mistaken for a connection open

    ; ---------- all checks passed: print the KAT, then earn the marker ----------
    lea  rdi, [rel str_tcp_synseq]
    mov  esi, r14d
    call tcp_emit_hex_kat
    lea  rdi, [rel str_tcp_saack]
    mov  esi, r13d
    call tcp_emit_hex_kat
    lea  rdi, [rel str_tcp_flags]
    movzx esi, byte [rbx + TCP_FLAGS]
    call tcp_emit_hex_kat
    lea  rdi, [rel str_tcp_cksum]
    mov  esi, r15d
    call tcp_emit_hex_kat
    lea  rdi, [rel str_tcp_state_est]
    call serial_string
    lea  rdi, [rel str_tcp_pass]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; tcp_emit_hex_kat(RDI=prefix ending in "0x", ESI=value) — print "<prefix><hex>\r\n"
;   through the canonical fmt_str/fmt_hex (G1 formatters). clobbers: volatiles + R12
tcp_emit_hex_kat:
    push rsi                               ; stash value
    lea  r12, [rel tcp_kat_buf]
    mov  rsi, r12                          ; dst (RDI already = prefix src)
    call fmt_str
    add  r12, rax
    pop  rdi                               ; value -> fmt_hex RDI
    mov  rsi, r12
    xor  rdx, rdx                          ; minimal-width hex
    call fmt_hex
    add  r12, rax
    mov  byte [r12],     13
    mov  byte [r12 + 1], 10
    mov  byte [r12 + 2], 0
    lea  rdi, [rel tcp_kat_buf]
    call serial_string
    ret

; ===========================================================================
; tcp_build_synack_kat — TOURNAMENT 1415 (durability class) correctness GATE +
;   fault-containment proof for tcp_build_synack. Three honest markers:
;     [tourn.tcp_build_synack.kat]     — drive the LIVE fn over the canned SYN;
;                                        the 16 header bytes (ports swapped, seq=ISN,
;                                        ack=SYN.seq+1, dataoff 0x50, flags 0x12,
;                                        window 0xFFFF) match a byte-exact literal;
;                                        the inserted checksum self-folds to 0
;                                        (RFC1071) AND is non-zero; a short seg (<20)
;                                        is rejected. A wrong-output variant fails here.
;     [tourn.tcp_build_synack.degrade] — a NULL reply ptr and a NULL syn ptr BOTH
;                                        return -1 with NO crash. The baseline (and the
;                                        smallest/fastest siblings) deref these pointers
;                                        and fault; this variant contains the fault.
;     [tourn.tcp_build_synack.guard]   — the reject path writes NOTHING into the reply
;                                        buffer (poison survives) and leaves the live
;                                        tcp_state / tcp_our_seq untouched.
;   Snapshots + restores tcp_state and tcp_our_seq so the ESTABLISHED handshake that
;   tcp_handshake_selftest just proved is left undisturbed. clobbers: caller-saved;
;   preserves rbx,r12-r15 (saved here).
; ===========================================================================
tcp_build_synack_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; snapshot the live handshake state (tcp_build_synack mutates both on success)
    movzx r14d, byte [rel tcp_state]
    mov   r15d, [rel tcp_our_seq]

    ; ---------- KAT: build a SYN-ACK from the canned SYN via the LIVE fn ----------
    lea  rdi, [rel tcp_kat_reply]         ; poison the reply buffer first
    mov  rcx, TCP_HDR_LEN
.kat_poison:
    dec  rcx
    mov  byte [rdi + rcx], 0xEE
    jnz  .kat_poison
    lea  rdi, [rel tcp_kat_reply]
    lea  rsi, [rel tcp_syn_seg]
    mov  rdx, TCP_HDR_LEN
    call tcp_build_synack
    test rax, rax
    jnz  .done                            ; a full SYN must build a SYN-ACK

    ; first 16 header bytes byte-exact vs the literal (ports/seq/ack/dataoff/flags/window)
    lea  rbx, [rel tcp_kat_reply]
    lea  r12, [rel tcp_synack_kat_expect]
    mov  rax, [rbx]
    cmp  rax, [r12]
    jne  .done
    mov  rax, [rbx + 8]
    cmp  rax, [r12 + 8]
    jne  .done

    ; the inserted checksum self-folds to 0 (RFC1071) AND is non-zero
    lea  rdi, [rel tcp_kat_reply]
    mov  rsi, TCP_HDR_LEN
    call tcp_checksum
    test ax, ax
    jnz  .done                            ; re-sum WITH checksum must fold to 0
    movzx eax, byte [rbx + TCP_CKSUM]
    movzx ecx, byte [rbx + TCP_CKSUM + 1]
    or   eax, ecx
    jz   .done                            ; a stub emitting 0 fails here

    ; a short segment (< TCP_HDR_LEN) is rejected
    lea  rdi, [rel tcp_kat_reply]
    lea  rsi, [rel tcp_syn_seg]
    mov  rdx, 8
    call tcp_build_synack
    cmp  rax, -1
    jne  .done
    lea  rdi, [rel str_tourn_tcp_kat]
    call serial_string

    ; ---------- DEGRADE: NULL pointers return -1 with NO crash ----------
    xor  edi, edi                         ; NULL reply buffer
    lea  rsi, [rel tcp_syn_seg]
    mov  rdx, TCP_HDR_LEN
    call tcp_build_synack
    cmp  rax, -1
    jne  .done                            ; must reject, not fault
    lea  rdi, [rel tcp_kat_reply]
    xor  esi, esi                         ; NULL syn segment
    mov  rdx, TCP_HDR_LEN
    call tcp_build_synack
    cmp  rax, -1
    jne  .done
    lea  rdi, [rel str_tourn_tcp_degrade]
    call serial_string

    ; ---------- GUARD: the reject path writes NOTHING into the reply buffer ----------
    lea  rdi, [rel tcp_kat_reply]         ; re-poison
    mov  rcx, TCP_HDR_LEN
.guard_poison:
    dec  rcx
    mov  byte [rdi + rcx], 0xEE
    jnz  .guard_poison
    lea  rdi, [rel tcp_kat_reply]
    lea  rsi, [rel tcp_syn_seg]
    mov  rdx, 4                           ; len < TCP_HDR_LEN -> reject
    call tcp_build_synack
    cmp  rax, -1
    jne  .done
    lea  rbx, [rel tcp_kat_reply]
    mov  rcx, TCP_HDR_LEN
.guard_check:
    dec  rcx
    cmp  byte [rbx + rcx], 0xEE           ; every byte must be untouched
    jne  .done
    test rcx, rcx
    jnz  .guard_check
    ; the reject path also touched neither tcp_state nor tcp_our_seq — they still
    ; hold the SYN_RCVD / ISN the earlier successful KAT build left behind
    movzx eax, byte [rel tcp_state]
    cmp  eax, TCP_SYN_RCVD
    jne  .done
    mov  eax, [rel tcp_our_seq]
    cmp  eax, TCP_OUR_ISN
    jne  .done
    lea  rdi, [rel str_tourn_tcp_guard]
    call serial_string

    ; ---------- FAULT: fixed hostile-input battery, content-graded live ----------
    call tcp_build_synack_fault_battery   ; RAX=contained, RDX=total
    mov  r12, rax
    mov  r13, rdx
    lea  rdi, [rel str_tourn_tcp_fault]
    call serial_string
    mov  rdi, r12
    lea  rsi, [rel tcp_kat_buf]
    call fmt_dec
    lea  rdi, [rel tcp_kat_buf]
    call serial_string
    lea  rdi, [rel str_tourn_tcp_fault_total]
    call serial_string
    mov  rdi, r13
    lea  rsi, [rel tcp_kat_buf]
    call fmt_dec
    lea  rdi, [rel tcp_kat_buf]
    call serial_string
    lea  rdi, [rel str_tourn_tcp_fault_end]
    call serial_string

.done:
    ; restore the live handshake state the KAT build mutated
    mov  byte [rel tcp_state], r14b
    mov  [rel tcp_our_seq], r15d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; tcp_build_synack_fault_battery -> RAX=contained, RDX=total (fixed T=8).
;   Each reject vector must return -1 without touching reply/state. Each accepted
;   edge must produce a byte-correct, checksum-valid 20-byte SYN-ACK without
;   crossing the reply canary. Live TCP state is restored before return.
TCP_SYNACK_FAULT_TOTAL equ 8
tcp_build_synack_fault_battery:
    push r12
    push r14
    push r15
    movzx r14d, byte [rel tcp_state]
    mov   r15d, [rel tcp_our_seq]
    xor   r12d, r12d

    ; Mutable copy keeps the canonical positive vector unchanged across live runs.
    lea  rdi, [rel tcp_fault_syn]
    lea  rsi, [rel tcp_syn_seg]
    mov  edx, TCP_HDR_LEN
    call memcpy

    ; F1: NULL input segment. (NULL reply remains in the frozen DEGRADE floor.)
    xor  esi, esi
    mov  edx, TCP_HDR_LEN
    call tcp_fault_reject_case
    add  r12, rax

    ; F2: empty segment.
    lea  rsi, [rel tcp_syn_seg]
    xor  edx, edx
    call tcp_fault_reject_case
    add  r12, rax

    ; F3: truncated fixed header (19 bytes).
    lea  rsi, [rel tcp_syn_seg]
    mov  edx, TCP_HDR_LEN - 1
    call tcp_fault_reject_case
    add  r12, rax

    ; F4: malformed data offset advertises a 16-byte TCP header.
    mov  byte [rel tcp_fault_syn + TCP_DATAOFF], 0x40
    lea  rsi, [rel tcp_fault_syn]
    mov  edx, TCP_HDR_LEN
    call tcp_fault_reject_case
    add  r12, rax

    ; F5: oversized options advertise 60 bytes, but only 20 were supplied.
    mov  byte [rel tcp_fault_syn + TCP_DATAOFF], 0xF0
    lea  rsi, [rel tcp_fault_syn]
    mov  edx, TCP_HDR_LEN
    call tcp_fault_reject_case
    add  r12, rax

    ; F6: bogus length outside TCP's 16-bit segment envelope.
    lea  rsi, [rel tcp_syn_seg]
    mov  edx, 0x10000
    call tcp_fault_reject_case
    add  r12, rax

    ; F7: zero-window SYN is legal; reply content/checksum/canary must be correct.
    mov  byte [rel tcp_fault_syn + TCP_DATAOFF], 0x50
    mov  word [rel tcp_fault_syn + TCP_WINDOW], 0
    lea  rsi, [rel tcp_fault_syn]
    mov  edx, TCP_HDR_LEN
    call tcp_fault_accept_case
    add  r12, rax

    ; F8: sequence 0xFFFFFFFF wraps ACK to 0 per TCP serial arithmetic.
    mov  word  [rel tcp_fault_syn + TCP_WINDOW], 0xFFFF
    mov  dword [rel tcp_fault_syn + TCP_SEQ], 0xFFFFFFFF
    lea  rsi, [rel tcp_fault_syn]
    mov  edx, TCP_HDR_LEN
    call tcp_fault_accept_case
    add  r12, rax

    mov  byte [rel tcp_state], r14b
    mov  [rel tcp_our_seq], r15d
    mov  rax, r12
    mov  edx, TCP_SYNACK_FAULT_TOTAL
    pop  r15
    pop  r14
    pop  r12
    ret

; One rejected vector. RSI=input (NULL allowed), RDX=len. Uses the battery's
; R14D/R15D snapshots to prove the reject path leaves live state unchanged.
tcp_fault_reject_case:
    mov  rax, 0xA5A5A5A5A5A5A5A5
    mov  [rel tcp_fault_reply], rax
    mov  [rel tcp_fault_reply + 8], rax
    mov  dword [rel tcp_fault_reply + 16], 0xA5A5A5A5
    mov  [rel tcp_fault_reply + 20], rax
    lea  rdi, [rel tcp_fault_reply]
    call tcp_build_synack
    cmp  rax, -1
    jne  .bad
    mov  rax, 0xA5A5A5A5A5A5A5A5
    cmp  qword [rel tcp_fault_reply], rax
    jne  .bad
    cmp  qword [rel tcp_fault_reply + 8], rax
    jne  .bad
    cmp  dword [rel tcp_fault_reply + 16], 0xA5A5A5A5
    jne  .bad
    cmp  qword [rel tcp_fault_reply + 20], rax
    jne  .bad
    movzx eax, byte [rel tcp_state]
    cmp  eax, r14d
    jne  .bad
    cmp  dword [rel tcp_our_seq], r15d
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; One accepted edge vector. Content-check ports, ACK serial arithmetic, fixed
; reply fields, RFC1071 checksum, state transition, and the byte-20 canary.
tcp_fault_accept_case:
    push rbx
    mov  rbx, rsi
    mov  rax, 0xC3C3C3C3C3C3C3C3
    mov  [rel tcp_fault_reply + 20], rax
    lea  rdi, [rel tcp_fault_reply]
    call tcp_build_synack
    test rax, rax
    jnz  .bad
    mov  ax, [rel tcp_fault_reply + TCP_SRCPORT]
    cmp  ax, [rbx + TCP_DSTPORT]
    jne  .bad
    mov  ax, [rel tcp_fault_reply + TCP_DSTPORT]
    cmp  ax, [rbx + TCP_SRCPORT]
    jne  .bad
    mov  eax, [rbx + TCP_SEQ]
    bswap eax
    inc  eax
    bswap eax
    cmp  [rel tcp_fault_reply + TCP_ACK], eax
    jne  .bad
    cmp  byte [rel tcp_fault_reply + TCP_DATAOFF], 0x50
    jne  .bad
    cmp  byte [rel tcp_fault_reply + TCP_FLAGS], TCP_F_SYNACK
    jne  .bad
    cmp  word [rel tcp_fault_reply + TCP_WINDOW], 0xFFFF
    jne  .bad
    cmp  word [rel tcp_fault_reply + TCP_CKSUM], 0
    je   .bad
    cmp  word [rel tcp_fault_reply + TCP_URG], 0
    jne  .bad
    mov  rax, 0xC3C3C3C3C3C3C3C3
    cmp  qword [rel tcp_fault_reply + 20], rax
    jne  .bad
    cmp  byte [rel tcp_state], TCP_SYN_RCVD
    jne  .bad
    cmp  dword [rel tcp_our_seq], TCP_OUR_ISN
    jne  .bad
    lea  rdi, [rel tcp_fault_reply]
    mov  esi, TCP_HDR_LEN
    call tcp_checksum
    test ax, ax
    jnz  .bad
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; ============================================================================
; Contract 1026 — live passive-open TCP endpoint.
;
; The old selftest above remains the frozen C10c logic gate.  The code below is
; the wire path: an N-ary listener registry, tuple-keyed TCB table, bounded IPv4
; parser, real pseudo-header checksums, MSS-bearing SYN-ACK, echo/data ACK, FIN,
; and closed-port RST.  Every transmitted peer MAC is deliberately obtained by
; arp_cache_lookup after ingress learning; frame[6] is never passed directly to
; the builder. tcp_live_lock protects listener/TCB ownership; independent
; try-lock scratch guards keep checksum/TX contention from blocking control.
; ============================================================================

TCP_LIVE_PORT_A       equ 7000
TCP_LIVE_PORT_B       equ 7001
TCP_SERVER_DATA_REV   equ 2140
%if PAOS_PUBLIC_BUILD
%undef TCP_SERVER_DIAG_ENABLE
%define TCP_SERVER_DIAG_ENABLE 0
%elifndef TCP_SERVER_DIAG_ENABLE
%define TCP_SERVER_DIAG_ENABLE 1
%endif
TCP_LISTENER_N        equ 4
TCP_LISTENER_SIZE     equ 16              ; port:u16, pad, accept_cb:qword
TCP_TCB_N             equ 16              ; fixed cap: SYN flood cannot allocate
                                          ; (power of two: tcp_poll cursor masks it;
                                          ;  SSH_CTX_N follows it 1:1 per TCB slot)
%if TCP_TCB_N & (TCP_TCB_N - 1)
%error "TCP_TCB_N must be a power of two (tcp_poll cursor mask)"
%endif
TCP_TCB_SIZE          equ 128
TCP_LAST_ACK          equ 3
TCP_SYN_SENT          equ 4
TCP_FIN_WAIT_1        equ 5
TCP_FIN_WAIT_2        equ 6
TCP_TIME_WAIT         equ 7
TCP_CLOSING           equ 8
TCP_REAP_PENDING      equ 9               ; bounded RST staged before next-tick reap
TCP_WIRE_MAX_SEG      equ 1480            ; IPv4 MTU 1500 - fixed IPv4 header
TCP_WIRE_MAX_PAYLOAD  equ 1460
TCP_DEFAULT_MSS       equ 536             ; RFC 9293 IPv4 no-MSS default
TCP_WIRE_FRAME_MAX    equ 1514
TCP_RX_CAP            equ 4096
; Per-slot RX queues + TX flights: ONE zeroed kernel-heap block (tcp_bufs_base),
; RX at +0, TX at +TCP_BUFS_TX_OFF. Was 88,896 zero bytes in the image.
TCP_BUFS_TX_OFF       equ TCP_TCB_N * TCP_RX_CAP
TCP_BUFS_BYTES        equ TCP_BUFS_TX_OFF + TCP_TCB_N * TCP_WIRE_MAX_PAYLOAD
%include "core/abi/heap_once.inc"
TCP_RTO_MS            equ 250
TCP_MAX_RETRIES       equ 5
TCP_HALF_OPEN_MS      equ 3000
TCP_IDLE_MS           equ 60000
TCP_CLOSE_MS          equ 5000
TCP_TIME_WAIT_MS      equ 1000
TCP_CHALLENGE_ACK_MS  equ 100             ; minimum interval per connection
TCP_PERSIST_MAX_MS    equ 8000            ; exponential probe interval ceiling
TCP_PERSIST_SILENT_MS equ TCP_IDLE_MS     ; resource policy: no valid ACK for 60 s
P_NEXT               equ 0
P_SILENT             equ 8
P_EPOCH              equ 16
P_TOTAL              equ 24              ; private bytes, including current flight
P_INTERVAL           equ 28
P_SIZE               equ 32

TCB_STATE             equ 0
TCB_LOCAL_PORT        equ 2
TCB_REMOTE_PORT       equ 4
TCB_LOCAL_IP          equ 8
TCB_REMOTE_IP         equ 12
TCB_SEND_NEXT         equ 16
TCB_RECV_NEXT         equ 20
TCB_ACCEPT_CB         equ 24
TCB_RECV_CB           equ 32
TCB_PEER_WINDOW       equ 40              ; latest advertised peer window
TCB_PEER_MSS          equ 42              ; qualified SYN offer; zero before handshake
TCB_RX_LEN            equ 44              ; queued in-order service bytes
TCB_TX_LEN            equ 48              ; one bounded in-flight segment
TCB_TX_SEQ            equ 52              ; first unacknowledged sequence
TCB_TX_FLAGS          equ 56
TCB_RETRIES           equ 57
TCB_SERVICE_ACTIVE    equ 58              ; 0 idle, 1 callback running, 2 commit pending
TCB_ACK_PENDING       equ 59              ; queued data has not been cumulatively ACKed
TCB_SERVICE_LEN       equ 60              ; pinned callback prefix length
TCB_LAST_ACTIVITY     equ 64              ; monotonic milliseconds
TCB_DEADLINE          equ 72              ; retransmit / lifecycle deadline
TCB_BYTES_RX          equ 80
TCB_BYTES_TX          equ 88
TCB_SERVICE_RESULT    equ 96              ; callback result committed next poll
TCB_SERVICE_CB        equ 104             ; callback pinned while lock is dropped
TCB_TX_ACK_HIGH       equ 112             ; private per-flight ACK high-water (128-byte slot unchanged)
TCB_CHALLENGE_NEXT    equ 120             ; private challenge-ACK deadline; cleared with slot

TCPPA_NONE            equ 0
TCPPA_SEND            equ 1
TCPPA_RETRANSMIT      equ 2
TCPPA_SYN_RETRY       equ 3
TCPPA_FIN_RETRY       equ 4
TCPPA_ACK             equ 5
TCPPA_RST_REAP        equ 6
TCPPA_CLIENT_SYN      equ 7
TCPPA_PERSIST         equ 8
TCPPA_RX_FIN          equ 9

OO_EPOCH             equ 0
OO_BYTES             equ 8
OO_FIN_SEQ           equ 12
OO_FIN_VALID         equ 16              ; 0 none,1 retained,2 sequence consumed
OO_FIN_CONSUMED      equ 2
OO_HEADER            equ 32
OO_SLOTS             equ 4
OO_MAX_GAP           equ 2048
OO_BYTE_CAP          equ 2048
OS_SEQ               equ 0
OS_LEN               equ 4
OS_DATA              equ 8
OS_SIZE              equ 1472
OO_SIZE              equ OO_HEADER + OO_SLOTS * OS_SIZE

; tcp_diag_snapshot output (18 qwords, caller supplies TCPD_SIZE bytes).
TCPD_LISTENERS        equ 0
TCPD_USED             equ 8
TCPD_MAX              equ 16
TCPD_SYN              equ 24
TCPD_EST              equ 32
TCPD_CLOSING          equ 40
TCPD_TIMEWAIT         equ 48
TCPD_ACCEPTS          equ 56
TCPD_RX_BYTES         equ 64
TCPD_TX_BYTES         equ 72
TCPD_RETRANSMITS      equ 80
TCPD_REAPED           equ 88
TCPD_FULL_RSTS        equ 96
TCPD_RSTS             equ 104
TCPD_CLOSES           equ 112
TCPD_LOCK_BUSY        equ 120             ; diagnostic skipped locked table, never spun
TCPD_LAST_STAGE       equ 128             ; last live stream progress checkpoint
TCPD_SYN_REAPS        equ 136             ; closed TCBs reclaimed by a new SYN
TCPD_SIZE             equ 144

; tcp_live_init(RDI=our MAC, ESI=our IPv4) -> 0 ready / -1 degrade.
; Populates function pointers with runtime LEAs (never dq-symbol RVAs), binds two
; distinct echo/discard services through the same registry, then exercises the live
; segment builder/state transition in-memory so BOOTLOG can expose readiness
; before the external host opens its first connection.  The frozen probe still
; content-grades the real wire path with two fresh nonces; these markers alone
; are intentionally insufficient evidence.
tcp_live_init:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    test rbx, rbx
    jz   .fail
    test r12d, r12d
    jz   .fail
    mov  byte [rel tcp_client_ready], 0
    mov  byte [rel tcp_client_public], 0
    mov  qword [rel tcp_public_ssh_callback], 0
    lea  rdi, [rel tcp_listeners]
    xor  esi, esi
    mov  edx, TCP_LISTENER_N * TCP_LISTENER_SIZE
    call memset
    lea  rdi, [rel tcp_tcbs]
    xor  esi, esi
    mov  edx, TCP_TCB_N * TCP_TCB_SIZE
    call memset
    lea  rdi, [rel tcp_client_routes]
    xor  esi, esi
    mov  edx, TCP_TCB_N * 16
    call memset
    lea  rdi, [rel tcp_persist_state]
    xor  esi, esi
    mov  edx, TCP_TCB_N * P_SIZE
    call memset
    lea  rdi, [rel tcp_rx_ooo]
    xor  esi, esi
    mov  edx, TCP_TCB_N * OO_SIZE
    call memset
    ; RX/TX slot buffers live on the kernel heap (allocated + zeroed here, the
    ; first use: command_udp runs this long after PH_HEAP_INIT). A heap refusal
    ; degrades TCP (-1) exactly like any other live-init failure, and
    ; tcp_tcb_alloc refuses every TCB while the block is absent.
    call tcp_bufs_base
    test rax, rax
    jz   .fail
    mov  rdi, rax
    xor  esi, esi
    mov  edx, TCP_BUFS_BYTES
    call memset
    mov  qword [rel tcp_stat_accepts], 0
    mov  qword [rel tcp_stat_rx_bytes], 0
    mov  qword [rel tcp_stat_tx_bytes], 0
    mov  qword [rel tcp_stat_retransmits], 0
    mov  qword [rel tcp_stat_reaped], 0
    mov  qword [rel tcp_stat_full_rsts], 0
    mov  qword [rel tcp_stat_rsts], 0
    mov  qword [rel tcp_stat_closes], 0
    mov  qword [rel tcp_stat_syn_reaps], 0
    mov  qword [rel tcp_last_stage], 0
    mov  byte [rel tcp_live_lock], 0
    mov  byte [rel tcp_tx_lock], 0
    mov  byte [rel tcp_cksum_lock], 0
    mov  byte [rel tcp_poll_cursor], 0
    mov  byte [rel tcp_m_listen], 0
    mov  byte [rel tcp_m_syn_rx], 0
    mov  byte [rel tcp_m_synack_tx], 0
    mov  byte [rel tcp_m_established], 0
    lea  rdi, [rel tcp_live_mac]
    mov  rsi, rbx
    mov  edx, 6
    call memcpy
    mov  [rel tcp_live_ip], r12d
    mov  dword [rel tcp_client_alias_ip], 0
    mov  byte [rel tcp_client_alias_ready], 0
    mov  byte [rel tcp_client_public], 0
    mov  byte [rel tcp_client_ready], 1

%if TCP_SERVER_DIAG_ENABLE
    mov  edi, TCP_LIVE_PORT_A
    lea  rsi, [rel tcp_echo_accept]
    call tcp_listener_register
    test rax, rax
    jnz  .fail
    mov  edi, TCP_LIVE_PORT_B
    lea  rsi, [rel tcp_discard_accept]
    call tcp_listener_register
    test rax, rax
    jnz  .fail
    call tcp_mark_listen
    call tcp_live_canary
    test rax, rax
    jnz  .fail
%endif
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; tcp_client_ready is published under tcp_live_lock and may be revoked by the
; sole BSP endpoint owner before a try-lock succeeds; revocation is one-way
; until locked retirement/rebinding completes. All wire/work entries gate it.
; Public outbound readiness is not a listener grant. Only the explicit trusted
; tcp_public_ssh_bind API grants the fixed port22/callback exception below.
; Bind only a validated local DHCP endpoint. Idempotent renewal retains active
; TCBs/epochs/private copies; address/MAC change retires bounded old clients.
; Fleet tcp_live_init owns its endpoint and cannot be replaced by this API.
; RDI=MAC,ESI=IPv4 ->0/-1. Refusal (lock/pinned callback/heap/fleet) changes no
; endpoint or TCB. The caller retries only at its cooperative poll boundary.
tcp_client_bind:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    test rbx, rbx
    jz   .fail
    test r12d, r12d
    jz   .fail
    test byte [rbx], 1
    jnz  .fail
    mov  eax, [rbx]
    movzx edx, word [rbx + 4]
    or   eax, edx
    jz   .fail
    call tcp_live_try_acquire
    test rax, rax
    jnz  .fail
    ; A live fleet stack is a distinct owner, including a build with diagnostics
    ; disabled. Only an explicitly granted SSH listener may survive rebind.
    cmp  byte [rel tcp_client_ready], 0
    je   .client_owner
    cmp  byte [rel tcp_client_public], 1
    jne  .unlock_fail
.client_owner:
    call tcp_client_no_listeners_locked
    test eax, eax
    jnz  .unlock_fail
    cmp  byte [rel tcp_client_ready], 1
    jne  .new_binding
    cmp  r12d, [rel tcp_live_ip]
    jne  .new_binding
    mov  eax, [rbx]
    cmp  eax, [rel tcp_live_mac]
    jne  .new_binding
    mov  ax, [rbx + 4]
    cmp  ax, [rel tcp_live_mac + 4]
    je   .ok
.new_binding:
    call tcp_client_unpinned_locked
    test eax, eax
    jnz  .unlock_fail
    call tcp_bufs_base
    test rax, rax
    jz   .unlock_fail
    call tcp_client_retire_locked
    lea  rdi, [rel tcp_live_mac]
    mov  rsi, rbx
    mov  edx, 6
    call memcpy
    mov  [rel tcp_live_ip], r12d
    mov  byte [rel tcp_client_public], 1
    mov  byte [rel tcp_client_ready], 1          ; publish endpoint last
.ok:
    call tcp_live_lock_release
    xor  eax, eax
    jmp  .out
.unlock_fail:
    call tcp_live_lock_release
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Retire only this expected public endpoint, never a replacement/fleet owner.
; RDI=expectedMAC,ESI=expectedIP ->0 retired/already gone, -1 retirement pending.
; A matching revocation blocks ingress/open/poll/TX immediately even if table
; lock or callback is busy. Identity and private buffers remain until actual
; detach; the public pump retains this exact expected pair for bounded retry.
tcp_client_unbind:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    test rbx, rbx
    jz   .gone
    test r12d, r12d
    jz   .gone
    cmp  byte [rel tcp_client_public], 1
    jne  .gone
    cmp  r12d, [rel tcp_live_ip]
    jne  .gone
    mov  eax, [rbx]
    cmp  eax, [rel tcp_live_mac]
    jne  .gone
    mov  ax, [rbx + 4]
    cmp  ax, [rel tcp_live_mac + 4]
    jne  .gone
    mov  byte [rel tcp_client_ready], 0
    call tcp_live_try_acquire
    test rax, rax
    jnz  .pending
    call tcp_client_no_listeners_locked
    test eax, eax
    jnz  .unlock_pending
    call tcp_client_unpinned_locked
    test eax, eax
    jnz  .unlock_pending
    call tcp_client_retire_locked
    mov  dword [rel tcp_live_ip], 0
    mov  dword [rel tcp_live_mac], 0
    mov  word [rel tcp_live_mac + 4], 0
    mov  byte [rel tcp_client_public], 0
    call tcp_live_lock_release
.gone:
    xor  eax, eax
    jmp  .out
.unlock_pending:
    call tcp_live_lock_release
.pending:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; One explicitly granted DHCP alias on the existing fleet NIC. It authorizes
; only routed/polled active clients, never listeners or legacy callback opens.
; RDI=exact fleet MAC, ESI=primary IPv4, EDX=alias IPv4 ->0/-1.
; Renewal is idempotent. Replacement requires exact old-alias retirement first.
; Alias owner is the sole BSP selected-native DHCP projection in command_udp.
tcp_client_alias_bind:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    test r13d, r13d
    jz   .fail
    cmp  r13d, -1
    je   .fail
    mov  eax, r13d
    test al, al
    jz   .fail
    cmp  al, 127
    je   .fail
    cmp  al, 224
    jae  .fail
    cmp  r13d, r12d
    je   .fail                           ; primary already owns itself
    call tcp_live_try_acquire
    test rax, rax
    jnz  .fail
    call tcp_client_alias_owner_locked
    test eax, eax
    jz   .unlock_fail
    cmp  dword [rel tcp_client_alias_ip], 0
    je   .install
    cmp  r13d, [rel tcp_client_alias_ip]
    jne  .unlock_fail
    cmp  byte [rel tcp_client_alias_ready], 1
    jne  .unlock_fail                    ; revoked binding cannot re-arm pending retirement
    jmp  .ok
.install:
    mov  [rel tcp_client_alias_ip], r13d
    mov  byte [rel tcp_client_alias_ready], 1
.ok:
    call tcp_live_lock_release
    xor  eax, eax
    jmp  .out
.unlock_fail:
    call tcp_live_lock_release
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exact expected fleet owner+alias only. Revoke before try-lock; pending work
; cannot send/consume alias data. Two bounded scans leave primary rows/listeners
; unchanged and never detach a callback-pinned slot. 0 done/gone, -1 pending.
tcp_client_alias_unbind:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    call tcp_client_alias_owner_locked
    test eax, eax
    jz   .gone
    test r13d, r13d
    jz   .gone
    cmp  r13d, [rel tcp_client_alias_ip]
    jne  .gone
    mov  byte [rel tcp_client_alias_ready], 0
    call tcp_live_try_acquire
    test rax, rax
    jnz  .pending
    call tcp_client_alias_owner_locked
    test eax, eax
    jz   .unlock_gone
    cmp  r13d, [rel tcp_client_alias_ip]
    jne  .unlock_gone
    lea  rbx, [rel tcp_tcbs]
    mov  r12d, TCP_TCB_N
.scan:
    cmp  [rbx + TCB_LOCAL_IP], r13d
    jne  .scan_next
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 1
    je   .unlock_pending
.scan_next:
    add  rbx, TCP_TCB_SIZE
    dec  r12d
    jnz  .scan
    lea  rbx, [rel tcp_tcbs]
    mov  r12d, TCP_TCB_N
.retire:
    cmp  [rbx + TCB_LOCAL_IP], r13d
    jne  .retire_next
    mov  rdi, rbx
    call tcp_tcb_free
.retire_next:
    add  rbx, TCP_TCB_SIZE
    dec  r12d
    jnz  .retire
    mov  dword [rel tcp_client_alias_ip], 0
.unlock_gone:
    call tcp_live_lock_release
.gone:
    xor  eax, eax
    jmp  .out
.unlock_pending:
    call tcp_live_lock_release
.pending:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RBX=expected MAC,R12D=primary. Pure identity check; BSP may use it before
; acquiring the table lock to revoke its own alias immediately.
tcp_client_alias_owner_locked:
    xor  eax, eax
    test rbx, rbx
    jz   .out
    test r12d, r12d
    jz   .out
    cmp  byte [rel tcp_client_ready], 1
    jne  .out
    cmp  byte [rel tcp_client_public], 0
    jne  .out
    cmp  r12d, [rel tcp_live_ip]
    jne  .out
    mov  edx, [rbx]
    cmp  edx, [rel tcp_live_mac]
    jne  .out
    mov  dx, [rbx + 4]
    cmp  dx, [rel tcp_live_mac + 4]
    jne  .out
    mov  eax, 1
.out:
    ret

; EAX=source IPv4 ->EAX=1 only for current primary or live explicit alias.
; No learning from DNS, incoming packets, cookies or an arbitrary route buffer.
tcp_client_source_owned:
    cmp  eax, [rel tcp_live_ip]
    je   .yes
    cmp  byte [rel tcp_client_alias_ready], 1
    jne  .no
    cmp  eax, [rel tcp_client_alias_ip]
    jne  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

%include "net/tcp_public_ssh.inc"

; Existing public bind/unbind guard: ignore only the explicitly granted SSH
; port/callback pair. Unrelated or ungranted listeners still refuse retirement.
tcp_client_no_listeners_locked:
    lea  rdx, [rel tcp_listeners]
    mov  ecx, TCP_LISTENER_N
.scan:
    cmp  word [rdx], 0
    je   .next
    cmp  word [rdx], 22
    jne  .busy
    mov  rax, [rel tcp_public_ssh_callback]
    test rax, rax
    jz   .busy
    cmp  [rdx + 8], rax
    jne  .busy
.next:
    add  rdx, TCP_LISTENER_SIZE
    dec  ecx
    jnz  .scan
    xor  eax, eax
    ret
.busy:
    mov  eax, -1
    ret

tcp_client_unpinned_locked:
    lea  rdx, [rel tcp_tcbs]
    mov  ecx, TCP_TCB_N
.scan:
    movzx eax, byte [rdx + TCB_SERVICE_ACTIVE]
    test eax, eax
    jz   .next
    cmp  eax, 2                              ; callback returned; only old commit is pending
    jne  .busy
.next:
    add  rdx, TCP_TCB_SIZE
    dec  ecx
    jnz  .scan
    xor  eax, eax
    ret
.busy:
    mov  eax, -1
    ret

; Fixed-table retirement, no callbacks/TX/allocation and no epoch-counter reset.
tcp_client_retire_locked:
    push rbx
    push r12
    lea  rbx, [rel tcp_tcbs]
    mov  r12d, TCP_TCB_N
.loop:
    mov  rdi, rbx
    call tcp_tcb_free
    add  rbx, TCP_TCB_SIZE
    dec  r12d
    jnz  .loop
    pop  r12
    pop  rbx
    ret

; tcp_listener_register(EDI=host-order port, RSI=accept callback) -> 0/-1.
; Same port+callback is idempotent; a conflicting duplicate or full table is a
; clean refusal that leaves every existing listener untouched.
tcp_listener_register:
    test di, di
    jz   .reject
    test rsi, rsi
    jz   .reject
    lea  r8, [rel tcp_listeners]
    xor  r9d, r9d                         ; scan index
    xor  r10d, r10d                       ; first-free entry, 0 until found
.scan:
    cmp  r9d, TCP_LISTENER_N
    jae  .commit
    movzx eax, word [r8]
    test ax, ax
    jz   .free
    cmp  ax, di
    jne  .next
    cmp  [r8 + 8], rsi
    jne  .reject                          ; same port owned by another service
    xor  eax, eax                         ; identical bind is idempotent
    ret
.free:
    test r10, r10
    cmovz r10, r8
.next:
    add  r8, TCP_LISTENER_SIZE
    inc  r9d
    jmp  .scan
.commit:
    test r10, r10
    jz   .reject
    mov  [r10], di
    mov  [r10 + 8], rsi
    xor  eax, eax
    ret
.reject:
    mov  rax, -1
    ret

; tcp_listener_lookup(EDI=host-order port) -> listener entry / 0.
tcp_listener_lookup:
    lea  r8, [rel tcp_listeners]
    mov  ecx, TCP_LISTENER_N
.scan:
    cmp  [r8], di
    je   .hit
    add  r8, TCP_LISTENER_SIZE
    dec  ecx
    jnz  .scan
    xor  eax, eax
    ret
.hit:
    mov  rax, r8
    ret

; Tuple lookup and allocation are called only with tcp_live_lock held.
tcp_tcb_find:
    ; EDI=local port, ESI=remote port, EDX=remote IPv4, ECX=local IPv4.
    ; Both owned local addresses may use the same ports and remote endpoint.
    lea  r8, [rel tcp_tcbs]
    mov  r9d, TCP_TCB_N
.scan:
    cmp  byte [r8 + TCB_STATE], 0
    je   .next
    cmp  [r8 + TCB_LOCAL_PORT], di
    jne  .next
    cmp  [r8 + TCB_REMOTE_PORT], si
    jne  .next
    cmp  [r8 + TCB_REMOTE_IP], edx
    jne  .next
    cmp  [r8 + TCB_LOCAL_IP], ecx
    je   .hit
.next:
    add  r8, TCP_TCB_SIZE
    dec  r9d
    jnz  .scan
    xor  eax, eax
    ret
.hit:
    mov  rax, r8
    ret

tcp_tcb_alloc:
    call tcp_bufs_base                    ; no heap slot buffers -> no TCB at all
    test rax, rax
    jz   .none
    lea  r8, [rel tcp_tcbs]
    mov  ecx, TCP_TCB_N
.scan:
    cmp  byte [r8 + TCB_STATE], 0
    je   .hit
    add  r8, TCP_TCB_SIZE
    dec  ecx
    jnz  .scan
.none:
    xor  eax, eax
    ret
.hit:
    mov  rax, r8
    ret

; tcp_tcb_claim -> RAX=free TCB / 0. Called only with tcp_live_lock held.
; A free slot wins. When every slot is held, a new connection (passive SYN or
; active open) reclaims the best CLOSED-lifecycle TCB instead of being refused
; (FINDING_20260930_SSH_TCP_SLOT_EXHAUSTION; RFC 1122 4.2.2.13 / RFC 6191 spirit:
; a TIME_WAIT tuple may yield to new work). Preference: TIME_WAIT first, then
; FIN_WAIT_2 / CLOSING / LAST_ACK (both FINs exchanged or ours acknowledged);
; within a class the least recently active. NEVER SYN_RCVD, SYN_SENT,
; ESTABLISHED, FIN_WAIT_1 (our FIN still unacknowledged), REAP_PENDING (RST
; staged), or a TCB whose service callback is pinned (SERVICE_ACTIVE != 0), so
; a live connection is never evicted and a table full of live connections still
; answers the SYN with the bounded fast refusal. The victim is returned zeroed.
; tcp_poll stages and executes its single wire action inside one call on the
; command thread, so no staged action can outlive into this ingress path.
tcp_tcb_claim:
    call tcp_tcb_alloc
    test rax, rax
    jnz  .out
    lea  r8, [rel tcp_tcbs]
    mov  ecx, TCP_TCB_N
    mov  r9d, 2                           ; best class so far (2 = none)
    xor  r10d, r10d                       ; best LAST_ACTIVITY within that class
.scan:
    cmp  byte [r8 + TCB_SERVICE_ACTIVE], 0
    jne  .next                            ; callback owns the tuple/buffer
    movzx edx, byte [r8 + TCB_STATE]
    cmp  edx, TCP_TIME_WAIT
    je   .class0
    cmp  edx, TCP_FIN_WAIT_2
    je   .class1
    cmp  edx, TCP_CLOSING
    je   .class1
    cmp  edx, TCP_LAST_ACK
    je   .class1
    jmp  .next                            ; live / half-open / FIN in flight
.class0:
    xor  edx, edx
    jmp  .rank
.class1:
    mov  edx, 1
.rank:
    mov  r11, [r8 + TCB_LAST_ACTIVITY]
    cmp  edx, r9d
    jb   .take                            ; strictly better class
    ja   .next
    cmp  r11, r10
    jae  .next                            ; same class: keep the older one
.take:
    mov  rax, r8
    mov  r9d, edx
    mov  r10, r11
.next:
    add  r8, TCP_TCB_SIZE
    dec  ecx
    jnz  .scan
    test rax, rax
    jz   .out                             ; only live connections: caller refuses
    push rax
    mov  rdi, rax
    call tcp_tcb_free
    pop  rax
    inc  qword [rel tcp_stat_syn_reaps]
.out:
    ret

; tcp_time_wait_syn_ok(RDI=TCB, ESI=segment seq host order, EDX=flags) -> EAX 1/0.
; RFC 1122 4.2.2.13 / RFC 6191 (no timestamps): a bare SYN on a tuple still in
; TIME_WAIT may open a new incarnation when its sequence number is beyond the
; old incarnation's receive frontier. Anything else keeps the TIME_WAIT reply.
tcp_time_wait_syn_ok:
    xor  eax, eax
    cmp  byte [rdi + TCB_STATE], TCP_TIME_WAIT
    jne  .out
    and  edx, TCP_F_SYN | TCP_F_ACK | TCP_F_RST | TCP_F_FIN
    cmp  edx, TCP_F_SYN
    jne  .out
    sub  esi, [rdi + TCB_RECV_NEXT]
    test esi, esi
    jle  .out                             ; serial arithmetic: not strictly newer
    mov  eax, 1
.out:
    ret

tcp_tcb_free:
    ; RDI=TCB; a running callback owns its slot/buffers until it returns.
    ; Fail closed immediately, but never clear/reuse storage under that callback.
    cmp  byte [rdi + TCB_SERVICE_ACTIVE], 1
    jne  .clear
    mov  byte [rdi + TCB_STATE], TCP_REAP_PENDING
    ret
.clear:
    jmp  tcp_tcb_free_observed

; Internal clear body; common completion observer wraps only this actual free.
tcp_tcb_clear:
    ; Clear the entire tuple/callback state so RST/close cannot leak it.
    call tcp_client_route_ptr
    test rax, rax
    jz   .tuple
    mov  qword [rax], 0
    mov  qword [rax + 8], 0
.tuple:
    call tcp_rx_clear
    call tcp_persist_clear
    xor  esi, esi
    mov  edx, TCP_TCB_SIZE
    call memset
    ret

; Fixed per-slot buffers preserve the bounded-allocation guarantee. A TCB's
; address is validated by allocation/lookup before either helper is called, and
; a TCB can only be allocated once the heap block exists (tcp_tcb_alloc), so the
; base below is never 0 here. Clobbers RAX, RDI, flags (unchanged contract).
tcp_tcb_rx_ptr:
    lea  rax, [rel tcp_tcbs]
    sub  rdi, rax
    shr  rdi, 7                           ; TCP_TCB_SIZE = 128
    imul rdi, rdi, TCP_RX_CAP
    call tcp_bufs_base
    add  rax, rdi
    ret

tcp_tcb_tx_ptr:
    lea  rax, [rel tcp_tcbs]
    sub  rdi, rax
    shr  rdi, 7
    imul rdi, rdi, TCP_WIRE_MAX_PAYLOAD
    call tcp_bufs_base
    add  rax, TCP_BUFS_TX_OFF
    add  rax, rdi
    ret

; tcp_bufs_base -> RAX = the zeroed RX/TX slot-buffer block (TCP_BUFS_BYTES), or
; 0 if the heap refused. Preserves every register except RAX.
HEAP_ONCE_ACCESSOR tcp_bufs_base, tcp_bufs_ptr, TCP_BUFS_BYTES, str_tcp_bufs_fail

tcp_tcb_touch:
    push rdi
    call boot_ms_now
    pop  rdi
    mov  [rdi + TCB_LAST_ACTIVITY], rax
    ret

; tcp_queue_rx(RDI=TCB, RSI=payload, EDX=len) -> 0 / -1 when receive window full.
tcp_queue_rx:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    test r13d, r13d
    jz   .ok
    mov  eax, [rbx + TCB_RX_LEN]
    add  eax, r13d
    jc   .full
    cmp  eax, TCP_RX_CAP
    ja   .full
    mov  rdi, rbx
    call tcp_tcb_rx_ptr
    mov  rdi, rax
    mov  eax, [rbx + TCB_RX_LEN]
    add  rdi, rax
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    add  [rbx + TCB_RX_LEN], r13d
    add  [rbx + TCB_BYTES_RX], r13
    add  [rel tcp_stat_rx_bytes], r13
.ok:
    xor  eax, eax
    jmp  .out
.full:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded receive reassembly. Four privately owned fragments, <=2048 payload
; bytes and <=2048 bytes ahead of RCV.NXT. Partial overlaps (including old
; prefixes with new tails) are deliberately refused atomically: peer retries
; the missing exact range. Exact retained duplicates compare every byte.
; All helpers run under tcp_live_lock; no incoming pointer survives admission.
; Sidecar epochs qualify poll's deferred FIN across abort/reuse/reinitialization.
tcp_rx_ptr:                             ; RDI preserved; clobbers RAX,RDX
    lea  rax, [rel tcp_tcbs]
    mov  rdx, rdi
    sub  rdx, rax
    cmp  rdx, TCP_TCB_N * TCP_TCB_SIZE
    jae  .bad
    test edx, TCP_TCB_SIZE - 1
    jnz  .bad
    shr  rdx, 7
    imul rdx, rdx, OO_SIZE
    lea  rax, [rel tcp_rx_ooo]
    add  rax, rdx
    ret
.bad:
    xor  eax, eax
    ret

tcp_rx_clear:                           ; preserves RDI
    push rdi
    call tcp_rx_ptr
    test rax, rax
    jz   .out
    mov  rdi, rax
    xor  esi, esi
    mov  edx, OO_SIZE
    call memset
.out:
    pop  rdi
    ret

tcp_rx_begin:                           ; 0/-1, RDI preserved
    call tcp_rx_clear
    call tcp_rx_ptr
    test rax, rax
    jz   .bad
    mov  rdx, [rel tcp_rx_epoch_next]
    cmp  rdx, -1
    je   .bad                           ; never reuse a published incarnation
    inc  rdx
    mov  [rel tcp_rx_epoch_next], rdx
    mov  [rax + OO_EPOCH], rdx
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

tcp_receive_window:                     ; EAX=actual free space; preserves RDI,R10
    call tcp_rx_ptr
    mov  edx, TCP_RX_CAP
    sub  edx, [rdi + TCB_RX_LEN]
    jc   .zero
    test rax, rax                       ; synthetic canary/reset TCB has no sidecar
    jz   .out
    sub  edx, [rax + OO_BYTES]
    jc   .zero
    cmp  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
    je   .zero                          ; peer's receive stream already closed
    movzx eax, byte [rax + OO_FIN_VALID]
    sub  edx, eax                       ; retained FIN also owns sequence space
    jc   .zero
.out:
    mov  eax, edx
    ret
.zero:
    xor  eax, eax
    ret

; RDI=TCB,RSI=payload,EDX=len,ECX=wire SEQ,R8D=flags -> EAX -1 refusal,
; 0 retained/duplicate/no data, >0 newly contiguous bytes. Preflight EVERYTHING
; before publishing payload/FIN; queued bytes and retained fragments are intact
; on unsupported overlap, conflict, bounds or storage exhaustion.
tcp_rx_accept:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    mov  rbx, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  [rsp], ecx
    and  r8d, TCP_F_FIN
    mov  [rsp + 4], r8d
    mov  dword [rsp + 24], 0             ; exact retained duplicate
    mov  qword [rsp + 16], 0             ; first unused slot
    call tcp_rx_ptr
    test rax, rax
    jz   .bad
    mov  r12, rax
    cmp  qword [r12 + OO_EPOCH], 0
    je   .bad
    cmp  byte [r12 + OO_FIN_VALID], OO_FIN_CONSUMED
    jne  .open_stream
    test r14d, r14d
    jnz  .bad                           ; never deliver data after consumed EOF
    cmp  dword [rsp + 4], 0
    jne  .bad                           ; duplicate FIN only repeats current ACK
    xor  eax, eax                       ; legal empty ACK still advances outbound
    jmp  .out
.open_stream:
    cmp  r14d, TCP_WIRE_MAX_PAYLOAD
    ja   .bad
    mov  r15d, [rsp]
    sub  r15d, [rbx + TCB_RECV_NEXT]
    test r15d, r15d
    js   .bad                           ; old prefix or half-space ambiguity
    cmp  r15d, OO_MAX_GAP
    ja   .bad
    lea  eax, [r15 + r14]
    mov  [rsp + 28], eax                ; end distance relative to current frontier
    mov  eax, [rsp]
    add  eax, r14d
    mov  [rsp + 8], eax                 ; FIN point modulo 2^32
    cmp  byte [r12 + OO_FIN_VALID], 0
    je   .scan
    mov  edx, [r12 + OO_FIN_SEQ]
    sub  edx, [rbx + TCB_RECV_NEXT]
    cmp  [rsp + 28], edx
    ja   .bad                           ; no payload beyond an already retained FIN
    cmp  dword [rsp + 4], 0
    je   .scan
    cmp  eax, [r12 + OO_FIN_SEQ]
    jne  .bad                           ; conflicting FIN point
.scan:
    lea  rsi, [r12 + OO_HEADER]
    mov  ecx, OO_SLOTS
.slot:
    mov  edx, [rsi + OS_LEN]
    test edx, edx
    jz   .empty
    mov  eax, [rsi + OS_SEQ]
    sub  eax, [rbx + TCB_RECV_NEXT]
    add  edx, eax                       ; retained end distance (bounded at admission)
    cmp  dword [rsp + 4], 0
    je   .overlap
    cmp  edx, [rsp + 28]
    ja   .bad                           ; new FIN cannot cut off retained data
.overlap:
    test r14d, r14d
    jz   .next
    cmp  r15d, edx
    jae  .next
    cmp  [rsp + 28], eax
    jbe  .next
    cmp  r15d, eax
    jne  .bad                           ; unsupported partial overlap
    cmp  r14d, [rsi + OS_LEN]
    jne  .bad
    xor  r8d, r8d
.compare:
    mov  r9b, [r13 + r8]
    cmp  r9b, [rsi + OS_DATA + r8]
    jne  .bad
    inc  r8d
    cmp  r8d, r14d
    jb   .compare
    mov  dword [rsp + 24], 1
    jmp  .next
.empty:
    cmp  qword [rsp + 16], 0
    jne  .next
    mov  [rsp + 16], rsi
.next:
    add  rsi, OS_SIZE
    dec  ecx
    jnz  .slot
    ; Duplicate payload consumes no new bytes. A new FIN still needs a byte.
    mov  r9d, r14d
    cmp  dword [rsp + 24], 0
    je   .new_fin
    xor  r9d, r9d
.new_fin:
    mov  r8d, [rsp + 4]
    cmp  byte [r12 + OO_FIN_VALID], 0
    je   .capacity
    xor  r8d, r8d
.capacity:
    mov  rdi, rbx
    call tcp_receive_window             ; preserves R8/R9
    lea  edx, [r9 + r8]
    test edx, edx
    jz   .commit                        ; pure ACK / already owned exact duplicate
    cmp  edx, eax
    ja   .bad
    ; A new range must end inside the currently advertised receive window.
    mov  edx, [rsp + 28]
    add  edx, r8d
    cmp  edx, eax
    ja   .bad
    test r15d, r15d
    jz   .commit
    mov  eax, [r12 + OO_BYTES]
    add  eax, r9d
    cmp  eax, OO_BYTE_CAP
    ja   .bad
    test r9d, r9d
    jz   .commit
    cmp  qword [rsp + 16], 0
    je   .bad
.commit:
    test r14d, r14d
    jz   .fin
    cmp  dword [rsp + 24], 0
    jne  .fin
    test r15d, r15d
    jz   .in_order
    mov  rdi, [rsp + 16]
    add  rdi, OS_DATA
    mov  rsi, r13
    mov  edx, r14d
    call memcpy
    mov  rax, [rsp + 16]
    mov  edx, [rsp]
    mov  [rax + OS_SEQ], edx
    mov  [rax + OS_LEN], r14d
    add  [r12 + OO_BYTES], r14d
    jmp  .fin
.in_order:
    mov  rdi, rbx
    mov  rsi, r13
    mov  edx, r14d
    call tcp_queue_rx
    test rax, rax
    jnz  .bad                           ; preflight guarantees queue capacity
    add  [rbx + TCB_RECV_NEXT], r14d
.fin:
    cmp  dword [rsp + 4], 0
    je   .drain
    mov  eax, [rsp + 8]
    mov  [r12 + OO_FIN_SEQ], eax
    mov  byte [r12 + OO_FIN_VALID], 1
.drain:
    ; Each success removes a slot. Four scans of four slots is the hard bound.
    mov  r15d, OO_SLOTS
.restart:
    lea  r13, [r12 + OO_HEADER]
    mov  r14d, OO_SLOTS
.find_ready:
    cmp  dword [r13 + OS_LEN], 0
    je   .find_next
    mov  eax, [r13 + OS_SEQ]
    cmp  eax, [rbx + TCB_RECV_NEXT]
    jne  .find_next
    mov  rdi, rbx
    lea  rsi, [r13 + OS_DATA]
    mov  edx, [r13 + OS_LEN]
    call tcp_queue_rx
    test rax, rax
    jnz  .done                          ; reserved capacity guarantees success
    mov  eax, [r13 + OS_LEN]
    add  [rbx + TCB_RECV_NEXT], eax
    sub  [r12 + OO_BYTES], eax
    mov  dword [r13 + OS_LEN], 0
    dec  r15d
    jnz  .restart
    jmp  .done
.find_next:
    add  r13, OS_SIZE
    dec  r14d
    jnz  .find_ready
.done:
    mov  eax, [rbx + TCB_RECV_NEXT]
    sub  eax, [rsp]                     ; only current-SEQ arrival reports progress
    mov  edx, [rsp]
    sub  edx, [rbx + TCB_RECV_NEXT]
    test edx, edx
    jle  .out
    xor  eax, eax                       ; future admission cannot report progress
    jmp  .out
.bad:
    mov  rax, -1
.out:
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Consume a contiguous FIN after actual callback/owned-reader consumption,
; never while pinned. Its sequence must advance before outbound data drains:
; the peer's subsequent ACK/window update uses FIN+1. Keep accepted private TX
; and the epoch while half closed; only local FIN waits for outbound ACKs.
tcp_rx_fin_ready:                      ; RDI preserved; RAX=incarnation / 0
    cmp  byte [rdi + TCB_STATE], TCP_ESTABLISHED
    jne  .no
    cmp  byte [rdi + TCB_SERVICE_ACTIVE], 0
    jne  .no
    cmp  dword [rdi + TCB_RX_LEN], 0
    jne  .no
    call tcp_rx_ptr
    test rax, rax
    jz   .no
    cmp  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
    je   .drained
    cmp  byte [rax + OO_FIN_VALID], 1
    jne  .no
    mov  edx, [rax + OO_FIN_SEQ]
    cmp  edx, [rdi + TCB_RECV_NEXT]
    jne  .no
    cmp  dword [rdi + TCB_TX_LEN], 0
    je   .ready                         ; empty TX keeps staged FIN revalidation
    inc  dword [rdi + TCB_RECV_NEXT]
    mov  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
    mov  byte [rdi + TCB_ACK_PENDING], 1
.drained:
    cmp  dword [rdi + TCB_TX_LEN], 0
    jne  .no
.ready:
    mov  rax, [rax + OO_EPOCH]
    ret
.no:
    xor  eax, eax
    ret

tcp_rx_fin_transmit:                   ; staged pointer + RSI=epoch, bounded try-lock
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    call tcp_live_try_acquire
    test rax, rax
    jnz  .out
    mov  rdi, rbx
    call tcp_rx_fin_ready
    test rax, rax
    jz   .unlock
    cmp  rax, r12
    jne  .unlock
    mov  rdi, rbx
    call tcp_rx_finish_locked
.unlock:
    call tcp_live_lock_release
.out:
    pop  r12
    pop  rbx
    ret

tcp_rx_finish_locked:                  ; caller has validated FIN and holds table
    push rbx
    mov  rbx, rdi
    call tcp_rx_ptr
    cmp  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
    je   .already_consumed
    inc  dword [rbx + TCB_RECV_NEXT]
.already_consumed:
    call tcp_rx_clear
    call tcp_persist_clear
    mov  byte [rbx + TCB_ACK_PENDING], 0
    mov  rdi, rbx
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    mov  byte [rbx + TCB_STATE], TCP_LAST_ACK
    ; Keep ownership when local TX refuses the first FIN, as tcp_close does.
    ; Only an emitted FIN consumes sequence space or may be acknowledged.
    mov  byte [rbx + TCB_TX_FLAGS], 0
    mov  rdi, rbx
    mov  esi, TCP_F_FIN | TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jnz  .arm_retry
    mov  byte [rbx + TCB_TX_FLAGS], TCP_F_FIN
.arm_retry:
    mov  byte [rbx + TCB_RETRIES], 0
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    pop  rbx
    ret

; Drop ESI bytes already accepted by the service from the queue prefix.
tcp_consume_rx:
    push rbx
    mov  rbx, rdi
    mov  ecx, [rbx + TCB_RX_LEN]
    cmp  esi, ecx
    ja   .out
    sub  ecx, esi
    mov  [rbx + TCB_RX_LEN], ecx
    test ecx, ecx
    jz   .out
    call tcp_tcb_rx_ptr
    mov  rdi, rax
    lea  rsi, [rax + rsi]
    cld
    rep  movsb                           ; dst precedes src: overlap-safe
.out:
    pop  rbx
    ret

; tcp_isn_assign(RDI=TCB with its tuple stored) -> RAX=0, or -1 leaving
; TCB_SEND_NEXT untouched.  RFC 9293 3.4.1 / RFC 6528:
;   ISN = M + F(local IP, remote IP, local port, remote port, secret)
; M is boot milliseconds * 250 (a 4 us clock) plus a per-boot counter, so ISNs
; never repeat within one millisecond and stay monotonic for every tuple. F is
; the first 32 bits of HMAC-SHA256 under a per-boot 32-byte key drawn once from
; the keep's CSPRNG. Observing one connection's ISN predicts no other tuple's.
; No TSC or constant fallback: while the CSPRNG is degraded the open/accept is
; refused and the key draw is retried on the next one. Caller holds
; tcp_live_lock, which protects the key, its ready flag and the counter.
tcp_isn_assign:
    push rbx
    sub  rsp, 48                         ; [0,32) digest, [32,44) tuple
    mov  rbx, rdi
    cmp  byte [rel tcp_isn_secret_ready], 0
    jne  .keyed
    lea  rdi, [rel tcp_isn_secret]
    mov  esi, 32
    call csprng_generate                 ; wipes the span itself on failure
    test rax, rax
    jnz  .fail
    mov  byte [rel tcp_isn_secret_ready], 1
.keyed:
    mov  eax, [rbx + TCB_LOCAL_IP]
    mov  [rsp + 32], eax
    mov  eax, [rbx + TCB_REMOTE_IP]
    mov  [rsp + 36], eax
    mov  ax, [rbx + TCB_LOCAL_PORT]
    mov  [rsp + 40], ax
    mov  ax, [rbx + TCB_REMOTE_PORT]
    mov  [rsp + 42], ax
    mov  rdi, rsp
    lea  rsi, [rel tcp_isn_secret]
    mov  edx, 32
    lea  rcx, [rsp + 32]
    mov  r8d, 12
    call hmac_sha256
    test rax, rax
    jnz  .wipe_fail
    call boot_ms_now
    imul eax, eax, 250                   ; 4 us ticks, modulo 2^32
    add  eax, [rel tcp_isn_count]
    inc  dword [rel tcp_isn_count]
    add  eax, [rsp]                      ; + F
    mov  [rbx + TCB_SEND_NEXT], eax
    xor  ebx, ebx
    jmp  .wipe
.wipe_fail:
    mov  rbx, -1
.wipe:
    xor  eax, eax                        ; digest bits beyond F stay private
    mov  [rsp], rax
    mov  [rsp + 8], rax
    mov  [rsp + 16], rax
    mov  [rsp + 24], rax
    mov  rax, rbx
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 48
    pop  rbx
    ret

; tcp_client_open(EDI=remote IPv4 in wire-byte layout, ESI=remote host-order
; port, EDX=local host-order port, RCX=connected callback, R8=receive callback)
; -> RAX=TCB handle, or 0.  This is the active-open half of the same tuple table
; and frame builder used by passive TCP; no second socket stack exists.  The
; An uncached peer remains SYN_SENT while the existing bounded ARP discovery
; resolves its next hop. Receiving a UDP command does not grant an ARP binding.
tcp_client_open:
    xor  r10d, r10d
    xor  r9d, r9d                       ; preserve the original callback API
    jmp  tcp_client_open_common

; Callback client with a private {handle:u64, incarnation:u64} output pair.
; Same arguments as tcp_client_open, R9=pair; published while table-locked,
; before any connected callback can run. Incarnation is never reused.
tcp_client_open_tracked:
    test r9, r9
    jz   tcp_client_open_routed.invalid
    mov  r10d, 1
    jmp  tcp_client_open_common

; Explicit finite owner probe: same tracked pair, no callbacks, and -1 busy.
; Existing callback clients retain their blocking acquisition contract.
tcp_client_open_tracked_try:
    test r9, r9
    jz   tcp_client_open_routed.invalid
    test rcx, rcx
    jnz  tcp_client_open_routed.invalid
    test r8, r8
    jnz  tcp_client_open_routed.invalid
    mov  r10d, 2
    jmp  tcp_client_open_common

; Routed, polled active client: the usual tuple arguments, RCX=R8=0, and
; R9 -> {next-hop IPv4:u32, source IPv4:u32, nonzero owner cookie:u64}.
; The caller keeps a nonreused cookie per lookup. No callbacks are installed;
; tcp_client_io_owned polls/queues bytes under the existing TCP table lock.
; Returns handle/0, or -1 when the table try-lock is busy (no open attempted).
tcp_client_open_routed:
    xor  r10d, r10d
    test r9, r9
    jnz  tcp_client_open_common
.invalid:
    xor  eax, eax
    ret

tcp_client_open_common:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48
    mov  [rsp + 40], r10
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    mov  [rsp], r8
    mov  qword [rsp + 8], 0
    mov  qword [rsp + 16], 0
    mov  qword [rsp + 24], 0
    mov  qword [rsp + 32], 0
    test r10d, r10d
    jz   .route
    mov  [rsp + 24], r9
    jmp  .tuple
.route:
    test r9, r9
    jz   .tuple
    test rcx, rcx
    jnz  .fail
    test r8, r8
    jnz  .fail
    mov  eax, [r9]
    test eax, eax
    jz   .fail
    mov  [rsp + 8], rax
    mov  eax, [r9 + 4]
    test eax, eax
    jz   .fail
    mov  [rsp + 32], eax
    call tcp_client_source_owned
    test eax, eax
    jz   .fail
    mov  rax, [r9 + 8]
    test rax, rax
    jz   .fail
    mov  [rsp + 16], rax
.tuple:
    test r12d, r12d
    jz   .fail
    test r13w, r13w
    jz   .fail
    test r14w, r14w
    jz   .fail
    cmp  byte [rel tcp_client_ready], 1
    jne  .fail
    cmp  qword [rsp + 16], 0
    je   .legacy_lock                   ; callback clients discover ARP asynchronously
    mov  edi, [rsp + 8]
    call arp_cache_lookup
    test rax, rax
    jz   .fail
    call tcp_live_try_acquire
    test rax, rax
    jnz  .lock_busy
    jmp  .locked
.legacy_lock:
    cmp  qword [rsp + 40], 2
    jne  .callback_lock
    call tcp_live_try_acquire
    test rax, rax
    jnz  .lock_busy
    jmp  .locked
.callback_lock:
    call tcp_live_lock_acquire
.locked:
    cmp  byte [rel tcp_client_ready], 1
    jne  .unlock_fail
    mov  eax, [rsp + 32]
    test eax, eax
    jz   .source_ready
    call tcp_client_source_owned
    test eax, eax
    jz   .unlock_fail
.source_ready:
    ; Materialize the legacy primary source while table-locked, just as the
    ; explicit routed source is retained for lookup and later TCB publication.
    mov  ecx, [rsp + 32]
    test ecx, ecx
    jnz  .tuple_source
    mov  ecx, [rel tcp_live_ip]
    mov  [rsp + 32], ecx
.tuple_source:
    ; One live TCB per 4-tuple: ingress resolves tuples with tcp_tcb_find's
    ; first match, so a duplicate open could never complete.
    mov  edi, r14d
    mov  esi, r13d
    mov  edx, r12d
    call tcp_tcb_find
    test rax, rax
    jnz  .unlock_fail
    call tcp_tcb_claim
    test rax, rax
    jz   .unlock_fail
    mov  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, TCP_TCB_SIZE
    call memset
    mov  rdi, rbx
    call tcp_persist_clear
    call tcp_rx_begin
    test rax, rax
    jnz  .free_fail
    mov  rdi, rbx
    call tcp_client_route_ptr
    mov  rdx, [rsp + 8]
    mov  [rax], rdx
    mov  rdx, [rsp + 16]
    mov  [rax + 8], rdx
    mov  byte [rbx + TCB_STATE], TCP_SYN_SENT
    mov  [rbx + TCB_LOCAL_PORT], r14w
    mov  [rbx + TCB_REMOTE_PORT], r13w
    mov  eax, [rsp + 32]
    test eax, eax
    jnz  .local_source
    mov  eax, [rel tcp_live_ip]
.local_source:
    mov  [rbx + TCB_LOCAL_IP], eax
    mov  [rbx + TCB_REMOTE_IP], r12d
    mov  [rbx + TCB_ACCEPT_CB], r15
    mov  rax, [rsp]
    mov  [rbx + TCB_RECV_CB], rax
    mov  rdi, rbx
    call tcp_isn_assign
    test rax, rax
    jnz  .free_fail
    mov  rdi, rbx
    mov  esi, TCP_F_SYN
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit
    test rax, rax
    jz   .syn_sent
    cmp  rax, -2                       ; ARP unresolved, no SYN emitted or sequence consumed
    jne  .free_fail
    cmp  qword [rsp + 16], 0
    je   .opened                       ; existing retry budget owns this callback open
.free_fail:
    mov  rdi, rbx
    call tcp_tcb_free
    jmp  .unlock_fail
.syn_sent:
    mov  byte [rbx + TCB_TX_FLAGS], TCP_F_SYN
.opened:
    ; Share the passive/data retry budget. The Terminal still owns its 10 s
    ; handshake / 20 s channel deadlines; an exhausted tuple can yield sooner.
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    cmp  qword [rsp + 24], 0
    je   .published
    mov  rdi, rbx
    call tcp_rx_ptr
    mov  rdx, [rax + OO_EPOCH]
    mov  rcx, [rsp + 24]
    mov  [rcx + 8], rdx
    mov  [rcx], rbx                     ; publish pair before unlocking callbacks
.published:
    call tcp_live_lock_release
    mov  rax, rbx
    jmp  .out
.unlock_fail:
    call tcp_live_lock_release
.fail:
    xor  eax, eax
    jmp  .out
.lock_busy:
    mov  rax, -1                       ; routed caller retries within its deadline
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate a table address before looking up its private route/cookie sidecar.
; RDI preserved; RAX=sidecar/0. No TCB dereference on an invalid address.
tcp_client_route_ptr:
    lea  rax, [rel tcp_tcbs]
    mov  rcx, rdi
    sub  rcx, rax
    cmp  rcx, TCP_TCB_N * TCP_TCB_SIZE
    jae  .bad
    test ecx, TCP_TCB_SIZE - 1
    jnz  .bad
    shr  rcx, 3                         ; 128-byte slot -> 16-byte sidecar
    lea  rax, [rel tcp_client_routes]
    add  rax, rcx
    ret
.bad:
    xor  eax, eax
    ret

; RDI=handle, RSI=owner cookie, RDX=buffer, ECX=capacity/length, R8D=operation:
; 0 read/consume, 1 queue a send prefix, 2 abort, 3 ACK then detach.
; Operation 3 retains ownership on bounded TX failure; cancellation uses 2.
; RAX=TCP state, -1 lock/TX busy,
; -2 stale/invalid ownership; EDX=bytes copied/admitted (0 on backpressure).
; All ownership checks and queue changes are atomic under the table try-lock.
; DNS uses this instead of callbacks, so no old callback can target a new query.
tcp_client_io_owned:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    mov  r15d, r8d
    call tcp_live_try_acquire
    test rax, rax
    jnz  .busy
    mov  rdi, rbx
    call tcp_client_route_ptr
    test rax, rax
    jz   .stale
    test r12, r12
    jz   .stale
    cmp  [rax + 8], r12
    jne  .stale
    cmp  byte [rbx + TCB_STATE], 0
    je   .stale
    xor  r12d, r12d                     ; admitted bytes
    cmp  r15d, 2
    je   .abort
    cmp  r15d, 3
    je   .complete
    cmp  byte [rel tcp_client_ready], 1
    jne  .stale
    mov  eax, [rbx + TCB_LOCAL_IP]
    call tcp_client_source_owned
    test eax, eax
    jz   .stale
    test r13, r13
    jz   .state
    test r14d, r14d
    jz   .state
    cmp  r15d, 1
    je   .send
    test r15d, r15d
    jnz  .state
    mov  eax, [rbx + TCB_RX_LEN]
    cmp  r14d, eax
    cmova r14d, eax
    test r14d, r14d
    jz   .state
    mov  rdi, rbx
    call tcp_tcb_rx_ptr
    mov  rsi, rax
    mov  rdi, r13
    mov  edx, r14d
    call memcpy
    mov  rdi, rbx
    mov  esi, r14d
    call tcp_consume_rx
    mov  r12d, r14d
    mov  byte [rbx + TCB_ACK_PENDING], 1
    jmp  .state
.send:
    movzx eax, word [rbx + TCB_PEER_WINDOW]
    test eax, eax
    jz   .send_cap                       ; zero-window admission privately owns a prefix
    cmp  r14d, eax
    cmova r14d, eax
.send_cap:
    mov  eax, TCP_WIRE_MAX_PAYLOAD
    cmp  r14d, eax
    cmova r14d, eax
    mov  rdi, rbx
    mov  rsi, r13
    mov  edx, r14d
    call tcp_send_prepare_locked
    test rax, rax
    jnz  .state
    mov  r12d, r14d
.state:
    movzx r15d, byte [rbx + TCB_STATE]
    call tcp_live_lock_release
    mov  eax, r15d
    mov  edx, r12d
    jmp  .out
.complete:
    ; Successful polled consumers must not discard their last receive ACK.
    ; Cookie validation and bounded TX share the table lock, so cancellation
    ; or slot reuse cannot replace the tuple between validation and emission.
    ; Reading the last payload can leave its contiguous FIN queued for poll.
    ; Completion detaches before that poll, so consume EOF here after actual
    ; reader drain. Keep the consumed marker on TX refusal: retry must ACK the
    ; same FIN+1 frontier, not consume it again or admit data past EOF.
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .complete_ack
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 0
    jne  .complete_ack
    cmp  dword [rbx + TCB_RX_LEN], 0
    jne  .complete_ack
    mov  rdi, rbx
    call tcp_rx_ptr
    test rax, rax
    jz   .complete_ack
    cmp  byte [rax + OO_FIN_VALID], 1
    jne  .complete_ack
    mov  edx, [rax + OO_FIN_SEQ]
    cmp  edx, [rbx + TCB_RECV_NEXT]
    jne  .complete_ack                 ; future FIN cannot acknowledge a gap
    inc  dword [rbx + TCB_RECV_NEXT]
    mov  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
.complete_ack:
    ; Always ACK the current frontier: an earlier poll/ingress TX may have
    ; failed after clearing ACK_PENDING. A successful NIC admission permits
    ; detach; a local TX failure leaves the complete TCB/route for retry.
    mov  rdi, rbx
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jz   .abort
    call tcp_live_lock_release
    jmp  .busy
.abort:
    mov  rdi, rbx
    call tcp_tcb_free
    jmp  .state
.stale:
    call tcp_live_lock_release
    mov  rax, -2
    xor  edx, edx
    jmp  .out
.busy:
    mov  rax, -1
    xor  edx, edx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=handle, RSI=nonzero incarnation, RDX=payload, ECX=exact length,
; R8D=1 send / 2 abort. RAX=0 admitted, -1 busy/backpressure, -2 stale/invalid.
; Unlike the polled DNS prefix API, a TLS record is admitted all-or-none.
; Validation and mutation share one bounded table try-lock; no raw TCB read.
tcp_client_epoch_io:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    mov  r15d, r8d
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
    cmp  byte [rbx + TCB_STATE], 0
    je   .stale
    cmp  r15d, 2
    je   .abort
    cmp  r15d, 1
    jne  .stale
    mov  rdi, rbx
    mov  rsi, r13
    mov  edx, r14d
    call tcp_send_prepare_locked
    mov  r12, rax
    jmp  .unlock
.abort:
    mov  rdi, rbx
    call tcp_tcb_free                   ; pinned callback defers actual reuse
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
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "net/tcp_epoch_snapshot.inc"
%include "net/tcp_epoch_retirement.inc"
%include "net/tcp_epoch_reap.inc"

; tcp_client_send(RDI=TCB, RSI=payload, EDX=len) -> 0/-1. Active clients share
; the same private-copy, one-flight pacing and retransmit path as server users.
tcp_client_send:
    test rdi, rdi
    jz   .bad
    cmp  byte [rdi + TCB_STATE], TCP_ESTABLISHED
    jne  .bad
    jmp  tcp_send
.bad:
    mov  rax, -1
    ret

; tcp_client_abort(RDI=TCB).  A failed certificate/Finished gate must erase the
; tuple immediately; it must never leave an apparently established transport.
tcp_client_abort:
    test rdi, rdi
    jz   .done
    jmp  tcp_tcb_free
.done:
    ret

tcp_live_lock_acquire:
    lea  rdi, [rel tcp_live_lock]
    jmp  spin_acquire

tcp_live_lock_release:
    lea  rdi, [rel tcp_live_lock]
    jmp  spin_release

; tcp_live_try_acquire -> 0 acquired / -1 busy. STATUS and the cooperative
; control-plane poll must never spin behind a stalled stream callback.
tcp_live_try_acquire:
    lea  rdi, [rel tcp_live_lock]
    mov  al, 1
    xchg al, byte [rdi]
    test al, al
    jnz  .busy
    xor  eax, eax
    ret
.busy:
    mov  rax, -1
    ret

; Non-blocking variants are used by the shared RX/control-plane path. A busy
; scratch buffer is ordinary backpressure; it must never turn STATUS into a
; spin loop behind another CPU's TCP work.
tcp_tx_lock_acquire:
    lea  rdi, [rel tcp_tx_lock]
    call spin_try_acquire
    test eax, eax
    jz   .busy
    xor  eax, eax
    ret
.busy:
    mov  rax, -1
    ret

tcp_tx_lock_release:
    lea  rdi, [rel tcp_tx_lock]
    jmp  spin_release

tcp_cksum_lock_acquire:
    lea  rdi, [rel tcp_cksum_lock]
    call spin_try_acquire
    test eax, eax
    jz   .busy
    xor  eax, eax
    ret
.busy:
    mov  rax, -1
    ret

tcp_cksum_lock_release:
    lea  rdi, [rel tcp_cksum_lock]
    jmp  spin_release

; tcp_checksum_ipv4(RDI=TCP segment, ESI=len, EDX=src IP, ECX=dst IP)
; -> AX checksum (0 when validating an already checksummed segment), RAX=-1 reject.
tcp_checksum_ipv4:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    mov  ebx, edx
    call tcp_cksum_lock_acquire
    test rax, rax
    jnz  .busy
    test r12, r12
    jz   .reject
    cmp  r13d, TCP_HDR_LEN
    jb   .reject
    cmp  r13d, TCP_WIRE_MAX_SEG
    ja   .reject
    lea  rdi, [rel tcp_cksum_wire]
    mov  [rdi + 0], ebx
    mov  [rdi + 4], ecx
    mov  byte [rdi + 8], 0
    mov  byte [rdi + 9], 6
    mov  eax, r13d
    mov  [rdi + 10], ah
    mov  [rdi + 11], al
    lea  rdi, [rel tcp_cksum_wire + 12]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  rdi, [rel tcp_cksum_wire]
    mov  esi, r13d
    add  esi, 12
    call net_cksum16
    jmp  .out
.reject:
    mov  rax, -1
.out:
    call tcp_cksum_lock_release
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret
.busy:
    mov  rax, -1
    jmp  .done

; tcp_build_segment(RDI=dst, RSI=TCB, EDX=flags, RCX=payload, R8D=len)
; -> RAX=TCP segment length / -1. SYN replies carry MSS=1460 (kind=2,len=4).
tcp_build_segment:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15d, r8d
    test rbx, rbx
    jz   .reject
    test r12, r12
    jz   .reject
    cmp  r15d, TCP_WIRE_MAX_PAYLOAD
    ja   .reject
    mov  rdi, r12
    call tcp_peer_mss
    cmp  r15d, eax
    ja   .reject                         ; final guard covers every data emission path
    test r15d, r15d
    jz   .payload_ok
    test r14, r14
    jz   .reject
.payload_ok:
    mov  r10d, TCP_HDR_LEN
    test r13b, TCP_F_SYN
    jz   .header_len_ok
    add  r10d, 4
.header_len_ok:
    mov  eax, r10d
    add  eax, r15d
    cmp  eax, TCP_WIRE_MAX_SEG
    ja   .reject

    movzx eax, word [r12 + TCB_LOCAL_PORT]
    mov  [rbx + TCP_SRCPORT], ah
    mov  [rbx + TCP_SRCPORT + 1], al
    movzx eax, word [r12 + TCB_REMOTE_PORT]
    mov  [rbx + TCP_DSTPORT], ah
    mov  [rbx + TCP_DSTPORT + 1], al
    mov  eax, [r12 + TCB_SEND_NEXT]
    bswap eax
    mov  [rbx + TCP_SEQ], eax
    mov  eax, [r12 + TCB_RECV_NEXT]
    bswap eax
    mov  [rbx + TCP_ACK], eax
    cmp  r10d, TCP_HDR_LEN
    je   .plain_header
    mov  byte [rbx + TCP_DATAOFF], 0x60
    mov  byte [rbx + 20], 2              ; MSS option
    mov  byte [rbx + 21], 4
    mov  byte [rbx + 22], 0x05           ; 1460 = 0x05b4
    mov  byte [rbx + 23], 0xb4
    jmp  .common_header
.plain_header:
    mov  byte [rbx + TCP_DATAOFF], 0x50
.common_header:
    mov  [rbx + TCP_FLAGS], r13b
    mov  rdi, r12
    call tcp_receive_window             ; includes private fragments and pending FIN
    mov  [rbx + TCP_WINDOW], ah
    mov  [rbx + TCP_WINDOW + 1], al
    mov  word [rbx + TCP_CKSUM], 0
    mov  word [rbx + TCP_URG], 0
    test r15d, r15d
    jz   .checksum
    lea  rdi, [rbx + r10]
    mov  rsi, r14
    mov  edx, r15d
    call memcpy
.checksum:
    add  r15d, r10d
    mov  rdi, rbx
    mov  esi, r15d
    mov  edx, [r12 + TCB_LOCAL_IP]
    mov  ecx, [r12 + TCB_REMOTE_IP]
    call tcp_checksum_ipv4
    cmp  rax, -1
    je   .reject
    mov  edx, eax
    shr  edx, 8
    mov  [rbx + TCP_CKSUM], dl
    mov  [rbx + TCP_CKSUM + 1], al
    mov  eax, r15d
    jmp  .out
.reject:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; struct dns_route_snapshot (net/dns) field offsets used by the ARP-miss path.
TCP_ROUTE_GW      equ 4
TCP_ROUTE_MASK    equ 8
TCP_ROUTE_SIZE    equ 24

; tcp_arp_miss(RBX=TCB) -> RAX = ARP entry of the peer's next hop, or 0 after at
;   most one who-has. Called with tcp_tx_lock held (tcp_tx_frame is scratch).
;   The next hop is the peer when on-link, else the gateway, from the same
;   route snapshot the NTP client uses; an off-subnet peer is reached through
;   the gateway's binding. Who-has is rate-limited to one per TCP_RTO_MS per
;   TCB slot; the caller returns its existing failure value, so the existing
;   retransmit / ACK_PENDING machinery retries once the binding arrives.
tcp_arp_miss:
    push r12
    push r13
    mov  r12d, [rbx + TCB_REMOTE_IP]      ; on-link (or no route): the peer itself
    lea  rdi, [rel tcp_arp_route]
    call dns_wire_route_snapshot
    test rax, rax
    jnz  .hop
    mov  eax, [rbx + TCB_REMOTE_IP]
    xor  eax, [rbx + TCB_LOCAL_IP]
    test eax, [rel tcp_arp_route + TCP_ROUTE_MASK]
    jz   .hop
    mov  eax, [rel tcp_arp_route + TCP_ROUTE_GW]
    test eax, eax
    jz   .miss_none                       ; off-subnet without a gateway: nothing to ask
    mov  r12d, eax
    mov  edi, r12d
    call arp_cache_lookup                ; the next hop's binding
    test rax, rax
    jnz  .miss_out
.hop:
    mov  rax, rbx
    lea  rdx, [rel tcp_tcbs]
    sub  rax, rdx
    shr  rax, 7                           ; TCB slot (TCP_TCB_SIZE = 128)
    cmp  rax, TCP_TCB_N
    jae  .miss_none
    lea  rdx, [rel tcp_arp_next_ms]
    lea  r13, [rdx + rax*8]
    call boot_ms_now
    mov  rdx, r13
    cmp  rax, [rdx]
    jb   .miss_quiet
    add  rax, TCP_RTO_MS
    mov  [r13], rax
    lea  rdi, [rel tcp_live_mac]
    mov  esi, [rbx + TCB_LOCAL_IP]
    mov  edx, r12d
    lea  rcx, [rel tcp_tx_frame]
    mov  r8d, 64
    call udp4_arp_request
.miss_quiet:
.miss_none:
    xor  eax, eax
.miss_out:
    pop  r13
    pop  r12
    ret

; tcp_transmit_once(RDI=TCB, ESI=flags, RDX=payload, ECX=len) -> 0/-1;
; -2 only for an initial SYN awaiting ARP, with no SYN sequence consumed.
; Ethernet destination is an ARP-cache lookup, then every frame exits through
; netdev_tx (and therefore the N-ary egress-select hook).
tcp_transmit:
tcp_transmit_once:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    cmp  byte [rel tcp_client_ready], 1
    jne  .busy
    mov  eax, [rbx + TCB_LOCAL_IP]
    call tcp_client_source_owned
    test eax, eax
    jz   .busy
    call tcp_tx_lock_acquire
    test rax, rax
    jnz  .busy
    mov  rdi, rbx
    call tcp_client_route_ptr
    test rax, rax
    jz   .default_route
    cmp  qword [rax + 8], 0
    je   .default_route
    mov  edi, [rax]                     ; explicit owner route; no DNS-lock recursion
    call arp_cache_lookup
    test rax, rax
    jnz  .have_mac
    jmp  .fail
.default_route:
    mov  edi, [rbx + TCB_REMOTE_IP]
    call arp_cache_lookup
    test rax, rax
    jnz  .have_mac
    call tcp_arp_miss                    ; next-hop binding, or a bounded who-has
    test rax, rax
    jnz  .have_mac
    cmp  r12b, TCP_F_SYN
    jne  .fail
    cmp  byte [rbx + TCB_STATE], TCP_SYN_SENT
    jne  .fail
    cmp  byte [rbx + TCB_TX_FLAGS], TCP_F_SYN
    je   .fail                         ; retransmitted SYN retains its existing frontier
    mov  rax, -2
    jmp  .out
.have_mac:
    lea  r15, [rax + 8]                  ; E_MAC, cache-owned peer L2 binding
    lea  rdi, [rel tcp_tx_frame + 34]
    mov  rsi, rbx
    mov  edx, r12d
    mov  rcx, r13
    mov  r8d, r14d
    call tcp_build_segment
    test rax, rax
    js   .fail
    mov  [rsp], rax                      ; TCP segment length

    lea  rdi, [rel tcp_tx_frame]
    mov  eax, [r15]
    mov  [rdi + 0], eax
    mov  ax, [r15 + 4]
    mov  [rdi + 4], ax
    mov  eax, [rel tcp_live_mac]
    mov  [rdi + 6], eax
    mov  ax, [rel tcp_live_mac + 4]
    mov  [rdi + 10], ax
    mov  word [rdi + 12], 0x0008         ; wire bytes 08 00
    lea  rdi, [rel tcp_tx_frame + 14]
    mov  byte [rdi + 0], 0x45
    mov  byte [rdi + 1], 0
    mov  rax, [rsp]
    add  eax, 20
    mov  [rdi + 2], ah
    mov  [rdi + 3], al
    mov  word [rdi + 4], 0
    mov  byte [rdi + 6], 0x40            ; DF, offset 0
    mov  byte [rdi + 7], 0
    mov  byte [rdi + 8], 64
    mov  byte [rdi + 9], 6
    mov  word [rdi + 10], 0
    mov  eax, [rbx + TCB_LOCAL_IP]
    mov  [rdi + 12], eax
    mov  eax, [rbx + TCB_REMOTE_IP]
    mov  [rdi + 16], eax
    mov  esi, 20
    call net_cksum16
    mov  edx, eax
    shr  edx, 8
    mov  byte [rel tcp_tx_frame + 24], dl
    mov  byte [rel tcp_tx_frame + 25], al

    mov  rdx, [rsp]
    add  edx, 34
    cmp  edx, 60
    jae  .send
    lea  rdi, [rel tcp_tx_frame]
    add  rdi, rdx
    mov  ecx, 60
    sub  ecx, edx
    xor  esi, esi
    mov  rdx, rcx
    call memset
    mov  edx, 60
.send:
    lea  rsi, [rel tcp_tx_frame]
    call netdev_tx
    test rax, rax
    jnz  .fail
    add  [rbx + TCB_SEND_NEXT], r14d     ; data consumes sequence space
    test r12b, TCP_F_SYN
    jz   .no_syn_inc
    inc  dword [rbx + TCB_SEND_NEXT]
.no_syn_inc:
    test r12b, TCP_F_FIN
    jz   .ok
    inc  dword [rbx + TCB_SEND_NEXT]
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    call tcp_tx_lock_release
.done:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.busy:
    mov  rax, -1
    jmp  .done

; tcp_send(RDI=ESTABLISHED TCB, RSI=data, EDX=len) -> 0 accepted / -1 backpressure.
; At most TCP_WIRE_MAX_PAYLOAD bytes are privately owned, with one MSS flight.
; Zero-window acceptance queues that copy for persist; callers must not resend
; accepted bytes. Rejection leaves caller ownership unchanged. Poll owns TX.
tcp_send:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    call tcp_live_try_acquire
    test rax, rax
    jnz  .busy
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, r13d
    call tcp_send_prepare_locked
    mov  r14, rax
    call tcp_live_lock_release
    test r14, r14
    jnz  .done
    mov  qword [rel tcp_last_stage], 4   ; flight copied; poll owns hardware TX
.done:
    mov  rax, r14
    jmp  .out
.busy:
    mov  rax, -1                         ; bounded backpressure; never spin poll callers
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Reserve one bounded flight while locked. Hardware TX is deliberately absent:
; callbacks run outside tcp_live_lock, so a slow/faulted NIC cannot pin STATUS.
tcp_send_prepare_locked:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    cmp  byte [rel tcp_client_ready], 1
    jne  .reject
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .reject
    test r13d, r13d
    jz   .reject
    cmp  r13d, TCP_WIRE_MAX_PAYLOAD
    ja   .reject
    cmp  dword [rbx + TCB_TX_LEN], 0
    jne  .reject                         ; bounded pacing: one flight per TCB
    movzx eax, word [rbx + TCB_PEER_WINDOW]
    test eax, eax
    jnz  .window_bound
    mov  rdi, rbx
    mov  esi, r13d
    call tcp_persist_arm
    test rax, rax
    jnz  .reject                         ; no ownership accepted on epoch exhaustion
    jmp  .copy
.window_bound:
    cmp  r13d, eax
    ja   .reject                         ; honor the peer's advertised window
    mov  rdi, rbx
    call tcp_peer_mss
    cmp  r13d, eax
    jbe  .copy
    mov  rdi, rbx
    mov  esi, r13d
    call tcp_persist_arm                 ; same bounded private owner for segmented tails
    test rax, rax
    jnz  .reject
.copy:
    mov  rdi, rbx
    call tcp_tcb_tx_ptr
    mov  rdi, rax
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    mov  eax, [rbx + TCB_SEND_NEXT]
    mov  [rbx + TCB_TX_SEQ], eax
    mov  [rbx + TCB_TX_ACK_HIGH], eax   ; new flight starts at the current frontier
    mov  rdi, rbx
    call tcp_peer_mss
    cmp  r13d, eax
    cmovb eax, r13d
    mov  [rbx + TCB_TX_LEN], eax
    cmp  word [rbx + TCB_PEER_WINDOW], 0
    jne  .flight
    mov  dword [rbx + TCB_TX_LEN], 1      ; only one owned octet is a zero-window probe
.flight:
    mov  byte [rbx + TCB_TX_FLAGS], TCP_F_PSH | TCP_F_ACK
    mov  byte [rbx + TCB_RETRIES], 0
    mov  qword [rbx + TCB_DEADLINE], 0   ; unsent flight; next bounded poll emits it
    mov  byte [rbx + TCB_ACK_PENDING], 0 ; PSH|ACK covers receive frontier
    xor  eax, eax
    jmp  .out
.reject:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=TCB -> EAX=effective send MSS. Zero exists only before negotiation or
; in isolated synthetic TCBs; never inflate a legal small peer offer.
tcp_peer_mss:
    movzx eax, word [rdi + TCB_PEER_MSS]
    test eax, eax
    jnz  .out
    mov  eax, TCP_DEFAULT_MSS
.out:
    ret

; Emit a flight already reserved by tcp_send_prepare_locked. Callers retain
; table ownership through this bounded TX and result, so cancellation/reuse
; cannot swap the selected queue.
tcp_send_prepared:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, [rbx + TCB_TX_LEN]
    test r12d, r12d
    jz   .tx_fail
    mov  rdi, rbx
    call tcp_tcb_tx_ptr
    mov  rdx, rax
    mov  rdi, rbx
    movzx esi, byte [rbx + TCB_TX_FLAGS]
    mov  ecx, r12d
    call tcp_transmit_once
    test rax, rax
    jnz  .tx_fail
    mov  qword [rel tcp_last_stage], 5   ; netdev accepted the byte flight
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    add  [rbx + TCB_BYTES_TX], r12
    add  [rel tcp_stat_tx_bytes], r12
    xor  eax, eax
    jmp  .out
.tx_fail:
    ; Preserve the private flight for a bounded retry under caller ownership.
    ; No reacquisition or spinning is needed to publish a failed hardware send.
    inc  byte [rbx + TCB_RETRIES]
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Emit at most one queued action after the NIC RX drain has returned. Neither a
; service callback nor payload TX recursively extends tcp4_ingress.
tcp_send_pending:
    push rbx
    mov  rbx, rdi
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .done
    mov  rdi, rbx
    call tcp_persist_ptr
    test rax, rax
    jz   .ordinary
    cmp  qword [rax + P_EPOCH], 0
    jne  .done                           ; cooperative poll owns every persist emission
.ordinary:
    cmp  word [rbx + TCB_PEER_WINDOW], 0
    je   .done
    cmp  dword [rbx + TCB_TX_LEN], 0
    je   .ack_only
    cmp  qword [rbx + TCB_DEADLINE], 0
    jne  .done
    mov  rdi, rbx
    call tcp_send_prepared
    jmp  .done
.ack_only:
    cmp  byte [rbx + TCB_ACK_PENDING], 0
    je   .done
    mov  byte [rbx + TCB_ACK_PENDING], 0
    mov  rdi, rbx
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
.done:
    pop  rbx
    ret

tcp_complete_handshake:
    ; RDI=TCB, ESI=peer seq, EDX=peer ACK, ECX=flags (all host order).
    cmp  byte [rdi + TCB_STATE], TCP_SYN_RCVD
    jne  .bad
    test cl, TCP_F_SYN | TCP_F_RST
    jnz  .bad                            ; neither control completes our SYN-ACK
    test cl, TCP_F_ACK
    jz   .bad
    cmp  esi, [rdi + TCB_RECV_NEXT]
    jne  .bad
    cmp  edx, [rdi + TCB_SEND_NEXT]
    jne  .bad
    mov  byte [rdi + TCB_STATE], TCP_ESTABLISHED
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

%if !PAOS_PUBLIC_BUILD
tcp_echo_accept:
    lea  rax, [rel tcp_echo_receive]
    mov  [rdi + TCB_RECV_CB], rax
    ret

tcp_discard_accept:
    lea  rax, [rel tcp_discard_receive]
    mov  [rdi + TCB_RECV_CB], rax
    ret

%endif
; tcp_deliver_payload(RDI=TCB, RSI=TCP header, EDX=header len, ECX=payload len)
; -> callback result / -1 when the accepted service installed no receiver.
; Keep the callback out of RAX: EAX is deliberately reused for length/address
; arithmetic by ingress callers, and clobbering the indirect target here was the
; wire-only fault caught by the contract's first nonce probe.
tcp_deliver_payload:
    mov  r11, [rdi + TCB_RECV_CB]
    test r11, r11
    jz   .no_receiver
    add  rsi, rdx
    mov  edx, ecx
    call r11
    ret
.no_receiver:
    mov  rax, -1
    ret

%if !PAOS_PUBLIC_BUILD
tcp_echo_receive:
    ; RDI=TCB, RSI=payload, EDX=len. Each TCB carries its own callback/tuple, so
    ; the two listener ports cannot share reply state or leak one nonce to another.
    jmp  tcp_send

tcp_discard_receive:
    xor  eax, eax
    ret

%endif
; Deliver at most one paced chunk from the per-TCB receive queue. The queue is
; pinned with SERVICE_ACTIVE, then the callback runs OUTSIDE tcp_live_lock. This
; is load-bearing for the command plane: a service may call public tcp_send and
; hardware TX may take time, but STATUS can still acquire/snapshot the table.
tcp_service_drain:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    call tcp_live_lock_acquire
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .locked_busy
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 0
    jne  .locked_busy
    cmp  dword [rbx + TCB_TX_LEN], 0
    jne  .locked_busy
    mov  r12d, [rbx + TCB_RX_LEN]
    test r12d, r12d
    jz   .locked_ok
    cmp  r12d, TCP_WIRE_MAX_PAYLOAD
    jbe  .queue_cap_ok
    mov  r12d, TCP_WIRE_MAX_PAYLOAD
.queue_cap_ok:                          ; callback budget; owned TX segments by peer MSS
    movzx eax, word [rbx + TCB_PEER_WINDOW]
    test eax, eax
    jnz  .window_limit
    mov  eax, TCP_WIRE_MAX_PAYLOAD
.window_limit:
    cmp  r12d, eax
    jbe  .window_ok
    mov  r12d, eax
.window_ok:
    mov  r14, [rbx + TCB_RECV_CB]
    test r14, r14
    jz   .locked_busy
    mov  byte [rbx + TCB_SERVICE_ACTIVE], 1
    mov  rdi, rbx
    call tcp_tcb_rx_ptr
    mov  r13, rax
    call tcp_live_lock_release
    mov  qword [rel tcp_last_stage], 2   ; service chunk pinned outside lock
    mov  rsi, r13
    mov  rdi, rbx
    mov  edx, r12d
    call r14
    mov  r13, rax
    mov  qword [rel tcp_last_stage], 3   ; callback returned
    call tcp_live_lock_acquire
    mov  byte [rbx + TCB_SERVICE_ACTIVE], 0
    test r13, r13
    jnz  .locked_busy
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .locked_busy
    mov  rdi, rbx
    mov  esi, r12d
    call tcp_consume_rx
    mov  qword [rel tcp_last_stage], 6   ; service consumed the queued prefix
.locked_ok:
    call tcp_live_lock_release
    xor  eax, eax
    jmp  .out
.locked_busy:
    call tcp_live_lock_release
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Build a standards-shaped RST|ACK for a SYN that did not match a listener (or
; could not allocate a TCB). Called with tcp_live_lock held.
tcp_send_closed_rst:
    ; RDI=tcp hdr, ESI=local port, EDX=remote port, ECX=local IP,
    ; R8D=remote IP, R9D=tcp length.
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15d, r8d
    mov  [rsp], r9d
    lea  rdi, [rel tcp_rst_tcb]
    xor  esi, esi
    mov  edx, TCP_TCB_SIZE
    call memset
    mov  [rel tcp_rst_tcb + TCB_LOCAL_PORT], r12w
    mov  [rel tcp_rst_tcb + TCB_REMOTE_PORT], r13w
    mov  [rel tcp_rst_tcb + TCB_LOCAL_IP], r14d
    mov  [rel tcp_rst_tcb + TCB_REMOTE_IP], r15d
    mov  eax, [rbx + TCP_SEQ]
    bswap eax
    movzx ecx, byte [rbx + TCP_DATAOFF]
    shr  ecx, 4
    shl  ecx, 2
    mov  edx, [rsp]
    sub  edx, ecx
    add  eax, edx
    test byte [rbx + TCP_FLAGS], TCP_F_SYN
    jz   .no_syn
    inc  eax
.no_syn:
    test byte [rbx + TCP_FLAGS], TCP_F_FIN
    jz   .ack_ready
    inc  eax
.ack_ready:
    mov  [rel tcp_rst_tcb + TCB_RECV_NEXT], eax
    lea  rdi, [rel tcp_rst_tcb]
    mov  esi, TCP_F_RST | TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Per-slot private queue state; validate membership before any sidecar access.
tcp_persist_ptr:
    lea  rax, [rel tcp_tcbs]
    mov  rcx, rdi
    sub  rcx, rax
    cmp  rcx, TCP_TCB_N * TCP_TCB_SIZE
    jae  .bad
    test ecx, TCP_TCB_SIZE - 1
    jnz  .bad
    shr  rcx, 2                         ; 128-byte TCB -> 32-byte persist sidecar
    lea  rax, [rel tcp_persist_state]
    add  rax, rcx
    ret
.bad:
    xor  eax, eax
    ret

tcp_persist_clear:
    call tcp_persist_ptr
    test rax, rax
    jz   .out
    mov  qword [rax + P_NEXT], 0
    mov  qword [rax + P_SILENT], 0
    mov  qword [rax + P_EPOCH], 0
    mov  qword [rax + P_TOTAL], 0
.out:
    ret

; RFC 9293 3.8.6.1: first probe after RTO, exponential backoff, responsive peers
; may stay open. Resource policy expires only a full silent TCP_IDLE_MS span;
; application close/abort/deadlines remain effective (RFC 6429 clarification).
; RDI=TCB, ESI=owned byte count (segmented queue or persist). With zero window,
; first probe follows the existing RTO; positive-window queues have no probe timer.
; Epochs never reuse within this boot, including across live TCP reinit.
tcp_persist_arm:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    mov  ebx, esi
    call tcp_persist_ptr
    test rax, rax
    jz   .bad
    cmp  qword [rel tcp_persist_epoch_next], -1
    je   .bad
    mov  r12, rax
    inc  qword [rel tcp_persist_epoch_next]
    mov  rax, [rel tcp_persist_epoch_next]
    mov  [r12 + P_EPOCH], rax
    mov  [r12 + P_TOTAL], ebx
    mov  dword [r12 + P_INTERVAL], TCP_RTO_MS
    call boot_ms_now
    lea  rdx, [rax + TCP_RTO_MS]
    mov  [r12 + P_NEXT], rdx
    add  rax, TCP_PERSIST_SILENT_MS
    mov  [r12 + P_SILENT], rax
    cmp  word [r13 + TCB_PEER_WINDOW], 0
    je   .armed
    mov  qword [r12 + P_NEXT], 0         ; segmentation has no zero-window timer
    mov  dword [r12 + P_INTERVAL], 0
.armed:
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Called only after the existing frontier/ACK interval/high-water validation.
; Qualified zero-window responses refresh silence, never probe backoff. Opening
; the window makes the owned flight immediately eligible without duplicating it.
tcp_persist_window:
    push rbx
    push r12
    mov  rbx, rdi
    call tcp_persist_ptr
    test rax, rax
    jz   .out
    cmp  qword [rax + P_EPOCH], 0
    je   .out
    mov  r12, rax
    call boot_ms_now
    lea  rdx, [rax + TCP_PERSIST_SILENT_MS]
    mov  [r12 + P_SILENT], rdx
    cmp  word [rbx + TCB_PEER_WINDOW], 0
    jne  .open
    cmp  qword [r12 + P_NEXT], 0
    jne  .out
    add  rax, TCP_RTO_MS
    mov  [r12 + P_NEXT], rax
    mov  dword [r12 + P_INTERVAL], TCP_RTO_MS
    jmp  .out
.open:
    cmp  qword [r12 + P_NEXT], 0
    je   .out
    mov  qword [r12 + P_NEXT], 0
    mov  dword [r12 + P_INTERVAL], 0
    mov  ecx, [rbx + TCB_SEND_NEXT]
    sub  ecx, [rbx + TCB_TX_SEQ]
    test ecx, ecx
    jnz  .emitted_open
    xor  eax, eax
.emitted_open:
    mov  [rbx + TCB_DEADLINE], rax       ; emitted bytes stay ACK-eligible while retry is due
    mov  byte [rbx + TCB_RETRIES], 0
.out:
    mov  rdi, rbx
    pop  r12
    pop  rbx
    ret

; Full ACK of an emitted private flight: remove exactly that prefix once.
; RAX=1 if an owned suffix remains; 0 for ordinary/fully-completed flights.
tcp_persist_advance:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    call tcp_persist_ptr
    test rax, rax
    jz   .none
    cmp  qword [rax + P_EPOCH], 0
    je   .none
    mov  r12, rax
    mov  r13d, [rbx + TCB_TX_LEN]
    mov  r14d, [r12 + P_TOTAL]
    sub  r14d, r13d
    jbe  .clear
    mov  rdi, rbx
    call tcp_tcb_tx_ptr
    mov  rdi, rax
    lea  rsi, [rax + r13]
    mov  edx, r14d
    call memcpy                         ; dst < src: production forward copy is overlap-safe
    mov  [r12 + P_TOTAL], r14d
    mov  eax, [rbx + TCB_SEND_NEXT]
    mov  [rbx + TCB_TX_SEQ], eax
    mov  [rbx + TCB_TX_ACK_HIGH], eax
    movzx eax, word [rbx + TCB_PEER_WINDOW]
    test eax, eax
    jnz  .bound
    inc  eax                            ; next zero-window flight is only one owned byte
.bound:
    cmp  r14d, eax
    cmova r14d, eax
    mov  rdi, rbx
    call tcp_peer_mss
    cmp  r14d, eax
    cmova r14d, eax
    mov  [rbx + TCB_TX_LEN], r14d
    mov  qword [rbx + TCB_DEADLINE], 0
    mov  byte [rbx + TCB_RETRIES], 0
    mov  eax, 1
    jmp  .out
.clear:
    mov  rdi, rbx
    call tcp_persist_clear
.none:
    xor  eax, eax
.out:
    mov  rdi, rbx
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=staged TCB, RSI=queue epoch. Like active SYN retries, revalidate under
; the table try-lock through bounded TX. A cancelled/reused slot cannot emit.
tcp_persist_transmit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r15, rsi
    call tcp_live_try_acquire
    test rax, rax
    jnz  .out
    mov  rdi, rbx
    call tcp_persist_ptr
    test rax, rax
    jz   .unlock
    cmp  [rax + P_EPOCH], r15
    jne  .unlock
    test r15, r15
    jz   .unlock
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .unlock
    mov  r12, rax
    call boot_ms_now
    mov  r14, rax
    cmp  word [rbx + TCB_PEER_WINDOW], 0
    jne  .open
    cmp  rax, [r12 + P_SILENT]
    jae  .expired
    cmp  rax, [r12 + P_NEXT]
    jb   .unlock
    mov  ecx, [r12 + P_INTERVAL]
    shl  ecx, 1
    mov  edx, TCP_PERSIST_MAX_MS
    cmp  ecx, edx
    cmova ecx, edx
    mov  [r12 + P_INTERVAL], ecx
    add  rax, rcx
    mov  [r12 + P_NEXT], rax             ; reserve even if TX fails or is busy
    mov  rdi, rbx
    call tcp_tcb_tx_ptr
    mov  rdx, rax
    mov  r13d, [rbx + TCB_SEND_NEXT]
    mov  eax, [rbx + TCB_TX_SEQ]
    mov  [rbx + TCB_SEND_NEXT], eax
    mov  rdi, rbx
    mov  esi, TCP_F_PSH | TCP_F_ACK
    mov  ecx, 1
    call tcp_transmit_once
    test rax, rax
    jnz  .restore
    cmp  r13d, [rbx + TCB_TX_SEQ]
    jne  .restore                      ; repeated probes consume no new sequence space
    inc  qword [rbx + TCB_BYTES_TX]
    inc  qword [rel tcp_stat_tx_bytes]
    add  r14, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], r14       ; qualifies ACK of this actually emitted octet
    jmp  .unlock
.restore:
    mov  [rbx + TCB_SEND_NEXT], r13d
    jmp  .unlock
.open:
    cmp  qword [rbx + TCB_DEADLINE], 0
    je   .ready
    cmp  rax, [rbx + TCB_DEADLINE]
    jb   .unlock
.ready:
    mov  eax, [rbx + TCB_SEND_NEXT]
    sub  eax, [rbx + TCB_TX_SEQ]
    jnz  .retry
    mov  r13d, [r12 + P_TOTAL]
    movzx eax, word [rbx + TCB_PEER_WINDOW]
    cmp  r13d, eax
    cmova r13d, eax
    mov  rdi, rbx
    call tcp_peer_mss
    cmp  r13d, eax
    cmova r13d, eax
    mov  [rbx + TCB_TX_LEN], r13d
    mov  rdi, rbx
    call tcp_send_prepared
    jmp  .unlock
.retry:
    mov  rdi, rbx
    call tcp_retransmit_data
    jmp  .unlock
.expired:
    mov  rdi, rbx
    call tcp_tcb_free
    inc  qword [rel tcp_stat_reaped]
.unlock:
    call tcp_live_lock_release
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Accept a cumulative ACK/window only at the qualified receive frontier.
; One original <=MSS flight remains intact until fully ACKed. Modulo offsets
; from TX_SEQ bound the interval without ordering raw uint32 sequence numbers.
; Partial/duplicate current ACKs may refresh the window, but cannot retire data;
; ACK_HIGH prevents a regressive partial ACK from reverting the window. Only a
; full emitted-flight ACK can advance a persist queue's privately-owned suffix.
tcp_process_ack:
    ; RDI=TCB, ESI=ack host order, EDX=window; ingress qualifies SEG.SEQ first.
    cmp  dword [rdi + TCB_TX_LEN], 0
    je   .frontier_only
    mov  ecx, [rdi + TCB_SEND_NEXT]
    sub  ecx, [rdi + TCB_TX_SEQ]       ; emitted span, including uint32 wrap
    jz   .frontier_only               ; queued/failed TX advanced no sequence
    cmp  ecx, [rdi + TCB_TX_LEN]
    jne  .bad                        ; not a complete successfully emitted flight
    mov  eax, esi
    sub  eax, [rdi + TCB_TX_SEQ]
    cmp  eax, ecx
    ja   .bad                        ; stale/future/half-space ACK outside <=MSS
    mov  r8d, [rdi + TCB_TX_ACK_HIGH]
    sub  r8d, [rdi + TCB_TX_SEQ]
    cmp  eax, r8d
    jb   .bad                        ; regressive ACK cannot update peer window
    mov  [rdi + TCB_TX_ACK_HIGH], esi
    mov  [rdi + TCB_PEER_WINDOW], dx
    cmp  eax, ecx
    jne  .ok                         ; partial/duplicate retains original flight
    cmp  qword [rdi + TCB_DEADLINE], 0
    je   .ok                         ; emission has not yet armed its timer
    call tcp_persist_advance
    test eax, eax
    jnz  .ok                         ; remaining privately-owned suffix is queued once
    mov  dword [rdi + TCB_TX_LEN], 0
    mov  byte [rdi + TCB_RETRIES], 0
    mov  qword [rdi + TCB_DEADLINE], 0
    jmp  .ok
.frontier_only:
    cmp  esi, [rdi + TCB_SEND_NEXT]
    jne  .bad                        ; idle/unsent: only the exact frontier exists
    mov  [rdi + TCB_PEER_WINDOW], dx
.ok:
    call tcp_persist_window
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

tcp_retransmit_data:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, [rbx + TCB_SEND_NEXT]
    mov  eax, [rbx + TCB_TX_SEQ]
    mov  [rbx + TCB_SEND_NEXT], eax
    mov  rdi, rbx
    call tcp_tcb_tx_ptr
    mov  rdx, rax
    mov  rdi, rbx
    movzx esi, byte [rbx + TCB_TX_FLAGS]
    mov  ecx, [rbx + TCB_TX_LEN]
    call tcp_transmit_once
    test rax, rax
    jnz  .restore_frontier
    cmp  r12d, [rbx + TCB_TX_SEQ]
    jne  .restore_frontier             ; already emitted: retry consumes no new space
    ; A failed initial send armed a timer without advancing SEND_NEXT. Its first
    ; successful retry is the first emission, not a second sequence consumption.
    mov  eax, [rbx + TCB_TX_LEN]
    add  [rbx + TCB_BYTES_TX], rax
    add  [rel tcp_stat_tx_bytes], rax
    jmp  .retry_account
.restore_frontier:
    mov  [rbx + TCB_SEND_NEXT], r12d
.retry_account:
    inc  byte [rbx + TCB_RETRIES]
    inc  qword [rel tcp_stat_retransmits]
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
.out:
    pop  r12
    pop  rbx
    ret

; tcp_close(RDI=TCB) — active close.  The transition and FIN are serialized
; with ingress; completion continues through FIN_WAIT_1/2 -> TIME_WAIT.
tcp_close:
    push rbx
    mov  rbx, rdi
    call tcp_live_try_acquire
    test rax, rax
    jnz  .tx_fail
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .bad
    cmp  dword [rbx + TCB_TX_LEN], 0
    jne  .bad
    mov  rdi, rbx
    mov  byte [rbx + TCB_STATE], TCP_FIN_WAIT_1
    call tcp_rx_ptr
    test rax, rax
    jz   .close_state
    cmp  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
    jne  .close_state
    mov  byte [rbx + TCB_STATE], TCP_LAST_ACK
.close_state:
    call tcp_persist_clear
    call tcp_rx_clear
    mov  byte [rbx + TCB_RETRIES], 0
    mov  byte [rbx + TCB_TX_FLAGS], 0    ; set only after the first FIN is sent
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    ; Keep the tuple owned through this bounded try-lock TX and its result,
    ; just like initial active SYN. Unlocking here allows abort/slot reuse to
    ; redirect the FIN and write its success marker into a new connection.
    mov  rdi, rbx
    mov  esi, TCP_F_FIN | TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jnz  .bad                           ; failed FIN still releases table ownership
    mov  byte [rbx + TCB_TX_FLAGS], TCP_F_FIN
    call tcp_live_lock_release
    xor  eax, eax
    jmp  .out
.bad:
    call tcp_live_lock_release
.tx_fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; tcp_poll — O(TCP_TCB_N), non-blocking. Called only after command_udp has
; drained both RX owners. It scans under tcp_live_lock with try-acquire,
; stages at most one wire action and one callback. FIN retries, queued data,
; passive SYN retries, ACK and reset retain ownership through bounded TX/result.
; Callbacks always run after unlock. Active-SYN and persist work revalidate
; under a second try-acquire through bounded TX, as initial open does, before
; returning the table.
; Callback completion is committed next tick; the UDP plane never spins.
tcp_poll:
    cmp  byte [rel tcp_client_ready], 1
    je   .ready
    ret
.ready:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48                         ; staged work + active tuple/frontier pins
    mov  qword [rsp + 0], 0             ; staged wire-action TCB
    mov  dword [rsp + 8], TCPPA_NONE
    mov  qword [rsp + 16], 0            ; staged service-callback TCB
    call boot_ms_now
    mov  r12, rax
    call tcp_live_try_acquire
    test rax, rax
    jnz  .poll_out                       ; control plane never spins on TCP work
    ; Rotate the first slot so one busy stream cannot monopolize the single
    ; staged wire action/callback budget across cooperative ticks.
    movzx eax, byte [rel tcp_poll_cursor]
    mov  ecx, eax
    inc  ecx
    and  ecx, TCP_TCB_N - 1              ; TCP_TCB_N is the fixed power-of-two cap
    mov  [rel tcp_poll_cursor], cl
    imul eax, eax, TCP_TCB_SIZE
    lea  rbx, [rel tcp_tcbs]
    add  rbx, rax
    mov  r13d, TCP_TCB_N
.slot:
    movzx eax, byte [rbx + TCB_STATE]
    test eax, eax
    jz   .next
    cmp  eax, TCP_REAP_PENDING
    je   .reap
    cmp  byte [rel tcp_client_alias_ready], 0
    jne  .alias_live
    mov  eax, [rel tcp_client_alias_ip]
    test eax, eax
    jz   .alias_live
    cmp  [rbx + TCB_LOCAL_IP], eax
    je   .reap
.alias_live:

    ; A callback ran after the preceding poll dropped the lock. Commit its
    ; pinned prefix now; a failed callback leaves the bytes queued for retry.
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 2
    jne  .state
    mov  byte [rbx + TCB_SERVICE_ACTIVE], 0
    cmp  qword [rbx + TCB_SERVICE_RESULT], 0
    jne  .service_clear
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .service_clear
    mov  rdi, rbx
    mov  esi, [rbx + TCB_SERVICE_LEN]
    call tcp_consume_rx
    mov  qword [rel tcp_last_stage], 6
.service_clear:
    mov  dword [rbx + TCB_SERVICE_LEN], 0
    mov  qword [rbx + TCB_SERVICE_CB], 0
.state:
    movzx eax, byte [rbx + TCB_STATE]
    cmp  eax, TCP_SYN_SENT
    je   .client_syn
    cmp  eax, TCP_SYN_RCVD
    je   .half_open
    cmp  eax, TCP_ESTABLISHED
    je   .established
    cmp  eax, TCP_LAST_ACK
    je   .fin_retry
    cmp  eax, TCP_FIN_WAIT_1
    je   .fin_retry
    cmp  eax, TCP_CLOSING
    je   .fin_retry
    cmp  eax, TCP_FIN_WAIT_2
    je   .deadline_reap
    cmp  eax, TCP_TIME_WAIT
    je   .deadline_reap
    jmp  .next
.client_syn:
    cmp  r12, [rbx + TCB_DEADLINE]
    jb   .next
    cmp  byte [rbx + TCB_RETRIES], TCP_MAX_RETRIES
    jae  .client_timeout
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_CLIENT_SYN
    mov  eax, [rbx + TCB_SEND_NEXT]
    mov  [rsp + 24], eax                ; guard against cancellation/slot reuse
    mov  eax, [rbx + TCB_LOCAL_PORT]
    mov  [rsp + 28], eax                ; both ports (contiguous u16s)
    mov  rax, [rbx + TCB_LOCAL_IP]
    mov  [rsp + 32], rax                ; both IPv4 addresses
    mov  rax, [rbx + TCB_DEADLINE]
    mov  [rsp + 40], rax                ; a redial must arm its own deadline
    jmp  .next
.half_open:
    cmp  r12, [rbx + TCB_DEADLINE]
    jb   .next
    cmp  byte [rbx + TCB_RETRIES], TCP_MAX_RETRIES
    jae  .reap
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_SYN_RETRY
    jmp  .next
.established:
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 0
    jne  .next                           ; callback pins tuple/buffer until commit
    mov  rdi, rbx
    call tcp_rx_fin_ready
    test rax, rax
    jz   .established_data
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_RX_FIN
    mov  [rsp + 24], rax
    jmp  .next
.established_data:
    ; A FIN consumed after callback completion still owes a prompt ACK even
    ; when accepted outbound data waits on a long zero-window persist timer.
    mov  rdi, rbx
    call tcp_rx_ptr
    test rax, rax
    jz   .established_tx
    cmp  byte [rax + OO_FIN_VALID], OO_FIN_CONSUMED
    jne  .established_tx
    cmp  byte [rbx + TCB_ACK_PENDING], 0
    jne  .ack_only
.established_tx:
    mov  eax, [rbx + TCB_TX_LEN]
    test eax, eax
    jz   .service_or_ack
    mov  rdi, rbx
    call tcp_persist_ptr
    test rax, rax
    jz   .ordinary_flight
    cmp  qword [rax + P_EPOCH], 0
    jne  .persist
    cmp  word [rbx + TCB_PEER_WINDOW], 0
    jne  .ordinary_flight
    mov  rdi, rbx
    mov  esi, [rbx + TCB_TX_LEN]
    call tcp_persist_arm                ; window shrank over an existing private flight
    test rax, rax
    jnz  .reap
    mov  rdi, rbx
    call tcp_persist_ptr
    mov  ecx, [rbx + TCB_SEND_NEXT]
    cmp  ecx, [rbx + TCB_TX_SEQ]
    jne  .persist                       ; preserve the original actually-emitted flight
    ; P_TOTAL retains every owned byte, but no prior byte reached the wire.
    ; The current flight is only the one-byte probe, including after failed TX.
    mov  dword [rbx + TCB_TX_LEN], 1
    mov  qword [rbx + TCB_DEADLINE], 0
.persist:
    cmp  word [rbx + TCB_PEER_WINDOW], 0
    jne  .persist_open
    mov  ecx, [rbx + TCB_SEND_NEXT]
    cmp  ecx, [rbx + TCB_TX_SEQ]
    jne  .persist_zero_ready
    ; A segmented queue already has an epoch when its window shrinks. Keep
    ; its whole P_TOTAL, but qualify only the byte the first probe can emit.
    mov  dword [rbx + TCB_TX_LEN], 1
    mov  qword [rbx + TCB_DEADLINE], 0
.persist_zero_ready:
    cmp  r12, [rax + P_SILENT]
    jae  .reap                         ; silent resource timeout, not a probe-count limit
    cmp  r12, [rax + P_NEXT]
    jb   .next
    jmp  .persist_stage
.persist_open:
    cmp  qword [rbx + TCB_DEADLINE], 0
    je   .persist_stage
    cmp  r12, [rbx + TCB_DEADLINE]
    jb   .idle_check
    cmp  byte [rbx + TCB_RETRIES], TCP_MAX_RETRIES
    jae  .reset_reap
.persist_stage:
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_PERSIST
    mov  rax, [rax + P_EPOCH]
    mov  [rsp + 24], rax                 ; staged work never authorizes a reused queue
    jmp  .next
.ordinary_flight:
    cmp  qword [rbx + TCB_DEADLINE], 0
    je   .stage_send
    cmp  r12, [rbx + TCB_DEADLINE]
    jb   .idle_check
    cmp  byte [rbx + TCB_RETRIES], TCP_MAX_RETRIES
    jae  .reset_reap
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_RETRANSMIT
    jmp  .next
.stage_send:
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_SEND
    jmp  .next
.service_or_ack:
    ; Queued work is not peer activity. Check the existing silent timeout
    ; before selecting callbacks/ACKs, which may otherwise fail every tick
    ; forever. Running callbacks were excluded above; persist keeps its own
    ; silence clock and data/FIN retries keep their existing bounded policy.
    mov  rax, r12
    sub  rax, [rbx + TCB_LAST_ACTIVITY]
    cmp  rax, TCP_IDLE_MS
    jae  .reset_reap
    cmp  dword [rbx + TCB_RX_LEN], 0
    je   .ack_only
    cmp  qword [rsp + 16], 0
    jne  .ack_only                       ; one callback per cooperative tick
    movzx eax, word [rbx + TCB_PEER_WINDOW]
    test eax, eax
    jnz  .callback_window
    mov  eax, TCP_WIRE_MAX_PAYLOAD       ; a service may privately queue zero-window data
.callback_window:
    mov  r14, [rbx + TCB_RECV_CB]
    test r14, r14
    jz   .ack_only
    mov  ecx, [rbx + TCB_RX_LEN]
    cmp  ecx, TCP_WIRE_MAX_PAYLOAD
    jbe  .service_queue_cap
    mov  ecx, TCP_WIRE_MAX_PAYLOAD
.service_queue_cap:                     ; callback owns a bounded queue, not a wire segment
    cmp  ecx, eax
    jbe  .service_window
    mov  ecx, eax
.service_window:
    mov  [rbx + TCB_SERVICE_LEN], ecx
    mov  [rbx + TCB_SERVICE_CB], r14
    mov  qword [rbx + TCB_SERVICE_RESULT], -1
    mov  byte [rbx + TCB_SERVICE_ACTIVE], 1
    mov  [rsp + 16], rbx
    jmp  .next
.ack_only:
    cmp  byte [rbx + TCB_ACK_PENDING], 0
    je   .next
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_ACK
    jmp  .next
.idle_check:
    mov  rax, r12
    sub  rax, [rbx + TCB_LAST_ACTIVITY]
    cmp  rax, TCP_IDLE_MS
    jb   .next
.reset_reap:
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  byte [rbx + TCB_STATE], TCP_REAP_PENDING
    inc  qword [rel tcp_stat_rsts]
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_RST_REAP
    jmp  .next
.fin_retry:
    cmp  r12, [rbx + TCB_DEADLINE]
    jb   .next
    cmp  byte [rbx + TCB_RETRIES], TCP_MAX_RETRIES
    jae  .reap
    cmp  dword [rsp + 8], TCPPA_NONE
    jne  .next
    mov  [rsp + 0], rbx
    mov  dword [rsp + 8], TCPPA_FIN_RETRY
    jmp  .next
.client_timeout:
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 1
    je   .next
    mov  rdi, rbx
    call tcp_client_syn_timeout_free_locked
    inc  qword [rel tcp_stat_reaped]
    jmp  .next
.deadline_reap:
    cmp  r12, [rbx + TCB_DEADLINE]
    jb   .next
.reap:
    cmp  byte [rbx + TCB_SERVICE_ACTIVE], 1
    je   .next
    mov  rdi, rbx
    call tcp_tcb_free
    inc  qword [rel tcp_stat_reaped]
.next:
    add  rbx, TCP_TCB_SIZE
    lea  rax, [rel tcp_tcbs + TCP_TCB_N * TCP_TCB_SIZE]
    cmp  rbx, rax
    jb   .next_count
    lea  rbx, [rel tcp_tcbs]
.next_count:
    dec  r13d
    jnz  .slot
    ; A staged FIN retains ownership through its bounded TX and result.
    cmp  dword [rsp + 8], TCPPA_FIN_RETRY
    je   .action_fin_locked
    ; The selected tuple and private flight stay owned until this one bounded
    ; wire operation and its result finish. No service callback runs here.
    mov  rbx, [rsp + 0]
    mov  r15d, [rsp + 8]
    cmp  r15d, TCPPA_SEND
    je   .action_send_locked
    cmp  r15d, TCPPA_RETRANSMIT
    je   .action_retransmit_locked
    cmp  r15d, TCPPA_SYN_RETRY
    je   .action_syn_locked
    cmp  r15d, TCPPA_ACK
    je   .action_ack_locked
    cmp  r15d, TCPPA_RST_REAP
    je   .action_rst_locked
    call tcp_live_lock_release

    ; Remaining actions follow their existing action-specific lifetime paths.
    mov  rbx, [rsp + 0]
    mov  r15d, [rsp + 8]
    test rbx, rbx
    jz   .service
    cmp  r15d, TCPPA_CLIENT_SYN
    je   .action_client_syn
    cmp  r15d, TCPPA_RX_FIN
    je   .action_rx_fin
    cmp  r15d, TCPPA_PERSIST
    je   .action_persist

    jmp  .service
.action_rx_fin:
    mov  rdi, rbx
    mov  rsi, [rsp + 24]
    call tcp_rx_fin_transmit
    jmp  .service
.action_persist:
    mov  rdi, rbx
    mov  rsi, [rsp + 24]
    call tcp_persist_transmit
    jmp  .service
.action_send_locked:
    mov  rdi, rbx
    call tcp_send_prepared
    jmp  .wire_unlock
.action_retransmit_locked:
    mov  rdi, rbx
    call tcp_retransmit_data
    jmp  .wire_unlock
.action_syn_locked:
    mov  r14d, [rbx + TCB_SEND_NEXT]
    dec  dword [rbx + TCB_SEND_NEXT]
    mov  rdi, rbx
    mov  esi, TCP_F_SYNACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once               ; SYN consumes restored sequence again
    test rax, rax
    jz   .action_syn_account
    mov  [rbx + TCB_SEND_NEXT], r14d     ; failed TX consumes no sequence space
.action_syn_account:
    inc  byte [rbx + TCB_RETRIES]
    inc  qword [rel tcp_stat_retransmits]
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    jmp  .wire_unlock
.action_client_syn:
    ; Staged work is not authority to transmit a cancelled or reused tuple.
    ; Reacquire without spinning and validate the pending SYN frontier. Like
    ; initial open/ingress, the bounded try-lock TX runs under the table lock.
    call tcp_live_try_acquire
    test rax, rax
    jnz  .service
    cmp  byte [rbx + TCB_STATE], TCP_SYN_SENT
    jne  .client_syn_unlock
    mov  r14d, [rsp + 24]
    cmp  [rbx + TCB_SEND_NEXT], r14d
    jne  .client_syn_unlock
    mov  eax, [rsp + 28]
    cmp  [rbx + TCB_LOCAL_PORT], eax
    jne  .client_syn_unlock
    mov  rax, [rsp + 32]
    cmp  [rbx + TCB_LOCAL_IP], rax
    jne  .client_syn_unlock
    mov  rax, [rsp + 40]
    cmp  [rbx + TCB_DEADLINE], rax
    jne  .client_syn_unlock
    cmp  byte [rbx + TCB_TX_FLAGS], TCP_F_SYN
    jne  .client_syn_emit              ; ARP delayed the first SYN: ISN is still unconsumed
    dec  dword [rbx + TCB_SEND_NEXT]    ; retransmit the original ISN, not ISN+1
.client_syn_emit:
    mov  rdi, rbx
    mov  esi, TCP_F_SYN                 ; active open never sends SYN|ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jnz  .client_syn_failed
    mov  byte [rbx + TCB_TX_FLAGS], TCP_F_SYN
    jmp  .client_syn_account
.client_syn_failed:
    mov  [rbx + TCB_SEND_NEXT], r14d    ; a failed emission consumes no sequence space
.client_syn_account:
    inc  byte [rbx + TCB_RETRIES]       ; failed TX is bounded too
    inc  qword [rel tcp_stat_retransmits]
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
.client_syn_unlock:
    call tcp_live_lock_release
    jmp  .service
.action_fin_locked:
    mov  rbx, [rsp + 0]
    mov  r14d, [rbx + TCB_SEND_NEXT]
    cmp  byte [rbx + TCB_TX_FLAGS], TCP_F_FIN
    jne  .action_fin_emit                ; initial send failed: seq was not consumed
    dec  dword [rbx + TCB_SEND_NEXT]
.action_fin_emit:
    mov  rdi, rbx
    mov  esi, TCP_F_FIN | TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once               ; FIN consumes restored sequence again
    test rax, rax
    jz   .action_fin_sent
    mov  [rbx + TCB_SEND_NEXT], r14d     ; failed TX consumes no sequence space
    jmp  .action_fin_account
.action_fin_sent:
    mov  byte [rbx + TCB_TX_FLAGS], TCP_F_FIN
.action_fin_account:
    inc  byte [rbx + TCB_RETRIES]
    inc  qword [rel tcp_stat_retransmits]
    call boot_ms_now
    add  rax, TCP_RTO_MS
    mov  [rbx + TCB_DEADLINE], rax
    call tcp_live_lock_release
    jmp  .service
.action_ack_locked:
    mov  rdi, rbx
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jnz  .wire_unlock                  ; local refusal retains next-poll obligation
    mov  byte [rbx + TCB_ACK_PENDING], 0
    jmp  .wire_unlock
.action_rst_locked:
    mov  rdi, rbx
    mov  esi, TCP_F_RST | TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once

.wire_unlock:
    call tcp_live_lock_release
    jmp  .service

.service:
    ; Run one pinned callback out of lock. The callback may use public tcp_send,
    ; which itself now try-locks and reports backpressure instead of spinning.
    mov  rbx, [rsp + 16]
    test rbx, rbx
    jz   .poll_out
    mov  r14, [rbx + TCB_SERVICE_CB]
    test r14, r14
    jz   .service_fail
    mov  rdi, rbx
    call tcp_tcb_rx_ptr
    mov  rsi, rax
    mov  rdi, rbx
    mov  edx, [rbx + TCB_SERVICE_LEN]
    mov  qword [rel tcp_last_stage], 2
    call r14
    mov  [rbx + TCB_SERVICE_RESULT], rax
    mov  qword [rel tcp_last_stage], 3
    mov  byte [rbx + TCB_SERVICE_ACTIVE], 2
    jmp  .poll_out
.service_fail:
    mov  qword [rbx + TCB_SERVICE_RESULT], -1
    mov  byte [rbx + TCB_SERVICE_ACTIVE], 2
.poll_out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; tcp_diag_snapshot(RDI=136-byte caller buffer) -> 0. STATUS uses try-lock and
; reports lock_busy instead of spinning, preserving the independent UDP floor.
tcp_diag_snapshot:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    xor  esi, esi
    mov  edx, TCPD_SIZE
    call memset
    mov  qword [rbx + TCPD_MAX], TCP_TCB_N
    call tcp_live_try_acquire
    test rax, rax
    jz   .locked
    mov  qword [rbx + TCPD_LOCK_BUSY], 1
    jmp  .copy_counters
.locked:
    lea  r12, [rel tcp_listeners]
    mov  r13d, TCP_LISTENER_N
.listener:
    cmp  word [r12], 0
    je   .listener_next
    inc  qword [rbx + TCPD_LISTENERS]
.listener_next:
    add  r12, TCP_LISTENER_SIZE
    dec  r13d
    jnz  .listener
    lea  r12, [rel tcp_tcbs]
    mov  r13d, TCP_TCB_N
.tcb:
    movzx eax, byte [r12 + TCB_STATE]
    test eax, eax
    jz   .tcb_next
    inc  qword [rbx + TCPD_USED]
    cmp  eax, TCP_SYN_RCVD
    je   .count_syn
    cmp  eax, TCP_ESTABLISHED
    je   .count_est
    cmp  eax, TCP_TIME_WAIT
    je   .count_timewait
    inc  qword [rbx + TCPD_CLOSING]
    jmp  .tcb_next
.count_syn:
    inc  qword [rbx + TCPD_SYN]
    jmp  .tcb_next
.count_est:
    inc  qword [rbx + TCPD_EST]
    jmp  .tcb_next
.count_timewait:
    inc  qword [rbx + TCPD_TIMEWAIT]
.tcb_next:
    add  r12, TCP_TCB_SIZE
    dec  r13d
    jnz  .tcb
    mov  rax, [rel tcp_stat_accepts]
    mov  [rbx + TCPD_ACCEPTS], rax
    mov  rax, [rel tcp_stat_rx_bytes]
    mov  [rbx + TCPD_RX_BYTES], rax
    mov  rax, [rel tcp_stat_tx_bytes]
    mov  [rbx + TCPD_TX_BYTES], rax
    mov  rax, [rel tcp_stat_retransmits]
    mov  [rbx + TCPD_RETRANSMITS], rax
    mov  rax, [rel tcp_stat_reaped]
    mov  [rbx + TCPD_REAPED], rax
    mov  rax, [rel tcp_stat_full_rsts]
    mov  [rbx + TCPD_FULL_RSTS], rax
    mov  rax, [rel tcp_stat_rsts]
    mov  [rbx + TCPD_RSTS], rax
    mov  rax, [rel tcp_stat_closes]
    mov  [rbx + TCPD_CLOSES], rax
    call tcp_live_lock_release
.copy_counters:
    ; Counters/stage are naturally aligned monotonic words. A lock-busy STATUS
    ; may omit transient table counts, but it remains live and says so plainly.
    mov  rax, [rel tcp_stat_accepts]
    mov  [rbx + TCPD_ACCEPTS], rax
    mov  rax, [rel tcp_stat_rx_bytes]
    mov  [rbx + TCPD_RX_BYTES], rax
    mov  rax, [rel tcp_stat_tx_bytes]
    mov  [rbx + TCPD_TX_BYTES], rax
    mov  rax, [rel tcp_stat_retransmits]
    mov  [rbx + TCPD_RETRANSMITS], rax
    mov  rax, [rel tcp_stat_reaped]
    mov  [rbx + TCPD_REAPED], rax
    mov  rax, [rel tcp_stat_full_rsts]
    mov  [rbx + TCPD_FULL_RSTS], rax
    mov  rax, [rel tcp_stat_rsts]
    mov  [rbx + TCPD_RSTS], rax
    mov  rax, [rel tcp_stat_closes]
    mov  [rbx + TCPD_CLOSES], rax
    mov  rax, [rel tcp_last_stage]
    mov  [rbx + TCPD_LAST_STAGE], rax
    mov  rax, [rel tcp_stat_syn_reaps]
    mov  [rbx + TCPD_SYN_REAPS], rax
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret

; tcp4_ingress(RDI=complete Ethernet frame, RSI=available bytes) -> 0 consumed /
; -1 ignored. The shared command_udp RX owner calls this only for IPv4 proto 6.
tcp4_ingress:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    mov  dword [rsp + 32], 0             ; queued service work; poll drains later
    mov  dword [rsp + 36], 0             ; accept callback deferred past table lock
    mov  rbx, rdi                         ; frame
    mov  r15, rsi                         ; available bytes
    cmp  byte [rel tcp_client_ready], 1
    jne  .reject
    test rbx, rbx
    jz   .reject
    cmp  r15, 14 + 20 + TCP_HDR_LEN
    jb   .reject
    cmp  word [rbx + 12], 0x0008
    jne  .reject
    lea  r12, [rbx + 14]                 ; IPv4 header
    movzx eax, byte [r12]
    mov  ecx, eax
    shr  ecx, 4
    cmp  ecx, 4
    jne  .reject
    and  eax, 0x0f
    shl  eax, 2
    cmp  eax, 20
    jb   .reject
    cmp  eax, 60
    ja   .reject
    mov  r13d, eax                        ; IPv4 IHL
    lea  rax, [r13 + 14 + TCP_HDR_LEN]
    cmp  rax, r15
    ja   .reject
    cmp  byte [r12 + 9], 6
    jne  .reject
    mov  al, [r12 + 6]
    and  al, 0xbf                         ; allow DF only
    jnz  .reject
    cmp  byte [r12 + 7], 0
    jne  .reject
    movzx eax, byte [r12 + 2]
    shl  eax, 8
    mov  al, [r12 + 3]
    cmp  eax, r13d
    jb   .reject
    cmp  eax, 1500
    ja   .reject
    lea  rcx, [rax + 14]
    cmp  rcx, r15
    ja   .reject
    sub  eax, r13d
    cmp  eax, TCP_HDR_LEN
    jb   .reject
    cmp  eax, TCP_WIRE_MAX_SEG
    ja   .reject
    mov  [rsp + 0], eax                  ; TCP segment length
    mov  eax, [r12 + 12]
    mov  [rsp + 8], eax                  ; source IP
    mov  eax, [r12 + 16]
    mov  [rsp + 12], eax
    call tcp_client_source_owned
    test eax, eax
    jz   .reject
    ; Destination already captured before the pure ownership check.
    lea  rdi, [rbx + 14]
    mov  esi, r13d
    call net_cksum16
    test ax, ax
    jnz  .reject                         ; invalid IPv4 header checksum
    lea  r14, [r12 + r13]                ; TCP header
    movzx eax, byte [r14 + TCP_DATAOFF]
    shr  eax, 4
    shl  eax, 2
    cmp  eax, TCP_HDR_LEN
    jb   .reject
    cmp  eax, [rsp + 0]
    ja   .reject
    mov  [rsp + 4], eax                  ; TCP header length
    mov  rdi, r14
    mov  esi, eax
    call tcp_options_validate
    test eax, eax
    jnz  .reject
    mov  [rsp + 28], r8d                 ; candidate; never retained before authentication
    mov  eax, [rsp + 0]
    sub  eax, [rsp + 4]
    mov  [rsp + 24], eax                 ; payload length
    mov  al, [r14 + TCP_FLAGS]
    mov  [rsp + 20], al
    mov  rdi, r14
    mov  esi, [rsp + 0]
    mov  edx, [rsp + 8]
    mov  ecx, [rsp + 12]
    call tcp_checksum_ipv4
    test ax, ax
    jnz  .reject                         ; host stack must supply a valid checksum

    ; SEC-S7a: a segment never teaches the ARP cache (a spoofed source IP would
    ; rebind the gateway). Replies resolve the next hop through the cache, and a
    ; miss asks with a solicited who-has (udp4_arp_request); the peer's SYN retry
    ; then finds the binding.
    call tcp_live_try_acquire
    test rax, rax
    jnz  .reject                         ; contention is a bounded packet drop

    mov  eax, [rsp + 12]
    call tcp_client_source_owned
    test eax, eax
    jz   .unlock_ok
    movzx eax, byte [r14 + TCP_SRCPORT]
    shl  eax, 8
    mov  al, [r14 + TCP_SRCPORT + 1]
    mov  [rsp + 16], ax                  ; remote port
    movzx eax, byte [r14 + TCP_DSTPORT]
    shl  eax, 8
    mov  al, [r14 + TCP_DSTPORT + 1]
    mov  [rsp + 18], ax                  ; local port
    movzx edi, word [rsp + 18]
    movzx esi, word [rsp + 16]
    mov  edx, [rsp + 8]
    mov  ecx, [rsp + 12]
    call tcp_tcb_find
    test rax, rax
    jz   .no_tcb
    mov  r13, rax                        ; matched connection
    mov  eax, [rsp + 12]
    cmp  eax, [r13 + TCB_LOCAL_IP]
    jne  .unlock_ok                      ; alias cannot target the primary tuple
    cmp  byte [r13 + TCB_STATE], TCP_SYN_SENT
    jne  .tuple_ready
    cmp  byte [r13 + TCB_TX_FLAGS], TCP_F_SYN
    jne  .unlock_ok                      ; no peer reply can acknowledge an unsent SYN
.tuple_ready:
    test byte [rsp + 20], TCP_F_RST
    jnz  .peer_reset                     ; account and contain peer reset
    ; RFC 9293 3.10.7.4: after SYN/RST handling, ACK is required before
    ; established text or FIN processing. Reject before even activity refresh;
    ; an ACK-free packet cannot own receive storage or finish the connection.
    ; Leave SYN on its existing challenge rail, which precedes ACK admission.
    cmp  byte [r13 + TCB_STATE], TCP_ESTABLISHED
    jne  .dispatch_state
    test byte [rsp + 20], TCP_F_SYN
    jnz  .dispatch_state
    test byte [rsp + 20], TCP_F_ACK
    jz   .unlock_ok
.dispatch_state:
    cmp  byte [r13 + TCB_STATE], TCP_SYN_RCVD
    je   .syn_rcvd
    cmp  byte [r13 + TCB_STATE], TCP_SYN_SENT
    je   .syn_sent
    cmp  byte [r13 + TCB_STATE], TCP_ESTABLISHED
    je   .established
    cmp  byte [r13 + TCB_STATE], TCP_FIN_WAIT_1
    je   .fin_wait_1
    cmp  byte [r13 + TCB_STATE], TCP_FIN_WAIT_2
    je   .fin_wait_2
    cmp  byte [r13 + TCB_STATE], TCP_CLOSING
    je   .closing
    cmp  byte [r13 + TCB_STATE], TCP_TIME_WAIT
    je   .time_wait
    cmp  byte [r13 + TCB_STATE], TCP_LAST_ACK
    je   .last_ack
    jmp  .unlock_ok

.time_wait:
    mov  rdi, r13
    mov  esi, [r14 + TCP_SEQ]
    bswap esi
    movzx edx, byte [rsp + 20]
    call tcp_time_wait_syn_ok
    test eax, eax
    jz   .time_wait_old                  ; old incarnation: re-ACK its FIN
    mov  rdi, r13
    call tcp_tcb_free                    ; new incarnation reuses the tuple
    inc  qword [rel tcp_stat_syn_reaps]
    jmp  .no_tcb

.time_wait_old:
    ; RFC 9293 3.10.7.4: a retransmission of the consumed remote FIN
    ; restarts TIME_WAIT. ACK-only traffic, SYN challenges and unrelated
    ; FIN sequences must not extend it. Include retransmitted text in the
    ; FIN position, using wrapping sequence arithmetic; never consume it again.
    movzx eax, byte [rsp + 20]
    and  eax, TCP_F_SYN | TCP_F_ACK | TCP_F_FIN
    cmp  eax, TCP_F_ACK | TCP_F_FIN
    jne  .send_current_ack
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    add  eax, [rsp + 24]
    inc  eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .send_current_ack
    call boot_ms_now
    add  rax, TCP_TIME_WAIT_MS
    mov  [r13 + TCB_DEADLINE], rax
    jmp  .send_current_ack

.no_tcb:
    mov  eax, [rsp + 12]
    cmp  eax, [rel tcp_live_ip]
    jne  .unlock_ok                      ; no listener or reset grant on DHCP alias
    test byte [rsp + 20], TCP_F_RST
    jnz  .unlock_ok                      ; never answer a reset with another reset
    test byte [rsp + 20], TCP_F_SYN
    jz   .unlock_ok
    test byte [rsp + 20], TCP_F_ACK
    jnz  .closed_rst                     ; unsolicited SYN-ACK is closed
    movzx edi, word [rsp + 18]
    call tcp_listener_lookup
    test rax, rax
    jz   .closed_rst
    mov  rbx, rax                        ; listener entry
    call tcp_tcb_claim                   ; free slot, else oldest closed TCB
    test rax, rax
    jz   .table_full_rst                 ; only live connections -> fast refusal
    mov  r13, rax
    mov  rdi, r13
    xor  esi, esi
    mov  edx, TCP_TCB_SIZE
    call memset
    mov  rdi, r13
    call tcp_persist_clear
    call tcp_rx_begin
    test rax, rax
    jnz  .free_tcb
    mov  byte [r13 + TCB_STATE], TCP_SYN_RCVD
    mov  eax, [rsp + 28]
    mov  [r13 + TCB_PEER_MSS], ax
    mov  ax, [rsp + 18]
    mov  [r13 + TCB_LOCAL_PORT], ax
    mov  ax, [rsp + 16]
    mov  [r13 + TCB_REMOTE_PORT], ax
    mov  eax, [rsp + 12]
    mov  [r13 + TCB_LOCAL_IP], eax
    mov  eax, [rsp + 8]
    mov  [r13 + TCB_REMOTE_IP], eax
    mov  rax, [rbx + 8]
    mov  [r13 + TCB_ACCEPT_CB], rax
    mov  rdi, r13
    call tcp_isn_assign
    test rax, rax
    jnz  .free_tcb                       ; no key: drop the SYN, the peer retries
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    inc  eax
    mov  [r13 + TCB_RECV_NEXT], eax
    movzx eax, word [r14 + TCP_WINDOW]
    xchg al, ah
    mov  [r13 + TCB_PEER_WINDOW], ax
    call boot_ms_now
    mov  [r13 + TCB_LAST_ACTIVITY], rax
    add  rax, TCP_HALF_OPEN_MS
    mov  [r13 + TCB_DEADLINE], rax
    call tcp_mark_syn_rx
    mov  rdi, r13
    mov  esi, TCP_F_SYNACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jnz  .free_tcb
    call tcp_mark_synack_tx
    jmp  .unlock_ok

.table_full_rst:
    inc  qword [rel tcp_stat_full_rsts]
    jmp  .closed_rst

.closed_rst:
    mov  rdi, r14
    movzx esi, word [rsp + 18]
    movzx edx, word [rsp + 16]
    mov  ecx, [rsp + 12]
    mov  r8d, [rsp + 8]
    mov  r9d, [rsp + 0]
    call tcp_send_closed_rst
    jmp  .unlock_ok

.syn_rcvd:
    mov  esi, [r14 + TCP_SEQ]
    bswap esi
    mov  edx, [r14 + TCP_ACK]
    bswap edx
    movzx ecx, byte [rsp + 20]
    mov  rdi, r13
    call tcp_complete_handshake
    test rax, rax
    jnz  .unlock_ok
    movzx eax, word [r14 + TCP_WINDOW]
    xchg al, ah
    mov  [r13 + TCB_PEER_WINDOW], ax
    mov  qword [r13 + TCB_DEADLINE], 0
    mov  rdi, r13
    call tcp_tcb_touch
    mov  dword [rsp + 36], 1
    inc  qword [rel tcp_stat_accepts]
    call tcp_mark_established
    ; RFC 9293 3.10.7.4: the ACK completing a passive open can also carry
    ; text/FIN. Admit those bytes through the same bounded receive path now,
    ; before the deferred accept installs its receiver outside the table lock.
    jmp  .established

.syn_sent:
    ; Active open accepts exactly SYN|ACK acknowledging our SYN.  Any malformed
    ; response leaves the TCB pending; RST qualifies this same ACK frontier.
    ; Keep FIN in the admission mask: SYN|FIN is contradictory, not a SYNACK.
    ; Optional flags retain their policy; qualified RST already took precedence.
    movzx eax, byte [rsp + 20]
    and  eax, TCP_F_SYN | TCP_F_ACK | TCP_F_RST | TCP_F_FIN
    cmp  eax, TCP_F_SYNACK
    jne  .unlock_ok
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    cmp  eax, [r13 + TCB_SEND_NEXT]
    jne  .unlock_ok
    mov  eax, [rsp + 28]
    mov  [r13 + TCB_PEER_MSS], ax
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    inc  eax
    mov  [r13 + TCB_RECV_NEXT], eax
    mov  byte [r13 + TCB_STATE], TCP_ESTABLISHED
    movzx eax, word [r14 + TCP_WINDOW]
    xchg al, ah
    mov  [r13 + TCB_PEER_WINDOW], ax
    mov  qword [r13 + TCB_DEADLINE], 0
    mov  rdi, r13
    call tcp_tcb_touch
    ; RFC 9293 3.10.7.3: a qualified SYNACK may carry text. Its SYN has
    ; already consumed one sequence number; queue the following bytes before
    ; the final ACK so that ACK never skips data we do not own. Keep delivery
    ; on the usual post-connected poll rail, including polled routed clients.
    cmp  dword [rsp + 24], 0
    je   .syn_sent_send_ack
    mov  rdi, r13
    mov  rsi, r14
    mov  eax, [rsp + 4]
    add  rsi, rax
    mov  edx, [rsp + 24]
    mov  ecx, [r13 + TCB_RECV_NEXT]       ; SEG.SEQ + 1, modulo 2^32
    xor  r8d, r8d                       ; SYN consumed; FIN was refused above
    call tcp_rx_accept
    test eax, eax
    jle  .syn_sent_send_ack              ; refusal leaves SYN-only frontier
    mov  qword [rel tcp_last_stage], 1
    mov  dword [rsp + 32], 1
.syn_sent_send_ack:
    mov  rdi, r13
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    test rax, rax
    jz   .syn_sent_acked
    ; A local final-ACK TX failure (busy TX lock, ARP miss, driver error) must
    ; be no worse than wire loss: stay ESTABLISHED and let tcp_poll's ack-only
    ; path retry; a retransmitted SYN|ACK reaches .established's current ACK.
    mov  byte [r13 + TCB_ACK_PENDING], 1
.syn_sent_acked:
    mov  dword [rsp + 36], 1             ; active-open callback is deferred too
    call tcp_mark_established
    jmp  .unlock_ok

.established:
    ; RFC 5961 section 4.2: challenge then discard SYN before it can
    ; acknowledge a flight, replace the peer window or refresh activity.
    test byte [rsp + 20], TCP_F_SYN
    jnz  .send_current_ack
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .receive_segment               ; future storage grants no ACK/window authority
    test byte [rsp + 20], TCP_F_ACK
    jz   .sequence
    mov  esi, [r14 + TCP_ACK]
    bswap esi
    movzx edx, word [r14 + TCP_WINDOW]
    xchg dl, dh
    mov  rdi, r13
    call tcp_process_ack
    test rax, rax
    jnz  .send_current_ack
.sequence:
.receive_segment:
    test byte [rsp + 20], TCP_F_SYN
    jnz  .send_current_ack               ; established SYN never supplies stream bytes
    mov  rdi, r13
    mov  rsi, r14
    mov  eax, [rsp + 4]
    add  rsi, rax
    mov  edx, [rsp + 24]
    mov  ecx, [r14 + TCP_SEQ]
    bswap ecx
    movzx r8d, byte [rsp + 20]
    call tcp_rx_accept
    test eax, eax
    js   .send_current_ack
    ; Rejected ACKs/ranges cannot extend the connection's idle lifetime.
    ; An admitted payload or FIN includes bounded out-of-order ownership and
    ; exact retained duplicates. An empty ACK needs the receive frontier too:
    ; the reassembler's zero-length future no-op grants no peer activity.
    cmp  dword [rsp + 24], 0
    jne  .receive_activity
    test byte [rsp + 20], TCP_F_FIN
    jnz  .receive_activity
    mov  edx, [r14 + TCP_SEQ]
    bswap edx
    cmp  edx, [r13 + TCB_RECV_NEXT]
    jne  .receive_activity_done
.receive_activity:
    push rax                             ; preserve actual stream progress
    mov  rdi, r13
    call tcp_tcb_touch
    pop  rax
.receive_activity_done:
    test eax, eax
    jz   .receive_no_progress
    mov  byte [r13 + TCB_ACK_PENDING], 1
    mov  qword [rel tcp_last_stage], 1
    mov  dword [rsp + 32], 1
.receive_no_progress:
    ; A third-ACK FIN must not close/free the tuple before its accept callback.
    ; The existing poll path finishes retained FIN after that callback and any
    ; queued service bytes have drained; no second packet is required.
    cmp  dword [rsp + 36], 0
    jne  .receive_ack
    mov  rdi, r13
    call tcp_rx_fin_ready
    test rax, rax
    jz   .receive_ack
    mov  rdi, r13
    call tcp_rx_finish_locked
    jmp  .unlock_ok
.receive_ack:
    cmp  dword [rsp + 24], 0
    jne  .send_current_ack               ; cumulative ACK never crosses a hole
    test byte [rsp + 20], TCP_F_FIN
    jnz  .send_current_ack
    jmp  .unlock_ok
.send_current_ack:
    ; SYNs and in-window RST guesses must not drive unbounded ACK/ARP/NIC
    ; work. Keep the budget per connection, under the existing table lock, so
    ; one peer cannot exhaust another connection's challenge allowance.
    test byte [rsp + 20], TCP_F_RST | TCP_F_SYN
    jz   .send_current_ack_emit          ; ordinary duplicate/data/FIN ACKs bypass
    call boot_ms_now
    cmp  rax, [r13 + TCB_CHALLENGE_NEXT]
    jb   .unlock_ok
    lea  rdx, [rax + TCP_CHALLENGE_ACK_MS]
    mov  [r13 + TCB_CHALLENGE_NEXT], rdx ; reserve before even a failed/busy TX
.send_current_ack_emit:
    mov  rdi, r13
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    jmp  .unlock_ok

.fin_wait_1:
    ; RFC 9293 3.10.7.4: SYN is challenged before ordinary ACK admission.
    ; A FIN without ACK must not advance the receive frontier or close state.
    test byte [rsp + 20], TCP_F_SYN
    jnz  .send_current_ack
    test byte [rsp + 20], TCP_F_ACK
    jz   .unlock_ok
    ; An ACK for sequence space never emitted cannot authorize a peer FIN.
    ; Allow exact/older ACKs (simultaneous close); the half-space is ambiguous.
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    sub  eax, [r13 + TCB_SEND_NEXT]
    jz   .fin_wait_1_ack_bound_ok
    cmp  eax, 0x80000000
    jbe  .send_current_ack
.fin_wait_1_ack_bound_ok:
    ; Close-state ACKs must name our receive frontier before advancing the
    ; lifecycle, just like ESTABLISHED. A matching tuple/ACK can still be stale.
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .send_current_ack
    mov  byte [rsp + 28], 0              ; did this segment ACK our FIN?
    test byte [rsp + 20], TCP_F_ACK
    jz   .fin_wait_1_fin
    ; Failed first TX has not consumed FIN sequence space. An ACK of the
    ; unchanged send frontier only acknowledges earlier bytes, never our FIN.
    cmp  byte [r13 + TCB_TX_FLAGS], TCP_F_FIN
    jne  .fin_wait_1_fin
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    cmp  eax, [r13 + TCB_SEND_NEXT]
    jne  .fin_wait_1_fin
    mov  byte [rsp + 28], 1
.fin_wait_1_fin:
    test byte [rsp + 20], TCP_F_FIN
    jnz  .fin_wait_1_peer_fin
    cmp  byte [rsp + 28], 1
    jne  .unlock_ok
    mov  byte [r13 + TCB_STATE], TCP_FIN_WAIT_2
    call boot_ms_now
    add  rax, TCP_CLOSE_MS
    mov  [r13 + TCB_DEADLINE], rax
    jmp  .unlock_ok
.fin_wait_1_peer_fin:
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .send_current_ack
    inc  dword [r13 + TCB_RECV_NEXT]
    mov  rdi, r13
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
    cmp  byte [rsp + 28], 1
    je   .enter_time_wait
    mov  byte [r13 + TCB_STATE], TCP_CLOSING
    jmp  .unlock_ok

.fin_wait_2:
    ; Same synchronized-state admission as FIN_WAIT_1; RST dispatched earlier.
    test byte [rsp + 20], TCP_F_SYN
    jnz  .send_current_ack
    test byte [rsp + 20], TCP_F_ACK
    jz   .unlock_ok
    ; An ACK for sequence space never emitted cannot authorize a peer FIN.
    ; Allow exact/older ACKs (simultaneous close); the half-space is ambiguous.
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    sub  eax, [r13 + TCB_SEND_NEXT]
    jz   .fin_wait_2_ack_bound_ok
    cmp  eax, 0x80000000
    jbe  .send_current_ack
.fin_wait_2_ack_bound_ok:
    test byte [rsp + 20], TCP_F_FIN
    jz   .send_current_ack
.active_fin:
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .send_current_ack
    inc  dword [r13 + TCB_RECV_NEXT]
    mov  rdi, r13
    mov  esi, TCP_F_ACK
    xor  edx, edx
    xor  ecx, ecx
    call tcp_transmit_once
.enter_time_wait:
    mov  byte [r13 + TCB_STATE], TCP_TIME_WAIT
    call boot_ms_now
    add  rax, TCP_TIME_WAIT_MS
    mov  [r13 + TCB_DEADLINE], rax
    inc  qword [rel tcp_stat_closes]
    jmp  .unlock_ok

.closing:
    ; RFC 5961 section 4.2: a SYN cannot acknowledge our outstanding FIN.
    test byte [rsp + 20], TCP_F_SYN
    jnz  .send_current_ack
    ; A peer FIN can arrive while our first FIN TX is still pending. Keep
    ; retry ownership until that FIN has actually been emitted and ACKed.
    cmp  byte [r13 + TCB_TX_FLAGS], TCP_F_FIN
    jne  .send_current_ack
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .send_current_ack
    test byte [rsp + 20], TCP_F_ACK
    jz   .send_current_ack
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    cmp  eax, [r13 + TCB_SEND_NEXT]
    jne  .send_current_ack
    jmp  .enter_time_wait

.peer_reset:
    ; RFC 5961 section 3.2: a matching tuple alone cannot validate a reset.
    ; SYN_SENT qualifies the ACK of our SYN; all other states require the exact
    ; receive frontier. Challenge a non-exact in-window RST, silently drop one
    ; outside our bounded receive window, before accounting or TCB mutation.
    cmp  byte [r13 + TCB_STATE], TCP_SYN_SENT
    jne  .peer_reset_sequence
    test byte [rsp + 20], TCP_F_ACK
    jz   .unlock_ok
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    cmp  eax, [r13 + TCB_SEND_NEXT]
    jne  .unlock_ok
    jmp  .peer_reset_valid
.peer_reset_sequence:
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    sub  eax, [r13 + TCB_RECV_NEXT]      ; modulo-32 distance, including wrap
    jz   .peer_reset_valid
    push rax
    mov  rdi, r13
    call tcp_receive_window
    mov  edx, eax
    pop  rax
    cmp  eax, edx
    jb   .send_current_ack
    jmp  .unlock_ok
.peer_reset_valid:
    inc  qword [rel tcp_stat_rsts]
    jmp  .free_tcb

.last_ack:
    ; Challenge SYN before its ACK could retire this synchronized tuple.
    test byte [rsp + 20], TCP_F_SYN
    jnz  .send_current_ack
    ; A local refusal left no FIN for even an exact-frontier ACK to retire.
    cmp  byte [r13 + TCB_TX_FLAGS], TCP_F_FIN
    jne  .unlock_ok
    mov  eax, [r14 + TCP_SEQ]
    bswap eax
    cmp  eax, [r13 + TCB_RECV_NEXT]
    jne  .send_current_ack
    test byte [rsp + 20], TCP_F_ACK
    jz   .unlock_ok
    mov  eax, [r14 + TCP_ACK]
    bswap eax
    cmp  eax, [r13 + TCB_SEND_NEXT]
    jne  .unlock_ok
    inc  qword [rel tcp_stat_closes]
.free_tcb:
    mov  rdi, r13
    call tcp_tcb_free
.unlock_ok:
    cmp  dword [rsp + 36], 0
    je   .unlock_no_accept
    ; Pin the connected callback just like a receive callback, before unlock.
    mov  rbx, [r13 + TCB_ACCEPT_CB]
    test rbx, rbx
    jz   .unlock_no_accept
    mov  byte [r13 + TCB_SERVICE_ACTIVE], 1
    call tcp_live_lock_release
    mov  rdi, r13
    call rbx                             ; accept callback outside table lock
    call tcp_live_lock_acquire
    mov  byte [r13 + TCB_SERVICE_ACTIVE], 0
.unlock_no_accept:
    call tcp_live_lock_release
.consumed:
    xor  eax, eax
    jmp  .out
.reject:
    mov  rax, -1
.out:
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; The readiness canary uses the same registry, segment builder, checksum, and
; ACK transition as live traffic, but a dedicated TCB/scratch and no netdev TX.
; This keeps the four BOOTLOG tokens available before the probe's first connect;
; only the subsequent two fresh-nonce wire exchanges can complete the contract.
%if !PAOS_PUBLIC_BUILD
tcp_live_canary:
    push rbx
    push r12
    mov  edi, TCP_LIVE_PORT_A
    call tcp_listener_lookup
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  edi, TCP_LIVE_PORT_B
    call tcp_listener_lookup
    test rax, rax
    jz   .fail
    cmp  rax, rbx
    je   .fail                            ; two ports must occupy distinct entries
    cmp  qword [rbx + 8], 0
    je   .fail
    cmp  qword [rax + 8], 0
    je   .fail
    lea  rdi, [rel tcp_canary_tcb]
    xor  esi, esi
    mov  edx, TCP_TCB_SIZE
    call memset
    mov  byte [rel tcp_canary_tcb + TCB_STATE], TCP_SYN_RCVD
    mov  word [rel tcp_canary_tcb + TCB_LOCAL_PORT], TCP_LIVE_PORT_A
    mov  word [rel tcp_canary_tcb + TCB_REMOTE_PORT], 49152
    mov  eax, [rel tcp_live_ip]
    mov  [rel tcp_canary_tcb + TCB_LOCAL_IP], eax
    mov  dword [rel tcp_canary_tcb + TCB_REMOTE_IP], 0x010200c0
    mov  dword [rel tcp_canary_tcb + TCB_SEND_NEXT], 0x13579bdf
    mov  dword [rel tcp_canary_tcb + TCB_RECV_NEXT], 0x01020305
    lea  rax, [rel tcp_echo_accept]
    mov  [rel tcp_canary_tcb + TCB_ACCEPT_CB], rax
    call tcp_mark_syn_rx
    lea  rdi, [rel tcp_canary_segment]
    lea  rsi, [rel tcp_canary_tcb]
    mov  edx, TCP_F_SYNACK
    xor  ecx, ecx
    xor  r8d, r8d
    call tcp_build_segment
    cmp  eax, 24
    jne  .fail
    cmp  byte [rel tcp_canary_segment + TCP_DATAOFF], 0x60
    jne  .fail
    cmp  byte [rel tcp_canary_segment + TCP_FLAGS], TCP_F_SYNACK
    jne  .fail
    cmp  dword [rel tcp_canary_segment + 20], 0xb4050402
    jne  .fail                            ; wire bytes 02 04 05 b4 (MSS 1460)
    lea  rdi, [rel tcp_canary_segment]
    mov  esi, 24
    mov  edx, [rel tcp_canary_tcb + TCB_LOCAL_IP]
    mov  ecx, [rel tcp_canary_tcb + TCB_REMOTE_IP]
    call tcp_checksum_ipv4
    test ax, ax
    jnz  .fail
    call tcp_mark_synack_tx
    inc  dword [rel tcp_canary_tcb + TCB_SEND_NEXT]
    lea  rdi, [rel tcp_canary_tcb]
    mov  esi, 0x01020305
    mov  edx, 0x13579be0
    mov  ecx, TCP_F_ACK
    call tcp_complete_handshake
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tcp_canary_tcb]
    call tcp_echo_accept
    cmp  qword [rel tcp_canary_tcb + TCB_RECV_CB], 0
    je   .fail
    lea  rdi, [rel str_tcp_server_accept]
    call serial_string
    mov  dword [rel tcp_canary_segment + 20], 0x5a5a5958 ; payload bytes "XYZZ"
    mov  byte [rel tcp_canary_rx_seen], 0
    lea  rax, [rel tcp_canary_receive]
    mov  [rel tcp_canary_tcb + TCB_RECV_CB], rax
    lea  rdi, [rel tcp_canary_tcb]
    lea  rsi, [rel tcp_canary_segment]
    mov  edx, TCP_HDR_LEN
    mov  ecx, 4
    call tcp_deliver_payload
    test rax, rax
    jnz  .fail
    cmp  byte [rel tcp_canary_rx_seen], 1
    jne  .fail
    ; The stream marker additionally earns the shared data builder/checksum and
    ; cumulative-ACK retirement path, not merely callback invocation.
    mov  byte [rel tcp_canary_tcb + TCB_STATE], TCP_ESTABLISHED
    mov  word [rel tcp_canary_tcb + TCB_PEER_WINDOW], TCP_RX_CAP
    lea  rdi, [rel tcp_canary_segment]
    lea  rsi, [rel tcp_canary_tcb]
    mov  edx, TCP_F_PSH | TCP_F_ACK
    lea  rcx, [rel tcp_canary_segment + 20]
    mov  r8d, 4
    call tcp_build_segment
    cmp  eax, 24
    jne  .fail
    cmp  byte [rel tcp_canary_segment + TCP_FLAGS], TCP_F_PSH | TCP_F_ACK
    jne  .fail
    lea  rdi, [rel tcp_canary_segment]
    mov  esi, 24
    mov  edx, [rel tcp_canary_tcb + TCB_LOCAL_IP]
    mov  ecx, [rel tcp_canary_tcb + TCB_REMOTE_IP]
    call tcp_checksum_ipv4
    test ax, ax
    jnz  .fail
    ; A handshake ACK may arrive after a service callback reserves its first
    ; application flight but before poll hands those bytes to the NIC.  Such an
    ; ACK names SEND_NEXT only because the queued bytes have not advanced it;
    ; it must not retire the unsent flight.
    mov  dword [rel tcp_canary_tcb + TCB_TX_LEN], 4
    mov  eax, [rel tcp_canary_tcb + TCB_SEND_NEXT]
    mov  [rel tcp_canary_tcb + TCB_TX_SEQ], eax
    mov  [rel tcp_canary_tcb + TCB_TX_ACK_HIGH], eax
    mov  qword [rel tcp_canary_tcb + TCB_DEADLINE], 0
    lea  rdi, [rel tcp_canary_tcb]
    mov  esi, [rel tcp_canary_tcb + TCB_SEND_NEXT]
    mov  edx, TCP_RX_CAP
    call tcp_process_ack
    test rax, rax
    jnz  .fail
    cmp  dword [rel tcp_canary_tcb + TCB_TX_LEN], 4
    jne  .fail
    cmp  qword [rel tcp_canary_tcb + TCB_DEADLINE], 0
    jne  .fail
    ; Once emission arms the retransmit deadline, the same cumulative frontier
    ; is earned evidence that the peer received this one-flight payload.
    mov  qword [rel tcp_canary_tcb + TCB_DEADLINE], 1
    mov  eax, [rel tcp_canary_tcb + TCB_SEND_NEXT]
    sub  eax, 4
    mov  [rel tcp_canary_tcb + TCB_TX_SEQ], eax
    mov  [rel tcp_canary_tcb + TCB_TX_ACK_HIGH], eax
    lea  rdi, [rel tcp_canary_tcb]
    mov  esi, [rel tcp_canary_tcb + TCB_SEND_NEXT]
    mov  edx, TCP_RX_CAP
    call tcp_process_ack
    test rax, rax
    jnz  .fail
    cmp  dword [rel tcp_canary_tcb + TCB_TX_LEN], 0
    jne  .fail
    cmp  qword [rel tcp_canary_tcb + TCB_DEADLINE], 0
    jne  .fail

    ; Exercise the exact live queue/service seam that the metal client reaches.
    ; Use a non-TX callback so QEMU proves pointer derivation, lock handoff, and
    ; byte consumption without turning a canned fixture into wire evidence.
    lea  rdi, [rel tcp_tcbs]
    xor  esi, esi
    mov  edx, TCP_TCB_N * TCP_TCB_SIZE
    call memset
    mov  byte [rel tcp_tcbs + TCB_STATE], TCP_ESTABLISHED
    mov  word [rel tcp_tcbs + TCB_PEER_WINDOW], TCP_RX_CAP
    lea  rax, [rel tcp_canary_receive]
    mov  [rel tcp_tcbs + TCB_RECV_CB], rax
    mov  byte [rel tcp_canary_rx_seen], 0
    lea  rdi, [rel tcp_tcbs]
    lea  rsi, [rel tcp_canary_segment + 20]
    mov  edx, 4
    call tcp_queue_rx
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tcp_tcbs]
    call tcp_service_drain
    test rax, rax
    jnz  .fail
    cmp  byte [rel tcp_canary_rx_seen], 1
    jne  .fail
    cmp  dword [rel tcp_tcbs + TCB_RX_LEN], 0
    jne  .fail
    cmp  qword [rel tcp_last_stage], 6
    jne  .fail
    mov  qword [rel tcp_stat_rx_bytes], 0
    mov  qword [rel tcp_last_stage], 0
    lea  rdi, [rel str_tcp_server_stream]
    call serial_string

    ; Exercise both timer-driven reap classes and the fixed-cap allocator before
    ; the teardown marker. The live table is still private to boot initialization.
    lea  rdi, [rel tcp_tcbs]
    xor  esi, esi
    mov  edx, TCP_TCB_N * TCP_TCB_SIZE
    call memset
    mov  byte [rel tcp_tcbs + TCB_STATE], TCP_SYN_RCVD
    mov  byte [rel tcp_tcbs + TCB_RETRIES], TCP_MAX_RETRIES
    mov  qword [rel tcp_tcbs + TCB_DEADLINE], 0
    mov  byte [rel tcp_tcbs + TCP_TCB_SIZE + TCB_STATE], TCP_TIME_WAIT
    mov  qword [rel tcp_tcbs + TCP_TCB_SIZE + TCB_DEADLINE], 0
    mov  qword [rel tcp_stat_reaped], 0
    call tcp_poll
    cmp  byte [rel tcp_tcbs + TCB_STATE], 0
    jne  .fail
    cmp  byte [rel tcp_tcbs + TCP_TCB_SIZE + TCB_STATE], 0
    jne  .fail
    cmp  qword [rel tcp_stat_reaped], 2
    jne  .fail
    lea  rbx, [rel tcp_tcbs]
    mov  ecx, TCP_TCB_N
.fill_table:
    mov  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    add  rbx, TCP_TCB_SIZE
    dec  ecx
    jnz  .fill_table
    call tcp_tcb_alloc
    test rax, rax
    jnz  .fail
    ; SYN-under-pressure reclamation KAT. Advisory: a red KAT is reported on
    ; serial but never withdraws the already-proven listeners.
    call tcp_syn_reap_kat
    lea  rdi, [rel tcp_tcbs]
    xor  esi, esi
    mov  edx, TCP_TCB_N * TCP_TCB_SIZE
    call memset
    mov  qword [rel tcp_stat_reaped], 0
    mov  qword [rel tcp_stat_syn_reaps], 0
    lea  rdi, [rel str_tcp_server_teardown]
    call serial_string
    call tcp_mark_established
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; tcp_syn_reap_kat -> 0 PASS / -1 FAIL (marker or FAIL line on serial).
; FINDING_20260930: back-to-back connections were refused because closed TCBs
; still held the table. Drives tcp_tcb_claim (the exact passive-SYN/active-open
; allocator) through 20 connection lifecycles against a table whose every slot
; is held -- live, half-open, FIN-in-flight, RST-staged, callback-pinned, or
; closed-but-unreaped -- and requires: every lifecycle gets a TCB, the victim is
; always the oldest TIME_WAIT (then the oldest FIN_WAIT_2/CLOSING/LAST_ACK), a
; live/pinned/in-flight TCB is never touched, and a table of only live TCBs
; still refuses. Also grades the RFC 6191 same-tuple TIME_WAIT SYN rule.
; Boot-private table (tcp_live_canary); caller clears it afterwards.
TCP_REAP_KAT_LIFECYCLES equ 20
%if TCP_TCB_N < 16
%error "tcp_syn_reap_kat fixture needs at least 16 TCB slots"
%endif
tcp_syn_reap_kat:
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, 1                          ; failing stage for the FAIL line
    lea  rdi, [rel tcp_tcbs]
    xor  esi, esi
    mov  edx, TCP_TCB_N * TCP_TCB_SIZE
    call memset
    mov  qword [rel tcp_stat_syn_reaps], 0
    lea  rbx, [rel tcp_tcbs]
    xor  r12d, r12d
.seed:
    lea  rax, [rel tcp_reap_kat_state]
    movzx eax, byte [rax + r12]
    mov  [rbx + TCB_STATE], al
    lea  eax, [r12d + 1000]
    mov  [rbx + TCB_LOCAL_PORT], ax
    lea  rax, [rel tcp_reap_kat_age]
    movzx eax, word [rax + r12 * 2]
    mov  [rbx + TCB_LAST_ACTIVITY], rax
    mov  qword [rbx + TCB_DEADLINE], -1   ; lifecycle timers never fire here
    add  rbx, TCP_TCB_SIZE
    inc  r12d
    cmp  r12d, TCP_TCB_N
    jb   .seed
    mov  byte [rel tcp_tcbs + 8 * TCP_TCB_SIZE + TCB_SERVICE_ACTIVE], 1 ; pinned TIME_WAIT, age 0

    ; Phase 1: 20 lifecycles. Each claim must yield a zeroed TCB taken from the
    ; oldest TIME_WAIT; the lifecycle then closes into an unreaped TIME_WAIT.
    xor  r12d, r12d
.life:
    mov  r14d, 2
    call tcp_tcb_claim
    test rax, rax
    jz   .fail                            ; would have been a full-table RST
    mov  rbx, rax
    mov  r14d, 3
    cmp  byte [rbx + TCB_STATE], 0
    jne  .fail
    cmp  word [rbx + TCB_LOCAL_PORT], 0
    jne  .fail
    mov  rcx, rbx
    lea  rax, [rel tcp_tcbs]
    sub  rcx, rax
    shr  rcx, 7                           ; TCP_TCB_SIZE = 128
    mov  eax, r12d
    and  eax, 3
    lea  rdx, [rel tcp_reap_kat_tw_order]
    movzx eax, byte [rdx + rax]
    mov  r14d, 4
    cmp  ecx, eax
    jne  .fail                            ; not the oldest closed TCB
    mov  byte [rbx + TCB_STATE], TCP_SYN_RCVD
    lea  eax, [ecx + 1000]
    mov  [rbx + TCB_LOCAL_PORT], ax
    mov  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    mov  byte [rbx + TCB_STATE], TCP_TIME_WAIT ; server closed first, not yet reaped
    lea  eax, [r12d + 1001]
    mov  [rbx + TCB_LAST_ACTIVITY], rax
    mov  qword [rbx + TCB_DEADLINE], -1
    inc  r12d
    cmp  r12d, TCP_REAP_KAT_LIFECYCLES
    jb   .life
    mov  r14d, 5
    cmp  qword [rel tcp_stat_syn_reaps], TCP_REAP_KAT_LIFECYCLES
    jne  .fail
    ; Every slot keeps its seeded state and identity (victims were re-seeded
    ; with their own port and closed back into TIME_WAIT).
    lea  rbx, [rel tcp_tcbs]
    xor  r12d, r12d
    mov  r14d, 6
.verify:
    lea  rax, [rel tcp_reap_kat_state]
    movzx eax, byte [rax + r12]
    cmp  [rbx + TCB_STATE], al
    jne  .fail
    lea  eax, [r12d + 1000]
    cmp  [rbx + TCB_LOCAL_PORT], ax
    jne  .fail
    add  rbx, TCP_TCB_SIZE
    inc  r12d
    cmp  r12d, TCP_TCB_N
    jb   .verify
    mov  r14d, 7
    cmp  byte [rel tcp_tcbs + 8 * TCP_TCB_SIZE + TCB_SERVICE_ACTIVE], 1
    jne  .fail

    ; Phase 2: with no TIME_WAIT left, the oldest FIN_WAIT_2/CLOSING/LAST_ACK
    ; yields next; each claimant then becomes a live connection.
    xor  r12d, r12d
.retire_tw:
    lea  rax, [rel tcp_reap_kat_tw_order]
    movzx eax, byte [rax + r12]
    imul eax, eax, TCP_TCB_SIZE
    lea  rdx, [rel tcp_tcbs]
    mov  byte [rdx + rax + TCB_STATE], TCP_ESTABLISHED
    inc  r12d
    cmp  r12d, 4
    jb   .retire_tw
    xor  r12d, r12d
.closing_class:
    mov  r14d, 8
    call tcp_tcb_claim
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  rcx, rbx
    lea  rax, [rel tcp_tcbs]
    sub  rcx, rax
    shr  rcx, 7
    lea  rdx, [rel tcp_reap_kat_fin_order]
    movzx eax, byte [rdx + r12]
    mov  r14d, 9
    cmp  ecx, eax
    jne  .fail
    mov  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    lea  eax, [ecx + 1000]
    mov  [rbx + TCB_LOCAL_PORT], ax
    inc  r12d
    cmp  r12d, 3
    jb   .closing_class

    ; Phase 3: only live / half-open / FIN-in-flight / RST-staged / pinned
    ; TCBs remain: the claim must refuse and touch nothing.
    mov  r14d, 10
    call tcp_tcb_claim
    test rax, rax
    jnz  .fail
    cmp  qword [rel tcp_stat_syn_reaps], TCP_REAP_KAT_LIFECYCLES + 3
    jne  .fail
    mov  r14d, 11
    cmp  byte [rel tcp_tcbs + 8 * TCP_TCB_SIZE + TCB_STATE], TCP_TIME_WAIT
    jne  .fail
    cmp  byte [rel tcp_tcbs + 5 * TCP_TCB_SIZE + TCB_STATE], TCP_FIN_WAIT_1
    jne  .fail
    cmp  byte [rel tcp_tcbs + 6 * TCP_TCB_SIZE + TCB_STATE], TCP_REAP_PENDING
    jne  .fail

    ; Phase 4: RFC 6191 same-tuple rule on a TIME_WAIT TCB (RECV_NEXT 0x1000).
    lea  rbx, [rel tcp_tcbs]
    mov  byte [rbx + TCB_STATE], TCP_TIME_WAIT
    mov  dword [rbx + TCB_RECV_NEXT], 0x1000
    mov  r14d, 12
    mov  rdi, rbx
    mov  esi, 0x2000
    mov  edx, TCP_F_SYN
    call tcp_time_wait_syn_ok
    cmp  eax, 1
    jne  .fail                            ; newer bare SYN: new incarnation
    mov  r14d, 13
    mov  rdi, rbx
    mov  esi, 0x1000
    mov  edx, TCP_F_SYN
    call tcp_time_wait_syn_ok
    test eax, eax
    jnz  .fail                            ; not beyond the old frontier
    mov  r14d, 14
    mov  rdi, rbx
    mov  esi, 0x80001000
    mov  edx, TCP_F_SYN
    call tcp_time_wait_syn_ok
    test eax, eax
    jnz  .fail                            ; serial-arithmetic "older"
    mov  r14d, 15
    mov  rdi, rbx
    mov  esi, 0x2000
    mov  edx, TCP_F_SYNACK
    call tcp_time_wait_syn_ok
    test eax, eax
    jnz  .fail                            ; SYN|ACK is never a new passive open
    mov  r14d, 16
    mov  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    mov  rdi, rbx
    mov  esi, 0x2000
    mov  edx, TCP_F_SYN
    call tcp_time_wait_syn_ok
    test eax, eax
    jnz  .fail                            ; only TIME_WAIT may yield its tuple

    lea  rdi, [rel str_tcp_syn_reap_kat]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail:
    lea  rdi, [rel str_tcp_syn_reap_fail]
    mov  esi, r14d
    call tcp_emit_hex_kat                 ; clobbers r12 (restored below)
    mov  rax, -1
.out:
    push rax
    lea  rdi, [rel tcp_tcbs]
    xor  esi, esi
    mov  edx, TCP_TCB_N * TCP_TCB_SIZE
    call memset
    mov  qword [rel tcp_stat_syn_reaps], 0
    pop  rax
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

tcp_canary_receive:
    cmp  edx, 4
    jne  .fail
    cmp  dword [rsi], 0x5a5a5958          ; byte-exact "XYZZ" payload view
    jne  .fail
    mov  byte [rel tcp_canary_rx_seen], 1
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

tcp_mark_listen:
    cmp  byte [rel tcp_m_listen], 1
    je   .done
    mov  byte [rel tcp_m_listen], 1
    lea  rdi, [rel str_tcp_live_listen]
    call serial_string
.done:
    ret

%endif
tcp_mark_syn_rx:
    cmp  byte [rel tcp_m_syn_rx], 1
    je   .done
    mov  byte [rel tcp_m_syn_rx], 1
    lea  rdi, [rel str_tcp_live_syn]
    call serial_string
.done:
    ret

tcp_mark_synack_tx:
    cmp  byte [rel tcp_m_synack_tx], 1
    je   .done
    mov  byte [rel tcp_m_synack_tx], 1
    lea  rdi, [rel str_tcp_live_synack]
    call serial_string
.done:
    ret

tcp_mark_established:
    cmp  byte [rel tcp_m_established], 1
    je   .done
    mov  byte [rel tcp_m_established], 1
    lea  rdi, [rel str_tcp_live_established]
    call serial_string
.done:
    ret

; --- net/tcp data (canned vectors; writable, in-image — image page is RW+X
;     until the W^X code-lock increment, per boot/paging.asm) --------------------
; Canned SYN from a client: src port 0x1234, dst 80, seq X=0x11223344, ack=0,
; flags=SYN, window=0xffff. All multi-byte fields are network-order (big-endian).
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_tcp_0 0
tcp_syn_seg:
    db 0x12, 0x34                 ; src port
    db 0x00, 0x50                 ; dst port = 80
    db 0x11, 0x22, 0x33, 0x44     ; seq = 0x11223344
    db 0x00, 0x00, 0x00, 0x00     ; ack = 0
    db 0x50, TCP_F_SYN            ; data offset 5, flags SYN
    db 0xFF, 0xFF                 ; window
    db 0x00, 0x00                 ; checksum (don't-care on input)
    db 0x00, 0x00                 ; urgent

; Canned final ACK from the client: seq X+1, ack = our ISN+1 (0xA0000002),
; flags=ACK. Advances SYN_RCVD -> ESTABLISHED.
tcp_ack_seg:
    db 0x12, 0x34
    db 0x00, 0x50
    db 0x11, 0x22, 0x33, 0x45     ; seq = X+1
    db 0xA0, 0x00, 0x00, 0x02     ; ack = our_seq(0xA0000001)+1
    db 0x50, TCP_F_ACK
    db 0xFF, 0xFF
    db 0x00, 0x00
    db 0x00, 0x00

; TCP pseudo-header for the checksum (RFC 793 §3.1): src IP, dst IP, zero, proto=6,
; TCP length (20). Network-order. IPs are the canned endpoints (value only matters
; in that both sides agree — the LOGIC rung has no live NIC).
tcp_pseudo_hdr:
    db 0x0A, 0x00, 0x02, 0x0F     ; src IP 10.0.2.15
    db 0x0A, 0x00, 0x02, 0x02     ; dst IP 10.0.2.2
    db 0x00                       ; zero
    db 0x06                       ; protocol = TCP
    db 0x00, 0x14                 ; TCP length = 20

tcp_synack_seg: times TCP_HDR_LEN db 0    ; SYN-ACK scratch (built at runtime)
tcp_options_kat_good: times TCP_HDR_LEN db 0
    db 2,4,0x05,0xb4                     ; valid MSS option consumes all 24 bytes
tcp_options_kat_nolen: times TCP_HDR_LEN db 0
    db 2                                 ; kind without length byte
tcp_options_kat_zero: times TCP_HDR_LEN db 0
    db 2,0                               ; invalid length < 2
tcp_options_kat_overrun: times TCP_HDR_LEN db 0
    db 2,4                               ; declares four bytes, only two remain
tcp_cksum_buf:  times 32 db 0             ; pseudo(12) + segment(20) checksum span
tcp_kat_buf:    times 96 db 0
tcp_kat_reply:  times TCP_HDR_LEN db 0    ; 1415 tournament: dedicated KAT reply scratch
tcp_fault_syn:  times TCP_HDR_LEN db 0    ; 1432: mutable hostile-input vector
tcp_fault_reply: times TCP_HDR_LEN + 8 db 0 ; 1432: reply plus overrun canary
tcp_state:      db 0
tcp_our_seq:    dd 0

align 8
tcp_live_lock:      db 0
tcp_tx_lock:        db 0
tcp_cksum_lock:     db 0
tcp_poll_cursor:    db 0
tcp_m_listen:       db 0
tcp_m_syn_rx:       db 0
tcp_m_synack_tx:    db 0
tcp_m_established:  db 0
%if !PAOS_PUBLIC_BUILD
tcp_canary_rx_seen: db 0
%endif
tcp_live_mac:       times 6 db 0
tcp_live_ip:        dd 0
tcp_isn_secret_ready: db 0
tcp_isn_count:      dd 0
align 8
tcp_isn_secret:     times 32 db 0       ; per-boot RFC 6528 ISN key (tcp_isn_assign)
tcp_listeners:      times TCP_LISTENER_N * TCP_LISTENER_SIZE db 0
tcp_tcbs:           times TCP_TCB_N * TCP_TCB_SIZE db 0
tcp_bufs_ptr:       dq 0                ; -> heap RX/TX slot buffers (tcp_bufs_base); was 88,896 image bytes
tcp_rst_tcb:        times TCP_TCB_SIZE db 0
%if !PAOS_PUBLIC_BUILD
tcp_canary_tcb:     times TCP_TCB_SIZE db 0
%endif
%if !PAOS_PUBLIC_BUILD
tcp_canary_segment: times 24 db 0
%endif
tcp_cksum_wire:     times 12 + TCP_WIRE_MAX_SEG db 0
tcp_tx_frame:       times TCP_WIRE_FRAME_MAX db 0
align 8
tcp_arp_next_ms:    times TCP_TCB_N dq 0           ; per-TCB-slot who-has rate limit (ARP miss)
tcp_arp_route:      times TCP_ROUTE_SIZE db 0      ; dns_route_snapshot scratch (tx lock held)
tcp_stat_accepts:      dq 0
tcp_stat_rx_bytes:     dq 0
tcp_stat_tx_bytes:     dq 0
tcp_stat_retransmits:  dq 0
tcp_stat_reaped:       dq 0
tcp_stat_full_rsts:    dq 0
tcp_stat_rsts:         dq 0
tcp_stat_closes:       dq 0
tcp_stat_syn_reaps:    dq 0
; tcp_syn_reap_kat fixture: slots 0-3 ESTABLISHED, 4 SYN_RCVD, 5 FIN_WAIT_1,
; 6 REAP_PENDING, 7 SYN_SENT, 8 TIME_WAIT pinned by a callback (oldest of all),
; 9 LAST_ACK, 10/12/14/15 TIME_WAIT, 11 FIN_WAIT_2, 13 CLOSING; extra slots live.
%if !PAOS_PUBLIC_BUILD
tcp_reap_kat_state:
    db TCP_ESTABLISHED, TCP_ESTABLISHED, TCP_ESTABLISHED, TCP_ESTABLISHED
    db TCP_SYN_RCVD, TCP_FIN_WAIT_1, TCP_REAP_PENDING, TCP_SYN_SENT
    db TCP_TIME_WAIT, TCP_LAST_ACK, TCP_TIME_WAIT, TCP_FIN_WAIT_2
    db TCP_TIME_WAIT, TCP_CLOSING, TCP_TIME_WAIT, TCP_TIME_WAIT
    times TCP_TCB_N - 16 db TCP_ESTABLISHED
align 2
tcp_reap_kat_age:                         ; LAST_ACTIVITY ms; live slots are OLDEST
    dw 0, 0, 0, 0, 0, 0, 0, 0
    dw 0, 100, 500, 50, 300, 10, 400, 200
    times TCP_TCB_N - 16 dw 0
tcp_reap_kat_tw_order:  db 15, 12, 14, 10 ; TIME_WAIT victims, oldest first
tcp_reap_kat_fin_order: db 13, 11, 9      ; CLOSING(10) FIN_WAIT_2(50) LAST_ACK(100)
%endif
tcp_last_stage:        dq 0

; 1415 tournament KAT vector: the 16 header bytes tcp_build_synack MUST emit for the
; canned SYN above — ports swapped (src=0x0050, dst=0x1234), seq=ISN 0xA0000001 (BE),
; ack=SYN.seq+1=0x11223345 (BE), data-offset 0x50, flags 0x12 (SYN|ACK), window 0xFFFF.
; (Bytes 16..17 are the pseudo-header-dependent checksum — verified by self-fold, not here.)
tcp_synack_kat_expect:
    db 0x00, 0x50, 0x12, 0x34
    db 0xA0, 0x00, 0x00, 0x01
    db 0x11, 0x22, 0x33, 0x45
    db 0x50, 0x12, 0xFF, 0xFF

str_tcp_synseq:    db "[PAOS64][INF][net] tcp.kat syn_seq=0x", 0
str_tcp_saack:     db "[PAOS64][INF][net] tcp.kat synack_ack=0x", 0
str_tcp_flags:     db "[PAOS64][INF][net] tcp.kat flags=0x", 0
str_tcp_cksum:     db "[PAOS64][INF][net] tcp.kat cksum=0x", 0
str_tcp_state_est: db "[PAOS64][INF][net] tcp.kat state=ESTABLISHED", 13, 10, 0
str_tcp_pass:      db "[PAOS64] P4 net tcp: SYN->SYN-ACK->ACK->ESTABLISHED selftest PASS [tcp.handshake.logic]", 13, 10, 0

%if !PAOS_PUBLIC_BUILD
str_tcp_live_listen:      db "[PAOS64] P2 TCP: listener registry ready (N-ary, cap=4 ports=7000,7001) [tcp.listen.seam]", 13,10,0
%endif
str_tcp_live_syn:         db "[PAOS64] P2 TCP: SYN received on a listen port [tcp.syn.rx]", 13,10,0
str_tcp_live_synack:      db "[PAOS64] P2 TCP: SYN-ACK sent (seq/ack + MSS=1460) [tcp.synack.tx]", 13,10,0
str_tcp_live_established: db "[PAOS64] P2 TCP: 3-way handshake complete [tcp.established]", 13,10,0
%if !PAOS_PUBLIC_BUILD
str_tcp_server_accept: db "[PAOS64] SSH rung 0: live TCP accept from NIC ingress -> ESTABLISHED TCB delivered to callback [net.tcp.server.accept]", 13,10,0
%endif
%if !PAOS_PUBLIC_BUILD
str_tcp_server_stream: db "[PAOS64] SSH rung 0: bidirectional recv/send stream with ack/retransmit/window selftest [net.tcp.server.stream]", 13,10,0
%endif
%if !PAOS_PUBLIC_BUILD
str_tcp_syn_reap_kat: db "[PAOS64] P2 TCP: SYN under a full table reclaims the oldest closed TCB, never a live one (20 lifecycles + RFC6191 TIME_WAIT reuse) [tcp.syn.reap.kat]", 13,10,0
%endif
%if !PAOS_PUBLIC_BUILD
str_tcp_syn_reap_fail: db "[PAOS64][ERR][net] tcp.syn.reap.kat FAIL stage=0x", 0
%endif
str_tcp_bufs_fail: db "[PAOS64][ERR][net] tcp: heap refused the RX/TX slot buffers -> TCP degraded", 13,10,0
%if !PAOS_PUBLIC_BUILD
str_tcp_server_teardown: db "[PAOS64] SSH rung 0: FIN/RST teardown + bounded conn table + reaper selftest [net.tcp.server.teardown]", 13,10,0
%endif

str_tourn_tcp_kat:     db "[PAOS64] P4 net tcp: tcp_build_synack tournament KAT PASS (16 hdr bytes + cksum fold) [tourn.tcp_build_synack.kat]", 13, 10, 0
str_tourn_tcp_degrade: db "[PAOS64] P4 net tcp: tcp_build_synack NULL-ptr fault contained -> -1 [tourn.tcp_build_synack.degrade]", 13, 10, 0
str_tourn_tcp_guard:   db "[PAOS64] P4 net tcp: tcp_build_synack reject writes-nothing + state intact [tourn.tcp_build_synack.guard]", 13, 10, 0
str_tourn_tcp_fault:       db "[PAOS64] P4 net tcp: hostile battery [tourn.tcp_build_synack.fault contained=", 0
str_tourn_tcp_fault_total: db " total=", 0
str_tourn_tcp_fault_end:   db "]", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_net_tcp_0

%macro WDATA_net_tcp_routes 0
alignb 8
tcp_client_routes:  resb TCP_TCB_N * 16 ; routed client next hop + cookie
%endmacro
WDATA_BSS_DEFER WDATA_net_tcp_routes

%macro WDATA_net_tcp_persist 0
alignb 8
tcp_persist_state:      resb TCP_TCB_N * P_SIZE
tcp_persist_epoch_next: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_net_tcp_persist

%macro WDATA_net_tcp_rx_ooo 0
alignb 8
tcp_rx_ooo:        resb TCP_TCB_N * OO_SIZE
tcp_rx_epoch_next: resq 1                ; never reset by live_init
%endmacro
WDATA_BSS_DEFER WDATA_net_tcp_rx_ooo

; Separate outbound readiness/public ownership in preallocated zero-fill state.
%macro WDATA_tcp_client_binding 0
tcp_client_alias_ip: resd 1
tcp_client_alias_ready: resb 1
tcp_client_ready: resb 1
tcp_client_public: resb 1
alignb 8
tcp_public_ssh_callback: resq 1             ; retained only for exact port22 service
%endmacro
WDATA_BSS_DEFER WDATA_tcp_client_binding

; Bounded observational event store: last exact SYN timeout per table slot.
; Retained across live_init just like the never-reused receive epoch counter.
%macro WDATA_tcp_syn_retirements 0
alignb 8
tcp_syn_retirements: resb TCP_TCB_N * 16 ; epoch, completed boot milliseconds
%endmacro
WDATA_BSS_DEFER WDATA_tcp_syn_retirements

; Last actual common free per slot: epoch, completion, prior state/activity/
; deadline/retry count. Never reset by live_init; no timeout/cause inference.
%macro WDATA_tcp_reap_completions 0
alignb 8
tcp_reap_completions: resb TCP_TCB_N * 48
%endmacro
WDATA_BSS_DEFER WDATA_tcp_reap_completions
