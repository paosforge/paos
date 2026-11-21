;; MODULE net/dhcp
;; LAYER 4
;; EXPORTS dhcp_client_selftest, dhcp_find_option, dhcp_parse_offer, dhcp_parse_ack, dhcp_find_option_kat, dhcp_parse_ack_kat, dhcp_parse_offer_kat, dhcp_wr_u8_kat, dhcp_wire_start, dhcp_wire_start_no_server, dhcp_wire_stop, dhcp_wire_tick, dhcp_wire_ingest, dhcp_wire_mark_bound, dhcp_ack_yiaddr, dhcp_ack_mask_v, dhcp_ack_gw_v, dhcp_ack_dns_v, dhcp_ack_ntp_v, dhcp_ack_lease_s, dhcp_ack_t1_s, dhcp_ack_t2_s, dhcp_wire_state, dhcp_wire_tx_started, dhcp_wire_tx_attempts, dhcp_wire_tx_ok, dhcp_wire_tx_fail, dhcp_wire_rx_frames, dhcp_wire_rx_port68, dhcp_wire_rx_xid_ok, dhcp_wire_m_discover, dhcp_wire_m_offer, dhcp_wire_m_request, dhcp_wire_m_ack, dhcp_wire_abandon, dhcp_wire_observation, dhcp_wire_lease_snapshot, dhcp_wire_start_preferred, dhcp_wire_ntp_server
;; IMPORTS boot/serial, core/lib/mem, core/lib/cksum, lib/safe_buffer, core/time, core/lock, net/netdev, net/arp_cache
;; CAPS
;; OWNER saga:net
;; LOCK: dhcp_wire_lock PROTECTS dhcp_wire_preferred_server, dhcp_wire_state, dhcp_wire_no_server, dhcp_wire_owner_handle, dhcp_wire_retry_tsc, dhcp_wire_t1_tsc, dhcp_wire_t2_tsc, dhcp_wire_expire_tsc, dhcp_wire_tx_started, dhcp_wire_tx_attempts, dhcp_wire_tx_ok, dhcp_wire_tx_fail, dhcp_wire_rx_frames, dhcp_wire_rx_port68, dhcp_wire_rx_xid_ok, dhcp_wire_m_discover, dhcp_wire_m_offer, dhcp_wire_m_request, dhcp_wire_m_ack, dhcp_ack_yiaddr, dhcp_ack_mask_v, dhcp_ack_gw_v, dhcp_ack_dns_v, dhcp_ack_ntp_v, dhcp_ack_lease_s, dhcp_ack_t1_s, dhcp_ack_t2_s
; ============================================================================
; net/dhcp.asm — the DHCP client message-build/parse LOGIC (contract 1046 /
; C10e, the qemu rung of the bare-metal 1022/1024/1025). Rides ON TOP of the
; udp/ipv4 stack proven in 1042 (net/stack.asm): given a CANNED in-memory DHCP
; OFFER, PARSE it (xid, yiaddr, server-id) and BUILD the matching DHCPREQUEST,
; then PARSE a CANNED DHCPACK (lease yiaddr, mask, gateway, DNS) — no NIC, no
; live wire (the live-wire DORA lease is 1022/1024/1025 bare_metal). The selftest
; is CONTENT-graded: it drives the real build/parse and PRINTS the values it read
; back OUT OF the frames/buffer (KAT), so a stub that emits the marker without
; building/parsing FAILS:
;   * dhcp.client.logic — parse OFFER (op=BOOTREPLY, magic cookie 0x63825363,
;                         msg-type opt53=OFFER(2)) -> capture xid, yiaddr,
;                         server-id(opt54); BUILD the REQUEST echoing the SAME
;                         xid, opt53=REQUEST(3), opt50=offered-yiaddr,
;                         opt54=server-id; parse the ACK (opt53=ACK(5)) for the
;                         lease yiaddr + mask(opt1) + gw(opt3) + dns(opt6). The
;                         printed KAT reads opt50 + xid back OUT OF the built
;                         REQUEST buffer, so the probe re-checks
;                         req_opt50 == parsed_yiaddr (a non-zero dotted-quad) AND
;                         req_xid == offer_xid (echoed, not regenerated).
;   * NEGATIVE GATE      — a frame with a BAD magic cookie (not 0x63825363) or one
;                         SHORTER than the 240-byte BOOTP+cookie header is bounds-
;                         checked and REJECTED (no OOB read, no crash, boot
;                         continues to P2). The TLV option walk is fully bounds-
;                         checked (never reads past frame end).
;
; All copies go through core/lib/mem (G1). Byte order: xid + IPv4 fields are held
; in-frame byte order and echoed byte-for-byte, so what the OFFER carries is what
; the REQUEST carries.
; ============================================================================

; --- DHCP/BOOTP header field offsets (RFC 2131) --------------------------------
DHCP_OP        equ 0          ; 1=BOOTREQUEST (client->server), 2=BOOTREPLY
DHCP_XID       equ 4          ; transaction id (4 bytes, opaque — client echoes)
DHCP_YIADDR    equ 16         ; "your" IP: the offered/leased address (4 bytes)
DHCP_MAGIC     equ 236        ; magic cookie (4 bytes) precedes the options
DHCP_OPTIONS   equ 240        ; first option TLV
DHCP_MAGIC_LE  equ 0x63538263 ; bytes 63 82 53 63 read as a little-endian dword

; --- DHCP option tags ----------------------------------------------------------
OPT_SUBNET     equ 1          ; subnet mask (4 bytes)
OPT_ROUTER     equ 3          ; default gateway (4 bytes)
OPT_DNS        equ 6          ; DNS server (4 bytes)
OPT_NTP        equ 42         ; NTP servers (RFC 2132 8.3), first address used
OPT_PRL        equ 55         ; parameter-request list
OPT_REQIP      equ 50         ; Requested-IP (REQUEST echoes the offered yiaddr)
OPT_LEASE      equ 51         ; lease duration, network-order seconds
OPT_MSGTYPE    equ 53         ; DHCP message type (1 byte)
OPT_SERVERID   equ 54         ; DHCP server identifier (4 bytes)
OPT_T1         equ 58         ; renewal time, network-order seconds
OPT_T2         equ 59         ; rebinding time, network-order seconds
OPT_END        equ 255        ; end of options
OPT_PAD        equ 0          ; pad (single byte, no length)

MSG_OFFER      equ 2          ; DHCPOFFER
MSG_REQUEST    equ 3          ; DHCPREQUEST
MSG_ACK        equ 5          ; DHCPACK
MSG_NAK        equ 6          ; DHCPNAK

; dhcp_kat_isolated(RAX = KAT body) -> the body's RAX. RCQ-10 S3 (G3): the DHCP
;   KATs parse canned lab frames through the live parser, so they write the
;   lease, OFFER and REQUEST state in WDATA_net_dhcp_0 (dhcp_parsed_xid up to the
;   end of dhcp_request_buf). SELFTEST FULL re-runs them on a live boot. Run the
;   body under dhcp_wire_lock, with that block saved first and put back after, so
;   no test value (192.0.2.150, gw .1, dns 8.8.8.8) reaches a live lease or a
;   renewal. Clobbers: caller-saved; the body preserves rbx, r12-r15.
DHCP_KAT_LIVE_LEN  equ dhcp_request_buf + 300 - dhcp_parsed_xid
DHCP_KAT_FRAME_LEN equ (DHCP_KAT_LIVE_LEN + 15) & ~15 ; cover the live block, preserve alignment
dhcp_kat_isolated:
    push rbx
    sub  rsp, DHCP_KAT_FRAME_LEN             ; tracks any growth in the live block
    mov  rbx, rax
    call dhcp_wire_lock_acquire
    mov  rdi, rsp
    lea  rsi, [rel dhcp_parsed_xid]
    mov  edx, DHCP_KAT_LIVE_LEN
    call memcpy
    call rbx
    mov  rbx, rax
    lea  rdi, [rel dhcp_parsed_xid]
    mov  rsi, rsp
    mov  edx, DHCP_KAT_LIVE_LEN
    call memcpy
    call dhcp_wire_lock_release
    mov  rax, rbx
    add  rsp, DHCP_KAT_FRAME_LEN
    pop  rbx
    ret

; dhcp_client_selftest — THE 1046 acceptance gate. Parse the canned OFFER, build
;   the REQUEST from it, parse the canned ACK, run the negative gates, and only
;   print the KAT + marker when EVERY check passes (all values read back live).
;   clobbers: caller-saved; preserves rbx,r12-r15 (saved here).
dhcp_client_selftest:
    lea  rax, [rel .isolated]                ; RCQ-10 S3: never over a live lease
    jmp  dhcp_kat_isolated
.isolated:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---------- (1) parse the canned OFFER ----------
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    call dhcp_parse_offer
    test rax, rax
    jnz  .done                               ; a valid OFFER must parse (0)

    ; ---------- (2) build the REQUEST from the parsed OFFER state ----------
    lea  rdi, [rel dhcp_request_buf]
    call dhcp_build_request                   ; -> EAX = request length
    mov  [rel dhcp_request_len], eax

    ; ---------- (3) parse the canned ACK (lease yiaddr + mask + gw + dns) ----------
    lea  rdi, [rel dhcp_ack]
    mov  esi, DHCP_ACK_LEN
    call dhcp_parse_ack
    test rax, rax
    jnz  .done                               ; a valid ACK must parse (0)

    ; ---------- (4) NEGATIVE GATE: bad magic cookie -> rejected, no crash ----------
    lea  rdi, [rel dhcp_badframe]
    mov  esi, DHCP_BADFRAME_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .done                               ; a bad-cookie frame MUST be rejected

    ; ---------- (5) NEGATIVE GATE: short frame (< 240) -> rejected ----------
    lea  rdi, [rel dhcp_offer]
    mov  esi, 100                            ; truncated below the BOOTP+cookie header
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .done

    ; ---------- verify the built REQUEST actually carries opt50 == offered yiaddr ----------
    lea  rdi, [rel dhcp_request_buf]
    mov  esi, [rel dhcp_request_len]
    mov  edx, OPT_REQIP
    call dhcp_find_option
    test rax, rax
    jz   .done                               ; the REQUEST must carry option 50
    mov  r8d, [rax]                          ; opt50 value (from the built buffer)
    cmp  r8d, [rel dhcp_parsed_yiaddr]
    jne  .done                               ; opt50 must ECHO the offered yiaddr

    ; ---------- verify the REQUEST's msg-type is REQUEST(3) ----------
    lea  rdi, [rel dhcp_request_buf]
    mov  esi, [rel dhcp_request_len]
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jz   .done
    cmp  byte [rax], MSG_REQUEST
    jne  .done

    ; ---------- verify the REQUEST's opt54 == parsed server-id ----------
    lea  rdi, [rel dhcp_request_buf]
    mov  esi, [rel dhcp_request_len]
    mov  edx, OPT_SERVERID
    call dhcp_find_option
    test rax, rax
    jz   .done
    mov  r8d, [rax]
    cmp  r8d, [rel dhcp_parsed_serverid]
    jne  .done

    ; ---------- all checks passed: print the KAT lines, then earn the marker ----------
    ; main KAT line: parsed_yiaddr (from OFFER) | req_opt50 (from built REQUEST) |
    ;                offer_xid (from OFFER) | req_xid (from built REQUEST)
    lea  rdi, [rel str_dhcp_kat_pre]
    call serial_string
    lea  rsi, [rel dhcp_parsed_yiaddr]        ; parsed_yiaddr= (OFFER yiaddr)
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_kat_o50]
    call serial_string
    lea  rdi, [rel dhcp_request_buf]          ; req_opt50= read back OUT of the REQUEST
    mov  esi, [rel dhcp_request_len]
    mov  edx, OPT_REQIP
    call dhcp_find_option
    mov  rsi, rax
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_kat_oxid]
    call serial_string
    lea  rsi, [rel dhcp_parsed_xid]           ; offer_xid= (parsed OFFER xid)
    call dhcp_print_xid
    lea  rdi, [rel str_dhcp_kat_rxid]
    call serial_string
    lea  rsi, [rel dhcp_request_buf + DHCP_XID] ; req_xid= read back OUT of the REQUEST
    call dhcp_print_xid
    lea  rdi, [rel str_dhcp_crlf]
    call serial_string

    ; secondary KAT line: the parsed ACK lease fields (proves a real ACK parse)
    lea  rdi, [rel str_dhcp_ack_pre]
    call serial_string
    lea  rsi, [rel dhcp_ack_yiaddr]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_ack_mask]
    call serial_string
    lea  rsi, [rel dhcp_ack_mask_v]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_ack_gw]
    call serial_string
    lea  rsi, [rel dhcp_ack_gw_v]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_ack_dns]
    call serial_string
    lea  rsi, [rel dhcp_ack_dns_v]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_crlf]
    call serial_string

    lea  rdi, [rel str_dhcp_pass]
    call serial_string
    ; Contract 1024 declares these rows for both QEMU and hardware. Here they
    ; are earned by the complete canned DORA KAT above; the live wire path has
    ; separate flags and a content-graded dynamic-IP probe on bare metal.
    lea  rdi, [rel str_dhcp_kat_discover]
    call serial_string
    lea  rdi, [rel str_dhcp_kat_offer]
    call serial_string
    lea  rdi, [rel str_dhcp_kat_request]
    call serial_string
    lea  rdi, [rel str_dhcp_kat_bound]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dhcp_validate(RDI=frame, ESI=len) -> RAX = 0 ok / -1 reject.
;   A well-formed DHCP frame must be >= 240 bytes (full BOOTP header + cookie)
;   AND carry the magic cookie 0x63825363 at offset 236. Checked BEFORE any
;   field read. clobbers: RAX.
dhcp_validate:
    cmp  esi, DHCP_OPTIONS
    jb   .bad                                ; too short for header+cookie
    cmp  dword [rdi + DHCP_MAGIC], DHCP_MAGIC_LE
    jne  .bad
    xor  rax, rax
    ret
.bad:
    mov  rax, -1
    ret

; dhcp_find_option(RDI=frame, ESI=len, EDX=tag) -> RAX = value ptr, or 0.
;   Walks the option TLVs from offset 240, fully bounds-checked: never reads past
;   frame end, stops at OPT_END(255), skips OPT_PAD(0), and rejects a truncated
;   option (declared length runs past the frame). clobbers: RAX,RCX,R8,R10,R11.
;   TOURNAMENT 1402 (most-durable variant, re-run of 1307): same walk, same
;   returns for every legal frame — but the FAILURE ENVELOPE is widened and made
;   fully OBSERVABLE. Every hostile/malformed argument is contained as a clean 0,
;   never a fault: a NULL frame, a len too short to hold any option, an ABSURD len
;   (caller bug / negative-as-unsigned — rejected BEFORE the walk so no giant OOB
;   scan can #PF the box), a frame+len that wraps the address space, a tag with no
;   length byte, a truncated option, and a pathological never-terminating walk
;   (last-resort fuel ceiling). The shared safe_tlv_u8_view reads each declared
;   length once and validates it against remaining input before pointer formation.
;   Each reject records its DISTINCT reason (a per-reason
;   sub-counter + a live last-reason code), so a misbehaving peer's exact malformation
;   is visible after the fact — not just "some reject happened". Every outcome is
;   COUNTED (find/miss + 7 reject reasons) and the KAT delta-checks the aggregate AND
;   the per-reason breakdown, so the telemetry itself is correctness-gated.
DHCP_FO_FUEL   equ 65536      ; > max TLVs any 16-bit-sized frame can hold; a walk
                              ; that burns this much fuel is a logic fault being
                              ; contained, not a legal frame being parsed
DHCP_FO_MAXLEN equ 65535      ; a DHCP message rides one UDP datagram (payload <= 65507);
                              ; a len above this is a caller bug (garbage / a negative
                              ; length read as unsigned). Contain it at the door so the
                              ; walk can never be pointed at gigabytes of OOB memory.
; reject reason codes — stored live in dhcp_fo_last_rej for post-hoc peer diagnosis
FO_REJ_NULL    equ 1
FO_REJ_SHORT   equ 2
FO_REJ_WRAP    equ 3
FO_REJ_NOLEN   equ 4
FO_REJ_TRUNC   equ 5
FO_REJ_TOOBIG  equ 6
FO_REJ_FUEL    equ 7
dhcp_find_option:
    push rbx
    push r12
    mov  r12d, edx                           ; requested tag survives shared reader
    test rdi, rdi
    jz   .rej_null                           ; NULL frame -> contained, no deref
    cmp  esi, DHCP_OPTIONS + 1
    jb   .rej_short                          ; no room for even one option byte
    cmp  esi, DHCP_FO_MAXLEN
    ja   .rej_toobig                         ; absurd len -> contain BEFORE any walk
    mov  esi, esi                            ; explicit zero-extension of wire length
    call safe_checked_add                    ; validate base+len before exposing an end ptr
    test edx, edx
    jnz  .rej_wrap
    mov  r11, rax                            ; end-of-frame ptr (one past last byte)
    lea  r10, [rdi + DHCP_OPTIONS]           ; option cursor
    mov  ebx, DHCP_FO_FUEL                   ; last-resort anti-livelock ceiling
.walk:
    sub  ebx, 1
    jl   .rej_fuel                           ; fuel exhausted -> contained (unreachable
                                             ; on a bounded frame — fires only if an
                                             ; invariant is ever violated, made VISIBLE)
    cmp  r10, r11
    jae  .miss                               ; ran off the end -> not found
    movzx eax, byte [r10]                    ; tag
    cmp  al, OPT_END
    je   .miss                               ; end of options
    cmp  al, OPT_PAD
    je   .pad                                ; pad -> single byte, no length
    mov  rax, r11
    sub  rax, r10                            ; remaining; r10 < r11 above
    cmp  rax, 2
    jb   .rej_nolen                          ; tag with NO length byte -> malformed
    mov  rdi, r10
    mov  rsi, r11
    call safe_tlv_u8_view                    ; EDX=tag, RDI=value, RSI=next
    test eax, eax
    jnz  .rej_trunc                          ; declared length exceeds remaining
    cmp  edx, r12d                           ; tag match?
    je   .found
    mov  r10, rsi                            ; advance to validated next option
    jmp  .walk
.pad:
    inc  r10
    jmp  .walk
.found:
    inc  dword [rel dhcp_fo_ct_find]
    mov  rax, rdi                            ; validated option value pointer
    pop  r12
    pop  rbx
    ret
.miss:
    inc  dword [rel dhcp_fo_ct_miss]         ; clean not-found (END / end-of-frame)
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
; --- contained rejects: each records its DISTINCT reason (a per-reason sub-counter
;     + the live last-reason code) so a misbehaving peer's exact malformation is
;     visible after the fact, then falls into the shared aggregate+return. Every path
;     returns a clean 0 and faults NOTHING. ---
.rej_null:
    inc  dword [rel dhcp_fo_rej_null]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_NULL
    jmp  .rej
.rej_short:
    inc  dword [rel dhcp_fo_rej_short]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_SHORT
    jmp  .rej
.rej_toobig:
    inc  dword [rel dhcp_fo_rej_toobig]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_TOOBIG
    jmp  .rej
.rej_wrap:
    inc  dword [rel dhcp_fo_rej_wrap]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_WRAP
    jmp  .rej
.rej_nolen:
    inc  dword [rel dhcp_fo_rej_nolen]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_NOLEN
    jmp  .rej
.rej_trunc:
    inc  dword [rel dhcp_fo_rej_trunc]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_TRUNC
    jmp  .rej
.rej_fuel:
    inc  dword [rel dhcp_fo_rej_fuel]
    mov  dword [rel dhcp_fo_last_rej], FO_REJ_FUEL
    ; fall through to the shared aggregate + return
.rej:
    inc  dword [rel dhcp_fo_ct_rej]          ; aggregate (KAT-guarded delta stays 5)
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

; dhcp_parse_offer(RDI=frame, ESI=len) -> RAX = 0 ok / -1 reject.
;   Validates the frame, requires op=BOOTREPLY(2) and msg-type opt53=OFFER(2),
;   then captures xid, yiaddr, and server-id(opt54) into the parsed-state vars.
;   A zero yiaddr (bogus offer) is rejected so no all-zero REQUEST is built.
;
;   TOURNAMENT 1410 (MOST-DURABLE variant): the shipped baseline made THREE passes
;   (dhcp_validate + two dhcp_find_option re-walks) AND — the durability hole this
;   variant closes — committed dhcp_parsed_xid/yiaddr to the SHARED parsed state
;   BEFORE it had proven opt54 (server-id) was present. A well-formed OFFER that is
;   missing opt54 therefore left CORRUPT partial state behind even though the call
;   returned -1: a later dhcp_build_request would echo the bogus xid/yiaddr of a
;   rejected frame. This re-implements it as ONE bounds-checked pass (envelope PORTED
;   verbatim from dhcp_find_option's proven walk: len/magic gate, absurd-len +
;   address-wrap containment, per-TLV in-frame length check, END-stop, PAD-skip)
;   with two additive durability guarantees:
;     (1) ATOMIC COMMIT — nothing is written to the shared dhcp_parsed_* vars until
;         EVERY required field (opt53==OFFER, non-zero yiaddr, opt54) has passed.
;         A rejected frame NEVER perturbs the parsed state (no torn writes).
;     (2) OBSERVABLE CONTAINMENT — every hostile/malformed argument is contained as a
;         clean -1 (never a fault): NULL frame, len too short, an ABSURD len (caller
;         bug / negative-as-unsigned — rejected BEFORE the walk so no giant OOB scan
;         can #PF the box), a frame+len that wraps the address space, a bad magic
;         cookie, a wrong op, a missing/non-OFFER opt53, a zero yiaddr, a missing
;         opt54. Each reject records its DISTINCT reason (a per-reason sub-counter +
;         a live last-reason code) and a success bumps an ok counter, so a peer's
;         exact malformation is visible after the fact and the KAT can delta-check
;         the telemetry itself.
;   Same inputs -> BYTE-IDENTICAL outputs vs the baseline for every legal frame
;   (KAT-gated). clobbers: volatiles; preserves rbx,r12-r15 (saved).
; reject reason codes — stored live in dhcp_po_last_rej for post-hoc peer diagnosis.
; KEEP 1..9 CONTIGUOUS (the shared .rej indexes the per-reason counter block by them).
PO_REJ_NULL     equ 1          ; NULL frame pointer
PO_REJ_SHORT    equ 2          ; len too short for BOOTP header + cookie
PO_REJ_TOOBIG   equ 3          ; absurd len contained before the walk
PO_REJ_WRAP     equ 4          ; frame+len wrapped the address space
PO_REJ_MAGIC    equ 5          ; bad magic cookie
PO_REJ_OP       equ 6          ; op != BOOTREPLY
PO_REJ_MSGTYPE  equ 7          ; opt53 missing or != OFFER
PO_REJ_YIADDR   equ 8          ; zero offered address
PO_REJ_SERVERID equ 9          ; opt54 (server-id) missing
dhcp_parse_offer:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; ---- containment envelope (distinct, counted reject reasons; ported from
    ;      dhcp_find_option — contain BEFORE any field read so nothing can #PF) ----
    test rdi, rdi
    jz   .rej_null                           ; NULL frame -> contained, no deref
    cmp  esi, DHCP_OPTIONS
    jb   .rej_short                          ; too short for header + cookie
    cmp  esi, DHCP_FO_MAXLEN
    ja   .rej_toobig                         ; absurd len -> contain BEFORE the walk
    mov  rbx, rdi                            ; frame base
    mov  rdi, rbx
    mov  esi, esi                            ; explicit zero-extension of wire length
    call safe_checked_add
    test edx, edx
    jnz  .rej_wrap
    mov  r11, rax                            ; end-of-frame ptr (one past last byte)
    cmp  dword [rbx + DHCP_MAGIC], DHCP_MAGIC_LE
    jne  .rej_magic                          ; bad magic cookie
    cmp  byte [rbx + DHCP_OP], 2             ; BOOTREPLY
    jne  .rej_op
    ; ---- single bounds-checked pass: collect opt53 + opt54 (first-occurrence-wins) ----
    lea  r10, [rbx + DHCP_OPTIONS]           ; option cursor
    xor  r12d, r12d                          ; opt53 (msg-type)  value ptr, 0 = unseen
    xor  r13d, r13d                          ; opt54 (server-id) value ptr, 0 = unseen
.walk:
    cmp  r10, r11
    jae  .collected                          ; ran off the end -> stop
    movzx eax, byte [r10]                    ; tag
    cmp  al, OPT_END
    je   .collected                          ; end of options
    cmp  al, OPT_PAD
    je   .pad                                ; pad -> single byte, no length
    mov  rax, r11
    sub  rax, r10
    cmp  rax, 2
    jb   .rej_msgtype                        ; malformed tail cannot validate an OFFER
    mov  rdi, r10
    mov  rsi, r11
    call safe_tlv_u8_view                    ; read-once length + remaining check
    test eax, eax
    jnz  .rej_msgtype                        ; reject, never accept a valid-looking prefix
    mov  r9, rdi                             ; validated value pointer
    mov  r8, rsi                             ; validated next option
    mov  eax, edx                            ; tag
    cmp  al, OPT_MSGTYPE
    jne  .not53
    cmp  ecx, 1
    jne  .rej_msgtype                        ; fixed-width option 53
    test r12, r12
    jnz  .adv
    mov  r12, r9
    jmp  .adv
.not53:
    cmp  al, OPT_SERVERID
    jne  .adv
    cmp  ecx, 4
    jne  .rej_serverid                       ; fixed-width option 54
    test r13, r13
    jnz  .adv
    mov  r13, r9
.adv:
    mov  r10, r8                             ; advance to the next option
    jmp  .walk
.pad:
    inc  r10
    jmp  .walk
.collected:
    ; ---- required-field gate (checks ONLY temporaries — nothing committed yet) ----
    test r12, r12
    jz   .rej_msgtype                         ; no opt53
    cmp  byte [r12], MSG_OFFER                ; opt53 must be a DHCPOFFER
    jne  .rej_msgtype
    mov  r14d, [rbx + DHCP_YIADDR]            ; offered address (temp)
    test r14d, r14d
    jz   .rej_yiaddr                          ; zero yiaddr (bogus offer) -> reject
    test r13, r13
    jz   .rej_serverid                        ; opt54 required (baseline corrupted here)
    ; ---- ATOMIC COMMIT: every check passed -> now (and only now) touch shared state ----
    mov  eax, [rbx + DHCP_XID]
    mov  [rel dhcp_parsed_xid], eax
    mov  [rel dhcp_parsed_yiaddr], r14d
    mov  eax, [r13]
    mov  [rel dhcp_parsed_serverid], eax
    inc  dword [rel dhcp_po_ct_ok]
    xor  rax, rax
    jmp  .out
    ; --- contained rejects: each records its DISTINCT reason, then the shared .rej
    ;     bumps the aggregate + per-reason counter and returns a clean -1 (faults
    ;     nothing, leaves dhcp_parsed_* untouched). ---
.rej_null:
    mov  r15d, PO_REJ_NULL
    jmp  .rej
.rej_short:
    mov  r15d, PO_REJ_SHORT
    jmp  .rej
.rej_toobig:
    mov  r15d, PO_REJ_TOOBIG
    jmp  .rej
.rej_wrap:
    mov  r15d, PO_REJ_WRAP
    jmp  .rej
.rej_magic:
    mov  r15d, PO_REJ_MAGIC
    jmp  .rej
.rej_op:
    mov  r15d, PO_REJ_OP
    jmp  .rej
.rej_msgtype:
    mov  r15d, PO_REJ_MSGTYPE
    jmp  .rej
.rej_yiaddr:
    mov  r15d, PO_REJ_YIADDR
    jmp  .rej
.rej_serverid:
    mov  r15d, PO_REJ_SERVERID
    ; fall through to the shared reject epilogue
.rej:
    inc  dword [rel dhcp_po_ct_rej]           ; aggregate reject counter
    mov  [rel dhcp_po_last_rej], r15d         ; live last-reason code (1..9)
    lea  rcx, [rel dhcp_po_rej_null]          ; base of the 9 contiguous reason counters
    mov  eax, r15d
    dec  eax                                  ; reason 1..9 -> index 0..8
    inc  dword [rcx + rax*4]
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dhcp_build_request(RDI=dst) -> EAX = request length.
;   Builds a DHCPREQUEST from the parsed-OFFER state: op=BOOTREQUEST, echoed xid,
;   magic cookie, opt53=REQUEST(3), opt50=offered-yiaddr, opt54=server-id, end.
;   clobbers: volatiles; preserves rbx (saved).
dhcp_build_request:
    push rbx
    mov  rbx, rdi                            ; dst base
    ; zero the BOOTP header + cookie slot (240 bytes)
    xor  esi, esi
    mov  edx, DHCP_OPTIONS
    call memset                              ; memset(rdi=dst, 0, 240); rbx preserved
    mov  byte [rbx + DHCP_OP], 1             ; BOOTREQUEST
    mov  byte [rbx + 1], 1                   ; htype = Ethernet
    mov  byte [rbx + 2], 6                   ; hlen  = 6
    ; hops(3) stays 0
    mov  eax, [rel dhcp_parsed_xid]          ; echo the OFFER's xid
    mov  [rbx + DHCP_XID], eax
    mov  dword [rbx + DHCP_MAGIC], DHCP_MAGIC_LE
    lea  rcx, [rbx + DHCP_OPTIONS]           ; option write cursor
    ; opt53: message type = REQUEST(3)
    mov  byte [rcx + 0], OPT_MSGTYPE
    mov  byte [rcx + 1], 1
    mov  byte [rcx + 2], MSG_REQUEST
    add  rcx, 3
    ; opt55: the DISCOVER's parameter-request list (servers answer the ACK from it)
    mov  byte [rcx + 0], OPT_PRL
    mov  byte [rcx + 1], 5
    mov  byte [rcx + 2], OPT_SUBNET
    mov  byte [rcx + 3], OPT_ROUTER
    mov  byte [rcx + 4], OPT_DNS
    mov  byte [rcx + 5], 51
    mov  byte [rcx + 6], OPT_NTP
    add  rcx, 7
    ; opt50: Requested-IP = offered yiaddr (echo)
    mov  byte [rcx + 0], OPT_REQIP
    mov  byte [rcx + 1], 4
    mov  eax, [rel dhcp_parsed_yiaddr]
    mov  [rcx + 2], eax
    add  rcx, 6
    ; opt54: server identifier (echo)
    mov  byte [rcx + 0], OPT_SERVERID
    mov  byte [rcx + 1], 4
    mov  eax, [rel dhcp_parsed_serverid]
    mov  [rcx + 2], eax
    add  rcx, 6
    ; end option
    mov  byte [rcx], OPT_END
    inc  rcx
    mov  rax, rcx
    sub  rax, rbx                            ; length = cursor - base
    pop  rbx
    ret

; dhcp_parse_ack(RDI=frame, ESI=len) -> RAX = 0 ok / -1 reject.
;   Validates, requires op=BOOTREPLY(2) and opt53=ACK(5), then captures the lease
;   yiaddr + mask(opt1) + gw(opt3) + dns(opt6) + lease/T1/T2 (51/58/59).
;   RCQ-10 S2: opt3 and opt6 are optional (RFC 2132 3.5, 3.8). An absent router is
;   gw=0 (on-link only), an absent resolver is dns=0; a present but short one is
;   still malformed and rejected.
;   Clock unit (ROOT 122029): the first opt42 offers its first NTP server
;   (dhcp_ack_ntp_v). A zero or partial length refuses the ACK like opt3/opt6;
;   an absent or non-unicast first address (0/8, 127/8, 224/4, 240/4,
;   broadcast; SEC 122036 T3) offers none (0). It is committed with the lease
;   in the same atomic block.
;   clobbers: volatiles; saves rbx,r12-r15.
;
;   TOURNAMENT 1407 (FASTEST variant): the shipped baseline made FIVE passes over the
;   frame — dhcp_validate + FOUR full dhcp_find_option walks (each re-walking the TLV
;   area from offset 240, so the 4th option costs a 4-TLV re-scan). This re-implements
;   it as ONE bounds-checked pass that collects opt53/1/3/6 in a single sweep: same
;   inputs -> BYTE-IDENTICAL outputs (KAT-gated), fewer memory reads, zero repeated
;   call overhead. The bounds envelope is PORTED verbatim from dhcp_find_option's proven
;   walk (len/magic gate, absurd-len + address-wrap containment, per-TLV in-frame length
;   check, END-stop, PAD-skip) — improved additively (one pass, not four), never a
;   from-scratch reinvention. First-occurrence-wins per tag, matching find_option.
dhcp_parse_ack:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 72                            ; option pointers + atomic commit scratch
    mov  qword [rsp + 0], 0
    mov  qword [rsp + 8], 0
    mov  qword [rsp + 16], 0
    mov  qword [rsp + 56], 0                ; first opt42 pointer (clock unit)
    ; --- validate: op=BOOTREPLY + len>=240 + magic cookie (ported from dhcp_validate) ---
    test rdi, rdi
    jz   .bad                                ; reject before the first frame read
    cmp  esi, DHCP_OPTIONS
    jb   .bad                                ; too short for BOOTP header + cookie
    cmp  esi, DHCP_FO_MAXLEN
    ja   .bad                                ; absurd len -> contain BEFORE the walk
    mov  rbx, rdi                            ; frame base
    mov  rdi, rbx
    mov  esi, esi                            ; explicit zero-extension of wire length
    call safe_checked_add
    test edx, edx
    jnz  .bad
    mov  r11, rax                            ; end-of-frame ptr (one past last byte)
    ; Complete the size/wrap envelope BEFORE any caller-frame dereference.
    cmp  dword [rbx + DHCP_MAGIC], DHCP_MAGIC_LE
    jne  .bad
    cmp  byte [rbx + DHCP_OP], 2             ; BOOTREPLY
    jne  .bad
    lea  r10, [rbx + DHCP_OPTIONS]           ; option cursor
    xor  r12d, r12d                          ; opt53 (msg-type) value ptr, 0 = unseen
    xor  r13d, r13d                          ; opt1  (subnet)   value ptr
    xor  r14d, r14d                          ; opt3  (router)   value ptr
    xor  r15d, r15d                          ; opt6  (dns)      value ptr
.walk:
    cmp  r10, r11
    jae  .collected                          ; ran off the end -> stop
    movzx eax, byte [r10]                    ; tag
    cmp  al, OPT_END
    je   .collected                          ; end of options
    cmp  al, OPT_PAD
    je   .pad                                ; pad -> single byte, no length
    mov  rax, r11
    sub  rax, r10
    cmp  rax, 2
    jb   .bad                                ; malformed tail cannot validate an ACK
    mov  rdi, r10
    mov  rsi, r11
    call safe_tlv_u8_view                    ; read-once length + remaining check
    test eax, eax
    jnz  .bad                                ; reject, never accept a valid-looking prefix
    mov  r9, rdi                             ; validated value pointer
    mov  r8, rsi                             ; validated next option
    mov  eax, edx                            ; tag
    ; Record the seven tags we need (first occurrence wins, like
    ; dhcp_find_option). Fixed scalars have exact widths; router/resolver lists
    ; contain complete IPv4 addresses. Check even duplicate tags before saving
    ; pointers, so malformed options cannot publish a valid-looking prefix.
    cmp  al, OPT_MSGTYPE
    jne  .not53
    cmp  ecx, 1
    jne  .bad                               ; malformed fixed-width option 53
    test r12, r12
    jnz  .adv
    mov  r12, r9
    jmp  .adv
.not53:
    cmp  al, OPT_SUBNET
    jne  .not1
    cmp  ecx, 4
    jne  .bad                               ; subnet is exactly one IPv4 mask
    test r13, r13
    jnz  .adv
    mov  r13, r9
    jmp  .adv
.not1:
    cmp  al, OPT_ROUTER
    jne  .not3
    cmp  ecx, 4
    jb   .bad                               ; cannot supply even the first router
    test ecx, 3
    jnz  .bad                               ; no partial address at the list tail
    test r14, r14
    jnz  .adv
    mov  r14, r9
    jmp  .adv
.not3:
    cmp  al, OPT_DNS
    jne  .not6
    cmp  ecx, 4
    jb   .bad                               ; cannot supply even the first resolver
    test ecx, 3
    jnz  .bad                               ; no partial address at the list tail
    test r15, r15
    jnz  .adv
    mov  r15, r9
    jmp  .adv
.not6:
    cmp  al, OPT_LEASE
    jne  .not51
    cmp  ecx, 4
    jne  .bad                               ; fixed-width seconds scalar
    cmp  qword [rsp + 0], 0
    jne  .adv
    mov  [rsp + 0], r9
    jmp  .adv
.not51:
    cmp  al, OPT_T1
    jne  .not58
    cmp  ecx, 4
    jne  .bad                               ; fixed-width seconds scalar
    cmp  qword [rsp + 8], 0
    jne  .adv
    mov  [rsp + 8], r9
    jmp  .adv
.not58:
    cmp  al, OPT_NTP
    jne  .not42
    ; Clock unit (ROOT 122029, SEC 122036 T3): an address list like 3/6. A
    ; zero or partial length refuses the ACK; the FIRST option 42 decides, and
    ; a later duplicate cannot replace it.
    cmp  ecx, 4
    jb   .bad                               ; cannot supply even the first server
    test ecx, 3
    jnz  .bad                               ; no partial address at the list tail
    cmp  qword [rsp + 56], 0
    jne  .adv
    mov  [rsp + 56], r9
    jmp  .adv
.not42:
    cmp  al, OPT_T2
    jne  .adv
    cmp  ecx, 4
    jne  .bad                               ; fixed-width seconds scalar
    cmp  qword [rsp + 16], 0
    jne  .adv
    mov  [rsp + 16], r9
.adv:
    mov  r10, r8                             ; advance to the next option
    jmp  .walk
.pad:
    inc  r10
    jmp  .walk
.collected:
    ; --- require msg-type ACK, a non-zero lease and the mask; router/DNS optional ---
    test r12, r12
    jz   .bad                                ; no opt53
    cmp  byte [r12], MSG_ACK                 ; must be a DHCPACK
    jne  .bad
    mov  eax, [rbx + DHCP_YIADDR]            ; lease yiaddr
    test eax, eax
    jz   .bad
    mov  [rsp + 24], eax                     ; stage; no retained state until all pass
    test r13, r13
    jz   .bad                                ; opt1 subnet mask required
    mov  eax, [r13]
    mov  [rsp + 28], eax
    xor  eax, eax                            ; RCQ-10 S2: no opt3 = no router (on-link only)
    test r14, r14
    jz   .gw_staged
    mov  eax, [r14]
.gw_staged:
    mov  [rsp + 32], eax
    xor  eax, eax                            ; RCQ-10 S2: no opt6 = no resolver offered
    test r15, r15
    jz   .dns_staged
    mov  eax, [r15]
.dns_staged:
    mov  [rsp + 36], eax
    xor  eax, eax                            ; no opt42 = no NTP server offered
    mov  rdx, [rsp + 56]
    test rdx, rdx
    jz   .ntp_staged
    mov  eax, [rdx]                          ; wire order: AL = first octet
    test al, al                              ; 0/8 is not a server
    jz   .ntp_none
    cmp  al, 127                             ; loopback
    je   .ntp_none
    cmp  al, 224                             ; 224/4 multicast, 240/4 and broadcast
    jb   .ntp_staged
.ntp_none:
    xor  eax, eax                            ; SEC T3: unicast only, else no server
.ntp_staged:
    mov  [rsp + 64], eax

    ; Lease clocks are host-order seconds. RFC 2131 defaults T1 to 1/2 and T2
    ; to 7/8 of the lease when the server omits them. Refuse nonsensical server
    ; clocks by folding them back to those bounded defaults.
    mov  rdx, [rsp + 0]
    mov  eax, 3600                          ; conservative one-hour default
    test rdx, rdx
    jz   .lease_ready
    mov  eax, [rdx]
    bswap eax
    test eax, eax
    jnz  .lease_ready
    mov  eax, 3600
.lease_ready:
    mov  [rsp + 40], eax
    mov  ecx, eax
    shr  ecx, 1                            ; default T1 = lease/2
    mov  rdx, [rsp + 8]
    test rdx, rdx
    jz   .t1_ready
    mov  edx, [rdx]
    bswap edx
    test edx, edx
    jz   .t1_ready
    cmp  edx, eax
    jae  .t1_ready                         ; T1 must precede expiry
    mov  ecx, edx
.t1_ready:
    mov  [rsp + 44], ecx
    mov  edx, eax
    shr  edx, 3
    sub  edx, eax
    neg  edx                               ; default T2 = lease - lease/8
    mov  r8, [rsp + 16]
    test r8, r8
    jz   .t2_ready
    mov  r8d, [r8]
    bswap r8d
    cmp  r8d, ecx
    jbe  .t2_ready                         ; T2 must follow T1
    cmp  r8d, eax
    jae  .t2_ready                         ; and precede expiry
    mov  edx, r8d
.t2_ready:
    ; An omitted/rejected T2 uses the default, which may precede a valid late
    ; server T1. Normalize the pair before arming clocks; coherent overrides stay.
    cmp  edx, ecx
    ja   .timers_ready
    mov  ecx, eax
    shr  ecx, 1                            ; restore half-lease T1 with default T2
    mov  [rsp + 44], ecx
.timers_ready:
    mov  [rsp + 48], edx
    ; All required options and derived clocks are now valid. Commit the staged
    ; lease as one failure-atomic block so every reject leaves prior state intact.
    mov  eax, [rsp + 24]
    mov  [rel dhcp_ack_yiaddr], eax
    mov  eax, [rsp + 28]
    mov  [rel dhcp_ack_mask_v], eax
    mov  eax, [rsp + 32]
    mov  [rel dhcp_ack_gw_v], eax
    mov  eax, [rsp + 36]
    mov  [rel dhcp_ack_dns_v], eax
    mov  eax, [rsp + 40]
    mov  [rel dhcp_ack_lease_s], eax
    mov  eax, [rsp + 44]
    mov  [rel dhcp_ack_t1_s], eax
    mov  eax, [rsp + 48]
    mov  [rel dhcp_ack_t2_s], eax
    mov  eax, [rsp + 64]
    mov  [rel dhcp_ack_ntp_v], eax
    xor  rax, rax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    add  rsp, 72
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; TOURNAMENT 1407 — dhcp_parse_ack known-answer test (FASTEST variant gate).
; Drives the SINGLE-PASS dhcp_parse_ack and content-grades it byte-for-byte so a
; fast-but-wrong parser scores 0:
;   * POSITIVE — the canned DHCPACK parses (RAX==0) and the four lease fields it
;     wrote are bit-exact: yiaddr=192.0.2.150, mask=255.255.255.0,
;     gw=192.0.2.1, dns=8.8.8.8 (read straight out of the live dhcp_ack_* vars).
;   * 3 CONTAINED REJECTS (each MUST return -1, no fault, boot continues):
;       (a) bad magic cookie  (dhcp_badframe, 240B, wrong cookie)
;       (b) short frame       (the ACK truncated to 100B, below the header)
;       (c) wrong msg-type    (the canned OFFER — valid frame, opt53=OFFER not ACK)
;   * OPTIONAL OPTION (RCQ-10 S2) — an ACK with opt53/1/3 and NO opt6 DNS parses
;     (RAX==0) with dns=0 and the router it carries; the KAT no longer rejects it.
; PASS prints the read-back lease line + earns [tourn.dhcp_parse_ack.kat]
; [tourn.dhcp_parse_ack.guard]; any mismatch prints the failing step id + the .fail
; marker and boot CONTINUES (degrade, never crash). The positive is re-run LAST so
; the shipped dhcp_ack_* state is left clean for anything downstream.
; clobbers: volatiles; preserves rbx,r12-r15 (saved).
dhcp_parse_ack_kat:
    lea  rax, [rel .isolated]                ; RCQ-10 S3: never over a live lease
    jmp  dhcp_kat_isolated
.isolated:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; ---- (a) bad magic cookie -> reject ----
    mov  r15d, 1
    lea  rdi, [rel dhcp_badframe]
    mov  esi, DHCP_BADFRAME_LEN
    call dhcp_parse_ack
    cmp  rax, -1
    jne  .fail
    ; ---- (b) short frame (< 240) -> reject ----
    mov  r15d, 2
    lea  rdi, [rel dhcp_ack]
    mov  esi, 100
    call dhcp_parse_ack
    cmp  rax, -1
    jne  .fail
    ; ---- (c) wrong msg-type: the OFFER (opt53=OFFER, not ACK) -> reject ----
    mov  r15d, 3
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    call dhcp_parse_ack
    cmp  rax, -1
    jne  .fail
    ; ---- (d) RCQ-10 S2: no opt6 DNS -> a lease with no resolver, not a reject ----
    mov  r15d, 4
    lea  rdi, [rel dhcp_ack_nodns]
    mov  esi, DHCP_ACK_NODNS_LEN
    call dhcp_parse_ack
    test rax, rax
    jnz  .fail
    cmp  dword [rel dhcp_ack_dns_v], 0
    jne  .fail
    cmp  dword [rel dhcp_ack_gw_v], 0x010200c0
    jne  .fail
    ; ---- POSITIVE (run LAST so dhcp_ack_* is left holding the good lease) ----
    mov  r15d, 5
    lea  rdi, [rel dhcp_ack]
    mov  esi, DHCP_ACK_LEN
    call dhcp_parse_ack
    test rax, rax
    jnz  .fail                               ; a valid ACK must parse (0)
    mov  r15d, 6                             ; yiaddr == 192.0.2.150
    cmp  dword [rel dhcp_ack_yiaddr], 0x960200c0
    jne  .fail
    mov  r15d, 7                             ; mask == 255.255.255.0
    cmp  dword [rel dhcp_ack_mask_v], 0x00FFFFFF
    jne  .fail
    mov  r15d, 8                             ; gw == 192.0.2.1
    cmp  dword [rel dhcp_ack_gw_v], 0x010200c0
    jne  .fail
    mov  r15d, 9                             ; dns == 8.8.8.8
    cmp  dword [rel dhcp_ack_dns_v], 0x08080808
    jne  .fail
    ; ---- all checks passed: print the read-back lease + earn the markers ----
    lea  rdi, [rel str_dhcp_pa_pre]
    call serial_string
    lea  rsi, [rel dhcp_ack_yiaddr]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_ack_mask]
    call serial_string
    lea  rsi, [rel dhcp_ack_mask_v]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_ack_gw]
    call serial_string
    lea  rsi, [rel dhcp_ack_gw_v]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_ack_dns]
    call serial_string
    lea  rsi, [rel dhcp_ack_dns_v]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_pa_post]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_dhcp_pa_fail]
    call serial_string
    mov  eax, r15d
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_crlf]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; TOURNAMENT 1410 — dhcp_parse_offer known-answer test (MOST-DURABLE variant gate).
; Drives the atomic single-pass dhcp_parse_offer and content-grades it three ways so a
; fast-but-wrong OR a state-corrupting variant scores 0:
;   * POSITIVE — the canned DHCPOFFER parses (RAX==0) and the three captured vars are
;     bit-exact: parsed_xid=0x26F30339 (wire 39 03 f3 26), parsed_yiaddr=192.0.2.150,
;     parsed_serverid=192.0.2.1 (read straight out of the live dhcp_parsed_* vars).
;   * 9 CONTAINED REJECTS — one per DISTINCT reason (each returns -1, faults nothing):
;       null(1), short(2), toobig(3), magic(5), op(6), msgtype-missing(7),
;       msgtype-wrong(7), yiaddr(8), serverid(9). Every reject's live last-reason code
;       is asserted, and the per-reason + ok counters are delta-checked to the EXACT
;       mix the vectors injected — so the observability seam is itself correctness-gated.
;       (wrap(4) cannot be crafted from a static frame; implemented + contained, count 0.)
;   * ATOMICITY — the two DEEP rejects (a valid OFFER missing opt54; a valid OFFER with
;     a zero yiaddr) get PAST validate/op/opt53, exactly where the baseline committed
;     partial state. After each, dhcp_parsed_xid/yiaddr/serverid MUST still equal the
;     good OFFER snapshot — proving a rejected frame never perturbs shared state.
; PASS emits [tourn.dhcp_parse_offer.kat] (positive+rejects), [tourn.dhcp_parse_offer.guard]
; (counter deltas exact) and [tourn.dhcp_parse_offer.atomic] (no torn writes). Any
; mismatch prints the failing step id + the .fail marker and boot CONTINUES (degrade,
; never crash). The positive is re-run implicitly at the start so the shipped
; dhcp_parsed_* state is left holding the good OFFER for anything downstream.
; clobbers: volatiles; preserves rbx,r12-r15 (saved).
dhcp_parse_offer_kat:
    lea  rax, [rel .isolated]                ; RCQ-10 S3: never over a live lease
    jmp  dhcp_kat_isolated
.isolated:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; ---- snapshot the live counters (delta-checked at the end; NEVER reset — a
    ;      selftest must not destroy telemetry that booted before it) ----
    mov  eax, [rel dhcp_po_ct_ok]
    mov  [rel dhcp_po_kat_c0], eax
    mov  eax, [rel dhcp_po_ct_rej]
    mov  [rel dhcp_po_kat_c0 + 4], eax
    lea  rbx, [rel dhcp_po_rej_null]         ; base of the 9 contiguous reason counters
    lea  r14, [rel dhcp_po_kat_r0]
    xor  ecx, ecx
.snap_r:
    mov  eax, [rbx + rcx*4]
    mov  [r14 + rcx*4], eax
    inc  ecx
    cmp  ecx, 9
    jb   .snap_r

    ; ---- POSITIVE (run FIRST so dhcp_parsed_* holds the good OFFER for the atomicity
    ;      checks + for anything downstream) ----
    mov  r15d, 1
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    call dhcp_parse_offer
    test rax, rax
    jnz  .fail                               ; a valid OFFER must parse (0)
    mov  r15d, 2                             ; xid (wire 39 03 f3 26, LE) == 0x26F30339
    cmp  dword [rel dhcp_parsed_xid], 0x26F30339
    jne  .fail
    mov  r15d, 3                             ; yiaddr == 192.0.2.150
    cmp  dword [rel dhcp_parsed_yiaddr], 0x960200c0
    jne  .fail
    mov  r15d, 4                             ; server-id == 192.0.2.1
    cmp  dword [rel dhcp_parsed_serverid], 0x010200c0
    jne  .fail
    ; save the good parsed state — the atomicity checks assert it stays byte-identical
    mov  eax, [rel dhcp_parsed_xid]
    mov  [rel dhcp_po_kat_good], eax
    mov  eax, [rel dhcp_parsed_yiaddr]
    mov  [rel dhcp_po_kat_good + 4], eax
    mov  eax, [rel dhcp_parsed_serverid]
    mov  [rel dhcp_po_kat_good + 8], eax

    ; ---- CONTAINED REJECTS (each -1, live last-reason asserted) ----
    mov  r15d, 10                            ; NULL frame -> reason NULL(1)
    xor  edi, edi
    mov  esi, 300
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_NULL
    jne  .fail

    mov  r15d, 11                            ; short frame (<240) -> reason SHORT(2)
    lea  rdi, [rel dhcp_offer]
    mov  esi, 100
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_SHORT
    jne  .fail

    mov  r15d, 12                            ; absurd len (256 MiB) -> reason TOOBIG(3)
    lea  rdi, [rel dhcp_offer]
    mov  esi, 0x10000000
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_TOOBIG
    jne  .fail

    mov  r15d, 13                            ; bad magic cookie -> reason MAGIC(5)
    lea  rdi, [rel dhcp_badframe]
    mov  esi, DHCP_BADFRAME_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_MAGIC
    jne  .fail

    mov  r15d, 14                            ; op != BOOTREPLY -> reason OP(6)
    lea  rdi, [rel dhcp_offer_badop]
    mov  esi, DHCP_OFFER_BADOP_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_OP
    jne  .fail

    mov  r15d, 15                            ; opt53 MISSING -> reason MSGTYPE(7)
    lea  rdi, [rel dhcp_offer_no53]
    mov  esi, DHCP_OFFER_NO53_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_MSGTYPE
    jne  .fail

    mov  r15d, 16                            ; opt53 present but == ACK, not OFFER -> MSGTYPE(7)
    lea  rdi, [rel dhcp_ack]
    mov  esi, DHCP_ACK_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_MSGTYPE
    jne  .fail

    ; ---- DEEP reject A: valid OFFER, zero yiaddr -> reason YIADDR(8) + ATOMICITY ----
    mov  r15d, 17
    lea  rdi, [rel dhcp_offer_zeroyi]
    mov  esi, DHCP_OFFER_ZEROYI_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_YIADDR
    jne  .fail
    mov  r15d, 18                            ; parsed_* UNCHANGED (no torn write)
    mov  eax, [rel dhcp_parsed_xid]
    cmp  eax, [rel dhcp_po_kat_good]
    jne  .fail
    mov  eax, [rel dhcp_parsed_yiaddr]
    cmp  eax, [rel dhcp_po_kat_good + 4]
    jne  .fail
    mov  eax, [rel dhcp_parsed_serverid]
    cmp  eax, [rel dhcp_po_kat_good + 8]
    jne  .fail

    ; ---- DEEP reject B: valid OFFER, opt53=OFFER, non-zero yiaddr, NO opt54 ->
    ;      reason SERVERID(9) + ATOMICITY (this is the exact spot the baseline
    ;      corrupted parsed_xid/yiaddr before discovering opt54 was missing) ----
    mov  r15d, 19
    lea  rdi, [rel dhcp_offer_no54]
    mov  esi, DHCP_OFFER_NO54_LEN
    call dhcp_parse_offer
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel dhcp_po_last_rej], PO_REJ_SERVERID
    jne  .fail
    mov  r15d, 20                            ; parsed_* STILL the good OFFER
    mov  eax, [rel dhcp_parsed_xid]
    cmp  eax, [rel dhcp_po_kat_good]
    jne  .fail
    mov  eax, [rel dhcp_parsed_yiaddr]
    cmp  eax, [rel dhcp_po_kat_good + 4]
    jne  .fail
    mov  eax, [rel dhcp_parsed_serverid]
    cmp  eax, [rel dhcp_po_kat_good + 8]
    jne  .fail

    ; ---- GUARD: the counters must have moved by EXACTLY the injected mix ----
    mov  r15d, 30                            ; ok delta == 1 (one positive parse)
    mov  eax, [rel dhcp_po_ct_ok]
    sub  eax, [rel dhcp_po_kat_c0]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 31                            ; aggregate rej delta == 9
    mov  eax, [rel dhcp_po_ct_rej]
    sub  eax, [rel dhcp_po_kat_c0 + 4]
    cmp  eax, 9
    jne  .fail
    ; per-reason deltas: null1 short1 toobig1 wrap0 magic1 op1 msgtype2 yiaddr1 serverid1
    mov  r15d, 32
    mov  eax, [rel dhcp_po_rej_null]
    sub  eax, [rel dhcp_po_kat_r0 + 0]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 33
    mov  eax, [rel dhcp_po_rej_short]
    sub  eax, [rel dhcp_po_kat_r0 + 4]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 34
    mov  eax, [rel dhcp_po_rej_toobig]
    sub  eax, [rel dhcp_po_kat_r0 + 8]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 35                            ; wrap == 0 (implemented, not crafted)
    mov  eax, [rel dhcp_po_rej_wrap]
    sub  eax, [rel dhcp_po_kat_r0 + 12]
    cmp  eax, 0
    jne  .fail
    mov  r15d, 36
    mov  eax, [rel dhcp_po_rej_magic]
    sub  eax, [rel dhcp_po_kat_r0 + 16]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 37
    mov  eax, [rel dhcp_po_rej_op]
    sub  eax, [rel dhcp_po_kat_r0 + 20]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 38                            ; msgtype == 2 (missing + wrong)
    mov  eax, [rel dhcp_po_rej_msgtype]
    sub  eax, [rel dhcp_po_kat_r0 + 24]
    cmp  eax, 2
    jne  .fail
    mov  r15d, 39
    mov  eax, [rel dhcp_po_rej_yiaddr]
    sub  eax, [rel dhcp_po_kat_r0 + 28]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 40
    mov  eax, [rel dhcp_po_rej_serverid]
    sub  eax, [rel dhcp_po_kat_r0 + 32]
    cmp  eax, 1
    jne  .fail

    ; ---- all checks passed: print the read-back OFFER line + earn the 3 markers ----
    lea  rdi, [rel str_dhcp_po_pre]
    call serial_string
    lea  rsi, [rel dhcp_parsed_yiaddr]
    call dhcp_print_ip
    lea  rdi, [rel str_dhcp_po_post]
    call serial_string
    lea  rdi, [rel str_dhcp_po_guard]
    call serial_string
    lea  rdi, [rel str_dhcp_po_atomic]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_dhcp_po_fail]
    call serial_string
    mov  eax, r15d
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_crlf]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; TOURNAMENT 1307 — dhcp_find_option known-answer test (most-durable variant).
; dhcp_find_option_kat: 18 vectors through the REAL walk, three outcome classes:
;   * 8 bit-exact FINDS  — every option class in the canned OFFER (53/54/1/3/6,
;     values compared byte-for-byte) + the edge frames: option after a pad run,
;     a zero-length option (value ptr position-checked), an option flush against
;     the exact frame end with no END terminator.
;   * 5 clean MISSES     — absent tag, searching for END, searching for PAD, a
;     TLV hidden BEHIND the END terminator (END-stop), ran-off-end.
;   * 5 contained REJECTS — NULL frame, len=0, len=240 (no option space), a
;     declared length running past the frame (truncation), a tag with no length
;     byte as the last frame byte. All must return 0 with no fault.
; The find/miss/reject counters must move by EXACTLY (8,5,5) across the run —
; the observability seam is itself correctness-gated. PASS prints the deltas
; read back from the LIVE counters + earns [tourn.dhcp_find_option.kat]
; [tourn.dhcp_find_option.guard]; any mismatch prints the failing step id +
; the .fail marker and boot CONTINUES (degrade, never crash).
; clobbers: volatiles; preserves rbx,r12-r15 (saved).
dhcp_find_option_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; snapshot the live counters (delta-checked at the end; NOT reset — they are
    ; live telemetry and a selftest must not destroy what booted before it)
    mov  eax, [rel dhcp_fo_ct_find]
    mov  [rel dhcp_fo_kat_c0], eax
    mov  eax, [rel dhcp_fo_ct_miss]
    mov  [rel dhcp_fo_kat_c0 + 4], eax
    mov  eax, [rel dhcp_fo_ct_rej]
    mov  [rel dhcp_fo_kat_c0 + 8], eax
    ; snapshot the 7 per-reason reject counters too (delta-checked below; NEVER
    ; assume they start at zero — an earlier self-test may have moved them)
    lea  rbx, [rel dhcp_fo_rej_null]         ; base of the 7 contiguous reason counters
    lea  r14, [rel dhcp_fo_kat_r0]
    xor  ecx, ecx
.snap_r:
    mov  eax, [rbx + rcx*4]
    mov  [r14 + rcx*4], eax
    inc  ecx
    cmp  ecx, 7
    jb   .snap_r

    ; ---- FINDS in the canned OFFER (values compared byte-for-byte) ----
    mov  r15d, 1                             ; step 1: opt53 present, == OFFER(2)
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  byte [rax], MSG_OFFER
    jne  .fail

    mov  r15d, 2                             ; step 2: opt54 == 192.0.2.1
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_SERVERID
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  dword [rax], 0x010200c0             ; bytes 192,0,2,1 (wire order)
    jne  .fail

    mov  r15d, 3                             ; step 3: opt1 == 255.255.255.0
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_SUBNET
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  dword [rax], 0x00FFFFFF             ; bytes 255,255,255,0 (wire order)
    jne  .fail

    mov  r15d, 4                             ; step 4: opt3 == 192.0.2.1
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_ROUTER
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  dword [rax], 0x010200c0
    jne  .fail

    mov  r15d, 5                             ; step 5: opt6 == 8.8.8.8
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_DNS
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  dword [rax], 0x08080808
    jne  .fail

    ; ---- clean MISSES against the well-formed OFFER ----
    mov  r15d, 6                             ; step 6: absent tag -> 0
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, 42
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    mov  r15d, 7                             ; step 7: searching for END -> 0
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_END
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    mov  r15d, 8                             ; step 8: searching for PAD -> 0
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OFFER_LEN
    mov  edx, OPT_PAD
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    ; ---- contained REJECTS (hostile/malformed arguments; must not fault) ----
    mov  r15d, 9                             ; step 9: NULL frame -> 0, no deref
    xor  edi, edi
    mov  esi, 300
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    mov  r15d, 10                            ; step 10: len=0 -> 0, no read
    lea  rdi, [rel dhcp_offer]
    xor  esi, esi
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    mov  r15d, 11                            ; step 11: len=240 (no option space) -> 0
    lea  rdi, [rel dhcp_offer]
    mov  esi, DHCP_OPTIONS
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    ; ---- edge frame F1: pad run + zero-length option + END-stop ----
    mov  r15d, 12                            ; step 12: opt50 found after pads +
    lea  rdi, [rel dhcp_fo_f1]               ;          a zero-len TLV, value +
    mov  esi, DHCP_FO_F1_LEN                 ;          POSITION both exact
    mov  edx, OPT_REQIP
    call dhcp_find_option
    lea  rcx, [rel dhcp_fo_f1 + 247]         ; pads(3) + zero-len TLV(2) + t,l = 247
    cmp  rax, rcx
    jne  .fail
    cmp  dword [rax], 0x960200c0             ; bytes 192,0,2,150 (wire order)
    jne  .fail

    mov  r15d, 13                            ; step 13: zero-LENGTH option is found,
    lea  rdi, [rel dhcp_fo_f1]               ;          value ptr = its own end
    mov  esi, DHCP_FO_F1_LEN
    mov  edx, 7
    call dhcp_find_option
    lea  rcx, [rel dhcp_fo_f1 + 245]         ; pads(3) + tag,len -> value at +245
    cmp  rax, rcx
    jne  .fail

    mov  r15d, 14                            ; step 14: a TLV BEHIND the END
    lea  rdi, [rel dhcp_fo_f1]               ;          terminator stays invisible
    mov  esi, DHCP_FO_F1_LEN
    mov  edx, 99
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    ; ---- edge frame F2: declared length runs past the frame end ----
    mov  r15d, 15                            ; step 15: truncated option -> 0 (no OOB)
    lea  rdi, [rel dhcp_fo_f2]
    mov  esi, DHCP_FO_F2_LEN
    mov  edx, OPT_REQIP
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    ; ---- edge frame F3: tag as the LAST byte, no length byte ----
    mov  r15d, 16                            ; step 16: walks the leading TLV, then
    lea  rdi, [rel dhcp_fo_f3]               ;          contains the len-less tag
    mov  esi, DHCP_FO_F3_LEN
    mov  edx, OPT_REQIP
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    ; ---- edge frame F4: option flush against the exact frame end, no END ----
    mov  r15d, 17                            ; step 17: value ending AT the boundary
    lea  rdi, [rel dhcp_fo_f4]               ;          is still found
    mov  esi, DHCP_FO_F4_LEN
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  byte [rax], MSG_OFFER
    jne  .fail

    mov  r15d, 18                            ; step 18: absent tag on the END-less
    lea  rdi, [rel dhcp_fo_f4]               ;          frame -> clean ran-off-end 0
    mov  esi, DHCP_FO_F4_LEN
    mov  edx, OPT_SERVERID
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    ; ---- GUARD: the counters must have moved by EXACTLY (8,5,5) ----
    mov  r15d, 30                            ; step 30: find delta == 8
    mov  eax, [rel dhcp_fo_ct_find]
    sub  eax, [rel dhcp_fo_kat_c0]
    cmp  eax, 8
    jne  .fail
    mov  r15d, 31                            ; step 31: miss delta == 5
    mov  eax, [rel dhcp_fo_ct_miss]
    sub  eax, [rel dhcp_fo_kat_c0 + 4]
    cmp  eax, 5
    jne  .fail
    mov  r15d, 32                            ; step 32: reject delta == 5
    mov  eax, [rel dhcp_fo_ct_rej]
    sub  eax, [rel dhcp_fo_kat_c0 + 8]
    cmp  eax, 5
    jne  .fail

    ; ---- REASONS GUARD: the 5 rejects above must break down by EXACTLY the mix the
    ;      vectors injected (null=1, short=2, wrap=0, nolen=1, trunc=1, toobig=0,
    ;      fuel=0). This gates the per-reason telemetry: a broken reason path shows
    ;      up as a wrong sub-delta, so the observability is itself correctness-gated. ----
    mov  r15d, 33                            ; step 33: null == 1 (NULL frame)
    mov  eax, [rel dhcp_fo_rej_null]
    sub  eax, [rel dhcp_fo_kat_r0 + 0]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 34                            ; step 34: short == 2 (len=0, len=240)
    mov  eax, [rel dhcp_fo_rej_short]
    sub  eax, [rel dhcp_fo_kat_r0 + 4]
    cmp  eax, 2
    jne  .fail
    mov  r15d, 35                            ; step 35: wrap == 0 (address wrap, not hit)
    mov  eax, [rel dhcp_fo_rej_wrap]
    sub  eax, [rel dhcp_fo_kat_r0 + 8]
    cmp  eax, 0
    jne  .fail
    mov  r15d, 36                            ; step 36: nolen == 1 (F3 bare-tag last byte)
    mov  eax, [rel dhcp_fo_rej_nolen]
    sub  eax, [rel dhcp_fo_kat_r0 + 12]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 37                            ; step 37: trunc == 1 (F2 over-declared len)
    mov  eax, [rel dhcp_fo_rej_trunc]
    sub  eax, [rel dhcp_fo_kat_r0 + 16]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 38                            ; step 38: toobig == 0 (not exercised yet)
    mov  eax, [rel dhcp_fo_rej_toobig]
    sub  eax, [rel dhcp_fo_kat_r0 + 20]
    cmp  eax, 0
    jne  .fail
    mov  r15d, 39                            ; step 39: fuel == 0 (every walk terminated)
    mov  eax, [rel dhcp_fo_rej_fuel]
    sub  eax, [rel dhcp_fo_kat_r0 + 24]
    cmp  eax, 0
    jne  .fail

    ; ---- PASS (part 1): print the (8,5,5) deltas from the LIVE counters + the reason
    ;      breakdown line. Printed HERE, before the envelope test moves the counters,
    ;      so the printed rej delta matches the guard's exact 5. ----
    lea  rdi, [rel str_dhcp_fo_pre]
    call serial_string
    mov  eax, [rel dhcp_fo_ct_find]
    sub  eax, [rel dhcp_fo_kat_c0]
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_fo_miss]
    call serial_string
    mov  eax, [rel dhcp_fo_ct_miss]
    sub  eax, [rel dhcp_fo_kat_c0 + 4]
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_fo_rej]
    call serial_string
    mov  eax, [rel dhcp_fo_ct_rej]
    sub  eax, [rel dhcp_fo_kat_c0 + 8]
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_fo_post]
    call serial_string
    lea  rdi, [rel str_dhcp_fo_rsn]          ; reason breakdown + [.reasons] marker
    call serial_string

    ; ---- ENVELOPE: exercise the WIDENED failure envelope the old KAT never did —
    ;      feed an ABSURD length (256 MiB, far past any real DHCP datagram) and prove
    ;      it is contained BEFORE the walk: returns 0, faults nothing, and is counted
    ;      as a DISTINCT 'toobig' reject with the live last-reason code set. ----
    mov  eax, [rel dhcp_fo_ct_rej]
    mov  [rel dhcp_fo_kat_e_rej], eax        ; aggregate-rej snapshot for this window
    mov  eax, [rel dhcp_fo_rej_toobig]
    mov  [rel dhcp_fo_kat_e_tb], eax         ; toobig snapshot for this window
    mov  r15d, 40                            ; step 40: absurd len -> contained 0
    lea  rdi, [rel dhcp_offer]
    mov  esi, 0x10000000                     ; 256 MiB
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jnz  .fail                               ; MUST be contained (0), never a value
    mov  r15d, 41                            ; step 41: counted as exactly one 'toobig'
    mov  eax, [rel dhcp_fo_rej_toobig]
    sub  eax, [rel dhcp_fo_kat_e_tb]
    cmp  eax, 1
    jne  .fail
    mov  r15d, 42                            ; step 42: live last-reason code == TOOBIG
    cmp  dword [rel dhcp_fo_last_rej], FO_REJ_TOOBIG
    jne  .fail
    mov  r15d, 43                            ; step 43: aggregate rej moved by exactly 1
    mov  eax, [rel dhcp_fo_ct_rej]
    sub  eax, [rel dhcp_fo_kat_e_rej]
    cmp  eax, 1
    jne  .fail

    ; ---- PASS (part 2): the envelope guard passed -> emit the [.envelope] marker ----
    lea  rdi, [rel str_dhcp_fo_env]          ; widened envelope + [.envelope] marker
    call serial_string
    jmp  .out
.fail:
    ; contained failure: name the step, do NOT halt the boot
    lea  rdi, [rel str_dhcp_fo_fail]
    call serial_string
    mov  eax, r15d
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_crlf]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dhcp_fo_print_u8(EAX=0..255) — decimal via the module's shared scratch buf.
;   clobbers: volatiles.
dhcp_fo_print_u8:
    lea  rdi, [rel dhcp_ipbuf]
    call dhcp_wr_u8
    mov  byte [rdi], 0
    lea  rdi, [rel dhcp_ipbuf]
    call serial_string
    ret

; dhcp_wr_u8(EAX=value 0..255, RDI=dst) -> RDI advanced past the decimal digits.
;   No leading zeros (so "8"/"87"/"150", never "008" — keeps the probe's bash
;   octet check from choking on an octal-looking octet). clobbers: EAX,ECX,EDX,R8.
;   DURABILITY (1411, most-durable): a caller that hands us a value >255 or a
;   register with dirty high bits (e.g. a stale 32-bit EAX behind a movzx-less
;   caller) must NOT be able to make us emit a non-digit byte — a hundreds digit
;   >=10 would print ':' or worse, and the write length would drift. Contain the
;   input to a true byte FIRST: for every legal 0..255 input this is a no-op
;   (output byte-identical to the proven baseline), but an out-of-range input is
;   folded to its low byte and STILL yields only 1..3 ASCII decimal digits. The
;   write is thereby bounded to at most 3 bytes for ANY 32-bit input.
dhcp_wr_u8:
    movzx eax, al                            ; fault-contain: clamp to 0..255 (no-op for legal input)
    xor  edx, edx
    mov  r8d, 100
    div  r8d                                 ; eax=hundreds, edx=rem(0..99)
    test eax, eax
    jz   .no_h
    add  al, '0'
    mov  [rdi], al
    inc  rdi
    mov  eax, edx
    xor  edx, edx
    mov  r8d, 10
    div  r8d                                 ; eax=tens, edx=units
    add  al, '0'
    mov  [rdi], al
    inc  rdi
    add  dl, '0'
    mov  [rdi], dl
    inc  rdi
    ret
.no_h:
    mov  eax, edx
    xor  edx, edx
    mov  r8d, 10
    div  r8d
    test eax, eax
    jz   .no_t
    add  al, '0'
    mov  [rdi], al
    inc  rdi
.no_t:
    add  dl, '0'
    mov  [rdi], dl
    inc  rdi
    ret

; ---------------------------------------------------------------------------
; TOURNAMENT 1411 — dhcp_wr_u8 known-answer test (MOST-DURABLE variant gate).
; dhcp_wr_u8 is the shared 0..255 decimal formatter (fan-in 5: every IP octet +
; option byte printed by this module flows through it). A leaner/faster variant
; that drops a digit, mis-suppresses a leading zero, over/under-advances RDI, or
; overruns the destination buffer must score 0. This gate earns THREE honest,
; independently-asserted markers — correctness FIRST, then two durability
; properties the smaller/faster variants do not prove:
;
;   [tourn.dhcp_wr_u8.kat]   — every vector's emitted bytes match byte-for-byte
;       across all three write paths: 1-digit (0,9 -> "0"/"9", never "00"),
;       2-digit (10,87,99 -> no leading zero), 3-digit incl. embedded-zero tens
;       (100,205 -> "100"/"205"), and the 0/255 boundaries.
;   [tourn.dhcp_wr_u8.guard] — BOUNDED WRITE: the returned RDI advance equals the
;       expected digit count EXACTLY (no over/under-advance) AND the destination
;       byte one past the digits is still the pre-planted 0xEE sentinel — proving
;       dhcp_wr_u8 writes EXACTLY len bytes and never scribbles past its output.
;   [tourn.dhcp_wr_u8.clamp] — FAULT CONTAINMENT: an out-of-range / dirty-high
;       input (256, 0x1FF, 1000, 0xFFFFFF05) is folded to its low byte and STILL
;       yields only ASCII '0'..'9' digits equal to (v&0xFF) — and calling with a
;       dirty high dword returns byte-identical output to the clean low byte.
;       A naive itoa without the movzx clamp would emit a non-digit ':' here.
;
; Any mismatch prints the failing record index + the matching .fail marker and
; boot CONTINUES (degrade, never crash). All three drives run over a scratch
; buffer, never touching live DHCP state.
; clobbers: volatiles; preserves rbx,r12-r15 (saved).
dhcp_wr_u8_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---- KAT + GUARD: positive vectors, bytes + bounded-write, one pass ----
    lea  rbx, [rel dhcp_wu_kat_vec]              ; current 8-byte record base
    xor  r12d, r12d                              ; record index (== failing step id)
.kloop:
    cmp  r12d, DHCP_WU_KAT_N
    jae  .kat_ok
    ; plant a 0xEE sentinel across the whole scratch so an overrun is detectable
    mov  dword [rel dhcp_wu_scratch], 0xEEEEEEEE
    mov  dword [rel dhcp_wu_scratch + 4], 0xEEEEEEEE
    mov  eax, [rbx]                              ; 32-bit input value
    lea  rdi, [rel dhcp_wu_scratch]              ; scratch dst
    mov  r14, rdi                                ; remember start (survives the call)
    call dhcp_wr_u8                              ; writes digits, advances rdi
    sub  rdi, r14                                ; rdi = bytes actually written
    movzx ecx, byte [rbx + 4]                    ; expected length
    cmp  rdi, rcx
    jne  .fail                                   ; GUARD: wrong advance (over/under)
    cmp  byte [r14 + rcx], 0xEE                  ; GUARD: byte past digits untouched
    jne  .fail                                   ; overrun detected
    xor  edx, edx
.kcmp:
    cmp  edx, ecx
    jae  .knext
    mov  al, [r14 + rdx]                         ; byte we wrote
    cmp  al, [rbx + 5 + rdx]                     ; expected ASCII byte
    jne  .fail                                   ; KAT: byte mismatch
    inc  edx
    jmp  .kcmp
.knext:
    add  rbx, 8                                  ; fixed-width record stride
    inc  r12d
    jmp  .kloop
.kat_ok:
    lea  rdi, [rel str_dhcp_wu_kat]
    call serial_string
    lea  rdi, [rel str_dhcp_wu_guard]
    call serial_string

    ; ---- CLAMP: dirty-high containment. For each low byte, calling with a dirty
    ;      high dword must (a) emit only decimal digits and (b) return byte-for-byte
    ;      the SAME output as the clean low byte. ----
    lea  rbx, [rel dhcp_wu_clamp_vec]            ; current 4-byte record (dd dirty input)
    xor  r12d, r12d
.cloop:
    cmp  r12d, DHCP_WU_CLAMP_N
    jae  .clamp_ok
    mov  r13d, 100                               ; step base for clamp fails
    add  r13d, r12d
    ; (1) clean low byte -> reference output in dhcp_wu_ref
    mov  eax, [rbx]
    movzx eax, al                                ; the clean byte the caller MEANT
    lea  rdi, [rel dhcp_wu_ref]
    mov  r14, rdi
    call dhcp_wr_u8
    sub  rdi, r14
    mov  r15, rdi                                ; r15 = reference length
    ; (2) dirty full dword -> output in dhcp_wu_scratch
    mov  dword [rel dhcp_wu_scratch], 0xEEEEEEEE
    mov  dword [rel dhcp_wu_scratch + 4], 0xEEEEEEEE
    mov  eax, [rbx]                              ; the FULL dirty 32-bit value
    lea  rdi, [rel dhcp_wu_scratch]
    mov  r14, rdi
    call dhcp_wr_u8
    sub  rdi, r14
    cmp  rdi, r15                                ; same length as the clean byte?
    jne  .cfail
    ; compare the two outputs byte-for-byte AND assert each is a decimal digit.
    ; Index off REGISTER bases (r14=scratch, rsi=ref) — [rel sym + reg] can't be
    ; RIP-relative and would bake a compile-time RVA (wrong at runtime).
    lea  rsi, [rel dhcp_wu_ref]                  ; clean-byte reference base
    xor  edx, edx
.ccmp:
    cmp  rdx, r15
    jae  .cdigit_done
    mov  al, [r14 + rdx]                         ; dirty output byte (r14 = scratch base)
    cmp  al, [rsi + rdx]                         ; == clean output byte
    jne  .cfail
    cmp  al, '0'                                 ; and it's an ASCII decimal digit
    jb   .cfail
    cmp  al, '9'
    ja   .cfail
    inc  edx
    jmp  .ccmp
.cdigit_done:
    add  rbx, 4
    inc  r12d
    jmp  .cloop
.clamp_ok:
    lea  rdi, [rel str_dhcp_wu_clamp]
    call serial_string
    jmp  .out

.cfail:
    mov  r12d, r13d                              ; report the clamp step id (100+i)
.fail:
    lea  rdi, [rel str_dhcp_wu_fail]
    call serial_string
    mov  eax, r12d
    call dhcp_fo_print_u8
    lea  rdi, [rel str_dhcp_crlf]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dhcp_fmt_ip(RSI=4-byte IPv4 ptr, RDI=dst) -> writes "A.B.C.D\0".
;   clobbers: EAX,ECX,EDX,R8,RDI; preserves rbx (saved).
dhcp_fmt_ip:
    push rbx
    mov  rbx, rsi                            ; ip ptr (stable across div clobbers)
    movzx eax, byte [rbx]
    call dhcp_wr_u8
    mov  byte [rdi], '.'
    inc  rdi
    movzx eax, byte [rbx + 1]
    call dhcp_wr_u8
    mov  byte [rdi], '.'
    inc  rdi
    movzx eax, byte [rbx + 2]
    call dhcp_wr_u8
    mov  byte [rdi], '.'
    inc  rdi
    movzx eax, byte [rbx + 3]
    call dhcp_wr_u8
    mov  byte [rdi], 0
    pop  rbx
    ret

; dhcp_print_ip(RSI=4-byte IPv4 ptr) — format into the scratch buf + serial_string.
;   clobbers: volatiles.
dhcp_print_ip:
    lea  rdi, [rel dhcp_ipbuf]
    call dhcp_fmt_ip
    lea  rdi, [rel dhcp_ipbuf]
    call serial_string
    ret

; dhcp_print_xid(RSI=4-byte ptr) — print "0x" + 8 lowercase hex digits in memory
;   (wire) byte order, then serial_string. clobbers: volatiles; saves rbx.
dhcp_print_xid:
    push rbx
    mov  rbx, rsi
    lea  rdi, [rel dhcp_xidbuf]
    mov  byte [rdi], '0'
    mov  byte [rdi + 1], 'x'
    add  rdi, 2
    xor  ecx, ecx
.xd:
    movzx eax, byte [rbx + rcx]
    mov  edx, eax
    shr  edx, 4                              ; high nibble
    lea  r8, [rel dhcp_hexchars]
    mov  dl, [r8 + rdx]
    mov  [rdi], dl
    mov  edx, eax
    and  edx, 0x0f                           ; low nibble
    mov  dl, [r8 + rdx]
    mov  [rdi + 1], dl
    add  rdi, 2
    inc  ecx
    cmp  ecx, 4
    jb   .xd
    mov  byte [rdi], 0
    lea  rdi, [rel dhcp_xidbuf]
    call serial_string
    pop  rbx
    ret

; --- net/dhcp data (canned vectors + parsed state + scratch; in-image) ---------
; Canned DHCPOFFER: op=BOOTREPLY(2), xid=39 03 f3 26, yiaddr=192.0.2.150,
;   magic cookie, options: msg-type=OFFER(2), server-id=192.0.2.1,
;   subnet=255.255.255.0, router=192.0.2.1, dns=8.8.8.8, END.
dhcp_offer:
    db 0x02, 0x01, 0x06, 0x00                ; op, htype, hlen, hops
    db 0x39, 0x03, 0xf3, 0x26                ; xid
    times 4 db 0                             ; secs(2) + flags(2)
    times 4 db 0                             ; ciaddr
    db 192, 0, 2, 150                       ; yiaddr (offset 16 — the offered IP)
    times 4 db 0                             ; siaddr
    times 4 db 0                             ; giaddr
    times 16 db 0                            ; chaddr
    times 64 db 0                            ; sname
    times 128 db 0                           ; file
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie (offset 236)
    db OPT_MSGTYPE, 1, MSG_OFFER             ; 53: OFFER
    db OPT_SERVERID, 4, 192, 0, 2, 1        ; 54: server id
    db OPT_SUBNET, 4, 255, 255, 255, 0       ; 1: subnet mask
    db OPT_ROUTER, 4, 192, 0, 2, 1          ; 3: gateway
    db OPT_DNS, 4, 8, 8, 8, 8                ; 6: DNS
    db OPT_END
dhcp_offer_end:
DHCP_OFFER_LEN equ dhcp_offer_end - dhcp_offer

; Canned DHCPACK: same xid + yiaddr, msg-type=ACK(5), with mask/gw/dns.
dhcp_ack:
    db 0x02, 0x01, 0x06, 0x00
    db 0x39, 0x03, 0xf3, 0x26                ; xid (same transaction)
    times 4 db 0
    times 4 db 0
    db 192, 0, 2, 150                       ; yiaddr (leased IP)
    times 4 db 0
    times 4 db 0
    times 16 db 0
    times 64 db 0
    times 128 db 0
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie
    db OPT_MSGTYPE, 1, MSG_ACK               ; 53: ACK
    db OPT_SUBNET, 4, 255, 255, 255, 0       ; 1: subnet mask
    db OPT_ROUTER, 4, 192, 0, 2, 1          ; 3: gateway
    db OPT_DNS, 4, 8, 8, 8, 8                ; 6: DNS
    db OPT_END
dhcp_ack_end:
DHCP_ACK_LEN equ dhcp_ack_end - dhcp_ack

; NEGATIVE vector: 240 bytes with a WRONG magic cookie (must be rejected).
dhcp_badframe:
    times DHCP_MAGIC db 0                    ; 236 zero bytes (bad op, no cookie yet)
    db 0xde, 0xad, 0xbe, 0xef                ; NOT the DHCP magic cookie
dhcp_badframe_end:
DHCP_BADFRAME_LEN equ dhcp_badframe_end - dhcp_badframe

; A well-formed DHCPACK with no opt6 DNS (op=BOOTREPLY, magic, opt53=ACK, opt1
;   subnet, opt3 router, END). TOURNAMENT 1407 rejected it; since RCQ-10 S2 it parses
;   as a lease with no resolver (dns=0), as RFC 2132 makes opt6 optional.
dhcp_ack_nodns:
    db 0x02, 0x01, 0x06, 0x00
    db 0x39, 0x03, 0xf3, 0x26                ; xid
    times 4 db 0
    times 4 db 0
    db 192, 0, 2, 150                       ; yiaddr
    times 4 db 0
    times 4 db 0
    times 16 db 0
    times 64 db 0
    times 128 db 0
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie
    db OPT_MSGTYPE, 1, MSG_ACK               ; 53: ACK
    db OPT_SUBNET, 4, 255, 255, 255, 0       ; 1: subnet mask
    db OPT_ROUTER, 4, 192, 0, 2, 1          ; 3: gateway (no opt6 DNS follows)
    db OPT_END
dhcp_ack_nodns_end:
DHCP_ACK_NODNS_LEN equ dhcp_ack_nodns_end - dhcp_ack_nodns

; TOURNAMENT 1410 negative vectors (each exercises ONE distinct parse_offer reject reason):
; badop — magic-VALID frame whose op is BOOTREQUEST(1), not BOOTREPLY(2) -> reason OP.
dhcp_offer_badop:
    db 0x01, 0x01, 0x06, 0x00                ; op=1 (BOOTREQUEST) — the only change vs dhcp_offer
    db 0x39, 0x03, 0xf3, 0x26                ; xid
    times 4 db 0
    times 4 db 0
    db 192, 0, 2, 150                       ; yiaddr
    times 4 db 0
    times 4 db 0
    times 16 db 0
    times 64 db 0
    times 128 db 0
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie (valid)
    db OPT_MSGTYPE, 1, MSG_OFFER
    db OPT_SERVERID, 4, 192, 0, 2, 1
    db OPT_END
dhcp_offer_badop_end:
DHCP_OFFER_BADOP_LEN equ dhcp_offer_badop_end - dhcp_offer_badop

; no53 — valid BOOTREPLY/magic frame with NO opt53 (msg-type) at all -> reason MSGTYPE.
dhcp_offer_no53:
    db 0x02, 0x01, 0x06, 0x00
    db 0x39, 0x03, 0xf3, 0x26
    times 4 db 0
    times 4 db 0
    db 192, 0, 2, 150                       ; yiaddr (non-zero)
    times 4 db 0
    times 4 db 0
    times 16 db 0
    times 64 db 0
    times 128 db 0
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie
    db OPT_SERVERID, 4, 192, 0, 2, 1        ; opt54 present, but opt53 absent
    db OPT_SUBNET, 4, 255, 255, 255, 0
    db OPT_END
dhcp_offer_no53_end:
DHCP_OFFER_NO53_LEN equ dhcp_offer_no53_end - dhcp_offer_no53

; zeroyi — valid OFFER (op/magic/opt53=OFFER/opt54 all present) but yiaddr==0 -> reason YIADDR.
;   Reaches PAST validate/op/opt53 — the atomicity-critical region.
dhcp_offer_zeroyi:
    db 0x02, 0x01, 0x06, 0x00
    db 0x39, 0x03, 0xf3, 0x26
    times 4 db 0
    times 4 db 0
    times 4 db 0                             ; yiaddr = 0.0.0.0 (bogus offer)
    times 4 db 0
    times 4 db 0
    times 16 db 0
    times 64 db 0
    times 128 db 0
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie
    db OPT_MSGTYPE, 1, MSG_OFFER
    db OPT_SERVERID, 4, 192, 0, 2, 1
    db OPT_END
dhcp_offer_zeroyi_end:
DHCP_OFFER_ZEROYI_LEN equ dhcp_offer_zeroyi_end - dhcp_offer_zeroyi

; no54 — valid OFFER (op/magic/opt53=OFFER, non-zero yiaddr) but NO opt54 server-id ->
;   reason SERVERID. This is the EXACT frame that made the baseline commit partial
;   dhcp_parsed_xid/yiaddr before it discovered opt54 was missing; the atomic variant
;   leaves the shared state untouched.
dhcp_offer_no54:
    db 0x02, 0x01, 0x06, 0x00
    db 0x39, 0x03, 0xf3, 0x26
    times 4 db 0
    times 4 db 0
    db 192, 0, 2, 150                       ; yiaddr (non-zero)
    times 4 db 0
    times 4 db 0
    times 16 db 0
    times 64 db 0
    times 128 db 0
    db 0x63, 0x82, 0x53, 0x63                ; magic cookie
    db OPT_MSGTYPE, 1, MSG_OFFER             ; opt53=OFFER present
    db OPT_SUBNET, 4, 255, 255, 255, 0       ; opt1 present, but opt54 (server-id) absent
    db OPT_ROUTER, 4, 192, 0, 2, 1
    db OPT_END
dhcp_offer_no54_end:
DHCP_OFFER_NO54_LEN equ dhcp_offer_no54_end - dhcp_offer_no54

; ---------------------------------------------------------------------------
; Live wire DORA client.  The message parser/build logic above remains the one
; source of DHCP truth; this adapter only frames those payloads as ordinary
; Ethernet/IPv4/UDP and sends them through the owning netdev's TX operation. It has no backend or
; chip knowledge, so a native NIC and virtio_domain exercise identical code.
;
; The DORA transaction is bound to the opaque netdev handle supplied at start.
; A machine may poll several NICs on one broadcast LAN; XID+chaddr alone cannot
; distinguish a matching OFFER/ACK observed by the wrong handle.  Binding here
; keeps lease ownership in the class seam without importing any chip/backend.
; ---------------------------------------------------------------------------
DHCP_WS_OFF        equ 0
DHCP_WS_SELECTING  equ 1
DHCP_WS_REQUESTING equ 2
DHCP_WS_BOUND      equ 3
DHCP_WS_FALLBACK   equ 4
DHCP_WS_RENEWING   equ 5
DHCP_WS_REBINDING  equ 6
DHCP_RETRY_MS      equ 2000
DHCP_MAX_ATTEMPTS  equ 4
DHCP_FAULT_WAIT_MS equ 50
; RFC 1542 §2.1 permits BOOTP/DHCP servers to drop UDP payloads shorter
; than the 300-octet BOOTP minimum.  Keep TLVs unchanged and zero-pad only
; the actual wire packet so one shared NIC-independent path serves all three.
DHCP_MIN_BOOTP_BYTES equ 300

dhcp_wire_lock_acquire:
    lea  rdi, [rel dhcp_wire_lock]
    jmp  spin_acquire

dhcp_wire_lock_release:
    lea  rdi, [rel dhcp_wire_lock]
    jmp  spin_release

; Read-only coherent DORA generation and actual DHCP owner, for retained
; recovery observations. EAX=generation, RDX=owner handle.
dhcp_wire_observation:
    push rbx
    push r12
    call dhcp_wire_lock_acquire
    mov  ebx, [rel dhcp_wire_generation]
    mov  r12, [rel dhcp_wire_owner_handle]
    call dhcp_wire_lock_release
    mov  eax, ebx
    mov  rdx, r12
    pop  r12
    pop  rbx
    ret

; RDI=120-byte caller storage. Read-only coherent lease snapshot, 15 qwords:
; NOW,STATE,GEN,OWNER,XID,SERVER,ADDR,LEASE_S,T1_S,T2_S,T1_AT,T2_AT,
; EXPIRE_AT,RETRY_AT,KHZ. Addresses/xid retain native packed representation.
; The caller owns its buffer; this never ticks the FSM, transmits or rearms.
dhcp_wire_lease_snapshot:
    push r12
    mov  r12, rdi
    call dhcp_wire_lock_acquire
    call tsc_now
    mov  [r12], rax
    movzx eax, byte [rel dhcp_wire_state]
    mov  [r12 + 8], rax
    mov  eax, [rel dhcp_wire_generation]
    mov  [r12 + 16], rax
    mov  rax, [rel dhcp_wire_owner_handle]
    mov  [r12 + 24], rax
    mov  eax, [rel dhcp_wire_xid]
    mov  [r12 + 32], rax
    mov  eax, [rel dhcp_parsed_serverid]
    mov  [r12 + 40], rax
    mov  eax, [rel dhcp_ack_yiaddr]
    mov  [r12 + 48], rax
    mov  eax, [rel dhcp_ack_lease_s]
    mov  [r12 + 56], rax
    mov  eax, [rel dhcp_ack_t1_s]
    mov  [r12 + 64], rax
    mov  eax, [rel dhcp_ack_t2_s]
    mov  [r12 + 72], rax
    mov  rax, [rel dhcp_wire_t1_tsc]
    mov  [r12 + 80], rax
    mov  rax, [rel dhcp_wire_t2_tsc]
    mov  [r12 + 88], rax
    mov  rax, [rel dhcp_wire_expire_tsc]
    mov  [r12 + 96], rax
    mov  rax, [rel dhcp_wire_retry_tsc]
    mov  [r12 + 104], rax
    mov  rax, [rel tsc_khz]
    mov  [r12 + 112], rax
    call dhcp_wire_lock_release
    pop  r12
    ret

; dhcp_wire_ntp_server(EDI=wire IPv4 of the live route source) -> EAX = the
; current lease's first option-42 server, or 0. Clock unit (ROOT 122029): the
; offer counts only while the lease that carried it is held (BOUND, RENEWING or
; REBINDING) and is the address the route actually uses; raw ACK fields alone
; are never configuration. Read-only, under the owner lock.
dhcp_wire_ntp_server:
    push rbx
    mov  ebx, edi
    call dhcp_wire_lock_acquire
    xor  edx, edx
    test ebx, ebx
    jz   .out
    cmp  ebx, [rel dhcp_ack_yiaddr]
    jne  .out
    movzx eax, byte [rel dhcp_wire_state]
    cmp  eax, DHCP_WS_BOUND
    je   .held
    cmp  eax, DHCP_WS_RENEWING
    je   .held
    cmp  eax, DHCP_WS_REBINDING
    jne  .out
.held:
    mov  edx, [rel dhcp_ack_ntp_v]
.out:
    push rdx
    call dhcp_wire_lock_release
    pop  rax
    pop  rbx
    ret

; RDI=client MAC, RSI=owning netdev handle.
dhcp_wire_start:
    xor  r8d, r8d
    xor  edx, edx
    jmp  dhcp_wire_start_common

; EDX=owner-selected wire-order initial server. Ordinary restart clears it.
; This SELECTING preference is not an ACK policy or a T2 server pin.
dhcp_wire_start_preferred:
    mov  r8d, edx
    xor  edx, edx
    jmp  dhcp_wire_start_common

; Same real DISCOVER path, but valid replies are suppressed for one bounded
; negative-test attempt. The ordinary FSM deadline then earns FALLBACK; the
; command surface never fabricates that result itself.
dhcp_wire_start_no_server:
    xor  r8d, r8d
    mov  edx, 1
dhcp_wire_start_common:
    push rbx
    push r12
    sub  rsp, 8                             ; keep 16-byte call alignment
    mov  rbx, rdi
    mov  r12, rsi
    call dhcp_wire_lock_acquire
    mov  [rel dhcp_wire_no_server], dl
    mov  [rel dhcp_wire_preferred_server], r8d
    test rbx, rbx
    jz   .bad
    test r12, r12
    jz   .bad
    mov  [rel dhcp_wire_owner_handle], r12
    mov  eax, [rbx]
    mov  [rel dhcp_wire_mac], eax
    mov  ax, [rbx + 4]
    mov  [rel dhcp_wire_mac + 4], ax
    call tsc_now
    inc  dword [rel dhcp_wire_generation]
    xor  eax, [rel dhcp_wire_generation]
    xor  eax, 0x50414f53                    ; unique-enough per-boot transaction
    test eax, eax
    jnz  .xid_ok
    mov  eax, 1
.xid_ok:
    mov  [rel dhcp_wire_xid], eax
    lea  rdi, [rel dhcp_wire_payload]
    xor  esi, esi
    mov  edx, 300
    call memset
    lea  rbx, [rel dhcp_wire_payload]
    mov  byte [rbx + DHCP_OP], 1
    mov  byte [rbx + 1], 1
    mov  byte [rbx + 2], 6
    mov  eax, [rel dhcp_wire_xid]
    mov  [rbx + DHCP_XID], eax
    mov  byte [rbx + 10], 0x80              ; BOOTP broadcast flag (network 0x8000)
    mov  eax, [rel dhcp_wire_mac]
    mov  [rbx + 28], eax
    mov  ax, [rel dhcp_wire_mac + 4]
    mov  [rbx + 32], ax
    mov  dword [rbx + DHCP_MAGIC], DHCP_MAGIC_LE
    lea  rdi, [rbx + DHCP_OPTIONS]
    mov  byte [rdi + 0], OPT_MSGTYPE
    mov  byte [rdi + 1], 1
    mov  byte [rdi + 2], 1                  ; DHCPDISCOVER
    mov  byte [rdi + 3], OPT_PRL            ; parameter-request list
    mov  byte [rdi + 4], 5
    mov  byte [rdi + 5], OPT_SUBNET
    mov  byte [rdi + 6], OPT_ROUTER
    mov  byte [rdi + 7], OPT_DNS
    mov  byte [rdi + 8], 51                 ; lease time
    mov  byte [rdi + 9], OPT_NTP            ; clock unit (ROOT 122029): boot SNTP server
    mov  byte [rdi + 10], OPT_END
    mov  dword [rel dhcp_wire_payload_len], DHCP_OPTIONS + 11
    mov  byte [rel dhcp_wire_state], DHCP_WS_SELECTING
    mov  qword [rel dhcp_wire_retry_tsc], 0
    mov  qword [rel dhcp_wire_t1_tsc], 0
    mov  qword [rel dhcp_wire_t2_tsc], 0
    mov  qword [rel dhcp_wire_expire_tsc], 0
    mov  qword [rel dhcp_wire_tx_started], 0
    mov  qword [rel dhcp_wire_tx_attempts], 0
    mov  qword [rel dhcp_wire_tx_ok], 0
    mov  qword [rel dhcp_wire_tx_fail], 0
    mov  qword [rel dhcp_wire_rx_frames], 0
    mov  qword [rel dhcp_wire_rx_port68], 0
    mov  qword [rel dhcp_wire_rx_xid_ok], 0
    mov  dword [rel dhcp_ack_yiaddr], 0
    mov  dword [rel dhcp_ack_mask_v], 0
    mov  dword [rel dhcp_ack_gw_v], 0
    mov  dword [rel dhcp_ack_dns_v], 0
    mov  dword [rel dhcp_ack_ntp_v], 0
    mov  dword [rel dhcp_ack_lease_s], 0
    mov  dword [rel dhcp_ack_t1_s], 0
    mov  dword [rel dhcp_ack_t2_s], 0
    mov  byte [rel dhcp_wire_m_discover], 0
    mov  byte [rel dhcp_wire_m_offer], 0
    mov  byte [rel dhcp_wire_m_request], 0
    mov  byte [rel dhcp_wire_m_ack], 0
    lea  rdi, [rel dhcp_wire_payload]
    mov  esi, [rel dhcp_wire_payload_len]
    call dhcp_wire_send_payload
    test rax, rax
    jnz  .discover_done
    mov  byte [rel dhcp_wire_m_discover], 1
.discover_done:
    call dhcp_wire_arm_retry
    xor  eax, eax
    call dhcp_wire_lock_release
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
.bad:
    mov  dword [rel dhcp_wire_preferred_server], 0
    mov  byte [rel dhcp_wire_no_server], 0
    mov  qword [rel dhcp_wire_owner_handle], 0
    mov  rax, -1
    call dhcp_wire_lock_release
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

dhcp_wire_stop:
    call dhcp_wire_lock_acquire
    mov  byte [rel dhcp_wire_state], DHCP_WS_OFF
    mov  dword [rel dhcp_wire_preferred_server], 0
    mov  byte [rel dhcp_wire_no_server], 0
    mov  qword [rel dhcp_wire_retry_tsc], 0
    mov  qword [rel dhcp_wire_t1_tsc], 0
    mov  qword [rel dhcp_wire_t2_tsc], 0
    mov  qword [rel dhcp_wire_expire_tsc], 0
    mov  qword [rel dhcp_wire_owner_handle], 0
    mov  dword [rel dhcp_ack_yiaddr], 0
    mov  dword [rel dhcp_ack_mask_v], 0
    mov  dword [rel dhcp_ack_gw_v], 0
    mov  dword [rel dhcp_ack_dns_v], 0
    mov  dword [rel dhcp_ack_ntp_v], 0
    mov  dword [rel dhcp_ack_lease_s], 0
    mov  dword [rel dhcp_ack_t1_s], 0
    mov  dword [rel dhcp_ack_t2_s], 0
    call dhcp_wire_lock_release
    ret

; A qualified ACK the command projection could not install (owner changed,
; gateway ARP TX failed). End in the ordinary FALLBACK, never BOUND w/o lease.
dhcp_wire_abandon:
    call dhcp_wire_lock_acquire
    call dhcp_wire_fallback
    call dhcp_wire_lock_release
    ret

; Advance the bounded DORA/renewal FSM. Selecting/requesting exhaust four real
; TX attempts and fall back; bound leases advance through T1 renewal, T2 rebind,
; and expiry without ever blocking the command poll task.
dhcp_wire_tick:
    push rbx
    call dhcp_wire_lock_acquire
    movzx ebx, byte [rel dhcp_wire_state]
    test ebx, ebx
    jz   .done
    call tsc_now

    cmp  ebx, DHCP_WS_BOUND
    je   .bound
    cmp  ebx, DHCP_WS_RENEWING
    je   .renewing
    cmp  ebx, DHCP_WS_REBINDING
    je   .rebinding
    cmp  ebx, DHCP_WS_FALLBACK
    je   .done

    ; SELECTING / REQUESTING: a real timeout is the retry deadline expiring
    ; after the bounded attempt count. The injected no-server attempt has a
    ; deliberately short one-attempt budget but traverses this same branch.
    cmp  rax, [rel dhcp_wire_retry_tsc]
    jb   .done
    cmp  byte [rel dhcp_wire_no_server], 0
    jne  .fallback
    cmp  qword [rel dhcp_wire_tx_attempts], DHCP_MAX_ATTEMPTS
    jae  .fallback
    cmp  ebx, DHCP_WS_SELECTING
    jne  .request
    lea  rdi, [rel dhcp_wire_payload]
    mov  esi, [rel dhcp_wire_payload_len]
    jmp  .send
.request:
    lea  rdi, [rel dhcp_request_buf]
    mov  esi, [rel dhcp_wire_request_len]
.send:
    call dhcp_wire_send_payload
    test rax, rax
    jnz  .rearm
    cmp  ebx, DHCP_WS_SELECTING
    jne  .mark_request
    mov  byte [rel dhcp_wire_m_discover], 1
    jmp  .rearm
.mark_request:
    mov  byte [rel dhcp_wire_m_request], 1
.rearm:
    call dhcp_wire_arm_retry
    jmp  .done

.bound:
    mov  rdx, [rel dhcp_wire_expire_tsc]
    test rdx, rdx
    jz   .done                              ; not yet armed by mark_bound
    cmp  rax, rdx
    jae  .fallback                          ; a delayed poll never renews expired IP
    mov  rdx, [rel dhcp_wire_t1_tsc]
    test rdx, rdx
    jz   .done
    cmp  rax, rdx
    jb   .done
    ; The first idle poll may miss the whole renewal interval. Select the
    ; current lease phase before sending: at T2 broadcast without T1 ARP.
    mov  rdx, [rel dhcp_wire_t2_tsc]
    test rdx, rdx
    jz   .begin_renew
    cmp  rax, rdx
    jae  .begin_rebind
.begin_renew:
    mov  byte [rel dhcp_wire_state], DHCP_WS_RENEWING
    mov  ebx, DHCP_WS_RENEWING
    call dhcp_wire_renew_request
    jmp  .renew_send

.renewing:
    mov  rdx, [rel dhcp_wire_expire_tsc]
    test rdx, rdx
    jz   .fallback
    cmp  rax, rdx
    jae  .fallback
    mov  rdx, [rel dhcp_wire_t2_tsc]
    test rdx, rdx
    jz   .retry_renew
    cmp  rax, rdx
    jb   .retry_renew
.begin_rebind:
    mov  byte [rel dhcp_wire_state], DHCP_WS_REBINDING
    mov  ebx, DHCP_WS_REBINDING
    call dhcp_wire_renew_request
    jmp  .renew_send
.retry_renew:
    cmp  rax, [rel dhcp_wire_retry_tsc]
    jb   .done
    jmp  .renew_send

.rebinding:
    mov  rdx, [rel dhcp_wire_expire_tsc]
    test rdx, rdx
    jz   .fallback
    cmp  rax, rdx
    jae  .fallback
    cmp  rax, [rel dhcp_wire_retry_tsc]
    jb   .done
.renew_send:
    lea  rdi, [rel dhcp_request_buf]
    mov  esi, [rel dhcp_wire_request_len]
    call dhcp_wire_send_payload
    test rax, rax
    jnz  .renew_rearm
    mov  byte [rel dhcp_wire_m_request], 1
.renew_rearm:
    call dhcp_wire_arm_retry
    jmp  .done

.fallback:
    call dhcp_wire_fallback
.done:
    call dhcp_wire_lock_release
    pop  rbx
    ret

; A new transaction frontier prevents an old initial/renewal ACK being accepted
; in a later phase. The transport unicasts T1 to the selected server and
; broadcasts T2; both use the retained lease as ciaddr and IPv4 source.
dhcp_wire_renew_request:
    inc  dword [rel dhcp_wire_generation]
    mov  eax, [rel dhcp_wire_xid]
    add  eax, [rel dhcp_wire_generation]
    jnz  .xid
    inc  eax
.xid:
    mov  [rel dhcp_wire_xid], eax
    mov  [rel dhcp_request_buf + DHCP_XID], eax
    mov  eax, [rel dhcp_ack_yiaddr]
    mov  [rel dhcp_request_buf + 12], eax      ; ciaddr, not Requested-IP
    mov  word [rel dhcp_request_buf + 10], 0
    mov  byte [rel dhcp_request_buf + DHCP_OPTIONS + 10], OPT_END ; keep 53 + the 55 list
    mov  dword [rel dhcp_wire_request_len], DHCP_OPTIONS + 11
    ret

dhcp_wire_fallback:
    mov  byte [rel dhcp_wire_state], DHCP_WS_FALLBACK
    mov  byte [rel dhcp_wire_no_server], 0
    mov  qword [rel dhcp_wire_retry_tsc], 0
    mov  qword [rel dhcp_wire_t1_tsc], 0
    mov  qword [rel dhcp_wire_t2_tsc], 0
    mov  qword [rel dhcp_wire_expire_tsc], 0
    mov  dword [rel dhcp_ack_yiaddr], 0
    mov  dword [rel dhcp_ack_mask_v], 0
    mov  dword [rel dhcp_ack_gw_v], 0
    mov  dword [rel dhcp_ack_dns_v], 0
    mov  dword [rel dhcp_ack_ntp_v], 0
    mov  dword [rel dhcp_ack_lease_s], 0
    mov  dword [rel dhcp_ack_t1_s], 0
    mov  dword [rel dhcp_ack_t2_s], 0
    ret

dhcp_wire_arm_retry:
    call tsc_now
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jnz  .scaled
    mov  rdx, 1000000
.scaled:
    mov  ecx, DHCP_RETRY_MS
    cmp  byte [rel dhcp_wire_no_server], 0
    je   .have_retry_ms
    mov  ecx, DHCP_FAULT_WAIT_MS
.have_retry_ms:
    imul rdx, rcx
    add  rax, rdx
    mov  [rel dhcp_wire_retry_tsc], rax
    ret

; Arm absolute lease deadlines from the ACK's host-order seconds. This is the
; scale-1 T1/T2 seam: the same idle tick that advances DORA advances renewal and
; rebind, with no timer callback or backend-specific path to retrofit later.
dhcp_wire_arm_lease:
    push rbx
    push r12
    call tsc_now
    mov  rbx, rax
    mov  r12, [rel tsc_khz]
    test r12, r12
    jnz  .khz_ready
    mov  r12, 1000000
.khz_ready:
    mov  ecx, [rel dhcp_ack_t1_s]
    call .deadline
    mov  [rel dhcp_wire_t1_tsc], rax
    mov  ecx, [rel dhcp_ack_t2_s]
    call .deadline
    mov  [rel dhcp_wire_t2_tsc], rax
    mov  ecx, [rel dhcp_ack_lease_s]
    call .deadline
    mov  [rel dhcp_wire_expire_tsc], rax
    mov  qword [rel dhcp_wire_retry_tsc], 0
    pop  r12
    pop  rbx
    ret
; ECX=seconds -> RAX=now+seconds, saturated: a long/infinite lease on a fast
; TSC must never wrap into an already-expired or early deadline.
.deadline:
    mov  eax, ecx
    mov  ecx, 1000
    mul  rcx
    mul  r12
    test rdx, rdx
    jnz  .saturate
    add  rax, rbx
    jc   .saturate
    ret
.saturate:
    mov  rax, -1
    ret

; Called only after the command layer installed yiaddr and successfully armed
; a gateway ARP (or, for a public lease with no router, sent the announcement of
; the leased address, RCQ-10 S2). Thus dhcp.ack.bound means usable configuration,
; not merely that a syntactically valid ACK reached the parser.
dhcp_wire_mark_bound:
    call dhcp_wire_lock_acquire
    call dhcp_wire_arm_lease
    mov  byte [rel dhcp_wire_no_server], 0
    mov  byte [rel dhcp_wire_m_ack], 1
    call dhcp_wire_lock_release
    ret

; RDI=BOOTP payload, ESI=len. Build Ethernet/IPv4/UDP 68->67.
; RFC 2131 4.4.5: T1 uses the selected server, T2 broadcasts. An unresolved
; T1 neighbor defers DHCP until the ordinary retry; T2 never depends on ARP.
dhcp_wire_send_payload:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  ebx, esi
    test r12, r12
    jz   .fail
    cmp  ebx, DHCP_OPTIONS
    jb   .fail
    cmp  ebx, 1472 - 28
    ja   .fail
    mov  r13d, ebx                     ; original BOOTP/options length
    cmp  ebx, DHCP_MIN_BOOTP_BYTES
    jae  .wire_length_ready
    mov  ebx, DHCP_MIN_BOOTP_BYTES     ; advertised IPv4/UDP lengths include pad
.wire_length_ready:
    xor  r14d, r14d                    ; initial DORA uses source 0.0.0.0
    mov  r15d, 0xffffffff
    lea  rdi, [rel dhcp_wire_frame]
    mov  dword [rdi + 0], 0xffffffff
    mov  word [rdi + 4], 0xffff
    cmp  byte [rel dhcp_wire_state], DHCP_WS_RENEWING
    je   .renew_route
    cmp  byte [rel dhcp_wire_state], DHCP_WS_REBINDING
    jne  .ethernet_ready
    mov  r14d, [rel dhcp_ack_yiaddr]
    test r14d, r14d
    jz   .fail
    jmp  .ethernet_ready
.renew_route:
    mov  r14d, [rel dhcp_ack_yiaddr]
    test r14d, r14d
    jz   .fail
    call dhcp_wire_renew_neighbor
    test rax, rax
    jz   .fail
    lea  rdi, [rel dhcp_wire_frame]
    mov  edx, [rax]
    mov  [rdi], edx
    mov  dx, [rax + 4]
    mov  [rdi + 4], dx
    mov  r15d, [rel dhcp_parsed_serverid]
.ethernet_ready:
    lea  rdi, [rel dhcp_wire_frame]
    mov  eax, [rel dhcp_wire_mac]
    mov  [rdi + 6], eax
    mov  ax, [rel dhcp_wire_mac + 4]
    mov  [rdi + 10], ax
    mov  byte [rdi + 12], 0x08
    mov  byte [rdi + 13], 0x00
    lea  rdi, [rel dhcp_wire_frame + 14]
    mov  byte [rdi + 0], 0x45
    mov  byte [rdi + 1], 0
    lea  eax, [rbx + 28]
    mov  [rdi + 2], ah
    mov  [rdi + 3], al
    mov  dword [rdi + 4], 0
    mov  byte [rdi + 8], 64
    mov  byte [rdi + 9], 17
    mov  word [rdi + 10], 0
    mov  [rdi + 12], r14d
    mov  [rdi + 16], r15d
    lea  rdi, [rel dhcp_wire_frame + 14]
    mov  esi, 20
    call net_cksum16
    lea  rdi, [rel dhcp_wire_frame + 14]
    mov  [rdi + 10], ah
    mov  [rdi + 11], al
    lea  rdi, [rel dhcp_wire_frame + 34]
    mov  byte [rdi + 0], 0
    mov  byte [rdi + 1], 68
    mov  byte [rdi + 2], 0
    mov  byte [rdi + 3], 67
    lea  eax, [rbx + 8]
    mov  [rdi + 4], ah
    mov  [rdi + 5], al
    mov  word [rdi + 6], 0
    lea  rdi, [rel dhcp_wire_frame + 42]
    mov  rsi, r12
    mov  edx, r13d                     ; copy only initialized caller bytes
    call memcpy
    cmp  ebx, r13d
    jbe  .padding_done
    lea  rdi, [rel dhcp_wire_frame + 42]
    add  rdi, r13
    xor  esi, esi
    mov  edx, ebx
    sub  edx, r13d
    call memset                       ; never leak old frame bytes after END
.padding_done:
    lea  rsi, [rel dhcp_wire_frame]
    lea  edx, [ebx + 42]
    lock inc qword [rel dhcp_wire_tx_started] ; before backend entry: attempts below count returns
    call dhcp_wire_tx_owned
    lock inc qword [rel dhcp_wire_tx_attempts]
    test rax, rax
    jnz  .tx_failed
    lock inc qword [rel dhcp_wire_tx_ok]
    jmp  .out
.tx_failed:
    lock inc qword [rel dhcp_wire_tx_fail]
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RSI=frame, EDX=length. Both DHCP and its ARP resolution use this exact owner.
dhcp_wire_tx_owned:
    ; RX accepts only dhcp_wire_owner_handle. Do not send through the global
    ; priority selector: it can pick a different NIC after this lease starts.
    mov  rdi, [rel dhcp_wire_owner_handle]
    test rdi, rdi
    jz   .tx_drop
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .tx_drop
    mov  r10, [rdi + dev.ops]
    test r10, r10
    jz   .tx_drop
    mov  r11, [r10 + netdev_ops.tx]
    test r11, r11
    jz   .tx_drop
    jmp  r11                          ; retain caller's ABI alignment
.tx_drop:
    mov  rax, -1
    ret

; RAX=next-hop MAC pointer or 0 (defer). Caller holds dhcp_wire_lock.
; The existing cache is populated by solicited ARP on the public owner. Keep
; DHCP's owner for the solicitation too; udp4_arp_request selects globally.
dhcp_wire_renew_neighbor:
    push rbx
    mov  eax, [rel dhcp_parsed_serverid]
    bswap eax
    call dhcp_wire_unicast_ip
    test eax, eax
    jnz  .defer
    mov  ebx, [rel dhcp_parsed_serverid]
    mov  eax, ebx
    xor  eax, [rel dhcp_ack_yiaddr]
    and  eax, [rel dhcp_ack_mask_v]
    jz   .next_hop
    mov  ebx, [rel dhcp_ack_gw_v]
    test ebx, ebx
    jz   .defer
.next_hop:
    mov  edi, ebx
    call arp_cache_lookup
    test rax, rax
    jz   .solicit
    add  rax, 8                       ; arp_cache entry E_MAC
    pop  rbx
    ret
.solicit:
    mov  edi, ebx
    call arp_pending_note
    lea  rdi, [rel dhcp_wire_frame]
    mov  dword [rdi], 0xffffffff
    mov  word [rdi + 4], 0xffff
    mov  eax, [rel dhcp_wire_mac]
    mov  [rdi + 6], eax
    mov  [rdi + 22], eax
    mov  ax, [rel dhcp_wire_mac + 4]
    mov  [rdi + 10], ax
    mov  [rdi + 26], ax
    mov  word [rdi + 12], 0x0608
    mov  dword [rdi + 14], 0x00080100
    mov  dword [rdi + 18], 0x01000406
    mov  eax, [rel dhcp_ack_yiaddr]
    mov  [rdi + 28], eax
    mov  dword [rdi + 32], 0
    mov  word [rdi + 36], 0
    mov  [rdi + 38], ebx
    add  rdi, 42
    xor  esi, esi
    mov  edx, 18
    call memset
    lea  rsi, [rel dhcp_wire_frame]
    mov  edx, 60
    call dhcp_wire_tx_owned            ; ARP is not a DHCP TX counter event
.defer:
    xor  eax, eax
    pop  rbx
    ret

; Wire-only ACK route qualification; pure logic KAT/default parsing unchanged.
; Mask must be a contiguous /1../30 prefix, yiaddr/router unicast host
; addresses on that subnet, first DNS unicast. Lease clocks keep the retained
; dhcp_parse_ack defaults. RBX=payload, R13D=len; -1 refuses, 0 qualifies.
; RCQ-10 S2: the router and the DNS option are optional; each one present must
; still qualify.
dhcp_wire_ack_qualify:
    sub  rsp, 32
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_SUBNET
    call dhcp_find_option
    test rax, rax
    jz   .bad
    cmp  ecx, 4
    jne  .bad
    mov  eax, [rax]
    bswap eax
    test eax, eax
    jz   .bad
    mov  edx, eax
    not  edx
    cmp  edx, 3                             ; require network/host range + gateway
    jb   .bad
    lea  ecx, [rdx + 1]
    test ecx, edx                           ; mask must be a contiguous prefix
    jnz  .bad
    mov  [rsp + 16], eax
    mov  ecx, [rbx + DHCP_YIADDR]
    bswap ecx
    mov  [rsp + 20], ecx
    mov  eax, ecx
    call dhcp_wire_unicast_ip
    test eax, eax
    jnz  .bad
    mov  eax, [rsp + 20]
    mov  edx, [rsp + 16]
    not  edx
    and  eax, edx
    jz   .bad
    cmp  eax, edx
    je   .bad
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_ROUTER
    call dhcp_find_option
    test rax, rax
    jz   .resolver                          ; RCQ-10 S2: no router, an on-link lease
    cmp  ecx, 4
    jb   .bad
    mov  eax, [rax]
    bswap eax
    mov  [rsp + 24], eax
    call dhcp_wire_unicast_ip
    test eax, eax
    jnz  .bad
    mov  eax, [rsp + 24]
    cmp  eax, [rsp + 20]
    je   .bad
    xor  eax, [rsp + 20]
    test eax, [rsp + 16]
    jnz  .bad                              ; gateway must be on the learned subnet
    mov  eax, [rsp + 24]
    mov  edx, [rsp + 16]
    not  edx
    and  eax, edx
    jz   .bad
    cmp  eax, edx
    je   .bad
.resolver:
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_DNS
    call dhcp_find_option
    test rax, rax
    jz   .ok                                ; RCQ-10 S2: no resolver offered
    cmp  ecx, 4
    jb   .bad
    mov  eax, [rax]
    bswap eax
    call dhcp_wire_unicast_ip
    test eax, eax
    jnz  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    add  rsp, 32
    ret

; Caller holds dhcp_wire_lock. EAX=1 and FALLBACK when the armed lease has
; expired (or none is armed); EAX=0 while it is still live.
dhcp_wire_lease_expired:
    call tsc_now
    mov  rdx, [rel dhcp_wire_expire_tsc]
    test rdx, rdx
    jz   .expired
    cmp  rax, rdx
    jae  .expired
    xor  eax, eax
    ret
.expired:
    call dhcp_wire_fallback
    mov  eax, 1
    ret

; EAX=host-order IPv4 -> 0 supported unicast / -1 unspecified/loop/multicast.
dhcp_wire_unicast_ip:
    shr  eax, 24
    test eax, eax
    jz   .bad
    cmp  eax, 127
    je   .bad
    cmp  eax, 224
    jae  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; RBX=payload,R13D=len. Require selected server except fresh REBINDING phase.
; Traverse the entire option tail, including malformed neighbors, for NAK too.
dhcp_wire_server_qualify:
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_SERVERID
    call dhcp_find_option
    test rax, rax
    jz   .bad
    cmp  ecx, 4
    jne  .bad
    mov  eax, [rax]
    test eax, eax
    jz   .bad
    cmp  byte [rel dhcp_wire_state], DHCP_WS_REBINDING
    je   .tail
    cmp  eax, [rel dhcp_parsed_serverid]
    jne  .bad
.tail:
    lea  rdi, [rbx + DHCP_OPTIONS]
    lea  rsi, [rbx + r13]
.walk:
    cmp  rdi, rsi
    jae  .bad                             ; wire responses require a complete END
    cmp  byte [rdi], OPT_END
    je   .ok
    cmp  byte [rdi], OPT_PAD
    je   .pad
    call safe_tlv_u8_view
    test eax, eax
    jnz  .bad
    mov  rdi, rsi
    lea  rsi, [rbx + r13]
    jmp  .walk
.pad:
    inc  rdi
    jmp  .walk
.ok:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; RDI=full Ethernet frame, RSI=len, RDX=ingress netdev handle.
; Returns 0=not DHCP, 1=consumed, 2=ACK accepted (lease fields atomically
; available in dhcp_ack_*). Frames from a non-owner handle are not consumed.
dhcp_wire_ingest:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rsi
    mov  r14, rdx                            ; ingress handle survives shared validators
    call dhcp_wire_lock_acquire
    xor  r12d, r12d
    cmp  byte [rel dhcp_wire_state], 0
    je   .out
    test r14, r14
    jz   .out
    cmp  r14, [rel dhcp_wire_owner_handle]
    jne  .out
    lock inc qword [rel dhcp_wire_rx_frames]
    mov  rdi, rbx
    mov  rsi, r13
    xor  edx, edx
    mov  ecx, 42                            ; Ethernet + fixed IPv4 + UDP header
    call safe_span_validate
    test eax, eax
    jnz  .out
    cmp  byte [rbx + 12], 0x08
    jne  .out
    cmp  byte [rbx + 13], 0x00
    jne  .out
    cmp  byte [rbx + 14], 0x45
    jne  .out
    cmp  byte [rbx + 23], 17
    jne  .out
    mov  al, [rbx + 20]
    and  al, 0xbf                            ; DHCP path accepts only unfragmented IPv4
    jnz  .out
    cmp  byte [rbx + 21], 0
    jne  .out
    movzx r10d, byte [rbx + 16]
    shl  r10d, 8
    mov  r10b, [rbx + 17]                   ; IPv4 total length, read once
    cmp  r10d, 28 + DHCP_OPTIONS
    jb   .out
    mov  rdi, rbx
    mov  rsi, r13
    mov  edx, 14
    mov  ecx, r10d
    call safe_span_validate
    test eax, eax
    jnz  .out                               ; declared IPv4 packet exceeds frame
    cmp  word [rbx + 34], 0x4300            ; source port 67
    jne  .out
    cmp  word [rbx + 36], 0x4400            ; destination port 68
    jne  .out
    lock inc qword [rel dhcp_wire_rx_port68]
    movzx r11d, byte [rbx + 38]
    shl  r11d, 8
    mov  r11b, [rbx + 39]                   ; UDP length, read once
    cmp  r11d, 8 + DHCP_OPTIONS
    jb   .out
    mov  eax, r10d
    sub  eax, 20                            ; enclosing IPv4 payload
    cmp  r11d, eax
    ja   .out
    sub  r11d, 8                            ; DHCP payload length
    mov  rdi, rbx
    mov  rsi, r13
    mov  edx, 42
    mov  ecx, r11d
    call safe_span_validate
    test eax, eax
    jnz  .out
    mov  rbx, rdx                           ; validated DHCP payload
    cmp  byte [rbx + DHCP_OP], 2
    jne  .out
    cmp  byte [rbx + 1], 1
    jne  .out
    cmp  byte [rbx + 2], 6
    jne  .out
    cmp  dword [rbx + DHCP_MAGIC], DHCP_MAGIC_LE
    jne  .out
    cmp  dword [rbx + DHCP_XID], 0
    je   .out
    mov  edx, [rel dhcp_wire_xid]
    cmp  [rbx + DHCP_XID], edx
    jne  .out
    mov  edx, [rel dhcp_wire_mac]
    cmp  [rbx + 28], edx
    jne  .out
    mov  dx, [rel dhcp_wire_mac + 4]
    cmp  [rbx + 32], dx
    jne  .out
    lock inc qword [rel dhcp_wire_rx_xid_ok]
    cmp  byte [rel dhcp_wire_no_server], 0
    jne  .consumed                         ; negative gate: suppress valid replies
    mov  r13d, r11d                         ; payload len
    ; RX drains before the idle timeout poll. The final initial-DORA attempt
    ; must therefore enforce the same cutoff here: a late OFFER cannot start
    ; another REQUEST and a late ACK cannot install a lease after timeout.
    ; Earlier retry deadlines are not terminal; renewal/rebind use the armed
    ; lease deadline below, independently of their transmit attempt count.
    movzx eax, byte [rel dhcp_wire_state]
    cmp  eax, DHCP_WS_SELECTING
    je   .initial_deadline
    cmp  eax, DHCP_WS_REQUESTING
    jne  .message_type
.initial_deadline:
    cmp  qword [rel dhcp_wire_tx_attempts], DHCP_MAX_ATTEMPTS
    jb   .message_type
    call tsc_now
    cmp  rax, [rel dhcp_wire_retry_tsc]
    jb   .message_type
    call dhcp_wire_fallback
    jmp  .consumed
.message_type:
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_MSGTYPE
    call dhcp_find_option
    test rax, rax
    jz   .out
    cmp  ecx, 1                             ; option 53 has exactly one value byte
    jne  .out
    cmp  byte [rax], MSG_OFFER
    je   .offer
    cmp  byte [rax], MSG_ACK
    je   .ack
    cmp  byte [rax], MSG_NAK
    je   .nak
    jmp  .out
.offer:
    cmp  byte [rel dhcp_wire_state], 1
    jne  .consumed
    cmp  dword [rel dhcp_wire_preferred_server], 0
    je   .offer_parse
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_SERVERID
    call dhcp_find_option
    test rax, rax
    jz   .consumed
    cmp  ecx, 4
    jne  .consumed
    mov  eax, [rax]
    cmp  eax, [rel dhcp_wire_preferred_server]
    jne  .consumed                         ; no parsed-state publication or REQUEST
.offer_parse:
    mov  rdi, rbx
    mov  esi, r13d
    call dhcp_parse_offer
    test rax, rax
    jnz  .consumed
    mov  byte [rel dhcp_wire_m_offer], 1
    lea  rdi, [rel dhcp_request_buf]
    call dhcp_build_request
    mov  [rel dhcp_wire_request_len], eax
    mov  byte [rel dhcp_request_buf + 10], 0x80
    mov  eax, [rel dhcp_wire_mac]
    mov  [rel dhcp_request_buf + 28], eax
    mov  ax, [rel dhcp_wire_mac + 4]
    mov  [rel dhcp_request_buf + 32], ax
    mov  byte [rel dhcp_wire_state], DHCP_WS_REQUESTING
    lea  rdi, [rel dhcp_request_buf]
    mov  esi, [rel dhcp_wire_request_len]
    call dhcp_wire_send_payload
    test rax, rax
    jnz  .request_sent
    mov  byte [rel dhcp_wire_m_request], 1
.request_sent:
    call dhcp_wire_arm_retry
    jmp  .consumed
.ack:
    movzx eax, byte [rel dhcp_wire_state]
    cmp  eax, DHCP_WS_REQUESTING
    je   .ack_state_ok
    cmp  eax, DHCP_WS_RENEWING
    je   .ack_lease_live
    cmp  eax, DHCP_WS_REBINDING
    jne  .consumed
.ack_lease_live:
    call dhcp_wire_lease_expired            ; a late reply cannot revive it
    test eax, eax
    jnz  .consumed
.ack_state_ok:
    call dhcp_wire_server_qualify
    test rax, rax
    jnz  .consumed
    mov  eax, [rbx + DHCP_YIADDR]
    cmp  eax, [rel dhcp_parsed_yiaddr]
    jne  .consumed                         ; do not borrow another offered address
    call dhcp_wire_ack_qualify
    test rax, rax
    jnz  .consumed
    mov  rdi, rbx
    mov  esi, r13d
    call dhcp_parse_ack
    test rax, rax
    jnz  .consumed
    ; A rebinding ACK may come from a different server; renew with it later.
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, OPT_SERVERID
    call dhcp_find_option
    mov  eax, [rax]                        ; qualified above: present, 4 bytes
    mov  [rel dhcp_parsed_serverid], eax
    mov  byte [rel dhcp_wire_state], DHCP_WS_BOUND
    mov  r12d, 2
    jmp  .out
.nak:
    movzx eax, byte [rel dhcp_wire_state]
    cmp  eax, DHCP_WS_REQUESTING
    je   .nak_state
    cmp  eax, DHCP_WS_RENEWING
    je   .nak_lease
    cmp  eax, DHCP_WS_REBINDING
    jne  .consumed
.nak_lease:
    call dhcp_wire_lease_expired
    test eax, eax
    jnz  .consumed                         ; expiry already owns the outcome
.nak_state:
    call dhcp_wire_server_qualify
    test rax, rax
    jnz  .consumed
    call dhcp_wire_fallback
.consumed:
    mov  r12d, 1
.out:
    mov  eax, r12d
    call dhcp_wire_lock_release
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; parsed-OFFER state (captured at runtime, echoed into the REQUEST)
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_dhcp_0 0
dhcp_parsed_xid:      resd 1
dhcp_parsed_yiaddr:   resd 1
dhcp_parsed_serverid: resd 1
; parsed-ACK lease fields
dhcp_ack_yiaddr:      resd 1
dhcp_ack_mask_v:      resd 1
dhcp_ack_gw_v:        resd 1
dhcp_ack_dns_v:       resd 1
dhcp_ack_lease_s:     resd 1
dhcp_ack_t1_s:        resd 1
dhcp_ack_t2_s:        resd 1
dhcp_ack_ntp_v:       resd 1  ; first option-42 server, 0 = none (clock unit)
; the built REQUEST + its length
dhcp_request_len:     resd 1
dhcp_request_buf:     resb 300
%endmacro
WDATA_BSS_DEFER WDATA_net_dhcp_0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_dhcp 0
align 8
dhcp_wire_retry_tsc:  dq 0
dhcp_wire_t1_tsc:     dq 0
dhcp_wire_t2_tsc:     dq 0
dhcp_wire_expire_tsc: dq 0
dhcp_wire_generation: dd 0
align 8
dhcp_wire_owner_handle: dq 0
dhcp_wire_tx_started:  dq 0
dhcp_wire_tx_attempts: dq 0
dhcp_wire_tx_ok:       dq 0
dhcp_wire_tx_fail:     dq 0
dhcp_wire_rx_frames:   dq 0
dhcp_wire_rx_port68:   dq 0
dhcp_wire_rx_xid_ok:   dq 0
dhcp_wire_xid:        dd 0
dhcp_wire_payload_len: dd 0
dhcp_wire_request_len: dd 0
dhcp_wire_state:      db 0
dhcp_wire_lock:       db 0
dhcp_wire_preferred_server: dd 0
dhcp_wire_no_server:  db 0
dhcp_wire_m_discover: db 0
dhcp_wire_m_offer:    db 0
dhcp_wire_m_request:  db 0
dhcp_wire_m_ack:      db 0
dhcp_wire_mac:        times 6 db 0
align 8
dhcp_wire_payload:    times 300 db 0
dhcp_wire_frame:      times 1514 db 0
%endmacro
WDATA_DEFER WDATA_dhcp

dhcp_ipbuf:   times 20 db 0                  ; "255.255.255.255\0"
dhcp_xidbuf:  times 12 db 0                  ; "0xXXXXXXXX\0"
dhcp_hexchars: db "0123456789abcdef"

; --- TOURNAMENT 1307: dhcp_find_option outcome telemetry + KAT vectors --------
; live outcome counters (incremented by every dhcp_find_option call, forever)
dhcp_fo_ct_find: dd 0                        ; option located, value ptr returned
dhcp_fo_ct_miss: dd 0                        ; clean not-found (END / end-of-frame)
dhcp_fo_ct_rej:  dd 0                        ; malformed/hostile input contained (aggregate)
; per-reason reject breakdown — KEEP CONTIGUOUS + IN THIS ORDER (the KAT snapshots
; the block by index: 0=null 1=short 2=wrap 3=nolen 4=trunc 5=toobig 6=fuel)
dhcp_fo_rej_null:   dd 0                      ; NULL frame pointer
dhcp_fo_rej_short:  dd 0                      ; len too short for any option
dhcp_fo_rej_wrap:   dd 0                      ; frame+len wrapped the address space
dhcp_fo_rej_nolen:  dd 0                      ; tag present but no length byte
dhcp_fo_rej_trunc:  dd 0                      ; option length runs past the frame end
dhcp_fo_rej_toobig: dd 0                      ; absurd len contained before the walk
dhcp_fo_rej_fuel:   dd 0                      ; last-resort anti-livelock ceiling hit
dhcp_fo_last_rej:   dd 0                      ; live: last reject reason code (1..7), 0=none
dhcp_fo_kat_c0:  dd 0, 0, 0                  ; KAT-entry snapshot (find/miss/rej)
dhcp_fo_kat_r0:  dd 0, 0, 0, 0, 0, 0, 0      ; KAT-entry snapshot of the 7 reason counters
dhcp_fo_kat_e_rej: dd 0                       ; envelope-window aggregate-rej snapshot
dhcp_fo_kat_e_tb:  dd 0                       ; envelope-window toobig snapshot

; --- TOURNAMENT 1410: dhcp_parse_offer outcome telemetry (durability observability) --
dhcp_po_ct_ok:   dd 0                         ; OFFER parsed + committed atomically
dhcp_po_ct_rej:  dd 0                         ; malformed/hostile input contained (aggregate)
; per-reason reject breakdown — KEEP CONTIGUOUS + IN THIS ORDER (the shared .rej + the
; KAT index the block by (reason-1): 0=null 1=short 2=toobig 3=wrap 4=magic 5=op
; 6=msgtype 7=yiaddr 8=serverid)
dhcp_po_rej_null:     dd 0
dhcp_po_rej_short:    dd 0
dhcp_po_rej_toobig:   dd 0
dhcp_po_rej_wrap:     dd 0
dhcp_po_rej_magic:    dd 0
dhcp_po_rej_op:       dd 0
dhcp_po_rej_msgtype:  dd 0
dhcp_po_rej_yiaddr:   dd 0
dhcp_po_rej_serverid: dd 0
dhcp_po_last_rej:     dd 0                     ; live: last reject reason code (1..9), 0=none
dhcp_po_kat_c0:  dd 0, 0                       ; KAT-entry snapshot (ok, rej)
dhcp_po_kat_r0:  dd 0, 0, 0, 0, 0, 0, 0, 0, 0  ; KAT-entry snapshot of the 9 reason counters
dhcp_po_kat_good: dd 0, 0, 0                   ; good-OFFER parsed state (xid, yiaddr, serverid)

; --- TOURNAMENT 1411: dhcp_wr_u8 KAT vectors + scratch (most-durable) ----------
; Fixed-width 8-byte records: dd value(32-bit; only 0..255 legal), db exp_len,
; db expected ASCII[0..2] (unused trailing bytes are 0, never read past exp_len).
; A 32-bit value field lets the SAME table exercise the boundary octets AND lets
; the clamp table below feed genuinely out-of-range values.
align 4
dhcp_wu_kat_vec:
    dd 0
    db 1, '0',  0,   0                           ; 1-digit: "0" (not "00")
    dd 9
    db 1, '9',  0,   0                           ; 1-digit: "9"
    dd 10
    db 2, '1', '0',  0                           ; 2-digit: "10" (no leading zero)
    dd 87
    db 2, '8', '7',  0                           ; 2-digit: a real IP octet
    dd 99
    db 2, '9', '9',  0                           ; 2-digit boundary
    dd 100
    db 3, '1', '0', '0'                          ; 3-digit, embedded-zero tens+units
    dd 150
    db 3, '1', '5', '0'                          ; 3-digit, the offered-yiaddr octet
    dd 205
    db 3, '2', '0', '5'                          ; 3-digit, embedded-zero tens
    dd 255
    db 3, '2', '5', '5'                          ; 3-digit boundary (max legal)
dhcp_wu_kat_vec_end:
DHCP_WU_KAT_N equ (dhcp_wu_kat_vec_end - dhcp_wu_kat_vec) / 8

; Clamp table: OUT-OF-RANGE / dirty-high 32-bit inputs. Each must fold to its low
; byte (256->0, 0x1FF->255, 1000->232, 0xFFFFFF05->5) and emit only digits.
align 4
dhcp_wu_clamp_vec:
    dd 256                                       ; &0xFF = 0
    dd 0x1FF                                      ; &0xFF = 255
    dd 1000                                       ; &0xFF = 232
    dd 0xFFFFFF05                                 ; dirty high dword, low byte = 5
dhcp_wu_clamp_vec_end:
DHCP_WU_CLAMP_N equ (dhcp_wu_clamp_vec_end - dhcp_wu_clamp_vec) / 4

dhcp_wu_scratch:  times 8 db 0                   ; sentinel-fenced write target
dhcp_wu_ref:      times 8 db 0                   ; clean-byte reference for clamp eq

; F1: pad run + zero-length TLV + opt50 + END + a TLV hidden behind the END.
dhcp_fo_f1:
    times DHCP_OPTIONS db 0                  ; BOOTP header area (walk ignores it)
    db OPT_PAD, OPT_PAD, OPT_PAD             ; +240..242: pad run
    db 7, 0                                  ; +243: zero-LENGTH option (legal TLV)
    db OPT_REQIP, 4, 192, 0, 2, 150         ; +245: opt50 (value at +247)
    db OPT_END                               ; +251: terminator
    db 99, 1, 0xAA                           ; +252: valid TLV BEHIND the END —
dhcp_fo_f1_end:                              ;       must stay invisible
DHCP_FO_F1_LEN equ dhcp_fo_f1_end - dhcp_fo_f1

; F2: option declaring a 200-byte value on a frame that ends 4 bytes later.
dhcp_fo_f2:
    times DHCP_OPTIONS db 0
    db OPT_REQIP, 200, 1, 2, 3, 4            ; declared len runs far past the end
dhcp_fo_f2_end:
DHCP_FO_F2_LEN equ dhcp_fo_f2_end - dhcp_fo_f2

; F3: a well-formed TLV, then a bare tag as the LAST byte (no length byte).
dhcp_fo_f3:
    times DHCP_OPTIONS db 0
    db OPT_MSGTYPE, 1, MSG_ACK               ; traversed without matching
    db OPT_REQIP                             ; bare tag, frame ends here
dhcp_fo_f3_end:
DHCP_FO_F3_LEN equ dhcp_fo_f3_end - dhcp_fo_f3

; F4: single option flush against the EXACT frame end, no END terminator.
dhcp_fo_f4:
    times DHCP_OPTIONS db 0
    db OPT_MSGTYPE, 1, MSG_OFFER             ; value's last byte == frame's last byte
dhcp_fo_f4_end:
DHCP_FO_F4_LEN equ dhcp_fo_f4_end - dhcp_fo_f4

str_dhcp_fo_pre:  db "[PAOS64] P4 net dhcp: find_option KAT+GUARD PASS (bit-exact finds, pad/zero-len/END-stop/flush-end walk, NULL/short/trunc/no-len contained, counter deltas exact) finds+=", 0
str_dhcp_fo_miss: db " miss+=", 0
str_dhcp_fo_rej:  db " rej+=", 0
str_dhcp_fo_post: db " [tourn.dhcp_find_option.kat] [tourn.dhcp_find_option.guard]", 13, 10, 0
str_dhcp_fo_rsn:  db "[PAOS64] P4 net dhcp: find_option reject-reason breakdown exact (null=1 short=2 wrap=0 nolen=1 trunc=1 toobig=0 fuel=0; per-reason + last-reason telemetry live) [tourn.dhcp_find_option.reasons]", 13, 10, 0
str_dhcp_fo_env:  db "[PAOS64] P4 net dhcp: find_option failure envelope widened — absurd len (256MiB) contained BEFORE the walk, counted as toobig, no OOB read / no fault [tourn.dhcp_find_option.envelope]", 13, 10, 0
str_dhcp_fo_fail: db "[PAOS64] P4 net dhcp: find_option KAT FAIL [tourn.dhcp_find_option.kat.fail] step=", 0

; TOURNAMENT 1407 — dhcp_parse_ack KAT markers
str_dhcp_pa_pre:   db "[PAOS64] P4 net dhcp: parse_ack KAT PASS (single-pass ACK parse; bad-magic/short/wrong-type/missing-opt contained) ack_yiaddr=", 0
str_dhcp_pa_post:  db " [tourn.dhcp_parse_ack.kat] [tourn.dhcp_parse_ack.guard]", 13,10,0
str_dhcp_pa_fail:  db "[PAOS64] P4 net dhcp: parse_ack KAT FAIL [tourn.dhcp_parse_ack.kat.fail] step=", 0

; TOURNAMENT 1410 — dhcp_parse_offer KAT markers (durability variant: 3 honest markers)
str_dhcp_po_pre:    db "[PAOS64] P4 net dhcp: parse_offer KAT PASS (atomic single-pass; xid/yiaddr/server-id bit-exact; null/short/toobig/magic/op/msgtype/yiaddr/server-id all contained) parsed_yiaddr=", 0
str_dhcp_po_post:   db " [tourn.dhcp_parse_offer.kat]", 13,10,0
str_dhcp_po_guard:  db "[PAOS64] P4 net dhcp: parse_offer GUARD PASS (ok+=1, rej+=9; per-reason breakdown null=1 short=1 toobig=1 wrap=0 magic=1 op=1 msgtype=2 yiaddr=1 server-id=1) [tourn.dhcp_parse_offer.guard]", 13,10,0
str_dhcp_po_atomic: db "[PAOS64] P4 net dhcp: parse_offer ATOMIC PASS (a rejected frame — missing opt54 or zero yiaddr — leaves dhcp_parsed_* byte-identical; no torn write, unlike the 3-pass baseline) [tourn.dhcp_parse_offer.atomic]", 13,10,0
str_dhcp_po_fail:   db "[PAOS64] P4 net dhcp: parse_offer KAT FAIL [tourn.dhcp_parse_offer.kat.fail] step=", 0

; TOURNAMENT 1411 — dhcp_wr_u8 markers (most-durable: correctness + 2 durability props)
str_dhcp_wu_kat:   db "[PAOS64] P4 net dhcp: wr_u8 KAT PASS (8 vectors 0/9/10/87/99/100/150/205/255 emitted bytes exact across 1/2/3-digit + embedded-zero + no-leading-zero paths) [tourn.dhcp_wr_u8.kat]", 13,10,0
str_dhcp_wu_guard: db "[PAOS64] P4 net dhcp: wr_u8 GUARD PASS (bounded write: RDI advance == digit count exactly + 0xEE sentinel one-past-end untouched for every vector; no over/under-run) [tourn.dhcp_wr_u8.guard]", 13,10,0
str_dhcp_wu_clamp: db "[PAOS64] P4 net dhcp: wr_u8 CLAMP PASS (out-of-range 256/0x1FF/1000/0xFFFFFF05 folded to low byte -> only ASCII digits, dirty-high output byte-identical to clean byte; non-digit contained) [tourn.dhcp_wr_u8.clamp]", 13,10,0
str_dhcp_wu_fail:  db "[PAOS64] P4 net dhcp: wr_u8 KAT FAIL [tourn.dhcp_wr_u8.kat.fail] rec=", 0

str_dhcp_pass:     db "[PAOS64] P4 net dhcp: OFFER->REQUEST build + ACK parse selftest PASS [dhcp.client.logic]", 13,10,0
str_dhcp_kat_discover: db "[PAOS64] P2 DHCP: DISCOVER broadcast [dhcp.discover.tx]", 13,10,0
str_dhcp_kat_offer:    db "[PAOS64] P2 DHCP: OFFER selected [dhcp.offer.rx]", 13,10,0
str_dhcp_kat_request:  db "[PAOS64] P2 DHCP: REQUEST sent [dhcp.request.tx]", 13,10,0
str_dhcp_kat_bound:    db "[PAOS64] P2 DHCP: ACK lease bound [dhcp.ack.bound]", 13,10,0
str_dhcp_kat_pre:  db "[PAOS64][INF][net] dhcp.kat parsed_yiaddr=", 0
str_dhcp_kat_o50:  db "  req_opt50=", 0
str_dhcp_kat_oxid: db "  offer_xid=", 0
str_dhcp_kat_rxid: db "  req_xid=", 0
str_dhcp_ack_pre:  db "[PAOS64][INF][net] dhcp.kat ack_yiaddr=", 0
str_dhcp_ack_mask: db "  mask=", 0
str_dhcp_ack_gw:   db "  gw=", 0
str_dhcp_ack_dns:  db "  dns=", 0
str_dhcp_crlf:     db 13,10,0
