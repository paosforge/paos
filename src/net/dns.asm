;; MODULE net/dns
;; LAYER 4
;; EXPORTS dns_resolver_selftest, dns_parse_response, dns_decode_name_kat, dns_parse_response_kat, dns_wr_u8_kat, dns_skip_name_kat, dns_encode_qname_kat, dns_streq_kat, dns_wire_init, dns_wire_bootstrap_arm, dns_wire_bootstrap_pending, dns_wire_configure, dns_wire_dhcp_failed, dns_wire_take_release, dns_wire_set_source, dns_wire_route_seed, dns_wire_route_snapshot, dns_wire_server_snapshot, dns_wire_tick, dns_wire_ingest, dns_resolve_start, dns_cache_get, dns_cache_snapshot, DNS_CACHE_SNAPSHOT_SIZE, DSO_LOOKUP, DSO_STATE, DSO_RESULT, DSO_IP, DSO_TIME_KNOWN, DSO_CACHE_KNOWN, DSO_NOW_MS, DSO_STORED_MS, DSO_EXPIRES_MS, DSO_REMAINING_MS, DSO_TTL_S, DSO_INITIAL_TTL_S, DSO_ROUTE_GENERATION, DSO_QUERY_GENERATION, DSO_CACHE_GENERATION, DSO_REQUEST_STATE, DSO_REASON, DSO_REQUEST_DEADLINE, DSO_SOURCE_IP, DSO_SERVER_IP, DSO_GATEWAY_IP, DSO_MASK_IP, DSO_SOURCE_MAC, DSO_CLOCK_EPOCH, DSO_NAME, DSO_ABSENT, DSO_HIT, DSO_QUEUED, DSO_ACTIVE, DSO_TIMEOUT, DSO_CANCELLED, DSO_EXPIRED, DSO_UNCACHED, DSO_CLOCK_UNKNOWN, DSO_STALE_ROUTE, DCR_NONE, DCR_EXPIRED, DCR_CLOCK, DCR_ROUTE, DCR_TTL_ZERO, DCR_OVERFLOW, DCR_EXHAUSTED, dns_request_status, dns_m_query_tx, dns_m_response_rx, dns_m_answer_a, dns_wire_state_peek, dns_wire_config_peek
;; IMPORTS boot/serial, core/lib/mem, core/lib/cksum, lib/safe_buffer, core/time, core/lock, net/arp_cache, net/netdev, core/csprng, net/tcp
;; CAPS
;; OWNER saga:net
;; LOCK: dns_wire_lock PROTECTS dns_wire_state, dns_pending_name, dns_name_tmp, dns_txid, dns_query_port, dns_query_attempts, dns_retry_ms, dns_query_entropy, dns_query_live, dns_query_live_len, dns_wire_frame, dns_server_ip, dns_source_ip, dns_gateway_ip, dns_mask_ip, dns_next_hop_ip, dns_source_mac, dns_deadline_ms, dns_arp_retry_ms, dns_bootstrap_active, dns_bootstrap_release, dns_query_started_ms, dns_cache_live, dns_cache_victim, dns_parse_frame, dns_parse_len, dns_parse_ans_cursor, dns_parse_ancount, dns_parse_ip, dns_parse_rcode, dns_rr_rdata, dns_rr_type, dns_rr_class, dns_rr_ttl, dns_rr_rdlen, dns_owner_name, dns_chain_name, dns_alias_name, dns_chain_ttl, dns_m_query_tx, dns_m_response_rx, dns_m_answer_a, dns_tcp_handle, dns_tcp_cookie_next, dns_tcp_route, dns_tcp_sent, dns_tcp_received, dns_tcp_expected, dns_tcp_finishing, dns_tcp_opened, dns_tcp_query, dns_tcp_reply, dns_requests, dns_request_generation, dns_request_active, dns_request_order, dns_request_count, dns_request_victim, dns_cache_clock_last, dns_cache_clock_sample, dns_cache_clock_known, dns_cache_clock_epoch, dns_cache_incarnation_next, dns_query_incarnation, dns_query_incarnation_next, dns_query_route_generation
; ============================================================================
; net/dns.asm — the DNS A-record query-build / response-parse LOGIC (contract
; 1047 / C10f, the qemu rung of the bare-metal 1022/1024/1025). Rides ON TOP of
; the udp/ipv4 stack proven in 1042 (DNS is a udp/53 client): given the canned
; name "example.com", BUILD an A-record query — correct QNAME label encoding
; (each label prefixed by its length byte, whole name terminated by a zero byte:
; 07 'example' 03 'com' 00 = 13 wire bytes), qtype=1(A), qclass=1(IN), a 12-byte
; header with QDCOUNT=1 — then PARSE a canned DNS RESPONSE and EXTRACT the A
; record (the 4-byte IPv4 answer), FOLLOWING the standard 0xC0 name-compression
; pointer in the answer section back to the question QNAME. This selftest uses
; no NIC; the contract-1025 live DHCP/ARP/UDP adapter follows below. The KAT is
; CONTENT-graded: it drives the real encode/parse and PRINTS the values it
; produced/read (KAT), so a stub that emits the marker without encoding/parsing
; FAILS:
;   * dns.resolver.logic — encode QNAME for "example.com" (prints qname_len read
;                          back from the real encoder), parse the canned response
;                          (prints the extracted a_ip), and DECODE the answer's
;                          compression-pointer name back to "example.com".
;   * NEGATIVE GATES     — (a) a truncated/short DNS response is bounds-checked
;                          and REJECTED (no OOB read, no crash); (b) a QNAME with
;                          a label length > 63 is rejected by the encoder (never
;                          written past the buffer); (c) a self-referential
;                          compression-pointer loop is bounded by a jump guard,
;                          so the name decoder RETURNS (does not hang). Only when
;                          every check passes are the KAT lines + marker printed;
;                          boot continues to .halt regardless (no crash).
;
; All copies go through core/lib/mem (G1). The A-record RDATA is 4 raw
; network-order octets = the dotted-quad directly, printed byte[0..3] in order.
; ============================================================================

; --- DNS header field offsets / constants (RFC 1035) ---------------------------
DNS_ID        equ 0           ; transaction id (2 bytes, big-endian)
DNS_FLAGS     equ 2           ; flags (2 bytes)
DNS_QDCOUNT   equ 4           ; question count (2 bytes, BE)
DNS_ANCOUNT   equ 6           ; answer count (2 bytes, BE)
DNS_HDRLEN    equ 12          ; fixed header size
DNS_QTYPE_A   equ 1           ; A record (IPv4)
DNS_QCLASS_IN equ 1           ; Internet class
DNS_FLAGS_RD  equ 0x0100      ; recursion-desired (query flags), stored BE below
DNS_MAX_LABEL equ 63          ; a label > 63 has the pointer bits set — illegal len
DNS_MAX_JUMPS equ 32          ; compression-pointer follow limit (loop guard)
DNS_MAX_NAME  equ 255         ; RFC 1035 name ceiling — decoded-output cap

; dns_resolver_selftest — THE 1047 acceptance gate. Encode the query for the
;   canned name, parse the canned response, decode the pointer-name, run the three
;   negative gates, and only print the KAT + marker when EVERY check passes.
;   clobbers: caller-saved; preserves rbx,r12-r15 (saved here).
dns_resolver_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---------- (1) BUILD the A-record query for "example.com" ----------
    lea  rdi, [rel dns_query_buf]
    call dns_build_query                      ; -> EAX = total query length, or -1
    cmp  eax, -1
    je   .done                                ; a valid name must encode
    mov  [rel dns_query_len], eax
    ; qname_len = encoded QNAME length = (query len) - 12 (header) - 4 (qtype+qclass)
    sub  eax, DNS_HDRLEN + 4
    mov  [rel dns_qname_len], eax

    ; ---------- (2) PARSE the canned response, extract the A record ----------
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    call dns_parse_response                    ; -> RAX = 0 ok / -1, fills dns_a_ip
    test rax, rax
    jnz  .done                                 ; a valid response must parse

    ; ---------- (3) FOLLOW the 0xC0 pointer: decode the answer name ----------
    ;   the answer NAME is a compression pointer (offset DNS_ANS_NAME_OFF) back to
    ;   the question QNAME; decoding it must reproduce "example.com".
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    mov  edx, DNS_ANS_NAME_OFF
    lea  r8, [rel dns_decoded_name]
    call dns_decode_name                       ; -> RAX = 0 ok / -1
    test rax, rax
    jnz  .done
    lea  rdi, [rel dns_decoded_name]
    lea  rsi, [rel str_dns_example]
    call dns_streq                             ; -> RAX = 1 equal / 0
    test rax, rax
    jz   .done                                 ; decoded name must be example.com

    ; ---------- (4) NEGATIVE GATE: truncated response -> rejected, no crash ------
    lea  rdi, [rel dns_response]
    mov  esi, DNS_HDRLEN + 5                    ; header + partial question only
    call dns_parse_response
    cmp  rax, -1
    jne  .done                                 ; a truncated frame MUST be rejected

    ; ---------- (5) NEGATIVE GATE: over-length label -> encoder rejects ----------
    lea  rdi, [rel dns_scratch]
    lea  rsi, [rel dns_badname]                ; a 70-char single label (> 63)
    call dns_encode_qname
    cmp  eax, -1
    jne  .done                                 ; a > 63 label MUST be rejected

    ; ---------- (6) NEGATIVE GATE: pointer loop -> decoder returns (no hang) ------
    lea  rdi, [rel dns_ptrloop]
    mov  esi, DNS_PTRLOOP_LEN
    xor  edx, edx                              ; start at offset 0 (self-pointer)
    lea  r8, [rel dns_scratch]
    call dns_decode_name
    cmp  rax, -1
    jne  .done                                 ; a self-loop MUST be bounded -> -1

    ; ---------- all checks passed: print the KAT line, then earn the marker ------
    ;   dns.kat qname_name=example.com  qname_len=13  a_ip=93.184.216.34
    lea  rdi, [rel str_dns_kat_pre]
    call serial_string
    lea  rdi, [rel str_dns_example]            ; qname_name= (the encoded name)
    call serial_string
    lea  rdi, [rel str_dns_kat_qlen]
    call serial_string
    mov  eax, [rel dns_qname_len]              ; qname_len= read back from the encoder
    call dns_print_u32
    lea  rdi, [rel str_dns_kat_aip]
    call serial_string
    lea  rsi, [rel dns_a_ip]                   ; a_ip= extracted from the response
    call dns_print_ip
    lea  rdi, [rel str_dns_crlf]
    call serial_string

    lea  rdi, [rel str_dns_pass]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dns_be16(RDI=ptr) -> EAX = 16-bit big-endian value at [RDI]. clobbers EAX,ECX.
dns_be16:
    movzx eax, byte [rdi]
    shl   eax, 8
    movzx ecx, byte [rdi + 1]
    or    eax, ecx
    ret

; dns_encode_qname(RDI=dst, RSI=ascii name, NUL-terminated) -> EAX = encoded wire
;   length (incl the terminating zero), or -1 if a label exceeds 63 bytes or the
;   whole name exceeds 255 wire bytes. Each label is prefixed by its length byte;
;   the name is terminated by a zero byte. clobbers volatiles; preserves rbx.
; TOURNAMENT 1421 (durable variant): the encoder body is byte-for-byte identical
;   for every legal caller — the ONLY additions are fault containment folded onto
;   the existing -1 reject: (a) a NULL dst/src is rejected at entry BEFORE any
;   deref (the baseline would #PF-write to address 0 / read low-memory garbage),
;   and (b) a per-BYTE total-wire bound stops a > 255 name BEFORE it overruns the
;   caller's dst buffer (the baseline only checked at each LABEL boundary, so a
;   hostile multi-label name could write up to ~64 bytes PAST the 255-byte cap
;   into the buffer before returning -1). A legal name encodes bit-for-bit as
;   before; an illegal name rejects at exactly the same boundary, now without the
;   overrun. ;durable-guard — do not remove
dns_encode_qname:
    push rbx
    test rdi, rdi
    jz   .bad                                 ; NULL dst -> contain (no #PF write)
    test rsi, rsi
    jz   .bad                                 ; NULL src -> contain (no wild read)
    mov  rbx, rdi                             ; wire base (for total-length calc)
.label:
    mov  r9, rdi                              ; reserve the length-byte slot
    inc  rdi
    xor  ecx, ecx                             ; current label length
.chars:
    mov  al, [rsi]
    test al, al
    je   .endlabel
    cmp  al, '.'
    je   .endlabel
    cmp  ecx, DNS_MAX_LABEL
    jae  .bad                                 ; label > 63 -> illegal (pointer bits)
    mov  r10, rdi
    sub  r10, rbx                             ; total wire bytes emitted so far
    cmp  r10, 255
    jae  .bad                                 ; next byte would exceed 255 -> reject pre-overrun
    mov  [rdi], al
    inc  rdi
    inc  rsi
    inc  ecx
    jmp  .chars
.endlabel:
    mov  [r9], cl                             ; write the label length
    mov  r10, rdi
    sub  r10, rbx
    cmp  r10, DNS_MAX_NAME
    jae  .bad                                 ; reserve the root zero within 255 wire bytes
    cmp  byte [rsi], '.'
    jne  .terminate
    inc  rsi                                  ; skip the dot, encode the next label
    jmp  .label
.terminate:
    mov  byte [rdi], 0                        ; terminating zero
    inc  rdi
    mov  rax, rdi
    sub  rax, rbx                             ; total encoded length
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

; dns_build_query(RDI=dst) -> EAX = total query length (header + qname + qtype +
;   qclass), or -1 if the name fails to encode. clobbers volatiles; preserves rbx.
dns_build_query:
    push rbx
    mov  rbx, rdi                             ; dst base
    ; --- 12-byte header (big-endian) ---
    mov  byte [rbx + DNS_ID],     0x13        ; id = 0x1337 (matches the response)
    mov  byte [rbx + DNS_ID + 1], 0x37
    mov  word [rbx + DNS_FLAGS],  0x0001      ; 0x0100 BE = RD set (byte0=0x01)
    mov  byte [rbx + DNS_QDCOUNT],     0
    mov  byte [rbx + DNS_QDCOUNT + 1], 1      ; QDCOUNT = 1
    mov  word [rbx + DNS_ANCOUNT],     0      ; ANCOUNT/NSCOUNT
    mov  word [rbx + 8],  0                   ; NSCOUNT
    mov  word [rbx + 10], 0                   ; ARCOUNT
    ; --- question: QNAME(example.com) + QTYPE + QCLASS ---
    lea  rdi, [rbx + DNS_HDRLEN]
    lea  rsi, [rel str_dns_example]
    call dns_encode_qname                     ; -> EAX = qname wire length, or -1
    cmp  eax, -1
    je   .bad
    lea  rcx, [rbx + DNS_HDRLEN]
    add  rcx, rax                             ; cursor just past the QNAME
    mov  byte [rcx + 0], 0
    mov  byte [rcx + 1], DNS_QTYPE_A          ; QTYPE = A (BE 0x0001)
    mov  byte [rcx + 2], 0
    mov  byte [rcx + 3], DNS_QCLASS_IN        ; QCLASS = IN (BE 0x0001)
    add  rcx, 4
    mov  rax, rcx
    sub  rax, rbx                             ; total query length
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

; dns_skip_name(RDI=frame, ESI=len, RDX=cursor ptr) -> RAX = new cursor ptr past
;   the name, or -1. Advances past a name field: a run of length-prefixed labels
;   terminated by a zero byte, OR a 2-byte 0xC0 compression pointer (which itself
;   terminates the name in the current stream). Fully bounds-checked. clobbers
;   RAX,RCX,R8,R9,R10,R11.
dns_skip_name:
    mov  r10, rdx                             ; cursor
    mov  r9, rdi                              ; immutable frame base
    mov  esi, esi                             ; explicit zero-extension of wire length
    call safe_checked_add                     ; reject base+len wrap before the walk
    test edx, edx
    jnz  .bad
    mov  r11, rax                             ; end-of-frame ptr (one past last)
    cmp  r10, r9
    jb   .bad                                 ; caller cursor may not precede frame
.walk:
    cmp  r10, r11
    jae  .bad                                 ; ran off the end
    movzx eax, byte [r10]
    test al, al
    je   .zero                                ; zero terminator
    mov  r8d, eax
    and  r8d, 0xC0
    cmp  r8d, 0xC0
    je   .ptr                                 ; compression pointer -> 2 bytes, done
    test r8d, r8d
    jnz  .bad                                 ; reserved 0x40/0x80 bits -> illegal
    mov  rcx, r11
    sub  rcx, r10                             ; remaining from length byte
    inc  rax                                  ; length byte + declared label
    cmp  rax, rcx
    ja   .bad                                 ; validate before cursor formation
    add  r10, rax
    jmp  .walk
.ptr:
    mov  rax, r11
    sub  rax, r10
    cmp  rax, 2
    jb   .bad                                 ; pointer low byte must be in-frame
    lea  rax, [r10 + 2]                       ; safe after remaining-input check
    ret
.zero:
    lea  rax, [r10 + 1]                       ; past the terminating zero
    ret
.bad:
    mov  rax, -1
    ret

; dns_parse_response(RDI=frame, ESI=len) -> RAX = 0 ok / -1 reject. Requires a
;   full 12-byte header with ANCOUNT>=1, skips the question, skips the answer name
;   (following/terminating on the 0xC0 pointer), requires TYPE=A + RDLENGTH=4, and
;   copies the 4-byte RDATA into dns_a_ip. Every step bounds-checked (no OOB, no
;   crash on a short frame). TOURNAMENT 1310 durable variant: the header SHAPE
;   is validated BEFORE any walk — QR=1 (a response, not an echoed query),
;   RCODE=0 (NOERROR — an NXDOMAIN/SERVFAIL answer section is never trusted),
;   QDCOUNT=1 (the only shape our single-question client ever sends) — and
;   dns_a_ip is written ONLY on full success, so a reject can never leave a
;   half-parsed address behind. clobbers volatiles; preserves rbx,r12,r13.
dns_parse_response:
    push rbx
    push r12
    push r13
    mov  rbx, rdi                             ; frame base
    mov  r12d, esi                            ; frame len
    test rbx, rbx
    jz   .bad
    cmp  r12d, DNS_HDRLEN
    jb   .bad                                 ; too short for a header
    cmp  r12d, 65535
    ja   .bad                                 ; DNS rides one bounded UDP datagram
    mov  rdi, rbx
    mov  rsi, r12
    call safe_checked_add
    test edx, edx
    jnz  .bad                                 ; reject frame+len carry before deref
    test byte [rbx + DNS_FLAGS], 0x80         ; QR must be 1: reject queries
    jz   .bad
    test byte [rbx + DNS_FLAGS + 1], 0x0F     ; RCODE must be 0 (NOERROR)
    jnz  .bad
    cmp  word [rbx + DNS_QDCOUNT], 0x0100     ; QDCOUNT == 1 (BE 0x0001)
    jne  .bad
    ; ANCOUNT must be >= 1
    lea  rdi, [rbx + DNS_ANCOUNT]
    call dns_be16
    test eax, eax
    jz   .bad
    ; skip the question name
    lea  rdx, [rbx + DNS_HDRLEN]
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, -1
    je   .bad
    mov  r13, rax                             ; cursor after QNAME
    ; skip QTYPE(2) + QCLASS(2), validating before pointer formation
    mov  rdx, r13
    sub  rdx, rbx
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, 4
    call safe_span_validate
    test eax, eax
    jnz  .bad
    lea  r13, [rdx + 4]
    ; skip the ANSWER name (the 0xC0 pointer back to the question)
    mov  rdx, r13
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, -1
    je   .bad
    mov  r13, rax                             ; cursor at answer TYPE
    ; need TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) = 10 bytes, then RDATA
    mov  rdx, r13
    sub  rdx, rbx
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, 10
    call safe_span_validate
    test eax, eax
    jnz  .bad
    ; TYPE must be A
    mov  rdi, r13
    call dns_be16
    cmp  eax, DNS_QTYPE_A
    jne  .bad
    ; RDLENGTH (at TYPE+8) must be 4
    lea  rdi, [r13 + 8]
    call dns_be16
    cmp  eax, 4
    jne  .bad
    ; RDATA (at TYPE+10) — bounds-check 4 bytes then copy
    mov  rdx, r13
    sub  rdx, rbx
    add  rdx, 10                            ; bounded DNS offset (len <= 65535)
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, 4
    call safe_span_validate
    test eax, eax
    jnz  .bad
    mov  rsi, rdx
    mov  eax, [rsi]                           ; 4 raw network-order octets
    mov  [rel dns_a_ip], eax
    xor  rax, rax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; dns_decode_name(RDI=frame, ESI=len, EDX=start offset, R8=dst) -> RAX = 0 ok /
;   -1. Reconstructs a dotted name, FOLLOWING 0xC0 compression pointers, bounded
;   by DNS_MAX_JUMPS so a self-referential pointer loop RETURNS (does not hang),
;   and the decoded OUTPUT capped at DNS_MAX_NAME bytes so a pointer-AMPLIFICATION
;   frame (long label + back-pointer) is rejected BEFORE it can write past the
;   caller's buffer — the jump guard alone admits ~2KB of output first. Fully
;   bounds-checked. TOURNAMENT 1308 fastest variant: zero stack traffic (volatile
;   registers only, so rbx/r12-r15 are trivially preserved), a single hoisted
;   end-of-frame pointer compared once per walk step, the length byte classified
;   by two unsigned compares (>= 0xC0 pointer / > 63 reserved-bit illegal / else
;   label), labels copied in 8-byte chunks with a byte tail (chunk reads stay
;   inside the already bounds-checked label). clobbers volatiles; preserves
;   rbx,r12-r15.
dns_decode_name:
    test r8, r8
    jz   .bad_no_dst
    mov  r10, r8                              ; immutable destination base
    mov  byte [r10], 0                        ; every later reject exposes empty, not partial
    test rdi, rdi
    jz   .bad
    movzx r11d, dx                            ; established 16-bit DNS offset envelope
    cmp  r11d, esi
    jae  .bad                                 ; offset must name a byte in the frame
    mov  esi, esi
    call safe_checked_add                     ; reject frame+len carry before any walk
    test edx, edx
    jnz  .bad
    mov  r9, rax                              ; end-of-frame (one past last byte)
    lea  rsi, [rdi + r11]                     ; safe: offset < len and end did not wrap
    xor  r11d, r11d                           ; compression-jump count
.walk:
    cmp  rsi, r9
    jae  .bad                                 ; cursor out of frame
    movzx eax, byte [rsi]
    test al, al
    je   .end                                 ; zero terminator -> done
    cmp  al, 0xC0
    jae  .ptr                                 ; top two bits set -> pointer
    cmp  al, DNS_MAX_LABEL
    ja   .bad                                 ; reserved 0x40/0x80 bits -> illegal
    ; --- label of length AL: frame bounds, output cap, separator, copy ---
    mov  rcx, r9
    sub  rcx, rsi                             ; remaining from length byte
    mov  rdx, rax
    inc  rdx                                  ; length byte + label bytes
    cmp  rdx, rcx
    ja   .bad                                 ; validate before input pointer formation
    lea  rdx, [r8 + rax]
    sub  rdx, r10                             ; decoded length AFTER this label
    cmp  r8, r10
    je   .cap                                 ; first label: no separator
    inc  rdx                                  ; + the '.' separator
    cmp  rdx, DNS_MAX_NAME
    ja   .bad                                 ; output cap — nothing written yet
    mov  byte [r8], '.'
    inc  r8
    jmp  .copy
.cap:
    cmp  rdx, DNS_MAX_NAME
    ja   .bad                                 ; output cap (amplification guard)
.copy:
    inc  rsi                                  ; -> first label byte
    mov  ecx, eax                             ; label length -> copy counter
    cmp  ecx, 8
    jb   .tail
.q8:
    mov  rdx, [rsi]                           ; 8-byte chunk (inside the label)
    mov  [r8], rdx
    add  rsi, 8
    add  r8, 8
    sub  ecx, 8
    cmp  ecx, 8
    jae  .q8
.tail:
    test ecx, ecx
    jz   .walk
.t1:
    mov  al, [rsi]
    mov  [r8], al
    inc  rsi
    inc  r8
    dec  ecx
    jnz  .t1
    jmp  .walk
.ptr:
    inc  r11d
    cmp  r11d, DNS_MAX_JUMPS
    ja   .bad                                 ; too many jumps -> loop guard fires
    mov  rcx, r9
    sub  rcx, rsi
    cmp  rcx, 2
    jb   .bad                                 ; pointer low byte out of frame
    and  eax, 0x3F                            ; high 6 bits of the offset
    shl  eax, 8
    movzx ecx, byte [rsi + 1]
    or   eax, ecx                             ; 14-bit pointer target offset
    mov  rcx, r9
    sub  rcx, rdi                             ; original frame length
    cmp  rax, rcx
    jae  .bad                                 ; target checked before pointer formation
    lea  rsi, [rdi + rax]                     ; jump the cursor
    jmp  .walk
.end:
    mov  byte [r8], 0                         ; terminate the decoded string
    xor  eax, eax
    ret
.bad:
    mov  byte [r10], 0                        ; hide any partially decoded prefix
.bad_no_dst:
    or   rax, -1
    ret

; dns_decode_name_kat — TOURNAMENT 1308 known-answer gate: 11 vectors through the
;   REAL decoder, two outcome classes:
;   * 5 bit-exact DECODES — the answer's 0xC0 pointer name, the question QNAME
;     decoded directly, a mid-name decode ("com" from the second label), the DNS
;     root (empty name, poison byte must be cleared), and a two-hop pointer CHAIN
;     ("foo" behind ptr->ptr). Every decoded string is compared byte-for-byte
;     (dns_streq) and the return code checked.
;   * 6 contained REJECTS — self-referential pointer loop (jump guard), start
;     offset outside the frame, a reserved 0x40 length byte, a label declared
;     past the frame end, a pointer whose low byte the frame cuts off, and a
;     pointer-AMPLIFICATION frame (63-byte label + back-pointer) that the output
;     cap must stop BEFORE the 255-byte name ceiling — a canary byte planted
;     behind the cap is checked untouched afterwards.
;   PASS re-decodes the pointer name and prints it READ BACK from the live buffer
;   + earns [tourn.dns_decode_name.kat] [tourn.dns_decode_name.guard], then
;   TSC-measures 64 pointer-chase decodes and prints the live cycle count
;   [tourn.dns_decode_name.perf]. Any mismatch prints the failing step id + the
;   .fail marker and boot CONTINUES (degrade, never crash).
;   clobbers: volatiles; preserves rbx,r12-r15 (saved).
dns_decode_name_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---- (1) answer name: FOLLOW the 0xC0 pointer -> "example.com" ----
    mov  r15d, 1
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    mov  edx, DNS_ANS_NAME_OFF
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    test rax, rax
    jnz  .fail
    lea  rdi, [rel dns_kat_dst]
    lea  rsi, [rel str_dns_example]
    call dns_streq
    test rax, rax
    jz   .fail

    ; ---- (2) question QNAME decoded directly (no pointer) -> "example.com" ----
    mov  r15d, 2
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    mov  edx, DNS_HDRLEN
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    test rax, rax
    jnz  .fail
    lea  rdi, [rel dns_kat_dst]
    lea  rsi, [rel str_dns_example]
    call dns_streq
    test rax, rax
    jz   .fail

    ; ---- (3) mid-name decode: start at the second label -> "com" ----
    mov  r15d, 3
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    mov  edx, DNS_HDRLEN + 8                  ; the 3,'com' label inside the QNAME
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    test rax, rax
    jnz  .fail
    lea  rdi, [rel dns_kat_dst]
    lea  rsi, [rel str_dns_kat_com]
    call dns_streq
    test rax, rax
    jz   .fail

    ; ---- (4) the DNS root: a lone zero byte -> empty name, rc 0 ----
    mov  r15d, 4
    mov  byte [rel dns_kat_dst], 0x7F         ; poison: decoder must clear it
    lea  rdi, [rel dns_kat_root]
    mov  esi, 1
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    test rax, rax
    jnz  .fail
    cmp  byte [rel dns_kat_dst], 0
    jne  .fail

    ; ---- (5) two-hop pointer chain: ptr -> ptr -> label -> "foo" ----
    mov  r15d, 5
    lea  rdi, [rel dns_kat_chain]
    mov  esi, DNS_KAT_CHAIN_LEN
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    test rax, rax
    jnz  .fail
    lea  rdi, [rel dns_kat_dst]
    lea  rsi, [rel str_dns_kat_foo]
    call dns_streq
    test rax, rax
    jz   .fail

    ; ---- (6) REJECT: self-referential pointer loop (jump guard bounds it) ----
    mov  r15d, 6
    lea  rdi, [rel dns_ptrloop]
    mov  esi, DNS_PTRLOOP_LEN
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    cmp  rax, -1
    jne  .fail

    ; ---- (7) REJECT: start offset outside the frame ----
    mov  r15d, 7
    lea  rdi, [rel dns_kat_root]
    mov  esi, 1
    mov  edx, 1                               ; == len -> already out of frame
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    cmp  rax, -1
    jne  .fail

    ; ---- (8) REJECT: reserved 0x40 length bits ----
    mov  r15d, 8
    lea  rdi, [rel dns_kat_resv]
    mov  esi, 1
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    cmp  rax, -1
    jne  .fail

    ; ---- (9) REJECT: label declared past the frame end ----
    mov  r15d, 9
    lea  rdi, [rel dns_kat_short]
    mov  esi, 3                               ; declares 5 label bytes, has 2
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    cmp  rax, -1
    jne  .fail

    ; ---- (10) REJECT: pointer whose low byte the frame cuts off ----
    mov  r15d, 10
    lea  rdi, [rel dns_kat_cut]
    mov  esi, 1
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    cmp  rax, -1
    jne  .fail

    ; ---- (11) REJECT: pointer AMPLIFICATION — output cap fires, canary lives ----
    mov  r15d, 11
    mov  byte [rel dns_kat_dst + DNS_KAT_CANARY_OFF], 0x5A
    lea  rdi, [rel dns_kat_amp]
    mov  esi, DNS_KAT_AMP_LEN
    xor  edx, edx
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel dns_kat_dst + DNS_KAT_CANARY_OFF], 0x5A
    jne  .fail                                ; decoder wrote past the name cap

    ; ---- all gates passed: re-decode fresh, print the LIVE buffer, markers ----
    mov  r15d, 12
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    mov  edx, DNS_ANS_NAME_OFF
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_dns_dn_kat1]
    call serial_string
    lea  rdi, [rel dns_kat_dst]               ; name= READ BACK from the buffer
    call serial_string
    lea  rdi, [rel str_dns_dn_kat2]
    call serial_string
    lea  rdi, [rel str_dns_dn_pass]
    call serial_string

    ; ---- perf: TSC over 64 pointer-chase decodes (live, varies per boot) ----
    rdtsc
    mov  r12d, eax                            ; low 32 TSC bits (delta is small)
    mov  r14d, 64
.perf:
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    mov  edx, DNS_ANS_NAME_OFF
    lea  r8, [rel dns_kat_dst]
    call dns_decode_name
    dec  r14d
    jnz  .perf
    rdtsc
    sub  eax, r12d
    mov  r13d, eax
    lea  rdi, [rel str_dns_dn_perf1]
    call serial_string
    mov  eax, r13d
    call dns_print_u32
    lea  rdi, [rel str_dns_dn_perf2]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_dns_dn_fail]
    call serial_string
    mov  eax, r15d                            ; failing step id, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dns_parse_response_kat — TOURNAMENT 1310 known-answer gate (durable variant):
;   11 TABLE-driven contained REJECTS — each row pokes ONE byte of the canned
;   response hostile (or just truncates it), parses, RESTORES the byte BEFORE the
;   verdict compare, and must get -1: short header, QR=0 echoed query,
;   RCODE=NXDOMAIN, QDCOUNT=0, ANCOUNT=0, reserved label bits, QTYPE/QCLASS cut,
;   pointer low byte cut, RDATA cut, TYPE->NS, RDLENGTH->5. A dns_a_ip POISON
;   (0xDEADBEEF) is planted FIRST and checked untouched after ALL rejects (no
;   partial write ever escapes a reject), then the pristine vector must parse
;   rc=0 with dns_a_ip BIT-EXACT (93.184.216.34) — printed READ BACK from the
;   live store -> [tourn.dns_parse_response.kat] [..guard]. Then TSC-times 64
;   full parses and re-verifies a_ip is STILL exact (no state decay under
;   repetition) -> [..perf]. Any mismatch prints the failing step id + the .fail
;   marker and boot CONTINUES (degrade, never crash). clobbers volatiles;
;   preserves rbx,r12-r15 (r12-r14 saved; rbx,r15 untouched).
dns_parse_response_kat:
    push r12
    push r13
    push r14
    mov  dword [rel dns_a_ip], 0xDEADBEEF     ; poison: only full success may write
    ; ---- (0..10) REJECT table: poke, parse hostile, restore FIRST, verdict ----
    lea  r12, [rel dns_pr_neg_tbl]
    xor  r13d, r13d
.neg:
    lea  rdi, [rel dns_response]
    movzx eax, word [r12 + r13*8]             ; row: tamper offset
    mov  cl,  [r12 + r13*8 + 2]               ; row: hostile byte
    mov  [rdi + rax], cl                      ; poke
    movzx esi, word [r12 + r13*8 + 6]         ; row: hostile frame length
    call dns_parse_response
    mov  r14, rax                             ; rc — verdict only AFTER restore
    lea  rdi, [rel dns_response]
    movzx eax, word [r12 + r13*8]
    mov  cl,  [r12 + r13*8 + 4]               ; row: pristine byte
    mov  [rdi + rax], cl                      ; restore
    cmp  r14, -1
    jne  .fail                                ; a hostile shape got through
    inc  r13d
    cmp  r13d, DNS_PR_NEG_N
    jb   .neg
    ; ---- (11) GUARD: the poison survived all 11 rejects (no partial write) ----
    mov  r13d, 11
    cmp  dword [rel dns_a_ip], 0xDEADBEEF
    jne  .fail
    ; ---- (12) POSITIVE: pristine vector (proves every restore) rc=0, BIT-EXACT --
    mov  r13d, 12
    call .parse_full
    test rax, rax
    jnz  .fail
    cmp  dword [rel dns_a_ip], 0x22D8B85D     ; 93.184.216.34 in wire order
    jne  .fail
    ; ---- all gates passed: print a_ip READ BACK live + kat/guard markers ----
    lea  rdi, [rel str_dns_pr_kat1]
    call serial_string
    lea  rsi, [rel dns_a_ip]                  ; read back from the live store
    call dns_print_ip
    lea  rdi, [rel str_dns_pr_pass]
    call serial_string
    ; ---- perf: TSC over 64 full parses, then re-verify (no state decay) ----
    rdtsc
    mov  r12d, eax                            ; low 32 TSC bits (delta is small)
    mov  r14d, 64
.perf:
    call .parse_full
    dec  r14d
    jnz  .perf
    rdtsc
    sub  eax, r12d
    mov  r14d, eax
    mov  r13d, 13
    cmp  dword [rel dns_a_ip], 0x22D8B85D     ; still exact after 64 reparses
    jne  .fail
    lea  rdi, [rel str_dns_pr_perf1]
    call serial_string
    mov  eax, r14d
    call dns_print_u32
    lea  rdi, [rel str_dns_pr_perf2]
    call serial_string
    jmp  .done
.parse_full:                                  ; parse the pristine canned response;
    lea  rdi, [rel dns_response]              ;   tail-jump so the parser's rc
    mov  esi, DNS_RESPONSE_LEN                ;   returns straight to OUR caller
    jmp  dns_parse_response
.fail:
    lea  rdi, [rel str_dns_pr_fail]
    call serial_string
    mov  eax, r13d                            ; failing step id, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    pop  r14
    pop  r13
    pop  r12
    ret

; dns_streq(RDI=a, RSI=b) -> RAX = 1 if the NUL-terminated strings are equal, else
;   0. NULL is never equal. clobbers RAX,RCX; preserves the established R8-R10
;   caller ABI even though the qword implementation uses them internally.
; TOURNAMENT 1428 v2 FASTEST: compare eight bytes per common-path iteration and
;   use the standard subtract/NOT/high-bit test to find a NUL in an equal word.
;   The scalar path is selected whenever either eight-byte load would cross a
;   4-KiB page, so the speedup cannot turn a valid page-edge string into a fault.
;   A differing word is also resolved bytewise, preserving strcmp semantics when
;   bytes beyond a shared first NUL differ. RDI/RSI remain unchanged for callers.
dns_streq:
    push r8
    push r9
    push r10
    test rdi, rdi
    jz   .ne
    test rsi, rsi
    jz   .ne
    mov  r8, 0x0101010101010101             ; zero-byte detection low bits
    mov  r9, 0x8080808080808080             ; zero-byte detection high bits
    xor  ecx, ecx
.word:
    ; One conservative combined check: OR may choose scalar unnecessarily, but
    ; can never miss either pointer being in the final seven bytes of a page.
    lea  rax, [rdi + rcx]
    lea  r10, [rsi + rcx]
    or   eax, r10d
    and  eax, 0x0FFF
    cmp  eax, 0x0FF8                        ; qword at page offset <= FF8 is safe
    ja   .edge

    mov  rax, [rdi + rcx]
    cmp  rax, [rsi + rcx]
    jne  .tail                              ; find first mismatch/NUL exactly
    mov  r10, rax
    sub  r10, r8
    not  rax
    and  r10, rax
    test r10, r9                            ; ((x-01..) & ~x & 80..) != 0
    jnz  .eq
    add  rcx, 8
    jmp  .word

.edge:
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .ne
    inc  rcx
    test al, al
    jnz  .word                              ; re-enter qword path when safe
    jmp  .eq

.tail:                                      ; one unequal qword: resolve once
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .ne
    inc  rcx
    test al, al
    jnz  .tail
.eq:
    mov  eax, 1
    jmp  .out
.ne:
    xor  eax, eax
.out:
    pop  r10
    pop  r9
    pop  r8
    ret

; dns_streq_kat — TOURNAMENT 1428 v2 FASTEST. The table is deliberately the
;   tournament's fixed battery: four ordinary known answers, then eight hostile
;   exact-result rows (high-bit bytes, first-NUL semantics, empty/non-empty,
;   >255-byte equal/different strings, and either input NULL). The performance
;   marker measures 512 live equal-name calls only after every correctness row.
dns_streq_kat:
    push r12
    push r13
    push r14
    push r15

    ; Reuse existing DNS work areas for two equal 260-byte strings and one whose
    ; final payload byte differs. 260 deliberately exceeds the DNS name ceiling.
    lea  rdi, [rel dns_scratch]
    mov  ecx, 260
    mov  al, 'q'
    rep  stosb
    mov  byte [rdi], 0
    lea  rdi, [rel dns_kat_dst]
    mov  ecx, 260
    rep  stosb
    mov  byte [rdi], 0
    lea  rdi, [rel dns_decoded_name]
    mov  ecx, 260
    rep  stosb
    mov  byte [rdi], 0
    mov  byte [rel dns_decoded_name + 259], 'r'

    lea  r12, [rel dns_st_vec_base]
    lea  r13, [rel dns_st_vec_tbl]
    mov  r14d, DNS_ST_VEC_N
    mov  r15d, 1                             ; live failure row, one-based
.vec:
    movsxd rdi, dword [r13]
    test edi, edi                            ; offset zero is the NULL sentinel
    jz   .a_ready
    add  rdi, r12
.a_ready:
    movsxd rsi, dword [r13 + 4]
    test esi, esi
    jz   .b_ready
    add  rsi, r12
.b_ready:
    ; ABI regression gate: the old scalar helper preserved R8-R10. Tournament
    ; implementations may use them internally, but must not leak that change to
    ; existing assembly callers.
    mov  r8d,  0x13579BDF
    mov  r9d,  0x2468ACE0
    mov  r10d, 0x55AA33CC
    call dns_streq
    cmp  r8d,  0x13579BDF
    jne  .fail
    cmp  r9d,  0x2468ACE0
    jne  .fail
    cmp  r10d, 0x55AA33CC
    jne  .fail
    cmp  al, byte [r13 + 8]
    jne  .fail
    add  r13, DNS_ST_VEC_SIZE
    inc  r15d
    dec  r14d
    jnz  .vec

    ; A fenced, repeatable hot-path axis. The result check stays inside the loop,
    ; so an incorrect comparator can never earn either the KAT or perf marker.
    mov  r14d, 512
    lfence
    rdtsc
    mov  r12d, eax
.perf:
    lea  rdi, [rel str_dns_example]
    lea  rsi, [rel str_dns_example]
    call dns_streq
    test eax, eax
    jz   .fail
    dec  r14d
    jnz  .perf
    lfence
    rdtsc
    sub  eax, r12d
    mov  r12d, eax

    lea  rdi, [rel str_dns_st_pass]
    call serial_string
    lea  rdi, [rel str_dns_st_fault]
    call serial_string
    lea  rdi, [rel str_dns_st_perf1]
    call serial_string
    mov  eax, r12d
    call dns_print_u32
    lea  rdi, [rel str_dns_st_perf2]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_dns_st_fail]
    call serial_string
    mov  eax, r15d
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; dns_print_u32(EAX=value) — print an unsigned decimal (no leading zeros) via
;   serial. clobbers volatiles; preserves rbx.
dns_print_u32:
    push rbx
    lea  rbx, [rel dns_numbuf + 15]           ; build digits backward from the end
    mov  byte [rbx], 0
    mov  ecx, 10
    mov  r8d, eax
.dig:
    mov  eax, r8d
    xor  edx, edx
    div  ecx                                  ; eax=quot, edx=digit
    add  dl, '0'
    dec  rbx
    mov  [rbx], dl
    mov  r8d, eax
    test r8d, r8d
    jnz  .dig
    mov  rdi, rbx
    call serial_string
    pop  rbx
    ret

; dns_wr_u8(EAX=0..255, RDI=dst) -> RDI advanced past the decimal digits (no
;   leading zeros). clobbers EAX,ECX,EDX,R8.
;   DURABILITY (tourn 1417, additive — byte-identical for every legal 0..255,
;   non-NULL caller): (1) contain a NULL dst — write nothing, return rdi=0 rather
;   than deref address 0 (which is live low memory here); (2) bound the input to a
;   real u8 with `movzx eax,al` so a contract-violating caller (high bits set)
;   can NEVER leak a non-digit char into the octet/hostname string — the output
;   stays a valid 1-3 digit decimal of the low byte. Legal callers pass 0..255 in
;   a non-NULL rdi, so both guards are no-ops for them. Do not remove — the KAT's
;   .guard gate exercises both paths (dns_wr_u8_kat).
dns_wr_u8:
    test rdi, rdi
    jz   .contained                            ; NULL dst -> contain, write nothing
    movzx eax, al                              ; bound to u8 (0..255); legal = no-op
    xor  edx, edx
    mov  r8d, 100
    div  r8d
    test eax, eax
    jz   .no_h
    add  al, '0'
    mov  [rdi], al
    inc  rdi
    mov  eax, edx
    xor  edx, edx
    mov  r8d, 10
    div  r8d
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
.contained:                                    ; NULL dst: rdi already 0, nothing written
    ret

; dns_print_ip(RSI=4-byte IPv4 ptr) — format "A.B.C.D" into scratch + serial.
;   clobbers volatiles; preserves rbx.
dns_print_ip:
    push rbx
    mov  rbx, rsi
    lea  rdi, [rel dns_ipbuf]
    movzx eax, byte [rbx]
    call dns_wr_u8
    mov  byte [rdi], '.'
    inc  rdi
    movzx eax, byte [rbx + 1]
    call dns_wr_u8
    mov  byte [rdi], '.'
    inc  rdi
    movzx eax, byte [rbx + 2]
    call dns_wr_u8
    mov  byte [rdi], '.'
    inc  rdi
    movzx eax, byte [rbx + 3]
    call dns_wr_u8
    mov  byte [rdi], 0
    lea  rdi, [rel dns_ipbuf]
    call serial_string
    pop  rbx
    ret

; dns_wr_u8_kat — TOURNAMENT 1417 known-answer gate (durable variant): drive the
;   LIVE dns_wr_u8 through 9 bit-exact positive vectors covering every branch —
;   0/7 (1-digit), 10/42/99 (2-digit incl. trailing zero + the 99 max), and
;   100/205/250/255 (3-digit hundreds path incl. zero tens/ones). Each format
;   writes into dns_wr_dst behind a 0x5A canary at DNS_WR_CANARY_OFF; after the
;   call the returned RDI is NUL-terminated and the buffer is compared byte-for-
;   byte (dns_streq) against a literal (so the exact digits AND the RDI advance
;   are both proven), and the canary is checked untouched (no wild write past the
;   <=3 digits). Then two DEGRADE gates prove the durability hardening: an
;   out-of-range value (0x466 -> low byte 102) must format the bounded "102"
;   (not a non-digit char), and a NULL dst must be CONTAINED (rdi returns 0, no
;   write, no crash). Only when all 12 gates pass does it re-format 255 fresh,
;   print it READ BACK from the live buffer, and earn [tourn.dns_wr_u8.kat]
;   [tourn.dns_wr_u8.guard]; then TSC-times 64 formats -> [tourn.dns_wr_u8.perf].
;   Any mismatch prints the failing step id + the .fail marker and boot CONTINUES
;   (degrade, never crash). clobbers volatiles; preserves rbx,r12-r15 (saved).
dns_wr_u8_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  r15d, 1
    mov  eax, 0
    lea  rsi, [rel str_dns_wr_0]
    call .fmt_eq
    jz   .fail
    mov  r15d, 2
    mov  eax, 7
    lea  rsi, [rel str_dns_wr_7]
    call .fmt_eq
    jz   .fail
    mov  r15d, 3
    mov  eax, 10
    lea  rsi, [rel str_dns_wr_10]
    call .fmt_eq
    jz   .fail
    mov  r15d, 4
    mov  eax, 42
    lea  rsi, [rel str_dns_wr_42]
    call .fmt_eq
    jz   .fail
    mov  r15d, 5
    mov  eax, 99
    lea  rsi, [rel str_dns_wr_99]
    call .fmt_eq
    jz   .fail
    mov  r15d, 6
    mov  eax, 100
    lea  rsi, [rel str_dns_wr_100]
    call .fmt_eq
    jz   .fail
    mov  r15d, 7
    mov  eax, 205
    lea  rsi, [rel str_dns_wr_205]
    call .fmt_eq
    jz   .fail
    mov  r15d, 8
    mov  eax, 250
    lea  rsi, [rel str_dns_wr_250]
    call .fmt_eq
    jz   .fail
    mov  r15d, 9
    mov  eax, 255
    lea  rsi, [rel str_dns_wr_255]
    call .fmt_eq
    jz   .fail

    ; ---- (10) DEGRADE: out-of-range input, high bits ignored -> bounded "102" ----
    mov  r15d, 10
    mov  eax, 0x466                             ; 1126; low byte 0x66=102
    lea  rsi, [rel str_dns_wr_102]
    call .fmt_eq
    jz   .fail
    ; ---- (11) DEGRADE: another out-of-range (0x1FF) -> low byte 0xFF=255 ----
    mov  r15d, 11
    mov  eax, 0x1FF
    lea  rsi, [rel str_dns_wr_255]
    call .fmt_eq
    jz   .fail

    ; ---- (12) GUARD: NULL dst is CONTAINED — rdi stays 0, nothing written ----
    mov  r15d, 12
    xor  edi, edi
    mov  eax, 5
    call dns_wr_u8
    test rdi, rdi                               ; must be untouched (no deref of 0)
    jnz  .fail

    ; ---- all gates passed: format 255 fresh, print READ BACK, earn kat+guard ----
    lea  rdi, [rel dns_wr_dst]
    mov  eax, 255
    call dns_wr_u8
    mov  byte [rdi], 0
    lea  rdi, [rel str_dns_wr_kat1]
    call serial_string
    lea  rdi, [rel dns_wr_dst]                  ; value= READ BACK from the buffer
    call serial_string
    lea  rdi, [rel str_dns_wr_pass]
    call serial_string

    ; ---- perf: TSC over 64 formats of 255 (live, varies per boot) ----
    rdtsc
    mov  r12d, eax                              ; low 32 TSC bits (delta is small)
    mov  r14d, 64
.perf:
    lea  rdi, [rel dns_wr_dst]
    mov  eax, 255
    call dns_wr_u8
    dec  r14d
    jnz  .perf
    rdtsc
    sub  eax, r12d
    mov  r13d, eax
    lea  rdi, [rel str_dns_wr_perf1]
    call serial_string
    mov  eax, r13d
    call dns_print_u32
    lea  rdi, [rel str_dns_wr_perf2]
    call serial_string
    jmp  .done

.fmt_eq:                                        ; EAX=value, RSI=expected str ->
    push rsi                                    ;   ZF set (jz) on MISMATCH, clear on OK
    lea  rdi, [rel dns_wr_dst]
    mov  byte [rdi + DNS_WR_CANARY_OFF], 0x5A   ; plant overrun canary
    call dns_wr_u8                              ; RDI advanced past the digits
    mov  byte [rdi], 0                           ; NUL-terminate at the returned ptr
    cmp  byte [rel dns_wr_dst + DNS_WR_CANARY_OFF], 0x5A
    jne  .fmt_canary                            ; wrote past 3 digits -> fail
    lea  rdi, [rel dns_wr_dst]
    pop  rsi
    call dns_streq                              ; RAX=1 equal, 0 differ
    test rax, rax                               ; set ZF from the verdict
    ret
.fmt_canary:
    pop  rsi
    xor  eax, eax                               ; ZF=1 -> caller's jz .fail fires
    ret
.fail:
    lea  rdi, [rel str_dns_wr_fail]
    call serial_string
    mov  eax, r15d                              ; failing step id, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dns_skip_name_kat — TOURNAMENT 1425 (durable, SMALLEST variant): known-answer +
;   adversarial-fault gate for dns_skip_name. Drives the LIVE (byte-for-byte
;   unchanged) skipper through 3 bit-exact POSITIVE vectors (a multi-label QNAME
;   terminated by a zero, a 0xC0 compression pointer, the lone-zero DNS root — each
;   return cursor compared to the exact expected frame offset) and a FIXED battery
;   of 6 hostile vectors (malformed reserved-bit length byte, truncated compression
;   pointer, label declared past the frame end, cursor already at the frame end, an
;   unterminated label run that overruns a truncated frame, and a NULL/zero-length
;   frame). Every hostile vector must return -1 with NO out-of-bounds read — the
;   NULL vector proves the bounds check fires BEFORE any deref. Reuses the existing
;   canned vectors (dns_response / dns_kat_root / dns_kat_resv / dns_kat_cut /
;   dns_kat_short) — no new data. PASS earns [tourn.dns_skip_name.kat]
;   [tourn.dns_skip_name.guard] and emits [tourn.dns_skip_name.fault contained=N
;   total=6]. Any mismatch prints the failing step id + .fail marker and boot
;   CONTINUES (degrade, never crash). clobbers: volatiles; preserves rbx,r12-r15.
dns_skip_name_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r14d, r14d                           ; contained-fault counter

    ; ---- (1) POSITIVE: multi-label QNAME "example.com" -> cursor past the zero ----
    mov  r15d, 1
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    lea  rdx, [rel dns_resp_q]                 ; cursor at the QNAME
    call dns_skip_name
    lea  rcx, [rel dns_resp_q + 13]            ; 13 wire bytes: 7,'example',3,'com',0
    cmp  rax, rcx
    jne  .fail

    ; ---- (2) POSITIVE: 0xC0 compression pointer -> cursor past the 2 ptr bytes ----
    mov  r15d, 2
    lea  rdi, [rel dns_response]
    mov  esi, DNS_RESPONSE_LEN
    lea  rdx, [rel dns_resp_ans]               ; the 0xC0 0x0C answer name
    call dns_skip_name
    lea  rcx, [rel dns_resp_ans + 2]
    cmp  rax, rcx
    jne  .fail

    ; ---- (3) POSITIVE: the DNS root (lone zero) -> cursor past the zero ----
    mov  r15d, 3
    lea  rdi, [rel dns_kat_root]
    mov  esi, 1
    lea  rdx, [rel dns_kat_root]
    call dns_skip_name
    lea  rcx, [rel dns_kat_root + 1]
    cmp  rax, rcx
    jne  .fail

    ; ---- (4) FAULT: malformed reserved-bit (0x40) length byte -> -1 ----
    mov  r15d, 4
    lea  rdi, [rel dns_kat_resv]
    mov  esi, 1
    lea  rdx, [rel dns_kat_resv]
    call dns_skip_name
    cmp  rax, -1
    jne  .fail
    inc  r14d

    ; ---- (5) FAULT: truncated compression pointer (low byte cut off) -> -1 ----
    mov  r15d, 5
    lea  rdi, [rel dns_kat_cut]
    mov  esi, 1
    lea  rdx, [rel dns_kat_cut]
    call dns_skip_name
    cmp  rax, -1
    jne  .fail
    inc  r14d

    ; ---- (6) FAULT: label declares 5 bytes, frame has 2 (overflow) -> -1 ----
    mov  r15d, 6
    lea  rdi, [rel dns_kat_short]
    mov  esi, 3
    lea  rdx, [rel dns_kat_short]
    call dns_skip_name
    cmp  rax, -1
    jne  .fail
    inc  r14d

    ; ---- (7) FAULT: boundary — cursor already at the frame end -> -1 ----
    mov  r15d, 7
    lea  rdi, [rel dns_kat_root]
    mov  esi, 1
    lea  rdx, [rel dns_kat_root + 1]           ; == frame end
    call dns_skip_name
    cmp  rax, -1
    jne  .fail
    inc  r14d

    ; ---- (8) FAULT: unterminated label run overruns a truncated frame -> -1 ----
    mov  r15d, 8
    lea  rdi, [rel dns_response]
    mov  esi, DNS_HDRLEN + 2                   ; QNAME len byte 7 walks past this
    lea  rdx, [rel dns_resp_q]
    call dns_skip_name
    cmp  rax, -1
    jne  .fail
    inc  r14d

    ; ---- (9) FAULT: NULL / zero-length frame -> -1 (bounds check, NO deref) ----
    mov  r15d, 9
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    call dns_skip_name
    cmp  rax, -1
    jne  .fail
    inc  r14d

    ; ---- all gates passed: print KAT line + markers, then the fault tally ----
    lea  rdi, [rel str_dns_sk_kat1]
    call serial_string
    lea  rdi, [rel str_dns_sk_pass]
    call serial_string
    lea  rdi, [rel str_dns_sk_flt1]
    call serial_string
    mov  eax, r14d                            ; contained count, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_sk_flt2]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_dns_sk_fail]
    call serial_string
    mov  eax, r15d                            ; failing step id, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dns_encode_qname_kat — TOURNAMENT 1421 (durable variant): known-answer +
;   adversarial-fault gate for dns_encode_qname. Drives the LIVE (byte-for-byte
;   for legal callers) encoder through 2 bit-exact POSITIVE vectors ("example.com"
;   compared byte-for-byte against the canned wire QNAME dns_resp_q, and a single
;   label "com" -> 03 'c' 'o' 'm' 00) and a FIXED battery of 8 hostile/boundary
;   vectors (a strict SUPERSET of the smallest variant's 6): (F1) a single label
;   > 63; (F2) a 64-byte label = the FIRST illegal length (boundary); (F3) a
;   > 255-byte name (4x63 labels) contained to -1 with an overrun SENTINEL past
;   the 255-byte cap proven intact (the baseline only checked at each LABEL edge,
;   so it wrote ~64 bytes past the cap before rejecting — a real buffer overrun
;   this variant prevents); (F4) the empty name "" -> a graceful 00 00 (len 2);
;   (F5) a trailing dot "a." -> 01 'a' 00 00 (len 4); (F6) a leading dot ".a" ->
;   00 01 'a' 00 (len 4); (F7) NULL dst and (F8) NULL src — both contained to -1
;   at entry with NO deref (the smallest/baseline body #PF-writes to 0 / reads
;   low-memory garbage on these two — this durable variant CONTAINS what v1 could
;   not). Every hostile vector is CONTENT-checked against its expected graceful
;   result, not merely "didn't crash". PASS earns [tourn.dns_encode_qname.kat]
;   [tourn.dns_encode_qname.guard] and emits [tourn.dns_encode_qname.fault
;   contained=N total=8]. Any mismatch prints the failing step id + .fail marker
;   and boot CONTINUES (degrade, never crash). clobbers volatiles; preserves
;   rbx,r12-r15.
dns_encode_qname_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r14d, r14d                           ; contained-fault counter

    ; ---- (P1) POSITIVE: "example.com" -> 13 wire bytes, byte-exact vs golden ----
    mov  r15d, 1
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel str_dns_example]
    call dns_encode_qname
    cmp  eax, 13
    jne  .fail                                ; encoded length must be 13
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel dns_resp_q]                ; canned wire QNAME: 7,'example',3,'com',0
    mov  ecx, 13
.p1cmp:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .fail                                ; any diverging byte -> KAT fails
    inc  rdi
    inc  rsi
    dec  ecx
    jnz  .p1cmp

    ; ---- (P2) POSITIVE: single label "com" -> 03 'c' 'o' 'm' 00 (5 bytes) ----
    mov  r15d, 2
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel str_dns_kat_com]           ; "com"
    call dns_encode_qname
    cmp  eax, 5
    jne  .fail
    cmp  byte [rel dns_eq_dst + 0], 3
    jne  .fail
    cmp  byte [rel dns_eq_dst + 1], 'c'
    jne  .fail
    cmp  byte [rel dns_eq_dst + 4], 0
    jne  .fail

    ; ---- (F1) FAULT: single label > 63 (70 'a') -> -1 (pointer-bit guard) ----
    mov  r15d, 3
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel dns_badname]
    call dns_encode_qname
    cmp  eax, -1
    jne  .fail
    inc  r14d

    ; ---- (F2) FAULT: 64-byte label = FIRST illegal length (boundary) -> -1 ----
    mov  r15d, 4
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel dns_eq_lab64]
    call dns_encode_qname
    cmp  eax, -1
    jne  .fail
    inc  r14d

    ; ---- (F3) FAULT: name > 255 wire (4x63 labels) -> -1, overrun sentinel intact ----
    mov  r15d, 5
    mov  byte [rel dns_eq_dst + DNS_EQ_CANARY_OFF], 0xC3   ; sentinel past the 255 cap
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel dns_kat_over]
    call dns_encode_qname
    cmp  eax, -1
    jne  .fail
    cmp  byte [rel dns_eq_dst + DNS_EQ_CANARY_OFF], 0xC3   ; MUST survive (durable: no overrun)
    jne  .fail
    inc  r14d

    ; ---- (F4) BOUNDARY: empty name "" -> 00 00 (len 2), byte-exact graceful ----
    mov  r15d, 6
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel str_dns_eq_empty]
    call dns_encode_qname
    cmp  eax, 2
    jne  .fail
    cmp  byte [rel dns_eq_dst + 0], 0
    jne  .fail
    cmp  byte [rel dns_eq_dst + 1], 0
    jne  .fail
    inc  r14d

    ; ---- (F5) MALFORMED: trailing dot "a." -> 01 'a' 00 00 (len 4), byte-exact ----
    mov  r15d, 7
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel str_dns_eq_trail]
    call dns_encode_qname
    cmp  eax, 4
    jne  .fail
    cmp  byte [rel dns_eq_dst + 0], 1
    jne  .fail
    cmp  byte [rel dns_eq_dst + 1], 'a'
    jne  .fail
    cmp  byte [rel dns_eq_dst + 2], 0
    jne  .fail
    cmp  byte [rel dns_eq_dst + 3], 0
    jne  .fail
    inc  r14d

    ; ---- (F6) MALFORMED: leading dot ".a" -> 00 01 'a' 00 (len 4), byte-exact ----
    mov  r15d, 8
    lea  rdi, [rel dns_eq_dst]
    lea  rsi, [rel str_dns_eq_dota]
    call dns_encode_qname
    cmp  eax, 4
    jne  .fail
    cmp  byte [rel dns_eq_dst + 0], 0
    jne  .fail
    cmp  byte [rel dns_eq_dst + 1], 1
    jne  .fail
    cmp  byte [rel dns_eq_dst + 2], 'a'
    jne  .fail
    inc  r14d

    ; ---- (F7) DURABLE: NULL dst -> -1 (contained at entry, NO #PF write) ----
    ;      the smallest/baseline body dereferences dst[0]=0 here and #PFs; this
    ;      durable variant folds it onto the -1 reject -> contains what v1 cannot.
    mov  r15d, 9
    xor  edi, edi
    lea  rsi, [rel str_dns_example]
    call dns_encode_qname
    cmp  eax, -1
    jne  .fail
    inc  r14d

    ; ---- (F8) DURABLE: NULL src -> -1 (contained at entry, NO wild read) ----
    mov  r15d, 10
    lea  rdi, [rel dns_eq_dst]
    xor  esi, esi
    call dns_encode_qname
    cmp  eax, -1
    jne  .fail
    inc  r14d

    ; ---- all gates passed: print KAT line + markers, then the fault tally ----
    lea  rdi, [rel str_dns_eq_kat1]
    call serial_string
    lea  rdi, [rel str_dns_eq_pass]
    call serial_string
    lea  rdi, [rel str_dns_eq_flt1]
    call serial_string
    mov  eax, r14d                            ; contained count, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_eq_flt2]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_dns_eq_fail]
    call serial_string
    mov  eax, r15d                            ; failing step id, read back live
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; Contract 1025: live DNS stub resolver.  This is the L4 owner of query, cache,
; timeout, and response semantics.  svc/command_dns is only a registry
; projection and svc/command_udp only hands ordinary RX frames to this module.
; ============================================================================

DNS_LIVE_PORT_BASE equ 49152            ; per-query source port: 49152..65535 (RFC 6335 dynamic)
DNS_LIVE_NTP_PORT  equ 49154            ; net/ntp's fixed client port is never drawn
DNS_LIVE_ATTEMPTS  equ 3                ; transmissions per query (first + 2 retransmits)
DNS_LIVE_RETRY_MS  equ 1000             ; retransmit interval
DNS_LIVE_TOTAL_MS  equ 3000             ; reply deadline after the first transmission
DNS_LIVE_ARP_MS   equ 250
DNS_LIVE_ARP_BUDGET_MS equ 3000
DNS_LIVE_CACHE_N  equ 8
DNS_LIVE_CACHE_SZ equ 320
DNS_REQUEST_N     equ 8                 ; active + queued; terminal records reclaimed boundedly
DNS_REQUEST_SZ    equ 280
DR_STATUS         equ 0
DR_NAME           equ 1                 ; normalized private name, <=253 + NUL
DR_GENERATION     equ 256
DR_DEADLINE       equ 264               ; immutable admission end-to-end deadline
DR_STARTED        equ 272
DNS_REQUEST_MS    equ DNS_LIVE_ARP_BUDGET_MS + DNS_LIVE_TOTAL_MS ; queue wait spends this 6 s maximum
DNS_RQ_MISS       equ 0
DNS_RQ_QUEUED     equ 1
DNS_RQ_ACTIVE     equ 2
DNS_RQ_DONE       equ 3
DNS_RQ_NX         equ 4
DNS_RQ_TIMEOUT    equ 5
DNS_RQ_CANCELLED  equ 6
DNS_RQ_NODATA     equ 8                 ; DNS_LOOKUP_NODATA + 2, existing codes stable
DCE_STATUS        equ 0                  ; 0 empty, 1 A, 2 NXDOMAIN, 6 NODATA (IN/A)
DCE_NAME          equ 1                  ; 255 bytes including NUL
DCE_IP            equ 256
DCE_EXPIRES_MS    equ 264
DCE_REASON        equ 260
DCE_TIME_KNOWN    equ 261
DCE_RESULT        equ 262
DCE_STORED_MS     equ 272
DCE_ROUTE_GENERATION equ 280
DCE_QUERY_GENERATION equ 288
DCE_INCARNATION   equ 296
DCE_TTL_S         equ 304
DCE_CLOCK_EPOCH   equ 312
DCR_NONE          equ 0
DCR_EXPIRED       equ 1
DCR_CLOCK         equ 2
DCR_ROUTE         equ 3
DCR_TTL_ZERO      equ 4
DCR_OVERFLOW      equ 5
DCR_EXHAUSTED     equ 6

DNS_CACHE_SNAPSHOT_SIZE equ 400
DSO_LOOKUP        equ 0
DSO_STATE         equ 4
DSO_RESULT        equ 8
DSO_IP            equ 12
DSO_TIME_KNOWN    equ 16
DSO_CACHE_KNOWN   equ 20
DSO_NOW_MS        equ 24
DSO_STORED_MS     equ 32
DSO_EXPIRES_MS    equ 40
DSO_REMAINING_MS  equ 48
DSO_TTL_S         equ 56
DSO_INITIAL_TTL_S equ 60
DSO_ROUTE_GENERATION equ 64
DSO_QUERY_GENERATION equ 72
DSO_CACHE_GENERATION equ 80
DSO_REQUEST_STATE equ 88
DSO_REASON        equ 92
DSO_REQUEST_DEADLINE equ 96
DSO_SOURCE_IP     equ 104
DSO_SERVER_IP     equ 108
DSO_GATEWAY_IP    equ 112
DSO_MASK_IP       equ 116
DSO_SOURCE_MAC    equ 120
DSO_CLOCK_EPOCH   equ 128
DSO_NAME          equ 144
DSO_ABSENT        equ 0
DSO_HIT           equ 1
DSO_QUEUED        equ 2
DSO_ACTIVE        equ 3
DSO_TIMEOUT       equ 4
DSO_CANCELLED     equ 5
DSO_EXPIRED       equ 6
DSO_UNCACHED      equ 7
DSO_CLOCK_UNKNOWN equ 8
DSO_STALE_ROUTE   equ 9

DNS_LOOKUP_MISS    equ 0
DNS_LOOKUP_A       equ 1
DNS_LOOKUP_NX      equ 2
DNS_LOOKUP_PENDING equ 3
DNS_LOOKUP_TIMEOUT equ 4
DNS_LOOKUP_BUSY    equ 5
DNS_LOOKUP_NODATA  equ 6               ; only IN/A queries are supported by this cache

DNS_WS_IDLE       equ 0
DNS_WS_WAIT_ARP   equ 1
DNS_WS_WAIT_REPLY equ 2
DNS_WS_DONE       equ 3
DNS_WS_NX         equ 4
DNS_WS_TIMEOUT    equ 5
DNS_WS_WAIT_TCP   equ 6
DNS_WS_NODATA     equ 7
DNS_TCP_MAX       equ 4096             ; bounded single DNS message, excluding prefix

; Read-only route handoff for sibling UDP clients. DNS/DHCP remains the mutable
; configuration owner; consumers receive one coherent value snapshot.
struc dns_route_snapshot
  .source_ip:  resd 1
  .gateway_ip: resd 1
  .mask_ip:    resd 1
  .source_mac: resb 6
endstruc

dns_wire_lock_acquire:
    lea  rdi, [rel dns_wire_lock]
    jmp  spin_acquire

dns_wire_lock_release:
    lea  rdi, [rel dns_wire_lock]
    jmp  spin_release

; dns_wire_state_peek -> EAX = state (TCP fallback projects as WAIT_REPLY),
; RDX = dns_query_started_ms (when the
;   last lookup started; 0 = none since boot), read together under dns_wire_lock.
;   Read-only (RCQ-40 J3 NETCHECK). clobbers: caller-saved.
dns_wire_state_peek:
    push rbx
    push r12
    call dns_wire_lock_acquire
    movzx ebx, byte [rel dns_wire_state]
    cmp  ebx, DNS_WS_WAIT_TCP
    jne  .sample
    mov  ebx, DNS_WS_WAIT_REPLY           ; preserve the existing public pending ABI
.sample:
    mov  r12, [rel dns_query_started_ms]
    call dns_wire_lock_release
    mov  eax, ebx
    mov  rdx, r12
    pop  r12
    pop  rbx
    ret

; Read the configured source, gateway and resolver together under the DNS lock.
; EAX=source IPv4, EDX=gateway IPv4, ECX=resolver IPv4 (all wire order).
; A zero source is absent configuration. No query, ARP touch or driver call.
; DHCP ACK scratch is deliberately not configuration authority.
dns_wire_config_peek:
    push rbx
    push r12
    push r13
    call dns_wire_lock_acquire
    mov  ebx, [rel dns_source_ip]
    mov  r12d, [rel dns_gateway_ip]
    mov  r13d, [rel dns_server_ip]
    call dns_wire_lock_release
    mov  eax, ebx
    mov  edx, r12d
    mov  ecx, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret

dns_wire_init:
    call dns_tcp_cancel_locked           ; boot init or an already quiescent reset
    call dns_request_cancel_locked
    lea  rdi, [rel dns_cache_live]
    xor  esi, esi
    mov  edx, DNS_LIVE_CACHE_N * DNS_LIVE_CACHE_SZ
    call memset
    mov  byte [rel dns_wire_state], DNS_WS_IDLE
    mov  byte [rel dns_bootstrap_active], 0
    mov  byte [rel dns_bootstrap_release], 0
    mov  byte [rel dns_m_query_tx], 0
    mov  byte [rel dns_m_response_rx], 0
    mov  byte [rel dns_m_answer_a], 0
    mov  dword [rel dns_server_ip], 0
    mov  dword [rel dns_source_ip], 0
    mov  dword [rel dns_gateway_ip], 0
    mov  dword [rel dns_mask_ip], 0
    mov  dword [rel dns_source_mac], 0
    mov  word [rel dns_source_mac + 4], 0
    mov  byte [rel dns_pending_name], 0
    mov  byte [rel dns_cache_victim], 0
    ret

dns_wire_bootstrap_arm:
    call dns_wire_lock_acquire
    mov  byte [rel dns_bootstrap_active], 1
    mov  byte [rel dns_bootstrap_release], 0
    call dns_wire_lock_release
    ret

; EAX=1 while the boot-only DHCP->DNS readiness transaction is incomplete.
; The UDP projection uses this to withhold liveness replies until BOOTLOG's DNS
; receipts are stable, eliminating a first-probe race without blocking the pump.
dns_wire_bootstrap_pending:
    push rbx
    call dns_wire_lock_acquire
    movzx ebx, byte [rel dns_bootstrap_active]
    call dns_wire_lock_release
    mov  eax, ebx
    pop  rbx
    ret

; Configure only from a DHCP ACK accepted by the live client.
; RDI=source MAC, ESI=leased source IP, EDX=DNS server, ECX=mask, R8D=gateway.
dns_wire_configure:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15d, r8d
    call dns_wire_lock_acquire
    call dns_tcp_cancel_locked
    call dns_request_cancel_locked
    mov  eax, [rbx]
    mov  [rel dns_source_mac], eax
    mov  ax, [rbx + 4]
    mov  [rel dns_source_mac + 4], ax
    mov  [rel dns_source_ip], r12d
    mov  [rel dns_server_ip], r13d
    mov  [rel dns_mask_ip], r14d
    mov  [rel dns_gateway_ip], r15d
    mov  eax, r13d
    and  eax, r14d
    mov  edx, r12d
    and  edx, r14d
    cmp  eax, edx
    jne  .via_gateway
    mov  [rel dns_next_hop_ip], r13d
    jmp  .configured
.via_gateway:
    mov  [rel dns_next_hop_ip], r15d
.configured:
    movzx ebx, byte [rel dns_bootstrap_active]
    call dns_wire_lock_release
    test ebx, ebx
    jz   .no_bootstrap
    lea  rdi, [rel str_dns_bootstrap_name]
    call dns_resolve_start
.no_bootstrap:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

dns_wire_dhcp_failed:
    call dns_wire_lock_acquire
    cmp  byte [rel dns_bootstrap_active], 1
    jne  .done
    cmp  dword [rel dns_server_ip], 0
    jne  .done
    lea  rdi, [rel dns_pending_name]
    lea  rsi, [rel str_dns_bootstrap_name]
    call dns_copy_cstr
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    mov  byte [rel dns_bootstrap_active], 0
    mov  byte [rel dns_bootstrap_release], 1
.done:
    call dns_wire_lock_release
    ret

dns_wire_take_release:
    push rbx
    call dns_wire_lock_acquire
    movzx ebx, byte [rel dns_bootstrap_release]
    mov  byte [rel dns_bootstrap_release], 0
    call dns_wire_lock_release
    mov  eax, ebx
    pop  rbx
    ret

dns_wire_set_source:
    push rbx
    mov  ebx, edi
    call dns_wire_lock_acquire
    call dns_tcp_cancel_locked
    call dns_request_cancel_locked
    mov  [rel dns_source_ip], ebx
    call dns_wire_lock_release
    pop  rbx
    ret

; Seed the ordinary static route before the boot-only DHCP discovery. A DHCP
; ACK later overwrites these fields with learned values; a timeout leaves the
; canonical static address usable for same-LAN SNTP instead of inventing a
; dependency on a lease.
; RDI=source MAC, ESI=source IP, EDX=mask, ECX=gateway -> RAX=0/-1.
dns_wire_route_seed:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    test rbx, rbx
    jz   .seed_bad
    call dns_wire_lock_acquire
    call dns_tcp_cancel_locked
    call dns_request_cancel_locked
    mov  eax, [rbx]
    mov  [rel dns_source_mac], eax
    mov  ax, [rbx + 4]
    mov  [rel dns_source_mac + 4], ax
    mov  [rel dns_source_ip], r12d
    mov  [rel dns_mask_ip], r13d
    mov  [rel dns_gateway_ip], r14d
    call dns_wire_lock_release
    xor  eax, eax
    jmp  .seed_out
.seed_bad:
    mov  rax, -1
.seed_out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dns_wire_route_snapshot(RDI=struct dns_route_snapshot) -> 0 ready / -1 absent.
dns_wire_route_snapshot:
    push rbx
    mov  rbx, rdi
    test rbx, rbx
    jz   .route_absent
    call dns_wire_lock_acquire
    mov  eax, [rel dns_source_ip]
    mov  [rbx + dns_route_snapshot.source_ip], eax
    mov  eax, [rel dns_gateway_ip]
    mov  [rbx + dns_route_snapshot.gateway_ip], eax
    mov  eax, [rel dns_mask_ip]
    mov  [rbx + dns_route_snapshot.mask_ip], eax
    mov  eax, [rel dns_source_mac]
    mov  [rbx + dns_route_snapshot.source_mac], eax
    mov  ax, [rel dns_source_mac + 4]
    mov  [rbx + dns_route_snapshot.source_mac + 4], ax
    cmp  dword [rel dns_source_ip], 0
    je   .route_unlock_absent
    cmp  dword [rel dns_mask_ip], 0
    je   .route_unlock_absent
    mov  eax, [rel dns_source_mac]
    movzx edx, word [rel dns_source_mac + 4]
    or   eax, edx
    jz   .route_unlock_absent
    call dns_wire_lock_release
    xor  eax, eax
    pop  rbx
    ret
.route_unlock_absent:
    call dns_wire_lock_release
.route_absent:
    mov  rax, -1
    pop  rbx
    ret

; Read-only selected upstream for DHCP advertisements. EAX=wire-order IPv4 or
; zero. Sample and qualify the whole configured route under its owner lock;
; raw DHCP ACK fields are neither configuration nor lease authority here.
; Public expiry/owner loss clears through dns_wire_configure; fleet static
; restore intentionally retains its resolver through dns_wire_set_source.
dns_wire_server_snapshot:
    push rbx
    xor  ebx, ebx
    call dns_wire_lock_acquire
    mov  eax, [rel dns_source_mac]
    movzx edx, word [rel dns_source_mac + 4]
    or   eax, edx
    jz   .done
    test byte [rel dns_source_mac], 1
    jnz  .done
    mov  eax, [rel dns_source_ip]
    call dns_wire_forwardable_ip
    test eax, eax
    jz   .done
    mov  r8d, eax
    mov  r10d, [rel dns_mask_ip]
    test r10d, r10d
    jz   .done
    mov  ecx, r10d
    bswap ecx
    not  ecx
    cmp  ecx, 3                           ; ordinary /1../30 route
    jb   .done
    lea  edx, [rcx + 1]
    test edx, ecx
    jnz  .done
    mov  ecx, r10d
    not  ecx
    mov  edx, r8d
    and  edx, ecx
    jz   .done                            ; source is network/broadcast
    cmp  edx, ecx
    je   .done
    mov  eax, [rel dns_server_ip]
    call dns_wire_forwardable_ip
    test eax, eax
    jz   .done
    cmp  eax, r8d                         ; no native DNS proxy exists
    je   .done
    mov  r9d, eax
    mov  edx, eax
    xor  edx, r8d
    test edx, r10d
    jnz  .gateway
    and  eax, ecx
    jz   .done                            ; on-link network/broadcast
    cmp  eax, ecx
    je   .done
    cmp  r9d, [rel dns_next_hop_ip]
    jne  .done                            ; route reseed invalidated next hop
    jmp  .selected
.gateway:
    mov  eax, [rel dns_gateway_ip]
    call dns_wire_forwardable_ip
    test eax, eax
    jz   .done                            ; off-link resolver needs a route
    cmp  eax, r8d
    je   .done
    cmp  eax, [rel dns_next_hop_ip]
    jne  .done
    mov  edx, eax
    xor  edx, r8d
    test edx, r10d
    jnz  .done
    and  eax, ecx
    jz   .done
    cmp  eax, ecx
    je   .done
.selected:
    mov  ebx, r9d
.done:
    call dns_wire_lock_release
    mov  eax, ebx
    pop  rbx
    ret

; EAX=wire-order IPv4 -> same or zero. Clobbers EDX only. Link-local,
; unspecified, loopback, multicast and reserved/broadcast cannot be forwarded.
dns_wire_forwardable_ip:
    test al, al
    jz   .bad
    cmp  al, 127
    je   .bad
    cmp  al, 224
    jae  .bad
    mov  edx, eax
    and  edx, 0xFFFF
    cmp  edx, 0xFEA9                       ; 169.254/16
    je   .bad
    ret
.bad:
    xor  eax, eax
    ret

dns_copy_cstr:
.cp:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rdi
    inc  rsi
    test al, al
    jnz  .cp
    ret

; Validate + lowercase a DNS presentation name. EAX=0 ok/-1.
dns_name_copy_validate:
    push rbx
    mov  rbx, rdi
    xor  ecx, ecx                         ; total chars
    xor  edx, edx                         ; current label chars
.next:
    movzx eax, byte [rsi]
    test al, al
    jz   .end
    cmp  al, ' '
    jbe  .bad
    cmp  al, 0x7f
    jae  .bad
    cmp  al, '.'
    je   .dot
    cmp  al, 'A'
    jb   .store
    cmp  al, 'Z'
    ja   .store
    or   al, 0x20
.store:
    cmp  edx, DNS_MAX_LABEL
    jae  .bad
    cmp  ecx, 253
    jae  .bad
    mov  [rdi], al
    inc  rdi
    inc  rsi
    inc  ecx
    inc  edx
    jmp  .next
.dot:
    test edx, edx
    jz   .bad
    cmp  ecx, 253
    jae  .bad
    mov  byte [rdi], '.'
    inc  rdi
    inc  rsi
    inc  ecx
    xor  edx, edx
    jmp  .next
.end:
    test ecx, ecx
    jz   .bad
    test edx, edx
    jz   .bad
    mov  byte [rdi], 0
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  byte [rbx], 0
    mov  rax, -1
    pop  rbx
    ret

; Case-insensitive ASCII DNS-name equality. EAX=1 equal/0 different.
dns_name_eq_ci:
.eq_loop:
    movzx eax, byte [rdi]
    movzx edx, byte [rsi]
    cmp  al, 'A'
    jb   .a_folded
    cmp  al, 'Z'
    ja   .a_folded
    or   al, 0x20
.a_folded:
    cmp  dl, 'A'
    jb   .b_folded
    cmp  dl, 'Z'
    ja   .b_folded
    or   dl, 0x20
.b_folded:
    cmp  al, dl
    jne  .not_eq
    test al, al
    jz   .equal
    inc  rdi
    inc  rsi
    jmp  .eq_loop
.equal:
    mov  eax, 1
    ret
.not_eq:
    xor  eax, eax
    ret

; RDI=dst, RSI=normalized name, EDX=host-order txid -> EAX=query len/-1.
dns_build_live_query:
    push rbx
    mov  rbx, rdi
    mov  eax, edx
    mov  [rbx + DNS_ID], ah
    mov  [rbx + DNS_ID + 1], al
    mov  byte [rbx + DNS_FLAGS], 1
    mov  byte [rbx + DNS_FLAGS + 1], 0
    mov  byte [rbx + DNS_QDCOUNT], 0
    mov  byte [rbx + DNS_QDCOUNT + 1], 1
    mov  qword [rbx + DNS_ANCOUNT], 0
    lea  rdi, [rbx + DNS_HDRLEN]
    call dns_encode_qname
    cmp  eax, -1
    je   .bad
    lea  rcx, [rbx + DNS_HDRLEN]
    add  rcx, rax
    mov  byte [rcx], 0
    mov  byte [rcx + 1], DNS_QTYPE_A
    mov  byte [rcx + 2], 0
    mov  byte [rcx + 3], DNS_QCLASS_IN
    add  eax, DNS_HDRLEN + 4
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret

; Cache time is a conservative local monotonic observation. boot_ms_now's zero
; also means uncalibrated/pre-start, so zero cannot authorize reusable content.
; A regression revokes every cache entry; catching up cannot revive old bytes.
; Caller holds dns_wire_lock. RAX=sample, EDX=known (all uint64 arithmetic).
dns_cache_clock_locked:
    call boot_ms_now
    mov  [rel dns_cache_clock_sample], rax
    test rax, rax
    jz   .unknown
    cmp  rax, [rel dns_cache_clock_last]
    jb   .unknown
    mov  [rel dns_cache_clock_last], rax
    cmp  qword [rel dns_cache_clock_epoch], 0
    jne  .known
    mov  qword [rel dns_cache_clock_epoch], 1
.known:
    mov  byte [rel dns_cache_clock_known], 1
    mov  edx, 1
    ret
.unknown:
    cmp  byte [rel dns_cache_clock_known], 0
    je   .already_unknown
    cmp  qword [rel dns_cache_clock_epoch], -1
    je   .revoke
    inc  qword [rel dns_cache_clock_epoch]
.revoke:
    mov  eax, DCR_CLOCK
    call dns_cache_revoke_locked
.already_unknown:
    mov  byte [rel dns_cache_clock_known], 0
    mov  rax, [rel dns_cache_clock_sample]
    xor  edx, edx
    ret

; EAX=reason; revoke authority, retain bounded diagnostic tombstones only.
dns_cache_revoke_locked:
    lea  r8, [rel dns_cache_live]
    mov  ecx, DNS_LIVE_CACHE_N
.loop:
    mov  byte [r8 + DCE_TIME_KNOWN], 0
    cmp  byte [r8 + DCE_STATUS], 0
    je   .next
    mov  byte [r8 + DCE_STATUS], 0
    mov  [r8 + DCE_REASON], al
.next:
    add  r8, DNS_LIVE_CACHE_SZ
    dec  ecx
    jnz  .loop
    ret

; Exact normalized name including invalid/expired tombstone, never authority.
dns_cache_name_locked:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    lea  rbx, [rel dns_cache_live]
    mov  r13d, DNS_LIVE_CACHE_N
.scan:
    cmp  byte [rbx + DCE_NAME], 0
    je   .next
    lea  rdi, [rbx + DCE_NAME]
    mov  rsi, r12
    call dns_name_eq_ci
    test eax, eax
    jnz  .hit
.next:
    add  rbx, DNS_LIVE_CACHE_SZ
    dec  r13d
    jnz  .scan
    xor  eax, eax
    jmp  .out
.hit:
    mov  rax, rbx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Find reusable A/NX/NODATA. Internal sample entry avoids re-sampling a snapshot.
dns_cache_find_locked:
    push rdi
    call dns_cache_clock_locked
    pop  rdi
    jmp  dns_cache_find_sample_locked

dns_cache_find_sample_locked:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    cmp  byte [rel dns_cache_clock_known], 1
    jne  .miss
    mov  r13, [rel dns_cache_clock_sample]
    mov  rdi, r12
    call dns_cache_name_locked
    test rax, rax
    jz   .out
    mov  rbx, rax
    cmp  byte [rbx + DCE_STATUS], DNS_LOOKUP_A
    je   .live
    cmp  byte [rbx + DCE_STATUS], DNS_LOOKUP_NX
    je   .live
    cmp  byte [rbx + DCE_STATUS], DNS_LOOKUP_NODATA
    jne  .miss
.live:
    mov  eax, DCR_ROUTE
    mov  rdx, [rel dns_request_generation]
    cmp  rdx, -1
    je   .revoke
    cmp  rdx, [rbx + DCE_ROUTE_GENERATION]
    jne  .revoke
    mov  eax, DCR_CLOCK
    cmp  byte [rbx + DCE_TIME_KNOWN], 1
    jne  .revoke
    mov  rdx, [rel dns_cache_clock_epoch]
    cmp  rdx, [rbx + DCE_CLOCK_EPOCH]
    jne  .revoke
    mov  rdx, [rbx + DCE_EXPIRES_MS]
    test rdx, rdx
    jz   .revoke                         ; no immortal zero-expiry sentinel
    mov  eax, DCR_EXPIRED
    cmp  r13, rdx
    jae  .revoke                         ; exact exclusive expiry
    mov  rax, rbx
    jmp  .out
.revoke:
    mov  byte [rbx + DCE_STATUS], 0
    mov  [rbx + DCE_REASON], al
.miss:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Qualified response publication. TTL0/unknown/regressed/overflow time cannot
; create a cache hit; a diagnostic record preserves the genuine parser result
; and query incarnation without altering the transport's terminal state.
; RDI=name,ESI=A/NX/NODATA,EDX=IPv4,ECX=TTL seconds. Only IN/A queries.
dns_cache_store_locked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    cmp  r13d, DNS_LOOKUP_A
    je   .sample
    cmp  r13d, DNS_LOOKUP_NX
    je   .sample
    cmp  r13d, DNS_LOOKUP_NODATA
    jne  .bad
.sample:
    call dns_cache_clock_locked
    mov  [rsp], rax
    mov  qword [rsp + 8], 0             ; checked exclusive deadline
    mov  dword [rsp + 16], DCR_CLOCK
    mov  dword [rsp + 20], 0            ; deadline provenance known
    test edx, edx
    jz   .slot_select
    mov  dword [rsp + 16], DCR_TTL_ZERO
    mov  dword [rsp + 20], 1
    mov  [rsp + 8], rax
    test r15d, r15d
    jz   .slot_select
    mov  dword [rsp + 16], DCR_OVERFLOW
    mov  dword [rsp + 20], 0
    imul rdx, r15, 1000                 ; uint32 TTL *1000 fits uint64
    add  rax, rdx
    jc   .slot_select                   ; refuse caching rather than wrap/saturate authority
    mov  [rsp + 8], rax
    mov  dword [rsp + 16], DCR_NONE
    mov  dword [rsp + 20], 1
    cmp  qword [rel dns_request_generation], -1
    je   .exhausted_route
    cmp  qword [rel dns_cache_clock_epoch], -1
    jne  .slot_select
.exhausted_route:
    mov  dword [rsp + 16], DCR_ROUTE
    mov  dword [rsp + 20], 0
.slot_select:
    mov  rdi, r12
    call dns_cache_name_locked
    mov  rbx, rax
    test rbx, rbx
    jnz  .slot
    lea  rbx, [rel dns_cache_live]
    mov  ecx, DNS_LIVE_CACHE_N
.empty:
    cmp  byte [rbx + DCE_STATUS], 0
    je   .slot
    add  rbx, DNS_LIVE_CACHE_SZ
    dec  ecx
    jnz  .empty
    movzx eax, byte [rel dns_cache_victim]
    inc  byte [rel dns_cache_victim]
    and  byte [rel dns_cache_victim], DNS_LIVE_CACHE_N - 1
    imul eax, eax, DNS_LIVE_CACHE_SZ
    lea  rbx, [rel dns_cache_live]
    add  rbx, rax
.slot:
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, DNS_LIVE_CACHE_SZ
    call memset
    lea  rdi, [rbx + DCE_NAME]
    mov  rsi, r12
    call dns_copy_cstr
    mov  [rbx + DCE_RESULT], r13b
    cmp  r13d, DNS_LOOKUP_A
    jne  .metadata
    mov  [rbx + DCE_IP], r14d
.metadata:
    mov  rax, [rsp]
    mov  [rbx + DCE_STORED_MS], rax
    mov  rax, [rsp + 8]
    mov  [rbx + DCE_EXPIRES_MS], rax
    mov  eax, [rsp + 16]
    mov  [rbx + DCE_REASON], al
    mov  eax, [rsp + 20]
    mov  [rbx + DCE_TIME_KNOWN], al
    mov  [rbx + DCE_TTL_S], r15d
    mov  rax, [rel dns_request_generation]
    mov  [rbx + DCE_ROUTE_GENERATION], rax
    mov  rax, [rel dns_query_incarnation]
    mov  [rbx + DCE_QUERY_GENERATION], rax
    mov  rax, [rel dns_cache_clock_epoch]
    mov  [rbx + DCE_CLOCK_EPOCH], rax
    mov  rax, [rel dns_cache_incarnation_next]
    cmp  rax, -1
    je   .no_incarnation
    inc  rax
    mov  [rel dns_cache_incarnation_next], rax
    mov  [rbx + DCE_INCARNATION], rax
    cmp  byte [rbx + DCE_REASON], DCR_NONE
    jne  .ok
    mov  [rbx + DCE_STATUS], r13b         ; publish authority last, under DNS lock
.ok:
    xor  eax, eax
    jmp  .out
.no_incarnation:
    mov  byte [rbx + DCE_REASON], DCR_EXHAUSTED
    mov  byte [rbx + DCE_TIME_KNOWN], 0
.bad:
    mov  rax, -1
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=name -> EAX=DNS_LOOKUP_*, EDX=IPv4 for A.
dns_cache_get:
    push rbx
    push r12
    mov  r12, rdi
    call dns_wire_lock_acquire
    test r12, r12
    jz   .miss
    lea  rdi, [rel dns_name_tmp]
    mov  rsi, r12
    call dns_name_copy_validate
    test eax, eax
    jnz  .miss
    lea  rdi, [rel dns_name_tmp]
    call dns_cache_find_locked
    test rax, rax
    jz   .state
    mov  rbx, rax
    movzx eax, byte [rbx + DCE_STATUS]
    mov  edx, [rbx + DCE_IP]
    jmp  .out
.state:
    call dns_request_prune_locked
    call dns_request_sync_locked
    lea  rdi, [rel dns_name_tmp]
    call dns_request_find_locked
    test rax, rax
    jz   .legacy
    movzx eax, byte [rax + DR_STATUS]
    cmp  eax, DNS_RQ_QUEUED
    je   .pending
    cmp  eax, DNS_RQ_ACTIVE
    je   .pending
    cmp  eax, DNS_RQ_TIMEOUT
    je   .timeout
    cmp  eax, DNS_RQ_CANCELLED
    je   .timeout
    jmp  .miss                          ; terminal A/NX with expired TTL is a cache miss
.legacy:
    lea  rdi, [rel dns_pending_name]
    lea  rsi, [rel dns_name_tmp]
    call dns_name_eq_ci
    test eax, eax
    jz   .miss
    movzx eax, byte [rel dns_wire_state]
    cmp  eax, DNS_WS_WAIT_ARP
    je   .pending
    cmp  eax, DNS_WS_WAIT_REPLY
    je   .pending
    cmp  eax, DNS_WS_WAIT_TCP
    je   .pending
    cmp  eax, DNS_WS_TIMEOUT
    je   .timeout
.miss:
    mov  eax, DNS_LOOKUP_MISS
    xor  edx, edx
    jmp  .out
.pending:
    mov  eax, DNS_LOOKUP_PENDING
    xor  edx, edx
    jmp  .out
.timeout:
    mov  eax, DNS_LOOKUP_TIMEOUT
    xor  edx, edx
.out:
    mov  ebx, eax
    mov  r12d, edx
    call dns_wire_lock_release
    mov  eax, ebx
    mov  edx, r12d
    pop  r12
    pop  rbx
    ret

; Caller-owned bounded value snapshot. No pointers escape, no nested public
; cache/status/route calls. One lock and one clock sample cover every field.
; RDI=name,RSI=output,EDX=capacity -> RAX=0/-1. Short/null output untouched.
dns_cache_snapshot:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rbx, rsi
    test rbx, rbx
    jz   .bad
    cmp  edx, DNS_CACHE_SNAPSHOT_SIZE
    jb   .bad
    test r12, r12
    jz   .bad
    call dns_wire_lock_acquire
    lea  rdi, [rel dns_name_tmp]
    mov  rsi, r12
    call dns_name_copy_validate
    test eax, eax
    jnz  .unlock_bad
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, DNS_CACHE_SNAPSHOT_SIZE
    call memset
    lea  rdi, [rbx + DSO_NAME]
    lea  rsi, [rel dns_name_tmp]
    call dns_copy_cstr
    call dns_cache_clock_locked
    mov  [rbx + DSO_NOW_MS], rax
    mov  [rbx + DSO_TIME_KNOWN], edx
    mov  rax, [rel dns_cache_clock_epoch]
    mov  [rbx + DSO_CLOCK_EPOCH], rax
    mov  rax, [rel dns_request_generation]
    mov  [rbx + DSO_ROUTE_GENERATION], rax
    mov  eax, [rel dns_source_ip]
    mov  [rbx + DSO_SOURCE_IP], eax
    mov  eax, [rel dns_server_ip]
    mov  [rbx + DSO_SERVER_IP], eax
    mov  eax, [rel dns_gateway_ip]
    mov  [rbx + DSO_GATEWAY_IP], eax
    mov  eax, [rel dns_mask_ip]
    mov  [rbx + DSO_MASK_IP], eax
    mov  eax, [rel dns_source_mac]
    mov  [rbx + DSO_SOURCE_MAC], eax
    mov  ax, [rel dns_source_mac + 4]
    mov  [rbx + DSO_SOURCE_MAC + 4], ax
    lea  rdi, [rel dns_name_tmp]
    call dns_cache_find_sample_locked
    test rax, rax
    jz   .request
    mov  r13, rax
    movzx eax, byte [r13 + DCE_STATUS]
    mov  [rbx + DSO_LOOKUP], eax
    mov  [rbx + DSO_RESULT], eax
    mov  eax, [r13 + DCE_IP]
    mov  [rbx + DSO_IP], eax
    mov  dword [rbx + DSO_STATE], DSO_HIT
    mov  dword [rbx + DSO_CACHE_KNOWN], 1
    call .record_metadata
    mov  rax, [r13 + DCE_EXPIRES_MS]
    sub  rax, [rbx + DSO_NOW_MS]
    mov  [rbx + DSO_REMAINING_MS], rax
    xor  edx, edx
    mov  ecx, 1000
    div  rcx
    mov  [rbx + DSO_TTL_S], eax           ; conservative floor, full uint64 subtraction/division
    jmp  .done
.request:
    ; Derive status without pruning/resampling or calling another public API.
    call dns_request_sync_locked
    lea  rdi, [rel dns_name_tmp]
    call dns_request_find_locked
    test rax, rax
    jz   .tombstone
    mov  r13, rax
    movzx eax, byte [r13 + DR_STATUS]
    mov  [rbx + DSO_REQUEST_STATE], eax
    mov  rdx, [r13 + DR_GENERATION]
    cmp  rdx, [rel dns_request_generation]
    jne  .cancelled
    mov  rdx, [r13 + DR_DEADLINE]
    mov  [rbx + DSO_REQUEST_DEADLINE], rdx
    cmp  eax, DNS_RQ_CANCELLED
    je   .cancelled
    cmp  eax, DNS_RQ_TIMEOUT
    je   .timeout
    cmp  eax, DNS_RQ_QUEUED
    je   .pending
    cmp  eax, DNS_RQ_ACTIVE
    jne  .tombstone                      ; terminal A/NX residue is never a cache hit
    mov  rax, [rel dns_query_incarnation]
    mov  [rbx + DSO_QUERY_GENERATION], rax
.pending:
    cmp  dword [rbx + DSO_TIME_KNOWN], 1
    jne  .pending_unknown
    mov  rax, [rbx + DSO_NOW_MS]
    cmp  rax, [rbx + DSO_REQUEST_DEADLINE]
    jae  .timeout
    mov  eax, DSO_QUEUED
    cmp  dword [rbx + DSO_REQUEST_STATE], DNS_RQ_QUEUED
    je   .pending_state
    mov  eax, DSO_ACTIVE
.pending_state:
    mov  [rbx + DSO_STATE], eax
    mov  dword [rbx + DSO_LOOKUP], DNS_LOOKUP_PENDING
    jmp  .done
.pending_unknown:
    mov  dword [rbx + DSO_STATE], DSO_CLOCK_UNKNOWN
    mov  dword [rbx + DSO_LOOKUP], DNS_LOOKUP_PENDING
    jmp  .done
.cancelled:
    mov  dword [rbx + DSO_REQUEST_STATE], DNS_RQ_CANCELLED
    mov  dword [rbx + DSO_STATE], DSO_CANCELLED
    mov  dword [rbx + DSO_LOOKUP], DNS_LOOKUP_TIMEOUT
    jmp  .done
.timeout:
    mov  dword [rbx + DSO_STATE], DSO_TIMEOUT
    mov  dword [rbx + DSO_LOOKUP], DNS_LOOKUP_TIMEOUT
    jmp  .done
.tombstone:
    lea  rdi, [rel dns_name_tmp]
    call dns_cache_name_locked
    test rax, rax
    jz   .done                          ; explicit absent, no stale global answer
    mov  r13, rax
    mov  rdx, [r13 + DCE_ROUTE_GENERATION]
    cmp  rdx, [rel dns_request_generation]
    jne  .stale
    call .record_metadata
    movzx eax, byte [r13 + DCE_REASON]
    cmp  eax, DCR_EXPIRED
    je   .expired
    cmp  eax, DCR_CLOCK
    je   .clock_unknown
    cmp  eax, DCR_ROUTE
    je   .stale
    mov  dword [rbx + DSO_STATE], DSO_UNCACHED
    ; Only a current real activation can supply an uncached response receipt.
    cmp  qword [r13 + DCE_QUERY_GENERATION], 0
    je   .done
    movzx eax, byte [r13 + DCE_RESULT]
    mov  [rbx + DSO_RESULT], eax
    mov  eax, [r13 + DCE_IP]
    mov  [rbx + DSO_IP], eax
    jmp  .done
.expired:
    mov  dword [rbx + DSO_STATE], DSO_EXPIRED
    jmp  .done
.clock_unknown:
    mov  dword [rbx + DSO_STATE], DSO_CLOCK_UNKNOWN
    jmp  .done
.stale:
    mov  dword [rbx + DSO_STATE], DSO_STALE_ROUTE
    jmp  .done
.record_metadata:
    movzx eax, byte [r13 + DCE_REASON]
    mov  [rbx + DSO_REASON], eax
    mov  rax, [r13 + DCE_INCARNATION]
    mov  [rbx + DSO_CACHE_GENERATION], rax
    mov  rax, [r13 + DCE_QUERY_GENERATION]
    mov  [rbx + DSO_QUERY_GENERATION], rax
    mov  eax, [r13 + DCE_TTL_S]
    mov  [rbx + DSO_INITIAL_TTL_S], eax
    cmp  byte [r13 + DCE_TIME_KNOWN], 1
    jne  .record_out
    cmp  dword [rbx + DSO_TIME_KNOWN], 1
    jne  .record_out
    mov  rax, [r13 + DCE_STORED_MS]
    mov  [rbx + DSO_STORED_MS], rax
    mov  rax, [r13 + DCE_EXPIRES_MS]
    mov  [rbx + DSO_EXPIRES_MS], rax
.record_out:
    ret
.done:
    call dns_wire_lock_release
    xor  eax, eax
    jmp  .out
.unlock_bad:
    call dns_wire_lock_release
.bad:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Requests retain only bounded per-name metadata. All wire/TCP buffers remain
; owned by the single active engine. Callers hold dns_wire_lock throughout.
; EAX=index -> RAX=private record.
dns_request_ptr:
    imul eax, eax, DNS_REQUEST_SZ
    lea  rdx, [rel dns_requests]
    add  rax, rdx
    ret

; RDI=normalized name -> RAX=record/0, EDX=index when found.
dns_request_find_locked:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    lea  rbx, [rel dns_requests]
    xor  r13d, r13d
.scan:
    cmp  byte [rbx + DR_STATUS], DNS_RQ_MISS
    je   .next
    lea  rdi, [rbx + DR_NAME]
    mov  rsi, r12
    call dns_name_eq_ci
    test eax, eax
    jnz  .found
.next:
    add  rbx, DNS_REQUEST_SZ
    inc  r13d
    cmp  r13d, DNS_REQUEST_N
    jb   .scan
    xor  eax, eax
    jmp  .out
.found:
    mov  rax, rbx
    mov  edx, r13d
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Pending work shares the cache's monotonic clock observation. Unknown time
; cannot bound a request or authorize a response. Expire live records without
; changing route generation or erasing a TCP owner whose try-lock is busy.
; Caller holds dns_wire_lock. RAX=sample, EDX=known; unknown returns both zero.
dns_request_time_locked:
    call dns_cache_clock_locked
    test edx, edx
    jnz  .out
    push rbx
    push r12
    lea  rbx, [rel dns_requests]
    mov  r12d, DNS_REQUEST_N
.scan:
    cmp  byte [rbx + DR_STATUS], DNS_RQ_QUEUED
    je   .expire
    cmp  byte [rbx + DR_STATUS], DNS_RQ_ACTIVE
    jne  .next
.expire:
    mov  byte [rbx + DR_STATUS], DNS_RQ_TIMEOUT
.next:
    add  rbx, DNS_REQUEST_SZ
    dec  r12d
    jnz  .scan
    mov  byte [rel dns_request_count], 0
    cmp  byte [rel dns_request_active], 0xff
    je   .unknown
    ; The active slot remains reserved until actual TCP cleanup detaches.
    ; Completed answers keep their record; only a live wire FSM is expired.
    movzx eax, byte [rel dns_wire_state]
    cmp  eax, DNS_WS_WAIT_ARP
    je   .cancel
    cmp  eax, DNS_WS_WAIT_REPLY
    je   .cancel
    cmp  eax, DNS_WS_WAIT_TCP
    jne  .unknown
.cancel:
    call dns_tcp_cancel_locked
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    call dns_request_sync_locked
.unknown:
    pop  r12
    pop  rbx
    xor  eax, eax
    xor  edx, edx
.out:
    ret

; Remove obsolete/expired queued indices before any terminal slot can be
; reclaimed. Compact FIFO in place; no stale index can alias a later request.
dns_request_prune_locked:
    push rbx
    push r12
    push r13
    push r14
    call dns_request_time_locked
    test edx, edx
    jz   .out
    mov  r12, rax
    lea  rbx, [rel dns_request_order]
    xor  r13d, r13d
    xor  r14d, r14d
.scan:
    cmp  r13b, [rel dns_request_count]
    jae  .done
    movzx esi, byte [rbx + r13]
    mov  eax, esi
    call dns_request_ptr
    cmp  byte [rax + DR_STATUS], DNS_RQ_QUEUED
    jne  .next
    mov  rdx, [rel dns_request_generation]
    cmp  [rax + DR_GENERATION], rdx
    jne  .cancel
    cmp  r12, [rax + DR_DEADLINE]
    jae  .expire
    mov  [rbx + r14], sil
    inc  r14d
    jmp  .next
.cancel:
    mov  byte [rax + DR_STATUS], DNS_RQ_CANCELLED
    jmp  .next
.expire:
    mov  byte [rax + DR_STATUS], DNS_RQ_TIMEOUT
.next:
    inc  r13d
    jmp  .scan
.done:
    mov  [rel dns_request_count], r14b
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Publish the active request's terminal state, but reserve its slot/engine until
; the actual owned TCP handle and finishing flag have both detached.
dns_request_sync_locked:
    push rbx
    movzx eax, byte [rel dns_request_active]
    cmp  eax, DNS_REQUEST_N
    jae  .out
    call dns_request_ptr
    mov  rbx, rax
    movzx eax, byte [rel dns_wire_state]
    cmp  eax, DNS_WS_WAIT_ARP
    je   .out
    cmp  eax, DNS_WS_WAIT_REPLY
    je   .out
    cmp  eax, DNS_WS_WAIT_TCP
    je   .out
    cmp  byte [rbx + DR_STATUS], DNS_RQ_ACTIVE
    jne  .detach
    cmp  eax, DNS_WS_NODATA
    jne  .legacy_terminal
    mov  eax, DNS_RQ_NODATA
    jmp  .terminal
.legacy_terminal:
    cmp  eax, DNS_WS_DONE
    jb   .detach
    cmp  eax, DNS_WS_TIMEOUT
    ja   .detach
.terminal:
    mov  [rbx + DR_STATUS], al            ; legacy DONE/NX/TIMEOUT retain their codes
.detach:
    cmp  qword [rel dns_tcp_handle], 0
    jne  .out
    cmp  byte [rel dns_tcp_finishing], 0
    jne  .out
    mov  byte [rel dns_request_active], 0xff
.out:
    pop  rbx
    ret

; Configure/source/route/reset cancellation. TCP cancellation is performed
; first by the configuration owner; this never erases its deferred cleanup.
dns_request_cancel_locked:
    push rbx
    push r12
    cmp  qword [rel dns_request_generation], -1
    je   .exhausted
    inc  qword [rel dns_request_generation]
.exhausted:
    mov  eax, DCR_ROUTE
    call dns_cache_revoke_locked
    lea  rbx, [rel dns_requests]
    mov  r12d, DNS_REQUEST_N
.scan:
    movzx eax, byte [rbx + DR_STATUS]
    cmp  eax, DNS_RQ_QUEUED
    je   .cancel
    cmp  eax, DNS_RQ_ACTIVE
    jne  .next
.cancel:
    mov  byte [rbx + DR_STATUS], DNS_RQ_CANCELLED
.next:
    add  rbx, DNS_REQUEST_SZ
    dec  r12d
    jnz  .scan
    mov  byte [rel dns_request_count], 0
    cmp  byte [rel dns_request_active], 0xff
    je   .out
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    call dns_request_sync_locked
.out:
    pop  r12
    pop  rbx
    ret

; RAX=now, EDX=phase budget -> RAX=min(now+budget, admission deadline).
; Saturate phase addition on carry; an admission whose clock addition itself
; overflows is refused rather than creating an unbounded/wrapped request.
dns_request_phase_deadline_locked:
    mov  r8, rax
    add  r8, rdx
    jnc  .bound
    mov  r8, -1
.bound:
    movzx eax, byte [rel dns_request_active]
    cmp  eax, DNS_REQUEST_N
    jae  .none
    call dns_request_ptr
    mov  rax, [rax + DR_DEADLINE]
    cmp  r8, rax
    cmovb rax, r8
    ret
.none:
    mov  rax, r8
    ret

; FIFO, at most N metadata skips and one real activation per call. The old
; transport's buffers/cookie are never available merely because it is terminal.
dns_request_dispatch_locked:
    push rbx
    push r12
    push r13
    push r14
    cmp  byte [rel dns_request_active], 0xff
    jne  .out
    cmp  qword [rel dns_tcp_handle], 0
    jne  .out
    cmp  byte [rel dns_tcp_finishing], 0
    jne  .out
    mov  r14d, DNS_REQUEST_N
.next:
    movzx edx, byte [rel dns_request_count]
    test edx, edx
    jz   .out
    lea  rdi, [rel dns_request_order]
    movzx r12d, byte [rdi]
    dec  edx
    mov  [rel dns_request_count], dl
    lea  rsi, [rdi + 1]
    call memcpy                         ; bounded forward compaction, dst < src
    mov  eax, r12d
    call dns_request_ptr
    mov  r13, rax
    cmp  byte [rax + DR_STATUS], DNS_RQ_QUEUED
    jne  .skip
    lea  rdi, [rax + DR_NAME]
    call dns_cache_find_locked
    test rax, rax
    jz   .activate
    movzx eax, byte [rax + DCE_STATUS]
    add  eax, 2                         ; cached A/NX/NODATA -> matching request terminal code
    mov  [r13 + DR_STATUS], al
.skip:
    dec  r14d
    jnz  .next
    jmp  .out
.activate:
    mov  [rel dns_request_active], r12b
    mov  byte [r13 + DR_STATUS], DNS_RQ_ACTIVE
    mov  rdi, r13
    call dns_request_activate_locked
    call dns_request_sync_locked
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Explicit status ABI, separate from the unchanged DNS_LOOKUP_* ABI:
; RDI=name -> EAX=DNS_RQ_*, RDX=immutable admission deadline (0 for cache only).
; Terminal failure/cancel records are retained until bounded slot reclamation;
; A/NX/NODATA authority still comes only from the existing TTL cache.
dns_request_status:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    call dns_wire_lock_acquire
    xor  ebx, ebx
    xor  r13d, r13d
    test r12, r12
    jz   .out
    lea  rdi, [rel dns_name_tmp]
    mov  rsi, r12
    call dns_name_copy_validate
    test eax, eax
    jnz  .out
    call dns_request_prune_locked
    call dns_request_sync_locked
    lea  rdi, [rel dns_name_tmp]
    call dns_request_find_locked
    test rax, rax
    jz   .cache
    movzx ebx, byte [rax + DR_STATUS]
    mov  r13, [rax + DR_DEADLINE]
    cmp  ebx, DNS_RQ_DONE
    je   .cache
    cmp  ebx, DNS_RQ_NX
    je   .cache
    cmp  ebx, DNS_RQ_NODATA
    jne  .out
.cache:
    lea  rdi, [rel dns_name_tmp]
    call dns_cache_find_locked
    test rax, rax
    jz   .miss
    movzx ebx, byte [rax + DCE_STATUS]
    add  ebx, 2
    jmp  .out
.miss:
    xor  ebx, ebx                       ; an expired A/NX record conveys no authority
.out:
    call dns_wire_lock_release
    mov  eax, ebx
    mov  rdx, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; Privately admit/coalesce one name. Legacy return values are unchanged:
; both queued and active are PENDING; full bounded capacity is BUSY. A new
; explicit retry may replace a terminal record after actual TCP detachment.
dns_resolve_start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    xor  r15d, r15d
    call dns_wire_lock_acquire
    test r12, r12
    jz   .badname
    lea  rdi, [rel dns_name_tmp]
    mov  rsi, r12
    call dns_name_copy_validate
    test eax, eax
    jnz  .badname
    lea  rdi, [rel dns_name_tmp]
    call dns_cache_find_locked
    test rax, rax
    jz   .not_cached
    movzx ebx, byte [rax + DCE_STATUS]
    mov  r15d, [rax + DCE_IP]
    jmp  .unlock
.not_cached:
    call dns_request_prune_locked
    call dns_request_sync_locked
    lea  rdi, [rel dns_name_tmp]
    call dns_request_find_locked
    test rax, rax
    jz   .allocate
    mov  r13, rax
    mov  r14d, edx
    movzx eax, byte [r13 + DR_STATUS]
    cmp  eax, DNS_RQ_QUEUED
    je   .pending
    cmp  eax, DNS_RQ_ACTIVE
    je   .pending
    cmp  r14b, [rel dns_request_active]
    je   .busy                          ; cancelled same-name slot is still pinned by TCP
    jmp  .admit
.allocate:
    movzx r14d, byte [rel dns_request_victim]
    mov  r12d, DNS_REQUEST_N
.scan:
    cmp  r14b, [rel dns_request_active]
    je   .next
    mov  eax, r14d
    call dns_request_ptr
    mov  r13, rax
    cmp  byte [rax + DR_STATUS], DNS_RQ_QUEUED
    je   .next
    cmp  byte [rax + DR_STATUS], DNS_RQ_ACTIVE
    jne  .admit
.next:
    inc  r14d
    and  r14d, DNS_REQUEST_N - 1
    dec  r12d
    jnz  .scan
.busy:
    mov  ebx, DNS_LOOKUP_BUSY
    jmp  .unlock
.admit:
    mov  rdi, r13
    xor  esi, esi
    mov  edx, DNS_REQUEST_SZ
    call memset
    lea  rdi, [r13 + DR_NAME]
    lea  rsi, [rel dns_name_tmp]
    call dns_copy_cstr
    lea  eax, [r14d + 1]
    and  eax, DNS_REQUEST_N - 1
    mov  [rel dns_request_victim], al
    mov  rax, [rel dns_request_generation]
    mov  [r13 + DR_GENERATION], rax
    cmp  rax, -1
    je   .exhausted
    call dns_request_time_locked
    test edx, edx
    jz   .exhausted
    mov  [r13 + DR_STARTED], rax
    add  rax, DNS_REQUEST_MS
    jc   .exhausted
    mov  [r13 + DR_DEADLINE], rax
    mov  byte [r13 + DR_STATUS], DNS_RQ_QUEUED
    lea  rdi, [rel dns_request_order]
    movzx eax, byte [rel dns_request_count]
    mov  [rdi + rax], r14b
    inc  byte [rel dns_request_count]
    call dns_request_dispatch_locked
    cmp  byte [r13 + DR_STATUS], DNS_RQ_TIMEOUT
    je   .timeout
.pending:
    mov  ebx, DNS_LOOKUP_PENDING
    jmp  .unlock
.exhausted:
    mov  byte [r13 + DR_STATUS], DNS_RQ_TIMEOUT
.timeout:
    mov  ebx, DNS_LOOKUP_TIMEOUT
    jmp  .unlock
.badname:
    mov  ebx, DNS_LOOKUP_MISS
.unlock:
    call dns_wire_lock_release
    mov  eax, ebx
    mov  edx, r15d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

dns_request_activate_locked:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel dns_pending_name]
    lea  rsi, [rbx + DR_NAME]
    call dns_copy_cstr
    mov  rax, [rel dns_query_incarnation_next]
    cmp  rax, -1
    je   .build_bad
    inc  rax
    mov  [rel dns_query_incarnation_next], rax
    mov  [rel dns_query_incarnation], rax
    mov  rax, [rel dns_request_generation]
    mov  [rel dns_query_route_generation], rax
    cmp  dword [rel dns_server_ip], 0
    je   .build_bad
    cmp  dword [rel dns_next_hop_ip], 0
    je   .build_bad
    cmp  dword [rel dns_source_ip], 0
    je   .build_bad
    ; RFC 5452: an unpredictable txid AND source port per query, from the
    ; keep's CSPRNG (HMAC_DRBG over RDSEED/RDRAND). Never fall back to TSC.
    lea  rdi, [rel dns_query_entropy]
    mov  esi, 4
    call csprng_generate
    test rax, rax
    jnz  .no_entropy
    movzx eax, word [rel dns_query_entropy + 2]
    and  eax, 0x3FFF
    add  eax, DNS_LIVE_PORT_BASE
    cmp  eax, DNS_LIVE_NTP_PORT
    jne  .port_ok
    xor  eax, 1                             ; 49155: still unpredictable, never NTP's
.port_ok:
    mov  [rel dns_query_port], ax
    movzx eax, word [rel dns_query_entropy]
    test eax, eax
    jnz  .txid_ok
    inc  eax                                ; 0 is the only biased value
.txid_ok:
    mov  [rel dns_txid], ax
    mov  dword [rel dns_query_entropy], 0
    mov  byte [rel dns_query_attempts], 0
    mov  edx, eax
    lea  rdi, [rel dns_query_live]
    lea  rsi, [rel dns_pending_name]
    call dns_build_live_query
    cmp  eax, -1
    je   .build_bad
    mov  [rel dns_query_live_len], eax
    call dns_request_time_locked
    test edx, edx
    jz   .build_bad
    mov  rdx, [rbx + DR_STARTED]
    mov  [rel dns_query_started_ms], rdx   ; includes this request's queue wait
    mov  edx, DNS_LIVE_ARP_BUDGET_MS
    call dns_request_phase_deadline_locked
    mov  [rel dns_deadline_ms], rax
    mov  qword [rel dns_arp_retry_ms], 0
    mov  byte [rel dns_wire_state], DNS_WS_WAIT_ARP
    jmp  .out
.no_entropy:
    lea  rdi, [rel str_dns_no_entropy]
    call serial_string
.build_bad:
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
.out:
    pop  rbx
    ret

; Build/send an ARP who-has for dns_next_hop_ip. Caller holds DNS lock.
dns_send_arp_locked:
    push rbx
    mov  edi, [rel dns_next_hop_ip]
    call arp_pending_note                ; SEC-S7a: only this next hop's reply is solicited
    lea  rbx, [rel dns_wire_frame]
    mov  dword [rbx], 0xffffffff
    mov  word [rbx + 4], 0xffff
    mov  eax, [rel dns_source_mac]
    mov  [rbx + 6], eax
    mov  ax, [rel dns_source_mac + 4]
    mov  [rbx + 10], ax
    mov  word [rbx + 12], 0x0608
    lea  rdi, [rbx + 14]
    mov  word [rdi], 0x0100
    mov  word [rdi + 2], 0x0008
    mov  byte [rdi + 4], 6
    mov  byte [rdi + 5], 4
    mov  word [rdi + 6], 0x0100
    mov  eax, [rel dns_source_mac]
    mov  [rdi + 8], eax
    mov  ax, [rel dns_source_mac + 4]
    mov  [rdi + 12], ax
    mov  eax, [rel dns_source_ip]
    mov  [rdi + 14], eax
    mov  qword [rdi + 18], 0
    mov  eax, [rel dns_next_hop_ip]
    mov  [rdi + 24], eax
    lea  rdi, [rbx + 42]
    xor  eax, eax
    mov  ecx, 18
    rep  stosb
    lea  rsi, [rel dns_wire_frame]
    mov  edx, 60
    call netdev_tx
    pop  rbx
    ret

; RDI=next-hop MAC. Build Ethernet/IPv4/UDP dns_query_port->53 around dns_query_live.
dns_send_query_locked:
    push rbx
    push r12
    mov  r12, rdi
    lea  rbx, [rel dns_wire_frame]
    mov  eax, [r12]
    mov  [rbx], eax
    mov  ax, [r12 + 4]
    mov  [rbx + 4], ax
    mov  eax, [rel dns_source_mac]
    mov  [rbx + 6], eax
    mov  ax, [rel dns_source_mac + 4]
    mov  [rbx + 10], ax
    mov  word [rbx + 12], 0x0008
    lea  rdi, [rbx + 14]
    mov  byte [rdi], 0x45
    mov  byte [rdi + 1], 0
    mov  eax, [rel dns_query_live_len]
    add  eax, 28
    mov  [rdi + 2], ah
    mov  [rdi + 3], al
    mov  dword [rdi + 4], 0
    mov  byte [rdi + 8], 64
    mov  byte [rdi + 9], 17
    mov  word [rdi + 10], 0
    mov  eax, [rel dns_source_ip]
    mov  [rdi + 12], eax
    mov  eax, [rel dns_server_ip]
    mov  [rdi + 16], eax
    lea  rdi, [rbx + 14]
    mov  esi, 20
    call net_cksum16
    mov  [rbx + 24], ah
    mov  [rbx + 25], al
    lea  rdi, [rbx + 34]
    movzx eax, word [rel dns_query_port]
    mov  [rdi], ah
    mov  [rdi + 1], al
    mov  byte [rdi + 2], 0
    mov  byte [rdi + 3], 53
    mov  eax, [rel dns_query_live_len]
    add  eax, 8
    mov  [rdi + 4], ah
    mov  [rdi + 5], al
    mov  word [rdi + 6], 0
    lea  rdi, [rbx + 42]
    lea  rsi, [rel dns_query_live]
    mov  edx, [rel dns_query_live_len]
    call memcpy
    mov  edx, [rel dns_query_live_len]
    add  edx, 42
    cmp  edx, 60
    jae  .send
    lea  rdi, [rbx + rdx]
    mov  ecx, 60
    sub  ecx, edx
    xor  eax, eax
    rep  stosb
    mov  edx, 60
.send:
    lea  rsi, [rel dns_wire_frame]
    call netdev_tx
    pop  r12
    pop  rbx
    ret

dns_mark_query_locked:
    cmp  byte [rel dns_m_query_tx], 1
    je   .done
    mov  byte [rel dns_m_query_tx], 1
    lea  rdi, [rel str_dns_m_query]
    call serial_string
    lea  rdi, [rel str_dns_txid_pre]
    call serial_string
    movzx eax, word [rel dns_txid]
    call dns_print_u32
    lea  rdi, [rel str_dns_crlf]
    call serial_string
.done:
    ret

dns_bootstrap_complete_locked:
    cmp  byte [rel dns_bootstrap_active], 1
    jne  .done
    mov  byte [rel dns_bootstrap_active], 0
    mov  byte [rel dns_bootstrap_release], 1
.done:
    ret

; Non-blocking timeout/ARP/TX FSM, called once per command poll tick.
dns_wire_tick:
    push rbx
    push r12
    call dns_wire_lock_acquire
    call dns_request_prune_locked
    call dns_request_sync_locked
    cmp  byte [rel dns_tcp_finishing], 0
    je   .tick_state
    call dns_tcp_cleanup_locked
    jmp  .out
.tick_state:
    call dns_request_dispatch_locked
    movzx ebx, byte [rel dns_wire_state]
    cmp  ebx, DNS_WS_WAIT_TCP
    je   .active
    cmp  ebx, DNS_WS_WAIT_ARP
    je   .active
    cmp  ebx, DNS_WS_WAIT_REPLY
    jne  .out
.active:
    call dns_request_time_locked
    test edx, edx
    jz   .out
    mov  r12, rax
    cmp  rax, [rel dns_deadline_ms]
    jb   .not_timeout
    call dns_tcp_cancel_locked
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    jmp  .out
.not_timeout:
    cmp  ebx, DNS_WS_WAIT_TCP
    jne  .udp
    call dns_tcp_tick_locked
    jmp  .out
.udp:
    cmp  ebx, DNS_WS_WAIT_REPLY
    je   .retransmit
    cmp  rax, [rel dns_arp_retry_ms]
    jb   .out
    mov  edi, [rel dns_next_hop_ip]
    test edi, edi
    jz   .timeout_now
    call arp_cache_lookup
    test rax, rax
    jz   .arp
    lea  rdi, [rax + E_MAC]
    call dns_send_query_locked
    test rax, rax
    jnz  .arp
    mov  byte [rel dns_wire_state], DNS_WS_WAIT_REPLY
    mov  byte [rel dns_query_attempts], 1
    mov  rax, r12
    mov  edx, DNS_LIVE_TOTAL_MS
    call dns_request_phase_deadline_locked
    mov  [rel dns_deadline_ms], rax
    lea  rax, [r12 + DNS_LIVE_RETRY_MS]
    mov  [rel dns_retry_ms], rax
    call dns_mark_query_locked
    jmp  .out
.retransmit:
    ; A lost query or reply: resend the same txid/port/question (a late reply
    ; to any attempt is the same answer), bounded by count and the deadline.
    cmp  rax, [rel dns_retry_ms]
    jb   .out
    cmp  byte [rel dns_query_attempts], DNS_LIVE_ATTEMPTS
    jae  .out
    inc  byte [rel dns_query_attempts]
    lea  rax, [r12 + DNS_LIVE_RETRY_MS]
    mov  [rel dns_retry_ms], rax
    mov  edi, [rel dns_next_hop_ip]
    call arp_cache_lookup
    test rax, rax
    jz   .out                               ; next hop aged out: this attempt is spent
    lea  rdi, [rax + E_MAC]
    call dns_send_query_locked
    jmp  .out
.arp:
    call dns_send_arp_locked
    lea  rax, [r12 + DNS_LIVE_ARP_MS]
    mov  [rel dns_arp_retry_ms], rax
    jmp  .out
.timeout_now:
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
.out:
    call dns_request_sync_locked
    call dns_wire_lock_release
    pop  r12
    pop  rbx
    ret

; All DNS stream operations use table try-locks, while DNS owns this FSM lock.
; Polling avoids connected/receive callbacks and their reuse/cancellation races.
dns_tcp_begin_locked:
    cmp  qword [rel dns_tcp_cookie_next], -1
    je   .exhausted                      ; never wrap/reuse an ownership cookie
    inc  qword [rel dns_tcp_cookie_next]
    mov  rax, [rel dns_tcp_cookie_next]
    mov  [rel dns_tcp_route + 8], rax
    mov  eax, [rel dns_next_hop_ip]
    mov  [rel dns_tcp_route], eax
    mov  eax, [rel dns_source_ip]
    mov  [rel dns_tcp_route + 4], eax
    mov  eax, [rel dns_query_live_len]
    mov  [rel dns_tcp_query], ah
    mov  [rel dns_tcp_query + 1], al
    mov  edx, eax
    lea  rdi, [rel dns_tcp_query + 2]
    lea  rsi, [rel dns_query_live]
    call memcpy
    mov  dword [rel dns_tcp_sent], 0
    mov  dword [rel dns_tcp_received], 0
    mov  dword [rel dns_tcp_expected], 0
    mov  byte [rel dns_tcp_opened], 0
    mov  byte [rel dns_tcp_finishing], 0
    mov  byte [rel dns_wire_state], DNS_WS_WAIT_TCP
    ; Preserve the original UDP reply deadline and query/entropy/retry budget.
    mov  eax, 1
    ret
.exhausted:
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    mov  eax, 1
    ret

dns_tcp_cleanup_locked:
    cmp  qword [rel dns_tcp_handle], 0
    je   .clear
    mov  r8d, 2                       ; cancellation/deadline stays silent abort
    cmp  byte [rel dns_tcp_finishing], 2
    jne  .detach
    call dns_cache_clock_locked       ; no recursive request/TCP cleanup
    mov  r8d, 2
    test edx, edx
    jz   .detach
    cmp  rax, [rel dns_deadline_ms]
    jae  .detach                      ; failed final ACK cannot pin DNS forever
    mov  r8d, 3                       ; success: final ACK before actual detach
.detach:
    mov  rdi, [rel dns_tcp_handle]
    mov  rsi, [rel dns_tcp_route + 8]
    xor  edx, edx
    xor  ecx, ecx
    call tcp_client_io_owned
    cmp  rax, -1
    je   .out                           ; retain handle/buffers until actual detach
.clear:
    mov  qword [rel dns_tcp_handle], 0
    lea  rdi, [rel dns_tcp_route]
    xor  esi, esi
    mov  edx, dns_tcp_state_end - dns_tcp_route
    call memset
.out:
    ret

dns_tcp_cancel_locked:
    cmp  byte [rel dns_wire_state], DNS_WS_WAIT_TCP
    je   .cancel
    cmp  qword [rel dns_tcp_handle], 0
    je   .out
.cancel:
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    mov  byte [rel dns_tcp_finishing], 1
    call dns_tcp_cleanup_locked
.out:
    ret

dns_tcp_tick_locked:
    push rbx
    push r12
    cmp  byte [rel dns_tcp_opened], 0
    jne  .send
    mov  edi, [rel dns_server_ip]
    mov  esi, 53
    movzx edx, word [rel dns_query_port]
    xor  ecx, ecx
    xor  r8d, r8d
    lea  r9, [rel dns_tcp_route]
    call tcp_client_open_routed
    cmp  rax, -1
    je   .out                           ; no connection attempt while lock busy
    mov  byte [rel dns_tcp_opened], 1
    test rax, rax
    jz   .fail
    mov  [rel dns_tcp_handle], rax
.send:
    mov  eax, [rel dns_tcp_sent]
    mov  ecx, [rel dns_query_live_len]
    add  ecx, 2
    sub  ecx, eax
    jz   .read
    lea  rdx, [rel dns_tcp_query]
    add  rdx, rax
    mov  rdi, [rel dns_tcp_handle]
    mov  rsi, [rel dns_tcp_route + 8]
    mov  r8d, 1
    call tcp_client_io_owned
    cmp  rax, -1
    je   .out
    test rax, rax
    js   .fail
    add  [rel dns_tcp_sent], edx
    cmp  eax, 4                         ; existing TCP_SYN_SENT
    je   .out
    cmp  eax, 2                         ; existing TCP_ESTABLISHED
    jne  .fail
.read:
    mov  eax, [rel dns_tcp_received]
    mov  ecx, DNS_TCP_MAX + 3
    sub  ecx, eax
    jbe  .fail
    lea  rdx, [rel dns_tcp_reply]
    add  rdx, rax
    mov  rdi, [rel dns_tcp_handle]
    mov  rsi, [rel dns_tcp_route + 8]
    xor  r8d, r8d
    call tcp_client_io_owned
    cmp  rax, -1
    je   .out
    test rax, rax
    js   .fail
    mov  r12d, eax
    add  [rel dns_tcp_received], edx
    mov  eax, [rel dns_tcp_received]
    test edx, edx
    jz   .incomplete
    mov  ecx, [rel dns_query_live_len]
    add  ecx, 2
    cmp  [rel dns_tcp_sent], ecx
    jne  .fail                          ; unsolicited response before query admission
    cmp  eax, 2
    jb   .incomplete
    movzx ebx, byte [rel dns_tcp_reply]
    shl  ebx, 8
    mov  bl, [rel dns_tcp_reply + 1]
    cmp  ebx, DNS_HDRLEN
    jb   .fail
    cmp  ebx, DNS_TCP_MAX
    ja   .fail
    add  ebx, 2
    mov  [rel dns_tcp_expected], ebx
    cmp  eax, ebx
    ja   .fail                          ; exactly one length-framed response
    jb   .incomplete
    call dns_request_time_locked
    test edx, edx
    jz   .fail
    cmp  rax, [rel dns_deadline_ms]
    jae  .fail
    lea  rdi, [rel dns_tcp_reply + 2]
    lea  esi, [ebx - 2]
    call dns_parse_live_locked
    cmp  eax, 1
    jne  .fail
    mov  byte [rel dns_tcp_finishing], 2
    call dns_tcp_cleanup_locked
    jmp  .out
.incomplete:
    cmp  r12d, 2
    je   .out
    cmp  r12d, 4
    je   .out
.fail:
    call dns_tcp_cancel_locked
.out:
    pop  r12
    pop  rbx
    ret

; Validate every declared RR and the exact message end before any cache commit.
; Relevant A/CNAME/SOA records are checked even after the first useful answer.
; EDX returns the RFC2308 negative lifetime for dns_chain_name (zero without
; an enclosing authority SOA). The caller initializes it to the question, then
; revalidates negative replies after resolving the bounded CNAME chain.
; ECX returns classification bits: 1=enclosing authority SOA, 2=authority IN/NS.
; A zero-lifetime SOA still distinguishes NODATA from an NS-only referral.
; The existing 60-second policy is an upper bound, never a TTL extension.
dns_validate_message_locked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  rbx, [rel dns_parse_frame]
    mov  r12d, [rel dns_parse_len]
    mov  r13, [rel dns_parse_ans_cursor]
    lea  rdi, [rbx + DNS_ANCOUNT]
    call dns_be16
    mov  r14d, eax
    lea  rdi, [rbx + 8]                  ; NSCOUNT
    call dns_be16
    mov  [rsp + 20], eax
    add  r14d, eax
    lea  rdi, [rbx + 10]                 ; ARCOUNT
    call dns_be16
    mov  [rsp + 24], eax
    add  [rsp + 20], eax                 ; authority starts at remaining NS+AR
    add  r14d, eax
    mov  dword [rsp + 28], 60
    mov  dword [rsp + 32], 0             ; no qualifying SOA yet
    mov  dword [rsp + 48], 0             ; no authority IN/NS yet
.rr:
    test r14d, r14d
    jz   .end
    mov  rdx, r13
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    lea  r8, [rel dns_owner_name]
    call dns_decode_name
    test rax, rax
    jnz  .bad
    mov  rdi, rbx
    mov  esi, r12d
    mov  rdx, r13
    call dns_skip_name
    cmp  rax, -1
    je   .bad
    mov  rdx, rax
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    mov  ecx, 10
    call safe_span_validate
    test eax, eax
    jnz  .bad
    mov  r13, rdx
    mov  rdi, r13
    call dns_be16
    mov  [rsp], eax
    lea  rdi, [r13 + 2]
    call dns_be16
    mov  [rsp + 4], eax
    mov  eax, [r13 + 4]
    bswap eax
    mov  [rsp + 16], eax                 ; RR TTL, before advancing into RDATA
    lea  rdi, [r13 + 8]
    call dns_be16
    mov  r15d, eax
    lea  rdx, [r13 + 10]
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    mov  ecx, r15d
    call safe_span_validate
    test eax, eax
    jnz  .bad
    mov  r13, rdx
    add  r13, r15
    cmp  dword [rsp + 4], DNS_QCLASS_IN
    jne  .next
    cmp  dword [rsp], DNS_QTYPE_A
    jne  .cname
    cmp  r15d, 4
    jne  .bad
    jmp  .next
.cname:
    cmp  dword [rsp], 5
    jne  .soa
    mov  [rsp + 8], rdx
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, r13
    jne  .bad                          ; inline CNAME consumes exactly RDLENGTH
    mov  rdx, [rsp + 8]
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    lea  r8, [rel dns_alias_name]
    call dns_decode_name
    test rax, rax
    jnz  .bad
    jmp  .next
.soa:
    cmp  dword [rsp], 2
    jne  .check_soa
    cmp  r14d, [rsp + 20]
    ja   .next                          ; answer NS cannot make a referral
    cmp  r14d, [rsp + 24]
    jbe  .next                          ; additional NS cannot make a referral
    mov  dword [rsp + 48], 2
    jmp  .next
.check_soa:
    cmp  dword [rsp], 6
    jne  .next
    mov  [rsp + 8], rdx
    mov  dword [rsp + 36], 2             ; MNAME and RNAME, possibly compressed
.soa_name:
    mov  rdx, [rsp + 8]
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, -1
    je   .bad
    cmp  rax, r13
    ja   .bad                           ; inline name cannot consume another RR
    mov  r15, rax
    mov  rdx, [rsp + 8]
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    lea  r8, [rel dns_alias_name]
    call dns_decode_name
    test rax, rax
    jnz  .bad                           ; validate compression target/loop too
    mov  [rsp + 8], r15
    dec  dword [rsp + 36]
    jnz  .soa_name
    lea  rax, [r15 + 20]
    cmp  rax, r13
    jne  .bad                           ; exactly five uint32 SOA fields remain
    cmp  r14d, [rsp + 20]
    ja   .next                          ; answer SOA is not negative authority
    cmp  r14d, [rsp + 24]
    jbe  .next                          ; nor is additional SOA
    ; The SOA owner must enclose the current chain target at a label boundary.
    ; Root encloses every name; a byte suffix such as ample.test does not.
    cmp  byte [rel dns_owner_name], 0
    je   .soa_lifetime
    lea  rax, [rel dns_chain_name]
    mov  [rsp + 40], rax
.soa_zone:
    mov  rdi, [rsp + 40]
    lea  rsi, [rel dns_owner_name]
    call dns_name_eq_ci
    test eax, eax
    jnz  .soa_lifetime
    mov  rax, [rsp + 40]
.soa_label:
    mov  cl, [rax]
    inc  rax
    test cl, cl
    jz   .next
    cmp  cl, '.'
    jne  .soa_label
    mov  [rsp + 40], rax
    jmp  .soa_zone
.soa_lifetime:
    mov  ecx, [r15 + 16]                 ; SOA.MINIMUM
    bswap ecx
    mov  eax, [rsp + 16]
    ; RFC2181 TTL high bit means zero; never turn it into long-lived authority.
    test eax, eax
    js   .soa_zero
    test ecx, ecx
    js   .soa_zero
    cmp  ecx, eax
    cmova ecx, eax
    jmp  .soa_minimum
.soa_zero:
    xor  ecx, ecx
.soa_minimum:
    cmp  ecx, [rsp + 28]
    jae  .soa_seen
    mov  [rsp + 28], ecx
.soa_seen:
    mov  dword [rsp + 32], 1
.next:
    dec  r14d
    jmp  .rr
.end:
    lea  rax, [rbx + r12]
    cmp  r13, rax
    jne  .bad
    xor  edx, edx
    cmp  dword [rsp + 32], 0
    je   .valid
    mov  edx, [rsp + 28]
.valid:
    mov  ecx, [rsp + 32]
    or   ecx, [rsp + 48]
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Find A or CNAME whose owner equals RDI target. Uses parser globals set by
; dns_parse_live_locked. Returns EAX=1 A, 2 CNAME, 0 absent, -1 malformed.
dns_find_target_rr_locked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48                           ; staged RR fields + first A/set lifetime
    mov  dword [rsp + 32], 0                ; no matching A yet
    mov  dword [rsp + 40], 0xffffffff       ; normalized matching A TTL minimum
    mov  r15, rdi
    mov  rbx, [rel dns_parse_frame]
    mov  r12d, [rel dns_parse_len]
    mov  r13, [rel dns_parse_ans_cursor]
    mov  r14d, [rel dns_parse_ancount]
.rr:
    test r14d, r14d
    jz   .none
    mov  rdx, r13
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    lea  r8, [rel dns_owner_name]
    call dns_decode_name
    test rax, rax
    jnz  .bad
    mov  rdx, r13
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, -1
    je   .bad
    mov  r13, rax
    mov  rdx, r13
    sub  rdx, rbx
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, 10
    call safe_span_validate
    test eax, eax
    jnz  .bad                               ; fixed RR header must be wholly present
    mov  r13, rdx
    mov  rdi, r13
    call dns_be16
    mov  [rsp + 0], eax                     ; stage type
    lea  rdi, [r13 + 2]
    call dns_be16
    mov  [rsp + 4], eax                     ; stage class
    movzx eax, byte [r13 + 4]
    shl  eax, 24
    movzx ecx, byte [r13 + 5]
    shl  ecx, 16
    or   eax, ecx
    movzx ecx, byte [r13 + 6]
    shl  ecx, 8
    or   eax, ecx
    movzx ecx, byte [r13 + 7]
    or   eax, ecx
    ; RFC2181: a wire TTL with its high bit set is zero. Normalize each
    ; A/CNAME before taking the chain minimum, so an ordinary shorter TTL
    ; cannot hide an alias or answer that permits no reusable authority.
    xor  ecx, ecx
    test eax, eax
    cmovs eax, ecx
    mov  [rsp + 8], eax                     ; stage TTL
    lea  rdi, [r13 + 8]
    call dns_be16
    mov  [rsp + 12], eax                    ; declared RDLENGTH read once
    mov  rdx, r13
    sub  rdx, rbx
    add  rdx, 10                            ; bounded: DNS frame <= 65535
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, eax
    call safe_span_validate
    test eax, eax
    jnz  .bad                               ; validate RDATA before retaining fields
    mov  [rsp + 16], rdx                    ; validated RDATA pointer
    lea  rdi, [rel dns_owner_name]
    mov  rsi, r15
    call dns_name_eq_ci
    test eax, eax
    jz   .next
    cmp  dword [rsp + 4], DNS_QCLASS_IN
    jne  .next
    cmp  dword [rsp + 0], DNS_QTYPE_A
    je   .a
    cmp  dword [rsp + 0], 5               ; CNAME
    je   .cname
.next:
    mov  r13, [rsp + 16]
    mov  eax, [rsp + 12]
    add  r13, rax
    dec  r14d
    jmp  .rr
.a:
    cmp  dword [rsp + 12], 4
    jne  .next
    cmp  dword [rsp + 32], 0
    jne  .a_ttl
    mov  rax, [rsp + 16]
    mov  eax, [rax]
    mov  [rsp + 36], eax                    ; retain the first address choice
    mov  dword [rsp + 32], 1
.a_ttl:
    ; RFC2181 section5.2: a configured resolver's A RRset cannot outlive
    ; its lowest TTL. Later records may shorten even a first-record hit.
    mov  eax, [rsp + 8]
    cmp  eax, [rsp + 40]
    jae  .next
    mov  [rsp + 40], eax
    jmp  .next
.cname:
    cmp  dword [rsp + 32], 0
    jne  .next                             ; preserve an already selected A
    mov  rdx, [rsp + 16]
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, -1
    je   .bad
    mov  rcx, [rsp + 16]
    mov  edx, [rsp + 12]
    add  rcx, rdx
    cmp  rax, rcx
    ja   .bad                            ; inline name may not cross RDLENGTH
    mov  rdx, [rsp + 16]
    sub  rdx, rbx
    mov  rdi, rbx
    mov  esi, r12d
    lea  r8, [rel dns_alias_name]
    call dns_decode_name
    test rax, rax
    jnz  .bad
    mov  eax, [rsp + 8]
    mov  [rel dns_rr_ttl], eax              ; commit only after alias decode succeeds
    mov  eax, 2
    jmp  .out
.none:
    xor  eax, eax
    cmp  dword [rsp + 32], 0
    je   .out
    mov  eax, [rsp + 36]
    mov  [rel dns_parse_ip], eax
    mov  eax, [rsp + 40]
    mov  [rel dns_rr_ttl], eax               ; publish the complete matching set
    mov  eax, 1
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; DNS payload parser. Caller holds lock and has authenticated the UDP tuple.
dns_parse_live_locked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    test rbx, rbx
    jz   .reject
    cmp  r12d, DNS_HDRLEN
    jb   .reject
    cmp  r12d, 65535
    ja   .reject
    mov  rdi, rbx
    mov  rsi, r12
    call safe_checked_add
    test edx, edx
    jnz  .reject                            ; validate frame end before any field read
    mov  rdi, rbx
    call dns_be16
    cmp  ax, [rel dns_txid]
    jne  .reject
    test byte [rbx + DNS_FLAGS], 0x80
    jz   .reject
    test byte [rbx + DNS_FLAGS], 0x78        ; only standard-query opcode
    jnz  .reject
    movzx eax, byte [rbx + DNS_FLAGS + 1]
    and  eax, 0x0f
    mov  r15d, eax                            ; stage until the echoed question is valid
    cmp  word [rbx + DNS_QDCOUNT], 0x0100
    jne  .reject
    mov  edx, DNS_HDRLEN
    mov  rdi, rbx
    mov  esi, r12d
    lea  r8, [rel dns_owner_name]
    call dns_decode_name
    test rax, rax
    jnz  .reject
    lea  rdi, [rel dns_owner_name]
    lea  rsi, [rel dns_pending_name]
    call dns_name_eq_ci
    test eax, eax
    jz   .reject
    lea  rdx, [rbx + DNS_HDRLEN]
    mov  rdi, rbx
    mov  esi, r12d
    call dns_skip_name
    cmp  rax, -1
    je   .reject
    mov  r13, rax
    mov  rdx, r13
    sub  rdx, rbx
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, 4
    call safe_span_validate
    test eax, eax
    jnz  .reject                            ; QTYPE/QCLASS must both be present
    mov  r13, rdx
    mov  rdi, r13
    call dns_be16
    cmp  eax, DNS_QTYPE_A
    jne  .reject
    lea  rdi, [r13 + 2]
    call dns_be16
    cmp  eax, DNS_QCLASS_IN
    jne  .reject
    test byte [rbx + DNS_FLAGS], 0x02
    jz   .complete_message
    ; A TC indication is useful only after the full echoed question matches.
    ; UDP tuple admission is done by ingest; TCP must never recurse fallback.
    cmp  byte [rel dns_wire_state], DNS_WS_WAIT_REPLY
    jne  .reject
    mov  eax, 2
    jmp  .out
.complete_message:
    ; Only now publish parser scratch consumed by the RR walker.  A malformed
    ; question cannot retain an attacker-selected frame, length or RCODE.
    mov  [rel dns_parse_frame], rbx
    mov  [rel dns_parse_len], r12d
    mov  [rel dns_parse_rcode], r15d
    add  r13, 4                            ; validated by safe_span_validate above
    mov  [rel dns_parse_ans_cursor], r13
    lea  rdi, [rel dns_chain_name]
    lea  rsi, [rel dns_pending_name]
    call dns_copy_cstr
    call dns_validate_message_locked
    test eax, eax
    jnz  .reject
    mov  r14d, edx                       ; validated negative TTL survives markers
    mov  eax, [rel dns_parse_rcode]
    cmp  eax, 3
    je   .nxdomain
    test eax, eax
    jnz  .failure
    lea  rdi, [rbx + DNS_ANCOUNT]
    call dns_be16
    mov  [rel dns_parse_ancount], eax
    lea  rdi, [rel dns_chain_name]
    lea  rsi, [rel dns_pending_name]
    call dns_copy_cstr
    mov  dword [rel dns_chain_ttl], 0xffffffff
    mov  r14d, 8
.chain:
    lea  rdi, [rel dns_chain_name]
    call dns_find_target_rr_locked
    cmp  eax, 1
    je   .answer
    test eax, eax
    jz   .nodata
    cmp  eax, 2
    jne  .reject
    mov  eax, [rel dns_rr_ttl]
    cmp  eax, [rel dns_chain_ttl]
    jae  .copy_alias
    mov  [rel dns_chain_ttl], eax
.copy_alias:
    lea  rdi, [rel dns_chain_name]
    lea  rsi, [rel dns_alias_name]
    call dns_copy_cstr
    dec  r14d
    jnz  .chain
    jmp  .reject
.answer:
    mov  ecx, [rel dns_rr_ttl]
    cmp  ecx, [rel dns_chain_ttl]
    jbe  .ttl_ready
    mov  ecx, [rel dns_chain_ttl]
.ttl_ready:
    cmp  ecx, 0xffffffff
    jne  .store_a
    mov  ecx, [rel dns_rr_ttl]
.store_a:
    lea  rdi, [rel dns_pending_name]
    mov  esi, DNS_LOOKUP_A
    mov  edx, [rel dns_parse_ip]
    call dns_cache_store_locked
    call .mark_response                    ; fully validated A/CNAME chain
    mov  byte [rel dns_wire_state], DNS_WS_DONE
    cmp  byte [rel dns_m_answer_a], 1
    je   .answer_marked
    mov  byte [rel dns_m_answer_a], 1
    lea  rdi, [rel str_dns_m_answer]
    call serial_string
.answer_marked:
    call dns_bootstrap_complete_locked
    mov  eax, 1
    jmp  .out
.nxdomain:
    ; This cache records the result of the original A lookup. An NXDOMAIN
    ; reached through CNAMEs cannot outlive any alias used to reach it. Walk
    ; only matching answer owners, with the same bounded depth as positive
    ; resolution; unrelated aliases do not limit this query's receipt.
    lea  rdi, [rbx + DNS_ANCOUNT]
    call dns_be16
    mov  [rel dns_parse_ancount], eax
    lea  rdi, [rel dns_chain_name]
    lea  rsi, [rel dns_pending_name]
    call dns_copy_cstr
    mov  r14d, 60                        ; independent alias/policy cap, not original-zone SOA
    mov  r15d, 8
.negative_chain:
    lea  rdi, [rel dns_chain_name]
    call dns_find_target_rr_locked
    test eax, eax
    jz   .negative_ready
    cmp  eax, 2
    jne  .reject                           ; an A contradicts NXDOMAIN
    mov  eax, [rel dns_rr_ttl]              ; normalized zero/high-bit TTL
    cmp  eax, r14d
    cmovb r14d, eax
    lea  rdi, [rel dns_chain_name]
    lea  rsi, [rel dns_alias_name]
    call dns_copy_cstr
    dec  r15d
    jnz  .negative_chain
    jmp  .reject                           ; cyclic or overlong alias chain
.negative_ready:
    ; RFC2308 QNAME is the final CNAME target. The first full validation made
    ; every RR safe to walk; now derive authority for that target, never for
    ; the original alias or an intermediate zone. This bounded second pass
    ; remains before any response marker, cache or request publication.
    call dns_validate_message_locked
    test eax, eax
    jnz  .reject
    cmp  edx, r14d
    cmovb r14d, edx
    call .mark_response                    ; complete, noncontradictory chain
    lea  rdi, [rel dns_pending_name]
    mov  esi, DNS_LOOKUP_NX
    xor  edx, edx
    mov  ecx, r14d
    call dns_cache_store_locked
    mov  byte [rel dns_wire_state], DNS_WS_NX
    jmp  .negative_complete
.nodata:
    ; NOERROR with no terminal A after the bounded alias walk (RFC2308 2.2).
    ; Revalidate the final target's SOA. An authority NS without an enclosing
    ; SOA is a referral, not a terminal answer. Missing SOA supplies no TTL.
    mov  r14d, 60
    cmp  r14d, [rel dns_chain_ttl]
    cmova r14d, [rel dns_chain_ttl]
    call dns_validate_message_locked
    test eax, eax
    jnz  .reject
    test ecx, 1
    jnz  .nodata_ready
    test ecx, 2
    jnz  .reject
.nodata_ready:
    cmp  edx, r14d
    cmovb r14d, edx
    call .mark_response
    lea  rdi, [rel dns_pending_name]
    mov  esi, DNS_LOOKUP_NODATA
    xor  edx, edx
    mov  ecx, r14d
    call dns_cache_store_locked
    mov  byte [rel dns_wire_state], DNS_WS_NODATA
.negative_complete:
    call dns_bootstrap_complete_locked
    mov  eax, 1
    jmp  .out
.failure:
    call .mark_response                    ; valid echoed question + terminal RCODE
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    mov  eax, 1
    jmp  .out
.reject:
    ; Failure-atomic parser state: no malformed/truncated reply can leave a
    ; partial frame, RR, decoded-name or derived-address snapshot behind.  The
    ; pending query and cache are intentionally preserved for a later reply.
    mov  qword [rel dns_parse_frame], 0
    mov  qword [rel dns_parse_ans_cursor], 0
    mov  qword [rel dns_rr_rdata], 0
    mov  dword [rel dns_parse_len], 0
    mov  dword [rel dns_parse_ancount], 0
    mov  dword [rel dns_parse_ip], 0
    mov  dword [rel dns_parse_rcode], 0
    mov  dword [rel dns_rr_type], 0
    mov  dword [rel dns_rr_class], 0
    mov  dword [rel dns_rr_ttl], 0
    mov  dword [rel dns_rr_rdlen], 0
    mov  dword [rel dns_chain_ttl], 0
    mov  byte [rel dns_owner_name], 0
    mov  byte [rel dns_chain_name], 0
    mov  byte [rel dns_alias_name], 0
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.mark_response:
    cmp  byte [rel dns_m_response_rx], 1
    je   .mark_response_done
    mov  byte [rel dns_m_response_rx], 1
    lea  rdi, [rel str_dns_m_response]
    call serial_string
.mark_response_done:
    ret

; RDI=full Ethernet frame, RSI=len -> EAX=1 consumed DNS tuple, 0 otherwise.
dns_wire_ingest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    xor  r14d, r14d
    call dns_wire_lock_acquire
    cmp  byte [rel dns_wire_state], DNS_WS_WAIT_REPLY
    jne  .out
    call dns_request_time_locked
    test edx, edx
    jz   .out
    cmp  rax, [rel dns_deadline_ms]
    jb   .timely
    mov  byte [rel dns_wire_state], DNS_WS_TIMEOUT
    call dns_bootstrap_complete_locked
    jmp  .out
.timely:
    mov  rdi, rbx
    mov  rsi, r12
    xor  edx, edx
    mov  ecx, 14 + 20
    call safe_span_validate
    test eax, eax
    jnz  .out
    cmp  word [rbx + 12], 0x0008
    jne  .out
    lea  r13, [rbx + 14]
    movzx eax, byte [r13]
    mov  ecx, eax
    shr  ecx, 4
    cmp  ecx, 4
    jne  .out
    and  eax, 0x0f
    shl  eax, 2
    cmp  eax, 20
    jb   .out
    mov  ecx, eax
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 14
    lea  ecx, [ecx + 8]
    call safe_span_validate
    test eax, eax
    jnz  .out
    movzx r15d, byte [r13 + 2]
    shl  r15d, 8
    mov  r15b, [r13 + 3]                     ; declared IPv4 total length, read once
    movzx ecx, byte [r13]
    and  ecx, 0x0f
    shl  ecx, 2
    lea  eax, [ecx + 8]
    cmp  r15d, eax
    jb   .out
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 14
    mov  ecx, r15d
    call safe_span_validate
    test eax, eax
    jnz  .out
    movzx ecx, byte [r13]
    and  ecx, 0x0f
    shl  ecx, 2
    cmp  byte [r13 + 9], 17
    jne  .out
    mov  al, [r13 + 6]
    and  al, 0xbf                             ; DNS replies must be unfragmented
    jnz  .out
    cmp  byte [r13 + 7], 0
    jne  .out
    mov  eax, [r13 + 12]
    cmp  eax, [rel dns_server_ip]
    jne  .out
    mov  eax, [r13 + 16]
    cmp  eax, [rel dns_source_ip]
    jne  .out
    lea  rdx, [r13 + rcx]
    cmp  byte [rdx], 0
    jne  .out
    cmp  byte [rdx + 1], 53
    jne  .out
    movzx eax, byte [rdx + 2]
    shl  eax, 8
    mov  al, [rdx + 3]
    cmp  ax, [rel dns_query_port]
    jne  .out
    movzx eax, byte [rdx + 4]
    shl  eax, 8
    mov  al, [rdx + 5]
    cmp  eax, 8
    jb   .out
    mov  esi, r15d
    sub  esi, ecx                             ; declared IPv4 payload bytes
    cmp  eax, esi
    ja   .out                                 ; UDP length exceeds enclosing packet
    sub  eax, 8
    mov  r10d, eax                            ; DNS payload length survives validator
    sub  rdx, rbx                             ; UDP-header offset in the frame
    add  rdx, 8                               ; bounded small offset after header proof
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, r10d
    call safe_span_validate
    test eax, eax
    jnz  .out
    mov  rdi, rdx                             ; validated DNS payload
    mov  esi, r10d
    call dns_parse_live_locked
    cmp  eax, 2
    jne  .parsed
    call dns_tcp_begin_locked
.parsed:
    mov  r14d, eax
.out:
    call dns_request_sync_locked
    call dns_wire_lock_release
    mov  eax, r14d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- net/dns data (canned vectors + parsed state + scratch; in-image) ----------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_dns 0
align 8
dns_wire_lock:         dq 0
dns_deadline_ms:       dq 0
dns_arp_retry_ms:      dq 0
dns_retry_ms:          dq 0                 ; next retransmit (WAIT_REPLY)
dns_parse_frame:       dq 0
dns_parse_ans_cursor:  dq 0
dns_rr_rdata:          dq 0
dns_server_ip:         dd 0
dns_source_ip:         dd 0
dns_gateway_ip:        dd 0
dns_mask_ip:           dd 0
dns_next_hop_ip:       dd 0
dns_query_live_len:    dd 0
dns_parse_len:         dd 0
dns_parse_ancount:     dd 0
dns_parse_ip:          dd 0
dns_parse_rcode:       dd 0
dns_rr_type:           dd 0
dns_rr_class:          dd 0
dns_rr_ttl:            dd 0
dns_rr_rdlen:          dd 0
dns_chain_ttl:         dd 0
dns_txid:              dw 0
dns_query_port:        dw 0                 ; this query's random UDP source port
dns_query_entropy:     dd 0                 ; CSPRNG draw, wiped after use
dns_query_attempts:    db 0                 ; transmissions of the outstanding query
dns_source_mac:        times 6 db 0
dns_wire_state:        db DNS_WS_IDLE
dns_request_active:    db 0xff           ; retained while an old TCP detach is pending
; dns_bootstrap_active..dns_cache_live moved to WDATA_dns_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_dns
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_dns_bss1 0
resb 4                 ; retained zero-fill padding before the bootstrap flags
dns_bootstrap_active:  resb 1
dns_bootstrap_release: resb 1
dns_cache_victim:      resb 1
dns_m_query_tx:        resb 1
dns_m_response_rx:     resb 1
dns_m_answer_a:        resb 1
dns_pending_name:      resb 255
dns_name_tmp:          resb 255
dns_owner_name:        resb 256
dns_chain_name:        resb 256
dns_alias_name:        resb 256
dns_query_live:        resb 288            ; 12 + max 255-byte QNAME + QTYPE/QCLASS
dns_wire_frame:        resb 384            ; max outbound DNS query frame is 313 bytes
alignb 8
dns_cache_live:        resb DNS_LIVE_CACHE_N * DNS_LIVE_CACHE_SZ
%endmacro
WDATA_BSS_DEFER WDATA_dns_bss1
; RCQ-40 J3: when the last lookup started (ms since boot, 0 = none), under dns_wire_lock.
%macro WDATA_dns_netcheck 0
alignb 8
dns_query_started_ms:  resq 1
%endmacro
WDATA_BSS_DEFER WDATA_dns_netcheck

%macro WDATA_dns_tcp 0
alignb 8
dns_tcp_handle:       resq 1
dns_tcp_cookie_next:  resq 1           ; never reset/reused during this boot
dns_tcp_route:        resb 16          ; next hop, source IPv4, unique cookie
dns_tcp_sent:         resd 1
dns_tcp_received:     resd 1
dns_tcp_expected:     resd 1
dns_tcp_finishing:    resb 1
dns_tcp_opened:       resb 1
dns_tcp_query:        resb 290         ; 2-byte length + unchanged <=288-byte query
dns_tcp_reply:        resb DNS_TCP_MAX + 3 ; prefix + payload + trailing-byte sentinel
dns_tcp_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_dns_tcp

%macro WDATA_dns_requests 0
alignb 8
dns_request_generation: resq 1          ; never reset/reused within this boot; exhaustion refuses
dns_requests:           resb DNS_REQUEST_N * DNS_REQUEST_SZ
dns_request_order:      resb DNS_REQUEST_N
dns_request_count:      resb 1
dns_request_victim:     resb 1
%endmacro
WDATA_BSS_DEFER WDATA_dns_requests

str_dns_bootstrap_name: db "one.one.one.one", 0
str_dns_no_entropy: db "[PAOS64] P2 DNS: no random query identity (CSPRNG refused); lookup failed closed [dns.query.no_entropy]", 13,10,0
str_dns_m_query:    db "[PAOS64] P2 DNS: A query sent [dns.query.tx]", 13,10,0
str_dns_txid_pre:   db "[PAOS64][INF][net] dns.txid=", 0
str_dns_m_response: db "[PAOS64] P2 DNS: response txid-matched [dns.response.rx]", 13,10,0
str_dns_m_answer:   db "[PAOS64] P2 DNS: A record extracted + cached [dns.answer.a]", 13,10,0

; Canned DNS RESPONSE for "example.com": header id=0x1337, flags=0x8180 (response,
;   RD,RA), QDCOUNT=1, ANCOUNT=1; question QNAME "example.com"(13B)+A+IN; answer
;   NAME=0xC0 0x0C (pointer to the question QNAME at offset 12), TYPE=A, CLASS=IN,
;   TTL=300, RDLENGTH=4, RDATA=93.184.216.34.
dns_response:
    db 0x13, 0x37                              ; id (offset 0)
    db 0x81, 0x80                              ; flags: response, RD, RA
    db 0x00, 0x01                              ; QDCOUNT = 1
    db 0x00, 0x01                              ; ANCOUNT = 1
    db 0x00, 0x00                              ; NSCOUNT = 0
    db 0x00, 0x00                              ; ARCOUNT = 0
dns_resp_q:                                    ; question QNAME (offset 12)
    db 7, 'example', 3, 'com', 0               ; 13 wire bytes
    db 0x00, 0x01                              ; QTYPE = A
    db 0x00, 0x01                              ; QCLASS = IN
dns_resp_ans:                                  ; answer section
    db 0xC0, 0x0C                              ; NAME = pointer -> offset 12
    db 0x00, 0x01                              ; TYPE = A
    db 0x00, 0x01                              ; CLASS = IN
    db 0x00, 0x00, 0x01, 0x2c                  ; TTL = 300
    db 0x00, 0x04                              ; RDLENGTH = 4
    db 93, 184, 216, 34                        ; RDATA = 93.184.216.34
dns_response_end:
DNS_RESPONSE_LEN equ dns_response_end - dns_response
DNS_ANS_NAME_OFF equ dns_resp_ans - dns_response   ; offset of the answer name

; NEGATIVE: a self-referential compression pointer (offset 0 -> offset 0).
dns_ptrloop:
    db 0xC0, 0x00
dns_ptrloop_end:
DNS_PTRLOOP_LEN equ dns_ptrloop_end - dns_ptrloop

; NEGATIVE: a single 70-char label (> 63) — the encoder must reject it.
dns_badname:
    times 70 db 'a'
    db 0

; TOURNAMENT 1421 encode_qname over-length vector: 4 labels of 63 'a' separated by
;   dots = 4*(1+63) = 256 wire bytes pre-terminator (> 255). The durable encoder
;   must reject it (-1) WITHOUT writing past the 255-byte cap into the dst buffer.
dns_kat_over:
    times 63 db 'a'
    db '.'
    times 63 db 'a'
    db '.'
    times 63 db 'a'
    db '.'
    times 63 db 'a'
    db 0

; --- TOURNAMENT 1308 dns_decode_name KAT vectors ------------------------------
dns_kat_root:  db 0                            ; the DNS root: empty name
dns_kat_resv:  db 0x40                         ; reserved length bits (illegal)
dns_kat_short: db 5, 'ab'                      ; declares 5 label bytes, has 2
dns_kat_cut:   db 0xC0                         ; pointer high byte only, low cut off
dns_kat_chain:                                 ; ptr(0)->ptr(2)->label(4) = "foo"
    db 0xC0, 0x02
    db 0xC0, 0x04
    db 3, 'foo', 0
dns_kat_chain_end:
DNS_KAT_CHAIN_LEN equ dns_kat_chain_end - dns_kat_chain
dns_kat_amp:                                   ; 63-byte label + pointer back to 0:
    db 63                                      ;   output grows 64B/hop — only the
    times 63 db 'a'                            ;   255-byte name cap stops it before
    db 0xC0, 0x00                              ;   the jump guard admits ~2KB
dns_kat_amp_end:
DNS_KAT_AMP_LEN equ dns_kat_amp_end - dns_kat_amp
DNS_KAT_CANARY_OFF equ 280                     ; behind the cap, inside dns_kat_dst

; --- TOURNAMENT 1310 dns_parse_response hostile-shape table: dw (offset, poke,
;   restore, len) per row — poke ONE canned-response byte (poke==restore for
;   pure truncations), parse at len, restore, expect -1. COMPILE-TIME constants
;   only (offsets, never symbols — a dq symbol table would bake RVAs).
dns_pr_neg_tbl:
    dw 0, 0x13, 0x13, DNS_HDRLEN - 1,          2, 0x01, 0x81, DNS_RESPONSE_LEN
    dw 3, 0x83, 0x80, DNS_RESPONSE_LEN,        5, 0x00, 0x01, DNS_RESPONSE_LEN
    dw 7, 0x00, 0x01, DNS_RESPONSE_LEN,        12, 0x47, 0x07, DNS_RESPONSE_LEN
    dw 0, 0x13, 0x13, DNS_ANS_NAME_OFF - 2,    0, 0x13, 0x13, DNS_ANS_NAME_OFF + 1
    dw 0, 0x13, 0x13, DNS_RESPONSE_LEN - 1
    dw DNS_ANS_NAME_OFF + 3, 0x02, 0x01, DNS_RESPONSE_LEN
    dw DNS_ANS_NAME_OFF + 11, 0x05, 0x04, DNS_RESPONSE_LEN
DNS_PR_NEG_N equ 11

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_dns_0 0
str_dns_example: db "example.com", 0

; parsed / built state
dns_a_ip:      dd 0                            ; extracted A-record IPv4 (4 octets)
dns_query_len: dd 0
dns_qname_len: dd 0
dns_query_buf: times 64 db 0                   ; built query (header+qname+qt+qc)
dns_decoded_name: times 264 db 0               ; decoded pointer-name (<=255+nul)
dns_scratch:   times 264 db 0                  ; negative-gate scratch
dns_ipbuf:     times 20 db 0                   ; "255.255.255.255\0"
dns_numbuf:    times 16 db 0                   ; decimal scratch
dns_kat_dst:   times 300 db 0                  ; KAT decode target (cap=255 + canary)
dns_eq_dst:    times 272 db 0                  ; tourn 1421 encode_qname KAT target (256 max + canary)
%endmacro
WDATA_DEFER WDATA_net_dns_0
DNS_EQ_CANARY_OFF equ 260                       ; overrun sentinel, past the 255-byte cap
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_dns_1 0
str_dns_eq_empty:  db 0                         ; empty name ""
str_dns_eq_trail:  db "a.", 0                   ; trailing-dot malformed vector
str_dns_eq_dota:   db ".a", 0                   ; leading-dot malformed vector
dns_eq_lab64:      times 64 db 'a'              ; 64-byte label = first illegal length
                   db 0
dns_wr_dst:    times 16 db 0                   ; tourn 1417 wr_u8 KAT target (<=3 digits + canary)
%endmacro
WDATA_DEFER WDATA_net_dns_1
DNS_WR_CANARY_OFF equ 8                         ; overrun canary, past the 3-digit max

str_dns_pass:     db "[PAOS64] P4 net dns: A-record query build + response parse selftest PASS [dns.resolver.logic]", 13,10,0
str_dns_kat_pre:  db "[PAOS64][INF][net] dns.kat qname_name=", 0
str_dns_kat_qlen: db "  qname_len=", 0
str_dns_kat_aip:  db "  a_ip=", 0
str_dns_crlf:     db 13,10,0

str_dns_kat_com:  db "com", 0
str_dns_kat_foo:  db "foo", 0
str_dns_dn_kat1:  db "[PAOS64][INF][net] tourn.dns_decode_name kat name=", 0
str_dns_dn_kat2:  db "  pos=5 neg=6 cap=255", 13,10,0
str_dns_dn_pass:  db "[PAOS64] P4 net dns: decode_name tournament KAT PASS [tourn.dns_decode_name.kat] [tourn.dns_decode_name.guard]", 13,10,0
str_dns_dn_perf1: db "[PAOS64][INF][net] tourn.dns_decode_name perf decode64_cycles=", 0
str_dns_dn_perf2: db " [tourn.dns_decode_name.perf]", 13,10,0
str_dns_dn_fail:  db "[PAOS64] P4 net dns: decode_name tournament KAT FAIL [tourn.dns_decode_name.kat.fail] step=", 0

str_dns_pr_kat1:  db "[PAOS64][INF][net] tourn.dns_parse_response kat a_ip=", 0
str_dns_pr_pass:  db "  neg=11 hdr=qr+rcode+qdcount guard=aip_untouched", 13,10,"[PAOS64] P4 net dns: parse_response tournament KAT PASS [tourn.dns_parse_response.kat] [tourn.dns_parse_response.guard]", 13,10,0
str_dns_pr_perf1: db "[PAOS64][INF][net] tourn.dns_parse_response perf parse64_cycles=", 0
str_dns_pr_perf2: db " [tourn.dns_parse_response.perf]", 13,10,0
str_dns_pr_fail:  db "[PAOS64] P4 net dns: parse_response tournament KAT FAIL [tourn.dns_parse_response.kat.fail] step=", 0

; --- TOURNAMENT 1428 dns_streq fixed vectors + fast-path measurement ----------
; Relocation-safe signed offsets; zero is reserved as the NULL sentinel. Row =
; a_off dd, b_off dd, exact expected Boolean db. The final eight rows are the
; fixed fault battery shared by every tournament variant.
dns_st_vec_base:    db 0
str_dns_st_same_a:  db "paos", 0
str_dns_st_same_b:  db "paos", 0
str_dns_st_diff:    db "Paos", 0
str_dns_st_prefix:  db "paosx", 0
str_dns_st_empty:   db 0
str_dns_st_hi_a:    db 0x80, 0xFF, 0
str_dns_st_hi_b:    db 0x80, 0xFF, 0
str_dns_st_hi_diff: db 0x80, 0xFE, 0
str_dns_st_nul_a:   db 'x', 0, 0x11
str_dns_st_nul_b:   db 'x', 0, 0x22
dns_st_vec_tbl:
    dd str_dns_st_same_a - dns_st_vec_base, str_dns_st_same_b - dns_st_vec_base
    db 1
    dd str_dns_st_same_a - dns_st_vec_base, str_dns_st_diff - dns_st_vec_base
    db 0
    dd str_dns_st_same_a - dns_st_vec_base, str_dns_st_prefix - dns_st_vec_base
    db 0
    dd str_dns_st_empty - dns_st_vec_base, str_dns_st_empty - dns_st_vec_base
    db 1
    dd str_dns_st_hi_a - dns_st_vec_base, str_dns_st_hi_b - dns_st_vec_base
    db 1
    dd str_dns_st_hi_a - dns_st_vec_base, str_dns_st_hi_diff - dns_st_vec_base
    db 0
    dd str_dns_st_nul_a - dns_st_vec_base, str_dns_st_nul_b - dns_st_vec_base
    db 1
    dd str_dns_st_empty - dns_st_vec_base, str_dns_st_same_a - dns_st_vec_base
    db 0
    dd dns_scratch - dns_st_vec_base, dns_kat_dst - dns_st_vec_base
    db 1
    dd dns_scratch - dns_st_vec_base, dns_decoded_name - dns_st_vec_base
    db 0
    dd 0, str_dns_st_same_a - dns_st_vec_base
    db 0
    dd str_dns_st_same_a - dns_st_vec_base, 0
    db 0
dns_st_vec_tbl_end:
DNS_ST_VEC_SIZE equ 9
DNS_ST_VEC_N equ (dns_st_vec_tbl_end - dns_st_vec_tbl) / DNS_ST_VEC_SIZE
%if DNS_ST_VEC_N != 12
    %error "dns_streq tournament battery must remain 4 KAT + 8 hostile vectors"
%endif

str_dns_st_pass:
    db "[PAOS64] P4 net dns: streq tournament KAT PASS pos=4 [tourn.dns_streq.kat]",13,10,0
str_dns_st_fault:
    db "[PAOS64][INF][net] tourn.dns_streq fault [tourn.dns_streq.fault contained=8 total=8]",13,10,0
str_dns_st_perf1:
    db "[PAOS64][INF][net] tourn.dns_streq perf impl=qword_page_safe calls=512 cycles=",0
str_dns_st_perf2:
    db " [tourn.dns_streq.perf]",13,10,0
str_dns_st_fail:
    db "[PAOS64] P4 net dns: streq tournament KAT FAIL [tourn.dns_streq.kat.fail] step=",0

; --- TOURNAMENT 1417 dns_wr_u8 KAT vectors + markers --------------------------
str_dns_wr_0:     db "0", 0
str_dns_wr_7:     db "7", 0
str_dns_wr_10:    db "10", 0
str_dns_wr_42:    db "42", 0
str_dns_wr_99:    db "99", 0
str_dns_wr_100:   db "100", 0
str_dns_wr_205:   db "205", 0
str_dns_wr_250:   db "250", 0
str_dns_wr_255:   db "255", 0
str_dns_wr_102:   db "102", 0
str_dns_wr_kat1:  db "[PAOS64][INF][net] tourn.dns_wr_u8 kat max255=", 0
str_dns_wr_pass:  db "  pos=9 bound=u8 null=contained guard=canary", 13,10,"[PAOS64] P4 net dns: wr_u8 tournament KAT PASS [tourn.dns_wr_u8.kat] [tourn.dns_wr_u8.guard]", 13,10,0
str_dns_wr_perf1: db "[PAOS64][INF][net] tourn.dns_wr_u8 perf fmt64_cycles=", 0
str_dns_wr_perf2: db " [tourn.dns_wr_u8.perf]", 13,10,0
str_dns_wr_fail:  db "[PAOS64] P4 net dns: wr_u8 tournament KAT FAIL [tourn.dns_wr_u8.kat.fail] step=", 0

; --- TOURNAMENT 1425 dns_skip_name KAT + fault-battery markers -----------------
str_dns_sk_kat1:  db "[PAOS64][INF][net] tourn.dns_skip_name kat pos=3 neg=6", 13,10,0
str_dns_sk_pass:  db "[PAOS64] P4 net dns: skip_name tournament KAT PASS [tourn.dns_skip_name.kat] [tourn.dns_skip_name.guard]", 13,10,0
str_dns_sk_flt1:  db "[PAOS64][INF][net] tourn.dns_skip_name fault [tourn.dns_skip_name.fault contained=", 0
str_dns_sk_flt2:  db " total=6]", 13,10,0
str_dns_sk_fail:  db "[PAOS64] P4 net dns: skip_name tournament KAT FAIL [tourn.dns_skip_name.kat.fail] step=", 0

; --- TOURNAMENT 1421 dns_encode_qname KAT + fault-battery markers --------------
str_dns_eq_kat1:  db "[PAOS64][INF][net] tourn.dns_encode_qname kat pos=2 neg=8 example.com->13 com->5", 13,10,0
str_dns_eq_pass:  db "[PAOS64] P4 net dns: encode_qname tournament KAT PASS [tourn.dns_encode_qname.kat] [tourn.dns_encode_qname.guard]", 13,10,0
str_dns_eq_flt1:  db "[PAOS64][INF][net] tourn.dns_encode_qname fault [tourn.dns_encode_qname.fault contained=", 0
str_dns_eq_flt2:  db " total=8]", 13,10,0
str_dns_eq_fail:  db "[PAOS64] P4 net dns: encode_qname tournament KAT FAIL [tourn.dns_encode_qname.kat.fail] step=", 0

%macro WDATA_dns_cache_observation 0
alignb 8
dns_cache_clock_last:        resq 1  ; high-water retained across live reset
dns_cache_clock_sample:     resq 1
dns_cache_clock_epoch:      resq 1
dns_cache_incarnation_next: resq 1  ; never reused during this boot
dns_query_incarnation_next: resq 1
dns_query_incarnation:      resq 1
dns_query_route_generation: resq 1
dns_cache_clock_known:      resb 1
%endmacro
WDATA_BSS_DEFER WDATA_dns_cache_observation
