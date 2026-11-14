;; MODULE net/icmp
;; LAYER 4
;; EXPORTS icmp_echo_selftest, icmp_build_reply_kat, icmp_build_ipv4_reply
;; IMPORTS boot/serial, core/lib/fmt, core/lib/cksum, core/lib/mem
;; CAPS
;; OWNER saga:net
; ============================================================================
; net/icmp.asm — the ICMP echo responder LOGIC (contract 1043 / C10b, the qemu
; rung of the bare-metal 1023 net_icmp_echo). ICMP rides ON TOP of the ipv4 layer
; proven in 1042 (net/stack.asm); here we prove the echo request->reply math at
; boot over a CANNED in-memory frame — no NIC, no host ping (the live-wire round
; trip is 1023/bare_metal). The selftest is CONTENT-graded: it PRINTS the computed
; reply ICMP checksum + a digest of the echoed payload, and the probe re-checks
; them (checksum non-zero + well-formed; echoed-payload digest == request-payload
; digest — proves a real echo, not a zeroed/truncated one). A stub that emits the
; marker without the arithmetic FAILS.
;
;   * icmp.echo.logic  — build the echo REPLY for a canned echo REQUEST: type 0,
;                        code 0, id/seq preserved, payload echoed VERBATIM, and a
;                        correct ICMP checksum recomputed over the ICMP header+
;                        payload ONLY (NOT the IP header — a classic off-by-scope
;                        bug). Self-verifying: re-summing the reply WITH the
;                        computed checksum inserted folds to 0 (RFC1071 validity).
;   * NEGATIVE GATE   — a short/truncated ICMP frame (len < 8) is bounds-checked
;                        and REJECTED (no OOB, no crash, boot continues); an echo
;                        request whose type/code is NOT 8/0 is ignored.
;
; All checksum math goes through core/lib/cksum (G1: one one's-complement routine
; for the whole stack — no per-protocol copy).
; ============================================================================

ICMP_TYPE_ECHO_REQUEST equ 8
ICMP_TYPE_ECHO_REPLY   equ 0
ICMP_MIN_LEN           equ 8       ; ICMP header = type,code,cksum(2),id(2),seq(2)
ICMP_ETH_HLEN          equ 14
ICMP_IPV4_MIN_HLEN     equ 20
ICMP_IPV4_MTU          equ 1500

; icmp_build_ipv4_reply — build one complete Ethernet+IPv4 Echo Reply through the
;   protocol-layer seam. The caller has already established that the IPv4 dst is
;   owned by this ingress handle and supplies the peer MAC returned by
;   arp_cache_lookup; this function never resolves or bypasses the cache inline.
;   RDI=dst frame, RSI=request frame, RDX=request frame len, RCX=request IHL,
;   R8=ARP-cached peer MAC, R9=our ingress MAC.
;   Returns RAX=reply frame len / -1 reject. Only type 8/code 0 Echo Requests
;   are answered. Rejection leaves dst untouched. Fragmented/oversize requests
;   degrade to a drop; the contract explicitly defers fragment reassembly.
icmp_build_ipv4_reply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbx, rdi                         ; reply frame
    mov  r12, rsi                         ; request frame
    mov  r10, rdx                         ; received frame length
    mov  r14, rcx                         ; request IPv4 IHL
    mov  r15, r8                          ; peer MAC from ARP cache
    mov  [rsp], r9                        ; our ingress MAC
    test rbx, rbx
    jz   .ipv4_reject
    test r12, r12
    jz   .ipv4_reject
    test r15, r15
    jz   .ipv4_reject
    cmp  r10, ICMP_ETH_HLEN + ICMP_IPV4_MIN_HLEN + ICMP_MIN_LEN
    jb   .ipv4_reject
    cmp  r14, ICMP_IPV4_MIN_HLEN
    jb   .ipv4_reject
    cmp  r14, 60                          ; IPv4 IHL maximum
    ja   .ipv4_reject
    movzx eax, byte [r12 + ICMP_ETH_HLEN]
    mov  edx, eax
    shr  edx, 4
    cmp  edx, 4                           ; IPv4 only
    jne  .ipv4_reject
    and  eax, 0x0f
    shl  eax, 2
    cmp  rax, r14                         ; caller/parser IHL must agree on-wire
    jne  .ipv4_reject
    ; Reject reserved/MF/fragment-offset while allowing only the DF flag.
    mov  al, [r12 + ICMP_ETH_HLEN + 6]
    and  al, 0xbf                         ; clear DF; every other set bit rejects
    jnz  .ipv4_reject
    cmp  byte [r12 + ICMP_ETH_HLEN + 7], 0
    jne  .ipv4_reject
    ; IP total length must fit the received frame and the v1 MTU.
    movzx eax, byte [r12 + ICMP_ETH_HLEN + 2]
    shl  eax, 8
    mov  al, [r12 + ICMP_ETH_HLEN + 3]
    cmp  eax, ICMP_IPV4_MTU
    ja   .ipv4_reject
    mov  r13d, eax                        ; IP total length
    cmp  r13, r14
    jb   .ipv4_reject
    lea  rax, [r13 + ICMP_ETH_HLEN]
    cmp  rax, r10
    ja   .ipv4_reject
    sub  r13, r14                         ; ICMP header + payload length
    cmp  r13, ICMP_MIN_LEN
    jb   .ipv4_reject
    ; Validate Echo grammar before any destination write. The inner builder
    ; repeats this admission for its direct callers; nonzero codes are never
    ; normalized into valid replies. The declared ICMP span is bounded above.
    cmp  byte [r12 + ICMP_ETH_HLEN + r14], ICMP_TYPE_ECHO_REQUEST
    jne  .ipv4_reject
    cmp  byte [r12 + ICMP_ETH_HLEN + r14 + 1], 0
    jne  .ipv4_reject
    ; Both incoming checksums must validate before we amplify the request.
    lea  rdi, [r12 + ICMP_ETH_HLEN]
    mov  rsi, r14
    call net_cksum16
    test ax, ax
    jnz  .ipv4_reject
    lea  rdi, [r12 + ICMP_ETH_HLEN + r14]
    mov  rsi, r13
    call net_cksum16
    test ax, ax
    jnz  .ipv4_reject
    ; Ethernet dst comes only from the ARP-cache lookup supplied by the caller.
    mov  eax, [r15]
    mov  [rbx + 0], eax
    mov  ax, [r15 + 4]
    mov  [rbx + 4], ax
    mov  r11, [rsp]
    mov  eax, [r11]
    mov  [rbx + 6], eax
    mov  ax, [r11 + 4]
    mov  [rbx + 10], ax
    mov  byte [rbx + 12], 0x08
    mov  byte [rbx + 13], 0x00
    ; Canonical fresh IPv4 header: src/dst swapped, protocol 1, DF, TTL 64.
    lea  rdi, [rbx + ICMP_ETH_HLEN]
    mov  byte [rdi + 0], 0x45
    mov  byte [rdi + 1], 0
    lea  eax, [r13 + ICMP_IPV4_MIN_HLEN]
    mov  [rdi + 2], ah
    mov  [rdi + 3], al
    mov  word [rdi + 4], 0
    mov  byte [rdi + 6], 0x40
    mov  byte [rdi + 7], 0
    mov  byte [rdi + 8], 64
    mov  byte [rdi + 9], 1
    mov  word [rdi + 10], 0
    mov  eax, [r12 + ICMP_ETH_HLEN + 16] ; reply src = request dst (owned IP)
    mov  [rdi + 12], eax
    mov  eax, [r12 + ICMP_ETH_HLEN + 12] ; reply dst = request src
    mov  [rdi + 16], eax
    ; Copy id/sequence/payload verbatim and recompute checksum over the reply.
    lea  rdi, [rbx + ICMP_ETH_HLEN + ICMP_IPV4_MIN_HLEN]
    lea  rsi, [r12 + ICMP_ETH_HLEN + r14]
    mov  rdx, r13
    call icmp_build_reply
    test rax, rax
    jnz  .ipv4_reject
    lea  rdi, [rbx + ICMP_ETH_HLEN]
    mov  rsi, ICMP_IPV4_MIN_HLEN
    call net_cksum16
    mov  cx, ax
    lea  rdi, [rbx + ICMP_ETH_HLEN]
    mov  [rdi + 10], ch
    mov  [rdi + 11], cl
    lea  rax, [r13 + ICMP_ETH_HLEN + ICMP_IPV4_MIN_HLEN]
    jmp  .ipv4_out
.ipv4_reject:
    mov  rax, -1
.ipv4_out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; icmp_build_reply(RDI=dst reply buf, RSI=src request buf, RDX=len) -> RAX = 0 on
;   success (reply built in dst), RAX = -1 on REJECT (len < 8, or src is not a
;   type 8/code 0 echo REQUEST). On reject NOTHING is written to dst: the length
;   is validated BEFORE memcpy, so a short/hostile frame can never OOB.
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
icmp_build_reply:
    cmp  rdx, ICMP_MIN_LEN
    jb   .reject                         ; too short for even the ICMP header
    cmp  byte [rsi], ICMP_TYPE_ECHO_REQUEST
    jne  .reject                         ; not an echo request -> do not mis-reply
    cmp  byte [rsi + 1], 0
    jne  .reject                         ; Echo Request code must be zero
    mov  r8,  rdi                         ; stash dst
    mov  r9,  rdx                         ; stash len
    ; reply := request (verbatim copy, incl. id/seq/payload), then patch fields
    call memcpy                           ; (rdi=dst, rsi=src, rdx=len)
    mov  byte [r8],     ICMP_TYPE_ECHO_REPLY   ; type 0
    mov  byte [r8 + 1], 0                       ; code 0
    mov  byte [r8 + 2], 0                       ; zero the checksum field before summing
    mov  byte [r8 + 3], 0
    ; ICMP checksum covers the ICMP header+payload ONLY (r8..r8+len), not the IP hdr
    mov  rdi, r8
    mov  rsi, r9
    call net_cksum16                      ; AX = checksum C (network-order value)
    mov  edx, eax
    shr  edx, 8                           ; DL = high byte (AH unusable w/ REX r8)
    mov  byte [r8 + 2], dl                ; insert C, network order: high byte first
    mov  byte [r8 + 3], al
    xor  eax, eax                         ; success
    ret
.reject:
    mov  rax, -1
    ret

; icmp_payload_digest(RDI=frame ptr, RSI=len) -> RAX = digest of the payload
;   (bytes at offset ICMP_MIN_LEN..len). Reuses net_cksum16 (G1) as a cheap,
;   deterministic content digest — identical bytes => identical digest, so a real
;   echo makes req.digest == rep.digest and a zeroed/truncated echo does not.
;   clobbers: RAX,RCX,RDX,RDI,RSI
icmp_payload_digest:
    add  rdi, ICMP_MIN_LEN
    sub  rsi, ICMP_MIN_LEN
    call net_cksum16
    ret

; icmp_echo_selftest — THE 1043 acceptance gate. Build the reply for the canned
;   request, content-validate it, PRINT the KAT (reply checksum + req/rep payload
;   digests), and emit the marker ONLY when every check passes. Then prove the
;   negative gate (short frame + non-echo type are both rejected, no crash).
;   clobbers: caller-saved; preserves rbx,r12-r15 (saved here).
icmp_echo_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---------- positive: canned echo REQUEST -> echo REPLY ----------
    lea  rdi, [rel icmp_reply]
    lea  rsi, [rel icmp_request]
    mov  rdx, icmp_req_len
    call icmp_build_reply
    test rax, rax
    jnz  .done                            ; a valid request must build a reply

    lea  rbx, [rel icmp_reply]
    ; type must be echo-reply (0), code 0
    cmp  byte [rbx],     ICMP_TYPE_ECHO_REPLY
    jne  .done
    cmp  byte [rbx + 1], 0
    jne  .done
    ; identifier + sequence preserved verbatim (reply[4..7] == request[4..7])
    lea  rsi, [rel icmp_request]
    mov  eax, [rbx + 4]
    cmp  eax, [rsi + 4]
    jne  .done
    ; well-formed: re-summing the reply (checksum now inserted) folds to 0
    lea  rdi, [rel icmp_reply]
    mov  rsi, icmp_req_len
    call net_cksum16
    test ax, ax
    jnz  .done
    ; checksum value must be NON-ZERO (a stub emitting 0 fails the probe)
    movzx r13d, byte [rbx + 2]
    shl   r13d, 8
    movzx eax,  byte [rbx + 3]
    or    r13d, eax                       ; R13 = computed reply checksum C
    test  r13d, r13d
    jz    .done

    ; payload digests: request vs reply (must match -> proves verbatim echo)
    lea  rdi, [rel icmp_request]
    mov  rsi, icmp_req_len
    call icmp_payload_digest
    mov  r14d, eax                         ; req payload digest
    lea  rdi, [rel icmp_reply]
    mov  rsi, icmp_req_len
    call icmp_payload_digest
    mov  r15d, eax                         ; rep payload digest
    cmp  r14d, r15d
    jne  .done                             ; echo altered the payload -> fail

    ; ---------- negative gate: reject short + non-echo frames, no crash ----------
    lea  rdi, [rel icmp_reply]
    lea  rsi, [rel icmp_request]
    mov  rdx, 4                            ; truncated (< ICMP_MIN_LEN)
    call icmp_build_reply
    cmp  rax, -1
    jne  .done                             ; a short frame MUST be rejected
    lea  rdi, [rel icmp_reply]
    lea  rsi, [rel icmp_nonecho]
    mov  rdx, icmp_req_len
    call icmp_build_reply
    cmp  rax, -1
    jne  .done                             ; a non-echo type MUST be rejected

    ; ---------- all checks passed: print the KAT, then earn the marker ----------
    lea  rdi, [rel str_icmp_kat_cksum]
    mov  esi, r13d
    call icmp_emit_hex_kat
    lea  rdi, [rel str_icmp_req_digest]
    mov  esi, r14d
    call icmp_emit_hex_kat
    lea  rdi, [rel str_icmp_rep_digest]
    mov  esi, r15d
    call icmp_emit_hex_kat
    lea  rdi, [rel str_icmp_pass]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; icmp_emit_hex_kat(RDI=prefix ending in "0x", ESI=value) — print "<prefix><hex>\r\n"
;   through the canonical fmt_str/fmt_hex (G1 formatters). clobbers: volatiles + R12
icmp_emit_hex_kat:
    push rsi                               ; stash value
    lea  r12, [rel icmp_kat_buf]
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
    lea  rdi, [rel icmp_kat_buf]
    call serial_string
    ret

; icmp_build_reply_kat — TOURNAMENT 1429 (durability class, SMALLEST/SIMPLEST
;   variant): known-answer + adversarial-fault gate for icmp_build_reply. The
;   shipped body is KEPT BYTE-FOR-BYTE — it is already the leanest correct form
;   (length-check-BEFORE-memcpy, echo-request type gate, one checksum via the
;   canonical net_cksum16, no per-protocol copy). This variant adds ONLY the
;   correctness GATE the tournament mandates; it does not touch the hot path.
;
;   POSITIVE (P1): the canned echo REQUEST (type 8, id 0x1234, seq 0x002a, payload
;     "PaOS-42!") builds BYTE-FOR-BYTE into: type=0, code=0, checksum=0xEE97
;     (RFC1071, independently verified), id/seq preserved, payload echoed VERBATIM,
;     and the finished reply re-sums (checksum inserted) to 0 — RFC1071 validity.
;
;   FAULT BATTERY (T=5, every vector CONTAINED by the unchanged body -> -1 with the
;     dst scratch UNTOUCHED): (F1) empty len=0; (F2) boundary len=7 (one below
;     ICMP_MIN_LEN); (F3) degenerate len=1; (F4) type=0 echo-REPLY (not a request);
;     (F5) type=13 timestamp (non-echo). Each is CONTENT-checked — the -1 return AND
;     a 0xBB canary in the dst scratch proven intact (a reject writes NOTHING, so no
;     corruption — not merely "didn't crash"). N (never < baseline) is the tally.
;
;   PASS earns [tourn.icmp_build_reply.kat] [tourn.icmp_build_reply.guard] and emits
;   [tourn.icmp_build_reply.fault contained=N total=5]. Any mismatch prints the
;   failing step id + .fail marker and boot CONTINUES (degrade, never crash).
;   clobbers volatiles; preserves rbx,r12-r15.
icmp_build_reply_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r14d, r14d                       ; contained-fault counter

    ; ---- (P1) POSITIVE: canned echo request -> byte-exact echo reply ----
    mov  r15d, 1
    lea  rdi, [rel icmp_kr_reply]
    lea  rsi, [rel icmp_request]
    mov  rdx, icmp_req_len
    call icmp_build_reply
    test rax, rax
    jnz  .fail                            ; a valid request MUST build a reply
    lea  rbx, [rel icmp_kr_reply]
    cmp  byte [rbx + 0], ICMP_TYPE_ECHO_REPLY
    jne  .fail                            ; type 0
    cmp  byte [rbx + 1], 0
    jne  .fail                            ; code 0
    cmp  byte [rbx + 2], 0xEE             ; checksum hi — golden 0xEE97, byte-exact
    jne  .fail
    cmp  byte [rbx + 3], 0x97             ; checksum lo
    jne  .fail
    lea  rsi, [rel icmp_request]
    mov  eax, [rbx + 4]                   ; id+seq (bytes 4..7) preserved verbatim
    cmp  eax, [rsi + 4]
    jne  .fail
    mov  eax, [rbx + 8]                   ; payload word 0 (bytes 8..11) echoed
    cmp  eax, [rsi + 8]
    jne  .fail
    mov  eax, [rbx + 12]                  ; payload word 1 (bytes 12..15) echoed
    cmp  eax, [rsi + 12]
    jne  .fail
    lea  rdi, [rel icmp_kr_reply]         ; RFC1071: re-sum with cksum inserted -> 0
    mov  rsi, icmp_req_len
    call net_cksum16
    test ax, ax
    jnz  .fail

    ; ---- fault battery: 5 hostile/boundary vectors, all contained to -1 with the
    ;      dst scratch untouched. Arm the canary once; every reject leaves it intact.
    mov  byte [rel icmp_kr_reply], 0xBB

    ; (F1) empty len=0 -> -1 (length gate, before any deref)
    mov  r15d, 2
    lea  rdi, [rel icmp_kr_reply]
    lea  rsi, [rel icmp_request]
    xor  edx, edx
    call icmp_build_reply
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel icmp_kr_reply], 0xBB   ; dst untouched (reject writes nothing)
    jne  .fail
    inc  r14d

    ; (F2) boundary len=7 (one below ICMP_MIN_LEN) -> -1
    mov  r15d, 3
    lea  rdi, [rel icmp_kr_reply]
    lea  rsi, [rel icmp_request]
    mov  edx, 7
    call icmp_build_reply
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel icmp_kr_reply], 0xBB
    jne  .fail
    inc  r14d

    ; (F3) degenerate len=1 -> -1
    mov  r15d, 4
    lea  rdi, [rel icmp_kr_reply]
    lea  rsi, [rel icmp_request]
    mov  edx, 1
    call icmp_build_reply
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel icmp_kr_reply], 0xBB
    jne  .fail
    inc  r14d

    ; (F4) type=0 echo-REPLY at valid len -> -1 (must not re-reply to a reply)
    mov  r15d, 5
    lea  rdi, [rel icmp_kr_reply]
    lea  rsi, [rel icmp_kr_type0]
    mov  edx, 8
    call icmp_build_reply
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel icmp_kr_reply], 0xBB
    jne  .fail
    inc  r14d

    ; (F5) type=13 timestamp (non-echo) at valid len -> -1
    mov  r15d, 6
    lea  rdi, [rel icmp_kr_reply]
    lea  rsi, [rel icmp_nonecho]
    mov  rdx, icmp_req_len
    call icmp_build_reply
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel icmp_kr_reply], 0xBB
    jne  .fail
    inc  r14d

    ; ---- all gates passed: KAT + guard markers, then the live fault tally ----
    lea  rdi, [rel str_icmp_kr_kat1]
    call serial_string
    lea  rdi, [rel str_icmp_kr_pass]
    call serial_string
    lea  rdi, [rel str_icmp_kr_flt1]
    call serial_string
    mov  edi, r14d                        ; contained count, read back live
    lea  rsi, [rel icmp_kat_buf]
    call fmt_dec
    lea  rdi, [rel icmp_kat_buf]
    call serial_string
    lea  rdi, [rel str_icmp_kr_flt2]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_icmp_kr_fail]
    call serial_string
    mov  edi, r15d                        ; failing step id, read back live
    lea  rsi, [rel icmp_kat_buf]
    call fmt_dec
    lea  rdi, [rel icmp_kat_buf]
    call serial_string
    lea  rdi, [rel str_icmp_kr_crlf]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- net/icmp data (canned vectors; writable, in-image) -------------------------
; Canned ICMP echo REQUEST: type=8, code=0, cksum=0(don't-care), id=0x1234,
; seq=0x002a, payload "PaOS-42!" (8 bytes). Total = 16 bytes (ICMP hdr + payload).
icmp_request:  db 0x08, 0x00              ; type=echo request, code=0
               db 0x00, 0x00              ; checksum (recomputed for the reply)
               db 0x12, 0x34              ; identifier
               db 0x00, 0x2a              ; sequence
               db 'P','a','O','S','-','4','2','!'   ; echo payload
icmp_req_len   equ $ - icmp_request

; Same frame but a NON-echo type (13 = timestamp request) — the negative gate
; asserts icmp_build_reply ignores it rather than fabricating a bogus reply.
icmp_nonecho:  db 0x0d, 0x00
               db 0x00, 0x00
               db 0x12, 0x34
               db 0x00, 0x2a
               db 'P','a','O','S','-','4','2','!'

icmp_reply:    times icmp_req_len db 0    ; reply scratch (built at runtime)
icmp_kat_buf:  times 96 db 0

; --- TOURNAMENT 1429 icmp_build_reply KAT vectors + scratch + markers -----------
icmp_kr_reply: times icmp_req_len db 0    ; KAT reply scratch (+ 0xBB canary target)
; type=0 echo-REPLY (NOT a request) — the type gate must refuse to re-reply (8 bytes)
icmp_kr_type0: db 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x2a

str_icmp_kr_kat1: db "[PAOS64][INF][net] tourn.icmp_build_reply kat pos=1 neg=5 cksum=0xEE97 id_seq+payload echoed", 13,10,0
str_icmp_kr_pass: db "[PAOS64] P4 net icmp: build_reply tournament KAT PASS [tourn.icmp_build_reply.kat] [tourn.icmp_build_reply.guard]", 13,10,0
str_icmp_kr_flt1: db "[PAOS64][INF][net] tourn.icmp_build_reply fault [tourn.icmp_build_reply.fault contained=", 0
str_icmp_kr_flt2: db " total=5]", 13,10,0
str_icmp_kr_fail: db "[PAOS64] P4 net icmp: build_reply tournament KAT FAIL [tourn.icmp_build_reply.kat.fail] step=", 0
str_icmp_kr_crlf: db 13,10,0

str_icmp_pass:        db "[PAOS64] P4 net icmp: canned request->reply selftest PASS [icmp.echo.logic]", 13,10,0
str_icmp_kat_cksum:   db "[PAOS64][INF][net] icmp.kat cksum=0x", 0
str_icmp_req_digest:  db "[PAOS64][INF][net] icmp.req_digest=0x", 0
str_icmp_rep_digest:  db "[PAOS64][INF][net] icmp.rep_digest=0x", 0
