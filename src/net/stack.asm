;; MODULE net/stack
;; LAYER 4
;; EXPORTS net_stack_selftest
;; IMPORTS boot/serial, core/lib/fmt, core/lib/cksum, core/lib/mem
;; CAPS
;; OWNER saga:net
; ============================================================================
; net/stack.asm — the L4 network STACK LOGIC (arp/ipv4/udp) + the command/verb
; DISPATCH REGISTRY, proven in QEMU without a real NIC (contract 1042 / C10a, the
; qemu rung of 1010). The stack math is fed CANNED frames from memory and the
; selftest PRINTS its computed results (KAT) so the probe content-grades them — a
; stub that emits the marker without doing the arithmetic FAILS:
;   * arp.stack        — build the ARP reply for a canned request; the reply's
;                        sender-HW-addr must be OUR MAC, opcode must be 2, and the
;                        reply's target-HW must be the request's sender-HW.
;   * ipv4.stack       — the IPv4 header checksum of the RFC1071 worked-example
;                        header must equal 0xb861 (the published answer).
;   * udp.stack        — the UDP checksum over a canned pseudo-header+datagram;
;                        re-summing WITH the computed checksum inserted must fold
;                        to 0x0000 (the receiver's validity test) — self-verifying.
;   * framework.dispatch — a canned 'ECHO' command routed through a 2-verb registry
;                        must land on the echo handler (not ping), and an unknown
;                        verb must return no-handler (default-deny) — proves ROUTING.
;
; All checksum math goes through core/lib/cksum (G1: one one's-complement routine
; for the whole stack). Handler pointers are populated at RUNTIME via lea (PaOS's
; PE32+ ImageBase is NOT applied to `dq <symbol>` — the loopnet_ops pattern), so
; the registry dispatches to the true runtime VA, not a compile-time org-0 offset.
; ============================================================================

; net_stack_selftest — the 1042 acceptance gate. Each of the 4 markers is EARNED
;   (gated on the real computed outcome), and each numeric KAT is printed for the
;   probe to re-check. Live-wire UDP round-trip over the real NIC is 1010.
;   clobbers: caller-saved; preserves rbx,r12-r15 (saved here).
net_stack_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; --- populate dispatch handler pointers at RUNTIME (dq-symbol VA trap) ---
    lea  rax, [rel h_ping]
    mov  [rel verb_handlers], rax
    lea  rax, [rel h_echo]
    mov  [rel verb_handlers + 8], rax

    ; ================= (1) ARP: build reply from canned request ==============
    lea  rdi, [rel arp_reply]
    lea  rsi, [rel arp_request]
    mov  rdx, 28
    call memcpy                          ; reply := request (then patch the fields)
    lea  rbx, [rel arp_reply]
    ; opcode: request(0x0001) -> reply(0x0002)  (network order: bytes 00 02)
    mov  byte [rbx + 6], 0x00
    mov  byte [rbx + 7], 0x02
    ; tha (reply[18..23]) := request.sha (request[8..13])  -- BEFORE overwriting sha
    lea  rsi, [rel arp_request]
    mov  eax, [rsi + 8]
    mov  [rbx + 18], eax
    mov  ax,  [rsi + 12]
    mov  [rbx + 22], ax
    ; tpa (reply[24..27]) := request.spa (request[14..17])
    mov  eax, [rsi + 14]
    mov  [rbx + 24], eax
    ; sha (reply[8..13]) := OUR_MAC
    lea  rsi, [rel our_mac]
    mov  eax, [rsi]
    mov  [rbx + 8], eax
    mov  ax,  [rsi + 4]
    mov  [rbx + 12], ax
    ; spa (reply[14..17]) := OUR_IP  (== request.tpa)
    lea  rsi, [rel our_ip]
    mov  eax, [rsi]
    mov  [rbx + 14], eax

    ; --- validate the reply (content-grade gate for arp.stack) ---
    cmp  byte [rbx + 6], 0x00
    jne  .arp_done
    cmp  byte [rbx + 7], 0x02
    jne  .arp_done
    lea  rsi, [rel our_mac]
    mov  eax, [rbx + 8]
    cmp  eax, [rsi]                       ; reply.sha low4 == OUR_MAC low4
    jne  .arp_done
    mov  ax,  [rbx + 12]
    cmp  ax,  [rsi + 4]                   ; reply.sha hi2  == OUR_MAC hi2
    jne  .arp_done
    lea  rsi, [rel arp_request]
    mov  eax, [rbx + 18]
    cmp  eax, [rsi + 8]                   ; reply.tha == request.sha
    jne  .arp_done
    lea  rdi, [rel str_stk_arp_pass]
    call serial_string
.arp_done:

    ; ================= (2) IPv4 header checksum (RFC1071) ====================
    lea  rdi, [rel ipv4_hdr]
    mov  word [rdi + 10], 0              ; zero the checksum field before summing
    lea  rdi, [rel ipv4_hdr]
    mov  rsi, 20
    call net_cksum16                     ; AX = checksum (net_cksum16 clobbers RDI)
    mov  r13d, eax
    cmp  ax, 0xb861                       ; the published worked-example answer
    jne  .ipv4_done
    lea  rdi, [rel str_ipv4_pass]
    call serial_string
    lea  rdi, [rel str_kat_ipv4]
    mov  esi, r13d
    call emit_hex_kat
.ipv4_done:

    ; ================= (3) UDP checksum (pseudo-header) ======================
    lea  rdi, [rel udp_buf]
    mov  word [rdi + 18], 0             ; zero checksum field (udp hdr off 8 -> buf off 18)
    lea  rdi, [rel udp_buf]
    mov  rsi, 24
    call net_cksum16                     ; AX = computed UDP checksum C
    mov  r14d, eax
    test ax, ax                          ; UDP maps 0->0xFFFF; our vector is nonzero
    jz   .udp_done
    ; insert C in network order (high byte first) and re-sum -> must fold to 0
    lea  rdi, [rel udp_buf]
    mov  eax, r14d
    mov  dl, al
    mov  dh, ah
    mov  [rdi + 18], dh                   ; checksum field high byte
    mov  [rdi + 19], dl                   ; checksum field low byte
    lea  rdi, [rel udp_buf]
    mov  rsi, 24
    call net_cksum16                     ; valid datagram re-sums to 0
    test ax, ax
    jnz  .udp_done
    lea  rdi, [rel str_udp_pass]
    call serial_string
    lea  rdi, [rel str_kat_udp]
    mov  esi, r14d
    call emit_hex_kat
.udp_done:

    ; ================= (4) command/verb dispatch registry ====================
    mov  edi, [rel cmd_echo]             ; canned 'ECHO' command (4-char verb)
    call net_dispatch                    ; RAX = matched verb index / -1
    cmp  rax, 1                           ; 'ECHO' is registered at index 1
    jne  .disp_done
    cmp  byte [rel disp_sentinel], 'E'   ; the echo handler actually ran
    jne  .disp_done
    mov  edi, [rel cmd_unknown]          ; negative: unknown verb -> default-deny
    call net_dispatch
    cmp  rax, -1
    jne  .disp_done                       ; an unknown verb matching = broken registry
    lea  rdi, [rel str_disp_pass]
    call serial_string
    lea  rdi, [rel str_kat_route]
    call serial_string
.disp_done:

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; net_dispatch(EDI=4-char verb) -> RAX = matched verb index / -1 (default-deny).
;   Scans the registry, compares the packed 4-byte verb, and CALLs the matching
;   handler through its runtime-populated pointer. Proves ROUTING (not a hardcode):
;   two verbs are registered and only the matching one's handler runs.
;   clobbers: RAX,RCX,R8,R9,R10 (+ whatever the handler clobbers)
net_dispatch:
    mov  ecx, [rel stk_verb_count]
    xor  r8, r8
    lea  r9,  [rel verb_names]           ; RIP-rel base (no index reg in [rel ..])
    lea  r10, [rel verb_handlers]
.scan:
    cmp  r8d, ecx
    jae  .none
    mov  eax, [r9 + r8*4]
    cmp  eax, edi
    je   .hit
    inc  r8
    jmp  .scan
.hit:
    mov  rax, [r10 + r8*8]               ; runtime VA populated by net_stack_selftest
    call rax
    mov  rax, r8
    ret
.none:
    mov  rax, -1
    ret

h_ping:                                  ; verb handler #0 — stamps 'P'
    mov  byte [rel disp_sentinel], 'P'
    ret
h_echo:                                  ; verb handler #1 — stamps 'E'
    mov  byte [rel disp_sentinel], 'E'
    ret

; emit_hex_kat(RDI=prefix string ending in "0x", ESI=value) — print one KAT line
;   "<prefix><hexvalue>\r\n" through the canonical fmt_str/fmt_hex (G1 formatters).
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10,R12
emit_hex_kat:
    push rsi                              ; stash value
    lea  r12, [rel netkat_buf]
    mov  rsi, r12                         ; dst (RDI already = prefix src)
    call fmt_str
    add  r12, rax
    pop  rdi                              ; value -> fmt_hex RDI
    mov  rsi, r12
    xor  rdx, rdx                         ; minimal-width hex
    call fmt_hex
    add  r12, rax
    mov  byte [r12], 13
    mov  byte [r12 + 1], 10
    mov  byte [r12 + 2], 0
    lea  rdi, [rel netkat_buf]
    call serial_string
    ret

; --- net/stack data (canned test vectors + registry; writable, in-image) --------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_stack_0 0
our_mac:       db 0x52,0x54,0x00,0x12,0x34,0x56
our_ip:        db 192,168,0,199                     ; c0 a8 00 c7

; canned ARP request (28 bytes): htype/ptype/hlen/plen/oper, sha, spa, tha, tpa
arp_request:   db 0x00,0x01, 0x08,0x00, 0x06, 0x04, 0x00,0x01
               db 0xaa,0xbb,0xcc,0xdd,0xee,0xff      ; sha (requester)
               db 192,168,0,1                        ; spa
               db 0,0,0,0,0,0                         ; tha (unknown in a request)
               db 192,168,0,199                       ; tpa (our IP)
arp_reply:     times 28 db 0

; RFC1071 worked-example IPv4 header (20 bytes); checksum field zeroed for compute
ipv4_hdr:      db 0x45,0x00,0x00,0x73, 0x00,0x00, 0x40,0x00, 0x40,0x11
               db 0x00,0x00                           ; checksum -> computes to 0xb861
               db 192,168,0,1                         ; src
               db 192,168,0,199                       ; dst

; UDP checksum buffer = pseudo-header(12) + UDP header(8) + payload(4) = 24 bytes
udp_buf:       db 192,168,0,1                         ; pseudo: src IP
               db 192,168,0,199                       ; pseudo: dst IP
               db 0x00, 0x11                          ; pseudo: zero, proto=17 (UDP)
               db 0x00, 0x0c                          ; pseudo: UDP length = 12
               db 0x30,0x39                           ; UDP src port 12345
               db 0x00,0x35                           ; UDP dst port 53
               db 0x00,0x0c                           ; UDP length 12
               db 0x00,0x00                           ; UDP checksum (runtime)
               db 0x74,0x65,0x73,0x74                 ; payload "test"

verb_names:    dd 'PING', 'ECHO'                      ; packed 4-char verb ids
stk_verb_count:    dd 2
verb_handlers: times 2 dq 0                           ; runtime VAs (dq-symbol trap)
disp_sentinel: db 0
cmd_echo:      db 'ECHO'
cmd_unknown:   db 'XXXX'
netkat_buf:    times 96 db 0

str_stk_arp_pass:  db "[PAOS64] P4 net arp: request->reply selftest PASS [arp.stack]", 13,10,0
str_ipv4_pass: db "[PAOS64] P4 net ipv4: header+checksum selftest PASS [ipv4.stack]", 13,10,0
str_udp_pass:  db "[PAOS64] P4 net udp: checksum+port selftest PASS [udp.stack]", 13,10,0
str_disp_pass: db "[PAOS64] P4 net dispatch: 2-verb registry route PASS [framework.dispatch]", 13,10,0
str_kat_ipv4:  db "[PAOS64][INF][net] net.kat ipv4_cksum=0x", 0
str_kat_udp:   db "[PAOS64][INF][net] net.kat udp_cksum=0x", 0
str_kat_route: db "[PAOS64][INF][net] net.kat dispatch_route=echo", 13,10,0
%endmacro
WDATA_DEFER WDATA_net_stack_0
