;; MODULE svc/command_serial
;; LAYER 5
;; EXPORTS network_parser_bounds_kat_ok, command_serial_init, command_serial_beacon, command_serial_poll, command_serial_selftest, command_serial_rx_byte, command_serial_dispatch_line, command_serial_parse_u64
;; IMPORTS boot/serial, core/lib/fmt, lib/safe_buffer, core/time, net/udp, net/dhcp, net/dns, net/tcp, net/tls13, net/http, svc/command, svc/command_auth, svc/command_udp, svc/command_software_stop
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/command_serial.asm — THE SERIAL PROJECTION of the command registry
; (contract 1078, COMMANDS.md §1-3). Serial (COM1 0x3F8) is the EARLIEST
; bare-metal command surface — live before the NIC and before GOP — so it is the
; first report-back channel a headless, NIC-less box has. Per §1 this surface is
; a THIN PROJECTION: it reads a line-oriented verb off the UART and DISPATCHES it
; INTO the SAME command_dispatch (svc/command.asm, 1077) the in-process/UDP/ACP
; surfaces use. It owns NO command logic — only the wire framing (line assembly,
; arg marshalling per the verb's §9.4b ARGT self-description, reply formatting).
;
; THREE deliverables (1078):
;   (1) A COM1 RECEIVER: command_serial_poll drains the 16550 RBR, command_serial_
;       rx_byte assembles a CR/LF-terminated line, command_serial_dispatch_line
;       resolves the verb via the registry (command_lookup) and dispatches it.
;       The idle loop pumps command_serial_poll, so the channel is LIVE post-boot —
;       a rescue+verify path even when the NIC and screen are dead.
;   (2) The BEACON serial leg: command_serial_beacon emits "PAOS_BOOT_BEACON
;       <nonce>" on 0x3F8 at boot — the third beacon leg 1076 lacks, confirmable
;       over the FTDI cable with no NIC.
;   (3) CONTENT-GRADE (not a latch): PING carries a caller nonce; the reply must
;       carry the EXACT nonce back THROUGH the registry (RSP_VAL is the pointer the
;       registry echoed from REQ_ARG — a non-dispatching side-door leaves it 0, so
;       the nonce cannot be faked). command_serial_selftest proves the whole
;       UART-bytes -> line -> registry -> reply pipeline IN QEMU by feeding a fresh
;       rdtsc nonce through the identical rx path; bare metal proves it over the
;       LIVE /dev/ttyUSB0 (the binding gate, probe_command_serial_projection.sh).
;
; ARG MARSHALLING via §9.4b self-description: the projection reads the matched
; verb's ARGT tag (command_verb_argt) to marshal the token — ARGT_TEXT verbs
; (PING) get a POINTER to the raw token in REQ_ARG (echoed back verbatim);
; ARGT_U64 verbs (STATUS job_id) get the parsed decimal. No verb name is hardcoded
; in the marshalling — it is driven by the registry's own metadata.
; ============================================================================

CMD_SERIAL_LINEMAX equ 1536          ; compact AUTH1 RSA envelope + largest registry command

; ---------------------------------------------------------------------------
; command_serial_init — arm the COM1 command receiver (reset the line buffer,
;   emit the rx.init marker). The UART itself is already up (boot/serial.asm
;   serial_init at first-light); this arms the REGISTRY projection over it.
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
; ---------------------------------------------------------------------------
command_serial_init:
    mov  dword [rel cmd_serial_len], 0
    lea  rdi, [rel str_serial_rxinit]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; command_serial_beacon — the beacon serial leg: emit "PAOS_BOOT_BEACON <nonce>"
;   on 0x3F8 (a fresh per-boot rdtsc-mixed nonce). A headless, NIC-less box still
;   signals back over serial. clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
; ---------------------------------------------------------------------------
command_serial_beacon:
    push rbx
    rdtsc                              ; EDX:EAX
    xor  eax, edx
    imul eax, eax, 0x9E3779B1          ; Fibonacci-hash mix (not raw TSC low bits)
    and  eax, 0x00FFFFFF               ; keep it short + printable
    or   eax, 1                        ; never 0 (degenerate)
    mov  [rel cmd_serial_beacon_nonce], eax
    lea  rdi, [rel str_beacon_pre]     ; "...PAOS_BOOT_BEACON "
    call serial_string
    mov  edi, [rel cmd_serial_beacon_nonce]
    lea  rsi, [rel cmd_serial_numbuf]
    call fmt_dec                       ; the ONE canonical decimal formatter (G1)
    lea  rdi, [rel cmd_serial_numbuf]
    call serial_string
    lea  rdi, [rel str_beacon_post]    ; " emitted on 0x3F8 [beacon.serial.sent]\r\n"
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_serial_poll — drain the 16550 RBR: while the LSR Data-Ready bit is set,
;   read a byte and hand it to the line assembler. Non-blocking (returns as soon
;   as the RBR is empty). The idle loop calls this so the command channel is live
;   post-boot. Degrades to a no-op if no UART. clobbers: RAX,RCX,RDX,RDI
;   A public build has no COM1 command surface: output stays, input is never read.
; ---------------------------------------------------------------------------
command_serial_poll:
%if PAOS_PUBLIC_BUILD != 0
    ret
%else
    push rax
    push rdx
    push rdi
    cmp  byte [rel serial_available], 0     ; boot/serial.asm: cleared if no UART
    je   .done
.drain:
    cmp  byte [rel serial_mode], 1          ; HP-PORT-3: AX99100 MMIO UART selected
    je   .drain_ax
    mov  dx, COM1 + 5                       ; LSR
    in   al, dx
    test al, 1                              ; Data Ready
    jz   .done
    mov  dx, COM1                           ; RBR
    in   al, dx
    mov  dil, al
    call command_serial_rx_byte
    jmp  .drain
.drain_ax:
    call serial_rx_byte                     ; EAX=-1 empty, else the RBR byte
    cmp  eax, -1
    je   .done
    mov  dil, al
    call command_serial_rx_byte
    jmp  .drain
.done:
    pop  rdi
    pop  rdx
    pop  rax
    ret
%endif

; ---------------------------------------------------------------------------
; command_serial_rx_byte(DIL=byte) — assemble a CR/LF-terminated line. On a
;   terminator, dispatch the accumulated line (if non-empty) and reset. Once a
;   line exceeds capacity, discard it through EOL and emit INPUT_BOUNDS; never
;   dispatch a valid-looking truncated prefix. clobbers: RAX,RBX
; ---------------------------------------------------------------------------
command_serial_rx_byte:
    push rax
    push rbx
    movzx eax, dil
    cmp  al, 13                             ; CR
    je   .eol
    cmp  al, 10                             ; LF
    je   .eol
    cmp  byte [rel cmd_serial_overflow], 1
    je   .out                               ; discard the rest of an oversized line
    mov  ebx, [rel cmd_serial_len]
    cmp  ebx, CMD_SERIAL_LINEMAX - 1        ; leave room for the NUL
    jae  .overflow                          ; full -> refuse the complete line at EOL
    lea  rax, [rel cmd_serial_line]
    mov  [rax + rbx], dil
    inc  ebx
    mov  [rel cmd_serial_len], ebx
    jmp  .out
.overflow:
    mov  byte [rel cmd_serial_overflow], 1
    jmp  .out
.eol:
    cmp  byte [rel cmd_serial_overflow], 1
    jne  .eol_bounded
    lea  rdi, [rel str_serial_input_bounds]
    call serial_string
    jmp  .reset
.eol_bounded:
    mov  ebx, [rel cmd_serial_len]
    test ebx, ebx
    jz   .reset                             ; bare CR/LF -> ignore
    lea  rax, [rel cmd_serial_line]
    mov  byte [rax + rbx], 0                ; NUL-terminate the line
    mov  rdi, rax
    mov  esi, CMD_SERIAL_LINEMAX
    call safe_capped_len
    test edx, edx
    jnz  .embedded_nul
    cmp  eax, ebx
    jne  .embedded_nul                     ; NUL byte cannot conceal a retained tail
    call command_serial_dispatch_line
    jmp  .reset
.embedded_nul:
    lea  rdi, [rel str_serial_input_bounds]
    call serial_string
.reset:
    mov  dword [rel cmd_serial_len], 0
    mov  byte [rel cmd_serial_overflow], 0
    mov  byte [rel cmd_serial_line], 0
.out:
    pop  rbx
    pop  rax
    ret

; ---------------------------------------------------------------------------
; command_serial_dispatch_line — parse the NUL-terminated line in cmd_serial_line
;   (verb + optional arg), resolve the verb THROUGH the registry, marshal the arg
;   per the verb's ARGT self-description, dispatch, and reply over serial. THE
;   projection: it never owns logic, only framing. clobbers: caller-saved.
; ---------------------------------------------------------------------------
command_serial_dispatch_line:
    push r15
    xor  r15d, r15d                         ; this serial request owns no reset yet
    push rbx
    push r12
    push r13
    push r14
    call command_udp_gres_reply_retire       ; even an early refusal owns no previous diagnostic
    ; This ingress always owns SERIAL attribution. Clear the previous request's
    ; principal before unwrap, including unsigned and early-refused lines.
    mov  qword [rel cmd_serial_req + REQ_SOURCE], CMD_SOURCE_SERIAL
    mov  qword [rel cmd_serial_req + REQ_PRINCIPAL], CMD_PRINCIPAL_NONE
    lea  r12, [rel cmd_serial_line]
    mov  rdi, r12
    lea  rsi, [rel cmd_serial_auth_ticket]
    call command_auth_unwrap_line
    cmp  eax, AUTH_TS_VALID
    jne  .auth_attributed
    mov  rcx, [rel cmd_serial_auth_ticket + AUTH_T_PRINCIPAL]
    mov  [rel cmd_serial_req + REQ_PRINCIPAL], rcx
.auth_attributed:
    cmp  eax, AUTH_TS_MALFORMED
    je   .auth_malformed
    cmp  eax, AUTH_TS_WRONG_KEY
    je   .auth_wrong_key
    cmp  eax, AUTH_TS_EXPIRED
    je   .auth_expired
    cmp  eax, AUTH_TS_RETIRED
    je   .auth_retired
    cmp  eax, AUTH_TS_WRONG_NODE
    je   .auth_wrong_node
    lea  rdi, [rel cmd_serial_auth_ticket]
    call command_auth_remote_begin
    lea  r12, [rel cmd_serial_line]         ; verified inner/public verb name start
    mov  rdi, r12
    mov  esi, CMD_SERIAL_LINEMAX
    call safe_capped_len
    test edx, edx
    jnz  .input_bounds
    mov  rbx, r12
.findsp:
    movzx eax, byte [rbx]
    test al, al
    jz   .noarg
    cmp  al, ' '
    je   .hassp
    inc  rbx
    jmp  .findsp
.hassp:
    mov  byte [rbx], 0                       ; split: terminate the verb name
    inc  rbx
.skipsp:
    cmp  byte [rbx], ' '
    jne  .argset
    inc  rbx
    jmp  .skipsp
.argset:
    mov  r13, rbx                            ; r13 = arg text ptr
    jmp  .lookup
.noarg:
    mov  r13, rbx                            ; points at the NUL -> empty arg
.lookup:
    mov  rdi, r12
    call command_lookup                      ; RAX = verb id, or -1 (registry-owned)
    cmp  eax, -1                             ; 32-bit, like command_udp: an id is < 2^32, and a
                                             ; 64-bit compare once let an unknown verb through as
                                             ; id 0xFFFFFFFF -> command_verb_argt #PF (FINDING 20261001)
    je   .unknown
    mov  r14, rax                            ; r14 = verb id
    ; --- build the typed request envelope (marshal arg by ARGT self-description) ---
    lea  rdi, [rel cmd_serial_req]
    mov  [rdi + REQ_VERB], r14
    mov  qword [rdi + REQ_CAP], 0            ; remote authority stays in this AUTH2 ticket
    mov  qword [rdi + REQ_IDEM], 0
    mov  qword [rdi + REQ_SEL], 0
    mov  rdi, r14
    call command_verb_argt                   ; RAX = ARGT_*
    cmp  rax, ARGT_TEXT
    je   .arg_text
    ; numeric arg (e.g. STATUS job_id): parse the decimal token
    mov  rdi, r13
    call command_serial_parse_u64            ; RAX = value
    test edx, edx
    jnz  .input_bounds
    lea  rdi, [rel cmd_serial_req]
    mov  [rdi + REQ_ARG], rax
    jmp  .doreq
.arg_text:
    lea  rdi, [rel cmd_serial_req]
    mov  [rdi + REQ_ARG], r13                ; POINTER to the raw token (echoed verbatim)
.doreq:
    ; BOOT WIN has an explicit serial ack-then-reset completion. Refuse a
    ; pre-existing reset owner before dispatch, never consume its pending bit.
    mov  rdi, r12
    mov  rsi, r13
    call command_serial_boot_win_begin
    cmp  eax, 2
    je   .done
    mov  r15d, eax                           ; 1 only for exact BOOT + WIN
    lea  rdi, [rel cmd_serial_req]
    lea  rsi, [rel cmd_serial_rsp]
    call command_dispatch                    ; THE single entry; preserves rbx,r12-r15
    test r15d, r15d
    jz   .ordinary_reply
    lea  rdi, [rel cmd_serial_rsp]
    call command_serial_boot_win_reply
    mov  r15d, eax                           ; 2 only after the full accepted ack
    jmp  .done
.ordinary_reply:
    ; --- marker: a serial-arriving verb went through the 1077 registry ---
    lea  rdi, [rel str_serial_disp_pre]      ; "[PAOS64] cmd.serial.verb.dispatched="
    call serial_string
    mov  rdi, r12                            ; the verb name
    call serial_string
    cmp  byte [rel command_auth_out_ready], 1
    je   .auth_text_dispatch
    call command_udp_gres_reply_take
    test rax, rax
    jnz  .gres_text_dispatch                 ; current registry producer, not a nonce echo
    ; --- reply (formatting only; the ACTION already went through dispatch) ---
    mov  rax, [rel cmd_serial_rsp + RSP_CODE]
    test rax, rax
    jnz  .err                                ; non-OK (e.g. BADJOB) -> ERR line
    mov  rdi, r14
    call command_verb_argt
    cmp  rax, ARGT_TEXT
    jne  .ok_num
    ; text echo: RSP_VAL is the pointer the REGISTRY echoed from REQ_ARG. Assert it
    ; equals our token pointer (proves real dispatch — a side-door leaves it 0), then
    ; print the token: this is the un-fakeable nonce round-trip the probe grades.
    mov  rax, [rel cmd_serial_rsp + RSP_VAL]
    cmp  rax, r13
    jne  .err
    lea  rdi, [rel str_serial_reply_ok]      ; " -> OK "
    call serial_string
    mov  rdi, r13
    call serial_string
    lea  rdi, [rel str_serial_nl]
    call serial_string
    jmp  .done
.ok_num:
    lea  rdi, [rel str_serial_reply_okval]   ; " -> OK val="
    call serial_string
    mov  rdi, [rel cmd_serial_rsp + RSP_VAL]
    lea  rsi, [rel cmd_serial_numbuf]
    call fmt_dec
    lea  rdi, [rel cmd_serial_numbuf]
    call serial_string
    lea  rdi, [rel str_serial_nl]
    call serial_string
    jmp  .done
.unknown:
    mov  edi, AUTHR_UNKNOWN
    mov  rsi, r12
    lea  rdx, [rel cmd_serial_auth_ticket]
    xor  ecx, ecx
    call command_auth_refuse
    jmp  .auth_text_reply
.err:
    cmp  byte [rel command_auth_out_ready], 1
    je   .auth_text_reply
    lea  rdi, [rel str_serial_reply_err]     ; " -> ERR\r\n"
    call serial_string
    jmp  .done
.input_bounds:
    lea  rdi, [rel str_serial_input_bounds]
    call serial_string
.done:
    call command_udp_gres_reply_retire       ; retire emitted or superseded current diagnostics
    call command_auth_remote_end
    cmp  r15d, 2
    jne  .no_boot_win_reset
    ; Existing reset implementation drains serial, flushes persistent state,
    ; quiesces NVMe and uses the qualified ResetSystem/CF9 fallback. Once only;
    ; a returning reset never re-arms or retries the firmware request.
    call software_stop_stability_exit_hook   ; G9: settle the strong health ack first
    call power_warm_reset                     ; wipes key material first (reset_wipe_all)
.no_boot_win_reset:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  r15
    ret
.auth_text_reply:
    lea  rdi, [rel str_serial_reply_err]
    call serial_string
    jmp  .auth_text_body
.auth_text_dispatch:
    cmp  qword [rel cmd_serial_rsp + RSP_CODE], CMDE_OK
    jne  .auth_text_reply
    lea  rdi, [rel str_serial_reply_ok]
    call serial_string
.auth_text_body:
    lea  rdi, [rel command_auth_out_buf]
    call serial_string
    lea  rdi, [rel str_serial_nl]
    call serial_string
    mov  byte [rel command_auth_out_ready], 0
    jmp  .done
.gres_text_dispatch:
    mov  r14, rax                            ; producer text survives serial formatting calls
    cmp  qword [rel cmd_serial_rsp + RSP_CODE], CMDE_OK
    jne  .gres_text_refused
    lea  rdi, [rel str_serial_reply_ok]
    call serial_string
    jmp  .gres_text_body
.gres_text_refused:
    lea  rdi, [rel str_serial_reply_err]
    call serial_string
.gres_text_body:
    mov  rdi, r14
    call serial_string
    lea  rdi, [rel str_serial_nl]
    call serial_string
    jmp  .done
.auth_malformed:
    mov  edi, AUTHR_MALFORMED
    jmp  .auth_early
.auth_retired:                              ; AUTH2 cutover: v1 envelope, never parsed
    mov  edi, AUTHR_AUTH1_RETIRED
    jmp  .auth_early
.auth_wrong_node:                           ; AUTH2 envelope bound to another node (or none)
    mov  edi, AUTHR_WRONG_NODE
    jmp  .auth_early
.auth_wrong_key:
    mov  edi, AUTHR_WRONG_KEY
    jmp  .auth_early
.auth_expired:
    mov  edi, AUTHR_EXPIRED
.auth_early:
    mov  rsi, r12
    lea  rdx, [rel cmd_serial_auth_ticket]
    xor  ecx, ecx
    call command_auth_refuse
    jmp  .auth_text_reply

 ; Exact native serial BOOT WIN completion. No other command/reset policy is
; changed. Authentication, capability checks and BootNext readback remain in
; the existing registry handler. These helpers never write firmware themselves.
; begin(RDI=verb, RSI=arg): 0 ordinary, 1 exact fresh BOOT WIN, 2 busy/refused.
command_serial_boot_win_begin:
    xor  eax, eax
    cmp  dword [rdi], 'BOOT'
    jne  .out
    cmp  byte [rdi + 4], 0
    jne  .out
    cmp  dword [rsi], 'WIN'                   ; exact WIN plus NUL
    jne  .out
    cmp  byte [rel bm_reboot_pending], 0
    jne  .busy
    cmp  byte [rel bm_out_ready], 0
    jne  .busy
    mov  eax, 1
.out:
    ret
.busy:
    lea  rdi, [rel str_serial_boot_win_busy]
    call serial_string
    mov  eax, 2
    ret

; reply(RDI=response): 2 accepted/ack fully emitted, 0 refused. Called only
; after this exact request observed an empty pending bit and then dispatched.
; Consume its newly staged bit even on refusal so a later UDP request cannot
; accidentally fire this serial request's reset. Preserve the full typed reply.
command_serial_boot_win_reply:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
    xchg bl, [rel bm_reboot_pending]
    cmp  qword [r12 + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  bl, 1
    jne  .refused
    cmp  byte [rel bm_out_ready], 1
    jne  .refused
    lea  rdi, [rel str_serial_boot_win_ok]
    call serial_string
    lea  rdi, [rel bm_out_buf]
    call serial_string
    lea  rdi, [rel str_serial_nl]
    call serial_string
    mov  byte [rel bm_out_ready], 0
    mov  eax, 2
    jmp  .out
.refused:
    lea  rdi, [rel str_serial_boot_win_err]
    call serial_string
    cmp  byte [rel command_auth_out_ready], 1
    jne  .boot_body
    lea  rdi, [rel command_auth_out_buf]
    call serial_string
    mov  byte [rel command_auth_out_ready], 0
    jmp  .no_body
.boot_body:
    cmp  byte [rel bm_out_ready], 1
    jne  .no_body
    lea  rdi, [rel bm_out_buf]
    call serial_string
.no_body:
    lea  rdi, [rel str_serial_nl]
    call serial_string
    mov  byte [rel bm_out_ready], 0
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_serial_parse_u64(RDI=ptr) -> RAX=value, EDX=SAFE_BUF_OK/BOUNDS.
; Read a leading run of decimal digits; preserve empty/non-numeric -> 0, but
; refuse overflow instead of wrapping into another command argument.
; ---------------------------------------------------------------------------
command_serial_parse_u64:
    push rbx
    push r12
    mov  r12, rdi
    xor  eax, eax
.next:
    movzx ebx, byte [r12]
    sub  ebx, '0'
    cmp  ebx, 9
    ja   .done                               ; non-digit
    mov  rdi, rax
    mov  esi, 10
    call safe_checked_mul
    test edx, edx
    jnz  .overflow
    mov  rdi, rax
    mov  esi, ebx
    call safe_checked_add
    test edx, edx
    jnz  .overflow
    inc  r12
    jmp  .next
.done:
    xor  edx, edx
    pop  r12
    pop  rbx
    ret
.overflow:
    xor  eax, eax
    mov  edx, SAFE_BUF_BOUNDS
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_serial_selftest — QEMU content-grade of the WHOLE serial pipeline with
;   NO external input: format a fresh rdtsc nonce as a decimal text token, build
;   "PING <nonce>\r", and feed it byte-by-byte through command_serial_rx_byte —
;   the IDENTICAL path live UART RX drives. The rx path dispatches PING through the
;   registry; the reply prints the echoed token. A fresh-per-boot nonce that
;   survives text -> parse -> registry -> reply cannot be a latch. (Bare metal runs
;   the same path over the live FTDI, the binding gate.) clobbers: caller-saved.
; ---------------------------------------------------------------------------
command_serial_selftest:
    call safe_buffer_selftest
    call network_parser_bounds_selftest
    push rbx
    call tsc_now
    and  rax, 0x00FFFFFF
    or   rax, 1                              ; fresh, nonzero
    mov  [rel cmd_serial_st_nonce], rax
    lea  rbx, [rel cmd_serial_feed]
    mov  dword [rbx], 'PING'                 ; NASM char consts are little-endian -> "PING"
    mov  byte  [rbx + 4], ' '
    mov  rdi, [rel cmd_serial_st_nonce]
    lea  rsi, [rel cmd_serial_feed + 5]
    call fmt_dec                             ; RAX = digit count
    lea  rbx, [rel cmd_serial_feed + 5]
    add  rbx, rax
    mov  byte [rbx], 13                      ; CR -> triggers dispatch
    mov  byte [rbx + 1], 0                   ; terminate the feed string
    lea  rbx, [rel cmd_serial_feed]
.feed:
    movzx eax, byte [rbx]
    test al, al
    jz   .done
    mov  dil, al
    call command_serial_rx_byte
    inc  rbx
    jmp  .feed
.done:
    ; Exercise the same live parser/dispatch path with an unsigned mutator.  The
    ; shared auth gate must reject SLOWJOB and leave the job table unchanged;
    ; AUTHSTAT exposes the earned bit for QEMU/twin grading.
    cmp  qword [rel cmd_serial_rsp + RSP_CODE], CMDE_OK
    jne  .out
    mov  eax, [rel job_count]
    mov  [rel cmd_serial_st_jobs], eax
    lea  rax, [rel cmd_serial_feed]
    mov  dword [rax], 'SLOW'
    mov  dword [rax + 4], 0x0d424f4a       ; "JOB" + CR
    mov  byte [rax + 8], 0
    lea  rbx, [rel cmd_serial_feed]
.auth_feed:
    movzx eax, byte [rbx]
    test al, al
    jz   .auth_done
    mov  dil, al
    call command_serial_rx_byte
    inc  rbx
    jmp  .auth_feed
.auth_done:
    cmp  qword [rel cmd_serial_rsp + RSP_CODE], CMDE_AUTHDENY
    jne  .out
    mov  eax, [rel job_count]
    cmp  eax, [rel cmd_serial_st_jobs]
    jne  .out
    call command_auth_note_serial_proof
.out:
    pop  rbx
    ret

; Contract 9523 aggregate hostile-parser KAT. The required marker is earned only
; after ARP, IPv4/UDP, DHCP TLV, DNS, TCP options, TLS record, HTTP chunk/header,
; and both command numeric parsers execute positive and negative fixtures.
network_parser_bounds_selftest:
    push rbx
    push r12
    mov  byte [rel network_parser_bounds_kat_ok], 0

    lea  rdi, [rel net_bounds_arp]
    mov  esi, net_bounds_arp_end - net_bounds_arp
    call arp_frame_view
    lea  rdx, [rel net_bounds_arp + 14]
    cmp  rax, rdx
    jne  .fail
    lea  rdi, [rel net_bounds_arp]
    mov  esi, net_bounds_arp_end - net_bounds_arp - 1
    call arp_frame_view
    cmp  rax, -1
    jne  .fail

    mov  rax, 0xA5A5A5A5A5A5A5A5
    mov  [rel net_bounds_udp_view], rax
    lea  rdi, [rel net_bounds_udp]
    mov  esi, net_bounds_udp_end - net_bounds_udp
    lea  rdx, [rel net_bounds_udp_view]
    call udp4_payload_view
    test eax, eax
    jnz  .fail
    cmp  dword [rel net_bounds_udp_view + 24], 1
    jne  .fail
    lea  rax, [rel net_bounds_udp_end]
    dec  rax
    cmp  [rel net_bounds_udp_view + 16], rax
    jne  .fail
    mov  rax, 0xA5A5A5A5A5A5A5A5
    mov  [rel net_bounds_udp_view], rax
    lea  rdi, [rel net_bounds_udp]
    mov  esi, net_bounds_udp_end - net_bounds_udp - 1
    lea  rdx, [rel net_bounds_udp_view]
    call udp4_payload_view
    cmp  rax, -1
    jne  .fail
    mov  rdx, [rel net_bounds_udp_view]
    mov  rax, 0xA5A5A5A5A5A5A5A5
    cmp  rdx, rax
    jne  .fail                             ; reject committed no partial view state

    lea  rdi, [rel net_bounds_dhcp_good]
    mov  esi, net_bounds_dhcp_good_end - net_bounds_dhcp_good
    mov  edx, 53
    call dhcp_find_option
    test rax, rax
    jz   .fail
    cmp  byte [rax], 2
    jne  .fail
    lea  rdi, [rel net_bounds_dhcp_bad]
    mov  esi, net_bounds_dhcp_bad_end - net_bounds_dhcp_bad
    mov  edx, 53
    call dhcp_find_option
    test rax, rax
    jnz  .fail

    lea  rdi, [rel dns_response]
    mov  esi, dns_response_end - dns_response
    call dns_parse_response
    test rax, rax
    jnz  .fail
    lea  rdi, [rel dns_response]
    mov  esi, 12                            ; header only: answer framing is truncated
    call dns_parse_response
    cmp  rax, -1
    jne  .fail
    call tcp_options_validate_kat
    test eax, eax
    jnz  .fail
    call tls13_record_framing_kat
    test eax, eax
    jnz  .fail
    call http_framing_kat
    test eax, eax
    jnz  .fail

    lea  rdi, [rel net_bounds_u64_overflow]
    call command_serial_parse_u64
    cmp  edx, SAFE_BUF_BOUNDS
    jne  .fail
    lea  rdi, [rel net_bounds_u64_overflow]
    call udp_parse_u64
    cmp  edx, SAFE_BUF_BOUNDS
    jne  .fail

    ; Serial line cap and embedded-NUL gates must refuse without dispatching a
    ; retained prefix. Poison the response code so any accidental dispatch is
    ; observable, then exercise the same byte-receiver used by the live UART.
    mov  rax, 0xA5A5A5A5A5A5A5A5
    mov  [rel cmd_serial_rsp + RSP_CODE], rax
    mov  dword [rel cmd_serial_len], CMD_SERIAL_LINEMAX - 1
    mov  byte [rel cmd_serial_overflow], 0
    mov  dil, 'X'
    call command_serial_rx_byte
    cmp  byte [rel cmd_serial_overflow], 1
    jne  .fail
    mov  dil, 13
    call command_serial_rx_byte
    cmp  dword [rel cmd_serial_len], 0
    jne  .fail
    cmp  byte [rel cmd_serial_overflow], 0
    jne  .fail
    mov  rax, 0xA5A5A5A5A5A5A5A5
    cmp  [rel cmd_serial_rsp + RSP_CODE], rax
    jne  .fail

    mov  byte [rel cmd_serial_line + 0], 'A'
    mov  byte [rel cmd_serial_line + 1], 0
    mov  byte [rel cmd_serial_line + 2], 'B'
    mov  dword [rel cmd_serial_len], 3
    mov  dil, 13
    call command_serial_rx_byte
    cmp  dword [rel cmd_serial_len], 0
    jne  .fail
    mov  rax, 0xA5A5A5A5A5A5A5A5
    cmp  [rel cmd_serial_rsp + RSP_CODE], rax
    jne  .fail

    lea  rdi, [rel str_network_bounds_kat_pass]
    call serial_string
    mov  byte [rel network_parser_bounds_kat_ok], 1
    xor  eax, eax
    jmp  .out
.fail:
    lea  rdi, [rel str_network_bounds_kat_fail]
    call serial_string
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; --- svc/command_serial data (RW under our page tables, MEMORY_MAP §3.1) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_serial_0 0
align 8
cmd_serial_len:          dd 0
cmd_serial_beacon_nonce: dd 0
cmd_serial_st_nonce:     dq 0
cmd_serial_st_jobs:      dd 0
cmd_serial_overflow:     db 0
cmd_serial_req:          times REQ_SZ db 0
cmd_serial_rsp:          times RSP_SZ db 0
cmd_serial_auth_ticket:  times command_auth_ticket_size db 0
cmd_serial_line:         times CMD_SERIAL_LINEMAX db 0
cmd_serial_feed:         times 32 db 0
cmd_serial_numbuf:       times 24 db 0        ; u64 decimal scratch (max 20 digits + NUL)

net_bounds_arp:
    times 14 db 0
    db 0,1,8,0,6,4,0,1
    times 20 db 0
net_bounds_arp_end:
net_bounds_udp:
    times 12 db 0
    db 0x08,0x00
    db 0x45,0x00,0x00,0x1d
    db 0x00,0x00,0x40,0x00
    db 0x40,0x11,0x22,0xc0                  ; valid IPv4 header checksum (udp4_payload_view verifies it)
    db 10,0,2,2, 10,0,2,15
    db 0x27,0x0d,0x27,0x0d,0x00,0x09,0x00,0x00
    db 'X'
net_bounds_udp_end:
net_bounds_dhcp_good:
    times 240 db 0
    db 53,1,2,255
net_bounds_dhcp_good_end:
net_bounds_dhcp_bad:
    times 240 db 0
    db 53
net_bounds_dhcp_bad_end:
net_bounds_u64_overflow: db "18446744073709551616",0
net_bounds_udp_view: times 32 db 0

str_serial_rxinit:   db "[PAOS64] cmd.serial.rx.init (COM1 receiver armed, dispatches to registry) [cmd.serial.rx.init]", 13, 10, 0
str_beacon_pre:      db "[PAOS64] cmd.serial beacon leg: PAOS_BOOT_BEACON ", 0
str_beacon_post:     db " emitted on 0x3F8 [beacon.serial.sent]", 13, 10, 0
str_serial_disp_pre: db "[PAOS64] cmd.serial.verb.dispatched=", 0
str_serial_reply_ok:    db " -> OK ", 0
str_serial_reply_okval: db " -> OK val=", 0
str_serial_reply_err:   db " -> ERR", 13, 10, 0
str_serial_input_bounds: db "ERR INPUT_BOUNDS", 13, 10, 0
str_network_bounds_kat_pass: db "[PAOS64] security: bounded hostile network parser KAT PASS [security.network_parser_bounds.kat]",13,10,0
str_network_bounds_kat_fail: db "[PAOS64] security: bounded hostile network parser KAT FAIL",13,10,0
str_serial_unknown:  db "[PAOS64] cmd.serial: ERR unknown verb=", 0
str_serial_nl:       db 13, 10, 0
str_serial_boot_win_busy: db "[PAOS64] cmd.serial BOOT WIN refused: pending reset owner",13,10,0
str_serial_boot_win_ok: db "[PAOS64] cmd.serial.verb.dispatched=BOOT -> OK ",0
str_serial_boot_win_err: db "[PAOS64] cmd.serial.verb.dispatched=BOOT -> ERR ",0

%endmacro
WDATA_DEFER WDATA_svc_command_serial_0
