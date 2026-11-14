;; MODULE svc/command_web
;; LAYER 5
;; EXPORTS command_web_register, cmd_verb_webstruct
;; IMPORTS boot/header, svc/command, web/structured_data, web/light_extract, core/lib/sha256, core/lib/fmt, core/lib/str, net/http, net/tls13, net/dns
;; CAPS
;; OWNER saga:web_browser
; Task2701 diagnostic T0 observation adapter (WEBSTRUCT): it accepts caller
; bytes only and has no URL, guest, DNS, TCP, TLS, HTTP, timer or fetch path.
; The HTTPGET/HTTPSTAT/HTTPBODY verbs below DO fetch: HTTPGET opens TCP to a
; caller-chosen host:port and starts one HTTPS GET on net/tls13's single
; pinned application owner (lab public floor only, command_auth). The server is
; authenticated only by http_server_pin, the SHA-256 of its leaf certificate.
; While that pin is the all-zero placeholder, HTTPGET refuses (pin_unset) before
; any parse, TCP or TLS. The verb also refuses (tls_owner_busy), touching nothing,
; while another owner (net/notify_http) holds the TLS application session, and it
; closes and reopens only its own earlier session. The fetch tick acts (seal, flush,
; close) only while HTTPGET still owns the session: a notification that takes it
; over stops the fetch, and nothing of HTTPGET's is sent on the notification's
; session or closes it. A refused start releases the session it took.
; HTTPPIN <64 hex digits>|SHOW|CLEAR provisions/reads/revokes that exact leaf
; pin through the existing owner capability gate, in RAM for this boot only.
; A mutation refuses while any TLS app session or HTTP fetch is active. It
; opens no connection and does not obtain trust from the network it authenticates.

WEB_WIRE_INPUT_CAP equ 640
WEB_WIRE_HEX_CAP   equ WEB_WIRE_INPUT_CAP * 2
WEB_CMD_ARENA_CAP equ 1200
WEB_CMD_OUT_CAP   equ 1400

command_web_register:
    lea  rdi, [rel str_verb_webstruct]
    lea  rsi, [rel cmd_verb_webstruct]
    xor  edx, edx                       ; read-only T0 metadata
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

cmd_verb_webstruct:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r14, rsi                       ; response envelope
    mov  r12, [rdi + REQ_ARG]
    call web_cmd_reset
    test r12, r12
    jz   .malformed
    cmp  dword [r12], 'INFO'
    jne  .hex_check
    cmp  byte [r12 + 4], 0
    jne  .malformed
    lea  rdi, [rel str_web_info]
    call web_cmd_puts
    jmp  .ready
.hex_check:
    cmp  dword [r12], 'HEX '
    jne  .malformed
    add  r12, 4
    xor  r13d, r13d                     ; encoded char count
.validate:
    cmp  r13d, WEB_WIRE_HEX_CAP
    jae  .at_cap
    movzx eax, byte [r12 + r13]
    test al, al
    jz   .validated
    call web_hex_nibble
    test eax, eax
    js   .malformed
    inc  r13d
    jmp  .validate
.at_cap:
    cmp  byte [r12 + r13], 0
    jne  .bounds
.validated:
    test r13b, 1
    jnz  .malformed
    xor  ecx, ecx                       ; decoded index
    xor  edx, edx                       ; encoded index
.decode:
    cmp  edx, r13d
    jae  .decoded
    movzx eax, byte [r12 + rdx]
    call web_hex_nibble
    shl  eax, 4
    mov  r8d, eax
    movzx eax, byte [r12 + rdx + 1]
    call web_hex_nibble
    or   eax, r8d
    lea  r9, [rel web_cmd_input]
    mov  [r9 + rcx], al
    add  edx, 2
    inc  ecx
    jmp  .decode
.decoded:
    lea  rdi, [rel web_cmd_input]
    mov  esi, ecx
    lea  rdx, [rel web_cmd_arena]
    mov  ecx, WEB_CMD_ARENA_CAP
    call web_struct_extract
    test eax, eax
    jnz  .core_refused
    mov  r12, rdx                       ; used
    mov  r13, rcx                       ; records
    lea  rdi, [rel str_web_ok]
    call web_cmd_puts
    lea  rdi, [rel str_web_used]
    call web_cmd_puts
    mov  rdi, r12
    call web_cmd_putdec
    lea  rdi, [rel str_web_records]
    call web_cmd_puts
    mov  rdi, r13
    call web_cmd_putdec
    test r12, r12
    jz   .ready
    lea  rdi, [rel str_web_space]
    call web_cmd_puts
    lea  rdi, [rel web_cmd_arena]
    call web_cmd_puts
    jmp  .ready
.core_refused:
    cmp  eax, WEB_STRUCT_TRUNCATED
    je   .truncated
    cmp  eax, WEB_STRUCT_BOUNDS
    je   .bounds
    cmp  eax, WEB_STRUCT_TOO_MANY_FIELDS
    je   .too_many
    jmp  .malformed
.truncated:
    lea  rdi, [rel str_web_refused_truncated]
    call web_cmd_puts
    jmp  .ready
.bounds:
    lea  rdi, [rel str_web_refused_bounds]
    call web_cmd_puts
    jmp  .ready
.too_many:
    lea  rdi, [rel str_web_refused_too_many]
    call web_cmd_puts
    jmp  .ready
.malformed:
    lea  rdi, [rel str_web_refused_malformed]
    call web_cmd_puts
.ready:
    mov  byte [rel web_out_ready], 1
    mov  qword [r14 + RSP_CODE], CMDE_OK
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; AL=ASCII hex -> EAX nibble or -1.
web_hex_nibble:
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .upper
    cmp  al, 'f'
    jbe  .lower
.upper:
    cmp  al, 'A'
    jb   .bad
    cmp  al, 'F'
    ja   .bad
    sub  al, 'A' - 10
    movzx eax, al
    ret
.lower:
    sub  al, 'a' - 10
    movzx eax, al
    ret
.digit:
    sub  al, '0'
    movzx eax, al
    ret
.bad:
    mov  eax, -1
    ret

web_cmd_reset:
    lea  rax, [rel web_out_buf]
    mov  [rel web_out_cur], rax
    mov  byte [rax], 0
    ret

; RDI=safe cstr.  All callers are fixed literals or the bounded core arena.
web_cmd_puts:
    mov  rsi, [rel web_out_cur]
    lea  rdx, [rel web_out_buf + WEB_CMD_OUT_CAP]
.loop:
    movzx eax, byte [rdi]
    test al, al
    jz   .done
    lea  rcx, [rsi + 1]
    cmp  rcx, rdx
    jae  .done                          ; impossible under committed caps; stay NUL-safe
    mov  [rsi], al
    inc  rsi
    mov  byte [rsi], 0
    inc  rdi
    jmp  .loop
.done:
    mov  [rel web_out_cur], rsi
    ret

web_cmd_putdec:
    mov  rsi, [rel web_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel web_out_cur], rsi
    ret

align 8
web_out_ready: db 0
align 8
web_out_cur: dq 0
web_out_buf: times WEB_CMD_OUT_CAP db 0
web_cmd_input: times WEB_WIRE_INPUT_CAP db 0
web_cmd_arena: times WEB_CMD_ARENA_CAP db 0

str_verb_webstruct: db "WEBSTRUCT",0
str_web_info: db "webstruct=info wire_cap=640 core_cap=65536 fields_cap=16 name_cap=64 value_cap=256 table_rows_cap=16 table_columns_cap=16 form_controls_cap=16 images_cap=16 json_depth_cap=8",0
str_web_ok: db "webstruct=ok",0
str_web_used: db " used=",0
str_web_records: db " records=",0
str_web_space: db " ",0
str_web_refused_truncated: db "webstruct=refused reason=truncated",0
str_web_refused_bounds: db "webstruct=refused reason=bounds",0
str_web_refused_malformed: db "webstruct=refused reason=malformed",0
str_web_refused_too_many: db "webstruct=refused reason=too_many_fields",0

; ============================================================================
; Task1059 — HTTPGET / HTTPSTAT / HTTPBODY verb seam.
; HTTPGET parses a `https://host:port/path?query` URL, resolves the host, and
; kicks off an ASYNC fetch over the TLS 1.3 session (net/http streaming parser).
; The handshake + request send + response parse advance across command_udp_poll
; cycles (http_client_tick) driven by NIC RX; HTTPSTAT/HTTPBODY project the
; result. Those three retain cap=0/destr=0 and the lab public floor. HTTPPIN
; always requires MUTATE, including in the lab profile. A live fetch additionally
; needs a matching leaf certificate and supported TLS peer; host framing alone
; does not prove a wire fetch.
; ============================================================================

HTTP_URL_HOST_MAX equ 256
HTTP_URL_PATH_MAX equ 512
HTTP_CMD_OUT_CAP  equ 1400
HTTP_FETCH_TIMEOUT_MS equ 60000         ; one total budget: connect, TLS, flush and response

; RCQ-40 J3: the last fetch's outcome, latched when http_client_tick ends it.
; tls13_error is shared with notify_http's session, so NETCHECK reads this latch
; instead of the live byte. NETCHECK maps DONE..LOST in this order.
HTTP_FO_NONE       equ 0                 ; no fetch has ended since boot (read only while inactive)
HTTP_FO_DONE       equ 1
HTTP_FO_HTTP_ERROR equ 2
HTTP_FO_TLS_ERROR  equ 3                 ; http_fetch_tls_err holds the TLS13_ERR_* code
HTTP_FO_LOST       equ 4                 ; another owner took the TLS session
HTTP_FO_TIMEOUT    equ 5                 ; own pending fetch exhausted its total budget

command_http_register:
    lea  rdi, [rel str_verb_httpget]
    lea  rsi, [rel http_cmd_get]
    xor  edx, edx                       ; cap=0
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                          ; destr=0
    call command_register_verb
    cmp  eax, -1
    je   .out
    lea  rdi, [rel str_verb_httpstat]
    lea  rsi, [rel http_cmd_stat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .out
    lea  rdi, [rel str_verb_httpbody]
    lea  rsi, [rel http_cmd_body]
    xor  edx, edx
    mov  ecx, ARGT_TEXT                 ; optional exact DIGEST <format>; empty remains body
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .out
    lea  rdi, [rel str_verb_httppin]
    lea  rsi, [rel http_cmd_pin]
    mov  rdx, CMD_AUTH_CAP_MUTATE         ; also protects console/internal entry
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                          ; trust mutation, never a public query
    call command_register_verb
.out:
    ret

; HTTPPIN: exact SHA-256 leaf DER pin, supplied by the owner out of band.
; Decode completely on the stack before publishing. Dispatch is serialized;
; no callbacks/yields/network operations occur between validation and the copy.
; All-zero enrollment refuses; CLEAR explicitly restores HTTPGET's pin_unset.
http_cmd_pin:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 40                        ; 32-byte candidate / 3-byte hex output
    mov  rbx, rsi
    mov  r12, [rdi + REQ_ARG]
    mov  qword [rbx + RSP_ACCEPTED], 0
    test r12, r12
    jz   .bad
    cmp  byte [r12], 'S'
    jne  .clear_check
    cmp  byte [r12 + 1], 'H'
    jne  .bad
    cmp  byte [r12 + 2], 'O'
    jne  .bad
    cmp  byte [r12 + 3], 'W'
    jne  .bad
    cmp  byte [r12 + 4], 0
    jne  .bad
    jmp  .show
.clear_check:
    cmp  byte [r12], 'C'
    jne  .hex
    cmp  byte [r12 + 1], 'L'
    jne  .hex
    cmp  byte [r12 + 2], 'E'
    jne  .bad
    cmp  byte [r12 + 3], 'A'
    jne  .bad
    cmp  byte [r12 + 4], 'R'
    jne  .bad
    cmp  byte [r12 + 5], 0
    jne  .bad
    xor  eax, eax
    mov  [rsp], rax
    mov  [rsp + 8], rax
    mov  [rsp + 16], rax
    mov  [rsp + 24], rax
    jmp  .publish
.hex:
    xor  r13d, r13d
    xor  r14d, r14d
.decode:
    movzx eax, byte [r12 + r13*2]
    call web_hex_nibble
    test eax, eax
    js   .bad
    shl  eax, 4
    mov  r8d, eax
    movzx eax, byte [r12 + r13*2 + 1]
    call web_hex_nibble
    test eax, eax
    js   .bad
    or   eax, r8d
    mov  [rsp + r13], al
    or   r14d, eax
    inc  r13d
    cmp  r13d, 32
    jb   .decode
    cmp  byte [r12 + 64], 0
    jne  .bad
    test r14d, r14d
    jz   .zero
.publish:
    call tls13_app_owner
    test rax, rax
    jnz  .busy
    cmp  byte [rel http_fetch_active], 0
    jne  .busy
    lea  rdx, [rel http_server_pin]
    mov  rax, [rsp]
    mov  [rdx], rax
    mov  rax, [rsp + 8]
    mov  [rdx + 8], rax
    mov  rax, [rsp + 16]
    mov  [rdx + 16], rax
    mov  rax, [rsp + 24]
    mov  [rdx + 24], rax
    mov  qword [rbx + RSP_ACCEPTED], 1
.show:
    call http_cmd_reset
    lea  rdi, [rel http_str_pin_scope]
    call http_cmd_puts
    xor  r13d, r13d
.format:
    lea  rdx, [rel http_server_pin]
    movzx eax, byte [rdx + r13]
    mov  ecx, eax
    shr  eax, 4
    and  ecx, 15
    lea  rdx, [rel http_pin_digits]
    mov  al, [rdx + rax]
    mov  [rsp], al
    mov  al, [rdx + rcx]
    mov  [rsp + 1], al
    mov  byte [rsp + 2], 0
    mov  rdi, rsp
    call http_cmd_puts
    inc  r13d
    cmp  r13d, 32
    jb   .format
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .ready
.zero:
    lea  rdi, [rel http_str_pin_zero]
    jmp  .refuse
.busy:
    lea  rdi, [rel http_str_pin_busy]
    jmp  .refuse
.bad:
    lea  rdi, [rel http_str_pin_bad]
.refuse:
    mov  [rbx + RSP_HINT], rdi
    push rdi
    call http_cmd_reset
    pop  rdi
    call http_cmd_puts
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
.ready:
    mov  byte [rel http_cmd_out_ready], 1
    add  rsp, 40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; http_cmd_get — begin an async HTTPS GET. RDI=request, RSI=response.
http_cmd_get:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    ; RCQ-39-Fc: no outbound connection to a caller-chosen host while no
    ; certificate can authenticate it (the all-zero pin matches none).
    lea  rsi, [rel http_server_pin]
    xor  ecx, ecx
.pin_scan:
    cmp  byte [rsi + rcx], 0
    jne  .pin_set
    inc  ecx
    cmp  ecx, 32
    jb   .pin_scan
    lea  rdi, [rel http_str_refused_pin]
    jmp  .refuse
.pin_set:
    ; The TLS application session has one owner. Another owner's session
    ; (notify_http) is never closed or re-owned from here.
    call tls13_app_owner
    test rax, rax
    jz   .owner_free
    lea  rcx, [rel http_client_feed]
    cmp  rax, rcx
    je   .owner_free
    lea  rdi, [rel http_str_refused_busy]
    jmp  .refuse
.owner_free:
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad
    call http_url_parse
    test eax, eax
    jnz  .bad
    call http_build_connect_arg
    test eax, eax
    jnz  .bad
    call tls13_app_close                 ; drop our own prior session, if any
    call http_client_reset
    ; RCQ-40 J3 F1: http_client_reset zeroed http_status, so the previous
    ; fetch's outcome no longer describes it. A refused start then reads as
    ; no outcome (NETCHECK web=idle), never as the old fetch failing.
    mov  byte [rel http_fetch_outcome], HTTP_FO_NONE
    mov  rdi, [r12 + REQ_ARG]
    call http_digest_begin              ; retire old snapshot only after native reset
    lea  rdi, [rel http_connect_arg]
    lea  rsi, [rel http_server_pin]
    lea  rdx, [rel http_client_feed]
    call tls13_app_start
    test eax, eax                        ; EAX: 0 started, else refused (-1/-2/-3)
    jnz  .start_failed
    mov  byte [rel http_fetch_active], 1
    mov  byte [rel http_fetch_sent], 0
    call boot_ms_now
    mov  [rel http_fetch_started_ms], rax   ; RCQ-40 J3: NETCHECK's web age
    call http_stage_status
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .done
.start_failed:
    ; tls13_app_start took the owner before the connect failed: release it, or
    ; HTTPGET would keep the session until the next HTTPGET (owner checked
    ; above, so this session is ours). A fetch still marked active stops at
    ; its next tick, which finds no owner.
    call tls13_app_close
.bad:
    call http_stage_status
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    jmp  .done
.refuse:
    push rdi
    call http_cmd_reset
    mov  rdi, [rsp]
    call http_cmd_puts
    mov  byte [rel http_cmd_out_ready], 1
    pop  rdi
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  [rbx + RSP_HINT], rdi
.done:
    pop  r12
    pop  rbx
    ret

; http_cmd_stat — project last fetch: "status=<n> headers=<n> ... body=<text>".
http_cmd_stat:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call http_stage_status
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret

; http_cmd_body — project the decoded body text only.
http_cmd_body:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    mov  rdi, [rdi + REQ_ARG]
    mov  byte [rel http_cmd_out_ready], 0
    call http_digest_body_reply               ; empty argument keeps the original body projection
    pop  rbx
    ret

http_cmd_body_legacy:
    call http_cmd_reset
    lea  rdi, [rel http_body_buf]
    call http_cmd_puts
    mov  byte [rel http_cmd_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    ret

; http_client_tick — advance the async fetch. Called each command_udp_poll cycle.
; Idle (no active fetch) is a cheap early return. Sends the request ONCE the TLS
; session is established (trust_path==3); response bytes are delivered by the
; http_client_feed callback and finalize on DONE/ERROR/TLS-fail.
; Every step acts only while HTTPGET still owns the TLS application session.
; tls13_app_prepare/flush check only that someone owns it; if a notification
; took it over, the fetch stops here and touches nothing.
http_client_tick:
    cmp  byte [rel http_fetch_active], 1
    jne  .out
    call tls13_app_owner
    lea  rcx, [rel http_client_feed]
    cmp  rax, rcx
    jne  .lost
    ; A completed response or typed error wins over the wall-clock bound.
    ; Never expire or close a notification's session: owner checked above.
    cmp  byte [rel http_parse_state], HTTP_ST_DONE
    je   .finish
    cmp  byte [rel http_parse_state], HTTP_ST_ERROR
    je   .finish
    cmp  byte [rel tls13_error], 0
    jne  .finish
    call boot_ms_now
    sub  rax, [rel http_fetch_started_ms]
    jc   .timeout                       ; regressed clock cannot prolong ownership
    cmp  rax, HTTP_FETCH_TIMEOUT_MS
    jae  .timeout                       ; no progress/flush retry renews the budget
    cmp  byte [rel http_fetch_sent], 0
    jne  .after_send
    cmp  byte [rel tls13_established], 1
    jne  .check_err
    cmp  byte [rel tls13_trust_path], 3
    jne  .check_err
    call http_digest_request            ; join saved URL to bytes actually sent
    lea  rdi, [rel http_url_host]
    lea  rsi, [rel http_url_path]
    call http_build_request
    lea  rdi, [rel http_req_buf]
    mov  esi, [rel http_req_len]
    call tls13_app_prepare               ; seals ONE record (guarded, no reseal)
    test eax, eax                        ; EAX 0 sealed, -1 not ready
    jnz  .out                            ; not ready: retry next tick
    call tls13_app_flush
    test rax, rax
    jnz  .sealed                         ; backpressure: flush again next tick
    mov  byte [rel http_fetch_sent], 1
    jmp  .out
.sealed:
    mov  byte [rel http_fetch_sent], 2
    jmp  .out
.after_send:
    cmp  byte [rel http_fetch_sent], 2
    jne  .poll_resp
    call tls13_app_flush                 ; retry the paced flush
    test rax, rax
    jnz  .out
    mov  byte [rel http_fetch_sent], 1
.poll_resp:
    movzx eax, byte [rel http_parse_state]
    cmp  al, HTTP_ST_DONE
    je   .finish
    cmp  al, HTTP_ST_ERROR
    je   .finish
    jmp  .check_err
.check_err:
    cmp  byte [rel tls13_error], 0
    jne  .finish
    jmp  .out
.finish:
    mov  byte [rel http_fetch_outcome], HTTP_FO_DONE
    movzx eax, byte [rel http_parse_state]
    cmp  al, HTTP_ST_DONE
    je   .latched
    mov  byte [rel http_fetch_outcome], HTTP_FO_HTTP_ERROR
    cmp  al, HTTP_ST_ERROR
    je   .latched
    mov  byte [rel http_fetch_outcome], HTTP_FO_TLS_ERROR
    mov  al, [rel tls13_error]           ; ours: read before the session closes
    mov  [rel http_fetch_tls_err], al
    jmp  .latched
.timeout:
    mov  byte [rel http_error_reason], HTTP_ERR_TIMEOUT
    mov  byte [rel http_parse_state], HTTP_ST_ERROR
    mov  byte [rel http_fetch_outcome], HTTP_FO_TIMEOUT
.latched:
    call http_digest_finish             ; copy complete authenticated source before close
    call tls13_app_close                 ; ours: the owner was checked on entry
    jmp  .inactive
.lost:                                   ; another owner holds the session now
    call http_digest_clear
    mov  byte [rel http_fetch_outcome], HTTP_FO_LOST
.inactive:
    mov  byte [rel http_fetch_active], 0
.out:
    ret

; http_url_parse(RDI=url) -> RAX 0 ok / -1. Fills http_url_host/port/path.
http_url_parse:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    test rbx, rbx
    jz   .bad
    mov  rdi, rbx
    lea  rsi, [rel http_scheme_https]
    call http_ci_prefix
    test eax, eax
    jnz  .have_scheme
    mov  rdi, rbx
    lea  rsi, [rel http_scheme_http]
    call http_ci_prefix
    test eax, eax
    jz   .bad
.have_scheme:
    mov  rbx, rdi                        ; cursor after scheme
    lea  r12, [rel http_url_host]
    xor  r13d, r13d
.host_loop:
    mov  al, [rbx]
    test al, al
    je   .host_done
    cmp  al, ':'
    je   .host_done
    cmp  al, '/'
    je   .host_done
    cmp  r13d, HTTP_URL_HOST_MAX - 1
    jae  .bad
    mov  [r12 + r13], al
    inc  r13d
    inc  rbx
    jmp  .host_loop
.host_done:
    test r13d, r13d
    jz   .bad
    mov  byte [r12 + r13], 0
    mov  dword [rel http_url_port], 443
    cmp  byte [rbx], ':'
    jne  .path
    inc  rbx
    xor  eax, eax
    xor  ecx, ecx
.port_loop:
    movzx edx, byte [rbx]
    sub  edx, '0'
    cmp  edx, 9
    ja   .port_done
    imul eax, eax, 10
    add  eax, edx
    cmp  eax, 65535
    ja   .bad
    inc  rbx
    inc  ecx
    jmp  .port_loop
.port_done:
    test ecx, ecx
    jz   .bad
    test eax, eax
    jz   .bad
    mov  [rel http_url_port], eax
.path:
    lea  r12, [rel http_url_path]
    cmp  byte [rbx], '/'
    je   .path_copy
    mov  word [r12], '/'                 ; '/' + NUL
    jmp  .ok
.path_copy:
    xor  r13d, r13d
.path_loop:
    mov  al, [rbx]
    test al, al
    je   .path_end
    cmp  r13d, HTTP_URL_PATH_MAX - 1
    jae  .path_end
    mov  [r12 + r13], al
    inc  r13d
    inc  rbx
    jmp  .path_loop
.path_end:
    mov  byte [r12 + r13], 0
.ok:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; http_is_dotted_quad(RDI=cstr) -> RAX 1 if a bare A.B.C.D (each 0-255), else 0.
http_is_dotted_quad:
    push rbx
    mov  rbx, rdi
    xor  r8d, r8d                        ; component index
.comp:
    xor  eax, eax
    xor  ecx, ecx                        ; digit count
.dig:
    movzx edx, byte [rbx]
    sub  edx, '0'
    cmp  edx, 9
    ja   .comp_done
    imul eax, eax, 10
    add  eax, edx
    cmp  eax, 255
    ja   .no
    inc  rbx
    inc  ecx
    cmp  ecx, 3
    ja   .no
    jmp  .dig
.comp_done:
    test ecx, ecx
    jz   .no
    cmp  r8d, 3
    je   .last
    cmp  byte [rbx], '.'
    jne  .no
    inc  rbx
    inc  r8d
    jmp  .comp
.last:
    cmp  byte [rbx], 0
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; http_fmt_ipv4(RDI=dst) — dotted-decimal of the four octets in http_ip_wire.
http_fmt_ipv4:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    lea  r12, [rel http_ip_wire]
    xor  r13d, r13d
.oct:
    movzx edi, byte [r12 + r13]
    mov  rsi, rbx
    call fmt_dec
    add  rbx, rax
    inc  r13d
    cmp  r13d, 4
    jae  .done
    mov  byte [rbx], '.'
    inc  rbx
    jmp  .oct
.done:
    mov  byte [rbx], 0
    pop  r13
    pop  r12
    pop  rbx
    ret

; http_resolve_ip -> RAX 0 ok (dotted quad in http_ip_text) / -1. IP literals
; pass straight through; names go through the DNS cache (async miss kicks a
; lookup and fails this attempt, so the caller retries).
http_resolve_ip:
    lea  rdi, [rel http_url_host]
    call http_is_dotted_quad
    test eax, eax
    jz   .try_dns
    lea  rdi, [rel http_ip_text]
    lea  rsi, [rel http_url_host]
    mov  edx, 16
    call strcpy_s
    xor  eax, eax
    ret
.try_dns:
    lea  rdi, [rel http_url_host]
    call dns_cache_get                   ; EAX=DNS_LOOKUP_*, EDX=wire IPv4
    cmp  eax, DNS_LOOKUP_A
    jne  .kick
    mov  [rel http_ip_wire], edx
    lea  rdi, [rel http_ip_text]
    call http_fmt_ipv4
    xor  eax, eax
    ret
.kick:
    lea  rdi, [rel http_url_host]
    call dns_resolve_start
    mov  eax, -1
    ret

; http_build_connect_arg -> RAX 0 ok / -1. "ip:port sni" for tls13_app_start.
http_build_connect_arg:
    push rbx
    call http_resolve_ip
    test eax, eax
    jnz  .bad
    lea  rbx, [rel http_connect_arg]
    lea  rdi, [rel http_ip_text]
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    mov  byte [rbx], ':'
    inc  rbx
    mov  edi, [rel http_url_port]
    mov  rsi, rbx
    call fmt_dec
    add  rbx, rax
    mov  byte [rbx], ' '
    inc  rbx
    lea  rdi, [rel http_url_host]
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    mov  byte [rbx], 0
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret

; --- reply staging (mirrors web_cmd_*) ---
http_stage_status:
    call http_cmd_reset
    lea  rdi, [rel http_str_status]
    call http_cmd_puts
    mov  edi, [rel http_status]
    call http_cmd_putdec
    lea  rdi, [rel http_str_headers]
    call http_cmd_puts
    mov  edi, [rel http_header_count]
    call http_cmd_putdec
    lea  rdi, [rel http_str_clen]
    call http_cmd_puts
    mov  edi, [rel http_content_length]
    call http_cmd_putdec
    lea  rdi, [rel http_str_blen]
    call http_cmd_puts
    mov  edi, [rel http_body_len]
    call http_cmd_putdec
    lea  rdi, [rel http_str_parse_state]
    call http_cmd_puts
    movzx edi, byte [rel http_parse_state]
    call http_cmd_putdec
    lea  rdi, [rel http_str_framing_error]
    call http_cmd_puts
    movzx edi, byte [rel http_error_reason]
    call http_cmd_putdec
    lea  rdi, [rel http_str_framing]
    call http_cmd_puts
    movzx edi, byte [rel http_phase]
    call http_cmd_putdec
    lea  rdi, [rel http_str_cl_present]
    call http_cmd_puts
    movzx edi, byte [rel http_cl_present]
    call http_cmd_putdec
    lea  rdi, [rel http_str_declared]
    call http_cmd_puts
    mov  rdi, [rel http_declared_length]
    call http_cmd_putdec
    lea  rdi, [rel http_str_eof]
    call http_cmd_puts
    movzx edi, byte [rel http_eof_seen]
    call http_cmd_putdec
    lea  rdi, [rel http_str_body]
    call http_cmd_puts
    lea  rdi, [rel http_body_buf]
    call http_cmd_puts
    mov  byte [rel http_cmd_out_ready], 1
    ret

http_cmd_reset:
    lea  rax, [rel http_cmd_out_buf]
    mov  [rel http_cmd_out_cur], rax
    mov  byte [rax], 0
    ret

; RDI=safe cstr. Bounded append into the reply buffer.
http_cmd_puts:
    mov  rsi, [rel http_cmd_out_cur]
    lea  rdx, [rel http_cmd_out_buf + HTTP_CMD_OUT_CAP]
.loop:
    movzx eax, byte [rdi]
    test al, al
    jz   .done
    lea  rcx, [rsi + 1]
    cmp  rcx, rdx
    jae  .done
    mov  [rsi], al
    inc  rsi
    mov  byte [rsi], 0
    inc  rdi
    jmp  .loop
.done:
    mov  [rel http_cmd_out_cur], rsi
    ret

http_cmd_putdec:
    mov  rsi, [rel http_cmd_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel http_cmd_out_cur], rsi
    ret

align 8
http_cmd_out_ready: db 0
http_fetch_active:  db 0
http_fetch_sent:    db 0
http_fetch_outcome: db HTTP_FO_NONE      ; RCQ-40 J3 (see HTTP_FO_*)
http_fetch_tls_err: db 0
align 8
http_cmd_out_cur:   dq 0
http_fetch_started_ms: dq 0              ; RCQ-40 J3: ms when the last fetch started
http_url_port:      dd 0
http_ip_wire:       dd 0
http_cmd_out_buf:   times HTTP_CMD_OUT_CAP db 0
http_url_host:      times HTTP_URL_HOST_MAX db 0
http_url_path:      times HTTP_URL_PATH_MAX db 0
http_connect_arg:   times 320 db 0
http_ip_text:       times 20 db 0
http_server_pin:    times 32 db 0        ; owner-provisioned HTTPPIN; boot-local/unset

str_verb_httpget:  db "HTTPGET",0
str_verb_httpstat: db "HTTPSTAT",0
str_verb_httpbody: db "HTTPBODY",0
str_verb_httppin:  db "HTTPPIN",0
http_pin_digits: db "0123456789abcdef",0
http_str_pin_scope: db "HTTPPIN scope=boot sha256=",0
http_str_pin_bad: db "REFUSED pin_format expected=64hex|SHOW|CLEAR",0
http_str_pin_zero: db "REFUSED pin_zero use=CLEAR",0
http_str_pin_busy: db "REFUSED pin_busy",0
http_scheme_https: db "https://",0
http_scheme_http:  db "http://",0
http_str_parse_state: db " state=",0
http_str_framing_error: db " framing_error=",0
http_str_framing: db " framing=",0
http_str_cl_present: db " cl_present=",0
http_str_declared: db " declared=",0
http_str_eof: db " eof=",0
http_str_status:   db "status=",0
http_str_refused_pin:  db "REFUSED pin_unset",0
http_str_refused_busy: db "REFUSED tls_owner_busy",0
http_str_headers:  db " headers=",0
http_str_clen:     db " clen=",0
http_str_blen:     db " blen=",0
http_str_body:     db " body=",0

; RCQ49_DIGEST_HELPERS_BEGIN (actual source block used by inert link fixtures)
; Read-only saved-fetch projection; no transport, trust or command producer.
; Snapshot states: 0 absent, 1 accepted URL, 2 exact request joined, 3 complete.
; All helpers preserve callee-saved registers. Dispatch/tick are BSP serialized.
http_digest_clear:
    lea rdi, [rel http_digest_state_begin]
    mov ecx, http_digest_state_end-http_digest_state_begin
    xor eax, eax
    rep stosb
    ret

; RDI=original URL, after native parser/reset and before TLS start. Only the
; exact HTTPS/no-credential/no-query small URL subset is digest-eligible.
; Refusal affects this projection alone; original HTTPGET behavior is retained.
http_digest_begin:
    push rdi
    call http_digest_clear
    pop rsi
    test rsi, rsi
    jz .out
    cmp dword [rsi], 'http'
    jne .out
    cmp dword [rsi+4], 's://'
    jne .out
    mov r8d, 8                         ; total URL byte count
    xor r9d, r9d                       ; host label length
    xor r10d, r10d                     ; host length
.host:
    cmp r8d, 192
    jae .out
    movzx eax, byte [rsi+r8]
    cmp al, '/'
    je .host_end
    test al, al
    jz .out                            ; explicit path required
    cmp al, '.'
    je .dot
    cmp al, '-'
    je .hyphen
    cmp al, 'a'
    jb .digit
    cmp al, 'z'
    jbe .host_char
.digit:
    cmp al, '0'
    jb .out
    cmp al, '9'
    ja .out
    jmp .host_char
.hyphen:
    test r9d, r9d
    jz .out
    jmp .host_char
.dot:
    test r9d, r9d
    jz .out
    cmp byte [rsi+r8-1], '-'
    je .out
    xor r9d, r9d
    jmp .host_next
.host_char:
    inc r9d
    cmp r9d, 63
    ja .out
.host_next:
    inc r8d
    inc r10d
    jmp .host
.host_end:
    test r9d, r9d
    jz .out
    cmp byte [rsi+r8-1], '-'
    je .out
    mov [rel http_digest_host_len], r10d
    mov [rel http_digest_path_offset], r8d
.path:
    cmp r8d, 192
    ja .out
    movzx eax, byte [rsi+r8]
    test al, al
    jz .copy
    cmp al, '/'
    je .path_next
    cmp al, '.'
    je .path_next
    cmp al, '-'
    je .path_next
    cmp al, '_'
    je .path_next
    cmp al, '~'
    je .path_next
    cmp al, '0'
    jb .out
    cmp al, '9'
    jbe .path_next
    cmp al, 'A'
    jb .out
    cmp al, 'Z'
    jbe .path_next
    cmp al, 'a'
    jb .out
    cmp al, 'z'
    ja .out
.path_next:
    inc r8d
    jmp .path
.copy:
    lea rdi, [rel http_digest_url]
    mov ecx, r8d
    inc ecx                            ; include NUL
    rep movsb
    mov byte [rel http_digest_state], 1
.out:
    ret

; Verify original URL against the actual native host/path at request construction.
; Failed HTTPGET parses can change those native globals while an old fetch is
; pending. Such a fetch cannot inherit the original URL's provenance.
http_digest_request:
    cmp byte [rel http_digest_state], 1
    jne .out
    lea rsi, [rel http_digest_url+8]
    lea rdi, [rel http_url_host]
    mov ecx, [rel http_digest_host_len]
    repe cmpsb
    jne http_digest_clear
    cmp byte [rdi], 0
    jne http_digest_clear
    lea rsi, [rel http_digest_url]
    mov eax, [rel http_digest_path_offset]
    add rsi, rax
    lea rdi, [rel http_url_path]
.path:
    mov al, [rsi]
    cmp al, [rdi]
    jne http_digest_clear
    inc rsi
    inc rdi
    test al, al
    jnz .path
    mov byte [rel http_digest_state], 2
.out:
    ret

; Called with HTTP's TLS ownership already checked, before its native close.
http_digest_finish:
    cmp byte [rel http_digest_state], 2
    jne http_digest_clear
    cmp byte [rel http_fetch_outcome], HTTP_FO_DONE
    jne http_digest_clear
    cmp byte [rel http_parse_state], HTTP_ST_DONE
    jne http_digest_clear
    cmp byte [rel http_fetch_sent], 1
    jne http_digest_clear
    cmp byte [rel tls13_error], 0
    jne http_digest_clear
    cmp byte [rel tls13_established], 1
    jne http_digest_clear
    cmp byte [rel tls13_trust_path], 3
    jne http_digest_clear
    cmp dword [rel http_status], 200
    jb http_digest_clear
    cmp dword [rel http_status], 299
    ja http_digest_clear
    mov ecx, [rel http_body_len]
    cmp ecx, 1024
    ja http_digest_clear
    mov [rel http_digest_body_len], ecx
    lea rdi, [rel http_digest_body]
    lea rsi, [rel http_body_buf]
    rep movsb
    mov byte [rdi], 0
    lea rdi, [rel http_digest_pin]
    lea rsi, [rel http_server_pin]
    mov ecx, 32
    rep movsb
    mov rax, [rel http_fetch_started_ms]
    mov [rel http_digest_started_ms], rax
    mov eax, [rel http_status]
    mov [rel http_digest_status], eax
    call boot_ms_now
    cmp rax, [rel http_digest_started_ms]
    jb http_digest_clear
    mov [rel http_digest_finished_ms], rax
    lea rdi, [rel http_digest_sha]
    lea rsi, [rel http_digest_body]
    mov edx, [rel http_digest_body_len]
    call sha256_hash
    test eax, eax
    jnz http_digest_clear
    mov byte [rel http_digest_state], 3
    ret

; RDI=HTTPBODY argument, RBX=response. No new verb or authority entry.
http_digest_body_reply:
    test rdi, rdi
    jz http_cmd_body_legacy
    cmp byte [rdi], 0
    je http_cmd_body_legacy
    push r12
    mov r12, rdi
    call http_cmd_reset
    call http_digest_scratch_clear
    ; Bytewise prefix: short NUL-terminated args cannot be overread.
    lea rsi, [rel http_digest_prefix]
.prefix:
    mov al, [rsi]
    test al, al
    jz .selector
    cmp al, [r12]
    jne .bad
    inc rsi
    inc r12
    jmp .prefix
.selector:
    xor r8d, r8d
    lea rsi, [rel http_digest_formats]
.next_format:
    mov rdi, r12
.compare:
    mov al, [rsi]
    cmp al, [rdi]
    jne .skip
    inc rsi
    inc rdi
    test al, al
    jnz .compare
    jmp .selected
.skip:
    cmp byte [rsi], 0
    je .advance
    inc rsi
    jmp .skip
.advance:
    inc rsi
    inc r8d
    cmp r8d, 4
    jb .next_format
    jmp .bad
.selected:
    mov r12d, r8d
    cmp byte [rel http_digest_state], 3
    jne .unavailable
    cmp byte [rel http_fetch_active], 0
    jne .unavailable
    lea rdi, [rel http_digest_body]
    mov esi, [rel http_digest_body_len]
    lea rdx, [rel http_digest_text]
    mov ecx, 769                       ; max 768 emitted, no clipped success
    call web_light_extract
    test eax, eax
    jnz .parser_refused
    mov [rel http_digest_text_len], edx
    lea rdi, [rel http_digest_header]
    call http_cmd_puts
    mov rdi, [rel http_digest_started_ms]
    call http_cmd_putdec
    lea rdi, [rel http_digest_end_time]
    call http_cmd_puts
    mov rdi, [rel http_digest_finished_ms]
    call http_cmd_putdec
    lea rdi, [rel http_digest_status_label]
    call http_cmd_puts
    mov edi, [rel http_digest_status]
    call http_cmd_putdec
    lea rdi, [rel http_digest_url_label]
    call http_cmd_puts
    lea rdi, [rel http_digest_url]
    call http_cmd_puts
    lea rdi, [rel http_digest_bytes_label]
    call http_cmd_puts
    mov edi, [rel http_digest_body_len]
    call http_cmd_putdec
    lea rdi, [rel http_digest_sha_label]
    call http_cmd_puts
    lea rdi, [rel http_digest_sha]
    call http_digest_hex32
    lea rdi, [rel http_digest_pin_label]
    call http_cmd_puts
    lea rdi, [rel http_digest_pin]
    call http_digest_hex32
    lea rdi, [rel http_digest_format_label]
    call http_cmd_puts
    lea rdi, [rel http_digest_formats]
    mov eax, r12d
.format_name:
    test eax, eax
    jz .put_format
.seek_zero:
    cmp byte [rdi], 0
    je .zero
    inc rdi
    jmp .seek_zero
.zero:
    inc rdi
    dec eax
    jmp .format_name
.put_format:
    call http_cmd_puts
    lea rdi, [rel http_digest_text_len_label]
    call http_cmd_puts
    mov edi, [rel http_digest_text_len]
    call http_cmd_putdec
    lea rdi, [rel http_digest_text_label]
    call http_cmd_puts
    lea rdi, [rel http_digest_text]
    call http_cmd_puts
    call http_digest_scratch_clear
    mov qword [rbx+RSP_CODE], CMDE_OK
    jmp .ready
.bad:
    lea rdi, [rel http_digest_bad]
    jmp .refuse
.unavailable:
    lea rdi, [rel http_digest_unavailable]
    jmp .refuse
.parser_refused:
    lea rdi, [rel http_digest_parse_bad]
.refuse:
    push rdi
    call http_cmd_reset
    call http_digest_scratch_clear
    pop rdi
    call http_cmd_puts
    mov qword [rbx+RSP_CODE], CMDE_BADARG
.ready:
    mov byte [rel http_cmd_out_ready], 1
    pop r12
    ret
http_digest_scratch_clear:
    lea rdi, [rel http_digest_text]
    mov ecx, 769
    xor eax, eax
    rep stosb
    mov dword [rel http_digest_text_len], 0
    ret

; Format through the canonical native formatter, not a second hex primitive.
http_digest_hex32:
    push r12
    push r13
    sub rsp, 24
    mov r12, rdi
    xor r13d, r13d
.next:
    movzx edi, byte [r12+r13]
    mov rsi, rsp
    mov edx, 2
    call fmt_hex
    mov rdi, rsp
    call http_cmd_puts
    inc r13d
    cmp r13d, 32
    jb .next
    add rsp, 24
    pop r13
    pop r12
    ret
; RCQ49_DIGEST_HELPERS_END

; RCQ49_DIGEST_DATA_BEGIN
align 8
http_digest_state_begin:
http_digest_state: db 0
align 8
http_digest_started_ms: dq 0
http_digest_finished_ms: dq 0
http_digest_status: dd 0
http_digest_body_len: dd 0
http_digest_host_len: dd 0
http_digest_path_offset: dd 0
http_digest_text_len: dd 0
http_digest_url: times 193 db 0
http_digest_sha: times 32 db 0
http_digest_pin: times 32 db 0
http_digest_body: times 1025 db 0
http_digest_text: times 769 db 0
http_digest_state_end:
http_digest_prefix: db 'DIGEST ',0
http_digest_formats: db 'TEXT',0,'HTML',0,'FEED',0,'JSON',0
http_digest_header: db 'digest=v1 source=[1] origin=native-https trust=leaf-pin model=none clock=boot-ms started_ms=',0
http_digest_end_time: db ' finished_ms=',0
http_digest_status_label: db ' status=',0
http_digest_url_label: db ' url=',0
http_digest_bytes_label: db ' body_bytes=',0
http_digest_sha_label: db ' body_sha256=',0
http_digest_pin_label: db ' pin_sha256=',0
http_digest_format_label: db ' format=',0
http_digest_text_len_label: db ' text_bytes=',0
http_digest_text_label: db ' text=',0
http_digest_bad: db 'digest=refused reason=syntax expected=DIGEST_TEXT|HTML|FEED|JSON',0
http_digest_unavailable: db 'digest=refused reason=no_complete_native_https_source',0
http_digest_parse_bad: db 'digest=refused reason=unsupported_or_malformed_or_oversized_text',0
; RCQ49_DIGEST_DATA_END
