;; MODULE net/notify_http
;; LAYER 4
;; EXPORTS notify_http_start, notify_http_tick, notify_http_cancel, notify_http_state, notify_http_fail_phase, notify_http_tls_state, notify_http_tls_error, notify_http_tcp_connected, notify_http_tls_records, notify_http_tls_handshakes, notify_http_tls_last_record, notify_http_tls_last_handshake
;; IMPORTS net/tls13, net/http, net/dns, core/time, core/lib/str, core/lib/fmt, core/lib/mem
;; CAPS
;; OWNER saga:login_surfaces
; The one outbound notification seam. Fixed bounded POST over the existing
; asynchronous DNS/TCP/TLS engine. No worker, network stack, redirect, retry
; carousel or plaintext transport. Exact leaf pin + CertificateVerify + Finished
; must succeed before an endpoint token or challenge is sent.
; RDI=validated policy record (layout in config/keep_config), RSI=code32,
; EDX=method (1 two-factor, 2 reset, 3 passwordless).
; States: 0 idle, 1 DNS, 2 TLS, 3 queued, 4 response, 5 delivered, 6 unreachable.
NF_BUDGET_MS equ 12000
NF_RESPONSE_BUDGET_MS equ 6000
NF_REQ_CAP equ 1100
NF_RX_CAP equ 4096
notify_http_start:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx
    call tls13_app_close                 ; a notification takes the session from any owner
    call notify_http_cancel
    mov byte [rel notify_http_fail_phase], 0
    mov byte [rel notify_http_tls_state], 0
    mov byte [rel notify_http_tls_error], 0
    mov byte [rel notify_http_tcp_connected], 0
    mov byte [rel notify_http_tls_last_record], 0
    mov byte [rel notify_http_tls_last_handshake], 0
    mov dword [rel notify_http_tls_records], 0
    mov dword [rel notify_http_tls_handshakes], 0
    mov al, [rbx + 1]
    mov [rel nf_provider], al
    mov ax, [rbx + 2]
    mov [rel nf_port], ax
    lea rdi, [rel nf_host]
    lea rsi, [rbx + 8]
    mov edx, 96
    call strcpy_s
    lea rdi, [rel nf_pin]
    lea rsi, [rbx + 360]
    mov edx, 32
    call memcpy
    ; Opaque code is the only variable payload. No caller text enters it.
    lea rdi, [rel nf_body]
    lea rsi, [rel nf_body_ntfy]
    cmp byte [rel nf_provider], 1
    je .prefix
    lea rsi, [rel nf_body_gotify]
.prefix:
    mov edx, 160
    call strcpy_s
.body_append:
    lea rdi, [rel nf_body]
    call strlen
    lea rdi, [rel nf_body]
    add rdi, rax
    mov rsi, r12
    mov edx, 32
    call memcpy
    mov byte [rdi], 0
    ; memcpy's RDI is advanced by the primitive; use strlen for the suffix.
    cmp byte [rel nf_provider], 1
    je .body_done
    lea rdi, [rel nf_body]
    call strlen
    lea rdi, [rel nf_body]
    add rdi, rax
    lea rsi, [rel nf_body_suffix]
    mov edx, 16
    call strcpy_s
.body_done:
    mov dword [rel nf_req_len], 0
    mov byte [rel nf_build_bad], 0
    lea rdi, [rel nf_post]
    call nf_put
    lea rdi, [rbx + 104]
    call nf_put
    lea rdi, [rel nf_http]
    call nf_put
    lea rdi, [rel nf_host]
    call nf_put
    lea rdi, [rel nf_colon]
    call nf_put
    movzx edi, word [rel nf_port]
    lea rsi, [rel nf_num]
    call fmt_dec
    lea rdi, [rel nf_num]
    call nf_put
    lea rdi, [rel nf_content]
    call nf_put
    lea rdi, [rel nf_text_type]
    cmp byte [rel nf_provider], 1
    je .type
    lea rdi, [rel nf_json_type]
.type:
    call nf_put
    cmp byte [rbx + 232], 0
    je .length
    lea rdi, [rel nf_bearer]
    cmp byte [rel nf_provider], 1
    je .auth
    lea rdi, [rel nf_gotify_key]
.auth:
    call nf_put
    lea rdi, [rbx + 232]
    call nf_put
.length:
    lea rdi, [rel nf_length]
    call nf_put
    lea rdi, [rel nf_body]
    call strlen
    mov rdi, rax
    lea rsi, [rel nf_num]
    call fmt_dec
    lea rdi, [rel nf_num]
    call nf_put
    lea rdi, [rel nf_end]
    call nf_put
    lea rdi, [rel nf_body]
    call nf_put
    cmp byte [rel nf_build_bad], 0
    jne .bad
    call boot_ms_now
    add rax, NF_BUDGET_MS
    mov [rel nf_deadline], rax
    mov byte [rel notify_http_state], 1
    ; Literal IPv4 skips DNS; names use the existing resolver/cache. Reuse the
    ; TLS connect parser's bounded IPv4 conversion, not a second IP parser.
    call nf_connect_text
    lea rdi, [rel nf_connect]
    call tls13_parse_connect_arg
    cmp eax, -1
    jne .connect
    lea rdi, [rel nf_host]
    call dns_resolve_start
    cmp eax, DNS_LOOKUP_A
    je .ok
    cmp eax, DNS_LOOKUP_PENDING
    jne .bad
    jmp .ok
.connect:
    call nf_tls_start
    test eax, eax
    jnz .bad
.ok:
    xor eax, eax
    jmp .out
.bad:
    call nf_latch_failure
    call notify_http_cancel
    mov byte [rel notify_http_state], 6
    mov eax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Append validated strings to the bounded request. Overflow poisons the build.
nf_put:
    push rbx
    mov rbx, rdi
    call strlen
    mov edx, [rel nf_req_len]
    add rax, rdx
    cmp rax, NF_REQ_CAP - 1
    ja .bad
    lea rdi, [rel nf_request]
    add rdi, rdx
    mov rsi, rbx
    mov edx, NF_REQ_CAP
    sub edx, [rel nf_req_len]
    call strcpy_s
    add [rel nf_req_len], eax
    pop rbx
    ret
.bad:
    mov byte [rel nf_build_bad], 1
    pop rbx
    ret

; Build literal connect arg from nf_address if set, else the original host.
nf_connect_text:
    push rbx
    lea rdi, [rel nf_connect]
    lea rsi, [rel nf_host]
    cmp byte [rel nf_address], 0
    je .copy
    lea rsi, [rel nf_address]
.copy:
    mov edx, 240
    call strcpy_s
    lea rbx, [rel nf_connect]
    add rbx, rax
    mov byte [rbx], ':'
    inc rbx
    movzx edi, word [rel nf_port]
    mov rsi, rbx
    call fmt_dec
    add rbx, rax
    mov byte [rbx], ' '
    inc rbx
    mov rdi, rbx
    lea rsi, [rel nf_host]
    mov edx, 96
    call strcpy_s
    pop rbx
    ret

nf_tls_start:
    lea rdi, [rel nf_connect]
    lea rsi, [rel nf_pin]
    lea rdx, [rel nf_receive]
    call tls13_app_start
    test eax, eax
    jnz .out
    mov byte [rel notify_http_state], 2
.out:
    ret

notify_http_tick:
    push rbx
    push r12
    movzx ebx, byte [rel notify_http_state]
    test ebx, ebx
    jz .out
    cmp ebx, 5
    jae .out
    call boot_ms_now
    cmp rax, [rel nf_deadline]
    jae .bad
    cmp ebx, 1
    je .dns
    cmp byte [rel tls13_state], TLS13_ST_FAILED
    je .bad
    cmp ebx, 2
    je .tls
    cmp ebx, 3
    je .send
    jmp .out
.dns:
    lea rdi, [rel nf_host]
    call dns_cache_get
    cmp eax, DNS_LOOKUP_PENDING
    je .out
    cmp eax, DNS_LOOKUP_A
    jne .bad
    mov r12d, edx
    lea rbx, [rel nf_address]
    xor ecx, ecx
.octet:
    push rcx
    movzx edi, r12b
    mov rsi, rbx
    call fmt_dec
    add rbx, rax
    shr r12d, 8
    pop rcx
    inc ecx
    cmp ecx, 4
    je .address_done
    mov byte [rbx], '.'
    inc rbx
    jmp .octet
.address_done:
    call nf_connect_text
    call nf_tls_start
    test eax, eax
    jnz .bad
    jmp .out
.tls:
    cmp byte [rel tls13_established], 1
    jne .out
    lea rdi, [rel nf_request]
    mov esi, [rel nf_req_len]
    call tls13_app_prepare
    test eax, eax
    jnz .bad
    lea rdi, [rel nf_request]
    xor esi, esi
    mov edx, NF_REQ_CAP
    call memset
    lea rdi, [rel nf_body]
    xor esi, esi
    mov edx, 160
    call memset
    mov byte [rel notify_http_state], 3
.send:
    call tls13_app_flush
    test eax, eax
    jnz .out
    ; The connection budget starts before DNS and the software RSA/TLS work.
    ; Once TCP accepts the sealed POST, give the authenticated response its
    ; own bounded window; otherwise a successful slow handshake can consume
    ; the whole original budget and be misreported as provider-unreachable
    ; immediately after the endpoint has received the request.
    call boot_ms_now
    add rax, NF_RESPONSE_BUDGET_MS
    mov [rel nf_deadline], rax
    mov byte [rel notify_http_state], 4
    jmp .out
.bad:
    call nf_latch_failure
    call notify_http_cancel
    mov byte [rel notify_http_state], 6
.out:
    pop r12
    pop rbx
    ret

; TLS callback gets authenticated bytes only. Never abort/free the tuple here:
; the TCP/TLS receive stack still owns it. Completion is cleaned up by the tick.
nf_receive:
    ; Authenticated TLS EOF is never provider acceptance. An already accepted
    ; complete framed/schema-checked reply remains accepted; partial EOF fails.
    test rdi, rdi
    jnz .data
    test rsi, rsi
    jnz .data
    cmp byte [rel notify_http_state], 5
    je .eof_commit
    call nf_latch_failure
    mov byte [rel notify_http_state], 6
.eof_commit:
    xor eax, eax
    ret
.data:
    push rbx
    mov rbx, rsi
    cmp byte [rel notify_http_state], 4
    jne .bad
    mov eax, [rel nf_rx_len]
    add rax, rbx
    cmp rax, NF_RX_CAP - 1
    ja .bad
    mov rsi, rdi
    lea rdi, [rel nf_response]
    mov edx, [rel nf_rx_len]
    add rdi, rdx
    mov rdx, rbx
    call memcpy
    add [rel nf_rx_len], ebx
    lea rdi, [rel nf_response]
    mov esi, [rel nf_rx_len]
    mov byte [rdi + rsi], 0
    movzx edx, byte [rel nf_provider]
    call http_notify_response
    cmp eax, 1
    je .good
    test eax, eax
    jz .out
.bad:
    call nf_latch_failure
    mov byte [rel notify_http_state], 6
    xor eax, eax
    jmp .out
.good:
    mov byte [rel notify_http_state], 5
    xor eax, eax
.out:
    pop rbx
    ret

; Closes the TLS application session only while the notification owns it: a
; cancel never tears down another owner's session (HTTPGET's, RCQ-39-Fc).
notify_http_cancel:
    call tls13_app_owner
    lea rcx, [rel nf_receive]
    cmp rax, rcx
    jne .wipe
    call tls13_app_close
.wipe:
    lea rdi, [rel nf_private]
    xor esi, esi
    mov edx, nf_private_end - nf_private
    call memset
    mov byte [rel notify_http_state], 0
    ret

; Snapshot the failing transport before tls13_app_close deliberately tears it
; down.  The close path reports FAILED/NONE because it is an administrative
; cancellation, so sampling after close destroys the evidence needed to tell a
; TCP timeout from a particular authenticated-record failure.
nf_latch_failure:
    mov al, [rel notify_http_state]
    mov [rel notify_http_fail_phase], al
    mov al, [rel tls13_state]
    mov [rel notify_http_tls_state], al
    mov al, [rel tls13_error]
    mov [rel notify_http_tls_error], al
    mov al, [rel tls13_tcp_connected_seen]
    mov [rel notify_http_tcp_connected], al
    mov al, [rel tls13_last_record_type]
    mov [rel notify_http_tls_last_record], al
    mov al, [rel tls13_last_handshake_type]
    mov [rel notify_http_tls_last_handshake], al
    mov eax, [rel tls13_records_rx]
    mov [rel notify_http_tls_records], eax
    mov eax, [rel tls13_handshake_messages_rx]
    mov [rel notify_http_tls_handshakes], eax
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_notify_http_0 0
nf_post: db 'POST ',0
nf_colon: db ':',0
nf_http: db ' HTTP/1.1',13,10,'Host: ',0
; Keep the response-bearing TCP tuple ESTABLISHED until nf_receive has consumed
; the final TLS application record.  The current TCP ingress moves a payload+FIN
; segment to LAST_ACK before its deferred receive callback can drain the payload;
; persistent HTTP avoids losing a provider response coalesced with its close.
; notify_http_cancel still tears the tuple down immediately after success/failure.
nf_content: db 13,10,'Connection: keep-alive',13,10,'Content-Type: ',0
nf_text_type: db 'text/plain',0
nf_json_type: db 'application/json',0
nf_bearer: db 13,10,'Authorization: Bearer ',0
nf_gotify_key: db 13,10,'X-Gotify-Key: ',0
nf_length: db 13,10,'Content-Length: ',0
nf_end: db 13,10,13,10,0
nf_body_ntfy: db 'PaOS one-time approval code: ',0
nf_body_gotify: db '{"message":"PaOS one-time approval code: ',0
nf_body_suffix: db '","priority":5}',0
notify_http_state: db 0
notify_http_fail_phase: db 0
notify_http_tls_state: db 0
notify_http_tls_error: db 0
notify_http_tcp_connected: db 0
notify_http_tls_last_record: db 0
notify_http_tls_last_handshake: db 0
align 4
notify_http_tls_records: dd 0
notify_http_tls_handshakes: dd 0
align 8
nf_deadline: dq 0
nf_private:
nf_provider: db 0
nf_build_bad: db 0
nf_port: dw 0
nf_req_len: dd 0
nf_rx_len: dd 0
nf_host: times 96 db 0
nf_address: times 16 db 0
nf_connect: times 240 db 0
nf_pin: times 32 db 0
nf_num: times 24 db 0
nf_body: times 160 db 0
nf_request: times NF_REQ_CAP db 0
nf_response: times NF_RX_CAP db 0
nf_private_end:
%endmacro
WDATA_DEFER WDATA_net_notify_http_0
