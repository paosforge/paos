;; MODULE net/http
;; LAYER 4
;; EXPORTS http_find_header_end, http_parse_chunk_size, http_chunk_frame_view, http_framing_kat, http_notify_response, http_notify_selftest, http_selftest_once, http_client_reset, http_client_feed, http_client_eof, http_error_reason, http_phase, http_cl_present, http_eof_seen, http_declared_length, http_wire_len, http_build_request, http_status, http_header_count, http_content_length, http_body_len, http_parse_state, http_body_buf
;; IMPORTS lib/safe_buffer, core/lib/str, core/lib/mem, core/lib/fmt, boot/serial
;; CAPS
;; OWNER saga:security_hardening
; Contract 9523 owns only bounded HTTP response/header/chunk framing here.
; Task1059 still owns request building, response semantics, streaming callbacks,
; TLS composition and live fetch proof.

HTTP_HEADER_MAX      equ 8192
HTTP_CHUNK_LINE_MAX  equ 128

; Task2504 response gate. Full framed response, valid bounded JSON object with
; a provider id required; status alone never means delivery. 0=need bytes,
; 1=accepted, -1=malformed/non-success. No redirect or close-delimited ambiguity.
; RDI=bytes (NUL at available), RSI=available, EDX=provider.
http_notify_response:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov byte [rel hnf_id_seen], 0
    cmp edx, 1
    jb .bad
    cmp edx, 2
    ja .bad
    mov [rel hnf_provider], dl
    cmp rsi, 13
    jb .more
    cmp dword [rbx], 'HTTP'
    jne .bad
    cmp dword [rbx + 4], '/1.1'
    jne .bad
    cmp byte [rbx + 8], ' '
    jne .bad
    cmp byte [rbx + 9], '2'
    jne .bad
    cmp byte [rbx + 10], '0'
    jne .bad
    cmp byte [rbx + 11], '0'
    jne .bad
    cmp byte [rbx + 12], ' '
    jne .bad
    call http_find_header_end
    cmp rax, -1
    je .more
    mov r13, rax
    lea r14, [rbx + rax]
    xor r15d, r15d                    ; content length; high bit=chunked
    mov rdi, rbx
.status_line:
    cmp rdi, r14
    jae .bad
    cmp word [rdi], 0x0a0d
    je .headers_begin
    inc rdi
    jmp .status_line
.headers_begin:
    add rdi, 2
.header:
    lea rax, [r14 - 2]
    cmp rdi, rax
    jae .body
    push rdi
    lea rsi, [rel hnf_length]
    call hnf_header
    pop rdi
    test eax, eax
    jnz .length
    push rdi
    lea rsi, [rel hnf_chunked]
    call hnf_header
    pop rdi
    test eax, eax
    jnz .chunked
.skip:
    cmp rdi, r14
    jae .bad
    cmp word [rdi], 0x0a0d
    je .headers_begin
    cmp byte [rdi], 0x20
    jb .bad
    inc rdi
    jmp .skip
.length:
    test r15, r15
    jnz .bad
    add rdi, 15
    call hnf_ows
    xor eax, eax
    xor ecx, ecx
.dec:
    movzx edx, byte [rdi]
    sub edx, '0'
    cmp edx, 9
    ja .dec_end
    imul eax, eax, 10
    add eax, edx
    cmp eax, 2047
    ja .bad
    inc rdi
    inc ecx
    jmp .dec
.dec_end:
    test ecx, ecx
    jz .bad
    test eax, eax
    jz .bad
    mov r15d, eax
    call hnf_ows
    cmp word [rdi], 0x0a0d
    jne .bad
    jmp .headers_begin
.chunked:
    test r15, r15
    jnz .bad
    add rdi, 18
    call hnf_ows
    lea rsi, [rel hnf_chunk_value]
    call hnf_header
    test eax, eax
    jz .bad
    mov r15, -1
    jmp .skip
.body:
    test r15, r15
    jz .bad
    cmp r15, -1
    je .chunks
    mov rax, r12
    sub rax, r13
    cmp rax, r15
    jb .more
    jne .bad
    lea rdi, [rel hnf_json]
    mov rsi, r14
    mov rdx, r15
    call memcpy
    mov byte [rdi], 0
    jmp .json
.chunks:
    xor r15d, r15d
.chunk:
    mov rdi, r14
    mov rsi, r12
    sub rsi, r13
    call http_chunk_frame_view
    cmp eax, SAFE_BUF_TRUNCATED
    je .more
    test eax, eax
    jnz .bad
    add r13, rsi
    add r14, rsi
    test rcx, rcx
    jz .chunks_end
    mov rax, r15
    add rax, rcx
    cmp rax, 2047
    ja .bad
    lea rdi, [rel hnf_json]
    add rdi, r15
    mov rsi, rdx
    mov rdx, rcx
    add r15, rcx
    call memcpy
    jmp .chunk
.chunks_end:
    cmp r13, r12
    jne .bad
    lea rax, [rel hnf_json]
    mov byte [rax + r15], 0
.json:
    lea rdi, [rel hnf_json]
    lea rsi, [rdi + r15]
    xor ecx, ecx
    call hnf_ws
    cmp byte [rdi], '{'
    jne .bad
    call hnf_value
    test eax, eax
    jnz .bad
    call hnf_ws
    cmp rdi, rsi
    jne .bad
    cmp byte [rel hnf_id_seen], 1
    jne .bad
.accepted:
    mov ebx, 1
    jmp .wipe
.more:
    xor ebx, ebx
    jmp .wipe
.bad:
    mov ebx, -1
.wipe:
    lea rdi, [rel hnf_json]
    xor esi, esi
    mov edx, 2048
    call memset
    mov eax, ebx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Case-insensitive header-prefix comparison, bounded by the literal and input
; NUL. This parser helper never copies a header or exposes it to diagnostics.
hnf_header:
    xor ecx, ecx
.loop:
    mov al, [rsi + rcx]
    test al, al
    jz .yes
    lea rdx, [rdi + rcx]
    cmp rdx, r14
    jae .no
    mov dl, [rdi + rcx]
    cmp dl, 'A'
    jb .folded
    cmp dl, 'Z'
    ja .folded
    or dl, 0x20
.folded:
    cmp dl, al
    jne .no
    inc ecx
    jmp .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

hnf_ows:
    cmp byte [rdi], ' '
    je .next
    cmp byte [rdi], 9
    jne .out
.next:
    inc rdi
    jmp hnf_ows
.out:
    ret

; Bounded allocation-free port of Classic json_parse_value/object/array/string.
; It validates rather than building an AST. Additions: explicit end, depth 8,
; strict escape/number syntax and trailing-byte rejection.
hnf_ws:
    cmp rdi, rsi
    jae .out
    mov al, [rdi]
    cmp al, ' '
    je .next
    cmp al, 9
    je .next
    cmp al, 10
    je .next
    cmp al, 13
    jne .out
.next:
    inc rdi
    jmp hnf_ws
.out:
    ret

hnf_value:
    push rbx
    call hnf_ws
    cmp rdi, rsi
    jae .bad
    cmp ecx, 8
    jae .bad
    mov al, [rdi]
    cmp al, '"'
    je .string
    cmp al, '{'
    je .object
    cmp al, '['
    je .array
    cmp al, 't'
    je .true
    cmp al, 'f'
    je .false
    cmp al, 'n'
    je .null
    cmp al, '-'
    jne .number
    inc rdi
.number:
    cmp rdi, rsi
    jae .bad
    cmp byte [rdi], '0'
    jne .integer
    inc rdi
    jmp .fraction
.integer:
    cmp byte [rdi], '1'
    jb .bad
    cmp byte [rdi], '9'
    ja .bad
    call hnf_digits
.fraction:
    cmp rdi, rsi
    jae .ok
    cmp byte [rdi], '.'
    jne .exponent
    inc rdi
    mov rbx, rdi
    call hnf_digits
    cmp rdi, rbx
    je .bad
.exponent:
    cmp rdi, rsi
    jae .ok
    mov al, [rdi]
    or al, 0x20
    cmp al, 'e'
    jne .ok
    inc rdi
    cmp rdi, rsi
    jae .bad
    cmp byte [rdi], '+'
    je .sign
    cmp byte [rdi], '-'
    jne .exp_digits
.sign:
    inc rdi
.exp_digits:
    mov rbx, rdi
    call hnf_digits
    cmp rdi, rbx
    je .bad
    jmp .ok
.string:
    call hnf_string
    jmp .out
.object:
    mov bl, '}'
    jmp .container
.array:
    mov bl, ']'
.container:
    inc ecx
    inc rdi
    call hnf_ws
    cmp rdi, rsi
    jae .container_bad
    cmp [rdi], bl
    je .close
.element:
    xor bh, bh
    cmp bl, '}'
    jne .element_value
    mov rdx, rdi
    push rdx
    call hnf_string
    pop rdx
    test eax, eax
    jnz .container_bad
    cmp ecx, 1
    jne .key_done
    mov rax, rdi
    sub rax, rdx
    cmp rax, 4
    jne .key_done
    cmp dword [rdx], '"id"'
    jne .key_done
    cmp byte [rel hnf_id_seen], 0
    jne .container_bad
    mov byte [rel hnf_id_seen], 1
    mov bh, 1
.key_done:
    call hnf_ws
    cmp rdi, rsi
    jae .container_bad
    cmp byte [rdi], ':'
    jne .container_bad
    inc rdi
.element_value:
    test bh, bh
    jz .parse_value
    call hnf_ws
    cmp rdi, rsi
    jae .container_bad
    cmp byte [rel hnf_provider], 1
    je .id_string
    ; Gotify ids are positive integers, never floats, strings or nested ids.
    cmp byte [rdi], '1'
    jb .container_bad
    cmp byte [rdi], '9'
    ja .container_bad
    mov rdx, rdi
    call hnf_digits
    cmp rdi, rsi
    jae .container_bad
    mov al, [rdi]
    mov rdi, rdx
    cmp al, ','
    je .parse_value
    cmp al, '}'
    je .parse_value
    cmp al, ' '
    je .parse_value
    cmp al, 9
    je .parse_value
    cmp al, 10
    je .parse_value
    cmp al, 13
    jne .container_bad
    jmp .parse_value
.id_string:
    cmp byte [rdi], '"'
    jne .container_bad
    cmp byte [rdi + 1], '"'
    je .container_bad
.parse_value:
    call hnf_value
    test eax, eax
    jnz .container_bad
    call hnf_ws
    cmp rdi, rsi
    jae .container_bad
    cmp [rdi], bl
    je .close
    cmp byte [rdi], ','
    jne .container_bad
    inc rdi
    call hnf_ws
    jmp .element
.close:
    inc rdi
    dec ecx
    jmp .ok
.container_bad:
    dec ecx
    jmp .bad
.true:
    lea rax, [rdi + 4]
    cmp rax, rsi
    ja .bad
    cmp dword [rdi], 'true'
    jne .bad
    add rdi, 4
    jmp .ok
.null:
    lea rax, [rdi + 4]
    cmp rax, rsi
    ja .bad
    cmp dword [rdi], 'null'
    jne .bad
    add rdi, 4
    jmp .ok
.false:
    lea rax, [rdi + 5]
    cmp rax, rsi
    ja .bad
    cmp dword [rdi], 'fals'
    jne .bad
    cmp byte [rdi + 4], 'e'
    jne .bad
    add rdi, 5
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop rbx
    ret

hnf_digits:
    cmp rdi, rsi
    jae .out
    cmp byte [rdi], '0'
    jb .out
    cmp byte [rdi], '9'
    ja .out
    inc rdi
    jmp hnf_digits
.out:
    ret

hnf_string:
    cmp rdi, rsi
    jae .bad
    cmp byte [rdi], '"'
    jne .bad
    inc rdi
.byte:
    cmp rdi, rsi
    jae .bad
    mov al, [rdi]
    inc rdi
    cmp al, '"'
    je .ok
    cmp al, 0x20
    jb .bad
    cmp al, 0x80
    jae .bad                         ; bounded ASCII provider metadata only
    cmp al, 92
    jne .byte
    cmp rdi, rsi
    jae .bad
    mov al, [rdi]
    inc rdi
    cmp al, '"'
    je .byte
    cmp al, 92
    je .byte
    cmp al, '/'
    je .byte
    cmp al, 'b'
    je .byte
    cmp al, 'f'
    je .byte
    cmp al, 'n'
    je .byte
    cmp al, 'r'
    je .byte
    cmp al, 't'
    je .byte
    cmp al, 'u'
    jne .bad
    mov edx, 4
.hex:
    cmp rdi, rsi
    jae .bad
    mov al, [rdi]
    inc rdi
    sub al, '0'
    cmp al, 9
    jbe .hex_next
    mov al, [rdi - 1]
    or al, 0x20
    sub al, 'a'
    cmp al, 5
    ja .bad
.hex_next:
    dec edx
    jnz .hex
    jmp .byte
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_http_0 0
hnf_length: db 'content-length:',0
hnf_chunked: db 'transfer-encoding:',0
hnf_chunk_value: db 'chunked',13,10,0
hnf_id_seen: db 0
hnf_provider: db 0
hnf_json: times 2048 db 0
%endmacro
WDATA_DEFER WDATA_net_http_0

; Boot-only fixtures call the production framing and provider-schema gate.
; No transport, certificate, credential, firmware or service state is touched.
http_notify_selftest:
    lea rdi, [rel hnf_kat_ntfy]
    mov esi, hnf_kat_ntfy.len
    mov edx, 1
    call http_notify_response
    cmp eax, 1
    jne .bad
    ; Match the controlled live endpoint's BaseHTTPRequestHandler response,
    ; including ordinary Server/Date/Content-Type/Connection headers.  The
    ; compact fixture above alone did not cover the metal response shape.
    lea rdi, [rel hnf_kat_basehttp]
    mov esi, hnf_kat_basehttp.len
    mov edx, 1
    call http_notify_response
    cmp eax, 1
    jne .bad
    lea rdi, [rel hnf_kat_gotify]
    mov esi, hnf_kat_gotify.len
    mov edx, 2
    call http_notify_response
    cmp eax, 1
    jne .bad
    lea rdi, [rel hnf_kat_chunks]
    mov esi, hnf_kat_chunks.len
    mov edx, 1
    call http_notify_response
    cmp eax, 1
    jne .bad
    lea rdi, [rel hnf_kat_partial]
    mov esi, hnf_kat_partial.len
    mov edx, 1
    call http_notify_response
    cmp eax, 0
    jne .bad
    lea rdi, [rel hnf_kat_malformed]
    mov esi, hnf_kat_malformed.len
    mov edx, 1
    call http_notify_response
    cmp eax, -1
    jne .bad
    lea rdi, [rel hnf_kat_nested]
    mov esi, hnf_kat_nested.len
    mov edx, 1
    call http_notify_response
    cmp eax, -1
    jne .bad
    lea rdi, [rel hnf_kat_duplicate]
    mov esi, hnf_kat_duplicate.len
    mov edx, 1
    call http_notify_response
    cmp eax, -1
    jne .bad
    lea rdi, [rel hnf_kat_float]
    mov esi, hnf_kat_float.len
    mov edx, 2
    call http_notify_response
    cmp eax, -1
    jne .bad
    lea rdi, [rel hnf_kat_wrong_type]
    mov esi, hnf_kat_wrong_type.len
    mov edx, 2
    call http_notify_response
    cmp eax, -1
    jne .bad
    lea rdi, [rel hnf_kat_ambiguous]
    mov esi, hnf_kat_ambiguous.len
    mov edx, 1
    call http_notify_response
    cmp eax, -1
    jne .bad
    lea rdi, [rel hnf_kat_status]
    mov esi, hnf_kat_status.len
    mov edx, 1
    call http_notify_response
    cmp eax, -1
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret
hnf_kat_ntfy: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 33',13,10,'',13,10,'{"id":"opaque","event":"message"}'
.len equ $ - hnf_kat_ntfy
    db 0
hnf_kat_basehttp: db 'HTTP/1.1 200 OK',13,10
    db 'Server: BaseHTTP/0.6 Python/3.13.5',13,10
    db 'Date: Sun, 14 Sep 2026 19:00:00 GMT',13,10
    db 'Content-Type: application/json',13,10
    db 'Content-Length: 28',13,10
    db 'Connection: keep-alive',13,10,13,10
    db '{"id":"1","event":"message"}'
.len equ $ - hnf_kat_basehttp
    db 0
hnf_kat_gotify: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 8',13,10,'',13,10,'{"id":1}'
.len equ $ - hnf_kat_gotify
    db 0
hnf_kat_chunks: db 'HTTP/1.1 200 OK',13,10,'Transfer-Encoding: chunked',13,10,'',13,10,'a',13,10,'{"id":"1"}',13,10,'0',13,10,'',13,10,''
.len equ $ - hnf_kat_chunks
    db 0
hnf_kat_partial: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 10',13,10,'',13,10,'{"id":'
.len equ $ - hnf_kat_partial
    db 0
hnf_kat_malformed: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 10',13,10,'',13,10,'{"id":xxx}'
.len equ $ - hnf_kat_malformed
    db 0
hnf_kat_nested: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 22',13,10,'',13,10,'{"message":{"id":"1"}}'
.len equ $ - hnf_kat_nested
    db 0
hnf_kat_duplicate: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 19',13,10,'',13,10,'{"id":"1","id":"2"}'
.len equ $ - hnf_kat_duplicate
    db 0
hnf_kat_float: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 10',13,10,'',13,10,'{"id":1.5}'
.len equ $ - hnf_kat_float
    db 0
hnf_kat_wrong_type: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 10',13,10,'',13,10,'{"id":"1"}'
.len equ $ - hnf_kat_wrong_type
    db 0
hnf_kat_ambiguous: db 'HTTP/1.1 200 OK',13,10,'Content-Length: 10',13,10,'Transfer-Encoding: chunked',13,10,'',13,10,'{"id":"1"}'
.len equ $ - hnf_kat_ambiguous
    db 0
hnf_kat_status: db 'HTTP/1.1 2000 OK',13,10,'Content-Length: 10',13,10,'',13,10,'{"id":"1"}'
.len equ $ - hnf_kat_status
    db 0



; http_find_header_end(RDI=bytes, RSI=available) -> RAX=offset past CRLFCRLF
; or -1; EDX=SAFE_BUF_OK/TRUNCATED/BOUNDS/INVALID. The scan is capped even when
; the peer never sends a terminator.
http_find_header_end:
    test rdi, rdi
    jz   .invalid
    call safe_checked_add                   ; base+available must not wrap
    test edx, edx
    jnz  .bounds_missing
    mov  rcx, rsi
    cmp  rcx, HTTP_HEADER_MAX
    jbe  .limit_ready
    mov  ecx, HTTP_HEADER_MAX
.limit_ready:
    xor  eax, eax
.scan:
    mov  rdx, rcx
    sub  rdx, rax
    cmp  rdx, 4
    jb   .missing
    cmp  byte [rdi + rax], 13
    jne  .next
    cmp  byte [rdi + rax + 1], 10
    jne  .next
    cmp  byte [rdi + rax + 2], 13
    jne  .next
    cmp  byte [rdi + rax + 3], 10
    jne  .next
    add  rax, 4
    xor  edx, edx
    ret
.next:
    inc  rax
    jmp  .scan
.missing:
    mov  rax, -1
    mov  edx, SAFE_BUF_TRUNCATED
    cmp  rsi, HTTP_HEADER_MAX
    jbe  .out
    mov  edx, SAFE_BUF_BOUNDS
.out:
    ret
.bounds_missing:
    mov  rax, -1
    mov  edx, SAFE_BUF_BOUNDS
    ret
.invalid:
    mov  rax, -1
    mov  edx, SAFE_BUF_INVALID
    ret

; http_parse_chunk_size(RDI=line, RSI=available)
;   out: RAX=size, RDX=bytes through size-line CRLF, ECX=SAFE_BUF_*.
; Hex arithmetic uses the shared checked helpers. An optional bounded extension
; is skipped, but no chunk body pointer is formed here.
http_parse_chunk_size:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    xor  r13d, r13d                      ; cursor
    xor  r14d, r14d                      ; accumulated size
    xor  r15d, r15d                      ; digit count
    test rbx, rbx
    jz   .invalid
    mov  rdi, rbx
    mov  rsi, r12
    call safe_checked_add                   ; cap every subsequent indexed read
    test edx, edx
    jnz  .bounds
.digit:
    cmp  r13, r12
    jae  .truncated
    cmp  r13, HTTP_CHUNK_LINE_MAX
    jae  .bounds
    movzx eax, byte [rbx + r13]          ; input byte read once
    cmp  al, 13
    je   .line_end
    cmp  al, ';'
    je   .extension
    mov  edx, eax
    sub  edx, '0'
    cmp  edx, 9
    jbe  .have_hex
    mov  edx, eax
    and  edx, 0xdf
    sub  edx, 'A'
    cmp  edx, 5
    ja   .invalid
    add  edx, 10
.have_hex:
    push rdx                              ; digit across checked multiply
    mov  rdi, r14
    mov  esi, 16
    call safe_checked_mul
    pop  rsi                              ; digit becomes addend
    test edx, edx
    jnz  .bounds
    mov  rdi, rax
    call safe_checked_add
    test edx, edx
    jnz  .bounds
    mov  r14, rax
    inc  r15d
    inc  r13
    jmp  .digit
.extension:
    test r15d, r15d
    jz   .invalid
    inc  r13
.extension_byte:
    cmp  r13, r12
    jae  .truncated
    cmp  r13, HTTP_CHUNK_LINE_MAX
    jae  .bounds
    movzx eax, byte [rbx + r13]
    cmp  al, 13
    je   .line_end
    cmp  al, 0x20
    jb   .invalid
    inc  r13
    jmp  .extension_byte
.line_end:
    test r15d, r15d
    jz   .invalid
    mov  rax, r12
    sub  rax, r13
    cmp  rax, 2
    jb   .truncated
    cmp  byte [rbx + r13 + 1], 10
    jne  .invalid
    mov  rax, r14
    lea  rdx, [r13 + 2]
    xor  ecx, ecx
    jmp  .out
.truncated:
    mov  ecx, SAFE_BUF_TRUNCATED
    jmp  .reject
.bounds:
    mov  ecx, SAFE_BUF_BOUNDS
    jmp  .reject
.invalid:
    mov  ecx, SAFE_BUF_INVALID
.reject:
    xor  eax, eax
    xor  edx, edx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; http_chunk_frame_view(RDI=frame, RSI=available)
;   out success: EAX=OK, RDX=body pointer, RCX=body length,
;                RSI=bytes consumed through trailing CRLF
;   reject: EAX=SAFE_BUF_*, outputs zero. No body pointer is formed until both
;   declared length and required suffix fit remaining input.
http_chunk_frame_view:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    call http_parse_chunk_size
    test ecx, ecx
    jnz  .parser_reject
    mov  r13, rax                          ; declared chunk size
    mov  r14, rdx                          ; size-line bytes
    mov  rdi, rbx
    mov  rsi, r12
    call safe_checked_add
    test edx, edx
    jnz  .bounds                           ; frame+available must not wrap
    cmp  r14, r12
    ja   .truncated
    mov  rax, r12
    sub  rax, r14                          ; remaining after size line
    cmp  r13, rax
    ja   .truncated
    sub  rax, r13                          ; bytes after declared body
    cmp  rax, 2
    jb   .truncated
    lea  rdx, [rbx + r14]                  ; body pointer after all bounds checks
    lea  rax, [rdx + r13]
    cmp  byte [rax], 13
    jne  .invalid
    cmp  byte [rax + 1], 10
    jne  .invalid
    lea  rsi, [r14 + r13 + 2]
    mov  rcx, r13
    xor  eax, eax
    jmp  .view_out
.parser_reject:
    mov  eax, ecx
    jmp  .view_reject
.truncated:
    mov  eax, SAFE_BUF_TRUNCATED
    jmp  .view_reject
.bounds:
    mov  eax, SAFE_BUF_BOUNDS
    jmp  .view_reject
.invalid:
    mov  eax, SAFE_BUF_INVALID
.view_reject:
    xor  edx, edx
    xor  ecx, ecx
    xor  esi, esi
.view_out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

http_framing_kat:
    lea  rdi, [rel http_kat_headers]
    mov  esi, http_kat_headers_end - http_kat_headers
    call http_find_header_end
    cmp  rax, http_kat_headers_end - http_kat_headers
    jne  .fail
    test edx, edx
    jnz  .fail
    lea  rdi, [rel http_kat_no_end]
    mov  esi, http_kat_no_end_end - http_kat_no_end
    call http_find_header_end
    cmp  edx, SAFE_BUF_TRUNCATED
    jne  .fail
    lea  rdi, [rel http_kat_chunk]
    mov  esi, http_kat_chunk_end - http_kat_chunk
    call http_chunk_frame_view
    test eax, eax
    jnz  .fail
    cmp  ecx, 4
    jne  .fail
    cmp  esi, http_kat_chunk_end - http_kat_chunk
    jne  .fail
    cmp  dword [rdx], 'Wiki'
    jne  .fail
    lea  rdi, [rel http_kat_chunk_short]
    mov  esi, http_kat_chunk_short_end - http_kat_chunk_short
    call http_chunk_frame_view
    cmp  eax, SAFE_BUF_TRUNCATED
    jne  .fail
    lea  rdi, [rel http_kat_chunk_bad]
    mov  esi, http_kat_chunk_bad_end - http_kat_chunk_bad
    call http_chunk_frame_view
    cmp  eax, SAFE_BUF_INVALID
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

http_kat_headers: db "HTTP/1.1 200 OK",13,10,"X: y",13,10,13,10
http_kat_headers_end:
http_kat_no_end: db "HTTP/1.1 200 OK",13,10,"X: y"
http_kat_no_end_end:
http_kat_chunk: db "4",13,10,"Wiki",13,10
http_kat_chunk_end:
http_kat_chunk_short: db "4",13,10,"Wi"
http_kat_chunk_short_end:
http_kat_chunk_bad: db "Z",13,10
http_kat_chunk_bad_end:

; ============================================================================
; HTTP/1.1 GET response framing. A complete supported body is bounded to
; HTTP_BODY_MAX; scratch is used only for a current owned header/size/trailer
; line. Oversize and incomplete results are explicit failures, never a prefix
; presented as a successful response. Only authenticated TLS close_notify can
; finalize close-delimited bodies through the supported NULL/0 callback event.
; ============================================================================

; Strict bounded incremental GET response parser. Owned bytes are consumed once;
; only complete bounded header/size/trailer lines are scanned. The callback
; always commits (RAX=0), including a latched HTTP error: no record replay.
HTTP_REQ_MAX     equ 640
HTTP_RESP_MAX    equ 4096          ; owned header/line scratch, never a response prefix
HTTP_BODY_MAX    equ 1024          ; complete supported body, oversize is an error
HTTP_WIRE_MAX    equ 16384         ; finite encoded response budget, including interim/trailers
HTTP_TRAILER_MAX equ 2048
HTTP_INFO_MAX    equ 4

HTTP_ST_IDLE     equ 0
HTTP_ST_RECV     equ 1
HTTP_ST_DONE     equ 2
HTTP_ST_ERROR    equ 3
HTTP_ERR_NONE       equ 0
HTTP_ERR_FRAMING    equ 1
HTTP_ERR_OVERSIZE   equ 2
HTTP_ERR_INCOMPLETE equ 3
HTTP_ERR_ARGUMENT   equ 4
HTTP_ERR_UNSUPPORTED equ 5
HTTP_ERR_TIMEOUT    equ 6
HTTP_HP_HEADERS equ 0
HTTP_HP_LENGTH  equ 1
HTTP_HP_CLOSE   equ 2
HTTP_HP_SIZE    equ 3
HTTP_HP_DATA    equ 4
HTTP_HP_CR      equ 5
HTTP_HP_LF      equ 6
HTTP_HP_TRAILERS equ 7
HTTP_HP_END     equ 8

http_client_reset:
    cld
    mov  dword [rel http_status], 0
    mov  dword [rel http_header_count], 0
    mov  dword [rel http_content_length], 0
    mov  dword [rel http_body_len], 0
    mov  dword [rel http_resp_len], 0
    mov  byte [rel http_te_chunked], 0
    mov  byte [rel http_cl_present], 0
    mov  byte [rel http_eof_seen], 0
    mov  byte [rel http_info_count], 0
    mov  byte [rel http_error_reason], HTTP_ERR_NONE
    mov  byte [rel http_phase], HTTP_HP_HEADERS
    mov  qword [rel http_declared_length], 0
    mov  qword [rel http_remaining], 0
    mov  qword [rel http_wire_len], 0
    mov  dword [rel http_header_bytes], 0
    mov  dword [rel http_trailer_bytes], 0
    mov  byte [rel http_body_buf], 0
    mov  byte [rel http_parse_state], HTTP_ST_RECV
    ret

; TLS callback: (non-null bytes,len) is data (including an empty record).
; (NULL,0) is the explicit authenticated close_notify event. Bare TCP close,
; TLS errors/cancellation and an empty TLS data record are never EOF authority.
http_client_feed:
    cld
    test rdi, rdi
    jnz  .data
    test rsi, rsi
    jz   http_client_eof
    mov  eax, HTTP_ERR_ARGUMENT
    jmp  http_client_error
.data:
    cmp  byte [rel http_parse_state], HTTP_ST_ERROR
    je   .commit
    test rsi, rsi
    jz   .commit
    mov  rax, rdi
    add  rax, rsi
    jc   .argument
    cmp  byte [rel http_parse_state], HTTP_ST_RECV
    jne  .trailing
    cmp  byte [rel http_eof_seen], 0
    jne  .trailing
    mov  rax, [rel http_wire_len]
    add  rax, rsi
    jc   .oversize
    cmp  rax, HTTP_WIRE_MAX
    ja   .oversize
    mov  [rel http_wire_len], rax
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
.byte:
    test r13, r13
    jz   .out
    cmp  byte [rel http_parse_state], HTTP_ST_RECV
    jne  .late
    movzx ebx, byte [r12]
    inc  r12
    dec  r13
    movzx eax, byte [rel http_phase]
    cmp  eax, HTTP_HP_HEADERS
    je   .header
    cmp  eax, HTTP_HP_SIZE
    je   .line
    cmp  eax, HTTP_HP_TRAILERS
    je   .trailer
    cmp  eax, HTTP_HP_CR
    je   .cr
    cmp  eax, HTTP_HP_LF
    je   .lf
    ; Length, close-delimited or chunk data. A bounded body is complete or an
    ; explicit oversize error, never a successful truncated read-back window.
    mov  eax, [rel http_body_len]
    cmp  eax, HTTP_BODY_MAX
    jae  .large
    lea  rdx, [rel http_body_buf]
    mov  [rdx + rax], bl
    inc  eax
    mov  [rel http_body_len], eax
    mov  byte [rdx + rax], 0
    cmp  byte [rel http_phase], HTTP_HP_CLOSE
    je   .byte
    dec  qword [rel http_remaining]
    jnz  .byte
    cmp  byte [rel http_phase], HTTP_HP_DATA
    jne  .done
    mov  byte [rel http_phase], HTTP_HP_CR
    jmp  .byte
.cr:
    cmp  bl, 13
    jne  .bad
    mov  byte [rel http_phase], HTTP_HP_LF
    jmp  .byte
.lf:
    cmp  bl, 10
    jne  .bad
    mov  byte [rel http_phase], HTTP_HP_SIZE
    jmp  .byte
.header:
    inc  dword [rel http_header_bytes]
    cmp  dword [rel http_header_bytes], HTTP_RESP_MAX
    ja   .large
    jmp  .line
.trailer:
    inc  dword [rel http_trailer_bytes]
    cmp  dword [rel http_trailer_bytes], HTTP_TRAILER_MAX
    ja   .large
.line:
    mov  eax, [rel http_resp_len]
    mov  edx, HTTP_RESP_MAX
    cmp  byte [rel http_phase], HTTP_HP_SIZE
    jne  .line_limit
    mov  edx, HTTP_CHUNK_LINE_MAX
.line_limit:
    cmp  eax, edx
    jae  .large
    lea  rcx, [rel http_resp_buf]
    test eax, eax
    jz   .first
    cmp  byte [rcx + rax - 1], 13
    jne  .first
    cmp  bl, 10
    jne  .bad
.first:
    cmp  bl, 10
    jne  .append
    test eax, eax
    jz   .bad
    cmp  byte [rcx + rax - 1], 13
    jne  .bad
.append:
    mov  [rcx + rax], bl
    inc  eax
    mov  [rel http_resp_len], eax
    cmp  bl, 10
    jne  .byte
    cmp  byte [rel http_phase], HTTP_HP_HEADERS
    jne  .other_line
    cmp  eax, 4
    jb   .byte
    cmp  dword [rcx + rax - 4], 0x0a0d0a0d
    jne  .byte
    call http_client_parse
    jmp  .parsed
.other_line:
    lea  rsi, [rcx + rax - 2]         ; excludes CRLF, never reads beyond line
    mov  rdi, rcx
    cmp  byte [rel http_phase], HTTP_HP_SIZE
    jne  .trailer_line
    call http_client_chunk_line
    test eax, eax
    jnz  .out
    jmp  .parsed
.trailer_line:
    cmp  rdi, rsi
    je   .done
    call http_client_field
    test eax, eax
    jnz  .bad                        ; malformed or framing fields in trailers
.parsed:
    mov  dword [rel http_resp_len], 0
    cmp  byte [rel http_parse_state], HTTP_ST_ERROR
    je   .out
    jmp  .byte
.done:
    mov  byte [rel http_phase], HTTP_HP_END
    mov  byte [rel http_parse_state], HTTP_ST_DONE
    jmp  .byte
.late:
    cmp  byte [rel http_parse_state], HTTP_ST_ERROR
    je   .out
.bad:
    mov  eax, HTTP_ERR_FRAMING
    jmp  .error
.large:
    mov  eax, HTTP_ERR_OVERSIZE
.error:
    call http_client_error
.out:
    pop  r13
    pop  r12
    pop  rbx
.commit:
    xor  eax, eax
    ret
.argument:
    mov  eax, HTTP_ERR_ARGUMENT
    jmp  http_client_error
.trailing:
    mov  eax, HTTP_ERR_FRAMING
    jmp  http_client_error
.oversize:
    mov  eax, HTTP_ERR_OVERSIZE
    jmp  http_client_error

; Explicit supported finalization. Framed responses may complete before EOF;
; close-delimited responses complete only here. All other pending states are
; incomplete, including a partial size line, chunk suffix or trailer block.
http_client_eof:
    cld
    mov  byte [rel http_eof_seen], 1
    cmp  byte [rel http_parse_state], HTTP_ST_RECV
    jne  .commit
    cmp  byte [rel http_phase], HTTP_HP_CLOSE
    jne  .incomplete
    mov  byte [rel http_parse_state], HTTP_ST_DONE
    mov  byte [rel http_phase], HTTP_HP_END
.commit:
    xor  eax, eax
    ret
.incomplete:
    mov  eax, HTTP_ERR_INCOMPLETE
    jmp  http_client_error

; EAX=typed error. First failure is sticky until reset; TLS bytes still commit.
http_client_error:
    cmp  byte [rel http_parse_state], HTTP_ST_ERROR
    je   .out
    mov  [rel http_error_reason], al
    mov  byte [rel http_parse_state], HTTP_ST_ERROR
.out:
    xor  eax, eax
    ret

; Complete bounded header block only. Unsupported upgrade is never a bodyless
; success. Up to four ordinary 1xx blocks may precede one final GET response.
http_client_parse:
    push rbx
    push r12
    push r13
    lea  rbx, [rel http_resp_buf]
    mov  r12d, [rel http_resp_len]
    add  r12, rbx
    mov  rdi, rbx
    mov  rsi, r12
    call http_client_line_end
    cmp  rax, -1
    je   .bad
    mov  r13, rdx
    sub  rax, rbx
    cmp  rax, 13
    jb   .bad
    cmp  dword [rbx], 'HTTP'
    jne  .bad
    cmp  dword [rbx + 4], '/1.1'
    jne  .unsupported
    cmp  byte [rbx + 8], ' '
    jne  .bad
    cmp  byte [rbx + 12], ' '
    jne  .bad
    xor  r8d, r8d
    mov  ecx, 9
.code:
    movzx edx, byte [rbx + rcx]
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    imul r8d, r8d, 10
    add  r8d, edx
    inc  ecx
    cmp  ecx, 12
    jb   .code
    cmp  r8d, 100
    jb   .bad
    cmp  r8d, 599
    ja   .bad
    mov  [rel http_status], r8d
    mov  ecx, 13
.reason:
    cmp  rcx, rax
    jae  .headers
    mov  dl, [rbx + rcx]
    cmp  dl, 9
    je   .reason_next
    cmp  dl, 32
    jb   .bad
    cmp  dl, 127
    je   .bad
.reason_next:
    inc  ecx
    jmp  .reason
.headers:
    mov  dword [rel http_header_count], 0
    mov  dword [rel http_content_length], 0
    mov  qword [rel http_declared_length], 0
    mov  byte [rel http_cl_present], 0
    mov  byte [rel http_te_chunked], 0
.header:
    mov  rdi, r13
    mov  rsi, r12
    call http_client_line_end
    cmp  rax, -1
    je   .bad
    cmp  rax, r13
    je   .headers_done
    push rdx
    mov  rdi, r13
    mov  rsi, rax
    call http_client_field
    pop  r13
    cmp  eax, -1
    je   .bad
    inc  dword [rel http_header_count]
    cmp  eax, 1
    je   .length
    cmp  eax, 2
    jne  .header
    cmp  byte [rel http_te_chunked], 0
    jne  .bad
    cmp  byte [rel http_cl_present], 0
    jne  .bad
    mov  rdx, rsi
    sub  rdx, rdi
    mov  rsi, rdx
    lea  rdx, [rel http_lit_chunked]
    call http_client_name_eq
    test eax, eax
    jz   .unsupported
    mov  byte [rel http_te_chunked], 1
    jmp  .header
.length:
    cmp  byte [rel http_cl_present], 0
    jne  .bad                        ; strict policy rejects even identical duplicates
    cmp  byte [rel http_te_chunked], 0
    jne  .bad
    cmp  rdi, rsi
    je   .bad
    xor  r8d, r8d
.decimal:
    movzx edx, byte [rdi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    mov  rax, 1844674407370955161
    cmp  r8, rax
    ja   .bad
    jb   .accumulate
    cmp  edx, 5
    ja   .bad
.accumulate:
    imul r8, r8, 10
    add  r8, rdx
    inc  rdi
    cmp  rdi, rsi
    jb   .decimal
    mov  [rel http_declared_length], r8
    mov  rax, r8
    shr  rax, 32
    jnz  .large_declared             ; legacy dd remains representable, explicit u64 below
    mov  [rel http_content_length], r8d
.large_declared:
    mov  byte [rel http_cl_present], 1
    jmp  .header
.headers_done:
    cmp  rdx, r12
    jne  .bad
    mov  eax, [rel http_status]
    cmp  eax, 200
    jae  .final
    cmp  eax, 101
    je   .unsupported
    cmp  byte [rel http_cl_present], 0
    jne  .bad
    cmp  byte [rel http_te_chunked], 0
    jne  .bad
    inc  byte [rel http_info_count]
    cmp  byte [rel http_info_count], HTTP_INFO_MAX
    ja   .unsupported
    mov  dword [rel http_status], 0
    jmp  .out                        ; feed clears scratch for next header block
.final:
    cmp  eax, 204
    je   .no_content
    cmp  eax, 205
    je   .reset_content
    cmp  eax, 304
    je   .bodyless
    cmp  byte [rel http_te_chunked], 1
    je   .chunked
    cmp  byte [rel http_cl_present], 0
    je   .close
    mov  rax, [rel http_declared_length]
    cmp  rax, HTTP_BODY_MAX
    ja   .oversize
    mov  [rel http_remaining], rax
    test rax, rax
    jz   .done
    mov  byte [rel http_phase], HTTP_HP_LENGTH
    jmp  .out
.close:
    mov  byte [rel http_phase], HTTP_HP_CLOSE
    jmp  .out
.chunked:
    mov  byte [rel http_phase], HTTP_HP_SIZE
    jmp  .out
.no_content:
    cmp  byte [rel http_cl_present], 0
    jne  .bad
    jmp  .bodyless
.reset_content:
    cmp  qword [rel http_declared_length], 0
    jne  .bad
.bodyless:
    cmp  byte [rel http_te_chunked], 0
    jne  .bad
.done:
    mov  byte [rel http_phase], HTTP_HP_END
    mov  byte [rel http_parse_state], HTTP_ST_DONE
    jmp  .out
.unsupported:
    mov  eax, HTTP_ERR_UNSUPPORTED
    jmp  .error
.oversize:
    mov  eax, HTTP_ERR_OVERSIZE
    jmp  .error
.bad:
    mov  eax, HTTP_ERR_FRAMING
.error:
    call http_client_error
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded CRLF line view: RDI=start RSI=end(exclusive), RAX=CR RDX=next.
http_client_line_end:
    mov  rax, rdi
.scan:
    lea  rdx, [rax + 1]
    cmp  rdx, rsi
    jae  .bad
    cmp  byte [rax], 13
    je   .cr
    inc  rax
    jmp  .scan
.cr:
    cmp  byte [rdx], 10
    jne  .bad
    inc  rdx
    ret
.bad:
    mov  rax, -1
    ret

; AL -> EAX=1 for RFC token characters, zero otherwise.
http_client_tchar:
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .yes
    cmp  al, 'A'
    jb   .punct
    cmp  al, 'Z'
    jbe  .yes
    cmp  al, 'a'
    jb   .punct
    cmp  al, 'z'
    jbe  .yes
.punct:
    lea  rdx, [rel http_token_punct]
.loop:
    cmp  byte [rdx], 0
    je   .no
    cmp  al, [rdx]
    je   .yes
    inc  rdx
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI=name,RSI=length,RDX=lowercase literal -> EAX exact CI match.
http_client_name_eq:
    xor  ecx, ecx
.loop:
    cmp  rcx, rsi
    jae  .end
    mov  al, [rdi + rcx]
    cmp  al, 'A'
    jb   .folded
    cmp  al, 'Z'
    ja   .folded
    or   al, 0x20
.folded:
    cmp  byte [rdx + rcx], 0
    je   .no
    cmp  al, [rdx + rcx]
    jne  .no
    inc  ecx
    jmp  .loop
.end:
    cmp  byte [rdx + rcx], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Complete field line view, no CRLF: EAX=-1 invalid,0 other,1 CL,2 TE.
; On success RDI/RSI are trimmed value start/end. No obs-fold/colon whitespace.
http_client_field:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdi
.name:
    cmp  r13, r12
    jae  .bad
    mov  al, [r13]
    cmp  al, ':'
    je   .colon
    call http_client_tchar
    test eax, eax
    jz   .bad
    inc  r13
    jmp  .name
.colon:
    cmp  r13, rbx
    je   .bad
    mov  rsi, r13
    sub  rsi, rbx
    mov  rdi, rbx
    lea  rdx, [rel http_name_cl]
    call http_client_name_eq
    test eax, eax
    jnz  .cl
    mov  rdi, rbx
    mov  rsi, r13
    sub  rsi, rbx
    lea  rdx, [rel http_name_te]
    call http_client_name_eq
    test eax, eax
    jnz  .te
    xor  ebx, ebx
    jmp  .value
.cl:
    mov  ebx, 1
    jmp  .value
.te:
    mov  ebx, 2
.value:
    inc  r13
    mov  rdi, r13
    mov  rsi, r12
.trim_start:
    cmp  rdi, rsi
    jae  .valid
    mov  al, [rdi]
    cmp  al, ' '
    je   .start_next
    cmp  al, 9
    jne  .trim_end
.start_next:
    inc  rdi
    jmp  .trim_start
.trim_end:
    cmp  rdi, rsi
    jae  .valid
    mov  al, [rsi - 1]
    cmp  al, ' '
    je   .end_next
    cmp  al, 9
    jne  .check
.end_next:
    dec  rsi
    jmp  .trim_end
.check:
    mov  rcx, rdi
.check_byte:
    cmp  rcx, rsi
    jae  .valid
    mov  al, [rcx]
    cmp  al, 9
    je   .next
    cmp  al, 32
    jb   .bad
    cmp  al, 127
    je   .bad
.next:
    inc  rcx
    jmp  .check_byte
.valid:
    mov  eax, ebx
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Strict chunk-size/extensions on one bounded owned line (no CRLF).
; Extensions: *(OWS ';' OWS token [OWS '=' OWS (token / quoted-string)]).
; A missing token/value, illegal escape/control or trailing junk is malformed.
http_client_chunk_line:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    xor  r13d, r13d
    xor  ecx, ecx
.hex:
    cmp  rbx, r12
    jae  .hex_end
    movzx eax, byte [rbx]
    mov  edx, eax
    sub  edx, '0'
    cmp  edx, 9
    jbe  .digit
    or   al, 0x20
    sub  al, 'a'
    cmp  al, 5
    ja   .hex_end
    movzx edx, al
    add  edx, 10
.digit:
    mov  rax, r13
    shr  rax, 60
    jnz  .bad
    shl  r13, 4
    or   r13, rdx
    inc  rbx
    inc  ecx
    jmp  .hex
.hex_end:
    test ecx, ecx
    jz   .bad
.extension:
    call .ows
    cmp  rbx, r12
    jae  .size
    cmp  byte [rbx], ';'
    jne  .bad
    inc  rbx
    call .ows
    call .token
    test eax, eax
    jz   .bad
    call .ows
    cmp  rbx, r12
    jae  .size
    cmp  byte [rbx], '='
    jne  .extension
    inc  rbx
    call .ows
    cmp  rbx, r12
    jae  .bad
    cmp  byte [rbx], '"'
    je   .quote
    call .token
    test eax, eax
    jz   .bad
    jmp  .extension
.quote:
    inc  rbx
.qbyte:
    cmp  rbx, r12
    jae  .bad
    mov  al, [rbx]
    inc  rbx
    cmp  al, '"'
    je   .extension
    cmp  al, 92
    jne  .qchar
    cmp  rbx, r12
    jae  .bad
    mov  al, [rbx]
    inc  rbx
.qchar:
    cmp  al, 9
    je   .qbyte
    cmp  al, 32
    jb   .bad
    cmp  al, 127
    je   .bad
    jmp  .qbyte
.size:
    mov  rax, HTTP_BODY_MAX
    mov  edx, [rel http_body_len]
    sub  rax, rdx
    cmp  r13, rax
    ja   .large
    mov  [rel http_remaining], r13
    mov  byte [rel http_phase], HTTP_HP_DATA
    test r13, r13
    jnz  .ok
    mov  byte [rel http_phase], HTTP_HP_TRAILERS
.ok:
    xor  eax, eax
    jmp  .out
.large:
    mov  eax, HTTP_ERR_OVERSIZE
    jmp  .error
.bad:
    mov  eax, HTTP_ERR_FRAMING
.error:
    call http_client_error
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.ows:
    cmp  rbx, r12
    jae  .ows_done
    cmp  byte [rbx], ' '
    je   .ows_next
    cmp  byte [rbx], 9
    jne  .ows_done
.ows_next:
    inc  rbx
    jmp  .ows
.ows_done:
    ret
.token:
    push r13
    mov  r13, rbx
.token_byte:
    cmp  rbx, r12
    jae  .token_end
    mov  al, [rbx]
    call http_client_tchar
    test eax, eax
    jz   .token_end
    inc  rbx
    jmp  .token_byte
.token_end:
    xor  eax, eax
    cmp  rbx, r13
    setne al
    pop  r13
    ret

; http_ci_prefix(RDI=str, RSI=lowercase literal) -> RAX=1 if str begins with the
; literal (ASCII case-insensitive); on match RDI is advanced past the literal.
http_ci_prefix:
.l:
    mov  al, [rsi]
    test al, al
    jz   .yes
    mov  dl, [rdi]
    cmp  dl, 'A'
    jb   .cmp
    cmp  dl, 'Z'
    ja   .cmp
    or   dl, 0x20
.cmp:
    cmp  dl, al
    jne  .no
    inc  rdi
    inc  rsi
    jmp  .l
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; http_put_text(RDI=src cstr) — append into the request-build buffer at the
; running cursor http_bld_cur, bounded by HTTP_REQ_MAX.
http_put_text:
    mov  rsi, [rel http_bld_cur]
    lea  rcx, [rel http_req_buf + HTTP_REQ_MAX - 1]
.l:
    mov  al, [rdi]
    test al, al
    jz   .d
    cmp  rsi, rcx
    jae  .d
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .l
.d:
    mov  byte [rsi], 0
    mov  [rel http_bld_cur], rsi
    ret

; http_build_request(RDI=host cstr, RSI=path cstr) -> RAX=length. Builds
; "GET <path> HTTP/1.1\r\nHost: <host>\r\n<fixed headers>\r\n\r\n".
http_build_request:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rax, [rel http_req_buf]
    mov  [rel http_bld_cur], rax
    lea  rdi, [rel http_lit_get]
    call http_put_text
    mov  rdi, r13
    call http_put_text
    lea  rdi, [rel http_lit_ver]
    call http_put_text
    mov  rdi, r12
    call http_put_text
    lea  rdi, [rel http_lit_tail]
    call http_put_text
    lea  rax, [rel http_req_buf]
    mov  rcx, [rel http_bld_cur]
    sub  rcx, rax
    mov  [rel http_req_len], ecx
    mov  rax, rcx
    pop  r13
    pop  r12
    pop  rbx
    ret

; http_reqline_build_kat -> RAX 0 pass / -1 fail. Byte-exact request-line build.
http_reqline_build_kat:
    lea  rdi, [rel http_kat_host]
    lea  rsi, [rel http_kat_path]
    call http_build_request
    lea  rdi, [rel http_req_buf]
    lea  rsi, [rel http_kat_reqline_expect]
    call strcmp
    test rax, rax
    jnz  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; http_resp_parse_kat -> RAX 0 pass / -1 fail. Drives the LIVE streaming parser
; over three fixtures: a Content-Length body fed in two pieces (proves
; incremental feeding), a chunked body (proves the streaming chunk decoder), and
; a malformed status line (proves bounded rejection).
http_resp_parse_kat:
    push rbx
    ; (1) Content-Length, fed in two pieces
    call http_client_reset
    lea  rdi, [rel http_kat_cl]
    mov  esi, 20
    call http_client_feed
    lea  rdi, [rel http_kat_cl + 20]
    mov  esi, http_kat_cl_end - http_kat_cl - 20
    call http_client_feed
    cmp  byte [rel http_parse_state], HTTP_ST_DONE
    jne  .fail
    cmp  dword [rel http_status], 200
    jne  .fail
    cmp  dword [rel http_header_count], 2
    jb   .fail
    cmp  dword [rel http_body_len], 11
    jne  .fail
    lea  rdi, [rel http_body_buf]
    lea  rsi, [rel http_kat_tok]
    call str_find
    test rax, rax
    jz   .fail
    ; (2) chunked
    call http_client_reset
    lea  rdi, [rel http_kat_ck]
    mov  esi, http_kat_ck_end - http_kat_ck
    call http_client_feed
    cmp  byte [rel http_parse_state], HTTP_ST_DONE
    jne  .fail
    cmp  byte [rel http_te_chunked], 1
    jne  .fail
    cmp  dword [rel http_status], 200
    jne  .fail
    lea  rdi, [rel http_body_buf]
    lea  rsi, [rel http_kat_tok]
    call str_find
    test rax, rax
    jz   .fail
    ; (3) malformed status line -> ERROR (bounded reject, no hang)
    call http_client_reset
    lea  rdi, [rel http_kat_bad]
    mov  esi, http_kat_bad_end - http_kat_bad
    call http_client_feed
    cmp  byte [rel http_parse_state], HTTP_ST_ERROR
    jne  .fail
    call http_client_reset
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  rbx
    ret

; http_selftest_once — boot KAT. Emits the three regression markers, each gated
; on live-function behaviour (a wrong build cannot fire them).
http_selftest_once:
    push rbx
    xor  ebx, ebx                    ; bit0=reqline PASS, bit1=parse PASS
    call http_reqline_build_kat
    test eax, eax
    jnz  .p2
    or   ebx, 1
    lea  rdi, [rel http_marker_reqline]
    call serial_string
.p2:
    call http_resp_parse_kat
    test eax, eax
    jnz  .ready
    or   ebx, 2
    lea  rdi, [rel http_marker_parse]
    call serial_string
.ready:
    cmp  ebx, 3
    jne  .out
    lea  rdi, [rel http_marker_ready]
    call serial_string
.out:
    call http_client_reset
    xor  eax, eax
    pop  rbx
    ret

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_http_1 0
align 8
http_status:          dd 0
http_header_count:    dd 0
http_content_length:  dd 0
http_body_len:        dd 0
http_req_len:         dd 0
http_resp_len:        dd 0
http_te_chunked:      db 0
http_parse_state:     db HTTP_ST_IDLE
align 8
times 9 db 0                  ; http_bld_cur..http_resp_buf moved to WDATA_net_http_1_bss1: keeps the labels below at their offset mod 64

http_lit_get:     db "GET ",0
http_lit_ver:     db " HTTP/1.1",13,10,"Host: ",0
http_lit_tail:    db 13,10,"User-Agent: paos-fetch/1",13,10,"Accept: */*",13,10,"Connection: close",13,10,13,10,0
http_token_punct: db 33,35,36,37,38,39,42,43,45,46,94,95,96,124,126,0
http_name_cl: db 'content-length',0
http_name_te: db 'transfer-encoding',0
http_lit_clen:    db "content-length:",0
http_lit_te:      db "transfer-encoding:",0
http_lit_chunked: db "chunked",0

http_kat_host: db "example.com",0
http_kat_path: db "/echo?tok=XYZZY-1",0
http_kat_tok:  db "XYZZY",0
http_kat_reqline_expect:
    db "GET /echo?tok=XYZZY-1 HTTP/1.1",13,10
    db "Host: example.com",13,10
    db "User-Agent: paos-fetch/1",13,10
    db "Accept: */*",13,10
    db "Connection: close",13,10,13,10,0
http_kat_cl:
    db "HTTP/1.1 200 OK",13,10
    db "Content-Type: text/plain",13,10
    db "Content-Length: 11",13,10,13,10
    db "XYZZY-hello"
http_kat_cl_end:
http_kat_ck:
    db "HTTP/1.1 200 OK",13,10
    db "Transfer-Encoding: chunked",13,10,13,10
    db "5",13,10,"XYZZY",13,10
    db "6",13,10,"-chunk",13,10
    db "0",13,10,13,10
http_kat_ck_end:
http_kat_bad:
    db "HELLO NOT AN HTTP RESPONSE",13,10,13,10
http_kat_bad_end:

http_marker_ready:   db "[PAOS64] P8 http: HTTPS GET client ready [http.client.ready]",13,10,0
http_marker_reqline: db "[PAOS64] P8 http: request-line+headers build selftest PASS [http.reqline.build]",13,10,0
http_marker_parse:   db "[PAOS64] P8 http: status/header/chunked parse selftest PASS [http.resp.parse]",13,10,0
%endmacro
WDATA_DEFER WDATA_net_http_1
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_net_http_1_bss1 0
resb 32                 ; keeps http_bld_cur at its WDATA offset mod 64
alignb 8
http_bld_cur:         resq 1
http_body_buf:        resb HTTP_BODY_MAX + 1
http_req_buf:         resb HTTP_REQ_MAX
http_resp_buf:        resb HTTP_RESP_MAX
%endmacro
WDATA_BSS_DEFER WDATA_net_http_1_bss1

; Framing state is preallocated in the zero-fill tail, not raw-zero file data.
%macro WDATA_http_incremental 0
alignb 8
http_declared_length: resq 1
http_remaining:      resq 1
http_wire_len:       resq 1
http_header_bytes:   resd 1
http_trailer_bytes:  resd 1
http_cl_present:    resb 1
http_eof_seen:      resb 1
http_info_count:    resb 1
http_error_reason:  resb 1
http_phase:         resb 1
%endmacro
WDATA_BSS_DEFER WDATA_http_incremental
