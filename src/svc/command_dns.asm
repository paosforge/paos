;; MODULE svc/command_dns
;; LAYER 5
;; EXPORTS command_dns_init, dns_cmd_out_ready, dns_cmd_out_buf
;; IMPORTS core/lib/fmt, svc/command, net/dns
;; CAPS
;; OWNER saga:net
; Contract 1025 thin projection. DNS query/parser/cache state remains in L4.

command_dns_init:
    call dns_wire_init
    lea  rdi, [rel str_verb_resolve]
    lea  rsi, [rel cmd_verb_resolve]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dnscache]
    lea  rsi, [rel cmd_verb_dnscache]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

dns_cmd_out_reset:
    lea  rax, [rel dns_cmd_out_buf]
    mov  [rel dns_cmd_out_cur], rax
    mov  byte [rax], 0
    ret

dns_cmd_out_str:
    mov  rsi, [rel dns_cmd_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel dns_cmd_out_cur], rsi
    ret

; RDI=caller name. Copy at most the DNS presentation-name ceiling so an
; oversized UDP argument cannot overrun the staged reply buffer.
dns_cmd_out_name:
    mov  rsi, [rel dns_cmd_out_cur]
    mov  ecx, 253
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    test ecx, ecx
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel dns_cmd_out_cur], rsi
    ret

dns_cmd_out_dec:
    mov  rsi, [rel dns_cmd_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel dns_cmd_out_cur], rsi
    ret

; EDI=raw four IPv4 octets.
dns_cmd_out_ipv4:
    push rbx
    mov  ebx, edi
    movzx edi, bl
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_dot]
    call dns_cmd_out_str
    shr  ebx, 8
    movzx edi, bl
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_dot]
    call dns_cmd_out_str
    shr  ebx, 8
    movzx edi, bl
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_dot]
    call dns_cmd_out_str
    shr  ebx, 8
    movzx edi, bl
    call dns_cmd_out_dec
    pop  rbx
    ret

; Append the semantic result. EAX=DNS_LOOKUP_*, EDX=A IPv4, RDI=caller name.
dns_cmd_out_result:
    cmp  eax, DNS_LOOKUP_A
    je   .a
    cmp  eax, DNS_LOOKUP_NX
    je   .nx
    cmp  eax, DNS_LOOKUP_NODATA
    je   .nodata
    cmp  eax, DNS_LOOKUP_PENDING
    je   .pending
    cmp  eax, DNS_LOOKUP_TIMEOUT
    je   .timeout
    cmp  eax, DNS_LOOKUP_BUSY
    je   .busy
    lea  rdi, [rel str_dns_miss]
    jmp  dns_cmd_out_str
.a:
    lea  rdi, [rel str_dns_a]
    call dns_cmd_out_str
    mov  edi, edx
    jmp  dns_cmd_out_ipv4
.nx:
    lea  rdi, [rel str_dns_nx]
    jmp  dns_cmd_out_str
.nodata:
    lea  rdi, [rel str_dns_nodata]
    jmp  dns_cmd_out_str
.pending:
    call dns_request_status
    cmp  eax, DNS_RQ_QUEUED
    je   .queued
    cmp  eax, DNS_RQ_ACTIVE
    je   .active
    lea  rdi, [rel str_dns_pending]
    jmp  dns_cmd_out_str
.queued:
    lea  rdi, [rel str_dns_queued]
    jmp  dns_cmd_out_str
.active:
    lea  rdi, [rel str_dns_active]
    jmp  dns_cmd_out_str
.timeout:
    lea  rdi, [rel str_dns_timeout]
    jmp  dns_cmd_out_str
.busy:
    lea  rdi, [rel str_dns_busy]
    jmp  dns_cmd_out_str

cmd_verb_resolve:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    call dns_cmd_out_reset
    mov  rdi, [r12 + REQ_ARG]
    cmp  byte [rdi], 0
    je   .bad
    push rdi
    call dns_resolve_start
    mov  r10d, eax
    pop  rdi
    push r10
    push rdx
    lea  rdi, [rel str_dns_resolve_pre]
    call dns_cmd_out_str
    mov  rdi, [r12 + REQ_ARG]
    call dns_cmd_out_name
    pop  rdx
    pop  rax
    mov  rdi, [r12 + REQ_ARG]
    call dns_cmd_out_result
    mov  byte [rel dns_cmd_out_ready], 1
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .out
.bad:
    lea  rdi, [rel str_dns_badarg]
    call dns_cmd_out_str
    mov  byte [rel dns_cmd_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
.out:
    pop  r12
    pop  rbx
    ret

; Format a single native observation; pending uses its captured request state,
; never a second public lookup/time sample. Static max name253 + IP15 + field
; labels/numbers (<900 bytes) fits DNS_CMD_OUT_CAP without truncating evidence.
dns_cmd_out_snapshot:
    push rbx
    mov  rbx, rdi
    mov  eax, [rbx + DSO_LOOKUP]
    mov  edx, [rbx + DSO_IP]
    cmp  dword [rbx + DSO_STATE], DSO_UNCACHED
    jne  .semantic
    cmp  dword [rbx + DSO_RESULT], DNS_LOOKUP_NODATA
    jne  .semantic
    mov  eax, DNS_LOOKUP_NODATA          ; current receipt, explicitly without cache authority
.semantic:
    cmp  eax, DNS_LOOKUP_PENDING
    je   .pending
    lea  rdi, [rbx + DSO_NAME]
    call dns_cmd_out_result
    jmp  .fields
.pending:
    lea  rdi, [rel str_dns_pending]
    cmp  dword [rbx + DSO_REQUEST_STATE], DNS_RQ_QUEUED
    jne  .active
    lea  rdi, [rel str_dns_queued]
    jmp  .put_pending
.active:
    cmp  dword [rbx + DSO_REQUEST_STATE], DNS_RQ_ACTIVE
    jne  .put_pending
    lea  rdi, [rel str_dns_active]
.put_pending:
    call dns_cmd_out_str
.fields:
    lea  rdi, [rel str_dns_obs_cache_state]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_STATE]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_time_known]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_TIME_KNOWN]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_cache_known]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_CACHE_KNOWN]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_obs_ms]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_NOW_MS]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_stored_ms]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_STORED_MS]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_expires_ms]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_EXPIRES_MS]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_ttl_ms]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_REMAINING_MS]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_ttl_s]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_TTL_S]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_ttl_original_s]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_INITIAL_TTL_S]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_route_gen]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_ROUTE_GENERATION]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_query_gen]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_QUERY_GENERATION]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_cache_gen]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_CACHE_GENERATION]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_clock_epoch]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_CLOCK_EPOCH]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_request_state]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_REQUEST_STATE]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_request_expires_ms]
    call dns_cmd_out_str
    mov  rdi, [rbx + DSO_REQUEST_DEADLINE]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_reason]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_REASON]
    call dns_cmd_out_dec
    lea  rdi, [rel str_dns_obs_source]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_SOURCE_IP]
    call dns_cmd_out_ipv4
    lea  rdi, [rel str_dns_obs_dns_server]
    call dns_cmd_out_str
    mov  edi, [rbx + DSO_SERVER_IP]
    call dns_cmd_out_ipv4
    pop  rbx
    ret

cmd_verb_dnscache:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    call dns_cmd_out_reset
    mov  rdi, [r12 + REQ_ARG]
    cmp  byte [rdi], 0
    je   .bad
    lea  rsi, [rel dns_cmd_snapshot]
    mov  edx, DNS_CACHE_SNAPSHOT_SIZE
    call dns_cache_snapshot
    test rax, rax
    jnz  .bad
    lea  rdi, [rel str_dns_cache_pre]
    call dns_cmd_out_str
    lea  rdi, [rel dns_cmd_snapshot + DSO_NAME]
    call dns_cmd_out_name
    lea  rdi, [rel dns_cmd_snapshot]
    call dns_cmd_out_snapshot
    mov  byte [rel dns_cmd_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .out
.bad:
    lea  rdi, [rel str_dns_badarg]
    call dns_cmd_out_str
    mov  byte [rel dns_cmd_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
.out:
    pop  r12
    pop  rbx
    ret

dns_cmd_out_ready: db 0
align 8
dns_cmd_out_cur:   dq 0


str_verb_resolve:  db "RESOLVE", 0
str_verb_dnscache: db "DNSCACHE", 0
str_dns_resolve_pre: db " DNS RESOLVE name=", 0
str_dns_cache_pre: db " DNSCACHE name=", 0
str_dns_a:         db " A=", 0
str_dns_nx:        db " NXDOMAIN not-found", 0
str_dns_nodata:    db " NODATA no-A-record", 0
str_dns_pending:   db " PENDING", 0
str_dns_queued:    db " PENDING queued", 0
str_dns_active:    db " PENDING active", 0
str_dns_timeout:   db " TIMEOUT failure", 0
str_dns_busy:      db " BUSY", 0
str_dns_miss:      db " MISS not-found", 0
str_dns_badarg:    db " DNS ERR invalid-name", 0
str_dns_dot:       db ".", 0
str_dns_obs_cache_state: db " CACHE_STATE=",0
str_dns_obs_time_known: db " TIME_KNOWN=",0
str_dns_obs_cache_known: db " CACHE_KNOWN=",0
str_dns_obs_obs_ms: db " OBS_MS=",0
str_dns_obs_stored_ms: db " STORED_MS=",0
str_dns_obs_expires_ms: db " EXPIRES_MS=",0
str_dns_obs_ttl_ms: db " TTL_MS=",0
str_dns_obs_ttl_s: db " TTL_S=",0
str_dns_obs_ttl_original_s: db " TTL_ORIGINAL_S=",0
str_dns_obs_route_gen: db " ROUTE_GEN=",0
str_dns_obs_query_gen: db " QUERY_GEN=",0
str_dns_obs_cache_gen: db " CACHE_GEN=",0
str_dns_obs_clock_epoch: db " CLOCK_EPOCH=",0
str_dns_obs_request_state: db " REQUEST_STATE=",0
str_dns_obs_request_expires_ms: db " REQUEST_EXPIRES_MS=",0
str_dns_obs_reason: db " REASON=",0
str_dns_obs_source: db " SOURCE=",0
str_dns_obs_dns_server: db " DNS_SERVER=",0

DNS_CMD_OUT_CAP equ 1024
%macro WDATA_command_dns_observation 0
alignb 8
dns_cmd_out_buf:  resb DNS_CMD_OUT_CAP
dns_cmd_snapshot: resb DNS_CACHE_SNAPSHOT_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_command_dns_observation
