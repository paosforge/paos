; Compact projection of the same private pair, already nonce/owner admitted.
; R14=result0 actual/1 missing/2 busy/3 wrong owner nonce. No timeout assertion.
tcpprobe_reap_render:
    push r15
    call boot_ms_now
    mov  r15, rax
    call tcpdiag_out_reset
    lea  rdi, [rel str_tcpreap_prefix]
    call tcpdiag_out_text
    mov  rdi, [rel tcpdiag_out_cur]
    mov  rax, [r12]
    mov  [rdi], rax
    mov  rax, [r12 + 8]
    mov  [rdi + 8], rax
    mov  byte [rdi + 16], 0
    add  rdi, 16
    mov  [rel tcpdiag_out_cur], rdi
    lea  rdi, [rel str_tcpprobe_result]
    call tcpdiag_out_text
    mov  rdi, r14
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_opened]
    call tcpdiag_out_text
    mov  rdi, [rel tcpprobe_opened]
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_now]
    call tcpdiag_out_text
    mov  rdi, r15
    call tcpdiag_out_u64
    lea  r15, [rel tcpreap_fields]
.fields:
    mov  eax, [r15]
    cmp  eax, -1
    je   .counters
    lea  rdi, [r15 + 4]
    call tcpdiag_out_text
    mov  eax, [r15]
    lea  rdx, [rel tcpprobe_reap_sample]
    mov  rdi, [rdx + rax]
    call tcpdiag_out_u64
    add  r15, 28
    jmp  .fields
.counters:
    lea  rdi, [rel tcpdiag_snapshot]
    call tcp_diag_snapshot
    lea  rdi, [rel str_tcpprobe_used]
    mov  esi, TCPD_USED
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpprobe_busy]
    mov  esi, TCPD_LOCK_BUSY
    call tcpdiag_out_field
    pop  r15
    ret

str_tcpreap_prefix: db ' TCPREAP rev=1 nonce=',0
%macro TCPREAP_FIELD 2
    dd %1
%%label: db %2,0
    times 24-($-%%label) db 0
%endmacro
tcpreap_fields:
    TCPREAP_FIELD 0, ' completed_ms='
    TCPREAP_FIELD 8, ' prior_state='
    TCPREAP_FIELD 16,' activity_ms='
    TCPREAP_FIELD 24,' deadline_ms='
    TCPREAP_FIELD 32,' retries='
    dd -1
%unmacro TCPREAP_FIELD 2
