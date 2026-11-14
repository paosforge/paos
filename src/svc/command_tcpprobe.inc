; Owner-only finite TCP exerciser, using the common stack and exact incarnations.
; TCPPROBE nonce16 o remoteIPv4wire8 remoteHostPort4 localHostPort4
; TCPPROBE nonce16 p|c|r|s|l|k. s sends the sixteen-byte request nonce once,
; through the common epoch-owned send path; r reads actual completed free.
; All hex lowercase; only one owned connection at a time.
; result: 0 observed,1 retired,2 busy,3 ownership/live refusal,4 open failed,
; 5 canceled. No implicit retry, timer/budget change, or automatic displacement.
tcpprobe_register:
    lea  rdi, [rel str_verb_tcpprobe]
    lea  rsi, [rel cmd_verb_tcpprobe]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1                        ; real network mutation; normal owner gate
    call command_register_verb
    ret

; Bounded lowercase hex, RDI input, ECX exact count -> EAX value, CF invalid.
; Preserves RDI. NUL/short strings refuse before reading subsequent bytes.
tcpprobe_hex:
    xor  eax, eax
    xor  edx, edx
.loop:
    movzx r8d, byte [rdi + rdx]
    sub  r8d, '0'
    cmp  r8d, 9
    jbe  .digit
    sub  r8d, 'a'-'0'
    cmp  r8d, 5
    ja   .bad
    add  r8d, 10
.digit:
    shl  eax, 4
    or   eax, r8d
    inc  edx
    cmp  edx, ecx
    jb   .loop
    clc
    ret
.bad:
    stc
    ret

cmd_verb_tcpprobe:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  rbx, rsi
    mov  r12, [rdi + REQ_ARG]
    test r12, r12
    jz   .bad
    mov  rdi, r12
    mov  ecx, 8
    call tcpprobe_hex
    jc   .bad
    lea  rdi, [r12 + 8]
    mov  ecx, 8
    call tcpprobe_hex
    jc   .bad
    cmp  byte [r12 + 16], ' '
    jne  .bad
    movzx r13d, byte [r12 + 17]
    cmp  r13d, 'o'
    je   .parse_open
    cmp  r13d, 'p'
    je   .parse_short
    cmp  r13d, 'r'
    je   .parse_short
    cmp  r13d, 'l'
    je   .parse_short
    cmp  r13d, 'k'
    je   .parse_short
    cmp  r13d, 's'
    je   .parse_short
    cmp  r13d, 'c'
    jne  .bad
.parse_short:
    cmp  byte [r12 + 18], 0
    jne  .bad
    jmp  .admit
.parse_open:
    cmp  byte [r12 + 18], ' '
    jne  .bad
    lea  rdi, [r12 + 19]
    mov  ecx, 8
    call tcpprobe_hex
    jc   .bad
    test eax, eax
    jz   .bad
    mov  [rsp], eax
    cmp  byte [r12 + 27], ' '
    jne  .bad
    lea  rdi, [r12 + 28]
    mov  ecx, 4
    call tcpprobe_hex
    jc   .bad
    test eax, eax
    jz   .bad
    mov  [rsp + 4], eax
    cmp  byte [r12 + 32], ' '
    jne  .bad
    lea  rdi, [r12 + 33]
    mov  ecx, 4
    call tcpprobe_hex
    jc   .bad
    test eax, eax
    jz   .bad
    mov  [rsp + 8], eax
    cmp  byte [r12 + 37], 0
    jne  .bad
.admit:
    ; No spinning behind another producer. The existing staged reply rail is
    ; command-dispatch-owned; private pair changes are additionally try-locked.
    mov  al, 1
    xchg al, byte [rel tcpprobe_lock]
    test al, al
    jnz  .busy_unlocked
    mov  r14d, 3
    call tcpprobe_retirement_clear
    lea  rdi, [rel tcpprobe_sample]
    xor  esi, esi
    mov  edx, 72
    call memset
    cmp  r13d, 'o'
    je   .open
    mov  rax, [r12]
    cmp  [rel tcpprobe_nonce], rax
    jne  .render
    mov  rax, [r12 + 8]
    cmp  [rel tcpprobe_nonce + 8], rax
    jne  .render
    cmp  r13d, 'k'
    je   .link_show
    cmp  r13d, 'l'
    je   .link_arm
    cmp  r13d, 'r'
    je   .read_reap
    cmp  r13d, 'c'
    je   .cancel
    cmp  r13d, 's'
    je   .send
    call tcpprobe_observe
    jmp  .render
.open:
    ; A duplicate open never allocates or displaces the current incarnation.
    mov  rax, [r12]
    cmp  [rel tcpprobe_nonce], rax
    jne  .check_previous
    mov  rax, [r12 + 8]
    cmp  [rel tcpprobe_nonce + 8], rax
    je   .render
.check_previous:
    cmp  qword [rel tcpprobe_pair], 0
    je   .start
    call tcpprobe_observe
    cmp  r14d, 1                      ; only actual retirement admits replacement
    je   .start
    cmp  r14d, 2
    je   .render
    mov  r14d, 3
    jmp  .render
.start:
    call tcpprobe_retirement_clear
    mov  byte [rel tcpprobe_sent], 0
    mov  rax, [r12]
    mov  [rel tcpprobe_nonce], rax
    mov  rax, [r12 + 8]
    mov  [rel tcpprobe_nonce + 8], rax
    mov  qword [rel tcpprobe_pair], 0
    mov  qword [rel tcpprobe_pair + 8], 0
    call boot_ms_now
    mov  [rel tcpprobe_opened], rax
    mov  edi, [rsp]
    mov  esi, [rsp + 4]
    mov  edx, [rsp + 8]
    xor  ecx, ecx
    xor  r8d, r8d
    lea  r9, [rel tcpprobe_pair]
    call tcp_client_open_tracked_try
    mov  r14d, 2
    cmp  rax, -1
    je   .render
    mov  r14d, 4
    test rax, rax
    jz   .render
    call tcpprobe_observe
    jmp  .render
.link_arm:
    call tcpprobe_link_arm
    jmp  .render
.link_show:
    call tcpprobe_link_render
    jmp  .publish
.send:
    ; A single fixed public nonce is sufficient to exercise established data
    ; retransmission. Never copy arbitrary memory or bypass the epoch guard.
    ; Consume before attempting admission: an uncertain/busy send is not
    ; silently replayed by a repeated owner request.
    cmp  byte [rel tcpprobe_sent], 0
    jne  .render
    mov  byte [rel tcpprobe_sent], 1
    mov  rdi, [rel tcpprobe_pair]
    mov  rsi, [rel tcpprobe_pair + 8]
    mov  rdx, r12
    mov  ecx, 16
    mov  r8d, 1
    call tcp_client_epoch_io
    mov  r14d, 2
    cmp  rax, -1
    je   .render
    mov  r14d, 1
    test rax, rax
    jnz  .render
    call tcpprobe_observe
    jmp  .render
.cancel:
    mov  rdi, [rel tcpprobe_pair]
    mov  rsi, [rel tcpprobe_pair + 8]
    xor  edx, edx
    xor  ecx, ecx
    mov  r8d, 2
    call tcp_client_epoch_io
    mov  r14d, 5
    test rax, rax
    jz   .render
    mov  r14d, 2
    cmp  rax, -1
    je   .render
    mov  r14d, 1
.render:
    cmp  r13d, 'r'
    je   .render_reap
    call boot_ms_now
    mov  r15, rax
    call tcpdiag_out_reset
    lea  rdi, [rel str_tcpprobe_prefix]
    call tcpdiag_out_text
    ; Echo exactly the current request's validated nonce, not a prior job's.
    mov  rdi, [rel tcpdiag_out_cur]
    mov  rax, [r12]
    mov  [rdi], rax
    mov  rax, [r12 + 8]
    mov  [rdi + 8], rax
    mov  byte [rdi + 16], 0
    add  rdi, 16
    mov  [rel tcpdiag_out_cur], rdi
    lea  rdi, [rel str_tcpprobe_action]
    call tcpdiag_out_text
    mov  edi, r13d
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_result]
    call tcpdiag_out_text
    mov  edi, r14d
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_opened]
    call tcpdiag_out_text
    mov  rdi, [rel tcpprobe_opened]
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_now]
    call tcpdiag_out_text
    mov  rdi, r15
    call tcpdiag_out_u64
    lea  r15, [rel tcpprobe_fields]
.fields:
    mov  eax, [r15]
    cmp  eax, -1
    je   .counters
    lea  rdi, [r15 + 4]
    call tcpdiag_out_text
    mov  eax, [r15]
    lea  rdx, [rel tcpprobe_sample]
    mov  rdi, [rdx + rax]
    call tcpdiag_out_u64
    add  r15, 20
    jmp  .fields
.counters:
    lea  rdi, [rel tcpdiag_snapshot]
    call tcp_diag_snapshot
    lea  rdi, [rel str_tcpprobe_used]
    mov  esi, TCPD_USED
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpprobe_retrans]
    mov  esi, TCPD_RETRANSMITS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpprobe_reaped]
    mov  esi, TCPD_REAPED
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpprobe_reaps]
    mov  esi, TCPD_SYN_REAPS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpprobe_retired]
    call tcpdiag_out_text
    mov  rdi, [rel tcpprobe_retired_ms]
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_retire_status]
    call tcpdiag_out_text
    mov  rdi, [rel tcpprobe_retire_status]
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpprobe_busy]
    mov  esi, TCPD_LOCK_BUSY
    call tcpdiag_out_field
.publish:
    mov  byte [rel tcpdiag_out_ready], 1
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  byte [rel tcpprobe_lock], 0
    jmp  .out
.read_reap:
    mov  rdi, [rel tcpprobe_pair]
    mov  rsi, [rel tcpprobe_pair + 8]
    lea  rdx, [rel tcpprobe_reap_sample]
    call tcp_client_epoch_reap
    xor  r14d, r14d
    test rax, rax
    jz   .render
    mov  r14d, 2
    cmp  rax, -1
    je   .render
    mov  r14d, 1
    jmp  .render
.render_reap:
    call tcpprobe_reap_render
    jmp  .publish
.busy_unlocked:
    ; Do not touch another in-flight handler's private state or staged reply.
    mov  qword [rbx + RSP_CODE], CMDE_BADJOB
    jmp  .out
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Private caller supplies only its own pair; failed snapshots always clear72B.
tcpprobe_observe:
    mov  rdi, [rel tcpprobe_pair]
    mov  rsi, [rel tcpprobe_pair + 8]
    lea  rdx, [rel tcpprobe_sample]
    call tcp_client_epoch_snapshot
    xor  r14d, r14d
    test rax, rax
    jz   .out
    mov  r14d, 2
    cmp  rax, -1
    je   .busy
    mov  r14d, 1
    mov  rdi, [rel tcpprobe_pair]
    mov  rsi, [rel tcpprobe_pair + 8]
    lea  rdx, [rel tcpprobe_retired_ms]
    call tcp_client_epoch_retirement
    test rax, rax
    jz   .observed
    cmp  rax, -1
    je   .busy
    jmp  .out
.observed:
    mov  qword [rel tcpprobe_retire_status], 0
    jmp  .out
.busy:
    mov  qword [rel tcpprobe_retire_status], 2
.out:
    ret

tcpprobe_retirement_clear:
    mov  qword [rel tcpprobe_retired_ms], 0
    mov  qword [rel tcpprobe_retire_status], 1
    lea  rdi, [rel tcpprobe_reap_sample]
    xor  esi, esi
    mov  edx, 40
    call memset
    ret

%include "svc/command_tcpprobe_reap.inc"
%include "svc/command_tcpprobe_link.inc"

align 8
tcpprobe_pair: times 2 dq 0
tcpprobe_opened: dq 0
tcpprobe_retired_ms: dq 0
tcpprobe_retire_status: dq 1
tcpprobe_sample: times 9 dq 0
tcpprobe_reap_sample: times 5 dq 0
tcpprobe_nonce: times 17 db 0
tcpprobe_lock: db 0
tcpprobe_sent: db 0
str_verb_tcpprobe: db 'TCPPROBE',0
str_tcpprobe_prefix: db ' TCPPROBE rev=2 nonce=',0
str_tcpprobe_action: db ' action=',0
str_tcpprobe_result: db ' result=',0
str_tcpprobe_opened: db ' opened=',0
str_tcpprobe_now: db ' now=',0
str_tcpprobe_used: db ' used=',0
str_tcpprobe_retrans: db ' retrans=',0
str_tcpprobe_reaped: db ' reaped=',0
str_tcpprobe_reaps: db ' syn_reaps=',0
str_tcpprobe_busy: db ' counters_busy=',0
str_tcpprobe_retired: db ' retired_ms=',0
str_tcpprobe_retire_status: db ' retire_status=',0
%macro TCPPROBE_FIELD 2
    dd %1
%%label: db %2,0
    times 16-($-%%label) db 0
%endmacro
tcpprobe_fields:
    TCPPROBE_FIELD 0, ' state='
    TCPPROBE_FIELD 8, ' retries='
    TCPPROBE_FIELD 16,' deadline='
    TCPPROBE_FIELD 24,' rto='
    TCPPROBE_FIELD 32,' limit='
    TCPPROBE_FIELD 40,' lip='
    TCPPROBE_FIELD 48,' rip='
    TCPPROBE_FIELD 56,' lport='
    TCPPROBE_FIELD 64,' rport='
    dd -1
%unmacro TCPPROBE_FIELD 2
