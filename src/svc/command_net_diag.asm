;; MODULE svc/command_net_diag
;; LAYER 5
;; EXPORTS command_net_diag_init, tcpdiag_stage_snapshot, tcpdiag_out_ready, tcpdiag_out_buf, tcpdiag_out_cur
;; IMPORTS boot/header, core/lib/mem, dev/net/ax_lifetime_observation, dev/net/ax88179, core/lib/fmt, net/tcp, svc/command
;; CAPS
;; OWNER saga:ssh_server
; Read-only TCP lifecycle projection. The L4 module owns all TCP state and
; returns one locked snapshot. TCPSTAT is registered with read-only metadata but
; remains owner-authorized under the central fail-closed public-name policy;
; public STATUS uses the same renderer from command_udp's existing STATUS
; projection, so no transport-side access-control exception is introduced.

command_net_diag_init:
    lea  rdi, [rel str_verb_tcpstat]
    lea  rsi, [rel cmd_verb_tcpstat]
    xor  edx, edx                       ; public read-only diagnostic
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    call axlife_register
    call axstat_register
    call tcpprobe_register
    ret

tcpdiag_out_reset:
    lea  rax, [rel tcpdiag_out_buf]
    mov  [rel tcpdiag_out_cur], rax
    mov  byte [rax], 0
    ret

tcpdiag_out_text:
    mov  rsi, [rel tcpdiag_out_cur]
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
    mov  [rel tcpdiag_out_cur], rsi
    ret

tcpdiag_out_u64:
    mov  rsi, [rel tcpdiag_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel tcpdiag_out_cur], rsi
    ret

; Append label RDI followed by snapshot qword at offset ESI.
tcpdiag_out_field:
    push rbx
    mov  ebx, esi
    call tcpdiag_out_text
    lea  rax, [rel tcpdiag_snapshot]
    mov  rdi, [rax + rbx]
    call tcpdiag_out_u64
    pop  rbx
    ret

; Stage one bounded, internally consistent semantic line for a registry reply.
; This is also called by the already-public STATUS projection.
tcpdiag_stage_snapshot:
    lea  rdi, [rel tcpdiag_snapshot]
    call tcp_diag_snapshot
    call tcpdiag_out_reset
    lea  rdi, [rel str_tcpstat_prefix]
    call tcpdiag_out_text
    mov  edi, TCP_SERVER_DATA_REV
    call tcpdiag_out_u64
    lea  rdi, [rel str_tcpstat_listeners]
    mov  esi, TCPD_LISTENERS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_used]
    mov  esi, TCPD_USED
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_max]
    mov  esi, TCPD_MAX
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_syn]
    mov  esi, TCPD_SYN
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_est]
    mov  esi, TCPD_EST
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_closing]
    mov  esi, TCPD_CLOSING
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_timewait]
    mov  esi, TCPD_TIMEWAIT
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_accepts]
    mov  esi, TCPD_ACCEPTS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_rx]
    mov  esi, TCPD_RX_BYTES
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_tx]
    mov  esi, TCPD_TX_BYTES
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_retrans]
    mov  esi, TCPD_RETRANSMITS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_reaped]
    mov  esi, TCPD_REAPED
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_full_rsts]
    mov  esi, TCPD_FULL_RSTS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_rsts]
    mov  esi, TCPD_RSTS
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_closes]
    mov  esi, TCPD_CLOSES
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_lock_busy]
    mov  esi, TCPD_LOCK_BUSY
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_last_stage]
    mov  esi, TCPD_LAST_STAGE
    call tcpdiag_out_field
    lea  rdi, [rel str_tcpstat_syn_reaps]
    mov  esi, TCPD_SYN_REAPS
    call tcpdiag_out_field
    mov  byte [rel tcpdiag_out_ready], 1
    ret

cmd_verb_tcpstat:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call tcpdiag_stage_snapshot
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret

tcpdiag_out_ready: db 0
align 8
tcpdiag_out_cur:   dq 0
tcpdiag_snapshot:  times TCPD_SIZE db 0
tcpdiag_out_buf:   times 640 db 0

str_verb_tcpstat:        db "TCPSTAT", 0
str_tcpstat_prefix:      db " TCPSTAT rev=", 0
str_tcpstat_listeners:   db " listeners=", 0
str_tcpstat_used:        db " used=", 0
str_tcpstat_max:         db " max=", 0
str_tcpstat_syn:         db " syn=", 0
str_tcpstat_est:         db " est=", 0
str_tcpstat_closing:     db " closing=", 0
str_tcpstat_timewait:    db " timewait=", 0
str_tcpstat_accepts:     db " accepts=", 0
str_tcpstat_rx:          db " rx=", 0
str_tcpstat_tx:          db " tx=", 0
str_tcpstat_retrans:     db " retrans=", 0
str_tcpstat_reaped:      db " reaped=", 0
str_tcpstat_full_rsts:   db " full_rsts=", 0
str_tcpstat_rsts:        db " rsts=", 0
str_tcpstat_closes:      db " closes=", 0
str_tcpstat_lock_busy:   db " lock_busy=", 0
str_tcpstat_last_stage:  db " last_stage=", 0
str_tcpstat_syn_reaps:   db " syn_reaps=", 0

%include "svc/command_axstat.inc"
%include "svc/command_axlife.inc"
%include "svc/command_tcpprobe.inc"
