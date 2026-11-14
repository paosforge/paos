;; MODULE svc/command_tls13
;; LAYER 5
;; EXPORTS command_tls13_init, tls13_cmd_out_ready, tls13_cmd_out_buf
;; IMPORTS core/capability, core/lib/fmt, net/tls13, svc/command
;; CAPS
;; OWNER saga:net
; Thin transport-independent registry projection for the native TLS 1.3 engine.
; The L4 protocol state machine owns no UDP formatting or command policy.

tls13_out_reset:
    lea  rax, [rel tls13_cmd_out_buf]
    mov  [rel tls13_cmd_out_cur], rax
    mov  byte [rax], 0
    ret

tls13_out_text:
    mov  rsi, [rel tls13_cmd_out_cur]
.loop:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.done:
    mov  byte [rsi], 0
    mov  [rel tls13_cmd_out_cur], rsi
    ret

tls13_out_u64:
    mov  rsi, [rel tls13_cmd_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel tls13_cmd_out_cur], rsi
    ret

tls13_out_hex:
    mov  rsi, [rel tls13_cmd_out_cur]
    lea  r8, [rel tls13_hex_digits]
    xor  ecx, ecx
.byte:
    cmp  ecx, edx
    jae  .done
    movzx eax, byte [rdi + rcx]
    mov  r9d, eax
    shr  eax, 4
    mov  al, [r8 + rax]
    mov  [rsi], al
    and  r9d, 15
    mov  al, [r8 + r9]
    mov  [rsi + 1], al
    add  rsi, 2
    inc  ecx
    jmp  .byte
.done:
    mov  byte [rsi], 0
    mov  [rel tls13_cmd_out_cur], rsi
    ret

tls13_stage_status:
    call tls13_out_reset
    lea  rdi, [rel tls13_str_established]
    call tls13_out_text
    movzx edi, byte [rel tls13_established]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_cert_verified]
    call tls13_out_text
    movzx edi, byte [rel tls13_cert_verified]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_sni]
    call tls13_out_text
    lea  rdi, [rel tls13_sni]
    call tls13_out_text
    lea  rdi, [rel tls13_str_state]
    call tls13_out_text
    movzx edi, byte [rel tls13_state]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_error]
    call tls13_out_text
    movzx edi, byte [rel tls13_error]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_tcp_connected]
    call tls13_out_text
    movzx edi, byte [rel tls13_tcp_connected_seen]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_records]
    call tls13_out_text
    mov  edi, [rel tls13_records_rx]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_hs_messages]
    call tls13_out_text
    mov  edi, [rel tls13_handshake_messages_rx]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_last_record]
    call tls13_out_text
    movzx edi, byte [rel tls13_last_record_type]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_last_hs]
    call tls13_out_text
    movzx edi, byte [rel tls13_last_handshake_type]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_peer_finished]
    call tls13_out_text
    movzx edi, byte [rel tls13_peer_finished_ok]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_trust_path]
    call tls13_out_text
    movzx edi, byte [rel tls13_trust_path]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_rx_pending]
    call tls13_out_text
    mov  edi, [rel tls13_rx_len]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_hs_pending]
    call tls13_out_text
    mov  edi, [rel tls13_hs_len]
    call tls13_out_u64
    lea  rdi, [rel tls13_str_entropy]
    call tls13_out_text
    movzx edi, byte [rel tls13_entropy_degraded]
    call tls13_out_u64
    mov  byte [rel tls13_cmd_out_ready], 1
    ret

tls13_stage_kat:
    call tls13_out_reset
    lea  rdi, [rel tls13_str_ks]
    call tls13_out_text
    lea  rdi, [rel tls13_kat_ks_out]
    mov  edx, 32
    call tls13_out_hex
    lea  rdi, [rel tls13_str_x25519]
    call tls13_out_text
    lea  rdi, [rel tls13_kat_x_out]
    mov  edx, 32
    call tls13_out_hex
    lea  rdi, [rel tls13_str_gcmct]
    call tls13_out_text
    lea  rdi, [rel tls13_kat_gcm_ct]
    mov  edx, 37
    call tls13_out_hex
    lea  rdi, [rel tls13_str_gcmtag]
    call tls13_out_text
    lea  rdi, [rel tls13_kat_gcm_tag]
    mov  edx, 16
    call tls13_out_hex
    lea  rdi, [rel tls13_str_katok]
    call tls13_out_text
    movzx edi, byte [rel tls13_kat_flags]
    call tls13_out_u64
    mov  byte [rel tls13_cmd_out_ready], 1
    ret

tls13_cmd_connect:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    mov  rdi, [r12 + REQ_ARG]
    call tls13_connect_start
    test rax, rax
    jnz  .bad
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .stage
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
.stage:
    call tls13_stage_status
    pop  r12
    pop  rbx
    ret

tls13_cmd_stat:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call tls13_stage_status
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret

tls13_cmd_kat:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call tls13_stage_kat
    cmp  byte [rel tls13_kat_flags], 7
    jne  .failed
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .out
.failed:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
.out:
    pop  rbx
    ret

command_tls13_init:
    call tls13_init
    lea  rdi, [rel tls13_verb_connect]
    lea  rsi, [rel tls13_cmd_connect]
    mov  edx, PMCAP_NET                 ; outbound connection is owner-authorized
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .out
    lea  rdi, [rel tls13_verb_stat]
    lea  rsi, [rel tls13_cmd_stat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .out
    lea  rdi, [rel tls13_verb_kat]
    lea  rsi, [rel tls13_cmd_kat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
.out:
    ret

tls13_cmd_out_ready: db 0
align 8
tls13_cmd_out_cur:   dq 0
tls13_cmd_out_buf:   times 1024 db 0      ; TLSSTAT/TLSKAT and bounded TLSOBS public snapshot

tls13_hex_digits:       db "0123456789abcdef"
tls13_verb_connect:     db "TLSCONNECT",0
tls13_verb_stat:        db "TLSSTAT",0
tls13_verb_kat:         db "TLSKAT",0
tls13_str_established:  db " established=",0
tls13_str_cert_verified: db " cert_verified=",0
tls13_str_sni:          db " sni=",0
tls13_str_state:        db " state=",0
tls13_str_error:        db " error=",0
tls13_str_tcp_connected: db " tcp_connected=",0
tls13_str_records:      db " records=",0
tls13_str_hs_messages:  db " hs_messages=",0
tls13_str_last_record:  db " last_record=",0
tls13_str_last_hs:      db " last_hs=",0
tls13_str_peer_finished: db " peer_finished=",0
tls13_str_trust_path:   db " trust_path=",0
tls13_str_rx_pending:   db " rx_pending=",0
tls13_str_hs_pending:   db " hs_pending=",0
tls13_str_entropy:      db " entropy_degraded=",0
tls13_str_ks:           db " ks=",0
tls13_str_x25519:       db " x25519=",0
tls13_str_gcmct:        db " gcmct=",0
tls13_str_gcmtag:       db " gcmtag=",0
tls13_str_katok:        db " kat_flags=",0
