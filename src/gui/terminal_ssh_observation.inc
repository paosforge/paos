; Actual Terminal-owned lifecycle observations. No timer/network/session work in
; copy/feed. Hooks run only in the existing serialized Terminal lifecycle.
; One last dial per instance; release forgets it, global IDs never reset/reuse.
; 16 qwords: id,win,start,tcp_deadline,channel_deadline,done,reason,state,error,
; ip_wire,port,session,first_ready,last_tick,local_port,sequence. All times us.
TERM_OBS_SIZE equ 128
TERM_OBS_SEQ equ 120

; R12 exact live instance pointer -> RAX record or zero. No TI dereference until
; membership/alignment is checked. Clobbers RAX/RCX/RDX only.
term_ssh_observation_ptr:
    mov  rcx, [rel term_instances_ptr]
    test rcx, rcx
    jz   .none
    mov  rax, r12
    sub  rax, rcx
    jc   .none
    cmp  rax, TERM_MAX * TI_SIZE
    jae  .none
    xor  edx, edx
    mov  ecx, TI_SIZE
    div  rcx
    test rdx, rdx
    jnz  .none
    shl  rax, 7
    lea  rcx, [rel term_ssh_observations]
    add  rax, rcx
    ret
.none:
    xor  eax, eax
    ret

; RDI actual clock captured when the existing caller set its deadlines. Called
; after lookup_deadline preserves the earlier DNS/ARP total ceiling.
term_ssh_observation_begin:
    push rbx
    mov  r8, rdi
    call term_ssh_observation_ptr
    test rax, rax
    jz   .out
    mov  rbx, rax
    inc  qword [rbx + TERM_OBS_SEQ]
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, 15
    rep  stosq
    mov  rax, [rel term_ssh_observation_id]
    cmp  rax, -1
    je   .publish                       ; saturation disables evidence, never SSH
    inc  rax
    mov  [rel term_ssh_observation_id], rax
    mov  [rbx], rax
    mov  eax, [r12 + TI_WIN]
    mov  [rbx + 8], rax
    mov  [rbx + 16], r8
    mov  rax, [r12 + TI_NEXTTRY]
    mov  [rbx + 24], rax
    mov  rax, [r12 + TI_DEADLINE]
    mov  [rbx + 32], rax
    movzx eax, byte [rel ssh_cli_state]
    mov  [rbx + 56], rax
    movzx eax, byte [rel ssh_cli_error]
    mov  [rbx + 64], rax
    mov  eax, [r12 + TI_DIALIP]
    mov  [rbx + 72], rax
%ifdef PAOS_TERMINAL_SSH
    movzx eax, word [rel ssh_cli_target_port]
%else
    xor  eax, eax                       ; absent client can never attach
%endif
    mov  [rbx + 80], rax
%ifdef PAOS_TERMINAL_SSH
    mov  eax, [rel ssh_cli_lport]        ; actual random tuple, never a fixture port
%else
    xor  eax, eax
%endif
    mov  [rbx + 112], rax
    mov  eax, [r12 + TI_SESS]
    mov  [rbx + 88], rax
.publish:
    inc  qword [rbx + TERM_OBS_SEQ]
.out:
    pop  rbx
    ret

; Called immediately after the existing session_use. Capture actual state and
; ready tick, without driving the client or inferring TCP/channel completion.
term_ssh_observation_tick:
    push rbx
    call term_ssh_observation_ptr
    test rax, rax
    jz   .out
    mov  rbx, rax
    cmp  qword [rbx], 0
    je   .out
    cmp  qword [rbx + 40], 0
    jne  .out
    inc  qword [rbx + TERM_OBS_SEQ]
    movzx eax, byte [rel ssh_cli_state]
    mov  [rbx + 56], rax
    movzx eax, byte [rel ssh_cli_error]
    mov  [rbx + 64], rax
    call time_monotonic_now_us
    mov  [rbx + 104], rax
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .publish
    cmp  qword [rbx + 96], 0
    jne  .publish
    mov  [rbx + 96], rax
.publish:
    inc  qword [rbx + TERM_OBS_SEQ]
.out:
    pop  rbx
    ret

; EDI actual detach branch: 1 TCP caller ceiling, 2 channel/exec caller ceiling,
; 3 native SSH failure, 5 clean close. Generic detach defaults to reason4.
term_ssh_observation_reason:
    call term_ssh_observation_ptr
    test rax, rax
    jz   .out
    cmp  qword [rax], 0
    je   .out
    cmp  qword [rax + 40], 0
    jne  .out
    inc  qword [rax + TERM_OBS_SEQ]
    mov  [rax + 48], rdi
    inc  qword [rax + TERM_OBS_SEQ]
.out:
    ret

; Only after actual session_end and TI detach. This is caller detachment, NOT
; proof that asynchronous TCP/session retirement has completed.
term_ssh_observation_detached:
    push rbx
    call term_ssh_observation_ptr
    test rax, rax
    jz   .out
    mov  rbx, rax
    cmp  qword [rbx], 0
    je   .out
    cmp  qword [rbx + 40], 0
    jne  .out
    inc  qword [rbx + TERM_OBS_SEQ]
    cmp  qword [rbx + 48], 0
    jne  .clock
    mov  qword [rbx + 48], 4
.clock:
    call time_monotonic_now_us
    mov  [rbx + 40], rax
    inc  qword [rbx + TERM_OBS_SEQ]
.out:
    pop  rbx
    ret

term_ssh_observation_forget:
    call term_ssh_observation_ptr
    test rax, rax
    jz   .out
    inc  qword [rax + TERM_OBS_SEQ]
    mov  qword [rax], 0
    inc  qword [rax + TERM_OBS_SEQ]
.out:
    ret

; R12 current instance, RDI distinct writable out128 -> 0 stable record,
; -1 no current event, -2 writer busy/changed. Failure clears the complete output.
; Single bounded copy, no locks/spin/time/session/TCP/UI calls. RDI/RSI preserved.
term_ssh_observation_copy:
    push rbx
    push rdi
    push rsi
    test rdi, rdi
    jz   .null
    mov  r8, rdi
    xor  eax, eax
    mov  ecx, 16
    rep  stosq
    call term_ssh_observation_ptr
    test rax, rax
    jz   .none
    mov  rbx, rax
    mov  r9, [rbx + TERM_OBS_SEQ]
    test r9b, 1
    jnz  .busy
    cmp  byte [r12 + TI_USED], 1
    jne  .none
    cmp  qword [rbx], 0
    je   .none
    mov  eax, [r12 + TI_WIN]
    cmp  [rbx + 8], rax
    jne  .none
    mov  rsi, rbx
    mov  rdi, r8
    mov  ecx, 16
    rep  movsq
    cmp  r9, [rbx + TERM_OBS_SEQ]
    jne  .busy
    mov  rax, [r8]
    cmp  rax, [rbx]
    jne  .busy
    xor  eax, eax
    jmp  .out
.busy:
    mov  rdi, r8
    xor  eax, eax
    mov  ecx, 16
    rep  stosq
    mov  eax, -2
    jmp  .out
.none:
    mov  eax, -1
    jmp  .out
.null:
    mov  eax, -1
.out:
    pop  rsi
    pop  rdi
    pop  rbx
    ret

; Existing owner TERMFEED @SSHOBS projection of a stable copy. RDI is text after
; keyword (existing term_prefix may consume one separating space); EAX4 malformed,
; 0 valid (including explicit missing/busy STATUS).
term_ssh_observation_feed:
    push rbx
    push r13
    cmp  byte [rdi], 0
    jne  .bad
    sub  rsp, TERM_OBS_SIZE
    mov  rdi, rsp
    call term_ssh_observation_copy
    mov  ebx, eax
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_ssh_observation_header]
    call grid_out_str
    ; STATUS is unsigned:0 available,1missing,2busy. No negative decimal ABI.
    neg  ebx
    mov  edi, ebx
    call grid_out_dec
    xor  r13d, r13d
.fields:
    lea  rax, [rel term_ssh_observation_names]
    mov  rdi, [rax + r13*8]
    call grid_out_str
    mov  rdi, [rsp + r13*8]
    call grid_out_dec
    inc  r13d
    cmp  r13d, 15
    jb   .fields
    add  rsp, TERM_OBS_SIZE
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 4
.out:
    pop  r13
    pop  rbx
    ret

term_ssh_observation_header: db ' SSHOBS=1 STATUS=',0
term_ssh_observation_names:
    dq .id,.win,.start,.tcp,.channel,.done,.reason,.state,.error,.ip,.port,.session,.ready,.tick,.lport
.id: db ' ID=',0
.win: db ' WIN=',0
.start: db ' START_US=',0
.tcp: db ' TCP_US=',0
.channel: db ' CHANNEL_US=',0
.done: db ' DONE_US=',0
.reason: db ' REASON=',0
.state: db ' STATE=',0
.error: db ' ERROR=',0
.ip: db ' IP=',0
.port: db ' PORT=',0
.session: db ' SESSION=',0
.ready: db ' READY_US=',0
.tick: db ' TICK_US=',0
.lport: db ' LPORT=',0

%include "core/abi/wdata.inc"
%macro WDATA_gui_terminal_ssh_observation_0 0
align 8
term_ssh_observation_id: dq 0
term_ssh_observations: times TERM_MAX * TERM_OBS_SIZE db 0
%endmacro
WDATA_DEFER WDATA_gui_terminal_ssh_observation_0
