; Actual preconnect CID refusal, before native argument parsing/TCP. Separate
; public record: no endpoint, session tuple or synthetic lifecycle deadlines.
; 128B: ID,WIN,AT_US,RESULT,STATE,ERROR,CHECK,AUTH_CALLS,FP32,reserved24,SEQ.
TERM_START_OBS_SIZE equ 128
TERM_START_OBS_SEQ equ 120

; Same validated instance mapping as the legacy record, independent sequence.
term_ssh_start_observation_ptr:
    call term_ssh_observation_ptr
    test rax, rax
    jz   .out
    lea  rcx, [rel term_ssh_observations]
    sub  rax, rcx
    lea  rcx, [rel term_ssh_start_observations]
    add  rax, rcx
.out:
    ret

term_ssh_start_observation_forget:
    call term_ssh_start_observation_ptr
    test rax, rax
    jz   .out
    inc  qword [rax + TERM_START_OBS_SEQ]
    mov  qword [rax], 0
    inc  qword [rax + TERM_START_OBS_SEQ]
.out:
    ret

; EAX actual connect_start return, current selected client still loaded and
; session_end not yet called. Capture the real early CID branch only. Preserve
; return/callee-saved registers; never drive or retry a client/session action.
term_ssh_start_observation_record:
    push rax
    push rbx
%ifdef PAOS_TERMINAL_SSH
    cmp  eax, -10
    jne  .out
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    jne  .out
    cmp  byte [rel ssh_cli_error], 17
    jne  .out
    call term_ssh_start_observation_ptr
    test rax, rax
    jz   .out
    mov  rbx, rax
    inc  qword [rbx + TERM_START_OBS_SEQ]
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, 15
    rep  stosq
    mov  rax, [rel term_ssh_observation_id]
    cmp  rax, -1
    je   .publish                       ; exhausted evidence IDs never stop SSH
    inc  rax
    mov  [rel term_ssh_observation_id], rax
    mov  [rbx], rax
    mov  eax, [r12 + TI_WIN]
    mov  [rbx + 8], rax
    call time_monotonic_now_us
    mov  [rbx + 16], rax
    mov  eax, [rsp + 8]                 ; original native return, not a guessed code
    neg  eax
    mov  [rbx + 24], rax
    movzx eax, byte [rel ssh_cli_state]
    mov  [rbx + 32], rax
    movzx eax, byte [rel ssh_cli_error]
    mov  [rbx + 40], rax
    lea  rsi, [rel ssh_cli_key_check]
    lea  rdi, [rbx + 48]
    mov  ecx, 6                         ; actual CHECK/AUTH_CALLS/public digest
    rep  movsq
.publish:
    inc  qword [rbx + TERM_START_OBS_SEQ]
%endif
.out:
    pop  rbx
    pop  rax
    ret

; R12 current instance, RDI distinct writable out128. Single bounded copy;
; 0 stable, -1 missing, -2 busy. All unavailable output bytes are zero.
term_ssh_start_observation_copy:
    push rbx
    push rdi
    push rsi
    test rdi, rdi
    jz   .null
    mov  r8, rdi
    xor  eax, eax
    mov  ecx, 16
    rep  stosq
    call term_ssh_start_observation_ptr
    test rax, rax
    jz   .none
    mov  rbx, rax
    mov  r9, [rbx + TERM_START_OBS_SEQ]
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
    cmp  r9, [rbx + TERM_START_OBS_SEQ]
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

; Existing owner TERMFEED exact public projection. No clock/network/session
; action here. STATUS0 available,1 missing,2 busy; unavailable tail all zero.
term_ssh_start_observation_feed:
    push rbx
    push r13
    cmp  byte [rdi], 0
    jne  .bad
    sub  rsp, TERM_START_OBS_SIZE
    mov  rdi, rsp
    call term_ssh_start_observation_copy
    mov  ebx, eax
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_ssh_start_observation_header]
    call grid_out_str
    neg  ebx
    mov  edi, ebx
    call grid_out_dec
    xor  r13d, r13d
.fields:
    lea  rax, [rel term_ssh_start_observation_names]
    mov  rdi, [rax + r13*8]
    add  rdi, rax                       ; table-relative offset -> live image pointer
    call grid_out_str
    mov  rdi, [rsp + r13*8]
    call grid_out_dec
    inc  r13d
    cmp  r13d, 8
    jb   .fields
    lea  rdi, [rel term_ssh_key_observation_fp]
    call grid_out_str
    xor  r13d, r13d
.hex:
    movzx eax, byte [rsp + r13 + 64]
    shr  eax, 4
    lea  rbx, [rel term_ssh_key_observation_hex]
    movzx edi, byte [rbx + rax]
    call grid_out_char
    movzx eax, byte [rsp + r13 + 64]
    and  eax, 15
    movzx edi, byte [rbx + rax]
    call grid_out_char
    inc  r13d
    cmp  r13d, 32
    jb   .hex
    add  rsp, TERM_START_OBS_SIZE
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 4
.out:
    pop  r13
    pop  rbx
    ret

term_ssh_start_observation_header: db ' SSHSTARTOBS=1 STATUS=',0
; Immutable relative offsets: flat org0 images have no ELF data relocation.
term_ssh_start_observation_names:
    dq .id-term_ssh_start_observation_names,.win-term_ssh_start_observation_names,.at-term_ssh_start_observation_names
    dq .result-term_ssh_start_observation_names,.state-term_ssh_start_observation_names,.error-term_ssh_start_observation_names
    dq .check-term_ssh_start_observation_names,.auth-term_ssh_start_observation_names
.id: db ' ID=',0
.win: db ' WIN=',0
.at: db ' AT_US=',0
.result: db ' RESULT=',0
.state: db ' STATE=',0
.error: db ' ERROR=',0
.check: db ' CHECK=',0
.auth: db ' AUTH_CALLS=',0

%include "core/abi/wdata.inc"
%macro WDATA_gui_terminal_ssh_start_observation_0 0
align 8
term_ssh_start_observations: times TERM_MAX * TERM_START_OBS_SIZE db 0
%endmacro
WDATA_DEFER WDATA_gui_terminal_ssh_start_observation_0
