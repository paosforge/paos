; Deliberate bounded SSH exec grammar. RDI=owned arguments, ESI=available
; bytes including terminator. Legacy term_ssh_start uses its prior324B bound;
; the actual builtin passes only the remaining extent of TI_LINE.
; Normalize a trusted NUL command-line within its caller-owned available span.
; EAX=exact framed extent including NUL,0 absent/overflow/unterminated.
term_ssh_argument_extent:
    test rdi, rdi
    jz   .bad
    test esi, esi
    jz   .bad
    cmp  esi, TERM_LINE_BUF
    ja   .bad
    mov  rax, rdi
    mov  ecx, esi
    add  rax, rcx
    jc   .bad
    xor  eax, eax
.scan:
    cmp  eax, esi
    jae  .bad
    cmp  byte [rdi + rax], 0
    je   .end
    inc  eax
    jmp  .scan
.end:
    inc  eax
    ret
.bad:
    xor  eax, eax
    ret

term_ssh_command_parse:
    cld
    push rbx
    push r13
    push r14
    push r15
    sub  rsp, 344                       ; target324B + private parse mode/offset
    mov  dword [rsp + 332], 7
    mov  dword [rsp + 336], 0
    mov  r13, rdi
    mov  r14d, esi
    test r13, r13
    jz   .bad
    test r14d, r14d
    jz   .bad
    cmp  r14d, TERM_LINE_BUF
    ja   .bad
    mov  rax, r13
    add  rax, r14
    jc   .bad
    xor  ecx, ecx
.end:
    cmp  ecx, r14d
    jae  .bad
    cmp  byte [r13 + rcx], 0
    je   .terminated
    inc  ecx
    jmp  .end
.terminated:
    lea  eax, [rcx + 1]
    cmp  eax, r14d
    jne  .bad                           ; exact framed input, no hidden/trailing bytes
    mov  r15d, ecx
    cmp  r15d, 7
    jb   .interactive
    cmp  dword [r13], '--ex'
    jne  .interactive
    cmp  word [r13 + 4], 'ec'
    jne  .interactive
    cmp  byte [r13 + 6], ' '
    je   .target_start
    cmp  r15d, 13
    jb   .bad
    cmp  byte [r13 + 6], '-'
    jne  .bad
    cmp  dword [r13 + 7], 'stdi'
    jne  .bad
    cmp  word [r13 + 11], 'n '
    jne  .bad
    mov  dword [rsp + 332], 13
    mov  dword [rsp + 336], 1
.target_start:
    mov  eax, [rsp + 332]
    lea  rbx, [r13 + rax]
    xor  ecx, ecx
    xor  edx, edx
.target:
    mov  eax, ecx
    add  eax, [rsp + 332]
    cmp  eax, r15d
    jae  .bad
    cmp  ecx, 323
    jae  .bad
    mov  al, [rbx + rcx]
    cmp  al, '@'
    jne  .not_at
    inc  edx
.not_at:
    cmp  al, ' '
    je   .delimiter
    cmp  al, 33
    jb   .bad
    cmp  al, 126
    ja   .bad
    mov  [rsp + rcx], al
    inc  ecx
    jmp  .target
.delimiter:
    test ecx, ecx
    jz   .bad
    cmp  edx, 1                         ; exec has one explicit USER@HOST target
    jne  .bad
    lea  eax, [rcx + 4]
    add  eax, [rsp + 332]
    cmp  eax, r15d
    jae  .bad                           ; delimiter plus at least one command byte
    cmp  dword [rbx + rcx], ' -- '
    jne  .bad
    mov  byte [rsp + rcx], 0
    lea  r14, [rbx + rcx + 4]
    add  r13, r15
    sub  r13, r14                       ; command length, not including NUL
    cmp  r13d, TERM_SSH_EXEC_CAP
    ja   .bad
    cmp  byte [r14], ' '
    je   .bad
    cmp  byte [r14 + r13 - 1], ' '
    je   .bad
    xor  ecx, ecx
.command:
    mov  al, [r14 + rcx]
    cmp  al, 32
    jb   .bad
    cmp  al, 126
    ja   .bad
    inc  ecx
    cmp  ecx, r13d
    jb   .command
    mov  rdi, rsp
    call term_ssh_lookup_parse           ; unchanged numeric/DNS target rules
    cmp  eax, -1
    je   .bad
    mov  r15d, eax
    call term_ssh_lookup_ptr
    mov  rbx, rax
    lea  rdi, [rbx + TS_EXEC_CMD]
    mov  rsi, r14
    mov  edx, r13d
    call memcpy
    mov  [rbx + TS_EXEC_LEN], r13d
    mov  edx, [rsp + 336]
    mov  [rbx + TS_EXEC_STREAM], edx
    mov  eax, r15d
    jmp  .out
.interactive:
    mov  rdi, r13
    call term_ssh_lookup_parse
    jmp  .out
.bad:
    call term_ssh_lookup_ptr
    mov  rdi, rax
    xor  esi, esi
    mov  edx, TS_SIZE
    call memset                         ; no stale command/intent survives any parser refusal
    mov  eax, -1
.out:
    add  rsp, 344
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

term_ssh_exec_forget:
    call term_ssh_lookup_ptr
    lea  rdi, [rax + TS_EXEC_LEN]
    xor  esi, esi
    mov  edx, TS_SIZE - TS_EXEC_LEN
    jmp  memset

; The window's original generation and the native caller token must both live.
term_ssh_exec_token:
    push rbx
    cmp  byte [r12 + TI_SSH], 1
    jne  .bad
    call term_ssh_lookup_ptr
    mov  rbx, rax
    cmp  dword [rbx + TS_EXEC_USED], 1
    jne  .bad
    mov  eax, [r12 + TI_SESS]
    cmp  eax, [rbx + TS_EXEC_SESSION]
    jne  .bad
    call term_inst_index
    cmp  eax, TERM_MAX
    jae  .bad
    lea  rdx, [rel term_paste_generations]
    mov  rdx, [rdx + rax*8]
    cmp  rdx, [rbx + TS_EPOCH]
    jne  .bad
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    mov  rax, [rbx + TS_EXEC_TOKEN]
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Actual GUI key path. Clipboard chords run first in terminal_key_hook; this
; path has no PTY key encoding, mouse reports, bracketed paste or implicit ^C.
term_ssh_exec_key:
    mov  esi, TERM_SSH_EXEC_KEY
    call term_ssh_input_ok
    test eax, eax
    jz   .out
    call term_ssh_exec_token
    test rax, rax
    jz   .out
    mov  rdi, rax
    mov  eax, r14d
    and  eax, 7
    cmp  eax, 5                       ; Ctrl+Shift, no Alt: deliberate owner control
    jne  .data
    cmp  r13d, 0x04
    je   .eof
    cmp  r13d, 0x18
    je   .int
    cmp  r13d, 0x14
    je   .term
    cmp  r13d, 0x11
    je   .cancel
.data:
    test r14d, 6                      ; Alt/Ctrl bytes are never shell control in exec
    jnz  .out
    push rdi
    call ssh_cli_exec_status
    test eax, 1                       ; default no-stdin exec remains quiet
    pop  rdi
    jz   .out
    cmp  eax, -1
    je   .out
    mov  eax, r13d
    cmp  eax, GUI_KEY_ENTER
    je   .lf
    cmp  eax, GUI_KEY_TAB
    je   .tab
    cmp  eax, GUI_KEY_BACKSPACE
    je   .backspace
    cmp  eax, 32
    jb   .out
    cmp  eax, 126
    ja   .out
    jmp  .byte
.lf:
    mov  eax, 10
    jmp  .byte
.tab:
    mov  eax, 9
    jmp  .byte
.backspace:
    mov  eax, 127
.byte:
    mov  [rel term_keybuf], al
    lea  rsi, [rel term_keybuf]
    mov  edx, 1
    call ssh_cli_exec_stdin
    jmp  term_ssh_exec_result
.eof:
    call ssh_cli_exec_close_stdin
    test eax, eax
    jnz  term_ssh_exec_result
    lea  rsi, [rel term_ssh_exec_close_queued]
    jmp  term_out_cstr
.int:
    mov  esi, 1
    jmp  .signal
.term:
    mov  esi, 2
.signal:
    call ssh_cli_exec_signal
    test eax, eax
    jnz  term_ssh_exec_result
    lea  rsi, [rel term_ssh_exec_signal_queued]
    jmp  term_out_cstr
.cancel:
    call ssh_cli_exec_cancel
    test eax, eax
    jnz  term_ssh_exec_result
    call term_session_reset
    call term_ssh_detach
    lea  rsi, [rel term_ssh_exec_cancelled]
    call term_out_cstr
    jmp  term_prompt
.out:
    ret

; One original text event, copied atomically by the token-bound client API.
term_ssh_exec_text:
    push r13
    push r14
    mov  r13, rdi
    mov  r14d, esi
    test r14d, r14d
    jz   .out
    cmp  r14d, WGT_TEXT_CAP
    ja   .out
    mov  esi, TERM_SSH_EXEC_KEY
    call term_ssh_input_ok
    test eax, eax
    jz   .out
    call term_ssh_exec_token
    test rax, rax
    jz   .out
    mov  rdi, rax
    mov  rsi, r13
    mov  edx, r14d
    call ssh_cli_exec_stdin
    call term_ssh_exec_result
.out:
    pop  r14
    pop  r13
    ret

term_ssh_exec_result:
    test eax, eax
    jz   .out
    lea  rsi, [rel term_ssh_exec_full]
    cmp  eax, 1
    je   term_out_cstr
    lea  rsi, [rel term_ssh_exec_closed]
    cmp  eax, 2
    je   term_out_cstr
    lea  rsi, [rel term_ssh_exec_control_refused]
    jmp  term_out_cstr
.out:
    ret

; WM lock is trusted local revocation, never an input origin or a remote ACK.
term_ssh_exec_lock:
    call term_ssh_exec_token
    test rax, rax
    jz   .out
    mov  rdi, rax
    call ssh_cli_exec_cancel
    call term_session_reset
    call term_ssh_detach
    lea  rsi, [rel term_ssh_exec_cancelled]
    call term_out_cstr
    call term_prompt
.out:
    ret
