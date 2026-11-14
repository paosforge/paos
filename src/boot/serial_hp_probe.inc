; Included by boot/serial. A real, bounded operation on the selected HP UART.
; RDI=fresh nonce. EAX=0 completed,1 unavailable,2 busy,3 hardware timeout;
; EDX=accepted bytes, ECX=last LSR. Never programs the UART or consumes RX.
; One canonical lock try, no FIFO/capture substitution. THRE precedes every
; THR write and TEMT|THRE must be observed after the final byte. No claim of
; remote reception or cable continuity. Callee-saved registers/IF preserved.
serial_hp_transmit_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  rbx, rdi
    xor  r12d, r12d
    xor  r13d, r13d
    mov  r15d, 1
    cmp  byte [rel serial_available], 1
    jne  .out
    cmp  byte [rel serial_mode], 1
    jne  .out
    cmp  qword [rel serial_ax_base], 0
    je   .out
    mov  r15d, 2
    call serial_uart_lock_try_acquire
    test eax, eax
    jz   .out
    ; Format 21 bytes on the stack, avoiding recursive serial/fmt calls.
    mov  word [rsp], 'P3'
    mov  byte [rsp + 2], ':'
    mov  r14d, 3
.hex:
    rol  rbx, 4
    mov  eax, ebx
    and  eax, 15
    add  al, '0'
    cmp  al, '9'
    jbe  .digit
    add  al, 'a' - '9' - 1
.digit:
    mov  [rsp + r14], al
    inc  r14d
    cmp  r14d, 19
    jb   .hex
    mov  word [rsp + 19], 0x0a0d
    mov  r15d, 3
.send:
    movzx edi, byte [rsp + r12]
    call serial_ax_tx
    jc   .release
    inc  r12d
    cmp  r12d, 21
    jb   .send
    mov  rdx, [rel serial_ax_base]
    mov  ecx, SERIAL_AX_POLL
.complete:
    mov  r13d, [rdx + SERIAL_AX_LSR]
    mov  eax, r13d
    and  eax, 0x60
    cmp  eax, 0x60                      ; holding register AND shifter empty
    je   .success
    pause
    dec  ecx
    jnz  .complete
    jmp  .release
.success:
    xor  r15d, r15d
.release:
    call serial_uart_lock_release
.out:
    mov  eax, r15d
    mov  edx, r12d
    mov  ecx, r13d
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
