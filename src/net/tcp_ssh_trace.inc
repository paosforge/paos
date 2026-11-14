; Owner opt-in initial SSH KEX timing. All producers/control run on the existing
; BSP command/network pump. Observation never drives TCP/SSH decisions.
; No payload, key, hash, IP, pointer, principal or authentication material.
; Records: monotonic us, SSH connection serial, event, byte count/peer port,
; original TCB slot. First 256 retained, no overwrite. All state is boot RAM.
TCP_SSH_TRACE_MAX equ 256
TCP_SSH_TRACE_US equ 120000000

; Preserve ALL GPRs and flags: insertion cannot affect the observed operation.
; Off by default: no clock call, allocation, output, lock or protocol work.
; RDI=TCB, ESI=event, EDX=nonsecret count, RCX=serial for event1 only.
tcp_ssh_trace_event:
    pushfq
    cmp  byte [rel tcp_ssh_trace_enabled], 1
    jne  .quiet
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    call tcp_ssh_trace_event_inner
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.quiet:
    popfq
    ret

; Internal scratch ABI; only called by the complete preservation wrapper.
tcp_ssh_trace_event_inner:
    mov  rbx, rdi
    mov  r14d, esi
    mov  r15d, edx
    mov  rbp, rcx
    call tcp_rx_ptr                     ; validates exact table-slot address
    test rax, rax
    jz   .out
    cmp  byte [rbx + TCB_STATE], TCP_ESTABLISHED
    jne  .out
    cmp  word [rbx + TCB_LOCAL_PORT], 22
    jne  .out
    mov  r10, [rax + OO_EPOCH]
    test r10, r10
    jz   .out
    mov  r12, rbx
    lea  rax, [rel tcp_tcbs]
    sub  r12, rax
    shr  r12, 7
    imul r13, r12, 40
    lea  rax, [rel tcp_ssh_trace_slots]
    add  r13, rax
    cmp  r14d, 1                        ; accepted native SSH incarnation
    jne  .existing
    test rbp, rbp
    jz   .out
    mov  [r13], rbp
    mov  [r13 + 8], r10
    mov  qword [r13 + 16], 0            ; phase before ECDH computation
    mov  qword [r13 + 24], 0            ; accepted-send sequence frontier
    mov  qword [r13 + 32], 0            ; reply bytes not yet driver-accepted
    jmp  .stamp
.existing:
    cmp  [r13 + 8], r10                 ; never borrow a reused TCP slot
    jne  .out
    cmp  qword [r13], 0
    je   .out
    cmp  r14d, 4
    je   .computed
    cmp  r14d, 5
    je   .queued
    cmp  r14d, 6
    je   .send
    cmp  r14d, 7
    je   .send
    cmp  r14d, 2
    je   .stamp
    cmp  r14d, 3
    jne  .out
    jmp  .stamp
.computed:
    mov  qword [r13 + 16], 1
    jmp  .stamp
.queued:
    cmp  qword [r13 + 16], 1
    jne  .out
    test r15d, r15d
    jz   .out
    mov  qword [r13 + 16], 2
    mov  eax, [rbx + TCB_SEND_NEXT]
    mov  [r13 + 24], rax
    mov  [r13 + 32], r15
    jmp  .stamp
.send:
    cmp  qword [r13 + 16], 2
    jne  .out
    test r15d, r15d                     ; ACK-only frames are not reply sends
    jz   .out
    mov  eax, [rbx + TCB_SEND_NEXT]
    cmp  eax, [r13 + 24]                ; retransmitted old bytes don't advance
    jne  .out
.stamp:
    call tcp_ssh_trace_clock
    test rax, rax
    jz   .out
    mov  rcx, [rel tcp_ssh_trace_used]
    cmp  rcx, TCP_SSH_TRACE_MAX
    jae  .full
    imul rcx, rcx, 40
    lea  rdi, [rel tcp_ssh_trace_records]
    add  rdi, rcx
    mov  [rdi], rax
    mov  rax, [r13]
    mov  [rdi + 8], rax
    mov  [rdi + 16], r14
    mov  [rdi + 24], r15
    mov  [rdi + 32], r12
    inc  qword [rel tcp_ssh_trace_used]
    jmp  .advance
.full:
    cmp  qword [rel tcp_ssh_trace_dropped], -1
    je   .advance
    inc  qword [rel tcp_ssh_trace_dropped]
.advance:
    cmp  r14d, 6
    jne  .out
    add  [r13 + 24], r15d               ; modulo TCP sequence space
    cmp  [r13 + 32], r15
    jbe  .finished
    sub  [r13 + 32], r15
    ret
.finished:
    mov  qword [r13], 0                 ; no subsequent auth/exec observation
.out:
    ret

; RAX=valid time or0. Zero/backward/expiry disables observation only.
tcp_ssh_trace_clock:
    call time_monotonic_now_us
    test rax, rax
    jz   .disable
    cmp  rax, [rel tcp_ssh_trace_last]
    jb   .disable
    cmp  rax, [rel tcp_ssh_trace_deadline]
    jae  .disable
    mov  [rel tcp_ssh_trace_last], rax
    ret
.disable:
    mov  qword [rel tcp_ssh_trace_enabled], 0
    xor  eax, eax
    ret

; Private adapter ABI; authority is enforced by SSHPRETRACE's consumed-owner
; handler. EDI=0 off/preserve,1 arm/reset,2..257 read record0..255.
; RSI=80B destination: version,enabled,used,dropped,deadline,then record40B.
; RAX=0/-1; invalid op/clock on arm writes no destination or product state.
tcp_ssh_trace_control:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    cmp  ebx, TCP_SSH_TRACE_MAX + 1
    ja   .bad
    test ebx, ebx
    jz   .off
    cmp  ebx, 1
    jne  .read
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    mov  r13, rax
    add  rax, TCP_SSH_TRACE_US
    jc   .bad
    mov  qword [rel tcp_ssh_trace_enabled], 0
    mov  [rel tcp_ssh_trace_deadline], rax
    mov  [rel tcp_ssh_trace_last], r13
    mov  qword [rel tcp_ssh_trace_used], 0
    mov  qword [rel tcp_ssh_trace_dropped], 0
    lea  rdi, [rel tcp_ssh_trace_slots]
    xor  esi, esi
    mov  edx, TCP_TCB_N * 40 + TCP_SSH_TRACE_MAX * 40
    call memset
    mov  qword [rel tcp_ssh_trace_enabled], 1
    jmp  .snapshot
.off:
    mov  qword [rel tcp_ssh_trace_enabled], 0
    jmp  .snapshot
.read:
    cmp  byte [rel tcp_ssh_trace_enabled], 1
    jne  .snapshot
    call tcp_ssh_trace_clock
.snapshot:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 80
    call memset
    mov  qword [r12], 1
    mov  rax, [rel tcp_ssh_trace_enabled]
    mov  [r12 + 8], rax
    mov  rax, [rel tcp_ssh_trace_used]
    mov  [r12 + 16], rax
    mov  rax, [rel tcp_ssh_trace_dropped]
    mov  [r12 + 24], rax
    mov  rax, [rel tcp_ssh_trace_deadline]
    mov  [r12 + 32], rax
    sub  ebx, 2
    jc   .ok
    cmp  rbx, [rel tcp_ssh_trace_used]
    jae  .ok
    imul rbx, rbx, 40
    lea  rsi, [rel tcp_ssh_trace_records]
    add  rsi, rbx
    lea  rdi, [r12 + 40]
    mov  edx, 40
    call memcpy
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_tcp_ssh_trace 0
alignb 8
tcp_ssh_trace_enabled: resq 1
tcp_ssh_trace_used: resq 1
tcp_ssh_trace_dropped: resq 1
tcp_ssh_trace_deadline: resq 1
tcp_ssh_trace_last: resq 1
tcp_ssh_trace_slots: resb TCP_TCB_N * 40
tcp_ssh_trace_records: resb TCP_SSH_TRACE_MAX * 40
%endmacro
