; Passive, bounded observation of the ORIGINAL ingress, never an admission mode.
; A busy witness skips observation only. No product lock/state/result depends on it.
; Exact <=80-byte RX spans only: larger frames are not represented as complete.
; Record: seq,u64 length,u64 return,u32 stage/pre/post/txflags/send/recv/candidate/
; retained-before/retained-at-admission/reserved,u64 boot-ms,80 before,80 after.
; Stages1=entry,2=owned bounded IP,3=IP checksum,4=options,5=TCP checksum,
; 6=lock+owned destination,7=matching tuple,8=qualified SYN_SENT commit.
%macro TCP_INGRESS_OBSERVE_STAGE 1
    mov r11, [rsp+40]
    test r11, r11
    jz %%done
    mov dword [r11+24], %1
%%done:
%endmacro

tcp_ingress_observation_begin:
    test rdi, rdi
    jz .absent
    cmp rsi, 14
    jb .absent
    cmp rsi, 80
    ja .absent
    mov al, 1
    xchg al, byte [rel tcp_ingress_observation_lock]
    test al, al
    jnz .absent
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    lea rbx, [rel tcp_ingress_observation_state]
    mov rdi, rbx
    xor esi, esi
    mov edx, 232
    call memset
    inc qword [rel tcp_ingress_observation_generation]
    mov rax, [rel tcp_ingress_observation_generation]
    mov [rbx], rax
    mov [rbx+8], r13
    mov dword [rbx+24], 1
    mov dword [rbx+28], 255
    mov dword [rbx+32], 255
    call boot_ms_now
    mov [rbx+64], rax
    lea rdi, [rbx+72]
    mov rsi, r12
    mov rdx, r13
    call memcpy
    mov rax, rbx
    pop r13
    pop r12
    pop rbx
    ret
.absent:
    xor eax, eax
    ret

tcp_ingress_observation_end:
    ; RDI=own record or0, RSI=original caller-owned frame, RDX=actual return.
    test rdi, rdi
    jz .done
    push rbx
    mov rbx, rdi
    mov [rbx+16], rdx
    lea rdi, [rbx+152]
    mov rdx, [rbx+8]
    call memcpy
    mov byte [rel tcp_ingress_observation_lock], 0
    pop rbx
.done:
    ret

tcp_ingress_observation_snapshot:
    ; RDI=232-byte destination. 0=busy/absent, else actual never-reused sequence.
    ; Copy is read-only and bounded; no live TCB or parser invocation is made.
    mov al, 1
    xchg al, byte [rel tcp_ingress_observation_lock]
    test al, al
    jnz .absent
    push rbx
    mov rbx, [rel tcp_ingress_observation_state]
    test rbx, rbx
    jz .release
    lea rsi, [rel tcp_ingress_observation_state]
    mov edx, 232
    call memcpy
.release:
    mov byte [rel tcp_ingress_observation_lock], 0
    mov rax, rbx
    pop rbx
    ret
.absent:
    xor eax, eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_tcp_ingress_observation 0
alignb 8
tcp_ingress_observation_generation: resq 1
tcp_ingress_observation_lock: resb 1
alignb 8
tcp_ingress_observation_state: resb 232
%endmacro
