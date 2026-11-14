;; MODULE core/normal_deadman
;; LAYER 1
;; EXPORTS normal_deadman_arm, normal_deadman_heartbeat, normal_deadman_irq, normal_deadman_fault, normal_deadman_state, normal_deadman_interval_tsc, normal_deadman_last_tsc, normal_deadman_expired_tsc
;; IMPORTS
;; CAPS
;; OWNER saga:boot
; BSP-only fixed TSC lease. No IRQ/worker may renew it. Aligned qword stores
; are atomic on x86-64; IRQ sees either old or new heartbeat, never torn bytes.
; No lock, allocation, firmware, serial output or timer programming here.
; State is monotonic 0 disabled -> 1 armed -> 2 expired. No disarm/rearm ABI.
normal_deadman_arm:
    cmp byte [rel normal_deadman_state],0
    jne .refuse
    test rsi,rsi
    jz .refuse
    js .refuse                         ; interval strictly below 2^63
    mov [rel normal_deadman_interval_tsc],rsi
    mov [rel normal_deadman_last_tsc],rdi
    mov byte [rel normal_deadman_state],1 ; publish only fully initialized lease
    xor eax,eax
    ret
.refuse:
    mov eax,-1
    ret

; RDI=now. An overdue live pass cannot erase a missed deadline. Return -1;
; the next independent IRQ owns the actual fault, even if live code resumes.
normal_deadman_heartbeat:
    cmp byte [rel normal_deadman_state],1
    jne .refuse
    mov rax,rdi
    sub rax,[rel normal_deadman_last_tsc]
    cmp rax,[rel normal_deadman_interval_tsc]
    jae .refuse
    mov [rel normal_deadman_last_tsc],rdi
    xor eax,eax
    ret
.refuse:
    mov eax,-1
    ret

; RDI=now from the BSP's existing PIT or LAPIC IRQ, before blocking callbacks.
; Unsigned modular elapsed supports TSC wrap. A backwards TSC expires rather
; than silently renewing. Only this path can reach the dedicated UD2 address.
normal_deadman_irq:
    cmp byte [rel normal_deadman_state],1
    jne .out
    mov rax,rdi
    sub rax,[rel normal_deadman_last_tsc]
    cmp rax,[rel normal_deadman_interval_tsc]
    jb .out
    mov [rel normal_deadman_expired_tsc],rdi
    mov byte [rel normal_deadman_state],2
    jmp normal_deadman_fault
.out:
    ret
normal_deadman_fault:
    ud2
    jmp normal_deadman_fault            ; expiry never resumes a caller

%include "core/abi/wdata.inc"
%macro WDATA_normal_deadman 0
align 8
normal_deadman_interval_tsc: dq 0
normal_deadman_last_tsc: dq 0
normal_deadman_expired_tsc: dq 0
normal_deadman_state: db 0
%endmacro
WDATA_DEFER WDATA_normal_deadman
