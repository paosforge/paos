;; MODULE boot/native_driver_gate
;; LAYER 0
;; EXPORTS native_driver_gate, native_driver_blocked, native_driver_permitted
;; IMPORTS boot/native_driver_policy, boot/native_driver_preload
;; CAPS
;; OWNER saga:boot
; RDI class, RSI candidate packed PCI BDF. CF=0 allow, CF=1 deny.
; Preserves every GPR, including RAX and original inputs; only flags change.
; No hardware, allocation, logging, lock acquisition, polling or policy mutation.
; Counts are boot-local census, not evidence of ownership or successful probes.
; Unknown kinds contribute to final slot10 and remain denied in boot_only.
native_driver_gate:
    push rax
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, [rel native_driver_selected_policy]
    mov rcx, [rel native_driver_boot_bdf]
    call native_driver_policy_decide
    mov rdx, [rsp + 40]             ; original RDI class
    cmp rdx, 10
    jbe .bounded
    mov edx, 10
.bounded:
    test rax, rax
    jnz .blocked
    lea rcx, [rel native_driver_permitted]
    lock inc qword [rcx + rdx*8]
    jmp .result
.blocked:
    lea rcx, [rel native_driver_blocked]
    lock inc qword [rcx + rdx*8]
.result:
    bt rax, 0                      ; exactly 0/-1 -> carry admission
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_native_driver_gate 0
alignb 8
native_driver_blocked: resq 11
native_driver_permitted: resq 11
%endmacro
WDATA_BSS_DEFER WDATA_native_driver_gate
