;; MODULE sec/adopt_decision
;; LAYER 5
;; PURPOSE Fixed native callback bridge for the one-use local adoption decision.
;; EXPORTS adopt_decision_register, av_adopt_decision_consume
;; IMPORTS core/smp, svc/command, svc/command_auth, sec/session
;; OWNER saga:sec
;; CONTEXT: bsp_only
; FS cannot import a GUI module. Like session's native erasers, this bridge
; holds one immutable composition callback, registered by the original card.
; It holds no decision or password grant. The callback spends the decision
; first, including on a bad context, then revalidates the whole native gesture.
; SEC108140: storage_grant_lint pins registration, callback and consumer sites.

; RDI=original native card consumer -> EAX 1 registered / 0 refused.
adopt_decision_register:
    push rbx
    mov rbx,rdi
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp byte [rel session_injected_input],0
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,[rel adc_consumer]
    test rax,rax
    jz .store
    cmp rax,rbx
    jne .bad
.store:
    mov [rel adc_consumer],rbx
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; FS ABI: RDI=FS's stored snapshot id16 -> EAX 0 valid / -1 refused.
; Do not short-circuit context or id checks here: the callback must spend
; its decision on every call. Its identity cannot change after registration.
av_adopt_decision_consume:
    mov rax,[rel adc_consumer]
    test rax,rax
    jz .bad
    jmp rax
.bad:
    mov eax,-1
    ret

%include "core/abi/wdata.inc"
%macro WDATA_adopt_decision 0
align 8
adc_consumer: dq 0
%endmacro
WDATA_DEFER WDATA_adopt_decision
