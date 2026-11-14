;; MODULE hv/a1_reset_dispatch
;; LAYER 5
;; EXPORTS a1_reset_dispatch
;; IMPORTS hv/a1_reset_hp, hv/a1_reset_i219, hv/a1_reset_rtl8161, hv/a1_reset_rtl8168h, hv/a1_reset_e5000b
;; CAPS CAP_MMIO
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
%include "hv/a1_reset.inc"

; Internal observation composition ONLY. No runtime caller is added here.
; RDI=resident request320, RSI=private result256, RDX=exact result bytes.
; EAX=R2 status. Inputs/nested pointers must be immutable native custody;
; authenticated owner START, signed policy/hash pins and complete fresh census
; remain caller prerequisites. Checking MODE is not authenticating that mode.
; Nothing here grants attach, reset completion, service-ready or reclaim.
; Only exact family op1 discovery routes are enabled. Dell host quiesce and
; every other mutating operation refuse, with no legacy/family fallback.
; Invalid outer operands leave output untouched; valid ones get a bounded result.
a1_reset_dispatch:
    mov eax, A1_STATUS_REFUSED
    cmp rdx, A1_RS_BYTES
    jne .early
    test rsi, rsi
    jz .early
    test rsi, 7
    jnz .early
    test rdi, rdi
    jz .early
    test rdi, 7
    jnz .early
    mov r8, rsi
    add r8, A1_RS_BYTES
    jc .early
    mov r9, rdi
    add r9, A1_RQ_BYTES
    jc .early
    ; Reject noncanonical endpoints, including ranges crossing the address hole.
    mov rax, rdi
    shl rax, 16
    sar rax, 16
    cmp rax, rdi
    jne .refuse_early
    mov rax, rsi
    shl rax, 16
    sar rax, 16
    cmp rax, rsi
    jne .refuse_early
    lea rcx, [r8-1]
    mov rax, rcx
    shl rax, 16
    sar rax, 16
    cmp rax, rcx
    jne .refuse_early
    lea rcx, [r9-1]
    mov rax, rcx
    shl rax, 16
    sar rax, 16
    cmp rax, rcx
    jne .refuse_early
    cmp rsi, r9
    jae .separate
    cmp rdi, r8
    jb .refuse_early
.separate:
    push r12
    push r13
    sub rsp, 328                     ; request320, SysV call alignment
    mov r13, rsi
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, A1_RQ_BYTES/8
    cld
    rep movsq                       ; stable outer request before any callback
    mov r12, rsp
    mov rdi, r13
    xor eax, eax
    mov ecx, A1_RS_BYTES/8
    rep stosq
    mov dword [r13+A1_RS_MAGIC], 'A1RS'
    mov dword [r13+A1_RS_VERSION], (A1_RS_BYTES<<16)|A1_ABI_VERSION
    mov dword [r13+A1_RS_STATUS], A1_STATUS_REFUSED
    mov dword [r13+A1_RS_REASON], A1_REASON_ENVELOPE
    cmp dword [r12+A1_RQ_MAGIC], 'A1RQ'
    jne .done
    cmp dword [r12+A1_RQ_VERSION], (A1_RQ_BYTES<<16)|A1_ABI_VERSION
    jne .done
    mov eax, [r12+A1_RQ_METHOD]
    mov [r13+A1_RS_METHOD], eax
    mov eax, [r12+A1_RQ_OP]
    mov [r13+A1_RS_OP], eax
    mov eax, [r12+A1_RQ_BDF]
    mov [r13+A1_RS_BDF], eax
    mov rax, [r12+A1_RQ_START]
    mov [r13+A1_RS_START], rax
    mov rax, [r12+A1_RQ_GENERATION]
    mov [r13+A1_RS_GENERATION], rax
    mov rax, [r12+A1_RQ_NONCE]
    mov [r13+A1_RS_NONCE], rax
    mov rax, [r12+A1_RQ_ATTEMPT]
    mov [r13+A1_RS_ATTEMPT], rax
    mov dword [r13+A1_RS_REASON], A1_REASON_BINDING
    cmp dword [r12+A1_RQ_MODE], A1_MODE_TRUSTED_NETWORK
    jne .done
    cmp qword [r12+A1_RQ_RESERVED], 0
    jne .done
    cmp qword [r12+A1_RQ_START], 0
    je .done
    cmp qword [r12+A1_RQ_GENERATION], 0
    je .done
    cmp qword [r12+A1_RQ_NONCE], 0
    je .done
    cmp qword [r12+A1_RQ_ATTEMPT], 0
    je .done
    cmp dword [r12+A1_RQ_INTENT], A1_INTENT_ATTACH
    jb .done
    cmp dword [r12+A1_RQ_INTENT], A1_INTENT_FAILED_ATTACH_UNWIND
    ja .done
    mov dword [r13+A1_RS_REASON], A1_REASON_ROUTE
    cmp dword [r12+A1_RQ_OP], A1_OP_PROBE
    jne .done
    mov rdi, r12
    mov rsi, r13
    mov edx, A1_RS_BYTES
    mov eax, [r12+A1_RQ_METHOD]
    cmp eax, A1_METHOD_HP_PCIE_FLR
    je .hp_probe
    cmp eax, A1_METHOD_HP_VENDOR
    je .hp_probe
    cmp eax, A1_METHOD_DELL_I219
    je .dell_probe
    cmp eax, A1_METHOD_LENOVO_RTL8161
    je .lenovo_probe
    cmp eax, A1_METHOD_BEELINK_RTL8168H
    je .beelink_probe
    cmp eax, A1_METHOD_MSI_E5000B
    jne .done
    call a1_reset_e5000b_probe          ; exact config-only op1; no reset claim
    jmp .done
.beelink_probe:
    call a1_reset_rtl8168h_probe
    jmp .done
.dell_probe:
    call a1_reset_i219_phase           ; op1 only; op2 quiesce is not dispatched
    jmp .done
.lenovo_probe:
    call a1_reset_rtl8161_probe
    jmp .done
.hp_probe:
    call a1_reset_hp_probe
.done:
    mov eax, [r13+A1_RS_STATUS]
    add rsp, 328
    pop r13
    pop r12
    ret
.refuse_early:
    mov eax, A1_STATUS_REFUSED
.early:
    ret
