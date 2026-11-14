;; MODULE sec/cpu_security_report
;; LAYER 2
;; EXPORTS cpu_security_report_text
;; IMPORTS sec/cpu_security_live, sec/cpu_microcode_boot, sec/ucode_preload, core/lib/fmt
;; CAPS
;; OWNER saga:security
; T1-6: read-only composition for AUDIT CPU and System Properties. The fresh
; sample describes ONLY the calling CPU. The retained update result describes
; ONLY the BSP's earlier boot attempt, never AP coverage or current/fresh
; upstream microcode. A loaded firmware revision is not a PaOS update proof.
; Result0 means applied only when MCB_DONE is exactly1. BSS result0 before the
; boot call is unknown. Fresh sampling uses checked CPU-local I/O (including
; the Intel revision latch clear); no updater, allocation or event is added.
; Policy stays incomplete; observed controls do not attest VM boundaries.
; Trusted serialized BSP consumers, after the early boot state is immutable.
; RDI mapped destination, ESI capacity, EDX0 full / nonzero compact. Returns
; length or -1. Overflow clears byte0; zero capacity/NULL/wrap touches nothing.
; Full includes read reason and before/selected/after (u32 revision values).
; Compact includes the same signed BSP result; both retain current CPU rev.

cpu_security_report_text:
    test esi, esi
    jz   .bad_empty
    test rdi, rdi
    jz   .bad_empty
    mov  eax, esi
    add  rax, rdi
    jc   .bad_empty
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24                       ; private decimal staging, max u64+NUL
    mov  rbx, rdi
    lea  r13, [rax - 1]                 ; reserve final NUL
    mov  ebp, edx
    xor  r14d, r14d                     ; sticky overflow
    call cpu_security_live_text
    test rax, rax
    js   .bad
    lea  r12, [rbx + rax]
    lea  rsi, [rel csr_percpu]
    call cpu_security_report_put
    lea  rsi, [rel csr_result]
    call cpu_security_report_put
    cmp  dword [rel mcb_state + MCB_DONE], 1
    jne  .unknown
    movsxd rdi, dword [rel mcb_state + MCB_RESULT]
    test rdi, rdi
    jns  .result_number
    lea  rsi, [rel csr_minus]
    push rdi
    call cpu_security_report_put
    pop  rdi
    neg  rdi                           ; INT32_MIN widened before negation
.result_number:
    call cpu_security_report_number
    jmp  .details
.unknown:
    lea  rsi, [rel csr_unknown]
    call cpu_security_report_put
.details:
    test ebp, ebp
    jnz  .finish
    lea  rsi, [rel csr_done]
    call cpu_security_report_put
    mov  edi, [rel mcb_state + MCB_DONE]
    call cpu_security_report_number
    lea  rsi, [rel csr_reason]
    call cpu_security_report_put
    mov  edi, [rel ucp_reason]           ; dword, no adjacent padding
    call cpu_security_report_number
    cmp  dword [rel mcb_state + MCB_DONE], 1
    jne  .finish                       ; never expose stale/unrun record cells
    lea  r15, [rel csr_fields]
    mov  ebp, 4
.field:
    mov  eax, [r15]
    lea  rsi, [rel csr_names]
    add  rsi, rax
    call cpu_security_report_put
    mov  eax, [r15 + 4]
    lea  rdx, [rel mcb_state]
    mov  edi, [rdx + rax]               ; all revision/valid cells are u32
    call cpu_security_report_number
    add  r15, 8
    dec  ebp
    jnz  .field
.finish:
    mov  byte [r12], 0
    test r14d, r14d
    jnz  .bad
    mov  rax, r12
    sub  rax, rbx
    jmp  .out
.bad:
    mov  byte [rbx], 0
    mov  rax, -1
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.bad_empty:
    mov  rax, -1
    ret

cpu_security_report_number:
    lea  rsi, [rsp + 8]                 ; caller's private staging
    call fmt_dec
    lea  rsi, [rsp + 8]
    ; fall through, retaining the caller's return address
cpu_security_report_put:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .out
    cmp  r12, r13
    jae  .full
    mov  [r12], al
    inc  r12
    inc  rsi
    jmp  cpu_security_report_put
.full:
    mov  r14d, 1
.out:
    ret

csr_percpu: db " percpu_report=pages64 coverage=incomplete last_pair=historical",0
csr_result: db " ucode_bsp_result=",0
csr_unknown: db "unknown",0
csr_minus: db "-",0
csr_done: db " ucode_bsp_done=",0
csr_reason: db " ucode_read_reason=",0
csr_names:
csr_fwvalid: db " ucode_bsp_fw_valid=",0
csr_fw: db " ucode_bsp_fw=",0
csr_selected: db " ucode_bsp_selected=",0
csr_after: db " ucode_bsp_after=",0
align 4
csr_fields:
    dd csr_fwvalid-csr_names,MCB_SAMPLE+CSS_REV_VALID
    dd csr_fw-csr_names,MCB_SAMPLE+CSS_REV
    dd csr_selected-csr_names,MCB_RECORD+MCS_REV
    dd csr_after-csr_names,MCB_RECORD+MCS_AFTER
