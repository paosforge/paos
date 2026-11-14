;; MODULE hv/vcpu_ap_go
;; LAYER 5
;; EXPORTS vcpu_ap_go_check
;; IMPORTS hv/vcpu_ap_mode, hv/vcpu_ap_controls, hv/vcpu_ap_caps, hv/vcpu_ap_activity, hv/vcpu_ap_frozen
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Per-attempt checks; no persistent entry grant.
; RDI immutable64B descriptor: vCPU1,reset-generation,epoch,GO,VMCS physical,
; EFER feature mask,START23-qword controls pointer,frozen-blob manifest pointer.
; RSI current custody epoch, EDX current GO, RCX current virtual reset generation.
; Caller independently obtains these from the live gang protocol and owns the
; descriptor, VMCS and mapped inputs outside guest EPT. It holds IF0, the live
; park guard and current vCPU1 VMCS. All inputs stay frozen during this call.
; Returns1 active /2 virtual root-idle /0 refuse. No VM entry, VMCS/control write,
; boundary entry or ack; caller still owes fresh DOWN/abort/deadline checks,
; actual activity0 immediately before each physical entry, and clear-before-ack.
; Only stack scratch is written. Current VMCS identity precedes all VMREADs.
vcpu_ap_go_check:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 112                       ; tuple64, actual controls40, VMPTRST8
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    cmp  qword [rbx], 1
    jne  .bad
    test r14, r14
    jz   .bad
    cmp  [rbx + 8], r14
    jne  .bad
    test r12, r12
    jz   .bad
    cmp  [rbx + 16], r12
    jne  .bad
    test r13, r13
    jz   .bad
    cmp  [rbx + 24], r13
    jne  .bad
    mov  rax, [rbx + 32]
    test rax, rax
    jz   .bad
    test rax, 4095
    jnz  .bad
    cmp  qword [rbx + 48], 0
    je   .bad
    cmp  qword [rbx + 56], 0
    je   .bad
    vmptrst [rsp + 104]
    jc   .bad
    jz   .bad
    mov  rax, [rsp + 104]
    cmp  rax, [rbx + 32]
    jne  .bad
    mov  qword [rsp], 1
    mov  [rsp + 8], r12
    mov  [rsp + 16], r13
    xor  r15d, r15d
.mode:
    lea  rax, [rel vap_go_mode_fields]
    mov  edi, [rax + r15*4]
    vmread rax, rdi
    jc   .bad
    jz   .bad
    mov  [rsp + r15*8 + 24], rax
    inc  r15d
    cmp  r15d, 5
    jb   .mode
    mov  rdi, rsp
    mov  rsi, r12
    mov  rdx, r13
    mov  rax, [rbx + 48]
    mov  ecx, [rax + 9*8]               ; START entry, never actual expected mode
    mov  r8, [rbx + 40]
    call vcpu_ap_mode_check
    cmp  eax, 1
    jne  .bad
    mov  rdi, [rbx + 48]
    mov  rsi, [rsp + 40]                ; independently validated actual EFER.LMA
    shr  rsi, 1
    and  esi, 1 << 9
    call vcpu_ap_controls_check
    cmp  eax, 1
    jne  .bad
    mov  rdi, [rbx + 56]
    mov  rsi, r12
    call vcpu_ap_frozen_check
    cmp  eax, 1
    jne  .bad
    xor  r15d, r15d
.caps:
    lea  rax, [rel vap_go_caps_fields]
    mov  edi, [rax + r15*4]
    vmread rax, rdi
    jc   .bad
    jz   .bad
    mov  [rsp + r15*8 + 64], rax        ; actual window/mode bits, not START copy
    inc  r15d
    cmp  r15d, 5
    jb   .caps
    lea  rdi, [rsp + 64]
    call vcpu_ap_caps_check
    cmp  eax, 1
    jne  .bad
    call vcpu_ap_activity_read           ; actual state; never force1/3 to active0
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 112
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
align 4
vap_go_mode_fields:
    dd 0x6800, 0x6804, 0x2806, 0x4816, 0x4012
vap_go_caps_fields:
    dd 0x4000, 0x4002, 0x401E, 0x400C, 0x4012
