;; MODULE hv/vcpu_write_guard
;; LAYER 5
;; EXPORTS vcb_write_check
;; IMPORTS hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, hv/vmx
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Central BSP VMCS writer gate for S7.
; READY0 retains the existing one-vCPU ABI. READY1 permits only selected
; guest state/events/timer and the two window bits; all templates, host
; fields, bitmap/MSR-list addresses/counts, EPTP and masks stay frozen.
; The checked private EFER helper owns ENTRY bit9: this general writer
; cannot change ENTRY controls. The per-CPU checked host writer owns HOST.
; This is not the separate EPT-memory writer gate or full C4 census.
; RDI full field encoding, RSI full value -> EAX1 allowed /0 refuse.
; Preserve RDI/RSI and callee-save registers; no VMCS or data writes.
vcb_write_check:
    cmp  qword [rel vca_ready], 0
    je   .ok
    cmp  qword [rel vca_ready], 1
    jne  .bad
    cmp  dword [rel vcb_handoff_active], 1
    ja   .bad
    cmp  byte [rel vcg_root], 1
    jne  .bad
    cmp  byte [rel vcg_root + 1], 1
    jne  .bad
    cmp  qword [rel vca_vmx + VAP_CURRENT], 0
    jne  .bad
    mov  rax, rdi
    shr  rax, 16
    jnz  .bad
    sub  rsp, 8
    vmptrst [rsp]
    jc   .ptr_bad
    jz   .ptr_bad
    mov  rax, [rsp]
    add  rsp, 8
    mov  r8, [rel hv_launch_vmcs_pa]
    cmp  dword [rel vcb_handoff_active], 0
    je   .identity
    mov  r8, [rel vca_vmx + VAP_CS]
.identity:
    test r8, r8
    jz   .bad
    test r8, 4095
    jnz  .bad
    cmp  rax, r8
    jne  .bad
    cmp  edi, 0x4002
    je   .window
    lea  r8, [rel vcb_write_fields]
    mov  ecx, (vcb_write_fields_end - vcb_write_fields) / 2
.field:
    movzx eax, word [r8]
    cmp  rdi, rax
    je   .ok
    add  r8, 2
    dec  ecx
    jnz  .field
.bad:
    xor  eax, eax
    ret
.ptr_bad:
    add  rsp, 8
    jmp  .bad
.window:
    vmread rax, rdi
    jc   .bad
    jz   .bad
    xor  rax, rsi
    test rax, ~((1 << 2) | (1 << 22))
    jnz  .bad
.ok:
    mov  eax, 1
    ret
align 2
vcb_write_fields:
    dw 0x0800,0x0802,0x0804,0x0806,0x0808,0x080A,0x080C,0x080E
    dw 0x2804,0x280A,0x280C,0x280E,0x2810
    dw 0x4016,0x4018,0x401A
    dw 0x4800,0x4802,0x4804,0x4806,0x4808,0x480A,0x480C,0x480E
    dw 0x4810,0x4812,0x4814,0x4816,0x4818,0x481A,0x481C,0x481E
    dw 0x4820,0x4822,0x4824,0x4826,0x482A,0x482E
    dw 0x6800,0x6802,0x6804,0x6806,0x6808,0x680A,0x680C,0x680E
    dw 0x6810,0x6812,0x6814,0x6816,0x6818,0x681A,0x681C,0x681E
    dw 0x6820,0x6822,0x6824,0x6826
vcb_write_fields_end:
