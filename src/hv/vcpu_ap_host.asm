;; MODULE hv/vcpu_ap_host
;; LAYER 5
;; EXPORTS vcpu_ap_host_write, vcpu_bsp_host_write, vcpu_native_host_write
;; IMPORTS hv/vcpu_ap
;; CAPS
;; OWNER saga:hv
; S7 E3. Before EVERY GO's boundary entry, rewrite all host-state fields
; used by this backend from this AP. A BSP VMCS hand-off cannot leave its
; descriptors, stack, control registers or MSRs behind. No guest/control
; field is written here. IF0, live AP epoch IDT and current vCPU1 VMCS;
; VMX fixed bits have already been applied by vcpu_ap_vmx_begin.
;
; RDI = this cycle's private HOST_RSP, RSI = AP's exit landing HOST_RIP.
; -> EAX 1, or 0 (do not enter; discard any partial host-field writes).
; Caller validates owned stack/landing addresses and frozen VMCS controls.
; Preserve callee-save GPRs. No allocation and no writable shared scratch.
vcpu_ap_host_write:
    mov  rdx, [rel vcg_idtr_ap + 2]
    mov  rcx, rdx
    jmp  vch_write

; BSP is still on its shared host IDT; GO installs the epoch IDT after the
; entry executor. VM-exit MUST load the private BSP epoch IDT before HOST_RIP.
; RDI own retained HOST_RSP, RSI own Linux exit landing; IF0, READY1, VMCS0.
vcpu_bsp_host_write:
    mov  rdx, [rel vcg_idtr_shared + 2]
    mov  rcx, [rel vcg_idtr_bsp + 2]
    test rcx, rcx
    jz   .bad
    jmp  vch_write
.bad:
    xor  eax, eax
    ret

; Independent BSP VM: use this CPU's actual current IDT on both sides. No S7
; epoch/global IDT pointer is imported into the app VM. The same host-field
; validation engine still checks IF0, selectors, TSS, CRs and control support.
; RDI private HOST_RSP, RSI private HOST_RIP -> EAX1/0; callee saves retained.
vcpu_native_host_write:
    sub rsp,24
    sidt [rsp]
    mov rdx,[rsp+2]
    mov rcx,rdx
    add rsp,24
    jmp vch_write

; RDX expected CURRENT IDT base; RCX desired HOST_IDTR base. Only wrappers
; above call this internal engine; all other host fields come from this CPU.
vch_write:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 216                        ; 20 values, private GDTR/IDTR + bases
    mov  [rsp + 192], rcx
    mov  [rsp + 200], rdx
    mov  r12, rdi
    mov  r13, rsi
    mov  edi, 0x400C                     ; VM-exit controls
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test eax, 1 << 9                     ; only a 64-bit host
    jz   .bad
    ; These host-load fields are not supported by S7. Refuse rather than
    ; preserve a BSP value or access an optional MSR on an unsupported CPU.
    test eax, (1 << 12) | (1 << 28) | (1 << 29) | (1 << 31)
    jnz  .bad                            ; PERF, CET, PKRS, secondary controls
    mov  r14d, eax
    mov  ax, es
    movzx eax, ax
    mov  [rsp], rax
    mov  ax, cs
    movzx eax, ax
    test eax, eax
    jz   .bad
    mov  [rsp + 8], rax
    mov  ax, ss
    movzx eax, ax
    mov  [rsp + 16], rax
    mov  ax, ds
    movzx eax, ax
    mov  [rsp + 24], rax
    mov  ax, fs
    movzx eax, ax
    mov  [rsp + 32], rax
    mov  ax, gs
    movzx eax, ax
    mov  [rsp + 40], rax
    str  ax
    movzx eax, ax
    test eax, eax
    jz   .bad
    mov  [rsp + 48], rax
    xor  ecx, ecx
.selectors:
    test byte [rsp + rcx*8], 7           ; no RPL or LDT selector
    jnz  .bad
    inc  ecx
    cmp  ecx, 7
    jb   .selectors
    sgdt [rsp + 160]
    sidt [rsp + 176]
    cmp  word [rsp + 176], 4095
    jb   .bad
    mov  rax, [rsp + 178]
    test rax, rax
    jz   .bad
    cmp  rax, [rsp + 200]
    jne  .bad
    mov  rax, [rsp + 192]
    mov  [rsp + 120], rax
    mov  rax, [rsp + 162]
    mov  [rsp + 112], rax
    movzx ecx, word [rsp + 160]
    mov  edi, [rsp + 48]                 ; THIS AP's live TR, not BSP tss_struct
    lea  edx, [rdi + 15]
    cmp  edx, ecx
    ja   .bad
    add  rdi, rax
    cmp  byte [rdi + 5], 0x8B            ; present, busy 64-bit TSS
    jne  .bad
    movzx eax, word [rdi + 2]
    movzx edx, byte [rdi + 4]
    shl  rdx, 16
    or   rax, rdx
    movzx edx, byte [rdi + 7]
    shl  rdx, 24
    or   rax, rdx
    mov  edx, [rdi + 8]
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp + 104], rax
    mov  rax, cr0
    mov  [rsp + 64], rax
    mov  rax, cr3
    mov  [rsp + 72], rax
    mov  rax, cr4
    mov  [rsp + 80], rax
    mov  ecx, 0x174
    rdmsr
    mov  eax, eax                       ; SYSENTER_CS is a 32-bit VMCS field
    mov  [rsp + 56], rax
    mov  ecx, 0x175
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp + 128], rax
    mov  ecx, 0x176
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp + 136], rax
    mov  ecx, 0xC0000100
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp + 88], rax
    mov  ecx, 0xC0000101
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp + 96], rax
    mov  [rsp + 144], r12
    mov  [rsp + 152], r13
    xor  ebx, ebx
.fields:
    lea  rax, [rel vap_host_fields]
    mov  edi, [rax + rbx*4]
    mov  rsi, [rsp + rbx*8]
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    inc  ebx
    cmp  ebx, 20
    jb   .fields
    test r14d, 1 << 19                   ; host PAT load enabled
    jz   .efer
    mov  ecx, 0x277
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  rsi, rax
    mov  edi, 0x2C00
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
.efer:
    test r14d, 1 << 21                   ; host EFER load enabled
    jz   .ok
    mov  ecx, 0xC0000080
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  rsi, rax
    mov  edi, 0x2C02
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 216
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

align 4
vap_host_fields:
    dd 0x0C00, 0x0C02, 0x0C04, 0x0C06, 0x0C08, 0x0C0A, 0x0C0C
    dd 0x4C00
    dd 0x6C00, 0x6C02, 0x6C04, 0x6C06, 0x6C08, 0x6C0A
    dd 0x6C0C, 0x6C0E, 0x6C10, 0x6C12, 0x6C14, 0x6C16
