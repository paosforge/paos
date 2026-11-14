;; MODULE hv/vcpu_ap_caps
;; LAYER 5
;; EXPORTS vcpu_ap_caps_check
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; S7 C2 AP-local capability checker. RDI is a verified immutable 5-qword snapshot:
; pin, primary, secondary, exit, entry controls. Only this AP's MSRs count.
; Caller has already proved Intel VMX, secondary controls/EPT MSR availability
; and owns current vCPU1 VMCS. Every field must be a zero-extended dword.
; Refuse unsupported bits AND missing mandatory bits, never adjust controls.
; Required S7 mode: EPT+unrestricted guest (SIPI), trapped IRQ/NMI + timer,
; HLT/I/O exits, host64 + save timer + ACK-on-exit, private guest EFER load/save/host restore.
; Inactive virtual states are emulated in root: NEVER enter wait-for-SIPI.
; Return 1/0; preserve callee-save, snapshot, CRs and all MSRs.
vcpu_ap_caps_check:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    ; Required backend invariants, independent of hardware capability folding.
    mov  eax, [r12]
    and  eax, 0x49
    cmp  eax, 0x49
    jne  .bad
    mov  eax, [r12 + 8]
    and  eax, 0x81000080
    cmp  eax, 0x81000080
    jne  .bad
    mov  eax, [r12 + 16]
    and  eax, 0x82
    cmp  eax, 0x82
    jne  .bad
    mov  eax, [r12 + 24]
    and  eax, 0x708200
    cmp  eax, 0x708200
    jne  .bad
    test dword [r12 + 24], 0xB0001000 ; perf/CET/PKRS/secondary host loads
    jnz  .bad
    test dword [r12 + 32], 1 << 15
    jz   .bad
    mov  ecx, 0x485
    rdmsr
    and  eax, 1 << 5                    ; unrestricted guest saves actual LMA
    cmp  eax, 1 << 5
    jne  .bad
    mov  ecx, 0x480
    rdmsr
    xor  r13d, r13d
    bt   edx, 23                        ; VMX_BASIC[55] true controls
    jnc  .table
    mov  r13d, 4
.table:
    xor  ebx, ebx
.field:
    mov  r8, [r12 + rbx*8]
    mov  rax, r8
    shr  rax, 32
    jnz  .bad
    lea  rax, [rel vap_caps_msrs]
    add  rax, r13
    mov  ecx, [rax + rbx*8]
    rdmsr
    mov  r9d, eax                       ; fixed-1 / disallowed-0 bits
    not  r8d
    test r9d, r8d
    jnz  .bad
    not  r8d
    not  edx                           ; disallowed-1 bits
    test r8d, edx
    jnz  .bad
    inc  ebx
    cmp  ebx, 5
    jb   .field
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
align 8
vap_caps_msrs:
    dd 0x481, 0x48D
    dd 0x482, 0x48E
    dd 0x48B, 0x48B
    dd 0x483, 0x48F
    dd 0x484, 0x490
