;; MODULE hv/vcpu_ap_controls
;; LAYER 5
;; EXPORTS vcpu_ap_controls_capture, vcpu_ap_controls_check
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; C4/P8/E3 frozen VMCS control comparison. All 23 START values are
; immutable before the first AP epoch. Capture is BSP-only at START; a
; partial capture is unusable. Caller still owes AP-local capability checks,
; bitmap/CPUID/XSETBV hashes, exact private page ownership and mode binding.
; RDI 23-qword output. Return 1 complete/0 refuse; no READY publication here.
vcpu_ap_controls_capture:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.field:
    lea  rax, [rel vap_control_fields]
    mov  edi, [rax + rbx*8]
    vmread rax, rdi
    jc   .bad
    jz   .bad
    mov  [r12 + rbx*8], rax
    inc  ebx
    cmp  ebx, 23
    jb   .field
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RDI frozen START values, RSI expected ENTRY bit9 (0 or 0x200), independently
; validated from the vCPU1 GO tuple, never read from ENTRY_CTLS itself.
; Compare every other bit exactly. No control, snapshot or guest-state write.
vcpu_ap_controls_check:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    xor  ebx, ebx
.field:
    lea  rax, [rel vap_control_fields]
    mov  edi, [rax + rbx*8]
    vmread rax, rdi
    jc   .bad
    jz   .bad
    mov  r9, rax
    xor  rax, [r12 + rbx*8]
    lea  rdx, [rel vap_control_fields]
    mov  edx, [rdx + rbx*8 + 4]
    not  rdx
    test rax, rdx
    jnz  .bad
    cmp  edi, 0x4012
    jne  .next
    and  r9d, 1 << 9
    cmp  r9, r13
    jne  .bad
.next:
    inc  ebx
    cmp  ebx, 23
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
vap_control_fields:                     ; encoding, sole mutable-bit allowance
    dd 0x4000, 0                        ; pin
    dd 0x4002, (1 << 2) | (1 << 22)      ; interrupt/NMI window only
    dd 0x4004, 0                        ; exception bitmap
    dd 0x4006, 0                        ; PF mask
    dd 0x4008, 0                        ; PF match
    dd 0x400A, 0                        ; CR3 target count
    dd 0x400C, 0                        ; exit controls (host restore stays frozen)
    dd 0x400E, 0                        ; exit MSR store count
    dd 0x4010, 0                        ; exit MSR load count
    dd 0x4012, 1 << 9                   ; checked LMA; accepted SEC amendment
    dd 0x4014, 0                        ; entry MSR load count
    dd 0x401E, 0                        ; secondary controls
    dd 0x2000, 0                        ; I/O bitmap A
    dd 0x2002, 0                        ; I/O bitmap B
    dd 0x2004, 0                        ; MSR bitmap
    dd 0x2006, 0                        ; exit MSR store area
    dd 0x2008, 0                        ; exit MSR load area
    dd 0x200A, 0                        ; entry MSR load area
    dd 0x201A, 0                        ; EPTP
    dd 0x6000, 0                        ; CR0 mask
    dd 0x6002, 0                        ; CR4 mask
    dd 0x6004, (1 << 29) | (1 << 30)    ; only guest CD/NW shadow may change
    dd 0x6006, 0                        ; CR4 shadow
; E3 independently mutable fields, intentionally outside START comparison:
; 4016 entry intr info; 4018 entry errcode; 401A entry insn length;
; 4824 guest interruptibility; 4826 guest activity. The final source census
; must verify their complete dispatcher write set and the masks above.
