;; MODULE hv/vcpu_ap_activity
;; LAYER 5
;; EXPORTS vcpu_ap_activity_read
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; AP pre-entry activity classification. Current AP-owned vCPU1 VMCS, IF0. No caller may
; issue VM entry unless EAX=1. EAX2 means a virtual idle state emulated in
; root; caller clears any current VMCS before ack. EAX0 means stop/refuse.
; Wait-for-SIPI3 blocks kick and VMX timer exits; never enter it physically.
; HLT1 is emulated in root; shutdown2/reserved states never execute.
vcpu_ap_activity_read:
    mov  edi, 0x4826
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test rax, rax
    jz   .active
    cmp  rax, 1
    je   .idle
    cmp  rax, 3
    je   .idle
.bad:
    xor  eax, eax
    ret
.idle:
    mov  eax, 2
    ret
.active:
    mov  eax, 1
    ret
