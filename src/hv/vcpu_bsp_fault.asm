;; MODULE hv/vcpu_bsp_fault
;; LAYER 5
;; EXPORTS vcb_fault_stop
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, core/smp, core/idt
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. BSP epoch interrupt context. Callee-free
; terminal retirement; no process-context helper or BSP crypto is reachable.
%include "hv/vcpu_bsp.inc"

; The BSP epoch IDT normalizes vector/error/RIP. No ordinary call/return
; before the floor, and no diagnostic or unrelated VMX before retirement.
vcb_fault_stop:
    cmp qword [rel vsr_enabled], 1
    je vsm_fault_floor
    cmp  dword [rel vcb_handoff_active], 0
    je   .floor
    vmclear [rel vca_vmx + VAP_CS]
    vmptrld [rel vcb_owner_vmcs]
.floor:
    mov  byte [rel vcg_root], 1
    mov  dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    jmp  cpu_boundary_fault_stop

; SVM contexts have no VMCS to clear. Fatal native ownership stays retained.
vsm_fault_floor:
    mov byte [rel vcg_root], 1
    mov dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    jmp cpu_boundary_fault_stop
