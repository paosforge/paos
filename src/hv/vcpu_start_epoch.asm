;; MODULE hv/vcpu_start_epoch
;; LAYER 5
;; EXPORTS vst_epoch_prepare
;; IMPORTS hv/vcpu_start_inputs, hv/vcpu_start_vmcs, hv/vcpu_cpuid_sample, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_bsp, hv/vcpu_bsp_context, hv/vmx, hv/boundary, hv/boundary_owner, core/smp
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Before EVERY native BSP context save, IF0,
; own VMCS0, no guest/executor pair live. Reacquire after a host opening and
; bind the SAME frozen model to the fresh guarded epoch. Never resample or
; replace digests. AP token is published LAST, before any GO is published.
; Return1 retained custody /0 refusal; actual caller stops on refusal.
vst_epoch_prepare:
    push rbx
    push r12
    push r13
    sub  rsp, 16
    cmp  qword [rel vca_ready], 1
    jne  .bad
    cmp  dword [rel vcb_handoff_active], 0
    jne  .bad
    cmp  qword [rel vcb_context_loaded], 0
    jne  .bad
    cmp  qword [rel vcb_xstate + 48], 0
    jne  .bad
    cmp  qword [rel vca_xstate + 48], 0
    jne  .bad
    cmp  qword [rel vca_vmx + 56], 0
    jne  .bad
    cmp  word [rel vcg_root], 0x101
    jne  .bad
    cmp  dword [rel vcg_abort], 0
    jne  .bad
    mov  eax, [rel vcg_go]
    cmp  eax, [rel vcg_down]
    jne  .bad
    cmp  eax, [rel vcg_ack]
    jne  .bad
    cmp  rax, [rel vca_go_desc + 24]
    jne  .bad
    mov  rbx, [rel hv_vmx_boundary_frame]
    test rbx, rbx
    jz   .bad
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  .bad
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  .bad
    mov  r12, [rel vst_sealed]
    cmp  r12, [rel vcg_token]
    jne  .bad
    cmp  r12, [rel vcs_epoch]
    jne  .bad
    mov  rdi, r12
    call vst_inputs_check               ; before using any private pointer
    cmp  eax, 1
    jne  .bad
    vmptrst [rsp]
    jc   .bad
    jz   .bad
    mov  rax, [rsp]
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  .bad
    cmp  qword [rbx + HVB_LEASE], 0
    jne  .existing
    cmp  qword [rel vca_vmx + 48], 0    ; old epoch fully departed/VMXOFF
    jne  .bad
    cmp  qword [rbx + HVB_GUARD], 0
    jne  .armed
    mov  rdi, rbx
    call hv_boundary_arm
    test eax, eax
    jnz  .bad
.armed:
    mov  rdi, rbx
    call hv_vmx_boundary_owner_check
    cmp  eax, 1
    jne  .bad
    mov  rdi, rbx
    call hv_boundary_intel_acquire
    test eax, eax
    jnz  .bad
    mov  r13, [rbx + HVB_LEASE]
    cmp  r13, r12
    je   .bad                         ; retired epoch must never be reused
    jmp  .held
.existing:
    mov  r13, [rbx + HVB_LEASE]
    cmp  r13, r12
    jne  .bad
.held:
    test r13, r13
    jz   .bad
    cmp  r13, -1
    je   .bad
    cmp  r13, [rel smp_cc_release]
    je   .bad
    cmp  dword [rbx + HVB_CUSTODY_KIND], 3
    jne  .bad
    cmp  dword [rbx + HVB_CORE_STATE], 3
    jne  .bad
    cmp  dword [rbx + HVB_SVM], 2
    jne  .bad
    cmp  qword [rbx + HVB_GUARDED_PHASE], 0
    jne  .bad
    mov  rdi, rbx
    call hv_boundary_intel_held
    mov  rdi, r12
    call vst_inputs_check               ; repeat under retained closed custody
    cmp  eax, 1
    jne  .bad
    mov  [rel vst_manifest], r13
    mov  [rel vst_sealed], r13
    mov  [rel vcs_epoch], r13
    mov  [rel vca_go_desc + 16], r13
    mov  [rel vcg_token], r13           ; last: selected AP may bind and serve
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 16
    pop  r13
    pop  r12
    pop  rbx
    ret
