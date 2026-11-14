;; MODULE hv/vcpu_start_inputs
;; LAYER 5
;; EXPORTS vst_inputs_check
;; IMPORTS hv/vcpu_start_vmcs, hv/vcpu_start_resources, hv/vcpu_cpuid_sample, hv/vcpu_cpuid, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_bsp_state, hv/vcpu_bsp_context, hv/vcpu_ap_frozen, hv/vmx, hv/vm_profile
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Read-only early check, on either core BEFORE
; any private VMX/XSAVE pointer or epoch IDTR use. RDI expected sealed epoch.
; Validate every manifest address/length against its canonical object BEFORE
; hashing. A redirected record cannot hide a changed object or cause a hash
; of arbitrary memory. No rehash-as-new-truth and no READY/epoch publication.
%include "hv/vcpu_start.inc"
%include "hv/vcpu_cpuid.inc"
%macro VSI_RECORD 3
    lea  rax, %2
    cmp  [r12 + 16 + %1*48], rax
    jne  .bad
    cmp  qword [r12 + 24 + %1*48], %3
    jne  .bad
%endmacro
vst_inputs_check:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    test r13, r13
    jz   .bad
    cmp  r13, -1
    je   .bad
    cmp  qword [rel vca_ready], 1
    ja   .bad
    cmp  qword [rel vst_initialized], 1
    jne  .bad
    cmp  r13, [rel vst_sealed]
    jne  .bad
    lea  r12, [rel vst_manifest]
    cmp  [r12], r13
    jne  .bad
    cmp  qword [r12 + 8], 23
    jne  .bad
    mov  rbx, [rel vst_base]
    test rbx, rbx
    jz   .bad
    test rbx, 0x1FFFFF
    jnz  .bad
    cmp  rbx, [rel hv_linux_region]
    jne  .bad
    cmp  qword [rel hv_linux_mb_token], 0
    je   .bad
    lea  rax, [rbx + 0x1000]
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  .bad
    lea  rax, [rbx + 0x2000]
    or   rax, 0x1E
    cmp  rax, [rel hv_linux_eptp]
    jne  .bad
    lea  rax, [rbx + 0x200000]
    cmp  rax, [rel hv_linux_ram]
    jne  .bad
    cmp  qword [rel vca_go_desc], 1
    jne  .bad
    mov  rax, [rel vca_reset]
    test rax, rax
    jz   .bad
    cmp  rax, [rel vca_go_desc + 8]
    jne  .bad
    cmp  r13, [rel vca_go_desc + 16]
    jne  .bad
    lea  rax, [rbx + VST_CS1]
    cmp  rax, [rel vca_go_desc + 32]
    jne  .bad
    cmp  qword [rel vca_go_desc + 40], 0x901
    jne  .bad
    lea  rax, [rel vst_ap_controls]
    cmp  rax, [rel vca_go_desc + 48]
    jne  .bad
    cmp  r12, [rel vca_go_desc + 56]
    jne  .bad
    VSI_RECORD 0, [rbx + VST_IOA], 4096
    VSI_RECORD 1, [rbx + VST_IOB], 4096
    VSI_RECORD 2, [rbx + VST_MSR], 4096
    VSI_RECORD 3, [rel vcb_cpuid_table], VCP_BYTES
    VSI_RECORD 4, [rel vcb_efer_mask], 24
    VSI_RECORD 5, [rel vst_ap_controls], 184
    VSI_RECORD 6, [rel vcs_controls], 80
    VSI_RECORD 7, [rel vst_reset_table], vst_reset_end - vst_reset_table
    VSI_RECORD 8, [rbx + 0x2000], 4096
    VSI_RECORD 9, [rbx + 0x3000], 4096
    VSI_RECORD 10, [rbx + 0x4000], 4096
    VSI_RECORD 11, [rbx + 0x6000], 4096
    VSI_RECORD 12, [rbx + 0x7000], 4096
    VSI_RECORD 13, [rbx + VST_IDT0], 4096
    VSI_RECORD 14, [rbx + VST_IDT1], 4096
    VSI_RECORD 15, [rel vcs_bsp_caps], 72
    VSI_RECORD 16, [rel vcs_ap_caps], 72
    VSI_RECORD 17, [rel vcg_idtr_bsp], 10
    VSI_RECORD 18, [rel vcg_idtr_ap], 10
    VSI_RECORD 19, [rel vca_vmx], 32
    VSI_RECORD 20, [rel vcb_xstate], 32
    VSI_RECORD 21, [rel vca_xstate], 32
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .bad
    cmp  [r12 + 16 + 22*48], rax
    jne  .bad
    cmp  qword [r12 + 24 + 22*48], 280
    jne  .bad
    mov  rdi, r12
    mov  rsi, r13
    call vcpu_ap_frozen_check
    cmp  eax, 1
    jne  .bad
    mov  rdx, [rel vm_profile_active]
    mov  rax, [rel hv_linux_ram_bytes]
    cmp  rax, [rdx + 40]
    jne  .bad
    add  rax, 0x200000
    jc   .bad
    cmp  rax, [rel hv_linux_region_capacity]
    ja   .bad
    cmp  dword [rel vm_profile_dev_mask], 1027
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
%unmacro VSI_RECORD 3
