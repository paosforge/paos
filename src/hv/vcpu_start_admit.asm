;; MODULE hv/vcpu_start_admit
;; LAYER 5
;; EXPORTS vst_admit, vst_select, vst_activate
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_inputs, hv/vcpu_start_prepare, hv/vcpu_start_inputs, hv/vcpu_start_vmcs, hv/vcpu_start_resources, hv/vcpu_start_close, hv/vcpu_bsp_dispatch, hv/vcpu_bsp_context, hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, hv/vm_profile, hv/vmx, hv/hv_ops, hv/svm, hv/guestsnap, hv/guestnet, hv/vtd, hv/pci_assign, hv/pad_channel, hv/input_owner, hv/warm_lifecycle, hv/guest_surface, hv/cdp_bridge, hv/guest_power, core/sched
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Actual START admission and the sole READY1
; publication. Admission is repeated before any device reset and immediately
; before CPU saves. No foreign binding is cleared to make admission succeed.
; Private selection precedes ALL legacy MSR/XSAVE/vector operations; refused
; private attempts retain the exact native CR restore decision for teardown.

; EAX0 legacy /1 admitted private /2 completed refusal. EDX exact failed
; predicate (numbered below),0 on admission. No writes; native uncertainty
; still fail-stops. These codes describe refusal, never an execution grant.
vst_admit:
    xor  edx, edx                       ; reason0: legacy/private admission succeeds
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_native_restore], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_base], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_initialized], 0
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    mov  rdi, [rel vm_profile_active]
    test rdi, rdi
    jz   .legacy
    cmp  dword [rdi + 36], 1
    je   .legacy
    sub  rsp, 8
    call vm_profile_smp2_match
    add  rsp, 8
    test eax, eax
    mov  edx, 1
    jz   .refused
    lea  rax, [rel hv_ops_vmx]
    cmp  rax, [rel hv_ops_active]
    je   .vendor
    lea  rax, [rel hv_ops_svm]
    cmp  rax, [rel hv_ops_active]
    mov  edx, 2
    jne  .refused
    cmp  qword [rel vsr_enabled], 0
    jne  vcb_fail_stop
    cmp  qword [rel vsm_base], 0
    jne  vcb_fail_stop
.vendor:
    cmp  byte [rel gsn_resume_live], 0
    mov  edx, 3
    jne  .refused
    cmp  byte [rel gsn_capture_req], 0
    mov  edx, 4
    jne  .refused
    cmp  byte [rel gsn_resume_armed], 0
    mov  edx, 5
    jne  .refused
    cmp  byte [rel cdp_bound], 0
    mov  edx, 6
    jne  .refused
    cmp  byte [rel gws_bound], 0
    mov  edx, 7
    jne  .refused
    cmp  byte [rel hvp_bound], 0
    mov  edx, 8
    jne  .refused
    cmp  byte [rel hvw_bound], 0
    mov  edx, 9
    jne  .refused
    cmp  byte [rel padc_bound], 0
    mov  edx, 10
    jne  .refused
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    mov  edx, 11
    jne  .refused
%endif
%endif
    cmp  byte [rel guestnet_active], 0
    mov  edx, 12
    jne  .refused
    cmp  qword [rel guestnet_domain_ctx], 0
    mov  edx, 13
    jne  .refused
    cmp  byte [rel vtd_owner_guest], 0
    mov  edx, 14
    jne  .refused
    cmp  byte [rel vtd_network_mode], 0
    mov  edx, 15
    jne  .refused
    cmp  byte [rel pcia_state], 0
    mov  edx, 16
    jne  .refused
    cmp  byte [rel hv_guest_power_fenced], 0
    mov  edx, 17
    jne  .refused
    cmp  qword [rel hv_guest_power_inflight], 0
    mov  edx, 18
    jne  .refused
    cmp  qword [rel hv_svm_cur_vmcb], 0
    mov  edx, 19
    jne  .refused
    cmp  byte [rel sched_xsave_mode], 1
    mov  edx, 20
    jne  .refused
    mov  eax, [rel sched_xsave_mask_lo]
    and  eax, 3
    cmp  eax, 3
    mov  edx, 21
    jne  .refused
    mov  rax, cr4
    test eax, 1 << 18                    ; native OSXSAVE, never enable it here
    mov  edx, 22
    jz   .refused
    xor  edx, edx
    mov  eax, 1
    ret
.legacy:
    xor  edx, edx
    xor  eax, eax
    ret
.refused:
    mov  eax, 2
    ret

; After original CR0/CR4 capture and fixed-bit setup, before any legacy save.
; EAX has the admission result. Only private attempts set native_restore.
vst_select:
    sub  rsp, 8
    call vst_admit
    add  rsp, 8
    test eax, eax
    jz   .out
    mov  qword [rel vst_native_restore], 1
.out:
    ret

; RDI exact retained guarded BSP frame, VMCS0 controls/state/HOST/deadline
; already initialized, IF0. Returns1 or completed refusal0 (take vst_close).
; Preparation seals both vCPUs under retained closed custody. Recheck all
; canonical inputs/hashes before publishing; no AP GO is issued here.
vst_activate:
    push rbx
    mov  rbx, rdi
    call vst_prepare
    cmp  eax, 1
    jne  .bad
    mov  rdi, [rel vst_sealed]
    call vst_inputs_check
    cmp  eax, 1
    jne  .bad
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    mov  qword [rel vca_ready], 1          ; sole grant, after complete seal
    call vcd_ops_check                    ; finite accessor targets before entry
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret
