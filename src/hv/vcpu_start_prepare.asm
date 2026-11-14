;; MODULE hv/vcpu_start_prepare
;; LAYER 5
;; EXPORTS vst_prepare
;; IMPORTS hv/vcpu_start_resources, hv/vcpu_start_vmcs, hv/vcpu_start_seal, hv/vcpu_start_close, hv/vcpu_cpuid_sample, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_bsp, hv/vmx, hv/boundary, core/sched
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. One START preparation transaction, no READY
; or guest entry grant. Caller selected the private native path BEFORE any
; legacy vector/MSR save or scrub, set vst_native_restore=1, armed the guard,
; and initialized its own VMCS0. IF0/DF0, no custody or previous gang live.
; Return1: both VMCS images and common model prepared under retained custody.
; Return0: completed refusal; caller MUST take ordinary teardown/vst_close,
; even if no AP request was published. Uncertain AP completion never returns.
%include "hv/vcpu_start.inc"
%include "hv/vcpu_ap_xstate.inc"

vst_prepare:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_native_restore], 1
    jne  .bad
    cmp  qword [rel vst_base], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_initialized], 0
    jne  vcb_fail_stop
    cmp  dword [rel vcg_ap], -1
    jne  vcb_fail_stop
    cmp  qword [rel vcg_token], 0
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    test rbx, rbx
    jz   .bad
    cmp  rbx, [rel hv_vmx_boundary_frame]
    jne  .bad
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  vcb_fail_stop
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  vcb_fail_stop
    cmp  qword [rbx + HVB_LEASE], 0
    jne  vcb_fail_stop
    cmp  qword [rbx + HVB_GUARD], 0
    je   .bad
    cmp  byte [rel hv_linux_vmx_live], 1
    jne  .bad
    cmp  byte [rel gsn_resume_live], 0
    jne  .bad
    cmp  byte [rel gsn_capture_req], 0
    jne  .bad
    cmp  byte [rel sched_xsave_mode], 1
    jne  .bad
    mov  eax, [rel sched_xsave_mask_lo]
    and  eax, 3
    cmp  eax, 3
    jne  .bad
    ; Prove the current owner before any private reservation write.
    vmptrst [rsp]
    jc   .bad
    jz   .bad
    mov  rax, [rsp]
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  .bad
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .bad
    test edx, 0x1FFFFF
    jnz  .bad
    cmp  qword [rel hv_linux_mb_token], 0
    je   .bad
    lea  rdx, [rdx + 0x1000]
    cmp  rax, rdx
    jne  .bad
    call vcpu_ap_pick
    cmp  eax, -1
    je   .bad
    mov  r12d, eax
    mov  rdi, [rel hv_linux_region]
    mov  rsi, [rel hv_linux_region_capacity]
    mov  rdx, [rel hv_linux_eptp]
    mov  ecx, [rdi]                    ; own VMXON revision, checked by VMXON
    call vst_resources_init
    cmp  eax, 1
    jne  .bad
    mov  edi, r12d
    mov  rsi, [rel vst_base]
    lea  rdx, [rsi + VST_IDT1]
    add  rsi, VST_IDT0
    call vcpu_ap_gang_open
    cmp  eax, 1
    jne  .bad
    mov  rdi, rbx
    call hv_boundary_intel_acquire
    test eax, eax
    jnz  .bad
    cmp  dword [rbx + HVB_CUSTODY_KIND], 3
    jne  vcb_fail_stop
    mov  rdi, rbx
    mov  esi, 3                        ; this carve's x87/SSE-only policy
    call vcs_collect                  ; own-core samples, exact epoch ACK
    cmp  rax, 3
    jne  .bad
    mov  rdi, rbx
    call vst_vmcs_init                 ; clears private VMCS1 back to VMCS0
    cmp  eax, 1
    jne  .bad
    ; Neither a successful helper nor its return value publishes READY.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_initialized], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    mov  rax, [rbx + HVB_LEASE]
    test rax, rax
    jz   vcb_fail_stop
    cmp  rax, -1
    je   vcb_fail_stop
    cmp  rax, [rel vcg_token]
    jne  vcb_fail_stop
    cmp  rax, [rel vcs_epoch]
    jne  vcb_fail_stop
    cmp  rax, [rel vst_manifest]
    jne  vcb_fail_stop
    mov  rdi, rbx
    call hv_boundary_intel_held
    mov  rdi, rbx
    call vst_seal                       ; exact EPT/IDT/input closure, no READY
    cmp  eax, 1
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
