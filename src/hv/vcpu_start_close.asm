;; MODULE hv/vcpu_start_close
;; LAYER 5
;; EXPORTS vst_close, vst_finish, vst_native_restore
;; IMPORTS hv/vmx, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_bsp, hv/vcpu_bsp_context, hv/vcpu_start_resources, hv/vcpu_start_vmcs, hv/boundary
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Closed-pair START retirement, IF0.
; Preserve the native-restore decision after READY is retired: legacy restore
; would use single-vCPU XSAVE/MSR scratch that this session never owned.
; AP departure includes its own VMXOFF, CR restoration and host-vector repost.
; No resource or writer gate opens until that departure is proven.
%include "hv/vcpu_ap_xstate.inc"

; RDI retained BSP frame. Return1 private restore /0 legacy, idempotent.
; vcb_context_cancel already restored any prepared BSP native context.
vst_close:
    push rbx
    sub  rsp, 16
    mov  rbx, rdi
    cmp  qword [rel vca_ready], 1
    ja   vcb_fail_stop
    cmp  qword [rel vst_native_restore], 1
    ja   vcb_fail_stop
    cmp  qword [rel vst_initialized], 1
    ja   vcb_fail_stop
    cmp  qword [rel vst_base], 0
    jne  .prepared
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_initialized], 0
    jne  vcb_fail_stop
    mov  eax, [rel vst_native_restore]
    jmp  .out
.prepared:
    test rbx, rbx
    jz   vcb_fail_stop
    cmp  rbx, [rel hv_vmx_boundary_frame]
    jne  vcb_fail_stop
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  vcb_fail_stop
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_vmx + 56], 0
    jne  vcb_fail_stop
    cmp  word [rel vcg_root], 0x101
    jne  vcb_fail_stop
    cmp  dword [rel vcg_abort], 0
    jne  vcb_fail_stop
    mov  eax, [rel vcg_go]
    cmp  eax, [rel vcg_ack]
    jne  vcb_fail_stop
    cmp  eax, [rel vcg_down]
    jne  vcb_fail_stop
    mov  rax, [rbx + HVB_LEASE]
    test rax, rax
    jz   .already_drained
    cmp  rax, -1
    je   vcb_fail_stop
    cmp  dword [rbx + HVB_CUSTODY_KIND], 3
    jne  vcb_fail_stop
    cmp  qword [rel vcg_token], 0
    je   .held                          ; completed refusal before AP request
    cmp  rax, [rel vcg_token]
    jne  vcb_fail_stop
.held:
    mov  rdi, rbx
    call hv_boundary_intel_held
    jmp  .drain
.already_drained:
    cmp  qword [rel vca_vmx + 48], 0
    jne  vcb_fail_stop
.drain:
    mov  qword [rel vst_native_restore], 1
    mov  rdi, rbx
    call hv_boundary_finish             ; waits exact AP departure, or stops
    cmp  qword [rbx + HVB_LEASE], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_vmx + 48], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_vmx + 56], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    ; VMCS1 can be cleared only after AP relinquished it. VMCS0 stays current.
    cmp  byte [rel hv_linux_vmx_live], 1
    je   .clear
    cmp  byte [rel hv_linux_vmx_live], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_initialized], 0
    jne  vcb_fail_stop
    jmp  .retire
.clear:
    vmptrst [rsp]
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rax, [rsp]
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  vcb_fail_stop
    vmclear [rel vca_vmx + 16]
    jc   vcb_fail_stop
    jz   vcb_fail_stop
.retire:
    mov  qword [rel vca_ready], 0        ; thaw after AP VMXOFF and VMCS1 clear
    mov  dword [rel vcg_ap], -1
    mov  qword [rel vcg_token], 0
    mov  dword [rel vcg_go], 0
    mov  dword [rel vcg_ack], 0
    mov  dword [rel vcg_down], 0
    mov  qword [rel vst_manifest], 0
    mov  qword [rel vst_sealed], 0
    mov  qword [rel vst_initialized], 0
    mov  qword [rel vst_base], 0         ; allocator carve may be initialized again
    mov  eax, 1
.out:
    add  rsp, 16
    pop  rbx
    ret

; After BSP VMXOFF/native CR restoration and ordinary boundary finish,
; before original RFLAGS. Never erase the AP reset generation.
vst_finish:
    cmp  qword [rel vst_native_restore], 0
    je   .done
    cmp  qword [rel vst_native_restore], 1
    jne  vcb_fail_stop
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_base], 0
    jne  vcb_fail_stop
    cmp  qword [rel vst_initialized], 0
    jne  vcb_fail_stop
    cmp  byte [rel hv_linux_vmx_live], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_vmx + 48], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_vmx + 56], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    mov  qword [rel vst_native_restore], 0
.done:
    ret

%macro WDATA_hv_vcpu_start_close 0
align 8, db 0
vst_native_restore: dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_start_close
