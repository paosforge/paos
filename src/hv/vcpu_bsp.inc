; S7 BSP-only frontiers. The AP's host VMCS is never executable on the BSP.
%ifndef HV_VCPU_BSP_INC
%define HV_VCPU_BSP_INC 1
%include "hv/vcpu_ap.inc"
%include "hv/vcpu_ap_xstate.inc"
%macro VCB_ENTRY_GUARD 0
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_entry_stop
    mov  byte [rel vcg_root], 0
%endmacro
; Caller has saved every guest GPR; no ordinary call before the inline DOWN.
%macro VCB_GANG_DOWN 0
    cmp  qword [rel vca_ready], 0
    je   %%single
    cmp  qword [rel vca_ready], 1
    jne  vcg_stop_down
    VCG_GANG_DOWN
%%single:
%endmacro
; After own LAND, before the first ordinary CALL/RET. Guest GPRs saved.
%macro VCB_CONTEXT_LAND 0
    cmp  qword [rel vca_ready], 0
    je   %%single
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 1
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 1
    jne  vcb_fail_stop
    mov  rax, cr2
    mov  [rel vcb_guest_cr2], rax
    mov  rax, dr6
    mov  [rel vcb_debug + 32], rax
    VAX_LAND vcb_xstate
    mov  rax, [rel vcb_host_context + 0]
    mov  cr2, rax
    mov  rax, [rel vcb_host_context + 8]
    mov  dr0, rax
    mov  rax, [rel vcb_host_context + 16]
    mov  dr1, rax
    mov  rax, [rel vcb_host_context + 24]
    mov  dr2, rax
    mov  rax, [rel vcb_host_context + 32]
    mov  dr3, rax
    mov  rax, [rel vcb_host_context + 40]
    mov  dr6, rax
    mov  qword [rel vcb_context_loaded], 0
    jmp  %%done
%%single:
    HV_BOUNDARY_HOST_XCR0
%%done:
%endmacro
%endif
