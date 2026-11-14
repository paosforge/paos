;; MODULE hv/vcpu_bsp_context
;; LAYER 5
;; EXPORTS vcb_context_host_write, vcb_context_save, vcb_context_guest, vcb_context_host, vcb_context_cancel, vcb_xstate, vcb_host_msrs, vcb_guest_cr2, vcb_host_context, vcb_context_loaded
;; IMPORTS hv/vcpu_start_epoch, hv/vcpu_bsp, hv/vcpu_bsp_state, hv/vcpu_ap_run, hv/vcpu_ap_xstate, hv/vcpu_ap_msrs, hv/vcpu_ap_host, hv/vmx
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Native BSP context is captured anew before
; EVERY attempted boundary entry. No READY publisher. START owns mapped,
; disjoint XSAVE buffers, frozen policy and VMCS list addresses/counts.
; No guest is running; IF0, own VMCS current, deferred vCPU1 flag clear.
%include "hv/vcpu_ap_xstate.inc"

vcb_context_save:
    cmp  qword [rel vca_ready], 0
    je   .single
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    sub  rsp, 8
    call vst_epoch_prepare
    add  rsp, 8
    cmp  eax, 1
    jne  vcb_fail_stop
    ; Snapshot restore/capture still uses the single-vCPU format.
    cmp  byte [rel gsn_resume_live], 0
    jne  vcb_fail_stop
    cmp  byte [rel gsn_capture_req], 0
    jne  vcb_fail_stop
    sub  rsp, 8
    vmptrst [rsp]
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rax, [rsp]
    add  rsp, 8
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  vcb_fail_stop
    ; Require automatic guest DR7/DEBUGCTL and PAT swapping. Native debug
    ; ownership is unsupported rather than silently reusing a guest register.
    mov  edi, 0x400C
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    and  eax, (1 << 2) | (1 << 18) | (1 << 19)
    cmp  eax, (1 << 2) | (1 << 18) | (1 << 19)
    jne  vcb_fail_stop
    mov  edi, 0x4012
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    and  eax, (1 << 2) | (1 << 14)
    cmp  eax, (1 << 2) | (1 << 14)
    jne  vcb_fail_stop
    mov  edi, 0x681A
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rdx, rax
    and  edx, 0xFFFF23FF
    or   edx, 0x400
    cmp  rax, rdx
    jne  vcb_fail_stop
    mov  edi, 0x2802
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test rax, rax
    jnz  vcb_fail_stop
    mov  rax, dr7
    cmp  rax, 0x400
    jne  vcb_fail_stop
    mov  ecx, 0x1D9
    rdmsr
    or   eax, edx
    jnz  vcb_fail_stop
    mov  rax, cr2
    mov  [rel vcb_host_context + 0], rax
    mov  rax, dr0
    mov  [rel vcb_host_context + 8], rax
    mov  rax, dr1
    mov  [rel vcb_host_context + 16], rax
    mov  rax, dr2
    mov  [rel vcb_host_context + 24], rax
    mov  rax, dr3
    mov  [rel vcb_host_context + 32], rax
    mov  rax, dr6
    mov  [rel vcb_host_context + 40], rax
    ; Callee ABI alignment: entry RSP is8 mod16.
    sub  rsp, 8
    lea  rdi, [rel vcb_guest_msrs]
    lea  rsi, [rel vcb_host_msrs]
    call vcpu_ap_msrs_prepare             ; actual BSP values, every attempt
    cmp  eax, 1
    jne  vcb_fail_stop
    mov  rax, [rel vcb_xcr0_allowed]
    cmp  [rel vcb_xstate + VAX_ALLOWED], rax
    jne  vcb_fail_stop
    mov  rax, [rel hv_linux_guest_xcr0]
    mov  [rel vcb_xstate + VAX_VALUE], rax
    lea  rdi, [rel vcb_xstate]
    call vcpu_ap_xstate_save
    cmp  eax, 1
    jne  vcb_fail_stop
    add  rsp, 8
.single:
    mov  eax, 1
    ret

; After the entry executor, BEFORE any private guest restore or GO.
; RDI own retained frame, RSI own HOST_RIP. Only host fields are rewritten.
vcb_context_host_write:
    cmp  qword [rel vca_ready], 0
    je   .single
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 1
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    sub  rsp, 8
    call vcpu_bsp_host_write
    cmp  eax, 1
    jne  vcb_fail_stop
    add  rsp, 8
.single:
    mov  eax, 1
    ret

; After the entry executor; last guest-state helper before BSP GO/FINAL.
vcb_context_guest:
    cmp  qword [rel vca_ready], 0
    je   hv_linux_xcr0_to_guest
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 1
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    sub  rsp, 8
    lea  rdi, [rel vcb_xstate]
    call vcpu_ap_xstate_guest
    add  rsp, 8
    mov  rax, [rel vcb_guest_cr2]
    mov  cr2, rax
    mov  rax, [rel vcb_debug + 0]
    mov  dr0, rax
    mov  rax, [rel vcb_debug + 8]
    mov  dr1, rax
    mov  rax, [rel vcb_debug + 16]
    mov  dr2, rax
    mov  rax, [rel vcb_debug + 24]
    mov  dr3, rax
    mov  rax, [rel vcb_debug + 32]
    mov  dr6, rax
    mov  qword [rel vcb_context_loaded], 1
    ret

; After inline LAND+native debug restore and the closed exit executor.
vcb_context_host:
    cmp  qword [rel vca_ready], 0
    je   .single
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 1
    jne  vcb_fail_stop
    lea  rdi, [rel vcb_xstate]
    jmp  vcpu_ap_xstate_host
.single:
    ret

; Prepared boundary refusal: guest state was never loaded. No fabricated LAND.
; Also called on teardown paths that did not prepare a context at all.
vcb_context_cancel:
    cmp  qword [rel vca_ready], 0
    je   .single
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  qword [rel vcb_context_loaded], 0
    jne  vcb_fail_stop
    cmp  qword [rel vcb_xstate + VAX_SAVED], 0
    je   .single
    cmp  qword [rel vcb_xstate + VAX_SAVED], 1
    jne  vcb_fail_stop
    lea  rdi, [rel vcb_xstate]
    jmp  vcpu_ap_xstate_host
.single:
    ret

%macro WDATA_hv_vcpu_bsp_context 0
align 16, db 0
vcb_host_msrs: times 6 dq 0,0
vcb_xstate: times VAX_SIZE db 0
vcb_guest_cr2: dq 0
vcb_host_context: times 6 dq 0          ; own CR2,DR0,DR1,DR2,DR3,DR6
vcb_context_loaded: dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_bsp_context
