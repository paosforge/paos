;; MODULE hv/vcpu_ap_run
;; LAYER 5
;; EXPORTS vcpu_ap_run, vca_stop, vca_ready, vca_reset, vca_vmx, vca_go_desc, vca_xstate, vca_gpr, vca_guest_msrs, vca_host_msrs, vca_exit, vca_deferred, vca_status, vca_debug, vca_guest_cr2
;; IMPORTS hv/boundary_execution, hv/vcpu_observe, hv/vcpu_start_inputs, hv/vcpu_ap, hv/vcpu_ap_vmx, hv/vcpu_ap_host, hv/vcpu_ap_go, hv/vcpu_ap_msrs, hv/vcpu_ap_xstate, hv/boundary, core/smp, core/time, sec/cpu_boundary_fault
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. AP cycle engine. No BSP/device dispatch.
; START publishes vca_ready after private preparation and sealed-input recheck.
; Full BSP handoff, reset and writer guards apply. Runtime fields are private outside
; guest EPT. BSP writes guest records only after clear+ack, before publishing GO.
; Caller EDI currentGO, IF0, park guard, epoch IDT, kind4 vcg_frame bound.
%include "hv/vcpu_ap.inc"
%include "hv/vcpu_ap_xstate.inc"

%macro VCA_SAVE_GPRS 0
    mov  [rel vca_gpr + 0], rax
    mov  [rel vca_gpr + 8], rbx
    mov  [rel vca_gpr + 16], rcx
    mov  [rel vca_gpr + 24], rdx
    mov  [rel vca_gpr + 32], rsi
    mov  [rel vca_gpr + 40], rdi
    mov  [rel vca_gpr + 48], rbp
    mov  [rel vca_gpr + 56], r8
    mov  [rel vca_gpr + 64], r9
    mov  [rel vca_gpr + 72], r10
    mov  [rel vca_gpr + 80], r11
    mov  [rel vca_gpr + 88], r12
    mov  [rel vca_gpr + 96], r13
    mov  [rel vca_gpr + 104], r14
    mov  [rel vca_gpr + 112], r15
%endmacro
%macro VCA_LOAD_GPRS 0
    mov  rax, [rel vca_gpr + 0]
    mov  rbx, [rel vca_gpr + 8]
    mov  rcx, [rel vca_gpr + 16]
    mov  rdx, [rel vca_gpr + 24]
    mov  rsi, [rel vca_gpr + 32]
    mov  rdi, [rel vca_gpr + 40]
    mov  rbp, [rel vca_gpr + 48]
    mov  r8, [rel vca_gpr + 56]
    mov  r9, [rel vca_gpr + 64]
    mov  r10, [rel vca_gpr + 72]
    mov  r11, [rel vca_gpr + 80]
    mov  r12, [rel vca_gpr + 88]
    mov  r13, [rel vca_gpr + 96]
    mov  r14, [rel vca_gpr + 104]
    mov  r15, [rel vca_gpr + 112]
%endmacro

VCA_STOP equ 0x304

; Saved native stack return and all six callee-save GPRs lie ABOVE the private
; HVB frame. Calls/fill write below it. Never point HOST_RSP at WDATA vcg_frame.
vcpu_ap_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HVB_SIZE
    mov  ebx, edi
    mov  rbp, rsp
    mov  [rel vca_frame], rsp
    mov  [rel vca_cycle], ebx
    mov  dword [rel vca_status], 0
    mov  dword [rel vca_deferred], 0
    mov  dword [rel vca_cancel_flag], 0
    mov  dword [rel vca_failed], 0
    mov  dword [rel vca_launched], 0
    cmp  qword [rel vca_ready], 1
    jne  vca_stop                      ; no fabricated successful/idle ack
    mov  rsi, [rel vcg_token]
    test rsi, rsi
    jz   vca_stop
    cmp  [rel vca_go_desc + 16], rsi
    jne  vca_stop
    cmp  [rel vca_go_desc + 24], rbx
    jne  vca_stop
    mov  rax, [rel vca_reset]
    test rax, rax
    jz   vca_stop
    cmp  [rel vca_go_desc + 8], rax
    jne  vca_stop
    mov  rdi, rsi
    call vst_inputs_check
    cmp  eax, 1
    jne  vca_stop
    mov  rdi, rsp
    lea  rsi, [rel vcg_frame]
    mov  ecx, HVB_SIZE / 8
    rep  movsq
    cmp  qword [rel vca_vmx + VAP_LIVE], 0
    jne  .load
    lea  rdi, [rel vca_vmx]
    call vcpu_ap_vmx_begin
    cmp  eax, 1
    jne  vca_stop
.load:
    lea  rdi, [rel vca_vmx]
    call vcpu_ap_vmx_load
    cmp  eax, 1
    jne  vca_stop
    ; Each AP derives its own preemption count from its own VMX_MISC rate.
    mov  ecx, 0x485
    rdmsr
    and  eax, 31
    mov  ecx, eax
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    mov  rax, [rel tsc_khz]
    test rax, rax
    jz   vca_stop                      ; no uncalibrated time-bound claim
    add  rax, rdx
    jc   vca_stop
    shr  rax, cl
    test rax, rax
    jz   vca_stop
    mov  edx, 0xFFFFFFFF
    cmp  rax, rdx
    ja   vca_stop
    mov  [rel vca_timer], eax
    VCG_DEADLINE r8
    mov  [rel vca_deadline], r8
.again:
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vca_stop
    mov  eax, [rel vca_cycle]
    cmp  eax, [rel vcg_down]
    je   .clear
    cmp  eax, [rel vcg_go]
    jne  vca_stop
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel vca_deadline]
    jae  .clear
    lea  rdi, [rel vca_go_desc]
    mov  rsi, [rel vcg_token]
    mov  edx, [rel vca_cycle]
    mov  rcx, [rel vca_reset]
    call vcpu_ap_go_check
    cmp  eax, 2
    je   .idle                        ; inactive: no executor entry
    cmp  eax, 1
    jne  vca_stop
    ; Automatic PAT and debug-state swaps; all MOV-DR accesses are emulated.
    mov  edi, 0x400C
    vmread rax, rdi
    jc   vca_stop
    jz   vca_stop
    and  eax, (1 << 2) | (1 << 18) | (1 << 19)
    cmp  eax, (1 << 2) | (1 << 18) | (1 << 19)
    jne  vca_stop
    mov  edi, 0x4012
    vmread rax, rdi
    jc   vca_stop
    jz   vca_stop
    and  eax, (1 << 2) | (1 << 14)
    cmp  eax, (1 << 2) | (1 << 14)
    jne  vca_stop
    mov  edi, 0x4002
    vmread rax, rdi
    jc   vca_stop
    jz   vca_stop
    mov  edx, eax
    and  eax, (1 << 23) | (1 << 19) | (1 << 20)
    cmp  eax, (1 << 23) | (1 << 19) | (1 << 20)
    jne  vca_stop
    test edx, 1 << 21                   ; TPR-shadow/pass-through unsupported
    jnz  vca_stop
    mov  edi, 0x681A                    ; normalized private guest DR7
    vmread rax, rdi
    jc   vca_stop
    jz   vca_stop
    mov  rdx, rax
    and  edx, 0xFFFF23FF
    or   edx, 0x400
    cmp  rax, rdx
    jne  vca_stop
    mov  edi, 0x2802
    vmread rax, rdi
    jc   vca_stop
    jz   vca_stop
    test rax, rax
    jnz  vca_stop
    mov  rax, dr7
    cmp  rax, 0x400
    jne  vca_stop                      ; refuse native debug owner, no takeover
    mov  ecx, 0x1D9
    rdmsr
    or   eax, edx
    jnz  vca_stop                      ; refuse native DEBUGCTL owner
    mov  rax, dr0
    mov  [rel vca_host_debug + 0], rax
    mov  rax, dr1
    mov  [rel vca_host_debug + 8], rax
    mov  rax, dr2
    mov  [rel vca_host_debug + 16], rax
    mov  rax, dr3
    mov  [rel vca_host_debug + 24], rax
    mov  rax, dr6
    mov  [rel vca_host_dr6], rax
    mov  rax, cr2
    mov  [rel vca_host_cr2], rax
    lea  rdi, [rel vca_guest_msrs]
    lea  rsi, [rel vca_host_msrs]
    call vcpu_ap_msrs_prepare
    cmp  eax, 1
    jne  vca_stop
    mov  rdi, rsp
    lea  rsi, [rel vca_exit_landing]
    call vcpu_ap_host_write
    cmp  eax, 1
    jne  vca_stop
    lea  rdi, [rel vca_xstate]
    call vcpu_ap_xstate_save
    cmp  eax, 1
    jne  vca_stop
    mov  edi, 1
    mov  esi, [rel vcg_ap]
    call vob_begin
    mov  rdi, rsp
    call hv_boundary_enter
    test rax, rax
    jnz  .refused
    ; Executor entry succeeded. No ordinary host work follows guest restore.
    lea  rdi, [rel vca_xstate]
    call vcpu_ap_xstate_guest
    mov  rax, [rel vca_guest_cr2]
    mov  cr2, rax
    mov  rax, [rel vca_debug + 0]
    mov  dr0, rax
    mov  rax, [rel vca_debug + 8]
    mov  dr1, rax
    mov  rax, [rel vca_debug + 16]
    mov  dr2, rax
    mov  rax, [rel vca_debug + 24]
    mov  dr3, rax
    mov  rax, [rel vca_guest_dr6]
    mov  dr6, rax
    mov  edi, 0x482E
    mov  esi, [rel vca_timer]
    vmwrite rdi, rsi
    jc   .failed_pre
    jz   .failed_pre
    ; Fresh check immediately before EVERY physical launch/resume. No stale
    ; GO grant, no forced activity0, and no RET/CALL after this final check.
    mov  edi, 0x4826
    vmread rax, rdi
    jc   .failed_pre
    jz   .failed_pre
    test rax, rax
    jnz  .skip
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  .failed_pre
    mov  eax, [rel vca_cycle]
    cmp  eax, [rel vcg_down]
    je   .skip
    cmp  eax, [rel vcg_go]
    jne  .failed_pre
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel vca_deadline]
    jae  .skip
    mov  byte [rel vcg_root + 1], 0
    ; Scoped stop redirect: malformed LAND/FINAL never reaches a RET before
    ; an unconditional RSB stop floor on this AP.
%define cpu_boundary_fail_stop vca_stop
    HV_BOUNDARY_FINAL
%undef cpu_boundary_fail_stop
    cmp  dword [rel vca_launched], 0
    jne  .resume
    VCA_LOAD_GPRS
    vmlaunch
    jmp  vca_entry_failed
.resume:
    VCA_LOAD_GPRS
    vmresume
    jmp  vca_entry_failed
.failed_pre:
    mov  dword [rel vca_failed], 1
.skip:
    ; Close a prepared pair through the same inline frontier without entry.
    ; This is an AP-local canceled attempt, never an inactive guest entry.
%define cpu_boundary_fail_stop vca_stop
    HV_BOUNDARY_FINAL
%undef cpu_boundary_fail_stop
    jmp  vca_canceled
.refused:
    mov  dword [rel vca_status], 3        ; BSP must report selector refusal
    lea  rdi, [rel vca_xstate]
    call vcpu_ap_xstate_host
    jmp  .clear
.idle:
    mov  dword [rel vca_status], 1
.clear:
    lea  rdi, [rel vca_vmx]
    call vcpu_ap_vmx_clear
    ; Only a known closed pair and cleared VMCS may reach the hook's ack.
    cmp  qword [rsp + HVB_ACTIVE], 0
    jne  vca_stop
    cmp  qword [rsp + HVB_FRONTIER], 0
    jne  vca_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vca_stop
    mov  rsi, rsp
    lea  rdi, [rel vcg_frame]
    mov  ecx, HVB_SIZE / 8
    rep  movsq
    mov  qword [rel vca_frame], 0
    add  rsp, HVB_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Hardware HOST_RSP == the retained actual stack frame. First instruction
; publishes root; all15 guest GPRs precede LAND, every CALL/RET and scratch.
vca_exit_landing:
    mov  byte [rel vcg_root + 1], 1
    VCA_SAVE_GPRS
    mov  rax, cr2
    mov  [rel vca_guest_cr2], rax
    mov  rax, dr6
    mov  [rel vca_guest_dr6], rax
    mov  dword [rel vca_launched], 1
    jmp  vca_land
vca_entry_failed:
    mov  byte [rel vcg_root + 1], 1
    ; VMfail returns with guest registers loaded, but no guest execution.
    ; Preserve the previous retained GPRs and close before fail-stop.
    mov  dword [rel vca_failed], 1
    jmp  vca_land
vca_canceled:
    mov  byte [rel vcg_root + 1], 1
    mov  dword [rel vca_cancel_flag], 1
vca_land:
%define cpu_boundary_fail_stop vca_stop
    HV_BOUNDARY_LAND
%undef cpu_boundary_fail_stop
    VAX_LAND vca_xstate
    mov  rax, [rel vca_host_cr2]
    mov  cr2, rax
    mov  rax, [rel vca_host_debug + 0]
    mov  dr0, rax
    mov  rax, [rel vca_host_debug + 8]
    mov  dr1, rax
    mov  rax, [rel vca_host_debug + 16]
    mov  dr2, rax
    mov  rax, [rel vca_host_debug + 24]
    mov  dr3, rax
    mov  rax, [rel vca_host_dr6]
    mov  dr6, rax
    mov  rdi, rsp
    call hv_boundary_exit
    lea  rdi, [rel vca_xstate]
    call vcpu_ap_xstate_host
    cmp  dword [rel vca_failed], 0
    jne  vca_stop
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vca_stop
    cmp  dword [rel vca_cancel_flag], 0
    jne  vcpu_ap_run.clear
    mov rdi,rsp
    mov edx,3
    call hv_boundary_exec_vmx
    ; Capture deferred data after executor exit; no BSP dispatcher on this AP.
    xor  r12d, r12d
.read_exit:
    lea  rax, [rel vca_exit_fields]
    mov  edi, [rax + r12*4]
    vmread rax, rdi
    jc   vca_stop
    jz   vca_stop
    lea  rdi, [rel vca_exit]
    mov  [rdi + r12*8], rax
    inc  r12d
    cmp  r12d, 6
    jb   .read_exit
    mov  eax, [rel vca_exit]
    test eax, 1 << 31                   ; failed VM entry, not a guest exit
    jnz  vca_stop
    mov  esi, eax
    mov  edi, 1
    call vob_end
    mov  eax, [rel vca_exit]
    and  eax, 0xFFFF
    cmp  eax, 52                        ; preemption timer: bounded local exit
    je   vcpu_ap_run.again
    cmp  eax, 1                         ; acknowledged host external interrupt
    jne  .defer                        ; ordinary exit -> BSP after ACK
    mov  eax, [rel vca_exit + 16]
    mov  edx, eax
    and  edx, 0x80000700
    cmp  edx, 0x80000000                 ; valid, external-interrupt type0
    jne  vca_stop
    movzx ebx, al
    cmp  ebx, 32
    jb   vca_stop
    lea  rdi, [rel vcg_hostvec]
    bts  [rdi], ebx
    ; EOI only the host LAPIC, never guest device models or shared glapic.
    cmp  byte [rel smp_lapic_mode], 0
    je   .xapic_eoi
    mov  ecx, X2APIC_MSR_BASE + (0xB0 >> 4)
    xor  eax, eax
    xor  edx, edx
    wrmsr
    jmp  vcpu_ap_run.again
.xapic_eoi:
    mov  rdi, 0xFEE000B0
    mov  dword [rdi], 0
    jmp  vcpu_ap_run.again

.defer:
    mov  dword [rel vca_status], 2
    mov  eax, [rel vca_cycle]
    mov  [rel vca_deferred], eax         ; validity bound to this exact cleared GO
    jmp  vcpu_ap_run.clear

vca_stop:
    mov  byte [rel vcg_root + 1], 1
    mov  dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov  edi, VCA_STOP
    jmp  cpu_boundary_fail_stop_reason

align 4
vca_exit_fields: dd 0x4402,0x6400,0x4404,0x440C,0x2400,0x640A
%macro WDATA_hv_vcpu_ap_run 0
align 16, db 0
vca_ready: dq 0
vca_reset: dq 0
vca_frame: dq 0
vca_deadline: dq 0
vca_host_cr2: dq 0
vca_guest_cr2: dq 0
vca_host_debug: times 4 dq 0
vca_host_dr6: dq 0
vca_debug: times 4 dq 0
vca_guest_dr6: dq 0xFFFF0FF0
vca_cycle: dd 0
vca_timer: dd 0
vca_failed: dd 0
vca_launched: dd 0
vca_cancel_flag: dd 0
vca_deferred: dd 0
vca_status: dd 0                      ;0 closed,1 idle,2 deferred,3 refused
align 16, db 0
vca_vmx: times VAP_SIZE db 0
vca_go_desc: times 64 db 0
vca_xstate: times VAX_SIZE db 0
vca_gpr: times 15 dq 0
vca_exit: times 6 dq 0
align 16, db 0
vca_guest_msrs: times 6 dq 0,0
vca_host_msrs: times 6 dq 0,0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_ap_run
