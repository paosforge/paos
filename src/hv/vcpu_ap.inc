; T1-5 S7: the gang's W-BSP sequence and stop floor, expanded in callers.
; SEC E1 (VCPU_AP_PLAN_READ): between a VM exit and that core's own executor
; exit, guest SPEC_CTRL, RSB and branch history are still live. Code on that
; path has no RET, no CALL and no indirect branch, only direct jumps, and
; loads no secret: VCG_GANG_DOWN, the abort entries and stub, and the BSP
; stops. A stop path enters the boundary stop only after VCG_STOP_FLOOR.
%ifndef HV_VCPU_AP_INC
%define HV_VCPU_AP_INC 1
%include "hv/boundary_transition.inc"

VCG_WAIT_MS       equ 10               ; > one ~1 ms preemption slice plus exit work
VCG_ABORT_BIT     equ 1
VCG_KICK_VECTOR   equ SMP_IDLE_WAKE_VECTOR

; %1 = 64-bit register <- TSC now + VCG_WAIT_MS. Clobbers RAX, RCX, RDX.
%macro VCG_DEADLINE 1
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  %%rate
    mov  rcx, 3000000                      ; bounded degrade, as the run deadline
%%rate:
    imul rcx, rcx, VCG_WAIT_MS
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    lea  %1, [rax + rcx]
%endmacro

; Before a stop path's first RET (the stop's serial emit): overwrite the
; guest-filled RSB. The owner check keeps CR4.CET clear for the whole epoch.
%macro VCG_STOP_FLOOR 0
    HV_BOUNDARY_FILL32
%endmacro

; The W-BSP fixed sequence, expanded once at the BSP's VM-exit landing after
; its exit stub stored vcg_root[0] (C1, D1). Tests ABORT first, ends a live
; cycle (vcg_down, kick) and waits for vCPU1's ack, then restores the shared
; IDT and falls through: only then may the BSP run its executor exit (P3).
; It never falls through with vCPU1 in guest mode (C5). Clobbers RAX, RCX,
; RDX, R8, R9.
%macro VCG_GANG_DOWN 0
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vcg_bsp_abort_seen
    mov  r8d, [rel vcg_go]
    cmp  r8d, [rel vcg_ack]
    je   %%down
    mov  [rel vcg_down], r8d
    ; Kick vCPU1: in guest mode a host IPI is an external-interrupt exit.
    mov  edx, [rel vcg_apic + 4]
    mov  eax, SMP_ICR_FIXED | VCG_KICK_VECTOR
    cmp  byte [rel smp_lapic_mode], 0
    je   %%xapic
    mov  ecx, X2APIC_MSR_BASE + (0x300 >> 4)
    wrmsr
    jmp  %%kicked
%%xapic:
    mov  ecx, 100000
    mov  r9, LAPIC_ICR_LO
%%idle:
    test dword [r9], 1 << 12               ; the previous send is still pending
    jz   %%send
    dec  ecx
    jnz  %%idle
%%send:
    shl  edx, 24
    mov  rcx, LAPIC_ICR_HI
    mov  [rcx], edx
    mov  [r9], eax
%%kicked:
    VCG_DEADLINE r9
%%wait:
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vcg_bsp_abort_seen
    cmp  r8d, [rel vcg_ack]
    je   %%down
    pause
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, r9
    jb   %%wait
    jmp  vcg_stop_down
%%down:
    lidt [rel vcg_idtr_shared]
%endmacro
%endif
