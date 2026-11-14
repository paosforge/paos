;; MODULE svc/reserve_gate
;; LAYER 5
;; EXPORTS reserve_gate_admit, reserve_gate_open, reserve_gate_open_tsc, reserve_gate_quiet_tsc
;; IMPORTS boot/header, core/time, hv/vmx
;; CAPS
;; OWNER saga:rc_speed_reserve_gate
; Spec 7.6.7 item 3 (root 2026-10-17 15:27:11): speed-reserve work (warm local
; model, preloading) starts only after the desktop is ready and idle, so it can
; move no G0-G11 gate. BOOT owns this read-only gate; rc-resource's SPEED_RESERVE
; (kind 3) admission calls it. Reclaim, guest START and snapshots are not gated.
;
; Closed until all of these hold continuously for RESERVE_QUIET_MS:
;   calibrated TSC (tsc_khz), interactive desktop stamp (boot_tsc_end),
;   readiness gate pass (boot_bg5_ready_tsc), every settle producer decided
;   (boot_settle_state: complete or not-required), and no accepted guest START
;   short of guest init (hv_linux_start_active && !hv_guest_booted).
; Then it latches open for this boot. A condition dropping before the interval
; ends restarts it. Reads only; writes only its own three cells.

RESERVE_QUIET_MS equ 10000
RESERVE_SETTLE_SLOTS equ 4

; reserve_gate_admit -> EAX=1 open, 0 closed. Clobbers RCX, RDX, R8-R10 and
; flags only; SysV nonvolatiles are preserved.
reserve_gate_admit:
    cmp  byte [rel reserve_gate_open], 1
    je   .yes
    mov  r8, [rel tsc_khz]
    test r8, r8
    jz   .reset
    cmp  qword [rel boot_tsc_end], 0
    je   .reset
    cmp  qword [rel boot_bg5_ready_tsc], 0
    je   .reset
    lea  r9, [rel boot_settle_state]
    xor  ecx, ecx
.settle:
    cmp  byte [r9 + rcx], 0
    je   .reset
    inc  ecx
    cmp  ecx, RESERVE_SETTLE_SLOTS
    jb   .settle
    cmp  byte [rel hv_linux_start_active], 0
    je   .quiet
    cmp  byte [rel hv_guest_booted], 0
    je   .reset
.quiet:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r10, [rel reserve_gate_quiet_tsc]
    test r10, r10
    jnz  .elapsed
    mov  [rel reserve_gate_quiet_tsc], rax
    jmp  .no
.elapsed:
    sub  rax, r10
    jb   .reset                         ; regressed stamp: start the interval again
    imul r8, r8, RESERVE_QUIET_MS       ; tsc_khz = ticks per ms
    cmp  rax, r8
    jb   .no
    add  rax, r10
    mov  [rel reserve_gate_open_tsc], rax
    mov  byte [rel reserve_gate_open], 1
.yes:
    mov  eax, 1
    ret
.reset:
    mov  qword [rel reserve_gate_quiet_tsc], 0
.no:
    xor  eax, eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_svc_reserve_gate 0
reserve_gate_quiet_tsc: resq 1          ; first TSC of the current all-true interval
reserve_gate_open_tsc:  resq 1          ; TSC at which the gate latched open
reserve_gate_open:      resb 1          ; sticky 1 once open
%endmacro
WDATA_BSS_DEFER WDATA_svc_reserve_gate
