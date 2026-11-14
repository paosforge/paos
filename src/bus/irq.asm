;; MODULE bus/irq
;; LAYER 2
;; EXPORTS apic_init, apic_cap_selftest, cap_mmio_read32, cap_mmio_write32, fault_containment_account
;; IMPORTS boot/serial, core/time, core/lib/fmt, core/smp, bus/hal
;; CAPS CAP_MMIO, CAP_IRQ
;; OWNER saga:bus
; ============================================================================
; bus/irq.asm — LAPIC online + periodic timer + the CAPABILITY seam (C6/1006).
;
; TWO things land here, both non-retrofittable-at-v1:
;
;  1. The capability model (SECURITY.md §3-4). Destructive hardware primitives —
;     here, MMIO poke/peek — are GATED on the current principal holding an
;     explicit capability bit (CAP_MMIO). The gate is a RUNTIME CHECK that runs
;     BEFORE the operation, not an advisory warning: a principal without CAP_MMIO
;     is BLOCKED (CF=1, DENY logged, no MMIO performed, read returns 0 not garbage).
;     cap_mmio_{read,write}32 are the gated entry points; every driver pokes the
;     LAPIC through them, never through hal_* or a raw `mov [mmio]` directly.
;     `cap_current` is the current principal's capability word — in the full model
;     this lives in the task struct (core/sched); at this seam it is a single
;     kernel global the selftest flips between principal A (the authorized irq
;     module, CAP_MMIO|CAP_IRQ) and principal B (a throwaway timer-access module
;     with NO caps) to prove the gate both PERMITS and DENIES.
;
;  2. The Local APIC (0xFEE00000, identity-mapped in boot/paging's 0-16 GiB map):
;     SVR enabled (spurious vec 0xFF, APIC-enable bit), periodic timer armed
;     (divide-by-16, vector 0x20), ICR calibrated so the counter reloads at ~1000
;     Hz. The LVT is armed MASKED (bit16): the counter free-runs (CCR decrements
;     + reloads — the "running" proof) but does NOT deliver an interrupt, because
;     the legacy PIT (core/time) already OWNS vector 0x20 / IRQ0 delivery and a
;     second unacked source on the same vector would just fight it. The LAPIC's
;     job at this seam is the free-running time base + the cap gate, not a second
;     IRQ0. (Unmasked LAPIC-timer IRQ delivery + LAPIC-EOI is a later refinement
;     once the IO-APIC replaces the 8259 — SKELETON.md L2+.)
;
; Grounding: monolith paos.asm apic_init (SVR/DCR/ICR), hal/ESSENCE.md MMIO layer.
; ============================================================================

; ---- capability bits (SECURITY.md §3: the CAP_* vocabulary) ----
CAP_MMIO          equ 1                      ; may touch device MMIO registers
CAP_IRQ           equ 2                      ; may register/handle hardware IRQs

; ---- Local APIC (xAPIC MMIO) — offsets from APIC_BASE (Intel SDM Vol.3 10.4) ----
IA32_APIC_BASE    equ 0x1B                    ; MSR: bit 11 = xAPIC global enable
APIC_BASE_PHYS    equ 0xFEE00000
APIC_ID           equ 0x020                   ; Local APIC ID (side-effect-free read)
APIC_SVR          equ 0x0F0                   ; Spurious Interrupt Vector Register
APIC_LVT_TIMER    equ 0x320                   ; LVT timer entry
APIC_TIMER_ICR    equ 0x380                   ; Initial Count
APIC_TIMER_CCR    equ 0x390                   ; Current Count (the negative-test target)
APIC_TIMER_DCR    equ 0x3E0                   ; Divide Configuration
SVR_ENABLE_VFF    equ 0x1FF                   ; APIC-enable (bit8) | spurious vec 0xFF
DCR_DIV16         equ 0x03                    ; divide input clock by 16
LVT_PERIODIC_MASK equ 0x30020                 ; periodic(bit17)|masked(bit16)|vec 0x20
LVT_ONESHOT_MASK  equ 0x10020                 ; one-shot|masked|vec 0x20 (calibration)

; ============================================================================
; cap_mmio_write32(RDI=region, RSI=offset, EDX=value) -> CF=1 on capability deny.
;   The capability check runs FIRST (before any MMIO). If the current principal
;   lacks CAP_MMIO: bump deny counter, set CF, do NOTHING to hardware. Otherwise
;   fall through to the HAL's bounds-checked store (which itself may reject OOB).
; ============================================================================
cap_mmio_write32:
    test qword [rel cap_current], CAP_MMIO
    jz   .deny
    lea  rax, [rel apic_region]
    cmp  rdi, rax
    jne  .hal
    cmp  byte [rel smp_lapic_mode], 0
    je   .hal
    call smp_lapic_write32                 ; x2APIC MSR path, same capability gate
    jc   .ret
    inc  qword [rel cap_mmio_access_count]
    clc
    ret
.hal:
    call hal_mmio_write32                     ; authorized -> HAL bounds gate + store
    jc   .ret
    inc  qword [rel cap_mmio_access_count]    ; count actual accepted store
    clc
.ret:
    ret
.deny:
    inc  qword [rel cap_deny_count]
    stc
    ret

; cap_mmio_read32(RDI=region, RSI=offset) -> EAX=value; CF=1 on capability deny.
;   Same gate-first discipline. A denied read LOGS the DENY marker (observable,
;   per the contract: a silent error is un-provable), returns EAX=0 (not the real
;   register, not garbage) and CF=1. The caller chooses the side-effect-free APIC
;   register used by its proof (CCR in the boot KAT, ID in MMIOCAP).
cap_mmio_read32:
    test qword [rel cap_current], CAP_MMIO
    jz   .deny
    lea  rax, [rel apic_region]
    cmp  rdi, rax
    jne  .hal
    cmp  byte [rel smp_lapic_mode], 0
    je   .hal
    call smp_lapic_read32                  ; x2APIC MSR path, same capability gate
    jc   .ret
    inc  qword [rel cap_mmio_access_count]
    clc
    ret
.hal:
    call hal_mmio_read32                      ; authorized -> HAL bounds gate + load
    jc   .ret
    inc  qword [rel cap_mmio_access_count]    ; count actual accepted load
    clc
.ret:
    ret
.deny:
    inc  qword [rel cap_deny_count]
    lea  rdi, [rel str_cap_deny]
    call serial_string
    xor  eax, eax                            ; value = 0 (never the real register)
    stc
    ret

; ============================================================================
; apic_init — bring the LAPIC online + arm the periodic timer. Runs under the cap
;   gate (caller must have set cap_current with CAP_MMIO), so every register poke
;   also exercises the authorized path of the seam.
; ============================================================================
apic_init:
    ; --- xAPIC global-enable via IA32_APIC_BASE MSR bit 11 (belt + suspenders;
    ;     QEMU enables it at reset, but assert it so MMIO decode is guaranteed) ---
    mov  ecx, IA32_APIC_BASE
    rdmsr
    or   eax, 0x800                          ; bit 11 = xAPIC enable
    wrmsr
    call smp_lapic_detect_mode               ; preserve firmware-selected xAPIC/x2APIC
    ; --- SVR = 0x1FF (APIC software-enable + spurious vector 0xFF) ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_SVR
    mov  edx, SVR_ENABLE_VFF
    call cap_mmio_write32
    ; --- timer divide = /16 ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_DCR
    mov  edx, DCR_DIV16
    call cap_mmio_write32
    ; --- LVT timer = periodic, vector 0x20, MASKED (counter free-runs; PIT owns
    ;     actual IRQ0 delivery). "periodic timer armed" per the contract. ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_LVT_TIMER
    mov  edx, LVT_PERIODIC_MASK
    call cap_mmio_write32
    ; --- ICR = nominal 0x100000 (recalibrated to 1000 Hz by apic_timer_measure) ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_ICR
    mov  edx, 0x100000
    call cap_mmio_write32
    lea  rdi, [rel str_apic_init]            ; marker: apic.init.ok
    call serial_string
    ret

; ============================================================================
; apic_timer_measure — select a nominal 1000 Hz reload, then count
;   10 real reloads over TSC, emitting the "APIC timer tick: ... ticks: N" line the
;   probe content-grades + the timer.lapic.running marker. Observing a reload
;   target alone is not independent confirmation of frequency or IRQ delivery.
;   Honest measurement:
;   the LAPIC input clock is unknown a priori (QEMU ~1 GHz/16), so we time a
;   one-shot countdown against the (already TSC-calibrated) 10 ms delay to derive
;   ticks/ms, program that as the periodic ICR, then observe the counter sawtooth.
; ============================================================================
apic_timer_measure:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; --- one-shot, full-scale, to measure LAPIC ticks per 10 ms ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_LVT_TIMER
    mov  edx, LVT_ONESHOT_MASK
    call cap_mmio_write32
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_DCR
    mov  edx, DCR_DIV16
    call cap_mmio_write32
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_ICR
    mov  edx, 0xFFFFFFFF                      ; start full-scale one-shot countdown
    call cap_mmio_write32
    lea  rdi, [rel apic_region]              ; CCR0
    mov  esi, APIC_TIMER_CCR
    call cap_mmio_read32
    mov  r12d, eax
    mov  rdi, 10000                          ; wait 10 ms (TSC-calibrated)
    call tsc_delay_us
    lea  rdi, [rel apic_region]              ; CCR1
    mov  esi, APIC_TIMER_CCR
    call cap_mmio_read32
    mov  r13d, eax
    ; ticks_10ms = CCR0 - CCR1 ; ICR_1ms = ticks_10ms / 10
    mov  eax, r12d
    sub  eax, r13d
    xor  edx, edx
    mov  ecx, 10
    div  ecx                                 ; eax = LAPIC ticks per 1 ms
    mov  r14d, eax
    test r14d, r14d
    jnz  .have_icr
    mov  r14d, 0x1000                        ; degenerate measurement -> safe fallback
.have_icr:
    ; Hand the scheduler the measured BSP reload before any later owner
    ; (including PMOD) can borrow deadline mode.  The C6 KAT already earned
    ; this calibration; central timer restoration must replay it, not the
    ; nominal 0x100000 bring-up count.
    mov  edi, r14d
    call smp_preempt_set_bsp_initial
    ; --- arm periodic at the calibrated 1000 Hz ICR ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_LVT_TIMER
    mov  edx, LVT_PERIODIC_MASK
    call cap_mmio_write32
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_ICR
    mov  edx, r14d                           ; ICR = ticks/ms -> reload @ ~1000 Hz
    call cap_mmio_write32
    ; --- count 10 reloads (CCR jumps UP = a new period began) over TSC ---
    call tsc_now
    mov  r15, rax                            ; TSC start
    mov  rcx, [rel tsc_khz]
    imul rcx, 200                            ; 200 ms safety bound (ticks)
    add  rcx, r15                            ; abort-TSC
    mov  rbx, rcx                            ; stash abort-TSC (rcx is clobbered by reads)
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_CCR
    call cap_mmio_read32
    mov  r13d, eax                           ; prev CCR
    xor  r12d, r12d                          ; reload count
.count_loop:
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_CCR
    call cap_mmio_read32
    cmp  eax, r13d
    jbe  .no_reload                          ; cur <= prev: still counting down
    inc  r12d                                ; cur > prev: counter reloaded
.no_reload:
    mov  r13d, eax                           ; prev = cur
    cmp  r12d, 10
    jae  .counted
    call tsc_now
    cmp  rax, rbx                            ; past safety bound?
    jb   .count_loop
.counted:
    call tsc_now
    sub  rax, r15                            ; elapsed TSC ticks
    mov  rcx, 1000
    mul  rcx                                 ; rdx:rax = elapsed * 1000
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .div_ok
    xor  eax, eax                            ; no fabricated microseconds without a scale
    jmp  .elapsed_ready
.div_ok:
    div  rcx                                 ; rax = elapsed_us
.elapsed_ready:
    mov  r14, rax
    ; Preserve the actual count and elapsed time, including bounded partial work.
    ; Never promote a timeout or fallback reload to a frequency confirmation.
    lea  rdi, [rel str_tick_a]
    call serial_string
    mov  rdi, r12                            ; actual reload count, including partial work
    lea  rsi, [rel apic_numbuf]
    call fmt_dec
    lea  rdi, [rel apic_numbuf]
    call serial_string
    lea  rdi, [rel str_tick_b]
    call serial_string
    mov  rdi, r14                            ; elapsed_us (real measurement)
    lea  rsi, [rel apic_numbuf]
    call fmt_dec
    lea  rdi, [rel apic_numbuf]
    call serial_string
    lea  rdi, [rel str_tick_partial]
    cmp  qword [rel tsc_khz], 0
    je   .uncalibrated
    cmp  r12d, 10
    jb   .result_ready
    lea  rdi, [rel str_tick_reached]
    jmp  .result_ready
.uncalibrated:
    lea  rdi, [rel str_tick_uncalibrated]
.result_ready:
    call serial_string
    lea  rdi, [rel str_tick_c]
    call serial_string
    ; --- timer.lapic.running iff the counter actually reloaded ---
    test r12d, r12d
    jz   .done
    lea  rdi, [rel str_timer_running]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; apic_cap_selftest — the C6 acceptance. Positive path (authorized) + negative
;   path (unauthorized principal BLOCKED). Emits all four regression markers.
; ============================================================================
apic_cap_selftest:
    ; --- principal A: the authorized irq module (CAP_MMIO | CAP_IRQ) ---
    mov  qword [rel cap_current], CAP_MMIO | CAP_IRQ
    call apic_init                           ; -> apic.init.ok
    call apic_timer_measure                  ; -> "APIC timer tick:..." + timer.lapic.running
    ; --- positive cap path: authorized read of SVR must SUCCEED (CF=0) ---
    lea  rdi, [rel apic_region]
    mov  esi, APIC_SVR
    call cap_mmio_read32
    jc   .fail                               ; authorized read must not be denied
    lea  rdi, [rel str_cap_enforced]         ; -> cap.mmio.enforced (guard live + permits)
    call serial_string
    ; --- principal B: a throwaway timer-access module with NO capabilities ---
    mov  qword [rel cap_current], 0
    lea  rdi, [rel apic_region]
    mov  esi, APIC_TIMER_CCR                 ; try to read APIC timer Current Count (0x390)
    call cap_mmio_read32                      ; MUST deny: logs DENY marker, CF=1, EAX=0
    jnc  .fail                               ; unauthorized read MUST be rejected
    test eax, eax
    jnz  .fail                               ; denied read MUST return 0, not the register
    lea  rdi, [rel str_cap_blocked]          ; -> cap.violation.blocked
    call serial_string
    ; --- restore the authorized principal; report measured health state ---
    mov  qword [rel cap_current], CAP_MMIO | CAP_IRQ
    lea  rdi, [rel str_c6_crashes]
    call serial_string
    movzx edi, byte [rel boot_crashes_observed]
    lea  rsi, [rel apic_numbuf]
    call fmt_dec
    lea  rdi, [rel apic_numbuf]
    call serial_string
    lea  rdi, [rel str_c6_faults]
    call serial_string
    movzx edi, byte [rel faults_contained_current]
    lea  rsi, [rel apic_numbuf]
    call fmt_dec
    lea  rdi, [rel apic_numbuf]
    call serial_string
    lea  rdi, [rel str_c6_end]
    call serial_string
    call smp_preempt_init_local            ; restore scheduler vector after the C6 timer KAT
    ret
.fail:
    mov  qword [rel cap_current], CAP_MMIO | CAP_IRQ
    lea  rdi, [rel str_cap_fail]
    call serial_string
    call smp_preempt_init_local
    ret

; fault_containment_account — shared post-resume accounting boundary (1216).
; Call only after a captured fault frame has been validated and control has
; resumed. Saturation preserves a bounded bare-integer health surface even
; under a fault storm. No packet/reply path writes this counter.
fault_containment_account:
    cmp  byte [rel faults_contained_current], 0xFF
    je   .done
    inc  byte [rel faults_contained_current]
.done:
    ret

; --- bus/irq data (in-image writable; lands in the RW+X low identity region) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_bus_irq_0 0
apic_region:                                ; HAL region handle { bar_base, bar_size }
    dq APIC_BASE_PHYS                        ; .bar_base = 0xFEE00000 (identity-mapped)
    dq 0x1000                                ; .bar_size = 4 KiB (one LAPIC page)
cap_current:     dq 0                        ; current principal's capability word
cap_deny_count:  dq 0                        ; unauthorized-access denials this boot
cap_mmio_access_count: dq 0                  ; accepted accesses reaching MMIO
faults_contained_current: db 0               ; current boot, saturating at 255
apic_numbuf:     times 24 db 0               ; fmt_dec scratch (u64 decimal + NUL)

str_apic_init:      db "[PAOS64] M2 apic: LAPIC init SVR+timer armed [apic.init.ok]", 13, 10, 0
str_timer_running:  db "[PAOS64] M2 apic: LAPIC periodic timer running [timer.lapic.running]", 13, 10, 0
str_cap_enforced:   db "[PAOS64] M2 cap: CAP_MMIO runtime guard active [cap.mmio.enforced]", 13, 10, 0
str_cap_blocked:    db "[PAOS64] M2 cap: unauthorized APIC read rejected [cap.violation.blocked]", 13, 10, 0
str_cap_deny:       db "[PAOS64-CAP] CAP_MMIO required: DENIED before MMIO access", 13, 10, 0
str_cap_fail:       db "[PAOS64] M2 cap: SEAM SELFTEST FAIL", 13, 10, 0
str_c6_crashes:     db "[PAOS64] C6 apic/cap seam: CRASHES=", 0
str_c6_faults:      db " FAULTS_CONTAINED=", 0
str_c6_end:         db 13, 10, 0
str_tick_a:         db "[PAOS64] APIC timer tick: measurement (ticks: ", 0
str_tick_b:         db ", elapsed_us: ", 0
str_tick_partial:   db ", result: partial", 0
str_tick_reached:   db ", result: reload_target_reached", 0
str_tick_uncalibrated: db ", result: uncalibrated", 0
str_tick_c:         db ")", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_bus_irq_0
