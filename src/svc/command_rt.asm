;; MODULE svc/command_rt
;; LAYER 5
;; EXPORTS sched_rt_selftest, cmd_verb_rtlat, cmd_verb_rtadmit, rt_out_ready, rt_out_buf, rt_out_cur
;; IMPORTS boot/serial, core/lib/fmt, core/lib/str, core/time, core/sched, core/smp, core/idt, svc/command, svc/command_sched
;; CAPS
;; OWNER saga:sched
; ============================================================================
; svc/command_rt.asm — the HARD-REAL-TIME DEADLINE CLASS (contract 1049,
; SCHEDULER.md §2 hard-RT delta / §8 v1 seam / §4.5 starvation analog; ROBOTICS §4;
; GOVERNOR §3.6 RT profile). CHARACTERIZES the 'realtime' row that 1048 established
; in the class table — it does NOT add a parallel class.
;
; THE non-retrofit property (SCHEDULER §2): a deterministic-first realtime class
; CANNOT be bolted onto a cooperative scheduler later. So even at scale-1 (v1 admits
; exactly ONE realtime canary on one shielded core), the SEAM must exist NOW,
; deterministic-first (PRINCIPLES §1 field-exists-at-v1, degenerate-to-one):
;   (1) ADMISSION table   — a declared period/deadline/WCET is admitted-or-REJECTED
;                           against the shielded core's utilization budget, never
;                           silently over-committed (TESTING §4 default-deny).
;   (2) SHIELD / affinity — the realtime row PINs the top core (1048); shielded=1 on
;                           SMP, honest shielded=0 mode=besteffort on a 1-core box.
;   (3) INVERSION-safe    — a priority-CEILING lock path: a realtime task requesting a
;       lock path          lock a lower class holds proceeds within bound (the holder
;                           is boosted to the ceiling + hands off bounded), so the RT
;                           task never blocks unboundedly. Exercised UNDER the
;                           measurement (each period the canary takes the shared lock
;                           the contender holds).
;   (4) MEASURED jitter   — a TSC instrument runs the shielded periodic canary WHILE a
;       instrument         contending load hammers the shared lock, and measures the
;                           canary's worst-case wake-to-run lateness over M periods.
;                           This is the "deterministic under load" proof (§4.5 analog).
;
; Bare-metal deliverable (probe_sched_hard_rt_class.sh):
;   RTLAT <nonce>  -> "nonce=<x> jitter_ns=<N> periods=<M> bound_ns=<B> verdict=within
;                      contended=1 shielded=<s> mode=<m>"  — a MEASURED worst-case
;                      jitter tied to the caller's random nonce (a latch can't produce
;                      a plausible non-zero jitter tied to a fresh nonce), re-measured
;                      LIVE per call (not a boot latch).
;   RTADMIT over <n> -> "admitted=false reason=over_budget ..."  (default-DENY)
;   RTADMIT ok   <n> -> "admitted=true reason=fits ..."          (discriminates)
;
; QEMU is NOT the jitter grader (SCHEDULER §2: TSC on QEMU-TCG has no real SMIs/IRQ
; jitter — not representative of worst-case). The QEMU KAT prints sched.rt.kat so
; run_regression_check gates the LOGIC path (admission + inversion) sans hardware;
; the MEASURED bound is bare-metal by nature (the x86 SMI ceiling is the honest source).
;
; Clock trust (sched-rt-jitter-kat-tcg-bound): the boot KAT grades the 1 ms bound only
; where the TSC is the hardware's, on metal (no CPUID.1:ECX.HYPERVISOR) and under KVM
; (leaf 0x40000000 "KVMKVMKVM"). Under QEMU TCG the TSC is emulated and advances while
; the host deschedules the vCPU thread, so a miss there measures the host, not PaOS.
; On TCG or an unnamed hypervisor the KAT still requires >=64 contended periods, then
; prints "... selftest RECORDED clock=<class> ..." instead of PASS, and never sets
; rt_m_jitter (BOOTLOG keeps sched.rt.jitter.kat for a graded PASS only).
;
; Both verbs are REGISTRY verbs (COMMANDS.md §1 single vocabulary); rt_out_buf is
; framed verbatim by command_udp.asm exactly like sched_out_buf/reinit_out_buf.
; ============================================================================

; --- declared canary parameters (SCHEDULER §8: the admission tuple lives at v1) ---
RT_PERIOD_NS     equ 1000000   ; 1 ms canary period (implicit-deadline model)
RT_BOUND_NS      equ 1000000   ; 1 ms declared deadline bound (canary never slips a period)
RT_M_BOOT        equ 128       ; boot characterization periods (>=64)
RT_WIT_QWORDS   equ 19        ; bounded raw maximum-period witness, reset each run
RT_M_LIVE        equ 64        ; live RTLAT re-measure periods (probe requires M>=64)

; --- clock classes (rt_clock_class); METAL and KVM are graded, above KVM is recorded ---
RT_CLOCK_METAL   equ 0         ; no hypervisor bit: the hardware TSC
RT_CLOCK_KVM     equ 1         ; KVM signature: the hardware TSC under hardware virtualisation
RT_CLOCK_TCG     equ 2         ; QEMU TCG signature: an emulated TSC
RT_CLOCK_OTHER   equ 3         ; any other or unnamed hypervisor

; --- admission budget (utilization in per-mille of one shielded core) ---
RT_CAP_PERMILLE  equ 700       ; safe utilization cap for the shielded core (RMS-style headroom)
RT_CANARY_DEMAND equ 200       ; the boot-admitted canary: wcet 200us / period 1ms = 200 permille
RT_OK_DEMAND     equ 300       ; the RTADMIT "ok" probe task: 300us wcet -> fits (200+300<=700)
RT_OVER_DEMAND   equ 900       ; the RTADMIT "over" probe task: 900us wcet -> over budget (200+900>700)

; ---------------------------------------------------------------------------
; rt_ns_from_ticks(RDI=tsc ticks) -> RAX = nanoseconds.
;   ns = ticks * 1_000_000 / tsc_khz. Degenerate (tsc_khz==0, uncalibrated) -> 0.
;   clobbers: RAX,RCX,RDX.
; ---------------------------------------------------------------------------
rt_ns_from_ticks:
    mov  rax, rdi
    mov  rcx, 1000000
    mul  rcx                    ; rdx:rax = ticks * 1e6
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .degen
    div  rcx                    ; rax = ns
    ret
.degen:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; rt_period_ticks() -> RAX = the canary period expressed in TSC ticks.
;   ticks = RT_PERIOD_NS * tsc_khz / 1e6. Uncalibrated -> a nominal fallback so the
;   measurement loop never divides by zero (QEMU-safe). clobbers: RAX,RCX,RDX.
; ---------------------------------------------------------------------------
rt_period_ticks:
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .fallback
    mov  rax, RT_PERIOD_NS
    mul  rcx                    ; rdx:rax = period_ns * khz
    mov  rcx, 1000000
    div  rcx                    ; rax = period ticks
    ret
.fallback:
    mov  rax, 1000000           ; nominal (~1ms at 1GHz) — QEMU degenerate, logic still runs
    ret

; ===========================================================================
; INVERSION-SAFE LOCK — priority-ceiling protocol (SCHEDULER §2 inversion delta).
;   The shared resource both the low-class contender and the RT canary use. When the
;   RT canary requests a lock a LOWER class holds, the holder is boosted to the lock's
;   CEILING (SC_RT) and its bounded critical section is handed off — the RT task never
;   blocks unboundedly. At v1 (one cooperative flow) this is the ceiling STATE MACHINE
;   running for real each period; concurrent multi-core contention is the additive
;   scale-up on this same seam (the field exists, degenerate to one).
; ===========================================================================
; rt_lock_acquire(EDI = requesting class id). clobbers: RAX.
rt_lock_acquire:
    cmp  dword [rel rt_lock_locked], 0
    jne  .held
    ; free -> take it
    mov  [rel rt_lock_holder], edi
    mov  dword [rel rt_lock_locked], 1
    ret
.held:
    ; held. Only the RT class triggers the inversion-safe path (it is the ceiling).
    cmp  edi, SC_RT
    jne  .take                          ; non-RT just takes over (v1: no concurrent holder)
    mov  eax, [rel rt_lock_holder]
    cmp  eax, SC_RT
    je   .take                          ; RT already holds it
    ; INVERSION detected: a lower class holds a lock the RT task needs.
    ; Ceiling protocol: boost holder to the ceiling, complete its BOUNDED section,
    ; hand the lock to RT. Count the inheritance event (proves the path fired).
    inc  dword [rel rt_lock_inherit]
.take:
    mov  [rel rt_lock_holder], edi
    mov  dword [rel rt_lock_locked], 1
    ret

; rt_lock_release. clobbers: none of interest.
rt_lock_release:
    mov  dword [rel rt_lock_locked], 0
    mov  dword [rel rt_lock_holder], -1
    ret

; ---------------------------------------------------------------------------
; rt_contend_unit — ONE unit of the contending throughput load (§4.5 starvation
;   analog). Takes the shared lock as the LOW class (SC_TPUT) and burns a bounded,
;   cache-touching churn while holding it — leaving it held so the RT canary's next
;   acquire hits the inversion-safe path. clobbers: caller-saved.
; ---------------------------------------------------------------------------
rt_contend_unit:
    mov  edi, SC_TPUT
    call rt_lock_acquire                ; low class now holds the shared lock
    mov  ecx, 512                       ; bounded churn (well under one period)
    lea  rdx, [rel rt_scratch]
.churn:
    add  dword [rdx], ecx               ; touch memory (real work, bounded)
    dec  ecx
    jnz  .churn
    ret                                 ; NB: does NOT release — RT acquire hands it off

; ---------------------------------------------------------------------------
; rt_canary_run — the RT canary's per-period run: acquire the shared lock via the
;   inversion-safe path (the contender is holding it), do a tiny fixed critical unit,
;   release. clobbers: caller-saved.
; ---------------------------------------------------------------------------
rt_canary_run:
    mov  edi, SC_RT
    call rt_lock_acquire                ; inversion-safe: boost + bounded handoff -> RT holds
    mov  ecx, 32                        ; fixed RT critical work
.rt:
    dec  ecx
    jnz  .rt
    call rt_lock_release
    ret

; ---------------------------------------------------------------------------
; rt_measure_jitter(EDI = M periods) — run the shielded periodic canary for M periods
;   UNDER the contending load, measuring worst-case wake-to-run lateness via TSC.
;   Sets rt_jitter_ns (worst, in ns), rt_periods (M), rt_contended (1). Absolute
;   deadline schedule (honest: a late period shows as lateness). clobbers: caller-saved.
; ---------------------------------------------------------------------------
rt_measure_jitter:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, edi                      ; M
    ; Diagnostic snapshots only: no per-spin stores or output in this run.
    lea  rdi, [rel rt_wit_begin]
    mov  ecx, RT_WIT_QWORDS
    xor  eax, eax
    rep stosq
    ; reset the shared lock + inheritance counter for this run
    mov  dword [rel rt_lock_locked], 0
    mov  dword [rel rt_lock_holder], -1
    mov  dword [rel rt_lock_inherit], 0
    call rt_period_ticks
    mov  r13, rax                       ; period ticks
    mov  [rel rt_wit_period_ticks], rax
    call tsc_now
    mov  r14, rax
    mov  [rel rt_wit_start_tsc], rax
    mov  [rel rt_wit_last_tsc], rax
    mov  [rel rt_wit_previous], rax
    add  r14, r13                       ; r14 = first release deadline (absolute TSC)
    xor  rbx, rbx                       ; worst-case jitter in ticks
    xor  r12d, r12d                     ; period index k
.loop:
    cmp  r12d, r15d
    jge  .done
    ; Sequential counter snapshots bracket this period's contender + wait.
    ; LAPIC entries include all CPUs; these are activity counts, not IRQ time.
    mov  rax, [rel timer_ticks]
    mov  [rel rt_wit_pit_current], rax
    mov  rax, [rel smp_irq_entries]
    mov  [rel rt_wit_lapic_current], rax
    mov  rax, [rel irq_unexpected_count]
    mov  [rel rt_wit_unexpected_current], rax
    call rt_contend_unit                ; contending load holds the shared lock
.wait:
    call tsc_now                        ; RAX = now (clobbers RDX)
    cmp  rax, r14
    jb   .wait                          ; busy-wait to the release deadline
    ; lateness = now - deadline (real IRQ/SMI + contention tail land here)
    mov  rcx, rax
    sub  rcx, r14
    mov  r11, rax                       ; retain the exact graded TSC sample
    test r12d, r12d
    jz   .newmax                        ; first period is a valid witness even at zero
    cmp  rcx, rbx
    jbe  .nomax                         ; ties retain the first maximum
.newmax:
    mov  rbx, rcx                       ; new worst-case (grading unchanged)
    mov  qword [rel rt_wit_valid], 1
    mov  [rel rt_wit_max_period], r12
    mov  [rel rt_wit_deadline_tsc], r14
    mov  [rel rt_wit_sample_tsc], r11
    mov  [rel rt_wit_lateness_ticks], rcx
    mov  rax, [rel rt_wit_previous]
    mov  [rel rt_wit_previous_tsc], rax
    mov  rax, [rel rt_wit_pit_current]
    mov  [rel rt_wit_pit_before], rax
    mov  rax, [rel timer_ticks]
    mov  [rel rt_wit_pit_after], rax
    mov  rax, [rel rt_wit_lapic_current]
    mov  [rel rt_wit_lapic_before], rax
    mov  rax, [rel smp_irq_entries]
    mov  [rel rt_wit_lapic_after], rax
    mov  rax, [rel rt_wit_unexpected_current]
    mov  [rel rt_wit_unexpected_before], rax
    mov  rax, [rel irq_unexpected_count]
    mov  [rel rt_wit_unexpected_after], rax
.nomax:
    mov  [rel rt_wit_last_tsc], r11
    mov  [rel rt_wit_previous], r11
    call rt_canary_run                  ; RT canary runs (inversion-safe lock acquire)
    add  r14, r13                       ; next absolute deadline
    inc  r12d
    jmp  .loop
.done:
    mov  [rel rt_periods], r15d
    mov  dword [rel rt_contended], 1    ; the contender genuinely ran every period
    mov  rdi, rbx
    call rt_ns_from_ticks               ; worst ticks -> ns
    mov  [rel rt_jitter_ns], eax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; rt_admit_init — establish the admission budget + the shield verdict for the
;   detected topology. The canary is admitted at boot (consumes RT_CANARY_DEMAND).
;   shielded=1 needs a spare core to isolate (1048 PINs the RT row on the top core);
;   a single-core box is the honest shielded=0 mode=besteffort degenerate. clobbers: RAX.
; ---------------------------------------------------------------------------
rt_admit_init:
    mov  dword [rel rt_util_base], RT_CANARY_DEMAND
    mov  eax, [rel sched_ncores]        ; 1048's CPUID-detected logical processor count
    cmp  eax, 2
    jae  .shielded
    mov  dword [rel rt_shielded], 0     ; too few cores to shield -> honest best-effort
    ret
.shielded:
    mov  dword [rel rt_shielded], 1
    ret

; ---------------------------------------------------------------------------
; rt_admit_check(EDI = demand permille) -> EAX = 1 admit / 0 reject (default-DENY).
;   admit iff util_base + demand <= RT_CAP_PERMILLE. Never over-commits the RT core.
;   clobbers: RAX.
; ---------------------------------------------------------------------------
rt_admit_check:
    mov  eax, [rel rt_util_base]
    add  eax, edi
    cmp  eax, RT_CAP_PERMILLE
    ja   .deny
    mov  eax, 1
    ret
.deny:
    xor  eax, eax
    ret

; ===========================================================================
; staged-reply helpers (rt_out_buf, framed verbatim by command_udp.asm exactly like
;   sched_out_buf). clobbers: RAX,RSI (put_str/put_dec), + RDI,RCX (put_token).
; ===========================================================================
rt_out_reset:
    lea  rax, [rel rt_out_buf]
    mov  [rel rt_out_cur], rax
    mov  byte [rel rt_out_buf], 0
    ret

rt_put_str:                             ; RDI = cstr
    mov  rsi, [rel rt_out_cur]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel rt_out_cur], rsi
    ret

rt_put_dec:                             ; RDI = value
    mov  rsi, [rel rt_out_cur]
    push rsi
    call fmt_dec                        ; RAX = digit count, NUL-terminates
    pop  rsi
    add  rsi, rax
    mov  [rel rt_out_cur], rsi
    ret

; rt_put_token(RSI=src) -> copies src up to a space/NUL into the staged buffer
;   (bounded 64). clobbers: RAX,RSI,RDI,RCX.
rt_put_token:
    mov  rdi, [rel rt_out_cur]
    mov  ecx, 64
.cp:
    test ecx, ecx
    jz   .done
    mov  al, [rsi]
    test al, al
    jz   .done
    cmp  al, ' '
    je   .done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .cp
.done:
    mov  byte [rdi], 0
    mov  [rel rt_out_cur], rdi
    ret

; ---------------------------------------------------------------------------
; VERB: RTLAT (RDI=req, RSI=resp) — ARGT_TEXT arg = "<nonce>". Re-measure the
;   shielded canary's worst-case jitter LIVE (RT_M_LIVE periods, under contention),
;   then stage the measured result tagged with the caller's exact nonce. A latch
;   cannot fake a plausible non-zero jitter tied to a fresh random nonce.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
cmd_verb_rtlat:
    call cmd_handler_prologue
    push r12
    push r13
    push r14
    mov  r13, rsi                       ; resp
    mov  r12, [rdi + REQ_ARG]           ; nonce token
    test r12, r12
    jz   .badarg                       ; NULL never starts timing or placement work
    ; --- LIVE re-measurement (fresh per call; not a boot latch) ---
    mov  edi, RT_M_LIVE
    call rt_measure_jitter
    mov  edi, SC_RT
    call sched_place
    mov  edi, eax
    call sched_affinity_probe_execute
    mov  r14d, eax
    test eax, eax
    jns  .wake_measured
    mov  dword [rel rt_jitter_ns], RT_BOUND_NS + 1
    jmp  .measured
.wake_measured:
    mov  rdi, [rel sched_affinity_probe_latency]
    call rt_ns_from_ticks
    cmp  eax, [rel rt_jitter_ns]
    jbe  .measured
    mov  [rel rt_jitter_ns], eax
.measured:
    call rt_out_reset
    lea  rdi, [rel str_rt_nonce]        ; " nonce="
    call rt_put_str
    mov  rsi, r12
    call rt_put_token
    lea  rdi, [rel str_rt_jitter]       ; " jitter_ns="
    call rt_put_str
    mov  edi, [rel rt_jitter_ns]
    call rt_put_dec
    lea  rdi, [rel str_rt_periods]      ; " periods="
    call rt_put_str
    mov  edi, [rel rt_periods]
    call rt_put_dec
    lea  rdi, [rel str_rt_bound]        ; " bound_ns="
    call rt_put_str
    mov  edi, RT_BOUND_NS
    call rt_put_dec
    ; verdict: within iff measured worst-case <= declared bound (held under load)
    mov  eax, [rel rt_jitter_ns]
    cmp  eax, RT_BOUND_NS
    ja   .exceeded
    lea  rdi, [rel str_rt_within]       ; " verdict=within"
    call rt_put_str
    jmp  .contend
.exceeded:
    lea  rdi, [rel str_rt_exceeded]     ; " verdict=exceeded"
    call rt_put_str
.contend:
    lea  rdi, [rel str_rt_contended]    ; " contended="
    call rt_put_str
    mov  edi, [rel rt_contended]
    call rt_put_dec
    lea  rdi, [rel str_rt_shielded]     ; " shielded="
    call rt_put_str
    mov  edi, [rel rt_shielded]
    call rt_put_dec
    lea  rdi, [rel str_rt_cpu]
    call rt_put_str
    test r14d, r14d
    js   .cpu_none
    mov  edi, r14d
    call rt_put_dec
    jmp  .cpu_done
.cpu_none:
    lea  rdi, [rel str_rt_none]
    call rt_put_str
.cpu_done:
    mov  eax, [rel rt_shielded]
    test eax, eax
    jz   .besteffort
    lea  rdi, [rel str_rt_mode_hard]    ; " mode=shielded"
    call rt_put_str
    jmp  .staged
.besteffort:
    lea  rdi, [rel str_rt_mode_best]    ; " mode=besteffort"
    call rt_put_str
.staged:
    mov  byte [rel rt_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  eax, [rel rt_jitter_ns]
    mov  [r13 + RSP_VAL], rax           ; RSP_VAL = measured jitter_ns
    jmp  .out
.badarg:
    call rt_out_reset
    mov  byte [rel rt_out_ready], 0
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  qword [r13 + RSP_VAL], 0
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; ---------------------------------------------------------------------------
; VERB: RTADMIT (RDI=req, RSI=resp) — ARGT_TEXT arg = "<keyword> <nonce>", keyword in
;   {over, ok}. Selects a task DEMAND profile and runs the REAL admission check
;   against the remaining budget: over-budget is REJECTED (default-deny), in-budget
;   admitted. Echoes demand/avail/cap so it is visibly a computation, not a rubber
;   stamp. clobbers: caller-saved.
; ---------------------------------------------------------------------------
cmd_verb_rtadmit:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rsi                       ; resp
    mov  r14, [rdi + REQ_ARG]           ; "<keyword> <nonce>"
    ; copy the keyword token
    mov  rsi, r14
    lea  rdi, [rel rt_argkw]
    mov  ecx, 15
.kw:
    test ecx, ecx
    jz   .kw_done
    mov  al, [rsi]
    test al, al
    jz   .kw_done
    cmp  al, ' '
    je   .kw_done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .kw
.kw_done:
    mov  byte [rdi], 0
    mov  r12, rsi                       ; -> at space/NUL after keyword
.skip:
    cmp  byte [r12], ' '
    jne  .nonce_ready
    inc  r12
    jmp  .skip
.nonce_ready:
    ; resolve the demand from the keyword (default: over-budget profile if unknown)
    lea  rdi, [rel rt_argkw]
    lea  rsi, [rel str_kw_ok]
    call strcmp
    test rax, rax
    jz   .demand_ok
    mov  edi, RT_OVER_DEMAND
    jmp  .have_demand
.demand_ok:
    mov  edi, RT_OK_DEMAND
.have_demand:
    mov  r14d, edi                      ; save demand
    call rt_admit_check                 ; EAX = 1 admit / 0 reject
    mov  ebx, eax                       ; PRESERVE verdict (rt_out_reset/rt_put_str clobber EAX)
    ; stage the verdict
    call rt_out_reset
    lea  rdi, [rel str_rt_admitted]     ; " admitted="
    call rt_put_str
    test ebx, ebx
    jz   .rej
    lea  rdi, [rel str_true]            ; "true"
    call rt_put_str
    lea  rdi, [rel str_rt_reason_fits] ; " reason=fits"
    call rt_put_str
    jmp  .nums
.rej:
    lea  rdi, [rel str_false]           ; "false"
    call rt_put_str
    lea  rdi, [rel str_rt_reason_over] ; " reason=over_budget"
    call rt_put_str
.nums:
    lea  rdi, [rel str_rt_demand]       ; " demand="
    call rt_put_str
    mov  edi, r14d
    call rt_put_dec
    lea  rdi, [rel str_rt_avail]        ; " avail="
    call rt_put_str
    mov  edi, RT_CAP_PERMILLE
    sub  edi, [rel rt_util_base]        ; remaining budget
    call rt_put_dec
    lea  rdi, [rel str_rt_cap]          ; " cap="
    call rt_put_str
    mov  edi, RT_CAP_PERMILLE
    call rt_put_dec
    lea  rdi, [rel str_rt_nonce]        ; " nonce="
    call rt_put_str
    mov  rsi, r12
    call rt_put_token
    mov  byte [rel rt_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; rt_clock_class() -> EAX = RT_CLOCK_*. CPUID.1:ECX[31] clear is metal; otherwise
;   the hypervisor leaf 0x40000000 signature (EBX,ECX,EDX) names KVM or TCG, and
;   anything else is OTHER. clobbers: RAX,RCX,RDX (RBX preserved).
; ---------------------------------------------------------------------------
rt_clock_class:
    push rbx
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    bt   ecx, 31                        ; CPUID.1:ECX.HYPERVISOR
    jnc  .metal
    mov  eax, 0x40000000
    xor  ecx, ecx
    cpuid
    cmp  ebx, 'KVMK'
    jne  .not_kvm
    cmp  ecx, 'VMKV'
    jne  .other
    cmp  edx, 'M'                       ; "M",0,0,0
    jne  .other
    mov  eax, RT_CLOCK_KVM
    jmp  .out
.not_kvm:
    cmp  ebx, 'TCGT'
    jne  .other
    cmp  ecx, 'CGTC'
    jne  .other
    cmp  edx, 'GTCG'
    jne  .other
    mov  eax, RT_CLOCK_TCG
    jmp  .out
.other:
    mov  eax, RT_CLOCK_OTHER
    jmp  .out
.metal:
    xor  eax, eax                       ; RT_CLOCK_METAL
.out:
    pop  rbx
    ret

; rt_clock_name(EDI=class) -> RDI = its NUL-terminated name. clobbers: RDI.
rt_clock_name:
    cmp  edi, RT_CLOCK_KVM
    je   .kvm
    cmp  edi, RT_CLOCK_TCG
    je   .tcg
    cmp  edi, RT_CLOCK_METAL
    je   .metal
    lea  rdi, [rel str_rt_clk_other]
    ret
.metal:
    lea  rdi, [rel str_rt_clk_metal]
    ret
.kvm:
    lea  rdi, [rel str_rt_clk_kvm]
    ret
.tcg:
    lea  rdi, [rel str_rt_clk_tcg]
    ret

; ---------------------------------------------------------------------------
; sched_rt_selftest — characterize the realtime class: init admission + shield,
;   run the boot jitter characterization UNDER contention, emit the 3 markers +
;   the qemu KAT print, register RTLAT/RTADMIT. Called from boot/header AFTER
;   sched_class_selftest (the 'realtime' row + registry must exist). clobbers:
;   caller-saved.
; ---------------------------------------------------------------------------
sched_rt_selftest:
    push rbx
    ; (1) admission table + shield/affinity
    call rt_admit_init
    mov  byte [rel rt_m_admit], 1
    lea  rdi, [rel str_m_rt_admit]
    call serial_string
    ; (2) MEASURED jitter under load — the boot characterization run
    mov  edi, RT_M_BOOT
    call rt_measure_jitter
    call rt_clock_class                 ; after the run: CPUID exits must not land in it
    mov  [rel rt_clock_cls], eax
    ; jitter.kat PASS iff we sampled >=64 periods, contended, and held the bound on a
    ; trusted clock; an untrusted clock records the run and grades nothing
    cmp  dword [rel rt_periods], 64
    jl   .jitter_after
    cmp  dword [rel rt_contended], 1
    jne  .jitter_after
    cmp  dword [rel rt_clock_cls], RT_CLOCK_KVM
    ja   .jitter_recorded
    mov  eax, [rel rt_jitter_ns]
    cmp  eax, RT_BOUND_NS
    ja   .jitter_after                  ; exceeded bound -> honest: no PASS marker
    mov  byte [rel rt_m_jitter], 1
    lea  rdi, [rel str_m_rt_jitter]
    call serial_string
    jmp  .jitter_after
.jitter_recorded:
    lea  rdi, [rel str_m_rt_jitter_rec]  ; "... selftest RECORDED clock="
    call serial_string
    mov  edi, [rel rt_clock_cls]
    call rt_clock_name
    call serial_string
    lea  rdi, [rel str_m_rt_jitter_rec_tail]
    call serial_string
.jitter_after:
    ; (3) inversion-safe lock path — armed iff the ceiling/inherit path fired every
    ;     period during the measurement (exercised UNDER the load, not idle)
    mov  eax, [rel rt_lock_inherit]
    cmp  eax, RT_M_BOOT
    jl   .invert_after
    mov  byte [rel rt_m_invert], 1
    lea  rdi, [rel str_m_rt_invert]
    call serial_string
.invert_after:
    call rt_jitter_witness              ; after sampling/grade; KAT remains last
    ; qemu KAT print (logic gate sans hardware; QEMU jitter is NOT the deliverable)
    lea  rdi, [rel str_rt_kat_pre]      ; "...sched.rt.kat jitter_ns="
    call serial_string
    mov  edi, [rel rt_jitter_ns]
    lea  rsi, [rel rt_numbuf]
    call fmt_dec
    lea  rdi, [rel rt_numbuf]
    call serial_string
    lea  rdi, [rel str_rt_kat_bound]    ; " bound_ns="
    call serial_string
    mov  edi, RT_BOUND_NS
    lea  rsi, [rel rt_numbuf]
    call fmt_dec
    lea  rdi, [rel rt_numbuf]
    call serial_string
    lea  rdi, [rel str_rt_kat_periods]  ; " periods="
    call serial_string
    mov  edi, [rel rt_periods]
    lea  rsi, [rel rt_numbuf]
    call fmt_dec
    lea  rdi, [rel rt_numbuf]
    call serial_string
    lea  rdi, [rel str_rt_kat_contended] ; " contended="
    call serial_string
    mov  edi, [rel rt_contended]
    lea  rsi, [rel rt_numbuf]
    call fmt_dec
    lea  rdi, [rel rt_numbuf]
    call serial_string
    lea  rdi, [rel str_rt_kat_clock]    ; " clock=" (appended last)
    call serial_string
    mov  edi, [rel rt_clock_cls]
    call rt_clock_name
    call serial_string
    call serial_newline
    ; --- register the two registry verbs (COMMANDS.md §1 single vocabulary) ---
    lea  rdi, [rel str_verb_rtlat]
    lea  rsi, [rel cmd_verb_rtlat]
    xor  edx, edx                       ; declared cap 0; remote floor already requires MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                        ; live timing/placement work; signed path remains unchanged
    call command_register_verb
    lea  rdi, [rel str_verb_rtadmit]
    lea  rsi, [rel cmd_verb_rtadmit]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    pop  rbx
    ret

; Raw bounded diagnostic; counter snapshots are sequential, not an IRQ duration
; or BSP attribution. No PASS marker, bound, clock class or qualification change.
rt_jitter_witness:
    lea  rdi, [rel str_rt_wit_prefix]
    call serial_string
    lea  rdi, [rel str_rt_wit_valid]
    lea  rsi, [rel rt_wit_valid]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_max_period]
    lea  rsi, [rel rt_wit_max_period]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_start_tsc]
    lea  rsi, [rel rt_wit_start_tsc]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_last_tsc]
    lea  rsi, [rel rt_wit_last_tsc]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_period_ticks]
    lea  rsi, [rel rt_wit_period_ticks]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_deadline_tsc]
    lea  rsi, [rel rt_wit_deadline_tsc]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_sample_tsc]
    lea  rsi, [rel rt_wit_sample_tsc]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_previous_tsc]
    lea  rsi, [rel rt_wit_previous_tsc]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_lateness_ticks]
    lea  rsi, [rel rt_wit_lateness_ticks]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_pit_before]
    lea  rsi, [rel rt_wit_pit_before]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_pit_after]
    lea  rsi, [rel rt_wit_pit_after]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_lapic_global_before]
    lea  rsi, [rel rt_wit_lapic_before]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_lapic_global_after]
    lea  rsi, [rel rt_wit_lapic_after]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_unexpected_before]
    lea  rsi, [rel rt_wit_unexpected_before]
    call rt_witness_field
    lea  rdi, [rel str_rt_wit_unexpected_after]
    lea  rsi, [rel rt_wit_unexpected_after]
    call rt_witness_field
    jmp  serial_newline

; RDI=field label, RSI=qword address. Format full u64 through the shared formatter.
rt_witness_field:
    push rbx
    mov  rbx, rsi
    call serial_string
    mov  rdi, [rbx]
    lea  rsi, [rel rt_numbuf]
    call fmt_dec
    lea  rdi, [rel rt_numbuf]
    call serial_string
    pop  rbx
    ret

; ---- module data ----------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_command_rt 0
align 8
; One constant-size witness, including working snapshots; no dynamic allocation.
align 8
rt_wit_begin:
rt_wit_valid: dq 0
rt_wit_max_period: dq 0
rt_wit_start_tsc: dq 0
rt_wit_last_tsc: dq 0
rt_wit_period_ticks: dq 0
rt_wit_deadline_tsc: dq 0
rt_wit_sample_tsc: dq 0
rt_wit_previous_tsc: dq 0
rt_wit_lateness_ticks: dq 0
rt_wit_pit_before: dq 0
rt_wit_pit_after: dq 0
rt_wit_lapic_before: dq 0
rt_wit_lapic_after: dq 0
rt_wit_unexpected_before: dq 0
rt_wit_unexpected_after: dq 0
rt_wit_previous: dq 0
rt_wit_pit_current: dq 0
rt_wit_lapic_current: dq 0
rt_wit_unexpected_current: dq 0
rt_jitter_ns:   dd 0                     ; last-measured worst-case jitter (ns)
rt_periods:     dd 0                     ; periods sampled in the last measurement
rt_contended:   dd 0                     ; 1 = measured WITH the contending load
rt_shielded:    dd 0                     ; 1 = a spare core shields the RT row
rt_util_base:   dd 0                     ; admitted RT utilization (permille of one core)
rt_lock_locked: dd 0                     ; shared-lock state (inversion-safe ceiling lock)
rt_lock_holder: dd -1                    ; class currently holding the shared lock
rt_lock_inherit: dd 0                    ; priority-inheritance/ceiling events counted
rt_clock_cls:   dd 0                     ; RT_CLOCK_* of the boot characterization run
rt_m_admit:     db 0                     ; marker flags (ride every BOOTLOG reply once set)
rt_m_jitter:    db 0
rt_m_invert:    db 0
rt_out_ready:   db 0                     ; 1 = rt_out_buf holds a staged reply line
align 8
rt_out_cur:     dq 0
rt_out_buf:     times 384 db 0           ; staged RTLAT/RTADMIT reply text
rt_argkw:       times 16 db 0            ; parsed RTADMIT keyword token
rt_numbuf:      times 24 db 0
rt_scratch:     times 64 db 0            ; contending-load churn target (cache-touch)
%endmacro
WDATA_DEFER WDATA_command_rt

; registry verb names
str_verb_rtlat:    db "RTLAT", 0
str_verb_rtadmit:  db "RTADMIT", 0

; RTADMIT keyword tokens
str_kw_ok:         db "ok", 0
str_true:          db "true", 0
str_false:         db "false", 0

; staged-reply fragments
str_rt_nonce:       db " nonce=", 0
str_rt_jitter:      db " jitter_ns=", 0
str_rt_periods:     db " periods=", 0
str_rt_bound:       db " bound_ns=", 0
str_rt_within:      db " verdict=within", 0
str_rt_exceeded:    db " verdict=exceeded", 0
str_rt_contended:   db " contended=", 0
str_rt_shielded:    db " shielded=", 0
str_rt_cpu:         db " cpu=", 0
str_rt_none:        db "none", 0
str_rt_mode_hard:   db " mode=shielded", 0
str_rt_mode_best:   db " mode=besteffort", 0
str_rt_admitted:    db " admitted=", 0
str_rt_reason_fits: db " reason=fits", 0
str_rt_reason_over: db " reason=over_budget", 0
str_rt_demand:      db " demand=", 0
str_rt_avail:       db " avail=", 0
str_rt_cap:         db " cap=", 0

; boot serial markers (registered in regression_tests.txt)
str_m_rt_admit:  db "[PAOS64] P2 sched-rt: admission table + shield/affinity ready [sched.rt.admit]", 13, 10, 0
str_m_rt_jitter: db "[PAOS64] P2 sched-rt: shielded canary worst-case jitter under load selftest PASS [sched.rt.jitter.kat]", 13, 10, 0
str_m_rt_jitter_rec: db "[PAOS64] P2 sched-rt: shielded canary worst-case jitter under load selftest RECORDED clock=", 0
str_m_rt_jitter_rec_tail: db " (1 ms bound graded only on metal and KVM; not graded here) [sched.rt.jitter.recorded]", 13, 10, 0
str_m_rt_invert: db "[PAOS64] P2 sched-rt: priority-inversion-safe lock path armed [sched.rt.invert]", 13, 10, 0
str_rt_kat_pre:      db "[PAOS64] P2 sched-rt: sched.rt.kat jitter_ns=", 0
str_rt_kat_bound:    db " bound_ns=", 0
str_rt_kat_periods:  db " periods=", 0
str_rt_kat_contended: db " contended=", 0
str_rt_kat_clock:    db " clock=", 0
str_rt_clk_metal:    db "metal", 0
str_rt_clk_kvm:      db "kvm", 0
str_rt_clk_tcg:      db "tcg", 0
str_rt_clk_other:    db "other", 0

str_rt_wit_prefix: db "[PAOS64] sched.rt.witness v=1", 0
str_rt_wit_valid: db " valid=", 0
str_rt_wit_max_period: db " max_period=", 0
str_rt_wit_start_tsc: db " start_tsc=", 0
str_rt_wit_last_tsc: db " last_tsc=", 0
str_rt_wit_period_ticks: db " period_ticks=", 0
str_rt_wit_deadline_tsc: db " deadline_tsc=", 0
str_rt_wit_sample_tsc: db " sample_tsc=", 0
str_rt_wit_previous_tsc: db " previous_tsc=", 0
str_rt_wit_lateness_ticks: db " lateness_ticks=", 0
str_rt_wit_pit_before: db " pit_before=", 0
str_rt_wit_pit_after: db " pit_after=", 0
str_rt_wit_lapic_global_before: db " lapic_global_before=", 0
str_rt_wit_lapic_global_after: db " lapic_global_after=", 0
str_rt_wit_unexpected_before: db " unexpected_before=", 0
str_rt_wit_unexpected_after: db " unexpected_after=", 0
