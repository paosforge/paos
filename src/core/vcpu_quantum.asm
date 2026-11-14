;; MODULE core/vcpu_quantum
;; LAYER 1
;; EXPORTS vcpu_quantum_selftest, vcpu_entity_init, vq_run_interleaved
;; IMPORTS core/time, core/lib/fmt, boot/serial
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/vcpu_quantum.asm — the SCHEDULER §4.5 RESIDENT-vCPU FAIRNESS SEAM (1071).
;
; THE NON-RETROFITTABLE SEAM: a resident guest vCPU is a FIRST-CLASS scheduling
; entity with a BOUNDED, DECLARED quantum (throughput-class, PREEMPTIBLE at
; quantum end), and the host's driver-class poll/heartbeat loops get a
; GUARANTEED interleaved service slice regardless of guest demand — the host's
; own lifeline never waits on the guest. This is the STRUCTURAL cure for the
; 9374j starvation family (a resident consumer that monopolizes the core got
; ~1% CPU and overran its turn; separately it starved host net_poll and .50
; went UDP-dark). Fairness MUST be a seam: the quantum FIELD lives on the
; entity and the interleave enforces it at v1 — bolting it on later fights every
; resident-guest call site (the duct tape SCHEDULER §4.5 / §7 forbids).
;
; v1 is DEGENERATE-TO-ONE (the 9390 sim-drives-real pattern): a SIMULATED
; resident-vCPU consumer — a CPU-bound task standing in for a real guest, no hv
; needed — drives the SAME bounded-quantum decision code the real guest will.
; The consumer runs flat-out; the scheduler PREEMPTS it at its declared quantum
; (never kills it — SCHEDULER §4.5 clause 3) and hands the host its guaranteed
; slice; the host HEARTBEAT ticks on that slice. The real resident-Linux-guest
; interleave (host .50 UDP stays answered under a live guest) lands with the hv
; passthrough contracts (1011/1012); this proves the fairness SEAM exists.
;
; CONTENT-GRADE, NOT LATCH (TESTING §1/§4/§6): the selftest measures, by TSC
; deltas, the MAXIMUM gap between consecutive host heartbeats over the consumer
; run, and PRINTS the declared bound + heartbeat count + the measured max gap as
; a KAT. The un-fakeable discriminator is a DUAL measurement driven by the SAME
; consumer over the SAME interleave:
;   - BOUNDED   consumer (quantum enforced) -> host max-gap <= bound  (host lived)
;   - UNBOUNDED consumer (quantum bypassed) -> host max-gap  > bound  (STARVED)
; A latch that always prints PASS cannot produce a bounded run that stays under
; the bound AND an unbounded run that blows past it. The NEGATIVE run is the
; gate (TESTING §4): if the unbounded consumer did NOT starve the heartbeat, the
; test is not measuring fairness and FAILS.
;
; SINGLE DEFINITION (G1 / known_trap): there is exactly ONE bounded-quantum
; enforcer + guaranteed-host-slice interleave, here. modlint forbids a 2nd variant.
; ============================================================================

; --- resident-vCPU scheduling entity: additive-by-design, quantum FIELD at v1 ---
VCPU_ID       equ 0      ; entity id
VCPU_QUANTUM  equ 8      ; declared bounded quantum (TSC ticks) — THE seam field
VCPU_STATE    equ 16     ; 0=ready, 1=running, 2=preempted (preempted, never killed)
VCPU_RAN      equ 24     ; work units accumulated (proves the consumer ran flat-out)
VCPU_PREEMPTS equ 32     ; times preempted at quantum end (bounded path only)
VCPU_ENT_SZ   equ 40

; The declared quantum + the guaranteed host-slice headroom. The BOUND (the
; guaranteed host-service interval, i.e. the max tolerated inter-heartbeat gap)
; is quantum + slice headroom: after the consumer's bounded quantum the host is
; serviced within one bound. Large vs loop-iteration cost so a measured gap
; tracks the declaration within a few percent (§6, generous TSC-jitter tolerance).
VQ_QUANTUM       equ 1000000    ; resident vCPU bounded quantum (TSC ticks)
VQ_HOST_SLICE    equ 2000000    ; guaranteed host-slice headroom
VQ_BOUND         equ 3000000    ; VQ_QUANTUM + VQ_HOST_SLICE — max tolerated host gap
VQ_UNBOUNDED     equ 15000000   ; the negative: an UNINTERRUPTED burst (quantum bypassed)
VQ_HB_TARGET     equ 6          ; drive until the host heartbeat has ticked this many times
VQ_MIN_SAMPLES   equ 3          ; bounded gate: sample the bounded run N times, gate the MIN.
                                ; A host deschedule of the QEMU/TCG process inflates ONE
                                ; inter-heartbeat gap of ONE sample above the absolute bound;
                                ; the MIN across N samples discards that spike so a single
                                ; host-load hiccup can't false-fail an unchanged binary
                                ; (side_bugs (A) / vcpu-selftest-flaky-under-qemu-load).

; vcpu_entity_init(RDI=id, RSI=quantum) — build the resident-vCPU entity with its
;   BOUNDED QUANTUM field. The field EXISTS at v1 even simulated; omitting it now
;   would force a quantum-field format change at every resident-guest call site
;   later (SCHEDULER §4.5). clobbers: RAX
vcpu_entity_init:
    lea  rax, [rel vq_entity]
    mov  [rax + VCPU_ID], rdi
    mov  [rax + VCPU_QUANTUM], rsi        ; the declared bounded quantum
    mov  qword [rax + VCPU_STATE], 0      ; ready
    mov  qword [rax + VCPU_RAN], 0
    mov  qword [rax + VCPU_PREEMPTS], 0
    ret

; vq_consumer_run(RDI=cap_ticks) — the SIMULATED resident-vCPU consumer: a
;   CPU-bound task that runs flat-out, accumulating work units, until cap_ticks
;   of TSC have elapsed. TSC-based deadline (never a fixed sleep, §6). The caller
;   sets the cap: the bounded path passes the entity's declared quantum; the
;   unbounded negative passes a long burst (quantum bypassed). clobbers: RAX,RCX
vq_consumer_run:
    call tsc_now
    mov  rcx, rax
    add  rcx, rdi                         ; deadline = now + cap
.spin:
    inc  qword [rel vq_work_units]        ; flat-out CPU-bound work (the resident guest)
    call tsc_now
    cmp  rax, rcx
    jb   .spin
    ret

; vq_host_beat — the host driver-class HEARTBEAT tick, invoked on the guaranteed
;   slice after every consumer run. Records the max inter-heartbeat gap (TSC).
;   HEAL-ON-RESIDENT-PATH (SCHEDULER §4.5 clause 3): the host heal/watchdog tick
;   fires on THIS resident-scheduling path too — not only the non-resident path
;   (the omitted-heal-on-one-path bug). clobbers: RAX,RCX,RDX
vq_host_beat:
    call tsc_now                          ; RAX = now
    mov  rcx, [rel vq_last_beat]
    test rcx, rcx
    jz   .first                           ; first beat has no predecessor gap
    mov  rdx, rax
    sub  rdx, rcx                         ; gap = now - last_beat
    cmp  rdx, [rel vq_max_gap]
    jbe  .nomax
    mov  [rel vq_max_gap], rdx            ; track the maximum gap
.nomax:
.first:
    mov  [rel vq_last_beat], rax
    inc  qword [rel vq_hb_count]
    inc  qword [rel vq_heal_ticks]        ; heal fires on the resident path too (§4.5 c3)
    ret

; vq_run_interleaved(RDI=vcpu_ptr, RSI=hb_target, RDX=enforce) — the ONE bounded-
;   quantum enforcer + guaranteed-host-slice interleave. Runs the resident
;   consumer interleaved with the host heartbeat until the host has beaten
;   hb_target times, returning the measured max inter-heartbeat gap in RAX.
;     enforce=1 (BOUNDED): the consumer runs at most its DECLARED QUANTUM, then is
;       PREEMPTED (state=preempted, never killed) and the host gets its guaranteed
;       slice — the seam. Host stays responsive: max-gap ~ quantum <= bound.
;     enforce=0 (UNBOUNDED negative): the quantum is BYPASSED — the consumer runs a
;       long uninterrupted burst before the host is serviced — max-gap >> bound.
;   clobbers: caller-saved; preserves RBX,R12-R15.
vq_run_interleaved:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                         ; vcpu entity ptr
    mov  r13, rsi                         ; hb_target
    mov  r14, rdx                         ; enforce flag
    ; reset the per-run heartbeat measurement
    mov  qword [rel vq_last_beat], 0
    mov  qword [rel vq_max_gap], 0
    mov  qword [rel vq_hb_count], 0
    ; the host beats once at run start (establishes the first timestamp)
    call vq_host_beat
.loop:
    test r14, r14
    jz   .unbounded
    ; ---- BOUNDED: run the consumer for its declared quantum, then PREEMPT ----
    mov  qword [r12 + VCPU_STATE], 1      ; running
    mov  rdi, [r12 + VCPU_QUANTUM]        ; the declared bounded quantum FIELD
    call vq_consumer_run
    mov  qword [r12 + VCPU_STATE], 2      ; preempted at quantum end (NOT killed)
    inc  qword [r12 + VCPU_PREEMPTS]
    jmp  .hostslice
.unbounded:
    ; ---- UNBOUNDED negative: quantum bypassed, one long uninterrupted burst ----
    mov  qword [r12 + VCPU_STATE], 1
    mov  rdi, VQ_UNBOUNDED
    call vq_consumer_run
.hostslice:
    ; guaranteed host slice: the heartbeat ALWAYS ticks after the consumer yields
    call vq_host_beat
    mov  rax, [rel vq_hb_count]
    cmp  rax, r13
    jb   .loop
    mov  rax, [rel vq_max_gap]            ; return the measured max inter-beat gap
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vq_emit_num(RDI=value) — print an unsigned decimal to serial (KAT numbers).
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
vq_emit_num:
    lea  rsi, [rel vq_numbuf]
    call fmt_dec                          ; the ONE canonical decimal formatter (G1)
    lea  rdi, [rel vq_numbuf]
    call serial_string
    ret

; vcpu_quantum_selftest — build the resident-vCPU entity (declared quantum field),
;   drive the SIMULATED consumer flat-out through the ONE bounded-quantum
;   interleave, TSC-measure the host heartbeat, then run the SAME consumer
;   UNBOUNDED and prove it STARVES the heartbeat. Prints the KAT the probe grades.
;   Plain call (no diag PHASE — keeps DIAG_NPHASES ring geometry). Emits markers.
vcpu_quantum_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; --- (1) build the entity: the bounded-quantum FIELD exists at v1 (the seam) ---
    mov  rdi, 1                           ; resident vCPU id
    mov  rsi, VQ_QUANTUM
    call vcpu_entity_init
    lea  rax, [rel vq_entity]
    cmp  qword [rax + VCPU_QUANTUM], VQ_QUANTUM
    jne  .fail                            ; the declared quantum must be on the entity
    mov  qword [rel vq_work_units], 0
    mov  qword [rel vq_heal_ticks], 0
    lea  rdi, [rel str_vq_declared]
    call serial_string

    ; --- (2) BOUNDED run (MIN-of-N: deterministic under host load) ------------------
    ; Sample the bounded interleave N times and keep the MINIMUM max_gap_bounded. A host
    ; deschedule between two tsc_now reads in vq_host_beat inflates ONE gap in ONE sample
    ; above VQ_BOUND; the MIN discards that spike (the un-loaded truth is ~1.1M, ~3x under
    ; the bound). vq_run_interleaved preserves RBX,R12-R15 and resets its per-run
    ; measurement state, so looping it is safe. r15 = remaining samples.
    mov  r12, -1                          ; r12 = MIN max_gap_bounded so far (start = max u64)
    mov  r15, VQ_MIN_SAMPLES
.bounded_sample:
    lea  rdi, [rel vq_entity]
    mov  rsi, VQ_HB_TARGET
    mov  rdx, 1                           ; enforce = bounded
    call vq_run_interleaved               ; RAX = this sample's max_gap_bounded
    cmp  rax, r12
    jae  .keep_min                        ; keep the smaller sample (MIN, not avg/max)
    mov  r12, rax
.keep_min:
    dec  r15
    jnz  .bounded_sample
    mov  r13, [rel vq_hb_count]           ; r13 = host heartbeat count (last bounded sample)

    ; the simulated consumer actually ran flat-out (accumulated work) AND was
    ; preempted at its quantum (never killed) — the sim drove the real decision path
    cmp  qword [rel vq_work_units], 1000
    jb   .fail
    lea  rax, [rel vq_entity]
    cmp  qword [rax + VCPU_PREEMPTS], 1
    jb   .fail
    cmp  qword [rax + VCPU_STATE], 2      ; ended preempted, not killed
    jne  .fail
    lea  rdi, [rel str_vq_simran]
    call serial_string

    ; --- (3) UNBOUNDED negative run: SAME consumer, quantum bypassed -> starves ---
    lea  rdi, [rel vq_entity]
    mov  rsi, VQ_HB_TARGET
    mov  rdx, 0                           ; enforce = 0 (unbounded — the negative)
    call vq_run_interleaved
    mov  r14, rax                         ; r14 = max_gap_unbounded

    ; --- (4) PRINT the KAT (bound, hb_count, both max-gaps) — the probe grades this ---
    lea  rdi, [rel str_vqkat_pfx]
    call serial_string
    mov  rdi, VQ_BOUND
    call vq_emit_num
    lea  rdi, [rel str_vqkat_hb]
    call serial_string
    mov  rdi, r13
    call vq_emit_num
    lea  rdi, [rel str_vqkat_gb]
    call serial_string
    mov  rdi, r12
    call vq_emit_num
    lea  rdi, [rel str_vqkat_gu]
    call serial_string
    mov  rdi, r14
    call vq_emit_num
    lea  rdi, [rel str_vq_nl]
    call serial_string

    ; --- (5) GATE (content, not latch): bounded stayed under the bound with a
    ;     non-trivial heartbeat count (host lived); unbounded blew past it (starved) ---
    cmp  r12, VQ_BOUND
    ja   .fail                            ; bounded max-gap must be <= bound
    cmp  r13, 4
    jb   .fail                            ; host must have kept ticking (non-trivial)
    lea  rdi, [rel str_vq_hbcont]
    call serial_string

    cmp  r14, VQ_BOUND
    jbe  .negfail                         ; NEGATIVE gate: unbounded MUST starve (> bound)
    lea  rdi, [rel str_vq_neggate]
    call serial_string
    jmp  .done
.negfail:
    lea  rdi, [rel str_vq_negfail]        ; unbounded did NOT starve -> not measuring fairness
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_vq_fail]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- core/vcpu_quantum data (RW under our page tables, MEMORY_MAP §3.1) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_vcpu_quantum 0
align 8
vq_entity:      times VCPU_ENT_SZ db 0    ; the single resident-vCPU scheduling entity
vq_work_units:  dq 0                       ; consumer flat-out work tally (ran-proof)
vq_heal_ticks:  dq 0                       ; host heal fired on the resident path (§4.5 c3)
vq_last_beat:   dq 0                        ; TSC of the previous host heartbeat
vq_max_gap:     dq 0                        ; measured max inter-heartbeat gap (TSC)
vq_hb_count:    dq 0                        ; host heartbeat count over the run
vq_numbuf:      times 24 db 0              ; u64 decimal scratch (max 20 digits + NUL)
%endmacro
WDATA_DEFER WDATA_vcpu_quantum

str_vq_declared: db "[PAOS64] P2 sched vcpu: bounded quantum field present [sched.vcpu.quantum.declared]", 13, 10, 0
str_vq_simran:   db "[PAOS64] P2 sched vcpu: simulated resident consumer ran flat-out [sched.vcpu.sim.ran]", 13, 10, 0
str_vq_hbcont:   db "[PAOS64] P2 sched vcpu: host heartbeat continuous under load PASS [sched.host.heartbeat.continuous]", 13, 10, 0
str_vq_neggate:  db "[PAOS64] P2 sched vcpu: unbounded-consumer starves heartbeat (negative proof) PASS [sched.vcpu.starve.negative_gate]", 13, 10, 0
str_vq_negfail:  db "[PAOS64] P2 sched vcpu: unbounded consumer did NOT starve — negative gate FAIL", 13, 10, 0
str_vq_fail:     db "[PAOS64] P2 sched vcpu: FAIL", 13, 10, 0
str_vqkat_pfx:   db "sched.vcpu.kat bound=", 0
str_vqkat_hb:    db " hb_count=", 0
str_vqkat_gb:    db " max_gap_bounded=", 0
str_vqkat_gu:    db " max_gap_unbounded=", 0
str_vq_nl:       db 13, 10, 0
