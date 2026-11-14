;; MODULE core/sched
;; LAYER 1
;; EXPORTS sched_interactive_set_class, sched_interactive_set_pressure, sched_interactive_begin, sched_interactive_end, sched_interactive_epoch, sched_init, sched_spawn, sched_yield, sched_selftest, sched_unified_context_init, sched_unified_cpu_local_init, sched_unified_bench_begin, sched_unified_run_one, sched_unified_soak_bsp_service, sched_unified_bench_drive, sched_unified_seen_count, sched_balance_boot_selftest, sched_preempt_irq, sched_resched_ipi_irq, sched_idle_wake_ipi_irq, sched_affinity_probe_execute, sched_affinity_probe_latency, sched_preempt_boot_selftest, sched_preempt_post_pmod_selftest, sched_preempt_post_pmod_request, sched_preempt_post_pmod_tick, sched_preempt_post_pmod_poll, sched_preempt_post_pmod_last_ok, sched_watchdog_checkpoint, sched_watchdog_claim_expiry, sched_watchdog_deferred_reap, sched_watchdog_safe_frame, usched_job_faults_contained, usched_job_stale_mapping, usched_job_cpu_units, job_submit, job_bind_owner_lookup, job_set_dispatch_hook, sched_smp_policy_init, sched_smp_policy_apply, sched_smp_policy_rollback, sched_xstate_avx_ready, sched_preempt_post_pmod_settle_state
;; IMPORTS boot/serial, core/heap, core/time, core/capability, core/lock, core/smp topology counters
;; CAPS
;; OWNER saga:core
;; LOCK: sched_task_lock PROTECTS sched_tasks, sched_interactive_fair_at
; Input producers atomically increment sched_interactive_epoch after queue publication.
; Remaining sched_interactive_* fields have one serialized BSP desktop writer.
;; LOCK: sched_smp_policy_lock PROTECTS sched_smp_policy_profile, sched_smp_policy_previous_profile, sched_smp_policy_rollback_from_profile, sched_smp_policy_last_valid, sched_smp_policy_last_operation, sched_smp_policy_last_requested_profile, sched_smp_policy_auto_rollback, sched_smp_policy_last_rolled_back, sched_smp_policy_generation, sched_smp_policy_previous_generation, sched_smp_policy_rollback_from_generation, sched_smp_policy_last_requested_generation, sched_smp_policy_audit_seq, sched_smp_policy_last_audit, sched_smp_policy_online_before, sched_smp_policy_online_after, sched_smp_policy_last_request
;; LOCK: usched_task_lock PROTECTS usched_task_policy, usched_task_generation, usched_task_deferred_reap, usched_task_last_cpu, usched_task_deadline, usched_task_deadline_mirror, usched_task_checkpoint, usched_task_checkpoint_mirror, usched_task_expiry_claim, usched_task_signature, usched_task_mirror, usched_task_pinned_cpu, usched_task_class
;; LOCK: usched_context_lock PROTECTS usched_context_xstate, usched_context_expected
;; LOCK: usched_rq_lock PROTECTS usched_rq_head, usched_rq_tail, usched_rq_reserved_mask
; ============================================================================

SMP_POLICY_BALANCED       equ 0
SMP_POLICY_PHYSICAL_FIRST equ 1
SMP_POLICY_OP_APPLY       equ 1
SMP_POLICY_OP_ROLLBACK    equ 2
SMP_POLICY_TX_OK          equ 0
SMP_POLICY_TX_REPLAY      equ 1
SMP_POLICY_TX_UNSUPPORTED equ -1
SMP_POLICY_TX_STALE       equ -2
SMP_POLICY_TX_HEALTH      equ -3
SMP_POLICY_TX_COLLISION   equ -4

; Task1330j policy seam.  Registration stays in svc/command_smp; boot starts
; balanced until a fully validated, authenticated transaction commits.
sched_smp_policy_init:
    mov  byte [rel sched_smp_policy_profile], SMP_POLICY_BALANCED
    mov  byte [rel sched_smp_policy_previous_profile], SMP_POLICY_BALANCED
    mov  byte [rel sched_smp_policy_last_valid], 0
    mov  byte [rel sched_smp_policy_auto_rollback], 0
    mov  byte [rel sched_smp_policy_last_rolled_back], 0
    mov  byte [rel sched_smp_policy_test_force_health_bad], 0
    mov  dword [rel sched_smp_policy_generation], 1
    mov  dword [rel sched_smp_policy_previous_generation], 1
    mov  dword [rel sched_smp_policy_audit_seq], 0
    mov  dword [rel sched_smp_policy_last_audit], 0
    mov  qword [rel sched_smp_policy_last_request], 0
    ret

; Health is intentionally the predecessor's already-frozen topology/runtime
; truth, not a second telemetry model.  The synthetic override is private to
; the boot KAT and can never be reached from a command.
sched_smp_policy_health_ok:
    cmp  byte [rel sched_smp_policy_test_force_health_bad], 0
    jne  .bad
    mov  eax, [rel smp_topology_online]
    test eax, eax
    jz   .bad
    cmp  eax, [rel smp_discovered_count]
    jne  .bad
    cmp  dword [rel smp_failed_count], 0
    jne  .bad
    cmp  byte [rel smp_topology_overflow], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Common idempotency gate.  EDI=operation, ESI=profile, EDX=generation,
; R8=request.  Returns EAX=0 fresh, REPLAY, or COLLISION.
sched_smp_policy_replay_check:
    cmp  byte [rel sched_smp_policy_last_valid], 1
    jne  .fresh
    cmp  r8, [rel sched_smp_policy_last_request]
    jne  .fresh
    cmp  dil, [rel sched_smp_policy_last_operation]
    jne  .collision
    cmp  sil, [rel sched_smp_policy_last_requested_profile]
    jne  .collision
    cmp  edx, [rel sched_smp_policy_last_requested_generation]
    jne  .collision
    mov  eax, SMP_POLICY_TX_REPLAY
    ret
.collision:
    mov  eax, SMP_POLICY_TX_COLLISION
    ret
.fresh:
    xor  eax, eax
    ret

; Publish the request identity and one audit sequence only after all stale/
; unsupported checks pass. Replays therefore return the original receipt.
sched_smp_policy_record_request:
    mov  [rel sched_smp_policy_last_operation], dil
    mov  [rel sched_smp_policy_last_requested_profile], sil
    mov  [rel sched_smp_policy_last_requested_generation], edx
    mov  [rel sched_smp_policy_last_request], r8
    mov  byte [rel sched_smp_policy_last_valid], 1
    inc  dword [rel sched_smp_policy_audit_seq]
    jnz  .audit_ready
    inc  dword [rel sched_smp_policy_audit_seq]
.audit_ready:
    mov  eax, [rel sched_smp_policy_audit_seq]
    mov  [rel sched_smp_policy_last_audit], eax
    ret

; sched_smp_policy_apply(EDI=profile, ESI=exact current generation,
; RDX=request id) -> SMP_POLICY_TX_*.  Only the preference byte changes.  CPU
; state, SMT, topology, pins, watchdog policy and IRQ ownership are never
; written by this path.
sched_smp_policy_apply:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  r13, rdx
    cmp  ebx, SMP_POLICY_PHYSICAL_FIRST
    ja   .unsupported
    call sched_smp_policy_lock_acquire
    mov  edi, SMP_POLICY_OP_APPLY
    mov  esi, ebx
    mov  edx, r12d
    mov  r8, r13
    call sched_smp_policy_replay_check
    test eax, eax
    jnz  .unlock
    cmp  r12d, [rel sched_smp_policy_generation]
    jne  .stale
    mov  al, [rel sched_smp_policy_profile]
    mov  [rel sched_smp_policy_previous_profile], al
    mov  eax, [rel sched_smp_policy_generation]
    mov  [rel sched_smp_policy_previous_generation], eax
    mov  eax, [rel smp_topology_online]
    mov  [rel sched_smp_policy_online_before], eax
    mov  edi, SMP_POLICY_OP_APPLY
    mov  esi, ebx
    mov  edx, r12d
    mov  r8, r13
    call sched_smp_policy_record_request
    mov  byte [rel sched_smp_policy_auto_rollback], 0
    mov  byte [rel sched_smp_policy_last_rolled_back], 0
    cmp  bl, [rel sched_smp_policy_profile]
    je   .apply_effect
    mov  [rel sched_smp_policy_profile], bl
    inc  dword [rel sched_smp_policy_generation]
    jnz  .apply_effect
    inc  dword [rel sched_smp_policy_generation]
.apply_effect:
    mfence
    mov  eax, [rel smp_topology_online]
    mov  [rel sched_smp_policy_online_after], eax
    cmp  eax, [rel sched_smp_policy_online_before]
    jne  .health_rollback
    call sched_smp_policy_health_ok
    test eax, eax
    jz   .health_rollback
    mov  eax, SMP_POLICY_TX_OK
    jmp  .unlock
.health_rollback:
    mov  al, [rel sched_smp_policy_previous_profile]
    mov  [rel sched_smp_policy_profile], al
    mov  eax, [rel sched_smp_policy_previous_generation]
    mov  [rel sched_smp_policy_generation], eax
    mov  byte [rel sched_smp_policy_auto_rollback], 1
    mov  byte [rel sched_smp_policy_last_rolled_back], 1
    mfence
    mov  eax, SMP_POLICY_TX_HEALTH
    jmp  .unlock
.stale:
    mov  eax, SMP_POLICY_TX_STALE
.unlock:
    push rax
    call sched_smp_policy_lock_release
    pop  rax
    jmp  .out
.unsupported:
    mov  eax, SMP_POLICY_TX_UNSUPPORTED
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; sched_smp_policy_rollback(EDI=target profile, ESI=exact target generation,
; RDX=request id).  The only accepted target is the snapshot captured by the
; preceding apply, which makes rollback exact rather than a new mutation.
sched_smp_policy_rollback:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  r13, rdx
    cmp  ebx, SMP_POLICY_PHYSICAL_FIRST
    ja   .unsupported
    call sched_smp_policy_lock_acquire
    mov  edi, SMP_POLICY_OP_ROLLBACK
    mov  esi, ebx
    mov  edx, r12d
    mov  r8, r13
    call sched_smp_policy_replay_check
    test eax, eax
    jnz  .unlock
    cmp  bl, [rel sched_smp_policy_previous_profile]
    jne  .stale
    cmp  r12d, [rel sched_smp_policy_previous_generation]
    jne  .stale
    mov  eax, [rel smp_topology_online]
    mov  [rel sched_smp_policy_online_before], eax
    mov  edi, SMP_POLICY_OP_ROLLBACK
    mov  esi, ebx
    mov  edx, r12d
    mov  r8, r13
    call sched_smp_policy_record_request
    mov  al, [rel sched_smp_policy_profile]
    mov  [rel sched_smp_policy_rollback_from_profile], al
    mov  eax, [rel sched_smp_policy_generation]
    mov  [rel sched_smp_policy_rollback_from_generation], eax
    mov  [rel sched_smp_policy_profile], bl
    mov  [rel sched_smp_policy_generation], r12d
    mov  byte [rel sched_smp_policy_auto_rollback], 0
    mov  byte [rel sched_smp_policy_last_rolled_back], 1
    mfence
    mov  eax, [rel smp_topology_online]
    mov  [rel sched_smp_policy_online_after], eax
    cmp  eax, [rel sched_smp_policy_online_before]
    jne  .health_restore
    call sched_smp_policy_health_ok
    test eax, eax
    jz   .health_restore
    mov  eax, SMP_POLICY_TX_OK
    jmp  .unlock
.health_restore:
    mov  al, [rel sched_smp_policy_rollback_from_profile]
    mov  [rel sched_smp_policy_profile], al
    mov  eax, [rel sched_smp_policy_rollback_from_generation]
    mov  [rel sched_smp_policy_generation], eax
    mov  byte [rel sched_smp_policy_auto_rollback], 1
    mfence
    mov  eax, SMP_POLICY_TX_HEALTH
    jmp  .unlock
.stale:
    mov  eax, SMP_POLICY_TX_STALE
.unlock:
    push rax
    call sched_smp_policy_lock_release
    pop  rax
    jmp  .out
.unsupported:
    mov  eax, SMP_POLICY_TX_UNSUPPORTED
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Map a scan ordinal to the existing topology placement order only for the
; physical-first profile. Balanced preserves the shipped dense queue order.
sched_smp_policy_victim_cpu:
    cmp  byte [rel sched_smp_policy_profile], SMP_POLICY_PHYSICAL_FIRST
    jne  .dense
    cmp  byte [rel smp_placement_valid], 1
    jne  .dense
    xor  eax, eax
.scan:
    cmp  eax, esi
    jae  .dense
    lea  rcx, [rel cpu_placement_rank]
    cmp  [rcx + rax*4], edi
    je   .out
    inc  eax
    jmp  .scan
.dense:
    mov  eax, edi
.out:
    ret
; core/sched.asm — the scheduler seam (SCHEDULER.md v1): tasks + a cooperative
; yield-based context switch. Each task has its own heap stack; sched_yield saves
; the complete integer/flags/segment/TLS and negotiated XSAVE/FXSAVE state plus
; rsp, then switches to the next ready task (round-robin).
;
; Cooperative yield remains available, while each CPU's private LAPIC timer and
; wake/reschedule vectors drive the interruptible unified scheduler path. The
; CPU-local in-run mask preserves the proven no-reentry rule from the classic
; IRQ0 scheduler; work stealing remains a later additive policy layer.
; ============================================================================

TASK_MAX        equ 9                     ; > legacy fixed-eight boundary; bounded image budget
TASK_FREE       equ 0
TASK_READY      equ 1
TASK_TERMINAL   equ 2                     ; scheduler-safe deferred reap required

WD_POLICY_NONE     equ 0
WD_POLICY_PROGRESS equ 1
WD_POLICY_SYSTEM   equ 2
WD_POLICY_QUIESCED equ 3

SCHED_XSTATE_BYTES equ 1024               ; M720s CPUID.D size is bounded at init
IA32_FS_BASE       equ 0xC0000100
IA32_GS_BASE       equ 0xC0000101

struc task
  .rsp:       resq 1                      ; saved stack pointer
  .state:     resd 1                      ; 0 = free, 1 = ready
  .id:        resd 1
  .principal: resd 1                      ; 1053: owning-principal id (v1 = OWNER=1) — non-retrofittable header field
  .wd_policy: resd 1                      ; typed watchdog policy; migration never rewrites it
  .generation: resd 1                     ; monotonically advances on slot reuse
  .deferred_reap: resd 1                  ; terminal stack is reaped only from a scheduler frame
  .deadline:  resq 1                      ; absolute watchdog deadline
  .checkpoint_epoch: resq 1               ; explicit progress only; dispatch is not progress
  .expiry_claim: resq 1                    ; zero or generation owning expiry
  .fs_base:   resq 1
  .gs_base:   resq 1
  .ds_sel:    resw 1
  .es_sel:    resw 1
  .fs_sel:    resw 1
  .gs_sel:    resw 1
  .cs_sel:    resw 1                      ; invariant kernel selectors, still context-owned
  .ss_sel:    resw 1
  .last_cpu:  resd 1                      ; dense logical CPU; observation only
  .pinned_cpu: resd 1                     ; -1 migratable, 0 BSP-pinned boot/realtime
  .reserved:  resb 36                     ; xstate begins at a 64-byte boundary
  .xstate:    resb SCHED_XSTATE_BYTES     ; XSAVE(XCR0) or FXSAVE64 image
endstruc

; Slot-owned stack cache uses aligned bytes in the existing reserved area.
; No task offsets/size or heap ABI change.  Only FREE slots may reuse it, after
; generation-bound retirement from a different scheduler frame.  The boot KAT
; snapshots/clears/restores this field with the task, never a live stack cache.
TASK_STACK_IN_USE equ task.reserved
TASK_STACK_BASE  equ task.reserved + 4
TASK_STACK_BYTES equ 16384

; Generation-bound runtime scheduling policy, in previously reserved bytes.
; The existing stack cache ends at +12; all task offsets/size stay unchanged.
TASK_INTERACTIVE_CLASS equ task.reserved + 16
TASK_INTERACTIVE_GEN   equ task.reserved + 20
TASK_INTERACTIVE_NEXT  equ task.reserved + 24
SCHED_CLASS_SERVICE equ 0
SCHED_CLASS_BACKGROUND equ 1

PRIN_OWNER_TASK equ 1                      ; v1 single OWNER principal id

; Canonical portable JOB descriptor (contract 1055).  This is distinct from
; svc/command's control-plane async-command bookkeeping: this descriptor is the
; unit the scheduler EXECUTES/PLACES.  Every execution call site submits one of
; these instead of invoking compute directly.
struc sched_job
  .id:             resq 1                  ; scheduler-assigned portable job id
  .owner:          resq 1                  ; owning principal identity
  .owner_caps:     resq 1                  ; caller ceiling, rechecked against registry
  .cap_scope:      resq 1                  ; declared subset this job may exercise
  .required_cap:   resq 1                  ; capability required by the entry
  .scope_name:     resq 1                  ; canonical printable scope name
  .decl_cpu_us:    resq 1                  ; declared CPU budget
  .decl_mem:       resq 1                  ; declared memory bytes
  .decl_energy:    resq 1                  ; declared energy estimate ceiling
  .result_channel: resq 1                  ; optional completion callback(job*)
  .nonce_ptr:      resq 1                  ; caller nonce bound into the receipt
  .nonce_len:      resq 1
  .entry:          resq 1                  ; local compute entry(job*) at scale 1
  .meter_hook:     resq 1                  ; completion metering/receipt hook(job*)
  .tsc_start:      resq 1
  .tsc_end:        resq 1
  .cpu_us:         resq 1                  ; metered usage
  .mem_used:       resq 1
  .energy_est:     resq 1
  .work_result:    resq 1
  .receipt_body:   resq 1
  .receipt_len:    resq 1
  .signature:      resq 1
  .state:          resd 1
  .reaped:         resd 1                  ; dead result channel was contained
  ; Optional bounded receipt workspace, owned by this descriptor through
  ; synchronous completion. Distinct nested jobs never share signed bytes.
  .receipt_storage:   resb 512
  .signature_storage: resb 64
endstruc

SJOB_ST_FREE      equ 0
SJOB_ST_ACCEPTED  equ 1
SJOB_ST_RUNNING   equ 2
SJOB_ST_METERING  equ 3
SJOB_ST_DONE      equ 4
SJOB_ST_REJECTED  equ 5
SJOB_ST_FAILED    equ 6
SJOB_ERR_INVALID  equ -1
SJOB_ERR_CAP      equ -2
SJOB_ERR_METER    equ -3

; Private invocation storage for bounded opaque tokens, not a token grammar.
; Larger/empty/null extents retain raw pointer/length bindings; their meter
; owns validation policy. Non-null bounded extents are caller-owned readable
; native memory through synchronous return, just as for the receipt producer.
SJOB_NONCE_COPY_BYTES equ 96
SJOB_BIND_FRAME_BYTES equ 192              ; bindings/nonce bytes + returned artifact tuple

USCHED_MODE_DISPATCH equ 1
USCHED_MODE_CONTEXT  equ 2
USCHED_MODE_PREEMPT  equ 3
USCHED_MODE_STEAL    equ 4
USCHED_MODE_COHERENCE equ 5
USCHED_MODE_FAULT     equ 6
USCHED_MODE_TLB       equ 7
USCHED_MODE_SINGLE    equ 8
USCHED_MODE_PARALLEL  equ 9
USCHED_MODE_SOAK      equ 10
USCHED_SOAK_CHURN_KHZ_MAX equ 10000000 ; AP SOAK churn budget clamp (10 GHz TSC)
USCHED_SOAK_CHURN_BLOCKS  equ 8192     ; AP SOAK churn block cap if the TSC never advances
USCHED_CLASS_RT      equ 1
USCHED_CLASS_NORMAL  equ 2
USCHED_CLASS_BOOT    equ 3
USCHED_PENDING_NONE       equ 0
USCHED_PENDING_IF_CLEAR   equ 1
USCHED_PENDING_TIMER_MASK equ 2
USCHED_PENDING_IPI_ACK    equ 3
USCHED_PENDING_INCOMPLETE equ 4
USCHED_PENDING_DOUBLE_RUN equ 5
SMP_CPU_CAPACITY     equ 32                ; one enforced bound shared by sched + SMP
USCHED_CPU_MAX       equ SMP_CPU_CAPACITY
; Two pinned sentinels, one disjoint reserved context per CPU, and two
; disjoint queue-0 migration contexts per AP.  Keeping those ranges separate
; matters at capacity: reusing a reserved context for its CPU's first remote
; ticket turns a real steal into a local re-run and falsifies the ledger.
USCHED_TASK_CONTEXTS equ SMP_CPU_CAPACITY * 3
USCHED_WAIT_STEPS_PER_CPU equ 5000          ; 250 ms/CPU at the 50 us poll cadence
USCHED_MAX_UNITS     equ 2048              ; bounded exactly-once bitmap
USCHED_SEEN_QWORDS   equ (USCHED_MAX_UNITS / 64)
USCHED_CAPSTONE_MAX_UNITS equ 1048576       ; 1330g: block-CAS accounting, no giant bitmap
USCHED_SCALING_MAX_UNITS equ 4194304        ; opt-in 4x real work; SINGLE/PARALLEL only
USCHED_CAPSTONE_BLOCK equ 64
USCHED_CAPSTONE_MIX_ROUNDS equ 1024
USCHED_PARALLEL_POLL_BLOCKS equ 1024       ; bounded BSP work per parallel RESULT
USCHED_LONG_SINGLE_POLL_BLOCKS equ 4096   ; extended SINGLE yields within owner request budget

; sched_init — register the current (boot) context as task 0
sched_init:
    call sched_smp_policy_init
    lea  rax, [rel sched_tasks]
    mov  dword [rax + task.state], TASK_READY
    mov  dword [rax + task.id], 0
    mov  dword [rax + task.principal], PRIN_OWNER_TASK   ; 1053: tag task 0 with OWNER
    mov  dword [rax + task.wd_policy], WD_POLICY_SYSTEM ; boot/control is explicitly exempt + BSP-pinned
    mov  dword [rax + task.generation], 1
    mov  dword [rax + TASK_STACK_IN_USE], 1
    mov  dword [rax + task.pinned_cpu], 0
    mov  dword [rax + task.last_cpu], 0
    mov  dword [rel sched_cur], 0
    lea  rax, [rel job_dispatch_local]
    mov  [rel job_dispatch_hook], rax       ; runtime VA (never a baked dq symbol)
    call sched_unified_context_init
    ret

; Negotiate the exact extended-state contract once. XSAVE is selected only when
; CPUID advertises XSAVE+OSXSAVE, XCR0 contains mandatory x87/SSE, and CPUID.D's
; live enabled-image size fits the task ABI. Otherwise the complete architectural
; x87/SSE image uses the proven FXSAVE64 fallback.
; Firmware need not hand off with OSXSAVE set. On an XSAVE CPU whose CPUID.D
; supports x87+SSE, the BSP enables OSXSAVE with exactly XCR0=x87|SSE before any
; task image exists (no AVX: its consumers keep their fallback); APs adopt the
; result in sched_unified_cpu_local_init. A firmware-enabled XCR0 is kept as is.
sched_unified_context_init:
    push rbx
    mov  byte [rel sched_xsave_mode], 0
    mov  dword [rel sched_xsave_mask_lo], 3
    mov  dword [rel sched_xsave_mask_hi], 0
    mov  dword [rel sched_xstate_size], 512
    mov  eax, 1
    cpuid
    test ecx, (1 << 26)                    ; XSAVE
    jz   .done
    test ecx, (1 << 27)                    ; OSXSAVE already set by firmware
    jz   .bsp_enable
    cmp  byte [rel sched_xsave_enable], 2  ; a repeat call keeps PaOS's own enable
    je   .negotiate
    mov  byte [rel sched_xsave_enable], 1
    jmp  .negotiate
.bsp_enable:
    mov  eax, 0x0D
    xor  ecx, ecx
    cpuid
    and  eax, 3
    cmp  eax, 3                            ; XCR0 x87+SSE supported
    jne  .done
    mov  rax, cr4
    or   rax, (1 << 18)                    ; CR4.OSXSAVE
    mov  cr4, rax
    xor  ecx, ecx
    mov  eax, 3
    xor  edx, edx
    xsetbv
    mov  byte [rel sched_xsave_enable], 2
.negotiate:
    xor  ecx, ecx
    xgetbv
    mov  [rel sched_xsave_mask_lo], eax
    mov  [rel sched_xsave_mask_hi], edx
    mov  ecx, eax
    and  ecx, 3
    cmp  ecx, 3
    jne  .fallback
    mov  eax, 0x0D
    xor  ecx, ecx
    cpuid
    cmp  ebx, SCHED_XSTATE_BYTES
    ja   .fallback
    mov  [rel sched_xstate_size], ebx
    mov  byte [rel sched_xsave_mode], 1
    jmp  .done
.fallback:
    mov  dword [rel sched_xsave_mask_lo], 3
    mov  dword [rel sched_xsave_mask_hi], 0
    mov  dword [rel sched_xstate_size], 512
.done:
    pop  rbx
    ret

; Read-only current scheduler contract for AVX/YMM consumers. The immutable
; boot-negotiated XSAVE image must include x87/SSE/YMM, with room for YMM_Hi128.
; Does not enable CPU state or alter scheduling. EAX=1 ready,0 fallback; all
; other registers/FP/DF untouched. Used alongside live CPU/XCR0 capability checks.
sched_xstate_avx_ready:
    cmp  byte [rel sched_xsave_mode], 1
    jne  .no
    mov  eax, [rel sched_xsave_mask_lo]
    and  eax, 7
    cmp  eax, 7
    jne  .no
    cmp  dword [rel sched_xstate_size], 832
    jb   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Adopt the BSP-negotiated extended-state contract on each AP before work runs.
sched_unified_cpu_local_init:
    mov  rax, cr0
    and  rax, ~(1 << 2)
    or   rax, (1 << 1)
    mov  cr0, rax
    mov  rax, cr4
    or   rax, (1 << 9) | (1 << 10)
    cmp  byte [rel sched_xsave_mode], 0
    je   .cr4_ready
    or   rax, (1 << 18)
.cr4_ready:
    mov  cr4, rax
    cmp  byte [rel sched_xsave_mode], 0
    je   .done
    xor  ecx, ecx
    mov  eax, [rel sched_xsave_mask_lo]
    mov  edx, [rel sched_xsave_mask_hi]
    xsetbv
.done:
    ret

; R8 = task*. The task table and stride keep .xstate 64-byte aligned.
sched_xstate_save:
    cmp  byte [rel sched_xsave_mode], 0
    je   .fx
    mov  eax, [rel sched_xsave_mask_lo]
    mov  edx, [rel sched_xsave_mask_hi]
    xsave [r8 + task.xstate]
    ret
.fx:
    fxsave [r8 + task.xstate]
    ret

sched_xstate_restore:
    cmp  byte [rel sched_xsave_mode], 0
    je   .fx
    mov  eax, [rel sched_xsave_mask_lo]
    mov  edx, [rel sched_xsave_mask_hi]
    xrstor [r8 + task.xstate]
    ret
.fx:
    fxrstor [r8 + task.xstate]
    ret

; RDI = aligned SCHED_XSTATE_BYTES image.
sched_xstate_save_ptr:
    cmp  byte [rel sched_xsave_mode], 0
    je   .fx
    mov  eax, [rel sched_xsave_mask_lo]
    mov  edx, [rel sched_xsave_mask_hi]
    xsave [rdi]
    ret
.fx:
    fxsave [rdi]
    ret

sched_xstate_restore_ptr:
    cmp  byte [rel sched_xsave_mode], 0
    je   .fx
    mov  eax, [rel sched_xsave_mask_lo]
    mov  edx, [rel sched_xsave_mask_hi]
    xrstor [rdi]
    ret
.fx:
    fxrstor [rdi]
    ret

; Canonical lock wrappers required by the module lock manifest. The indexed
; wrapper takes EDI=task slot and resolves the byte lock before tail-calling the
; one core/lock implementation.
sched_task_lock_acquire:
    lea  rdi, [rel sched_task_lock]
    jmp  spin_acquire
sched_task_lock_release:
    lea  rdi, [rel sched_task_lock]
    jmp  spin_release
sched_smp_policy_lock_acquire:
    lea  rdi, [rel sched_smp_policy_lock]
    jmp  spin_acquire
sched_smp_policy_lock_release:
    lea  rdi, [rel sched_smp_policy_lock]
    jmp  spin_release
usched_task_lock_acquire:
    lea  rax, [rel usched_task_lock]
    add  rax, rdi
    mov  rdi, rax
    jmp  spin_acquire
usched_task_lock_release:
    lea  rax, [rel usched_task_lock]
    add  rax, rdi
    mov  rdi, rax
    jmp  spin_release
usched_context_lock_acquire:
    lea  rdi, [rel usched_context_lock]
    jmp  spin_acquire
usched_context_lock_release:
    lea  rdi, [rel usched_context_lock]
    jmp  spin_release
usched_rq_lock_acquire:
    lea  rax, [rel usched_rq_lock]
    add  rax, rdi
    mov  rdi, rax
    jmp  spin_acquire
usched_rq_lock_release:
    lea  rax, [rel usched_rq_lock]
    add  rax, rdi
    mov  rdi, rax
    jmp  spin_release

; Explicit progress is generation-bound. Dispatch and migration never call it.
sched_watchdog_checkpoint:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, edi
    mov  r12d, esi
    mov  r13, rdx
    mov  r14, rcx
    cmp  ebx, TASK_MAX
    jae  .bad
    call sched_task_lock_acquire
    mov  eax, ebx
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    cmp  dword [r8 + task.state], TASK_READY
    jne  .unlock_bad
    cmp  [r8 + task.generation], r12d
    jne  .unlock_bad
    cmp  dword [r8 + task.wd_policy], WD_POLICY_PROGRESS
    jne  .unlock_bad
    cmp  qword [r8 + task.expiry_claim], 0
    jne  .unlock_bad
    cmp  r14, [r8 + task.checkpoint_epoch]
    jbe  .unlock_bad
    mov  [r8 + task.deadline], r13
    mov  [r8 + task.checkpoint_epoch], r14
    call sched_task_lock_release
    xor  eax, eax
    jmp  .out
.unlock_bad:
    call sched_task_lock_release
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; One lock owner binds an expiry claim to the observed slot generation.
sched_watchdog_claim_expiry:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  r13, rdx
    cmp  ebx, TASK_MAX
    jae  .bad
    call sched_task_lock_acquire
    mov  eax, ebx
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    cmp  dword [r8 + task.state], TASK_READY
    jne  .unlock_bad
    cmp  [r8 + task.generation], r12d
    jne  .unlock_bad
    cmp  dword [r8 + task.wd_policy], WD_POLICY_PROGRESS
    jne  .unlock_bad
    cmp  qword [r8 + task.expiry_claim], 0
    jne  .unlock_bad
    mov  rax, [r8 + task.deadline]
    test rax, rax
    jz   .unlock_bad
    cmp  r13, rax
    jb   .unlock_bad
    mov  eax, r12d
    mov  [r8 + task.expiry_claim], rax
    mov  dword [r8 + task.deferred_reap], 1
    mov  dword [r8 + task.state], TASK_TERMINAL
    call sched_task_lock_release
    xor  eax, eax
    jmp  .out
.unlock_bad:
    call sched_task_lock_release
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Reuse becomes visible only from a scheduler-owned frame and only for the
; generation that owns the terminal claim.
sched_watchdog_deferred_reap:
    pushfq
    cli                                     ; no same-CPU lock reentry
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, esi
    cmp  ebx, TASK_MAX
    jae  .bad
    cmp  ebx, [rel sched_cur]
    je   .bad
    call sched_task_lock_acquire
    mov  eax, ebx
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    cmp  dword [r8 + task.state], TASK_TERMINAL
    jne  .unlock_bad
    cmp  [r8 + task.generation], r12d
    jne  .unlock_bad
    cmp  dword [r8 + task.deferred_reap], 1
    jne  .unlock_bad
    cmp  [r8 + task.expiry_claim], r12
    jne  .unlock_bad
    cmp  dword [r8 + TASK_STACK_IN_USE], 0 ; sched_cur may change before RSP does
    jne  .unlock_bad
    mov  qword [r8 + task.expiry_claim], 0
    mov  dword [r8 + task.deferred_reap], 0
    mov  dword [r8 + task.state], TASK_FREE
    call sched_task_lock_release
    xor  eax, eax
    jmp  .out
.unlock_bad:
    call sched_task_lock_release
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    popfq
    ret

; sched_spawn(RDI=entry) -> EAX = task id / -1. Reuses a slot-owned stack + frame
; so the first switch into it "returns" into entry.
;
; TOURNAMENT 1418 v3 (durability class). Byte-identical result for every legal
; (non-null) caller — same slot pick, same 56-byte frame, same task.* fields.
; Adds fault CONTAINMENT + atomic commit over the baseline:
;   * NULL entry (rdi=0) is REFUSED up front (folds onto the -1 reject) — the
;     baseline would spawn a task whose first switch "returns" into ip 0 and
;     triple-faults. A null function pointer is the one hostile input the scan
;     can't catch later, so it is rejected before any slot is consumed.
;   * OOM (kmalloc==0) already rejects; keeps -1 with no half-initialised slot.
;   * The task.state=1 "ready" flag is published LAST — after rsp / id /
;     principal are all written — so a preemptive picker (core/time IRQ0, the
;     documented next step) can never observe a half-formed frame as runnable.
; Preserves all callee-saved (rbx/r12); touches only caller-saved otherwise.
sched_spawn:
    pushfq
    cli                                     ; serialize slot claim through READY
    push rbx
    push r12
    test rdi, rdi                         ; DURABLE: NULL entry -> refuse (no ip-0 task)
    jz   .reject                          ; contained before any slot is consumed
    mov  r12, rdi                         ; entry
    call sched_task_lock_acquire
    lea  rbx, [rel sched_tasks]
    xor  ecx, ecx
.find:
    cmp  ecx, TASK_MAX
    jge  .unlock_reject
    mov  eax, ecx
    imul eax, task_size
    lea  r8, [rbx + rax]
    cmp  dword [r8 + task.state], TASK_FREE
    je   .got
    inc  ecx
    jmp  .find
.reject:                                  ; NULL / table-full / OOM all land here
    mov  rax, -1
    pop  r12
    pop  rbx
    popfq
    ret
.unlock_reject:
    call sched_task_lock_release
    jmp  .reject
.got:
    mov  rax, [r8 + TASK_STACK_BASE]
    test rax, rax
    jnz  .have_stack
    push rcx
    push r8
    mov  edi, TASK_STACK_BYTES             ; at most one allocation per live slot
    call kmalloc
    pop  r8
    pop  rcx
    test rax, rax
    jz   .unlock_reject                    ; no cache/slot published on OOM
    mov  [r8 + TASK_STACK_BASE], rax
.have_stack:
    ; Retired contents must never become the next task's uninitialized memory.
    ; Keep the cache in this task record, not in a cross-slot free list.
    push rcx
    mov  rdi, rax
    mov  edx, TASK_STACK_BYTES
.clear_stack:
    mov  qword [rdi], 0
    add  rdi, 8
    sub  edx, 8
    jnz  .clear_stack
    pop  rcx
    add  rax, TASK_STACK_BYTES             ; stack top (16-byte aligned)
    sub  rax, 144                          ; 15 GPR + RFLAGS + entry + task-exit
    mov  qword [rax + 0],  0               ; r15..rax initial (zero), unrolled
    mov  qword [rax + 8],  0
    mov  qword [rax + 16], 0
    mov  qword [rax + 24], 0
    mov  qword [rax + 32], 0
    mov  qword [rax + 40], 0
    mov  qword [rax + 48], 0
    mov  qword [rax + 56], 0
    mov  qword [rax + 64], 0
    mov  qword [rax + 72], 0
    mov  qword [rax + 80], 0
    mov  qword [rax + 88], 0
    mov  qword [rax + 96], 0
    mov  qword [rax + 104], 0
    mov  qword [rax + 112], 0
    mov  qword [rax + 120], 0x202          ; caller RFLAGS: IF + reserved bit
    mov  [rax + 128], r12                  ; first ret target = entry
    lea  rdx, [rel sched_task_exit]
    mov  [rax + 136], rdx                  ; returning entry is contained
    mov  [r8 + task.rsp], rax              ; frame first ...
    mov  [r8 + task.id], ecx
    mov  dword [r8 + task.principal], PRIN_OWNER_TASK   ; 1053: spawned tasks owned by OWNER
    mov  eax, [r8 + task.generation]
    inc  eax
    jnz  .generation_ok
    inc  eax                               ; generation zero is never published
.generation_ok:
    mov  [r8 + task.generation], eax
    mov  dword [r8 + task.wd_policy], WD_POLICY_PROGRESS
    mov  dword [r8 + task.deferred_reap], 0
    mov  qword [r8 + task.deadline], 0
    mov  qword [r8 + task.checkpoint_epoch], 0
    mov  qword [r8 + task.expiry_claim], 0
    mov  dword [r8 + task.last_cpu], 0
    mov  dword [r8 + task.pinned_cpu], -1
    mov  ax, ds
    mov  [r8 + task.ds_sel], ax
    mov  ax, es
    mov  [r8 + task.es_sel], ax
    mov  ax, fs
    mov  [r8 + task.fs_sel], ax
    mov  ax, gs
    mov  [r8 + task.gs_sel], ax
    mov  ax, cs
    mov  [r8 + task.cs_sel], ax
    mov  ax, ss
    mov  [r8 + task.ss_sel], ax
    ; FXSAVE/XSAVE may leave reserved/inactive bytes unwritten.  Do not retain
    ; a prior generation's extended-state padding in the new task record.
    lea  rdi, [r8 + task.xstate]
    mov  edx, SCHED_XSTATE_BYTES
.clear_xstate:
    mov  qword [rdi], 0
    add  rdi, 8
    sub  edx, 8
    jnz  .clear_xstate
    mov  ecx, IA32_FS_BASE
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [r8 + task.fs_base], rax
    mov  ecx, IA32_GS_BASE
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [r8 + task.gs_base], rax
    call sched_xstate_save
    mov  ecx, [r8 + task.id]
    mov  dword [r8 + TASK_STACK_IN_USE], 0
    mov  dword [r8 + TASK_INTERACTIVE_CLASS], SCHED_CLASS_SERVICE
    mov  dword [r8 + TASK_INTERACTIVE_GEN], 0
    mov  qword [r8 + TASK_INTERACTIVE_NEXT], 0
    mov  dword [r8 + task.state], TASK_READY ; publish LAST (atomic commit)
    call sched_task_lock_release
    mov  eax, ecx
    pop  r12
    pop  rbx
    popfq
    ret

; The retiring stack stays terminal until another scheduler frame reaps it.
sched_task_exit:
    cli                                     ; yield restores the next task's flags
    call sched_task_lock_acquire
    mov  eax, [rel sched_cur]
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    mov  eax, [r8 + task.generation]
    mov  [r8 + task.expiry_claim], rax      ; normal return owns this generation
    mov  dword [r8 + task.deferred_reap], 1
    mov  dword [r8 + task.state], TASK_TERMINAL
    call sched_task_lock_release
.yield:
    call sched_yield
    jmp  .yield

 ; Trusted runtime policy only: BSP, IF enabled, outside IRQ frames.
; No session authority is granted by a class or pressure hint.
sched_interactive_context:
    pushfq
    pop rax
    test eax, 1 << 9
    jz .bad
    cmp byte [rel cpu_irq_depth], 0
    jne .bad
    push rdi
    push rsi
    push rdx
    call smp_current_logical
    pop rdx
    pop rsi
    pop rdi
    test eax, eax
    jnz .bad
    ret
.bad:
    mov eax, -3
    ret

; set_class(EDI=slot, ESI=current generation, EDX=0 service / 1 background)
; -> EAX=0 / -1 invalid / -2 stale / -3 wrong context. No task-0 demotion.
sched_interactive_set_class:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12d, esi
    mov r13d, edx
    call sched_interactive_context
    test eax, eax
    jnz .out
    cmp ebx, TASK_MAX
    jae .bad
    cmp r13d, SCHED_CLASS_BACKGROUND
    ja .bad
    test ebx, ebx
    jz .bad
    pushfq
    cli
    call sched_task_lock_acquire
    mov eax, ebx
    imul eax, task_size
    lea r8, [rel sched_tasks]
    add r8, rax
    cmp dword [r8 + task.state], TASK_READY
    jne .unlock_bad
    test r12d, r12d
    jz .unlock_stale
    cmp [r8 + task.generation], r12d
    jne .unlock_stale
    cmp [r8 + TASK_INTERACTIVE_CLASS], r13d
    jne .change
    cmp [r8 + TASK_INTERACTIVE_GEN], r12d
    je .unchanged
.change:
    mov [r8 + TASK_INTERACTIVE_CLASS], r13d
    mov [r8 + TASK_INTERACTIVE_GEN], r12d
    mov qword [r8 + TASK_INTERACTIVE_NEXT], 0
.unchanged:
    xor ebx, ebx
    jmp .unlock
.unlock_stale:
    mov ebx, -2
    jmp .unlock
.unlock_bad:
    mov ebx, -1
.unlock:
    call sched_task_lock_release
    popfq
    mov eax, ebx
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Trusted telemetry: EDI bit0 battery, bit1 hot; unknown = 0.
; This never reads energy or changes firmware. Stronger hint wins in the picker.
sched_interactive_set_pressure:
    push rdi
    call sched_interactive_context
    pop rdi
    test eax, eax
    jnz .out
    cmp edi, 3
    ja .bad
    mov [rel sched_interactive_pressure], edi
    xor eax, eax
.out:
    ret
.bad:
    mov eax, -1
    ret

; Serialized desktop sweep. Only the epoch sampled before input drain is
; serviced; a producer arriving inside/after that drain remains pending.
sched_interactive_begin:
    mov byte [rel sched_interactive_live], 1 ; policy starts only at desktop handoff
    mov rax, [rel sched_interactive_epoch]
    mov [rel sched_interactive_snapshot], rax
    ret
; EDI=ps2_input_pending(): never acknowledge a partly drained input burst.
sched_interactive_end:
    test edi, edi
    jnz .done
    mov rax, [rel sched_interactive_snapshot]
    cmp rax, [rel sched_interactive_serviced]
    je .done
    mov [rel sched_interactive_serviced], rax
    cmp rax, [rel sched_interactive_epoch]
    jne .recent                        ; a racing new input retains its pending period
    mov qword [rel sched_interactive_fair_at], 0
.recent:
    call time_monotonic_now_us
    test rax, rax
    jz .done
    add rax, 8000
    mov [rel sched_interactive_recent_until], rax
.done:
    ret

; Round-robin among service and eligible background tasks. Caller owns the
; task lock with IRQs disabled. Never waits: cooling tasks leave CPU to task 0,
; whose existing idle path uses HLT. Monotonic time is independent of IRQ rates.
sched_pick_next:
    push rbx
    push r12
    push r13
    push r14
    xor r12d, r12d
    cmp byte [rel sched_interactive_live], 1
    jne .scan                          ; boot selftests retain their original picker
    call time_monotonic_now_us
    mov r12, rax
    mov r13d, 1000                      ; normal per-task admission interval
    mov r14d, 8000                      ; pending-input fairness interval
    test rax, rax
    jz .scan                           ; unavailable clock: legacy round-robin
    cmp rax, [rel sched_interactive_recent_until]
    jae .pressure
    mov r13d, 4000
.pressure:
    test dword [rel sched_interactive_pressure], 1
    jz .hot
    mov r13d, 8000
    mov r14d, 16000
.hot:
    test dword [rel sched_interactive_pressure], 2
    jz .input
    mov r13d, 16000
    mov r14d, 32000
.input:
    mov rax, [rel sched_interactive_epoch]
    cmp rax, [rel sched_interactive_serviced]
    je .quiet
    cmp r13d, 4000
    jae .pending
    mov r13d, 4000
.pending:
    cmp qword [rel sched_interactive_fair_at], 0
    jne .fair_started
    lea rax, [r12 + r14]
    mov [rel sched_interactive_fair_at], rax
.fair_started:
    cmp r12, [rel sched_interactive_fair_at]
    jae .scan                          ; one due background opportunity
    cmp dword [rel sched_tasks + task.state], TASK_READY
    jne .scan
    xor ecx, ecx
    jmp .found                         ; desktop drains pending input first
.quiet:
    mov qword [rel sched_interactive_fair_at], 0
.scan:
    mov ecx, [rel sched_cur]
    xor ebx, ebx
.l:
    inc ecx
    cmp ecx, TASK_MAX
    jl .nowrap
    xor ecx, ecx
.nowrap:
    mov eax, ecx
    imul eax, task_size
    lea r8, [rel sched_tasks]
    add r8, rax
    cmp dword [r8 + task.state], TASK_READY
    jne .next
    test r12, r12
    jz .found
    cmp dword [r8 + TASK_INTERACTIVE_CLASS], SCHED_CLASS_BACKGROUND
    jne .found
    mov eax, [r8 + task.generation]
    cmp eax, [r8 + TASK_INTERACTIVE_GEN]
    jne .found                         ; stale policy never attaches to reuse
    cmp r12, [r8 + TASK_INTERACTIVE_NEXT]
    jb .next
    lea rax, [r12 + r13]
    mov [r8 + TASK_INTERACTIVE_NEXT], rax
    mov rax, [rel sched_interactive_epoch]
    cmp rax, [rel sched_interactive_serviced]
    je .found                          ; quiet admissions do not start input fairness
    lea rax, [r12 + r14]
    mov [rel sched_interactive_fair_at], rax
.found:
    mov [rel sched_cur], ecx
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.next:
    inc ebx
    cmp ebx, TASK_MAX
    jl .l
    ; Task 0 is the permanent service context. Preserve the old current slot
    ; only in malformed/no-ready fixtures; product always has READY task 0.
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; 1330d interrupt-frame entries. The assembly ISR has already saved every GPR;
; count an event only when that interrupt actually advances a scheduler unit.
sched_preempt_irq:
    push rbx
    mov  ebx, edi
    mov  byte [rel sched_watchdog_scan_pending], 1
    xor  eax, eax
    cmp  byte [rel usched_job_active], 1
    jne  .out
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .out
    mov  edi, ebx
    call sched_unified_run_one
    test eax, eax
    jz   .out
    lock inc dword [rel usched_job_preemptions]
    lock bts dword [rel usched_job_timer_mask], ebx
.out:
    pop  rbx
    ret

sched_resched_ipi_irq:
    push rbx
    push r12
    mov  ebx, edi
    xor  r12d, r12d
    cmp  dword [rel sched_affinity_probe_pending], 1
    jne  .bench
    cmp  ebx, [rel sched_affinity_probe_target]
    jne  .bench
    mov  eax, 1
    mov  edx, 2
    lock cmpxchg dword [rel sched_affinity_probe_pending], edx
    jne  .bench
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel sched_affinity_probe_start]
    mov  [rel sched_affinity_probe_latency], rax
    mov  [rel sched_affinity_probe_actual], ebx
    mov  dword [rel sched_affinity_probe_pending], 0
    mov  r12d, 1
.bench:
    xor  eax, eax
    cmp  byte [rel usched_job_active], 1
    jne  .result
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .result
    mov  edi, ebx
    call sched_unified_run_one
    test eax, eax
    jz   .result
    lock inc dword [rel usched_job_resched_ipis]
    mov  r12d, 1
.result:
    mov  eax, r12d
    pop  r12
    pop  rbx
    ret

sched_idle_wake_ipi_irq:
    push rbx
    mov  ebx, edi
    xor  eax, eax
    cmp  byte [rel usched_job_active], 1
    jne  .out
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .out
    mov  edi, ebx
    call sched_unified_run_one
    test eax, eax
    jz   .out
    lock inc dword [rel usched_job_idle_wakes]
.out:
    pop  rbx
    ret

; Execute a placement probe in the selected CPU's reschedule-vector frame.
sched_affinity_probe_execute:
    push rbx
    push r12
    mov  ebx, edi
    cmp  ebx, 0
    jl   .bad
    cmp  ebx, [rel smp_discovered_count]
    jae  .bad
    ; A timed-out claimed IRQ still owns this descriptor until it publishes
    ; pending=0. Refuse another probe without replacing its target/timestamp
    ; or sending another IPI; the original completion retires that ownership.
    cmp  dword [rel sched_affinity_probe_pending], 0
    jne  .bad
    mov  [rel sched_affinity_probe_target], ebx
    mov  dword [rel sched_affinity_probe_actual], -1
    mov  qword [rel sched_affinity_probe_latency], 0
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel sched_affinity_probe_start], rax
    mov  dword [rel sched_affinity_probe_pending], 1
    call smp_current_logical
    cmp  eax, ebx
    jne  .send_remote
    ; A self-IPI cannot be serviced while command dispatch owns an IF-cleared
    ; frame. The probe is already executing on the selected CPU, so publish
    ; that live identity directly rather than timing out on its own interrupt.
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel sched_affinity_probe_start]
    mov  [rel sched_affinity_probe_latency], rax
    mov  [rel sched_affinity_probe_actual], ebx
    mov  dword [rel sched_affinity_probe_pending], 0
    jmp  .done
.send_remote:
    mov  edi, ebx
    call smp_preempt_send_resched_one
    test eax, eax
    jz   .cancel
    ; The probe also runs after PMOD and the late device/selftest wave.  A raw
    ; PAUSE-count window passed the early KAT but expired on the 32-vCPU TCG
    ; leg once all vCPU/device threads were active.  Use the same bounded,
    ; topology-scaled cadence as the scheduler barriers: 250 ms per online
    ; CPU, capped by the enforced 32-CPU capacity.  Metal normally exits on
    ; the first observed acknowledgement.
    call sched_unified_wait_budget
    mov  r12d, eax
.wait:
    cmp  dword [rel sched_affinity_probe_pending], 0
    je   .done
    mov  edi, 50
    call tsc_delay_us
    dec  r12d
    jnz  .wait
.cancel:
    mov  eax, 1
    xor  edx, edx
    lock cmpxchg dword [rel sched_affinity_probe_pending], edx
    je   .bad
    test eax, eax
    jz   .done
    cmp  eax, 2
    jne  .bad
    call sched_unified_wait_budget
    mov  r12d, eax
.claim_wait:
    cmp  dword [rel sched_affinity_probe_pending], 0
    je   .done
    mov  edi, 50
    call tsc_delay_us
    dec  r12d
    jnz  .claim_wait
.bad:
    mov  eax, -1
    pop  r12
    pop  rbx
    ret
.done:
    mov  eax, [rel sched_affinity_probe_actual]
    pop  r12
    pop  rbx
    ret

; Called only by a normal BSP/AP scheduler loop after an interrupt returned.
sched_watchdog_safe_frame:
    xor  eax, eax
    mov  dl, 0
    xchg dl, [rel sched_watchdog_scan_pending]
    test dl, dl
    jz   .done
    push rbx
    push r12
    mov  ebx, 1
.scan:
    cmp  ebx, TASK_MAX
    jae  .scan_done
    mov  eax, ebx
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    cmp  dword [r8 + task.state], TASK_TERMINAL
    je   .terminal_reap
    cmp  dword [r8 + task.state], TASK_READY
    jne  .next
    cmp  dword [r8 + task.wd_policy], WD_POLICY_PROGRESS
    jne  .next
    mov  rax, [r8 + task.deadline]
    test rax, rax
    jz   .next
    mov  r12d, [r8 + task.generation]
    mov  edi, ebx
    mov  esi, r12d
    mov  rdx, [rel timer_ticks]
    call sched_watchdog_claim_expiry
    test eax, eax
    jnz  .next
    lock inc qword [rel sched_watchdog_claims]
    jmp  .reap_claimed
.terminal_reap:
    mov  r12d, [r8 + task.generation]
.reap_claimed:
    mov  edi, ebx
    mov  esi, r12d
    call sched_watchdog_deferred_reap
    test eax, eax
    jnz  .next
    lock inc qword [rel sched_watchdog_reaps]
.next:
    inc  ebx
    jmp  .scan
.scan_done:
    pop  r12
    pop  rbx
.done:
    ret

; sched_yield — complete cooperative context switch. pushfq MUST precede cli.
sched_yield:
    pushfq
    cli
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel sched_cur]             ; old slot survives until RSP switches
    mov  eax, r12d
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    mov  [r8 + task.rsp], rsp              ; complete integer/flags/RIP/RSP frame
    mov  ax, ds
    mov  [r8 + task.ds_sel], ax
    mov  ax, es
    mov  [r8 + task.es_sel], ax
    mov  ax, fs
    mov  [r8 + task.fs_sel], ax
    mov  ax, gs
    mov  [r8 + task.gs_sel], ax
    mov  ax, cs
    mov  [r8 + task.cs_sel], ax
    mov  ax, ss
    mov  [r8 + task.ss_sel], ax
    mov  ecx, IA32_FS_BASE
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [r8 + task.fs_base], rax
    mov  ecx, IA32_GS_BASE
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [r8 + task.gs_base], rax
    sub  rsp, 8                            ; internal calls keep SysV alignment
    call sched_xstate_save
    call sched_task_lock_acquire           ; claim next READY stack against reap
    call sched_pick_next
    mov  eax, [rel sched_cur]
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    mov  dword [r8 + TASK_STACK_IN_USE], 1
    call sched_task_lock_release
    call sched_xstate_restore
    add  rsp, 8
    mov  ax, [r8 + task.ds_sel]
    mov  ds, ax
    mov  ax, [r8 + task.es_sel]
    mov  es, ax
    mov  ax, [r8 + task.fs_sel]
    mov  fs, ax
    mov  ax, [r8 + task.gs_sel]
    mov  gs, ax
    mov  rax, [r8 + task.fs_base]
    mov  rdx, rax
    shr  rdx, 32
    mov  ecx, IA32_FS_BASE
    wrmsr
    mov  rax, [r8 + task.gs_base]
    mov  rdx, rax
    shr  rdx, 32
    mov  ecx, IA32_GS_BASE
    wrmsr
    mov  rsp, [r8 + task.rsp]              ; switch to next
    cmp  r12d, [r8 + task.id]
    je   .stack_detached
    ; The old stack is physically detached now.  Publish only after the last
    ; access; a concurrent safe-frame reaper can then make that slot FREE.
    imul r12d, task_size
    lea  rdx, [rel sched_tasks]
    mov  dword [rdx + r12 + TASK_STACK_IN_USE], 0
    cmp  dword [rdx + r12 + task.state], TASK_TERMINAL
    jne  .stack_detached
    mov  byte [rel sched_watchdog_scan_pending], 1
.stack_detached:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    pop  rdx
    pop  rcx
    pop  rax
    popfq
    ret

; job_set_dispatch_hook(RDI=policy(job*) fn) -> RAX=0/-1.  Policy is installed
; during scheduler setup; live submissions only read the pointer.  v1 installs
; job_dispatch_local, while a later grid policy can choose a peer without any
; submitter/call-site rewrite.
job_set_dispatch_hook:
    test rdi, rdi
    jz   .bad
    mov  [rel job_dispatch_hook], rdi
    xor  eax, eax
    ret
.bad:
    mov  eax, SJOB_ERR_INVALID
    ret

; job_bind_owner_lookup(RDI=locked registry lookup(pid)->caps) -> RAX=0/-1.
; The L5 principal consumer binds its established lookup through this L1
; callback seam, just as placement uses a policy callback. No role table is
; duplicated here. Binding is one-time/idempotent; no live policy replacement.
job_bind_owner_lookup:
    test rdi, rdi
    jz   .bad
    xor  eax, eax
    lock cmpxchg [rel job_owner_lookup_hook], rdi
    je   .bound
    cmp  rax, rdi
    jne  .bad
.bound:
    xor  eax, eax
    ret
.bad:
    mov  eax, SJOB_ERR_INVALID
    ret

; job_dispatch_local(RDI=sched_job*) -> entry result.  This is the scale-1
; policy behind the replaceable scheduler hook, not a submitter-side direct call.
job_dispatch_local:
    mov  rax, [rdi + sched_job.entry]
    test rax, rax
    jz   .bad
    jmp  rax                              ; tail-call keeps SysV entry alignment
.bad:
    mov  eax, SJOB_ERR_INVALID
    ret

; job_submit(RDI=sched_job*) -> RAX=0 / SJOB_ERR_*.
; Deterministic admission barrier:
;   current registry grant AND caller ceiling contain the declared scope,
;   active caller scope contains it, and it contains the entry's required cap.
;   Only then is cap_current_mask narrowed for execution.
; TSC edges and the mandatory per-JOB meter hook are owned by the scheduler;
; an absent result channel is reaped cleanly instead of wedging completion.
; Entry/meter/result bindings are fixed for this synchronous invocation. Work
; may report its result and usage; it cannot replace the admitted identity or
; callbacks. The caller retains the descriptor until completion returns.
job_submit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, SJOB_BIND_FRAME_BYTES       ; private per-invocation bindings
    mov  qword [rsp], 0
    mov  r12, rdi
    test r12, r12
    jz   .invalid
    cmp  qword [r12 + sched_job.owner], 0
    je   .invalid
    cmp  qword [r12 + sched_job.entry], 0
    je   .invalid
    cmp  qword [r12 + sched_job.meter_hook], 0
    je   .invalid

    ; Caller owns the descriptor through synchronous completion (the receipt
    ; caller holds job_receipt_lock). Keep admitted identity/scope in callee-
    ; saved registers; callbacks must not change what is later signed.
    mov  r14, [r12 + sched_job.owner]
    mov  r15, [r12 + sched_job.cap_scope]
    mov  rbx, [r12 + sched_job.required_cap]
    mov  rax, [r12 + sched_job.entry]
    mov  [rsp + 8], rax
    mov  rax, [r12 + sched_job.meter_hook]
    mov  [rsp + 16], rax
    mov  rax, [r12 + sched_job.result_channel]
    mov  [rsp + 24], rax
    mov  rax, [r12 + sched_job.nonce_ptr]
    mov  [rsp + 32], rax
    mov  rax, [r12 + sched_job.nonce_len]
    mov  [rsp + 40], rax
    mov  qword [rsp + 48], 0             ; no byte reads before cap admission
    call .retire_receipt
    mov  rax, [rel job_owner_lookup_hook]
    test rax, rax
    jz   .cap_reject
    mov  rdi, r14
    call rax                              ; current locked principal registry
    test rax, rax                         ; absent/authority-free owner cannot run
    jz   .cap_reject
    and  rax, [r12 + sched_job.owner_caps] ; cached metadata can only restrict
    mov  rdx, r15
    and  rdx, rax
    cmp  rdx, r15
    jne  .cap_reject
    mov  rdx, rbx
    and  rdx, r15
    cmp  rdx, rbx
    jne  .cap_reject
    mov  rdi, r15
    call cap_scope_admit                  ; nested dispatch cannot widen its caller
    test eax, eax
    jnz  .cap_reject
    cmp  [r12 + sched_job.owner], r14
    jne  .cap_reject
    cmp  [r12 + sched_job.cap_scope], r15
    jne  .cap_reject
    cmp  [r12 + sched_job.required_cap], rbx
    jne  .cap_reject

    lea  rsi, [rsp]
    call .check_callbacks
    test eax, eax
    jnz  .cap_reject
    lea  rsi, [rsp]
    call .capture_nonce_bytes            ; before any workload callback

    ; Reserve a nonzero monotonic identity without wrapping the shared next-id.
    ; UINT64_MAX is terminal, not issuable. A losing CPU must recheck the
    ; observed value before retrying: another CPU may have taken the last id.
    mov  rax, [rel sched_job_next_id]
.id_retry:
    test rax, rax
    jz   .id_exhausted
    cmp  rax, -1
    je   .id_exhausted
    lea  rdx, [rax + 1]
.id_attempt:
    lock cmpxchg qword [rel sched_job_next_id], rdx
    jne  .id_retry
    mov  [rsp], rax                      ; private reservation survives callbacks/nesting
    mov  [r12 + sched_job.id], rax
    mov  dword [r12 + sched_job.state], SJOB_ST_ACCEPTED
    mov  dword [r12 + sched_job.reaped], 0
    call tsc_now
    mov  [r12 + sched_job.tsc_start], rax

    ; Narrow the canonical capability word for exactly this JOB invocation.
    mov  rdi, r15
    call cap_enter_scope
    mov  r13, rax                         ; previous scope to restore on every exit
    mov  rdi, rbx
    call cap_check_gate
    test rax, rax
    jnz  .cap_after_enter

    mov  dword [r12 + sched_job.state], SJOB_ST_RUNNING
    mov  rdi, r12
    mov  rax, [rel job_dispatch_hook]
    test rax, rax
    jnz  .dispatch
    lea  rax, [rel job_dispatch_local]     ; honest pre-init fallback remains local
.dispatch:
    call rax
    mov  [r12 + sched_job.work_result], rax
    mov  rdi, r13
    call cap_leave_scope

    ; The stack/register snapshot is the admitted identity, not mutable
    ; workload metadata. A mismatch fails before the meter or signer runs.
    cmp  [r12 + sched_job.owner], r14
    jne  .meter_fail
    cmp  [r12 + sched_job.cap_scope], r15
    jne  .meter_fail
    cmp  [r12 + sched_job.required_cap], rbx
    jne  .meter_fail
    lea  rsi, [rsp]
    call .check_binding
    test eax, eax
    jnz  .meter_fail
    call tsc_now
    mov  [r12 + sched_job.tsc_end], rax
    mov  dword [r12 + sched_job.state], SJOB_ST_METERING
    mov  rdi, r12
    call qword [rsp + 16]                ; admitted meter, never workload-selected
    test rax, rax
    jnz  .meter_fail
    lea  rsi, [rsp]
    call .check_after_meter
    test eax, eax
    jnz  .meter_fail
    ; Meter-produced artifacts are opaque to the scheduler. Bind the returned
    ; tuple before delivery without imposing a token or receipt grammar here.
    mov  rax, [r12 + sched_job.receipt_body]
    mov  [rsp + 160], rax
    mov  rax, [r12 + sched_job.receipt_len]
    mov  [rsp + 168], rax
    mov  rax, [r12 + sched_job.signature]
    mov  [rsp + 176], rax
    mov  dword [r12 + sched_job.state], SJOB_ST_DONE

    mov  rax, [rsp + 24]                 ; admitted result, including absence
    test rax, rax
    jz   .reap
    mov  rdi, r12
    call rax
    lea  rsi, [rsp]
    call .check_after_meter             ; result callback cannot change returned identity
    test eax, eax
    jnz  .meter_fail
    mov  rax, [rsp + 160]
    cmp  [r12 + sched_job.receipt_body], rax
    jne  .meter_fail
    mov  rax, [rsp + 168]
    cmp  [r12 + sched_job.receipt_len], rax
    jne  .meter_fail
    mov  rax, [rsp + 176]
    cmp  [r12 + sched_job.signature], rax
    jne  .meter_fail
    xor  eax, eax                        ; callback return remains advisory
    jmp  .out
.reap:
    mov  dword [r12 + sched_job.reaped], 1
    xor  eax, eax
    jmp  .out

.id_exhausted:
    ; No reservation, TSC edge, scope entry, work, meter or receipt. A reused
    ; descriptor must not expose its previous successful identity as this JOB.
    mov  qword [r12 + sched_job.id], 0
    jmp  .invalid
.cap_after_enter:
    mov  rdi, r13
    call cap_leave_scope
.cap_reject:
    mov  dword [r12 + sched_job.state], SJOB_ST_REJECTED
    mov  eax, SJOB_ERR_CAP
    jmp  .clear_receipt
.meter_fail:
    ; A failed admitted invocation retains its own reservation and bindings,
    ; not callback-supplied identity. No failed return exposes an old receipt.
    mov  rax, [rsp]
    mov  [r12 + sched_job.id], rax         ; failed work keeps its reserved identity
    mov  [r12 + sched_job.owner], r14
    mov  [r12 + sched_job.cap_scope], r15
    mov  [r12 + sched_job.required_cap], rbx
    mov  rax, [rsp + 8]
    mov  [r12 + sched_job.entry], rax
    mov  rax, [rsp + 16]
    mov  [r12 + sched_job.meter_hook], rax
    mov  rax, [rsp + 24]
    mov  [r12 + sched_job.result_channel], rax
    mov  rax, [rsp + 32]
    mov  [r12 + sched_job.nonce_ptr], rax
    mov  rax, [rsp + 40]
    mov  [r12 + sched_job.nonce_len], rax
    mov  dword [r12 + sched_job.state], SJOB_ST_FAILED
    mov  eax, SJOB_ERR_METER
    jmp  .clear_receipt
.invalid:
    test r12, r12
    jz   .invalid_code
    mov  dword [r12 + sched_job.state], SJOB_ST_REJECTED
    mov  eax, SJOB_ERR_INVALID
    jmp  .clear_receipt
.invalid_code:
    mov  eax, SJOB_ERR_INVALID
    jmp  .out
.clear_receipt:
    call .retire_receipt
.out:
    add  rsp, SJOB_BIND_FRAME_BYTES
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RSI points to this invocation's private frame, including from local calls.
; The descriptor remains caller-owned through synchronous completion. These
; software consistency checks do not isolate arbitrary native memory writes.
.check_after_meter:
    cmp  [r12 + sched_job.owner], r14
    jne  .binding_changed
    cmp  [r12 + sched_job.cap_scope], r15
    jne  .binding_changed
    cmp  [r12 + sched_job.required_cap], rbx
    jne  .binding_changed
.check_binding:
    mov  rax, [rsi]
    cmp  [r12 + sched_job.id], rax
    jne  .binding_changed
.check_callbacks:
    mov  rax, [rsi + 8]
    cmp  [r12 + sched_job.entry], rax
    jne  .binding_changed
    mov  rax, [rsi + 16]
    cmp  [r12 + sched_job.meter_hook], rax
    jne  .binding_changed
    mov  rax, [rsi + 24]
    cmp  [r12 + sched_job.result_channel], rax
    jne  .binding_changed
    ; Compare identity/extent before touching any caller bytes: a callback
    ; may have retargeted the public descriptor to invalid or guarded memory.
    mov  rax, [rsi + 32]
    cmp  [r12 + sched_job.nonce_ptr], rax
    jne  .binding_changed
    mov  rdx, [rsi + 40]
    cmp  [r12 + sched_job.nonce_len], rdx
    jne  .binding_changed
    mov  r8, [rsi + 48]
    xor  ecx, ecx
.nonce_compare:
    cmp  rcx, r8
    jae  .binding_ok
    mov  dl, [rax + rcx]
    cmp  dl, [rsi + rcx + 56]
    jne  .binding_changed
    inc  rcx
    jmp  .nonce_compare
.binding_ok:
    xor  eax, eax
    ret
.capture_nonce_bytes:
    mov  rax, [rsi + 32]
    mov  rdx, [rsi + 40]
    test rax, rax
    jz   .nonce_captured
    test rdx, rdx
    jz   .nonce_captured
    cmp  rdx, SJOB_NONCE_COPY_BYTES - 1
    ja   .nonce_captured
    mov  r8, rax
    add  r8, rdx
    jc   .nonce_captured                 ; meter owns invalid-extent policy
    mov  [rsi + 48], rdx
    xor  ecx, ecx
.nonce_capture:
    mov  r8b, [rax + rcx]
    mov  [rsi + rcx + 56], r8b
    inc  rcx
    cmp  rcx, rdx
    jb   .nonce_capture
.nonce_captured:
    ret
.binding_changed:
    mov  eax, -1
    ret
.retire_receipt:
    mov  qword [r12 + sched_job.receipt_len], 0
    mov  qword [r12 + sched_job.receipt_body], 0
    mov  qword [r12 + sched_job.signature], 0
    ret

; ==========================================================================
; 1330c shared BSP/AP scheduler challenge
;
; Every CPU calls sched_unified_run_one with its dense logical id. Units are
; claimed once, then bound to one of USCHED_TASK_CONTEXTS reusable contexts.
; Dispatch does not refresh watchdog state; only completed work advances the
; generation-bound checkpoint. The first unit is reserved per online CPU so
; the core mask is earned by execution rather than placement accounting.
; ==========================================================================

; EAX=actual online mask, EDI=participant count -> EAX=first real members.
; CPU slots are stable across AP failure; a population count is not a prefix.
sched_unified_online_prefix:
    mov  edx, eax
    xor  eax, eax
    xor  ecx, ecx
.scan:
    test edi, edi
    jz   .done
    cmp  ecx, USCHED_CPU_MAX
    jae  .done
    bt   edx, ecx
    jnc  .next
    bts  eax, ecx
    dec  edi
.next:
    inc  ecx
    jmp  .scan
.done:
    ret

; EDI=logical CPU -> EAX=compact reserved ticket, or -1 when not selected.
; Only the unit index is compacted; accounting and pinning retain CPU identity.
sched_unified_cpu_ticket:
    mov  eax, [rel usched_job_reserved_mask]
    bt   eax, edi
    jnc  .absent
    mov  ecx, edi
    mov  edx, 1
    shl  edx, cl
    dec  edx
    and  eax, edx
    jmp  smp_popcount32
.absent:
    mov  eax, -1
    ret

; EDI=compact reserved ticket -> EAX=its unchanged logical CPU.
sched_unified_ticket_cpu:
    mov  edx, [rel usched_job_reserved_mask]
.next:
    test edx, edx
    jz   .absent
    bsf  eax, edx
    test edi, edi
    jz   .done
    lea  ecx, [rdx - 1]
    and  edx, ecx
    dec  edi
    jmp  .next
.absent:
    mov  eax, -1
.done:
    ret

; sched_unified_bench_begin(EDI=mode, ESI=units) -> EAX=0/-1
sched_unified_bench_begin:
    push rbx
    push r12
    cmp  byte [rel usched_job_active], 0
    jne  .bad                              ; one measured job owns the globals
    cmp  edi, USCHED_MODE_DISPATCH
    je   .mode_ok
    cmp  edi, USCHED_MODE_CONTEXT
    je   .mode_ok
    cmp  edi, USCHED_MODE_PREEMPT
    je   .mode_ok
    cmp  edi, USCHED_MODE_STEAL
    je   .mode_ok
    cmp  edi, USCHED_MODE_COHERENCE
    je   .mode_ok
    cmp  edi, USCHED_MODE_FAULT
    je   .mode_ok
    cmp  edi, USCHED_MODE_TLB
    je   .mode_ok
    cmp  edi, USCHED_MODE_SINGLE
    je   .mode_ok
    cmp  edi, USCHED_MODE_PARALLEL
    je   .mode_ok
    cmp  edi, USCHED_MODE_SOAK
    jne  .bad
.mode_ok:
    mov  ebx, esi                          ; mechanism selftests may clobber ESI
    test esi, esi
    jz   .bad
    cmp  edi, USCHED_MODE_SINGLE
    jb   .legacy_size
    cmp  edi, USCHED_MODE_SINGLE
    je   .scaling_size
    cmp  edi, USCHED_MODE_PARALLEL
    je   .scaling_size
    cmp  esi, USCHED_CAPSTONE_MAX_UNITS
    ja   .bad
    jmp  .size_ok
.scaling_size:
    cmp  esi, USCHED_SCALING_MAX_UNITS
    ja   .bad
    jmp  .size_ok
.legacy_size:
    cmp  esi, USCHED_MAX_UNITS
    ja   .bad
.size_ok:
    mov  [rel usched_job_mode], dil
    mov  [rel usched_job_units], esi
    call smp_coherence_prepare_mode
    test eax, eax
    jz   .bad
    inc  dword [rel usched_job_epoch]
    jnz  .epoch_ok
    inc  dword [rel usched_job_epoch]
.epoch_ok:
    mov  r12d, [rel usched_job_epoch]
    mov  eax, [rel smp_topology_online]
    test eax, eax
    jnz  .online_ok
    mov  eax, 1
.online_ok:
    cmp  eax, ebx
    cmova eax, ebx
    cmp  byte [rel usched_job_mode], USCHED_MODE_SINGLE
    jne  .reserved_ready
    mov  eax, 1                            ; single mode deliberately admits only BSP work
.reserved_ready:
    mov  [rel usched_job_reserved], eax    ; compact unit tickets, unchanged CPU identities
    mov  [rel usched_job_next], eax
    ; Reserve one placement for this job before publishing active. A policy
    ; apply/rollback may run between CPU pulls; changing ticket ownership in
    ; flight duplicates one reserved unit and leaves another unexecuted.
    mov  edi, eax
    call smp_online_mask_now
    test eax, eax
    jnz  .membership_available
    cmp  dword [rel smp_discovered_count], 0
    jne  .bad                              ; never invent an online CPU after discovery
    mov  eax, 1                            ; pre-SMP BSP-only scheduler
.membership_available:
    mov  [rel usched_job_online_mask], eax
    call sched_unified_online_prefix
    mov  [rel usched_job_reserved_mask], eax
    mov  byte [rel usched_job_physical_first], 0
    cmp  byte [rel usched_job_mode], USCHED_MODE_SINGLE
    jbe  .placement_frozen                 ; legacy modes and SINGLE use dense tickets
    cmp  byte [rel sched_smp_policy_profile], SMP_POLICY_PHYSICAL_FIRST
    jne  .placement_frozen
    cmp  byte [rel smp_placement_valid], 1
    jne  .placement_frozen                 ; freeze the effective dense fallback too
    mov  edi, [rel usched_job_reserved]
    call smp_placement_prefix_mask
    mov  [rel usched_job_reserved_mask], eax
    mov  byte [rel usched_job_physical_first], 1
.placement_frozen:
    mov  dword [rel usched_job_completed], 0
    mov  dword [rel usched_job_double_run], 0
    mov  dword [rel usched_job_state_leaks], 0
    cmp  byte [rel usched_job_mode], USCHED_MODE_CONTEXT
    jne  .context_floor_done
    movzx eax, byte [rel sched_context_leaks]
    mov  [rel usched_job_state_leaks], eax
.context_floor_done:
    mov  dword [rel usched_job_core_mask], 0
    mov  dword [rel usched_job_timer_mask], 0
    mov  dword [rel usched_job_migrations], 0
    mov  dword [rel usched_job_steals], 0
    mov  dword [rel usched_cpu_in_run_mask], 0
    mov  dword [rel usched_job_preemptions], 0
    mov  dword [rel usched_job_resched_ipis], 0
    mov  dword [rel usched_job_idle_wakes], 0
    mov  dword [rel usched_job_deadline_miss], 0
    ; A job reports only faults it caused: mode=fault re-ran the concurrent
    ; fault selftest just above (one deliberate #GP per online AP); any other
    ; mode reports 0, never the boot selftest's count (RCQ-27, 15 on the Reatan).
    xor  eax, eax
    cmp  byte [rel usched_job_mode], USCHED_MODE_FAULT
    jne  .job_faults_ready
    mov  eax, [rel smp_faults_last_contained]
.job_faults_ready:
    mov  [rel usched_job_faults_contained], eax
    mov  eax, [rel smp_stale_mapping]
    mov  [rel usched_job_stale_mapping], eax
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_NONE
    mov  rax, [rel e1000e_rx_frames]
    mov  [rel usched_job_host_rx_start], rax
    mov  qword [rel usched_job_host_rx_delta], 0
    mov  qword [rel usched_job_digest], 0
    cld
    lea  rdi, [rel usched_seen]
    xor  eax, eax
    mov  ecx, USCHED_SEEN_QWORDS
    rep  stosq
    lea  rdi, [rel usched_cpu_epoch]
    mov  ecx, USCHED_CPU_MAX / 2
    rep  stosq
    ; Job-local executed work, separated by cache line to avoid adding a
    ; shared counter to the scaling worker. Reset before job publication.
    lea  rdi, [rel usched_job_cpu_units]
    mov  ecx, USCHED_CPU_MAX * 8
    rep  stosq
    lea  rdi, [rel usched_rq_head]
    mov  ecx, USCHED_CPU_MAX
    rep  stosd
    lea  rdi, [rel usched_rq_tail]
    mov  ecx, USCHED_CPU_MAX
    rep  stosd
    ; SMPSTAT steal counters are cumulative observations.  Snapshot them for
    ; job-local invariants, but never clear them: the capstone independently
    ; binds the same job to fresh external before/after per-CPU deltas.
    lea  rsi, [rel usched_steal_in]
    lea  rdi, [rel usched_steal_base_in]
    mov  ecx, USCHED_CPU_MAX
    rep  movsd
    lea  rsi, [rel usched_steal_out]
    lea  rdi, [rel usched_steal_base_out]
    mov  ecx, USCHED_CPU_MAX
    rep  movsd
    ; Only the private deterministic-receiver cursor resets.
    lea  rdi, [rel usched_steal_quota]
    mov  ecx, USCHED_CPU_MAX
    rep  stosd
    lea  rdi, [rel usched_rq_lock]
    mov  ecx, USCHED_CPU_MAX
    rep  stosb
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .queues_ready
    ; Keep own reserved claims out of steal accounting.  The next two tickets
    ; for each AP are distinct queue-0 work and are claimed by that AP below;
    ; this deterministically proves at least three receivers on the Lenovo.
    mov  eax, [rel usched_job_reserved]
    mov  ecx, eax
    dec  ecx
    shl  ecx, 1
    add  eax, ecx
    cmp  eax, [rel usched_job_units]
    cmova eax, [rel usched_job_units]
    mov  [rel usched_rq_head], eax
    mov  [rel usched_job_next], eax
    mov  eax, [rel usched_job_units]
    mov  [rel usched_rq_tail], eax         ; every eligible unit starts on victim queue 0
    mov  eax, [rel usched_job_reserved_mask]
    mov  [rel usched_rq_reserved_mask], eax ; queue-locked front tickets, one per participant
.queues_ready:

    xor  ebx, ebx
.task_init:
    cmp  ebx, USCHED_TASK_CONTEXTS
    jae  .publish
    lea  rax, [rel usched_task_lock]
    mov  byte [rax + rbx], 0
    lea  rax, [rel usched_task_policy]
    mov  dword [rax + rbx*4], WD_POLICY_PROGRESS
    lea  rax, [rel usched_task_generation]
    mov  [rax + rbx*4], r12d
    lea  rax, [rel usched_task_deferred_reap]
    mov  dword [rax + rbx*4], 0
    lea  rax, [rel usched_task_checkpoint]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel usched_task_checkpoint_mirror]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel usched_task_expiry_claim]
    mov  qword [rax + rbx*8], 0
    mov  rdx, [rel timer_ticks]
    add  rdx, 0x100000                     ; dispatch never refreshes this deadline
    lea  rax, [rel usched_task_deadline]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel usched_task_deadline_mirror]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel usched_task_last_cpu]
    mov  dword [rax + rbx*4], -1
    lea  rax, [rel usched_task_pinned_cpu]
    mov  dword [rax + rbx*4], -1
    lea  rax, [rel usched_task_class]
    mov  dword [rax + rbx*4], USCHED_CLASS_NORMAL
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .check_preempt_policy
    cmp  ebx, 2
    jae  .steal_movable
    lea  rax, [rel usched_task_pinned_cpu]
    mov  dword [rax + rbx*4], 0            ; boot and RT pins are absolute
    lea  rax, [rel usched_task_class]
    mov  dword [rax + rbx*4], USCHED_CLASS_RT
    test ebx, ebx
    jnz  .policy_ready
    lea  rax, [rel usched_task_policy]
    mov  dword [rax], WD_POLICY_SYSTEM
    lea  rax, [rel usched_task_class]
    mov  dword [rax], USCHED_CLASS_BOOT
    jmp  .policy_ready
.steal_movable:
    lea  rax, [rel usched_task_last_cpu]
    mov  dword [rax + rbx*4], 0            ; all movable contexts are initially owned by victim 0
    jmp  .policy_ready
.check_preempt_policy:
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .policy_ready
    ; Every admitted CPU has a private context; the derived final slot remains
    ; movable for shared work even at the full 32-logical-CPU capacity.
    cmp  dword [rel usched_job_reserved], USCHED_TASK_CONTEXTS
    jae  .policy_ready
    cmp  ebx, [rel usched_job_reserved]
    jae  .policy_ready
    mov  edi, ebx
    call sched_unified_ticket_cpu
    lea  rdx, [rel usched_task_pinned_cpu]
    mov  [rdx + rbx*4], eax
    lea  rax, [rel usched_task_class]
    mov  dword [rax + rbx*4], USCHED_CLASS_RT
.policy_ready:
    mov  eax, ebx
    inc  rax
    imul rax, rax, 0x1F123BB5
    mov  edx, r12d
    shl  rdx, 32
    xor  rax, rdx
    lea  rdx, [rel usched_task_signature]
    mov  [rdx + rbx*8], rax
    lea  rdx, [rel usched_task_mirror]
    mov  [rdx + rbx*8], rax
    inc  ebx
    jmp  .task_init
.publish:
    cmp  byte [rel usched_job_mode], USCHED_MODE_CONTEXT
    jne  .publish_active
    lea  rdi, [rel usched_context_xstate]
    call sched_xstate_save_ptr
    mov  rax, [rel usched_context_sentinel]
    mov  [rel usched_context_xstate + 400], rax
    mov  qword [rel usched_context_xstate + 408], 0
    cmp  byte [rel sched_xsave_mode], 0
    je   .lane0_header_done
    or   qword [rel usched_context_xstate + 512], 2
.lane0_header_done:
    mov  [rel usched_context_expected], rax
    lea  rdi, [rel usched_context_xstate + SCHED_XSTATE_BYTES]
    call sched_xstate_save_ptr
    mov  rax, [rel usched_context_sentinel + 8]
    mov  [rel usched_context_xstate + SCHED_XSTATE_BYTES + 400], rax
    mov  qword [rel usched_context_xstate + SCHED_XSTATE_BYTES + 408], 0
    cmp  byte [rel sched_xsave_mode], 0
    je   .lane1_header_done
    or   qword [rel usched_context_xstate + SCHED_XSTATE_BYTES + 512], 2
.lane1_header_done:
    mov  [rel usched_context_expected + 8], rax
.publish_active:
    cmp  byte [rel usched_job_mode], USCHED_MODE_SOAK
    jne  .publish_now
    call time_monotonic_now_us
    mov  [rel usched_job_start_us], rax    ; soak release clock is monotonic, never wall time
.publish_now:
    ; Raw diagnostic clock only. Cross-CPU TSC synchronization is not established
    ; by this scheduler; consumers must not turn parallel endpoints into a
    ; qualified duration. Freeze the calibration with this publication too.
    mov  rax, [rel tsc_khz]
    mov  [rel usched_job_native_khz], rax
    call tsc_now
    lfence
    mov  [rel usched_job_native_start_tsc], rax
    mov  byte [rel usched_job_active], 1
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .published
    cmp  dword [rel smp_topology_online], 1
    jbe  .published                         ; one CPU has no remote wake/resched target
    ; START publishes an asynchronous job.  Kick wake/reschedule vectors now,
    ; while all units are still available, so their receive-side counters can
    ; be earned by task progress.  Waiting for the first RESULT poll lets the
    ; 1 kHz timer fleet finish a 257-unit job before either IPI can do work.
    call smp_preempt_send_kicks
.published:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  r12
    pop  rbx
    ret

; Move a negotiated extended-state image through the executing CPU, restoring
; the executor's own SIMD/FPU image before returning.
sched_context_migrate_xstate:
    push rbx
    push r12
    push r13
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    mov  r12d, edi                         ; image lane 0/1
    mov  r13d, esi                         ; completed unit identity
    call usched_context_lock_acquire
    sub  rsp, SCHED_XSTATE_BYTES + 128
    movq rax, xmm15
    mov  [rsp + SCHED_XSTATE_BYTES + 120], rax
    lea  rbx, [rsp + 63]
    and  rbx, -64
    ; XSAVE writes only XSTATE_BV; standard XRSTOR faults on a stale header.
    xor  eax, eax
    mov  [rbx + 512], rax
    mov  [rbx + 520], rax
    mov  [rbx + 528], rax
    mov  [rbx + 536], rax
    mov  [rbx + 544], rax
    mov  [rbx + 552], rax
    mov  [rbx + 560], rax
    mov  [rbx + 568], rax
    mov  rdi, rbx
    call sched_xstate_save_ptr
    mov  eax, r12d
    imul eax, SCHED_XSTATE_BYTES
    lea  rdi, [rel usched_context_xstate]
    add  rdi, rax
    call sched_xstate_restore_ptr
    movq rax, xmm15
    lea  rdx, [rel usched_context_expected]
    cmp  rax, [rdx + r12*8]
    je   .state_ok
    lock inc dword [rel usched_job_state_leaks]
.state_ok:
    rol  rax, 7
    mov  edx, r13d
    shl  rdx, 32
    xor  rax, rdx
    add  rax, 0x4F1BBCDD
    movq xmm15, rax
    lea  rdx, [rel usched_context_expected]
    mov  [rdx + r12*8], rax
    mov  eax, r12d
    imul eax, SCHED_XSTATE_BYTES
    lea  rdi, [rel usched_context_xstate]
    add  rdi, rax
    call sched_xstate_save_ptr
    mov  rdi, rbx
    call sched_xstate_restore_ptr
    movq rax, xmm15
    cmp  rax, [rsp + SCHED_XSTATE_BYTES + 120]
    je   .executor_ok
    lock inc dword [rel usched_job_state_leaks]
.executor_ok:
    mov  rsp, rbp
    sub  rsp, 8
    call usched_context_lock_release
    add  rsp, 8
    pop  rbp
    pop  r13
    pop  r12
    pop  rbx
    ret

; 1330g scaling/soak worker.  The large capstone cannot use a
; one-bit-per-unit image within its 4 KiB budget.  A bounded CAS claims each
; disjoint block exactly once; the commutative digest is therefore independent
; of block order, CPU count and transport nonce.  Compact reserved unit N
; belongs to the Nth selected online CPU. Every participant executes real work.
sched_capstone_run_one:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    xor  eax, eax
    cmp  byte [rel usched_job_active], 1
    jne  .out
    cmp  edi, USCHED_CPU_MAX
    jae  .out
    mov  r12d, edi
    bt   dword [rel usched_job_online_mask], r12d
    jnc  .out
    cmp  byte [rel usched_job_mode], USCHED_MODE_SINGLE
    jne  .cpu_admitted
    test r12d, r12d
    jnz  .out                              ; the BSP is the only single-mode executor
.cpu_admitted:
    lock bts dword [rel usched_cpu_in_run_mask], r12d
    jc   .out

    ; First execution in an epoch is this CPU's job-selected reserved claim.
    ; Balanced preserves dense logical order. Physical-first consumes the
    ; predecessor's topology rank (distinct cores before SMT siblings), while
    ; the execution mask still records every unchanged logical CPU identity.
    mov  edi, r12d
    call sched_unified_cpu_ticket
    mov  r13d, eax
    cmp  byte [rel usched_job_physical_first], 1
    jne  .placement_ready
    lea  rax, [rel cpu_placement_rank]
    mov  r13d, [rax + r12*4]
.placement_ready:
    cmp  r13d, [rel usched_job_reserved]
    jae  .shared
    mov  ebx, [rel usched_job_epoch]
    lea  rdx, [rel usched_cpu_epoch]
    mov  eax, [rdx + r12*4]
    cmp  eax, ebx
    je   .shared
    lock cmpxchg [rdx + r12*4], ebx
    jne  .shared
    mov  ebp, r13d
    inc  ebp
    jmp  .work

.shared:
    mov  r11d, [rel usched_job_units]
    cmp  byte [rel usched_job_mode], USCHED_MODE_SOAK
    jne  .claim
    ; Keep the job alive for its requested number of seconds.  Reserved CPU
    ; witnesses are immediate; thereafter exactly one unit becomes eligible
    ; per elapsed second. The driver also requires the full requested duration:
    ; immediate reserved witnesses must not shorten a 600-second soak.
    call time_monotonic_now_us
    sub  rax, [rel usched_job_start_us]
    jc   .no_work                         ; regressed/unavailable clock releases no future unit
    xor  edx, edx
    mov  ecx, 1000000
    div  rcx
    ; Clamp elapsed seconds at full width before adding the small reservation.
    ; Narrowing first can wrap a large valid age back into an early release.
    cmp  rax, r11
    jae  .claim                           ; the full job is eligible, R11D already holds units
    add  eax, [rel usched_job_reserved]
    cmp  eax, r11d
    cmova eax, r11d
    mov  r11d, eax                         ; exclusive currently eligible limit
.claim:
    lea  rdx, [rel usched_job_next]
.claim_retry:
    mov  eax, [rdx]
    cmp  eax, r11d
    jae  .no_work
    mov  ecx, eax
    add  ecx, USCHED_CAPSTONE_BLOCK
    cmp  ecx, r11d
    cmova ecx, r11d
    lock cmpxchg [rdx], ecx
    jne  .claim_retry
    mov  r13d, eax
    mov  ebp, ecx

.work:
    ; CPU-local block interval, including interruptions/accounting, excluding
    ; the AP outer-loop pause and host polling. No scheduling authority.
    call tsc_now
    lfence
    push rax
    xor  r14, r14                          ; block-local order-independent digest
    xor  r15d, r15d
.unit:
    cmp  r13d, ebp
    jae  .account
    mov  eax, r13d
    inc  rax
    imul rax, rax, 0x5BD1E995
    mov  rdx, rax
    mov  ecx, USCHED_CAPSTONE_MIX_ROUNDS
.mix:
    imul rax, rax, 0x27D4EB2D
    add  rax, 0x6D2B79F5
    xor  rax, rdx
    rol  rax, 17
    add  rdx, 0x1F123BB5
    dec  ecx
    jnz  .mix
    ; The mix above is mode-neutral timed work.  The externally recomputed
    ; digest retains the shipped scheduler formula exactly across all modes.
    mov  eax, r13d
    inc  rax
    imul rax, rax, 0x1F123BB5
    mov  rdx, rax
    shl  rdx, 32
    xor  rax, rdx
    xor  r14, rax
    inc  r15d
    inc  r13d
    jmp  .unit
.account:
    lock xor qword [rel usched_job_digest], r14
    lock bts dword [rel usched_job_core_mask], r12d
    ; This CPU holds its in-run bit. Publish its completed block before the
    ; existing terminal completion counter makes the result visible.
    mov  ecx, r12d
    shl  ecx, 6
    lea  rax, [rel usched_job_cpu_units]
    add  [rax + rcx], r15d
    lfence
    call tsc_now
    lea  rdx, [rel usched_job_cpu_units]
    mov  [rdx + rcx + 16], rax             ; last block endpoint, raw CPU-local TSC
    pop  r8                               ; this block's CPU-local origin
    sub  rax, r8
    add  [rdx + rcx + 8], rax              ; ticks accumulated in this CPU's blocks
    ; Publish timing before completion, just like digest/core/CPU-unit counts.
    ; No later snapshot/replay can borrow a later epoch's live timings.
    lock add dword [rel usched_job_completed], r15d ; after digest/core/CPU units
    lea  rax, [rel cpu_context_switch_count]
    inc  qword [rax + r12*8]
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    lea  rdx, [rel cpu_last_progress_tsc]
    mov  [rdx + r12*8], rax
    mov  eax, 1
    jmp  .release

.no_work:
    cmp  byte [rel usched_job_mode], USCHED_MODE_SOAK
    jne  .idle
    ; The time gate controls accounting, not stress.  Keep every AP exercising
    ; integer state between releases while each scheduler quantum remains
    ; bounded so NIC/STATUS and watchdog safe frames continue to run.
    ; An AP with interrupts on churns for 3/4 ms of its own TSC (most of its
    ; 1 ms tick), checking the clock, job and epoch every 256 steps, then
    ; yields; the timer, IPIs and smp_scheduler_tick's polled workers still run
    ; within one quantum. The BSP (its quantum is the resident service sweep),
    ; interrupts off or an uncalibrated TSC keep the fixed 2048 steps.
    mov  eax, [rel usched_job_epoch]
    xor  eax, r12d
    mov  ecx, 2048
    test r12d, r12d
    jz   .churn
    pushfq
    pop  rdx
    test edx, 0x200
    jz   .churn
    mov  r8, [rel tsc_khz]
    test r8, r8
    jz   .churn
    cmp  r8, USCHED_SOAK_CHURN_KHZ_MAX
    jbe  .churn_budget
    mov  r8d, USCHED_SOAK_CHURN_KHZ_MAX
.churn_budget:
    lea  r8, [r8 + r8*2]
    shr  r8, 2                             ; TSC ticks in 3/4 ms
    mov  r10d, [rel usched_job_epoch]
    mov  r11d, USCHED_SOAK_CHURN_BLOCKS
    mov  r9, rax                           ; churn state; rdtsc takes RAX/RDX
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xchg rax, r9                           ; R9 = this CPU's start TSC
.churn_block:
    mov  ecx, 256
.churn_step:
    imul rax, rax, 0x27D4EB2D
    add  rax, 0x6D2B79F5
    rol  rax, 11
    dec  ecx
    jnz  .churn_step
    cmp  byte [rel usched_job_active], 1
    jne  .idle
    cmp  r10d, [rel usched_job_epoch]
    jne  .idle
    dec  r11d
    jz   .idle
    mov  rcx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, r9                           ; unsigned: a backward TSC ends the churn
    xchg rax, rcx
    cmp  rcx, r8
    jb   .churn_block
    jmp  .idle
.churn:
    imul rax, rax, 0x27D4EB2D
    add  rax, 0x6D2B79F5
    rol  rax, 11
    dec  ecx
    jnz  .churn
.idle:
    xor  eax, eax
.release:
    lock btr dword [rel usched_cpu_in_run_mask], r12d
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; One bounded turn of the existing finite SOAK worker in resident BSP context.
; Call only at the resident BSP safe frame after service/return owners unwind.
; EAX=1: a live finite SOAK quantum ran; repeat the service sweep without HLT.
; EAX=0: ordinary idle policy. No slot, nonce, authority or retirement changes.
sched_unified_soak_bsp_service:
    push rbx
    xor ebx, ebx
    pushfq
    pop rax
    test eax, 0x200
    jz .done
    cmp byte [rel usched_job_active], 1
    jne .done
    cmp byte [rel usched_job_mode], USCHED_MODE_SOAK
    jne .done
    call time_monotonic_now_us
    test rax, rax
    jz .done
    cmp rax, [rel usched_job_start_us]
    jb .done
    sub rax, [rel usched_job_start_us]
    mov ecx, [rel usched_job_units]
    imul rcx, rcx, 1000000
    cmp rax, rcx
    jae .done
    xor edi, edi
    call sched_unified_run_one
    mov ebx, 1
.done:
    mov eax, ebx
    pop rbx
    ret

; sched_unified_run_one(EDI=dense logical CPU) -> EAX=1 unit, 0 no unit.
sched_unified_run_one:
    mov  al, [rel usched_job_mode]
    cmp  al, USCHED_MODE_SINGLE
    jae  sched_capstone_run_one
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi                              ; local victim queue id survives helper calls
    xor  eax, eax
    cmp  byte [rel usched_job_active], 1
    jne  .out
    cmp  edi, USCHED_CPU_MAX
    jae  .out
    mov  r12d, edi
    bt   dword [rel usched_job_online_mask], r12d
    jnc  .out
    mov  dword [rsp], edi
    lock bts dword [rel usched_cpu_in_run_mask], r12d
    jc   .out                              ; an IRQ cannot re-enter this CPU's scheduler frame
    mov  r14d, [rel usched_job_epoch]
    lea  rax, [rel usched_cpu_epoch]
    mov  eax, [rax + r12*4]
    cmp  eax, r14d
    je   .shared_claim
    lea  rdx, [rel usched_cpu_epoch]
    lock cmpxchg [rdx + r12*4], r14d
    jne  .shared_claim
    mov  edi, r12d
    call sched_unified_cpu_ticket
    mov  r13d, eax                         ; compact unit rank in frozen real membership
    cmp  r13d, [rel usched_job_reserved]
    jae  .shared_claim
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .claimed
    xor  edi, edi
    call usched_rq_lock_acquire
    btr  dword [rel usched_rq_reserved_mask], r12d
    jnc  .reserved_missing
    xor  edi, edi
    call usched_rq_lock_release
    mov  [rsp], r12d                       ; own reserved ticket is not a steal
    jmp  .claimed
.reserved_missing:
    xor  edi, edi
    call usched_rq_lock_release
    jmp  .shared_claim
.shared_claim:
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .shared_global
    ; Each AP earns two real migrations from victim queue 0 after completing
    ; its own reserved ticket.  These units are outside [0,reserved), map to
    ; distinct initially-victim-owned task contexts, and therefore cannot be
    ; mistaken for own-reservation completion.
    mov  edi, r12d
    call sched_unified_cpu_ticket
    test eax, eax
    jz   .victim_setup                     ; BSP owns queue 0
    cmp  eax, [rel usched_job_reserved]
    jae  .victim_setup
    mov  r8d, eax                          ; compact receiver rank, not CPU identity
    lea  rdx, [rel usched_steal_quota]
    mov  eax, [rdx + r12*4]
    cmp  eax, 2
    jae  .victim_setup
    inc  dword [rdx + r12*4]              ; CPU-owned under in-run exclusion
    mov  ecx, r8d
    dec  ecx
    shl  ecx, 1
    add  ecx, [rel usched_job_reserved]
    add  ecx, eax
    cmp  ecx, [rel usched_job_units]
    jae  .victim_setup
    mov  r13d, ecx
    mov  dword [rsp], 0                    ; actual source is victim queue 0
    jmp  .claimed
.victim_setup:
    ; Victims are visited in ascending dense-logical order. Only one canonical
    ; queue lock is ever held, and it is released before any task lock, so the
    ; total order is explicit and cannot form an ABBA cycle. The scan is capped
    ; at the live CPU count; an idle pass never polls indefinitely.
    xor  r10d, r10d
    mov  r11d, [rel smp_topology_online]
    test r11d, r11d
    jnz  .victim_count_live
    mov  r11d, 1
.victim_count_live:
    cmp  r11d, USCHED_CPU_MAX
    jbe  .victim_scan
    mov  r11d, USCHED_CPU_MAX
.victim_scan:
    cmp  r10d, r11d
    jae  .no_work
    mov  edi, r10d
    mov  esi, r11d
    call sched_smp_policy_victim_cpu
    mov  r9d, eax
    mov  edi, r9d
    call usched_rq_lock_acquire
    lea  rdx, [rel usched_rq_head]
    mov  eax, [rdx + r9*4]
    lea  rcx, [rel usched_rq_tail]
    cmp  eax, [rcx + r9*4]
    jae  .victim_empty
    lea  ecx, [eax + 1]
    mov  [rdx + r9*4], ecx
    mov  [rel usched_job_next], ecx        ; queue 0 owns this mode's complete range
    mov  r13d, eax
    mov  [rsp], r9d
    mov  edi, r9d
    call usched_rq_lock_release
    jmp  .claimed
.victim_empty:
    mov  edi, r9d
    call usched_rq_lock_release
    inc  r10d
    jmp  .victim_scan
.shared_global:
    ; Bounded CAS keeps the externally reported next cursor exact. A fetch-add
    ; lets losing CPUs push it beyond units after the final claim, obscuring
    ; whether work was lost or merely over-claimed.
    lea  rdx, [rel usched_job_next]
.shared_retry:
    mov  eax, [rdx]
    cmp  eax, [rel usched_job_units]
    jae  .no_work
    lea  ecx, [eax + 1]
    lock cmpxchg [rdx], ecx
    jne  .shared_retry
    mov  r13d, eax
.claimed:
    lock bts qword [rel usched_seen], r13
    jnc  .first
    lock inc dword [rel usched_job_double_run]
    jmp  .no_work
.first:
    ; Reserved units execute on their frozen selected CPUs. Steal mode uses
    ; disjoint bounded context ranges so reservations cannot pre-consume a context
    ; whose queue-0 transition must later earn migration credit.
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .check_preempt_task_select
    mov  eax, r13d
    cmp  eax, [rel usched_job_reserved]
    jae  .steal_nonreserved_context
    ; Reserved executions have a private range [2, 2+N).  They may establish
    ; CPU-local ownership, but can never consume a context whose later
    ; queue-0 transition is supposed to earn steal credit.
    mov  r15d, eax
    add  r15d, 2
    jmp  .task_selected
.steal_nonreserved_context:
    sub  eax, [rel usched_job_reserved]
    mov  ecx, [rel usched_job_reserved]
    dec  ecx
    shl  ecx, 1
    cmp  eax, ecx
    jae  .steal_tail_context
    ; The deterministic two-ticket/AP range gets one initially-victim-owned
    ; context per ticket.  At N=32 the highest index is 95, exactly inside the
    ; 96-context bound above.
    mov  r15d, [rel usched_job_reserved]
    add  r15d, 2
    add  r15d, eax
    jmp  .task_selected
.steal_tail_context:
    ; Any ordinary tail work remains bounded and reusable; it is not part of
    ; the deterministic two-steals-per-AP witness.
    mov  eax, r13d
    xor  edx, edx
    mov  ecx, USCHED_TASK_CONTEXTS - 2
    div  ecx
    mov  r15d, edx
    add  r15d, 2
    jmp  .task_selected
.check_preempt_task_select:
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .legacy_task_select
    mov  eax, [rel usched_job_reserved]
    cmp  eax, USCHED_TASK_CONTEXTS
    jae  .no_work                          ; impossible under the enforced CPU bound
    cmp  r13d, eax
    jae  .preempt_movable
    mov  r15d, r13d
    jmp  .task_selected
.preempt_movable:
    mov  ecx, USCHED_TASK_CONTEXTS
    sub  ecx, eax
    mov  eax, r13d
    xor  edx, edx
    div  ecx
    mov  r15d, [rel usched_job_reserved]
    add  r15d, edx
    jmp  .task_selected
.legacy_task_select:
    xor  r15d, r15d
    mov  eax, [rel smp_topology_online]
    cmp  r13d, eax
    jb   .task_selected
    mov  eax, r13d
    xor  edx, edx
    mov  ecx, USCHED_TASK_CONTEXTS
    div  ecx
    mov  r15d, edx
.task_selected:
    mov  edi, r15d
    call usched_task_lock_acquire

    xor  ebp, ebp
    lea  rax, [rel usched_task_pinned_cpu]
    mov  ecx, [rax + r15*4]
    cmp  ecx, -1
    je   .pin_ok
    cmp  ecx, r12d
    je   .pin_ok
    lock inc dword [rel usched_job_state_leaks]
    mov  edi, r15d
    call usched_task_lock_release
    jmp  .no_work
.pin_ok:
    lea  rax, [rel usched_task_generation]
    cmp  [rax + r15*4], r14d
    sete bpl
    lea  rax, [rel usched_task_policy]
    cmp  dword [rax + r15*4], WD_POLICY_PROGRESS
    sete bl
    and  bpl, bl
    lea  rax, [rel usched_task_expiry_claim]
    cmp  qword [rax + r15*8], 0
    sete bl
    and  bpl, bl
    lea  rax, [rel usched_task_deferred_reap]
    cmp  dword [rax + r15*4], 0
    sete bl
    and  bpl, bl
    lea  rax, [rel usched_task_deadline]
    mov  rdx, [rax + r15*8]
    lea  rax, [rel usched_task_deadline_mirror]
    cmp  [rax + r15*8], rdx               ; dispatch/migration must not refresh deadline
    sete bl
    and  bpl, bl
    lea  rax, [rel usched_task_checkpoint]
    mov  rdx, [rax + r15*8]
    lea  rax, [rel usched_task_checkpoint_mirror]
    cmp  [rax + r15*8], rdx               ; prior explicit progress must survive exactly
    sete bl
    and  bpl, bl
    cmp  byte [rel usched_job_mode], USCHED_MODE_CONTEXT
    jne  .xstate_ok
    mov  edi, r15d
    and  edi, 1
    mov  esi, r13d
    call sched_context_migrate_xstate
.xstate_ok:
    lea  rax, [rel usched_task_signature]
    mov  rdx, [rax + r15*8]
    lea  rax, [rel usched_task_mirror]
    cmp  [rax + r15*8], rdx
    sete bl
    and  bpl, bl
    test bpl, bpl
    jnz  .context_ok
    lock inc dword [rel usched_job_state_leaks]
.context_ok:
    xor  ebp, ebp                          ; credit steals only with a real migration
    lea  rax, [rel usched_task_last_cpu]
    mov  ecx, [rax + r15*4]
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .compare_last_cpu
    cmp  r13d, [rel usched_job_reserved]
    jae  .compare_last_cpu
    jmp  .record_cpu                       ; own reserved ticket is not a migration
.compare_last_cpu:
    cmp  ecx, -1
    je   .record_cpu
    cmp  ecx, r12d
    je   .record_cpu
    lea  rdx, [rel usched_task_pinned_cpu]
    cmp  dword [rdx + r15*4], -1
    jne  .pin_migration_violation
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .count_migration
    mov  ecx, [rsp]
    cmp  ecx, r12d
    je   .record_cpu                       ; owner re-run is local, not a migration/steal
.count_migration:
    lock inc dword [rel usched_job_migrations]
    lea  rdx, [rel cpu_migration_count]
    inc  qword [rdx + r12*8]
    mov  ebp, 1
    jmp  .record_cpu
.pin_migration_violation:
    lock inc dword [rel usched_job_state_leaks]
    mov  edi, r15d
    call usched_task_lock_release
    jmp  .no_work
.record_cpu:
    mov  [rax + r15*4], r12d
    lea  rax, [rel usched_task_checkpoint]
    inc  qword [rax + r15*8]               ; explicit completed progress only
    lea  rax, [rel usched_task_checkpoint_mirror]
    inc  qword [rax + r15*8]
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .deadline_ok
    lea  rax, [rel usched_task_deadline]
    mov  rax, [rax + r15*8]
    cmp  [rel timer_ticks], rax
    jbe  .deadline_ok
    lock inc dword [rel usched_job_deadline_miss]
.deadline_ok:
    mov  rax, rdx
    rol  rax, 13
    xor  rax, r13
    add  rax, 0x51ED270B
    lea  rdx, [rel usched_task_signature]
    mov  [rdx + r15*8], rax
    lea  rdx, [rel usched_task_mirror]
    mov  [rdx + r15*8], rax
    mov  edi, r15d
    call usched_task_lock_release

    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .account_unit
    mov  ecx, [rsp]
    cmp  ecx, r12d
    je   .account_unit
    test ebp, ebp
    jz   .account_unit                     ; remote dequeue without migration is not credited
    ; The per-CPU ledgers are the durable event record.  The terminal job total
    ; is derived from their matched deltas after every completion is visible,
    ; avoiding a fourth independently updated counter at this hot boundary.
    lea  rax, [rel usched_steal_in]
    lock inc dword [rax + r12*4]
    lea  rax, [rel usched_steal_out]
    lock inc dword [rax + rcx*4]

.account_unit:
    mov  eax, r13d
    inc  rax
    imul rax, rax, 0x1F123BB5
    mov  rdx, rax
    shl  rdx, 32
    xor  rax, rdx
    lock xor qword [rel usched_job_digest], rax
    lock bts dword [rel usched_job_core_mask], r12d
    mov  ecx, r12d
    shl  ecx, 6
    lea  rax, [rel usched_job_cpu_units]
    inc  dword [rax + rcx]
    lock inc dword [rel usched_job_completed]
    lea  rax, [rel cpu_context_switch_count]
    inc  qword [rax + r12*8]
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    lea  rdx, [rel cpu_last_progress_tsc]
    mov  [rdx + r12*8], rax
    mov  eax, 1
    jmp  .release_out
.no_work:
    xor  eax, eax
.release_out:
    lock btr dword [rel usched_cpu_in_run_mask], r12d
.out:
    pop  rdi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EAX = bounded poll budget scaled to the live topology.  TCG schedules larger
; vCPU sets serially enough that the former fixed 200 ms window expired before
; otherwise-online peers could earn their reserved claims.  Scaling from the
; authoritative online count retains a 250 ms floor and caps naturally at the
; enforced 32-CPU capacity (8 s per barrier).  The wider full-capacity window
; covers TCG's late post-PMOD replay after every vCPU and device are active;
; bare-metal exits immediately once the measured membership mask is complete.
sched_unified_wait_budget:
    mov  eax, [rel smp_topology_online]
    test eax, eax
    jnz  .have_count
    mov  eax, 1
.have_count:
    imul eax, USCHED_WAIT_STEPS_PER_CPU
    cmp  eax, 5000
    jae  .ready
    mov  eax, 5000
.ready:
    ret

; BSP joins the same scheduler, then waits for the exact reserved CPU set to
; earn its per-CPU claims.  Waiting for merely "any AP" is racy under QEMU's
; vCPU timeslicing: the BSP can exhaust its bounded local drive loop before the
; remaining APs are scheduled, leaving their reserved units incomplete.  The
; participant count is min(online, units), so tiny jobs retain a bounded
; single-CPU degradation while ordinary scheduler challenges bind every online
; CPU to actual execution.
sched_unified_bench_drive:
    push rbx
    push r12
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_NONE
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .join
    mov  r12d, [rel usched_job_reserved_mask]
    mov  eax, [rel usched_job_timer_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .timer_edges_ready
    ; UDP command dispatch can run with IF clear. In that state a local timer
    ; cannot win while RESULT is draining work. Return pending first so the
    ; interrupt frame can run; otherwise BSP progress consumes every unit and
    ; permanently strands the required CPU0 timer witness.
    pushfq
    pop  rax
    test eax, (1 << 9)
    jz   .pending_if_clear
    call sched_unified_wait_budget
    cmp  eax, 20000                        ; preserve the existing 1 s timer floor
    jae  .timer_budget_ready
    mov  eax, 20000
.timer_budget_ready:
    mov  ebx, eax
.wait_timer_edges:
    mov  eax, [rel usched_job_timer_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .timer_edges_ready
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_timer_edges
    jmp  .pending_timer                    ; never drain work without every timer witness
.timer_edges_ready:
    cmp  dword [rel smp_topology_online], 1
    jbe  .join                              ; no peer exists for resched/idle IPIs
    call smp_preempt_send_kicks
    call sched_unified_wait_budget
    mov  ebx, eax
.wait_preempt_edges:
    cmp  dword [rel usched_job_resched_ipis], 0
    je   .preempt_wait
    cmp  dword [rel usched_job_idle_wakes], 0
    jne  .join
.preempt_wait:
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_preempt_edges
    jmp  .pending_ipi
.join:
    xor  edi, edi
    call sched_unified_run_one
    mov  r12d, [rel usched_job_reserved_mask] ; same frozen placement as the claims
    ; Parallel RESULT must yield to the resident service loop without waiting
    ; for a descheduled AP. Its reserved ticket remains exclusively that AP's;
    ; exact completion below cannot succeed until every unit really ran.
    cmp  byte [rel usched_job_mode], USCHED_MODE_PARALLEL
    je   .drive
    call sched_unified_wait_budget
    mov  ebx, eax                          ; bounded topology-scaled participant window
.wait_reserved:
    mov  eax, [rel usched_job_core_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .reserved_ready
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_reserved
.reserved_ready:
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .drive
    ; The deterministic imbalance layout owns two non-reserved queue-0 tickets
    ; per AP.  Do not let the BSP drain the ordinary tail until those tickets
    ; have completed and earned observable steal-in deltas.  Own reserved
    ; claims precede this barrier and therefore cannot satisfy it.
    mov  eax, [rel usched_job_reserved]
    mov  ecx, eax
    dec  ecx
    shl  ecx, 1
    add  eax, ecx
    cmp  eax, [rel usched_job_units]
    ja   .drive                            ; tiny jobs have no full two-ticket/AP contract
    call sched_unified_wait_budget
    mov  ebx, eax                          ; bounded topology-scaled receiver window
.wait_steal_receivers:
    mov  ecx, 1                            ; CPU0 owns the victim queue
.check_steal_receiver:
    cmp  ecx, USCHED_CPU_MAX
    jae  .drive
    bt   dword [rel usched_job_reserved_mask], ecx
    jnc  .next_steal_receiver
    lea  rdx, [rel usched_steal_in]
    mov  eax, [rdx + rcx*4]
    lea  rdx, [rel usched_steal_base_in]
    sub  eax, [rdx + rcx*4]
    cmp  eax, 2
    jb   .steal_receiver_pending
.next_steal_receiver:
    inc  ecx
    jmp  .check_steal_receiver
.steal_receiver_pending:
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_steal_receivers
.drive:
    mov  ebx, USCHED_MAX_UNITS * 4
    cmp  byte [rel usched_job_mode], USCHED_MODE_SINGLE
    jb   .loop
    ; Preserve the full drain for existing single/soak sizes. Parallel polls
    ; execute real bounded work, then expose actual progress while APs continue on
    ; the existing scheduler rail. No synthetic pending reply or time gate.
    mov  ebx, (USCHED_CAPSTONE_MAX_UNITS / USCHED_CAPSTONE_BLOCK) + USCHED_CPU_MAX
    cmp  byte [rel usched_job_mode], USCHED_MODE_SINGLE
    jne  .parallel_budget
    cmp  dword [rel usched_job_units], USCHED_CAPSTONE_MAX_UNITS
    jbe  .loop
    ; More useful work must not turn one RESULT into a fourfold full drain.
    ; Execute real blocks then return actual progress under the same deadline.
    mov  ebx, USCHED_LONG_SINGLE_POLL_BLOCKS
    jmp  .loop
.parallel_budget:
    cmp  byte [rel usched_job_mode], USCHED_MODE_PARALLEL
    jne  .loop
    mov  ebx, USCHED_PARALLEL_POLL_BLOCKS
.loop:
    mov  eax, [rel usched_job_completed]
    cmp  eax, [rel usched_job_units]
    jae  .check
    xor  edi, edi
    call sched_unified_run_one
    test eax, eax
    jnz  .next
    ; A time-gated SOAK has no eligible unit until the next release. Return
    ; pending instead of repeating the entire capstone budget's idle churn
    ; inside RESULT. AP scheduler quanta keep exercising the unchanged worker.
    cmp  byte [rel usched_job_mode], USCHED_MODE_SOAK
    je   .check
    pause
.next:
    dec  ebx
    jnz  .loop
.check:
    xor  eax, eax
    mov  ecx, [rel usched_job_completed]
    cmp  ecx, [rel usched_job_units]
    jne  .pending_incomplete
    cmp  dword [rel usched_job_double_run], 0
    jne  .pending_double_run
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    jne  .exact
    mov  edx, [rel usched_job_timer_mask]
    and  edx, r12d
    cmp  edx, r12d
    jne  .pending_timer
.exact:
    cmp  byte [rel usched_job_mode], USCHED_MODE_SOAK
    jne  .finalize
    ; Reserved witnesses are immediate, so exact work can precede the requested
    ; duration (600 units on 32 CPUs are all eligible at 568 s). Keep the job
    ; active and AP churn running until every requested monotonic second passed.
    ; A pending RESULT returns immediately; never busy-wait inside the command.
    call time_monotonic_now_us
    cmp  rax, [rel usched_job_start_us]
    jb   .pending_incomplete               ; unavailable/backward time earns no duration
    sub  rax, [rel usched_job_start_us]
    mov  ecx, [rel usched_job_units]
    imul rcx, rcx, 1000000                 ; full range needs more than 32 bits
    cmp  rax, rcx
    jb   .pending_incomplete
.finalize:
    call sched_steal_finalize
    mov  eax, 1                            ; exact completion; caller grades spread
    jmp  .done
.pending_if_clear:
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_IF_CLEAR
    jmp  .pending
.pending_timer:
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_TIMER_MASK
    jmp  .pending
.pending_ipi:
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_IPI_ACK
    jmp  .pending
.pending_incomplete:
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_INCOMPLETE
    jmp  .pending
.pending_double_run:
    mov  byte [rel usched_job_pending_reason], USCHED_PENDING_DOUBLE_RUN
.pending:
    xor  eax, eax
.done:
    pop  r12
    pop  rbx
    ret

; Finalize the imbalance job from the cumulative per-CPU event ledger.  The
; host independently takes the same before/after SMPSTAT deltas.  Refuse to
; publish a claim when inbound, outbound, and real-migration totals differ.
sched_steal_finalize:
    cmp  byte [rel usched_job_mode], USCHED_MODE_STEAL
    jne  .not_steal
    push rbx
    push r12
    push r13
    xor  ebx, ebx                          ; inbound delta total
    xor  r12d, r12d                        ; outbound delta total
    xor  r13d, r13d
.sum:
    cmp  r13d, USCHED_CPU_MAX
    jae  .sum_done
    lea  rax, [rel usched_steal_in]
    mov  ecx, [rax + r13*4]
    lea  rax, [rel usched_steal_base_in]
    sub  ecx, [rax + r13*4]
    add  ebx, ecx
    lea  rax, [rel usched_steal_out]
    mov  ecx, [rax + r13*4]
    lea  rax, [rel usched_steal_base_out]
    sub  ecx, [rax + r13*4]
    add  r12d, ecx
    inc  r13d
    jmp  .sum
.sum_done:
    xor  eax, eax                          ; fail closed: zero is not a steal claim
    cmp  ebx, r12d
    jne  .publish
    cmp  ebx, [rel usched_job_migrations]
    jne  .publish
    mov  eax, ebx
.publish:
    mov  [rel usched_job_steals], eax
    pop  r13
    pop  r12
    pop  rbx
.not_steal:
    ret

; Count claimed unit bits without assuming POPCNT support. A refused claim can
; make seen differ from completed, so pending telemetry must report both.
sched_unified_seen_count:
    push rbx
    push r12
    xor  ebx, ebx
    xor  r12d, r12d
.word:
    cmp  r12d, USCHED_SEEN_QWORDS
    jae  .done
    lea  rdx, [rel usched_seen]
    mov  rax, [rdx + r12*8]
.bit:
    test rax, rax
    jz   .next
    lea  rdx, [rax - 1]
    and  rax, rdx
    inc  ebx
    jmp  .bit
.next:
    inc  r12d
    jmp  .word
.done:
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; The boot marker uses the same timer/IPI path and benchmark state as UDP.
; The watchdog KAT proves both serialized race outcomes: a checkpoint that
; moves the deadline wins before expiry, while an earned generation claim
; rejects later checkpoints and is reaped only from a scheduler-owned frame.
sched_preempt_boot_selftest:
    push rbx
    push r12
    xor  ebx, ebx
    mov  edi, USCHED_MODE_PREEMPT
    ; Each admitted CPU can earn one timer claim, one idle-wake claim, and one
    ; reschedule-IPI claim before the BSP grades the job.  The old fixed 33
    ; units covered the shipped eight-CPU ceiling but let a 16+ CPU timer fleet
    ; exhaust all work before either required IPI class could be observed.
    ; Scale the bounded KAT from authoritative online membership; at the
    ; enforced 32-CPU capacity this is only 97 units.
    mov  esi, [rel smp_topology_online]
    test esi, esi
    jnz  .preempt_units_have_cpus
    mov  esi, 1
.preempt_units_have_cpus:
    cmp  esi, USCHED_CPU_MAX
    jbe  .preempt_units_bounded
    mov  esi, USCHED_CPU_MAX
.preempt_units_bounded:
    lea  esi, [rsi + rsi*2 + 1]
    call sched_unified_bench_begin
    test eax, eax
    jnz  .fail
    call sched_unified_bench_drive
    test eax, eax
    jz   .fail
    cmp  dword [rel usched_job_preemptions], 0
    je   .fail
    cmp  dword [rel smp_topology_online], 1
    jbe  .ipi_degenerate
    cmp  dword [rel usched_job_resched_ipis], 0
    je   .fail
    cmp  dword [rel usched_job_idle_wakes], 0
    je   .fail
.ipi_degenerate:
    cmp  dword [rel usched_job_state_leaks], 0
    jne  .fail
    mov  eax, [rel usched_job_reserved_mask]
    mov  edx, [rel usched_job_timer_mask]
    and  edx, eax
    cmp  edx, eax
    jne  .fail

    xor  ebx, ebx
.find_watchdog_slot:
    inc  ebx
    cmp  ebx, TASK_MAX
    jae  .fail
    cmp  ebx, [rel sched_cur]
    je   .find_watchdog_slot
    mov  eax, ebx
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    cmp  dword [r8 + task.state], TASK_FREE
    jne  .find_watchdog_slot
    mov  eax, [r8 + task.generation]
    inc  eax
    jnz  .watchdog_generation_ready
    inc  eax
.watchdog_generation_ready:
    mov  r12d, eax
    mov  [r8 + task.generation], eax
    mov  dword [r8 + task.wd_policy], WD_POLICY_PROGRESS
    mov  dword [r8 + task.deferred_reap], 0
    mov  qword [r8 + task.expiry_claim], 0
    mov  qword [r8 + task.checkpoint_epoch], 1
    mov  rdx, [rel timer_ticks]
    add  rdx, 100000
    mov  [r8 + task.deadline], rdx
    mov  dword [r8 + task.state], TASK_READY

    ; Checkpoint wins the lock first: the old deadline may not reap this task.
    mov  edi, ebx
    mov  esi, r12d
    mov  rdx, [rel timer_ticks]
    add  rdx, 200000
    mov  ecx, 2
    call sched_watchdog_checkpoint
    test eax, eax
    jnz  .fail
    mov  edi, ebx
    mov  esi, r12d
    mov  rdx, [rel timer_ticks]
    add  rdx, 100000
    call sched_watchdog_claim_expiry
    test eax, eax
    jz   .fail

    ; Once the moved deadline has elapsed, exactly one generation claim wins.
    mov  edi, ebx
    mov  esi, r12d
    mov  rdx, [rel timer_ticks]
    add  rdx, 300000
    call sched_watchdog_claim_expiry
    test eax, eax
    jnz  .fail
    mov  edi, ebx
    mov  esi, r12d
    xor  edx, edx
    call sched_watchdog_claim_expiry
    test eax, eax
    jz   .fail
    mov  edi, ebx
    mov  esi, r12d
    mov  rdx, [rel timer_ticks]
    add  rdx, 100
    mov  ecx, 2
    call sched_watchdog_checkpoint
    test eax, eax
    jz   .fail
    mov  edi, ebx
    mov  esi, r12d
    call sched_watchdog_deferred_reap
    test eax, eax
    jnz  .fail
    cmp  byte [rel sched_preempt_report_post_pmod], 1
    je   .post_pmod_ok
    lea  rdi, [rel str_sched_preempt_ok]
    call serial_string
    jmp  .success
.post_pmod_ok:
    lea  rdi, [rel str_sched_preempt_post_pmod_ok]
    call serial_string
.success:
    mov  byte [rel usched_job_active], 0
    mov  eax, 1
    pop  r12
    pop  rbx
    ret
.fail:
    mov  byte [rel usched_job_active], 0
    cmp  ebx, 1
    jb   .fail_report
    cmp  ebx, TASK_MAX
    jae  .fail_report
    mov  eax, ebx
    imul eax, task_size
    lea  r8, [rel sched_tasks]
    add  r8, rax
    mov  dword [r8 + task.state], TASK_FREE
.fail_report:
    cmp  byte [rel sched_preempt_report_post_pmod], 1
    je   .post_pmod_fail
    lea  rdi, [rel str_sched_preempt_fail]
    jmp  .emit_fail
.post_pmod_fail:
    lea  rdi, [rel str_sched_preempt_post_pmod_fail]
.emit_fail:
    call serial_string
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

; A PMOD timer restore arms sched_preempt_post_pmod_request.  Preserve that
; request here: replaying the full boot benchmark inside this boot frame races
; 32 TCG vCPUs for the shared scheduler job and can report a spurious late SMP
; failure after the topology/capstone work already completed.  If PMOD degraded
; before taking the timer lease, restore_seq remains zero and there is no
; post-PMOD timer state to prove; the already-earned boot timer/IPI KAT remains
; authoritative.  An attempted bad restore still leaves state 3 and is
; reported fail-closed by the normal scheduler poll path.
sched_preempt_post_pmod_selftest:
    mov  byte [rel sched_preempt_post_pmod_last_ok], 0
    movzx eax, byte [rel sched_preempt_post_pmod_pending]
    test eax, eax
    jnz  .armed_or_failed
    cmp  dword [rel smp_timer_restore_seq], 0
    jne  .restore_request_missing
    mov  eax, 1                          ; no borrower: boot KAT already owns proof
    ret
.restore_request_missing:
    call sched_preempt_post_pmod_request
    movzx eax, byte [rel sched_preempt_post_pmod_pending]
.armed_or_failed:
    cmp  eax, 3
    jne  .armed
    xor  eax, eax
    ret
.armed:
    mov  eax, 1
    ret

; Runtime PMOD executes inside the UDP receive/reply frame.  Do not replay the
; boot KAT here: it creates temporary tasks and watchdog generations and is not
; re-entrant with a live command frame.  Instead, arm a two-part runtime KAT.
; A real BSP timer interrupt earns state 2; a later normal scheduler-loop frame
; must then complete a reschedule IPI on the selected CPU.  This binds success
; to the restored timer and affinity/IPI paths without touching reply staging.
sched_preempt_post_pmod_request:
    mov  byte [rel sched_preempt_post_pmod_last_ok], 0
    mov  byte [rel sched_preempt_post_pmod_fail_stage], 0
    cmp  byte [rel smp_timer_restore_ok], 1
    jne  .restore_bad
    mov  byte [rel sched_preempt_post_pmod_pending], 1
    ret
.restore_bad:
    mov  byte [rel sched_preempt_post_pmod_fail_stage], 1
    mov  byte [rel sched_preempt_post_pmod_pending], 3
    ret

; Called from the timer ISR after cpu_irq_count[0] has advanced.  It is strictly
; measurement-only on the interrupt stack; task/IPI work remains deferred.
sched_preempt_post_pmod_tick:
    test edi, edi                         ; only the BSP owns PMOD's timer lease
    jnz  .out
    cmp  byte [rel sched_preempt_post_pmod_pending], 1
    jne  .out
    mov  rax, [rel cpu_irq_count]
    cmp  rax, [rel smp_timer_irq0_before]
    jbe  .failed
    mov  rax, [rel cpu_preempt_count]
    cmp  rax, [rel smp_timer_preempt0_before]
    jb   .failed
    mov  al, 1
    mov  dl, 2
    lock cmpxchg byte [rel sched_preempt_post_pmod_pending], dl
    ret
.failed:
    mov  byte [rel sched_preempt_post_pmod_fail_stage], 2
    mov  al, 1
    mov  dl, 3
    lock cmpxchg byte [rel sched_preempt_post_pmod_pending], dl
.out:
    ret

; Settled checks producer (BOOTCLOCK v5, report-only). EAX=1 when the deferred
; runtime-PMOD KAT ran and passed, 2 when nothing is deferred (no request and no
; pass), else 0: armed, claimed or failed (state 3 never counts as done).
sched_preempt_post_pmod_settle_state:
    movzx eax, byte [rel sched_preempt_post_pmod_pending]
    test eax, eax
    jnz  .pending
    movzx eax, byte [rel sched_preempt_post_pmod_last_ok]
    test eax, eax
    jnz  .passed
    mov  eax, 2
    ret
.passed:
    mov  eax, 1
    ret
.pending:
    xor  eax, eax
    ret

; Complete the runtime KAT only from a normal scheduler-owned frame.  State 4
; is the private claim value; it prevents a second main-loop observer from
; issuing a duplicate affinity IPI while the first is in flight.
sched_preempt_post_pmod_poll:
    cmp  byte [rel sched_preempt_post_pmod_pending], 0
    jne  .pending
    ret
.pending:
    cmp  byte [rel usched_job_active], 0
    jne  .out
    cmp  byte [rel sched_preempt_post_pmod_pending], 3
    je   .report_fail
    cmp  byte [rel sched_preempt_post_pmod_pending], 2
    jne  .out
    mov  al, 2
    mov  dl, 4
    lock cmpxchg byte [rel sched_preempt_post_pmod_pending], dl
    jne  .out
    push rbx
    xor  ebx, ebx
    ; Firmware discovery includes APs intentionally left offline by HP Phase-0
    ; and failed startup rows. Probe an actually ONLINE AP, or the live BSP
    ; when none exists, as the boot KAT's single-CPU degradation does.
    mov  ecx, 1
    lea  rdx, [rel cpu_state]
.find_online_target:
    cmp  ecx, [rel smp_discovered_count]
    jae  .target_ready
    cmp  ecx, USCHED_CPU_MAX
    jae  .target_ready
    cmp  byte [rdx + rcx], CPU_STATE_ONLINE
    je   .online_target
    inc  ecx
    jmp  .find_online_target
.online_target:
    mov  ebx, ecx
.target_ready:
    mov  edi, ebx
    call sched_affinity_probe_execute
    cmp  eax, ebx
    jne  .claimed_fail
    mov  byte [rel sched_preempt_post_pmod_last_ok], 1
    mov  byte [rel sched_preempt_post_pmod_pending], 0
    lea  rdi, [rel str_sched_preempt_post_pmod_ok]
    call serial_string
    pop  rbx
    jmp  .out
.claimed_fail:
    mov  byte [rel sched_preempt_post_pmod_fail_stage], 3
    mov  byte [rel sched_preempt_post_pmod_pending], 3
    pop  rbx
.report_fail:
    mov  al, 3
    xor  dl, dl
    lock cmpxchg byte [rel sched_preempt_post_pmod_pending], dl
    jne  .out
    mov  byte [rel sched_preempt_post_pmod_last_ok], 0
    movzx eax, byte [rel sched_preempt_post_pmod_fail_stage]
    cmp  eax, 1
    je   .report_restore_fail
    cmp  eax, 2
    je   .report_timer_fail
    cmp  eax, 3
    je   .report_affinity_fail
    lea  rdi, [rel str_sched_preempt_post_pmod_fail]
    jmp  .emit_report_fail
.report_restore_fail:
    lea  rdi, [rel str_sched_preempt_post_pmod_restore_fail]
    jmp  .emit_report_fail
.report_timer_fail:
    lea  rdi, [rel str_sched_preempt_post_pmod_timer_fail]
    jmp  .emit_report_fail
.report_affinity_fail:
    lea  rdi, [rel str_sched_preempt_post_pmod_affinity_fail]
.emit_report_fail:
    call serial_string
.out:
    ret

; Boot/QEMU marker is earned by the same live scheduler used by UDP.
sched_unified_boot_selftest:
    mov  edi, USCHED_MODE_CONTEXT
    mov  esi, 33
    call sched_unified_bench_begin
    test eax, eax
    jnz  .fail_begin
    call sched_unified_bench_drive
    test eax, eax
    jz   .fail_drive
    cmp  dword [rel smp_topology_online], 1
    jbe  .single_cpu
    mov  eax, [rel usched_job_core_mask]
    mov  ecx, eax
    dec  ecx
    and  eax, ecx
    jz   .fail_cores
    cmp  dword [rel usched_job_state_leaks], 0
    jne  .fail_leak
    cmp  dword [rel usched_job_migrations], 0
    je   .fail_migration
    jmp  .common
.single_cpu:
    cmp  dword [rel usched_job_core_mask], 1
    jne  .fail_cores
    cmp  dword [rel usched_job_migrations], 0
    jne  .fail_migration
.common:
    cmp  dword [rel usched_job_state_leaks], 0
    jne  .fail_leak
    cmp  qword [rel usched_job_digest], 0
    je   .fail_digest
    lea  rdi, [rel str_sched_unified_ok]
    call serial_string
    mov  byte [rel usched_job_active], 0
    mov  eax, 1
    ret
.fail_begin:
    lea  rdi, [rel str_sched_unified_fail_begin]
    jmp  .report_fail
.fail_drive:
    lea  rdi, [rel str_sched_unified_fail_drive]
    jmp  .report_fail
.fail_cores:
    lea  rdi, [rel str_sched_unified_fail_cores]
    jmp  .report_fail
.fail_leak:
    lea  rdi, [rel str_sched_unified_fail_leak]
    jmp  .report_fail
.fail_migration:
    lea  rdi, [rel str_sched_unified_fail_migration]
    jmp  .report_fail
.fail_digest:
    lea  rdi, [rel str_sched_unified_fail_digest]
.report_fail:
    call serial_string
.fail:
    mov  byte [rel usched_job_active], 0
    xor  eax, eax
    ret

; The boot marker and the UDP imbalance mode share the exact victim queue and
; execution path.  Own reserved tickets never count; only a completed remote
; dequeue that actually migrates its movable task context earns steal credit.
sched_balance_boot_selftest:
    push rbx
    push r12
    mov  edi, USCHED_MODE_STEAL
    ; The fixture reserves one unit per admitted CPU and two additional
    ; queue-0 tickets per AP.  Derive the bounded workload from the live MADT
    ; membership so the full-capacity case does not retain the old 65-unit
    ; ceiling (32 + 2*31 = 94 required units).
    mov  esi, [rel smp_topology_online]
    test esi, esi
    jnz  .units_have_cpus
    mov  esi, 1
.units_have_cpus:
    cmp  esi, USCHED_CPU_MAX
    jbe  .units_bounded
    mov  esi, USCHED_CPU_MAX
.units_bounded:
    lea  esi, [rsi + rsi*2]               ; 3*N >= N + 2*(N-1)
    mov  r12d, esi                         ; exact completion target
    call sched_unified_bench_begin
    test eax, eax
    jnz  .fail
    call sched_unified_bench_drive
    test eax, eax
    jz   .fail
    cmp  dword [rel usched_job_state_leaks], 0
    jne  .fail
    cmp  dword [rel usched_job_double_run], 0
    jne  .fail
    cmp  dword [rel usched_job_completed], r12d
    jne  .fail
    mov  eax, [rel usched_rq_head]
    cmp  eax, [rel usched_rq_tail]
    jne  .fail
    cmp  dword [rel usched_rq_reserved_mask], 0
    jne  .fail

    ; Slots 0/1 model the immutable boot and RT pins. No unit maps to them and
    ; their execution identity, pin and class must remain unchanged.
    cmp  dword [rel usched_task_last_cpu], -1
    jne  .fail
    cmp  dword [rel usched_task_last_cpu + 4], -1
    jne  .fail
    cmp  dword [rel usched_task_pinned_cpu], 0
    jne  .fail
    cmp  dword [rel usched_task_pinned_cpu + 4], 0
    jne  .fail
    cmp  dword [rel usched_task_class], USCHED_CLASS_BOOT
    jne  .fail
    cmp  dword [rel usched_task_class + 4], USCHED_CLASS_RT
    jne  .fail

    xor  ebx, ebx
    xor  r12d, r12d
    xor  edx, edx
.sum:
    cmp  ebx, USCHED_CPU_MAX
    jae  .sum_done
    lea  rax, [rel usched_steal_in]
    mov  ecx, [rax + rbx*4]
    lea  rax, [rel usched_steal_base_in]
    sub  ecx, [rax + rbx*4]
    add  r12d, ecx
    lea  rax, [rel usched_steal_out]
    mov  ecx, [rax + rbx*4]
    lea  rax, [rel usched_steal_base_out]
    sub  ecx, [rax + rbx*4]
    add  edx, ecx
    inc  ebx
    jmp  .sum
.sum_done:
    cmp  r12d, [rel usched_job_steals]
    jne  .fail
    cmp  edx, [rel usched_job_steals]
    jne  .fail
    mov  eax, [rel usched_steal_out]
    sub  eax, [rel usched_steal_base_out]
    cmp  eax, [rel usched_job_steals]
    jne  .fail                           ; queue 0 is the only declared victim
    cmp  dword [rel smp_topology_online], 1
    jbe  .single
    cmp  dword [rel usched_job_steals], 0
    je   .fail
    mov  eax, [rel usched_job_migrations]
    cmp  eax, [rel usched_job_steals]
    jne  .fail                            ; migration and steal credit are paired one-for-one
    mov  ebx, 1
.receiver_delta:
    cmp  ebx, USCHED_CPU_MAX
    jae  .receiver_delta_done
    bt   dword [rel usched_job_reserved_mask], ebx
    jnc  .receiver_delta_next
    lea  rax, [rel usched_steal_in]
    mov  ecx, [rax + rbx*4]
    lea  rax, [rel usched_steal_base_in]
    sub  ecx, [rax + rbx*4]
    cmp  ecx, 2
    jb   .fail                            ; every AP completed two real queue-0 steals
.receiver_delta_next:
    inc  ebx
    jmp  .receiver_delta
.receiver_delta_done:
    mov  eax, [rel usched_job_core_mask]
    mov  ecx, eax
    dec  ecx
    and  eax, ecx
    jz   .fail
    jmp  .pass
.single:
    cmp  dword [rel usched_job_steals], 0
    jne  .fail
    cmp  dword [rel usched_job_migrations], 0
    jne  .fail
.pass:
    lea  rdi, [rel str_sched_balance_ok]
    call serial_string
    mov  byte [rel usched_job_active], 0
    mov  eax, 1
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_sched_balance_fail]
    call serial_string
    mov  byte [rel usched_job_active], 0
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

; Two context challenge tasks. Distinct GPR, stack-local and XMM15 sentinels
; must survive a complete trip through the other task.
sched_task_a:
    mov  r12, [rel sched_task_a_sentinel]
    mov  rax, r12
    movq xmm15, rax
    sub  rsp, 8
    mov  [rsp], r12
.loop:
    call sched_yield
    cmp  r12, [rel sched_task_a_sentinel]
    jne  .leak
    cmp  [rsp], r12
    jne  .leak
    movq rax, xmm15
    cmp  rax, r12
    jne  .leak
    mov  byte [rel sched_flag_a], 1
    jmp  .loop
.leak:
    mov  byte [rel sched_context_leaks], 1
    jmp  .loop
sched_task_b:
    mov  r12, [rel sched_task_b_sentinel]
    mov  rax, r12
    movq xmm15, rax
    sub  rsp, 8
    mov  [rsp], r12
.loop:
    call sched_yield
    cmp  r12, [rel sched_task_b_sentinel]
    jne  .leak
    cmp  [rsp], r12
    jne  .leak
    movq rax, xmm15
    cmp  rax, r12
    jne  .leak
    mov  byte [rel sched_flag_b], 1
    jmp  .loop
.leak:
    mov  byte [rel sched_context_leaks], 1
    jmp  .loop

; Read-only boot witness of the negotiated extended-state contract: mode, XCR0
; mask, image size and who enabled OSXSAVE (none/firmware/paos). No state is
; changed; the line is emitted whether the later scheduler selftest passes.
sched_xstate_report:
    push rbx
    sub  rsp, 96
    mov  rdi, rsp
    lea  rsi, [rel str_sched_xstate_mode]
    call .copy
    movzx eax, byte [rel sched_xsave_mode]
    add  al, '0'
    stosb
    lea  rsi, [rel str_sched_xstate_mask]
    call .copy
    mov  edx, [rel sched_xsave_mask_hi]
    shl  rdx, 32
    mov  eax, [rel sched_xsave_mask_lo]
    or   rdx, rax
    mov  ecx, 16
.hex:
    rol  rdx, 4
    mov  eax, edx
    and  eax, 15
    add  eax, '0'
    cmp  eax, '9'
    jbe  .hex_digit
    add  eax, 'a' - '9' - 1
.hex_digit:
    stosb
    dec  ecx
    jnz  .hex
    lea  rsi, [rel str_sched_xstate_size]
    call .copy
    mov  eax, [rel sched_xstate_size]
    mov  ebx, 10
    xor  ecx, ecx
.div:
    xor  edx, edx
    div  ebx
    push rdx
    inc  ecx
    test eax, eax
    jnz  .div
.dec:
    pop  rax
    add  al, '0'
    stosb
    dec  ecx
    jnz  .dec
    lea  rsi, [rel str_sched_xstate_none]
    cmp  byte [rel sched_xsave_enable], 1
    jb   .source
    lea  rsi, [rel str_sched_xstate_firmware]
    je   .source
    lea  rsi, [rel str_sched_xstate_paos]
.source:
    call .copy
    mov  dword [rdi], 0x000A0D
    mov  rdi, rsp
    call serial_string
    add  rsp, 96
    pop  rbx
    ret
.copy:
    lodsb
    test al, al
    jz   .copied
    stosb
    jmp  .copy
.copied:
    ret

; sched_selftest — spawn 2 tasks, yield, confirm both ran
sched_selftest:
    call sched_init
    call sched_xstate_report
    mov  byte [rel sched_flag_a], 0
    mov  byte [rel sched_flag_b], 0
    mov  byte [rel sched_context_leaks], 0
    lea  rdi, [rel sched_task_a]
    call sched_spawn
    lea  rdi, [rel sched_task_b]
    call sched_spawn
    call sched_yield                       ; main -> A -> B -> main (both run once)
    call sched_yield
    call sched_yield
    cmp  byte [rel sched_flag_a], 1
    jne  .fail
    cmp  byte [rel sched_flag_b], 1
    jne  .fail
    cmp  byte [rel sched_context_leaks], 0
    jne  .fail
    lea  rdi, [rel str_sched_ok]
    call serial_string
    call sched_spawn_kat                    ; TOURNAMENT 1418 v3: KAT + fault battery
    ret
.fail:
    lea  rdi, [rel str_sched_fail]
    call serial_string
    ret

; ============================================================================
; sched_spawn_kat (TOURNAMENT 1418, durability class) — snapshots the LIVE task
; table + sched_cur, drives the shipped sched_spawn through a fixed known-answer
; test (KAT) and a FIXED T=3 hostile fault battery, CONTENT-checks every result
; (correct return, exact 56-byte frame, exact task.* fields, overrun canary
; intact — never merely "did not crash"), then restores the table byte-for-byte
; so the real boot tasks (task 0 + demo A/B) are undisturbed. Emits its own
; markers; the marker fires ONLY on a full pass, so a wrong-output variant can
; never carry it. Preserves rbx, r12-r15.
;
; Fault battery (fixed for sched_spawn — same 3 vectors for every variant + the
; baseline; the fault surface is genuinely 3, so T=3 is honest, not padded):
;   F1  NULL entry (rdi=0)      -> must return -1 AND consume no slot
;   F2  table full (all ready)  -> must return -1 AND not overrun the table
;                                  (24-byte 0xA5 canary immediately past the
;                                   table stays intact)
;   F3  only final slot free    -> must return TASK_MAX-1 (scan boundary)
; ============================================================================
sched_spawn_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Snapshot the three live boot tasks. Later slots are known-free at this
    ; boot-only KAT and are republished FREE during restore.
    lea  rsi, [rel sched_tasks]
    lea  rdi, [rel sched_kat_save]
    mov  ecx, 3 * task_size
.snap:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .snap
    mov  eax, [rel sched_cur]
    mov  [rel sched_kat_cur], eax

    ; ===================== KAT: correctness =====================
    call sched_kat_zero_table              ; empty table

    ; V1: empty -> slot 0, frame + fields exact
    lea  rdi, [rel sched_task_a]
    call sched_spawn
    cmp  eax, 0
    jne  .kat_fail
    lea  rbx, [rel sched_tasks]            ; slot 0
    cmp  dword [rbx + task.state], 1
    jne  .kat_fail
    cmp  dword [rbx + task.id], 0
    jne  .kat_fail
    cmp  dword [rbx + task.principal], PRIN_OWNER_TASK
    jne  .kat_fail
    mov  r8, [rbx + task.rsp]              ; frame pointer
    lea  rax, [rel sched_task_a]
    cmp  [r8 + 128], rax                   ; ret target == entry
    jne  .kat_fail
    cmp  qword [r8 + 0], 0                 ; r15..rbx zeroed
    jne  .kat_fail
    cmp  qword [r8 + 112], 0
    jne  .kat_fail

    ; V2: -> slot 1, id 1, entry propagated
    lea  rdi, [rel sched_task_b]
    call sched_spawn
    cmp  eax, 1
    jne  .kat_fail
    lea  rbx, [rel sched_tasks + task_size] ; slot 1
    cmp  dword [rbx + task.state], 1
    jne  .kat_fail
    cmp  dword [rbx + task.id], 1
    jne  .kat_fail
    mov  r8, [rbx + task.rsp]
    lea  rax, [rel sched_task_b]
    cmp  [r8 + 128], rax
    jne  .kat_fail

    lea  rdi, [rel str_ss_kat]             ; KAT marker (only on full pass)
    call serial_string
    jmp  .fault_battery
.kat_fail:
    lea  rdi, [rel str_ss_katfail]
    call serial_string

    ; ===================== FAULT BATTERY (T=3) =====================
.fault_battery:
    xor  r14d, r14d                        ; r14 = contained count

    ; --- F1: NULL entry -> -1, no slot consumed ---
    call sched_kat_zero_table
    xor  edi, edi
    call sched_spawn
    cmp  eax, -1
    jne  .f1_done
    lea  rbx, [rel sched_tasks]
    mov  ecx, TASK_MAX
.f1_scan:
    cmp  dword [rbx + task.state], 0       ; every slot must still be free
    jne  .f1_done
    add  rbx, task_size
    dec  ecx
    jnz  .f1_scan
    inc  r14d
.f1_done:

    ; --- F2: table full -> -1, 24-byte canary past the table intact ---
    call sched_kat_fill_table              ; all 8 slots ready
    call sched_kat_arm_guard               ; 0xA5 sentinel into sched_guard[0..23]
    lea  rdi, [rel sched_task_a]
    call sched_spawn
    cmp  eax, -1
    jne  .f2_done
    lea  rbx, [rel sched_guard]
    mov  ecx, 24
.f2_scan:
    cmp  byte [rbx], 0xA5                  ; nothing written one slot past the end
    jne  .f2_done
    inc  rbx
    dec  ecx
    jnz  .f2_scan
    inc  r14d
.f2_done:

    ; --- F3: only final slot free -> returns TASK_MAX-1 (scan boundary) ---
    call sched_kat_fill_table
    lea  rbx, [rel sched_tasks + (TASK_MAX-1)*task_size]
    mov  dword [rbx + task.state], 0       ; free slot 7 only
    lea  rdi, [rel sched_task_a]
    call sched_spawn
    cmp  eax, TASK_MAX-1
    jne  .f3_done
    inc  r14d
.f3_done:

    ; --- observability: always print the contained count ---
    lea  rdi, [rel str_ss_fpfx]
    call serial_string
    mov  rdi, r14
    lea  rsi, [rel sched_katbuf]
    call fmt_dec
    lea  rdi, [rel sched_katbuf]
    call serial_string
    lea  rdi, [rel str_ss_fsfx]
    call serial_string

    ; --- gated marker: fires only when ALL 3 vectors were contained ---
    cmp  r14d, 3
    jne  .restore
    lea  rdi, [rel str_ss_fault]
    call serial_string

    ; ===================== restore live table + sched_cur =====================
.restore:
    lea  rsi, [rel sched_kat_save]
    lea  rdi, [rel sched_tasks]
    mov  ecx, 3 * task_size
.rest:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .rest
    lea  rbx, [rel sched_tasks + 3*task_size]
    mov  ecx, TASK_MAX - 3
.rest_free:
    mov  dword [rbx + task.state], TASK_FREE
    add  rbx, task_size
    dec  ecx
    jnz  .rest_free
    mov  eax, [rel sched_kat_cur]
    mov  [rel sched_cur], eax

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- KAT table helpers (operate on the LIVE table; caller snapshots/restores) ---
sched_kat_zero_table:
    lea  rax, [rel sched_tasks]
    mov  ecx, TASK_MAX * task_size
.z:
    mov  byte [rax], 0
    inc  rax
    dec  ecx
    jnz  .z
    ret
sched_kat_fill_table:
    lea  rax, [rel sched_tasks]
    mov  ecx, TASK_MAX
.f:
    mov  dword [rax + task.state], 1
    add  rax, task_size
    dec  ecx
    jnz  .f
    ret
sched_kat_arm_guard:
    lea  rax, [rel sched_guard]
    mov  ecx, 24
.g:
    mov  byte [rax], 0xA5
    inc  rax
    dec  ecx
    jnz  .g
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_sched 0
align 64
sched_cur:    dd 0
sched_flag_a: db 0
sched_flag_b: db 0
sched_context_leaks: db 0
sched_kat_cur: dd 0
align 64
sched_tasks:  times (TASK_MAX * task_size) db 0
sched_guard:  times 24 db 0                ; overrun canary — MUST sit right after the table
align 64
sched_kat_save: times (3 * task_size) db 0
sched_katbuf:   times 24 db 0              ; fmt_dec scratch
align 8
sched_job_next_id: dq 1                    ; bounded CAS allocator; UINT64_MAX terminal
job_owner_lookup_hook: dq 0               ; trusted L5 registry callback, bound once
job_dispatch_hook: dq 0                    ; populated with runtime VA by sched_init
sched_xsave_mask_lo: dd 3
sched_xsave_mask_hi: dd 0
sched_xstate_size:   dd 512
sched_xsave_mode:   db 0
sched_xsave_enable: db 0                   ; 0 none, 1 firmware, 2 PaOS set OSXSAVE
sched_task_lock:    db 0

; Task1330j scheduling-policy transaction. The lock covers every field below;
; readers that need a coherent receipt run on the command thread after commit.
align 8
sched_interactive_epoch: dq 0
sched_interactive_serviced: dq 0
sched_interactive_snapshot: dq 0
sched_interactive_recent_until: dq 0
sched_interactive_fair_at: dq 0
sched_interactive_pressure: dd 0
sched_interactive_live: db 0
sched_smp_policy_lock: db 0
sched_smp_policy_profile: db SMP_POLICY_BALANCED
sched_smp_policy_previous_profile: db SMP_POLICY_BALANCED
sched_smp_policy_rollback_from_profile: db SMP_POLICY_BALANCED
sched_smp_policy_last_valid: db 0
sched_smp_policy_last_operation: db 0
sched_smp_policy_last_requested_profile: db SMP_POLICY_BALANCED
sched_smp_policy_auto_rollback: db 0
sched_smp_policy_last_rolled_back: db 0
sched_smp_policy_test_force_health_bad: db 0
align 4
sched_smp_policy_generation: dd 1
sched_smp_policy_previous_generation: dd 1
sched_smp_policy_rollback_from_generation: dd 1
sched_smp_policy_last_requested_generation: dd 0
sched_smp_policy_audit_seq: dd 0
sched_smp_policy_last_audit: dd 0
sched_smp_policy_online_before: dd 0
sched_smp_policy_online_after: dd 0
align 8
sched_smp_policy_last_request: dq 0

align 8
usched_job_digest:      dq 0
usched_job_units:       dd 0
usched_job_reserved:    dd 0
usched_job_next:        dd 0
usched_job_completed:   dd 0
usched_job_double_run:  dd 0
usched_job_state_leaks: dd 0
usched_job_core_mask:   dd 0
usched_job_timer_mask:  dd 0
usched_job_migrations:  dd 0
usched_job_steals:      dd 0
usched_job_preemptions: dd 0
usched_job_resched_ipis: dd 0
usched_job_idle_wakes:  dd 0
usched_job_deadline_miss: dd 0
usched_job_faults_contained: dd 0
usched_job_stale_mapping: dd 0
sched_affinity_probe_pending: dd 0
sched_affinity_probe_target:  dd -1
sched_affinity_probe_actual:  dd -1
align 8
sched_affinity_probe_start:    dq 0
sched_affinity_probe_latency:  dq 0
usched_job_epoch:       dd 0
usched_job_mode:        db 0
usched_job_active:      db 0
usched_job_pending_reason: db USCHED_PENDING_NONE
usched_job_physical_first: db 0            ; effective placement frozen before active
usched_job_reserved_mask: dd 0            ; frozen selected logical CPU identities
usched_job_online_mask: dd 0              ; frozen runnable CPUs, including shared executors
times 52 db 0                  ; membership uses padding; later WDATA offsets unchanged
usched_task_last_cpu: times USCHED_TASK_CONTEXTS dd -1
usched_task_pinned_cpu: times USCHED_TASK_CONTEXTS dd -1
times 60 db 0                  ; usched_task_class..usched_context_expected moved to WDATA_sched_bss2: keeps the labels below at their offset mod 64
usched_context_sentinel: dq 0xA55A1330C001C0DE, 0x5AA51330C002C0DE
sched_task_a_sentinel: dq 0x13579BDF2468ACE0
sched_task_b_sentinel: dq 0x0F1E2D3C4B5A6978
%endmacro
WDATA_DEFER WDATA_sched
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_sched_bss1 0
resb 23                 ; keeps sched_watchdog_scan_pending at its WDATA offset mod 64
sched_watchdog_scan_pending: resb 1
sched_preempt_report_post_pmod: resb 1
sched_preempt_post_pmod_pending: resb 1
sched_preempt_post_pmod_last_ok: resb 1
sched_preempt_post_pmod_fail_stage: resb 1 ; 1=restore, 2=timer progress, 3=affinity IPI
alignb 8
usched_cpu_in_run_mask: resd 1
usched_job_host_rx_start: resq 1
usched_job_host_rx_delta: resq 1
usched_job_start_us:      resq 1
usched_job_native_start_tsc: resq 1
usched_job_native_khz: resq 1
sched_watchdog_claims: resq 1
sched_watchdog_reaps: resq 1
usched_seen: resq USCHED_SEEN_QWORDS
usched_cpu_epoch: resd USCHED_CPU_MAX
usched_task_lock: resb USCHED_TASK_CONTEXTS
usched_context_lock: resb 1
usched_rq_lock: resb USCHED_CPU_MAX
alignb 4
usched_rq_head: resd USCHED_CPU_MAX
usched_rq_tail: resd USCHED_CPU_MAX
usched_rq_reserved_mask: resd 1
usched_steal_quota: resd USCHED_CPU_MAX
usched_steal_base_in: resd USCHED_CPU_MAX
usched_steal_base_out: resd USCHED_CPU_MAX
usched_steal_in: resd USCHED_CPU_MAX
usched_steal_out: resd USCHED_CPU_MAX
usched_task_policy: resd USCHED_TASK_CONTEXTS
usched_task_generation: resd USCHED_TASK_CONTEXTS
usched_task_deferred_reap: resd USCHED_TASK_CONTEXTS
%endmacro
WDATA_BSS_DEFER WDATA_sched_bss1
%macro WDATA_sched_bss2 0
resb 20                 ; keeps usched_task_class at its WDATA offset mod 64
usched_task_class: resd USCHED_TASK_CONTEXTS
alignb 8
usched_task_deadline: resq USCHED_TASK_CONTEXTS
usched_task_deadline_mirror: resq USCHED_TASK_CONTEXTS
usched_task_checkpoint: resq USCHED_TASK_CONTEXTS
usched_task_checkpoint_mirror: resq USCHED_TASK_CONTEXTS
usched_task_expiry_claim: resq USCHED_TASK_CONTEXTS
usched_task_signature: resq USCHED_TASK_CONTEXTS
usched_task_mirror: resq USCHED_TASK_CONTEXTS
alignb 64
usched_context_xstate: resb (2 * SCHED_XSTATE_BYTES)
usched_context_expected: resq 2
%endmacro
WDATA_BSS_DEFER WDATA_sched_bss2
str_sched_ok:   db "[PAOS64] M1 sched: 2 tasks ran via cooperative yield/switch", 13, 10, 0
str_sched_fail: db "[PAOS64] M1 sched: context switch FAILED", 13, 10, 0
str_sched_xstate_mode: db "[PAOS64] sched xstate: mode=", 0
str_sched_xstate_mask: db " mask=0x", 0
str_sched_xstate_size: db " size=", 0
str_sched_xstate_none: db " enable=none", 0
str_sched_xstate_firmware: db " enable=firmware", 0
str_sched_xstate_paos: db " enable=paos", 0
str_sched_unified_ok: db "[PAOS64] SMP scheduler: unified context selftest PASS [smp.scheduler.unified.ok]", 13, 10, 0
str_sched_unified_fail_begin: db "[PAOS64] SMP scheduler: unified context selftest FAIL stage=begin", 13, 10, 0
str_sched_unified_fail_drive: db "[PAOS64] SMP scheduler: unified context selftest FAIL stage=drive", 13, 10, 0
str_sched_unified_fail_cores: db "[PAOS64] SMP scheduler: unified context selftest FAIL stage=cpu_spread", 13, 10, 0
str_sched_unified_fail_leak: db "[PAOS64] SMP scheduler: unified context selftest FAIL stage=state_leak", 13, 10, 0
str_sched_unified_fail_migration: db "[PAOS64] SMP scheduler: unified context selftest FAIL stage=migration", 13, 10, 0
str_sched_unified_fail_digest: db "[PAOS64] SMP scheduler: unified context selftest FAIL stage=digest", 13, 10, 0
str_sched_preempt_ok: db "[PAOS64] SMP preemption: timer/IPI/affinity selftest PASS [smp.preempt.ipi.ok]", 13, 10, 0
str_sched_preempt_fail: db "[PAOS64] SMP preemption: timer/IPI/affinity selftest FAIL", 13, 10, 0
str_sched_preempt_post_pmod_ok: db "[PAOS64] SMP preemption: post-PMOD timer/IPI/affinity selftest PASS", 13, 10, 0
str_sched_preempt_post_pmod_fail: db "[PAOS64] SMP preemption: post-PMOD timer/IPI/affinity selftest FAIL", 13, 10, 0
str_sched_preempt_post_pmod_restore_fail: db "[PAOS64] SMP preemption: post-PMOD timer-restore selftest FAIL", 13, 10, 0
str_sched_preempt_post_pmod_timer_fail: db "[PAOS64] SMP preemption: post-PMOD timer-progress selftest FAIL", 13, 10, 0
str_sched_preempt_post_pmod_affinity_fail: db "[PAOS64] SMP preemption: post-PMOD affinity-IPI selftest FAIL", 13, 10, 0
str_sched_balance_ok: db "[PAOS64] SMP balance: bounded work-steal selftest PASS [smp.steal.balance.ok]", 13, 10, 0
str_sched_balance_fail: db "[PAOS64] SMP balance: bounded work-steal selftest FAIL", 13, 10, 0
str_ss_kat:     db "[PAOS64] tourn.sched_spawn: KAT v1->slot0 v2->slot1 id/state/principal + frame[128]==entry + regs zeroed PASS [tourn.sched_spawn.kat]", 13, 10, 0
str_ss_katfail: db "[PAOS64] tourn.sched_spawn: KAT FAILED", 13, 10, 0
str_ss_fault:   db "[PAOS64] tourn.sched_spawn: fault battery NULL/full/boundary all contained gracefully [tourn.sched_spawn.fault contained=3 total=3]", 13, 10, 0
str_ss_fpfx:    db "[PAOS64] tourn.sched_spawn: fault contained=", 0
str_ss_fsfx:    db "/3", 13, 10, 0

; Private observations only: no claim, placement or scheduling authority.
%macro WDATA_sched_cpu_work_bss1 0
alignb 64
; Each cache line: completed units:u32 at0, block ticks:u64 at8,
; last block TSC:u64 at16; remaining bytes reserved. Reset as one job image.
usched_job_cpu_units: resd (USCHED_CPU_MAX * 16)
%endmacro
WDATA_BSS_DEFER WDATA_sched_cpu_work_bss1
