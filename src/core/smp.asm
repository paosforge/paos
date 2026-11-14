;; MODULE core/smp
;; LAYER 1
;; EXPORTS smp_cpu_report_copy, smp_timer_initial_count, smp_matmul, cpu_pf_matmul_units, smp_core_custody_acquire_native_guarded, smp_core_custody_check_native_guarded, smp_core_custody_release_native_guarded, smp_core_custody_check_gang_member, smp_core_custody_acquire_intel_absent, smp_core_custody_check_intel_absent, smp_core_custody_release_intel_absent, smp_core_custody_acquire_svm, smp_core_custody_svm_prepare, smp_core_custody_svm_check, smp_core_custody_svm_transfer, smp_core_custody_svm_land, smp_core_custody_svm_host, smp_core_custody_release_svm, smp_core_custody_acquire, smp_core_custody_check, smp_core_custody_release, smp_core_custody_gate, smpwork_async_results, smp_idle_observation_snapshot, smp_par_begin, smp_par_begin_single, smp_pc_cpu_chunks, smp_pc_finished_us, smp_par_step, smp_par_status, smp_par_cancel, smp_par_release, smpwork_async_begin, smpwork_async_step, smpwork_async_take, smpwork_async_cancel, smpwork_async_status, smpwork_async_detail, smpwork_async_progress, smp_par_for, smp_par_for_retired, smp_pf_bench, smp_pf_bench_observation, smp_bsp_idle_hlt, smp_bsp_hlt_tsc, smp_bsp_hlt_count, smp_idle_enter, smp_idle_hint, smp_idle_io_base, smp_idle_irq_refusals, smp_idle_mwait_count, smp_idle_hlt_count, smp_idle_cpu_state, smp_idle_cpu_edx5, smp_selftest, smp_msr_apply_aps, smp_msr_read_aps, smp_msr_req_rd_val, smp_msr_req_rd_c5, smp_msr_req_rd_type, smpwork_snapshot, smp_command_register_verb, smp_frequency_snapshot_validate, smp_lapic_detect_mode, smp_lapic_read32, smp_lapic_write32, smp_lapic_read_id, smp_current_logical, smp_preempt_global_init, smp_preempt_set_bsp_initial, smp_preempt_init_local, smp_preempt_timer_restore_bsp, smp_preempt_send_kicks, smp_preempt_send_resched_one, smp_mapping_update_begin, smp_mapping_update_commit, smp_coherence_prepare_mode, smp_lock_collision_selftest, smp_fault_concurrent_selftest, smp_tlb_coherence_selftest, smp_coherence_expected, smp_coherence_actual, smp_coherence_double_run, smp_coherence_lost, smp_fault_isolated, smp_faults_last_contained, smp_tlb_epoch, smp_tlb_requested, smp_tlb_acked, smp_stale_mapping, smp_irq_entries, smp_irq_eois, smp_irq_duplicate_eoi, smp_irq_ownership_faults, smp_timer_post_dcr, smp_timer_post_lvt, smp_timer_post_icr, smp_timer_post_current, smp_timer_irq0_before, smp_timer_preempt0_before, smp_timer_restore_seq, smp_timer_restore_ok, smp_halt_wait_us, smp_topology_online, smp_bsp_tick_handover, smp_bsp_tick_lease_begin, smp_bsp_tick_lease_end, smp_bsp_tick_owner
;; IMPORTS core/mca_cmci, core/mca_poll, core/mca_init, boot/serial, boot/smbios, boot/gdt, boot/paging, boot/pmod_loader, core/lib/fmt, core/time, core/idt, core/heap, core/lock, core/sched, core/smp_audit, boot/indicator, sec/cpu_security_percpu, sec/cpu_microcode_percpu, sec/cpu_microcode_boot, sec/cpu_microcode_bsp_checked, sec/cpu_idle_tsa, core/normal_deadman
;; CAPS
;; OWNER saga:core
; Standalone source harnesses retain the same disabled default as boot/header.
%ifndef PAOS_NORMAL_DEADMAN_MS
%define PAOS_NORMAL_DEADMAN_MS 0
%endif
;; LOCK: rq_locks[logical] PROTECTS run_queue_per_core[logical], coremap_counts[logical], smpwork_worker_epoch[logical], smpwork_worker_token[logical], smpwork_worker_runs[logical], smpwork_worker_published_us[logical]
;; LOCK: smp_state_lock PROTECTS cpu_state(AP startup transitions), smp_failed_count(AP startup transitions), smp_late_ap_mask(AP startup transitions), smp_late_ap_count(AP startup transitions), cpu_timer_ready(late-AP withdrawal on FAILED rows), cpu_runq_ready(late-AP withdrawal on FAILED rows), smp_topology_online(AP startup transitions), smp_online_aps, smpwork_online_mask, smpwork_challenge, smpwork_requested_epoch, smpwork_expected_workers, smpwork_expected_mask, smpwork_snapshot_challenge, smpwork_snapshot_epoch, smpwork_snapshot_workers, smpwork_async_phase, smpwork_async_generation, smpwork_async_source, smpwork_async_principal, smpwork_async_nonce, smpwork_async_epoch, smpwork_async_mask, smpwork_async_expected, smpwork_async_start, smpwork_async_last, smpwork_async_deadline, smpwork_async_expiry, smpwork_async_result, smpwork_worker_published_us
;; LOCK: smp_coherence_counter_lock PROTECTS smp_coherence_counter
;; LOCK: smp_core_custody_gate PROTECTS smp_cc_generation, smp_cc_request, smp_cc_release, smp_cc_departed, smp_cc_members, smp_cc_owner_apic, smp_cc_svm_mode, smp_cc_svm_ready, smp_cc_svm_failed, smp_cc_svm_phase, smp_cc_svm_guard, smp_cc_intel_guard, smp_cc_intel_token
;; LOCK: smp_mapping_lock PROTECTS smp_mapping_target, smp_mapping_owner, smp_mapping_required_mask, smp_quiesce_ack_mask, smp_tlb_ack_mask, smp_tlb_epoch, smp_release_epoch
; ============================================================================
; core/smp.asm — exact firmware topology and CPU-local SMP state.
; Enabled MADT Local APIC/Local x2APIC records are de-duplicated into dense
; logical slots.  Hardware APIC identities remain 32-bit data and are never
; array indexes.  Every online processor validates its own CPUID topology and
; installs a private stack, GDT/TSS/IST, fault slot, timer slot, run queue and
; current-task slot before it publishes ONLINE.
;
; Flow (all serial output is emitted on the BSP so lines never interleave; the
; per-core COMPUTE values are genuinely produced by the APs and stored in shared
; slots the BSP then prints):
;   1. BSP prints the boot nonce seed ("smp.seed=0x..").
;   2. BSP copies a real-mode->long-mode AP trampoline to low memory (0x8000,
;      SIPI-reachable, page-aligned, with its own executable low PTE from
;      boot/paging even when firmware relocates the image above 2 MiB), patches in
;      CR3 (our PML4) and the 64-bit AP entry (smp_ap_main).
;   3. BSP contributes core 0 (reads BSP APIC id, computes, stores).
;   4. For each dense firmware AP row: INIT-SIPI-SIPI the row's full APIC id,
;      wait boundedly for complete local-state publication, and report failures.
;   5. Each online AP (smp_ap_main): loads our GDT+IDT, reads its APIC id, computes
;      crc32(apic^seed), stores coremap_counts[logical]=1 + the value in
;      run_queue_per_core[logical] under rq_lock, marks itself online, then pulls
;      the installed compounding worker from that per-core queue forever.
;   6. BSP prints one "smp.core: apic=<id> compute=0x<hex>" line per active core,
;      the COREMAP, and the online/compute markers.
;   7. NEGATIVE GATE: every online AP enters a deliberate #GP concurrently.
;      Vector 13 resolves the dense logical CPU and consumes only that CPU's
;      recovery slot; all handlers must enter before BSP releases the barrier.
;
; The QEMU Intel/AMD topology matrix is architecture pre-flight. The same AP
; path is re-qualified on Lenovo metal here; exact HP AMD metal remains owned
; by Task3260 and is never inferred from an emulated vendor string.
; ============================================================================

MAXCORE          equ SMP_CPU_CAPACITY
times (CSP_COUNT == SMP_CPU_CAPACITY) - 1 db 0 ; retained CPU slots match dense topology capacity
SMP_IDLE_CPU_OK  equ 1                   ; RCQ-27 L2 smp_idle_cpu_state
SMP_IDLE_CPU_NO  equ 2
SMP_IDLE_CPU_IO_OK equ 3                 ; the L1 IO-window check passed (never the MWAIT one)
%ifdef PAOS_HP_SMP_TRIAL_APS
  %if PAOS_HP_SMP_TRIAL_APS != 1 && PAOS_HP_SMP_TRIAL_APS != 31
    %error "PAOS_HP_SMP_TRIAL_APS must be 1 (Step A: one AP) or 31 (Step B: every firmware row)"
  %endif
  %define SMP_STK_LIMIT smp_stk_limit
%else
  %define SMP_STK_LIMIT smp_discovered_count
%endif
AP_STACK_SIZE    equ 16384
TRAMP_BASE       equ 0x8000               ; SIPI vector 0x08 -> phys 0x8000
LAPIC_ID_REG     equ 0xFEE00020
LAPIC_ICR_LO     equ 0xFEE00300
LAPIC_ICR_HI     equ 0xFEE00310
ICR_INIT         equ 0x00004500           ; INIT, assert, edge
ICR_SIPI         equ 0x00004600 + (TRAMP_BASE >> 12)  ; STARTUP, vector = page 0x08
SMPWORK_CLASS_COMPOUNDING equ 1
; Cooperative slot statuses (also the EAX API result). No timer is installed.
SMPWORK_ASYNC_IDLE        equ 0
SMPWORK_ASYNC_PENDING     equ 1
SMPWORK_ASYNC_COMPLETE    equ 2
SMPWORK_ASYNC_PARTIAL     equ 3
SMPWORK_ASYNC_BUSY        equ 4
SMPWORK_ASYNC_STALE       equ 5
SMPWORK_ASYNC_CANCELLED   equ 6
SMPWORK_ASYNC_CLOCK       equ 7
SMPWORK_ASYNC_COUNTER     equ 8
SMPWORK_ASYNC_TOPOLOGY    equ 9
SMPWORK_ASYNC_SYNC        equ 10
SMPWORK_ASYNC_FROZEN      equ 11
SMPWORK_ASYNC_WAIT_US     equ 100000
SMPWORK_ASYNC_RETAIN_US   equ 1000000
SMPWORK_WAIT_STEPS        equ 2000
IA32_APIC_BASE_MSR        equ 0x1B
X2APIC_MSR_BASE           equ 0x800
CPU_STATE_DISCOVERED      equ 0
CPU_STATE_BSP             equ 1
CPU_STATE_PENDING         equ 2
CPU_STATE_ONLINE          equ 3
CPU_STATE_FAILED          equ 4
SMP_TIMER_VECTOR          equ 0xE8
SMP_RESCHED_VECTOR        equ 0xE9
SMP_IDLE_WAKE_VECTOR      equ 0xEA
SMP_TIMER_REARM_VECTOR    equ 0xEB
SMP_COHERENCE_VECTOR      equ 0xEC
SMP_CMCI_VECTOR           equ 0xED
SMP_ICR_FIXED             equ 0x00000000
SMP_TIMER_INITIAL         equ 0x00100000
SMP_IDLE_TICK_STRETCH     equ 16           ; RC power I1: a parked AP's tick period, calibrated ms
SMP_LAPIC_LVT_TIMER       equ 0x320
SMP_LAPIC_INITIAL_COUNT   equ 0x380
SMP_LAPIC_CURRENT_COUNT   equ 0x390
SMP_LAPIC_DIVIDE_CONFIG   equ 0x3E0
SMP_TSC_DEADLINE_MSR      equ 0x6E0
SMP_COHERENCE_ITERS       equ 257
SMP_LOAD_WINDOW_US        equ 100000       ; public sample: measured 100 ms window
SMP_LOAD_STALL_MS         equ 2000         ; queued work without progress is unhealthy
SMP_FREQ_WAIT_STEPS       equ 1000         ; 50 ms per own-core edge acknowledgement
SMP_FREQ_MSR_MPERF        equ 0xE7
SMP_FREQ_MSR_APERF        equ 0xE8
SMP_FREQ_STATE_UNSUPPORTED equ 0
SMP_FREQ_STATE_IDLE        equ 1
SMP_FREQ_STATE_MEASURED    equ 2
SMP_FREQ_SOURCE_UNSUPPORTED equ 0
SMP_FREQ_SOURCE_CPUID16     equ 1
SMP_FREQ_SOURCE_PLATFORM    equ 2
SMP_FREQ_SOURCE_NO_BASE     equ 3
SMP_VENDOR_UNKNOWN        equ 0
SMP_VENDOR_INTEL          equ 1
SMP_VENDOR_AMD            equ 2

SMP_GDT_BOOT_SLOTS        equ 8
SMP_GDT_EXT_SLOTS         equ SMP_CPU_CAPACITY - SMP_GDT_BOOT_SLOTS
SMP_GDT_TABLE_SIZE        equ 40
SMP_GDT_GDTR_SIZE         equ 16
SMP_GDT_TSS_SIZE          equ 104
SMP_GDT_IST_SIZE          equ GDT_PERCPU_IST_SIZE

; Extend the proven boot/GDT CPU-local implementation without replacing it.
; The first eight slots call the shipped owner verbatim. Higher dense IDs use
; the same descriptor/TSS sequence and a private guarded IST page.
smp_gdt_percpu_prepare:
    ; A slot is prepared once per boot and never reassigned, even after failure.
    push rdi
    call percpu_stack_prepare_check
    pop  rdi
    jc   .bad
    cmp  edi, SMP_CPU_CAPACITY
    jae  .bad
    cmp  edi, SMP_GDT_BOOT_SLOTS
    jae  .extension
    push rdi
    call boot_gdt_percpu_prepare
    pop  rdi
    jc   .out
    lea  rax, [rel smp_gdt_percpu_ready]
    mov  byte [rax + rdi], 7
    call percpu_stack_seal
.out:
    ret
.extension:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    sub  edi, SMP_GDT_BOOT_SLOTS

    mov  eax, edi
    imul rax, SMP_GDT_TABLE_SIZE
    lea  rbx, [rel smp_gdt_ext_tables]
    add  rbx, rax
    mov  r14, rbx
    lea  rsi, [rel gdt_start]
    mov  rdi, rbx
    mov  ecx, 24
    cld
    rep  movsb
    xor  eax, eax
    mov  ecx, 16
    rep  stosb

    mov  eax, r12d
    sub  eax, SMP_GDT_BOOT_SLOTS
    imul rax, SMP_GDT_TSS_SIZE
    lea  rbx, [rel smp_gdt_ext_tss]
    add  rbx, rax
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, SMP_GDT_TSS_SIZE
    rep  stosb
    mov  [rbx + 4], r13
    mov  edi, r12d
    call percpu_stack_ist_top
    mov  rdx, rax
    mov  [rbx + 0x24], rdx

    lea  rdi, [r14 + 24]
    mov  word [rdi], 0x0067
    mov  rax, rbx
    mov  [rdi + 2], ax
    shr  rax, 16
    mov  [rdi + 4], al
    mov  byte [rdi + 5], 0x89
    mov  byte [rdi + 6], 0
    mov  [rdi + 7], ah
    shr  rax, 16
    mov  [rdi + 8], eax
    mov  dword [rdi + 12], 0

    mov  eax, r12d
    sub  eax, SMP_GDT_BOOT_SLOTS
    imul rax, SMP_GDT_GDTR_SIZE
    lea  rdi, [rel smp_gdt_ext_gdtr]
    add  rdi, rax
    mov  word [rdi], SMP_GDT_TABLE_SIZE - 1
    mov  [rdi + 2], r14
    lea  rax, [rel smp_gdt_percpu_ready]
    mov  byte [rax + r12], 7
    mov  edi, r12d
    call percpu_stack_seal
    clc
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.extension_bad:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    stc
    ret
.bad:
    stc
    ret

smp_gdt_percpu_load:
    cmp  edi, SMP_CPU_CAPACITY
    jae  .bad
    cmp  edi, SMP_GDT_BOOT_SLOTS
    jb   boot_gdt_percpu_load
    mov  eax, edi
    sub  eax, SMP_GDT_BOOT_SLOTS
    imul rax, SMP_GDT_GDTR_SIZE
    lea  rdx, [rel smp_gdt_ext_gdtr]
    add  rdx, rax
    lgdt [rdx]
    push qword 0x08
    lea  rax, [rel .cs_loaded]
    push rax
    retfq
.cs_loaded:
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  ss, ax
    mov  fs, ax
    mov  gs, ax
    mov  ax, 0x18
    ltr  ax
    clc
    ret
.bad:
    stc
    ret

; ---- one xAPIC/x2APIC abstraction -----------------------------------------
smp_lapic_detect_mode:
    mov  ecx, IA32_APIC_BASE_MSR
    rdmsr
    bt   eax, 10                           ; firmware-selected x2APIC mode
    setc byte [rel smp_lapic_mode]
    ret

; smp_lapic_read32(ESI=architectural LAPIC offset) -> EAX, CF=0
smp_lapic_read32:
    test esi, 0x0F                         ; architectural LAPIC registers are 16-byte slots
    jnz  .bad
    cmp  esi, 0x3F0                        ; stay within the one-page LAPIC register file
    ja   .bad
    cmp  byte [rel smp_lapic_mode], 0
    je   .xapic
    mov  ecx, esi
    shr  ecx, 4
    add  ecx, X2APIC_MSR_BASE
    rdmsr
    clc
    ret
.xapic:
    mov  rax, 0xFEE00000
    mov  eax, [rax + rsi]
    clc
    ret
.bad:
    xor  eax, eax
    stc
    ret

; smp_lapic_write32(ESI=offset, EDX=value) -> CF=0
smp_lapic_write32:
    test esi, 0x0F
    jnz  .bad
    cmp  esi, 0x3F0
    ja   .bad
    cmp  byte [rel smp_lapic_mode], 0
    je   .xapic
    mov  ecx, esi
    shr  ecx, 4
    add  ecx, X2APIC_MSR_BASE
    mov  eax, edx
    xor  edx, edx
    wrmsr
    clc
    ret
.xapic:
    mov  rax, 0xFEE00000
    mov  [rax + rsi], edx
    clc
    ret
.bad:
    stc
    ret

smp_lapic_read_id:
    mov  esi, 0x20
    call smp_lapic_read32
    cmp  byte [rel smp_lapic_mode], 0
    jne  .done
    shr  eax, 24
.done:
    ret

; smp_lapic_send_ipi(EDI=full APIC id, ESI=ICR low) -> CF on unsupported dest
smp_lapic_send_ipi:
    cmp  byte [rel smp_lapic_mode], 0
    je   .xapic
    mov  ecx, X2APIC_MSR_BASE + (0x300 >> 4)
    mov  eax, esi
    mov  edx, edi                           ; x2APIC ICR destination bits 63:32
    wrmsr
    clc
    ret
.xapic:
    cmp  edi, 255
    ja   .bad
    mov  eax, edi
    shl  eax, 24
    mov  rcx, LAPIC_ICR_HI
    mov  [rcx], eax
    mov  rcx, LAPIC_ICR_LO
    mov  [rcx], esi
    mov  r8d, 100000
.wait:
    mov  eax, [rcx]
    test eax, (1 << 12)
    jz   .sent
    dec  r8d
    jnz  .wait
    stc
    ret
.sent:
    clc
    ret
.bad:
    stc
    ret

; Install shared gates before AP startup; arm each local timer only after its
; private GDT/TSS/IST state is live.
smp_preempt_global_init:
    ; The legacy diagnostic arm is process-global.  Route #GP through a
    ; CPU-indexed gate before AP startup; unarmed faults still forward to the
    ; original core/idt path unchanged.
    mov  edi, 13
    lea  rsi, [rel smp_fault_gp_isr]
    call idt_set_handler
    mov  edi, SMP_TIMER_VECTOR
    lea  rsi, [rel smp_preempt_timer_isr]
    call idt_set_handler
    mov  edi, SMP_RESCHED_VECTOR
    lea  rsi, [rel smp_resched_ipi_isr]
    call idt_set_handler
    mov  edi, SMP_IDLE_WAKE_VECTOR
    lea  rsi, [rel smp_idle_wake_ipi_isr]
    call idt_set_handler
    mov  edi, SMP_TIMER_REARM_VECTOR
    lea  rsi, [rel smp_timer_rearm_ipi_isr]
    call idt_set_handler
    mov  edi, SMP_COHERENCE_VECTOR
    lea  rsi, [rel smp_coherence_ipi_isr]
    call idt_set_handler
    mov  edi, SMP_CMCI_VECTOR
    lea  rsi, [rel smp_cmci_isr]
    call idt_set_handler
    lea  rdi, [rel smp_lapic_read32]
    lea  rsi, [rel smp_lapic_write32]
    lea  rdx, [rel smp_cmci_isr]
    call mca_cmci_bind
    lea  rdi, [rel smp_preempt_timer_restore_bsp]
    call pmod_timer_hooks_bind
    ret

; The existing C6 LAPIC KAT measures the BSP timer input against the calibrated
; TSC and produces the real one-millisecond reload.  Retain that hardware value
; as scheduler ownership state: replaying the nominal bring-up count after a
; PMOD deadline lease can leave CPU0 without an interrupt in the live probe
; window even though DCR/LVT/ICR readback looks superficially valid.
smp_preempt_set_bsp_initial:
    push rbx
    push r12
    test edi, edi
    jz   .out
    mov  [rel smp_timer_initial_count], edi
    mov  byte [rel smp_bsp_tick_calibrated], 1 ; RCQ-27 B1: halting waits may rely on the 1 ms tick

    ; APs were brought online before the late C6 calibration and therefore
    ; still own the nominal 0x100000 reload.  Publish the measured reload, then
    ; make every online AP replay the same complete local DCR/LVT/ICR seam.
    ; Without this acknowledged handoff an external 250 ms delta can randomly
    ; miss the first AP even though the repaired BSP advances at 1000 Hz.
    mov  dword [rel smp_timer_rearm_ack_mask], 1 ; BSP is rearmed by C6 itself
    ; Require exactly the rows that own a live LAPIC timer (BSP + ONLINE APs).
    ; A DISCOVERED/FAILED row (HP trial cap, late or failed AP) never receives
    ; the IPI below, so requiring it only burned the whole 50 ms window.
    call smp_online_mask_now
    mov  r12d, eax
    mov  [rel smp_timer_rearm_required_mask], r12d
    mov  ebx, 1
.send:
    cmp  ebx, [rel smp_discovered_count]
    jae  .wait
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .next
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + rbx*4]
    mov  esi, SMP_ICR_FIXED | SMP_TIMER_REARM_VECTOR
    call smp_lapic_send_ipi
.next:
    inc  ebx
    jmp  .send
.wait:
    mov  ebx, 1000                       ; bounded 50 ms acknowledgement window
.wait_ack:
    mov  eax, [rel smp_timer_rearm_ack_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .out
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_ack
.out:
    pop  r12
    pop  rbx
    ret

smp_preempt_init_local:
    mov  esi, 0x0F0
    mov  edx, 0x1FF
    call smp_lapic_write32
    mov  esi, SMP_LAPIC_DIVIDE_CONFIG
    mov  edx, 0x03
    call smp_lapic_write32
    mov  esi, SMP_LAPIC_LVT_TIMER
    mov  edx, (1 << 17) | SMP_TIMER_VECTOR
    call smp_lapic_write32
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    mov  edx, [rel smp_timer_initial_count]
    call smp_lapic_write32
    ret

; ---------------------------------------------------------------------------
; RC power I2 (PLAN.md, I2_DESIGN.md): the BSP took two 1 kHz ticks, PIT IRQ0
; (timer_ticks + serial_boot_tick) and its scheduler LAPIC timer. After every
; boot selftest, the calibrated LAPIC tick takes IRQ0's work and IRQ0 is masked
; at the 8259 (one read-modify-write of bit 0; the other bits are kept). The
; legacy PIT preemption is armed only by preempt_selftest/watchdog_selftest,
; which have returned by then. Anything unproven stays on the PIT (today).
; A PMOD lease borrows the BSP's LAPIC timer for up to PMOD_TIMEOUT_MS, so
; timer_ticks goes back to the PIT for the lease and returns after the restore.
; Each handover may repeat or skip one tick; timer_ticks never goes backwards.
; ---------------------------------------------------------------------------
SMP_BSP_TICK_KAT_US      equ 50000        ; 50 ms of the BSP's own 1 ms tick
SMP_BSP_TICK_KAT_MIN     equ 40           ; +-20 %
SMP_BSP_TICK_KAT_MAX     equ 60
SMP_BSP_TICK_R_LAPIC     equ 0
SMP_BSP_TICK_R_UNCAL     equ 1            ; no measured 1 ms reload
SMP_BSP_TICK_R_IF        equ 2            ; IF clear: no tick could be observed
SMP_BSP_TICK_R_LVT       equ 3            ; the BSP's LVT is not the scheduler's periodic 0xE8
SMP_BSP_TICK_R_KAT       equ 4            ; the tick did not advance 40..60 times in 50 ms

; smp_bsp_tick_handover -> EAX = SMP_BSP_TICK_R_*. BSP main-loop entry only
;   (boot/header.asm, after strong health). Logs "[power.i2] tick=lapic" or
;   "tick=pit reason=<n> kat=<BSP ticks in the 50 ms KAT>". Clobbers caller-saved.
smp_bsp_tick_handover:
    push rbx
    push r12
    mov  ebx, SMP_BSP_TICK_R_UNCAL
    cmp  byte [rel smp_bsp_tick_calibrated], 1
    jne  .stay
    mov  ebx, SMP_BSP_TICK_R_IF
    pushfq
    pop  rax
    test eax, 0x200
    jz   .stay
    mov  ebx, SMP_BSP_TICK_R_LVT
    mov  esi, SMP_LAPIC_LVT_TIMER
    call smp_lapic_read32
    cmp  eax, (1 << 17) | SMP_TIMER_VECTOR
    jne  .stay
    mov  r12, [rel cpu_irq_count]         ; the BSP's own row (dense 0)
    mov  edi, SMP_BSP_TICK_KAT_US
    call tsc_delay_us
    mov  rax, [rel cpu_irq_count]
    sub  rax, r12
    mov  [rel smp_bsp_tick_kat_count], rax
    mov  ebx, SMP_BSP_TICK_R_KAT
    cmp  rax, SMP_BSP_TICK_KAT_MIN
    jb   .stay
    cmp  rax, SMP_BSP_TICK_KAT_MAX
    ja   .stay
    pushfq
    cli
    mov  byte [rel smp_bsp_tick_owner], 1
    in   al, 0x21
    or   al, 0x01                          ; mask IRQ0 only
    out  0x21, al
    popfq
    mov  ebx, SMP_BSP_TICK_R_LAPIC
    lea  rdi, [rel str_bsp_tick_lapic]
    call serial_string
    jmp  .out
.stay:
    lea  rdi, [rel str_bsp_tick_pit]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_bsp_tick_kat]
    call serial_string
    mov  rdi, [rel smp_bsp_tick_kat_count]  ; 0 when no KAT ran
    call serial_hex64
    lea  rdi, [rel str_bsp_tick_eol]
    call serial_string
.out:
    mov  [rel smp_bsp_tick_reason], bl
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; smp_bsp_tick_lease_begin — PMOD is about to own this CPU's LAPIC timer (IF
;   clear). On the BSP with the LAPIC owning timer_ticks: the PIT carries it
;   through the lease. Preserves every register and flag.
smp_bsp_tick_lease_begin:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    cli
    cmp  byte [rel smp_bsp_tick_owner], 1
    jne  .out
    call smp_current_logical
    test eax, eax
    jnz  .out
    mov  byte [rel smp_bsp_tick_owner], 0
    mov  byte [rel smp_bsp_tick_leased], 1
    in   al, 0x21
    and  al, 0xFE                          ; unmask IRQ0 only
    out  0x21, al
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    popfq
    ret

; smp_bsp_tick_lease_end — PMOD restored the scheduler's timer (IF clear). The
;   LAPIC owns timer_ticks again only after the complete restore succeeded and
;   the scheduler's periodic 0xE8/reload still match; otherwise PIT keeps it (counted).
;   Preserves every register and flag.
smp_bsp_tick_lease_end:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    cli
    cmp  byte [rel smp_bsp_tick_leased], 1
    jne  .out
    call smp_current_logical
    test eax, eax
    jnz  .out
    mov  byte [rel smp_bsp_tick_leased], 0
    cmp  byte [rel smp_timer_restore_ok], 1 ; complete DCR/LVT/reload restore, either PMOD path
    jne  .fallback
    mov  esi, SMP_LAPIC_LVT_TIMER
    call smp_lapic_read32
    cmp  eax, (1 << 17) | SMP_TIMER_VECTOR
    jne  .fallback
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    call smp_lapic_read32
    cmp  eax, [rel smp_timer_initial_count]
    jne  .fallback
    in   al, 0x21
    or   al, 0x01                          ; mask IRQ0 only
    out  0x21, al
    mov  byte [rel smp_bsp_tick_owner], 1
    jmp  .out
.fallback:
    inc  dword [rel smp_bsp_tick_lease_fallbacks]
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    popfq
    ret

; Switching to deadline mode consumes the old periodic countdown. Clearing the
; deadline MSR is therefore only half of restore: restart the complete scheduler
; DCR/LVT/initial-count contract and retain readback from the live state.
smp_preempt_timer_restore_bsp:
    mov  rax, [rel cpu_irq_count]
    mov  [rel smp_timer_irq0_before], rax
    mov  rax, [rel cpu_preempt_count]
    mov  [rel smp_timer_preempt0_before], rax
    mov  byte [rel smp_timer_restore_ok], 0
    mov  ecx, SMP_TSC_DEADLINE_MSR
    xor  eax, eax
    xor  edx, edx
    wrmsr
    call smp_preempt_init_local
    mov  esi, SMP_LAPIC_DIVIDE_CONFIG
    call smp_lapic_read32
    mov  [rel smp_timer_post_dcr], eax
    mov  esi, SMP_LAPIC_LVT_TIMER
    call smp_lapic_read32
    mov  [rel smp_timer_post_lvt], eax
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    call smp_lapic_read32
    mov  [rel smp_timer_post_icr], eax
    mov  esi, SMP_LAPIC_CURRENT_COUNT
    call smp_lapic_read32
    mov  [rel smp_timer_post_current], eax
    inc  dword [rel smp_timer_restore_seq]
    mov  byte [rel smp_timer_restore_ok], 0
    cmp  dword [rel smp_timer_post_dcr], 0x03
    jne  .bad
    cmp  dword [rel smp_timer_post_lvt], (1 << 17) | SMP_TIMER_VECTOR
    jne  .bad
    mov  eax, [rel smp_timer_initial_count]
    cmp  dword [rel smp_timer_post_icr], eax
    jne  .bad
    ; CURRENT_COUNT is a live down-counter, not configuration readback.  A
    ; single zero sample is legal at the periodic reload boundary and becomes
    ; common when 32-vCPU TCG deschedules the BSP between the write and read.
    ; DCR/LVT/INITIAL_COUNT prove the restore programming; the deferred KAT
    ; below still requires a subsequent real timer IRQ before it can pass.
    mov  byte [rel smp_timer_restore_ok], 1
    call sched_preempt_post_pmod_request ; execute only from a later safe frame
    mov  eax, 1
    ret
.bad:
    call sched_preempt_post_pmod_request ; retain a falsifying post-call KAT
    xor  eax, eax
    ret

; Translate the live APIC identity through the dense firmware table.
smp_current_logical:
    push rbx
    call smp_lapic_read_id
    mov  ebx, eax
    xor  eax, eax
.scan:
    cmp  eax, [rel smp_discovered_count]
    jae  .unknown
    lea  rcx, [rel cpu_apic_id]
    cmp  [rcx + rax*4], ebx
    je   .out
    inc  eax
    jmp  .scan
.unknown:
    mov  eax, MAXCORE
.out:
    pop  rbx
    ret

%macro SMP_ISR_SAVE 0
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
%endmacro

%macro SMP_ISR_RESTORE 0
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
%endmacro

; Every LAPIC-owned vector enters and leaves through this pair.  The per-CPU
; depth byte makes a duplicate EOI or nested ownership transfer observable;
; the EOI write itself exists in exactly one function.
smp_irq_enter:
    cmp  edi, MAXCORE
    jae  .out
    lea  rax, [rel cpu_irq_depth]
    mov  dl, 1
    xchg dl, [rax + rdi]
    test dl, dl
    jz   .count
    lock inc dword [rel smp_irq_ownership_faults]
.count:
    lock inc qword [rel smp_irq_entries]
.out:
    ret

smp_irq_eoi:
    cmp  edi, MAXCORE
    jae  .write
    lea  rax, [rel cpu_irq_depth]
    xor  dl, dl
    xchg dl, [rax + rdi]
    test dl, dl
    jnz  .count
    lock inc dword [rel smp_irq_duplicate_eoi]
.count:
    lock inc qword [rel smp_irq_eois]
.write:
    mov  esi, 0x0B0
    xor  edx, edx
    jmp  smp_lapic_write32

; CMCI has no MCA status access or logging in IRQ context. The ordinary local
; MCA poller is the sole consumer. Its bounded IRQ marker masks storms.
smp_cmci_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    mov edi,eax
    mov r12d,eax
    call smp_irq_enter
    mov edi,r12d
    call mca_cmci_irq
    mov edi,r12d
    call smp_irq_eoi
    SMP_ISR_RESTORE
    iretq

; Dedicated #GP gate for CPU-local fault recovery.  A direct exception gate
; arrives with [err][rip][cs][rflags].  SMP_ISR_SAVE adds 120 bytes.  When the
; current CPU has no armed slot, reconstruct the original vector-13 entry by
; forwarding through its canonical stub.
align 16
smp_fault_gp_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .forward
    mov  ebx, eax
    lea  rcx, [rel cpu_fault_expect]
    cmp  byte [rcx + rbx], 1
    jne  .forward
    mov  byte [rcx + rbx], 0
    lea  rcx, [rel cpu_fault_recover]
    mov  rax, [rcx + rbx*8]
    test rax, rax
    jz   .forward
    mov  [rsp + 128], rax                 ; saved RIP after 15 pushed registers
    lock bts dword [rel smp_fault_entered_mask], ebx
.release_wait:
    mov  eax, [rel smp_fault_epoch]
    cmp  [rel smp_fault_release_epoch], eax
    je   .resume
    pause
    jmp  .release_wait
.resume:
    SMP_ISR_RESTORE
    add  rsp, 8                           ; discard #GP error code
    iretq
.forward:
    SMP_ISR_RESTORE
    jmp  isr_stub_13

; Peers acknowledge quiescence before the caller mutates a mapping or patch.
; EOI is issued before the bounded rendezvous wait; after release each peer
; invalidates locally, samples the post-mutation witness, and publishes last.
align 16
smp_coherence_ipi_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    mov  ebx, eax
    mov  edi, ebx
    call smp_irq_enter
    cmp  ebx, MAXCORE
    jae  .eoi_only
    lock bts dword [rel smp_quiesce_ack_mask], ebx
    mov  edi, ebx
    call smp_irq_eoi
    mov  r12d, [rel smp_tlb_epoch]
.wait_release:
    cmp  [rel smp_release_epoch], r12d
    je   .invalidate
    pause
    jmp  .wait_release
.invalidate:
    mov  rax, [rel smp_mapping_target]
    test rax, rax
    jz   .flush_all
    invlpg [rax]
    jmp  .sample
.flush_all:
    mov  rax, cr3
    mov  cr3, rax
.sample:
    mfence
    push rbx
    xor  eax, eax
    cpuid                                  ; serialize peer instruction fetch
    pop  rbx
    mov  rax, [rel smp_mapping_probe]
    lea  rcx, [rel cpu_mapping_observed]
    mov  [rcx + rbx*8], rax
    lea  rcx, [rel cpu_tlb_epoch]
    mov  [rcx + rbx*4], r12d              ; publish observation before ack
    lock bts dword [rel smp_tlb_ack_mask], ebx
    SMP_ISR_RESTORE
    iretq
.eoi_only:
    mov  edi, ebx
    call smp_irq_eoi
    SMP_ISR_RESTORE
    iretq

align 16
smp_preempt_timer_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    mov  ebx, eax
    cmp  eax, MAXCORE
    jae  .eoi
    mov  edi, ebx
    call smp_irq_enter
    lea  rcx, [rel cpu_irq_count]
    lock inc qword [rcx + rbx*8]
    test ebx, ebx
    jnz  .not_bsp_tick
    cmp  byte [rel smp_bsp_tick_owner], 1
    jne  .not_bsp_tick
    inc  qword [rel timer_ticks]           ; RC power I2: IRQ0's work, on the BSP's own tick
%if PAOS_NORMAL_DEADMAN_MS
    call tsc_now
    mov  rdi, rax
    call normal_deadman_irq            ; only BSP tick owner, before callbacks
%endif
    call serial_boot_tick
    call tsc_now
    mov  rdi, rax
    mov  rsi, [rel tsc_khz]
    call boot_indicator_tick
.not_bsp_tick:
    xor  r12d, r12d
    mov  eax, [rel usched_cpu_in_run_mask]
    bt   eax, ebx                          ; sampled before ISR-owned dispatch
    setc r12b
    mov  edi, ebx
    call sched_preempt_post_pmod_tick
    mov  edi, ebx
    call sched_preempt_irq
    mov  r13d, eax                         ; one preempted scheduler unit completed
    or   r12d, eax
    test r12d, r12d
    jz   .preempt_count
    lea  rcx, [rel cpu_load_busy_ticks]
    lock inc qword [rcx + rbx*8]
.preempt_count:
    test r13d, r13d
    jz   .eoi
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .eoi
    lea  rcx, [rel cpu_preempt_count]
    lock inc qword [rcx + rax*8]
.eoi:
    mov  edi, ebx
    call smp_irq_eoi
    SMP_ISR_RESTORE
    iretq

align 16
smp_resched_ipi_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    mov  ebx, eax
    cmp  eax, MAXCORE
    jae  .eoi
    mov  edi, ebx
    call smp_irq_enter
    mov  edi, ebx
    call sched_resched_ipi_irq
    test eax, eax
    jz   .eoi
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .eoi
    lea  rcx, [rel cpu_resched_count]
    lock inc qword [rcx + rax*8]
.eoi:
    mov  edi, ebx
    call smp_irq_eoi
    SMP_ISR_RESTORE
    iretq

align 16
smp_idle_wake_ipi_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    mov  ebx, eax
    cmp  eax, MAXCORE
    jae  .eoi
    mov  edi, ebx
    call smp_irq_enter
    mov  edi, ebx
    call sched_idle_wake_ipi_irq
    test eax, eax
    jz   .eoi
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .eoi
    lea  rcx, [rel cpu_idle_wake_count]
    lock inc qword [rcx + rax*8]
.eoi:
    mov  edi, ebx
    call smp_irq_eoi
    SMP_ISR_RESTORE
    iretq

align 16
smp_timer_rearm_ipi_isr:
    SMP_ISR_SAVE
    call smp_current_logical
    mov  ebx, eax
    cmp  eax, MAXCORE
    jae  .eoi
    mov  edi, ebx
    call smp_irq_enter
    call smp_preempt_init_local
    lock bts dword [rel smp_timer_rearm_ack_mask], ebx
.eoi:
    mov  edi, ebx
    call smp_irq_eoi
    SMP_ISR_RESTORE
    iretq

; Receive-side counters in the handlers are the acknowledgements; sending is
; never counted as success.
smp_preempt_send_kicks:
    push rbx
    push r12
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel smp_discovered_count]
    jae  .done
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_BSP
    je   .send
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .next
.send:
    lea  rax, [rel cpu_apic_id]
    mov  r12d, [rax + rbx*4]
    mov  edi, r12d
    mov  esi, SMP_ICR_FIXED | SMP_IDLE_WAKE_VECTOR
    call smp_lapic_send_ipi
    mov  edi, 10
    call tsc_delay_us
    mov  edi, r12d
    mov  esi, SMP_ICR_FIXED | SMP_RESCHED_VECTOR
    call smp_lapic_send_ipi
.next:
    inc  ebx
    jmp  .loop
.done:
    pop  r12
    pop  rbx
    ret

smp_preempt_send_resched_one:
    cmp  edi, 0
    jl   .bad
    cmp  edi, [rel smp_discovered_count]
    jae  .bad
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rdi], CPU_STATE_BSP
    je   .send
    cmp  byte [rax + rdi], CPU_STATE_ONLINE
    jne  .bad
.send:
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + rdi*4]
    mov  esi, SMP_ICR_FIXED | SMP_RESCHED_VECTOR
    call smp_lapic_send_ipi
    jc   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; ---- exact MADT -> dense logical topology ---------------------------------
smp_topology_clear:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    stc
    ret
.custody_free:
    mov  dword [rel smp_configured_count], 0
    mov  dword [rel smp_enabled_count], 0
    mov  dword [rel smp_discovered_count], 0
    mov  dword [rel smp_topology_online], 0
    mov  dword [rel smp_failed_count], 0
    mov  dword [rel smp_late_ap_mask], 0
    mov  dword [rel smp_late_ap_count], 0
    mov  dword [rel smp_duplicate_count], 0
    mov  dword [rel smp_topology_leaf], 0
    mov  dword [rel smp_package_count], 0
    mov  dword [rel smp_physical_core_count], 0
    mov  dword [rel smp_threads_per_core], 0
    mov  byte [rel smp_cpu_vendor], SMP_VENDOR_UNKNOWN
    mov  byte [rel smp_placement_valid], 0
    mov  byte [rel smp_topology_exact], 0
    mov  byte [rel smp_topology_overflow], 0
    xor  ecx, ecx
.loop:
    cmp  ecx, MAXCORE
    jae  .done
    lea  rax, [rel cpu_apic_id]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    lea  rax, [rel cpu_uid]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    lea  rax, [rel cpu_package]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    lea  rax, [rel cpu_core]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    lea  rax, [rel cpu_thread]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    lea  rax, [rel cpu_core_type]
    mov  byte [rax + rcx], 0
    lea  rax, [rel cpu_state]
    mov  byte [rax + rcx], CPU_STATE_DISCOVERED
    lea  rax, [rel cpu_placement_rank]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    inc  ecx
    jmp  .loop
.done:
    ret

; add enabled firmware row EAX=APIC, EDX=UID. Duplicates are ignored; CF means
; the firmware topology exceeded the one declared dense-logical capacity.
smp_topology_add:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    stc
    ret
.custody_free:
    push rbx
    push r12
    mov  r12d, eax
    mov  ebx, edx
    xor  ecx, ecx
.find:
    cmp  ecx, [rel smp_discovered_count]
    jae  .unique
    lea  rax, [rel cpu_apic_id]
    cmp  [rax + rcx*4], r12d
    je   .duplicate
    inc  ecx
    jmp  .find
.unique:
    cmp  ecx, MAXCORE
    jae  .overflow
    lea  rax, [rel cpu_apic_id]
    mov  [rax + rcx*4], r12d
    lea  rax, [rel cpu_uid]
    mov  [rax + rcx*4], ebx
    inc  dword [rel smp_discovered_count]
    inc  dword [rel smp_enabled_count]
    clc
    jmp  .out
.duplicate:
    inc  dword [rel smp_duplicate_count]
    clc
    jmp  .out
.overflow:
    mov  byte [rel smp_topology_overflow], 1
    stc
.out:
    pop  r12
    pop  rbx
    ret

; smp_topology_parse_entries(RDI=first, RSI=end) -> CF on malformed/overflow.
; Type 0 and type 9 share one enabled+unique insertion path.
smp_topology_parse_entries:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
.walk:
    cmp  rbx, r12
    jae  .ok
    mov  rax, r12
    sub  rax, rbx
    cmp  rax, 2
    jb   .bad
    movzx ecx, byte [rbx + 1]
    cmp  ecx, 2
    jb   .bad
    lea  rax, [rbx + rcx]
    cmp  rax, r12
    ja   .bad
    movzx eax, byte [rbx]
    test eax, eax
    jz   .lapic
    cmp  eax, 9
    je   .x2apic
    jmp  .next
.lapic:
    cmp  ecx, 8
    jb   .bad
    test dword [rbx + 4], 1               ; enabled is authoritative
    jz   .next
    movzx eax, byte [rbx + 3]
    movzx edx, byte [rbx + 2]
    call smp_topology_add
    jc   .bad
    jmp  .next
.x2apic:
    cmp  ecx, 16
    jb   .bad
    test dword [rbx + 8], 1
    jz   .next
    mov  eax, [rbx + 4]
    mov  edx, [rbx + 12]
    call smp_topology_add
    jc   .bad
.next:
    movzx eax, byte [rbx + 1]
    add  rbx, rax
    jmp  .walk
.ok:
    clc
    jmp  .out
.bad:
    stc
.out:
    pop  r12
    pop  rbx
    ret

; Synthetic disabled+duplicate+sparse+x2APIC fixture.  It runs through the same
; parser as firmware and must retain the full 0x00000123 APIC id.
smp_topology_fixture_selftest:
    call smp_topology_clear
    lea  rdi, [rel smp_madt_fixture]
    lea  rsi, [rel smp_madt_fixture_end]
    call smp_topology_parse_entries
    jc   .fail
    cmp  dword [rel smp_enabled_count], 3  ; enabled means unique usable processors
    jne  .fail
    cmp  dword [rel smp_duplicate_count], 1
    jne  .fail
    cmp  dword [rel smp_discovered_count], 3
    jne  .fail
    cmp  dword [rel cpu_apic_id], 0
    jne  .fail
    cmp  dword [rel cpu_apic_id + 4], 4
    jne  .fail
    cmp  dword [rel cpu_apic_id + 8], 0x123
    jne  .fail

    ; Fill the exact capacity, then require row 33 to degrade honestly without
    ; writing beyond any per-CPU array. This is the MADT helper used at boot.
    call smp_topology_clear
    xor  r8d, r8d
.overflow_fill:
    mov  eax, r8d
    mov  edx, r8d
    call smp_topology_add
    jc   .overflow_observed
    cmp  r8d, SMP_CPU_CAPACITY
    jae  .fail
    inc  r8d
    jmp  .overflow_fill
.overflow_observed:
    cmp  r8d, SMP_CPU_CAPACITY
    jne  .fail
    cmp  byte [rel smp_topology_overflow], 1
    jne  .fail
    cmp  dword [rel smp_discovered_count], SMP_CPU_CAPACITY
    jne  .fail
    cmp  dword [rel smp_enabled_count], SMP_CPU_CAPACITY
    jne  .fail
    mov  byte [rel smp_topology_fixture_ok], 1
    ret
.fail:
    mov  byte [rel smp_topology_fixture_ok], 0
    ret

smp_topology_discover:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    stc
    ret
.custody_free:
    call smp_topology_fixture_selftest
    call smp_topology_clear
    mov  rbx, [rel acpi_madt]
    test rbx, rbx
    jz   smp_topology_fallback
    mov  eax, [rbx + 4]
    cmp  eax, 44
    jb   smp_topology_fallback
    lea  rdi, [rbx + 44]
    lea  rsi, [rbx + rax]
    call smp_topology_parse_entries
    jnc  .parsed
    cmp  byte [rel smp_topology_overflow], 1
    jne  smp_topology_fallback
    ; Retain the admitted prefix and publish an explicit degraded lower bound.
    ; Never erase a valid >capacity MADT into a misleading BSP-only topology.
    mov  dword [rel smp_configured_count], SMP_CPU_CAPACITY + 1
    mov  dword [rel smp_failed_count], 1
.parsed:
    cmp  dword [rel smp_discovered_count], 0
    je   smp_topology_fallback
    call smp_lapic_read_id
    mov  [rel smp_bsp_apic], eax
    xor  ecx, ecx
.find_bsp:
    cmp  ecx, [rel smp_discovered_count]
    jae  .bsp_not_in_prefix
    lea  rdx, [rel cpu_apic_id]
    cmp  [rdx + rcx*4], eax
    je   .swap_bsp
    inc  ecx
    jmp  .find_bsp
.bsp_not_in_prefix:
    cmp  byte [rel smp_topology_overflow], 1
    jne  smp_topology_fallback
    ; If an oversized MADT lists the BSP after the admitted prefix, replace
    ; slot zero with its live APIC identity rather than lying about scale one.
    mov  [rel cpu_apic_id], eax
    mov  dword [rel cpu_uid], 0xFFFFFFFF
    ret
.swap_bsp:
    test ecx, ecx
    jz   .ordered
    mov  edx, [rel cpu_apic_id]
    lea  r8, [rel cpu_apic_id]
    mov  r9d, [r8 + rcx*4]
    mov  [rel cpu_apic_id], r9d
    mov  [r8 + rcx*4], edx
    mov  edx, [rel cpu_uid]
    lea  r8, [rel cpu_uid]
    mov  r9d, [r8 + rcx*4]
    mov  [rel cpu_uid], r9d
    mov  [r8 + rcx*4], edx
.ordered:
    cmp  byte [rel smp_topology_overflow], 0
    jne  .degraded
    ; MADT alone owns membership. CPU-local CPUID derives topology but never
    ; invents or removes a firmware processor row.
    mov  eax, [rel smp_discovered_count]
    mov  [rel smp_configured_count], eax
    mov  byte [rel smp_topology_exact], 1
.degraded:
    ret
smp_topology_fallback:
    ; Clean scale-1 degradation: retain the real BSP identity but do not earn
    ; the exact-MADT marker.
    call smp_topology_clear
    call smp_lapic_read_id
    mov  [rel smp_bsp_apic], eax
    xor  edx, edx
    call smp_topology_add
    mov  dword [rel smp_enabled_count], 1
    mov  dword [rel smp_configured_count], 1
    ret

; Fill package/core/thread from architectural CPUID topology on the processor
; itself. Structured 0x1f/0x0b wins when valid; AMD's extended topology is the
; capability-selected fallback. EDI=dense logical; CF on invalid facts.
smp_topology_local_init:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    stc
    ret
.custody_free:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    cmp  r12d, SMP_CPU_CAPACITY
    jae  .bad
    xor  eax, eax
    cpuid
    mov  r13d, eax                         ; maximum basic leaf
    xor  r8d, r8d                          ; runtime vendor enum
    cmp  ebx, 'Genu'
    jne  .vendor_amd
    cmp  edx, 'ineI'
    jne  .vendor_amd
    cmp  ecx, 'ntel'
    jne  .vendor_amd
    mov  r8d, SMP_VENDOR_INTEL
    jmp  .vendor_ready
.vendor_amd:
    cmp  ebx, 'Auth'
    jne  .vendor_ready
    cmp  edx, 'enti'
    jne  .vendor_ready
    cmp  ecx, 'cAMD'
    jne  .vendor_ready
    mov  r8d, SMP_VENDOR_AMD
.vendor_ready:
    test r12d, r12d
    jnz  .vendor_match
    mov  [rel smp_cpu_vendor], r8b
    jmp  .select_leaf
.vendor_match:
    cmp  r8b, [rel smp_cpu_vendor]
    jne  .bad

.select_leaf:
    cmp  r13d, 0x1F
    jb   .try_0b
    mov  r8d, 0x1F
    jmp  .structured_begin
.try_0b:
    cmp  r13d, 0x0B
    jb   .try_amd
    mov  r8d, 0x0B
.structured_begin:
    xor  r9d, r9d
    mov  r10d, 0xFFFFFFFF                  ; SMT shift
    xor  r11d, r11d                        ; highest/package shift
    xor  r14d, r14d                        ; full x2APIC identity
.structured_loop:
    mov  eax, r8d
    mov  ecx, r9d
    cpuid
    mov  r14d, edx
    mov  r15d, ebx
    and  r15d, 0xFFFF
    jz   .structured_done
    mov  r15d, ecx
    shr  r15d, 8
    and  r15d, 0xFF
    jz   .structured_done
    and  eax, 0x1F
    cmp  eax, r11d
    cmova r11d, eax
    cmp  r15d, 1
    jne  .structured_next
    mov  r10d, eax
.structured_next:
    inc  r9d
    cmp  r9d, 32
    jb   .structured_loop
.structured_done:
    cmp  r10d, 0xFFFFFFFF
    je   .structured_invalid
    cmp  r11d, r10d
    jb   .structured_invalid
    cmp  r11d, 31
    ja   .structured_invalid
    jmp  .structured_store
.structured_invalid:
    cmp  r8d, 0x1F
    jne  .try_amd
    cmp  r13d, 0x0B
    jb   .try_amd
    mov  r8d, 0x0B
    jmp  .structured_begin

.structured_store:
    lea  rdx, [rel cpu_apic_id]
    cmp  [rdx + r12*4], r14d
    jne  .bad
    mov  ecx, r11d
    mov  edx, r14d
    shr  edx, cl
    lea  rbx, [rel cpu_package]
    mov  [rbx + r12*4], edx
    mov  ecx, r10d
    mov  edx, r14d
    shr  edx, cl
    mov  ecx, r11d
    sub  ecx, r10d
    cmp  ecx, 31
    jae  .core_store
    mov  ebx, 1
    shl  ebx, cl
    dec  ebx
    and  edx, ebx
.core_store:
    lea  rbx, [rel cpu_core]
    mov  [rbx + r12*4], edx
    mov  ecx, r10d
    test ecx, ecx
    jz   .thread_zero
    mov  edx, 1
    shl  edx, cl
    dec  edx
    and  edx, r14d
    jmp  .thread_store
.thread_zero:
    xor  edx, edx
.thread_store:
    lea  rbx, [rel cpu_thread]
    mov  [rbx + r12*4], edx
    test r12d, r12d
    jnz  .good
    mov  [rel smp_topology_leaf], r8d
    jmp  .good

.try_amd:
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_AMD
    jne  .bad
    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x8000001E
    jb   .bad
    ; The maximum extended leaf alone does not make the topology fields valid.
    ; AMD reserves Fn8000_001E when Fn8000_0001_ECX[TopologyExtensions] is clear.
    mov  eax, 0x80000001
    xor  ecx, ecx
    cpuid
    bt   ecx, 22
    jnc  .bad
    mov  eax, 0x8000001E
    xor  ecx, ecx
    cpuid
    mov  r14d, eax
    mov  r15d, ebx
    lea  rdx, [rel cpu_apic_id]
    cmp  [rdx + r12*4], r14d
    jne  .bad
    mov  r10d, r15d
    shr  r10d, 8
    and  r10d, 0xFF
    inc  r10d
    xor  r11d, r11d
    mov  eax, 1
.amd_thread_bits:
    cmp  eax, r10d
    jae  .amd_thread_ready
    shl  eax, 1
    inc  r11d
    cmp  r11d, 8
    jb   .amd_thread_bits
    jmp  .bad
.amd_thread_ready:
    mov  eax, 0x80000008
    xor  ecx, ecx
    cpuid
    mov  r13d, ecx
    shr  r13d, 12
    and  r13d, 0x0F
    test r13d, r13d
    jnz  .amd_package_bits
    and  ecx, 0xFF
    inc  ecx
    mov  eax, 1
.amd_core_bits:
    cmp  eax, ecx
    jae  .amd_package_bits
    shl  eax, 1
    inc  r13d
    cmp  r13d, 16
    jb   .amd_core_bits
    jmp  .bad
.amd_package_bits:
    cmp  r13d, r11d
    jb   .bad
    mov  ecx, r13d
    mov  edx, r14d
    shr  edx, cl
    lea  rbx, [rel cpu_package]
    mov  [rbx + r12*4], edx
    mov  edx, r15d
    and  edx, 0xFF
    lea  rbx, [rel cpu_core]
    mov  [rbx + r12*4], edx
    mov  ecx, r11d
    xor  edx, edx
    test ecx, ecx
    jz   .amd_thread_store
    mov  edx, 1
    shl  edx, cl
    dec  edx
    and  edx, r14d
.amd_thread_store:
    lea  rbx, [rel cpu_thread]
    mov  [rbx + r12*4], edx
    test r12d, r12d
    jnz  .good
    mov  dword [rel smp_topology_leaf], 0x8000001E
.good:
    ; Retain this processor's own Intel CPUID.1AH:EAX[31:24], alongside
    ; its already validated APIC/package/core/thread identity. Zero means
    ; unreported/unsupported, never an inferred E core. Preserve future raw
    ; values; 40h=Core (P), 20h=Atom (E), as in IDLEPROBE. No AP rendezvous,
    ; MSR access or scheduler policy is needed to read the inventory later.
    xor  edx, edx
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_INTEL
    jne  .type_store
    cmp  r13d, 0x1A
    jb   .type_store
    mov  eax, 0x1A
    xor  ecx, ecx
    cpuid
    shr  eax, 24
    mov  edx, eax
.type_store:
    lea  rax, [rel cpu_core_type]
    mov  [rax + r12], dl
    ; Local topology/APIC is validated. Retain this CPU's own observation before
    ; publishing BSP/ONLINE; unavailable observation is not topology failure.
    mov  edi, r12d
    lea  rax, [rel cpu_apic_id]
    mov  esi, [rax + r12*4]
    call cpu_security_percpu_capture
    mov  edi, r12d
    call smp_core_sibling_local_capture
    clc
    jmp  .out
.bad:
    stc
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Summarize only processors that completed CPU-local initialization, then rank
; one representative of every package/core pair before any SMT sibling. Dense
; logical identity is unchanged and every sibling remains eligible.
smp_topology_summarize:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel smp_placement_valid], 0
    mov  dword [rel smp_package_count], 0
    mov  dword [rel smp_physical_core_count], 0
    mov  dword [rel smp_threads_per_core], 0
    xor  r12d, r12d
.clear_rank:
    cmp  r12d, SMP_CPU_CAPACITY
    jae  .admit_begin
    lea  rax, [rel cpu_placement_rank]
    mov  dword [rax + r12*4], 0xFFFFFFFF
    inc  r12d
    jmp  .clear_rank
; Admit only complete, unique live CPU identities before assigning any rank.
; Degraded startup may leave FAILED/PENDING holes; those rows are not members.
.admit_begin:
    cmp  dword [rel smp_discovered_count], SMP_CPU_CAPACITY
    ja   .bad
    xor  r12d, r12d
.admit_cpu:
    cmp  r12d, [rel smp_discovered_count]
    jae  .first_pass
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r12], CPU_STATE_BSP
    je   .admit_facts
    cmp  byte [rax + r12], CPU_STATE_ONLINE
    jne  .admit_next
.admit_facts:
    lea  rax, [rel cpu_package]
    mov  r13d, [rax + r12*4]
    cmp  r13d, 0xFFFFFFFF
    je   .bad
    lea  rax, [rel cpu_core]
    mov  r14d, [rax + r12*4]
    cmp  r14d, 0xFFFFFFFF
    je   .bad
    lea  rax, [rel cpu_thread]
    mov  edx, [rax + r12*4]
    cmp  edx, 0xFFFFFFFF
    je   .bad
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r12*4]
    cmp  edi, 0xFFFFFFFF
    je   .bad
    xor  ebx, ebx
.admit_prior:
    cmp  ebx, r12d
    jae  .admit_next
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_BSP
    je   .admit_compare
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .admit_prior_next
.admit_compare:
    lea  rax, [rel cpu_apic_id]
    cmp  [rax + rbx*4], edi
    je   .bad                             ; duplicate live hardware identity
    lea  rax, [rel cpu_package]
    cmp  [rax + rbx*4], r13d
    jne  .admit_prior_next
    lea  rax, [rel cpu_core]
    cmp  [rax + rbx*4], r14d
    jne  .admit_prior_next
    lea  rax, [rel cpu_thread]
    cmp  [rax + rbx*4], edx
    je   .bad                             ; duplicate live logical identity
.admit_prior_next:
    inc  ebx
    jmp  .admit_prior
.admit_next:
    inc  r12d
    jmp  .admit_cpu
.first_pass:
    xor  r12d, r12d
    xor  r15d, r15d
.first_cpu:
    cmp  r12d, [rel smp_discovered_count]
    jae  .siblings
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r12], CPU_STATE_BSP
    je   .first_online
    cmp  byte [rax + r12], CPU_STATE_ONLINE
    jne  .first_next
.first_online:
    lea  rax, [rel cpu_package]
    mov  r13d, [rax + r12*4]
    lea  rax, [rel cpu_core]
    mov  r14d, [rax + r12*4]
    xor  ebx, ebx
.find_prior_core:
    cmp  ebx, r12d
    jae  .new_core
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_BSP
    je   .prior_online
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .prior_next
.prior_online:
    lea  rax, [rel cpu_package]
    cmp  [rax + rbx*4], r13d
    jne  .prior_next
    lea  rax, [rel cpu_core]
    cmp  [rax + rbx*4], r14d
    je   .first_next
.prior_next:
    inc  ebx
    jmp  .find_prior_core
.new_core:
    lea  rax, [rel cpu_placement_rank]
    mov  [rax + r12*4], r15d
    inc  r15d
    inc  dword [rel smp_physical_core_count]

    xor  ebx, ebx
.find_prior_package:
    cmp  ebx, r12d
    jae  .new_package
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_BSP
    je   .package_online
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .package_next
.package_online:
    lea  rax, [rel cpu_package]
    cmp  [rax + rbx*4], r13d
    je   .count_threads
.package_next:
    inc  ebx
    jmp  .find_prior_package
.new_package:
    inc  dword [rel smp_package_count]
.count_threads:
    xor  ebx, ebx
    xor  ecx, ecx
.thread_scan:
    cmp  ebx, [rel smp_discovered_count]
    jae  .thread_done
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_BSP
    je   .thread_online
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .thread_next
.thread_online:
    lea  rax, [rel cpu_package]
    cmp  [rax + rbx*4], r13d
    jne  .thread_next
    lea  rax, [rel cpu_core]
    cmp  [rax + rbx*4], r14d
    jne  .thread_next
    inc  ecx
.thread_next:
    inc  ebx
    jmp  .thread_scan
.thread_done:
    cmp  ecx, [rel smp_threads_per_core]
    jbe  .first_next
    mov  [rel smp_threads_per_core], ecx
.first_next:
    inc  r12d
    jmp  .first_cpu
.siblings:
    xor  r12d, r12d
.sibling_cpu:
    cmp  r12d, [rel smp_discovered_count]
    jae  .validate
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r12], CPU_STATE_BSP
    je   .sibling_online
    cmp  byte [rax + r12], CPU_STATE_ONLINE
    jne  .sibling_next
.sibling_online:
    lea  rax, [rel cpu_placement_rank]
    cmp  dword [rax + r12*4], 0xFFFFFFFF
    jne  .sibling_next
    mov  [rax + r12*4], r15d
    inc  r15d
.sibling_next:
    inc  r12d
    jmp  .sibling_cpu
.validate:
    cmp  r15d, [rel smp_topology_online]
    jne  .bad
    cmp  dword [rel smp_package_count], 0
    je   .bad
    cmp  dword [rel smp_physical_core_count], 0
    je   .bad
    cmp  dword [rel smp_threads_per_core], 0
    je   .bad
    mov  byte [rel smp_placement_valid], 1
    mov  eax, 1
    jmp  .out
.bad:
    mov  byte [rel smp_placement_valid], 0
    xor  ecx, ecx
.bad_clear:
    lea  rax, [rel cpu_placement_rank]
    mov  dword [rax + rcx*4], 0xFFFFFFFF
    inc  ecx
    cmp  ecx, SMP_CPU_CAPACITY
    jb   .bad_clear
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=preferred participant count -> EAX=dense logical membership mask.
smp_placement_prefix_mask:
    xor  eax, eax
    cmp  byte [rel smp_placement_valid], 1
    jne  .done
    cmp  dword [rel smp_discovered_count], SMP_CPU_CAPACITY
    ja   .done
    cmp  edi, SMP_CPU_CAPACITY
    ja   .done
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel smp_discovered_count]
    jae  .done
    lea  rdx, [rel cpu_placement_rank]
    cmp  [rdx + rcx*4], edi
    jae  .next
    bts  eax, ecx
.next:
    inc  ecx
    jmp  .scan
.done:
    ret

smp_lapic_init_local:
    jmp  smp_preempt_init_local

; Freeze one bounded load-observation window for all CHIP/per-logical rows.
; LAPIC timer samples classify a CPU as busy only when it was inside the shared
; scheduler or the timer itself completed one scheduler unit.  Every published
; row is copied into generation-owned storage before the lock is released.
; Task1330j1 extends that same window with two owner-local APERF/MPERF edges.
; AP rows run from smp_frequency_worker_tick on their existing scheduler path;
; the command-running BSP executes the identical reader locally.  Capability,
; nominal base and both counters are frozen per edge so a partial/mixed result
; can never inherit bytes from an older generation.
smp_frequency_sample_local:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    lea  rax, [rel smp_freq_worker_capable]
    mov  byte [rax + r13], 0
    lea  rax, [rel smp_freq_worker_source]
    mov  byte [rax + r13], SMP_FREQ_SOURCE_UNSUPPORTED
    lea  rax, [rel smp_freq_worker_base]
    mov  dword [rax + r13*4], 0
    lea  rax, [rel smp_freq_worker_aperf]
    mov  qword [rax + r13*8], 0
    lea  rax, [rel smp_freq_worker_mperf]
    mov  qword [rax + r13*8], 0

    xor  eax, eax
    cpuid
    mov  r12d, eax                         ; maximum basic leaf on this CPU
    cmp  r12d, 6
    jb   .out
    mov  eax, 6
    xor  ecx, ecx
    cpuid
    test ecx, 1                            ; architectural APERF/MPERF capability
    jz   .out
    lea  rax, [rel smp_freq_worker_capable]
    mov  byte [rax + r13], 1
    lea  rax, [rel smp_freq_worker_source]
    mov  byte [rax + r13], SMP_FREQ_SOURCE_NO_BASE

    cmp  r12d, 0x16
    jb   .platform_fallback
    mov  eax, 0x16
    xor  ecx, ecx
    cpuid
    and  eax, 0xFFFF                       ; CPUID.16H:EAX nominal base MHz
    jz   .platform_fallback
    lea  rdx, [rel smp_freq_worker_base]
    mov  [rdx + r13*4], eax
    lea  rdx, [rel smp_freq_worker_source]
    mov  byte [rdx + r13], SMP_FREQ_SOURCE_CPUID16
    jmp  .read_counters
.platform_fallback:
    ; Port the governor's proven safety gate and decode locally: only Intel
    ; CPUs advertising HWP may read PLATFORM_INFO, and the fixed-BCLK fallback
    ; is used only when CPUID.16H supplied no nominal base.
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_INTEL
    jne  .read_counters
    mov  eax, 6
    xor  ecx, ecx
    cpuid
    test eax, (1 << 7)
    jz   .read_counters
    mov  ecx, 0xCE
    rdmsr
    shr  eax, 8
    and  eax, 0xFF
    imul eax, eax, 100
    test eax, eax
    jz   .read_counters
    lea  rdx, [rel smp_freq_worker_base]
    mov  [rdx + r13*4], eax
    lea  rdx, [rel smp_freq_worker_source]
    mov  byte [rdx + r13], SMP_FREQ_SOURCE_PLATFORM
.read_counters:
    mov  ecx, SMP_FREQ_MSR_MPERF
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    lea  rbx, [rel smp_freq_worker_mperf]
    mov  [rbx + r13*8], rax
    mov  ecx, SMP_FREQ_MSR_APERF
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    lea  rbx, [rel smp_freq_worker_aperf]
    mov  [rbx + r13*8], rax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; smp_halt_wait_us(EDI = microseconds) — the LOAD/HEALTH sample window on the CPU
;   that serves the command (the BSP). RCQ-27 B1: tsc_delay_us SPINS, so that CPU's
;   own APERF/MPERF row read 100 % C0 at boost for exactly the measured window
;   (PW61's "BSP never halts"). With IF set and the BSP's calibrated 1 kHz LAPIC tick
;   armed (smp_bsp_tick_calibrated, set by the C6 calibration) it halts until the TSC deadline instead:
;   each hlt ends at the next tick (<= 1 ms past the deadline) or any IRQ. Without
;   both it spins exactly as before. Clobbers RAX, RCX, RDX.
smp_halt_wait_us:
    cmp  byte [rel smp_bsp_tick_calibrated], 1
    jne  tsc_delay_us                      ; no calibrated 1 ms tick: a hlt could overshoot
    pushfq
    pop  rax
    test eax, 0x200
    jz   tsc_delay_us                      ; IF clear: hlt would not return on the tick
    push rbx
    call tsc_us_ticks
    mov  rbx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rbx, rax                          ; TSC deadline
.wait:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, rbx
    jae  .done
    push rdi
    push rsi
    cli
    xor  edi, edi                         ; this timed sample is BSP-only
    mov  esi, 1                           ; frozen TSA ABI: HLT
    call smp_idle_prepare
    pop  rsi
    pop  rdi
    test eax, eax
    jz   .spin_wait
    sti
    hlt
    jmp  .wait
.spin_wait:
    sti
    pause                                 ; bounded by the same original TSC deadline
    jmp  .wait
.done:
    pop  rbx
    ret

; smp_bsp_idle_hlt — the BSP idle loop's halt (boot/header.asm .halt) with residency
;   accounting: TSC cycles from entering hlt to resuming (the waking handler's time
;   included) add to smp_bsp_hlt_tsc and smp_bsp_hlt_count counts the halts. STATUS
;   publishes them with TSC, so two reads give CPU0's halted share without
;   perturbing it (RCQ-27 B1). The halt is smp_idle_enter's, so an MWAIT
;   residency counts the same way (L2). Clobbers RAX, RDX.
smp_bsp_idle_hlt:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel smp_bsp_hlt_enter], rax
    push rcx
    push rdi
    cli
    xor  edi, edi                         ; the BSP is dense logical 0
    call smp_idle_enter                   ; RCQ-27 L2: hlt, or MWAIT where the row allows it
    pop  rdi
    pop  rcx
    test eax, eax
    jz   .no_idle                         ; refusal is not halted residency
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel smp_bsp_hlt_enter]
    add  [rel smp_bsp_hlt_tsc], rax
    inc  qword [rel smp_bsp_hlt_count]
.no_idle:
    ret

; Bounded, passive per-CPU idle entry snapshot, caller-owned SIO_SZ bytes.
; Serialized BSP command only: boot topology has finished publishing and cannot
; change. APs own their aligned counter qwords and publish one cached check byte.
; Loads are individually atomic, sequential samples; never infer residency/time.
; No active CPU check, CPUID, port/MSR access, IRQ mask or rendezvous here.
SIO_TOPO equ 0
SIO_NCPU equ 4
SIO_CPU equ 8
SIO_LIVE equ 12
SIO_MASK equ 16
SIO_HALTS equ 24
SIO_DEEP equ 32
SIO_CHECK equ 40
SIO_SZ equ 56

; RDI writable SIO_SZ bytes, ESI dense CPU or -1. Caller-saved clobbers only.
smp_idle_observation_snapshot:
    mov  r8, rdi
    xor  eax, eax
    mov  ecx, SIO_SZ / 8
    rep  stosq
    mov  rdi, r8
    mov  [rdi + SIO_CPU], esi
    mov  ecx, [rel smp_discovered_count]
    test ecx, ecx
    jz   .out
    cmp  ecx, MAXCORE
    ja   .out                             ; invalid topology: never touch arrays
    mov  dword [rdi + SIO_TOPO], 1
    xor  edx, edx
    xor  r9d, r9d
    xor  r10d, r10d
    lea  r11, [rel cpu_state]
.scan:
    movzx eax, byte [r11 + rdx]
    cmp  eax, CPU_STATE_BSP
    je   .online
    cmp  eax, CPU_STATE_ONLINE
    jne  .next
.online:
    bts  r9, rdx
    inc  r10d
.next:
    inc  edx
    cmp  edx, ecx
    jb   .scan
    mov  [rdi + SIO_MASK], r9
    mov  [rdi + SIO_NCPU], r10d
    cmp  esi, ecx
    jae  .out                             ; includes summary (-1)
    bt   r9, rsi
    jnc  .out                             ; offline/stale slots never observed
.cpu_live:
    mov  dword [rdi + SIO_LIVE], 1
    lea  rax, [rel smp_idle_cpu_state]
    movzx eax, byte [rax + rsi]
    mov  [rdi + SIO_CHECK], eax
    lea  rax, [rel smp_idle_hlt_count]
    mov  rax, [rax + rsi*8]
    mov  [rdi + SIO_HALTS], rax
    lea  rax, [rel smp_idle_mwait_count]
    mov  rax, [rax + rsi*8]
    mov  [rdi + SIO_DEEP], rax
.out:
    ret

; ---------------------------------------------------------------------------
; RCQ-27 B2 L2 — the one idle entry (root 13:31 c1, srcreview 13:13 c1-c6, root
; 16:20 irq-depth guard). Both idle loops call it: the BSP's smp_bsp_idle_hlt and
; the AP scheduler's .idle_pause. smp_halt_wait_us and every deadline wait keep
; their own checked HLT frontier and never come here.
; smp_idle_enter(EDI = dense logical CPU), entered with IF=0; returns IF=1,
; EAX1 after an actual idle/wake,0 after bounded policy-refused PAUSE.
; The deep form runs only when every check passes:
;   - smp_idle_hint != -1: svc/idle_probe sets it this boot from a matched
;     per-target row with no NVRAM opt-out (owner IDLEDEPTH); -1 is the default.
;     It is read ONCE per entry and that value stays on the stack: every check
;     below and the MWAIT use the same snapshot, so a concurrent IDLEDEPTH or
;     probe store lands on the next entry, never between the check and MWAIT;
;   - cpu_irq_depth[cpu] == 0: never inside an interrupt frame (else refused);
;   - this CPU's own CPUID (smp_idle_check_local, once per CPU: hybrid P/E
;     cores each answer for themselves): MONITOR/MWAIT, the 05H extensions with
;     interrupt break, ARAT, no hypervisor; and the 05H:EDX sub-state count of
;     the hint's C-state is nonzero and above the hint's sub-state (CPUID 05H:EDX
;     sub C-states per MWAIT C-state, Intel SDM Vol 2A).
;   Deep: MONITOR this CPU's own 64-byte line, MWAIT EAX=hint ECX=1 (an
;   interrupt breaks it although IF=0, so one that arrived after the caller's
;   checks is never lost), then sti delivers it. Otherwise sti;hlt (atomic),
;   counted after wake in smp_idle_hlt_count[cpu] (RCQ-12: SMPSTAT CPU halts=,
;   IDLEPROBE halts= sums them); MWAIT and IO entries count in smp_idle_mwait_count.
;   L1 (AMD, root 14:46 step iii): when smp_idle_io_base != 0 the hint is an
;   offset 1..7 into the core's trapped C-state window and the deep form is one
;   IN from base+offset (the ACPI _CST SystemIO entry register, ACPI 6.5 8.1.3;
;   trapped in this thread's MSRC001_0073 window for C-state entry requests, AMD
;   PPR 17h/18h p.138 and 19h/11h p.64), issued in the shadow of sti, the
;   sti;hlt form: an enabled interrupt ends the C-state, so the entry rests on no
;   claim about IF=0 wakes. This assumes a shadow-held interrupt breaks the IO
;   C-state; ARAT alone does not prove it (later ticks may coalesce with a pending
;   tick). Metal must show every CPU's tick count advancing during C2 idle (about
;   1 kHz on the BSP, 62 Hz on a parked AP); a stalled count fails the row. The
;   per-CPU check is then AMD's: no hypervisor, ARAT, and this thread's
;   MSRC001_0073[15:0] == smp_idle_io_base.
;   Clobbers RAX, RCX, RDX.
; ---------------------------------------------------------------------------
smp_idle_enter:
    mov  eax, [rel smp_idle_hint]         ; the one read of the hint this entry
    push rax                              ; [rsp] = that snapshot until MWAIT
    cmp  eax, -1
    je   .hlt_pop
    cmp  edi, MAXCORE
    jae  .hlt_pop
    lea  rcx, [rel cpu_irq_depth]
    cmp  byte [rcx + rdi], 0
    jne  .in_irq
    lea  rcx, [rel smp_idle_cpu_state]
    movzx edx, byte [rcx + rdi]
    test edx, edx
    jnz  .checked
    call smp_idle_check_local
    lea  rcx, [rel smp_idle_cpu_state]
    movzx edx, byte [rcx + rdi]
.checked:
    mov  eax, [rsp]                       ; the snapshot, never a re-read
    cmp  dword [rel smp_idle_io_base], 0  ; written before the hint, never cleared
    jne  .io
    cmp  edx, SMP_IDLE_CPU_OK             ; this CPU passed the MWAIT check
    jne  .hlt_pop
    mov  ecx, eax
    shr  ecx, 4
    and  ecx, 0x0F                        ; the hint's C-state - 1
    inc  ecx
    shl  ecx, 2                           ; its 05H:EDX nibble
    cmp  ecx, 32
    jae  .hlt_pop
    lea  rdx, [rel smp_idle_cpu_edx5]
    mov  edx, [rdx + rdi*4]
    shr  edx, cl
    and  edx, 0x0F                        ; sub-states of that C-state
    and  eax, 0x0F                        ; the hint's sub-state
    cmp  eax, edx
    jae  .hlt_pop                         ; 0 sub-states, or past the last one
    push rsi
    mov  esi, 2                           ; clear BEFORE MONITOR, not just MWAIT
    call smp_idle_prepare
    pop  rsi
    test eax, eax
    jz   .refused_pop
    mov  eax, edi
    shl  eax, 6
    lea  rcx, [rel smp_idle_lines]
    add  rax, rcx
    xor  ecx, ecx
    xor  edx, edx
    monitor                               ; RAX = this CPU's line, no extensions
    pop  rax                              ; EAX = the checked snapshot
    mov  ecx, 1                           ; break on interrupt even with IF=0
    mwait
    sti
    lea  rcx, [rel smp_idle_mwait_count]
    lock inc qword [rcx + rdi*8]
    mov  eax, 1
    ret
.io:
    cmp  edx, SMP_IDLE_CPU_IO_OK          ; this CPU passed the IO-window check, not
    jne  .hlt_pop                         ; an MWAIT OK cached before the base was set
    mov  edx, [rel smp_idle_io_base]
    dec  eax                              ; the row's offset 1..7 -> 0..6
    cmp  eax, 7
    jae  .hlt_pop                         ; only inside the trapped window
    push rsi
    mov  esi, 3                           ; frozen TSA ABI: trapped IO idle
    call smp_idle_prepare
    pop  rsi
    test eax, eax
    jz   .refused_pop
    pop  rax                              ; original checked offset 1..7
    mov  edx, [rel smp_idle_io_base]
    add  edx, eax
    sti                                   ; IF first: the read sits in the sti shadow
    in   al, dx                           ; trapped by this core: a C-state entry request
    lea  rcx, [rel smp_idle_mwait_count]
    lock inc qword [rcx + rdi*8]
    mov  eax, 1
    ret
.in_irq:
    lock inc qword [rel smp_idle_irq_refusals]
.hlt_pop:
    add  rsp, 8                           ; drop the single hint snapshot
    push rsi
    mov  esi, 1                           ; HLT fallback is checked too
    call smp_idle_prepare
    pop  rsi
    test eax, eax
    jz   .refused
    sti
    hlt
    ; Count completed wakes only: no store may follow the successful clear
    ; before HLT/MONITOR/IO. Refused policy never increments idle counters.
    cmp  edi, MAXCORE
    jae  .woke
    lea  rcx, [rel smp_idle_hlt_count]
    inc  qword [rcx + rdi*8]
.woke:
    mov  eax, 1
    ret
.refused_pop:
    add  rsp, 8
.refused:
    sti
    pause                                 ; return to the cooperative scheduler
    xor  eax, eax
    ret

; Native final idle frontier. EDI=dense CPU, ESI=kind1/2/3; IF0.
; EAX1 permits the instruction,0 refuses. All other GPRs preserved so no
; state stores/helper calls are needed after SEC's memory VERW+LFENCE.
; Exact full owner and fresh calling-CPU policy are checked by SEC every time;
; no global cached applicability or retained receipt authorizes idle. A native
; core lease (including poison) excludes ALL idle entries, on Intel and AMD.
smp_idle_prepare:
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    cmp  edi, MAXCORE
    jae  .refuse
    cmp  edi, [rel smp_discovered_count]
    jae  .refuse
    cmp  byte [rel smp_topology_exact], 1
    jne  .refuse
    cmp  qword [rel smp_core_custody_gate], 0
    jne  .refuse
    lea  rax, [rel cpu_irq_depth]
    cmp  byte [rax + rdi], 0
    jne  .refuse
    lea  rax, [rel cpu_state]
    test edi, edi
    jnz  .ap
    cmp  byte [rax], CPU_STATE_BSP
    jne  .refuse
    jmp  .owner
.ap:
    cmp  byte [rax + rdi], CPU_STATE_ONLINE
    jne  .refuse
.owner:
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + rdi*4]                ; full32 identity, never the dense id
    mov  edx, 1                           ; frozen policy ABI version1
    call cpu_idle_tsa_prepare
    cmp  eax, 1                           ; ONLY exact CLEARED0/NOT_REQUIRED1
    seta al
    xor  al, 1
    movzx eax, al
    jmp  .out
.refuse:
    xor  eax, eax
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    ret

; RC power I1 (root RC-power-service-20261017): a parked AP's LAPIC timer.
; The periodic tick only dispatches PREEMPT-mode units and counts samples, and a
; parked AP has neither (a live job or par_for keeps it in .spin_sti). So it
; ticks every SMP_IDLE_TICK_STRETCH calibrated ms instead of every 1 ms
; (Windows' default tick is 15.6 ms). Work for a parked AP arrives by IPI: job
; kicks, par_for, coherence/TLB, rearm, and every BSP request that APs poll for
; (smp_pf_kick_aps right after it publishes). The stretched tick only bounds a
; missed wake, well inside every poller's window (50 ms and up).
; smp_idle_tick_stretch writes the count on every park (a rearm IPI may have put
; the 1 ms count back); smp_idle_tick_restore writes the 1 ms count only after
; a stretch, so the spin path never restarts a running countdown.
; Both run on the AP itself with IF=0. EDI = dense logical CPU.
; Clobbers RAX, RCX, RDX, RSI.
smp_idle_tick_stretch:
    cmp  edi, MAXCORE
    jae  .out
    lea  rax, [rel smp_idle_tick_stretched]
    mov  byte [rax + rdi], 1
    mov  edx, [rel smp_timer_initial_count]
    cmp  edx, 0xFFFFFFFF / SMP_IDLE_TICK_STRETCH
    jbe  .scale
    mov  edx, 0xFFFFFFFF / SMP_IDLE_TICK_STRETCH
.scale:
    imul edx, edx, SMP_IDLE_TICK_STRETCH
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    jmp  smp_lapic_write32
.out:
    ret

smp_idle_tick_restore:
    cmp  edi, MAXCORE
    jae  .out
    lea  rax, [rel smp_idle_tick_stretched]
    cmp  byte [rax + rdi], 0
    je   .out
    mov  byte [rax + rdi], 0
    mov  edx, [rel smp_timer_initial_count]
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    jmp  smp_lapic_write32
.out:
    ret

; smp_idle_check_local(EDI = dense logical CPU) — on the CPU itself, once: store
;   SMP_IDLE_CPU_OK (MWAIT check), SMP_IDLE_CPU_IO_OK (L1 IO-window check, when
;   smp_idle_io_base != 0) or SMP_IDLE_CPU_NO in smp_idle_cpu_state[cpu] and its CPUID
;   05H:EDX in smp_idle_cpu_edx5[cpu]. Each path accepts only its own OK. Read-only (CPUID; on the L1 path one
;   RDMSR, only after AuthenticAMD and no hypervisor). Clobbers RAX, RCX, RDX.
smp_idle_check_local:
    push rbx
    push r8
    mov  r8d, SMP_IDLE_CPU_NO
    xor  eax, eax
    cpuid
    cmp  eax, 6
    jb   .store                           ; no leaf 05H/06H
    cmp  dword [rel smp_idle_io_base], 0
    jne  .amd_io
    mov  eax, 1
    cpuid
    bt   ecx, 3                           ; MONITOR/MWAIT
    jnc  .store
    bt   ecx, 31                          ; a hypervisor: plain hlt
    jc   .store
    mov  eax, 5
    xor  ecx, ecx
    cpuid
    test ecx, 1                           ; 05H extensions enumerated
    jz   .store
    test ecx, 2                           ; interrupts break MWAIT with IF=0
    jz   .store
    lea  rax, [rel smp_idle_cpu_edx5]
    mov  [rax + rdi*4], edx
    mov  eax, 6
    cpuid
    test eax, 4                           ; ARAT: the LAPIC timer runs in deep states
    jz   .store
    mov  r8d, SMP_IDLE_CPU_OK
    jmp  .store
.amd_io:
    cmp  ebx, 0x68747541                  ; "Auth" "enti" "cAMD"
    jne  .store
    cmp  edx, 0x69746e65
    jne  .store
    cmp  ecx, 0x444d4163
    jne  .store
    mov  eax, 1
    cpuid
    bt   ecx, 31                          ; a hypervisor: plain hlt
    jc   .store
    mov  eax, 6
    cpuid
    test eax, 4                           ; ARAT
    jz   .store
    mov  ecx, 0xC0010073                  ; CStateBaseAddr, per thread (PPR 19h)
    rdmsr
    and  eax, 0xFFFF
    cmp  eax, [rel smp_idle_io_base]      ; this thread traps the row's window
    jne  .store
    mov  r8d, SMP_IDLE_CPU_IO_OK
.store:
    lea  rax, [rel smp_idle_cpu_state]
    mov  [rax + rdi], r8b
    pop  r8
    pop  rbx
    ret

; Publish one edge and require every CPU in the generation's frozen online
; mask to acknowledge that exact epoch.  EAX=1 success, 0 timeout/partial.
smp_frequency_publish_edge:
    push rbx
    push r12
    inc  dword [rel smp_freq_request_epoch]
    jnz  .epoch_ready
    inc  dword [rel smp_freq_request_epoch]
.epoch_ready:
    mov  r12d, [rel smp_freq_request_epoch]
    mov  dword [rel smp_freq_ack_mask], 0
    mfence
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick

    xor  edi, edi                          ; BSP owns dense logical zero
    call smp_frequency_sample_local
    lea  rax, [rel smp_freq_worker_epoch]
    mov  [rax], r12d
    lock bts dword [rel smp_freq_ack_mask], 0

    mov  ebx, SMP_FREQ_WAIT_STEPS
.wait:
    mov  eax, [rel smp_freq_ack_mask]
    and  eax, [rel smp_freq_required_mask]
    cmp  eax, [rel smp_freq_required_mask]
    je   .ok
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait
    xor  eax, eax
    jmp  .out
.ok:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

; First edge: freeze exact membership and copy the complete owner-local rows.
smp_frequency_snapshot_prepare:
    push rbx
    push r12
    call smp_online_mask_now
    mov  [rel smp_freq_required_mask], eax
    test eax, 1
    jz   .bad
    call smp_popcount32
    cmp  eax, [rel smp_topology_online]
    jne  .bad
    call smp_frequency_publish_edge
    test eax, eax
    jz   .bad
    mov  r12d, [rel smp_freq_request_epoch]
    xor  ebx, ebx
.copy:
    cmp  ebx, [rel smp_topology_online]
    jae  .ok
    lea  rax, [rel smp_freq_worker_epoch]
    cmp  [rax + rbx*4], r12d
    jne  .bad
    lea  rax, [rel smp_freq_worker_capable]
    mov  dl, [rax + rbx]
    lea  rax, [rel smp_freq_base_capable]
    mov  [rax + rbx], dl
    lea  rax, [rel smp_freq_worker_source]
    mov  dl, [rax + rbx]
    lea  rax, [rel smp_freq_base_source]
    mov  [rax + rbx], dl
    lea  rax, [rel smp_freq_worker_base]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smp_freq_base_mhz]
    mov  [rax + rbx*4], edx
    lea  rax, [rel smp_freq_worker_aperf]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_freq_base_aperf]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel smp_freq_worker_mperf]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_freq_base_mperf]
    mov  [rax + rbx*8], rdx
    inc  ebx
    jmp  .copy
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Second edge + arithmetic freeze.  Unsigned subtraction deliberately accepts
; architectural 64-bit counter wrap.  Impossible one-sided/overflowing deltas
; invalidate the whole generation instead of fabricating a MHz value.
smp_frequency_snapshot_finish:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call smp_frequency_publish_edge
    test eax, eax
    jz   .bad
    mov  r15d, [rel smp_freq_request_epoch]
    mov  dword [rel smp_freq_snapshot_capable], 0
    mov  dword [rel smp_freq_snapshot_measured], 0
    mov  dword [rel smp_freq_snapshot_idle], 0
    mov  dword [rel smp_freq_snapshot_active], 0
    mov  qword [rel smp_freq_snapshot_aperf_total], 0
    mov  qword [rel smp_freq_snapshot_mperf_total], 0
    mov  qword [rel smp_freq_snapshot_effective_total], 0
    mov  qword [rel smp_freq_snapshot_weighted_num], 0
    mov  qword [rel smp_freq_snapshot_active_mperf], 0
    mov  qword [rel smp_freq_snapshot_frequency], 0
    mov  qword [rel smp_freq_snapshot_effective_mean], 0
    mov  qword [rel smp_freq_snapshot_ratio], 0
    mov  qword [rel smp_freq_snapshot_min], -1
    mov  qword [rel smp_freq_snapshot_max], 0
    mov  dword [rel smp_freq_snapshot_us], SMP_LOAD_WINDOW_US

    xor  ebx, ebx
.cpu:
    cmp  ebx, [rel smp_topology_online]
    jae  .aggregate
    mov  eax, [rel smp_freq_required_mask]
    bt   eax, ebx
    jnc  .bad
    lea  rax, [rel smp_freq_worker_epoch]
    cmp  [rax + rbx*4], r15d
    jne  .bad
    lea  rax, [rel smp_freq_worker_capable]
    mov  dl, [rax + rbx]
    lea  rax, [rel smp_freq_base_capable]
    cmp  [rax + rbx], dl
    jne  .bad
    lea  rax, [rel smp_freq_worker_source]
    mov  dl, [rax + rbx]
    lea  rax, [rel smp_freq_base_source]
    cmp  [rax + rbx], dl
    jne  .bad
    lea  rax, [rel smp_freq_worker_base]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smp_freq_base_mhz]
    cmp  [rax + rbx*4], edx
    jne  .bad

    lea  rax, [rel smp_freq_base_capable]
    cmp  byte [rax + rbx], 1
    jne  .unsupported
    inc  dword [rel smp_freq_snapshot_capable]
    lea  rax, [rel smp_freq_worker_aperf]
    mov  r12, [rax + rbx*8]
    lea  rax, [rel smp_freq_base_aperf]
    sub  r12, [rax + rbx*8]
    lea  rax, [rel smp_freq_worker_mperf]
    mov  r13, [rax + rbx*8]
    lea  rax, [rel smp_freq_base_mperf]
    sub  r13, [rax + rbx*8]
    lea  rax, [rel smp_freq_snapshot_aperf]
    mov  [rax + rbx*8], r12
    lea  rax, [rel smp_freq_snapshot_mperf]
    mov  [rax + rbx*8], r13
    add  [rel smp_freq_snapshot_aperf_total], r12
    jc   .bad
    add  [rel smp_freq_snapshot_mperf_total], r13
    jc   .bad
    test r13, r13
    jnz  .measured
    test r12, r12
    jnz  .bad                              ; one counter advancing is anomalous
    lea  rax, [rel smp_freq_snapshot_state]
    mov  byte [rax + rbx], SMP_FREQ_STATE_IDLE
    lea  rax, [rel smp_freq_snapshot_effective]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel smp_freq_snapshot_ratio_cpu]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel smp_freq_snapshot_frequency_cpu]
    mov  qword [rax + rbx*8], 0
    inc  dword [rel smp_freq_snapshot_idle]
    jmp  .next
.measured:
    test r12, r12
    jz   .bad
    lea  rax, [rel smp_freq_snapshot_state]
    mov  byte [rax + rbx], SMP_FREQ_STATE_MEASURED
    inc  dword [rel smp_freq_snapshot_measured]

    mov  rax, r12
    xor  edx, edx
    mov  ecx, SMP_LOAD_WINDOW_US
    div  rcx
    lea  rdx, [rel smp_freq_snapshot_effective]
    mov  [rdx + rbx*8], rax
    add  [rel smp_freq_snapshot_effective_total], rax
    jc   .bad

    mov  rax, r12
    mov  ecx, 1000
    mul  rcx
    cmp  rdx, r13
    jae  .bad
    div  r13
    lea  rdx, [rel smp_freq_snapshot_ratio_cpu]
    mov  [rdx + rbx*8], rax

    lea  rax, [rel smp_freq_base_mhz]
    mov  r14d, [rax + rbx*4]
    test r14d, r14d
    jz   .no_active_mhz
    mov  rax, r12
    mul  r14
    test rdx, rdx
    jnz  .bad
    mov  r12, rax                          ; base * APERF, weighted numerator
    xor  edx, edx
    div  r13
    lea  rdx, [rel smp_freq_snapshot_frequency_cpu]
    mov  [rdx + rbx*8], rax
    inc  dword [rel smp_freq_snapshot_active]
    add  [rel smp_freq_snapshot_weighted_num], r12
    jc   .bad
    add  [rel smp_freq_snapshot_active_mperf], r13
    jc   .bad
    cmp  rax, [rel smp_freq_snapshot_min]
    jae  .min_ready
    mov  [rel smp_freq_snapshot_min], rax
.min_ready:
    cmp  rax, [rel smp_freq_snapshot_max]
    jbe  .next
    mov  [rel smp_freq_snapshot_max], rax
    jmp  .next
.no_active_mhz:
    lea  rax, [rel smp_freq_snapshot_frequency_cpu]
    mov  qword [rax + rbx*8], 0
    jmp  .next
.unsupported:
    lea  rax, [rel smp_freq_snapshot_state]
    mov  byte [rax + rbx], SMP_FREQ_STATE_UNSUPPORTED
    lea  rax, [rel smp_freq_snapshot_aperf]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel smp_freq_snapshot_mperf]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel smp_freq_snapshot_effective]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel smp_freq_snapshot_ratio_cpu]
    mov  qword [rax + rbx*8], 0
    lea  rax, [rel smp_freq_snapshot_frequency_cpu]
    mov  qword [rax + rbx*8], 0
.next:
    inc  ebx
    jmp  .cpu

.aggregate:
    mov  rax, [rel smp_freq_snapshot_effective_total]
    mov  ecx, [rel smp_topology_online]
    mov  edx, ecx
    shr  edx, 1
    add  rax, rdx
    jc   .bad
    xor  edx, edx
    div  rcx
    mov  [rel smp_freq_snapshot_effective_mean], rax

    cmp  dword [rel smp_freq_snapshot_measured], 0
    je   .ratio_ready
    mov  r13, [rel smp_freq_snapshot_mperf_total]
    test r13, r13
    jz   .bad
    mov  rax, [rel smp_freq_snapshot_aperf_total]
    mov  ecx, 1000
    mul  rcx
    cmp  rdx, r13
    jae  .bad
    div  r13
    mov  [rel smp_freq_snapshot_ratio], rax
.ratio_ready:
    cmp  dword [rel smp_freq_snapshot_active], 0
    je   .ok
    mov  rcx, [rel smp_freq_snapshot_active_mperf]
    test rcx, rcx
    jz   .bad
    mov  rax, [rel smp_freq_snapshot_weighted_num]
    xor  edx, edx
    div  rcx
    mov  [rel smp_freq_snapshot_frequency], rax
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

smp_load_snapshot_capture:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, [rel smp_topology_online]
    test r14d, r14d
    jz   .unavailable
    cmp  r14d, MAXCORE
    ja   .unavailable
    cmp  qword [rel tsc_khz], 0
    je   .unavailable
    lea  rdi, [rel smp_load_lock]
    call spin_acquire
    call smp_frequency_snapshot_prepare
    test eax, eax
    jz   .frequency_unavailable

    ; Freeze every baseline before opening the named measurement window.
    xor  ebx, ebx
.baseline:
    cmp  ebx, r14d
    jae  .window
    lea  rax, [rel cpu_load_busy_ticks]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_busy]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel cpu_irq_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_irq]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel cpu_preempt_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_preempt]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel cpu_context_switch_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_ctx]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel cpu_migration_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_migration]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel usched_steal_in]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smp_load_base_steal_in]
    mov  [rax + rbx*4], edx
    lea  rax, [rel usched_steal_out]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smp_load_base_steal_out]
    mov  [rax + rbx*4], edx
    inc  ebx
    jmp  .baseline

.window:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  edi, SMP_LOAD_WINDOW_US
    call smp_halt_wait_us                  ; RCQ-27 B1: the serving CPU halts through its own window
    call smp_frequency_snapshot_finish
    test eax, eax
    jz   .frequency_unavailable
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  [rel smp_load_snapshot_end_tsc], rax
    sub  rax, r12
    xor  edx, edx
    div  qword [rel tsc_khz]              ; calibrated cycles / cycles-per-ms
    test eax, eax
    jnz  .sample_ms_ready
    mov  eax, 1                            ; a non-empty sub-ms window rounds up
.sample_ms_ready:
    mov  [rel smp_load_snapshot_ms], eax
    mov  [rel smp_load_snapshot_logical], r14d
    mov  dword [rel smp_load_snapshot_sum], 0
    mov  dword [rel smp_load_snapshot_runq_total], 0
    mov  dword [rel smp_load_snapshot_runq_max], 0
    mov  dword [rel smp_load_snapshot_max], 0
    mov  dword [rel smp_load_snapshot_min], 1001
    mov  dword [rel smp_load_snapshot_busiest], 0
    mov  dword [rel smp_load_snapshot_healthy], 0
    mov  dword [rel smp_load_snapshot_stalled], 0
    mov  qword [rel smp_load_snapshot_last_progress_ms], 0

    xor  ebx, ebx
.freeze:
    cmp  ebx, r14d
    jae  .aggregate

    ; Timer-window utilization: busy timer samples / all timer samples.
    lea  rax, [rel cpu_irq_count]
    mov  r8, [rax + rbx*8]
    lea  rax, [rel smp_load_base_irq]
    sub  r8, [rax + rbx*8]
    lea  rax, [rel smp_load_snapshot_irq]
    mov  [rax + rbx*8], r8
    lea  rax, [rel cpu_load_busy_ticks]
    mov  rax, [rax + rbx*8]
    lea  rcx, [rel smp_load_base_busy]
    sub  rax, [rcx + rbx*8]
    test r8, r8
    jz   .zero_load
    mov  ecx, 1000
    mul  rcx
    div  r8
    cmp  rax, 1000
    jbe  .load_ready
    mov  eax, 1000                         ; racing edge cannot exceed one CPU
    jmp  .load_ready
.zero_load:
    xor  eax, eax
.load_ready:
    mov  r9d, eax
    lea  rcx, [rel smp_load_snapshot_load]
    mov  [rcx + rbx*4], eax

    lea  rax, [rel cpu_preempt_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_preempt]
    sub  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_snapshot_preempt]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel cpu_context_switch_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_ctx]
    sub  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_snapshot_ctx]
    mov  [rax + rbx*8], rdx
    mov  r15, rdx                          ; nonzero means real work ran in-window
    lea  rax, [rel cpu_migration_count]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_base_migration]
    sub  rdx, [rax + rbx*8]
    lea  rax, [rel smp_load_snapshot_migration]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel usched_steal_in]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smp_load_base_steal_in]
    sub  edx, [rax + rbx*4]
    lea  rax, [rel smp_load_snapshot_steal_in]
    mov  [rax + rbx*4], edx
    lea  rax, [rel usched_steal_out]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smp_load_base_steal_out]
    sub  edx, [rax + rbx*4]
    lea  rax, [rel smp_load_snapshot_steal_out]
    mov  [rax + rbx*4], edx

    ; The fixed per-CPU scheduler task plus any live unified-queue depth.
    ; coremap_counts is not a depth: smpwork publishes cumulative runs there.
    lea  rax, [rel usched_rq_tail]
    mov  r10d, [rax + rbx*4]
    lea  rax, [rel usched_rq_head]
    sub  r10d, [rax + rbx*4]
    jnc  .runq_dynamic_ready
    xor  r10d, r10d
.runq_dynamic_ready:
    lea  rax, [rel cpu_runq_ready]
    cmp  byte [rax + rbx], 1
    jne  .runq_fixed_ready
    inc  r10d                              ; the fixed per-CPU scheduler task
.runq_fixed_ready:
    lea  rax, [rel smp_load_snapshot_runq]
    mov  [rax + rbx*4], r10d

    ; Last explicit scheduler progress is a TSC timestamp, so idle CPUs report
    ; honest boot-relative age instead of an invented zero.
    lea  rax, [rel cpu_last_progress_tsc]
    mov  r11, [rax + rbx*8]
    test r11, r11
    jnz  .progress_origin_ready
    mov  r11, [rel time_monotonic_tsc_origin]
.progress_origin_ready:
    mov  rax, r13
    cmp  rax, r11
    jae  .progress_ordered
    mov  rax, r11
.progress_ordered:
    sub  rax, r11
    xor  edx, edx
    div  qword [rel tsc_khz]
    lea  rcx, [rel smp_load_snapshot_progress_age]
    mov  [rcx + rbx*8], rax
    cmp  rax, [rel smp_load_snapshot_last_progress_ms]
    jbe  .progress_max_ready
    mov  [rel smp_load_snapshot_last_progress_ms], rax
.progress_max_ready:
    lea  rcx, [rel cpu_fault_count]
    mov  edx, [rcx + rbx*4]
    lea  rcx, [rel smp_load_snapshot_faults]
    mov  [rcx + rbx*4], edx

    xor  edx, edx                         ; frozen current: idle=0, unified=1
    test r9d, r9d
    jnz  .current_busy
    test r15, r15
    jz   .current_ready
.current_busy:
    mov  edx, 1
.current_ready:
    lea  rcx, [rel smp_load_snapshot_current]
    mov  [rcx + rbx], dl

    ; Health is readiness plus a falsifiable queued-work progress bound.
    mov  edx, 1
    lea  rcx, [rel cpu_state]
    cmp  ebx, 0
    jne  .health_ap
    cmp  byte [rcx], CPU_STATE_BSP
    jne  .health_bad
    jmp  .health_ready_bits
.health_ap:
    cmp  byte [rcx + rbx], CPU_STATE_ONLINE
    jne  .health_bad
.health_ready_bits:
    lea  rcx, [rel cpu_timer_ready]
    cmp  byte [rcx + rbx], 1
    jne  .health_bad
    lea  rcx, [rel cpu_runq_ready]
    cmp  byte [rcx + rbx], 1
    jne  .health_bad
    cmp  byte [rel usched_job_active], 1
    jne  .health_store
    cmp  r10d, 1                           ; dynamic queued work exists
    jbe  .health_store
    lea  rcx, [rel smp_load_snapshot_progress_age]
    cmp  qword [rcx + rbx*8], SMP_LOAD_STALL_MS
    jbe  .health_store
    inc  dword [rel smp_load_snapshot_stalled]
.health_bad:
    xor  edx, edx
.health_store:
    lea  rcx, [rel smp_load_snapshot_health]
    mov  [rcx + rbx], dl
    test edx, edx
    jz   .aggregate_cpu
    inc  dword [rel smp_load_snapshot_healthy]

.aggregate_cpu:
    add  [rel smp_load_snapshot_sum], r9d
    add  [rel smp_load_snapshot_runq_total], r10d
    cmp  r10d, [rel smp_load_snapshot_runq_max]
    jbe  .runq_max_ready
    mov  [rel smp_load_snapshot_runq_max], r10d
.runq_max_ready:
    cmp  r9d, [rel smp_load_snapshot_max]
    jbe  .load_max_ready
    mov  [rel smp_load_snapshot_max], r9d
    mov  [rel smp_load_snapshot_busiest], ebx
.load_max_ready:
    cmp  r9d, [rel smp_load_snapshot_min]
    jae  .next_cpu
    mov  [rel smp_load_snapshot_min], r9d
.next_cpu:
    inc  ebx
    jmp  .freeze

.aggregate:
    mov  eax, [rel smp_load_snapshot_sum]
    mov  ecx, r14d
    shr  ecx, 1
    add  eax, ecx                          ; host oracle uses rounded mean
    xor  edx, edx
    div  r14d
    mov  [rel smp_load_snapshot_mean], eax
    mov  eax, [rel smp_load_snapshot_max]
    sub  eax, [rel smp_load_snapshot_min]
    mov  [rel smp_load_snapshot_imbalance], eax
    inc  dword [rel smp_load_snapshot_seq]
    jnz  .sequence_ready
    inc  dword [rel smp_load_snapshot_seq] ; zero is never a published generation
.sequence_ready:
    lea  rdi, [rel smp_load_lock]
    call spin_release
    mov  eax, 1
    jmp  .out
.frequency_unavailable:
    ; A failed edge may have touched staging rows.  Retire the previously
    ; addressable sequence before releasing the lock so no caller can combine
    ; those bytes with an older successful generation.
    inc  dword [rel smp_load_snapshot_seq]
    jnz  .frequency_invalidated
    inc  dword [rel smp_load_snapshot_seq]
.frequency_invalidated:
    mov  dword [rel smp_load_snapshot_logical], 0
    mov  dword [rel smp_freq_snapshot_us], 0
    lea  rdi, [rel smp_load_lock]
    call spin_release
.unavailable:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Independent boot-KAT reconciliation over the immutable frequency rows.
; Returns EAX=1 only when every per-CPU formula, count and chip aggregate agrees
; with the raw own-core deltas.  It accepts a wholly unsupported QEMU fixture,
; but never a partial/mixed/counter-anomalous generation.
smp_frequency_snapshot_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ecx, [rel smp_load_snapshot_logical]
    test ecx, ecx
    jz   .bad
    cmp  ecx, [rel smp_topology_online]
    jne  .bad
    cmp  dword [rel smp_freq_snapshot_us], SMP_LOAD_WINDOW_US
    jne  .bad
    mov  eax, [rel smp_freq_ack_mask]
    and  eax, [rel smp_freq_required_mask]
    cmp  eax, [rel smp_freq_required_mask]
    jne  .bad

    xor  r12d, r12d                       ; row
    xor  r13, r13                         ; APERF sum
    xor  r14, r14                         ; MPERF sum
    xor  r15, r15                         ; effective-MHz sum
    xor  ebx, ebx                         ; capable
    xor  r10d, r10d                       ; measured
    xor  r11d, r11d                       ; idle
    xor  r8d, r8d                         ; active-MHz available
.row:
    cmp  r12d, [rel smp_load_snapshot_logical]
    jae  .rows_done
    lea  rax, [rel smp_freq_snapshot_state]
    movzx eax, byte [rax + r12]
    cmp  eax, SMP_FREQ_STATE_UNSUPPORTED
    je   .unsupported
    cmp  eax, SMP_FREQ_STATE_IDLE
    je   .idle
    cmp  eax, SMP_FREQ_STATE_MEASURED
    jne  .bad
    inc  ebx
    inc  r10d
    lea  rax, [rel smp_freq_snapshot_aperf]
    mov  r9, [rax + r12*8]
    test r9, r9
    jz   .bad
    lea  rax, [rel smp_freq_snapshot_mperf]
    mov  rcx, [rax + r12*8]
    test rcx, rcx
    jz   .bad
    add  r13, r9
    jc   .bad
    add  r14, rcx
    jc   .bad
    mov  rax, r9
    xor  edx, edx
    mov  edi, SMP_LOAD_WINDOW_US
    div  rdi
    lea  rdx, [rel smp_freq_snapshot_effective]
    cmp  [rdx + r12*8], rax
    jne  .bad
    add  r15, rax
    jc   .bad
    mov  rax, r9
    mov  edi, 1000
    mul  rdi
    cmp  rdx, rcx
    jae  .bad
    div  rcx
    lea  rdx, [rel smp_freq_snapshot_ratio_cpu]
    cmp  [rdx + r12*8], rax
    jne  .bad
    lea  rax, [rel smp_freq_base_mhz]
    cmp  dword [rax + r12*4], 0
    je   .next
    inc  r8d
    jmp  .next
.idle:
    inc  ebx
    inc  r11d
    lea  rax, [rel smp_freq_snapshot_aperf]
    cmp  qword [rax + r12*8], 0
    jne  .bad
    lea  rax, [rel smp_freq_snapshot_mperf]
    cmp  qword [rax + r12*8], 0
    jne  .bad
    lea  rax, [rel smp_freq_snapshot_effective]
    cmp  qword [rax + r12*8], 0
    jne  .bad
    jmp  .next
.unsupported:
    lea  rax, [rel smp_freq_base_source]
    cmp  byte [rax + r12], SMP_FREQ_SOURCE_UNSUPPORTED
    jne  .bad
    lea  rax, [rel smp_freq_snapshot_aperf]
    cmp  qword [rax + r12*8], 0
    jne  .bad
    lea  rax, [rel smp_freq_snapshot_mperf]
    cmp  qword [rax + r12*8], 0
    jne  .bad
.next:
    inc  r12d
    jmp  .row

.rows_done:
    cmp  ebx, [rel smp_freq_snapshot_capable]
    jne  .bad
    cmp  r10d, [rel smp_freq_snapshot_measured]
    jne  .bad
    cmp  r11d, [rel smp_freq_snapshot_idle]
    jne  .bad
    cmp  r8d, [rel smp_freq_snapshot_active]
    jne  .bad
    cmp  r13, [rel smp_freq_snapshot_aperf_total]
    jne  .bad
    cmp  r14, [rel smp_freq_snapshot_mperf_total]
    jne  .bad
    cmp  r15, [rel smp_freq_snapshot_effective_total]
    jne  .bad
    mov  rax, r15
    mov  ecx, [rel smp_load_snapshot_logical]
    mov  edx, ecx
    shr  edx, 1
    add  rax, rdx
    jc   .bad
    xor  edx, edx
    div  rcx
    cmp  rax, [rel smp_freq_snapshot_effective_mean]
    jne  .bad
    test r10d, r10d
    jz   .ratio_done
    test r14, r14
    jz   .bad
    mov  rax, r13
    mov  ecx, 1000
    mul  rcx
    cmp  rdx, r14
    jae  .bad
    div  r14
    cmp  rax, [rel smp_freq_snapshot_ratio]
    jne  .bad
.ratio_done:
    test r8d, r8d
    jz   .ok

    xor  ebx, ebx                         ; second pass: active rows only
    xor  r13, r13                         ; weighted base*APERF
    xor  r14, r14                         ; active MPERF
    mov  r15, -1                          ; min active MHz
    xor  r12, r12                         ; max active MHz
.active_row:
    cmp  ebx, [rel smp_load_snapshot_logical]
    jae  .active_done
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + rbx], SMP_FREQ_STATE_MEASURED
    jne  .active_next
    lea  rax, [rel smp_freq_base_mhz]
    mov  r10d, [rax + rbx*4]
    test r10d, r10d
    jz   .active_next
    lea  rax, [rel smp_freq_snapshot_aperf]
    mov  r11, [rax + rbx*8]
    mov  rax, r11
    mul  r10
    test rdx, rdx
    jnz  .bad
    add  r13, rax
    jc   .bad
    lea  rcx, [rel smp_freq_snapshot_mperf]
    mov  rcx, [rcx + rbx*8]
    add  r14, rcx
    jc   .bad
    xor  edx, edx
    div  rcx
    lea  rdx, [rel smp_freq_snapshot_frequency_cpu]
    cmp  [rdx + rbx*8], rax
    jne  .bad
    cmp  rax, r15
    cmovb r15, rax
    cmp  rax, r12
    cmova r12, rax
.active_next:
    inc  ebx
    jmp  .active_row
.active_done:
    test r14, r14
    jz   .bad
    mov  rax, r13
    xor  edx, edx
    div  r14
    cmp  rax, [rel smp_freq_snapshot_frequency]
    jne  .bad
    cmp  r15, [rel smp_freq_snapshot_min]
    jne  .bad
    cmp  r12, [rel smp_freq_snapshot_max]
    jne  .bad
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Interpose only the SMPSTAT registration emitted by svc/command_smp.asm.  The
; registry remains the single vocabulary owner; SMPWORK and SMPBENCH pass
; through unchanged.
smp_command_register_verb:
    lea  rax, [rel cmd_verb_smpstat]
    cmp  rsi, rax
    jne  .pass
    lea  rsi, [rel cmd_verb_smpstat_topology]
.pass:
    jmp  command_register_verb

; EDI dense logical CPU. Append only the immutable local-init sample; reading
; this view never samples the calling CPU on behalf of a different processor.
; Missing/busy/identity-mismatched records expose ready=0 without stale fields.
; Read-only copied topology row, EDI=dense index, RSI=64-byte destination.
; All 32 slots may be queried, including absent/failed rows. No dispatch or I/O.
; EAX0 or -1; complete caller-owned 64B projection, original counts unmodified.
smp_cpu_report_copy:
    cmp edi,SMP_CPU_CAPACITY
    jae .bad
    mov r8d,edi
    mov r9,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
%macro PCR_TOPO 2
    mov eax,[rel %2]
    mov [r9+%1],eax
%endmacro
    PCR_TOPO 0,smp_discovered_count
    PCR_TOPO 4,smp_configured_count
    PCR_TOPO 8,smp_enabled_count
    PCR_TOPO 12,smp_topology_online
    lea rdx,[rel cpu_apic_id]
    mov eax,[rdx+r8*4]
    mov [r9+16],eax
    lea rdx,[rel cpu_state]
    movzx eax,byte [rdx+r8]
    mov [r9+20],eax
%macro PCR_ID 2
    lea rdx,[rel %2]
    mov eax,[rdx+r8*4]
    mov [r9+%1],eax
%endmacro
    PCR_ID 24,cpu_package
    PCR_ID 28,cpu_core
    PCR_ID 32,cpu_thread
%unmacro PCR_ID 2
    movzx eax,byte [rel smp_placement_valid]
    mov [r9+36],eax
    movzx eax,byte [rel smp_topology_exact]
    mov [r9+40],eax
    movzx eax,byte [rel smp_topology_overflow]
    mov [r9+44],eax
    mov dword [r9+48],SMP_CPU_CAPACITY
    PCR_TOPO 52,smp_failed_count
%unmacro PCR_TOPO 2
    cmp r8d,[rel smp_discovered_count]
    setb al
    movzx eax,al
    mov [r9+56],eax
    xor eax,eax
    ret
.bad:
    mov rax,-1
    ret

smpstat_cpu_security:
    push r12
    push r13
    push r14
    xor  r12d, r12d
    cmp  edi, SMP_CPU_CAPACITY
    jae  .header
    lea  rax, [rel cpu_apic_id]
    mov  esi, [rax + rdi*4]
    call cpu_security_percpu_get
    mov  r12, rax
.header:
    lea  rdi, [rel smpstat_sec_header]
    call smpobs_put_str
    xor  edi, edi
    test r12, r12
    setnz dil
    call smpobs_put_dec
    test r12, r12
    jz   .out
    lea  r13, [rel smpstat_sec_fields]
    mov  r14d, 11
.field:
    movsxd rdi, dword [r13]
    lea  rax, [rel smpstat_sec_fields]
    add  rdi, rax
    call smpobs_put_str
    mov  edx, [r13 + 4]
    cmp  dword [r13 + 8], 4
    jne  .qword
    mov  edi, [r12 + rdx]
    jmp  .number
.qword:
    mov  rdi, [r12 + rdx]
.number:
    call smpobs_put_dec
    add  r13, 12
    dec  r14d
    jnz  .field
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; EDI dense logical CPU. Read only the immutable early-AP attempt; no
; CPUID/MSR, dispatch, policy selection, BSP substitution or online gate.
; READY describes the record, not success. Negative result bits retain u32
; representation on the existing unsigned wire formatter (uc_result32).
smpstat_cpu_microcode:
    push r12
    push r13
    push r14
    push r15
    xor r15d,r15d
    xor  r12d, r12d
    cmp  edi, SMP_CPU_CAPACITY
    jae  .header
    lea  rax, [rel cpu_apic_id]
    mov  esi, [rax + rdi*4]
    lea rdx,[rel cpu_state]
    cmp byte [rdx + rdi],CPU_STATE_BSP
    je .bsp
    call cpu_microcode_percpu_get
    mov  r12, rax
.header:
    lea  rdi, [rel smpstat_uc_header]
    jmp .emit_header
.bsp:
    mov edi,esi
    call cpu_microcode_boot_checked_get
    mov r12,rax
    lea r15,[rel mcb_state]
    lea rdi,[rel smpstat_uc_bsp_header]
.emit_header:
    call smpobs_put_str
    xor  edi, edi
    test r12, r12
    setnz dil
    call smpobs_put_dec
    test r12, r12
    jz   .out
    lea  r13, [rel smpstat_uc_fields]
    test r15,r15
    jz .table_ready
    lea r13,[rel smpstat_uc_bsp_fields]
.table_ready:
    mov  r14d, 32
    test r15,r15
    jnz .field
    mov r14d,39                       ; additive AP cost tail; BSP unchanged
.field:
    movsxd rdi, dword [r13]
    lea  rax, [rel smpstat_uc_fields]
    add  rdi, rax
    call smpobs_put_str
    mov rax,r12
    cmp dword [r13 + 12],0
    je .source_ready
    mov rax,r15
.source_ready:
    mov  edx, [r13 + 4]
    cmp  dword [r13 + 8], 4
    jne  .qword
    mov  edi, [rax + rdx]
    jmp  .number
.qword:
    mov  rdi, [rax + rdx]
.number:
    call smpobs_put_dec
    add  r13, 16
    dec  r14d
    jnz  .field
.out:
    pop r15
    pop  r14
    pop  r13
    pop  r12
    ret

smpobs_begin_stat_v2:
    push rdi
    call smpobs_out_reset
    lea  rdi, [rel smpstat_v2_prefix]
    call smpobs_put_str
    pop  rdi
    call smpobs_put_hex16
    ret

; Topology-aware SMPSTAT projection.  It deliberately reuses the frozen v1
; nonce parser and bounded output cursor from the observability predecessor.
cmd_verb_smpstat_topology:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rdi
    mov  r15, rsi
    mov  rdi, [r14 + REQ_ARG]
    call smpobs_arg_bounded
    jc   .oversized
    mov  rdi, [r14 + REQ_ARG]
    call smpobs_parse_nonce
    jc   .bad_nonce
    mov  r12, rax
    mov  rbx, rdx
    cmp  byte [rbx], ' '
    jne  .malformed
    inc  rbx
    cmp  dword [rbx], 'SUMM'
    jne  .check_cpu
    cmp  dword [rbx + 4], 'ARY'
    jne  .check_cpu
    cmp  byte [rbx + 7], 0
    je   .summary
.check_cpu:
    cmp  dword [rbx], 'CPU '
    jne  .check_coherence
    lea  rdi, [rbx + 4]
    call smpobs_parse_dec
    jc   .malformed
    cmp  byte [rdx], 0
    jne  .malformed
    cmp  eax, [rel smp_discovered_count]
    jae  .range
    mov  r13d, eax
    jmp  .cpu
.check_coherence:
    cmp  dword [rbx], 'COHE'
    jne  .check_health
    cmp  dword [rbx + 4], 'RENC'
    jne  .unknown
    cmp  byte [rbx + 8], 'E'
    jne  .unknown
    cmp  byte [rbx + 9], 0
    jne  .unknown
    jmp  .coherence
.check_health:
    cmp  dword [rbx], 'HEAL'
    jne  .check_load
    cmp  word [rbx + 4], 'TH'
    jne  .unknown
    cmp  byte [rbx + 6], 0
    je   .health
    jmp  .unknown
.check_load:
    cmp  dword [rbx], 'LOAD'
    jne  .check_schema
    cmp  byte [rbx + 4], ' '
    jne  .malformed
    cmp  dword [rbx + 5], 'CHIP'
    jne  .parse_load_cpu
    cmp  byte [rbx + 9], 0
    je   .load_chip
    jmp  .malformed
.parse_load_cpu:
    lea  rdi, [rbx + 5]
    call smpobs_parse_dec
    jc   .malformed
    cmp  rax, MAXCORE
    jae  .range
    mov  r13d, eax
    cmp  dword [rdx], ' sam'
    jne  .malformed
    cmp  dword [rdx + 4], 'ple='
    jne  .malformed
    lea  rdi, [rdx + 8]
    call smpobs_parse_dec
    jc   .malformed
    cmp  byte [rdx], 0
    jne  .malformed
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    ja   .range
    cmp  eax, [rel smp_load_snapshot_seq]
    jne  .stale
    cmp  r13d, [rel smp_load_snapshot_logical]
    jae  .range
    jmp  .load_cpu
.check_schema:
    cmp  dword [rbx], 'SCHE'
    jne  .unknown
    cmp  word [rbx + 4], 'MA'
    jne  .unknown
    cmp  byte [rbx + 6], 0
    je   .schema
    jmp  .unknown

.summary:
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_summary]
    call smpobs_put_str
    mov  edi, [rel smp_configured_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_enabled]
    call smpobs_put_str
    mov  edi, [rel smp_enabled_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_discovered]
    call smpobs_put_str
    mov  edi, [rel smp_discovered_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_online]
    call smpobs_put_str
    mov  edi, [rel smp_topology_online]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_failed]
    call smpobs_put_str
    mov  edi, [rel smp_failed_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_late]
    call smpobs_put_str
    mov  edi, [rel smp_late_ap_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_vendor]
    call smpobs_put_str
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_INTEL
    je   .summary_vendor_intel
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_AMD
    je   .summary_vendor_amd
    lea  rdi, [rel smp_vendor_unknown]
    jmp  .summary_vendor_emit
.summary_vendor_intel:
    lea  rdi, [rel smp_vendor_intel]
    jmp  .summary_vendor_emit
.summary_vendor_amd:
    lea  rdi, [rel smp_vendor_amd]
.summary_vendor_emit:
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_capacity]
    call smpobs_put_str
    mov  edi, SMP_CPU_CAPACITY
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_packages]
    call smpobs_put_str
    mov  edi, [rel smp_package_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_physical]
    call smpobs_put_str
    mov  edi, [rel smp_physical_core_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_threads]
    call smpobs_put_str
    mov  edi, [rel smp_threads_per_core]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_logical]
    call smpobs_put_str
    mov  edi, [rel smp_discovered_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_overflow]
    call smpobs_put_str
    movzx edi, byte [rel smp_topology_overflow]
    call smpobs_put_dec
    mov  eax, [rel smp_topology_leaf]
    cmp  eax, 0x1F
    je   .summary_leaf_1f
    cmp  eax, 0x0B
    je   .summary_leaf_0b
    cmp  eax, 0x8000001E
    je   .summary_leaf_amd
    lea  rdi, [rel smpstat_v2_leaf_unknown]
    jmp  .summary_leaf_emit
.summary_leaf_1f:
    lea  rdi, [rel smpstat_v2_leaf_1f]
    jmp  .summary_leaf_emit
.summary_leaf_0b:
    lea  rdi, [rel smpstat_v2_leaf_0b]
    jmp  .summary_leaf_emit
.summary_leaf_amd:
    lea  rdi, [rel smpstat_v2_leaf_amd]
.summary_leaf_emit:
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_bsp]
    call smpobs_put_str
    xor  edi, edi                           ; BSP is dense logical 0
    call smpobs_put_dec
    cmp  byte [rel smp_lapic_mode], 0
    je   .summary_xapic
    lea  rdi, [rel smpstat_v2_x2apic]
    jmp  .summary_mode
.summary_xapic:
    lea  rdi, [rel smpstat_v2_xapic]
.summary_mode:
    call smpobs_put_str
    mov  edi, [rel usched_job_resched_ipis]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_tlb_epoch]
    call smpobs_put_str
    mov  edi, [rel smp_tlb_epoch]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_crashes]
    call smpobs_put_str
    movzx edi, byte [rel boot_crashes_observed]
    call smpobs_put_dec
    jmp  .finish_ok

.cpu:
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_cpu]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_apic]
    call smpobs_put_str
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_uid]
    call smpobs_put_str
    lea  rax, [rel cpu_uid]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_package]
    call smpobs_put_str
    lea  rax, [rel cpu_package]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_core]
    call smpobs_put_str
    lea  rax, [rel cpu_core]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_thread]
    call smpobs_put_str
    lea  rax, [rel cpu_thread]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    mov  edi, r13d
    call smpstat_cpu_security
    mov  edi, r13d
    call smpstat_cpu_microcode
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r13], CPU_STATE_BSP
    je   .state_bsp
    cmp  byte [rax + r13], CPU_STATE_ONLINE
    je   .state_online
    ; Firmware-listed rows that were never started (an HP trial build's cap) or are
    ; still starting are not failures; report each state as it is.
    cmp  byte [rax + r13], CPU_STATE_DISCOVERED
    je   .state_discovered
    cmp  byte [rax + r13], CPU_STATE_PENDING
    je   .state_pending
    lea  rdi, [rel smpstat_v2_state_failed]
    jmp  .state_emit
.state_discovered:
    lea  rdi, [rel smpstat_v2_state_discovered]
    jmp  .state_emit
.state_pending:
    lea  rdi, [rel smpstat_v2_state_pending]
    jmp  .state_emit
.state_bsp:
    lea  rdi, [rel smpstat_v2_state_bsp]
    jmp  .state_emit
.state_online:
    lea  rdi, [rel smpstat_v2_state_online]
.state_emit:
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_late]
    call smpobs_put_str
    mov  eax, [rel smp_late_ap_mask]
    xor  edi, edi
    bt   eax, r13d
    setc dil
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_stack]
    call smpobs_put_str
    lea  rax, [rel ap_stacks]
    xor  edi, edi
    cmp  qword [rax + r13*8], 0
    setne dil
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_tss]
    call smpobs_put_str
    lea  rax, [rel gdt_percpu_ready]
    movzx edi, byte [rax + r13]
    and  edi, 2
    shr  edi, 1
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_ist]
    call smpobs_put_str
    lea  rax, [rel gdt_percpu_ready]
    movzx edi, byte [rax + r13]
    and  edi, 4
    shr  edi, 2
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_timer]
    call smpobs_put_str
    lea  rax, [rel cpu_timer_ready]
    movzx edi, byte [rax + r13]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_runq]
    call smpobs_put_str
    lea  rax, [rel cpu_runq_ready]
    movzx edi, byte [rax + r13]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_current]
    call smpobs_put_str
    lea  rax, [rel cpu_preempt_count]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_steal_in]
    call smpobs_put_str
    lea  rax, [rel usched_steal_in]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_steal_out]
    call smpobs_put_str
    lea  rax, [rel usched_steal_out]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_irq]
    call smpobs_put_str
    lea  rax, [rel cpu_irq_count]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r13], CPU_STATE_BSP
    jne  .cpu_faults
    lea  rdi, [rel smpstat_v2_lapic_lvt]
    call smpobs_put_str
    mov  esi, SMP_LAPIC_LVT_TIMER
    call smp_lapic_read32
    mov  edi, eax
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_lapic_dcr]
    call smpobs_put_str
    mov  esi, SMP_LAPIC_DIVIDE_CONFIG
    call smp_lapic_read32
    mov  edi, eax
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_lapic_icr]
    call smpobs_put_str
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    call smp_lapic_read32
    mov  edi, eax
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_lapic_rearm_required]
    call smpobs_put_str
    mov  edi, [rel smp_timer_rearm_required_mask]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_lapic_rearm_acked]
    call smpobs_put_str
    mov  edi, [rel smp_timer_rearm_ack_mask]
    call smpobs_put_dec
.cpu_faults:
    lea  rdi, [rel smpstat_v2_faults]
    call smpobs_put_str
    lea  rax, [rel cpu_fault_count]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_halts]      ; RCQ-12: appended last, every earlier byte unchanged
    call smpobs_put_str
    lea  rax, [rel smp_idle_hlt_count]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_chunks]     ; RCQ-12 track 2: appended after halts=, every earlier byte unchanged
    call smpobs_put_str
    lea  rax, [rel cpu_pf_chunks]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_busy_tsc]
    call smpobs_put_str
    lea  rax, [rel cpu_pf_busy_tsc]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_core_type]
    call smpobs_put_str
    lea  rax, [rel cpu_core_type]
    movzx edi, byte [rax + r13]
    call smpobs_put_dec
    jmp  .finish_ok

.schema:
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_schema]
    call smpobs_put_str
    jmp  .finish_ok

.health:
    call smp_load_snapshot_capture
    test eax, eax
    jz   .unavailable
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_health]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_seq]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_ms]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_ms]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_us]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_us]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_online]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_logical]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_healthy]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_healthy]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_stalled]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_stalled]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_last_progress]
    call smpobs_put_str
    mov  rdi, [rel smp_load_snapshot_last_progress_ms]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_critical]
    call smpobs_put_str
    jmp  .finish_ok

.load_chip:
    call smp_load_snapshot_capture
    test eax, eax
    jz   .unavailable
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_load_chip]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_logical]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_online]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_logical]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_seq]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_seq]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_ms]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_ms]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_us]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_us]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_load]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_mean]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_idle]
    call smpobs_put_str
    mov  edi, 1000
    sub  edi, [rel smp_load_snapshot_mean]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_load_sum]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_sum]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_runq_total]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_runq_total]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_runq_max]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_runq_max]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_imbalance]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_imbalance]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_busiest]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_busiest]
    call smpobs_put_dec

    lea  rdi, [rel smpstat_v2_freq_capable]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_capable]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_freq_measured]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_measured]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_freq_idle]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_idle]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_freq_active]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_active]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_aperf_total]
    call smpobs_put_str
    mov  rdi, [rel smp_freq_snapshot_aperf_total]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_mperf_total]
    call smpobs_put_str
    mov  rdi, [rel smp_freq_snapshot_mperf_total]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_frequency]
    call smpobs_put_str
    cmp  dword [rel smp_freq_snapshot_active], 0
    je   .load_chip_frequency_unavailable
    mov  rdi, [rel smp_freq_snapshot_frequency]
    call smpobs_put_dec
    jmp  .load_chip_frequency_done
.load_chip_frequency_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_chip_frequency_done:
    lea  rdi, [rel smpstat_v2_effective_total]
    call smpobs_put_str
    mov  rdi, [rel smp_freq_snapshot_effective_total]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_effective_mean]
    call smpobs_put_str
    mov  rdi, [rel smp_freq_snapshot_effective_mean]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_freq_min]
    call smpobs_put_str
    cmp  dword [rel smp_freq_snapshot_active], 0
    je   .load_chip_min_unavailable
    mov  rdi, [rel smp_freq_snapshot_min]
    call smpobs_put_dec
    jmp  .load_chip_min_done
.load_chip_min_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_chip_min_done:
    lea  rdi, [rel smpstat_v2_freq_max]
    call smpobs_put_str
    cmp  dword [rel smp_freq_snapshot_active], 0
    je   .load_chip_max_unavailable
    mov  rdi, [rel smp_freq_snapshot_max]
    call smpobs_put_dec
    jmp  .load_chip_max_done
.load_chip_max_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_chip_max_done:
    lea  rdi, [rel smpstat_v2_freq_ratio]
    call smpobs_put_str
    cmp  dword [rel smp_freq_snapshot_measured], 0
    je   .load_chip_ratio_unavailable
    mov  rdi, [rel smp_freq_snapshot_ratio]
    call smpobs_put_dec
    jmp  .load_chip_ratio_done
.load_chip_ratio_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_chip_ratio_done:
    lea  rdi, [rel smpstat_v2_freq_source_mixed]
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_temperature_unavailable]
    call smpobs_put_str
    jmp  .finish_ok

.load_cpu:
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_load_cpu]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_package]
    call smpobs_put_str
    lea  rax, [rel cpu_package]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_core]
    call smpobs_put_str
    lea  rax, [rel cpu_core]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_thread]
    call smpobs_put_str
    lea  rax, [rel cpu_thread]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_seq]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_seq]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_ms]
    call smpobs_put_str
    mov  edi, [rel smp_load_snapshot_ms]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_sample_us]
    call smpobs_put_str
    mov  edi, [rel smp_freq_snapshot_us]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_load]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_load]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_idle]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_load]
    mov  edi, 1000
    sub  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_runq]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_runq]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_current_load]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_current]
    cmp  byte [rax + r13], 0
    je   .load_current_idle
    lea  rdi, [rel smpstat_v2_current_unified]
    jmp  .load_current_emit
.load_current_idle:
    lea  rdi, [rel smpstat_v2_current_idle]
.load_current_emit:
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_irq_delta]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_irq]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_preempt_delta]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_preempt]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_ctx_delta]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_ctx]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_migration_delta]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_migration]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_steal_in_delta]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_steal_in]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_steal_out_delta]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_steal_out]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_progress_age]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_progress_age]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_faults]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_faults]
    mov  edi, [rax + r13*4]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_health_cpu]
    call smpobs_put_str
    lea  rax, [rel smp_load_snapshot_health]
    cmp  byte [rax + r13], 1
    jne  .load_health_stalled
    lea  rdi, [rel smpstat_v2_health_ok]
    jmp  .load_health_emit
.load_health_stalled:
    lea  rdi, [rel smpstat_v2_health_stalled]
.load_health_emit:
    call smpobs_put_str

    lea  rdi, [rel smpstat_v2_aperf_delta]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_UNSUPPORTED
    je   .load_cpu_aperf_unavailable
    lea  rax, [rel smp_freq_snapshot_aperf]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    jmp  .load_cpu_aperf_done
.load_cpu_aperf_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_cpu_aperf_done:
    lea  rdi, [rel smpstat_v2_mperf_delta]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_UNSUPPORTED
    je   .load_cpu_mperf_unavailable
    lea  rax, [rel smp_freq_snapshot_mperf]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    jmp  .load_cpu_mperf_done
.load_cpu_mperf_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_cpu_mperf_done:
    lea  rdi, [rel smpstat_v2_base_mhz]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_UNSUPPORTED
    je   .load_cpu_base_unavailable
    lea  rax, [rel smp_freq_base_mhz]
    mov  edi, [rax + r13*4]
    test edi, edi
    jz   .load_cpu_base_unavailable
    call smpobs_put_dec
    jmp  .load_cpu_base_done
.load_cpu_base_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_cpu_base_done:
    lea  rdi, [rel smpstat_v2_frequency]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_MEASURED
    jne  .load_cpu_frequency_unavailable
    lea  rax, [rel smp_freq_base_mhz]
    cmp  dword [rax + r13*4], 0
    je   .load_cpu_frequency_unavailable
    lea  rax, [rel smp_freq_snapshot_frequency_cpu]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    jmp  .load_cpu_frequency_done
.load_cpu_frequency_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_cpu_frequency_done:
    lea  rdi, [rel smpstat_v2_effective]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_UNSUPPORTED
    je   .load_cpu_effective_unavailable
    lea  rax, [rel smp_freq_snapshot_effective]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    jmp  .load_cpu_effective_done
.load_cpu_effective_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_cpu_effective_done:
    lea  rdi, [rel smpstat_v2_freq_ratio]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_MEASURED
    jne  .load_cpu_ratio_unavailable
    lea  rax, [rel smp_freq_snapshot_ratio_cpu]
    mov  rdi, [rax + r13*8]
    call smpobs_put_dec
    jmp  .load_cpu_ratio_done
.load_cpu_ratio_unavailable:
    lea  rdi, [rel smpstat_v2_unavailable]
    call smpobs_put_str
.load_cpu_ratio_done:
    lea  rdi, [rel smpstat_v2_freq_state]
    call smpobs_put_str
    lea  rax, [rel smp_freq_snapshot_state]
    cmp  byte [rax + r13], SMP_FREQ_STATE_MEASURED
    je   .load_cpu_state_measured
    cmp  byte [rax + r13], SMP_FREQ_STATE_IDLE
    je   .load_cpu_state_idle
    lea  rdi, [rel smpstat_v2_state_unsupported]
    jmp  .load_cpu_state_emit
.load_cpu_state_measured:
    lea  rdi, [rel smpstat_v2_state_measured]
    jmp  .load_cpu_state_emit
.load_cpu_state_idle:
    lea  rdi, [rel smpstat_v2_state_idle]
.load_cpu_state_emit:
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_freq_source]
    call smpobs_put_str
    lea  rax, [rel smp_freq_base_source]
    cmp  byte [rax + r13], SMP_FREQ_SOURCE_CPUID16
    je   .load_cpu_source_cpuid
    cmp  byte [rax + r13], SMP_FREQ_SOURCE_PLATFORM
    je   .load_cpu_source_platform
    cmp  byte [rax + r13], SMP_FREQ_SOURCE_NO_BASE
    je   .load_cpu_source_no_base
    lea  rdi, [rel smpstat_v2_source_unsupported]
    jmp  .load_cpu_source_emit
.load_cpu_source_cpuid:
    lea  rdi, [rel smpstat_v2_source_cpuid]
    jmp  .load_cpu_source_emit
.load_cpu_source_platform:
    lea  rdi, [rel smpstat_v2_source_platform]
    jmp  .load_cpu_source_emit
.load_cpu_source_no_base:
    lea  rdi, [rel smpstat_v2_source_no_base]
.load_cpu_source_emit:
    call smpobs_put_str
    lea  rdi, [rel smpstat_v2_temperature_unavailable]
    call smpobs_put_str
    jmp  .finish_ok

.coherence:
    mov  rdi, r12
    call smpobs_begin_stat_v2
    lea  rdi, [rel smpstat_v2_coherence]
    call smpobs_put_str
    mov  edi, [rel smp_coherence_expected]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_actual]
    call smpobs_put_str
    mov  edi, [rel smp_coherence_actual]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_double]
    call smpobs_put_str
    mov  edi, [rel smp_coherence_double_run]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_lost]
    call smpobs_put_str
    mov  edi, [rel smp_coherence_lost]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_ack_missing]
    call smpobs_put_str
    mov  edi, [rel smp_coherence_ack_missing]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_fault_isolated]
    call smpobs_put_str
    movzx edi, byte [rel smp_fault_isolated]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_tlb_requested]
    call smpobs_put_str
    mov  edi, [rel smp_tlb_requested]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_tlb_acked]
    call smpobs_put_str
    mov  edi, [rel smp_tlb_acked]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_stale]
    call smpobs_put_str
    mov  edi, [rel smp_stale_mapping]
    call smpobs_put_dec
    ; RCQ-12: runtime LAPIC IRQ/EOI totals since smp_selftest, sequential loads in print order (not one snapshot)
    lea  rdi, [rel smpstat_v2_irq_entries]
    call smpobs_put_str
    mov  rdi, [rel smp_irq_entries]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_irq_eois]
    call smpobs_put_str
    mov  rdi, [rel smp_irq_eois]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_duplicate_eoi]
    call smpobs_put_str
    mov  edi, [rel smp_irq_duplicate_eoi]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_ownership_faults]
    call smpobs_put_str
    mov  edi, [rel smp_irq_ownership_faults]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_unexpected_irq]
    call smpobs_put_str
    mov  rdi, [rel irq_unexpected_count]
    call smpobs_put_dec
    lea  rdi, [rel smpstat_v2_unexpected_vector]
    call smpobs_put_str
    mov  rdi, [rel irq_unexpected_last]
    call smpobs_put_dec
.finish_ok:
    mov  rsi, r15
    call smpobs_finish_ok
    jmp  .out
.oversized:
    lea  rdi, [rel str_smp_err_oversized]
    jmp  .error
.bad_nonce:
    lea  rdi, [rel str_smp_err_nonce]
    jmp  .error
.malformed:
    lea  rdi, [rel str_smp_err_malformed]
    jmp  .error
.range:
    lea  rdi, [rel str_smp_err_range]
    jmp  .error
.stale:
    lea  rdi, [rel smpstat_v2_err_stale]
    jmp  .error
.unavailable:
    lea  rdi, [rel smpstat_v2_err_unavailable]
    jmp  .error
.unknown:
    lea  rdi, [rel str_smp_err_unknown]
.error:
    mov  rsi, r15
    call smpobs_stage_error
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- Per-queue canonical locks (SCHEDULER.md §4).  EDI is always a dense
;      logical queue id.  A steal path that ever needs two queues must acquire
;      the lower id first; current paths hold at most one queue lock. ----
rq_lock_acquire:
    cmp  edi, MAXCORE
    jae  .bad
    lea  rax, [rel rq_locks]
    add  rax, rdi
    mov  rdi, rax
    jmp  spin_acquire
.bad:
    ud2

rq_lock_release:
    cmp  edi, MAXCORE
    jae  .bad
    lea  rax, [rel rq_locks]
    add  rax, rdi
    mov  rdi, rax
    jmp  spin_release
.bad:
    ud2

; Narrow global publication lock.  It protects only SMP epoch/snapshot state;
; it is never held while executing or selecting a scheduler task.
smp_state_lock_acquire:
    lea  rdi, [rel smp_state_lock]
    jmp  spin_acquire
smp_state_lock_release:
    lea  rdi, [rel smp_state_lock]
    jmp  spin_release

smp_coherence_counter_lock_acquire:
    lea  rdi, [rel smp_coherence_counter_lock]
    jmp  spin_acquire
smp_coherence_counter_lock_release:
    lea  rdi, [rel smp_coherence_counter_lock]
    jmp  spin_release

smp_mapping_lock_acquire:
    lea  rdi, [rel smp_mapping_lock]
    jmp  spin_acquire
smp_mapping_lock_release:
    lea  rdi, [rel smp_mapping_lock]
    jmp  spin_release

; EDI=count -> EAX=low count membership bits, including count=32.
smp_count_mask32:
    xor  eax, eax
    test edi, edi
    jz   .done
    cmp  edi, SMP_CPU_CAPACITY
    jae  .full
    mov  eax, 1
    mov  ecx, edi
    shl  eax, cl
    dec  eax
    ret
.full:
    mov  eax, 0xFFFFFFFF
.done:
    ret

; EAX=value -> EAX=population count without assuming POPCNT.
smp_popcount32:
    xor  ecx, ecx
.bit:
    test eax, eax
    jz   .done
    lea  edx, [eax - 1]
    and  eax, edx
    inc  ecx
    jmp  .bit
.done:
    mov  eax, ecx
    ret

; Return the exact dense mask of CPUs that currently own runnable local state.
smp_online_mask_now:
    xor  eax, eax
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel smp_discovered_count]
    jae  .done
    lea  rdx, [rel cpu_state]
    cmp  byte [rdx + rcx], CPU_STATE_BSP
    je   .add
    cmp  byte [rdx + rcx], CPU_STATE_ONLINE
    jne  .next
.add:
    bts  eax, ecx
.next:
    inc  ecx
    jmp  .scan
.done:
    ret

; ==========================================================================
; Native physical-core custody. A global lease deliberately parks ALL peers,
; so sibling/control writers on other cores cannot race the protected pair.
; No NMI/SMI/firmware exclusion is asserted. VM retains its independent refusal
; until its entire boundary contract is satisfied. Private retained token only.
;
; Gate is ONE atomic word: low32 phase (0 free,1 acquire,2 held,3 drain,4 poison),
; high32 acknowledged APs. Low32 also retains generation<<3 (nonreused, bounded
; to29bits), preventing ABA by a peer stalled across an abort/new acquire.
; Freeze phase+acks atomically before abort/release:
; a peer cannot publish a late ack after the owner has counted departures.
; BEGIN CORE CUSTODY NATIVE
SMP_CC_WAIT equ 4000                       ; <=200ms plus bounded IPI delivery
SMP_CC_NATIVE_FACTS equ 7                  ; host parking, sibling set, writer gate
SMP_CC_GANG_FACTS equ 16                   ; T1-5 S7: gang AP parked on this generation, own guard

; CPU-local additive observation, before ONLINE publication. Unsupported or
; inconsistent topology remains count0 UNKNOWN and never prevents normal SMP.
; AMD TopologyExtensions explicit threads/core or checked Intel non-SMT domain.
smp_core_sibling_local_capture:
    push rbx
    push r12
    mov  r12d, edi
    cmp  r12d, MAXCORE
    jae  .out
    lea  rax, [rel cpu_sibling_count]
    mov  dword [rax + r12*4], 0
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_INTEL
    je   .intel_absent
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_AMD
    jne  .out
    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x8000001E
    jb   .out
    mov  eax, 0x80000001
    xor  ecx, ecx
    cpuid
    bt   ecx, 22
    jnc  .out
    mov  eax, 0x8000001E
    xor  ecx, ecx
    cpuid
    lea  rdx, [rel cpu_apic_id]
    cmp  eax, [rdx + r12*4]
    jne  .out
    shr  ebx, 8
    and  ebx, 255
    inc  ebx
    cmp  ebx, MAXCORE
    ja   .out
    lea  rax, [rel cpu_thread]
    cmp  [rax + r12*4], ebx
    jae  .out
    lea  rax, [rel cpu_sibling_count]
    mov  [rax + r12*4], ebx
    jmp  .out
.intel_absent:
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r12*4]
    call smp_cc_intel_absent_local
    lea  rdx, [rel cpu_sibling_count]
    mov  [rdx + r12*4], eax
.out:
    pop  r12
    pop  rbx
    ret

; Complete CPU-local inventory, not a mapping epoch or an online-mask proxy.
; Each package/core has exactly its own reported count, distinct thread/APIC
; identities and every thread in [0,count). No failed, late or missing rows.
smp_cc_membership:
    xor  eax, eax                       ; original AMD-only entry
    jmp  smp_cc_membership_mode
smp_cc_intel_membership:
    mov  eax, 1                         ; additive Intel absent-siblings entry
    jmp  smp_cc_membership_mode
smp_cc_enabled_membership:
    mov  eax, 2                         ; all enabled CPUs, no SMT inference
smp_cc_membership_mode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r11d, eax
    xor  r15d, r15d
    cmp  r11d, 2
    je   .enabled_only
    mov  eax, SMP_VENDOR_AMD
    sub  eax, r11d
    cmp  byte [rel smp_cpu_vendor], al
    jne  .bad
.enabled_only:
    cmp  byte [rel smp_topology_exact], 1
    jne  .bad
    cmp  byte [rel smp_topology_overflow], 0
    jne  .bad
    cmp  dword [rel smp_failed_count], 0
    jne  .bad
    cmp  dword [rel smp_late_ap_count], 0
    jne  .bad
    cmp  dword [rel smp_late_ap_mask], 0
    jne  .bad
    mov  r12d, [rel smp_discovered_count]
    test r12d, r12d
    jz   .bad
    cmp  r12d, MAXCORE
    ja   .bad
    cmp  r12d, [rel smp_topology_online]
    jne  .bad
    cmp  r12d, [rel smp_enabled_count]
    jne  .bad
    xor  ebx, ebx
.row:
    lea  rax, [rel cpu_state]
    movzx eax, byte [rax + rbx]
    test ebx, ebx
    jnz  .ap
    cmp  eax, CPU_STATE_BSP
    jne  .bad
    jmp  .state_ok
.ap:
    cmp  eax, CPU_STATE_ONLINE
    jne  .bad
.state_ok:
    lea  rax, [rel cpu_apic_id]
    cmp  dword [rax + rbx*4], -1
    je   .bad
    cmp  r11d, 2
    je   .enabled_peers
    lea  rax, [rel cpu_package]
    mov  r13d, [rax + rbx*4]
    cmp  r13d, -1
    je   .bad
    lea  rax, [rel cpu_core]
    mov  r14d, [rax + rbx*4]
    cmp  r14d, -1
    je   .bad
    lea  rax, [rel cpu_sibling_count]
    mov  ebp, [rax + rbx*4]
    test ebp, ebp
    jz   .bad
    cmp  ebp, MAXCORE
    ja   .bad
    test r11d, r11d
    jz   .sibling_count_ok
    cmp  ebp, 1                         ; Intel supports absent siblings only
    jne  .bad
.sibling_count_ok:
    lea  rax, [rel cpu_thread]
    mov  ecx, [rax + rbx*4]
    cmp  ecx, ebp
    jae  .bad
    xor  r8d, r8d                         ; exact sibling count
    xor  r9d, r9d                         ; unique thread mask
    xor  edx, edx
.peer:
    lea  rax, [rel cpu_apic_id]
    mov  esi, [rax + rbx*4]
    cmp  esi, [rax + rdx*4]
    jne  .identity_ok
    cmp  ebx, edx
    jne  .bad
.identity_ok:
    lea  rax, [rel cpu_package]
    cmp  r13d, [rax + rdx*4]
    jne  .next_peer
    lea  rax, [rel cpu_core]
    cmp  r14d, [rax + rdx*4]
    jne  .next_peer
    lea  rax, [rel cpu_sibling_count]
    cmp  ebp, [rax + rdx*4]
    jne  .bad
    lea  rax, [rel cpu_thread]
    mov  ecx, [rax + rdx*4]
    cmp  ecx, ebp
    jae  .bad
    bts  r9d, ecx
    jc   .bad
    inc  r8d
.next_peer:
    inc  edx
    cmp  edx, r12d
    jb   .peer
    cmp  r8d, ebp
    jne  .bad
    jmp  .row_complete
.enabled_peers:
    ; All enabled CPUs are parked; physical package/core/thread classification
    ; is unnecessary. Still require distinct full APIC identities and complete
    ; exact firmware inventory. This cannot prove anything about SMM or NMIs.
    xor  edx, edx
.enabled_peer:
    lea  rax, [rel cpu_apic_id]
    mov  esi, [rax + rbx*4]
    cmp  esi, [rax + rdx*4]
    jne  .enabled_next
    cmp  ebx, edx
    jne  .bad
.enabled_next:
    inc  edx
    cmp  edx, r12d
    jb   .enabled_peer
.row_complete:
    bts  r15d, ebx
    inc  ebx
    cmp  ebx, r12d
    jb   .row
    mov  eax, r15d
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI0 freeze /1 compare exact CPU-local membership, not merely its mask.
smp_cc_inventory:
    xor  ecx, ecx
    lea  r8, [rel smp_cc_inventory_rows]
.row:
    lea  rax, [rel cpu_apic_id]
    mov  edx, [rax + rcx*4]
    lea  rax, [rel cpu_package]
    mov  esi, [rax + rcx*4]
    shl  rsi, 32
    or   rdx, rsi
    test edi, edi
    jnz  .compare_first
    mov  [r8], rdx
    jmp  .second
.compare_first:
    cmp  [r8], rdx
    jne  .bad
.second:
    lea  rax, [rel cpu_core]
    mov  edx, [rax + rcx*4]
    lea  rax, [rel cpu_thread]
    mov  esi, [rax + rcx*4]
    shl  rsi, 32
    or   rdx, rsi
    test edi, edi
    jnz  .compare_second
    mov  [r8 + 8], rdx
    jmp  .third
.compare_second:
    cmp  [r8 + 8], rdx
    jne  .bad
.third:
    lea  rax, [rel cpu_sibling_count]
    mov  edx, [rax + rcx*4]
    test edi, edi
    jnz  .compare_third
    mov  [r8 + 16], edx
    jmp  .next
.compare_third:
    cmp  [r8 + 16], edx
    jne  .bad
.next:
    add  r8, 24
    inc  ecx
    cmp  ecx, [rel smp_discovered_count]
    jb   .row
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Calling-CPU precondition: trusted BSP, CPL0, IF0/DF0 and outside IRQ frames.
; AP owners refuse until there is an equivalent safe-boundary BSP park path.
smp_cc_context:
    mov  ax, cs
    test al, 3
    jnz  .bad
    pushfq
    pop  rax
    test eax, (1 << 9) | (1 << 10)
    jnz  .bad
    call smp_current_logical
    test eax, eax
    jnz  .bad
    cmp  byte [rel cpu_irq_depth], 0     ; BSP slot only; AP slots are separate bytes
    jne  .bad
    call smp_read_apic_id
    cmp  eax, [rel cpu_apic_id]
    jne  .bad
    mov  edx, eax                         ; full32 owner
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Acquire EDI=expected fullAPIC -> RAX token,0 clean refusal,-1 uncertain.
; -1 requires nonresuming containment; it is never a token or clean unwind. The owner
; must keep IF0 and its nonresuming boundary guard throughout entry/exit/restore.
smp_core_custody_acquire:
    xor  esi, esi                       ; original host-only ABI
    jmp  smp_cc_acquire_common

; Additive SVM ABI: caller armed its nonresuming guard and saved/enabled its
; own EFER.SVME before this call. RDX is that exact live guard cookie.
; Acquire leaves owner GIF unchanged; only svm_prepare starts exclusion.
; No owner EFER mutation here; the VM restores its own exact host state.
smp_core_custody_acquire_svm:
    mov  esi, 1
    jmp  smp_cc_acquire_common

; Additive conservative mitigation: all enabled peers park with IF0 and a
; CPU-local nonresuming guard. RDX exact owner guard, EDI full owner APIC.
; No model/SMT whitelist, no SVM/VMX/MSR mutation, no architectural custody grant.
smp_core_custody_acquire_native_guarded:
    mov  esi, 2
smp_cc_acquire_common:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdx
    mov  r14d, esi
    mov  r12d, edi
    call smp_cc_context
    test eax, eax
    jz   .refuse
    cmp  edx, r12d
    jne  .refuse
    xor  eax, eax
    mov  edx, 1
    lock cmpxchg [rel smp_core_custody_gate], rdx
    jne  .occupied                        ; never recurse/spin on ownership
    cmp  r14d, 2
    jne  .initialize
    cmp  qword [rel smp_cc_request], 0
    jne  .poison_acquire                 ; do not overwrite uncertain prior peers
.initialize:
    mov  [rel smp_cc_svm_mode], r14d
    mov  dword [rel smp_cc_svm_ready], 0
    mov  dword [rel smp_cc_svm_failed], 0
    mov  dword [rel smp_cc_svm_phase], 0 ; HOST, no architectural grant
    test r14d, r14d
    jz   .native
    call smp_cc_svm_flags
    test eax, 1 << 8                    ; no single-step exception in GIF0 hold
    jnz  .free_refuse
    mov  rdi, r15
    call cpu_boundary_fault_check
    test eax, eax
    jz   .free_refuse
    mov  [rel smp_cc_svm_guard], r15
    cmp  r14d, 2
    je   .native
    mov  ecx, 0xC0000080
    rdmsr
    test eax, 1 << 12                   ; caller's saved/enabled SVM prerequisite
    jz   .free_refuse
.native:
    cmp  qword [rel smp_cc_generation], 0x1FFFFFFF
    jae  .free_refuse                     ; never reuse a wrapped token
    cmp  r14d, 2
    je   .enabled_members
    call smp_cc_membership
    jmp  .members_ready
.enabled_members:
    call smp_cc_enabled_membership
.members_ready:
    test eax, eax
    jz   .free_refuse
    mov  [rel smp_cc_members], eax
    xor  edi, edi
    call smp_cc_inventory
    mov  [rel smp_cc_owner_apic], r12d
    inc  qword [rel smp_cc_generation]
    mov  r13, [rel smp_cc_generation]
    mov  qword [rel smp_cc_release], 0
    mov  dword [rel smp_cc_departed], 0
    mov  rax, r13
    shl  rax, 3
    or   rax, 1
    mov  [rel smp_core_custody_gate], rax
    mfence
    mov  [rel smp_cc_request], r13         ; publish context before peer request
    xor  ebx, ebx
.kick:
    inc  ebx
    cmp  ebx, [rel smp_discovered_count]
    jae  .wait
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + rbx*4]
    mov  esi, SMP_ICR_FIXED | SMP_IDLE_WAKE_VECTOR
    call smp_lapic_send_ipi
    jc   .abort
    jmp  .kick
.wait:
    mov  ebx, SMP_CC_WAIT
.wait_ack:
    cmp  dword [rel smp_cc_svm_failed], 0
    jne  .abort
    mov  edx, [rel smp_cc_members]
    and  edx, ~1
    shl  rdx, 32
    mov  rax, r13
    shl  rax, 3
    or   rax, 1
    or   rdx, rax
    mov  rax, [rel smp_core_custody_gate]
    cmp  rax, rdx
    jne  .wait_more
    cmp  dword [rel smp_cc_svm_mode], 0
    je   .held
    mov  ecx, [rel smp_cc_members]
    and  ecx, ~1
    cmp  ecx, [rel smp_cc_svm_ready]
    je   .held
.wait_more:
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_ack
.abort:
    call smp_cc_drain                     ; acquired no guest authority
    test eax, eax
    jz   .uncertain
    jmp  .refuse
.held:
    mov  rcx, rax
    inc  rcx                             ; atomically phase1 ->2, exact peer set
    lock cmpxchg [rel smp_core_custody_gate], rcx
    jne  .abort
    mov  rdi, r13
    cmp  r14d, 2
    je   .check_guarded
    call smp_core_custody_check
    jmp  .checked
.check_guarded:
    call smp_core_custody_check_native_guarded
.checked:
    test eax, eax
    jz   .abort
    mov  rax, r13
    jmp  .out
.occupied:
    and  eax, 7
    cmp  eax, 4
    jne  .refuse
    jmp  .uncertain
.poison_acquire:
    mov  dword [rel smp_core_custody_gate], 4
.uncertain:
    mov  rax, -1
    jmp  .out
.free_refuse:
    mov  qword [rel smp_core_custody_gate], 0
.refuse:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Check RDI token -> EAX1, EDX native-only enforced facts7;0/0 invalid. No
; capture equality can manufacture a lease. A broken held invariant poisons
; the lease and leaves peers parked: caller must nonreturningly contain failure.
smp_core_custody_check:
    cmp  dword [rel smp_cc_svm_mode], 2
    je   smp_cc_svm_bad                  ; guarded ABI has a separate fact domain
smp_cc_check_common:
    push rbx
    mov  rbx, rdi
    call smp_cc_context
    test eax, eax
    jz   .bad
    cmp  edx, [rel smp_cc_owner_apic]
    jne  .bad
    test rbx, rbx
    jz   .bad
    cmp  rbx, [rel smp_cc_request]
    jne  .bad
    mov  eax, [rel smp_core_custody_gate]
    and  eax, 7
    cmp  eax, 2
    jne  .bad
    cmp  dword [rel smp_cc_svm_mode], 2
    je   .enabled_members
    call smp_cc_membership
    jmp  .members_ready
.enabled_members:
    call smp_cc_enabled_membership
.members_ready:
    test eax, eax
    jz   .poison
    cmp  eax, [rel smp_cc_members]
    jne  .poison
    and  eax, ~1
    cmp  eax, [rel smp_core_custody_gate + 4]
    jne  .poison
    cmp  dword [rel smp_cc_departed], 0
    jne  .poison
    cmp  qword [rel smp_cc_release], 0
    jne  .poison
    mov  edi, 1
    call smp_cc_inventory
    test eax, eax
    jz   .poison
    mov  eax, 1
    mov  edx, SMP_CC_NATIVE_FACTS
    pop  rbx
    ret
.poison:
    mov  dword [rel smp_core_custody_gate], 4
.bad:
    xor  eax, eax
    xor  edx, edx
    pop  rbx
    ret

; Release only after completed protected host restore; wrong token/CPU cannot
; release anyone. Missing departure leaves state4 poisoned; never re-admit.
smp_core_custody_release:
    cmp  dword [rel smp_cc_svm_mode], 0
    jne  smp_cc_svm_bad                  ; cannot release a phased SVM lease
    push rbx
    mov  rbx, rdi
    call smp_core_custody_check
    test eax, eax
    jz   .out
    call smp_cc_drain
.out:
    pop  rbx
    ret

; Freeze phase+ack set as ONE CAS before publishing release. This also closes
; the timeout vs late-ack race on failed acquire. Returns1 only after all acked
; peers left the park; a missing peer cannot free the transaction for reuse.
smp_cc_drain:
    push rbx
.freeze:
    mov  rax, [rel smp_core_custody_gate]
    mov  edx, eax
    and  edx, 7
    cmp  edx, 1
    je   .phase_ok
    cmp  edx, 2
    jne  .bad
.phase_ok:
    mov  rcx, rax
    and  rcx, -8
    or   rcx, 3
    lock cmpxchg [rel smp_core_custody_gate], rcx
    jne  .freeze
    shr  rcx, 32
    mov  ebx, ecx                         ; frozen exact ack set
    mov  rax, [rel smp_cc_request]
    mov  [rel smp_cc_release], rax
    mfence
    mov  ecx, SMP_CC_WAIT
.wait:
    cmp  [rel smp_cc_departed], ebx
    je   .free
    push rcx
    mov  edi, 50
    call tsc_delay_us
    pop  rcx
    dec  ecx
    jnz  .wait
    mov  dword [rel smp_core_custody_gate], 4
.bad:
    xor  eax, eax
    pop  rbx
    ret
.free:
    mov  qword [rel smp_cc_request], 0
    mfence
    mov  qword [rel smp_core_custody_gate], 0
    mov  eax, 1
    pop  rbx
    ret

; Only called at AP outer task boundary, with NO subsystem/runqueue lock held.
; Exact ack CAS rejects phase3/4 and closes late arrivals. IRQs stay disabled
; through the actual hold; no native work, HLT, MWAIT or callbacks run here.
smp_core_custody_park:
    pushfq
    cli
    push rbx
    push r12
    push r13
    push r14
    xor  r13d, r13d                     ; local fault-guard cookie
    xor  r14d, r14d                     ; saved EFER (only valid with guard)
    mov  ebx, edi
    test ebx, ebx
    jz   .out
    cmp  ebx, MAXCORE
    jae  .out
    mov  r12, [rel smp_cc_request]
    test r12, r12
    jz   .out
    bt   dword [rel smp_cc_members], ebx
    jnc  .out
.ack:
    mov  rax, [rel smp_core_custody_gate]
    mov  edx, eax
    and  edx, 7
    cmp  edx, 1
    je   .ack_phase
    cmp  edx, 2
    jne  .out
.ack_phase:
    cmp  r12, [rel smp_cc_request]
    jne  .out
    mov  rcx, rax
    mov  edx, ebx
    add  edx, 32
    bts  rcx, rdx
    jc   .out                            ; never nested/double park
    lock cmpxchg [rel smp_core_custody_gate], rcx
    jne  .ack
    ; The CAS reserves this peer BEFORE any privileged preparation. Abort
    ; freezes this exact reservation set and cannot lose an in-flight mutation.
    cmp  dword [rel smp_cc_svm_mode], 0
    je   .hold
    test qword [rsp + 32], (1 << 8) | (1 << 10) ; saved TF/DF
    jnz  .prep_refused
    call smp_read_apic_id
    lea  rdx, [rel smp_cc_inventory_rows]
    imul ecx, ebx, 24
    cmp  eax, [rdx + rcx]
    jne  .prep_refused
    cmp  dword [rel smp_cc_svm_mode], 2
    je   .guard_prepare
    push rbx
    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x8000000A
    jb   .feature_refused
    mov  eax, 0x80000001
    xor  ecx, ecx
    cpuid
    test ecx, 1 << 2                    ; CPU-local SVM, never a BSP proxy
    jz   .feature_refused
    pop  rbx
.guard_prepare:
    mov  ecx, MAXCORE                   ; bounded retry for concurrent guard CAS
.guard_arm:
    call cpu_boundary_fault_arm
    test rax, rax
    jnz  .guard_ready
    pause
    loop .guard_arm
    jmp  .prep_refused
.guard_ready:
    mov  r13, rax
    cmp  dword [rel smp_cc_svm_mode], 2
    je   .publish_ready
    mov  ecx, 0xC0010114                 ; VM_CR, do not unlock firmware policy
    rdmsr
    test eax, 1 << 4                    ; SVMDIS
    jnz  .prep_refused
    mov  ecx, 0xC0000080
    rdmsr
    test eax, 1 << 12                   ; refuse nested/foreign SVM state
    jnz  .prep_refused
    shl  rdx, 32
    or   rax, rdx
    mov  r14, rax
    or   eax, 1 << 12
    mov  rdx, r14
    shr  rdx, 32
    wrmsr                              ; guarded: any partial/unknown state stops
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, r14
    or   rcx, 1 << 12
    cmp  rax, rcx
    jne  cpu_boundary_fail_stop
    clgi                               ; only after verified EFER.SVME=1
.publish_ready:
    lock bts dword [rel smp_cc_svm_ready], ebx
    jmp  .hold
.feature_refused:
    pop  rbx
.prep_refused:
    ; No EFER mutation on these clean refusals. Stay reserved until drain so
    ; the owner cannot free/reuse this generation while this peer is in flight.
    lock bts dword [rel smp_cc_svm_failed], ebx
.hold:
    cmp  r12, [rel smp_cc_release]
    je   .depart
    call vcpu_ap_park_hook             ; T1-5 S7: the gang's designated AP serves vCPU1
    pause
    jmp  .hold
.depart:
    cmp  dword [rel smp_cc_svm_mode], 0
    je   .depart_native
    cmp  dword [rel smp_cc_svm_mode], 2
    je   .disarm                        ; guarded native path never changes GIF
    bt   dword [rel smp_cc_svm_ready], ebx
    jnc  .disarm
    ; Pair is already closed/restored on the owner before release. STGI must
    ; precede clearing SVME; pending events are now safe, never guest exposure.
    stgi
    mov  ecx, 0xC0000080
    mov  rax, r14
    mov  rdx, r14
    shr  rdx, 32
    wrmsr
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, r14
    jne  cpu_boundary_fail_stop
.disarm:
    test r13, r13
    jz   .depart_native
    mov  rdi, r13
    call cpu_boundary_fault_disarm
    test eax, eax
    jnz  cpu_boundary_fail_stop
.depart_native:
    lock bts dword [rel smp_cc_departed], ebx
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    popfq
    ret

; Guarded native check RDI token -> EAX1 parking held, EDX0 architectural
; custody UNKNOWN, ECX15 native facts (complete enabled inventory, IF0 park,
; writer gate, nonresuming per-CPU guards). Never convert ECX into SEC custody1.
; The owner guard stays live until completed host restore and exact drain.
smp_core_custody_check_native_guarded:
    cmp  dword [rel smp_cc_svm_mode], 2
    jne  .bad
    call smp_cc_check_common
    test eax, eax
    jz   .bad
    call smp_cc_svm_flags
    test eax, 1 << 8
    jnz  .poison
    mov  rdi, [rel smp_cc_svm_guard]
    call cpu_boundary_fault_check
    test eax, eax
    jz   .poison
    cmp  dword [rel smp_cc_svm_failed], 0
    jne  .poison
    mov  eax, [rel smp_cc_members]
    and  eax, ~1
    cmp  eax, [rel smp_cc_svm_ready]
    jne  .poison
    mov  eax, 1
    xor  edx, edx                       ; architectural custody UNKNOWN
    mov  ecx, 15                        ; native parking facts, separate domain
    ret
.poison:
    mov  dword [rel smp_core_custody_gate], 4
.bad:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    ret

smp_core_custody_release_native_guarded:
    call smp_core_custody_check_native_guarded
    test eax, eax
    jz   .out
    jmp  smp_cc_drain
.out:
    ret

; T1-5 S7 (P2) gang-member check, AP context only: the designated AP's own
; boundary frame inside the BSP's guarded epoch. RDI the frame's read-only
; token copy, ESI the designated logical CPU, RDX this CPU's park guard ->
; EAX1, EDX0 architectural custody UNKNOWN, ECX SMP_CC_GANG_FACTS (separate
; domain, never 15 or custody1). The AP never acquires, releases or drains.
; A wrong caller or a generation not live is a plain 0; once the token names
; the live phase-2 generation, any missing invariant poisons it (phase 4).
smp_core_custody_check_gang_member:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    mov  ax, cs
    test al, 3
    jnz  .bad
    pushfq
    pop  rax
    test eax, (1 << 8) | (1 << 9)       ; TF0, IF0
    jnz  .bad
    test r12d, r12d
    jz   .bad                            ; never the owner
    cmp  r12d, MAXCORE
    jae  .bad
    call smp_current_logical
    cmp  eax, r12d
    jne  .bad
    test rbx, rbx
    jz   .bad
    cmp  rbx, [rel smp_cc_request]
    jne  .bad
    mov  rax, [rel smp_core_custody_gate]
    mov  edx, eax
    and  edx, 7
    cmp  edx, 2
    jne  .bad
    lea  ecx, [r12 + 32]
    bt   rax, rcx                        ; this CPU acked this generation
    jnc  .poison
    cmp  dword [rel smp_cc_svm_mode], 2
    jne  .poison
    bt   dword [rel smp_cc_members], r12d
    jnc  .poison
    bt   dword [rel smp_cc_svm_ready], r12d
    jnc  .poison
    bt   dword [rel smp_cc_svm_failed], r12d
    jc   .poison
    bt   dword [rel smp_cc_departed], r12d
    jc   .poison
    cmp  qword [rel smp_cc_release], 0
    jne  .poison
    call smp_read_apic_id
    lea  rdx, [rel smp_cc_inventory_rows]
    imul ecx, r12d, 24
    cmp  eax, [rdx + rcx]
    jne  .poison
    mov  rdi, r13
    call cpu_boundary_fault_check
    test eax, eax
    jz   .poison
    mov  eax, 1
    xor  edx, edx
    mov  ecx, SMP_CC_GANG_FACTS
    jmp  .out
.poison:
    mov  dword [rel smp_core_custody_gate], 4
.bad:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; SVM phase APIs are additive. Every CALL still requires IF0; only the explicit
; TRANSFER lifetime permits the trusted SVM caller's IF1 under provider GIF0.
; 0 HOST,1 PREPARED,2 TRANSFER,3 LANDED. No sample/bitmap conversion grants this.
smp_core_custody_svm_prepare:
    push rbx
    mov  rbx, rdi
    call smp_cc_svm_native_check
    test eax, eax
    jz   .out
    cmp  dword [rel smp_cc_svm_phase], 0
    jne  .bad
    mov  ecx, 0xC0000080
    rdmsr
    test eax, 1 << 12
    jz   .bad
    clgi
    mov  dword [rel smp_cc_svm_phase], 1
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

smp_cc_svm_native_check:
    call smp_core_custody_check
    test eax, eax
    jz   smp_cc_svm_bad
    cmp  dword [rel smp_cc_svm_mode], 1
    jne  smp_cc_svm_bad
    call smp_cc_svm_flags
    test eax, 1 << 8
    jnz  smp_cc_svm_poison
    mov  rdi, [rel smp_cc_svm_guard]
    call cpu_boundary_fault_check
    test eax, eax
    jz   smp_cc_svm_poison
    cmp  dword [rel smp_cc_svm_failed], 0
    jne  smp_cc_svm_poison
    mov  eax, [rel smp_cc_members]
    and  eax, ~1
    cmp  eax, [rel smp_cc_svm_ready]
    jne  smp_cc_svm_poison
    mov  eax, 1
    ret

smp_core_custody_svm_check:
    call smp_cc_svm_native_check
    test eax, eax
    jz   smp_cc_svm_bad
    mov  ecx, 0xC0000080
    rdmsr
    test eax, 1 << 12
    jz   smp_cc_svm_poison
    mov  eax, [rel smp_cc_svm_phase]
    cmp  eax, 1
    je   .ready
    cmp  eax, 3
    jne  smp_cc_svm_bad
.ready:
    mov  eax, 1
    mov  edx, 1                         ; distinct, architecturally enforced enum
    ret

smp_core_custody_svm_transfer:
    call smp_core_custody_svm_check
    test eax, eax
    jz   smp_cc_svm_bad
    cmp  dword [rel smp_cc_svm_phase], 1
    jne  smp_cc_svm_bad
    mov  dword [rel smp_cc_svm_phase], 2
    mov  eax, 1
    ret

smp_core_custody_svm_land:
    call smp_cc_svm_native_check
    test eax, eax
    jz   smp_cc_svm_bad
    cmp  dword [rel smp_cc_svm_phase], 2
    jne  smp_cc_svm_bad
    mov  dword [rel smp_cc_svm_phase], 3
    mov  eax, 1
    ret

smp_core_custody_svm_host:
    call smp_core_custody_svm_check
    test eax, eax
    jz   smp_cc_svm_bad
    mov  dword [rel smp_cc_svm_phase], 0
    stgi                               ; exit executor/clean refusal completed
    mov  eax, 1
    ret

smp_core_custody_release_svm:
    call smp_cc_svm_native_check
    test eax, eax
    jz   smp_cc_svm_bad
    cmp  dword [rel smp_cc_svm_phase], 0
    jne  smp_cc_svm_bad
    jmp  smp_cc_drain

smp_cc_svm_flags:
    pushfq
    pop  rax
    ret

smp_cc_svm_poison:
    mov  dword [rel smp_core_custody_gate], 4
smp_cc_svm_bad:
    xor  eax, eax
    xor  edx, edx
    ret

; Additive Intel provider: authoritative absent siblings, not AP quiescence.
; Other physical cores keep running. Owner VMX controls/frontiers remain VM's.
; CPUID.1F/0B subleaf0 must report native Intel SMT domain count1/shift0.
; No online count, inferred shift cardinality or generic facts7 grants absence.
; EDI expected full APIC -> EAX1 absent,0 unsupported/unknown; preserves RBX.
smp_cc_intel_absent_local:
    push rbx
    mov  r8d, edi
    xor  eax, eax
    cpuid
    cmp  ebx, 'Genu'
    jne  .bad
    cmp  edx, 'ineI'
    jne  .bad
    cmp  ecx, 'ntel'
    jne  .bad
    mov  r9d, eax
    cmp  r9d, 0x0B
    jb   .bad
    mov  eax, 1
    cpuid
    bt   ecx, 31                        ; native observation, no hypervisor proxy
    jc   .bad
    mov  eax, 0x0B
    cmp  r9d, 0x1F
    jb   .sample
    mov  eax, 0x1F
    xor  ecx, ecx
    cpuid
    test ebx, 0xFFFF
    jnz  .validate                      ; present but malformed/SMT never fallback
    mov  eax, 0x0B
.sample:
    xor  ecx, ecx
    cpuid
.validate:
    cmp  edx, r8d                       ; same full32 CPU, no BSP proxy
    jne  .bad
    and  ecx, 0xFFFF
    cmp  ecx, 0x100                     ; subleaf0, level type SMT
    jne  .bad
    and  ebx, 0xFFFF
    cmp  ebx, 1                         ; reported cardinality, not 1<<shift
    jne  .bad
    and  eax, 31
    test eax, eax                      ; bounded contract: zero SMT address bits
    jnz  .bad
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; EDI expected full BSP APIC, RDX exact live fault cookie (RSI unused).
; RAX nonzero private generation token,0 clean refusal,-1 poisoned state.
; All calls CPL0/IF0/DF0/TF0, outside IRQ, same trusted BSP and live guard.
; No peer request/ack is issued: each physical core has exactly one member.
smp_core_custody_acquire_intel_absent:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rdx
    call smp_cc_context
    test eax, eax
    jz   .refuse
    cmp  edx, r12d
    jne  .refuse
    call smp_cc_svm_flags
    test eax, 1 << 8
    jnz  .refuse
    mov  rdi, r13
    call cpu_boundary_fault_check
    test eax, eax
    jz   .refuse
    xor  eax, eax
    mov  edx, 1
    lock cmpxchg [rel smp_core_custody_gate], rdx
    jne  .occupied
    cmp  qword [rel smp_cc_request], 0
    jne  .poison                       ; uncertain previous peer lifetime
    cmp  qword [rel smp_cc_generation], 0x1FFFFFFF
    jae  .free_refuse
    call smp_cc_intel_membership
    test eax, eax
    jz   .free_refuse
    mov  [rel smp_cc_members], eax
    mov  edi, r12d
    call smp_cc_intel_absent_local
    test eax, eax
    jz   .free_refuse
    xor  edi, edi
    call smp_cc_inventory
    mov  [rel smp_cc_owner_apic], r12d
    mov  [rel smp_cc_intel_guard], r13
    inc  qword [rel smp_cc_generation]
    mov  rbx, [rel smp_cc_generation]
    mov  [rel smp_cc_intel_token], rbx
    mov  rax, rbx
    shl  rax, 3
    or   rax, 2
    mov  [rel smp_core_custody_gate], rax
    mov  rdi, rbx
    call smp_core_custody_check_intel_absent
    test eax, eax
    jz   .poison
    mov  rax, rbx
    jmp  .out
.free_refuse:
    mov  qword [rel smp_core_custody_gate], 0
.refuse:
    xor  eax, eax
    jmp  .out
.occupied:
    and  eax, 7
    cmp  eax, 4
    jne  .refuse
    jmp  .uncertain
.poison:
    mov  dword [rel smp_core_custody_gate], 4
.uncertain:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI private token -> EAX1/EDX1 HELD_ALL_SIBLINGS_ABSENT;0/0 otherwise.
; This fact covers sibling event activity vacuously, not owner VMX event safety.
; Exact-owner held invariant loss poisons; foreign/wrong tokens cannot free it.
smp_core_custody_check_intel_absent:
    push rbx
    mov  rbx, rdi
    call smp_cc_context
    test eax, eax
    jz   .bad
    cmp  edx, [rel smp_cc_owner_apic]
    jne  .bad
    test rbx, rbx
    jz   .bad
    cmp  rbx, [rel smp_cc_intel_token]
    jne  .bad
    mov  rax, rbx
    shl  rax, 3
    or   rax, 2
    cmp  rax, [rel smp_core_custody_gate]
    jne  .bad
    cmp  qword [rel smp_cc_request], 0
    jne  .poison
    call smp_cc_svm_flags
    test eax, 1 << 8
    jnz  .poison
    mov  rdi, [rel smp_cc_intel_guard]
    call cpu_boundary_fault_check
    test eax, eax
    jz   .poison
    mov  edi, [rel smp_cc_owner_apic]
    call smp_cc_intel_absent_local
    test eax, eax
    jz   .poison
    call smp_cc_intel_membership
    test eax, eax
    jz   .poison
    cmp  eax, [rel smp_cc_members]
    jne  .poison
    mov  edi, 1
    call smp_cc_inventory
    test eax, eax
    jz   .poison
    mov  eax, 1
    mov  edx, 1
    pop  rbx
    ret
.poison:
    mov  dword [rel smp_core_custody_gate], 4
.bad:
    xor  eax, eax
    xor  edx, edx
    pop  rbx
    ret

; Only after completed protected owner host restore, before guard disarm and
; either hostwork opening. Zero peers were parked, so exact drain is empty.
smp_core_custody_release_intel_absent:
    push rbx
    mov  rbx, rdi
    call smp_core_custody_check_intel_absent
    test eax, eax
    jz   .out
    mov  qword [rel smp_cc_intel_token], 0
    mov  qword [rel smp_cc_intel_guard], 0
    mov  qword [rel smp_core_custody_gate], 0
    mov  eax, 1
.out:
    pop  rbx
    ret

%macro WDATA_smp_core_custody 0
align 8
smp_core_custody_gate: dq 0
smp_cc_generation: dq 0
smp_cc_request: dq 0
smp_cc_release: dq 0
smp_cc_departed: dd 0
smp_cc_members: dd 0
smp_cc_owner_apic: dd 0
smp_cc_svm_mode: dd 0
smp_cc_svm_ready: dd 0
smp_cc_svm_failed: dd 0
smp_cc_svm_phase: dd 0
align 8
smp_cc_svm_guard: dq 0
smp_cc_intel_guard: dq 0
smp_cc_intel_token: dq 0
cpu_sibling_count: times MAXCORE dd 0
align 8
smp_cc_inventory_rows: times MAXCORE * 24 db 0
%endmacro
WDATA_DEFER WDATA_smp_core_custody
; END CORE CUSTODY NATIVE

; smp_mapping_update_begin(RDI=linear address, zero means full CR3 flush).
; Returns CF=0 with every online peer quiesced and smp_mapping_lock held across
; the caller's mutation.  Failure releases every peer and the lock before CF=1.
smp_mapping_update_begin:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    call smp_mapping_lock_acquire
    cmp  dword [rel smp_discovered_count], 0
    jne  .resolve_owner
    xor  r12d, r12d                       ; pre-SMP hotpatch: local BSP only
    mov  dword [rel smp_mapping_required_mask], 1
    jmp  .owner_ready
.resolve_owner:
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .fail_unlock
    mov  [rel smp_mapping_owner], eax
    mov  r12d, eax
    call smp_online_mask_now
    mov  [rel smp_mapping_required_mask], eax
    bt   eax, r12d
    jnc  .fail_unlock
.owner_ready:
    mov  [rel smp_mapping_owner], r12d
    inc  dword [rel smp_tlb_epoch]
    jnz  .epoch_ready
    inc  dword [rel smp_tlb_epoch]
.epoch_ready:
    mov  eax, [rel smp_tlb_epoch]
    lea  ecx, [eax - 1]
    mov  [rel smp_release_epoch], ecx
    mov  [rel smp_mapping_target], r13
    mov  dword [rel smp_quiesce_ack_mask], 0
    mov  dword [rel smp_tlb_ack_mask], 0
    lock bts dword [rel smp_quiesce_ack_mask], r12d
    mfence
    xor  ebx, ebx
.send:
    cmp  ebx, [rel smp_discovered_count]
    jae  .wait
    cmp  ebx, r12d
    je   .next
    mov  eax, [rel smp_mapping_required_mask]
    bt   eax, ebx
    jnc  .next
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + rbx*4]
    mov  esi, SMP_ICR_FIXED | SMP_COHERENCE_VECTOR
    call smp_lapic_send_ipi
.next:
    inc  ebx
    jmp  .send
.wait:
    mov  ebx, 4000                         ; bounded 200 ms rendezvous
.wait_loop:
    mov  eax, [rel smp_quiesce_ack_mask]
    and  eax, [rel smp_mapping_required_mask]
    cmp  eax, [rel smp_mapping_required_mask]
    je   .ok
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_loop
    mov  eax, [rel smp_tlb_epoch]          ; release peers that did arrive
    mov  [rel smp_release_epoch], eax
    mfence
.fail_unlock:
    call smp_mapping_lock_release
    stc
    jmp  .out
.ok:
    clc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Commit the mutation guarded by smp_mapping_update_begin.  The initiator
; invalidates locally, releases peers, waits for all acknowledgements, and then
; derives stale_mapping from per-CPU epoch + post-release witness observations.
smp_mapping_update_commit:
    push rbx
    push r12
    push r13
    cmp  dword [rel smp_discovered_count], 0
    jne  .resolve_owner
    xor  r12d, r12d
    jmp  .owner_ready
.resolve_owner:
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .failed
    mov  r12d, eax
.owner_ready:
    mov  rax, [rel smp_mapping_target]
    test rax, rax
    jz   .flush_all
    invlpg [rax]
    jmp  .local_sample
.flush_all:
    mov  rax, cr3
    mov  cr3, rax
.local_sample:
    mfence
    xor  eax, eax
    cpuid                                  ; serialize initiator instruction fetch
    mov  r13, [rel smp_mapping_probe]
    mov  [rel smp_mapping_expected], r13
    lea  rax, [rel cpu_mapping_observed]
    mov  [rax + r12*8], r13
    lea  rax, [rel cpu_tlb_epoch]
    mov  ecx, [rel smp_tlb_epoch]
    mov  [rax + r12*4], ecx
    lock bts dword [rel smp_tlb_ack_mask], r12d
    mfence
    mov  [rel smp_release_epoch], ecx      ; peers invalidate only after mutation
    mov  ebx, 4000
.wait_ack:
    mov  eax, [rel smp_tlb_ack_mask]
    and  eax, [rel smp_mapping_required_mask]
    cmp  eax, [rel smp_mapping_required_mask]
    je   .grade
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_ack
.grade:
    mov  eax, [rel smp_mapping_required_mask]
    call smp_popcount32
    mov  [rel smp_tlb_requested], eax
    mov  eax, [rel smp_tlb_ack_mask]
    and  eax, [rel smp_mapping_required_mask]
    call smp_popcount32
    mov  [rel smp_tlb_acked], eax
    mov  dword [rel smp_stale_mapping], 0
    xor  ebx, ebx
.grade_cpu:
    cmp  ebx, [rel smp_discovered_count]
    jae  .graded
    mov  eax, [rel smp_mapping_required_mask]
    bt   eax, ebx
    jnc  .grade_next
    lea  rax, [rel cpu_tlb_epoch]
    mov  ecx, [rel smp_tlb_epoch]
    cmp  [rax + rbx*4], ecx
    jne  .stale
    lea  rax, [rel cpu_mapping_observed]
    cmp  [rax + rbx*8], r13
    je   .grade_next
.stale:
    inc  dword [rel smp_stale_mapping]
.grade_next:
    inc  ebx
    jmp  .grade_cpu
.graded:
    mov  eax, [rel smp_tlb_requested]
    cmp  eax, [rel smp_tlb_acked]
    jne  .failed
    cmp  dword [rel smp_stale_mapping], 0
    jne  .failed
    clc
    jmp  .unlock
.failed:
    stc
.unlock:
    call smp_mapping_lock_release
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- smpwork_snapshot(EDI = challenge32) -> EAX = workers in the frozen
;      response snapshot. Bring-up freezes smpwork_expected_workers from the
;      stable smp_online_aps count. Every request waits for that full set, then
;      copies epoch/token/runs under rq_lock so the header and rows cannot observe
;      different instants. The wait remains bounded at 100 ms. ----
smpwork_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, edi
    call smp_state_lock_acquire
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jne  .owned
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_SYNC
    mov  [rel smpwork_challenge], r14d
    inc  dword [rel smpwork_requested_epoch]
    mov  r15d, [rel smpwork_requested_epoch]
    call smp_state_lock_release
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick

    mov  r13d, SMPWORK_WAIT_STEPS
.wait:
    call smp_state_lock_acquire
    xor  r12d, r12d                       ; workers at requested epoch
    xor  ebx, ebx
.scan:
    cmp  ebx, MAXCORE
    jae  .scan_done
    mov  eax, [rel smpwork_expected_mask]
    bt   eax, ebx
    jnc  .scan_next                       ; ignore APs outside the frozen set
    lea  rax, [rel smpwork_worker_epoch]
    cmp  dword [rax + rbx*4], r15d
    jne  .scan_next
    inc  r12d
.scan_next:
    inc  ebx
    jmp  .scan
.scan_done:
    call smp_state_lock_release
    cmp  r12d, [rel smpwork_expected_workers]
    jae  .freeze
    mov  edi, 50                          ; bounded 50 us cadence, 100 ms total
    call tsc_delay_us
    dec  r13d
    jnz  .wait

.freeze:
    ; Freeze exactly one epoch while AP publication is excluded. Clear every
    ; row first so a timed-out request cannot inherit a prior epoch's row.
    call smp_state_lock_acquire
    mov  [rel smpwork_snapshot_challenge], r14d
    mov  [rel smpwork_snapshot_epoch], r15d
    mov  dword [rel smpwork_snapshot_workers], 0
    xor  ebx, ebx
.copy:
    cmp  ebx, MAXCORE
    jae  .copy_done
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    mov  dword [rax + rbx*4], 0
    mov  eax, [rel smpwork_expected_mask]
    bt   eax, ebx
    jnc  .copy_next
    lea  rax, [rel smpwork_worker_epoch]
    cmp  dword [rax + rbx*4], r15d
    jne  .copy_next
    lea  rax, [rel smpwork_worker_token]
    mov  r12d, [rax + rbx*4]
    lea  rax, [rel smpwork_snapshot_worker_token]
    mov  [rax + rbx*4], r12d
    lea  rax, [rel smpwork_worker_runs]
    mov  r12, [rax + rbx*8]
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  [rax + rbx*8], r12
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    mov  [rax + rbx*4], r15d               ; publish frozen row last
    inc  dword [rel smpwork_snapshot_workers]
.copy_next:
    inc  ebx
    jmp  .copy
.copy_done:
    call smp_state_lock_release
    call smpwork_validate_live
    call smp_state_lock_acquire
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    call smp_state_lock_release
    mov  eax, [rel smpwork_snapshot_workers]
    clc
    jmp  .out
.owned:
    call smp_state_lock_release
    xor  eax, eax
    stc                                  ; honest busy, no epoch or row mutation
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Cooperative snapshot service. All APIs preserve SysV callee-saved registers.
; Begin(source64 RDI, principal64 RSI, challenge32 EDX) -> EAX status,
; RDX generation64 only on PENDING (zero on refusal). The source/principal
; must come from the dispatch request, never a mutable "last caller" cell.
; Step() -> EAX status: one try-lock, one scan and at most one 32-row copy.
; Take/cancel/status(source RDI, principal RSI, challenge EDX, generation RCX) require
; an exact four-field owner match. Take is destructive only when terminal;
; its frozen snapshot globals must be formatted/copied before another begin.
; Command dispatch and resident service are BSP-serialized. APs only publish.
; Every phase/row transition is under the existing state lock. No step spins,
; delays, waits for an AP, allocates or starts another epoch.
smpwork_async_try_lock:
    push rdi
    lea  rdi, [rel smp_state_lock]
    call spin_try_acquire
    pop  rdi
    ret

smpwork_async_begin:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    call smpwork_async_step               ; includes abandoned-slot expiry
    call smpwork_async_try_lock
    test eax, eax
    jz   .busy_unheld
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jne  .busy
    call time_monotonic_now_us
    test rax, rax
    jz   .clock
    mov  r8, rax
    add  r8, SMPWORK_ASYNC_RETAIN_US
    jc   .clock
    mov  r9, rax
    add  r9, SMPWORK_ASYNC_WAIT_US
    jc   .clock
    cmp  qword [rel smpwork_async_generation], -1
    je   .counter
    mov  edx, [rel smpwork_requested_epoch]
    inc  edx
    jz   .epoch_wrap
    mov  ecx, [rel smpwork_expected_mask]
    xor  edi, edi
    xor  esi, esi
.count:
    bt   ecx, esi
    adc  edi, 0
    inc  esi
    cmp  esi, MAXCORE
    jb   .count
    cmp  edi, [rel smpwork_expected_workers]
    jne  .topology
    mov  [rel smpwork_async_mask], ecx
    mov  [rel smpwork_async_expected], edi
    mov  [rel smpwork_async_start], rax
    mov  [rel smpwork_async_last], rax
    mov  [rel smpwork_async_deadline], r9
    mov  [rel smpwork_async_expiry], r8
    mov  [rel smpwork_async_source], r12
    mov  [rel smpwork_async_principal], r13
    mov  [rel smpwork_async_nonce], r14d
    mov  [rel smpwork_challenge], r14d
    mov  [rel smpwork_async_epoch], edx
    ; Clear publication sentinels before opening an epoch, including wrap reuse.
    xor  ecx, ecx
.clear:
    lea  rax, [rel smpwork_worker_epoch]
    mov  dword [rax + rcx*4], 0
    inc  ecx
    cmp  ecx, MAXCORE
    jb   .clear
    inc  qword [rel smpwork_async_generation]
    mov  [rel smpwork_requested_epoch], edx
    mov  dword [rel smpwork_async_result], 0 ; retire any cancelled tombstone
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    mov  eax, SMPWORK_ASYNC_PENDING
    jmp  .unlock
.epoch_wrap:
    ; Zero is never an active epoch. Consume the wrap sentinel without a job.
    mov  dword [rel smpwork_requested_epoch], 0
.counter:
    mov  eax, SMPWORK_ASYNC_COUNTER
    jmp  .unlock
.clock:
    mov  eax, SMPWORK_ASYNC_CLOCK
    jmp  .unlock
.topology:
    mov  eax, SMPWORK_ASYNC_TOPOLOGY
    jmp  .unlock
.busy:
    mov  eax, SMPWORK_ASYNC_BUSY
.unlock:
    push rax
    call smp_state_lock_release
    pop  rax
    xor  edx, edx
    cmp  eax, SMPWORK_ASYNC_PENDING
    jne  .out
    push rax
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick
    pop  rax
    mov  rdx, [rel smpwork_async_generation]
    jmp  .out
.busy_unheld:
    mov  eax, SMPWORK_ASYNC_BUSY
    xor  edx, edx
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

smpwork_async_step:
    push rbx
    push r12
    push r13
    call smpwork_async_try_lock
    test eax, eax
    jz   .busy
    mov  eax, [rel smpwork_async_phase]
    cmp  eax, SMPWORK_ASYNC_IDLE
    je   .unlock
    cmp  eax, SMPWORK_ASYNC_SYNC
    je   .sync
    call time_monotonic_now_us
    test rax, rax
    jz   .clock
    cmp  rax, [rel smpwork_async_last]
    jb   .clock
    mov  [rel smpwork_async_last], rax
    cmp  rax, [rel smpwork_async_expiry]
    jae  .expire
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    je   .result
    mov  r12, rax
    xor  ebx, ebx
    xor  r13d, r13d
.scan:
    mov  eax, [rel smpwork_async_mask]
    bt   eax, ebx
    jnc  .next
    lea  rax, [rel smpwork_worker_epoch]
    mov  ecx, [rel smpwork_async_epoch]
    cmp  [rax + rbx*4], ecx
    jne  .next
    ; Independently check the AP's final publication sample as well as epoch.
    lea  rax, [rel smpwork_worker_published_us]
    mov  rdx, [rax + rbx*8]
    cmp  rdx, [rel smpwork_async_start]
    jb   .next
    cmp  rdx, [rel smpwork_async_deadline]
    jae  .next
    cmp  rdx, r12                         ; a future stamp is not observed work
    ja   .next
    inc  r13d
.next:
    inc  ebx
    cmp  ebx, MAXCORE
    jb   .scan
    cmp  r13d, [rel smpwork_async_expected]
    je   .freeze
    cmp  r12, [rel smpwork_async_deadline]
    jae  .freeze
    mov  eax, SMPWORK_ASYNC_PENDING
    jmp  .unlock
.freeze:
    mov  eax, [rel smpwork_async_nonce]
    mov  [rel smpwork_snapshot_challenge], eax
    mov  eax, [rel smpwork_async_epoch]
    mov  [rel smpwork_snapshot_epoch], eax
    mov  dword [rel smpwork_snapshot_workers], 0
    xor  ebx, ebx
.copy:
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    mov  dword [rax + rbx*4], 0
    mov  eax, [rel smpwork_async_mask]
    bt   eax, ebx
    jnc  .copy_next
    lea  rax, [rel smpwork_worker_epoch]
    mov  ecx, [rel smpwork_async_epoch]
    cmp  [rax + rbx*4], ecx
    jne  .copy_next
    lea  rax, [rel smpwork_worker_published_us]
    mov  rdx, [rax + rbx*8]
    cmp  rdx, [rel smpwork_async_start]
    jb   .copy_next
    cmp  rdx, [rel smpwork_async_deadline]
    jae  .copy_next
    cmp  rdx, r12
    ja   .copy_next
    lea  rax, [rel smpwork_worker_token]
    mov  edx, [rax + rbx*4]
    lea  rax, [rel smpwork_snapshot_worker_token]
    mov  [rax + rbx*4], edx
    lea  rax, [rel smpwork_worker_runs]
    mov  rdx, [rax + rbx*8]
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    mov  [rax + rbx*4], ecx
    inc  dword [rel smpwork_snapshot_workers]
.copy_next:
    inc  ebx
    cmp  ebx, MAXCORE
    jb   .copy
    call smpwork_validate_live             ; audit bits freeze with the rows
    mov  eax, SMPWORK_ASYNC_COMPLETE
    mov  ecx, [rel smpwork_snapshot_workers]
    cmp  ecx, [rel smpwork_async_expected]
    je   .terminal
    mov  eax, SMPWORK_ASYNC_PARTIAL
.terminal:
    mov  [rel smpwork_async_result], eax
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    jmp  .unlock
.clock:
    ; A terminal snapshot is immutable even if a later clock sample regresses.
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    je   .result
    ; Clock faults never turn missing/late rows into a complete snapshot.
    mov  eax, SMPWORK_ASYNC_CLOCK
    jmp  .terminal
.expire:
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    mov  eax, SMPWORK_ASYNC_STALE
    jmp  .unlock
.result:
    mov  eax, [rel smpwork_async_result]
    jmp  .unlock
.sync:
    mov  eax, SMPWORK_ASYNC_BUSY
.unlock:
    push rax
    call smp_state_lock_release
    pop  rax
    jmp  .out
.busy:
    mov  eax, SMPWORK_ASYNC_BUSY
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Caller holds state lock; exact identity is checked before ANY slot mutation.
smpwork_async_owned:
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    je   .identity
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    jne  .stale
.identity:
    jmp  smpwork_async_identity
.stale:
    stc
    ret

; Caller holds state lock. Includes retired identity for read-only cancellation.
smpwork_async_identity:
    cmp  rdi, [rel smpwork_async_source]
    jne  .stale
    cmp  rsi, [rel smpwork_async_principal]
    jne  .stale
    cmp  edx, [rel smpwork_async_nonce]
    jne  .stale
    cmp  rcx, [rel smpwork_async_generation]
    jne  .stale
    clc
    ret
.stale:
    stc
    ret

; Retained observation only: one try-lock, exact owner, no maintenance/clock,
; row scan, result take or lifecycle writes. Elapsed time is not sampled here.
; CANCELLED survives IDLE until a successful BEGIN admits a successor.
smpwork_async_status:
    call smpwork_async_try_lock
    test eax, eax
    jz   smpwork_async_busy
    call smpwork_async_identity
    jc   smpwork_async_stale
    mov  eax, SMPWORK_ASYNC_PENDING
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    je   smpwork_async_return
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    je   .result
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jne  smpwork_async_stale
    cmp  dword [rel smpwork_async_result], SMPWORK_ASYNC_CANCELLED
    jne  smpwork_async_stale
.result:
    mov  eax, [rel smpwork_async_result]
    jmp  smpwork_async_return

; Owned retained admission detail. Same owner ABI as STATUS; R8 points to a
; writable caller-owned 32-byte record: phase/result/epoch/mask/expected/nonce
; (six u32), generation (u64). BUSY/STALE zero the record, meaning UNKNOWN,
; not an admitted zero-valued fact. All valid fields are copied under ONE
; try-lock. No clock, service step, row scan, take or lifecycle write.
smpwork_async_detail:
    mov  qword [r8], 0
    mov  qword [r8 + 8], 0
    mov  qword [r8 + 16], 0
    mov  qword [r8 + 24], 0
    call smpwork_async_try_lock
    test eax, eax
    jz   smpwork_async_busy
    call smpwork_async_identity
    jc   smpwork_async_stale
    mov  eax, SMPWORK_ASYNC_PENDING
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    je   .copy
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    je   .result
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jne  smpwork_async_stale
    cmp  dword [rel smpwork_async_result], SMPWORK_ASYNC_CANCELLED
    jne  smpwork_async_stale
.result:
    mov  eax, [rel smpwork_async_result]
.copy:
    mov  r9d, [rel smpwork_async_phase]
    mov  [r8], r9d
    mov  r9d, [rel smpwork_async_result]
    mov  [r8 + 4], r9d
    mov  r9d, [rel smpwork_async_epoch]
    mov  [r8 + 8], r9d
    mov  r9d, [rel smpwork_async_mask]
    mov  [r8 + 12], r9d
    mov  r9d, [rel smpwork_async_expected]
    mov  [r8 + 16], r9d
    mov  r9d, [rel smpwork_async_nonce]
    mov  [r8 + 20], r9d
    mov  r9, [rel smpwork_async_generation]
    mov  [r8 + 24], r9
    jmp  smpwork_async_return

; Original-owned retained publisher observation. Same owner ABI as DETAIL;
; R8 -> caller-private 48-byte record: first32 bytes match DETAIL, followed by
; u32 publication-known/mask/count/reserved. One state try-lock also protects
; AP epoch/timestamp publication. Bounded32-row scan; no clock/step or writes
; outside caller memory. Stored [start,deadline) is not a fresh time sample.
smpwork_async_progress:
    mov  qword [r8], 0
    mov  qword [r8 + 8], 0
    mov  qword [r8 + 16], 0
    mov  qword [r8 + 24], 0
    mov  qword [r8 + 32], 0
    mov  qword [r8 + 40], 0
    call smpwork_async_try_lock
    test eax, eax
    jz   smpwork_async_busy
    call smpwork_async_identity
    jc   smpwork_async_stale
    mov  eax, SMPWORK_ASYNC_PENDING
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    je   .copy
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    je   .result
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jne  smpwork_async_stale
    cmp  dword [rel smpwork_async_result], SMPWORK_ASYNC_CANCELLED
    jne  smpwork_async_stale
.result:
    mov  eax, [rel smpwork_async_result]
.copy:
    mov  r9d, [rel smpwork_async_phase]
    mov  [r8], r9d
    mov  r9d, [rel smpwork_async_result]
    mov  [r8 + 4], r9d
    mov  r9d, [rel smpwork_async_epoch]
    mov  [r8 + 8], r9d
    mov  r9d, [rel smpwork_async_mask]
    mov  [r8 + 12], r9d
    mov  r9d, [rel smpwork_async_expected]
    mov  [r8 + 16], r9d
    mov  r9d, [rel smpwork_async_nonce]
    mov  [r8 + 20], r9d
    mov  r9, [rel smpwork_async_generation]
    mov  [r8 + 24], r9
    ; Publication rows are not frozen validation. Failure/cancel paths may
    ; retain older snapshot arrays, so this observer never reads those arrays.
    cmp  dword [r8], SMPWORK_ASYNC_PENDING
    je   .scan_init
    cmp  eax, SMPWORK_ASYNC_COMPLETE
    je   .scan_init
    cmp  eax, SMPWORK_ASYNC_PARTIAL
    jne  .return
.scan_init:
    mov  dword [r8 + 32], 1              ; known publication set, including zero
    xor  r9d, r9d
    mov  r10d, [r8 + 12]                ; original admitted membership
    mov  r11d, [r8 + 8]                 ; original admitted epoch
    xor  ecx, ecx                       ; qualifying publication mask
    xor  esi, esi                       ; qualifying publication count
.scan:
    bt   r10d, r9d
    jnc  .next
    lea  rax, [rel smpwork_worker_epoch]
    cmp  dword [rax + r9*4], r11d
    jne  .next
    lea  rax, [rel smpwork_worker_published_us]
    mov  rdx, [rax + r9*8]
    cmp  rdx, [rel smpwork_async_start]
    jb   .next
    cmp  rdx, [rel smpwork_async_deadline]
    jae  .next
    bts  ecx, r9d
    inc  esi
.next:
    inc  r9d
    cmp  r9d, MAXCORE
    jb   .scan
    mov  [r8 + 36], ecx
    mov  [r8 + 40], esi
.return:
    mov  eax, SMPWORK_ASYNC_PENDING
    cmp  dword [r8], SMPWORK_ASYNC_PENDING
    je   smpwork_async_return
    mov  eax, [r8 + 4]
    jmp  smpwork_async_return

; Non-consuming final result observation. Owner ABI matches DETAIL; R8 must
; point to writable caller-owned448 bytes (see docs/smpwork_owned_results.md).
; Clear first, then ONE try-lock and exact full-width identity check. Only a
; FROZEN COMPLETE/PARTIAL copies final facts. Other states leave ALL unknown.
; Only retained snapshot rows are read; no AP/live scan, clock or lifecycle
; write. Caller storage remains private after unlock and successor admission.
smpwork_async_results:
    xor  eax, eax
    xor  r9d, r9d
.clear:
    mov  [r8 + r9*8], rax
    inc  r9d
    cmp  r9d, 56
    jb   .clear
    call smpwork_async_try_lock
    test eax, eax
    jz   smpwork_async_busy
    call smpwork_async_identity
    jc   smpwork_async_stale
    mov  eax, SMPWORK_ASYNC_PENDING
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    je   smpwork_async_return
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    je   .result
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jne  smpwork_async_stale
    cmp  dword [rel smpwork_async_result], SMPWORK_ASYNC_CANCELLED
    jne  smpwork_async_stale
.result:
    mov  eax, [rel smpwork_async_result]
    cmp  eax, SMPWORK_ASYNC_COMPLETE
    je   .copy
    cmp  eax, SMPWORK_ASYNC_PARTIAL
    jne  smpwork_async_return
.copy:
    mov  [r8 + 4], eax
    mov  eax, [rel smpwork_async_phase]
    mov  [r8], eax
    mov  eax, [rel smpwork_async_epoch]
    mov  [r8 + 8], eax
    mov  eax, [rel smpwork_async_mask]
    mov  [r8 + 12], eax
    mov  eax, [rel smpwork_async_expected]
    mov  [r8 + 16], eax
    mov  eax, [rel smpwork_async_nonce]
    mov  [r8 + 20], eax
    mov  rax, [rel smpwork_async_generation]
    mov  [r8 + 24], rax
    mov  eax, [rel smpwork_snapshot_workers]
    mov  [r8 + 36], eax
    movzx eax, byte [rel smpwork_rq_audit]
    mov  [r8 + 40], eax
    movzx eax, byte [rel smpwork_rt_bsp]
    mov  [r8 + 44], eax
    movzx eax, byte [rel smpwork_boot_bsp]
    mov  [r8 + 48], eax
    xor  r9d, r9d
    mov  r10d, [r8 + 12]
    mov  r11d, [r8 + 8]
.rows:
    bt   r10d, r9d
    jnc  .next
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    cmp  [rax + r9*4], r11d
    jne  .next
    bts  dword [r8 + 32], r9d
    lea  rax, [rel smpwork_snapshot_worker_token]
    mov  edx, [rax + r9*4]
    mov  [r8 + 64 + r9*4], edx
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  rdx, [rax + r9*8]
    mov  [r8 + 192 + r9*8], rdx
.next:
    inc  r9d
    cmp  r9d, MAXCORE
    jb   .rows
    mov  eax, [r8 + 4]
    jmp  smpwork_async_return

smpwork_async_maintain_owned:
    push rdi
    push rsi
    push rdx
    push rcx
    call smpwork_async_step
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

smpwork_async_take:
    call smpwork_async_maintain_owned
    call smpwork_async_try_lock
    test eax, eax
    jz   smpwork_async_busy
    call smpwork_async_owned
    jc   smpwork_async_stale
    mov  eax, SMPWORK_ASYNC_PENDING
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_FROZEN
    jne  smpwork_async_return
    mov  eax, [rel smpwork_async_result]
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    jmp  smpwork_async_return

smpwork_async_cancel:
    call smpwork_async_maintain_owned
    call smpwork_async_try_lock
    test eax, eax
    jz   smpwork_async_busy
    call smpwork_async_owned
    jc   smpwork_async_stale
    mov  dword [rel smpwork_async_result], SMPWORK_ASYNC_CANCELLED
    mov  dword [rel smpwork_async_phase], SMPWORK_ASYNC_IDLE
    mov  eax, SMPWORK_ASYNC_CANCELLED
    jmp  smpwork_async_return
smpwork_async_stale:
    mov  eax, SMPWORK_ASYNC_STALE
smpwork_async_return:
    push rax
    call smp_state_lock_release
    pop  rax
    ret
smpwork_async_busy:
    mov  eax, SMPWORK_ASYNC_BUSY
    ret

; ---- smp_crc32(EDI = 32-bit value) -> EAX = crc32 (zlib/IEEE-802.3, poly
;      0xEDB88320, reflected, init 0xFFFFFFFF, final xor) over the 4 LE bytes of
;      EDI. Matches python zlib.crc32(struct.pack("<I", v)) — the probe recomputes
;      exactly this. ----
smp_crc32:
    mov  eax, 0xFFFFFFFF                   ; crc
    mov  r8d, 4                            ; 4 bytes, little-endian
.byte_loop:
    movzx ecx, dil                        ; next LE byte of value
    xor  al, cl                           ; crc ^= byte (low 8 bits)
    mov  r9d, 8
.bit_loop:
    test eax, 1
    jz   .no_xor
    shr  eax, 1
    xor  eax, 0xEDB88320
    jmp  .bit_done
.no_xor:
    shr  eax, 1
.bit_done:
    dec  r9d
    jnz  .bit_loop
    shr  edi, 8                            ; advance to next byte
    dec  r8d
    jnz  .byte_loop
    not  eax                               ; final xor 0xFFFFFFFF
    ret

; ---- smp_read_apic_id -> EAX (xAPIC ID register bits 24..31) ----
smp_read_apic_id:
    jmp  smp_lapic_read_id

; ---- smpwork_worker_tick — one background/compounding-class task quantum.
;      R15D is the AP's dense logical id. live_runs is owner-only per-core data,
;      so the common path is lock-free. A newly published challenge is the real
;      sharing point: under rq_lock the AP stamps epoch/token/runs and refreshes
;      COREMAP's RUNNING count. ----
smp_frequency_worker_tick:
    push rbx
    push r12
    mov  ebx, r15d
    mov  r12d, [rel smp_freq_request_epoch]
    test r12d, r12d
    jz   .out
    lea  rax, [rel smp_freq_worker_epoch]
    cmp  [rax + rbx*4], r12d
    je   .out
    mov  edi, ebx
    call smp_frequency_sample_local
    mfence
    lea  rax, [rel smp_freq_worker_epoch]
    mov  [rax + rbx*4], r12d               ; row publication precedes ack
    lock bts dword [rel smp_freq_ack_mask], ebx
.out:
    pop  r12
    pop  rbx
    ret

smpwork_worker_tick:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, r15d
    lea  rax, [rel smpwork_live_runs]
    inc  qword [rax + rbx*8]
    mov  r12d, [rel smpwork_requested_epoch]
    test r12d, r12d
    jz   .out
    lea  rax, [rel smpwork_worker_epoch]
    cmp  dword [rax + rbx*4], r12d
    je   .out

    call smp_state_lock_acquire
    mov  edi, ebx
    call rq_lock_acquire
    mov  r12d, [rel smpwork_requested_epoch]
    test r12d, r12d
    jz   .unlock
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_SYNC
    je   .publish
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    jne  .unlock
    mov  eax, [rel smpwork_async_mask]
    bt   eax, ebx
    jnc  .unlock
.publish:
    mov  r13d, [rel smpwork_challenge]
    xor  r13d, ebx
    xor  r13d, r12d
    mov  edi, r13d
    call smp_crc32
    mov  r14d, eax
    lea  rax, [rel smpwork_worker_token]
    mov  [rax + rbx*4], r14d
    lea  rax, [rel smpwork_live_runs]
    mov  r14, [rax + rbx*8]
    lea  rax, [rel smpwork_worker_runs]
    mov  [rax + rbx*8], r14
    lea  rax, [rel coremap_counts]
    mov  [rax + rbx*4], r14d              ; low 32 = real RUNNING quantum count
    cmp  dword [rel smpwork_async_phase], SMPWORK_ASYNC_PENDING
    jne  .stamp
    ; Sample after CRC and row data preparation, just before epoch publication.
    ; Deadline is exclusive: a late AP cannot stamp this epoch even if no
    ; resident/poll step ran at the deadline.
    call time_monotonic_now_us
    cmp  rax, [rel smpwork_async_start]
    jb   .unlock
    cmp  rax, [rel smpwork_async_last]
    jb   .unlock
    cmp  rax, [rel smpwork_async_deadline]
    jae  .unlock
    lea  rdx, [rel smpwork_worker_published_us]
    mov  [rdx + rbx*8], rax
.stamp:
    lea  rax, [rel smpwork_worker_epoch]
    mov  [rax + rbx*4], r12d              ; publish last, under rq_lock
.unlock:
    mov  edi, ebx
    call rq_lock_release
    call smp_state_lock_release
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; One AP scheduler entry shared with the BSP benchmark driver. The predecessor
; SMPWORK quantum remains an additive observation task behind the unified
; dispatcher; APs no longer own a proof-only scheduler ABI.
smp_scheduler_tick:
    mov  edi, r15d                         ; RCQ-12 track 2: live par_for chunks first
    call smp_pf_ap_tick
    call smp_frequency_worker_tick
    call smp_msr_worker_tick
    call smp_msr_read_tick
    call smp_coherence_worker_tick
    cmp  byte [rel usched_job_mode], USCHED_MODE_PREEMPT
    je   .background_only
    mov  edi, r15d                         ; dense logical CPU
    call sched_unified_run_one
.background_only:
    call sched_watchdog_safe_frame
    jmp  smpwork_worker_tick

; ==========================================================================
; RCQ-12 track 2: the AP parallel-for lane (DP0 section 5.2, root 11:29:14).
; smp_par_for(EDI=body id, RSI=ctx, EDX=n_chunks) -> CF=0 every chunk ran,
;   CF=1 refused (unknown body, null ctx) or the bounded join timed out.
;   BSP only, run to completion, no task context. The BSP copies the caller's
;   ctx into the lane-owned descriptor, opens the lobby (smp_pf_active with the
;   claim word still 0) and wakes the ONLINE APs with IDLE_WAKE. Each AP checks
;   in and waits in the lobby; after every kicked AP checked in, or a bounded
;   rendezvous, the BSP publishes the claim word, so all of them start
;   together. The BSP claims alongside them and joins under a bounded deadline.
;   Every CPU claims the next index with lock cmpxchg on the packed claim word
;   (gen<<32 | next): a word read in an old generation can never claim in a
;   new one. A completion counts in the packed done word only while it names
;   the same generation.
;   The BSP runs every chunk itself (a plain loop) with no online AP (-smp 1),
;   on re-entry, or while a timed-out generation still owes a completion: a
;   dead or slow AP can only make a call slower, never hang it. After CF=1 from
;   a timeout, a late AP may still finish the chunk it claimed (at most one per
;   AP: the BSP drains the rest before the join). Caller contract (SEC P1/P2):
;   dst/src stay the caller's own and mapped; after CF=1 the caller never
;   consumes or publishes dst, and never releases, reuses or passes dst/src to
;   the lane again until smp_par_for_retired reports 1; the caller validates
;   dst/src/len (no wrap, inside its own buffers), which the lane does not.
; Chunk bodies are leaf, pure-memory routines selected by id through a direct
; jump chain (no table, no indirect call): each is reachable from smp_ap_main,
; so bsp_only_context_lint guards them. They never take a lock, allocate, or
; touch a capability or device.
; ==========================================================================
SMP_PF_BODY_FILL   equ 1               ; dst, len, chunk, fill
SMP_PF_BODY_COPY   equ 2               ; dst, src, len, chunk
SMP_PF_BODY_MATMUL equ 3               ; private float32 vector @ matrix, 16 columns/chunk
SMP_PF_BODY_MAX    equ 2               ; cooperative byte-lane ceiling is unchanged
SMP_PF_CTX_DST     equ 0
SMP_PF_CTX_SRC     equ 8
SMP_PF_CTX_LEN     equ 16
SMP_PF_CTX_CHUNK   equ 24
SMP_PF_CTX_FILL    equ 32                ; low byte
SMP_PF_CTX_SZ      equ 40
SMP_PF_RENDEZVOUS_POLLS equ 100          ; x 10 us: the lobby waits this long for kicked APs
SMP_PF_JOIN_POLLS  equ 10000             ; x 10 us: 100 ms bounded join
%if MAXCORE > 64
%error "smp_pf_seen_mask is one qword"
%endif

%ifdef PAOS_RCQ12_F3_HOLD_MS
%ifndef PAOS_RCQ12_F3_INJECT
%error "PAOS_RCQ12_F3_HOLD_MS needs PAOS_RCQ12_F3_INJECT"
%endif
%endif
%ifdef PAOS_RCQ12_F3_INJECT
; Finite lab-only, one-shot staged-copy timeout witness. No absent-define bytes.
%if PAOS_PUBLICITY_LAB_PROFILE != 1
%error "F3 needs publicity lab"
%endif
%if PAOS_SCAP_LAB_PROFILE != 1
%error "F3 needs SCAP lab"
%endif
%if PAOS_PUBLIC_BUILD != 0
%error "F3 forbids public builds"
%endif
%if PAOS_RCQ12_F3_INJECT < 1 || PAOS_RCQ12_F3_INJECT > 4096
%error "F3 draw must be 1..4096"
%endif
%ifndef PAOS_RCQ12_F3_HOLD_MS
%define PAOS_RCQ12_F3_HOLD_MS 2000
%endif
%if PAOS_RCQ12_F3_HOLD_MS < 2000 || PAOS_RCQ12_F3_HOLD_MS > 10000
%error "F3 hold must be 2000..10000 ms"
%endif
F3_IDLE equ 0
F3_ARMED equ 1
F3_FIRED equ 2
F3_EXPIRED equ 3
; Discovery swaps the BSP into cpu_apic_id[0]; fallback adds BSP first;
; smp_init assigns cpu_state[0] = CPU_STATE_BSP. This is not an AP slot test.
F3_BSP_DENSE equ 0
%macro WDATA_smp_f3_bss 0
alignb 4
f3_state: resd 1
f3_draws: resd 1
f3_fired_cpu: resd 1
f3_fired_pfgen: resd 1
f3_fired_gdgen: resd 1
f3_fired_index: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_smp_f3_bss
%endif
smp_par_for:
    cmp  dword [rel smp_pc_phase], 0
    jne  .cooperative_busy
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi                         ; body id
    mov  r13, rsi                          ; caller ctx
    mov  r14d, edx                         ; chunk count
    cmp  r12d, SMP_PF_BODY_MATMUL
    je   .matrix
    cmp  r12d, SMP_PF_BODY_FILL
    jb   .refuse
    cmp  r12d, SMP_PF_BODY_MAX
    ja   .refuse
    jmp  .validated
.matrix:
    mov  rsi, r13
    mov  edx, r14d
    call smp_matmul_validate
    jc   .refuse
.validated:
    test r13, r13
    jz   .refuse
    test r14d, r14d
    jz   .ok                               ; nothing to run
    call smp_current_logical
    mov  r15d, eax                         ; BSP accounting slot (MAXCORE = none)
    cmp  byte [rel smp_pf_active], 0
    jne  .serial                           ; re-entry never touches a live generation
    cmp  byte [rel smp_pf_stalled], 0
    je   .peers
    mov  eax, [rel smp_pf_gen]
    shl  rax, 32
    mov  ecx, [rel smp_pf_n]
    or   rax, rcx
    cmp  [rel smp_pf_done], rax
    jne  .serial                           ; a late AP still owes its claimed chunk
    mov  byte [rel smp_pf_stalled], 0
.peers:
    cmp  dword [rel smp_topology_online], 1
    jbe  .serial                           ; -smp 1: a plain loop
    ; Retire the old word first: an AP holding it fails its cmpxchg while the
    ; descriptor is rewritten (stores stay in program order).
    mov  qword [rel smp_pf_claim], 0
    mov  ebx, [rel smp_pf_gen]
    inc  ebx
    jnz  .gen_ok
    inc  ebx                               ; generation 0 never names a descriptor
.gen_ok:
    mov  [rel smp_pf_gen], ebx
    lea  rdi, [rel smp_pf_desc]
    mov  rsi, r13
    mov  ecx, SMP_PF_CTX_SZ / 8
    cld
    rep  movsq
    mov  [rel smp_pf_body], r12d
    mov  [rel smp_pf_n], r14d
    mov  qword [rel smp_pf_seen_mask], 0
    mov  rax, rbx
    shl  rax, 32
    mov  [rel smp_pf_done], rax            ; gen | 0 completed
    mov  byte [rel smp_pf_active], 1      ; lobby open, claim word still 0
    mfence
    call smp_pf_kick_aps
    mov  rbp, rax                          ; AP rows expected in the lobby
    inc  qword [rel smp_pf_runs]
    mov  r8d, SMP_PF_RENDEZVOUS_POLLS
.rendezvous:
    mov  rax, [rel smp_pf_seen_mask]
    and  rax, rbp
    mov  r10, rax                          ; exact sample used for this decision
    cmp  rax, rbp
    je   .open
    mov  edi, 10
    call tsc_delay_us                      ; clobbers RAX/RCX/RDX only
    dec  r8d
    jnz  .rendezvous
    inc  qword [rel smp_pf_lobby_timeouts]   ; a kicked AP never checked in
.open:
    ; BSP-only observation of the decision, before claim publication. A late
    ; check-in cannot rewrite this sample. R8=0 denotes lobby expiry, which
    ; is independent of the later bounded join timeout. No AP hot-path write.
    mov  [rel smp_pf_open_observation], rbx
    mov  [rel smp_pf_open_observation + 8], rbp
    mov  [rel smp_pf_open_observation + 16], r10
    xor  ecx, ecx
    test r8d, r8d
    setz cl
    mov  [rel smp_pf_open_observation + 24], rcx
    mov  rax, rbx
    shl  rax, 32
    mov  [rel smp_pf_claim], rax           ; gen | next 0: the descriptor stores precede it
    mov  edi, r15d
%ifdef PAOS_RCQ12_F3_INJECT
    xor  esi, esi                          ; BSP entry, independently of accounting slot
%endif
    call smp_pf_drain                      ; the BSP claims whatever is left
    mov  r9, rbx
    shl  r9, 32
    mov  eax, r14d
    or   r9, rax                           ; gen | n: every chunk completed
    mov  r8d, SMP_PF_JOIN_POLLS
.join:
    cmp  [rel smp_pf_done], r9
    je   .joined
    mov  edi, 10
    call tsc_delay_us
    dec  r8d
    jnz  .join
    inc  qword [rel smp_pf_timeouts]
    mov  byte [rel smp_pf_stalled], 1
    mov  byte [rel smp_pf_active], 0
    stc
    jmp  .out
.joined:
    mov  byte [rel smp_pf_active], 0
.ok:
    clc
    jmp  .out
.serial:
    inc  qword [rel smp_pf_serial_runs]
    xor  ebx, ebx
.serial_loop:
    mov  edi, r12d
    mov  rsi, r13
    mov  edx, ebx
    mov  ecx, r15d
    call smp_pf_run_chunk
    inc  ebx
    cmp  ebx, r14d
    jb   .serial_loop
    clc
    jmp  .out
.refuse:
    stc
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

.cooperative_busy:
    stc                                    ; no serial fallback over a live cooperative owner
    ret

; smp_par_for_retired -> EAX 1 when no timed-out generation still owes a
;   completion, so no AP can write a caller buffer any more; else 0. Read-only
;   (smp_pf_stalled itself clears on the next smp_par_for). clobbers: RCX.
smp_par_for_retired:
    xor  eax, eax
    cmp  dword [rel smp_pc_phase], 0
    jne  .out
    mov  eax, 1
    cmp  byte [rel smp_pf_stalled], 0
    je   .out
    mov  eax, [rel smp_pf_gen]
    shl  rax, 32
    mov  ecx, [rel smp_pf_n]
    or   rax, rcx
    cmp  [rel smp_pf_done], rax
    sete al
    movzx eax, al
.out:
    ret

; smp_pf_kick_aps -> RAX = mask of the ONLINE AP rows sent IDLE_WAKE. The BSP
;   and every row that is not ONLINE stay out. A failed send is not retried:
;   that AP still sees smp_pf_active on its next tick (1 ms, or 16 ms parked).
;   RC power I1: every BSP request that APs poll for (frequency edges, SMPWORK,
;   MSR apply/read, coherence and fault selftests, the smp_par_begin lane)
;   calls it right after it publishes. Clobbers RAX, RCX, RDX, RSI, RDI, R8; flags.
smp_pf_kick_aps:
    mfence                                ; srcreview L2: an x2APIC ICR WRMSR is not serializing (SDM:
    lfence                                ;   MFENCE;LFENCE), so the publication is globally visible first
    push rbx
    push r12
    xor  ebx, ebx
    xor  r12d, r12d
.loop:
    cmp  ebx, [rel smp_discovered_count]
    jae  .done
    cmp  ebx, MAXCORE
    jae  .done
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .next
    bts  r12, rbx
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + rbx*4]
    mov  esi, SMP_ICR_FIXED | SMP_IDLE_WAKE_VECTOR
    pushfq
    cli                                    ; one ICR high/low pair, no BSP sender between
    call smp_lapic_send_ipi
    popfq
.next:
    inc  ebx
    jmp  .loop
.done:
    mov  rax, r12
    pop  r12
    pop  rbx
    ret

; smp_pf_ap_tick(EDI = dense logical CPU): the AP side, first in each
;   smp_scheduler_tick pull. Nothing unless a generation is live and the lane
;   is armed (PAOS_SMP_PF_DISARM builds the red-first control: APs never claim).
smp_pf_ap_tick:
    push rdi
    call smp_pc_worker
    pop  rdi
    cmp  byte [rel smp_pf_active], 0
    je   .out
    cmp  byte [rel smp_pf_disarm], 0
    jne  .out
%ifdef PAOS_RCQ12_F3_INJECT
    mov  esi, 1                            ; AP entry, not an inferred dense slot
%endif
    jmp  smp_pf_drain
.out:
    ret

; smp_pf_drain(EDI = accounting slot): claim and run chunks of the published
;   generation until none is left. In the lobby (smp_pf_active set, claim word
;   0) an AP checks in once and waits for the open; the BSP's rendezvous bounds
;   that wait, and the wait ends as soon as smp_pf_active drops.
smp_pf_drain:
%ifdef PAOS_RCQ12_F3_INJECT
    push rbp
    mov  ebp, esi                          ; entry marker survives every claimed chunk
%endif
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, edi
.claim:
    mov  rax, [rel smp_pf_claim]
    mov  rbx, rax
    shr  rbx, 32                           ; this word's generation
    jnz  .live
    cmp  byte [rel smp_pf_active], 0
    je   .out                              ; nothing published (or being rewritten)
    cmp  r15d, MAXCORE
    jae  .lobby
    bt   qword [rel smp_pf_seen_mask], r15
    jc   .lobby
    lock bts qword [rel smp_pf_seen_mask], r15 ; checked in
.lobby:
    pause
    jmp  .claim
.live:
    mov  r12d, [rel smp_pf_body]          ; descriptor stores precede the word
    mov  r14d, [rel smp_pf_n]
    cmp  eax, r14d
    jae  .out                              ; exhausted
    lea  rcx, [rax + 1]
    lock cmpxchg [rel smp_pf_claim], rcx
    jne  .claim                            ; lost the race, or the generation moved on
    mov  r13d, eax                         ; claimed index
%ifdef PAOS_RCQ12_F3_INJECT
    ; Claim acquired: RBX is this descriptor's generation, R13D its index.
    ; No lock is held; IRQ-driven rendezvous and TLB acknowledgments stay live.
    cmp  ebp, 1
    jne  .f3_done
    cmp  dword [rel f3_state], F3_ARMED
    jne  .f3_done
    cmp  r12d, SMP_PF_BODY_COPY
    jne  .f3_done
    cmp  r14d, GD_STAGE_CHUNKS
    jne  .f3_done
    mov  rax, [rel smp_pf_desc + SMP_PF_CTX_DST]
    cmp  rax, [rel gd_stage_d]
    jne  .f3_done
    mov  rax, [rel smp_pf_desc + SMP_PF_CTX_SRC]
    cmp  rax, [rel gd_stage_s]
    jne  .f3_done
    cmp  qword [rel tsc_khz], 0
    je   .f3_done
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .f3_done
    mov  eax, F3_ARMED
    mov  ecx, F3_FIRED
    lock cmpxchg dword [rel f3_state], ecx
    jne  .f3_done
    mov  [rel f3_fired_cpu], r15d
    mov  [rel f3_fired_pfgen], ebx
    mov  eax, [rel gd_stage_gen]
    mov  [rel f3_fired_gdgen], eax
    mov  [rel f3_fired_index], r13d
    mov  edi, PAOS_RCQ12_F3_HOLD_MS * 1000
    call tsc_delay_us                       ; clobbers RAX/RCX/RDX only; IF unchanged
.f3_done:
%endif
    mov  edi, r12d
    lea  rsi, [rel smp_pf_desc]
    mov  edx, r13d
    mov  ecx, r15d
    call smp_pf_run_chunk
    mov  edi, ebx
    call smp_pf_complete
    jmp  .claim
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
%ifdef PAOS_RCQ12_F3_INJECT
    pop  rbp
%endif
    ret

; smp_pf_complete(EDI = generation): count one finished chunk while the done
;   word still names that generation; a late completion never counts toward
;   a newer descriptor.
smp_pf_complete:
    mov  rax, [rel smp_pf_done]
.retry:
    mov  rcx, rax
    shr  rcx, 32
    cmp  ecx, edi
    jne  .out
    lea  rcx, [rax + 1]
    lock cmpxchg [rel smp_pf_done], rcx
    jne  .retry                            ; RAX holds the current word
.out:
    ret

; smp_pf_run_chunk(EDI=body id, RSI=ctx, EDX=chunk index, ECX=accounting slot):
;   run one chunk and add its TSC ticks and count to that CPU's slot (each
;   slot has one writer, its own CPU; MAXCORE = not counted).
smp_pf_run_chunk:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  r12d, ecx
    mov  r13d, edx
    mov  r14d, edi
    mov  rbx, rsi
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbp, rax
    mov  rdi, rbx
    mov  esi, r13d
    cmp  r14d, SMP_PF_BODY_FILL
    jne  .not_memset
    call smp_pf_body_fill
    jmp  .account
.not_memset:
    cmp  r14d, SMP_PF_BODY_MATMUL
    jne  .copy
    call smp_pf_body_matmul
    mov  r13d, eax                         ; exact scalar MAC units completed
    cmp  r12d, MAXCORE
    jae  .account
    lea  rcx, [rel cpu_pf_matmul_units]
    add  [rcx + r12*8], r13
    jmp  .account
.copy:
    cmp  r14d, SMP_PF_BODY_COPY
    jne  .account                          ; smp_par_for admits known ids only
    call smp_pf_body_copy
.account:
    cmp  r12d, MAXCORE
    jae  .out
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbp
    lea  rcx, [rel cpu_pf_busy_tsc]
    add  [rcx + r12*8], rax
    lea  rcx, [rel cpu_pf_chunks]
    inc  qword [rcx + r12*8]
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; smp_pf_body_fill(RDI=ctx, ESI=chunk index): leaf. Fills bytes
;   [index*chunk, min(len, (index+1)*chunk)) of dst with the fill byte.
smp_pf_body_fill:
    mov  r8, rdi
    mov  eax, esi
    mul  qword [r8 + SMP_PF_CTX_CHUNK]
    jc   .out                              ; start past 2^64: nothing
    mov  rcx, [r8 + SMP_PF_CTX_LEN]
    cmp  rax, rcx
    jae  .out
    sub  rcx, rax
    cmp  rcx, [r8 + SMP_PF_CTX_CHUNK]
    cmova rcx, [r8 + SMP_PF_CTX_CHUNK]
    mov  rdi, [r8 + SMP_PF_CTX_DST]
    add  rdi, rax
    movzx eax, byte [r8 + SMP_PF_CTX_FILL]
    cld
    rep  stosb
.out:
    ret

; smp_pf_body_copy(RDI=ctx, ESI=chunk index): leaf. Copies the same range
;   from src to dst.
smp_pf_body_copy:
    mov  r8, rdi
    mov  eax, esi
    mul  qword [r8 + SMP_PF_CTX_CHUNK]
    jc   .out
    mov  rcx, [r8 + SMP_PF_CTX_LEN]
    cmp  rax, rcx
    jae  .out
    sub  rcx, rax
    cmp  rcx, [r8 + SMP_PF_CTX_CHUNK]
    cmova rcx, [r8 + SMP_PF_CTX_CHUNK]
    mov  rdi, [r8 + SMP_PF_CTX_DST]
    mov  rsi, [r8 + SMP_PF_CTX_SRC]
    add  rdi, rax
    add  rsi, rax
    cld
    rep  movsb
.out:
    ret

; smp_matmul(EDI=0 single / 1 parallel, RSI=private 40-byte ctx) -> CF.
; ctx = C, A, B, N, K (all qwords); C[0:N] = A[0:K] @ B[K,N].
; Immutable A/B and disjoint C belong to the native caller, never wire pointers.
; Identical 16-column tiles in both modes; each CPU uses its own stack/SIMD state.
; CF=1 forbids consuming/reusing ANY buffers until smp_par_for_retired=1.
smp_matmul:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rsi
    mov r13d, edi
    cmp edi, 1
    ja .bad
    test rsi, rsi
    jz .bad
    mov rdx, [rsi + 24]
    add rdx, 15
    shr rdx, 4
    call smp_matmul_validate
    jc .bad
    mov r14d, edx
    cmp byte [rel smp_pf_active], 0
    jne .bad
    call smp_par_for_retired
    test eax, eax
    jz .bad                              ; no serial reuse over a late writer
    test r13d, r13d
    jz .single
    mov edi, SMP_PF_BODY_MATMUL
    mov rsi, r12
    mov edx, r14d
    call smp_par_for
    jmp .out
.single:
    call smp_current_logical
    mov r13d, eax
    xor ebx, ebx
.loop:
    mov edi, SMP_PF_BODY_MATMUL
    mov rsi, r12
    mov edx, ebx
    mov ecx, r13d
    call smp_pf_run_chunk
    inc ebx
    cmp ebx, r14d
    jb .loop
    clc
    jmp .out
.bad:
    stc
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Private bounded geometry, not an allocation/authority proof. Caller retains
; allocation/mapping custody. Preserve RSI/EDX for both entry points.
smp_matmul_validate:
    test rsi, rsi
    jz .bad
    mov rax, [rsi + 24]
    test rax, rax
    jz .bad
    cmp rax, 3072
    ja .bad
    mov rcx, [rsi + 32]
    test rcx, rcx
    jz .bad
    cmp rcx, 3072
    ja .bad
    add eax, 15
    shr eax, 4
    cmp eax, edx
    jne .bad
    ; Bound every byte range, canonical at both ends, and forbid an output
    ; alias with either immutable input. Mapping/allocation custody is caller-owned.
    push rdx
    mov r8, [rsi]                         ; C begin
    mov r9, [rsi + 24]
    shl r9, 2
    add r9, r8                            ; C end exclusive
    jc .range_bad
    mov r10, [rsi + 8]                    ; A begin
    mov r11, [rsi + 32]
    shl r11, 2
    add r11, r10                          ; A end
    jc .range_bad
    cmp r8, r11
    jae .ab
    cmp r10, r9
    jb .range_bad
.ab:
    mov rax, [rsi + 24]
    imul rax, [rsi + 32]
    shl rax, 2
    mov rcx, [rsi + 16]                    ; B begin
    add rax, rcx                          ; B end
    jc .range_bad
    cmp r8, rax
    jae .canonical
    cmp rcx, r9
    jb .range_bad
.canonical:
    ; All starts nonzero and canonical, as are the last bytes.
    test r8, r8
    jz .range_bad
    test r10, r10
    jz .range_bad
    test rcx, rcx
    jz .range_bad
    dec r9
    dec r11
    dec rax
    mov rdx, r8
    shl rdx, 16
    sar rdx, 16
    cmp rdx, r8
    jne .range_bad
    mov rdx, r9
    shl rdx, 16
    sar rdx, 16
    cmp rdx, r9
    jne .range_bad
    mov rdx, r10
    shl rdx, 16
    sar rdx, 16
    cmp rdx, r10
    jne .range_bad
    mov rdx, r11
    shl rdx, 16
    sar rdx, 16
    cmp rdx, r11
    jne .range_bad
    mov rdx, rcx
    shl rdx, 16
    sar rdx, 16
    cmp rdx, rcx
    jne .range_bad
    mov rdx, rax
    shl rdx, 16
    sar rdx, 16
    cmp rdx, rax
    jne .range_bad
    pop rdx
    clc
    ret
.range_bad:
    pop rdx
.bad:
    stc
    ret

; Pure SSE tile. No global scratch, allocation, indirect callback or locks.
; Save every SIMD register touched and MXCSR in CPU-local stack scratch;
; legacy SSE preserves upper YMM state. Explicit round-to-nearest matches both
; modes irrespective of the executing CPU's interrupted MXCSR. Each lane sums
; k in the same order; no cross-CPU reduction or FMA contraction.
; RDI=ctx, ESI=tile; EAX=actual scalar multiply-accumulate units (tail included).
smp_pf_body_matmul:
    sub rsp, 72
    movups [rsp], xmm0
    movups [rsp + 16], xmm1
    movups [rsp + 32], xmm2
    stmxcsr [rsp + 48]
    mov dword [rsp + 52], 0x1f80
    ldmxcsr [rsp + 52]
    mov r8, [rdi]                          ; C
    mov r9, [rdi + 8]                      ; A
    mov r10, [rdi + 16]                    ; B
    mov r11d, [rdi + 24]                   ; N
    mov ecx, [rdi + 32]                    ; K
    shl esi, 4                            ; first output column
    mov [rsp + 56], esi
    lea eax, [rsi + 16]
    cmp eax, r11d
    cmova eax, r11d
    mov [rsp + 60], eax                    ; exclusive last column
.columns:
    cmp esi, [rsp + 60]
    jae .done
    xorps xmm0, xmm0
    xor edx, edx
    lea eax, [rsi + 4]
    cmp eax, [rsp + 60]
    ja .scalar
.vector_k:
    movss xmm1, [r9 + rdx*4]
    shufps xmm1, xmm1, 0
    mov eax, edx
    imul eax, r11d
    add eax, esi
    movups xmm2, [r10 + rax*4]
    mulps xmm2, xmm1
    addps xmm0, xmm2
    inc edx
    cmp edx, ecx
    jb .vector_k
    movups [r8 + rsi*4], xmm0
    add esi, 4
    jmp .columns
.scalar:
    movss xmm1, [r9 + rdx*4]
    mov eax, edx
    imul eax, r11d
    add eax, esi
    mulss xmm1, [r10 + rax*4]
    addss xmm0, xmm1
    inc edx
    cmp edx, ecx
    jb .scalar
    movss [r8 + rsi*4], xmm0
    inc esi
    jmp .columns
.done:
    mov eax, [rsp + 60]
    sub eax, [rsp + 56]
    jnc .units
    xor eax, eax
.units:
    imul eax, ecx
    ldmxcsr [rsp + 48]
    movups xmm0, [rsp]
    movups xmm1, [rsp + 16]
    movups xmm2, [rsp + 32]
    add rsp, 72
    ret

; Owned cooperative useful-memory lane. BSP API callers serialize themselves;
; APs execute only one <=2048-byte closed body per scheduler pull. No lobby,
; IPI, join, delay, allocation, callback or yield. Pointer geometry is checked,
; never asserted to prove allocation/custody. Caller pins immutable src/dst
; until status reports retired AND release succeeds, even after cancellation.
SMP_PC_PENDING equ 1
SMP_PC_COMPLETE equ 2
SMP_PC_CANCELLED equ 3
SMP_PC_TIMEOUT equ 4
SMP_PC_CLOCK equ 5
SMP_PC_TOPOLOGY equ 6
SMP_PC_BUSY equ 7
SMP_PC_STALE equ 8
SMP_PC_COUNTER equ 9
SMP_PC_BUDGET equ 10
SMP_PC_REFUSED equ 11
SMP_PC_STEP_CHUNKS equ 4
SMP_PC_CHUNK_MAX equ 2048
SMP_PC_STEPS_MAX equ 1024

; begin(EDI=FILL/COPY, RSI=40B ctx, EDX=exact ceil(len/chunk),
;       RCX=nonzero private owner id, R8=now_us, R9=exclusive deadline_us)
; -> CF=0 RAX=nonzero uint32 generation widened to64; CF=1 EAX=reason.
; Copies descriptor before publish; caller scratch may disappear on return.
smp_par_begin:
    push qword 0                           ; ordinary job: BSP and APs
    jmp smp_pc_begin_mode

; Same descriptor and bounded claim/body path, restricted to its BSP for a
; single-CPU reference. Mode belongs to this generation, never global policy.
smp_par_begin_single:
    push qword 1
smp_pc_begin_mode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  rbp, rsi
    mov  r12d, edx
    mov  r13, rcx
    mov  r14, r8
    mov  r15, r9
    mov  eax, SMP_PC_BUSY
    cmp  dword [rel smp_pc_phase], 0
    jne  .fail
    cmp  dword [rel smp_pc_stepping], 0
    jne  .fail
    cmp  byte [rel smp_pf_active], 0
    jne  .fail
    call smp_par_for_retired
    test eax, eax
    jz   .busy
    mov  eax, SMP_PC_COUNTER
    cmp  dword [rel smp_pc_gen], -1
    je   .fail                              ; never wrap or reuse an old packed generation
    mov  eax, SMP_PC_REFUSED
    cmp  ebx, SMP_PF_BODY_FILL
    jb   .fail
    cmp  ebx, SMP_PF_BODY_MAX
    ja   .fail
    test r13, r13
    jz   .fail
    test r12d, r12d
    jz   .fail
    test r14, r14
    jz   .clock
    cmp  r15, r14
    jbe  .clock
    mov  rdi, rbp
    mov  esi, SMP_PF_CTX_SZ
    call smp_pc_range
    test eax, eax
    jz   .bad
    xor  eax, eax
    mov  ecx, 4
    lock cmpxchg [rel smp_pc_phase], ecx     ; atomically reserve PREPARING before scratch
    jne  .busy
    ; Recheck after reservation: an intervening owner may have exhausted its
    ; counter or left a synchronous write owed. No sync entry can now overlap.
    cmp  dword [rel smp_pc_gen], -1
    je   .counter_prepared
    cmp  byte [rel smp_pf_active], 0
    jne  .busy_prepared
    cmp  byte [rel smp_pf_stalled], 0
    je   .descriptor
    mov  eax, [rel smp_pf_gen]
    shl  rax, 32
    mov  edx, [rel smp_pf_n]
    or   rax, rdx
    cmp  rax, [rel smp_pf_done]
    jne  .busy_prepared
.descriptor:
    mov  rsi, rbp
    lea  rdi, [rel smp_pc_desc]
    mov  ecx, SMP_PF_CTX_SZ / 8
    cld
    rep  movsq
    mov  rsi, [rel smp_pc_desc + SMP_PF_CTX_LEN]
    test rsi, rsi
    jz   .bad_prepared
    mov  rcx, [rel smp_pc_desc + SMP_PF_CTX_CHUNK]
    test rcx, rcx
    jz   .bad_prepared
    cmp  rcx, SMP_PC_CHUNK_MAX
    ja   .bad_prepared
    mov  rax, rsi
    dec  rax
    xor  edx, edx
    div  rcx
    inc  rax
    cmp  rax, r12                          ; exact coverage; no redundant/overflowed indices
    jne  .bad_prepared
    mov  rdi, [rel smp_pc_desc + SMP_PF_CTX_DST]
    call smp_pc_range
    test eax, eax
    jz   .bad_prepared
    ; Caller descriptor must not be overwritten while begin is validating it.
    mov  rdx, rdi
    add  rdx, rsi
    lea  rcx, [rbp + SMP_PF_CTX_SZ]
    cmp  rdi, rcx
    jae  .dst_apart
    cmp  rbp, rdx
    jb   .bad_prepared
.dst_apart:
    cmp  ebx, SMP_PF_BODY_COPY
    jne  .geometry_ok
    mov  rdi, [rel smp_pc_desc + SMP_PF_CTX_SRC]
    call smp_pc_range
    test eax, eax
    jz   .bad_prepared
    mov  rdx, rdi
    add  rdx, rsi
    lea  rcx, [rbp + SMP_PF_CTX_SZ]
    cmp  rdi, rcx
    jae  .src_apart
    cmp  rbp, rdx
    jb   .bad_prepared
.src_apart:
    mov  rcx, [rel smp_pc_desc + SMP_PF_CTX_DST]
    cmp  rcx, rdx
    jae  .geometry_ok
    add  rcx, rsi
    cmp  rdi, rcx
    jb   .bad_prepared                     ; COPY has memcpy, never overlapping memmove authority
.geometry_ok:
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .topology
    mov  [rel smp_pc_bsp], eax
    mov  eax, [rel smp_discovered_count]
    mov  [rel smp_pc_count], eax
    mov  eax, [rel smp_topology_online]
    mov  [rel smp_pc_online], eax
    lea  rsi, [rel cpu_state]
    lea  rdi, [rel smp_pc_states]
    mov  ecx, MAXCORE
    rep  movsb
    lea  rsi, [rel cpu_apic_id]
    lea  rdi, [rel smp_pc_apics]
    mov  ecx, MAXCORE
    rep  movsd
    call smp_pc_topology
    test eax, eax
    jz   .topology
    mov  [rel smp_pc_owner], r13
    mov  [rel smp_pc_last_us], r14
    mov  [rel smp_pc_deadline], r15
    mov  [rel smp_pc_body], ebx
    mov  [rel smp_pc_n], r12d
    mov  eax, [rsp + 48]                    ; mode pushed by entry wrapper
    mov  [rel smp_pc_single], eax
    mov  qword [rel smp_pc_finished_us], 0
    lea  rdi, [rel smp_pc_cpu_chunks]
    xor  eax, eax
    mov  ecx, MAXCORE
    rep  stosq                             ; before generation publication
    mov  dword [rel smp_pc_steps], 0
    mov  dword [rel smp_pc_reason], SMP_PC_PENDING
    inc  dword [rel smp_pc_gen]
    mov  eax, [rel smp_pc_gen]
    shl  rax, 32
    mov  [rel smp_pc_done], rax
    mov  [rel smp_pc_claim], rax             ; x86 store order: descriptor before publication
    or   rax, 1
    mov  [rel smp_pc_phase], rax            ; generation | ACTIVE, no AP lobby
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick
    mov  eax, [rel smp_pc_gen]
    clc
    jmp  .out
.counter_prepared:
    mov  eax, SMP_PC_COUNTER
    jmp  .fail_prepared
.busy_prepared:
    mov  eax, SMP_PC_BUSY
.fail_prepared:
    mov  dword [rel smp_pc_phase], 0
    jmp  .fail
.bad_prepared:
    mov  dword [rel smp_pc_phase], 0
.bad:
    mov  eax, SMP_PC_REFUSED
    jmp  .fail
.topology:
    mov  dword [rel smp_pc_phase], 0
    mov  eax, SMP_PC_TOPOLOGY
    jmp  .fail
.clock:
    mov  eax, SMP_PC_CLOCK
    jmp  .fail
.busy:
    mov  eax, SMP_PC_BUSY
.fail:
    stc
.out:
    cld
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    lea  rsp, [rsp + 8]                     ; discard mode, keep CF
    ret

; range(RDI=base, RSI=nonzero bytes) -> EAX=1 iff nonwrapping canonical48
; and disjoint from this lane's own scratch. Preserves RDI/RSI.
smp_pc_range:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    test rsi, rsi
    jz   .out
    mov  rdx, rdi
    add  rdx, rsi
    jc   .out
    mov  rcx, rdi
    shl  rcx, 16
    sar  rcx, 16
    cmp  rcx, rdi
    jne  .out
    lea  rcx, [rdx - 1]
    mov  r8, rcx
    shl  r8, 16
    sar  r8, 16
    cmp  r8, rcx
    jne  .out
    xor  r8, rdi
    bt   r8, 47
    jc   .out                              ; endpoints must not cross the canonical hole
    lea  rcx, [rel smp_pc_scratch_end]
    cmp  rdi, rcx
    jae  .yes
    lea  rcx, [rel smp_pc_scratch_begin]
    cmp  rdx, rcx
    ja   .out
.yes:
    mov  eax, 1
.out:
    ret

; Fixed <=MAXCORE^2 identity checks; no lock, delay or callback. Snapshot
; dense BSP and all APIC IDs/states must still match the actual topology.
smp_pc_topology:
    mov  eax, [rel smp_pc_count]
    test eax, eax
    jz   .no
    cmp  eax, MAXCORE
    ja   .no
    cmp  eax, [rel smp_discovered_count]
    jne  .no
    mov  eax, [rel smp_pc_online]
    cmp  eax, [rel smp_topology_online]
    jne  .no
    xor  r9d, r9d                         ; actual online incl BSP
    xor  r10d, r10d
.loop:
    cmp  r10d, [rel smp_pc_count]
    jae  .done
    lea  rax, [rel cpu_state]
    movzx edx, byte [rax + r10]
    lea  rax, [rel smp_pc_states]
    cmp  dl, [rax + r10]
    jne  .no
    cmp  edx, CPU_STATE_BSP
    jne  .ap
    cmp  r10d, [rel smp_pc_bsp]
    jne  .no
    inc  r9d
    jmp  .id
.ap:
    cmp  r10d, [rel smp_pc_bsp]
    je   .no
    cmp  edx, CPU_STATE_ONLINE
    jne  .id
    inc  r9d
.id:
    lea  rax, [rel cpu_apic_id]
    mov  edx, [rax + r10*4]
    lea  rcx, [rel smp_pc_apics]
    cmp  edx, [rcx + r10*4]
    jne  .no
    xor  r11d, r11d
.unique:
    cmp  r11d, r10d
    jae  .next
    cmp  edx, [rcx + r11*4]
    je   .no
    inc  r11d
    jmp  .unique
.next:
    inc  r10d
    jmp  .loop
.done:
    cmp  r9d, [rel smp_pc_online]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Exact uint64 handle + owner and actual BSP. Foreign calls never retire or
; cancel another owner. The public generation is not an authority credential.
smp_pc_match:
    cmp  dword [rel smp_pc_phase], 0
    je   .no
    mov  eax, [rel smp_pc_gen]
    cmp  rdi, rax
    jne  .no
    cmp  rsi, [rel smp_pc_owner]
    jne  .no
    call smp_current_logical
    cmp  eax, [rel smp_pc_bsp]
    jne  .no
    clc
    ret
.no:
    stc
    ret

; status(handle RDI, owner RSI) -> EAX reason, EDX=retired (0/1).
; Pending/closing are never retired. Terminal reason is distinct from actual
; retired writes; even CANCELLED/TIMEOUT must be pinned while EDX=0.
smp_par_status:
    cld
    call smp_pc_match
    jc   .stale
    xor  edx, edx
    mov  eax, SMP_PC_PENDING
    cmp  dword [rel smp_pc_phase], 3
    jne  .out
    mov  eax, [rel smp_pc_reason]
    mov  rcx, [rel smp_pc_done]
    cmp  rcx, [rel smp_pc_target]
    sete dl
.out:
    ret
.stale:
    mov  eax, SMP_PC_STALE
    xor  edx, edx
    ret

; Freeze(EDI=reason, ESI=expected generation), BSP or AP. The atomic
; phase carries generation too: a preempted old completion/clock check cannot
; close a successor after its write retired and the old owner released it.
; One winner enters CLOSING, then exchanges the packed claim to zero. Racing
; claims are included in target or fail CAS; CLOSING never reports retirement.
smp_pc_freeze:
    mov  r11d, edi
    mov  eax, esi
    shl  rax, 32
    or   rax, 1
    lea  rcx, [rax + 1]
    lock cmpxchg [rel smp_pc_phase], rcx
    jne  .out
    xor  eax, eax
    xchg rax, [rel smp_pc_claim]
    mov  [rel smp_pc_target], rax
    mov  [rel smp_pc_reason], r11d
    call time_monotonic_now_us              ; winner timestamps terminal closure
    mov  [rel smp_pc_finished_us], rax
    mov  dword [rel smp_pc_phase], 3
.out:
    ret

; Clock maintenance (RAX sample, ESI expected generation) is pure and bounded on BSP and APs. Loss of the BSP caller
; still closes new AP claims at deadline; no clock/retirement progress is inferred
; from silence. A frozen clock is additionally bounded by the BSP step cap.
smp_pc_clock:
    mov  edi, SMP_PC_CLOCK
    test rax, rax
    jz   smp_pc_freeze
    cmp  rax, [rel smp_pc_last_us]
    jb   smp_pc_freeze
    mov  edi, SMP_PC_TIMEOUT
    cmp  rax, [rel smp_pc_deadline]
    jae  smp_pc_freeze
    ret

; step(handle RDI, owner RSI, RDX=now_us) -> status EAX/retired EDX.
; At most four chunks (<=8192 bytes) and bounded claim retries, no join.
smp_par_step:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
    call smp_pc_match
    jc   .status
    xor  eax, eax
    mov  ecx, 1
    lock cmpxchg [rel smp_pc_stepping], ecx
    jne  .busy
    mov  rdi, r12
    mov  rsi, r13
    call smp_pc_match                       ; revalidate after acquiring the step guard
    jc   .unlock
    cmp  dword [rel smp_pc_phase], 1
    jne  .unlock
    mov  rax, rbx
    mov  esi, r12d
    call smp_pc_clock
    cmp  dword [rel smp_pc_phase], 1
    jne  .unlock
    mov  [rel smp_pc_last_us], rbx
    mov  edi, SMP_PC_BUDGET
    cmp  dword [rel smp_pc_steps], SMP_PC_STEPS_MAX
    jae  .freeze
    inc  dword [rel smp_pc_steps]
    call smp_pc_topology
    test eax, eax
    mov  edi, SMP_PC_TOPOLOGY
    jz   .freeze
    mov  ebx, SMP_PC_STEP_CHUNKS
.work:
    mov  edi, [rel smp_pc_bsp]
    call smp_pc_worker                      ; one bounded chunk, no draining
    dec  ebx
    jnz  .work
    jmp  .unlock
.freeze:
    mov  esi, r12d
    call smp_pc_freeze
.unlock:
    mov  dword [rel smp_pc_stepping], 0
.status:
    mov  rdi, r12
    mov  rsi, r13
    call smp_par_status
    jmp  .out
.busy:
    mov  eax, SMP_PC_BUSY
    xor  edx, edx
.out:
    pop  r13
    pop  r12
    pop  rbx
    cld
    ret

smp_par_cancel:
    push rdi
    push rsi
    call smp_pc_match
    jc   .out
    mov  esi, edi
    mov  edi, SMP_PC_CANCELLED
    call smp_pc_freeze
.out:
    pop  rsi
    pop  rdi
    jmp  smp_par_status

; release(handle,owner) -> EAX=1 only after actual terminal retirement.
; Clears no generation counter; zeroing claim is not itself retirement proof.
smp_par_release:
    cld
    cmp  dword [rel smp_pc_stepping], 0
    jne  .no
    call smp_par_status
    cmp  edx, 1
    jne  .no
    mov  eax, edi
    shl  rax, 32
    or   rax, 3
    lea  rcx, [rax + 1]
    lock cmpxchg [rel smp_pc_phase], rcx     ; never release a successor after an intervening call
    jne  .no
    mov  qword [rel smp_pc_owner], 0
    mov  dword [rel smp_pc_phase], 0
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; One worker invocation, at most4 CAS attempts/one closed memory body. APs
; cannot select arbitrary callbacks or touch guest/auth/device state.
smp_pc_worker:
    push rbx
    push rbp
    push r12
    push r13
    mov  r13d, [rel smp_pc_gen]
    mov  r12d, edi
    cmp  dword [rel smp_pc_phase], 1
    jne  .out
    cmp  r12d, [rel smp_pc_count]
    jae  .out
    lea  rax, [rel cpu_state]
    movzx edx, byte [rax + r12]
    cmp  r12d, [rel smp_pc_bsp]
    jne  .ap
    cmp  edx, CPU_STATE_BSP
    jne  .out
    jmp  .identity
.ap:
    cmp  dword [rel smp_pc_single], 0
    jne  .out
    cmp  byte [rel smp_pf_disarm], 0
    jne  .out
    cmp  edx, CPU_STATE_ONLINE
    jne  .out
.identity:
    lea  rax, [rel cpu_apic_id]
    mov  eax, [rax + r12*4]
    lea  rdx, [rel smp_pc_apics]
    cmp  eax, [rdx + r12*4]
    jne  .out
    call smp_pc_topology
    test eax, eax
    jnz  .clock
    mov  edi, SMP_PC_TOPOLOGY
    mov  esi, r13d
    call smp_pc_freeze
    jmp  .out
.clock:
    call time_monotonic_now_us
    mov  esi, r13d
    call smp_pc_clock
    cmp  dword [rel smp_pc_phase], 1
    jne  .out
    mov  ebp, 4
.claim:
    mov  rax, [rel smp_pc_claim]
    mov  rbx, rax
    shr  rbx, 32
    test ebx, ebx
    jz   .out
    cmp  ebx, r13d                         ; a delayed pull never adopts a successor generation
    jne  .out
    cmp  eax, [rel smp_pc_n]
    jae  .out
    lea  rcx, [rax + 1]
    lock cmpxchg [rel smp_pc_claim], rcx
    je   .run
    dec  ebp
    jnz  .claim
    jmp  .out
.run:
    mov  edx, eax
    mov  edi, [rel smp_pc_body]
    lea  rsi, [rel smp_pc_desc]
    mov  ecx, r12d
    call smp_pf_run_chunk
    lea  rax, [rel smp_pc_cpu_chunks]
    inc  qword [rax + r12*8]                ; this generation; before done credit
    ; This invocation owns exactly one outstanding claim. Reuse is forbidden
    ; until it completes, so one packed atomic increment cannot credit a new job.
    mov  eax, 1
    lock xadd [rel smp_pc_done], rax
    lea  rcx, [rax + 1]
    mov  edx, [rel smp_pc_n]
    mov  rax, rbx
    shl  rax, 32
    or   rax, rdx
    cmp  rax, rcx
    jne  .out
    mov  edi, SMP_PC_COMPLETE
    mov  esi, r13d
    call smp_pc_freeze
.out:
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    cld
    ret

%macro WDATA_smp_pc_bss 0
alignb 64
smp_pc_scratch_begin:
smp_pc_claim: resq 1
smp_pc_done: resq 1
smp_pc_target: resq 1
smp_pc_owner: resq 1
smp_pc_last_us: resq 1
smp_pc_deadline: resq 1
smp_pc_desc: resb SMP_PF_CTX_SZ
smp_pc_phase: resq 1
smp_pc_stepping: resd 1
smp_pc_reason: resd 1
smp_pc_gen: resd 1
smp_pc_body: resd 1
smp_pc_n: resd 1
smp_pc_steps: resd 1
smp_pc_single: resd 1
alignb 8
smp_pc_finished_us: resq 1
smp_pc_cpu_chunks: resq MAXCORE
smp_pc_bsp: resd 1
smp_pc_count: resd 1
smp_pc_online: resd 1
smp_pc_states: resb MAXCORE
smp_pc_apics: resd MAXCORE
smp_pc_scratch_end:
%endmacro
WDATA_BSS_DEFER WDATA_smp_pc_bss

; smp_msr_apply_aps(EDI=MSR, ESI=32-bit value, EDX=enable MSR or 0) -> EAX ok
;   mask, EDX failed-or-missing mask (dense AP bits; the caller handles the BSP).
;   Every online AP's scheduler tick (smp_msr_worker_tick) sets bit 0 of the
;   enable MSR when one is named, writes the value (upper half 0) and reads the
;   low 32 bits back. Bounded: 250 ms (5000 x 50 us), no retry. RCQ-27 stage P.
;   The request is open only during the wait: an AP that wakes after it was
;   closed does not apply a request the caller already reported as failed.
smp_msr_apply_aps:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    mov  edx, [rel smpwork_online_mask]
    xor  eax, eax
    ret
.custody_free:
    push rbx
    push r12
    mov  [rel smp_msr_req_msr], edi
    mov  [rel smp_msr_req_value], esi
    mov  [rel smp_msr_req_enable], edx
    mov  dword [rel smp_msr_ok_mask], 0
    mov  dword [rel smp_msr_fail_mask], 0
    mov  r12d, [rel smpwork_online_mask]   ; AP-only dense mask
    test r12d, r12d
    jz   .done
    mov  byte [rel smp_msr_req_open], 1
    mov  eax, [rel smp_msr_req_epoch]
    inc  eax
    jnz  .epoch_ok
    inc  eax
.epoch_ok:
    mfence
    mov  [rel smp_msr_req_epoch], eax      ; publish last
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick
    mov  ebx, 5000
.wait:
    mov  eax, [rel smp_msr_ok_mask]
    or   eax, [rel smp_msr_fail_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .done
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait
.done:
    mov  byte [rel smp_msr_req_open], 0      ; late APs no longer apply it
    mfence
    mov  eax, [rel smp_msr_ok_mask]
    and  eax, r12d
    mov  edx, [rel smp_msr_fail_mask]
    mov  ecx, eax
    or   ecx, edx
    not  ecx
    and  ecx, r12d                         ; never answered
    or   edx, ecx
    pop  r12
    pop  rbx
    ret

; The AP half of smp_msr_apply_aps: once per published epoch, on this CPU.
smp_msr_worker_tick:
    push rbx
    push r12
    mov  ebx, r15d
    mov  r12d, [rel smp_msr_req_epoch]
    test r12d, r12d
    jz   .out
    lea  rax, [rel cpu_msr_epoch]
    cmp  [rax + rbx*4], r12d
    je   .out
    cmp  byte [rel smp_msr_req_open], 1
    jne  .out                              ; closed: the caller already reported this AP
    mov  ecx, [rel smp_msr_req_enable]
    test ecx, ecx
    jz   .request
    rdmsr
    or   eax, 1
    wrmsr
.request:
    mov  ecx, [rel smp_msr_req_msr]
    mov  eax, [rel smp_msr_req_value]
    xor  edx, edx
    wrmsr
    rdmsr
    cmp  eax, [rel smp_msr_req_value]
    jne  .failed
    lock bts dword [rel smp_msr_ok_mask], ebx
    jmp  .acked
.failed:
    lock bts dword [rel smp_msr_fail_mask], ebx
.acked:
    lea  rax, [rel cpu_msr_epoch]
    mov  [rax + rbx*4], r12d
.out:
    pop  r12
    pop  rbx
    ret

; smp_msr_read_aps(EDI=MSR or 0) -> EAX answered mask, EDX missing mask (dense AP
;   bits; the caller reads the BSP itself). RCQ-27 B2 IDLEPROBE: the read-only
;   sibling of smp_msr_apply_aps, with its own request, so no read request can ever
;   reach the apply path's wrmsr. Every online AP's scheduler tick
;   (smp_msr_read_tick) stores RDMSR(EDI) (skipped when EDI=0), CPUID.05H:EDX and
;   the CPUID.1AH core type into its own slots; nothing is written to an MSR.
;   Bounded: 250 ms (5000 x 50 us), no retry; open only during the wait.
smp_msr_read_aps:
    push rbx
    push r12
    mov  [rel smp_msr_req_rd_msr], edi
    mov  dword [rel smp_msr_req_rd_ack], 0
    mov  r12d, [rel smpwork_online_mask]   ; AP-only dense mask
    test r12d, r12d
    jz   .done
    mov  byte [rel smp_msr_req_rd_open], 1
    mov  eax, [rel smp_msr_req_rd_epoch]
    inc  eax
    jnz  .epoch_ok
    inc  eax
.epoch_ok:
    mfence
    mov  [rel smp_msr_req_rd_epoch], eax   ; publish last
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick
    mov  ebx, 5000
.wait:
    mov  eax, [rel smp_msr_req_rd_ack]
    and  eax, r12d
    cmp  eax, r12d
    je   .done
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait
.done:
    mov  byte [rel smp_msr_req_rd_open], 0 ; a late AP no longer answers
    mfence
    mov  eax, [rel smp_msr_req_rd_ack]
    and  eax, r12d
    mov  edx, eax
    not  edx
    and  edx, r12d                         ; never answered
    pop  r12
    pop  rbx
    ret

; The AP half of smp_msr_read_aps: once per published read epoch, on this CPU.
smp_msr_read_tick:
    push rbx
    push r12
    mov  ebx, r15d
    mov  r12d, [rel smp_msr_req_rd_epoch]
    test r12d, r12d
    jz   .out
    lea  rax, [rel smp_msr_req_rd_cpu_epoch]
    cmp  [rax + rbx*4], r12d
    je   .out
    cmp  byte [rel smp_msr_req_rd_open], 1
    jne  .out                              ; closed: the caller already reported this AP
    xor  eax, eax
    lea  rcx, [rel smp_msr_req_rd_val]
    mov  [rcx + rbx*8], rax
    mov  ecx, [rel smp_msr_req_rd_msr]
    test ecx, ecx
    jz   .cpuid
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    lea  rcx, [rel smp_msr_req_rd_val]
    mov  [rcx + rbx*8], rax
.cpuid:
    push rbx
    xor  eax, eax
    xor  ecx, ecx
    cpuid
    mov  r8d, eax                          ; max basic leaf
    xor  r9d, r9d                          ; CPUID.05H:EDX
    xor  r10d, r10d                        ; CPUID.1AH:EAX[31:24] core type
    cmp  r8d, 5
    jb   .ids
    mov  eax, 5
    xor  ecx, ecx
    cpuid
    mov  r9d, edx
    cmp  r8d, 0x1A
    jb   .ids
    mov  eax, 0x1A
    xor  ecx, ecx
    cpuid
    shr  eax, 24
    mov  r10d, eax
.ids:
    pop  rbx
    lea  rax, [rel smp_msr_req_rd_c5]
    mov  [rax + rbx*4], r9d
    lea  rax, [rel smp_msr_req_rd_type]
    mov  [rax + rbx], r10b
    mfence
    lea  rax, [rel smp_msr_req_rd_cpu_epoch]
    mov  [rax + rbx*4], r12d               ; row publication precedes ack
    lock bts dword [rel smp_msr_req_rd_ack], ebx
.out:
    pop  r12
    pop  rbx
    ret

; Each AP contributes the same bounded number of increments through the one
; canonical lock protecting this deliberately shared counter.  The request
; epoch is published last; the per-CPU epoch is published before the ack bit.
smp_coherence_worker_tick:
    push rbx
    push r12
    mov  ebx, r15d
    mov  r12d, [rel smp_coherence_epoch]
    test r12d, r12d
    jz   .out
    lea  rax, [rel cpu_coherence_epoch]
    cmp  [rax + rbx*4], r12d
    je   .out
    mov  ecx, SMP_COHERENCE_ITERS
.increment:
    call smp_coherence_counter_lock_acquire
    inc  qword [rel smp_coherence_counter]
    call smp_coherence_counter_lock_release
    dec  ecx
    jnz  .increment
    lea  rax, [rel cpu_coherence_epoch]
    mov  [rax + rbx*4], r12d
    lock bts dword [rel smp_coherence_ack_mask], ebx
.out:
    pop  r12
    pop  rbx
    ret

; smp_pf_bench -> EAX 1 when both lane passes equal their serial reference,
;   0 otherwise, 2 when it did not run; ECX chunks per pass; EDX chunks the APs
;   ran; R8D passes that took the parallel lane (0..2); R9D passes whose join
;   timed out (0..1). RCQ-12 track 2 option A (admin 16:06:59): SMPBENCH START
;   parfor. BSP only. Fixed private scratch and fixed sizes: no caller pointer,
;   size, job slot or scheduler job state. Pass 1 fills dst through the lane
;   and compares it with a serial fill of ref; pass 2 copies a fresh
;   pseudo-random ref (seeded by the call count) into dst through the lane and
;   compares. Before each pass dst holds the other pass's bytes (the last
;   call's random copy, or the fill byte), so a chunk the lane skipped never
;   compares equal. The scratch is this routine's own static storage (not
;   exported, never handed to another owner). SEC P1(b)/P2: while
;   smp_par_for_retired reads 0 (a timed-out chunk may still land in dst) the
;   scratch is not touched (EAX 2, the rest 0); after a pass times out, dst is
;   neither compared nor reused, so the copy pass does not run.
SMP_PF_BENCH_LEN    equ 65536
SMP_PF_BENCH_CHUNK  equ 2048
SMP_PF_BENCH_CHUNKS equ SMP_PF_BENCH_LEN / SMP_PF_BENCH_CHUNK
SMP_PF_BENCH_FILL   equ 0xA5
%if SMP_PF_BENCH_LEN % SMP_PF_BENCH_CHUNK
%error "smp_pf_bench passes are whole chunks"
%endif

smp_pf_bench:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, SMP_PF_CTX_SZ                ; the lane copies this ctx before it publishes
    call smp_par_for_retired
    test eax, eax
    jnz  .retired
    mov  eax, 2                            ; a late chunk may still land in dst: not run
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    jmp  .out
.retired:
    ; Two retained 40-byte records, fill then copy: five u64 fields each,
    ; generation/expected mask/seen mask at decision/lobby expired/AP chunks.
    ; Generation zero means no parallel pass ran, including serial or an
    ; unentered copy after a join timeout. Only a runnable bench clears them.
    cld
    lea  rdi, [rel smp_pf_bench_observation]
    xor  eax, eax
    mov  ecx, 10
    rep  stosq
    inc  dword [rel smp_pf_bench_seq]
    call smp_current_logical
    mov  r15d, eax                         ; the BSP's own chunks are not AP chunks
    mov  edi, r15d
    call smp_pf_ap_chunk_sum
    mov  r12, rax
    mov  r13, [rel smp_pf_runs]
    mov  r14, [rel smp_pf_timeouts]
    cld
    lea  rdi, [rel smp_pf_bench_ref]       ; pass 1: fill
    mov  eax, SMP_PF_BENCH_FILL
    mov  ecx, SMP_PF_BENCH_LEN
    rep  stosb
    mov  qword [rsp + SMP_PF_CTX_SRC], 0
    mov  qword [rsp + SMP_PF_CTX_FILL], SMP_PF_BENCH_FILL
    mov  edi, SMP_PF_BODY_FILL
    call smp_pf_bench_pass
    mov  ebp, eax
    jc   .passes_done                      ; timed out: dst is not reused before retire
    lea  rdi, [rel smp_pf_bench_ref]       ; pass 2: copy a fresh reference
    mov  eax, [rel smp_pf_bench_seq]
    mov  rdx, 0x9E3779B97F4A7C15
    imul rax, rdx
    or   rax, 1                            ; xorshift never starts at 0
    mov  ecx, SMP_PF_BENCH_LEN / 8
.ref:
    mov  rdx, rax
    shl  rdx, 13
    xor  rax, rdx
    mov  rdx, rax
    shr  rdx, 7
    xor  rax, rdx
    mov  rdx, rax
    shl  rdx, 17
    xor  rax, rdx
    mov  [rdi], rax
    add  rdi, 8
    dec  ecx
    jnz  .ref
    lea  rax, [rel smp_pf_bench_ref]
    mov  [rsp + SMP_PF_CTX_SRC], rax
    mov  qword [rsp + SMP_PF_CTX_FILL], 0
    mov  edi, SMP_PF_BODY_COPY
    call smp_pf_bench_pass
    and  ebp, eax
.passes_done:
    mov  edi, r15d
    call smp_pf_ap_chunk_sum
    sub  rax, r12
    mov  edx, eax
    mov  r8, [rel smp_pf_runs]
    sub  r8, r13
    mov  r9, [rel smp_pf_timeouts]
    sub  r9, r14
    mov  eax, ebp
    mov  ecx, SMP_PF_BENCH_CHUNKS
.out:
    add  rsp, SMP_PF_CTX_SZ
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; smp_pf_bench_pass(EDI body, ctx at the caller's RSP with SRC and FILL set) ->
;   CF=0 and EAX 1 when dst equals ref after the lane ran, else 0; CF=1 and
;   EAX 0 when the join timed out (dst is not read: SEC P2). Sets the ctx's
;   fixed DST, LEN and CHUNK. clobbers: caller-saved.
smp_pf_bench_pass:
    push rbx
    push rbp
    imul ebx, edi, 40                      ; body 1=fill, 2=copy
    lea  rax, [rel smp_pf_bench_observation - 40]
    add  rbx, rax
    mov  rbp, [rel smp_pf_runs]
    push rdi                              ; preserve body across AP counter sum
    mov  edi, r15d                         ; bench caller retains the BSP slot
    call smp_pf_ap_chunk_sum
    pop  rdi
    mov  [rbx + 32], rax                   ; per-pass AP counter baseline
    lea  rsi, [rsp + 24]                    ; the caller's ctx
    lea  rax, [rel smp_pf_bench_dst]
    mov  [rsi + SMP_PF_CTX_DST], rax
    mov  qword [rsi + SMP_PF_CTX_LEN], SMP_PF_BENCH_LEN
    mov  qword [rsi + SMP_PF_CTX_CHUNK], SMP_PF_BENCH_CHUNK
    mov  edx, SMP_PF_BENCH_CHUNKS
    call smp_par_for
    pushfq                                ; preserve the real join result
    cmp  rbp, [rel smp_pf_runs]
    je   .observed                        ; serial: no generation observation
    lea  rsi, [rel smp_pf_open_observation]
    mov  rdi, rbx
    mov  ecx, 4
    cld
    rep  movsq
.observed:
    mov  edi, r15d
    call smp_pf_ap_chunk_sum
    sub  rax, [rbx + 32]
    mov  [rbx + 32], rax
    popfq
    pop  rbp
    pop  rbx
    jc   .timed_out
    lea  rsi, [rel smp_pf_bench_ref]
    lea  rdi, [rel smp_pf_bench_dst]
    mov  ecx, SMP_PF_BENCH_LEN
    cld
    repe cmpsb
    sete al
    movzx eax, al
    clc
    ret
.timed_out:
    xor  eax, eax
    stc
    ret

; smp_pf_ap_chunk_sum(EDI BSP slot) -> RAX = sum of cpu_pf_chunks over every
;   other slot. clobbers: RCX,RDX.
smp_pf_ap_chunk_sum:
    xor  eax, eax
    xor  ecx, ecx
    lea  rdx, [rel cpu_pf_chunks]
.slot:
    cmp  ecx, edi
    je   .next
    add  rax, [rdx + rcx * 8]
.next:
    inc  ecx
    cmp  ecx, MAXCORE
    jb   .slot
    ret

smp_lock_collision_selftest:
    push rbx
    push r12
    push r13
    mov  qword [rel smp_coherence_counter], 0
    mov  dword [rel smp_coherence_ack_mask], 0
    call smp_online_mask_now
    mov  r13d, eax
    mov  r12d, [rel smp_coherence_epoch]
    inc  r12d
    jnz  .epoch_ok
    inc  r12d
.epoch_ok:
    mfence
    mov  [rel smp_coherence_epoch], r12d   ; publish request last
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick
    mov  ecx, SMP_COHERENCE_ITERS
.bsp_increment:
    call smp_coherence_counter_lock_acquire
    inc  qword [rel smp_coherence_counter]
    call smp_coherence_counter_lock_release
    dec  ecx
    jnz  .bsp_increment
    mov  dword [rel cpu_coherence_epoch], r12d
    lock bts dword [rel smp_coherence_ack_mask], 0
    mov  ebx, 4000
.wait:
    mov  eax, [rel smp_coherence_ack_mask]
    and  eax, r13d
    cmp  eax, r13d
    je   .grade
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait
.grade:
    ; Acks before the count: an AP acks after its increments, so an ack read
    ; here is already in the count below. Later ones show up as missing.
    mov  eax, [rel smp_coherence_ack_mask]
    and  eax, r13d
    xor  eax, r13d
    call smp_popcount32
    mov  [rel smp_coherence_ack_missing], eax ; a late AP's lost is not a lock fault
    mov  eax, r13d
    call smp_popcount32
    imul eax, SMP_COHERENCE_ITERS
    mov  [rel smp_coherence_expected], eax
    mov  rax, [rel smp_coherence_counter]
    mov  [rel smp_coherence_actual], eax
    mov  dword [rel smp_coherence_double_run], 0
    mov  dword [rel smp_coherence_lost], 0
    mov  ecx, [rel smp_coherence_expected]
    cmp  eax, ecx
    je   .acks
    jb   .lost
    sub  eax, ecx
    mov  [rel smp_coherence_double_run], eax
    jmp  .acks
.lost:
    sub  ecx, eax
    mov  [rel smp_coherence_lost], ecx
.acks:
    cmp  dword [rel smp_coherence_ack_missing], 0
    jne  .fail
    cmp  dword [rel smp_coherence_double_run], 0
    jne  .fail
    cmp  dword [rel smp_coherence_lost], 0
    jne  .fail
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Arm every online AP before releasing any recovery frame.  All AP handlers
; must enter concurrently; the BSP remains outside the barrier so it can
; release them.  The no-AP branch exercises the same CPU-indexed gate on CPU0.
smp_fault_concurrent_selftest:
    push rbx
    push r12
    push r13
    mov  byte [rel smp_fault_isolated], 0
    mov  dword [rel smp_faults_last_contained], 0
    mov  dword [rel smp_fault_entered_mask], 0
    mov  dword [rel smp_fault_done_mask], 0
    mov  dword [rel smp_fault_ready_mask], 0
    mov  r12d, [rel smpwork_online_mask]   ; AP-only dense mask
    test r12d, r12d
    jz   .bsp_only
    inc  dword [rel smp_fault_epoch]
    jnz  .fault_epoch_ok
    inc  dword [rel smp_fault_epoch]
.fault_epoch_ok:
    mov  eax, [rel smp_fault_epoch]
    lea  ecx, [eax - 1]
    mov  [rel smp_fault_release_epoch], ecx
    mfence
    mov  [rel smp_fault_request_mask], r12d
    call smp_pf_kick_aps                  ; RC power I1: wake parked APs now, not at their stretched tick
    mov  ebx, 4000
.wait_entered:
    mov  eax, [rel smp_fault_entered_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .release
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_entered
    mov  eax, [rel smp_fault_epoch]        ; never strand a partial participant set
    mov  [rel smp_fault_release_epoch], eax
    mfence
    mov  dword [rel smp_fault_request_mask], 0
    jmp  .fail
.release:
    mov  eax, [rel smp_fault_epoch]
    mov  [rel smp_fault_release_epoch], eax
    mfence
    mov  ebx, 4000
.wait_done:
    mov  eax, [rel smp_fault_done_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .fault_grade
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_done
    mov  dword [rel smp_fault_request_mask], 0
    jmp  .fail
.fault_grade:
    mov  dword [rel smp_fault_request_mask], 0
    mov  ebx, 4000
.wait_ready:
    mov  eax, [rel smp_fault_ready_mask]
    and  eax, r12d
    cmp  eax, r12d
    je   .ready
    mov  edi, 50
    call tsc_delay_us
    dec  ebx
    jnz  .wait_ready
    jmp  .fail
.ready:
    mov  eax, r12d
    call smp_popcount32
    mov  [rel smp_faults_last_contained], eax
    mov  byte [rel smp_fault_isolated], 1
    mov  eax, 1
    jmp  .out
.bsp_only:
    inc  dword [rel smp_fault_epoch]
    mov  eax, [rel smp_fault_epoch]
    mov  [rel smp_fault_release_epoch], eax
    lea  rax, [rel .bsp_recover]
    mov  [rel cpu_fault_recover], rax
    mov  byte [rel cpu_fault_expect], 1
    mov  rax, 0xDEAD000000000000
    mov  qword [rax], 0
.bsp_recover:
    inc  dword [rel cpu_fault_count]
    mov  dword [rel smp_fault_entered_mask], 1
    mov  dword [rel smp_fault_done_mask], 1
    mov  dword [rel smp_faults_last_contained], 1
    mov  byte [rel smp_fault_isolated], 1
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

smp_tlb_coherence_selftest:
    inc  qword [rel smp_mapping_probe]
    lea  rdi, [rel smp_mapping_probe]
    call smp_mapping_update_begin
    jc   .fail
    add  qword [rel smp_mapping_probe], 0x101
    call smp_mapping_update_commit
    jc   .fail
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; START modes re-run the owned mechanism before publishing an asynchronous job;
; a failed mechanism leaves the mode unsupported by behavior (START is refused).
smp_coherence_prepare_mode:
    cmp  edi, USCHED_MODE_COHERENCE
    je   smp_lock_collision_selftest
    cmp  edi, USCHED_MODE_FAULT
    je   smp_fault_concurrent_selftest
    cmp  edi, USCHED_MODE_TLB
    je   smp_tlb_coherence_selftest
    mov  eax, 1
    ret

; ---- smpwork_validate_live — derive the three reported safety bits from live
;      state, never from reply constants. rq_audit requires the declared audit
;      row plus every stable online AP correctly bound to a queue. rt_bsp verifies
;      every AP queue is background-only and the RT owner remains the BSP.
;      boot_bsp reads xAPIC on the caller and compares it with the saved BSP id. ----
smpwork_validate_live:
    push rbx
    push r12
    mov  byte [rel smpwork_rq_audit], 1
    mov  byte [rel smpwork_rt_bsp], 1
    cmp  byte [rel audit_site_declared + 3], 1 ; rq_lock's live audit-registry row
    je   .audit_declared
    mov  byte [rel smpwork_rq_audit], 0
.audit_declared:
    lea  r12, [rel smp_scheduler_tick]
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
.vloop:
    cmp  ebx, MAXCORE
    jae  .vdone
    lea  rax, [rel run_queue_per_core]
    cmp  qword [rax + rbx*8], r12
    jne  .vnext
    inc  ecx
    bts  edx, ebx
    lea  rax, [rel smpwork_worker_class]
    cmp  byte [rax + rbx], SMPWORK_CLASS_COMPOUNDING
    je   .class_ok
    mov  byte [rel smpwork_rt_bsp], 0
.class_ok:
    lea  rax, [rel smpwork_live_runs]
    cmp  qword [rax + rbx*8], 0
    jne  .vnext
    mov  byte [rel smpwork_rq_audit], 0
.vnext:
    inc  ebx
    jmp  .vloop
.vdone:
    cmp  ecx, [rel smpwork_expected_workers]
    je   .expected_ok
    mov  byte [rel smpwork_rq_audit], 0
    mov  byte [rel smpwork_rt_bsp], 0
.expected_ok:
    cmp  edx, [rel smpwork_expected_mask]
    je   .mask_ok
    mov  byte [rel smpwork_rq_audit], 0
    mov  byte [rel smpwork_rt_bsp], 0
.mask_ok:
    cmp  ecx, 2
    jae  .enough
    mov  byte [rel smpwork_rq_audit], 0
    mov  byte [rel smpwork_rt_bsp], 0
.enough:
    mov  eax, [rel smpwork_rt_owner_apic]
    cmp  eax, [rel smp_bsp_apic]
    je   .rt_owner_ok
    mov  byte [rel smpwork_rt_bsp], 0
.rt_owner_ok:
    call smp_read_apic_id
    cmp  eax, [rel smp_bsp_apic]
    sete al
    mov  [rel smpwork_boot_bsp], al
    pop  r12
    pop  rbx
    ret

; ---- smpwork_emit_serial(EDI=challenge, ESI=emit-marker) — boot-grade row in
;      the exact shape the live SMPWORK registry verb returns. ----
smpwork_emit_serial:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, edi
    mov  r15d, esi
    call smpwork_snapshot
    mov  r13d, eax
    mov  r12d, [rel smpwork_snapshot_epoch]

    lea  rdi, [rel str_work_pre]
    call serial_string
    mov  edi, [rel smpwork_snapshot_challenge]
    lea  rsi, [rel smp_numbuf]
    mov  rdx, 8
    call fmt_hex
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_work_epoch]
    call serial_string
    mov  edi, r12d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_work_workers]
    call serial_string
    mov  edi, r13d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string

    xor  ebx, ebx
.row_loop:
    cmp  ebx, MAXCORE
    jae  .rows_done
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    cmp  dword [rax + rbx*4], r12d
    jne  .row_next
    lea  rdi, [rel str_work_core]
    call serial_string
    mov  edi, ebx
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_work_token]
    call serial_string
    lea  rax, [rel smpwork_snapshot_worker_token]
    mov  edi, [rax + rbx*4]
    lea  rsi, [rel smp_numbuf]
    mov  rdx, 8
    call fmt_hex
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_work_runs]
    call serial_string
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  rdi, [rax + rbx*8]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
.row_next:
    inc  ebx
    jmp  .row_loop
.rows_done:
    lea  rdi, [rel str_work_rq]
    call serial_string
    movzx edi, byte [rel smpwork_rq_audit]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_work_rt]
    call serial_string
    movzx edi, byte [rel smpwork_rt_bsp]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_work_boot]
    call serial_string
    movzx edi, byte [rel smpwork_boot_bsp]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    test r15d, r15d
    jz   .no_marker
    cmp  r13d, 2
    jb   .no_marker
    cmp  r13d, [rel smpwork_expected_workers]
    jne  .no_marker
    cmp  byte [rel smpwork_rq_audit], 1
    jne  .no_marker
    cmp  byte [rel smpwork_rt_bsp], 1
    jne  .no_marker
    cmp  byte [rel smpwork_boot_bsp], 1
    jne  .no_marker
    lea  rdi, [rel str_work_marker]
    call serial_string
.no_marker:
    call serial_newline
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- Re-emit COREMAP after the fixed challenge epochs. Counts are copied from
;      the same frozen worker snapshot as the final structured row. ----
smpwork_emit_coremap:
    push rbx
    push r12
    lea  rdi, [rel str_coremap_run_pre]
    call serial_string
    xor  ebx, ebx
.map_loop:
    cmp  ebx, MAXCORE
    jae  .map_done
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    cmp  dword [rax + rbx*4], 0
    je   .map_next
    lea  rdi, [rel str_map_core]
    call serial_string
    mov  edi, ebx
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_map_colon]
    call serial_string
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  rdi, [rax + rbx*8]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
.map_next:
    inc  ebx
    jmp  .map_loop
.map_done:
    lea  rdi, [rel str_map_tail]
    call serial_string
    call serial_newline
    pop  r12
    pop  rbx
    ret

; ---- smp_send_ipi(EDI = dest apic id, ESI = ICR low command) ----
smp_send_ipi:
    jmp  smp_lapic_send_ipi

; Startup has one terminal outcome per AP: PENDING -> ONLINE or FAILED.
; EDI=dense AP slot, ESI=local CRC. EAX=1 only for the first accepted ONLINE
; publication. A timed-out/duplicate AP must park without publishing its queue.
; Local setup precedes this call; state -> queue is the established lock order.
smp_ap_publish_online:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    xor  eax, eax
    ret
.custody_free:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, esi
    test ebx, ebx                         ; never mutate the BSP through this seam
    jz   .refused
    cmp  ebx, MAXCORE
    jae  .refused
    cmp  ebx, [rel smp_discovered_count]
    jae  .refused
    call smp_state_lock_acquire
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_PENDING
    jne  .unlock_refused
    mov  edi, ebx
    call rq_lock_acquire
    lea  rax, [rel coremap_counts]
    mov  dword [rax + rbx*4], 1
    lea  rax, [rel core_compute]
    mov  dword [rax + rbx*4], r12d
    lea  rcx, [rel run_queue_per_core]
    lea  rax, [rel smp_scheduler_tick]
    mov  [rcx + rbx*8], rax
    lea  rax, [rel smpwork_worker_class]
    mov  byte [rax + rbx], SMPWORK_CLASS_COMPOUNDING
    mov  edi, ebx
    call rq_lock_release
    bts  dword [rel smpwork_online_mask], ebx
    lea  rax, [rel cpu_state]
    mov  byte [rax + rbx], CPU_STATE_ONLINE
    inc  dword [rel smp_online_aps]
    inc  dword [rel smp_topology_online]
    call smp_state_lock_release
    mov  eax, 1
    jmp  .out
.unlock_refused:
    ; A FAILED row here is this AP arriving after the BSP timed it out. Keep
    ; one raw late record and withdraw the readiness it set before publishing;
    ; an ONLINE (duplicate) or never-started row belongs to no late arrival.
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_FAILED
    jne  .unlock_only
    lea  rax, [rel cpu_timer_ready]
    mov  byte [rax + rbx], 0
    lea  rax, [rel cpu_runq_ready]
    mov  byte [rax + rbx], 0
    bts  dword [rel smp_late_ap_mask], ebx
    jc   .unlock_only                     ; one record per row
    inc  dword [rel smp_late_ap_count]
.unlock_only:
    call smp_state_lock_release
.refused:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Mask and stop this CPU's LAPIC timer, programmed by smp_preempt_init_local
; before startup publication. A parked late AP keeps no live periodic source.
smp_ap_timer_quiesce:
    mov  esi, SMP_LAPIC_LVT_TIMER
    mov  edx, (1 << 16) | SMP_TIMER_VECTOR
    call smp_lapic_write32
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    xor  edx, edx
    call smp_lapic_write32
    ret

; EDI=dense AP slot. BSP timeout/IPI failure and AP-local setup failure share
; this transition. ONLINE is never demoted; repeated failure counts only once.
; EAX=1 iff this call won PENDING -> FAILED. Called with interrupts disabled.
smp_ap_fail_pending:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    xor  eax, eax
    ret
.custody_free:
    push rbx
    mov  ebx, edi
    test ebx, ebx
    jz   .unchanged
    cmp  ebx, MAXCORE
    jae  .unchanged
    cmp  ebx, [rel smp_discovered_count]
    jae  .unchanged
    call smp_state_lock_acquire
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_PENDING
    jne  .unlock_unchanged
    mov  byte [rax + rbx], CPU_STATE_FAILED
    inc  dword [rel smp_failed_count]
    call smp_state_lock_release
    mov  eax, 1
    pop  rbx
    ret
.unlock_unchanged:
    call smp_state_lock_release
.unchanged:
    xor  eax, eax
    pop  rbx
    ret

; ============================================================================
; smp_ap_main — entry for every application processor (jumped to from the low-mem
; trampoline in full 64-bit long mode, our CR3, but on the TRAMPOLINE GDT and with
; NO usable stack yet). Reads APIC id first (pure MMIO, no stack), then sets its
; per-core stack, adopts our real GDT+IDT, binds its queue, marks online, and
; enters the per-core scheduler pull loop.
; ============================================================================
smp_ap_main:
    ; Read the full local identity INLINE (no stack/call yet), then resolve it
    ; through the firmware table.  Hardware APIC IDs are never array indexes.
    cmp  byte [rel smp_lapic_mode], 0
    je   .read_xapic
    mov  ecx, X2APIC_MSR_BASE + (0x20 >> 4)
    rdmsr
    jmp  .have_apic
.read_xapic:
    mov  rax, LAPIC_ID_REG
    mov  eax, [rax]
    shr  eax, 24
.have_apic:
    mov  r14d, eax                         ; r14d = full hardware APIC id
    xor  r15d, r15d                        ; r15d = dense logical id
.resolve:
    cmp  r15d, [rel smp_discovered_count]
    jae  .unmapped
    lea  rbx, [rel cpu_apic_id]
    cmp  [rbx + r15*4], r14d
    je   .mapped
    inc  r15d
    jmp  .resolve
.unmapped:
    cli
.unmapped_halt:
    pause                                 ; no private stack/identity: cannot check TSA
    jmp  .unmapped_halt
.mapped:
    ; per-core stack is indexed only by the dense logical id.
    lea  rbx, [rel ap_stacks]
    mov  rsp, [rbx + r15*8]
    test rsp, rsp
    jz   .unmapped
    mov  edi, r15d
    call gdt_percpu_load                    ; private GDT/TSS/IST + TR
    jc   .local_fail
    lidt [rel idt_ptr]
    mov  edi, r15d
    mov  esi, r14d                          ; full mapped hardware identity
    call cpu_microcode_percpu_early         ; checked normal-only; UNKNOWN never gates online
    mov  edi, r15d
    call mca_boot_init                      ; retained boot logs before CTLs/CR4.MCE
    call sched_unified_cpu_local_init       ; consume this CPU's post-attempt enumeration
    mov  edi, r15d
    call smp_topology_local_init
    jc   .local_fail
    call smp_lapic_init_local
    lea  rax, [rel cpu_timer_ready]
    mov  byte [rax + r15], 1
    lea  rax, [rel cpu_runq_ready]
    mov  byte [rax + r15], 1
    lea  rax, [rel cpu_current_slot]
    mov  dword [rax + r15*4], r15d
    ; --- the per-core task: compute crc32(full APIC id ^ seed) ---
    mov  eax, [rel smp_seed]
    xor  eax, r14d
    mov  edi, eax
    call smp_crc32
    mov  r14d, eax                         ; my computed value
    mov  edi, r15d
    mov  esi, r14d
    call smp_ap_publish_online
    test eax, eax
    jz   .late_park                       ; timeout/duplicate cannot join later
    sti
.scheduler_loop:
    ; Only the outer AP task boundary can acknowledge custody. Never park an
    ; arbitrary interrupted writer or a scheduler frame that still owns locks.
    mov  edi, r15d
    call smp_core_custody_park
    mov  edi, r15d                       ; dense logical CPU, not APIC id
    call mca_corrected_tick              ; <=1 qualified MCA scan/s; owned logged CMCI clear
    ; Fault injection is a scheduler task boundary, not a terminal core park.
    mov  eax, [rel smp_fault_request_mask]
    bt   eax, r15d
    jc   .do_fault
    ; Pull the AP-owned task from its own queue. The pointer is immutable after
    ; publication, so the common path needs no global scheduler lock.
    mov  ebx, r15d
    lea  rax, [rel run_queue_per_core]
    mov  rax, [rax + rbx*8]
    test rax, rax
    jz   .idle_pause
    call rax
.idle_pause:
    ; RCQ-27 idle-halt (stage A): with no unified-scheduler job live there is
    ; nothing to pull, so request checked idle until the next interrupt:
    ; the LAPIC scheduler tick (stretched to 16 ms while parked, RC power I1),
    ; or any IPI (resched, idle-wake, coherence/TLB). The same pull runs on
    ; every wake; polled requests (fault/coherence/frequency/msr/smpwork epochs)
    ; send IDLE_WAKE after they publish, and the stretched tick bounds a missed
    ; one. The flag checks below run with IF clear, but the pull reads the
    ; polled epochs with IF set, so a kick that lands between that read and
    ; the cli is spent: that request waits for the next tick (<= 16 ms parked).
    ; The BSP's own 1 kHz tick arms the watchdog scan. Unknown/refused policy
    ; returns after one PAUSE with IF enabled and repeats this same queue pull.
    ; Halt only once THIS AP's timer runs at the measured 1 ms reload (its bit
    ; in smp_timer_rearm_ack_mask, set by the rearm IPI after the C6 LAPIC
    ; calibration). Before that it ticks at the nominal 0x100000/16 reload
    ; (17 ms in QEMU, ~170-700 ms on metal) while the boot SMP selftests poll
    ; the APs with 100-250 ms windows and no IPI, so an earlier halt would make
    ; them time out. The checks run with IF clear and smp_idle_enter's sti;hlt
    ; is atomic (its MWAIT breaks on a pending interrupt): a wake IPI that
    ; arrives after the check stays pending and ends the halt at once.
    ; A live job keeps the spin: sched_unified_run_one takes one unit per call.
    cli
    cmp  byte [rel usched_job_active], 1
    je   .spin_sti
    cmp  byte [rel smp_pf_active], 1      ; RCQ-12 track 2: a live par_for generation keeps the spin
    je   .spin_sti
    cmp  dword [rel smp_pc_phase], 0      ; RC power I1 (srcreview R1): so does a polled par_begin lane
    jne  .spin_sti
    mov  eax, [rel smp_timer_rearm_ack_mask]
    bt   eax, r15d
    jnc  .spin_sti                        ; not yet on the calibrated 1 ms tick
    mov  edi, r15d
    call smp_idle_tick_stretch            ; RC power I1: parked, the tick runs every 16 ms
    mov  edi, r15d
    call smp_idle_enter                   ; RCQ-27 L2: sti;hlt, or MWAIT where the row allows it
    jmp  .scheduler_loop
.spin_sti:
    mov  edi, r15d
    call smp_idle_tick_restore            ; live work: back on the measured 1 ms tick first
    sti
.busy_spin:
    mov  ecx, 10000                       ; bounded scheduler cadence while a job is live
.pause_tick:
    pause
    dec  ecx
    ; A newly published PARFOR lobby cannot wait the remaining 10000-PAUSE
    ; competing-job cadence. Sample every <=64 pauses and return through the
    ; SAME outer custody/MCA/fault/task boundary. This is not an IRQ worker.
    ; Keep every pause and task pull interruptible; only the flag read is
    ; bracketed, as in the existing idle decision. No timer/window extension.
    test ecx, 63
    jnz  .pause_continue
    cli
    cmp  byte [rel smp_pf_active], 1
    je   .parfor_pull_sti
    sti
.pause_continue:
    test ecx, ecx
    jnz  .pause_tick
    jmp  .scheduler_loop
.parfor_pull_sti:
    sti
    jmp  .scheduler_loop
.do_fault:
    ; Deliberate #GP inside this AP's task.  The vector-13 gate resolves this
    ; dense logical CPU and consumes only its private arm/recovery slot.
    lea  rax, [rel .recover]
    lea  rbx, [rel cpu_fault_recover]
    mov  [rbx + r15*8], rax
    lea  rbx, [rel cpu_fault_expect]
    mov  byte [rbx + r15], 1
    mov  rax, 0xDEAD000000000000           ; non-canonical -> #GP(0)
    mov  qword [rax], 0
.recover:
    lea  rax, [rel cpu_fault_count]
    inc  dword [rax + r15*4]
    lock bts dword [rel smp_fault_done_mask], r15d
.fault_ack_wait:
    mov  eax, [rel smp_fault_request_mask]
    bt   eax, r15d
    jc   .fault_still_armed
    lock bts dword [rel smp_fault_ready_mask], r15d
    jmp  .scheduler_loop
.fault_still_armed:
    pause
    jmp  .fault_ack_wait

.late_park:
    call smp_ap_timer_quiesce
    jmp  .park
.local_fail:
    mov  edi, r15d
    call smp_ap_fail_pending
.park:
    cli
.failed_halt:
    pause                                 ; FAILED CPU has no admitted idle policy
    jmp  .failed_halt

; Earn the 1330b marker only from the fixture parser plus the live dense table
; and every CPU-local readiness cell.  A partial boot remains observable but
; cannot accidentally print PASS.
smp_topology_emit_marker:
    cmp  byte [rel smp_topology_fixture_ok], 1
    jne  .out
    cmp  byte [rel smp_topology_exact], 1
    jne  .out
    cmp  byte [rel smp_topology_overflow], 0
    jne  .out
    mov  eax, [rel smp_enabled_count]
    cmp  eax, [rel smp_discovered_count]
    jne  .out
    cmp  eax, [rel smp_topology_online]
    jne  .out
    cmp  dword [rel smp_failed_count], 0
    jne  .out
    xor  ecx, ecx
.check:
    cmp  ecx, [rel smp_discovered_count]
    jae  .pass
    lea  rax, [rel ap_stacks]
    cmp  qword [rax + rcx*8], 0
    je   .out
    lea  rax, [rel gdt_percpu_ready]
    cmp  byte [rax + rcx], 7
    jne  .out
    lea  rax, [rel cpu_timer_ready]
    cmp  byte [rax + rcx], 1
    jne  .out
    lea  rax, [rel cpu_runq_ready]
    cmp  byte [rax + rcx], 1
    jne  .out
    lea  rax, [rel cpu_state]
    cmp  ecx, 0
    jne  .want_online
    cmp  byte [rax], CPU_STATE_BSP
    jne  .out
    jmp  .next
.want_online:
    cmp  byte [rax + rcx], CPU_STATE_ONLINE
    jne  .out
.next:
    inc  ecx
    jmp  .check
.pass:
    lea  rdi, [rel str_topology_exact_ok]
    call serial_string
.out:
    ret

; ============================================================================
; smp_selftest — the BSP orchestrator (called from boot/header after the core
; self-tests). Cli for the duration (no timer preemption mid-bring-up), restored
; on exit.
; ============================================================================
%ifdef PAOS_HP_SMP_TRIAL_APS
; smp_hp_trial_report — HP identity only: bound stack/SIPI preparation to the
; first PAOS_HP_SMP_TRIAL_APS firmware AP rows and say so on serial.
smp_hp_trial_report:
    push rbx
    mov  eax, PAOS_HP_SMP_TRIAL_APS + 1
    cmp  eax, [rel smp_discovered_count]
    jbe  .bounded
    mov  eax, [rel smp_discovered_count]
.bounded:
    mov  [rel smp_stk_limit], eax
    dec  eax
    mov  [rel smp_hp_trial_aps], eax
    lea  rdi, [rel str_smp_hp_trial]
    call serial_string
    mov  edi, [rel smp_hp_trial_aps]
    call serial_hex64
    lea  rdi, [rel str_smp_hp_trial_fw]
    call serial_string
    mov  edi, [rel smp_discovered_count]
    call serial_hex64
    lea  rdi, [rel str_smp_hp_trial_tail]
    call serial_string
    mov  eax, [rel smp_hp_trial_aps]     ; aps=<decimal> (contract text); <= 31
    cmp  eax, 10
    jb   .ones
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    mov  ebx, edx
    lea  edi, [rax + '0']
    call serial_char
    mov  eax, ebx
.ones:
    lea  edi, [rax + '0']
    call serial_char
    lea  rdi, [rel str_smp_hp_trial_reason]
    call serial_string
    pop  rbx
    ret
%endif

smp_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    pushfq
    cli

    mov  dword [rel smp_fault_request_mask], 0
    mov  dword [rel smp_fault_entered_mask], 0
    mov  dword [rel smp_fault_done_mask], 0
    mov  dword [rel smp_fault_epoch], 0
    mov  dword [rel smp_fault_release_epoch], 0
    mov  byte [rel smp_fault_isolated], 0
    mov  dword [rel smp_coherence_epoch], 0
    mov  dword [rel smp_coherence_ack_mask], 0
    mov  dword [rel smp_coherence_ack_missing], 0
    mov  dword [rel smp_tlb_epoch], 0
    mov  dword [rel smp_tlb_requested], 0
    mov  dword [rel smp_tlb_acked], 0
    mov  dword [rel smp_stale_mapping], 0
    mov  qword [rel smp_irq_entries], 0
    mov  qword [rel smp_irq_eois], 0
    mov  dword [rel smp_irq_duplicate_eoi], 0
    mov  dword [rel smp_irq_ownership_faults], 0
    mov  dword [rel smp_online_aps], 0
    mov  dword [rel smpwork_online_mask], 0
    mov  dword [rel smpwork_expected_workers], 0
    mov  dword [rel smpwork_expected_mask], 0
    mov  dword [rel smpwork_requested_epoch], 0
    call smp_lapic_detect_mode
    call smp_preempt_global_init
    call smp_topology_discover

    ; Clear every dense runtime slot before assigning private state.
    xor  r12d, r12d
.clear_runtime:
    cmp  r12d, MAXCORE
    jae  .runtime_clear
    lea  rax, [rel coremap_counts]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel core_compute]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel run_queue_per_core]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel ap_stacks]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_timer_ready]
    mov  byte [rax + r12], 0
    lea  rax, [rel cpu_runq_ready]
    mov  byte [rax + r12], 0
    lea  rax, [rel cpu_fault_expect]
    mov  byte [rax + r12], 0
    lea  rax, [rel cpu_fault_recover]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_fault_count]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel cpu_coherence_epoch]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel cpu_tlb_epoch]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel cpu_mapping_observed]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_irq_depth]
    mov  byte [rax + r12], 0
    lea  rax, [rel cpu_irq_count]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_preempt_count]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_resched_count]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_idle_wake_count]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_load_busy_ticks]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_context_switch_count]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_migration_count]
    mov  qword [rax + r12*8], 0
    lea  rax, [rel cpu_last_progress_tsc]
    mov  qword [rax + r12*8], 0
    inc  r12d
    jmp  .clear_runtime
.runtime_clear:
    mov  dword [rel smp_load_snapshot_seq], 0

    ; --- boot nonce seed (per-boot; low 32 of TSC) ---
    rdtsc
    mov  [rel smp_seed], eax
    lea  rdi, [rel str_seed_pre]
    call serial_string
    mov  edi, [rel smp_seed]
    lea  rsi, [rel smp_numbuf]
    mov  rdx, 8
    call fmt_hex
    lea  rdi, [rel smp_numbuf]
    call serial_string
    call serial_newline

    ; BSP is dense logical 0 on its retained arena stack. Replace the shared
    ; boot TSS with CPU0's private GDT/TSS/IST image.
    xor  edi, edi
    call percpu_stack_kernel_top
    lea  rbx, [rel ap_stacks]
    mov  [rbx], rax
    xor  edi, edi
    mov  rsi, rax
    call gdt_percpu_prepare
    jc   .bsp_local_fail
    xor  edi, edi
    call gdt_percpu_load
    jc   .bsp_local_fail
    lidt [rel idt_ptr]
    xor  edi, edi
    call smp_topology_local_init
    jc   .bsp_local_fail
    call smp_lapic_init_local
    mov  byte [rel cpu_timer_ready], 1
    mov  byte [rel cpu_runq_ready], 1
    mov  dword [rel cpu_current_slot], 0
    mov  byte [rel cpu_state], CPU_STATE_BSP
    mov  dword [rel smp_topology_online], 1

    ; Preallocate and describe state only for exact firmware AP rows.  A failed
    ; allocation is bounded and reported; no SIPI is sent for that logical CPU.
    mov  r12d, 1
    ; RCQ-12 S1: the ADMIN Q5 HP BSP-only gate is retired. HP Step B W1 (2026-10-10,
    ; iter-20261010-233758) brought every firmware AP up on the HP: 8/8/8, 0 failed.
    ; The HP prepares and starts every firmware AP row like every other target.
%ifdef PAOS_HP_SMP_TRIAL_APS
    ; RCQ-12 HP host-SMP trial (Peter 2026-10-07, contract 708d98f8): only a build
    ; with this define, and only on the HP identity, admits the first N firmware AP
    ; rows in dense order. Rows above N stay DISCOVERED: no stack, no PENDING, no
    ; INIT-SIPI-SIPI. Without the define this block assembles to nothing.
    mov  eax, [rel smp_discovered_count]
    mov  [rel smp_stk_limit], eax
    cmp  byte [rel smbios_hp_phase0], 1
    jne  .stk_loop
    call smp_hp_trial_report               ; sets smp_stk_limit = min(1+N, discovered)
%endif
.stk_loop:
    cmp  r12d, [rel SMP_STK_LIMIT]
    jge  .stk_done
    mov  edi, r12d
    call percpu_stack_kernel_top          ; retained arena, never the freeable heap
    lea  rbx, [rel ap_stacks]
    mov  [rbx + r12*8], rax
    mov  edi, r12d
    mov  rsi, rax
    call gdt_percpu_prepare
    jc   .stack_failed
    lea  rax, [rel cpu_state]
    mov  byte [rax + r12], CPU_STATE_PENDING
    jmp  .stack_next
.stack_failed:
    lea  rax, [rel cpu_state]
    mov  byte [rax + r12], CPU_STATE_FAILED
    inc  dword [rel smp_failed_count]
.stack_next:
    inc  r12d
    jmp  .stk_loop
.stk_done:

    ; --- copy the trampoline blob to 0x8000 + patch CR3 & 64-bit entry ---
    cld                                    ; forward copy (DF state unknown at boot)
    mov  rdi, TRAMP_BASE
    lea  rsi, [rel ap_tramp_start]
    mov  rcx, ap_tramp_end - ap_tramp_start
    rep  movsb
    mov  eax, [rel pml4_addr]              ; low 32 bits of our PML4 (QEMU <4GiB)
    mov  dword [TRAMP_BASE + (ap_cr3 - ap_tramp_start)], eax
    lea  rax, [rel smp_ap_main]
    mov  [TRAMP_BASE + (ap_entry_slot - ap_tramp_start)], rax

    ; --- BSP contributes dense logical core 0 (full APIC id + compute) ---
    mov  eax, [rel cpu_apic_id]
    mov  [rel smpwork_rt_owner_apic], eax  ; realtime + boot/control stay on BSP
    mov  edi, eax
    xor  edi, [rel smp_seed]
    call smp_crc32
    mov  r14d, eax
    xor  edi, edi
    call rq_lock_acquire
    xor  ebx, ebx
    lea  rax, [rel coremap_counts]
    mov  dword [rax + rbx*4], 1
    lea  rax, [rel core_compute]
    mov  dword [rax + rbx*4], r14d
    xor  edi, edi
    call rq_lock_release

    ; --- bring up exactly the firmware AP set, by full APIC destination ---
    mov  r12d, 1
.ap_loop:
    cmp  r12d, [rel smp_discovered_count]
    jge  .ap_done
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r12], CPU_STATE_PENDING
    jne  .ap_next
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r12*4]
    mov  esi, ICR_INIT
    call smp_send_ipi
    jc   .ap_failed
    mov  edi, 10000
    call tsc_delay_us                      ; 10 ms after INIT
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r12*4]
    mov  esi, ICR_SIPI
    call smp_send_ipi
    jc   .ap_failed
    mov  edi, 200
    call tsc_delay_us
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r12*4]
    mov  esi, ICR_SIPI
    call smp_send_ipi
    jc   .ap_failed
    mov  edi, 200
    call tsc_delay_us
    ; wait (bounded ~30 ms) for this AP to come online
    mov  r14d, 300
.ap_wait:
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r12], CPU_STATE_ONLINE
    je   .ap_next
    cmp  byte [rax + r12], CPU_STATE_FAILED
    je   .ap_next
    mov  edi, 100
    call tsc_delay_us
    dec  r14d
    jnz  .ap_wait
.ap_failed:
    mov  edi, r12d
    call smp_ap_fail_pending               ; race winner is final under state lock
.ap_next:
    inc  r12d
    jmp  .ap_loop
.ap_done:
    ; Freeze the exact expected set only after the bounded bring-up scan is
    ; complete. Count + membership were published together under smp_state_lock.
    call smp_state_lock_acquire
    mov  eax, [rel smp_online_aps]
    mov  [rel smpwork_expected_workers], eax
    mov  eax, [rel smpwork_online_mask]
    mov  [rel smpwork_expected_mask], eax
    call smp_state_lock_release
    jmp  .locals_ready

.bsp_local_fail:
    mov  byte [rel cpu_state], CPU_STATE_FAILED
    mov  dword [rel smp_failed_count], 1
    mov  dword [rel smp_topology_online], 0
.locals_ready:
    call smp_topology_summarize

    ; --- emit per-core lines + build COREMAP; count nonzero cores + sum ---
    xor  r12d, r12d                        ; core index
    xor  r13d, r13d                        ; nonzero-core count
    xor  r15d, r15d                        ; task sum
.emit_loop:
    cmp  r12d, [rel smp_discovered_count]
    jge  .emit_done
    mov  ebx, r12d
    lea  rax, [rel coremap_counts]
    mov  eax, [rax + rbx*4]
    test eax, eax
    jz   .emit_next
    inc  r13d
    add  r15d, eax
    ; "smp.core: apic=<id> compute=0x<hex8>"
    lea  rdi, [rel str_core_pre]
    call serial_string
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r12*4]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_core_mid]
    call serial_string
    mov  ebx, r12d
    lea  rdi, [rel core_compute]
    mov  edi, [rdi + rbx*4]
    lea  rsi, [rel smp_numbuf]
    mov  rdx, 8
    call fmt_hex
    lea  rdi, [rel smp_numbuf]
    call serial_string
    call serial_newline
.emit_next:
    inc  r12d
    jmp  .emit_loop
.emit_done:
    ; save nonzero-core count + sum for the markers below
    mov  [rel smp_core_count], r13d
    mov  [rel smp_task_sum],   r15d

    ; --- smp.cpuid_cores=<N> (1037 compatibility: actual online logical CPUs) ---
    lea  rdi, [rel str_cpuid_pre]
    call serial_string
    mov  edi, [rel smp_topology_online]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    call serial_newline

    ; --- smp.ap.online (only if a real AP acked) ---
    mov  eax, [rel smp_online_aps]
    test eax, eax
    jz   .no_online
    lea  rdi, [rel str_ap_online]
    call serial_string
.no_online:

    ; --- smp.core.compute marker ---
    lea  rdi, [rel str_compute_mk]
    call serial_string

    ; --- COREMAP line (real per-core task counts) + smp.coremap.real ---
    lea  rdi, [rel str_coremap_pre]
    call serial_string
    xor  r12d, r12d
.map_loop:
    cmp  r12d, [rel smp_discovered_count]
    jge  .map_done
    mov  ebx, r12d
    lea  rax, [rel coremap_counts]
    mov  eax, [rax + rbx*4]
    test eax, eax
    jz   .map_next
    lea  rdi, [rel str_map_core]           ; " core_"
    call serial_string
    mov  edi, r12d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_map_colon]          ; ": "
    call serial_string
    mov  ebx, r12d
    lea  rdi, [rel coremap_counts]
    mov  edi, [rdi + rbx*4]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
.map_next:
    inc  r12d
    jmp  .map_loop
.map_done:
    lea  rdi, [rel str_map_tail]           ; " [smp.coremap.real]"
    call serial_string
    call serial_newline

    ; Retain the legacy serial breadcrumb, but earn it from the concurrent
    ; CPU-local barrier rather than a global singleton arm.
    call smp_fault_concurrent_selftest
    test eax, eax
    jz   .finish
    lea  rdi, [rel str_faultc_all]
    call serial_string

.finish:
    call smp_topology_emit_marker
    ; Two fresh epochs over two fixed challenges. The AP scheduler workers, not
    ; the BSP, stamp the tokens/runs consumed by these structured rows.
    mov  edi, 0x13579BDF
    xor  esi, esi
    call smpwork_emit_serial
    mov  edi, 0x2468ACE0
    mov  esi, 1
    call smpwork_emit_serial
    call smpwork_emit_coremap
    call sched_unified_boot_selftest
    popfq
    pushfq
    sti
    call sched_preempt_boot_selftest
    popfq
    call sched_balance_boot_selftest
    pushfq
    sti
    call smp_coherence_selftest
    popfq
    call smp_completion_selftest_portable
    call smp_portability_emit
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Capacity-safe form of core/smp_audit's shipped capstone composition.  Keep
; the same single/parallel jobs and marker contract, but derive the all-online
; mask without x86's count-mod-32 shift behavior (1 << 32 becomes 1).
; This lives at the SMP owner seam because smp_audit is shared outside 1330i's
; transaction; the legacy entry remains unchanged for older callers.
smp_completion_selftest_portable:
    push rbx
    push r12
    push r13
    cmp  byte [rel smp_topology_exact], 1
    jne  .fail
    cmp  byte [rel smp_coherence_ready], 1
    jne  .fail
    mov  byte [rel usched_job_active], 0

    mov  edi, USCHED_MODE_SINGLE
    mov  esi, 257
    call sched_unified_bench_begin
    test eax, eax
    jnz  .fail
    mov  ebx, 32
.single_drive:
    call sched_unified_bench_drive
    test eax, eax
    jnz  .single_done
    dec  ebx
    jnz  .single_drive
    jmp  .fail
.single_done:
    cmp  dword [rel usched_job_completed], 257
    jne  .fail
    cmp  dword [rel usched_job_core_mask], 1
    jne  .fail
    cmp  dword [rel usched_job_double_run], 0
    jne  .fail
    cmp  dword [rel usched_job_state_leaks], 0
    jne  .fail
    mov  r12, [rel usched_job_digest]
    test r12, r12
    jz   .fail
    lea  rdi, [rel str_smp_single_ok]
    call serial_string
    cmp  dword [rel smp_topology_online], 1
    jne  .parallel_begin
    lea  rdi, [rel str_smp_work_single_ok]
    call serial_string

.parallel_begin:
    mov  byte [rel usched_job_active], 0
    mov  edi, USCHED_MODE_PARALLEL
    mov  esi, 257
    call sched_unified_bench_begin
    test eax, eax
    jnz  .fail
    mov  ebx, 32
.parallel_drive:
    call sched_unified_bench_drive
    test eax, eax
    jnz  .parallel_done
    dec  ebx
    jnz  .parallel_drive
    jmp  .fail
.parallel_done:
    cmp  dword [rel usched_job_completed], 257
    jne  .fail
    cmp  qword [rel usched_job_digest], r12
    jne  .fail
    cmp  dword [rel usched_job_double_run], 0
    jne  .fail
    cmp  dword [rel usched_job_state_leaks], 0
    jne  .fail
    cmp  dword [rel usched_job_stale_mapping], 0
    jne  .fail
    mov  edi, [rel smp_topology_online]
    call smp_count_mask32
    cmp  eax, [rel usched_job_core_mask]
    jne  .fail
    mov  ecx, [rel smp_topology_online]
    cmp  dword [rel smp_configured_count], ecx
    jne  .fail
    cmp  dword [rel smp_enabled_count], ecx
    jne  .fail
    cmp  dword [rel smp_discovered_count], ecx
    jne  .fail
    cmp  dword [rel smp_failed_count], 0
    jne  .fail
    cmp  ecx, 1
    jbe  .work_marker_done
    lea  rdi, [rel str_smp_work_multi_ok]
    call serial_string
.work_marker_done:
    call smp_completion_emit_qemu_row
    lea  rdi, [rel str_smp_daily_ok]
    call serial_string
    mov  byte [rel usched_job_active], 0
    mov  eax, 1
    jmp  .out
.fail:
    mov  byte [rel usched_job_active], 0
    lea  rdi, [rel str_smp_completion_fail]
    call serial_string
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate the dense live membership without assuming uniform SMT. Each row
; contributes once to its package/core group; the summary's threads_per_core
; is the MAXIMUM group size, not a multiplier for every physical core.
; Read-only, bounded by SMP_CPU_CAPACITY; EAX=1 iff identities, placement and
; summary counts agree. Preserves RBX/R12-R15; other GPRs are scratch.
smp_topology_membership_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel smp_topology_online]
    test r12d, r12d
    jz   .bad
    cmp  r12d, SMP_CPU_CAPACITY
    ja   .bad
    cmp  r12d, [rel smp_discovered_count]
    jne  .bad
    cmp  r12d, [rel smp_enabled_count]
    jne  .bad
    cmp  r12d, [rel smp_configured_count]
    jne  .bad
    xor  r8d, r8d                         ; dense logical row
    xor  r13d, r13d                       ; distinct packages
    xor  r14d, r14d                       ; distinct package/core pairs
    xor  r15d, r15d                       ; maximum actual siblings
.cpu:
    lea  rax, [rel cpu_state]
    test r8d, r8d
    jnz  .ap
    cmp  byte [rax + r8], CPU_STATE_BSP
    jne  .bad
    jmp  .facts
.ap:
    cmp  byte [rax + r8], CPU_STATE_ONLINE
    jne  .bad
.facts:
    lea  rax, [rel cpu_package]
    mov  r9d, [rax + r8*4]
    lea  rax, [rel cpu_core]
    mov  r10d, [rax + r8*4]
    lea  rax, [rel cpu_thread]
    mov  r11d, [rax + r8*4]
    lea  rax, [rel cpu_apic_id]
    mov  edi, [rax + r8*4]
    lea  rax, [rel cpu_placement_rank]
    mov  esi, [rax + r8*4]
    cmp  r9d, 0xFFFFFFFF
    je   .bad
    cmp  r10d, 0xFFFFFFFF
    je   .bad
    cmp  r11d, 0xFFFFFFFF
    je   .bad
    cmp  edi, 0xFFFFFFFF
    je   .bad
    cmp  esi, r12d
    jae  .bad
    mov  edx, 3                           ; unseen package/core bits
    mov  ecx, 1                           ; this row + earlier siblings
    xor  ebx, ebx
.prior:
    cmp  ebx, r8d
    jae  .count
    lea  rax, [rel cpu_apic_id]
    cmp  [rax + rbx*4], edi
    je   .bad
    lea  rax, [rel cpu_placement_rank]
    cmp  [rax + rbx*4], esi
    je   .bad
    lea  rax, [rel cpu_package]
    cmp  [rax + rbx*4], r9d
    jne  .next_prior
    and  edx, ~1
    lea  rax, [rel cpu_core]
    cmp  [rax + rbx*4], r10d
    jne  .next_prior
    and  edx, ~2
    inc  ecx
    lea  rax, [rel cpu_thread]
    cmp  [rax + rbx*4], r11d
    je   .bad                             ; duplicate logical identity
.next_prior:
    inc  ebx
    jmp  .prior
.count:
    test edx, 1
    jz   .core
    inc  r13d
.core:
    test edx, 2
    jz   .sibling
    inc  r14d
    cmp  esi, [rel smp_physical_core_count]
    jae  .bad                             ; representatives precede siblings
    jmp  .maximum
.sibling:
    cmp  esi, [rel smp_physical_core_count]
    jb   .bad
.maximum:
    cmp  ecx, r15d
    cmova r15d, ecx
    inc  r8d
    cmp  r8d, r12d
    jb   .cpu
    cmp  r13d, [rel smp_package_count]
    jne  .bad
    cmp  r14d, [rel smp_physical_core_count]
    jne  .bad
    cmp  r15d, [rel smp_threads_per_core]
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Emit one content-graded row from live CPUID topology and a real bounded
; parallel scheduler job. Vendor/model strings do not participate in work.
smp_portability_emit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel smp_topology_exact], 1
    jne  .fail
    cmp  byte [rel smp_topology_overflow], 0
    jne  .fail
    cmp  byte [rel smp_placement_valid], 1
    jne  .fail
    cmp  dword [rel smp_failed_count], 0
    jne  .fail
    mov  r12d, [rel smp_topology_online]
    cmp  r12d, [rel smp_discovered_count]
    jne  .fail
    test r12d, r12d
    jz   .fail
    cmp  r12d, SMP_CPU_CAPACITY
    ja   .fail
    call smp_topology_membership_validate
    test eax, eax
    jz   .fail
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_INTEL
    je   .vendor_ok
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_AMD
    jne  .fail
.vendor_ok:
    mov  eax, [rel smp_topology_leaf]
    cmp  eax, 0x1F
    je   .leaf_ok
    cmp  eax, 0x0B
    je   .leaf_ok
    cmp  eax, 0x8000001E
    jne  .fail
.leaf_ok:
    mov  edi, USCHED_MODE_PARALLEL
    mov  esi, 257
    call sched_unified_bench_begin
    test eax, eax
    jnz  .fail
    ; A PARALLEL drive is one bounded poll: it returns pending while an AP has
    ; not yet run its reserved ticket, which the BSP may never take. Poll like
    ; smp_completion_selftest_portable; a late AP is not a topology failure.
    mov  ebx, 32
.parallel_drive:
    call sched_unified_bench_drive
    test eax, eax
    jnz  .parallel_done
    dec  ebx
    jnz  .parallel_drive
    jmp  .fail
.parallel_done:
    cmp  dword [rel usched_job_completed], 257
    jne  .fail
    cmp  dword [rel usched_job_double_run], 0
    jne  .fail
    mov  edi, r12d
    call smp_count_mask32
    mov  r13d, eax
    mov  r14d, [rel usched_job_core_mask]
    cmp  r14d, r13d
    jne  .fail
    mov  byte [rel usched_job_active], 0

    lea  rdi, [rel str_portability_row]
    call serial_string
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_INTEL
    je   .row_intel
    lea  rdi, [rel smp_vendor_amd]
    jmp  .row_vendor
.row_intel:
    lea  rdi, [rel smp_vendor_intel]
.row_vendor:
    call serial_string
    mov  eax, [rel smp_topology_leaf]
    cmp  eax, 0x1F
    je   .row_leaf_1f
    cmp  eax, 0x0B
    je   .row_leaf_0b
    lea  rdi, [rel str_portability_leaf_amd]
    jmp  .row_leaf
.row_leaf_1f:
    lea  rdi, [rel str_portability_leaf_1f]
    jmp  .row_leaf
.row_leaf_0b:
    lea  rdi, [rel str_portability_leaf_0b]
.row_leaf:
    call serial_string
    lea  rdi, [rel str_portability_capacity]
    call serial_string
    mov  edi, SMP_CPU_CAPACITY
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_packages]
    call serial_string
    mov  edi, [rel smp_package_count]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_physical]
    call serial_string
    mov  edi, [rel smp_physical_core_count]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_threads]
    call serial_string
    mov  edi, [rel smp_threads_per_core]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_logical_count]
    call serial_string
    mov  edi, r12d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_online]
    call serial_string
    mov  edi, r12d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_failed]
    call serial_string
    mov  edi, [rel smp_failed_count]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_overflow]
    call serial_string
    movzx edi, byte [rel smp_topology_overflow]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string

    lea  rdi, [rel str_portability_logical]
    call serial_string
    xor  r15d, r15d
.logical_list:
    test r15d, r15d
    jz   .logical_value
    lea  rdi, [rel str_portability_comma]
    call serial_string
.logical_value:
    mov  edi, r15d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    inc  r15d
    cmp  r15d, r12d
    jb   .logical_list

    lea  rdi, [rel str_portability_workers]
    call serial_string
    xor  r15d, r15d
    xor  ebx, ebx
.worker_list:
    cmp  r15d, SMP_CPU_CAPACITY
    jae  .worker_done
    bt   r14d, r15d
    jnc  .worker_next
    test ebx, ebx
    jz   .worker_value
    lea  rdi, [rel str_portability_comma]
    call serial_string
.worker_value:
    mov  edi, r15d
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    inc  ebx
.worker_next:
    inc  r15d
    jmp  .worker_list
.worker_done:
    lea  rdi, [rel str_portability_digest]
    call serial_string
    mov  rdi, [rel usched_job_digest]
    lea  rsi, [rel smp_numbuf]
    mov  rdx, 16
    call fmt_hex
    lea  rdi, [rel smp_numbuf]
    call serial_string
    lea  rdi, [rel str_portability_crashes]
    call serial_string
    movzx edi, byte [rel boot_crashes_observed]
    lea  rsi, [rel smp_numbuf]
    call fmt_dec
    lea  rdi, [rel smp_numbuf]
    call serial_string
    call serial_newline
    lea  rdi, [rel str_topology_cross_vendor_ok]
    call serial_string
    lea  rdi, [rel str_topology_smt_logical_ok]
    call serial_string
    jmp  .out
.fail:
    mov  byte [rel usched_job_active], 0
    lea  rdi, [rel str_topology_portability_fail]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; AP trampoline — copied verbatim to TRAMP_BASE (0x8000). Real mode (CS=0x0800,
; base 0x8000) -> enable PAE + load our CR3 + set EFER.LME|NXE (our PDs carry NX
; bits, so NXE is mandatory or the first data access reserved-bit #PFs) -> set
; CR0.PG|PE -> far jump straight into 64-bit long mode -> jump to smp_ap_main.
; All intra-blob refs are offset-from-start (segment base supplies 0x8000); far
; targets and the lgdt base use the absolute linear 0x8000 + offset.
; ============================================================================
%define TO(x) ((x) - ap_tramp_start)
%define TL(x) (TRAMP_BASE + (x) - ap_tramp_start)
TR_CODE64 equ 0x08
TR_DATA   equ 0x10

align 16
ap_tramp_start:
bits 16
    cli
    mov  ax, cs
    mov  ds, ax
    o32 lgdt [TO(ap_gdtr)]
    mov  eax, cr4
    or   eax, (1 << 5)                     ; CR4.PAE
    mov  cr4, eax
    mov  eax, [TO(ap_cr3)]
    mov  cr3, eax                          ; our PML4 (identity map)
    mov  ecx, 0xC0000080                   ; IA32_EFER
    rdmsr
    or   eax, (1 << 8) | (1 << 11)         ; LME | NXE
    wrmsr
    mov  eax, cr0
    or   eax, 0x80000001                   ; PG | PE
    mov  cr0, eax
    jmp  dword TR_CODE64:TL(ap_tramp_long)

bits 64
ap_tramp_long:
    mov  ax, TR_DATA
    mov  ds, ax
    mov  es, ax
    mov  ss, ax
    mov  fs, ax
    mov  gs, ax
    ; 1249: mirror the BSP's IA32_PAT (PA1 = WC) so every core maps the
    ; framebuffer with the same effective type (boot/paging fb_pat_program).
    mov  eax, 1
    cpuid
    bt   edx, 16
    jnc  .ap_no_pat
    wbinvd
    mov  ecx, 0x277
    mov  eax, 0x00070106
    mov  edx, 0x00070406
    wrmsr
.ap_no_pat:
    mov  edi, TL(ap_entry_slot)            ; abs addr of the 64-bit entry slot
    mov  rax, [rdi]
    jmp  rax

align 8
ap_gdt:
    dq 0x0000000000000000                  ; 0x00 null
    dq 0x00AF9A000000FFFF                  ; 0x08 code64 (G=1,L=1,P,DPL0,Exec/Read)
    dq 0x00CF92000000FFFF                  ; 0x10 data   (G=1,D=1,P,DPL0,R/W)
ap_gdt_end:
ap_gdtr:
    dw ap_gdt_end - ap_gdt - 1
    dd TL(ap_gdt)
ap_cr3:        dd 0                        ; patched: our PML4 (low 32 bits)
ap_entry_slot: dq 0                        ; patched: VA of smp_ap_main
ap_tramp_end:
bits 64

; ---- module data ----------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_smp 0
align 16
smp_gdt_ext_tables: times SMP_GDT_EXT_SLOTS * SMP_GDT_TABLE_SIZE db 0
align 16
smp_gdt_ext_gdtr:   times SMP_GDT_EXT_SLOTS * SMP_GDT_GDTR_SIZE db 0
align 16
smp_gdt_ext_tss:    times SMP_GDT_EXT_SLOTS * SMP_GDT_TSS_SIZE db 0
align 16
smp_gdt_percpu_ready: times SMP_CPU_CAPACITY db 0

rq_locks:           times MAXCORE db 0     ; one canonical lock per dense run queue
smp_state_lock:     db 0                   ; narrow epoch/snapshot publication lock
smp_coherence_counter_lock: db 0           ; collision-test counter only
smp_mapping_lock:   db 0                   ; serializes quiesce/mutate/invalidate
smp_load_lock:      db 0                   ; serializes one frozen load generation
align 4
smp_seed:           dd 0                   ; boot nonce (per-boot)
smp_bsp_apic:       dd 0                   ; BSP's own APIC id
smp_online_aps:     dd 0                   ; count of APs that acked bring-up
smpwork_online_mask: dd 0                  ; exact dense logical AP membership
smp_msr_req_epoch:  dd 0                    ; RCQ-27 stage P: per-CPU MSR apply request
smp_msr_req_msr:    dd 0
smp_msr_req_value:  dd 0
smp_msr_req_enable: dd 0
smp_msr_ok_mask:    dd 0
smp_msr_fail_mask:  dd 0
smp_msr_req_open:   db 0
cpu_msr_epoch:      times MAXCORE dd 0
smp_msr_req_rd_epoch: dd 0                  ; RCQ-27 IDLEPROBE: per-CPU MSR read request
smp_msr_req_rd_msr: dd 0
smp_msr_req_rd_ack: dd 0
smp_msr_req_rd_open: db 0
smp_msr_req_rd_type: times MAXCORE db 0     ; CPUID.1AH:EAX[31:24] per CPU
align 8
smp_msr_req_rd_val: times MAXCORE dq 0      ; RDMSR value per CPU (0 when none read)
smp_msr_req_rd_c5:  times MAXCORE dd 0      ; CPUID.05H:EDX per CPU
smp_msr_req_rd_cpu_epoch: times MAXCORE dd 0
smp_configured_count: dd 0                 ; bounded supported firmware CPUs
smp_enabled_count:    dd 0                 ; enabled unique MADT processors
smp_discovered_count: dd 0                 ; enabled unique dense logical rows
smp_topology_online:  dd 0                 ; BSP + online APs
smp_failed_count:     dd 0                 ; bounded start/local-state failures
smp_late_ap_mask:     dd 0                 ; FAILED rows whose AP arrived after timeout
smp_late_ap_count:    dd 0                 ; one per late row (raw, never repaired)
smp_duplicate_count:  dd 0                 ; ignored duplicate firmware identities
smp_topology_leaf:    dd 0                 ; selected architectural CPUID leaf
smp_package_count:    dd 0
smp_physical_core_count: dd 0
smp_threads_per_core: dd 0
smp_lapic_mode:       db 0                 ; 0=xAPIC MMIO, 1=x2APIC MSR
smp_cpu_vendor:       db SMP_VENDOR_UNKNOWN
smp_placement_valid:  db 0
smp_topology_exact:   db 0
smp_topology_overflow: db 0
smp_topology_fixture_ok: db 0
smp_core_count:     dd 0                   ; total cores with a task (>=1)
smp_task_sum:       dd 0                   ; sum of per-core task counts
smp_fault_request_mask: dd 0               ; APs armed for the current barrier
smp_fault_entered_mask: dd 0               ; handlers that reached CPU-local recovery
smp_fault_done_mask:    dd 0               ; AP tasks that resumed after iretq
smp_fault_ready_mask:   dd 0               ; AP tasks that observed request clear
smp_fault_epoch:        dd 0
smp_fault_release_epoch: dd 0
smp_faults_last_contained: dd 0
smp_fault_isolated:     db 0
align 4
smpwork_challenge:       dd 0              ; BSP-published challenge (LOCK: smp_state_lock)
smpwork_requested_epoch: dd 0              ; monotonic epoch (LOCK: smp_state_lock)
smpwork_expected_workers: dd 0             ; stable post-bring-up smp_online_aps count
smpwork_expected_mask:    dd 0             ; frozen APIC membership for every epoch
smpwork_rt_owner_apic:   dd 0xFFFFFFFF     ; must remain the BSP xAPIC id
align 8
smpwork_async_phase: dd SMPWORK_ASYNC_IDLE
smpwork_async_result: dd 0
smpwork_async_source: dq 0
smpwork_async_principal: dq 0
smpwork_async_generation: dq 0
smpwork_async_nonce: dd 0
smpwork_async_epoch: dd 0
smpwork_async_mask: dd 0
smpwork_async_expected: dd 0
smpwork_async_start: dq 0
smpwork_async_last: dq 0
smpwork_async_deadline: dq 0
smpwork_async_expiry: dq 0
smpwork_worker_published_us: times MAXCORE dq 0
smpwork_snapshot_challenge: dd 0           ; frozen response header
smpwork_snapshot_epoch:     dd 0
smpwork_snapshot_workers:   dd 0
smpwork_rq_audit:        db 0              ; derived by smpwork_validate_live
smpwork_rt_bsp:          db 0
smpwork_boot_bsp:        db 0
smpwork_worker_class:    times MAXCORE db 0 ; queue class, APs are COMPOUNDING only
align 8
coremap_counts:     times MAXCORE dd 0     ; per-core task count (LOCK: rq_locks[logical])
core_compute:       times MAXCORE dd 0     ; per-core crc32(apic^seed)
run_queue_per_core: times MAXCORE dq 0     ; runnable fn VA (LOCK: rq_locks[logical])
smpwork_worker_epoch: times MAXCORE dd 0   ; proof epoch (LOCK: rq_locks[logical])
smpwork_worker_token: times MAXCORE dd 0   ; proof token (LOCK: rq_locks[logical])
align 8
smpwork_worker_runs: times MAXCORE dq 0    ; proof runs (LOCK: rq_locks[logical])
smpwork_live_runs:   times MAXCORE dq 0    ; AP-owner-only common-path quantum count
smpwork_snapshot_worker_epoch: times MAXCORE dd 0 ; immutable formatter row set
smpwork_snapshot_worker_token: times MAXCORE dd 0
align 8
smpwork_snapshot_worker_runs: times MAXCORE dq 0
ap_stacks:          times MAXCORE dq 0     ; per-core stack tops (preallocated)
cpu_apic_id:        times MAXCORE dd 0xFFFFFFFF
cpu_uid:            times MAXCORE dd 0xFFFFFFFF
cpu_package:        times MAXCORE dd 0xFFFFFFFF
cpu_core:           times MAXCORE dd 0xFFFFFFFF
cpu_thread:         times MAXCORE dd 0xFFFFFFFF
cpu_core_type:      times MAXCORE db 0       ; raw Intel CPUID.1AH type; 0 unknown
cpu_placement_rank: times MAXCORE dd 0xFFFFFFFF
cpu_state:          times MAXCORE db CPU_STATE_DISCOVERED
cpu_timer_ready:    times MAXCORE db 0
cpu_runq_ready:     times MAXCORE db 0
align 4
cpu_current_slot:   times MAXCORE dd 0xFFFFFFFF
cpu_fault_expect:   times MAXCORE db 0
align 8
cpu_fault_recover:  times MAXCORE dq 0
; SMPSTAT faults= is this count, armed self-test #GPs only (smp_fault_gp_isr),
; two per AP each boot. An unarmed fault forwards to isr_stub_13 and shows as
; summary crashes=, never here.
cpu_fault_count:    times MAXCORE dd 0
cpu_coherence_epoch: times MAXCORE dd 0
cpu_tlb_epoch:      times MAXCORE dd 0
cpu_irq_depth:      times MAXCORE db 0
align 8
cpu_mapping_observed: times MAXCORE dq 0
cpu_irq_count:      times MAXCORE dq 0
cpu_preempt_count:  times MAXCORE dq 0
cpu_resched_count:  times MAXCORE dq 0
cpu_idle_wake_count: times MAXCORE dq 0
cpu_load_busy_ticks: times MAXCORE dq 0     ; timer samples inside shared scheduler
cpu_context_switch_count: times MAXCORE dq 0
cpu_migration_count: times MAXCORE dq 0
cpu_last_progress_tsc: times MAXCORE dq 0

; Stable load snapshot: baseline counters are private to capture; snapshot rows
; remain immutable until the next CHIP/HEALTH generation is published.
smp_load_base_busy:       times MAXCORE dq 0
smp_load_base_irq:        times MAXCORE dq 0
smp_load_base_preempt:    times MAXCORE dq 0
smp_load_base_ctx:        times MAXCORE dq 0
smp_load_base_migration:  times MAXCORE dq 0
smp_load_base_steal_in:   times MAXCORE dd 0
smp_load_base_steal_out:  times MAXCORE dd 0
align 8
smp_load_snapshot_irq:          times MAXCORE dq 0
smp_load_snapshot_preempt:      times MAXCORE dq 0
smp_load_snapshot_ctx:          times MAXCORE dq 0
smp_load_snapshot_migration:    times MAXCORE dq 0
smp_load_snapshot_progress_age: times MAXCORE dq 0
smp_load_snapshot_load:         times MAXCORE dd 0
smp_load_snapshot_runq:         times MAXCORE dd 0
smp_load_snapshot_steal_in:     times MAXCORE dd 0
smp_load_snapshot_steal_out:    times MAXCORE dd 0
smp_load_snapshot_faults:       times MAXCORE dd 0
smp_load_snapshot_current:      times MAXCORE db 0
smp_load_snapshot_health:       times MAXCORE db 0
align 8
smp_load_snapshot_end_tsc: dq 0
smp_load_snapshot_last_progress_ms: dq 0
smp_load_snapshot_seq: dd 0
smp_load_snapshot_ms: dd 0
smp_load_snapshot_logical: dd 0
smp_load_snapshot_sum: dd 0
smp_load_snapshot_mean: dd 0
smp_load_snapshot_min: dd 0
smp_load_snapshot_max: dd 0
smp_load_snapshot_runq_total: dd 0
smp_load_snapshot_runq_max: dd 0
smp_load_snapshot_imbalance: dd 0
smp_load_snapshot_busiest: dd 0
smp_load_snapshot_healthy: dd 0
smp_load_snapshot_stalled: dd 0

; Task1330j1 owner-local APERF/MPERF challenge/ack state.  Worker rows are
; written only by their owning logical CPU.  The load lock serializes first-
; edge baselines and immutable published rows with the existing LOAD snapshot.
smp_freq_request_epoch: dd 0
smp_freq_required_mask: dd 0
smp_freq_ack_mask: dd 0
smp_freq_worker_epoch: times MAXCORE dd 0
smp_freq_worker_base: times MAXCORE dd 0
smp_freq_worker_capable: times MAXCORE db 0
smp_freq_worker_source: times MAXCORE db 0
align 8
smp_freq_worker_aperf: times MAXCORE dq 0
smp_freq_worker_mperf: times MAXCORE dq 0
smp_freq_base_aperf: times MAXCORE dq 0
smp_freq_base_mperf: times MAXCORE dq 0
smp_freq_base_mhz: times MAXCORE dd 0
smp_freq_base_capable: times MAXCORE db 0
smp_freq_base_source: times MAXCORE db 0
align 8
smp_freq_snapshot_aperf: times MAXCORE dq 0
smp_freq_snapshot_mperf: times MAXCORE dq 0
smp_freq_snapshot_frequency_cpu: times MAXCORE dq 0
smp_freq_snapshot_effective: times MAXCORE dq 0
smp_freq_snapshot_ratio_cpu: times MAXCORE dq 0
smp_freq_snapshot_state: times MAXCORE db 0
align 8
smp_freq_snapshot_aperf_total: dq 0
smp_freq_snapshot_mperf_total: dq 0
smp_freq_snapshot_frequency: dq 0
smp_freq_snapshot_effective_total: dq 0
smp_freq_snapshot_effective_mean: dq 0
smp_freq_snapshot_min: dq 0
smp_freq_snapshot_max: dq 0
smp_freq_snapshot_ratio: dq 0
smp_freq_snapshot_weighted_num: dq 0
smp_freq_snapshot_active_mperf: dq 0
smp_freq_snapshot_us: dd 0
smp_freq_snapshot_capable: dd 0
smp_freq_snapshot_measured: dd 0
smp_freq_snapshot_idle: dd 0
smp_freq_snapshot_active: dd 0
smp_coherence_epoch: dd 0
smp_coherence_ack_mask: dd 0
smp_coherence_expected: dd 0
smp_coherence_actual: dd 0
smp_coherence_double_run: dd 0
smp_coherence_lost: dd 0
smp_coherence_ack_missing: dd 0
align 8
smp_coherence_counter: dq 0
smp_mapping_target: dq 0
smp_mapping_probe: dq 0x1330F00DC0DE0001
smp_mapping_expected: dq 0
smp_mapping_owner: dd 0
smp_mapping_required_mask: dd 0
smp_quiesce_ack_mask: dd 0
smp_tlb_ack_mask: dd 0
smp_tlb_epoch: dd 0
smp_release_epoch: dd 0
smp_tlb_requested: dd 0
smp_tlb_acked: dd 0
smp_stale_mapping: dd 0
align 8
smp_irq_entries: dq 0
smp_irq_eois: dq 0
smp_irq_duplicate_eoi: dd 0
smp_irq_ownership_faults: dd 0
smp_timer_irq0_before:     dq 0
smp_timer_preempt0_before: dq 0
smp_timer_post_dcr:        dd 0
smp_timer_post_lvt:        dd 0
smp_timer_post_icr:        dd 0
smp_timer_post_current:    dd 0
smp_timer_restore_seq:     dd 0
smp_timer_initial_count:   dd SMP_TIMER_INITIAL
smp_timer_rearm_required_mask: dd 1
smp_timer_rearm_ack_mask:  dd 1
align 8
smp_bsp_hlt_enter:  dq 0                    ; RCQ-27 B1: BSP idle-loop residency
smp_bsp_hlt_tsc:    dq 0
smp_bsp_hlt_count:  dq 0
smp_bsp_tick_kat_count: dq 0                ; RC power I2: BSP ticks seen in the 50 ms handover KAT
smp_bsp_tick_lease_fallbacks: dd 0          ; restores whose readback kept timer_ticks on the PIT
smp_idle_hint:      dd -1                   ; RCQ-27 L2: MWAIT hint this boot, -1 = hlt (default)
smp_idle_io_base:   dd 0                    ; RCQ-27 L1: AMD C-state IO base, 0 = MWAIT rows
align 8
smp_idle_irq_refusals: dq 0                 ; deep entry refused inside an interrupt frame
smp_idle_mwait_count: times MAXCORE dq 0    ; per-CPU MWAIT entries
smp_idle_hlt_count: times MAXCORE dq 0      ; RCQ-12: per-CPU idle HLT entries (smp_idle_enter)
smp_idle_cpu_edx5:  times MAXCORE dd 0      ; per-CPU CPUID 05H:EDX (sub-state counts)
smp_idle_cpu_state: times MAXCORE db 0      ; SMP_IDLE_CPU_* (0 = not checked yet)
smp_idle_tick_stretched: times MAXCORE db 0 ; RC power I1: 1 = this AP's tick is stretched (own CPU only)
align 64
smp_idle_lines:     times MAXCORE * 64 db 0 ; per-CPU MONITOR lines; nothing writes them
smp_bsp_tick_calibrated: db 0
smp_bsp_tick_owner:     db 0               ; RC power I2: 1 = the BSP LAPIC tick owns timer_ticks
smp_bsp_tick_leased:    db 0               ; 1 = handed to the PIT for a PMOD lease
smp_bsp_tick_reason:    db 0xFF            ; SMP_BSP_TICK_R_* of the handover (0xFF = not run)
smp_timer_restore_ok:      db 0
smp_numbuf:         times 24 db 0
; RCQ-12 track 2 (smp_par_for). The claim and done words are cross-CPU,
; lock-free; the descriptor is written only by the BSP between generations.
%ifdef PAOS_SMP_PF_DISARM
SMP_PF_DISARM_INIT equ 1
%else
SMP_PF_DISARM_INIT equ 0
%endif
align 64
smp_pf_claim:       dq 0                    ; gen<<32 | next chunk index
align 64
smp_pf_done:        dq 0                    ; gen<<32 | completed chunks
smp_pf_seen_mask:   dq 0                    ; AP rows checked in to this generation's lobby
smp_pf_desc:        times SMP_PF_CTX_SZ db 0 ; the lane's copy of the caller ctx
smp_pf_body:        dd 0
smp_pf_n:           dd 0
smp_pf_gen:         dd 0                    ; BSP-private generation counter
smp_pf_active:      db 0                    ; AP idle gate: spin, not halt, while live
smp_pf_disarm:      db SMP_PF_DISARM_INIT   ; 1 = APs never claim (red-first control)
smp_pf_stalled:     db 0                    ; a timed-out generation still owes completions
align 8
smp_pf_runs:        dq 0
smp_pf_serial_runs: dq 0
smp_pf_timeouts:    dq 0
smp_pf_lobby_timeouts: dq 0
smp_pf_open_observation: times 4 dq 0      ; BSP snapshot at claim-open decision
cpu_pf_matmul_units: times MAXCORE dq 0    ; scalar MACs, exact native inference accounting
cpu_pf_chunks:      times MAXCORE dq 0      ; per-CPU chunks run (SMPSTAT V2 CPU chunks=)
cpu_pf_busy_tsc:    times MAXCORE dq 0      ; per-CPU TSC ticks in chunk bodies (busy_tsc=)

align 4
smp_madt_fixture:
    db 0, 8, 10, 0
    dd 1                                  ; enabled BSP-like Local APIC
    db 0, 8, 11, 2
    dd 0                                  ; disabled: must not be discovered
    db 0, 8, 12, 4
    dd 1                                  ; sparse enabled Local APIC
    db 0, 8, 13, 4
    dd 1                                  ; duplicate enabled APIC: ignored
    db 9, 16
    dw 0
    dd 0x00000123                         ; full >8-bit x2APIC identity
    dd 1
    dd 77
smp_madt_fixture_end:
%endmacro
WDATA_DEFER WDATA_smp
; RCQ-12 track 2 option A: smp_pf_bench's fixed private scratch (zero-fill tail).
%macro WDATA_smp_pf_bench_bss 0
alignb 64
smp_pf_bench_ref:   resb SMP_PF_BENCH_LEN
smp_pf_bench_dst:   resb SMP_PF_BENCH_LEN
smp_pf_bench_seq:   resd 1
alignb 8
smp_pf_bench_observation: resq 10          ; read-only to command formatter
%endmacro
WDATA_BSS_DEFER WDATA_smp_pf_bench_bss

str_seed_pre:    db "[PAOS64] P2 smp: smp.seed=0x", 0
str_core_pre:    db "[PAOS64] P2 smp.core: apic=", 0
str_core_mid:    db " compute=0x", 0
str_cpuid_pre:   db "[PAOS64] P2 smp: smp.cpuid_cores=", 0
%ifdef PAOS_HP_SMP_TRIAL_APS
str_smp_hp_trial: db "[PAOS64] P2 smp: HP host-SMP trial (HP EliteDesk 705 G5 SMBIOS identity, PAOS_HP_SMP_TRIAL_APS): admitted APs=", 0
str_smp_hp_trial_fw: db " firmware CPUs=", 0
str_smp_hp_trial_tail: db " [smp.hp_trial] aps=", 0
str_smp_hp_trial_reason: db " reason=hp-trial", 13, 10, 0
align 4
smp_stk_limit:      dd 0                 ; exclusive dense-row bound for AP preparation
smp_hp_trial_aps:   dd 0                 ; APs admitted by the HP trial build
times (SMP_CPU_CAPACITY == 32) - 1 db 0  ; 31 means every row only while capacity is 32
%endif
str_ap_online:   db "[PAOS64] P2 smp: AP came online (INIT-SIPI-SIPI ack) [smp.ap.online]", 13, 10, 0
str_compute_mk:  db "[PAOS64] P2 smp: per-core computed values emitted [smp.core.compute]", 13, 10, 0
str_coremap_pre: db "[PAOS64] P2 smp: COREMAP:", 0
str_map_core:    db " core_", 0
str_map_colon:   db ": ", 0
str_map_tail:    db " [smp.coremap.real]", 0
str_coremap_run_pre: db "[PAOS64] P2 smp: COREMAP RUNNING:", 0
str_faultc_all:  db "[PAOS64] P2 smp: concurrent CPU-local faults contained [smp.ap.fault_contained]", 13, 10, 0
str_work_pre:     db "[PAOS64] P2 smp: SMPWORK nonce=0x", 0
str_work_epoch:   db " epoch=", 0
str_work_workers: db " workers=", 0
str_work_core:    db " core=", 0
str_work_token:   db ",token=0x", 0
str_work_runs:    db ",runs=", 0
str_work_rq:      db " rq_audit=", 0
str_work_rt:      db " rt_bsp=", 0
str_work_boot:    db " boot_bsp=", 0
str_work_marker:  db " [smp.work.multicore.ok]", 0
str_topology_exact_ok: db "[PAOS64] SMP topology: dense MADT + per-CPU state selftest PASS [smp.topology.exact.ok]", 13, 10, 0
smp_vendor_intel: db "GenuineIntel", 0
smp_vendor_amd: db "AuthenticAMD", 0
smp_vendor_unknown: db "Unknown", 0
smpstat_v2_prefix: db "SMPSTAT_V2 nonce=", 0
smpstat_v2_summary: db " view=summary configured=", 0
smpstat_v2_enabled: db " enabled=", 0
smpstat_v2_discovered: db " discovered=", 0
smpstat_v2_online: db " online=", 0
smpstat_v2_failed: db " failed=", 0
smpstat_v2_vendor: db " vendor=", 0
smpstat_v2_capacity: db " capacity=", 0
smpstat_v2_packages: db " packages=", 0
smpstat_v2_physical: db " physical_cores=", 0
smpstat_v2_threads: db " threads_per_core=", 0
smpstat_v2_logical: db " logical_cpus=", 0
smpstat_v2_overflow: db " overflow=", 0
smpstat_v2_leaf_1f: db " topology_leaf=0x0000001f", 0
smpstat_v2_leaf_0b: db " topology_leaf=0x0000000b", 0
smpstat_v2_leaf_amd: db " topology_leaf=0x8000001e", 0
smpstat_v2_leaf_unknown: db " topology_leaf=unknown", 0
smpstat_v2_bsp: db " bsp=", 0
smpstat_v2_xapic: db " lapic=xapic scheduler=unified resched_ipi=", 0
smpstat_v2_x2apic: db " lapic=x2apic scheduler=unified resched_ipi=", 0
smpstat_v2_tlb_epoch: db " tlb_epoch=", 0
smpstat_v2_crashes: db " crashes=", 0
smpstat_v2_coherence: db " view=coherence lock_algo=canonical big_kernel_lock=0 expected=", 0
smpstat_v2_actual: db " actual=", 0
smpstat_v2_double: db " double_run=", 0
smpstat_v2_lost: db " lost=", 0
smpstat_v2_ack_missing: db " ack_missing=", 0
smpstat_v2_fault_isolated: db " fault_isolated=", 0
smpstat_v2_tlb_requested: db " tlb_requested=", 0
smpstat_v2_tlb_acked: db " tlb_acked=", 0
smpstat_v2_stale: db " stale_mapping=", 0
smpstat_v2_irq_entries: db " irq_entries=", 0
smpstat_v2_irq_eois: db " irq_eois=", 0
smpstat_v2_duplicate_eoi: db " duplicate_eoi=", 0
smpstat_v2_ownership_faults: db " ownership_faults=", 0
smpstat_v2_unexpected_irq: db " unexpected_irq=", 0
smpstat_v2_unexpected_vector: db " unexpected_vector=", 0
smpstat_v2_cpu: db " view=cpu logical=", 0
smpstat_v2_apic: db " apic=", 0
smpstat_v2_uid: db " uid=", 0
smpstat_v2_package: db " package=", 0
smpstat_v2_core: db " core=", 0
smpstat_v2_thread: db " thread=", 0
smpstat_v2_state_bsp: db " state=bsp", 0
smpstat_v2_state_online: db " state=online", 0
smpstat_v2_state_failed: db " state=failed", 0
smpstat_v2_state_discovered: db " state=discovered", 0
smpstat_v2_state_pending: db " state=pending", 0
smpstat_v2_late: db " late=", 0
smpstat_v2_stack: db " stack=", 0
smpstat_v2_tss: db " tss=", 0
smpstat_v2_ist: db " ist=", 0
smpstat_v2_timer: db " timer=", 0
smpstat_v2_runq: db " runq=", 0
smpstat_v2_current: db " current=unified preempt=", 0
smpstat_v2_steal_in: db " steal_in=", 0
smpstat_v2_steal_out: db " steal_out=", 0
smpstat_v2_irq: db " irq=", 0
smpstat_v2_lapic_lvt: db " lapic_lvt=", 0
smpstat_v2_lapic_dcr: db " lapic_dcr=", 0
smpstat_v2_lapic_icr: db " lapic_icr=", 0
smpstat_v2_lapic_rearm_required: db " lapic_rearm_required=", 0
smpstat_v2_lapic_rearm_acked: db " lapic_rearm_acked=", 0
smpstat_v2_faults: db " faults=", 0
smpstat_v2_halts: db " halts=", 0
smpstat_v2_chunks: db " chunks=", 0
smpstat_v2_busy_tsc: db " busy_tsc=", 0
smpstat_v2_core_type: db " core_type=", 0
smpstat_sec_header: db " sec_scope=cpu_init sec_policy=incomplete sec_ready=", 0
smpstat_sec_vendor: db " sec_vendor=", 0
smpstat_sec_hv: db " sec_hv=", 0
smpstat_sec_sig: db " sec_sig=", 0
smpstat_sec_rev_valid: db " sec_rev_valid=", 0
smpstat_sec_rev: db " sec_rev=", 0
smpstat_sec_caps: db " sec_caps=", 0
smpstat_sec_mask: db " sec_ctrl_mask=", 0
smpstat_sec_ctrl_valid: db " sec_ctrl_valid=", 0
smpstat_sec_ctrl: db " sec_ctrl=", 0
smpstat_sec_arch_valid: db " sec_arch_valid=", 0
smpstat_sec_arch: db " sec_arch=", 0
align 4, db 0
smpstat_sec_fields:
    dd smpstat_sec_vendor - smpstat_sec_fields, CSS_VENDOR, 4
    dd smpstat_sec_hv - smpstat_sec_fields, CSS_HV, 4
    dd smpstat_sec_sig - smpstat_sec_fields, CSS_SIG, 4
    dd smpstat_sec_rev_valid - smpstat_sec_fields, CSS_REV_VALID, 4
    dd smpstat_sec_rev - smpstat_sec_fields, CSS_REV, 4
    dd smpstat_sec_caps - smpstat_sec_fields, CSS_CAPS, 8
    dd smpstat_sec_mask - smpstat_sec_fields, CSS_MASK, 8
    dd smpstat_sec_ctrl_valid - smpstat_sec_fields, CSS_CTRL_VALID, 4
    dd smpstat_sec_ctrl - smpstat_sec_fields, CSS_CTRL, 8
    dd smpstat_sec_arch_valid - smpstat_sec_fields, CSS_ARCH_VALID, 4
    dd smpstat_sec_arch - smpstat_sec_fields, CSS_ARCH, 8
smpstat_uc_cost_v: db " uc_cost_v=", 0
smpstat_uc_cost_cpu: db " uc_cost_cpu=", 0
smpstat_uc_cost_profile: db " uc_cost_profile=", 0
smpstat_uc_cost_op: db " uc_cost_op=", 0
smpstat_uc_cost_valid: db " uc_cost_valid=", 0
smpstat_uc_cost_start: db " uc_cost_start=", 0
smpstat_uc_cost_end: db " uc_cost_end=", 0
smpstat_uc_bsp_header: db " uc_scope=early_bsp uc_ready=", 0
smpstat_uc_header: db " uc_scope=early_ap uc_ready=", 0
smpstat_uc_result32: db " uc_result32=", 0
smpstat_uc_owner: db " uc_owner=", 0
smpstat_uc_owner_valid: db " uc_owner_valid=", 0
smpstat_uc_load_match: db " uc_load_match=", 0
smpstat_uc_post_valid: db " uc_post_valid=", 0
smpstat_uc_pid: db " uc_pid=", 0
smpstat_uc_selected: db " uc_selected=", 0
smpstat_uc_readback: db " uc_readback=", 0
smpstat_uc_io_count: db " uc_io_count=", 0
smpstat_uc_io_failure: db " uc_io_failure=", 0
smpstat_uc_pre_vendor: db " uc_pre_vendor=", 0
smpstat_uc_pre_hv: db " uc_pre_hv=", 0
smpstat_uc_pre_sig: db " uc_pre_sig=", 0
smpstat_uc_pre_rev_valid: db " uc_pre_rev_valid=", 0
smpstat_uc_pre_rev: db " uc_pre_rev=", 0
smpstat_uc_pre_caps: db " uc_pre_caps=", 0
smpstat_uc_pre_ctrl_mask: db " uc_pre_ctrl_mask=", 0
smpstat_uc_pre_ctrl_valid: db " uc_pre_ctrl_valid=", 0
smpstat_uc_pre_ctrl: db " uc_pre_ctrl=", 0
smpstat_uc_pre_arch_valid: db " uc_pre_arch_valid=", 0
smpstat_uc_pre_arch: db " uc_pre_arch=", 0
smpstat_uc_post_vendor: db " uc_post_vendor=", 0
smpstat_uc_post_hv: db " uc_post_hv=", 0
smpstat_uc_post_sig: db " uc_post_sig=", 0
smpstat_uc_post_rev_valid: db " uc_post_rev_valid=", 0
smpstat_uc_post_rev: db " uc_post_rev=", 0
smpstat_uc_post_caps: db " uc_post_caps=", 0
smpstat_uc_post_ctrl_mask: db " uc_post_ctrl_mask=", 0
smpstat_uc_post_ctrl_valid: db " uc_post_ctrl_valid=", 0
smpstat_uc_post_ctrl: db " uc_post_ctrl=", 0
smpstat_uc_post_arch_valid: db " uc_post_arch_valid=", 0
smpstat_uc_post_arch: db " uc_post_arch=", 0
align 4, db 0
smpstat_uc_fields:
    dd smpstat_uc_result32 - smpstat_uc_fields, MCP_RESULT, 4, 0
    dd smpstat_uc_owner - smpstat_uc_fields, MCP_ACTUAL_APIC, 4, 0
    dd smpstat_uc_owner_valid - smpstat_uc_fields, MCP_OWNER_VALID, 4, 0
    dd smpstat_uc_load_match - smpstat_uc_fields, MCP_LOAD_MATCH, 4, 0
    dd smpstat_uc_post_valid - smpstat_uc_fields, MCP_POST_VALID, 4, 0
    dd smpstat_uc_pid - smpstat_uc_fields, MCP_PID, 4, 0
    dd smpstat_uc_selected - smpstat_uc_fields, MCP_RECORD + MCS_REV, 4, 0
    dd smpstat_uc_readback - smpstat_uc_fields, MCP_RECORD + MCS_AFTER, 4, 0
    dd smpstat_uc_io_count - smpstat_uc_fields, MCP_IO + CIO_COUNT, 4, 0
    dd smpstat_uc_io_failure - smpstat_uc_fields, MCP_IO + CIO_FAILURE, 4, 0
    dd smpstat_uc_pre_vendor - smpstat_uc_fields, MCP_BEFORE + CSS_VENDOR, 4, 0
    dd smpstat_uc_pre_hv - smpstat_uc_fields, MCP_BEFORE + CSS_HV, 4, 0
    dd smpstat_uc_pre_sig - smpstat_uc_fields, MCP_BEFORE + CSS_SIG, 4, 0
    dd smpstat_uc_pre_rev_valid - smpstat_uc_fields, MCP_BEFORE + CSS_REV_VALID, 4, 0
    dd smpstat_uc_pre_rev - smpstat_uc_fields, MCP_BEFORE + CSS_REV, 4, 0
    dd smpstat_uc_pre_caps - smpstat_uc_fields, MCP_BEFORE + CSS_CAPS, 8, 0
    dd smpstat_uc_pre_ctrl_mask - smpstat_uc_fields, MCP_BEFORE + CSS_MASK, 8, 0
    dd smpstat_uc_pre_ctrl_valid - smpstat_uc_fields, MCP_BEFORE + CSS_CTRL_VALID, 4, 0
    dd smpstat_uc_pre_ctrl - smpstat_uc_fields, MCP_BEFORE + CSS_CTRL, 8, 0
    dd smpstat_uc_pre_arch_valid - smpstat_uc_fields, MCP_BEFORE + CSS_ARCH_VALID, 4, 0
    dd smpstat_uc_pre_arch - smpstat_uc_fields, MCP_BEFORE + CSS_ARCH, 8, 0
    dd smpstat_uc_post_vendor - smpstat_uc_fields, MCP_AFTER + CSS_VENDOR, 4, 0
    dd smpstat_uc_post_hv - smpstat_uc_fields, MCP_AFTER + CSS_HV, 4, 0
    dd smpstat_uc_post_sig - smpstat_uc_fields, MCP_AFTER + CSS_SIG, 4, 0
    dd smpstat_uc_post_rev_valid - smpstat_uc_fields, MCP_AFTER + CSS_REV_VALID, 4, 0
    dd smpstat_uc_post_rev - smpstat_uc_fields, MCP_AFTER + CSS_REV, 4, 0
    dd smpstat_uc_post_caps - smpstat_uc_fields, MCP_AFTER + CSS_CAPS, 8, 0
    dd smpstat_uc_post_ctrl_mask - smpstat_uc_fields, MCP_AFTER + CSS_MASK, 8, 0
    dd smpstat_uc_post_ctrl_valid - smpstat_uc_fields, MCP_AFTER + CSS_CTRL_VALID, 4, 0
    dd smpstat_uc_post_ctrl - smpstat_uc_fields, MCP_AFTER + CSS_CTRL, 8, 0
    dd smpstat_uc_post_arch_valid - smpstat_uc_fields, MCP_AFTER + CSS_ARCH_VALID, 4, 0
    dd smpstat_uc_post_arch - smpstat_uc_fields, MCP_AFTER + CSS_ARCH, 8, 0

    dd smpstat_uc_cost_v - smpstat_uc_fields, MCP_COST_VERSION, 4, 0
    dd smpstat_uc_cost_cpu - smpstat_uc_fields, MCP_COST_CPU, 4, 0
    dd smpstat_uc_cost_profile - smpstat_uc_fields, MCP_COST_PROFILE, 4, 0
    dd smpstat_uc_cost_op - smpstat_uc_fields, MCP_COST_OP, 4, 0
    dd smpstat_uc_cost_valid - smpstat_uc_fields, MCP_COST_VALID, 4, 0
    dd smpstat_uc_cost_start - smpstat_uc_fields, MCP_COST_START, 8, 0
    dd smpstat_uc_cost_end - smpstat_uc_fields, MCP_COST_END, 8, 0

smpstat_uc_bsp_fields:
    dd smpstat_uc_result32 - smpstat_uc_fields, MCB_RESULT, 4, 1
    dd smpstat_uc_owner - smpstat_uc_fields, MCBC_OWNER, 4, 0
    dd smpstat_uc_owner_valid - smpstat_uc_fields, MCBC_OWNER_VALID, 4, 0
    dd smpstat_uc_load_match - smpstat_uc_fields, MCBC_LOAD_MATCH, 4, 0
    dd smpstat_uc_post_valid - smpstat_uc_fields, MCBC_POST_VALID, 4, 0
    dd smpstat_uc_pid - smpstat_uc_fields, MCB_PID, 4, 1
    dd smpstat_uc_selected - smpstat_uc_fields, MCB_RECORD + MCS_REV, 4, 1
    dd smpstat_uc_readback - smpstat_uc_fields, MCB_RECORD + MCS_AFTER, 4, 1
    dd smpstat_uc_io_count - smpstat_uc_fields, MCBC_IO + CIO_COUNT, 4, 0
    dd smpstat_uc_io_failure - smpstat_uc_fields, MCBC_IO + CIO_FAILURE, 4, 0
    dd smpstat_uc_pre_vendor - smpstat_uc_fields, MCB_SAMPLE + CSS_VENDOR, 4, 1
    dd smpstat_uc_pre_hv - smpstat_uc_fields, MCB_SAMPLE + CSS_HV, 4, 1
    dd smpstat_uc_pre_sig - smpstat_uc_fields, MCB_SAMPLE + CSS_SIG, 4, 1
    dd smpstat_uc_pre_rev_valid - smpstat_uc_fields, MCB_SAMPLE + CSS_REV_VALID, 4, 1
    dd smpstat_uc_pre_rev - smpstat_uc_fields, MCB_SAMPLE + CSS_REV, 4, 1
    dd smpstat_uc_pre_caps - smpstat_uc_fields, MCB_SAMPLE + CSS_CAPS, 8, 1
    dd smpstat_uc_pre_ctrl_mask - smpstat_uc_fields, MCB_SAMPLE + CSS_MASK, 8, 1
    dd smpstat_uc_pre_ctrl_valid - smpstat_uc_fields, MCB_SAMPLE + CSS_CTRL_VALID, 4, 1
    dd smpstat_uc_pre_ctrl - smpstat_uc_fields, MCB_SAMPLE + CSS_CTRL, 8, 1
    dd smpstat_uc_pre_arch_valid - smpstat_uc_fields, MCB_SAMPLE + CSS_ARCH_VALID, 4, 1
    dd smpstat_uc_pre_arch - smpstat_uc_fields, MCB_SAMPLE + CSS_ARCH, 8, 1
    dd smpstat_uc_post_vendor - smpstat_uc_fields, MCBC_AFTER + CSS_VENDOR, 4, 0
    dd smpstat_uc_post_hv - smpstat_uc_fields, MCBC_AFTER + CSS_HV, 4, 0
    dd smpstat_uc_post_sig - smpstat_uc_fields, MCBC_AFTER + CSS_SIG, 4, 0
    dd smpstat_uc_post_rev_valid - smpstat_uc_fields, MCBC_AFTER + CSS_REV_VALID, 4, 0
    dd smpstat_uc_post_rev - smpstat_uc_fields, MCBC_AFTER + CSS_REV, 4, 0
    dd smpstat_uc_post_caps - smpstat_uc_fields, MCBC_AFTER + CSS_CAPS, 8, 0
    dd smpstat_uc_post_ctrl_mask - smpstat_uc_fields, MCBC_AFTER + CSS_MASK, 8, 0
    dd smpstat_uc_post_ctrl_valid - smpstat_uc_fields, MCBC_AFTER + CSS_CTRL_VALID, 4, 0
    dd smpstat_uc_post_ctrl - smpstat_uc_fields, MCBC_AFTER + CSS_CTRL, 8, 0
    dd smpstat_uc_post_arch_valid - smpstat_uc_fields, MCBC_AFTER + CSS_ARCH_VALID, 4, 0
    dd smpstat_uc_post_arch - smpstat_uc_fields, MCBC_AFTER + CSS_ARCH, 8, 0
smpstat_v2_schema: db " view=schema selectors=SUMMARY,CPU,HEALTH,LOAD,SCHEMA ai_projection=registry sample_model=stable_snapshot frequency_model=passive_aperfmperf effect=read", 0
smpstat_v2_health: db " view=health sample_seq=", 0
smpstat_v2_sample_seq: db " sample_seq=", 0
smpstat_v2_sample_ms: db " sample_ms=", 0
smpstat_v2_sample_us: db " sample_us=", 0
smpstat_v2_healthy: db " healthy=", 0
smpstat_v2_stalled: db " stalled=", 0
smpstat_v2_last_progress: db " last_progress_ms=", 0
smpstat_v2_critical: db " critical_tasks=protected", 0
smpstat_v2_load_chip: db " view=load target=chip logical=", 0
smpstat_v2_load_cpu: db " view=load target=cpu logical=", 0
smpstat_v2_load: db " load_permille=", 0
smpstat_v2_idle: db " idle_permille=", 0
smpstat_v2_load_sum: db " load_sum_permille=", 0
smpstat_v2_runq_total: db " runq_total=", 0
smpstat_v2_runq_max: db " runq_max=", 0
smpstat_v2_imbalance: db " imbalance_permille=", 0
smpstat_v2_busiest: db " busiest_logical=", 0
smpstat_v2_current_load: db " current=", 0
smpstat_v2_current_idle: db "idle", 0
smpstat_v2_current_unified: db "unified", 0
smpstat_v2_irq_delta: db " irq_delta=", 0
smpstat_v2_preempt_delta: db " preempt_delta=", 0
smpstat_v2_ctx_delta: db " ctx_switch_delta=", 0
smpstat_v2_migration_delta: db " migration_delta=", 0
smpstat_v2_steal_in_delta: db " steal_in_delta=", 0
smpstat_v2_steal_out_delta: db " steal_out_delta=", 0
smpstat_v2_progress_age: db " progress_age_ms=", 0
smpstat_v2_health_cpu: db " health=", 0
smpstat_v2_health_ok: db "ok", 0
smpstat_v2_health_stalled: db "stalled", 0
smpstat_v2_freq_capable: db " freq_capable=", 0
smpstat_v2_freq_measured: db " freq_measured=", 0
smpstat_v2_freq_idle: db " freq_idle=", 0
smpstat_v2_freq_active: db " freq_active_mhz=", 0
smpstat_v2_aperf_delta: db " aperf_delta=", 0
smpstat_v2_mperf_delta: db " mperf_delta=", 0
smpstat_v2_aperf_total: db " aperf_delta_total=", 0
smpstat_v2_mperf_total: db " mperf_delta_total=", 0
smpstat_v2_base_mhz: db " base_mhz=", 0
smpstat_v2_frequency: db " frequency=", 0
smpstat_v2_effective: db " effective_mhz=", 0
smpstat_v2_effective_total: db " effective_mhz_total=", 0
smpstat_v2_effective_mean: db " effective_mhz_mean=", 0
smpstat_v2_freq_min: db " freq_min_mhz=", 0
smpstat_v2_freq_max: db " freq_max_mhz=", 0
smpstat_v2_freq_ratio: db " freq_ratio_permille=", 0
smpstat_v2_freq_state: db " freq_state=", 0
smpstat_v2_freq_source: db " freq_source=", 0
smpstat_v2_state_measured: db "measured", 0
smpstat_v2_state_idle: db "idle", 0
smpstat_v2_state_unsupported: db "unsupported", 0
smpstat_v2_source_cpuid: db "aperfmperf_cpuid16", 0
smpstat_v2_source_platform: db "aperfmperf_platform_info", 0
smpstat_v2_source_no_base: db "aperfmperf_base_unavailable", 0
smpstat_v2_source_unsupported: db "unsupported", 0
smpstat_v2_freq_source_mixed: db " freq_source=mixed", 0
smpstat_v2_unavailable: db "unavailable", 0
smpstat_v2_temperature_unavailable: db " temperature=unavailable", 0
smpstat_v2_err_stale: db "ERR SMP stale_sample", 0
smpstat_v2_err_unavailable: db "ERR SMP unavailable", 0
str_portability_row: db "SMPTOPO_V2 vendor=", 0
str_portability_leaf_1f: db " leaf=0x0000001f", 0
str_portability_leaf_0b: db " leaf=0x0000000b", 0
str_portability_leaf_amd: db " leaf=0x8000001e", 0
str_portability_capacity: db " capacity=", 0
str_portability_packages: db " packages=", 0
str_portability_physical: db " physical_cores=", 0
str_portability_threads: db " threads_per_core=", 0
str_portability_logical_count: db " logical_cpus=", 0
str_portability_online: db " online=", 0
str_portability_failed: db " failed=", 0
str_portability_overflow: db " overflow=", 0
str_portability_logical: db " logical=", 0
str_portability_workers: db " workers=", 0
str_portability_digest: db " digest=", 0
str_portability_crashes: db " crashes=", 0
str_portability_comma: db ",", 0
str_topology_cross_vendor_ok: db "[PAOS64] SMP portability: Intel/AMD topology and scalable logical-CPU KAT PASS [smp.topology.cross_vendor.ok]", 13, 10, 0
str_topology_smt_logical_ok: db "[PAOS64] SMP portability: physical-core/SMT logical scheduling KAT PASS [smp.topology.smt.logical.ok]", 13, 10, 0
str_topology_portability_fail: db "[PAOS64] SMP portability: topology/placement/worker KAT FAIL", 13, 10, 0
str_bsp_tick_lapic: db "[power.i2] tick=lapic pit=masked", 13, 10, 0
str_bsp_tick_pit:   db "[power.i2] tick=pit reason=", 0
str_bsp_tick_kat:   db " kat=", 0
str_bsp_tick_eol:   db 13, 10, 0
