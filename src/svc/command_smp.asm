;; MODULE svc/command_smp
;; LAYER 5
;; EXPORTS smpwork_declare, smpbench_reap_tick, smpbench_clock, smpbench_reaped_total, smpbench_driven_total, smpwork_out_ready, smpwork_out_buf, smpobs_out_ready, smpobs_out_buf, smpobs_out_cur, command_smp_public_observation
;; IMPORTS boot/header, core/smp, core/sched, core/lib/fmt, core/lib/mem, core/lib/str, svc/command, svc/command_aihook, svc/command_auth, svc/command_udp, net/netdev
;; CAPS
;; OWNER saga:sched
; ============================================================================
; SMPWORK publishes a challenge/epoch and freezes a bounded 100 ms work snapshot.
; SMPWORK/SMPBENCH retain the explicit SEC-P2b bounded public diagnostic grant:
; cap=0/destr=0 is a compatibility exception, not a claim of passive reads.
; Unsigned SMPBENCH START is work, capped at 2048 units and never soak; owner
; reserve/reaping remain part of that grant. See sched_native_effect_inventory.json.
; SMPBENCH START parfor (RCQ-12 track 2 option A) runs inline under the same
; floor and caps: one fixed smp_pf_bench pass pair, no slot, no scheduler job.
; The BSP publishes a challenge through smpwork_snapshot; each AP independently
; stamps its proof slot, and this module only formats those returned slots.
; ============================================================================

SMPWORK_LEGACY_CAP      equ 768
SMPWORK_OUT_CAP         equ 1280   ; all32 lossless compact rows + header fit; UDP envelopes separately
SMPOBS_ARG_MAX          equ 96
SMPOBS_OUT_CAP          equ 2048            ; terminal CPU-unit row includes all 32 logical CPUs
SMPOBS_UNKNOWN_U32      equ 4294967295
SMPBENCH_MODE_MAX       equ 16
SMPBENCH_UNITS_MAX      equ USCHED_SCALING_MAX_UNITS ; parser ceiling; mode/unsigned limits below
SMPBENCH_UNSIGNED_UNITS_MAX equ USCHED_MAX_UNITS   ; SEC-P2b: unauthenticated remote START (2048; the HP executor's dispatch/context modes are capped there)
SMPBENCH_SLOTS          equ 32
SMPBENCH_SLOT_USED      equ 0
SMPBENCH_SLOT_MODELEN   equ 1
SMPBENCH_SLOT_STATE     equ 2               ; 0=new/unsupported, 1=accepted, 2=done
SMPBENCH_SLOT_MODECODE  equ 3               ; USCHED_MODE_*
SMPBENCH_SLOT_UNSIGNED  equ 4               ; started by an unsigned remote request
SMPBENCH_SLOT_REAPED    equ 5               ; reaped: free for START, result still readable until reused
SMPBENCH_SLOT_NONCE     equ 8
SMPBENCH_SLOT_UNITS     equ 16
SMPBENCH_SLOT_MODE      equ 24
SMPBENCH_SLOT_DIGEST    equ 48
SMPBENCH_SLOT_COMPLETED equ 56
SMPBENCH_SLOT_COREMASK  equ 60
SMPBENCH_SLOT_MIGRATIONS equ 64
SMPBENCH_SLOT_LEAKS     equ 68
SMPBENCH_SLOT_DOUBLE    equ 72
SMPBENCH_SLOT_LOST      equ 76
SMPBENCH_SLOT_PREEMPT   equ 80
SMPBENCH_SLOT_RESCHED   equ 84
SMPBENCH_SLOT_IDLEWAKE  equ 88
SMPBENCH_SLOT_DEADLINE  equ 92
SMPBENCH_SLOT_HOSTRX    equ 96
SMPBENCH_SLOT_NEXT      equ 100
SMPBENCH_SLOT_SEEN      equ 104
SMPBENCH_SLOT_TIMERMASK equ 108
SMPBENCH_SLOT_REQMASK   equ 112
SMPBENCH_SLOT_REASON    equ 116
SMPBENCH_SLOT_PMOD_DCR  equ 120
SMPBENCH_SLOT_PMOD_LVT  equ 124
SMPBENCH_SLOT_PMOD_ICR  equ 128
SMPBENCH_SLOT_PMOD_CUR  equ 132
SMPBENCH_SLOT_IRQ0_DELTA equ 136
SMPBENCH_SLOT_PREEMPT0_DELTA equ 140
SMPBENCH_SLOT_RESTORE_SEQ equ 144
SMPBENCH_SLOT_RESTORE_OK equ 148
SMPBENCH_SLOT_POST_TEST_OK equ 149
SMPBENCH_SLOT_STEALS    equ 152
SMPBENCH_SLOT_FAULTS    equ 156
SMPBENCH_SLOT_STALE     equ 160
SMPBENCH_SLOT_TSEC      equ 164             ; smpbench_clock at START, then at the terminal snapshot
SMPBENCH_SLOT_CPUUNITS  equ 168             ; 32 terminal job-local completed-unit counts
SMPBENCH_SLOT_NATIVE_START equ SMPBENCH_SLOT_CPUUNITS + 4 * USCHED_CPU_MAX
SMPBENCH_SLOT_NATIVE_END equ SMPBENCH_SLOT_NATIVE_START + 8
SMPBENCH_SLOT_NATIVE_WORK_MAX equ SMPBENCH_SLOT_NATIVE_END + 8
SMPBENCH_SLOT_NATIVE_KHZ equ SMPBENCH_SLOT_NATIVE_WORK_MAX + 8
SMPBENCH_SLOT_SIZE      equ SMPBENCH_SLOT_NATIVE_KHZ + 8
; SMPBENCH-slot-leak-dos (rc-sec/rc-srcreview 2026-10-07): slots were freed only
; by RESULT, so 32 unsigned STARTs locked SMPBENCH (and HP SMP qualification) out
; until reboot, and an accepted job that nobody polled held the scheduler's single
; job lock forever. smpbench_reap_tick (resident idle loop, once per second):
;   * frees terminal slots (done, or an unsupported mode that never ran) once
;     they are SMPBENCH_REAP_S old; the slot keeps its data (SLOT_REAPED), so
;     RESULT still answers for that nonce until a START reuses the slot;
;   * performs the RESULT an UNSIGNED client never sent: an accepted unsigned job
;     SMPBENCH_DRIVE_S old is driven/snapshotted exactly as RESULT would (bounded:
;     unsigned jobs are <= 2048 units and never soak), at most once per
;     SMPBENCH_DRIVE_EVERY_S, which releases the job lock. Owner jobs are left to
;     their owner.
; An unsigned remote START that needs a new slot is refused while free slots are
; <= SMPBENCH_RESERVE, so owner/local requests always find one.
SMPBENCH_RESERVE        equ 4
SMPBENCH_REAP_S         equ 30
SMPBENCH_DRIVE_S        equ 30
SMPBENCH_DRIVE_EVERY_S  equ 10

command_smp_public_observation:
    xor  eax, eax
    ; NONCE_ECHO is the read-only, content-bearing runtime-PMOD measurement
    ; required by 1330d.  It must reach command_dispatch without an AUTH1
    ; owner envelope; exact spelling keeps the fail-closed public-name floor.
    cmp  dword [rdi], 'NONC'
    jne  .stat
    cmp  dword [rdi + 4], 'E_EC'
    jne  .no
    cmp  word [rdi + 8], 'HO'
    jne  .no
    cmp  byte [rdi + 10], 0
    je   .yes
.stat:
    cmp  dword [rdi], 'SMPS'
    jne  .polstat
    cmp  word [rdi + 4], 'TA'
    jne  .no
    cmp  byte [rdi + 6], 'T'
    jne  .no
    cmp  byte [rdi + 7], 0
    je   .yes
.polstat:
    cmp  dword [rdi], 'SMPP'
    jne  .polvalidate
    cmp  dword [rdi + 4], 'OLST'
    jne  .polvalidate
    cmp  word [rdi + 8], 'AT'
    jne  .no
    cmp  byte [rdi + 10], 0
    je   .yes
.polvalidate:
    cmp  dword [rdi], 'SMPP'
    jne  .bench
    cmp  dword [rdi + 4], 'OLVA'
    jne  .bench
    cmp  dword [rdi + 8], 'LIDA'
    jne  .bench
    cmp  word [rdi + 12], 'TE'
    jne  .no
    cmp  byte [rdi + 14], 0
    je   .yes
.bench:
    cmp  dword [rdi], 'SMPB'
    jne  .work
    cmp  dword [rdi + 4], 'ENCH'
    jne  .no
    cmp  byte [rdi + 8], 0
    je   .yes
.work:
    cmp  dword [rdi], 'SMPW'
    jne  .no
    cmp  word [rdi + 4], 'OR'
    jne  .no
    cmp  byte [rdi + 6], 'K'
    jne  .no
    cmp  byte [rdi + 7], 0
    jne  .no
.yes:
    mov  eax, 1
.no:
    ret

smpobs_out_reset:
    lea  rax, [rel smpobs_out_buf]
    mov  [rel smpobs_out_cur], rax
    mov  byte [rel smpobs_out_ready], 0
    mov  byte [rax], 0
    ret

smpobs_put_str:
    mov  rsi, [rel smpobs_out_cur]
    lea  rdx, [rel smpobs_out_buf + SMPOBS_OUT_CAP - 1]
.copy:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel smpobs_out_cur], rsi
    ret

smpobs_put_dec:
    lea  rsi, [rel smpobs_num_buf]
    call fmt_dec
    lea  rdi, [rel smpobs_num_buf]
    mov  byte [rdi + rax], 0
    lea  rdi, [rel smpobs_num_buf]
    jmp  smpobs_put_str

smpobs_put_hex16:
    lea  rsi, [rel smpobs_num_buf]
    mov  rdx, 16
    call fmt_hex
    mov  byte [rel smpobs_num_buf + 16], 0
    lea  rdi, [rel smpobs_num_buf]
    jmp  smpobs_put_str

smpobs_arg_bounded:
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.scan:
    mov  al, [rdi + rcx]
    test al, al
    jz   .ok
    cmp  ecx, SMPOBS_ARG_MAX
    jae  .bad
    inc  ecx
    jmp  .scan
.ok:
    mov  eax, ecx
    clc
    ret
.bad:
    stc
    ret

smpobs_parse_nonce:
    xor  r8, r8
    xor  ecx, ecx
.next:
    movzx eax, byte [rdi + rcx]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    jmp  .add
.digit:
    sub  al, '0'
.add:
    shl  r8, 4
    movzx rax, al
    or   r8, rax
    inc  ecx
    cmp  ecx, 16
    jb   .next
    mov  rax, r8
    lea  rdx, [rdi + 16]
    clc
    ret
.bad:
    stc
    ret

smpobs_parse_dec:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .bad
    cmp  al, '0'
    jne  .start
    movzx eax, byte [rdi + 1]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .bad
.start:
    xor  r8, r8
    xor  ecx, ecx
.loop:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .done
    cmp  ecx, 10
    jae  .bad
    imul r8, r8, 10
    add  r8, rax
    inc  rdi
    inc  ecx
    jmp  .loop
.done:
    test ecx, ecx
    jz   .bad
    mov  rax, r8
    mov  rdx, rdi
    clc
    ret
.bad:
    stc
    ret

smpobs_stage_error:
    push rbx
    mov  rbx, rsi
    call smpobs_out_reset
    call smpobs_put_str
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    pop  rbx
    ret

smpobs_begin_stat:
    push rdi
    call smpobs_out_reset
    lea  rdi, [rel str_smpstat_prefix]
    call smpobs_put_str
    pop  rdi
    call smpobs_put_hex16
    ret

smpobs_finish_ok:
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

cmd_verb_smpstat:
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
    cmp  word [rbx + 4], 'AR'
    jne  .check_cpu
    cmp  byte [rbx + 6], 'Y'
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
    cmp  rax, MAXCORE
    jae  .range
    mov  r13, rax
    lea  rcx, [rel coremap_counts]
    cmp  dword [rcx + r13*4], 0
    je   .range
    jmp  .cpu
.check_coherence:
    cmp  dword [rbx], 'COHE'
    jne  .unknown
    cmp  dword [rbx + 4], 'RENC'
    jne  .unknown
    cmp  byte [rbx + 8], 'E'
    jne  .unknown
    cmp  byte [rbx + 9], 0
    jne  .unknown
    jmp  .coherence

.summary:
    mov  rdi, r12
    call smpobs_begin_stat
    lea  rdi, [rel str_smpstat_summary]
    call smpobs_put_str
    mov  edi, SMPOBS_UNKNOWN_U32
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_enabled]
    call smpobs_put_str
    mov  edi, SMPOBS_UNKNOWN_U32
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_discovered]
    call smpobs_put_str
    mov  edi, SMPOBS_UNKNOWN_U32
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_online]
    call smpobs_put_str
    mov  edi, [rel smp_core_count]
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_failed]
    call smpobs_put_str
    mov  edi, SMPOBS_UNKNOWN_U32
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_bsp]
    call smpobs_put_str
    mov  edi, [rel smp_bsp_apic]
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_summary_tail]
    call smpobs_put_str
    movzx edi, byte [rel boot_crashes_observed]
    call smpobs_put_dec
    mov  rsi, r15
    call smpobs_finish_ok
    jmp  .out

.cpu:
    mov  rdi, r12
    call smpobs_begin_stat
    lea  rdi, [rel str_smpstat_cpu]
    call smpobs_put_str
    mov  rdi, r13
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_apic]
    call smpobs_put_str
    mov  rdi, r13
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_topology_unknown]
    call smpobs_put_str
    mov  eax, [rel smp_bsp_apic]
    cmp  r13d, eax
    jne  .cpu_online
    lea  rdi, [rel str_smpstat_state_bsp]
    jmp  .cpu_state
.cpu_online:
    lea  rdi, [rel str_smpstat_state_online]
.cpu_state:
    call smpobs_put_str
    lea  rdi, [rel str_smpstat_cpu_local_absent]
    call smpobs_put_str
    mov  rbx, r13
    lea  rax, [rel coremap_counts]
    mov  edi, [rax + rbx*4]
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_cpu_steal_in]
    call smpobs_put_str
    lea  rax, [rel usched_steal_in]
    mov  edi, [rax + rbx*4]
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_cpu_steal_out]
    call smpobs_put_str
    lea  rax, [rel usched_steal_out]
    mov  edi, [rax + rbx*4]
    call smpobs_put_dec
    lea  rdi, [rel str_smpstat_cpu_irq_tail]
    call smpobs_put_str
    mov  rsi, r15
    call smpobs_finish_ok
    jmp  .out

.coherence:
    mov  rdi, r12
    call smpobs_begin_stat
    lea  rdi, [rel str_smpstat_coherence]
    call smpobs_put_str
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

smpbench_clear:
    cld
    lea  rdi, [rel smpbench_slots]
    xor  eax, eax
    mov  ecx, (SMPBENCH_SLOTS * SMPBENCH_SLOT_SIZE) / 8
    rep  stosq
    mov  dword [rel smpbench_used_count], 0
    mov  byte [rel usched_job_active], 0
    ret

smpbench_emit_unsupported:
    push rsi
    call smpobs_out_reset
    lea  rdi, [rel str_smpbench_prefix]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NONCE]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_unsupported]
    call smpobs_put_str
    lea  rdi, [rbx + SMPBENCH_SLOT_MODE]
    call smpobs_put_str
    pop  rsi
    jmp  smpobs_finish_ok

; START is a publication/acknowledgement boundary.  It never drives the BSP
; completion loop inline, so command/NIC service remains responsive while APs
; consume the newly active scheduler job.  RESULT owns bounded completion and
; snapshots the terminal counters below.
smpbench_emit_accepted:
    push rsi
    call smpobs_out_reset
    lea  rdi, [rel str_smpbench_prefix]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NONCE]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_accepted]
    call smpobs_put_str
    lea  rdi, [rbx + SMPBENCH_SLOT_MODE]
    call smpobs_put_str
    pop  rsi
    jmp  smpobs_finish_ok

; smpbench_parfor(RDI units, RSI rsp, RDX nonce) -> EAX 0 replied, 1 range.
;   RCQ-12 track 2 option A (admin 16:06:59). One fixed smp_pf_bench pass pair
;   (a parallel fill and copy over core/smp's private scratch, each compared
;   with its serial reference); units must be 1. The reply is final: no slot,
;   so RESULT never knows this nonce. Per-AP work is read from SMPSTAT CPU
;   chunks=/busy_tsc= before and after. While the lane still owes a timed-out
;   chunk the bench does not run and the reply is state=stalled.
smpbench_parfor:
    cmp  rdi, 1
    jne  .range
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi
    mov  r14, rdx
    call smp_pf_bench                      ; EAX match (2 = not run), ECX chunks, EDX ap, R8D par, R9D timeouts
    cmp  eax, 2
    je   .stalled
    mov  ebx, eax
    mov  r12d, ecx
    mov  r13d, edx
    push r9
    push r8
    call smpobs_out_reset
    lea  rdi, [rel str_smpbench_prefix]
    call smpobs_put_str
    mov  rdi, r14
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_pf_match]
    call smpobs_put_str
    mov  edi, ebx
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_chunks]
    call smpobs_put_str
    mov  edi, r12d
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_par]
    call smpobs_put_str
    pop  rdi
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_timeouts]
    call smpobs_put_str
    pop  rdi
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_ap]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_dec
    ; Appended V1 fields retain the existing prefix and grades. Each mask
    ; is the exact bounded-lobby decision sample, not a later SMPSTAT read.
    lea  rdi, [rel str_smpbench_pf_fill_gen]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 0]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_fill_expected]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 8]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_pf_fill_seen]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 16]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_pf_fill_expired]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 24]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_fill_ap]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 32]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_copy_gen]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 40]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_copy_expected]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 48]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_pf_copy_seen]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 56]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_pf_copy_expired]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 64]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pf_copy_ap]
    call smpobs_put_str
    mov  rdi, [rel smp_pf_bench_observation + 72]
    call smpobs_put_dec
.finish:
    mov  rsi, r15
    call smpobs_finish_ok
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    xor  eax, eax
    ret
.range:
    mov  eax, 1
    ret
.stalled:
    call smpobs_out_reset
    lea  rdi, [rel str_smpbench_prefix]
    call smpobs_put_str
    mov  rdi, r14
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_pf_stalled]
    call smpobs_put_str
    jmp  .finish

; Host RX during a job counts frames on the NIC that carried its START
; (udp_ingress_handle), through the netdev_frame_stats seam, so every backend
; counts. The old e1000e_rx_frames global missed RTL8125/RTL8126/AX88179/CDC,
; and Reatan245 SOAK30 read host_rx_delta=0 with 15 RESULT polls answered.
; Neither helper changes any register except RAX.
smpbench_host_rx_begin:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  qword [rel smpbench_host_rx_handle], 0
    mov  rbx, [rel udp_ingress_handle]
    test rbx, rbx
    jz   .out
    mov  rdi, rbx
    call netdev_frame_stats
    test eax, eax
    jnz  .out
    mov  [rel usched_job_host_rx_start], rdx
    mov  [rel smpbench_host_rx_handle], rbx
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; RAX = frames since smpbench_host_rx_begin on the same NIC; 0 when no NIC was
; bound, the NIC is unavailable now, or its counter went backwards.
smpbench_host_rx_delta:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    xor  ebx, ebx
    mov  rdi, [rel smpbench_host_rx_handle]
    test rdi, rdi
    jz   .out
    call netdev_frame_stats
    test eax, eax
    jnz  .out
    sub  rdx, [rel usched_job_host_rx_start]
    jc   .out
    mov  rbx, rdx
.out:
    mov  rax, rbx
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; Snapshot the measured job into its nonce slot so replay never aliases a later
; benchmark's globals.
smpbench_snapshot_done:
    cmp  byte [rbx + SMPBENCH_SLOT_STATE], 2
    je   .done
    call sched_unified_bench_drive
    test eax, eax
    jz   .done
    mov  rax, [rel usched_job_digest]
    mov  [rbx + SMPBENCH_SLOT_DIGEST], rax
    mov  eax, [rel usched_job_completed]
    mov  [rbx + SMPBENCH_SLOT_COMPLETED], eax
    mov  eax, [rel usched_job_core_mask]
    mov  [rbx + SMPBENCH_SLOT_COREMASK], eax
    mov  rax, [rel usched_job_native_start_tsc]
    mov  [rbx + SMPBENCH_SLOT_NATIVE_START], rax
    mov  rax, [rel usched_job_native_khz]
    mov  [rbx + SMPBENCH_SLOT_NATIVE_KHZ], rax
    mov  qword [rbx + SMPBENCH_SLOT_NATIVE_END], 0
    mov  qword [rbx + SMPBENCH_SLOT_NATIVE_WORK_MAX], 0
    xor  ecx, ecx
    lea  rdx, [rel usched_job_cpu_units]
.cpu_units:
    mov  eax, [rdx]
    mov  [rbx + SMPBENCH_SLOT_CPUUNITS + rcx*4], eax
    mov  rax, [rdx + 8]
    cmp  rax, [rbx + SMPBENCH_SLOT_NATIVE_WORK_MAX]
    jbe  .work_max_ready
    mov  [rbx + SMPBENCH_SLOT_NATIVE_WORK_MAX], rax
.work_max_ready:
    mov  rax, [rdx + 16]
    cmp  rax, [rbx + SMPBENCH_SLOT_NATIVE_END]
    jbe  .end_max_ready
    mov  [rbx + SMPBENCH_SLOT_NATIVE_END], rax
.end_max_ready:
    add  rdx, 64
    inc  ecx
    cmp  ecx, USCHED_CPU_MAX
    jb   .cpu_units
    mov  eax, [rel usched_job_migrations]
    mov  [rbx + SMPBENCH_SLOT_MIGRATIONS], eax
    mov  eax, [rel usched_job_steals]
    mov  [rbx + SMPBENCH_SLOT_STEALS], eax
    mov  eax, [rel usched_job_faults_contained]
    mov  [rbx + SMPBENCH_SLOT_FAULTS], eax
    mov  eax, [rel usched_job_stale_mapping]
    mov  [rbx + SMPBENCH_SLOT_STALE], eax
    mov  eax, [rel usched_job_state_leaks]
    mov  [rbx + SMPBENCH_SLOT_LEAKS], eax
    mov  eax, [rel usched_job_double_run]
    mov  [rbx + SMPBENCH_SLOT_DOUBLE], eax
    mov  eax, [rel usched_job_preemptions]
    mov  [rbx + SMPBENCH_SLOT_PREEMPT], eax
    mov  eax, [rel usched_job_resched_ipis]
    mov  [rbx + SMPBENCH_SLOT_RESCHED], eax
    mov  eax, [rel usched_job_idle_wakes]
    mov  [rbx + SMPBENCH_SLOT_IDLEWAKE], eax
    mov  eax, [rel usched_job_deadline_miss]
    mov  [rbx + SMPBENCH_SLOT_DEADLINE], eax
    call smpbench_host_rx_delta
    mov  [rel usched_job_host_rx_delta], rax
    mov  [rbx + SMPBENCH_SLOT_HOSTRX], eax
    ; Bind every terminal diagnostic to this nonce. Pending rows deliberately
    ; remain live, but an exact RESULT replay must not borrow a later job's
    ; claim barrier or a later PMOD call's timer-restore evidence.
    mov  eax, [rel usched_job_next]
    mov  [rbx + SMPBENCH_SLOT_NEXT], eax
    call sched_unified_seen_count
    mov  [rbx + SMPBENCH_SLOT_SEEN], eax
    mov  eax, [rel usched_job_timer_mask]
    mov  [rbx + SMPBENCH_SLOT_TIMERMASK], eax
    mov  edi, [rel usched_job_reserved]
    call smp_count_mask32
    mov  [rbx + SMPBENCH_SLOT_REQMASK], eax
    movzx eax, byte [rel usched_job_pending_reason]
    mov  [rbx + SMPBENCH_SLOT_REASON], al
    mov  eax, [rel smp_timer_post_dcr]
    mov  [rbx + SMPBENCH_SLOT_PMOD_DCR], eax
    mov  eax, [rel smp_timer_post_lvt]
    mov  [rbx + SMPBENCH_SLOT_PMOD_LVT], eax
    mov  eax, [rel smp_timer_post_icr]
    mov  [rbx + SMPBENCH_SLOT_PMOD_ICR], eax
    mov  eax, [rel smp_timer_post_current]
    mov  [rbx + SMPBENCH_SLOT_PMOD_CUR], eax
    mov  rax, [rel cpu_irq_count]
    sub  rax, [rel smp_timer_irq0_before]
    mov  [rbx + SMPBENCH_SLOT_IRQ0_DELTA], eax
    mov  rax, [rel cpu_preempt_count]
    sub  rax, [rel smp_timer_preempt0_before]
    mov  [rbx + SMPBENCH_SLOT_PREEMPT0_DELTA], eax
    mov  eax, [rel smp_timer_restore_seq]
    mov  [rbx + SMPBENCH_SLOT_RESTORE_SEQ], eax
    mov  al, [rel smp_timer_restore_ok]
    mov  [rbx + SMPBENCH_SLOT_RESTORE_OK], al
    mov  al, [rel sched_preempt_post_pmod_last_ok]
    mov  [rbx + SMPBENCH_SLOT_POST_TEST_OK], al
    mov  eax, [rbx + SMPBENCH_SLOT_UNITS]
    sub  eax, [rbx + SMPBENCH_SLOT_COMPLETED]
    jnc  .lost_ok
    xor  eax, eax
.lost_ok:
    mov  [rbx + SMPBENCH_SLOT_LOST], eax
    mov  byte [rel usched_job_active], 0
    mov  byte [rbx + SMPBENCH_SLOT_STATE], 2
    mov  eax, [rel smpbench_clock]
    mov  [rbx + SMPBENCH_SLOT_TSEC], eax       ; reap age counts from the terminal snapshot
.done:
    ret

smpbench_emit_supported:
    push r12
    push r13
    push r14
    push r15
    push rsi
    call smpbench_snapshot_done
    call smpobs_out_reset
    lea  rdi, [rel str_smpbench_prefix]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NONCE]
    call smpobs_put_hex16
    cmp  byte [rbx + SMPBENCH_SLOT_STATE], 2
    jne  .pending
    lea  rdi, [rel str_smpbench_done]
    call smpobs_put_str
    jmp  .mode
.pending:
    lea  rdi, [rel str_smpbench_pending]
    call smpobs_put_str
.mode:
    movzx r15d, byte [rbx + SMPBENCH_SLOT_STATE]
    lea  rdi, [rbx + SMPBENCH_SLOT_MODE]
    call smpobs_put_str
    cmp  byte [rbx + SMPBENCH_SLOT_STATE], 2
    jne  .pending_diag
    lea  rdi, [rel str_smpbench_units]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_UNITS]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_digest]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_DIGEST]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_completed]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_COMPLETED]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_expected]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_UNITS]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_cores]
    call smpobs_put_str
    mov  r12d, [rbx + SMPBENCH_SLOT_COREMASK]
    xor  r13d, r13d
    xor  r14d, r14d
.core_loop:
    cmp  r13d, USCHED_CPU_MAX
    jae  .core_done
    bt   r12d, r13d
    jnc  .core_next
    test r14d, r14d
    jz   .core_value
    lea  rdi, [rel str_smpbench_comma]
    call smpobs_put_str
.core_value:
    mov  edi, r13d
    call smpobs_put_dec
    inc  r14d
.core_next:
    inc  r13d
    jmp  .core_loop
.core_done:
    ; Fixed CPU-index order, including zeroes. Read only this nonce's frozen
    ; slot; a later job's globals must never change a terminal RESULT replay.
    lea  rdi, [rel str_smpbench_cpu_units]
    call smpobs_put_str
    xor  r13d, r13d
.cpu_units:
    test r13d, r13d
    jz   .cpu_units_value
    lea  rdi, [rel str_smpbench_comma]
    call smpobs_put_str
.cpu_units_value:
    mov  edi, [rbx + SMPBENCH_SLOT_CPUUNITS + r13*4]
    call smpobs_put_dec
    inc  r13d
    cmp  r13d, USCHED_CPU_MAX
    jb   .cpu_units
    lea  rdi, [rel str_smpbench_migrations]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_MIGRATIONS]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_steals]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_STEALS]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_preemptions]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_PREEMPT]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_resched]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_RESCHED]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_idlewake]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_IDLEWAKE]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_deadline]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_DEADLINE]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_hostrx]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_HOSTRX]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_leaks]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_LEAKS]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_double]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_DOUBLE]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_lost]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_LOST]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_faults]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_FAULTS]
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_stale]
    call smpobs_put_str
    mov  edi, [rbx + SMPBENCH_SLOT_STALE]
    call smpobs_put_dec
    jmp  .claim_diag
.pending_diag:
    ; Preserve the active nonce's exact barrier/claim/timer branch in every
    ; pending response; a host timeout can now retain the final content row.
    lea  rdi, [rel str_smpbench_completed]
    call smpobs_put_str
    mov  edi, [rel usched_job_completed]
    call smpobs_put_dec
.claim_diag:
    lea  rdi, [rel str_smpbench_next]
    call smpobs_put_str
    mov  edi, [rel usched_job_next]
    cmp  r15d, 2
    jne  .next_ready
    mov  edi, [rbx + SMPBENCH_SLOT_NEXT]
.next_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_seen]
    call smpobs_put_str
    cmp  r15d, 2
    je   .seen_snapshot
    call sched_unified_seen_count
    mov  edi, eax
    jmp  .seen_ready
.seen_snapshot:
    mov  edi, [rbx + SMPBENCH_SLOT_SEEN]
.seen_ready:
    call smpobs_put_dec
.timer_diag:
    lea  rdi, [rel str_smpbench_timer_mask]
    call smpobs_put_str
    mov  edi, [rel usched_job_timer_mask]
    cmp  r15d, 2
    jne  .timer_mask_ready
    mov  edi, [rbx + SMPBENCH_SLOT_TIMERMASK]
.timer_mask_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_required_timer_mask]
    call smpobs_put_str
    mov  edi, [rel usched_job_reserved]
    call smp_count_mask32
    mov  edi, eax
    cmp  r15d, 2
    jne  .required_mask_ready
    mov  edi, [rbx + SMPBENCH_SLOT_REQMASK]
.required_mask_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pending_reason]
    call smpobs_put_str
    movzx eax, byte [rel usched_job_pending_reason]
    cmp  r15d, 2
    jne  .reason_ready
    movzx eax, byte [rbx + SMPBENCH_SLOT_REASON]
.reason_ready:
    cmp  eax, USCHED_PENDING_IF_CLEAR
    je   .reason_if_clear
    cmp  eax, USCHED_PENDING_TIMER_MASK
    je   .reason_timer_mask
    cmp  eax, USCHED_PENDING_IPI_ACK
    je   .reason_ipi_ack
    cmp  eax, USCHED_PENDING_INCOMPLETE
    je   .reason_incomplete
    cmp  eax, USCHED_PENDING_DOUBLE_RUN
    je   .reason_double_run
    lea  rdi, [rel str_smpbench_reason_none]
    jmp  .reason_emit
.reason_if_clear:
    lea  rdi, [rel str_smpbench_reason_if_clear]
    jmp  .reason_emit
.reason_timer_mask:
    lea  rdi, [rel str_smpbench_reason_timer_mask]
    jmp  .reason_emit
.reason_ipi_ack:
    lea  rdi, [rel str_smpbench_reason_ipi_ack]
    jmp  .reason_emit
.reason_incomplete:
    lea  rdi, [rel str_smpbench_reason_incomplete]
    jmp  .reason_emit
.reason_double_run:
    lea  rdi, [rel str_smpbench_reason_double_run]
.reason_emit:
    call smpobs_put_str
    lea  rdi, [rel str_smpbench_pmod_dcr]
    call smpobs_put_str
    mov  edi, [rel smp_timer_post_dcr]
    cmp  r15d, 2
    jne  .pmod_dcr_ready
    mov  edi, [rbx + SMPBENCH_SLOT_PMOD_DCR]
.pmod_dcr_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pmod_lvt]
    call smpobs_put_str
    mov  edi, [rel smp_timer_post_lvt]
    cmp  r15d, 2
    jne  .pmod_lvt_ready
    mov  edi, [rbx + SMPBENCH_SLOT_PMOD_LVT]
.pmod_lvt_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pmod_icr]
    call smpobs_put_str
    mov  edi, [rel smp_timer_post_icr]
    cmp  r15d, 2
    jne  .pmod_icr_ready
    mov  edi, [rbx + SMPBENCH_SLOT_PMOD_ICR]
.pmod_icr_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_pmod_current]
    call smpobs_put_str
    mov  edi, [rel smp_timer_post_current]
    cmp  r15d, 2
    jne  .pmod_current_ready
    mov  edi, [rbx + SMPBENCH_SLOT_PMOD_CUR]
.pmod_current_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_irq0_delta]
    call smpobs_put_str
    mov  rax, [rel cpu_irq_count]
    sub  rax, [rel smp_timer_irq0_before]
    mov  edi, eax
    cmp  r15d, 2
    jne  .irq0_delta_ready
    mov  edi, [rbx + SMPBENCH_SLOT_IRQ0_DELTA]
.irq0_delta_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_preempt0_delta]
    call smpobs_put_str
    mov  rax, [rel cpu_preempt_count]
    sub  rax, [rel smp_timer_preempt0_before]
    mov  edi, eax
    cmp  r15d, 2
    jne  .preempt0_delta_ready
    mov  edi, [rbx + SMPBENCH_SLOT_PREEMPT0_DELTA]
.preempt0_delta_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_restore_seq]
    call smpobs_put_str
    mov  edi, [rel smp_timer_restore_seq]
    cmp  r15d, 2
    jne  .restore_seq_ready
    mov  edi, [rbx + SMPBENCH_SLOT_RESTORE_SEQ]
.restore_seq_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_restore_ok]
    call smpobs_put_str
    movzx edi, byte [rel smp_timer_restore_ok]
    cmp  r15d, 2
    jne  .restore_ok_ready
    movzx edi, byte [rbx + SMPBENCH_SLOT_RESTORE_OK]
.restore_ok_ready:
    call smpobs_put_dec
    lea  rdi, [rel str_smpbench_post_pmod_test_ok]
    call smpobs_put_str
    movzx edi, byte [rel sched_preempt_post_pmod_last_ok]
    cmp  r15d, 2
    jne  .post_test_ready
    movzx edi, byte [rbx + SMPBENCH_SLOT_POST_TEST_OK]
.post_test_ready:
    call smpobs_put_dec
    cmp  r15d, 2
    jne  .finish
    cmp  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_SINGLE
    je   .native_timing
    cmp  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_PARALLEL
    jne  .finish
.native_timing:
    ; Compact terminal-only extension; all values are this nonce's frozen
    ; snapshot. Raw TSC endpoints are NOT a synchronized native duration.
    lea  rdi, [rel str_smpbench_native_start]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NATIVE_START]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_native_end]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NATIVE_END]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_native_work_max]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NATIVE_WORK_MAX]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_native_khz]
    call smpobs_put_str
    mov  rdi, [rbx + SMPBENCH_SLOT_NATIVE_KHZ]
    call smpobs_put_hex16
    lea  rdi, [rel str_smpbench_native_clock]
    call smpobs_put_str
.finish:
    pop  rsi
    call smpobs_finish_ok
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

cmd_verb_smpbench:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi
    mov  rdi, [rdi + REQ_ARG]
    mov  r12, rdi
    call smpobs_arg_bounded
    jc   .oversized
    cmp  dword [r12], 'STAR'
    jne  .check_result
    cmp  byte [r12 + 4], 'T'
    jne  .malformed
    cmp  byte [r12 + 5], ' '
    jne  .malformed
    lea  rbx, [r12 + 6]
    mov  r13, rbx
    xor  r14d, r14d
.mode:
    movzx eax, byte [rbx]
    cmp  al, ' '
    je   .mode_done
    test al, al
    jz   .malformed
    cmp  al, '_'
    je   .mode_char
    cmp  al, 'a'
    jb   .malformed
    cmp  al, 'z'
    ja   .malformed
.mode_char:
    cmp  r14d, SMPBENCH_MODE_MAX
    jae  .range
    inc  r14d
    inc  rbx
    jmp  .mode
.mode_done:
    test r14d, r14d
    jz   .malformed
    inc  rbx
    mov  rdi, rbx
    call smpobs_parse_nonce
    jc   .bad_nonce
    mov  r12, rax
    mov  rbx, rdx
    cmp  byte [rbx], ' '
    jne  .malformed
    inc  rbx
    mov  rdi, rbx
    call smpobs_parse_dec
    jc   .malformed
    cmp  byte [rdx], 0
    jne  .malformed
    test rax, rax
    jz   .range
    cmp  rax, SMPBENCH_UNITS_MAX
    ja   .range
    mov  r11, rax
    push r11
    mov  rdi, r11
    mov  rsi, r13                          ; mode token
    mov  edx, r14d                         ; mode length
    call smpbench_unsigned_admit
    pop  r11
    test eax, eax
    jnz  .unsigned_cap
    cmp  r14d, 6                           ; parfor runs inline: no slot, no job
    jne  .slot_mode
    cmp  dword [r13], 'parf'
    jne  .slot_mode
    cmp  word [r13 + 4], 'or'
    jne  .slot_mode
    mov  rdi, r11
    mov  rsi, r15
    mov  rdx, r12
    call smpbench_parfor
    test eax, eax
    jnz  .range
    jmp  .out
.slot_mode:
    push r11
    call smpbench_is_unsigned_remote
    pop  r11
    mov  [rel smpbench_req_unsigned], al

    lea  rbx, [rel smpbench_slots]
    xor  ecx, ecx
    xor  r10, r10                          ; first never-used free slot
    xor  r9, r9                            ; first reaped free slot (its old result is readable)
.start_scan:
    cmp  ecx, SMPBENCH_SLOTS
    jae  .start_miss
    cmp  byte [rbx + SMPBENCH_SLOT_USED], 0
    jne  .start_used
    cmp  byte [rbx + SMPBENCH_SLOT_REAPED], 0
    jne  .start_free_reaped
    test r10, r10
    cmovz r10, rbx
    jmp  .start_next
.start_free_reaped:
    test r9, r9
    cmovz r9, rbx
    jmp  .start_next
.start_used:
    cmp  qword [rbx + SMPBENCH_SLOT_NONCE], r12
    jne  .start_next
    cmp  qword [rbx + SMPBENCH_SLOT_UNITS], r11
    jne  .reuse
    movzx eax, byte [rbx + SMPBENCH_SLOT_MODELEN]
    cmp  eax, r14d
    jne  .reuse
    xor  edx, edx
.mode_compare:
    cmp  edx, r14d
    jae  .emit_start
    mov  al, [r13 + rdx]
    cmp  al, [rbx + SMPBENCH_SLOT_MODE + rdx]
    jne  .reuse
    inc  edx
    jmp  .mode_compare
.start_next:
    add  rbx, SMPBENCH_SLOT_SIZE
    inc  ecx
    jmp  .start_scan
.start_miss:
    test r10, r10
    cmovz r10, r9                          ; reuse a reaped slot only when no fresh one is left
    test r10, r10
    jz   .capacity
    cmp  byte [rel smpbench_req_unsigned], 1
    jne  .claim
    mov  eax, SMPBENCH_SLOTS
    sub  eax, [rel smpbench_used_count]
    cmp  eax, SMPBENCH_RESERVE
    jbe  .reserved                         ; the last SMPBENCH_RESERVE slots are owner/local only
.claim:
    mov  rbx, r10
    mov  byte [rbx + SMPBENCH_SLOT_REAPED], 0
    mov  al, [rel smpbench_req_unsigned]
    mov  [rbx + SMPBENCH_SLOT_UNSIGNED], al
    mov  eax, [rel smpbench_clock]
    mov  [rbx + SMPBENCH_SLOT_TSEC], eax
    mov  [rbx + SMPBENCH_SLOT_NONCE], r12
    mov  [rbx + SMPBENCH_SLOT_UNITS], r11
    mov  [rbx + SMPBENCH_SLOT_MODELEN], r14b
    xor  edx, edx
.mode_copy:
    cmp  edx, r14d
    jae  .mode_copied
    mov  al, [r13 + rdx]
    mov  [rbx + SMPBENCH_SLOT_MODE + rdx], al
    inc  edx
    jmp  .mode_copy
.mode_copied:
    mov  byte [rbx + SMPBENCH_SLOT_MODE + rdx], 0
    mov  byte [rbx + SMPBENCH_SLOT_STATE], 0
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], 0
    mov  byte [rbx + SMPBENCH_SLOT_USED], 1
    inc  dword [rel smpbench_used_count]
    cmp  r14d, 9
    jne  .check_dispatch_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'imba'
    jne  .check_coherence_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE + 4], 'lanc'
    jne  .check_coherence_mode
    cmp  byte [rbx + SMPBENCH_SLOT_MODE + 8], 'e'
    jne  .check_coherence_mode
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_STEAL
    jmp  .begin_supported
.check_dispatch_mode:
    cmp  r14d, 8
    jne  .check_coherence_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'disp'
    jne  .check_parallel_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE + 4], 'atch'
    jne  .check_parallel_mode
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_DISPATCH
    jmp  .begin_supported
.check_coherence_mode:
    cmp  r14d, 9
    jne  .check_fault_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'cohe'
    jne  .emit
    cmp  dword [rbx + SMPBENCH_SLOT_MODE + 4], 'renc'
    jne  .emit
    cmp  byte [rbx + SMPBENCH_SLOT_MODE + 8], 'e'
    jne  .emit
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_COHERENCE
    jmp  .begin_supported
.check_fault_mode:
    cmp  r14d, 5
    jne  .check_tlb_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'faul'
    jne  .emit
    cmp  byte [rbx + SMPBENCH_SLOT_MODE + 4], 't'
    jne  .emit
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_FAULT
    jmp  .begin_supported
.check_tlb_mode:
    cmp  r14d, 3
    jne  .check_context_mode
    cmp  word [rbx + SMPBENCH_SLOT_MODE], 'tl'
    jne  .emit
    cmp  byte [rbx + SMPBENCH_SLOT_MODE + 2], 'b'
    jne  .emit
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_TLB
    jmp  .begin_supported
.check_context_mode:
    cmp  r14d, 7
    jne  .check_single_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'cont'
    jne  .check_single_mode
    cmp  word [rbx + SMPBENCH_SLOT_MODE + 4], 'ex'
    jne  .check_single_mode
    cmp  byte [rbx + SMPBENCH_SLOT_MODE + 6], 't'
    jne  .check_single_mode
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_CONTEXT
    jmp  .begin_supported
.check_single_mode:
    cmp  r14d, 6
    jne  .check_parallel_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'sing'
    jne  .check_parallel_mode
    cmp  word [rbx + SMPBENCH_SLOT_MODE + 4], 'le'
    jne  .check_parallel_mode
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_SINGLE
    jmp  .begin_supported
.check_parallel_mode:
    cmp  r14d, 8
    jne  .check_soak_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'para'
    jne  .check_soak_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE + 4], 'llel'
    jne  .check_soak_mode
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_PARALLEL
    jmp  .begin_supported
.check_soak_mode:
    cmp  r14d, 4
    jne  .check_preempt_mode
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'soak'
    jne  .check_preempt_mode
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_SOAK
    jmp  .begin_supported
.check_preempt_mode:
    cmp  r14d, 7
    jne  .emit
    cmp  dword [rbx + SMPBENCH_SLOT_MODE], 'pree'
    jne  .emit
    cmp  word [rbx + SMPBENCH_SLOT_MODE + 4], 'mp'
    jne  .emit
    cmp  byte [rbx + SMPBENCH_SLOT_MODE + 6], 't'
    jne  .emit
    mov  byte [rbx + SMPBENCH_SLOT_MODECODE], USCHED_MODE_PREEMPT
.begin_supported:
    movzx eax, byte [rbx + SMPBENCH_SLOT_MODECODE]
    cmp  eax, USCHED_MODE_SINGLE
    jb   .legacy_size
    cmp  eax, USCHED_MODE_SINGLE
    je   .scaling_size
    cmp  eax, USCHED_MODE_PARALLEL
    je   .scaling_size
    cmp  r11d, USCHED_CAPSTONE_MAX_UNITS
    jbe  .supported_size_ok
    jmp  .supported_size_bad
.scaling_size:
    cmp  r11d, USCHED_SCALING_MAX_UNITS
    jbe  .supported_size_ok
    jmp  .supported_size_bad
.legacy_size:
    cmp  r11d, USCHED_MAX_UNITS
    jbe  .supported_size_ok
.supported_size_bad:
    mov  byte [rbx + SMPBENCH_SLOT_USED], 0
    dec  dword [rel smpbench_used_count]
    jmp  .range
.supported_size_ok:
    movzx edi, byte [rbx + SMPBENCH_SLOT_MODECODE]
    mov  esi, r11d
    call sched_unified_bench_begin
    test eax, eax
    jz   .accepted
    mov  byte [rbx + SMPBENCH_SLOT_USED], 0
    dec  dword [rel smpbench_used_count]
    jmp  .capacity                         ; another async job still owns globals
.accepted:
    call smpbench_host_rx_begin
    mov  byte [rbx + SMPBENCH_SLOT_STATE], 1
    jmp  .emit_start

.check_result:
    cmp  dword [r12], 'RESU'
    jne  .unknown
    cmp  word [r12 + 4], 'LT'
    jne  .unknown
    cmp  byte [r12 + 6], ' '
    jne  .malformed
    lea  rdi, [r12 + 7]
    call smpobs_parse_nonce
    jc   .bad_nonce
    cmp  byte [rdx], 0
    jne  .malformed
    mov  r12, rax
    lea  rbx, [rel smpbench_slots]
    xor  ecx, ecx
.result_scan:                              ; a live slot for this nonce wins ...
    cmp  ecx, SMPBENCH_SLOTS
    jae  .result_reaped
    cmp  byte [rbx + SMPBENCH_SLOT_USED], 0
    je   .result_next
    cmp  qword [rbx + SMPBENCH_SLOT_NONCE], r12
    je   .emit
.result_next:
    add  rbx, SMPBENCH_SLOT_SIZE
    inc  ecx
    jmp  .result_scan
.result_reaped:                            ; ... then a reaped slot still holding it
    lea  rbx, [rel smpbench_slots]
    xor  ecx, ecx
.reaped_scan:
    cmp  ecx, SMPBENCH_SLOTS
    jae  .unknown
    cmp  byte [rbx + SMPBENCH_SLOT_USED], 0
    jne  .reaped_next
    cmp  byte [rbx + SMPBENCH_SLOT_REAPED], 0
    je   .reaped_next
    cmp  qword [rbx + SMPBENCH_SLOT_NONCE], r12
    je   .emit
.reaped_next:
    add  rbx, SMPBENCH_SLOT_SIZE
    inc  ecx
    jmp  .reaped_scan

.emit_start:
    mov  rsi, r15
    cmp  byte [rbx + SMPBENCH_SLOT_MODECODE], 0
    je   .emit_unsupported
    cmp  byte [rbx + SMPBENCH_SLOT_STATE], 2
    je   .emit_supported
    call smpbench_emit_accepted
    jmp  .out
.emit:
    mov  rsi, r15
    cmp  byte [rbx + SMPBENCH_SLOT_MODECODE], 0
    je   .emit_unsupported
.emit_supported:
    call smpbench_emit_supported
    jmp  .out
.emit_unsupported:
    call smpbench_emit_unsupported
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
.unsigned_cap:
    lea  rdi, [rel str_smp_err_unsigned_cap]
    jmp  .error
.reuse:
    lea  rdi, [rel str_smp_err_reuse]
    jmp  .error
.capacity:
    lea  rdi, [rel str_smp_err_capacity]
    jmp  .error
.reserved:
    lea  rdi, [rel str_smp_err_reserved]
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

; smpbench_unsigned_admit(RDI = requested units, RSI = mode token, EDX = mode
;   length) -> EAX 0 admit, 1 refuse.
; SEC-P2b: SMPBENCH is on the shipped public floor because the SMP qualification
; executors drive it unsigned (HP Step A: dispatch/context modes, which the
; scheduler caps at USCHED_MAX_UNITS). A remote request without an owner
; envelope (AUTH2 VALID/CONSUMED or unrestricted SSH owner) may ask for at most
; SMPBENCH_UNSIGNED_UNITS_MAX units and never for 'soak', where one unit is one
; second of all-AP churn holding the job lock. Local/in-image callers and
; owner-signed requests keep the full range and every mode. Both floors.
; clobbers: RAX,RDX.
smpbench_unsigned_admit:
    xor  eax, eax
    cmp  byte [rel command_auth_remote_active], 1
    jne  .out                              ; no remote request in flight
    push rdi
    push rsi
    push rdx
    call command_auth_owner_envelope
    pop  rdx
    pop  rsi
    pop  rdi
    test eax, eax
    mov  eax, 0
    jnz  .out                              ; owner-authenticated: full range, every mode
    mov  eax, 1
    cmp  rdi, SMPBENCH_UNSIGNED_UNITS_MAX
    ja   .out
    cmp  edx, 4
    jne  .admit
    cmp  dword [rsi], 'soak'
    je   .out
.admit:
    xor  eax, eax
.out:
    ret

; smpbench_is_unsigned_remote -> EAX 1 for a remote request without an owner
;   envelope (the requests SEC-P2b caps), else 0. clobbers: caller-saved.
smpbench_is_unsigned_remote:
    xor  eax, eax
    cmp  byte [rel command_auth_remote_active], 1
    jne  .out
    call command_auth_owner_envelope
    xor  eax, 1
    and  eax, 1
.out:
    ret

; smpbench_reap_tick — resident idle loop (boot/header .halt). See the
;   SMPBENCH-slot-leak-dos note at the slot layout. clobbers: caller-saved.
smpbench_reap_tick:
    call smpwork_async_step               ; existing resident seam; finite, no new timer
    call boot_ms_now                       ; RAX ms since boot, 0 when uncalibrated
    test rax, rax
    jz   .untimed
    mov  rcx, rax
    sub  rcx, [rel smpbench_last_ms]
    cmp  rcx, 1000
    jb   .out
    mov  [rel smpbench_last_ms], rax
    jmp  .second
.untimed:                                  ; >= one ~1 kHz timer IRQ per idle iteration
    inc  dword [rel smpbench_untimed_ticks]
    cmp  dword [rel smpbench_untimed_ticks], 1000
    jb   .out
    mov  dword [rel smpbench_untimed_ticks], 0
.second:
    inc  dword [rel smpbench_clock]
    push rbx
    push r12
    lea  rbx, [rel smpbench_slots]
    xor  r12d, r12d
.slot:
    cmp  r12d, SMPBENCH_SLOTS
    jae  .done
    cmp  byte [rbx + SMPBENCH_SLOT_USED], 0
    je   .next
    mov  eax, [rel smpbench_clock]
    sub  eax, [rbx + SMPBENCH_SLOT_TSEC]   ; age in seconds (wrap-safe)
    cmp  byte [rbx + SMPBENCH_SLOT_MODECODE], 0
    je   .terminal                         ; unsupported mode: nothing ever ran
    cmp  byte [rbx + SMPBENCH_SLOT_STATE], 2
    je   .terminal
    cmp  byte [rbx + SMPBENCH_SLOT_STATE], 1
    jne  .next
    cmp  byte [rbx + SMPBENCH_SLOT_UNSIGNED], 1
    jne  .next                             ; owner/local jobs are their owner's
    cmp  eax, SMPBENCH_DRIVE_S
    jb   .next
    mov  eax, [rel smpbench_clock]
    sub  eax, [rel smpbench_last_drive]
    cmp  eax, SMPBENCH_DRIVE_EVERY_S
    jb   .next
    mov  eax, [rel smpbench_clock]
    mov  [rel smpbench_last_drive], eax
    inc  dword [rel smpbench_driven_total]
    call smpbench_snapshot_done            ; the RESULT the client never sent (RBX = slot)
    jmp  .next
.terminal:
    cmp  eax, SMPBENCH_REAP_S
    jb   .next
    mov  byte [rbx + SMPBENCH_SLOT_USED], 0
    mov  byte [rbx + SMPBENCH_SLOT_REAPED], 1
    dec  dword [rel smpbench_used_count]
    inc  dword [rel smpbench_reaped_total]
.next:
    add  rbx, SMPBENCH_SLOT_SIZE
    inc  r12d
    jmp  .slot
.done:
    pop  r12
    pop  rbx
.out:
    ret

smpwork_out_reset:
    lea  rax, [rel smpwork_out_buf]
    mov  [rel smpwork_out_cur], rax
    mov  byte [rax], 0
    lea  rax, [rel smpwork_out_buf + SMPWORK_LEGACY_CAP - 1]
    mov  [rel smpwork_out_limit], rax
    mov  byte [rel smpwork_out_failed], 0
    mov  byte [rel smpwork_out_ready], 0
    ret

; Atomic append: preflight the entire string plus the reserved NUL before any
; output write. A failed build stays failed until reset and is never published.
smpwork_put_str:                           ; RDI = trusted cstr
    cmp  byte [rel smpwork_out_failed], 0
    jne  .done
    mov  rsi, [rel smpwork_out_cur]
    lea  rax, [rel smpwork_out_buf]
    cmp  rsi, rax
    jb   .failed
    mov  rcx, [rel smpwork_out_limit]
    cmp  rsi, rcx
    ja   .failed
    sub  rcx, rsi                           ; available bytes, excluding NUL
    xor  edx, edx
.measure:
    cmp  byte [rdi + rdx], 0
    je   .fits
    cmp  rdx, rcx
    jae  .failed
    inc  rdx
    jmp  .measure
.fits:
    mov  rcx, rdx
    xchg rdi, rsi                          ; MOVSB uses RDI=destination, RSI=source
    cld
    rep  movsb
    mov  rsi, rdi                          ; cursor follows the destination
    mov  byte [rsi], 0
    mov  [rel smpwork_out_cur], rsi
.done:
    ret
.failed:
    mov  byte [rel smpwork_out_failed], 1
    ret

smpwork_put_dec:                           ; RDI = u64, <=20 digits + NUL
    lea  rsi, [rel smpwork_num_buf]         ; 32 bytes, never format into output
    call fmt_dec
    lea  rdi, [rel smpwork_num_buf]
    jmp  smpwork_put_str

smpwork_put_hex8:                          ; EDI = u32, exactly8 digits + NUL
    mov  edi, edi
    lea  rsi, [rel smpwork_num_buf]
    mov  edx, 8
    call fmt_hex
    lea  rdi, [rel smpwork_num_buf]
    jmp  smpwork_put_str

smpwork_put_header:
    lea  rdi, [rel str_sw_pre]
    call smpwork_put_str
    mov  edi, [rel smpwork_snapshot_challenge]
    call smpwork_put_hex8
    lea  rdi, [rel str_sw_epoch]
    call smpwork_put_str
    mov  edi, [rel smpwork_snapshot_epoch]
    call smpwork_put_dec
    lea  rdi, [rel str_sw_workers]
    call smpwork_put_str
    mov  edi, [rel smpwork_snapshot_workers]
    call smpwork_put_dec
    ret

smpwork_put_audit:
    lea  rdi, [rel str_sw_rq]
    call smpwork_put_str
    movzx edi, byte [rel smpwork_rq_audit]
    call smpwork_put_dec
    lea  rdi, [rel str_sw_rt]
    call smpwork_put_str
    movzx edi, byte [rel smpwork_rt_bsp]
    call smpwork_put_dec
    lea  rdi, [rel str_sw_boot]
    call smpwork_put_str
    movzx edi, byte [rel smpwork_boot_bsp]
    call smpwork_put_dec
    ret

; VERB: SMPWORK 0x<challenge32>. One unchanged AP work/snapshot operation.
; Preserve exact fitting normal legacy bodies. Otherwise return every frozen
; row in a lossless compact table: rows=logical:token_hex8:runs_decimal;...
; output=complete means the whole frozen row set is delivered; snapshot=partial
; explicitly distinguishes AP timeout/missing workers from output truncation.
; No pages or retained cursor: every reply has one challenge/epoch and row set.
cmd_verb_smpwork:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  byte [rel smpwork_out_ready], 0
    call smpwork_async_command
    cmp  eax, 1
    je   .out
    cmp  eax, 2
    je   .async_taken
    xor  r14d, r14d
    mov  rdi, [rdi + REQ_ARG]
    call smpwork_parse_u32                  ; unchanged legacy numeric grammar
    mov  edi, eax
    mov  r15d, eax                         ; request nonce for an overlap refusal
    call smpwork_snapshot                  ; no extra work on format fallback
    jc   .busy
    jmp  .taken
.async_taken:
    mov  r14d, 1
.taken:
    mov  eax, [rel smpwork_snapshot_workers]
    mov  r15d, eax
    mov  r12d, [rel smpwork_snapshot_epoch]
    mov  eax, [rel smpwork_expected_workers] ; stable post-bring-up AP expectation
    test r14d, r14d
    jz   .expected
    mov  eax, [rel smpwork_async_expected]   ; the async begin's frozen expectation
.expected:
    mov  [rel smpwork_output_expected], eax
    cmp  eax, MAXCORE
    ja   .inconsistent
    cmp  r15d, eax
    ja   .inconsistent
    cmp  r15d, [rel smpwork_snapshot_workers]
    jne  .inconsistent
    ; Core uses zero as the absent-row sentinel. After epoch wrap it cannot
    ; distinguish an unstamped row; refuse this one snapshot rather than expose
    ; stale tokens. The next ordinary request gets epoch1, with no core change.
    test r12d, r12d
    jz   .zero_epoch
    xor  ebx, ebx
    xor  r14d, r14d
.count_rows:
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    cmp  dword [rax + rbx*4], r12d
    jne  .count_next
    inc  r14d
.count_next:
    inc  ebx
    cmp  ebx, MAXCORE
    jb   .count_rows
    cmp  r14d, r15d
    jne  .inconsistent

    cmp  r15d, [rel smpwork_output_expected]
    jne  .compact                         ; missing APs need explicit partial state
    call smpwork_out_reset
    call smpwork_put_header
    xor  ebx, ebx
.row_loop:
    cmp  ebx, MAXCORE
    jae  .rows_done
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    cmp  dword [rax + rbx*4], r12d
    jne  .row_next
    lea  rdi, [rel str_sw_core]
    call smpwork_put_str
    mov  edi, ebx
    call smpwork_put_dec
    lea  rdi, [rel str_sw_token]
    call smpwork_put_str
    lea  rax, [rel smpwork_snapshot_worker_token]
    mov  edi, [rax + rbx*4]
    call smpwork_put_hex8
    lea  rdi, [rel str_sw_runs]
    call smpwork_put_str
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  rdi, [rax + rbx*8]
    call smpwork_put_dec
.row_next:
    inc  ebx
    jmp  .row_loop
.rows_done:
    call smpwork_put_audit
    cmp  byte [rel smpwork_out_failed], 0
    je   .publish
.compact:
    call smpwork_out_reset                 ; discard failed legacy build, same snapshot
    lea  rax, [rel smpwork_out_buf + SMPWORK_OUT_CAP - 1]
    mov  [rel smpwork_out_limit], rax
    call smpwork_put_header
    lea  rdi, [rel str_sw_compact]
    call smpwork_put_str
    lea  rdi, [rel str_sw_complete]
    cmp  r15d, [rel smpwork_output_expected]
    je   .snapshot_state
    lea  rdi, [rel str_sw_partial]
.snapshot_state:
    call smpwork_put_str
    lea  rdi, [rel str_sw_expected]
    call smpwork_put_str
    mov  edi, [rel smpwork_output_expected]
    call smpwork_put_dec
    lea  rdi, [rel str_sw_rows]
    call smpwork_put_str
    xor  ebx, ebx
    xor  r14d, r14d
.compact_row:
    cmp  ebx, MAXCORE
    jae  .compact_done
    lea  rax, [rel smpwork_snapshot_worker_epoch]
    cmp  dword [rax + rbx*4], r12d
    jne  .compact_next
    test r14d, r14d
    jz   .first
    lea  rdi, [rel str_sw_separator]
    call smpwork_put_str
.first:
    mov  edi, ebx
    call smpwork_put_dec
    lea  rdi, [rel str_sw_colon]
    call smpwork_put_str
    lea  rax, [rel smpwork_snapshot_worker_token]
    mov  edi, [rax + rbx*4]
    call smpwork_put_hex8
    lea  rdi, [rel str_sw_colon]
    call smpwork_put_str
    lea  rax, [rel smpwork_snapshot_worker_runs]
    mov  rdi, [rax + rbx*8]
    call smpwork_put_dec
    inc  r14d
.compact_next:
    inc  ebx
    jmp  .compact_row
.compact_done:
    test r14d, r14d
    jnz  .compact_audit
    lea  rdi, [rel str_sw_empty]
    call smpwork_put_str
.compact_audit:
    call smpwork_put_audit
    cmp  byte [rel smpwork_out_failed], 0
    jne  .output_bounds
.publish:
    mov  byte [rel smpwork_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  eax, r15d
    mov  [r13 + RSP_VAL], rax
    jmp  .out
.busy:
    mov  edi, SMPWORK_ASYNC_BUSY
    mov  rsi, r13
    mov  edx, r15d
    xor  ecx, ecx
    call smpwork_async_reply
    jmp  .out
.inconsistent:
    lea  rbx, [rel str_sw_inconsistent]
    jmp  .refuse
.zero_epoch:
    lea  rbx, [rel str_sw_zero_epoch]
    jmp  .refuse
.output_bounds:
    lea  rbx, [rel str_sw_bounds]
.refuse:
    ; A typed, nonce/epoch-bound refusal uses the existing diagnostic error
    ; surface. Never publish a failed/truncated SMPWORK body as ready or OK.
    mov  byte [rel smpwork_out_ready], 0
    mov  byte [rel smpwork_out_buf], 0
    call smpobs_out_reset
    lea  rdi, [rel str_sw_error]
    call smpobs_put_str
    mov  edi, [rel smpwork_snapshot_challenge]
    call smpobs_put_hex16
    lea  rdi, [rel str_sw_epoch]
    call smpobs_put_str
    mov  edi, r12d
    call smpobs_put_dec
    lea  rdi, [rel str_sw_reason]
    call smpobs_put_str
    mov  rdi, rbx
    call smpobs_put_str
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Explicit additive grammar (bounded, exact; legacy numeric grammar untouched):
; ASYNC BEGIN 0xhhhhhhhh
; ASYNC BEGIN 0xhhhhhhhh HOLD 0xmmmmmmmm (hold ms 1..5000; PENDING/cancellable until then)
; ASYNC POLL 0xhhhhhhhh 0xgggggggggggggggg
; ASYNC CANCEL 0xhhhhhhhh 0xgggggggggggggggg
; ASYNC STATUS 0xhhhhhhhh 0xgggggggggggggggg (read-only retained state)
; ASYNC DETAIL 0xhhhhhhhh 0xgggggggggggggggg (read-only admission scalars)
; ASYNC PROGRESS 0xhhhhhhhh 0xgggggggggggggggg (retained publications)
; ASYNC RESULTS 0xhhhhhhhh 0xgggggggggggggggg (non-consuming final rows)
; Returns 0 legacy (RDI request intact), 1 staged control reply, 2 taken rows.
smpwork_async_command:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    xor  r13d, r13d
    xor  r14d, r14d
    mov  rdi, [rbx + REQ_ARG]
    test rdi, rdi
    jz   .legacy
    ; Only the reserved ASYNC prefix changes behavior for historical text.
    cmp  byte [rdi], 'A'
    jne  .legacy
    cmp  byte [rdi + 1], 'S'
    jne  .legacy
    cmp  byte [rdi + 2], 'Y'
    jne  .legacy
    cmp  byte [rdi + 3], 'N'
    jne  .legacy
    cmp  byte [rdi + 4], 'C'
    jne  .legacy
    cmp  byte [rdi + 5], 0
    je   .malformed
    cmp  byte [rdi + 5], ' '
    jne  .legacy
    call smpobs_arg_bounded
    jc   .malformed
    cmp  eax, 22
    je   .begin
    cmp  eax, 38
    je   .begin_hold
    cmp  eax, 40
    je   .poll
    cmp  eax, 43
    je   .results
    cmp  eax, 44
    je   .progress
    cmp  eax, 42
    jne  .malformed
    cmp  dword [rdi + 5], ' DET'
    je   .detail
    cmp  dword [rdi + 5], ' STA'
    je   .status
    cmp  dword [rdi + 5], ' CAN'
    jne  .malformed
    cmp  dword [rdi + 9], 'CEL '
    jne  .malformed
    mov  r15d, 2
    add  rdi, 13
    jmp  .nonce
.results:
    cmp  dword [rdi + 5], ' RES'
    jne  .malformed
    cmp  dword [rdi + 9], 'ULTS'
    jne  .malformed
    cmp  byte [rdi + 13], ' '
    jne  .malformed
    mov  r15d, 6
    add  rdi, 14
    jmp  .nonce
.progress:
    cmp  dword [rdi + 5], ' PRO'
    jne  .malformed
    cmp  dword [rdi + 9], 'GRES'
    jne  .malformed
    cmp  word [rdi + 13], 'S '
    jne  .malformed
    mov  r15d, 5
    add  rdi, 15
    jmp  .nonce
.detail:
    cmp  dword [rdi + 9], 'AIL '
    jne  .malformed
    mov  r15d, 4
    add  rdi, 13
    jmp  .nonce
.status:
    cmp  dword [rdi + 9], 'TUS '
    jne  .malformed
    mov  r15d, 3
    add  rdi, 13
    jmp  .nonce
.poll:
    cmp  dword [rdi + 5], ' POL'
    jne  .malformed
    cmp  word [rdi + 9], 'L '
    jne  .malformed
    mov  r15d, 1
    add  rdi, 11
    jmp  .nonce
.begin_hold:
    mov  r15d, 7
    jmp  .begin_word
.begin:
    xor  r15d, r15d
.begin_word:
    cmp  dword [rdi + 5], ' BEG'
    jne  .malformed
    cmp  word [rdi + 9], 'IN'
    jne  .malformed
    cmp  byte [rdi + 11], ' '
    jne  .malformed
    add  rdi, 12
.nonce:
    cmp  word [rdi], '0x'
    jne  .malformed
    add  rdi, 2
    mov  ecx, 8
    call smpwork_async_hex
    jc   .malformed
    mov  r14d, eax
    test r15d, r15d
    jz   .dispatch
    cmp  r15d, 7
    je   .hold
    cmp  byte [rdi], ' '
    jne  .malformed
    inc  rdi
    cmp  word [rdi], '0x'
    jne  .malformed
    add  rdi, 2
    mov  ecx, 16
    call smpwork_async_hex
    jc   .malformed
    mov  r13, rax
    jmp  .dispatch
.hold:
    cmp  dword [rdi], ' HOL'
    jne  .malformed
    cmp  word [rdi + 4], 'D '
    jne  .malformed
    cmp  word [rdi + 6], '0x'
    jne  .malformed
    add  rdi, 8
    mov  ecx, 8
    call smpwork_async_hex
    jc   .malformed
    mov  r13, rax                         ; hold ms (core owns the 1..cap bound); replaced by the handle
.dispatch:
    cmp  byte [rdi], 0
    jne  .malformed
    ; Mutating APIs maintain; STATUS/DETAIL only observe retained state.
    mov  rdi, [rbx + REQ_SOURCE]
    mov  rsi, [rbx + REQ_PRINCIPAL]
    mov  edx, r14d
    mov  rcx, r13
    test r15d, r15d
    jz   .start
    cmp  r15d, 7
    je   .start_hold
    cmp  r15d, 2
    je   .cancel
    cmp  r15d, 3
    je   .observe
    cmp  r15d, 6
    je   .observe_results
    cmp  r15d, 5
    je   .observe_progress
    cmp  r15d, 4
    je   .observe_detail
    call smpwork_async_take
    cmp  eax, SMPWORK_ASYNC_COMPLETE
    je   .taken
    cmp  eax, SMPWORK_ASYNC_PARTIAL
    je   .taken
    jmp  .reply
.observe_results:
    sub  rsp, 448                        ; caller-private frozen rows and audits
    mov  r8, rsp
    call smpwork_async_results
    mov  edi, eax
    mov  rsi, r12
    mov  edx, r14d
    mov  rcx, r13
    mov  r8, rsp
    call smpwork_async_results_reply
    add  rsp, 448
    mov  eax, 1
    jmp  .out
.observe_progress:
    sub  rsp, 48                         ; private copied publication record
    mov  r8, rsp
    call smpwork_async_progress
    mov  edi, eax
    mov  rsi, r12
    mov  edx, r14d
    mov  rcx, r13
    mov  r8, rsp
    call smpwork_async_progress_reply
    add  rsp, 48
    mov  eax, 1
    jmp  .out
.observe_detail:
    sub  rsp, 32                         ; private copied admission record
    mov  r8, rsp
    call smpwork_async_detail
    mov  edi, eax
    mov  rsi, r12
    mov  edx, r14d
    mov  rcx, r13
    mov  r8, rsp
    call smpwork_async_detail_reply
    add  rsp, 32
    mov  eax, 1
    jmp  .out
.observe:
    call smpwork_async_status
    jmp  .reply
.cancel:
    call smpwork_async_cancel
    jmp  .reply
.start_hold:
    mov  ecx, r13d
    call smpwork_async_begin_hold
    mov  r13, rdx                         ; never disclose another owner's handle
    jmp  .reply
.start:
    call smpwork_async_begin
    mov  r13, rdx                         ; never disclose another owner's handle
    jmp  .reply
.malformed:
    mov  eax, 12                          ; command-only MALFORMED refusal
.reply:
    mov  edi, eax
    mov  rsi, r12
    mov  edx, r14d
    mov  rcx, r13
    call smpwork_async_reply
    mov  eax, 1
    jmp  .out
.taken:
    mov  eax, 2
    jmp  .out
.legacy:
    xor  eax, eax
.out:
    mov  rdi, rbx
    mov  rsi, r12
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exactly ECX hex nibbles, then caller checks exact delimiters/total length.
smpwork_async_hex:
    xor  r8d, r8d
    mov  esi, ecx
.next:
    movzx ecx, byte [rdi]
    call smpwork_nibble
    cmp  edx, 16
    jae  .bad
    shl  r8, 4
    or   r8, rdx
    inc  rdi
    dec  esi
    jnz  .next
    mov  rax, r8
    clc
    ret
.bad:
    stc
    ret

; Lean response through the existing SMP observation surface, under 160 bytes.
; EDI=status, RSI=response, EDX=nonce, RCX=handle. No staged snapshot on control.
smpwork_async_reply:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  byte [rel smpwork_out_ready], 0
    mov  byte [rel smpwork_out_buf], 0
    call smpobs_out_reset
    lea  rdi, [rel str_swa_prefix]
    call smpobs_put_str
    lea  rdi, [rel str_swa_malformed]
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ready
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .partial
    cmp  ebx, SMPWORK_ASYNC_PENDING
    jne  .busy
    lea  rdi, [rel str_swa_pending]
    jmp  .state
.ready:
    lea  rdi, [rel str_swa_ready]
    jmp  .state
.partial:
    lea  rdi, [rel str_swa_partial]
    jmp  .state
.busy:
    cmp  ebx, SMPWORK_ASYNC_BUSY
    jne  .stale
    lea  rdi, [rel str_swa_busy]
    jmp  .state
.stale:
    cmp  ebx, SMPWORK_ASYNC_STALE
    jne  .cancel
    lea  rdi, [rel str_swa_stale]
    jmp  .state
.cancel:
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .not_cancelled
    lea  rdi, [rel str_swa_cancelled]
    jmp  .state
.not_cancelled:
    cmp  ebx, SMPWORK_ASYNC_NOT_CANCELLED  ; refusal: finished work was kept
    jne  .clock
    lea  rdi, [rel str_swa_not_cancelled]
    jmp  .state
.clock:
    cmp  ebx, SMPWORK_ASYNC_CLOCK
    jne  .counter
    lea  rdi, [rel str_swa_clock]
    jmp  .state
.counter:
    cmp  ebx, SMPWORK_ASYNC_COUNTER
    jne  .topology
    lea  rdi, [rel str_swa_counter]
    jmp  .state
.topology:
    cmp  ebx, SMPWORK_ASYNC_TOPOLOGY
    jne  .state
    lea  rdi, [rel str_swa_topology]
.state:
    call smpobs_put_str
    lea  rdi, [rel str_swa_nonce]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_hex16
    lea  rdi, [rel str_swa_generation]
    call smpobs_put_str
    mov  rdi, r14
    call smpobs_put_hex16
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    cmp  ebx, SMPWORK_ASYNC_PENDING
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .out
.ok:
    mov  qword [r12 + RSP_CODE], CMDE_OK
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Versioned admission-only reply, under 256 bytes including CRLF.
; EDI=status, RSI=response, EDX/RCX=query nonce/generation, R8=copied record.
; Never reads retained slot cells after unlock. BUSY/STALE disclose no facts.
smpwork_async_detail_reply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    cmp  ebx, SMPWORK_ASYNC_BUSY
    je   .binding
    cmp  ebx, SMPWORK_ASYNC_STALE
    je   .binding
    mov  r13d, [r15 + 20]
    mov  r14, [r15 + 24]
.binding:
    mov  byte [rel smpwork_out_ready], 0
    mov  byte [rel smpwork_out_buf], 0
    call smpobs_out_reset
    lea  rdi, [rel str_swd_prefix]
    call smpobs_put_str
    lea  rdi, [rel str_swa_malformed]
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ready
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .partial
    cmp  ebx, SMPWORK_ASYNC_PENDING
    jne  .busy
    lea  rdi, [rel str_swa_pending]
    jmp  .state
.ready:
    lea  rdi, [rel str_swa_ready]
    jmp  .state
.partial:
    lea  rdi, [rel str_swa_partial]
    jmp  .state
.busy:
    cmp  ebx, SMPWORK_ASYNC_BUSY
    jne  .stale
    lea  rdi, [rel str_swa_busy]
    jmp  .state
.stale:
    cmp  ebx, SMPWORK_ASYNC_STALE
    jne  .cancel
    lea  rdi, [rel str_swa_stale]
    jmp  .state
.cancel:
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .clock
    lea  rdi, [rel str_swa_cancelled]
    jmp  .state
.clock:
    cmp  ebx, SMPWORK_ASYNC_CLOCK
    jne  .counter
    lea  rdi, [rel str_swa_clock]
    jmp  .state
.counter:
    cmp  ebx, SMPWORK_ASYNC_COUNTER
    jne  .topology
    lea  rdi, [rel str_swa_counter]
    jmp  .state
.topology:
    cmp  ebx, SMPWORK_ASYNC_TOPOLOGY
    jne  .state
    lea  rdi, [rel str_swa_topology]
.state:
    call smpobs_put_str
    lea  rdi, [rel str_swa_nonce]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_hex16
    lea  rdi, [rel str_swa_generation]
    call smpobs_put_str
    mov  rdi, r14
    call smpobs_put_hex16
    cmp  ebx, SMPWORK_ASYNC_BUSY
    je   .unknown
    cmp  ebx, SMPWORK_ASYNC_STALE
    je   .unknown
    lea  rdi, [rel str_swd_known]
    call smpobs_put_str
    mov  edi, [r15]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_result]
    call smpobs_put_str
    mov  edi, [r15 + 4]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_epoch]
    call smpobs_put_str
    mov  edi, [r15 + 8]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_mask]
    call smpobs_put_str
    mov  edi, [r15 + 12]
    call smpobs_put_hex16
    lea  rdi, [rel str_swd_expected]
    call smpobs_put_str
    mov  edi, [r15 + 16]
    call smpobs_put_dec
    jmp  .facts_done
.unknown:
    lea  rdi, [rel str_swd_unknown]
    call smpobs_put_str
.facts_done:
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    cmp  ebx, SMPWORK_ASYNC_PENDING
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .out
.ok:
    mov  qword [r12 + RSP_CODE], CMDE_OK
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Publication-only V1 wire, under320 bytes including CRLF. Same formatter
; ABI as DETAIL, R8 points to the private48-byte record. No global row reads.
smpwork_async_progress_reply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    cmp  ebx, SMPWORK_ASYNC_BUSY
    je   .binding
    cmp  ebx, SMPWORK_ASYNC_STALE
    je   .binding
    mov  r13d, [r15 + 20]
    mov  r14, [r15 + 24]
.binding:
    mov  byte [rel smpwork_out_ready], 0
    mov  byte [rel smpwork_out_buf], 0
    call smpobs_out_reset
    lea  rdi, [rel str_swp_prefix]
    call smpobs_put_str
    lea  rdi, [rel str_swa_malformed]
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ready
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .partial
    cmp  ebx, SMPWORK_ASYNC_PENDING
    jne  .busy
    lea  rdi, [rel str_swa_pending]
    jmp  .state
.ready:
    lea  rdi, [rel str_swa_ready]
    jmp  .state
.partial:
    lea  rdi, [rel str_swa_partial]
    jmp  .state
.busy:
    cmp  ebx, SMPWORK_ASYNC_BUSY
    jne  .stale
    lea  rdi, [rel str_swa_busy]
    jmp  .state
.stale:
    cmp  ebx, SMPWORK_ASYNC_STALE
    jne  .cancel
    lea  rdi, [rel str_swa_stale]
    jmp  .state
.cancel:
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .clock
    lea  rdi, [rel str_swa_cancelled]
    jmp  .state
.clock:
    cmp  ebx, SMPWORK_ASYNC_CLOCK
    jne  .counter
    lea  rdi, [rel str_swa_clock]
    jmp  .state
.counter:
    cmp  ebx, SMPWORK_ASYNC_COUNTER
    jne  .topology
    lea  rdi, [rel str_swa_counter]
    jmp  .state
.topology:
    cmp  ebx, SMPWORK_ASYNC_TOPOLOGY
    jne  .state
    lea  rdi, [rel str_swa_topology]
.state:
    call smpobs_put_str
    lea  rdi, [rel str_swa_nonce]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_hex16
    lea  rdi, [rel str_swa_generation]
    call smpobs_put_str
    mov  rdi, r14
    call smpobs_put_hex16
    cmp  ebx, SMPWORK_ASYNC_BUSY
    je   .unknown
    cmp  ebx, SMPWORK_ASYNC_STALE
    je   .unknown
    lea  rdi, [rel str_swd_known]
    call smpobs_put_str
    mov  edi, [r15]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_result]
    call smpobs_put_str
    mov  edi, [r15 + 4]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_epoch]
    call smpobs_put_str
    mov  edi, [r15 + 8]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_mask]
    call smpobs_put_str
    mov  edi, [r15 + 12]
    call smpobs_put_hex16
    lea  rdi, [rel str_swd_expected]
    call smpobs_put_str
    mov  edi, [r15 + 16]
    call smpobs_put_dec
    jmp  .facts_done
.unknown:
    lea  rdi, [rel str_swd_unknown]
    call smpobs_put_str
.facts_done:
    cmp  dword [r15 + 32], 1
    jne  .pub_unknown
    lea  rdi, [rel str_swp_known]
    call smpobs_put_str
    mov  edi, [r15 + 36]
    call smpobs_put_hex16
    lea  rdi, [rel str_swp_count]
    call smpobs_put_str
    mov  edi, [r15 + 40]
    call smpobs_put_dec
    jmp  .pub_done
.pub_unknown:
    lea  rdi, [rel str_swp_unknown]
    call smpobs_put_str
.pub_done:
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    cmp  ebx, SMPWORK_ASYNC_PENDING
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .out
.ok:
    mov  qword [r12 + RSP_CODE], CMDE_OK
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Final-only V1 wire: header<=202 +32*24 fixed hex row bytes =970.
; CRLF + NUL totals973, within SMPOBS_OUT_CAP. This route never
; sets smpwork_out_ready, so RESULTS cannot consume/masquerade as a POLL reply.
; All final facts come exclusively from the private448-byte copied record.
smpwork_async_results_reply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .copied_binding
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    jne  .binding
.copied_binding:
    mov  r13d, [r15 + 20]
    mov  r14, [r15 + 24]
.binding:
    mov  byte [rel smpwork_out_ready], 0
    mov  byte [rel smpwork_out_buf], 0
    call smpobs_out_reset
    lea  rdi, [rel str_swr_prefix]
    call smpobs_put_str
    lea  rdi, [rel str_swa_malformed]
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ready
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .partial
    cmp  ebx, SMPWORK_ASYNC_PENDING
    jne  .busy
    lea  rdi, [rel str_swa_pending]
    jmp  .state
.ready:
    lea  rdi, [rel str_swa_ready]
    jmp  .state
.partial:
    lea  rdi, [rel str_swa_partial]
    jmp  .state
.busy:
    cmp  ebx, SMPWORK_ASYNC_BUSY
    jne  .stale
    lea  rdi, [rel str_swa_busy]
    jmp  .state
.stale:
    cmp  ebx, SMPWORK_ASYNC_STALE
    jne  .cancel
    lea  rdi, [rel str_swa_stale]
    jmp  .state
.cancel:
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .clock
    lea  rdi, [rel str_swa_cancelled]
    jmp  .state
.clock:
    cmp  ebx, SMPWORK_ASYNC_CLOCK
    jne  .counter
    lea  rdi, [rel str_swa_clock]
    jmp  .state
.counter:
    cmp  ebx, SMPWORK_ASYNC_COUNTER
    jne  .topology
    lea  rdi, [rel str_swa_counter]
    jmp  .state
.topology:
    cmp  ebx, SMPWORK_ASYNC_TOPOLOGY
    jne  .state
    lea  rdi, [rel str_swa_topology]
.state:
    call smpobs_put_str
    lea  rdi, [rel str_swa_nonce]
    call smpobs_put_str
    mov  edi, r13d
    call smpobs_put_hex16
    lea  rdi, [rel str_swa_generation]
    call smpobs_put_str
    mov  rdi, r14
    call smpobs_put_hex16
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .known
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    jne  .unknown
.known:
    lea  rdi, [rel str_swr_known]
    call smpobs_put_str
    mov  edi, [r15 + 8]
    call smpobs_put_dec
    lea  rdi, [rel str_swd_mask]
    call smpobs_put_str
    mov  edi, [r15 + 12]
    call smpobs_put_hex16
    lea  rdi, [rel str_swd_expected]
    call smpobs_put_str
    mov  edi, [r15 + 16]
    call smpobs_put_dec
    lea  rdi, [rel str_swr_workers]
    call smpobs_put_str
    mov  edi, [r15 + 36]
    call smpobs_put_dec
    lea  rdi, [rel str_swr_rowmask]
    call smpobs_put_str
    mov  edi, [r15 + 32]
    call smpobs_put_hex16
    lea  rdi, [rel str_swr_audit]
    call smpobs_put_str
    mov  edi, [r15 + 40]
    call smpobs_put_dec
    mov  edi, [r15 + 44]
    call smpobs_put_dec
    mov  edi, [r15 + 48]
    call smpobs_put_dec
    lea  rdi, [rel str_sw_rows]
    call smpobs_put_str
    mov  r13d, [r15 + 32]
    test r13d, r13d
    jz   .empty
    xor  r14d, r14d
.rows:
    bt   r13d, r14d
    jnc  .next
    mov  edi, [r15 + 64 + r14*4]
    call smpwork_async_results_hex8
    mov  rdi, [r15 + 192 + r14*8]
    call smpobs_put_hex16
.next:
    inc  r14d
    cmp  r14d, MAXCORE
    jb   .rows
    jmp  .facts_done
.empty:
    lea  rdi, [rel str_sw_empty]
    call smpobs_put_str
    jmp  .facts_done
.unknown:
    lea  rdi, [rel str_swr_unknown]
    call smpobs_put_str
.facts_done:
    mov  byte [rel smpobs_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    cmp  ebx, SMPWORK_ASYNC_PENDING
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_COMPLETE
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_PARTIAL
    je   .ok
    cmp  ebx, SMPWORK_ASYNC_CANCELLED
    jne  .out
.ok:
    mov  qword [r12 + RSP_CODE], CMDE_OK
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Fixed8 lowercase nibbles, lossless u32 token, observation route only.
smpwork_async_results_hex8:
    lea  rsi, [rel smpobs_num_buf]
    mov  edx, 8
    call fmt_hex
    mov  byte [rel smpobs_num_buf + 8], 0
    lea  rdi, [rel smpobs_num_buf]
    jmp  smpobs_put_str

; smpwork_parse_u32(RDI=NUL text) -> EAX. This is the proven BLK numeric-parser
; sequence adapted to a NUL-terminated command argument: accept 0x-prefixed hex
; or decimal, stop at the first non-digit, and cap the shift loop at 8 nibbles.
; clobbers RAX,RCX,RDX,RSI,RDI
smpwork_parse_u32:
    xor  eax, eax
    test rdi, rdi
    jz   .done
    cmp  word [rdi], '0x'
    jne  .dec
    add  rdi, 2
    mov  esi, 8
.hex:
    test esi, esi
    jz   .done
    movzx ecx, byte [rdi]
    test cl, cl
    jz   .done
    call smpwork_nibble
    cmp  edx, 16
    jae  .done
    shl  eax, 4
    or   eax, edx
    inc  rdi
    dec  esi
    jmp  .hex
.dec:
    mov  esi, 10
.dec_next:
    test esi, esi
    jz   .done
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul eax, eax, 10
    add  eax, ecx
    inc  rdi
    dec  esi
    jmp  .dec_next
.done:
    ret

; smpwork_nibble(ECX=ASCII) -> EDX=0..15, or 16 when invalid.
smpwork_nibble:
    mov  edx, ecx
    sub  edx, '0'
    cmp  edx, 9
    jbe  .ok
    mov  edx, ecx
    or   edx, 0x20
    sub  edx, 'a'
    cmp  edx, 5
    ja   .bad
    add  edx, 10
.ok:
    ret
.bad:
    mov  edx, 16
    ret

smpobs_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call smpbench_clear

    mov  eax, [rel verb_id_smpstat]
    mov  [rel smpobs_kat_req + REQ_VERB], rax
    mov  qword [rel smpobs_kat_req + REQ_CAP], 0
    mov  qword [rel smpobs_kat_req + REQ_IDEM], 0
    mov  qword [rel smpobs_kat_req + REQ_SEL], 0
    lea  rax, [rel str_smpobs_kat_stat]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    cmp  dword [rel smpobs_out_buf], 'SMPS'
    jne  .fail
    cmp  dword [rel smpobs_out_buf + 4], 'TAT_'
    jne  .fail
    cmp  word [rel smpobs_out_buf + 8], 'V2'
    jne  .fail

    lea  rax, [rel str_smpobs_kat_bad_nonce]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_BADARG
    jne  .fail
    cmp  dword [rel smpobs_out_buf], 'ERR '
    jne  .fail

    ; Positional duplicates, unavailable logical IDs, and oversized text must
    ; all fail before any benchmark replay-cache state can change.
    lea  rax, [rel str_smpobs_kat_duplicate]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_BADARG
    jne  .fail

    lea  rax, [rel str_smpobs_kat_range]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_BADARG
    jne  .fail

    lea  rax, [rel str_smpobs_kat_oversized]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_BADARG
    jne  .fail
    cmp  dword [rel smpbench_used_count], 0
    jne  .fail

    mov  eax, [rel verb_id_smpbench]
    mov  [rel smpobs_kat_req + REQ_VERB], rax
    lea  rax, [rel str_smpobs_kat_bench]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    cmp  dword [rel smpobs_out_buf], 'SMPB'
    jne  .fail
    cmp  dword [rel smpobs_out_buf + 4], 'ENCH'
    jne  .fail
    cmp  dword [rel smpbench_used_count], 1
    jne  .fail
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    cmp  dword [rel smpbench_used_count], 1
    jne  .fail

    lea  rax, [rel str_smpobs_kat_reuse]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_BADARG
    jne  .fail
    cmp  dword [rel smpbench_used_count], 1
    jne  .fail

    ; J0 schema is exact, registry-generated, public and read-only.
    mov  eax, [rel verb_id_smpstat]
    mov  [rel smpobs_kat_req + REQ_VERB], rax
    lea  rax, [rel str_smpobs_kat_schema]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    lea  rdi, [rel smpobs_out_buf]
    lea  rsi, [rel str_smpobs_kat_schema_expected]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  edi, [rel verb_id_smpstat]
    call command_verb_cap
    test eax, eax
    jnz  .fail
    mov  edi, [rel verb_id_smpstat]
    call command_verb_destr
    test eax, eax
    jnz  .fail

    lea  rax, [rel str_smpobs_kat_health]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    mov  eax, [rel smp_load_snapshot_logical]
    cmp  eax, [rel smp_load_snapshot_healthy]
    jne  .fail
    cmp  dword [rel smp_load_snapshot_stalled], 0
    jne  .fail
    cmp  dword [rel smp_load_snapshot_ms], 0
    je   .fail

    ; Capture through the same registry handler, then independently recompute
    ; every aggregate from the immutable per-logical row storage.
    lea  rax, [rel str_smpobs_kat_load_chip]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    mov  ecx, [rel smp_load_snapshot_logical]
    test ecx, ecx
    jz   .fail
    cmp  ecx, [rel smp_topology_online]
    jne  .fail
    cmp  dword [rel smp_load_snapshot_seq], 0
    je   .fail
    cmp  dword [rel smp_load_snapshot_ms], 0
    je   .fail
    cmp  [rel smp_load_snapshot_healthy], ecx
    jne  .fail
    cmp  dword [rel smp_load_snapshot_stalled], 0
    jne  .fail
    xor  r12d, r12d                       ; logical cursor
    xor  r13d, r13d                       ; load sum
    xor  r14d, r14d                       ; runq total
    xor  r15d, r15d                       ; max load
    mov  ebx, 1001                        ; min load
    xor  r10d, r10d                       ; max runq
    xor  r11d, r11d                       ; first busiest logical
.load_reconcile:
    cmp  r12d, [rel smp_load_snapshot_logical]
    jae  .load_aggregate
    lea  rax, [rel smp_load_snapshot_load]
    mov  eax, [rax + r12*4]
    cmp  eax, 1000
    ja   .fail
    add  r13d, eax
    cmp  eax, r15d
    jbe  .load_max_ready
    mov  r15d, eax
    mov  r11d, r12d
.load_max_ready:
    cmp  eax, ebx
    jae  .load_min_ready
    mov  ebx, eax
.load_min_ready:
    lea  rax, [rel smp_load_snapshot_runq]
    mov  eax, [rax + r12*4]
    add  r14d, eax
    cmp  eax, r10d
    cmova r10d, eax
    lea  rax, [rel smp_load_snapshot_health]
    cmp  byte [rax + r12], 1
    jne  .fail
    inc  r12d
    jmp  .load_reconcile
.load_aggregate:
    cmp  r13d, [rel smp_load_snapshot_sum]
    jne  .fail
    cmp  r14d, [rel smp_load_snapshot_runq_total]
    jne  .fail
    cmp  r10d, [rel smp_load_snapshot_runq_max]
    jne  .fail
    cmp  r11d, [rel smp_load_snapshot_busiest]
    jne  .fail
    mov  eax, r15d
    sub  eax, ebx
    cmp  eax, [rel smp_load_snapshot_imbalance]
    jne  .fail
    mov  eax, r13d
    mov  ecx, [rel smp_load_snapshot_logical]
    mov  r8d, ecx
    shr  r8d, 1
    add  eax, r8d
    xor  edx, edx
    div  ecx
    cmp  eax, [rel smp_load_snapshot_mean]
    jne  .fail

    ; Format one stable CPU-row request, dispatch it first through the ordinary
    ; registry path, then through Task1079's typed in-process AI ingress.  Since
    ; CPU rows never advance the generation, byte identity proves one handler.
    call smpobs_kat_build_load_cpu
    lea  rax, [rel smpobs_kat_load_cpu]
    mov  [rel smpobs_kat_req + REQ_ARG], rax
    lea  rdi, [rel smpobs_kat_req]
    lea  rsi, [rel smpobs_kat_rsp]
    call command_dispatch
    cmp  qword [rel smpobs_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    lea  rdi, [rel smpobs_out_buf]
    call strlen
    inc  rax
    mov  rdx, rax
    lea  rdi, [rel smpobs_kat_registry_row]
    lea  rsi, [rel smpobs_out_buf]
    call memcpy
    mov  edi, [rel verb_id_smpstat]
    lea  rsi, [rel smpobs_kat_load_cpu]
    call command_aihook_submit
    cmp  rdx, CMDE_OK
    jne  .fail
    lea  rdi, [rel smpobs_kat_registry_row]
    lea  rsi, [rel smpobs_out_buf]
    call strcmp
    test eax, eax
    jnz  .fail
    call smp_frequency_snapshot_validate
    test eax, eax
    jz   .fail

    lea  rdi, [rel str_smp_aiops_schema_ok]
    call serial_string
    lea  rdi, [rel str_smp_aiops_snapshot_ok]
    call serial_string
    lea  rdi, [rel str_smp_aiops_aihook_ok]
    call serial_string
    lea  rdi, [rel str_smp_freq_schema_ok]
    call serial_string
    lea  rdi, [rel str_smp_freq_snapshot_ok]
    call serial_string
    lea  rdi, [rel str_smp_freq_aihook_ok]
    call serial_string
    lea  rdi, [rel str_smpobs_kat_ok]
    call serial_string
.fail:
    call smpbench_clear
    mov  byte [rel smpobs_out_ready], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Build "<nonce> LOAD 0 sample=<current>" with the canonical formatter.
smpobs_kat_build_load_cpu:
    push rbx
    lea  rdi, [rel str_smpobs_kat_load_cpu_prefix]
    call strlen
    mov  rbx, rax
    mov  rdx, rax
    lea  rdi, [rel smpobs_kat_load_cpu]
    lea  rsi, [rel str_smpobs_kat_load_cpu_prefix]
    call memcpy
    mov  edi, [rel smp_load_snapshot_seq]
    lea  rsi, [rel smpobs_kat_load_cpu]
    add  rsi, rbx
    call fmt_dec
    pop  rbx
    ret

; Register only after smp_selftest has bound the AP queues and earned its boot
; proof. Additive registry use keeps serial/UDP/in-process vocabulary identical.
smpwork_declare:
    lea  rdi, [rel str_verb_smpwork]
    lea  rsi, [rel cmd_verb_smpwork]
    xor  edx, edx                         ; explicit bounded public diagnostic exception (SEC-P2b)
    mov  ecx, ARGT_TEXT                    ; preserve and parse the 0x challenge
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_smpstat]
    lea  rsi, [rel cmd_verb_smpstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_smpstat], eax
    lea  rdi, [rel str_verb_smppolstat]
    lea  rsi, [rel cmd_verb_smppolstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_smppolstat], eax
    lea  rdi, [rel str_verb_smppolvalidate]
    lea  rsi, [rel cmd_verb_smppolvalidate]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_smppolvalidate], eax
    lea  rdi, [rel str_verb_smppolicy]
    lea  rsi, [rel cmd_verb_smppolicy]
    mov  rdx, CMD_AUTH_CAP_MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    mov  [rel verb_id_smppolicy], eax
    lea  rdi, [rel str_verb_smpbench]
    lea  rsi, [rel cmd_verb_smpbench]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_smpbench], eax
    call smpobs_selftest
    call smp_policy_selftest
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_smp_0 0
align 8
; smpobs_kat_req..smpwork_out_buf moved to WDATA_svc_command_smp_0_bss1 (zero-fill tail)

str_verb_smpwork: db "SMPWORK", 0
str_verb_smpstat: db "SMPSTAT", 0
str_verb_smpbench:db "SMPBENCH", 0
str_verb_smppolstat: db "SMPPOLSTAT", 0
str_verb_smppolvalidate: db "SMPPOLVALIDATE", 0
str_verb_smppolicy: db "SMPPOLICY", 0
str_smpstat_prefix: db "SMPSTAT_V1 nonce=", 0
str_smpstat_summary: db " view=summary configured=", 0
str_smpstat_enabled: db " enabled=", 0
str_smpstat_discovered: db " discovered=", 0
str_smpstat_online: db " online=", 0
str_smpstat_failed: db " failed=", 0
str_smpstat_bsp: db " bsp=", 0
str_smpstat_summary_tail: db " lapic=xapic scheduler=unified resched_ipi=0 tlb_epoch=0 crashes=", 0
str_smpstat_cpu: db " view=cpu logical=", 0
str_smpstat_apic: db " apic=", 0
str_smpstat_topology_unknown: db " uid=4294967295 package=4294967295 core=4294967295 thread=4294967295", 0
str_smpstat_state_bsp: db " state=bsp", 0
str_smpstat_state_online: db " state=online", 0
str_smpstat_cpu_local_absent: db " stack=0 tss=0 ist=0 timer=0 runq=", 0
str_smpstat_cpu_steal_in: db " current=unified preempt=0 steal_in=", 0
str_smpstat_cpu_steal_out: db " steal_out=", 0
str_smpstat_cpu_irq_tail: db " irq=0 faults=0", 0
str_smpstat_coherence: db " view=coherence", 0
str_smpbench_prefix: db "SMPBENCH_V1 nonce=", 0
str_smpbench_unsupported: db " state=unsupported mode=", 0
str_smpbench_accepted: db " state=accepted mode=", 0
str_smpbench_pending: db " state=pending mode=", 0
str_smpbench_done: db " state=done mode=", 0
str_smpbench_units: db " units=", 0
str_smpbench_digest: db " digest=", 0
str_smpbench_completed: db " completed=", 0
str_smpbench_expected: db " expected=", 0
str_smpbench_cores: db " cores=", 0
str_smpbench_cpu_units: db " cpu_units=", 0
str_smpbench_comma: db ",", 0
str_smpbench_migrations: db " migrations=", 0
str_smpbench_steals: db " steals=", 0
str_smpbench_preemptions: db " preemptions=", 0
str_smpbench_resched: db " resched_ipis=", 0
str_smpbench_idlewake: db " idle_wakes=", 0
str_smpbench_deadline: db " deadline_miss=", 0
str_smpbench_hostrx: db " host_rx_delta=", 0
str_smpbench_leaks: db " state_leaks=", 0
str_smpbench_double: db " double_run=", 0
str_smpbench_lost: db " lost=", 0
str_smpbench_faults: db " faults_contained=", 0
str_smpbench_stale: db " stale_mapping=", 0
str_smpbench_next: db " next=", 0
str_smpbench_seen: db " seen=", 0
str_smpbench_timer_mask: db " timer_mask=", 0
str_smpbench_required_timer_mask: db " required_timer_mask=", 0
str_smpbench_pending_reason: db " pending_reason=", 0
str_smpbench_reason_none: db "none", 0
str_smpbench_reason_if_clear: db "if_clear", 0
str_smpbench_reason_timer_mask: db "timer_mask", 0
str_smpbench_reason_ipi_ack: db "ipi_ack", 0
str_smpbench_reason_incomplete: db "incomplete", 0
str_smpbench_reason_double_run: db "double_run", 0
str_smpbench_pmod_dcr: db " pmod_dcr=", 0
str_smpbench_pmod_lvt: db " pmod_lvt=", 0
str_smpbench_pmod_icr: db " pmod_icr=", 0
str_smpbench_pmod_current: db " pmod_current=", 0
str_smpbench_irq0_delta: db " irq0_delta=", 0
str_smpbench_preempt0_delta: db " preempt0_delta=", 0
str_smpbench_restore_seq: db " pmod_restore_seq=", 0
str_smpbench_restore_ok: db " pmod_restore_ok=", 0
str_smpbench_post_pmod_test_ok: db " post_pmod_test_ok=", 0
str_smpbench_native_start: db " native_start_tsc=", 0
str_smpbench_native_end: db " native_end_tsc=", 0
str_smpbench_native_work_max: db " native_max_work_tsc=", 0
str_smpbench_native_khz: db " native_khz=", 0
str_smpbench_native_clock: db " native_clock=tsc_unverified", 0
str_smp_err_oversized: db "ERR SMP oversized", 0
str_smp_err_nonce: db "ERR SMP nonce", 0
str_smp_err_malformed: db "ERR SMP malformed", 0
str_smp_err_range: db "ERR SMP range", 0
str_smp_err_unsigned_cap: db "ERR SMP unsigned_limit units<=2048 no_soak (owner-sign this SMPBENCH)", 0
str_smp_err_reuse: db "ERR SMP reuse", 0
str_smp_err_capacity: db "ERR SMP capacity", 0
str_smp_err_reserved: db "ERR SMP capacity reserved", 0
str_smp_err_unknown: db "ERR SMP unknown", 0
str_smpobs_kat_stat: db "0123456789abcdef SUMMARY", 0
str_smpobs_kat_bad_nonce: db "0123456789abcdeF SUMMARY", 0
str_smpobs_kat_duplicate: db "0123456789abcdef SUMMARY SUMMARY", 0
str_smpobs_kat_range: db "0123456789abcdef CPU 4294967295", 0
str_smpobs_kat_oversized: times (SMPOBS_ARG_MAX + 1) db 'x'
    db 0
str_smpobs_kat_bench: db "START probe fedcba9876543210 1", 0
str_smpobs_kat_reuse: db "START other fedcba9876543210 1", 0
str_smpobs_kat_schema: db "0123456789abcdef SCHEMA", 0
str_smpobs_kat_schema_expected: db "SMPSTAT_V2 nonce=0123456789abcdef view=schema selectors=SUMMARY,CPU,HEALTH,LOAD,SCHEMA ai_projection=registry sample_model=stable_snapshot frequency_model=passive_aperfmperf effect=read", 0
str_smpobs_kat_health: db "0123456789abcdef HEALTH", 0
str_smpobs_kat_load_chip: db "0123456789abcdef LOAD CHIP", 0
str_smpobs_kat_load_cpu_prefix: db "0123456789abcdef LOAD 0 sample=", 0
str_smp_aiops_schema_ok: db "[PAOS64] SMP AI ops: registry schema/load/health KAT PASS [smp.aiops.schema.ok]", 13, 10, 0
str_smp_aiops_snapshot_ok: db "[PAOS64] SMP AI ops: whole-chip/per-logical snapshot reconciliation KAT PASS [smp.aiops.load.snapshot.ok]", 13, 10, 0
str_smp_aiops_aihook_ok: db "[PAOS64] SMP AI ops: registry and in-process AI-hook LOAD fields identical [smp.aiops.aihook.parity.ok]", 13, 10, 0
str_smp_freq_schema_ok: db "[PAOS64] SMP frequency: passive typed schema/capability KAT PASS [smp.freq.passive.schema.ok]", 13, 10, 0
str_smp_freq_snapshot_ok: db "[PAOS64] SMP frequency: own-core snapshot arithmetic/reconciliation KAT PASS [smp.freq.snapshot.reconcile.ok]", 13, 10, 0
str_smp_freq_aihook_ok: db "[PAOS64] SMP frequency: registry and AI-hook typed fields identical [smp.freq.aihook.parity.ok]", 13, 10, 0
str_smpobs_kat_ok: db "[PAOS64] SMP observability: nonce/schema/grammar selftest PASS [smp.observe.schema.ok]", 13, 10, 0
str_sw_compact: db " format=compact output=complete snapshot=", 0
str_sw_complete: db "complete", 0
str_sw_partial: db "partial", 0
str_sw_expected: db " expected=", 0
str_sw_rows: db " rows=", 0
str_sw_separator: db ";", 0
str_sw_colon: db ":", 0
str_sw_empty: db "-", 0
str_swr_prefix: db "SMPWORK_RESULTS_V1 state=", 0
str_swr_known: db " known=1 epoch=", 0
str_swr_workers: db " workers=", 0
str_swr_rowmask: db " rowmask=0x", 0
str_swr_audit: db " audit=", 0
str_swr_unknown: db " known=0 epoch=unknown mask=unknown expected=unknown workers=unknown rowmask=unknown audit=unknown rows=unknown", 0
str_swp_prefix: db "SMPWORK_PROGRESS_V1 state=", 0
str_swp_known: db " pub_known=1 published_mask=0x", 0
str_swp_count: db " published=", 0
str_swp_unknown: db " pub_known=0 published_mask=unknown published=unknown", 0
str_swd_prefix: db "SMPWORK_DETAIL_V1 state=", 0
str_swd_known: db " known=1 phase=", 0
str_swd_result: db " result=", 0
str_swd_epoch: db " epoch=", 0
str_swd_mask: db " mask=0x", 0
str_swd_expected: db " expected=", 0
str_swd_unknown: db " known=0 phase=unknown result=unknown epoch=unknown mask=unknown expected=unknown", 0
str_swa_prefix: db "SMPWORK_ASYNC state=", 0
str_swa_pending: db "PENDING", 0
str_swa_ready: db "READY", 0
str_swa_partial: db "PARTIAL", 0
str_swa_busy: db "BUSY", 0
str_swa_stale: db "STALE", 0
str_swa_cancelled: db "CANCELLED", 0
str_swa_not_cancelled: db "NOT_CANCELLED", 0
str_swa_clock: db "CLOCK", 0
str_swa_counter: db "COUNTER", 0
str_swa_topology: db "TOPOLOGY", 0
str_swa_malformed: db "MALFORMED", 0
str_swa_nonce: db " nonce=0x", 0
str_swa_generation: db " generation=0x", 0
str_sw_error: db "ERR SMPWORK nonce=0x", 0
str_sw_reason: db " reason=", 0
str_sw_inconsistent: db "snapshot_inconsistent", 0
str_sw_zero_epoch: db "snapshot_epoch_zero", 0
str_sw_bounds: db "output_bounds", 0
str_sw_pre:       db " SMPWORK nonce=0x", 0
str_sw_epoch:     db " epoch=", 0
str_sw_workers:   db " workers=", 0
str_sw_core:      db " core=", 0
str_sw_token:     db ",token=0x", 0
str_sw_runs:      db ",runs=", 0
str_sw_rq:        db " rq_audit=", 0
str_sw_rt:        db " rt_bsp=", 0
str_sw_boot:      db " boot_bsp=", 0
%endmacro
WDATA_DEFER WDATA_svc_command_smp_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_smp_0_bss1 0
alignb 8
smpobs_kat_req:       resb REQ_SZ
smpobs_kat_rsp:       resb RSP_SZ
smpobs_kat_load_cpu:  resb SMPOBS_ARG_MAX + 1
smpobs_kat_registry_row: resb SMPOBS_OUT_CAP
smpbench_slots:       resb (SMPBENCH_SLOTS * SMPBENCH_SLOT_SIZE)
smpbench_used_count:  resd 1
smpbench_clock:       resd 1                ; reaper seconds since boot
smpbench_untimed_ticks: resd 1
smpbench_last_drive:  resd 1
smpbench_reaped_total: resd 1
smpbench_driven_total: resd 1
alignb 8
smpbench_last_ms:     resq 1
smpbench_req_unsigned: resb 1
verb_id_smpstat:      resd 1
verb_id_smpbench:     resd 1
verb_id_smppolstat:   resd 1
verb_id_smppolvalidate: resd 1
verb_id_smppolicy:    resd 1
smpobs_out_cur:       resq 1
smpobs_out_ready:     resb 1
alignb 8
smpobs_out_buf:       resb SMPOBS_OUT_CAP
smpobs_num_buf:       resb 32
alignb 8
smpwork_out_cur:   resq 1
smpwork_out_ready: resb 1
alignb 8
smpwork_out_buf:   resb SMPWORK_OUT_CAP
smpwork_out_limit: resq 1
smpwork_out_failed: resb 1
smpwork_num_buf:   resb 32
alignb 4
smpwork_output_expected: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_smp_0_bss1
; RCQ-12 track 2 option A: the SMPBENCH parfor reply.
%macro WDATA_svc_command_smp_parfor 0
str_smpbench_pf_match:    db " state=complete mode=parfor match=", 0
str_smpbench_pf_chunks:   db " chunks=", 0
str_smpbench_pf_par:      db " par_passes=", 0
str_smpbench_pf_timeouts: db " timeouts=", 0
str_smpbench_pf_ap:       db " ap_chunks=", 0
str_smpbench_pf_stalled:  db " state=stalled mode=parfor", 0
%endmacro
WDATA_DEFER WDATA_svc_command_smp_parfor
%macro WDATA_svc_command_smp_hostrx 0
alignb 8
smpbench_host_rx_handle: resq 1            ; NIC bound at START; 0 = host RX unknown
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_smp_hostrx

; ---------------------------------------------------------------------------
; Task1330j policy control plane (EOF body keeps the existing module hot paths
; stable).  All three projections use the one registry and one staged output.
; ---------------------------------------------------------------------------

; Parse balanced/physical_first. EAX=profile, RDX=first trailing byte.
smp_policy_parse_profile:
    cmp  dword [rdi], 'bala'
    jne  .physical
    cmp  dword [rdi + 4], 'nced'
    jne  .bad
    xor  eax, eax
    lea  rdx, [rdi + 8]
    clc
    ret
.physical:
    cmp  dword [rdi], 'phys'
    jne  .bad
    cmp  dword [rdi + 4], 'ical'
    jne  .bad
    cmp  dword [rdi + 8], '_fir'
    jne  .bad
    cmp  word [rdi + 12], 'st'
    jne  .bad
    mov  eax, SMP_POLICY_PHYSICAL_FIRST
    lea  rdx, [rdi + 14]
    clc
    ret
.bad:
    stc
    ret

smp_policy_put_profile:
    cmp  edi, SMP_POLICY_PHYSICAL_FIRST
    je   .physical
    lea  rdi, [rel str_smppol_balanced]
    jmp  smpobs_put_str
.physical:
    lea  rdi, [rel str_smppol_physical]
    jmp  smpobs_put_str

smp_policy_begin_reply:
    push rdi
    push rsi
    call smpobs_out_reset
    pop  rdi
    call smpobs_put_str
    pop  rdi
    call smpobs_put_hex16
    ret

smp_policy_put_invariants:
    lea  rdi, [rel str_smppol_invariants]
    call smpobs_put_str
    ret

; Resolve the exact generation for APPLY. RDI=request, ESI=supplied value,
; EDX=1 when explicitly supplied. An omitted fresh request snapshots current
; generation; an omitted replay recovers the generation bound to its receipt.
smp_policy_resolve_apply_generation:
    mov  eax, esi
    test edx, edx
    jnz  .out
    mov  eax, [rel sched_smp_policy_generation]
    cmp  byte [rel sched_smp_policy_last_valid], 1
    jne  .out
    cmp  rdi, [rel sched_smp_policy_last_request]
    jne  .out
    mov  eax, [rel sched_smp_policy_last_requested_generation]
.out:
    ret

cmd_verb_smppolstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rdi, [rdi + REQ_ARG]
    mov  rbx, rdi
    call smpobs_arg_bounded
    jc   .oversized
    mov  rdi, rbx
    call smpobs_parse_nonce
    jc   .nonce
    cmp  byte [rdx], 0
    jne  .malformed
    mov  r12, rax
    mov  rdi, r12
    lea  rsi, [rel str_smppolstat_prefix]
    call smp_policy_begin_reply
    lea  rdi, [rel str_smppol_profile]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_profile]
    call smp_policy_put_profile
    lea  rdi, [rel str_smppol_generation]
    call smpobs_put_str
    mov  edi, [rel sched_smp_policy_generation]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_previous_profile]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_previous_profile]
    call smp_policy_put_profile
    lea  rdi, [rel str_smppol_previous_generation]
    call smpobs_put_str
    mov  edi, [rel sched_smp_policy_previous_generation]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_audit]
    call smpobs_put_str
    mov  edi, [rel sched_smp_policy_last_audit]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_auto]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_auto_rollback]
    call smpobs_put_dec
    call smp_policy_put_invariants
    mov  rsi, r13
    call smpobs_finish_ok
    jmp  .out
.oversized:
    lea  rdi, [rel str_smp_err_oversized]
    jmp  .error
.nonce:
    lea  rdi, [rel str_smp_err_nonce]
    jmp  .error
.malformed:
    lea  rdi, [rel str_smp_err_malformed]
.error:
    mov  rsi, r13
    call smpobs_stage_error
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_smppolvalidate:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r14, rsi
    mov  rdi, [rdi + REQ_ARG]
    mov  rbx, rdi
    call smpobs_arg_bounded
    jc   .oversized
    mov  rdi, rbx
    call smpobs_parse_nonce
    jc   .nonce
    mov  r12, rax
    mov  rbx, rdx
    cmp  dword [rbx], ' pro'
    jne  .malformed
    cmp  dword [rbx + 4], 'file'
    jne  .malformed
    cmp  byte [rbx + 8], '='
    jne  .malformed
    lea  rdi, [rbx + 9]
    call smp_policy_parse_profile
    jc   .unsupported
    cmp  byte [rdx], 0
    jne  .malformed
    mov  r13d, eax
    mov  rdi, r12
    lea  rsi, [rel str_smppolvalidate_prefix]
    call smp_policy_begin_reply
    lea  rdi, [rel str_smppol_profile]
    call smpobs_put_str
    mov  edi, r13d
    call smp_policy_put_profile
    lea  rdi, [rel str_smppol_validate_ok]
    call smpobs_put_str
    call smp_policy_put_invariants
    mov  rsi, r14
    call smpobs_finish_ok
    jmp  .out
.oversized:
    lea  rdi, [rel str_smp_err_oversized]
    jmp  .error
.nonce:
    lea  rdi, [rel str_smp_err_nonce]
    jmp  .error
.unsupported:
    lea  rdi, [rel str_smppol_err_unsupported]
    jmp  .error
.malformed:
    lea  rdi, [rel str_smp_err_malformed]
.error:
    mov  rsi, r14
    call smpobs_stage_error
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_smppolicy:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi
    mov  rdi, [rdi + REQ_ARG]
    mov  rbx, rdi
    call smpobs_arg_bounded
    jc   .oversized
    mov  rdi, rbx
    call smpobs_parse_nonce
    jc   .nonce
    mov  [rel smp_policy_nonce_tmp], rax
    mov  rbx, rdx
    cmp  dword [rbx], ' APP'
    jne  .check_rollback
    cmp  word [rbx + 4], 'LY'
    jne  .malformed
    cmp  dword [rbx + 6], ' pro'
    jne  .malformed
    cmp  dword [rbx + 10], 'file'
    jne  .malformed
    cmp  byte [rbx + 14], '='
    jne  .malformed
    lea  rdi, [rbx + 15]
    call smp_policy_parse_profile
    jc   .unsupported
    mov  r13d, eax
    mov  rbx, rdx
    xor  r14, r14                    ; bit 32 clear: generation omitted
    cmp  dword [rbx], ' gen'
    jne  .apply_request
    cmp  dword [rbx + 4], 'erat'
    jne  .malformed
    cmp  dword [rbx + 8], 'ion='
    jne  .malformed
    lea  rdi, [rbx + 12]
    call smpobs_parse_dec
    jc   .malformed
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    ja   .malformed
    mov  r14d, eax
    bts  r14, 32                     ; caller supplied an exact generation
    mov  rbx, rdx
.apply_request:
    call smp_policy_parse_request
    jc   .malformed
    mov  r12, rax
    xor  edx, edx
    bt   r14, 32
    adc  edx, 0
    mov  rdi, r12
    mov  esi, r14d
    call smp_policy_resolve_apply_generation
    mov  r14d, eax
    mov  edi, r13d
    mov  esi, r14d
    mov  rdx, r12
    call sched_smp_policy_apply
    mov  ebx, eax
    cmp  eax, SMP_POLICY_TX_OK
    je   .format_apply
    cmp  eax, SMP_POLICY_TX_REPLAY
    je   .format_apply
    jmp  .transaction_error
.format_apply:
    mov  rdi, [rel smp_policy_nonce_tmp]
    lea  rsi, [rel str_smppolicy_prefix]
    call smp_policy_begin_reply
    lea  rdi, [rel str_smppol_operation_apply]
    call smpobs_put_str
    jmp  .format_common

.check_rollback:
    cmp  dword [rbx], ' ROL'
    jne  .malformed
    cmp  dword [rbx + 4], 'LBAC'
    jne  .malformed
    cmp  byte [rbx + 8], 'K'
    jne  .malformed
    cmp  dword [rbx + 9], ' gen'
    jne  .malformed
    cmp  dword [rbx + 13], 'erat'
    jne  .malformed
    cmp  dword [rbx + 17], 'ion='
    jne  .malformed
    lea  rdi, [rbx + 21]
    call smpobs_parse_dec
    jc   .malformed
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    ja   .malformed
    mov  r14d, eax
    mov  rbx, rdx
    cmp  dword [rbx], ' pro'
    jne  .malformed
    cmp  dword [rbx + 4], 'file'
    jne  .malformed
    cmp  byte [rbx + 8], '='
    jne  .malformed
    lea  rdi, [rbx + 9]
    call smp_policy_parse_profile
    jc   .unsupported
    mov  r13d, eax
    mov  rbx, rdx
    call smp_policy_parse_request
    jc   .malformed
    mov  r12, rax
    mov  edi, r13d
    mov  esi, r14d
    mov  rdx, r12
    call sched_smp_policy_rollback
    mov  ebx, eax
    cmp  eax, SMP_POLICY_TX_OK
    je   .format_rollback
    cmp  eax, SMP_POLICY_TX_REPLAY
    je   .format_rollback
    jmp  .transaction_error
.format_rollback:
    mov  rdi, [rel smp_policy_nonce_tmp]
    lea  rsi, [rel str_smppolicy_prefix]
    call smp_policy_begin_reply
    lea  rdi, [rel str_smppol_operation_rollback]
    call smpobs_put_str

.format_common:
    lea  rdi, [rel str_smppol_profile]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_profile]
    call smp_policy_put_profile
    lea  rdi, [rel str_smppol_generation]
    call smpobs_put_str
    mov  edi, [rel sched_smp_policy_generation]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_request]
    call smpobs_put_str
    mov  rdi, [rel smp_policy_request_tmp]
    call smpobs_put_hex16
    lea  rdi, [rel str_smppol_replay]
    call smpobs_put_str
    xor  edi, edi
    cmp  ebx, SMP_POLICY_TX_REPLAY
    sete dil
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_audit]
    call smpobs_put_str
    mov  edi, [rel sched_smp_policy_last_audit]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_rolled_back]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_last_rolled_back]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_auto]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_auto_rollback]
    call smpobs_put_dec
    lea  rdi, [rel str_smppol_effect]
    call smpobs_put_str
    movzx edi, byte [rel sched_smp_policy_profile]
    call smp_policy_put_profile
    call smp_policy_put_invariants
    mov  rsi, r15
    call smpobs_finish_ok
    jmp  .out

.transaction_error:
    cmp  ebx, SMP_POLICY_TX_UNSUPPORTED
    je   .unsupported
    cmp  ebx, SMP_POLICY_TX_STALE
    je   .stale
    cmp  ebx, SMP_POLICY_TX_COLLISION
    je   .collision
    lea  rdi, [rel str_smppol_err_health]
    jmp  .error
.oversized:
    lea  rdi, [rel str_smp_err_oversized]
    jmp  .error
.nonce:
    lea  rdi, [rel str_smp_err_nonce]
    jmp  .error
.unsupported:
    lea  rdi, [rel str_smppol_err_unsupported]
    jmp  .error
.stale:
    lea  rdi, [rel str_smppol_err_stale]
    jmp  .error
.collision:
    lea  rdi, [rel str_smppol_err_collision]
    jmp  .error
.malformed:
    lea  rdi, [rel str_smp_err_malformed]
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

; RBX=space before request; RAX=request, CF clear on exact grammar.
smp_policy_parse_request:
    cmp  dword [rbx], ' req'
    jne  .bad
    cmp  dword [rbx + 4], 'uest'
    jne  .bad
    cmp  byte [rbx + 8], '='
    jne  .bad
    lea  rdi, [rbx + 9]
    call smpobs_parse_nonce
    jc   .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  [rel smp_policy_request_tmp], rax
    clc
    ret
.bad:
    stc
    ret

; Hostile boot fixture: unsupported/stale/collision, exact replay+rollback,
; forced health-regression auto-rollback, and unsigned AI-hook denial. Restore
; the safe boot default afterwards so the KAT cannot become runtime policy.
smp_policy_selftest:
    push rbx
    call sched_smp_policy_init
    mov  edi, 2
    mov  esi, 1
    mov  rdx, 0x1330A001
    call sched_smp_policy_apply
    cmp  eax, SMP_POLICY_TX_UNSUPPORTED
    jne  .fail
    mov  edi, SMP_POLICY_PHYSICAL_FIRST
    mov  esi, 2
    mov  rdx, 0x1330A002
    call sched_smp_policy_apply
    cmp  eax, SMP_POLICY_TX_STALE
    jne  .fail
    mov  edi, SMP_POLICY_PHYSICAL_FIRST
    mov  esi, 1
    mov  rdx, 0x1330A003
    call sched_smp_policy_apply
    cmp  eax, SMP_POLICY_TX_OK
    jne  .fail
    ; Exercise the command layer's omitted-generation binding. This is the
    ; live replay boundary: after 1->2, request A003 must still resolve to 1,
    ; while a different request resolves to current generation 2.
    mov  rdi, 0x1330A003
    xor  esi, esi
    xor  edx, edx
    call smp_policy_resolve_apply_generation
    cmp  eax, 1
    jne  .fail
    mov  rdi, 0x1330A0FF
    xor  esi, esi
    xor  edx, edx
    call smp_policy_resolve_apply_generation
    cmp  eax, 2
    jne  .fail
    mov  ebx, [rel sched_smp_policy_last_audit]
    mov  edi, SMP_POLICY_PHYSICAL_FIRST
    mov  esi, 1
    mov  rdx, 0x1330A003
    call sched_smp_policy_apply
    cmp  eax, SMP_POLICY_TX_REPLAY
    jne  .fail
    cmp  ebx, [rel sched_smp_policy_last_audit]
    jne  .fail
    mov  edi, SMP_POLICY_BALANCED
    mov  esi, 1
    mov  rdx, 0x1330A003
    call sched_smp_policy_rollback
    cmp  eax, SMP_POLICY_TX_COLLISION
    jne  .fail
    mov  edi, SMP_POLICY_BALANCED
    mov  esi, 1
    mov  rdx, 0x1330A004
    call sched_smp_policy_rollback
    cmp  eax, SMP_POLICY_TX_OK
    jne  .fail
    cmp  byte [rel sched_smp_policy_profile], SMP_POLICY_BALANCED
    jne  .fail
    cmp  dword [rel sched_smp_policy_generation], 1
    jne  .fail
    mov  byte [rel sched_smp_policy_test_force_health_bad], 1
    mov  edi, SMP_POLICY_PHYSICAL_FIRST
    mov  esi, 1
    mov  rdx, 0x1330A005
    call sched_smp_policy_apply
    mov  byte [rel sched_smp_policy_test_force_health_bad], 0
    cmp  eax, SMP_POLICY_TX_HEALTH
    jne  .fail
    cmp  byte [rel sched_smp_policy_profile], SMP_POLICY_BALANCED
    jne  .fail
    cmp  dword [rel sched_smp_policy_generation], 1
    jne  .fail
    mov  edi, [rel verb_id_smppolicy]
    lea  rsi, [rel str_smppol_kat_ai_arg]
    call command_aihook_submit
    cmp  rdx, CMDE_AUTHDENY
    jne  .fail
    mov  byte [rel command_auth_out_ready], 0
    call sched_smp_policy_init
    lea  rdi, [rel str_smppol_kat_ok]
    call serial_string
.fail:
    mov  byte [rel sched_smp_policy_test_force_health_bad], 0
    mov  byte [rel smpobs_out_ready], 0
    pop  rbx
    ret

align 8
smp_policy_nonce_tmp: dq 0
smp_policy_request_tmp: dq 0
str_smppol_balanced: db "balanced", 0
str_smppol_physical: db "physical_first", 0
str_smppolstat_prefix: db "SMPPOLSTAT nonce=", 0
str_smppolvalidate_prefix: db "SMPPOLVALIDATE nonce=", 0
str_smppolicy_prefix: db "SMPPOLICY nonce=", 0
str_smppol_profile: db " profile=", 0
str_smppol_generation: db " generation=", 0
str_smppol_previous_profile: db " previous_profile=", 0
str_smppol_previous_generation: db " previous_generation=", 0
str_smppol_validate_ok: db " valid=1 mutated=0", 0
str_smppol_operation_apply: db " operation=apply", 0
str_smppol_operation_rollback: db " operation=rollback", 0
str_smppol_request: db " request=", 0
str_smppol_replay: db " replay=", 0
str_smppol_audit: db " audit=", 0
str_smppol_rolled_back: db " rolled_back=", 0
str_smppol_auto: db " auto_rollback=", 0
str_smppol_effect: db " observed_effect=", 0
str_smppol_invariants: db " critical_tasks=protected online_change=0 smt_change=0 topology_change=0 effect=scheduling_preference", 0
str_smppol_err_unsupported: db "ERR SMPPOLICY unsupported_profile", 0
str_smppol_err_stale: db "ERR SMPPOLICY stale_generation", 0
str_smppol_err_collision: db "ERR SMPPOLICY request_collision", 0
str_smppol_err_health: db "ERR SMPPOLICY health_regression auto_rollback=1", 0
str_smppol_kat_ai_arg: db "0123456789abcdef APPLY profile=physical_first request=1330a0061330a006", 0
str_smppol_kat_ok: db "[PAOS64] SMP AI ops: authenticated idempotent policy rollback KAT PASS [smp.aiops.policy.rollback.ok]", 13, 10, 0

; Per-pass PARFOR decision observations (BSP snapshot, no new verb).
str_smpbench_pf_fill_gen: db " fill_gen=", 0
str_smpbench_pf_fill_expected: db " fill_expected=", 0
str_smpbench_pf_fill_seen: db " fill_seen=", 0
str_smpbench_pf_fill_expired: db " fill_expired=", 0
str_smpbench_pf_fill_ap: db " fill_ap=", 0
str_smpbench_pf_copy_gen: db " copy_gen=", 0
str_smpbench_pf_copy_expected: db " copy_expected=", 0
str_smpbench_pf_copy_seen: db " copy_seen=", 0
str_smpbench_pf_copy_expired: db " copy_expired=", 0
str_smpbench_pf_copy_ap: db " copy_ap=", 0
