;; MODULE core/log
;; LAYER 1
;; EXPORTS log_render, log_line, logfmt_selftest, security_truth_catalog_selftest, boot_log_mode_select, boot_log_mode_policy_kat, boot_timeline_init, boot_timeline_latch, boot_timeline_special_register, boot_timeline_overflow_kat, boot_timeline_ordering_kat, boot_timeline_token_ptr, boot_timeline_records, boot_timeline_count, boot_timeline_dropped, log_cost_serial_tsc, log_cost_ring_tsc, log_cost_capture_tsc, tok_boot_ab_verify, tok_boot_ab_loaded, tok_boot_wdog_arm, tok_boot_wdog_none, tok_boot_ab_commit, tok_boot_p7, tok_boot_p8_warm, tok_boot_p8_ready, tok_boot_hv_ready, boot_log_mode, boot_log_trigger
;; IMPORTS core/lib/fmt, core/lib/str, core/diag, boot/serial
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/log.asm — the ONE canonical structured leveled log path (MODULES §3).
;
; Renders "[PAOS64][<LVL>][<sub>] <msg>\r\n" — a namespaced, greppable, parseable
; line — through core/lib/fmt (never its own formatter: G1). Two entry points:
;   log_render  builds the line into a caller buffer (pure, testable) and
;   log_line    renders into the shared line buffer and flushes to serial.
; This replaces the monolith's lone log_emit and the scattered ad-hoc
; "serial_string + serial_hex64" print sites: from L1 up, output goes through
; here so every line has the same shape and one place to change it.
;
; DEGRADE (TESTING §4): native ordinary output after P2 detail selection uses
; the image-owned FIFO in either detail mode, then non-blocking idle-loop drain.
; Full queues and IF=0/fault diagnostics keep the bounded synchronous UART
; boundary. Hypervisor output stays synchronous for midboot injection markers.
;
; TOURNAMENT (TESTING §7): candidates for the render — (A) one fmt_str-append per
; field tracking a running offset  (B) a printf-style %-format mini-parser  (C)
; hand-inlined string copies. WINNER A: correct, simplest, reuses fmt_str only
; (no new parser, no duplicate copy loop — the simple/no-dup axis), and each
; field is independently a fmt_* call so adding one is additive.
; ============================================================================

LOG_DBG  equ 0
LOG_INF  equ 1
LOG_WRN  equ 2
LOG_ERR  equ 3
LOG_FTL  equ 4

SELFTEST_VERDICT_PASS    equ 1
SELFTEST_VERDICT_FAIL    equ 2
SELFTEST_VERDICT_SKIPPED equ 3
SELFTEST_VERDICT_CAT_SIZE equ 16
SELFTEST_VERDICT_REC_SIZE equ 24
SELFTEST_VERDICT_MAX      equ 64
BOOT_TIMELINE_MAX         equ 256
BOOT_TIMELINE_REC_SIZE    equ 10       ; packed {marker_id:u16, first_tsc:u64}
BOOT_TIMELINE_SPECIAL_MAX equ 16
BOOT_WAIT_MAX             equ 32
BOOT_WAIT_REC_SIZE        equ 48
BOOT_WAIT_CLASS_IO        equ 5
BOOT_WAIT_OUTCOME_OK      equ 1
BOOT_WAIT_PHASE_UNKNOWN   equ 255     ; explicit unattributed raw remainder, never P255
BOOT_WAIT_OBSERVER_TAX_BUDGET_MS equ 20
BOOT_WAIT_SERIAL_BUDGET_MS equ 5000

LOG_MODE_VERBOSE equ 0
LOG_MODE_LEAN    equ 1

LOG_TRIGGER_CLEAN    equ 0
LOG_TRIGGER_TRIAL    equ 1
LOG_TRIGGER_FAULTS   equ 2
LOG_TRIGGER_FIRST    equ 3
LOG_TRIGGER_OVERRIDE equ 4

; boot_log_mode_decide -- pure fail-open policy used by both production and the
; in-image KAT.  Inputs: EDI=prior trial (-1 means unreadable), ESI=prior-ring
; state (DIAG_PREV_*), RDX=prior faults_total, ECX=override (0=AUTO, 1=LEAN,
; 2=VERBOSE, any other nonzero is malformed).  Returns mode in AL and trigger
; in AH.  No recording path consults this result; it controls serial only.
boot_log_mode_decide:
    test ecx, ecx
    jz   .auto
    cmp  ecx, LOG_MODE_LEAN
    je   .override_lean
    mov  al, LOG_MODE_VERBOSE            ; explicit VERBOSE or malformed: fail open
    mov  ah, LOG_TRIGGER_OVERRIDE
    ret
.override_lean:
    mov  al, LOG_MODE_LEAN
    mov  ah, LOG_TRIGGER_OVERRIDE
    ret
.auto:
    test edi, edi
    js   .first                          ; unreadable CMOS is doubt, never lean
    jnz  .trial
    cmp  esi, DIAG_PREV_VALID
    je   .valid_ring
    cmp  esi, DIAG_PREV_NONE
    je   .first
    jmp  .faults                         ; malformed retained ring is trouble
.valid_ring:
    test rdx, rdx
    jnz  .faults
    mov  al, LOG_MODE_LEAN
    mov  ah, LOG_TRIGGER_CLEAN
    ret
.trial:
    mov  al, LOG_MODE_VERBOSE
    mov  ah, LOG_TRIGGER_TRIAL
    ret
.faults:
    mov  al, LOG_MODE_VERBOSE
    mov  ah, LOG_TRIGGER_FAULTS
    ret
.first:
    mov  al, LOG_MODE_VERBOSE
    mov  ah, LOG_TRIGGER_FIRST
    ret

; Inputs match boot_log_mode_decide.  Record and announce the selected policy;
; all messages are emitted before the fixed native FIFO is bound.
boot_log_mode_select:
    call boot_log_mode_decide
    mov  [rel boot_log_mode], al
    mov  [rel boot_log_trigger], ah
    cmp  al, LOG_MODE_LEAN
    jne  .verbose
    mov  edi, BOOT_TIMELINE_ID_LOG_MODE_LEAN
    call boot_timeline_latch
    lea  rdi, [rel str_boot_log_mode_lean]
    call serial_string
    jmp  .trigger
.verbose:
    mov  edi, BOOT_TIMELINE_ID_LOG_MODE_VERBOSE
    call boot_timeline_latch
    lea  rdi, [rel str_boot_log_mode_verbose]
    call serial_string
.trigger:
    movzx eax, byte [rel boot_log_trigger]
    cmp  eax, LOG_TRIGGER_TRIAL
    je   .tr_trial
    cmp  eax, LOG_TRIGGER_FAULTS
    je   .tr_faults
    cmp  eax, LOG_TRIGGER_FIRST
    je   .tr_first
    cmp  eax, LOG_TRIGGER_OVERRIDE
    je   .tr_override
    lea  rdi, [rel str_boot_log_trigger_clean]
    jmp  .emit_trigger
.tr_trial:
    lea  rdi, [rel str_boot_log_trigger_trial]
    jmp  .emit_trigger
.tr_faults:
    lea  rdi, [rel str_boot_log_trigger_faults]
    jmp  .emit_trigger
.tr_first:
    lea  rdi, [rel str_boot_log_trigger_first]
    jmp  .emit_trigger
.tr_override:
    lea  rdi, [rel str_boot_log_trigger_override]
.emit_trigger:
    call serial_string
    lea  rdi, [rel str_boot_log_mode_recorded]
    call serial_string
    ret

; Six-vector production-function KAT: clean, trial, retained faults, malformed
; ring, first boot, and explicit override.  It does not touch live mode state.
boot_log_mode_policy_kat:
    xor  edi, edi
    mov  esi, DIAG_PREV_VALID
    xor  edx, edx
    xor  ecx, ecx
    call boot_log_mode_decide
    cmp  ax, (LOG_TRIGGER_CLEAN << 8) | LOG_MODE_LEAN
    jne  .bad
    mov  edi, 1
    mov  esi, DIAG_PREV_VALID
    xor  edx, edx
    xor  ecx, ecx
    call boot_log_mode_decide
    cmp  ax, (LOG_TRIGGER_TRIAL << 8) | LOG_MODE_VERBOSE
    jne  .bad
    xor  edi, edi
    mov  esi, DIAG_PREV_VALID
    mov  edx, 1
    xor  ecx, ecx
    call boot_log_mode_decide
    cmp  ax, (LOG_TRIGGER_FAULTS << 8) | LOG_MODE_VERBOSE
    jne  .bad
    xor  edi, edi
    mov  esi, DIAG_PREV_BAD_MAGIC
    xor  edx, edx
    xor  ecx, ecx
    call boot_log_mode_decide
    cmp  ax, (LOG_TRIGGER_FAULTS << 8) | LOG_MODE_VERBOSE
    jne  .bad
    xor  edi, edi
    mov  esi, DIAG_PREV_NONE
    xor  edx, edx
    xor  ecx, ecx
    call boot_log_mode_decide
    cmp  ax, (LOG_TRIGGER_FIRST << 8) | LOG_MODE_VERBOSE
    jne  .bad
    xor  edi, edi
    mov  esi, DIAG_PREV_VALID
    mov  edx, 9
    mov  ecx, LOG_MODE_LEAN
    call boot_log_mode_decide
    cmp  ax, (LOG_TRIGGER_OVERRIDE << 8) | LOG_MODE_LEAN
    jne  .bad
    lea  rdi, [rel str_boot_log_mode_kat]
    call serial_string
    ret
.bad:
    lea  rdi, [rel str_boot_log_mode_kat_fail]
    call serial_string
    ret

; The established injected-bad verdict build also exercises all six security
; catalog FAIL alternatives.
%ifdef PAOS_SELFTEST_VERDICT_FORCE_FAIL
%ifndef PAOS_SECURITY_TRUTH_FORCE_FAIL
%define PAOS_SECURITY_TRUTH_FORCE_FAIL 1
%endif
%endif

; serial_string_projected — transparent wrapper around the proven UART writer.
; Exact message-pointer identity selects the earned verdict/timeline row.  This
; is the SAME instruction path that prints the marker: there is no text parser
; and diagnostic prose cannot consume timeline capacity.
serial_string_projected:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  r11, rdi
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    push rax
    push r11
    mov  rdi, r11
    call boot_timeline_special_latch
    mov  rdi, [rsp]
    call selftest_verdict_latch
    mov  rdi, [rsp]
    call serial_string_raw
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    push rax
    mov  rdx, rax
    mov  rsi, [rsp + 16]
    mov  rdi, [rsp + 8]
    sub  rsp, 8                         ; projected UART passes the ordinary call ABI
    call boot_wait_record_serial
    add  rsp, 8
    mov  rax, [rsp]
    sub  rax, [rsp + 16]
    add  rsp, 8
    cmp  byte [rel log_cost_serial_suppress], 0
    jne  .cost_done
    add  [rel log_cost_serial_tsc], rax
.cost_done:
    add  rsp, 16
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; EDI=stable marker id. Membership owns first-arrival suppression; repeated
; latch calls preserve the first TSC. Overflow saturates its counter and never
; wraps or overwrites a row.
boot_timeline_latch:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    mov  r8d, edi
    lea  rsi, [rel boot_timeline_records]
    mov  ecx, [rel boot_timeline_count]
.find:
    test ecx, ecx
    jz   .new
    cmp  word [rsi], r8w
    je   .done
    add  rsi, BOOT_TIMELINE_REC_SIZE
    dec  ecx
    jmp  .find
.new:
    mov  eax, [rel boot_timeline_count]
    cmp  eax, BOOT_TIMELINE_MAX
    jb   .store
    cmp  dword [rel boot_timeline_dropped], -1
    je   .done
    inc  dword [rel boot_timeline_dropped]
    jmp  .done
.store:
    imul ecx, eax, BOOT_TIMELINE_REC_SIZE
    lea  rsi, [rel boot_timeline_records]
    add  rsi, rcx
    mov  [rsi], r8w
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rsi + 2], rax
    inc  dword [rel boot_timeline_count]
.done:
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; RDI=exact serial message pointer. Header registers runtime pointers, avoiding
; baked runtime pointers. Multiple rows may match one message.
boot_timeline_special_latch:
    push rbx
    push rbp
    push r12
    push r13
    mov  r13, rdi
    lea  rbx, [rel boot_timeline_special_catalog]
    mov  ebp, [rel boot_timeline_special_count]
.row:
    test ebp, ebp
    jz   .done
    cmp  r13, [rbx]
    jne  .next
    movzx edi, word [rbx + 8]
    call boot_timeline_latch
.next:
    add  rbx, 16
    dec  ebp
    jmp  .row
.done:
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=runtime message pointer, ESI=stable marker id. Fixed and allocation-free.
boot_timeline_special_register:
    mov  eax, [rel boot_timeline_special_count]
    cmp  eax, BOOT_TIMELINE_SPECIAL_MAX
    jae  .done
    imul ecx, eax, 16
    lea  rdx, [rel boot_timeline_special_catalog]
    add  rdx, rcx
    mov  [rdx], rdi
    mov  [rdx + 8], si
    inc  dword [rel boot_timeline_special_count]
.done:
    ret

; Clear the fixed ledger before the first serial line can carry a verdict.
selftest_verdict_init:
    pushfq
    push rax
    push rcx
    push rdi
    xor  eax, eax
    cld
    lea  rdi, [rel selftest_verdict_results]
    mov  ecx, (SELFTEST_VERDICT_MAX * SELFTEST_VERDICT_REC_SIZE) / 8
    rep  stosq
    mov  dword [rel selftest_verdict_count], eax
    mov  dword [rel selftest_verdict_passes], eax
    mov  dword [rel selftest_verdict_fails], eax
    mov  dword [rel selftest_verdict_skips], eax
    mov  byte [rel selftest_verdict_conflict], al
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

boot_timeline_init:
    pushfq
    push rax
    push rcx
    push rdi
    xor  eax, eax
    cld
    lea  rdi, [rel boot_timeline_records]
    mov  ecx, (BOOT_TIMELINE_MAX * BOOT_TIMELINE_REC_SIZE) / 2
    rep  stosw
    mov  dword [rel boot_timeline_count], eax
    mov  dword [rel boot_timeline_dropped], eax
    mov  qword [rel log_cost_serial_tsc], rax
    mov  qword [rel log_cost_ring_tsc], rax
    mov  qword [rel log_cost_capture_tsc], rax
    mov  byte [rel log_cost_serial_suppress], al
    ; Timeline KAT resets must not erase real early UART coverage or loss.
    cmp  byte [rel boot_wait_ready], 1
    je   .wait_ready
    lea  rdi, [rel boot_wait_records]
    mov  ecx, (BOOT_WAIT_MAX * BOOT_WAIT_REC_SIZE) / 8
    rep  stosq
    mov  dword [rel boot_wait_count], eax
    mov  dword [rel boot_wait_dropped], eax
    mov  qword [rel boot_wait_recorded_tsc], rax
    mov  qword [rel boot_wait_last_end], rax
    mov  byte [rel boot_wait_active], al
    mov  byte [rel boot_wait_ready], 1
.wait_ready:
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; One fixed row is {boot_id:qword, owner_rva:dword, phase:u8, class:u8,
; outcome:u8, flags:u8, first_start:qword, last_end:qword,
; exclusive_sum:qword, retries:dword, budget_ms:dword}. One row per phase/owner.
; first_start/last_end retain original UART interval extrema; exclusive_sum
; counts only exact overlaps with that phase. P8/post-boot time is outside this
; P0-P7 ledger. Pre-P0/interphase gaps retain an explicit unattributed row;
; inconsistent metadata and actual loss still drop. Known+unknown sums exactly
; partition the accepted raw interval; the row layout stays48 bytes (wire v2).
; flags bit0 means the completed summary was copied to the retained diag ring.
; Stage a fixed-size candidate ledger: every interval is accepted atomically,
; including a split spanning multiple rows. No allocation or sampling loop.
BOOT_WAIT_WORK_COUNT  equ BOOT_WAIT_MAX * BOOT_WAIT_REC_SIZE
BOOT_WAIT_WORK_SUM    equ BOOT_WAIT_WORK_COUNT + 8
BOOT_WAIT_WORK_PREV   equ BOOT_WAIT_WORK_COUNT + 16
BOOT_WAIT_WORK_ACTIVE equ BOOT_WAIT_WORK_COUNT + 24
BOOT_WAIT_WORK_END    equ BOOT_WAIT_WORK_COUNT + 32
BOOT_WAIT_WORK_AMOUNT equ BOOT_WAIT_WORK_COUNT + 40
BOOT_WAIT_WORK_TOTAL  equ BOOT_WAIT_WORK_COUNT + 48
BOOT_WAIT_WORK_SIZE   equ BOOT_WAIT_WORK_COUNT + 72

boot_wait_record_serial:
    cmp  byte [rel boot_wait_ready], 1
    jne  .done
    cmp  byte [rel boot_wait_active], 0
    jne  .done                            ; never release another invocation's guard
    test rsi, rsi
    jz   .wrap
    cmp  rdx, rsi
    jbe  .wrap
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, BOOT_WAIT_WORK_SIZE
    mov  byte [rel boot_wait_active], 1
    mov  r13, rsi
    mov  r14, rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel boot_wait_cost_entry], rax
    cmp  dword [rel boot_wait_count], BOOT_WAIT_MAX
    ja   .overflow
    cmp  qword [rel boot_tsc_start], 0
    je   .overflow
    cmp  r13, [rel boot_tsc_start]
    jb   .overflow
    cmp  r13, [rel boot_wait_last_end]
    jb   .overflow                        ; the actual UART owner is globally sequential
    call boot_wait_phases_valid
    test eax, eax
    jz   .overflow
    lea  rdi, [rel boot_wait_records]
    mov  esi, [rel boot_wait_count]
    call boot_wait_rows_valid
    test eax, eax
    jz   .overflow
    call boot_wait_coverage_valid
    test eax, eax
    jz   .overflow

    ; Later output can flush completed rows, but cannot become P7 time.
    mov  rax, [rel boot_phase_tsc + 8*16]
    test rax, rax
    jz   .check_p7_end
    cmp  r13, rax
    jae  .flush
.check_p7_end:
    mov  rax, [rel boot_phase_tsc + 7*16 + 8]
    test rax, rax
    jz   .stage
    cmp  r13, rax
    jae  .flush
.stage:
    mov  r12, rsp
    lea  rsi, [rel boot_wait_records]
    mov  rdi, r12
    mov  ecx, (BOOT_WAIT_MAX * BOOT_WAIT_REC_SIZE) / 8
    cld
    rep  movsq
    mov  eax, [rel boot_wait_count]
    mov  [rsp + BOOT_WAIT_WORK_COUNT], rax
    mov  qword [rsp + BOOT_WAIT_WORK_SUM], 0
    mov  qword [rsp + BOOT_WAIT_WORK_PREV], 0
    mov  qword [rsp + BOOT_WAIT_WORK_ACTIVE], 0
    mov  [rsp + BOOT_WAIT_WORK_END], r14
    mov  rax, [rel boot_phase_tsc + 7*16 + 8]
    test rax, rax
    jz   .owner
    cmp  rax, r14
    jae  .owner
    mov  [rsp + BOOT_WAIT_WORK_END], rax
.owner:
    lea  rax, [rel serial_string_raw]
    lea  rcx, [rel code_start]
    sub  rcx, code_start
    sub  rax, rcx
    mov  r11d, eax
    xor  r15d, r15d
.phase:
    lea  rax, [rel boot_phase_tsc]
    mov  ecx, r15d
    shl  ecx, 4
    mov  r8, [rax + rcx]
    mov  r9, [rax + rcx + 8]
    test r8, r8
    jnz  .known_start
    test r9, r9
    jnz  .overflow
    jmp  .next_phase
.known_start:
    cmp  qword [rsp + BOOT_WAIT_WORK_ACTIVE], 0
    jne  .overflow                        ; an uncompleted phase has no known successor
    cmp  r8, [rsp + BOOT_WAIT_WORK_PREV]
    jb   .overflow                        ; overlapping/reversed phase extents
    test r9, r9
    jz   .active_phase
    cmp  r9, r8
    jb   .overflow
    mov  [rsp + BOOT_WAIT_WORK_PREV], r9
    jmp  .overlap
.active_phase:
    mov  qword [rsp + BOOT_WAIT_WORK_ACTIVE], 1
    mov  r9, [rsp + BOOT_WAIT_WORK_END]     ; provisional extent only for the last active phase
.overlap:
    mov  r10, r13
    cmp  r10, r8
    cmovb r10, r8
    mov  rax, [rsp + BOOT_WAIT_WORK_END]
    cmp  rax, r9
    cmova rax, r9
    cmp  rax, r10
    jbe  .next_phase
    sub  rax, r10
    mov  [rsp + BOOT_WAIT_WORK_AMOUNT], rax
    add  [rsp + BOOT_WAIT_WORK_SUM], rax
    jc   .overflow
    mov  rbx, r12
    mov  ebp, [rsp + BOOT_WAIT_WORK_COUNT]
.find_row:
    test ebp, ebp
    jz   .new_row
    cmp  [rbx + 8], r11d
    jne  .find_next
    cmp  [rbx + 12], r15b
    je   .aggregate
.find_next:
    add  rbx, BOOT_WAIT_REC_SIZE
    dec  ebp
    jmp  .find_row
.aggregate:
    mov  rax, [rel boot_tsc_start]
    cmp  [rbx], rax
    jne  .overflow
    cmp  byte [rbx + 13], BOOT_WAIT_CLASS_IO
    jne  .overflow
    cmp  byte [rbx + 14], BOOT_WAIT_OUTCOME_OK
    jne  .overflow
    cmp  byte [rbx + 15], 0
    jne  .overflow                        ; never change an already retained summary
    cmp  qword [rbx + 16], 0
    je   .overflow
    mov  rax, [rbx + 24]
    cmp  rax, [rbx + 16]
    jbe  .overflow
    cmp  r13, rax
    jb   .overflow                        ; duplicates/overlaps are not exclusive waits
    mov  rax, [rsp + BOOT_WAIT_WORK_AMOUNT]
    add  rax, [rbx + 32]
    jc   .overflow
    cmp  r15d, BOOT_WAIT_PHASE_UNKNOWN
    je   .store_aggregate                 ; complement extent validated before commit
    mov  r10, r14
    cmp  r10, r9
    cmova r10, r9
    mov  rcx, [rbx + 16]
    cmp  rcx, r8
    cmovb rcx, r8
    sub  r10, rcx
    jb   .overflow
    cmp  rax, r10
    ja   .overflow                        ; candidate sum must fit its phase-clipped extent
.store_aggregate:
    mov  [rbx + 24], r14
    mov  [rbx + 32], rax
    jmp  .next_phase
.new_row:
    mov  eax, [rsp + BOOT_WAIT_WORK_COUNT]
    cmp  eax, BOOT_WAIT_MAX
    jae  .overflow
    imul ecx, eax, BOOT_WAIT_REC_SIZE
    lea  rbx, [r12 + rcx]
    mov  rax, [rel boot_tsc_start]
    mov  [rbx], rax
    mov  [rbx + 8], r11d
    mov  [rbx + 12], r15b
    mov  byte [rbx + 13], BOOT_WAIT_CLASS_IO
    mov  byte [rbx + 14], BOOT_WAIT_OUTCOME_OK
    mov  byte [rbx + 15], 0
    mov  [rbx + 16], r13
    mov  [rbx + 24], r14
    mov  rax, [rsp + BOOT_WAIT_WORK_AMOUNT]
    mov  [rbx + 32], rax
    mov  dword [rbx + 40], 0
    mov  dword [rbx + 44], BOOT_WAIT_SERIAL_BUDGET_MS
    inc  dword [rsp + BOOT_WAIT_WORK_COUNT]
.next_phase:
    cmp  r15d, BOOT_WAIT_PHASE_UNKNOWN
    je   .covered
    inc  r15d
    cmp  r15d, 8
    jb   .phase
    ; P8 is independently stamped, but is not part of the P0-P7 wait ledger.
    mov  rax, [rel boot_phase_tsc + 8*16]
    test rax, rax
    jz   .unknown_remainder
    cmp  qword [rsp + BOOT_WAIT_WORK_ACTIVE], 0
    jne  .overflow
    cmp  rax, [rsp + BOOT_WAIT_WORK_PREV]
    jb   .overflow
.unknown_remainder:
    ; Remaining raw duration is retained exactly once, never assigned a phase.
    mov  rax, [rsp + BOOT_WAIT_WORK_END]
    sub  rax, r13
    sub  rax, [rsp + BOOT_WAIT_WORK_SUM]
    jb   .overflow
    test rax, rax
    jz   .covered
    mov  [rsp + BOOT_WAIT_WORK_AMOUNT], rax
    add  [rsp + BOOT_WAIT_WORK_SUM], rax
    jc   .overflow
    mov  r15d, BOOT_WAIT_PHASE_UNKNOWN
    mov  rbx, r12
    mov  ebp, [rsp + BOOT_WAIT_WORK_COUNT]
    jmp  .find_row
.covered:
    mov  rax, [rsp + BOOT_WAIT_WORK_END]
    sub  rax, r13
    cmp  rax, [rsp + BOOT_WAIT_WORK_SUM]
    jne  .overflow
    add  rax, [rel boot_wait_recorded_tsc]
    jc   .overflow
    mov  [rsp + BOOT_WAIT_WORK_TOTAL], rax
    mov  rdi, r12
    mov  esi, [rsp + BOOT_WAIT_WORK_COUNT]
    call boot_wait_rows_valid
    test eax, eax
    jz   .overflow
    mov  rsi, r12
    lea  rdi, [rel boot_wait_records]
    mov  ecx, (BOOT_WAIT_MAX * BOOT_WAIT_REC_SIZE) / 8
    rep  movsq
    mov  eax, [rsp + BOOT_WAIT_WORK_COUNT]
    mov  [rel boot_wait_count], eax
    mov  rax, [rsp + BOOT_WAIT_WORK_TOTAL]
    mov  [rel boot_wait_recorded_tsc], rax
    mov  [rel boot_wait_last_end], r14
.flush:
    lea  rbx, [rel boot_wait_records]
    mov  ebp, [rel boot_wait_count]
.flush_row:
    test ebp, ebp
    jz   .finish
    test byte [rbx + 15], 1
    jnz  .flush_next
    movzx eax, byte [rbx + 12]
    cmp  eax, BOOT_WAIT_PHASE_UNKNOWN
    je   .flush_unknown
    cmp  eax, 7
    ja   .overflow
    lea  rcx, [rel boot_phase_tsc]
    shl  eax, 4
    add  rcx, rax
    mov  rax, [rcx + 8]
    jmp  .flush_boundary
.flush_unknown:
    mov  rax, [rel boot_phase_tsc + 7*16 + 8] ; unknown bucket stays open through P7
.flush_boundary:
    test rax, rax
    jz   .flush_next
    cmp  rax, r14
    ja   .flush_next
    cmp  byte [rel diag_ready], 0
    je   .flush_next
    mov  edi, DIAG_K_EXIT
    movzx esi, byte [rbx + 12]
    mov  rdx, [rbx + 32]
    mov  ecx, [rbx + 8]
    movzx eax, byte [rbx + 13]
    shl  rax, 32
    or   rcx, rax
    movzx eax, byte [rbx + 14]
    shl  rax, 40
    or   rcx, rax
    mov  r8d, [rbx + 44]
    lea  r9, [rel str_boot_wait_owner_serial]
    cmp  byte [rbx + 12], BOOT_WAIT_PHASE_UNKNOWN
    jne  .flush_emit
    lea  r9, [rel str_boot_wait_owner_unknown]
.flush_emit:
    call diag_ring_append
    or   byte [rbx + 15], 1
.flush_next:
    add  rbx, BOOT_WAIT_REC_SIZE
    dec  ebp
    jmp  .flush_row
.finish:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel boot_wait_cost_entry]
    jb   .cost_bad
    add  rax, [rel boot_wait_cost_tsc]
    jc   .cost_bad
    mov  [rel boot_wait_cost_tsc], rax
    jmp  .release
.cost_bad:
    mov  qword [rel boot_wait_cost_tsc], -1
    cmp  dword [rel boot_wait_dropped], -1
    je   .release
    inc  dword [rel boot_wait_dropped]
.release:
    mov  byte [rel boot_wait_active], 0
    add  rsp, BOOT_WAIT_WORK_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
.done:
    ret
.overflow:
    cmp  dword [rel boot_wait_dropped], -1
    je   .finish
    inc  dword [rel boot_wait_dropped]
    jmp  .finish
.wrap:
    cmp  dword [rel boot_wait_dropped], -1
    je   .done
    inc  dword [rel boot_wait_dropped]
    ret

; Independently stamped phases must be ordered and disjoint. Only the last
; known phase may still be active; unset phases do not invent an interval.
; EAX=1 valid / 0 refused; caller-saved clobbers only, fixed nine-phase bound.
boot_wait_phases_valid:
    mov  r8, [rel boot_tsc_start]
    xor  r9d, r9d
    xor  r10d, r10d
    lea  r11, [rel boot_phase_tsc]
.phase:
    mov  rax, [r11]
    mov  rdx, [r11 + 8]
    test rax, rax
    jnz  .start
    test rdx, rdx
    jnz  .bad
    jmp  .next
.start:
    test r9d, r9d
    jnz  .bad
    cmp  rax, r8
    jb   .bad
    test rdx, rdx
    jz   .active
    cmp  rdx, rax
    jb   .bad
    mov  r8, rdx
    jmp  .next
.active:
    mov  r9d, 1
.next:
    add  r11, 16
    inc  r10d
    cmp  r10d, 9
    jb   .phase
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Pure bounded row validation shared by staging and reconciliation. Raw TSC
; recording does not require calibration; budget conversion belongs to the KAT.
; RDI=rows, ESI=count -> EAX=1 valid / 0 refused; caller-saved clobbers only.
boot_wait_rows_valid:
    push rbx
    push rbp
    push r12
    mov  r12, rdi
    mov  rbx, rdi
    mov  ebp, esi
    cmp  ebp, BOOT_WAIT_MAX
    ja   .bad
.row:
    test ebp, ebp
    jz   .good
    cmp  dword [rbx + 8], 0
    je   .bad
    mov  rax, [rel boot_tsc_start]
    test rax, rax
    jz   .bad
    cmp  [rbx], rax
    jne  .bad
    cmp  byte [rbx + 12], BOOT_WAIT_PHASE_UNKNOWN
    je   .kind_ok
    cmp  byte [rbx + 12], 7
    ja   .bad
.kind_ok:
    cmp  byte [rbx + 13], BOOT_WAIT_CLASS_IO
    jne  .bad
    cmp  byte [rbx + 14], BOOT_WAIT_OUTCOME_OK
    jne  .bad
    mov  al, [rbx + 15]
    and  al, 0xFE
    jnz  .bad
    mov  r8, [rbx + 16]
    test r8, r8
    jz   .bad
    cmp  r8, [rel boot_tsc_start]
    jb   .bad
    mov  r9, [rbx + 24]
    cmp  r9, r8
    jbe  .bad
    cmp  byte [rbx + 12], BOOT_WAIT_PHASE_UNKNOWN
    je   .unknown_extent
    movzx eax, byte [rbx + 12]
    shl  eax, 4
    lea  rdx, [rel boot_phase_tsc]
    mov  rcx, [rdx + rax]
    test rcx, rcx
    jz   .bad
    cmp  r8, rcx
    cmovb r8, rcx
    mov  rcx, [rdx + rax + 8]
    test rcx, rcx
    jz   .row_extent
    cmp  r9, rcx
    cmova r9, rcx
.row_extent:
    sub  r9, r8
    jb   .bad
    jmp  .sum_extent
.unknown_extent:
    mov  rdi, r8
    mov  rsi, r9
    call boot_wait_unknown_extent
    jc   .bad
    mov  r9, rax
.sum_extent:
    mov  r11, [rbx + 32]
    test r11, r11
    jz   .bad
    cmp  r11, r9
    ja   .bad
    cmp  dword [rbx + 44], 0
    je   .bad
    mov  rcx, r12
.unique:
    cmp  rcx, rbx
    je   .advance
    mov  eax, [rcx + 8]
    cmp  eax, [rbx + 8]
    jne  .unique_next
    mov  al, [rcx + 12]
    cmp  al, [rbx + 12]
    je   .bad                            ; no owner/bucket alias rows
.unique_next:
    add  rcx, BOOT_WAIT_REC_SIZE
    jmp  .unique
.advance:
    add  rbx, BOOT_WAIT_REC_SIZE
    dec  ebp
    jmp  .row
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Validate the already-published coverage counters before any new candidate.
; Raw row sums equal accepted input ticks; extrema fit the global UART high-water.
; No calibration needed; fixed32-row work and caller-saved clobbers only.
boot_wait_coverage_valid:
    mov  edx, [rel boot_wait_count]
    cmp  edx, BOOT_WAIT_MAX
    ja   .bad
    test edx, edx
    jnz  .rows
    cmp  qword [rel boot_wait_recorded_tsc], 0
    jne  .bad
    cmp  qword [rel boot_wait_last_end], 0
    jne  .bad
    jmp  .good
.rows:
    mov  r8, [rel boot_wait_last_end]
    mov  r9, r8
    sub  r9, [rel boot_tsc_start]
    jb   .bad
    lea  rdi, [rel boot_wait_records]
    xor  ecx, ecx
.row:
    cmp  [rdi + 24], r8
    ja   .bad
    add  rcx, [rdi + 32]
    jc   .bad
    add  rdi, BOOT_WAIT_REC_SIZE
    dec  edx
    jnz  .row
    cmp  rcx, [rel boot_wait_recorded_tsc]
    jne  .bad
    cmp  rcx, r9
    ja   .bad
.good:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Complement of the independently stamped known P0-P7 extents in raw bounds.
; RDI=original first, RSI=original last -> RAX=unattributed extent, CF=invalid.
; Caller first validates ordered/disjoint phases; no stamps or rows are changed.
boot_wait_unknown_extent:
    mov  r8, rdi
    mov  r9, rsi
    mov  rax, [rel boot_phase_tsc + 7*16 + 8]
    test rax, rax
    jz   .domain
    cmp  r9, rax
    cmova r9, rax
.domain:
    mov  r10, r9
    sub  r10, r8
    jb   .bad
    lea  r11, [rel boot_phase_tsc]
    xor  ecx, ecx
.phase:
    mov  rax, [r11]
    mov  rdx, [r11 + 8]
    test rax, rax
    jz   .next
    mov  rdi, r8
    cmp  rdi, rax
    cmovb rdi, rax
    test rdx, rdx
    cmovz rdx, r9
    cmp  rdx, r9
    cmova rdx, r9
    cmp  rdx, rdi
    jbe  .next
    sub  rdx, rdi
    sub  r10, rdx
    jb   .bad
.next:
    add  r11, 16
    inc  ecx
    cmp  ecx, 8
    jb   .phase
    mov  rax, r10
    clc
    ret
.bad:
    stc
    ret

; Validate complete bounded rows, then reconcile exclusive waits against each
; independently stamped completed phase.  The non-negative remainder is the
; active+unattributed time, giving exact equality without nested counting.
; The production caller runs inside P6, before P6 completion/P7 start. Require
; the P0-P6 prefix; reconcile P7 too when stamped, without requiring its future
; start at the native P6-active cut. Refused recordings still prevent PASS.
boot_wait_ledger_kat:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    cmp  dword [rel boot_wait_count], 0
    je   .bad
    cmp  dword [rel boot_wait_count], BOOT_WAIT_MAX
    ja   .bad
    cmp  dword [rel boot_wait_dropped], 0
    jne  .bad
    call boot_wait_phases_valid
    test eax, eax
    jz   .bad
    lea  rdi, [rel boot_wait_records]
    mov  esi, [rel boot_wait_count]
    call boot_wait_rows_valid
    test eax, eax
    jz   .bad
    call boot_wait_coverage_valid
    test eax, eax
    jz   .bad
    mov  r12, [rel tsc_khz]
    test r12, r12
    jz   .bad
    mov  rax, BOOT_WAIT_OBSERVER_TAX_BUDGET_MS
    mul  r12
    test rdx, rdx
    jnz  .bad
    cmp  qword [rel boot_wait_cost_tsc], 0
    je   .bad
    cmp  [rel boot_wait_cost_tsc], rax
    ja   .bad
    xor  r15d, r15d
    lea  rbx, [rel boot_wait_records]
    mov  ebp, [rel boot_wait_count]
.budget:
    mov  eax, [rbx + 44]
    mul  r12
    test rdx, rdx
    jnz  .bad
    cmp  [rbx + 32], rax
    ja   .bad
    mov  rax, [rbx + 24]
    cmp  rax, [rel boot_wait_last_end]
    ja   .bad
    add  r15, [rbx + 32]
    jc   .bad
    add  rbx, BOOT_WAIT_REC_SIZE
    dec  ebp
    jnz  .budget
.reconcile:
    cmp  r15, [rel boot_wait_recorded_tsc]
    jne  .bad                            ; known+unknown must equal retained raw coverage
    mov  rax, [rel boot_wait_last_end]
    sub  rax, [rel boot_tsc_start]
    jb   .bad
    cmp  r15, rax
    ja   .bad
    xor  r12d, r12d
    xor  r10d, r10d
.phase:
    lea  rdx, [rel boot_phase_tsc]
    mov  ecx, r12d
    shl  ecx, 4
    add  rdx, rcx
    mov  r13, [rdx]
    mov  r14, [rdx + 8]
    test r13, r13
    jz   .not_started
    cmp  r13, r10
    jb   .bad
    test r14, r14
    jz   .active_phase
    cmp  r14, r13
    jb   .bad
    mov  r10, r14
    sub  r14, r13
    xor  r15d, r15d
    lea  rbx, [rel boot_wait_records]
    mov  ebp, [rel boot_wait_count]
.sum:
    test ebp, ebp
    jz   .sum_done
    cmp  [rbx + 12], r12b
    jne  .sum_next
    add  r15, [rbx + 32]
    jc   .bad
.sum_next:
    add  rbx, BOOT_WAIT_REC_SIZE
    dec  ebp
    jmp  .sum
.sum_done:
    cmp  r15, r14
    ja   .bad
    jmp  .next_phase
.active_phase:
    mov  r10, -1
.next_phase:
    inc  r12d
    cmp  r12d, 8
    jb   .phase
.passed:
    lea  rdi, [rel str_boot_wait_recorded]
    call serial_string
    lea  rdi, [rel str_boot_wait_reconciled]
    call serial_string
    jmp  .out
.not_started:
    cmp  r12d, 7
    jne  .bad                            ; mandatory P0-P6 prefix remains required
    cmp  qword [rel boot_phase_tsc + 6*16 + 8], 0
    jne  .bad                            ; explicit active edge, no UINT64 sentinel alias
    jmp  .passed                         ; no P7 extent exists to reconcile yet
.bad:
    lea  rdi, [rel str_boot_wait_failed]
    call serial_string
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Production-path KAT: reject an unregistered message, preserve a duplicate's
; first timestamp, fill 256 rows, then prove a 257th distinct id increments the
; dropped counter without altering either edge row.
boot_timeline_overflow_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, [rel log_cost_serial_tsc]
    mov  r14, [rel log_cost_ring_tsc]
    mov  r15, [rel log_cost_capture_tsc]
    call boot_timeline_init
    lea  rdi, [rel str_timeline_unlatched]
    call boot_timeline_special_latch
    cmp  dword [rel boot_timeline_count], 0
    jne  .bad
    mov  edi, 0x7FFE
    call boot_timeline_latch
    mov  rax, [rel boot_timeline_records + 2]
    push rax
    mov  edi, 0x7FFE
    call boot_timeline_latch
    cmp  dword [rel boot_timeline_count], 1
    jne  .dup_bad
    pop  rax
    cmp  [rel boot_timeline_records + 2], rax
    jne  .bad
    call boot_timeline_init
    lea  rbx, [rel boot_timeline_records]
    xor  r12d, r12d
.fill:
    mov  [rbx], r12w
    mov  [rbx + 2], r12
    add  rbx, BOOT_TIMELINE_REC_SIZE
    inc  r12d
    cmp  r12d, BOOT_TIMELINE_MAX
    jb   .fill
    mov  dword [rel boot_timeline_count], BOOT_TIMELINE_MAX
    mov  edi, 0xFFFF
    call boot_timeline_latch
    cmp  dword [rel boot_timeline_count], BOOT_TIMELINE_MAX
    jne  .bad
    cmp  dword [rel boot_timeline_dropped], 1
    jne  .bad
    cmp  word [rel boot_timeline_records], 0
    jne  .bad
    cmp  word [rel boot_timeline_records + (BOOT_TIMELINE_MAX-1)*BOOT_TIMELINE_REC_SIZE], BOOT_TIMELINE_MAX-1
    jne  .bad
    call boot_timeline_init
    mov  byte [rel boot_timeline_overflow_kat_ok], 1
    jmp  .out
.dup_bad:
    add  rsp, 8
.bad:
    call boot_timeline_init
    mov  byte [rel boot_timeline_overflow_kat_ok], 0
.out:
    mov  [rel log_cost_serial_tsc], r13
    mov  [rel log_cost_ring_tsc], r14
    mov  [rel log_cost_capture_tsc], r15
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; P6 live KAT: append order is TSC-sorted and actual A/B verify precedes actual
; commit. P7 must also have reached the ledger before the acceptance markers.
boot_timeline_ordering_kat:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    cmp  byte [rel boot_timeline_overflow_kat_ok], 1
    jne  .bad
    lea  rbx, [rel boot_timeline_records]
    mov  ebp, [rel boot_timeline_count]
    xor  r12d, r12d
    xor  r13d, r13d
    xor  r14d, r14d
    sub  rsp, 16
    mov  qword [rsp], 0
    mov  qword [rsp + 8], 0
.scan:
    cmp  r12d, ebp
    jae  .scan_done
    mov  rax, [rbx + 2]
    test r12d, r12d
    jz   .ordered
    cmp  rax, r13
    jb   .stack_bad
.ordered:
    mov  r13, rax
    movzx ecx, word [rbx]
    cmp  ecx, BOOT_TIMELINE_ID_AB_VERIFY
    jne  .not_verify
    mov  [rsp], rax
    or   r14d, 1
.not_verify:
    cmp  ecx, BOOT_TIMELINE_ID_AB_COMMIT
    jne  .not_commit
    mov  [rsp + 8], rax
    or   r14d, 2
.not_commit:
    cmp  ecx, BOOT_TIMELINE_ID_P7
    jne  .next
    or   r14d, 4
.next:
    add  rbx, BOOT_TIMELINE_REC_SIZE
    inc  r12d
    jmp  .scan
.scan_done:
    cmp  r14d, 7
    jne  .stack_bad
    mov  rax, [rsp]
    cmp  rax, [rsp + 8]
    ja   .stack_bad
    add  rsp, 16
    lea  rdi, [rel str_timeline_kat]
    call serial_string
    lea  rdi, [rel str_timeline_recorded]
    call serial_string
    call boot_wait_ledger_kat
    jmp  .out
.stack_bad:
    add  rsp, 16
.bad:
    lea  rdi, [rel str_timeline_kat_fail]
    call serial_string
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI=marker id, RAX=canonical bare token pointer (or zero).
boot_timeline_token_ptr:
    movzx eax, di
    cmp  eax, SELFTEST_VERDICT_CATALOG_COUNT
    jae  .special
    imul ecx, eax, SELFTEST_VERDICT_CAT_SIZE
    lea  rdx, [rel selftest_verdict_catalog]
    add  rdx, rcx
    mov  eax, [rdx + 8]
    lea  rdx, [rel code_start]
    sub  rdx, code_start
    add  rax, rdx
    ret
.special:
    sub  eax, BOOT_TIMELINE_SPECIAL_BASE
    cmp  eax, BOOT_TIMELINE_SPECIAL_TOKEN_COUNT
    jae  .missing
    lea  rdx, [rel boot_timeline_special_tokens]
    mov  eax, [rdx + rax*4]
    lea  rdx, [rel code_start]
    sub  rdx, code_start
    add  rax, rdx
    ret
.missing:
    xor  eax, eax
    ret

; RDI=the exact c-string about to be written to serial.  Catalog entries store
; 32-bit RVAs deliberately; they are rebased here before use (never dereference
; a baked `dq symbol`, whose compile-time RVA is not a runtime VA).
selftest_verdict_latch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi
    lea  r14, [rel code_start]
    sub  r14, code_start                 ; runtime image base
    lea  r12, [rel selftest_verdict_catalog]
    mov  ebp, SELFTEST_VERDICT_CATALOG_COUNT
.catalog:
    test ebp, ebp
    jz   .done
    mov  eax, [r12]
    add  rax, r14
    cmp  r15, rax
    je   .matched
    add  r12, SELFTEST_VERDICT_CAT_SIZE
    dec  ebp
    jmp  .catalog
.matched:
    mov  rax, r12
    lea  rdi, [rel selftest_verdict_catalog]
    sub  rax, rdi
    shr  rax, 4
    mov  edi, eax
    call boot_timeline_latch
    mov  r13d, [r12 + 4]                ; key RVA (pass-token identity)
    add  r13, r14
    mov  ebx, [r12 + 8]                 ; selected bare token RVA
    add  rbx, r14
    movzx r11d, byte [r12 + 12]          ; status
%ifdef PAOS_SECURITY_TRUTH_FORCE_FAIL
    ; The injected-bad image still runs ordinary boot selftests. Suppress only
    ; the six catalog PASS selections so their explicit FAIL alternatives can
    ; occupy the same keys without manufacturing a conflict.
    cmp  r11b, SELFTEST_VERDICT_PASS
    jne  .fixture_filter_done
    lea  rax, [rel tok_security_wx_pass]
    cmp  r13, rax
    je   .done
    lea  rax, [rel tok_security_capability_pass]
    cmp  r13, rax
    je   .done
    lea  rax, [rel tok_security_principal_pass]
    cmp  r13, rax
    je   .done
    lea  rax, [rel tok_security_command_auth_pass]
    cmp  r13, rax
    je   .done
    lea  rax, [rel tok_security_audit_pass]
    cmp  r13, rax
    je   .done
    lea  rax, [rel tok_security_secure_boot_pass]
    cmp  r13, rax
    je   .done
.fixture_filter_done:
%endif
    lea  r10, [rel selftest_verdict_results]
    mov  ecx, [rel selftest_verdict_count]
.find_existing:
    test ecx, ecx
    jz   .new
    cmp  [r10], r13
    je   .existing
    add  r10, SELFTEST_VERDICT_REC_SIZE
    dec  ecx
    jmp  .find_existing
.existing:
    cmp  byte [r10 + 16], r11b
    jne  .conflict
    cmp  [r10 + 8], rbx
    je   .done                           ; repeated print of same earned verdict
.conflict:
    mov  byte [rel selftest_verdict_conflict], 1
    jmp  .done
.new:
    mov  eax, [rel selftest_verdict_count]
    cmp  eax, SELFTEST_VERDICT_MAX
    jae  .conflict
    imul ecx, eax, SELFTEST_VERDICT_REC_SIZE
    lea  r10, [rel selftest_verdict_results]
    add  r10, rcx
    mov  [r10], r13
    mov  [r10 + 8], rbx
    mov  byte [r10 + 16], r11b
    inc  dword [rel selftest_verdict_count]
    cmp  r11b, SELFTEST_VERDICT_PASS
    je   .inc_pass
    cmp  r11b, SELFTEST_VERDICT_FAIL
    je   .inc_fail
    inc  dword [rel selftest_verdict_skips]
    jmp  .done
.inc_pass:
    inc  dword [rel selftest_verdict_passes]
    jmp  .done
.inc_fail:
    inc  dword [rel selftest_verdict_fails]
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Final normal-build KAT: every observed table row owns one valid token/status,
; keys are unique, and the counters are a bijection with the row count.
selftest_verdict_kat:
    push rbx
    push r12
    push r13
%ifdef PAOS_SELFTEST_VERDICT_FORCE_FAIL
    lea  rdi, [rel str_selftest_fixture_fail]
    call serial_string
%endif
    cmp  byte [rel selftest_verdict_conflict], 0
    jne  .bad
    mov  eax, [rel selftest_verdict_passes]
    add  eax, [rel selftest_verdict_fails]
    add  eax, [rel selftest_verdict_skips]
    cmp  eax, [rel selftest_verdict_count]
    jne  .bad
    test eax, eax
    jz   .bad
    lea  r12, [rel selftest_verdict_results]
    xor  ebx, ebx
.row:
    cmp  ebx, [rel selftest_verdict_count]
    jae  .good
    cmp  qword [r12], 0
    je   .bad
    cmp  qword [r12 + 8], 0
    je   .bad
    movzx eax, byte [r12 + 16]
    cmp  eax, SELFTEST_VERDICT_PASS
    jb   .bad
    cmp  eax, SELFTEST_VERDICT_SKIPPED
    ja   .bad
    lea  r13, [r12 + SELFTEST_VERDICT_REC_SIZE]
    mov  ecx, ebx
    inc  ecx
.unique:
    cmp  ecx, [rel selftest_verdict_count]
    jae  .next
    mov  rax, [r13]
    cmp  rax, [r12]
    je   .bad
    add  r13, SELFTEST_VERDICT_REC_SIZE
    inc  ecx
    jmp  .unique
.next:
    add  r12, SELFTEST_VERDICT_REC_SIZE
    inc  ebx
    jmp  .row
.good:
%ifdef PAOS_SELFTEST_VERDICT_FORCE_FAIL
    ; One legacy fixture row plus all six security FAIL alternatives must have
    ; arrived through the same pointer-identity latch.
    cmp  dword [rel selftest_verdict_fails], 7
    jne  .bad
    lea  rdi, [rel str_selftest_fixture_ok]
    call serial_string
    jmp  .out
%else
    lea  rdi, [rel str_selftest_projected]
    call serial_string
    mov  eax, 1
    cpuid
    test ecx, 0x80000000                ; qemu-only marker never emitted on metal
    jz   .out
    lea  rdi, [rel str_selftest_bijection]
    call serial_string
    jmp  .out
%endif
.bad:
    lea  rdi, [rel str_selftest_bijection_fail]
    call serial_string
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Require an earned PASS already observed from an owning subsystem. RDI is the
; runtime pass-key pointer and RSI the explicit FAIL message. RAX=0/1.
security_truth_require_pass:
    push rbx                            ; keep child-call stack alignment
    lea  r10, [rel selftest_verdict_results]
    mov  ecx, [rel selftest_verdict_count]
.row:
    test ecx, ecx
    jz   .missing
    cmp  [r10], rdi
    jne  .next
    cmp  byte [r10 + 16], SELFTEST_VERDICT_PASS
    jne  .missing
    xor  eax, eax
    pop  rbx
    ret
.next:
    add  r10, SELFTEST_VERDICT_REC_SIZE
    dec  ecx
    jmp  .row
.missing:
    mov  rdi, rsi
    call serial_string
    mov  eax, 1
    pop  rbx
    ret

; Run after all boot selftests and service declarations. Five rows reuse exact
; earned producer verdicts. The Secure Boot row proves only that its pre-EBS
; GetVariable observation succeeded; it does not claim policy or chain validity.
security_truth_catalog_selftest:
    push rbx
    push r12
    sub  rsp, 8                         ; align all child calls
    xor  r12d, r12d
    lea  rdi, [rel tok_security_wx_pass]
    lea  rsi, [rel str_security_wx_fail]
    call security_truth_require_pass
    or   r12d, eax
    lea  rdi, [rel tok_security_capability_pass]
    lea  rsi, [rel str_security_capability_fail]
    call security_truth_require_pass
    or   r12d, eax
    lea  rdi, [rel tok_security_principal_pass]
    lea  rsi, [rel str_security_principal_fail]
    call security_truth_require_pass
    or   r12d, eax
    lea  rdi, [rel tok_security_command_auth_pass]
    lea  rsi, [rel str_security_command_auth_fail]
    call security_truth_require_pass
    or   r12d, eax
    lea  rdi, [rel tok_security_audit_pass]
    lea  rsi, [rel str_security_audit_fail]
    call security_truth_require_pass
    or   r12d, eax
    cmp  byte [rel pbm_sb_snapshot_valid], 1
    jne  .secure_boot_fail
    lea  rdi, [rel str_security_secure_boot_pass]
    call serial_string
    jmp  .secure_boot_done
.secure_boot_fail:
    lea  rdi, [rel str_security_secure_boot_fail]
    call serial_string
    or   r12d, 1
.secure_boot_done:
    test r12d, r12d
    jnz  .out
    mov  eax, 1
    cpuid
    test ecx, 0x80000000                ; contract marker is QEMU-only
    jz   .out
    lea  rdi, [rel str_security_truth_catalog]
    call serial_string
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; log_render — build a structured log line into [RCX], NUL-terminated.
;   in: RDI=level(0..4), RSI=subsystem str, RDX=message str, RCX=buf
;  out: RAX=length (excl NUL)
;  clobbers: RAX,RCX,RDX,RSI,RDI (RBX,R12-R15 saved)
log_render:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rcx                        ; buf base (for the final length)
    mov  r12, rdi                        ; level
    mov  r13, rsi                        ; subsystem
    mov  r14, rdx                        ; message
    mov  r15, rcx                        ; running write cursor
    lea  rdi, [rel str_log_open]         ; "[PAOS64]["
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    mov  rax, r12                        ; level name (clamp unknown -> FTL slot)
    cmp  rax, LOG_FTL
    jbe  .lvlok
    mov  rax, LOG_FTL
.lvlok:
    shl  rax, 2                          ; 4-byte stride per name
    lea  rdi, [rel log_lvl_names]
    add  rdi, rax
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    ; --- owning-principal field (1053): every log line carries [pid=N] in the
    ;     HEADER from v1 (non-retrofittable — appending it later rewrites every
    ;     line). v1 = OWNER (log_current_principal, id 1). ---
    lea  rdi, [rel str_log_pido]         ; "][pid="
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    mov  rdi, [rel log_current_principal]
    mov  rsi, r15
    call fmt_dec
    add  r15, rax
    lea  rdi, [rel str_log_sep1]         ; "]["
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    mov  rdi, r13                        ; subsystem
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    lea  rdi, [rel str_log_sep2]         ; "] "
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    mov  rdi, r14                        ; message
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    lea  rdi, [rel str_log_crlf]         ; CR LF
    mov  rsi, r15
    call fmt_str
    add  r15, rax
    mov  rax, r15
    sub  rax, rbx                        ; total length
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; log_line — render a structured line and flush it to serial (the canonical path).
;   in: RDI=level, RSI=subsystem str, RDX=message str
;  clobbers: RAX,RCX,RDX,RSI,RDI
log_line:
    push r10
    push r11
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r10, rax
    pop  rdx
    push r10
    inc  byte [rel log_cost_serial_suppress]
    lea  rcx, [rel log_linebuf]
    call log_render
    lea  rdi, [rel log_linebuf]
    call serial_string
    dec  byte [rel log_cost_serial_suppress]
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    pop  r10
    sub  rax, r10
    add  [rel log_cost_serial_tsc], rax
    pop  r11
    pop  r10
    ret

; logfmt_selftest — the combined log+fmt gate (emits the acceptance marker).
;   1. fmt known-answer vectors (fmt_selftest) must all pass.
;   2. CONTENT-GRADE the log+fmt path together (TESTING §1, not a mere latch):
;      format a nonce 0xCAFE through fmt_hex into a message, render a full line,
;      and assert it equals the expected literal byte-for-byte. A candidate that
;      didn't really convert/render cannot produce "nonce=cafe" in place.
;   3. Emit the verified line + a canonical INFO line (observable, TESTING §7).
;   4. PASS/FAIL marker.
logfmt_selftest:
    call fmt_selftest                    ; RAX = fmt vector failures
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_nonce_pfx]        ; build "nonce=" into the message buffer
    lea  rsi, [rel log_msgbuf]
    call fmt_str                         ; RAX = 6
    lea  rsi, [rel log_msgbuf]
    add  rsi, rax                        ; append after "nonce="
    mov  rdi, 0xCAFE                      ; the nonce
    xor  rdx, rdx                         ; minimal hex -> "cafe"
    call fmt_hex
    mov  rdi, LOG_INF                     ; render the full line
    lea  rsi, [rel str_sub_lib]
    lea  rdx, [rel log_msgbuf]
    lea  rcx, [rel log_linebuf]
    call log_render
    lea  rdi, [rel log_linebuf]          ; grade it against the expected literal
    lea  rsi, [rel str_log_expected]
    call strcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel log_linebuf]          ; observable: emit the graded line
    call serial_string
    mov  rdi, LOG_INF                     ; and a canonical INFO line via log_line
    lea  rsi, [rel str_sub_lib]
    lea  rdx, [rel str_log_ready]
    call log_line
    lea  rdi, [rel str_logfmt_pass]
    call serial_string
    call log_kat_report                  ; PRINT the KAT results + earned fmt/log markers
    ret
.fail:
    lea  rdi, [rel str_logfmt_fail]
    call serial_string
    ret

; log_kat_report — content-graded observability (TESTING §1): PRINT the fmt
;   known-answer results the probe validates byte-for-byte, then emit the
;   fmt/log acceptance markers. Reached ONLY after fmt_selftest (KAT table) and
;   the log-render nonce grade both PASS above, so the markers are EARNED, not a
;   latch — the printed "ff|0a|deadbeef|2a" is computed live through the one
;   canonical fmt_hex (G1: no 2nd formatter), so a stub can't fake it.
;   clobbers: volatiles (RBX,R12 saved)
log_kat_report:
    push rbx
    push r12
    lea  r12, [rel log_linebuf]           ; running write cursor
    lea  rdi, [rel str_kat_pfx]           ; "[PAOS64][INF][fmt] fmt.kat: "
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  edi, 0xFF                        ; -> "ff"   (zero-extend: never mov r64,imm32)
    mov  rsi, r12
    xor  rdx, rdx
    call fmt_hex
    add  r12, rax
    mov  byte [r12], '|'
    inc  r12
    mov  edi, 0x0A                        ; pad2 -> "0a"
    mov  rsi, r12
    mov  rdx, 2
    call fmt_hex
    add  r12, rax
    mov  byte [r12], '|'
    inc  r12
    mov  edi, 0xDEADBEEF                  ; -> "deadbeef"
    mov  rsi, r12
    xor  rdx, rdx
    call fmt_hex
    add  r12, rax
    mov  byte [r12], '|'
    inc  r12
    mov  edi, 0x2A                        ; -> "2a"  (=42)
    mov  rsi, r12
    xor  rdx, rdx
    call fmt_hex
    add  r12, rax
    mov  byte [r12], 13                   ; CR LF NUL
    mov  byte [r12 + 1], 10
    mov  byte [r12 + 2], 0
    lea  rdi, [rel log_linebuf]
    call serial_string
    lea  rdi, [rel str_fmt_kat_pass]      ; fmt KAT gate marker (core.fmt.kat)
    call serial_string
    lea  rdi, [rel str_log_selftest_pass] ; log structured-line gate marker (core.log.selftest)
    call serial_string
    pop  r12
    pop  rbx
    ret

; --- log.asm data (in-image RW+X pre-BSS, MEMORY_MAP §3.1) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_core_log_0 0
log_linebuf:  times 256 db 0
log_msgbuf:   times 64  db 0

; Level names, 4-byte stride (3 chars + NUL). Adding a level is one more slot +
; one equ — the level set is a table, not a hardcoded switch (TESTING §5 seam).
log_lvl_names: db "DBG", 0, "INF", 0, "WRN", 0, "ERR", 0, "FTL", 0

str_log_open:     db "[PAOS64][", 0
str_log_pido:     db "][pid=", 0
str_log_sep1:     db "][", 0
str_log_sep2:     db "] ", 0
align 8
log_current_principal: dq 1               ; 1053: owning principal for log lines (v1 = OWNER id 1)
str_log_crlf:     db 13, 10, 0
str_sub_lib:      db "lib", 0
str_nonce_pfx:    db "nonce=", 0
str_log_ready:    db "log+fmt online", 0
str_log_expected: db "[PAOS64][INF][pid=1][lib] nonce=cafe", 13, 10, 0
str_logfmt_pass:  db "[PAOS64] P2 lib: log+fmt selftest PASS", 13, 10, 0
str_logfmt_fail:  db "[PAOS64] P2 lib: log+fmt selftest FAIL", 13, 10, 0
str_kat_pfx:          db "[PAOS64][INF][fmt] fmt.kat: ", 0
str_fmt_kat_pass:     db "[PAOS64] P2 fmt: known-answer vectors PASS [core.fmt.kat]", 13, 10, 0
str_log_selftest_pass:db "[PAOS64] P2 log: structured line PASS [core.log.selftest]", 13, 10, 0

; Timeline phase tokens are the same bytes consumed by BOOTLOG.
tok_boot_ab_verify: db " boot.ab.verify",0
tok_boot_ab_loaded: db " boot.ab.state.loaded",0
tok_boot_wdog_arm:  db " boot.watchdog.armed",0
tok_boot_wdog_none: db " boot.watchdog.absent",0
tok_boot_ab_commit: db " boot.ab.committed",0
tok_boot_p7:        db " boot.p7.after_paint",0
tok_boot_p8_warm:   db " boot.p8.warming",0
tok_boot_p8_ready:  db " boot.p8.ready",0
tok_boot_hv_ready:  db " hv.foundation.ready",0
tok_boot_log_lean:  db " boot.log.mode.lean",0
tok_boot_log_verbose: db " boot.log.mode.verbose",0
; Boot-milestone marks (measurement only; latched from the idle-frame owners).
tok_boot_input_kbd_live: db " boot.input.kbd.live",0
tok_boot_input_ptr_live: db " boot.input.ptr.live",0
tok_boot_ssh_ready:      db " boot.ssh.ready",0
tok_boot_terminal_usable: db " boot.terminal.usable",0
tok_boot_dhcp_bound:      db " boot.dhcp.bound",0
tok_boot_dhcp_discover:   db " boot.dhcp.discover",0
tok_boot_dhcp_offer:      db " boot.dhcp.offer",0

align 4
boot_timeline_special_tokens:
    dd tok_boot_ab_verify, tok_boot_ab_loaded, tok_boot_wdog_arm
    dd tok_boot_wdog_none, tok_boot_ab_commit, tok_boot_p7
    dd tok_boot_p8_warm, tok_boot_p8_ready, tok_boot_hv_ready
    dd tok_boot_log_lean, tok_boot_log_verbose
    dd tok_boot_input_kbd_live, tok_boot_input_ptr_live, tok_boot_ssh_ready
    dd tok_boot_terminal_usable, tok_boot_dhcp_bound
    dd tok_boot_dhcp_discover, tok_boot_dhcp_offer
boot_timeline_special_tokens_end:
%endmacro
WDATA_DEFER WDATA_core_log_0
BOOT_TIMELINE_SPECIAL_TOKEN_COUNT equ (boot_timeline_special_tokens_end - boot_timeline_special_tokens) / 4

; Task2301 pointer-identity catalog.  Each row is
; {message_rva,key_rva,token_rva,status}; key_rva is the pass token for the
; subsystem and therefore joins PASS/FAIL/SKIPPED alternatives into one row in
; the live result table.  RVAs are intentionally rebased by the latch routine.
%macro SELFTEST_VERDICT 4
    dd %1, %2, %3
    db %4, 0, 0, 0
%endmacro
align 8
selftest_verdict_catalog:
    SELFTEST_VERDICT str_logfmt_pass,          tok_logfmt_pass,          tok_logfmt_pass,          SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_logfmt_fail,          tok_logfmt_pass,          tok_logfmt_fail,          SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_km_pass,              tok_strmem_pass,          tok_strmem_pass,          SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_km_fail,              tok_strmem_pass,          tok_strmem_fail,          SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_heap_ok,              tok_heap_pass,            tok_heap_pass,            SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_heap_fail,            tok_heap_pass,            tok_heap_fail,            SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_diag_pass,            tok_diag_pass,            tok_diag_pass,            SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_diag_fail,            tok_diag_pass,            tok_diag_fail,            SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_hp_pass,              tok_hotpatch_pass,        tok_hotpatch_pass,        SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_hp_fail,              tok_hotpatch_pass,        tok_hotpatch_fail,        SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_bc_pass,              tok_boot_canon_pass,      tok_boot_canon_pass,      SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_cad_rate,             tok_cadence_pass,         tok_cadence_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_cad_fail,             tok_cadence_pass,         tok_cadence_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_vq_hbcont,            tok_vcpu_quantum_pass,    tok_vcpu_quantum_pass,    SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_vq_fail,              tok_vcpu_quantum_pass,    tok_vcpu_quantum_fail,    SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_tcp_pass,             tok_tcp_pass,             tok_tcp_pass,             SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_arp_pass,             tok_arp_cache_pass,       tok_arp_cache_pass,       SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_dhcp_pass,            tok_dhcp_pass,            tok_dhcp_pass,            SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_dns_pass,             tok_dns_pass,             tok_dns_pass,             SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_stk_arp_pass,         tok_arp_stack_pass,       tok_arp_stack_pass,       SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_ipv4_pass,            tok_ipv4_stack_pass,      tok_ipv4_stack_pass,      SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_udp_pass,             tok_udp_stack_pass,       tok_udp_stack_pass,       SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_blk_flush_ok,         tok_block_flush_pass,     tok_block_flush_pass,     SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_blk_flush_bad,        tok_block_flush_pass,     tok_block_flush_fail,     SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_blk_reinit_ok,        tok_block_reinit_pass,    tok_block_reinit_pass,    SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_blk_reinit_bad,       tok_block_reinit_pass,    tok_block_reinit_fail,    SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_selftest_basic,       tok_vfs_pass,             tok_vfs_pass,             SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_vfs_fail,             tok_vfs_pass,             tok_vfs_fail,             SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_fbkat_ok,             tok_fb_rect_pass,         tok_fb_rect_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_fbkat_fail,           tok_fb_rect_pass,         tok_fb_rect_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_fbkat_nofb,           tok_fb_rect_pass,         tok_fb_rect_skipped,      SELFTEST_VERDICT_SKIPPED
    SELFTEST_VERDICT str_fbkatgeom_ok,         tok_fb_geom_pass,         tok_fb_geom_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_fbkatgeom_fail,       tok_fb_geom_pass,         tok_fb_geom_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_fbkatgeom_nofb,       tok_fb_geom_pass,         tok_fb_geom_skipped,      SELFTEST_VERDICT_SKIPPED
    SELFTEST_VERDICT str_m_turn,               tok_chat_turn_pass,       tok_chat_turn_pass,       SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_turn_fail,            tok_chat_turn_pass,       tok_chat_turn_fail,       SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_chat_nofb,            tok_chat_turn_pass,       tok_chat_turn_skipped,    SELFTEST_VERDICT_SKIPPED
    SELFTEST_VERDICT str_csprng_kat_ok,        tok_csprng_pass,          tok_csprng_pass,          SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_csprng_kat_fail,      tok_csprng_pass,          tok_csprng_fail,          SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_fd_kat_ok,            tok_fmt_dec_pass,         tok_fmt_dec_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_fd_kat_fail,          tok_fmt_dec_pass,         tok_fmt_dec_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_nc_kat_ok,            tok_net_cksum_pass,       tok_net_cksum_pass,       SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_nc_kat_fail,          tok_net_cksum_pass,       tok_net_cksum_fail,       SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_sha256_stream_ok,     tok_sha256_pass,          tok_sha256_pass,          SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_sha256_stream_fail,   tok_sha256_pass,          tok_sha256_fail,          SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_hkdf_kat_marker,      tok_hkdf_pass,            tok_hkdf_pass,            SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_hkdf_kat_fail,        tok_hkdf_pass,            tok_hkdf_fail,            SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_ed_kat_marker,        tok_ed25519_pass,         tok_ed25519_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_ed_fail,              tok_ed25519_pass,         tok_ed25519_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_gcm_kat_marker,       tok_crypto_standard_pass, tok_crypto_standard_pass, SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_crypto_standard_fail, tok_crypto_standard_pass, tok_crypto_standard_fail, SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_cmd_singlevocab,      tok_command_pass,         tok_command_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_cmd_fail,             tok_command_pass,         tok_command_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_aihook_err_ok,        tok_aihook_pass,          tok_aihook_pass,          SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_aihook_fail,          tok_aihook_pass,          tok_aihook_fail,          SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_ml_scan,              tok_mem_layout_pass,      tok_mem_layout_pass,      SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_ml_fail,              tok_mem_layout_pass,      tok_mem_layout_fail,      SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_bootlog_full_kat,     tok_bootlog_full_pass,    tok_bootlog_full_pass,    SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_bootlog_full_kat_fail,tok_bootlog_full_pass,    tok_bootlog_full_fail,    SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_wx_enforced,           tok_security_wx_pass,            tok_security_wx_pass,            SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_security_wx_fail,      tok_security_wx_pass,            tok_security_wx_fail,            SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_cap_pmod_ok,           tok_security_capability_pass,    tok_security_capability_pass,    SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_security_capability_fail,tok_security_capability_pass,  tok_security_capability_fail,    SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_prin_m_kdf,            tok_security_principal_pass,     tok_security_principal_pass,     SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_security_principal_fail,tok_security_principal_pass,    tok_security_principal_fail,     SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_auth_m_principal_deny, tok_security_command_auth_pass,  tok_security_command_auth_pass,  SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_security_command_auth_fail,tok_security_command_auth_pass,tok_security_command_auth_fail,SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_m_audit_kat,           tok_security_audit_pass,         tok_security_audit_pass,         SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_security_audit_fail,   tok_security_audit_pass,         tok_security_audit_fail,         SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_security_secure_boot_pass,tok_security_secure_boot_pass,tok_security_secure_boot_pass,   SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_security_secure_boot_fail,tok_security_secure_boot_pass,tok_security_secure_boot_fail,   SELFTEST_VERDICT_FAIL
    SELFTEST_VERDICT str_selftest_fixture_fail,tok_fixture_pass,         tok_fixture_fail,         SELFTEST_VERDICT_FAIL
    ; Preserve earned boot memory stages even when the target has no serial
    ; sink. These owning message pointers are reached after the actual KAT
    ; checks; they do not snapshot the allocator's live numeric counters.
    ; Append rows so existing timeline catalogue IDs retain their meanings.
    SELFTEST_VERDICT str_heap_kat,             tok_heap_kat_pass,        tok_heap_kat_pass,        SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_heap_guard1,          tok_heap_guard_pass,      tok_heap_guard_pass,      SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_heap_align,           tok_heap_align_pass,      tok_heap_align_pass,      SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_heap_stress,          tok_heap_stress_pass,     tok_heap_stress_pass,     SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_dma_refusal_ok,       tok_dma_adverse_pass,     tok_dma_adverse_pass,     SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_dma_ok,               tok_dma_pass,             tok_dma_pass,             SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_dma_fail,             tok_dma_pass,             tok_dma_fail,             SELFTEST_VERDICT_FAIL
    ; RC s21.1 firmware memory-ownership census (core/memmap_owner.asm).
    SELFTEST_VERDICT str_mmo_pass,             tok_memmap_owner_pass,    tok_memmap_owner_pass,    SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_mmo_fail,             tok_memmap_owner_pass,    tok_memmap_owner_fail,    SELFTEST_VERDICT_FAIL
    ; T1-4.8 final-map refusal KAT (core/mmap_refusal.asm).
    SELFTEST_VERDICT str_mrk_pass,             tok_mmap_refusal_pass,    tok_mmap_refusal_pass,    SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_mrk_fail,             tok_mmap_refusal_pass,    tok_mmap_refusal_fail,    SELFTEST_VERDICT_FAIL
    ; RC s21.1 per-CPU stack privacy + lifetime census (core/smp_stack_census.asm).
    SELFTEST_VERDICT str_ssc_pass,             tok_smp_stack_pass,       tok_smp_stack_pass,       SELFTEST_VERDICT_PASS
    SELFTEST_VERDICT str_ssc_fail,             tok_smp_stack_pass,       tok_smp_stack_fail,       SELFTEST_VERDICT_FAIL
selftest_verdict_catalog_end:
SELFTEST_VERDICT_CATALOG_COUNT equ (selftest_verdict_catalog_end - selftest_verdict_catalog) / SELFTEST_VERDICT_CAT_SIZE
%unmacro SELFTEST_VERDICT 4

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_core_log_1 0
align 8
times 42 db 0                  ; selftest_verdict_results..log_cost_serial_suppress moved to WDATA_core_log_1_bss1: keeps the labels below at their offset mod 64
boot_log_mode:         db LOG_MODE_VERBOSE
boot_log_trigger:      db LOG_TRIGGER_FIRST
align 8
log_cost_serial_tsc:   dq 0
log_cost_ring_tsc:     dq 0
log_cost_capture_tsc:  dq 0

align 8
boot_wait_records: times BOOT_WAIT_MAX * BOOT_WAIT_REC_SIZE db 0
boot_wait_count:   dd 0
boot_wait_dropped: dd 0
boot_wait_ready:   db 0
boot_wait_active:  db 0
align 8
boot_wait_cost_entry: dq 0   ; per-invocation recorder-entry TSC (scratch)
boot_wait_recorded_tsc: dq 0 ; exact accepted P0-P7-domain input ticks, including unknown
boot_wait_last_end:   dq 0   ; original last accepted UART end (global exclusive order)
boot_wait_cost_tsc:   dq 0   ; cumulative recorder cost in TSC ticks (observer tax)

str_timeline_unlatched: db "[PAOS64] P0 fixture [fixture.unlatched]",13,10,0
str_timeline_kat: db "[PAOS64] P6 svc: timeline ordering KAT PASS [boot.timeline.kat]",13,10,0
str_timeline_kat_fail: db "[PAOS64] P6 svc: timeline ordering/overflow KAT FAIL",13,10,0
str_timeline_recorded: db "[PAOS64] P6 svc: marker timeline recorded [boot.timeline.recorded]",13,10,0
str_boot_wait_recorded: db "[PAOS64] boot wait ledger: bounded records present [boot.wait_ledger.recorded]",13,10,0
str_boot_wait_reconciled: db "[PAOS64] boot wait ledger: reconciliation KAT PASS [boot.wait_ledger.reconciled.kat]",13,10,0
str_boot_wait_failed: db "[PAOS64] boot wait ledger: reconciliation KAT FAIL",13,10,0
str_boot_wait_owner_serial: db "bootwait.serial",0
str_boot_wait_owner_unknown: db "bootwait.unattributed",0

str_boot_log_mode_lean: db "[PAOS64] P2 core: serial mode LEAN [boot.log.mode.lean]",13,10,0
str_boot_log_mode_verbose: db "[PAOS64] P2 core: serial mode VERBOSE [boot.log.mode.verbose]",13,10,0
str_boot_log_trigger_clean: db "[PAOS64] P2 core: prior boot clean [boot.log.trigger.clean]",13,10,0
str_boot_log_trigger_trial: db "[PAOS64] P2 core: prior boot had trial attempts [boot.log.trigger.trial]",13,10,0
str_boot_log_trigger_faults: db "[PAOS64] P2 core: prior ring faulted or malformed [boot.log.trigger.faults]",13,10,0
str_boot_log_trigger_first: db "[PAOS64] P2 core: no trustworthy prior boot [boot.log.trigger.first]",13,10,0
str_boot_log_trigger_override: db "[PAOS64] P2 core: owner one-boot policy consumed [boot.log.trigger.override]",13,10,0
str_boot_log_mode_recorded: db "[PAOS64] P2 core: log mode selected [boot.log.mode.recorded]",13,10,0
str_boot_log_mode_kat: db "[PAOS64] P2 core: mode-selection policy KAT PASS [boot.log.mode.kat]",13,10,0
str_boot_log_mode_kat_fail: db "[PAOS64] P2 core: mode-selection policy KAT FAIL",13,10,0

str_selftests_summary: db " SELFTESTS=",0
str_selftests_conflict: db " SELFTEST_CONFLICT=",0
str_selftests_slash:   db "/",0
str_selftests_space:   db " ",0
str_selftest_projected: db "[PAOS64] P6 svc: selftest verdicts projected to BOOTLOG FULL [boot.selftest.verdicts.projected]",13,10,0
str_selftest_bijection: db "[PAOS64] P6 svc: selftest verdict table<->token bijection KAT PASS [boot.selftest.bijection.kat]",13,10,0
str_selftest_bijection_fail: db "[PAOS64] P6 svc: selftest verdict table<->token bijection KAT FAIL",13,10,0
str_selftest_fixture_fail: db "[PAOS64] P6 svc: forced verdict fixture selftest FAIL",13,10,0
str_selftest_fixture_ok: db "[PAOS64] P6 svc: forced verdict fixture observed same-path .fail PASS",13,10,0
str_security_wx_fail: db "[PAOS64] M6 security: W^X NX-half execution test FAIL",13,10,0
str_security_capability_fail: db "[PAOS64] M6 security: capability absent-write denial/granted-read KAT FAIL",13,10,0
str_security_principal_fail: db "[PAOS64] M6 security: principal auth KDF derive KAT FAIL",13,10,0
str_security_command_auth_fail: db "[PAOS64] M6 security: command_auth non-wire system-principal BOOT denial KAT FAIL",13,10,0
str_security_audit_fail: db "[PAOS64] M6 security: audit receipt ring write/readback content KAT FAIL",13,10,0
str_security_secure_boot_pass: db "[PAOS64] M6 security: secure boot firmware observation predicate PASS [security.secure_boot.snapshot.observed]",13,10,0
str_security_secure_boot_fail: db "[PAOS64] M6 security: secure boot pre-EBS snapshot path reached FAIL",13,10,0
str_security_truth_catalog: db "[PAOS64] M6 security: truthful claims and PASS/FAIL verdict catalog PASS [security.marker.truth.catalog]",13,10,0

tok_logfmt_pass:          db "selftest.logfmt.pass",0
tok_logfmt_fail:          db "selftest.logfmt.fail",0
tok_strmem_pass:          db "selftest.strmem.pass",0
tok_strmem_fail:          db "selftest.strmem.fail",0
tok_heap_pass:            db "selftest.heap.pass",0
tok_heap_fail:            db "selftest.heap.fail",0
tok_heap_kat_pass:        db "selftest.heap.kat.pass",0
tok_heap_guard_pass:      db "selftest.heap.guard.pass",0
tok_heap_align_pass:      db "selftest.heap.align.pass",0
tok_heap_stress_pass:     db "selftest.heap.stress.pass",0
tok_dma_adverse_pass:     db "selftest.dma.adverse.pass",0
tok_dma_pass:             db "selftest.dma.pass",0
tok_dma_fail:             db "selftest.dma.fail",0
tok_diag_pass:            db "selftest.diag.pass",0
tok_diag_fail:            db "selftest.diag.fail",0
tok_hotpatch_pass:        db "selftest.hotpatch.pass",0
tok_hotpatch_fail:        db "selftest.hotpatch.fail",0
tok_boot_canon_pass:      db "selftest.boot_canon.pass",0
tok_cadence_pass:         db "selftest.cadence.pass",0
tok_cadence_fail:         db "selftest.cadence.fail",0
tok_vcpu_quantum_pass:    db "selftest.vcpu_quantum.pass",0
tok_vcpu_quantum_fail:    db "selftest.vcpu_quantum.fail",0
tok_tcp_pass:             db "selftest.tcp.pass",0
tok_arp_cache_pass:       db "selftest.arp_cache.pass",0
tok_dhcp_pass:            db "selftest.dhcp.pass",0
tok_dns_pass:             db "selftest.dns.pass",0
tok_arp_stack_pass:       db "selftest.arp_stack.pass",0
tok_ipv4_stack_pass:      db "selftest.ipv4_stack.pass",0
tok_udp_stack_pass:       db "selftest.udp_stack.pass",0
tok_block_flush_pass:     db "selftest.block_flush.pass",0
tok_block_flush_fail:     db "selftest.block_flush.fail",0
tok_block_reinit_pass:    db "selftest.block_reinit.pass",0
tok_block_reinit_fail:    db "selftest.block_reinit.fail",0
tok_vfs_pass:             db "selftest.vfs.pass",0
tok_vfs_fail:             db "selftest.vfs.fail",0
tok_fb_rect_pass:         db "selftest.fb_rect.pass",0
tok_fb_rect_fail:         db "selftest.fb_rect.fail",0
tok_fb_rect_skipped:      db "selftest.fb_rect.skipped",0
tok_fb_geom_pass:         db "selftest.fb_geom.pass",0
tok_fb_geom_fail:         db "selftest.fb_geom.fail",0
tok_fb_geom_skipped:      db "selftest.fb_geom.skipped",0
tok_chat_turn_pass:       db "selftest.chat_turn.pass",0
tok_chat_turn_fail:       db "selftest.chat_turn.fail",0
tok_chat_turn_skipped:    db "selftest.chat_turn.skipped",0
tok_csprng_pass:          db "selftest.csprng.pass",0
tok_csprng_fail:          db "selftest.csprng.fail",0
tok_fmt_dec_pass:         db "selftest.fmt_dec.pass",0
tok_fmt_dec_fail:         db "selftest.fmt_dec.fail",0
tok_net_cksum_pass:       db "selftest.net_cksum.pass",0
tok_net_cksum_fail:       db "selftest.net_cksum.fail",0
tok_sha256_pass:          db "selftest.sha256.pass",0
tok_sha256_fail:          db "selftest.sha256.fail",0
tok_hkdf_pass:            db "selftest.hkdf.pass",0
tok_hkdf_fail:            db "selftest.hkdf.fail",0
tok_ed25519_pass:         db "selftest.ed25519.pass",0
tok_ed25519_fail:         db "selftest.ed25519.fail",0
tok_crypto_standard_pass: db "selftest.crypto_standard.pass",0
tok_crypto_standard_fail: db "selftest.crypto_standard.fail",0
tok_command_pass:         db "selftest.command.pass",0
tok_command_fail:         db "selftest.command.fail",0
tok_aihook_pass:          db "selftest.aihook.pass",0
tok_aihook_fail:          db "selftest.aihook.fail",0
tok_mem_layout_pass:      db "selftest.mem_layout.pass",0
tok_mem_layout_fail:      db "selftest.mem_layout.fail",0
tok_memmap_owner_pass:    db "selftest.memmap_owner.pass",0
tok_memmap_owner_fail:    db "selftest.memmap_owner.fail",0
tok_mmap_refusal_pass:    db "selftest.mmap_refusal.pass",0
tok_mmap_refusal_fail:    db "selftest.mmap_refusal.fail",0
tok_smp_stack_pass:       db "selftest.smp_stack.pass",0
tok_smp_stack_fail:       db "selftest.smp_stack.fail",0
tok_bootlog_full_pass:    db "selftest.bootlog_full.pass",0
tok_bootlog_full_fail:    db "selftest.bootlog_full.fail",0
tok_security_wx_pass:           db "security.wx.nx_half.pass",0
tok_security_wx_fail:           db "security.wx.nx_half.fail",0
tok_security_capability_pass:   db "security.capability.kat.pass",0
tok_security_capability_fail:   db "security.capability.kat.fail",0
tok_security_principal_pass:    db "security.principal.kdf.pass",0
tok_security_principal_fail:    db "security.principal.kdf.fail",0
tok_security_command_auth_pass: db "security.command_auth.nonwire_deny.pass",0
tok_security_command_auth_fail: db "security.command_auth.nonwire_deny.fail",0
tok_security_audit_pass:        db "security.audit.receipt.pass",0
tok_security_audit_fail:        db "security.audit.receipt.fail",0
tok_security_secure_boot_pass:  db "security.secure_boot.snapshot_path.pass",0
tok_security_secure_boot_fail:  db "security.secure_boot.snapshot_path.fail",0
tok_fixture_pass:         db "selftest.fixture.pass",0
tok_fixture_fail:         db "selftest.fixture.fail",0
%endmacro
WDATA_DEFER WDATA_core_log_1
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_core_log_1_bss1 0
alignb 8
selftest_verdict_results: resb SELFTEST_VERDICT_MAX * SELFTEST_VERDICT_REC_SIZE
selftest_verdict_count:    resd 1
selftest_verdict_passes:   resd 1
selftest_verdict_fails:    resd 1
selftest_verdict_skips:    resd 1
selftest_verdict_conflict: resb 1

alignb 8
boot_timeline_records: resb BOOT_TIMELINE_MAX * BOOT_TIMELINE_REC_SIZE
boot_timeline_count:   resd 1
boot_timeline_dropped: resd 1
boot_timeline_special_count: resd 1
alignb 8
boot_timeline_special_catalog: resb BOOT_TIMELINE_SPECIAL_MAX * 16
boot_timeline_overflow_kat_ok: resb 1
log_cost_serial_suppress: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_core_log_1_bss1
