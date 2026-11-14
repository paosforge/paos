;; MODULE core/time
; Task1230e1 seam: NTP may publish only through the canonical wall-offset record.
;; LAYER 1
;; EXPORTS tsc_now, tsc_calibrate, tsc_delay_us, time_selftest, tsc_khz, time_monotonic_now_us, time_wall_set_us, time_wall_now_us, time_wall_now_s, time_wall_utc_now_s, wall_offset, time_wall_seq, time_wall_valid, time_wall_source, time_wall_clear, time_wall_window_now_s, time_wall_local_issue_s, time_wall_local_issue_end, time_rtc_read_count, time_rtc_write_count, timer_init, timer_selftest, timer_ticks, timer_irq0_count, timer_irq0_snapshot, preempt_selftest, time_zone_hook, time_utc_offset, time_local_to_utc
;; IMPORTS boot/serial, core/idt, core/heap, boot/indicator, core/normal_deadman
;; CAPS
;; OWNER saga:core
; Standalone source harnesses retain the same disabled default as boot/header.
%ifndef PAOS_NORMAL_DEADMAN_MS
%define PAOS_NORMAL_DEADMAN_MS 0
%endif
; ============================================================================
; core/time.asm — TSC timestamps + microsecond delays, calibrated from validated
; architectural CPUID.15 data or the measured PIT fallback.
;
; The kernel's time base. tsc_calibrate prefers complete architectural Intel
; frequency data, then measures a known PIT channel-2 interval; tsc_delay_us gives the
; bounded busy-waits hardware bring-up needs. (HPET-based recalibration is a
; later refinement; PIT is the M1 floor.) The calibration poll is BOUNDED so a
; dead/odd PIT degrades to a reported failure, never a hang.
;
; PIT: 1193182 Hz. Ports: 0x43 cmd, 0x42 ch2 data, 0x61 (bit0 gate2, bit5 OUT2).
; ============================================================================

PIT_HZ          equ 1193182
TSC_CPUID15_MIN_KHZ equ 100000       ; reject rates below 100 MHz
TSC_CPUID15_MAX_KHZ equ 10000000     ; reject rates above 10 GHz

TSC_CAL_SOURCE_PIT     equ 0
TSC_CAL_SOURCE_CPUID15 equ 1

; RCQ-17: what last set the wall clock. These are its only setters: the CMOS seed
; and an applied SNTP sample. The NTP self-test restores the pre-test pair, or
; (time_wall_clear) returns a wall that was unseeded before it to unseeded.
; command_gui.asm's CLOCK reply names them in this order (str_ck_src_names).
TIME_SRC_NONE equ 0                  ; unseeded
TIME_SRC_RTC  equ 1                  ; time_wall_seed_rtc (approximate, may be local time)
TIME_SRC_NTP  equ 2                  ; ntp_grade_commit_best
TIME_SRC_COUNT equ 3

TSC_CAL_REASON_NONE          equ 0
TSC_CAL_REASON_NON_INTEL     equ 1
TSC_CAL_REASON_LEAF15_ABSENT equ 2
TSC_CAL_REASON_NO_INVARIANT  equ 3
TSC_CAL_REASON_ZERO_DENOM    equ 4
TSC_CAL_REASON_ZERO_NUMER    equ 5
TSC_CAL_REASON_ZERO_CRYSTAL  equ 6
TSC_CAL_REASON_OVERFLOW      equ 7
TSC_CAL_REASON_IMPLAUS_LOW   equ 8
TSC_CAL_REASON_IMPLAUS_HIGH  equ 9

; tsc_calibrate_cpuid15() -> RAX = validated kHz, or zero for measured fallback.
;
; Intel SDM CPUID.15H defines TSC Hz as crystal_hz * numerator / denominator.
; A result is architectural only when the vendor, invariant-TSC capability,
; maximum basic leaf, and all three ratio fields validate.  The inputs are
; zero-extended CPUID dwords and MUL retains the complete 128-bit product;
; checking RDX before DIV makes the no-overflow contract explicit.  CPUID.16
; and model/base-clock guesses are intentionally absent.
;
; The old tsc_calibrate contract clobbers RAX/RCX/RDX and preserves all other
; caller registers.  CPUID also writes RBX, while the calculation uses R8/R9,
; so preserve all three here.
tsc_calibrate_cpuid15:
    push rbx
    push r8
    push r9
    mov  byte [rel tsc_calibration_source], TSC_CAL_SOURCE_PIT
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_NONE

    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547             ; "Genu"
    jne  .non_intel
    cmp  edx, 0x49656E69             ; "ineI"
    jne  .non_intel
    cmp  ecx, 0x6C65746E             ; "ntel"
    jne  .non_intel
    cmp  eax, 0x15
    jb   .leaf15_absent

    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x80000007
    jb   .no_invariant
    mov  eax, 0x80000007
    cpuid
    test edx, 1 << 8                 ; invariant TSC
    jz   .no_invariant

    mov  eax, 0x15
    xor  ecx, ecx
    cpuid
    test eax, eax                    ; denominator
    jz   .zero_denom
    test ebx, ebx                    ; numerator
    jz   .zero_numer
    test ecx, ecx                    ; crystal Hz (must be enumerated)
    jz   .zero_crystal

    mov  r8d, eax                    ; zero-extended denominator
    mov  r9d, ebx                    ; zero-extended numerator
    mov  eax, ecx                    ; zero-extended crystal Hz
    mul  r9                          ; RDX:RAX = crystal * numerator
    test rdx, rdx                    ; reject before DIV if quotient could overflow
    jnz  .overflow
    div  r8                          ; exact floor TSC Hz
    xor  edx, edx
    mov  ecx, 1000
    div  rcx                         ; exact floor kHz
    cmp  rax, TSC_CPUID15_MIN_KHZ
    jb   .implausible_low
    cmp  rax, TSC_CPUID15_MAX_KHZ
    ja   .implausible_high

    mov  byte [rel tsc_calibration_source], TSC_CAL_SOURCE_CPUID15
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_NONE
    jmp  .done

.non_intel:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_NON_INTEL
    jmp  .reject
.leaf15_absent:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_LEAF15_ABSENT
    jmp  .reject
.no_invariant:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_NO_INVARIANT
    jmp  .reject
.zero_denom:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_ZERO_DENOM
    jmp  .reject
.zero_numer:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_ZERO_NUMER
    jmp  .reject
.zero_crystal:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_ZERO_CRYSTAL
    jmp  .reject
.overflow:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_OVERFLOW
    jmp  .reject
.implausible_low:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_IMPLAUS_LOW
    jmp  .reject
.implausible_high:
    mov  byte [rel tsc_calibration_reason], TSC_CAL_REASON_IMPLAUS_HIGH
.reject:
    xor  eax, eax
.done:
    pop  r9
    pop  r8
    pop  rbx
    ret

; tsc_now() -> RAX = full 64-bit TSC
tsc_now:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    ret

; tsc_calibrate() -> sets [tsc_khz] (0 on timeout or invalid PIT interval)
tsc_calibrate:
    push rbx
    call tsc_now
    mov  rbx, rax                   ; start of architectural validation
    call tsc_calibrate_cpuid15
    test rax, rax
    jz   .pit_fallback
    mov  [rel tsc_khz], rax
    call tsc_now
    mov  [rel time_monotonic_tsc_origin], rax
    sub  rax, rbx
    mov  [rel tsc_calibration_duration_ticks], rax
    pop  rbx
    ret

.pit_fallback:
    ; PIT ch2: speaker off, gate on
    in   al, 0x61
    and  al, 0xFC
    or   al, 0x01
    out  0x61, al
    ; ch2, access lo/hi, mode 0 (terminal count), binary
    mov  al, 0xB0
    out  0x43, al
    mov  al, 0xFF                   ; count = 0xFFFF (~54.9 ms)
    out  0x42, al
    mov  al, 0xFF
    out  0x42, al

    call tsc_now
    mov  rbx, rax                   ; TSC start
    mov  rcx, 0x80000000            ; bounded poll
.wait:
    in   al, 0x61
    test al, 0x20                   ; OUT2 high = count reached 0
    jnz  .done
    dec  rcx
    jnz  .wait
    call tsc_now
    sub  rax, rbx
    mov  [rel tsc_calibration_duration_ticks], rax
    mov  qword [rel tsc_khz], 0     ; timeout — degrade
    pop  rbx
    ret
.done:
    call tsc_now
    sub  rax, rbx                   ; delta TSC over 0xFFFF PIT ticks
    mov  [rel tsc_calibration_duration_ticks], rax
    jc   .invalid_pit               ; backward sample, not an elapsed interval
    test rax, rax
    jz   .invalid_pit               ; no measured progress
    xor  rdx, rdx
    mov  rcx, PIT_HZ
    mul  rcx                        ; rdx:rax = delta * PIT_HZ
    mov  rcx, 65535
    cmp  rdx, rcx                   ; DIV fits iff high product < divisor
    jae  .invalid_pit               ; refuse before a quotient-overflow #DE
    div  rcx                        ; rax = TSC Hz
    xor  rdx, rdx
    mov  rcx, 1000
    div  rcx                        ; rax = TSC kHz
    test rax, rax
    jz   .invalid_pit               ; no usable scale: do not publish an origin
    mov  [rel tsc_khz], rax
    mov  [rel time_monotonic_tsc_origin], rbx
    pop  rbx
    ret
.invalid_pit:
    mov  qword [rel tsc_khz], 0     ; degrade exactly as timeout, no new origin
    pop  rbx
    ret

; State the selected source and exact CPUID refusal.  Only a validated
; architectural selection emits the compiler-registered earned marker.
tsc_calibration_report:
    cmp  byte [rel tsc_calibration_source], TSC_CAL_SOURCE_CPUID15
    jne  .fallback
    lea  rdi, [rel str_time_cpuid15_validated]
    call serial_string
    jmp  .duration
.fallback:
    lea  rdi, [rel str_time_cpuid15_fallback]
    call serial_string
    movzx eax, byte [rel tsc_calibration_reason]
    mov  rdi, rax
    call serial_hex64
    lea  rdi, [rel str_time_cal_newline]
    call serial_string
.duration:
    lea  rdi, [rel str_time_cal_duration]
    call serial_string
    mov  rdi, [rel tsc_calibration_duration_ticks]
    call serial_hex64
    lea  rdi, [rel str_time_cal_newline]
    call serial_string
    ret

; tsc_us_ticks(RDI = microseconds) -> RAX = us * tsc_khz / 1000 (exact floor)
; DIV-FREE: /1000 as >>3 then reciprocal-multiply by ceil(2^68/125) then >>4
; (the compiler-proven u64/1000 sequence) — exact for every product < 2^64
; (error bound 19*n < 2^68 holds through n = 2^61) and ~60 cycles cheaper per
; call than div. Product >= 2^64 (a >53-day delay at 4 GHz) is out of contract,
; as it was for the old div (whose quotient overflow raised #DE). Clobbers rcx, rdx.
tsc_us_ticks:
    mov  rax, rdi
    mul  qword [rel tsc_khz]        ; rax = us * kHz (low 64 — see bound above)
    shr  rax, 3                     ; /8 ...
    mov  rcx, 0x20C49BA5E353F7CF    ; ceil(2^68 / 125)
    mul  rcx
    shr  rdx, 4                     ; ... then /125 => exact /1000
    mov  rax, rdx
    ret

; tsc_delay_us(RDI = microseconds) — busy-wait, hot-path tuned (fan-in 21:
; xhci/nvme/irq poll loops lean on this). rdtsc is INLINED in the spin (no
; call/ret per poll), pause sits AFTER the exit test so the final iteration
; never pays it, and 0 ticks (us=0 or uncalibrated tsc_khz=0) returns without
; reading the TSC at all. Clobbers rax, rcx, rdx only (rdi/rbx preserved,
; no stack traffic).
tsc_delay_us:
    call tsc_us_ticks
    test rax, rax
    jz   .out
    mov  rcx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rcx, rax                   ; target TSC
.spin:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, rcx
    jae  .out
    pause
    jmp  .spin
.out:
    ret

; time_selftest — calibrate + report; nonzero kHz = pass
time_selftest:
    call tsc_calibrate
    call tsc_calibration_report
    mov  rax, [rel tsc_khz]
    test rax, rax
    jz   .fail
    call time_wall_seed_rtc            ; approximate epoch; SNTP later corrects it
    lea  rdi, [rel str_time_ok]
    call serial_string
    mov  rdi, [rel tsc_khz]
    call serial_hex64
    lea  rdi, [rel str_khz]
    call serial_string
    call tsc_delay_kat              ; grade the delay now that calibration is live
    ret
.fail:
    lea  rdi, [rel str_time_fail]
    call serial_string
    ret

; time_monotonic_now_us() -> RAX = boot-relative invariant-TSC microseconds.
; This is the sole duration substrate: wall corrections never write its origin
; or tsc_khz, so scheduler deadlines and timeout measurements cannot step.
time_monotonic_now_us:
    mov  r8, [rel tsc_khz]
    test r8, r8
    jz   .mono_unavailable
    call tsc_now
    sub  rax, [rel time_monotonic_tsc_origin]
    mov  rcx, 1000
    mul  rcx
    div  r8
    ret
.mono_unavailable:
    xor  eax, eax
    ret

; time_wall_set_us(RDI=Unix microseconds, ESI=TIME_SRC_*) — atomically replace
; only the one canonical wall-offset record: wall = monotonic + offset.  The
; invariant-TSC base and every duration/deadline remain untouched.  A tiny
; sequence counter lets an IRQ or future core obtain one coherent offset
; snapshot.  RCQ-17: the setter's source (CLOCK src=) is published with it.
time_wall_set_us:
    push rbx
    mov  rbx, rdi
    pushfq
    cli                              ; sample+publish is one atomic critical section
    push rsi
    call time_monotonic_now_us
    pop  rsi
    mov  rdx, rax
    sub  rbx, rax                      ; desired wall - monotonic = new offset
    inc  dword [rel time_wall_seq]
    ; Only an NTP step over a valid wall keeps the frame it replaced, with the
    ; hold that frame had (for time_wall_window_now_s); RTC seeds and the KAT
    ; restore keep none. Any backward set over a valid wall raises the hold to
    ; the replaced frame's second: no window issued at or before it is read in
    ; a later frame, so a backward step never revives an expired ticket.
    mov  byte [rel time_wall_prev_valid], 0
    cmp  byte [rel time_wall_valid], 1
    jne  .publish
    mov  rax, [rel wall_offset]
    mov  rcx, [rel time_wall_hold_s]
    cmp  sil, TIME_SRC_NTP
    jne  .hold
    mov  [rel time_wall_prev_offset], rax
    mov  [rel time_wall_step_mono_us], rdx
    mov  [rel time_wall_prev_hold_s], rcx
    mov  byte [rel time_wall_prev_valid], 1
.hold:
    cmp  rbx, rax
    jge  .publish
    add  rax, rdx                      ; the replaced frame's wall now
    xor  edx, edx
    mov  r8d, 1000000
    div  r8
    cmp  rax, rcx
    jbe  .publish
    mov  [rel time_wall_hold_s], rax
.publish:
    mov  [rel wall_offset], rbx
    mov  byte [rel time_wall_valid], 1
    mov  [rel time_wall_source], sil
    inc  dword [rel time_wall_seq]
    popfq
    pop  rbx
    ret

; time_wall_clear — RCQ-17: return the wall to unseeded (valid=0, source none) in
; the same seq-bracketed critical section the setter uses. Only the NTP self-test
; calls it: its known-answer reply is applied for real, and without this an
; unseeded wall (rejected CMOS seed) kept the fixture time as a valid ntp wall.
time_wall_clear:
    pushfq
    cli
    inc  dword [rel time_wall_seq]
    mov  byte [rel time_wall_valid], 0
    mov  byte [rel time_wall_source], TIME_SRC_NONE
    mov  byte [rel time_wall_prev_valid], 0
    inc  dword [rel time_wall_seq]
    popfq
    ret

; time_wall_now_us() -> RAX=Unix microseconds, or zero before an epoch seed.
time_wall_now_us:
.snapshot:
    mov  esi, [rel time_wall_seq]
    test sil, 1
    jnz  .snapshot
    mov  r9, [rel wall_offset]
    movzx r10d, byte [rel time_wall_valid]
    test r10d, r10d
    jz   .not_set
    call time_monotonic_now_us
    add  rax, r9
    cmp  esi, [rel time_wall_seq]
    jne  .snapshot
    ret
.not_set:
    cmp  esi, [rel time_wall_seq]
    jne  .snapshot
    xor  eax, eax
    ret

; time_wall_window_now_s(RDI=first s, RSI=last s, RDX=grace s) -> RAX = the wall
; second inside [first, last], read in the current frame or else in the frame the
; last NTP step replaced while that step is at most grace s old (monotonic); zero
; = neither (or unseeded). A signed window issued just before an asynchronous NTP
; step stays usable, and only for its own real length: both frames advance with
; the one monotonic clock. A frame reads no window whose first second is at or
; before its hold (time_wall_set_us), except the current frame's one armed
; native issue (time_wall_local_issue_s). Clobbers RCX, RDX, RSI, R8-R10.
time_wall_window_now_s:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
.snapshot:
    mov  ebx, [rel time_wall_seq]
    test bl, 1
    jnz  .snapshot
    cmp  byte [rel time_wall_valid], 1
    jne  .none
    call time_monotonic_now_us
    mov  r15, rax
    add  rax, [rel wall_offset]
    xor  edx, edx
    mov  rcx, 1000000
    div  rcx
    cmp  rax, r12
    jb   .previous
    cmp  rax, r13
    ja   .previous
    cmp  r12, [rel time_wall_hold_s]
    ja   .done
    cmp  byte [rel time_wall_local_armed], 1   ; a native issue at now in this frame
    jne  .previous
    cmp  r12, [rel time_wall_local_s]
    je   .done
.previous:
    cmp  byte [rel time_wall_prev_valid], 1
    jne  .none
    mov  rax, r15
    sub  rax, [rel time_wall_step_mono_us]
    jb   .none
    mov  rcx, r14
    imul rcx, rcx, 1000000
    cmp  rax, rcx
    ja   .none
    mov  rax, r15
    add  rax, [rel time_wall_prev_offset]
    xor  edx, edx
    mov  rcx, 1000000
    div  rcx
    cmp  rax, r12
    jb   .none
    cmp  rax, r13
    ja   .none
    cmp  r12, [rel time_wall_prev_hold_s]
    ja   .done
.none:
    xor  eax, eax
.done:
    cmp  ebx, [rel time_wall_seq]
    jne  .snapshot
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; time_wall_local_issue_s() -> RAX = time_wall_now_s, latched for a window a
; native issuer stamps at now (console password, SSH owner, AI hook): after a
; backward step that window is at or before the hold, and nothing in its numbers
; tells it from a revived remote one. While armed, a current-frame read of
; exactly that first second passes the hold. The issuer's check runs in the same
; call chain and the issuer calls time_wall_local_issue_end after it, so no
; remote window meets an armed latch. Clobbers as time_wall_now_s.
time_wall_local_issue_s:
    call time_wall_now_s
    mov  [rel time_wall_local_s], rax
    mov  byte [rel time_wall_local_armed], 1
    ret

; time_wall_local_issue_end() drops the latch; every register and flag is kept.
time_wall_local_issue_end:
    mov  byte [rel time_wall_local_armed], 0
    ret

; time_wall_now_s() -> RAX=Unix whole seconds (zero while unseeded).
time_wall_now_s:
    call time_wall_now_us
    test rax, rax
    jz   .seconds_done
    xor  edx, edx
    mov  rcx, 1000000
    div  rcx
.seconds_done:
    ret

; RCQ-20 E2t (root 2026-10-17 21:04:41): the PaOS clock zone for the layers below the GUI. FAT32
; stores local time in the PaOS clock zone; the zone (TZSET's fixed minutes or a pinned named zone)
; lives in gui/window, which a lower layer may not call. The GUI installs its lookup here
; (clock_prefs_load); 0 = no zone known (a boot without the GUI): every conversion is then unknown.
; The hook: RAX = UTC seconds -> RDX = minutes east of UTC, CF=1 none; it keeps RAX, R8 and R11.
; time_utc_offset(RAX=UTC seconds) -> RDX = minutes east of UTC in force then, CF=1 unknown.
;   RAX, R8, R11 kept; clobbers RCX, RSI, R9, R10.
time_utc_offset:
    mov  rcx, [rel time_zone_hook]
    test rcx, rcx
    jz   .unknown
    jmp  rcx
.unknown:
    stc
    ret

; time_local_to_utc(RAX=local civil seconds, the reading of the PaOS clock zone) -> RAX = the UTC
;   instant at which the zone reads that, CF=1 unknown (no zone, outside the zone's pinned range, or a
;   local time a forward transition skips). A repeated hour resolves to the instant the passes meet
;   first. Clobbers RCX, RDX, RSI, R8, R9, R10, R11.
time_local_to_utc:
    test rax, rax
    jle  .unknown
    mov  r11, rax                        ; L
    call time_utc_offset                 ; first guess: the offset at L read as UTC
    jc   .unknown
    mov  r8d, 2                          ; at most two refinements
.pass:
    movsxd rcx, edx
    imul rdx, rcx, 60
    mov  rax, r11
    sub  rax, rdx                        ; U = L - offset
    jle  .unknown
    push rcx
    call time_utc_offset                 ; the offset in force at U (RAX kept)
    pop  rcx
    jc   .unknown
    cmp  edx, ecx
    je   .found                          ; the zone reads L at U
    dec  r8d
    jnz  .pass
.unknown:
    stc
    ret
.found:
    clc
    ret

; time_wall_utc_now_s() -> RAX=Unix whole seconds with UTC provenance, else zero.
; RCQ-20 (root 2026-10-16 22:58:37): only an applied SNTP sample (TIME_SRC_NTP)
; sets the wall from UTC. The CMOS seed is local time on a dual-boot RTC that
; Windows keeps (Reatan/Dell/Beelink stamped UTC-7h), and nothing here can tell a
; local RTC from a UTC one, so an RTC-seeded or unseeded wall reads zero: a
; caller that must write UTC (NTFS FILETIME) refuses rather than stamp a local
; or invented time. No offset is guessed and the RTC is never written. The
; source and the wall come from one seq-coherent snapshot.
time_wall_utc_now_s:
    push rbx
.snapshot:
    mov  ebx, [rel time_wall_seq]
    test bl, 1
    jnz  .snapshot
    cmp  byte [rel time_wall_source], TIME_SRC_NTP
    jne  .no_utc
    call time_wall_now_s
    cmp  ebx, [rel time_wall_seq]
    jne  .snapshot
    pop  rbx
    ret
.no_utc:
    cmp  ebx, [rel time_wall_seq]
    jne  .snapshot
    xor  eax, eax
    pop  rbx
    ret

; CMOS RTC seed.  It is intentionally approximate (dual-boot RTCs may be local
; time); its only job is to put T1/T4 within the one-day anti-spoof envelope so
; the first authenticated-by-originate SNTP sample can correct the epoch.
time_wall_seed_rtc:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel time_wall_valid], 0
    mov  byte [rel time_wall_source], TIME_SRC_NONE
    mov  r10d, 200000
.wait_uip:
    mov  dil, 0x0a
    call time_cmos_read
    test al, 0x80
    jz   .read
    dec  r10d
    jnz  .wait_uip
    jmp  .invalid                    ; update never cleared: no trustworthy epoch seed
.read:
    mov  dil, 0x00
    call time_cmos_read
    mov  bl, al                       ; second
    mov  dil, 0x02
    call time_cmos_read
    mov  r12b, al                     ; minute
    mov  dil, 0x04
    call time_cmos_read
    mov  r13b, al                     ; hour (+ PM bit in 12-hour mode)
    mov  dil, 0x07
    call time_cmos_read
    mov  r14b, al                     ; day
    mov  dil, 0x08
    call time_cmos_read
    mov  r15b, al                     ; month
    mov  dil, 0x09
    call time_cmos_read
    mov  bpl, al                      ; year 00..99
    mov  dil, 0x0b
    call time_cmos_read
    mov  r9b, al                      ; RTC mode
    ; A clear UIP before the first byte does not protect a later rollover.
    ; Confirm one identical raw calendar/mode between two more clear UIP
    ; observations. No retry: an unstable seed stays invalid/NONE for NTP.
    mov  dil, 0x0a
    call time_cmos_read
    test al, 0x80
    jnz  .invalid
    mov  dil, 0x00
    call time_cmos_read
    cmp  al, bl
    jne  .invalid
    mov  dil, 0x02
    call time_cmos_read
    cmp  al, r12b
    jne  .invalid
    mov  dil, 0x04
    call time_cmos_read
    cmp  al, r13b
    jne  .invalid
    mov  dil, 0x07
    call time_cmos_read
    cmp  al, r14b
    jne  .invalid
    mov  dil, 0x08
    call time_cmos_read
    cmp  al, r15b
    jne  .invalid
    mov  dil, 0x09
    call time_cmos_read
    cmp  al, bpl
    jne  .invalid
    mov  dil, 0x0b
    call time_cmos_read
    cmp  al, r9b
    jne  .invalid
    mov  dil, 0x0a
    call time_cmos_read
    test al, 0x80
    jnz  .invalid
    mov  r11b, r13b
    and  r11b, 0x80                   ; PM is meaningful only in 12-hour mode
    test r9b, 0x02
    jz   .hour_flag_ok
    test r11b, r11b
    jnz  .invalid                    ; 24-hour input must not contain a PM flag
.hour_flag_ok:
    and  r13b, 0x7f
    test r9b, 0x04                    ; binary mode?
    jnz  .binary
    mov  al, bl
    call time_bcd2bin
    jc   .invalid                    ; malformed packed decimal is not a calendar
    mov  bl, al
    mov  al, r12b
    call time_bcd2bin
    jc   .invalid                    ; malformed packed decimal is not a calendar
    mov  r12b, al
    mov  al, r13b
    call time_bcd2bin
    jc   .invalid                    ; malformed packed decimal is not a calendar
    mov  r13b, al
    mov  al, r14b
    call time_bcd2bin
    jc   .invalid                    ; malformed packed decimal is not a calendar
    mov  r14b, al
    mov  al, r15b
    call time_bcd2bin
    jc   .invalid                    ; malformed packed decimal is not a calendar
    mov  r15b, al
    mov  al, bpl
    call time_bcd2bin
    jc   .invalid                    ; malformed packed decimal is not a calendar
    mov  bpl, al
.binary:
    test r9b, 0x02                    ; 24-hour mode?
    jnz  .validate
    cmp  r13b, 1
    jb   .invalid
    cmp  r13b, 12
    ja   .invalid                    ; validate before 12-hour normalization
    jne  .not_noon
    xor  r13d, r13d
.not_noon:
    test r11b, r11b
    jz   .validate
    add  r13b, 12
.validate:
    movzx eax, bpl
    add  eax, 2000
    mov  ebp, eax
    cmp  eax, 2020
    jb   .invalid
    cmp  eax, 2099
    ja   .invalid
    movzx eax, r15b
    cmp  eax, 1
    jb   .invalid
    cmp  eax, 12
    ja   .invalid
    movzx eax, r14b
    cmp  eax, 1
    jb   .invalid
    cmp  eax, 31
    ja   .invalid
    cmp  r13b, 23
    ja   .invalid
    cmp  r12b, 59
    ja   .invalid
    cmp  bl, 59
    ja   .invalid
    ; Month/year were admitted above. Only 2020..2099 is supported, so
    ; divisible-by-four is the complete leap rule within this seed window.
    movzx eax, r15b
    dec  eax
    lea  r8, [rel time_month_days]
    movzx edx, byte [r8 + rax]
    cmp  r15b, 2
    jne  .day_limit
    test bpl, 3
    jnz  .day_limit
    inc  edx
.day_limit:
    cmp  r14b, dl
    ja   .invalid                    ; never normalize an impossible civil date

    ; Gregorian days since 1970; 2000 is leap and the accepted range ends
    ; before the 2100 century exception.
    mov  eax, ebp
    sub  eax, 1970
    imul rax, rax, 365
    mov  ecx, ebp
    sub  ecx, 1969
    shr  ecx, 2
    add  rax, rcx
    movzx ecx, r15b
    dec  ecx
    lea  r8, [rel time_month_days]
    xor  edx, edx
.month_loop:
    cmp  edx, ecx
    jae  .months_done
    movzx esi, byte [r8 + rdx]
    add  rax, rsi
    inc  edx
    jmp  .month_loop
.months_done:
    cmp  ecx, 2
    jb   .day
    test bpl, 3
    jnz  .day
    inc  rax
.day:
    movzx edx, r14b
    dec  edx
    add  rax, rdx
    imul rax, rax, 86400
    movzx edx, r13b
    imul rdx, rdx, 3600
    add  rax, rdx
    movzx edx, r12b
    imul rdx, rdx, 60
    add  rax, rdx
    movzx edx, bl
    add  rax, rdx
    imul rax, rax, 1000000
    mov  rdi, rax
    mov  esi, TIME_SRC_RTC
    call time_wall_set_us
.invalid:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

time_cmos_read:
    inc  qword [rel time_rtc_read_count] ; evidence only; NTP never calls this path
    mov  al, dil
    or   al, 0x80                      ; match the proven project CMOS access
    mov  dx, 0x70
    out  dx, al
    mov  dx, 0x71
    in   al, dx
    ret

time_bcd2bin:
    push rcx
    mov  cl, al
    and  cl, 0x0f
    cmp  cl, 9
    ja   .invalid
    shr  al, 4
    cmp  al, 9
    ja   .invalid
    mov  ah, 10
    mul  ah
    add  al, cl
    pop  rcx
    clc                               ; CF=0: both packed-decimal digits admitted
    ret
.invalid:
    pop  rcx
    stc                               ; CF=1: caller must refuse this raw field
    ret

; tsc_delay_kat — known-answer gate for tsc_delay_us. Exact conversion vectors
; run with tsc_khz INJECTED (saved/restored; boot is single-threaded here):
; a conversion off by one bit fails byte-for-byte. V6/V7 deliberately stress
; the reciprocal path (high product, floor just under .999 round-up). Then ONE
; live measured delay: elapsed TSC must be >= the exact requested tick count
; (early return fails) and < 64x it (wild over-delay fails; 64x absorbs QEMU
; TCG TSC-gap jitter).
tsc_delay_kat:
    push rbx
    push r12
    push r13
    mov  rbx, [rel tsc_khz]         ; save live calibration
    ; V1 exact: 1000us @ 2400000 kHz = 2400000 ticks
    mov  qword [rel tsc_khz], 2400000
    mov  edi, 1000
    call tsc_us_ticks
    cmp  rax, 2400000
    jne  .fail
    ; V2 floor: 1us @ 999 kHz = 0 ticks
    mov  qword [rel tsc_khz], 999
    mov  edi, 1
    call tsc_us_ticks
    test rax, rax
    jnz  .fail
    ; V3 zero in = zero out
    xor  edi, edi
    call tsc_us_ticks
    test rax, rax
    jnz  .fail
    ; V4 64-bit product: 1s @ 3.6 GHz = 3600000000 ticks (> 32 bits)
    mov  qword [rel tsc_khz], 3600000
    mov  edi, 1000000
    call tsc_us_ticks
    mov  rcx, 3600000000
    cmp  rax, rcx
    jne  .fail
    ; V5 truncation: 7us @ 1193182 kHz = floor(8352.274) = 8352
    mov  qword [rel tsc_khz], 1193182
    mov  edi, 7
    call tsc_us_ticks
    cmp  rax, 8352
    jne  .fail
    ; V6 high product: (2^53-1)us @ 1000 kHz = 2^53-1 ticks (9.0e18 product)
    mov  qword [rel tsc_khz], 1000
    mov  rdi, 9007199254740991
    call tsc_us_ticks
    mov  rcx, 9007199254740991
    cmp  rax, rcx
    jne  .fail
    ; V7 floor boundary: 1us @ 1999 kHz = floor(1.999) = 1 tick
    mov  qword [rel tsc_khz], 1999
    mov  edi, 1
    call tsc_us_ticks
    cmp  rax, 1
    jne  .fail
    mov  [rel tsc_khz], rbx         ; restore live calibration
    ; LIVE: delay 2000us; elapsed must land in [exact ticks, 64x)
    mov  edi, 2000
    call tsc_us_ticks
    mov  r12, rax                   ; exact expected ticks
    call tsc_now
    mov  r13, rax
    mov  edi, 2000
    call tsc_delay_us
    call tsc_now
    sub  rax, r13                   ; elapsed
    cmp  rax, r12
    jb   .fail                      ; returned early
    mov  rcx, r12
    shl  rcx, 6
    cmp  rax, rcx
    jae  .fail                      ; >= 64x requested — wildly long
    sub  rax, r12                   ; overshoot = elapsed - requested (exit latency)
    mov  r13, rax
    lea  rdi, [rel str_tsc_kat_ok]
    call serial_string
    lea  rdi, [rel str_tsc_over]
    call serial_string
    mov  rdi, r13
    call serial_hex64
    lea  rdi, [rel str_tsc_over2]
    call serial_string
    jmp  .kat_out
.fail:
    mov  [rel tsc_khz], rbx         ; restore even on vector fail
    lea  rdi, [rel str_tsc_kat_fail]
    call serial_string
.kat_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; PIT timer interrupt — the first HARDWARE IRQ (vs exceptions/polling so far).
; Remaps the 8259 PIC (so IRQ0 -> vector 0x20, clear of CPU exceptions 0-31),
; installs the IRQ0 handler, programs PIT ch0 ~1000 Hz, unmasks IRQ0, sti.
; Gives a tick counter — the basis for preemptive scheduling + timeouts.
; ============================================================================

; ---- preemptive multitasking (timer-driven, full-context switch) -----------
; The timer owns preemption (the switch must happen inside the IRQ frame). Tasks
; here use a FULL-context format (15 GP regs + iret frame) — distinct from the
; cooperative core/sched tasks, kept separate on purpose. When preempt_on, every
; tick round-robins to the next ready task. The IDT catches any bad iret frame.
PT_MAX          equ 4
struc ptask
  .rsp:   resq 1
  .state: resd 1
  .id:    resd 1
endstruc

; timer_irq — IRQ0 handler: save full context, tick, EOI, optionally preempt
timer_irq:
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
    inc  qword [rel timer_irq0_count]     ; IRQ0 only; LAPIC also advances timer_ticks
    inc  qword [rel timer_ticks]
    mov  al, 0x20
    out  0x20, al                        ; EOI to master PIC
%if PAOS_NORMAL_DEADMAN_MS
    call tsc_now
    mov  rdi, rax
    call normal_deadman_irq            ; BEFORE serial / indicator callbacks
%endif
    ; Native startup FIFO progresses even before the application idle loop.
    ; One try only: an interrupted UART owner must never deadlock IRQ0.
    ; The canonical drain remains capped at 16 bytes / 250us, no THRE spin.
    call serial_boot_tick
    call tsc_now
    mov  rdi, rax
    mov  rsi, [rel tsc_khz]
    call boot_indicator_tick
    cmp  byte [rel preempt_on], 0
    je   .done
    mov  eax, [rel preempt_cur]           ; save current task's rsp
    imul eax, ptask_size
    lea  r8, [rel preempt_tasks]
    add  r8, rax
    mov  [r8 + ptask.rsp], rsp
    call preempt_pick_next
    mov  eax, [rel preempt_cur]           ; switch to next task's rsp
    imul eax, ptask_size
    lea  r8, [rel preempt_tasks]
    add  r8, rax
    mov  rsp, [r8 + ptask.rsp]
.done:
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
    iretq

timer_init:
    ; remap PIC: master vectors 0x20-0x27, slave 0x28-0x2F
    mov  al, 0x11
    out  0x20, al
    out  0xA0, al                        ; ICW1 (init, cascade, ICW4)
    mov  al, 0x20
    out  0x21, al                        ; ICW2 master offset
    mov  al, 0x28
    out  0xA1, al                        ; ICW2 slave offset
    mov  al, 0x04
    out  0x21, al                        ; ICW3 master: slave at IRQ2
    mov  al, 0x02
    out  0xA1, al                        ; ICW3 slave id
    mov  al, 0x01
    out  0x21, al
    out  0xA1, al                        ; ICW4 8086 mode
    mov  al, 0xFE                         ; master mask: unmask IRQ0 only
    out  0x21, al
    mov  al, 0xFF                         ; slave mask: all masked
    out  0xA1, al
    ; install IRQ0 handler at vector 0x20
    mov  edi, 0x20
    lea  rsi, [rel timer_irq]
    call idt_set_handler
    ; PIT channel 0, mode 3 (square wave), divisor 1193 -> ~1000 Hz
    mov  al, 0x36
    out  0x43, al
    mov  ax, 1193
    out  0x40, al
    mov  al, ah
    out  0x40, al
    ; Firmware may leave LAPIC-local sources armed on vectors PaOS has not yet
    ; claimed.  Mask those sources before the first STI; later LAPIC ownership
    ; code reprograms what it owns.  LINT0/LINT1 stay untouched because the
    ; legacy PIC timer about to be enabled may arrive through LINT0/ExtINT.
    ; This is the target-neutral half of the Dell metal-proven stray-IRQ repair
    ; from source commit c3e6dc767deb0ff4d8f41f4f684908d05667777f.
    mov  ecx, 0x1B                       ; IA32_APIC_BASE
    rdmsr
    test eax, (1 << 11)                  ; LAPIC globally enabled?
    jz   .lvt_done
    test eax, (1 << 10)                  ; x2APIC mode?
    jz   .lvt_xapic
    xor  edx, edx
    mov  ecx, 0x832                      ; LVT timer
    mov  eax, 0x10000                    ; masked
    wrmsr
    mov  ecx, 0x833                      ; LVT thermal
    mov  eax, 0x10000
    wrmsr
    mov  ecx, 0x834                      ; LVT performance counter
    mov  eax, 0x10000
    wrmsr
    mov  ecx, 0x837                      ; LVT error
    mov  eax, 0x10000
    wrmsr
    jmp  .lvt_done
.lvt_xapic:
    and  eax, 0xFFFFF000                 ; APIC base (identity-mapped)
    mov  dword [rax + 0x320], 0x10000    ; LVT timer masked
    mov  dword [rax + 0x330], 0x10000    ; LVT thermal masked
    mov  dword [rax + 0x340], 0x10000    ; LVT performance masked
    mov  dword [rax + 0x370], 0x10000    ; LVT error masked
.lvt_done:
    sti
    ret

; timer_selftest — ticks must advance over a ~50 ms TSC delay.
; BSP boot selftest is the sole witness writer. Keep the first interval even if
; a later FULL selftest runs after LAPIC tick handover. No extra delay or gate.
timer_selftest:
    push rbx
    xor ebx, ebx
    cmp qword [rel timer_irq0_test_state], 0
    jne .sample_ticks
    mov qword [rel timer_irq0_test_state], 1 ; started, not completed
    mov bl, 1
    mov rax, [rel timer_irq0_count]
    mov [rel timer_irq0_test_before], rax
.sample_ticks:
    mov  rax, [rel timer_ticks]
    mov  [rel timer_t0], rax
    mov  edi, 50000
    call tsc_delay_us
    test bl, bl
    jz .legacy_result
    mov rax, [rel timer_irq0_count]
    mov [rel timer_irq0_test_after], rax
    mov ecx, 3                          ; unsigned count regressed/wrapped: unknown
    cmp rax, [rel timer_irq0_test_before]
    jb .publish_irq0
    mov ecx, 2                          ; completed, no IRQ0 delivery in interval
    je .publish_irq0
    mov ecx, 1                          ; actual IRQ0 ISR entries advanced
.publish_irq0:
    mov [rel timer_irq0_test_result], rcx
    mov qword [rel timer_irq0_test_state], 2 ; publish last; immutable for this boot
.legacy_result:
    mov  rax, [rel timer_ticks]
    sub  rax, [rel timer_t0]
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_timer_ok]
    call serial_string
    pop rbx
    ret
.fail:
    lea  rdi, [rel str_timer_fail]
    call serial_string
    pop rbx
    ret

; RDI -> 32 caller-owned bytes: state/result/before/after (four u64s).
; State0 not started,1 incomplete,2 complete; result0 unknown,1 delivered,
; 2 no delivery in the sampled interval,3 regressed. Partial data is withheld.
; Read-only and bounded; no live counter in the snapshot, no retry or IRQ mask.
timer_irq0_snapshot:
    mov rax, [rel timer_irq0_test_state]
    mov [rdi], rax
    mov qword [rdi + 8], 0
    mov qword [rdi + 16], 0
    mov qword [rdi + 24], 0
    cmp rax, 2
    jne .out
    mov rax, [rel timer_irq0_test_result]
    mov [rdi + 8], rax
    mov rax, [rel timer_irq0_test_before]
    mov [rdi + 16], rax
    mov rax, [rel timer_irq0_test_after]
    mov [rdi + 24], rax
.out:
    ret

; preempt_init — register the current (boot) context as preempt task 0
preempt_init:
    lea  rax, [rel preempt_tasks]
    mov  dword [rax + ptask.state], 1
    mov  dword [rax + ptask.id], 0
    mov  dword [rel preempt_cur], 0
    ret

; preempt_spawn(RDI=entry) — heap stack + a full iret-frame initial context
preempt_spawn:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    lea  rbx, [rel preempt_tasks]
    xor  ecx, ecx
.find:
    cmp  ecx, PT_MAX
    jge  .full
    mov  eax, ecx
    imul eax, ptask_size
    lea  r8, [rbx + rax]
    cmp  dword [r8 + ptask.state], 0
    je   .got
    inc  ecx
    jmp  .find
.full:
    mov  rax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret
.got:
    push rcx
    push r8
    mov  edi, 16384
    call kmalloc
    pop  r8
    pop  rcx
    test rax, rax
    jz   .full
    add  rax, 16384                       ; stack top
    mov  r13, rax
    sub  rax, 160                         ; rsp = 15 GP regs + 5-word iret frame
    mov  r9, rax
    ; iret frame at r9+120 (after the 15 saved GP regs, which start as garbage —
    ; harmless: a fresh task reads no input regs)
    mov  [r9 + 120], r12                  ; RIP = entry
    xor  rdx, rdx
    mov  dx, cs
    mov  [r9 + 128], rdx                  ; CS
    mov  qword [r9 + 136], 0x202          ; RFLAGS (IF set, reserved bit1)
    mov  [r9 + 144], r13                  ; RSP = stack top
    xor  rdx, rdx
    mov  dx, ss
    mov  [r9 + 152], rdx                  ; SS
    mov  [r8 + ptask.rsp], r9
    mov  dword [r8 + ptask.state], 1
    mov  [r8 + ptask.id], ecx
    mov  eax, ecx
    pop  r13
    pop  r12
    pop  rbx
    ret

; preempt_pick_next — round-robin to the next ready preempt task
preempt_pick_next:
    mov  ecx, [rel preempt_cur]
    xor  edx, edx
.l:
    inc  ecx
    cmp  ecx, PT_MAX
    jl   .nw
    xor  ecx, ecx
.nw:
    mov  eax, ecx
    imul eax, ptask_size
    lea  r8, [rel preempt_tasks]
    add  r8, rax
    cmp  dword [r8 + ptask.state], 1
    je   .found
    inc  edx
    cmp  edx, PT_MAX
    jl   .l
    ret
.found:
    mov  [rel preempt_cur], ecx
    ret

; two busy tasks that NEVER yield — only the timer can move between them
preempt_task_a:
    inc  qword [rel preempt_count_a]
    jmp  preempt_task_a
preempt_task_b:
    inc  qword [rel preempt_count_b]
    jmp  preempt_task_b

; preempt_selftest — enable preemption, busy-wait; both no-yield tasks must run
preempt_selftest:
    call preempt_init
    lea  rdi, [rel preempt_task_a]
    call preempt_spawn
    lea  rdi, [rel preempt_task_b]
    call preempt_spawn
    mov  qword [rel preempt_count_a], 0
    mov  qword [rel preempt_count_b], 0
    mov  byte [rel preempt_on], 1         ; arm preemption
    mov  edi, 100000                       ; ~100 ms; the timer preempts during it
    call tsc_delay_us
    mov  byte [rel preempt_on], 0         ; disarm
    cmp  qword [rel preempt_count_a], 0
    je   .fail
    cmp  qword [rel preempt_count_b], 0
    je   .fail
    lea  rdi, [rel str_preempt_ok]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_preempt_fail]
    call serial_string
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_time 0
timer_irq0_count: dq 0
timer_irq0_test_state: dq 0
timer_irq0_test_result: dq 0
timer_irq0_test_before: dq 0
timer_irq0_test_after: dq 0
timer_ticks:   dq 0
timer_t0:      dq 0
preempt_on:    db 0
preempt_cur:   dd 0
; Keep both hot qword counters within a cache line after the packed flag/index.
align 8, db 0
preempt_count_a: dq 0
preempt_count_b: dq 0
preempt_tasks: times (PT_MAX * ptask_size) db 0
time_zone_hook: dq 0                    ; E2t: the GUI's zone lookup (clock_local_offset), 0 = none
%endmacro
WDATA_DEFER WDATA_time
str_timer_ok:   db "[PAOS64] M1 timer: PIT IRQ0 firing, ticks advancing", 13, 10, 0
str_timer_fail: db "[PAOS64] M1 timer: no PIT ticks (IRQ not firing)", 13, 10, 0
str_preempt_ok:   db "[PAOS64] M1 preempt: 2 no-yield tasks both ran (timer-driven switch)", 13, 10, 0
str_preempt_fail: db "[PAOS64] M1 preempt: preemption FAILED", 13, 10, 0
tsc_khz:       dq 0
align 8
time_monotonic_tsc_origin: dq 0
tsc_calibration_duration_ticks: dq 0
tsc_calibration_source: db TSC_CAL_SOURCE_PIT
tsc_calibration_reason: db TSC_CAL_REASON_NONE
align 8
wall_offset:             dq 0
time_wall_seq:        dd 0
time_wall_valid:      db 0
time_wall_source:     db TIME_SRC_NONE   ; RCQ-17: who set the wall (CLOCK src=)
time_wall_prev_valid: db 0              ; the frame before the last NTP step is kept
time_wall_local_armed: db 0             ; time_wall_local_issue_s latch
align 8
time_wall_prev_offset:  dq 0            ; wall_offset that step replaced
time_wall_step_mono_us: dq 0            ; monotonic time of that step
time_wall_prev_hold_s:  dq 0            ; time_wall_hold_s while that frame was current
time_wall_hold_s:       dq 0            ; highest second a backward set replaced
time_wall_local_s:      dq 0            ; the latched native issue second
time_rtc_read_count:  dq 0
time_rtc_write_count: dq 0              ; explicit RTC-write verb does not exist yet
time_month_days:      db 31,28,31,30,31,30,31,31,30,31,30,31
str_time_ok:   db "[PAOS64] M1 time: TSC calibrated ", 0
str_khz:       db " kHz", 13, 10, 0
str_time_fail: db "[PAOS64] M1 time: TSC calibration FAILED (PIT timeout)", 13, 10, 0
str_time_cpuid15_validated: db "[PAOS64] time: architectural CPUID.15 calibration validated [time.calibration.architectural.validated]", 13, 10, 0
str_time_cpuid15_fallback: db "[PAOS64] time: CPUID.15 rejected; bounded PIT fallback reason_code=", 0
str_time_cal_duration: db "[PAOS64] time: calibration duration_tsc_ticks=", 0
str_time_cal_newline: db 13, 10, 0
str_tsc_kat_ok:   db "[PAOS64] M1 time: tsc_delay_us KAT PASS (7 exact conversion vectors + live delay bounded) [tourn.tsc_delay_us.kat]", 13, 10, 0
str_tsc_kat_fail: db "[PAOS64] M1 time: tsc_delay_us KAT FAIL [tourn.tsc_delay_us.kat.fail]", 13, 10, 0
str_tsc_over:  db "[PAOS64] M1 time: tsc_delay_us live overshoot ticks=", 0
str_tsc_over2: db " [tourn.tsc_delay_us.overshoot]", 13, 10, 0
