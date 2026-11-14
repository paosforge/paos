;; MODULE svc/boot_ab
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS boot_ab_prior_snapshot, boot_log_override_consume, boot_log_override_clear, boot_log_override_policy, boot_ab_early, boot_ab_commit, boot_ab_declare, cmd_verb_abstate, cmd_verb_abcounter, cmd_verb_logmode, fault_warmreset_arm, boot_ab_demote, cmd_verb_faultinj, cmd_verb_abforce, boot_ab_fault_bump
;; IMPORTS boot/serial, boot/chainload, boot/boot_v2_handoff, core/lib/fmt, core/lib/cksum, bus/pci, bus/irq, svc/command, core/idt
;; CAPS
;; OWNER saga:boot
; ============================================================================
; svc/boot_ab.asm — the 1014 BARE-METAL LIVE-WIRE rung of the A/B fault-tolerant
; boot canon. Where core/boot_canon.asm (1073) proves the STATE-MACHINE LOGIC in
; QEMU over canned in-memory keeps, THIS module owns the live-hardware half the
; LOGIC rung deliberately left to bare metal (its own header comment): the CMOS-
; backed trial/good boot-attempt counter (survives warm reboot), the Intel PCH
; TCO hardware watchdog arm (the pre-P7 silent-wedge catcher), and the AB_STATE /
; AB_COUNTER UDP verbs that project the live decision onto the wire with a nonce
; round-trip. Four earned markers (BOOT_SEQUENCE.md recovery ladder rung 6):
;   (1) boot.ab.verify        — verify-then-jump hash: a GOOD keep matches its
;       trusted manifest + is selected; a one-byte-CORRUPT keep hash-MISMATCHES
;       + is REJECTED (never jumped to). Reuses the ONE canonical net_cksum16 (G1).
;   (2) boot.ab.state.loaded  — trial/good state LOADED from the CMOS manifest
;       (0x74 trial count + 0x75 confirmed magic) and this boot counted as a trial.
;   (3) boot.watchdog.armed|absent — the Intel PCH TCO watchdog is discovered off
;       the LPC ACPI base (PCI 0:1F.0 ABASE, offset 0x40). ARMED is emitted only
;       after two TCO_RLD reads prove the live countdown decremented. LOCKed,
;       clock-gated, and missing backends emit boot.watchdog.absent with the reason.
;       The timer is returned to HALTED after the bounded readback, preserving the
;       armed-safe recovery policy; boot.watchdog.truthful grades either outcome.
;   (4) boot.ab.committed     — trial->good COMMIT at selftest-pass: confirmed
;       magic written + trial counter reset to 0 (a keep that crashes before this
;       point boots next in an un-confirmed 'trial' state, and after AB_MAX_TRIALS
;       no-good boots the state reads FALLBACK — the auto-rollback).
;
; PORT NOTE (M16): the CMOS 0x74/0x75 offsets (CMOS_AB_TRIAL / CMOS_AB_CONFIRMED)
; and the TCO base derivation (ABASE from LPC 0:1F.0 + 0x60, halt/set-timeout/
; clear-status sequence) are ported from the monolith (paos.asm tco_watchdog_init +
; the Phase-E CMOS A/B counter) — proven-safe OEM CMOS bytes + register order on
; THIS exact Lenovo. The ARMED-SAFE (halted) choice is the deliberate improvement:
; the monolith runs the timer live (and KP115-recovered a few times); on the shared
; loop box we prove the full MMIO path without the brick risk, and gate the
; live-firing arm behind a supervised contract.
;
; CONTENT-GRADE, NOT A LATCH (TESTING §1): boot.ab.verify PRINTS the live-computed
; good/corrupt hashes (a stub emitting the marker without the arithmetic fails the
; good==manifest && corrupt!=manifest gate); AB_STATE/AB_COUNTER read the REAL CMOS
; bytes and the nonce round-trips through the reply's ARG= echo. DEGRADE (TESTING §4):
; no PCH -> watchdog reports degraded but boot continues; garbage/uninitialised CMOS
; -> counter sanitised to 0, never out of the plausible 0..AB_MAX_TRIALS band.
; ============================================================================

CMOS_IDX_PORT     equ 0x70            ; CMOS index (bit7 = NMI-disable)
CMOS_DATA_PORT    equ 0x71            ; CMOS data
CMOS_AB_TRIAL     equ 0x74            ; OEM CMOS byte: boots-since-last-confirmed (the counter)
CMOS_AB_CONFIRMED equ 0x75            ; OEM CMOS byte: 0xC0 == this keep confirmed 'good'
CMOS_LOGMODE      equ 0x7A            ; one-boot owner override; clear of retained forensics
CMOS_LOGMODE_AUTO equ 0xA0
CMOS_LOGMODE_LEAN equ 0xA1
CMOS_LOGMODE_VERBOSE equ 0xA2
AB_CONFIRMED_MAGIC equ 0xC0           ; the confirmed sentinel (monolith Phase-E)
AB_MAX_TRIALS     equ 3               ; > this many un-confirmed boots -> FALLBACK (known_trap)

; AB state enum (small ints -> strings at print/reply time)
AB_ST_PENDING     equ 0
AB_ST_CONFIRMED   equ 1
AB_ST_FALLBACK    equ 2

AB_TCO_REASON_NONE       equ 0
AB_TCO_REASON_NO_BACKEND equ 1
AB_TCO_REASON_LOCKED     equ 2
AB_TCO_REASON_GATED      equ 3

; Intel PCH TCO watchdog (off the LPC ACPI base) — same offsets as the monolith
LPC_BUS           equ 0
LPC_DEV           equ 31
LPC_FN            equ 0
LPC_ABASE_OFF     equ 0x40            ; ACPI Base Address (PMBASE) in LPC config space
TCO_BASE_OFF      equ 0x60            ; TCO regs live at ABASE + 0x60
TCO_RLD           equ 0x00            ; timer reload (write any value)
TCO1_STS          equ 0x04            ; status (W1C)
TCO2_STS          equ 0x06            ; status (W1C)
TCO1_CNT          equ 0x08            ; control: bit11 = TMR_HLT, bit12 = LOCK
TCO_TMR           equ 0x12            ; timer initial value (bits 9:0)
TCO_TIMEOUT_TICKS equ 30             ; ~18 s per stage (matches the monolith)

; ---------------------------------------------------------------------------
; cmos_ab_rd(DIL=index) -> AL = byte. NMI-disable bit set on the index write
;   (monolith cmos_read). clobbers: RAX,RDX.
; ---------------------------------------------------------------------------
cmos_ab_rd:
    call chainload_cmos_nvram_ok      ; HP CMOS allowlist: non-Intel -> 0, no port I/O
    jne  .volatile
    mov  al, dil
    or   al, 0x80                     ; keep NMI disabled during the access
    mov  dx, CMOS_IDX_PORT
    out  dx, al
    mov  dx, CMOS_DATA_PORT
    in   al, dx
    ret
.volatile:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; cmos_ab_wr(DIL=index, SIL=value). clobbers: RAX,RDX.
; ---------------------------------------------------------------------------
cmos_ab_wr:
    call chainload_cmos_nvram_ok      ; HP CMOS allowlist: non-Intel -> write dropped
    jne  .dropped
    mov  al, dil
    or   al, 0x80
    mov  dx, CMOS_IDX_PORT
    out  dx, al
    mov  al, sil
    mov  dx, CMOS_DATA_PORT
    out  dx, al
.dropped:
    ret

; Snapshot the PRIOR trial byte before any hang-capable normal-profile work.
; This sample belongs only to adaptive logging. The later A/B arm deliberately
; re-reads CMOS because a pre-EBS fallback attempt may reset the live ladder.
; Garbage is marked unreadable so adaptive logging fails open instead of
; misclassifying it clean; existing CRASHES/A-B semantics remain untouched.
boot_ab_prior_snapshot:
    cmp  byte [rel boot_log_prior_done], 1
    je   .done
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_rd
    mov  byte [rel boot_log_prior_done], 1
    cmp  al, AB_MAX_TRIALS + 2
    jbe  .valid
    mov  byte [rel boot_log_prior_trial], 0
    mov  byte [rel boot_log_prior_valid], 0
    ret
.valid:
    mov  [rel boot_log_prior_trial], al
    mov  byte [rel boot_log_prior_valid], 1
.done:
    ret

; Decode the owner override once at P0. Return ECX policy encoding
; expected by boot_log_mode_select: 0=AUTO, 1=LEAN, 2=VERBOSE,
; 3=malformed/fail-open. A nonzero byte is only marked here: the one-boot clear
; is boot_log_override_clear, right after the Boot-v2 handoff probe, because a
; live Try boot (RCQ-29) is known only there and must leave CMOS untouched.
boot_log_override_consume:
    mov  byte [rel boot_log_override_pending], 0
    mov  dil, CMOS_LOGMODE
    call cmos_ab_rd
    movzx ecx, al
    test al, al
    jz   .auto
    mov  byte [rel boot_log_override_pending], 1
    cmp  cl, CMOS_LOGMODE_AUTO
    je   .auto
    cmp  cl, CMOS_LOGMODE_LEAN
    je   .lean
    cmp  cl, CMOS_LOGMODE_VERBOSE
    je   .verbose
    mov  ecx, 3
    ret
.auto:
    xor  ecx, ecx
    ret
.lean:
    mov  ecx, LOG_MODE_LEAN
    ret
.verbose:
    mov  ecx, 2
    ret

; Clear a pending override (any nonzero byte) once the handoff probe has run,
; including Manager safe-profile launches that do not reach normal mode
; selection, so no override reaches boot N+2. A live Try boot clears nothing
; (cmos_ab_wr is volatile there) and ignores the byte: on a foreign machine it
; is not a PaOS override.
boot_log_override_clear:
    cmp  byte [rel pbm_try_media], 1
    jne  .installed
    mov  byte [rel boot_log_override_policy], 0
    ret
.installed:
    cmp  byte [rel boot_log_override_pending], 1
    jne  .done
    mov  byte [rel boot_log_override_pending], 0
    mov  dil, CMOS_LOGMODE
    xor  esi, esi
    call cmos_ab_wr
.done:
    ret

; ---------------------------------------------------------------------------
; boot_ab_early — P0/P1: verify-then-jump + load the CMOS trial/good state +
;   count this boot as a trial + arm the PCH TCO watchdog. Emits three of the
;   four markers (verify, state.loaded, watchdog.armed). clobbers: caller-saved
;   (rbx,r12 saved).
; ---------------------------------------------------------------------------
boot_ab_early:
    push rbx
    push r12

    ; ===== (1) VERIFY-THEN-JUMP HASH =====================================
    ; trusted manifest = hash of the pristine GOOD keep signature (recomputed
    ; from the in-image blob — the manifest a real ESP deploy would store).
    lea  rdi, [rel ab_good_sig]
    mov  rsi, ab_sig_len
    call net_cksum16                     ; AX = hash(good)  (G1 checksum, reused)
    mov  [rel ab_good_hash], ax
    mov  [rel ab_manifest], ax
    ; a one-byte-corrupt keep MUST hash-mismatch the manifest (reject, never jump)
    lea  rdi, [rel ab_corrupt_sig]
    mov  rsi, ab_sig_len
    call net_cksum16                     ; AX = hash(corrupt)
    mov  [rel ab_corrupt_hash], ax
    ; gate: good == manifest AND corrupt != manifest, else fall through WITHOUT
    ; the marker (fail-closed — a keep we cannot verify is not declared verified).
    mov  ax, [rel ab_good_hash]
    cmp  ax, [rel ab_manifest]
    jne  .after_verify
    mov  ax, [rel ab_corrupt_hash]
    cmp  ax, [rel ab_manifest]
    je   .after_verify                   ; identical hash => corruption not caught
    ; PRINT the KAT (good_hash + corrupt_hash) the probe/regression content-grades
    lea  rdi, [rel str_ab_v_pre]
    call serial_string
    movzx edi, word [rel ab_good_hash]
    call ab_emit_hex
    lea  rdi, [rel str_ab_v_corr]
    call serial_string
    movzx edi, word [rel ab_corrupt_hash]
    call ab_emit_hex
    lea  rdi, [rel str_ab_v_post]        ; " selected=A rejected=corrupt [boot.ab.verify]\r\n"
    call serial_string
    mov  byte [rel ab_m_verify], 1
.after_verify:

    ; ===== (2) LOAD trial/good STATE from the CMOS manifest ==============
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_rd
    movzx eax, al
    cmp  eax, AB_MAX_TRIALS + 2          ; garbage / first-ever-boot sanitise
    jbe  .trial_ok
    xor  eax, eax
.trial_ok:
    ; 1216: snapshot PRIOR attempts before adding this one. This is the
    ; authoritative CRASHES value for the whole boot: commit may clear the live
    ; trial byte, but cannot erase evidence recovered at P0. Start the separate
    ; operational containment count here so deliberate pre-P0 fault KATs do not
    ; make an otherwise clean boot unhealthy.
    mov  [rel boot_crashes_observed], al
    mov  byte [rel faults_contained_current], 0
    ; count THIS boot as a trial attempt (incremented now, reset to 0 at commit)
    inc  eax
    mov  [rel ab_trial], eax
    mov  sil, al
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_wr                      ; persist the attempt (survives warm reboot)
    mov  dil, CMOS_AB_CONFIRMED
    call cmos_ab_rd
    movzx eax, al
    mov  [rel ab_confirmed], eax
    ; compute the loaded state enum: confirmed magic wins; else pending while under
    ; the trial cap; else fallback (a keep that never confirmed after N trials).
    cmp  eax, AB_CONFIRMED_MAGIC
    je   .st_confirmed
    mov  eax, [rel ab_trial]
    cmp  eax, AB_MAX_TRIALS
    ja   .st_fallback
    mov  dword [rel ab_state], AB_ST_PENDING
    jmp  .st_done
.st_confirmed:
    mov  dword [rel ab_state], AB_ST_CONFIRMED
    jmp  .st_done
.st_fallback:
    mov  dword [rel ab_state], AB_ST_FALLBACK
.st_done:
    lea  rdi, [rel str_ab_s_pre]         ; "...state loaded trial="
    call serial_string
    mov  edi, [rel ab_trial]
    call ab_emit_dec
    lea  rdi, [rel str_ab_s_conf]        ; " confirmed=0x"
    call serial_string
    mov  edi, [rel ab_confirmed]
    call ab_emit_hex
    lea  rdi, [rel str_ab_s_state]       ; " state="
    call serial_string
    call ab_emit_state                   ; CONFIRMED|PENDING|FALLBACK
    lea  rdi, [rel str_ab_s_post]        ; " [boot.ab.state.loaded]\r\n"
    call serial_string
    mov  byte [rel ab_m_loaded], 1

    ; ===== (3) MEASURE the Intel PCH TCO watchdog (ARMED-SAFE, halted) ===
    call boot_ab_watchdog_arm

    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; boot_ab_watchdog_arm — derive the TCO base from the LPC ACPI base (PCI
;   0:1F.0 offset 0x40), preserve the proven program/clear/reload sequence, then
;   briefly run it across a bounded PIT window. Only a decreasing TCO_RLD earns
;   boot.watchdog.armed; every other path names why it is absent. The timer is
;   halted again before return, so the recovery ladder remains unchanged.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
boot_ab_watchdog_arm:
    push rbx
    ; HP-PORT-1 (paos_hp f4ef61c40 / hp009, src/svc/boot_ab.asm:223-236 there):
    ; TCO is an Intel PCH block. On an AuthenticAMD platform (HP EliteDesk
    ; 705 G5) PCI 00:1F.0 is not an Intel LPC controller, so reading its
    ; dword 0x40 as ABASE could turn the writes below into unrelated I/O
    ; transactions. Non-Intel CPUs take the existing no-backend result before
    ; ANY PCI or port I/O; the GenuineIntel path below is unchanged.
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547                 ; GenuineIntel: EBX='Genu'
    jne  .absent_vendor
    cmp  edx, 0x49656E69                 ; EDX='ineI'
    jne  .absent_vendor
    cmp  ecx, 0x6C65746E                 ; ECX='ntel'
    jne  .absent_vendor
    ; --- read the LPC ABASE (ACPI I/O base) from PCI config ---
    mov  edi, LPC_BUS
    mov  esi, LPC_DEV
    mov  edx, LPC_FN
    mov  ecx, LPC_ABASE_OFF
    call pci_cfg_read32                  ; EAX = ABASE dword
    cmp  eax, 0xFFFFFFFF
    je   .absent_no_backend              ; no LPC / bus reads all-ones
    test eax, 1                          ; bit0 = I/O-space enable (ABASE valid)
    jz   .absent_no_backend
    and  eax, 0xFF80                     ; align to the 128-byte ACPI block
    test eax, eax
    jz   .absent_no_backend
    lea  ebx, [eax + TCO_BASE_OFF]       ; TCO base = ABASE + 0x60
    mov  [rel ab_tco_base], bx
    ; abort if the TCO config is LOCKed (bit12 of TCO1_CNT) — cannot reprogram
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO1_CNT
    in   ax, dx
    test ax, (1 << 12)                   ; TCO_LOCK
    jnz  .absent_locked
    ; halt the timer first (TMR_HLT=1) — armed-SAFE: we program but never un-halt
    or   ax, (1 << 11)
    and  ax, ~(1 << 8)                   ; NMI2SMI_EN=0 (route to NMI, not SMI)
    out  dx, ax
    ; set the timeout value
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO_TMR
    mov  ax, TCO_TIMEOUT_TICKS
    out  dx, ax
    ; clear any pending status (W1C)
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO1_STS
    mov  ax, 0xFFFF
    out  dx, ax
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO2_STS
    mov  ax, 0xFFFF
    out  dx, ax
    ; reload the timer (staged so a future live arm just clears TMR_HLT)
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO_RLD
    mov  ax, 1
    out  dx, ax

    ; Temporarily unhalt and prove the device-owned countdown moves. Merely
    ; reading TMR_HLT=0 is insufficient on the fuse-gated M720s.
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO1_CNT
    in   ax, dx
    and  ax, ~(1 << 11)                  ; TMR_HLT=0 for the readback window
    out  dx, ax
    in   ax, dx
    test ax, (1 << 11)
    jnz  .absent_gated
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO_RLD
    in   ax, dx                          ; first live counter sample
    and  ax, 0x03FF
    mov  [rel ab_tco_first], ax
    call boot_ab_wait_tco_tick
    test eax, eax
    jz   .absent_gated
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO_RLD
    in   ax, dx                          ; second live counter sample
    and  ax, 0x03FF
    mov  [rel ab_tco_second], ax
    cmp  ax, [rel ab_tco_first]
    jae  .absent_gated                   ; equal/increasing is not a countdown

    ; Restore the contract's safe final state before making any claim.
    call boot_ab_watchdog_halt
    mov  byte [rel ab_tco_present], 1
    mov  byte [rel ab_tco_absent_reason], AB_TCO_REASON_NONE
    lea  rdi, [rel str_ab_w_ok]          ; "...TCO base=0x"
    call serial_string
    movzx edi, word [rel ab_tco_base]
    call ab_emit_hex
    lea  rdi, [rel str_ab_w_first]
    call serial_string
    movzx edi, word [rel ab_tco_first]
    call ab_emit_hex
    lea  rdi, [rel str_ab_w_second]
    call serial_string
    movzx edi, word [rel ab_tco_second]
    call ab_emit_hex
    lea  rdi, [rel str_ab_w_ok_post]     ; counting proven; timer restored halted
    call serial_string
    jmp  .truthful

.absent_gated:
    call boot_ab_watchdog_halt           ; restore HLT even after a failed proof
    mov  byte [rel ab_tco_absent_reason], AB_TCO_REASON_GATED
    lea  rdi, [rel str_ab_w_absent_gated]
    jmp  .absent
.absent_locked:
    mov  byte [rel ab_tco_absent_reason], AB_TCO_REASON_LOCKED
    lea  rdi, [rel str_ab_w_absent_locked]
    jmp  .absent
.absent_vendor:
    ; HP-PORT-1: same reason code (NO_BACKEND) so AB_STATE/collector grading is
    ; unchanged; the serial line adds vendor=non-intel as the gate witness.
    mov  byte [rel ab_tco_absent_reason], AB_TCO_REASON_NO_BACKEND
    lea  rdi, [rel str_ab_w_absent_vendor]
    jmp  .absent
.absent_no_backend:
    mov  byte [rel ab_tco_absent_reason], AB_TCO_REASON_NO_BACKEND
    lea  rdi, [rel str_ab_w_absent_backend]
.absent:
    mov  byte [rel ab_tco_present], 0
    call serial_string
.truthful:
    lea  rdi, [rel str_ab_w_truthful]
    call serial_string
    mov  byte [rel ab_m_wdog], 1         ; watchdog state was measured + reported
    pop  rbx
    ret

; Restore the armed-safe final state after a valid TCO base was discovered.
; clobbers: RAX, RDX.
boot_ab_watchdog_halt:
    movzx edx, word [rel ab_tco_base]
    add  dx, TCO1_CNT
    in   ax, dx
    or   ax, (1 << 11)
    out  dx, ax
    ret

; Wait just over one TCO tick (~600 ms) using PIT channel 2. boot_ab_early runs
; before the normal TSC calibration/timer init, so this bounded local wait does
; not pretend an uncalibrated TSC is a clock. EAX=1 on elapsed window, 0 if PIT
; itself never reaches terminal count. The speaker-control byte is restored.
boot_ab_wait_tco_tick:
    push rbx
    push r12
    in   al, 0x61
    mov  r12b, al
    and  al, 0xFC
    or   al, 0x01                       ; speaker off, PIT2 gate on
    out  0x61, al
    mov  ebx, 12                        ; 12 * 65535/PIT_HZ ~= 659 ms
.round:
    mov  al, 0xB0                       ; ch2, lo/hi, mode 0, binary
    out  0x43, al
    mov  al, 0xFF
    out  0x42, al
    out  0x42, al
    mov  ecx, 0x01000000                ; bounded dead-PIT protection
.poll:
    in   al, 0x61
    test al, 0x20
    jnz  .round_done
    dec  ecx
    jnz  .poll
    xor  eax, eax
    jmp  .restore
.round_done:
    dec  ebx
    jnz  .round
    mov  eax, 1
.restore:
    mov  edx, eax                       ; preserve result while AL restores port 0x61
    mov  al, r12b
    out  0x61, al
    mov  eax, edx
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; boot_ab_commit — P6: all self-tests passed, so COMMIT trial->good. Write the
;   confirmed magic + reset the trial counter to 0 in CMOS (so the next boot
;   reads a confirmed, zero-trial keep). Emits boot.ab.committed. clobbers:
;   caller-saved.
; ---------------------------------------------------------------------------
boot_ab_commit:
    push rbx
    mov  dword [rel ab_confirmed], AB_CONFIRMED_MAGIC
    mov  sil, AB_CONFIRMED_MAGIC
    mov  dil, CMOS_AB_CONFIRMED
    call cmos_ab_wr
    mov  dword [rel ab_trial], 0
    xor  sil, sil
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_wr
    mov  dword [rel ab_state], AB_ST_CONFIRMED
    lea  rdi, [rel str_ab_c_pre]         ; "...trial->good commit confirmed=0x"
    call serial_string
    mov  edi, [rel ab_confirmed]
    call ab_emit_hex
    lea  rdi, [rel str_ab_c_ctr]         ; " counter=0 [boot.ab.committed]\r\n"
    call serial_string
    mov  byte [rel ab_m_commit], 1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fault_warmreset_arm — 9702: arm the .panic CF9 warm reset, BARE METAL ONLY.
;   The QEMU-vs-metal discriminator is the CPUID.1:ECX bit31 HYPERVISOR-PRESENT
;   bit: set under QEMU (both TCG and KVM expose it) and CLEAR on real silicon.
;   This is the industry-standard VM discriminator and it demonstrably splits the
;   only two environments this ever runs in — the QEMU regression (bit SET -> the
;   marker-only path, so an armed CF9 never truncates a -no-reboot run) and the
;   M720s (bit CLEAR -> real arm). The PCH TCO is NOT a second AND-gate: this
;   exact M720s honestly reports boot.watchdog.absent when its countdown is
;   locked or gated, so gating on it would wrongly refuse to arm the real metal.
;   TCO presence is reported for context but does not block the CF9 arm.
;   Called AFTER boot_ab_early persisted this boot's trial count, so every armed
;   fault-reset climbs the CMOS ladder toward the pre-EBS Windows escalation
;   (boot/chainload.asm) — a fault-looping keep is BOUNDED, never infinite.
;   Also installs the demote hook: .panic clears the CMOS confirmed magic before
;   firing CF9, so a fault-rebooted keep must RE-EARN confirmed at commit.
;   Runtime lea into fault_demote_hook (never dq <symbol> — MODULES §3.2).
;   clobbers: caller-saved (rbx saved around cpuid).
; ---------------------------------------------------------------------------
fault_warmreset_arm:
    push rbx
    mov  eax, 1
    cpuid                                ; ECX bit31 = hypervisor present
    test ecx, (1 << 31)
    jnz  .skip_vm
    lea  rax, [rel boot_ab_demote]
    mov  [rel fault_demote_hook], rax
    mov  byte [rel fault_warmreset_armed], 1
    lea  rdi, [rel str_ab_arm_ok]        ; [fault.warmreset.armed] (hw-only)
    call serial_string
    pop  rbx
    ret
.skip_vm:
    lea  rdi, [rel str_ab_arm_vm]
    call serial_string
    pop  rbx
    ret

; boot_ab_demote — the .panic pre-CF9 hook (fault context; only RAX/RDX live
;   rules apply — cmos_ab_wr clobbers exactly those). Clears the confirmed
;   magic so the A/B ladder treats the fault-rebooted keep as UNCONFIRMED.
boot_ab_demote:
    mov  dil, CMOS_AB_CONFIRMED
    xor  esi, esi
    call cmos_ab_wr
    ret

; ---------------------------------------------------------------------------
; boot_ab_fault_bump — 1273a: increment the CMOS trial counter from FAULT
;   context, saturating at the cap. boot/early_trap calls this when it catches a
;   PRE-EBS fault.
;
;   WHY IT IS NEEDED. boot_ab_early is the only other incrementer and it runs
;   long after ExitBootServices, so a fault before EBS never reaches it. Without
;   this bump the trial byte is FROZEN across such a fault: demote clears the
;   confirmed magic, the box warm-resets, faults at the same place, and the
;   ladder never climbs — a bounded-looking design that is actually an infinite
;   reboot loop. Counting here is what makes chainload_escalate_check able to
;   see a pre-EBS fault at all.
;
;   Saturating, not wrapping: rolling 0xFF -> 0x00 would silently reset the
;   ladder and hide a persistently-broken keep.
;
;   Fault-context rules (same as boot_ab_demote): only RAX/RDX/RDI/RSI are
;   treated as live-clobberable — exactly what cmos_ab_rd/cmos_ab_wr touch.
; ---------------------------------------------------------------------------
boot_ab_fault_bump:
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_rd
    movzx eax, al
    cmp  eax, AB_MAX_TRIALS + 2          ; garbage -> restart the ladder at 1
    jbe  .sane
    xor  eax, eax
.sane:
    cmp  eax, 0xFE                       ; saturate, never wrap
    jae  .store
    inc  eax
.store:
    mov  sil, al
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_wr
    ret

; ===========================================================================
; UDP/registry PROJECTION — AB_STATE + AB_COUNTER. Thin handlers that read the
; live state and STAGE a reply line into ab_out_buf (framed verbatim by
; command_udp.asm's udp_send_reply, the SAME staging pattern thermal/reinit use).
; The raw arg token (nonce) round-trips via the reply's ARG= echo.
; ===========================================================================

; boot_ab_declare — register AB_STATE / AB_COUNTER through the SAME
;   command_register_verb (additive, no registry-core edit). clobbers: caller-saved.
boot_ab_declare:
    lea  rdi, [rel str_verb_abstate]
    lea  rsi, [rel cmd_verb_abstate]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                          ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_abcounter]
    lea  rsi, [rel cmd_verb_abcounter]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; 9702/1117c: keep the legacy FAULTINJ spelling for its deployed DIV0 probe,
    ; and register the public FAULTINJECT <kind> spelling over the SAME guarded
    ; handler. ABFORCE remains the escalation probe's setup/cleanup verb.
    ; All three are destructive -> R9=1.
    lea  rdi, [rel str_verb_faultinj]
    lea  rsi, [rel cmd_verb_faultinj]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_faultinject]
    lea  rsi, [rel cmd_verb_faultinj]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_abforce]
    lea  rsi, [rel cmd_verb_abforce]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_logmode]
    lea  rsi, [rel cmd_verb_logmode]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                          ; AUTH1 owner mutation; unsigned fails closed
    call command_register_verb
    ret

; --- VERB: FAULTINJ <xhci|ud|de> (FAULTINJECT alias; legacy DIV0) -------------
; xhci is the sole driver target: active e1000e, boot, and storage selectors
; are refused without mutation. The xHCI path returns only after real HCHalted
; acknowledgement plus reset/reinit verification.
; "ud" executes a real UD2 through core/idt's armed diagnostic path and returns
; only after vector 6 was captured + iretq resumed. The staged line exposes the
; actual frame vector/RIP plus a fresh TSC-derived nonce. "de" (or legacy DIV0)
; retains 9702's intentionally uncontained #DE -> persistent dump -> gated CF9
; warm reset path; it cannot reply because the machine resets. Without a known
; token this is a harmless arm/status read.
cmd_verb_faultinj:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rsi, [rdi + REQ_ARG]            ; raw token ptr (ARGT_TEXT)
    test rsi, rsi
    jz   .status
    lea  rdi, [rel str_ab_tok_xhci]
    call hp_streq
    test rax, rax
    jz   .inject_xhci
    mov  rsi, [rsp + 8]
    mov  rsi, [rsi + REQ_ARG]
    lea  rdi, [rel str_ab_tok_xhci_upper]
    call hp_streq
    test rax, rax
    jz   .inject_xhci
    mov  rsi, [rsp + 8]
    mov  rsi, [rsi + REQ_ARG]
    lea  rdi, [rel str_ab_tok_ud]
    call hp_streq
    test rax, rax
    jz   .inject_ud
    mov  rsi, [rsp + 8]                   ; saved request pointer
    mov  rsi, [rsi + REQ_ARG]
    lea  rdi, [rel str_ab_tok_de]
    call hp_streq
    test rax, rax
    jz   .inject_de
    mov  rsi, [rsp + 8]                   ; preserve the deployed uppercase token
    mov  rsi, [rsi + REQ_ARG]
    lea  rdi, [rel str_ab_tok_div0]
    call hp_streq                        ; RAX=0 iff arg == "DIV0"
    test rax, rax
    jnz  .refuse
    jmp  .inject_de
.inject_xhci:
%if PAOS_PUBLIC_BUILD
    jmp .refuse
%else
    call airlock_faultinj_xhci
    pop  rsi                             ; response
    pop  rdi                             ; request
    mov  rdx, [rel xhci_airlock_contained]
    mov  [rsi + RSP_VAL], rdx
    test rax, rax
    jnz  .xhci_failed
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.xhci_failed:
    mov  qword [rsi + RSP_CODE], CMDE_BADJOB
    ret
%endif
.inject_de:
    ; --- INJECT: a genuinely uncontained fault, right here in the handler ---
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    div  ecx                             ; #DE(0) -> .panic (does not return)
.inject_ud:
    call fault_inject_ud
    test rax, rax
    jz   .inject_ud_reply
    ; fault_inject_ud returns 1 only after the real vector-6 frame was copied,
    ; diag_ring_fault returned, and iretq resumed at its validated recovery
    ; point. Account exactly there; a fall-through/broken handler earns none.
    call fault_containment_account
.inject_ud_reply:
    call ab_out_reset
    lea  rdi, [rel str_ab_o_ud_trapped]  ; " kind=ud trapped="
    call ab_out_str
    movzx edi, byte [rel fault_inject_ud_seen]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_ud_recovered]
    call ab_out_str
    movzx edi, byte [rel fault_inject_ud_seen]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_ud_dump]
    call ab_out_str
    movzx edi, byte [rel fault_inject_ud_dumped]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_ud_vector]
    call ab_out_str
    mov  rdi, [rel fault_inject_ud_vector]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_ud_rip]
    call ab_out_str
    mov  rdi, [rel fault_inject_ud_rip]
    call ab_out_hex
    lea  rdi, [rel str_ab_o_ud_nonce]
    call ab_out_str
    mov  rdi, [rel fault_inject_ud_nonce]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_ud_baremetal]
    call ab_out_str
    movzx edi, byte [rel fault_warmreset_armed]
    call ab_out_dec
    mov  byte [rel ab_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rel fault_inject_ud_nonce]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.refuse:
    call ab_out_reset
    lea  rdi, [rel str_ab_o_refused]
    call ab_out_str
    mov  byte [rel ab_out_ready], 1
    pop  rsi
    pop  rdi
    xor  eax, eax
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_BADSEL
    ret
.status:
    call ab_out_reset
    lea  rdi, [rel str_ab_o_armed]       ; " armed="
    call ab_out_str
    movzx edi, byte [rel fault_warmreset_armed]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_inject]      ; " kinds=ud,de legacy=DIV0"
    call ab_out_str
    mov  byte [rel ab_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: ABFORCE <1..5 | RESTORE> — 9702 escalation-probe CMOS override.
;     "ABFORCE 3" writes trial=3 + confirmed=0 (an unconfirmed keep one fault
;     short of FALLBACK); "ABFORCE RESTORE" writes trial=0 + confirmed=0xC0.
;     Anything else (incl. no arg / 0 / >5) is a read-only status reply. The
;     reply stages LIVE CMOS read-backs, so the probe grades the actual bytes.
cmd_verb_abforce:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    mov  rbx, [rdi + REQ_ARG]            ; raw token ptr
    test rbx, rbx
    jz   .reply
    lea  rdi, [rel str_ab_tok_restore]
    mov  rsi, rbx
    call hp_streq
    test rax, rax
    jnz  .try_num
    ; RESTORE: trial=0, confirmed=magic
    mov  dil, CMOS_AB_TRIAL
    xor  esi, esi
    call cmos_ab_wr
    mov  dil, CMOS_AB_CONFIRMED
    mov  sil, AB_CONFIRMED_MAGIC
    call cmos_ab_wr
    jmp  .reply
.try_num:
    ; single-digit trial force 1..5 (anything else -> read-only status)
    movzx eax, byte [rbx]
    sub  eax, '0'
    cmp  eax, 1
    jb   .reply
    cmp  eax, 5
    ja   .reply
    cmp  byte [rbx + 1], 0               ; must be exactly one digit
    jne  .reply
    mov  esi, eax
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_wr                      ; trial = N
    mov  dil, CMOS_AB_CONFIRMED
    xor  esi, esi
    call cmos_ab_wr                      ; confirmed = 0 (unconfirmed keep)
.reply:
    ; stage LIVE CMOS read-backs: " abforce trial=N confirmed=0xNN"
    call ab_out_reset
    lea  rdi, [rel str_ab_o_force]
    call ab_out_str
    mov  dil, CMOS_AB_TRIAL
    call cmos_ab_rd
    movzx edi, al
    call ab_out_dec
    lea  rdi, [rel str_ab_o_conf]        ; " confirmed=0x"
    call ab_out_str
    mov  dil, CMOS_AB_CONFIRMED
    call cmos_ab_rd
    movzx edi, al
    call ab_out_hex
    mov  byte [rel ab_out_ready], 1
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: LOGMODE VERBOSE|LEAN|AUTO <32-hex nonce> -------------------------
; Registry metadata marks this destructive, so command_dispatch requires an
; AUTH1 owner envelope before this handler can touch CMOS.  The policy byte is
; read back and reported; it is consumed+cleared by the next boot selector.
cmd_verb_logmode:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    call logmode_parse_arg
    cmp  eax, -1
    je   .badarg
    mov  r12d, eax                       ; 0=AUTO, 1=LEAN, 2=VERBOSE
    mov  sil, CMOS_LOGMODE_AUTO
    test eax, eax
    jz   .write
    mov  sil, CMOS_LOGMODE_LEAN
    cmp  eax, LOG_MODE_LEAN
    je   .write
    mov  sil, CMOS_LOGMODE_VERBOSE
.write:
    mov  dil, CMOS_LOGMODE
    call cmos_ab_wr
    mov  dil, CMOS_LOGMODE
    call cmos_ab_rd
    movzx ebx, al                        ; live readback
    mov  r13d, CMOS_LOGMODE_AUTO
    test r12d, r12d
    jz   .expected_ready
    mov  r13b, CMOS_LOGMODE_LEAN
    cmp  r12d, LOG_MODE_LEAN
    je   .expected_ready
    mov  r13b, CMOS_LOGMODE_VERBOSE
.expected_ready:
    call ab_out_reset
    lea  rdi, [rel str_logmode_out]
    call ab_out_str
    test r12d, r12d
    jz   .name_auto
    cmp  r12d, LOG_MODE_LEAN
    je   .name_lean
    lea  rdi, [rel str_logmode_verbose]
    jmp  .name_emit
.name_auto:
    lea  rdi, [rel str_logmode_auto]
    jmp  .name_emit
.name_lean:
    lea  rdi, [rel str_logmode_lean]
.name_emit:
    call ab_out_str
    lea  rdi, [rel str_logmode_persisted]
    call ab_out_str
    mov  edi, ebx
    call ab_out_hex
    cmp  bl, r13b
    jne  .write_fail
    lea  rdi, [rel str_logmode_ok]
    call ab_out_str
    mov  byte [rel ab_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.write_fail:
    lea  rdi, [rel str_logmode_write_fail]
    call ab_out_str
    mov  byte [rel ab_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  qword [rsi + RSP_CODE], CMDE_BADSEL
    ret
.badarg:
    call ab_out_reset
    lea  rdi, [rel str_logmode_usage]
    call ab_out_str
    mov  byte [rel ab_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  qword [rsi + RSP_CODE], CMDE_BADARG
    ret

; Parse one of the three exact policy names plus a printable 128-bit nonce.
; RDI=argument string, EAX=0 AUTO / 1 LEAN / 2 VERBOSE / -1 invalid.
logmode_parse_arg:
    test rdi, rdi
    jz   .bad
    cmp  dword [rdi], 'AUTO'
    jne  .try_lean
    cmp  byte [rdi + 4], ' '
    jne  .bad
    xor  eax, eax
    lea  rdx, [rdi + 5]
    jmp  .nonce
.try_lean:
    cmp  dword [rdi], 'LEAN'
    jne  .try_verbose
    cmp  byte [rdi + 4], ' '
    jne  .bad
    mov  eax, LOG_MODE_LEAN
    lea  rdx, [rdi + 5]
    jmp  .nonce
.try_verbose:
    cmp  dword [rdi], 'VERB'
    jne  .bad
    cmp  word [rdi + 4], 'OS'
    jne  .bad
    cmp  byte [rdi + 6], 'E'
    jne  .bad
    cmp  byte [rdi + 7], ' '
    jne  .bad
    mov  eax, 2
    lea  rdx, [rdi + 8]
.nonce:
    xor  ecx, ecx
.hex:
    cmp  ecx, 32
    jae  .end
    movzx r8d, byte [rdx + rcx]
    cmp  r8b, '0'
    jb   .bad
    cmp  r8b, '9'
    jbe  .next
    or   r8b, 0x20
    cmp  r8b, 'a'
    jb   .bad
    cmp  r8b, 'f'
    ja   .bad
.next:
    inc  ecx
    jmp  .hex
.end:
    cmp  byte [rdx + 32], 0
    jne  .bad
    ret
.bad:
    mov  eax, -1
    ret

; --- VERB: AB_STATE <nonce> — the live keep decision. Reply:
;     "state=<CONFIRMED|PENDING|FALLBACK> counter=N confirmed=0xNN".
cmd_verb_abstate:
    call cmd_handler_prologue
    push rdi
    push rsi
    call ab_out_reset
    lea  rdi, [rel str_ab_o_state]       ; "state="
    call ab_out_str
    call ab_out_state                    ; CONFIRMED|PENDING|FALLBACK (staged)
    lea  rdi, [rel str_ab_o_counter]     ; " counter="
    call ab_out_str
    mov  edi, [rel ab_trial]
    call ab_out_dec
    lea  rdi, [rel str_ab_o_conf]        ; " confirmed=0x"
    call ab_out_str
    mov  edi, [rel ab_confirmed]
    call ab_out_hex
    mov  byte [rel ab_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax            ; echo nonce back through the envelope
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: AB_COUNTER <nonce> — the boot-attempt counter. Reply: "counter=N".
cmd_verb_abcounter:
    call cmd_handler_prologue
    push rdi
    push rsi
    call ab_out_reset
    lea  rdi, [rel str_ab_o_counter2]    ; "counter="
    call ab_out_str
    mov  edi, [rel ab_trial]
    call ab_out_dec
    mov  byte [rel ab_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- serial emit helpers (canonical fmt_dec/fmt_hex, G1) ---
ab_emit_dec:
    lea  rsi, [rel ab_numbuf]
    call fmt_dec
    lea  rdi, [rel ab_numbuf]
    call serial_string
    ret
ab_emit_hex:
    lea  rsi, [rel ab_numbuf]
    xor  edx, edx
    call fmt_hex
    lea  rdi, [rel ab_numbuf]
    call serial_string
    ret
; ab_emit_state — print the CONFIRMED|PENDING|FALLBACK token to serial.
ab_emit_state:
    mov  eax, [rel ab_state]
    cmp  eax, AB_ST_CONFIRMED
    je   .c
    cmp  eax, AB_ST_FALLBACK
    je   .f
    lea  rdi, [rel str_ab_en_pending]
    jmp  .out
.c:
    lea  rdi, [rel str_ab_en_confirmed]
    jmp  .out
.f:
    lea  rdi, [rel str_ab_en_fallback]
.out:
    call serial_string
    ret

; --- staged-reply buffer helpers (mirror thermal's therm_out_*) ---
ab_out_reset:
    lea  rax, [rel ab_out_buf]
    mov  [rel ab_out_cur], rax
    ret
ab_out_str:
    mov  rsi, [rel ab_out_cur]
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
    mov  [rel ab_out_cur], rsi
    ret
ab_out_dec:
    mov  rsi, [rel ab_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel ab_out_cur], rsi
    ret
ab_out_hex:
    mov  rsi, [rel ab_out_cur]
    push rsi
    xor  edx, edx
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel ab_out_cur], rsi
    ret
; ab_out_state — append the CONFIRMED|PENDING|FALLBACK token to the staged reply.
ab_out_state:
    mov  eax, [rel ab_state]
    cmp  eax, AB_ST_CONFIRMED
    je   .c
    cmp  eax, AB_ST_FALLBACK
    je   .f
    lea  rdi, [rel str_ab_en_pending]
    jmp  .out
.c:
    lea  rdi, [rel str_ab_en_confirmed]
    jmp  .out
.f:
    lea  rdi, [rel str_ab_en_fallback]
.out:
    call ab_out_str
    ret

; --- svc/boot_ab data (RW under our page tables, in-image) -------------------
align 8
ab_out_cur:        dq 0                  ; live staged-reply cursor
ab_trial:          dd 0                  ; CMOS 0x74 boot-attempt counter (this boot)
ab_confirmed:      dd 0                  ; CMOS 0x75 confirmed byte (0xC0 == good)
ab_state:          dd AB_ST_PENDING      ; live enum (PENDING/CONFIRMED/FALLBACK)
boot_crashes_observed: db 0              ; live pre-increment A/B trial count; commit/network never clear it
boot_log_prior_trial: db 0                ; immutable P0 sample used only by mode selection
boot_log_prior_done: db 0                 ; prevents the selector from resampling changed CMOS
boot_log_prior_valid: db 0                ; invalid bytes force VERBOSE instead of clean
boot_log_override_policy: db 0            ; immutable P0 decode: AUTO/LEAN/VERBOSE/malformed
boot_log_override_pending: db 0           ; P0 saw a nonzero byte; boot_log_override_clear clears it
ab_good_hash:      dw 0                  ; live hash of the good keep signature
ab_corrupt_hash:   dw 0                  ; live hash of the one-byte-corrupt keep
ab_manifest:       dw 0                  ; trusted stored hash (= good keep hash)
ab_tco_base:       dw 0                  ; derived TCO I/O base (ABASE + 0x60)
ab_tco_present:    db 0                  ; 1 == TCO_RLD decrement observed
ab_tco_absent_reason: db AB_TCO_REASON_NONE ; live reason projected in replies
ab_tco_first:      dw 0                  ; first live TCO_RLD sample
ab_tco_second:     dw 0                  ; second live TCO_RLD sample
ab_m_verify:       db 0                  ; boot.ab.verify earned
ab_m_loaded:       db 0                  ; boot.ab.state.loaded earned
ab_m_wdog:         db 0                  ; watchdog state measured + reported
ab_m_commit:       db 0                  ; boot.ab.committed earned
ab_out_ready:      db 0                  ; a per-command reply line is staged in ab_out_buf
ab_numbuf:         times 24 db 0         ; u64 dec/hex scratch
; GOOD and CORRUPT differ by exactly ONE byte so the mismatch is deterministic.
ab_good_sig:       db "PAOS-REWORK-KEEP-SLOT-A-verify-then-jump"
ab_sig_len         equ $ - ab_good_sig
ab_corrupt_sig:    db "PAOS-REWORK-KEEP-SLOT-A-verify-then-jVmp"  ; 'u'->'V'
align 8
ab_out_buf:        times 128 db 0

; --- boot markers (serial + BOOTLOG content-grade) ---
str_ab_v_pre:   db "[PAOS64] P0 boot-ab: verify-then-jump good_hash=0x", 0
str_ab_v_corr:  db " corrupt_hash=0x", 0
str_ab_v_post:  db " selected=A corrupt_rejected=1 [boot.ab.verify]", 13, 10, 0
str_ab_s_pre:   db "[PAOS64] P0 boot-ab: trial/good state loaded trial=", 0
str_ab_s_conf:  db " confirmed=0x", 0
str_ab_s_state: db " state=", 0
str_ab_s_post:  db " [boot.ab.state.loaded]", 13, 10, 0
str_ab_w_ok:    db "[PAOS64] P1 boot-ab: Intel PCH TCO watchdog TCO base=0x", 0
str_ab_w_first: db " first=0x", 0
str_ab_w_second: db " second=0x", 0
str_ab_w_ok_post: db " counting=1 mode=armed-safe(halted) [boot.watchdog.armed]", 13, 10, 0
str_ab_w_absent_locked: db "[PAOS64] P1 boot-ab: watchdog absent reason=locked counting=0 [boot.watchdog.absent]", 13, 10, 0
str_ab_w_absent_gated: db "[PAOS64] P1 boot-ab: watchdog absent reason=gated counting=0 [boot.watchdog.absent]", 13, 10, 0
str_ab_w_absent_backend: db "[PAOS64] P1 boot-ab: watchdog absent reason=no-backend counting=0 [boot.watchdog.absent]", 13, 10, 0
str_ab_w_absent_vendor: db "[PAOS64] P1 boot-ab: watchdog absent reason=no-backend vendor=non-intel (no PCH TCO; no PCI/port I/O) counting=0 [boot.watchdog.absent]", 13, 10, 0
str_ab_w_truthful: db "[PAOS64] P1 boot-ab: watchdog state reported truthfully (armed only if counting) [boot.watchdog.truthful]", 13, 10, 0
str_ab_c_pre:   db "[PAOS64] P6 boot-ab: trial->good commit confirmed=0x", 0
str_ab_c_ctr:   db " counter=0 [boot.ab.committed]", 13, 10, 0

; --- state enum tokens (matched by the probe's state=(CONFIRMED|PENDING|FALLBACK)) ---
str_ab_en_pending:   db "PENDING", 0
str_ab_en_confirmed: db "CONFIRMED", 0
str_ab_en_fallback:  db "FALLBACK", 0

; --- verb names (matched verbatim by command_lookup) ---
str_verb_abstate:    db "AB_STATE", 0
str_verb_abcounter:  db "AB_COUNTER", 0
str_verb_faultinj:   db "FAULTINJ", 0
str_verb_faultinject: db "FAULTINJECT", 0
str_verb_abforce:    db "ABFORCE", 0
str_verb_logmode:    db "LOGMODE", 0

str_logmode_out:       db " logmode=", 0
str_logmode_auto:      db "auto", 0
str_logmode_lean:      db "lean", 0
str_logmode_verbose:   db "verbose", 0
str_logmode_persisted: db " persisted=one_boot cmos=0x", 0
str_logmode_ok:        db " writeback=match", 0
str_logmode_write_fail:db " writeback=mismatch", 0
str_logmode_usage:     db " logmode=refused expected=VERBOSE|LEAN|AUTO+32hex", 0

; --- 9702 arm markers + verb tokens/fragments ---
str_ab_arm_ok:    db "[PAOS64] P1 fault-recover: CF9 warm-reset ARMED (bare metal: CPUID hypervisor bit clear) [fault.warmreset.armed]", 13, 10, 0
str_ab_arm_vm:    db "[PAOS64] P1 fault-recover: CF9 arm SKIPPED (hypervisor present — QEMU/VM keeps the marker-only path)", 13, 10, 0
str_ab_tok_xhci:    db "xhci", 0
str_ab_tok_xhci_upper: db "XHCI", 0
str_ab_tok_ud:      db "ud", 0
str_ab_tok_de:      db "de", 0
str_ab_tok_div0:    db "DIV0", 0
str_ab_tok_restore: db "RESTORE", 0
str_ab_o_armed:     db " armed=", 0
str_ab_o_inject:    db " kinds=xhci,ud,de legacy=DIV0 protected=e1000e,boot,storage", 0
str_ab_o_refused:   db " FAULTINJ refused=1 reason=unknown_or_protected allowed=xhci", 0
str_ab_o_force:     db " abforce trial=", 0
str_ab_o_ud_trapped:   db " kind=ud trapped=", 0
str_ab_o_ud_recovered: db " recovered=", 0
str_ab_o_ud_dump:      db " dump=", 0
str_ab_o_ud_vector:    db " vector=", 0
str_ab_o_ud_rip:       db " rip=0x", 0
str_ab_o_ud_nonce:     db " nonce=", 0
str_ab_o_ud_baremetal: db " baremetal=", 0

; --- staged UDP reply fragments ---
str_ab_o_state:    db " state=", 0
str_ab_o_counter:  db " counter=", 0
str_ab_o_conf:     db " confirmed=0x", 0
str_ab_o_counter2: db " counter=", 0
