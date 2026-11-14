;; MODULE gui/power_button
;; LAYER 6
;; EXPORTS pwr_m1_sleep_exec, pwr_m1_restore_on_signin, power_events_tick, power_remote_shutdown_tick, power_lid_changes, power_bl_verb_id, cmd_verb_backlight
;; IMPORTS svc/m1_checkpoint, gui/session_restore, svc/command_auth, fs/vfs, core/sched, dev/power/ec_power, svc/command, svc/command_shutdown, gui/power_exec, core/time, sec/principal, sec/session, config/keep_config, gui/lock_screen, boot/header, boot/boot_v2_handoff, boot/boot_v2_health, boot/serial, gui/window, gui/command_gui, bus/acpi
;; CAPS CAP_GUI
;; OWNER saga:rc_power
; ============================================================================
; gui/power_button.asm — the idle-loop side of RCQ-27 slice 1.
;
; power_events_tick runs in the resident idle loop (boot/header.asm .halt, the
; timer-woken hlt loop that already hosts the bounded periodic ticks). On a
; machine without an EC platform descriptor it initialises once (two SMBIOS
; string compares, no I/O, no output) and then returns at the first compare.
; With a descriptor: the PM1 fixed-feature power button is polled every
; PWR_PM1_MS and the EC battery/AC snapshot refreshed every PWR_EC_MS.
;
; Desktop root 2026-10-17 00:30 / root-on-duty 00:42: a physical press on
; an unlocked local OWNER desktop is the shutdown intent. It requests the
; existing power_execute(POWER_SHUTDOWN) directly, including its managed plan
; when bound and its storage/quiesce/S5/fallback checks. No GUI confirmation is
; synthesized. Locked, headless, pre-desktop or absent/revoked local authority
; still logs only. An unready Boot-v2 Trial is held, without force override.
;
; Slice 2: the lid (ecp_lid_poll, debounced) is polled on the same 100 ms
; cadence; a change is logged ([power.lid]) and shown as LID= in the owner-signed
; STATUS. POWER-05 (root 2026-10-08 08:32): closing the lid locks and, after a
; short grace, runs the normal quiesced Shut down (pwr_lid_tick). When the descriptor's
; backlight came up, ONE owner-gated verb is registered, on this machine only:
;   BACKLIGHT [pct]   0..100 -> the clamped PCH PWM duty (never 0); no arg = no
;                     change. Read-back: BL_DUTY/BL_MAX/BL_PCT in owner STATUS.
; It is destructive=1 with no public-floor entry, so a remote caller needs an
; owner envelope (command_auth_required_cap fails closed for new verbs), and a
; machine without the descriptor never gets the verb (registry unchanged).
; ============================================================================

PWR_PM1_MS equ 100
PWR_EC_MS  equ 10000
PWR_TICK_MS_GUESS equ 1                      ; uncalibrated fallback: the idle loop wakes at least per ~1000 Hz PIT IRQ (time.asm:724)

power_events_tick:
    sub rsp, 8
    call power_s5_step                      ; opt-in managed request, independent of EC presence
    call pwr_fixed_button_tick              ; generic FADT event; existing local-owner shutdown gate
    call pwr_button_grace_tick              ; a routed press's fixed 1 s grace (needs no EC, no STATUS reader)
    add rsp, 8
    cmp  byte [rel pwr_inited], 1
    je   .inited
    mov  byte [rel pwr_inited], 1
    call ecp_init_cooperative                ; EC battery/lid IO advances on later idle ticks
    cmp  byte [rel ecp_active], 1
    jne  .out
    call boot_ms_now
    mov  [rel pwr_last_ec_ms], rax           ; no second read on the next tick
    mov  al, [rel ecp_lid]
    mov  [rel pwr_lid_known], al             ; POWER-05: only a close from a known-open lid arms
    cmp  byte [rel ecp_bl_ok], 1
    jne  .inited
    lea  rdi, [rel pwr_verb_backlight]
    lea  rsi, [rel cmd_verb_backlight]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                               ; DESTRUCTIVE: changes the panel's light
    call command_register_verb
    mov  [rel power_bl_verb_id], eax
.inited:
    cmp  byte [rel ecp_active], 1
    jne  .out
    push rbx
    call boot_ms_now                         ; RAX = ms since boot (clobbers RAX,RCX,RDX)
    test rax, rax
    jnz  .timed
    ; Uncalibrated TSC: boot_ms_now stays 0, so the ms cadence would never fire
    ; and a press would be silently ignored. Count idle ticks instead (the loop
    ; is timer-woken) and say so once.
    inc  qword [rel pwr_ticks]
    cmp  byte [rel pwr_untimed_said], 1
    je   .tick_cadence
    mov  byte [rel pwr_untimed_said], 1
    lea  rdi, [rel pwr_s_untimed]
    call serial_string
.tick_cadence:
    mov  rax, [rel pwr_ticks]
    imul rax, rax, PWR_TICK_MS_GUESS
.timed:
    mov  rbx, rax
    mov  rcx, rax
    sub  rcx, [rel pwr_last_ec_ms]
    cmp  rcx, PWR_EC_MS
    jb   .sample_step
    mov  [rel pwr_last_ec_ms], rbx
    cmp  byte [rel ecp_sample_state], 2
    jne  .sample_begin
    call ecp_sample_recover                 ; one bounded retirement retry on a later 10 s cadence
    jmp  .sample_step
.sample_begin:
    call ecp_sample_begin                   ; captures intent; never busy-polls
    cmp  eax, 2                            ; an already-completed producer may return DONE
    jne  .sample_step
    mov  byte [rel pwr_cell_check], 1
.sample_step:
    call ecp_sample_step                    ; ONE phase, <=2 EC byte IO on this tick
    cmp  eax, 0
    je   .crit
    cmp  eax, 1
    je   .crit
    mov  byte [rel pwr_cell_check], 1        ; completion, failed or blocked retirement
.crit:
    push rbx
    call pwr_critical_tick                   ; RBX = now (ms); every tick: the countdown is per second
    pop  rbx
    push rbx
    call pwr_lid_tick                        ; RBX = now (ms): the POWER-05 lid grace
    pop  rbx
    cmp  byte [rel pwr_cell_check], 1
    jne  .pm1
    mov  byte [rel pwr_cell_check], 0
    push rbx
    movzx esi, byte [rel bat_crit_left_s]     ; RCQ-27: the same countdown on the lock screen
    xor  edi, edi
    test esi, esi
    setnz dil                                ; LOCK_NOTICE_BATTERY while armed, else none
    call lock_screen_notice                  ; dedups; paints only on the composed sign-in surface
    call taskbar_battery_stale               ; RCQ-27 POWER-04: the cell shows an older state
    test eax, eax
    jz   .cell_ok
    call taskbar_draw_registry               ; lock-gated: nothing while the session is locked
.cell_ok:
    pop  rbx
.pm1:
    mov  rcx, rbx
    sub  rcx, [rel pwr_last_pm1_ms]
    cmp  rcx, PWR_PM1_MS
    jb   .done
    mov  [rel pwr_last_pm1_ms], rbx
    call ecp_lid_poll                       ; queue demand, consume completed result only
    cmp eax, 2
    jne .lid_event
    mov al, [rel ecp_lid]
    mov [rel pwr_lid_known], al             ; initial baseline is not a close transition
    jmp .lid_same
.lid_event:
    test eax, eax
    jz   .lid_same
    call pwr_lid_changed
    jmp  .lid_done
.lid_same:
    call pwr_lid_bl_retry
.lid_done:
    cmp byte [rel pwr_fixed_button_owns_pm1], 1
    je .done                               ; generic path already owns this fixed event
    ; The descriptor fallback must not bypass a failed/unknown SCI handoff.
    call power_button_ownership
    test eax, eax
    jnz .done
    call ecp_pm1_poll
    test eax, eax
    jz   .done
    call pwr_button_pressed
.done:
    pop  rbx
.out:
    ret

; pwr_button_pressed — consume physical intent after the existing local gate.
; Only the qualified fixed/descriptor poll calls this; input injection does not.
; RCQ-27 Dell order (root 2026-10-17 18:41, O1): a routed press counts
; power_button_presses_routed (owner STATUS PWRB_ROUTED, read-only) and arms a fixed
; PWR_BTN_GRACE_MS grace; power_events_tick then runs the same power_execute. The
; gates are the press's own and are not re-run: the grace only delays, it never
; extends or cancels. A second routed press inside the grace, or no calibrated clock,
; executes at once. Nothing outside this module reads or writes the grace state, so no
; verb can hold it. Why: the box answers UDP for ~1 s after the route, so a 200 ms
; STATUS poller sees ROUTED 0->1 between the press and the power-off.
PWR_BTN_GRACE_MS equ 1000
pwr_button_pressed:
    lea  rsi, [rel pwr_why_cli]
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .log
    lea  rsi, [rel pwr_why_locked]
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .log
    lea  rsi, [rel pwr_why_nodesktop]
    cmp  byte [rel lock_desktop_created], 1
    jne  .log
    call session_shell_local_authority  ; RAX=login PID, RDX=token; 0/0 refused
    lea  rsi, [rel pwr_why_principal]
    cmp  rax, PRIN_OWNER
    jne  .log
    ; Preserve Trial health accounting, as on the signed SHUTDOWN rail.
    lea  rsi, [rel pwr_why_trial]
    cmp  byte [rel pbm_manager_launch], 1
    jne  .shutdown
    cmp  byte [rel pbm_reason], PBM_REASON_TRIAL
    jne  .shutdown
    cmp  byte [rel pbm_strong_health_published], 1
    jne  .log
.shutdown:
    inc  dword [rel power_button_presses_routed]
    cmp  byte [rel pwr_btn_grace_armed], 1
    je   pwr_button_execute                 ; a second press inside the grace: now
    call boot_ms_now                         ; RAX = ms since boot (clobbers RAX,RCX,RDX)
    test rax, rax
    jz   pwr_button_execute                 ; no calibrated clock: no grace to count
    mov  [rel pwr_btn_grace_at], rax
    mov  byte [rel pwr_btn_grace_armed], 1
    lea  rdi, [rel pwr_s_grace]
    call serial_string
    ret
.log:
    push rsi
    inc  dword [rel power_button_presses_logged]
    lea  rdi, [rel pwr_s_logged]
    call serial_string
    pop  rdi
    call serial_string
    lea  rdi, [rel pwr_s_tail]
    call serial_string
    ret

; pwr_button_grace_tick — every idle tick: an armed grace that is over runs the Shut down.
; A clock read of 0 or one behind the arm wraps high and fires too (never a longer wait).
pwr_button_grace_tick:
    cmp  byte [rel pwr_btn_grace_armed], 1
    jne  .out
    call boot_ms_now
    sub  rax, [rel pwr_btn_grace_at]
    cmp  rax, PWR_BTN_GRACE_MS
    jae  pwr_button_execute                 ; same stack depth as the press's own call
.out:
    ret

; pwr_button_execute — the routed press's Shut down (disarms first, so it runs once per arm).
pwr_button_execute:
    mov  byte [rel pwr_btn_grace_armed], 0
    lea  rdi, [rel pwr_s_shutdown]
    call serial_string
    mov  edi, POWER_SHUTDOWN
    call power_execute                      ; same guarded/quiesced path as Start > Power
    push rax                                ; pending managed request or returned failure
    lea  rdi, [rel pwr_s_returned]
    call serial_string
    pop  rdi
    call serial_string
    ret

; RCQ-27 POWER-05 thermal floor (root 2026-10-08 08:32 (5a); SLEEP.md 7.1): before
; M1 exists a closed lid still takes a safe action.
; - Lid closed (a debounced transition from a lid last known OPEN; a lid closed
;   or unreadable at boot, e.g. a docked laptop, never arms): lock now if the
;   session is unlocked (the Win+L / LOCK transition), then arm.
; - Still closed PWR_LID_GRACE_MS later with no busy job, and a FRESH EC lid read
;   (not the debounced state) says closed: the normal quiesced Shut down
;   (power_execute: storage quiesce, ACPI S5). A fresh read of open or a timeout
;   holds this round (the debounced poll cancels a real open; a misread never
;   disarms the floor). If the Shut down returns (nothing powered off), or a round
;   is held, the next attempt is a grace period later; the 15-min cap keeps
;   counting from the close.
; - A busy job (a unified-scheduler job such as SMPBENCH, or an FSCOPY running or
;   reclaiming) defers it (SLEEP.md 7.6), but at most PWR_LID_INHIBIT_MAX_MS after
;   the close; then the thermal floor wins.
; - Lid opened: cancelled. The session stays locked, so lid open lands on sign-in
;   (after a Shut down the next boot also lands on sign-in).
; - An unknown lid read changes nothing. Lid-open WAKE from S5 is unverified on
;   the Dell and needs a product disposition before laptop acceptance.
; - Without a calibrated TSC the grace counts idle wakes (shorter, never longer).
; - pwr_lid_action 0 disables power-off only; lid close still locks (§21.2.2).
; - Backlight (root 16:43:12, independent of pwr_lid_action): every debounced close
;   blanks the panel PWM (ecp_bl_lid_blank: duty saved, duty 0) and the open
;   writes the saved duty back. If the PWM does not validate at the open, the
;   panel stays dark only until a later lid poll (100 ms) finds it valid
;   (pwr_lid_bl_retry, srcreview H1); a PWM that validates but will not keep the
;   duty is given up after three writes and left to firmware. DPMS is untouched both ways: it blanks the
;   scanout, not the PWM, so a DPMS-blanked screen stays black after the open
;   until input wakes it, and a lid close never changes dpms_blanked.
PWR_LID_GRACE_MS       equ 30000
PWR_LID_INHIBIT_MAX_MS equ 900000            ; 15 min: a job never keeps a closed laptop running longer

; pwr_lid_changed(RBX = now ms) — the debounced lid transition.
pwr_lid_changed:
    inc  dword [rel power_lid_changes]
    lea  rdi, [rel pwr_s_lid]
    call serial_string
    cmp  byte [rel ecp_lid], 0
    je   .closed
    cmp  byte [rel ecp_lid], 1
    jne  .unknown
    mov  byte [rel pwr_lid_known], 1
    lea  rdi, [rel pwr_s_lid_open]
    call serial_string
    call ecp_bl_lid_restore
    test eax, eax
    jg   .lit                                ; 1: the close never blanked it
    lea  rdi, [rel pwr_s_lid_bl_on]
    jz   .bl_said
    lea  rdi, [rel pwr_s_lid_bl_on_refused]  ; -1: still dark, pwr_lid_bl_retry retries
    cmp  eax, -1
    je   .bl_said
    lea  rdi, [rel pwr_s_lid_bl_gave_up]
.bl_said:
    call serial_string
.lit:
    cmp  byte [rel pwr_lid_armed], 1
    jne  .out
    mov  byte [rel pwr_lid_armed], 0
    lea  rdi, [rel pwr_s_lid_cancel]
    jmp  serial_string
.unknown:
    lea  rdi, [rel pwr_s_lid_unknown]
    jmp  serial_string
.closed:
    lea  rdi, [rel pwr_s_lid_closed]
    call serial_string
    cmp  byte [rel ecp_bl_ok], 1
    jne  .bl_done                            ; no panel PWM on this machine
    call ecp_bl_lid_blank
    lea  rdi, [rel pwr_s_lid_bl_off]
    test eax, eax
    jz   .bl_off_said
    lea  rdi, [rel pwr_s_lid_bl_off_refused]
.bl_off_said:
    call serial_string
.bl_done:
    cmp  byte [rel pwr_lid_known], 1
    mov  byte [rel pwr_lid_known], 0
    jne  .out                                ; not from a known-open lid (boot closed / unreadable)
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .arm                                ; never relock: that would wipe a password being typed
    call session_shell_lock                  ; lock_screen_sync paints the sign-in surface
    lea  rdi, [rel pwr_s_lid_locked]
    call serial_string
.arm:
    cmp  byte [rel pwr_lid_action], 1         ; power policy never disables locking
    jne  .out
    mov  byte [rel pwr_lid_armed], 1
    mov  byte [rel pwr_lid_deferred_said], 0
    mov  [rel pwr_lid_since], rbx
    mov  [rel pwr_lid_closed_at], rbx
    lea  rdi, [rel pwr_s_lid_armed]
    jmp  serial_string
.out:
    ret

; pwr_lid_bl_retry — srcreview H1: the lid is known open but the panel is still
;   dark from the close (the restore at the open found the PWM unusable): retry
;   the restore on each lid poll and say only its outcome. Preserves RBX.
pwr_lid_bl_retry:
    cmp  byte [rel ecp_bl_lid_dark], 0
    je   .out
    cmp  byte [rel pwr_lid_known], 1
    jne  .out                                ; closed or unknown: the close's blank stands
    call ecp_bl_lid_restore
    test eax, eax
    jz   .lit
    cmp  eax, -1
    je   .out                                ; still not valid: the next poll retries
    lea  rdi, [rel pwr_s_lid_bl_gave_up]
    jmp  serial_string
.lit:
    lea  rdi, [rel pwr_s_lid_bl_on_retry]
    jmp  serial_string
.out:
    ret

; pwr_lid_tick(RBX = now ms) — run the lid Shut down once the grace is over.
pwr_lid_tick:
    cmp  byte [rel pwr_lid_armed], 1
    jne  .cancel_verify
    cmp  byte [rel ecp_lid], 1
    je   .cancel_verify                      ; opened: cancel the raw request
    mov  rax, rbx
    sub  rax, [rel pwr_lid_since]
    jc   .held
    cmp  rax, PWR_LID_GRACE_MS
    jb   .out
    call pwr_busy_job
    test eax, eax
    jz   .go
    mov  rax, rbx
    sub  rax, [rel pwr_lid_closed_at]
    cmp  rax, PWR_LID_INHIBIT_MAX_MS
    jae  .capped
    cmp  byte [rel pwr_lid_deferred_said], 1
    je   .out
    mov  byte [rel pwr_lid_deferred_said], 1
    lea  rdi, [rel pwr_s_lid_deferred]
    jmp  serial_string
.capped:
    lea  rdi, [rel pwr_s_lid_capped]
    call serial_string
.go:
    cmp  qword [rel pwr_lid_verify_id], 0
    jne  .await
    call ecp_lid_confirm_begin              ; request only, zero EC IO
    test rax, rax
    jz   .held
    mov  [rel pwr_lid_verify_id], rax
.await:
    mov  rdi, [rel pwr_lid_verify_id]
    call ecp_lid_read_now                   ; matching one-shot raw result; zero EC IO
    cmp  eax, 256
    je   .out                              ; pending is not fresh closed confirmation
    test eax, eax
    jz   .closed_now
.held:
    mov  [rel pwr_lid_since], rbx            ; held/failed attempts retry after a full grace
    mov  rdi, [rel pwr_lid_verify_id]
    mov  qword [rel pwr_lid_verify_id], 0
    call ecp_lid_confirm_cancel             ; retained-phase retirement, never drop custody
    lea  rdi, [rel pwr_s_lid_held]
    jmp  serial_string
.cancel_verify:
    mov  rdi, [rel pwr_lid_verify_id]
    mov  qword [rel pwr_lid_verify_id], 0
    jmp  ecp_lid_confirm_cancel
.closed_now:
    mov qword [rel pwr_lid_verify_id], 0
    mov [rel pwr_lid_since], rbx
    lea  rdi, [rel pwr_s_lid_go]
    call serial_string
    mov  edi, PWR_M1_LID
    call pwr_m1_sleep_exec                   ; M1-3: the session is locked, so this takes the plain safe off
    mov  rdi, rax
    jmp  serial_string
.out:
    ret

; pwr_busy_job -> EAX 1 while a job must not be cut off by the lid Shut down.
pwr_busy_job:
    mov  eax, 1
    cmp  byte [rel usched_job_active], 1
    je   .out
    call vfs_copy_busy
.out:
    ret

; cmd_verb_backlight(RDI=req, RSI=rsp): BACKLIGHT [pct]
cmd_verb_backlight:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    xor  eax, eax
    test rbx, rbx
    jz   .noarg
    cmp  byte [rbx], 0
    je   .noarg
    xor  ecx, ecx                            ; value
    xor  edx, edx                            ; digits
.digit:
    movzx r8d, byte [rbx]
    test r8d, r8d
    jz   .parsed
    sub  r8d, '0'
    cmp  r8d, 9
    ja   .badarg
    inc  edx
    cmp  edx, 3
    ja   .badarg
    imul ecx, ecx, 10
    add  ecx, r8d
    inc  rbx
    jmp  .digit
.parsed:
    cmp  ecx, 100
    ja   .badarg
    mov  edi, ecx
    call ecp_bl_set_pct
    test eax, eax
    jnz  .unavailable
.noarg:
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  eax, [rel ecp_bl_duty]
    mov  [r12 + RSP_VAL], rax
    mov  qword [r12 + RSP_ACCEPTED], 1
    jmp  .out
.unavailable:
    lea  rax, [rel pwr_bl_unavailable]
    cmp  byte [rel ecp_bl_lid_dark], 0
    je   .refused
    lea  rax, [rel pwr_bl_lid_dark]
    jmp  .refused
.badarg:
    lea  rax, [rel pwr_bl_grammar]
.refused:
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    mov  qword [r12 + RSP_EXPECTED], 100
    mov  [r12 + RSP_HINT], rax
.out:
    pop  r12
    pop  rbx
    ret

; power_remote_shutdown_tick: an owner-signed remote SHUTDOWN accepted by
; svc/command_shutdown runs here, in the idle loop, after the UDP frame that
; sent "SHUTDOWN accepted <nonce>" has returned. A 100 ms grace lets that frame
; leave the NIC, then power_execute(POWER_SHUTDOWN), the Start > Power path:
; storage quiesce, ACPI S5, else firmware shutdown. It returns only when nothing
; powered off; the nonce then reports "failed <nonce> <reason>".
power_remote_shutdown_tick:
    call pwr_m1_sleep_tick                   ; RCQ-27 M1-3: the SLEEP verb (every target)
    call command_shutdown_take
    test eax, eax
    jz   .out
    lea  rdi, [rel pwr_remote_go]
    call serial_string
    mov  edi, 100000
    call tsc_delay_us
    mov  edi, POWER_SHUTDOWN
    call power_execute                       ; RAX = why nothing happened
    push rax
    lea  rdi, [rel pwr_remote_failed]
    call serial_string
    mov  rdi, [rsp]
    call serial_string
    pop  rdi
    call command_shutdown_failed
.out:
    ret

; ---------------------------------------------------------------------------
; RCQ-27 POWER-06 M1-3: SLEEP = checkpoint + off (SLEEP.md M1; root 08:32 (b),
; 10:22 D1-D5, 10:56 C2(a)). A trigger seals the session (the window manifest,
; the build identity in the header) under the signed-in owner's key, commits it
; to PaOSCheckpointTmp/Primary, then takes the normal Shut down (storage quiesce,
; ACPI S5). EVERY reason not to checkpoint falls back to the plain safe off with
; the reason logged: a persisted PUSH policy (C2: its record escrows the owner key
; under an NVRAM-recoverable key - SEC-owner-key-in-push-record), no runtime
; NVRAM, no owner session or windows, no owner key (a locked session: the lid
; locks first), the CSPRNG, too little variable space, a failed write. The
; checkpoint is stored at most once per boot, so a Shut down that returns and is
; retried never writes again (one write pair per SLEEP). Restore runs once after
; the owner signs in (pwr_m1_restore_on_signin).
; ---------------------------------------------------------------------------
PWR_M1_VERB        equ 1
PWR_M1_LID         equ 2
PWR_M1_CRITICAL    equ 3
PWR_M1_MAGIC       equ 0x4C50314D           ; "M1PL"
PWR_M1_VERSION     equ 1
PWR_M1_MANIFEST    equ 512
PWR_M1_PLAIN_LEN   equ 8 + PWR_M1_MANIFEST

; pwr_m1_checkpoint -> EAX 0 stored (or already stored this boot), else the
;   PWR_M1_S_* index of the reason it was skipped (logged).
PWR_M1_S_PUSH      equ 1
PWR_M1_S_NO_SESSION equ 2
PWR_M1_S_NO_KEY    equ 3
PWR_M1_S_RNG       equ 4
PWR_M1_S_NO_SPACE  equ 5
PWR_M1_S_WRITE     equ 6
PWR_M1_S_SEAL      equ 7
PWR_M1_S_NO_RUNTIME equ 8
pwr_m1_checkpoint:
    push rbx
    xor  ebx, ebx
    cmp  byte [rel pwr_m1_stored], 1
    je   .done
    mov  ebx, PWR_M1_S_NO_RUNTIME
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .skip
    mov  ebx, PWR_M1_S_PUSH
    call m1_push_record_present              ; root C2(a) + srcreview R1: the v1 RECORD (it holds the owner
                                             ; key); a v2-only box (PaOSPush2: one-way handle) seals with push on
    test eax, eax
    jnz  .skip
    mov  ebx, PWR_M1_S_NO_SESSION
    call session_ram_checkpoint_build        ; C1: the live windows, owner only, no disk write
    test eax, eax
    jnz  .skip
    lea  rdi, [rel pwr_m1_plain + 8]
    call session_ram_checkpoint_export
    test eax, eax
    jnz  .skip
    mov  dword [rel pwr_m1_plain], PWR_M1_MAGIC
    mov  dword [rel pwr_m1_plain + 4], PWR_M1_VERSION
    call m1_next_generation
    mov  ebx, PWR_M1_S_WRITE
    cmp  rax, -1
    je   .skip
    mov  rcx, rax
    lea  rdi, [rel pwr_m1_slot]
    lea  rsi, [rel pwr_m1_plain]
    mov  edx, PWR_M1_PLAIN_LEN
    call m1_seal
    mov  ebx, PWR_M1_S_NO_KEY
    cmp  rax, M1_SEAL_NO_KEY
    je   .skip
    mov  ebx, PWR_M1_S_RNG
    cmp  rax, M1_SEAL_RNG
    je   .skip
    mov  ebx, PWR_M1_S_SEAL
    test rax, rax
    jle  .skip
    lea  rdi, [rel pwr_m1_slot]
    mov  esi, eax
    call m1_commit
    mov  ebx, PWR_M1_S_NO_SPACE
    cmp  eax, M1_VAR_NO_SPACE
    je   .skip
    mov  ebx, PWR_M1_S_WRITE
    test eax, eax
    jnz  .skip
    mov  byte [rel pwr_m1_stored], 1
    lea  rdi, [rel pwr_m1_s_stored]
    call serial_string
    xor  ebx, ebx
    jmp  .done
.skip:
    lea  rdi, [rel pwr_m1_s_skipped]
    call serial_string
    imul edi, ebx, PWR_M1_TEXT_SLOT
    lea  rcx, [rel pwr_m1_reasons]
    add  rdi, rcx
    call serial_string
.done:
    lea  rdi, [rel pwr_m1_plain]             ; the plaintext never outlives the call
    xor  esi, esi
    mov  edx, PWR_M1_PLAIN_LEN
    call memset
    call principal_wipe_owner_boot_key       ; P1 (root 12:58 a): nor does the boot owner-key copy
    mov  eax, ebx
    pop  rbx
    ret

; pwr_m1_sleep_exec(EDI = PWR_M1_* trigger) -> RAX = why nothing powered off (as
;   power_execute). The checkpoint is attempted first; whatever its outcome, the
;   normal Shut down follows (root 10:56: a refused checkpoint takes the plain
;   safe off). Revoke the session after checkpointing but before power-off, so
;   unavailable firmware or refused quiescence also returns to a locked session.
pwr_m1_sleep_exec:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi                           ; trigger survives checkpoint and all diagnostics
    mov  edi, M1_HIST_SLEEP
    xor  esi, esi
    mov  edx, ebx
    call pwr_m1_history
    call pwr_m1_checkpoint
    mov  r12d, eax
    test eax, eax
    jz   .off
    mov  edi, M1_HIST_PROBLEM
    mov  esi, r12d
    mov  edx, ebx
    call pwr_m1_history
.off:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .locked                            ; do not disturb an existing sign-in
    call session_shell_lock                  ; checkpoint used the owner before revocation
.locked:
    lea  rdi, [rel pwr_m1_s_off]
    call serial_string
    mov  edi, M1_HIST_OFF_ISSUED
    mov  esi, r12d
    mov  edx, ebx
    call pwr_m1_history
    mov  edi, POWER_SHUTDOWN
    call power_execute                      ; normal storage/driver quiescence and safe recovery
    mov  edi, M1_HIST_RETURNED
    mov  esi, r12d
    mov  edx, ebx
    call pwr_m1_history                      ; preserves the returned diagnostic pointer in RAX
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Best-effort history must not change the caller's result or trigger/reason.
; A failure is latched by svc/m1_checkpoint; report it once, without retries.
pwr_m1_history:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    call boot_ms_now
    mov  rcx, rax                           ; 0 explicitly means unknown; no invented RTC time
    mov  edi, [rsp]
    mov  esi, [rsp + 8]
    mov  edx, [rsp + 16]
    call m1_history_append
    test eax, eax
    jz   .out
    cmp  byte [rel pwr_m1_history_said], 0
    jne  .out
    mov  byte [rel pwr_m1_history_said], 1
    lea  rdi, [rel pwr_m1_history_error]
    call serial_string
.out:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; pwr_m1_sleep_tick — the SLEEP verb: registered once, executed here in the idle
;   loop after its reply has gone (100 ms grace, as the remote SHUTDOWN).
pwr_m1_sleep_tick:
    cmp  byte [rel pwr_m1_verb_done], 1
    je   .pending
    mov  byte [rel pwr_m1_verb_done], 1
    lea  rdi, [rel pwr_m1_verb_name]
    lea  rsi, [rel cmd_verb_sleep]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                               ; DESTRUCTIVE: powers the machine off
    call command_register_verb
    mov  [rel pwr_m1_verb_id], eax
.pending:
    cmp  byte [rel pwr_m1_pending], 1
    jne  .out
    mov  byte [rel pwr_m1_pending], 0
    mov  edi, 100000                         ; let the SLEEP reply leave the NIC
    call tsc_delay_us
    mov  edi, PWR_M1_VERB
    call pwr_m1_sleep_exec                   ; returns only when nothing powered off
    mov  rdi, rax
    jmp  serial_string
.out:
    ret

; cmd_verb_sleep(RDI = req, RSI = rsp): SLEEP - checkpoint + off, owner only, from
;   an unlocked owner session (the checkpoint key needs the signed-in owner). A
;   remote caller must be the owner (an AUTH1 owner ticket or an owner SSH
;   session), not merely MUTATE-capable. The session must be bound to the OWNER:
;   an unlocked lab dev-autologin (SYSTEM-bound) desktop refuses it as locked
;   (RCQ-27 M1 case A, root 15:58:31). Busy jobs refuse it (SLEEP.md 7.6).
cmd_verb_sleep:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rsi
    mov  rbx, rdi
    cmp  qword [rbx + REQ_SOURCE], CMD_SOURCE_CONSOLE
    je   .local                              ; the dispatcher already requires the console owner
    call command_auth_owner_request
    test eax, eax
    jz   .not_owner
.local:
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    call principal_current                   ; the gate just held it == session_bound_pid,
    cmp  rax, PRIN_OWNER                     ;   so this is bound == PRIN_OWNER
    jne  .locked
    lea  rax, [rel pwr_m1_busy]
    cmp  byte [rel pwr_m1_pending], 1
    je   .refused
    cmp  byte [rel usched_job_active], 1
    je   .refused
    call vfs_copy_busy
    test eax, eax
    lea  rax, [rel pwr_m1_busy]
    jnz  .refused
    mov  byte [rel pwr_m1_pending], 1
    lea  rdi, [rel pwr_m1_s_accepted]
    call serial_string
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_ACCEPTED], 1
    lea  rdi, [rel pwr_m1_r_accepted]
    jmp  .stage
.locked:
    mov  qword [r12 + RSP_CODE], CMDE_DESKTOP_LOCKED
    lea  rdi, [rel pwr_m1_r_locked]
    jmp  .stage
.not_owner:
    mov  qword [r12 + RSP_CODE], CMDE_AUTHDENY
    lea  rdi, [rel pwr_m1_r_owner]
    jmp  .stage
.refused:
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    mov  [r12 + RSP_HINT], rax
    mov  edi, M1_HIST_REFUSED
    mov  esi, 1                             ; busy: only after owner/unlocked checks
    mov  edx, PWR_M1_VERB
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_r_busy]
.stage:                                      ; C1: the generic envelope prints "SLEEP OK" for every
    push rdi                                 ;   code, so every path stages its own outcome
    call gui_out_reset
    pop  rdi
    call gui_out_str
    mov  byte [rel gui_out_ready], 1
.out:
    pop  r12
    pop  rbx
    ret

; pwr_m1_restore_on_signin — once per boot, right after the owner signs in (gui/
;   lock_screen's workspace-restore callback): a verified checkpoint above the
;   attempted high-water mark (raised first) becomes the in-RAM workspace checkpoint
;   that the restore about to run applies. Any doubt: nothing changes (fresh boot).
;   A sign-in that leaves the owner without this boot's key (a PUSH-only sign-in)
;   cannot open the checkpoint, so it defers without spending the once-flag: the
;   first sign-in of the boot that holds the key restores (rc-sec 14:27 NIT).
;   Unless that keyless session already saved its own workspace (a lock commit with
;   windows is the in-RAM checkpoint): the pre-sleep manifest is then superseded,
;   consumed (attempted mark raised) and never applied over the live session
;   (srcreview R1 16:39, C1 17:00).
pwr_m1_restore_on_signin:
    cmp  byte [rel pwr_m1_restore_done], 1
    je   .out
    mov  edi, PRIN_OWNER
    call principal_credential               ; RAX = 0: no owner key this boot (m1_open would fail)
    test rax, rax
    jz   .deferred
    mov  byte [rel pwr_m1_restore_done], 1
    push rbx
    cmp  byte [rel pwr_m1_deferred], 1       ; a keyless sign-in opened this boot's session
    jne  .candidate
    lea  rdi, [rel pwr_m1_plain]
    call session_ram_checkpoint_export       ; EAX 0: its lock commit left a valid manifest
    test eax, eax
    jnz  .candidate
    mov  edi, M1_HIST_RESTORE
    xor  esi, esi
    xor  edx, edx
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_plain]             ; consume it all the same: the attempted mark
    mov  esi, M1_PLAIN_CAP                   ;   rises past it, so no later boot restores a
    call m1_restore_candidate                ;   superseded workspace; the plaintext is discarded
    mov  edi, M1_HIST_SUPERSEDED
    mov  esi, edx                           ; actual candidate result, never an apply claim
    xor  edx, edx
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_s_superseded]
    call serial_string
    jmp  .wipe
.candidate:
    mov  edi, M1_HIST_RESTORE
    xor  esi, esi
    xor  edx, edx
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_plain]
    mov  esi, M1_PLAIN_CAP
    call m1_restore_candidate
    mov  ebx, edx                            ; fresh reason
    test eax, eax
    jz   .fresh
    mov  ebx, 6                              ; malformed payload
    cmp  eax, PWR_M1_PLAIN_LEN
    jne  .fresh
    cmp  dword [rel pwr_m1_plain], PWR_M1_MAGIC
    jne  .fresh
    cmp  dword [rel pwr_m1_plain + 4], PWR_M1_VERSION
    jne  .fresh
    lea  rsi, [rel pwr_m1_plain + 8]
    call session_ram_checkpoint_install      ; the bounded manifest parser (root D2)
    test eax, eax
    jnz  .fresh
    mov  edi, M1_HIST_INSTALLED
    xor  esi, esi
    xor  edx, edx
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_s_restored]
    call serial_string
    jmp  .wipe
.fresh:
    mov  edi, M1_HIST_FRESH
    mov  esi, ebx
    xor  edx, edx
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_s_fresh]
    call serial_string
    imul edi, ebx, PWR_M1_TEXT_SLOT
    lea  rcx, [rel pwr_m1_fresh_reasons]
    add  rdi, rcx
    call serial_string
.wipe:
    lea  rdi, [rel pwr_m1_plain]
    xor  esi, esi
    mov  edx, M1_PLAIN_CAP
    call memset
    pop  rbx
.out:
    ret
.deferred:
    cmp  byte [rel pwr_m1_deferred], 1
    je   .out
    mov  byte [rel pwr_m1_deferred], 1
    mov  edi, M1_HIST_DEFERRED
    mov  esi, PWR_M1_S_NO_KEY
    xor  edx, edx
    call pwr_m1_history
    lea  rdi, [rel pwr_m1_s_deferred]
    jmp  serial_string

pwr_m1_history_error: db "[PAOS64] power: M1 history failed; history writes disabled this boot [power.m1.history_failed]", 13, 10, 0
pwr_m1_verb_name:   db "SLEEP", 0
pwr_m1_busy:        db "SLEEP: refused - a job is running or a sleep is pending", 0
pwr_m1_r_accepted:  db " SLEEP accepted", 0
pwr_m1_r_locked:    db " SLEEP refused desktop_locked", 0
pwr_m1_r_owner:     db " SLEEP refused owner_only", 0
pwr_m1_r_busy:      db " SLEEP refused busy", 0
pwr_m1_s_accepted:  db "[PAOS64] power: SLEEP accepted - checkpoint + off [power.m1.accepted]", 13, 10, 0
pwr_m1_s_stored:    db "[PAOS64] power: checkpoint stored (TMP + PRIMARY verified) [power.m1.stored]", 13, 10, 0
pwr_m1_s_skipped:   db "[PAOS64] power: checkpoint skipped: ", 0
pwr_m1_s_off:       db "[PAOS64] power: Shut down (quiesce + S5) [power.m1.off]", 13, 10, 0
pwr_m1_s_restored:  db "[PAOS64] power: checkpoint restored after sign-in [power.m1.restored]", 13, 10, 0
pwr_m1_s_fresh:     db "[PAOS64] power: fresh session (no checkpoint restored): ", 0
pwr_m1_s_deferred:  db "[PAOS64] power: checkpoint restore deferred: no owner key [power.m1.deferred]", 13, 10, 0
pwr_m1_s_superseded: db "[PAOS64] power: checkpoint restore superseded: this session saved its own workspace [power.m1.superseded]", 13, 10, 0
%macro PWR_M1_TEXT 1                         ; one fixed 96-byte reason slot (no pointer tables)
%%s: db %1, 13, 10, 0
    times PWR_M1_TEXT_SLOT - ($ - %%s) db 0
%endmacro
PWR_M1_TEXT_SLOT equ 96
pwr_m1_reasons:
    PWR_M1_TEXT "none [power.m1.skipped]"
    PWR_M1_TEXT "owner key exposure pending (SEC-owner-key-in-push-record) [power.m1.skipped]"
    PWR_M1_TEXT "no owner session or no windows [power.m1.skipped]"
    PWR_M1_TEXT "no owner key [power.m1.skipped]"
    PWR_M1_TEXT "CSPRNG unavailable [power.m1.skipped]"
    PWR_M1_TEXT "insufficient variable space [power.m1.skipped]"
    PWR_M1_TEXT "write or verify failed [power.m1.skipped]"
    PWR_M1_TEXT "seal refused [power.m1.skipped]"
    PWR_M1_TEXT "no runtime NVRAM on this boot [power.m1.skipped]"
pwr_m1_fresh_reasons:
    PWR_M1_TEXT "none [power.m1.fresh]"
    PWR_M1_TEXT "no checkpoint [power.m1.fresh]"
    PWR_M1_TEXT "doubt (invalid, torn or disagreeing copies) [power.m1.fresh]"
    PWR_M1_TEXT "already attempted (high-water mark) [power.m1.fresh]"
    PWR_M1_TEXT "attempt mark could not be written [power.m1.fresh]"
    PWR_M1_TEXT "no runtime NVRAM on this boot [power.m1.fresh]"
    PWR_M1_TEXT "malformed payload [power.m1.fresh]"

pwr_remote_go:     db "[PAOS64] power.remote.shutdown executing (reply sent)", 13, 10, 0
pwr_remote_failed: db "[PAOS64] power.remote.shutdown failed: ", 0

; pwr_critical_tick(RBX = now ms) — RCQ-27 critical-charge action, root ruling
; 2026-10-08 06:30 (adopted; Peter can overrule with pwr_critical_action = 0, warn
; only). Critical (<= 7 %) on battery: warn (logged; the taskbar cell counts
; down "OFF 60s" .. "OFF 1s", and the lock screen shows the same countdown
; through lock_screen_notice); still critical on battery after
; PWR_CRITICAL_GRACE_MS -> the normal Shut down path (storage quiesce, ACPI S5).
; AC, charge back to >= 10 % (ec_power eases the warning to low) or an unknown
; EC reading cancels. Samples expire at 20 s; a refresh gap of 20 s also
; cancels an armed countdown. Recovery gets a new full grace. The EC is
; re-read cooperatively immediately before the Shut down. Pending work freezes
; the countdown display; only completed validated groups can resume or act. Without
; a calibrated TSC the action is warn only (the 60 s would be counted in idle
; wakes). If
; the Shut down does not happen (it returns), the next attempt is a full grace
; period later. Sets pwr_cell_check when the countdown shown changes.
PWR_CRITICAL_GRACE_MS equ 60000
pwr_critical_tick:
    sub  rsp, 8
    call ecp_freshness                      ; expire before warning/countdown even in warn-only mode
    add  rsp, 8
    cmp  byte [rel pwr_critical_action], 1
    jne  .out
    cmp  byte [rel pwr_untimed_said], 1
    je   .clear                              ; uncalibrated TSC: idle wakes are no clock, so warn only
    cmp  byte [rel ecp_bat_warn], 2
    jne  .clear
    cmp  byte [rel ecp_ac], 0
    jne  .clear
    cmp  byte [rel ecp_sample_state], 2
    je   .clear                             ; uncertain transport cannot authorize power
    cmp  byte [rel ecp_sample_state], 1
    je   .out                               ; freeze: pending bytes are not a new sample
    cmp  byte [rel pwr_crit_is_armed], 1
    je   .armed
    mov  byte [rel pwr_crit_is_armed], 1
    mov  [rel pwr_crit_since], rbx
    mov  rax, [rel ecp_bat_sample_ms]
    mov  [rel pwr_crit_sample_ms], rax
    lea  rdi, [rel pwr_crit_armed]
    call serial_string
.armed:
    ; A successful refresh after a missed cadence must not conceal a gap in
    ; fresh evidence and keep the old countdown alive. Re-arm a full grace on
    ; a later tick, even if the recovered sample is still critical.
    mov  rax, [rel ecp_bat_sample_ms]
    mov  rcx, rax
    sub  rax, [rel pwr_crit_sample_ms]
    jc   .clear
    cmp  rax, ECP_MAX_AGE_MS
    jae  .clear
    mov  [rel pwr_crit_sample_ms], rcx
    mov  rax, rbx
    sub  rax, [rel pwr_crit_since]
    jc   .clear                             ; a reversed policy clock is not an elapsed grace
    cmp  rax, PWR_CRITICAL_GRACE_MS
    jae  .go
    mov  ecx, PWR_CRITICAL_GRACE_MS + 999   ; seconds left, rounded up: 60 .. 1
    sub  ecx, eax
    mov  eax, ecx
    xor  edx, edx
    mov  ecx, 1000
    div  ecx
.show:
    cmp  al, [rel bat_crit_left_s]
    je   .out
    mov  [rel bat_crit_left_s], al
    mov  byte [rel pwr_cell_check], 1
    ret
.go:
    ; Final revalidation is itself cooperative. No synchronous battery refresh
    ; remains on the desktop rail. Partial/pending bytes cannot authorize off.
    cmp  byte [rel pwr_crit_verify], 1
    je   .verified
    mov  [rel pwr_crit_verify_ms], rbx
    mov  [rel pwr_last_ec_ms], rbx
    call ecp_sample_begin
    cmp  eax, 1
    je   .verify_pending
    cmp  eax, 2                            ; explicit completed producer
    jne  .clear
    mov  byte [rel pwr_crit_verify], 1
    jmp  .verified
.verify_pending:
    mov  byte [rel pwr_crit_verify], 1
    ret
.verified:
    cmp  byte [rel ecp_bat_warn], 2
    jne  .clear
    cmp  byte [rel ecp_ac], 0
    jne  .clear
    mov  byte [rel pwr_crit_verify], 0
    mov  rax, [rel ecp_bat_sample_ms]
    cmp  rax, [rel pwr_crit_verify_ms]
    jb   .clear                             ; only a sample started after this request qualifies
    mov  byte [rel pwr_cell_check], 1
    mov  [rel pwr_crit_since], rbx           ; a failed Shut down retries a grace period later
    lea  rdi, [rel pwr_crit_go]
    call serial_string
    mov  edi, PWR_M1_CRITICAL
    call pwr_m1_sleep_exec                   ; M1-3: checkpoint if possible, then the Shut down
    mov  rdi, rax
    jmp  serial_string
.clear:
    mov  byte [rel pwr_crit_verify], 0
    cmp  byte [rel pwr_crit_is_armed], 1
    jne  .out
    mov  byte [rel pwr_crit_is_armed], 0
    mov  byte [rel bat_crit_left_s], 0
    mov  byte [rel pwr_cell_check], 1
    lea  rdi, [rel pwr_crit_cancel]
    jmp  serial_string
.out:
    ret

pwr_crit_armed:  db "[PAOS64] power: battery critical on battery - Shut down in 60 s unless AC or >= 10 % [power.battery.critical_armed]", 13, 10, 0
pwr_crit_go:     db "[PAOS64] power: battery still critical - Shut down now [power.battery.critical_shutdown]", 13, 10, 0
pwr_crit_cancel: db "[PAOS64] power: battery critical shutdown cancelled (AC, charge or an unknown EC reading) [power.battery.critical_cancelled]", 13, 10, 0

align 8
pwr_crit_since:  dq 0
pwr_crit_verify_ms: dq 0                    ; final cooperative request start
pwr_crit_verify: db 0
align 8
pwr_crit_sample_ms: dq 0                    ; most recently observed qualified battery sample
pwr_lid_verify_id: dq 0                     ; current raw confirmation token, zero = none
pwr_lid_since:   dq 0                        ; grace start (re-based after a failed Shut down)
pwr_lid_closed_at: dq 0                      ; the close itself (the inhibitor cap)
pwr_critical_action: db 1                    ; POLICY SWITCH (root 06:30): 1 shut down after the grace, 0 warn only
pwr_crit_is_armed: db 0
pwr_lid_action:  db 1                        ; POLICY SWITCH (root 08:32 POWER-05): 1 lock + Shut down after the grace, 0 log only
pwr_lid_armed:   db 0
pwr_lid_deferred_said: db 0
pwr_lid_known:   db 0xFF                     ; last known lid state (1 open, 0 closed, 0xFF none)
pwr_m1_history_said: db 0                   ; first history failure reported once
pwr_m1_stored:   db 0                        ; a checkpoint was committed this boot
pwr_m1_pending:  db 0                        ; SLEEP accepted, runs on the next idle tick
pwr_m1_verb_done: db 0
pwr_m1_restore_done: db 0                    ; the sign-in restore step ran (once per boot)
pwr_m1_deferred: db 0                        ; a keyless sign-in deferred the restore ([power.m1.deferred] printed once)
align 4
pwr_m1_verb_id:  dd -1
pwr_cell_check:  db 0                        ; re-check the taskbar battery cell this tick
align 8
pwr_last_ec_ms:  dq 0
pwr_last_pm1_ms: dq 0
pwr_ticks:       dq 0
power_lid_changes: dd 0
power_bl_verb_id: dd -1
pwr_inited:      db 0
pwr_untimed_said: db 0
align 8
pwr_verb_backlight: db "BACKLIGHT", 0
pwr_bl_grammar:  db "BACKLIGHT [0..100]", 0
pwr_bl_unavailable: db "backlight unavailable or read-back mismatch", 0
pwr_bl_lid_dark: db "backlight held off by the lid (closed, or its restore waits for a valid PWM)", 0
pwr_s_lid:       db "[PAOS64] power: lid ", 0
pwr_s_lid_open:  db "open [power.lid]", 13, 10, 0
pwr_s_lid_closed: db "closed [power.lid]", 13, 10, 0
pwr_s_lid_unknown: db "state unknown (EC read; no action) [power.lid]", 13, 10, 0
pwr_s_lid_bl_off: db "[PAOS64] power: lid closed - backlight off (duty saved) [power.lid.backlight_off]", 13, 10, 0
pwr_s_lid_bl_off_refused: db "[PAOS64] power: lid closed - backlight blank refused (PWM unusable or read-back mismatch) [power.lid.backlight_off_refused]", 13, 10, 0
pwr_s_lid_bl_on: db "[PAOS64] power: lid opened - backlight restored to the pre-close duty [power.lid.backlight_on]", 13, 10, 0
pwr_s_lid_bl_on_refused: db "[PAOS64] power: lid opened - backlight restore deferred (PWM unusable or read-back mismatch; retried while open) [power.lid.backlight_on_refused]", 13, 10, 0
pwr_s_lid_bl_on_retry: db "[PAOS64] power: lid open - backlight restored on retry [power.lid.backlight_on_retry]", 13, 10, 0
pwr_s_lid_bl_gave_up: db "[PAOS64] power: lid open - backlight restore given up after 3 writes; left to firmware [power.lid.backlight_given_up]", 13, 10, 0
pwr_s_lid_locked: db "[PAOS64] power: lid closed - session locked [power.lid.locked]", 13, 10, 0
pwr_s_lid_armed: db "[PAOS64] power: lid closed - Shut down in 30 s unless the lid opens (a running job defers it, at most 15 min) [power.lid.armed]", 13, 10, 0
pwr_s_lid_cancel: db "[PAOS64] power: lid opened - Shut down cancelled; sign in to continue [power.lid.cancelled]", 13, 10, 0
pwr_s_lid_deferred: db "[PAOS64] power: lid closed - Shut down deferred while a job runs [power.lid.deferred]", 13, 10, 0
pwr_s_lid_capped: db "[PAOS64] power: lid closed 15 min with a job still running - thermal floor, Shut down anyway [power.lid.capped]", 13, 10, 0
pwr_s_lid_held:  db "[PAOS64] power: lid not read closed just before the Shut down (open or EC timeout) - held this round [power.lid.held]", 13, 10, 0
pwr_s_lid_go:    db "[PAOS64] power: lid still closed - Shut down now [power.lid.shutdown]", 13, 10, 0
pwr_s_shutdown:  db "[PAOS64] power: power button -> quiesced Shut down [power.button.shutdown]", 13, 10, 0
pwr_s_grace:     db "[PAOS64] power: power button routed - Shut down in 1 s [power.button.routed]", 13, 10, 0
pwr_s_returned:  db "[PAOS64] power: button shutdown returned: ", 0
pwr_s_logged:    db "[PAOS64] power: power button press logged, no action reason=", 0
pwr_s_tail:      db " [power.button.logged]", 13, 10, 0
pwr_s_untimed:   db "[PAOS64] power: no calibrated time base; power button polled by idle-tick count [power.button.untimed]", 13, 10, 0
pwr_why_cli:     db "headless", 0
pwr_why_locked:  db "locked", 0
pwr_why_nodesktop: db "no_desktop", 0
pwr_why_principal: db "not_owner", 0
pwr_why_trial:   db "trial_pending", 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_power_button_m1 0
alignb 16
pwr_m1_slot:  resb M1_SLOT_CAP               ; the sealed image (ciphertext only)
pwr_m1_plain: resb M1_PLAIN_CAP              ; the plaintext payload, wiped after every use
%endmacro
WDATA_BSS_DEFER WDATA_gui_power_button_m1

; Generic fixed-button policy shares the existing local-owner authority gate.
; The descriptor-specific fallback also requires established live SCI ownership.
pwr_fixed_button_tick:
    sub rsp, 8
    call power_button_ownership
    test eax, eax
    jnz .fallback
    call acpi_fixed_button_init
    test rax, rax
    jnz .abort
    call acpi_fixed_button_poll
    test rax, rax
    js .abort
    mov byte [rel pwr_fixed_button_owns_pm1], 1
    jz .out
    call pwr_button_pressed
    jmp .out
.abort:
    mov edi, 4
    call power_button_ownership_abort
.fallback:
    mov byte [rel pwr_fixed_button_owns_pm1], 0
.out:
    add rsp, 8
    ret
%macro WDATA_gui_fixed_button 0
pwr_fixed_button_owns_pm1: db 0
pwr_btn_grace_armed: db 0                  ; a routed press waits out its grace
align 8
pwr_btn_grace_at: dq 0                     ; boot ms of that press
%endmacro
WDATA_DEFER WDATA_gui_fixed_button
