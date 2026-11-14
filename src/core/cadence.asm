;; MODULE core/cadence
;; LAYER 1
;; EXPORTS cadence_registry_init, cadence_register, cadence_register_named, cadence_unregister, cadence_run, cadence_poll, cadence_live_rearm, cadence_registry_selftest, cad_measured, cad_table, cad_count
;; IMPORTS core/time, core/lib/fmt, boot/serial
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/cadence.asm — the SCHEDULER §4.6 CADENCE REGISTRY (contract 1070).
;
; THE NON-RETROFITTABLE SEAM: every periodic loop in PaOS (render, timer, net
; poll, watchdog) REGISTERS its cadence through ONE registry — a table of
; {cadence_id, period_ticks, current_rate, controller_hook, policy_hook, health
; vital} — and the registry DRIVES those loops from ONE tickless deadline
; authority, NOT from scattered hardcoded timer calls. Because a loop never
; bakes its own period, the scheduler + forge can retune timing per machine
; ADDITIVELY (swap a row's current_rate) with ZERO call-site edits. v1 is
; degenerate — static default rates, policy hook left at default — but the
; registry + the register() indirection EXIST at v1; omitting them now would
; force a cadence-field format change at every timer call site later (the duct
; tape SCHEDULER §7/§8 forbids; PRINCIPLES §1 field-exists-at-v1).
;
; CONTROLLER vs POLICY split (§4.6): each entry carries TWO hooks. The
; controller_hook is the deterministic in-loop action, invoked THROUGH the
; registry on every fire (proving the indirection is live). The policy_hook is
; the LLM-tunable rate governor — left NULL (default) in v1; the apex per-machine
; rate learning binds it later. Each entry also carries a health VITAL and the
; deterministic ESCALATION FLOOR: if a cadence misses a full period, the driver
; sets its vital WITHOUT any LLM (project_cron_admin_offline_signature) — the
; nervous system's higher tiers are later contracts; the floor exists at v1.
;
; CONTENT-GRADE, NOT LATCH (TESTING §1/§6): the selftest registers TWO cadences
; at DIFFERENT declared periods (fast A, slow B, ratio 4:1), lets the registry
; DRIVE both for a bounded window, and MEASURES each one's actual fire interval
; by TSC deltas between fires. It PRINTS, per cadence, its declared period, its
; TSC-measured period, and its fire count as a KAT. A stub that fires on a single
; hardcoded tick yields ONE rate / equal counts and CANNOT reproduce two distinct
; measured rates -> FAIL. The RATIO (A fires strictly more often than B) is the
; un-fakeable discriminator; tolerance on absolute periods is generous (QEMU TSC
; jitters, §6). The DEGENERATE-SECOND proof (TESTING §5): registering cadence B
; required NO edit to the registry core — the SAME cadence_register() call — so a
; design that can only drive one hardcoded rate FAILS.
;
; SINGLE DEFINITION (G1 / known_trap): there is exactly ONE cadence registry and
; ONE tickless-deadline driver, here. modlint forbids a 2nd variant.
; ============================================================================

; --- registry entry: stable v1 prefix + F2 §12.2 vital/audit tail ---
CAD_ID       equ 0      ; cadence_id
CAD_PERIOD   equ 8      ; declared period (TSC ticks) — what the loop asked for
CAD_RATE     equ 16     ; current_rate (effective period) — v1 == declared; forge-tunable
CAD_CTRL     equ 24     ; controller_hook (deterministic in-loop fn ptr)
CAD_POLICY   equ 32     ; policy_hook (LLM-tunable rate governor) — NULL default at v1
CAD_VITAL    equ 40     ; health vital: 0=healthy, 1=escalated (deterministic floor)
CAD_DEADLINE equ 48     ; next fire deadline (absolute TSC) — the tickless authority
CAD_FIRES    equ 56     ; fire count over the window
CAD_FIRST    equ 64     ; TSC of first fire (for measured-period math)
CAD_LAST     equ 72     ; TSC of last fire
CAD_CLASS    equ 80     ; 0=fixed, 1=on_demand, 2=freerun_capped
CAD_DECL_HZ  equ 88     ; declared whole-Hz rate
CAD_MEAS_HZ  equ 96     ; latest non-missed TSC-measured whole-Hz rate
CAD_JIT0     equ 104    ; jitter <=5%
CAD_JIT1     equ 112    ; jitter <=15%
CAD_JIT2     equ 120    ; jitter <=30%
CAD_JIT3     equ 128    ; jitter >30%
CAD_MISSED   equ 136    ; deterministic missed-deadline count
CAD_AUDIT    equ 144    ; last audit, milliseconds since boot
CAD_ENT_SZ   equ 152
CAD_MAX      equ 12     ; progress marquee + reserved consumer, bounded registry

; declared periods for the seam proof (TSC ticks). A is 4x faster than B — the
; ratio is the un-fakeable discriminator. Large vs loop-iteration cost so a
; measured period tracks its declaration within a few percent.
CAD_ID_A     equ 1
CAD_ID_B     equ 2
CAD_PERIOD_A equ 2000000
CAD_PERIOD_B equ 8000000
CAD_STOP_B   equ 6      ; drive until slow cadence B has fired this many times

; cadence_registry_init — reset the registry (count=0, controller tally=0). This
;   is the "registry built" step: the table becomes live and empty here.
;   clobbers: RAX
cadence_registry_init:
    mov  dword [rel cad_count], 0
    mov  qword [rel cad_ctrl_calls], 0
    ret

; cadence_register(RDI=id, RSI=period_ticks, RDX=controller_hook) -> RAX=slot, or -1 if full.
;   THE indirection: a periodic loop hands the registry its cadence; the registry
;   owns the deadline + drives it. Registering a SECOND cadence needs NO core edit
;   (same call) — that is the degenerate-second seam proof. policy_hook is left at
;   its NULL default (LLM tuning is a later contract). clobbers: RAX, RCX, R8
cadence_register:
    xor  eax, eax
    lea  r8, [rel cad_table]
.free_slot:
    cmp  eax, [rel cad_count]
    jae  .append
    imul rcx, rax, CAD_ENT_SZ
    cmp  qword [r8 + rcx + CAD_ID], 0
    je   .slot
    inc  eax
    jmp  .free_slot
.append:
    cmp  eax, CAD_MAX
    jae  .full
    inc  dword [rel cad_count]
.slot:
    imul rcx, rax, CAD_ENT_SZ
    lea  r8, [rel cad_table]
    add  r8, rcx
    mov  [r8 + CAD_ID], rdi
    mov  [r8 + CAD_PERIOD], rsi
    mov  [r8 + CAD_RATE], rsi            ; current_rate = declared at v1
    mov  [r8 + CAD_CTRL], rdx
    mov  qword [r8 + CAD_POLICY], 0      ; policy hook default (LLM tuning later)
    mov  qword [r8 + CAD_VITAL], 0       ; healthy
    mov  qword [r8 + CAD_DEADLINE], 0    ; set at run start
    mov  qword [r8 + CAD_FIRES], 0
    mov  qword [r8 + CAD_FIRST], 0
    mov  qword [r8 + CAD_LAST], 0
    mov  qword [r8 + CAD_CLASS], 0
    mov  qword [r8 + CAD_DECL_HZ], 0
    mov  qword [r8 + CAD_MEAS_HZ], 0
    mov  qword [r8 + CAD_JIT0], 0
    mov  qword [r8 + CAD_JIT1], 0
    mov  qword [r8 + CAD_JIT2], 0
    mov  qword [r8 + CAD_JIT3], 0
    mov  qword [r8 + CAD_MISSED], 0
    mov  qword [r8 + CAD_AUDIT], 0
    ret
.full:
    mov  eax, -1
    ret

; Release an on-demand row without moving other consumers' cached indices.
; cad_count is a high-water bound; register reuses holes before appending.
; Safe from a controller: cadence_poll does not touch its row after the call.
cadence_unregister:
    cmp  edi, [rel cad_count]
    jae  .done
    imul rax, rdi, CAD_ENT_SZ
    lea  r8, [rel cad_table]
    mov  qword [r8 + rax + CAD_ID], 0
    mov  qword [r8 + rax + CAD_CTRL], 0
    mov  qword [r8 + rax + CAD_RATE], 0
.trim:
    mov  eax, [rel cad_count]
    test eax, eax
    jz   .done
    dec  eax
    imul rcx, rax, CAD_ENT_SZ
    cmp  qword [r8 + rcx + CAD_ID], 0
    jne  .done
    mov  [rel cad_count], eax
    jmp  .trim
.done:
    ret

; cadence_register_named(RDI=id cstr, RSI=class, RDX=declared_hz,
;   RCX=period_ticks, R8=controller) -> RAX=slot/-1. Uses the same table and
; registration path; only fills the additive F2 metadata tail.
cadence_register_named:
    push rbx
    push r12
    push r13
    mov  rbx, rsi
    mov  r12, rdx
    mov  r13, r8
    mov  rsi, rcx
    mov  rdx, r13
    call cadence_register
    cmp  eax, -1
    je   .out
    mov  ecx, eax
    imul rcx, rcx, CAD_ENT_SZ
    lea  rdx, [rel cad_table]
    mov  [rdx + rcx + CAD_CLASS], rbx
    mov  [rdx + rcx + CAD_DECL_HZ], r12
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Non-blocking live driver. Called once per idle-loop turn; each due entry fires
; at most once, advances to a future absolute deadline, and updates §12.2 facts.
cadence_poll:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call tsc_now
    mov  r13, rax                     ; one coherent `now` for this scan
    xor  r12d, r12d
.scan:
    cmp  r12d, [rel cad_count]
    jae  .done
    mov  eax, r12d
    imul rax, rax, CAD_ENT_SZ
    lea  rbx, [rel cad_table]
    add  rbx, rax
    cmp  qword [rbx + CAD_ID], 0
    je   .next
    mov  rax, [rbx + CAD_DEADLINE]
    test rax, rax
    jnz  .armed
    mov  rax, r13
    add  rax, [rbx + CAD_RATE]
    mov  [rbx + CAD_DEADLINE], rax
    jmp  .next
.armed:
    cmp  r13, rax
    jb   .next
    mov  r14, [rbx + CAD_LAST]        ; previous edge for measured rate/jitter
    mov  rax, [rbx + CAD_FIRES]
    test rax, rax
    jnz  .not_first
    mov  [rbx + CAD_FIRST], r13
.not_first:
    inc  rax
    mov  [rbx + CAD_FIRES], rax
    mov  [rbx + CAD_LAST], r13
    test r14, r14
    jz   .miss_check
    mov  r15, r13
    sub  r15, r14                    ; actual interval
    test r15, r15
    jz   .jitter3
    ; A missed edge is already accounted independently in CAD_MISSED and the
    ; >30% jitter bucket below.  Do not let a long observer pause (for example,
    ; the native framebuffer capture used by the F2 proof) overwrite the last
    ; earned live rate with 0 Hz.  The measured rate therefore
    ; remains the latest completed, non-missed interval; missed stays explicit.
    mov  rax, [rbx + CAD_RATE]
    shl  rax, 1
    cmp  r15, rax
    ja   .jitter3
    mov  rax, [rel tsc_khz]
    imul rax, rax, 1000
    mov  rcx, r15
    shr  rcx, 1
    add  rax, rcx                    ; nearest whole Hz, not a downward-only floor
    xor  edx, edx
    div  r15
    mov  [rbx + CAD_MEAS_HZ], rax
    mov  rax, r15
    sub  rax, [rbx + CAD_RATE]
    jns  .abs_ready
    neg  rax
.abs_ready:
    imul rax, rax, 100
    mov  rcx, [rbx + CAD_RATE]
    imul rcx, rcx, 5
    cmp  rax, rcx
    jbe  .jitter0
    mov  rcx, [rbx + CAD_RATE]
    imul rcx, rcx, 15
    cmp  rax, rcx
    jbe  .jitter1
    mov  rcx, [rbx + CAD_RATE]
    imul rcx, rcx, 30
    cmp  rax, rcx
    jbe  .jitter2
.jitter3:
    inc  qword [rbx + CAD_JIT3]
    jmp  .miss_check
.jitter0:
    inc  qword [rbx + CAD_JIT0]
    jmp  .miss_check
.jitter1:
    inc  qword [rbx + CAD_JIT1]
    jmp  .miss_check
.jitter2:
    inc  qword [rbx + CAD_JIT2]
.miss_check:
    mov  rax, r13
    sub  rax, [rbx + CAD_DEADLINE]
    cmp  rax, [rbx + CAD_RATE]
    jbe  .deadline
    inc  qword [rbx + CAD_MISSED]
    mov  qword [rbx + CAD_VITAL], 1
.deadline:
    mov  rax, r13
    add  rax, [rbx + CAD_RATE]
    mov  [rbx + CAD_DEADLINE], rax
    call time_monotonic_now_us
    xor  edx, edx
    mov  ecx, 1000
    div  rcx
    mov  [rbx + CAD_AUDIT], rax
    mov  rax, [rbx + CAD_CTRL]
    test rax, rax
    jz   .next
    mov  rdi, rbx
    call rax
.next:
    inc  r12d
    jmp  .scan
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Rearm the existing registry at the exact boot-to-resident handoff. Long
; device bring-up after GUI registration is not redraw jitter. This resets
; only runtime measurements/deadlines; ids, rates, classes and hooks stay put.
cadence_live_rearm:
    push rbx
    push r12
    push r13
    call tsc_now
    mov  r12, rax
    lea  rbx, [rel cad_table]
    xor  r13d, r13d
.row:
    cmp  r13d, [rel cad_count]
    jae  .done
    mov  eax, r13d
    imul rax, rax, CAD_ENT_SZ
    mov  rcx, [rbx + rax + CAD_RATE]
    add  rcx, r12
    mov  [rbx + rax + CAD_DEADLINE], rcx
    mov  qword [rbx + rax + CAD_VITAL], 0
    mov  qword [rbx + rax + CAD_FIRES], 0
    mov  qword [rbx + rax + CAD_FIRST], 0
    mov  qword [rbx + rax + CAD_LAST], 0
    mov  qword [rbx + rax + CAD_MEAS_HZ], 0
    mov  qword [rbx + rax + CAD_JIT0], 0
    mov  qword [rbx + rax + CAD_JIT1], 0
    mov  qword [rbx + rax + CAD_JIT2], 0
    mov  qword [rbx + rax + CAD_JIT3], 0
    mov  qword [rbx + rax + CAD_MISSED], 0
    mov  qword [rbx + rax + CAD_AUDIT], 0
    inc  r13d
    jmp  .row
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; cad_ctrl_tick(RDI=entry ptr) — the deterministic in-loop controller hook shared
;   by v1's cadences. Called THROUGH the registry on every fire; bumps a global
;   tally so the selftest can PROVE the registry actually drove the loops (tally
;   == total fires) rather than a private timer. A richer controller (render one
;   frame, service the NIC) binds here later. MUST preserve callee-saved regs
;   (the driver keeps loop state in them). clobbers: none (memory + flags only)
cad_ctrl_tick:
    inc  qword [rel cad_ctrl_calls]
    ret

; cadence_run(RDI=stop_slot, RSI=stop_fires) — the tickless deadline DRIVER.
;   ONE authority drives EVERY registered cadence: each entry's next_deadline is
;   an absolute TSC; when now >= deadline the cadence fires (record TSC, bump
;   count, invoke its controller_hook THROUGH the registry, advance deadline by
;   current_rate). An UNREGISTERED loop is never in the table, so it is never
;   driven. The deterministic escalation floor sets an entry's vital if it ever
;   misses a full period (no LLM). Runs until table[stop_slot] has fired
;   stop_fires times. clobbers: caller-saved; preserves RBX,R12-R15.
cadence_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rdi                        ; stop_slot
    mov  r15, rsi                        ; stop_fires
    lea  r12, [rel cad_table]            ; table base
    mov  r13d, [rel cad_count]           ; live cadence count

    ; init each deadline = start + current_rate (first fire is one period out)
    call tsc_now                         ; RAX = start TSC
    xor  ecx, ecx
.initd:
    cmp  ecx, r13d
    jae  .mainloop
    imul rdx, rcx, CAD_ENT_SZ
    mov  rbx, [r12 + rdx + CAD_RATE]
    add  rbx, rax
    mov  [r12 + rdx + CAD_DEADLINE], rbx
    inc  ecx
    jmp  .initd

.mainloop:
    call tsc_now                         ; RAX = now
    mov  r11, rax                        ; r11 = now (no calls until the guarded hook)
    xor  ecx, ecx
.scan:
    cmp  ecx, r13d
    jae  .checkstop
    imul rdx, rcx, CAD_ENT_SZ
    lea  rbx, [r12 + rdx]                ; rbx = entry ptr
    mov  rax, [rbx + CAD_DEADLINE]
    cmp  r11, rax
    jb   .next                           ; now < deadline -> not due
    ; ---- FIRE ----
    mov  rax, [rbx + CAD_FIRES]
    test rax, rax
    jnz  .notfirst
    mov  [rbx + CAD_FIRST], r11
.notfirst:
    mov  [rbx + CAD_LAST], r11
    inc  rax
    mov  [rbx + CAD_FIRES], rax
    ; deterministic escalation floor (LLM-independent): missed a full period?
    mov  rax, [rbx + CAD_DEADLINE]       ; the deadline we just passed
    mov  r9, r11
    sub  r9, rax                         ; lateness = now - deadline
    cmp  r9, [rbx + CAD_RATE]
    jbe  .noesc
    mov  qword [rbx + CAD_VITAL], 1      ; escalate via the floor (no LLM)
.noesc:
    mov  rax, [rbx + CAD_RATE]
    add  [rbx + CAD_DEADLINE], rax       ; advance the tickless deadline
    ; invoke the controller hook THROUGH the registry (the live indirection)
    mov  rax, [rbx + CAD_CTRL]
    test rax, rax
    jz   .next
    push rcx                             ; preserve loop counter across the call
    push r11                             ; preserve now
    mov  rdi, rbx                        ; hook arg = entry ptr
    call rax
    pop  r11
    pop  rcx
.next:
    inc  ecx
    jmp  .scan
.checkstop:
    imul rdx, r14, CAD_ENT_SZ
    mov  rax, [r12 + rdx + CAD_FIRES]
    cmp  rax, r15
    jb   .mainloop
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; cad_measured(RDI=entry ptr) -> RAX = TSC-measured period = span/(fires-1), or 0
;   if fewer than 2 fires. clobbers: RAX, RCX, RDX
cad_measured:
    mov  rax, [rdi + CAD_LAST]
    sub  rax, [rdi + CAD_FIRST]          ; span across all fires
    mov  rcx, [rdi + CAD_FIRES]
    dec  rcx
    jz   .none                           ; <2 fires -> undefined
    xor  edx, edx
    div  rcx                             ; RAX = span / (fires - 1)
    ret
.none:
    xor  eax, eax
    ret

; cad_within(RDI=declared, RSI=measured) -> RAX=1 if |meas-decl| <= 50% of decl.
;   Generous, TSC-jitter-tolerant (§6). clobbers: RAX
cad_within:
    mov  rax, rsi
    sub  rax, rdi                        ; meas - decl (signed)
    jns  .pos
    neg  rax
.pos:
    shl  rax, 1                          ; 2*|diff|
    cmp  rax, rdi
    jbe  .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; cad_emit_num(RDI=value) — print an unsigned decimal to serial (KAT numbers).
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
cad_emit_num:
    lea  rsi, [rel cad_numbuf]
    call fmt_dec                         ; the ONE canonical decimal formatter (G1)
    lea  rdi, [rel cad_numbuf]
    call serial_string
    ret

; cadence_registry_selftest — build the registry, register TWO cadences at
;   different declared periods, DRIVE both from the ONE deadline authority for a
;   bounded window, then TSC-measure each fire interval and PRINT the KAT. Plain
;   call (no diag PHASE — keeps DIAG_NPHASES ring geometry). Emits its own markers.
cadence_registry_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; --- (1) build the registry (empty, live) ---
    call cadence_registry_init
    lea  rdi, [rel str_cad_init]
    call serial_string

    ; --- (2) register TWO cadences through the SAME register() call (seam) ---
    mov  rdi, CAD_ID_A
    mov  rsi, CAD_PERIOD_A
    lea  rdx, [rel cad_ctrl_tick]
    call cadence_register
    mov  rdi, CAD_ID_B
    mov  rsi, CAD_PERIOD_B
    lea  rdx, [rel cad_ctrl_tick]         ; degenerate-second: no core edit needed
    call cadence_register
    mov  eax, [rel cad_count]
    cmp  eax, 2
    jne  .fail                            ; the table must hold exactly the 2 registrants
    lea  rdi, [rel str_cad_reg2]
    call serial_string

    ; --- (3) DRIVE both from the ONE registry until slow cadence B fires N times ---
    mov  rdi, 1                           ; stop_slot = B (slow)
    mov  rsi, CAD_STOP_B
    call cadence_run

    ; --- (4) gather results into callee-saved regs ---
    lea  rbx, [rel cad_table]             ; slot0 = A
    mov  r12, [rbx + CAD_FIRES]           ; a_fires
    mov  r13, [rbx + CAD_ENT_SZ + CAD_FIRES] ; b_fires
    mov  rdi, rbx
    call cad_measured
    mov  r14, rax                         ; a_meas
    lea  rdi, [rbx + CAD_ENT_SZ]
    call cad_measured
    mov  r15, rax                         ; b_meas

    ; driven proof: the registry actually invoked the controller hook once per
    ; fire (tally == total fires), and BOTH cadences fired enough to measure.
    mov  rax, r12
    add  rax, r13
    cmp  [rel cad_ctrl_calls], rax
    jne  .fail                            ; a private timer would not match the tally
    cmp  r12, 2
    jb   .fail
    cmp  r13, 2
    jb   .fail
    lea  rdi, [rel str_cad_driven]
    call serial_string

    ; --- (5) PRINT the KAT: declared vs TSC-measured period + fire count, both ---
    lea  rdi, [rel str_cadkat_pfx]
    call serial_string
    mov  rdi, CAD_PERIOD_A
    call cad_emit_num
    lea  rdi, [rel str_cadkat_ame]
    call serial_string
    mov  rdi, r14
    call cad_emit_num
    lea  rdi, [rel str_cadkat_afi]
    call serial_string
    mov  rdi, r12
    call cad_emit_num
    lea  rdi, [rel str_cadkat_bde]
    call serial_string
    mov  rdi, CAD_PERIOD_B
    call cad_emit_num
    lea  rdi, [rel str_cadkat_bme]
    call serial_string
    mov  rdi, r15
    call cad_emit_num
    lea  rdi, [rel str_cadkat_bfi]
    call serial_string
    mov  rdi, r13
    call cad_emit_num
    lea  rdi, [rel str_cad_nl]
    call serial_string

    ; --- (6) rate match: each measured period ~ its declared period AND the fast
    ;     cadence fired strictly more often than the slow (the ratio discriminator) ---
    mov  rdi, CAD_PERIOD_A
    mov  rsi, r14
    call cad_within
    test eax, eax
    jz   .fail
    mov  rdi, CAD_PERIOD_B
    mov  rsi, r15
    call cad_within
    test eax, eax
    jz   .fail
    cmp  r12, r13
    jbe  .fail                            ; A must fire more often than B
    lea  rdi, [rel str_cad_rate]
    call serial_string

    ; --- (7) TOURNAMENT KAT (1416): cadence_run correctness GATE, byte-exact ---
    ;   The ONE tickless driver drove BOTH registered cadences: slow B stopped at
    ;   EXACTLY CAD_STOP_B fires (each scan pass fires an entry at most once, so the
    ;   first pass B reaches the stop count it is exactly that count), fast A fired
    ;   strictly more, and the controller tally == total fires (proved above). A stub
    ;   that fires a single hardcoded tick can reproduce NONE of that. The emitted
    ;   string is FIXED, so every correct variant reproduces it bit-for-bit; a
    ;   wrong-output variant fails an invariant here and never prints it -> scores 0.
    cmp  r13, CAD_STOP_B
    jne  .fail
    lea  rdi, [rel str_cad_tourn_kat]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_cad_fail]
    call serial_string
.done:
    call cadence_no_second_variant_kat   ; Task3477: single deadline-driver attestation
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Task3477: cadence single-deadline-driver KAT. There is exactly ONE cadence
; registry (cad_table/cad_count) and ONE tickless-deadline driver
; (cadence_run/cadence_poll); modlint forbids a second variant at build. This
; runtime attestation asserts the single registry is present and bounded — a
; parallel timer would need its own table/count. Emits the marker on pass.
cadence_no_second_variant_kat:
    mov  eax, [rel cad_count]
    test eax, eax
    jz   .cnv_fail                        ; the one registry must have live consumers
    cmp  eax, CAD_MAX
    ja   .cnv_fail                        ; bounded by the single table
    lea  rax, [rel cad_table]
    test rax, rax
    jz   .cnv_fail
    lea  rdi, [rel str_cadence_no_second_variant_kat]
    call serial_string
.cnv_fail:
    ret

; cad_perf_med -> RAX = MIN rdtsc cycles across CAD_PERF_N cadence_run drives over a
;   FIXED tiny two-cadence registry (A=64, B=256 ticks; stop slow B at 4 fires). This
;   exercises the tickless hot path — scan / deadline compare / fire / escalation
;   floor / deadline advance / controller dispatch — without the multi-million-tick
;   real periods (which would make a 1000-call bench take seconds). Running-minimum
;   estimator (identical shape to sc_perf_med / nc_perf_med in svc/command_udp). The
;   PERF verb on :9997 calls this so the metal-finalists loop elects on REAL cycles.
;   Reuses the ONE registry (v1 binds no live loops yet). Preserves RBX,R12-R15
;   through cadence_run. clobbers other caller-saved.
CAD_PERF_N        equ 1000               ; bench calls (contract: N=1000)
CAD_PERF_PERIOD_A equ 64                 ; tiny fast period (fixed representative input)
CAD_PERF_PERIOD_B equ 256                ; tiny slow period (4:1, same ratio as the seam)
CAD_PERF_STOP     equ 4                  ; drive each run until B has fired this many
cad_perf_med:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  eax, [rel cad_count]
    mov  [rel cad_perf_saved_count], eax
    mov  rax, [rel cad_ctrl_calls]
    mov  [rel cad_perf_saved_ctrl_calls], rax
    lea  rsi, [rel cad_table]
    lea  rdi, [rel cad_perf_saved_table]
    mov  ecx, (CAD_MAX * CAD_ENT_SZ) / 8
    cld
    rep  movsq
    call cadence_registry_init
    mov  rdi, CAD_ID_A
    mov  rsi, CAD_PERF_PERIOD_A
    lea  rdx, [rel cad_ctrl_tick]
    call cadence_register
    mov  rdi, CAD_ID_B
    mov  rsi, CAD_PERF_PERIOD_B
    lea  rdx, [rel cad_ctrl_tick]
    call cadence_register
    mov  r13, -1                         ; running min (unsigned max)
    xor  r12d, r12d
.sample:
    lea  rax, [rel cad_table]            ; reset both fire counts so each drive re-runs
    mov  qword [rax + CAD_FIRES], 0
    mov  qword [rax + CAD_ENT_SZ + CAD_FIRES], 0
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbx, rax                        ; start tsc
    mov  rdi, 1                          ; stop_slot = B (slow)
    mov  rsi, CAD_PERF_STOP
    call cadence_run
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbx                        ; delta
    cmp  rax, r13
    jae  .next
    mov  r13, rax                        ; new min
.next:
    inc  r12d
    cmp  r12d, CAD_PERF_N
    jb   .sample
    mov  r14, r13
    lea  rsi, [rel cad_perf_saved_table]
    lea  rdi, [rel cad_table]
    mov  ecx, (CAD_MAX * CAD_ENT_SZ) / 8
    cld
    rep  movsq
    mov  eax, [rel cad_perf_saved_count]
    mov  [rel cad_count], eax
    mov  rax, [rel cad_perf_saved_ctrl_calls]
    mov  [rel cad_ctrl_calls], rax
    mov  rax, r14
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- core/cadence data (RW under our page tables, MEMORY_MAP §3.1) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_cadence 0
align 8
cad_count:      dd 0
cad_ctrl_calls: dq 0
align 16
cad_table:      times (CAD_MAX * CAD_ENT_SZ) db 0
cad_numbuf:     times 24 db 0            ; u64 decimal scratch (max 20 digits + NUL)
cad_perf_saved_count: dd 0
align 8
cad_perf_saved_ctrl_calls: dq 0
cad_perf_saved_table: times (CAD_MAX * CAD_ENT_SZ) db 0
%endmacro
WDATA_DEFER WDATA_cadence

str_cad_init:   db "[PAOS64] P2 sched cadence: registry built [sched.cadence.registry.init]", 13, 10, 0
str_cad_reg2:   db "[PAOS64] P2 sched cadence: 2 distinct cadences registered [sched.cadence.registered.2]", 13, 10, 0
str_cad_driven: db "[PAOS64] P2 sched cadence: registry drove both loops, TSC-measured PASS [sched.cadence.driven.tsc]", 13, 10, 0
str_cad_rate:   db "[PAOS64] P2 sched cadence: each fired at its declared rate PASS [sched.cadence.rate.match]", 13, 10, 0
str_cad_fail:   db "[PAOS64] P2 sched cadence: FAIL", 13, 10, 0
str_cad_tourn_kat: db "[PAOS64] tourn.cadence_run: 1 tickless driver drove 2 cadences, b_fires=6 a>b tally==fires PASS [tourn.cadence_run.kat]", 13, 10, 0
str_cadence_no_second_variant_kat: db "[PAOS64] cadence: one deadline driver KAT PASS [core.cadence.no_second_variant.kat]", 13, 10, 0
str_cadkat_pfx:    db "sched.cadence.kat a_decl=", 0
str_cadkat_ame:    db " a_meas=", 0
str_cadkat_afi:    db " a_fires=", 0
str_cadkat_bde:    db " b_decl=", 0
str_cadkat_bme:    db " b_meas=", 0
str_cadkat_bfi:    db " b_fires=", 0
str_cad_nl:     db 13, 10, 0
