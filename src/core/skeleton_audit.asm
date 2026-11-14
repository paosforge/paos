;; MODULE core/skeleton_audit
;; LAYER 1
;; EXPORTS skeleton_walks_audit, seam_audit_observe
;; IMPORTS boot/serial, core/lib/str
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/skeleton_audit.asm — C22 capstone (1072): "the skeleton walks" audit.
;
; A boot-LATE, READ-ONLY aggregation pass. It does NOT re-run any seam. It
; OBSERVES the marker each foundation seam already emits this boot — via a single
; call hook in boot/serial.asm:serial_string (seam_audit_observe) that matches
; every emitted string against the required-seam needle table — and, at the end
; of boot, PRINTS a per-seam PASS/FAIL scorecard the probe re-derives row-by-row.
; The summary marker skeleton.walks.audit fires ONLY when every required seam row
; is PASS; a missing seam prints FAIL and WITHHOLDS the summary (audit-as-gate,
; TESTING §4/§5). Read-only: it never perturbs a seam's behaviour.
;
; SINGLE SOURCE for the required-seam list: gauntlet_v2/probes/probe_skeleton_
; walks_audit.sh REQUIRED_SEAMS. Keep the two in lockstep — if a seam marker
; string drifts, update the needle here AND the probe. Each needle is the seam's
; own bracketed marker tag (the exact substring that appears in serial when the
; seam runs) EXCEPT p2_core_ok, whose serial proxy is the "P2 core ok" line.
;
; RELOCATION NOTE: needles and names are laid out as CONTIGUOUS null-terminated
; string BLOBS and addressed by walking N terminators from a `lea [rel base]`
; anchor (seam_nth). This deliberately avoids a `dq <symbol>` pointer table —
; PaOS's PE32+ ImageBase is NOT applied to baked-in dq references, so such a
; table would dereference to org-0 (BIOS) garbage (the documented dq-symbol VA
; trap). lea-relative addressing yields the true runtime VA.
;
; HONEST-STATE NOTE (2026-07-09): at authoring, only 7 of the 23 required seams
; actually fire this boot. The other 16 foundation seams are NOT yet composed
; into the boot — pci/hal/cap(irq)/blockdev/vfs/stack/smp are not %included
; and/or their selftest is never called in boot/header.asm, and 3 required
; markers (core.smp.class.registered, core.smp.selftest.spread,
; core.lib.modlint.ok) are emitted by NO module at all. So this audit correctly
; prints those as FAIL and withholds skeleton.walks.audit. Wiring/finishing those
; seams is each seam contract's job (tracked in the iter's NEEDS_ note). This
; module is the correct SCANNER; it greens automatically as the ladder completes.
; ============================================================================

N_SEAMS equ 23

; ---- seam_nth(RDI = blob base, RSI = index) -> RAX = ptr to the index-th
;      null-terminated string in the blob. Relocation-safe (base is a [rel ..]
;      anchor). clobbers RAX; reads RDI/RSI. ----
seam_nth:
    mov  rax, rdi
.outer:
    test rsi, rsi
    jz   .done
.scan:
    cmp  byte [rax], 0
    je   .term
    inc  rax
    jmp  .scan
.term:
    inc  rax                            ; step past the terminator
    dec  rsi
    jmp  .outer
.done:
    ret

; ---- seam_audit_observe(RDI = null-terminated string about to be printed) ----
;   For each still-unset seam latch, if the string contains that seam's needle,
;   set the latch. Read-only w.r.t. every seam; preserves ALL registers so the
;   serial_string hook is fully transparent. Does NOT call serial_string (no
;   recursion). The audit's own scorecard rows print the seam NAME without
;   brackets, so they never match a bracketed needle (no self-latching).
seam_audit_observe:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12
    push r14
    mov  r14, rdi                       ; r14 = haystack (survives seam_nth/str_find)
    xor  r12, r12                       ; r12 = seam index
.loop:
    cmp  r12, N_SEAMS
    jae  .done
    lea  rbx, [rel seam_latch]
    cmp  byte [rbx + r12], 0
    jne  .next                          ; already latched -> skip work
    lea  rdi, [rel seam_needles]        ; needle = seam_nth(needles, index)
    mov  rsi, r12
    call seam_nth
    mov  rsi, rax                       ; needle ptr
    mov  rdi, r14                       ; haystack (str_find slides rdi)
    call str_find                       ; -> rax; clobbers rax,rcx,rbx
    test rax, rax
    jz   .next
    lea  rbx, [rel seam_latch]
    mov  byte [rbx + r12], 1            ; seam observed this boot
.next:
    inc  r12
    jmp  .loop
.done:
    pop  r14
    pop  r12
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ---- skeleton_walks_audit — the boot-late scorecard ----
;   Prints one "[PAOS64] P8 audit.row <seam> PASS|FAIL" line per required seam
;   (the probe re-derives the table from these), then the table marker, then —
;   only when zero rows FAIL — the summary marker skeleton.walks.audit. Degrades
;   gracefully: a missing seam is a FAIL row, never a crash.
;   clobbers: caller-saved (rbx,r12,r15 saved).
skeleton_walks_audit:
    push rbx
    push r12
    push r15
    mov  r15d, 1                        ; all_pass (1 until a FAIL is printed)
    xor  r12, r12                       ; seam index
.row_loop:
    cmp  r12, N_SEAMS
    jae  .rows_done
    lea  rdi, [rel str_audit_row_pfx]   ; "[PAOS64] P8 audit.row "
    call serial_string
    lea  rdi, [rel seam_names]          ; name = seam_nth(names, index)
    mov  rsi, r12
    call seam_nth
    mov  rdi, rax
    call serial_string
    lea  rdi, [rel str_space]
    call serial_string
    lea  rbx, [rel seam_latch]
    cmp  byte [rbx + r12], 0
    je   .fail
    lea  rdi, [rel str_pass]
    call serial_string
    jmp  .eol
.fail:
    xor  r15d, r15d                     ; all_pass = 0
    lea  rdi, [rel str_fail]
    call serial_string
.eol:
    call serial_newline
    inc  r12
    jmp  .row_loop
.rows_done:
    lea  rdi, [rel str_audit_table]     ; scorecard printed (always)
    call serial_string
    test r15d, r15d
    jz   .withheld
    lea  rdi, [rel str_audit_summary]   ; every row PASS -> the skeleton walks
    call serial_string
    jmp  .out
.withheld:
    lea  rdi, [rel str_audit_withheld]  ; note: contains NO bracketed tag
    call serial_string
.out:
    pop  r15
    pop  r12
    pop  rbx
    ret

; ---- data: required-seam needle + name BLOBS (index-parallel, lockstep w/ probe).
;      Order MUST match between the two blobs and the probe's REQUIRED_SEAMS. ----

; needles — the exact substring that appears in serial when the seam runs.
; (p2_core_ok's serial proxy is the "P2 core ok" first-light-of-core line.)
seam_needles:
    db "P2 core ok", 0
    db "[core.fmt.kat]", 0
    db "[diag.ring.preserved]", 0
    db "[fault.dump.captured]", 0
    db "[core.smp.class.registered]", 0
    db "[core.smp.selftest.spread]", 0
    db "[core.lib.modlint.ok]", 0
    db "[pci.scan.complete]", 0
    db "[hal.init]", 0
    db "[cap.mmio.enforced]", 0
    db "[cap.violation.blocked]", 0
    db "[blockdev.class.seam.init]", 0
    db "[blockdev.reinit.verify]", 0
    db "[vfs.readback.match]", 0
    db "[netdev.table.init]", 0
    db "[netdev.loopnet.registered]", 0
    db "[netdev.affinity.field]", 0
    db "[framework.dispatch]", 0
    db "[arp.stack]", 0
    db "[mem.layout.reloc.integrity]", 0
    db "[sched.cadence.rate.match]", 0
    db "[sched.host.heartbeat.continuous]", 0
    db "[sched.vcpu.starve.negative_gate]", 0

; names — printed in the scorecard row; MUST match the probe's REQUIRED_SEAMS.
seam_names:
    db "p2_core_ok", 0
    db "core.fmt.kat", 0
    db "diag.ring.preserved", 0
    db "fault.dump.captured", 0
    db "core.smp.class.registered", 0
    db "core.smp.selftest.spread", 0
    db "core.lib.modlint.ok", 0
    db "pci.scan.complete", 0
    db "hal.init", 0
    db "cap.mmio.enforced", 0
    db "cap.violation.blocked", 0
    db "blockdev.class.seam.init", 0
    db "blockdev.reinit.verify", 0
    db "vfs.readback.match", 0
    db "netdev.table.init", 0
    db "netdev.loopnet.registered", 0
    db "netdev.affinity.field", 0
    db "framework.dispatch", 0
    db "arp.stack", 0
    db "mem.layout.reloc.integrity", 0
    db "sched.cadence.rate.match", 0
    db "sched.host.heartbeat.continuous", 0
    db "sched.vcpu.starve.negative_gate", 0

seam_latch: times N_SEAMS db 0

str_audit_row_pfx: db "[PAOS64] P8 audit.row ", 0
str_space:         db " ", 0
str_pass:          db "PASS", 0
str_fail:          db "FAIL", 0
str_audit_table:   db "[PAOS64] P8 audit: per-seam PASS/FAIL scorecard printed [skeleton.walks.audit.table]", 13, 10, 0
str_audit_summary: db "[PAOS64] P8 audit: ALL foundation seams + 2nd/degenerate proofs GREEN [skeleton.walks.audit]", 13, 10, 0
str_audit_withheld:db "[PAOS64] P8 audit: summary WITHHELD - one or more required foundation seams FAIL (see scorecard rows)", 13, 10, 0
