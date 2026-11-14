;; MODULE boot/early_trap
;; LAYER 0
;; EXPORTS early_trap_install, early_trap_verify, early_trap_uninstall, et_installed, et_m_armed, et_m_fault, et_fault_vec, et_fault_rip, et_fault_err
;; IMPORTS boot/serial, boot/header, core/reset_wipe
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/early_trap.asm — 1273a: the PRE-EBS FAULT TRAP.
;
; WHY THIS EXISTS (measured 2026-08-06/07)
; ----------------------------------------
; On 2026-08-06 a bad PaOS build #GP'd inside gop_query — BEFORE
; ExitBootServices. The fault was delivered on the FIRMWARE's IDT (CS=0x0038,
; firmware IDTR/CR3, RIP in the DXE range), where EDK2's exception handler ends
; in CpuDeadLoop(). The box sat dark forever; only a human pressing F12 got it
; back. The reason is pure ORDERING — every PaOS recovery mechanism arms after
; the window it is supposed to protect:
;
;     chainload_escalate_check   reads the CMOS ladder, never increments it
;     gop_query                  <-- THE FAULT HAPPENS HERE (pre-EBS)
;     exit_boot_and_page         ExitBootServices
;     idt_init                   PaOS's own IDT exists only now
;     boot_ab_early              the ONLY trial-counter increment
;     fault_warmreset_arm        CF9 warm reset armed only now
;
; core/idt.asm's demote+CF9 ladder is CORRECT and proven. It simply never runs,
; because the fault never reaches it. This module makes it reachable.
;
; WHY NOT THE PCH WATCHDOG (the original keystone — REFUTED ON HARDWARE)
; ----------------------------------------------------------------------
; The intended fix was to arm the Intel PCH TCO watchdog early. Measured four
; ways on the M720s twin 2026-08-07, that is impossible on this board:
;   * /dev/watchdog, 35 s timeout, never kicked  -> no reset in 130 s
;   * manual arm (TMR_HLT=0, NO_REBOOT clear)    -> TCO_RLD frozen, never counts
;   * MSR_SMI_COUNT (0x34) while armed           -> ZERO SMIs (so not an SMM kick)
;   * TCO1_CNT reads 0x1000                      -> TCO_LOCK SET by firmware
;   * full Lenovo think-lmi attribute enumeration -> NO watchdog/WDT option
; The countdown clock is gated and locked with no exposed toggle. Evidence:
; gauntlet_v2/artifacts/1014b_tco_livefire_refutation_20260807/.
;
; That refutation is what makes this module the right answer instead: the
; 2026-08-06 failure was a FAULT, not a hang, and a fault only reaches
; CpuDeadLoop because it lands on the firmware's IDT. Take the fault instead.
; Pure software, zero chipset dependency, works on the AMD HP too.
;
; HOOK, DO NOT REPLACE
; --------------------
; We deliberately do NOT `lidt` our own table here. Boot services are still live
; and the firmware needs its own timer/IRQ gates to service the very calls we
; still have to make (GOP, LoadImage, GetMemoryMap). Swapping IDTR wholesale
; pre-EBS risks breaking those. Instead `sidt` the firmware's IDTR and overwrite
; ONLY the four fault gates, reusing each gate's EXISTING selector, IST and type
; byte — so we inherit a CS and a stack the firmware has already proven good.
; UEFI guarantees identity mapping while boot services are up, so the handler's
; link-time VA is valid under the firmware's CR3.
;
; This is the standard bootloader/hypervisor idiom, and it is deliberately the
; SMALLEST change that turns "dark forever, needs F12" into "self-recovers".
;
; NOT resumable: a pre-EBS fault has no safe continuation, so the handler always
; ends in a reset. That is the point — sitting still IS the bug being fixed.
; ============================================================================

; ---- the four hooked vectors, as 16-byte-stride stubs ----------------------
; Same fixed-stride trick core/idt.asm uses, for the same reason: the gate
; offsets are computed with a RIP-relative lea at RUNTIME, never an absolute
; `dq <symbol>` (which would store ORG-0 offsets, wrong at ImageBase —
; MODULES.md §3.2, the hazard this tree has been bitten by before).
align 16
et_stub_base:
et_stub_ud:                             ; #UD (6) — no CPU error code
    push 0
    push 6
    jmp  et_isr_common
align 16
et_stub_df:                             ; #DF (8) — CPU pushes an error code
    push 8
    jmp  et_isr_common
align 16
et_stub_gp:                             ; #GP (13) — THE 2026-08-06 vector
    push 13
    jmp  et_isr_common
align 16
et_stub_pf:                             ; #PF (14)
    push 14
    jmp  et_isr_common

; ---------------------------------------------------------------------------
; early_trap_install — hook the firmware IDT's fault gates. Call as early in
;   efi_entry as serial allows, and BEFORE the first risky firmware call.
;   Degrades LOUDLY (a marker naming the reason) if the IDT looks implausible —
;   never silently believes itself protected.
;   clobbers: caller-saved
; ---------------------------------------------------------------------------
early_trap_install:
    push rbx
    push r12
    push r13

    sidt [rel et_idtr]
    movzx eax, word [rel et_idtr]           ; IDT limit
    mov  r12, [rel et_idtr + 2]             ; IDT base

    cmp  eax, 32*16 - 1                     ; must cover at least the 32 faults
    jb   .degrade
    test r12, r12
    jz   .degrade
    mov  [rel et_saved_base], r12

    xor  r13d, r13d                         ; slot 0: #UD
    lea  rbx, [rel et_stub_ud]
    call et_hook_one
    mov  r13d, 1                            ; slot 1: #DF
    lea  rbx, [rel et_stub_df]
    call et_hook_one
    mov  r13d, 2                            ; slot 2: #GP
    lea  rbx, [rel et_stub_gp]
    call et_hook_one
    mov  r13d, 3                            ; slot 3: #PF
    lea  rbx, [rel et_stub_pf]
    call et_hook_one

    mov  byte [rel et_installed], 1
    mov  byte [rel et_m_armed], 1
    lea  rdi, [rel str_et_armed]
    call serial_string
    jmp  .done
.degrade:
    mov  byte [rel et_installed], 0
    lea  rdi, [rel str_et_degraded]
    call serial_string
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; et_hook_one — R13D = slot (0..3), RBX = handler VA, R12 = IDT base.
;   Saves the original 16-byte gate, then rewrites ONLY offset[0:63]. The
;   selector (+2), IST (+4) and type (+5) bytes are deliberately left alone.
;   clobbers: rax rcx rdx rdi rsi
; ---------------------------------------------------------------------------
et_hook_one:
    ; NOTE: [rel sym + reg] is illegal — RIP-relative cannot carry an index.
    ; Materialize the base with lea, THEN index. (nasm only warns; the encoding
    ; it picks would address the wrong memory.)
    lea  rax, [rel et_slot_vec]
    movzx eax, byte [rax + r13]              ; slot -> real vector number
    shl  eax, 4
    lea  rsi, [r12 + rax]                    ; rsi = &gate[vector]

    mov  eax, r13d                           ; rdi = &et_saved[slot*16]
    shl  eax, 4
    lea  rdi, [rel et_saved]
    add  rdi, rax
    mov  rax, [rsi]
    mov  [rdi], rax
    mov  rax, [rsi + 8]
    mov  [rdi + 8], rax

    mov  rax, rbx                            ; install our offset
    mov  word [rsi],      ax
    shr  rax, 16
    mov  word [rsi + 6],  ax
    shr  rax, 16
    mov  dword [rsi + 8], eax
    ret

; ---------------------------------------------------------------------------
; early_trap_uninstall — put the firmware's original gates back. Called
;   immediately before ExitBootServices: past EBS the firmware IDT is replaced
;   by core/idt.asm anyway, and leaving a stale hook pointing into code whose
;   mapping is about to change is exactly the kind of latent trap this module
;   exists to remove. Idempotent.
;   clobbers: caller-saved
; ---------------------------------------------------------------------------
early_trap_uninstall:
    cmp  byte [rel et_installed], 0
    je   .out
    push rbx
    push r12
    push r13
    mov  r12, [rel et_saved_base]
    test r12, r12
    jz   .pop_out
    xor  r13d, r13d
.loop:
    lea  rax, [rel et_slot_vec]              ; same lea-then-index rule as above
    movzx eax, byte [rax + r13]
    shl  eax, 4
    lea  rsi, [r12 + rax]
    mov  eax, r13d
    shl  eax, 4
    lea  rdi, [rel et_saved]
    add  rdi, rax
    mov  rax, [rdi]
    mov  [rsi], rax
    mov  rax, [rdi + 8]
    mov  [rsi + 8], rax
    inc  r13d
    cmp  r13d, 4
    jb   .loop
    mov  byte [rel et_installed], 0
    lea  rdi, [rel str_et_unhooked]
    call serial_string
.pop_out:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; ---------------------------------------------------------------------------
; early_trap_verify — DIAGNOSTIC: re-read the LIVE IDT and print the base plus
;   the currently-installed #GP(13) handler offset, so we can see whether the
;   firmware moved its IDTR or overwrote our gate between install and the risky
;   call. Instrument-then-conclude: do not guess which one it was.
; ---------------------------------------------------------------------------
early_trap_verify:
    push rbx
    push r12
    sidt [rel et_idtr]
    mov  r12, [rel et_idtr + 2]
    lea  rdi, [rel str_et_v_base]
    call serial_string
    mov  rdi, r12
    call et_emit_hex
    lea  rdi, [rel str_et_v_saved]
    call serial_string
    mov  rdi, [rel et_saved_base]
    call et_emit_hex
    ; reassemble gate[13] offset from its three fields
    lea  rbx, [r12 + 13*16]
    movzx eax, word [rbx + 6]
    shl  rax, 16
    mov  ax,  word [rbx]
    mov  rcx, rax
    mov  eax, dword [rbx + 8]
    shl  rax, 32
    or   rcx, rax
    lea  rdi, [rel str_et_v_gate]
    call serial_string
    mov  rdi, rcx
    call et_emit_hex
    lea  rdi, [rel str_et_v_want]
    call serial_string
    lea  rdi, [rel et_stub_gp]
    call et_emit_hex
    lea  rdi, [rel str_et_v_end]
    call serial_string
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; et_isr_common — the pre-EBS fault handler.
;
;   Stack on entry (uniform, thanks to the stubs):
;       [rsp+0]  vector
;       [rsp+8]  error code (0 for #UD)
;       [rsp+16] RIP        <- the faulting instruction
;       [rsp+24] CS
;       [rsp+32] RFLAGS
;
;   Runs on the FIRMWARE's stack under the FIRMWARE's CR3, so it assumes nothing
;   about PaOS state and touches only serial (already up) and CMOS port I/O.
;   Order is deliberate:
;     1. record vector/err/RIP so the next boot can report WHY
;     2. say it on serial — the only output that exists this early
;     3. count the attempt   — otherwise a pre-EBS fault is invisible to the
;                              ladder and the box reboot-loops forever
;     4. demote the keep     — clears the CMOS confirmed magic so the A/B ladder
;                              treats the next boot as UNCONFIRMED and climbs
;                              toward chainload escalation
;     5. CF9 warm reset      — unconditional. Unlike the post-EBS handler there
;                              is no self-test to protect and no way to resume.
; ---------------------------------------------------------------------------
et_isr_common:
    cli
    ; The trap remains installed while system_secret_preebs reads Y, including
    ; its transient buffers. Wipe before diagnostics or either reset/halt path.
    call reset_wipe_all
    mov  rax, [rsp]
    mov  [rel et_fault_vec], rax
    mov  rax, [rsp + 8]
    mov  [rel et_fault_err], rax
    mov  rax, [rsp + 16]
    mov  [rel et_fault_rip], rax
    mov  byte [rel et_m_fault], 1

    lea  rdi, [rel str_et_fault_pre]
    call serial_string
    mov  rdi, [rel et_fault_vec]
    call et_emit_hex
    lea  rdi, [rel str_et_fault_rip]
    call serial_string
    mov  rdi, [rel et_fault_rip]
    call et_emit_hex
    ; err and this image's load base, so an offline reader can tell a PaOS RIP
    ; (base + RVA) from one inside firmware (HP184 warm, rip 0x382fe08f, base
    ; unknown).  The base comes from a RIP-relative lea, not LoadedImage: .text
    ; (code_start) sits at RVA 0x1000 (header.asm section_header).
    lea  rdi, [rel str_et_fault_err]
    call serial_string
    mov  rdi, [rel et_fault_err]
    call et_emit_hex
    lea  rdi, [rel str_et_fault_base]
    call serial_string
    lea  rdi, [rel code_start]
    sub  rdi, 0x1000
    call et_emit_hex
    lea  rdi, [rel str_et_fault_post]
    call serial_string

    call boot_ab_fault_bump                 ; (3) count it — CMOS only
    call boot_ab_demote                     ; (4) clear the confirmed magic

    lea  rdi, [rel str_et_reset]
    call serial_string
    mov  al, 0x06                           ; CF9: RST_CPU|SYS_RST = warm reset
    mov  dx, 0x0cf9
    out  dx, al
.hang:
    cli
    hlt
    jmp  .hang

; et_emit_hex — RDI = value, print 16 hex digits. Fault-context safe: no heap,
;   no format helpers, one byte at a time down the already-live UART.
et_emit_hex:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, 60
.next:
    mov  rax, rbx
    mov  rcx, r12
    shr  rax, cl
    and  eax, 0x0F
    cmp  al, 10
    jb   .digit
    add  al, 'a' - 10
    jmp  .put
.digit:
    add  al, '0'
.put:
    mov  [rel et_hexbuf], al
    lea  rdi, [rel et_hexbuf]
    call serial_string
    sub  r12d, 4
    jns  .next
    pop  r12
    pop  rbx
    ret

; ---- data ------------------------------------------------------------------
et_slot_vec:      db 6, 8, 13, 14         ; slot -> vector
et_idtr:          times 16 db 0
et_saved_base:    dq 0
et_saved:         times 64 db 0           ; 4 gates x 16 bytes
et_installed:     db 0
et_m_armed:       db 0
et_m_fault:       db 0
et_fault_vec:     dq 0
et_fault_err:     dq 0
et_fault_rip:     dq 0
et_hexbuf:        db 0, 0

str_et_armed:
    db "[PAOS64] P0 early-trap: firmware IDT fault gates hooked pre-EBS "
    db "(#UD/#DF/#GP/#PF) [boot.early.trap.armed]", 13, 10, 0
str_et_degraded:
    db "[PAOS64] P0 early-trap: implausible firmware IDT — NOT hooked, "
    db "pre-EBS faults remain unrecoverable [boot.early.trap.degraded]", 13, 10, 0
str_et_unhooked:
    db "[PAOS64] P0 early-trap: firmware gates restored before EBS "
    db "[boot.early.trap.unhooked]", 13, 10, 0
str_et_v_base:  db "[PAOS64] P0 early-trap VERIFY: live_idt=0x", 0
str_et_v_saved: db " hooked_idt=0x", 0
str_et_v_gate:  db " gate13=0x", 0
str_et_v_want:  db " want=0x", 0
str_et_v_end:   db "", 13, 10, 0
str_et_fault_pre:
    db "[PAOS64] P0 early-trap: PRE-EBS FAULT vec=0x", 0
str_et_fault_rip:
    db " rip=0x", 0
str_et_fault_err:
    db " err=0x", 0
str_et_fault_base:
    db " base=0x", 0
str_et_fault_post:
    db " [boot.early.trap.fault]", 13, 10, 0
str_et_reset:
    db "[PAOS64] P0 early-trap: counted + demoted -> CF9 warm reset "
    db "[boot.early.trap.reset]", 13, 10, 0
