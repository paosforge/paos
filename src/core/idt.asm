;; MODULE core/idt
;; LAYER 1
;; EXPORTS idt_handler_matches, idt_machine_check_present, cpu_boundary_fault_check, cpu_boundary_fault_arm, cpu_boundary_fault_disarm, cpu_boundary_fail_stop, cpu_boundary_fail_stop_reason, irq_unexpected_count, irq_unexpected_last, idt_gp_fixup_arm, idt_gp_fixup_disarm, idt_gp_fixup_observe, idt_gp_fixup_cpu, idt_gp_fixup_count, idt_init, idt_machine_check_enable, idt_selftest, wx_selftest, fault_contain_selftest, fault_inject_ud, fault_recover_selftest, fault_df_selftest, idt_set_handler, diag_fault_expect, diag_fault_recover_rip, fault_warmreset_armed, fault_demote_hook, fault_inject_ud_seen, fault_inject_ud_dumped, fault_inject_ud_ok, fault_inject_ud_vector, fault_inject_ud_rip, fault_inject_ud_nonce, idt_m_df
;; IMPORTS boot/serial, boot/paging, core/diag, core/reset_wipe, core/normal_deadman
;; CAPS
;; OWNER saga:core
; Standalone source harnesses retain the same disabled default as boot/header.
%ifndef PAOS_NORMAL_DEADMAN_MS
%define PAOS_NORMAL_DEADMAN_MS 0
%endif
; ============================================================================
; core/idt.asm — 64-bit Interrupt Descriptor Table + exception handlers.
;
; An armed CPU boundary or an interrupted fail-stop takes precedence over
; every ordinary recovery path described below. See the boundary fault contract.
;
; First piece of core L1. Installs a 256-entry IDT; vectors 0-31 (CPU
; exceptions) get real stubs, 32-255 a default stub. The common handler prints
; a diagnostic (vector, error code, faulting RIP, CR2) and halts — EXCEPT #BP
; (int3, vector 3), which returns cleanly (the self-test path + future debugger
; hook). This is what makes a fault a *diagnosable* event instead of a silent
; triple-fault reboot (PLAN resilience dividend), and it's the prerequisite for
; the destructive W^X self-test + the 4 KiB image split that makes code RO.
;
; Selector: uses the current CS (the firmware GDT persists across EBS and is in
; our identity map). A dedicated GDT is a later core piece; firmware CS works now.
; Gates are interrupt gates (type 0x8E): IF auto-cleared on entry.
; ============================================================================

; ---- ISR stubs: normalize the stack to [vector][errcode][rip][cs][rflags]... --
; Each stub is padded to a FIXED 16-byte stride (align 16) so idt_init can find
; handler N at (isr_stub_0 + N*16) via a RIP-relative lea — NEVER an absolute
; `dq isr_stub_N` table, which would store ORG-0 offsets that are wrong at the
; ImageBase load address (the absolute-`dq <symbol>` hazard, MODULES §3.2).
%macro ISR_NOERR 1
    align 16
isr_stub_%1:
    push 0                          ; dummy error code (uniform layout)
    push %1                         ; vector
    jmp  isr_common
%endmacro
%macro ISR_ERR 1
    align 16
isr_stub_%1:
    push %1                         ; vector (CPU already pushed the real errcode)
    jmp  isr_common
%endmacro

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3                         ; #BP (int3) — handled specially (returns)
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8                         ; #DF
ISR_NOERR 9
ISR_ERR   10                        ; #TS
ISR_ERR   11                        ; #NP
ISR_ERR   12                        ; #SS
ISR_ERR   13                        ; #GP
ISR_ERR   14                        ; #PF
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17                        ; #AC
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21                        ; #CP
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_NOERR 30
ISR_NOERR 31
    align 16
isr_stub_default:
    push 0
    push 255
    jmp  isr_common

; ---- unclaimed hardware-interrupt containment --------------------------------
; Vectors 32..255 are hardware-interrupt territory, not CPU faults.  Routing an
; unclaimed firmware-left interrupt through isr_common turns an otherwise
; recoverable stray delivery into the armed CF9 fault-reset path.  This exact
; target-neutral handler was metal-proven on the Dell Latitude 5490 in source
; commit c3e6dc767deb0ff4d8f41f4f684908d05667777f: record the vector, EOI the
; legacy PIC window and/or LAPIC, then return.  Keep every stub at a fixed
; 16-byte stride so idt_init can derive its address without a pointer table.
%assign irqv 32
%rep 224
    align 16
irq_stub_%+irqv:
    push 0                          ; dummy error code (uniform layout)
    push irqv                       ; vector
    jmp  irq_common
%assign irqv irqv+1
%endrep

irq_common:
    push rax
    push rcx
    push rdx
    mov  rax, [rsp + 24]            ; vector beneath the three saved registers
    mov  [rel irq_unexpected_last], rax
    inc  qword [rel irq_unexpected_count]
    cmp  rax, 0x30
    jae  .lapic_eoi
    cmp  rax, 0x28
    jb   .master_eoi
    mov  al, 0x20
    out  0xA0, al                   ; slave PIC EOI (IRQ8..15)
.master_eoi:
    mov  al, 0x20
    out  0x20, al                   ; master PIC EOI
.lapic_eoi:
    mov  ecx, 0x1B                  ; IA32_APIC_BASE
    rdmsr
    test eax, (1 << 11)             ; LAPIC globally enabled?
    jz   .done
    test eax, (1 << 10)             ; x2APIC mode?
    jz   .xapic_eoi
    mov  ecx, 0x80B                 ; x2APIC EOI register
    xor  eax, eax
    xor  edx, edx
    wrmsr
    jmp  .done
.xapic_eoi:
    and  eax, 0xFFFFF000            ; APIC base (identity-mapped)
    mov  dword [rax + 0xB0], 0      ; a stray EOI with no ISR bit is ignored
.done:
    pop  rdx
    pop  rcx
    pop  rax
    add  rsp, 16                    ; discard vector + dummy error code
    iretq

; ---- common handler --------------------------------------------------------
; stack: [rsp]=vector [+8]=errcode [+16]=rip [+24]=cs [+32]=rflags [+40]=rsp [+48]=ss
isr_common:
    ; Contain uncertain VM/paired-executor state BEFORE any resumable fixup.
    ; Preserve the interrupted registers on the ordinary (unarmed) path.
    push rax
    push rcx
    push rdx
    mov  rax, [rsp + 40]               ; interrupted RIP (3 saved GPRs + 16)
    jmp  cpu_boundary_fault_active     ; no CALL/RET before protected LAND
.boundary_test:
    test eax, eax
    pop  rdx
    pop  rcx
    pop  rax
    jnz  cpu_boundary_fault_stop
%if PAOS_NORMAL_DEADMAN_MS
    cmp qword [rsp],6
    jne .not_deadman
    push rax
    lea rax,[rel normal_deadman_fault]
    cmp [rsp+24],rax                   ; original frame RIP, plus saved RAX
    pop rax
    je .panic                         ; dedicated IRQ expiry is always fatal
.not_deadman:
%endif
    mov  rsi, [rsp]                 ; vector (survives serial_* calls)
    cmp  rsi, 3
    je   .bp_return
    ; RCQ-43: #MC has no implemented MCA recovery assessment yet. Generic
    ; fault-test latches cannot establish restartability or clear MCIP, so it
    ; must reach the persistent dump and fatal decision even during a test.
    cmp  rsi, 18
    je   .panic
    ; --- 9702: #DF(8) arrives on the IST1 stack (boot/gdt.asm TSS + gate-8 IST=1),
    ;     so this handler RUNS even when the interrupted context's stack is the
    ;     thing that broke (pre-IST that class was an undiagnosable TRIPLE fault).
    ;     Checked FIRST (before the #PF/#chk_diag ladder — those `jne .chk_diag`
    ;     jumps would skip a later #DF test). The armed self-test proves
    ;     containment: restore a sane RSP into the saved frame + resume at the
    ;     recovery point. An UNEXPECTED #DF (df_expect=0) falls through to the
    ;     diag/panic ladder — which now also works, because we're on IST1. ---
    cmp  rsi, 8
    jne  .not_df
    cmp  byte [rel df_expect], 0
    je   .chk_diag                      ; real #DF: diag-dump + gated warm reset (no hang)
    mov  rdi, [rsp]                     ; vector
    mov  rsi, [rsp + 8]                 ; error code (always 0 for #DF)
    mov  rdx, [rsp + 16]                ; RIP at #DF promotion
    mov  rcx, cr2
    call diag_ring_fault                ; forensic dump (same contract as .chk_diag)
    mov  byte [rel df_expect], 0
    mov  rax, [rel df_recover_rip]
    mov  [rsp + 16], rax                ; frame.RIP = recovery point
    mov  rax, [rel df_saved_rsp]
    mov  [rsp + 40], rax                ; frame.RSP = the saved-good stack (the broken
                                        ; one is what CAUSED the #DF — must not resume on it)
    add  rsp, 16                        ; discard vector + errcode
    iretq
.not_df:
    ; RCQ-42 2b: an armed one-shot #GP slot (the microcode-load WRMSR) is
    ; decided out of line by idt_gp_fixup; whatever it does not own comes
    ; back to .not_gp_fixup with RSI = the vector, unchanged.
    cmp  rsi, 13
    jne  .not_gp_fixup
    cmp  byte [rel idt_gp_fixup_armed], 0
    jne  idt_gp_fixup
.not_gp_fixup:
    ; #PF (14) during the W^X self-test → expected; redirect to the recovery point
    cmp  rsi, 14
    jne  .chk_diag
    cmp  byte [rel wx_expecting], 0
    je   .chk_diag
    mov  rax, [rel wx_recover_rip]
    mov  [rsp + 16], rax            ; overwrite saved RIP with .recover
    add  rsp, 16                    ; discard vector + errcode
    iretq
.chk_diag:
    ; expected, recoverable diag-test fault (any vector): record the FULL register
    ; dump into the persistent diag ring, disarm, then resume at the armed recovery
    ; point — a TRAPPED fault (diagnosed, not fatal). diag_ring_fault no-ops if the
    ; ring isn't up. Unexpected faults fall through to .panic (real crash).
    cmp  byte [rel diag_fault_expect], 0
    je   .panic
    ; 1117c live FAULTINJECT receipt: snapshot the actual interrupt frame before
    ; diag_ring_fault clobbers caller-saved registers. The UDP command is
    ; registered only after P2 diag initialization. EAX must additionally say
    ; the ring write committed; a contended writer returns without a dump.
    ; The earned flag also requires iretq to reach fault_inject_ud.recover.
    cmp  byte [rel fault_inject_ud_expect], 0
    je   .diag_snapshot_done
    mov  rax, [rsp]
    mov  [rel fault_inject_ud_vector], rax
    mov  rax, [rsp + 16]
    mov  [rel fault_inject_ud_rip], rax
.diag_snapshot_done:
    mov  rdi, [rsp]                 ; vector
    mov  rsi, [rsp + 8]             ; error code
    mov  rdx, [rsp + 16]           ; faulting RIP
    mov  rcx, cr2                   ; fault address
    call diag_ring_fault
    cmp  byte [rel fault_inject_ud_expect], 0
    je   .diag_record_done
    test eax, eax
    jz   .diag_record_done             ; contended diagnostic write is not a dump
    mov  byte [rel fault_inject_ud_dumped], 1
.diag_record_done:
    mov  byte [rel diag_fault_expect], 0
    mov  rax, [rel diag_fault_recover_rip]
    mov  [rsp + 16], rax           ; resume at the recovery point
    add  rsp, 16                    ; discard vector + errcode
    iretq
.panic:
    ; Capture bounded MCA status before the final fault record flushes the ring.
    ; The snapshot never clears banks/MCIP or authorizes a #MC return.
    cmp  qword [rsp], 18
    jne  .panic_frame
    call diag_ring_mca
.panic_frame:
    ; crash forensics: write the dump to the PERSISTENT ring BEFORE we print/halt,
    ; so the next boot's P2 can report this fault (survives warm reboot). No-op if
    ; the ring isn't up yet. Then print "[PAOS64] EXC .." and halt as before.
    mov  rdi, [rsp]                 ; vector
    mov  rsi, [rsp + 8]            ; error code
    mov  rdx, [rsp + 16]          ; faulting RIP
    mov  rcx, cr2                  ; fault address
    call diag_ring_fault
    ; --- panic: print "[PAOS64] EXC v=.. err=.. rip=.. cr2=.." then halt ---
    mov  rsi, [rsp]                ; vector (reload; diag_ring_fault clobbered it)
    mov  rdx, [rsp + 8]            ; error code
    mov  r8,  [rsp + 16]          ; faulting RIP
    mov  r9,  cr2                  ; fault address (#PF)
    lea  rdi, [rel str_exc]
    call serial_string
    mov  rdi, rsi
    call serial_hex64
    lea  rdi, [rel str_err]
    call serial_string
    mov  rdi, rdx
    call serial_hex64
    lea  rdi, [rel str_rip]
    call serial_string
    mov  rdi, r8
    call serial_hex64
    lea  rdi, [rel str_cr2]
    call serial_string
    mov  rdi, r9
    call serial_hex64
    lea  rdi, [rel str_nl]
    call serial_string
    ; --- RECOVERY (9701): NO uncontained fault hard-hangs. The forensic dump was
    ;     written to the persistent diag ring + printed above; now emit the
    ;     recovered-path marker and take the GATED warm-reset decision instead of
    ;     cli;hlt forever. The marker is UNFAKEABLE — it is only reached if a real
    ;     uncontained fault fell through to .panic and this code ran (a latch can't
    ;     pre-fire it, .panic is not on any nominal path). ---
    lea  rdi, [rel str_fault_recover]
    call serial_string                 ; [fault.recover.warmreset]
    ; self-test hook: a recover self-test arms panic_recover_expect + a resume RIP
    ; so it can PROVE the dump-then-reset path was reached WITHOUT rebooting the
    ; graded boot. Production uncontained faults leave it clear -> warm-reset path.
    cmp  qword [rsp], 18                ; never return a #MC through the panic KAT
    je   .warmreset_decide
%if PAOS_NORMAL_DEADMAN_MS
    cmp qword [rsp],6
    jne .not_deadman_kat
    push rax
    lea rax,[rel normal_deadman_fault]
    cmp [rsp+24],rax
    pop rax
    je .warmreset_decide               ; never resume an expired live lease
.not_deadman_kat:
%endif
    cmp  byte [rel panic_recover_expect], 0
    je   .warmreset_decide
    mov  byte [rel panic_recover_expect], 0
    mov  rax, [rel panic_recover_rip]
    mov  [rsp + 16], rax               ; resume at the self-test recovery point
    add  rsp, 16                       ; discard vector + errcode (match .chk_diag)
    iretq
.warmreset_decide:
    ; RCQ-41: only a genuinely fatal fault gets here (every self-test escape is
    ; above). Claim the first-fatal crash slot in the persistent ring header;
    ; the next Manager-launched boot projects it into PaOSCrashRecord.
    mov  rdi, [rsp]                    ; vector
    mov  rsi, [rsp + 8]                ; error code
    mov  rdx, [rsp + 16]               ; faulting RIP (stored image-relative)
    call diag_crash_slot_fatal
    ; GATED CF9 warm reset. Only fires when ARMED; armed=0 during boot + QEMU runs
    ; -no-reboot, so the graded boot NEVER reboots (the marker above already proved
    ; the recovered path). Arming + the CMOS crash-counter escalation to
    ; bootmgfw_orig (repeat-fault -> Windows chainload, never an infinite reboot
    ; loop; core/boot_canon 1073 + bare-metal 1014) is the DELIBERATE bare-metal
    ; leg of 9701 — fault handling is bare-metal-sensitive.
    ; SEC-pre-reset-wipe-hook: key material never outlives a fatal fault, whether
    ; the CF9 below resets (DRAM kept) or the CPU halts until someone resets it.
    ; Lock-free and call-free inside, so it is safe in the fault context.
    call reset_wipe_all
    call serial_fault_flush            ; the CPU stops next: queued output (and the dump above) reaches the wire
    cmp  byte [rel fault_warmreset_armed], 0
    je   .hang                         ; not armed (boot/QEMU): degrade to a safe halt
    ; 9702: DEMOTE the keep before resetting — the hook (runtime-lea-filled by
    ; svc/boot_ab fault_warmreset_arm, never dq) clears the CMOS confirmed magic
    ; so the A/B trial ladder sees a fault-rebooted keep as UNCONFIRMED. A keep
    ; that re-reaches commit re-earns confirmed (single fault -> recovered); one
    ; that faults every boot climbs the trial counter to the pre-EBS escalation
    ; (boot/chainload.asm -> bootmgfw_orig) — NEVER an infinite reboot loop.
    mov  rax, [rel fault_demote_hook]
    test rax, rax
    jz   .fire_cf9
    call rax
.fire_cf9:
    mov  al, 0x06                      ; CF9: RST_CPU(bit2)+SYS_RST(bit1) = warm reset
    mov  dx, 0x0cf9
    out  dx, al
.hang:
    cli
    hlt
    jmp  .hang
.bp_return:
    add  rsp, 16                    ; discard vector + (dummy) errcode
    iretq                           ; resume after the int3

; Trusted VM caller contract: IF=0, CPU pinned, host LAPIC identity stable.
; Arm BEFORE paired execution or VM-state mutation; hold across guest, exit and
; cleanup. Disarm only after known paired closure and full host restoration.
; Both APIs preserve every GPR except RAX; arithmetic flags clobbered, IF intact.
; Token is a host custody cookie, never a guest capability or an exit receipt.
; Bounded 32 slots: atomic qword = nonzero generation:32 | full APIC ID:32.
; Generation never wraps; exhaustion/contention refuses instead of reusing it.
cpu_boundary_fault_arm:
    push rcx
    push rdx
    push rsi
    push r8
    push r9
    call cpu_boundary_fault_flags
    test eax, (1 << 9)
    jnz  .refuse
    call idt_gp_fixup_cpu
    cmp  eax, -1
    je   .refuse
    mov  r8d, eax
    lea  rsi, [rel cpu_boundary_fault_slots]
    mov  ecx, 32
.nested:
    mov  rax, [rsi]
    test rax, rax
    jz   .next
    cmp  eax, r8d
    je   .refuse
.next:
    add  rsi, 8
    loop .nested
    mov  eax, [rel cpu_boundary_fault_generation]
    cmp  eax, -1
    je   .refuse
    lea  edx, [rax + 1]
    lock cmpxchg [rel cpu_boundary_fault_generation], edx
    jne  .refuse
    mov  r9d, edx
    shl  r9, 32
    or   r9, r8
    lea  rsi, [rel cpu_boundary_fault_slots]
    mov  ecx, 32
.publish:
    xor  eax, eax
    lock cmpxchg [rsi], r9
    je   .armed
    add  rsi, 8
    loop .publish
.refuse:
    xor  eax, eax
    jmp  .done
.armed:
    mov  rax, r9
.done:
    pop  r9
    pop  r8
    pop  rsi
    pop  rdx
    pop  rcx
    ret

; Read-only exact owner/cookie check. Same IF0/pinned identity ABI as arm/disarm;
; preserves every GPR except RAX and arithmetic flags. Never clears a slot.
cpu_boundary_fault_check:
    push rcx
    push rdx
    push rsi
    call cpu_boundary_fault_flags
    test eax, (1 << 9)
    jnz  .refuse
    mov  rax, rdi
    shr  rax, 32
    jz   .refuse
    call idt_gp_fixup_cpu
    cmp  eax, -1
    je   .refuse
    cmp  eax, edi
    jne  .refuse
    lea  rsi, [rel cpu_boundary_fault_slots]
    mov  ecx, 32
.find:
    cmp  [rsi], rdi
    je   .owned
    add  rsi, 8
    loop .find
.refuse:
    xor  eax, eax
    jmp  .done
.owned:
    mov  eax, 1
.done:
    pop  rsi
    pop  rdx
    pop  rcx
    ret

cpu_boundary_fault_disarm:
    push rcx
    push rdx
    push rsi
    call cpu_boundary_fault_flags
    test eax, (1 << 9)
    jnz  .refuse
    mov  rax, rdi
    shr  rax, 32
    jz   .refuse
    call idt_gp_fixup_cpu
    cmp  eax, -1
    je   .refuse
    cmp  eax, edi
    jne  .refuse
    lea  rsi, [rel cpu_boundary_fault_slots]
    mov  ecx, 32
.find:
    mov  rax, rdi
    xor  edx, edx
    lock cmpxchg [rsi], rdx
    je   .cleared
    add  rsi, 8
    loop .find
.refuse:
    mov  eax, 1
    jmp  .done
.cleared:
    xor  eax, eax
.done:
    pop  rsi
    pop  rdx
    pop  rcx
    ret

; Hardware observation seam, not an NMI-exclusion mechanism.
cpu_boundary_fault_flags:
    pushfq
    pop  rax
    ret

; ISR-private: jump dispatch; RAX = interrupted RIP; no CALL/RET before
; ownership is resolved. Clobbers RAX/RCX/RDX only. Avoid LAPIC reads entirely when no
; boundary is armed, preserving the ordinary early-boot exception behavior.
; If identity becomes unavailable with a live boundary, conservatively stop.
cpu_boundary_fault_active:
    ; A direct fail-stop after arm refusal must itself survive NMI/fault fixups.
    ; This address-range guard has no mutable latch or LAPIC dependency.
    lea  rcx, [rel cpu_boundary_fail_stop]
    cmp  rax, rcx
    jb   .slots
    lea  rcx, [rel cpu_boundary_fail_stop_end]
    cmp  rax, rcx
    jb   .active
.slots:
    lea  rcx, [rel cpu_boundary_fault_slots]
    mov  edx, 32
.any:
    cmp  qword [rcx], 0
    jne  .identify
    add  rcx, 8
    dec  edx
    jnz  .any
    xor  eax, eax
    jmp  isr_common.boundary_test
.identify:
    ; BEGIN boundary inline APIC identity (no CALL/RET on owner event).
    mov  ecx, 0x1B
    rdmsr
    test eax, (1 << 11)
    jz   .active
    test eax, (1 << 10)
    jz   .xapic
    mov  ecx, 0x802
    rdmsr
    jmp  .identified
.xapic:
    and  eax, 0xFFFFF000
    mov  eax, [rax + 0x20]
    shr  eax, 24
.identified:
    ; END boundary inline APIC identity.
    cmp  eax, -1
    je   .active
    push rsi
    lea  rcx, [rel cpu_boundary_fault_slots]
    lea  rsi, [rcx + 32*8]
.match:
    mov  rdx, [rcx]                    ; one atomic snapshot, including occupancy
    test rdx, rdx
    jz   .next
    cmp  eax, edx
    je   .matched
.next:
    add  rcx, 8
    cmp  rcx, rsi
    jb   .match
    pop  rsi
    xor  eax, eax
    jmp  isr_common.boundary_test
.matched:
    pop  rsi
.active:
    mov  eax, 1
    jmp  isr_common.boundary_test

; Nonresuming per-CPU containment. All terminal instructions (including the
; observer) stay inside the address guard above, even for an unarmed direct
; stop. No helper, return, fixup, wipe or reset. This is not NMI exclusion.
; Generic direct failures have reason0; selected native adapters use a fixed
; source reason in EDI. Exception fields come only from the actual ISR frame.
cpu_boundary_fail_stop:
    cli
    xor edi, edi
cpu_boundary_fail_stop_reason:
    cli
    mov r9d, edi
    mov r8d, 'D'
    xor r10d, r10d
    xor r11d, r11d
    jmp cpu_boundary_stop_emit
cpu_boundary_fault_stop:
    cli
    mov r8d, 'I'
    mov r9, [rsp]                       ; vector, never an inferred cause
    mov r10, [rsp + 8]                  ; normalized hardware error code
    mov r11, [rsp + 16]                 ; interrupted RIP, no guest dereference
cpu_boundary_stop_emit:
    cli
    ; Lenovo/legacy COM1 only. AX99100 MMIO is intentionally not touched from
    ; uncertain state. One lock try, no queue/flush, and one shared poll budget.
    cmp byte [rel serial_available], 1
    jne .halt
    cmp byte [rel serial_mode], 0
    jne .halt
    xor eax, eax
    mov cl, 1
    lock cmpxchg byte [rel serial_uart_lock], cl
    jne .halt
    lea rsi, [rel .template]
    mov ebp, 65536                    ; total LSR reads, not per character
.next:
    movzx r14d, byte [rsi]
    inc rsi
    test r14d, r14d
    jz .done
    xor r12d, r12d
    cmp r14d, 1
    jne .field
    mov r14b, r8b
    jmp .send
.field:
    cmp r14d, 2
    jb .send
    cmp r14d, 4
    ja .send
    mov r13, r9
    cmp r14d, 2
    je .hex
    mov r13, r10
    cmp r14d, 3
    je .hex
    mov r13, r11
.hex:
    mov r12d, 1
    mov r15d, 16
.digit:
    rol r13, 4
    mov r14d, r13d
    and r14d, 15
    add r14d, '0'
    cmp r14d, '9'
    jbe .send
    add r14d, 7
.send:
    test ebp, ebp
    jz .done
    dec ebp
    mov dx, 0x3FD
    in al, dx
    cmp al, 0xFF
    je .done
    test al, 0x20
    jz .send
    mov dx, 0x3F8
    mov al, r14b
    out dx, al
    test r12d, r12d
    jz .next
    dec r15d
    jnz .digit
    jmp .next
.done:
    mov byte [rel serial_uart_lock], 0 ; release UART ownership only, never custody
.halt:
    hlt
    jmp  .halt
.template:
    db 13,10,'[PAOS64] BOUNDSTOP ',1,':',2,':',3,':',4,13,10,0
cpu_boundary_fail_stop_end:

; RCQ-42 2b slot, the handler half (the arm/disarm API is after wx_selftest).
; Reached from isr_common with vector 13 and the slot nonzero; the frame is
; isr_common's ([rsp]=vector, [+8]=error, [+16]=RIP). A resume leaves the
; interrupted RAX, RCX, RDX and RSI (= 13) clobbered, as isr_common's other
; resumes do; cpu_microcode_write treats all four as dead after its WRMSR.
idt_gp_fixup:
    cmp  byte [rel idt_gp_fixup_armed], 1
    jne  isr_common.not_gp_fixup
    mov  rax, [rsp + 16]
    cmp  rax, [rel idt_gp_fixup_rip]
    jne  isr_common.not_gp_fixup
    call idt_gp_fixup_cpu
    cmp  eax, [rel idt_gp_fixup_owner]
    jne  isr_common.not_gp_fixup
    mov  byte [rel idt_gp_fixup_fault], 1
    mov  byte [rel idt_gp_fixup_armed], 3   ; fired: held until the owner's disarm frees it
    inc  qword [rel idt_gp_fixup_count]
    mov  rax, [rel idt_gp_fixup_resume]
    mov  [rsp + 16], rax
    add  rsp, 16                        ; discard vector + errcode
    iretq

; This CPU's local APIC id: x2APIC 32-bit id, xAPIC bits 31:24, -1 with the
; LAPIC globally disabled. Reads IA32_APIC_BASE (as irq_common) because it
; runs before smp chooses a LAPIC mode. Hardware adapter: host tests replace
; this body. Clobbers RAX, RCX, RDX.
idt_gp_fixup_cpu:
    mov  ecx, 0x1B                      ; IA32_APIC_BASE
    rdmsr
    test eax, (1 << 11)
    jz   .none
    test eax, (1 << 10)
    jz   .xapic
    mov  ecx, 0x802                     ; x2APIC ID
    rdmsr
    ret
.xapic:
    and  eax, 0xFFFFF000                ; identity-mapped APIC base
    mov  eax, [rax + 0x20]
    shr  eax, 24
    ret
.none:
    mov  eax, -1
    ret

; ---- idt_init: build the table + lidt ---------------------------------------
idt_init:
    push rbx
    mov  ax, cs
    mov  [rel idt_sel], ax
    lea  rbx, [rel idt_table]
    lea  r10, [rel isr_stub_0]          ; runtime base (RIP-relative — correct VA)
    lea  r11, [rel irq_stub_32]         ; hardware vectors use fixed-stride EOI stubs
    xor  ecx, ecx
.fill:
    cmp  ecx, 256
    jge  .loaded
    cmp  ecx, 32
    jge  .use_irq
    mov  rax, r10                       ; handler = isr_stub_0 + vector*16
    mov  edx, ecx
    shl  edx, 4
    add  rax, rdx
    jmp  .have
.use_irq:
    mov  rax, r11                       ; irq_stub_32 + (vector-32)*16
    mov  edx, ecx
    sub  edx, 32
    shl  edx, 4
    add  rax, rdx
.have:
    mov  word [rbx],      ax        ; offset[0:15]
    mov  dx, [rel idt_sel]
    mov  word [rbx + 2],  dx        ; selector
    mov  byte [rbx + 4],  0         ; IST = 0
    mov  byte [rbx + 5],  0x8E      ; P=1, DPL=0, 64-bit interrupt gate
    shr  rax, 16
    mov  word [rbx + 6],  ax        ; offset[16:31]
    shr  rax, 16
    mov  dword [rbx + 8], eax       ; offset[32:63]
    mov  dword [rbx + 12], 0        ; reserved
    add  rbx, 16
    inc  ecx
    jmp  .fill
.loaded:
    ; 9702: #DF(8) gets IST1 — the dedicated stack boot/gdt.asm installed in the
    ; TSS — so a double fault caused by a broken stack is still deliverable
    ; (IST=0 would push the frame onto the broken stack -> triple fault).
    lea  rbx, [rel idt_table]
    mov  byte [rbx + 8*16 + 4], 1       ; gate 8 IST field = IST1
    mov  word [rel idt_ptr], 256*16 - 1
    lea  rax, [rel idt_table]
    mov  [rel idt_ptr + 2], rax
    lidt [rel idt_ptr]
    lea  rdi, [rel str_idt_loaded]
    call serial_string
    pop  rbx
    ret

; idt_machine_check_enable — CPU-local, after a valid IDT and stack/TSS.
; Firmware CR4 state is not inherited by APs. Enable architectural #MC delivery
; on every MCE-capable CPU so the fatal handler can capture its MCA state.
; Preserve all GPRs and unrelated CR4 bits. No bank control/status MSR writes.
idt_machine_check_enable:
    push rax
    push rbx
    push rcx
    push rdx
    xor  eax, eax
    cpuid
    cmp  eax, 1
    jb   .done
    mov  eax, 1
    cpuid
    test edx, (1 << 7)                 ; CPUID.1:EDX.MCE
    jz   .done
    mov  rax, cr4
    test eax, (1 << 6)                 ; already enabled: no redundant write
    jnz  .done
    or   rax, (1 << 6)                 ; CR4.MCE
    mov  cr4, rax
.done:
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret
; ---- end CPU-local machine-check enable ----

; idt_set_handler(EDI=vector, RSI=handler) — install/override one gate (after idt_init)
idt_set_handler:
    mov  eax, edi
    shl  eax, 4
    lea  r9, [rel idt_table]
    add  r9, rax                         ; entry = idt_table + vector*16
    mov  rax, rsi
    mov  word [r9],      ax
    mov  dx, [rel idt_sel]
    mov  word [r9 + 2],  dx
    mov  byte [r9 + 4],  0
    mov  byte [r9 + 5],  0x8E
    shr  rax, 16
    mov  word [r9 + 6],  ax
    shr  rax, 16
    mov  dword [r9 + 8], eax
    mov  dword [r9 + 12], 0
    ret

; Read-only current-CPU route witness. Compare the loaded IDTR, complete gate,
; selector/attributes and exact installed handler, not just the present bit.
; EDI vector,RSI expected handler -> EAX1 exact/0 unavailable. Bounded, no I/O.
idt_handler_matches:
    cmp edi,256
    jae .bad
    test rsi,rsi
    jz .bad
    sub rsp,16
    sidt [rsp]
    lea r9,[rel idt_table]
    cmp [rsp+2],r9
    jne .refuse
    mov eax,edi
    shl eax,4
    lea edx,[rax+15]
    movzx ecx,word [rsp]
    cmp ecx,edx
    jb .refuse
    add r9,rax
    cmp byte [r9+5],0x8e
    jne .refuse
    cmp byte [r9+4],0
    jne .refuse
    cmp dword [r9+12],0
    jne .refuse
    mov ax,[rel idt_sel]
    cmp [r9+2],ax
    jne .refuse
    movzx eax,word [r9]
    movzx edx,word [r9+6]
    shl rdx,16
    or rax,rdx
    mov edx,[r9+8]
    shl rdx,32
    or rax,rdx
    cmp rax,rsi
    sete al
    movzx eax,al
    add rsp,16
    ret
.refuse:
    add rsp,16
.bad:
    xor eax,eax
    ret

idt_machine_check_present:
    mov edi,18
    lea rsi,[rel isr_stub_18]
    jmp idt_handler_matches
; ---- end read-only current IDT route witness ----

; ---- idt_selftest: int3 must be caught AND returned-from -------------------
idt_selftest:
    int3                            ; -> isr_common .bp_return -> iretq back here
    lea  rdi, [rel str_idt_ok]      ; reached only if the round-trip worked
    call serial_string
    ret

; ---- fault_contain_selftest: prove a previously-UNCONTAINED class DEGRADES ----
; Arms the SAME proven trapped-fault contract diag_selftest uses for #GP
; (diag_fault_expect + diag_fault_recover_rip), then executes `ud2` — a real
; #UD(6). isr_common .chk_diag records the full register dump into the persistent
; diag ring, disarms, and resumes at .recover: a diagnosed, non-fatal fault
; instead of a hard hang. Reaching .recover = #UD CONTAINED; falling through the
; ud2 = the handler is broken. Emits [fault.contain.ud] ONLY on the recovered
; path (a latch can't fire it — the marker is unreachable unless trap+resume ran).
;   clobbers: RAX, RDI (no callee-saved touched)
fault_contain_selftest:
    lea  rax, [rel .recover]
    mov  [rel diag_fault_recover_rip], rax
    mov  byte [rel diag_fault_expect], 1
    ud2                                 ; #UD(6) -> isr_common .chk_diag records+resumes
    ; fall-through only if NO fault fired -> the handler is broken
    mov  byte [rel diag_fault_expect], 0
    lea  rdi, [rel str_fc_broken]
    call serial_string
    ret
.recover:
    mov  byte [rel diag_fault_expect], 0   ; belt-and-suspenders (handler already cleared it)
    lea  rdi, [rel str_fc_ud]              ; reached ONLY via the trapped+resumed #UD
    call serial_string
    ret

; ---- fault_inject_ud: live, command-triggered #UD containment proof (1117c) ----
; Arms the same diag + recovery path as fault_contain_selftest, but returns a
; content-graded receipt for FAULTINJECT ud. A success requires all three real
; events: vector 6 arrived, diag_ring_fault returned, and iretq resumed here.
; The bare-metal marker/latch additionally requires the already-proven P1 CF9
; recovery arm, which is set only when CPUID says no hypervisor is present.
;   out: RAX=1 trapped+dumped+resumed, 0 if UD2 unexpectedly fell through
;   clobbers: RAX,RDX,RDI
fault_inject_ud:
    mov  byte [rel fault_inject_ud_seen], 0
    mov  byte [rel fault_inject_ud_dumped], 0
    mov  qword [rel fault_inject_ud_vector], 0
    mov  qword [rel fault_inject_ud_rip], 0
    mov  qword [rel fault_inject_ud_nonce], 0
    lea  rax, [rel .recover]
    mov  [rel diag_fault_recover_rip], rax
    mov  byte [rel fault_inject_ud_expect], 1
    mov  byte [rel diag_fault_expect], 1
    ud2                                 ; #UD(6) -> isr_common -> persistent dump -> iretq
    ; No #UD means the CPU/handler contract is broken: withhold every success bit.
    mov  byte [rel diag_fault_expect], 0
    mov  byte [rel fault_inject_ud_expect], 0
    xor  eax, eax
    ret
.recover:
    mov  byte [rel diag_fault_expect], 0
    mov  byte [rel fault_inject_ud_expect], 0
    cmp  byte [rel fault_inject_ud_dumped], 1
    jne  .fail
    cmp  qword [rel fault_inject_ud_vector], 6
    jne  .fail
    cmp  qword [rel fault_inject_ud_rip], 0
    je   .fail
    mov  byte [rel fault_inject_ud_seen], 1
    inc  qword [rel fault_inject_ud_seq]
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel fault_inject_ud_rip]
    xor  rax, [rel fault_inject_ud_seq]
    mov  [rel fault_inject_ud_nonce], rax
    cmp  byte [rel fault_warmreset_armed], 1
    jne  .success
    mov  byte [rel fault_inject_ud_ok], 1
    lea  rdi, [rel str_fc_ud_baremetal]
    call serial_string                  ; live hardware path only
.success:
    mov  eax, 1
    ret
.fail:
    mov  byte [rel fault_inject_ud_seen], 0
    xor  eax, eax
    ret

; ---- fault_recover_selftest: prove the .panic RECOVERY path (no hard hang) -----
; The tournament-#2 'recovery' proof. Arms panic_recover_expect + a resume RIP,
; then triggers a genuinely UNCONTAINED fault — #DE(0), integer div-by-zero, which
; nothing traps (diag_fault_expect=0, not the W^X #PF) so it falls through to
; .panic. .panic records the diag dump, prints EXC, emits [fault.recover.warmreset]
; and — because we armed the recover latch — resumes HERE instead of hanging or
; actually pulling CF9. Reaching .recover = an uncontained fault DEGRADED (diag +
; would-warm-reset) rather than hard-hung. The real CF9 fire + crash-counter
; escalation is armed only on bare metal (the deliberate 9701 metal leg).
;   clobbers: RAX, RCX, RDX, RDI
fault_recover_selftest:
    lea  rax, [rel .recover]
    mov  [rel panic_recover_rip], rax
    mov  byte [rel panic_recover_expect], 1
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    div  ecx                            ; #DE(0) -> isr_common -> .panic (uncontained)
    ; fall-through only if NO fault fired -> the panic/recovery path is broken
    mov  byte [rel panic_recover_expect], 0
    lea  rdi, [rel str_fr_broken]
    call serial_string
    ret
.recover:
    mov  byte [rel panic_recover_expect], 0  ; belt-and-suspenders (.panic already cleared it)
    ret

; ---- fault_df_selftest: prove #DF(8) is CONTAINED via the IST1 stack (9702) -----
; The nastiest class: a fault whose CAUSE is an unusable stack. Pre-IST this was
; an undiagnosable TRIPLE fault (the CPU cannot push the exception frame, cannot
; deliver #DF either -> silent reboot). Now: arm df_expect + a recovery RIP + the
; CURRENT (good) RSP, then point RSP at a non-canonical address and push. The push
; raises #SS(0); delivering #SS needs the same broken stack -> promotion to #DF;
; #DF's gate says IST1 -> the handler runs on the dedicated stack (boot/gdt.asm),
; records the diag dump, restores the saved-good RSP into the frame and resumes
; HERE. Reaching .recover is unfakeable — it requires a real #DF delivered over
; IST to a handler that fixed the broken stack (a latch can't pre-fire it, and
; without IST the box would have triple-faulted, visibly killing the boot).
;   clobbers: RAX, RCX, RDX, RDI (no callee-saved touched)
fault_df_selftest:
    lea  rax, [rel .recover]
    mov  [rel df_recover_rip], rax
    mov  [rel df_saved_rsp], rsp        ; the sane stack the handler must restore
    mov  byte [rel df_expect], 1
    mov  rax, 0x8000000000000000        ; non-canonical
    mov  rsp, rax
    push rax                            ; #SS(0) -> delivery fails -> #DF via IST1
    ; fall-through only if NO fault fired -> IST/#DF plumbing is broken.
    ; RSP is still non-canonical here, so even reporting is unsafe — restore first.
    mov  rsp, [rel df_saved_rsp]
    mov  byte [rel df_expect], 0
    lea  rdi, [rel str_df_broken]
    call serial_string
    ret
.recover:
    mov  byte [rel df_expect], 0        ; belt-and-suspenders (handler already cleared it)
    mov  byte [rel idt_m_df], 1         ; earned flag (BOOTLOG projection reads this)
    lea  rdi, [rel str_df_contained]    ; reached ONLY via trap+IST+stack-fix+resume
    call serial_string
    ret

; ---- wx_selftest: DESTRUCTIVE W^X proof — executing an NX page must #PF ------
; Jumps into an owned page that lands in an NX 2 MiB mapping; the instruction
; FETCH faults (NX), the #PF handler redirects to .recover. Proves W^X (the NX
; half) is hardware-enforced, not just configured. Reaching .recover = enforced;
; falling through the jmp = NX broken; page <2 MiB (X region) = skipped.
wx_selftest:
    mov  rax, [rel wx_test_page]
    cmp  rax, 0x200000              ; must be in an NX (>=2 MiB) page to test
    jb   .skip
    mov  byte [rax], 0xC3           ; write a byte (page is RW) — also proves W of RW
    lea  rcx, [rel .recover]
    mov  [rel wx_recover_rip], rcx
    mov  byte [rel wx_expecting], 1
    jmp  rax                        ; FETCH from NX page → #PF → handler → .recover
    ; fall-through only if NX did NOT fault — W^X is broken
    mov  byte [rel wx_expecting], 0
    lea  rdi, [rel str_wx_broken]
    call serial_string
    ret
.recover:
    mov  byte [rel wx_expecting], 0
    lea  rdi, [rel str_wx_enforced]
    call serial_string
    ret
.skip:
    lea  rdi, [rel str_wx_skip]
    call serial_string
    ret

; ---- RCQ-42 2b: one-shot #GP fixup for one armed instruction ----------------
; BOOT design (rc-boot 00:11:00, RCQ-42-microcode-apply-20261017): a vendor
; microcode load is a WRMSR the CPU may refuse with #GP. One slot, armed by the
; CPU about to execute it, resumes exactly that instruction once: vector 13,
; the frame RIP equal to the armed RIP, on the arming CPU (local APIC id).
; Anything else (another vector, RIP or CPU, a second fault) is untouched and
; takes isr_common's ordinary diag/panic ladder. Callers serialize use (BSP
; before smp start; APs under one lock), so one slot suffices; a busy slot
; refuses the arm and nothing is written. A fired slot (3) stays held until
; its owner's disarm reads the fault and frees it: freeing it in the handler
; would let another CPU arm in between, and the first owner's disarm would
; then lose its fault and free the second CPU's slot (rc-amd F1).

; idt_gp_fixup_arm(RDI=RIP of the instruction, RSI=resume RIP) -> EAX 1 armed,
; 0 busy. Owner = this CPU. Clobbers RAX, RCX, RDX.
idt_gp_fixup_arm:
    xor  eax, eax
    mov  dl, 2                          ; 2 = being armed: the handler matches only 1
    lock cmpxchg [rel idt_gp_fixup_armed], dl
    jne  .busy
    call idt_gp_fixup_cpu
    mov  [rel idt_gp_fixup_owner], eax
    mov  [rel idt_gp_fixup_rip], rdi
    mov  [rel idt_gp_fixup_resume], rsi
    mov  byte [rel idt_gp_fixup_fault], 0
    mov  byte [rel idt_gp_fixup_armed], 1   ; published after the fields (x86 store order)
    mov  eax, 1
    ret
.busy:
    xor  eax, eax
    ret

; idt_gp_fixup_disarm -> EAX 1 = the armed instruction faulted and resumed,
; 0 = it did not. The owner calls it after the instruction, faulted or not.
; Clobbers RAX only.
idt_gp_fixup_disarm:
    movzx eax, byte [rel idt_gp_fixup_fault]
    mov  byte [rel idt_gp_fixup_fault], 0
    mov  byte [rel idt_gp_fixup_armed], 0
    ret

; idt_gp_fixup_observe -> EAX the owned slot's observed fault, without freeing
; it. Only the CPU that successfully armed may call, after its exact opcode
; returned and before its disarm. The fired slot remains held. Clobbers RAX
; only. No raw error/RIP is claimed and no global count difference is used.
idt_gp_fixup_observe:
    movzx eax, byte [rel idt_gp_fixup_fault]
    ret

; ---- data (in-image RW for now; migrates to BSS under W^X) ------------------
; NOTE: deliberately NO `dq isr_stub_N` table — absolute symbol values are ORG-0
; offsets, wrong at the ImageBase load VA. Handler addrs come from a fixed-stride
; lea in idt_init instead (the absolute-`dq <symbol>` hazard, MODULES §3.2).
idt_sel:  dw 0
idt_ptr:  dw 0
          dq 0
idt_table: times 256*16 db 0
wx_expecting:   db 0                ; 1 while the W^X self-test expects its #PF
wx_recover_rip: dq 0                ; where the #PF handler resumes for that test
diag_fault_expect:     db 0         ; 1 while core/diag expects a trapped test fault
diag_fault_recover_rip: dq 0        ; where the handler resumes for that trapped fault
panic_recover_expect:  db 0         ; 1 while fault_recover_selftest proves the .panic recover path
panic_recover_rip:     dq 0         ; where .panic resumes for that self-test (instead of reset)
irq_unexpected_count:  dq 0         ; unclaimed hardware interrupts contained and EOIed
irq_unexpected_last:   dq 0         ; most recently contained vector
fault_warmreset_armed: db 0         ; 0 = boot/QEMU (marker only); 1 = bare-metal (real CF9 fire) — set by svc/boot_ab fault_warmreset_arm (9702)
fault_demote_hook:     dq 0         ; 9702: runtime-lea-filled (svc/boot_ab) — clears the CMOS confirmed magic before an armed CF9 fire
fault_inject_ud_expect: db 0        ; live command has armed the recoverable #UD path
fault_inject_ud_seen:   db 0        ; earned only after vector 6 resumes at fault_inject_ud.recover
fault_inject_ud_dumped: db 0        ; earned only when diag_ring_fault commits that live #UD
fault_inject_ud_ok:     db 0        ; sticky this boot: live #UD proof completed with bare-metal arm active
fault_inject_ud_vector: dq 0        ; actual vector copied from the interrupt frame
fault_inject_ud_rip:    dq 0        ; actual faulting RIP copied from the interrupt frame
fault_inject_ud_seq:    dq 0        ; monotonically advances per successful live injection
fault_inject_ud_nonce:  dq 0        ; TSC ^ fault RIP ^ sequence; content-grade receipt
df_expect:             db 0         ; 1 while fault_df_selftest expects its #DF
df_recover_rip:        dq 0         ; where the #DF handler resumes for that test
df_saved_rsp:          dq 0         ; the sane RSP the #DF handler restores into the frame
idt_m_df:              db 0         ; earned: #DF contained this boot (BOOTLOG projection)
idt_gp_fixup_armed:    db 0         ; RCQ-42 one-shot #GP slot: 0 free, 2 being armed, 1 armed, 3 fired
idt_gp_fixup_fault:    db 0         ; 1 once the armed instruction #GP'd and resumed
align 4
idt_gp_fixup_owner:    dd 0         ; local APIC id of the arming CPU
align 8
idt_gp_fixup_rip:      dq 0         ; the armed instruction
idt_gp_fixup_resume:   dq 0         ; where its #GP resumes
idt_gp_fixup_count:    dq 0         ; contained armed #GPs this boot
align 8
cpu_boundary_fault_slots: times 32 dq 0
cpu_boundary_fault_generation: dd 0
str_idt_loaded: db "[PAOS64] M1 IDT: 256 gates loaded (lidt)", 13, 10, 0
str_idt_ok:     db "[PAOS64] M1 IDT: int3 trap caught + returned", 13, 10, 0
str_wx_enforced: db "[PAOS64] M1 W^X-enforce: exec-data #PF caught (NX is live)", 13, 10, 0
str_wx_broken:   db "[PAOS64] M1 W^X-enforce: FAILED — NX did not fault", 13, 10, 0
str_wx_skip:     db "[PAOS64] M1 W^X-enforce: skipped (test page <2MiB)", 13, 10, 0
str_fc_ud:       db "[PAOS64] M1 fault-contain: #UD (ud2) trapped+recovered — degraded, not fatal [fault.contain.ud]", 13, 10, 0
str_fc_ud_baremetal: db "[PAOS64] M1 fault-contain: live #UD trapped+recovered on bare metal [fault.contain.ud.baremetal]", 13, 10, 0
str_fc_broken:   db "[PAOS64] M1 fault-contain: FAILED — #UD did not fault (handler broken)", 13, 10, 0
str_fault_recover: db "[PAOS64] fault-recover: uncontained fault -> diag-dump + gated warm reset (not a hang) [fault.recover.warmreset]", 13, 10, 0
str_fr_broken:   db "[PAOS64] fault-recover: FAILED — armed #DE did not fault (panic path broken)", 13, 10, 0
str_df_contained: db "[PAOS64] M1 fault-contain: #DF on IST1 trapped + broken-stack fixed + resumed [fault.contain.df]", 13, 10, 0
str_df_broken:   db "[PAOS64] M1 fault-contain: FAILED — broken-stack push did not #DF (IST plumbing broken)", 13, 10, 0
str_exc:  db "[PAOS64] EXC v=", 0
str_err:  db " err=", 0
str_rip:  db " rip=", 0
str_cr2:  db " cr2=", 0
str_nl:   db 13, 10, 0
