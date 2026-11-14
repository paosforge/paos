;; MODULE boot/serial
;; LAYER 0
;; EXPORTS serial_hp_transmit_probe, boot_pci_cfg_read32, pci_cfg_io_lock, serial_available, serial_mode, serial_uart_lock, serial_init, serial_fault_flush, serial_ax99100_probe, serial_rx_byte, serial_char, serial_string, serial_string_fault, serial_newline, serial_newline_fault, serial_hex64, serial_hex64_fault, serial_deferred_bind, serial_deferred_flush, serial_deferred_finish, serial_deferred_status, serial_tx_state, serial_tx_reason, serial_tx_generation, serial_tx_finish_goal, serial_equivalence_kat, serial_boot_tick, serial_drain_poll, serial_telemetry_try, serial_lock_kat, serial_lock_kat_then_smp, serial_tx_enqueued, serial_tx_drained, serial_tx_count, serial_tx_dropped, serial_tx_drain_tsc, serial_lean_buf
;; IMPORTS boot/smbios
;; CAPS
;; OWNER saga:boot
;; LOCK: serial_uart_lock PROTECTS serial_available, serial_deferred, serial_tx_base, serial_tx_capacity, serial_tx_head, serial_tx_tail, serial_tx_count, serial_tx_enqueued, serial_tx_drained, serial_tx_dropped, serial_tx_drain_tsc, serial_capture_active, serial_capture_base, serial_capture_capacity, serial_capture_pos, serial_tx_state, serial_tx_reason, serial_tx_generation, serial_tx_finish_generation, serial_tx_finish_goal, serial_tx_failed, serial_tx_cost_invalid, serial_tx_flushing, serial_tx_capture_kat, serial_tx_emergency, serial_tx_hold_complete, serial_telemetry_len, serial_telemetry_pos, serial_telemetry_buf
; ============================================================================
; boot/serial.asm — COM1 16550 UART output (115200 8N1).
;
; Ported from the old tree's proven serial path (MIGRATION.md §1) MINUS the
; old accretions: the udp_serial_relay mirror is dropped (that's an L5 service,
; not boot), as is the wedge-probe scaffolding. Pure UART, no dependencies.
;
; M1 NOTE: at first-light this is boot's only output. It likely MOVES to
; core/log.asm (L1) as the canonical log formatter once L1 exists — boot keeps
; only the raw UART poke. Tracked; not done yet.
;
; SD-D FORWARD SEAM: this L0 owner calls core/lock's canonical primitive from
; first-light code already resident in the one-image keep, and calls fmt_* only
; from serial_lock_kat at the post-core redirect in src/paos.asm. The direct
; symbols and their runtime ordering are explicit below.
; ============================================================================

COM1            equ 0x3F8
; Historical LEAN symbol names are retained for the existing buffer ABI. Both
; native detail modes now share this fixed image-owned 64-KiB FIFO. The extra
; 60 KiB absorbs ordinary verbose bursts without heap allocation; full queues
; still apply ordered synchronous backpressure rather than dropping a prefix.
SERIAL_LEAN_CAPACITY equ 65536
SERIAL_TX_POLL_BYTES equ 16
SERIAL_TX_SYNC      equ 0
SERIAL_TX_OPEN      equ 1
SERIAL_TX_SEALED    equ 2
SERIAL_TX_COMPLETE  equ 3
SERIAL_TX_FAILED    equ 4
SERIAL_TX_BUSY      equ 5              ; one-shot API could not acquire ownership
SERIAL_TX_R_NONE    equ 0
SERIAL_TX_R_LOCK    equ 1
SERIAL_TX_R_UART    equ 2
SERIAL_TX_R_ABSENT  equ 3
SERIAL_TX_R_CLOCK   equ 4
SERIAL_TX_R_LOSS    equ 5
SERIAL_TX_R_CAPTURE equ 6
SERIAL_TX_R_INVALID equ 7
SERIAL_TX_R_SLICE   equ 8
; The cooperative drain uses tsc_khz only after P2 binding. Unknown calibration
; falls back to the fixed16-byte cap and reports CLOCK, never a timing claim.

serial_init:
    push rdi
    call serial_uart_lock_acquire
    call serial_init_unlocked
    call serial_uart_lock_release
    pop  rdi
    ret

serial_init_unlocked:
    push rax
    push rdx
    ; HP-PORT-3: the HP EliteDesk 705 G5 (AuthenticAMD AND its SMBIOS identity)
    ; carrying the ASIX AX99100 PCIe UART (it has no legacy 0x3F8) selects the
    ; MMIO UART and never touches COM1. Intel and every other AMD machine return
    ; CF=1 before any PCI access and program COM1 exactly as before.
    call serial_ax99100_probe
    jnc  .present
    mov dx, COM1 + 1                ; IER — disable interrupts
    xor al, al
    out dx, al
    mov dx, COM1 + 3                ; LCR — set DLAB
    mov al, 0x80
    out dx, al
    mov dx, COM1                    ; DLL — divisor 1 (115200)
    mov al, 1
    out dx, al
    mov dx, COM1 + 1                ; DLH
    xor al, al
    out dx, al
    mov dx, COM1 + 3                ; LCR — 8N1, clear DLAB
    mov al, 0x03
    out dx, al
    mov dx, COM1 + 2                ; FCR — enable FIFO, 14-byte threshold
    mov al, 0xC7
    out dx, al
    mov dx, COM1 + 4                ; MCR — RTS + DTR + OUT2
    mov al, 0x0B
    out dx, al
    mov dx, COM1 + 2                ; IIR — 0xFF means no UART
    in  al, dx
    cmp al, 0xFF
    jne .present
    mov byte [rel serial_available], 0
.present:
    pop rdx
    pop rax
    ret

; ---------------------------------------------------------------------------
; serial_ax99100_probe — HP-PORT-3, ported from paos_hp c9755fd2e
;   (src/boot/serial.asm:41-74 there: BAR1 read via CF8/CFC, LSR THRE poll at
;   +0x294, THR at +0x280, dword register spacing). Hardened per paos_hp
;   gauntlet_v2/side_bugs.md 2026-09-11 (the HP tree read BAR1 at a fixed
;   09:00.x WITHOUT an identity check; an absent device masked 0xFFFFFFFF to
;   0xFFFFFFF0 and polled MMIO at 0x1_0000_0284):
;     gate 1: CPUID vendor AuthenticAMD (no PCI access at all otherwise), and
;             gate 1b: the HP SMBIOS identity: another AMD machine, or one
;             whose SMBIOS is unreadable, keeps the legacy COM1 console with
;             no PCI scan;
;     gate 2: PCI vendor:device 125B:9100 at dev 0 of buses 1..255 (a PCIe
;             add-in endpoint; tolerant of bus renumbering by a new card);
;     gate 3: BAR1 is a non-zero, non-all-ones 32-bit memory BAR below 4 GiB;
;     gate 4: LSR.THRE observed within the HP tree's 300000-poll budget.
;   fn0 is tried first, then fn1 (same order as the HP tree; the HP records
;   put the FTDI-wired console on fn0). The UART is NOT reprogrammed — like the
;   HP tree, the preceding stage (HP Manager 533dd5a2 / firmware) owns
;   baud/LCR. Out: CF=0 + serial_mode=1/serial_ax_base set when selected; CF=1
;   otherwise (serial_mode stays 0 = legacy COM1). clobbers: RAX,RDX (saved
;   RBX,RCX,RSI,RDI).
; ---------------------------------------------------------------------------
SERIAL_AX_VIDDID   equ 0x9100125B       ; ASIX AX99100 (vendor 125B, device 9100)
SERIAL_AX_THR      equ 0x280            ; 16550 regs at BAR1+0x280, regshift 2
SERIAL_AX_LSR      equ 0x294
SERIAL_AX_POLL     equ 300000           ; paos_hp c9755fd2e THRE budget

 ; boot_pci_cfg_read32(EAX=encoded CF8 selector)->EAX DWORD, clobbers DX only.
; Layer-0 runtime read rail shared with bus/pci's IRQ-safe cross-CPU lock.
; No callback/serial path while held. Preserves the caller's other registers.
boot_pci_cfg_read32:
    pushfq
    cli
    push rcx
    push rax
.spin:
    mov ecx,1
    xchg ecx,[rel pci_cfg_io_lock]
    test ecx,ecx
    jz .held
    pause
    jmp .spin
.held:
    pop rax
    mov dx,0xcf8
    out dx,eax
    mov dx,0xcfc
    in eax,dx
    mov dword [rel pci_cfg_io_lock],0
    pop rcx
    popfq
    ret

serial_ax99100_probe:
    push rbx
    push rcx
    push rsi
    push rdi
    xor  eax, eax
    cpuid
    cmp  ebx, 0x68747541                ; AuthenticAMD: EBX='Auth'
    jne  .absent
    cmp  edx, 0x69746E65                ; EDX='enti'
    jne  .absent
    cmp  ecx, 0x444D4163                ; ECX='cAMD'
    jne  .absent
    call smbios_hp_quirk_identity       ; gate 1b: the HP identity, not every AMD machine
    test eax, eax
    jz   .absent
    mov  esi, 1                         ; bus
.bus:
    mov  eax, esi
    shl  eax, 16
    or   eax, 0x80000000                ; enable | bus<<16 | dev0 fn0 reg0
    mov  dx, 0xCF8
    out  dx, eax
    mov  dx, 0xCFC
    in   eax, dx
    cmp  eax, SERIAL_AX_VIDDID
    jne  .next_bus
    xor  edi, edi                       ; fn0, then fn1
.fn:
    mov  eax, esi
    shl  eax, 16
    mov  ecx, edi
    shl  ecx, 8
    or   eax, ecx
    or   eax, 0x80000000
    mov  ecx, eax                       ; ECX = this function's CONFIG_ADDRESS
    mov  dx, 0xCF8
    out  dx, eax
    mov  dx, 0xCFC
    in   eax, dx
    cmp  eax, SERIAL_AX_VIDDID          ; the function itself must be an AX99100
    jne  .next_fn
    lea  eax, [ecx + 0x14]              ; BAR1
    mov  dx, 0xCF8
    out  dx, eax
    mov  dx, 0xCFC
    in   eax, dx
    cmp  eax, 0xFFFFFFFF
    je   .next_fn
    test eax, 0x7                       ; memory BAR (bit0=0), 32-bit (type 00)
    jnz  .next_fn
    and  eax, 0xFFFFFFF0
    jz   .next_fn
    mov  ebx, eax                       ; candidate membase (zero-extended)
    mov  ecx, SERIAL_AX_POLL
.thre:
    mov  eax, [rbx + SERIAL_AX_LSR]
    test al, 0x20                       ; THRE
    jnz  .selected
    dec  ecx
    jnz  .thre
.next_fn:
    inc  edi
    cmp  edi, 2
    jb   .fn
.next_bus:
    inc  esi
    cmp  esi, 256
    jb   .bus
.absent:
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rbx
    stc
    ret
.selected:
    mov  [rel serial_ax_base], rbx
    mov  byte [rel serial_mode], 1
    mov  byte [rel serial_available], 1
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rbx
    clc
    ret

; serial_ax_tx(DIL=byte) — HP-PORT-3 MMIO emitter (the HP tree's .sc_wait /
;   .sc_write): bounded THRE wait, then a dword store to THR; drop on timeout,
;   never hang. clobbers: RAX (saved RCX,RDX).
serial_ax_tx:
    push rcx
    push rdx
    mov  rdx, [rel serial_ax_base]
    mov  ecx, SERIAL_AX_POLL
.wait:
    mov  eax, [rdx + SERIAL_AX_LSR]
    test al, 0x20                       ; THRE
    jnz  .write
    dec  ecx
    jnz  .wait
    stc
    jmp  .out                           ; timed out — byte was not accepted
.write:
    movzx eax, dil
    mov  [rdx + SERIAL_AX_THR], eax     ; writel char -> THR
    clc
.out:
    pop  rdx
    pop  rcx
    ret

; serial_rx_byte — nonblocking RX from the UART serial_init selected (the HP
;   tree's serial_read_byte). EAX=-1 when empty/unavailable, else the byte.
;   Legacy path = the same LSR.DR/RBR reads command_serial_poll always did.
;   clobbers: RAX (saved RDX).
serial_rx_byte:
    push rdx
    cmp  byte [rel serial_available], 0
    je   .empty
    cmp  byte [rel serial_mode], 1
    je   .ax
    mov  dx, COM1 + 5                   ; LSR
    in   al, dx
    test al, 1                          ; Data Ready
    jz   .empty
    mov  dx, COM1                       ; RBR
    in   al, dx
    movzx eax, al
    jmp  .out
.ax:
    mov  rdx, [rel serial_ax_base]
    mov  eax, [rdx + SERIAL_AX_LSR]
    test al, 1                          ; Data Ready
    jz   .empty
    mov  eax, [rdx + SERIAL_AX_THR]     ; RBR shares the THR offset
    and  eax, 0xFF
    jmp  .out
.empty:
    mov  eax, -1
.out:
    pop  rdx
    ret

; The public writer selects policy from the interrupted-state bit. IF=1 is
; ordinary thread context and may wait for ownership. IF=0 is an IRQ/fault or
; otherwise non-preemptible context: exactly one try, then skip the whole write.
serial_char:
    push rax
    push rdi
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .if0
    call serial_uart_lock_acquire
    mov  rdi, [rsp]
    call serial_char_unlocked
    call serial_uart_lock_release
    jmp  .done
.if0:
    call serial_lock_if0_try
    test eax, eax
    jz   .done
    call serial_if0_begin_unlocked
    mov  rdi, [rsp]
    call serial_char_unlocked
    call serial_if0_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

; Sole byte emitter. The bounded THRE timeout and absent-UART degradation are
; deliberately unchanged; callers own the lock before entering this routine.
serial_char_unlocked:
    push rax
    push rdx
    cmp  byte [rel serial_lock_kat_sentinel_active], 0
    je   .sentinel_done
    lock inc qword [rel serial_lock_sentinel_bytes]
.sentinel_done:
    cmp  byte [rel serial_capture_active], 0
    je   .capture_done
    mov  rax, [rel serial_capture_pos]
    cmp  rax, [rel serial_capture_capacity]
    jae  .capture_full
    add  rax, [rel serial_capture_base]
    mov  [rax], dil
    inc  qword [rel serial_capture_pos]
    jmp  .accepted
.capture_full:
    mov  byte [rel serial_capture_overflow], 1
    stc
    jmp  .out
.capture_done:
    cmp  byte [rel serial_deferred], 0
    je   .sync
.deferred_retry:
    push rcx
    call serial_tx_queue_valid
    test eax, eax
    jz   .invalid
    mov  rcx, [rel serial_tx_count]
    cmp  rcx, [rel serial_tx_capacity]
    jae  .deferred_full
    cmp  qword [rel serial_tx_enqueued], -1
    je   .invalid
    mov  rax, [rel serial_tx_base]
    add  rax, [rel serial_tx_head]
    mov  [rax], dil
    mov  rax, [rel serial_tx_head]
    inc  rax
    cmp  rax, [rel serial_tx_capacity]
    jb   .head_ok
    xor  eax, eax
.head_ok:
    mov  [rel serial_tx_head], rax
    inc  qword [rel serial_tx_count]
    inc  qword [rel serial_tx_enqueued]
    pop  rcx
    jmp  .accepted
.invalid:
    pop  rcx
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_INVALID
    jmp  .lost
.deferred_full:
    pop  rcx
    ; Normal backpressure needs one free slot, not the complete 64-KiB prefix.
    ; A diagnostic retry after a failed emergency flush retains its old complete
    ; prefix policy, including explicit fault callers whose ambient IF is set.
    cmp  byte [rel serial_tx_failed], 0
    jne  .lost
    push rdi
    cmp  byte [rel serial_tx_emergency], 0
    jne  .critical_full
    call serial_deferred_reclaim_unlocked
    jmp  .reclaimed
.critical_full:
    call serial_deferred_flush_unlocked
.reclaimed:
    pop  rdi
    jc   .lost                          ; incoming byte cannot overtake the prefix
    cmp  byte [rel serial_deferred], 0
    je   .sync
    jmp  .deferred_retry
.sync:
    cmp  byte [rel serial_available], 0
    je   .absent
    cmp  byte [rel serial_mode], 1
    jne  .sync_port
    call serial_ax_tx
    jc   .not_sent
    jmp  .accepted
.sync_port:
    push rcx
    mov ecx, 100000                 ; protected bounded timeout unchanged
.wait_thre:
    mov dx, COM1 + 5
    in  al, dx
    test al, 0x20
    jnz .ready
    dec ecx
    jnz .wait_thre
    pop rcx
    jmp .not_sent
.ready:
    mov al, dil
    mov dx, COM1
    out dx, al
    pop rcx
.accepted:
    clc
    jmp  .out
.absent:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_ABSENT
    jmp  .failed_send
.not_sent:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_UART
.failed_send:
    cmp  byte [rel serial_tx_flushing], 1
    je   .pending                       ; queued byte is retained, not lost
.lost:
    call serial_tx_loss_unlocked
.pending:
    stc
.out:
    pop rdx
    pop rax
    ret

; Bind the fixed image-owned FIFO after P2 detail selection, in either mode.
; RDI=canonical image buffer, RSI=SERIAL_LEAN_CAPACITY. Refusal preserves owner.
; EAX=1 bound/0 refused, EDX=reason; no wait for a held lock.
serial_deferred_bind:
    push rbx
    push rdi
    push rsi
    call serial_uart_lock_try_acquire
    test eax, eax
    jz   .busy
    mov  rdi, [rsp + 8]
    mov  rsi, [rsp]
    call serial_deferred_bind_unlocked
    call serial_uart_lock_release
    jmp  .out
.busy:
    mov  edx, SERIAL_TX_R_LOCK
.out:
    pop  rsi
    pop  rdi
    pop  rbx
    ret

serial_deferred_bind_unlocked:
    ; Preserve the existing hypervisor boundary: the QMP harness needs midboot
    ; markers synchronously. No queue is rebound while any owner has pending data.
    push rbx
    mov  eax, 1
    cpuid
    bt   ecx, 31
    pop  rbx
    jc   .refused
    cmp  qword [rel serial_tx_generation], 0
    je   .first_bind
    call serial_tx_queue_valid
    test eax, eax
    jz   .refused
.first_bind:
    cmp  qword [rel serial_tx_count], 0
    jne  .refused
    cmp  byte [rel serial_tx_failed], 0
    jne  .refused
    cmp  qword [rel serial_tx_dropped], 0
    jne  .refused
    cmp  byte [rel serial_capture_active], 0
    jne  .refused
    cmp  qword [rel serial_tx_generation], -1
    je   .refused
    lea  rax, [rel serial_lean_buf]
    cmp  rdi, rax
    jne  .refused                        ; fixed image-owned storage only
    cmp  rsi, SERIAL_LEAN_CAPACITY
    jne  .refused
    mov  [rel serial_tx_base], rdi
    mov  [rel serial_tx_capacity], rsi
    mov  qword [rel serial_tx_head], 0
    mov  qword [rel serial_tx_tail], 0
    ; Lifetime accepted/drained/loss/physical-cost counters never reset on reuse.
    inc  qword [rel serial_tx_generation]
    mov  qword [rel serial_tx_finish_generation], 0
    mov  byte [rel serial_tx_state], SERIAL_TX_OPEN
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_NONE
    mov  byte [rel serial_deferred], 1
    mov  eax, 1
    xor  edx, edx
    ret
.refused:
    xor  eax, eax
    mov  edx, SERIAL_TX_R_INVALID
    ret

; Flush the complete deferred transaction in FIFO order.  The unlocked helper
; temporarily disables enqueue so its calls reach the raw UART/capture sink.
serial_deferred_flush:
    call serial_uart_lock_acquire
    call serial_deferred_flush_unlocked
    call serial_uart_lock_release
    ret

; These entries share the sole synchronous FIFO drain and protected byte
; emitter. One byte is sufficient for normal enqueue and safe for both COM's
; known 16-byte FIFO and AX's unknown geometry. No speculative burst or extra
; readiness poll is needed. Idle drain retains its COM16/AX1 burst geometry.
; CF=0 means the requested prefix was accepted (or no deferred owner remains);
; CF=1 retains the unsent byte. Full flush still succeeds only when empty.
serial_deferred_reclaim_unlocked:
    push r10
    mov  r10d, 1
    call serial_deferred_prefix_unlocked
    pop  r10
    ret

serial_deferred_flush_unlocked:
    push r10
    mov  r10, -1                         ; full prefix, including critical retries
    call serial_deferred_prefix_unlocked
    pop  r10
    ret

serial_deferred_prefix_unlocked:
    cmp  byte [rel serial_deferred], 0
    je   .empty
    call serial_tx_queue_valid
    test eax, eax
    jz   .invalid
    cmp  byte [rel serial_capture_active], 0
    je   .start
    cmp  byte [rel serial_tx_capture_kat], 1
    jne  .capture                       ; only private equivalence KAT may swap the sink
.start:
    mov  byte [rel serial_deferred], 0
    mov  byte [rel serial_tx_flushing], 1
    push rax
    push rcx
    push rdx
    push rdi
    push r8
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r8, rax
.next:
    cmp  qword [rel serial_tx_count], 0
    je   .account
    mov  rax, [rel serial_tx_base]
    add  rax, [rel serial_tx_tail]
    movzx edi, byte [rax]
    call serial_char_unlocked
    jc   .account                       ; no phantom drain on timeout/absence
    mov  rax, [rel serial_tx_tail]
    inc  rax
    cmp  rax, [rel serial_tx_capacity]
    jb   .tail_ok
    xor  eax, eax
.tail_ok:
    mov  [rel serial_tx_tail], rax
    dec  qword [rel serial_tx_count]
    inc  qword [rel serial_tx_drained]
    dec  r10
    jnz  .next
.account:
    call serial_tx_account_unlocked
    mov  byte [rel serial_tx_flushing], 0
    mov  byte [rel serial_deferred], 1
    call serial_tx_settle_unlocked
    pop  r8
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rax
    test r10, r10
    jz   .empty                         ; requested slot reclaimed, backlog retained
    cmp  qword [rel serial_tx_count], 0
    jne  .pending
.empty:
    clc
    ret
.capture:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_CAPTURE
.pending:
    stc
    ret
.invalid:
    call serial_tx_invalid_unlocked
    stc
    ret

; Normal finish seals once, without UART reads/writes, backlog walk or waiting
; for another owner. Later writers join the same FIFO until real drain completes.
; EAX=state (BUSY if not acquired), EDX=reason. R8=generation and R9=sealed
; goal are valid only after ownership was acquired. COMPLETE means all queued
; bytes accepted by THR; it is not TEMT/wire-idle or remote receipt.
serial_deferred_finish:
    push rbx
    call serial_uart_lock_try_acquire
    test eax, eax
    jz   .busy
    cmp  byte [rel serial_deferred], 0
    je   .status
    call serial_tx_queue_valid
    test eax, eax
    jz   .invalid
    mov  rax, [rel serial_tx_generation]
    cmp  [rel serial_tx_finish_generation], rax
    je   .settle
    mov  [rel serial_tx_finish_generation], rax
    mov  rax, [rel serial_tx_enqueued]
    mov  [rel serial_tx_finish_goal], rax
    cmp  byte [rel serial_tx_failed], 0
    jne  .settle
    mov  byte [rel serial_tx_state], SERIAL_TX_SEALED
.settle:
    call serial_tx_settle_unlocked
    jmp  .status
.invalid:
    call serial_tx_invalid_unlocked
.status:
    call serial_tx_status_unlocked
    call serial_uart_lock_release
    pop  rbx
    ret
.busy:
    mov  eax, SERIAL_TX_BUSY
    mov  edx, SERIAL_TX_R_LOCK
    pop  rbx
    ret

serial_deferred_status:
    push rbx
    call serial_uart_lock_try_acquire
    test eax, eax
    jz   .busy
    call serial_tx_status_unlocked
    call serial_uart_lock_release
    pop  rbx
    ret
.busy:
    mov  eax, SERIAL_TX_BUSY
    mov  edx, SERIAL_TX_R_LOCK
    pop  rbx
    ret

serial_tx_status_unlocked:
    movzx eax, byte [rel serial_tx_state]
    movzx edx, byte [rel serial_tx_reason]
    mov  r8, [rel serial_tx_generation]
    mov  r9, [rel serial_tx_finish_goal]
    ret

; Startup progress before the idle loop exists. IRQ0 already saves all GP
; context and keeps IF clear. Never wait behind the writer it interrupted.
; These unlocked reads are only skip hints: the canonical drain validates the
; queue/capture/sink again under the UART owner. Skip hints may defer service.
; Native binding alone enables this; hypervisor injection stays synchronous.
; It keeps draining after the seal (P5..sign-in), so no writer meets a backlog
; flush. It never settles COMPLETE: that ends deferral for good, so the idle
; drain alone takes it. Finish generation/goal and idle ownership are unchanged.
serial_boot_tick:
    ; Resident telemetry must share startup's hold-complete guard. Only the
    ; post-deferral path may use the ordinary drain that settles COMPLETE.
    cmp  byte [rel serial_deferred], 0
    jne  .prefix
    cmp  qword [rel serial_telemetry_len], 0
    jne  serial_drain_poll             ; telemetry-only progress after startup
    ret
.prefix:
    cmp  byte [rel serial_tx_state], SERIAL_TX_OPEN
    je   .live
    cmp  byte [rel serial_tx_state], SERIAL_TX_SEALED
    jne  .ret
.live:
    cmp  qword [rel serial_tx_count], 0
    jne  .work
    cmp  qword [rel serial_telemetry_len], 0
    je   .ret
.work:
    push rax
    push rdi
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .if0
    call serial_uart_lock_try_acquire   ; same one-try owner rail as serial_drain_poll
    test eax, eax
    jz   .skip
    call serial_boot_tick_drain_unlocked
    call serial_uart_lock_release
    jmp  .skip
.if0:
    call serial_lock_if0_try            ; IRQ context: one try, never wait
    test eax, eax
    jz   .skip
    call serial_boot_tick_drain_unlocked
    call serial_lock_try_release
.skip:
    pop  rdi
    pop  rax
.ret:
    ret

serial_boot_tick_drain_unlocked:
    mov  byte [rel serial_tx_hold_complete], 1
    call serial_drain_poll_unlocked
    call serial_telemetry_drain_unlocked
    mov  byte [rel serial_tx_hold_complete], 0
    ret

; One bounded quantum. IF=0 retains the existing one-shot ownership rail;
; IF=1 now also tries once, so idle/finish never spin behind another writer.
serial_drain_poll:
    push rax
    push rdi
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .if0
    call serial_uart_lock_try_acquire
    test eax, eax
    jz   .done
    call serial_drain_poll_unlocked
    call serial_telemetry_drain_unlocked
    call serial_uart_lock_release
    jmp  .done
.if0:
    call serial_lock_if0_try
    test eax, eax
    jz   .done
    call serial_drain_poll_unlocked
    call serial_telemetry_drain_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

; Best-effort resident diagnostics, separate from boot completion accounting.
; RDI=bytes, RSI=length (1..640), EAX=1 queued/0 dropped. One lock try, no
; UART access, prefix flush, waiting, FIFO reopen, allocation or readiness effect.
; One fixed pending line; a slow/absent sink cannot stall its producer.
serial_telemetry_try:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    call serial_uart_lock_try_acquire
    test eax, eax
    jz   .out
    push rbx
    xor  ebx, ebx                       ; result
    test r12, r12
    jz   .release
    cmp  r12, 640
    ja   .release
    cmp  qword [rel serial_telemetry_len], 0
    jne  .release
    cmp  byte [rel serial_available], 0
    je   .release
    mov  rsi, [rsp]
    lea  rdi, [rel serial_telemetry_buf]
    mov  rcx, r12
    rep movsb
    mov  qword [rel serial_telemetry_pos], 0
    mov  [rel serial_telemetry_len], r12
    mov  ebx, 1
.release:
    call serial_uart_lock_release
    mov  eax, ebx
    add  rsp, 8
.out:
    pop  r12
    pop  rbx
    ret

; Called only under the existing UART lock after its boot-prefix quantum.
; At most16 byte attempts, one LSR read each, ZERO wait/retry. Prefix priority;
; telemetry may be delayed/dropped/interleaved, never treated as health proof.
serial_telemetry_drain_unlocked:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    cmp  qword [rel serial_tx_count], 0
    jne  .out
    cmp  qword [rel serial_telemetry_len], 0
    je   .out
    cmp  byte [rel serial_available], 0
    je   .clear
    mov  ecx, 16
.next:
    mov  rsi, [rel serial_telemetry_pos]
    cmp  rsi, [rel serial_telemetry_len]
    jae  .clear
    cmp  byte [rel serial_capture_active], 0
    jne  .capture
    cmp  byte [rel serial_mode], 1
    jne  .port
    mov  rdx, [rel serial_ax_base]
    mov  eax, [rdx + SERIAL_AX_LSR]
    test al, 0x20
    jz   .out
    lea  rdi, [rel serial_telemetry_buf]
    movzx eax, byte [rdi + rsi]
    mov  [rdx + SERIAL_AX_THR], eax
    jmp  .sent
.port:
    mov  dx, COM1 + 5
    in   al, dx
    test al, 0x20
    jz   .out
    lea  rdi, [rel serial_telemetry_buf]
    mov  al, [rdi + rsi]
    mov  dx, COM1
    out  dx, al
    jmp  .sent
.capture:
    mov  rax, [rel serial_capture_pos]
    cmp  rax, [rel serial_capture_capacity]
    jae  .out
    add  rax, [rel serial_capture_base]
    lea  rdi, [rel serial_telemetry_buf]
    mov  dl, [rdi + rsi]
    mov  [rax], dl
    inc  qword [rel serial_capture_pos]
.sent:
    inc  qword [rel serial_telemetry_pos]
    dec  ecx
    jnz  .next
    mov  rax, [rel serial_telemetry_pos]
    cmp  rax, [rel serial_telemetry_len]
    jb   .out
.clear:
    mov  qword [rel serial_telemetry_len], 0
    mov  qword [rel serial_telemetry_pos], 0
.out:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

serial_drain_poll_unlocked:
    cmp  byte [rel serial_deferred], 0
    je   .ret
    call serial_tx_queue_valid
    test eax, eax
    jz   .invalid
    cmp  byte [rel serial_capture_active], 0
    jne  .capture
    cmp  byte [rel serial_available], 0
    je   .absent
    cmp  qword [rel serial_tx_count], 0
    je   serial_tx_settle_unlocked
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_NONE
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r8, rax
    mov  r9, [rel tsc_khz]
    shr  r9, 2                          ;250us, checked by division, never multiplication
    jnz  .clock_ready
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_CLOCK
.clock_ready:
    mov  r10d, SERIAL_TX_POLL_BYTES
.next:
    cmp  qword [rel serial_tx_count], 0
    je   .account
    cmp  byte [rel serial_mode], 1
    jne  .lsr_port
    mov  rax, [rel serial_ax_base]
    mov  eax, [rax + SERIAL_AX_LSR]
    jmp  .lsr_read
.lsr_port:
    mov  dx, COM1 + 5
    in   al, dx
.lsr_read:
    test al, 0x20
    jz   .uart_busy
    mov  ecx, 16                         ; same known COM FIFO depth
    cmp  byte [rel serial_mode], 1
    jne  .burst
    mov  ecx, 1                          ; unknown AX FIFO: recheck each byte
.burst:
    cmp  qword [rel serial_tx_count], 0
    je   .account
    test r9, r9
    jz   .write
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, r8
    jb   .clock_bad
    cmp  rax, r9
    jae  .slice
.write:
    mov  rax, [rel serial_tx_base]
    add  rax, [rel serial_tx_tail]
    mov  al, [rax]
    cmp  byte [rel serial_mode], 1
    jne  .thr_port
    movzx eax, al
    mov  rdx, [rel serial_ax_base]
    mov  [rdx + SERIAL_AX_THR], eax
    jmp  .thr_done
.thr_port:
    mov  dx, COM1
    out  dx, al
.thr_done:
    mov  rax, [rel serial_tx_tail]
    inc  rax
    cmp  rax, [rel serial_tx_capacity]
    jb   .tail_ok
    xor  eax, eax
.tail_ok:
    mov  [rel serial_tx_tail], rax
    dec  qword [rel serial_tx_count]
    inc  qword [rel serial_tx_drained]
    dec  r10d
    jz   .slice
    dec  ecx
    jnz  .burst
    jmp  .next
.clock_bad:
    mov  byte [rel serial_tx_cost_invalid], 1
    mov  qword [rel serial_tx_drain_tsc], -1
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_CLOCK
    jmp  .account
.uart_busy:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_UART
    jmp  .account
.slice:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_SLICE
.account:
    call serial_tx_account_unlocked
    call serial_tx_settle_unlocked
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rax
.ret:
    ret
.capture:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_CAPTURE
    ret
.absent:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_ABSENT
    ret
.invalid:
    jmp  serial_tx_invalid_unlocked

; Validators and accounting never claim queued bytes were physically accepted.
serial_tx_queue_valid:
    lea  rax, [rel serial_lean_buf]
    cmp  [rel serial_tx_base], rax
    jne  .bad
    cmp  qword [rel serial_tx_capacity], SERIAL_LEAN_CAPACITY
    jne  .bad
    cmp  qword [rel serial_tx_head], SERIAL_LEAN_CAPACITY
    jae  .bad
    cmp  qword [rel serial_tx_tail], SERIAL_LEAN_CAPACITY
    jae  .bad
    cmp  qword [rel serial_tx_count], SERIAL_LEAN_CAPACITY
    ja   .bad
    mov  rax, [rel serial_tx_tail]
    add  rax, [rel serial_tx_count]       ; both bounded, sum <=2*capacity-1
    and  eax, SERIAL_LEAN_CAPACITY - 1
    cmp  rax, [rel serial_tx_head]
    jne  .bad
    mov  rax, [rel serial_tx_enqueued]
    sub  rax, [rel serial_tx_drained]
    jb   .bad
    cmp  rax, [rel serial_tx_count]
    jne  .bad
    cmp  byte [rel serial_tx_state], SERIAL_TX_SEALED
    jne  .valid
    mov  rax, [rel serial_tx_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [rel serial_tx_finish_generation]
    jne  .bad
    mov  rax, [rel serial_tx_finish_goal]
    cmp  rax, [rel serial_tx_enqueued]
    ja   .bad
.valid:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

serial_tx_loss_unlocked:
    cmp  qword [rel serial_tx_dropped], -1
    je   .saturated
    inc  qword [rel serial_tx_dropped]
.saturated:
    mov  byte [rel serial_tx_failed], SERIAL_TX_R_LOSS
    mov  byte [rel serial_tx_state], SERIAL_TX_FAILED
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_LOSS
    ret

serial_tx_invalid_unlocked:
    mov  byte [rel serial_tx_failed], SERIAL_TX_R_INVALID
    mov  byte [rel serial_tx_state], SERIAL_TX_FAILED
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_INVALID
    ret

serial_tx_account_unlocked:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, r8
    jb   .bad
    test rax, rax
    jz   .bad
    add  rax, [rel serial_tx_drain_tsc]
    jc   .bad
    cmp  byte [rel serial_tx_cost_invalid], 0
    jne  .bad
    mov  [rel serial_tx_drain_tsc], rax
    cmp  qword [rel tsc_khz], 4
    jb   .unknown
    ret
.bad:
    mov  qword [rel serial_tx_drain_tsc], -1
    mov  byte [rel serial_tx_cost_invalid], 1
.unknown:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_CLOCK
    ret

serial_tx_settle_unlocked:
    cmp  qword [rel serial_tx_dropped], 0
    je   .loss_checked
    mov  byte [rel serial_tx_failed], SERIAL_TX_R_LOSS
.loss_checked:
    cmp  byte [rel serial_tx_failed], 0
    jne  .failed
    cmp  byte [rel serial_tx_state], SERIAL_TX_SEALED
    jne  .ret
    cmp  qword [rel serial_tx_count], 0
    jne  .ret
    cmp  byte [rel serial_capture_active], 0
    jne  .ret
    cmp  byte [rel serial_tx_hold_complete], 0
    jne  .ret                           ; boot tick drains; only idle/explicit drains settle
    mov  byte [rel serial_deferred], 0
    mov  byte [rel serial_tx_state], SERIAL_TX_COMPLETE
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_NONE
    cmp  byte [rel serial_tx_cost_invalid], 0
    jne  .clock
    cmp  qword [rel tsc_khz], 4
    jae  .ret
.clock:
    mov  byte [rel serial_tx_reason], SERIAL_TX_R_CLOCK
.ret:
    ret
.failed:
    mov  byte [rel serial_tx_state], SERIAL_TX_FAILED
    mov  al, [rel serial_tx_failed]
    mov  [rel serial_tx_reason], al
    ret

; IRQ/fault diagnostic boundary: preserve FIFO prefix then use the original
; synchronous emitter. Its bounded per-byte waits/whole-prefix residual remain.
serial_emergency_begin_unlocked:
    mov  byte [rel serial_tx_emergency], 1
    cmp  byte [rel serial_deferred], 0
    je   .ret
    call serial_deferred_flush_unlocked
    jc   .ret                           ; pending prefix remains owned; no overtaking
    mov  byte [rel serial_deferred], 0
.ret:
    ret

; Early boot also runs with IF=0 before timer_init's first STI. Keep its
; diagnostic boundary synchronous, then resume an OPEN FIFO owner. A SEALED
; owner settles only after the real prefix drain, and cannot be reopened here.
serial_emergency_end_unlocked:
    mov  byte [rel serial_tx_emergency], 0
    cmp  byte [rel serial_tx_state], SERIAL_TX_OPEN
    jne  .ret
    cmp  byte [rel serial_tx_failed], 0
    jne  .ret
    mov  byte [rel serial_deferred], 1
.ret:
    ret

; Ordinary IF=0 output (the boot thread before timer_init's STI, IRQ context).
; While a FIFO owner is live it enqueues like IF=1 output: boot work never waits
; for the UART (root RC-boot-audit-fixes 2026-10-17). With no live queue it keeps
; the synchronous emergency emitter. Explicit *_fault variants and terminal
; paths (serial_fault_flush) still drain the prefix synchronously first.
serial_if0_begin_unlocked:
    cmp  byte [rel serial_deferred], 0
    jne  .ret
    jmp  serial_emergency_begin_unlocked
.ret:
    ret

serial_if0_end_unlocked:
    cmp  byte [rel serial_tx_emergency], 0
    je   .ret
    jmp  serial_emergency_end_unlocked
.ret:
    ret

; serial_fault_flush — terminal fault boundary (panic reset/hang, key-wipe halt).
;   The CPU is about to stop, so queued output can no longer drain later: drain
;   the whole prefix synchronously, one fault-style lock try (a fault inside a
;   held writer skips, as the *_fault emitters do). Preserves all GPRs.
serial_fault_flush:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call serial_lock_fault_try
    test eax, eax
    jz   .done
    call serial_emergency_begin_unlocked
    call serial_emergency_end_unlocked
    call serial_lock_try_release
.done:
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

; One complete null-terminated transaction. It never acquires per byte, so a
; peer cannot splice output into the middle of this string.
serial_string:
    push rax
    push rdi
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .if0
    call serial_uart_lock_acquire
    mov  rdi, [rsp]
    call serial_string_unlocked
    mov  rdi, [rsp]
    call serial_lock_kat_publish_if_ready_unlocked
    call serial_uart_lock_release
    jmp  .done
.if0:
    call serial_lock_if0_try
    test eax, eax
    jz   .done
    call serial_if0_begin_unlocked
    mov  rdi, [rsp]
    call serial_string_unlocked
    mov  rdi, [rsp]
    call serial_lock_kat_publish_if_ready_unlocked
    call serial_if0_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

; Explicit diagnostic/fault projection. This remains nonblocking even if a
; caller invokes it with IF=1 (the KAT exercises that otherwise-rare edge).
serial_string_fault:
    push rax
    push rdi
    call serial_lock_fault_try
    test eax, eax
    jz   .done
    call serial_emergency_begin_unlocked
    mov  rdi, [rsp]
    call serial_string_unlocked
    call serial_emergency_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

; KAT-only normal projection, independent of the ambient IF state.
serial_string_normal:
    push rax
    push rdi
    call serial_uart_lock_acquire
    mov  rdi, [rsp]
    call serial_string_unlocked
    call serial_uart_lock_release
    pop  rdi
    pop  rax
    ret

serial_string_unlocked:
    push rdi
    push rax
.next:
    movzx eax, byte [rdi]
    test al, al
    jz  .done
    push rdi
    mov dil, al
    call serial_char_unlocked
    pop rdi
    inc rdi
    jmp .next
.done:
    pop rax
    pop rdi
    ret

; serial_newline — CR LF
serial_newline:
    push rax
    push rdi
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .if0
    call serial_uart_lock_acquire
    call serial_newline_unlocked
    call serial_uart_lock_release
    jmp  .done
.if0:
    call serial_lock_if0_try
    test eax, eax
    jz   .done
    call serial_if0_begin_unlocked
    call serial_newline_unlocked
    call serial_if0_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

serial_newline_fault:
    push rax
    push rdi
    call serial_lock_fault_try
    test eax, eax
    jz   .done
    call serial_emergency_begin_unlocked
    call serial_newline_unlocked
    call serial_emergency_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

serial_newline_unlocked:
    push rdi
    mov dil, 13
    call serial_char_unlocked
    mov dil, 10
    call serial_char_unlocked
    pop rdi
    ret

; serial_hex64 — print "0x" + 16 hex digits of RDI (fault diagnostics).
; (Temporary home; migrates to core/lib/fmt.asm when L1 lib lands, MODULES §3.)
serial_hex64:
    push rax
    push rdi
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .if0
    call serial_uart_lock_acquire
    mov  rdi, [rsp]
    call serial_hex64_unlocked
    call serial_uart_lock_release
    jmp  .done
.if0:
    call serial_lock_if0_try
    test eax, eax
    jz   .done
    call serial_if0_begin_unlocked
    mov  rdi, [rsp]
    call serial_hex64_unlocked
    call serial_if0_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

serial_hex64_fault:
    push rax
    push rdi
    call serial_lock_fault_try
    test eax, eax
    jz   .done
    call serial_emergency_begin_unlocked
    mov  rdi, [rsp]
    call serial_hex64_unlocked
    call serial_emergency_end_unlocked
    call serial_lock_try_release
.done:
    pop  rdi
    pop  rax
    ret

serial_hex64_unlocked:
    push rax
    push rbx
    push rcx
    mov  rbx, rdi                   ; value (serial_char preserves rbx/rcx/rax/rdi)
    mov  dil, '0'
    call serial_char_unlocked
    mov  dil, 'x'
    call serial_char_unlocked
    mov  ecx, 16                    ; 16 nibbles, high-to-low
.nib:
    rol  rbx, 4
    mov  al, bl
    and  al, 0x0F
    cmp  al, 10
    jb   .dec
    add  al, 'A' - 10
    jmp  .emit
.dec:
    add  al, '0'
.emit:
    movzx edi, al
    call serial_char_unlocked
    dec  ecx
    jnz  .nib
    pop  rcx
    pop  rbx
    pop  rax
    ret

; Thin serial-owned wrappers: the blocking and one-shot algorithms remain
; canonical in core/lock.asm. Only the owner counters and lock address live
; here. The try paths contain no retry edge by construction.
serial_uart_lock_acquire:
    lea  rdi, [rel serial_uart_lock]
    call spin_acquire
    lock inc qword [rel serial_lock_normal_acquires]
    ret

serial_uart_lock_try_acquire:
    lea  rdi, [rel serial_uart_lock]
    call spin_try_acquire
    test eax, eax
    jz   .out
    lock inc qword [rel serial_lock_normal_acquires]
.out:
    ret

serial_uart_lock_release:
    lock inc qword [rel serial_lock_normal_releases]
    lea  rdi, [rel serial_uart_lock]
    jmp  spin_release

serial_lock_if0_try:
    lock inc qword [rel serial_lock_if0_attempts]
    lea  rdi, [rel serial_uart_lock]
    call spin_try_acquire
    test eax, eax
    jnz  .done
    lock inc qword [rel serial_lock_if0_skips]
.done:
    ret

serial_lock_fault_try:
    lock inc qword [rel serial_lock_fault_attempts]
    lea  rdi, [rel serial_uart_lock]
    call spin_try_acquire
    test eax, eax
    jnz  .done
    lock inc qword [rel serial_lock_fault_skips]
.done:
    ret

serial_lock_try_release:
    lea  rdi, [rel serial_uart_lock]
    jmp  spin_release

; The KAT runs at the post-core/pre-AP seam, but its two new evidence lines are
; held until the existing live-link marker is emitted. That keeps every prior
; serial byte in place and makes the probe's NIC_LINK=1 token an earned report,
; not a prediction made before e1000e initialization.
serial_lock_kat:
    push rbx
    push r12
    cmp  byte [rel serial_uart_lock], 0
    jne  .out
    mov  byte [rel serial_lock_kat_passed], 0
    mov  byte [rel serial_lock_kat_published], 0
    mov  qword [rel serial_lock_normal_acquires], 0
    mov  qword [rel serial_lock_normal_releases], 0
    mov  qword [rel serial_lock_if0_attempts], 0
    mov  qword [rel serial_lock_if0_skips], 0
    mov  qword [rel serial_lock_fault_attempts], 0
    mov  qword [rel serial_lock_fault_skips], 0
    mov  qword [rel serial_lock_nested_spins], 0
    mov  qword [rel serial_lock_sentinel_bytes], 0

    ; Hold UART ownership while both nonblocking projections attempt nested
    ; writes. IF is restored exactly; neither path may reach the byte emitter.
    call serial_uart_lock_acquire
    mov  byte [rel serial_lock_kat_sentinel_active], 1
    pushfq
    cli
    lea  rdi, [rel serial_lock_kat_if0_sentinel]
    call serial_string
    popfq
    lea  rdi, [rel serial_lock_kat_fault_sentinel]
    call serial_string_fault
    mov  byte [rel serial_lock_kat_sentinel_active], 0
    call serial_uart_lock_release

    ; Exercise the ordinary complete-string path independently of ambient IF.
    lea  rdi, [rel serial_lock_kat_empty]
    call serial_string_normal

    cmp  qword [rel serial_lock_normal_acquires], 0
    je   .out
    mov  rax, [rel serial_lock_normal_acquires]
    cmp  rax, [rel serial_lock_normal_releases]
    jne  .out
    cmp  qword [rel serial_lock_if0_attempts], 0
    je   .out
    mov  rax, [rel serial_lock_if0_attempts]
    cmp  rax, [rel serial_lock_if0_skips]
    jne  .out
    cmp  qword [rel serial_lock_fault_attempts], 0
    je   .out
    mov  rax, [rel serial_lock_fault_attempts]
    cmp  rax, [rel serial_lock_fault_skips]
    jne  .out
    cmp  qword [rel serial_lock_nested_spins], 0
    jne  .out
    cmp  qword [rel serial_lock_sentinel_bytes], 0
    jne  .out
    cmp  byte [rel serial_uart_lock], 0
    jne  .out

    rdtsc
    shl  rdx, 32
    or   rax, rdx
    test rax, rax
    jnz  .nonce_ok
    inc  rax
.nonce_ok:
    mov  [rel serial_lock_kat_nonce], rax
    lea  r12, [rel serial_lock_kat_row]

    lea  rdi, [rel serial_lock_kat_pfx]
    call .append_str
    mov  rdi, [rel serial_lock_kat_nonce]
    mov  rsi, r12
    mov  edx, 16
    call fmt_hex
    add  r12, rax
    lea  rdi, [rel serial_lock_kat_manifest]
    call .append_str
    mov  rdi, [rel serial_lock_normal_acquires]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_release]
    call .append_str
    mov  rdi, [rel serial_lock_normal_releases]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_if0_attempts]
    call .append_str
    mov  rdi, [rel serial_lock_if0_attempts]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_if0_skips]
    call .append_str
    mov  rdi, [rel serial_lock_if0_skips]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_fault_attempts]
    call .append_str
    mov  rdi, [rel serial_lock_fault_attempts]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_fault_skips]
    call .append_str
    mov  rdi, [rel serial_lock_fault_skips]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_nested_spins]
    call .append_str
    mov  rdi, [rel serial_lock_nested_spins]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_sentinel_bytes]
    call .append_str
    mov  rdi, [rel serial_lock_sentinel_bytes]
    call .append_dec
    lea  rdi, [rel serial_lock_kat_eol]
    call .append_str
    mov  byte [rel serial_lock_kat_passed], 1
.out:
    mov  byte [rel serial_lock_kat_sentinel_active], 0
    pop  r12
    pop  rbx
    ret

.append_str:
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    ret

.append_dec:
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    ret

; Called only with the UART lock held and only after the caller's original
; string was emitted. Pointer identity binds publication to the existing
; e1000e live-link verdict; the one-shot byte suppresses replay.
serial_lock_kat_publish_if_ready_unlocked:
    cmp  byte [rel serial_lock_kat_passed], 1
    jne  .out
    cmp  byte [rel serial_lock_kat_published], 0
    jne  .out
    lea  rax, [rel str_p8_ready_nic]
    cmp  rdi, rax
    jne  .out
    mov  byte [rel serial_lock_kat_published], 1
    lea  rdi, [rel serial_lock_kat_row]
    call serial_string_unlocked
    lea  rdi, [rel serial_lock_kat_marker]
    call serial_string_unlocked
.out:
    ret

; Header's established SMP seam lands here after the L1 core tests. The UART
; KAT therefore uses the canonical core primitive while still running before
; ACPI discovery and AP startup, then preserves the existing chain unchanged.
serial_lock_kat_then_smp:
    call serial_lock_kat
    jmp  smp_selftest_after_acpi

; QEMU-only byte-equivalence KAT over the actual serial_char_unlocked branches.
; VERBOSE writes to the capture sink directly; LEAN enqueues the same strings in
; the production 64-KiB ring and drains them to a second capture sink.
serial_equivalence_kat:
    push r12
    push rbx
    mov  eax, 1
    cpuid
    bt   ecx, 31
    pop  rbx
    jnc  .ret

    ; The boot can have live APs by P6.  Hold the canonical UART lock across
    ; the temporary sink swap, and restore every production counter/pointer
    ; before publishing the verdict.
    call serial_uart_lock_acquire
    call serial_equivalence_kat_save
    cmp  byte [rel serial_kat_saved_deferred], 0
    jne  .bad
    cmp  qword [rel serial_kat_saved_tx_count], 0
    jne  .bad
    cmp  byte [rel serial_kat_saved_capture_active], 0
    jne  .bad

    mov  byte [rel serial_tx_capture_kat], 1
    mov  byte [rel serial_tx_state], SERIAL_TX_OPEN
    mov  byte [rel serial_tx_failed], 0
    mov  byte [rel serial_deferred], 0
    lea  rax, [rel serial_equiv_verbose]
    mov  [rel serial_capture_base], rax
    mov  qword [rel serial_capture_capacity], 256
    mov  qword [rel serial_capture_pos], 0
    mov  byte [rel serial_capture_overflow], 0
    mov  byte [rel serial_capture_active], 1
    lea  rdi, [rel serial_equiv_a]
    call serial_string_unlocked
    lea  rdi, [rel serial_equiv_b]
    call serial_string_unlocked
    mov  r12, [rel serial_capture_pos]
    cmp  r12, SERIAL_EQUIV_EXPECTED_LEN
    jne  .bad

    mov  byte [rel serial_capture_active], 0
    lea  rax, [rel serial_lean_buf]
    mov  [rel serial_tx_base], rax
    mov  qword [rel serial_tx_capacity], SERIAL_LEAN_CAPACITY
    mov  qword [rel serial_tx_head], 0
    mov  qword [rel serial_tx_tail], 0
    mov  qword [rel serial_tx_count], 0
    mov  qword [rel serial_tx_enqueued], 0
    mov  qword [rel serial_tx_drained], 0
    mov  qword [rel serial_tx_dropped], 0
    mov  qword [rel serial_tx_drain_tsc], 0
    mov  byte [rel serial_deferred], 1
    lea  rdi, [rel serial_equiv_a]
    call serial_string_unlocked
    lea  rdi, [rel serial_equiv_b]
    call serial_string_unlocked

    lea  rax, [rel serial_equiv_lean]
    mov  [rel serial_capture_base], rax
    mov  qword [rel serial_capture_capacity], 256
    mov  qword [rel serial_capture_pos], 0
    mov  byte [rel serial_capture_overflow], 0
    mov  byte [rel serial_capture_active], 1
    call serial_deferred_flush_unlocked
    mov  byte [rel serial_deferred], 0

    cmp  byte [rel serial_capture_overflow], 0
    jne  .bad
    cmp  [rel serial_capture_pos], r12
    jne  .bad
    lea  rdi, [rel serial_equiv_verbose]
    lea  rsi, [rel serial_equiv_lean]
    mov  rdx, r12
    call memcmp
    test rax, rax
    jnz  .bad
    call serial_equivalence_kat_reset
    call serial_uart_lock_release
    lea  rdi, [rel serial_equiv_pass]
    call serial_string
    jmp  .ret
.bad:
    call serial_equivalence_kat_reset
    call serial_uart_lock_release
    lea  rdi, [rel serial_equiv_fail]
    call serial_string
.ret:
    pop  r12
    ret

serial_equivalence_kat_save:
    mov  al, [rel serial_deferred]
    mov  [rel serial_kat_saved_deferred], al
    mov  al, [rel serial_capture_active]
    mov  [rel serial_kat_saved_capture_active], al
    mov  al, [rel serial_capture_overflow]
    mov  [rel serial_kat_saved_capture_overflow], al
    mov  rax, [rel serial_tx_base]
    mov  [rel serial_kat_saved_tx_base], rax
    mov  rax, [rel serial_tx_capacity]
    mov  [rel serial_kat_saved_tx_capacity], rax
    mov  rax, [rel serial_tx_head]
    mov  [rel serial_kat_saved_tx_head], rax
    mov  rax, [rel serial_tx_tail]
    mov  [rel serial_kat_saved_tx_tail], rax
    mov  rax, [rel serial_tx_count]
    mov  [rel serial_kat_saved_tx_count], rax
    mov  rax, [rel serial_tx_enqueued]
    mov  [rel serial_kat_saved_tx_enqueued], rax
    mov  rax, [rel serial_tx_drained]
    mov  [rel serial_kat_saved_tx_drained], rax
    mov  rax, [rel serial_tx_dropped]
    mov  [rel serial_kat_saved_tx_dropped], rax
    mov  rax, [rel serial_tx_drain_tsc]
    mov  [rel serial_kat_saved_tx_drain_tsc], rax
    mov  rax, [rel serial_capture_base]
    mov  [rel serial_kat_saved_capture_base], rax
    mov  rax, [rel serial_capture_capacity]
    mov  [rel serial_kat_saved_capture_capacity], rax
    mov  rax, [rel serial_capture_pos]
    mov  [rel serial_kat_saved_capture_pos], rax
    mov  al, [rel serial_tx_state]
    mov  [rel serial_kat_saved_tx_state], al
    mov  al, [rel serial_tx_reason]
    mov  [rel serial_kat_saved_tx_reason], al
    mov  al, [rel serial_tx_failed]
    mov  [rel serial_kat_saved_tx_failed], al
    mov  al, [rel serial_tx_cost_invalid]
    mov  [rel serial_kat_saved_tx_cost_invalid], al
    mov  al, [rel serial_tx_flushing]
    mov  [rel serial_kat_saved_tx_flushing], al
    mov  al, [rel serial_tx_capture_kat]
    mov  [rel serial_kat_saved_tx_capture_kat], al
    mov  rax, [rel serial_tx_generation]
    mov  [rel serial_kat_saved_tx_generation], rax
    mov  rax, [rel serial_tx_finish_generation]
    mov  [rel serial_kat_saved_tx_finish_generation], rax
    mov  rax, [rel serial_tx_finish_goal]
    mov  [rel serial_kat_saved_tx_finish_goal], rax
    ret

serial_equivalence_kat_reset:
    mov  al, [rel serial_kat_saved_capture_active]
    mov  [rel serial_capture_active], al
    mov  al, [rel serial_kat_saved_capture_overflow]
    mov  [rel serial_capture_overflow], al
    mov  al, [rel serial_kat_saved_deferred]
    mov  [rel serial_deferred], al
    mov  rax, [rel serial_kat_saved_capture_base]
    mov  [rel serial_capture_base], rax
    mov  rax, [rel serial_kat_saved_capture_capacity]
    mov  [rel serial_capture_capacity], rax
    mov  rax, [rel serial_kat_saved_capture_pos]
    mov  [rel serial_capture_pos], rax
    mov  rax, [rel serial_kat_saved_tx_base]
    mov  [rel serial_tx_base], rax
    mov  rax, [rel serial_kat_saved_tx_capacity]
    mov  [rel serial_tx_capacity], rax
    mov  rax, [rel serial_kat_saved_tx_head]
    mov  [rel serial_tx_head], rax
    mov  rax, [rel serial_kat_saved_tx_tail]
    mov  [rel serial_tx_tail], rax
    mov  rax, [rel serial_kat_saved_tx_count]
    mov  [rel serial_tx_count], rax
    mov  rax, [rel serial_kat_saved_tx_enqueued]
    mov  [rel serial_tx_enqueued], rax
    mov  rax, [rel serial_kat_saved_tx_drained]
    mov  [rel serial_tx_drained], rax
    mov  rax, [rel serial_kat_saved_tx_dropped]
    mov  [rel serial_tx_dropped], rax
    mov  rax, [rel serial_kat_saved_tx_drain_tsc]
    mov  [rel serial_tx_drain_tsc], rax
    mov  al, [rel serial_kat_saved_tx_state]
    mov  [rel serial_tx_state], al
    mov  al, [rel serial_kat_saved_tx_reason]
    mov  [rel serial_tx_reason], al
    mov  al, [rel serial_kat_saved_tx_failed]
    mov  [rel serial_tx_failed], al
    mov  al, [rel serial_kat_saved_tx_cost_invalid]
    mov  [rel serial_tx_cost_invalid], al
    mov  al, [rel serial_kat_saved_tx_flushing]
    mov  [rel serial_tx_flushing], al
    mov  al, [rel serial_kat_saved_tx_capture_kat]
    mov  [rel serial_tx_capture_kat], al
    mov  rax, [rel serial_kat_saved_tx_generation]
    mov  [rel serial_tx_generation], rax
    mov  rax, [rel serial_kat_saved_tx_finish_generation]
    mov  [rel serial_tx_finish_generation], rax
    mov  rax, [rel serial_kat_saved_tx_finish_goal]
    mov  [rel serial_tx_finish_goal], rax
    ret

section .text                       ; (no-op: keep following content in .text)

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_serial 0
align 8
pci_cfg_io_lock: dd 0
align 8
serial_telemetry_len: dq 0
serial_telemetry_pos: dq 0
serial_telemetry_buf: times 640 db 0
serial_available: db 1              ; cleared by serial_init if IIR reads 0xFF
                                    ; (migrates to the BSS region under W^X, with paging)
serial_tx_state: db SERIAL_TX_SYNC
serial_tx_reason: db SERIAL_TX_R_NONE
serial_tx_failed: db 0             ; sticky failure reason, not transient poll outcome
serial_tx_cost_invalid: db 0
serial_tx_flushing: db 0
serial_tx_emergency: db 0                ; lock-owned begin/end context, never ambient IF
serial_tx_hold_complete: db 0            ; lock-owned: set only around the boot-tick drain
serial_tx_capture_kat: db 0
align 8
serial_tx_generation: dq 0
serial_tx_finish_generation: dq 0
serial_tx_finish_goal: dq 0
serial_deferred:   db 0
serial_mode:       db 0             ; HP-PORT-3: 0 = legacy COM1 0x3F8, 1 = AX99100 MMIO
serial_capture_active: db 0
serial_capture_overflow: db 0
serial_uart_lock:  db 0
serial_lock_kat_sentinel_active: db 0
serial_lock_kat_passed: db 0
serial_lock_kat_published: db 0
align 8
serial_ax_base:     dq 0            ; HP-PORT-3: AX99100 BAR1 (valid iff serial_mode=1)
serial_tx_base:     dq 0
serial_tx_capacity: dq 0
serial_tx_head:     dq 0
serial_tx_tail:     dq 0
serial_tx_count:    dq 0
serial_tx_enqueued: dq 0
serial_tx_drained:  dq 0
serial_tx_dropped:  dq 0
serial_tx_drain_tsc: dq 0
serial_capture_base: dq 0
serial_capture_capacity: dq 0
serial_capture_pos: dq 0
serial_kat_saved_tx_state: db 0
serial_kat_saved_tx_reason: db 0
serial_kat_saved_tx_failed: db 0
serial_kat_saved_tx_cost_invalid: db 0
serial_kat_saved_tx_flushing: db 0
serial_kat_saved_tx_capture_kat: db 0
serial_kat_saved_tx_generation: dq 0
serial_kat_saved_tx_finish_generation: dq 0
serial_kat_saved_tx_finish_goal: dq 0
serial_kat_saved_deferred: db 0
serial_kat_saved_capture_active: db 0
serial_kat_saved_capture_overflow: db 0
align 8
serial_kat_saved_tx_base: dq 0
serial_kat_saved_tx_capacity: dq 0
serial_kat_saved_tx_head: dq 0
serial_kat_saved_tx_tail: dq 0
serial_kat_saved_tx_count: dq 0
serial_kat_saved_tx_enqueued: dq 0
serial_kat_saved_tx_drained: dq 0
serial_kat_saved_tx_dropped: dq 0
serial_kat_saved_tx_drain_tsc: dq 0
serial_kat_saved_capture_base: dq 0
serial_kat_saved_capture_capacity: dq 0
serial_kat_saved_capture_pos: dq 0
serial_lock_normal_acquires: dq 0
serial_lock_normal_releases: dq 0
serial_lock_if0_attempts: dq 0
serial_lock_if0_skips: dq 0
serial_lock_fault_attempts: dq 0
serial_lock_fault_skips: dq 0
serial_lock_nested_spins: dq 0
serial_lock_sentinel_bytes: dq 0
serial_lock_kat_nonce: dq 0
serial_lock_kat_row: times 256 db 0

align 16
serial_lean_buf: times SERIAL_LEAN_CAPACITY db 0
serial_equiv_verbose: times 256 db 0
serial_equiv_lean: times 256 db 0
%endmacro
WDATA_DEFER WDATA_serial

serial_lock_kat_empty: db 0
serial_lock_kat_if0_sentinel: db "IF0_SENTINEL", 0
serial_lock_kat_fault_sentinel: db "FAULT_SENTINEL", 0
serial_lock_kat_pfx: db "SERIALLOCK_V1 nonce=", 0
serial_lock_kat_manifest: db " manifest=declared normal_acquire=", 0
serial_lock_kat_release: db " normal_release=", 0
serial_lock_kat_if0_attempts: db " if0_attempts=", 0
serial_lock_kat_if0_skips: db " if0_skips=", 0
serial_lock_kat_fault_attempts: db " fault_attempts=", 0
serial_lock_kat_fault_skips: db " fault_skips=", 0
serial_lock_kat_nested_spins: db " nested_spins=", 0
serial_lock_kat_sentinel_bytes: db " sentinel_bytes=", 0
serial_lock_kat_eol: db 13, 10, 0
serial_lock_kat_marker:
    db "[PAOS64] serial: UART lock/fault policy KAT PASS [serial.uart.lock.kat] NIC_LINK=1", 13, 10, 0
serial_equiv_a: db "[PAOS64] equivalence-alpha [marker.a]",13,10,0
serial_equiv_a_len equ $ - serial_equiv_a - 1
serial_equiv_b: db "[PAOS64] equivalence-beta [marker.b]",13,10,0
serial_equiv_b_len equ $ - serial_equiv_b - 1
SERIAL_EQUIV_EXPECTED_LEN equ serial_equiv_a_len + serial_equiv_b_len
serial_equiv_pass: db "[PAOS64] P6 svc: lean-verbose serial equivalence KAT PASS [boot.log.equivalence.kat]",13,10,0
serial_equiv_fail: db "[PAOS64] P6 svc: lean-verbose serial equivalence KAT FAIL",13,10,0

%include "boot/serial_hp_probe.inc"
