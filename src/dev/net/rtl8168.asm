;; MODULE dev/net/rtl8168
;; LAYER 3
;; EXPORTS rtl8168_link_rearm_counts, rtl8168_link_live, rtl8168_witness, rtl8168_terminal_quiesce, rtl8168_create, rtl8168_hw_bringup, rtl8168_boot_bringup, rtl8168_status_line, rtl8168_bootlog_line, rtl8168_rx_diag_emit, rtl8168_frame_stats, rtl8168_dev, rtl8168_carrier_ready, rtl8168_carrier_read, rtl8168_carrier_write, rtl8168_carrier_link
;; IMPORTS core/time, boot/native_driver_gate, net/netdev, bus/pci, core/dma, core/heap, boot/serial, dev/net/e1000e, net/dns, core/lib/mem, bus/pci_claim, hv/pci_assign
;; CAPS mmio dma
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
%include "dev/net/realtek_link_rearm.inc"
%include "core/abi/pci_claim.inc" ; RCQ-29 hardware report: bind outcome ids/states
; ============================================================================
; dev/net/rtl8168.asm — bee004: the REAL Realtek RTL8168H (r8169, MAC_VER_46)
; native 1GbE backend. The common payload binds it only from live PCI class,
; vendor/device/revision, and MAC_VER_46 identity. No machine-name, target build,
; or compiled-in MAC is permitted.
;
; Upstream notices (FreeBSD/OpenBSD/NetBSD re(4)): see LICENSES/RTL8168_NOTICES.md.
; Copyright (c) 1997, 1998-2003 Bill Paul <wpaul@windriver.com>. All rights reserved.
; (BSD-4-Clause; the full license text is in LICENSES/RTL8168_NOTICES.md.)
; This product includes software developed by Bill Paul.
;
; WHAT THIS SHIPS (metal grade; QEMU has no RTL model): see the spec.
;   0x0200, BMCR=0x1200). link_status reads live PHYSTS; tx/rx_poll drive the
;   real rings with the Alder Lake clflush discipline (non-coherent DMA snoop).
;   On link-up link_status also RELEASES the DNS bootstrap gate (dns_wire_dhcp_failed)
;   so the :9997 command port answers inside the bounded trial window on the
;   DHCP-less static-address lab box — without editing command_udp.asm/dns.asm (see the
;   link_status comment + VERSIONS v0.0.15).
;
; THE r8169 QUIRK (ESSENCE silent-regression worked example): RX is NON-COHERENT
; DMA — clflush the descriptor before reading OWN, clflush the packet buffer
; before copying, and RE-POST the RxPoll doorbell after recycling or RX silently
; stalls. recover() re-posts RxPoll.
;
; Foreign devices / QEMU: the backend stays HEALTH_DEGRADED and touches no MMIO
; unless strict live identity matches, so egress-select never picks an unbound
; RTL and the e1000e path remains authoritative.
; ============================================================================

; --- RTL8168H register offsets (BAR2-relative), ported from the monolith ------
RTL_IDR0        equ 0x00        ; MAC bytes 0-3
RTL_IDR4        equ 0x04        ; MAC bytes 4-5
RTL_TNPDS       equ 0x20        ; TX Normal Priority Desc Start (low 32)
RTL_TNPDS_HI    equ 0x24        ; TX Normal Priority Desc Start (high 32)
RTL_TPPOLL      equ 0x38        ; TX/RX poll doorbell (byte): NPQ=0x40, RxPoll/FSWInt=0x01
RTL_CMD         equ 0x37        ; Command register (byte): TE|RE
RTL_IMR         equ 0x3C        ; Interrupt Mask (16-bit)
RTL_ISR         equ 0x3E        ; Interrupt Status (16-bit)
RTL_TCR         equ 0x40        ; TX Config
RTL_RCR         equ 0x44        ; RX Config
RTL_RMS         equ 0xDA        ; RX maximum frame size
RTL_RDSAR       equ 0xE4        ; RX Desc Start (low 32)
RTL_RDSAR_HI    equ 0xE8        ; RX Desc Start (high 32)
RTL_PHYSTS      equ 0x6C        ; PHY status (byte): bit1=LinkSts, bit2=10M, bit3=100M, bit4=1000M
RTL_CFG9346     equ 0x50        ; 93C46 config-register lock (0xC0=unlock, 0x00=lock)

RTL_CMD_TE      equ (1 << 2)
RTL_CMD_RE      equ (1 << 3)

; --- v0.1 clean-room bring-up values (sources: spec section 5; FreeBSD/OpenBSD/NetBSD re(4)) ---
RTL_MISC            equ 0xF0                ; MISC (32-bit); bit19 = RXDV gate (8168G and later)
RTL_MISC_RXDV_GATE  equ (1 << 19)
RTL_CFG9346_UNLOCK  equ 0xC0                ; config-register write enable
RTL_CFG9346_LOCKED  equ 0x00                ; normal operation (config registers protected)
; TxConfig: IFG 96-bit (0x03000000) | max TX DMA burst 2048 B (0x700); CRC appended by the MAC.
RTL_TCR_VAL         equ 0x03000700
; RxConfig: no RX FIFO threshold (0xE000) | unlimited RX DMA burst (0x700) | buf-size/early-off
; field (0x1800, covers EARLYOFFV2 0x800) | accept broadcast (0x08) | accept physical match (0x02).
; No promiscuous and no multicast: ARP/DHCP use broadcast, the :9997 path is unicast.
RTL_RCR_VAL         equ 0x0000FF0A
RTL_ISR_ALL         equ 0xFFFF              ; W1C every latched status bit

RTL_NUM_TX_DESC equ 256
RTL_NUM_RX_DESC equ 256
RTL_DESC_SIZE   equ 16
RTL_RX_BUF_SIZE equ 2048
RTL_RX_GHOST_RETRY_SPINS equ 1024         ; bounded late-DMA visibility trial, RTL-only

RTL_VENDOR_ID       equ 0x10EC
RTL_DEVICE_ID       equ 0x8168
RTL_PCI_REVISION    equ 0x15

; MAC_VER_46 identity: TCR(0x40) & 0x7CF00000 == 0x54100000 (RTL8168H/8111H).
RTL_MAC_VER_46_MASK  equ 0x7CF00000
RTL_MAC_VER_46_VALUE equ 0x54100000

; ============================================================================
; rtl8168_create() -> RAX = assigned slot index / -1. Builds the netdev_ops
;   vtable at RUNTIME VAs (lea -> mov; a static `dq rtl8168_init` would bake the
;   org-0 RVA — the PE ImageBase is not applied to baked-in dq symbols), fills
;   the uniform struct dev header at PRIO_NATIVE, and registers with the class
;   core. Registered AFTER e1000e so on QEMU (equal PRIO_NATIVE, first-seen
;   native wins) the e1000e stand-in stays primary; on the Beelink e1000e is
;   absent/degraded and this backend is selected.
; ============================================================================
; One software producer at a time; terminal state2 is irreversible. The
; wrapper retains all argument and return registers except volatile R11/RAX.
%macro RTL8168_PRODUCER 2
    xor eax,eax
    mov r11d,1
    lock cmpxchg [rel rtl8168_terminal_gate],r11d
    jne %%refuse
    call .producer_body
    mov dword [rel rtl8168_terminal_gate],0
    ret
%%refuse:
    mov rax,%2
    ret
%endmacro

rtl8168_create:
    RTL8168_PRODUCER rtl8168_create,-1
.producer_body:
    NATIVE_DRIVER_REFUSE 6
    PCIA_NATIVE_COLD_REFUSE                        ; before first probe or upstream effect
    lea  rdi, [rel rtl8168_ops]
    lea  rax, [rel rtl8168_init]
    mov  [rdi + netdev_ops.init], rax
    lea  rax, [rel rtl8168_start]
    mov  [rdi + netdev_ops.start], rax
    lea  rax, [rel rtl8168_stop]
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel rtl8168_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel rtl8168_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel rtl8168_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel rtl8168_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel rtl8168_recover]
    mov  [rdi + netdev_ops.recover], rax
    lea  rdi, [rel rtl8168_dev]
    lea  rax, [rel rtl8168_ops]
    mov  [rdi + dev.ops], rax
    lea  rax, [rel str_rtl8168_name]
    mov  [rel rtl8168_info + netdev_info.name], rax   ; runtime address (abs_ptr_check)
    lea  rax, [rel rtl8168_info]
    mov  [rdi + dev.info], rax
    mov  qword [rdi + dev.priv], 0
    mov  dword [rdi + dev.prio], PRIO_NATIVE
    mov  dword [rdi + dev.health], HEALTH_DEGRADED
    mov  dword [rdi + dev.class], CLASS_NET
    mov  dword [rdi + dev.flags], 0
    lea  rax, [rel str_rtl8168_name]
    mov  [rdi + dev.name], rax
    call netdev_register
    ret

; ============================================================================
; rtl8168_boot_bringup — the P8 wiring entry (called from guestnet_register_verbs,
;   the allowed same-P8 seam next to e1000e_hw_bringup). Registers the backend
;   degraded, then binds only the exact runtime PCI/MAC identity. Any other class
;   or absent chip remains degraded, so egress-select skips it. Never fatal.
; ============================================================================
rtl8168_boot_bringup:
    RTL8168_PRODUCER rtl8168_boot_bringup,-1
.producer_body:
    NATIVE_DRIVER_REFUSE 6
    call rtl8168_rx_wipe_kat.producer_body               ; w046: in-image ring only, before register/bind
    call rtl8168_create.producer_body                    ; register fail-closed/degraded
    call rtl8168_hw_bringup.producer_body                 ; strict runtime-discovered bind
    cmp  byte [rel rtl8168_bound], 1
    jne  .degrade                           ; absent / wrong identity / bad BAR
    mov  dword [rel rtl8168_dev + dev.health], HEALTH_OK
    ret
.degrade:
    mov  dword [rel rtl8168_dev + dev.health], HEALTH_DEGRADED
    ret

; ============================================================================
; rtl8168_rx_wipe_kat — w046 boot KAT [net.rtl8168.rxwipe.kat]. Drives the REAL
;   rtl8168_rx_poll (same code the bound Beelink runs) over a private one-slot
;   RX/TX rings in this image's WDATA and RAM standing in for BAR2: no
;   MMIO, no PCI, no DMA. Runs from rtl8168_boot_bringup BEFORE rtl8168_create
;   and rtl8168_hw_bringup (single-threaded P8, nothing registered or bound),
;   snapshots every driver global it touches (including link rearm) and restores
;   them byte-for-byte. Private TX stays idle and the private PHY reads up.
;   Cases (each fails on the pre-w046 rx_poll logic, see the katred control):
;     A  delivered frame: content exact; slot dword0 == DEADBEEF and bytes
;        [4, len+4) zero as re-read from RAM after clflush; tail untouched;
;        descriptor recycled OWN|EOR|2048, opts2 cleared, index advanced.
;     B  ghost on the REUSED slot (descriptor complete, payload never written):
;        must be rejected + counted; the stale frame must not be re-delivered.
;     C  frame longer than the caller cap: the WHOLE frame is wiped, not cap.
;   Gated on CPUID.7:EBX.CLFLUSHOPT (rx_poll's recycle uses it; TCG #UDs
;   without it) and on a sub-4-GiB image (rx_poll uses the low 32 address bits).
; ============================================================================
RTL_KAT_LEN_A  equ 300                     ; payload bytes (len+4 is dword-aligned)
RTL_KAT_LEN_C  equ 1200
RTL_KAT_CAP_C  equ 64
RTL_KAT_DESC   equ (1 << 29) | (1 << 28)   ; FirstFrag|LastFrag, OWN clear

rtl8168_rx_wipe_kat:
    RTL8168_PRODUCER rtl8168_rx_wipe_kat,-1
.producer_body:
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel rtl8168_rxwipe_kat_verdict], 3
    lea  r13, [rel str_rtl_kat_skip_cpu]
    xor  eax, eax
    cpuid
    cmp  eax, 7
    jb   .skip
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    bt   ebx, 23                           ; CLFLUSHOPT
    jnc  .skip
    lea  r13, [rel str_rtl_kat_skip_state]
    cmp  byte [rel rtl8168_bound], 0
    jne  .skip
    lea  rax, [rel rtl_kat_slot]
    mov  rdx, rax
    shr  rdx, 32
    jnz  .skip

    ; snapshot driver state, then point the driver at the private ring
    lea  rdi, [rel rtl_kat_save]
    lea  rsi, [rel rtl8168_bar2]
    mov  edx, RTL_STATE_BYTES
    call memcpy
    ; Ordinary RX also samples link-rearm state. Borrow only private state
    ; for this KAT, then restore the complete original transition/counters.
    lea  rdi, [rel rtl_kat_rearm_save]
    lea  rsi, [rel rtl8168_link_rearm_state]
    mov  edx, REALTEK_LR_SIZE
    call memcpy
    lea  rdi, [rel rtl8168_link_rearm_state]
    xor  esi, esi
    mov  edx, REALTEK_LR_SIZE
    call memset
    lea  rdi, [rel rtl_kat_tx_ring]
    xor  esi, esi
    mov  edx, 64
    call memset
    mov  dword [rel rtl_kat_tx_ring], (1 << 30) ; idle private TX, OWN clear
    lea  rax, [rel rtl_kat_tx_ring]
    mov  [rel rtl8168_tx_ring], rax
    lea  rdi, [rel rtl_kat_bar]
    xor  esi, esi
    mov  edx, 256
    call memset                   ; no stale private ISR/RDU or controller bits
    mov  byte [rel rtl_kat_bar + RTL_PHYSTS], 2 ; private known-up PHY sample
    lea  rax, [rel rtl_kat_bar]
    mov  [rel rtl8168_bar2], rax
    lea  rax, [rel rtl_kat_ring]
    mov  [rel rtl8168_rx_ring], rax
    lea  rax, [rel rtl_kat_slot]
    mov  [rel rtl8168_rx_buffers], rax
    mov  dword [rel rtl8168_rx_idx], 0
    mov  byte [rel rtl8168_gate_released], 1        ; never touch the DNS gate
    mov  byte [rel rtl8168_first_poll_reset_done], 1 ; never run the ring reset
    mov  byte [rel rtl8168_bound], 1

    ; ---- case A: delivered frame -------------------------------------------
    lea  r13, [rel str_rtl_kat_r_len]
    mov  edi, RTL_KAT_LEN_A
    call rtl_kat_arm
    lea  rdi, [rel rtl8168_dev]
    lea  rsi, [rel rtl_kat_rx]
    mov  edx, RTL_RX_BUF_SIZE
    call rtl8168_rx_poll.producer_body
    cmp  rax, RTL_KAT_LEN_A
    jne  .fail
    lea  r13, [rel str_rtl_kat_r_content]
    lea  rdi, [rel rtl_kat_rx]
    mov  esi, RTL_KAT_LEN_A
    call rtl_kat_check_pattern
    test eax, eax
    jnz  .fail
    mov  edi, RTL_KAT_LEN_A
    call rtl_kat_check_slot                 ; sets r13 to the reason on failure
    test eax, eax
    jnz  .fail
    lea  r13, [rel str_rtl_kat_r_bound]
    lea  rdi, [rel rtl_kat_slot + RTL_KAT_LEN_A + 4]
    mov  ecx, (RTL_RX_BUF_SIZE - RTL_KAT_LEN_A - 4) / 4
    mov  eax, 0xDEADBEEF
    cld
    repe scasd                              ; bytes past the frame never written
    jne  .fail
    lea  r13, [rel str_rtl_kat_r_desc]
    cmp  dword [rel rtl_kat_ring], (1 << 31) | (1 << 30) | RTL_RX_BUF_SIZE
    jne  .fail
    cmp  dword [rel rtl_kat_ring + 4], 0
    jne  .fail
    cmp  dword [rel rtl8168_rx_idx], 1
    jne  .fail
    lea  r13, [rel str_rtl_kat_r_residue]
    mov  rax, [rel rtl_kat_save + (rtl8168_rx_wipes - rtl8168_bar2)]
    inc  rax
    cmp  rax, [rel rtl8168_rx_wipes]        ; exactly one slot wipe, no skip
    jne  .fail

    ; ---- case B: ghost on the reused slot ----------------------------------
    lea  rdi, [rel rtl_kat_rx]
    xor  esi, esi
    mov  edx, RTL_RX_BUF_SIZE
    call memset
    mov  dword [rel rtl8168_rx_idx], 0
    mov  dword [rel rtl_kat_ring + 4], 0
    mov  dword [rel rtl_kat_ring], (1 << 30) | RTL_KAT_DESC | (RTL_KAT_LEN_A + 4)
    mov  r14, [rel rtl8168_rx_ghost_rejects]
    lea  rdi, [rel rtl8168_dev]
    lea  rsi, [rel rtl_kat_rx]
    mov  edx, RTL_RX_BUF_SIZE
    call rtl8168_rx_poll.producer_body
    lea  r13, [rel str_rtl_kat_r_stale]
    test rax, rax
    jnz  .fail                              ; stale frame re-delivered
    lea  rdi, [rel rtl_kat_rx]
    mov  ecx, RTL_KAT_LEN_A
    xor  eax, eax
    repe scasb
    jne  .fail
    lea  r13, [rel str_rtl_kat_r_ghost]
    inc  r14
    cmp  r14, [rel rtl8168_rx_ghost_rejects]
    jne  .fail
    cmp  dword [rel rtl_kat_ring], (1 << 31) | (1 << 30) | RTL_RX_BUF_SIZE
    jne  .fail

    ; ---- case C: frame longer than the caller cap ---------------------------
    lea  r13, [rel str_rtl_kat_r_len]
    mov  dword [rel rtl8168_rx_idx], 0
    mov  edi, RTL_KAT_LEN_C
    call rtl_kat_arm
    lea  rdi, [rel rtl8168_dev]
    lea  rsi, [rel rtl_kat_rx]
    mov  edx, RTL_KAT_CAP_C
    call rtl8168_rx_poll.producer_body
    cmp  rax, RTL_KAT_LEN_C
    jne  .fail
    lea  r13, [rel str_rtl_kat_r_content]
    lea  rdi, [rel rtl_kat_rx]
    mov  esi, RTL_KAT_CAP_C
    call rtl_kat_check_pattern
    test eax, eax
    jnz  .fail
    lea  r13, [rel str_rtl_kat_r_cap]
    cmp  byte [rel rtl_kat_rx + RTL_KAT_CAP_C], 0   ; cap honoured
    jne  .fail
    mov  edi, RTL_KAT_LEN_C
    call rtl_kat_check_slot
    test eax, eax
    jnz  .fail

    call rtl_kat_restore
    mov  byte [rel rtl8168_rxwipe_kat_verdict], 1
    lea  rdi, [rel str_rtl_kat_pass]
    call serial_string
    jmp  .out
.fail:
    call rtl_kat_restore
    mov  byte [rel rtl8168_rxwipe_kat_verdict], 2
    lea  rdi, [rel str_rtl_kat_fail]
    call serial_string
    mov  rdi, r13
    call serial_string
    lea  rdi, [rel str_rtl_kat_fail_tail]
    call serial_string
    jmp  .out
.skip:
    lea  rdi, [rel str_rtl_kat_skip]
    call serial_string
    mov  rdi, r13
    call serial_string
    lea  rdi, [rel str_rtl_kat_skip_tail]
    call serial_string
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; rtl_kat_arm(EDI=payload len): slot := init state (DEADBEEF fill) carrying a
; generated frame + 4 CRC bytes; descriptor := completed (OWN clear), EOR set,
; opts2 dirty, address = the slot. Clobbers caller-saved only.
rtl_kat_arm:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel rtl_kat_slot]
    mov  ecx, RTL_RX_BUF_SIZE / 4
    mov  eax, 0xDEADBEEF
    cld
    rep  stosd
    lea  rdi, [rel rtl_kat_slot]
    xor  ecx, ecx
.gen:
    imul eax, ecx, 59
    add  eax, 167
    xor  eax, 0x5A
    mov  [rdi + rcx], al
    inc  ecx
    cmp  ecx, ebx
    jb   .gen
    mov  dword [rdi + rcx], 0x4433A5A5      ; CRC bytes as the chip leaves them
    lea  eax, [ebx + 4]
    or   eax, (1 << 30) | RTL_KAT_DESC
    mov  dword [rel rtl_kat_ring], eax
    mov  dword [rel rtl_kat_ring + 4], 0x12345678
    lea  rax, [rel rtl_kat_slot]
    mov  [rel rtl_kat_ring + 8], eax
    mov  dword [rel rtl_kat_ring + 12], 0
    mfence
    pop  rbx
    ret

; rtl_kat_check_pattern(RDI=buf, ESI=len) -> EAX 0 iff buf == generated frame.
rtl_kat_check_pattern:
    xor  ecx, ecx
.cmp:
    cmp  ecx, esi
    jae  .ok
    imul eax, ecx, 59
    add  eax, 167
    xor  eax, 0x5A
    cmp  [rdi + rcx], al
    jne  .bad
    inc  ecx
    jmp  .cmp
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; rtl_kat_check_slot(EDI=payload len) -> EAX 0 iff the slot, re-read from RAM
; after clflush, is DEADBEEF + zero through len+4. R13 = reason on failure.
rtl_kat_check_slot:
    push rbx
    mov  ebx, edi
    lea  rax, [rel rtl_kat_slot]
    mov  ecx, RTL_RX_BUF_SIZE / 64
.fl:
    clflush [rax]
    add  rax, 64
    dec  ecx
    jnz  .fl
    mfence
    lea  r13, [rel str_rtl_kat_r_residue]
    lea  rdi, [rel rtl_kat_slot + 4]
    mov  ecx, ebx                           ; bytes [4, len+4)
    xor  eax, eax
    cld
    repe scasb
    jne  .bad
    lea  r13, [rel str_rtl_kat_r_sentinel]
    cmp  dword [rel rtl_kat_slot], 0xDEADBEEF
    jne  .bad
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  eax, 1
    pop  rbx
    ret

; Restore every driver global from the snapshot and remove the KAT's frames.
; The KAT's two delivered frames also bumped the shared wire RX= counter.
rtl_kat_restore:
    mov  rcx, [rel rtl8168_rx_frames]
    sub  rcx, [rel rtl_kat_save + (rtl8168_rx_frames - rtl8168_bar2)]
    lock sub qword [rel e1000e_rx_frames], rcx  ; rx_poll bumps both in lockstep
    lea  rdi, [rel rtl8168_bar2]
    lea  rsi, [rel rtl_kat_save]
    mov  edx, RTL_STATE_BYTES
    call memcpy
    lea  rdi, [rel rtl8168_link_rearm_state]
    lea  rsi, [rel rtl_kat_rearm_save]
    mov  edx, REALTEK_LR_SIZE
    call memcpy
    lea  rdi, [rel rtl_kat_ring]
    xor  esi, esi
    mov  edx, RTL_KAT_SCRATCH_BYTES
    call memset
    ret

; rtl8168_pci_claim — RCQ-29 hardware report: when the scan matched a chip,
;   record BOUND (rings up, rtl8168_bound) or FAILED.  Preserves every general
;   register.
rtl8168_pci_claim:
    cmp  byte [rel rtl8168_claim_found], 1
    jne  .out
    push rax
    push rdi
    push rcx
    push r8
    lea  rdi, [rel rtl8168_pci_bus]
    mov  ecx, PCI_DRV_RTL8168
    mov  r8d, PCI_CLAIM_FAILED
    cmp  byte [rel rtl8168_bound], 1
    jne  .claim
    mov  r8d, PCI_CLAIM_BOUND
.claim:
    call pci_claim_bdf3
    pop  r8
    pop  rcx
    pop  rdi
    pop  rax
.out:
    ret

; ============================================================================
; rtl8168_hw_bringup — the MAC_VER_46 bring-up (v0.1: holes A/B are being rewritten clean-room). Bounded everywhere; a missing chip
;   or stuck poll degrades (no marker, no hang). Preserves callee-saved.
; ============================================================================
rtl8168_hw_bringup:
    RTL8168_PRODUCER rtl8168_hw_bringup,-1
.producer_body:
    NATIVE_DRIVER_REFUSE 6
    PCIA_NATIVE_COLD_REFUSE                        ; before probe and upstream bridge effects
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  byte [rel rtl8168_claim_found], 0
    ; --- 1. scan every PCI bus/dev/fn for the exact RTL8168H PCI identity ------
    xor  r15d, r15d                        ; bus
.scan_bus:
    xor  r14d, r14d                        ; dev
.scan_dev:
    xor  r13d, r13d                        ; fn
.scan_fn:
    mov  edi, r15d
    mov  esi, r14d
    mov  edx, r13d
    xor  ecx, ecx
    call pci_cfg_read32                    ; EAX = device<<16 | vendor
    cmp  ax, RTL_VENDOR_ID                 ; Realtek?
    jne  .scan_next
    mov  ebx, eax
    shr  ebx, 16
    cmp  bx, RTL_DEVICE_ID                 ; RTL8168 family device id
    jne  .scan_next
    ; Class and revision are part of the live identity. This prevents a reused
    ; vendor/device pair or Lenovo's 10ec:8161 secondary NIC from entering MMIO.
    mov  edi, r15d
    mov  esi, r14d
    mov  edx, r13d
    mov  ecx, 0x08                         ; class[31:16], revision[7:0]
    call pci_cfg_read32
    mov  ebx, eax
    shr  eax, 16
    cmp  eax, 0x0200                       ; Ethernet controller
    jne  .scan_next
    cmp  bl, RTL_PCI_REVISION
    je   .found
.scan_next:
    inc  r13d
    cmp  r13d, 8
    jl   .scan_fn
    inc  r14d
    cmp  r14d, 32
    jl   .scan_dev
    inc  r15d
    cmp  r15d, 256
    jl   .scan_bus
    ; no exact RTL present -> honest skip (QEMU / foreign devices land here)
    or   dword [rel rtl8168_dev + dev.flags], NETDEV_F_ABSENT   ; nothing there: 'absent', not a fault
    lea  rdi, [rel str_rtl_absent]
    call serial_string
    jmp  .out

.found:
    A1_NATIVE_NIC_SKIP r15,r14,r13,.scan_next
    and  dword [rel rtl8168_dev + dev.flags], ~NETDEV_F_ABSENT   ; a chip is there (a bind failure is a fault)
    mov  [rel rtl8168_pci_bus], r15d
    mov  [rel rtl8168_pci_dev], r14d
    mov  [rel rtl8168_pci_fn], r13d
    mov  byte [rel rtl8168_claim_found], 1  ; hardware report: claimed at the shared exit

    ; --- 2. if behind a PCIe bridge (bus != 0), enable BM on the bridge --------
    test r15d, r15d
    jz   .no_bridge
    xor  ebx, ebx                          ; bridge dev on bus 0
.bridge_scan:
    cmp  ebx, 32
    jge  .no_bridge
    xor  edi, edi
    mov  esi, ebx
    xor  edx, edx
    xor  ecx, ecx
    call pci_cfg_read32
    cmp  ax, 0xFFFF
    je   .bridge_next
    xor  edi, edi
    mov  esi, ebx
    xor  edx, edx
    mov  ecx, 0x08                         ; class/subclass
    call pci_cfg_read32
    mov  r8d, eax
    shr  r8d, 24
    cmp  r8b, 0x06                         ; class Bridge
    jne  .bridge_next
    mov  r8d, eax
    shr  r8d, 16
    and  r8b, 0xFF
    cmp  r8b, 0x04                         ; subclass PCI-to-PCI
    jne  .bridge_next
    xor  edi, edi
    mov  esi, ebx
    xor  edx, edx
    mov  ecx, 0x18                         ; secondary bus in bits 15:8
    call pci_cfg_read32
    shr  eax, 8
    and  eax, 0xFF
    cmp  eax, r15d
    jne  .bridge_next
    ; matching bridge -> enable IO|MEM|BM
    xor  edi, edi
    mov  esi, ebx
    xor  edx, edx
    mov  ecx, 0x04
    call pci_cfg_read32
    or   eax, 0x07
    mov  r8d, eax
    xor  edi, edi
    mov  esi, ebx
    xor  edx, edx
    mov  ecx, 0x04
    call pci_cfg_write32
    jmp  .no_bridge
.bridge_next:
    inc  ebx
    jmp  .bridge_scan
.no_bridge:

    ; --- 3. enable PCI Bus Mastering on the NIC ------------------------------
    mov  edi, [rel rtl8168_pci_bus]
    mov  esi, [rel rtl8168_pci_dev]
    mov  edx, [rel rtl8168_pci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    or   eax, 0x07                         ; IO + MEM + Bus Master
    mov  r8d, eax
    mov  edi, [rel rtl8168_pci_bus]
    mov  esi, [rel rtl8168_pci_dev]
    mov  edx, [rel rtl8168_pci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32

    ; --- 4. read BAR2 (offset 0x18) -> MMIO base -----------------------------
    mov  edi, [rel rtl8168_pci_bus]
    mov  esi, [rel rtl8168_pci_dev]
    mov  edx, [rel rtl8168_pci_fn]
    mov  ecx, 0x18
    call pci_cfg_read32
    mov  ebx, eax                          ; BAR2 low dword
    test al, 0x04                          ; 64-bit BAR (bits 2:1 = 10b)?
    jz   .bar2_32
    mov  edi, [rel rtl8168_pci_bus]
    mov  esi, [rel rtl8168_pci_dev]
    mov  edx, [rel rtl8168_pci_fn]
    mov  ecx, 0x1C                         ; BAR3 = high 32
    call pci_cfg_read32
    shl  rax, 32
    and  ebx, 0xFFFFFFF0
    or   rax, rbx
    mov  [rel rtl8168_bar2], rax
    jmp  .bar2_done
.bar2_32:
    and  ebx, 0xFFFFFFF0
    mov  [rel rtl8168_bar2], rbx
.bar2_done:
    mov  r12, [rel rtl8168_bar2]
    test r12, r12
    jz   .out                              ; no BAR -> unusable
    mov  rax, r12
    shr  rax, 32
    test eax, eax
    jnz  .out                              ; BAR above 4 GiB -> outside identity map

    ; --- flush WB caches BEFORE marking UC (preserve pending UEFI reg writes),
    ;     then mark the BAR2 2 MiB page uncacheable so MMIO reaches the chip ---
    wbinvd
    mfence
    mov  rdi, r12
    call rtl_mark_uc

    ; MAC_VER_46 is the final identity gate and precedes all device MMIO writes.
    mov  eax, [r12 + RTL_TCR]
    and  eax, RTL_MAC_VER_46_MASK
    cmp  eax, RTL_MAC_VER_46_VALUE
    jne  .identity_mismatch
    mov  byte [rel rtl8168_mac_ver46], 1

    ; --- preserve UEFI PCI state; disable TX/RX via CMD for a clean re-init ---
    mov  byte [r12 + RTL_CMD], 0x00
    mfence
    mov  word [r12 + RTL_IMR], 0x0000      ; poll mode: mask all NIC interrupts
    ; ==== CLEANROOM HOLE A (v0.1 clean-room, spec section 2; provenance in spec section 5) ===============
    ; Minimal init on the state UEFI leaves (rtl8126.asm model): no chip reset, so the PHY, C+ mode and
    ; the IDR MAC stay as firmware left them. TE|RE are already clear and IMR is 0 (A3); W1C any status
    ; the firmware left latched. Open the 93C46 config lock for the rest of bring-up (A1: the Config5
    ; WoL clear below); hole B closes it again. A2: for the 8168H the BSD re(4) drivers set no MAC
    ; deep-sleep (MACSLEEP) or MAC-side PHY power gate (PHYWAKE_PM) quirk; the one firmware-left gate on
    ; this family is the RXDV gate, opened in hole B after the rings are live. Register access is
    ; already proven by the TCR identity read. No polls here (A4 holds trivially).
    mov  word [r12 + RTL_ISR], RTL_ISR_ALL
    mov  byte [r12 + RTL_CFG9346], RTL_CFG9346_UNLOCK
    mfence
    ; ===================================================================================================

    ; --- read MAC from IDR0-5 ------------------------------------------------
    mov  eax, [r12 + RTL_IDR0]
    mov  [rel rtl8168_mac], eax
    movzx eax, word [r12 + RTL_IDR4]
    mov  [rel rtl8168_mac + 4], ax
    mov  eax, [rel rtl8168_mac]
    or   eax, [rel rtl8168_mac + 4]
    jz   .mac_bad
    mov  eax, [rel rtl8168_mac]
    and  eax, [rel rtl8168_mac + 4]
    cmp  eax, 0xFFFFFFFF
    je   .mac_bad
    mov  byte [rel rtl8168_mac_ok], 1
    jmp  .mac_done
.mac_bad:
    mov  byte [rel rtl8168_mac_ok], 0
    jmp  .cfg_relock_out                    ; unlocked by hole A: relock, then exit
.mac_done:
    ; Config5: clear WoL flags that can interfere
    movzx eax, byte [r12 + 0x56]
    and  al, ~((1 << 6) | (1 << 5) | (1 << 4) | (1 << 1))
    mov  [r12 + 0x56], al

    ; Reserve a DMA pool only after strict hardware identity succeeds. The
    ; IOMMU record table survives dma_init, so existing mappings remain live.
    call dma_init

    ; --- TX descriptor ring (sub-4-GiB, page-aligned via core/dma) -----------
    mov  rdi, RTL_NUM_TX_DESC * RTL_DESC_SIZE
    call dma_alloc
    test rax, rax
    jz   .cfg_relock_out
    mov  rdx, rax
    shr  rdx, 32
    jnz  .cfg_relock_out
    mov  [rel rtl8168_tx_ring], rax
    mov  rdi, rax
    mov  rcx, RTL_NUM_TX_DESC * RTL_DESC_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  r12, [rel rtl8168_bar2]           ; reload (dma_alloc is external)
    mov  rax, [rel rtl8168_tx_ring]
    mov  ebx, eax
    mov  [r12 + RTL_TNPDS], ebx
    mov  rbx, [rel rtl8168_tx_ring]
    shr  rbx, 32
    mov  [r12 + RTL_TNPDS_HI], ebx

    ; --- TX bounce buffer (synchronous TX) -----------------------------------
    mov  rdi, RTL_RX_BUF_SIZE
    call dma_alloc
    test rax, rax
    jz   .cfg_relock_out
    mov  rdx, rax
    shr  rdx, 32
    jnz  .cfg_relock_out
    mov  [rel rtl8168_tx_buffer], rax

    ; --- RX descriptor ring (sub-4-GiB, page-aligned via core/dma) -----------
    ; WB + clflush discipline, the monolith v0.3.11 doctrine. The ring is NEVER
    ; marked UC on the Beelink: anti_patterns.md #9 ("Mark TX/RX ring or RX buffer
    ; pages UC") = "Alder Lake doesn't bind NIC". CONFIRMED on metal 2026-09-13
    ; 07:27 — candidate #1 (dedicated 2 MiB UC ring page) went fully dark (paos_seen
    ; false, :9997 never answered), a regression from the WB ring that at least
    ; delivered ~13 frames + a PING. Ring stays WB; rtl8168_rx_poll clflushes each
    ; descriptor line before reading OWN (ap#12). The ~13-frame RDU stall is cured
    ; instead by the ported RX-ring reset recovery in .rx_none (see below), not by
    ; UC memory. dma_alloc is page-aligned => the 256-byte RDSAR alignment the
    ; RTL8168 requires is satisfied, and the ring lives below 4 GiB (ap#11).
    mov  rdi, RTL_NUM_RX_DESC * RTL_DESC_SIZE
    call dma_alloc
    test rax, rax
    jz   .cfg_relock_out
    mov  rdx, rax
    shr  rdx, 32
    jnz  .cfg_relock_out
    mov  [rel rtl8168_rx_ring], rax
    mov  rdi, rax
    mov  rcx, RTL_NUM_RX_DESC * RTL_DESC_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq

    ; --- RX buffers (256 * 2 KiB) --------------------------------------------
    mov  rdi, RTL_NUM_RX_DESC * RTL_RX_BUF_SIZE
    call dma_alloc
    test rax, rax
    jz   .cfg_relock_out
    mov  rdx, rax
    shr  rdx, 32
    jnz  .cfg_relock_out
    mov  [rel rtl8168_rx_buffers], rax
    ; fill with a DEADBEEF ghost-frame sentinel, then write back + clean caches
    mov  rdi, rax
    mov  rcx, RTL_NUM_RX_DESC * RTL_RX_BUF_SIZE / 4
    mov  eax, 0xDEADBEEF
    cld
    rep  stosd
    wbinvd
    mfence

    ; bee004 RX-DEAD guard (monolith anti_patterns.md #9, instrument-proven): the RX
    ; BUFFERS stay WB. Marking the packet buffers UC makes RX silently deliver NOTHING
    ; (the "TX ok, RX dead" wire signature: PaOS TXes the :9998 beacon but never
    ; ARP-replies to who-has .149). The buffers are large, cached, and read via the
    ; clflush-before-copy discipline in rtl8168_rx_poll — that is correct and stays.
    ; The DESCRIPTOR RING is likewise WB (marking it UC = ap#9 no-bind on Alder
    ; Lake, confirmed fully-dark on metal); its OWN reads stay coherent via the
    ; per-descriptor clflush in rx_poll, and the ~13-frame RDU stall is cured by
    ; the ported RX-ring reset recovery in .rx_none, not by UC memory.

    ; --- initialise RX descriptors: OWN|size, EOR on the last ----------------
    mov  r13, [rel rtl8168_rx_ring]
    mov  r14, [rel rtl8168_rx_buffers]
    xor  ecx, ecx
.rxd_init:
    cmp  ecx, RTL_NUM_RX_DESC
    jge  .rxd_done
    mov  dword [r13 + 4], 0                ; opts2 = 0
    mov  rax, r14
    mov  [r13 + 8], eax                    ; buffer addr low
    shr  rax, 32
    mov  [r13 + 12], eax                   ; buffer addr high
    sfence                                 ; addr visible before OWN
    mov  eax, (1 << 31) | RTL_RX_BUF_SIZE  ; OWN | length
    cmp  ecx, RTL_NUM_RX_DESC - 1
    jne  .rxd_no_eor
    or   eax, (1 << 30)                    ; EOR on last
.rxd_no_eor:
    mov  [r13], eax
    add  r13, RTL_DESC_SIZE
    add  r14, RTL_RX_BUF_SIZE
    inc  ecx
    jmp  .rxd_init
.rxd_done:
    ; Flush the initialised WB descriptors to RAM so the NIC's DMA reads OWN=1
    ; (monolith init discipline). The ring is NOT marked UC (ap#9 = no-bind on
    ; Alder Lake); rx_poll keeps it coherent with per-descriptor clflush (ap#12).
    wbinvd
    mfence
    mov  r12, [rel rtl8168_bar2]
    mov  rax, [rel rtl8168_rx_ring]
    mov  ebx, eax
    mov  [r12 + RTL_RDSAR], ebx
    mov  rbx, [rel rtl8168_rx_ring]
    shr  rbx, 32
    mov  [r12 + RTL_RDSAR_HI], ebx

    ; TX last descriptor EOR
    mov  r13, [rel rtl8168_tx_ring]
    mov  rax, (RTL_NUM_TX_DESC - 1) * RTL_DESC_SIZE
    add  r13, rax
    mov  dword [r13], (1 << 30)
    mov  dword [rel rtl8168_tx_idx], 0
    mov  dword [rel rtl8168_rx_idx], 0

    ; ==== CLEANROOM HOLE B (v0.1 clean-room, spec section 3; provenance in spec section 5) ===============
    ; Rings are programmed (r12 = BAR2). The re(4) order for 8168G-and-later parts: open the RXDV gate
    ; (B4), write TxConfig, then RxConfig, and only then enable TE|RE. RMS = the 2048-byte RX buffer
    ; size (B3, the FreeBSD rule RMS = RX buffer length). Lock the config registers again (B5), then
    ; a bounded read-back of TE|RE (B1/B6): a chip that does not report both degrades with no marker.
    mov  eax, [r12 + RTL_MISC]
    and  eax, ~RTL_MISC_RXDV_GATE          ; RXDV gate off: RX data reaches the MAC
    mov  [r12 + RTL_MISC], eax
    mov  dword [r12 + RTL_TCR], RTL_TCR_VAL
    mov  dword [r12 + RTL_RCR], RTL_RCR_VAL
    mov  word [r12 + RTL_RMS], RTL_RX_BUF_SIZE
    mfence
    mov  byte [r12 + RTL_CMD], RTL_CMD_TE | RTL_CMD_RE
    mfence
    mov  byte [r12 + RTL_CFG9346], RTL_CFG9346_LOCKED
    mfence
    mov  ecx, 10000
.enable_wait:
    movzx eax, byte [r12 + RTL_CMD]
    and  al, RTL_CMD_TE | RTL_CMD_RE
    cmp  al, RTL_CMD_TE | RTL_CMD_RE
    je   .enable_ok
    pause
    dec  ecx
    jnz  .enable_wait
    jmp  .out                              ; TE|RE never reported: degrade, no marker
.enable_ok:
    ; ===================================================================================================

    ; === PHY autoneg restart OUT of the UEFI 10BASE-T default ================
    ; UEFI leaves ANAR=0x0061 (10BASE-T only). Advertise 10/100 (ANAR 0x01E1) +
    ; 1000BASE-T FD (GBCR 0x0200), then restart autoneg (BMCR 0x1200). GPHY_OCP
    ; (MMIO 0xB8), NOT PHYAR 0x60, is the MAC_VER_46 PHY access.
    mov  edi, 4                            ; ANAR = PHY reg 4
    mov  esi, 0x01E1
    call rtl_gphy_ocp_write
    mov  edi, 9                            ; GBCR = PHY reg 9
    mov  esi, 0x0200
    call rtl_gphy_ocp_write
    mov  edi, 0                            ; BMCR = PHY reg 0
    mov  esi, 0x1200                       ; autoneg enable + restart
    call rtl_gphy_ocp_write

    ; bounded wait for link (PHYSTS bit1). ~1s cap of pause spins; then continue.
    mov  r12, [rel rtl8168_bar2]
    mov  ecx, 200
.link_wait:
    movzx eax, byte [r12 + RTL_PHYSTS]
    test al, 0x02
    jnz  .link_up
    mov  r8d, 100000
.link_delay:
    pause
    dec  r8d
    jnz  .link_delay
    dec  ecx
    jnz  .link_wait
    jmp  .rings_ready                      ; link late -> boot_p8_nic_watch flips it
.link_up:
    mov  byte [rel rtl8168_link_up], 1
    mov  byte [rel e1000e_link_up], 1      ; wire NIC_LINK reflects the active NIC
.rings_ready:
    mov  byte [rel rtl8168_first_poll_reset_done], 0
    mov  byte [rel rtl8168_bound], 1
    ; This point is reachable only after exact 10ec:8168, Ethernet class,
    ; revision 0x15 and MAC_VER_46 validation plus successful ring bring-up.
    mov  dword [rel rtl8168_dev + dev.flags], NETDEV_F_ADDR_BEELINK
    ; earned hw-only marker: the driver bound rings on real silicon
    lea  rdi, [rel str_rtl_ready]
    call serial_string
.identity_mismatch:
.out:
    call rtl8168_pci_claim
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Degrade exit for failures after hole A opened the config lock: put Cfg9346 back to
; locked (0x00), then take the shared exit. r12 is reloaded (dma_alloc is external).
.cfg_relock_out:
    mov  r12, [rel rtl8168_bar2]
    mov  byte [r12 + RTL_CFG9346], RTL_CFG9346_LOCKED
    mfence
    jmp  .out

; BEGIN RTL8168 TERMINAL QUIESCE
; Terminal BSP/IF0-only leaf, RDI=trusted64B report; preserves callee-saved.
; Separate from recoverable stop. EAX0 proven never-owned,1 completed,
; -1 no controller effect,-2 irreversible/attempted/uncertain. Report ABI and
; pinned BSD hardware facts: gauntlet_v2/docs/RTL8168_TERMINAL_QUIESCE.md.
; This never releases/reuses DMA memory, enters D3 or alters an upstream bridge.
rtl8168_terminal_quiesce:
    cld
    test rdi,rdi
    jz .null
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,40
    mov rbx,rdi
    xor eax,eax
    mov ecx,8
    rep stosq
    cmp dword [rel rtl8168_terminal_latched],0
    jne .replay
    xor eax,eax
    mov edx,1
    lock cmpxchg [rel rtl8168_terminal_gate],edx
    jne .busy
    cmp byte [rel rtl8168_bound],1
    je .owned
    ; Passive original inactive operand snapshot, under the already-held gate.
    ; Bit9 alone selects this alternate 64B shape; no addresses escape.
    movzx eax,byte [rel rtl8168_bound]
    mov [rbx+12],eax
    movzx eax,byte [rel rtl8168_claim_found]
    mov [rbx+16],eax
    xor edx,edx
    cmp qword [rel rtl8168_bar2],0
    setne dl
    lea rsi,[rel rtl8168_tx_ring]
    mov ecx,4
    mov r8d,2
.inactive_observe_dma:
    cmp qword [rsi],0
    je .inactive_observe_next
    or edx,r8d
.inactive_observe_next:
    add rsi,8
    shl r8d,1
    loop .inactive_observe_dma
    cmp qword [rel rtl8168_tx_busy],0 ; same qword predicate as original below
    je .inactive_observe_busy_done
    or edx,32
.inactive_observe_busy_done:
    ; Original storage order is TXring/RXring/RXbuffers/TXbuffer. Export the
    ; documented semantic bit order TXring/RXring/TXbuffer/RXbuffers.
    mov eax,edx
    and edx,~24
    mov ecx,eax
    and eax,8
    shl eax,1
    and ecx,16
    shr ecx,1
    or edx,eax
    or edx,ecx
    mov [rbx+20],edx
    mov eax,[rel rtl8168_dev+dev.class]
    mov [rbx+24],eax
    xor edx,edx
    mov rax,[rel rtl8168_dev+dev.ops]
    test rax,rax
    setnz dl
    lea rcx,[rel rtl8168_ops]
    cmp rax,rcx
    jne .inactive_observe_ops_done
    or edx,2
.inactive_observe_ops_done:
    mov [rbx+28],edx
    mov eax,[rel rtl8168_dev+dev.health]
    mov [rbx+32],eax
    mov eax,[rel rtl8168_dev+dev.flags]
    mov [rbx+36],eax
    or dword [rbx+8],512             ; all RAM operands actually observed
    ; Cached absence alone is insufficient: no retained binding, rings,
    ; buffers, BAR or healthy native state, plus a complete claim census.
    cmp byte [rel rtl8168_claim_found],0
    jne .refused
    cmp qword [rel rtl8168_bar2],0
    jne .refused
    lea rsi,[rel rtl8168_tx_ring]
    mov ecx,4
.inactive_dma:
    cmp qword [rsi],0
    jne .refused
    add rsi,8
    loop .inactive_dma
    cmp dword [rel rtl8168_dev+dev.class],0
    jne .inactive_registered
    cmp qword [rel rtl8168_dev+dev.ops],0
    jne .refused
    jmp .inactive_class_ok
.inactive_registered:
    cmp dword [rel rtl8168_dev+dev.class],CLASS_NET
    jne .refused
    lea rax,[rel rtl8168_ops]
    cmp [rel rtl8168_dev+dev.ops],rax
    jne .refused
    cmp dword [rel rtl8168_dev+dev.health],HEALTH_DEGRADED
    jne .refused
    test dword [rel rtl8168_dev+dev.flags],NETDEV_F_ABSENT
    jz .refused
.inactive_class_ok:
    cmp qword [rel rtl8168_tx_busy],0
    jne .refused
    xor edi,edi
    xor esi,esi
    call rtl8168_terminal_claims
    mov [rbx+40],eax                 ; actual original helper result, not inferred
    mov [rbx+44],r9d                 ; actual bounded snapshot count
    mov [rbx+48],r8d                 ; actual snapshot overflow bits
    or dword [rbx+8],1024            ; original census actually attempted
    test eax,eax
    jnz .refused
    mov dword [rel rtl8168_terminal_gate],0
    xor eax,eax
    jmp .out
.owned:
    mov dword [rbx+52],1              ; ownership/preflight reason
    cmp byte [rel rtl8168_claim_found],1
    jne .refused
    cmp byte [rel rtl8168_mac_ok],1
    jne .refused
    cmp byte [rel rtl8168_mac_ver46],1
    jne .refused
    cmp qword [rel rtl8168_tx_busy],0
    jne .refused
    cmp dword [rel rtl8168_pci_bus],255
    ja .refused
    cmp dword [rel rtl8168_pci_dev],31
    ja .refused
    cmp dword [rel rtl8168_pci_fn],7
    ja .refused
    mov eax,[rel rtl8168_pci_bus]
    shl eax,8
    mov edx,[rel rtl8168_pci_dev]
    shl edx,3
    or eax,edx
    or eax,[rel rtl8168_pci_fn]
    mov [rbx+12],eax
    mov edi,eax
    mov esi,1
    call rtl8168_terminal_claims
    test eax,eax
    jnz .refused
    mov [rsp+24],edx                 ; exact current BOUND claim sequence
    or dword [rbx+8],4
    lea rdi,[rel rtl8168_dev]
    lea rsi,[rel rtl8168_ops]
    call netdev_power_member
    test rax,rax
    jz .refused
    mov [rsp],rax
    mov [rsp+8],rdx
    mov [rbx+56],rdx
    or dword [rbx+8],2
    ; Exact-width physical configuration; no guessed virtual bus.
    xor ecx,ecx
    call rtl8168_terminal_pci
    mov [rbx+16],eax
    cmp eax,0x816810ec
    jne .refused
    mov ecx,8
    call rtl8168_terminal_pci
    and eax,0xffff00ff
    cmp eax,0x02000015
    jne .refused
    mov ecx,0x18
    call rtl8168_terminal_pci
    mov r13d,eax
    and eax,15
    cmp eax,0
    je .bar32
    cmp eax,4
    jne .refused
    mov ecx,0x1c
    call rtl8168_terminal_pci
    test eax,eax                     ; driver admits sub4G DMA/MMIO only
    jnz .refused
.bar32:
    and r13d,0xfffffff0
    mov r12,[rel rtl8168_bar2]
    test r12,r12
    jz .refused
    cmp r12,r13
    jne .refused
    or dword [rbx+8],1
    mov ecx,4
    call rtl8168_terminal_pci
    cmp eax,-1
    je .refused
    movzx eax,ax
    mov [rbx+20],eax
    and eax,6
    cmp eax,6
    jne .refused
    ; Nonzero, aligned, disjoint, sub4G buffers with no MMIO overlap.
    lea r13,[rel rtl8168_tx_ring]
    xor r14d,r14d
.spans:
    mov rax,[r13+r14*8]
    test rax,rax
    jz .refused
    test eax,63
    jnz .refused
    lea rsi,[rel rtl8168_terminal_spans]
    mov edx,[rsi+r14*4]
    add rdx,rax
    jc .refused
    mov rcx,rdx
    shr rcx,32
    jnz .refused
    lea rcx,[r12+256]
    cmp rax,rcx
    jae .no_mmio_overlap
    cmp rdx,r12
    ja .refused
.no_mmio_overlap:
    xor ecx,ecx
.prior:
    cmp ecx,r14d
    jae .span_next
    mov rdi,[r13+rcx*8]
    mov r8d,[rsi+rcx*4]
    add r8,rdi
    cmp rax,r8
    jae .disjoint
    cmp rdx,rdi
    ja .refused
.disjoint:
    inc ecx
    jmp .prior
.span_next:
    inc r14d
    cmp r14d,4
    jb .spans
    mov esi,RTL_TCR
    call rtl8168_terminal_rd32
    jc .refused
    mov [rbx+36],eax
    and eax,RTL_MAC_VER_46_MASK
    cmp eax,RTL_MAC_VER_46_VALUE
    jne .refused
    mov esi,RTL_IMR
    call rtl8168_terminal_rd16
    jc .refused
    mov [rbx+32],eax
    test eax,eax                     ; polling ownership, no native IRQ user
    jnz .refused
    mov esi,RTL_CMD
    call rtl8168_terminal_rd8
    jc .refused
    mov [rbx+28],eax
    and eax,0x9c
    cmp eax,RTL_CMD_TE|RTL_CMD_RE
    jne .refused
    ; Verify actual programmed ring addresses before any controller write.
    mov esi,RTL_TNPDS
    call rtl8168_terminal_rd32
    jc .refused
    cmp eax,[rel rtl8168_tx_ring]
    jne .refused
    mov esi,RTL_TNPDS_HI
    call rtl8168_terminal_rd32
    jc .refused
    test eax,eax
    jnz .refused
    mov esi,RTL_RDSAR
    call rtl8168_terminal_rd32
    jc .refused
    cmp eax,[rel rtl8168_rx_ring]
    jne .refused
    mov esi,RTL_RDSAR_HI
    call rtl8168_terminal_rd32
    jc .refused
    test eax,eax
    jnz .refused
    mov esi,RTL_RCR
    call rtl8168_terminal_rd32
    jc .refused
    mov [rsp+16],eax
    mov esi,RTL_MISC
    call rtl8168_terminal_rd32
    jc .refused
    mov [rsp+20],eax
    or dword [rbx+8],8
    ; Final current claim and class epoch under producer exclusion. Native
    ; assignment refuses BOUND/FAILED claims and cannot unbind this backend.
    mov ecx,4
    call rtl8168_terminal_pci
    movzx eax,ax
    cmp eax,[rbx+20]
    jne .refused
    mov edi,[rbx+12]
    mov esi,1
    call rtl8168_terminal_claims
    test eax,eax
    jnz .refused
    cmp edx,[rsp+24]
    jne .refused
    lea rdi,[rel rtl8168_dev]
    lea rsi,[rel rtl8168_ops]
    call netdev_power_member
    cmp rax,[rsp]
    jne .refused
    test rax,rax
    jz .refused
    cmp rdx,[rsp+8]
    jne .refused
    ; Terminal latch precedes the first hardware effect. No rollback, no
    ; native producer or recovery can ever reopen the gate after this point.
    mov dword [rel rtl8168_terminal_latched],1
    mov dword [rel rtl8168_terminal_gate],2
    mov dword [rbx+4],1
    mov dword [rbx+52],2              ; RX gating/readback
    mov esi,RTL_RCR
    mov edx,[rsp+16]
    and edx,~15
    call rtl8168_terminal_wr32
    mov esi,RTL_RCR
    call rtl8168_terminal_rd32
    jc .uncertain
    mov edx,[rsp+16]
    and edx,~15
    cmp eax,edx
    jne .uncertain
    mov esi,RTL_MISC
    mov edx,[rsp+20]
    or edx,RTL_MISC_RXDV_GATE
    call rtl8168_terminal_wr32
    mov esi,RTL_MISC
    call rtl8168_terminal_rd32
    jc .uncertain
    mov edx,[rsp+20]
    or edx,RTL_MISC_RXDV_GATE
    cmp eax,edx
    jne .uncertain
    mov dword [rbx+4],2
    mov edi,2000
    call tsc_delay_us
    mov dword [rbx+52],3              ; TX queue drain
    mov ebp,1000
.tx_wait:
    inc dword [rbx+48]
    mov esi,RTL_TCR
    call rtl8168_terminal_rd32
    jc .uncertain
    mov [rbx+36],eax
    test eax,0x800
    jnz .tx_empty
    mov edi,100
    call tsc_delay_us
    dec ebp
    jnz .tx_wait
    jmp .uncertain
.tx_empty:
    or dword [rbx+8],16
    mov dword [rbx+4],3
    ; MAC46: TE/RE clear AFTER TXQ, BEFORE FIFO empty. STOPREQ is invalid.
    mov esi,RTL_CMD
    mov edx,[rbx+28]
    and edx,~(RTL_CMD_TE|RTL_CMD_RE)
    call rtl8168_terminal_wr8
    mov esi,RTL_CMD
    call rtl8168_terminal_rd8
    jc .uncertain
    mov [rbx+28],eax
    test eax,0x1c
    jnz .uncertain
    mov dword [rbx+52],4              ; on-chip FIFO drain
    mov ebp,3000
.fifo_wait:
    inc dword [rbx+48]
    mov esi,0xd3
    call rtl8168_terminal_rd8
    jc .uncertain
    mov [rbx+40],eax
    and eax,0x30
    cmp eax,0x30
    je .fifo_empty
    mov edi,20
    call tsc_delay_us
    dec ebp
    jnz .fifo_wait
    jmp .uncertain
.fifo_empty:
    or dword [rbx+8],32
    mov dword [rbx+4],4
    mov edi,1000
    call tsc_delay_us
    mov dword [rbx+52],5              ; mask/readback
    mov esi,RTL_IMR
    xor edx,edx
    call rtl8168_terminal_wr16
    mov esi,RTL_IMR
    call rtl8168_terminal_rd16
    jc .uncertain
    mov [rbx+32],eax
    test eax,eax
    jnz .uncertain
    or dword [rbx+8],128
    mov dword [rbx+52],6              ; reset/readback
    mov esi,RTL_CMD
    mov edx,0x10
    call rtl8168_terminal_wr8
    mov ebp,1000
.reset_wait:
    inc dword [rbx+44]
    mov edi,10
    call tsc_delay_us
    mov esi,RTL_CMD
    call rtl8168_terminal_rd8
    jc .uncertain
    mov [rbx+28],eax
    test eax,0x10
    jz .reset_done
    dec ebp
    jnz .reset_wait
    jmp .uncertain
.reset_done:
    test eax,RTL_CMD_TE|RTL_CMD_RE
    jnz .uncertain
    or dword [rbx+8],64
    mov dword [rbx+4],5
    ; Reset must leave interrupts masked; no stale pre-reset mask proof.
    mov esi,RTL_IMR
    call rtl8168_terminal_rd16
    jc .uncertain
    mov [rbx+32],eax
    test eax,eax
    jnz .uncertain
    mov dword [rbx+52],7              ; own-function BM clear/readback
    xor ecx,ecx
    call rtl8168_terminal_pci
    cmp eax,0x816810ec
    jne .uncertain
    mov ecx,4
    call rtl8168_terminal_pci
    cmp eax,-1
    je .uncertain
    movzx r8d,ax                      ; upper PCI Status W1C bits always zero
    and r8d,~4
    mov edi,[rel rtl8168_pci_bus]
    mov esi,[rel rtl8168_pci_dev]
    mov edx,[rel rtl8168_pci_fn]
    mov ecx,4
    call pci_cfg_write32
    mov ecx,4
    call rtl8168_terminal_pci
    cmp eax,-1
    je .uncertain
    movzx eax,ax
    mov [rbx+24],eax
    mov edx,[rbx+20]
    and edx,~4
    cmp eax,edx
    jne .uncertain
    or dword [rbx+8],256
    mov dword [rbx+4],6
    mov dword [rbx+52],0
    mov eax,1
    jmp .out
.refused:
    mov dword [rel rtl8168_terminal_gate],0
.busy:
    cmp dword [rbx+52],0
    jne .refusal_result
    mov dword [rbx+52],1
.refusal_result:
    mov eax,-1
    jmp .out
.replay:
    mov dword [rbx+4],1
.uncertain:
    mov eax,-2
.out:
    mov [rbx],eax
    add rsp,40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.null:
    mov eax,-1
    ret

; Complete, duplicate-free locked census; no partial/FAILED/foreign ownership.
; EDI=packed own BDF, ESI=1 owned /0 never-owned; ->EAX0/-1, EDX claim sequence.
; Caller-clobbered R8D/R9D also retain raw overflow/count from this same call.
rtl8168_terminal_claims:
    push rbx
    push r12
    push r13
    sub rsp,512
    mov r12d,edi
    mov r13d,esi
    mov rdi,rsp
    call pci_claim_snapshot
    mov r8d,edx                      ; passive metadata before original validation
    mov r9d,eax
    test edx,edx
    jnz .bad
    cmp eax,32
    ja .bad
    xor r10d,r10d
    xor r11d,r11d
    xor ecx,ecx
.record:
    cmp ecx,r9d
    jae .done
    mov ebx,ecx
    shl ebx,4
    add rbx,rsp
    cmp dword [rbx],0xffff
    ja .bad
    mov eax,[rbx+4]
    cmp eax,1
    jb .bad
    cmp eax,PCI_DRV_LAST
    ja .bad
    mov edx,[rbx+8]
    cmp edx,PCI_CLAIM_BOUND
    jb .bad
    cmp edx,PCI_CLAIM_FAILED
    ja .bad
    cmp dword [rbx+12],0
    je .bad
    xor edx,edx
.duplicate:
    cmp edx,ecx
    jae .driver
    mov eax,edx
    shl eax,4
    mov eax,[rsp+rax]
    cmp eax,[rbx]
    je .bad
    inc edx
    jmp .duplicate
.driver:
    cmp dword [rbx+4],PCI_DRV_RTL8168
    jne .next
    test r13d,r13d
    jz .bad
    cmp [rbx],r12d
    jne .bad
    cmp dword [rbx+8],PCI_CLAIM_BOUND
    jne .bad
    inc r10d
    mov r11d,[rbx+12]
.next:
    inc ecx
    jmp .record
.done:
    cmp r10d,r13d
    jne .bad
    xor eax,eax
    mov edx,r11d
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,512
    pop r13
    pop r12
    pop rbx
    ret
rtl8168_terminal_pci:
    mov edi,[rel rtl8168_pci_bus]
    mov esi,[rel rtl8168_pci_dev]
    mov edx,[rel rtl8168_pci_fn]
    jmp pci_cfg_read32
; Exact-width, volatile device accesses; all-ones is unavailable, never success.
rtl8168_terminal_rd8:
    movzx eax,byte [r12+rsi]
    cmp eax,0xff
    je .bad
    clc
    ret
.bad: stc
    ret
rtl8168_terminal_rd16:
    movzx eax,word [r12+rsi]
    cmp eax,0xffff
    je .bad
    clc
    ret
.bad: stc
    ret
rtl8168_terminal_rd32:
    mov eax,[r12+rsi]
    cmp eax,-1
    je .bad
    clc
    ret
.bad: stc
    ret
rtl8168_terminal_wr8:
    mov [r12+rsi],dl
    mfence
    ret
rtl8168_terminal_wr16:
    mov [r12+rsi],dx
    mfence
    ret
rtl8168_terminal_wr32:
    mov [r12+rsi],edx
    mfence
    ret
rtl8168_terminal_access_end:
    ret
; END RTL8168 TERMINAL QUIESCE

; ============================================================================
; netdev_ops implementations
; ============================================================================
rtl8168_init:
    RTL8168_PRODUCER rtl8168_init,-1
.producer_body:
    NATIVE_DRIVER_REFUSE 6
    xor  eax, eax
    ret
rtl8168_start:
    RTL8168_PRODUCER rtl8168_start,-1
.producer_body:
    xor  eax, eax
    ret
rtl8168_stop:
    RTL8168_PRODUCER rtl8168_stop,-1
.producer_body:
    xor  eax, eax
    ret

; tx(self, RSI=frame, RDX=len) -> RAX 0 ok / -1. Synchronous single-descriptor
;   ring TX (desc 0 carries EOR so the NIC wraps back to it): copy the frame into
;   the DMA bounce buffer, clflush it and the descriptor (Alder Lake non-coherent
;   DMA), ring the NPQ TxPoll doorbell, bounded-wait the OWN bit to clear.
; BEGIN FRAME STATS -- pure selected-device software readout.
; RDI=self; EAX=0, RDX=RX, RCX=TX, or -1. Aligned qword observations pair
; with LOCK increments; no transactional cross-counter or hardware-read claim.
rtl8168_frame_stats:
    lea  rax, [rel rtl8168_dev]
    cmp  rdi, rax
    jne  .unavailable
    lea  rax, [rel rtl8168_ops]
    cmp  [rdi + dev.ops], rax
    jne  .unavailable
    mov  rdx, [rel rtl8168_rx_frames]
    mov  rcx, [rel rtl8168_stat_tx_frames]
    xor  eax, eax
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret
; END FRAME STATS

rtl8168_tx:
    RTL8168_PRODUCER rtl8168_tx,-1
.producer_body:
    push rbx
    push r12
    push r13
    push r14
    ; Reject unusable caller lengths before touching the DMA slot. Zero would
    ; underflow the decrement-before-test cache flush loop; an oversized frame
    ; must never be silently truncated and reported as sent.
    test rdx, rdx
    jz   .tx_unowned_reject
    cmp  rdx, RTL_RX_BUF_SIZE
    ja   .tx_unowned_reject
    ; Serialize software producers before the hardware OWN check and copy.
    ; A busy caller returns without touching the current owner's DMA state.
    lock bts dword [rel rtl8168_tx_busy], 0
    jc   .tx_unowned_reject
    cmp  byte [rel rtl8168_bound], 1
    jne  .tx_degrade
    call r68_lr_tick
    test eax, eax
    jnz .tx_reject
    ; Do not hand DMA ownership to a PHY that is down or unreadable. Keep
    ; this fresh byte read before any descriptor/bounce mutation; cached link
    ; state can still describe the period before an autonomous carrier pulse.
    mov  r12, [rel rtl8168_bar2]
    test r12, r12
    jz   .tx_reject
    movzx eax, byte [r12 + RTL_PHYSTS]
    cmp  eax, 0xff
    je   .tx_reject
    test eax, 2
    jz   .tx_reject
    ; Descriptor zero and its bounce buffer are a single in-flight DMA slot.
    ; Never overwrite either while the chip still owns the previous frame.
    mov  rbx, [rel rtl8168_tx_ring]
    test rbx, rbx
    jz   .tx_degrade
    clflush [rbx]
    mfence
    mov  eax, [rbx]
    test eax, (1 << 31)
    jnz  .tx_timeout
    mov  r13, [rel rtl8168_tx_buffer]
    test r13, r13
    jz   .tx_degrade
    mov  r14, rdx
    mov  rdi, r13                          ; copy frame -> bounce buffer
    mov  rcx, r14
    cld
    rep  movsb
    ; flush the packet buffer to RAM (ceil(len/64) lines)
    mov  rax, r13
    mov  ecx, r14d
    add  ecx, 63
    shr  ecx, 6
.tx_flush:
    clflush [rax]
    add  rax, 64
    dec  ecx
    jnz  .tx_flush
    mfence
    ; descriptor 0: OWN|EOR|FS|LS|len
    mov  eax, (1 << 31) | (1 << 30) | (1 << 29) | (1 << 28)
    or   eax, r14d
    mov  [rbx], eax
    mov  dword [rbx + 4], 0
    mov  eax, r13d
    mov  [rbx + 8], eax
    mov  rax, r13
    shr  rax, 32
    mov  [rbx + 12], eax
    clflush [rbx]
    mfence
    mov  r12, [rel rtl8168_bar2]
    mov  byte [r12 + RTL_TPPOLL], 0x40     ; NPQ TxPoll
    mov  ecx, 200000
.tx_wait:
    clflush [rbx]                         ; observe DMA's ownership update
    mfence
    mov  eax, [rbx]
    test eax, (1 << 31)                    ; OWN still set?
    jz   .tx_sent
    pause
    dec  ecx
    jnz  .tx_wait
    jmp  .tx_timeout
.tx_timeout:
    ; A queued descriptor is not wire proof. Leave it/bounce buffer untouched
    ; until a later call sees OWN clear; callers may retry under their budget.
    lock inc qword [rel rtl8168_tx_timeouts]   ; diagnostic only (ROOT120117)
.tx_reject:
    mov  rax, -1
    jmp  .tx_out
.tx_sent:
    lock inc qword [rel rtl8168_stat_tx_frames] ; success only; legacy includes degrade
    lock inc qword [rel rtl8168_tx_frames]
    lock inc qword [rel e1000e_tx_frames]  ; wire TX= counter tracks the active NIC
    xor  eax, eax
    jmp  .tx_out
.tx_degrade:
    lock inc qword [rel rtl8168_tx_frames]
    mov  rax, -1
    jmp  .tx_out
.tx_unowned_reject:
    mov  rax, -1
    jmp  .tx_restore
.tx_out:
    ; Keep admission through completion and counters, including failure exits.
    ; A timed-out DMA descriptor remains protected by its hardware OWN bit.
    mov  dword [rel rtl8168_tx_busy], 0
.tx_restore:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; rx_poll(self, RSI=buf, RDX=cap) -> RAX = len (0 none). Real ring drain with the
;   r8169 cache discipline: clflush the descriptor before reading OWN, clflush the
;   packet buffer before copying, drop DEADBEEF ghost frames, recycle the
;   descriptor (OWN|EOR|size, clflushopt+sfence), and RE-POST the RxPoll doorbell.
rtl8168_rx_poll:
    RTL8168_PRODUCER rtl8168_rx_poll,0
.producer_body:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel rtl8168_bound], 1
    jne  .rx_none
    call r68_lr_tick
    test eax, eax
    jnz .rx_none
    lock inc qword [rel rtl8168_rx_poll_calls]  ; bee004 telemetry: count idle passes that reach RX drain
    mov  r15, rsi                          ; caller buffer
    mov  r14, rdx                          ; cap
    ; bee004: FIRST-idle-tick DNS bootstrap gate release. command_udp.asm gates the
    ; :9997 command port on dns_wire_bootstrap_pending (armed in command_udp_init when
    ; a NIC is egress-selected). The link_status release (below) fires only on the
    ; link-UP transition, which RACES DHCP on this LAN — a FortiGate server answers
    ; PaOS's DISCOVER, and once a DHCP ACK sets dns_server_ip!=0, dns_wire_dhcp_failed
    ; permanently no-ops (its dns_server_ip==0 guard) so the gate never clears inside
    ; TT_TRIAL_BUDGET_S=20 and the box warm-CF9s to Windows before STATUS/PING answer.
    ; rtl8168_rx_poll runs EVERY command_udp_poll tick as the bound egress, starting
    ; on the FIRST idle tick. bee004 v1 (3x phase-7 fail) cleared the gate via
    ; dns_wire_dhcp_failed, but that clear is GUARDED (dns.asm:1726 `dns_server_ip==0`):
    ; the FortiGate on this LAN answers PaOS's DISCOVER, and a DHCP ACK processed in the
    ; SAME command_udp_poll tick — before this rx_poll runs — sets dns_server_ip!=0, so
    ; dns_wire_dhcp_failed permanently no-ops and the gate never clears in-window. The
    ; robust fix: clear the boolean gate DIRECTLY and unconditionally (dns_bootstrap_active
    ; is a plain db; a lone byte store is atomic on x86 and only ever races the one-shot
    ; arm in command_udp_init, which has already run by the first idle tick). This is the
    ; same cross-module global-write pattern this file already uses for e1000e_link_up.
    ; One-shot, and reached only when rtl8168_bound==1 (Beelink metal): QEMU/e1000e and
    ; every foreign class are byte-unchanged. r14/r15 (callee-saved) survive.
    cmp  byte [rel rtl8168_gate_released], 1
    je   .rx_gate_done
    mov  byte [rel rtl8168_gate_released], 1
    mov  byte [rel dns_bootstrap_active], 0   ; open :9997 unconditionally (bypass the guarded clear)
.rx_gate_done:
    ; The proven monolith Beelink reset ran at net_poll_task entry, after all
    ; early boot initialization but before its first descriptor read. This
    ; common driver previously reset only on RDU, which the ghost-payload
    ; Beelink boots never raised. Re-arm once on the exact bound RTL path.
    cmp  byte [rel rtl8168_first_poll_reset_done], 1
    je   .rx_first_reset_done
    call rtl8168_rx_ring_reset
    mov  byte [rel rtl8168_first_poll_reset_done], 1
.rx_first_reset_done:
    mov  rbx, [rel rtl8168_rx_ring]
    mov  eax, [rel rtl8168_rx_idx]
    movzx r13d, al                         ; index (0..255)
    mov  ecx, r13d
    shl  ecx, 4
    add  rbx, rcx                          ; rbx = &rx_ring[idx]
    clflush [rbx]                          ; non-coherent DMA: pull the fresh desc
    mfence
    mov  eax, [rbx]
    test eax, (1 << 31)                    ; OWN set -> HW still owns it
    jnz  .rx_none
    movzx ecx, ax
    and  ecx, 0x3FFF                       ; frame length (incl CRC)
    sub  ecx, 4                            ; strip CRC
    jg   .rx_len_ok
    lock inc qword [rel rtl8168_rx_short_rejects] ; descriptor completed without a usable length
    jmp  .rx_recycle
.rx_len_ok:
    ; A completion is untrusted until its full frame fits this 2 KiB slot
    ; (including CRC), has both endpoints and carries no receive-error summary.
    ; Validate before even flushing/reading its descriptor-supplied address.
    cmp  ecx, RTL_RX_BUF_SIZE - 4
    ja   .rx_recycle
    test eax, (1 << 21)                    ; RxRES
    jnz  .rx_recycle
    mov  edx, eax
    and  edx, (1 << 29) | (1 << 28)        ; FirstFrag|LastFrag
    cmp  edx, (1 << 29) | (1 << 28)
    jne  .rx_recycle
    mov  r12d, ecx                         ; payload length
    mov  rax, [rbx + 8]                    ; validate all 64 descriptor address bits
    mov  rdx, [rel rtl8168_rx_buffers]
    mov  ecx, r13d
    shl  rcx, 11                           ; owned 2048-byte slot for this index
    add  rdx, rcx
    cmp  rax, rdx
    jne  .rx_bad_address
    ; flush ceil(len/64) cache lines of the packet buffer
    push rax
    mov  ecx, r12d
    add  ecx, 63
    shr  ecx, 6
.rx_flush:
    clflush [rax]
    add  rax, 64
    dec  ecx
    jnz  .rx_flush
    mfence
    pop  rax
    mov  edx, [rax]
    cmp  edx, 0xDEADBEEF                   ; ghost frame -> recycle + none
    jne  .rx_payload_ok
    ; Beelink bb30 metal: 172/182 completed descriptors still exposed the
    ; untouched sentinel after the first clflush. Distinguish a late DMA/cache
    ; visibility edge from a permanently absent payload without retaining a
    ; descriptor indefinitely. Only this exact sentinel path pays the bound.
    mov  ecx, RTL_RX_GHOST_RETRY_SPINS
.rx_ghost_wait:
    pause
    clflush [rax]
    mfence
    cmp  dword [rax], 0xDEADBEEF
    jne  .rx_ghost_late
    dec  ecx
    jnz  .rx_ghost_wait
    lock inc qword [rel rtl8168_rx_ghost_rejects] ; descriptor complete, payload untouched
    ; Diagnostic only: separate a corrupt DMA address, a 2 MiB boundary,
    ; and HW error/fragment status. Never expose a physical pointer on wire.
    cmp  dword [rel rtl8168_rx_first_ghost_idx], -1
    jne  .rx_ghost_first_done
    mov  [rel rtl8168_rx_first_ghost_idx], r13d
.rx_ghost_first_done:
    mov  rdx, [rel rtl8168_rx_buffers]
    mov  ecx, r13d
    shl  rcx, 11                         ; 2048-byte slot stride
    add  rdx, rcx                        ; expected DMA address
    cmp  rax, rdx                        ; descriptor-supplied address
    je   .rx_ghost_addr_ok
    lock inc qword [rel rtl8168_rx_addr_mismatch]
.rx_ghost_addr_ok:
    mov  rcx, [rel rtl8168_rx_buffers]
    shr  rdx, 21                         ; expected buffer's 2 MiB page
    shr  rcx, 21                         ; first buffer's 2 MiB page
    cmp  rdx, rcx
    je   .rx_ghost_boundary_ok
    lock inc qword [rel rtl8168_rx_ghost_cross_2m]
.rx_ghost_boundary_ok:
    mov  ecx, [rbx]                      ; completed descriptor status
    test ecx, (1 << 21)                 ; RxRES hardware receive error
    jz   .rx_ghost_error_ok
    lock inc qword [rel rtl8168_rx_ghost_hw_error]
.rx_ghost_error_ok:
    and  ecx, (1 << 29) | (1 << 28)    ; FirstFrag|LastFrag
    cmp  ecx, (1 << 29) | (1 << 28)
    je   .rx_ghost_frag_ok
    lock inc qword [rel rtl8168_rx_ghost_fragmented]
.rx_ghost_frag_ok:
    jmp  .rx_recycle
.rx_ghost_late:
    lock inc qword [rel rtl8168_rx_late_recoveries]
    ; Re-synchronize the whole frame, not only the now-visible first cache line.
    push rax
    mov  ecx, r12d
    add  ecx, 63
    shr  ecx, 6
.rx_late_flush:
    clflush [rax]
    add  rax, 64
    dec  ecx
    jnz  .rx_late_flush
    mfence
    pop  rax
.rx_payload_ok:
    ; copy min(len, cap) to the caller buffer
    mov  rcx, r12
    cmp  rcx, r14
    jbe  .rx_cap_ok
    mov  rcx, r14
.rx_cap_ok:
    mov  rsi, rax
    mov  rdi, r15
    cld
    rep  movsb
    ; w046 secret hygiene: the frame now lives only in the caller's buffer.
    ; Zero the DMA slot (payload + the CRC the chip wrote, bounded by the
    ; slot), re-arm the DEADBEEF ghost sentinel in dword 0 so a reused slot is
    ; byte-identical to its init state (ghost detection then works on every
    ; pass exactly as on the metal-proven first pass), and clflush every line
    ; written + MFENCE BEFORE the OWN store below: no dirty line can be evicted
    ; over a later device write. Only the slot this index owns is written --
    ; never a descriptor-supplied address that disagrees with it.
    mov  rdx, [rel rtl8168_rx_buffers]
    mov  ecx, r13d
    shl  rcx, 11                           ; 2048-byte slot stride
    add  rdx, rcx                          ; expected slot for this index
    cmp  rax, rdx
    jne  .rx_wipe_skip
    push rax                               ; slot base
    mov  rdi, rax
    xor  esi, esi
    lea  edx, [r12d + 4]                   ; payload + stripped CRC
    cmp  edx, RTL_RX_BUF_SIZE
    jbe  .rx_wipe_len_ok
    mov  edx, RTL_RX_BUF_SIZE
.rx_wipe_len_ok:
    push rdx
    call memset
    pop  rcx                               ; wiped length (>= 5)
    mov  rax, [rsp]
    mov  dword [rax], 0xDEADBEEF           ; ghost sentinel back in dword 0
    add  ecx, 63
    shr  ecx, 6                            ; lines touched (slot is 2 KiB aligned)
.rx_wipe_flush:
    clflush [rax]
    add  rax, 64
    dec  ecx
    jnz  .rx_wipe_flush
    mfence                                 ; write-back complete before OWN
    pop  rax
    lock inc qword [rel rtl8168_rx_wipes]
    jmp  .rx_wipe_done
.rx_wipe_skip:
    lock inc qword [rel rtl8168_rx_wipe_skips]
.rx_wipe_done:
    ; recycle the descriptor: clear opts2, OWN|EOR|size
    mov  dword [rbx + 4], 0
    mov  eax, [rbx]
    and  eax, (1 << 30)                    ; preserve EOR
    or   eax, (1 << 31) | RTL_RX_BUF_SIZE
    mov  [rbx], eax
    clflushopt [rbx]
    sfence
    ; re-post the RxPoll doorbell (the non-coherent-RX re-arm)
    mov  rax, [rel rtl8168_bar2]
    mov  byte [rax + RTL_TPPOLL], 0x01
    ; advance index
    mov  eax, r13d
    inc  eax
    cmp  eax, RTL_NUM_RX_DESC
    jb   .rx_adv
    xor  eax, eax
.rx_adv:
    mov  [rel rtl8168_rx_idx], eax
    lock inc qword [rel rtl8168_rx_frames]
    lock inc qword [rel e1000e_rx_frames]  ; wire RX= counter tracks the active NIC
    mov  rax, r12                          ; return the frame length
    jmp  .rx_out
.rx_bad_address:
    lock inc qword [rel rtl8168_rx_addr_mismatch]
.rx_recycle:
    ; Restore the trusted slot address before giving OWN back to the device.
    ; Retaining a corrupted address would authorize the next DMA elsewhere.
    mov  rax, [rel rtl8168_rx_buffers]
    mov  ecx, r13d
    shl  rcx, 11
    add  rax, rcx
    mov  [rbx + 8], rax
    mov  dword [rbx + 4], 0
    mov  eax, [rbx]
    and  eax, (1 << 30)
    or   eax, (1 << 31) | RTL_RX_BUF_SIZE
    mov  [rbx], eax
    clflushopt [rbx]
    sfence
    mov  rax, [rel rtl8168_bar2]
    mov  byte [rax + RTL_TPPOLL], 0x01
    mov  eax, r13d
    inc  eax
    cmp  eax, RTL_NUM_RX_DESC
    jb   .rx_rec_adv
    xor  eax, eax
.rx_rec_adv:
    mov  [rel rtl8168_rx_idx], eax
.rx_none:
    ; bee004 RX-STALL RECOVERY. Telemetry (the :9998 beacon P/R/S counters) proved
    ; the ~13-frame stall precisely: the idle loop ran ~37k passes, R (rx_frames)
    ; stuck at 0x0D, ISR bit4 RDU (RxDescUnavailable) set, CMD=0x0C (RE+TE on). A
    ; bare RxPoll re-kick here was a telemetry-proven NO-OP — the RTL8168 does not
    ; resume from RDU on a TPPoll write once its RX engine has parked. The PROVEN
    ; remedy is a full RX-ring reset, ported by symbol from the monolith
    ; net_poll_task one-time reset (paos.asm): disable RE (CMD=TE only), pause for
    ; the RX DMA to quiesce, re-arm all 256 descriptors (clear opts2, OWN|size, EOR
    ; on last), clflush them to RAM (WB ring, non-coherent DMA — ap#12), reset
    ; rx_idx + RDSAR so the NIC restarts at ring head, clear the latched ISR, then
    ; re-enable RE and kick RxPoll. Triggered ONLY when RDU is actually latched, so
    ; the steady no-frame poll stays cheap. Guarded on bound + real BAR2 (QEMU /
    ; e1000e / foreign classes never reach here); bee003's deadman still returns the
    ; box to Windows if this reset ever wedges, so exercising it on metal is safe.
    cmp  byte [rel rtl8168_bound], 1
    jne  .rx_none_ret
    mov  r12, [rel rtl8168_bar2]
    test r12, r12
    jz   .rx_none_ret
    movzx eax, word [r12 + RTL_ISR]
    test eax, (1 << 4)                     ; RDU (RxDescUnavailable) latched?
    jz   .rx_none_ret
    call rtl8168_rx_ring_reset
    lock inc qword [rel rtl8168_rx_rearms]
.rx_none_ret:
    xor  eax, eax
.rx_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared one-time/RDU receive reset. Called only from bound rtl8168_rx_poll;
; the caller has already saved rbx/r12 and verified exact PCI/MAC identity.
; The ring remains WB; invalidate/write back each completed descriptor line
; before re-enabling RX. This is the v0.3.10 metal-proven first-poll sequence
; and the existing RDU recovery sequence, not a new runtime reset policy.
rtl8168_rx_ring_reset:
    mov  r12, [rel rtl8168_bar2]
    mov  byte [r12 + RTL_CMD], RTL_CMD_TE  ; disable RE, keep TE
    mfence
    mov  ecx, 100000
.rx_rearm_pause:
    pause
    dec  ecx
    jnz  .rx_rearm_pause
    mov  rbx, [rel rtl8168_rx_ring]
    xor  ecx, ecx
.rx_rearm_arm:
    cmp  ecx, RTL_NUM_RX_DESC
    jge  .rx_rearm_done
    mov  dword [rbx + 4], 0                ; clear opts2
    mov  eax, (1 << 31) | RTL_RX_BUF_SIZE  ; OWN | size
    cmp  ecx, RTL_NUM_RX_DESC - 1
    jne  .rx_rearm_no_eor
    or   eax, (1 << 30)                    ; EOR on last
.rx_rearm_no_eor:
    mov  [rbx], eax
    add  rbx, RTL_DESC_SIZE
    inc  ecx
    jmp  .rx_rearm_arm
.rx_rearm_done:
    mov  rbx, [rel rtl8168_rx_ring]        ; flush re-armed WB descriptors to RAM
    mov  ecx, RTL_NUM_RX_DESC * RTL_DESC_SIZE / 64
.rx_rearm_flush:
    clflush [rbx]
    add  rbx, 64
    dec  ecx
    jnz  .rx_rearm_flush
    sfence
    mov  dword [rel rtl8168_rx_idx], 0
    mov  rax, [rel rtl8168_rx_ring]
    mov  [r12 + RTL_RDSAR], eax
    mov  rax, [rel rtl8168_rx_ring]
    shr  rax, 32
    mov  [r12 + RTL_RDSAR_HI], eax
    movzx eax, word [r12 + RTL_ISR]     ; count actual classes at existing W1C
    or [rel rtl8168_isr_seen], rax
    test eax, 3
    jz .no_rx_count
    inc qword [rel rtl8168_rx_status_acks]
.no_rx_count:
    test eax, 12
    jz .no_tx_count
    inc qword [rel rtl8168_tx_status_acks]
.no_tx_count:
    mov  word [r12 + RTL_ISR], 0xFFFF      ; W1C: clear the latched RDU (+ all) status
    mov  byte [r12 + RTL_CMD], RTL_CMD_TE | RTL_CMD_RE  ; re-enable RX
    mfence
    mov  byte [r12 + RTL_TPPOLL], 0x01     ; kick RxPoll to resume the ring
    ; The first reset is not an RDU recovery. The caller increments the RDU
    ; counter only when the interrupt actually latched.
    ret

; link_status(self) -> RAX bit0=up | speed<<8. Reads LIVE PHYSTS. Latches the
;   shared wire NIC_LINK byte when up (the reply reads e1000e_link_up before the
;   allowed guestnet seam runs, so the latch must happen here / at bring-up).
;   Polled every idle tick by boot_p8_nic_watch while the net tile is WARMING
;   (header.asm:1710), which runs AFTER command_udp_init has armed the DNS
;   bootstrap — so this is the in-scope idle seam that opens the command port.
rtl8168_link_status:
    RTL8168_PRODUCER rtl8168_link_status,0
.producer_body:
    xor  eax, eax
    cmp  byte [rel rtl8168_bound], 1
    jne  .ls_out
    call r68_lr_tick
    test eax, eax
    jnz .ls_unknown
    mov  rdx, [rel rtl8168_bar2]
    movzx ecx, byte [rdx + RTL_PHYSTS]
    test cl, 0x02                          ; LinkSts
    jz   .ls_out
    mov  byte [rel rtl8168_link_up], 1
    mov  byte [rel e1000e_link_up], 1      ; latch wire NIC_LINK=1 for the active NIC
    ; bee004: on the bound Beelink, also RELEASE the DNS bootstrap gate at link-up (a
    ; second, transition-triggered site in addition to the rx_poll clear above).
    ; command_udp.asm gates the :9997 command port on dns_wire_bootstrap_pending (armed
    ; in command_udp_init). Clear the boolean directly and unconditionally — the guarded
    ; dns_wire_dhcp_failed no-ops once a FortiGate DHCP ACK sets dns_server_ip!=0 (the
    ; bug that failed bee004 v1 3x). Idempotent (only 1->0), reached only when
    ; rtl8168_bound==1 (Beelink metal), so QEMU/e1000e and foreign classes are unchanged.
    mov  byte [rel dns_bootstrap_active], 0
    mov  byte [rel rtl8168_gate_released], 1
    ; speed from PHYSTS bits 4/3/2 (1000/100/10)
    test cl, 0x10
    jz   .ls_not_1000
    mov  eax, (1000 << 8) | 1
    jmp  .ls_out
.ls_not_1000:
    test cl, 0x08
    jz   .ls_10
    mov  eax, (100 << 8) | 1
    jmp  .ls_out
.ls_10:
    mov  eax, (10 << 8) | 1
.ls_out:
    ret

.ls_unknown:
    mov rax, -1
    ret

; get_mac(self, RSI=out6) -> RAX 0/-1. Only the live IDR MAC is valid. There is
; no target-specific compiled fallback in the common payload.
rtl8168_get_mac:
    cmp  byte [rel rtl8168_mac_ok], 1
    jne  .gm_fail
    mov  eax, [rel rtl8168_mac]
    mov  [rsi], eax
    movzx eax, word [rel rtl8168_mac + 4]
    mov  [rsi + 4], ax
    xor  eax, eax
    ret
.gm_fail:
    mov  eax, -1
    ret

; recover(self) -> RAX 0. The r8169 reset rung: re-post the RxPoll doorbell (the
;   non-coherent-RX re-arm). Structural OK when unbound.
rtl8168_recover:
    RTL8168_PRODUCER rtl8168_recover,-1
.producer_body:
    NATIVE_DRIVER_REFUSE 6
    cmp  byte [rel rtl8168_bound], 1
    jne  .rec_out
    mov  rax, [rel rtl8168_bar2]
    mov  byte [rax + RTL_TPPOLL], 0x01
    mfence
.rec_out:
    xor  eax, eax
    ret

; rtl8168_status_line — append the " NIC=rtl8168" token to a UDP reply, gated on a
;   bound chip. Called from guestnet_status_line (the allowed reply seam). QEMU /
;   non-Beelink never binds, so the reply is byte-unchanged there.
rtl8168_status_line:
    cmp  byte [rel rtl8168_bound], 1
    jne  .sl_out
    lea  rdi, [rel str_rtl8168_nic_tok]
    call udp_put_str
.sl_out:
    ret

; rtl8168_bootlog_line — w046 read-only metal evidence, appended ONLY to the
;   public lean BOOTLOG reply (guestnet_status_line's BOOTLOG branch, and the
;   DHCP-bound lean branch in udp_append_dhcp_bootlog, which returns before it)
;   and ONLY on a bound chip, so QEMU/Lenovo/Dell/MSI replies stay byte-identical. Emits
;   the boot KAT verdict token plus the live RX health counters (low 64 bits).
rtl8168_bootlog_line:
%ifndef PAOS_RTL_BOOTLOG_QEMU_EVIDENCE
    cmp  byte [rel rtl8168_bound], 1
    jne  .bl_out
%endif
    ; NASM_EXTRA=-DPAOS_RTL_BOOTLOG_QEMU_EVIDENCE is a QEMU-harness variant only
    ; (gauntlet_v2/tests/test_rtl8168_bootlog_evidence_qemu.py): QEMU models no
    ; RTL8168, so the variant drops the bound gate to exercise the reply path.
    ; No shipped or lab build defines it.
    lea  rdi, [rel str_rtl_bl_skip]
    cmp  byte [rel rtl8168_rxwipe_kat_verdict], 1
    jne  .bl_not_pass
    lea  rdi, [rel str_rtl_bl_pass]
.bl_not_pass:
    cmp  byte [rel rtl8168_rxwipe_kat_verdict], 2
    jne  .bl_tok
    lea  rdi, [rel str_rtl_bl_fail]
.bl_tok:
    call udp_put_str
    lea  rdi, [rel str_rtl_bl_frames]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_frames]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_wipes]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_wipes]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_wskip]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_wipe_skips]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_ghost]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_ghost_rejects]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_late]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_late_recoveries]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_short]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_short_rejects]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_rearm]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_rearms]
    call udp_put_dec
    lea  rdi, [rel str_rtl_bl_addr]
    call udp_put_str
    mov  rdi, [rel rtl8168_rx_addr_mismatch]
    call udp_put_dec
.bl_out:
    ret

; ============================================================================
; RTL8168H MMIO helper primitives (ported verbatim; R12 = BAR2 base)
; ============================================================================
; rtl_eri_read(EDI=addr) -> EAX = ERIDR. Poll ERIAR(0x74) bit31 high.
rtl_eri_read:
    push rcx
    mov  eax, edi
    and  eax, 0x0FFF
    or   eax, 0xF000                       ; ERIAR_MASK_1111
    mov  [r12 + 0x74], eax
    mov  ecx, 10000
.err_wait:
    mov  eax, [r12 + 0x74]
    test eax, 0x80000000
    jnz  .err_done
    pause
    dec  ecx
    jnz  .err_wait
.err_done:
    mov  eax, [r12 + 0x70]
    pop  rcx
    ret
; rtl_eri_write(EDI=addr, ESI=mask4, EDX=data). Poll ERIAR bit31 clear.
rtl_eri_write:
    push rcx
    mov  [r12 + 0x70], edx
    mov  eax, edi
    and  eax, 0x0FFF
    mov  ecx, esi
    shl  ecx, 12
    or   eax, ecx
    or   eax, 0x80000000
    mov  [r12 + 0x74], eax
    mov  ecx, 10000
.erw_wait:
    mov  eax, [r12 + 0x74]
    test eax, 0x80000000
    jz   .erw_done
    pause
    dec  ecx
    jnz  .erw_wait
.erw_done:
    pop  rcx
    ret
; rtl_mac_ocp_read(EDI=reg) -> AX. OCPDR at 0xB0.
rtl_mac_ocp_read:
    mov  eax, edi
    shl  eax, 15
    mov  [r12 + 0xB0], eax
    mov  eax, [r12 + 0xB0]
    and  eax, 0xFFFF
    ret
; rtl_mac_ocp_write(EDI=reg, ESI=data16).
rtl_mac_ocp_write:
    mov  eax, edi
    shl  eax, 15
    or   eax, 0x80000000
    and  esi, 0xFFFF
    or   eax, esi
    mov  [r12 + 0xB0], eax
    ret
; rtl_gphy_ocp_read(EDI=MII reg) -> AX. OCP addr 0xA400+reg*2 at GPHY_OCP 0xB8.

; Trusted BSP observation: RDI exact selected handle, RSI 20-qword output.
; EAX=0 complete, -1 unavailable (output may be partial; caller keeps validity
; separate). Existing terminal/policy admission; no waits, PHY/OCP transactions,
; MMIO writes, interrupt clears, DMA ownership writes or readiness decisions.
; Schema: family, software TX cursor, tail(-1 unavailable), active TX slots,
; OWN bitmap, RX cursor, current RX status, live PHY, ISR, IMR, TX/RX frames,
; RX/TX status-ACK class counts (poll mode, NOT delivered IRQs), command,
; service-derived new ISR bits, ACK ISR OR, TX timeouts, owner mismatches, RX polls.
; RTL8168 allocates256 TX slots but synchronous TX uses only descriptor0.
rtl8168_witness:
    RTL8168_PRODUCER rtl8168_witness,-1
.producer_body:
    jmp rtl8168_witness_active
rtl8168_witness_active:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13, rsi
    call rtl8168_carrier_ready
    cmp eax, 1
    jne .bad
    mov r12, [rel rtl8168_tx_ring]
    test r12, r12
    jz .bad
    mov r14, [rel rtl8168_rx_ring]
    test r14, r14
    jz .bad
    mov eax, [rel rtl8168_tx_idx]
    cmp eax, 1
    jae .bad
    mov [r13 + 8], rax
    mov eax, [rel rtl8168_rx_idx]
    cmp eax, 256
    jae .bad
    mov [r13 + 40], rax
    shl rax, 4
    add r14, rax
    clflush [r14]
    mfence
    mov eax, [r14 + 0]
    mov [r13 + 48], rax
    xor r15d, r15d
    xor ecx, ecx
.own:
    clflush [r12]
    mfence
    mov eax, [r12]
    test eax, 0x80000000
    jz .next
    bts r15, rcx
.next:
    add r12, 16
    inc ecx
    cmp ecx, 1
    jb .own
    mov [r13 + 32], r15
    mov qword [r13 + 16], -1
    mov qword [r13 + 24], 1
    mov r12, [rel rtl8168_bar2]
    movzx eax, byte [r12 + RTL_PHYSTS]
    mov [r13 + 56], rax
    movzx eax, word [r12 + RTL_ISR]
    mov [r13 + 64], rax
    movzx eax, word [r12 + RTL_IMR]
    mov [r13 + 72], rax
    movzx eax, byte [r12 + RTL_CMD]
    mov [r13 + 112], rax
    mov rax, [rel rtl8168_stat_tx_frames]
    mov [r13 + 80], rax
    mov rax, [rel rtl8168_rx_frames]
    mov [r13 + 88], rax
    mov rax, [rel rtl8168_rx_status_acks]
    mov [r13 + 96], rax
    mov rax, [rel rtl8168_tx_status_acks]
    mov [r13 + 104], rax
    mov qword [r13 + 120], -1          ; service derives 8168 new ISR bits
    mov rax, [rel rtl8168_isr_seen]
    mov [r13 + 128], rax
    mov qword [r13 + 136], -1           ; no existing TX timeout counter
    mov qword [r13 + 144], -1           ; no existing owner mismatch counter
    mov rax, [rel rtl8168_rx_poll_calls]
    mov [r13 + 152], rax
    mov qword [r13], 8168
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; BEGIN CARRIER_DRILL_LEAVES
; RTL8168H/8111H only (the driver's admitted MAC_VER46). Fixed BMCR0
; through the existing GPHY OCP path; separate checked transactions so legacy
; callers keep their contracts. 10000 polls + mandatory 5000 PAUSE quiet gap.
rtl8168_carrier_ready:
    cmp dword [rel rtl8168_terminal_latched],0
    jne .bad
    NATIVE_DRIVER_REFUSE 6
    lea rax, [rel rtl8168_dev]
    cmp rdi, rax
    jne .bad
    cmp byte [rel rtl8168_bound], 1
    jne .bad
    cmp byte [rel rtl8168_mac_ok], 1
    jne .bad
    cmp qword [rel rtl8168_bar2], 0
    je .bad
    cmp qword [rel rtl8168_tx_ring], 0
    je .bad
    cmp qword [rel rtl8168_rx_ring], 0
    je .bad
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret
rtl8168_carrier_read:
    RTL8168_PRODUCER rtl8168_carrier_read,-1
.producer_body:
    call rtl8168_carrier_ready
    cmp eax, 1
    jne rtl8168_carrier_bad
    mov edx, (0xa400 << 15)
    xor r8d, r8d
    jmp rtl8168_carrier_ocp
rtl8168_carrier_write:
    RTL8168_PRODUCER rtl8168_carrier_write,-1
.producer_body:
    call rtl8168_carrier_ready
    cmp eax, 1
    jne rtl8168_carrier_bad
    test esi, 0xffff0000
    jnz rtl8168_carrier_bad
    mov edx, esi
    or edx, (0xa400 << 15) | 0x80000000
    mov r8d, 1
rtl8168_carrier_ocp:
    mov r9, [rel rtl8168_bar2]
    mov [r9 + 0xb8], edx
    mov ecx, 10000
.poll:
    mov eax, [r9 + 0xb8]
    cmp eax, -1
    je .fail
    test eax, 0x80000000
    jz .clear
    test r8d, r8d
    jz .read
    jmp .wait
.clear:
    test r8d, r8d
    jnz .write
.wait:
    pause
    dec ecx
    jnz .poll
.fail:
    mov rax, -1
    jmp .quiet
.read:
    and eax, 0xffff
    jmp .quiet
.write:
    xor eax, eax
.quiet:
    mov ecx, 5000
.delay:
    pause
    dec ecx
    jnz .delay
    ret
rtl8168_carrier_link:
    RTL8168_PRODUCER rtl8168_carrier_link,-1
.producer_body:
    call rtl8168_carrier_ready
    cmp eax, 1
    jne .bad
    mov r9, [rel rtl8168_bar2]
    movzx edx, byte [r9 + 0x6c]
    cmp edx, 0xff
    je .bad
    mov eax, edx
    shr eax, 1
    and eax, 1
    ret
.bad:
    mov rdx, -1
rtl8168_carrier_bad:
    mov rax, -1
    ret
; END CARRIER_DRILL_LEAVES

rtl_gphy_ocp_read:
    push rcx
    movzx eax, di
    and  eax, 0x1F
    shl  eax, 1
    add  eax, 0xA400
    shl  eax, 15
    mov  [r12 + 0xB8], eax
    mov  ecx, 10000
.gpr_wait:
    mov  eax, [r12 + 0xB8]
    test eax, 0x80000000
    jnz  .gpr_done
    pause
    dec  ecx
    jnz  .gpr_wait
.gpr_done:
    and  eax, 0xFFFF
    mov  ecx, 5000
.gpr_delay:
    pause
    dec  ecx
    jnz  .gpr_delay
    pop  rcx
    ret
; rtl_gphy_ocp_write(EDI=MII reg, ESI=value16).
rtl_gphy_ocp_write:
    push rcx
    movzx eax, di
    and  eax, 0x1F
    shl  eax, 1
    add  eax, 0xA400
    shl  eax, 15
    movzx ecx, si
    or   eax, ecx
    or   eax, 0x80000000
    mov  [r12 + 0xB8], eax
    mov  ecx, 10000
.gpw_wait:
    mov  eax, [r12 + 0xB8]
    test eax, 0x80000000
    jz   .gpw_done
    pause
    dec  ecx
    jnz  .gpw_wait
.gpw_done:
    mov  ecx, 5000
.gpw_delay:
    pause
    dec  ecx
    jnz  .gpw_delay
    pop  rcx
    ret
; rtl_ephy_read(EDI=reg5) -> AX. EPHYAR at 0x80.
rtl_ephy_read:
    push rcx
    mov  eax, edi
    and  eax, 0x1F
    shl  eax, 16
    mov  [r12 + 0x80], eax
    mov  ecx, 10000
.epr_wait:
    mov  eax, [r12 + 0x80]
    test eax, 0x80000000
    jnz  .epr_done
    pause
    dec  ecx
    jnz  .epr_wait
.epr_done:
    and  eax, 0xFFFF
    pop  rcx
    ret
; rtl_ephy_write(EDI=reg5, ESI=value16).
rtl_ephy_write:
    push rcx
    mov  eax, edi
    and  eax, 0x1F
    shl  eax, 16
    or   eax, esi
    or   eax, 0x80000000
    mov  [r12 + 0x80], eax
    mov  ecx, 10000
.epw_wait:
    mov  eax, [r12 + 0x80]
    test eax, 0x80000000
    jz   .epw_done
    pause
    dec  ecx
    jnz  .epw_wait
.epw_done:
    pop  rcx
    ret
; rtl_csi_read(EDI=addr) -> EAX. CSIAR 0x68 / CSIDR 0x64.
rtl_csi_read:
    push rcx
    mov  eax, edi
    and  eax, 0x0FFF
    mov  [r12 + 0x68], eax
    mov  ecx, 10000
.csr_wait:
    mov  eax, [r12 + 0x68]
    test eax, 0x80000000
    jnz  .csr_done
    pause
    dec  ecx
    jnz  .csr_wait
.csr_done:
    mov  eax, [r12 + 0x64]
    pop  rcx
    ret
; rtl_csi_write(EDI=addr, ESI=data32).
rtl_csi_write:
    push rcx
    mov  [r12 + 0x64], esi
    mov  eax, edi
    and  eax, 0x0FFF
    or   eax, 0x80000000
    mov  [r12 + 0x68], eax
    mov  ecx, 10000
.csw_wait:
    mov  eax, [r12 + 0x68]
    test eax, 0x80000000
    jz   .csw_done
    pause
    dec  ecx
    jnz  .csw_wait
.csw_done:
    pop  rcx
    ret

; rtl_mark_uc(RDI=phys) — mark the containing 2 MiB identity page uncacheable
;   (PCD+PWT). Ported from the monolith mark_mmio_uncacheable; this tree's
;   boot/paging.asm uses the SAME layout (PD0 at pml4_addr+0x2000, 8192 entries,
;   index = phys>>21) so the walk is identical. clobbers RAX,RCX,R8.
rtl_mark_uc:
    mov  rax, rdi
    mov  rcx, rax
    shr  rcx, 21                           ; PD entry index
    cmp  ecx, 8192
    jge  .uc_out
    mov  r8, [rel pml4_addr]
    lea  r8, [r8 + 0x2000]                 ; PD0 base
    mov  rax, [r8 + rcx*8]
    or   rax, 0x18                         ; PCD | PWT = UC
    mov  [r8 + rcx*8], rax
    mov  rax, rdi
    and  rax, ~0x1FFFFF
    invlpg [rax]
.uc_out:
    ret

; ============================================================================
; rtl8168_rx_diag_emit(RDI=wire cursor) -> RDI advanced. bee004 descriptor-level
; instrument for the serial-less box: appends four space-prefixed 8-hex fields to
; the :9998 beacon so tcpdump-on-gpu can see WHY RX sticks at ~13 (RDU) — the pure
; cache theories (WB stall vs UC stall) were BOTH 13, so this reads the actual
; descriptor + page state at the stuck slot:
;   D<opts1>  desc[rx_idx].opts1 read FRESH (clflush+mfence) — host's OWN view at
;             the stuck descriptor (bit31 OWN=1 => host thinks NIC still owns it)
;   E<pde>    ring page PDE low32 — bit4 PCD|bit3 PWT (=0x18 masked) proves whether
;             candidate #1's rtl_mark_uc actually made the ring UNCACHED on metal
;   I<idx>    rtl8168_rx_idx — where the host drain pointer is parked
;   Z<opts1>  desc[0].opts1 FRESH — a recycled descriptor's OWN as it reached memory
; Read-only (clflush of a live descriptor is exactly what rtl8168_rx_poll already
; does); preserves every register the beacon builder relies on (RBX frame base, R12).
; ============================================================================
rtl8168_rx_diag_emit:
    push rax
    push rbx
    push rcx
    push rdx
    push r9
    push r10
    ; No target binary fork: absent/wrong-device/QEMU beacons stay byte-identical.
    cmp  byte [rel rtl8168_bound], 1
    jne  .rd_done
    cld
    mov  rbx, [rel rtl8168_rx_ring]
    test rbx, rbx
    jz   .rd_zeros
    mov  eax, [rel rtl8168_rx_idx]
    and  eax, 0xFF
    shl  eax, 4
    lea  r10, [rbx + rax]                   ; &desc[rx_idx]
    clflush [r10]
    mfence
    mov  r9d, [r10]                          ; D
    mov  dl, 'D'
    call .rd_field
    mov  rax, rbx
    shr  rax, 21                            ; PD index
    mov  rcx, [rel pml4_addr]
    mov  r9d, [rcx + 0x2000 + rax*8]         ; E = PDE low32
    mov  dl, 'E'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_idx]           ; I
    mov  dl, 'I'
    call .rd_field
    clflush [rbx]
    mfence
    mov  r9d, [rbx]                          ; Z = desc[0].opts1 fresh
    mov  dl, 'Z'
    call .rd_field
    ; These low-32 snapshots distinguish an idle poller, drained frames and a
    ; real RDU reset while command RX itself is temporarily unreachable.
    mov  r9d, [rel rtl8168_rx_poll_calls]
    mov  dl, 'P'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_frames]
    mov  dl, 'R'
    call .rd_field
    ; f349 metal: index 0->224 while only 12 usable frames. Distinguish the
    ; historical zero-length descriptor from untouched DEADBEEF DMA buffers.
    mov  r9d, [rel rtl8168_rx_ghost_rejects]
    mov  dl, 'G'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_late_recoveries]
    mov  dl, 'T'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_addr_mismatch]
    mov  dl, 'A'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_first_ghost_idx]
    mov  dl, 'B'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_ghost_cross_2m]
    mov  dl, 'C'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_ghost_hw_error]
    mov  dl, 'H'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_ghost_fragmented]
    mov  dl, 'F'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_short_rejects]
    mov  dl, 'L'
    call .rd_field
    mov  r9d, [rel rtl8168_rx_rearms]
    mov  dl, 'U'
    call .rd_field
    mov  rax, [rel rtl8168_bar2]
    test rax, rax
    jz   .rd_isr_zero
    movzx r9d, word [rax + RTL_ISR]         ; S = live interrupt/RDU flags
    jmp  .rd_isr_ready
.rd_isr_zero:
    xor  r9d, r9d
.rd_isr_ready:
    mov  dl, 'S'
    call .rd_field
    jmp  .rd_done
.rd_zeros:
    xor  r9d, r9d
    mov  dl, 'D'
    call .rd_field
    mov  dl, 'E'
    call .rd_field
    mov  dl, 'I'
    call .rd_field
    mov  dl, 'Z'
    call .rd_field
.rd_done:
    pop  r10
    pop  r9
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret
.rd_field:
    mov  al, ' '
    stosb
    mov  al, dl
    stosb
    mov  ecx, 8
.rd_nib:
    rol  r9d, 4
    mov  eax, r9d
    and  eax, 0x0F
    cmp  al, 10
    jb   .rd_dec
    add  al, 'A' - 10
    jmp  .rd_emit
.rd_dec:
    add  al, '0'
.rd_emit:
    stosb
    dec  ecx
    jnz  .rd_nib
    ret

; ============================================================================
; data (in-image writable)
; ============================================================================
rtl8168_dev:        times dev_size db 0
rtl8168_ops:        times netdev_ops_size db 0
align 8
rtl8168_terminal_gate: dd 0       ; 0 idle,1 producer/preflight,2 terminal
rtl8168_terminal_latched: dd 0
rtl8168_terminal_spans: dd 4096,4096,524288,2048
rtl8168_tx_busy:    dq 0                  ; bit0: synchronous TX software owner
rtl8168_bar2:       dq 0
rtl8168_tx_ring:    dq 0
rtl8168_rx_ring:    dq 0
rtl8168_rx_buffers: dq 0
rtl8168_tx_buffer:  dq 0
rtl8168_stat_tx_frames: dq 0
rtl8168_isr_seen: dq 0                  ; OR of actual existing ACK observations
rtl8168_rx_status_acks: dq 0             ; latched ISR classes observed at existing W1C
rtl8168_tx_status_acks: dq 0             ; not hardware delivered interrupt counts
rtl8168_tx_frames:  dq 0
rtl8168_rx_frames:  dq 0
rtl8168_rx_ghost_rejects: dq 0            ; completed desc, DEADBEEF buffer sentinel survives clflush
rtl8168_rx_late_recoveries: dq 0           ; sentinel cleared during bounded post-OWN retry
rtl8168_rx_addr_mismatch: dq 0             ; completed descriptor address != expected slot
rtl8168_rx_ghost_cross_2m: dq 0            ; ghost slot past first buffer's 2 MiB page
rtl8168_rx_ghost_hw_error: dq 0             ; ghost descriptor RxRES set
rtl8168_rx_ghost_fragmented: dq 0           ; ghost descriptor lacks both frame endpoints
rtl8168_rx_short_rejects: dq 0            ; completed desc, length <= CRC bytes
rtl8168_rx_poll_calls: dq 0               ; bee004 wire telemetry: idle-pass proxy (rx_poll runs once per command_udp_poll tick)
rtl8168_rx_rearms:  dq 0                   ; bee004 wire telemetry: RDU-triggered RX-ring reset recoveries (.rx_none)
rtl8168_rx_wipes:   dq 0                   ; w046: delivered slots zeroed + sentinel re-armed before OWN
rtl8168_rx_wipe_skips: dq 0                ; w046: descriptor address != index slot, slot left untouched
rtl8168_claim_found: db 0                 ; 1 = rtl8168_pci_bus/dev/fn name the chip matched
align 4
rtl8168_pci_bus:    dd 0
rtl8168_pci_dev:    dd 0
rtl8168_pci_fn:     dd 0
rtl8168_tx_idx:     dd 0
rtl8168_rx_idx:     dd 0
rtl8168_rx_first_ghost_idx: dd -1          ; diagnostic index only, no DMA pointer
rtl8168_bound:      db 0
rtl8168_link_up:    db 0
rtl8168_gate_released: db 0                ; bee004: one-shot DNS bootstrap gate release (first idle tick)
rtl8168_first_poll_reset_done: db 0        ; after exact RTL bind, before first RX descriptor read
rtl8168_mac_ok:     db 0
rtl8168_mac_ver46:  db 0
rtl8168_mac:        times 6 db 0
rtl8168_state_end:                         ; w046 KAT snapshot covers rtl8168_bar2 .. here
RTL_STATE_BYTES equ rtl8168_state_end - rtl8168_bar2
rtl8168_rxwipe_kat_verdict: db 0           ; w046: 1 pass, 2 fail, 3 skipped (never restored)
align 8
rtl8168_info:
    dq 0                                   ; .name: set at register time (org 0 image: no static pointers)
    dd 1500                                ; .mtu
    db 64                                   ; .dma_mask
    dd 0                                    ; .flags
    dd 0                                    ; .speed_caps
str_rtl8168_name:     db "rtl8168", 0
str_rtl8168_nic_tok:  db " NIC=rtl8168", 0
str_rtl_ready:        db "[PAOS64] L2 netdev: RTL8168H MAC_VER_46 bound: rings armed + PHY autoneg (ANAR 0x01E1) [net.rtl8168h.ready]", 13, 10, 0
str_rtl_absent:       db "[PAOS64] L2 netdev: rtl8168 skipped (no 10ec:8168 on any bus) [netdev.rtl8168.absent]", 13, 10, 0
; --- w046 RX slot wipe KAT + BOOTLOG evidence --------------------------------
str_rtl_kat_pass:     db "[PAOS64] L2 netdev: rtl8168 RX slot wipe KAT PASS cases=3 residue=none sentinel=rearmed stale=0 via=rtl8168_rx_poll [net.rtl8168.rxwipe.kat]", 13, 10, 0
str_rtl_kat_fail:     db "[PAOS64] L2 netdev: rtl8168 RX slot wipe KAT FAIL reason=", 0
str_rtl_kat_fail_tail: db " [net.rtl8168.rxwipe.fail]", 13, 10, 0
str_rtl_kat_skip:     db "[PAOS64] L2 netdev: rtl8168 RX slot wipe KAT skipped reason=", 0
str_rtl_kat_skip_tail: db " [net.rtl8168.rxwipe.skipped]", 13, 10, 0
str_rtl_kat_skip_cpu:   db "no_clflushopt", 0
str_rtl_kat_skip_state: db "driver_bound_or_image_above_4g", 0
str_rtl_kat_r_len:      db "length", 0
str_rtl_kat_r_content:  db "content", 0
str_rtl_kat_r_residue:  db "residue", 0
str_rtl_kat_r_sentinel: db "sentinel", 0
str_rtl_kat_r_bound:    db "overwipe", 0
str_rtl_kat_r_desc:     db "descriptor", 0
str_rtl_kat_r_stale:    db "stale_redelivered", 0
str_rtl_kat_r_ghost:    db "ghost_not_counted", 0
str_rtl_kat_r_cap:      db "cap", 0
str_rtl_bl_pass:      db " net.rtl8168.rxwipe.kat", 0
str_rtl_bl_fail:      db " net.rtl8168.rxwipe.fail", 0
str_rtl_bl_skip:      db " net.rtl8168.rxwipe.skipped", 0
str_rtl_bl_frames:    db " rtl_rx_frames=", 0
str_rtl_bl_wipes:     db " rtl_rx_wipes=", 0
str_rtl_bl_wskip:     db " rtl_rx_wipe_skips=", 0
str_rtl_bl_ghost:     db " rtl_rx_ghost=", 0
str_rtl_bl_late:      db " rtl_rx_late=", 0
str_rtl_bl_short:     db " rtl_rx_short=", 0
str_rtl_bl_rearm:     db " rtl_rx_rearms=", 0
str_rtl_bl_addr:      db " rtl_rx_addr_mismatch=", 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; w046 KAT scratch: page-isolated WDATA (KAT stores never share a page with code).
%macro WDATA_dev_net_rtl8168_0 0
alignb 64
rtl_kat_ring:       resb 64                 ; one 16-byte descriptor (+ pad)
rtl_kat_tx_ring:    resb 64                 ; private idle TX for ordinary RX link sampling
rtl_kat_bar:        resb 256                ; BAR2 stand-in: TPPOLL/ISR land here
rtl_kat_slot:       resb RTL_RX_BUF_SIZE       ; 64-aligned (block start + 384)
rtl_kat_rx:         resb RTL_RX_BUF_SIZE       ; caller buffer
rtl_kat_rearm_save: resb REALTEK_LR_SIZE       ; restored before the whole scratch scrub
rtl_kat_scratch_end:
rtl_kat_save:       resb RTL_STATE_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_dev_net_rtl8168_0
RTL_KAT_SCRATCH_BYTES equ rtl_kat_scratch_end - rtl_kat_ring

; Ordinary producer paths hold RTL8168_PRODUCER, including RX (the common
; UDP poll does not call link_status for this backend).
r68_lr_tick:
    NATIVE_DRIVER_REFUSE 6
    lea rax, [rel rtl8168_link_rearm_state]
    REALTEK_LINK_REARM_BODY r68
r68_lr_sample:
    mov edx, REALTEK_LR_UNREAD
    cmp byte [rel rtl8168_bound], 1
    jne .bad
    cmp qword [rel rtl8168_tx_ring], 0
    je .bad
    mov r9, [rel rtl8168_bar2]
    movzx eax, byte [r9+RTL_PHYSTS]
    mov edx, eax                    ; raw PHYSTS for the diagnostic record
    cmp eax, 0xff
    je .bad
    shr eax, 1
    and eax, 1
    ret
.bad:
    mov rax, -1
    ret
r68_lr_cmd:
    mov r9, [rel rtl8168_bar2]
    movzx eax, byte [r9+RTL_CMD]
    ret
r68_lr_own:
    ; This driver publishes only synchronous descriptor zero, with EOR on it.
    mov r8, [rel rtl8168_tx_ring]
    clflush [r8]
    mfence
    mov eax, [r8]
    shr eax, 31
    ret
r68_lr_phy_read:
    mov edx, edi
    shl edx, 15
    xor r8d, r8d
    jmp rtl8168_carrier_ocp
r68_lr_phy_write:
    shl edi, 15
    or edx, edi
    or edx, 0x80000000
    mov r8d, 1
    jmp rtl8168_carrier_ocp
r68_lr_advertise:
    ; The backend's own full PHY bring-up advertisement order (ANAR, GBCR),
    ; now using checked OCP completion, before the checked BMCR restart.
    mov edi, 0xa408
    mov edx, 0x01e1
    call r68_lr_phy_write
    test eax, eax
    jnz .bad
    mov edi, 0xa412
    mov edx, 0x0200
    jmp r68_lr_phy_write
.bad:
    mov rax, -1
    ret
r68_lr_wake:
    REALTEK_PHY_WAKE_BODY r68
r68_lr_ready:
    REALTEK_PHY_READY_BODY r68
r68_lr_close:
    mov byte [rel rtl8168_bound], 0
    mov byte [rel rtl8168_link_up], 0
    ret
; Memory copy only. Five counts down/up/rearmed/stuck/failures; once the tick
; has run, ten more: phase, saved OWN, live OWN, PHYSTS, BMCR, BMSR, CMD,
; TX timeouts, rx_poll calls, ticks. EAX = qwords written (5 or 15).
rtl8168_link_rearm_counts:
    lea r8, [rel rtl8168_link_rearm_state+16]
    xor ecx, ecx
.copy:
    mov rax, [r8+rcx*8]
    mov [rdi+rcx*8], rax
    inc ecx
    cmp ecx, 5
    jb .copy
    mov eax, 5
    lea r8, [rel rtl8168_link_rearm_state]
    cmp qword [r8+REALTEK_LR_TICKS], 0
    je .out                          ; never driven: the legacy five-count tuple
    lea r9, [rdi+40]
    REALTEK_LR_RECORD
    mov rax, [rel rtl8168_tx_timeouts]
    mov [r9+56], rax
    mov rax, [rel rtl8168_rx_poll_calls]
    mov [r9+64], rax
    mov eax, 15
.out:
    ret
; Live command-NIC link for NIC_LINK (ROOT120117): memory only, no hardware
; read. 1 iff bound, the transition machine is up (phase 1) and its latest
; raw PHYSTS sample has LinkSts. A down, settling, failed or closed NIC is 0.
rtl8168_link_live:
    xor eax, eax
    cmp byte [rel rtl8168_bound], 1
    jne .out
    cmp qword [rel rtl8168_link_rearm_state], 1
    jne .out
    mov rdx, [rel rtl8168_link_rearm_state+REALTEK_LR_PHYS]
    cmp rdx, 0xff
    jae .out
    shr edx, 1
    and edx, 1
    mov eax, edx
.out:
    ret
align 8
rtl8168_link_rearm_state: times REALTEK_LR_SIZE db 0
rtl8168_tx_timeouts: dq 0

; Reset/re-arm only the already bound MAC_VER46 and retained DMA allocation.
; Called with the existing producer gate held, never by a private dispatcher.
; MAC reset completion (including TE/RE clear) precedes EVERY ring rewrite.
r68_lr_reset:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, [rel rtl8168_bar2]
    mov r13, [rel rtl8168_tx_ring]
    mov r14, [rel rtl8168_rx_ring]
    mov r15, [rel rtl8168_rx_buffers]
    test r12, r12
    jz .bad
    test r13, r13
    jz .bad
    test r14, r14
    jz .bad
    test r15, r15
    jz .bad
    cmp qword [rel rtl8168_tx_buffer], 0
    je .bad
    mov eax, [r12+RTL_TCR]
    and eax, RTL_MAC_VER_46_MASK
    cmp eax, RTL_MAC_VER_46_VALUE
    jne .bad
    mov byte [rel rtl8168_bound], 0
    mov byte [rel rtl8168_link_up], 0
    mov word [r12+RTL_IMR], 0
    mov eax, [r12+RTL_RCR]
    and eax, ~0x3f
    mov [r12+RTL_RCR], eax
    mov eax, [r12+RTL_MISC]
    or eax, RTL_MISC_RXDV_GATE
    mov [r12+RTL_MISC], eax
    mfence
    mov byte [r12+RTL_CMD], 0x10   ; BSD RE_CMD_RESET / chip soft reset
    mfence
    mov ebx, 1000
.wait_reset:
    movzx eax, byte [r12+RTL_CMD]
    cmp eax, 0xff
    je .bad
    test eax, 0x1c                ; reset + both DMA enables must clear
    jz .reset_done
    mov edi, 100
    call tsc_delay_us
    dec ebx
    jnz .wait_reset
    jmp .bad
.reset_done:
    mov eax, [r12+RTL_IDR0]
    cmp eax, [rel rtl8168_mac]
    jne .bad
    mov ax, [r12+RTL_IDR4]
    cmp ax, [rel rtl8168_mac+4]
    jne .bad
    mov byte [r12+RTL_CFG9346], RTL_CFG9346_UNLOCK
    mov word [r12+RTL_ISR], RTL_ISR_ALL
    ; Pinned buffers stay at their original addresses; no allocation/free or
    ; packet replay. Ring zeroing is safe only after the checked idle reset.
    mov rdi, r13
    mov ecx, RTL_NUM_TX_DESC*RTL_DESC_SIZE/8
    xor eax, eax
    cld
    rep stosq
    mov dword [r13+(RTL_NUM_TX_DESC-1)*RTL_DESC_SIZE], 1<<30
    mov rdi, r14
    mov rdx, r15
    xor ecx, ecx
.rx_arm:
    mov dword [rdi+4], 0
    mov [rdi+8], rdx
    mov eax, (1<<31)|RTL_RX_BUF_SIZE
    cmp ecx, RTL_NUM_RX_DESC-1
    jne .not_last
    or eax, 1<<30
.not_last:
    sfence
    mov [rdi], eax
    clflush [rdi]
    add rdi, RTL_DESC_SIZE
    add rdx, RTL_RX_BUF_SIZE
    inc ecx
    cmp ecx, RTL_NUM_RX_DESC
    jb .rx_arm
    mov rdi, r13
    mov ecx, RTL_NUM_TX_DESC*RTL_DESC_SIZE/64
.tx_flush:
    clflush [rdi]
    add rdi, 64
    dec ecx
    jnz .tx_flush
    mfence
    mov [r12+RTL_TNPDS], r13d
    mov rax, r13
    shr rax, 32
    mov [r12+RTL_TNPDS_HI], eax
    mov [r12+RTL_RDSAR], r14d
    mov rax, r14
    shr rax, 32
    mov [r12+RTL_RDSAR_HI], eax
    mov dword [rel rtl8168_tx_idx], 0
    mov dword [rel rtl8168_rx_idx], 0
    mov eax, [r12+RTL_MISC]
    and eax, ~RTL_MISC_RXDV_GATE
    mov [r12+RTL_MISC], eax
    mov dword [r12+RTL_TCR], RTL_TCR_VAL
    mov dword [r12+RTL_RCR], RTL_RCR_VAL
    mov word [r12+RTL_RMS], RTL_RX_BUF_SIZE
    mov word [r12+0xe0], 0         ; checksum/offload disabled, retained 64-bit desc
    mfence
    mov byte [r12+RTL_CMD], RTL_CMD_TE|RTL_CMD_RE
    mfence
    mov byte [r12+RTL_CFG9346], RTL_CFG9346_LOCKED
    mov ecx, 10000
.enable:
    movzx eax, byte [r12+RTL_CMD]
    cmp eax, 0xff
    je .bad
    and eax, RTL_CMD_TE|RTL_CMD_RE
    cmp eax, RTL_CMD_TE|RTL_CMD_RE
    je .armed
    pause
    dec ecx
    jnz .enable
    jmp .bad
.armed:
    mov byte [r12+RTL_TPPOLL], 1
    mfence
    mov byte [rel rtl8168_first_poll_reset_done], 1
    mov byte [rel rtl8168_bound], 1
    xor eax, eax
    jmp .out
.bad:
    ; A failed reset leaves DMA memory pinned and the driver closed; it never
    ; zeroes an OWN descriptor to manufacture recovery or recycles a buffer.
    mov byte [rel rtl8168_bound], 0
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
