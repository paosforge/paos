;; MODULE dev/net/rtl8168
;; LAYER 3
;; EXPORTS rtl8168_create, rtl8168_hw_bringup, rtl8168_boot_bringup, rtl8168_status_line, rtl8168_bootlog_line, rtl8168_rx_diag_emit, rtl8168_frame_stats, rtl8168_dev
;; IMPORTS boot/native_driver_gate, net/netdev, bus/pci, core/dma, core/heap, boot/serial, dev/net/e1000e, net/dns, core/lib/mem, bus/pci_claim
;; CAPS mmio dma
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
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
rtl8168_create:
    NATIVE_DRIVER_REFUSE 6
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
    NATIVE_DRIVER_REFUSE 6
    call rtl8168_rx_wipe_kat               ; w046: in-image ring only, before register/bind
    call rtl8168_create                    ; register fail-closed/degraded
    call rtl8168_hw_bringup                 ; strict runtime-discovered bind
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
;   ring in this image's WDATA, with a scratch page standing in for BAR2: no
;   MMIO, no PCI, no DMA. Runs from rtl8168_boot_bringup BEFORE rtl8168_create
;   and rtl8168_hw_bringup (single-threaded P8, nothing registered or bound),
;   snapshots every driver global it touches and restores them byte-for-byte.
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
    call rtl8168_rx_poll
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
    call rtl8168_rx_poll
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
    call rtl8168_rx_poll
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
    NATIVE_DRIVER_REFUSE 6
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

; ============================================================================
; netdev_ops implementations
; ============================================================================
rtl8168_init:
    NATIVE_DRIVER_REFUSE 6
    xor  eax, eax
    ret
rtl8168_start:
    xor  eax, eax
    ret
rtl8168_stop:
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
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel rtl8168_bound], 1
    jne  .rx_none
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
    xor  eax, eax
    cmp  byte [rel rtl8168_bound], 1
    jne  .ls_out
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
rtl8168_tx_busy:    dq 0                  ; bit0: synchronous TX software owner
rtl8168_bar2:       dq 0
rtl8168_tx_ring:    dq 0
rtl8168_rx_ring:    dq 0
rtl8168_rx_buffers: dq 0
rtl8168_tx_buffer:  dq 0
rtl8168_stat_tx_frames: dq 0
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
rtl_kat_bar:        resb 256                ; BAR2 stand-in: TPPOLL/ISR land here
rtl_kat_slot:       resb RTL_RX_BUF_SIZE       ; 64-aligned (block start + 320)
rtl_kat_rx:         resb RTL_RX_BUF_SIZE       ; caller buffer
rtl_kat_scratch_end:
rtl_kat_save:       resb RTL_STATE_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_dev_net_rtl8168_0
RTL_KAT_SCRATCH_BYTES equ rtl_kat_scratch_end - rtl_kat_ring
