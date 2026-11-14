;; MODULE dev/net/rtl8126
;; LAYER 3
;; EXPORTS e5000b_hw_bringup, e5000b_recover, e5000b_dev, e5000b_mac, e5000b_devid, e5000b_hw_ok, e5000b_mac_ok, e5000b_rings_ok, e5000b_iso_ok, e5000b_link_up, e5000b_link_speed, e5000b_rx_frames, e5000b_tx_frames, e5000b_matches, rtl8126_frame_stats, rtl8126_attach_snapshot
;; IMPORTS boot/native_driver_gate, net/netdev, bus/pci, bus/hal, core/dma, core/time, boot/serial, dev/net/e1000e, bus/pci_claim
;; CAPS mmio dma
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
; ============================================================================
; dev/net/rtl8126.asm — Realtek RTL8126 / Killer E5000B (5 GbE)
; native backend behind the netdev_ops class seam.
;
; RCQ-31 clean-room chip protocol, independently implemented from pinned ISC
; OpenBSD rge sources and the contract in
; gauntlet_v2/docs/CLEANROOM_RTL8126_SPEC.md. Section 5 binds every chip fact,
; source hash, initialization facts and host control. R16 replaces inherited
; state with the pinned MAC_R26 complete attach/PHY/MAC sequence. R9 programs
; the bounded BSD single-queue MAC setup on every arm/recovery instead of
; inheriting another OS's RSS/queue/config state.
; Kept glue: PCI discovery (exactly one 10ec:5000 or 10ec:8126 on
; any bus), memory/bus-master enable, BAR2, the DMA rings and buffers, netdev
; registration at PRIO_NATIVE+1 with NETDEV_F_ADDR_MSI, the recovery rung, the
; bounded link wait, frame statistics, the diag line and the markers. Absent
; (QEMU / no supported chip) the path is unchanged: [netdev.rtl8126.absent], nothing
; registers. Host controls are preflight; the native path still needs MSI proof.
;
; BSD source notices retained for the pinned OpenBSD protocol reference:
; if_rge.c: Copyright (c) 2019, 2020, 2023-2025 Kevin Lo <kevlo@openbsd.org>
; if_rgereg.h: Copyright (c) 2019, 2020, 2025 Kevin Lo <kevlo@openbsd.org>
;
; Permission to use, copy, modify, and distribute this software for any
; purpose with or without fee is hereby granted, provided that the above
; copyright notice and this permission notice appear in all copies.
;
; THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
; WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
; MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
; ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
; WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
; ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
; OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
; ============================================================================

%include "core/abi/pci_claim.inc"
%include "core/abi/rtl8126_attach.inc"

; --- Killer E5000B / RTL8126 PCI identity ---------------------------------------
E5B_VENDOR        equ 0x10EC          ; Realtek
E5B_DEVID         equ 0x5000          ; Killer E5000B (RTL8126 5GbE)
E5B_VENDEV        equ 0x500010EC      ; pci_scan callback ECX form: vendor low16 | device high16
R26_VENDEV        equ 0x812610EC      ; plain Realtek RTL8126; same MAC-version sequence

; ==== CLEANROOM CONSTANTS (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R0 ====
; [OH] if_rgereg.h at e574c2d36cbcacf2556088879be336775e80154b.
; Offsets L23-64, bits L84-172, layout L212-286, config L399/L403.
E5B_DESC_SIZE     equ 32
R26_MAC0         equ 0x00
R26_MAC4         equ 0x04
R26_TX_BASE_LO   equ 0x20
R26_TX_BASE_HI   equ 0x24
R26_CMD_DWORD    equ 0x34            ; command byte at +3
R26_IMR         equ 0x38
R26_ISR         equ 0x3C
R26_TXCFG       equ 0x40
R26_RXCFG       equ 0x44
R26_EECMD       equ 0x50            ; low byte
R26_PHYSTAT     equ 0x6C            ; low word, read only
R26_TXSTART     equ 0x90            ; low word
R26_MACOCP      equ 0xB0
R26_RXMAX_DWORD equ 0xD8            ; RXMAXSIZE word at +2
R26_RX_BASE_LO  equ 0xE4
R26_RX_BASE_HI  equ 0xE8
R26_PPSW_DWORD  equ 0xF0            ; PPSW byte at +2
R26_RSS_CTRL    equ 0x4500          ; low byte
R26_RXQUEUE     equ 0x4800          ; low word
R26_RX_ACCEPT   equ 0x3F
R26_RX_GATE     equ 0x00080000
R26_RESET       equ 0x10000000
R26_ENABLE      equ 0x0C000000
R26_CFG_UNLOCK  equ 0xC0
R26_TX_CONFIG   equ 0x03000700
R26_RX_CONFIG   equ 0x41200D00
R26_RX_FILTER   equ 0x0A            ; individual + broadcast, no multicast
R26_RX_MAX      equ 1522            ; single buffer, VLAN frame including FCS
R26_OWN         equ 0x80000000
R26_EOR         equ 0x40000000
R26_TX_SOF_EOF  equ 0x30000000
R26_RX_SOF_EOF  equ 0x03000000
R26_RX_ERROR    equ 0x00100000
R26_RX_LENGTH   equ 0x3FFF
R26_RX_OVERFLOW equ 0x50            ; descriptor unavailable / FIFO overflow
R26_RX_ADDR     equ 16
R26_RX_EXT      equ 24
R26_RX_CMD      equ 28
R26_LINK        equ 0x0002
R26_SPEED_10    equ 0x0004
R26_SPEED_100   equ 0x0008
R26_SPEED_1000  equ 0x0010
R26_SPEED_2500  equ 0x0400
R26_SPEED_5000  equ 0x1000
R26_SPEED_10000 equ 0x4000
; ==== END CLEANROOM CONSTANTS ====

; routine result codes (kept glue <-> CLEANROOM ROUTINES)
E5B_TX_SENT       equ 0               ; e5000b_tx_frame: the chip completed the frame
E5B_TX_BUSY       equ 1               ;   slot still chip-owned: nothing copied, nothing written
E5B_TX_TIMEOUT    equ 2               ;   posted, not completed within the bound
E5B_RX_BAD        equ -1              ; e5000b_rx_desc: completed but refused (error / multi-desc / length)
E5B_RX_EMPTY      equ -2              ;   the chip still owns the slot
; ring geometry (PaOS choices)
E5B_NUM_TX        equ 32
; RX is enabled before xHCI, display and console bring-up complete, so the ring
; must hold the LAN traffic that arrives before the resident poll loop starts
; (metal first replies already showed RX > 32 with a 32-entry ring).
E5B_NUM_RX        equ 256
E5B_RX_BUF        equ 2048
E5B_TX_BUF        equ 2048
E5B_FRAME_MIN     equ 14
E5B_FRAME_MAX     equ 1518
E5B_LINK_WAIT_MS  equ 4000            ; bounded autoneg wait (ms), bring-up and recovery

; --- HAL-gated MMIO helpers (dword only; never a raw `mov [mmio]`) ---------------
; e5b_rd(RSI=BAR2 offset) -> EAX. clobbers RAX,RDI.
e5b_rd:
    lea  rdi, [rel e5000b_region]
    call hal_mmio_read32
    ret
; e5b_wr(RSI=BAR2 offset, EDX=value). clobbers RAX,R9,RDI.
e5b_wr:
    lea  rdi, [rel e5000b_region]
    call hal_mmio_write32
    ret
; e5b_or(RSI=offset, EDX=bits): dword read-modify-write OR. clobbers RAX,RDI,R9,RDX.
e5b_or:
    push rsi
    push rdx
    call e5b_rd
    pop  rdx
    pop  rsi
    or   edx, eax
    jmp  e5b_wr
; e5b_andn(RSI=offset, EDX=bits to clear). clobbers RAX,RDI,R9,RDX.
e5b_andn:
    push rsi
    push rdx
    call e5b_rd
    pop  rdx
    pop  rsi
    not  edx
    and  edx, eax
    jmp  e5b_wr

; R9 MAC-OCP port encoding from pinned ISC OpenBSD if_rge.c:3527-3547.
; ESI=even MAC register, EDX=16-bit value for write; read returns EAX low16.
; Fixed pinned R26 registers and firmware data only; no arbitrary external scripts.
e5b_mac_read:
    shl  esi, 15                     ; (register / 2) << 16
    mov  edx, esi
    mov  esi, R26_MACOCP
    call e5b_wr
    mov  esi, R26_MACOCP
    call e5b_rd
    and  eax, 0xFFFF
    ret
e5b_mac_write:
    shl  esi, 15
    and  edx, 0xFFFF
    or   edx, esi
    or   edx, 0x80000000
    mov  esi, R26_MACOCP
    jmp  e5b_wr

; R9: one installed RX ring must use the BSD one-queue configuration.
; Pinned ISC OpenBSD if_rge.c:740-777; BSD FreeBSD if_rge.c:1171-1208.
; Called with EECMD unlocked and RX/TX disabled, on initial arm and recovery.
; Keep undocumented MAC field meanings unnamed; use the cited R26 sequence.
e5000b_single_queue_setup:
    mov  esi, R26_RSS_CTRL
    mov  edx, 0xFF
    call e5b_andn                    ; RSS disabled, preserve adjacent bytes
    mov  esi, R26_RXQUEUE
    mov  edx, 0x001C
    call e5b_andn                    ; (fls(1) - 1) << 2 = 0
    ; The 32-byte TX ring requires the new descriptor format. RXCFG selects
    ; RX's format separately; neither that nor queue count selects TX stride.
    ; Pinned ISC OpenBSD if_rge.c:750; BSD FreeBSD if_rge.c:1181.
    mov  esi, 0xEB58
    call e5b_mac_read
    mov  edx, eax
    or   edx, 0x0001
    mov  esi, 0xEB58
    call e5b_mac_write
    mov  esi, R26_RXMAX_DWORD
    mov  edx, 0x00000002
    call e5b_andn                    ; BSD R26 byte d8 bit1 clear
    mov  esi, 0xE614
    call e5b_mac_read
    and  eax, 0xF8FF
    mov  edx, eax
    or   edx, 0x0300                 ; BSD MAC_R26 configuration
    mov  esi, 0xE614
    call e5b_mac_write
    mov  esi, 0xE63E
    call e5b_mac_read
    and  eax, 0xF3FF
    mov  edx, eax                    ; one queue: clear bits 11:10
    mov  esi, 0xE63E
    call e5b_mac_write
    mov  esi, 0xE63E
    call e5b_mac_read
    and  eax, 0xFFCF
    mov  edx, eax
    or   edx, 0x0020                 ; separate BSD config RMW
    mov  esi, 0xE63E
    jmp  e5b_mac_write

; e5000b_dma_range_ok(RDI=iova, RSI=bytes) -> EAX=1 only when the complete
; interval is present in the DMA allocator's live map, does not wrap, and fits
; below 4 GiB (the ring base high dwords are programmed from a 32-bit base).
e5000b_dma_range_ok:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    shr  rax, 32
    jnz  .bad
    call dma_iommu_lookup
    cmp  rax, rsi
    jb   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; e5000b_create() -> RAX = assigned slot index / -1. Builds the ops vtable at
;   runtime (lea -> mov), fills the uniform struct dev header at PRIO_NATIVE, and
;   registers with the class core. Called ONLY from e5000b_hw_bringup AFTER the real
;   10ec:5000 chip is found + armed, so it registers as a healthy SECONDARY native;
;   egress-select keeps the first-seen native (the Intel CT at slot 0) primary.
e5000b_create:
    NATIVE_DRIVER_REFUSE 6
    lea  rdi, [rel e5000b_ops]
    lea  rax, [rel e5000b_init]
    mov  [rdi + netdev_ops.init], rax
    lea  rax, [rel e5000b_start]
    mov  [rdi + netdev_ops.start], rax
    lea  rax, [rel e5000b_stop]
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel e5000b_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel e5000b_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel e5000b_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel e5000b_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel e5000b_recover]
    mov  [rdi + netdev_ops.recover], rax
    lea  rdi, [rel e5000b_dev]
    lea  rax, [rel e5000b_ops]
    mov  [rdi + dev.ops], rax
    lea  rax, [rel str_rtl8126_name]
    mov  [rel e5000b_info + netdev_info.name], rax   ; runtime address (abs_ptr_check)
    lea  rax, [rel e5000b_info]
    mov  [rdi + dev.info], rax
    mov  qword [rdi + dev.priv], 0
    ; Task3480: on this machine the Killer E5000B is the board's OWN 5GbE port
    ; and the Intel CT is an add-in 1GbE card, so the onboard adapter outranks
    ; it in netdev_egress_select. One step above PRIO_NATIVE, never a new class:
    ; every other target has no 10ec:5000 and is untouched.
    mov  dword [rdi + dev.prio], PRIO_NATIVE + 1
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_NET
    ; Unified payload: runtime identity for the MSI static address; the UDP
    ; projection grants .100 only to the Killer's exact MAC.
    mov  dword [rdi + dev.flags], NETDEV_F_ADDR_MSI
    lea  rax, [rel str_e5000b_name]
    mov  [rdi + dev.name], rax
    call netdev_register
    mov  [rel e5000b_slot], rax
    ret

e5000b_init:
    NATIVE_DRIVER_REFUSE 6
    xor  eax, eax
    ret
e5000b_start:
    xor  eax, eax
    ret
e5000b_stop:
    xor  eax, eax
    ret

; tx(self, RSI=frame, RDX=len) -> RAX 0 ok / -1 refused (NON-BLOCKING except the
;   bounded completion wait inside e5000b_tx_frame). One DMA-owned bounce buffer;
;   a slot the chip still owns is an owner mismatch, never overwritten.
; BEGIN FRAME STATS -- pure selected-device software readout.
; RDI=self; EAX=0, RDX=RX, RCX=TX, or -1. Aligned qword observations pair
; with LOCK increments; no transactional cross-counter or hardware-read claim.
rtl8126_frame_stats:
    lea  rax, [rel e5000b_dev]
    cmp  rdi, rax
    jne  .unavailable
    lea  rax, [rel e5000b_ops]
    cmp  [rdi + dev.ops], rax
    jne  .unavailable
    mov  rdx, [rel e5000b_rx_frames]
    mov  rcx, [rel e5000b_tx_frames]
    xor  eax, eax
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret
; END FRAME STATS

; RTL-DELTA-5: one nonblocking atomic admission for the single TX domain
; covers the head and OWN checks, bounce copy, publication, doorbell and
; completion wait. A second producer refuses at once; admission is released
; on every later path, while a timed-out descriptor keeps OWN and its bytes.
e5000b_tx:
    push rbx
    push r12
    push r13
    push r14
    mov  al, 1
    xchg al, [rel e5000b_tx_busy]         ; XCHG with memory is implicitly locked
    test al, al
    jnz  .busy
    cmp  byte [rel e5000b_rings_ok], 1
    jne  .degrade
    mov  r13, [rel e5000b_tx_buffer]
    test r13, r13
    jz   .degrade
    mov  r14, rdx
    cmp  r14, E5B_FRAME_MIN
    jb   .degrade
    cmp  r14, E5B_FRAME_MAX
    ja   .degrade
    mov  ebx, [rel e5000b_tx_head]
    cmp  ebx, E5B_NUM_TX
    jae  .owner_bad
    cmp  qword [rel e5000b_tx_ring], 0
    je   .degrade
    call e5000b_tx_frame                          ; EBX slot, RSI frame, R13 bounce, R14 len
    cmp  eax, E5B_TX_SENT
    je   .sent
    cmp  eax, E5B_TX_BUSY
    je   .owner_bad                               ; chip still owns this slot
    lock inc qword [rel e5000b_tx_timeouts]
    lock inc qword [rel e5000b_tx_drops]
    mov  rax, -1
    jmp  .release
.sent:
    lea  eax, [rbx + 1]
    cmp  eax, E5B_NUM_TX
    jb   .no_wrap
    xor  eax, eax
    lock inc qword [rel e5000b_tx_wraps]
.no_wrap:
    mov  [rel e5000b_tx_head], eax
    lock inc qword [rel e5000b_tx_frames]
    xor  eax, eax
    jmp  .release
.owner_bad:
    lock inc qword [rel e5000b_owner_mismatches]
.degrade:
    lock inc qword [rel e5000b_tx_drops]
    mov  rax, -1
.release:
    mov  byte [rel e5000b_tx_busy], 0     ; software admission only, never OWN
    jmp  .tx_out
.busy:
    lock inc qword [rel e5000b_tx_drops]  ; another producer holds the domain
    mov  rax, -1
.tx_out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; rx_poll(self, RSI=buf, RDX=cap) -> RAX = len (0 none / -1 err). Asks
;   e5000b_rx_desc about the slot at the SW cursor; a completed frame that fits
;   the caller's buffer is copied, then the slot is handed back with
;   e5000b_rx_repost and the cursor advances. Bounded, never blocks.
; e5000b_rx_ack_status — after the slot is handed back, acknowledge latched
;   receive status (e5000b_isr_ack) and count overflow observations. Poll mode:
;   nothing else consumes the status.
e5000b_rx_ack_status:
    cmp  byte [rel e5000b_hw_ok], 1
    jne  .out
    cmp  byte [rel e5000b_rings_ok], 1
    jne  .out
    call e5000b_isr_ack
    test eax, eax
    jz   .out
    lock inc qword [rel e5000b_rx_du_acks]
.out:
    ret

e5000b_rx_poll:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel e5000b_rings_ok], 1
    jne  .rx_none
    cmp  qword [rel e5000b_rx_ring], 0
    je   .rx_none
    mov  ebx, [rel e5000b_rx_cursor]
    cmp  ebx, E5B_NUM_RX
    jae  .rx_owner_bad
    mov  r12, rsi                                 ; caller buffer
    mov  r13, rdx                                 ; caller capacity
    call e5000b_rx_desc                           ; EBX slot -> RAX len / E5B_RX_BAD / E5B_RX_EMPTY
    cmp  rax, E5B_RX_EMPTY
    je   .rx_none                                 ; chip still owns it: empty
    cmp  rax, E5B_RX_BAD
    je   .rx_malformed
    mov  r14, rax                                 ; frame length, CRC excluded
    cmp  r14, E5B_FRAME_MIN
    jb   .rx_malformed
    cmp  r14, E5B_FRAME_MAX
    ja   .rx_malformed
    cmp  r14, r13
    ja   .rx_malformed                            ; never expose a truncated frame
    mov  rax, [rel e5000b_rx_buffers]
    test rax, rax
    jz   .rx_malformed
    imul r15, rbx, E5B_RX_BUF
    add  r15, rax
    mov  rcx, r14
    mov  rdi, r12
    mov  rsi, r15
    cld
    rep  movsb
    jmp  .rx_repost
.rx_malformed:
    lock inc qword [rel e5000b_rx_drops]
    xor  r14d, r14d
.rx_repost:
    call e5000b_rx_repost                         ; EBX slot: back to the chip
    lea  eax, [rbx + 1]
    cmp  eax, E5B_NUM_RX
    jb   .rx_adv
    xor  eax, eax
    lock inc qword [rel e5000b_rx_wraps]
.rx_adv:
    mov  [rel e5000b_rx_cursor], eax
    test r14, r14
    jz   .rx_none
    lock inc qword [rel e5000b_rx_frames]
    mov  rax, r14
    jmp  .rx_out
.rx_owner_bad:
    lock inc qword [rel e5000b_owner_mismatches]
    mov  dword [rel e5000b_rx_cursor], 0
    mov  rax, -1
    jmp  .rx_out
.rx_none:
    xor  eax, eax
.rx_out:
    ; Acknowledge status after .rx_repost made a slot available. The empty and
    ; owner-bad paths also clear a stale latch.
    push rax
    call e5000b_rx_ack_status
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; e5000b_link_refresh: live PHY status read -> e5000b_link_up / e5000b_link_speed.
; e5000b_wait_link: up to E5B_LINK_WAIT_MS 1 ms polls until PHY status reports link
;   (returns at once when it does). Bounded: a port with no cable costs the budget
;   once and stays DEGRADED, as before. Preserves RBX.
e5000b_wait_link:
    push rbx
    mov  ebx, E5B_LINK_WAIT_MS
.poll:
    call e5000b_link_refresh
    cmp  byte [rel e5000b_link_up], 1
    je   .out
    mov  edi, 1000                                ; 1 ms
    call tsc_delay_us
    dec  ebx
    jnz  .poll
.out:
    pop  rbx
    ret

e5000b_link_refresh:
    mov  byte [rel e5000b_link_up], 0
    mov  dword [rel e5000b_link_speed], 0
    cmp  byte [rel e5000b_hw_ok], 1
    jne  .out
    call e5000b_phy_status                        ; EAX up, ECX Mb/s
    test eax, eax
    jz   .out
    mov  byte [rel e5000b_link_up], 1
    mov  [rel e5000b_link_speed], ecx
.out:
    ret

; link_status(self) -> RAX bit0=up | speed<<8, from a live PHY status read.
e5000b_link_status:
    call e5000b_link_refresh
    xor  eax, eax
    cmp  byte [rel e5000b_link_up], 1
    jne  .down
    mov  eax, [rel e5000b_link_speed]
    shl  eax, 8
    or   eax, 1
.down:
    ret

; get_mac(self, RSI=out6) -> RAX 0. The live station address read at bring-up.
e5000b_get_mac:
    lea  r9, [rel e5000b_mac]
    xor  ecx, ecx
.copy:
    mov  al, [r9 + rcx]
    mov  [rsi + rcx], al
    inc  ecx
    cmp  ecx, 6
    jb   .copy
    xor  eax, eax
    ret

; e5000b_discover_cb(EDI=bus,ESI=dev,EDX=fn,ECX=vendev) — pci_scan_with_filter
;   callback: record the first supported RTL8126 BDF and its actual device ID.
;   Count both PCI IDs together; a second chip is ambiguous, never guessed.
e5000b_discover_cb:
    cmp  ecx, E5B_VENDEV
    je   .match
    cmp  ecx, R26_VENDEV
    jne  .ret
.match:
    inc  dword [rel e5000b_matches]
    cmp  qword [rel e5000b_bdf], -1
    jne  .ret
    mov  r8d, edi
    shl  r8d, 16
    mov  r9d, esi
    shl  r9d, 8
    or   r8d, r9d
    or   r8d, edx
    mov  [rel e5000b_bdf], r8
    mov  eax, ecx
    shr  eax, 16
    mov  [rel e5000b_devid], eax
.ret:
    ret

; ==== CLEANROOM ROUTINE e5000b_soft_reset (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R1 ====
; e5000b_soft_reset -> EAX 0 reset completed / -1 bounded timeout.
e5000b_soft_reset:
    push rbx
    mov  esi, R26_RXCFG
    mov  edx, R26_RX_ACCEPT
    call e5b_andn
    mov  esi, R26_PPSW_DWORD
    mov  edx, R26_RX_GATE
    call e5b_or
    mov  esi, R26_IMR
    xor  edx, edx
    call e5b_wr
    call e5000b_isr_ack
    ; Replace only CMD byte 37; preserve the three neighboring byte lanes.
    mov  esi, R26_CMD_DWORD
    call e5b_rd
    and  eax, 0x00FFFFFF
    mov  edx, eax
    or   edx, R26_RESET
    call e5b_wr
    mov  ebx, 100
.poll:
    mov  edi, 100
    call tsc_delay_us
    mov  esi, R26_CMD_DWORD
    call e5b_rd
    test eax, R26_RESET
    jz   .done
    dec  ebx
    jnz  .poll
    mov  rax, -1
    pop  rbx
    ret
.done:
    xor  eax, eax
    pop  rbx
    ret

; Retained R11 checked helpers below serve historical controls. R16 full reset
; uses the observed, best-effort table engine in rtl8126_attach_impl.inc.
; Only command-reset failure is fatal inside that sequence. Identity, MAC,
; DMA interval and ownership checks in the surrounding glue still apply.

; ESI=MAC register, EDX=expected low16. Preserve the register/value across HAL.
e5b_mac_write_checked:
    push rbx
    push r12
    push r13
    mov  ebx, esi
    movzx r12d, dx
    call e5b_mac_write
    mov  r13d, 100
.poll:
    mov  esi, ebx
    call e5b_mac_read
    cmp  eax, r12d
    je   .ok
    mov  edi, 10
    call tsc_delay_us
    dec  r13d
    jnz  .poll
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ESI=MAC register, EDX=bits to clear. Neighboring bits must read back intact.
e5b_mac_clear_checked:
    push rbx
    push r12
    mov  ebx, esi
    mov  r12d, edx
    call e5b_mac_read
    not  r12d
    and  eax, r12d
    mov  edx, eax
    mov  esi, ebx
    call e5b_mac_write_checked
    pop  r12
    pop  rbx
    ret

; ESI=aligned MMIO register, EDX=bits to clear. Bound posted readback to 1ms.
e5b_clear_checked:
    push rbx
    push r12
    push r13
    mov  ebx, esi
    mov  r12d, edx
    call e5b_andn
    mov  r13d, 100
.poll:
    mov  esi, ebx
    call e5b_rd
    test eax, r12d
    jz   .ok
    mov  edi, 10
    call tsc_delay_us
    dec  r13d
    jnz  .poll
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ESI=even PHY-OCP register, EDX=data for write. Bit31 has opposite completion
; polarity for read/write (OB:3636-3668); never treat an uncompleted read as data.
e5b_phy_read:
    push rbx
    shl  esi, 15
    mov  edx, esi
    mov  esi, 0xB8
    call e5b_wr
    mov  ebx, 20000
.poll:
    mov  edi, 1
    call tsc_delay_us
    mov  esi, 0xB8
    call e5b_rd
    test eax, 0x80000000
    jnz  .ok
    dec  ebx
    jnz  .poll
    mov  rax, -1
    jmp  .out
.ok:
    and  eax, 0xFFFF
.out:
    pop  rbx
    ret

e5b_phy_write:
    push rbx
    shl  esi, 15
    and  edx, 0xFFFF
    or   edx, esi
    or   edx, 0x80000000
    mov  esi, 0xB8
    call e5b_wr
    mov  ebx, 20000
.poll:
    mov  edi, 1
    call tsc_delay_us
    mov  esi, 0xB8
    call e5b_rd
    test eax, 0x80000000
    jz   .ok
    dec  ebx
    jnz  .poll
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

e5b_phy_clear_checked:
    push rbx
    push r12
    mov  ebx, esi
    mov  r12d, edx
    call e5b_phy_read
    test eax, eax
    js   .bad
    not  r12d
    and  r12d, eax
    mov  edx, r12d
    mov  esi, ebx
    call e5b_phy_write
    test eax, eax
    jnz  .bad
    mov  esi, ebx
    call e5b_phy_read
    cmp  eax, r12d
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; The OOB handshake must be observed on both sides of the fixed MAC sequence.
e5b_twi_ready:
    push rbx
    mov  ebx, 10
.poll:
    mov  edi, 100
    call tsc_delay_us
    mov  esi, 0xD0                   ; TWICMD word d2, bit9 -> dword bit25
    call e5b_rd
    test eax, 0x02000000
    jnz  .ok
    dec  ebx
    jnz  .poll
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Standard MII BMCR at PHY-OCP A400. Bit11 power-down survives some warm
; handoffs; MAC reset/UPS exit alone does not clear it. Preserve other control
; bits, enable/restart autoneg, and verify power-up/enable with bounded PHY IO.
; ANRESTART (bit9) self-clears: its absence on readback is not an error.
; Cached observation validity: bit7 attempted, bits0/1/2 before/after/state,
; bit6 wake readbacks passed. No link/Ready claim. Reset at each full-reset entry.
e5000b_phy_wake:
    push rbx
    or   byte [rel e5000b_bmcr_valid], 0x80
    mov  esi, 0xA400
    call e5b_phy_read
    test eax, eax
    js   .bad
    cmp  eax, 0xFFFF
    je   .bad
    mov  [rel e5000b_bmcr_before], ax
    or   byte [rel e5000b_bmcr_valid], 1
    mov  ebx, eax
    test ebx, 0x0800
    jz   .restart
    and  ebx, ~0x0800
    mov  esi, 0xA400
    mov  edx, ebx
    call e5b_phy_write
    test eax, eax
    jnz  .bad
    call .read_after
    test eax, eax
    js   .bad
    test eax, 0x0800
    jnz  .bad
    mov  ebx, eax
.restart:
    and  ebx, ~0x0800
    or   ebx, 0x1200                ; ANENABLE | ANRESTART
    mov  esi, 0xA400
    mov  edx, ebx
    call e5b_phy_write
    test eax, eax
    jnz  .bad
    call .read_after
    test eax, eax
    js   .bad
    and  eax, 0x1800                ; PDOWN must clear, ANENABLE must remain
    cmp  eax, 0x1000
    jne  .bad
    mov  esi, 0xA420
    call e5b_phy_read
    test eax, eax
    js   .bad
    cmp  eax, 0xFFFF
    je   .bad
    mov  [rel e5000b_phy_state], ax
    or   byte [rel e5000b_bmcr_valid], 0x44
    xor  eax, eax
    pop  rbx
    ret
.read_after:
    mov  esi, 0xA400
    call e5b_phy_read
    test eax, eax
    js   .read_out
    cmp  eax, 0xFFFF
    je   .read_bad
    mov  [rel e5000b_bmcr_after], ax
    or   byte [rel e5000b_bmcr_valid], 2
.read_out:
    ret
.read_bad:
    mov  rax, -1
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

rtl8126_attach_snapshot:
    jmp r26_attach_snapshot_impl

%include "dev/net/rtl8126_attach_impl.inc"

; ==== CLEANROOM ROUTINE e5000b_read_mac (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R2 ====
; e5000b_read_mac -> EAX = station address bytes 0..3, EDX low 16 = bytes 4..5.
e5000b_read_mac:
    mov  esi, R26_MAC0
    call e5b_rd
    push rax
    mov  esi, R26_MAC4
    call e5b_rd
    movzx edx, ax
    pop  rax
    ret

; ==== CLEANROOM ROUTINE e5000b_arm_rings (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R3 ====
; e5000b_arm_rings -> EAX 0 armed (TX and RX live) / -1 refused.
e5000b_arm_rings:
    push rbx
    mov  esi, R26_IMR
    xor  edx, edx
    call e5b_wr
    call e5000b_isr_ack
    mov  rdi, [rel e5000b_tx_ring]
    mov  ecx, E5B_NUM_TX * E5B_DESC_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  r8, [rel e5000b_tx_ring]
    mov  dword [r8 + (E5B_NUM_TX - 1) * E5B_DESC_SIZE], R26_EOR
    mov  dword [rel e5000b_tx_head], 0
    xor  ebx, ebx
.rx_slot:
    call e5000b_rx_repost
    inc  ebx
    cmp  ebx, E5B_NUM_RX
    jb   .rx_slot
    mov  dword [rel e5000b_rx_cursor], 0
    mov  esi, R26_EECMD
    mov  edx, R26_CFG_UNLOCK
    call e5b_or
    mov  esi, R26_RX_BASE_LO
    mov  edx, [rel e5000b_rx_ring]
    call e5b_wr
    mov  esi, R26_RX_BASE_HI
    xor  edx, edx
    call e5b_wr
    mov  esi, R26_TX_BASE_LO
    mov  edx, [rel e5000b_tx_ring]
    call e5b_wr
    mov  esi, R26_TX_BASE_HI
    xor  edx, edx
    call e5b_wr
    mov  esi, R26_RXCFG
    mov  edx, R26_RX_CONFIG | R26_RX_FILTER
    call e5b_wr
    mov  esi, R26_TXCFG
    mov  edx, R26_TX_CONFIG
    call e5b_wr
    call r26_mac_config
    mov  esi, R26_RXMAX_DWORD
    call e5b_rd
    and  eax, 0x0000FFFF
    mov  edx, eax
    or   edx, R26_RX_MAX << 16
    call e5b_wr
    mov  esi, R26_PPSW_DWORD
    mov  edx, R26_RX_GATE
    call e5b_andn
    mov  edi, 2000
    call tsc_delay_us
    mov  esi, R26_EECMD
    mov  edx, R26_CFG_UNLOCK
    call e5b_andn
    mov  edi, 10
    call tsc_delay_us
    call r26_media_config
    ; Enable only after the rings, filters, RX bound and gate are ready.
    mov  esi, R26_CMD_DWORD
    call e5b_rd
    and  eax, 0x00FFFFFF
    mov  edx, eax
    or   edx, R26_ENABLE
    call e5b_wr
    call r26_dump_registers
    xor  eax, eax
    pop  rbx
    ret

; ==== CLEANROOM ROUTINE e5000b_tx_frame (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R4 ====
; e5000b_tx_frame(EBX=slot, RSI=frame, R13=bounce buffer, R14=len) -> EAX E5B_TX_*.
e5000b_tx_frame:
    push r12
    push r15
    imul r12, rbx, E5B_DESC_SIZE
    add  r12, [rel e5000b_tx_ring]
    mov  eax, [r12]
    test eax, R26_OWN
    jnz  .busy
    mov  rdi, r13
    mov  rcx, r14
    cld
    rep  movsb
    mov  dword [r12 + 4], 0
    mov  [r12 + 8], r13
    mov  qword [r12 + 16], 0
    mov  qword [r12 + 24], 0
    mov  eax, r14d
    or   eax, R26_TX_SOF_EOF | R26_OWN
    cmp  ebx, E5B_NUM_TX - 1
    jne  .post
    or   eax, R26_EOR
.post:
    sfence
    mov  [r12], eax
    sfence
    mov  esi, R26_TXSTART
    call e5b_rd
    and  eax, 0xFFFF0000
    mov  edx, eax
    or   edx, 1
    call e5b_wr
    mov  r15d, 200
.completion:
    mov  edi, 100
    call tsc_delay_us
    mov  eax, [r12]
    test eax, R26_OWN
    jz   .sent
    dec  r15d
    jnz  .completion
    mov  eax, E5B_TX_TIMEOUT
    jmp  .out
.busy:
    mov  eax, E5B_TX_BUSY
    jmp  .out
.sent:
    mov  eax, E5B_TX_SENT
.out:
    pop  r15
    pop  r12
    ret

; ==== CLEANROOM ROUTINE e5000b_rx_desc (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R5 ====
; e5000b_rx_desc(EBX=slot) -> RAX frame length (CRC excluded) / E5B_RX_BAD / E5B_RX_EMPTY.
e5000b_rx_desc:
    imul r8, rbx, E5B_DESC_SIZE
    add  r8, [rel e5000b_rx_ring]
    mov  eax, [r8 + R26_RX_CMD]           ; one observation of chip-owned status
    test eax, R26_OWN
    jnz  .empty
    test eax, R26_RX_ERROR
    jnz  .bad
    mov  edx, eax
    and  edx, R26_RX_SOF_EOF
    cmp  edx, R26_RX_SOF_EOF
    jne  .bad
    and  eax, R26_RX_LENGTH
    cmp  eax, 4
    jbe  .bad
    sub  eax, 4
    ret
.bad:
    mov  rax, E5B_RX_BAD
    ret
.empty:
    mov  rax, E5B_RX_EMPTY
    ret

; ==== CLEANROOM ROUTINE e5000b_rx_repost (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R6 ====
; e5000b_rx_repost(EBX=slot): hand the slot's 2 KiB buffer back to the chip.
e5000b_rx_repost:
    imul r8, rbx, E5B_DESC_SIZE
    add  r8, [rel e5000b_rx_ring]
    imul rax, rbx, E5B_RX_BUF
    add  rax, [rel e5000b_rx_buffers]
    mov  qword [r8], 0
    mov  qword [r8 + 8], 0
    mov  [r8 + R26_RX_ADDR], rax
    mov  dword [r8 + R26_RX_EXT], 0
    mov  eax, E5B_RX_BUF | R26_OWN
    cmp  ebx, E5B_NUM_RX - 1
    jne  .post
    or   eax, R26_EOR
.post:
    sfence
    mov  [r8 + R26_RX_CMD], eax
    sfence
    ret

; ==== CLEANROOM ROUTINE e5000b_isr_ack (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R7 ====
; e5000b_isr_ack -> EAX 1 when a receive-overflow class status was acknowledged, else 0.
e5000b_isr_ack:
    mov  esi, R26_ISR
    call e5b_rd
    mov  r8d, eax
    test eax, eax
    jz   .result
    mov  edx, eax
    call e5b_wr                         ; W1C: exactly the single observation
.result:
    xor  eax, eax
    test r8d, R26_RX_OVERFLOW
    setnz al
    ret

; ==== CLEANROOM ROUTINE e5000b_phy_status (RCQ-31 clean-room rewrite): contract in CLEANROOM_RTL8126_SPEC.md section R8 ====
; e5000b_phy_status -> EAX 1 link up / 0, ECX = speed in Mb/s (0 when down or unknown).
e5000b_phy_status:
    mov  esi, R26_PHYSTAT
    call e5b_rd
    xor  ecx, ecx
    test eax, R26_LINK
    jz   .down
    mov  ecx, 10
    test eax, R26_SPEED_10
    jnz  .up
    mov  ecx, 100
    test eax, R26_SPEED_100
    jnz  .up
    mov  ecx, 1000
    test eax, R26_SPEED_1000
    jnz  .up
    mov  ecx, 2500
    test eax, R26_SPEED_2500
    jnz  .up
    mov  ecx, 5000
    test eax, R26_SPEED_5000
    jnz  .up
    mov  ecx, 10000
    test eax, R26_SPEED_10000
    jnz  .up
    xor  ecx, ecx
.up:
    mov  eax, 1
    ret
.down:
    xor  eax, eax
    ret

; ==== CLEANROOM DATA (RCQ-31): implementer state, if any, goes here ====

; recover(self) -> RAX 0 recovered / -1 dead. The RTL8126 SOFTWARE DEVICE reset
;   rung (Task3477 sustained_recovery): soft reset (bounded), exact identity,
;   re-arm both rings and the chip, then a LIVE link read. The proof of recovery is a
;   post-reset challenged reply observed by the GPU, never this return value alone.
e5000b_recover:
    NATIVE_DRIVER_REFUSE 6
    push rbx
    cmp  byte [rel e5000b_recover_busy], 0
    jne  .busy
    mov  byte [rel e5000b_recover_busy], 1
    lock inc qword [rel e5000b_recover_attempts]
    cmp  byte [rel e5000b_hw_ok], 1
    jne  .dead
    cmp  byte [rel e5000b_mac_ok], 1
    jne  .dead
    call e5000b_full_reset
    test eax, eax
    jz   .reset_done
    lock inc qword [rel e5000b_recover_timeouts]
    jmp  .dead
.reset_done:
    ; the exact identity must survive the reset (a different device can never
    ; earn the recovery)
    call e5000b_read_mac
    cmp  eax, [rel e5000b_mac]
    jne  .dead
    cmp  dx, [rel e5000b_mac + 4]
    jne  .dead
    call e5000b_arm_rings
    test eax, eax
    jnz  .arm_fail
    mov  byte [rel e5000b_rings_ok], 1
    ; Bounded wait for the PHY to finish re-negotiating (multi-gig autoneg takes
    ; seconds) so this reset's OWN reply can still egress. The proof of recovery
    ; is the post-reset challenged reply the GPU observes, never this bit alone:
    ; a still-dark link after the wait is recorded, not fatal.
    mov  ebx, E5B_LINK_WAIT_MS
.link_wait:
    call e5000b_link_refresh
    cmp  byte [rel e5000b_link_up], 1
    je   .link_back
    mov  edi, 1000                                ; 1 ms
    call tsc_delay_us
    dec  ebx
    jnz  .link_wait
.link_back:
    lock inc qword [rel e5000b_recover_successes]
    mov  byte [rel e5000b_recover_busy], 0
    xor  eax, eax
    pop  rbx
    ret
.arm_fail:
.dead:
    ; A failed reset or identity check invalidates the old software rings too.
    ; Keep them closed until a later successful arm; never deliver stale RX or
    ; publish TX after this recovery has failed. Busy rejection skips this path.
    mov  byte [rel e5000b_rings_ok], 0
    lock inc qword [rel e5000b_recover_failures]
    mov  byte [rel e5000b_recover_busy], 0
.busy:
    mov  rax, -1
    pop  rbx
    ret

; Final reporting is independent of the chip/native-acceptance marker.
; Exactly one match receives one final record, including early "absent" exits.
; Preserves every general-purpose register; the PCI reporting ABI does too.
r26_record_claim:
    push rdi
    push rcx
    push r8
    cmp  dword [rel e5000b_matches], 1
    jne  .out
    mov  edi, [rel e5000b_bdf]
    mov  ecx, PCI_DRV_RTL8126
    mov  r8d, PCI_CLAIM_FAILED
    cmp  byte [rel e5000b_registered], 1
    jne  .record
    mov  r8d, PCI_CLAIM_BOUND
.record:
    call pci_claim_packed16
.out:
    pop  r8
    pop  rcx
    pop  rdi
    ret

; ============================================================================
; e5000b_hw_bringup — the REAL RTL8126 init on the MSI signed trial. Emits the ONE
;   registered hw-only marker [msi.network.killer_e5000b.native] ONLY when every
;   earned condition holds (exactly one chip found + reset done + valid live MAC + rings
;   armed + registered + Intel-CT isolation preserved + live link). Bounded
;   everywhere; an absent RTL8126 degrades cleanly (no marker, no register, no hang).
; ============================================================================
e5000b_hw_bringup:
    NATIVE_DRIVER_REFUSE 6
    push rbx
    push r12
    push r13
    mov  byte [rel e5000b_registered], 0
    mov  byte [rel e5000b_hw_ok], 0
    mov  byte [rel e5000b_link_up], 0
    mov  byte [rel e5000b_rings_ok], 0
    mov  byte [rel e5000b_mac_ok], 0
    mov  byte [rel e5000b_iso_ok], 0
    ; Observations never begin with the compiled expected identity, including
    ; a repeated bring-up that fails before reaching the live MAC read.
    mov  dword [rel e5000b_mac], 0
    mov  word [rel e5000b_mac + 4], 0
    mov  dword [rel e5000b_matches], 0
    mov  dword [rel e5000b_devid], 0
    ; --- 1. locate either RTL8126 PCI ID across ALL bus/dev/fn ---
    mov  qword [rel e5000b_bdf], -1
    lea  rdi, [rel e5000b_discover_cb]
    call pci_scan_with_filter
    cmp  qword [rel e5000b_bdf], -1
    je   .absent
    cmp  dword [rel e5000b_matches], 1
    jne  .absent                                  ; ambiguous: refuse, never guess
    mov  rax, [rel e5000b_bdf]
    mov  r12, rax
    shr  r12, 16
    and  r12d, 0xFF                               ; bus
    mov  r13, rax
    shr  r13, 8
    and  r13d, 0xFF                               ; dev
    and  eax, 0xFF                                ; fn
    mov  [rel e5000b_pci_bus], r12d
    mov  [rel e5000b_pci_dev], r13d
    mov  [rel e5000b_pci_fn], eax
    ; --- 2. PCI Command |= Memory Space + Bus Master (this exact function only) ---
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rel e5000b_pci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    and  eax, 0xFFFF                              ; Status half is W1C, not Command
    or   eax, 0x06
    mov  r8d, eax
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rel e5000b_pci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
    ; --- 3. BAR2 (0x18) = RTL MMIO; honour a 64-bit BAR, require base < 4 GiB ---
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rel e5000b_pci_fn]
    mov  ecx, 0x18
    call pci_cfg_read32
    mov  ebx, eax
    test al, 0x01
    jnz  .absent                                  ; I/O BAR: not the MMIO window
    test al, 0x04
    jz   .bar32
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rel e5000b_pci_fn]
    mov  ecx, 0x1C
    call pci_cfg_read32
    mov  ecx, eax
    and  ebx, 0xFFFFFFF0
    mov  eax, ebx
    shl  rcx, 32
    or   rax, rcx
    jmp  .bar_have
.bar32:
    and  ebx, 0xFFFFFFF0
    mov  eax, ebx
.bar_have:
    test rax, rax
    jz   .absent
    mov  rcx, rax
    shr  rcx, 32
    jnz  .absent
    mov  [rel e5000b_bar], rax
    mov  [rel e5000b_region + HAL_R_BAR_BASE], rax
    mov  qword [rel e5000b_region + HAL_R_BAR_SIZE], 0x10000
    ; --- 4. full chip/OOB/power handoff reset (bounded and read back) ---
    call e5000b_full_reset
    test eax, eax
    jz   .reset_ok
    lock inc qword [rel e5000b_recover_timeouts]
    ; R1 failure containment: this function cannot retain bus-master authority.
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rel e5000b_pci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    and  eax, 0xFFFB                              ; low Command only, BME clear
    mov  r8d, eax
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rel e5000b_pci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
    jmp  .diag_norings
.reset_ok:
    ; --- 5. capture this device's live unicast MAC; never a lab identity ---
    call e5000b_read_mac
    mov  [rel e5000b_mac + 0], eax
    mov  [rel e5000b_mac + 4], dx
    mov  eax, [rel e5000b_mac]
    test al, 1                                    ; multicast and broadcast are invalid
    jnz  .mac_checked
    movzx edx, word [rel e5000b_mac + 4]
    or   eax, edx                                 ; reject all six bytes zero
    jz   .mac_checked
    mov  byte [rel e5000b_mac_ok], 1
.mac_checked:
    ; --- 6. rings + buffers: DMA-backed, range-checked (own pool, never the CT's) ---
    mov  edi, E5B_NUM_TX * E5B_DESC_SIZE
    call dma_alloc
    test rax, rax
    jz   .diag_norings
    mov  [rel e5000b_tx_ring], rax
    mov  rdi, rax
    mov  esi, E5B_NUM_TX * E5B_DESC_SIZE
    call e5000b_dma_range_ok
    test eax, eax
    jz   .diag_norings
    mov  edi, E5B_NUM_RX * E5B_DESC_SIZE
    call dma_alloc
    test rax, rax
    jz   .diag_norings
    mov  [rel e5000b_rx_ring], rax
    mov  rdi, rax
    mov  esi, E5B_NUM_RX * E5B_DESC_SIZE
    call e5000b_dma_range_ok
    test eax, eax
    jz   .diag_norings
    mov  edi, E5B_TX_BUF
    call dma_alloc
    test rax, rax
    jz   .diag_norings
    mov  [rel e5000b_tx_buffer], rax
    mov  rdi, rax
    mov  esi, E5B_TX_BUF
    call e5000b_dma_range_ok
    test eax, eax
    jz   .diag_norings
    mov  edi, E5B_NUM_RX * E5B_RX_BUF
    call dma_alloc
    test rax, rax
    jz   .diag_norings
    mov  [rel e5000b_rx_buffers], rax
    mov  rdi, rax
    mov  esi, E5B_NUM_RX * E5B_RX_BUF
    call e5000b_dma_range_ok
    test eax, eax
    jz   .diag_norings
    ; --- 7. arm rings + chip, TX and RX live ---
    call e5000b_arm_rings
    test eax, eax
    jnz  .diag_norings
    mov  byte [rel e5000b_rings_ok], 1
    mov  byte [rel e5000b_hw_ok], 1
    ; --- 8. register as the SECONDARY native member ---
    call e5000b_create
    test rax, rax
    js   .no_marker
    mov  byte [rel e5000b_registered], 1
    ; --- 9. isolation diagnostic: does the Intel CT still own slot 0, HEALTH_OK?
    ;     paos_msi Task3477 gated acceptance on this while the CT was primary. In
    ;     the unified payload the Killer must not depend on an unrelated add-in
    ;     card being present, so it is recorded (e5000b_iso_ok), never gating.
    lea  r12, [rel netdev_table]
    mov  rax, [r12]
    lea  rdi, [rel e1000e_dev]
    cmp  rax, rdi
    jne  .iso_done
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .iso_done
    mov  byte [rel e5000b_iso_ok], 1
.iso_done:
    ; --- 10. live link read. RCQ-14: a bounded autoneg wait for the exact Killer.
    ;     A 5GbE link still negotiating at ONE read left the port DEGRADED for the
    ;     whole boot: command_udp_init (right after this bring-up) never bound it
    ;     and nothing re-probes a DEGRADED member, so the MSI never answered
    ;     natively (r4.2: exact BootReady, 0 replies). Same budget and 1 ms poll
    ;     as e5000b_recover's post-reset wait. ---
    cmp  byte [rel e5000b_mac_ok], 1
    jne  .link_once                               ; not our exact port: one read, no wait
    call e5000b_wait_link
    jmp  .link_read
.link_once:
    call e5000b_link_refresh
.link_read:
    ; --- 11. EARN the marker iff valid live MAC + rings + live link ---
    cmp  byte [rel e5000b_mac_ok], 1
    jne  .no_marker
    cmp  byte [rel e5000b_link_up], 1
    jne  .link_late
    mov  dword [rel e5000b_dev + dev.health], HEALTH_OK
    lea  rdi, [rel str_e5000b_native]
    call serial_string
    jmp  .diag
.link_late:
    ; RCQ-10: the exact Killer, rings armed, link still down after the wait: DEGRADED
    ; for link only, so netdev_link_reprobe promotes it when the link comes up.
    or   dword [rel e5000b_dev + dev.flags], NETDEV_F_LINK_WAIT
.no_marker:
    mov  dword [rel e5000b_dev + dev.health], HEALTH_DEGRADED
    jmp  .diag
.diag_norings:
    mov  byte [rel e5000b_rings_ok], 0
    jmp  .diag
.absent:
    lea  rdi, [rel str_e5000b_absent]
    call serial_string
    jmp  .done
.diag:
    lea  rdi, [rel str_e5000b_diag]
    call serial_string
    mov  edi, [rel e5000b_pci_bus]
    call serial_hex64
    lea  rdi, [rel str_e5000b_diag_df]
    call serial_string
    mov  edi, [rel e5000b_pci_dev]
    call serial_hex64
    mov  edi, [rel e5000b_pci_fn]
    call serial_hex64
    lea  rdi, [rel str_e5000b_diag_bar]
    call serial_string
    mov  rdi, [rel e5000b_region + HAL_R_BAR_BASE]
    call serial_hex64
    lea  rdi, [rel str_e5000b_diag_mac]
    call serial_string
    mov  edi, [rel e5000b_mac]
    call serial_hex64
    lea  rdi, [rel str_e5000b_diag_st]
    call serial_string
    movzx edi, byte [rel e5000b_mac_ok]
    call serial_hex64
    movzx edi, byte [rel e5000b_rings_ok]
    call serial_hex64
    movzx edi, byte [rel e5000b_iso_ok]
    call serial_hex64
    movzx edi, byte [rel e5000b_link_up]
    call serial_hex64
    mov  edi, [rel e5000b_link_speed]
    call serial_hex64
    call serial_newline
.done:
    call r26_record_claim
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- e5000b data (in-image writable) --------------------------------------------
e5000b_dev:        times dev_size db 0
e5000b_ops:        times netdev_ops_size db 0
e5000b_region:     times 16 db 0                  ; HAL region: .bar_base (dq) + .bar_size (dq)
e5000b_slot:       dq 0
e5000b_bmcr_valid: db 0
e5000b_reset_phase: db 0
e5000b_drain_expired: db 0
e5000b_bmcr_before: dw 0
e5000b_bmcr_after: dw 0
e5000b_phy_state: dw 0
align 8
e5000b_bdf:        dq -1
e5000b_bar:        dq 0
e5000b_tx_ring:    dq 0
e5000b_rx_ring:    dq 0
e5000b_tx_buffer:  dq 0
e5000b_rx_buffers: dq 0
e5000b_tx_frames:  dq 0
e5000b_rx_frames:  dq 0
e5000b_tx_drops:   dq 0
e5000b_rx_drops:   dq 0
e5000b_tx_timeouts: dq 0
e5000b_tx_wraps:   dq 0
e5000b_rx_wraps:   dq 0
e5000b_owner_mismatches: dq 0
e5000b_recover_attempts: dq 0
e5000b_recover_successes: dq 0
e5000b_recover_failures: dq 0
e5000b_recover_timeouts: dq 0
e5000b_rx_du_acks: dq 0                           ; latched RDU/FIFO status acknowledged
e5000b_devid:      dd 0                ; actual first matched device ID, zero before discovery
e5000b_matches:    dd 0
e5000b_pci_bus:    dd 0
e5000b_pci_dev:    dd 0
e5000b_pci_fn:     dd 0
e5000b_tx_head:    dd 0
e5000b_rx_cursor:  dd 0
e5000b_link_speed: dd 0
e5000b_registered: db 0             ; current bring-up registration outcome only
e5000b_hw_ok:      db 0
e5000b_link_up:    db 0
e5000b_rings_ok:   db 0
e5000b_mac_ok:     db 0
e5000b_iso_ok:     db 0
e5000b_recover_busy: db 0
; Observed station address, unavailable until the live e5000b_read_mac.
e5000b_mac:        times 6 db 0
e5000b_tx_busy:    db 0             ; TX producer admission (XCHG only)
align 8
e5000b_info:
    dq 0                                   ; .name: set at register time (org 0 image: no static pointers)
    dd 1500
    db 64
    dd 0
    dd 0
str_e5000b_name:   db "e5000b", 0
; The backend family token of the COMPAT HW nic member (the interface keeps
; dev.name e5000b), the same token as this chip's PCI claim (PCI_DRV_RTL8126).
str_rtl8126_name:  db "rtl8126", 0
; The ONE registered marker for Task3477 (hw-only; never fires in QEMU). EXACT bytes.
str_e5000b_native: db "[PAOS64] MSI Killer E5000B physical native acceptance [msi.network.killer_e5000b.native]", 13, 10, 0
str_e5000b_absent: db "[PAOS64] L2 netdev: RTL8126 Killer E5000B (10ec:5000) not present -> not registered [netdev.rtl8126.absent]", 13, 10, 0
str_e5000b_diag:       db "[PAOS64] L2 netdev: e5000b.diag bus=", 0
str_e5000b_diag_df:    db " devfn=", 0
str_e5000b_diag_bar:   db " bar=", 0
str_e5000b_diag_mac:   db " mac0_3=", 0
str_e5000b_diag_st:    db " [macok rings iso link speed]=", 0

%include "dev/net/rtl8126_bsd_facts.inc"
