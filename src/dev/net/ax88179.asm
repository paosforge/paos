;; MODULE dev/net/ax88179
;; LAYER 3
;; EXPORTS ax88179_lifecycle_poll, ax88179_observation_snapshot, ax88179_port_owned, ax88179_claims_desc, ax88179_selftest, ax88179_create, ax88179_frame_stats
;; IMPORTS boot/native_driver_gate, dev/net/ax_lifecycle, dev/usb/xhci, usb/enum, net/netdev, boot/serial, core/lib/fmt, core/lib/str, core/time
;; CAPS
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
;; LOCK: ax_tx_busy PROTECTS ax_txbuf
;; LOCK: ax_io_busy PROTECTS ax_runtime
%include "dev/net/ax_lifecycle.inc"
; ============================================================================
; dev/net/ax88179.asm — ASIX AX88179 / AX88178A USB Gigabit Ethernet backend
; (Peter's carry-anywhere USB-NIC dongle). Post-USB-enum class consumer on the
; SAME netdev_ops + usbhc_ops seam the CDC-ECM driver established.
;
; PROVENANCE: the ASIX protocol here is ported from the monolith's proven-correct
; ASIX logic (~/projects/paos/paos.asm usb_ax88179_* — chip_reset sequence, the
; ACCESS_MAC vendor request format, register map) BUT NOT its transport: the
; monolith hand-built raw xHCI EP0/bulk TRBs and could never get the controller
; to process them ("controller isn't processing OUT-with-data TRB chains").
; This driver instead uses the rework's WORKING usbhc_ops.control / bulk_in /
; bulk_out (proven by dev/net/cdc_ecm) — so it can work where the monolith couldn't.
;
; Implementation notes (hardware references are pinned in SOURCES.json below):
;   * RX strips the configured two-byte IPE prefix. CRC/DROP bits 29/31 and
;     zero-length metadata handling were corrected 2026-10-17 against BSD facts.
;   * ax_chip_init writes this implementation's RX_CTL, MEDIUM, queue-control
;     and auxiliary values, then its configured BMCR restart value. These are
;     software choices; device effects beyond the sourced facts are unverified.
;   * ax_link_status reads PHYSR and ax_link_reset writes the selected medium
;     and queue row. The queue bytes and speed selection have BSD references.
;   * ax_tx writes its configured padding bits when (len+8) is divisible by maxpacket.
;     The flag value is sourced; a no-ZLP hardware guarantee is not claimed.
;   * PAOS_AX_DTEST=1 (NASM_EXTRA) compiles a metal-only data-path self-test:
;     requires explicit PAOS_AX_DTEST_SPA/TPA IPv4 integers (network order),
;     waits for link, broadcasts an ARP who-has for that target, then polls
;     for the ARP REPLY (not merely the first broadcast that happens by) and
;     hexdumps the first raw bulk-IN so the RX layout is nailed in one boot.
;     Production builds do not carry it (no LAN address, no boot-time TX).
;
; ⚠ METAL-ONLY VALIDATION: QEMU has no AX88179 model. Bring this up on the Lenovo
; (serial console shows the ax88179.* markers) with the dongle plugged in.
;
; HC ops (self-less): control RSI=usb_setup*,RDX=port,RCX=buf,R8=cap;
;   bulk_in/out RSI=port,RDX=ep,RCX=buf,R8=len; configure_ep RSI=port,RDX=ep_desc*.
; ============================================================================

; --- USB / ASIX constants ---
AX_VID                equ 0x0B95
AX_PID_179            equ 0x1790
AX_PID_178A           equ 0x178A
AX_LEGACY_BCD_MAX     equ 0x0100        ; ASIX legacy179/178A driver range0000..0100
AX_DT_DEVICE          equ 1
AX_DT_CONFIG          equ 2
AX_DT_ENDPOINT        equ 5
AX_REQ_GET_DESCRIPTOR equ 6
AX_REQ_SET_CONFIG     equ 9
AX_ACCESS_MAC         equ 0x01          ; ASIX vendor bRequest: MAC register access
AX_ACCESS_PHY         equ 0x02          ; ASIX vendor bRequest: PHY (MII) register access
AX_PHY_ID             equ 0x03          ; AX88179 internal PHY address
AX_RT_WRITE           equ 0x40          ; H2D, vendor, device
AX_RT_READ            equ 0xC0          ; D2H, vendor, device
AX_RT_H2D_STD_DEV     equ 0x00
AX_RT_D2H_STD_DEV     equ 0x80
AX_XFER_BULK          equ 0x02
AX_EP_IN              equ 0x80
; ASIX MAC register addresses: FreeBSD if_axgereg.h; exact pin in SOURCES.json.
AX_REG_PLSR           equ 0x02          ; 1-byte: USB link speed (FS/HS/SS)
AX_REG_RX_CTL         equ 0x0B          ; 2-byte
AX_REG_NODE_ID        equ 0x10          ; 6-byte MAC
AX_REG_MEDIUM_MODE    equ 0x22          ; 2-byte
AX_REG_PHYPWR_RSTCTL  equ 0x26          ; 2-byte (chip_reset)
AX_REG_RX_BULKIN_QCTRL equ 0x2E         ; 5-byte bulk-IN aggregation/flush control
AX_REG_CLK_SELECT     equ 0x33          ; 1-byte
; FreeBSD if_axgereg.h@8011f6b0: AXGE_PWLLR=0x55, AXGE_PWLHR=0x54.
; URL/revision and threshold writes: RCQ-10-AX88179-pause-waterlevels-20261017/SOURCES.json.
AX_REG_PAUSE_WL_LOW   equ 0x55
AX_REG_PAUSE_WL_HIGH  equ 0x54
AX_PLSR_USB_FS        equ 0x01
AX_PLSR_USB_HS        equ 0x02
AX_PLSR_USB_SS        equ 0x04
AX_RXCTL_PRO          equ 0x0001
AX_RXCTL_AMALL        equ 0x0002        ; accept all multicast
AX_RXCTL_AB           equ 0x0008        ; accept broadcast
AX_RXCTL_AM           equ 0x0010        ; accept multicast (hash)
AX_RXCTL_AP           equ 0x0020        ; accept physical (own unicast)
AX_RXCTL_START        equ 0x0080
AX_RXCTL_DROPCRCERR   equ 0x0100
AX_RXCTL_IPE          equ 0x0200        ; IP-header 32-bit alignment: 2-byte pad before each packet
AX_RXCTL_INIT         equ (AX_RXCTL_DROPCRCERR | AX_RXCTL_IPE | AX_RXCTL_START | AX_RXCTL_AP | AX_RXCTL_AMALL | AX_RXCTL_AB)
AX_MEDIUM_GIGAMODE    equ 0x0001
AX_MEDIUM_FULL_DUPLEX equ 0x0002
AX_MEDIUM_EN_125MHZ   equ 0x0008
AX_MEDIUM_RXFLOW      equ 0x0010
AX_MEDIUM_TXFLOW      equ 0x0020
AX_MEDIUM_RECEIVE_EN  equ 0x0100
AX_MEDIUM_PS          equ 0x0200        ; 100 Mb/s port speed
AX_MEDIUM_BASE        equ (AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW | AX_MEDIUM_RXFLOW)
AX_MEDIUM_INIT        equ (AX_MEDIUM_BASE | AX_MEDIUM_FULL_DUPLEX | AX_MEDIUM_GIGAMODE)   ; configured PaOS initial medium value
AX_PHYPWR_IPRL        equ 0x0020
AX_CLK_ACS_BCS        equ 0x03
AX_PAUSE_WL_LOW_VAL   equ 0x34
AX_PAUSE_WL_HIGH_VAL  equ 0x52
; MII (ACCESS_PHY) registers
GMII_PHY_BMCR         equ 0x00
GMII_BMCR_ANENABLE    equ 0x1000
GMII_BMCR_ANRESTART   equ 0x0200
GMII_PHY_PHYSR        equ 0x11
GMII_PHYSR_GIGA       equ 0x8000
GMII_PHYSR_100        equ 0x4000
GMII_PHYSR_SPEED_MASK equ 0xC000
GMII_PHYSR_FULL       equ 0x2000
GMII_PHYSR_LINK       equ 0x0400
; RX packing
AX_RXHDR_ERR_MASK     equ 0xA0000000    ; CRC_ERR (bit29) | DROP_ERR (bit31) in the per-packet info dword
AX_RX_IPE_PAD         equ 2             ; bytes of IP-alignment pad before each packet (counted in pkt_len)
AX_RX_MAX             equ 2048          ; == XHCI_INTR_REPORT_BYTES (2048 since usbnic-late-bind); one full 1514B frame + ASIX hdr/trailer
AX_RX_FRAME_MAX       equ (AX_RX_MAX - 4) / (AX_RX_IPE_PAD + 14 + 4) ; 102 minimum frames + info words
AX_RX_HEADER_MAX      equ (AX_RX_MAX - 4) / 4 ; 511 metadata entries, including zero-length padding
AX_TX_HDR             equ 8             ; AX88179 TX header (2 dwords) prepended to each frame
AX_TX_PAD_FLAG        equ 0x80008000    ; hdr dword1: chip pads when (len+8) % maxpacket == 0

; ============================================================================
; ax88179_selftest — probe + bind + register. Runs AFTER usb_enum (device table
; populated), like cdc_ecm / hid. Degrade-never-wedge: no dongle -> skip marker.
; ============================================================================
ax88179_selftest:
    NATIVE_DRIVER_REFUSE 6, 0
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel ax_rx_count], 0
    mov  dword [rel ax_rx_index], 0
    call usb_dev_count
    mov  r15d, eax
    xor  r14d, r14d
.dev_loop:
    cmp  r14d, r15d
    jae  .none
    mov  edi, r14d
    call usb_dev_is_null
    test eax, eax
    jnz  .dev_next
    mov  edi, r14d
    call usb_dev_hc
    test rax, rax
    jz   .dev_next
    mov  [rel ax_hc], rax
    mov  rbx, [rax + dev.ops]
    mov  [rel ax_hcops], rbx
    mov  edi, r14d
    call usb_dev_addr
    test eax, eax
    jz   .dev_next
    mov  [rel ax_port], al
    ; --- GET_DESCRIPTOR(DEVICE) -> match ASIX VID/PID ---
    call ax_read_device_desc
    ; A shared1790 PID also identifies newer179A/B,772D/E and279/A silicon.
    ; ASIX's table selects distinct drivers by bcdDevice: this backend implements
    ; only its legacy0000..0100 range, for both1790 and178a. Require the complete
    ; fresh standard descriptor before touching revision or issuing chip writes.
    mov  rsi, rax
    lea  rdi, [rel ax_devbuf]
    call ax88179_claims_desc
    test eax, eax
    jz   .dev_next
    movzx eax, word [rel ax_devbuf + 10]
.match:
    mov  [rel ax_pid], ax
    ; RCQ-10: the bind is all-or-nothing. A dongle that stalls or times out at any
    ; step gets no further transfers, is reported, and never registers: the boot
    ; continues to the onboard NICs with at most one bounded transfer spent here.
    mov  byte [rel ax_bind_step], 1
    ; --- read the config descriptor to find bulk IN/OUT endpoints + config value ---
    call ax_read_config_desc
    cmp  rax, 9                              ; -1/-2 is a failure, never a 4 GiB walk length
    jl   .bind_failed
    cmp  rax, AX_CFGBUF_SZ
    ja   .bind_failed
    mov  r12d, eax
    call ax_walk_config                      ; -> RAX=1 found bulk eps (+ config value)
    test rax, rax
    jz   .bind_failed
    ; --- bind: SET_CONFIG -> configure eps -> chip init -> netdev register ---
    mov  byte [rel ax_bind_step], 2
    movzx edx, byte [rel ax_config]
    call ax_set_configuration
    test rax, rax
    js   .bind_failed
    mov  byte [rel ax_bind_step], 3
    lea  rdx, [rel ax_in_ep_desc]
    call ax_configure_ep
    test rax, rax
    js   .bind_failed
    mov  byte [rel ax_bind_step], 4
    lea  rdx, [rel ax_out_ep_desc]
    call ax_configure_ep
    test rax, rax
    js   .bind_failed
    mov  byte [rel ax_bind_step], 5
    call ax_chip_init                        ; chip_reset + MAC + RX/medium/bulk-IN + autoneg
    test rax, rax
    jnz  .bind_failed                        ; ax_init_fail names the chip-init step
    mov  byte [rel ax_present], 1
    call ax88179_create
    cmp dword [rel ax_reg_rc],0
    jl .capture_done
    lea rdi,[rel ax_life]
    mov esi,r14d
    lea rdx,[rel ax_dev]
    lea rcx,[rel ax_rebind_wire]
    lea r8,[rel ax_devbuf]
    lea r9,[rel ax_mac]
    call ax_lifecycle_capture
.capture_done:
    ; HONEST: the registered marker is earned ONLY when netdev_register took the
    ; handle; a rejecting (full) table prints its own marker so "registered" can
    ; never mask an unselectable NIC (the 4-slot table was FULL at boot before
    ; usbnic-late-bind widened it to 8).
    cmp  dword [rel ax_reg_rc], 0
    jl   .reg_rejected
    lea  rdi, [rel str_ax_registered]
    jmp  .reg_print
.reg_rejected:
    lea  rdi, [rel str_ax_reg_rejected]
.reg_print:
    call serial_string
    call ax_emit_diag
%ifdef PAOS_AX_DTEST
    call ax_datapath_selftest                ; metal bring-up only (NASM_EXTRA=-DPAOS_AX_DTEST=1)
%endif
    jmp  .done
.dev_next:
    inc  r14d
    jmp  .dev_loop
.bind_failed:
    lea  rdi, [rel str_ax_bind_failed]
    call serial_string
    movzx edi, byte [rel ax_bind_step]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_initf]
    call serial_string
    movzx edi, byte [rel ax_init_fail]
    call serial_hex64
    lea  rdi, [rel str_ax_bind_failed_tail]
    call serial_string
    jmp  .done
.none:
    lea  rdi, [rel str_ax_skipped]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; ax_read_device_desc -> RAX = bytes read into ax_devbuf (0 = fail)
; ---------------------------------------------------------------------------
ax_read_device_desc:
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_D2H_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], AX_REQ_GET_DESCRIPTOR
    mov  word [rdi + usb_setup.wValue], (AX_DT_DEVICE << 8)
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], 18
    mov  rsi, rdi
    movzx edx, byte [rel ax_port]
    lea  rcx, [rel ax_devbuf]
    mov  r8d, 18
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    ret

; ax_read_config_desc -> RAX = bytes read into ax_cfgbuf
ax_read_config_desc:
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_D2H_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], AX_REQ_GET_DESCRIPTOR
    mov  word [rdi + usb_setup.wValue], (AX_DT_CONFIG << 8)
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], AX_CFGBUF_SZ
    mov  rsi, rdi
    movzx edx, byte [rel ax_port]
    lea  rcx, [rel ax_cfgbuf]
    mov  r8d, AX_CFGBUF_SZ
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    ret

; ax_walk_config(R12=len) -> RAX=1 if both bulk endpoints found; fills config +
; in_ep/out_ep + the two endpoint-descriptor copies. AX88179 has ONE data
; interface with a bulk IN + bulk OUT (+ an interrupt EP we ignore for v1).
ax_walk_config:
    push rbx
    push r14
    mov  byte [rel ax_in_ep], 0
    mov  byte [rel ax_out_ep], 0
    mov  byte [rel ax_in_ep_valid], 0
    mov  byte [rel ax_out_ep_valid], 0
    lea  rbx, [rel ax_cfgbuf]
    movzx eax, byte [rbx + 5]                 ; bConfigurationValue
    mov  [rel ax_config], al
    lea  r14, [rbx + r12]
.wl:
    cmp  rbx, r14
    jae  .done
    movzx eax, byte [rbx]                      ; bLength
    test eax, eax
    jz   .done
    movzx ecx, byte [rbx + 1]                  ; bDescriptorType
    cmp  ecx, AX_DT_ENDPOINT
    jne  .next
    movzx edx, byte [rbx + 3]                  ; bmAttributes
    and  edx, 0x03
    cmp  edx, AX_XFER_BULK
    jne  .next
    movzx eax, byte [rbx + 2]                  ; bEndpointAddress
    test al, AX_EP_IN
    jz   .out
    cmp  byte [rel ax_in_ep_valid], 1          ; first bulk IN wins
    je   .next
    mov  [rel ax_in_ep], al
    mov  byte [rel ax_in_ep_valid], 1
    lea  rdi, [rel ax_in_ep_desc]
    call ax_copy_ep
    jmp  .next
.out:
    cmp  byte [rel ax_out_ep_valid], 1         ; first bulk OUT wins
    je   .next
    mov  [rel ax_out_ep], al
    mov  byte [rel ax_out_ep_valid], 1
    lea  rdi, [rel ax_out_ep_desc]
    call ax_copy_ep
.next:
    movzx eax, byte [rbx]
    add  rbx, rax
    jmp  .wl
.done:
    xor  eax, eax
    cmp  byte [rel ax_in_ep_valid], 1
    jne  .ret
    cmp  byte [rel ax_out_ep_valid], 1
    jne  .ret
    mov  eax, 1
.ret:
    pop  r14
    pop  rbx
    ret

ax_copy_ep:
    push rsi
    push rcx
    mov  rsi, rbx
    mov  ecx, 7
    cld
    rep  movsb
    pop  rcx
    pop  rsi
    ret

ax_set_configuration:
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_H2D_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], AX_REQ_SET_CONFIG
    movzx eax, dl
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], 0
    jmp  ax_ctrl_nodata

ax_configure_ep:
    movzx esi, byte [rel ax_port]
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.configure_ep]
    mov  rdi, [rel ax_hc]
    call rax
    ret

ax_ctrl_nodata:
    lea  rsi, [rel ax_setup]
    movzx edx, byte [rel ax_port]
    xor  ecx, ecx
    xor  r8d, r8d
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    ret

; ---------------------------------------------------------------------------
; ax_write_mac_reg(DIL=reg, SIL=length(1..8), RDX=data LE) — ASIX ACCESS_MAC write.
; bmReq 0x40, bReq 0x01, wValue=reg, wIndex=length, wLength=length.
; FreeBSD axge_write_mem/axge_write_cmd_1/_2 use this setup layout; see SOURCES.json.
; -> RAX = control rc (>=0 ok / <0 fail)
; ---------------------------------------------------------------------------
ax_write_mac_reg:
    push rbx
    movzx ebx, dil                            ; reg
    mov  [rel ax_regbuf], rdx                 ; up to 8 data bytes (LE)
    movzx r9d, sil                            ; length
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_WRITE
    mov  byte [rdi + usb_setup.bRequest], AX_ACCESS_MAC
    mov  word [rdi + usb_setup.wValue], bx
    mov  word [rdi + usb_setup.wIndex], r9w
    mov  word [rdi + usb_setup.wLength], r9w
    mov  rsi, rdi
    movzx edx, byte [rel ax_port]
    lea  rcx, [rel ax_regbuf]
    mov  r8d, r9d
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    pop  rbx
    ret

; ax_read_mac_reg(DIL=reg, SIL=length, RCX=out buf) — ASIX ACCESS_MAC read.
; -> RAX = control rc
ax_read_mac_reg:
    push rbx
    push rcx
    movzx ebx, dil
    movzx r9d, sil
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_READ
    mov  byte [rdi + usb_setup.bRequest], AX_ACCESS_MAC
    mov  word [rdi + usb_setup.wValue], bx
    mov  word [rdi + usb_setup.wIndex], r9w
    mov  word [rdi + usb_setup.wLength], r9w
    mov  rsi, rdi
    movzx edx, byte [rel ax_port]
    pop  rcx                                   ; out buf
    mov  r8d, r9d
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    pop  rbx
    ret

; ax_write_phy_reg(DIL=mii reg, DX=value) — ACCESS_PHY write.
; bmReq 0x40, bReq 0x02, wValue=PHY id, wIndex=reg, wLength=2. -> RAX = rc
; FreeBSD axge_miibus_writereg and axge_write_cmd_2 corroborate the layout.
ax_write_phy_reg:
    push rbx
    movzx ebx, dil
    mov  [rel ax_regbuf], dx
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_WRITE
    mov  byte [rdi + usb_setup.bRequest], AX_ACCESS_PHY
    mov  word [rdi + usb_setup.wValue], AX_PHY_ID
    mov  word [rdi + usb_setup.wIndex], bx
    mov  word [rdi + usb_setup.wLength], 2
    mov  rsi, rdi
    movzx edx, byte [rel ax_port]
    lea  rcx, [rel ax_regbuf]
    mov  r8d, 2
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    pop  rbx
    ret

; ax_read_phy_reg(DIL=mii reg) -> RAX = 16-bit value (0 when the transfer failed;
; the rc is latched in ax_phy_rc for the diag).
ax_read_phy_reg:
    push rbx
    movzx ebx, dil
    mov  word [rel ax_regbuf], 0
    lea  rdi, [rel ax_setup]
    mov  byte [rdi + usb_setup.bmRequestType], AX_RT_READ
    mov  byte [rdi + usb_setup.bRequest], AX_ACCESS_PHY
    mov  word [rdi + usb_setup.wValue], AX_PHY_ID
    mov  word [rdi + usb_setup.wIndex], bx
    mov  word [rdi + usb_setup.wLength], 2
    mov  rsi, rdi
    movzx edx, byte [rel ax_port]
    lea  rcx, [rel ax_regbuf]
    mov  r8d, 2
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.control]
    mov  rdi, [rel ax_hc]
    call rax
    mov  [rel ax_phy_rc], eax
    cmp  rax, 2                                ; a partial PHY word is not link evidence
    jne  .fail
    movzx eax, word [rel ax_regbuf]
    pop  rbx
    ret
.fail:
    xor  eax, eax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; ax_chip_init — existing PaOS register-write sequence. Register addresses and
; setup formats have BSD references; this sequence/delays are software policy.
; Unsourced device-effect assertions are unverified and are not claimed.
; Each control step is numbered (ax_init_step) and the FIRST failing one is latched
; into ax_init_fail (0 = every control completed its full wLength) and printed in the
; diag — so a metal STALL/timeout is attributable to an exact step, blind-free:
;   1 PHYPWR_RSTCTL=0      2 PHYPWR_RSTCTL=IPRL   3 CLK_SELECT=ACS|BCS
;   4 NODE_ID read (MAC)   5 NODE_ID write-back   6 RX_BULKIN_QCTRL
;   7 PAUSE_WL_LOW         8 PAUSE_WL_HIGH        9 RX_CTL
;  10 MEDIUM_MODE         11 PHY BMCR autoneg restart (ACCESS_PHY)
; ---------------------------------------------------------------------------
ax_chip_init:
    NATIVE_DRIVER_REFUSE 6
    push rbx
    mov  byte [rel ax_init_step], 0
    mov  byte [rel ax_init_fail], 0
    ; 1. PHY power-down: PHYPWR_RSTCTL(0x26)=0x0000
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_PHYPWR_RSTCTL
    mov  sil, 2
    xor  edx, edx
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    ; 2. Write PHYPWR_RSTCTL/IPRL 0x26=0x0020, then delay 200 ms (PaOS policy)
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_PHYPWR_RSTCTL
    mov  sil, 2
    mov  edx, AX_PHYPWR_IPRL
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    mov  edi, 200000
    call tsc_delay_us
    ; 3. CLK_SELECT(0x33)=ACS|BCS, 1 byte, then 100 ms
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_CLK_SELECT
    mov  sil, 1
    mov  edx, AX_CLK_ACS_BCS
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    mov  edi, 100000
    call tsc_delay_us
    ; 4. read MAC from NODE_ID(0x10), 6 bytes
    inc  byte [rel ax_init_step]
    mov  qword [rel ax_mac], 0
    mov  dil, AX_REG_NODE_ID
    mov  sil, 6
    lea  rcx, [rel ax_mac]
    call ax_read_mac_reg
    call ax_note_rc
    jc   .failed
    ; 5. Write MAC back to NODE_ID (also done by FreeBSD axge_init)
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_NODE_ID
    mov  sil, 6
    mov  rdx, [rel ax_mac]                     ; low 6 bytes of the qword are the MAC
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    ; 6. Write RX_BULKIN_QCTRL(0x2E) using table row0; re-tuned by ax_link_reset
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_RX_BULKIN_QCTRL
    mov  sil, 5
    mov  rdx, [rel ax_bulkin_tbl]
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    ; 7/8. FreeBSD axge_init@if_axge.c ca48e43b: low(0x55)=0x34, high(0x54)=0x52.
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_PAUSE_WL_LOW
    mov  sil, 1
    mov  edx, AX_PAUSE_WL_LOW_VAL
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_PAUSE_WL_HIGH
    mov  sil, 1
    mov  edx, AX_PAUSE_WL_HIGH_VAL
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    ; 9. Write RX_CTL(0x0B) = this implementation's AX_RXCTL_INIT flags
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_RX_CTL
    mov  sil, 2
    mov  edx, AX_RXCTL_INIT
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    ; 10. MEDIUM_MODE(0x22) = RECEIVE_EN|TXFLOW|RXFLOW|FULL_DUPLEX|GIGAMODE (bind default)
    inc  byte [rel ax_init_step]
    mov  dil, AX_REG_MEDIUM_MODE
    mov  sil, 2
    mov  edx, AX_MEDIUM_INIT
    call ax_write_mac_reg
    call ax_note_rc
    jc   .failed
    ; 11. Write this implementation's BMCR ANENABLE|ANRESTART value
    inc  byte [rel ax_init_step]
    mov  dil, GMII_PHY_BMCR
    mov  edx, (GMII_BMCR_ANENABLE | GMII_BMCR_ANRESTART)
    call ax_write_phy_reg
    call ax_note_rc
    jc   .failed
    mov  word [rel ax_link_state], 0xFFFF       ; force link_reset on the first link-up
    xor  eax, eax
    pop  rbx
    ret
.failed:
    mov  rax, -1                                ; ax_init_fail names the step; nothing more is sent
    pop  rbx
    ret

; ax_note_rc(RAX = control-transfer byte count) — latch the first failing step.
; PaOS usbhc_ops.control returns bytes moved, not merely a success status. Init
; requires the complete current setup.wLength, including the six-byte MAC read.
; CF=1 for negative, short or oversized completion; caller stops before binding.
ax_note_rc:
    test rax, rax
    js   .incomplete
    push rcx
    movzx ecx, word [rel ax_setup + usb_setup.wLength]
    cmp  rax, rcx                             ; full-width count must equal requested bytes
    pop  rcx
    je   .ok
.incomplete:
    cmp  byte [rel ax_init_fail], 0
    jne  .failed
    push rax
    movzx eax, byte [rel ax_init_step]
    mov  [rel ax_init_fail], al
    pop  rax
.failed:
    stc
    ret
.ok:
    clc
    ret

; ---------------------------------------------------------------------------
; ax_link_reset(EDI = PHYSR) — program RX_BULKIN_QCTRL
; for (USB link speed x Ethernet speed) and MEDIUM_MODE for speed/duplex.
; RAX=0 only after all three complete controls, -1 on the first failed/short
; completion. The caller must not cache the PHY state before this succeeds.
; ---------------------------------------------------------------------------
ax_link_reset:
    push rbx
    push r12
    mov  ebx, edi                              ; PHYSR
    ; USB link speed (PLSR, 1 byte)
    mov  byte [rel ax_plsr], 0
    mov  dil, AX_REG_PLSR
    mov  sil, 1
    lea  rcx, [rel ax_plsr]
    call ax_read_mac_reg
    cmp  rax, 1
    jne  .fail
    movzx eax, byte [rel ax_plsr]
    mov  r12d, AX_MEDIUM_BASE
    test bx, GMII_PHYSR_FULL
    jz   .dup
    or   r12d, AX_MEDIUM_FULL_DUPLEX
.dup:
    test bx, GMII_PHYSR_GIGA
    jz   .not_giga
    or   r12d, (AX_MEDIUM_GIGAMODE | AX_MEDIUM_EN_125MHZ)
    xor  edx, edx                              ; row 0: SS giga
    test al, AX_PLSR_USB_SS
    jnz  .row
    mov  edx, 1                                ; row 1: HS giga
    test al, AX_PLSR_USB_HS
    jnz  .row
    mov  edx, 3
    jmp  .row
.not_giga:
    test bx, GMII_PHYSR_100
    jz   .slow
    or   r12d, AX_MEDIUM_PS
    mov  edx, 2                                ; row 2: 100 Mb/s over SS/HS
    test al, (AX_PLSR_USB_SS | AX_PLSR_USB_HS)
    jnz  .row
.slow:
    mov  edx, 3                                ; row 3: everything else
.row:
    lea  rax, [rel ax_bulkin_tbl]
    mov  rdx, [rax + rdx*8]
    mov  dil, AX_REG_RX_BULKIN_QCTRL
    mov  sil, 5
    call ax_write_mac_reg
    cmp  rax, 5
    jne  .fail
    mov  dil, AX_REG_MEDIUM_MODE
    mov  sil, 2
    mov  edx, r12d
    call ax_write_mac_reg
    cmp  rax, 2
    jne  .fail
    mov  [rel ax_medium], r12w
    xor  eax, eax
    jmp  .done
.fail:
    mov  rax, -1
.done:
    pop  r12
    pop  rbx
    ret

; ============================================================================
; ax88179_create — netdev_ops vtable + register (identical shape to cdc_ecm).
; ============================================================================
ax88179_create:
    lea  rdi, [rel ax_ops]
    lea  rax, [rel ax_init]
    mov  [rdi + netdev_ops.init], rax
    lea  rax, [rel ax_start]
    mov  [rdi + netdev_ops.start], rax
    lea  rax, [rel ax_stop]
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel ax_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel ax_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel ax_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel ax_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel ax_recover]
    mov  [rdi + netdev_ops.recover], rax
    lea  rdi, [rel ax_dev]
    lea  rax, [rel ax_ops]
    mov  [rdi + dev.ops], rax
    lea  rax, [rel str_ax_name]
    mov  [rel ax_info], rax               ; dev.info.name (no absolute label in data)
    lea  rax, [rel ax_info]
    mov  [rdi + dev.info], rax
    mov  qword [rdi + dev.priv], 0
    ; RCQ-10: egress-select keeps the FIRST member among equal priorities, and this
    ; USB NIC registers during USB bring-up, before the onboard RTL8168/RTL8126.
    ; At PRIO_NATIVE it shadowed a healthy onboard NIC (the Beelink went dark). One tier
    ; down it is still a native member (net tile WARMING) and still the egress when
    ; it is the only NIC; a proven onboard NIC now wins.
    mov  dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_NET
    mov  dword [rdi + dev.flags], 0
    lea  rax, [rel str_ax_name]
    mov  [rdi + dev.name], rax
    mov  rax, [rel ax_hcops]                   ; RCQ-10: the GONE watch (netdev_usbnic_*)
    mov  [rel ax_watch + usbnic_watch.hcops], rax
    mov  rax, [rel ax_hc]
    mov  [rel ax_watch + usbnic_watch.hc], rax
    movzx eax, byte [rel ax_port]
    mov  [rel ax_watch + usbnic_watch.port], eax
    call netdev_register
    mov  [rel ax_reg_rc], eax           ; slot index, or -1 = REJECTED (table full / bad handle)
    ret

ax_init:
    NATIVE_DRIVER_REFUSE 6
    xor  eax, eax
    ret
ax_start:
    xor  eax, eax
    ret
ax_stop:
    xor  eax, eax
    ret

; tx(self, RSI=frame, RDX=len) -> RAX 0/-1. Prepend the 8-byte AX TX header
; (dword0 = pkt_len, dword1 = 0 | 0x80008000 padding flag when (len+8) is an
; exact multiple of the OUT max packet), then bulk_out (PaOS TX policy).
; BEGIN FRAME STATS -- pure selected-device software readout.
; RDI=self; EAX=0, RDX=RX, RCX=TX, or -1. Aligned qword observations pair
; with LOCK increments; no transactional cross-counter or hardware-read claim.
ax88179_frame_stats:
    lea  rax, [rel ax_dev]
    cmp  rdi, rax
    jne  .unavailable
    lea  rax, [rel ax_ops]
    cmp  [rdi + dev.ops], rax
    jne  .unavailable
    mov  rdx, [rel ax_stat_rx_frames]
    mov  rcx, [rel ax_stat_tx_frames]
    xor  eax, eax
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret
; END FRAME STATS

ax_tx_owned:
    cmp  dword [rel ax_dev + dev.health], HEALTH_DEAD
    je   .gone                                 ; RCQ-10: never a transfer to a GONE device (DEGRADED still sends)
    test rdx, rdx
    jz   .err                                  ; invalid caller input is not a USB device failure
    cmp  rdx, AX_TXBUF_SZ - AX_TX_HDR
    ja   .err                                  ; never truncate a frame or its full-width length
    ; One caller owns staging until the synchronous HC and completion note return.
    ; Refuse overlap without spinning: reentry can occur while that owner waits.
    lock bts dword [rel ax_tx_busy], 0
    jc   .err                                  ; caller contention is not a USB device failure
    push rbx
    push r12
    mov  r12, rsi                              ; frame
    mov  ebx, edx                              ; len
    mov  eax, ebx
    and  eax, 0xFFFF
    mov  [rel ax_txbuf], eax                   ; hdr dword0 = pkt_len
    mov  dword [rel ax_txbuf + 4], 0           ; hdr dword1 = 0 (no TSO)
    movzx ecx, word [rel ax_out_ep_desc + 4]   ; wMaxPacketSize (bits 10:0)
    and  ecx, 0x7FF
    jz   .nopad
    lea  eax, [rbx + AX_TX_HDR]
    xor  edx, edx
    div  ecx
    test edx, edx
    jnz  .nopad
    mov  dword [rel ax_txbuf + 4], AX_TX_PAD_FLAG
.nopad:
    ; copy frame after the 8-byte header
    lea  rdi, [rel ax_txbuf + AX_TX_HDR]
    mov  rsi, r12
    mov  ecx, ebx
    cld
    rep  movsb
    ; bulk_out(port, out_ep, ax_txbuf, len + 8)
    movzx esi, byte [rel ax_port]
    movzx edx, byte [rel ax_out_ep]
    lea  rcx, [rel ax_txbuf]
    lea  r8d, [rbx + AX_TX_HDR]
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.bulk_out]
    mov  rdi, [rel ax_hc]
    call rax
    ; Only a complete nonempty bulk transfer accounts a delivered TX frame.
    lea  r8d, [rbx + AX_TX_HDR]
    cmp  rax, r8
    je   .tx_complete
    mov  rax, -1                               ; short/overlong completion is a failed transfer
    jmp  .stat_tx_done
.tx_complete:
    lock inc qword [rel ax_stat_tx_frames]
.stat_tx_done:
    push rax
    xor  edx, edx
    test rax, rax
    js   .noted
    mov  edx, 1
.noted:
    lea  rdi, [rel ax_dev]
    lea  rsi, [rel ax_watch]
    call netdev_usbnic_io                      ; RCQ-10: a failed transfer may mean GONE
    pop  rax
    mov  dword [rel ax_tx_busy], 0
    pop  r12
    pop  rbx
    test rax, rax
    js   .err
    xor  eax, eax
    ret
.err:
.gone:
    mov  rax, -1                               ; netdev callers inspect the full signed return
    ret

; rx_poll(self, RSI=buf, RDX=cap) -> RAX = len (0 none / -1 err).
; RX format sources: FreeBSD if_axgereg.h, revision
; 8011f6b0d8ba2ee18a60f3bd719f950081a474b3, and if_axge.c, revision
; ca48e43ba9ee73a07cdbad8365117793b01273bb (both BSD-2-Clause).
; Exact URLs and fact-to-source mapping: rc_standing_source/
; RCQ-10-AX88179-rx-error-bits-20261017/SOURCES.json under gauntlet_v2/docs.
; AX88179 RX packing: the bulk-IN buffer ends with a
; 4-byte trailer = (hdr_off << 16) | pkt_count; a per-packet info array of
; `pkt_count` LE dwords starts at hdr_off, each = (pkt_len << 16) | flags
; (bit29 CRC_ERR, bit31 DROP_ERR); the packets sit at the front, each 8-byte
; padded, and — because RX_CTL.IPE is set — each begins with a 2-byte
; IP-alignment pad that pkt_len includes.
; Zero-length metadata entries consume neither packet data nor a cached extent.
; Validate the whole aggregate before delivery, then drain cached frame extents
; in order without overwriting the raw buffer with another USB transfer.
ax_rx_poll_owned:
    push rbx
    push r12
    push r13
    mov  r12, rsi                              ; caller buf
    mov  r13, rdx                              ; caller cap
    lea  rdi, [rel ax_dev]
    lea  rsi, [rel ax_watch]
    call netdev_usbnic_poll                    ; RCQ-10: rate-limited CCS; GONE -> no transfer
    test rax, rax
    jnz  .flush
    mov  eax, [rel ax_rx_index]
    cmp  eax, [rel ax_rx_count]
    jb   .deliver
    ; bulk_in into the raw aggregation buffer, bounded by AX_RX_MAX
    movzx esi, byte [rel ax_port]
    movzx edx, byte [rel ax_in_ep]
    lea  rcx, [rel ax_rxbuf]
    mov  r8d, AX_RX_MAX
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.bulk_in_poll]   ; non-blocking RX: 0 = nothing yet
    test rax, rax
    jnz  .rx_call
    mov  rax, [rel ax_hcops]
    mov  rax, [rax + usbhc_ops.bulk_in]        ; HC without a poll op: blocking fallback
.rx_call:
    mov  rdi, [rel ax_hc]
    call rax
    test rax, rax
    jz   .none                                 ; nothing yet: not a transfer result
    js   .rx_count_checked
    cmp  rax, AX_RX_MAX
    jbe  .rx_count_checked
    mov  rax, -1                               ; reject full-width completion before any buffer access
.rx_count_checked:
    push rax
    xor  edx, edx
    test rax, rax
    js   .rx_noted
    mov  edx, 1
.rx_noted:
    lea  rdi, [rel ax_dev]
    lea  rsi, [rel ax_watch]
    call netdev_usbnic_rx                      ; RCQ-10: RX never re-promotes a DEGRADED member
    pop  rax
    test rax, rax
    jle  .none                                 ; 0 or -1 -> nothing
    mov  ebx, eax                              ; total bulk-IN bytes
%ifdef PAOS_AX_DTEST
    call ax_dt_rxdump                          ; first raw bulk-IN only (nails the layout)
%endif
    lea  rdi, [rel ax_rxbuf]
    mov  esi, ebx
    call ax_rx_parse_aggregate
    test eax, eax
    jz   .none
.deliver:
    mov  eax, [rel ax_rx_index]
    lea  rdx, [rel ax_rx_frames]
    movzx esi, word [rdx + rax*4]
    movzx ecx, word [rdx + rax*4 + 2]
    inc  dword [rel ax_rx_index]                ; a small caller drops only this frame
    cmp  rcx, r13                             ; capacity is the full netdev ABI word
    ja   .none
    lea  rdx, [rel ax_rxbuf]
    add  rsi, rdx
    mov  rdi, r12
    mov  eax, ecx
    cld
    rep  movsb
    lock inc qword [rel ax_stat_rx_frames]
    jmp  .ret
.flush:
    mov  dword [rel ax_rx_count], 0
    mov  dword [rel ax_rx_index], 0
.none:
    xor  eax, eax
.ret:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=received bytes, ESI=bounded byte count -> EAX=valid cached frames.
; A malformed length/table invalidates the whole aggregate. CRC/drop flags
; discard only that structurally valid packet; later valid frames survive.
; Both the loop and fixed extent array are bounded by the 2048-byte RX buffer.
ax_rx_parse_aggregate:
    push rbx
    mov  dword [rel ax_rx_count], 0
    mov  dword [rel ax_rx_index], 0
    mov  ebx, esi
    cmp  ebx, 8
    jb   .bad
    ; trailer = last 4 bytes: pkt_count = low16, hdr_off = high16
    mov  eax, [rdi + rbx - 4]
    movzx ecx, ax                              ; pkt_count
    test ecx, ecx
    jz   .bad
    cmp  ecx, AX_RX_HEADER_MAX
    ja   .bad
    shr  eax, 16                               ; hdr_off
    cmp  eax, ebx
    jae  .bad                                  ; metadata must lie inside the received bytes
    mov  r8d, eax                              ; start of packet-info array / end of data region
    lea  edx, [rax + rcx*4]                    ; all advertised packet-info dwords must fit
    sub  ebx, 4
    cmp  edx, ebx
    ja   .bad                                  ; metadata may not overlap the final trailer
    xor  esi, esi                              ; data cursor (8-byte aligned)
    xor  r9d, r9d                              ; packet-info ordinal
    xor  r10d, r10d                            ; valid cached frames
    lea  r11, [rel ax_rx_frames]
.packet:
    lea  eax, [r8 + r9*4]
    mov  edx, [rdi + rax]
    mov  eax, edx
    shr  eax, 16
    and  eax, 0x1FFF                           ; packet length includes IPE pad
    test eax, eax
    jz   .advance                             ; dummy metadata: no data cursor or cache advancement
    cmp  eax, AX_RX_IPE_PAD + 14
    jb   .bad
    lea  ebx, [rsi + rax + 7]
    and  ebx, -8                              ; include the packet's alignment padding
    cmp  ebx, r8d
    ja   .bad                                  ; every packet must precede its metadata
    test edx, AX_RXHDR_ERR_MASK
    jnz  .next
    cmp  r10d, AX_RX_FRAME_MAX
    jae  .bad                                 ; metadata count is not frame-cache capacity
    add  esi, AX_RX_IPE_PAD
    sub  eax, AX_RX_IPE_PAD
    mov  [r11 + r10*4], si
    mov  [r11 + r10*4 + 2], ax
    inc  r10d
.next:
    mov  esi, ebx
.advance:
    inc  r9d
    dec  ecx
    jnz  .packet
    mov  [rel ax_rx_count], r10d                ; publish only after all extents validate
    mov  eax, r10d
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; link_status(self) -> RAX bit0=up | speed<<8. Reads PHYSR through ACCESS_PHY;
; on a speed/duplex change calls ax_link_reset to re-program MEDIUM_MODE and
; RX_BULKIN_QCTRL. Down (or unbound) -> 0. See BSD/source-policy mapping in SOURCES.json.
ax_link_status_owned:
    push rbx
    xor  eax, eax
    cmp  byte [rel ax_present], 1
    jne  .ret
    cmp  dword [rel ax_dev + dev.health], HEALTH_DEAD
    je   .ret                                  ; RCQ-10: GONE reads down, no control transfer
    mov  dil, GMII_PHY_PHYSR
    call ax_read_phy_reg                       ; RAX = PHYSR (0 on transfer failure)
    mov  [rel ax_physr], ax
    test ax, GMII_PHYSR_LINK
    jz   .down
    mov  ebx, eax
    mov  ecx, 1000
    test bx, GMII_PHYSR_GIGA
    jnz  .speed
    mov  ecx, 100
    test bx, GMII_PHYSR_100
    jnz  .speed
    mov  ecx, 10
.speed:
    mov  eax, ebx
    and  eax, (GMII_PHYSR_SPEED_MASK | GMII_PHYSR_FULL)
    cmp  ax, [rel ax_link_state]
    je   .up
    push rcx
    mov  edi, ebx
    call ax_link_reset
    pop  rcx
    test rax, rax
    jnz  .down                                 ; retry even when the next PHYSR is identical
    mov  eax, ebx
    and  eax, (GMII_PHYSR_SPEED_MASK | GMII_PHYSR_FULL)
    mov  [rel ax_link_state], ax
.up:
    ; A readable PHY alone does not prove the data path was configured. Recover
    ; a soft-degraded member only after successful (or already cached) setup.
    lea  rdi, [rel ax_dev]
    lea  rsi, [rel ax_watch]
    test dword [rdi + dev.flags], NETDEV_F_USBNIC_SOFT
    jz   .ready
    push rcx
    call netdev_usbnic_recover
    pop  rcx
.ready:
    mov  eax, ecx
    shl  eax, 8
    or   eax, 1
    jmp  .ret
.down:
    mov  word [rel ax_link_state], 0xFFFF       ; re-program on the next link-up
    xor  eax, eax
.ret:
    pop  rbx
    ret

ax_get_mac_owned:
    lea  rax, [rel ax_mac]
    mov  ecx, 6
.cp:
    mov  dl, [rax]
    mov  [rsi], dl
    inc  rax
    inc  rsi
    dec  ecx
    jnz  .cp
    xor  eax, eax
    ret

ax_recover:
    mov rax,-1                    ; health only restored by actual root lifecycle
    ret

; The same owner covers TX, RX, link controls and lifetime transitions. The
; existing TX staging guard remains intact. Contention never spins or waits.
%macro AX_IO_WRAPPER 2
    lock bts dword [rel ax_io_busy],0
    jc %%busy
    sub rsp,8
    call %1
    mov dword [rel ax_io_busy],0
    add rsp,8
    ret
%%busy:
    mov rax,%2
    ret
%endmacro
ax_tx:
    AX_IO_WRAPPER ax_tx_owned,-1
ax_rx_poll:
    AX_IO_WRAPPER ax_rx_poll_owned,-1
ax_link_status:
    AX_IO_WRAPPER ax_link_status_owned,0
ax_get_mac:
    AX_IO_WRAPPER ax_get_mac_owned,-1

ax88179_lifecycle_poll:
    NATIVE_DRIVER_REFUSE 6
    lock bts dword [rel ax_io_busy],0
    jc .out
    sub rsp,8
    lea rdi,[rel ax_life]
    call ax_lifecycle_poll
    cmp dword [rel ax_life+ax_lifetime.phase],2
    jb .release
    mov dword [rel ax_rx_count],0
    mov dword [rel ax_rx_index],0
.release:
    mov dword [rel ax_io_busy],0
    add rsp,8
.out:
    ret

; Exact existing class and configuration paths; no selftest scan or registry
; replay. Called only with original owner held after confirmed HC retirement.
ax_rebind_wire:
    push rbx
    push r12
    push r13
    mov r13,rsi                   ; original MAC remains independently retained
    call ax_read_device_desc
    cmp rax,18
    jne .failed
    lea rdi,[rel ax_life]
    lea rsi,[rel ax_devbuf]
    call ax_lifecycle_descriptor_same
    test eax,eax
    jz .failed
    call ax_read_config_desc
    cmp rax,9
    jl .failed
    cmp rax,AX_CFGBUF_SZ
    ja .failed
    mov r12d,eax
    call ax_walk_config
    test rax,rax
    jz .failed
    movzx edx,byte [rel ax_config]
    call ax_set_configuration
    test rax,rax
    jnz .failed
    lea rdx,[rel ax_in_ep_desc]
    call ax_configure_ep
    test rax,rax
    jnz .failed
    lea rdx,[rel ax_out_ep_desc]
    call ax_configure_ep
    test rax,rax
    jnz .failed
    call ax_chip_init
    test rax,rax
    jnz .failed
    mov eax,[rel ax_mac]
    cmp eax,[r13]
    jne .failed
    mov ax,[rel ax_mac+4]
    cmp ax,[r13+4]
    jne .failed
    mov dword [rel ax_watch+usbnic_watch.streak],0
    mov dword [rel ax_watch+usbnic_watch.polls],0
    and dword [rel ax_dev+dev.flags],~NETDEV_F_USBNIC_SOFT
    mov dword [rel ax_rx_count],0
    mov dword [rel ax_rx_index],0
    xor eax,eax
    jmp .out
.failed:
    mov eax,[r13]
    mov [rel ax_mac],eax
    mov ax,[r13+4]
    mov [rel ax_mac+4],ax
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

ax_emit_diag:
    lea  rdi, [rel str_ax_diag]
    call serial_string
    movzx edi, word [rel ax_pid]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_port]
    call serial_string
    movzx edi, byte [rel ax_port]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_in]
    call serial_string
    movzx edi, byte [rel ax_in_ep]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_out]
    call serial_string
    movzx edi, byte [rel ax_out_ep]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_mac]
    call serial_string
    mov  edi, [rel ax_mac]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_initf]
    call serial_string
    movzx edi, byte [rel ax_init_fail]
    call serial_hex64
    lea  rdi, [rel str_ax_diag_regrc]
    call serial_string
    mov  edi, [rel ax_reg_rc]
    call serial_hex64
    call serial_newline
    ret

%ifdef PAOS_AX_DTEST
; ============================================================================
; METAL BRING-UP ONLY: data-path self-test, no built-in network identity.
; NASM_EXTRA must define PAOS_AX_DTEST=1 plus PAOS_AX_DTEST_SPA (our explicitly
; reserved IPv4) and PAOS_AX_DTEST_TPA (peer IPv4), as network-order integers.
; Example inert fixture: SPA=0xC000020A and TPA=0xC0000201 (RFC5737 TEST-NET-1).
; Real diagnostics must use operator-selected addresses for the attached LAN.
; Missing/invalid parameters refuse assembly instead of silently transmitting
; with a stale lab address. Normal builds require no parameters and emit no test.
%ifndef PAOS_AX_DTEST_SPA
    %error "PAOS_AX_DTEST requires explicit PAOS_AX_DTEST_SPA"
%endif
%ifndef PAOS_AX_DTEST_TPA
    %error "PAOS_AX_DTEST requires explicit PAOS_AX_DTEST_TPA"
%endif
%ifdef PAOS_AX_DTEST_SPA
%ifdef PAOS_AX_DTEST_TPA
%if PAOS_AX_DTEST_SPA < 0x01000000 || PAOS_AX_DTEST_SPA >= 0xE0000000 || (PAOS_AX_DTEST_SPA >> 24) = 127
    %error "PAOS_AX_DTEST_SPA must be an explicit unicast IPv4 integer"
%endif
%if PAOS_AX_DTEST_TPA < 0x01000000 || PAOS_AX_DTEST_TPA >= 0xE0000000 || (PAOS_AX_DTEST_TPA >> 24) = 127
    %error "PAOS_AX_DTEST_TPA must be an explicit unicast IPv4 integer"
%endif
%if PAOS_AX_DTEST_SPA = PAOS_AX_DTEST_TPA
    %error "PAOS_AX_DTEST source and target must differ"
%endif
%endif
%endif
; Waits for the PHY link (<= 4 s of autoneg), broadcasts an ARP who-has for the
; selected peer through ax_tx, then polls ax_rx_poll (<= 1 s) for the ARP REPLY
; (ethertype 0x0806, opcode 2) — other broadcasts that happen by are counted,
; not mistaken for success. Serial evidence:
;   ax88179.rxdump total= trailer= info= b0= b8=   (first raw bulk-IN, once)
;   ax88179.dtest link= tx= rx= et= frames=       (rx>0 && et=0x0806 = data path)
;   ax88179.dtest.arp from= ip=                   (the replier's MAC/IP)
; ============================================================================
ax_datapath_selftest:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, 400                             ; <= 400 x 10 ms link wait
.lw:
    call ax_link_status
    test eax, eax
    jnz  .linked
    mov  edi, 10000
    call tsc_delay_us
    dec  r12d
    jnz  .lw
.linked:
    mov  r13d, eax                             ; link word (0 = never came up; still try)
    cld
    lea  rsi, [rel ax_mac]                     ; eth src (offset 6) + ARP sha (offset 22)
    lea  rdi, [rel ax_arp + 6]
    mov  ecx, 6
    rep  movsb
    lea  rsi, [rel ax_mac]
    lea  rdi, [rel ax_arp + 22]
    mov  ecx, 6
    rep  movsb
    lea  rsi, [rel ax_arp]
    mov  edx, 60
    call ax_tx                                 ; RAX 0 ok / -1
    mov  ebx, eax
    xor  r14d, r14d                            ; frames received (any)
    mov  dword [rel ax_dt_rxlen], 0
    mov  r12d, 1000                            ; <= 1000 x 1 ms
.rx:
    lea  rsi, [rel ax_dtbuf]
    mov  edx, 1024
    call ax_rx_poll
    test rax, rax
    jle  .wait
    inc  r14d
    mov  [rel ax_dt_rxlen], eax
    cmp  word [rel ax_dtbuf + 12], 0x0608      ; ethertype 0x0806 (bytes 08 06)
    jne  .wait
    cmp  word [rel ax_dtbuf + 20], 0x0200      ; ARP opcode 2 = reply (bytes 00 02)
    je   .got
.wait:
    mov  edi, 1000
    call tsc_delay_us
    dec  r12d
    jnz  .rx
.got:
    lea  rdi, [rel str_ax_dtest]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_ax_dtest_tx]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_ax_dtest_rx]
    call serial_string
    mov  edi, [rel ax_dt_rxlen]
    call serial_hex64
    lea  rdi, [rel str_ax_dtest_et]
    call serial_string
    movzx edi, byte [rel ax_dtbuf + 12]
    shl  edi, 8
    movzx eax, byte [rel ax_dtbuf + 13]
    or   edi, eax
    call serial_hex64
    lea  rdi, [rel str_ax_dtest_fr]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    call serial_newline
    cmp  dword [rel ax_dt_rxlen], 42
    jb   .out
    lea  rdi, [rel str_ax_dtest_arp]
    call serial_string
    mov  edi, [rel ax_dtbuf + 22]              ; sender MAC bytes 0..3
    call serial_hex64
    lea  rdi, [rel str_ax_dtest_ip]
    call serial_string
    mov  edi, [rel ax_dtbuf + 28]              ; sender IP (LE dword of the 4 bytes)
    call serial_hex64
    call serial_newline
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ax_dt_rxdump(EBX = total bulk-IN bytes) — print the first raw bulk-IN once.
ax_dt_rxdump:
    cmp  byte [rel ax_dt_dumped], 0
    jne  .ret
    mov  byte [rel ax_dt_dumped], 1
    lea  rdi, [rel str_ax_rxdump]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_ax_rxdump_tr]
    call serial_string
    lea  rdi, [rel ax_rxbuf]
    mov  edi, [rdi + rbx - 4]
    call serial_hex64
    lea  rdi, [rel str_ax_rxdump_info]
    call serial_string
    lea  rdi, [rel ax_rxbuf]
    mov  eax, [rdi + rbx - 4]
    shr  eax, 16
    cmp  eax, ebx
    jae  .noinfo
    mov  edi, [rdi + rax]
    call serial_hex64
    jmp  .b0
.noinfo:
    mov  edi, 0xFFFFFFFF
    call serial_hex64
.b0:
    lea  rdi, [rel str_ax_rxdump_b0]
    call serial_string
    mov  rdi, [rel ax_rxbuf]
    call serial_hex64
    lea  rdi, [rel str_ax_rxdump_b8]
    call serial_string
    mov  rdi, [rel ax_rxbuf + 8]
    call serial_hex64
    call serial_newline
.ret:
    ret

str_ax_dtest:      db "[PAOS64] L2 netdev: ax88179.dtest link=", 0
str_ax_dtest_tx:   db " tx=", 0
str_ax_dtest_rx:   db " rx=", 0
str_ax_dtest_et:   db " et=", 0
str_ax_dtest_fr:   db " frames=", 0
str_ax_dtest_arp:  db "[PAOS64] L2 netdev: ax88179.dtest.arp from=", 0
str_ax_dtest_ip:   db " ip=", 0
str_ax_rxdump:     db "[PAOS64] L2 netdev: ax88179.rxdump total=", 0
str_ax_rxdump_tr:  db " trailer=", 0
str_ax_rxdump_info: db " info=", 0
str_ax_rxdump_b0:  db " b0=", 0
str_ax_rxdump_b8:  db " b8=", 0
ax_dt_dumped:      db 0
align 4
ax_dt_rxlen:       dd 0
ax_dtbuf:          times 1024 db 0
; Broadcast ARP request with explicit diagnostic-only source and peer IPv4.
ax_arp:
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0,0,0,0,0,0, 0x08,0x06
    db 0x00,0x01, 0x08,0x00, 6, 4, 0x00,0x01
    db 0,0,0,0,0,0                    ; sha (runtime = our MAC)
    db (PAOS_AX_DTEST_SPA >> 24) & 255, (PAOS_AX_DTEST_SPA >> 16) & 255
    db (PAOS_AX_DTEST_SPA >> 8) & 255, PAOS_AX_DTEST_SPA & 255 ; spa
    db 0,0,0,0,0,0                    ; tha
    db (PAOS_AX_DTEST_TPA >> 24) & 255, (PAOS_AX_DTEST_TPA >> 16) & 255
    db (PAOS_AX_DTEST_TPA >> 8) & 255, PAOS_AX_DTEST_TPA & 255 ; tpa
    times 60-($-ax_arp) db 0
%endif

; ax88179_claims_desc(RDI=descriptor, RSI=completed byte count) -> EAX 0/1.
; One legacy identity boundary for fresh vendor admission and cached class
; exclusion. Clobbers only RAX/flags; never transfers or changes ownership.
; The caller owns an immutable mapped buffer of RSI bytes. Cached enum device
; descriptors are published only after an exact18B standard DEVICE completion.
ax88179_claims_desc:
    xor  eax, eax
    cmp  rsi, 18
    jne  .out
    test rdi, rdi
    jz   .out
    cmp  byte [rdi], 18
    jne  .out
    cmp  byte [rdi + 1], AX_DT_DEVICE
    jne  .out
    cmp  word [rdi + 8], AX_VID
    jne  .out
    cmp  word [rdi + 12], AX_LEGACY_BCD_MAX
    ja   .out
    cmp  word [rdi + 10], AX_PID_179
    je   .yes
    cmp  word [rdi + 10], AX_PID_178A
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; ax88179_port_owned(RDI=hc dev*, ESI=root port) -> EAX 1 when this driver bound that
;   controller/port. Read-only; lets a later class binder (dev/blk/usb_msd)
;   never take a device this driver owns.
ax88179_port_owned:
    xor  eax, eax
    cmp  byte [rel ax_present], 1
    jne  .out
    cmp  [rel ax_hc], rdi
    jne  .out
    cmp  [rel ax_port], sil
    jne  .out
    mov  eax, 1
.out:
    ret

%include "dev/net/ax88179_observation.inc"

; --- data (in-image writable) ------------------------------------------------
AX_CFGBUF_SZ  equ 256
AX_TXBUF_SZ   equ 2048
AX_RXBUF_SZ   equ 2048
ax_hc:            dq 0
ax_watch:         times usbnic_watch_size db 0   ; RCQ-10 GONE watch (filled at create)
ax_hcops:         dq 0
ax_port:          db 0
ax_config:        db 0
ax_in_ep:         db 0
ax_out_ep:        db 0
ax_in_ep_valid:   db 0
ax_out_ep_valid:  db 0
ax_present:       db 0
ax_init_step:     db 0                    ; current chip_init control step (1..11)
ax_init_fail:     db 0                    ; first failing step (0 = all control xfers ok)
ax_bind_step:     db 0                    ; RCQ-10: bind stage reached (1 config .. 5 chip init)
ax_reg_rc:        dd 0                    ; netdev_register rc: slot index or -1 (rejected/full)
ax_plsr:          db 0                    ; USB link speed (PLSR)
align 2
ax_pid:           dw 0
ax_link_state:    dw 0xFFFF               ; last programmed PHYSR speed|duplex bits (0xFFFF = none)
ax_physr:         dw 0                    ; last PHYSR read
ax_medium:        dw 0                    ; last MEDIUM_MODE written by link_reset
align 4
ax_phy_rc:        dd 0                    ; last ACCESS_PHY read rc
align 8
ax_mac:           times 8 db 0            ; 6-byte MAC (read via qword)
ax_regbuf:        times 8 db 0
; RX_BULKIN_QCTRL rows: FreeBSD axge_bulk_size, exact pin in SOURCES.json. Five bytes LE:
;   0: SS giga {07,4f,00,12,ff}  1: HS giga {07,20,03,16,ff}
;   2: 100Mb   {07,ae,07,18,ff}  3: other   {07,cc,4c,18,08}
ax_bulkin_tbl:    dq 0x000000FF12004F07, 0x000000FF16032007, 0x000000FF1807AE07, 0x0000000008184CCC07
align 8
ax_stat_rx_frames: dq 0
ax_stat_tx_frames: dq 0
ax_tx_busy:        dd 0                    ; atomic nonblocking owner of TX staging
align 8
ax_rx_count:       dd 0
ax_rx_index:       dd 0
ax_rx_frames:      times AX_RX_FRAME_MAX * 4 db 0 ; LE u16 offset/length pairs
ax_dev:           times dev_size db 0
ax_ops:           times netdev_ops_size db 0
ax_setup:         times usb_setup_size db 0
ax_in_ep_desc:    times 8 db 0
ax_out_ep_desc:   times 8 db 0
ax_devbuf:        times 32 db 0
ax_cfgbuf:        times AX_CFGBUF_SZ db 0
ax_txbuf:         times AX_TXBUF_SZ db 0
ax_rxbuf:         times AX_RXBUF_SZ db 0
ax_info:
    dq 0                              ; name ptr bound at runtime in ax88179_create (relocation-safe)
    dd 1500
    db 64
    dd 0
    dd 0
str_ax_name:  db "ax88179", 0

str_ax_registered: db "[PAOS64] L2 netdev: ASIX AX88179 USB-GbE bound via netdev_ops HANDLE [netdev.ax88179.registered]", 13, 10, 0
str_ax_bind_failed: db "[PAOS64] L2 netdev: ax88179 bind FAILED step=", 0
str_ax_bind_failed_tail: db " - not registered, onboard NICs unaffected [netdev.ax88179.bind.failed]", 13, 10, 0
str_ax_skipped:    db "[PAOS64] L2 netdev: ax88179 skipped (no ASIX dongle enumerated) [netdev.ax88179.skipped]", 13, 10, 0
str_ax_diag:       db "[PAOS64] L2 netdev: ax88179.diag pid=", 0
str_ax_diag_port:  db " port=", 0
str_ax_diag_in:    db " in_ep=", 0
str_ax_diag_out:   db " out_ep=", 0
str_ax_diag_mac:   db " mac0_3=", 0
str_ax_diag_initf: db " init_fail=", 0
str_ax_diag_regrc: db " reg_rc=", 0
str_ax_reg_rejected: db "[PAOS64] L2 netdev: ax88179 bound on USB but netdev_register REJECTED the handle (table full?) - NOT selectable [netdev.ax88179.reg_rejected]", 13, 10, 0

align 8
ax_io_busy: dd 0
align 8
ax_life: times ax_lifetime_size db 0
