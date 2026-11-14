; ============================================================================
; driver_classes.inc — THE DEVICE-CLASS ABI (the hand-designed seam, G2)
;
; DRIVER_MODEL.md made concrete. This header is the CONTRACT every chip backend
; ports against and every class upper-half implements. The loop FILLS backends
; against these fixed vtables; it must NEVER invent or alter an interface here
; (MIGRATION.md §3). Changing a slot's meaning is a deliberate ABI change,
; reviewed by hand, version-bumped (DRIVER_ABI_VERSION below).
;
; This is a .inc HEADER: pure struc/equ/macro, NO code, NO manifest. It is
; %include'd EARLY in paos.asm (single-pass: strucs must precede first use).
; modlint walks .asm modules only, so headers are not module-linted.
;
; CALLING CONVENTION (all ops): SysV internal ABI (RDI,RSI,RDX,RCX,R8,R9).
;   * RDI = self  — ALWAYS the device handle (struct dev*) as the first arg.
;   * Callee preserves RBX,RBP,R12-R15,RSP. Each op's extra clobbers are stated.
;   * Return in RAX. Convention: 0 = ok, -1 = error/again, >=0 = a count/value
;     where a slot says so. NEVER a blocking call: an op either completes within
;     a bounded budget or returns -1/again — a wedged chip degrades, never hangs
;     the stack (DRIVER_MODEL.md §1, fault-tolerance rule).
; ============================================================================

%ifndef DRIVER_CLASSES_INC
%define DRIVER_CLASSES_INC

DRIVER_ABI_VERSION   equ 2            ; bump on any incompatible slot change (v2: snd stream/status seam, Task3201)

; ---- device class tags ------------------------------------------------------
CLASS_NET            equ 1
CLASS_BLOCK          equ 2
CLASS_INPUT          equ 3
CLASS_SOUND          equ 4
CLASS_DISPLAY        equ 5
CLASS_USBHC          equ 6            ; USB host controller (xhci)

; ---- backend selection priority (HIGHER wins; DRIVER_MODEL.md §6) -----------
; A class core routes through the highest-priority HEALTHY backend for a device.
PRIO_DOMAIN          equ 10           ; Linux-in-guest via virtio (the launch floor)
PRIO_NATIVE_EXPERIMENTAL equ 50       ; native but flagged unproven on this box
PRIO_NATIVE          equ 100          ; proven native chip driver — always preferred

; ---- backend health (the recover/degrade ladder, §5) -----------------------
HEALTH_OK            equ 0
HEALTH_DEGRADED      equ 1            ; recover() ladder running; bounded retries
HEALTH_DEAD          equ 2            ; ladder exhausted; deregistered, box runs on

; ---- register() return ------------------------------------------------------
REG_OK               equ 0
REG_REJECT           equ -1           ; class core refused (bad ABI ver / dup / caps)

; ============================================================================
; struct dev — the UNIFORM device handle (every backend's context starts here)
;
; A backend allocates a context whose first bytes ARE this header, fills .ops/
; .info/.prio/.class, sets .priv to its own chip state, and calls <class>_register.
; The class core threads handles on its intrusive .next list and dispatches via
; .ops. This is the single lifecycle object across ALL classes (§5).
; ============================================================================
struc dev
  .ops:      resq 1     ; -> class *_ops vtable (function pointers below)
  .info:     resq 1     ; -> class *_info block
  .priv:     resq 1     ; -> chip-private context (backend owns; opaque to core)
  .prio:     resd 1     ; PRIO_* (selection)
  .health:   resd 1     ; HEALTH_*
  .class:    resd 1     ; CLASS_*
  .flags:    resd 1     ; class-specific flag bits (see *_F_* below)
  .next:     resq 1     ; intrusive registry list link (core owns)
  .name:     resq 1     ; -> short ASCII name (for COREMAP/logs/markers)
endstruc
DEV_SIZE             equ dev_size

; ============================================================================
; netdev  (upper half: net/netdev.asm — eth/ARP/IP/UDP/TCP/DHCP/DNS, the
;          multi-NIC table + primary-selection/failover (lifeline-NIC logic
;          generalized) + the NIC watchdog ladder + TX queue/RX dispatch)
;          backends: dev/net/{e1000e,i219_lm,rtl8168h,rtl8161,rtl8139,
;                              ax88179(USB), virtio_domain, loopnet(fake)}.asm
; ============================================================================
struc netdev_ops
  .init:        resq 1  ; (self)            -> RAX 0/-1   alloc dma, map mmio (via HAL), reset
  .start:       resq 1  ; (self)            -> RAX 0/-1   enable rx/tx, arm irq/poll
  .stop:        resq 1  ; (self)            -> RAX        quiesce; safe to re-start or unload
  .tx:          resq 1  ; (self,RSI=frame,RDX=len) -> RAX 0 ok / -1 ring-full (NON-BLOCKING)
  .rx_poll:     resq 1  ; (self,RSI=buf,RDX=cap)   -> RAX =len (0 none / -1 err); fills buf
  .link_status: resq 1  ; (self)            -> RAX bit0=up; bits[8..31]=speed Mbps
  .get_mac:     resq 1  ; (self,RSI=out6)   -> RAX 0/-1   write 6-byte MAC to [RSI]
  .recover:     resq 1  ; (self)            -> RAX 0 recovered / -1 dead (the chip's reset rung)
endstruc

; ---- RCQ-10 USB NIC surprise removal: the GONE watch ------------------------
; One per USB NIC backend, filled when it registers; judged by the net class core
; (netdev_usbnic_io for TX, netdev_usbnic_rx, netdev_usbnic_poll). GONE is HEALTH_DEAD, set only on positive
; detach evidence (PORTSC.CCS=0): egress select skips the member from the next TX on,
; and it is sticky (a re-plugged device stays GONE until reboot; re-attach is HUB1).
; An error streak alone is DEGRADED + NETDEV_F_USBNIC_SOFT: non-sticky, and egress
; still uses it while no member is healthy. Poll-time only: no interrupt source.
struc usbnic_watch
  .hcops:  resq 1   ; usbhc_ops* (NULL, or a NULL .port_status, = no CCS signal)
  .hc:     resq 1   ; usbhc self
  .port:   resd 1   ; the backend-neutral port address its transfers use
  .streak: resd 1   ; consecutive failed bulk transfers since the last success
  .polls:  resd 1   ; rx polls since the last PORTSC read
  .logs:   resd 1   ; DEGRADED/recovered serial lines written (bounded: USBNIC_LOG_TRANSITIONS)
endstruc
USBNIC_DEGRADE_STREAK equ 4         ; consecutive failed bulk transfers, no success between -> DEGRADED
USBNIC_LOG_TRANSITIONS equ 8        ; DEGRADED/recovered lines per device per boot (a flapping NIC stays quiet)
USBNIC_CCS_EVERY    equ 64          ; rx polls per PORTSC.CCS read while present
USBNIC_PORT_CONNECT equ (1 << 0)    ; = USB_PORT_CONNECT (usb/enum.asm): PORTSC.CCS through .port_status

struc netdev_info
  .name:        resq 1  ; -> ASCII
  .mtu:         resd 1
  .dma_mask:    resb 1  ; 32 or 64
  .flags:       resd 1  ; NETF_*
  .speed_caps:  resd 1  ; advertised speeds bitmask (info/diag)
endstruc
NETF_WIFI            equ (1 << 0)     ; backend also registers net/wifi80211.asm
NETF_USB             equ (1 << 1)     ; rides usb/core.asm (ax88179) — hotplug aware

; Per-instance static-address ownership in dev.flags.  These are runtime
; identities, not build targets: the selected NIC backend sets exactly one bit
; only after matching the live controller.  The UDP projection additionally
; binds metal identities to the expected NIC MAC before assigning an address.
NETDEV_F_ADDR_QEMU    equ (1 << 0)
NETDEV_F_ADDR_LENOVO  equ (1 << 1)
NETDEV_F_ADDR_DELL    equ (1 << 2)
NETDEV_F_ADDR_BEELINK equ (1 << 3)
NETDEV_F_ADDR_MSI_CT  equ (1 << 4)     ; MSI MS-7E19 Intel CT 82574L add-in (metal only)
NETDEV_F_ADDR_MSI     equ (1 << 5)     ; MSI MS-7E19 onboard Killer E5000B / RTL8126
NETDEV_F_ADDR_HP      equ (1 << 6)     ; HP-PORT-4: HP EliteDesk 705 G5 onboard RTL8168ep (MAC-bound; no backend sets it yet — B1/Q1)
NETDEV_F_ADDR_HP_CT   equ (1 << 7)     ; HP EliteDesk 705 G5 + Intel CT 82574L add-in (PETER 06:22): identity-keyed (AuthenticAMD + 8086:10D3), MAC unknown until install
NETDEV_F_ABSENT       equ (1 << 9)     ; a backend registered with NO device behind it (no NIC / chip / guest):
                                       ;   DEGRADED means 'nothing there', not a fault. Display only (NETCFG
                                       ;   MEMBERS / netmon 'absent'); egress never reads it.
NETDEV_F_USBNIC_SOFT  equ (1 << 8)     ; RCQ-10: a USB NIC netdev DEGRADED on an error streak (non-sticky; egress fallback)
NETDEV_F_LINK_WAIT    equ (1 << 10)    ; RCQ-10: DEGRADED ONLY because the link was down at bring-up (exact identity,
                                       ;   rings armed). netdev_link_reprobe promotes it to HEALTH_OK on a later
                                       ;   link-up read and clears the flag. Never set for absent/foreign/GONE members.
NETDEV_F_ADDR_MASK    equ (NETDEV_F_ADDR_QEMU | NETDEV_F_ADDR_LENOVO | NETDEV_F_ADDR_DELL | NETDEV_F_ADDR_BEELINK | NETDEV_F_ADDR_MSI_CT | NETDEV_F_ADDR_MSI | NETDEV_F_ADDR_HP | NETDEV_F_ADDR_HP_CT)

; ============================================================================
; blockdev (upper half: fs/blockdev.asm — partition scan, the VFS mount table
;           (already vtable-shaped today), FAT32/exFAT/NTFS/ext4, cache policy,
;           AND the boot-canon write gates + LBA allowlist (SECURITY.md §4 —
;           the upper half is the STRUCTURAL-ONLY path to .write; backends MUST
;           NOT expose a raw writer reachable below the gate, CRITIQUE issue A).
;           backends: dev/blk/{nvme,ahci,usb_msc,ramblk(fake)}.asm
; ============================================================================
struc blk_ops
  .identify:    resq 1  ; (self)                       -> RAX 0/-1; fills blk_info
  .read:        resq 1  ; (self,RSI=lba,RDX=count,RCX=buf) -> RAX 0/-1
  .write:       resq 1  ; (self,RSI=lba,RDX=count,RCX=buf) -> RAX 0/-1  [CAP_BLOCK_WRITE +
                        ;   LBA allowlist enforced by the upper half BEFORE this is reached]
  .flush:       resq 1  ; (self)                       -> RAX 0/-1  (FUA/cache-flush — must
                        ;   actually fire; DRAM-less NVMe FTL-loss lesson, DATA.md)
endstruc

struc blk_info
  .name:        resq 1
  .sector_size: resd 1  ; 512 / 4096
  .lba_max:     resq 1
  .dma_mask:    resb 1
  .removable:   resb 1
  .flags:       resd 1  ; BLKF_*
  .unit:        resd 1  ; stable backend unit (AHCI physical port, NVMe namespace, ...)
  ; Additive geometry/capability ABI (2912).  The shipped fields above and
  ; their offsets are immutable; sector_size remains the compatibility view
  ; of logical_sector_bytes for existing callers.
  .abi_v2_pad:               resw 1  ; align appended scalar/qword fields; v1 ends at byte 29
  .logical_sector_bytes:    resd 1
  .physical_sector_bytes:   resd 1
  .physical_alignment_bytes: resd 1  ; bytes from LBA 0 to the first physical-sector boundary
                                     ;   (Linux alignment_offset); 0 = LBA 0 starts one
  .max_transfer_sectors:    resd 1
  .capabilities:            resq 1  ; BLKCAP_* policy, never inferred from name/unit
  .media_generation:        resq 1  ; immutable while this registered medium is current
endstruc
; Compile-time guard for the shipped v1 prefix.  New fields must remain after
; byte 29; an accidental reorder of any legacy member is an assembly failure.
%if blk_info.name != 0
  %error "blk_info.name ABI offset changed"
%endif
%if blk_info.sector_size != 8
  %error "blk_info.sector_size ABI offset changed"
%endif
%if blk_info.lba_max != 12
  %error "blk_info.lba_max ABI offset changed"
%endif
%if blk_info.dma_mask != 20
  %error "blk_info.dma_mask ABI offset changed"
%endif
%if blk_info.removable != 21
  %error "blk_info.removable ABI offset changed"
%endif
%if blk_info.flags != 22
  %error "blk_info.flags ABI offset changed"
%endif
%if blk_info.unit != 26
  %error "blk_info.unit ABI offset changed"
%endif
%if blk_info.abi_v2_pad != 30
  %error "blk_info additive fields no longer follow the shipped v1 prefix"
%endif
%if blk_info.logical_sector_bytes != 32
  %error "blk_info v2 geometry alignment changed"
%endif
BLKF_REMOVABLE       equ (1 << 0)
BLKF_RO              equ (1 << 1)     ; mounted read-only (allowlist default off-boot-disk)
BLKCAP_READ          equ (1 << 0)
BLKCAP_WRITE         equ (1 << 1)
BLKCAP_FLUSH         equ (1 << 2)
BLKCAP_ALL_IO        equ (BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH)

; Stable class-core refusal classes.  Backends retain -1 for a bounded device
; failure; every validation/gate refusal is distinguishable and is returned
; before a vtable entry can run.
BLK_ERR_BACKEND          equ -1
BLK_ERR_ZERO_COUNT       equ -2
BLK_ERR_LBA_OVERFLOW     equ -3
BLK_ERR_END_OF_DEVICE    equ -4
BLK_ERR_BYTE_OVERFLOW    equ -5
BLK_ERR_INVALID_GEOMETRY equ -6
BLK_ERR_MAX_TRANSFER     equ -7
BLK_ERR_CAPABILITY       equ -8
BLK_ERR_WRITE_GATE       equ -9
BLK_ERR_UNHEALTHY        equ -10
BLK_ERR_FLUSH_UNSUPPORTED equ -11  ; a declared capability mask without BLKCAP_FLUSH

; ============================================================================
; inputdev (PUSH model — backends translate hw events into one normalized
;           input_event and call input_push() in gui/input core. Keymaps,
;           repeat, modifiers, focus routing live above, written once.
;           CANON: USB HID usage codes for keys; PS/2 backend translates UP.)
;           backends: dev/input/{ps2_kbd,ps2_mouse,usb_hid_kbd,usb_hid_mouse}.asm
; ============================================================================
struc inputdev_ops
  .init:        resq 1  ; (self) -> RAX 0/-1
  .start:       resq 1  ; (self) -> RAX 0/-1  arm irq; from here it PUSHES events up
  .stop:        resq 1  ; (self) -> RAX
  .recover:     resq 1  ; (self) -> RAX 0/-1
endstruc

struc input_event              ; the ONE normalized event (backend fills, pushes up)
  .type:        resb 1  ; EV_*
  .pad0:        resb 1
  .code:        resw 1  ; keys: USB HID usage; rel: REL_*; btn: BTN_*
  .value:       resd 1  ; key make=1/break=0; rel: signed delta; abs: position
  .dev:         resq 1  ; -> source struct dev
endstruc
EV_KEY               equ 1
EV_REL               equ 2           ; relative (mouse dx/dy/wheel)
EV_ABS               equ 3           ; absolute (touch/tablet — future)
EV_SYNC              equ 4           ; end-of-packet boundary
REL_X                equ 0
REL_Y                equ 1
REL_WHEEL            equ 2
BTN_LEFT             equ 0x110
BTN_RIGHT            equ 0x111
BTN_MIDDLE           equ 0x112

; ============================================================================
; sounddev (upper half: snd/core.asm — mixer, format conversion, the MP3/FLAC/
;           WAV codecs (pure software, zero hw coupling), playback/record svcs,
;           audio test markers).  backends: dev/snd/{hda,nullsnd(fake)}.asm
; ============================================================================
; snd_ops — ABI v2 (Task3201). Every stream op is handle-scoped: open() returns
; one opaque core-owned handle; submit/position/status/set_volume/close take it
; and reject stale/cross-backend handles. recover() alone is backend/controller-
; scoped (no handle). Handle-scoped media seam so no second breaking bump later.
struc snd_ops
  .open:        resq 1  ; (self,RSI=snd_stream_params*,RDX=out_handle*) -> RAX 0/-1
  .submit:      resq 1  ; (self,RSI=handle,RDX=buf,RCX=len)             -> RAX bytes-transferred / -1
  .position:    resq 1  ; (self,RSI=handle)                            -> RAX = cursor frames / -1
  .status:      resq 1  ; (self,RSI=handle,RDX=snd_status*)            -> RAX 0/-1
  .set_volume:  resq 1  ; (self,RSI=handle,RDX=vol_q15)                -> RAX 0/-1
  .close:       resq 1  ; (self,RSI=handle)                            -> RAX 0/-1
  .recover:     resq 1  ; (self)  backend/controller-scoped            -> RAX 0/-1
endstruc

struc snd_info
  .name:        resq 1
  .formats:     resd 1  ; SNDFMT_* bitmask
  .max_chan:    resd 1
  .rates:       resd 1  ; supported sample-rate bitmask
endstruc

; snd_stream_params — the durable ABI-v2 media-stream envelope handed to open().
struc snd_stream_params
  .rate:            resd 1  ; sample rate (Hz)
  .format:          resd 1  ; SNDFMT_* (exactly one)
  .channels:        resd 1  ; channel count
  .direction:       resd 1  ; SND_DIR_PLAY / SND_DIR_CAPTURE
  .latency_class:   resd 1  ; SND_LATENCY_*
  .timestamp_base:  resd 1  ; SND_TSBASE_*
  .session_group:   resq 1  ; opaque caller session-group id (retained, non-zero)
endstruc

; snd_status — presentation timing/state readback for a live stream handle.
struc snd_status
  .frames:      resq 1  ; frames consumed/produced so far
  .timestamp:   resq 1  ; presentation timestamp (frames, TSC-derived seam)
  .state:       resd 1  ; SND_STATE_*
  .xruns:       resd 1  ; under/overrun count
endstruc
; A backend without a qualified presentation clock must report unavailable,
; rather than substitute submit/DMA counts for an audible timestamp.
SND_TIMESTAMP_UNAVAILABLE equ -1

SND_DIR_PLAY         equ 0
SND_DIR_CAPTURE      equ 1
SNDFMT_S16LE         equ (1 << 0)
SNDFMT_S24LE         equ (1 << 1)
SNDFMT_S32LE         equ (1 << 2)
SND_LATENCY_INTERACTIVE equ 0    ; lowest-latency class (games/comms)
SND_LATENCY_BALANCED    equ 1
SND_LATENCY_BULK        equ 2    ; throughput-first (media playback)
SND_TSBASE_TSC          equ 1    ; presentation timestamps derived from the TSC
SND_STATE_CLOSED     equ 0
SND_STATE_IDLE       equ 1
SND_STATE_RUNNING    equ 2

; ============================================================================
; displaydev (consumers in gui/fb.asm + compositor. Two backends day one: GOP
;             (always works) and igpu-accel where the ladder reached. Compositor
;             asks caps, accelerates opportunistically (graceful degradation).
;             RESOLUTION = monitor-native, UNCAPPED (4K waypoint; dirty-rects
;             mandatory). backends: dev/gpu/{gop,igpu}.asm
; ============================================================================
struc disp_ops
  .fill:        resq 1  ; (self,RSI=rect*,RDX=argb)       -> RAX  (HW or sw fallback)
  .blit:        resq 1  ; (self,RSI=blit_desc*)           -> RAX
  .present:     resq 1  ; (self)                          -> RAX  flip / flush dirty rects
  .caps:        resq 1  ; (self)                          -> RAX = DISPCAP_* bitmask
endstruc

struc disp_info
  .width:       resd 1
  .height:      resd 1
  .stride:      resd 1  ; bytes/scanline
  .bpp:         resd 1
  .fb_phys:     resq 1
  .fb_virt:     resq 1
  .caps:        resd 1  ; DISPCAP_*
  .scale_q8:    resd 1  ; UI scale factor *256 (1.0/1.5/2.0/3.0 from res+DPI)
endstruc
DISPCAP_HW_FILL      equ (1 << 0)
DISPCAP_HW_BLIT      equ (1 << 1)
DISPCAP_HW_3D        equ (1 << 2)
DISPCAP_HW_MEDIA     equ (1 << 3)     ; hw JPEG/video decode (igpu vdbox)

struc rect
  .x:  resd 1
  .y:  resd 1
  .w:  resd 1
  .h:  resd 1
endstruc

; ============================================================================
; usb (usb/core.asm — host-controller backend (xhci) + class drivers (MSC/HID/
;      NCM) that register match rules and get enumeration callbacks. The #1
;      duplication-survey finding: usb_control_request is ONE upper-half here,
;      not re-implemented per chip (ax88179/wifi/hid/msc). DRIVER_MODEL.md §1.)
; ============================================================================
struc usbhc_ops                ; host controller (e.g. xhci)
  .init:        resq 1  ; (self) -> RAX 0/-1
  .start:       resq 1  ; (self) -> RAX 0/-1
  .stop:        resq 1  ; (self) -> RAX
  .port_status: resq 1  ; (self,RSI=port) -> RAX status bits
  .control:     resq 1  ; (self,RSI=usb_setup*,RDX=dev_addr) -> RAX len/-1  (THE shared xfer)
  .bulk_in:     resq 1  ; (self,RSI=port,RDX=ep,RCX=buf,R8=len) -> RAX len/-1
  .bulk_out:    resq 1  ; (self,RSI=port,RDX=ep,RCX=buf,R8=len) -> RAX len/-1
  ; Additive Task2903 endpoint seam. `port` is the same backend-neutral address
  ; accepted by .control; the xHCI backend privately resolves it to a slot/DCI.
  .configure_ep:       resq 1 ; (self,RSI=port,RDX=usb_endpoint_desc*) -> RAX 0/-1
  .interrupt_in_queue: resq 1 ; (self,RSI=port,RDX=ep_addr,RCX=exact_len) -> RAX 0/-1
  .interrupt_in_poll:  resq 1 ; (self,RSI=port,RDX=ep_addr,RCX=out,R8=cap,
                                ;  R9=usb_intr_completion*) -> RAX len/-1
  ; Additive usbnic-late-bind seam: NON-BLOCKING bulk IN for asynchronous receivers
  ; (USB NICs). Same ABI as .bulk_in but never waits: RAX = len of a transfer that has
  ; completed (the TRB armed by an earlier call), 0 = nothing yet (TRB stays/gets armed;
  ; poll again next tick), -1 = refused. A NULL entry means the HC has no poll op —
  ; callers fall back to .bulk_in.
  .bulk_in_poll:       resq 1 ; (self,RSI=port,RDX=ep,RCX=buf,R8=cap) -> RAX len/0/-1
  ; Additive HUB0 hub-class seam (usb/enum owns the generic hub class; the
  ; backend owns only the controller-specific slot work). A backend without
  ; hub support points all three at a function returning -1.
  .hub_configure:      resq 1 ; (self,RSI=hub addr,EDX=ports,ECX=TT think time,
                                ;  R8D=MTT selection(0)) -> RAX 0/-1
  .hub_address_child:  resq 1 ; (self,RSI=hub addr,EDX=hub port,ECX=child speed
                                ;  USB_SPEED_*) -> RAX new neutral child addr / <=0
  .topology:           resq 1 ; (self,RSI=addr,RDX=usb_topo*) -> RAX 0/-1
  .configure_ep_ss:    resq 1 ; optional (self,RSI=addr,RDX=endpoint+SS companion,RCX=13 readable bytes) -> 0/-1; SS interrupt IN or non-stream bulk
endstruc

; Backend-neutral topology of one addressed device (HUB0). Speeds use the xHCI
; Protocol Speed IDs: 1 full, 2 low, 3 high, 4 super. route is the USB 3.0 /
; xHCI 20-bit route string (4 bits per hub tier, tier 1 in bits 3:0); depth is
; the number of hubs between the root port and the device (0 = root port).
struc usb_topo
  .slot:        resb 1
  .root:        resb 1  ; one-based root-hub port
  .depth:       resb 1
  .speed:       resb 1
  .parent_slot: resb 1  ; 0 = root port
  .parent_port: resb 1  ; parent hub downstream port (0 = root port)
  .tt_slot:     resb 1  ; LS/FS behind a HS hub: the TT hub's slot, else 0
  .tt_port:     resb 1
  .route:       resd 1
  .hub_ports:   resb 1  ; nonzero once configured as a hub
  .hub_ctx:     resb 1  ; bit0 = controller accepted Hub/ports/TTT; bit1 = Output Slot Context echoes them
  .pci_dev:     resb 1  ; host controller PCI device/function (boot-media match)
  .pci_fn:      resb 1
endstruc
USB_SPEED_FULL       equ 1
USB_SPEED_LOW        equ 2
USB_SPEED_HIGH       equ 3
USB_SPEED_SUPER      equ 4

; Immutable ownership copied out with an accepted interrupt-IN report.  The
; controller fills this before it clears completion ownership and requeues, so
; a class consumer never has to infer slot/cycle/generation from mutable rings.
struc usb_intr_completion
  .slot:       resb 1
  .dci:        resb 1
  .ep_addr:    resb 1
  .cycle:      resb 1
  .generation: resd 1
  .sequence:   resd 1
  .length:     resd 1
endstruc

struc usb_setup                ; the 8-byte SETUP packet (one definition, survey #1)
  .bmRequestType: resb 1
  .bRequest:      resb 1
  .wValue:        resw 1
  .wIndex:        resw 1
  .wLength:       resw 1
endstruc

struc usb_endpoint_desc        ; USB 2.0 9.6.6, byte-exact on-wire form
  .bLength:          resb 1
  .bDescriptorType:  resb 1
  .bEndpointAddress: resb 1
  .bmAttributes:     resb 1
  .wMaxPacketSize:   resw 1
  .bInterval:        resb 1
endstruc

struc usb_match                ; a class driver's enumeration match rule
  .class:       resb 1  ; -1 = wildcard
  .subclass:    resb 1
  .protocol:    resb 1
  .pad:         resb 1
  .probe:       resq 1  ; (dev_desc*,iface*) -> RAX 0 claimed / -1 not mine
endstruc

; ============================================================================
; REGISTRATION + DISPATCH CONTRACT (uniform across classes — DRIVER_MODEL §5)
;
;   Each class core (net/netdev.asm, fs/blockdev.asm, ...) exports:
;     <class>_register(self)   ; RDI=struct dev*. Validates DRIVER_ABI_VERSION,
;                              ; checks .ops/.info non-null, links on the registry
;                              ; ordered by .prio. -> RAX REG_OK / REG_REJECT.
;     <class>_deregister(self) ; unlink; called by degrade() when a backend dies.
;   The core SELECTS, per device/route, the highest-.prio backend whose
;   .health == HEALTH_OK, and calls ops through .ops. On a bounded-retry failure
;   it runs .recover; on exhaustion sets HEALTH_DEAD, deregisters, and the next
;   boot's domain backend (lower prio) takes over (native->domain fallback, §6).
;
;   This registration edge is L3-backend -> L4-core, i.e. an UPWARD call through
;   a fixed export — the ONE sanctioned exception to downward-only (CRITIQUE:
;   modlint can't trace it; it's whitelisted as the register/callback edge).
;
;   VERIFICATION: each class ships a FAKE backend (loopnet / ramblk / nullsnd)
;   that is BOTH the QEMU-no-hardware regression target AND the reference
;   implementation of this contract (DRIVER_MODEL §7). Write the fake first; it
;   documents the ops semantics the chip backends must match.
; ============================================================================

%endif ; DRIVER_CLASSES_INC
