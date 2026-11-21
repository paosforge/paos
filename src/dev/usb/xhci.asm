;; MODULE dev/usb/xhci
;; LAYER 3
;; EXPORTS xhci_legacy_observations, xhci_terminal_firmware_observations, xhci_terminal_quiesce, xhci_terminal_observations, xhci_discard_owner_at, xhci_power_iso_guard, xhci_power_iso_observations, xhci_power_command_guard, xhci_power_command_observations, xhci_storage_bdf, xhci_device_root_power_cycle, xhci_device_root_retire, xhci_readiness_snapshot, xhci_iso_fs_stop, xhci_iso_fs_error_scalar, xhci_iso_fs_stream_queue, xhci_iso_fs_stream_poll, xhci_iso_fs_stream_close, xhci_iso_fs_burst_queue, xhci_iso_fs_burst_poll, xhci_iso_fs_configure, xhci_iso_fs_queue, xhci_iso_fs_poll, xhci_hub_port_available, xhci_hc_generation, xhci_hid_child_connected, xhci_get_init_receipt, xhci_hid_root_retire, xhci_usb_selftest, xhci_get_maxports, xhci_read_portsc, xhci_hub_child_last, xhci_airlock_fault, xhci_airlock_status, xhci_interrupt_set_reset_hook, xhci_found, xhci_preservation_snapshot
;; IMPORTS usb/enum, bus/pci, bus/hal, core/dma, core/heap, core/time, boot/serial, boot/paging, bus/pci_claim
;; CAPS mmio dma
;; OWNER saga:usb

; Attached profile keeps topology/resources fixed. Gates precede scratch,
; instance swaps, report consumption, DMA publication and MMIO effects.
%macro XHCI_POWER_GATE 1
    push rax
%if %1 = 1
    cmp qword [rel reinit_power_xhci_context], 0
    jne %%deny
%else
%if %1 = 2
    cmp qword [rel reinit_power_xhci_context], 0
    je %%legacy
    lea rax, [rel xhci_hcdev]
    cmp rdi, rax
    jne %%deny
%%legacy:
%endif
    call reinit_power_xhci_gate
    test rax, rax
    jnz %%deny
%endif
    pop rax
    jmp %%ok
%%deny:
    pop rax
    mov rax, -1                     ; port-status unavailable retains CONNECT
    ret
%%ok:
%endmacro
%include "core/abi/wdata.inc"
%include "core/abi/pci_claim.inc" ; RCQ-29 hardware report: bind outcome ids/states
%include "dev/usb/hp_usb184_lab_profile.inc"
%include "dev/usb/hp_ep0_witness_lab_profile.inc"
; ============================================================================
; dev/usb/xhci.asm — the NATIVE xHCI USB host-controller backend (contract 1031),
; registered behind the usb/enum seam (driver_classes.inc usbhc_ops) at PRIO_NATIVE
; so the enum core prefers it over the usb_nulldev software fake. This is a PORT of
; the proven bring-up in ../../paos/drivers/xhci/source/{xhci_detect,xhci_init,
; xhci_ports}.asm (which RAN on the Lenovo M720s) adapted to the rework seam:
; bus/pci discovery, core/dma rings, bus/hal MMIO gate, the usbhc_ops vtable.
;
; WHAT IT SHIPS (QEMU controller content-grade; real descriptor read bare-metal-owed):
;   xhci_usb_selftest: PCI class-code detect (0x0C/0x03/0x30) -> BAR0 map + bus-master
;   -> USB Legacy handoff (xECP cap 1) -> HCRST reset + wait CNR -> DCBAA + command ring
;   + event ring (ERST) in core/dma -> MaxSlotsEn -> USBCMD.R/S run. When the controller
;   reaches RUNNING (USBSTS.HCH==0) it emits xhci.controller.up and registers as a
;   usbhc backend (root-hub port count -> dev.flags). The generic enum core then port-
;   scans + issues the shared GET_DESCRIPTOR control transfer through .control.
;
;   .port_status(self, port)  -> real PORTSC CCS/PED read, mapped to USB_PORT_*.
;   .control(self, setup, port, buf, cap) -> per-port lazy addressing (port reset ->
;       Enable Slot -> Address Device, retained in bounded port/slot maps) then a
;       SETUP/DATA/STATUS transfer on that slot's private EP0 ring.
;
; FAULT RULE (driver_classes.inc §1): every poll is BOUNDED (tsc budget or spin
; count). No controller / a stuck ring / a NAKing device DEGRADES — the marker just
; doesn't fire and the enum core skips the slot; the boot never hangs.
;
; The `call usb_hc_register` is the sanctioned L3->L4 upward register edge.
;
; STORE_OUT_OF_DATE(task2901): the read-only Classic driver-store ESSENCE still
; describes the Task1031 endpoint surface. Follow-up owner: the next authorized
; usb_stack driver-store synchronization transaction must mirror this landed
; shared interrupt/bulk endpoint-ring, generation, and filtered-event contract
; before the first bulk class consumer is shipped.
;
; BARE-METAL NOTE: MMIO here must be UNCACHEABLE for doorbell writes to reach the
; controller (proven-source gotcha). QEMU is cache-transparent so the CI rung is
; unaffected; the bare-metal UC-map is the same latent precondition dev/net/e1000e
; carries and is owed with the supervised deploy-rework.
; ============================================================================

; --- capability registers (BAR0-relative) ---
XHCI_CAPLENGTH    equ 0x00       ; byte
XHCI_HCSPARAMS1   equ 0x04       ; [7:0]=MaxSlots, [31:24]=MaxPorts
XHCI_HCSPARAMS2   equ 0x08       ; max scratchpad buffers split across Hi/Lo fields
XHCI_HCCPARAMS1   equ 0x10       ; bit2=CSZ, [31:16]=xECP dword offset
XHCI_DBOFF        equ 0x14       ; doorbell array byte offset (& ~0x3)
XHCI_RTSOFF       equ 0x18       ; runtime register byte offset (& ~0x1F)

; --- operational registers (op_base = BAR0 + CAPLENGTH) ---
XHCI_USBCMD       equ 0x00       ; bit0=R/S, bit1=HCRST, bit2=INTE
XHCI_USBSTS       equ 0x04       ; bit0=HCH, bit2=HSE, bit11=CNR, bit12=HCE
XHCI_CRCR         equ 0x18       ; 64-bit; bit0=RCS
XHCI_CRCR_CA      equ (1 << 2)   ; Command Abort (write while running; pointer bits ignored)
XHCI_CRCR_CRR     equ (1 << 3)   ; Command Ring Running (RO)
XHCI_DCBAAP       equ 0x30       ; 64-bit
XHCI_CONFIG       equ 0x38       ; [7:0]=MaxSlotsEn
XHCI_PORTSC_BASE  equ 0x400      ; port 1; port n = +((n-1)*0x10)

XHCI_USBCMD_RS    equ (1 << 0)
XHCI_USBCMD_HCRST equ (1 << 1)
XHCI_USBCMD_INTE  equ (1 << 2)
XHCI_USBSTS_HCH   equ (1 << 0)
XHCI_USBSTS_HSE   equ (1 << 2)
XHCI_USBSTS_CNR   equ (1 << 11)
XHCI_USBSTS_HCE   equ (1 << 12)

; --- runtime registers (rt_base = BAR0 + RTSOFF), interrupter 0 ---
XHCI_IMAN         equ 0x20       ; bit0=IP(RW1C), bit1=IE
XHCI_ERSTSZ       equ 0x28
XHCI_ERSTBA       equ 0x30       ; 64-bit
XHCI_ERDP         equ 0x38       ; 64-bit; bit3=EHB

; --- PORTSC bits ---
XHCI_PORTSC_CCS   equ (1 << 0)   ; current connect status
XHCI_PORTSC_PED   equ (1 << 1)   ; port enabled (RW1C!)
XHCI_PORTSC_PR    equ (1 << 4)   ; port reset
XHCI_PORTSC_PRC   equ (1 << 21)  ; port reset change (RW1C)
XHCI_PORTSC_RW1C  equ 0x00FE0002 ; change bits + PED — AND ~ before OR'ing (RW1C hazard)
XHCI_PORTSC_PP    equ (1 << 9)   ; port power (RWS when HCCPARAMS1.PPC=1)
; PORTSC field attributes (xHCI 1.2 sec. 5.4.8): keep RO (0,3,10:13,30) and RWS (5:8,9,14:15,25:27);
; drop RW1C/RW1CS (1,17:23), RW1S (4, 31), RW (16) and RsvdZ (2,24,28:29).
XHCI_PORTSC_NEUTRAL equ 0x4E00FFE9
XHCI_HCC_PPC      equ (1 << 3)   ; HCCPARAMS1.PPC: ports have power switches
XHCI_PP_SETTLE_US equ 20000      ; xHCI 1.2 sec. 5.4.8 PP: with PPC=1 software waits 20 ms
XHCI_PP_READBACK  equ 10         ; PP read-back polls per port, 1 ms apart (bounded)
XHCI_PORTSC_SPEED_SH equ 10
XHCI_PORTSC_SPEED_MASK equ 0x0F

; --- TRB types (control DWORD bits [15:10]) ---
XHCI_TRB_NORMAL   equ 1
XHCI_TRB_SETUP    equ 2
XHCI_TRB_DATA     equ 3
XHCI_TRB_STATUS   equ 4
XHCI_TRB_ISOC     equ 5
XHCI_TRB_LINK     equ 6
XHCI_TRB_ENABLE_SLOT equ 9
XHCI_TRB_ADDRESS_DEVICE equ 11
XHCI_TRB_EVALUATE_CONTEXT equ 13
XHCI_TRB_CONFIGURE_ENDPOINT equ 12
XHCI_TRB_XFER_EVENT equ 32
XHCI_TRB_CMD_COMPLETION equ 33
XHCI_TRB_PORT_STATUS_CHANGE equ 34 ; xHCI 1.2 Table 6-91; Port ID = dword0[31:24] (6.4.2.3)
XHCI_TRB_RESET_ENDPOINT equ 14
XHCI_TRB_SET_TR_DEQUEUE equ 16
XHCI_TRB_NOOP_CMD equ 23          ; No Op Command (ring-control owner only, F.3.4)
XHCI_CC_SUCCESS   equ 1
XHCI_CC_CMD_RING_STOPPED equ 24   ; E5r: Command Ring Stopped (t:5165-5172)
XHCI_EVT_RING_CONTROL equ 0x40    ; evt_wait EDI: the ring-control owner (no TRB type is >= 64)
XHCI_EP_STATE_HALTED equ 2

; --- sizes / limits ---
XHCI_RING_TRBS    equ 256        ; 256 * 16 = 4096 per ring
XHCI_RING_BYTES   equ 4096
XHCI_MAX_SLOTS_EN equ 8          ; we enable up to 8 slots (enumeration breadth)
XHCI_SLOT_COUNT   equ (XHCI_MAX_SLOTS_EN + 1) ; slot zero is reserved
XHCI_PORT_COUNT   equ 256        ; root-hub port number is eight bits
; HUB0: a device behind an external hub has no root-port number of its own. Its
; backend-neutral address is a token above every live root port, bound 1:1 to
; its controller slot (token = base + slot) and published only after Address
; Device succeeds. Tokens share the bounded port/slot maps and so every existing
; endpoint/control op resolves them exactly like a root port.
XHCI_CHILD_ADDR_BASE  equ 0xC0
XHCI_CHILD_ADDR_LIMIT equ (XHCI_CHILD_ADDR_BASE + XHCI_SLOT_COUNT)
XHCI_TRB_DISABLE_SLOT equ 10
XHCI_OUT_CTX_STRIDE equ 2048     ; 32 contexts * max 64-byte CSZ, per slot
; One controller's DMA set (RCQ-09 slice 2), the layout of the static buffers.
XHCI_DS_CMD       equ 0x1000
XHCI_DS_EVT       equ 0x2000
XHCI_DS_ERST      equ 0x3000
XHCI_DS_IN        equ 0x4000
XHCI_DS_OUT       equ XHCI_DS_IN + XHCI_MAX_SLOTS_EN * 0x1000
XHCI_DS_EP0       equ XHCI_DS_OUT + XHCI_MAX_SLOTS_EN * XHCI_OUT_CTX_STRIDE
XHCI_DS_SCR       equ XHCI_DS_EP0 + XHCI_MAX_SLOTS_EN * 0x1000
XHCI_DS_BYTES     equ XHCI_DS_SCR + 0x1000
XHCI_SCRATCH_MAX  equ 128        ; proven source's bounded static pointer-array capacity
XHCI_CMD_BUDGET_US equ 300000    ; 300 ms per transfer completion poll (bounded)
XHCI_CMD_WAIT_US   equ 1000000   ; 1 s per COMMAND completion (Address Device to a slow device)

; Task2903's two interrupt-IN owners are the first half of each slot-local
; transfer slice. Task2901 adds one bulk-IN and one bulk-OUT owner in the same
; table/router instead of creating a second endpoint path. Thirty-one producer
; TRBs plus one Link TRB cover a 1024-byte transfer segmented at full-speed's
; 64-byte bulk MPS, including TDs that cross the Link TRB.
XHCI_INTR_PER_SLOT    equ 2
XHCI_BULK_PER_SLOT    equ 2
XHCI_ISO_PER_SLOT     equ 2
%if PAOS_LAB_HP_USB184_POOL
XHCI_XFER_PER_SLOT    equ (XHCI_INTR_PER_SLOT + XHCI_BULK_PER_SLOT)
%else
XHCI_XFER_PER_SLOT    equ (XHCI_INTR_PER_SLOT + XHCI_BULK_PER_SLOT + XHCI_ISO_PER_SLOT)
%endif
XHCI_INTR_STATE_COUNT equ (XHCI_MAX_SLOTS_EN * XHCI_XFER_PER_SLOT)
XHCI_INTR_RING_TRBS   equ 64         ; usbnic-late-bind: 2048-byte TD @ full-speed mps=64 = 32 TRBs (+link)
XHCI_INTR_RING_BYTES  equ (XHCI_INTR_RING_TRBS * 16)
XHCI_INTR_RING_ALIGN  equ 64         ; native ring contract; independent of bounce alignment
XHCI_BULK_LARGE_BYTES equ 49152      ; AX88179B bounded RX aggregate (fits u16 exact_len)
XHCI_BULK_LARGE_ALIGN equ 65536      ; one Normal TRB never crosses a 64KiB boundary
XHCI_INTR_REPORT_BYTES equ 2048       ; usbnic-late-bind: was 1024 -> a 1514-byte Ethernet frame (STATUS reply) was REFUSED on bulk OUT
XHCI_INTR_DRAIN_BUDGET equ 16
%if PAOS_LAB_HP_USB184_POOL
XHCI_INTR_DMA_ALIGN    equ 64   ; historical pre-ISO pool, ISO configure refused
%else
XHCI_INTR_DMA_ALIGN    equ 2048 ; each bounce extent divides64KiB, single FS ISO TRB cannot cross it
%endif
XHCI_XFER_DMA_BYTES    equ (XHCI_INTR_STATE_COUNT * (XHCI_INTR_RING_BYTES + XHCI_INTR_REPORT_BYTES))

struc xhci_intr_ep
  .active:             resb 1
  .configured:         resb 1
  .pending:            resb 1
  .completed:          resb 1
  .slot:               resb 1
  .dci:                resb 1
  .ep_addr:            resb 1
  .attributes:         resb 1
  .interval:           resb 1
  .ss_burst:           resb 1       ; zero USB2/bulk; SS companion bMaxBurst
  .mps:                resw 1
  .exact_len:          resw 1
  .segments:           resw 1
  .ss_payload:         resw 1       ; zero USB2/bulk, explicit SS Max ESIT payload
  .pad_ss:             resw 2       ; ISO burst index/left: preserve their offsets
  .report_capacity:    resw 1       ; 0 = default 2KiB, otherwise large bulk-IN extent
  .enqueue:            resd 1
  .pcs:                resd 1
  .generation:         resd 1
  .pending_generation: resd 1
  .pending_cycle:      resd 1
  .completed_len:      resd 1
  .completed_generation: resd 1
  .completed_cycle:    resd 1
  .completion_sequence: resd 1
  .pending_trb:        resq 1
  .pending_first_trb:  resq 1
  .pending_first_cycle: resd 1
  .ring:               resq 1
  .report:             resq 1
endstruc

; ---------------------------------------------------------------------------
; MMIO helpers through the HAL bounds gate (never a raw mov [mmio]).
; xh_rd(RSI = BAR0 byte offset) -> EAX. clobbers RAX,RDI.
; xh_wr(RSI = BAR0 byte offset, EDX = value). clobbers RAX,R9,RDI.
; ---------------------------------------------------------------------------
xh_rd:
    lea  rdi, [rel xhci_region]
    call hal_mmio_read32
    ret
xh_wr:
    lea  rdi, [rel xhci_region]
    call hal_mmio_write32
%if PAOS_LAB_HP_USBCMD_PROVENANCE
    ; CF is xh_wr's only result its callers read (flag census, SEC109398 (2)):
    ; a refusal returns CF=1 untouched, an accepted write records and returns CF=0.
    jc .lab_done
    call xhci_lab_usbcmd_record
    clc
.lab_done:
%endif
    ret

%if PAOS_LAB_HP_USBCMD_PROVENANCE
; Accepted 32-bit USBCMD writes only. No additional MMIO, IF change or serial.
; xh_wr's call frame puts its caller at [rsp+8]. RDX/RSI and every register
; outside xh_wr's declared clobbers remain unchanged; flags are not preserved.
xhci_lab_usbcmd_record:
    mov eax,[rel xhci_op]
    cmp rsi,rax
    jne .out
    mov eax,[rel xhci_inst_cur]
    cmp eax,XHCI_INST_MAX
    jae .out
    imul eax,eax,400
    lea r9,[rel xhci_lab_usbcmd_history]
    add r9,rax
    mov rdi,[r9+8]
    cmp rdi,8
    jae .out
    imul rdi,rdi,48
    lea rdi,[r9+rdi+16]
    push rdx
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [rdi],rax
    mov rax,[rsp+16]                ; caller, above saved RDX and xh_wr's return
    mov [rdi+8],rax
    pop rdx
    mov rax,[rel xhci_region]
    mov [rdi+16],rax
    mov [rdi+24],rsi
    mov eax,edx
    mov [rdi+32],rax
    mov eax,[rel xhci_generation]
    mov [rdi+40],rax
    mov rax,[r9+8]
    inc eax
    and eax,7
    mov [r9+8],rax
    cmp qword [r9],-1
    je .out
    inc qword [r9]
.out:
    ret
%endif

; xh_wr64(RSI = offset, RDX = 64-bit value) — low dword then high dword. clobbers RAX,R9,RDI,RCX.
xh_wr64:
    push rdx
    mov  ecx, edx                    ; low 32
    push rsi
    mov  edx, ecx
    call xh_wr
    pop  rsi
    pop  rdx
    add  rsi, 4
    mov  rax, rdx
    shr  rax, 32
    mov  edx, eax
    call xh_wr
    ret

; ---------------------------------------------------------------------------
; xhci_pci_cb — pci_scan_with_filter callback (EDI=bus,ESI=dev,EDX=fn,ECX=vendev).
;   Records every xHCI function (class 0C0330), in PCI order, as a selection
;   candidate (at most XHCI_CAND_MAX; later functions are ignored, bounded).
;   xhci_select_controller then chooses the one that actually has the devices
;   (RCQ-09: AMD boxes such as the Reatan expose four xHCIs and laptops two or
;   more; the keyboard and the GLKVM may sit on any of them).
;   Must preserve RBX,RBP,R12-R15 (scan-loop state). clobbers RAX,RCX,R8..R11.
; ---------------------------------------------------------------------------
XHCI_CAND_MAX        equ 8
XHCI_CAND_SZ         equ 32
XC_BUS               equ 0
XC_DEV               equ 4
XC_FN                equ 8
XC_VENDEV            equ 12
XC_BAR               equ 16
XC_CONN              equ 24      ; connected root ports, -1 = not probeable
XC_PORTS             equ 28      ; MaxPorts read (0 = not probed)
XHCI_PROBE_PORTS_MAX equ 32      ; root ports read per candidate (bounded)
XHCI_PROBE_APERTURE  equ 0x10000 ; caps + operational + 256 ports fit in 64 KiB
xhci_pci_cb:
    XHCI_POWER_GATE 1
    mov  r10d, ecx                   ; retain vendev across class cfg read
    push rdi
    push rsi
    push rdx
    ; read class register (offset 0x08): [31:24]=class,[23:16]=sub,[15:8]=progif
    mov  ecx, 0x08
    call pci_cfg_read32
    mov  r8d, eax
    shr  r8d, 8
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  r8d, 0x0C0330               ; class 0C sub 03 progif 30 (xHCI)
    jne  .done
    mov  eax, [rel xhci_cand_n]
    cmp  eax, XHCI_CAND_MAX
    jae  .done
    imul eax, eax, XHCI_CAND_SZ
    lea  r8, [rel xhci_cand]
    add  r8, rax
    mov  [r8 + XC_BUS], edi
    mov  [r8 + XC_DEV], esi
    mov  [r8 + XC_FN], edx
    mov  [r8 + XC_VENDEV], r10d
    mov  qword [r8 + XC_BAR], 0
    mov  dword [r8 + XC_CONN], -1
    mov  dword [r8 + XC_PORTS], 0
    inc  dword [rel xhci_cand_n]
.done:
    ret

; ---------------------------------------------------------------------------
; xhci_probe_candidate(EDI = candidate index) -> EAX connected root ports, or
;   -1 when the controller cannot be read. No reset, no ownership handoff, no
;   Bus Master. It reads the firmware-assigned BAR only when it is reachable
;   through the identity map (the same < 16 GiB / paging_xhci_bar_mapped rule
;   the bring-up uses). Memory decode can be off after ExitBootServices: then
;   Memory Space alone is set for the probe and the command register is
;   restored exactly. It reads CAPLENGTH, HCSPARAMS1 and at most
;   XHCI_PROBE_PORTS_MAX PORTSC.CCS bits (an unpowered port reads CCS=0). An
;   all-ones read ends the probe.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_probe_candidate:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    imul eax, edi, XHCI_CAND_SZ
    lea  r12, [rel xhci_cand]
    add  r12, rax
    mov  edi, [r12 + XC_BUS]
    mov  esi, [r12 + XC_DEV]
    mov  edx, [r12 + XC_FN]
    mov  ecx, 0x04
    call pci_cfg_read32
    mov  [rel xhci_probe_cmd], eax   ; restored on every exit
    mov  dword [rel xhci_probe_cmd_set], 0
    mov  edi, [r12 + XC_BUS]
    mov  esi, [r12 + XC_DEV]
    mov  edx, [r12 + XC_FN]
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r13d, eax                   ; BAR0
    test r13d, 1
    jnz  .unprobeable                ; an I/O BAR is not xHCI MMIO
    xor  r14d, r14d
    mov  eax, r13d
    and  eax, 0x06
    jz   .bar_assembled              ; 32-bit BAR
    cmp  eax, 0x04
    jne  .unprobeable                ; reserved/legacy type
    mov  edi, [r12 + XC_BUS]
    mov  esi, [r12 + XC_DEV]
    mov  edx, [r12 + XC_FN]
    mov  ecx, 0x14
    call pci_cfg_read32
    mov  r14d, eax                   ; BAR1 = high dword of a 64-bit BAR
.bar_assembled:
    mov  rbx, r14
    shl  rbx, 32
    and  r13d, 0xFFFFFFF0
    or   rbx, r13
    test rbx, rbx
    jz   .unprobeable                ; unassigned
    mov  [r12 + XC_BAR], rbx
    mov  rax, 0x400000000            ; 16 GiB: below it the identity map covers the BAR
    cmp  rbx, rax
    jb   .mapped
    mov  rdi, rbx
    call paging_xhci_bar_mapped
    test eax, eax
    jz   .unprobeable                ; not mapped: reading it would fault
.mapped:
    test dword [rel xhci_probe_cmd], 0x02
    jnz  .decoding                   ; firmware left memory decode on
    ; Decode can be off after ExitBootServices. Set Memory Space only (never
    ; Bus Master: the probe starts no DMA) for the read, restore it after.
    mov  r8d, [rel xhci_probe_cmd]
    and  r8d, 0xFFFF                 ; command only; status bits are RW1C
    or   r8d, 0x02
    mov  edi, [r12 + XC_BUS]
    mov  esi, [r12 + XC_DEV]
    mov  edx, [r12 + XC_FN]
    mov  ecx, 0x04
    call pci_cfg_write32
    mov  dword [rel xhci_probe_cmd_set], 1
.decoding:
    mov  [rel xhci_region + HAL_R_BAR_BASE], rbx
    mov  qword [rel xhci_region + HAL_R_BAR_SIZE], XHCI_PROBE_APERTURE
    mov  esi, XHCI_CAPLENGTH
    call xh_rd
    cmp  eax, 0xFFFFFFFF
    je   .unreadable
    and  eax, 0xFF
    cmp  eax, 0x20
    jb   .unreadable                 ; CAPLENGTH covers at least the capability block
    mov  r13d, eax                   ; operational base
    mov  esi, XHCI_HCSPARAMS1
    call xh_rd
    cmp  eax, 0xFFFFFFFF
    je   .unreadable
    shr  eax, 24                     ; MaxPorts
    test eax, eax
    jz   .unreadable
    cmp  eax, XHCI_PROBE_PORTS_MAX
    jbe  .ports
    mov  eax, XHCI_PROBE_PORTS_MAX
.ports:
    mov  [r12 + XC_PORTS], eax
    mov  r14d, eax                   ; ports to read
    xor  r15d, r15d                  ; port index
    xor  ebx, ebx                    ; connected
.port:
    cmp  r15d, r14d
    jae  .counted
    mov  esi, r15d
    shl  esi, 4
    add  esi, r13d
    add  esi, XHCI_PORTSC_BASE
    call xh_rd
    cmp  eax, 0xFFFFFFFF
    je   .unreadable                 ; the function went away mid-probe
    test eax, XHCI_PORTSC_CCS
    jz   .next_port
    inc  ebx
.next_port:
    inc  r15d
    jmp  .port
.counted:
    mov  [r12 + XC_CONN], ebx
    mov  eax, ebx
    jmp  .restore
.unreadable:
    mov  dword [r12 + XC_CONN], -1
    mov  eax, -1
.restore:
    mov  qword [rel xhci_region + HAL_R_BAR_BASE], 0
    mov  qword [rel xhci_region + HAL_R_BAR_SIZE], 0
    cmp  dword [rel xhci_probe_cmd_set], 1
    jne  .out
    push rax
    mov  r8d, [rel xhci_probe_cmd]
    and  r8d, 0xFFFF                 ; the firmware's command value, decode off again
    mov  edi, [r12 + XC_BUS]
    mov  esi, [r12 + XC_DEV]
    mov  edx, [r12 + XC_FN]
    mov  ecx, 0x04
    call pci_cfg_write32
    mov  dword [rel xhci_probe_cmd_set], 0
    pop  rax
    jmp  .out
.unprobeable:
    mov  dword [r12 + XC_CONN], -1
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_select_controller — choose ONE controller from the recorded candidates
;   (slice 1; every candidate becomes its own backend in slice 2):
;   1. a controller with a connected root port; among those the Alder Lake PCH
;      8086:51ED (Beelink: its GLKVM is routed through 51ED although 461E is
;      first and may also have a device), otherwise the first in PCI order;
;   2. nobody connected (or nothing probeable): the historical rule, 51ED if
;      present, else the first xHCI.
;   Sets xhci_bus/dev/fn/found/preferred_51ed and emits one
;   [usb.xhci.select] marker (every candidate: bdf, vendev, connected ports or
;   na; the chosen index and the rule). clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_select_controller:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  dword [rel xhci_cand_n], 0
    je   .out                        ; no candidate recorded: keep what is already known
    mov  dword [rel xhci_found], 0   ; (0 at boot; host fixtures that bypass the PCI
    mov  dword [rel xhci_preferred_51ed], 0  ; callback pre-set the controller)
    xor  r12d, r12d                  ; candidate index
    mov  r13d, -1                    ; chosen connected candidate
    mov  r14d, -1                    ; first 51ED candidate
.probe:
    cmp  r12d, [rel xhci_cand_n]
    jae  .choose
    mov  edi, r12d
    call xhci_probe_candidate
    mov  r15d, eax                   ; connected ports or -1
    imul ebx, r12d, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    add  rbx, rcx                    ; candidate record
    cmp  dword [rbx + XC_VENDEV], 0x51ED8086
    jne  .not_pch
    cmp  r14d, -1
    jne  .not_pch
    mov  r14d, r12d
.not_pch:
    test r15d, r15d
    jle  .next                       ; nothing connected, or not probeable
    cmp  r13d, -1
    je   .take
    cmp  dword [rbx + XC_VENDEV], 0x51ED8086
    jne  .next                       ; only the PCH may supersede the first connected
.take:
    mov  r13d, r12d
.next:
    inc  r12d
    jmp  .probe
.choose:
    lea  r15, [rel str_xsel_rule_connected]
    cmp  r13d, -1
    jne  .set
    lea  r15, [rel str_xsel_rule_fallback]
    mov  r13d, r14d                  ; historical preference: the PCH 51ED ...
    cmp  r13d, -1
    jne  .set
    xor  r13d, r13d                  ; ... else the first xHCI
    cmp  dword [rel xhci_cand_n], 0
    je   .marker                     ; no xHCI at all: xhci_found stays 0
.set:
    mov  [rel xhci_sel_chosen], r13d
    imul ebx, r13d, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    add  rbx, rcx
    mov  eax, [rbx + XC_BUS]
    mov  [rel xhci_bus], eax
    mov  eax, [rbx + XC_DEV]
    mov  [rel xhci_dev], eax
    mov  eax, [rbx + XC_FN]
    mov  [rel xhci_fn], eax
    mov  dword [rel xhci_found], 1
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    call xhci_lab_cfgw_arm           ; before the chosen function's first config write
%endif
    cmp  dword [rbx + XC_VENDEV], 0x51ED8086
    jne  .marker
    mov  dword [rel xhci_preferred_51ed], 1
.marker:
    cmp  dword [rel xhci_cand_n], 0
    je   .out                        ; no controller: enum prints its own skip line
    lea  rdi, [rel str_xsel_head]
    call serial_string
    mov  edi, [rel xhci_cand_n]
    call serial_decimal
    xor  r12d, r12d
.emit:
    cmp  r12d, [rel xhci_cand_n]
    jae  .emitted
    imul ebx, r12d, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    add  rbx, rcx
    lea  rdi, [rel str_xsel_c]
    call serial_string
    mov  edi, r12d
    call serial_decimal
    mov  dil, '='
    call serial_char
    mov  edi, [rbx + XC_BUS]
    mov  esi, 2
    call xhci_sel_hex
    mov  dil, ':'
    call serial_char
    mov  edi, [rbx + XC_DEV]
    mov  esi, 2
    call xhci_sel_hex
    mov  dil, '.'
    call serial_char
    mov  edi, [rbx + XC_FN]
    mov  esi, 1
    call xhci_sel_hex
    mov  dil, ','
    call serial_char
    movzx edi, word [rbx + XC_VENDEV]   ; vendor
    mov  esi, 4
    call xhci_sel_hex
    mov  dil, ':'
    call serial_char
    movzx edi, word [rbx + XC_VENDEV + 2] ; device
    mov  esi, 4
    call xhci_sel_hex
    lea  rdi, [rel str_xsel_conn]
    call serial_string
    mov  edi, [rbx + XC_CONN]
    cmp  edi, -1
    jne  .conn_n
    lea  rdi, [rel str_xsel_na]
    call serial_string
    jmp  .emit_next
.conn_n:
    call serial_decimal
.emit_next:
    inc  r12d
    jmp  .emit
.emitted:
    lea  rdi, [rel str_xsel_chosen]
    call serial_string
    mov  edi, r13d
    call serial_decimal
    lea  rdi, [rel str_xsel_rule]
    call serial_string
    mov  rdi, r15
    call serial_string
    lea  rdi, [rel str_xsel_tail]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

xhci_sel_hex:                        ; EDI value, ESI digits (1..8) -> lowercase hex. clobbers: caller-saved
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, esi
    mov  ecx, 8
    sub  ecx, esi
    shl  ecx, 2
    shl  ebx, cl                     ; the wanted digits to the top
.digit:
    rol  ebx, 4
    mov  eax, ebx
    and  eax, 0x0F
    lea  rcx, [rel str_xsel_hex]
    mov  dil, [rcx + rax]
    call serial_char
    dec  r12d
    jnz  .digit
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_usb_selftest — detect + bring up the controller, register the backend.
;   Emits xhci.controller.up ONLY when the controller reaches RUNNING off live
;   register reads. Missing controller -> silent return (enum prints the skip line).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_usb_selftest:
    XHCI_POWER_GATE 1
    push rbx
    push r12
%if PAOS_LAB_HP_USB184_POOL
    lea  rdi, [rel str_xhci_lab_pool184]
    call serial_string
%endif
    call xhci_acpi_mode_early        ; ACPI mode before any xHCI selection/handoff
%if PAOS_LAB_HP_EARLY_ACPI
    call xhci_lab_early_acpi         ; lab: early rc (EAX) + XHCIACPI early line
%endif
    ; --- 1. find the xHCI controller(s) on the PCI bus, pick the one with devices ---
    mov  dword [rel xhci_init_receipt], 0 ; no selected attempt yet
    mov  dword [rel xhci_cand_n], 0
    lea  rdi, [rel xhci_pci_cb]
    call pci_scan_with_filter
    call xhci_select_controller
    mov  dword [rel xhci_inst_n], 0
    mov  dword [rel xhci_inst_cur], 0
    cmp  dword [rel xhci_found], 1
    jne  .no_controller
    ; Snapshot the original selected PCI identity, independent of the live
    ; per-controller image. Later candidates/runtime swaps must not replace it.
    mov  dword [rel xhci_init_receipt], 1
    mov  eax, [rel xhci_bus]
    mov  [rel xhci_init_receipt + 4], eax
    mov  eax, [rel xhci_dev]
    mov  [rel xhci_init_receipt + 8], eax
    mov  eax, [rel xhci_fn]
    mov  [rel xhci_init_receipt + 12], eax
    mov  eax, [rel xhci_sel_chosen]
    imul eax, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    mov  eax, [rcx + rax + XC_VENDEV]
    mov  [rel xhci_init_receipt + 16], eax
    mov  dword [rel xhci_init_receipt + 36], -1 ; registry not attempted
    lea  rdi, [rel xhci_inst_template]  ; pristine per-controller state for later controllers
    call xhci_inst_copy_out
    mov  dword [rel xhci_inst_n], 1
    mov  eax, [rel xhci_sel_chosen]
    mov  [rel xhci_inst_cand], eax
    call xhci_conn_of                    ; EAX candidate -> its probed connected count
    mov  [rel xhci_bring_conn], eax
    mov  edi, 1                          ; the first controller may use the low-RAM relocation
    call xhci_bringup
    ; Save the actual return and last initialization phase before failure
    ; cleanup or another controller can overwrite the live state. No new MMIO.
    mov  [rel xhci_init_receipt + 32], eax
    mov  ecx, [rel xhci_init_hcs2]
    mov  [rel xhci_init_receipt + 20], ecx
    mov  ecx, [rel xhci_init_hcs2_valid]
    mov  [rel xhci_init_receipt + 24], ecx
    mov  ecx, [rel xhci_init_phase]
    mov  [rel xhci_init_receipt + 28], ecx
    test eax, eax
    jnz  .first_failed
    ; RUNNING alone is not an admitted backend. A full enum registry must not
    ; leave the initial controller DMA-capable or publish controller-up/KAT.
    call xhci_register
    mov  [rel xhci_init_receipt + 36], eax ; actual enum admission result, not RUNNING
    test eax, eax
    jnz  .registration_failed
    lea  rdi, [rel xhci_bus]             ; RCQ-29 hardware report: this controller is driven
    mov  ecx, PCI_DRV_XHCI
    mov  r8d, PCI_CLAIM_BOUND
    call pci_claim_bdf3
    ; RUNNING: emit the earned controller-up marker
    mov  byte [rel xhci_m_up], 1
    lea  rdi, [rel str_m_xhci_up]
    call serial_string
    ; The endpoint KAT is deliberately synthetic, so exercise it for every
    ; ordinary QEMU xHCI boot instead of making the regression marker depend on
    ; the optional two-device profile. The profile probe independently proves
    ; that two live descriptors retain distinct slot ownership.
    call xhci_interrupt_in_kat
    call xhci_bulk_kat
    ; RCQ-09 slice 2: every other readable xHCI becomes its own backend.
    call xhci_bring_up_others
    xor  edi, edi
    call xhci_inst_switch                ; the first controller is the live one at rest
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    call xhci_lab_after_others_legacy    ; did the others' bring-up latch its CTLSTS?
%endif
    jmp  .no_controller
.registration_failed:
    lea  rdi, [rel xhci_bus]
    mov  ecx, PCI_DRV_XHCI
    mov  r8d, PCI_CLAIM_FAILED
    call pci_claim_bdf3
    call xhci_discard_live           ; retain actual outcome before registry count drops
    mov  dword [rel xhci_inst_n], 0
    mov  byte [rel xhci_m_up], 0
    jmp  .no_controller              ; full registry cannot admit another candidate
.first_failed:
    lea  rdi, [rel xhci_bus]             ; selected, bring-up failed
    mov  ecx, PCI_DRV_XHCI
    mov  r8d, PCI_CLAIM_FAILED
    call pci_claim_bdf3
    cmp  dword [rel xhci_firmware_ready], 1
    jne  .first_unacquired              ; firmware was never handed to this driver
    call xhci_discard_live               ; retain acquired failure before fallback overwrites it
.first_unacquired:
    mov  dword [rel xhci_inst_n], 0
    call xhci_bring_up_others            ; a failed first choice must not hide healthy HCs
    cmp  dword [rel xhci_inst_n], 0
    je   .no_controller
    xor  edi, edi
    call xhci_inst_switch                ; first successful fallback is backend zero
    mov  byte [rel xhci_m_up], 1
    lea  rdi, [rel str_m_xhci_up]
    call serial_string
    call xhci_interrupt_in_kat
    call xhci_bulk_kat
.no_controller:
    pop  r12
    pop  rbx
    ret

; xhci_acpi_mode_early -> EAX = power_button_ownership rc (0 live owner, -1 not).
;   Enter ACPI mode at boot, before any xHCI scan, selection or BIOS handoff, as
;   Linux and Windows do. HP244 (2026-10-23): with SCI_EN=0 at handoff, the first
;   runtime ownership tick's ACPI_ENABLE ran the HP BIOS handler ~2 s after our
;   handoff and it halted the chipset xHCI; enabling first fixed the keys.
;   The existing ownership does it: FADT admission, SCI route held, one
;   ACPI_ENABLE only if SCI_EN=0 (tsc_khz bounds it), SCI_EN readback. Later
;   ownership ticks then take the live path (state 2): no second hold, no
;   command. Firmware already in ACPI mode gets the hold and no command.
;   Preserves all GPRs except RAX.
xhci_acpi_mode_early:
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call power_button_ownership
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    ret

; ---------------------------------------------------------------------------
; xhci_bringup(EDI = 1 to allow the guarded low-RAM BAR relocation) -> EAX 0
;   running / 1 not. Steps 2-9 of the historical bring-up on the LIVE
;   controller (xhci_bus/dev/fn); only the first controller may relocate its
;   BAR (one 8 GiB window). clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_bringup:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    mov  r12d, edi
    mov  dword [rel xhci_firmware_ready], 0
    mov  dword [rel xhci_init_phase], 1 ; BAR reachability
    mov  dword [rel xhci_init_hcs2], 0
    mov  dword [rel xhci_init_hcs2_valid], 0
    ; --- 2. BAR0/BAR1 -> 64-bit MMIO base ---
    ; Use the UC+NX identity map installed pre-EBS for an ordinary high metal BAR.
    ; QEMU can place its BAR beyond the 512 GiB PDPT; only when the live firmware
    ; inventory proves 8 GiB is above RAM may the historical low-BAR relocation
    ; be used. A real high-RAM host must fail closed rather than alias its RAM.
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r10d, eax                   ; BAR0 (type bits + low base)
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x14
    call pci_cfg_read32
    mov  r11d, eax                   ; BAR1 (high base, for a 64-bit BAR)
    ; assemble base = (BAR1<<32) | (BAR0 & ~0xF)
    mov  eax, r10d
    and  eax, 0xFFFFFFF0
    mov  rbx, r11
    shl  rbx, 32
    or   rbx, rax                    ; rbx = 64-bit base
    ; guard: base >= 16 GiB ?
    mov  rax, 0x400000000            ; 16 GiB
    cmp  rbx, rax
    jb   .bar_ok
    mov  rdi, rbx
    call paging_xhci_bar_mapped
    test eax, eax
    jnz  .bar_ok
    test r12d, r12d
    jz   .fail                       ; only the first controller may be relocated
    mov  rax, 0x200000000            ; 8 GiB relocation window
    cmp  qword [rel inv_top_of_ram], 0
    je   .fail              ; unknown inventory cannot prove safety
    cmp  [rel inv_top_of_ram], rax
    jae  .fail              ; occupied/unknown low window: no PCI write
    ; --- remap: disable MEM decode first ---
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    cmp  eax, -1
    je   .fail                       ; no Command or BAR write from an unavailable read
    and  eax, 0xFFFD                 ; clear MEM, preserve known BME; no Status RW1C request
    mov  r8d, eax
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
    ; write BAR1 (high) then BAR0 (low) = 8 GiB
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x14
    mov  r8d, 0x2                     ; high dword of 8 GiB (0x2_0000_0000)
    call pci_cfg_write32
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x10
    mov  r8d, 0x00000000             ; low dword (type bits are HW read-only)
    call pci_cfg_write32
    mov  rbx, 0x200000000            ; new base = 8 GiB
.bar_ok:
    mov  [rel xhci_region + HAL_R_BAR_BASE], rbx
    mov  qword [rel xhci_region + HAL_R_BAR_SIZE], 0x40000   ; 256 KiB aperture (ports+rt+db)
    mov  dword [rel xhci_init_phase], 2 ; PCI decode / bus mastering
    ; --- 3. PCI Command (0x04) |= MEM | BusMaster ---
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    cmp  eax, -1
    je   .fail                       ; unavailable Command is not permission to enable DMA
    and  eax, 0xFFFF                 ; Command only; no PCI Status RW1C request
    or   eax, 0x02                   ; Memory Space only; do not enable DMA before custody
    mov  r8d, eax
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
    mov  dword [rel xhci_init_phase], 3 ; capability layout / DMA reach
    ; --- 4. read capability layout: op/rt/db bases + MaxSlots/MaxPorts + CSZ ---
    mov  esi, XHCI_CAPLENGTH
    call xh_rd
    and  eax, 0xFF
    mov  [rel xhci_op], eax          ; op base = CAPLENGTH
    mov  esi, XHCI_HCSPARAMS1
    call xh_rd
    mov  ebx, eax                    ; save the full HCSPARAMS1 read
    mov  eax, ebx
    and  eax, 0xFF                   ; MaxSlots (bits [7:0])
    mov  [rel xhci_maxslots], eax
    mov  eax, ebx
    shr  eax, 24
    and  eax, 0xFF                   ; MaxPorts (bits [31:24])
    test eax, eax
    jnz  .ports_ok
    mov  eax, 1
.ports_ok:
    mov  [rel xhci_maxports], eax
    ; The proven Lenovo driver treats this as load-bearing: if HCSPARAMS2
    ; advertises scratchpads, DCBAA[0] must point at an array of page pointers
    ; before R/S is set. Omitting it lets the initial HCH=0 observation race a
    ; later Host System Error, which made AIRLOCKSTATUS report live=0.
    mov  esi, XHCI_HCSPARAMS2
    call xh_rd
    mov  [rel xhci_init_hcs2], eax     ; exact observed register, including non-count bits
    mov  dword [rel xhci_init_hcs2_valid], 1
    mov  ecx, eax
    shr  ecx, 21                    ; HCSPARAMS2[25:21] = count high five bits
    and  ecx, 0x1F
    shl  ecx, 5
    mov  edx, eax
    shr  edx, 27                    ; HCSPARAMS2[31:27] = count low five bits
    and  edx, 0x1F
    or   ecx, edx
    mov  [rel xhci_scratch_count], cx
    mov  esi, XHCI_DBOFF
    call xh_rd
    and  eax, ~0x3
    mov  [rel xhci_db], eax
    mov  esi, XHCI_RTSOFF
    call xh_rd
    and  eax, ~0x1F
    mov  [rel xhci_rt], eax
    mov  esi, XHCI_HCCPARAMS1
    call xh_rd
    mov  ebx, eax
    test ebx, 1                     ; AC64: 64-bit DMA addresses
    jnz  .dma_reach_ok
    mov  rax, [rel xhci_dma_set]
    add  rax, XHCI_DS_TOTAL
    mov  rcx, 0x100000000
    cmp  rax, rcx
    ja   .fail                       ; a heap set above 4 GiB is unreachable without AC64
    ; This failure precedes acquisition: the original caller skips acquired-owner
    ; discard and retains the existing bump allocation without touching firmware.
.dma_reach_ok:
    mov  dword [rel xhci_ctxsz], 32
    test ebx, (1 << 2)              ; CSZ: 1 -> 64-byte contexts
    jz   .ctx32
    mov  dword [rel xhci_ctxsz], 64
.ctx32:
    mov  dword [rel xhci_init_phase], 4 ; legacy handoff
    ; --- 5. USB Legacy handoff (xECP cap ID 1): claim OS ownership, kill BIOS SMI ---
    call xhci_legacy_handoff
    test eax, eax
    jnz  .fail                       ; no reset or acquired-owner cleanup on refusal
    mov  dword [rel xhci_firmware_ready], 1
    ; Enable Bus Master only after the actual native handoff succeeded.
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    cmp  eax, -1
    je   .fail
    or   eax, 0x06
    and  eax, 0xFFFF                 ; no PCI Status RW1C request
    mov  r8d, eax
    mov  edi, [rel xhci_bus]
    mov  esi, [rel xhci_dev]
    mov  edx, [rel xhci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    call xhci_lab_cfgw_handoff_mark  ; later armed-function writes follow this TSC
%endif
%if PAOS_LAB_HP_EARLY_ACPI
    push rdi
    lea  rdi, [rel str_xhci_lab_acpi_handoff]
    call xhci_lab_acpi_line          ; mode state as each controller is handed off
    pop  rdi
%endif
    mov  dword [rel xhci_init_phase], 5 ; halt (reset advances to HCRST/CNR)
    ; --- 6. halt + reset the controller ---
    call xhci_reset
    test eax, eax
    jnz  .fail             ; reset/CNR timed out -> degrade
    mov  dword [rel xhci_init_phase], 8 ; DMA / bounded scratchpads
    ; --- 7. allocate DMA structures (DCBAA, command ring, event ring, ERST) ---
    call xhci_alloc_dma
    test eax, eax
    jnz  .fail             ; OOM -> degrade
    mov  dword [rel xhci_init_phase], 9 ; ring programming
    ; --- 8. program DCBAAP, CRCR, ERSTSZ/ERSTBA/ERDP, MaxSlotsEn ---
    call xhci_program
    mov  dword [rel xhci_init_phase], 10 ; leave HCH
    ; --- 9. run the controller (USBCMD.R/S) + wait HCH clear ---
    call xhci_run
    test eax, eax
    jnz  .fail             ; never left halt -> degrade
    mov  dword [rel xhci_init_phase], 11 ; power / debounce
    ; --- RCQ-09 port power: with HCCPARAMS1.PPC=1, HCRST left every root port
    ;     unpowered (PP=0, so CCS=0); power them before any status decision. ---
    call xhci_port_power
    ; --- port debounce: after HCRST the root-hub ports re-detect connected devices,
    ;     and CCS takes ~100-200 ms to re-assert (USB2 connect debounce). The enum core
    ;     checks CCS BEFORE issuing a control transfer, so give the ports time to settle
    ;     or every port reads "empty" and nothing enumerates. Bounded poll: wait up to
    ;     ~600 ms for ANY port to show CCS=1, then proceed (QEMU asserts instantly -> no
    ;     wall-clock cost there). RCQ-09: skipped when the read-only probe saw no
    ;     connected port AND HCCPARAMS1.PPC=0 (ports always powered, so CCS=0 was real);
    ;     with port power control an unpowered port could hide a device, so it waits. ---
    cmp  dword [rel xhci_bring_conn], 0
    jne  .settle
    mov  esi, XHCI_HCCPARAMS1
    call xh_rd
    test eax, (1 << 3)               ; PPC
    jz   .settled
.settle:
    call xhci_port_settle
.settled:
    mov  dword [rel xhci_init_phase], 12 ; bring-up returned success; registry is separate
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_legacy_handoff -> EAX0 observed acquisition/no-legacy,1 refusal.
; Original1000ms bound and XHCILEG v1 ten fields remain; field8 stays0 because
; firmware's BIOS semaphore is never cleared by software. Every unknown refuses.
; Only actual original request/poll/SMI accesses, no observer reads.
; ---------------------------------------------------------------------------
xhci_legacy_handoff:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 80                    ; original serial fields, unchanged
    xor  eax, eax
    mov  ecx, 10
    mov  rdi, rsp
    rep  stosq
    mov  eax, [rel xhci_inst_cur]
    mov  [rsp], rax
    mov  eax, [rel xhci_bus]
    mov  [rsp + 8], rax
    mov  eax, [rel xhci_dev]
    mov  [rsp + 16], rax
    mov  eax, [rel xhci_fn]
    mov  [rsp + 24], rax
    ; A passive destination cannot grant custody. Unmatched direct calls use
    ; scratch, never a guessed candidate slot or an admission side effect.
    lea  r15, [rel xhci_legacy_scratch]
    mov  r13d, -1
    mov  ecx, [rel xhci_cand_n]
    cmp  ecx, XHCI_CAND_MAX
    ja   .record
    xor  ebx, ebx
    lea  r14, [rel xhci_cand]
.candidate:
    cmp  ebx, ecx
    jae  .record
    mov  eax, [rsp + 8]
    cmp  eax, [r14 + XC_BUS]
    jne  .next_candidate
    mov  eax, [rsp + 16]
    cmp  eax, [r14 + XC_DEV]
    jne  .next_candidate
    mov  eax, [rsp + 24]
    cmp  eax, [r14 + XC_FN]
    jne  .next_candidate
    mov  r13d, ebx
    imul eax, ebx, 160
    lea  r15, [rel xhci_legacy_observations]
    add  r15, rax
    jmp  .record
.next_candidate:
    inc  ebx
    add  r14, XHCI_CAND_SZ
    jmp  .candidate
.record:
    mov  rdi, r15
    xor  eax, eax
    mov  ecx, 20
    rep  stosq
    mov  dword [r15], 3
    mov  dword [r15 + 4], 5
    mov  [r15 + 8], r13d
    mov  dword [r15 + 12], 1        ; default refusal, never unobserved zero success
    mov  dword [r15 + 16], 1
    mov  eax, [rsp]
    mov  [r15 + 20], eax
    mov  eax, [rel xhci_init_phase]
    mov  [r15 + 24], eax
    mov  eax, [rel xhci_generation]
    mov  [r15 + 28], eax
    mov  eax, [rsp + 8]
    mov  [r15 + 32], eax
    mov  eax, [rsp + 16]
    mov  [r15 + 36], eax
    mov  eax, [rsp + 24]
    mov  [r15 + 40], eax
    mov  [r15 + 44], r13d
    mov  rax, [rel xhci_region]
    mov  [r15 + 48], rax
    mov  rax, [rel xhci_region + 8]
    mov  [r15 + 56], rax
    inc  dword [rel xhci_legacy_sequence]
    mov  eax, [rel xhci_legacy_sequence]
    mov  [r15 + 116], eax
    xor  r12d, r12d                 ; completed1ms delays
    mov  dword [r15 + 112], 2       ; HCC unavailable
    mov  esi, XHCI_HCCPARAMS1
    call xh_rd
    mov  [r15 + 64], eax
    jc   .report
    cmp  eax, -1
    je   .report
    or   dword [r15 + 16], 2
    shr  eax, 16
    shl  eax, 2
    mov  [r15 + 68], eax
    mov  ebx, eax
    test ebx, ebx
    jz   .none
    mov  r14d, 50
    mov  dword [r15 + 112], 3       ; chain unavailable/malformed/exhausted
.walk:
    cmp  ebx, 0x20
    jb   .report
    mov  [r15 + 72], ebx
    inc  dword [r15 + 80]
    and  dword [r15 + 16], ~4
    mov  esi, ebx
    call xh_rd
    mov  [r15 + 76], eax
    jc   .report
    cmp  eax, -1
    je   .report
    or   dword [r15 + 16], 4
    mov  ecx, eax
    and  ecx, 255
    test ecx, ecx
    jz   .report
    cmp  ecx, 1
    je   .found
    shr  eax, 8
    and  eax, 255
    test eax, eax
    jz   .none
    shl  eax, 2
    add  ebx, eax
    dec  r14d
    jnz  .walk
    jmp  .report
.found:
    or   dword [r15 + 16], 8
    lea  rdx, [rbx + 8]
    cmp  rdx, [rel xhci_region + HAL_R_BAR_SIZE]
    ja   .report
    mov  [rsp + 32], rbx
    mov  qword [rsp + 72], 1
    mov  dword [r15 + 112], 4       ; OS request unavailable
    or   eax, 1 << 24              ; preserve BIOS-owned, never force it clear
    mov  [r15 + 92], eax
    mov  edx, eax
    mov  esi, ebx
    call xh_wr
    mov  [r15 + 124], eax           ; actual HAL return, MOV preserves CF
    jc   .report
    or   dword [r15 + 16], 16
.wait_bios:
    mov  dword [r15 + 112], 5       ; poll unavailable, not raw hardware absence
    inc  dword [r15 + 84]
    and  dword [r15 + 16], ~4096
    mov  esi, ebx
    call xh_rd
    mov  [r15 + 120], eax           ; last poll distinct from final readback
    jc   .report
    cmp  eax, -1
    je   .report
    or   dword [r15 + 16], 4096
    mov  ecx, eax
    and  ecx, 255
    cmp  ecx, 1
    jne  .report
    test eax, 1 << 16
    jz   .os_observed
    mov  dword [r15 + 112], 6       ; BIOS still owns it at the original deadline
    cmp  r12d, 1000
    jae  .report
    mov  edi, 1000
    call tsc_delay_us
    inc  r12d
    jmp  .wait_bios
.os_observed:
    mov  dword [r15 + 112], 7
    test eax, 1 << 24
    jz   .report
    or   dword [r15 + 16], 32
    mov  dword [r15 + 112], 8       ; original SMI operand unavailable
    lea  esi, [ebx + 4]
    call xh_rd
    mov  [r15 + 100], eax
    jc   .report
    cmp  eax, -1
    je   .report
    or   dword [r15 + 16], 64
    and  eax, 0x000E1FEE
    or   eax, 0xE0000000            ; original RsvdP/RW1C image, no change
    mov  [r15 + 104], eax
    mov  edx, eax
    lea  esi, [ebx + 4]
    mov  dword [r15 + 112], 9
    call xh_wr
    mov  [r15 + 128], eax           ; actual HAL return, separate from MMIO data
    jc   .report
    or   dword [r15 + 16], 128
    mov  dword [r15 + 112], 10      ; final actual readbacks unavailable
    mov  esi, ebx
    call xh_rd
    mov  [r15 + 96], eax
    jc   .report
    cmp  eax, -1
    je   .report
    or   dword [r15 + 16], 256
    mov  [rsp + 40], rax
    lea  esi, [ebx + 4]
    call xh_rd
    mov  [r15 + 108], eax
    jc   .report
    cmp  eax, -1
    je   .report
    or   dword [r15 + 16], 512
    mov  [rsp + 48], rax
    mov  dword [r15 + 112], 11
    mov  eax, [r15 + 96]
    mov  ecx, eax
    and  ecx, 255
    cmp  ecx, 1
    jne  .report
    test eax, 1 << 16
    jnz  .report
    test eax, 1 << 24
    jz   .report
    mov  dword [r15 + 112], 12
    test dword [r15 + 108], 0x0000E011 ; RW SMI enables 0/4/13/14/15; bit16 is the RO EINT shadow
    jnz  .report
    mov  dword [r15 + 112], 1       ; observed completed legacy acquisition
    jmp  .ready
.none:
    or   dword [r15 + 16], 1024
    mov  dword [r15 + 112], 0       ; actual observed no-legacy, never physicalabsence
.ready:
    or   dword [r15 + 16], 2048
    mov  dword [r15 + 12], 0
.report:
    mov  [r15 + 88], r12d
    mov  [rsp + 56], r12
    ; Original forced field8 remains0. A timeout is a refusal, not a force.
    lea  rdi, [rel str_xhci_legacy_handoff]
    call serial_string
    xor  r14d, r14d
.fields:
    mov  rdi, [rsp + r14 * 8]
    call serial_hex64
    lea  rdi, [rel str_xhci_legacy_sep]
    call serial_string
    inc  r14d
    cmp  r14d, 10
    jb   .fields
    call serial_newline
    mov  eax, [r15 + 12]            ; serial output cannot substitute an admission
    add  rsp, 80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
str_xhci_legacy_handoff: db "XHCILEG v=1 phase=handoff fields=",0
str_xhci_legacy_sep: db " ",0

; ---------------------------------------------------------------------------
; xhci_reset — halt then HCRST, wait for reset + CNR clear (bounded).
;   -> EAX = 0 ok / 1 timeout. clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_reset:
    XHCI_POWER_GATE 1
    push rbx
    ; HCRST destroys every hardware slot. Invalidate software ownership before
    ; the reset write so even a timed-out reset cannot expose stale slot IDs.
    call xhci_clear_device_state
    ; halt: clear R/S
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    mov  [rel xhci_scr_off], esi
    call xh_rd
    and  eax, ~XHCI_USBCMD_RS
    mov  edx, eax
    mov  esi, [rel xhci_scr_off]
    call xh_wr
    ; wait HCH set (halted)
    mov  ebx, 200
.wait_halt:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBSTS
    call xh_rd
    test eax, XHCI_USBSTS_HCH
    jnz  .do_reset
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .wait_halt
    mov  eax, 1                      ; never issue HCRST while HCH remains clear
    jmp  .out
.do_reset:
    mov  dword [rel xhci_init_phase], 6 ; HCRST clear deadline
    ; set HCRST
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    call xh_rd
    or   eax, XHCI_USBCMD_HCRST
    mov  edx, eax
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    call xh_wr
    mov  edi, 10000                  ; Intel PCH quirk: >=10 ms before any HC read
    call tsc_delay_us
    ; wait HCRST clear
    mov  ebx, 500
.wait_reset:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    call xh_rd
    test eax, XHCI_USBCMD_HCRST
    jz   .wait_cnr
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .wait_reset
    mov  eax, 1
    jmp  .out
.wait_cnr:
    mov  dword [rel xhci_init_phase], 7 ; CNR clear deadline
    mov  ebx, 500
.cnr_loop:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBSTS
    call xh_rd
    test eax, XHCI_USBSTS_CNR
    jz   .ok
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .cnr_loop
    mov  eax, 1
    jmp  .out
.ok:
    ; An acknowledged HCRST ends the old command ring's quarantine. Keep it
    ; through every timeout and software-only clear/rebuild path.
    mov  byte [rel xhci_cmd_ring_dead], 0
    xor  eax, eax
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_alloc_dma — bind the DCBAA / command ring / event ring / ERST / per-slot
;   input+output contexts / EP0 rings to DEDICATED static page-aligned buffers,
;   zero every owner, and build all Link TRBs. -> EAX = 0 ok / 1 OOM. clobbers: c-s.
;
;   Static (not core/dma pool) DELIBERATELY: dev/net/e1000e re-calls dma_init later in
;   boot (resetting the bump pool), which would RECYCLE pool-allocated xHCI rings into
;   the NIC's rings and cross-corrupt two live DMA engines. Owned buffers are identity-
;   mapped (image < 16 GiB, RW+X map) + 4 KiB aligned, matching the proven source's
;   xhci_static_* approach and side-stepping the shared-pool lifetime conflict.
; ---------------------------------------------------------------------------
xhci_alloc_dma:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    call xhci_dma_bind               ; this controller's DMA set (instance 0: the static one)
    mov  rax, [rel xhci_dcbaa]
    call xhci_zero_page
    mov  rax, [rel xhci_cmd_ring]
    call xhci_zero_page
    mov  rax, [rel xhci_evt_ring]
    call xhci_zero_page
    mov  rax, [rel xhci_erst]
    call xhci_zero_page
    ; One physically contiguous, page-aligned input context per enabled slot.
    mov  r12, [rel xhci_in_ctx_base]
    xor  ebx, ebx
.zero_input_contexts:
    mov  rax, rbx
    shl  rax, 12
    add  rax, r12
    call xhci_zero_page
    inc  ebx
    cmp  ebx, XHCI_MAX_SLOTS_EN
    jb   .zero_input_contexts
    mov  rax, [rel xhci_out_ctx]
    ; Intel can fetch DCBAA[slot] during Enable Slot, before Address Device.
    ; Give every enabled slot an independent, worst-case-CSZ output context now.
    mov  r13, rax
    mov  rdi, rax
    mov  ecx, (XHCI_MAX_SLOTS_EN * XHCI_OUT_CTX_STRIDE) / 8
    xor  eax, eax
    rep  stosq
    mov  rdi, [rel xhci_dcbaa]
    mov  ebx, 1
.prepopulate_dcbaa:
    mov  eax, ebx
    dec  eax
    imul eax, XHCI_OUT_CTX_STRIDE
    lea  rdx, [r13 + rax]
    mov  [rdi + rbx*8], rdx
    inc  ebx
    cmp  ebx, XHCI_MAX_SLOTS_EN
    jbe  .prepopulate_dcbaa
    ; Each slot also owns a private EP0 transfer-ring page and Link TRB.
    mov  r12, [rel xhci_ep0_base]
    xor  ebx, ebx
.init_ep0_rings:
    mov  rax, rbx
    shl  rax, 12
    add  rax, r12
    call xhci_zero_page
    lea  rdi, [rax + 255*16]
    mov  [rdi], rax
    mov  dword [rdi + 8], 0
    mov  dword [rdi + 12], (XHCI_TRB_LINK << 10) | (1 << 1) | 1
    inc  ebx
    cmp  ebx, XHCI_MAX_SLOTS_EN
    jb   .init_ep0_rings
    ; command ring Link TRB @[255] -> ring base, TC=1, cycle=1
    mov  rbx, [rel xhci_cmd_ring]
    lea  rdi, [rbx + 255*16]
    mov  [rdi], rbx                  ; param = ring base (low 64)
    mov  dword [rdi + 8], 0
    mov  eax, (XHCI_TRB_LINK << 10) | (1 << 1) | 1  ; type|TC|cycle
    mov  [rdi + 12], eax
    mov  dword [rel xhci_cmd_idx], 0
    mov  dword [rel xhci_cmd_pcs], 1
    ; event ring: no Link TRB needed (single segment, ERST wraps via dequeue)
    mov  dword [rel xhci_evt_idx], 0
    mov  dword [rel xhci_evt_ccs], 1
    call xhci_clear_device_state

    ; Port the proven scratchpad contract rather than re-deriving controller
    ; behavior. One persistent, page-aligned heap extent survives all five
    ; reinitializations; only its contents and pointer array are refreshed.
    mov  rdi, [rel xhci_scr_arr_base]
    mov  ecx, XHCI_SCRATCH_MAX
    xor  eax, eax
    rep  stosq
    movzx r12d, word [rel xhci_scratch_count]
    test r12d, r12d
    jz   .scratch_done
    cmp  r12d, XHCI_SCRATCH_MAX
    ja   .oom
    mov  rax, [rel xhci_scratch_pages]
    test rax, rax
    jnz  .scratch_have_pages
    mov  rdi, r12
    shl  rdi, 12
    add  rdi, 4095
    call kmalloc
    test rax, rax
    jz   .oom
    add  rax, 4095
    and  rax, -4096
    mov  [rel xhci_scratch_pages], rax
.scratch_have_pages:
    mov  r13, [rel xhci_scr_arr_base]
    xor  ebx, ebx
.scratch_page_loop:
    mov  rax, rbx
    shl  rax, 12
    add  rax, [rel xhci_scratch_pages]
    mov  [r13 + rbx*8], rax
    push rax
    mov  rdi, rax
    mov  ecx, 4096 / 8
    xor  eax, eax
    rep  stosq
    pop  rax
    inc  ebx
    cmp  ebx, r12d
    jb   .scratch_page_loop
    mov  rax, [rel xhci_scr_arr_base]
    mov  rdi, [rel xhci_dcbaa]
    mov  [rdi], rax                       ; DCBAA[0] = scratchpad pointer array
.scratch_done:
    ; Publish zeroed rings, per-slot contexts, final Link TRBs, DCBAA, and
    ; scratch pages before
    ; CRCR/DCBAAP can expose them to the controller on a warm reinit.
    wbinvd
    xor  eax, eax
    jmp  .out
.oom:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_dma_bind — point this controller's DMA pointers at its own set: the
;   static, build-gated buffers when xhci_dma_set is 0 (the first controller,
;   unchanged), else one page-aligned dma_alloc extent with the same layout
;   (every structure a whole 4 KiB page or a 2 KiB slot stride inside one, so
;   none crosses a page or a 64 KiB boundary). clobbers: RAX, RDX.
xhci_dma_bind:
    XHCI_POWER_GATE 1
    mov  rax, [rel xhci_dma_set]
    test rax, rax
    jz   .static
    mov  [rel xhci_dcbaa], rax
    lea  rdx, [rax + XHCI_DS_CMD]
    mov  [rel xhci_cmd_ring], rdx
    lea  rdx, [rax + XHCI_DS_EVT]
    mov  [rel xhci_evt_ring], rdx
    lea  rdx, [rax + XHCI_DS_ERST]
    mov  [rel xhci_erst], rdx
    lea  rdx, [rax + XHCI_DS_IN]
    mov  [rel xhci_in_ctx_base], rdx
    lea  rdx, [rax + XHCI_DS_OUT]
    mov  [rel xhci_out_ctx], rdx
    lea  rdx, [rax + XHCI_DS_EP0]
    mov  [rel xhci_ep0_base], rdx
    lea  rdx, [rax + XHCI_DS_SCR]
    mov  [rel xhci_scr_arr_base], rdx
    ret
.static:
    lea  rax, [rel xhci_dcbaa_buf]
    mov  [rel xhci_dcbaa], rax
    lea  rax, [rel xhci_cmd_buf]
    mov  [rel xhci_cmd_ring], rax
    lea  rax, [rel xhci_evt_buf]
    mov  [rel xhci_evt_ring], rax
    lea  rax, [rel xhci_erst_buf]
    mov  [rel xhci_erst], rax
    lea  rax, [rel xhci_in_ctx_buf]
    mov  [rel xhci_in_ctx_base], rax
    lea  rax, [rel xhci_out_ctx_buf]
    mov  [rel xhci_out_ctx], rax
    lea  rax, [rel xhci_ep0_buf]
    mov  [rel xhci_ep0_base], rax
    lea  rax, [rel xhci_scratch_arr]
    mov  [rel xhci_scr_arr_base], rax
    ret

; xhci_zero_page(RAX = page ptr) — zero 4096 bytes. clobbers RCX,RDI (RAX preserved).
xhci_zero_page:
    XHCI_POWER_GATE 1
    push rax
    push rdi
    push rcx
    mov  rdi, rax
    mov  ecx, XHCI_RING_BYTES / 8
    xor  eax, eax
    rep  stosq
    wbinvd                              ; proven warm-reinit DMA publication rule
    pop  rcx
    pop  rdi
    pop  rax
    ret

; xhci_clear_device_state — invalidate every software owner for a new
; controller generation. Called before HCRST and after rebuilding the DMA pages.
xhci_clear_device_state:
    XHCI_POWER_GATE 1
    lea  rdi, [rel xhci_psc_changed]    ; A0: a controller reset ends every latch/quarantine
    mov  ecx, xhci_psc_events - xhci_psc_changed
    xor  eax, eax
    rep  stosb
    mov  dword [rel xhci_slot_quar], eax
    mov  dword [rel xhci_slot_parked], eax   ; PARK P4(a): reset releases every parked id
    mov  [rel xhci_cmd_out_seq], rax     ; F.3.2: a new controller generation has no command
    call xhci_cmd_record_clear
    lea  rdi, [rel xhci_port_slot]
    mov  ecx, XHCI_PORT_COUNT
    xor  eax, eax
    rep  stosd
    lea  rdi, [rel xhci_slot_port]
    mov  ecx, XHCI_SLOT_COUNT
    rep  stosd
    lea  rdi, [rel xhci_ep0_idx]
    mov  ecx, XHCI_SLOT_COUNT
    rep  stosd
    lea  rdi, [rel xhci_ep0_pcs]
    mov  ecx, XHCI_SLOT_COUNT
    mov  eax, 1
    rep  stosd
    lea  rdi, [rel xhci_multi_state_begin]
    mov  ecx, xhci_multi_state_end - xhci_multi_state_begin
    xor  eax, eax
    rep  stosb
    lea  rdi, [rel xhci_slot_topo]      ; HUB0: per-slot route/depth/TT identity
    mov  ecx, XHCI_SLOT_COUNT * usb_topo_size
    rep  stosb
    call xhci_interrupt_state_reset
    ret

; Advance the controller generation, then clear every interrupt/bulk endpoint
; owner, transfer ring, and immutable payload buffer. Default and lazy large DMA
; extents are aligned inside their allocations; reset reuses them so stale
; device addresses can never migrate into a new generation.
xhci_interrupt_state_reset:
    XHCI_POWER_GATE 1
    mov  rax, [rel xhci_interrupt_reset_hook]
    test rax, rax
    jz   .consumer_released
    call rax                         ; release class state before a slot can be reused
.consumer_released:
    inc  dword [rel xhci_generation]
    jnz  .have_generation
    mov  dword [rel xhci_generation], 1
.have_generation:
    lea  rdi, [rel xhci_intr_states]
    mov  ecx, (XHCI_INTR_STATE_COUNT * xhci_intr_ep_size) / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel xhci_xfer_dma]
    test rax, rax
    jnz  .have_dma
    mov  edi, XHCI_XFER_DMA_BYTES + XHCI_INTR_DMA_ALIGN - 1
    call dma_alloc
    test rax, rax
    jz   .no_dma
    add  rax, XHCI_INTR_DMA_ALIGN - 1
    and  rax, -XHCI_INTR_DMA_ALIGN
    mov  [rel xhci_xfer_dma], rax
.have_dma:
    mov  rdi, rax
    mov  ecx, (XHCI_INTR_STATE_COUNT * XHCI_INTR_RING_BYTES) / 8
    xor  eax, eax
    rep  stosq
    mov  ecx, (XHCI_INTR_STATE_COUNT * XHCI_INTR_REPORT_BYTES) / 8
    rep  stosq
    xor  r8d, r8d
.owner_loop:
    cmp  r8d, XHCI_INTR_STATE_COUNT
    jae  .done
    mov  eax, r8d
    imul eax, xhci_intr_ep_size
    lea  r9, [rel xhci_intr_states]
    add  r9, rax
    mov  r10, [rel xhci_xfer_dma]
    mov  eax, r8d
    imul eax, XHCI_INTR_RING_BYTES
    add  r10, rax
    mov  [r9 + xhci_intr_ep.ring], r10
    mov  r11, [rel xhci_xfer_dma]
    add  r11, XHCI_INTR_STATE_COUNT * XHCI_INTR_RING_BYTES
    mov  eax, r8d
    imul eax, XHCI_INTR_REPORT_BYTES
    add  r11, rax
    ; Large buffers are controller-local lifetime allocations. A verified reset
    ; retires their old owners, scrubs them and reuses them without pool growth.
    lea  rax, [rel xhci_bulk_large_dma]
    mov  rax, [rax + r8*8]
    test rax, rax
    jz   .default_report
    mov  r11, rax
    mov  word [r9 + xhci_intr_ep.report_capacity], XHCI_BULK_LARGE_BYTES
    mov  rdi, r11
    mov  ecx, XHCI_BULK_LARGE_BYTES / 8
    xor  eax, eax
    rep  stosq
.default_report:
    mov  [r9 + xhci_intr_ep.report], r11
    mov  dword [r9 + xhci_intr_ep.pcs], 1
    mov  eax, [rel xhci_generation]
    mov  [r9 + xhci_intr_ep.generation], eax
    lea  rdi, [r10 + (XHCI_INTR_RING_TRBS - 1) * 16]
    mov  [rdi], r10
    mov  dword [rdi + 8], 0
    mov  dword [rdi + 12], (XHCI_TRB_LINK << 10) | (1 << 1) | 1
    inc  r8d
    jmp  .owner_loop
.done:
    wbinvd
.no_dma:
    ret

; xhci_interrupt_set_reset_hook(RDI=consumer reset callback).  The callback is
; invoked before endpoint ownership is cleared and the generation advances.
xhci_interrupt_set_reset_hook:
    mov  [rel xhci_interrupt_reset_hook], rdi
    ret

; ---------------------------------------------------------------------------
; xhci_program — DCBAAP, CRCR (|RCS), ERSTSZ/ERSTBA/ERDP, MaxSlotsEn. clobbers: c-s.
; ---------------------------------------------------------------------------
xhci_program:
    XHCI_POWER_GATE 1
    push rbx
    ; MaxSlotsEn = min(MaxSlots, XHCI_MAX_SLOTS_EN)
    mov  eax, [rel xhci_maxslots]
    cmp  eax, XHCI_MAX_SLOTS_EN
    jbe  .have_slots
    mov  eax, XHCI_MAX_SLOTS_EN
.have_slots:
    mov  edx, eax
    mov  esi, [rel xhci_op]
    add  esi, XHCI_CONFIG
    call xh_wr
    ; DCBAAP = dcbaa
    mov  esi, [rel xhci_op]
    add  esi, XHCI_DCBAAP
    mov  rdx, [rel xhci_dcbaa]
    call xh_wr64
    ; CRCR = cmd_ring | RCS
    mov  esi, [rel xhci_op]
    add  esi, XHCI_CRCR
    mov  rdx, [rel xhci_cmd_ring]
    or   rdx, 1                      ; RCS
    call xh_wr64
    ; ERST[0]: base = evt_ring, size = 256
    mov  rbx, [rel xhci_erst]
    mov  rax, [rel xhci_evt_ring]
    mov  [rbx], rax
    mov  dword [rbx + 8], XHCI_RING_TRBS
    mov  dword [rbx + 12], 0
    wbinvd                              ; ERST contents precede ERSTBA publication
    ; ERSTSZ = 1 (BEFORE ERSTBA — spec order)
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_ERSTSZ
    mov  edx, 1
    call xh_wr
    ; ERSTBA = erst
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_ERSTBA
    mov  rdx, [rel xhci_erst]
    call xh_wr64
    ; ERDP = evt_ring | EHB(bit3)
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_ERDP
    mov  rdx, [rel xhci_evt_ring]
    or   rdx, (1 << 3)
    call xh_wr64
    ; IMAN.IE (bit1) for interrupter 0 (we poll, but arm IE so IP semantics behave)
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_IMAN
    call xh_rd
    or   eax, (1 << 1)
    mov  edx, eax
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_IMAN
    call xh_wr
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_run — set USBCMD.R/S + INTE, wait HCH clear (running). -> EAX 0 ok / 1 to. c-s.
; ---------------------------------------------------------------------------
xhci_run:
    XHCI_POWER_GATE 1
    push rbx
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    call xh_rd
    or   eax, XHCI_USBCMD_RS | XHCI_USBCMD_INTE
    mov  edx, eax
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    call xh_wr
    mov  ebx, 200
.wait:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBSTS
    call xh_rd
    test eax, XHCI_USBSTS_HCH
    jz   .ok
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .wait
    mov  eax, 1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_airlock_fault — real non-lifeline controller fault plus containment.
; The injection is credited only after hardware acknowledges USBCMD.R/S=0 with
; USBSTS.HCH=1. Containment is credited only after the shipped reset/program/run
; path returns a fresh healthy register read. All waits are bounded.
; -> EAX 0 contained / 1 unavailable / 2 halt not observed / 3 reinit failed.
; ---------------------------------------------------------------------------
xhci_airlock_fault:                       ; exported: describes the first controller
    XHCI_POWER_GATE 1
    call xhci_inst_live0
xhci_airlock_fault_live:              ; internal callers: the live controller
    XHCI_POWER_GATE 1
    push rbx
    inc  qword [rel xhci_airlock_attempts]
    mov  byte [rel xhci_airlock_last_halted], 0
    mov  byte [rel xhci_airlock_last_code], 1
    call xhci_airlock_status_live
    test eax, eax
    jz   .unavailable

    ; Inject a real controller stop without touching the e1000e command NIC.
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBCMD
    mov  [rel xhci_scr_off], esi
    call xh_rd
    and  eax, ~XHCI_USBCMD_RS
    mov  edx, eax
    mov  esi, [rel xhci_scr_off]
    call xh_wr
    mov  ebx, 200
.wait_halted:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBSTS
    call xh_rd
    mov  [rel xhci_airlock_last_usbsts], eax
    test eax, XHCI_USBSTS_HCH
    jnz  .fault_observed
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .wait_halted
    call xhci_run                         ; best-effort restore after a non-firing injection
    test eax, eax
    jnz  .restore_failed
    call xhci_airlock_status_live         ; R/S accepted alone does not establish a live HC
    test eax, eax
    jnz  .halt_not_observed
.restore_failed:
    ; The stop was not observed, but failed cleanup still invalidates readiness.
    ; Keep code 2 and the injection counters: no acknowledged fault is credited.
    mov  byte [rel xhci_m_up], 0
    mov  dword [rel xhci_hcdev + dev.health], HEALTH_DEGRADED
.halt_not_observed:
    mov  byte [rel xhci_airlock_last_code], 2
    mov  eax, 2
    jmp  .out

.fault_observed:
    mov  byte [rel xhci_airlock_last_halted], 1
    inc  qword [rel xhci_airlock_injected]
    mov  byte [rel xhci_m_up], 0
    mov  dword [rel xhci_hcdev + dev.health], HEALTH_DEGRADED

    call xhci_reset
    test eax, eax
    jnz  .uncontained
    call xhci_alloc_dma
    test eax, eax
    jnz  .uncontained
    call xhci_program
    call xhci_run
    test eax, eax
    jnz  .uncontained
    mov  byte [rel xhci_m_up], 1
    ; HCRST dropped PP on a PPC=1 controller: power the root ports again, as
    ; bring-up does after xhci_run, or "contained" leaves every device absent.
    call xhci_port_power
    call xhci_port_settle                 ; let delayed HSE/reattach state become observable
    call xhci_airlock_status_live
    test eax, eax
    jz   .uncontained
    mov  dword [rel xhci_hcdev + dev.health], HEALTH_OK
    inc  qword [rel xhci_airlock_contained]
    mov  byte [rel xhci_airlock_last_code], 0
    xor  eax, eax
    jmp  .out
.uncontained:
    inc  qword [rel xhci_airlock_uncontained]
    mov  byte [rel xhci_m_up], 0
    mov  dword [rel xhci_hcdev + dev.health], HEALTH_DEGRADED
    mov  byte [rel xhci_airlock_last_code], 3
    mov  eax, 3
    jmp  .out
.unavailable:
    mov  eax, 1
.out:
    pop  rbx
    ret

; xhci_airlock_status -> EAX live(0/1), EDX HCHalted(0/1). A fresh MMIO
; read, not the boot marker alone, grades HCH/HSE/CNR/HCE and is retained verbatim.
xhci_airlock_status:                       ; exported: describes the first controller
    call xhci_inst_live0
xhci_airlock_status_live:              ; internal callers: the live controller
    XHCI_POWER_GATE 0
    xor  edx, edx
    cmp  dword [rel xhci_found], 1
    jne  .not_live
    mov  esi, [rel xhci_op]
    add  esi, XHCI_USBSTS
    call xh_rd
    mov  [rel xhci_airlock_last_usbsts], eax
    mov  ecx, eax
    and  eax, XHCI_USBSTS_HCH
    mov  edx, eax
    cmp  byte [rel xhci_m_up], 1
    jne  .not_live
    test ecx, XHCI_USBSTS_HCH | XHCI_USBSTS_HSE | XHCI_USBSTS_CNR | XHCI_USBSTS_HCE
    jnz  .not_live
    mov  eax, 1
    ret
.not_live:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; xhci_register — build the usbhc_ops vtable + dev handle, store the root-hub port
;   count in dev.flags, register behind the enum seam (L3->L4).
;   -> EAX = REG_OK (0) / -1 (registry full or rejected). clobbers: RAX,RDI.
; ---------------------------------------------------------------------------
xhci_register:                       ; registers the LIVE controller (xhci_inst_cur)
    XHCI_POWER_GATE 1
    mov  eax, [rel xhci_inst_cur]
    test eax, eax
    jnz  .extra
    lea  rdi, [rel xhci_ops]
    lea  r8, [rel xhci_hcdev]
    lea  r9, [rel str_xhci_name]
    jmp  .fill
.extra:
    dec  eax
    imul ecx, eax, usbhc_ops_size
    lea  rdi, [rel xhci_inst_ops]
    add  rdi, rcx
    imul ecx, eax, DEV_SIZE
    lea  r8, [rel xhci_inst_hcdev]
    add  r8, rcx
    lea  r9, [rel str_xhci_names]
    lea  r9, [r9 + rax*8]
.fill:
    ; Every entry but the stateless no-op is this controller's thunk: it makes
    ; the controller live (xhci_inst_switch) and tail-calls the shared op.
    mov  ecx, [rel xhci_inst_cur]
    imul ecx, ecx, XHCI_THUNK_OPS * XHCI_THUNK_SZ
    lea  r10, [rel xhci_thunks]
    add  r10, rcx
    lea  rax, [rel xhci_op_noop]
    mov  [rdi + usbhc_ops.init], rax
    mov  [rdi + usbhc_ops.start], rax
    mov  [rdi + usbhc_ops.stop], rax
    lea  rax, [r10 + XT_PORT_STATUS * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.port_status], rax
    lea  rax, [r10 + XT_CONTROL * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.control], rax
    lea  rax, [r10 + XT_BULK_IN * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.bulk_in], rax
    lea  rax, [r10 + XT_BULK_OUT * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.bulk_out], rax
    lea  rax, [r10 + XT_INTR_CONFIGURE * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.configure_ep], rax
    lea  rax, [r10 + XT_INTR_QUEUE * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.interrupt_in_queue], rax
    lea  rax, [r10 + XT_INTR_POLL * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.interrupt_in_poll], rax
    lea  rax, [r10 + XT_BULK_IN_POLL * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.bulk_in_poll], rax
    lea  rax, [r10 + XT_HUB_CONFIGURE * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.hub_configure], rax
    lea  rax, [r10 + XT_HUB_ADDRESS_CHILD * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.hub_address_child], rax
    lea  rax, [r10 + XT_TOPOLOGY * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.topology], rax
    lea  rax, [r10 + XT_SS_CONFIGURE * XHCI_THUNK_SZ]
    mov  [rdi + usbhc_ops.configure_ep_ss], rax
    mov  rax, rdi                    ; ops
    mov  rdi, r8                     ; dev
    mov  [rdi + dev.ops], rax
    mov  qword [rdi + dev.info], 0
    mov  qword [rdi + dev.priv], 0
    mov  dword [rdi + dev.prio], PRIO_NATIVE
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_USBHC
    ; flags: low16 = root-hub port count; byte[3] = 0 (NOT the nulldev)
    mov  eax, [rel xhci_maxports]
    and  eax, 0xFFFF
    mov  [rdi + dev.flags], eax
    mov  qword [rdi + dev.next], 0
    mov  [rdi + dev.name], r9
    call usb_hc_register
    ret

; ---------------------------------------------------------------------------
; RCQ-09 slice 2: up to XHCI_INST_MAX controllers, each its own usb_hc backend.
;   The proven single-controller code keeps addressing one LIVE state image
;   (regions r1..r4) and one DMA set per controller (xhci_dma_bind). Making a
;   controller live parks the current image in its save slot and loads the
;   target's (xhci_inst_switch). The xHCI code never yields and is only reached
;   from the cooperative idle loop / HID task on the BSP (the preemptive picker
;   runs only user bench jobs), so an op always runs to completion on the
;   image it started with. Every backend entry point is a per-controller thunk.
; ---------------------------------------------------------------------------
XHCI_INST_MAX        equ 4
XHCI_INST_BYTES      equ (xhci_inst_r1_end - xhci_inst_r1) + (xhci_inst_r2_end - xhci_inst_r2) + (xhci_inst_r3_end - xhci_inst_r3) + (xhci_inst_r4_end - xhci_inst_r4)
XHCI_DS_TOTAL        equ XHCI_DS_BYTES + XHCI_XFER_DMA_BYTES   ; one later controller's heap extent
XHCI_THUNK_SZ        equ 32
XT_PORT_STATUS       equ 0
XT_CONTROL           equ 1
XT_BULK_IN           equ 2
XT_BULK_OUT          equ 3
XT_INTR_CONFIGURE    equ 4
XT_INTR_QUEUE        equ 5
XT_INTR_POLL         equ 6
XT_BULK_IN_POLL      equ 7
XT_HUB_CONFIGURE     equ 8
XT_HUB_ADDRESS_CHILD equ 9
XT_TOPOLOGY          equ 10
XT_SS_CONFIGURE      equ 11
XHCI_THUNK_OPS       equ 12

; Original terminal command-lifetime inhibitor. EAX0 = these observed command
; operands quiet, 2 = outstanding command, 3 = unavailable/quarantined. This is
; not controller halt, physical absence, or a DMA/Flush completion assertion.
; Read only original bounded LIVE/parked RAM; never switch/copy-in or touch MMIO.
; Family9: four64B records, explicit observed prefix; see exact ABI doc.
xhci_power_command_guard:
    pushfq
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    lea rdi,[rel xhci_power_command_observations]
    xor eax,eax
    mov ecx,32
    rep stosq
    mov r11d,[rel xhci_inst_n]
    mov r14d,[rel xhci_inst_cur]
    xor r9d,r9d
    cmp qword [rel reinit_power_xhci_context],0
    setne r9b
    lea rdi,[rel xhci_power_command_observations]
    mov dword [rdi],1
    mov dword [rdi+8],3
    mov dword [rdi+12],1
    mov [rdi+16],r11d
    mov [rdi+20],r14d
    mov [rdi+24],r9d
    mov r12d,3
    test r9d,r9d
    jnz .done                           ; owned profile is not this terminal rail
    cmp r11d,XHCI_INST_MAX
    ja .done
    mov r13d,r11d
    test r13d,r13d
    jnz .registered
    test r14d,r14d
    jnz .done
    inc r13d                            ; inspect actual partial LIVE even n0
    jmp .bounded
.registered:
    cmp r14d,r13d
    jae .done
.bounded:
    xor r12d,r12d
    xor ebx,ebx
.image:
    mov edi,ebx
    shl rdi,6
    lea rax,[rel xhci_power_command_observations]
    add rdi,rax
    mov dword [rdi],1
    mov [rdi+4],ebx
    mov dword [rdi+8],3
    mov dword [rdi+12],1
    mov [rdi+16],r11d
    mov [rdi+20],r14d
    mov [rdi+24],r9d
    lea r8,[rel xhci_generation]
    lea rdx,[rel xhci_cmd_ring_dead]
    lea rsi,[rel xhci_cmd_out_trb]
    cmp ebx,r14d
    je .operands
    imul eax,ebx,XHCI_INST_BYTES
    lea rcx,[rel xhci_inst_save]
    add rcx,rax
    lea r8,[rcx+xhci_generation-xhci_inst_r1]
    lea rdx,[rcx+(xhci_inst_r1_end-xhci_inst_r1)+xhci_cmd_ring_dead-xhci_inst_r2]
    lea rsi,[rcx+xhci_cmd_out_trb-xhci_inst_r1]
.operands:
    mov eax,[r8]
    mov [rdi+28],eax
    mov dword [rdi+12],3
    test r11d,r11d
    jz .dead
    test eax,eax
    jz .unknown                         ; registered lifetime must have generation
.dead:
    movzx eax,byte [rdx]
    mov [rdi+32],eax
    mov dword [rdi+12],7
    test eax,eax
    jnz .unknown                        ; pending has not been observed here
    cmp qword [rsi],0                    ; full64 original command predicate
    setne al
    movzx eax,al
    mov [rdi+36],eax
    mov dword [rdi+12],15
    mov [rdi+8],eax                      ; zero quiet; nonzero mapped to busy2
    test eax,eax
    jz .next
    mov dword [rdi+8],2
    test r12d,r12d
    jnz .next                           ; unknown3 dominates busy2
    mov r12d,2
    jmp .next
.unknown:
    mov r12d,3
.next:
    inc ebx
    cmp ebx,r13d
    jb .image
.done:
    mov eax,r12d
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    popfq
    ret

; Original ISO packet-work inhibitor. RAM only; no endpoint/controller action.
; EAX0 observed quiet,2 known work,3 unavailable/retained uncertain lifetime.
; Four160B family10 records; explicit header/generation/complete-scan masks.
xhci_power_iso_guard:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cld
    lea rdi,[rel xhci_power_iso_observations]
    xor eax,eax
    mov ecx,80
    rep stosq
    mov r11d,[rel xhci_inst_n]
    mov r14d,[rel xhci_inst_cur]
    xor r9d,r9d
    cmp qword [rel reinit_power_xhci_context],0
    setne r9b
    lea rdi,[rel xhci_power_iso_observations]
    mov dword [rdi],1
    mov dword [rdi+8],3
    mov dword [rdi+12],1
    mov [rdi+16],r11d
    mov [rdi+20],r14d
    mov [rdi+24],r9d
    mov r12d,3
    test r9d,r9d
    jnz .done
    cmp r11d,XHCI_INST_MAX
    ja .done
    mov r13d,r11d
    test r13d,r13d
    jnz .registered
    test r14d,r14d
    jnz .done
    inc r13d                         ; actual partial LIVE, never infer absence
    jmp .bounded
.registered:
    cmp r14d,r13d
    jae .done
.bounded:
    xor r12d,r12d
    xor ebx,ebx
.image:
    imul edi,ebx,160
    lea rax,[rel xhci_power_iso_observations]
    add rdi,rax
    mov dword [rdi],1
    mov [rdi+4],ebx
    mov dword [rdi+8],3
    mov dword [rdi+12],1
    mov [rdi+16],r11d
    mov [rdi+20],r14d
    mov [rdi+24],r9d
    lea r8,[rel xhci_intr_states]
    lea rdx,[rel xhci_generation]
    cmp ebx,r14d
    je .generation
    imul eax,ebx,XHCI_INST_BYTES
    lea rcx,[rel xhci_inst_save]
    add rcx,rax
    lea rdx,[rcx+xhci_generation-xhci_inst_r1]
    lea r8,[rcx+(xhci_inst_r1_end-xhci_inst_r1)+(xhci_inst_r2_end-xhci_inst_r2)+(xhci_inst_r3_end-xhci_inst_r3)+xhci_intr_states-xhci_inst_r4]
.generation:
    mov ebp,[rdx]
    mov [rdi+28],ebp
    mov dword [rdi+12],3
    test r11d,r11d
    jz .endpoints
    test ebp,ebp
    jz .unknown_image
.endpoints:
    mov dword [rdi+32],XHCI_INTR_STATE_COUNT
    cmp dword [rdi+32],64
    ja .unknown_image                ; bitmap/access bound before endpoint reads
    mov dword [rdi+8],0
    xor r10d,r10d
.endpoint:
    cmp r10d,XHCI_INTR_STATE_COUNT
    jae .scanned
    movzx eax,byte [r8+xhci_intr_ep.active]
    test eax,eax
    jz .class
    bts qword [rdi+48],r10
    cmp eax,1
    je .class
    bts qword [rdi+56],r10
    mov dword [rdi+8],3
.class:
    cmp byte [r8+xhci_intr_ep.attributes],1 ; original ISO class, even retained0
    jne .next_endpoint
    bts qword [rdi+64],r10
    bts qword [rdi+72],r10             ; all ISO operands below actually read
    xor r15d,r15d                     ; bit0 work,bit1 malformed/uncertain
    cmp byte [r8+xhci_intr_ep.active],1
    je .iso_generation
    or r15d,2
.iso_generation:
    mov eax,[r8+xhci_intr_ep.generation]
    test eax,eax
    jz .bad_generation
    cmp eax,ebp
    jne .bad_generation
    bts qword [rdi+80],r10
    jmp .configured
.bad_generation:
    or r15d,2
.configured:
    movzx eax,byte [r8+xhci_intr_ep.configured]
    cmp eax,1
    jne .stopped
    bts qword [rdi+88],r10
    jmp .pending
.stopped:
    cmp eax,3
    jne .bad_config
    bts qword [rdi+96],r10
    jmp .pending
.bad_config:
    or r15d,2
.pending:
    movzx eax,byte [r8+xhci_intr_ep.pending]
    test eax,eax
    jz .completed
    bts qword [rdi+104],r10
    or r15d,1
    cmp eax,1
    jbe .completed
    or r15d,2
.completed:
    movzx eax,byte [r8+xhci_intr_ep.completed]
    test eax,eax
    jz .count
    bts qword [rdi+112],r10
    or r15d,1
    cmp eax,1
    jbe .count
    or r15d,2
.count:
    movzx eax,word [r8+XHCI_ISOB_COUNT]
    test eax,0x8000
    jz .count_low
    bts qword [rdi+144],r10            ; rolling mode alone is not packet work
.count_low:
    and eax,0x7fff
    test eax,eax
    jz .left
    bts qword [rdi+120],r10
    or r15d,1
    cmp eax,8
    jbe .left
    or r15d,2
.left:
    movzx eax,word [r8+XHCI_ISOB_LEFT]
    test eax,eax
    jz .decide
    bts qword [rdi+128],r10
    or r15d,1
    cmp eax,8
    jbe .decide
    or r15d,2
.decide:
    test r15d,1
    jz .validity
    cmp byte [r8+xhci_intr_ep.configured],3
    jne .validity
    or r15d,2                        ; stopped + work is contradictory
.validity:
    test r15d,2
    jz .work
    bts qword [rdi+136],r10
    mov dword [rdi+8],3
    jmp .next_endpoint
.work:
    test r15d,1
    jz .next_endpoint
    cmp dword [rdi+8],3
    je .next_endpoint
    mov dword [rdi+8],2
.next_endpoint:
    inc r10d
    add r8,xhci_intr_ep_size
    mov [rdi+36],r10d
    jmp .endpoint
.scanned:
    mov dword [rdi+12],7
    cmp dword [rdi+8],3
    je .unknown_image
    cmp dword [rdi+8],2
    jne .next_image
    test r12d,r12d
    jnz .next_image
    mov r12d,2
    jmp .next_image
.unknown_image:
    mov r12d,3
.next_image:
    inc ebx
    cmp ebx,r13d
    jb .image
.done:
    mov eax,r12d
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

%include "dev/usb/xhci_terminal.inc"

; xhci_inst_copy_out(RDI = destination image). clobbers RCX, RSI, RDI.
xhci_inst_copy_out:
    cld
    lea  rsi, [rel xhci_inst_r1]
    mov  ecx, xhci_inst_r1_end - xhci_inst_r1
    rep  movsb
    lea  rsi, [rel xhci_inst_r2]
    mov  ecx, xhci_inst_r2_end - xhci_inst_r2
    rep  movsb
    lea  rsi, [rel xhci_inst_r3]
    mov  ecx, xhci_inst_r3_end - xhci_inst_r3
    rep  movsb
    lea  rsi, [rel xhci_inst_r4]
    mov  ecx, xhci_inst_r4_end - xhci_inst_r4
    rep  movsb
    ret

; xhci_inst_copy_in(RSI = source image). clobbers RCX, RSI, RDI.
xhci_inst_copy_in:
    XHCI_POWER_GATE 1
    cld
    lea  rdi, [rel xhci_inst_r1]
    mov  ecx, xhci_inst_r1_end - xhci_inst_r1
    rep  movsb
    lea  rdi, [rel xhci_inst_r2]
    mov  ecx, xhci_inst_r2_end - xhci_inst_r2
    rep  movsb
    lea  rdi, [rel xhci_inst_r3]
    mov  ecx, xhci_inst_r3_end - xhci_inst_r3
    rep  movsb
    lea  rdi, [rel xhci_inst_r4]
    mov  ecx, xhci_inst_r4_end - xhci_inst_r4
    rep  movsb
    ret

; xhci_inst_switch(EDI = controller) — make it the live one. An index that is
;   not a registered controller leaves the live one unchanged.
;   clobbers RAX, RCX, RSI, RDI.
xhci_inst_switch:
    cmp qword [rel reinit_power_xhci_context], 0
    jne .same
    cmp  edi, [rel xhci_inst_cur]
    je   .same
    cmp  edi, [rel xhci_inst_n]
    jae  .same
    push rdx
    mov  edx, edi
    mov  eax, [rel xhci_inst_cur]
    imul eax, eax, XHCI_INST_BYTES
    lea  rdi, [rel xhci_inst_save]
    add  rdi, rax
    call xhci_inst_copy_out
    mov  eax, edx
    imul eax, eax, XHCI_INST_BYTES
    lea  rsi, [rel xhci_inst_save]
    add  rsi, rax
    call xhci_inst_copy_in
    mov  [rel xhci_inst_cur], edx
    pop  rdx
.same:
    ret

; One thunk per (controller, op): preserves every argument register.
%macro XHCI_THUNK 2
%%start:
    push rdi
    push rsi
    push rcx
    mov  edi, %1
    call xhci_inst_switch
    pop  rcx
    pop  rsi
    pop  rdi
    jmp  %2
    times XHCI_THUNK_SZ - ($ - %%start) db 0xCC
%endmacro
%macro XHCI_THUNK_ROW 1
    XHCI_THUNK %1, xhci_op_port_status
    XHCI_THUNK %1, xhci_op_control
    XHCI_THUNK %1, xhci_op_bulk_in
    XHCI_THUNK %1, xhci_op_bulk_out
    XHCI_THUNK %1, xhci_op_interrupt_in_configure
    XHCI_THUNK %1, xhci_op_interrupt_in_queue
    XHCI_THUNK %1, xhci_op_interrupt_in_poll
    XHCI_THUNK %1, xhci_op_bulk_in_poll
    XHCI_THUNK %1, xhci_op_hub_configure
    XHCI_THUNK %1, xhci_op_hub_address_child
    XHCI_THUNK %1, xhci_op_topology
    XHCI_THUNK %1, xhci_op_interrupt_ss_configure
%endmacro
align 32
xhci_thunks:
    XHCI_THUNK_ROW 0
    XHCI_THUNK_ROW 1
    XHCI_THUNK_ROW 2
    XHCI_THUNK_ROW 3

; xhci_bring_up_others — after the original selection (successful or failed):
;   seed backend zero too when no controller succeeded. Every other candidate the
;   probe could read (conn != na) gets a fresh state image (the pristine boot
;   template), its own page-aligned heap DMA set + transfer extent, the same
;   bring-up (no relocation), a marker and its own backend. A controller that
;   fails is discarded and the previous live image restored. Bounded by
;   XHCI_CAND_MAX candidates and XHCI_INST_MAX controllers. clobbers: c-s.
xhci_bring_up_others:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r12d, r12d                  ; candidate index
.cand:
    cmp  r12d, [rel xhci_cand_n]
    jae  .done
    cmp  dword [rel xhci_inst_n], XHCI_INST_MAX
    jae  .done
    cmp  r12d, [rel xhci_sel_chosen]
    je   .next                       ; original selection, even if backend zero changed
    imul ebx, r12d, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    add  rbx, rcx
    cmp  dword [rbx + XC_CONN], -1
    je   .next                       ; unreadable: never touched
    mov  edi, XHCI_DS_TOTAL + 4095
    call kmalloc
    test rax, rax
    jz   .next
    add  rax, 4095
    and  rax, -4096
    mov  r13, rax                    ; this controller's DMA set
    mov  r15, rax                    ; bump heap: never freed, including uncertain discard
    mov  r14d, [rel xhci_inst_cur]   ; park the live controller
    mov  eax, r14d
    imul eax, eax, XHCI_INST_BYTES
    lea  rdi, [rel xhci_inst_save]
    add  rdi, rax
    call xhci_inst_copy_out
    lea  rsi, [rel xhci_inst_template]
    call xhci_inst_copy_in
    mov  eax, [rel xhci_inst_n]
    mov  [rel xhci_inst_cur], eax
    shl  eax, 24                     ; disjoint generations: a completion can never be
    mov  [rel xhci_generation], eax  ; credited to another controller's endpoint
    mov  [rel xhci_dma_set], r13
    lea  rax, [r13 + XHCI_DS_BYTES]
    mov  [rel xhci_xfer_dma], rax    ; the transfer extent comes with the set (not the DMA pool)
    mov  eax, [rbx + XC_BUS]
    mov  [rel xhci_bus], eax
    mov  eax, [rbx + XC_DEV]
    mov  [rel xhci_dev], eax
    mov  eax, [rbx + XC_FN]
    mov  [rel xhci_fn], eax
    mov  eax, [rbx + XC_CONN]
    mov  [rel xhci_bring_conn], eax
    xor  edi, edi
    call xhci_bringup
    test eax, eax
    jnz  .discard
    call xhci_register               ; the enum registry must take it, or it is discarded
    test eax, eax
    jnz  .discard
    lea  rdi, [rel xhci_bus]         ; RCQ-29 hardware report: this controller is driven
    mov  ecx, PCI_DRV_XHCI
    mov  r8d, PCI_CLAIM_BOUND
    call pci_claim_bdf3
    mov  eax, [rel xhci_inst_n]
    lea  rcx, [rel xhci_inst_cand]
    mov  [rcx + rax*4], r12d
    inc  dword [rel xhci_inst_n]
    call xhci_inst_up_marker
    jmp  .next
.discard:
    lea  rdi, [rel xhci_bus]         ; still this candidate's BDF: bring-up or register failed
    mov  ecx, PCI_DRV_XHCI
    mov  r8d, PCI_CLAIM_FAILED
    call pci_claim_bdf3
    cmp  dword [rel xhci_firmware_ready], 1
    jne  .restore_unacquired
    call xhci_discard_live           ; retain acquired failure before restoring healthy image
.restore_unacquired:
    mov  eax, r14d
    imul eax, eax, XHCI_INST_BYTES
    lea  rsi, [rel xhci_inst_save]
    add  rsi, rax
    call xhci_inst_copy_in
    mov  [rel xhci_inst_cur], r14d
.next:
    inc  r12d
    jmp  .cand
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Failed-init custody belongs to the original attempt, not the current LIVE
; image or registry count. No entry is recycled, including across selftest calls.
XHCI_DISCARD_BYTES equ 160
; xhci_discard_owner_at(EDI=index) -> RAX immutable original160B entry or0,
; EDX retained count, ECX sticky overflow/invalid header. Pure RAM, no authority.
; Incomplete entry also returns0. ABI/validity bits: XHCI_DISCARD_OWNER.md.
xhci_discard_owner_at:
    mov edx, [rel xhci_discard_n]
    mov ecx, [rel xhci_discard_overflow]
    xor eax, eax
    cmp edx, XHCI_CAND_MAX
    ja .bad_header
    cmp edi, edx
    jae .out
    imul edi, XHCI_DISCARD_BYTES
    lea rax, [rel xhci_discard_owners]
    add rax, rdi
    cmp dword [rax], 1
    je .out
    xor eax, eax
    ret
.bad_header:
    mov ecx, 1
.out:
    ret

; Original failed-init cleanup: same halt/IRQ/BME requests and200poll bound.
; Capture BEFORE every caller drops n or restores an image. Every claimed read
; has actual acceptance, HCH timeout is distinct, PCI requested != observed.
; RAX reports BME result only (0 observed off,2 observed on,3 unavailable).
; This historical result never asserts a general terminal halt/current safety.
xhci_discard_live:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    mov eax, [rel xhci_discard_n]
    lea r12, [rel xhci_discard_scratch]
    cmp eax, XHCI_CAND_MAX
    jae .overflow
    imul eax, XHCI_DISCARD_BYTES
    lea r12, [rel xhci_discard_owners]
    add r12, rax
    inc dword [rel xhci_discard_n] ; reserve unpublished original owner
    jmp .capture
.overflow:
    mov dword [rel xhci_discard_overflow], 1 ; never overwrite a retained owner
.capture:
    mov rdi, r12
    mov ecx, XHCI_DISCARD_BYTES / 8
    xor eax, eax
    rep stosq
    mov dword [r12 + 4], -1       ; no authenticated original candidate yet
    mov dword [r12 + 96], 3       ; halt unavailable, not zero-filled success
    mov dword [r12 + 100], 3      ; PCI BME unavailable
    mov eax, [rel xhci_bus]
    mov [r12 + 8], eax
    mov eax, [rel xhci_dev]
    mov [r12 + 12], eax
    mov eax, [rel xhci_fn]
    mov [r12 + 16], eax
    mov eax, [rel xhci_generation]
    mov [r12 + 24], eax
    mov eax, [rel xhci_init_phase]
    mov [r12 + 28], eax
    mov rax, [rel xhci_region + HAL_R_BAR_BASE]
    mov [r12 + 32], rax
    mov rax, [rel xhci_region + HAL_R_BAR_SIZE]
    mov [r12 + 40], rax
    mov rax, [rel xhci_dma_set]
    mov [r12 + 48], rax
    mov rax, [rel xhci_xfer_dma]
    mov [r12 + 56], rax
    mov eax, [rel xhci_inst_cur]
    mov [r12 + 104], eax
    mov eax, [rel xhci_inst_n]
    mov [r12 + 108], eax
    cmp dword [r12 + 8], 255
    ja .owner_unknown
    cmp dword [r12 + 12], 31
    ja .owner_unknown
    cmp dword [r12 + 16], 7
    ja .owner_unknown
    mov ecx, [rel xhci_cand_n]
    cmp ecx, XHCI_CAND_MAX
    ja .owner_unknown
    xor ebx, ebx
    lea r13, [rel xhci_cand]
.candidate:
    cmp ebx, ecx
    jae .owner_unknown
    mov eax, [r12 + 8]
    cmp eax, [r13 + XC_BUS]
    jne .next_candidate
    mov eax, [r12 + 12]
    cmp eax, [r13 + XC_DEV]
    jne .next_candidate
    mov eax, [r12 + 16]
    cmp eax, [r13 + XC_FN]
    jne .next_candidate
    mov [r12 + 4], ebx
    mov eax, [r13 + XC_VENDEV]
    mov [r12 + 20], eax
    mov rax, [r13 + XC_BAR]
    mov [r12 + 112], rax
    call .identity
    jc .pci_unknown
    or dword [r12 + 64], 1
    mov ecx, 4
    call .pci_read
    cmp eax, -1
    je .pci_unknown
    mov [r12 + 84], eax
    or dword [r12 + 64], 1 << 9
    test eax, 2                    ; MMIO requires current Memory Space Enable
    jz .bus_master
    cmp qword [r12 + 32], 0
    je .bus_master                 ; original attempt failed before mapping
    mov ecx, 0x10
    call .pci_read
    mov [r12 + 136], eax
    and eax, 15
    cmp eax, 4                     ; native mapped64-bit memory BAR, never IO
    jne .bar_unknown
    mov ecx, 0x14
    call .pci_read
    mov [r12 + 140], eax
    shl rax, 32
    mov edx, [r12 + 136]
    and edx, ~15
    or rax, rdx
    mov [r12 + 120], rax
    cmp rax, [r12 + 32]
    jne .bar_unknown
    mov rdx, [r12 + 40]
    test rdx, rdx
    jz .bar_unknown
    add rax, rdx
    jc .bar_unknown
    or dword [r12 + 64], 1 << 1
    mov esi, [rel xhci_op]
    cmp esi, 0x20
    jb .bus_master
    cmp esi, 0xFC
    ja .bus_master
    test esi, 3
    jnz .bus_master
    lea rax, [rsi + XHCI_USBSTS + 4]
    cmp rax, [r12 + 40]
    ja .bus_master
    call xh_rd
    jc .hal_command_unknown
    cmp eax, -1
    je .hal_command_unknown
    mov [r12 + 72], eax
    or dword [r12 + 64], 1 << 2
    and  eax, ~(XHCI_USBCMD_RS | XHCI_USBCMD_INTE)
    mov edx, eax
    mov esi, [rel xhci_op]
    call xh_wr
    jc .hal_command_unknown
    or dword [r12 + 64], 1 << 3
    mov ebx, 200
.wait_halt:
    mov esi, [rel xhci_op]
    add esi, XHCI_USBSTS
    inc dword [r12 + 68]            ; actual bounded attempted status reads
    call xh_rd
    jc .hal_command_unknown
    cmp eax, -1
    je .hal_command_unknown
    mov [r12 + 76], eax
    or dword [r12 + 64], 1 << 4
    test eax, XHCI_USBSTS_HCH
    jnz .halt_observed
    mov edi, 1000
    call tsc_delay_us
    dec ebx
    jnz .wait_halt
    or dword [r12 + 64], 1 << 6
    mov dword [r12 + 96], 2         ; all200 accepted reads lacked HCH
    jmp .irq
.halt_observed:
    or dword [r12 + 64], 1 << 5
    mov dword [r12 + 96], 0         ; only an accepted actual HCH read
    jmp .irq
.hal_command_unknown:
    or dword [r12 + 64], 1 << 13
.irq:
    mov esi, [rel xhci_rt]
    test esi, esi
    jz .bus_master
    test esi, 31
    jnz .bus_master
    add rsi, XHCI_IMAN
    lea rax, [rsi + 4]
    cmp rax, [r12 + 40]
    ja .bus_master
    call xh_rd
    jc .hal_irq_unknown
    cmp eax, -1
    je .hal_irq_unknown
    mov [r12 + 80], eax
    or dword [r12 + 64], 1 << 7
    and  eax, ~((1 << 1) | 1)        ; IE off; IP (RW1C) written as 0 is left alone
    mov edx, eax
    mov esi, [rel xhci_rt]
    add rsi, XHCI_IMAN
    call xh_wr
    jc .hal_irq_unknown
    or dword [r12 + 64], 1 << 8
    jmp .bus_master
.hal_irq_unknown:
    or dword [r12 + 64], 1 << 13
    jmp .bus_master
.next_candidate:
    inc ebx
    add r13, XHCI_CAND_SZ
    jmp .candidate
.bar_unknown:
    or dword [r12 + 64], 1 << 16 ; BAR conflict: no unqualified MMIO
.bus_master:
    call .identity                  ; refuse a changed/unavailable PCI owner
    jc .pci_unknown
    mov ecx, 4
    call .pci_read
    cmp eax, -1
    je .pci_unknown
    and  eax, ~0x04                  ; Bus Master Enable off (memory decode untouched)
    or   eax, 0x400                  ; INTx Disable
    and  eax, 0xFFFF                 ; Command only: a zero Status half clears no RW1C bit
    mov [r12 + 88], eax
    mov r8d, eax
    mov edi, [r12 + 8]
    mov esi, [r12 + 12]
    mov edx, [r12 + 16]
    mov ecx, 4
    call pci_cfg_write32
    or dword [r12 + 64], 1 << 10 ; request issued, not an acknowledgement
    mov ecx, 4
    call .pci_read
    mov [r12 + 92], eax
    cmp eax, -1
    je .pci_unknown
    or dword [r12 + 64], 1 << 11
    call .identity
    jc .pci_unknown
    or dword [r12 + 64], 1 << 12
    mov dword [r12 + 100], 2
    test dword [r12 + 92], 4
    jnz .publish
    mov dword [r12 + 100], 0         ; observed original BME off, separate from HCH
    jmp .publish
.owner_unknown:
    or dword [r12 + 64], 1 << 15
    jmp .publish
.pci_unknown:
    or dword [r12 + 64], 1 << 14
.publish:
    mov dword [r12], 1              ; complete before original caller can erase LIVE
    mov eax, [r12 + 100]
    pop r13
    pop r12
    pop rbx
    ret
.identity:
    xor ecx, ecx
    call .pci_read
    mov [r12 + 128], eax
    cmp ax, 0xFFFF
    je .identity_unknown
    test ax, ax
    jz .identity_unknown
    cmp eax, [r12 + 20]
    jne .identity_unknown
    mov ecx, 8
    call .pci_read
    mov [r12 + 132], eax
    shr eax, 8
    cmp eax, 0x0C0330
    jne .identity_unknown
    clc
    ret
.identity_unknown:
    stc
    ret
.pci_read:
    mov edi, [r12 + 8]
    mov esi, [r12 + 12]
    mov edx, [r12 + 16]
    call pci_cfg_read32
    ret

; xhci_conn_of(EAX = candidate index) -> EAX its probed connected-port count,
;   -1 when there is no such probed candidate (legacy path: always settle).
xhci_conn_of:
    XHCI_POWER_GATE 0
    cmp  eax, [rel xhci_cand_n]
    jae  .none
    imul eax, eax, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    mov  eax, [rcx + rax + XC_CONN]
    ret
.none:
    mov  eax, -1
    ret

; "[PAOS64] P2 usb-xhci: instance K up bb:dd.f vvvv:dddd ports=N [usb.xhci.instance.up]"
xhci_inst_up_marker:
    push rbx
    lea  rdi, [rel str_xinst_head]
    call serial_string
    mov  edi, [rel xhci_inst_cur]
    call serial_decimal
    lea  rdi, [rel str_xinst_up]
    call serial_string
    mov  eax, [rel xhci_inst_cur]
    lea  rcx, [rel xhci_inst_cand]
    mov  eax, [rcx + rax*4]
    imul ebx, eax, XHCI_CAND_SZ
    lea  rcx, [rel xhci_cand]
    add  rbx, rcx
    mov  edi, [rbx + XC_BUS]
    mov  esi, 2
    call xhci_sel_hex
    mov  dil, ':'
    call serial_char
    mov  edi, [rbx + XC_DEV]
    mov  esi, 2
    call xhci_sel_hex
    mov  dil, '.'
    call serial_char
    mov  edi, [rbx + XC_FN]
    mov  esi, 1
    call xhci_sel_hex
    mov  dil, ' '
    call serial_char
    movzx edi, word [rbx + XC_VENDEV]
    mov  esi, 4
    call xhci_sel_hex
    mov  dil, ':'
    call serial_char
    movzx edi, word [rbx + XC_VENDEV + 2]
    mov  esi, 4
    call xhci_sel_hex
    lea  rdi, [rel str_xinst_ports]
    call serial_string
    mov  edi, [rel xhci_maxports]
    call serial_decimal
    lea  rdi, [rel str_xinst_tail]
    call serial_string
    pop  rbx
    ret

; xhci_inst_live0 — make controller 0 live, preserving every register.
xhci_inst_live0:
    push rax
    push rcx
    push rsi
    push rdi
    xor  edi, edi
    call xhci_inst_switch
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rax
    ret

; xhci_hc_instance(RDI = usb_hc dev*) -> EAX controller index, -1 if not an
;   xHCI backend. clobbers RCX, RDX.
xhci_hc_instance:
    lea  rax, [rel xhci_hcdev]
    cmp  rdi, rax
    jne  .extra
    xor  eax, eax
    ret
.extra:
    xor  ecx, ecx
.loop:
    lea  eax, [rcx + 1]
    cmp  eax, [rel xhci_inst_n]
    jae  .none
    imul eax, ecx, DEV_SIZE
    lea  rdx, [rel xhci_inst_hcdev]
    add  rdx, rax
    cmp  rdi, rdx
    je   .found
    inc  ecx
    jmp  .loop
.found:
    lea  eax, [rcx + 1]
    ret
.none:
    mov  eax, -1
    ret

; xhci_inst_live_for(RDI = usb_hc dev*) — make the controller that owns RDI
;   live; any other handle leaves the live one unchanged. Preserves every
;   register: shared op entries call it so they never depend on an earlier op
;   (or the thunk) having switched.
xhci_inst_live_for:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    call xhci_hc_instance
    cmp  eax, -1
    je   .keep
    mov  edi, eax
    call xhci_inst_switch
.keep:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; xhci_hid_slot_for_port(RDI = hc dev*, ESI = port) -> EAX slot (0: not an
;   xHCI backend, or no slot), EDX that controller's generation. The HID
;   binder's one seam into the backend; any controller. clobbers: c-s.
xhci_hid_slot_for_port:
    push rsi
    call xhci_hc_instance
    pop  rsi
    cmp  eax, -1
    je   .none
    call xhci_inst_live_for
    call xhci_interrupt_slot_for_port
    mov  edx, [rel xhci_generation]
    ret
.none:
    xor  eax, eax
    xor  edx, edx
    ret

; Read the exact retained parent's downstream port. A complete four-byte hub
; status reply alone proves downstream disconnect; short/stalled reads are unknown.
; RDI=hc dev*, ESI=child token. EAX=1 connected, 0 disconnected, -1 unknown.
xhci_hid_child_connected:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 16
    mov  r12, rdi
    mov  r13d, esi
    call xhci_hc_instance
    cmp  eax, -1
    je   .unknown
    mov  rdi, r12
    call xhci_inst_live_for
    cmp  r13d, [rel xhci_maxports]
    jbe  .unknown
    mov  esi, r13d
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .unknown
    bt   dword [rel xhci_port_quar], r13d
    jc   .unknown
    bt   dword [rel xhci_slot_quar], eax
    jc   .unknown
    shl  eax, 4
    lea  rbx, [rel xhci_slot_topo]
    add  rbx, rax
    mov  eax, r13d
    sub  eax, XHCI_CHILD_ADDR_BASE
    cmp  [rbx + usb_topo.slot], al
    jne  .unknown
    movzx r14d, byte [rbx + usb_topo.parent_port]
    test r14d, r14d
    jz   .unknown
    movzx eax, byte [rbx + usb_topo.parent_slot]
    test eax, eax
    jz   .unknown
    cmp  eax, XHCI_MAX_SLOTS_EN
    ja   .unknown
    lea  rdx, [rel xhci_slot_port]
    mov  esi, [rdx + rax*4]
    mov  r13d, eax
    call xhci_interrupt_slot_for_port
    cmp  eax, r13d
    jne  .unknown
    bt   dword [rel xhci_slot_quar], eax
    jc   .unknown
    bt   dword [rel xhci_port_quar], esi
    jc   .unknown
    mov  r13d, esi                    ; exact parent neutral address
    mov  ecx, eax
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    cmp  [rdx + usb_topo.slot], cl
    jne  .unknown
    cmp  byte [rdx + usb_topo.depth], 5
    jae  .unknown
    cmp  r14b, [rdx + usb_topo.hub_ports]
    ja   .unknown
    test byte [rdx + usb_topo.hub_ctx], 1
    jz   .unknown
    mov  al, [rdx + usb_topo.root]
    cmp  al, [rbx + usb_topo.root]
    jne  .unknown
    movzx edi, al
    test edi, edi
    jz   .unknown
    cmp  edi, [rel xhci_maxports]
    ja   .unknown
    mov  al, [rdx + usb_topo.depth]
    inc  al
    cmp  al, [rbx + usb_topo.depth]
    jne  .unknown
    call xhci_read_portsc_live
    test eax, XHCI_PORTSC_CCS
    jz   .disconnected               ; entire retained root is gone
    mov  rax, 0x00040000000000A3
    mov  [rsp], rax ; hub GET_STATUS, four bytes
    mov  [rsp + 4], r14w
    mov  dword [rsp + 8], 0
    mov  rdi, r12
    mov  rsi, rsp
    mov  edx, r13d
    lea  rcx, [rsp + 8]
    mov  r8d, 4
    call xhci_op_control
    cmp  rax, 4
    jne  .unknown
    mov  eax, [rsp + 8]
    and  eax, 1
    jmp  .out
.disconnected:
    xor  eax, eax
    jmp  .out
.unknown:
    mov  eax, -1
.out:
    add  rsp, 16
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "dev/usb/xhci_root_power.inc"

; Class-owned root retirement. RDI=original hc*, ESI=root port,
; EDX=retained HC generation, RCX=retained 16-byte usb_topo copy.
; EAX=0 confirmed disabled/reclaimed, 1 refused/unknown. Unlike the legacy HID
; helper, an empty map is not a new retirement observation. Caller has exclusive
; device/class custody and consumes its retained incarnation before offering;
; HC generation/topology alone are not an incarnation nonce after slot reuse.
; Root leaf only: no hub/child inference and no controller reset/health clear.
xhci_device_root_retire:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    test r15, r15
    jz   .fail
    test r14d, r14d
    jz   .fail
    call xhci_hc_instance
    cmp  eax, -1
    je   .fail
    mov  rdi, r12
    call xhci_inst_live_for
    cmp  r14d, [rel xhci_generation]
    jne  .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, [rel xhci_maxports]
    ja   .fail
    cmp  r13d, XHCI_PORT_COUNT
    jae  .fail
    mov  esi, r13d
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  ebx, eax
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    cmp  [rdx + usb_topo.slot], bl
    jne  .fail
    cmp  [rdx + usb_topo.root], r13b
    jne  .fail
    cmp  byte [rdx + usb_topo.depth], 0
    jne  .fail
    cmp  dword [rdx + usb_topo.parent_slot], 0
    jne  .fail
    cmp  dword [rdx + usb_topo.route], 0
    jne  .fail
    cmp  word [rdx + usb_topo.hub_ports], 0
    jne  .fail
    mov  rax, [rdx]
    cmp  rax, [r15]
    jne  .fail
    mov  rax, [rdx + 8]
    cmp  rax, [r15 + 8]
    jne  .fail
    mov  rdi, r12
    mov  esi, r13d
    call xhci_hid_root_retire       ; positive disconnect + exact Disable Slot fence
    jmp  .out
.fail:
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Retire an unplugged root device on its own controller. Only a confirmed
; Disable Slot permits clearing DMA endpoint storage and the reciprocal maps.
; A failed disable retains that storage and quarantines both owners until reset.
; Connected/unknown ports, unknown HCs and quarantined owners are never disabled.
; Child teardown requires its exact parent port status; no hub re-enumeration.
; RDI=hc dev*, ESI=root port or child token. EAX=0 retired/already empty, 1 refused.
; On success EDX=0 root /1 child, so only roots earn reconnect records.
xhci_hid_root_retire:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r14d, esi
    call xhci_hc_instance
    cmp  eax, -1
    je   .fail
    mov  rdi, r12
    call xhci_inst_live_for
    test r14d, r14d
    jz   .fail
    cmp  r14d, [rel xhci_maxports]
    ja   .child
    cmp  r14d, XHCI_PORT_COUNT
    jae  .fail
    bt   dword [rel xhci_port_quar], r14d
    jc   .fail
    mov  edi, r14d
    call xhci_read_portsc_live
    test eax, XHCI_PORTSC_CCS
    jnz  .fail
    jmp  .resolve
.child:
    mov  rdi, r12
    mov  esi, r14d
    call xhci_hid_child_connected
    test eax, eax
    jnz  .fail
.resolve:
    mov  esi, r14d
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .empty
    mov  ebx, eax
    bt   dword [rel xhci_slot_quar], ebx
    jc   .fail
    xor  edi, edi
    mov  esi, (XHCI_TRB_DISABLE_SLOT << 10)
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .quarantine
    ; Hardware can no longer consume this slot's endpoint rings. Clear only
    ; its live transfer states; peer slots and the controller generation stay.
    lea  r12, [rel xhci_intr_states]
    mov  r13d, XHCI_INTR_STATE_COUNT
.endpoint:
    cmp  byte [r12 + xhci_intr_ep.active], 1
    jne  .next
    cmp  byte [r12 + xhci_intr_ep.slot], bl
    jne  .next
    mov  rdi, r12
    call xhci_interrupt_release_state
.next:
    add  r12, xhci_intr_ep_size
    dec  r13d
    jnz  .endpoint
    call xhci_slot_reclaim
.empty:
    xor  edx, edx
    cmp  r14d, [rel xhci_maxports]
    seta dl
    xor  eax, eax
    jmp  .out
.quarantine:
    bts  dword [rel xhci_slot_quar], ebx
    bts  dword [rel xhci_port_quar], r14d
.fail:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_hub_port_available(RDI=hc, ESI=parent token, EDX=port,
; ECX=retained generation, R8=retained parent topology) -> EAX1/0.
; Read-only native custody gate before downstream reset. Even a child whose
; descriptor was refused still owns its route; quarantine never earns a retry.
xhci_hub_port_available:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, r8
    mov  [rsp], ecx
    test r15, r15
    jz   .fail
    call xhci_hc_instance
    cmp  eax, -1
    je   .fail
    mov  rdi, r12
    call xhci_inst_live_for
    mov  eax, [rel xhci_generation]
    cmp  eax, [rsp]
    jne  .fail
    cmp  dword [rel xhci_slot_quar], 0
    jne  .fail                      ; unresolved DMA custody on this controller
    mov  esi, r13d
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    bt   dword [rel xhci_port_quar], r13d
    jc   .fail
    mov  ebx, eax
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    cmp  [rdx + usb_topo.slot], bl
    jne  .fail
    mov  rax, [rdx]
    cmp  rax, [r15]
    jne  .fail
    mov  rax, [rdx + 8]
    cmp  rax, [r15 + 8]
    jne  .fail
    test byte [r15 + usb_topo.hub_ctx], 1
    jz   .fail
    cmp  byte [r15 + usb_topo.depth], 5
    jae  .fail
    test r14d, r14d
    jz   .fail
    cmp  r14d, 15
    ja   .fail
    cmp  r14b, [r15 + usb_topo.hub_ports]
    ja   .fail
    mov  edi, [r15 + usb_topo.route]
    movzx esi, byte [r15 + usb_topo.depth]
    mov  edx, r14d
    call usb_hub_route_extend
    test rax, rax
    js   .fail
    and  eax, 0x000fffff
    mov  [rsp + 4], eax
    movzx edi, byte [r15 + usb_topo.root]
    test edi, edi
    jz   .fail
    cmp  edi, [rel xhci_maxports]
    ja   .fail
    call xhci_read_portsc_live
    test eax, XHCI_PORTSC_CCS
    jz   .fail
    lea  r8, [rel xhci_slot_port]
    lea  r9, [rel xhci_slot_topo + usb_topo_size]
    mov  ecx, 1
.scan:
    cmp  ecx, XHCI_MAX_SLOTS_EN
    ja   .available
    cmp  dword [r8 + rcx*4], 0
    je   .next
    cmp  [r9 + usb_topo.slot], cl
    jne  .fail                      ; inconsistent owner is never free space
    mov  al, [r15 + usb_topo.root]
    cmp  al, [r9 + usb_topo.root]
    jne  .next
    mov  eax, [rsp + 4]
    cmp  [r9 + usb_topo.route], eax
    je   .fail
.next:
    add  r9, usb_topo_size
    inc  ecx
    jmp  .scan
.available:
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_hc_generation(RDI = hc dev*) -> EAX that controller's generation
;   (0xFFFFFFFF if not an xHCI backend), without making it live.
;   clobbers RCX, RDX.
xhci_hc_generation:
    call xhci_hc_instance
    cmp  eax, -1
    je   .unknown
    cmp  eax, [rel xhci_inst_cur]
    jne  .saved
    mov  eax, [rel xhci_generation]
    ret
.saved:
    imul eax, eax, XHCI_INST_BYTES
    lea  rcx, [rel xhci_inst_save]
    add  rcx, rax
    mov  eax, [rcx + (xhci_generation - xhci_inst_r1)]
    ret
.unknown:
    mov  eax, -1
    ret

xhci_op_noop:
    xor  eax, eax
    ret

; Resolve a neutral root-hub port to retained slot ownership. Both ownership
; directions must agree so endpoint ops cannot resurrect a stale cache.
xhci_interrupt_slot_for_port:
    test esi, esi
    jz   .none
    cmp  esi, XHCI_PORT_COUNT - 1
    ja   .none
    cmp  esi, [rel xhci_maxports]
    jbe  .lookup                     ; every live root port: unchanged path
    cmp  esi, XHCI_CHILD_ADDR_BASE   ; HUB0 hub-child token range only
    jb   .none
    cmp  esi, XHCI_CHILD_ADDR_LIMIT
    jae  .none
    cmp  dword [rel xhci_maxports], XHCI_CHILD_ADDR_BASE
    jae  .none                       ; tokens never alias a root port
.lookup:
    lea  rdx, [rel xhci_port_slot]
    mov  eax, [rdx + rsi*4]
    test eax, eax
    jz   .none
    cmp  eax, XHCI_MAX_SLOTS_EN
    ja   .none
    lea  rdx, [rel xhci_slot_port]
    cmp  [rdx + rax*4], esi
    jne  .none
    ret
.none:
    xor  eax, eax
    ret

xhci_interrupt_find_by_ep:
    lea  r8, [rel xhci_intr_states]
    xor  ecx, ecx
.scan:
    cmp  ecx, XHCI_INTR_STATE_COUNT
    jae  .none
    cmp  byte [r8 + xhci_intr_ep.active], 1
    jne  .next
    cmp  byte [r8 + xhci_intr_ep.slot], sil
    jne  .next
    cmp  byte [r8 + xhci_intr_ep.ep_addr], dl
    je   .found
.next:
    add  r8, xhci_intr_ep_size
    inc  ecx
    jmp  .scan
.found:
    mov  rax, r8
    ret
.none:
    xor  eax, eax
    ret

xhci_interrupt_find_by_dci:
    lea  r8, [rel xhci_intr_states]
    xor  ecx, ecx
.scan:
    cmp  ecx, XHCI_INTR_STATE_COUNT
    jae  .none
    cmp  byte [r8 + xhci_intr_ep.active], 1
    jne  .next
    cmp  byte [r8 + xhci_intr_ep.slot], sil
    jne  .next
    cmp  byte [r8 + xhci_intr_ep.dci], dl
    je   .found
.next:
    add  r8, xhci_intr_ep_size
    inc  ecx
    jmp  .scan
.found:
    mov  rax, r8
    ret
.none:
    xor  eax, eax
    ret

xhci_interrupt_owner_by_trb:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    lea  rbx, [rel xhci_intr_states]
    xor  r13d, r13d
.scan:
    cmp  r13d, XHCI_INTR_STATE_COUNT
    jae  .none
    cmp  byte [rbx + xhci_intr_ep.active], 1
    jne  .next
    cmp  byte [rbx + xhci_intr_ep.pending], 1
    jne  .next
    mov  rdi, rbx
    mov  rsi, r12
    call xhci_interrupt_pointer_in_pending_td
    cmp  eax, 1
    je   .found
.next:
    add  rbx, xhci_intr_ep_size
    inc  r13d
    jmp  .scan
.found:
    mov  rax, rbx
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Identify structural ownership of a transfer-TRB address without accepting
; its contents.  The event router uses this only after full validation fails,
; so it can distinguish a stale cycle/generation from a wrong slot or DCI
; without consuming the hostile completion.  RDI=state, RSI=TRB -> EAX=1/0.
xhci_interrupt_pointer_in_pending_td:
    mov  r8, [rdi + xhci_intr_ep.pending_first_trb]
    test r8, r8
    jz   .invalid
    movzx ecx, word [rdi + xhci_intr_ep.segments]
    test ecx, ecx
    jz   .invalid
    mov  r9, [rdi + xhci_intr_ep.ring]
    lea  r10, [r9 + (XHCI_INTR_RING_TRBS - 1) * 16]
.scan:
    cmp  r8, rsi
    je   .valid
    add  r8, 16
    cmp  r8, r10
    jne  .next
    mov  r8, r9
.next:
    dec  ecx
    jnz  .scan
.invalid:
    xor  eax, eax
    ret
.valid:
    mov  eax, 1
    ret

; Validate that an event's transfer-TRB pointer names one current member of
; the pending TD, including a member after a cycle-toggling Link TRB.
; RDI=state, RSI=event transfer TRB -> EAX=1/0.
;   On EAX=1 also: R8D = bytes of the TD members BEFORE the named TRB (its byte
;   offset within the TD), R9D = the named TRB's own TRB Transfer Length. The
;   completion handler needs both: an IN short-packet event reports the residual of
;   THE TRB IT FIRED ON, so the TD's transferred count is R8D + (R9D - residual) —
;   `exact_len - residual` is only right for a single-TRB TD.
xhci_interrupt_event_in_pending_td:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    xor  r8d, r8d                    ; byte offset accumulator
    xor  r9d, r9d
    mov  rbx, [r12 + xhci_intr_ep.pending_first_trb]
    test rbx, rbx
    jz   .invalid
    movzx r14d, word [r12 + xhci_intr_ep.segments]
    test r14d, r14d
    jz   .invalid
    mov  edx, [r12 + xhci_intr_ep.pending_first_cycle]
.scan:
    cmp  rbx, r13
    je   .candidate
    mov  eax, [rbx + 8]
    and  eax, 0x1FFFF                ; this earlier member's TRB Transfer Length
    add  r8d, eax
    add  rbx, 16
    mov  rax, [r12 + xhci_intr_ep.ring]
    lea  rcx, [rax + (XHCI_INTR_RING_TRBS - 1) * 16]
    cmp  rbx, rcx
    jne  .next
    mov  rbx, rax
    xor  edx, 1
.next:
    dec  r14d
    jnz  .scan
    jmp  .invalid
.candidate:
    mov  eax, [rbx + 12]
    mov  ecx, eax
    shr  ecx, 10
    and  ecx, 0x3F
    cmp byte [r12+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .normal_type
    cmp word [r12+xhci_intr_ep.segments],1
    jne .invalid
    cmp ecx,XHCI_TRB_ISOC
    jne .invalid
    jmp .type_valid
.normal_type:
    cmp  ecx, XHCI_TRB_NORMAL
    jne  .invalid
.type_valid:
    and  eax, 1
    cmp  eax, edx
    jne  .invalid
    mov  r9d, [rbx + 8]
    and  r9d, 0x1FFFF                ; the named TRB's own length
    mov  eax, 1
    jmp  .out
.invalid:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Allocate from the selected slot's fixed two-owner slice. Existing address
; ownership is returned unchanged.
xhci_interrupt_get_or_alloc:
    XHCI_POWER_GATE 1
    test esi, esi
    jz   .none
    cmp  esi, XHCI_MAX_SLOTS_EN
    ja   .none
    test dl, USB_EP_DIR_IN
    jz   .none
    mov  eax, edx
    and  eax, USB_EP_NUM_MASK
    jz   .none
    mov  r8d, esi
    dec  r8d
    imul r8d, XHCI_XFER_PER_SLOT
    lea  r9, [rel xhci_intr_states]
    mov  eax, r8d
    imul eax, xhci_intr_ep_size
    add  r9, rax
    xor  r10d, r10d
    xor  ecx, ecx
.scan:
    cmp  ecx, XHCI_INTR_PER_SLOT
    jae  .allocate
    cmp  byte [r9 + xhci_intr_ep.active], 1
    jne  .remember_free
    cmp  byte [r9 + xhci_intr_ep.ep_addr], dl
    je   .found
    jmp  .next
.remember_free:
    test r10, r10
    cmovz r10, r9
.next:
    add  r9, xhci_intr_ep_size
    inc  ecx
    jmp  .scan
.allocate:
    test r10, r10
    jz   .none
    cmp  qword [r10 + xhci_intr_ep.ring], 0
    je   .none
    cmp  qword [r10 + xhci_intr_ep.report], 0
    je   .none
    mov  byte [r10 + xhci_intr_ep.active], 1
    mov  byte [r10 + xhci_intr_ep.configured], 0
    mov  byte [r10 + xhci_intr_ep.pending], 0
    mov  byte [r10 + xhci_intr_ep.completed], 0
    mov  byte [r10 + xhci_intr_ep.slot], sil
    mov  byte [r10 + xhci_intr_ep.ep_addr], dl
    mov  byte [r10 + xhci_intr_ep.attributes], USB_EP_XFER_INTR
    mov  eax, edx
    and  eax, USB_EP_NUM_MASK
    shl  eax, 1
    inc  eax
    mov  [r10 + xhci_intr_ep.dci], al
    mov  dword [r10 + xhci_intr_ep.enqueue], 0
    mov  dword [r10 + xhci_intr_ep.pcs], 1
    mov  eax, [rel xhci_generation]
    mov  [r10 + xhci_intr_ep.generation], eax
    mov  rax, r10
    ret
.found:
    mov  rax, r9
    ret
.none:
    xor  eax, eax
    ret

; Allocate from the bulk half of a slot-local transfer slice. IN and OUT with
; the same endpoint number remain distinct owners because their DCI differs.
xhci_bulk_get_or_alloc:
    XHCI_POWER_GATE 1
    test esi, esi
    jz   .none
    cmp  esi, XHCI_MAX_SLOTS_EN
    ja   .none
    mov  eax, edx
    test al, 0x70
    jnz  .none
    and  eax, USB_EP_NUM_MASK
    jz   .none
    mov  r8d, esi
    dec  r8d
    imul r8d, XHCI_XFER_PER_SLOT
    add  r8d, XHCI_INTR_PER_SLOT
    lea  r9, [rel xhci_intr_states]
    mov  eax, r8d
    imul eax, xhci_intr_ep_size
    add  r9, rax
    xor  r10d, r10d
    xor  ecx, ecx
.scan:
    cmp  ecx, XHCI_BULK_PER_SLOT
    jae  .allocate
    cmp  byte [r9 + xhci_intr_ep.active], 1
    jne  .remember_free
    cmp  byte [r9 + xhci_intr_ep.ep_addr], dl
    je   .found
    jmp  .next
.remember_free:
    test r10, r10
    cmovz r10, r9
.next:
    add  r9, xhci_intr_ep_size
    inc  ecx
    jmp  .scan
.allocate:
    test r10, r10
    jz   .none
    cmp  qword [r10 + xhci_intr_ep.ring], 0
    je   .none
    cmp  qword [r10 + xhci_intr_ep.report], 0
    je   .none
    mov  byte [r10 + xhci_intr_ep.active], 1
    mov  byte [r10 + xhci_intr_ep.configured], 0
    mov  byte [r10 + xhci_intr_ep.pending], 0
    mov  byte [r10 + xhci_intr_ep.completed], 0
    mov  byte [r10 + xhci_intr_ep.slot], sil
    mov  byte [r10 + xhci_intr_ep.ep_addr], dl
    mov  byte [r10 + xhci_intr_ep.attributes], USB_EP_XFER_BULK
    mov  eax, edx
    and  eax, USB_EP_NUM_MASK
    shl  eax, 1
    test dl, USB_EP_DIR_IN
    jz   .dci_ready
    inc  eax
.dci_ready:
    mov  [r10 + xhci_intr_ep.dci], al
    mov  dword [r10 + xhci_intr_ep.enqueue], 0
    mov  dword [r10 + xhci_intr_ep.pcs], 1
    mov  eax, [rel xhci_generation]
    mov  [r10 + xhci_intr_ep.generation], eax
    mov  rax, r10
    ret
.found:
    mov  rax, r9
    ret
.none:
    xor  eax, eax
    ret

; Release a failed configuration while preserving the preassigned non-aliased
; ring/report addresses. The Link TRB returns to PCS=1.
xhci_interrupt_release_state:
    XHCI_POWER_GATE 1
    push rbx
    mov  rbx, rdi
    mov  r8, [rbx + xhci_intr_ep.ring]
    mov  r9, [rbx + xhci_intr_ep.report]
    movzx r10d, word [rbx + xhci_intr_ep.report_capacity]
    mov  rdi, rbx
    mov  ecx, xhci_intr_ep_size / 8
    xor  eax, eax
    rep  stosq
    mov  [rbx + xhci_intr_ep.ring], r8
    mov  [rbx + xhci_intr_ep.report], r9
    mov  [rbx + xhci_intr_ep.report_capacity], r10w
    mov  dword [rbx + xhci_intr_ep.pcs], 1
    mov  eax, [rel xhci_generation]
    mov  [rbx + xhci_intr_ep.generation], eax
    mov  rdi, r8
    mov  ecx, XHCI_INTR_RING_BYTES / 8
    xor  eax, eax
    rep  stosq
    lea  rdi, [r8 + (XHCI_INTR_RING_TRBS - 1) * 16]
    mov  [rdi], r8
    mov  dword [rdi + 8], 0
    mov  dword [rdi + 12], (XHCI_TRB_LINK << 10) | (1 << 1) | 1
    mov  rdi, r9
    mov  ecx, XHCI_INTR_REPORT_BYTES / 8
    cmp  r10d, XHCI_BULK_LARGE_BYTES
    jne  .scrub_report
    mov  ecx, XHCI_BULK_LARGE_BYTES / 8
.scrub_report:
    xor  eax, eax
    rep  stosq
    wbinvd
    pop  rbx
    ret

; Build one private Configure-Endpoint Input Context without touching EP0's
; ring/index/PCS. Existing Output Slot Context fields are copied, and Context
; Entries only grows to the new DCI. ESI=slot, RDX=state -> RAX=context / 0.
xhci_interrupt_build_context:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13d, esi
    mov  r12, rdx
    mov  rax, [rel xhci_in_ctx_base]
    mov  ecx, r13d
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    call xhci_zero_page
    mov  r14, rax
    mov  r15d, [rel xhci_ctxsz]
    mov  rax, [rel xhci_dcbaa]
    mov  rsi, [rax + r13*8]
    test rsi, rsi
    jz   .fail
    mov  rdi, r14
    add  rdi, r15
    mov  ecx, r15d
    shr  ecx, 3
    rep  movsq
    movzx ecx, byte [r12 + xhci_intr_ep.dci]
    mov  eax, 1
    bts  eax, ecx
    mov  [r14 + 4], eax
    mov  eax, [r14 + r15]
    mov  edx, eax
    shr  edx, 27
    cmp  edx, ecx
    jae  .entries_ok
    and  eax, 0x07FFFFFF
    mov  edx, ecx
    shl  edx, 27
    or   eax, edx
    mov  [r14 + r15], eax
.entries_ok:
    mov  eax, ecx
    inc  eax
    imul eax, r15d
    lea  rbx, [r14 + rax]
    movzx edx, byte [r12 + xhci_intr_ep.attributes]
    and  edx, USB_EP_XFER_MASK
    cmp edx,USB_EP_XFER_ISO
    je .iso_interval
    cmp  edx, USB_EP_XFER_BULK
    je   .bulk_interval
    movzx eax, byte [r12 + xhci_intr_ep.interval]
    mov  edx, [r14 + r15]
    shr  edx, 20
    and  edx, 0x0F
    cmp  edx, 3
    jae  .interval_hs_ss
    bsr  eax, eax
    add  eax, 3
    cmp  eax, 10
    jbe  .interval_encoded
    mov  eax, 10
    jmp  .interval_encoded
.interval_hs_ss:
    cmp  eax, 16
    ja   .fail
    dec  eax
.interval_encoded:
    shl  eax, 16
    mov  [rbx], eax
    mov  edx, 7                    ; xHCI interrupt-IN endpoint type
    jmp  .endpoint_type_ready
.iso_interval:
    mov dword [rbx],(3<<16) ; FS one frame = 8 microframes
    mov edx,1             ; xHCI isochronous OUT
    test byte [r12+xhci_intr_ep.ep_addr],USB_EP_DIR_IN
    jz .endpoint_type_ready
    mov edx,5             ; isochronous IN
    jmp .endpoint_type_ready
.bulk_interval:
    mov  dword [rbx], 0           ; bulk endpoints have no service interval
    mov  edx, 2                    ; xHCI bulk-OUT endpoint type
    test byte [r12 + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .endpoint_type_ready
    mov  edx, 6                    ; xHCI bulk-IN endpoint type
.endpoint_type_ready:
    movzx eax, word [r12 + xhci_intr_ep.mps]
    shl  eax, 16
    shl  edx, 3
    cmp byte [r12+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    je .cerr_ready
    or   eax, (3 << 1)
.cerr_ready:
    or   eax, edx
    movzx ecx, byte [r12 + xhci_intr_ep.ss_burst]
    shl  ecx, 8
    or   eax, ecx                    ; Max Burst Size from admitted companion
    mov  [rbx + 4], eax
    mov  rax, [r12 + xhci_intr_ep.ring]
    or   rax, 1
    mov  [rbx + 8], rax
    movzx eax, word [r12 + xhci_intr_ep.mps]
    mov  edx, eax
    cmp  byte [r12 + xhci_intr_ep.attributes], USB_EP_XFER_BULK
    je   .average_ready
    movzx ecx, word [r12 + xhci_intr_ep.ss_payload]
    test ecx, ecx
    cmovnz eax, ecx                 ; SS uses companion budget, USB2 keeps MPS
    shl  eax, 16
    or   eax, edx
.average_ready:
    mov  [rbx + 16], eax
    sfence
    mov  rax, r14
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate a raw interrupt-IN or bulk descriptor, reserve its slot-local owner,
; and build the shared Configure-Endpoint input context. ESI=slot,RDX=desc.
xhci_interrupt_prepare_state:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13d, esi
    mov  r15, rdx
    mov  r12, r15
    test r12, r12
    jz   .fail
    cmp  byte [r12 + usb_endpoint_desc.bLength], usb_endpoint_desc_size
    jb   .fail
    cmp  byte [r12 + usb_endpoint_desc.bDescriptorType], USBD_TYPE_ENDPOINT
    jne  .fail
    movzx edx, byte [r12 + usb_endpoint_desc.bEndpointAddress]
    test dl, 0x70
    jnz  .fail
    mov  eax, edx
    and  eax, USB_EP_NUM_MASK
    jz   .fail
    movzx eax, byte [r12 + usb_endpoint_desc.bmAttributes]
    and  eax, USB_EP_XFER_MASK
    mov  r14d, eax
    cmp  eax, USB_EP_XFER_BULK
    je   .type_ok
    cmp  eax, USB_EP_XFER_INTR
    jne  .fail
    test dl, USB_EP_DIR_IN
    jz   .fail                       ; Task2903 supports interrupt-IN only
    cmp  byte [r12 + usb_endpoint_desc.bInterval], 0
    je   .fail
.type_ok:
    movzx ebx, word [r12 + usb_endpoint_desc.wMaxPacketSize]
    mov  eax, ebx
    shr  eax, 11
    and  eax, 3
    test eax, eax
    jnz  .fail
    and  ebx, 0x07FF
    test ebx, ebx
    jz   .fail
    cmp  ebx, XHCI_INTR_REPORT_BYTES
    ja   .fail
    mov  esi, r13d
    movzx edx, byte [r12 + usb_endpoint_desc.bEndpointAddress]
    call xhci_interrupt_find_by_ep
    test rax, rax
    jz   .allocate
    cmp byte [rax+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    je .fail                       ; ISO uncertainty pins until verified slot retirement
    cmp  byte [rax + xhci_intr_ep.configured], 1
    je   .fail
    mov  rdi, rax
    call xhci_interrupt_release_state
.allocate:
    mov  esi, r13d
    movzx edx, byte [r12 + usb_endpoint_desc.bEndpointAddress]
    cmp  r14d, USB_EP_XFER_BULK
    je   .allocate_bulk
    call xhci_interrupt_get_or_alloc
    jmp  .allocated
.allocate_bulk:
    call xhci_bulk_get_or_alloc
.allocated:
    test rax, rax
    jz   .fail
    mov  r12, rax
    cmp  byte [r12 + xhci_intr_ep.configured], 0
    jne  .fail
    mov  [r12 + xhci_intr_ep.mps], bx
    mov  word [r12 + xhci_intr_ep.ss_payload], 0
    mov  byte [r12 + xhci_intr_ep.ss_burst], 0
    mov  [r12 + xhci_intr_ep.attributes], r14b
    mov  byte [r12 + xhci_intr_ep.interval], 0
    cmp  r14d, USB_EP_XFER_INTR
    jne  .interval_ready
    mov  al, [r15 + usb_endpoint_desc.bInterval]
    mov  [r12 + xhci_intr_ep.interval], al
.interval_ready:
    mov  esi, r13d
    mov  rdx, r12
    call xhci_interrupt_build_context
    test rax, rax
    jz   .release_fail
    mov  rax, r12
    jmp  .out
.release_fail:
    mov  rdi, r12
    call xhci_interrupt_release_state
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Synthetic Configure-Endpoint content oracle. ESI=slot,RDX=state -> 1 only
; when the private context names exactly this DCI/ring/MPS and bounded interval.
xhci_interrupt_context_valid:
    test esi, esi
    jz   .invalid
    cmp  esi, XHCI_MAX_SLOTS_EN
    ja   .invalid
    movzx ecx, byte [rdx + xhci_intr_ep.dci]
    cmp  ecx, 2
    jb   .invalid
    cmp  ecx, 31
    ja   .invalid
    mov  r8, [rel xhci_in_ctx_base]
    mov  eax, esi
    dec  eax
    shl  rax, 12
    add  r8, rax
    mov  eax, 1
    bts  eax, ecx
    cmp  [r8 + 4], eax
    jne  .invalid
    mov  r9d, [rel xhci_ctxsz]
    mov  eax, [r8 + r9]
    shr  eax, 27
    cmp  eax, ecx
    jb   .invalid
    mov  r10d, ecx
    inc  r10d
    imul r10d, r9d
    add  r8, r10
    mov  eax, [r8]
    mov  r11d, eax
    cmp byte [rdx+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    je .iso_interval
    cmp  byte [rdx + xhci_intr_ep.attributes], USB_EP_XFER_BULK
    je   .bulk_interval
    and  eax, 0xFF00FFFF
    jnz  .invalid
    shr  r11d, 16
    and  r11d, 0xFF
    cmp  r11d, 15
    ja   .invalid
    mov  r10d, 7
    jmp  .type_ready
.iso_interval:
    cmp eax,(3<<16)
    jne .invalid
    mov r10d,1
    test byte [rdx+xhci_intr_ep.ep_addr],USB_EP_DIR_IN
    jz .type_ready
    mov r10d,5
    jmp .type_ready
.bulk_interval:
    test eax, eax
    jnz  .invalid
    mov  r10d, 2
    test byte [rdx + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .type_ready
    mov  r10d, 6
.type_ready:
    mov  eax, [r8 + 4]
    mov  r11d, eax
    and  eax, 0xFFFF
    shl  r10d, 3
    cmp byte [rdx+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    je .cerr_ready
    or   r10d, (3 << 1)
.cerr_ready:
    movzx ecx, byte [rdx + xhci_intr_ep.ss_burst]
    shl  ecx, 8
    or   r10d, ecx
    cmp  eax, r10d
    jne  .invalid
    shr  r11d, 16
    movzx ecx, word [rdx + xhci_intr_ep.mps]
    cmp  r11d, ecx
    jne  .invalid
    mov  rax, [rdx + xhci_intr_ep.ring]
    or   rax, 1
    cmp  [r8 + 8], rax
    jne  .invalid
    mov  eax, [r8 + 16]
    mov  r11d, eax
    and  eax, 0xFFFF
    cmp  eax, ecx
    jne  .invalid
    shr  r11d, 16
    cmp  byte [rdx + xhci_intr_ep.attributes], USB_EP_XFER_BULK
    jne  .payload_expected
    test r11d, r11d
    jnz  .invalid
    jmp  .valid
.payload_expected:
    movzx eax, word [rdx + xhci_intr_ep.ss_payload]
    test eax, eax
    cmovnz ecx, eax
    cmp  r11d, ecx
    jne  .invalid
.valid:
    mov  eax, 1
    ret
.invalid:
    xor  eax, eax
    ret

; ABI configure op: resolve the neutral port, build endpoint context fields,
; then issue one real Configure Endpoint command (TRB type 12).
xhci_op_interrupt_in_configure:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, esi
    mov  r13, rdx
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  r12d, eax
    imul eax, usb_topo_size
    lea  rdx, [rel xhci_slot_topo]
    cmp  byte [rdx + rax + usb_topo.speed], USB_SPEED_SUPER
    jne  .legacy_speed_ok
    test r13, r13
    jz   .fail
    movzx eax, byte [r13 + usb_endpoint_desc.bmAttributes]
    and  eax, USB_EP_XFER_MASK
    cmp  eax, USB_EP_XFER_INTR
    je   .fail                      ; SS interrupt needs the explicit companion seam
.legacy_speed_ok:
    mov  esi, r12d
    mov  rdx, r13
    call xhci_interrupt_prepare_state
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  rdi, [rel xhci_in_ctx_base]
    mov  eax, r12d
    dec  eax
    shl  rax, 12
    add  rdi, rax
    mov  esi, (XHCI_TRB_CONFIGURE_ENDPOINT << 10)
    mov  eax, r12d
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, r12d
    jne  .release
    mov  byte [rbx + xhci_intr_ep.configured], 1
    xor  eax, eax
    jmp  .out
.release:
    mov  rdi, rbx
    call xhci_interrupt_release_state
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Explicit SS endpoint + companion seam; legacy configure never reads byte 7.
; Interrupt-IN, period 1..16, MPS 1..1024, 1..3 packets/service, <=3072 bytes.
; Burst > one requires MPS1024. Queues retain their separate exact buffer bound.
; Also non-stream bulk IN/OUT: MPS1024, burst0..15, zero interval/payload.
xhci_op_interrupt_ss_configure:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rdx
    cmp  rcx, 13
    jne  .fail
    test r13, r13
    jz   .fail
    cmp  word [r13], 0x0507
    jne  .fail
    cmp  byte [r13 + 3], USB_EP_XFER_BULK
    je   .bulk_companion
    cmp  byte [r13 + 3], USB_EP_XFER_INTR
    jne  .fail
    test byte [r13 + 2], USB_EP_DIR_IN
    jz   .fail
    cmp  word [r13 + 7], 0x3006
    jne  .fail
    cmp  byte [r13 + 9], 2
    ja   .fail
    cmp  byte [r13 + 10], 0
    jne  .fail
    movzx eax, word [r13 + 4]
    test eax, eax
    jz   .fail
    cmp  eax, 1024
    ja   .fail
    cmp  byte [r13 + 9], 0
    je   .packet_ready
    cmp  eax, 1024
    jne  .fail
.packet_ready:
    movzx ecx, byte [r13 + 9]
    inc  ecx
    imul eax, ecx                    ; checked raw fields bound product to 3072
    jo   .fail
    movzx r14d, word [r13 + 11]
    test r14d, r14d
    jz   .fail
    cmp  r14d, eax
    ja   .fail
    movzx eax, byte [r13 + 6]
    dec  eax
    cmp  eax, 15
    ja   .fail
    jmp  .resolve_slot
.bulk_companion:
    ; Non-stream SS bulk: both directions, MaxPacket1024, MaxBurst0..15.
    ; The 13-byte descriptor+companion is retained until configuration ends.
    ; Unlike interrupt service, bulk has no interval or Max ESIT Payload.
    ; Reuse slot-local bulk owners and the real Configure Endpoint command;
    ; publish no configured state until its exact command result succeeds.
    cmp  word [r13 + 4], 1024
    jne  .fail
    cmp  byte [r13 + 6], 0
    jne  .fail
    cmp  word [r13 + 7], 0x3006
    jne  .fail
    cmp  byte [r13 + 9], 15
    ja   .fail
    cmp  byte [r13 + 10], 0          ; streams/reserved unsupported
    jne  .fail
    cmp  word [r13 + 11], 0
    jne  .fail
    xor  r14d, r14d
.resolve_slot:
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  r12d, eax
    imul eax, usb_topo_size
    lea  rdx, [rel xhci_slot_topo]
    cmp  byte [rdx + rax + usb_topo.speed], USB_SPEED_SUPER
    jne  .fail                      ; addressed slot speed, never bcdUSB inference
    mov  esi, r12d
    mov  rdx, r13
    call xhci_interrupt_prepare_state
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  [rbx + xhci_intr_ep.ss_payload], r14w
    mov  al, [r13 + 9]
    mov  [rbx + xhci_intr_ep.ss_burst], al
    mov  esi, r12d
    mov  rdx, rbx
    call xhci_interrupt_build_context
    test rax, rax
    jz   .release
    mov  rdi, rax
    mov  esi, (XHCI_TRB_CONFIGURE_ENDPOINT << 10)
    mov  eax, r12d
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, r12d
    jne  .release
    mov  byte [rbx + xhci_intr_ep.configured], 1
    xor  eax, eax
    jmp  .out
.release:
    mov  rdi, rbx
    call xhci_interrupt_release_state
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Queue one bounded TD against an endpoint's immutable private payload buffer.
; Interrupt and bulk endpoints share this producer. Small transfers segment on
; MaxPacketSize; large bulk-IN uses one aligned multi-packet Normal TRB. TDs may
; cross a cycle-correct Link TRB. Only the terminal Normal TRB has IOC; IN has ISP.
; xHCI 1.2b 4.11.2.4: TD Size is remaining packets, saturated at 31, terminal 0.
; RDI=state, ESI=exact length, EDX=publish doorbell (0 for synthetic KAT).
xhci_interrupt_queue_state:
    XHCI_POWER_GATE 0
    cmp byte [rdi+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .legacy_transfer
    mov rax,-1                       ; ISO must never be queued as Normal TRBs
    ret
.legacy_transfer:
    ; Attached finite profile admits exactly one Normal TRB per IN TD. This
    ; excludes intermediate short-packet events from halt/drain obligations.
    cmp qword [rel reinit_power_xhci_context], 0
    je .power_profile_ok
    push rax
    push rcx
    lea rax, [rel xhci_intr_states]
    mov ecx, XHCI_INTR_STATE_COUNT
.power_find:
    cmp rdi, rax
    je .power_found
    add rax, xhci_intr_ep_size
    loop .power_find
    jmp .power_refuse
.power_found:
    cmp byte [rdi + xhci_intr_ep.active], 1
    jne .power_refuse
    cmp byte [rdi + xhci_intr_ep.attributes], USB_EP_XFER_INTR
    jne .power_refuse
    test byte [rdi + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz .power_refuse
    movzx eax, word [rdi + xhci_intr_ep.mps]
    cmp esi, eax
    ja .power_refuse
    cmp edx, 1
    jne .power_refuse
    pop rcx
    pop rax
    jmp .power_profile_ok
.power_refuse:
    pop rcx
    pop rax
    mov rax, -1
    ret
.power_profile_ok:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r14d, esi
    mov  r13d, edx
    movzx eax, word [r12 + xhci_intr_ep.ss_payload]
    test eax, eax
    jz   .service_fits
    cmp  r14d, eax
    ja   .fail                      ; exact SS report bounded by admitted service payload
.service_fits:
    cmp  byte [r12 + xhci_intr_ep.configured], 1
    jne  .fail
    cmp  byte [r12 + xhci_intr_ep.pending], 0
    jne  .fail
    cmp  byte [r12 + xhci_intr_ep.completed], 0
    jne  .fail
    test r14d, r14d
    jz   .fail
    cmp  r14d, XHCI_INTR_REPORT_BYTES
    jbe  .small_report
    cmp  r14d, XHCI_BULK_LARGE_BYTES
    ja   .fail
    cmp  byte [r12 + xhci_intr_ep.attributes], USB_EP_XFER_BULK
    jne  .fail
    test byte [r12 + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .fail
    cmp  word [r12 + xhci_intr_ep.report_capacity], XHCI_BULK_LARGE_BYTES
    jne  .fail
    mov  rax, [r12 + xhci_intr_ep.report]
    test rax, rax
    jz   .fail
    test eax, XHCI_BULK_LARGE_ALIGN - 1
    jnz  .fail
    cmp  word [r12 + xhci_intr_ep.mps], 0
    je   .fail
    ; A Normal TRB can contain multiple USB packets. This single aligned span
    ; is <=48KiB, avoiding both the 64KiB boundary and 63-producer ring limit.
    mov  r9d, r14d
    jmp  .packet_quantum_ready
.small_report:
    movzx r9d, word [r12 + xhci_intr_ep.mps]
.packet_quantum_ready:
    test r9d, r9d
    jz   .fail
    mov  eax, r14d
    xor  edx, edx
    div  r9d
    test edx, edx
    jz   .segments_ready
    inc  eax
.segments_ready:
    test eax, eax
    jz   .fail
    cmp  eax, XHCI_INTR_RING_TRBS - 1
    ja   .fail
    mov  r15d, eax
    ; IN receives into a clean bounce buffer. OUT was copied here before queue.
    test byte [r12 + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .payload_ready
    mov  rdi, [r12 + xhci_intr_ep.report]
    mov  ecx, r14d
    xor  eax, eax
    rep  stosb
.payload_ready:
    mov  ebp, [r12 + xhci_intr_ep.enqueue]
    mov  r10d, r14d
    xor  r11d, r11d
    mov  qword [r12 + xhci_intr_ep.pending_first_trb], 0
    mov  dword [r12 + xhci_intr_ep.pending_first_cycle], 0
.segment_loop:
    cmp  ebp, XHCI_INTR_RING_TRBS - 1
    jne  .normal_trb
    mov  rbx, [r12 + xhci_intr_ep.ring]
    lea  rbx, [rbx + (XHCI_INTR_RING_TRBS - 1) * 16]
    mov  eax, (XHCI_TRB_LINK << 10) | (1 << 1)
    or   eax, [r12 + xhci_intr_ep.pcs]
    test r11d, r11d
    jz   .publish_link
    or   eax, (1 << 4)              ; preserve a TD crossing the Link TRB
.publish_link:
    mov  [rbx + 12], eax
    xor  dword [r12 + xhci_intr_ep.pcs], 1
    xor  ebp, ebp
.normal_trb:
    mov  rbx, [r12 + xhci_intr_ep.ring]
    mov  eax, ebp
    shl  eax, 4
    add  rbx, rax
    cmp  qword [r12 + xhci_intr_ep.pending_first_trb], 0
    jne  .first_ready
    mov  [r12 + xhci_intr_ep.pending_first_trb], rbx
    mov  eax, [r12 + xhci_intr_ep.pcs]
    mov  [r12 + xhci_intr_ep.pending_first_cycle], eax
.first_ready:
    mov  rax, [r12 + xhci_intr_ep.report]
    add  rax, r11
    mov  [rbx], rax
    mov  ecx, r10d
    cmp  ecx, r9d
    cmova ecx, r9d
    sub  r10d, ecx
    add  r11d, ecx
    test r10d, r10d
    jz   .td_size_ready             ; terminal Normal TRB always advertises zero
    ; Every nonterminal member ends on MPS (small-report path above).
    ; The one-TRB large-IN path is terminal and never enters this calculation.
    mov  eax, r10d
    xor  edx, edx
    div  r9d
    test edx, edx
    jz   .td_packets_ready
    inc  eax
.td_packets_ready:
    cmp  eax, 31
    jbe  .td_packets_bounded
    mov  eax, 31
.td_packets_bounded:
    shl  eax, 17
    or   ecx, eax
.td_size_ready:
    mov  [rbx + 8], ecx
    mov  eax, (XHCI_TRB_NORMAL << 10)
    or   eax, [r12 + xhci_intr_ep.pcs]
    test byte [r12 + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .short_packet_ready
    or   eax, (1 << 2)              ; ISP on every IN member that can short
.short_packet_ready:
    test r10d, r10d
    jz   .terminal_trb
    or   eax, (1 << 4)              ; CH: this TD continues
    jmp  .store_trb
.terminal_trb:
    or   eax, (1 << 5)              ; IOC exactly once per TD
.store_trb:
    mov  [rbx + 12], eax
    inc  ebp
    test r10d, r10d
    jnz  .segment_loop
    mov  [r12 + xhci_intr_ep.pending_trb], rbx
    mov  [r12 + xhci_intr_ep.exact_len], r14w
    mov  [r12 + xhci_intr_ep.segments], r15w
    mov  eax, [r12 + xhci_intr_ep.generation]
    mov  [r12 + xhci_intr_ep.pending_generation], eax
    mov  eax, [rbx + 12]
    and  eax, 1
    mov  [r12 + xhci_intr_ep.pending_cycle], eax
    mov  byte [r12 + xhci_intr_ep.pending], 1
    mov  [r12 + xhci_intr_ep.enqueue], ebp
    wbinvd
    sfence
    test r13d, r13d
    jz   .count
    mov  esi, [rel xhci_db]
    movzx eax, byte [r12 + xhci_intr_ep.slot]
    lea  esi, [esi + eax*4]
    movzx edx, byte [r12 + xhci_intr_ep.dci]
    call xh_wr
.count:
    inc  qword [rel xhci_intr_queued]
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; RCQ-36 native full-speed ISO packet seam. One owner per direction per slot;
; no class binding or continuous scheduling. Unknown configure completion pins
; the owner until verified slot retirement/controller reset. No timeout replay.
; RDI=xHCI handle,ESI=neutral port,RDX=readable9B USB endpoint descriptor.
xhci_iso_fs_configure:
%if PAOS_LAB_HP_USB184_POOL
    ; The historical pool has only interrupt/bulk records. Refuse before
    ; dereferencing operands, switching instances or reserving an ISO owner.
    mov rax, -1
    ret
%endif
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13d,esi
    mov r14,rdx
    call xhci_hc_instance
    cmp eax,-1
    je .fail
    mov rdi,r12
    call xhci_inst_live_for
    mov esi,r13d
    call xhci_interrupt_slot_for_port
    test eax,eax
    jz .fail
    mov r13d,eax
    imul eax,usb_topo_size
    lea rdx,[rel xhci_slot_topo]
    cmp byte [rdx+rax+usb_topo.speed],USB_SPEED_FULL
    jne .fail
    test r14,r14
    jz .fail
    cmp word [r14],0x0509
    jne .fail
    movzx edx,byte [r14+2]
    test dl,0x70
    jnz .fail
    mov eax,edx
    and eax,15
    jz .fail
    movzx eax,byte [r14+3]
    mov ecx,eax
    and ecx,0xf3
    cmp ecx,1
    jne .fail                     ; data ISO only, no feedback/usage/reserved bits
    shr eax,2
    test eax,eax
    jz .fail
    test dl,0x80
    jnz .sync_ok
    cmp eax,1
    je .fail                     ; async OUT requires a feedback owner
.sync_ok:
    movzx eax,word [r14+4]
    test eax,eax
    jz .fail
    cmp eax,1023
    ja .fail                     ; no high-speed transaction multiplier
    cmp byte [r14+6],1
    jne .fail
    cmp word [r14+7],0
    jne .fail
    mov esi,r13d
    call xhci_interrupt_find_by_ep
    test rax,rax
    jnz .fail                    ; never repurpose any existing endpoint owner
    cmp qword [rel xhci_in_ctx_base],0
    je .fail
    mov rax,[rel xhci_dcbaa]
    test rax,rax
    jz .fail
    mov rax,[rax+r13*8]
    test rax,rax
    jz .fail
    mov eax,[rax]
    shr eax,20
    and eax,15
    cmp eax,USB_SPEED_FULL
    jne .fail
    mov eax,r13d
    dec eax
    imul eax,XHCI_XFER_PER_SLOT
    add eax,XHCI_INTR_PER_SLOT+XHCI_BULK_PER_SLOT
    imul eax,xhci_intr_ep_size
    lea rbx,[rel xhci_intr_states]
    add rbx,rax
    ; Dedicated OUT/IN slots prevent either direction starving the other.
    test byte [r14+2],0x80
    jz .owner_ready
    add rbx,xhci_intr_ep_size
.owner_ready:
    cmp byte [rbx+xhci_intr_ep.active],0
    jne .fail
    cmp qword [rbx+xhci_intr_ep.ring],0
    je .fail
    cmp qword [rbx+xhci_intr_ep.report],0
    je .fail
    mov byte [rbx+xhci_intr_ep.active],1
    mov byte [rbx+xhci_intr_ep.configured],2 ; reserved/uncertain, not queueable
    mov [rbx+xhci_intr_ep.slot],r13b
    mov al,[r14+2]
    mov [rbx+xhci_intr_ep.ep_addr],al
    mov edx,eax
    and eax,15
    shl eax,1
    shr edx,7
    and edx,1
    or eax,edx
    mov [rbx+xhci_intr_ep.dci],al
    mov byte [rbx+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    mov byte [rbx+xhci_intr_ep.interval],1
    mov ax,[r14+4]
    mov [rbx+xhci_intr_ep.mps],ax
    mov eax,[rel xhci_generation]
    mov [rbx+xhci_intr_ep.generation],eax
    mov esi,r13d
    mov rdx,rbx
    call xhci_interrupt_build_context
    test rax,rax
    jz .fail
    mov rdi,rax
    mov esi,(XHCI_TRB_CONFIGURE_ENDPOINT<<10)
    mov eax,r13d
    shl eax,24
    or esi,eax
    call xhci_cmd_submit
    cmp eax,r13d
    jne .fail                    ; retain pinned reserved owner, never clear/replay
    mov byte [rbx+xhci_intr_ep.configured],1
    xor eax,eax
    jmp .out
.fail: mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Resolve only an admitted ISO owner on this handle/port. EDX=endpoint address.
; Returns RAX=state/0. Every public call resolves its own controller.
xhci_iso_fs_owner:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12d,esi
    mov r13d,edx
    cmp edx,255
    ja .none
    call xhci_hc_instance
    cmp eax,-1
    je .none
    mov rdi,rbx
    call xhci_inst_live_for
    mov esi,r12d
    call xhci_interrupt_slot_for_port
    test eax,eax
    jz .none
    mov esi,eax
    mov edx,r13d
    call xhci_interrupt_find_by_ep
    test rax,rax
    jz .none
    cmp byte [rax+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .none
    cmp byte [rax+xhci_intr_ep.configured],1
    jne .none
    mov edx,[rel xhci_generation]
    cmp [rax+xhci_intr_ep.generation],edx
    jne .none
    jmp .out
.none: xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; One full-speed service interval. RDI=handle,ESI=port,EDX=endpoint,
; RCX=OUT bytes (ignored for IN),R8=length1..MPS. 0 queued/-1 refused.
; Bounce snapshot stays pinned through completion/error; caller memory is not DMA.
; Schedule Immediately, one ISO TRB/one packet, IOC, ISP for IN, no retries.
xhci_iso_fs_queue:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov r12,rcx
    mov r13,r8
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp word [rbx+XHCI_ISOB_COUNT],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.pending],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.completed],0
    jne .fail
    cmp dword [rbx+xhci_intr_ep.enqueue],XHCI_INTR_RING_TRBS-1
    ja .fail
    cmp dword [rbx+xhci_intr_ep.pcs],1
    ja .fail
    test r13,r13
    jz .fail
    movzx eax,word [rbx+xhci_intr_ep.mps]
    cmp r13,rax
    ja .fail
    cmp r13,1023
    ja .fail
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jnz .input
    test r12,r12
    jz .fail
    mov rdi,[rbx+xhci_intr_ep.report]
    mov rsi,r12
    mov rcx,r13
    rep movsb
    jmp .payload_ready
.input:
    mov rdi,[rbx+xhci_intr_ep.report]
    mov rcx,r13
    xor eax,eax
    rep stosb
.payload_ready:
    mov edx,[rbx+xhci_intr_ep.enqueue]
    cmp edx,XHCI_INTR_RING_TRBS-1
    jb .producer
    mov rax,[rbx+xhci_intr_ep.ring]
    mov ecx,(XHCI_TRB_LINK<<10)|(1<<1)
    or ecx,[rbx+xhci_intr_ep.pcs]
    mov [rax+(XHCI_INTR_RING_TRBS-1)*16+12],ecx
    xor dword [rbx+xhci_intr_ep.pcs],1
    xor edx,edx
.producer:
    mov r14,[rbx+xhci_intr_ep.ring]
    mov eax,edx
    shl eax,4
    add r14,rax
    inc edx
    mov [rbx+xhci_intr_ep.enqueue],edx
    mov eax,[rbx+xhci_intr_ep.pcs]
    mov [rbx+xhci_intr_ep.pending_cycle],eax
    mov [rbx+xhci_intr_ep.pending_first_cycle],eax
    mov ecx,(XHCI_TRB_ISOC<<10)|(1<<5)|(1<<31)
    or ecx,eax
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .flags_ready
    or ecx,(1<<2)
.flags_ready:
    ; Publish a complete owner before the cycle bit and doorbell are visible.
    mov [rbx+xhci_intr_ep.pending_trb],r14
    mov [rbx+xhci_intr_ep.pending_first_trb],r14
    mov word [rbx+xhci_intr_ep.segments],1
    mov [rbx+xhci_intr_ep.exact_len],r13w
    mov eax,[rbx+xhci_intr_ep.generation]
    mov [rbx+xhci_intr_ep.pending_generation],eax
    mov byte [rbx+xhci_intr_ep.pending],1
    mov rax,[rbx+xhci_intr_ep.report]
    mov [r14],rax
    mov [r14+8],r13d
    sfence
    mov [r14+12],ecx
    wbinvd
    sfence
    mov esi,[rel xhci_db]
    movzx eax,byte [rbx+xhci_intr_ep.slot]
    lea esi,[esi+eax*4]
    movzx edx,byte [rbx+xhci_intr_ep.dci]
    call xh_wr
    inc qword [rel xhci_intr_queued]
    xor eax,eax
    jmp .out
.fail: mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Nonblocking consume: RDI=handle,ESI=port,EDX=endpoint,RCX=IN output,
; R8=capacity,R9=optional16B usb_intr_completion. Returns bytes>=0 ONLY on
; accepted completion (including a zero short packet),-2 pending,-1 refused.
; OUT never copies to caller. No automatic queue/replay, error pins until reset.
xhci_iso_fs_poll:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov r12,rcx
    mov r13,r8
    mov r14,r9
    cmp r13,0x7fffffff
    ja .fail
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp word [rbx+XHCI_ISOB_COUNT],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.completed],1
    je .take
    call xhci_interrupt_drain_once
    cmp byte [rbx+xhci_intr_ep.configured],1
    jne .fail
    cmp byte [rbx+xhci_intr_ep.completed],1
    jne .pending
.take:
    mov eax,[rbx+xhci_intr_ep.completed_len]
    cmp r13,rax
    jb .fail
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .metadata
    test r12,r12
    jz .fail
.metadata:
    test r14,r14
    jz .consume
    mov [r14+usb_intr_completion.length],eax
    mov al,[rbx+xhci_intr_ep.slot]
    mov [r14+usb_intr_completion.slot],al
    mov al,[rbx+xhci_intr_ep.dci]
    mov [r14+usb_intr_completion.dci],al
    mov al,[rbx+xhci_intr_ep.ep_addr]
    mov [r14+usb_intr_completion.ep_addr],al
    mov al,[rbx+xhci_intr_ep.completed_cycle]
    mov [r14+usb_intr_completion.cycle],al
    mov eax,[rbx+xhci_intr_ep.completed_generation]
    mov [r14+usb_intr_completion.generation],eax
    mov eax,[rbx+xhci_intr_ep.completion_sequence]
    mov [r14+usb_intr_completion.sequence],eax
.consume:
    mov rdi,rbx
    mov rsi,r12
    mov edx,r13d
    movzx ecx,byte [rbx+xhci_intr_ep.ep_addr]
    shr ecx,7
    call xhci_bulk_consume_state
    jmp .out
.pending: mov rax,-2
    jmp .out
.fail: mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ISO-only aliases: SS companion fields are unused by full-speed ISO.
XHCI_ISOB_COUNT equ xhci_intr_ep.ss_payload
XHCI_ISOB_INDEX equ xhci_intr_ep.pad_ss
XHCI_ISOB_LEFT  equ xhci_intr_ep.pad_ss+2
XHCI_ISOB_META  equ 1792
; Eight32B records in the private report's final256B:
; trb64,offset32,len32,cycle32,actual32,sequence32,status32(1pending/2done/3error).
; RDI handle,ESI port,EDX endpoint,RCX mapped array of{ptr64,len64},R8 count1..8.
; OUT snapshots all packets, IN ignores ptr. No writes on refusal.
; Rolling mode retains at most capacity=min(8,floor(1792/MPS)) payloads.
; Same packet-array ABI. Only consumed slots may be refilled, never pending DMA.
xhci_iso_fs_stream_queue:
    XHCI_POWER_GATE 1
    mov r9d,1
    jmp xhci_iso_fs_burst_queue.mode
xhci_iso_fs_burst_queue:
    XHCI_POWER_GATE 1
    xor r9d,r9d
.mode:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,176
    mov [rsp+136],r9
    mov r12,rcx
    mov r13,r8
    cmp r13,1
    jb .fail
    cmp r13,8
    ja .fail
    test r12,r12
    jz .fail
    mov rax,r13
    shl rax,4
    add rax,r12
    jc .fail
    dec rax
    shr rax,47
    jnz .fail
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp byte [rbx+xhci_intr_ep.completed],0
    jne .fail
    mov qword [rsp+152],0              ; prior unconsumed credits
    mov qword [rsp+160],0              ; prior consume head
    mov qword [rsp+144],8              ; legacy variable-size burst capacity
    cmp qword [rsp+136],0
    jne .rolling
    cmp word [rbx+XHCI_ISOB_COUNT],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.pending],0
    jne .fail
    jmp .mode_ready
.rolling:
    movzx ecx,word [rbx+xhci_intr_ep.mps]
    test ecx,ecx
    jz .fail
    cmp ecx,1023
    ja .fail
    mov eax,XHCI_ISOB_META
    xor edx,edx
    div ecx
    cmp eax,8
    jbe .capacity
    mov eax,8
.capacity:
    mov [rsp+144],rax
    movzx ecx,word [rbx+XHCI_ISOB_COUNT]
    test ecx,ecx
    jz .fresh_stream
    test ecx,0x8000
    jz .fail                          ; do not steal an unfinished legacy burst
    and ecx,0x7fff
    cmp ecx,eax
    ja .fail
    mov [rsp+152],rcx
    movzx edx,word [rbx+XHCI_ISOB_INDEX]
    cmp edx,eax
    jae .fail
    mov [rsp+160],rdx
    movzx edx,word [rbx+XHCI_ISOB_LEFT]
    cmp edx,ecx
    ja .fail
    jmp .credits
.fresh_stream:
    cmp byte [rbx+xhci_intr_ep.pending],0
    jne .fail
.credits:
    add rcx,r13
    cmp rcx,[rsp+144]
    ja .fail                          ; completed-but-unconsumed is still owned
.mode_ready:
    cmp dword [rbx+xhci_intr_ep.enqueue],XHCI_INTR_RING_TRBS-1
    ja .fail
    cmp dword [rbx+xhci_intr_ep.pcs],1
    ja .fail
    mov [rsp+128],r13
    mov rdi,rsp
    mov rsi,r12
    lea rcx,[r13+r13]
    rep movsq                         ; descriptor snapshot before DMA writes
    xor r10d,r10d
    xor r11d,r11d
.validate:
    mov rax,r10
    shl rax,4
    mov rdx,[rsp+rax]
    mov rax,[rsp+rax+8]
    test rax,rax
    jz .fail
    movzx ecx,word [rbx+xhci_intr_ep.mps]
    cmp rax,rcx
    ja .fail
    cmp rax,1023
    ja .fail
    add r11d,eax
    cmp r11d,XHCI_ISOB_META
    ja .fail
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jnz .valid_one
    test rdx,rdx
    jz .fail
    add rax,rdx                       ; source exclusive end
    jc .fail
    mov rcx,rax
    dec rcx
    shr rcx,47
    jnz .fail
    mov rcx,[rbx+xhci_intr_ep.report]
    cmp rax,rcx
    jbe .check_ring
    add rcx,XHCI_INTR_REPORT_BYTES
    cmp rdx,rcx
    jb .fail
.check_ring:
    mov rcx,[rbx+xhci_intr_ep.ring]
    cmp rax,rcx
    jbe .valid_one
    add rcx,XHCI_INTR_RING_BYTES
    cmp rdx,rcx
    jb .fail
.valid_one:
    cmp qword [rsp+136],0
    je .validated_slot
    mov rax,[rsp+160]
    add rax,[rsp+152]
    add rax,r10
    xor edx,edx
    div qword [rsp+144]
    shl edx,5
    mov rcx,[rbx+xhci_intr_ep.report]
    cmp dword [rcx+rdx+XHCI_ISOB_META+28],0
    jne .fail
.validated_slot:
    inc r10d
    cmp r10,r13
    jb .validate
    mov r15,[rbx+xhci_intr_ep.report]
    xor r12d,r12d                     ; packet index
    xor r13d,r13d                     ; payload offset
    mov r10d,[rbx+xhci_intr_ep.enqueue]
    mov r11d,[rbx+xhci_intr_ep.pcs]
.packet:
    cmp r10d,XHCI_INTR_RING_TRBS-1
    jb .trb
    mov rax,[rbx+xhci_intr_ep.ring]
    mov ecx,(XHCI_TRB_LINK<<10)|(1<<1)
    or ecx,r11d
    mov [rax+(XHCI_INTR_RING_TRBS-1)*16+12],ecx
    xor r11d,1
    xor r10d,r10d
.trb:
    mov r14,[rbx+xhci_intr_ep.ring]
    mov eax,r10d
    shl eax,4
    add r14,rax
    mov eax,r12d
    cmp qword [rsp+136],0
    je .metadata_slot
    mov rax,[rsp+160]
    add rax,[rsp+152]
    add rax,r12
    xor edx,edx
    div qword [rsp+144]
    mov eax,edx
    movzx r13d,word [rbx+xhci_intr_ep.mps]
    imul r13d,eax                     ; fixed private stride, no payload overlap
.metadata_slot:
    shl eax,5
    lea rbp,[r15+rax+XHCI_ISOB_META]
    test r12d,r12d
    jnz .save_packet
    mov [rsp+168],r14                 ; first newly appended TD, not oldest TD
.save_packet:
    mov [rbp],r14
    mov [rbp+8],r13d
    mov [rbp+16],r11d
    mov qword [rbp+20],0
    mov dword [rbp+28],1
    mov eax,r12d
    shl eax,4
    mov rcx,[rsp+rax+8]
    mov [rbp+12],ecx
    lea rdi,[r15+r13]
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jnz .zero
    mov rsi,[rsp+rax]
    rep movsb
    jmp .payload
.zero:
    xor eax,eax
    rep stosb
.payload:
    lea rax,[r15+r13]
    mov [r14],rax
    mov eax,[rbp+12]
    mov [r14+8],eax
    add r13d,eax
    mov ecx,(XHCI_TRB_ISOC<<10)|(1<<5)|(1<<31)
    or ecx,r11d
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .cycle
    or ecx,1<<2
.cycle:
    test r12d,r12d
    jnz .store
    xor ecx,1                         ; hold first TD until batch complete
.store:
    mov [r14+12],ecx
    inc r10d
    inc r12d
    cmp r12,[rsp+128]
    jb .packet
    mov [rbx+xhci_intr_ep.enqueue],r10d
    mov [rbx+xhci_intr_ep.pcs],r11d
    cmp qword [rsp+136],0
    jne .publish_stream
    mov [rbx+XHCI_ISOB_COUNT],r12w
    mov [rbx+XHCI_ISOB_LEFT],r12w
    mov word [rbx+XHCI_ISOB_INDEX],0
    jmp .publish_owner
.publish_stream:
    mov eax,[rsp+152]
    add eax,r12d
    or eax,0x8000
    mov [rbx+XHCI_ISOB_COUNT],ax
    add [rbx+XHCI_ISOB_LEFT],r12w
    mov eax,[rsp+160]
    mov [rbx+XHCI_ISOB_INDEX],ax
.publish_owner:
    mov eax,[rbx+xhci_intr_ep.generation]
    mov [rbx+xhci_intr_ep.pending_generation],eax
    mov r14,[rsp+168]
    mov [rbx+xhci_intr_ep.pending_trb],r14
    mov [rbx+xhci_intr_ep.pending_first_trb],r14
    mov eax,[r14+12]
    and eax,1
    xor eax,1
    mov [rbx+xhci_intr_ep.pending_cycle],eax
    mov [rbx+xhci_intr_ep.pending_first_cycle],eax
    mov word [rbx+xhci_intr_ep.segments],1
    mov byte [rbx+xhci_intr_ep.pending],1
    sfence
    wbinvd
    xor dword [r14+12],1               ; all metadata and later TDs ready
    wbinvd
    sfence
    mov esi,[rel xhci_db]
    movzx eax,byte [rbx+xhci_intr_ep.slot]
    lea esi,[esi+eax*4]
    movzx edx,byte [rbx+xhci_intr_ep.dci]
    call xh_wr
    add [rel xhci_intr_queued],r12
    xor eax,eax
    jmp .out
.fail: mov rax,-1
.out:
    add rsp,176
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Router already resolved controller-local slot/DCI. RDI=state,RSI=event.
; Accept each packet independently so completion consumption cannot block ERDP.
xhci_iso_fs_burst_route_event:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    movzx ecx,word [rbx+XHCI_ISOB_COUNT]
    test ecx,0x8000
    jz .legacy_count
    and ecx,0x7fff
    cmp ecx,1
    jb .invalid
    cmp ecx,8
    ja .invalid
    mov ecx,8                         ; fixed metadata extent, free entries zero
.legacy_count:
    cmp ecx,1
    jb .invalid
    cmp ecx,8
    ja .invalid
    mov eax,[rbx+xhci_intr_ep.generation]
    cmp eax,[rel xhci_generation]
    jne .invalid
    cmp eax,[rbx+xhci_intr_ep.pending_generation]
    jne .invalid
    mov r13,[rbx+xhci_intr_ep.report]
    add r13,XHCI_ISOB_META
    mov rdx,[r12]
.find:
    cmp [r13],rdx
    je .found
    add r13,32
    dec ecx
    jnz .find
    jmp .invalid
.found:
    cmp dword [r13+28],1
    jne .invalid
    mov rax,[rbx+xhci_intr_ep.ring]
    cmp rdx,rax
    jb .invalid
    add rax,(XHCI_INTR_RING_TRBS-1)*16
    cmp rdx,rax
    jae .invalid
    test dl,15
    jnz .invalid
    mov eax,[rdx+12]
    mov ecx,eax
    shr ecx,10
    and ecx,63
    cmp ecx,XHCI_TRB_ISOC
    jne .invalid
    and eax,1
    cmp eax,[r13+16]
    jne .invalid
    mov eax,[r13+12]
    test eax,eax
    jz .invalid
    cmp eax,1023
    ja .invalid
    cmp [rdx+8],eax
    jne .invalid
    mov ecx,[r13+8]
    add ecx,eax
    jc .invalid
    cmp ecx,XHCI_ISOB_META
    ja .invalid
    mov ecx,[r13+8]
    add rcx,[rbx+xhci_intr_ep.report]
    cmp [rdx],rcx
    jne .invalid
    cmp word [rbx+XHCI_ISOB_LEFT],0
    je .invalid
    mov edx,[r12+8]
    mov ecx,edx
    shr ecx,24
    and edx,0x00ffffff
    cmp edx,eax
    ja .invalid
    cmp byte [rbx+xhci_intr_ep.configured],1
    jne .error                        ; drain owned tail after poisoned packet
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jnz .input_code
    cmp ecx,1
    jne .error
    test edx,edx
    jnz .invalid
    jmp .credit
.input_code:
    cmp ecx,1
    je .credit
    cmp ecx,13
    jne .error
.credit:
    sub eax,edx
    mov [r13+20],eax
    inc dword [rbx+xhci_intr_ep.completion_sequence]
    jnz .sequence
    inc dword [rbx+xhci_intr_ep.completion_sequence]
.sequence:
    mov eax,[rbx+xhci_intr_ep.completion_sequence]
    mov [r13+24],eax
    mov dword [r13+28],2
    inc qword [rel xhci_intr_completed]
    mov eax,1
    jmp .retire
.error:
    ; Failed ISO metadata is never credited/consumed; retain the first actual
    ; owned hardware error in its existing actual/sequence words. Poisoned tail
    ; errors leave these words zero, preserving the original event identity.
    cmp byte [rbx+xhci_intr_ep.configured],1
    jne .poisoned
    mov rax,[r12+8]
    mov [r13+20],rax
.poisoned:
    mov byte [rbx+xhci_intr_ep.configured],0
    mov dword [r13+28],3
    inc qword [rel xhci_intr_refused_ep]
    mov eax,XHCI_ROUTE_ERROR_OWNED
.retire:
    dec word [rbx+XHCI_ISOB_LEFT]
    jnz .out
    mov byte [rbx+xhci_intr_ep.pending],0
    jmp .out
.invalid:
    inc qword [rel xhci_intr_refused_cycle]
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Same ABI as single-packet poll. Return next queued packet, not arrival order.
xhci_iso_fs_burst_poll:
    XHCI_POWER_GATE 1
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rcx
    mov r13,r8
    mov r14,r9
    cmp r13,0x7fffffff
    ja .fail
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    test word [rbx+XHCI_ISOB_COUNT],0x8000
    jnz .fail
    cmp word [rbx+XHCI_ISOB_COUNT],0
    je .pending
    call xhci_interrupt_drain_once
    cmp byte [rbx+xhci_intr_ep.configured],1
    jne .fail
    movzx eax,word [rbx+XHCI_ISOB_INDEX]
    cmp ax,[rbx+XHCI_ISOB_COUNT]
    jae .fail
    cmp eax,8
    jae .fail
    shl eax,5
    mov r15,[rbx+xhci_intr_ep.report]
    lea r15,[r15+rax+XHCI_ISOB_META]
    cmp dword [r15+28],2
    jne .pending
    mov ebp,[r15+20]
    cmp r13,rbp
    jb .fail
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .metadata
    test r12,r12
    jz .fail
.metadata:
    test r14,r14
    jz .consume
    mov al,[rbx+xhci_intr_ep.slot]
    mov [r14+usb_intr_completion.slot],al
    mov al,[rbx+xhci_intr_ep.dci]
    mov [r14+usb_intr_completion.dci],al
    mov al,[rbx+xhci_intr_ep.ep_addr]
    mov [r14+usb_intr_completion.ep_addr],al
    mov eax,[r15+16]
    mov [r14+usb_intr_completion.cycle],al
    mov eax,[rbx+xhci_intr_ep.generation]
    mov [r14+usb_intr_completion.generation],eax
    mov eax,[r15+24]
    mov [r14+usb_intr_completion.sequence],eax
    mov [r14+usb_intr_completion.length],ebp
.consume:
    mov esi,[r15+8]
    add rsi,[rbx+xhci_intr_ep.report]
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .scrub
    mov rdi,r12
    mov ecx,ebp
    rep movsb
.scrub:
    mov edi,[r15+8]
    add rdi,[rbx+xhci_intr_ep.report]
    mov ecx,[r15+12]
    xor eax,eax
    rep stosb
    mov dword [r15+28],0
    inc word [rbx+XHCI_ISOB_INDEX]
    mov ax,[rbx+XHCI_ISOB_INDEX]
    cmp ax,[rbx+XHCI_ISOB_COUNT]
    jb .done
    mov word [rbx+XHCI_ISOB_COUNT],0
    mov word [rbx+XHCI_ISOB_INDEX],0
.done:
    mov eax,ebp
    jmp .out
.pending: mov rax,-2
    jmp .out
.fail: mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

xhci_iso_fs_stream_poll:
    XHCI_POWER_GATE 1
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rcx
    mov r13,r8
    mov r14,r9
    cmp r13,0x7fffffff
    ja .fail
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    movzx eax,word [rbx+XHCI_ISOB_COUNT]
    test eax,0x8000
    jz .fail
    and eax,0x7fff
    cmp eax,8
    ja .fail
    test eax,eax
    jz .pending
    call xhci_interrupt_drain_once
    cmp byte [rbx+xhci_intr_ep.configured],1
    jne .fail
    movzx eax,word [rbx+XHCI_ISOB_INDEX]
    cmp eax,8
    jae .fail
    shl eax,5
    mov r15,[rbx+xhci_intr_ep.report]
    lea r15,[r15+rax+XHCI_ISOB_META]
    cmp dword [r15+28],2
    jne .pending
    mov ebp,[r15+20]
    cmp r13,rbp
    jb .fail
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .metadata
    test r12,r12
    jz .fail
.metadata:
    ; The completion receipt and IN copy cannot alias live DMA/metadata/ring.
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .receipt_span
    mov rdi,r12
    mov rsi,rbp
    call xhci_iso_fs_stream_span
    test eax,eax
    jnz .fail
.receipt_span:
    test r14,r14
    jz .consume
    mov rdi,r14
    mov esi,16
    call xhci_iso_fs_stream_span
    test eax,eax
    jnz .fail
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .receipt_ready
    lea rax,[r12+rbp]
    cmp r14,rax
    jae .receipt_ready
    lea rax,[r14+16]
    cmp r12,rax
    jb .fail
.receipt_ready:
    mov al,[rbx+xhci_intr_ep.slot]
    mov [r14+usb_intr_completion.slot],al
    mov al,[rbx+xhci_intr_ep.dci]
    mov [r14+usb_intr_completion.dci],al
    mov al,[rbx+xhci_intr_ep.ep_addr]
    mov [r14+usb_intr_completion.ep_addr],al
    mov eax,[r15+16]
    mov [r14+usb_intr_completion.cycle],al
    mov eax,[rbx+xhci_intr_ep.generation]
    mov [r14+usb_intr_completion.generation],eax
    mov eax,[r15+24]
    mov [r14+usb_intr_completion.sequence],eax
    mov [r14+usb_intr_completion.length],ebp
.consume:
    mov esi,[r15+8]
    add rsi,[rbx+xhci_intr_ep.report]
    test byte [rbx+xhci_intr_ep.ep_addr],0x80
    jz .scrub
    mov rdi,r12
    mov ecx,ebp
    rep movsb
.scrub:
    mov edi,[r15+8]
    add rdi,[rbx+xhci_intr_ep.report]
    mov ecx,[r15+12]
    xor eax,eax
    rep stosb
    mov rdi,r15
    xor eax,eax
    mov ecx,4
    rep stosq                         ; free metadata must not alias old ring TRBs
    dec word [rbx+XHCI_ISOB_COUNT]      ; retain the rolling-mode bit while empty
    movzx ecx,word [rbx+xhci_intr_ep.mps]
    mov eax,XHCI_ISOB_META
    xor edx,edx
    div ecx
    cmp eax,8
    jbe .capacity
    mov eax,8
.capacity:
    movzx edx,word [rbx+XHCI_ISOB_INDEX]
    inc edx
    cmp edx,eax
    jb .head
    xor edx,edx
.head:
    mov [rbx+XHCI_ISOB_INDEX],dx
.done:
    mov eax,ebp
    jmp .out
.pending: mov rax,-2
    jmp .out
.fail: mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; RBX state, RDI caller span, RSI bytes (zero allowed), EAX0/-1.
; Private endpoint state, report and ring remain immutable to caller outputs.
xhci_iso_fs_stream_span:
    test rdi,rdi
    jz .fail
    mov rax,rdi
    add rax,rsi
    jc .fail
    mov rdx,rax
    test rsi,rsi
    jz .canonical
    dec rdx
.canonical:
    shr rdx,47
    jnz .fail
    lea rdx,[rbx+xhci_intr_ep_size]
    cmp rdi,rdx
    jae .report
    cmp rax,rbx
    ja .fail
.report:
    mov rdx,[rbx+xhci_intr_ep.report]
    cmp rax,rdx
    jbe .ring
    add rdx,XHCI_INTR_REPORT_BYTES
    cmp rdi,rdx
    jb .fail
.ring:
    mov rdx,[rbx+xhci_intr_ep.ring]
    cmp rax,rdx
    jbe .ok
    add rdx,XHCI_INTR_RING_BYTES
    cmp rdi,rdx
    jb .fail
.ok:
    xor eax,eax
    ret
.fail:
    mov eax,-1
    ret

; Read-only retained owned ISO error. RDI hc,ESI port,EDX endpoint,
; ECX0 raw event status/control64;1 generation32|slot8|endpoint8|DCI8|valid8.
; No polling, configuration or DMA mutation. Accept poisoned endpoint only for
; this diagnostic, with the same actual controller, slot and generation checks.
xhci_iso_fs_error_scalar:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12d,esi
    mov r13d,edx
    mov r14d,ecx
    cmp ecx,1
    ja .bad
    cmp edx,255
    ja .bad
    call xhci_hc_instance
    cmp eax,-1
    je .bad
    mov rdi,rbx
    call xhci_inst_live_for
    mov esi,r12d
    call xhci_interrupt_slot_for_port
    test eax,eax
    jz .bad
    mov esi,eax
    mov edx,r13d
    call xhci_interrupt_find_by_ep
    test rax,rax
    jz .bad
    mov rbx,rax
    cmp byte [rbx+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .bad
    mov eax,[rel xhci_generation]
    cmp [rbx+xhci_intr_ep.generation],eax
    jne .bad
    mov r15,[rbx+xhci_intr_ep.report]
    add r15,XHCI_ISOB_META
    mov ecx,8
.scan:
    cmp dword [r15+28],3
    jne .next
    cmp qword [r15+20],0
    jne .found
.next:
    add r15,32
    dec ecx
    jnz .scan
    xor eax,eax
    jmp .out
.found:
    test r14d,r14d
    jnz .identity
    mov rax,[r15+20]
    jmp .out
.identity:
    mov eax,[rbx+xhci_intr_ep.generation]
    movzx edx,byte [rbx+xhci_intr_ep.slot]
    shl rdx,32
    or rax,rdx
    movzx edx,byte [rbx+xhci_intr_ep.ep_addr]
    shl rdx,40
    or rax,rdx
    movzx edx,byte [rbx+xhci_intr_ep.dci]
    shl rdx,48
    or rax,rdx
    bts rax,56
    jmp .out
.bad: mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Empty rolling queue can leave the mode without changing hardware ownership.
; No cancel/stop/timeout retirement: pending or unconsumed packets refuse.
xhci_iso_fs_stream_close:
    XHCI_POWER_GATE 1
    push rbx
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp word [rbx+XHCI_ISOB_COUNT],0x8000
    jne .fail
    cmp word [rbx+XHCI_ISOB_LEFT],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.pending],0
    jne .fail
    mov word [rbx+XHCI_ISOB_COUNT],0
    mov word [rbx+XHCI_ISOB_INDEX],0
    xor eax,eax
    jmp .out
.fail: mov rax,-1
.out:
    pop rbx
    ret

; Once all packet work is consumed, pending_first_cycle has no pending-TD
; meaning. Reuse only that ISO owner's dead fact for STOP (terminal lifetime),
; preserving every native state offset/size and instance/power ABI.
XHCI_ISO_STOP_SEEN equ xhci_intr_ep.pending_first_cycle
; Stop an empty, consumed FS ISO owner. RDI=HC,ESI=address,EDX=endpoint.
; Software stream_close alone is NOT a hardware barrier. No cancel, restart,
; allocation reuse, or freeing here. Fixed ring/report ownership survives until
; ordinary confirmed slot/controller retirement. Any unknown result quarantines.
xhci_iso_fs_stop:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    call xhci_iso_fs_owner
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp word [rbx+XHCI_ISOB_COUNT],0
    jne .fail
    cmp word [rbx+XHCI_ISOB_LEFT],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.pending],0
    jne .fail
    cmp byte [rbx+xhci_intr_ep.completed],0
    jne .fail
    cmp dword [rbx+xhci_intr_ep.enqueue],63
    ja .fail
    cmp dword [rbx+xhci_intr_ep.pcs],1
    ja .fail
    cmp qword [rel xhci_cmd_out_trb],0
    jne .fail
    cmp byte [rel xhci_cmd_ring_dead],0
    jne .fail
    mov dword [rbx+XHCI_ISO_STOP_SEEN],0
    mov byte [rbx+xhci_intr_ep.configured],4 ; only exact STOP event owns this state
    movzx r12d,byte [rbx+xhci_intr_ep.slot]
    mov esi,r12d
    shl esi,24
    movzx eax,byte [rbx+xhci_intr_ep.dci]
    shl eax,16
    or esi,eax
    or esi,(15<<10)                ; Stop Endpoint, Suspend=0
    xor edi,edi
    call xhci_cmd_submit
    cmp eax,r12d
    jne .unknown
    mov eax,[rel xhci_generation]
    cmp eax,[rbx+xhci_intr_ep.generation]
    jne .unknown
    cmp byte [rbx+xhci_intr_ep.configured],4
    jne .unknown
    cmp dword [rbx+XHCI_ISO_STOP_SEEN],1
    jne .unknown
    mov byte [rbx+xhci_intr_ep.configured],3 ; terminal known stopped, not reusable
    xor eax,eax
    jmp .out
.unknown:
    mov byte [rbx+xhci_intr_ep.configured],2 ; retain all ownership, never retry
.fail: mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

xhci_op_interrupt_in_queue:
    XHCI_POWER_GATE 2
    push r12
    push r13
    push r14
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  esi, eax
    mov  edx, r13d
    call xhci_interrupt_find_by_ep
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, r14d
    mov  edx, 1
    call xhci_interrupt_queue_state
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; Route one Transfer Event by validated slot, DCI, Normal-TRB pointer, endpoint
; generation, transfer-ring cycle, and pending ownership. RBX=event -> 1/2/-1.
; 2 = ERROR_OWNED: also the exact empty-ring STOP event below (no PCM credit).
; Ordinarily the event passed the complete ownership chain but carries an
; error code. The endpoint is unconfigured and earns nothing, yet the event is
; its owner's, so callers commit it (without credit) instead of leaving it to
; block every peer and command behind it.
XHCI_ROUTE_ERROR_OWNED equ 2
;
; Short IN follow-up (xHCI 1.2 4.10.1.1). After a Short Packet event on an ISP
; member, the xHC may still report the TD's IOC TRB: always for a short member
; before the last (mid-TD), and as a "spurious success" on the same TRB on
; xHCI >= 1.0 parts (Linux XHCI_SPURIOUS_SUCCESS). qemu-xhci reports once. The
; first event completes the TD; the follow-up names a TRB no TD owns any more,
; and a refused head is never acknowledged, so it held ERDP and every later
; completion behind it (feed 749 Beelink cdc_ecm: RXF stayed 1). A bulk or
; interrupt owner remembers only the terminal TRB of a TD it completed short
; (ring index + 1, 0 = none, and that TRB's cycle) and consumes exactly one later
; Success/Short Packet event naming exactly that TRB, with no completion, bytes or
; accept credit. ISO owners keep pad_ss for their burst index/left and never
; reach either edge.
XHCI_SHORT_TAIL       equ xhci_intr_ep.pad_ss
XHCI_SHORT_TAIL_CYCLE equ xhci_intr_ep.pad_ss+2
xhci_interrupt_route_event:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  eax, [rbx + 12]
    mov  r12d, eax
    shr  r12d, 24
    mov  r13d, eax
    shr  r13d, 16
    and  r13d, 0x1F
    mov  r14, [rbx]
    test r12d, r12d
    jz   .wrong_slot
    cmp  r12d, XHCI_MAX_SLOTS_EN
    ja   .wrong_slot
    cmp  r13d, 1
    jbe  .wrong_ep
    cmp  r13d, 31
    ja   .wrong_ep
    mov  esi, r12d
    mov  edx, r13d
    call xhci_interrupt_find_by_dci
    test rax, rax
    jz   .classify_pointer
    mov  r15, rax
    cmp byte [r15+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .single_packet
    cmp byte [r15+xhci_intr_ep.configured],4
    je .iso_stopping
    cmp word [r15+XHCI_ISOB_COUNT],0
    je .single_packet
    mov rdi,r15
    mov rsi,rbx
    call xhci_iso_fs_burst_route_event
    jmp .out
; xHCI4.6.9: stopping BETWEEN TDs posts Stopped-LengthInvalid (27)
; at the current dequeue pointer BEFORE the command completion. Consume only
; this exact empty owner while its exact Stop Endpoint command is outstanding.
; It earns no packet, completion sequence, presentation, ERDP/IMAN accept credit.
.iso_stopping:
    cmp dword [r15+XHCI_ISO_STOP_SEEN],0
    jne .duplicate
    mov eax,[r15+xhci_intr_ep.generation]
    cmp eax,[rel xhci_generation]
    jne .stale_cycle
    cmp word [r15+XHCI_ISOB_COUNT],0
    jne .stale_cycle
    cmp byte [r15+xhci_intr_ep.pending],0
    jne .stale_cycle
    cmp byte [r15+xhci_intr_ep.completed],0
    jne .stale_cycle
    test byte [rbx+12],4           ; Event Data must be clear (TRB pointer)
    jnz .stale_cycle
    mov eax,[rbx+8]
    shr eax,24
    cmp eax,27
    jne .stale_cycle
    cmp byte [rel xhci_cmd_out_type],15
    jne .stale_cycle
    cmp byte [rel xhci_cmd_out_slot],r12b
    jne .wrong_slot
    mov rax,[rel xhci_cmd_out_trb]
    test rax,rax
    jz .stale_cycle
    mov eax,[rax+12]
    test eax,(1<<23)              ; no suspended-stop substitution
    jnz .stale_cycle
    shr eax,16
    and eax,31
    cmp eax,r13d
    jne .wrong_ep
    mov eax,[r15+xhci_intr_ep.enqueue]
    cmp eax,63
    ja .stale_cycle
    shl eax,4
    add rax,[r15+xhci_intr_ep.ring]
    cmp r14,rax
    je .stop_owned
    ; The final completed IOC TD may still be the dequeue position at the
    ; TD boundary (xHCI Table4-2). No live/unconsumed TD exists. Admit only
    ; the immediately preceding producer TRB, with actual ISO/IOC/current PCS.
    cmp dword [r15+xhci_intr_ep.completion_sequence],0
    je .stop_link
    mov ecx,[r15+xhci_intr_ep.enqueue]
    test ecx,ecx
    jz .stop_link
    dec ecx
    shl ecx,4
    add rcx,[r15+xhci_intr_ep.ring]
    cmp r14,rcx
    jne .stop_link
    mov edx,[rcx+12]
    and edx,1
    cmp edx,[r15+xhci_intr_ep.pcs]
    jne .stale_cycle
    mov edx,[rcx+12]
    and edx,0xfffffffa             ; ignore cycle/IN ISP only
    cmp edx,(5<<10)|(1<<5)|(1<<31)
    jne .stale_cycle
    jmp .stop_owned
.stop_link:
    ; At the final Link TRB the HC may already have followed it to ring0.
    cmp dword [r15+xhci_intr_ep.enqueue],63
    jne .stale_cycle
    cmp r14,[r15+xhci_intr_ep.ring]
    jne .stale_cycle
    mov rcx,[r15+xhci_intr_ep.ring]
    cmp [rax],rcx
    jne .stale_cycle
    mov ecx,[rax+12]
    and ecx,0xfffffffe
    cmp ecx,(6<<10)|2
    jne .stale_cycle
.stop_owned:
    mov dword [r15+XHCI_ISO_STOP_SEEN],1
    mov eax,XHCI_ROUTE_ERROR_OWNED
    jmp .out
.single_packet:
    cmp  byte [r15 + xhci_intr_ep.attributes], USB_EP_XFER_ISO
    je   .live_td
    movzx eax, word [r15 + XHCI_SHORT_TAIL]
    test eax, eax
    jz   .live_td
    dec  eax
    shl  eax, 4
    add  rax, [r15 + xhci_intr_ep.ring]
    cmp  r14, rax
    jne  .live_td                    ; only the remembered terminal TRB
    mov  edx, [r15 + xhci_intr_ep.generation]
    cmp  edx, [rel xhci_generation]
    jne  .live_td
    mov  edx, [rax + 12]
    mov  ecx, edx
    and  ecx, 1
    cmp  cx, [r15 + XHCI_SHORT_TAIL_CYCLE]
    jne  .live_td                    ; that slot was recycled at the other cycle
    shr  edx, 10
    and  edx, 0x3F
    cmp  edx, XHCI_TRB_NORMAL
    jne  .live_td
    test dword [rax + 12], (1 << 5)  ; the TD's IOC TRB
    jz   .live_td
    test byte [rbx + 12], 4          ; Event Data clear: a TRB pointer
    jnz  .live_td
    mov  edx, [rbx + 8]
    shr  edx, 24
    cmp  edx, 1
    je   .follow_cc
    cmp  edx, 13
    jne  .live_td
.follow_cc:
    cmp  byte [r15 + xhci_intr_ep.pending], 1
    jne  .follow_owned
    mov  rdi, r15
    mov  rsi, r14
    call xhci_interrupt_event_in_pending_td
    test eax, eax
    jnz  .live_td                    ; a live TD reuses that TRB: ordinary path
.follow_owned:
    mov  dword [r15 + XHCI_SHORT_TAIL], 0   ; tail index and cycle: exactly once
    inc  qword [rel xhci_intr_short_follow]
    mov  eax, XHCI_ROUTE_ERROR_OWNED
    jmp  .out
.live_td:
    cmp  byte [r15 + xhci_intr_ep.pending], 1
    jne  .duplicate
    mov  eax, [r15 + xhci_intr_ep.generation]
    cmp  eax, [r15 + xhci_intr_ep.pending_generation]
    jne  .stale_cycle
    cmp  eax, [rel xhci_generation]
    jne  .stale_cycle
    test r14, r14
    jz   .stale_cycle
    mov  rdi, r15
    mov  rsi, r14
    call xhci_interrupt_event_in_pending_td   ; also R8D = member offset, R9D = member length
    test eax, eax
    jz   .classify_pointer
    mov  eax, [rbx + 8]
    mov  edx, eax
    shr  edx, 24
    cmp byte [r15+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .completion_code
    test byte [r15+xhci_intr_ep.ep_addr],USB_EP_DIR_IN
    jnz .completion_code
    cmp edx,1
    jne .transfer_error             ; an OUT short event cannot earn audio bytes
.completion_code:
    cmp  edx, 1
    je   .cc_ok
    cmp  edx, 13
    jne  .transfer_error
.cc_ok:
    and  eax, 0x00FFFFFF             ; residual of THE TRB THAT GENERATED THE EVENT (per-TRB)
    cmp byte [r15+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .residual_ready
    test byte [r15+xhci_intr_ep.ep_addr],USB_EP_DIR_IN
    jnz .residual_ready
    test eax,eax
    jnz .overflow
.residual_ready:
    cmp  eax, r9d
    ja   .overflow                   ; residual larger than that TRB -> impossible, refuse
    mov  edx, r9d
    sub  edx, eax                    ; bytes moved by the event TRB
    add  edx, r8d                    ; + bytes of every member before it = TD transferred
    movzx eax, word [r15 + xhci_intr_ep.exact_len]
    cmp  edx, eax
    ja   .overflow
    mov  [r15 + xhci_intr_ep.completed_len], edx
    mov  eax, [r15 + xhci_intr_ep.pending_generation]
    mov  [r15 + xhci_intr_ep.completed_generation], eax
    mov  eax, [r14 + 12]
    and  eax, 1
    mov  [r15 + xhci_intr_ep.completed_cycle], eax
    cmp  byte [r15 + xhci_intr_ep.attributes], USB_EP_XFER_ISO
    je   .tail_ready                 ; ISO owns pad_ss
    mov  dword [r15 + XHCI_SHORT_TAIL], 0
    test byte [r15 + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .tail_ready
    mov  edx, [rbx + 8]
    shr  edx, 24
    cmp  edx, 13
    jne  .tail_ready                 ; a full-length TD earns no follow-up
    mov  rdx, [r15 + xhci_intr_ep.pending_trb]
    sub  rdx, [r15 + xhci_intr_ep.ring]
    shr  rdx, 4
    inc  edx
    mov  [r15 + XHCI_SHORT_TAIL], dx
    mov  edx, [r15 + xhci_intr_ep.pending_cycle]
    mov  [r15 + XHCI_SHORT_TAIL_CYCLE], dx
.tail_ready:
    inc  dword [r15 + xhci_intr_ep.completion_sequence]
    jnz  .sequence_ready
    inc  dword [r15 + xhci_intr_ep.completion_sequence]
.sequence_ready:
    mov  byte [r15 + xhci_intr_ep.pending], 0
    mov  byte [r15 + xhci_intr_ep.completed], 1
    inc  qword [rel xhci_intr_completed]
    mov  eax, 1
    jmp  .out
.transfer_error:
    mov  byte [r15 + xhci_intr_ep.pending], 0
    mov  byte [r15 + xhci_intr_ep.completed], 0
    mov  byte [r15 + xhci_intr_ep.configured], 0
    inc  qword [rel xhci_intr_refused_ep]
    mov  eax, XHCI_ROUTE_ERROR_OWNED
    jmp  .out
.classify_pointer:
    mov  rdi, r14
    call xhci_interrupt_owner_by_trb
    test rax, rax
    jz   .wrong_ep
    movzx edx, byte [rax + xhci_intr_ep.slot]
    cmp  edx, r12d
    jne  .wrong_slot
    movzx edx, byte [rax + xhci_intr_ep.dci]
    cmp  edx, r13d
    jne  .wrong_ep
    jmp  .stale_cycle
.wrong_slot:
    inc  qword [rel xhci_intr_refused_slot]
    jmp  .refused
.wrong_ep:
    inc  qword [rel xhci_intr_refused_ep]
    jmp  .refused
.stale_cycle:
    inc  qword [rel xhci_intr_refused_cycle]
    jmp  .refused
.overflow:
    inc  qword [rel xhci_intr_refused_overflow]
    jmp  .refused
.duplicate:
    inc  qword [rel xhci_intr_refused_dup]
.refused:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared async-event classifier. Transfer Events for EP0 remain with the
; synchronous control-transfer owner.
xhci_interrupt_event_is_async:
    mov  edx, eax
    shr  eax, 10
    and  eax, 0x3F
    cmp  eax, XHCI_TRB_XFER_EVENT
    jne  .no
    mov  eax, edx
    shr  eax, 16
    and  eax, 0x1F
    cmp  eax, 1
    jbe  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Credit only an event that passed the full ownership filter. Production calls
; this after both ERDP and IMAN writes; the KAT uses the same accounting edge.
xhci_interrupt_credit_accept:
    inc  qword [rel xhci_intr_erdp_accept]
    inc  qword [rel xhci_intr_iman_accept]
    ret

xhci_interrupt_counters_clear:
    XHCI_POWER_GATE 1
    lea  rdi, [rel xhci_intr_queued]
    mov  ecx, 9
    xor  eax, eax
    rep  stosq
    ret

; Commit exactly the current Event Ring entry. EDI=1 credits one accepted
; interrupt completion; all other drains advance hardware without earning it.
xhci_event_commit:
    push r12
    mov  r12d, edi
    mov  eax, [rel xhci_evt_idx]
    inc  eax
    cmp  eax, XHCI_RING_TRBS
    jb   .no_wrap
    xor  eax, eax
    mov  edx, [rel xhci_evt_ccs]
    xor  edx, 1
    mov  [rel xhci_evt_ccs], edx
.no_wrap:
    mov  [rel xhci_evt_idx], eax
    mov  rdx, [rel xhci_evt_ring]
    mov  ecx, eax
    shl  ecx, 4
    add  rdx, rcx
    or   rdx, (1 << 3)
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_ERDP
    call xh_wr64
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_IMAN
    call xh_rd
    or   eax, 1
    mov  edx, eax
    mov  esi, [rel xhci_rt]
    add  esi, XHCI_IMAN
    call xh_wr
    test r12d, r12d
    jz   .done
    call xhci_interrupt_credit_accept
.done:
    pop  r12
    ret

; Drain at most one asynchronous endpoint Transfer Event or Port Status Change
; Event, never waiting. Only a fully validated owner's completion earns ERDP/IMAN
; accept credit; nothing else touches an owner, its bytes or a peer's work. Every
; other head of these two kinds is committed WITHOUT credit, because a head that
; is never acknowledged holds every later completion on the interrupter behind
; it (root 119342; feed 749 cdc_ecm stalled behind one such head): a validated
; owner's error completion (ERROR_OWNED), a valid PSC (port latched), and a
; refused Transfer Event or malformed PSC. A refusal is counted once, by the
; router's reason counter or xhci_psc_refused, and delivers nothing. Heads that
; belong to synchronous waiters (EP0 Transfer Events, command completions and
; other types) stay for xhci_evt_wait, as before.
xhci_interrupt_drain_once:
    XHCI_POWER_GATE 0
    push rbx
    push r12
    mov  eax, [rel xhci_evt_idx]
    mov  rbx, [rel xhci_evt_ring]
    mov  ecx, eax
    shl  ecx, 4
    add  rbx, rcx
    mov  r12d, [rbx + 12]
    mov  eax, r12d
    and  eax, 1
    cmp  eax, [rel xhci_evt_ccs]
    jne  .none
    mov  eax, r12d
    shr  eax, 10
    and  eax, 0x3F
    cmp  eax, XHCI_TRB_PORT_STATUS_CHANGE
    jne  .transfer
    call xhci_psc_accept             ; malformed: counted there, then committed
    xor  edi, edi                    ; without credit like any refused head
    jmp  .commit
.transfer:
    mov  eax, r12d
    call xhci_interrupt_event_is_async
    test eax, eax
    jz   .none
    call xhci_interrupt_route_event
    xor  edi, edi                    ; ERROR_OWNED or refused (-1, counted by
    cmp  eax, 1                      ; reason): commit, deliver nothing, no credit
    jne  .commit
    mov  edi, 1
.commit:
    call xhci_event_commit
    mov  eax, 1
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; xhci_psc_accept(RBX=Port Status Change Event TRB) -> EAX 1 valid (port bit
; latched in this controller's xhci_psc_changed) / 0 malformed. Never commits.
; Validity per xHCI 1.2 6.4.2.3 Tables 6-43..6-45: Completion Code Success, Port
; ID 1..MaxPorts, every RsvdZ field zero. clobbers RAX,RCX,RDX.
xhci_psc_accept:
    mov  eax, [rbx + 12]
    test eax, 0xFFFF03FE             ; RsvdZ 31:16 and 9:1
    jnz  .bad
    shr  eax, 10
    and  eax, 0x3F
    cmp  eax, XHCI_TRB_PORT_STATUS_CHANGE
    jne  .bad
    cmp  dword [rbx + 4], 0
    jne  .bad
    mov  eax, [rbx + 8]
    cmp  eax, (1 << 24)              ; Completion Code = Success, 23:0 RsvdZ
    jne  .bad
    mov  eax, [rbx]
    test eax, 0x00FFFFFF
    jnz  .bad
    shr  eax, 24                     ; Port ID
    jz   .bad
    cmp  eax, [rel xhci_maxports]
    ja   .bad
    mov  ecx, eax
    and  ecx, 7
    mov  edx, 1
    shl  edx, cl
    shr  eax, 3
    lea  rcx, [rel xhci_psc_changed]
    or   [rcx + rax], dl
    inc  qword [rel xhci_psc_events]
    mov  eax, 1
    ret
.bad:
    inc  qword [rel xhci_psc_refused]
    xor  eax, eax
    ret

; Copy immutable completion bytes before clearing ownership, then requeue.
; RDI=state,RSI=out,EDX=cap,R9=usb_intr_completion*,R10D=publish -> RAX=len/-1.
xhci_interrupt_copy_completed:
    XHCI_POWER_GATE 0
    cmp byte [rdi+xhci_intr_ep.attributes],USB_EP_XFER_ISO
    jne .legacy_consumer
    mov rax,-1
    ret
.legacy_consumer:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, r10d
    test r13, r13
    jz   .fail
    cmp  byte [r12 + xhci_intr_ep.completed], 1
    jne  .fail
    mov  ebx, [r12 + xhci_intr_ep.completed_len]
    cmp  ebx, edx
    ja   .fail
    mov  rdi, r13
    mov  rsi, [r12 + xhci_intr_ep.report]
    mov  ecx, ebx
    rep  movsb
    test r9, r9
    jz   .metadata_done
    movzx eax, byte [r12 + xhci_intr_ep.slot]
    mov  [r9 + usb_intr_completion.slot], al
    movzx eax, byte [r12 + xhci_intr_ep.dci]
    mov  [r9 + usb_intr_completion.dci], al
    movzx eax, byte [r12 + xhci_intr_ep.ep_addr]
    mov  [r9 + usb_intr_completion.ep_addr], al
    mov  eax, [r12 + xhci_intr_ep.completed_cycle]
    mov  [r9 + usb_intr_completion.cycle], al
    mov  eax, [r12 + xhci_intr_ep.completed_generation]
    mov  [r9 + usb_intr_completion.generation], eax
    mov  eax, [r12 + xhci_intr_ep.completion_sequence]
    mov  [r9 + usb_intr_completion.sequence], eax
    mov  [r9 + usb_intr_completion.length], ebx
.metadata_done:
    mov  byte [r12 + xhci_intr_ep.completed], 0
    mov  dword [r12 + xhci_intr_ep.completed_len], 0
    mov  rdi, r12
    movzx esi, word [r12 + xhci_intr_ep.exact_len]
    mov  edx, r14d
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
    mov  eax, ebx
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

xhci_op_interrupt_in_poll:
    XHCI_POWER_GATE 2
    call xhci_inst_live_for          ; RDI's own controller (RCQ-09 N10)
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, esi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15d, r8d
    mov  rbp, r9
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  esi, eax
    mov  edx, r13d
    call xhci_interrupt_find_by_ep
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  ecx, XHCI_INTR_DRAIN_BUDGET
.check:
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    je   .copy
    test ecx, ecx
    jz   .fail
    push rcx
    call xhci_interrupt_drain_once
    pop  rcx
    test eax, eax
    jz   .fail
    dec  ecx
    jmp  .check
.copy:
    mov  rdi, rbx
    mov  rsi, r14
    mov  edx, r15d
    mov  r9, rbp
    mov  r10d, 1
    call xhci_interrupt_copy_completed
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Consume one accepted bulk completion. Copying (IN) happens before ownership
; clears; OUT skips the copy but follows the same immutable/scrub edge.
; RDI=state, RSI=out, EDX=capacity, ECX=copy flag -> RAX=len/-1.
xhci_bulk_consume_state:
    XHCI_POWER_GATE 0
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  ebx, ecx
    cmp  byte [r12 + xhci_intr_ep.completed], 1
    jne  .fail
    mov  edx, [r12 + xhci_intr_ep.completed_len]
    cmp  edx, r14d
    ja   .fail
    test ebx, ebx
    jz   .copied
    test r13, r13
    jz   .fail
    mov  rdi, r13
    mov  rsi, [r12 + xhci_intr_ep.report]
    mov  ecx, edx
    rep  movsb
.copied:
    mov  ebx, edx
    mov  rdi, [r12 + xhci_intr_ep.report]
    movzx ecx, word [r12 + xhci_intr_ep.exact_len]
    xor  eax, eax
    rep  stosb
    mov  byte [r12 + xhci_intr_ep.completed], 0
    mov  dword [r12 + xhci_intr_ep.completed_len], 0
    mov  word [r12 + xhci_intr_ep.exact_len], 0
    mov  word [r12 + xhci_intr_ep.segments], 0
    mov  qword [r12 + xhci_intr_ep.pending_trb], 0
    mov  qword [r12 + xhci_intr_ep.pending_first_trb], 0
    mov  dword [r12 + xhci_intr_ep.pending_first_cycle], 0
    mov  dword [r12 + xhci_intr_ep.pending_generation], 0
    mov  dword [r12 + xhci_intr_ep.pending_cycle], 0
    mov  dword [r12 + xhci_intr_ep.completed_generation], 0
    mov  dword [r12 + xhci_intr_ep.completed_cycle], 0
    mov  eax, ebx
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Lazily upgrade an idle canonical bulk-IN owner. No caller bytes are DMA
; visible, no pending/completed extent is replaced, and OOM queues nothing.
; Allocations are retained per controller/state through release and reset,
; matching the bump-only core/dma lifetime. RDI=state -> RAX=0 / -1.
xhci_bulk_ensure_large:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    lea  rax, [rel xhci_intr_states]
    mov  rdx, rdi
    sub  rdx, rax
    jc   .fail
    cmp  rdx, XHCI_INTR_STATE_COUNT * xhci_intr_ep_size
    jae  .fail
    mov  rax, rdx
    xor  edx, edx
    mov  ecx, xhci_intr_ep_size
    div  ecx
    test edx, edx
    jnz  .fail
    mov  r12d, eax
    cmp  byte [rbx + xhci_intr_ep.active], 1
    jne  .fail
    cmp  byte [rbx + xhci_intr_ep.configured], 1
    jne  .fail
    cmp  byte [rbx + xhci_intr_ep.attributes], USB_EP_XFER_BULK
    jne  .fail
    test byte [rbx + xhci_intr_ep.ep_addr], USB_EP_DIR_IN
    jz   .fail
    mov  eax, [rbx + xhci_intr_ep.generation]
    cmp  eax, [rel xhci_generation]
    jne  .fail
    cmp  byte [rbx + xhci_intr_ep.pending], 0
    jne  .fail
    cmp  byte [rbx + xhci_intr_ep.completed], 0
    jne  .fail
    lea  r13, [rel xhci_bulk_large_dma]
    mov  rax, [r13 + r12*8]
    test rax, rax
    jnz  .have_dma
    mov  edi, XHCI_BULK_LARGE_BYTES + XHCI_BULK_LARGE_ALIGN - 1
    call dma_alloc                    ; entire raw extent mapped through core/dma
    test rax, rax
    jz   .fail
    add  rax, XHCI_BULK_LARGE_ALIGN - 1
    and  rax, -XHCI_BULK_LARGE_ALIGN
    mov  [r13 + r12*8], rax
.have_dma:
    mov  [rbx + xhci_intr_ep.report], rax
    mov  word [rbx + xhci_intr_ep.report_capacity], XHCI_BULK_LARGE_BYTES
    mov  rdi, rax
    mov  ecx, XHCI_BULK_LARGE_BYTES / 8
    xor  eax, eax
    rep  stosq
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared synchronous bulk op. ABI: RDI=self, ESI=port, EDX=endpoint address,
; RCX=caller bytes, R8D=capacity/request, R9D=direction (0 OUT, 1 IN).
; The caller buffer never becomes DMA-visible: OUT is snapshotted before the
; doorbell and IN is copied only after an accepted immutable completion.
xhci_op_bulk_common:
    XHCI_POWER_GATE 1
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, esi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15d, r8d
    mov  ebp, r9d
    test r14, r14
    jz   .fail
    test r15d, r15d
    jz   .fail
    cmp  r15d, XHCI_INTR_REPORT_BYTES
    jbe  .request_size_ok
    test ebp, ebp
    jz   .fail                       ; OUT keeps the original 2KiB contract
    cmp  r15d, XHCI_BULK_LARGE_BYTES
    ja   .fail
.request_size_ok:
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  esi, eax
    mov  edx, r13d
    call xhci_interrupt_find_by_ep
    test rax, rax
    jz   .fail
    mov  rbx, rax
    cmp  byte [rbx + xhci_intr_ep.configured], 1
    jne  .fail
    movzx eax, byte [rbx + xhci_intr_ep.attributes]
    and  eax, USB_EP_XFER_MASK
    cmp  eax, USB_EP_XFER_BULK
    jne  .fail
    mov  eax, [rbx + xhci_intr_ep.generation]
    cmp  eax, [rel xhci_generation]
    jne  .fail
    movzx eax, byte [rbx + xhci_intr_ep.ep_addr]
    shr  eax, 7
    cmp  eax, ebp
    jne  .fail
    ; OUT is synchronous: only a TD queued by THIS invocation may earn its
    ; result. A previous timeout may already have affected the device; -1 is
    ; not proof of cancellation and never authorizes replay (notably BOT CBWs).
    test ebp, ebp
    jnz  .late_in
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    je   .retire_old_out
    cmp  byte [rbx + xhci_intr_ep.pending], 1
    jne  .late_in
    ; Give the existing owner one nonblocking event drain, without replacing
    ; its snapshot/ring or waiting on it as if it belonged to the new request.
    call xhci_interrupt_drain_once
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    jne  .fail
.retire_old_out:
    mov  rdi, rbx
    xor  esi, esi                    ; OUT retirement never copies to a caller
    movzx edx, word [rbx + xhci_intr_ep.exact_len] ; retire OLD owned length, never new size
    xor  ecx, ecx
    call xhci_bulk_consume_state      ; only accepted completion may release/scrub
    jmp  .fail                       ; current request was never queued
.late_in:
    ; --- IN LATE COMPLETION FIRST: a transfer armed by an earlier call (a blocking call
    ;     that timed out, or a non-blocking poll) may have completed since. Consume it
    ;     rather than re-queue: queue_state refuses while completed/pending is set, so
    ;     the old flow refused every later call forever (RX wedge on the first idle
    ;     timeout — fatal for a NIC whose frames arrive asynchronously). ---
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    je   .take
    cmp  byte [rbx + xhci_intr_ep.pending], 1
    je   .armed                      ; still in flight: keep it, just wait/poll below
    test ebp, ebp
    jnz  .queue
    mov  rdi, [rbx + xhci_intr_ep.report]
    mov  rsi, r14
    mov  ecx, r15d
    rep  movsb                       ; immutable OUT snapshot
.queue:
    cmp  r15d, XHCI_INTR_REPORT_BYTES
    jbe  .capacity_ready
    mov  rdi, rbx
    call xhci_bulk_ensure_large       ; only idle owners may change bounce extents
    test rax, rax
    jnz  .fail
.capacity_ready:
    mov  rdi, rbx
    mov  esi, r15d
    mov  edx, 1
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
.armed:
    cmp  byte [rel xhci_bulk_nonblock], 0
    jne  .poll_once                  ; bulk_in_poll: one drain, then 0 = nothing yet
    mov  r11d, XHCI_CMD_BUDGET_US / 100
.poll:
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    je   .take
    push r11
    call xhci_interrupt_drain_once
    pop  r11
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    je   .take
    mov  edi, 100
    push r11
    call tsc_delay_us
    pop  r11
    dec  r11d
    jnz  .poll
    jmp  .fail                       ; keep pending DMA ownership; later OUT calls cannot claim its result
.poll_once:
    call xhci_interrupt_drain_once   ; never waits
    cmp  byte [rbx + xhci_intr_ep.completed], 1
    je   .take
    xor  eax, eax                    ; nothing yet: the TRB stays armed for the next poll
    jmp  .out
.take:
    mov  rdi, rbx
    mov  rsi, r14
    mov  edx, r15d
    mov  ecx, ebp
    call xhci_bulk_consume_state
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

xhci_op_bulk_in:
    mov  byte [rel xhci_bulk_nonblock], 0
    mov  r9d, 1
    jmp  xhci_op_bulk_common

xhci_op_bulk_out:
    mov  byte [rel xhci_bulk_nonblock], 0
    xor  r9d, r9d
    jmp  xhci_op_bulk_common

; usbhc_ops.bulk_in_poll — the NON-BLOCKING bulk IN (USB NIC receive): same ABI as
; bulk_in; RAX = len of a completed transfer, 0 = nothing yet (TRB armed), -1 refused.
xhci_op_bulk_in_poll:
    call xhci_inst_live_for          ; RDI's own controller (RCQ-09 N10)
    mov  byte [rel xhci_bulk_nonblock], 1
    mov  r9d, 1
    jmp  xhci_op_bulk_common

; xhci_port_settle — bounded wait (up to ~600 ms) for ANY root-hub port to assert CCS
;   after controller start (USB2 re-detect debounce). Returns as soon as a device is
;   seen; falls through on timeout (empty machine). clobbers: caller-saved.
xhci_port_settle:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    mov  r13d, 60                    ; 60 * 10 ms = 600 ms budget
.round:
    mov  r12d, 1
.scan:
    cmp  r12d, [rel xhci_maxports]
    ja   .next_round
    mov  edi, r12d
    call xhci_read_portsc_live
    test eax, XHCI_PORTSC_CCS
    jnz  .have                       ; a device is present -> stop waiting
    inc  r12d
    jmp  .scan
.next_round:
    mov  edi, 10000                  ; 10 ms
    call tsc_delay_us
    dec  r13d
    jnz  .round
.have:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_port_power — RCQ-09 (xHCI 1.2 sec. 4.19.4 / 5.4.8). Live controller,
;   after R/S. PPC=0: no register write
;   at all (behaviour unchanged). PPC=1: every root port gets
;   PORTSC = neutral(PORTSC) | PP, so no RW1C/RW1CS change bit, PED, PR, LWS or
;   WPR is ever written as 1 by accident; then one bounded 20 ms settle, then a
;   bounded PP read-back per port (the spec's confirm-before-modify). Emits one
;   [usb.xhci.ppc] line per controller. clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_port_power:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov  esi, XHCI_HCCPARAMS1
    call xh_rd
    xor  ecx, ecx
    test eax, XHCI_HCC_PPC
    setnz cl
    mov  r14d, ecx                   ; ppc
    mov  eax, [rel xhci_inst_cur]
    lea  rdx, [rel xhci_inst_ppc]
    mov  [rdx + rax*4], ecx
    xor  ebx, ebx                    ; ports that never reported PP=1
    xor  r13d, r13d                  ; ports confirmed powered
    test r14d, r14d
    jz   .marker                     ; PPC=0: ports are always powered; touch nothing
    mov  r12d, 1
.on:
    cmp  r12d, [rel xhci_maxports]
    ja   .settle
    mov  edi, r12d
    call xhci_portsc_off
    mov  esi, eax
    push rsi
    call xh_rd
    pop  rsi
    and  eax, XHCI_PORTSC_NEUTRAL
    or   eax, XHCI_PORTSC_PP
    mov  edx, eax
    call xh_wr
    inc  r12d
    jmp  .on
.settle:
    mov  edi, XHCI_PP_SETTLE_US
    call tsc_delay_us
    mov  r12d, 1
.check:
    cmp  r12d, [rel xhci_maxports]
    ja   .marker
    push r12
    mov  r12d, XHCI_PP_READBACK
.poll:
    mov  edi, [rsp]
    call xhci_portsc_off
    mov  esi, eax
    call xh_rd
    test eax, XHCI_PORTSC_PP
    jnz  .powered
    mov  edi, 1000
    call tsc_delay_us
    dec  r12d
    jnz  .poll
    pop  r12
    inc  ebx
    jmp  .check_next
.powered:
    pop  r12
    inc  r13d
.check_next:
    inc  r12d
    jmp  .check
.marker:
    ; "[PAOS64] P2 usb-xhci: instance K ppc=P ports=N powered=M stuck=S [usb.xhci.ppc]"
    lea  rdi, [rel str_xinst_head]
    call serial_string
    mov  edi, [rel xhci_inst_cur]
    call serial_decimal
    lea  rdi, [rel str_xppc_ppc]
    call serial_string
    mov  edi, r14d
    call serial_decimal
    lea  rdi, [rel str_xinst_ports]
    call serial_string
    mov  edi, [rel xhci_maxports]
    call serial_decimal
    lea  rdi, [rel str_xppc_powered]
    call serial_string
    mov  edi, r13d
    call serial_decimal
    lea  rdi, [rel str_xppc_stuck]
    call serial_string
    mov  edi, ebx
    call serial_decimal
    lea  rdi, [rel str_xppc_tail]
    call serial_string
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_get_init_receipt() -> RAX read-only original selected initialization.
; Ten dwords: seen, bus, device, function, PCI vendor/device, raw HCSPARAMS2,
; HCS2 observed, last phase, bring-up return, raw usb_hc_register return.
; Phase: 1 BAR,2 PCI,3 capabilities,4 legacy,5 halt,6 HCRST,7 CNR,8 DMA,
; 9 program,10 RUN,11 power/debounce,12 bring-up success. Registration is a
; separate fact: rg=0 accepted; ffffffff refused or not attempted (rc!=0).
; Saved before any later instance or fault/reinit; no MMIO or state switch.
xhci_get_init_receipt:
    lea  rax, [rel xhci_init_receipt]
    ret

; xhci_get_maxports() -> EAX = root-hub port count (0 if no controller). clobbers RAX.
xhci_get_maxports:                       ; exported: describes the first controller
    call xhci_inst_live0
xhci_get_maxports_live:              ; internal callers: the live controller
    XHCI_POWER_GATE 0
    cmp  dword [rel xhci_found], 1
    jne  .none
    mov  eax, [rel xhci_maxports]
    ret
.none:
    xor  eax, eax
    ret

; xhci_read_portsc(EDI = port, 1-based) -> EAX = raw PORTSC dword (0 if no controller).
;   Diagnostic (USBPORTS): shows the live connect/enable/speed/reset state per port.
;   clobbers RAX,RCX,RSI,RDI,R9.
xhci_read_portsc:                       ; exported: describes the first controller
    call xhci_inst_live0
xhci_read_portsc_live:              ; internal callers: the live controller
    XHCI_POWER_GATE 0
    cmp  dword [rel xhci_found], 1
    jne  .none
    test edi, edi
    jz   .none
    cmp  edi, [rel xhci_maxports]
    ja   .none                       ; a hub-child token has no PORTSC of its own
    lea  eax, [edi - 1]
    shl  eax, 4
    add  eax, XHCI_PORTSC_BASE
    add  eax, [rel xhci_op]
    mov  esi, eax
    call xh_rd
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; xhci_op_port_status(self, RSI = port) -> RAX = USB_PORT_* bits.
;   Reads PORTSC live, maps CCS->CONNECT, PED->ENABLED. clobbers: RAX,RCX,RDI,R9.
; ---------------------------------------------------------------------------
xhci_op_port_status:
    XHCI_POWER_GATE 2
    push rbx
    cmp  esi, [rel xhci_maxports]
    ja   .child
    ; PORTSC offset = op + 0x400 + (port-1)*0x10
    lea  eax, [esi - 1]
    shl  eax, 4
    add  eax, XHCI_PORTSC_BASE
    add  eax, [rel xhci_op]
    mov  esi, eax
    call xh_rd
    mov  ebx, eax
    xor  eax, eax
    test ebx, XHCI_PORTSC_CCS
    jz   .out
    or   eax, USB_PORT_CONNECT
    test ebx, XHCI_PORTSC_PED
    jz   .out
    or   eax, USB_PORT_ENABLED
.out:
    pop  rbx
    ret
.child:
    ; HUB0: a hub child stays connected while its slot is published and its
    ; root port still reports CCS (subtree detach/change handling is HUB1).
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .out
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    movzx edi, byte [rdx + rax + usb_topo.root]
    call xhci_read_portsc_live
    mov  ebx, eax
    xor  eax, eax
    test ebx, XHCI_PORTSC_CCS
    jz   .out
    mov  eax, USB_PORT_CONNECT | USB_PORT_ENABLED
    jmp  .out

; ---------------------------------------------------------------------------
; xhci_portsc_off(port) -> EAX = absolute PORTSC byte offset. clobbers RAX.
; ---------------------------------------------------------------------------
xhci_portsc_off:
    lea  eax, [edi - 1]
    shl  eax, 4
    add  eax, XHCI_PORTSC_BASE
    add  eax, [rel xhci_op]
    ret

; ---------------------------------------------------------------------------
; xhci_port_reset(EDI = port) -> EAX 0 ok / 1 fail. Acknowledges old PRC, sets
;   PR, then waits for this reset to finish on a connected, enabled port.
;   xHCI 1.2b 4.19.2/4.19.5: PRC is sticky and also signals failed resets.
;   Bounded 300 ms + 2 ms settle; preserves PED and unrelated change bits.
; ---------------------------------------------------------------------------
xhci_port_reset:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    mov  r12d, edi
    ; read PORTSC
    mov  edi, r12d
    call xhci_portsc_off
    mov  ebx, eax                    ; ebx = PORTSC offset
    mov  esi, ebx
    call xh_rd
    test eax, XHCI_PORTSC_CCS
    jz   .failed
    test eax, XHCI_PORTSC_PR       ; never adopt an already-running reset
    jnz  .failed
    ; PRC survives until W1C: clear the old completion as we start this reset.
    ; Neutral writes preserve power and do not disable PED or replay PR/WPR.
    and  eax, XHCI_PORTSC_NEUTRAL
    or   eax, XHCI_PORTSC_PR | XHCI_PORTSC_PRC
    mov  edx, eax
    mov  esi, ebx
    call xh_wr
    ; A fresh PRC alone is insufficient: failed resets also set it.
    mov  r8d, 300
.wait:
    mov  esi, ebx
    call xh_rd
    test eax, XHCI_PORTSC_CCS
    jz   .failed
    test eax, XHCI_PORTSC_PR
    jnz  .delay
    test eax, XHCI_PORTSC_PRC
    jz   .delay
    test eax, XHCI_PORTSC_PED
    jz   .failed
    jmp  .reset_done
.delay:
    mov  edi, 1000
    call tsc_delay_us
    dec  r8d
    jnz  .wait
    jmp  .failed
.reset_done:
    ; Acknowledge only this completion, never write PR back as a command.
    and  eax, XHCI_PORTSC_NEUTRAL
    or   eax, XHCI_PORTSC_PRC        ; W1C the reset-change
    mov  edx, eax
    mov  esi, ebx
    call xh_wr
    mov  edi, 2000                   ; brief settle after reset
    call tsc_delay_us
    mov  esi, ebx
    call xh_rd
    and  eax, XHCI_PORTSC_CCS | XHCI_PORTSC_PED | XHCI_PORTSC_PR
    cmp  eax, XHCI_PORTSC_CCS | XHCI_PORTSC_PED
    jne  .failed
    xor  eax, eax
    jmp  .out
.failed:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_cmd_submit(RDI = param(64), ESI = control-dword-without-cycle) -> EAX = slot
;   id (from the Command Completion Event) or 0 on failure. Enqueues one TRB on the
;   command ring, rings DB[0], polls the event ring for the completion (bounded).
;   S10-A1 F.3: the outstanding record (exact TRB address, type, slot, seq) is written
;   before DB0, and only the completion whose TRB Pointer equals it answers (F.3.3).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_cmd_submit:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rdi                    ; param
    mov  r14d, esi                   ; control (no cycle)
    cmp  byte [rel xhci_cmd_ring_dead], 0
    jne  .ring_dead                  ; an aborted-but-still-running ring answers nothing: refuse at once
    cmp  qword [rel xhci_cmd_out_trb], 0
    jne  .ring_dead                  ; F.3.2: at most one command outstanding per controller
    cmp  qword [rel xhci_cmd_out_seq], -1
    je   .ring_dead                  ; a saturated post counter refuses (never in practice)
    ; enqueue TRB at cmd_ring[cmd_idx]
    mov  eax, [rel xhci_cmd_idx]
    mov  rbx, [rel xhci_cmd_ring]
    mov  ecx, eax
    shl  ecx, 4
    add  rbx, rcx                    ; -> TRB
    mov  [rbx], r13                  ; param
    mov  dword [rbx + 8], 0          ; status
    mov  eax, r14d
    or   eax, [rel xhci_cmd_pcs]     ; set cycle from PCS
    mov  [rbx + 12], eax
    sfence
    ; F.3.2: record the outstanding command before DB0
    mov  [rel xhci_cmd_out_trb], rbx
    mov  eax, r14d
    shr  eax, 10
    and  eax, 0x3F
    mov  [rel xhci_cmd_out_type], al
    mov  eax, r14d
    shr  eax, 24
    mov  [rel xhci_cmd_out_slot], al
    inc  qword [rel xhci_cmd_out_seq]
    ; advance idx; at 255 (Link) toggle PCS + wrap
    mov  eax, [rel xhci_cmd_idx]
    inc  eax
    cmp  eax, 255
    jb   .no_wrap
    ; rewrite Link TRB cycle to current PCS, toggle PCS, wrap to 0
    mov  rbx, [rel xhci_cmd_ring]
    lea  rcx, [rbx + 255*16]
    mov  edx, (XHCI_TRB_LINK << 10) | (1 << 1)
    or   edx, [rel xhci_cmd_pcs]
    mov  [rcx + 12], edx
    mov  edx, [rel xhci_cmd_pcs]
    xor  edx, 1
    mov  [rel xhci_cmd_pcs], edx
    xor  eax, eax
.no_wrap:
    mov  [rel xhci_cmd_idx], eax
    ; ring doorbell 0 (command ring) = write 0
    mov  esi, [rel xhci_db]
    xor  edx, edx
    call xh_wr
    ; Poll for this command's completion: F.3.3 classifies every Command Completion
    ; head against the record and returns the matched one's checked result.
    mov  edi, XHCI_TRB_CMD_COMPLETION
    xor  esi, esi
    xor  edx, edx
    mov  dword [rel xhci_wait_budget], XHCI_CMD_WAIT_US / 100   ; commands may take up to 1 s
    call xhci_evt_wait
    mov  dword [rel xhci_wait_budget], XHCI_CMD_BUDGET_US / 100
    cmp  qword [rel xhci_cmd_out_trb], 0
    je   .submitted                  ; E5: the record is cleared, EAX = the result
    cmp  byte [rel xhci_evt_refused], 0
    jne  .head_refused
    call xhci_cmd_abort              ; timed out: F.3.4, EAX = a late E5's result or 0
    jmp  .submitted
.head_refused:
    call xhci_cmd_record_clear       ; an unowned head blocks the wait: failure, the ring is not
    mov  dword [rel xhci_evt_cc], 0  ; aborted (base rule); a later completion for it is E6. Its cc
    xor  eax, eax                    ; is not this command's: no Enable caller reads it as F3-R12
.submitted:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.ring_dead:
    mov  dword [rel xhci_evt_cc], 0
    xor  eax, eax
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_evt_wait(EDI=expected type,ESI=expected slot or 0,EDX=expected DCI or 0)
; -> EAX = slot id (or 1 for slot-zero EP0) on success, else 0. Asynchronous
; DCI>1 Transfer Events are routed to their owner and can never answer a waiter.
; ---------------------------------------------------------------------------
xhci_evt_wait:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  r14d, edi
    mov  r15d, esi
    mov  ebp, edx
    mov  r13d, [rel xhci_wait_budget]        ; budget in 100us units (commands raise it)
    mov  byte [rel xhci_evt_refused], 0
.poll:
    mov  eax, [rel xhci_evt_idx]
    mov  rbx, [rel xhci_evt_ring]
    mov  ecx, eax
    shl  ecx, 4
    add  rbx, rcx                    ; -> event TRB
    mov  r12d, [rbx + 12]            ; control dword
    ; cycle bit must match evt_ccs (else the controller hasn't written this slot yet)
    mov  eax, r12d
    and  eax, 1
    cmp  eax, [rel xhci_evt_ccs]
    jne  .not_yet
    ; Capture all identity fields before any dequeue commit.
    mov  rax, [rbx]                 ; TRB Pointer: the TRB that generated this event
    mov  [rel xhci_evt_ptr], rax
    mov  eax, [rbx + 8]
    and  eax, 0xFFFFFF              ; Transfer Length: the residual of a transfer event
    mov  [rel xhci_evt_len], eax
    mov  eax, [rbx + 8]             ; status: completion code in [31:24]
    shr  eax, 24
    mov  [rel xhci_evt_cc], eax
    mov  eax, r12d
    shr  eax, 24                    ; slot id [31:24]
    mov  [rel xhci_evt_slot], eax
    mov  eax, r12d
    shr  eax, 10
    and  eax, 0x3F                  ; TRB type
    mov  [rel xhci_evt_type], eax
    cmp  eax, XHCI_TRB_XFER_EVENT
    jne  .match_expected
    mov  eax, r12d
    shr  eax, 16
    and  eax, 0x1F
    cmp  eax, 1
    jbe  .match_expected
    call xhci_interrupt_route_event
    xor  edi, edi                 ; ERROR_OWNED: commit its own event, no credit
    cmp  eax, XHCI_ROUTE_ERROR_OWNED
    je   .async_commit
    cmp  eax, 1
    jne  .refused_async
    mov  edi, 1
.async_commit:
    call xhci_event_commit
    dec  r13d
    jnz  .poll
    xor  eax, eax
    jmp  .out
.refused_async:
    mov  byte [rel xhci_evt_refused], 1
    xor  eax, eax                 ; ownership refused: do not advance/ack
    jmp  .out
.match_expected:
    mov  eax, [rel xhci_evt_type]
    cmp  eax, XHCI_TRB_CMD_COMPLETION
    je   .command
    cmp  eax, r14d
    jne  .drain_other
    cmp  eax, XHCI_TRB_XFER_EVENT
    jne  .slot_check
    mov  eax, r12d
    shr  eax, 16
    and  eax, 0x1F
    cmp  eax, ebp
    jne  .drain_other
.slot_check:
    test r15d, r15d
    jz   .expected
    mov  eax, [rel xhci_evt_slot]
    test eax, eax
    jz   .expected
    cmp  eax, r15d
    jne  .drain_other
.expected:
    xor  edi, edi
    call xhci_event_commit
    jmp  .verdict
.drain_other:
    cmp  dword [rel xhci_evt_type], XHCI_TRB_PORT_STATUS_CHANGE
    jne  .drain_commit
    call xhci_psc_accept             ; latch a valid PSC's port; committed either way, as before
.drain_commit:
    xor  edi, edi
    call xhci_event_commit
    dec  r13d
    jnz  .poll
    xor  eax, eax
    jmp  .out
.verdict:
    ; completion code 1 (success) OR 13 (short packet, valid for descriptor reads)
    cmp  dword [rel xhci_evt_cc], 1
    je   .good
    cmp  dword [rel xhci_evt_cc], 13
    jne  .fail
.good:
    mov  eax, [rel xhci_evt_slot]
    test eax, eax
    jnz  .out
    mov  eax, r15d                   ; a slot-0 completion for a fixed-slot command answers with that slot
    test eax, eax
    jnz  .out
    mov  eax, 1                      ; xfer events carry slot 0 for EP0 — signal success
    jmp  .out
.fail:
    xor  eax, eax
    jmp  .out
; S10-A1 F.3.3: P = the event's full 64-bit TRB Pointer, O = xhci_cmd_out_trb.
;   cc 24             -> E5r: answers only the ring-control owner (EDI = XHCI_EVT_RING_CONTROL).
;   O == 0 or P != O  -> E6: committed, counted, answers no waiter.
;   P == O            -> E5: committed, the record cleared, the checked result returned to a
;                        command waiter (any other waiter keeps it in xhci_cmd_late_*).
.command:
    cmp  dword [rel xhci_evt_cc], XHCI_CC_CMD_RING_STOPPED
    jne  .command_e5
    cmp  r14d, XHCI_EVT_RING_CONTROL
    jne  .command_e6
    xor  edi, edi
    call xhci_event_commit
    mov  eax, 1                      ; E5r: its pointer (the new dequeue) is xhci_evt_ptr
    jmp  .out
.command_e5:
    mov  rax, [rel xhci_cmd_out_trb]
    test rax, rax
    jz   .command_e6
    cmp  rax, [rel xhci_evt_ptr]
    jne  .command_e6
    xor  edi, edi
    call xhci_event_commit
    call xhci_cmd_verdict            ; clears the record -> EAX = result
    cmp  r14d, XHCI_TRB_CMD_COMPLETION
    je   .out
    mov  [rel xhci_cmd_late_result], eax
    mov  eax, [rel xhci_evt_cc]
    mov  [rel xhci_cmd_late_cc], eax
    mov  byte [rel xhci_cmd_late_seen], 1
    jmp  .command_next
.command_e6:
    inc  dword [rel xhci_cmd_stray]
    xor  edi, edi
    call xhci_event_commit
.command_next:
    dec  r13d
    jnz  .poll
    mov  dword [rel xhci_evt_cc], 0  ; budget spent: no answer was consumed
    xor  eax, eax
    jmp  .out
.not_yet:
    mov  edi, 100
    call tsc_delay_us
    dec  r13d
    jnz  .poll
    mov  dword [rel xhci_evt_cc], 0  ; timeout: no completion was consumed
    xor  eax, eax
.out:
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_cmd_abort — a command that never completed leaves the ring blocked for every
;   later command (Lenovo root port 3, 2026-09-07). S10-A1 F.3.4: the timed-out submitter
;   is the ring-control owner.
;   1. CRCR.CA, then up to 100 ms for CRR = 0 (else the ring is dead).
;   2. Classify heads (F.3.3) until the E5r, within the 1 s command budget. A cc 25 or a late
;      real completion for O is an ordinary E5: its result is the submitter's.
;   3. Clear the record (O = 0) before any rewrite or DB0.
;   4. E5r pointer == the aborted TRB (never fetched): rewrite it in place as a No Op with the
;      cycle bit of the lap it was posted in, record it, DB0, and await exactly that No Op.
;      E5r pointer == the next empty enqueue: nothing (the next ordinary DB0 restarts the ring).
;      Anything else, or no E5r: xhci_cmd_ring_dead = 1.
;   -> EAX = the outstanding command's result (a late E5) or 0; xhci_evt_cc = its cc or 0.
xhci_cmd_abort:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    mov  r12, [rel xhci_cmd_out_trb]  ; O: the aborted TRB
    mov  byte [rel xhci_cmd_late_seen], 0
    mov  dword [rel xhci_cmd_late_result], 0
    mov  dword [rel xhci_cmd_late_cc], 0
    mov  esi, [rel xhci_op]
    add  esi, XHCI_CRCR
    mov  edx, XHCI_CRCR_CA
    call xh_wr
    mov  ebx, 1000                   ; up to 100 ms for the ring to stop
.wait_stop:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_CRCR
    call xh_rd
    test eax, XHCI_CRCR_CRR
    jz   .stopped
    mov  edi, 100
    call tsc_delay_us
    dec  ebx
    jnz  .wait_stop
.stopped:
    mov  esi, [rel xhci_op]
    add  esi, XHCI_CRCR
    call xh_rd
    test eax, XHCI_CRCR_CRR
    jz   .ring_quiet
    mov  byte [rel xhci_cmd_ring_dead], 1   ; CA ignored: the controller is wedged on that command
.ring_quiet:
    mov  edi, XHCI_EVT_RING_CONTROL  ; step 2: classify until the E5r
    xor  esi, esi
    xor  edx, edx
    mov  dword [rel xhci_wait_budget], XHCI_CMD_WAIT_US / 100
    call xhci_evt_wait               ; -> EAX 1 = E5r seen, its pointer in xhci_evt_ptr
    mov  dword [rel xhci_wait_budget], XHCI_CMD_BUDGET_US / 100
    mov  ebx, eax
    mov  r13, [rel xhci_evt_ptr]
    call xhci_cmd_record_clear       ; step 3: O = 0 before any rewrite or DB0
    cmp  byte [rel xhci_cmd_ring_dead], 0
    jne  .report
    test ebx, ebx
    jz   .dead                       ; no E5r within the budget
    cmp  r13, r12
    je   .rewrite
    mov  eax, [rel xhci_cmd_idx]
    shl  eax, 4
    add  rax, [rel xhci_cmd_ring]
    cmp  r13, rax
    je   .report                     ; stopped at the next empty enqueue: nothing to post
    jmp  .dead
.rewrite:
    cmp  byte [rel xhci_cmd_late_seen], 0
    jne  .dead                       ; completed, yet the dequeue never left it: inconsistent
    mov  qword [r12], 0              ; dwords 0-2 first
    mov  dword [r12 + 8], 0
    sfence
    mov  eax, [r12 + 12]
    and  eax, 1                      ; C: the cycle of the lap the aborted TRB was posted in
    or   eax, (XHCI_TRB_NOOP_CMD << 10)
    mov  [r12 + 12], eax
    sfence
    mov  [rel xhci_cmd_out_trb], r12 ; step 5: record the No Op, then DB0
    mov  byte [rel xhci_cmd_out_type], XHCI_TRB_NOOP_CMD
    mov  byte [rel xhci_cmd_out_slot], 0
    inc  qword [rel xhci_cmd_out_seq]
    mov  esi, [rel xhci_db]
    xor  edx, edx
    call xh_wr
    mov  edi, XHCI_TRB_CMD_COMPLETION  ; step 6: exactly that No Op (P == O, S == 0, cc 1)
    xor  esi, esi
    xor  edx, edx
    mov  dword [rel xhci_wait_budget], XHCI_CMD_WAIT_US / 100
    call xhci_evt_wait
    mov  dword [rel xhci_wait_budget], XHCI_CMD_BUDGET_US / 100
    cmp  eax, 1
    je   .report
    call xhci_cmd_record_clear
.dead:
    mov  byte [rel xhci_cmd_ring_dead], 1
.report:
    ; A quarantined command ring refuses every later command until verified
    ; HCRST. Report that loss on this controller's public backend, while keeping
    ; recoverable aborts healthy and leaving an already DEAD backend alone.
    cmp  byte [rel xhci_cmd_ring_dead], 0
    je   .health_done
    lea  rcx, [rel xhci_hcdev]
    mov  eax, [rel xhci_inst_cur]
    test eax, eax
    jz   .health_handle
    dec  eax
    imul eax, eax, DEV_SIZE
    lea  rcx, [rel xhci_inst_hcdev]
    add  rcx, rax
.health_handle:
    cmp  dword [rcx + dev.health], HEALTH_OK
    jne  .health_done
    mov  dword [rcx + dev.health], HEALTH_DEGRADED
.health_done:
    lea  rdi, [rel str_xhci_cmd_abort]
    call serial_string
    mov  edi, [rel xhci_cmd_late_cc]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_portsc]
    call serial_string
    mov  esi, [rel xhci_op]
    add  esi, XHCI_CRCR
    call xh_rd
    mov  edi, eax
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
    mov  eax, [rel xhci_cmd_late_cc]
    mov  [rel xhci_evt_cc], eax
    mov  eax, [rel xhci_cmd_late_result]
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_cmd_verdict — F.3.3 step 3 for the matched completion (xhci_evt_cc/xhci_evt_slot):
;   clears the record and returns EAX = the result. Success only for cc 1 and the slot rule
;   of the outstanding type: Enable Slot 1..min(maxslots, XHCI_MAX_SLOTS_EN) -> S; No Op
;   S == 0 -> 1; every other command S == its own nonzero slot -> S. Else 0 (the cc is kept;
;   a cc 1 slot-rule failure counts xhci_cmd_bad_slot). cc 13 is never a command success.
xhci_cmd_verdict:
    movzx ecx, byte [rel xhci_cmd_out_type]
    movzx edx, byte [rel xhci_cmd_out_slot]
    call xhci_cmd_record_clear
    cmp  dword [rel xhci_evt_cc], XHCI_CC_SUCCESS
    jne  .fail
    mov  eax, [rel xhci_evt_slot]
    cmp  ecx, XHCI_TRB_ENABLE_SLOT
    je   .enable
    cmp  ecx, XHCI_TRB_NOOP_CMD
    je   .noop
    test eax, eax
    jz   .bad_slot
    cmp  eax, edx
    jne  .bad_slot
    ret
.enable:
    test eax, eax
    jz   .bad_slot
    cmp  eax, [rel xhci_maxslots]
    ja   .bad_slot
    cmp  eax, XHCI_MAX_SLOTS_EN
    ja   .bad_slot
    ret
.noop:
    test eax, eax
    jnz  .bad_slot
    mov  eax, 1
    ret
.bad_slot:
    inc  dword [rel xhci_cmd_bad_slot]
.fail:
    xor  eax, eax
    ret

; xhci_cmd_record_clear — no command outstanding (seq stays monotonic). Clobbers nothing.
xhci_cmd_record_clear:
    XHCI_POWER_GATE 1
    mov  qword [rel xhci_cmd_out_trb], 0
    mov  byte [rel xhci_cmd_out_type], 0
    mov  byte [rel xhci_cmd_out_slot], 0
    ret

; ---------------------------------------------------------------------------
; xhci_op_control(self, RSI=setup*, RDX=port, RCX=buf, R8=cap) -> RAX = bytes moved / -1 /
;   -2 STALL. IN: wLength minus the data stage's short-packet residual (ISP, xHCI
;   4.10.1.1), so a caller never mistakes a stale buffer tail for received bytes.
;   OUT and no-data requests return wLength / 0.
;   Lazily addresses the device into bounded port/slot maps, then transfers on
;   that slot's private EP0 ring. The usbhc_ops seam remains unchanged.
; ---------------------------------------------------------------------------
xhci_op_control:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
%if PAOS_LAB_HP_EP0_WITNESS
    sub rsp,80                      ; nine waiter-local counter baselines
%endif
    mov  r15, rsi                    ; setup*
    mov  r14d, edx                   ; root-hub port
    mov  r13, rcx                    ; data buffer
    mov  r12d, r8d                   ; buffer capacity
    call xhci_address_port           ; -> EAX = retained slot (0 on failure)
    test eax, eax
    jz   .fail
    mov  ebx, eax                    ; validated slot id
    call xhci_ep0_recover_halt       ; a halt whose event another waiter drained
    movzx r10d, word [r15 + usb_setup.wLength]
    cmp  r10d, r12d                  ; never DMA beyond the caller's buffer
    ja   .fail
    test r10d, r10d
    jz   .setup_capacity_ok
    test r13, r13
    jz   .fail
.setup_capacity_ok:

    ; SETUP stage.
    call xhci_ep0_current_trb
    mov  rax, [r15]
    mov  [rdi], rax
    mov  dword [rdi + 8], 8
    mov  eax, (XHCI_TRB_SETUP << 10) | (1 << 6)
    test r10d, r10d
    jz   .setup_ready
    ; TRT from bmRequestType bit 7: device-to-host = IN data stage (3),
    ; host-to-device = OUT data stage (2) — e.g. an ASIX ACCESS_MAC register write.
    test byte [r15 + usb_setup.bmRequestType], 0x80
    jz   .setup_trt_out
    or   eax, (3 << 16)
    jmp  .setup_ready
.setup_trt_out:
    or   eax, (2 << 16)
.setup_ready:
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance

    ; DATA IN stage (absent for SET_CONFIGURATION/SET_PROTOCOL/SET_IDLE).
    mov  qword [rel xhci_ctl_data_trb], 0
    test r10d, r10d
    jz   .status_no_data
    call xhci_ep0_current_trb
    mov  [rel xhci_ctl_data_trb], rdi
    mov  [rdi], r13
    mov  [rdi + 8], r10d
    mov  eax, (XHCI_TRB_DATA << 10)
    test byte [r15 + usb_setup.bmRequestType], 0x80
    jz   .data_dir_ready             ; host-to-device: DATA OUT (DIR=0), caller buffer is the source
    ; device-to-host: DATA IN (DIR=1). ISP: a short packet earns its own Transfer
    ; Event carrying the residual; the xHC then runs the STATUS TD (xHCI 4.10.1.1).
    or   eax, (1 << 16) | (1 << 2)
.data_dir_ready:
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance

    ; STATUS stage, IOC earns the transfer event. Direction is OPPOSITE to the data
    ; stage (USB 2.0 §9.3): IN data -> OUT status; OUT data -> IN status.
    call xhci_ep0_current_trb
    mov  [rel xhci_ctl_status_trb], rdi
    mov  qword [rdi], 0
    mov  dword [rdi + 8], 0
    mov  eax, (XHCI_TRB_STATUS << 10) | (1 << 5)
    test byte [r15 + usb_setup.bmRequestType], 0x80
    jnz  .status_dir_ready           ; IN data  -> STATUS OUT (DIR=0)
    or   eax, (1 << 16)              ; OUT data -> STATUS IN  (DIR=1)
.status_dir_ready:
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance
    jmp  .publish_control

.status_no_data:
    ; USB control writes with no data use an IN status stage.
    call xhci_ep0_current_trb
    mov  [rel xhci_ctl_status_trb], rdi
    mov  qword [rdi], 0
    mov  dword [rdi + 8], 0
    mov  eax, (XHCI_TRB_STATUS << 10) | (1 << 5) | (1 << 16)
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance
.publish_control:
%if PAOS_LAB_HP_EP0_WITNESS
    mov rax,[rel xhci_intr_queued]
    mov [rsp+0],rax
    mov rax,[rel xhci_intr_completed]
    mov [rsp+8],rax
    mov rax,[rel xhci_intr_erdp_accept]
    mov [rsp+16],rax
    mov rax,[rel xhci_intr_iman_accept]
    mov [rsp+24],rax
    mov rax,[rel xhci_intr_refused_slot]
    mov [rsp+32],rax
    mov rax,[rel xhci_intr_refused_ep]
    mov [rsp+40],rax
    mov rax,[rel xhci_intr_refused_cycle]
    mov [rsp+48],rax
    mov rax,[rel xhci_intr_refused_dup]
    mov [rsp+56],rax
    mov rax,[rel xhci_intr_refused_overflow]
    mov [rsp+64],rax
%endif
    sfence
    mov  esi, [rel xhci_db]
    lea  esi, [esi + ebx*4]
    mov  edx, 1
    call xh_wr
    mov  dword [rel xhci_ctl_residual], 0
    mov  dword [rel xhci_ctl_events], 0
.wait_td:
    mov  edi, XHCI_TRB_XFER_EVENT
    mov  esi, ebx
    mov  edx, 1                     ; EP0 DCI
    mov  dword [rel xhci_evt_cc], 0
    call xhci_evt_wait
    test eax, eax
    jz   .td_failed
    ; Success is this TD's STATUS event. Before it, an IN data stage may report a
    ; short packet (its residual); any other EP0 event on this slot is an earlier
    ; transfer's late completion and is consumed here, bounded.
    mov  rax, [rel xhci_evt_ptr]
    cmp  rax, [rel xhci_ctl_status_trb]
    je   .control_ok
    cmp  rax, [rel xhci_ctl_data_trb]
    jne  .not_this_td
    mov  eax, [rel xhci_evt_len]
    mov  [rel xhci_ctl_residual], eax
.not_this_td:
    inc  dword [rel xhci_ctl_events]
    cmp  dword [rel xhci_ctl_events], 4
    jb   .wait_td
    jmp  .fail
.td_failed:
%if PAOS_LAB_HP_EP0_WITNESS
    ; Observe the failed transfer before the existing halt recovery changes it.
    mov rdi, r15                    ; setup already read by this control transfer
    mov esi, r14d                   ; validated root port
    mov edx, ebx                    ; addressed slot
    mov rcx,rsp                     ; this transfer publication baseline
    call xhci_lab_ep0_snapshot
%endif
    ; A STALL (or babble / transaction error) halts EP0 (xHCI 4.10.2), and a halted
    ; EP0 ignores its doorbell: without recovery every later control transfer on
    ; this slot times out. Clear it now; xhci_evt_cc keeps this transfer's code.
    call xhci_ep0_recover_halt
    cmp  dword [rel xhci_evt_cc], 6 ; STALL is distinguishable for HID SET_IDLE
    jne  .fail
    mov  rax, -2                     ; sign-extended: callers test RAX or EAX
    jmp  .out
.control_ok:
    movzx r12d, word [r15 + usb_setup.wLength]   ; bytes moved = wLength - residual
    mov  eax, [rel xhci_ctl_residual]
    cmp  eax, r12d
    jbe  .residual_ok
    mov  eax, r12d                   ; a residual larger than the request moved nothing
.residual_ok:
    sub  r12d, eax

    ; Observe only successful on-wire transfers. On the second distinct device,
    ; the observer re-enters this exact control seam to re-read device one.
    mov  rdi, r15
    mov  esi, r14d
    mov  edx, ebx
    mov  rcx, r13
    mov  r8d, r12d
    call xhci_multislot_observe
    mov  eax, r12d
    jmp  .out
.fail:
    ; Name the refusal: which root port, which slot the port maps to (0 = never addressed),
    ; and the last completion code the event wait saw (0 = no event / timeout).
    lea  rdi, [rel str_xhci_ctl_fail]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_slot]
    call serial_string
    lea  rdx, [rel xhci_port_slot]
    mov  edi, [rdx + r14*4]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_cc]
    call serial_string
    mov  edi, [rel xhci_evt_cc]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_portsc]
    call serial_string
    mov  edi, r14d
    call xhci_read_portsc_live
    mov  edi, eax
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
    mov  rax, -1                     ; sign-extended: callers test RAX or EAX
.out:
%if PAOS_LAB_HP_EP0_WITNESS
    add rsp,80
%endif
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; xhci_ep0_recover_halt(EBX = validated slot) -> EAX = 0 not halted / 1 cleared /
;   -1 recovery failed. xHCI 4.6.8 + 4.6.10: a Halted endpoint takes a Reset
;   Endpoint Command (Halted -> Stopped, TSP = 0), then a Set TR Dequeue Pointer
;   Command past the failed TD; the next doorbell restarts it. The new dequeue is
;   this ring's own enqueue position and cycle, so no queued TRB is replayed. The
;   device side needs nothing more on the default control pipe: the next SETUP
;   clears a protocol STALL (USB 2.0 8.5.3.4). The EP State is read from the
;   slot's Output Device Context (EP0 = DCI 1, right after the Slot Context).
;   Preserves xhci_evt_cc. clobbers: caller-saved.
; ---------------------------------------------------------------------------
xhci_ep0_recover_halt:
    XHCI_POWER_GATE 1
    push r12
    push r13
    mov  r12d, [rel xhci_evt_cc]
    xor  r13d, r13d
    mov  rax, [rel xhci_dcbaa]
    test rax, rax
    jz   .done
    mov  rcx, [rax + rbx*8]
    test rcx, rcx
    jz   .done
    mov  edx, [rel xhci_ctxsz]
    mov  eax, [rcx + rdx]            ; EP0 Context dword 0
    and  eax, 7                      ; EP State
    cmp  eax, XHCI_EP_STATE_HALTED
    jne  .done
    mov  r13d, -1
    xor  edi, edi
    mov  esi, (XHCI_TRB_RESET_ENDPOINT << 10) | (1 << 16)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .report
    call xhci_ep0_current_trb        ; RDI = this slot's EP0 enqueue TRB
    lea  r9, [rel xhci_ep0_pcs]
    mov  eax, [r9 + rbx*4]
    and  eax, 1
    or   rdi, rax                    ; DCS = producer cycle, SCT = 0
    mov  esi, (XHCI_TRB_SET_TR_DEQUEUE << 10) | (1 << 16)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .report
    mov  r13d, 1
.report:
    lea  rdi, [rel str_xhci_ep0_halt_cleared]
    cmp  r13d, 1
    je   .say
    lea  rdi, [rel str_xhci_ep0_halt_failed]
.say:
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_halt_cc]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_halt_cmd]
    call serial_string
    mov  edi, [rel xhci_evt_cc]
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
.done:
    mov  [rel xhci_evt_cc], r12d
    mov  eax, r13d
    pop  r13
    pop  r12
    ret

; xhci_ep0_current_trb(EBX=validated slot) -> RDI=current private-ring TRB.
xhci_ep0_current_trb:
    mov  rdi, [rel xhci_ep0_base]
    mov  ecx, ebx
    dec  ecx
    shl  rcx, 12
    add  rdi, rcx
    lea  r9, [rel xhci_ep0_idx]
    mov  eax, [r9 + rbx*4]
    shl  eax, 4
    add  rdi, rax
    ret

; xhci_ep0_advance(EBX=validated slot) — advance only that slot's ring state.
xhci_ep0_advance:
    XHCI_POWER_GATE 1
    lea  r11, [rel xhci_ep0_idx]
    mov  eax, [r11 + rbx*4]
    inc  eax
    cmp  eax, 255
    jb   .store
    mov  r11, [rel xhci_ep0_base]
    mov  ecx, ebx
    dec  ecx
    shl  rcx, 12
    add  r11, rcx
    lea  rcx, [r11 + 255*16]
    mov  edx, (XHCI_TRB_LINK << 10) | (1 << 1)
    lea  r11, [rel xhci_ep0_pcs]
    or   edx, [r11 + rbx*4]
    mov  [rcx + 12], edx
    mov  edx, [r11 + rbx*4]
    xor  edx, 1
    mov  [r11 + rbx*4], edx
    xor  eax, eax
.store:
    lea  r11, [rel xhci_ep0_idx]
    mov  [r11 + rbx*4], eax
    ret

; ---------------------------------------------------------------------------
; xhci_address_port(R14D=root port) -> EAX=retained slot id / 0.
; Both ownership directions must agree before a cached slot can be reused.
; ---------------------------------------------------------------------------
xhci_address_port:
    XHCI_POWER_GATE 1
    test r14d, r14d
    jz   .fail_fast
    cmp  r14d, XHCI_PORT_COUNT - 1
    ja   .fail_fast
    cmp  r14d, [rel xhci_maxports]
    ja   .child_token
    lea  rdx, [rel xhci_port_slot]
    mov  eax, [rdx + r14*4]
    test eax, eax
    jz   .fresh
    cmp  eax, XHCI_MAX_SLOTS_EN
    ja   .stale_port
    lea  rcx, [rel xhci_slot_port]
    cmp  [rcx + rax*4], r14d
    je   .ret_cached
.stale_port:
    mov  dword [rdx + r14*4], 0
.fresh:
    bt   dword [rel xhci_port_quar], r14d
    jc   .quarantined_port           ; an earlier failure left uncertain slot state here
    push rbx
    mov  byte [rel xhci_addr_stage], 1          ; 1 = port reset
    mov  edi, r14d
    call xhci_port_reset
    test eax, eax
    jnz  .fail_pop
    mov  byte [rel xhci_addr_stage], 2          ; 2 = Enable Slot
    mov  byte [rel xhci_park_retry], 0
.enable_slot:
    xor  edi, edi
    mov  esi, (XHCI_TRB_ENABLE_SLOT << 10)
    call xhci_cmd_submit
    test eax, eax
    jnz  .enabled
    cmp  dword [rel xhci_evt_cc], XHCI_CC_SUCCESS
    jne  .fail_pop
    mov  byte [rel xhci_addr_stage], 3          ; F3-R12: a Success naming an invalid id is this
    jmp  .fail_pop                              ; port's own failure (port quarantined, no Disable)
.enabled:
    mov  byte [rel xhci_addr_stage], 3          ; 3 = slot id out of range (classification backstop)
    cmp  eax, XHCI_MAX_SLOTS_EN
    ja   .fail_pop
    cmp  eax, [rel xhci_maxslots]
    ja   .fail_pop
    mov  ebx, eax
    mov  byte [rel xhci_addr_stage], 4          ; 4 = slot already bound to a port
    lea  rdx, [rel xhci_slot_port]
    cmp  dword [rdx + rbx*4], 0
    jne  .fail_pop
    ; PARK P1: a Success Enable Slot handing back a QUARANTINED id proves the controller now
    ; holds it allocated. It is PARKED (never addressed, bound, written or disabled) until
    ; controller reset. P2: one more Enable Slot for this port.
    bt   dword [rel xhci_slot_quar], ebx
    jnc  .fresh_id
    bts  dword [rel xhci_slot_parked], ebx
    cmp  byte [rel xhci_park_retry], 0
    jne  .park_failed
    mov  byte [rel xhci_park_retry], 1
    jmp  .enable_slot
.park_failed:
    inc  dword [rel xhci_park_retry_fail]
    mov  byte [rel xhci_addr_stage], 9          ; 9 = parked and retried (SLOT_STATE): the port is innocent
    jmp  .fail_pop
.fresh_id:
    mov  byte [rel xhci_addr_stage], 5          ; 5 = DCBAA entry missing
    mov  rax, [rel xhci_dcbaa]
    mov  rcx, [rax + rbx*8]
    test rcx, rcx
    jz   .fail_pop
    mov  byte [rel xhci_addr_stage], 6          ; 6 = input context
    call xhci_build_input_ctx        ; -> RAX = private input-context page
    test rax, rax
    jz   .fail_pop
    mov  byte [rel xhci_addr_stage], 7          ; 7 = Address Device
    mov  rdi, rax
    mov  esi, (XHCI_TRB_ADDRESS_DEVICE << 10)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .fail_pop
    lea  rdx, [rel xhci_slot_port]
    mov  [rdx + rbx*4], r14d
    lea  rdx, [rel xhci_port_slot]
    mov  [rdx + r14*4], ebx
    ; HUB0 topology: a root-port device has route 0, depth 0, no parent/TT.
    mov  eax, ebx
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    mov  qword [rdx], 0
    mov  qword [rdx + 8], 0
    mov  [rdx + usb_topo.slot], bl
    mov  [rdx + usb_topo.root], r14b
    lea  rax, [rel xhci_slot_speed]
    mov  eax, [rax + rbx*4]
    mov  [rdx + usb_topo.speed], al
    mov  eax, [rel xhci_dev]
    mov  [rdx + usb_topo.pci_dev], al
    mov  eax, [rel xhci_fn]
    mov  [rdx + usb_topo.pci_fn], al
    sfence
    call xhci_ep0_probe_mps                     ; USB 2.0 §9.1.2: honour bMaxPacketSize0
    mov  eax, ebx
    pop  rbx
    ret
.fail_pop:
    lea  rdi, [rel str_xhci_addr_fail]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_stage]
    call serial_string
    movzx edi, byte [rel xhci_addr_stage]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_cc]
    call serial_string
    mov  edi, [rel xhci_evt_cc]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_evslot]
    call serial_string
    mov  edi, [rel xhci_evt_slot]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_portsc]
    call serial_string
    mov  edi, r14d
    call xhci_read_portsc_live
    mov  edi, eax
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
    call xhci_root_slot_cleanup
    xor  eax, eax
    pop  rbx
    ret
.ret_cached:
    ret
.quarantined_port:
    inc  dword [rel xhci_x3_port_refused]
    xor  eax, eax
    ret
.child_token:
    ; HUB0: a hub child is addressed only by xhci_op_hub_address_child; the
    ; control path resolves its published token and never lazily resets it.
    mov  esi, r14d
    jmp  xhci_interrupt_slot_for_port
.fail_fast:
    xor  eax, eax
    ret

; xhci_root_slot_cleanup(EBX=slot, R14D=root port; xhci_addr_stage = the failed
; stage). A root-port address failure must not leak the slot Enable Slot gave
; it. Stages 5..7 hold a slot that is positively newly allocated, in range and
; bound to no port, so it is returned with Disable Slot (xHCI 1.2 4.6.4); no
; transfer TD was ever queued on it. A Disable confirmed under F.3.3 runs R4
; (xhci_slot_reclaim). Stages 3/4 (an invalid id, or an id the driver already
; binds to another port) are never disabled: that could hit a peer. Any
; uncertain outcome marks the port, and a failed Disable the slot, as
; quarantined until the next controller reset, so .fresh never loops on
; Enable Slot there. Stage 9 (S10-A1 PARK P2: a second quarantined id handed
; back) disables nothing and leaves the port unquarantined. clobbers: caller-saved.
xhci_root_slot_cleanup:
    XHCI_POWER_GATE 1
    movzx eax, byte [rel xhci_addr_stage]
    cmp  eax, 3
    jb   .done                       ; port reset / Enable Slot failed: no slot to return
    cmp  eax, 5
    jb   .quarantine_port
    cmp  eax, 9
    je   .done                       ; PARK P2/P3: parked ids are never disabled; the port is innocent
    inc  dword [rel xhci_x3_disable_n]
    xor  edi, edi
    mov  esi, (XHCI_TRB_DISABLE_SLOT << 10)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit             ; waits for exactly this slot's completion
    mov  edx, [rel xhci_evt_cc]
    mov  [rel xhci_x3_last_cc], edx
    cmp  eax, ebx
    jne  .quarantine_slot
    call xhci_slot_reclaim           ; R4: the confirmed-disabled id is FREE again
    ret
.quarantine_slot:
    bts  dword [rel xhci_slot_quar], ebx
.quarantine_port:
    bts  dword [rel xhci_port_quar], r14d
.done:
    ret

; xhci_slot_reclaim(EBX = slot id whose Disable Slot was confirmed under F.3.3) — S10-A1 F.2
;   R4, one non-yielding unit per controller: no command is posted and DB0 is never written
;   inside it.
;   1. DCBAA[S] = 0, sfence (the §4.6.4 clear, honoured transiently).
;   2. Zero S's output-context stride and its EP0 page.
;   3. DCBAA[S] = S's own stride again: the boot pre-population rule (:1024-1042) for the
;      Intel early fetch. R3-I1: an unallocated slot's entry is non-zero, the recorded
;      deviation from "unallocated entries shall be 0" (harmless: no Save/Restore State).
;   4. Clear S's maps and topology, sfence: S is FREE.
;   An id outside 1..XHCI_MAX_SLOTS_EN is never written. Preserves rbx, r12-r15.
xhci_slot_reclaim:
    XHCI_POWER_GATE 1
    test ebx, ebx
    jz   .out
    cmp  ebx, XHCI_MAX_SLOTS_EN
    ja   .out
    mov  rdx, [rel xhci_dcbaa]
    mov  qword [rdx + rbx*8], 0
    sfence
    mov  eax, ebx
    dec  eax
    imul eax, XHCI_OUT_CTX_STRIDE
    mov  rdi, [rel xhci_out_ctx]
    add  rdi, rax
    mov  r8, rdi                     ; the id's own stride
    mov  ecx, XHCI_OUT_CTX_STRIDE / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel xhci_ep0_base]
    mov  ecx, ebx
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    call xhci_zero_page
    mov  rdx, [rel xhci_dcbaa]
    mov  [rdx + rbx*8], r8
    lea  rdx, [rel xhci_slot_port]
    mov  ecx, [rdx + rbx*4]
    mov  dword [rdx + rbx*4], 0
    cmp  ecx, XHCI_PORT_COUNT
    jae  .maps_done
    lea  rdx, [rel xhci_port_slot]
    cmp  [rdx + rcx*4], ebx
    jne  .maps_done
    mov  dword [rdx + rcx*4], 0
.maps_done:
    lea  rdx, [rel xhci_ep0_idx]
    mov  dword [rdx + rbx*4], 0
    lea  rdx, [rel xhci_ep0_pcs]
    mov  dword [rdx + rbx*4], 1
    mov  eax, ebx
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    mov  qword [rdx + rax], 0
    mov  qword [rdx + rax + 8], 0
    sfence
.out:
    ret

; ---------------------------------------------------------------------------
; xhci_ep0_probe_mps(EBX=validated slot, R14D=root port) — USB 2.0 §9.1.2 /
;   xHCI 4.3.4: read the FIRST 8 bytes of the device descriptor with the port-
;   speed default EP0 MPS, then, when bMaxPacketSize0 differs, re-declare EP0
;   through Evaluate Context. Without this a device whose PORTSC speed field
;   does not match its real EP0 packet size (Lenovo M720s, ASIX dongle port)
;   fails every descriptor read and is skipped silently. Failures leave the
;   slot as addressed; the decision is printed to serial either way.
;   clobbers caller-saved; preserves rbx, r12-r15.
; ---------------------------------------------------------------------------
xhci_ep0_probe_mps:
    XHCI_POWER_GATE 1
    push r12
    push r13
    push r15
    lea  r12, [rel xhci_probe_buf]
    mov  qword [r12], 0
    ; SETUP: GET_DESCRIPTOR(DEVICE, index 0, wLength 8), IDT, TRT = IN data stage
    call xhci_ep0_current_trb
    mov  rax, 0x0008000001000680
    mov  [rdi], rax
    mov  dword [rdi + 8], 8
    mov  eax, (XHCI_TRB_SETUP << 10) | (1 << 6) | (3 << 16)
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance
    ; DATA IN: 8 bytes into the private probe buffer
    call xhci_ep0_current_trb
    mov  [rdi], r12
    mov  dword [rdi + 8], 8
    mov  eax, (XHCI_TRB_DATA << 10) | (1 << 16)
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance
    ; STATUS OUT with IOC
    call xhci_ep0_current_trb
    mov  qword [rdi], 0
    mov  dword [rdi + 8], 0
    mov  eax, (XHCI_TRB_STATUS << 10) | (1 << 5)
    lea  r9, [rel xhci_ep0_pcs]
    or   eax, [r9 + rbx*4]
    mov  [rdi + 12], eax
    call xhci_ep0_advance
    sfence
    mov  esi, [rel xhci_db]
    lea  esi, [esi + ebx*4]
    mov  edx, 1
    call xh_wr
    mov  edi, XHCI_TRB_XFER_EVENT
    mov  esi, ebx
    mov  edx, 1
    mov  dword [rel xhci_evt_cc], 0
    call xhci_evt_wait
    test eax, eax
    jz   .probe_failed
    cmp  byte [r12], 0x12                       ; bLength of a DEVICE descriptor
    jne  .probe_failed
    cmp  byte [r12 + 1], 0x01
    jne  .probe_failed
    movzx r13d, byte [r12 + 7]                  ; bMaxPacketSize0 (SS: exponent)
    lea  r9, [rel xhci_slot_speed]
    mov  eax, [r9 + rbx*4]
    cmp  eax, 4
    jne  .mps_bytes
    mov  eax, 1
    mov  ecx, r13d
    cmp  ecx, 12
    ja   .probe_failed
    shl  eax, cl
    mov  r13d, eax
.mps_bytes:
    cmp  r13d, 8
    jb   .probe_failed
    cmp  r13d, 512
    ja   .probe_failed
    lea  r9, [rel xhci_slot_mps]
    cmp  r13d, [r9 + rbx*4]
    je   .report                                ; the default already matches
    ; Evaluate Context: EP0 only (A1), new MPS in the slot's retained input page
    mov  rax, [rel xhci_in_ctx_base]
    mov  ecx, ebx
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    mov  r15, rax
    mov  dword [r15], 0                         ; drop flags
    mov  dword [r15 + 4], (1 << 1)              ; add EP0
    mov  ecx, [rel xhci_ctxsz]
    lea  rdi, [r15 + rcx*2]                     ; EP0 context
    mov  eax, [rdi + 4]
    and  eax, 0x0000FFFF
    mov  edx, r13d
    shl  edx, 16
    or   eax, edx
    mov  [rdi + 4], eax
    sfence
    mov  rdi, r15
    mov  esi, (XHCI_TRB_EVALUATE_CONTEXT << 10)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .eval_failed
    lea  r9, [rel xhci_slot_mps]
    mov  [r9 + rbx*4], r13d
    lea  rdi, [rel str_xhci_ep0_updated]
    call serial_string
    jmp  .print_common
.eval_failed:
    lea  rdi, [rel str_xhci_ep0_evalfail]
    call serial_string
    jmp  .print_common
.probe_failed:
    lea  rdi, [rel str_xhci_ep0_probefail]
    call serial_string
    mov  edi, [rel xhci_evt_cc]
    call serial_hex64
    jmp  .print_common
.report:
    lea  rdi, [rel str_xhci_ep0_ok]
    call serial_string
.print_common:
    lea  rdi, [rel str_xhci_ep0_slot]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_port]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_speed]
    call serial_string
    lea  r9, [rel xhci_slot_speed]
    mov  edi, [r9 + rbx*4]
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_mps]
    call serial_string
    lea  r9, [rel xhci_slot_mps]
    mov  edi, [r9 + rbx*4]
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_probed]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
    pop  r15
    pop  r13
    pop  r12
    ret

str_xhci_ep0_updated:   db "[PAOS64] P2 usb-xhci: EP0 MPS re-declared via Evaluate Context", 0
str_xhci_ep0_evalfail:  db "[PAOS64] P2 usb-xhci: EP0 MPS Evaluate Context refused", 0
str_xhci_ep0_probefail: db "[PAOS64] P2 usb-xhci: EP0 8-byte descriptor probe failed cc=", 0
str_xhci_ep0_ok:        db "[PAOS64] P2 usb-xhci: EP0 MPS default confirmed by probe", 0
str_xhci_ep0_slot:      db " slot=", 0
str_xhci_ep0_port:      db " port=", 0
str_xhci_ep0_speed:     db " speed=", 0
str_xhci_ep0_mps:       db " mps=", 0
str_xhci_ep0_probed:    db " probed=", 0
str_xhci_ep0_nl:        db 13, 10, 0
str_xhci_addr_fail:     db "[PAOS64] P2 usb-xhci: address refused port=", 0
str_xhci_ctl_fail:      db "[PAOS64] P2 usb-xhci: control transfer failed port=", 0
str_xhci_ep0_halt_cleared: db "[PAOS64] P2 usb-xhci: EP0 halt cleared (Reset Endpoint + Set TR Dequeue) slot=", 0
str_xhci_ep0_halt_failed:  db "[PAOS64] P2 usb-xhci: EP0 halt recovery FAILED slot=", 0
str_xhci_ep0_halt_cc:      db " xfer_cc=", 0
str_xhci_ep0_halt_cmd:     db " cmd_cc=", 0
str_xhci_addr_evslot:   db " evt_slot=", 0
str_xhci_cmd_abort:     db "[PAOS64] P2 usb-xhci: command timed out; ring aborted (CRCR.CA) drained_cc=", 0
xhci_inst_r2:                     ; per-controller state (swapped)
xhci_wait_budget:       dd XHCI_CMD_BUDGET_US / 100
xhci_cmd_ring_dead:     db 0                        ; abort failed; quarantined until verified HCRST
str_xhci_addr_stage:    db " stage=", 0
str_xhci_addr_cc:       db " last_cc=", 0
str_xhci_addr_portsc:   db " portsc=", 0
xhci_addr_stage:        db 0
align 8
xhci_probe_buf:   dq 0, 0                       ; 16-byte landing buffer for the 8-byte probe
xhci_slot_speed:  times XHCI_SLOT_COUNT dd 0    ; PORTSC speed at Address Device
xhci_slot_mps:    times XHCI_SLOT_COUNT dd 0    ; EP0 MPS currently declared to the controller
xhci_inst_r2_end:

; xhci_build_input_ctx(EBX=slot,R14D=port) -> RAX=private input-context page / 0.
xhci_build_input_ctx:
    XHCI_POWER_GATE 1
    test ebx, ebx
    jz   .invalid
    cmp  ebx, XHCI_MAX_SLOTS_EN
    ja   .invalid
    push rbx
    push r12
    push r13
    push r15
    mov  r15d, ebx
    mov  rax, [rel xhci_ep0_base]
    mov  ecx, r15d
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    call xhci_zero_page
    lea  rdi, [rax + 255*16]
    mov  [rdi], rax
    mov  dword [rdi + 8], 0
    mov  dword [rdi + 12], (XHCI_TRB_LINK << 10) | (1 << 1) | 1
    lea  r11, [rel xhci_ep0_idx]
    mov  dword [r11 + r15*4], 0
    lea  r11, [rel xhci_ep0_pcs]
    mov  dword [r11 + r15*4], 1

    mov  rax, [rel xhci_in_ctx_base]
    mov  ecx, r15d
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    call xhci_zero_page
    mov  r12, rax
    mov  r13d, [rel xhci_ctxsz]
    mov  dword [r12 + 4], (1 << 0) | (1 << 1)
    mov  edi, r14d
    call xhci_portsc_off
    mov  esi, eax
    call xh_rd
    shr  eax, XHCI_PORTSC_SPEED_SH
    and  eax, XHCI_PORTSC_SPEED_MASK
    mov  ebx, eax
    mov  rdi, r12
    add  rdi, r13
    mov  eax, ebx
    shl  eax, 20
    or   eax, (1 << 27)
    mov  [rdi], eax
    mov  eax, r14d
    shl  eax, 16
    mov  [rdi + 4], eax
    mov  rdi, r12
    lea  rax, [r13 + r13]
    add  rdi, rax
    mov  dword [rdi], 0
    lea  r11, [rel xhci_slot_speed]
    mov  [r11 + r15*4], ebx                     ; PORTSC speed for this slot
    call xhci_mps_for_speed
    lea  r11, [rel xhci_slot_mps]
    mov  [r11 + r15*4], eax                     ; default EP0 MPS declared to the controller
    shl  eax, 16
    or   eax, (4 << 3) | (3 << 1)
    mov  [rdi + 4], eax
    mov  rax, [rel xhci_ep0_base]
    mov  ecx, r15d
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    or   rax, 1
    mov  [rdi + 8], eax
    mov  rcx, rax
    shr  rcx, 32
    mov  [rdi + 12], ecx
    sfence
    mov  rax, r12
    pop  r15
    pop  r13
    pop  r12
    pop  rbx
    ret
.invalid:
    xor  eax, eax
    ret

; ===========================================================================
; HUB0 backend half of the generic hub class (usb/enum owns the protocol and
; policy; these three ops own only xHCI Slot-Context work).
; ===========================================================================

; xhci_op_topology(self, RSI=addr, RDX=usb_topo*) -> RAX 0/-1. Read-only copy
; of the retained per-slot identity of a published owner.
xhci_op_topology:
    XHCI_POWER_GATE 2
    test rdx, rdx
    jz   .fail
    mov  r8, rdx
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  ecx, eax
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    cmp  [rdx + usb_topo.slot], cl
    jne  .fail
    mov  rax, [rdx]
    mov  [r8], rax
    mov  rax, [rdx + 8]
    mov  [r8 + 8], rax
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; xhci_op_hub_configure(self, RSI=hub addr, EDX=ports, ECX=TT think time,
;   R8D=MTT selection) -> RAX 0/-1. xHCI 1.2 4.6.6 Configure Endpoint + 6.2.2 Slot Context:
;   one Configure Endpoint carrying ONLY the Slot Context (A0) with Hub=1,
;   Number of Ports and (HS hubs) TT Think Time over the controller's current
;   Output Slot Context, so route/speed/root/TT stay exactly as addressed. The
;   default alternate setting is single-TT; MTT selection is refused. hub_ctx
;   bit 0 = the controller ACCEPTED these hub fields (the command completed for
;   this slot): a LS/FS child behind a HS hub is refused unless it is set.
;   Bit 1 = the Output Slot Context also reads back Hub + Number of Ports -
;   diagnostic only: those fields are software-owned input and an xHC need not
;   reflect them (it may keep only Context Entries current); requiring the echo
;   refused every LS/FS device behind a HS hub there (RCQ-09 Reatan hub child).
xhci_op_hub_configure:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edx
    mov  r13d, ecx
    mov  r14d, r8d
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  ebx, eax
    test r12d, r12d
    jz   .fail
    cmp  r12d, USB_HUB_MAX_PORTS
    ja   .fail
    cmp  r13d, 3
    ja   .fail
    test r14d, r14d
    jnz  .fail
    mov  eax, ebx
    shl  eax, 4
    lea  r15, [rel xhci_slot_topo]
    add  r15, rax
    cmp  [r15 + usb_topo.slot], bl
    jne  .fail
    mov  rax, [rel xhci_dcbaa]
    cmp  qword [rax + rbx*8], 0
    je   .fail
    mov  rax, [rel xhci_in_ctx_base]
    mov  ecx, ebx
    dec  ecx
    shl  rcx, 12
    add  rax, rcx
    call xhci_zero_page
    mov  r14, rax                      ; private input context page
    mov  dword [r14 + 4], 1            ; add A0 only
    mov  rax, [rel xhci_dcbaa]
    mov  rsi, [rax + rbx*8]
    mov  ecx, [rel xhci_ctxsz]
    lea  rdi, [r14 + rcx]
    shr  ecx, 3
    lfence
    rep  movsq
    mov  ecx, [rel xhci_ctxsz]
    lea  rdi, [r14 + rcx]
    mov  eax, [rdi]
    and  eax, 0xF9FFFFFF               ; replace Hub(26) + MTT(25)
    or   eax, 1 << 26
    mov  [rdi], eax
    mov  eax, [rdi + 4]
    and  eax, 0x00FFFFFF
    mov  edx, r12d
    shl  edx, 24
    or   eax, edx                      ; Number of Ports
    mov  [rdi + 4], eax
    mov  eax, [rdi + 8]
    and  eax, 0xFFFCFFFF
    cmp  byte [r15 + usb_topo.speed], USB_SPEED_HIGH
    jne  .ttt_ready
    mov  edx, r13d
    shl  edx, 16
    or   eax, edx                      ; TT Think Time
.ttt_ready:
    mov  [rdi + 8], eax
    mov  dword [rdi + 12], 0           ; slot state/address are controller-owned
    sfence
    mov  rdi, r14
    mov  esi, (XHCI_TRB_CONFIGURE_ENDPOINT << 10)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .fail
    mov  [r15 + usb_topo.hub_ports], r12b
    mov  byte [r15 + usb_topo.hub_ctx], 1    ; accepted by the controller
    mov  rax, [rel xhci_dcbaa]
    mov  rax, [rax + rbx*8]
    lfence
    mov  edx, [rax]
    test edx, 1 << 26
    jz   .ok
    mov  edx, [rax + 4]
    shr  edx, 24
    cmp  edx, r12d
    jne  .ok
    mov  byte [r15 + usb_topo.hub_ctx], 3    ; ... and echoed in the Output Slot Context
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_op_hub_address_child(self, RSI=hub addr, EDX=hub port, ECX=child speed)
;   -> RAX = child token (XHCI_CHILD_ADDR_BASE + slot) / 0. The hub class has
;   already powered, reset and enabled the downstream port. Route string, depth
;   and TT come from the shared pure gates (usb_hub_route_extend /
;   usb_hub_child_tt) over the parent's retained identity; Enable Slot ->
;   private EP0 ring/input context -> Slot Context {route, speed, root port,
;   TT hub slot/port} -> Address Device. Both ownership directions and the
;   topology are published only after Address Device earns the slot; any
;   failure after Enable Slot disables that exact slot. Never touches the
;   parent or a sibling slot.
xhci_op_hub_address_child:
    XHCI_POWER_GATE 1
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12d, edx                      ; hub port
    mov  r13d, ecx                      ; child speed
    xor  ebx, ebx
    mov  byte [rel xhci_hub_child_stage], 1
    mov  dword [rel xhci_hub_child_parent], 0
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .fail
    mov  ebp, eax                       ; parent slot
    mov  [rel xhci_hub_child_parent], eax
    shl  eax, 4
    lea  r15, [rel xhci_slot_topo]
    add  r15, rax
    cmp  [r15 + usb_topo.slot], bpl
    jne  .fail
    movzx eax, byte [r15 + usb_topo.hub_ports]
    test eax, eax
    jz   .fail                          ; parent never configured as a hub
    test r12d, r12d
    jz   .fail
    cmp  r12d, eax
    ja   .fail
    cmp  dword [rel xhci_maxports], XHCI_CHILD_ADDR_BASE
    jae  .fail
    mov  byte [rel xhci_hub_child_stage], 2
    mov  edi, [r15 + usb_topo.route]
    movzx esi, byte [r15 + usb_topo.depth]
    mov  edx, r12d
    call usb_hub_route_extend
    test rax, rax
    js   .fail
    mov  [rsp], eax                     ; route | depth << 24
    mov  byte [rel xhci_hub_child_stage], 3
    mov  edi, ebp
    movzx esi, byte [r15 + usb_topo.speed]
    movzx edx, word [r15 + usb_topo.tt_slot]
    mov  ecx, r12d
    mov  r8d, r13d
    call usb_hub_child_tt
    test rax, rax
    js   .fail
    mov  [rsp + 4], eax                 ; TT hub slot | TT port << 8
    test eax, eax
    jz   .tt_ready
    movzx ecx, al
    shl  ecx, 4
    lea  rdx, [rel xhci_slot_topo]
    test byte [rdx + rcx + usb_topo.hub_ctx], 1
    jz   .fail                          ; hub fields never accepted: fail closed
.tt_ready:
    mov  byte [rel xhci_hub_child_stage], 4
    mov  byte [rel xhci_park_retry], 0
.enable_slot:
    xor  edi, edi
    mov  esi, (XHCI_TRB_ENABLE_SLOT << 10)
    call xhci_cmd_submit
    test eax, eax
    jnz  .enabled
    cmp  dword [rel xhci_evt_cc], XHCI_CC_SUCCESS
    jne  .fail
    mov  byte [rel xhci_hub_child_stage], 5   ; F3-R12: a Success naming an invalid id fails here,
    jmp  .fail                                ; with no Disable for an id that was never valid
.enabled:
    mov  ebx, eax
    mov  byte [rel xhci_hub_child_stage], 5
    cmp  ebx, XHCI_MAX_SLOTS_EN
    ja   .disable
    cmp  ebx, [rel xhci_maxslots]
    ja   .disable
    lea  rdx, [rel xhci_slot_port]
    cmp  dword [rdx + rbx*4], 0
    jne  .fail                          ; a published owner is never disabled here
    bt   dword [rel xhci_slot_quar], ebx
    jnc  .fresh_id                      ; PARK P1/P2, as on the root path
    bts  dword [rel xhci_slot_parked], ebx
    cmp  byte [rel xhci_park_retry], 0
    jne  .park_failed
    mov  byte [rel xhci_park_retry], 1
    jmp  .enable_slot
.park_failed:
    inc  dword [rel xhci_park_retry_fail]
    mov  byte [rel xhci_hub_child_stage], 9   ; 9 = parked and retried (SLOT_STATE)
    jmp  .fail
.fresh_id:
    lea  r14d, [rbx + XHCI_CHILD_ADDR_BASE]
    lea  rdx, [rel xhci_port_slot]
    mov  dword [rdx + r14*4], 0         ; no stale token cache survives
    mov  rax, [rel xhci_dcbaa]
    cmp  qword [rax + rbx*8], 0
    je   .disable
    mov  byte [rel xhci_hub_child_stage], 6
    push r14
    movzx r14d, byte [r15 + usb_topo.root]
    call xhci_build_input_ctx           ; EBX=slot, R14D=root -> fresh EP0 ring + A0|A1
    pop  r14
    test rax, rax
    jz   .disable
    mov  rdi, rax
    mov  ecx, [rel xhci_ctxsz]
    mov  eax, [rsp]
    and  eax, 0x000FFFFF                ; Route String
    mov  edx, r13d
    shl  edx, 20
    or   eax, edx                       ; Speed
    or   eax, 1 << 27                   ; Context Entries = 1 (EP0)
    mov  [rdi + rcx], eax
    movzx eax, byte [r15 + usb_topo.root]
    shl  eax, 16
    mov  [rdi + rcx + 4], eax           ; Root Hub Port Number
    mov  eax, [rsp + 4]
    mov  [rdi + rcx + 8], eax           ; TT Hub Slot ID / TT Port Number
    mov  dword [rdi + rcx + 12], 0
    lea  rdx, [rel xhci_slot_speed]
    mov  [rdx + rbx*4], r13d
    push rbx
    mov  ebx, r13d
    call xhci_mps_for_speed
    pop  rbx
    lea  rdx, [rel xhci_slot_mps]
    mov  [rdx + rbx*4], eax
    mov  ecx, [rel xhci_ctxsz]
    lea  r8, [rdi + rcx*2]              ; EP0 context
    mov  edx, [r8 + 4]
    and  edx, 0x0000FFFF
    shl  eax, 16
    or   edx, eax
    mov  [r8 + 4], edx
    sfence
    mov  byte [rel xhci_hub_child_stage], 7
    mov  esi, (XHCI_TRB_ADDRESS_DEVICE << 10)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit                ; RDI = input context
    cmp  eax, ebx
    jne  .disable
    mov  byte [rel xhci_hub_child_stage], 8
    mov  eax, ebx
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    mov  qword [rdx], 0
    mov  qword [rdx + 8], 0
    mov  [rdx + usb_topo.slot], bl
    mov  al, [r15 + usb_topo.root]
    mov  [rdx + usb_topo.root], al
    mov  eax, [rsp]
    mov  ecx, eax
    shr  ecx, 24
    mov  [rdx + usb_topo.depth], cl
    and  eax, 0x000FFFFF
    mov  [rdx + usb_topo.route], eax
    mov  [rdx + usb_topo.speed], r13b
    mov  [rdx + usb_topo.parent_slot], bpl
    mov  [rdx + usb_topo.parent_port], r12b
    mov  ax, [rsp + 4]
    mov  [rdx + usb_topo.tt_slot], ax
    mov  al, [r15 + usb_topo.pci_dev]
    mov  [rdx + usb_topo.pci_dev], al
    mov  al, [r15 + usb_topo.pci_fn]
    mov  [rdx + usb_topo.pci_fn], al
    lea  rdx, [rel xhci_slot_port]
    mov  [rdx + rbx*4], r14d
    lea  rdx, [rel xhci_port_slot]
    mov  [rdx + r14*4], ebx
    sfence
    call xhci_ep0_probe_mps             ; EBX=slot, R14D=token (diagnostic only)
    mov  eax, r14d
    jmp  .out
.disable:
    mov  dl, [rel xhci_hub_child_stage]
    mov  [rel xhci_hub_child_fail_stage], dl
    mov  edx, [rel xhci_evt_cc]
    mov  [rel xhci_hub_child_fail_cc], edx
    xor  edi, edi
    mov  esi, (XHCI_TRB_DISABLE_SLOT << 10)
    mov  eax, ebx
    shl  eax, 24
    or   esi, eax
    call xhci_cmd_submit
    cmp  eax, ebx
    jne  .uncertain
    bt   dword [rel xhci_slot_quar], ebx
    jc   .report                     ; a quarantined id keeps its reserved set until reset
    call xhci_slot_reclaim           ; R4: the confirmed-disabled id is FREE again
    jmp  .report
.uncertain:
    cmp  ebx, XHCI_MAX_SLOTS_EN      ; uncertain outcome: an in-range id stays quarantined
    ja   .report                     ; until controller reset (out-of-range ids have no bit)
    cmp  ebx, [rel xhci_maxslots]    ; XA0R3-2: bits only for 1..min(maxslots, XHCI_MAX_SLOTS_EN)
    ja   .report
    bts  dword [rel xhci_slot_quar], ebx
    jmp  .report
.fail:
    mov  dl, [rel xhci_hub_child_stage]
    mov  [rel xhci_hub_child_fail_stage], dl
    mov  edx, [rel xhci_evt_cc]
    mov  [rel xhci_hub_child_fail_cc], edx
.report:
    ; RCQ-09: the per-controller copy above swaps out with the instance; keep the
    ; last refusal (and a count) where a serial-less USBPORTS read still finds it.
    inc  dword [rel xhci_hub_last_n]
    mov  eax, [rel xhci_inst_cur]
    mov  [rel xhci_hub_last_inst], al
    mov  eax, [rel xhci_hub_child_parent]
    mov  [rel xhci_hub_last_parent], al
    mov  [rel xhci_hub_last_port], r12b
    mov  al, [rel xhci_hub_child_fail_stage]
    mov  [rel xhci_hub_last_stage], al
    mov  eax, [rel xhci_hub_child_fail_cc]
    mov  [rel xhci_hub_last_cc], eax
    lea  rdi, [rel str_xhci_hub_child_fail]
    call serial_string
    mov  edi, [rel xhci_hub_child_parent]
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_port]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_stage]
    call serial_string
    movzx edi, byte [rel xhci_hub_child_fail_stage]
    call serial_hex64
    lea  rdi, [rel str_xhci_addr_cc]
    call serial_string
    mov  edi, [rel xhci_hub_child_fail_cc]
    call serial_hex64
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
    xor  eax, eax
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

str_xhci_hub_child_fail: db "[PAOS64] P2 usb-xhci: hub child address refused parent_slot=", 0

; xhci_hub_child_last() -> RAX = the last hub-child address refusal, any controller:
;   +0 count(d) +4 xHCI instance +5 parent slot +6 hub port +7 stage +8 completion code(d).
xhci_hub_child_last:
    lea  rax, [rel xhci_hub_last_n]
    ret
align 4
xhci_hub_last_n:      dd 0              ; NOT swapped: survives the instance switch
xhci_hub_last_inst:   db 0
xhci_hub_last_parent: db 0
xhci_hub_last_port:   db 0
xhci_hub_last_stage:  db 0
xhci_hub_last_cc:     dd 0
align 4
xhci_inst_r3:                     ; per-controller state (swapped)
xhci_hub_child_parent:     dd 0
xhci_hub_child_fail_cc:    dd 0
xhci_hub_child_stage:      db 0
xhci_hub_child_fail_stage: db 0
align 8
xhci_slot_topo:   times (XHCI_SLOT_COUNT * usb_topo_size) db 0   ; HUB0 per-slot topology
xhci_inst_r3_end:

; xhci_multislot_observe(RDI=setup*,ESI=port,EDX=slot,RCX=buf,R8D=len)
; Earn the receipt only from two real DEVICE-descriptor transfers. After device
; two, re-read device one through the unchanged usbhc_ops.control function.
xhci_multislot_observe:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel xhci_multi_active], 0
    jne  .out
    cmp  byte [rel xhci_multi_emitted], 0
    jne  .out
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    cmp  r8d, 18
    jne  .out
    cmp  byte [r12 + usb_setup.bmRequestType], 0x80
    jne  .out
    cmp  byte [r12 + usb_setup.bRequest], 6
    jne  .out
    cmp  word [r12 + usb_setup.wValue], 0x0100
    jne  .out
    cmp  word [r12 + usb_setup.wLength], 18
    jne  .out
    cmp  byte [r15], 0x12
    jne  .out
    cmp  byte [r15 + 1], 0x01
    jne  .out
    test r13d, r13d
    jz   .out
    cmp  r13d, XHCI_PORT_COUNT - 1
    ja   .out
    test r14d, r14d
    jz   .out
    cmp  r14d, XHCI_MAX_SLOTS_EN
    ja   .out
    lea  rax, [rel xhci_port_slot]
    cmp  [rax + r13*4], r14d
    jne  .out
    lea  rax, [rel xhci_slot_port]
    cmp  [rax + r14*4], r13d
    jne  .out

    mov  eax, [rel xhci_multi_first_slot]
    test eax, eax
    jnz  .have_first
    mov  [rel xhci_multi_first_slot], r14d
    mov  [rel xhci_multi_first_port], r13d
    mov  rsi, r15
    lea  rdi, [rel xhci_multi_first_desc]
    mov  ecx, 18
    rep  movsb
    jmp  .out
.have_first:
    cmp  eax, r14d
    je   .out
    mov  [rel xhci_multi_second_slot], r14d
    mov  [rel xhci_multi_second_port], r13d
    mov  rsi, r15
    lea  rdi, [rel xhci_multi_second_desc]
    mov  ecx, 18
    rep  movsb
    mov  byte [rel xhci_multi_active], 1

    lea  rdi, [rel xhci_hcdev]
    lea  rsi, [rel xhci_multi_setup]
    mov  edx, [rel xhci_multi_first_port]
    lea  rcx, [rel xhci_multi_recheck_desc]
    mov  r8d, 18
    lea  rax, [rel xhci_ops]
    call [rax + usbhc_ops.control]
    cmp  eax, 18
    jne  .retry_later
    cmp  byte [rel xhci_multi_recheck_desc], 0x12
    jne  .retry_later
    cmp  byte [rel xhci_multi_recheck_desc + 1], 0x01
    jne  .retry_later
    cmp  byte [rel xhci_multi_second_desc], 0x12
    jne  .retry_later
    cmp  byte [rel xhci_multi_second_desc + 1], 0x01
    jne  .retry_later
    lea  rsi, [rel xhci_multi_first_desc]
    lea  rdi, [rel xhci_multi_recheck_desc]
    mov  ecx, 18
    repe cmpsb
    jne  .retry_later
    mov  ebx, [rel xhci_multi_first_slot]
    cmp  ebx, [rel xhci_multi_second_slot]
    je   .retry_later
    lea  rax, [rel xhci_slot_port]
    mov  edx, [rel xhci_multi_first_port]
    cmp  [rax + rbx*4], edx
    jne  .retry_later
    mov  ebx, [rel xhci_multi_second_slot]
    mov  edx, [rel xhci_multi_second_port]
    cmp  [rax + rbx*4], edx
    jne  .retry_later

    mov  byte [rel xhci_multi_emitted], 1
    lea  rdi, [rel str_xhci_multi_slots]
    call serial_string
    mov  edi, [rel xhci_multi_first_slot]
    add  edi, '0'
    call serial_char
    mov  dil, ','
    call serial_char
    mov  edi, [rel xhci_multi_second_slot]
    add  edi, '0'
    call serial_char
    lea  rdi, [rel str_xhci_multi_first]
    call serial_string
    lea  rsi, [rel xhci_multi_first_desc]
    mov  ecx, 18
    call xhci_serial_hex_bytes
    lea  rdi, [rel str_xhci_multi_recheck]
    call serial_string
    lea  rsi, [rel xhci_multi_recheck_desc]
    mov  ecx, 18
    call xhci_serial_hex_bytes
    lea  rdi, [rel str_xhci_multi_second]
    call serial_string
    lea  rsi, [rel xhci_multi_second_desc]
    mov  ecx, 18
    call xhci_serial_hex_bytes
    call serial_newline
    ; Emit the dependent endpoint KAT before the predecessor marker: the
    ; inherited profile runner may terminate as soon as that marker is complete.
    call xhci_interrupt_in_kat
    call xhci_bulk_kat
    lea  rdi, [rel str_m_xhci_multi]
    call serial_string
    mov  byte [rel xhci_multi_active], 0
    jmp  .out
.retry_later:
    mov  dword [rel xhci_multi_second_slot], 0
    mov  dword [rel xhci_multi_second_port], 0
    mov  byte [rel xhci_multi_active], 0
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Synthetic endpoint KATs reset all shared endpoint state on both success and
; failure. A late descriptor observer can reach them after a hub status TD has
; already been armed. Never erase that live DMA custody or its class reset hook:
; defer the synthetic attempt until the controller has no endpoint owners.
; -> EAX=1 idle / 0 owned; read-only, bounded, clobbers RAX/RCX/RDX.
xhci_endpoint_kat_idle:
    lea  rdx, [rel xhci_intr_states]
    mov  ecx, XHCI_INTR_STATE_COUNT
.next:
    cmp  dword [rdx + xhci_intr_ep.active], 0 ; active/configured/pending/completed
    jne  .owned
    add  rdx, xhci_intr_ep_size
    dec  ecx
    jnz  .next
    mov  eax, 1
    ret
.owned:
    xor  eax, eax
    ret

; Content KAT over two isolated controller slots. Descriptor/configuration/
; ring/event ownership is synthetic; the production ops retain real Configure
; Endpoint, transfer-ring, doorbell, and event-ring paths.
xhci_interrupt_in_kat:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel xhci_intr_kat_emitted], 0
    jne  .out
    call xhci_endpoint_kat_idle
    test eax, eax
    jz   .out                       ; no counter/reset/DMA effects on a live owner
    call xhci_interrupt_counters_clear
    mov  dword [rel xhci_intr_kat_flags], 0
    mov  r12d, [rel xhci_multi_first_slot]
    test r12d, r12d
    jnz  .slot_a_ready
    mov  r12d, 1
.slot_a_ready:
    mov  r13d, [rel xhci_multi_second_slot]
    test r13d, r13d
    jnz  .slot_b_ready
    mov  r13d, 2
    cmp  r12d, r13d
    jne  .slot_b_ready
    mov  r13d, 1
.slot_b_ready:
    cmp  r12d, XHCI_MAX_SLOTS_EN
    ja   .fail
    cmp  r13d, XHCI_MAX_SLOTS_EN
    ja   .fail
    cmp  r12d, r13d
    je   .fail
    mov  [rel xhci_intr_kat_slot_a], r12d
    mov  [rel xhci_intr_kat_slot_b], r13d
    lea  rax, [rel xhci_ep0_idx]
    mov  ecx, [rax + r12*4]
    mov  [rel xhci_intr_kat_ep0_a_idx], ecx
    mov  ecx, [rax + r13*4]
    mov  [rel xhci_intr_kat_ep0_b_idx], ecx
    lea  rax, [rel xhci_ep0_pcs]
    mov  ecx, [rax + r12*4]
    mov  [rel xhci_intr_kat_ep0_a_pcs], ecx
    mov  ecx, [rax + r13*4]
    mov  [rel xhci_intr_kat_ep0_b_pcs], ecx

    ; Parser skips the OUT descriptor, returns the one interrupt-IN descriptor,
    ; and refuses a nonexistent second match.
    lea  rdi, [rel xhci_intr_kat_config]
    mov  esi, xhci_intr_kat_config_end - xhci_intr_kat_config
    xor  edx, edx
    call usb_find_interrupt_in_ep
    test rax, rax
    jz   .fail
    mov  r14, rax
    cmp  byte [r14 + usb_endpoint_desc.bEndpointAddress], 0x81
    jne  .fail
    lea  rdi, [rel xhci_intr_kat_config]
    mov  esi, xhci_intr_kat_config_end - xhci_intr_kat_config
    mov  edx, 1
    call usb_find_interrupt_in_ep
    test rax, rax
    jnz  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 0)

    mov  esi, r12d
    mov  rdx, r14
    call xhci_interrupt_prepare_state
    test rax, rax
    jz   .fail
    mov  r15, rax
    mov  esi, r12d
    mov  rdx, r15
    call xhci_interrupt_context_valid
    cmp  eax, 1
    jne  .fail
    mov  byte [r15 + xhci_intr_ep.configured], 1
    mov  esi, r13d
    mov  rdx, r14
    call xhci_interrupt_prepare_state
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  esi, r13d
    mov  rdx, rbx
    call xhci_interrupt_context_valid
    cmp  eax, 1
    jne  .fail
    mov  [rel xhci_intr_kat_state_b], rbx
    mov  byte [rbx + xhci_intr_ep.configured], 1
    movzx eax, byte [r15 + xhci_intr_ep.dci]
    mov  [rel xhci_intr_kat_ep], eax
    cmp  al, [rbx + xhci_intr_ep.dci]
    jne  .fail

    ; Each slot owns disjoint ring/report storage, and neither aliases EP0.
    mov  rax, [r15 + xhci_intr_ep.ring]
    cmp  rax, [rbx + xhci_intr_ep.ring]
    je   .fail
    test eax, XHCI_INTR_RING_ALIGN - 1
    jnz  .fail
    mov  rax, [rbx + xhci_intr_ep.ring]
    test eax, XHCI_INTR_RING_ALIGN - 1
    jnz  .fail
    mov  rdx, [r15 + xhci_intr_ep.report]
    cmp  rdx, [rbx + xhci_intr_ep.report]
    je   .fail
    test edx, XHCI_INTR_DMA_ALIGN - 1
    jnz  .fail
    mov  rdx, [rbx + xhci_intr_ep.report]
    test edx, XHCI_INTR_DMA_ALIGN - 1
    jnz  .fail
    mov  rcx, [rel xhci_ep0_base]
    mov  eax, r12d
    dec  eax
    shl  rax, 12
    add  rcx, rax
    cmp  [r15 + xhci_intr_ep.ring], rcx
    je   .fail
    cmp  [r15 + xhci_intr_ep.report], rcx
    je   .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 1)

    ; Queue one exact eight-byte Normal TRB on each owner without ringing a
    ; physical doorbell; peer B remains pending throughout A's hostile tests.
    mov  rdi, r15
    mov  esi, 8
    xor  edx, edx
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  esi, 8
    xor  edx, edx
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel xhci_multi_first_desc]
    rol  rax, 17
    xor  rax, [r15 + xhci_intr_ep.report]
    test rax, rax
    jnz  .token_ok
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    or   rax, 1
.token_ok:
    mov  [rel xhci_intr_kat_token], rax
    mov  rdi, [r15 + xhci_intr_ep.report]
    mov  [rdi], rax

    lea  rbx, [rel xhci_intr_kat_event]
    mov  rax, [r15 + xhci_intr_ep.pending_trb]
    mov  [rel xhci_intr_kat_trb_a], rax
    mov  [rbx], rax
    mov  qword [rbx + 8], 0
    mov  dword [rbx + 8], (1 << 24)
    movzx eax, byte [r15 + xhci_intr_ep.dci]
    shl  eax, 16
    or   eax, (XHCI_TRB_XFER_EVENT << 10) | 1
    mov  edx, r12d
    shl  edx, 24
    or   eax, edx
    mov  [rbx + 12], eax
    mov  r14d, eax

    call xhci_interrupt_event_is_async
    cmp  eax, 1
    jne  .fail
    mov  eax, r14d
    and  eax, ~(0x1F << 16)
    or   eax, (1 << 16)
    call xhci_interrupt_event_is_async
    test eax, eax
    jnz  .fail

    ; Wrong slot: the TRB pointer still belongs to A, so B cannot consume it.
    mov  eax, r14d
    and  eax, 0x00FFFFFF
    mov  edx, r13d
    shl  edx, 24
    or   eax, edx
    mov  [rbx + 12], eax
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_slot], 1
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 2)

    ; Wrong endpoint on the right slot is likewise not an owner match.
    mov  eax, r14d
    and  eax, ~(0x1F << 16)
    movzx edx, byte [r15 + xhci_intr_ep.dci]
    add  edx, 2
    shl  edx, 16
    or   eax, edx
    mov  [rbx + 12], eax
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_ep], 1
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 3)

    ; Stale transfer-cycle replay: event identity is otherwise exact.
    mov  [rbx + 12], r14d
    mov  rdi, [rel xhci_intr_kat_trb_a]
    xor  dword [rdi + 12], 1
    call xhci_interrupt_route_event
    mov  r11, rax
    mov  rdi, [rel xhci_intr_kat_trb_a]
    xor  dword [rdi + 12], 1
    cmp  r11, -1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_cycle], 1
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 4)

    ; Exact completion is accepted once; duplicate observes pending=0.
    cmp  qword [rel xhci_intr_erdp_accept], 0
    jne  .fail
    cmp  qword [rel xhci_intr_iman_accept], 0
    jne  .fail
    call xhci_interrupt_route_event
    cmp  eax, 1
    jne  .fail
    cmp  qword [rel xhci_intr_completed], 1
    jne  .fail
    call xhci_interrupt_credit_accept
    or   dword [rel xhci_intr_kat_flags], (1 << 5)
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_dup], 1
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 6)
    mov  rax, [rel xhci_intr_kat_state_b]
    cmp  byte [rax + xhci_intr_ep.pending], 1
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 7)

    ; Configure/queue/event work must not change either slot's EP0 state.
    lea  rax, [rel xhci_ep0_idx]
    mov  ecx, [rax + r12*4]
    cmp  ecx, [rel xhci_intr_kat_ep0_a_idx]
    jne  .fail
    mov  ecx, [rax + r13*4]
    cmp  ecx, [rel xhci_intr_kat_ep0_b_idx]
    jne  .fail
    lea  rax, [rel xhci_ep0_pcs]
    mov  ecx, [rax + r12*4]
    cmp  ecx, [rel xhci_intr_kat_ep0_a_pcs]
    jne  .fail
    mov  ecx, [rax + r13*4]
    cmp  ecx, [rel xhci_intr_kat_ep0_b_pcs]
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 8)

    ; Copy before requeue. Requeue clears the private report only after the
    ; consumer buffer holds the unpredictable runtime token.
    mov  rdi, r15
    lea  rsi, [rel xhci_intr_kat_copy]
    mov  edx, 32
    xor  r10d, r10d
    xor  r9d, r9d
    call xhci_interrupt_copy_completed
    cmp  eax, 8
    jne  .fail
    mov  rax, [rel xhci_intr_kat_copy]
    cmp  rax, [rel xhci_intr_kat_token]
    jne  .fail
    mov  rdi, [r15 + xhci_intr_ep.report]
    cmp  qword [rdi], 0
    jne  .fail
    cmp  qword [rel xhci_intr_queued], 3
    jne  .fail
    cmp  qword [rel xhci_intr_completed], 1
    jne  .fail
    cmp  qword [rel xhci_intr_erdp_accept], 1
    jne  .fail
    cmp  qword [rel xhci_intr_iman_accept], 1
    jne  .fail
    or   dword [rel xhci_intr_kat_flags], (1 << 9)

    mov  rax, [rel xhci_intr_queued]
    mov  [rel xhci_intr_kat_queued], rax
    mov  rax, [rel xhci_intr_completed]
    mov  [rel xhci_intr_kat_completed], rax
    mov  rax, [rel xhci_intr_erdp_accept]
    mov  [rel xhci_intr_kat_erdp], rax
    mov  rax, [rel xhci_intr_iman_accept]
    mov  [rel xhci_intr_kat_iman], rax

    ; The HCRST helper clears all endpoint ownership and DMA residue while
    ; retaining only each ring's canonical Link TRB.
    call xhci_interrupt_state_reset
    lea  r14, [rel xhci_intr_states]
    mov  r15d, XHCI_INTR_STATE_COUNT
.reset_scan:
    cmp  dword [r14 + xhci_intr_ep.active], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.slot], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.mps], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.enqueue], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.pcs], 1
    jne  .fail_after_reset
    mov  eax, [rel xhci_generation]
    cmp  [r14 + xhci_intr_ep.generation], eax
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.pending_generation], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.pending_cycle], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.completed_len], 0
    jne  .fail_after_reset
    cmp  qword [r14 + xhci_intr_ep.pending_trb], 0
    jne  .fail_after_reset
    cmp  qword [r14 + xhci_intr_ep.pending_first_trb], 0
    jne  .fail_after_reset
    cmp  dword [r14 + xhci_intr_ep.pending_first_cycle], 0
    jne  .fail_after_reset
    mov  rdi, [r14 + xhci_intr_ep.ring]
    mov  ecx, (XHCI_INTR_RING_TRBS - 1) * 2
.reset_ring_zero:
    cmp  qword [rdi], 0
    jne  .fail_after_reset
    add  rdi, 8
    dec  ecx
    jnz  .reset_ring_zero
    mov  rax, [r14 + xhci_intr_ep.ring]
    cmp  [rdi], rax
    jne  .fail_after_reset
    cmp  dword [rdi + 8], 0
    jne  .fail_after_reset
    cmp  dword [rdi + 12], (XHCI_TRB_LINK << 10) | (1 << 1) | 1
    jne  .fail_after_reset
    mov  rdi, [r14 + xhci_intr_ep.report]
    mov  ecx, XHCI_INTR_REPORT_BYTES / 8
.reset_report_zero:
    cmp  qword [rdi], 0
    jne  .fail_after_reset
    add  rdi, 8
    loop .reset_report_zero
    add  r14, xhci_intr_ep_size
    dec  r15d
    jnz  .reset_scan
    or   dword [rel xhci_intr_kat_flags], (1 << 10)
    cmp  dword [rel xhci_intr_kat_flags], 0x7FF
    jne  .fail_after_reset
    mov  byte [rel xhci_intr_kat_emitted], 1
    call xhci_interrupt_kat_emit
    call xhci_interrupt_counters_clear
    jmp  .out
.fail:
    call xhci_interrupt_state_reset
    call xhci_interrupt_counters_clear
.fail_after_reset:
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Prepare one synthetic descriptor through the production endpoint/context
; path. ESI=slot,RDX=descriptor -> RAX=configured state / 0.
xhci_bulk_kat_prepare:
    push rbx
    push r12
    mov  ebx, esi
    call xhci_interrupt_prepare_state
    test rax, rax
    jz   .fail
    mov  r12, rax
    mov  esi, ebx
    mov  rdx, r12
    call xhci_interrupt_context_valid
    cmp  eax, 1
    jne  .fail
    mov  byte [r12 + xhci_intr_ep.configured], 1
    mov  rax, r12
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Build one synthetic Transfer Event around the production terminal TRB.
; Short-packet tests replace that pointer with the actual stopping member.
; RDI=state,ESI=residual,EDX=completion code -> RBX=event.
xhci_bulk_kat_event:
    lea  rbx, [rel xhci_bulk_kat_event_buf]
    mov  rax, [rdi + xhci_intr_ep.pending_trb]
    mov  [rbx], rax
    mov  eax, esi
    and  eax, 0x00FFFFFF
    shl  edx, 24
    or   eax, edx
    mov  [rbx + 8], eax
    movzx eax, byte [rdi + xhci_intr_ep.slot]
    shl  eax, 24
    movzx edx, byte [rdi + xhci_intr_ep.dci]
    shl  edx, 16
    or   eax, edx
    or   eax, (XHCI_TRB_XFER_EVENT << 10) | 1
    mov  [rbx + 12], eax
    ret

; Runtime-dependent deterministic payload generator.
; RDI=bytes,ESI=len,RDX=seed.
xhci_bulk_kat_fill:
    push rbx
    mov  rax, rdx
    mov  r8, 0x5851F42D4C957F2D
    mov  r9, 0x14057B7EF767814F
    xor  ebx, ebx
.next:
    cmp  ebx, esi
    jae  .done
    imul rax, r8
    add  rax, r9
    mov  [rdi + rbx], al
    inc  ebx
    jmp  .next
.done:
    pop  rbx
    ret

; FNV-1a-64 content binding. RSI=bytes,ECX=len -> RAX=checksum.
xhci_bulk_checksum:
    mov  rax, 0xCBF29CE484222325
    mov  r8, 0x00000100000001B3
    xor  edx, edx
.next:
    cmp  edx, ecx
    jae  .done
    movzx r9d, byte [rsi + rdx]
    xor  rax, r9
    imul rax, r8
    inc  edx
    jmp  .next
.done:
    ret

; Half-open range comparison used by the alias oracle.
; RDI=a, ESI=a_len, RDX=b, ECX=b_len -> EAX=1 only when disjoint.
xhci_bulk_ranges_disjoint:
    lea  rax, [rdi + rsi]
    cmp  rax, rdx
    jbe  .yes
    lea  rax, [rdx + rcx]
    cmp  rax, rdi
    jbe  .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Prove all four slot-local bulk owners are unique, aligned, and covered by
; the core/dma allocation. Compare complete ring/payload ranges rather than
; just their base addresses. The state-pointer table is CPU-only.
xhci_bulk_kat_disjoint:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rdi, [rel xhci_xfer_dma]
    test rdi, rdi
    jz   .fail
    mov  r10, rdi
    call dma_iommu_lookup
    cmp  rax, XHCI_XFER_DMA_BYTES
    jb   .fail
    lea  rbp, [r10 + rax]
    lea  r12, [rel xhci_bulk_kat_states]
    xor  ebx, ebx
.outer:
    cmp  ebx, 4
    jae  .pass
    mov  r13, [r12 + rbx*8]
    test r13, r13
    jz   .fail
    mov  r14, [r13 + xhci_intr_ep.ring]
    mov  r15, [r13 + xhci_intr_ep.report]
    test r14, r14
    jz   .fail
    test r15, r15
    jz   .fail
    test r14d, XHCI_INTR_RING_ALIGN - 1
    jnz  .fail
    test r15d, XHCI_INTR_DMA_ALIGN - 1
    jnz  .fail
    cmp  r14, r10
    jb   .fail
    lea  rax, [r14 + XHCI_INTR_RING_BYTES]
    cmp  rax, rbp
    ja   .fail
    cmp  r15, r10
    jb   .fail
    lea  rax, [r15 + XHCI_INTR_REPORT_BYTES]
    cmp  rax, rbp
    ja   .fail
    mov  rdi, r14
    mov  esi, XHCI_INTR_RING_BYTES
    mov  rdx, r15
    mov  ecx, XHCI_INTR_REPORT_BYTES
    call xhci_bulk_ranges_disjoint
    test eax, eax
    jz   .fail
    mov  r11d, ebx
    inc  r11d
.inner:
    cmp  r11d, 4
    jae  .next_outer
    mov  rax, [r12 + r11*8]
    mov  r8, [rax + xhci_intr_ep.ring]
    mov  r9, [rax + xhci_intr_ep.report]
    mov  rdi, r14
    mov  esi, XHCI_INTR_RING_BYTES
    mov  rdx, r8
    mov  ecx, XHCI_INTR_RING_BYTES
    call xhci_bulk_ranges_disjoint
    test eax, eax
    jz   .fail
    mov  rdi, r14
    mov  esi, XHCI_INTR_RING_BYTES
    mov  rdx, r9
    mov  ecx, XHCI_INTR_REPORT_BYTES
    call xhci_bulk_ranges_disjoint
    test eax, eax
    jz   .fail
    mov  rdi, r15
    mov  esi, XHCI_INTR_REPORT_BYTES
    mov  rdx, r8
    mov  ecx, XHCI_INTR_RING_BYTES
    call xhci_bulk_ranges_disjoint
    test eax, eax
    jz   .fail
    mov  rdi, r15
    mov  esi, XHCI_INTR_REPORT_BYTES
    mov  rdx, r9
    mov  ecx, XHCI_INTR_REPORT_BYTES
    call xhci_bulk_ranges_disjoint
    test eax, eax
    jz   .fail
    inc  r11d
    jmp  .inner
.next_outer:
    inc  ebx
    jmp  .outer
.pass:
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Validate reset-cleared ownership and zero residue across every shared
; endpoint owner. Link TRBs are the sole retained DMA bytes.
xhci_bulk_kat_reset_clean:
    push rbx
    push r12
    push r13
    lea  r12, [rel xhci_intr_states]
    mov  r13d, XHCI_INTR_STATE_COUNT
.state:
    cmp  dword [r12 + xhci_intr_ep.active], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.slot], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.mps], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.enqueue], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.pcs], 1
    jne  .fail
    mov  eax, [rel xhci_generation]
    cmp  [r12 + xhci_intr_ep.generation], eax
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.pending_generation], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.pending_cycle], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.completed_len], 0
    jne  .fail
    cmp  qword [r12 + xhci_intr_ep.pending_trb], 0
    jne  .fail
    cmp  qword [r12 + xhci_intr_ep.pending_first_trb], 0
    jne  .fail
    cmp  dword [r12 + xhci_intr_ep.pending_first_cycle], 0
    jne  .fail
    mov  rbx, [r12 + xhci_intr_ep.ring]
    mov  ecx, (XHCI_INTR_RING_TRBS - 1) * 2
.ring_zero:
    cmp  qword [rbx], 0
    jne  .fail
    add  rbx, 8
    dec  ecx
    jnz  .ring_zero
    mov  rax, [r12 + xhci_intr_ep.ring]
    cmp  [rbx], rax
    jne  .fail
    cmp  dword [rbx + 8], 0
    jne  .fail
    cmp  dword [rbx + 12], (XHCI_TRB_LINK << 10) | (1 << 1) | 1
    jne  .fail
    mov  rbx, [r12 + xhci_intr_ep.report]
    mov  ecx, XHCI_INTR_REPORT_BYTES / 8
.payload_zero:
    cmp  qword [rbx], 0
    jne  .fail
    add  rbx, 8
    dec  ecx
    jnz  .payload_zero
    add  r12, xhci_intr_ep_size
    dec  r13d
    jnz  .state
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Task2901 content KAT. Two descriptor-backed retained slots own four disjoint
; bulk rings; all hostile events traverse the same router as hardware events.
xhci_bulk_kat:
    XHCI_POWER_GATE 1
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel xhci_bulk_kat_emitted], 0
    jne  .out
    call xhci_endpoint_kat_idle
    test eax, eax
    jz   .out                       ; no counter/reset/DMA effects on a live owner
    mov  r12d, [rel xhci_multi_first_slot]
    test r12d, r12d
    jnz  .slot_a_ready
    mov  r12d, 1
.slot_a_ready:
    mov  r13d, [rel xhci_multi_second_slot]
    test r13d, r13d
    jnz  .slot_b_ready
    mov  r13d, 2
    cmp  r12d, r13d
    jne  .slot_b_ready
    mov  r13d, 1
.slot_b_ready:
    cmp  r12d, XHCI_MAX_SLOTS_EN
    ja   .fail
    cmp  r13d, XHCI_MAX_SLOTS_EN
    ja   .fail
    cmp  r12d, r13d
    je   .fail
    call xhci_interrupt_state_reset
    cmp  qword [rel xhci_xfer_dma], 0
    je   .fail
    call xhci_interrupt_counters_clear
    mov  [rel xhci_bulk_kat_slot_a], r12d
    mov  [rel xhci_bulk_kat_slot_b], r13d
    lea  rax, [rel xhci_ep0_idx]
    mov  ecx, [rax + r12*4]
    mov  [rel xhci_bulk_kat_ep0_a_idx], ecx
    mov  ecx, [rax + r13*4]
    mov  [rel xhci_bulk_kat_ep0_b_idx], ecx
    lea  rax, [rel xhci_ep0_pcs]
    mov  ecx, [rax + r12*4]
    mov  [rel xhci_bulk_kat_ep0_a_pcs], ecx
    mov  ecx, [rax + r13*4]
    mov  [rel xhci_bulk_kat_ep0_b_pcs], ecx

    mov  esi, r12d
    lea  rdx, [rel xhci_bulk_kat_desc_out]
    call xhci_bulk_kat_prepare
    test rax, rax
    jz   .fail
    mov  [rel xhci_bulk_kat_state_a_out], rax
    mov  esi, r12d
    lea  rdx, [rel xhci_bulk_kat_desc_in]
    call xhci_bulk_kat_prepare
    test rax, rax
    jz   .fail
    mov  [rel xhci_bulk_kat_state_a_in], rax
    mov  esi, r13d
    lea  rdx, [rel xhci_bulk_kat_desc_out]
    call xhci_bulk_kat_prepare
    test rax, rax
    jz   .fail
    mov  [rel xhci_bulk_kat_state_b_out], rax
    mov  esi, r13d
    lea  rdx, [rel xhci_bulk_kat_desc_in]
    call xhci_bulk_kat_prepare
    test rax, rax
    jz   .fail
    mov  [rel xhci_bulk_kat_state_b_in], rax
    call xhci_bulk_kat_disjoint
    cmp  eax, 1
    jne  .fail
    mov  rax, [rel xhci_bulk_kat_state_a_in]
    movzx ecx, byte [rax + xhci_intr_ep.dci]
    mov  [rel xhci_bulk_kat_ep_in], ecx
    mov  rax, [rel xhci_bulk_kat_state_a_out]
    movzx ecx, byte [rax + xhci_intr_ep.dci]
    mov  [rel xhci_bulk_kat_ep_out], ecx
    cmp  ecx, [rel xhci_bulk_kat_ep_in]
    je   .fail

    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel xhci_multi_first_desc]
    rol  rax, 23
    xor  rax, [rel xhci_xfer_dma]
    test rax, rax
    jnz  .token_ready
    mov  eax, 1
.token_ready:
    mov  [rel xhci_bulk_kat_token], rax
    lea  rdi, [rel xhci_bulk_kat_out]
    mov  esi, 1024
    mov  rdx, rax
    call xhci_bulk_kat_fill
    lea  rsi, [rel xhci_bulk_kat_out]
    mov  ecx, 1024
    call xhci_bulk_checksum
    test rax, rax
    jz   .fail
    mov  [rel xhci_bulk_kat_out_ck], rax

    mov  r14, [rel xhci_bulk_kat_state_a_out]
    mov  rdi, [r14 + xhci_intr_ep.report]
    lea  rsi, [rel xhci_bulk_kat_out]
    mov  ecx, 1024
    rep  movsb
    mov  rdi, r14
    mov  esi, 1024
    xor  edx, edx
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
    movzx eax, word [r14 + xhci_intr_ep.segments]
    mov  [rel xhci_bulk_kat_trbs_out], eax
    cmp  eax, 2
    jb   .fail
    mov  r15, [rel xhci_bulk_kat_state_b_out]
    mov  rdi, r15
    mov  esi, 1024
    xor  edx, edx
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail

    ; Wrong-slot completion cannot consume slot A or peer slot B.
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 1
    call xhci_bulk_kat_event
    and  dword [rbx + 12], 0x00FFFFFF
    mov  eax, r13d
    shl  eax, 24
    or   [rbx + 12], eax
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    ; Right slot but an unowned endpoint is refused.
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 1
    call xhci_bulk_kat_event
    and  dword [rbx + 12], ~(0x1F << 16)
    or   dword [rbx + 12], (31 << 16)
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    ; A stale generation and an impossible residual preserve valid ownership.
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 1
    call xhci_bulk_kat_event
    inc  dword [r14 + xhci_intr_ep.pending_generation]
    call xhci_interrupt_route_event
    dec  dword [r14 + xhci_intr_ep.pending_generation]
    cmp  rax, -1
    jne  .fail
    mov  rdi, r14
    mov  esi, 1025
    mov  edx, 1
    call xhci_bulk_kat_event
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    ; Exact OUT completion is accepted once; replay becomes duplicate.
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 1
    call xhci_bulk_kat_event
    call xhci_interrupt_route_event
    cmp  eax, 1
    jne  .fail
    call xhci_interrupt_credit_accept
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail
    cmp  byte [r15 + xhci_intr_ep.pending], 1
    jne  .fail
    mov  rsi, [r14 + xhci_intr_ep.report]
    mov  ecx, 1024
    call xhci_bulk_checksum
    cmp  rax, [rel xhci_bulk_kat_out_ck]
    jne  .fail
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 1024
    xor  ecx, ecx
    call xhci_bulk_consume_state
    cmp  eax, 1024
    jne  .fail

    ; Full 700-byte IN completion binds device-written bytes before scrub.
    mov  r14, [rel xhci_bulk_kat_state_a_in]
    mov  rdi, r14
    mov  esi, 700
    xor  edx, edx
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
    movzx eax, word [r14 + xhci_intr_ep.segments]
    mov  [rel xhci_bulk_kat_trbs_in], eax
    cmp  eax, 2
    jb   .fail
    mov  rdi, [r14 + xhci_intr_ep.report]
    mov  esi, 700
    mov  rdx, [rel xhci_bulk_kat_token]
    mov  rax, 0xD1B54A32D192ED03
    xor  rdx, rax
    call xhci_bulk_kat_fill
    mov  rsi, [r14 + xhci_intr_ep.report]
    mov  ecx, 700
    call xhci_bulk_checksum
    test rax, rax
    jz   .fail
    cmp  rax, [rel xhci_bulk_kat_out_ck]
    je   .fail
    mov  [rel xhci_bulk_kat_in_ck], rax
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 1
    call xhci_bulk_kat_event
    call xhci_interrupt_route_event
    cmp  eax, 1
    jne  .fail
    call xhci_interrupt_credit_accept
    mov  rdi, r14
    lea  rsi, [rel xhci_bulk_kat_in_copy]
    mov  edx, 700
    mov  ecx, 1
    call xhci_bulk_consume_state
    cmp  eax, 700
    jne  .fail
    lea  rsi, [rel xhci_bulk_kat_in_copy]
    mov  ecx, 700
    call xhci_bulk_checksum
    cmp  rax, [rel xhci_bulk_kat_in_ck]
    jne  .fail

    ; A 700-byte IN request completed by a 37-byte short packet is success.
    lea  rdi, [rel xhci_bulk_kat_short_copy]
    mov  ecx, 700
    mov  al, 0xA5
    rep  stosb
    mov  rdi, r14
    mov  esi, 700
    xor  edx, edx
    call xhci_interrupt_queue_state
    test rax, rax
    jnz  .fail
    mov  rdi, [r14 + xhci_intr_ep.report]
    mov  esi, 37
    mov  rdx, [rel xhci_bulk_kat_token]
    mov  rax, 0x94D049BB133111EB
    xor  rdx, rax
    call xhci_bulk_kat_fill
    mov  rdi, r14
    ; Event residual belongs to its generating first member, not the whole TD.
    movzx esi, word [r14 + xhci_intr_ep.mps]
    sub  esi, 37
    mov  edx, 13
    call xhci_bulk_kat_event
    mov  rax, [r14 + xhci_intr_ep.pending_first_trb]
    mov  [rbx], rax                 ; real short packet stops on first TD member
    test dword [rax + 12], (1 << 2) ; every possible short member must carry ISP
    jz   .fail
    call xhci_interrupt_route_event
    cmp  eax, 1
    jne  .fail
    call xhci_interrupt_credit_accept
    mov  rdi, r14
    lea  rsi, [rel xhci_bulk_kat_short_copy]
    mov  edx, 700
    mov  ecx, 1
    call xhci_bulk_consume_state
    cmp  eax, 37
    jne  .fail
    cmp  byte [rel xhci_bulk_kat_short_copy + 37], 0xA5
    jne  .fail

    cmp  qword [rel xhci_intr_completed], 3
    jne  .fail
    cmp  qword [rel xhci_intr_refused_slot], 1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_ep], 1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_cycle], 1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_dup], 1
    jne  .fail
    cmp  qword [rel xhci_intr_refused_overflow], 1
    jne  .fail
    cmp  qword [rel xhci_intr_erdp_accept], 3
    jne  .fail
    cmp  qword [rel xhci_intr_iman_accept], 3
    jne  .fail
    lea  rax, [rel xhci_ep0_idx]
    mov  ecx, [rax + r12*4]
    cmp  ecx, [rel xhci_bulk_kat_ep0_a_idx]
    jne  .fail
    mov  ecx, [rax + r13*4]
    cmp  ecx, [rel xhci_bulk_kat_ep0_b_idx]
    jne  .fail
    lea  rax, [rel xhci_ep0_pcs]
    mov  ecx, [rax + r12*4]
    cmp  ecx, [rel xhci_bulk_kat_ep0_a_pcs]
    jne  .fail
    mov  ecx, [rax + r13*4]
    cmp  ecx, [rel xhci_bulk_kat_ep0_b_pcs]
    jne  .fail
    mov  rax, [rel xhci_bulk_kat_state_b_out]
    cmp  byte [rax + xhci_intr_ep.pending], 1
    jne  .fail
    mov  rax, [rel xhci_intr_completed]
    mov  [rel xhci_bulk_kat_completed], rax

    ; Reset invalidates the still-pending peer and makes the old event replay
    ; unowned. Every payload/ring byte is then checked for deterministic scrub.
    call xhci_interrupt_state_reset
    lea  rbx, [rel xhci_bulk_kat_event_buf]
    call xhci_interrupt_route_event
    cmp  rax, -1
    jne  .fail_after_reset
    call xhci_bulk_kat_reset_clean
    cmp  eax, 1
    jne  .fail_after_reset
    mov  byte [rel xhci_bulk_kat_emitted], 1
    call xhci_bulk_kat_emit
    call xhci_interrupt_counters_clear
    jmp  .out
.fail:
    call xhci_interrupt_state_reset
.fail_after_reset:
    call xhci_interrupt_counters_clear
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

xhci_bulk_kat_emit:
    lea  rdi, [rel str_xhci_bulk_token]
    call serial_string
    mov  rdi, [rel xhci_bulk_kat_token]
    call xhci_serial_hex64
    lea  rdi, [rel str_xhci_bulk_slots]
    call serial_string
    mov  edi, [rel xhci_bulk_kat_slot_a]
    call serial_decimal
    mov  dil, ','
    call serial_char
    mov  edi, [rel xhci_bulk_kat_slot_b]
    call serial_decimal
    lea  rdi, [rel str_xhci_bulk_ep_in]
    call serial_string
    mov  edi, [rel xhci_bulk_kat_ep_in]
    call serial_decimal
    lea  rdi, [rel str_xhci_bulk_ep_out]
    call serial_string
    mov  edi, [rel xhci_bulk_kat_ep_out]
    call serial_decimal
    lea  rdi, [rel str_xhci_bulk_lengths]
    call serial_string
    lea  rdi, [rel str_xhci_bulk_out_ck]
    call serial_string
    mov  rdi, [rel xhci_bulk_kat_out_ck]
    call xhci_serial_hex64
    lea  rdi, [rel str_xhci_bulk_in_ck]
    call serial_string
    mov  rdi, [rel xhci_bulk_kat_in_ck]
    call xhci_serial_hex64
    lea  rdi, [rel str_xhci_bulk_trbs]
    call serial_string
    mov  edi, [rel xhci_bulk_kat_trbs_out]
    call serial_decimal
    mov  dil, ','
    call serial_char
    mov  edi, [rel xhci_bulk_kat_trbs_in]
    call serial_decimal
    lea  rdi, [rel str_xhci_bulk_completed]
    call serial_string
    mov  rdi, [rel xhci_bulk_kat_completed]
    call serial_decimal
    lea  rdi, [rel str_xhci_bulk_verdicts]
    call serial_string
    lea  rdi, [rel str_m_xhci_bulk]
    call serial_string
    ret

xhci_interrupt_kat_emit:
    lea  rdi, [rel str_xhci_intr_token]
    call serial_string
    mov  rdi, [rel xhci_intr_kat_token]
    call xhci_serial_hex64
    lea  rdi, [rel str_xhci_intr_slots]
    call serial_string
    mov  edi, [rel xhci_intr_kat_slot_a]
    call serial_decimal
    mov  dil, ','
    call serial_char
    mov  edi, [rel xhci_intr_kat_slot_b]
    call serial_decimal
    lea  rdi, [rel str_xhci_intr_ep]
    call serial_string
    mov  edi, [rel xhci_intr_kat_ep]
    call serial_decimal
    lea  rdi, [rel str_xhci_intr_queued]
    call serial_string
    mov  rdi, [rel xhci_intr_kat_queued]
    call serial_decimal
    lea  rdi, [rel str_xhci_intr_completed]
    call serial_string
    mov  rdi, [rel xhci_intr_kat_completed]
    call serial_decimal
    lea  rdi, [rel str_xhci_intr_erdp]
    call serial_string
    mov  rdi, [rel xhci_intr_kat_erdp]
    call serial_decimal
    lea  rdi, [rel str_xhci_intr_iman]
    call serial_string
    mov  rdi, [rel xhci_intr_kat_iman]
    call serial_decimal
    lea  rdi, [rel str_xhci_intr_verdicts]
    call serial_string
    lea  rdi, [rel str_m_xhci_intr]
    call serial_string
    ret

; Fixed-width lowercase runtime token (exactly sixteen hex digits).
xhci_serial_hex64:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, 60
.nibble:
    mov  rax, r12
    mov  ecx, r13d
    shr  rax, cl
    and  eax, 0x0F
    mov  edi, eax
    cmp  edi, 10
    jb   .decimal
    add  edi, 'a' - 10
    jmp  .emit
.decimal:
    add  edi, '0'
.emit:
    call serial_char
    sub  r13d, 4
    jns  .nibble
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_serial_hex_bytes(RSI=bytes,ECX=count) — compact lowercase receipt.
xhci_serial_hex_bytes:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13d, ecx
    xor  ebx, ebx
.byte:
    cmp  ebx, r13d
    jae  .done
    movzx eax, byte [r12 + rbx]
    mov  edi, eax
    shr  edi, 4
    and  edi, 0x0F
    cmp  edi, 10
    jb   .high_dec
    add  edi, 'a' - 10
    jmp  .high_emit
.high_dec:
    add  edi, '0'
.high_emit:
    call serial_char
    and  eax, 0x0F
    mov  edi, eax
    cmp  edi, 10
    jb   .low_dec
    add  edi, 'a' - 10
    jmp  .low_emit
.low_dec:
    add  edi, '0'
.low_emit:
    call serial_char
    inc  ebx
    jmp  .byte
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; xhci_mps_for_speed(EBX = speed) -> EAX = max packet size for EP0. clobbers RAX.
xhci_mps_for_speed:
    cmp  ebx, 2                      ; LS
    je   .ls
    cmp  ebx, 4                      ; SS
    je   .ss
    mov  eax, 64                     ; FS/HS
    ret
.ls:
    mov  eax, 8
    ret
.ss:
    mov  eax, 512
    ret

%include "dev/usb/xhci_readiness.inc"
%include "dev/usb/xhci_storage_identity.inc"

; ---- module data ----------------------------------------------------------
align 8
xhci_inst_r1:                     ; RCQ-09 slice 2: per-controller state (swapped)
xhci_init_hcs2:       dd 0
xhci_init_hcs2_valid: dd 0
xhci_init_phase:      dd 0
; Former alignment padding: every switched image keeps the same byte extent.
xhci_firmware_ready:  dd 0           ; set only by bring-up after actual handoff result0
align 8
xhci_region:     dq 0, 0            ; HAL region { bar_base, bar_size }
xhci_bus:        dd 0
xhci_dev:        dd 0
xhci_fn:         dd 0
; Reuse the former unused hcs_saved dword: no xHCI data-layout growth.
xhci_scratch_count: dw 0
align 4
xhci_op:         dd 0               ; operational base offset (= CAPLENGTH)
xhci_rt:         dd 0               ; runtime base offset
xhci_db:         dd 0               ; doorbell array base offset
xhci_maxslots:   dd 0
xhci_maxports:   dd 0
xhci_ctxsz:      dd 32
xhci_scr_off:    dd 0
align 8
xhci_dcbaa:      dq 0
xhci_cmd_ring:   dq 0
xhci_evt_ring:   dq 0
xhci_erst:       dq 0
xhci_out_ctx:    dq 0
xhci_in_ctx_base:  dq 0          ; this controller's input contexts (XHCI_MAX_SLOTS_EN pages)
xhci_ep0_base:     dq 0          ; this controller's EP0 rings (one page per slot)
xhci_scr_arr_base: dq 0          ; this controller's scratchpad pointer array
xhci_dma_set:      dq 0          ; 0 = the static set; else a heap extent (XHCI_DS_TOTAL)
xhci_scratch_pages: dq 0              ; persistent aligned heap extent, allocated once
xhci_cmd_idx:    dd 0
xhci_cmd_pcs:    dd 1
xhci_evt_idx:    dd 0
xhci_evt_ccs:    dd 1
xhci_evt_cc:     dd 0
xhci_evt_slot:   dd 0
xhci_evt_type:   dd 0
xhci_evt_len:    dd 0              ; the last event's Transfer Length field (residual)
xhci_ctl_residual: dd 0            ; this control transfer's short-packet residual
xhci_ctl_events: dd 0              ; non-status EP0 events seen while waiting
align 8
xhci_evt_ptr:    dq 0              ; the last event's TRB Pointer
xhci_ctl_data_trb: dq 0            ; this control transfer's DATA TRB (0 = none)
xhci_ctl_status_trb: dq 0          ; this control transfer's STATUS TRB
xhci_generation: dd 0
align 8
xhci_xfer_dma:   dq 0              ; core/dma extent: default endpoint rings + payloads
xhci_bulk_large_dma: times XHCI_INTR_STATE_COUNT dq 0 ; per-controller lifetime extents
xhci_ep0_idx:    times XHCI_SLOT_COUNT dd 0
xhci_ep0_pcs:    times XHCI_SLOT_COUNT dd 1
xhci_port_slot:  times XHCI_PORT_COUNT dd 0
xhci_slot_port:  times XHCI_SLOT_COUNT dd 0
align 4
xhci_multi_state_begin:
xhci_multi_first_port:   dd 0
xhci_multi_first_slot:   dd 0
xhci_multi_second_port:  dd 0
xhci_multi_second_slot:  dd 0
xhci_multi_active:       db 0
xhci_multi_emitted:      db 0
xhci_multi_first_desc:   times 18 db 0
xhci_multi_second_desc:  times 18 db 0
xhci_multi_recheck_desc: times 18 db 0
xhci_multi_state_end:
align 8
xhci_bulk_nonblock:      db 0        ; 1 while servicing usbhc_ops.bulk_in_poll (never waits)
xhci_intr_queued:        dq 0
xhci_intr_completed:     dq 0
xhci_intr_refused_slot:  dq 0
xhci_intr_refused_ep:    dq 0
xhci_intr_refused_cycle: dq 0
xhci_intr_refused_dup:   dq 0
xhci_intr_refused_overflow: dq 0
xhci_intr_erdp_accept:   dq 0
xhci_intr_iman_accept:   dq 0
xhci_intr_short_follow:  dq 0        ; short-IN follow-up events consumed (no completion, no credit);
                                     ; outside the 9-qword xhci_interrupt_counters_clear block
xhci_intr_kat_token:     dq 0
xhci_intr_kat_queued:    dq 0
xhci_intr_kat_completed: dq 0
xhci_intr_kat_erdp:      dq 0
xhci_intr_kat_iman:      dq 0
xhci_intr_kat_slot_a:    dd 0
xhci_intr_kat_slot_b:    dd 0
xhci_intr_kat_ep:        dd 0
xhci_intr_kat_flags:     dd 0
xhci_intr_kat_ep0_a_idx: dd 0
xhci_intr_kat_ep0_b_idx: dd 0
xhci_intr_kat_ep0_a_pcs: dd 0
xhci_intr_kat_ep0_b_pcs: dd 0
xhci_intr_kat_emitted:   db 0
align 8
xhci_intr_kat_state_b:   dq 0
xhci_intr_kat_trb_a:     dq 0
xhci_intr_kat_event:     times 16 db 0
xhci_intr_kat_copy:      times 32 db 0
xhci_intr_kat_config:
    db 9, 2, 32, 0, 1, 1, 0, 0x80, 50
    db 9, 4, 0, 0, 2, 3, 1, 1, 0
    db 7, 5, 0x01, 3, 8, 0, 10
    db 7, 5, 0x81, 3, 8, 0, 10
xhci_intr_kat_config_end:
align 8
xhci_bulk_kat_states:
xhci_bulk_kat_state_a_out: dq 0
xhci_bulk_kat_state_a_in:  dq 0
xhci_bulk_kat_state_b_out: dq 0
xhci_bulk_kat_state_b_in:  dq 0
xhci_bulk_kat_token:       dq 0
xhci_bulk_kat_out_ck:      dq 0
xhci_bulk_kat_in_ck:       dq 0
xhci_bulk_kat_completed:   dq 0
xhci_bulk_kat_slot_a:      dd 0
xhci_bulk_kat_slot_b:      dd 0
xhci_bulk_kat_ep_in:       dd 0
xhci_bulk_kat_ep_out:      dd 0
xhci_bulk_kat_trbs_out:    dd 0
xhci_bulk_kat_trbs_in:     dd 0
xhci_bulk_kat_ep0_a_idx:   dd 0
xhci_bulk_kat_ep0_b_idx:   dd 0
xhci_bulk_kat_ep0_a_pcs:   dd 0
xhci_bulk_kat_ep0_b_pcs:   dd 0
xhci_bulk_kat_emitted:     db 0
align 8
xhci_bulk_kat_event_buf:   times 16 db 0
xhci_bulk_kat_desc_out:
    db 7, 5, 0x02, USB_EP_XFER_BULK
    dw 512
    db 0
xhci_bulk_kat_desc_in:
    db 7, 5, 0x82, USB_EP_XFER_BULK
    dw 512
    db 0
align 8
xhci_bulk_kat_out:         times 1024 db 0
xhci_bulk_kat_in_copy:     times 700 db 0
xhci_bulk_kat_short_copy:  times 700 db 0
align 8
xhci_airlock_attempts:    dq 0
xhci_airlock_injected:    dq 0
xhci_airlock_contained:   dq 0
xhci_airlock_uncontained: dq 0
xhci_airlock_last_usbsts: dd 0
xhci_airlock_last_halted: db 0
xhci_airlock_last_code:   db 1
; RCQ-10 A0: Port Status Change latch and root-slot cleanup state.
xhci_psc_changed:     times 32 db 0  ; bit n = root port n reported a valid PSC (latched, never cleared here)
xhci_port_quar:       times 32 db 0  ; bit n = root port n refused until controller reset
xhci_psc_events:      dq 0           ; valid PSC events committed
xhci_psc_refused:     dq 0           ; malformed-PSC refusals: one per malformed head (drain_once acks it)
xhci_slot_quar:       dd 0           ; bit n = slot n quarantined until controller reset
xhci_x3_disable_n:    dd 0           ; root-port failure Disable Slot commands issued
xhci_x3_last_cc:      dd 0           ; their last completion code (0 = none consumed)
xhci_x3_port_refused: dd 0           ; attaches refused on a quarantined port
; S10-A1 F.3.2: the outstanding command (cleared by its E5, the abort hand-off, or reset)
align 8
xhci_cmd_out_trb:     dq 0           ; exact command TRB address; 0 = none outstanding
xhci_cmd_out_seq:     dq 0           ; monotonic post counter (the hand-off cookie)
xhci_cmd_out_type:    db 0           ; its TRB type
xhci_cmd_out_slot:    db 0           ; control[31:24]; 0 only for Enable Slot and No Op
xhci_cmd_late_seen:   db 0           ; abort: an E5 for the aborted command arrived first
xhci_evt_refused:     db 0           ; evt_wait stopped at a head it could not own
xhci_cmd_late_result: dd 0
xhci_cmd_late_cc:     dd 0
xhci_cmd_stray:       dd 0           ; E6: Command Completions that matched no record
xhci_cmd_bad_slot:    dd 0           ; E5 with cc 1 that failed its slot rule
xhci_slot_parked:     dd 0           ; PARK: bit n = quarantined slot n the controller handed back
                                     ; (allocated there, never used here) until controller reset
xhci_park_retry_fail: dd 0           ; attaches failed after one parked retry (P2, stage 9)
xhci_park_retry:      db 0           ; this attach already retried Enable Slot once (P2)
align 8
xhci_inst_r1_end:
; ---- not per controller ----
align 8
; Actual failed-init owners/outcomes are outside ALL r1/r2/r3/r4 swapped images.
; Capacity is the original candidate bound. Sticky overflow never means absence.
xhci_discard_n: dd 0
xhci_discard_overflow: dd 0
xhci_discard_owners: times (XHCI_CAND_MAX * XHCI_DISCARD_BYTES) db 0
xhci_discard_scratch: times XHCI_DISCARD_BYTES db 0 ; overflow effect scratch, never a retained slot
; Original selected initialization survives later candidates and runtime swaps.
xhci_init_receipt: times 10 dd 0
; Passive latest original handoff per candidate, outside every switched image.
xhci_legacy_sequence: dd 0
align 8
xhci_legacy_observations: times (XHCI_CAND_MAX * 160) db 0
xhci_legacy_scratch: times 160 db 0  ; unmatched direct call, never candidate evidence
xhci_found:      dd 0
xhci_preferred_51ed: dd 0
xhci_cand_n:     dd 0
xhci_probe_cmd:  dd 0            ; the candidate's PCI command register as found
xhci_probe_cmd_set: dd 0         ; 1 while the probe has Memory Space set itself
align 8
xhci_cand:       times (XHCI_CAND_MAX * XHCI_CAND_SZ) db 0   ; RCQ-09 selection candidates
str_xsel_head:   db "[PAOS64] P2 usb-xhci: select n=", 0
str_xsel_c:      db " c", 0
str_xsel_conn:   db ",conn=", 0
str_xsel_na:     db "na", 0
str_xsel_chosen: db " chosen=", 0
str_xsel_rule:   db " rule=", 0
str_xsel_rule_connected: db "connected", 0
str_xsel_rule_fallback:  db "fallback", 0
str_xsel_tail:   db " [usb.xhci.select]", 13, 10, 0
str_xsel_hex:    db "0123456789abcdef"
xhci_m_up:       db 0               ; xhci.controller.up marker flag
xhci_interrupt_reset_hook: dq 0     ; ONE hook for every controller (not per instance): a reset of
                                    ; any controller (e.g. an airlock re-init of XHC0) releases ALL
                                    ; HID states, including the GLKVM's on XHC3 (known limit, RCQ-09)
xhci_bring_conn: dd -1              ; probed connected ports of the controller being brought up
; Passive original per-call command operands; outside every swapped image.
xhci_power_command_observations: times 256 db 0
xhci_power_iso_observations: times 640 db 0
xhci_inst_n:     dd 0            ; registered controllers
xhci_inst_cur:   dd 0            ; the live controller
xhci_sel_chosen: dd 0            ; original selection; stable even if backend zero is a fallback
xhci_inst_cand:  times XHCI_INST_MAX dd 0   ; candidate index per controller
xhci_inst_ppc:   times XHCI_INST_MAX dd 0   ; HCCPARAMS1.PPC per controller (RCQ-09 port power)
str_xhci_names:  db "xhci1", 0, 0, 0, "xhci2", 0, 0, 0, "xhci3", 0, 0, 0
str_xinst_head:  db "[PAOS64] P2 usb-xhci: instance ", 0
str_xinst_up:    db " up ", 0
str_xinst_ports: db " ports=", 0
str_xinst_tail:  db " [usb.xhci.instance.up]", 13, 10, 0
str_xppc_ppc:    db " ppc=", 0
str_xppc_powered: db " powered=", 0
str_xppc_stuck:  db " stuck=", 0
str_xppc_tail:   db " [usb.xhci.ppc]", 13, 10, 0
align 8
xhci_inst_ops:   times ((XHCI_INST_MAX - 1) * usbhc_ops_size) db 0
xhci_inst_hcdev: times ((XHCI_INST_MAX - 1) * DEV_SIZE) db 0
xhci_ops:        times (usbhc_ops_size) db 0
xhci_hcdev:      times DEV_SIZE db 0
str_xhci_name:   db "xhci", 0
xhci_multi_setup:
    db 0x80, 0x06
    dw 0x0100, 0x0000, 0x0012
str_xhci_multi_slots:   db "USBMULTI slots=", 0
str_xhci_multi_first:   db " first=", 0
str_xhci_multi_recheck: db " first_recheck=", 0
str_xhci_multi_second:  db " second=", 0
str_m_xhci_multi: db "[PAOS64] usb: xHCI multi-slot descriptor recheck PASS [usb.xhci.multislot.kat]", 13, 10, 0
str_xhci_intr_token:     db "USBINT token=", 0
str_xhci_intr_slots:     db " slots=", 0
str_xhci_intr_ep:        db " ep=", 0
str_xhci_intr_queued:    db " queued=", 0
str_xhci_intr_completed: db " completed=", 0
str_xhci_intr_erdp:      db " erdp=", 0
str_xhci_intr_iman:      db " iman=", 0
str_xhci_intr_verdicts:  db " wrong_slot=refused wrong_ep=refused stale_cycle=refused duplicate=refused ep0_unchanged=1 peer_pending=1 alias=0 residue=0 reset_clear=1", 13, 10, 0
str_m_xhci_intr: db "[PAOS64] usb: xHCI interrupt-IN endpoint KAT PASS [usb.xhci.interrupt_in.kat]", 13, 10, 0
str_xhci_bulk_token:     db "USBBULK token=", 0
str_xhci_bulk_slots:     db " slots=", 0
str_xhci_bulk_ep_in:     db " ep_in=", 0
str_xhci_bulk_ep_out:    db " ep_out=", 0
str_xhci_bulk_lengths:   db " out_len=1024 in_len=700 short=37", 0
str_xhci_bulk_out_ck:    db " out_ck=", 0
str_xhci_bulk_in_ck:     db " in_ck=", 0
str_xhci_bulk_trbs:      db " trbs=", 0
str_xhci_bulk_completed: db " completed=", 0
str_xhci_bulk_verdicts:  db " wrong_slot=refused wrong_ep=refused stale=refused duplicate=refused overflow=refused ep0_unchanged=1 peer_pending=1 alias=0 residue=0 reset_clear=1", 13, 10, 0
str_m_xhci_bulk: db "[PAOS64] usb: xHCI isolated bulk-IN and bulk-OUT content KAT PASS [usb.xhci.bulk.kat]", 13, 10, 0

; --- dedicated DMA buffers, page-aligned IN MEMORY (see xhci_alloc_dma rationale) ---
; `align 4096` aligned only the FILE offset: code_start is file 0x200 at RVA 0x1000,
; so the block sat at page offset 0xE00 and its rings/contexts straddled pages. Pad
; on the RVA instead (the page math of core/abi/wdata.inc). xHCI Table 6-1: the
; DCBAA, contexts and the scratchpad array must not cross a page; ring segments must
; not cross 64 KiB. Each buffer up to xhci_ep0_buf is whole pages, so each starts on
; an in-memory page boundary. tools/xhci_dma_check.py gates this at build time.
; Same capacities and instance-copy span; the PE loader supplies initial zeros.
%macro WDATA_xhci_dma 0
    resb ((0x1000 - (($ - code_start) & 0xFFF)) & 0xFFF)
xhci_dcbaa_buf:   resb 4096     ; Device Context Base Address Array
xhci_cmd_buf:     resb 4096     ; command ring (256 TRBs)
xhci_evt_buf:     resb 4096     ; event ring (256 TRBs, single ERST segment)
xhci_erst_buf:    resb 4096     ; Event Ring Segment Table
xhci_in_ctx_buf:  resb (XHCI_MAX_SLOTS_EN * 4096)
                                         ; one Input Context page per live slot
xhci_out_ctx_buf: resb (XHCI_MAX_SLOTS_EN * XHCI_OUT_CTX_STRIDE)
                                         ; independent Output Device Contexts
xhci_ep0_buf:     resb (XHCI_MAX_SLOTS_EN * 4096)
                                         ; one EP0 transfer ring per live slot
xhci_scratch_arr: resq XHCI_SCRATCH_MAX
                                         ; page-aligned (follows whole pages): 1 KiB, never crosses one
; CPU-only ownership table. DMA-visible endpoint rings and payload buffers are
; carved from xhci_xfer_dma by xhci_interrupt_state_reset.
alignb 64
xhci_inst_r4:
xhci_intr_states:  resb (XHCI_INTR_STATE_COUNT * xhci_intr_ep_size)
xhci_inst_r4_end:
%endmacro
WDATA_BSS_DEFER WDATA_xhci_dma
%if PAOS_LAB_HP_USB184_POOL
str_xhci_lab_pool184: db "[PAOS64] usb: lab transfer pool records_per_slot=4 dma_align=64 iso=refused [lab.usb.xhci.pool184]", 13, 10, 0
%endif
str_m_xhci_up:   db "[PAOS64] P2 usb-xhci: xHCI host controller initialized (CRCR/DCBAA/cmd ring) [xhci.controller.up]", 13, 10, 0

; RCQ-09 slice 2: one parked state image per controller + the pristine template.
%macro WDATA_xhci_parked 0
alignb 64
xhci_inst_save:     resb (XHCI_INST_MAX * XHCI_INST_BYTES)
xhci_inst_template: resb XHCI_INST_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_xhci_parked


; Lab-only timeout witness. One capture per registered controller per boot.
; RDI=already-read setup, ESI=validated port, EDX=validated addressed slot.
; RCX=nine counter baselines on the caller stack, taken before the doorbell.
; Entire bounded snapshot precedes serial; no drain/ERDP/IMAN/reset/IF writes.
; Owner rows are CPU-only metadata, not report payload or owner authority.
%if PAOS_LAB_HP_EP0_WITNESS
%if PAOS_LAB_HP_PCICMD_PROVENANCE
XHCI_LAB_CFGW_FIELDS equ PCI_LAB_CFGW_ARMED + 6 + (PCI_LAB_CFGW_SLOTS + PCI_LAB_CFGW_OVL_SLOTS) * 4
XHCI_LAB_EP0_STACK equ 1936      ; 1216 + 90 recorder qwords, 16-byte multiple
%elif PAOS_LAB_HP_PREHALT_LEGACY
XHCI_LAB_EP0_STACK equ 1216
%elif PAOS_LAB_HP_USBCMD_PROVENANCE
XHCI_LAB_EP0_STACK equ 1104
%else
XHCI_LAB_EP0_STACK equ 640
%endif
xhci_lab_ep0_snapshot:
    XHCI_POWER_GATE 1
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, XHCI_LAB_EP0_STACK
    mov rbp,rsp
    mov r12,rcx                     ; retained caller-local publication baseline
    mov eax,[rel xhci_inst_cur]
    cmp eax,XHCI_INST_MAX
    jae .out
    cmp eax,[rel xhci_inst_n]
    jae .out
    cmp esi,1
    jb .out
    cmp esi,XHCI_PORT_COUNT
    jae .out
    cmp esi,[rel xhci_maxports]
    ja .out
    cmp edx,1
    jb .out
    cmp edx,XHCI_MAX_SLOTS_EN
    ja .out
    mov r11d,edx
    mov ecx,[rel xhci_evt_idx]
    cmp ecx,256
    jae .out
    mov r10,[rel xhci_evt_ring]
    mov rax,[rel xhci_dma_set]
    test rax,rax
    jz .static_ring
    add rax,XHCI_DS_EVT
    jc .out
    jmp .ring_check
.static_ring:
    lea rax,[rel xhci_evt_buf]
.ring_check:
    cmp r10,rax
    jne .out                       ; no dereference of an unowned ring
    mov eax,[rel xhci_evt_ccs]
    cmp eax,1
    ja .out
    mov eax,[rel xhci_inst_cur]
    bt dword [rel xhci_lab_ep0_seen],eax
    jc .out
    bts dword [rel xhci_lab_ep0_seen],eax
    shl rcx,4
    add r10,rcx
    mov eax,[rel xhci_inst_cur]
    mov [rbp+0],rax ; instance
    mov eax,[rel xhci_bus]
    mov [rbp+8],rax ; bus
    mov eax,[rel xhci_dev]
    mov [rbp+16],rax ; device
    mov eax,[rel xhci_fn]
    mov [rbp+24],rax ; function
    mov eax,[rel xhci_generation]
    mov [rbp+32],rax ; generation
    mov eax,esi
    mov [rbp+40],rax ; port
    mov eax,edx
    mov [rbp+48],rax ; slot
    mov rax,[rdi]
    mov [rbp+56],rax ; setup
    mov eax,[rel xhci_evt_idx]
    mov [rbp+64],rax ; event_index
    mov eax,[rel xhci_evt_ccs]
    mov [rbp+72],rax ; event_ccs
    mov rax,[rel xhci_evt_ring]
    mov [rbp+80],rax ; event_ring
    mov rax,[r10]
    mov [rbp+88],rax ; head_pointer
    mov rax,[r10+8]
    mov [rbp+96],rax ; head_status_control
    mov rax,[rel xhci_ctl_status_trb]
    mov [rbp+104],rax ; status_trb
    mov rax,[rel xhci_ctl_data_trb]
    mov [rbp+112],rax ; data_trb
    mov eax,[rel xhci_evt_cc]
    mov [rbp+120],rax ; last_cc
    movzx eax,byte [rel xhci_evt_refused]
    mov [rbp+128],rax ; refused
    mov rax,[rel xhci_cmd_ring]
    mov [rbp+136],rax ; command_ring
    mov rax,[rel xhci_dcbaa]
    mov [rbp+144],rax ; dcbaa
    mov rax,[rel xhci_ep0_base]
    mov [rbp+152],rax ; ep0_base
    mov esi,[rel xhci_op]
    add esi,XHCI_USBCMD
    call xh_rd
    mov [rbp+160],rax ; usbcmd
    mov esi,[rel xhci_op]
    add esi,XHCI_USBSTS
    call xh_rd
    mov [rbp+168],rax ; usbsts
    mov esi,[rel xhci_op]
    add esi,XHCI_CRCR
    call xh_rd
    mov [rbp+176],rax ; crcr_low
    mov esi,[rel xhci_op]
    add esi,XHCI_CRCR+4
    call xh_rd
    mov [rbp+184],rax ; crcr_high
    mov esi,[rel xhci_op]
    add esi,XHCI_DCBAAP
    call xh_rd
    mov [rbp+192],rax ; dcbaap_low
    mov esi,[rel xhci_op]
    add esi,XHCI_DCBAAP+4
    call xh_rd
    mov [rbp+200],rax ; dcbaap_high
    mov esi,[rel xhci_rt]
    add esi,XHCI_IMAN
    call xh_rd
    mov [rbp+208],rax ; iman
    mov esi,[rel xhci_rt]
    add esi,XHCI_ERDP
    call xh_rd
    mov [rbp+216],rax ; erdp_low
    mov esi,[rel xhci_rt]
    add esi,XHCI_ERDP+4
    call xh_rd
    mov [rbp+224],rax ; erdp_high
    mov rax,[rel xhci_intr_queued]
    sub rax,[r12+0]
    mov [rbp+232],rax ; queued_delta
    mov rax,[rel xhci_intr_completed]
    sub rax,[r12+8]
    mov [rbp+240],rax ; completed_delta
    mov rax,[rel xhci_intr_erdp_accept]
    sub rax,[r12+16]
    mov [rbp+248],rax ; erdp_accept_delta
    mov rax,[rel xhci_intr_iman_accept]
    sub rax,[r12+24]
    mov [rbp+256],rax ; iman_accept_delta
    mov rax,[rel xhci_intr_refused_slot]
    sub rax,[r12+32]
    mov [rbp+264],rax ; refused_slot_delta
    mov rax,[rel xhci_intr_refused_ep]
    sub rax,[r12+40]
    mov [rbp+272],rax ; refused_ep_delta
    mov rax,[rel xhci_intr_refused_cycle]
    sub rax,[r12+48]
    mov [rbp+280],rax ; refused_cycle_delta
    mov rax,[rel xhci_intr_refused_dup]
    sub rax,[r12+56]
    mov [rbp+288],rax ; refused_dup_delta
    mov rax,[rel xhci_intr_refused_overflow]
    sub rax,[r12+64]
    mov [rbp+296],rax ; refused_overflow_delta
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [rbp+304],rax ; tsc
    mov r11,[rbp+48]               ; failed slot, independent of MMIO clobbers
    ; Four records per failed slot are the selected pool's finite maximum.
    xor r12d,r12d
    xor r13d,r13d
    lea r14,[rel xhci_intr_states]
.owner:
    cmp r12d,XHCI_INTR_STATE_COUNT
    jae .emit
    cmp byte [r14+xhci_intr_ep.active],1
    jne .next
    cmp byte [r14+xhci_intr_ep.slot],r11b
    jne .next
    cmp r13d,4
    jae .emit
    mov rax,r13
    shl rax,6
    lea r15,[rbp+320+rax]
    movzx eax,byte [r14+xhci_intr_ep.slot]
    mov [r15+0],rax
    movzx eax,byte [r14+xhci_intr_ep.dci]
    mov [r15+8],rax
    mov eax,[r14+xhci_intr_ep.generation]
    mov [r15+16],rax
    movzx eax,byte [r14+xhci_intr_ep.pending]
    mov [r15+24],rax
    movzx eax,byte [r14+xhci_intr_ep.completed]
    mov [r15+32],rax
    mov eax,[r14+xhci_intr_ep.completion_sequence]
    mov [r15+40],rax
    mov rax,[r14+xhci_intr_ep.pending_trb]
    mov [r15+48],rax
    movzx eax,byte [r14+xhci_intr_ep.configured]
    mov [r15+56],rax
    inc r13d
.next:
    add r14,xhci_intr_ep_size
    inc r12d
    jmp .owner
.emit:
%if PAOS_LAB_HP_USBCMD_PROVENANCE
    ; Freeze all provenance before serial can service unrelated work. Eight
    ; physical ring slots, including zero unused entries; never chase a PC.
    mov eax,[rel xhci_inst_cur]
    imul eax,eax,400
    lea rsi,[rel xhci_lab_usbcmd_history]
    add rsi,rax
    lea rdi,[rbp+640]
    mov ecx,50
    rep movsq
    mov rax,[rel xhci_region]
    mov [rbp+1040],rax
    mov rax,[rel xhci_region+8]
    mov [rbp+1048],rax
    mov eax,[rel xhci_op]
    mov [rbp+1056],rax
    mov eax,[rel xhci_rt]
    mov [rbp+1064],rax
    mov eax,[rel xhci_db]
    mov [rbp+1072],rax
    xor esi,esi
    call xh_rd
    mov [rbp+1080],rax             ; raw CAPLENGTH/version dword, read-only
%endif
%if PAOS_LAB_HP_PREHALT_LEGACY
    lea rdi,[rbp+1104]
    call xhci_lab_prehalt_legacy    ; freeze both legacy dwords before serial/halt
%endif
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    lea rdi,[rbp+1216]
    call xhci_lab_prehalt_cfgw      ; freeze the recorder before serial/halt
%endif
    lea rdi,[rel str_xhci_lab_ep0]
    call serial_string
    xor r12d,r12d
.field:
    mov rdi,[rbp+r12*8]
    call serial_hex64
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    inc r12d
    cmp r12d,39
    jb .field
    lea rdi,[rel str_xhci_lab_owners]
    call serial_string
    mov rdi,r13
    call serial_hex64
    shl r13,3
    xor r12d,r12d
.owner_field:
    cmp r12,r13
    jae .newline
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    mov rdi,[rbp+320+r12*8]
    call serial_hex64
    inc r12d
    jmp .owner_field
.newline:
    lea rdi,[rel str_xhci_ep0_nl]
    call serial_string
%if PAOS_LAB_HP_USBCMD_PROVENANCE
    lea rdi,[rel str_xhci_lab_cmd_binding]
    call serial_string
    xor r12d,r12d
.binding_field:
    mov rdi,[rbp+1040+r12*8]
    call serial_hex64
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    inc r12d
    cmp r12d,6
    jb .binding_field
    lea rdi,[rel str_xhci_lab_cmd_history]
    call serial_string
    xor r12d,r12d
.history_field:
    mov rdi,[rbp+640+r12*8]
    call serial_hex64
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    inc r12d
    cmp r12d,50
    jb .history_field
    lea rdi,[rel str_xhci_ep0_nl]
    call serial_string
%endif
%if PAOS_LAB_HP_PREHALT_LEGACY
    lea rdi,[rel str_xhci_lab_legacy]
    call serial_string
    xor r12d,r12d
.legacy_field:
    mov rdi,[rbp+1104+r12*8]
    call serial_hex64
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    inc r12d
    cmp r12d,13
    jb .legacy_field
    lea rdi,[rel str_xhci_ep0_nl]
    call serial_string
%endif
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    lea rdi,[rel str_xhci_lab_cfgw]
    call serial_string
    xor r12d,r12d
.cfgw_field:
    mov rdi,[rbp+1216+r12*8]
    call serial_hex64
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    inc r12d
    cmp r12d,XHCI_LAB_CFGW_FIELDS
    jb .cfgw_field
    lea rdi,[rel str_xhci_ep0_nl]
    call serial_string
%if PAOS_LAB_HP_EARLY_ACPI
    lea rdi,[rel str_xhci_lab_acpi_prehalt]
    call xhci_lab_acpi_line
%endif
%endif
.out:
    add rsp,XHCI_LAB_EP0_STACK
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret
%if PAOS_LAB_HP_PREHALT_LEGACY
; RDI=13-qword CPU output. Read-only, sequential snapshot; never acknowledges
; SMI status or changes ownership, PCI, controller, interrupts or DMA state.
; Fields: instance,bus,dev,fn,generation,base,size,cap_offset,USBLEGSUP,
; USBLEGCTLSTS,status,tsc_begin,tsc_end. status=1 both read,2 absent,3 invalid.
; The frozen region and explicit whole-dword bounds apply even with HAL bypass.
xhci_lab_prehalt_legacy:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    xor eax,eax
    mov ecx,13
    rep stosq
    mov eax,[rel xhci_inst_cur]
    mov [rbx+0*8],rax
    mov eax,[rel xhci_bus]
    mov [rbx+1*8],rax
    mov eax,[rel xhci_dev]
    mov [rbx+2*8],rax
    mov eax,[rel xhci_fn]
    mov [rbx+3*8],rax
    mov eax,[rel xhci_generation]
    mov [rbx+4*8],rax
    mov rax,[rel xhci_region]
    mov [rbx+5*8],rax
    mov rax,[rel xhci_region+8]
    mov [rbx+6*8],rax
    mov qword [rbx+10*8],3
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [rbx+11*8],rax
    cmp qword [rbx+5*8],0
    je .done
    mov esi,XHCI_HCCPARAMS1
    call .read
    jc .done
    shr eax,16
    shl eax,2
    mov r12d,eax
    mov r13d,64                    ; finite relative xECP walk
.walk:
    test r12d,r12d
    jz .absent
    cmp r12d,0x20
    jb .done
    mov esi,r12d
    call .read
    jc .done
    cmp al,1                       ; USB Legacy Support
    je .found
    shr eax,8
    movzx eax,al
    test eax,eax
    jz .absent
    shl eax,2
    add r12d,eax
    jc .done
    dec r13d
    jnz .walk
    jmp .done
.found:
    mov [rbx+7*8],r12
    mov [rbx+8*8],rax
    lea esi,[r12+4]
    call .read
    jc .done
    mov [rbx+9*8],rax
    mov qword [rbx+10*8],1
    jmp .done
.absent:
    mov qword [rbx+10*8],2
.done:
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [rbx+12*8],rax
    pop r13
    pop r12
    pop rbx
    ret
.read:
    lea rax,[rsi+4]
    cmp rax,[rbx+6*8]
    ja .bad
    lea rdi,[rbx+5*8]              ; retained base/size, no later global lookup
    call hal_mmio_read32
    jc .bad
    cmp eax,-1                     ; disconnected/unavailable, not valid zero
    je .bad
    clc
    ret
.bad:
    stc
    ret
str_xhci_lab_legacy: db "XHCILEGACY v=1 phase=pre_halt_recovery fields=",0
%endif
%if PAOS_LAB_HP_PCICMD_PROVENANCE
; xhci_lab_cfgw_bdf -> EAX = CONFIG_ADDRESS function (offset 0) of the live
;   xhci_bus/dev/fn, packed exactly as pci_cfg_write32 does. clobbers: RAX.
xhci_lab_cfgw_bdf:
    push rcx
    mov eax,[rel xhci_bus]
    shl eax,16
    mov ecx,[rel xhci_dev]
    shl ecx,11
    or eax,ecx
    mov ecx,[rel xhci_fn]
    shl ecx,8
    or eax,ecx
    or eax,PCI_ENABLE
    pop rcx
    ret

; Arms once per boot: slot 0 = the selected function, then the other xHCI
;   candidates in candidate order while slots remain. clobbers: RAX.
xhci_lab_cfgw_arm:
    cmp dword [rel pci_lab_cfgw_armed],0
    jne .out
    push rcx
    push rdx
    push rsi
    push rdi
    call xhci_lab_cfgw_bdf
    mov [rel pci_lab_cfgw_armed],eax
    lea rdi,[rel pci_lab_cfgw_armed+4]
    mov edx,1                       ; slots filled
    xor ecx,ecx                     ; candidate index
.cand:
    cmp ecx,[rel xhci_cand_n]
    jae .done
    cmp edx,PCI_LAB_CFGW_ARMED
    jae .done
    imul esi,ecx,XHCI_CAND_SZ
    lea rax,[rel xhci_cand]
    add rsi,rax
    push rcx
    mov eax,[rsi+XC_BUS]
    shl eax,16
    mov ecx,[rsi+XC_DEV]
    shl ecx,11
    or eax,ecx
    mov ecx,[rsi+XC_FN]
    shl ecx,8
    or eax,ecx
    or eax,PCI_ENABLE
    pop rcx
    cmp eax,[rel pci_lab_cfgw_armed]
    je .next                        ; the selected function already holds slot 0
    mov [rdi],eax
    add rdi,4
    inc edx
.next:
    inc ecx
    jmp .cand
.done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
.out:
    ret

; First legacy handoff of the armed function: one TSC. Preserves registers.
xhci_lab_cfgw_handoff_mark:
    push rax
    push rdx
    call xhci_lab_cfgw_bdf
    cmp eax,[rel pci_lab_cfgw_armed]
    jne .out
    cmp qword [rel pci_lab_cfgw_handoff_tsc],0
    jne .out
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [rel pci_lab_cfgw_handoff_tsc],rax
.out:
    pop rdx
    pop rax
    ret

; RDI=XHCI_LAB_CFGW_FIELDS-qword CPU output. Fields: 4 armed addresses, total,
;   handoff TSC, live function's Command/Status dword (one config read, no
;   write), TSC, the 16 raw ring slots (TSC, caller, address, value), the CF8
;   selection count, overlapped writes, then the 4 raw overlap slots.
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8.
xhci_lab_prehalt_cfgw:
    push rbx
    mov rbx,rdi
    xor ecx,ecx
.armed:
    lea rax,[rel pci_lab_cfgw_armed]
    mov eax,[rax+rcx*4]
    mov [rbx+rcx*8],rax
    inc ecx
    cmp ecx,PCI_LAB_CFGW_ARMED
    jb .armed
    mov eax,[rel pci_lab_cfgw_total]
    mov [rbx+(PCI_LAB_CFGW_ARMED+0)*8],rax
    mov rax,[rel pci_lab_cfgw_handoff_tsc]
    mov [rbx+(PCI_LAB_CFGW_ARMED+1)*8],rax
    mov edi,[rel xhci_bus]
    mov esi,[rel xhci_dev]
    mov edx,[rel xhci_fn]
    mov ecx,0x04
    call pci_cfg_read32
    mov [rbx+(PCI_LAB_CFGW_ARMED+2)*8],rax
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [rbx+(PCI_LAB_CFGW_ARMED+3)*8],rax
    lea rsi,[rel pci_lab_cfgw_ring]
    lea rdi,[rbx+(PCI_LAB_CFGW_ARMED+4)*8]
    mov ecx,PCI_LAB_CFGW_SLOTS * 4
    rep movsq
    mov eax,[rel pci_lab_cfg_seq]
    stosq
    mov eax,[rel pci_lab_cfgw_overlaps]
    stosq
    lea rsi,[rel pci_lab_cfgw_ovl_ring]
    mov ecx,PCI_LAB_CFGW_OVL_SLOTS * 4
    rep movsq
    pop rbx
    ret

; After xhci_bring_up_others, with instance 0 switched back in: the same
;   read-only 13-field legacy snapshot, printed at once. Preserves registers.
xhci_lab_after_others_legacy:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    sub rsp,13*8
    mov rdi,rsp
    call xhci_lab_prehalt_legacy
    lea rdi,[rel str_xhci_lab_after_others]
    call serial_string
    xor r12d,r12d
.field:
    mov rdi,[rsp+r12*8]
    call serial_hex64
    lea rdi,[rel str_xhci_lab_sep]
    call serial_string
    inc r12d
    cmp r12d,13
    jb .field
    lea rdi,[rel str_xhci_ep0_nl]
    call serial_string
    add rsp,13*8
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret
str_xhci_lab_cfgw: db "XHCICFGW v=1 phase=pre_halt_recovery fields=",0
str_xhci_lab_after_others: db "XHCILEGACY v=1 phase=after_others fields=",0
%endif
%if PAOS_LAB_HP_EARLY_ACPI
; HP244 SMI_CMD trace. power_s5_mode_set (power_exec.asm) is the only SMI_CMD
;   writer; it expands these two macros under %ifdef PAOS_LAB_HP_SMICMD_TRACE.
;   ENTER runs after its four pushes: R15 = its caller, RBP = TSC before the write.
%macro POWER_LAB_SMICMD_ENTER 0
    push r15
    push rbp
    mov r15, [rsp+48]               ; caller, above RBP, R15, R14, R13, R12, RBX
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbp, rax
%endmacro
%macro POWER_LAB_SMICMD_EXIT 0
    call power_lab_smicmd_trace
    pop rbp
    pop r15
%endmacro
; One SMICMD line per power_s5_mode_set call, after its readback. In: EAX rc,
;   R12D packed mode command, R13D PM1a control, R14D desired, R15 caller,
;   RBP TSC before. Fields: caller, SMI_CMD port, value written, desired SCI_EN,
;   rc, PM1a_CNT after, TSC before, TSC after, writes so far. Preserves all GPRs.
power_lab_smicmd_trace:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    sub rsp, 9*8
    mov [rsp+32], rax                ; rc (EAX zero-extended by its producer)
    mov [rsp], r15
    movzx eax, r12w
    mov [rsp+8], rax
    mov eax, r12d
    shr eax, 16
    test r14d, r14d
    jnz .value
    shr eax, 8
.value:
    movzx eax, al
    mov [rsp+16], rax
    mov eax, r14d
    mov [rsp+24], rax
    mov edx, r13d
    in ax, dx
    movzx eax, ax
    mov [rsp+40], rax
    mov [rsp+48], rbp
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rsp+56], rax
    lock inc dword [rel power_lab_smicmd_count]
    mov eax, [rel power_lab_smicmd_count]
    mov [rsp+64], rax
    lea rdi, [rel str_power_lab_smicmd]
    call serial_string
    xor ebx, ebx
.field:
    mov rdi, [rsp+rbx*8]
    call serial_hex64
    lea rdi, [rel str_power_lab_smicmd_sep]
    call serial_string
    inc ebx
    cmp ebx, 9
    jb .field
    call serial_newline
    add rsp, 9*8
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret
str_power_lab_smicmd: db "SMICMD v=1 fields=",0
str_power_lab_smicmd_sep: db " ",0
%macro WDATA_xhci_lab_smicmd 0
align 4
power_lab_smicmd_count: dd 0
%endmacro
WDATA_DEFER WDATA_xhci_lab_smicmd
; HP244 lab: EAX = the boot ownership rc from xhci_acpi_mode_early. Record it
;   and print the early XHCIACPI line. Preserves all GPRs.
xhci_lab_early_acpi:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  [rel xhci_lab_acpi_early_rc], eax
    lea  rdi, [rel str_xhci_lab_acpi_early]
    call xhci_lab_acpi_line
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

; RDI=line prefix. Fields: live instance, early ownership rc (FFFFFFFF = not
;   run), ownership state, live SCI_EN sample, changed flag, PM1 port pair,
;   PM1a_CNT read now (FFFFFFFF without a port), SMI_CMD writes so far, TSC.
;   One PM1a_CNT read, no write. Preserves all GPRs.
xhci_lab_acpi_line:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    sub  rsp, 9*8
    mov  r12, rdi
    mov  eax, [rel xhci_inst_cur]
    mov  [rsp], rax
    mov  eax, [rel xhci_lab_acpi_early_rc]
    mov  [rsp+8], rax
    movzx eax, byte [rel power_button_ownership_state]
    mov  [rsp+16], rax
    movzx eax, byte [rel power_button_ownership_live]
    mov  [rsp+24], rax
    movzx eax, byte [rel power_button_ownership_changed]
    mov  [rsp+32], rax
    mov  eax, [rel power_button_ownership_pm1]
    mov  [rsp+40], rax
    mov  ecx, 0xFFFFFFFF
    movzx edx, ax                    ; PM1a control port
    test edx, edx
    jz   .no_port
    in   ax, dx
    movzx ecx, ax
.no_port:
    mov  [rsp+48], rcx
    mov  eax, [rel power_lab_smicmd_count]
    mov  [rsp+56], rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp+64], rax
    mov  rdi, r12
    call serial_string
    xor  r12d, r12d
.field:
    mov  rdi, [rsp+r12*8]
    call serial_hex64
    lea  rdi, [rel str_xhci_lab_sep]
    call serial_string
    inc  r12d
    cmp  r12d, 9
    jb   .field
    lea  rdi, [rel str_xhci_ep0_nl]
    call serial_string
    add  rsp, 9*8
    pop  r12
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
str_xhci_lab_acpi_early: db "XHCIACPI v=1 phase=early fields=",0
str_xhci_lab_acpi_handoff: db "XHCIACPI v=1 phase=handoff fields=",0
str_xhci_lab_acpi_prehalt: db "XHCIACPI v=1 phase=pre_halt_recovery fields=",0
%macro WDATA_xhci_lab_acpi 0
align 4
xhci_lab_acpi_early_rc: dd 0xFFFFFFFF
%endmacro
WDATA_DEFER WDATA_xhci_lab_acpi
%endif

str_xhci_lab_ep0: db "XHCIEP0 v=2 phase=pre_halt_recovery fields=",0
str_xhci_lab_sep: db " ",0
str_xhci_lab_owners: db "owners=",0
%if PAOS_LAB_HP_USBCMD_PROVENANCE
str_xhci_lab_cmd_binding: db "XHCICMD v=1 binding=",0
str_xhci_lab_cmd_history: db "history=",0
; Separate from swapped live state: four bounded boot-wide controller rings.
%macro WDATA_xhci_lab_usbcmd 0
alignb 8
xhci_lab_usbcmd_history: resb (XHCI_INST_MAX * 400)
%endmacro
WDATA_BSS_DEFER WDATA_xhci_lab_usbcmd
%endif
; Not inside the swapped state: the boot-wide bound survives instance swaps.
%macro WDATA_xhci_lab_ep0 0
align 4
xhci_lab_ep0_seen: dd 0
%endmacro
WDATA_DEFER WDATA_xhci_lab_ep0
%endif

; P4 read-only existing endpoint identity. No slot allocation/reset/PCI write.
; RDI=retained hc*,ESI=port/token,RDX=48-byte output; EAX=0 or-1 unavailable.
xhci_preservation_snapshot:
    XHCI_POWER_GATE 1
    push rbx
    push r12
    push r13
    mov  rbx, rdx
    mov  r12, rdi
    mov  r13d, esi
    call xhci_hc_instance
    cmp  eax, -1
    je   .bad
    mov  [rbx], rax
    mov  rdi, r12
    mov  esi, r13d
    call xhci_hid_slot_for_port
    test eax, eax
    jz   .bad
    mov  [rbx + 32], rax
    mov  [rbx + 16], rdx
    mov  [rbx + 24], r13
    mov  eax, [rel xhci_bus]
    shl  eax, 16
    mov  ecx, [rel xhci_dev]
    shl  ecx, 8
    or   eax, ecx
    or   eax, [rel xhci_fn]
    mov  [rbx + 8], rax
    mov  rax, [rel xhci_region + HAL_R_BAR_BASE]
    mov  [rbx + 40], rax
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
