;; MODULE dev/blk/nvme
;; LAYER 3
;; EXPORTS nvme_blk_create, nvme_self_exercise, nvme_identify_dma_to, nvme_get_log_error4_dma_to, nvme_quiesce_for_reset, nvme_quiesce_observation, nvme_quiesce_lifetime, nvme_quiesce_completion, nvme_power_gate, nvme_power_command_gate, nvme_io_exec_cooperative, nvme_admin_exec_cooperative, nvme_poll_cq_once, nvme_power_poll, nvme_identify_chunk
;; IMPORTS boot/native_driver_gate, fs/blockdev, fs/storage_access, bus/pci, core/dma, core/time, boot/serial, boot/paging, dev/blk/vmd, bus/pci_claim, boot/boot_v2_handoff
;; CAPS mmio dma
;; OWNER saga:storage
;; CONTEXT: bsp_only  (SEC-S6: the one-shot nvme_write_token is a global byte, sound only while one CPU drives the controller)
%include "core/abi/pci_claim.inc" ; RCQ-29 hardware report: bind outcome ids/states
; ============================================================================
; dev/blk/nvme.asm — the NVMe block backend (1027). PORT of the proven monolith
; NVMe controller bring-up (drivers/nvme/source/nvme_{detect,init,write,flush}.asm)
; into the rework's blk_ops class seam (fs/blockdev.asm, 1007), ADDITIVELY: the
; proven PCI-detect / CC reset-enable / admin+I/O queue / PRP single-block read+
; write+flush SEQUENCE is preserved where it was hard-won; the port ADDS (a) an
; IDENTIFY controller+namespace path the monolith deliberately skipped (so the
; class core can report a real model + LBA size — content, not a latch), (b)
; generalization of the fixed-LBA selftest write into the blk_ops
; write(self,lba,count,buf) signature via a page-aligned DMA bounce buffer, and
; (c) degrade-never-crash: no controller -> the backend registers HEALTH_DEGRADED
; and boot prints 'blk.nvme: skipped (no disk)', the box runs on ramblk.
;
; Verified against QEMU's emulated NVMe 1.x controller (-device nvme) in the
; regression harness (run_regression_check.py attaches a real nvme namespace) so
; the read/write/flush path is CONTENT-GRADED deterministically without touching
; the physical Intel boot SSD. The bare-metal random-sector round-trip on the real
; Intel SSDPEKKF256G8L + the UDP BLK* verb surface are a supervised follow-up
; (1027b): a destructive write to the Windows boot disk must not run unsupervised.
;
; DRAM-less brick anti-pattern (DATA.md): the Lenovo Intel NVMe is DRAM-PRESENT,
; so the HMB-FTL-loss-on-CF9 path is NOT ported and this backend NEVER issues a
; controller-level reset that could lose in-flight FTL metadata. flush() fires a
; real NVM Flush (opcode 0x00) so a committed write reaches NAND.
;
; The `call blk_register` is the ONE sanctioned L3->L4 upward edge (DRIVER_MODEL §5).
; ============================================================================

; Optional trusted BSP lifecycle admission; EAX=0 ordinary, 1 I/O submit,
; 2 admin submit, 3 cooperative completion, 4 tracked RUNNING completion.
; Private modes require their exact callback or accepted-command capability.
nvme_power_check:
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub rsp, 8
    test eax, eax
    jnz .command
    mov rax, [rel nvme_power_gate]
    test rax, rax
    jz .unattached
    call rax
    jmp .out
.command:
    mov r11d, eax
    mov rax, [rel nvme_power_command_gate]
    test rax, rax
    jz .refused
    call rax
    jmp .out
.refused:
    mov rax, -1
    jmp .out
.unattached:
    xor eax, eax
.out:
    add rsp, 8
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    cld
    ret

; ---- NVMe constants (ported from the monolith) ------------------------------
NVME_ASIZE       equ 64        ; admin queue entries (power of two -> mask wrap)
NVME_IOSIZE      equ 64        ; I/O   queue entries
NVME_SQ_ESZ      equ 64        ; submission-queue entry size (bytes)
NVME_CQ_ESZ      equ 16        ; completion-queue entry size (bytes)
NVME_IO_CQID     equ 1
NVME_IO_SQID     equ 1
NVME_OP_FLUSH    equ 0x00
NVME_OP_WRITE    equ 0x01
NVME_OP_READ     equ 0x02
NVME_OP_IDENTIFY equ 0x06
NVME_POLL_MAX    equ 2000000   ; bounded poll: up to ~2s (1us/iter) then timeout
NVME_MAX_XFER    equ 8         ; logical blocks per blk_read/blk_write call (RCQ-05)

; ============================================================================
; nvme_blk_create() -> RAX = REG_OK/REG_REJECT. Detect + (if present) bring up the
;   controller, IDENTIFY, then build the blk_ops vtable at RUNTIME (lea->mov: the
;   PE ImageBase is not applied to a baked `dq symbol`, so pointers MUST be runtime
;   VAs) and register. No controller -> register HEALTH_DEGRADED (a seam member
;   selection skips), so the box degrades to ramblk without a crash.
; ============================================================================
nvme_blk_create:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_admitted
    mov rax, -1
    ret
.power_admitted:
    push rbx
    push r12

    mov  byte  [rel nvme_present], 0
    mov dword [rel nvme_identify_pages_valid], 0
    mov qword [rel nvme_vmd_cfg], 0
    mov  byte  [rel nvme_vmd_child], 0
    mov  byte  [rel nvme_claim_legacy], 0
    mov  dword [rel nvme_sector_size], 0
    mov dword [rel nvme_physical_size], 0
    lea rdi, [rel nvme_identify_fields]
    mov ecx, 7
    xor eax, eax
    rep stosd
    mov  qword [rel nvme_lba_max], 0
    mov  byte  [rel nvme_model], 0
    mov  dword [rel nvme_info + blk_info.unit], 0   ; present member: namespace unit 0
    mov  byte  [rel nvme_class_seen], 0

    ; --- detect an NVMe controller on the PCI bus -------------------------
    mov  qword [rel nvme_bar0], 0
    lea  rdi, [rel nvme_detect_cb]
    call pci_scan_with_filter               ; callback records BAR0 + BDF on match
    mov  rax, [rel nvme_bar0]
    test rax, rax
    jnz  .legacy_ctrl
    ; --- no controller on the legacy bus: an NVMe under Intel VMD lives in the
    ;     VMD child domain (dev/blk/vmd enabled it via the child ECAM and its
    ;     BAR0 is identity-reachable, so the high-BAR remap must not run) ---
    mov  edi, 0x010802
    call vmd_find_child
    test rax, rax
    jnz  .vmd_ctrl
    ; ROOT 121997 / rc-review 122056: no usable controller. Only a scan that saw no
    ; NVM-class or RAID-class (possible VMD root) function at all, before any driver
    ; gate, is absence; a refused, zero-BAR or hidden controller stays present.
    cmp  byte [rel nvme_class_seen], 0
    jne  .degraded
    jmp  .no_controller
.vmd_ctrl:
    mov  [rel nvme_bar0], rax
    mov [rel nvme_vmd_cfg], rdx
    mov  byte [rel nvme_vmd_child], 1
    jmp  .ctrl_ready
.legacy_ctrl:
    mov  byte [rel nvme_claim_legacy], 1     ; a legacy-bus controller matched (hardware report)

    ; --- prefer the proven firmware BAR; otherwise keep guarded relocation ---
    ;   Pre-EBS paging can prove/map the actual high firmware BAR UC+NX. Use
    ;   that mapping without rewriting PCI BARs. If absent, preserve the older
    ;   >=16GiB guarded low-window fallback; no machine-name assumptions.
    ;   The 9 GiB window is RAM on a >=9 GiB machine: relocating there would alias
    ;   system memory (and, on MSI, reprogram the owner's Windows boot disk), so
    ;   the remap is refused unless the live memory map proves RAM ends below it.
    call nvme_remap_bar_if_high
    test eax, eax
    jz   .bar_usable
    lea  rdi, [rel str_nvme_bar_refused]
    call serial_string
    mov  qword [rel nvme_bar0], 0
    jmp  .degraded
.bar_usable:

    ; --- enable Memory Space + Bus Master in the PCI command register ------
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x04
    call pci_cfg_read32                     ; EAX = Status<<16 | Command
    or   ax, 0x0006                         ; bit1 Memory Space + bit2 Bus Master
    mov  r8d, eax
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
.ctrl_ready:

    ; --- CAP -> doorbell stride (4 << DSTRD, DSTRD = CAP[35:32]) -----------
    mov  rbx, [rel nvme_bar0]
    mov  rax, [rbx]                         ; CAP (64-bit MMIO, identity-mapped)
    mov  [rel nvme_cap], rax
    shr  rax, 32
    and  rax, 0x0F                          ; DSTRD
    mov  ecx, eax
    mov  eax, 4
    shl  eax, cl                            ; stride = 4 << DSTRD
    mov  [rel nvme_stride], eax
    ; Queue1 CQ doorbell is the last access: base+0x1000+3*stride, 4 bytes.
    ; CAP was inside the proven first page; refuse a larger DSTRD crossing it
    ; before allocating queues or issuing any controller/DMA command.
    cmp  byte [rel nvme_vmd_child], 0
    jne  .aperture_ready                ; existing VMD mapping is separately owned
    mov  rcx, [rel nvme_bar0]
    shr  rcx, 34
    jz   .aperture_ready                ; original low/relocated path
    lea  esi, [rax + rax*2 + 0x1004]
    call nvme_firmware_bar_mapped
    test eax, eax
    jz   .degraded
.aperture_ready:

    ; --- allocate admin + I/O queues + DMA scratch (page-aligned) ----------
    mov  rdi, NVME_ASIZE * NVME_SQ_ESZ
    call dma_alloc
    test rax, rax
    jz   .degraded
    mov  [rel nvme_asq], rax
    mov  rdi, NVME_ASIZE * NVME_CQ_ESZ
    call dma_alloc
    test rax, rax
    jz   .degraded
    mov  [rel nvme_acq], rax
    mov  rdi, NVME_IOSIZE * NVME_SQ_ESZ
    call dma_alloc
    test rax, rax
    jz   .degraded
    mov  [rel nvme_iosq], rax
    mov  rdi, NVME_IOSIZE * NVME_CQ_ESZ
    call dma_alloc
    test rax, rax
    jz   .degraded
    mov  [rel nvme_iocq], rax
    mov  rdi, 4096
    call dma_alloc                          ; DMA bounce buffer (one 512B/4KiB block)
    test rax, rax
    jz   .degraded
    mov  [rel nvme_bounce], rax
    mov  rdi, 4096
    call dma_alloc                          ; IDENTIFY buffer
    test rax, rax
    jz   .degraded
    mov  [rel nvme_idbuf], rax

    ; --- reset + enable the controller, create the I/O queues --------------
    call nvme_reset_enable
    test rax, rax
    jnz  .degraded
    call nvme_create_io_queues
    test rax, rax
    jnz  .degraded

    ; --- IDENTIFY: real model + LBA size (content, not a latch) ------------
    call nvme_identify                      ; fills nvme_model / sector_size / lba_max
    test eax, eax
    jnz  .degraded                          ; no usable namespace -> no data I/O
    mov  byte [rel nvme_present], 1
    mov  r8d, PCI_CLAIM_BOUND
    call nvme_pci_claim

    ; --- build the REAL blk_ops vtable -------------------------------------
    lea  rbx, [rel nvme_ops]
    lea  rax, [rel nvme_op_identify]
    mov  [rbx + blk_ops.identify], rax
    lea  rax, [rel nvme_op_read]
    mov  [rbx + blk_ops.read], rax
    lea  rax, [rel nvme_op_write]
    mov  [rbx + blk_ops.write], rax
    lea  rax, [rel nvme_op_flush]
    mov  [rbx + blk_ops.flush], rax
    mov  dword [rel nvme_health], HEALTH_OK
    jmp  .fill_info

.no_controller:
    ; ROOT 121997: the scan saw no NVM- or RAID-class function and no VMD child
    ; was found. Mark the seam as no unit, like the AHCI no-disk seam, so the
    ; census never reads it as a present unit without geometry. A controller
    ; that matched, was gate-refused or failed keeps unit 0 and stays present.
    mov  dword [rel nvme_info + blk_info.unit], 0xFFFFFFFF
.degraded:
    ; controller absent / bring-up failed -> every op returns -1, degrade never crash
    mov  r8d, PCI_CLAIM_FAILED               ; only if a controller had matched
    call nvme_pci_claim
    lea  rbx, [rel nvme_ops]
    lea  rax, [rel nvme_blk_degraded]
    mov  [rbx + blk_ops.identify], rax
    mov  [rbx + blk_ops.read], rax
    mov  [rbx + blk_ops.write], rax
    mov  [rbx + blk_ops.flush], rax
    mov  dword [rel nvme_health], HEALTH_DEGRADED

.fill_info:
    lea  rbx, [rel nvme_info]
    lea  rax, [rel str_nvme_name]
    mov  [rbx + blk_info.name], rax
    mov  eax, [rel nvme_sector_size]
    mov  [rbx + blk_info.sector_size], eax
    mov  rax, [rel nvme_lba_max]
    mov  [rbx + blk_info.lba_max], rax
    mov  byte  [rbx + blk_info.dma_mask], 64
    mov  byte  [rbx + blk_info.removable], 0
    mov  dword [rbx + blk_info.flags], 0
    ; RCQ-05 storage rung: a healthy namespace declares its v2 geometry and BLKCAP
    ; mask; the degraded member declares nothing. Physical/preferred granularity
    ; comes from this namespace's Identify fields, not the command transfer size.
    ; Each command moves one logical block, at most NVME_MAX_XFER per call.
    ; flush() issues a real
    ; NVM Flush: it commits completed writes held in a volatile write cache, and
    ; completes with no effect when none is present or enabled, where a completed
    ; write is already non-volatile. FLUSH is truthful either way.
    xor  eax, eax
    xor  ecx, ecx
    xor  edx, edx
    xor  esi, esi
    cmp  dword [rel nvme_health], HEALTH_OK
    jne  .declare
    mov  eax, [rel nvme_sector_size]
    mov  esi, [rel nvme_physical_size]
    mov  ecx, BLKCAP_ALL_IO
    mov  edx, NVME_MAX_XFER
.declare:
    mov  [rbx + blk_info.logical_sector_bytes], eax
    mov  [rbx + blk_info.physical_sector_bytes], esi
    mov  dword [rbx + blk_info.physical_alignment_bytes], 0
    mov  [rbx + blk_info.max_transfer_sectors], edx
    mov  [rbx + blk_info.capabilities], rcx

    lea  rbx, [rel nvme_devs]
    lea  rax, [rel nvme_ops]
    mov  [rbx + dev.ops], rax
    lea  rax, [rel nvme_info]
    mov  [rbx + dev.info], rax
    mov  qword [rbx + dev.priv], 0
    ; SELECTION POLICY (1027 scope boundary): register at PRIO_DOMAIN so the ramblk
    ; reference stays the SELECTED boot scratch default. The boot-time scratch/wedge
    ; consumers (blk_selftest, command_reinit, vfs) target blk_select() and assume a
    ; safe fake backend; promoting a real production disk to the selected default is
    ; the DEVICE_SLOT selection-policy saga (explicitly out of scope here). nvme is
    ; still registered + healthy + content-graded via its own direct self-exercise,
    ; and reachable by name (BLKWRITE nvme) once the UDP verb surface lands (1027b).
    mov  dword [rbx + dev.prio], PRIO_DOMAIN
    mov  eax, [rel nvme_health]
    mov  [rbx + dev.health], eax
    mov  dword [rbx + dev.class], CLASS_BLOCK
    mov  dword [rbx + dev.flags], 0
    lea  rax, [rel str_nvme_name]
    mov  [rbx + dev.name], rax

    mov  rdi, rbx
    call blk_register
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; nvme_detect_cb(EDI=bus,ESI=dev,EDX=fn,ECX=vendev) — PCI scan callback. Records
;   BAR0 + BDF for the FIRST class 0x01 / subclass 0x08 / prog-IF 0x02 function.
;   Must preserve RBX,RBP,R12-R15 (the scan keeps loop state there).
; ---------------------------------------------------------------------------
nvme_detect_cb:
    cmp  qword [rel nvme_bar0], 0
    jne  .out                               ; already found one
    push rdi
    push rsi
    push rdx
    ; class/subclass/progIF at config offset 0x08 (EAX = Rev|ProgIF|Sub|Class)
    mov  ecx, 0x08
    call pci_cfg_read32
    mov  r10d, eax
    shr  eax, 24
    cmp  al, 0x01                           ; class = Mass Storage
    jne  .pop
    mov  eax, r10d
    shr  eax, 16
    and  al, 0xFF
    cmp  al, 0x04                           ; subclass = RAID: a VMD root may hide NVMe
    je   .raid_seen
    cmp  al, 0x08                           ; subclass = NVM
    jne  .pop
    or   byte [rel nvme_class_seen], 1      ; NVM class seen, before any driver gate
    mov  eax, r10d
    shr  eax, 8
    and  al, 0xFF
    cmp  al, 0x02                           ; prog-IF = NVM Express
    jne  .pop
    ; Exact firmware boot controller only, before BAR selection/ownership.
    ; PCI scan supplies bounded segment-zero bus/device/function originals.
    mov esi, [rsp + 16]
    shl rsi, 8
    mov edi, [rsp + 8]
    shl rdi, 3
    or rsi, rdi
    mov edi, [rsp]
    or rsi, rdi
    mov edi, 5
    call native_driver_gate
    jc .pop
    ; matched — save BDF (originals were pushed: rsp+16=rdi, rsp+8=rsi, rsp+0=rdx)
    mov  eax, [rsp + 16]
    mov  [rel nvme_busno], eax
    mov  eax, [rsp + 8]
    mov  [rel nvme_devno], eax
    mov  eax, [rsp + 0]
    mov  [rel nvme_fn], eax
    ; BAR0 (offset 0x10); 64-bit BAR -> combine with BAR1 (0x14)
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r11d, eax                          ; BAR0 low
    test al, 0x04                           ; bits2:1 = 10b -> 64-bit BAR
    jz   .bar32
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x14
    call pci_cfg_read32                     ; BAR1 high
    mov  r9d, r11d
    and  r9d, 0xFFFFFFF0
    shl  rax, 32
    or   rax, r9
    mov  [rel nvme_bar0], rax
    jmp  .pop
.bar32:
    and  r11d, 0xFFFFFFF0
    mov  [rel nvme_bar0], r11
    jmp  .pop
.raid_seen:
    or   byte [rel nvme_class_seen], 2      ; observation only; VMD owns any use
.pop:
    pop  rdx
    pop  rsi
    pop  rdi
.out:
    ret

; nvme_pci_claim(R8D = PCI_CLAIM_*) — RCQ-29 hardware report: record that this
;   driver took (or matched and could not use) the legacy-bus controller.  A
;   VMD-child controller is the VMD root's claim.  Preserves every general register.
nvme_pci_claim:
    cmp  byte [rel nvme_claim_legacy], 1
    jne  .out
    push rax
    push rdi
    push rcx
    lea  rdi, [rel nvme_busno]
    mov  ecx, PCI_DRV_NVME
    call pci_claim_bdf3
    pop  rcx
    pop  rdi
    pop  rax
.out:
    ret

; ---------------------------------------------------------------------------
; nvme_remap_bar_if_high() -> EAX 0 = BAR usable, 1 = refused (BAR untouched).
;   Prefer the exact boot-proven UC+NX firmware BAR. Otherwise, if
;   nvme_bar0 >= 16 GiB, disable memory-space decode
;   and reprogram BAR0 to NVME_REMAP_LOW (9 GiB: below the 16 GiB map and DISTINCT
;   from the xHC's 8 GiB remap window in dev/usb/xhci.asm) — but ONLY when the
;   pre-EBS UEFI memory inventory (boot/paging inv_top_of_ram, RAM-backed memory
;   only) is known and ends at or below that window. Otherwise the window may be
;   RAM: refuse and leave the device untouched (fail closed, like xHCI). Updates
;   nvme_bar0. Memory space is re-enabled by the caller's bus-master step. No-op on
;   bare metal (firmware assigns a low BAR). clobbers caller-saved.
;   NVME_REMAP_LOW = 0x2_4000_0000 -> BAR low dword 0x4000_0004 (64-bit mem type),
;   BAR high dword 0x02.
; ---------------------------------------------------------------------------
NVME_REMAP_LOW equ 0x0000000240000000

nvme_remap_bar_if_high:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_admitted
    mov rax, -1
    ret
.power_admitted:
    mov  rax, [rel nvme_bar0]
    mov  rcx, rax
    shr  rcx, 34                            ; >= 16 GiB (2^34) ?
    test rcx, rcx
    jz   .done
    mov  esi, 0x1004                    ; controller registers + first doorbell
    call nvme_firmware_bar_mapped
    test eax, eax
    jnz  .done                         ; no PCI BAR writes for the proven actual BAR
    mov  rax, [rel inv_top_of_ram]
    test rax, rax
    jz   .refuse                            ; unknown inventory cannot prove safety
    mov  rcx, NVME_REMAP_LOW
    cmp  rax, rcx
    ja   .refuse                            ; RAM reaches the window: never alias it
    ; disable memory-space decode (clear command bit1) before touching BARs
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    and  ax, ~0x0002
    mov  r8d, eax
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
    ; BAR0 low (offset 0x10) = addr-low | 0x04 (64-bit mem type); high (0x14) = 0x02.
    ; 9 GiB, NOT 8 GiB: dev/usb/xhci.asm remaps ITS high BAR to 8 GiB and its init
    ; runs AFTER blk_selftest — a shared window let the xHC hijack the nvme BAR
    ; (QEMU-only: runtime CQ polls timed out while boot I/O had passed).
    mov  r8d, 0x40000004
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x10
    call pci_cfg_write32
    mov  r8d, 0x00000002
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x14
    call pci_cfg_write32
    mov  rax, NVME_REMAP_LOW                 ; imm64 -> reg (a [mem],imm32 store truncates)
    mov  [rel nvme_bar0], rax
.done:
    xor  eax, eax
    ret
.refuse:
    mov  eax, 1
    ret

; Shared live paging check, bound to the controller selected by native PCI scan.
; RSI=complete byte span. No new device discovery or allocation.
nvme_firmware_bar_mapped:
    mov  rdi, [rel nvme_bar0]
    mov  edx, [rel nvme_busno]
    shl  edx, 8
    mov  ecx, [rel nvme_devno]
    shl  ecx, 3
    or   edx, ecx
    or   edx, [rel nvme_fn]
    jmp  paging_nvme_bar_mapped

; ---------------------------------------------------------------------------
; nvme_reset_enable() -> RAX 0 ok / -1 fail. CC.EN=0 -> wait RDY=0 -> program
;   AQA/ASQ/ACQ -> CC.EN=1 -> wait RDY=1 (fail on CSTS.CFS). Ported from nvme_init.
; ---------------------------------------------------------------------------
nvme_reset_enable:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_admitted
    mov rax, -1
    ret
.power_admitted:
    push rbx
    push r12
    mov  rbx, [rel nvme_bar0]

    mov byte [rel nvme_io_pending], 0
    mov byte [rel nvme_admin_pending], 0
    mov word [rel nvme_io_sqhd], 0
    mov word [rel nvme_admin_sqhd], 0
    ; reset queue head/tail/phase state
    mov  word [rel nvme_asq_tail], 0
    mov  word [rel nvme_acq_head], 0
    mov  byte [rel nvme_acq_phase], 1
    mov  word [rel nvme_iosq_tail], 0
    mov  word [rel nvme_iocq_head], 0
    mov  byte [rel nvme_iocq_phase], 1

    ; A controller the firmware left enabled may still hold its writes in a
    ; volatile cache (DRAM-less drives): request a normal shutdown (CC.SHN=01,
    ; the controller commits its cache) before the CC.EN=0 controller reset.
    call nvme_shutdown_if_ready
    ; CC.EN = 0
    mov  eax, [rbx + 0x14]
    and  eax, ~1
    mov  [rbx + 0x14], eax
    ; wait CSTS.RDY = 0
    mov  r12d, NVME_POLL_MAX
.wd:
    mov  eax, [rbx + 0x1C]
    test eax, 1
    jz   .disabled
    mov  edi, 1
    call tsc_delay_us
    dec  r12d
    jnz  .wd
    jmp  .fail
.disabled:
    ; zero admin queues
    mov  rdi, [rel nvme_asq]
    mov  ecx, (NVME_ASIZE * NVME_SQ_ESZ) / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  rdi, [rel nvme_acq]
    mov  ecx, (NVME_ASIZE * NVME_CQ_ESZ) / 8
    xor  eax, eax
    rep  stosq
    ; AQA (0x24): ACQS<<16 | ASQS  (size-1)
    mov  eax, ((NVME_ASIZE - 1) << 16) | (NVME_ASIZE - 1)
    mov  [rbx + 0x24], eax
    ; ASQ (0x28), ACQ (0x30) — 64-bit phys (== virt, identity map)
    mov  rax, [rel nvme_asq]
    mov  [rbx + 0x28], rax
    mov  rax, [rel nvme_acq]
    mov  [rbx + 0x30], rax
    ; CC: IOCQES=4, IOSQES=6, MPS=0, CSS=0, EN=1
    mov  eax, (4 << 20) | (6 << 16) | (0 << 7) | (0 << 4) | 1
    mov  [rbx + 0x14], eax
    ; wait CSTS.RDY = 1 (fail on CFS)
    mov  r12d, NVME_POLL_MAX
.we:
    mov  eax, [rbx + 0x1C]
    test eax, 1
    jnz  .enabled
    test eax, 2                             ; CFS fatal
    jnz  .fail
    mov  edi, 1
    call tsc_delay_us
    dec  r12d
    jnz  .we
    jmp  .fail
.enabled:
    cmp  byte [rel nvme_io_poisoned], 0
    je   .armed
    mov  byte [rel nvme_io_poisoned], 0         ; nvme_reset_enable is the one re-arm
    mov  dword [rel nvme_health], HEALTH_OK
    mov  dword [rel nvme_devs + dev.health], HEALTH_OK
.armed:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; nvme_create_io_queues() -> RAX 0 ok / -1 fail. Admin CREATE I/O CQ (op 0x05) then
;   CREATE I/O SQ (op 0x01), each polled on the admin CQ. Ported from nvme_io_queues.
; ---------------------------------------------------------------------------
nvme_create_io_queues:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_admitted
    mov rax, -1
    ret
.power_admitted:
    push rbx
    ; zero the I/O queues
    mov  rdi, [rel nvme_iocq]
    mov  ecx, (NVME_IOSIZE * NVME_CQ_ESZ) / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  rdi, [rel nvme_iosq]
    mov  ecx, (NVME_IOSIZE * NVME_SQ_ESZ) / 8
    xor  eax, eax
    rep  stosq

    ; --- CREATE I/O CQ: op 0x05, CID 1, PRP1=iocq, CDW10=(QSIZE-1)<<16|QID,
    ;     CDW11 = IV=0 | IEN(bit1) | PC(bit0) ---
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0],  (1 << 16) | 0x05
    mov  rax, [rel nvme_iocq]
    mov  [rel nvme_cmd + 24], rax                                   ; PRP1
    mov  dword [rel nvme_cmd + 40], ((NVME_IOSIZE - 1) << 16) | NVME_IO_CQID
    mov  dword [rel nvme_cmd + 44], (0 << 16) | (1 << 1) | 1
    call nvme_admin_exec
    test eax, eax
    jnz  .fail

    ; --- CREATE I/O SQ: op 0x01, CID 2, PRP1=iosq, CDW10=(QSIZE-1)<<16|QID,
    ;     CDW11 = CQID<<16 | PC(bit0) ---
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0],  (2 << 16) | 0x01
    mov  rax, [rel nvme_iosq]
    mov  [rel nvme_cmd + 24], rax                                   ; PRP1
    mov  dword [rel nvme_cmd + 40], ((NVME_IOSIZE - 1) << 16) | NVME_IO_SQID
    mov  dword [rel nvme_cmd + 44], (NVME_IO_CQID << 16) | 1
    call nvme_admin_exec
    test eax, eax
    jnz  .fail

    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; nvme_identify() -> EAX 0/-1 (usable namespace/refusal).
;   IDENTIFY Controller (CNS=1) -> model @ bytes 24..63;
;   IDENTIFY Namespace (CNS=0, NSID=1) -> NSZE @ [0..7], FLBAS @ [26], LBAF[idx]
;   @ [128+idx*4], LBADS = byte2 -> sector_size = 1<<LBADS. New path (the monolith
;   deliberately skipped IDENTIFY); this is what earns blk.nvme.identify.ok.
; ---------------------------------------------------------------------------
nvme_identify:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_admitted
    mov rax, -1
    ret
.power_admitted:
    push rbx
    ; Invalidate both diagnostic copies before either DMA command.
    mov dword [rel nvme_identify_pages_valid], 0
    inc qword [rel nvme_identify_pages_epoch]
    mov eax, [rel nvme_busno]
    shl eax, 8
    mov edx, [rel nvme_devno]
    shl edx, 3
    or eax, edx
    or eax, [rel nvme_fn]
    mov [rel nvme_identify_pages_bdf], eax
    movzx eax, byte [rel nvme_vmd_child]
    mov [rel nvme_identify_pages_vmd], eax
    ; A failed Identify cannot retain geometry or raw fields from a prior page.
    mov dword [rel nvme_physical_size], 0
    lea rdi, [rel nvme_identify_fields]
    mov ecx, 7
    xor eax, eax
    rep stosd
    ; A repeated failed controller Identify must not expose the prior identity.
    ; Clear only these bounded outputs; namespace qualification stays separate.
    lea  rdi, [rel nvme_model]
    mov  ecx, 48 / 8
    xor  eax, eax
    cld
    rep  stosq
    lea  rdi, [rel nvme_serial]
    mov  ecx, 24 / 8
    rep  stosq
    ; --- IDENTIFY Controller (CNS=1, NSID=0) ---
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0], (7 << 16) | NVME_OP_IDENTIFY   ; CID=7
    mov  dword [rel nvme_cmd + 4], 0                              ; NSID=0
    mov  rax, [rel nvme_idbuf]
    mov  [rel nvme_cmd + 24], rax                                 ; PRP1
    mov  dword [rel nvme_cmd + 40], 1                             ; CDW10 CNS=1
    call nvme_admin_exec
    test eax, eax
    jnz  .ns                                 ; identify-ctrl failed -> leave model/serial empty
    ; Keep CNS=1 before CNS=0 overwrites the shared DMA page.
    mov rsi, [rel nvme_idbuf]
    lea rdi, [rel nvme_identify_controller_page]
    mov ecx, 4096 / 8
    rep movsq
    or dword [rel nvme_identify_pages_valid], 1
    ; Task3470: copy 20-byte serial (bytes 4..23) -> nvme_serial, NUL-term + trim spaces
    mov  rsi, [rel nvme_idbuf]
    add  rsi, 4
    lea  rdi, [rel nvme_serial]
    xor  ecx, ecx
.scp:
    cmp  ecx, 20
    jae  .sdone
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .scp
.sdone:
    mov  byte [rdi + 20], 0
.strim:
    test ecx, ecx
    jz   .model
    dec  ecx
    cmp  byte [rdi + rcx], ' '
    jne  .model
    mov  byte [rdi + rcx], 0
    jmp  .strim
.model:
    ; copy 40-byte model (bytes 24..63) -> nvme_model, NUL-terminate
    mov  rsi, [rel nvme_idbuf]
    add  rsi, 24
    lea  rdi, [rel nvme_model]
    xor  ecx, ecx
.mcp:
    cmp  ecx, 40
    jae  .mdone
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .mcp
.mdone:
    mov  byte [rdi + 40], 0
    ; trim trailing spaces (ecx == 40 here)
.mtrim:
    test ecx, ecx
    jz   .ns
    dec  ecx
    cmp  byte [rdi + rcx], ' '
    jne  .ns
    mov  byte [rdi + rcx], 0
    jmp  .mtrim

.ns:
    ; --- IDENTIFY Namespace (CNS=0, NSID=1) ---
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0], (8 << 16) | NVME_OP_IDENTIFY   ; CID=8
    mov  dword [rel nvme_cmd + 4], 1                              ; NSID=1
    mov  rax, [rel nvme_idbuf]
    mov  [rel nvme_cmd + 24], rax                                 ; PRP1
    mov  dword [rel nvme_cmd + 40], 0                             ; CDW10 CNS=0
    call nvme_admin_exec
    test eax, eax
    jnz  .out
    ; Completion is independent of namespace-format admission.
    mov rsi, [rel nvme_idbuf]
    lea rdi, [rel nvme_identify_namespace_page]
    mov ecx, 4096 / 8
    rep movsq
    or dword [rel nvme_identify_pages_valid], 2
    mov  rbx, [rel nvme_idbuf]
    call nvme_parse_namespace
    pop  rbx
    ret
.out:
    mov  dword [rel nvme_sector_size], 0
    mov  qword [rel nvme_lba_max], 0
    mov  eax, -1
    pop  rbx
    ret

; Peter 2026-10-30 scope trim14: 0.1 supports metadata-free 512B only.
; Native4K is deferred to0.2; never reinterpret it as512 or choose another LBAF.
; Extended FLBAS, protection information and other sizes remain unsupported.
; Publish geometry only after all checks pass.
; RBX = completed 4096-byte Identify Namespace buffer; clobbers RAX,RCX,RDX.
nvme_parse_namespace:
    mov  dword [rel nvme_sector_size], 0
    mov  dword [rel nvme_physical_size], 0
    mov  qword [rel nvme_lba_max], 0
    ; Retain the completed page's exact inputs even when its format is refused.
    ; The low nibble always addresses one of the bounded sixteen LBAF entries.
    mov dword [rel nvme_identify_valid], 1
    movzx eax, byte [rbx + 26]
    mov [rel nvme_identify_flbas], eax
    and eax, 15
    mov eax, [rbx + rax*4 + 128]
    mov [rel nvme_identify_lbaf], eax
    movzx eax, byte [rbx + 24]
    mov [rel nvme_identify_nsfeat], eax
    movzx eax, word [rbx + 64]
    mov [rel nvme_identify_npwg], eax
    movzx eax, word [rbx + 72]
    mov [rel nvme_identify_nows], eax
    movzx eax, word [rbx + 36]
    mov [rel nvme_identify_nawupf], eax
    movzx eax, byte [rbx + 26]              ; FLBAS: low four-bit format only
    test eax, 0xF0                         ; no metadata/extended/reserved flags
    jnz  .bad
    cmp  byte [rbx + 25], 15                ; NLBAF (zero-based)
    ja   .bad
    cmp  al, [rbx + 25]
    ja   .bad
    cmp  byte [rbx + 29], 0                 ; DPS: no protection information
    jne  .bad
    lea  eax, [rax * 4 + 128]
    cmp  word [rbx + rax], 0                ; LBAF.MS: no metadata buffer/PRP
    jne  .bad
    movzx ecx, byte [rbx + rax + 2]         ; LBAF.LBADS
    cmp  ecx, 9                            ; 0.1: metadata-free 512-byte namespace
    jne  .bad
.size:
    mov  eax, 1
    shl  eax, cl
    mov  ecx, eax                          ; bytes in one logical block
    mov  rax, [rbx]                        ; NSZE, in logical blocks
    test rax, rax
    jz   .bad
    mov  rdx, [rbx + 8]                    ; NCAP: nonempty, within NSZE
    test rdx, rdx
    jz   .bad
    cmp  rdx, rax
    ja   .bad
    mul  rcx                              ; representable namespace byte size
    test rdx, rdx
    jnz  .bad
    call nvme_namespace_physical
    test eax, eax
    jz .bad
    mov [rel nvme_physical_size], eax
    mov  rax, [rbx]
    dec  rax
    mov  [rel nvme_lba_max], rax
    mov  [rel nvme_sector_size], ecx
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; RBX=Identify Namespace, ECX=qualified logical bytes. EAX=preferred physical
; granularity, or zero if it cannot be represented by the block class ABI.
; NVMe 1.4, Identify Namespace: NSFEAT.OPT PERF validates NPWG (64:65),
; a zero-based count of logical blocks. NOWS (72:73) is optimal write *size*,
; not granularity: retain it in BLKINFO, never substitute it for NPWG.
; Without OPT PERF, namespace NAWUPF (36:37) is usable only with NSABP (bit 1).
; Zero NAWUPF supplies no larger namespace unit; fall back to one logical block.
; No controller-wide atomicity or Windows-specific emulation is inferred.
nvme_namespace_physical:
    mov eax, 1
    test byte [rbx + 24], 0x10
    jz .atomic
    movzx eax, word [rbx + 64]
    inc eax
    jmp .bytes
.atomic:
    test byte [rbx + 24], 2
    jz .bytes
    movzx eax, word [rbx + 36]
    inc eax
.bytes:
    imul eax, ecx                         ; 512 * (u16 + 1), no u32 overflow
    lea edx, [rax - 1]
    test eax, edx                         ; existing ABI requires a power of two
    jz .out
    xor eax, eax                          ; never round or invent a unit
.out:
    ret

; ---------------------------------------------------------------------------
; nvme_cmd_clear() — zero the 64-byte command staging buffer. clobbers RAX,RCX,RDI.
; ---------------------------------------------------------------------------
nvme_cmd_clear:
    lea  rdi, [rel nvme_cmd]
    mov  ecx, NVME_SQ_ESZ / 8
    xor  eax, eax
    cld
    rep  stosq
    ret

; nvme_identify_dma_to(RDI=page-aligned IOVA, ESI=caller CID) -> RAX=status.
; Narrow native-IOMMU proof seam: issue the same non-destructive Identify
; Controller operation used during bring-up while the VT-d owner supplies an
; intentionally invalid IOVA. No normal driver path or DMA ABI changes.
; A controller in the Intel VMD child domain may be an RST RAID member and is
; refused before any command, as ahci_identify_dma_to (SEC 76521 N1).
nvme_identify_dma_to:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_admitted
    mov rax, -1
    ret
.power_admitted:
    push rbx
    push r12
    cmp  byte [rel nvme_present], 1
    jne  .unavailable
    cmp  byte [rel nvme_vmd_child], 0
    jne  .unavailable                    ; VMD/RST RAID member: no probe DMA (as ahci_identify_dma_to)
    test rdi, rdi
    jz   .unavailable
    test rdi, 0x0FFF
    jnz  .unaligned
    mov  rbx, rdi
    mov  r12d, esi
    and  r12d, 0xFFFF
    call nvme_cmd_clear
    shl  r12d, 16
    or   r12d, NVME_OP_IDENTIFY
    mov  [rel nvme_cmd + 0], r12d
    mov  [rel nvme_cmd + 24], rbx         ; PRP1: caller-supplied IOVA
    mov  dword [rel nvme_cmd + 40], 1     ; CNS=Identify Controller
    call nvme_admin_exec
    jmp  .done
.unavailable:
    mov  eax, 0xFFFE
    jmp  .done
.unaligned:
    mov  eax, 0xFFFD
.done:
    pop  r12
    pop  rbx
    ret

; Bounded read-only AMD-Vi proof seam. RDI is the owner's denied aligned page.
; The hv owner proves that mapping/ownership; this driver grants only this exact
; command, once. CID E001..FFFE is reserved for this seam and never reused/reset
; within a boot. Existing Identify proof CIDs D111/D112 are unchanged.
nvme_get_log_error4_dma_to:
    cld
    push rbx
    push r12
    cmp qword [rel nvme_power_gate], 0
    jne .refuse
    cmp byte [rel nvme_present], 1
    jne .refuse
    cmp byte [rel nvme_io_poisoned], 0
    jne .refuse
    cmp byte [rel nvme_admin_pending], 0
    jne .refuse
    test rdi, rdi
    jz .refuse
    test rdi, 4095
    jnz .refuse
    mov rbx, rdi
    movzx eax, word [rel nvme_dma4_cid]
    cmp eax, 0xFFFE
    jae .refuse
    inc eax
    mov [rel nvme_dma4_cid], ax
    mov r12d, eax
    call nvme_cmd_clear
    shl r12d, 16
    or r12d, 0x02                       ; Get Log Page, flags/PSDT zero
    mov [rel nvme_cmd], r12d
    mov [rel nvme_cmd + 24], rbx
    mov dword [rel nvme_cmd + 40], 0x8001 ; Error Info, RAE1, NUMD0 -> exactly4B
    mov [rel nvme_dma4_page], rbx
    mov byte [rel nvme_dma4_token], 1
    call nvme_admin_exec                ; real SQ/CQ integrity path, no bypass
    mov byte [rel nvme_dma4_token], 0    ; also revoke if power gate refused early
    mov qword [rel nvme_dma4_page], 0
    jmp .out
.refuse:
    mov eax, 0xFFFE
.out:
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; nvme_admin_exec() -> RAX = status (0 ok). Copy nvme_cmd -> ASQ[tail], ring the
;   admin SQ0 tail doorbell (BAR0+0x1000, NOT stride-scaled), poll the admin CQ.
; ---------------------------------------------------------------------------
; nvme_admin_admitted() -> EAX 0 admitted / -1 refused, for the opcode staged in
;   nvme_cmd. SEC-S6 gate admits IDENTIFY (0x06), CREATE I/O CQ/SQ (0x05,
;   0x01), and the exact one-shot ErrorLog4 below. FORMAT NVM, SANITIZE,
;   namespace management, firmware download/commit, set features and every
;   other command (including all other GetLog shapes) remain refused.
;   Clobbers RAX only (all other GPRs preserved).
nvme_admin_admitted:
    push rcx
    movzx ecx, byte [rel nvme_dma4_token]
    mov byte [rel nvme_dma4_token], 0    ; one-shot on every gate invocation
    movzx eax, byte [rel nvme_cmd]
    cmp  eax, NVME_OP_IDENTIFY
    je   .yes
    cmp  eax, 0x05                          ; CREATE I/O CQ
    je   .yes
    cmp  eax, 0x01                          ; CREATE I/O SQ
    je   .yes
    cmp  eax, 0x02                          ; no generic Get Log Page grant
    jne  .no
    cmp  ecx, 1
    jne  .no
    cmp  word [rel nvme_cmd], 0x0002     ; flags, fuse, PSDT all zero
    jne  .no
    movzx eax, word [rel nvme_cmd + 2]
    cmp  ax, [rel nvme_dma4_cid]
    jne  .no
    cmp  eax, 0xE001
    jb   .no
    cmp  eax, 0xFFFE
    ja   .no
    cmp  dword [rel nvme_cmd + 4], 0    ; NSID and all reserved/metadata zero
    jne  .no
    cmp  qword [rel nvme_cmd + 8], 0
    jne  .no
    cmp  qword [rel nvme_cmd + 16], 0
    jne  .no
    mov  rax, [rel nvme_dma4_page]
    test rax, rax
    jz   .no
    test rax, 4095
    jnz  .no
    cmp  rax, [rel nvme_cmd + 24]       ; only this invocation's owned target
    jne  .no
    cmp  qword [rel nvme_cmd + 32], 0   ; PRP2 is never used for4B
    jne  .no
    cmp  dword [rel nvme_cmd + 40], 0x8001
    jne  .no
    cmp  dword [rel nvme_cmd + 44], 0
    jne  .no
    cmp  qword [rel nvme_cmd + 48], 0
    jne  .no
    cmp  qword [rel nvme_cmd + 56], 0
    jne  .no
.yes:
    xor  eax, eax
    pop  rcx
    ret
.no:
    mov  eax, -1
    pop  rcx
    ret

; nvme_io_admitted() -> EAX 0 admitted / -1 refused, for the I/O opcode staged in
;   nvme_cmd. READ and FLUSH are admitted; WRITE only with the one-shot
;   nvme_write_token that nvme_op_write sets right before its call; WRITE ZEROES,
;   DSM (deallocate), WRITE UNCORRECTABLE and every other I/O command are refused.
;   The token is consumed on every call. In a live Try boot (pbm_try_media) WRITE
;   is refused even with the token. clobbers EAX, ECX.
nvme_io_admitted:
    movzx ecx, byte [rel nvme_write_token]
    mov  byte [rel nvme_write_token], 0
    movzx eax, byte [rel nvme_cmd]
    cmp  eax, NVME_OP_READ
    je   .yes
    cmp  eax, NVME_OP_FLUSH
    je   .yes
    cmp  eax, NVME_OP_WRITE
    jne  .no
    cmp  ecx, 1
    je   .yes
.no:
    mov  eax, -1
    ret
.yes:
    cmp  eax, NVME_OP_WRITE                 ; RCQ-29 live Try: never WRITE, token or not
    jne  .admit
    cmp  byte [rel pbm_try_media], 1
    je   .no
.admit:
    xor  eax, eax
    ret

nvme_admin_exec_cooperative:
    mov eax, 2
    jmp nvme_admin_exec.cooperative
nvme_admin_exec:
    xor eax, eax
.cooperative:
    push r13
    mov r13d, eax
    call nvme_power_check
    test rax, rax
    jz .power_ok
    pop r13
    ret
.power_ok:
    push rbx
    push r12
    call nvme_admin_admitted                ; SEC-S6: the opcode gate, before the SQ copy
    test eax, eax
    jnz  .refused
    cmp byte [rel nvme_admin_pending], 0
    jne .refused
    mov ax, [rel nvme_cmd+2]
    mov [rel nvme_admin_cid], ax
    mov byte [rel nvme_admin_pending], 1
    mov  rbx, [rel nvme_bar0]
    movzx r12d, word [rel nvme_asq_tail]
    mov   rdi, [rel nvme_asq]
    imul  rax, r12, NVME_SQ_ESZ
    add   rdi, rax
    lea   rsi, [rel nvme_cmd]
    mov   ecx, NVME_SQ_ESZ / 8
    cld
    rep   movsq
    inc   r12d
    and   r12d, (NVME_ASIZE - 1)
    mov   [rel nvme_asq_tail], r12w
    mov   [rbx + 0x1000], r12d               ; admin SQ0 tail doorbell (raw)
    test r13d, r13d
    jnz .issued
    mov   rdi, [rel nvme_acq]
    lea   rsi, [rel nvme_acq_head]
    lea   rdx, [rel nvme_acq_phase]
    mov   r8d, NVME_ASIZE
    xor   r9d, r9d                           ; CQ id 0
    call  nvme_poll_cq_running
    cmp eax, 0xFFFF
    je .uncertain
    mov cx, [rel nvme_last_cqe_cid]
    cmp cx, [rel nvme_admin_cid]
    jne .uncertain
    cmp word [rel nvme_last_cqe_sqid], 0
    jne .uncertain
    mov cx, [rel nvme_last_cqe_sqhd]
    cmp cx, [rel nvme_asq_tail]
    jne .uncertain
    mov [rel nvme_admin_sqhd], cx
    mov byte [rel nvme_admin_pending], 0
    jmp .out
.uncertain:
    mov byte [rel nvme_io_poisoned], 1
    mov dword [rel nvme_health], HEALTH_DEGRADED
    mov dword [rel nvme_devs+dev.health], HEALTH_DEGRADED
    jmp .refused
.issued:
    xor eax, eax
    jmp .out
.refused:
    mov   eax, 0xFFFE                       ; refused, nothing submitted
.out:
    pop   r12
    pop   rbx
    pop r13
    cld
    ret

; ---------------------------------------------------------------------------
; nvme_io_exec() -> RAX = status (0 ok). Copy nvme_cmd -> IOSQ[tail], ring I/O SQ1
;   tail doorbell (BAR0+0x1000 + 2*stride), poll the I/O CQ (head @ +3*stride).
;   Completion integrity: every command gets a rolling CID (1..0xFFFE, stamped
;   over the op's staging value); only a CQE carrying that CID and SQ id 1
;   completes it. A timeout (command still outstanding, may DMA later) or a
;   foreign/stale CQE poisons the controller: nothing is submitted again and
;   health is DEGRADED until nvme_reset_enable re-arms it (0xFFFE = refused).
; ---------------------------------------------------------------------------
; Passive terminal Flush scope only: 0 outside, 1 original Flush bracket,
; 2 original synchronous io_exec poll. These stores never authorize transport.
; Capture only already-loaded native operands, preserving all registers/flags.
%macro NVME_QC_STORE 4
    pushfq
    cmp byte [rel nvme_qc_scope],%4
    jne %%out
%if %4 = 2
    cmp r15d,1                         ; original I/O CQ1, never admin CQ0
    jne %%out
%endif
    mov %2 [rel nvme_quiesce_completion+%1],%3
%%out:
    popfq
%endmacro
%macro NVME_QC_SCOPE 2
    pushfq
    cmp byte [rel nvme_qc_scope],%1
    jne %%out
    mov byte [rel nvme_qc_scope],%2
%%out:
    popfq
%endmacro
nvme_io_exec_cooperative:
    mov eax, 1
    jmp nvme_io_exec.cooperative
nvme_io_exec:
    xor eax, eax
.cooperative:
    push r13
    mov r13d, eax
    call nvme_power_check
    test rax, rax
    jz .power_ok
    mov byte [rel nvme_write_token], 0 ; failed admission also consumes the one-shot
    pop r13
    ret
.power_ok:
    push rbx
    push r12
    call nvme_io_admitted                   ; SEC-S6: the opcode gate (consumes the write token)
    test eax, eax
    jnz  .refused
    cmp  byte [rel nvme_io_poisoned], 0
    jne  .refused
    cmp byte [rel nvme_io_pending], 0
    jne .refused
    movzx eax, word [rel nvme_io_cid]
    inc  eax
    cmp  eax, 0xFFFF
    jb   .cid
    mov  eax, 1                                  ; never 0 or 0xFFFF
.cid:
    mov byte [rel nvme_io_pending], 1
    mov  [rel nvme_io_cid], ax
    NVME_QC_STORE 8,word,ax,1          ; actual assigned CID, not last CQE
    mov  [rel nvme_cmd + 2], ax                 ; CDW0[31:16] = CID
    mov  rbx, [rel nvme_bar0]
    movzx r12d, word [rel nvme_iosq_tail]
    mov   rdi, [rel nvme_iosq]
    imul  rax, r12, NVME_SQ_ESZ
    add   rdi, rax
    lea   rsi, [rel nvme_cmd]
    mov   ecx, NVME_SQ_ESZ / 8
    cld
    rep   movsq
    inc   r12d
    and   r12d, (NVME_IOSIZE - 1)
    mov   [rel nvme_iosq_tail], r12w
    NVME_QC_STORE 16,word,r12w,1       ; original published expected SQHD
    ; SQ1 tail doorbell = BAR0 + 0x1000 + 2*stride
    mov   eax, [rel nvme_stride]
    shl   eax, 1
    lea   rdi, [rbx + 0x1000]
    add   rdi, rax
    mov   [rdi], r12d
    NVME_QC_STORE 0,qword,1,1          ; original SQ1 doorbell was issued
    test r13d, r13d
    jnz .issued
    mov   rdi, [rel nvme_iocq]
    lea   rsi, [rel nvme_iocq_head]
    lea   rdx, [rel nvme_iocq_phase]
    mov   r8d, NVME_IOSIZE
    mov   r9d, 1                             ; CQ id 1
    NVME_QC_SCOPE 1,2                 ; this original synchronous Flush poll
    call  nvme_poll_cq_running
    NVME_QC_SCOPE 2,1                 ; close capture before integrity decisions
    cmp  eax, 0xFFFF
    je   .poison                       ; timeout: command still outstanding
    movzx ecx, word [rel nvme_last_cqe_cid]
    cmp  cx, [rel nvme_io_cid]
    jne  .poison
    cmp  word [rel nvme_last_cqe_sqid], 1
    jne  .poison
    mov cx, [rel nvme_last_cqe_sqhd]
    cmp cx, [rel nvme_iosq_tail]
    jne .poison
    mov [rel nvme_io_sqhd], cx
    mov byte [rel nvme_io_pending], 0
    jmp  .out
.poison:
    mov  byte [rel nvme_io_poisoned], 1
    mov  dword [rel nvme_health], HEALTH_DEGRADED
    mov  dword [rel nvme_devs + dev.health], HEALTH_DEGRADED
    lea  rdi, [rel str_nvme_poisoned]
    call serial_string
    jmp .refused
.issued:
    xor eax, eax
    jmp .out
.refused:
    mov  eax, 0xFFFE
.out:
    pop   r12
    pop   rbx
    pop r13
    cld
    ret

; ---------------------------------------------------------------------------
; nvme_poll_cq(RDI=cq_base, RSI=&head_word, RDX=&phase_byte, R8D=qsize, R9D=cqid)
;   -> RAX = status code (0 = success, 0xFFFF = timeout). Waits for the CQ entry's
;   phase (P) bit to match the expected phase, extracts status (word[+14]>>1)&0x7FFF,
;   advances head with wrap+phase-toggle, rings the CQ head doorbell.
;   Doorbell math: head db = BAR0 + 0x1000 + (2*cqid+1)*stride.
;   The entry pointer + poll counter are recomputed/preserved across tsc_delay_us
;   (it clobbers caller-saved regs incl. RCX/R10).
; ---------------------------------------------------------------------------
; Normal synchronous owner may finish its exact accepted command while RUNNING.
; Unattached behavior retains the original poll; an attached plan requires the
; narrower running-completion gate, never ordinary producer admission.
nvme_poll_cq_running:
    cmp qword [rel nvme_power_gate], 0
    je nvme_poll_cq
    mov eax, 4
    jmp nvme_poll_cq.cooperative
nvme_poll_cq_once:
    mov eax, 3
    jmp nvme_poll_cq.cooperative
nvme_poll_cq:
    xor eax, eax
.cooperative:
    push rbp
    mov ebp, eax
    call nvme_power_check
    test rax, rax
    jz .power_ok
    pop rbp
    ret
.power_ok:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi                            ; cq base
    mov  r12, rsi                            ; &head
    mov  r13, rdx                            ; &phase
    mov  r14d, r8d                           ; qsize
    mov  r15d, r9d                           ; cqid
    mov  r10d, NVME_POLL_MAX                  ; poll counter (preserved across delay)
.wait:
    movzx eax, word [r12]                    ; head (stable during wait)
    imul  rcx, rax, NVME_CQ_ESZ
    add   rcx, rbx                           ; rcx = CQ entry ptr
    movzx eax, word [rcx + 14]               ; status field (16-bit)
    mov   r11d, eax                          ; full status
    and   eax, 1                             ; P bit
    movzx edx, byte [r13]                    ; expected phase
    cmp   eax, edx
    je    .got
    cmp ebp, 3
    je .pending
    push  r10
    mov   edi, 1
    call  tsc_delay_us
    pop   r10
    dec   r10d
    jnz   .wait
    mov   eax, 0xFFFF                         ; timeout
    mov   [rel nvme_last_st], ax              ; diag: last completion status (verbs surface it)
    jmp   .ret
.pending:
    mov eax, 0x10000
    jmp .ret
.got:
    movzx eax, word [rcx + 8]
    mov [rel nvme_last_cqe_sqhd], ax
    NVME_QC_STORE 48,word,ax,2
    movzx eax, word [rcx + 12]                ; CQE DW3[15:0] command identifier
    mov   [rel nvme_last_cqe_cid], ax
    NVME_QC_STORE 32,word,ax,2
    movzx eax, word [rcx + 10]                ; CQE DW2[31:16] SQ identifier
    mov   [rel nvme_last_cqe_sqid], ax
    NVME_QC_STORE 40,word,ax,2
    mov   eax, r11d
    shr   eax, 1
    and   eax, 0x7FFF                         ; status code
    NVME_QC_STORE 56,dword,eax,2
    NVME_QC_STORE 24,qword,1,2          ; observed only after actual .got loads
    push  rax                                 ; save status across doorbell math
    ; advance head, wrap -> toggle expected phase
    movzx r8d, word [r12]
    inc   r8d
    cmp   r8d, r14d
    jb    .nowrap
    xor   r8d, r8d
    mov   dl, [r13]
    xor   dl, 1
    mov   [r13], dl
.nowrap:
    mov   [r12], r8w
    ; ring CQ head doorbell = BAR0 + 0x1000 + (2*cqid+1)*stride
    mov   eax, r15d
    shl   eax, 1
    inc   eax                                 ; 2*cqid+1
    imul  eax, dword [rel nvme_stride]
    mov   rdi, [rel nvme_bar0]
    lea   rdi, [rdi + 0x1000]
    add   rdi, rax
    mov   [rdi], r8d
    pop   rax                                 ; restore status
    mov   [rel nvme_last_st], ax              ; diag: last completion status (verbs surface it)
.ret:
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop rbp
    cld
    ret

%unmacro NVME_QC_STORE 4
%unmacro NVME_QC_SCOPE 2

; Private cooperative completion: EDI=0 admin / 1 I/O. The capability
; gate below nvme_poll_cq_once validates exact CQ/head/phase/size/qid before
; observing DMA. No delay, retry, reset or allocation; 0x10000 means pending.
nvme_power_poll:
    push rbx
    mov ebx, edi
    cmp edi, 1
    ja .refused
    test edi, edi
    jnz .io
    cmp byte [rel nvme_admin_pending], 1
    jne .refused
    mov rdi, [rel nvme_acq]
    lea rsi, [rel nvme_acq_head]
    lea rdx, [rel nvme_acq_phase]
    mov r8d, NVME_ASIZE
    xor r9d, r9d
    jmp .poll
.io:
    cmp byte [rel nvme_io_pending], 1
    jne .refused
    mov rdi, [rel nvme_iocq]
    lea rsi, [rel nvme_iocq_head]
    lea rdx, [rel nvme_iocq_phase]
    mov r8d, NVME_IOSIZE
    mov r9d, 1
.poll:
    call nvme_poll_cq_once
    cmp eax, 0x10000
    je .out
    cmp eax, 0x8000
    jae .refused
    cmp bx, [rel nvme_last_cqe_sqid]
    jne .poison
    mov cx, [rel nvme_last_cqe_sqhd]
    test ebx, ebx
    jnz .io_done
    cmp cx, [rel nvme_asq_tail]
    jne .poison
    mov dx, [rel nvme_last_cqe_cid]
    cmp dx, [rel nvme_admin_cid]
    jne .poison
    mov [rel nvme_admin_sqhd], cx
    mov byte [rel nvme_admin_pending], 0
    jmp .out
.io_done:
    cmp cx, [rel nvme_iosq_tail]
    jne .poison
    mov dx, [rel nvme_last_cqe_cid]
    cmp dx, [rel nvme_io_cid]
    jne .poison
    mov [rel nvme_io_sqhd], cx
    mov byte [rel nvme_io_pending], 0
    jmp .out
.poison:
    mov byte [rel nvme_io_poisoned], 1
    mov dword [rel nvme_health], HEALTH_DEGRADED
    mov dword [rel nvme_devs+dev.health], HEALTH_DEGRADED
.refused:
    mov eax, 0xFFFE
.out:
    pop rbx
    cld
    ret

; ============================================================================
; blk_ops implementations
; ============================================================================
; identify(self) -> 0/-1. Idempotent liveness the reinit contract drives: present
;   controller -> 0. (A full re-reset ladder is a resilience follow-up.)
nvme_op_identify:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_self_ok
    lea rax, [rel nvme_devs]
    cmp rdi, rax
    je .power_self_ok
    mov rax, -1
    ret
.power_self_ok:
    cld
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    cmp  byte [rel nvme_present], 0
    je   .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; read(self, RSI=lba, RDX=count, RCX=buf) -> 0/-1. Stream `count`
;   supported logical blocks one command at a time through the page-aligned bounce buffer.
;   The FAT guest-image path requests up to 8 sectors. Keep every controller
;   command at the metal-proven PRP1/NLB=0 shape for DRAM-less MAXIO devices.
nvme_op_read:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_self_ok
    lea rax, [rel nvme_devs]
    cmp rdi, rax
    je .power_self_ok
    mov rax, -1
    ret
.power_self_ok:
    cld
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push rbx
    push r12
    push r13
    cmp  byte [rel nvme_present], 0
    je   .fail
    cmp  byte [rel nvme_io_poisoned], 0
    jne  .fail                               ; a stale command may still own the bounce buffer
    call nvme_validate_io                   ; direct callers also checked pre-I/O
    test eax, eax
    jnz  .fail
    mov  rbx, rdx                            ; remaining block count
    mov  r13, rcx                            ; caller buf (advances per block)
    mov  r12, rsi                            ; lba (advances per block)
.blk:
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0], (1 << 16) | NVME_OP_READ       ; CID=1
    mov  dword [rel nvme_cmd + 4], 1                              ; NSID=1
    mov  rax, [rel nvme_bounce]
    mov  [rel nvme_cmd + 24], rax                                 ; PRP1 (one page-aligned logical block)
    mov  eax, r12d
    mov  [rel nvme_cmd + 40], eax                                 ; SLBA low
    mov  rax, r12
    shr  rax, 32
    mov  [rel nvme_cmd + 44], eax                                 ; SLBA high
    mov  dword [rel nvme_cmd + 48], 0                             ; NLB=0 (1 block)
    call nvme_io_exec
    test eax, eax
    jnz  .fail
    mov  rsi, [rel nvme_bounce]
    mov  rdi, r13
    mov  ecx, [rel nvme_sector_size]
    shr  ecx, 3
    cld
    rep  movsq
    add  r12, 1                              ; next LBA
    mov  eax, [rel nvme_sector_size]
    add  r13, rax                            ; next logical-block caller slot
    dec  rbx
    jnz  .blk
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; write(self, RSI=lba, RDX=count, RCX=buf) -> 0/-1. Stream `count` (1..NVME_MAX_XFER)
;   logical blocks one command at a time, as the read does: copy one block to the
;   bounce buffer, then DMA it out under its own one-shot SEC-S6 write token.
;   A controller found in the Intel VMD child domain (nvme_vmd_child) is never
;   written: it may be an Intel RST RAID member, whose metadata PaOS does not
;   parse (root 75379, as ahci_op_write). Reads stay allowed.
nvme_op_write:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_self_ok
    lea rax, [rel nvme_devs]
    cmp rdi, rax
    je .power_self_ok
    mov rax, -1
    ret
.power_self_ok:
    cld
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push rbx
    push r12
    push r13
    cmp  byte [rel nvme_present], 0
    je   .fail
    cmp  byte [rel nvme_io_poisoned], 0
    jne  .fail                               ; a stale command may still own the bounce buffer
    call nvme_validate_io
    test eax, eax
    jnz  .fail
    cmp  byte [rel nvme_vmd_child], 0
    jne  .fail                               ; VMD/RST RAID member: never written
    mov  rbx, rdx                            ; remaining block count
    mov  r13, rcx                            ; caller buf (advances per block)
    mov  r12, rsi                            ; lba (advances per block)
.blk:
    mov  rsi, r13
    mov  rdi, [rel nvme_bounce]
    mov  ecx, [rel nvme_sector_size]
    shr  ecx, 3
    cld
    rep  movsq
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0], (3 << 16) | NVME_OP_WRITE      ; CID=3
    mov  dword [rel nvme_cmd + 4], 1                              ; NSID=1
    mov  rax, [rel nvme_bounce]
    mov  [rel nvme_cmd + 24], rax                                 ; PRP1
    mov  eax, r12d
    mov  [rel nvme_cmd + 40], eax                                 ; SLBA low
    mov  rax, r12
    shr  rax, 32
    mov  [rel nvme_cmd + 44], eax                                 ; SLBA high
    mov  dword [rel nvme_cmd + 48], 0                             ; NLB=0
    mov  byte [rel nvme_write_token], 1     ; SEC-S6: only the registered write op may write
    call nvme_io_exec
    test eax, eax
    jnz  .fail
    add  r12, 1                              ; next LBA
    mov  eax, [rel nvme_sector_size]
    add  r13, rax                            ; next logical-block caller slot
    dec  rbx
    jnz  .blk
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate geometry, range, byte arithmetic and pointer wrap before any
; command or copy, including direct backend callers. The ABI has no caller
; allocation length: callers must supply count*sector_size accessible bytes.
; Preserves RSI,RDX,RCX (I/O arguments); clobbers RAX,R8-R10.
nvme_validate_io:
    mov  r8d, [rel nvme_sector_size]
    cmp  r8d, 512                          ; stale/direct callers cannot reopen4K
    jne  .bad
.size:
    test rdx, rdx
    jz   .bad
    cmp  rdx, NVME_MAX_XFER
    ja   .bad                              ; the declared max transfer (RCQ-05)
    test rcx, rcx
    jz   .bad
    mov  rax, [rel nvme_bounce]
    test rax, rax
    jz   .bad
    test eax, 4095                         ; one PRP page, no second-page alias
    jnz  .bad
    mov  rax, rdx
    dec  rax
    add  rax, rsi
    jc   .bad
    cmp  rax, [rel nvme_lba_max]
    ja   .bad
    mov  r9, rdx
    mov  rax, rdx
    mul  r8
    mov  r10, rdx
    mov  rdx, r9
    test r10, r10
    jnz  .bad
    add  rax, rcx                          ; exclusive caller buffer end
    jc   .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; flush(self) -> 0/-1. Real NVM Flush (opcode 0x00) — a committed write reaches NAND.
nvme_op_flush:
    cld
    cmp qword [rel nvme_power_gate], 0
    je .power_self_ok
    lea rax, [rel nvme_devs]
    cmp rdi, rax
    je .power_self_ok
    mov rax, -1
    ret
.power_self_ok:
    cld
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    cmp  byte [rel nvme_present], 0
    je   .fail
    cmp  dword [rel nvme_sector_size], 512  ; no flush to refused/stale geometry
    jne  .fail
    cmp  byte [rel nvme_io_poisoned], 0
    jne  .fail
    call nvme_cmd_clear
    mov  dword [rel nvme_cmd + 0], (80 << 16) | NVME_OP_FLUSH     ; CID=80
    mov  dword [rel nvme_cmd + 4], 1                              ; NSID=1
    call nvme_io_exec
    test eax, eax
    jnz  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; nvme_shutdown_if_ready(RBX=BAR0) -> EAX 0 shut down / 1 not enabled / 2 timeout.
;   Normal shutdown (NVMe 1.4 §7.6.2): CC.SHN=01b, then CSTS.SHST=10b. Bounded to
;   ~5 s; never writes EN, so the caller's controller reset stays the owner.
nvme_shutdown_if_ready:
    cld
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push r12
    mov  eax, [rbx + 0x1C]
    and  eax, 1                             ; CSTS.RDY
    xor  eax, 1
    jnz  .out                               ; 1 = nothing enabled to shut down
    mov  eax, [rbx + 0x14]
    and  eax, ~(3 << 14)
    or   eax, (1 << 14)                     ; CC.SHN = 01b normal shutdown
    mov  [rbx + 0x14], eax
    mov  r12d, 5000
.poll:
    mov  eax, [rbx + 0x1C]
    shr  eax, 2
    and  eax, 3
    cmp  eax, 2                             ; CSTS.SHST = 10b complete
    je   .done
    mov  edi, 1000
    call tsc_delay_us
    dec  r12d
    jnz  .poll
    mov  eax, 2
    jmp  .out
.done:
    xor  eax, eax
.out:
    pop  r12
    ret

; nvme_quiesce_for_reset() — terminal BSP-only decision, not a shutdown summary.
; EAX: 0 COMPLETE (actual Flush=0 AND shutdown=0), 1 INACTIVE (no original
; owned-controller state), 2 POLICY_REFUSED, 3 UNAVAILABLE (present degraded,
; unknown identity/activity/geometry), 4 FLUSH_FAILED, 5 SHUTDOWN_FAILED.
; Only 0/1 allow the platform's later irreversible transition. INACTIVE proves
; no controller owned by this backend; it does not assert physical PCI absence.
; A failed/refused Flush NEVER calls shutdown. The existing 34-qword per-call
; record retains separate attempted/raw-low32 results; attempt0/resultFFFFFFFF
; is missing, not a successful Flush. Class admission precedes all MMIO, and
; class-bound/poisoned/refused-geometry observer reads remain unavailable.
; Normal shutdown keeps its original bounded poll. Only actual shutdown0/2
; writes CC.SHN and marks the disk offline until its original reset re-arms it.
; Callee-saved registers and IF preserved; caller-saved registers clobbered.
nvme_quiesce_for_reset:
    cld
    ; BSP-only passive record for THIS call, never a stale prior controller.
    ; Qwords: present then the POWER NVMe device fields documented below.
    lea rdi,[rel nvme_quiesce_observation]
    xor eax,eax
    mov ecx,34
    rep stosq
    ; Separate passive lifetime snapshot, cleared even on pre-admission refusal.
    ; No original operand is sampled until its native predicate executes.
    lea rdi,[rel nvme_quiesce_lifetime]
    mov ecx,5
    rep stosq
    lea rdi,[rel nvme_quiesce_completion]
    mov ecx,8
    rep stosq
    mov byte [rel nvme_qc_scope],0
    mov eax,0xffffffff                   ; unavailable, distinct from success
    mov [rel nvme_quiesce_observation+152],rax
    mov [rel nvme_quiesce_observation+232],rax
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    mov eax,2                           ; bounded POLICY_REFUSED, never raw -1
    ret                                 ; no observer MMIO before class admission
.power_admitted:
    push rbx
    mov eax,3
    movzx edx,byte [rel nvme_present]
    cmp dl,0
    mov [rel nvme_quiesce_lifetime+8],rdx
    mov qword [rel nvme_quiesce_lifetime],1
    je .inactive
    movzx edx,byte [rel nvme_present]
    cmp dl,1
    mov [rel nvme_quiesce_lifetime+8],rdx
    jne .out                            ; malformed state cannot mean absence
    mov qword [rel nvme_quiesce_observation],1
    mov rax,[rel nvme_bar0]
    mov [rel nvme_quiesce_observation+16],rax
    mov eax,0xffffffff
    mov [rel nvme_quiesce_observation+8],rax
    xor ecx,ecx
    cmp byte [rel nvme_claim_legacy],0
    je .not_legacy
    or ecx,1
    mov eax,[rel nvme_busno]
    shl eax,8
    mov edx,[rel nvme_devno]
    shl edx,3
    or eax,edx
    or eax,[rel nvme_fn]
    mov [rel nvme_quiesce_observation+8],rax
.not_legacy:
    cmp byte [rel nvme_vmd_child],0
    je .owner_done
    or ecx,2
    mov eax,0xffffffff                   ; child physical BDF is not available
    mov [rel nvme_quiesce_observation+8],rax
.owner_done:
    mov eax,ecx
    mov [rel nvme_quiesce_observation+24],rax
    mov qword [rel nvme_quiesce_observation+32],1
    ; The existing backend selects namespace1 for the actual NVM Flush.
    mov eax,[rel nvme_sector_size]
    mov [rel nvme_quiesce_observation+40],rax
    mov eax,[rel nvme_health]
    mov [rel nvme_quiesce_observation+48],rax
    movzx eax,byte [rel nvme_io_poisoned]
    mov [rel nvme_quiesce_observation+56],rax
    mov [rel nvme_quiesce_observation+216],rax
    mov [rel nvme_quiesce_observation+264],rax
    movzx eax,byte [rel nvme_io_pending]
    mov [rel nvme_quiesce_observation+64],rax
    movzx eax,byte [rel nvme_admin_pending]
    mov [rel nvme_quiesce_observation+72],rax
    movzx eax,word [rel nvme_iosq_tail]
    mov [rel nvme_quiesce_observation+80],rax
    movzx eax,word [rel nvme_io_sqhd]
    mov [rel nvme_quiesce_observation+88],rax
    movzx eax,word [rel nvme_asq_tail]
    mov [rel nvme_quiesce_observation+96],rax
    movzx eax,word [rel nvme_admin_sqhd]
    mov [rel nvme_quiesce_observation+104],rax
    movzx eax,word [rel nvme_io_cid]
    mov [rel nvme_quiesce_observation+112],rax
    mov eax,3
    cmp dword [rel nvme_health],HEALTH_OK
    jne .out
    mov rbx,[rel nvme_bar0]
    test rbx,rbx
    jz .out
    ; Refuse existing work or unusable ownership before staging any command or
    ; touching observer MMIO. No draining, replay, reset or admission bypass.
    call .ready
    test eax,eax
    jnz .unavailable
    ; Read-only ownership/activity MMIO is unavailable for a class-bound,
    ; poisoned or refused-geometry device. Do not call/bypass its power gate.
    cmp qword [rel nvme_power_gate],0
    jne .before_done
    cmp byte [rel nvme_io_poisoned],0
    jne .before_done
    cmp dword [rel nvme_sector_size],512
    jne .before_done
    mov qword [rel nvme_quiesce_observation+120],1
    or qword [rel nvme_quiesce_observation+24],4
    mov rax,[rel nvme_asq]
    test rax,rax
    jz .acq_owner
    cmp rax,[rbx+0x28]                   ; live ASQ full64-bit equality
    jne .acq_owner
    or qword [rel nvme_quiesce_observation+24],8
.acq_owner:
    mov rax,[rel nvme_acq]
    test rax,rax
    jz .registers
    cmp rax,[rbx+0x30]                   ; live ACQ full64-bit equality
    jne .registers
    or qword [rel nvme_quiesce_observation+24],16
.registers:
    mov eax,[rbx+0x14]
    mov [rel nvme_quiesce_observation+128],rax
    mov eax,[rbx+0x1c]
    mov [rel nvme_quiesce_observation+136],rax
    ; These original live admin-queue comparisons are authority, not just
    ; diagnostic flags. A foreign queue must not receive our Flush/shutdown.
    mov eax,[rel nvme_quiesce_observation+24]
    and eax,24
    cmp eax,24
    jne .unavailable
    test dword [rel nvme_quiesce_observation+128],1 ; CC.EN
    jz .unavailable
    mov eax,[rel nvme_quiesce_observation+136]
    and eax,3                           ; CSTS.RDY=1 and CFS=0
    cmp eax,1
    jne .unavailable
.before_done:
    mov qword [rel nvme_quiesce_observation+144],1
    lea rdi,[rel nvme_devs]
    mov byte [rel nvme_qc_scope],1      ; bracket only this original Flush
    call nvme_op_flush                  ; original bounded call/gates unchanged
    mov byte [rel nvme_qc_scope],0      ; preserve actual return and flags
    push rax                            ; test FULL actual return after snapshots
    mov eax,eax                         ; preserve actual low32 return, -1 included
    mov [rel nvme_quiesce_observation+152],rax
    movzx eax,byte [rel nvme_io_pending]
    mov [rel nvme_quiesce_observation+160],rax
    movzx eax,byte [rel nvme_admin_pending]
    mov [rel nvme_quiesce_observation+168],rax
    movzx eax,word [rel nvme_iosq_tail]
    mov [rel nvme_quiesce_observation+176],rax
    movzx eax,word [rel nvme_io_sqhd]
    mov [rel nvme_quiesce_observation+184],rax
    movzx eax,word [rel nvme_asq_tail]
    mov [rel nvme_quiesce_observation+192],rax
    movzx eax,word [rel nvme_admin_sqhd]
    mov [rel nvme_quiesce_observation+200],rax
    movzx eax,word [rel nvme_io_cid]
    mov [rel nvme_quiesce_observation+208],rax
    movzx eax,byte [rel nvme_io_poisoned]
    mov [rel nvme_quiesce_observation+216],rax
    mov [rel nvme_quiesce_observation+264],rax ; final poison even if Flush failed
    pop rax
    test rax,rax
    jnz .flush_failed                   ; never manufacture success from shutdown
    call .ready                         ; no new work/poison after actual Flush
    test eax,eax
    jnz .unavailable
    mov qword [rel nvme_quiesce_observation+224],1
    call nvme_shutdown_if_ready         ; distinct original outcome, not flush proof
    mov edx,eax
    mov [rel nvme_quiesce_observation+232],rdx
    push rax                            ; preserve actual status across reporting
    cmp qword [rel nvme_quiesce_observation+120],1
    jne .after_done
    cmp qword [rel nvme_power_gate],0
    jne .after_done
    cmp byte [rel nvme_io_poisoned],0
    jne .after_done                     ; no added MMIO after a timeout/foreign CQE
    mov qword [rel nvme_quiesce_observation+240],1
    mov eax,[rbx+0x14]
    mov [rel nvme_quiesce_observation+248],rax
    mov eax,[rbx+0x1c]
    mov [rel nvme_quiesce_observation+256],rax
.after_done:
    cmp qword [rsp],0
    je .offline
    cmp qword [rsp],2
    jne .report                         ; policy refusal/not-ready wrote no CC.SHN
.offline:
    mov  byte [rel nvme_io_poisoned], 1
    mov  dword [rel nvme_health], HEALTH_DEGRADED
    mov  dword [rel nvme_devs + dev.health], HEALTH_DEGRADED
    lea  rdi, [rel str_nvme_offline]
    call serial_string
.report:
    movzx eax,byte [rel nvme_io_poisoned]
    mov [rel nvme_quiesce_observation+264],rax
    lea rdi,[rel str_nvme_quiesced]
    call serial_string
    pop rax
    test rax,rax
    jz .out                             ; only shutdown0 after Flush0 is COMPLETE
    mov eax,5                           ; raw result is separately retained
    jmp .out
.flush_failed:
    mov eax,4
    jmp .out
.unavailable:
    mov eax,3
    jmp .out
.inactive:
    ; A clear present flag alone cannot hide failed bring-up or an old owner.
    ; These are the backend's ORIGINAL ownership/lifetime fields, not guest
    ; inventory or a synthetic device witness. No MMIO is needed or allowed.
    cmp byte [rel nvme_claim_legacy],0
    mov qword [rel nvme_quiesce_lifetime+16],0x1
    setne byte [rel nvme_quiesce_lifetime+24]
    jne .out
    cmp byte [rel nvme_vmd_child],0
    mov qword [rel nvme_quiesce_lifetime+16],0x3
    setne byte [rel nvme_quiesce_lifetime+25]
    jne .out
    cmp byte [rel nvme_io_poisoned],0
    mov qword [rel nvme_quiesce_lifetime+16],0x7
    setne byte [rel nvme_quiesce_lifetime+26]
    jne .out
    cmp byte [rel nvme_io_pending],0
    mov qword [rel nvme_quiesce_lifetime+16],0xf
    setne byte [rel nvme_quiesce_lifetime+27]
    jne .out
    cmp byte [rel nvme_admin_pending],0
    mov qword [rel nvme_quiesce_lifetime+16],0x1f
    setne byte [rel nvme_quiesce_lifetime+28]
    jne .out
    cmp qword [rel nvme_bar0],0
    mov qword [rel nvme_quiesce_lifetime+16],0x3f
    setne byte [rel nvme_quiesce_lifetime+29]
    jne .out
    cmp qword [rel nvme_vmd_cfg],0
    mov qword [rel nvme_quiesce_lifetime+16],0x7f
    setne byte [rel nvme_quiesce_lifetime+30]
    jne .out
    cmp qword [rel nvme_asq],0
    mov qword [rel nvme_quiesce_lifetime+16],0xff
    setne byte [rel nvme_quiesce_lifetime+31]
    jne .out
    cmp qword [rel nvme_acq],0
    mov qword [rel nvme_quiesce_lifetime+16],0x1ff
    setne byte [rel nvme_quiesce_lifetime+32]
    jne .out
    cmp qword [rel nvme_iosq],0
    mov qword [rel nvme_quiesce_lifetime+16],0x3ff
    setne byte [rel nvme_quiesce_lifetime+33]
    jne .out
    cmp qword [rel nvme_iocq],0
    mov qword [rel nvme_quiesce_lifetime+16],0x7ff
    setne byte [rel nvme_quiesce_lifetime+34]
    jne .out
    cmp qword [rel nvme_bounce],0
    mov qword [rel nvme_quiesce_lifetime+16],0xfff
    setne byte [rel nvme_quiesce_lifetime+35]
    jne .out
    cmp qword [rel nvme_idbuf],0
    mov qword [rel nvme_quiesce_lifetime+16],0x1fff
    setne byte [rel nvme_quiesce_lifetime+36]
    jne .out
    cmp word [rel nvme_io_cid],0
    mov qword [rel nvme_quiesce_lifetime+16],0x3fff
    setne byte [rel nvme_quiesce_lifetime+37]
    jne .out
    cmp word [rel nvme_admin_cid],0
    mov qword [rel nvme_quiesce_lifetime+16],0x7fff
    setne byte [rel nvme_quiesce_lifetime+38]
    jne .out
    mov eax,1                           ; INACTIVE, never Flush success
.out:
    pop rbx
    ret
.ready:
    ; Software-only guards apply to attached and unattached ownership alike.
    cmp byte [rel nvme_present],1
    jne .not_ready
    cmp dword [rel nvme_health],HEALTH_OK
    jne .not_ready
    cmp byte [rel nvme_io_poisoned],0
    jne .not_ready
    cmp byte [rel nvme_io_pending],0
    jne .not_ready
    cmp byte [rel nvme_admin_pending],0
    jne .not_ready
    cmp dword [rel nvme_sector_size],512
    jne .not_ready
    cmp rbx,[rel nvme_bar0]              ; exact original controller retained
    jne .not_ready
    lea rax,[rel nvme_ops]
    cmp [rel nvme_devs+dev.ops],rax
    jne .not_ready
    lea rax,[rel nvme_info]
    cmp [rel nvme_devs+dev.info],rax
    jne .not_ready
    cmp qword [rel nvme_asq],0
    je .not_ready
    cmp qword [rel nvme_acq],0
    je .not_ready
    cmp qword [rel nvme_iosq],0
    je .not_ready
    cmp qword [rel nvme_iocq],0
    je .not_ready
    mov rax,[rel nvme_asq]
    or rax,[rel nvme_acq]
    or rax,[rel nvme_iosq]
    or rax,[rel nvme_iocq]
    test eax,4095                       ; original DMA queue page alignment
    jnz .not_ready
    cmp word [rel nvme_asq_tail],NVME_ASIZE
    jae .not_ready
    cmp word [rel nvme_acq_head],NVME_ASIZE
    jae .not_ready
    cmp word [rel nvme_admin_sqhd],NVME_ASIZE
    jae .not_ready
    cmp word [rel nvme_iosq_tail],NVME_IOSIZE
    jae .not_ready
    cmp word [rel nvme_iocq_head],NVME_IOSIZE
    jae .not_ready
    cmp word [rel nvme_io_sqhd],NVME_IOSIZE
    jae .not_ready
    xor eax,eax
    ret
.not_ready:
    mov eax,3
    ret

; degraded op — every call -1 until a controller is brought up (no disk present).
nvme_blk_degraded:
    mov  eax, -1
    ret

; ============================================================================
; nvme_self_exercise — boot acceptance for the NVMe backend. Emits the contract
;   markers (blk.nvme.registered; blk.nvme.identify.ok; blk.nvme.rw.verified), or
;   the documented SKIP line when no controller is present. Called from blk_selftest
;   AFTER nvme_blk_create. Content-graded: read LBA0 + a write->flush->readback of
;   a deterministic pattern to a scratch LBA (clamped into the namespace), compared
;   via FNV (blk_cksum) — a latch cannot reproduce the round-trip.
; ============================================================================
nvme_self_exercise:
    cld
    sub rsp, 8
    xor eax, eax
    call nvme_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push rbx
    push r12
    cmp  byte [rel nvme_present], 0
    jne  .present
    ; --- no controller: documented skip (clean, never a false pass) --------
    lea  rdi, [rel str_nvme_skipped]
    call serial_string
    lea  rdi, [rel str_nvme_registered]
    call serial_string                      ; backend registered (degraded)
    jmp  .done

.present:
    lea  rdi, [rel str_nvme_registered]
    call serial_string                      ; marker: blk.nvme.registered

    ; --- IDENTIFY marker: report the real model -----------------------------
    lea  rdi, [rel str_nvme_id_pre]
    call serial_string
    lea  rdi, [rel nvme_model]
    call serial_string
    lea  rdi, [rel str_nvme_id_post]
    call serial_string                      ; marker: blk.nvme.identify.ok

    ; --- content-graded READ of LBA 0 (real bytes off the namespace) -------
    lea  rdi, [rel nvme_devs]
    xor  rsi, rsi                           ; lba 0
    mov  rdx, 1
    lea  rcx, [rel nvme_ex_buf]
    call nvme_op_read
    test rax, rax
    jnz  .rw_fail

    ; --- SAFETY GATE: the WRITE round-trip is DESTRUCTIVE. Only run it against
    ;   the QEMU emulated controller (throwaway vvfat namespace). On the REAL
    ;   Intel SSD (the Windows boot disk) a boot-time write to a scratch sector is
    ;   NOT safe unsupervised -> defer to the supervised UDP probe (1027b). Detect
    ;   QEMU by the identify model containing "QEMU". Bare metal gets the read-only
    ;   content-grade (blk.nvme.read.verified); blk.nvme.rw.verified is QEMU-only.
    call nvme_model_is_qemu
    test rax, rax
    jz   .read_only

    ; --- pick a scratch LBA within the namespace ---------------------------
    ;   default reserved sector (bare metal); clamp to last LBA if the namespace
    ;   is smaller (QEMU's tiny vvfat namespace) so the write is never OOB.
    mov  rax, NVME_SCRATCH_LBA
    mov  rcx, [rel nvme_lba_max]
    test rcx, rcx
    jz   .scratch_lo
    cmp  rax, rcx
    jb   .scratch_set
    mov  rax, rcx
    dec  rax
    jmp  .scratch_set
.scratch_lo:
    mov  rax, 8
.scratch_set:
    mov  [rel nvme_scratch_rt], rax
    ; storage-access gate (ROB-03): implicit self-test write — QEMU test scratch only.
    lea  rdi, [rel nvme_devs]
    mov  rsi, rax
    mov  edx, 1
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_nvme_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .rw_refused

    ; --- content-graded WRITE round-trip: pattern B -> scratch -> flush ->
    ;     read back -> FNV must equal FNV(B) -------------------------------
    lea  rdi, [rel nvme_ex_buf]
    mov  ecx, 4096 / 8
    xor  eax, eax
    cld
    rep  stosq                              ; deterministic remainder for 4KiB
    lea  rdi, [rel nvme_ex_buf]
    call blk_fill_pattern_b                 ; deterministic 512B pattern (shared w/ blk core)
    lea  rdi, [rel nvme_ex_buf]
    mov  esi, [rel nvme_sector_size]
    call blk_cksum
    mov  r12, rax                           ; expected FNV(pattern B)

    lea  rdi, [rel nvme_devs]
    mov  rsi, [rel nvme_scratch_rt]
    mov  rdx, 1
    lea  rcx, [rel nvme_ex_buf]
    call storage_access_write_admitted      ; SEC-S6: a direct driver write is admitted like blk_write
    test rax, rax
    jnz  .rw_refused
    call nvme_op_write
    test rax, rax
    jnz  .rw_fail
    lea  rdi, [rel nvme_devs]
    call nvme_op_flush
    test rax, rax
    jnz  .rw_fail
    lea  rdi, [rel nvme_devs]
    mov  rsi, [rel nvme_scratch_rt]
    mov  rdx, 1
    lea  rcx, [rel nvme_ex_buf2]
    call nvme_op_read
    test rax, rax
    jnz  .rw_fail
    lea  rdi, [rel nvme_ex_buf2]
    mov  esi, [rel nvme_sector_size]
    call blk_cksum
    cmp  rax, r12
    jne  .rw_fail
    lea  rdi, [rel str_nvme_rw_pre]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_nvme_rw_post]
    call serial_string                      ; marker: blk.nvme.rw.verified
    jmp  .done
.rw_refused:
    lea  rdi, [rel str_nvme_rw_refused]
    call serial_string                      ; blk.nvme.rw.skipped.storage_access
.read_only:
    ; bare metal (real Intel SSD): read-only content-grade; write round-trip is a
    ; supervised bare-metal step (1027b), never an unsupervised boot-time disk write.
    lea  rdi, [rel str_nvme_ro]
    call serial_string                      ; blk.nvme.read.verified (write deferred)
    jmp  .done
.rw_fail:
    lea  rdi, [rel str_nvme_rw_bad]
    call serial_string
.done:
    pop  r12
    pop  rbx
    ret

; nvme_model_is_qemu() -> RAX = 1 if nvme_model contains "QEMU", else 0.
;   clobbers RAX,RCX,RDX,RSI.
nvme_model_is_qemu:
    lea  rsi, [rel nvme_model]
    xor  ecx, ecx
.scan:
    cmp  ecx, 45                            ; model buf is 48 bytes; stop before overrun
    jae  .no
    mov  al, [rsi + rcx]
    test al, al
    jz   .no
    cmp  al, 'Q'
    jne  .next
    cmp  byte [rsi + rcx + 1], 'E'
    jne  .next
    cmp  byte [rsi + rcx + 2], 'M'
    jne  .next
    cmp  byte [rsi + rcx + 3], 'U'
    jne  .next
    mov  eax, 1
    ret
.next:
    inc  ecx
    jmp  .scan
.no:
    xor  eax, eax
    ret

; ---- nvme data (in-image writable; migrates to BSS under full W^X) -----------
NVME_SCRATCH_LBA equ 0x00A00000            ; reserved scratch sector (bare-metal default)

; Bounded RAM-only observation, no new Identify or disk operation.
; EDI=CNS1(controller/NSID0) or CNS0(namespace/NSID1), ESI=chunk0..15,
; RDX=caller-owned320-byte destination. EAX0/-1; refusal writes nothing.
nvme_identify_chunk:
    cmp qword [rel nvme_power_gate], 0
    jne .unavailable
    cmp edi, 1
    ja .unavailable
    cmp esi, 15
    ja .unavailable
    test rdx, rdx
    jz .unavailable
    mov r9d, 2
    lea r10, [rel nvme_identify_namespace_page]
    test edi, edi
    jz .selected
    mov r9d, 1
    lea r10, [rel nvme_identify_controller_page]
.selected:
    test [rel nvme_identify_pages_valid], r9d
    jz .unavailable
    mov r11d, edi
    mov r8d, esi
    shl r8d, 8
    add r10, r8
    cld
    mov rdi, rdx
    xor eax, eax
    mov ecx, 320 / 8
    rep stosq
    mov dword [rdx], 'NVID'
    mov byte [rdx+4], '1'
    mov dword [rdx+8], 1
    mov dword [rdx+12], 320
    mov rax, [rel nvme_identify_pages_epoch]
    mov [rdx+16], rax
    mov [rdx+24], r11d
    xor r11d, 1
    mov [rdx+28], r11d
    mov [rdx+32], r8d
    mov dword [rdx+36], 256
    mov eax, [rel nvme_identify_pages_bdf]
    mov [rdx+40], eax
    mov eax, [rel nvme_identify_pages_vmd]
    mov [rdx+44], eax
    mov dword [rdx+48], 1
    mov rsi, r10
    lea rdi, [rdx+64]
    mov ecx, 256 / 8
    rep movsq
    xor eax, eax
    ret
.unavailable:
    mov eax, -1
    ret


%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_dev_blk_nvme_0 0
nvme_last_st:     dw 0                       ; last CQ completion status (0xFFFF = poll timeout)
align 8
nvme_power_gate: dq 0
nvme_power_command_gate: dq 0
nvme_vmd_cfg: dq 0
nvme_io_pending: db 0
nvme_admin_pending: db 0
nvme_admin_cid: dw 0
nvme_dma4_cid: dw 0xE000             ; never reset/reused within this boot
nvme_dma4_token: db 0
align 8
nvme_dma4_page: dq 0
nvme_io_sqhd: dw 0
nvme_admin_sqhd: dw 0
nvme_last_cqe_sqhd: dw 0
align 8
nvme_bar0:        dq 0
nvme_cap:         dq 0
nvme_stride:      dd 4
nvme_claim_legacy: db 0                     ; 1 = nvme_busno/devno/fn name the controller taken
align 4
nvme_busno:       dd 0
nvme_devno:       dd 0
nvme_fn:          dd 0
nvme_health:      dd 0
nvme_io_cid:      dw 0                       ; last I/O command identifier (rolling 1..0xFFFE)
nvme_last_cqe_cid: dw 0                      ; CID of the last consumed CQE
nvme_last_cqe_sqid: dw 0                     ; SQ id of the last consumed CQE
nvme_write_token: db 0                       ; SEC-S6: set only by nvme_op_write, consumed by nvme_io_admitted
nvme_io_poisoned: db 0                       ; 1 = timeout/foreign completion: I/O refused until reset
nvme_present:     db 0
nvme_vmd_child:   db 0                    ; 1 = BAR0 came from the Intel VMD child domain
nvme_sector_size: dd 0
nvme_physical_size: dd 0
nvme_identify_fields:
nvme_identify_valid: dd 0
nvme_identify_flbas: dd 0
nvme_identify_lbaf: dd 0
nvme_identify_nsfeat: dd 0
nvme_identify_npwg: dd 0
nvme_identify_nows: dd 0
nvme_identify_nawupf: dd 0
nvme_lba_max:     dq 0
nvme_scratch_rt:  dq 0

nvme_asq:         dq 0
nvme_acq:         dq 0
nvme_iosq:        dq 0
nvme_iocq:        dq 0
nvme_bounce:      dq 0
nvme_idbuf:       dq 0

nvme_asq_tail:    dw 0
nvme_acq_head:    dw 0
nvme_acq_phase:   db 1
nvme_iosq_tail:   dw 0
nvme_iocq_head:   dw 0
nvme_iocq_phase:  db 1

align 8
times 32 db 0                  ; nvme_cmd..nvme_ex_buf2 moved to WDATA_dev_blk_nvme_0_bss1: keeps the labels below at their offset mod 64

str_nvme_name:       db "nvme0", 0
str_nvme_sa_caller: db "nvme_self_exercise", 0
str_nvme_rw_refused: db "[PAOS64] P3 blk: NVMe write round-trip SKIPPED: storage access not permitted [blk.nvme.rw.skipped.storage_access]", 13, 10, 0
str_nvme_registered: db "[PAOS64] P3 blk: NVMe backend registered via blk_ops [blk.nvme.registered]", 13, 10, 0
str_nvme_skipped:    db "[PAOS64] P3 blk: blk.nvme: skipped (no disk)", 13, 10, 0
str_nvme_bar_refused: db "[PAOS64] P3 blk: NVMe BAR0 above identity map and RAM reaches the 9 GiB window: remap refused, device untouched [blk.nvme.bar.remap_refused]", 13, 10, 0
str_nvme_id_pre:     db "[PAOS64] P3 blk: NVMe identify model=", 0
str_nvme_id_post:    db " [blk.nvme.identify.ok]", 13, 10, 0
str_nvme_rw_pre:     db "[PAOS64] P3 blk: NVMe write->flush->readback PASS cksum=", 0
str_nvme_rw_post:    db " [blk.nvme.rw.verified]", 13, 10, 0
str_nvme_rw_bad:     db "[PAOS64] P3 blk: NVMe rw round-trip FAIL", 13, 10, 0
str_nvme_poisoned:   db "[PAOS64] blk: NVMe I/O completion timed out or did not match its command; I/O refused until controller reset [blk.nvme.poisoned]", 13, 10, 0
str_nvme_offline:    db "[PAOS64] blk: NVMe shut down (CC.SHN): I/O refused until the controller is reset [blk.nvme.offline]", 13, 10, 0
str_nvme_quiesced:   db "[PAOS64] blk: NVMe flush/shutdown attempted; separate outcomes required [blk.nvme.quiesced]", 13, 10, 0
str_nvme_ro:         db "[PAOS64] P3 blk: NVMe read-only content-grade PASS (write round-trip deferred: real disk, supervised 1027b) [blk.nvme.read.verified]", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_dev_blk_nvme_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_dev_blk_nvme_0_bss1 0
alignb 8
nvme_cmd:         resb NVME_SQ_ESZ          ; 64-byte command staging
nvme_devs:        resb dev_size
nvme_ops:         resb blk_ops_size
nvme_info:        resb blk_info_size
nvme_model:       resb 48
nvme_serial:      resb 24           ; Task3470: NVMe controller serial (bytes 4..23, NUL-term)
nvme_ex_buf:      resb 4096
nvme_ex_buf2:     resb 4096
%endmacro
WDATA_BSS_DEFER WDATA_dev_blk_nvme_0_bss1

; Passive per-call P4 observation only. present +33 qwords; original state
; offsets above stay unchanged. Queue activity is software state, ASQ/ACQ
; equality is a live admin-queue ownership witness, not complete I/O authority.
; bdf, bar, owner, nsid, sector, health, poison_before, io_before, admin_before, sqt_before, sqh_before, aqt_before, aqh_before, cid_before, before_valid, cc_before, csts_before, flush_attempt, flush_result, io_after, admin_after, sqt_after, sqh_after, aqt_after, aqh_after, cid_after, poison_after_flush, shutdown_attempt, shutdown_result, after_valid, cc_after, csts_after, poison_after
%macro WDATA_dev_blk_nvme_quiesce 0
alignb 8
nvme_quiesce_observation: resq 34
; Separate 40B ABI: present_available, actual present operand, observed mask,
; 15 byte nonzero results in original .inactive predicate order, one pad byte.
; SETNE and MOV preserve each original CMP/JNE flags; unobserved bytes are not
; evidence of zero operands. No address/inventory/MMIO/lifetime authority.
nvme_quiesce_lifetime: resq 5
; Separate 64B: submitted, expected CID/SQHD, observed, CQE CID/SQID/SQHD/status.
; Zero with submitted/observed=0 is unavailable, never a completion witness.
nvme_quiesce_completion: resq 8
nvme_qc_scope: resb 1                  ; private passive capture scope, no authority
%endmacro
WDATA_BSS_DEFER WDATA_dev_blk_nvme_quiesce

; ROOT 121997 / rc-review 122056: storage-class sightings of this create's PCI
; scan, recorded before any driver gate (bit 0 NVM 01:08, bit 1 RAID 01:04, a
; possible VMD root). Observation only: it never selects, claims or enables a
; function; it only keeps a refused or unusable controller from reading as absent.
%macro WDATA_dev_blk_nvme_seam 0
nvme_class_seen: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_dev_blk_nvme_seam

%macro WDATA_dev_blk_nvme_identify_pages 0
alignb 8
nvme_identify_pages_epoch: resq 1
nvme_identify_pages_valid: resd 1
nvme_identify_pages_bdf: resd 1
nvme_identify_pages_vmd: resd 1
nvme_identify_controller_page: resb 4096
nvme_identify_namespace_page: resb 4096
%endmacro
WDATA_BSS_DEFER WDATA_dev_blk_nvme_identify_pages
