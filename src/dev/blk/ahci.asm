;; MODULE dev/blk/ahci
;; LAYER 3
;; EXPORTS ahci_blk_create, ahci_terminal_quiesce, ahci_terminal_observations, ahci_vmd_terminal_observations, ahci_flush_for_reset, ahci_flush_observations, ahci_inactive_observations, ahci_table_observations, ahci_self_exercise, ahci_find_identity, ahci_bind_name_identity, ahci_dev_identity_matches, ahci_identity_absent, ahci_scan_summary, ahci_power_gate, ahci_power_command_gate, ahci_issue_cooperative, ahci_identify_dma_to, ahci_vmd_owner_snapshot, ahci_empty_owner_get, ahci_empty_owner_table, ahci_empty_owner_generation, ahci_boh_owner_acquire, ahci_boh_observations, ahci_boh_terminal_observations, ahci_vmd_boh_initial_root, ahci_vmd_boh_initial_child
;; IMPORTS bus/hal, core/time, boot/native_driver_gate, fs/blockdev, fs/storage_access, bus/pci, core/dma, boot/serial, dev/blk/vmd, bus/pci_claim, boot/boot_v2_handoff
;; CAPS mmio dma
;; OWNER saga:storage
;; CONTEXT: bsp_only  (SEC-S6: the one-shot ahci_write_token is a global byte, sound only while one CPU drives the HBA)
%include "core/abi/pci_claim.inc" ; RCQ-29 hardware report: bind outcome ids/states
; ============================================================================
; dev/blk/ahci.asm — the AHCI/SATA block backend (1028). PORT of the proven
; monolith AHCI driver (drivers/ahci/source/ahci_{init,identify,rw_common}.asm,
; block-I/O first-stable v0.4.45 on the Lenovo M720s Samsung SSD 870 QVO) into
; the rework's blk_ops class seam (fs/blockdev.asm, 1007), ADDITIVELY:
;   * the proven HBA sequence is preserved verbatim where it was hard-won —
;     DET==3 port scan off PI, stop-engine-then-spin CR|FR clear, one 4 KiB
;     page per port (CL @+0x000 / FIS @+0x400 / CT0 @+0x500), CAP.S64A guard,
;     FRE-before-ST (AHCI 1.3 §10.1.2), W1C of PxIS+PxSERR before issue,
;     slot-0-only synchronous I/O with pause-spin + TFES check, IDENTIFY
;     byte-swap + printable-filter model parse, LBA48 count @ words 100..103;
;   * the port ADDS (a) GHC.AE set-if-clear (spec §10.1.2 step 1 — the
;     monolith relied on BIOS leaving AE set; QEMU's secondary ich9-ahci that
;     OVMF never booted from can arrive with AE=0), (b) the blk_ops
;     (self,lba,count,buf) signature via a page-aligned DMA bounce buffer,
;     (c) degrade-never-crash: no HBA / no disk port -> the backend registers
;     HEALTH_DEGRADED and boot prints 'blk.ahci: skipped (no disk)'.
;   * every non-ATAPI DET==3 port is brought up through the same proven
;     sequence and registered as a distinct struct dev handle; the bounded
;     eight-disk table matches the proven Classic driver's cache bound.
;
; Read/write/flush capability comes from IDENTIFY and the backend, independently
; of the boot self-test. Implicit destructive testing additionally needs a
; proven PaOS-owned extent: a QEMU model or an absent GPT is not ownership.
; With no owned raw scratch extent minted by storage_access_classify today,
; boot testing is read-only. Supervised raw writes keep their existing gates.
;
; SELECTION POLICY (same as nvme, 1027 gotcha #3): register at PRIO_DOMAIN so
; the ramblk reference stays the SELECTED boot scratch default; a real disk
; winning blk_select() would break the 1065/1007/1008 scratch/wedge consumers.
; Promotion is the DEVICE_SLOT selection-policy saga.
;
; The `call blk_register` is the ONE sanctioned L3->L4 upward edge (DRIVER_MODEL §5).
; ============================================================================

; ---- AHCI constants (ported from the monolith) -------------------------------
AHCI_REG_CAP     equ 0x00      ; Host Capabilities
AHCI_REG_GHC     equ 0x04      ; Global HBA Control (bit31 = AE)
AHCI_REG_PI      equ 0x0C      ; Ports Implemented
AHCI_PORT_BASE   equ 0x100     ; Port 0 register base; +0x80 per port
AHCI_PORT_CLB    equ 0x00      ; Command List Base (low 32)
AHCI_PORT_CLBU   equ 0x04      ; Command List Base Upper
AHCI_PORT_FB     equ 0x08      ; FIS Base (low 32)
AHCI_PORT_FBU    equ 0x0C      ; FIS Base Upper
AHCI_PORT_IS     equ 0x10      ; Interrupt Status (TFES at bit 30)
AHCI_PORT_CMD    equ 0x18      ; Command + Status (PxCMD)
AHCI_PORT_TFD    equ 0x20      ; Task File Data
AHCI_PORT_SIG    equ 0x24      ; Signature
AHCI_PORT_SSTS   equ 0x28      ; SATA Status (DET in bits 3:0)
AHCI_PORT_SERR   equ 0x30      ; SATA Error
AHCI_PORT_CI     equ 0x38      ; Command Issue
AHCI_PXCMD_ST    equ 0x00000001
AHCI_PXCMD_SUD   equ 0x00000002      ; spin-up device (staggered spin-up)
AHCI_PXCMD_CLO   equ 0x00000008
AHCI_PXCMD_FRE   equ 0x00000010
AHCI_PXCMD_FR    equ 0x00004000
AHCI_PXCMD_CR    equ 0x00008000
AHCI_PXIS_TFES   equ 0x40000000
AHCI_CAP_S64A    equ 0x80000000
AHCI_CAP_SCLO    equ 0x01000000      ; supports command list override
AHCI_CAP_SSS     equ 0x08000000      ; supports staggered spin-up
AHCI_TFD_BSY_DRQ equ 0x88
AHCI_GHC_AE      equ 0x80000000
AHCI_SIG_ATAPI   equ 0xEB140101
AHCI_ATA_IDENTIFY equ 0xEC     ; IDENTIFY DEVICE
AHCI_ATA_READ    equ 0x25      ; READ DMA EXT
AHCI_ATA_WRITE   equ 0x35      ; WRITE DMA EXT
AHCI_ATA_FLUSH   equ 0xEA      ; FLUSH CACHE EXT
AHCI_STOP_SPIN   equ 1000000   ; engine-stop CR|FR spin (proven monolith bound)
AHCI_CMD_SPIN    equ 10000000  ; per-command CI spin (proven monolith bound)
AHCI_MAX_DISKS   equ 8          ; proven Classic port-table bound
AHCI_MAX_XFER    equ 8          ; sectors per command: the 4 KiB DMA bounce / 512
; ahci_enum_uncertain bits (report-only): why the boot scan cannot prove that a
; disk identity is absent. Any bit keeps ahci_identity_absent at "not proven".
AHCI_UNC_PORT    equ 0x01       ; DET==3 disk port whose bring-up/IDENTIFY failed
AHCI_UNC_TRUNC   equ 0x02       ; DET==3 disk port beyond AHCI_MAX_DISKS
AHCI_UNC_ATAPI   equ 0x04       ; DET==3 port skipped as ATAPI (unsupported)
AHCI_UNC_LINK    equ 0x08       ; DET not 0/3, or DET 0 on a staggered port not spun up
AHCI_UNC_INIT    equ 0x10       ; HBA reports no implemented port
AHCI_UNC_CTRL    equ 0x20       ; a legacy-bus storage function this scan did not take
AHCI_UNC_VMD     equ 0x40       ; an Intel VMD domain exists (hidden children)
AHCI_SCAN_SUMMARY_MAX equ 128   ; ahci_scan_summary bytes (longest rendering 108 + NUL)

; Optional class lifecycle admission. Preserve every input register: the hook
; observes the original slot/opcode/buffer for cooperative command capabilities.
; EAX=0 ordinary / 1 internal cooperative command. Only RAX is returned.
ahci_power_check:
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
    mov rax, [rel ahci_power_gate]
    test rax, rax
    jz .unattached
    call rax
    jmp .out
.command:
    mov rax, [rel ahci_power_command_gate]
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

; ============================================================================
; ahci_blk_create() -> RAX = REG_OK/REG_REJECT. Detect + (if a disk port is
;   present) bring up the HBA port, IDENTIFY, then build the blk_ops vtable at
;   RUNTIME (lea->mov: the PE ImageBase is not applied to a baked `dq symbol`)
;   and register. No HBA / no disk -> register HEALTH_DEGRADED (a seam member
;   selection skips), so the box degrades to ramblk without a crash.
; ============================================================================
ahci_blk_create:
    cld
    mov  byte  [rel ahci_enum_done], 0      ; report-only: set once the scan below ends
    mov  byte  [rel ahci_enum_uncertain], 0
    mov  dword [rel ahci_storage_fns], 0
    mov  dword [rel ahci_scan_sud], 0       ; report-only per-port scan record (BOOTLOG FULL)
    lea  rdi, [rel ahci_scan_det]
    xor  eax, eax
    mov  ecx, 32 / 8
    rep  stosq
    call ahci_scan_summarize                ; done:0 until a scan below ends
    cmp qword [rel ahci_power_gate], 0
    je .power_unbound
    mov rax, -1
    ret
.power_unbound:
    sub rsp, 8
    xor eax, eax
    call ahci_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  byte  [rel ahci_present], 0
    mov  dword [rel ahci_port_count], 0
    mov  dword [rel ahci_port], 0xFFFFFFFF
    mov  qword [rel ahci_lba_max], 0
    mov  byte  [rel ahci_model], 0
    mov  byte  [rel ahci_serial], 0

    ; One shared vtable; every registered dev carries its logical slot in
    ; dev.priv, and every I/O resolves that slot to the proven per-port tables.
    lea  rbx, [rel ahci_ops]
    lea  rax, [rel ahci_op_identify]
    mov  [rbx + blk_ops.identify], rax
    lea  rax, [rel ahci_op_read]
    mov  [rbx + blk_ops.read], rax
    lea  rax, [rel ahci_op_write]
    mov  [rbx + blk_ops.write], rax
    lea  rax, [rel ahci_op_flush]
    mov  [rbx + blk_ops.flush], rax

    ; --- detect an AHCI HBA on the PCI bus (class 0x01/0x06 progIF 0x01) ---
    call ahci_vmd_owner_reset              ; original admitted selection lifetime
    mov dword [rel ahci_terminal_selected_id],0 ; passive original selected identity
    mov  byte  [rel ahci_vmd_child], 0
    mov  byte  [rel ahci_claim_legacy], 0
    mov  qword [rel ahci_bar5], 0
    lea  rdi, [rel ahci_detect_cb]
    call pci_scan_with_filter               ; callback records ABAR + BDF on match
    ; Report-only: the legacy bus may hold exactly the one taken HBA (or none).
    xor  eax, eax
    cmp  qword [rel ahci_bar5], 0
    setne al
    cmp  [rel ahci_storage_fns], eax
    je   .fns_known
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_CTRL
.fns_known:
    cmp  byte [rel vmd_root_count], 0
    je   .vmd_known
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_VMD
.vmd_known:
    mov  rax, [rel ahci_bar5]
    test rax, rax
    jnz  .enable_cmd
    ; --- no HBA on the legacy bus: an AHCI mapped under Intel VMD lives in the
    ;     VMD child domain (dev/blk/vmd already set its Memory Space + Bus
    ;     Master through the child ECAM; the ABAR is identity-reachable) ---
    mov  edi, 0x010601
    call vmd_find_child
    test rax, rax
    jz   .no_hba
    mov  [rel ahci_bar5], rax
    mov  byte [rel ahci_vmd_child], 1
    call ahci_vmd_owner_capture            ; retain original RAX BAR/RDX child cfg
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_VMD
    jmp  .hba_ready
.enable_cmd:
    mov  byte [rel ahci_claim_legacy], 1     ; a legacy-bus HBA matched (hardware report)

    ; --- enable Memory Space + Bus Master in the PCI command register ------
    mov  edi, [rel ahci_busno]
    mov  esi, [rel ahci_devno]
    mov  edx, [rel ahci_fn]
    mov  ecx, 0x04
    call pci_cfg_read32                     ; EAX = Status<<16 | Command
    or   ax, 0x0006                         ; bit1 Memory Space + bit2 Bus Master
    mov  r8d, eax
    mov  edi, [rel ahci_busno]
    mov  esi, [rel ahci_devno]
    mov  edx, [rel ahci_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
.hba_ready:

    call ahci_boh_owner_acquire             ; original selected HBA, before GHC/port effects
    test eax,eax
    jns .firmware_owned
    or byte [rel ahci_enum_uncertain],AHCI_UNC_INIT
    mov byte [rel ahci_enum_done],1
    call ahci_scan_summarize
    jmp .degraded                          ; retain original degraded registry behavior
.firmware_owned:

    mov  rbx, [rel ahci_bar5]               ; rbx = ABAR (identity-mapped MMIO)

    ; --- GHC.AE set-if-clear (spec step 1; BIOS usually set it already) -----
    mov  eax, [rbx + AHCI_REG_GHC]
    test eax, AHCI_GHC_AE
    jnz  .ae_ok
    or   eax, AHCI_GHC_AE
    mov  [rbx + AHCI_REG_GHC], eax
.ae_ok:
    mov  eax, [rbx + AHCI_REG_CAP]
    mov  [rel ahci_cap], eax
    mov  eax, [rbx + AHCI_REG_PI]
    mov  [rel ahci_pi], eax
    test eax, eax
    jnz  .pi_known
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_INIT
.pi_known:

    ; --- port scan: register every implemented DET==3 non-ATAPI disk --------
    ; This ports Classic's proven multi-port tables.  Logical registration
    ; order remains physical-port order, preserving the historical first-disk
    ; fallback while making later disks visible through struct dev handles.
    mov  r12d, [rel ahci_pi]
    xor  r13d, r13d                         ; port idx 0..31
    xor  r14d, r14d                         ; healthy logical disk slot
.pscan:
    cmp  r13d, 32
    jge  .pscan_done
    bt   r12d, r13d
    jnc  .pnext
    mov  edi, r13d
    shl  edi, 7
    add  edi, AHCI_PORT_BASE
    mov  esi, [rbx + rdi + AHCI_PORT_SSTS]
    and  esi, 0x0F
    lea  rax, [rel ahci_scan_det]           ; report-only: this port's DET and SUD as scanned
    mov  [rax + r13], sil
    test dword [rbx + rdi + AHCI_PORT_CMD], AHCI_PXCMD_SUD
    jz   .sud_recorded
    bts  dword [rel ahci_scan_sud], r13d
.sud_recorded:
    cmp  esi, 3                             ; DET=3: device present + PHY up
    jne  .not_up
    mov  eax, [rbx + rdi + AHCI_PORT_SIG]
    cmp  eax, AHCI_SIG_ATAPI                ; skip ATAPI (DVD) ports
    jne  .not_atapi
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_ATAPI
    lea  rdi, [rel str_ahci_atapi_skip]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    call serial_newline
    jmp  .pnext
.not_atapi:
    cmp  r14d, AHCI_MAX_DISKS
    jae  .truncated                         ; bounded like the proven Classic tables
    mov  edi, r13d                          ; physical AHCI port
    mov  esi, r14d                          ; logical registered-disk slot
    mov  rdx, rbx                           ; ABAR
    call ahci_create_port
    test eax, eax
    jnz  .port_failed
    inc  r14d
    jmp  .pnext
; Report-only scan accounting; every path continues the unchanged scan.
.port_failed:
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_PORT
    jmp  .pnext
.truncated:
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_TRUNC
    jmp  .pnext
.not_up:
    test esi, esi
    jnz  .link_uncertain                    ; PHY detected but not up, offline or unknown
    push rdi                              ; original physical CMD operand for SSS/SUD scan
    mov  edi, r13d
    call ahci_empty_owner_acquire          ; original initial post-EBS empty-port takeover
    pop  rdi
    test eax, eax
    jns  .empty_acquired
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_PORT
.empty_acquired:
    test dword [rel ahci_cap], AHCI_CAP_SSS
    jz   .pnext                             ; DET=0: no device
    test dword [rbx + rdi + AHCI_PORT_CMD], AHCI_PXCMD_SUD
    jnz  .pnext
.link_uncertain:
    or   byte [rel ahci_enum_uncertain], AHCI_UNC_LINK
.pnext:
    inc  r13d
    jmp  .pscan
.pscan_done:
    mov  byte [rel ahci_enum_done], 1
    call ahci_scan_summarize
    mov  [rel ahci_port_count], r14d
    test r14d, r14d
    jz   .degraded
    mov  byte [rel ahci_present], 1
    mov  r8d, PCI_CLAIM_BOUND
    call ahci_pci_claim
    xor  eax, eax
    jmp  .out

.no_hba:
    mov  byte [rel ahci_enum_done], 1       ; no HBA anywhere: the scan is complete
    call ahci_scan_summarize
.degraded:
    mov  r8d, PCI_CLAIM_FAILED               ; only if an HBA had matched
    call ahci_pci_claim
    ; Preserve the historical degraded ahci0 registry member when no disk was
    ; usable, so diagnostics and degrade-never-crash behavior remain intact.
    lea  rbx, [rel ahci_ops]
    lea  rax, [rel ahci_blk_degraded]
    mov  [rbx + blk_ops.identify], rax
    mov  [rbx + blk_ops.read], rax
    mov  [rbx + blk_ops.write], rax
    mov  [rbx + blk_ops.flush], rax
    lea  rbx, [rel ahci_info]
    lea  rax, [rel str_ahci_name]
    mov  [rbx + blk_info.name], rax
    mov  dword [rbx + blk_info.sector_size], 512
    mov  qword [rbx + blk_info.lba_max], 0
    mov  byte  [rbx + blk_info.dma_mask], 64
    mov  byte  [rbx + blk_info.removable], 0
    mov  dword [rbx + blk_info.flags], 0
    mov  dword [rbx + blk_info.unit], 0xFFFFFFFF

    lea  rbx, [rel ahci_dev]
    lea  rax, [rel ahci_ops]
    mov  [rbx + dev.ops], rax
    lea  rax, [rel ahci_info]
    mov  [rbx + dev.info], rax
    mov  qword [rbx + dev.priv], 0
    ; PRIO_DOMAIN (NOT native): ramblk must stay the blk_select() default — the
    ; boot scratch/wedge consumers assume the safe fake backend (1027 gotcha #3).
    mov  dword [rbx + dev.prio], PRIO_DOMAIN
    mov  dword [rbx + dev.health], HEALTH_DEGRADED
    mov  dword [rbx + dev.class], CLASS_BLOCK
    mov  dword [rbx + dev.flags], 0
    lea  rax, [rel str_ahci_name]
    mov  [rbx + dev.name], rax

    mov  rdi, rbx
    call blk_register
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ahci_create_port(EDI=physical port, ESI=logical slot, RDX=ABAR) -> 0/-1.
; The register/DMA ordering is the proven single-port sequence, parameterized
; over Classic's per-port tables and surfaced as one block-device handle.
ahci_create_port:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14, rdx
    lea  rbx, [rel ahci_port_present]
    mov  byte [rbx + r13], 0
    lea  rbx, [rel ahci_port_poisoned]
    mov  byte [rbx + r13], 0
    lea  rbx, [rel ahci_ports]
    mov  dword [rbx + r13*4], 0xFFFFFFFF
    lea  rbx, [rel ahci_lba_maxes]
    mov  qword [rbx + r13*8], 0
    imul eax, r13d, 41
    lea  rbx, [rel ahci_models]
    mov  byte [rbx + rax], 0
    imul eax, r13d, 21
    lea  rbx, [rel ahci_serials]
    mov  byte [rbx + rax], 0

    mov  eax, r12d
    shl  eax, 7
    add  eax, AHCI_PORT_BASE
    add  rax, r14
    lea  rbx, [rel ahci_pbases]
    mov  [rbx + r13*8], rax
    mov  rsi, rax

    mov  eax, [rsi + AHCI_PORT_CMD]
    and  eax, 0xFFFFFFEE
    mov  [rsi + AHCI_PORT_CMD], eax
    mov  edx, AHCI_STOP_SPIN
.stop_spin:
    mov  eax, [rsi + AHCI_PORT_CMD]
    test eax, AHCI_PXCMD_CR | AHCI_PXCMD_FR
    jz   .stopped
    pause
    dec  edx
    jnz  .stop_spin
    jmp  .fail
.stopped:
    mov  rdi, 4096
    call dma_alloc
    test rax, rax
    jz   .fail
    lea  rbx, [rel ahci_cls]
    mov  [rbx + r13*8], rax
    lea  rcx, [rax + 0x500]
    lea  rbx, [rel ahci_cts]
    mov  [rbx + r13*8], rcx
    mov  [rax + 0x08], ecx
    mov  rdx, rcx
    shr  rdx, 32
    mov  [rax + 0x0C], edx
    mov  rdi, 4096
    call dma_alloc
    test rax, rax
    jz   .fail
    lea  rbx, [rel ahci_idbufs]
    mov  [rbx + r13*8], rax
    mov  rdi, 4096
    call dma_alloc
    test rax, rax
    jz   .fail
    lea  rbx, [rel ahci_bounces]
    mov  [rbx + r13*8], rax

    mov  eax, [rel ahci_cap]
    test eax, AHCI_CAP_S64A
    jnz  .prog
    lea  rbx, [rel ahci_cls]
    mov  rax, [rbx + r13*8]
    shr  rax, 32
    test eax, eax
    jnz  .fail
.prog:
    lea  rbx, [rel ahci_pbases]
    mov  rsi, [rbx + r13*8]
    lea  rbx, [rel ahci_cls]
    mov  rax, [rbx + r13*8]
    mov  [rsi + AHCI_PORT_CLB], eax
    mov  rdx, rax
    shr  rdx, 32
    mov  [rsi + AHCI_PORT_CLBU], edx
    mov  rax, [rbx + r13*8]
    add  rax, 0x400
    mov  [rsi + AHCI_PORT_FB], eax
    mov  rdx, rax
    shr  rdx, 32
    mov  [rsi + AHCI_PORT_FBU], edx
    mov  eax, [rsi + AHCI_PORT_CMD]
    or   eax, AHCI_PXCMD_FRE
    mov  [rsi + AHCI_PORT_CMD], eax
    mov  eax, [rsi + AHCI_PORT_CMD]
    or   eax, AHCI_PXCMD_ST
    mov  [rsi + AHCI_PORT_CMD], eax

    mov  r10b, AHCI_ATA_IDENTIFY
    xor  r11b, r11b
    xor  esi, esi
    xor  edx, edx
    mov  r8d, 512
    lea  rbx, [rel ahci_idbufs]
    mov  rcx, [rbx + r13*8]
    mov  edi, r13d
    call ahci_issue
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    call ahci_parse_identify
    lea  rbx, [rel ahci_lba_maxes]
    cmp  qword [rbx + r13*8], 0
    je   .fail
    lea  rbx, [rel ahci_port_present]
    mov  byte [rbx + r13], 1
    lea  rbx, [rel ahci_ports]
    mov  [rbx + r13*4], r12d

    mov  eax, r13d
    imul rax, blk_info_size
    lea  rbx, [rel ahci_infos]
    add  rbx, rax
    mov  eax, r13d
    shl  eax, 3
    lea  r8, [rel ahci_names]
    add  r8, rax
    mov  dword [r8], 'ahci'
    mov  eax, r13d
    add  al, '0'
    mov  [r8 + 4], al
    mov  byte [r8 + 5], 0
    mov  [rbx + blk_info.name], r8
    mov  dword [rbx + blk_info.sector_size], 512
    lea  rdx, [rel ahci_lba_maxes]
    mov  rax, [rdx + r13*8]
    mov  [rbx + blk_info.lba_max], rax
    mov  byte [rbx + blk_info.dma_mask], 64
    mov  byte [rbx + blk_info.removable], 0
    mov  dword [rbx + blk_info.flags], 0
    mov  [rbx + blk_info.unit], r12d
    mov  edi, r13d
    call ahci_declare                       ; RCQ-05: geometry + BLKCAP only as IDENTIFY proves

    mov  eax, r13d
    imul rax, dev_size
    lea  r15, [rel ahci_devs]
    add  r15, rax
    lea  rax, [rel ahci_ops]
    mov  [r15 + dev.ops], rax
    mov  [r15 + dev.info], rbx
    mov  [r15 + dev.priv], r13
    mov  dword [r15 + dev.prio], PRIO_DOMAIN
    mov  dword [r15 + dev.health], HEALTH_OK
    mov  dword [r15 + dev.class], CLASS_BLOCK
    mov  dword [r15 + dev.flags], 0
    mov  qword [r15 + dev.next], 0
    mov  [r15 + dev.name], r8
    mov  rdi, r15
    call blk_register
    test eax, eax
    jnz  .register_fail
    lea  rdi, [rel str_ahci_slot_pre]
    call serial_string
    mov  rdi, [r15 + dev.name]
    call serial_string
    lea  rdi, [rel str_ahci_slot_port]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_ahci_slot_model]
    call serial_string
    imul eax, r13d, 41
    lea  rdi, [rel ahci_models]
    add  rdi, rax
    call serial_string
    lea  rdi, [rel str_ahci_slot_serial]
    call serial_string
    imul eax, r13d, 21
    lea  rdi, [rel ahci_serials]
    add  rdi, rax
    call serial_string
    call serial_newline
    xor  eax, eax
    jmp  .out
.register_fail:
    lea  rdx, [rel ahci_port_present]
    mov  byte [rdx + r13], 0
.fail:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ahci_pci_claim(R8D = PCI_CLAIM_*) — RCQ-29 hardware report: record that this
;   driver took (or matched and could not use) the legacy-bus HBA.  A VMD-child
;   HBA is the VMD root's claim.  Preserves every general register.
ahci_pci_claim:
    cmp  byte [rel ahci_claim_legacy], 1
    jne  .out
    push rax
    push rdi
    push rcx
    lea  rdi, [rel ahci_busno]
    mov  ecx, PCI_DRV_AHCI
    call pci_claim_bdf3
    pop  rcx
    pop  rdi
    pop  rax
.out:
    ret

; ---------------------------------------------------------------------------
; ahci_detect_cb(EDI=bus,ESI=dev,EDX=fn,ECX=vendev) — PCI scan callback. Records
;   ABAR (BAR5, offset 0x24 — a 32-bit memory BAR on Intel PCH + ich9-ahci) +
;   BDF for the FIRST class 0x01 / subclass 0x06 / prog-IF 0x01 function.
;   Must preserve RBX,RBP,R12-R15 (the scan keeps loop state there).
; ---------------------------------------------------------------------------
ahci_detect_cb:
    sub rsp,16                         ; preserve callback identity without another PCI read
    mov [rsp],ecx
    push rdi
    push rsi
    push rdx
    ; class/subclass/progIF at config offset 0x08 (EAX = Class|Sub|ProgIF|Rev)
    mov  ecx, 0x08
    call pci_cfg_read32
    shr  eax, 8
    and  eax, 0xFFFFFF
    ; Report-only: count every IDE/RAID/SATA storage function, taken or not.
    mov  ecx, eax
    shr  ecx, 8
    cmp  ecx, 0x0101
    je   .storage_fn
    cmp  ecx, 0x0104
    je   .storage_fn
    cmp  ecx, 0x0106
    jne  .storage_known
.storage_fn:
    inc  dword [rel ahci_storage_fns]
.storage_known:
    cmp  qword [rel ahci_bar5], 0
    jne  .pop                               ; already found one
    cmp  eax, 0x010601                      ; SATA controller, AHCI 1.0 prog-IF
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
    ; matched — save BDF (rsp+16=bus, rsp+8=dev, rsp+0=fn)
    mov  eax, [rsp + 16]
    mov  [rel ahci_busno], eax
    mov  eax, [rsp + 8]
    mov  [rel ahci_devno], eax
    mov  eax, [rsp + 0]
    mov  [rel ahci_fn], eax
    ; ABAR = BAR5 (offset 0x24), memory BAR only (bit0 clear)
    mov  edi, [rel ahci_busno]
    mov  esi, [rel ahci_devno]
    mov  edx, [rel ahci_fn]
    mov  ecx, 0x24
    call pci_cfg_read32
    test al, 0x01                           ; I/O BAR? not AHCI's ABAR
    jnz  .pop
    and  eax, 0xFFFFFFF0
    mov  [rel ahci_bar5], rax               ; 32-bit BAR — high dword stays 0
    mov ecx,[rsp+24]                    ; actual original scan callback vendor/device
    mov [rel ahci_terminal_selected_id],ecx
.pop:
    pop  rdx
    pop  rsi
    pop  rdi
    add rsp,16
    ret

; ---------------------------------------------------------------------------
; ahci_issue(EDI=logical slot, R10B=ATA cmd, R11B=W flag, RSI=lba48,
;            EDX=FIS sector count, R8D=PRDT bytes, RCX=buf phys)
;   -> RAX 0 ok / -1 (TFES or timeout). The monolith ahci_rw_common ported to
;   the selected per-port tables: zero CT, build Register H2D FIS, optional
;   PRDT, CL[0] DW0 with CFL=5 + W + PRDTL, W1C PxSERR+PxIS, issue slot 0,
;   pause-spin until CI clears (TFES -> error). Bounded, never blocks forever.
;   Slot ownership: a poisoned port is refused, and slot 0 is never rebuilt
;   while PxCI bit 0 is set (the HBA may still own the table and the buffer);
;   that, TFES and a spin timeout run ahci_port_recover. A failed recovery
;   poisons the port (I/O refused, dev.health DEGRADED) until re-creation.
; ---------------------------------------------------------------------------
; ahci_cmd_admitted(R10B=ATA command, R11B=W) -> EAX 0 admitted / -1 refused.
;   SEC-S6 opcode gate (srcreview 10:31 defence in depth): IDENTIFY, READ DMA EXT and
;   FLUSH CACHE EXT with W=0 are admitted; WRITE DMA EXT only with W=1 AND the
;   one-shot ahci_write_token that ahci_op_write sets right before its call (so a
;   write opcode synthesised elsewhere, e.g. AHCI_ATA_READ+0x10, is refused); every
;   other ATA command (TRIM, SECURITY ERASE, DOWNLOAD MICROCODE, SANITIZE, other
;   writes) is refused. The token is consumed on every call. In a live Try boot
;   (pbm_try_media) WRITE DMA EXT is refused even with the token. clobbers EAX, ECX.
ahci_cmd_admitted:
    movzx ecx, byte [rel ahci_write_token]
    mov  byte [rel ahci_write_token], 0
    cmp  r10b, AHCI_ATA_WRITE
    je   .write
    test r11b, r11b
    jnz  .no                                ; W=1 is only for the write command
    cmp  r10b, AHCI_ATA_READ
    je   .yes
    cmp  r10b, AHCI_ATA_FLUSH
    je   .yes
    cmp  r10b, AHCI_ATA_IDENTIFY
    je   .yes
.no:
    mov  eax, -1
    ret
.write:
    cmp  byte [rel pbm_try_media], 1        ; RCQ-29 live Try: never WRITE DMA EXT
    je   .no
    cmp  r11b, 1
    jne  .no
    cmp  ecx, 1
    jne  .no
.yes:
    xor  eax, eax
    ret

; No command spins/recovery here: the coordinator owns subsequent observations.
ahci_issue_cooperative:
    cld
    mov eax, 1
    jmp ahci_issue.cooperative
ahci_issue:
    xor eax, eax
.cooperative:
    push r9
    mov r9d, eax
    call ahci_power_check
    test rax, rax
    jz .admitted
    pop r9
    ret
.admitted:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cmp edi, AHCI_MAX_DISKS
    jae .err
    mov  ebp, edi                           ; logical per-port table slot
    mov  r12, rsi                           ; lba
    mov  r13d, edx                          ; FIS sector count
    mov  r14d, r8d                          ; PRDT byte count
    mov  r15, rcx                           ; buf phys

    call ahci_cmd_admitted                  ; SEC-S6: the opcode gate, before any port access
    test eax, eax
    jnz  .err

    lea  rax, [rel ahci_cts]
    mov  rbx, [rax + rbp*8]
    test rbx, rbx
    jz   .err
    lea  rdx, [rel ahci_port_poisoned]
    cmp  byte [rdx + rbp], 0
    jne  .err                               ; poisoned port: refuse
    lea  rsi, [rel ahci_pbases]
    mov  rsi, [rsi + rbp*8]
    test r9d, r9d
    jz .synchronous_slot
    cmp dword [rsi + AHCI_PORT_CI], 0
    jne .err
.synchronous_slot:
    test dword [rsi + AHCI_PORT_CI], 1
    jz   .slot_free
    test r9d, r9d
    jnz .err                              ; cooperative path never takes recovery
    mov  edi, ebp                           ; slot 0 still owned: reclaim first
    call ahci_port_recover
    xor r9d, r9d
    test eax, eax
    jnz  .err                               ; (recover poisoned the port)
.slot_free:

    ; zero first 256 bytes of CT (Cmd FIS + ATAPI + reserved + PRDT slot)
    mov  rdi, rbx
    mov  ecx, 64
    xor  eax, eax
    cld
    rep  stosd

    ; Register H2D FIS at CT+0x00
    mov  byte [rbx + 0x00], 0x27            ; FIS type: Register H2D
    mov  byte [rbx + 0x01], 0x80            ; C-bit, PMP=0
    mov  [rbx + 0x02], r10b                 ; ATA command
    mov  byte [rbx + 0x03], 0               ; features[7:0]
    mov  rax, r12                           ; LBA[7:0] LBA[15:8] LBA[23:16]
    mov  [rbx + 0x04], al
    shr  rax, 8
    mov  [rbx + 0x05], al
    shr  rax, 8
    mov  [rbx + 0x06], al
    mov  byte [rbx + 0x07], 0x40            ; device: LBA mode
    mov  rax, r12                           ; LBA[31:24] LBA[39:32] LBA[47:40]
    shr  rax, 24
    mov  [rbx + 0x08], al
    shr  rax, 8
    mov  [rbx + 0x09], al
    shr  rax, 8
    mov  [rbx + 0x0A], al
    mov  byte [rbx + 0x0B], 0               ; features[15:8]
    mov  [rbx + 0x0C], r13b                 ; count[7:0]
    mov  eax, r13d
    shr  eax, 8
    mov  [rbx + 0x0D], al                   ; count[15:8]
    mov  byte [rbx + 0x0E], 0               ; ICC
    mov  byte [rbx + 0x0F], 0               ; control

    ; optional single PRDT entry at CT+0x80
    mov  eax, 0x00000005                    ; CL[0] DW0 base: CFL=5
    test r14d, r14d
    jz   .no_prdt
    mov  [rbx + 0x80], r15d                 ; DBA low
    mov  rdx, r15
    shr  rdx, 32
    mov  [rbx + 0x84], edx                  ; DBAU high
    mov  dword [rbx + 0x88], 0
    mov  edx, r14d
    dec  edx
    and  edx, 0x3FFFFF                      ; DBC = bytes-1 (22-bit), I=0
    mov  [rbx + 0x8C], edx
    or   eax, 0x00010000                    ; PRDTL=1
.no_prdt:
    test r11b, r11b
    jz   .dw0
    or   eax, 0x40                          ; W bit
.dw0:
    lea  rdx, [rel ahci_cls]
    mov  rdx, [rdx + rbp*8]
    mov  [rdx + 0x00], eax
    mov  dword [rdx + 0x04], 0              ; PRDBC

    ; clear stale PxSERR + PxIS (write-1-to-clear), then issue slot 0
    lea  rsi, [rel ahci_pbases]
    mov  rsi, [rsi + rbp*8]
    mov  dword [rsi + AHCI_PORT_SERR], 0xFFFFFFFF
    mov  dword [rsi + AHCI_PORT_IS], 0xFFFFFFFF
    mov  dword [rsi + AHCI_PORT_CI], 1

    test r9d, r9d
    jnz .ok                               ; issued only, caller must observe CI/TFD/IS
    mov  ecx, AHCI_CMD_SPIN
.spin:
    mov  eax, [rsi + AHCI_PORT_IS]
    test eax, AHCI_PXIS_TFES
    jnz  .recover
    mov  eax, [rsi + AHCI_PORT_CI]
    test eax, 1
    jz   .ok
    pause
    dec  ecx
    jnz  .spin
.recover:
    mov  edi, ebp                           ; TFES / timeout: the command failed;
    call ahci_port_recover                  ; recover the port for the next one
    jmp  .err

.ok:
    xor  eax, eax
    jmp  .ret
.err:
    mov  eax, -1
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    pop  r9
    ret

; ---------------------------------------------------------------------------
; ahci_port_recover(EDI=logical slot) -> EAX 0 port idle and restarted / -1
;   poisoned. AHCI 1.3 section 6.2.2 software recovery, every wait bounded:
;   clear PxCMD.ST, wait PxCMD.CR clear (the HBA clears PxCI), W1C PxSERR and
;   PxIS, CLO if the device still shows BSY/DRQ (only with CAP.SCLO; no
;   COMRESET), require PxCI clear, set ST. Failure marks the port poisoned and
;   its registered dev DEGRADED. Clobbers RAX,RCX,RDX,RSI.
; ---------------------------------------------------------------------------
ahci_port_recover:
    cld
    cmp edi, AHCI_MAX_DISKS
    jb .power_slot_ok
    mov rax, -1
    ret
.power_slot_ok:
    sub rsp, 8
    xor eax, eax
    call ahci_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    mov  edx, edi
    lea  rsi, [rel ahci_pbases]
    mov  rsi, [rsi + rdx*8]
    test rsi, rsi
    jz   .rfail
    mov  eax, [rsi + AHCI_PORT_CMD]
    and  eax, ~AHCI_PXCMD_ST
    mov  [rsi + AHCI_PORT_CMD], eax
    mov  edx, AHCI_STOP_SPIN               ; bounded CR wait
.stop:
    mov  eax, [rsi + AHCI_PORT_CMD]
    test eax, AHCI_PXCMD_CR
    jz   .stopped
    pause
    dec  edx
    jnz  .stop
    jmp  .rfail
.stopped:
    mov  dword [rsi + AHCI_PORT_SERR], 0xFFFFFFFF
    mov  dword [rsi + AHCI_PORT_IS], 0xFFFFFFFF
    mov  eax, [rsi + AHCI_PORT_TFD]
    test al, AHCI_TFD_BSY_DRQ
    jz   .idle
    test dword [rel ahci_cap], AHCI_CAP_SCLO
    jz   .rfail
    mov  eax, [rsi + AHCI_PORT_CMD]
    or   eax, AHCI_PXCMD_CLO
    mov  [rsi + AHCI_PORT_CMD], eax
    mov  edx, AHCI_STOP_SPIN
.clo:
    mov  eax, [rsi + AHCI_PORT_CMD]
    test eax, AHCI_PXCMD_CLO
    jz   .clo_done
    pause
    dec  edx
    jnz  .clo
    jmp  .rfail
.clo_done:
    mov  eax, [rsi + AHCI_PORT_TFD]
    test al, AHCI_TFD_BSY_DRQ
    jnz  .rfail
.idle:
    test dword [rsi + AHCI_PORT_CI], 1
    jnz  .rfail
    mov  eax, [rsi + AHCI_PORT_CMD]
    or   eax, AHCI_PXCMD_ST                 ; restart the engine
    mov  [rsi + AHCI_PORT_CMD], eax
    xor  eax, eax
    ret
.rfail:
    mov  edx, edi
    lea  rax, [rel ahci_port_poisoned]
    mov  byte [rax + rdx], 1
    imul rax, rdx, dev_size
    lea  rcx, [rel ahci_devs]
    add  rax, rcx
    mov  dword [rax + dev.health], HEALTH_DEGRADED
    push rdi
    lea  rdi, [rel str_ahci_poisoned]
    call serial_string
    pop  rdi
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; ahci_parse_identify(EDI=logical slot) — parse that port's IDENTIFY buffer:
;   serial words 10..19, model words 27..46 and LBA48 count words 100..103. Ported from
;   the monolith ahci_identify model-cache loop. clobbers caller-saved.
; ---------------------------------------------------------------------------
ahci_parse_identify:
    mov  r8d, edi
    lea  rax, [rel ahci_idbufs]
    mov  rsi, [rax + r8*8]
    add  rsi, 54                            ; word 27 byte offset
    imul eax, r8d, 41
    lea  rdi, [rel ahci_models]
    add  rdi, rax
    xor  ecx, ecx                           ; 40 output chars
.mcp:
    cmp  ecx, 40
    jae  .mdone
    mov  eax, ecx
    xor  eax, 1                             ; byte-swap within each word pair
    movzx edx, byte [rsi + rax]
    cmp  dl, 0x20
    jb   .msp
    cmp  dl, 0x7E
    jbe  .mpr
.msp:
    mov  dl, ' '
.mpr:
    mov  [rdi + rcx], dl
    inc  ecx
    jmp  .mcp
.mdone:
    mov  byte [rdi + 40], 0
.mtrim:                                     ; trim trailing spaces (ecx == 40)
    test ecx, ecx
    jz   .model_normalized
    dec  ecx
    cmp  byte [rdi + rcx], ' '
    jne  .model_normalized
    mov  byte [rdi + rcx], 0
    jmp  .mtrim
.model_normalized:
    mov  ecx, 41
    call ahci_trim_leading
.serial:
    lea  rax, [rel ahci_idbufs]
    mov  rsi, [rax + r8*8]
    add  rsi, 20                            ; word 10 byte offset
    imul eax, r8d, 21
    lea  rdi, [rel ahci_serials]
    add  rdi, rax
    xor  ecx, ecx                           ; 20 output chars
.scp:
    cmp  ecx, 20
    jae  .sdone
    mov  eax, ecx
    xor  eax, 1
    movzx edx, byte [rsi + rax]
    cmp  dl, 0x20
    jb   .ssp
    cmp  dl, 0x7E
    jbe  .spr
.ssp:
    mov  dl, ' '
.spr:
    mov  [rdi + rcx], dl
    inc  ecx
    jmp  .scp
.sdone:
    mov  byte [rdi + 20], 0
.strim:
    test ecx, ecx
    jz   .serial_normalized
    dec  ecx
    cmp  byte [rdi + rcx], ' '
    jne  .serial_normalized
    mov  byte [rdi + rcx], 0
    jmp  .strim
.serial_normalized:
    mov  ecx, 21
    call ahci_trim_leading
.lba:
    lea  rax, [rel ahci_idbufs]
    mov  rax, [rax + r8*8]
    mov  rax, [rax + 200]                   ; words 100..103 = LBA48 sector count
    test rax, rax
    jz   .out
    dec  rax
    lea  rdx, [rel ahci_lba_maxes]
    mov  [rdx + r8*8], rax
.out:
    ret

; ATA IDENTIFY strings are word-swapped and space padded.  Right padding is
; removed above; compact any legal left padding too so descriptor comparison
; and BLKINFO expose the same canonical identity that Windows/Linux report.
; RDI=buffer, ECX=buffer bytes including NUL.  Preserves RDI and R8.
ahci_trim_leading:
    push rdi
    mov  rsi, rdi
    xor  eax, eax
.skip:
    cmp  eax, ecx
    jae  .done
    cmp  byte [rsi + rax], ' '
    jne  .copy_start
    inc  eax
    jmp  .skip
.copy_start:
    test eax, eax
    jz   .done
    add  rsi, rax
.copy:
    mov  dl, [rsi]
    mov  [rdi], dl
    inc  rsi
    inc  rdi
    test dl, dl
    jnz  .copy
.done:
    pop  rdi
    ret

; ahci_dev_identity_matches(RDI=dev*, RSI=exact model, RDX=exact serial)
; -> 0/-1.  Resolve the logical slot only after proving the pointer is the
; corresponding member of ahci_devs; then compare both IDENTIFY strings through
; their terminating NUL so prefixes cannot authorize the model volume.
ahci_dev_identity_matches:
    test rdi, rdi
    jz   .identity_fail
    mov  r8, [rdi + dev.priv]
    cmp  r8, AHCI_MAX_DISKS
    jae  .identity_fail
    mov  rax, r8
    imul rax, dev_size
    lea  r9, [rel ahci_devs]
    add  r9, rax
    cmp  rdi, r9
    jne  .identity_fail
    imul eax, r8d, 41
    lea  r9, [rel ahci_models]
    add  r9, rax
    xor  r10d, r10d
.model_cmp:
    mov  al, [r9 + r10]
    cmp  al, [rsi + r10]
    jne  .identity_fail
    test al, al
    jz   .serial_begin
    inc  r10
    cmp  r10d, 41
    jb   .model_cmp
    jmp  .identity_fail
.serial_begin:
    imul eax, r8d, 21
    lea  r9, [rel ahci_serials]
    add  r9, rax
    xor  r10d, r10d
.serial_cmp:
    mov  al, [r9 + r10]
    cmp  al, [rdx + r10]
    jne  .identity_fail
    test al, al
    jz   .identity_ok
    inc  r10
    cmp  r10d, 21
    jb   .serial_cmp
.identity_fail:
    mov  rax, -1
    ret
.identity_ok:
    xor  eax, eax
    ret

; ahci_find_identity(RDI=exact model, RSI=exact serial) -> RAX=dev* / 0.
; Only a successfully initialized registered slot can match.  Cognition uses
; this before opening any partition, so the primary system disk is never
; mounted speculatively while looking for the descriptor-owned data volume.
ahci_find_identity:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    xor  ebx, ebx
.find_next:
    cmp  ebx, AHCI_MAX_DISKS
    jae  .find_fail
    lea  rax, [rel ahci_port_present]
    cmp  byte [rax + rbx], 1
    jne  .find_advance
    mov  rax, rbx
    imul rax, dev_size
    lea  rdi, [rel ahci_devs]
    add  rdi, rax
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .find_advance
    mov  rsi, r12
    mov  rdx, r13
    call ahci_dev_identity_matches
    test rax, rax
    jz   .find_ok
.find_advance:
    inc  ebx
    jmp  .find_next
.find_ok:
    mov  rax, rbx
    imul rax, dev_size
    lea  rdx, [rel ahci_devs]
    add  rax, rdx
    jmp  .find_out
.find_fail:
    xor  eax, eax
.find_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ahci_scan_summarize -> ahci_scan_summary = the last scan's accounting as one
; NUL-terminated BOOTLOG FULL token (leading space), so a settled 'storage
; not-reached' names its cause on a box with no console:
;   " blk.ahci.scan=done:0"                       scan not ended (gated / running)
;   " blk.ahci.scan=done:1,unc:0xUU,hba:0"         ended, no HBA taken
;   " blk.ahci.scan=done:1,unc:0xUU,hba:1,sss:S,pi:0xPPPPPPPP,det:D...,sud:0xMMMMMMMM"
; unc = AHCI_UNC_* bits; sss = CAP.SSS; det = one hex DET digit per port from 0
; to the highest implemented one ('-' not implemented); sud = PxCMD.SUD per port
; as scanned.  Report-only: no MMIO, no effect on the scan or ahci_identity_absent.
; Clobbers RAX, RCX, RDX, RSI, RDI, R8.
ahci_scan_summarize:
    cld
    lea  rdi, [rel ahci_scan_summary]
    lea  rsi, [rel str_ahci_scan_done]
    call .str
    movzx eax, byte [rel ahci_enum_done]
    add  al, '0'
    stosb
    cmp  byte [rel ahci_enum_done], 1
    jne  .end
    lea  rsi, [rel str_ahci_scan_unc]
    call .str
    movzx eax, byte [rel ahci_enum_uncertain]
    mov  ecx, 2
    call .hex
    lea  rsi, [rel str_ahci_scan_hba]
    call .str
    xor  eax, eax
    cmp  qword [rel ahci_bar5], 0
    setne al
    mov  r8d, eax
    add  al, '0'
    stosb
    test r8d, r8d
    jz   .end
    lea  rsi, [rel str_ahci_scan_sss]
    call .str
    mov  eax, [rel ahci_cap]
    shr  eax, 27                            ; AHCI_CAP_SSS
    and  eax, 1
    add  al, '0'
    stosb
    lea  rsi, [rel str_ahci_scan_pi]
    call .str
    mov  eax, [rel ahci_pi]
    mov  ecx, 8
    call .hex
    lea  rsi, [rel str_ahci_scan_det]
    call .str
    mov  r8d, [rel ahci_pi]
    xor  edx, edx                           ; port index
.det:
    test r8d, r8d
    jz   .det_done                          ; no implemented port from here up
    mov  al, '-'
    shr  r8d, 1
    jnc  .det_put
    lea  rsi, [rel ahci_scan_det]
    movzx eax, byte [rsi + rdx]
    and  eax, 0x0F
    lea  rsi, [rel str_ahci_hex_digits]
    mov  al, [rsi + rax]
.det_put:
    stosb
    inc  edx
    jmp  .det
.det_done:
    lea  rsi, [rel str_ahci_scan_sud]
    call .str
    mov  eax, [rel ahci_scan_sud]
    mov  ecx, 8
    call .hex
.end:
    mov  byte [rdi], 0
    ret
; RSI = NUL-terminated text, appended at RDI.
.str:
    lodsb
    test al, al
    jz   .str_out
    stosb
    jmp  .str
.str_out:
    ret
; EAX = value, ECX = digits: appended at RDI, most significant first.
.hex:
    lea  rsi, [rel str_ahci_hex_digits]
    mov  edx, ecx
.hex_next:
    dec  edx
    js   .hex_out
    lea  ecx, [rdx * 4]
    mov  r8d, eax
    shr  r8d, cl
    and  r8d, 0x0F
    movzx r8d, byte [rsi + r8]
    mov  [rdi], r8b
    inc  rdi
    jmp  .hex_next
.hex_out:
    ret

; ahci_identity_absent(RDI=exact model, RSI=exact serial) -> EAX 1 proven
; absent / 0 not proven.  Report-only (the settled storage row); binding still
; goes through ahci_find_identity.  1 needs the boot scan to have run to its end
; with no ahci_enum_uncertain bit, and no slot - healthy, degraded or poisoned
; alike - carrying this model+serial (every slot is compared: one never
; initialized holds empty strings).  A field without its NUL counts as a
; possible match.  Clobbers RCX, RDX, R8-R11.
ahci_identity_absent:
    xor  eax, eax
    cmp  byte [rel ahci_enum_done], 1
    jne  .absent_out
    cmp  byte [rel ahci_enum_uncertain], 0
    jne  .absent_out
    xor  ecx, ecx
.absent_slot:
    cmp  ecx, AHCI_MAX_DISKS
    jae  .absent_proven
    imul r9d, ecx, 41
    lea  r8, [rel ahci_models]
    add  r9, r8
    mov  r10, rdi
    mov  r11d, 41
    call .absent_same
    test edx, edx
    jz   .absent_next
    imul r9d, ecx, 21
    lea  r8, [rel ahci_serials]
    add  r9, r8
    mov  r10, rsi
    mov  r11d, 21
    call .absent_same
    test edx, edx
    jnz  .absent_out                        ; this slot may be the identity
.absent_next:
    inc  ecx
    jmp  .absent_slot
.absent_proven:
    mov  eax, 1
.absent_out:
    ret
; R9=slot field, R10=expected, R11D=field size -> EDX 1 same through the NUL.
.absent_same:
    mov  dl, [r9]
    cmp  dl, [r10]
    jne  .absent_differ
    test dl, dl
    jz   .absent_match
    inc  r9
    inc  r10
    dec  r11d
    jnz  .absent_same
.absent_match:
    mov  edx, 1
    ret
.absent_differ:
    xor  edx, edx
    ret

; ahci_bind_name_identity(RDI=exact model, RSI=exact serial, EDX=name unit)
; -> matching dev* / 0.  Stable public units are descriptor identities, not
; incidental HBA port order.  Swap only name pointers with the current unit
; holder: device handles, dev.priv physical slots, priorities, registry links,
; and all I/O state remain untouched.  Repeated calls are idempotent.
ahci_bind_name_identity:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, edx
    cmp  r14d, AHCI_MAX_DISKS
    jae  .bind_fail
    call ahci_find_identity
    test rax, rax
    jz   .bind_fail
    mov  r12, rax                         ; exact identity handle
    mov  eax, r14d
    shl  eax, 3
    lea  r13, [rel ahci_names]
    add  r13, rax                         ; desired stable name pointer
    xor  ebx, ebx
.holder_scan:
    cmp  ebx, AHCI_MAX_DISKS
    jae  .bind_fail
    lea  rax, [rel ahci_port_present]
    cmp  byte [rax + rbx], 1
    jne  .holder_next
    mov  rax, rbx
    imul rax, dev_size
    lea  r15, [rel ahci_devs]
    add  r15, rax
    cmp  [r15 + dev.name], r13
    je   .holder_found
.holder_next:
    inc  ebx
    jmp  .holder_scan
.holder_found:
    cmp  r12, r15
    je   .bound
    mov  rax, [r12 + dev.name]
    mov  rcx, [r15 + dev.name]
    mov  [r12 + dev.name], rcx
    mov  [r15 + dev.name], rax
    mov  rdx, [r12 + dev.info]
    mov  [rdx + blk_info.name], rcx
    mov  rdx, [r15 + dev.info]
    mov  [rdx + blk_info.name], rax
.bound:
    mov  rax, r12
    jmp  .bind_out
.bind_fail:
    xor  eax, eax
.bind_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; blk_ops implementations
; ============================================================================
; identify(self) -> 0/-1. Idempotent liveness the reinit contract drives.
ahci_op_identify:
    cld
    cmp qword [rel ahci_power_gate], 0
    je .power_self_ok
    mov rax, [rdi+dev.priv]
    cmp rax, AHCI_MAX_DISKS
    jae .power_bad_self
    imul rax, dev_size
    lea r9, [rel ahci_devs]
    add rax, r9
    cmp rdi, rax
    je .power_self_ok
.power_bad_self:
    mov rax, -1
    ret
.power_self_ok:
    sub rsp, 8
    xor eax, eax
    call ahci_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    mov  rax, [rdi + dev.priv]
    cmp  rax, AHCI_MAX_DISKS
    jae  .no
    lea  rdx, [rel ahci_port_present]
    cmp  byte [rdx + rax], 0
    je   .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; read(self, RSI=lba, RDX=count, RCX=buf) -> 0/-1. Bounded 1..AHCI_MAX_XFER sectors.
;   The original one-sector path is preserved; the 4 KiB DMA bounce page now
;   earns its full capacity so filesystem streaming does not issue 8 commands
;   per ordinary FAT32 cluster.
ahci_op_read:
    cld
    cmp qword [rel ahci_power_gate], 0
    je .power_self_ok
    mov rax, [rdi+dev.priv]
    cmp rax, AHCI_MAX_DISKS
    jae .power_bad_self
    imul rax, dev_size
    lea r9, [rel ahci_devs]
    add rax, r9
    cmp rdi, rax
    je .power_self_ok
.power_bad_self:
    mov rax, -1
    ret
.power_self_ok:
    sub rsp, 8
    xor eax, eax
    call ahci_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push r12
    push r13
    push r14
    mov  r12, [rdi + dev.priv]
    cmp  r12, AHCI_MAX_DISKS
    jae  .fail
    lea  r9, [rel ahci_port_present]
    cmp  byte [r9 + r12], 0
    je   .fail
    test rdx, rdx
    jz   .fail
    cmp  rdx, AHCI_MAX_XFER
    ja   .fail
    mov  rax, rsi
    add  rax, rdx
    jc   .fail
    dec  rax                              ; inclusive last requested LBA
    lea  r9, [rel ahci_lba_maxes]
    cmp  rax, [r9 + r12*8]
    ja   .fail
    mov  r13, rdx                           ; sector count
    mov  r14, rcx                           ; caller buf
    mov  r10b, AHCI_ATA_READ
    xor  r11b, r11b
    mov  rdx, r13                           ; FIS sector count
    mov  r8, r13
    shl  r8, 9                              ; PRDT bytes = count*512
    lea  r9, [rel ahci_bounces]
    mov  rcx, [r9 + r12*8]
    mov  edi, r12d
    call ahci_issue                         ; RSI=lba already in place
    test eax, eax
    jnz  .fail
    lea  r9, [rel ahci_bounces]
    mov  rsi, [r9 + r12*8]
    mov  rdi, r14
    mov  rcx, r13
    shl  rcx, 6                             ; count*512/8 qwords
    cld
    rep  movsq
    xor  eax, eax
    pop  r14
    pop  r13
    pop  r12
    ret
.fail:
    mov  eax, -1
    pop  r14
    pop  r13
    pop  r12
    ret

; write(self, RSI=lba, RDX=count, RCX=buf) -> 0/-1. Bounded 1..AHCI_MAX_XFER sectors,
;   the read's bound and range check (RCQ-05: the declared max transfer holds both
;   ways). Copy the caller's sectors to the bounce buffer, then ONE WRITE DMA EXT.
;   An HBA found in the Intel VMD child domain (ahci_vmd_child) is never written:
;   its disks may be Intel RST RAID members, whose metadata PaOS does not parse, so
;   any raw write can corrupt the array (root 75030). Every write path (generic,
;   owned, writer and job grants) ends here; reads stay allowed.
ahci_op_write:
    cld
    cmp qword [rel ahci_power_gate], 0
    je .power_self_ok
    mov rax, [rdi+dev.priv]
    cmp rax, AHCI_MAX_DISKS
    jae .power_bad_self
    imul rax, dev_size
    lea r9, [rel ahci_devs]
    add rax, r9
    cmp rdi, rax
    je .power_self_ok
.power_bad_self:
    mov rax, -1
    ret
.power_self_ok:
    sub rsp, 8
    xor eax, eax
    call ahci_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push r12
    push r13
    push r14                              ; keep nested-call stack alignment
    cmp  byte [rel ahci_vmd_child], 0
    jne  .fail                            ; VMD/RST RAID member: never written
    mov  r12, [rdi + dev.priv]
    cmp  r12, AHCI_MAX_DISKS
    jae  .fail
    lea  r9, [rel ahci_port_present]
    cmp  byte [r9 + r12], 0
    je   .fail
    lea  r9, [rel ahci_port_poisoned]
    cmp  byte [r9 + r12], 0
    jne  .fail                            ; poisoned: the HBA may still own the bounce
    test rdx, rdx
    jz   .fail
    cmp  rdx, AHCI_MAX_XFER
    ja   .fail
    mov  rax, rsi
    add  rax, rdx
    jc   .fail
    dec  rax                              ; inclusive last requested LBA
    lea  r9, [rel ahci_lba_maxes]
    cmp  rax, [r9 + r12*8]
    ja   .fail
    mov  r13, rsi                           ; lba (RSI needed for the copy)
    mov  r14, rdx                           ; sector count
    mov  rsi, rcx                           ; caller buf
    lea  r9, [rel ahci_bounces]
    mov  rdi, [r9 + r12*8]
    mov  rcx, r14
    shl  rcx, 6                             ; count*512/8 qwords
    cld
    rep  movsq
    mov  r10b, AHCI_ATA_WRITE
    mov  r11b, 1                            ; W=1
    mov  rsi, r13                           ; lba
    mov  rdx, r14                           ; FIS sector count
    mov  r8, r14
    shl  r8, 9                              ; PRDT bytes = count*512
    mov  rcx, [r9 + r12*8]
    mov  edi, r12d
    mov  byte [rel ahci_write_token], 1     ; SEC-S6: only the registered write op may write
    call ahci_issue
    test eax, eax
    jnz  .fail
    xor  eax, eax
    pop  r14
    pop  r13
    pop  r12
    ret
.fail:
    mov  eax, -1
    pop  r14
    pop  r13
    pop  r12
    ret

; ahci_flush_for_reset() -> EAX ports flushed, EDX ports not quiesced.
;   The power-off path's AHCI half (ACPI S5 / firmware shutdown): one FLUSH CACHE
;   EXT per live port, so no ACKed WRITE DMA EXT is left in a drive's volatile
;   cache when the platform removes power. Each command is ahci_issue's bounded
;   CI spin (TFES/timeout -> port recovery). A present poisoned port cannot be
;   flushed: count it as unquiesced without MMIO or issue. Refused ordinary I/O
;   is not proof of completed writes/Flush. Clobbers caller-saved.
ahci_flush_for_reset:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Passive bounded observation table, cleared on EVERY actual call. Each
    ; logical slot owns 16 dwords; no absent/old port can borrow a result.
    lea rdi,[rel ahci_flush_observations]
    mov ecx,64
    xor eax,eax
    cld
    rep stosq
    ; Separate additive record: do not change a present1 port's original wire.
    lea rdi,[rel ahci_inactive_observations]
    mov ecx,64
    rep stosq
    lea rdi,[rel ahci_table_observations]
    mov ecx,64
    rep stosq
    xor  ebx, ebx                           ; logical slot
    xor  r12d, r12d                         ; flushed
    xor  r13d, r13d                         ; failed
.slot:
    cmp  ebx, AHCI_MAX_DISKS
    jae  .done
    lea  rax, [rel ahci_port_present]
    movzx edx,byte [rax + rbx]
    cmp edx,1
    jne .inactive                          ; zero is not proof of no retained work
    mov r14d,ebx
    shl r14,6
    lea rax,[rel ahci_flush_observations]
    add r14,rax
    mov dword [r14],1
    lea rax,[rel ahci_ports]
    mov eax,[rax+rbx*4]
    mov [r14+4],eax                       ; actual selected physical HBA port
    mov dword [r14+8],0xffffffff          ; VMD child BDF is NOT the legacy root
    movzx eax,byte [rel ahci_claim_legacy]
    movzx edx,byte [rel ahci_vmd_child]
    shl edx,1
    or eax,edx
    mov [r14+12],eax                     ; provenance, not a fabricated lease
    cmp eax,1
    jne .identity_done
    mov eax,[rel ahci_busno]
    shl eax,8
    mov edx,[rel ahci_devno]
    shl edx,3
    or eax,edx
    or eax,[rel ahci_fn]
    mov [r14+8],eax
.identity_done:
    lea rax,[rel ahci_port_poisoned]
    movzx eax,byte [rax+rbx]
    mov [r14+16],eax
    mov [r14+60],eax
    test eax,eax
    jz .unpoisoned
    inc r13d                             ; present but no completed Flush: refuse power
    jmp .next                            ; original skip, NO MMIO or issue on poison
.unpoisoned:
    xor r15d,r15d
    ; An attached class lifecycle may have fenced this controller. Preserve
    ; ahci_issue's admission-before-MMIO rule: the observer does not call or
    ; bypass that gate. Only its existing issue path may admit the command.
    cmp qword [rel ahci_power_gate],0
    jne .issue
    lea rax,[rel ahci_pbases]
    mov r15,[rax+rbx*8]
    test r15,r15
    jz .owner_refused
    mov eax,[r15+AHCI_PORT_CI]
    mov [r14+24],eax
    mov eax,[r15+0x34]                    ; PxSACT: outstanding NCQ work
    mov [r14+28],eax
    mov eax,[r15+AHCI_PORT_TFD]
    mov [r14+32],eax
    mov dword [r14+20],1                 ; sampled before issue/recovery
    ; Current command/FIS DMA ownership, independently read at the original
    ; decision point. Bits2 sampled,3 CLB match,4 FB match. Never treat a
    ; boot-time legacy/VMD claim alone as live queue ownership.
    or dword [r14+12],4
    lea rax,[rel ahci_cls]
    mov rdx,[rax+rbx*8]
    test rdx,rdx
    jz .owner_refused
    mov eax,[r15+AHCI_PORT_CLBU]
    shl rax,32
    mov ecx,[r15+AHCI_PORT_CLB]
    or rax,rcx
    cmp rax,rdx
    jne .check_fis
    or dword [r14+12],8
.check_fis:
    add rdx,0x400                        ; driver's actual RFIS allocation
    mov eax,[r15+AHCI_PORT_FBU]
    shl rax,32
    mov ecx,[r15+AHCI_PORT_FB]
    or rax,rcx
    cmp rax,rdx
    jne .owner_refused
    or dword [r14+12],16
    ; Only the already sampled live queues can justify this terminal issue.
    ; Keep both original equality observations even if CLB was foreign.
    test dword [r14+12],8
    jz .owner_refused
    ; Other slots/NCQ are active ownership, not our bounded slot0 recovery.
    ; Reuse the actual existing before snapshot; no new port read or reset.
    test dword [r14+24],0xfffffffe
    jnz .owner_refused
    cmp dword [r14+28],0
    jne .owner_refused
    ; CLB/FIS ownership does not bind slot0's actual command-table address.
    ; Read only the original qualified CL allocation, never follow CTBA.
    mov edi,ebx
    shl rdi,6
    lea rax,[rel ahci_table_observations]
    add rdi,rax
    mov dword [rdi],1
    mov [rdi+4],ebx
    mov dword [rdi+8],0xffffffff         ; refusal until every actual check passes
    mov dword [rdi+12],3                ; original CL and CT RAM entries loaded
    mov dword [rdi+16],1                ; CL already nonzero and matches live CLB
    lea rax,[rel ahci_cls]
    mov rcx,[rax+rbx*8]
    lea rax,[rel ahci_cts]
    mov rdx,[rax+rbx*8]
    test rdx,rdx
    jz .owner_refused
    mov dword [rdi+20],1
    mov rax,rcx
    add rax,0x500                       ; original create_port allocation layout
    jc .owner_refused
    or dword [rdi+12],4
    cmp rdx,rax
    jne .owner_refused
    mov dword [rdi+24],1
    mov rax,[rcx+8]                     ; actual full64 CL[0].CTBA, ordinary RAM
    or dword [rdi+12],8
    cmp rax,rdx
    jne .owner_refused
    mov dword [rdi+28],1
    mov dword [rdi+8],0                 ; exact table binding only, not Flush
    jmp .issue
.owner_refused:
    inc r13d                            ; no issue: attempt/outcome remain zero
    jmp .next                           ; no post-call snapshot or resource change
.issue:
    mov dword [r14+36],1                 ; actual call attempt, not completion
    mov  edi, ebx
    mov  r10b, AHCI_ATA_FLUSH
    xor  r11b, r11b
    xor  esi, esi                           ; lba 0
    xor  edx, edx                           ; count 0
    xor  r8d, r8d                           ; no PRDT
    xor  ecx, ecx
    call ahci_issue
    test eax, eax
    jnz .failed
    inc r12d
    mov dword [r14+40],1                 ; actual successful return
    jmp .after
.failed:
    inc r13d
    mov dword [r14+40],2                 ; actual refused/failed return
.after:
    lea rax,[rel ahci_port_poisoned]
    movzx eax,byte [rax+rbx]
    mov [r14+60],eax
    test eax,eax
    jnz .next                            ; recovery may poison: do not read it
    test r15,r15
    jz .next
    mov eax,[r15+AHCI_PORT_CI]
    mov [r14+48],eax
    mov eax,[r15+0x34]
    mov [r14+52],eax
    mov eax,[r15+AHCI_PORT_TFD]
    mov [r14+56],eax
    mov dword [r14+44],1                 ; independent post-call registers
    ; A successful issue return is not terminal quiescence if work remains
    ; or the original post-call ATA status reports ERR/DF.
    ; Preserve actual flushed/attempt/outcome and every original sampled value.
    mov eax,[r14+48]
    or eax,[r14+52]
    jnz .post_active
    test dword [r14+56],AHCI_TFD_BSY_DRQ | 0x21 ; ERR(bit0), DF(bit5)
    jz .next
.post_active:
    cmp dword [r14+40],1
    jne .next                           ; an actual failed issue already counted
    inc r13d                            ; aggregate refuses power after effect
.next:
    inc  ebx
    jmp  .slot
.done:
    mov  eax, r12d
    mov  edx, r13d
    pop r15
    pop r14
    pop  r13
    pop  r12
    pop  rbx
    ret

.inactive:
    ; Original attach failures retain their RAM handles before present1. Do
    ; not dereference those handles or invent a new cleanup/recovery rail.
    mov r14d,ebx
    shl r14,6
    lea rax,[rel ahci_inactive_observations]
    add r14,rax
    mov dword [r14],1                      ; additive schema, this actual call
    mov [r14+4],ebx
    mov [r14+20],edx                       ; original raw present byte
    xor r15d,r15d
    test edx,edx
    setnz r15b                            ; noncanonical present is a refusal
    lea rax,[rel ahci_port_poisoned]
    movzx edx,byte [rax+rbx]
    mov [r14+24],edx
    test edx,edx
    setnz dl
    movzx edx,dl
    shl edx,1
    or r15d,edx
    lea rax,[rel ahci_pbases]
    mov rdx,[rax+rbx*8]                    ; actual original retained qword
    test rdx,rdx
    setnz dl
    movzx edx,dl
    mov [r14+28],edx                  ; presence, never an exported address
    shl edx,2
    or r15d,edx
    lea rax,[rel ahci_cls]
    mov rdx,[rax+rbx*8]                    ; actual original retained qword
    test rdx,rdx
    setnz dl
    movzx edx,dl
    mov [r14+32],edx                  ; presence, never an exported address
    shl edx,3
    or r15d,edx
    lea rax,[rel ahci_cts]
    mov rdx,[rax+rbx*8]                    ; actual original retained qword
    test rdx,rdx
    setnz dl
    movzx edx,dl
    mov [r14+36],edx                  ; presence, never an exported address
    shl edx,4
    or r15d,edx
    lea rax,[rel ahci_idbufs]
    mov rdx,[rax+rbx*8]                    ; actual original retained qword
    test rdx,rdx
    setnz dl
    movzx edx,dl
    mov [r14+40],edx                  ; presence, never an exported address
    shl edx,5
    or r15d,edx
    lea rax,[rel ahci_bounces]
    mov rdx,[rax+rbx*8]                    ; actual original retained qword
    test rdx,rdx
    setnz dl
    movzx edx,dl
    mov [r14+44],edx                  ; presence, never an exported address
    shl edx,6
    or r15d,edx
    mov [r14+16],r15d
    mov dword [r14+12],0x7f                ; all seven actual RAM operands observed
    mov dword [r14+8],1                    ; bounded inactive predicate only
    test r15d,r15d
    jz .next
    mov dword [r14+8],0xffffffff           ; retained/unknown: no Flush attempted
    mov dword [r14+48],1
    cmp dword [r14+20],0
    je .inactive_failed
    mov dword [r14+48],2                   ; noncanonical presence stays distinct
.inactive_failed:
    inc r13d                              ; actual original aggregate refuses power
    jmp .next

; flush(self) -> 0/-1. Real FLUSH CACHE EXT (0xEA) — a committed write reaches
;   the medium. No data phase (PRDTL=0).
ahci_op_flush:
    cld
    cmp qword [rel ahci_power_gate], 0
    je .power_self_ok
    mov rax, [rdi+dev.priv]
    cmp rax, AHCI_MAX_DISKS
    jae .power_bad_self
    imul rax, dev_size
    lea r9, [rel ahci_devs]
    add rax, r9
    cmp rdi, rax
    je .power_self_ok
.power_bad_self:
    mov rax, -1
    ret
.power_self_ok:
    sub rsp, 8
    xor eax, eax
    call ahci_power_check
    add rsp, 8
    test rax, rax
    jz .power_admitted
    ret
.power_admitted:
    push r12
    mov  r12, [rdi + dev.priv]
    cmp  r12, AHCI_MAX_DISKS
    jae  .fail
    lea  rax, [rel ahci_port_present]
    cmp  byte [rax + r12], 0
    je   .fail
    mov  r10b, AHCI_ATA_FLUSH
    xor  r11b, r11b
    xor  esi, esi                           ; lba 0
    xor  edx, edx                           ; count 0
    xor  r8d, r8d                           ; no PRDT
    xor  ecx, ecx
    mov  edi, r12d
    call ahci_issue
    test eax, eax
    jnz  .fail
    xor  eax, eax
    pop  r12
    ret
.fail:
    mov  eax, -1
    pop  r12
    ret

; ahci_declare(EDI=logical slot, RBX=that port's blk_info) — RCQ-05 storage rung.
;   Publish the v2 geometry and a BLKCAP mask only where the port's IDENTIFY proves
;   them (ACS-3 words 83, 106, 209); otherwise the zero mask stays (the pre-2912
;   compatibility view, nothing claimed). The driver moves 512-byte sectors, at most
;   AHCI_MAX_XFER per command through its 4 KiB bounce, so a logical sector longer
;   than 256 words is not declared. Word 106 without its valid pattern is the ACS
;   legacy 256-word sector, one per physical sector. Alignment is the ABI's
;   (driver_classes.inc): bytes from LBA 0 to the next physical boundary, from
;   w209's logical offset of LBA 0. FLUSH needs FLUSH CACHE EXT
;   (word 83 bit 13), the command ahci_op_flush issues. Preserves R8.
;   Clobbers RAX, RCX, RDX, RSI, R9.
ahci_declare:
    xor  eax, eax
    mov  [rbx + blk_info.logical_sector_bytes], eax
    mov  [rbx + blk_info.physical_sector_bytes], eax
    mov  [rbx + blk_info.physical_alignment_bytes], eax
    mov  [rbx + blk_info.max_transfer_sectors], eax
    mov  [rbx + blk_info.capabilities], rax
    lea  rax, [rel ahci_idbufs]
    mov  rsi, [rax + rdi*8]
    test rsi, rsi
    jz   .done
    movzx r9d, word [rsi + 83*2]
    mov  eax, r9d
    and  eax, 0xC400                        ; word valid (15:14 = 01b) + 48-bit LBA
    cmp  eax, 0x4400
    jne  .done
    mov  edx, 512                           ; physical sector bytes
    movzx eax, word [rsi + 106*2]
    mov  ecx, eax
    and  ecx, 0xC000
    cmp  ecx, 0x4000
    jne  .aligned                           ; not valid: legacy 512-byte, 1:1
    test eax, 1 << 12
    jnz  .done                              ; logical sector > 256 words
    test eax, 1 << 13
    jz   .aligned
    mov  ecx, eax
    and  ecx, 0x0F                          ; log2(logical sectors per physical)
    shl  edx, cl
.aligned:
    xor  ecx, ecx                           ; alignment bytes
    movzx eax, word [rsi + 209*2]
    mov  esi, eax
    and  esi, 0xC000
    cmp  esi, 0x4000
    jne  .publish
    and  eax, 0x3FFF                        ; logical offset of LBA 0 in its physical sector
    shl  eax, 9
    cmp  eax, edx
    jae  .done                              ; inconsistent: declare nothing
    test eax, eax
    jz   .publish                           ; LBA 0 on a boundary: alignment 0
    mov  ecx, edx
    sub  ecx, eax                           ; bytes from LBA 0 to the next physical boundary
.publish:
    mov  dword [rbx + blk_info.logical_sector_bytes], 512
    mov  [rbx + blk_info.physical_sector_bytes], edx
    mov  [rbx + blk_info.physical_alignment_bytes], ecx
    mov  dword [rbx + blk_info.max_transfer_sectors], AHCI_MAX_XFER
    mov  eax, BLKCAP_READ | BLKCAP_WRITE
    test r9d, 1 << 13                       ; FLUSH CACHE EXT supported
    jz   .caps
    or   eax, BLKCAP_FLUSH
.caps:
    mov  [rbx + blk_info.capabilities], rax
.done:
    ret

; degraded op — every call -1 (no HBA / no disk port / bring-up failed).
ahci_blk_degraded:
    mov  eax, -1
    ret

; ============================================================================
; ahci_self_exercise — boot acceptance for the AHCI backend. Always reports
; registration/IDENTIFY and content-grades LBA 0 when a disk is present.
; A destructive round-trip additionally requires SA_CLASS_PAOS_OWNED for the
; exact scratch range, followed by the existing implicit grant and SEC-S6
; write admission. QEMU/no-GPT TEST_SCRATCH is deliberately insufficient:
; on the native FAT superfloppy, LBA 0x700 is inside the signed boot shim.
; No physical owned raw scratch range is minted today, so this test reports
; SKIPPED plus blk.ahci.read.verified, never blk.ahci.rw.verified. Neither
; a model name nor the PERSIST_GAP alias/allowlist reserves an extent.
; ============================================================================
ahci_self_exercise:
    push rbx
    push r12
    cmp  byte [rel ahci_present], 0
    jne  .present
    ; --- no disk: documented skip (clean, never a false pass) ---------------
    lea  rdi, [rel str_ahci_skipped]
    call serial_string
    lea  rdi, [rel str_ahci_registered]
    call serial_string                      ; backend registered (degraded)
    jmp  .done

.present:
    lea  rdi, [rel str_ahci_registered]
    call serial_string                      ; marker: blk.ahci.registered

    ; --- IDENTIFY marker: report the real model ------------------------------
    lea  rdi, [rel str_ahci_id_pre]
    call serial_string
    lea  rdi, [rel ahci_model]
    call serial_string
    lea  rdi, [rel str_ahci_id_post]
    call serial_string                      ; marker: blk.ahci.identify.ok

    ; --- content-graded READ of LBA 0 (real bytes off the disk) -------------
    lea  rdi, [rel ahci_dev]
    xor  rsi, rsi                           ; lba 0
    mov  rdx, 1
    lea  rcx, [rel ahci_ex_buf]
    call ahci_op_read
    test rax, rax
    jnz  .rw_fail

    ; Keep the exact candidate range. Never clamp/fall back onto another sector.
    mov  rax, AHCI_SCRATCH_LBA
    cmp  rax, [rel ahci_lba_max]             ; inclusive last LBA (same as ahci_op_read)
    ja   .rw_refused
    mov  [rel ahci_scratch_rt], rax

    ; OWNED is the existing explicit range-authority hook; no disk extent is
    ; minted by it today. TEST_SCRATCH (QEMU model / absent GPT) is not a grant
    ; of ownership and cannot authorize an implicit boot-time disk overwrite.
    lea  rdi, [rel ahci_dev]
    mov  rsi, rax
    mov  edx, 1
    call storage_access_classify
    cmp  eax, SA_CLASS_PAOS_OWNED
    jne  .rw_refused

    lea  rdi, [rel ahci_dev]
    mov  rsi, [rel ahci_scratch_rt]
    mov  edx, 1
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_ahci_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .rw_refused

    lea  rdi, [rel ahci_ex_buf]
    call blk_fill_pattern_b                 ; deterministic 512B pattern
    lea  rdi, [rel ahci_ex_buf]
    mov  rsi, 512
    call blk_cksum
    mov  r12, rax                           ; expected FNV(pattern B)

    lea  rdi, [rel ahci_dev]
    mov  rsi, [rel ahci_scratch_rt]
    mov  rdx, 1
    lea  rcx, [rel ahci_ex_buf]
    call storage_access_write_admitted      ; SEC-S6: a direct driver write is admitted like blk_write
    test rax, rax
    jnz  .rw_refused
    call ahci_op_write
    test rax, rax
    jnz  .rw_fail
    lea  rdi, [rel ahci_dev]
    call ahci_op_flush
    test rax, rax
    jnz  .rw_fail
    lea  rdi, [rel ahci_dev]
    mov  rsi, [rel ahci_scratch_rt]
    mov  rdx, 1
    lea  rcx, [rel ahci_ex_buf2]
    call ahci_op_read
    test rax, rax
    jnz  .rw_fail
    lea  rdi, [rel ahci_ex_buf2]
    mov  rsi, 512
    call blk_cksum
    cmp  rax, r12
    jne  .rw_fail
    lea  rdi, [rel str_ahci_rw_pre]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_ahci_rw_post]
    call serial_string                      ; marker: blk.ahci.rw.verified
    jmp  .done
.rw_refused:
    lea  rdi, [rel str_ahci_rw_refused]
    call serial_string                      ; blk.ahci.rw.skipped.storage_access
.read_only:
    lea  rdi, [rel str_ahci_ro]
    call serial_string                      ; blk.ahci.read.verified (hw)
    jmp  .done
.rw_fail:
    lea  rdi, [rel str_ahci_rw_bad]
    call serial_string
.done:
    pop  r12
    pop  rbx
    ret

; ahci_model_is_qemu() -> RAX = 1 if ahci_model contains "QEMU", else 0.
;   clobbers RAX,RCX,RDX,RSI.
ahci_model_is_qemu:
    lea  rsi, [rel ahci_model]
    xor  ecx, ecx
.scan:
    cmp  ecx, 37                            ; model buf is 41 bytes; stop before overrun
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

; ---------------------------------------------------------------------------
; ahci_identify_dma_to(RDI = owner's denied aligned page) -> EAX 0 completed /
;   1 failed or timed out, port recovered / 0xFFFD recovery poisoned the port /
;   0xFFFE refused, nothing issued. T1-4 AMD-Vi proof seam, the AHCI twin of
;   nvme_get_log_error4_dma_to: the hv owner proves the page is absent from the
;   native domain; this driver sends one read-only IDENTIFY DEVICE (512 B) on
;   logical slot 0 through the ordinary ahci_issue opcode gate. No disk write.
;   An idle engine only: a busy slot is refused, never reclaimed. Clobbers
;   caller-saved.
; ---------------------------------------------------------------------------
ahci_identify_dma_to:
    cld
    cmp  byte [rel ahci_present], 1
    jne  .refuse
    cmp  byte [rel ahci_vmd_child], 0
    jne  .refuse
    cmp  byte [rel ahci_port_present], 0
    je   .refuse
    cmp  byte [rel ahci_port_poisoned], 0
    jne  .refuse
    test rdi, rdi
    jz   .refuse
    test rdi, 4095
    jnz  .refuse
    mov  rcx, rdi
    xor  eax, eax
    call ahci_power_check                   ; preserves RCX
    test rax, rax
    jnz  .refuse
    cmp  qword [rel ahci_cts], 0
    je   .refuse
    mov  rax, [rel ahci_pbases]
    test rax, rax
    jz   .refuse
    cmp  dword [rax + AHCI_PORT_CI], 0
    jne  .refuse
    mov  r10b, AHCI_ATA_IDENTIFY
    xor  r11b, r11b
    xor  esi, esi
    xor  edx, edx
    mov  r8d, 512
    xor  edi, edi
    call ahci_issue
    test eax, eax
    jz   .out
    mov  eax, 1
    cmp  byte [rel ahci_port_poisoned], 0
    je   .out
    mov  eax, 0xFFFD
    ret
.refuse:
    mov  eax, 0xFFFE
.out:
    ret

; ---- ahci data (in-image writable; migrates to BSS under full W^X) -----------
AHCI_SCRATCH_LBA equ PERSIST_GAP_LBA_PRIMARY ; candidate only; not an ownership reservation
%include "dev/blk/ahci_vmd_owner.inc"
%include "dev/blk/ahci_empty_owner.inc"
%include "dev/blk/ahci_boh_owner.inc"
%include "dev/blk/ahci_vmd_boh_owner.inc"

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_dev_blk_ahci_0 0
str_ahci_sa_caller: db "ahci_self_exercise", 0
str_ahci_rw_refused: db "[PAOS64] P3 blk: AHCI write round-trip SKIPPED: owned scratch/storage access not permitted [blk.ahci.rw.skipped.storage_access]", 13, 10, 0

ahci_power_gate: dq 0
ahci_power_command_gate: dq 0
ahci_bar5:        dq 0
ahci_cap:         dd 0
ahci_pi:          dd 0
ahci_claim_legacy: db 0                     ; 1 = ahci_busno/devno/fn name the HBA taken
align 4
ahci_busno:       dd 0
ahci_devno:       dd 0
ahci_fn:          dd 0
ahci_vmd_child:   db 0                    ; 1 = ABAR came from the Intel VMD child domain
ahci_present:     db 0
align 4
ahci_port_count:  dd 0                      ; healthy registered disk handles
ahci_scratch_rt:  dq 0

; Per-port tables ported from the proven Classic multi-port driver.  The second
; label at each table head preserves the historical slot-0 symbols consumed by
; existing diagnostics while blk_ops uses the indexed plural form.
align 8
ahci_ports:
ahci_port:        times AHCI_MAX_DISKS dd 0xFFFFFFFF
times 40 db 0                  ; ahci_port_present..ahci_ex_buf2 moved to WDATA_dev_blk_ahci_0_bss1: keeps the labels below at their offset mod 64

str_ahci_name:       db "ahci0", 0
str_ahci_poisoned:   db "[PAOS64] P3 blk: AHCI port recovery failed; I/O refused, port degraded [blk.ahci.poisoned]", 13, 10, 0
str_ahci_registered: db "[PAOS64] P3 blk: AHCI backend registered via blk_ops [blk.ahci.registered]", 13, 10, 0
str_ahci_skipped:    db "[PAOS64] P3 blk: blk.ahci: skipped (no disk)", 13, 10, 0
str_ahci_scan_done:  db " blk.ahci.scan=done:", 0
str_ahci_scan_unc:   db ",unc:0x", 0
str_ahci_scan_hba:   db ",hba:", 0
str_ahci_scan_sss:   db ",sss:", 0
str_ahci_scan_pi:    db ",pi:0x", 0
str_ahci_scan_det:   db ",det:", 0
str_ahci_scan_sud:   db ",sud:0x", 0
str_ahci_hex_digits: db "0123456789abcdef"
str_ahci_id_pre:     db "[PAOS64] P3 blk: AHCI identify model=", 0
str_ahci_id_post:    db " lba=512 [blk.ahci.identify.ok]", 13, 10, 0
str_ahci_rw_pre:     db "[PAOS64] P3 blk: AHCI write->flush->readback PASS cksum=", 0
str_ahci_rw_post:    db " [blk.ahci.rw.verified]", 13, 10, 0
str_ahci_rw_bad:     db "[PAOS64] P3 blk: AHCI rw round-trip FAIL", 13, 10, 0
str_ahci_ro:         db "[PAOS64] P3 blk: AHCI read-only content-grade PASS (write round-trip is the supervised 0x700-allowlist probe) [blk.ahci.read.verified]", 13, 10, 0
str_ahci_atapi_skip: db "[PAOS64] P3 blk: AHCI ATAPI port skipped port=", 0
str_ahci_slot_pre:   db "[PAOS64] P3 blk: AHCI slot=", 0
str_ahci_slot_port:  db " port=", 0
str_ahci_slot_model: db " model=", 0
str_ahci_slot_serial: db " serial=", 0
%endmacro
WDATA_DEFER WDATA_dev_blk_ahci_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_dev_blk_ahci_0_bss1 0
resb 24                 ; keeps ahci_port_present at its WDATA offset mod 64
ahci_port_present: resb AHCI_MAX_DISKS
ahci_write_token: resb 1                ; SEC-S6: set only by ahci_op_write, consumed by ahci_cmd_admitted
ahci_port_poisoned: resb AHCI_MAX_DISKS         ; 1 = recovery failed: I/O refused, dev DEGRADED
alignb 8
ahci_pbases:
ahci_pbase:       resq AHCI_MAX_DISKS
ahci_cls:
ahci_cl:          resq AHCI_MAX_DISKS
ahci_cts:
ahci_ct:          resq AHCI_MAX_DISKS
ahci_idbufs:
ahci_idbuf:       resq AHCI_MAX_DISKS
ahci_bounces:
ahci_bounce:      resq AHCI_MAX_DISKS
ahci_lba_maxes:
ahci_lba_max:     resq AHCI_MAX_DISKS

ahci_devs:
ahci_dev:         resb (AHCI_MAX_DISKS * dev_size)
ahci_ops:         resb blk_ops_size
ahci_infos:
ahci_info:        resb (AHCI_MAX_DISKS * blk_info_size)
ahci_models:
ahci_model:       resb (AHCI_MAX_DISKS * 41)
ahci_serials:
ahci_serial:      resb (AHCI_MAX_DISKS * 21)
ahci_names:       resb (AHCI_MAX_DISKS * 8)
ahci_ex_buf:      resb 512
ahci_ex_buf2:     resb 512
%endmacro
WDATA_BSS_DEFER WDATA_dev_blk_ahci_0_bss1
; RCQ-32 settled storage absence: its own block (WDATA_dev_blk_ahci_0_bss1's layout is pinned by the zero-storage move)
%macro WDATA_BSS_dev_blk_ahci_absence 0
ahci_storage_fns:    resd 1             ; legacy-bus IDE/RAID/SATA functions seen by ahci_detect_cb
ahci_enum_done:      resb 1             ; 1 = the last ahci_blk_create scan ran to its end
ahci_enum_uncertain: resb 1             ; AHCI_UNC_* bits of that scan
%endmacro
WDATA_BSS_DEFER WDATA_BSS_dev_blk_ahci_absence
; RCQ-32 settled storage: AHCI scan accounting for BOOTLOG FULL, its own block.
%macro WDATA_BSS_dev_blk_ahci_scan_report 0
ahci_scan_sud:       resd 1             ; PxCMD.SUD per implemented port, as scanned
ahci_scan_det:       resb 32            ; PxSSTS.DET per implemented port, as scanned
ahci_scan_summary:   resb AHCI_SCAN_SUMMARY_MAX ; ahci_scan_summarize's token (NUL-terminated)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_dev_blk_ahci_scan_report

; Per-slot flush witnesses: present,physical port,BDF,ownership flags,
; owner bits0 legacy claim,1 VMD child,2 live queues sampled,3 CLB match,4 FB match.
; poison-before,before-valid,CI/SACT/TFD-before,attempt,outcome,
; after-valid,CI/SACT/TFD-after,poison-after (16 dwords, 8 bounded slots).
; outcome0 skipped,1 successful call,2 failed call. A poisoned port remains
; present but unattempted; unavailable MMIO is NEVER reported as idle proof.
%macro WDATA_BSS_dev_blk_ahci_flush_observations 0
alignb 8
ahci_flush_observations: resb (AHCI_MAX_DISKS * 64)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_dev_blk_ahci_flush_observations

; Additive per-call inactive-slot ABI; independent block preserves all existing
; initialized/BSS storage offsets and the original present1 64B observation.
%macro WDATA_dev_blk_ahci_inactive_observation 0
align 8
ahci_inactive_observations: times (AHCI_MAX_DISKS*64) db 0
; Additive original per-call table-binding operands, never exported addresses.
align 8
ahci_table_observations: times AHCI_MAX_DISKS*64 db 0
%endmacro
WDATA_DEFER WDATA_dev_blk_ahci_inactive_observation

; Terminal-only owner containment; no ordinary I/O or Flush changes.
%include "dev/blk/ahci_terminal.inc"

%include "dev/blk/ahci_vmd_terminal.inc"
