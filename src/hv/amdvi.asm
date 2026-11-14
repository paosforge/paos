%include "hv/amdvi_lab_profile.inc"
;; MODULE hv/amdvi
;; LAYER 5
;; EXPORTS amdvi_lab_event_snapshot, amdvi_ownership_init, amdvi_outcome_get, amdvi_owned, amdvi_flush_domain, amdvi_flush_dte, amdvi_ivrs_parse, amdvi_native_map_range, amdvi_native_unmap_range, amdvi_observation_generation, amdvi_observation_publishing
;; IMPORTS boot/paging, boot/serial, bus/acpi, bus/pci, bus/pci_bdf, core/dma, core/heap, core/lock, svc/resilience, svc/command_audit
;; CAPS CAP_MMIO
;; OWNER saga:hv
; ============================================================================
; RCQ-18-AMDVI-S3a: AMD-Vi host DMA protection (root contract 200da163, design
; vm-evidence/RCQ-18-AMDVI-S3-design/DESIGN.md df0497c2). This is VT-d's boot
; ownership (hv/vtd.asm vtd_ownership_init) on the AMD IOMMU. There is no
; assignment and no interrupt remapping here (S3b).
;
; - Detect: acpi_find_table('IVRS') only, with no second XSDT walker and no
;   AML. Selected when IVRS is present and DMAR absent. An F0h (ACPI HID)
;   entry contributes its DeviceID only; its HID/UID text is never read.
; - IVHD flags drive no policy. They are reported raw in the detect marker;
;   reserved bits (11h/40h bits 7:6) are ignored, never read as 10h-style
;   PrefSup/PPRSup. HP's accept-4:0-only rule is not copied: it refuses
;   Reatan's measured 0x30. HP's own 11h carries 0xB0 (bit 7 reserved).
; - V=0 in a DTE is pass-through on AMD-Vi (VT-d's not-present context
;   blocks). So all 65,536 DTEs are written valid before IommuEn: blocked
;   (V=TV=1, IR=IW=0) unless an IVHD entry covers the DeviceID. Covered
;   requesters join the compat domain (DomainID 1: a 512 GiB identity IOPT
;   with 1 GiB leaves, VT-d DID 1's reach). PaOS's NVMe, SATA and Intel
;   Ethernet requesters join the native domain (DomainID 2: 4 KiB leaves over
;   core/dma's recorded valid set, VT-d DID 2).
; - IVMD exclusion ranges become unity maps. The exclusion registers are never
;   written; a firmware-armed one is refused as iommu_fw, like a
;   firmware-left IommuEn. ATS is never enabled (DTE.I stays 0).
; - Selective invalidation only. One submitter at a time (amdvi_cmd_lock, held
;   through the bounded COMPLETION_WAIT; no interrupt handler flushes).
;
; Slot contract (shared with VT-d/EPT/NPT, srcreview C-b): after EAX=1, no
; stale DMA translation is usable at the next device DMA. EAX=0 means the
; caller fails closed.
; ============================================================================

AMDVI_DEVIDS        equ 65536
AMDVI_DEVTAB_BYTES  equ AMDVI_DEVIDS * 32        ; full coverage: V=0 would be pass-through
AMDVI_DEVTAB_SIZE   equ AMDVI_DEVTAB_BYTES / 4096 - 1
AMDVI_RING_LEN      equ 8 << 56                  ; 2^8 entries x 16 B = one 4 KiB page
AMDVI_RING_MASK     equ 0xFF0
AMDVI_EVT_LEN       equ 11 << 56                 ; 2048 entries: room for 1024 denied 4B Identify writes
AMDVI_EVT_MASK      equ 0x7FF0
AMDVI_EVT_PAGES     equ 8
AMDVI_PTR_MASK      equ 0x7FFF0                  ; head/tail pointer bits 18:4
AMDVI_WAIT_SPINS    equ 1000000
AMDVI_SYNC_BATCH    equ 128                      ; commands per COMPLETION_WAIT during boot invalidation
AMDVI_CARVE_PAGES   equ 12                       ; compat splits: <= 6 PDs + 6 PTs over the 3 carved ranges
AMDVI_POOL_PAGES    equ 46 + AMDVI_CARVE_PAGES   ; original 39 + seven extra event pages, all compat-carved
AMDVI_POOL_BYTES    equ (AMDVI_POOL_PAGES + 1) * 4096   ; + the final canary page, outside every domain
AMDVI_ALIAS_MAX     equ 16
AMDVI_IVMD_MAX      equ 8
AMDVI_NATIVE_MAX    equ 8
AMDVI_IVMD_LIMIT    equ 1 << 39                  ; the compat domain's 512 GiB identity reach
AMDVI_MMIO_BYTES    equ 0x80000                  ; the aperture with performance counters (512 KiB)
AMDVI_MMIO_CORE     equ 0x4000                   ; without them: the registers below the counter bank (16 KiB)
AMDVI_EFR_PCSUP     equ 1 << 9

AMDVI_R_DEVTAB      equ 0x0000
AMDVI_R_CMD         equ 0x0008
AMDVI_R_EVT         equ 0x0010
AMDVI_R_CTRL        equ 0x0018
AMDVI_R_EXCL        equ 0x0020                   ; read only: never programmed
AMDVI_R_EFR         equ 0x0030
AMDVI_R_CMD_HEAD    equ 0x2000
AMDVI_R_CMD_TAIL    equ 0x2008
AMDVI_R_EVT_HEAD    equ 0x2010
AMDVI_R_EVT_TAIL    equ 0x2018
AMDVI_R_STATUS      equ 0x2020
AMDVI_CTRL_EN       equ 1 << 0
AMDVI_CTRL_EVTLOG   equ 1 << 2
AMDVI_CTRL_CMDBUF   equ 1 << 12
AMDVI_STS_EVT_OVF   equ 1 << 0
AMDVI_STS_EVT_RUN   equ 1 << 3
AMDVI_STS_CMD_RUN   equ 1 << 4

AMDVI_CMD_CW        equ 1 << 60                  ; COMPLETION_WAIT
AMDVI_CW_STORE      equ 1                        ; S: store the 64-bit token
AMDVI_CW_ADDR_MASK  equ 0x000FFFFFFFFFFFF8
AMDVI_CMD_INV_DTE   equ 2 << 60                  ; INVALIDATE_DEVTAB_ENTRY, DeviceID in 15:0
AMDVI_CMD_INV_PAGES equ 3 << 60                  ; INVALIDATE_IOMMU_PAGES, DomainID in 47:32
AMDVI_PAGES_ALL     equ 0x7FFFFFFFFFFFF000 | 3   ; every address: S=1, PDE=1

AMDVI_ADDR_MASK     equ 0x000FFFFFFFFFF000
AMDVI_DTE_BLOCKED   equ 3                        ; V=1, TV=1, Mode 0, IR=IW=0: DMA aborted
AMDVI_DTE_XLATE     equ (1 << 62) | (1 << 61) | (4 << 9) | 3   ; IW, IR, Mode 4, TV, V
AMDVI_PDE_RW        equ (1 << 62) | (1 << 61) | 1               ; IW, IR, PR (+ next level << 9)
AMDVI_PTE_LEAF      equ (1 << 62) | (1 << 61) | (1 << 60) | 1   ; IW, IR, FC, PR; next level 0
AMDVI_DOM_COMPAT    equ 1
AMDVI_DOM_NATIVE    equ 2

AMDVI_R_MALFORMED   equ 1                        ; amdvi_ivrs_parse reasons, index into the name list
AMDVI_R_CONFLICT    equ 2
AMDVI_R_MULTI       equ 3
AMDVI_R_SEGMENT     equ 4
; RCQ-12 0.0.68: amdvi_outcome, read by amdvi_outcome_get. Zero-fill is not_run, never ok.
AMDVI_OUT_NOT_RUN   equ 0
AMDVI_OUT_SILENT    equ 1                        ; IVRS absent, DMAR present: VT-d reports
AMDVI_OUT_SKIP      equ 2
AMDVI_OUT_OK        equ 3
AMDVI_OUT_BAD       equ 4                        ; amdvi_outcome_get only: a state it cannot vouch for

amdvi_ownership_init:
    push rbx
    push r12
    push r13
    call amdvi_observation_reset
    call amdvi_hda_reset
    call amdvi_guest_reset
    mov  byte [rel amdvi_owned], 0
    mov  byte [rel amdvi_enabled], 0
    mov  qword [rel amdvi_mmio], 0
    mov  qword [rel amdvi_native_root], 0
    mov  dword [rel amdvi_pool_next], 0
    mov  dword [rel amdvi_cmd_tail], 0
    mov  dword [rel amdvi_native_n], 0
    mov  dword [rel amdvi_native_mapped], 0
    mov  dword [rel amdvi_events], 0
    mov  byte [rel amdvi_outcome], AMDVI_OUT_NOT_RUN
    mov  edi, 'IVRS'
    call acpi_find_table
    test rax, rax
    jnz  .have_ivrs
    test edx, edx                        ; AF_ABSENT: no IVRS child at all
    jnz  .skip_af
    mov  edi, 'DMAR'
    call acpi_find_table
    test rax, rax                        ; any DMAR child: an Intel platform, VT-d reports
    jnz  .done
    test edx, edx
    jnz  .done
    lea  rsi, [rel str_amdvi_r_no_ivrs]
    jmp  .skip
.skip_af:
    lea  rdi, [rel str_amdvi_af_names]
    mov  esi, edx
    call amdvi_nth
    mov  rsi, rdi
    jmp  .skip
.have_ivrs:
    mov  rbx, rax
    mov  edi, 'DMAR'
    call acpi_find_table
    test rax, rax
    jnz  .skip_both
    test edx, edx
    jnz  .skip_both
    mov  rdi, rbx
    call amdvi_ivrs_parse
    test eax, eax
    jnz  .skip_parse

    ; M-A1 read-only detect marker: the selected IVHD as parsed.
    mov  r12, [rel amdvi_ivhd]
    lea  rdi, [rel str_amdvi_detect]
    movzx esi, byte [r12]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_flags]
    movzx esi, byte [r12 + 1]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_devid]
    movzx esi, word [r12 + 4]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_base]
    mov  rsi, [r12 + 8]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_ivinfo]
    mov  esi, [rel amdvi_ivinfo]
    call amdvi_kv
    xor  esi, esi
    cmp  byte [r12], 0x10
    je   .efr_image
    mov  rsi, [r12 + 24]                 ; 11h/40h carry an EFR image
.efr_image:
    lea  rdi, [rel str_amdvi_k_efr]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string

%if PAOS_LAB_AMDVI_SKIP_OWNERSHIP
    ; Explicit lab comparison only. No MMIO, allocation, enable or DMA hook.
    lea  rsi, [rel str_amdvi_r_lab_skip]
    jmp  .skip
%endif

    ; UC before the first register access, as VT-d does for its DRHD.
    mov  rbx, [r12 + 8]
    mov  [rel amdvi_mmio], rbx
    mov  rdi, rbx
    call mmio_mark_uc
    test eax, eax
    jz   .skip_mmio_uc
    lea  rdi, [rbx + AMDVI_R_STATUS]
    call mmio_mark_uc
    test eax, eax
    jz   .skip_mmio_uc
    lea  rdi, [rel str_amdvi_mmio]
    mov  rsi, [rbx + AMDVI_R_CTRL]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_status]
    mov  rsi, [rbx + AMDVI_R_STATUS]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_excl]
    mov  rsi, [rbx + AMDVI_R_EXCL]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_efr]
    mov  rsi, [rbx + AMDVI_R_EFR]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string

    ; Never take over a unit firmware left translating, or an exclusion
    ; range firmware armed: both are firmware's live protection state.
    ; MMIO is read as aligned dwords: the IOMMU expects 32/64-bit accesses.
    mov  eax, [rbx + AMDVI_R_CTRL]
    test eax, AMDVI_CTRL_EN
    jnz  .skip_iommu_fw
    mov  eax, [rbx + AMDVI_R_EXCL]
    test eax, 1
    jnz  .skip_iommu_fw
    call amdvi_cmd_kat
    test eax, eax
    jz   .skip_kat

    ; The device table lives outside the arena: 2 MiB, only on AMD-Vi hosts
    ; (D-mem). The arena holds every other metadata page plus the canary.
    mov  edi, AMDVI_DEVTAB_BYTES + 4095
    call kmalloc
    test rax, rax
    jz   .skip_alloc
    add  rax, 4095
    and  rax, -4096
    mov  [rel amdvi_devtab], rax
    mov  edi, AMDVI_POOL_BYTES + 4095
    call kmalloc
    test rax, rax
    jz   .skip_alloc
    add  rax, 4095
    and  rax, -4096
    mov  [rel amdvi_pool], rax           ; amdvi_take_page zeroes each page it hands out
    ; D-mem heap census: the bump high-water just after the device table.
    mov  rsi, [rel heap_next]
    sub  rsi, [rel heap_base]
    mov  [rel amdvi_heap_used], rsi
    lea  rdi, [rel str_amdvi_heap]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_size]
    mov  rsi, [rel heap_size]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string

    call amdvi_take_page
    mov  [rel amdvi_cmdbuf], rax
    call amdvi_take_page
    mov  [rel amdvi_evtlog], rax
    ; Reserve and zero the remaining contiguous event pages before any IOPT.
    mov  r12d, AMDVI_EVT_PAGES - 1
.event_pages:
    call amdvi_take_page
    test rax, rax
    jz   .skip_alloc
    dec  r12d
    jnz  .event_pages
    call amdvi_take_page
    mov  [rel amdvi_cw], rax
    call amdvi_take_page
    mov  r12, rax                        ; compat PML4
    call amdvi_take_page
    mov  r13, rax                        ; compat PDPT: 512 x 1 GiB identity leaves
    mov  rax, AMDVI_PDE_RW | (3 << 9)
    or   rax, r13
    mov  [r12], rax
    mov  rdx, AMDVI_PTE_LEAF
    xor  ecx, ecx
.id_leaf:
    mov  rax, rcx
    shl  rax, 30
    or   rax, rdx
    mov  [r13 + rcx*8], rax
    inc  ecx
    cmp  ecx, 512
    jb   .id_leaf
    mov  rax, AMDVI_DTE_XLATE
    or   rax, r12
    mov  [rel amdvi_compat_qw0], rax

    ; F-02 (c), root 22:04:42: no compat-domain requester reaches IOMMU state.
    ; The device table, the arena (command buffer, event log, CW store, every
    ; IOPT page, the canary) and the unit's MMIO leave the identity map before
    ; any DTE names it.
    mov  rdi, [rel amdvi_devtab]
    mov  esi, AMDVI_DEVTAB_BYTES
    call amdvi_compat_carve
    test eax, eax
    jz   .skip_carve
    mov  rdi, [rel amdvi_pool]
    mov  esi, AMDVI_POOL_BYTES
    call amdvi_compat_carve
    test eax, eax
    jz   .skip_carve
    call amdvi_mmio_span
    mov  esi, eax
    mov  rdi, rbx
    call amdvi_compat_carve
    test eax, eax
    jz   .skip_carve

    ; Every DTE valid before anything else: blocked, then compat for each
    ; IVHD-covered DeviceID (the walk was validated by amdvi_ivrs_parse).
    mov  rdi, [rel amdvi_devtab]
    xor  eax, eax
    mov  ecx, AMDVI_DEVTAB_BYTES / 8
    rep  stosq
    mov  rdi, [rel amdvi_devtab]
    mov  ecx, AMDVI_DEVIDS
.blocked:
    mov  qword [rdi], AMDVI_DTE_BLOCKED
    add  rdi, 32
    dec  ecx
    jnz  .blocked
    mov  esi, 1
    call amdvi_ivhd_entries
    test eax, eax
    jnz  .skip_coverage
    mov  rdi, [rel amdvi_devtab]
    mov  esi, AMDVI_DEVTAB_BYTES / 64
    call amdvi_clflush_lines
    mov  rdi, [rel amdvi_pool]
    mov  esi, AMDVI_POOL_PAGES * 64
    call amdvi_clflush_lines
    mfence

    ; Program the unit with translation still off, then start the command
    ; buffer and the event log.
    mov  qword [rbx + AMDVI_R_CTRL], 0
    mov  rax, [rel amdvi_devtab]
    or   rax, AMDVI_DEVTAB_SIZE
    mov  [rbx + AMDVI_R_DEVTAB], rax
    mov  rdx, AMDVI_RING_LEN
    mov  rax, [rel amdvi_cmdbuf]
    or   rax, rdx
    mov  [rbx + AMDVI_R_CMD], rax
    mov  rax, [rel amdvi_evtlog]
    mov  rdx, AMDVI_EVT_LEN
    or   rax, rdx
    mov  [rbx + AMDVI_R_EVT], rax
    xor  eax, eax
    mov  [rbx + AMDVI_R_CMD_HEAD], rax
    mov  [rbx + AMDVI_R_CMD_TAIL], rax
    mov  [rbx + AMDVI_R_EVT_HEAD], rax
    mov  [rbx + AMDVI_R_EVT_TAIL], rax
    mfence

    ; AMD 48882r3.10 section2.3.1: command fetch requires CmdBufEn AND
    ; IommuEn. Prepare final tables offline, including native aliases, before
    ; enabling either. Offline preparation is not a completion-wait receipt.
    lea  rdi, [rel amdvi_native_cb]
    call pci_scan_with_filter
    call amdvi_native_domain_build
    test eax, eax
    jz   .skip_domain
    call amdvi_native_attach
    test eax, eax
    jz   .skip_inval
    js   .skip_coverage
    call amdvi_coverage_ok
    test eax, eax
    jz   .skip_coverage
    mfence

    ; Treat an issued IommuEn as live until cleared. Final DTEs and protected
    ; mappings precede this write; DMA hooks remain unpublished until actual
    ; bounded invalidation completion and event checks below.
    mov  qword [rbx + AMDVI_R_CTRL], AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG | AMDVI_CTRL_EN
    mov  byte [rel amdvi_enabled], 1
    mfence
    mov  eax, [rbx + AMDVI_R_CTRL]
    and  eax, AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG | AMDVI_CTRL_EN
    cmp  eax, AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG | AMDVI_CTRL_EN
    jne  .skip_enable
    mov  ecx, AMDVI_WAIT_SPINS
.run_wait:
    mov  eax, [rbx + AMDVI_R_STATUS]
    and  eax, AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
    cmp  eax, AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
    je   .running
    pause
    dec  ecx
    jnz  .run_wait
    lea  rsi, [rel str_amdvi_r_cmdbuf]
    jmp  .skip_disable
.running:
    call amdvi_observation_arm
    call amdvi_boot_invalidate
    test eax, eax
    jz   .skip_inval
    call amdvi_event_check
    test eax, eax
    jnz  .skip_events
    lea  rdi, [rel amdvi_native_map_range]
    lea  rsi, [rel amdvi_native_unmap_range]
    call dma_iommu_bind
    test eax, eax
    jz   .skip_bind
    mov  byte [rel amdvi_owned], 1
    lea  rdi, [rel amdvi_hda_attach]
    lea  rsi, [rel amdvi_hda_receipt]
    call dma_domain_bind
    test eax, eax
    jz   .skip_bind
    lea  rdi, [rel amdvi_hda_live_receipt]
    call dma_domain_live_bind
    test eax, eax
    jz   .skip_bind
    ; RCQ-12: the ok line prints the recorded counts, so STATUS reports these exact values.
    mov  eax, [rel amdvi_native_n]
    mov  [rel amdvi_out_native], eax
    mov  eax, [rel amdvi_native_mapped]
    mov  [rel amdvi_out_mapped], eax
    mov  byte [rel amdvi_outcome], AMDVI_OUT_OK
    lea  rdi, [rel str_amdvi_ok]
    mov  esi, [rel amdvi_out_native]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_k_mapped]
    mov  esi, [rel amdvi_out_mapped]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string
    jmp  .done

; One fixed token per gate: "[PAOS64] amdvi.ownership.skip reason=<token>".
.skip_both:
    lea  rsi, [rel str_amdvi_r_iommu_both]
    jmp  .skip
.skip_parse:
    lea  rdi, [rel str_amdvi_parse_names]
    mov  esi, eax
    call amdvi_nth
    mov  rsi, rdi
    jmp  .skip
.skip_mmio_uc:
    lea  rsi, [rel str_amdvi_r_mmio_uc]
    jmp  .skip
.skip_iommu_fw:
    lea  rsi, [rel str_amdvi_r_iommu_fw]
    jmp  .skip
.skip_kat:
    lea  rsi, [rel str_amdvi_r_kat]
    jmp  .skip
.skip_carve:
    lea  rsi, [rel str_amdvi_r_carve]
    jmp  .skip
.skip_alloc:
    lea  rsi, [rel str_amdvi_r_alloc]
.skip:
    mov  [rel amdvi_out_tok], rsi            ; RCQ-12: the token this line prints
    mov  byte [rel amdvi_outcome], AMDVI_OUT_SKIP
    lea  rdi, [rel str_amdvi_skip]
    call serial_string
    mov  rdi, rsi
    call serial_string
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string
    jmp  .done
; The unit was programmed: say why, then the bounded disable.
.skip_domain:
    call amdvi_domain_failure_report
    lea  rsi, [rel str_amdvi_r_domain]
    jmp  .skip_disable
.skip_inval:
    call amdvi_invalidation_report
    lea  rsi, [rel str_amdvi_r_inval]
    jmp  .skip_disable
.skip_coverage:
    lea  rsi, [rel str_amdvi_r_coverage]
    jmp  .skip_disable
.skip_events:
    lea  rdi, [rel str_amdvi_event]
    mov  rsi, [rel amdvi_last_event]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string
    lea  rsi, [rel str_amdvi_r_events]
    jmp  .skip_disable
.skip_enable:
    lea  rsi, [rel str_amdvi_r_enable]
    jmp  .skip_disable
.skip_bind:
    lea  rsi, [rel str_amdvi_r_bind]
.skip_disable:
    mov  [rel amdvi_out_tok], rsi
    mov  byte [rel amdvi_outcome], AMDVI_OUT_SKIP
    lea  rdi, [rel str_amdvi_skip]
    call serial_string
    mov  rdi, rsi
    call serial_string
    lea  rdi, [rel str_amdvi_crlf]
    call serial_string
    call amdvi_disable
.done:
    cmp  byte [rel amdvi_outcome], AMDVI_OUT_NOT_RUN ; no ok or skip line: the DMAR exit
    jne  .recorded
    mov  byte [rel amdvi_outcome], AMDVI_OUT_SILENT
.recorded:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Clear IommuEn, the command buffer and the event log. The control register is
; read/write (no GCMD-style persistent-bit hazard).
amdvi_disable:
    mov  byte [rel amdvi_owned], 0
    mov  qword [rel amdvi_obs_mmio], 0       ; future reads lose provenance; historic queue survives
    mov  qword [rel amdvi_obs_publishing], 0
    mov  rdx, [rel amdvi_mmio]
    test rdx, rdx
    jz   .out
    and  qword [rdx + AMDVI_R_CTRL], ~(AMDVI_CTRL_EN | AMDVI_CTRL_EVTLOG | AMDVI_CTRL_CMDBUF)
    mfence
.out:
    mov  byte [rel amdvi_enabled], 0
    ret

; RDI = label, RSI = value: "<label>0x<16 hex digits>".
amdvi_kv:
    push rsi
    call serial_string
    pop  rdi
    jmp  serial_hex64

; amdvi_outcome_get (RCQ-12, root 19:01:42) -> EAX = the outcome amdvi_ownership_init
;   recorded (AMDVI_OUT_*), EDX/ECX = native/mapped as the ok line printed them, and
;   on SKIP RSI = the reason token. RSI is checked: the start of a whole string in the
;   token table, else EAX = AMDVI_OUT_BAD. Memory only: no MMIO, no lock, no re-probe.
;   Clobbers RAX, RCX, RDX, RSI, RDI.
amdvi_outcome_get:
    movzx eax, byte [rel amdvi_outcome]
    cmp  eax, AMDVI_OUT_OK
    ja   .bad
    mov  edx, [rel amdvi_out_native]
    mov  ecx, [rel amdvi_out_mapped]
    cmp  eax, AMDVI_OUT_SKIP
    jne  .ret
    mov  rsi, [rel amdvi_out_tok]
    lea  rdi, [rel str_amdvi_tokens_end]
    cmp  rsi, rdi
    jae  .bad
    lea  rdi, [rel str_amdvi_r_no_ivrs]      ; the table's first token
    cmp  rsi, rdi
    jb   .bad
    je   .ret
    cmp  byte [rsi - 1], 0                  ; a whole token, never the tail of one
    jne  .bad
.ret:
    ret
.bad:
    mov  eax, AMDVI_OUT_BAD
    ret

; RDI = NUL-separated names, ESI = index -> RDI = that name.
amdvi_nth:
    test esi, esi
    jz   .ret
.scan:
    inc  rdi
    cmp  byte [rdi - 1], 0
    jne  .scan
    dec  esi
    jmp  amdvi_nth
.ret:
    ret

; RDI = start, ESI = 64-byte line count.
amdvi_clflush_lines:
    clflush [rdi]
    add  rdi, 64
    dec  esi
    jnz  amdvi_clflush_lines
    ret

; -> RAX = a zeroed arena page, or 0 when the bounded arena is exhausted.
; Clobbers RAX, RCX, RDI, flags only.
amdvi_take_page:
    mov  eax, [rel amdvi_pool_next]
    cmp  eax, AMDVI_POOL_PAGES
    jae  .none
    inc  dword [rel amdvi_pool_next]
    shl  rax, 12
    add  rax, [rel amdvi_pool]
    push rax
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, 512
    cld
    rep  stosq
    pop  rax
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; IVRS. All reads stay inside the table length and each block's own length.
; ---------------------------------------------------------------------------

; amdvi_ivrs_parse(RDI = IVRS) -> EAX = 0 accepted, else AMDVI_R_*.
; Selects the highest IVHD type describing the one IOMMU (40h > 11h > 10h);
; every other IVHD must name the same unit. Records the IVMD unity/exclusion
; ranges and the alias table, then validates the selected IVHD's entries.
amdvi_ivrs_parse:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  qword [rel amdvi_ivhd], 0
    mov  dword [rel amdvi_ivmd_n], 0
    mov  dword [rel amdvi_alias_n], 0
    mov  eax, [r12 + 4]
    cmp  eax, 48
    jb   .malformed
    lea  r13, [r12 + rax]
    mov  eax, [r12 + 36]
    mov  [rel amdvi_ivinfo], eax
    lea  rbx, [r12 + 48]
.block:
    cmp  rbx, r13
    jae  .blocks_done
    lea  rax, [rbx + 4]
    cmp  rax, r13
    ja   .malformed
    movzx ecx, word [rbx + 2]
    cmp  ecx, 4
    jb   .malformed
    lea  r14, [rbx + rcx]
    cmp  r14, r13
    ja   .malformed
    movzx eax, byte [rbx]
    cmp  al, 0x10
    je   .ivhd10
    cmp  al, 0x11
    je   .ivhd40
    cmp  al, 0x40
    je   .ivhd40
    cmp  al, 0x20
    jb   .next
    cmp  al, 0x22
    jbe  .ivmd
    jmp  .next                           ; other block types are skipped, length-checked
.ivhd10:
    cmp  ecx, 24
    jb   .malformed
    jmp  .ivhd
.ivhd40:
    cmp  ecx, 40
    jb   .malformed
.ivhd:
    cmp  word [rbx + 16], 0
    jne  .segment
    mov  rdx, [rbx + 8]
    test rdx, rdx
    jz   .malformed
    test edx, 0x3FFF
    jnz  .malformed
    mov  rcx, [rel amdvi_ivhd]
    test rcx, rcx
    jz   .select
    cmp  rdx, [rcx + 8]
    jne  .multi
    mov  edx, [rbx + 4]                  ; IOMMU DeviceID + capability offset
    cmp  edx, [rcx + 4]
    jne  .conflict
    cmp  al, [rcx]
    jb   .next
    je   .conflict                       ; the same type twice for one unit
.select:
    mov  [rel amdvi_ivhd], rbx
    jmp  .next
.ivmd:
    cmp  ecx, 32
    jne  .malformed
    movzx edx, byte [rbx + 1]            ; 0 unity, 1 IR, 2 IW, 3 exclusion
    test dl, 0x09
    jz   .next
    test dl, 0x08
    jz   .ivmd_devids
    or   dl, 0x06                        ; an exclusion range becomes an IR+IW unity map
.ivmd_devids:
    movzx esi, word [rbx + 4]
    mov  edi, esi
    cmp  al, 0x21
    je   .ivmd_range
    ja   .ivmd_22
    xor  esi, esi                        ; 20h: every DeviceID
    mov  edi, 0xFFFF
    jmp  .ivmd_range
.ivmd_22:
    movzx edi, word [rbx + 6]
    cmp  edi, esi
    jb   .malformed
.ivmd_range:
    mov  r8, [rbx + 16]
    mov  r9, r8
    add  r9, [rbx + 24]
    jc   .malformed
    add  r9, 4095
    jc   .malformed
    and  r9, -4096
    and  r8, -4096
    mov  rax, AMDVI_IVMD_LIMIT
    cmp  r9, rax
    ja   .malformed
    cmp  r9, r8
    jbe  .next
    mov  eax, [rel amdvi_ivmd_n]
    cmp  eax, AMDVI_IVMD_MAX
    jae  .malformed
    inc  dword [rel amdvi_ivmd_n]
    imul eax, eax, 24
    lea  r10, [rel amdvi_ivmd]
    add  r10, rax
    mov  [r10], si
    mov  [r10 + 2], di
    mov  [r10 + 4], edx
    mov  [r10 + 8], r8
    sub  r9, r8
    mov  [r10 + 16], r9
.next:
    mov  rbx, r14
    jmp  .block
.blocks_done:
    cmp  qword [rel amdvi_ivhd], 0
    je   .malformed
    xor  esi, esi
    call amdvi_ivhd_entries
    jmp  .out
.malformed:
    mov  eax, AMDVI_R_MALFORMED
    jmp  .out
.conflict:
    mov  eax, AMDVI_R_CONFLICT
    jmp  .out
.multi:
    mov  eax, AMDVI_R_MULTI
    jmp  .out
.segment:
    mov  eax, AMDVI_R_SEGMENT
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; amdvi_ivhd_entries(ESI = mode) -> EAX = 0, or AMDVI_R_MALFORMED.
; Mode 0 validates the selected IVHD's device entries and records aliases;
; mode 1 writes the compat DTE for every covered DeviceID.
; 4-byte types 00h-3Fh, 8-byte 40h-7Fh; 80h-EFh (16/32-byte) are reserved and
; refused; F0h is bounded by its UID length; undefined 4/8-byte types carry
; no coverage and are skipped.
amdvi_ivhd_entries:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, esi
    mov  rbx, [rel amdvi_ivhd]
    movzx eax, word [rbx + 2]
    lea  r13, [rbx + rax]
    mov  eax, 40
    cmp  byte [rbx], 0x10
    jne  .hdr
    mov  eax, 24
.hdr:
    add  rbx, rax
    mov  r12d, -1                        ; open range start
    mov  r14d, -1                        ; open range alias source
.entry:
    cmp  rbx, r13
    jae  .end
    movzx eax, byte [rbx]
    mov  ecx, 4
    cmp  al, 0x40
    jb   .sized
    mov  ecx, 8
    cmp  al, 0x80
    jb   .sized
    cmp  al, 0xF0
    jne  .bad
    lea  rdx, [rbx + 22]
    cmp  rdx, r13
    ja   .bad
    movzx ecx, byte [rbx + 21]
    add  ecx, 22
.sized:
    lea  rdx, [rbx + rcx]
    cmp  rdx, r13
    ja   .bad
    push rdx
    movzx edi, word [rbx + 1]
    mov  esi, edi
    mov  edx, -1
    cmp  al, 0x01
    je   .all
    cmp  al, 0x02
    je   .cover
    cmp  al, 0x46
    je   .cover
    cmp  al, 0xF0
    je   .cover
    cmp  al, 0x42
    je   .alias_select
    cmp  al, 0x48
    je   .special
    cmp  al, 0x03
    je   .open
    cmp  al, 0x47
    je   .open
    cmp  al, 0x43
    je   .open_alias
    cmp  al, 0x04
    je   .close
    jmp  .advance
.all:
    xor  edi, edi
    mov  esi, 0xFFFF
    jmp  .cover
.alias_select:
    movzx edx, word [rbx + 5]
    jmp  .cover
.special:
    movzx edi, word [rbx + 5]
    mov  esi, edi
    jmp  .cover
.open_alias:
    cmp  r12d, -1
    jne  .bad_pushed
    movzx r14d, word [rbx + 5]
    mov  r12d, edi
    jmp  .advance
.open:
    cmp  r12d, -1
    jne  .bad_pushed
    mov  r12d, edi
    jmp  .advance
.close:
    cmp  r12d, -1
    je   .bad_pushed
    cmp  edi, r12d
    jb   .bad_pushed
    mov  esi, edi
    mov  edi, r12d
    mov  edx, r14d
    mov  r12d, -1
    mov  r14d, -1
.cover:
    mov  r8d, r15d
    call amdvi_cover
    test eax, eax
    jz   .bad_pushed
.advance:
    pop  rbx
    jmp  .entry
.end:
    xor  eax, eax
    cmp  r12d, -1                        ; an unterminated range
    je   .out
    jmp  .bad
.bad_pushed:
    pop  rdx
.bad:
    mov  eax, AMDVI_R_MALFORMED
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; amdvi_cover(EDI = first, ESI = last, EDX = alias source or -1, R8D = mode)
; -> EAX = 1, or 0 when the alias table is full.
amdvi_cover:
    test r8d, r8d
    jnz  .apply
    cmp  edx, -1
    je   .ok
    mov  eax, [rel amdvi_alias_n]
    cmp  eax, AMDVI_ALIAS_MAX
    jae  .full
    inc  dword [rel amdvi_alias_n]
    lea  rcx, [rel amdvi_alias]
    mov  [rcx + rax*8], di
    mov  [rcx + rax*8 + 2], si
    mov  [rcx + rax*8 + 4], dx
    jmp  .ok
.apply:
    mov  r9d, edi
    mov  r10d, esi
.apply_one:
    mov  edi, r9d
    call amdvi_dte_compat
    inc  r9d
    cmp  r9d, r10d
    jbe  .apply_one
    cmp  edx, -1
    je   .ok
    mov  edi, edx
    call amdvi_dte_compat
.ok:
    mov  eax, 1
    ret
.full:
    xor  eax, eax
    ret

amdvi_dte_compat:
    mov  rsi, [rel amdvi_compat_qw0]
    mov  ecx, AMDVI_DOM_COMPAT
    ; fall through
; amdvi_dte_set(EDI = DeviceID, RSI = qword 0, RCX = qword 1). Qwords 3..1
; first, qword 0 (V/TV/Mode/IR/IW) last, then the line is flushed.
; Clobbers RAX, RDI only.
amdvi_dte_set:
    movzx edi, di
    shl  edi, 5
    mov  rax, [rel amdvi_devtab]
    add  rax, rdi
    mov  qword [rax + 24], 0
    mov  qword [rax + 16], 0
    mov  [rax + 8], rcx
    mov  [rax], rsi
    clflush [rax]
    ret

; amdvi_mmio_span -> EAX = the bytes of MMIO the carve takes from [amdvi_mmio]
; (srcreview S3b N7). As Linux init_iommu_one sizes it: 512 KiB when the unit
; has performance counters, else 16 KiB. IVHD 10h: its EFR attribute names
; both PC banks (bits 16:13) and counters (bits 22:17); 11h/40h: the EFR image's
; PCSup. The live EFR's PCSup also counts (10h's fallback when the attribute is
; 0), so a source that disagrees keeps 512 KiB: over-carving is the safe side.
; Clobbers RCX, RDX.
amdvi_mmio_span:
    mov  eax, AMDVI_MMIO_BYTES
    mov  rcx, [rel amdvi_mmio]
    mov  edx, [rcx + AMDVI_R_EFR]
    test edx, AMDVI_EFR_PCSUP
    jnz  .out
    mov  rcx, [rel amdvi_ivhd]
    cmp  byte [rcx], 0x10
    jne  .image
    mov  edx, [rcx + 20]                 ; 10h EFR attribute
    test edx, 0xF << 13
    jz   .core
    test edx, 0x3F << 17
    jnz  .out
    jmp  .core
.image:
    test dword [rcx + 24], AMDVI_EFR_PCSUP
    jnz  .out
.core:
    mov  eax, AMDVI_MMIO_CORE
.out:
    ret

; amdvi_compat_carve(RDI = first byte, ESI = bytes) -> EAX = 1, or 0 when an IVMD
; unity range overlaps the range (firmware's map wins: fail closed) or the arena
; is exhausted. Every 4 KiB page of the range becomes not-present in the compat
; domain; a 1 GiB or 2 MiB identity leaf over it is first split into 512
; identity leaves one level down. A page at or above 512 GiB is already outside
; the domain. Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
amdvi_compat_carve:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    and  rbx, -4096                      ; the first page
    lea  r12, [rdi + rsi + 4095]
    and  r12, -4096                      ; the end, exclusive
    xor  ecx, ecx
.ivmd:
    cmp  ecx, [rel amdvi_ivmd_n]
    jae  .page
    imul eax, ecx, 24
    lea  rdx, [rel amdvi_ivmd]
    mov  r8, [rdx + rax + 8]
    mov  r9, [rdx + rax + 16]
    add  r9, r8                          ; amdvi_ivrs_parse refused a wrap
    inc  ecx
    cmp  r8, r12
    jae  .ivmd
    cmp  r9, rbx
    jbe  .ivmd
    jmp  .fail
.page:
    cmp  rbx, r12
    jae  .ok
    mov  r13, [rel amdvi_compat_qw0]
    mov  rax, AMDVI_ADDR_MASK
    and  r13, rax                        ; the PML4
    mov  r8d, 39
.level:
    mov  ecx, r8d
    mov  rdx, rbx
    shr  rdx, cl
    and  edx, 0x1FF
    lea  r13, [r13 + rdx*8]              ; this level's entry for the page
    cmp  r8d, 12
    je   .clear
    mov  rax, [r13]
    test al, 1
    jz   .next                           ; not present: already unreachable
    test eax, 7 << 9
    jnz  .down
    ; An identity leaf of 2^R8 bytes (only a PDPT or PD entry can be one):
    ; replace it with a table of 512 identity leaves of 2^(R8-9) bytes.
    call amdvi_take_page
    test rax, rax
    jz   .fail
    mov  r9, [r13]
    mov  r10, AMDVI_ADDR_MASK
    and  r9, r10                         ; the leaf's base
    mov  r10, AMDVI_PTE_LEAF
    or   r9, r10
    lea  ecx, [r8 - 9]
    mov  r10d, 1
    shl  r10, cl                         ; the child leaf size
    xor  edx, edx
.fill:
    mov  [rax + rdx*8], r9
    add  r9, r10
    inc  edx
    cmp  edx, 512
    jb   .fill
    mov  ecx, 2 << 9                     ; next level 2 under a PDPT entry,
    cmp  r8d, 30
    je   .link
    mov  ecx, 1 << 9                     ; 1 under a PD entry
.link:
    mov  r10, AMDVI_PDE_RW
    or   rax, r10
    or   rax, rcx
    mov  [r13], rax
.down:
    mov  r10, AMDVI_ADDR_MASK
    and  rax, r10
    mov  r13, rax
    sub  r8d, 9
    jmp  .level
.clear:
    mov  qword [r13], 0
.next:
    add  rbx, 4096
    jmp  .page
.ok:
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; pci_scan_with_filter callback(EDI=bus, ESI=dev, EDX=fn, ECX=vendev): PaOS's
; native DMA requesters (VT-d DID 2's set: NVMe, SATA, Intel Ethernet).
amdvi_native_cb:
    push rbx
    push r12
    mov  r12d, ecx
    mov  ebx, edi
    shl  ebx, 8
    shl  esi, 3
    or   ebx, esi
    or   ebx, edx
    mov  edi, ebx
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 16
    cmp  ax, 0x0108
    je   .take
    cmp  ax, 0x0106
    je   .take
    cmp  ax, 0x0200
    jne  .out
    cmp  r12w, 0x8086
    jne  .out
.take:
    mov  eax, [rel amdvi_native_n]
    cmp  eax, AMDVI_NATIVE_MAX
    jae  .out                            ; an extra requester stays in the compat domain
    lea  rdx, [rel amdvi_native_bdf]
    mov  [rdx + rax*4], ebx
    inc  dword [rel amdvi_native_n]
.out:
    pop  r12
    pop  rbx
    ret

; Native domain: a 4-level root, then every live core/dma record and every
; IVMD range that names a native requester, as identity 4 KiB leaves.
amdvi_native_domain_build:
    push rbx
    push r12
    mov  qword [rel amdvi_domain_stage], 1
    mov  qword [rel amdvi_domain_index], -1
    mov  qword [rel amdvi_domain_base], 0
    mov  qword [rel amdvi_domain_len], 0
    call amdvi_take_page
    test rax, rax
    jz   .bad
    mov  [rel amdvi_native_root], rax
    mov  rdx, AMDVI_DTE_XLATE
    or   rax, rdx
    mov  [rel amdvi_native_qw0], rax
    xor  r12d, r12d
.record:
    cmp  r12d, DMA_IOMMU_SLOTS
    jae  .ivmd
    mov  edi, r12d
    call dma_iommu_record
    test rdx, rdx
    jz   .record_next
    test ecx, ecx                        ; the native domain holds tag-0 records only
    jnz  .record_next
    mov  qword [rel amdvi_domain_stage], 2
    mov  [rel amdvi_domain_index], r12
    mov  [rel amdvi_domain_base], rax
    mov  [rel amdvi_domain_len], rdx
    mov  rdi, rax
    mov  rsi, rdx
    xor  edx, edx
    call amdvi_native_prepare_range
    test rax, rax
    jz   .bad
.record_next:
    inc  r12d
    jmp  .record
.ivmd:
    xor  r12d, r12d
.ivmd_one:
    cmp  r12d, [rel amdvi_ivmd_n]
    jae  .ok
    imul eax, r12d, 24
    lea  rbx, [rel amdvi_ivmd]
    add  rbx, rax
    xor  ecx, ecx
.native_in_range:
    cmp  ecx, [rel amdvi_native_n]
    jae  .ivmd_next
    lea  rax, [rel amdvi_native_bdf]
    mov  eax, [rax + rcx*4]
    inc  ecx
    cmp  ax, [rbx]
    jb   .native_in_range
    cmp  ax, [rbx + 2]
    ja   .native_in_range
    mov  rdi, [rbx + 8]
    mov  rsi, [rbx + 16]
    mov  qword [rel amdvi_domain_stage], 3
    mov  [rel amdvi_domain_index], r12
    mov  [rel amdvi_domain_base], rdi
    mov  [rel amdvi_domain_len], rsi
    xor  edx, edx
    call amdvi_native_prepare_range
    test rax, rax
    jz   .bad
.ivmd_next:
    inc  r12d
    jmp  .ivmd_one
.ok:
    mov  qword [rel amdvi_domain_stage], 0
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Failure-only boot report, before the existing bounded disable. The saved
; descriptor is the exact request passed to the native mapper; these values
; grant no mapping/ownership credit and never change a retry or return path.
amdvi_domain_failure_report:
    push rbx
    mov  rbx, [rel amdvi_mmio]
    lea  rdi, [rel str_amdvi_df_stage]
    mov  rsi, [rel amdvi_domain_stage]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_index]
    mov  rsi, [rel amdvi_domain_index]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_base]
    mov  rsi, [rel amdvi_domain_base]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_len]
    mov  rsi, [rel amdvi_domain_len]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_pool]
    mov  esi, [rel amdvi_pool_next]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_timeouts]
    mov  esi, [rel amdvi_cw_timeouts]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_ctrl]
    mov  rsi, [rbx + AMDVI_R_CTRL]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_status]
    mov  rsi, [rbx + AMDVI_R_STATUS]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_head]
    mov  rsi, [rbx + AMDVI_R_CMD_HEAD]
    call amdvi_kv
    lea  rdi, [rel str_amdvi_df_tail]
    mov  rsi, [rbx + AMDVI_R_CMD_TAIL]
    call amdvi_kv
    pop  rbx
    lea  rdi, [rel str_amdvi_crlf]
    jmp  serial_string

; Move each native requester (and the alias source it reaches the IOMMU as)
; from compat to the native domain while CTRL=0. The post-enable all-DTE
; sweep covers every requester and alias. -> EAX = 1; 0 = not offline;
; -1 = a native requester no IVHD entry covers (it would be blocked).
amdvi_native_attach:
    push rbx
    push r12
    ; Private bootstrap entry: never edit a live unit without invalidation.
    cmp  byte [rel amdvi_owned], 0
    jne  .refuse
    cmp  byte [rel amdvi_enabled], 0
    jne  .refuse
    mov  rax, [rel amdvi_mmio]
    test rax, rax
    jz   .refuse
    cmp  qword [rax + AMDVI_R_CTRL], 0
    jne  .refuse
    xor  r12d, r12d
.one:
    cmp  r12d, [rel amdvi_native_n]
    jae  .ok
    lea  rax, [rel amdvi_native_bdf]
    mov  ebx, [rax + r12*4]
    mov  rax, [rel amdvi_devtab]
    mov  edx, ebx
    shl  edx, 5
    mov  rdx, [rax + rdx]
    cmp  rdx, [rel amdvi_compat_qw0]
    jne  .uncovered
    mov  edi, ebx
    call amdvi_dte_native
    xor  ecx, ecx
.alias:
    cmp  ecx, [rel amdvi_alias_n]
    jae  .next
    lea  rax, [rel amdvi_alias]
    lea  rax, [rax + rcx*8]
    inc  ecx
    cmp  bx, [rax]
    jb   .alias
    cmp  bx, [rax + 2]
    ja   .alias
    movzx edi, word [rax + 4]
    push rcx
    call amdvi_dte_native
    pop  rcx
    jmp  .alias
.next:
    inc  r12d
    jmp  .one
.refuse:
    xor  eax, eax
    jmp  .out
.uncovered:
    mov  eax, -1
    jmp  .out
.ok:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

amdvi_dte_native:
    mov  rsi, [rel amdvi_native_qw0]
    mov  ecx, AMDVI_DOM_NATIVE
    jmp  amdvi_dte_set

; -> EAX = 1 when every one of the 65,536 DTEs has V=1 and TV=1.
amdvi_coverage_ok:
    mov  rdx, [rel amdvi_devtab]
    mov  ecx, AMDVI_DEVIDS
.one:
    mov  eax, [rdx]
    and  eax, 3
    cmp  eax, 3
    jne  .no
    add  rdx, 32
    dec  ecx
    jnz  .one
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Invalidation failure telemetry only; no cursor/token repair or bypass.
amdvi_invalidation_report:
    push rbx
    mov rbx,[rel amdvi_mmio]
    test rbx,rbx
    jz .out
    lea rdi,[rel str_amdvi_inval_head]
    mov rsi,[rbx+AMDVI_R_CMD_HEAD]
    call amdvi_kv
    lea rdi,[rel str_amdvi_inval_tail]
    mov rsi,[rbx+AMDVI_R_CMD_TAIL]
    call amdvi_kv
    lea rdi,[rel str_amdvi_inval_timeouts]
    mov esi,[rel amdvi_cw_timeouts]
    call amdvi_kv
    lea rdi,[rel str_amdvi_crlf]
    call serial_string
.out:
    pop rbx
    ret

; -> EAX = events pending (0 = clean). Overflow counts as one. The first
; pending entry is kept in amdvi_last_event; the log is consumed.
amdvi_event_check:
    mov  rdx, [rel amdvi_mmio]
    mov  eax, [rdx + AMDVI_R_EVT_HEAD]
    and  eax, AMDVI_PTR_MASK
    mov  ecx, [rdx + AMDVI_R_EVT_TAIL]
    and  ecx, AMDVI_PTR_MASK
    pushfq
    mov  byte [rel amdvi_obs_consuming], 1  ; only this actual consumer may activate the observer
    call amdvi_observation_poll
    mov  byte [rel amdvi_obs_consuming], 0
    popfq
    cmp  eax, ecx
    jne  .pending
    mov  eax, [rdx + AMDVI_R_STATUS]
    test eax, AMDVI_STS_EVT_OVF
    jz   .clean
    mov  eax, 1
    jmp  .count
.pending:
    mov  r8, [rel amdvi_evtlog]
    mov  r8, [r8 + rax]
    mov  [rel amdvi_last_event], r8
    mov  [rdx + AMDVI_R_EVT_HEAD], rcx
    sub  ecx, eax
    and  ecx, AMDVI_EVT_MASK
    shr  ecx, 4
    mov  eax, ecx
.count:
    add  [rel amdvi_events], eax
    ret
.clean:
    xor  eax, eax
    ret


; Native numeric observation, not translation policy. The witness is minted
; only after this boot owner has programmed and started its event log. The two
; existing consumers precede final amdvi_owned: requiring that final bit would
; make this producer unreachable. Disable revokes future reads, but already
; observed historical detail remains valid until the next owner generation.
amdvi_observation_reset:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    cmp  dword [rel amdvi_obs_test_depth], 0
    jne  .out
    mov  qword [rel amdvi_obs_mmio], 0
    mov  qword [rel amdvi_obs_log], 0
    mov  qword [rel amdvi_obs_publishing], 0
    mov  byte [rel amdvi_obs_consuming], 0
    mov  byte [rel amdvi_obs_overflow], 0
    cmp  qword [rel amdvi_obs_generation], -1
    je   .out
    inc  qword [rel amdvi_obs_generation]
.out:
    ret

; Current software ownership lifetime only; no IO or pointer dereference.
amdvi_observation_generation:
    mov  rax, [rel amdvi_obs_generation]
    test rax, rax
    jz   .none
    cmp  rax, -1
    jne  .out
.none:
    xor  eax, eax
.out:
    ret

; A generic numeric constructor or packet argument cannot create provenance.
; This token exists only during the actual consumer's numeric publication.
amdvi_observation_publishing:
    mov  rax, [rel amdvi_obs_publishing]
    ret

amdvi_observation_arm:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    cmp  dword [rel amdvi_obs_test_depth], 0
    jne  .out
    sub  rsp, 8
    call amdvi_observation_generation
    test rax, rax
    jz   .done
    call amdvi_observation_binding
    test eax, eax
    jz   .done
    mov  rax, [rel amdvi_evtlog]
    mov  [rel amdvi_obs_log], rax
    mov  rax, [rel amdvi_mmio]
    mov  [rel amdvi_obs_mmio], rax           ; publish owned witness last
.done:
    add  rsp, 8
.out:
    ret

; Read-only check of existing page tables. RDI=byte address, ESI=required leaf
; bits -> EAX1/0. Covers a 2MiB leaf or an existing 4KiB split. No new mapping,
; CR3/PCI/device write. Kernel page-table ownership is the trusted boundary.
amdvi_observation_leaf:
    mov  rax, rdi
    shr  rax, 39                           ; current identity map is below512GiB
    jnz  .no
    cmp  qword [rel pml4_addr], 0
    je   .no
    mov  r8, rdi
    mov  r9d, esi
    sub  rsp, 8
    call paging_pd_entry_ptr
    add  rsp, 8
    test rax, rax
    jz   .no
    mov  rdx, [rax]
    mov  ecx, edx
    and  ecx, 3
    cmp  ecx, 3
    jne  .no
    test dl, 0x80
    jnz  .big
    mov  r10, AMDVI_ADDR_MASK
    and  rdx, r10
    test rdx, rdx
    jz   .no
    mov  rcx, r8
    shr  rcx, 12
    and  ecx, 511
    mov  rdx, [rdx + rcx*8]
    mov  r10, AMDVI_ADDR_MASK
    jmp  .leaf
.big:
    mov  r10, 0x000FFFFFFFE00000
.leaf:
    mov  ecx, edx
    and  ecx, r9d
    cmp  ecx, r9d
    jne  .no
    and  rdx, r10
    and  r8, r10
    cmp  rdx, r8                           ; identity, not an alias
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Validate every event-log page and all three MMIO pages before any
; observer device/log read. Heap bounds include the complete allocated arena.
; Event consumer policy stays unchanged; only its separate log geometry grows.
amdvi_observation_binding:
    push rbx
    push r12
    push r13
    mov  rbx, [rel amdvi_mmio]
    test rbx, rbx
    jz   .no
    test rbx, 4095
    jnz  .no
    mov  r12, [rel amdvi_evtlog]
    test r12, 4095
    jnz  .no
    mov  rax, [rel amdvi_pool]
    add  rax, 4096
    jc   .no
    cmp  rax, r12
    jne  .no
    mov  r13, [rel heap_base]
    test r13, r13
    jz   .no
    mov  rax, r13
    add  rax, [rel heap_size]
    jc   .no
    mov  rdx, [rel heap_next]
    cmp  rdx, r13
    jb   .no
    cmp  rdx, rax
    ja   .no
    cmp  [rel amdvi_pool], r13
    jb   .no
    mov  rcx, [rel amdvi_pool]
    test rcx, 4095
    jnz  .no
    add  rcx, AMDVI_POOL_BYTES
    jc   .no
    cmp  rcx, rdx
    ja   .no
    mov  rdi, rbx
    mov  esi, 0x1B                         ; P|RW|PCD|PWT, true UC
    call amdvi_observation_leaf
    test eax, eax
    jz   .no
    lea  rdi, [rbx + 4096]
    mov  esi, 0x1B
    call amdvi_observation_leaf
    test eax, eax
    jz   .no
    lea  rdi, [rbx + 8192]
    mov  esi, 0x1B
    call amdvi_observation_leaf
    test eax, eax
    jz   .no
    lea  r13, [r12 + AMDVI_EVT_PAGES * 4096]
    mov  rdi, r12
.event_leaf:
    push rdi
    sub  rsp, 8
    mov  esi, 3
    call amdvi_observation_leaf
    add  rsp, 8
    pop  rdi
    test eax, eax
    jz   .no
    add  rdi, 4096
    cmp  rdi, r13
    jb   .event_leaf
    mov  rax, [rbx + AMDVI_R_EVT]
    mov  rdx, AMDVI_EVT_LEN
    or   rdx, r12
    cmp  rax, rdx
    jne  .no
    mov  eax, [rbx + AMDVI_R_CTRL]
    and  eax, AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG
    cmp  eax, AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG
    jne  .no
    mov  eax, [rbx + AMDVI_R_STATUS]
    and  eax, AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
    cmp  eax, AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Transparent observer carrier: RAX/RCX are the legacy consumer's masked
; head/tail snapshot. Its original result/register writes remain authoritative.
amdvi_observation_poll:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 8
    call amdvi_observation_read
    add  rsp, 8
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    popfq
    ret

; Only IO_PAGE_FAULT(type2) has a supported requester interpretation here.
; Linux/AMD event ABI: event[1] bits31:28 = code, event[0] bits15:0 = DeviceID.
; No address, domain, tag, raw flags or second qword enters the native queue.
; Remaining consumed entries/unsupported first/overflow are summary-only lost
; detail, never fabricated typed faults. One extra entry read, no hardware loop.
amdvi_observation_read:
    cmp  byte [rel amdvi_obs_consuming], 1
    jne  .out
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    cmp  dword [rel amdvi_obs_test_depth], 0
    jne  .out
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, eax
    mov  r13d, ecx
    call amdvi_observation_generation
    test rax, rax
    jz   .done
    mov  r14, rax
    mov  rbx, [rel amdvi_obs_mmio]
    test rbx, rbx
    jz   .done
    cmp  rbx, [rel amdvi_mmio]
    jne  .done
    mov  rax, [rel amdvi_evtlog]
    cmp  rax, [rel amdvi_obs_log]
    jne  .done
    call amdvi_observation_binding
    test eax, eax
    jz   .done
    mov  rax, [rbx + AMDVI_R_EVT_HEAD]         ; full64 reserved/cursor bits, no truncation
    mov  rcx, [rbx + AMDVI_R_EVT_TAIL]
    cmp  rax, AMDVI_EVT_MASK
    ja   .done
    cmp  rcx, AMDVI_EVT_MASK
    ja   .done
    test al, 15
    jnz  .done
    test cl, 15
    jnz  .done
    cmp  eax, r12d                           ; a changing snapshot is unproven
    jne  .done
    cmp  ecx, r13d
    jne  .done
    mov  r15d, [rbx + AMDVI_R_STATUS]
    test r15d, AMDVI_STS_EVT_OVF
    jnz  .overflow_live
    mov  byte [rel amdvi_obs_overflow], 0
.overflow_live:
    cmp  eax, ecx
    je   .empty
    sub  ecx, eax
    and  ecx, AMDVI_EVT_MASK
    shr  ecx, 4
    mov  edx, ecx                           ; exact original consumed-entry count
    mov  rdi, [rel amdvi_evtlog]
    mov  rax, [rdi + rax]                   ; complete16B span validated, header only
    mov  rsi, rax
    shr  rsi, 60
    cmp  esi, 2
    je   .supported
    xor  esi, esi                          ; unknown/unsupported: no requester interpretation
    xor  edi, edi
    jmp  .publish
.supported:
    movzx edi, ax
.publish:
    mov  [rel amdvi_obs_publishing], r14
    mov  rcx, r14
    call iommu_sec_enqueue_amd
    mov  qword [rel amdvi_obs_publishing], 0
    test r15d, AMDVI_STS_EVT_OVF
    jz   .done
.empty:
    test r15d, AMDVI_STS_EVT_OVF
    jz   .done
    cmp  byte [rel amdvi_obs_overflow], 0
    jne  .done
    mov  byte [rel amdvi_obs_overflow], 1      ; sticky status is one unknown-loss episode
    xor  edi, edi
    xor  esi, esi
    mov  edx, 1
    jmp  .overflow_publish
.overflow_publish:
    mov  [rel amdvi_obs_publishing], r14
    mov  rcx, r14
    call iommu_sec_enqueue_amd
    mov  qword [rel amdvi_obs_publishing], 0
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; ---------------------------------------------------------------------------
; Command buffer. Callers hold amdvi_cmd_lock.
; ---------------------------------------------------------------------------

; amdvi_cmd_put(RDI = qword 0, RSI = qword 1) -> EAX = 1, or 0 when full.
amdvi_cmd_put:
    mov  eax, [rel amdvi_cmd_tail]
    lea  ecx, [rax + 16]
    and  ecx, AMDVI_RING_MASK
    mov  rdx, [rel amdvi_mmio]
    mov  edx, [rdx + AMDVI_R_CMD_HEAD]
    and  edx, AMDVI_PTR_MASK
    cmp  ecx, edx
    je   .full
    mov  rdx, [rel amdvi_cmdbuf]
    mov  [rdx + rax], rdi
    mov  [rdx + rax + 8], rsi
    mov  [rel amdvi_cmd_tail], ecx
    mov  eax, 1
    ret
.full:
    xor  eax, eax
    ret

; amdvi_cmd_sync -> EAX = 1 only when this COMPLETION_WAIT's token is seen in
; the store qword: every command before it has completed. A timeout, a full
; ring or a stopped command buffer is 0.
amdvi_cmd_sync:
    mov  rsi, [rel amdvi_token]
    inc  rsi
    jnz  .token
    inc  rsi                             ; the token is never 0, the store's initial value
.token:
    mov  [rel amdvi_token], rsi
    mov  rdi, [rel amdvi_cw]
    mov  qword [rdi], 0
    call amdvi_enc_cw
    call amdvi_cmd_put
    test eax, eax
    jz   .fail
    mfence                               ; the entries are in memory before the tail moves
    mov  rdx, [rel amdvi_mmio]
    mov  eax, [rel amdvi_cmd_tail]
    mov  [rdx + AMDVI_R_CMD_TAIL], rax
    mov  rdi, [rel amdvi_cw]
    mov  rsi, [rel amdvi_token]
    mov  ecx, AMDVI_WAIT_SPINS
.poll:
    cmp  [rdi], rsi
    je   .done
    mov  eax, [rdx + AMDVI_R_STATUS]
    test eax, AMDVI_STS_CMD_RUN
    jz   .fail                           ; the unit stopped fetching
    pause
    dec  ecx
    jnz  .poll
    inc  dword [rel amdvi_cw_timeouts]
.fail:
    xor  eax, eax
    ret
.done:
    mov  eax, 1
    ret

; Encoders (SPEC field tables; amdvi_cmd_kat pins them before the first use).
; amdvi_enc_cw(RDI = store address, RSI = token) -> RDI/RSI = the command.
amdvi_enc_cw:
    mov  rax, AMDVI_CW_ADDR_MASK
    and  rdi, rax
    mov  rax, AMDVI_CMD_CW | AMDVI_CW_STORE
    or   rdi, rax
    ret

; amdvi_enc_inv_dte(EDI = DeviceID) -> RDI/RSI.
amdvi_enc_inv_dte:
    movzx edi, di
    mov  rax, AMDVI_CMD_INV_DTE
    or   rdi, rax
    xor  esi, esi
    ret

; amdvi_enc_inv_pages(EDI = DomainID) -> RDI/RSI: every page of the domain.
amdvi_enc_inv_pages:
    movzx edi, di
    shl  rdi, 32
    mov  rax, AMDVI_CMD_INV_PAGES
    or   rdi, rax
    mov  rsi, AMDVI_PAGES_ALL
    ret

; -> EAX = 1 when each encoder reproduces its hand-derived vector.
amdvi_cmd_kat:
    sub  rsp, 8
    mov  ecx, [rel amdvi_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel amdvi_obs_test_depth], 1
    call amdvi_cmd_kat_body
    mov  ecx, [rsp]
    mov  [rel amdvi_obs_test_depth], ecx
    add  rsp, 8
    ret

amdvi_cmd_kat_body:
    push rbx
    lea  rbx, [rel amdvi_kat_vectors]
    mov  rdi, [rbx]
    mov  rsi, [rbx + 8]
    call amdvi_enc_cw
    cmp  rdi, [rbx + 16]
    jne  .bad
    cmp  rsi, [rbx + 24]
    jne  .bad
    mov  edi, [rbx + 32]
    call amdvi_enc_inv_dte
    cmp  rdi, [rbx + 40]
    jne  .bad
    test rsi, rsi
    jnz  .bad
    mov  edi, [rbx + 48]
    call amdvi_enc_inv_pages
    cmp  rdi, [rbx + 56]
    jne  .bad
    cmp  rsi, [rbx + 64]
    jne  .bad
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; amdvi_flush_domain(EDI = DomainID) -> EAX. Slot contract: after EAX=1, no
; stale DMA translation is usable at the next device DMA.
amdvi_flush_domain:
    push rdi
    lea  rdi, [rel amdvi_cmd_lock]
    call spin_acquire
    pop  rdi
    call amdvi_enc_inv_pages
    call amdvi_cmd_put
    test eax, eax
    jz   .unlock
    call amdvi_cmd_sync
.unlock:
    push rax
    lea  rdi, [rel amdvi_cmd_lock]
    call spin_release
    pop  rax
    ret

; amdvi_flush_dte(EDI = DeviceID) -> EAX. Invalidates the DTE and every alias
; source the IVRS maps this DeviceID to. Slot contract as above.
amdvi_flush_dte:
    push rbx
    push r12
    mov  ebx, edi
    lea  rdi, [rel amdvi_cmd_lock]
    call spin_acquire
    mov  edi, ebx
    call amdvi_enc_inv_dte
    call amdvi_cmd_put
    test eax, eax
    jz   .unlock
    xor  r12d, r12d
.alias:
    cmp  r12d, [rel amdvi_alias_n]
    jae  .sync
    lea  rax, [rel amdvi_alias]
    lea  rax, [rax + r12*8]
    inc  r12d
    cmp  bx, [rax]
    jb   .alias
    cmp  bx, [rax + 2]
    ja   .alias
    movzx edi, word [rax + 4]
    call amdvi_enc_inv_dte
    call amdvi_cmd_put
    test eax, eax
    jz   .unlock
    jmp  .alias
.sync:
    call amdvi_cmd_sync
.unlock:
    push rax
    lea  rdi, [rel amdvi_cmd_lock]
    call spin_release
    pop  rax
    pop  r12
    pop  rbx
    ret

; Boot-only bulk producer. Caller holds amdvi_cmd_lock and synchronizes each
; batch before producing another. AMD IOMMU spec 48882 rev3.10 section2.4 and
; MMIO 2000h/2008h: head advances after fetch/validation and cannot refetch;
; tail must never catch/pass head. One validated head snapshot conservatively
; reserves 128 commands plus their COMPLETION_WAIT, leaving the empty slot.
; Hardware can only free more of this reserved space while software fills it.
; This is capacity accounting, never completion evidence: amdvi_cmd_sync still
; publishes after MFENCE and waits for its exact fresh 64-bit completion token.
; EDI=first DeviceID -> EAX=1 or 0; rejection writes no ring bytes or cursors.
amdvi_boot_dte_batch:
    cmp  edi, AMDVI_DEVIDS - AMDVI_SYNC_BATCH
    ja   .fail
    mov  eax, [rel amdvi_cmd_tail]
    cmp  eax, AMDVI_RING_MASK
    ja   .fail
    test al, 15
    jnz  .fail
    mov  rdx, [rel amdvi_mmio]
    mov  rdx, [rdx + AMDVI_R_CMD_HEAD]
    cmp  rdx, AMDVI_RING_MASK
    ja   .fail
    test dl, 15
    jnz  .fail
    mov  ecx, edx
    sub  ecx, eax
    sub  ecx, 16                          ; keep one entry unused
    and  ecx, AMDVI_RING_MASK
    cmp  ecx, (AMDVI_SYNC_BATCH + 1) * 16 ; reserve the completion too
    jb   .fail
    mov  r8, [rel amdvi_cmdbuf]
    mov  rdx, AMDVI_CMD_INV_DTE
    mov  edi, edi                         ; EDI input, never propagate upper bits
    or   rdi, rdx                         ; range check keeps DeviceID in 15:0
    mov  ecx, AMDVI_SYNC_BATCH
.fill:
    mov  [r8 + rax], rdi
    mov  qword [r8 + rax + 8], 0
    add  eax, 16
    and  eax, AMDVI_RING_MASK
    inc  rdi
    dec  ecx
    jnz  .fill
    mov  [rel amdvi_cmd_tail], eax        ; private cursor; no MMIO publication
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; Boot: invalidate all 65,536 DTEs (one COMPLETION_WAIT per batch), then
; domains 1 and 2. Selective commands only (no INVALIDATE_ALL; VT-d parity).
amdvi_boot_invalidate:
    push rbx
    lea  rdi, [rel amdvi_cmd_lock]
    call spin_acquire
    xor  ebx, ebx
.dte:
    mov  edi, ebx
    call amdvi_boot_dte_batch
    test eax, eax
    jz   .unlock
    add  ebx, AMDVI_SYNC_BATCH
    call amdvi_cmd_sync
    test eax, eax
    jz   .unlock
    cmp  ebx, AMDVI_DEVIDS
    jb   .dte
    mov  edi, AMDVI_DOM_COMPAT
    call amdvi_enc_inv_pages
    call amdvi_cmd_put
    test eax, eax
    jz   .unlock
    mov  edi, AMDVI_DOM_NATIVE
    call amdvi_enc_inv_pages
    call amdvi_cmd_put
    test eax, eax
    jz   .unlock
    call amdvi_cmd_sync
.unlock:
    push rax
    lea  rdi, [rel amdvi_cmd_lock]
    call spin_release
    pop  rax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Native domain hooks (dma_iommu_bind). The VT-d DID-2 shape: preflight,
; lazily allocated levels from the bounded arena, identity 4 KiB leaves, a
; domain flush before success, and rollback/restore when the flush fails.
; ---------------------------------------------------------------------------

; RDI = IOVA -> RAX = &level-1 PTE when every upper level exists, else 0.
amdvi_native_leaf_slot:
    mov  r11, [rel amdvi_native_root]
    mov  ecx, 39
    mov  r9d, 3 << 9                    ; fixed four-level tree: next 3, 2, 1
.walk:
    test r11, r11
    jz   .none
    mov  rax, rdi
    shr  rax, cl
    and  eax, 0x1FF
    lea  rax, [r11 + rax*8]
    cmp  ecx, 12
    je   .ret
    mov  r10, [rax]
    test r10b, 1
    jz   .none
    mov  r11d, r10d
    and  r11d, 7 << 9
    cmp  r11d, r9d                      ; never interpret a skipped/reserved level as a link
    jne  .none
    mov  r11, AMDVI_ADDR_MASK
    and  r11, r10
    sub  ecx, 9
    sub  r9d, 1 << 9
    jmp  .walk
.none:
    xor  eax, eax
.ret:
    ret

; RDI = IOVA -> RAX = &present 4 KiB leaf, else 0.
amdvi_native_leaf_ptr:
    call amdvi_native_leaf_slot
    test rax, rax
    jz   .none
    test byte [rax], 1
    jz   .none
    ret
.none:
    xor  eax, eax
    ret

; Boot-only construction, no hardware command or completion credit. The
; actual CTRL read prevents this entry being used against a running unit.
amdvi_native_prepare_range:
    test edx, edx
    jnz  .refuse
    cmp  byte [rel amdvi_owned], 0
    jne  .refuse
    cmp  byte [rel amdvi_enabled], 0
    jne  .refuse
    mov  rax, [rel amdvi_mmio]
    test rax, rax
    jz   .refuse
    cmp  qword [rax + AMDVI_R_CTRL], 0
    jne  .refuse
    mov  r11d, 1
    jmp  amdvi_native_map_range.prepare
.refuse:
    xor  eax, eax
    ret

; amdvi_native_map_range(RDI = virt, RSI = len, EDX = core/dma tag) -> RAX = the
; identity IOVA after actual invalidation, or 0. Tag 0 selects native DID 2;
; tag 1 selects isolated HDA DID 3. No other tag or passthrough fallback.
amdvi_native_map_range:
    cmp  edx, 1
    je   amdvi_hda_map_range
    test edx, edx
    jnz  .refuse
    xor  r11d, r11d
.prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  [rsp], r11d
    call amdvi_guest_range_overlap
    test eax,eax
    jnz .bad
    test rdi, rdi
    jz   .bad                           ; zero is the failure IOVA, never a live mapping
    test rdi, 0x0FFF
    jnz  .bad
    test rsi, rsi
    jz   .bad
    test rsi, 0x0FFF
    jnz  .bad
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bad
    ; These roots have four levels: bits above IOVA47 have no index.
    ; Test the last byte so a range ending exactly at 2^48 stays valid.
    mov  rax, r13
    dec  rax
    shr  rax, 48
    jnz  .bad
    mov  r14, rdi
.preflight:
    cmp  r14, r13
    jae  .pages
    ; IR/IW are cumulative across the full AMD walk, not just the leaf.
    ; Validate every existing upper path before this request allocates or
    ; publishes anything. Missing levels will be built with RW below.
    mov  r15, [rel amdvi_native_root]
    mov  ecx, 39
    mov  r9d, 3 << 9
.upper_permissions:
    test r15, r15
    jz   .bad
    mov  rax, r14
    shr  rax, cl
    and  eax, 0x1FF
    mov  rax, [r15 + rax*8]
    test al, 1
    jz   .upper_ok
    bt   rax, 61                       ; I/O read allowed by this level
    jnc  .bad
    bt   rax, 62                       ; I/O write allowed by this level
    jnc  .bad
    mov  edx, eax
    and  edx, 7 << 9
    cmp  edx, r9d                      ; follow only an exact next-level link
    jne  .bad
    mov  r15, AMDVI_ADDR_MASK
    and  r15, rax
    sub  ecx, 9
    sub  r9d, 1 << 9
    cmp  ecx, 12
    jne  .upper_permissions
.upper_ok:
    mov  rdi, r14
    call amdvi_hda_leaf_ptr
    test rax, rax
    jnz  .bad
    mov  rdi, r14
    call amdvi_native_leaf_ptr
    test rax, rax
    jnz  .bad
    add  r14, 4096
    jmp  .preflight
.pages:
    mov  r14, r12
.page:
    cmp  r14, r13
    jae  .mapped
    mov  r15, [rel amdvi_native_root]
    mov  r8d, 39
    mov  r9d, 3 << 9                     ; the next table's level
.level:
    mov  ecx, r8d
    mov  rax, r14
    shr  rax, cl
    and  eax, 0x1FF
    lea  rbx, [r15 + rax*8]
    cmp  r8d, 12
    je   .leaf
    mov  r15, [rbx]
    test r15b, 1
    jnz  .have
    call amdvi_take_page
    test rax, rax
    jz   .rollback
    mov  r15, rax
    mov  rdx, AMDVI_PDE_RW
    or   rax, rdx
    or   rax, r9
    mov  [rbx], rax
    clflush [rbx]
    jmp  .down
.have:
    mov  eax, r15d
    and  eax, 7 << 9
    cmp  eax, r9d                       ; the software descends exactly one level
    jne  .rollback
.down:
    mov  rax, AMDVI_ADDR_MASK
    and  r15, rax
    sub  r8d, 9
    sub  r9d, 1 << 9
    jmp  .level
.leaf:
    mov  rax, [rbx]
    test al, 1
    jz   .new_leaf
    mov  rdx, AMDVI_ADDR_MASK
    and  rax, rdx
    cmp  rax, r14
    jne  .rollback                       ; never admit an alias
    jmp  .next
.new_leaf:
    mov  rax, AMDVI_PTE_LEAF
    or   rax, r14
    mov  [rbx], rax
    clflush [rbx]
    inc  dword [rel amdvi_native_mapped]
.next:
    add  r14, 4096
    jmp  .page
.mapped:
    mfence
    cmp  dword [rsp], 1
    je   .prepared
    mov  edi, AMDVI_DOM_NATIVE
    call amdvi_flush_domain
    test eax, eax
    jz   .rollback
.prepared:
    mov  rax, r12
    jmp  .out
.rollback:
    ; No device has this IOVA yet: remove exactly this request's leaves.
    mov  r14, r12
.rollback_page:
    cmp  r14, r13
    jae  .rollback_flush
    mov  rdi, r14
    call amdvi_native_leaf_ptr
    test rax, rax
    jz   .rollback_next
    mov  rdx, [rax]
    mov  rcx, AMDVI_ADDR_MASK
    and  rdx, rcx
    cmp  rdx, r14
    jne  .rollback_next
    mov  qword [rax], 0
    clflush [rax]
    cmp  dword [rel amdvi_native_mapped], 0
    je   .rollback_next
    dec  dword [rel amdvi_native_mapped]
.rollback_next:
    add  r14, 4096
    jmp  .rollback_page
.rollback_flush:
    mfence
    cmp  dword [rsp], 1
    je   .bad
    mov  edi, AMDVI_DOM_NATIVE
    call amdvi_flush_domain              ; best effort; the result stays failure
.bad:
    xor  eax, eax
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    ret

; amdvi_native_unmap_range(RDI = iova, RSI = len, EDX = recorded tag) -> RAX =
; 1/0. Every leaf is preflighted, cleared, and the domain flushed before the
; return (the immediacy rule): the caller retires the record only after EAX=1.
; Tag1 dispatches to isolated HDA DID3; other nonzero tags are refused.
amdvi_native_unmap_range:
    cmp  edx, 1
    je   amdvi_hda_unmap_range
    test edx, edx
    jnz  .refuse
    push rbx
    push r12
    push r13
    push r14
    test rdi, rdi
    jz   .bad                           ; zero is the failure IOVA, never a live mapping
    test rdi, 0x0FFF
    jnz  .bad
    test rsi, rsi
    jz   .bad
    test rsi, 0x0FFF
    jnz  .bad
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bad
    ; These roots have four levels: bits above IOVA47 have no index.
    ; Test the last byte so a range ending exactly at 2^48 stays valid.
    mov  rax, r13
    dec  rax
    shr  rax, 48
    jnz  .bad
    mov  rbx, AMDVI_PTE_LEAF             ; exact encoding reconstructed on flush failure
    mov  r14, r12
.preflight:
    cmp  r14, r13
    jae  .clear_start
    mov  rdi, r14
    call amdvi_native_leaf_ptr
    test rax, rax
    jz   .bad
    ; No journal retains arbitrary leaf flags. Refuse the entire span before
    ; clearing if failure restoration could change permissions or metadata.
    mov  rdx, r14
    or   rdx, rbx
    cmp  [rax], rdx
    jne  .bad
    add  r14, 4096
    jmp  .preflight
.clear_start:
    mov  r14, r12
.clear:
    cmp  r14, r13
    jae  .flush
    mov  rdi, r14
    call amdvi_native_leaf_ptr
    mov  qword [rax], 0
    clflush [rax]
    cmp  dword [rel amdvi_native_mapped], 0
    je   .clear_next
    dec  dword [rel amdvi_native_mapped]
.clear_next:
    add  r14, 4096
    jmp  .clear
.flush:
    mfence
    mov  edi, AMDVI_DOM_NATIVE
    call amdvi_flush_domain
    test eax, eax
    jz   .restore
    mov  eax, 1
    jmp  .out
.restore:
    ; The record remains live: restore exactly the canonical encoding admitted
    ; across the entire span by preflight. Flush failure is never success.
    mov  r14, r12
.restore_page:
    cmp  r14, r13
    jae  .restore_flush
    mov  rdi, r14
    call amdvi_native_leaf_slot
    test rax, rax
    jz   .bad
    mov  rdx, AMDVI_PTE_LEAF
    or   rdx, r14
    mov  [rax], rdx
    clflush [rax]
    inc  dword [rel amdvi_native_mapped]
    add  r14, 4096
    jmp  .restore_page
.restore_flush:
    mfence
    mov  edi, AMDVI_DOM_NATIVE
    call amdvi_flush_domain              ; best effort; the mapping stays live
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    ret

%include "hv/amdvi_hda.asm"
%include "hv/amdvi_guest.asm"

; ---------------------------------------------------------------------------
; Immutable data.
; ---------------------------------------------------------------------------
; amdvi_cmd_kat vectors, derived by hand from the SPEC command formats:
;   COMPLETION_WAIT  store 0x0000_1234_5678_9AB8, token 0xFEED_FACE_0000_0001:
;     dw0 = addr[31:3] | S(bit 0), dw1 = addr[51:32] | opcode 1 << 28,
;     dw2:3 = the token -> 0x1000_1234_5678_9AB9 / 0xFEED_FACE_0000_0001
;     (input address bits 2:0 and 63:52 are dropped: 0xF..F_9ABF in)
;   INVALIDATE_DEVTAB_ENTRY DeviceID 0xFF0A (ff:01.2) -> 0x2000_0000_0000_FF0A / 0
;   INVALIDATE_IOMMU_PAGES DomainID 2 -> dw1 = DomainID | opcode 3 << 28,
;     dw2:3 = all-pages address 0x7FFF_FFFF_FFFF_F000 | PDE | S
;     -> 0x3000_0002_0000_0000 / 0x7FFF_FFFF_FFFF_F003
align 8
amdvi_kat_vectors:
    dq 0xFFF0123456789ABF, 0xFEEDFACE00000001
    dq 0x1000123456789AB9, 0xFEEDFACE00000001
    dq 0x000000000000FF0A, 0x200000000000FF0A
    dq 0x0000000000000002, 0x3000000200000000
    dq 0x7FFFFFFFFFFFF003

str_amdvi_skip:        db "[PAOS64] amdvi.ownership.skip reason=", 0
str_amdvi_crlf:        db 13, 10, 0
str_amdvi_r_no_ivrs:   db "no_ivrs", 0
str_amdvi_r_iommu_both: db "iommu_both", 0
str_amdvi_r_mmio_uc:   db "mmio_uc", 0
str_amdvi_r_iommu_fw:  db "iommu_fw", 0
str_amdvi_r_kat:       db "kat", 0
str_amdvi_r_alloc:     db "alloc", 0
str_amdvi_r_carve:     db "carve", 0
str_amdvi_r_cmdbuf:    db "cmdbuf", 0
str_amdvi_r_domain:    db "domain", 0
str_amdvi_r_inval:     db "inval", 0
str_amdvi_r_coverage:  db "coverage", 0
str_amdvi_r_events:    db "enable_events", 0
str_amdvi_r_enable:    db "enable_readback", 0
str_amdvi_r_bind:      db "bind", 0
; acpi_find_table AF_* states 0..9, then amdvi_ivrs_parse reasons 0..4.
str_amdvi_af_names:    db "ivrs_absent", 0, "ivrs_valid", 0, "ivrs_signature", 0, "ivrs_checksum", 0
                       db "ivrs_length", 0, "ivrs_budget", 0, "ivrs_address", 0, "ivrs_duplicate", 0
                       db "ivrs_entry", 0, "ivrs_unsupported", 0
str_amdvi_parse_names: db "ivrs_ok", 0, "ivrs_malformed", 0, "ivrs_conflict", 0, "ivrs_multi", 0
                       db "ivrs_segment", 0
%if PAOS_LAB_AMDVI_SKIP_OWNERSHIP
str_amdvi_r_lab_skip: db "lab_diagnostic",0
%endif
str_amdvi_tokens_end:                        ; RCQ-12: every skip token lies in [str_amdvi_r_no_ivrs, here)
str_amdvi_detect:      db "[PAOS64] amdvi.detect ivhd=", 0
str_amdvi_k_flags:     db " flags=", 0
str_amdvi_k_devid:     db " devid=", 0
str_amdvi_k_base:      db " base=", 0
str_amdvi_k_ivinfo:    db " ivinfo=", 0
str_amdvi_k_efr:       db " efr=", 0
str_amdvi_mmio:        db "[PAOS64] amdvi.mmio ctrl=", 0
str_amdvi_k_status:    db " status=", 0
str_amdvi_k_excl:      db " excl=", 0
str_amdvi_heap:        db "[PAOS64] amdvi.heap used=", 0
str_amdvi_k_size:      db " size=", 0
str_amdvi_df_stage:    db "[PAOS64] amdvi.domain.fail stage=", 0
str_amdvi_df_index: db " index=", 0
str_amdvi_df_base: db " base=", 0
str_amdvi_df_len: db " len=", 0
str_amdvi_df_pool: db " pool=", 0
str_amdvi_df_timeouts: db " timeouts=", 0
str_amdvi_df_ctrl: db " ctrl=", 0
str_amdvi_df_status: db " status=", 0
str_amdvi_df_head: db " head=", 0
str_amdvi_df_tail: db " tail=", 0
str_amdvi_event:       db "[PAOS64] amdvi.event q0=", 0
str_amdvi_inval_head: db "[PAOS64] amdvi.inval head=",0
str_amdvi_inval_tail: db " tail=",0
str_amdvi_inval_timeouts: db " timeouts=",0
str_amdvi_ok:          db "[PAOS64] amdvi.ownership ok native=", 0
str_amdvi_k_mapped:    db " mapped=", 0

%include "core/abi/wdata.inc"
; Zero-initialised state: deferred to the image's zero-fill tail.
%macro WDATA_hv_amdvi_0 0
alignb 8
amdvi_mmio:            resq 1
amdvi_ivhd:            resq 1                ; the selected IVHD block inside the IVRS
amdvi_devtab:          resq 1
amdvi_pool:            resq 1
amdvi_cmdbuf:          resq 1
amdvi_evtlog:          resq 1
amdvi_cw:              resq 1                ; COMPLETION_WAIT store qword (arena page 2)
amdvi_token:           resq 1
amdvi_compat_qw0:      resq 1
amdvi_native_qw0:      resq 1
amdvi_native_root:     resq 1
amdvi_last_event:      resq 1
amdvi_heap_used:       resq 1
amdvi_ivmd:            resq AMDVI_IVMD_MAX * 3   ; {first dw, last dw, flags dd, base dq, len dq}
amdvi_alias:           resq AMDVI_ALIAS_MAX      ; {first dw, last dw, source dw, pad dw}
amdvi_native_bdf:      resd AMDVI_NATIVE_MAX
amdvi_ivinfo:          resd 1
amdvi_ivmd_n:          resd 1
amdvi_alias_n:         resd 1
amdvi_native_n:        resd 1
alignb 8
amdvi_domain_stage:    resq 1               ; 0 success, 1 root, 2 DMA record, 3 IVMD
amdvi_domain_index:    resq 1
amdvi_domain_base:     resq 1
amdvi_domain_len:      resq 1
amdvi_native_mapped:   resd 1
amdvi_pool_next:       resd 1
amdvi_cmd_tail:        resd 1
amdvi_events:          resd 1
amdvi_cw_timeouts:     resd 1
amdvi_owned:           resb 1
amdvi_enabled:         resb 1
amdvi_cmd_lock:        resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_0
; RCQ-12 0.0.68: the recorded outcome. Its own block, outside the zero-storage pins of _0.
%macro WDATA_hv_amdvi_1 0
alignb 8
amdvi_out_tok:         resq 1                ; set only from a str_amdvi_r_*/name-table pointer at .skip*
amdvi_out_native:      resd 1
amdvi_out_mapped:      resd 1
amdvi_outcome:         resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_1


; Explicit lab snapshot: inspect at most the first pending hardware event.
; Never consume it, alter translation, or forward raw fields into audit queues.
; -> RAX=0 in ordinary builds; lab snapshot {state,header,address,head,tail,status}.
; state0=unbound,1=empty,2=event,3=invalid cursor. Full64 cursors must be valid before reads.
amdvi_lab_event_snapshot:
%if PAOS_LAB_AMDVI_EVENT_DUMP
    push rbx
    push r12
    push r13
    call amdvi_observation_generation
    test rax,rax
    jz .none
    cmp byte [rel amdvi_owned],1
    jne .none
    cmp byte [rel amdvi_enabled],1
    jne .none
    mov rbx,[rel amdvi_obs_mmio]
    test rbx,rbx
    jz .none
    cmp rbx,[rel amdvi_mmio]
    jne .none
    mov rax,[rel amdvi_evtlog]
    cmp rax,[rel amdvi_obs_log]
    jne .none
    call amdvi_observation_binding
    test eax,eax
    jz .none
    test dword [rbx+AMDVI_R_CTRL],AMDVI_CTRL_EN
    jz .none
    lea r12,[rel amdvi_lab_snapshot]
    mov qword [r12],3
    mov qword [r12+8],0
    mov qword [r12+16],0
    mov rax,[rbx+AMDVI_R_EVT_HEAD]
    mov rcx,[rbx+AMDVI_R_EVT_TAIL]
    mov [r12+24],rax
    mov [r12+32],rcx
    mov edx,[rbx+AMDVI_R_STATUS]
    mov [r12+40],rdx
    cmp rax,AMDVI_EVT_MASK
    ja .snapshot
    cmp rcx,AMDVI_EVT_MASK
    ja .snapshot
    test al,15
    jnz .snapshot
    test cl,15
    jnz .snapshot
    mov qword [r12],1
    cmp rax,rcx
    je .snapshot
    mov r13,[rel amdvi_evtlog]
    add r13,rax
    mov rax,[r13]
    mov rdx,[r13+8]
    mov [r12+8],rax
    mov [r12+16],rdx
    mov qword [r12],2
.snapshot:
    mov rax,r12
    jmp .done
.none:
    lea rax,[rel amdvi_lab_snapshot]
    mov qword [rax],0
    mov qword [rax+8],0
    mov qword [rax+16],0
    mov qword [rax+24],0
    mov qword [rax+32],0
    mov qword [rax+40],0
.done:
    pop r13
    pop r12
    pop rbx
    ret
%else
    xor eax,eax
    ret
%endif

%if PAOS_LAB_AMDVI_EVENT_DUMP
%macro WDATA_hv_amdvi_lab 0
alignb 8
amdvi_lab_snapshot: resq 6
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_lab
%endif

%macro WDATA_hv_amdvi_observation 0
alignb 8
amdvi_obs_generation: resq 1
amdvi_obs_mmio: resq 1
amdvi_obs_log: resq 1
amdvi_obs_publishing: resq 1
amdvi_obs_test_depth: resd 1
amdvi_obs_consuming: resb 1
amdvi_obs_overflow: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_observation
