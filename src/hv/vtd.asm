;; MODULE hv/vtd
;; LAYER 5
;; EXPORTS vtd_domainnet_ready_generation, vtd_ownership_init, vtd_reset_te_off, vtd_outcome_get, vtd_register_verb, vtd_status_line, vtd_data_pending, vtd_data_line, vtd_data_drop, vtd_deadman_check, vtd_vpci_in, vtd_vpci_out, vtd_guest_dataplane_prepare, vtd_guest_dataplane_try_inject, vtd_guest_dataplane_timer_due, vtd_guest_dataplane_irq0_injected, vtd_guest_dataplane_intr_window_exit, vtd_guest_bar_ept_service, vtd_guest_console_byte, vtd_domainnet_start, vtd_domainnet_stop, vtd_domainnet_alive, vtd_domain_l2_active, vtd_domain_bridge_ready, vtd_domain_bridge_stage, vtd_domain_iface_attempts, vtd_domain_iface_result, vtd_owner_guest, vtd_deadman_armed, vtd_deadman_fired, vtd_assign_fail_stage, vtd_assign_guest_stage, vtd_guest_stage, vtd_net_task_result, vtd_network_mode, vtd_guest_start_gen, vtd_first_ud_diag_gen, vtd_guest_gpa_is_secondary_bar, vtd_map_secondary_bars_ept, vtd_trace_select_for_ept, vtd_guest_domain_check
;; IMPORTS bus/pci_claim, boot/paging, boot/serial, boot/native_driver_preload, bus/acpi, bus/pci, core/dma, core/heap, core/lib/str, core/sched, core/time, dev/blk/nvme, dev/net/virtio_domain, svc/command, svc/command_udp, svc/resilience, hv/vmx, hv/hv_ops, hv/guestnet, hv/device_assignment, bus/pci_bdf, net/netdev, dev/net/e1000e, dev/net/rtl8168, dev/net/rtl8126, dev/blk/ahci, dev/blk/vmd, hv/vcpu_ap_run, hv/vcpu_bsp
;; OWNER saga:hv
; ============================================================================
; 1012/1012b — bounded VT-d ownership plus the secondary-RTL Linux dataplane.
;
; This is intentionally NOT a network-passthrough driver. PaOS's e1000e, AHCI,
; and NVMe requesters use the restrictive native DID-2 valid-set; legacy xHCI
; and untargeted Unit-B requesters retain DID-1 compatibility coverage. Only
; the discovered secondary 10ec Ethernet function can move to a 64 MiB guest
; domain. Ordinary 1012 proof keeps the vPCI device half non-matchable until
; built-in driver initcalls finish. DDOM NET instead exposes the saved physical
; BAR layout at launch, lets Linux's r8169 drive the spare function, and retains
; PaOS's witnessed native PCI NIC as the administrative/recovery lifeline.
;
; Lenovo has two DRHDs.  Never trust their example addresses: walk the live
; DMAR and select the INCLUDE_PCI_ALL unit.  The proven Classic sequence is
; preserved: tables first, coverage assertion second, RTADDR/SRTP, then TE.
; Runtime changes use device-selective context invalidation plus domain-
; selective IOTLB invalidation.  Unit B is never globally invalidated.
; ============================================================================

%include "core/abi/pci_claim.inc"

VTD_REG_CAP       equ 0x08
VTD_REG_ECAP      equ 0x10
VTD_REG_GCMD      equ 0x18
VTD_REG_GSTS      equ 0x1C
VTD_REG_RTADDR    equ 0x20
VTD_REG_CCMD      equ 0x28
VTD_REG_FSTS      equ 0x34
VTD_REG_PMEN      equ 0x64
VTD_REG_IQH       equ 0x80             ; SEC-D3a queued invalidation: head
VTD_REG_IQT       equ 0x88             ; tail (byte offset, bits 18:4 = index)
VTD_REG_IQA       equ 0x90             ; queue base | DW (bit 11) | QS (bits 2:0)
VTD_REG_IRTA      equ 0xB8             ; SEC-D3b: interrupt remapping table address | EIME (11) | S (3:0)

VTD_GCMD_TE       equ 0x80000000
VTD_GCMD_SRTP     equ 0x40000000
VTD_GSTS_TES      equ 0x80000000
VTD_GSTS_RTPS     equ 0x40000000
VTD_GCMD_QIE      equ 0x04000000       ; SEC-D3a: queued invalidation enable
VTD_GSTS_QIES     equ 0x04000000
VTD_GCMD_IRE      equ 0x02000000       ; SEC-D3b: interrupt remapping enable
VTD_GSTS_IRES     equ 0x02000000
VTD_GCMD_SIRTP    equ 0x01000000       ; set interrupt remap table pointer
VTD_GSTS_IRTPS    equ 0x01000000
VTD_GCMD_CFI      equ 0x00800000       ; compatibility-format interrupts (PaOS keeps it 0: blocked)
VTD_GSTS_CFIS     equ 0x00800000
VTD_ECAP_IR       equ 0x8
VTD_IRT_S         equ 7                ; 2^(S+1) = 256 entries x 16 B = one 4 KiB page
VTD_QI_DESC_IEC   equ 0x4              ; interrupt entry cache invalidate (G=0: global)
VTD_IR_R_ON       equ 0                ; vtd_ir_reason: why intr_remap is (not) enabled
VTD_IR_R_ECAP     equ 1                ;   the unit has no interrupt remapping
VTD_IR_R_QI       equ 2                ;   queued invalidation is not on
VTD_IR_R_HOSTPATH equ 3                ;   the host PIC would cross IR (not LINT0 ExtINT)
VTD_IR_R_HW       equ 4                ;   a SIRTP/IEC/IRE step or the read-back failed
VTD_IR_R_IDLE     equ 5                ;   no device is assigned: IR is off by design
VTD_IR_R_FW_STUCK equ 6                ;   a firmware-left IRE would not turn off at boot
VTD_ECAP_QI       equ 0x2
VTD_QI_ENTRIES    equ 256              ; QS=0: 256 x 128-bit descriptors = one 4 KiB page
VTD_QI_BOOT_BATCH equ 128              ; boot-only contexts + WAIT, leaving one empty slot
VTD_QI_DESC_CC    equ 0x1              ; context-cache invalidate
VTD_QI_DESC_IOTLB equ 0x2              ; IOTLB invalidate
VTD_QI_DESC_WAIT  equ 0x5              ; invalidation wait (bit 5 SW = status write)
VTD_FSTS_IQE_ITE  equ 0x50             ; invalidation queue error (4) | invalidation time-out (6)
VTD_DID_IDENTITY  equ 1
VTD_DID_NATIVE    equ 2
VTD_DID_GUEST     equ 0x10
VTD_DID_HDA       equ 3                  ; RCQ-36 S5b: the HDA-only domain (core/dma tag 1)
VTD_DOM_HDA       equ 1                  ; core/dma record tag of DID 3 (DMA_DOM_HDA); 0 = DID 2
VTD_HDA_IDLE      equ 0                  ; vtd_hda_state: never attached
VTD_HDA_OK        equ 1                  ;   in DID 3, receipt live
VTD_HDA_REFUSED   equ 2                  ;   a precondition refused (no hardware change)
VTD_HDA_POISON    equ 3                  ;   failed after the old entry was cleared (R3)
VTD_HDA_ATS_ABSENT   equ 0
VTD_HDA_ATS_DISABLED equ 1
VTD_HDA_ATS_UNREAD   equ 2               ; rc-sec R1: admitted on TT=00, never folded into absent
VTD_HDA_ATS_ENABLED  equ 3
VTD_HDA_R_POISONED       equ 1           ; vtd_hda_attach refusals = vtd_hda_reason_names order
VTD_HDA_R_ATTACHED       equ 2
VTD_HDA_R_NO_ENFORCEMENT equ 3           ; = core/dma DMA_DOM_R_UNBOUND
VTD_HDA_R_NOT_FOUND      equ 4
VTD_HDA_R_CLASS          equ 5
VTD_HDA_R_GUEST_LIVE     equ 6
VTD_HDA_R_BAR            equ 7
VTD_HDA_R_FOREIGN_DRHD   equ 8
VTD_HDA_R_NOT_QUIESCED   equ 9
VTD_HDA_R_ATS_ENABLED    equ 10
VTD_HDA_R_CTX_STATE      equ 11
VTD_HDA_R_POOL           equ 12
VTD_HDA_R_INVAL_TIMEOUT  equ 13
VTD_HDA_R_READBACK       equ 14
VTD_HDA_R_RMRR           equ 15
VTD_HDA_R_ALIAS          equ 16
VTD_HDA_R_FACTS          equ 17
VTD_HDA_R_DISJOINT       equ 18
VTD_HDA_R_NOPS           equ 19
VTD_HDA_R_FSTS           equ 20
VTD_HDA_R_NOT_ATTACHED   equ 21
VTD_HDA_R_LAST           equ 22          ; "unknown"
VTD_HDA_NAME_STRIDE      equ 16
VTD_HDA_LINE_MAX         equ 255
VTD_NET_GUEST_IRQ equ 6                  ; Classic-proven master-PIC line
VTD_CARVE_PAGES   equ 8                  ; DID 1 carve splits: the arena and the register span, each <= 2 PD + 2 PT
VTD_GUEST_RAM_PDS equ 3                  ; RCQ-50: DID 0x10 second-level PDs, flat guest RAM up to 3 GiB
VTD_GUEST_RAM_BYTES equ 0x4000000        ; RCQ-50 F1: DID 0x10 maps the legacy guest's RAM only
%if VTD_GUEST_RAM_BYTES != HV_LINUX_NORMAL_RAM_BYTES || VTD_GUEST_RAM_BYTES > VTD_GUEST_RAM_PDS * 512 * 0x200000
%error "DID 0x10 is the legacy guest's RAM, within its PDs"
%endif
VTD_NATIVE_POOL_PAGES equ 40 + 2 + VTD_CARVE_PAGES ; trusted VT-d metadata pages (+2 QI, +1 IRT, +6 native HDA, +7 guest RAM/context, +2: RCQ-50 guest PDs 1..2)
%if VTD_GUEST_RAM_PDS - 1 != 2
    %error "VTD_NATIVE_POOL_PAGES carries VTD_GUEST_RAM_PDS - 1 extra guest PDs"
%endif
VTD_DMAR_SNAP_PAGES equ 2               ; RCQ-18 DMAR snapshot: after the DMAVIOL page, outside the allocator
VTD_IOAPIC_SNAP_PAGES equ 1             ; bounded MADT identity copy, also outside the allocator
VTD_NATIVE_POOL_BYTES equ (VTD_NATIVE_POOL_PAGES + 1 + VTD_DMAR_SNAP_PAGES + VTD_IOAPIC_SNAP_PAGES) * 4096
                                             ; +1 reserved DMAVIOL page, then the
                                             ; DMAR and MADT snapshot pages; with
                                             ; alignment slack leaves budget
                                             ; for the DID-2 bus index + code
%assign VTD_GUEST_BOOT_ALLOW_MS HV_LINUX_RUN_MS
%assign VTD_MIN_RECLAIM_MARGIN_MS 30000
%assign VTD_DEADMAN_MS 240000
%assign VTD_NET_DEADMAN_MS 330000
VTD_WAIT_SPINS    equ 1000000
VTD_CCMD_KAT_VECTORS equ 5                ; vtd_ccmd_layout_kat table rows
VTD_OUT_MAX       equ 4095
VTD_CFG_BYTES     equ 256
VTD_EPT_POOL_OFF  equ 0x9000
VTD_EPT_POOL_PAGES equ 16
%if HV_GUESTIN_PAGE < VTD_EPT_POOL_OFF + VTD_EPT_POOL_PAGES * 0x1000
    %error "RCQ-23 F9: the guest input register page overlaps the VT-d EPT pool"
%endif
VTD_BAR_MAP_MAX_BYTES equ 0x1000000       ; Classic's bounded 16 MiB/BAR policy
VTD_VPCI_TRACE_MAX equ 32
VTD_TRACE_GEN       equ 0
VTD_TRACE_BAR       equ 4
VTD_TRACE_CFG_OFF   equ 5
VTD_TRACE_WIDTH     equ 6
VTD_TRACE_WRITE_LOW equ 8
VTD_TRACE_WRITE_HIGH equ 12
VTD_TRACE_SHADOW_LOW equ 16
VTD_TRACE_SHADOW_HIGH equ 20
VTD_TRACE_SAVED_LOW equ 24
VTD_TRACE_SAVED_HIGH equ 28
VTD_TRACE_SHADOW_GPA equ 32
VTD_TRACE_SAVED_HPA equ 40
VTD_TRACE_MAP_RESULT equ 48
VTD_TRACE_MAP_GPA    equ 56
VTD_TRACE_MAP_HPA    equ 64
VTD_TRACE_LEAF_ADDR  equ 72
VTD_TRACE_LEAF_VALUE equ 80
VTD_TRACE_LEAF_READBACK equ 88
VTD_TRACE_INVEPT_ERROR equ 96
VTD_TRACE_INVEPT_ATTEMPTED equ 100
VTD_TRACE_INVEPT_OK  equ 101
VTD_TRACE_ORDINAL   equ 102
VTD_TRACE_ENTRY_BYTES equ 104
VTD_BDF_MAX       equ 512
VTD_CLASS_ETH     equ 0x0200
VTD_CLASS_SATA    equ 0x0106
VTD_CLASS_NVM     equ 0x0108
VTD_CLASS_XHCI    equ 0x0C0330

; The guest layer owns the accepted dilation ceiling.  Ownership must remain
; guest-held throughout that complete window, with a finite reclaim margin.
%if VTD_GUEST_BOOT_ALLOW_MS <= 0
    %error "VT-d guest boot allowance must be positive"
%endif
%if VTD_DEADMAN_MS < VTD_GUEST_BOOT_ALLOW_MS + VTD_MIN_RECLAIM_MARGIN_MS
    %error "VT-d deadman must be at least 30 seconds outside guest boot allowance"
%endif
%if VTD_NET_DEADMAN_MS < VTD_GUEST_BOOT_ALLOW_MS + VTD_MIN_RECLAIM_MARGIN_MS
    %error "VT-d network deadman must retain the full guest allowance plus reclaim margin"
%endif

VTD_FAIL_NONE           equ 0
VTD_FAIL_CONTEXT_ASSIGN equ 1
VTD_FAIL_GUEST_PROOF    equ 2
VTD_FAIL_IOMMU_FAULT    equ 3
VTD_FAIL_ISOLATION      equ 4            ; RCQ-19: refused by the isolation precondition

; RCQ-19 S1 standing driver domain (root 2026-10-08 15:36). Once the DOMAINNET
; service has passed its bridge proof, the host-side deadman becomes a liveness
; lease: guest-to-PaOS frames renew it, a quiet domain is probed through the
; gateway, and a missed renewal (hang) or a guest that left its run loop
; (crash) reclaims within VTD_DD_LEASE_MS plus one host tick. A reclaimed
; domain restarts at most VTD_DD_BUDGET times per VTD_DD_WINDOW_MS; then the
; function stays host-owned and the capstone rolls back to native egress.
VTD_DD_LEASE_MS     equ 5000
VTD_DD_PROBE_MS     equ 1000
VTD_DD_BACKOFF_MS   equ 1000
VTD_DD_BUDGET       equ 3
VTD_DD_WINDOW_MS    equ 600000
VTD_DD_IDLE         equ 0                ; no standing service
VTD_DD_STARTING     equ 1                ; first launch: failure keeps the 1013b semantics
VTD_DD_SERVING      equ 2                ; bridge proven; the lease governs ownership
VTD_DD_RESTARTING   equ 3                ; relaunch in flight; failure counts against the budget
VTD_DD_RECOVERING   equ 4                ; reclaimed; relaunch after the backoff
VTD_DD_EXHAUSTED    equ 5                ; budget spent: host-owned, native egress
VTD_DD_STRANDED     equ 6                ; reclaim failed; the deadman keeps retrying it
VTD_DD_CAUSE_NONE   equ 0
VTD_DD_CAUSE_CRASH  equ 1
VTD_DD_CAUSE_HANG   equ 2
VTD_DD_CAUSE_PROOF  equ 3
VTD_DD_CAUSE_BOOT   equ 4                ; relaunch outlived its boot budget
VTD_DD_FAULT_CRASH  equ 1
VTD_DD_FAULT_HANG   equ 2
VTD_ISO_NAME_STRIDE equ 24               ; vtd_iso_reason_names entry size
VTD_DD_NAME_STRIDE  equ 12               ; vtd_dd_state_names / vtd_dd_cause_names
; RCQ-19 Lenovo 0.0.65 (root 00:26:37): why an assignment or a reset refused.
; One numbering for vtd_assign_refusal (the stage) and vtd_reset_refusal (the
; reset's own step), named by vtd_refusal_names in DDOM NET STAT.
VTD_REFUSE_NONE         equ 0
VTD_REFUSE_NOT_READY    equ 1            ; VT-d is not owned
VTD_REFUSE_NO_TIMEBASE  equ 2            ; tsc_khz = 0: no lease, no settle delay
VTD_REFUSE_OWNED        equ 3            ; the function is already guest-owned
VTD_REFUSE_ISOLATION    equ 4            ; vtd_iso_check refused (assign_iso names it)
VTD_REFUSE_GUEST_DOMAIN equ 5            ; guest tables or the 64 MiB reservation
VTD_REFUSE_BUS_CTX      equ 6            ; no present root entry for the function's bus
VTD_REFUSE_QUIESCE      equ 7            ; BAR2, ChipCmd or the bus-off read-back
VTD_REFUSE_HANDOFF_RESET equ 8           ; the handoff reset refused (assign_reset names why)
VTD_REFUSE_CTX_INVAL    equ 9            ; the context-cache/IOTLB invalidation timed out
VTD_REFUSE_CTX_VERIFY   equ 10           ; the guest context entry did not read back
VTD_REFUSE_ABSENT       equ 11           ; the function reads all-ones
VTD_REFUSE_NO_MARKER    equ 12           ; Command.INTx-disable (bus-off) was not set
VTD_REFUSE_TP_STUCK     equ 13           ; Transactions Pending held for 100 ms
VTD_REFUSE_NO_BRIDGE    equ 14           ; no FLR and no sole-function bus-0 bridge for SBR
VTD_REFUSE_NEVER_READY  equ 15           ; all-ones for the whole 1 s readiness poll
VTD_REFUSE_BAD_ANSWER   equ 16           ; neither the vendor nor all-ones (e.g. CRS)
VTD_REFUSE_IGNORED      equ 17           ; answered with the bus-off marker still set
VTD_REFUSE_RESTORE      equ 18           ; the vendor was lost restoring the header
VTD_REFUSE_LAST         equ 18
%if VTD_DD_LEASE_MS < 2 * VTD_DD_PROBE_MS
    %error "the domain lease must cover at least two gateway probes"
%endif

VTD_GUEST_STAGE_NONE        equ 0
VTD_GUEST_STAGE_STOP_WAIT   equ 1
VTD_GUEST_STAGE_SPAWN       equ 2
VTD_GUEST_STAGE_BOOT_WAIT   equ 3
VTD_GUEST_STAGE_INJECT      equ 4
VTD_GUEST_STAGE_VENDOR_WAIT equ 5
VTD_GUEST_STAGE_ECHO_WAIT   equ 6
VTD_GUEST_STAGE_RUN_NOT_CONSUMED equ 7
VTD_GUEST_STAGE_BOOT_EXIT   equ 8
VTD_GUEST_STAGE_CARRIER_WAIT equ 9
VTD_GUEST_STAGE_CARRIER_ZERO equ 10

VTD_DOMAIN_STAGE_NONE         equ 0
VTD_DOMAIN_STAGE_SHELL_WAIT   equ 1
VTD_DOMAIN_STAGE_IFACE_WAIT   equ 2
VTD_DOMAIN_STAGE_CARRIER_WAIT equ 3
VTD_DOMAIN_STAGE_BRIDGE_WAIT  equ 4
VTD_DOMAIN_STAGE_READY        equ 5
VTD_DOMAIN_STAGE_CARRIER_ZERO equ 6

; Interface discovery is retried by the host-side worker so console delivery
; is never confused with guest-side completion. Forty 500 ms receipt windows
; fit comfortably inside the existing network guest/deadman budget.
VTD_DOMAIN_IFACE_RETRY_MS       equ 500
VTD_DOMAIN_IFACE_MAX_ATTEMPTS   equ 40
VTD_DOMAIN_IFACE_RESULT_NONE              equ 0
VTD_DOMAIN_IFACE_RESULT_READY             equ 1
VTD_DOMAIN_IFACE_RESULT_NOT_FOUND         equ 2
VTD_DOMAIN_IFACE_RESULT_LINK_UP_FAILED    equ 3
VTD_DOMAIN_IFACE_RESULT_MALFORMED         equ 4
VTD_DOMAIN_IFACE_RESULT_TIMEOUT_NO_RECEIPT equ 5
VTD_DOMAIN_IFACE_RESULT_TIMEOUT_NOT_FOUND equ 6
VTD_DOMAIN_IFACE_RESULT_TIMEOUT_LINK_UP   equ 7
VTD_DOMAIN_IFACE_RESULT_TIMEOUT_MALFORMED equ 8

VTD_EPT_CLASS_NONE          equ 0
VTD_EPT_CLASS_VIRTIO_RESUME equ 1
VTD_EPT_CLASS_VIRTIO_ACCESS equ 2
VTD_EPT_CLASS_VIRTIO_DECODE equ 3
VTD_EPT_CLASS_ASSIGNED_BAR  equ 4
VTD_EPT_CLASS_FOREIGN_GPA   equ 5

VTD_EPT_MAP_NO_ROOT             equ 1
VTD_EPT_MAP_PML4_ABSENT         equ 2
VTD_EPT_MAP_POOL_EXHAUSTED      equ 3
VTD_EPT_MAP_LARGE_LEAF_CONFLICT equ 4
VTD_EPT_MAP_LEAF_CONFLICT       equ 5
VTD_EPT_MAP_INVALID_INPUT       equ 6
VTD_EPT_MAP_LEAF_WRITTEN        equ 7
VTD_EPT_MAP_LEAF_ALREADY_EXACT  equ 8
; RCQ-12 0.0.68: vtd_outcome, read by vtd_outcome_get. Zero-fill is not_run, never ok.
VTD_OUT_NOT_RUN     equ 0
VTD_OUT_SILENT      equ 1                        ; left unowned without a skip line
VTD_OUT_SKIP        equ 2
VTD_OUT_OK          equ 3
VTD_OUT_BAD         equ 4
VTD_SKIP_PREFIX_LEN equ 35                       ; "[PAOS64] vtd.ownership.skip reason="

; ---------------------------------------------------------------------------
; Boot discovery and clean first enable.
; ---------------------------------------------------------------------------
vtd_ownership_init:
    push rbx
    xor  edi, edi
    xor  esi, esi
    call dma_iommu_bind
    xor  edi, edi
    xor  esi, esi
    call dma_domain_bind
    call hv_vcon_proof_roll_state_reset
    mov  byte [rel vtd_outcome], VTD_OUT_NOT_RUN
    mov  byte [rel vtd_ready], 0
    call vtdg_reset
    mov  byte [rel vtd_enabled], 0
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_coverage_before_te], 0
    mov  qword [rel vtd_cov_record + 0], 0
    mov  qword [rel vtd_cov_record + 8], 0
    mov  qword [rel vtd_cov_record + 16], 0
    mov  qword [rel vtd_cov_record + 24], 0
    mov  qword [rel vtd_cov_record + 32], 0
    mov  qword [rel vtd_cov_record + 40], 0
    mov  qword [rel vtd_cov_record + 48], 0
    mov  qword [rel vtd_cov_record + 56], 0
    mov  byte [rel vtd_scoped_unit], 0
    mov  qword [rel vtd_ioapic_madt], 0
    mov  dword [rel vtd_ioapic_madt_len], 0
    mov  byte [rel vtd_secondary_found], 0
    mov  byte [rel vtd_deadman_armed], 0
    mov  byte [rel vtd_native_nic_found], 0
    mov  byte [rel vtd_native_nic_covered], 0
    mov  byte [rel vtd_e1000e_found], 0
    mov  byte [rel vtd_xhci_found], 0
    mov  byte [rel vtd_sata_found], 0
    mov  byte [rel vtd_nvme_found], 0
    mov  byte [rel vtd_e1000e_covered], 0
    mov  byte [rel vtd_xhci_covered], 0
    mov  byte [rel vtd_sata_covered], 0
    mov  byte [rel vtd_nvme_covered], 0
    mov  byte [rel vtd_reset_verified], 0
    mov  byte [rel vtd_reset_method], 0
    mov  byte [rel vtd_bus_ctx_ready], 0
    mov  byte [rel vtd_guest_tables_ready], 0
    mov  byte [rel vtd_vpci_active], 0
    mov  byte [rel vtd_vpci_identity_open], 0
    mov  byte [rel vtd_net_task_started], 0
    call vtd_net_reset_session
    mov  byte [rel vtd_reclaim_verified], 0
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_NONE
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_guest_inject_accepted], 0
    mov  byte [rel vtd_guest_vendor_seen], 0
    mov  byte [rel vtd_guest_echo_seen], 0
    mov  byte [rel vtd_assign_secondary_found], 0
    mov  byte [rel vtd_assign_ready], 0
    mov  byte [rel vtd_assign_reset_verified], 0
    mov  byte [rel vtd_assign_guest_vendor], 0
    mov  byte [rel vtd_assign_guest_echo], 0
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_assign_linux_running], 0
    mov  byte [rel vtd_assign_linux_kboot], 0
    mov  byte [rel vtd_assign_vcon_ready], 0
    mov  byte [rel vtd_assign_inject_accepted], 0
    mov  byte [rel vtd_assign_run_req], 0
    mov  byte [rel vtd_assign_task_started], 0
    mov  byte [rel vtd_assign_load_err], 0
    mov  byte [rel vtd_assign_launch_refused], 0
    mov  byte [rel vtd_assign_vmxon_fail], 0
    mov  byte [rel vtd_assign_vmcs_fail], 0
    mov  byte [rel vtd_assign_vcon_rx_ready], 0
    mov  byte [rel vtd_assign_vcon_tx_ready], 0
    mov  dword [rel vtd_guest_start_gen], 0
    mov  dword [rel vtd_first_ud_diag_gen], 0
    mov  byte [rel vtd_first_ud_diag_requested], 0
    mov  dword [rel vtd_assign_start_gen], 0
    mov  dword [rel vtd_assign_start_consumed], 0
    mov  dword [rel vtd_assign_instr_err], 0
    mov  dword [rel vtd_assign_vmwrite_fails], 0
    mov  dword [rel vtd_assign_last_exit], 0
    mov  dword [rel vtd_assign_capture_len], 0
    mov  qword [rel vtd_assign_ept_gpa], 0
    mov  qword [rel vtd_assign_ept_qual], 0
    mov  dword [rel vtd_assign_ept_ilen], 0
    mov  dword [rel vtd_assign_ept_decode_len], 0
    mov  dword [rel vtd_assign_ept_gen], 0
    mov  byte [rel vtd_assign_ept_access], 0
    mov  byte [rel vtd_assign_ept_decode], 0
    mov  byte [rel vtd_assign_ept_class], VTD_EPT_CLASS_NONE
    mov  byte [rel vtd_assign_ept_action], 0
    mov  dword [rel vtd_assign_fsts], 0
    mov  dword [rel vtd_assign_fault_count], 0
    mov  qword [rel vtd_assign_frcd_lo], 0
    mov  qword [rel vtd_assign_frcd_hi], 0
    mov  qword [rel vtd_ept_root], 0
    mov  qword [rel vtd_ept_pool_base], 0
    mov  byte [rel vtd_ept_pool_used], 0
    call vtd_bar_trace_reset
    mov  byte [rel vtd_bdf_overflow], 0
    mov  qword [rel vtd_unitb_base], 0
    mov  dword [rel vtd_fault_count], 0
    mov  dword [rel vtd_bdf_count], 0
    mov  byte [rel vtd_native_ready], 0
    mov  byte [rel vtd_native_marker_domains], 0
    mov  byte [rel vtd_native_marker_mapped], 0
    mov  qword [rel vtd_native_pool_base], 0
    mov  qword [rel vtd_native_pml4], 0
    mov  qword [rel vtd_hda_pml4], 0
    mov  qword [rel vtd_dmaviol_target_page], 0
    mov  dword [rel vtd_native_pool_next], 0
    mov  dword [rel vtd_native_record_count], 0
    mov  dword [rel vtd_native_mapped_pages], 0
    mov  dword [rel vtd_hda_mapped_pages], 0
    mov  byte [rel vtd_hda_state], VTD_HDA_IDLE
    mov  byte [rel vtd_hda_reason], 0
    mov  dword [rel vtd_hda_bdf], 0
    mov  qword [rel vtd_hda_mmio], 0
    mov  qword [rel vtd_dmaviol_canary], 0
    mov  qword [rel vtd_dmaviol_fault_before], 0
    mov  qword [rel vtd_dmaviol_frcd_lo], 0
    mov  qword [rel vtd_dmaviol_frcd_hi], 0
    mov  dword [rel vtd_dmaviol_fault_delta], 0
    mov  dword [rel vtd_dmaviol_nvme_status], 0
    mov  dword [rel vtd_dmaviol_stage], 0
    mov  byte [rel vtd_dmaviol_landed], 1
    mov  byte [rel vtd_dmaviol_blocked], 0
    mov  byte [rel vtd_dmaviol_valid], 0
    mov  byte [rel vtd_dmaviol_nonce], 0
    lea  rdi, [rel vtd_native_bus_ctx]
    xor  eax, eax
    mov  ecx, 256
    cld
    rep  stosq

    ; Never enable remapping with a context-invalidation encoder that misnames
    ; the requester: the cached context would outlive every reassignment.
    call vtd_ccmd_layout_kat
    test eax, eax
    jz   .ccmd_kat_fail
    lea  rdi, [rel str_vtd_ccmd_kat_pass]
    call serial_string

    call vtd_find_include_all_drhd
    test rax, rax
    jz   .skip_no_drhd
    mov  [rel vtd_unitb_base], rax
    mov  rbx, rax

    ; The rework identity map is WB.  Port Classic's proven PCD+PWT marking
    ; before the first DRHD register access; otherwise command/status polling
    ; can observe cacheable aliases rather than the live remapping unit.
    mov  rdi, rbx
    call mmio_mark_uc
    test eax, eax
    jz   .skip_mmio_uc

    mov  rax, [rbx + VTD_REG_CAP]
    mov  [rel vtd_cap], rax
    bt   rax, 35                         ; SLLPS: 1 GiB second-level leaves
    jnc  .skip_sllps1g                   ; native tables need 1 GiB leaves; upstream QEMU 8.2.2 advertises them
    bt   rax, 10                         ; SAGAW bit for context AW=2 (48-bit)
    jnc  .skip_sagaw48
    mov  rax, [rbx + VTD_REG_ECAP]
    mov  [rel vtd_ecap], rax

    ; Do not steal an already-enabled remapping unit.  This seam is the sole
    ; owner only when firmware handed it to us disabled.
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_TES
    jnz  .skip_tes_fw

    ; Include-all discovery follows the capability checks. Scoped selection
    ; has already required a complete inventory; never append it a second time.
    cmp  byte [rel vtd_scoped_unit], 1     ; scoped selection already took the complete inventory
    je   .discovered
    lea  rdi, [rel vtd_find_secondary_cb]
    call pci_scan_with_filter
.discovered:
    call vtd_sata_vmd_select               ; both discovery paths: VMD-only boards' SATA requester
    call vtd_native_nic_bind
    call vtd_native_nic_optional_current
    test eax, eax
    jz   .skip_coverage
    ; Native protection is independent of optional guest passthrough. Runtime
    ; ASSIGN still requires the secondary function, while DID 2 requires the
    ; witnessed native NIC/SATA/NVMe functions validated below. boot_only
    ; forbids native networking; its unbound NIC stays in DID 1 until the
    ; separate common assignment lifecycle establishes guest isolation.

    ; One bounded trusted arena owns every VT-d metadata page. The page after them is
    ; the deliberate violation target (the DMAR snapshot pages follow it), so
    ; neither metadata nor the canary can accidentally enter core/dma's
    ; device-visible valid-set.
    mov  edi, VTD_NATIVE_POOL_BYTES + 4095
    call kmalloc
    test rax, rax
    jz   .skip_alloc
    add  rax, 4095
    and  rax, -4096
    mov  [rel vtd_native_pool_base], rax
    mov  rdx, rax
    add  rdx, VTD_NATIVE_POOL_PAGES * 4096
    mov  [rel vtd_dmaviol_target_page], rdx
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, VTD_NATIVE_POOL_BYTES / 8
    cld
    rep  stosq

    call vtd_alloc_page
    test rax, rax
    jz   .skip_alloc
    mov  [rel vtd_root], rax
    call vtd_alloc_page                   ; SEC-D3a: invalidation queue (QS=0, one page)
    mov  [rel vtd_qi_queue], rax
    call vtd_alloc_page                   ; SEC-D3a: invalidation-wait status dword
    mov  [rel vtd_qi_status], rax
    call vtd_alloc_page                   ; SEC-D3b: interrupt remapping table (all entries not present)
    mov  [rel vtd_irt], rax
    call vtd_alloc_page
    test rax, rax
    jz   .skip_alloc
    mov  [rel vtd_shared_ctx], rax
    call vtd_alloc_page
    test rax, rax
    jz   .skip_alloc
    mov  [rel vtd_id_pml4], rax
    call vtd_alloc_page
    test rax, rax
    jz   .skip_alloc
    mov  [rel vtd_id_pdpt], rax

    ; 512 GiB identity domain: one PML4 entry and all 512 1-GiB PDPT leaves.
    mov  rdi, [rel vtd_id_pml4]
    mov  rax, [rel vtd_id_pdpt]
    or   rax, 3
    mov  [rdi], rax
    mov  rdi, [rel vtd_id_pdpt]
    xor  ecx, ecx
.id_leaf:
    mov  rax, rcx
    shl  rax, 30
    or   rax, 0x83
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 512
    jb   .id_leaf

    ; Every devfn in the shared context table is present in DID 1.
    mov  rdi, [rel vtd_shared_ctx]
    xor  ecx, ecx
.ctx_fill:
    mov  rax, [rel vtd_id_pml4]
    or   rax, 1
    mov  [rdi + rcx], rax
    mov  qword [rdi + rcx + 8], 0x102    ; DID=1, AW=2 (48-bit)
    add  ecx, 16
    cmp  ecx, 4096
    jb   .ctx_fill

    ; INCLUDE_PCI_ALL means every bus must resolve before TE, not merely bus 0.
    mov  rdi, [rel vtd_root]
    xor  ecx, ecx
.root_fill:
    mov  rax, [rel vtd_shared_ctx]
    or   rax, 1
    mov  [rdi + rcx], rax
    mov  qword [rdi + rcx + 8], 0
    add  ecx, 16
    cmp  ecx, 4096
    jb   .root_fill

    ; F-02 (c) for VT-d (root 22:04:42, design 01:31:41): no DID 1 requester
    ; reaches IOMMU state. The whole arena (root, context, QI queue and status,
    ; IRT, every DID 1/DID 2/guest table page, now or later, and the DMAVIOL
    ; canary) and unit B's register span leave the identity map before the
    ; root table is programmed. Nothing is programmed yet, so a refusal leaves
    ; the unit as firmware handed it over.
    mov  dword [rel vtd_carve_holes], 0
    mov  dword [rel vtd_carve_splits], 0
    mov  rdi, [rel vtd_native_pool_base]
    mov  esi, VTD_NATIVE_POOL_BYTES
    call vtd_compat_carve
    test eax, eax
    jz   .skip_carve
    mov  rax, [rel vtd_ecap]
    shr  rax, 8
    and  eax, 0x3FF
    shl  eax, 4
    add  eax, 16                         ; ECAP.IRO: IVA + IOTLB registers
    mov  rcx, [rel vtd_cap]
    mov  rdx, rcx
    shr  rcx, 24
    and  ecx, 0x3FF
    shl  ecx, 4                          ; CAP.FRO
    shr  rdx, 40
    and  edx, 0xFF
    inc  edx
    shl  edx, 4                          ; (CAP.NFR + 1) fault records
    add  ecx, edx
    cmp  eax, ecx
    jae  .reg_span
    mov  eax, ecx
.reg_span:
    mov  rdi, rbx
    mov  esi, eax                        ; the page holding 0x00..0xFF comes with it
    call vtd_compat_carve
    test eax, eax
    jz   .skip_carve
    call vtd_dmar_snap_take              ; RCQ-18: assignment reads this copy, never the live DMAR
    call vtd_ioapic_snap_take            ; IOAPIC identity must also leave device-visible firmware RAM
    call vtd_scoped_snapshot_ok          ; no scoped-unit hardware writes on a changed/invalid copy
    test eax, eax
    jz   .skip_no_drhd
    lea  rdi, [rel str_vtd_carve_pages]  ; census: pages made not present, split tables taken
    call serial_string
    mov  edi, [rel vtd_carve_holes]
    call serial_hex64
    lea  rdi, [rel str_vtd_carve_splits]
    call serial_string
    mov  edi, [rel vtd_carve_splits]
    call serial_hex64
    call serial_newline

    mov  rdi, [rel vtd_id_pml4]
    call vtd_flush_page
    mov  rdi, [rel vtd_id_pdpt]
    call vtd_flush_page
    mov  rdi, [rel vtd_shared_ctx]
    call vtd_flush_page
    mov  rdi, [rel vtd_root]
    call vtd_flush_page
    mfence

    ; Disable protected-memory trapping before translation is enabled.
    and  dword [rbx + VTD_REG_PMEN], 0x7FFFFFFF
    mov  ecx, VTD_WAIT_SPINS
.pmen_wait:
    test dword [rbx + VTD_REG_PMEN], 1
    jz   .pmen_done
    pause
    dec  ecx
    jnz  .pmen_wait
    jmp  .skip_pmen
.pmen_done:
    call vtd_clear_faults

    ; SEC-D3b: interrupt remapping is on only while a device is assigned to the
    ; guest (vtd_assign_context_only .. vtd_reclaim_internal). A firmware-left
    ; IRE is turned off FIRST, before any later command write could carry it
    ; (IRE is a persistent bit) and before QI is touched, so firmware's table
    ; is never live while its queue is reprogrammed (Linux order: IR, then QI).
    call vtd_ir_off
    mov  byte [rel vtd_ir_on], 0
    mov  byte [rel vtd_ir_reason], VTD_IR_R_IDLE
    test eax, eax
    jnz  .ir_off_ok
    mov  byte [rel vtd_ir_reason], VTD_IR_R_FW_STUCK ; firmware's IR stays live: say so
.ir_off_ok:
    mov  rax, [rel vtd_root]
    mov  [rbx + VTD_REG_RTADDR], rax
    mfence
    call vtd_gcmd_persistent               ; GCMD is write-only: keep TE/QIE as they are
    or   eax, VTD_GCMD_SRTP
    mov  [rbx + VTD_REG_GCMD], eax
    mfence
    mov  edi, VTD_GSTS_RTPS
    call vtd_wait_gsts_set
    test eax, eax
    jz   .skip_srtp

    ; Runtime assertions immediately before TE: all tables are aligned and
    ; both the root and a representative context entry resolve as present.
    call vtd_validate_coverage
    test eax, eax
    jz   .skip_coverage
    ; Port Classic's restrictive 4 KiB DID-2 domain, populated from core/dma's
    ; complete recorded valid-set rather than hardcoded driver buffers.
    call vtd_native_domain_build
    test eax, eax
    jz   .skip_domain
    mov  byte [rel vtd_coverage_before_te], 1

    ; SEC-D3a: queued invalidation when the unit supports it (required for
    ; interrupt remapping); otherwise the register CCMD/IOTLB path stays.
    call vtd_qi_enable
    test eax, eax
    jz   .skip_qi
    ; Unit B owns INCLUDE_PCI_ALL, so contract 1012 forbids a global invalidate.
    ; Invalidate every requester found by the bounded pre-TE scan, then DID 1's
    ; IOTLB.  TE remains off until the entire selective sequence completes.
    call vtd_boot_selective_invalidate
    test eax, eax
    jz   .skip_inval
    call vtd_gcmd_persistent               ; GCMD is write-only: keep QIE while setting TE
    or   eax, VTD_GCMD_TE
    mov  [rbx + VTD_REG_GCMD], eax
    mfence
    ; Treat an issued TE command as enabled until GSTS proves otherwise.  A
    ; timeout must enter the bounded disable path, never fall through with a
    ; possibly-live remapping unit recorded as disabled.
    mov  byte [rel vtd_enabled], 1
    mov  edi, VTD_GSTS_TES
    call vtd_wait_gsts_set
    test eax, eax
    jz   .skip_te_timeout
    call vtd_capture_faults
    cmp  dword [rel vtd_fsts], 0
    jne  .skip_te_faults
    mov  byte [rel vtd_ready], 1
    lea  rdi, [rel vtd_dma_map_hook]
    lea  rsi, [rel vtd_dma_unmap_hook]
    call dma_iommu_bind
    test eax, eax
    jz   .skip_te_bind
    mov  byte [rel vtd_native_ready], 1
    ; W4a: ownership with no native NIC bound closes later PCI NET registration
    ; (net/netdev netdev_policy_admit); a USB NIC adds no requester and stays open.
    cmp  byte [rel vtd_native_nic_found], 0
    jne  .late_pci_open
    mov  byte [rel netdev_late_pci_closed], 1
.late_pci_open:
    lea  rdi, [rel vtd_hda_attach]         ; RCQ-36 S5b: HDA asks for DID 3 through core/dma
    lea  rsi, [rel vtd_hda_receipt]
    call dma_domain_bind
    lea  rdi, [rel vtd_hda_live_receipt]
    call dma_domain_live_bind
    lea  rdi, [rel str_vtd_native_domains_marker]
    call serial_string
    mov  byte [rel vtd_native_marker_domains], 1
    lea  rdi, [rel str_vtd_dma_mapped_marker]
    call serial_string
    mov  byte [rel vtd_native_marker_mapped], 1

    ; A memory-only ownership-state KAT emits the three durable boot markers.
    ; It never alters a physical context; live commands below content-grade it.
    lea  rdi, [rel str_vtd_ready_marker]
    call serial_string
    mov  byte [rel vtd_marker_ready], 1
    mov  byte [rel vtd_kat_owner], 1
    cmp  byte [rel vtd_kat_owner], 1
    jne  .disable
    lea  rdi, [rel str_vtd_assigned_marker]
    call serial_string
    mov  byte [rel vtd_marker_assigned], 1
    mov  byte [rel vtd_kat_owner], 0
    cmp  byte [rel vtd_kat_owner], 0
    jne  .disable
    lea  rdi, [rel str_vtd_reclaimed_marker]
    call serial_string
    mov  byte [rel vtd_marker_reclaimed], 1
    mov  byte [rel vtd_outcome], VTD_OUT_OK
    jmp  .done
.ccmd_kat_fail:
    lea  rdi, [rel str_vtd_ccmd_kat_fail]
    call serial_string
    jmp  .done
; SEC-D3 skip marker (admin 10/08 04:54): each capability/allocation gate that
; leaves the unit unowned says which one, with a fixed token and nothing else.
.skip_no_drhd:
    lea  rdi, [rel str_vtd_skip_no_drhd]
    jmp  .skip_say
.skip_mmio_uc:
    lea  rdi, [rel str_vtd_skip_mmio_uc]
    jmp  .skip_say
.skip_sllps1g:
    lea  rdi, [rel str_vtd_skip_sllps1g]
    jmp  .skip_say
.skip_sagaw48:
    lea  rdi, [rel str_vtd_skip_sagaw48]
    jmp  .skip_say
.skip_tes_fw:
    lea  rdi, [rel str_vtd_skip_tes_fw]
    jmp  .skip_say
.skip_alloc:
    lea  rdi, [rel str_vtd_skip_alloc]
    jmp  .skip_say
.skip_carve:
    lea  rdi, [rel str_vtd_skip_carve]
    jmp  .skip_say
; Later exits (admin 05:18, rc-qemu 07:14: the QEMU unit passes every early gate).
.skip_pmen:
    lea  rdi, [rel str_vtd_skip_pmen]
    jmp  .skip_say
.skip_srtp:
    lea  rdi, [rel str_vtd_skip_srtp]
    jmp  .skip_say
.skip_coverage:
    lea  rdi, [rel str_vtd_skip_coverage]
    jmp  .skip_say
.skip_domain:
    lea  rdi, [rel str_vtd_skip_domain]
    jmp  .skip_say
.skip_qi:
    lea  rdi, [rel str_vtd_skip_qi]
    jmp  .skip_say
.skip_inval:
    lea  rdi, [rel str_vtd_skip_inval]
.skip_say:
    mov  [rel vtd_out_line], rdi             ; RCQ-12: the line this exit prints
    mov  byte [rel vtd_outcome], VTD_OUT_SKIP
    call serial_string
    jmp  .done
; After TE was issued: say why, then the SAME bounded disable path as before.
.skip_te_timeout:
    lea  rdi, [rel str_vtd_skip_te_timeout]
    jmp  .skip_record_disable
.skip_te_faults:
    lea  rdi, [rel str_vtd_skip_te_faults]
    jmp  .skip_record_disable
.skip_te_bind:
    lea  rdi, [rel str_vtd_skip_te_bind]
.skip_record_disable:
    mov  [rel vtd_out_line], rdi
    mov  byte [rel vtd_outcome], VTD_OUT_SKIP
.skip_say_disable:
    call serial_string
    jmp  .disable
.disable:
    call vtd_disable_te
.done:
    cmp  byte [rel vtd_outcome], VTD_OUT_NOT_RUN   ; no ok and no skip line
    jne  .recorded
    mov  byte [rel vtd_outcome], VTD_OUT_SILENT
.recorded:
    pop  rbx
    ret

; vtd_outcome_get (RCQ-12, root 19:01:42) -> EAX = the outcome vtd_ownership_init
;   recorded (VTD_OUT_*), and on SKIP RSI = the reason token: the recorded skip line
;   after its fixed prefix (ends at CR). A line without that exact prefix reads as
;   VTD_OUT_BAD. Memory only: no MMIO, no lock, no re-probe. Clobbers RAX, RCX, RSI, RDI.
vtd_outcome_get:
    movzx eax, byte [rel vtd_outcome]
    cmp  eax, VTD_OUT_OK
    ja   .bad
    cmp  eax, VTD_OUT_SKIP
    jne  .ret
    mov  rsi, [rel vtd_out_line]
    test rsi, rsi
    jz   .bad
    lea  rdi, [rel str_vtd_skip_no_drhd]     ; every skip line shares its first 35 bytes
    mov  ecx, VTD_SKIP_PREFIX_LEN
    cld
    repe cmpsb                           ; RSI ends on the token
    jne  .bad
.ret:
    ret
.bad:
    mov  eax, VTD_OUT_BAD
    ret

; Callback(EDI=bus, ESI=dev, EDX=fn, ECX=vendev). Select only a secondary
; Realtek Ethernet function; Intel 8086 can never enter this ownership path.
vtd_find_secondary_cb:
    push rbx
    push r12
    mov  r12d, ecx                       ; vendor/device survives cfg class read
    mov  ebx, edi
    shl  ebx, 8
    mov  eax, esi
    shl  eax, 3
    or   ebx, eax
    or   ebx, edx
    mov  eax, [rel vtd_bdf_count]
    cmp  eax, VTD_BDF_MAX
    jae  .record_overflow
    lea  rdi, [rel vtd_bdf_list]
    mov  [rdi + rax*4], ebx
    inc  eax
    mov  [rel vtd_bdf_count], eax
    jmp  .recorded
.record_overflow:
    mov  byte [rel vtd_bdf_overflow], 1
.recorded:
    ; The BDF-list store above uses RDI as its destination and therefore no
    ; longer leaves callback EDI holding the bus number.  Read through the
    ; packed-BDF helper so the class code comes from the function we just
    ; recorded (the old direct call queried a bogus bus and found no devices).
    mov  edi, ebx
    mov  esi, 8
    call pci_bdf_read
    mov  r8d, eax
    shr  eax, 16                         ; base class/subclass
    cmp  ax, VTD_CLASS_ETH
    jne  .not_eth
    cmp  r12w, 0x8086
    jne  .maybe_secondary
    ; RCQ-50 G0: the lifeline is the function the e1000e driver bound (its MAC and
    ; rings armed; bus, dev and fn as vtd_native_nic_probe resolves them), not the
    ; last Intel Ethernet function walked. Any other Intel NIC is an ordinary peer.
    cmp  byte [rel e1000e_mac_ok], 1
    jne  .maybe_secondary
    cmp  byte [rel e1000e_rings_ok], 1
    jne  .maybe_secondary
    xor  eax, eax
    cmp  byte [rel e1000e_bus_route_active], 0
    je   .intel_bus
    cmp  byte [rel e1000e_bus_route_active], 1
    jne  .maybe_secondary
    mov  eax, [rel e1kr_bus]
    cmp  eax, 255
    ja   .maybe_secondary
.intel_bus:
    mov  ecx, [rel e1000e_pci_dev]
    cmp  ecx, 31
    ja   .maybe_secondary
    mov  edx, [rel e1000e_pci_fn]
    cmp  edx, 7
    ja   .maybe_secondary
    shl  eax, 8
    shl  ecx, 3
    or   eax, ecx
    or   eax, edx
    cmp  eax, ebx
    jne  .maybe_secondary
    mov  [rel vtd_e1000e_bdf], ebx
    mov  byte [rel vtd_e1000e_found], 1
.maybe_secondary:
    cmp  r12w, 0x10EC
    jne  .cb_done
    cmp  byte [rel vtd_secondary_found], 1
    je   .cb_done
    mov  [rel vtd_secondary_bdf], ebx
    mov  byte [rel vtd_secondary_found], 1
    jmp  .cb_done
.not_eth:
    mov  eax, r8d
    shr  eax, 8                          ; base/subclass/prog-if
    cmp  eax, VTD_CLASS_XHCI
    jne  .not_xhci
    mov  [rel vtd_xhci_bdf], ebx
    mov  byte [rel vtd_xhci_found], 1
    jmp  .cb_done
.not_xhci:
    ; Every 01:08 NVM function is a DMA requester regardless of its PCI
    ; programming-interface byte. Keep the exact BDF live-discovered; the
    ; device is optional, but it must be covered whenever it is present.
    mov  eax, r8d
    shr  eax, 16
    cmp  ax, VTD_CLASS_NVM
    jne  .not_nvme
    mov  [rel vtd_nvme_bdf], ebx
    mov  byte [rel vtd_nvme_found], 1
    jmp  .cb_done
.not_nvme:
    cmp  ax, VTD_CLASS_SATA
    jne  .cb_done
    mov  [rel vtd_sata_bdf], ebx
    mov  byte [rel vtd_sata_found], 1
.cb_done:
    pop  r12
    pop  rbx
.ret:
    ret

; After discovery: a board whose AHCI lives in the Intel VMD child domain (MSI:
; the only PCH SATA-slot function is the class 08/80 VMD-managed placeholder) has
; no 01:06 function, and every child's DMA carries the VMD endpoint's requester
; ID. That endpoint is then the SATA requester DID 2 covers. Only on the AHCI
; backend's own facts (present, driven as a VMD child) and exactly one VMD root,
; recorded once by this walk and still reading Intel class 01/04/00. A scoped
; unit validates its SATA function before this runs, so it stays fail-closed.
vtd_sata_vmd_select:
    mov  byte [rel vtd_sata_vmd_step], 1     ; diagnostic: the last check reached (VTD COVERAGE)
    cmp  byte [rel vtd_sata_found], 0
    jne  .out
    mov  byte [rel vtd_sata_vmd_step], 2
    cmp  byte [rel ahci_present], 1
    jne  .out
    mov  byte [rel vtd_sata_vmd_step], 3
    cmp  byte [rel ahci_vmd_child], 1
    jne  .out
    mov  byte [rel vtd_sata_vmd_step], 4
    cmp  byte [rel vmd_root_count], 1
    jne  .out
    mov  byte [rel vtd_sata_vmd_step], 5
    cmp  byte [rel vmd_ecam_mapped], 1
    jne  .out
    mov  byte [rel vtd_sata_vmd_step], 6
    mov  eax, [rel vmd_root_bus]
    cmp  eax, 255
    ja   .out
    mov  ecx, [rel vmd_root_dev]
    cmp  ecx, 31
    ja   .out
    mov  edx, [rel vmd_root_fn]
    cmp  edx, 7
    ja   .out
    shl  eax, 8
    shl  ecx, 3
    or   eax, ecx
    or   eax, edx                        ; packed BDF
    push rbx
    mov  ebx, eax
    xor  ecx, ecx                        ; occurrences in this walk's inventory
    xor  edx, edx
    lea  rsi, [rel vtd_bdf_list]
.count:
    cmp  edx, [rel vtd_bdf_count]
    jae  .counted
    cmp  [rsi + rdx*4], ebx
    jne  .next
    inc  ecx
.next:
    inc  edx
    jmp  .count
.counted:
    mov  byte [rel vtd_sata_vmd_step], 7
    mov  [rel vtd_sata_vmd_hits], cl         ; occurrences of the VMD root in the inventory
    cmp  ecx, 1
    jne  .pop
    mov  byte [rel vtd_sata_vmd_step], 8
    mov  edi, ebx
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0x8086
    jne  .pop
    mov  byte [rel vtd_sata_vmd_step], 9
    mov  edi, ebx
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 8
    cmp  eax, 0x010400                   ; VMD RAID class|sub|progif
    jne  .pop
    mov  byte [rel vtd_sata_vmd_step], 10
    mov  [rel vtd_sata_bdf], ebx
    mov  byte [rel vtd_sata_found], 1
.pop:
    pop  rbx
.out:
    ret

; Resolve only an existing selected, registered and BOUND native PCI backend.
; No class-based Intel guess, default BDF, USB ancestor guess or guest backend.
; EAX=1, EDI=packed BDF, RSI=handle, RDX=registration generation, else EAX=0.
; Uses at most 512 bytes of bounded claim scratch; no allocation or device write.
vtd_native_nic_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 512
    mov  byte [rel vtd_nic_probe_step], 1    ; diagnostic: the last check reached (VTD COVERAGE)
    mov  byte [rel vtd_nic_probe_backend], 0
    mov  byte [rel vtd_nic_probe_link_wait], 0
    xor  ebp, ebp                            ; 1: the Killer is DEGRADED only for its link
    call netdev_select_peek
    mov  r12, rax
    lea  rdx, [rel e1000e_dev]
    cmp  rax, rdx
    je   .intel
    lea  rdx, [rel e5000b_dev]
    cmp  rax, rdx
    je   .rtl8126
    lea  rdx, [rel rtl8168_dev]
    cmp  rax, rdx
    jne  .link_wait
    mov  byte [rel vtd_nic_probe_backend], 3
    mov  byte [rel vtd_nic_probe_step], 2
    cmp  byte [rel rtl8168_claim_found], 1
    jne  .bad
    cmp  byte [rel rtl8168_bound], 1
    jne  .bad
    cmp  byte [rel rtl8168_mac_ok], 1
    jne  .bad
    lea  rsi, [rel rtl8168_ops]
    mov  ebx, [rel rtl8168_pci_bus]
    mov  ecx, [rel rtl8168_pci_dev]
    mov  edx, [rel rtl8168_pci_fn]
    mov  r14d, PCI_DRV_RTL8168
    jmp  .bdf
.link_wait:
    ; No native NIC is selectable, but the MSI's Killer may be bound with its MAC and
    ; rings armed and only its link late (rtl8126.asm .link_late: DEGRADED with
    ; NETDEV_F_LINK_WAIT until P8's netdev_link_reprobe). VT-d init runs before P8 and
    ; the Killer is already a DMA requester, so take it with every witness below.
    lea  rdi, [rel e5000b_dev]
    lea  rsi, [rel e5000b_ops]
    call netdev_link_wait_member
    test rax, rax
    jz   .bad
    lea  r12, [rel e5000b_dev]
    mov  ebp, 1
    mov  byte [rel vtd_nic_probe_link_wait], 1
.rtl8126:
    ; MSI onboard Killer E5000B: its own single-match bind, registration,
    ; live MAC and dma_alloc rings, then the same claim/inventory witnesses.
    mov  byte [rel vtd_nic_probe_backend], 2
    mov  byte [rel vtd_nic_probe_step], 2
    cmp  dword [rel e5000b_matches], 1
    jne  .bad
    cmp  byte [rel e5000b_registered], 1
    jne  .bad
    cmp  byte [rel e5000b_mac_ok], 1
    jne  .bad
    cmp  byte [rel e5000b_rings_ok], 1
    jne  .bad
    lea  rsi, [rel e5000b_ops]
    mov  ebx, [rel e5000b_pci_bus]
    mov  ecx, [rel e5000b_pci_dev]
    mov  edx, [rel e5000b_pci_fn]
    mov  r14d, PCI_DRV_RTL8126
    jmp  .bdf
.intel:
    mov  byte [rel vtd_nic_probe_backend], 1
    mov  byte [rel vtd_nic_probe_step], 2
    cmp  byte [rel e1000e_mac_ok], 1
    jne  .bad
    cmp  byte [rel e1000e_rings_ok], 1
    jne  .bad
    lea  rsi, [rel e1000e_ops]
    xor  ebx, ebx
    cmp  byte [rel e1000e_bus_route_active], 0
    je   .intel_bus
    cmp  byte [rel e1000e_bus_route_active], 1
    jne  .bad
    mov  ebx, [rel e1kr_bus]
.intel_bus:
    mov  ecx, [rel e1000e_pci_dev]
    mov  edx, [rel e1000e_pci_fn]
    mov  r14d, PCI_DRV_E1000E
.bdf:
    mov  byte [rel vtd_nic_probe_step], 3
    cmp  ebx, 255
    ja   .bad
    cmp  ecx, 31
    ja   .bad
    cmp  edx, 7
    ja   .bad
    shl  ebx, 8
    shl  ecx, 3
    or   ebx, ecx
    or   ebx, edx
    mov  r13d, ebx
    mov  rdi, r12
    test ebp, ebp
    jnz  .link_member
    call netdev_power_member             ; exact ops, registered/healthy/not absent
    jmp  .member
.link_member:
    call netdev_link_wait_member         ; the same seam: DEGRADED only for its link
.member:
    test rax, rax
    jz   .bad
    mov  r15, rdx
    mov  byte [rel vtd_nic_probe_step], 4
    cmp  byte [rel vtd_bdf_overflow], 0
    jne  .bad
    mov  ecx, [rel vtd_bdf_count]
    test ecx, ecx
    jz   .bad
    cmp  ecx, VTD_BDF_MAX
    ja   .bad
    lea  rdx, [rel vtd_bdf_list]
    xor  eax, eax
.inventory:
    cmp  [rdx], r13d
    jne  .next
    inc  eax
.next:
    add  rdx, 4
    loop .inventory
    cmp  eax, 1                         ; unique live enumeration witness
    jne  .bad
    mov  byte [rel vtd_nic_probe_step], 5
    mov  rdi, rsp
    call pci_claim_snapshot
    test edx, edx                       ; dropped/invalid claim census refuses
    jnz  .bad
    cmp  eax, 32
    ja   .bad
    mov  byte [rel vtd_nic_probe_step], 6
    mov  ecx, eax
    mov  rdx, rsp
    xor  ebp, ebp
.claim:
    test ecx, ecx
    jz   .claims_done
    cmp  [rdx], r13d
    jne  .claim_next
    inc  ebp
    cmp  [rdx + 4], r14d
    jne  .bad
    cmp  dword [rdx + 8], PCI_CLAIM_BOUND
    jne  .bad
.claim_next:
    add  rdx, 16
    dec  ecx
    jmp  .claim
.claims_done:
    cmp  ebp, 1
    jne  .bad
    mov  byte [rel vtd_nic_probe_step], 7
    mov  edi, r13d
    xor  esi, esi
    call pci_bdf_read
    mov  edx, 0x8086
    cmp  r14d, PCI_DRV_E1000E
    je   .vendor
    mov  edx, 0x10EC
.vendor:
    cmp  ax, dx
    jne  .bad
    mov  edi, r13d
    mov  esi, 8
    call pci_bdf_read
    mov  byte [rel vtd_nic_probe_step], 8
    shr  eax, 16
    cmp  ax, VTD_CLASS_ETH
    jne  .bad
    mov  byte [rel vtd_nic_probe_step], 9
    mov  edi, r13d
    mov  rsi, r12
    mov  rdx, r15
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 512
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Pin once from the boot inventory, before any context construction or TE.
; Current checks never rebind a changed owner. Preserve all registers but RAX.
vtd_native_nic_bind:
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    call vtd_native_nic_probe
    cmp  byte [rel vtd_nic_boot_step], 0     ; diagnostic: keep the first (boot) probe's step
    jne  .step_kept
    movzx r8d, byte [rel vtd_nic_probe_step]
    mov  [rel vtd_nic_boot_step], r8b
    movzx r8d, byte [rel vtd_nic_probe_backend]
    mov  [rel vtd_nic_boot_backend], r8b
    movzx r8d, byte [rel vtd_nic_probe_link_wait]
    mov  [rel vtd_nic_boot_link_wait], r8b
.step_kept:
    test eax, eax
    jz   .out
    cmp  byte [rel vtd_native_nic_found], 0
    jne  .existing
    mov  [rel vtd_native_nic_bdf], edi
    mov  [rel vtd_native_nic_handle], rsi
    mov  [rel vtd_native_nic_generation], rdx
    mov  byte [rel vtd_native_nic_found], 1 ; publish only complete witnessed identity
    ; A native RTL is not the guest secondary even if the classifier saw it.
    cmp  edi, [rel vtd_secondary_bdf]
    jne  .out
    mov  byte [rel vtd_secondary_found], 0
    jmp  .out
.existing:
    call vtd_native_nic_current
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    ret

vtd_native_nic_current:
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    cmp  byte [rel vtd_native_nic_found], 1
    jne  .bad
    call vtd_native_nic_probe
    test eax, eax
    jz   .out
    cmp  edi, [rel vtd_native_nic_bdf]
    jne  .bad
    cmp  rsi, [rel vtd_native_nic_handle]
    jne  .bad
    cmp  rdx, [rel vtd_native_nic_generation]
    jne  .bad
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    ret


; Discovery/native DMA construction may omit a command NIC in boot_only, which
; forbids native networking, and (W4a, ROOT109426 (2)(a), SEC109455) in normal
; policy when no native NIC is bound: otherwise a stock Intel machine without a
; native driver ran with no DMA remapping at all. network_guest reserves PCI
; NICs before probes and uses the same strict absence check as normal. It does
; not invent a native lifeline or relax actual group/reset qualification.
; Any other policy value refuses.
; A published native witness is always checked in full; it can never become
; optional after a lost claim or changed registration. A newly selectable
; native backend (valid or broken) is not absence and cannot be silently
; adopted after the boot bind.
; This does not relax the legacy secondary-NIC assignment/lifeline gates.
; Preserve every register except RAX, like vtd_native_nic_current.
vtd_native_nic_optional_current:
    cmp  byte [rel vtd_native_nic_found], 0
    jne  vtd_native_nic_current
    cmp  qword [rel native_driver_selected_policy], 2 ; normal/boot_only/network_guest
    ja   .bad
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    call vtd_native_nic_probe
    test eax, eax
    jnz  .unexpected_native
    cmp  byte [rel vtd_nic_probe_backend], 0
    jne  .unexpected_native
    cmp  qword [rel native_driver_selected_policy], 1
    je   .absent                          ; boot_only: the gate already forbids native NET
    call vtd_normal_absence_strict
    test eax, eax
    jz   .unexpected_native
.absent:
    mov  eax, 1
    jmp  .out
.unexpected_native:
    xor  eax, eax
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    ret
.bad:
    xor  eax, eax
    ret

; Under normal/network_guest "no selectable native NIC" is not yet absence. A
; native NIC registered at any health (DEGRADED, LINK_WAIT) or claimed by a
; native NIC driver (BOUND, or FAILED as discovery also counts it) may have
; armed rings; it must be witnessed, never left unwitnessed in DID 1. Requires
; no such member, no such claim, and an exact claim record (none dropped).
; EAX=1 strict absence, else 0. Read-only; clobbers RAX,RCX,RDX,RSI,RDI,R8-R11.
vtd_normal_absence_strict:
    sub  rsp, 512 + 8
    call netdev_pci_member_present
    test eax, eax
    jnz  .no
    mov  rdi, rsp
    call pci_claim_snapshot
    test edx, edx
    jnz  .no
    xor  ecx, ecx
.claim:
    cmp  ecx, eax
    jae  .yes
    mov  edx, ecx
    shl  edx, 4
    mov  edx, [rsp + rdx + 4]             ; driver id
    cmp  edx, PCI_DRV_E1000E
    je   .no
    cmp  edx, PCI_DRV_RTL8125
    je   .no
    cmp  edx, PCI_DRV_RTL8126
    je   .no
    cmp  edx, PCI_DRV_RTL8168
    je   .no
    inc  ecx
    jmp  .claim
.yes:
    mov  eax, 1
    add  rsp, 512 + 8
    ret
.no:
    xor  eax, eax
    add  rsp, 512 + 8
    ret

; Run device/DMA maintenance at a clean VM exit without consuming VM-entry's
; one interrupt slot. A discovered RTL cause is sticky when IRQ0 wins.
vtd_guest_dataplane_prepare:
    cmp  byte [rel vtd_network_mode], 1
    jne  .no
    cmp  byte [rel vtd_owner_guest], 1
    jne  .no
    cmp  byte [rel vtd_vpci_active], 1
    jne  .no
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    call vtd_rtl_sample_live
    call vtd_rtl_try_bind_phy_edge
    call vtd_rtl_prepare_irq
    mov  [rel vtd_net_service_result], al
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    movzx eax, byte [rel vtd_net_service_result]
    ret
.no:
    xor  eax, eax
    ret

; Called only after vcon and a due IRQ0 declined the entry slot.
vtd_guest_dataplane_try_inject:
    cmp  byte [rel vtd_network_mode], 1
    jne  .no
    cmp  byte [rel vtd_owner_guest], 1
    jne  .no
    cmp  byte [rel vtd_vpci_active], 1
    jne  .no
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    call vtd_rtl_try_inject_pending
    mov  [rel vtd_net_service_result], al
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    movzx eax, byte [rel vtd_net_service_result]
    ret
.no:
    xor  eax, eax
    ret

; Bind the arbitration receipt to the existing general E2 tick path.
vtd_guest_dataplane_timer_due:
    cmp  byte [rel vtd_network_mode], 1
    jne  .done
    cmp  byte [rel vtd_owner_guest], 1
    jne  .done
    inc  dword [rel vtd_net_timer_due]
.done:
    ret

vtd_guest_dataplane_irq0_injected:
    cmp  byte [rel vtd_network_mode], 1
    jne  .done
    cmp  byte [rel vtd_owner_guest], 1
    jne  .done
    inc  dword [rel vtd_net_timer_injections]
    cmp  word [rel vtd_net_irq_pending], 0
    je   .done
    ; The RTL cause remains pending while IRQ0 opens the NAPI/softirq window.
    inc  dword [rel vtd_net_irq0_deferrals]
.done:
    ret

; Persist the live hardware gates so a failed run names its boundary.
vtd_rtl_sample_live:
    mov  rdx, [rel vtd_secondary_bar2_mmio]
    test rdx, rdx
    jz   .done
    movzx eax, byte [rdx + 0x37]           ; ChipCmd
    mov  [rel vtd_net_chipcmd], al
    movzx eax, word [rdx + 0x3C]           ; IntrMask
    mov  [rel vtd_net_imr], ax
    movzx eax, word [rdx + 0x3E]           ; IntrStatus
    mov  [rel vtd_net_isr], ax
    movzx eax, byte [rdx + 0x6C]           ; PHYSTS
    mov  [rel vtd_net_physts], al
.done:
    ret

; Re-assert the passed RTL's physical carrier edge once r8169 has bound.
;
; Classic 9696 proved this exact bind-instant BMCR down/up one-shot 4/4:
; the native-to-guest handoff's original LinkChg can be acknowledged before
; r8169 binds, and holding that old interrupt alone leaves phylib's latched
; link-down state stale.  A real PHY transition after ChipCmd.TE and IntrMask
; are live refreshes both the PHY state and the MAC's LinkChg cause.  This runs
; only while the selected secondary Realtek is guest-owned; the e1000e/.50
; lifeline is neither selected nor touched.  The live TxPoll register and all
; 64 guest r8169 TX descriptors must be quiescent, preserving Classic's db_ct==0
; safety invariant without trapping or rewriting the guest's BAR accesses.
; vtd_rtl_prepare_irq retains the new real cause immediately after this returns.
vtd_rtl_try_bind_phy_edge:
    cmp  byte [rel vtd_network_mode], 1
    jne  .ret
    cmp  byte [rel vtd_owner_guest], 1
    jne  .ret
    cmp  byte [rel vtd_vpci_active], 1
    jne  .ret
    cmp  word [rel vtd_secondary_cfg], 0x10EC
    jne  .ret
    cmp  byte [rel vtd_net_phy_edge_state], 0
    jne  .ret
    movzx eax, byte [rel vtd_net_chipcmd]
    and  eax, 0x0C                             ; r8169 enabled ChipCmd.TE|RE
    cmp  eax, 0x0C
    jne  .predelay
    cmp  word [rel vtd_net_imr], 0              ; r8169 unmasked device causes
    je   .predelay
    mov  r12, [rel vtd_secondary_bar2_mmio]
    test r12, r12
    jz   .ret
    call vtd_rtl_tx_quiescent
    test eax, eax
    jz   .tx_not_quiescent
    movzx eax, byte [r12 + 0x38]              ; TxPoll: NPQ/HPQ doorbell
    mov  [rel vtd_net_phy_edge_tppoll], al
    test al, al
    jnz  .tx_not_quiescent
    movzx eax, byte [rel vtd_net_chipcmd]
    mov  [rel vtd_net_phy_edge_chipcmd], al
    movzx eax, word [rel vtd_net_imr]
    mov  [rel vtd_net_phy_edge_imr], ax

    ; PHY reg 0 (BMCR) through RTL8168H GPHY_OCP: real down, then
    ; autoneg-enabled restart.  The settled edge, not a synthetic ISR bit, is
    ; what lets the guest's phylib leave PHY_NOLINK deterministically.
    xor  edi, edi
    mov  esi, 0x0800
    call vtd_rtl_gphy_ocp_write
    mfence
    mov  ecx, 8000000
.down_settle:
    pause
    dec  ecx
    jnz  .down_settle

    xor  edi, edi
    mov  esi, 0x1200
    call vtd_rtl_gphy_ocp_write
    mfence
    mov  ecx, 8000000
.up_settle:
    pause
    dec  ecx
    jnz  .up_settle

    movzx eax, byte [r12 + 0x6C]
    mov  [rel vtd_net_phy_edge_physts], al
    movzx eax, word [r12 + 0x3E]
    mov  [rel vtd_net_phy_edge_isr], ax
    mov  byte [rel vtd_net_phy_edge_state], 1
    inc  dword [rel vtd_net_phy_edge_fires]
.ret:
    ret
.tx_not_quiescent:
    inc  dword [rel vtd_net_phy_edge_txblocks]
    ret
.predelay:
    inc  dword [rel vtd_net_phy_edge_predelays]
    ret

; EAX=1 only when r8169's complete 64-entry TX ring exists in bounded guest
; RAM and has no device-owned descriptor.  This is the in-flight half of the
; bind-one-shot safety gate; TxPoll itself is sampled by the caller.
vtd_rtl_tx_quiescent:
    mov  eax, [r12 + 0x20]                    ; TNPDS low
    mov  edx, [r12 + 0x24]                    ; TNPDS high
    shl  rdx, 32
    or   rax, rdx
    mov  [rel vtd_net_phy_edge_tnpds], rax
    test rax, rax
    jz   .no
    mov  rdi, rax
    mov  esi, 1024                            ; r8169 NUM_TX_DESC=64, 16 bytes each
    call hv_linux_gpa2hva
    test rax, rax
    jz   .no
    mov  byte [rel vtd_net_phy_edge_txring], 1
    mov  rdx, rax
    xor  ecx, ecx
    xor  r8d, r8d
.scan:
    mov  eax, [rdx]
    test eax, 0x80000000                      ; TxDesc.opts1 OWN
    jz   .next
    inc  r8d
.next:
    add  rdx, 16
    inc  ecx
    cmp  ecx, 64
    jb   .scan
    mov  [rel vtd_net_phy_edge_txown], r8d
    xor  eax, eax
    test r8d, r8d
    setz al
    ret
.no:
    xor  eax, eax
    ret

; R12=secondary RTL MMIO, EDI=MII register, ESI=value.  This is the proven
; RTL8168H GPHY-OCP write primitive from Classic's live driver.
vtd_rtl_gphy_ocp_write:
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
.wait:
    mov  eax, [r12 + 0xB8]
    test eax, 0x80000000
    jz   .done
    pause
    dec  ecx
    jnz  .wait
.done:
    mov  ecx, 5000
.delay:
    pause
    dec  ecx
    jnz  .delay
    pop  rcx
    ret

; RAX = the checksummed, identity-mapped DMAR table (ECX = its length), else
; RAX = 0. Shared by DRHD selection and the RCQ-19 RMRR scope walk.
vtd_dmar_locate:
    push rbx
    mov  rbx, [rel acpi_xsdt]
    test rbx, rbx
    jz   .none
    mov  rax, 0x400000000 - 36
    cmp  rbx, rax
    ja   .none
    mov  ecx, [rbx + 4]
    cmp  ecx, 0x100000
    ja   .none
    lea  rax, [rbx + rcx]
    mov  rdx, 0x400000000
    cmp  rax, rdx
    ja   .none
    cmp  ecx, 36
    jb   .none
    sub  ecx, 36
    test ecx, 7
    jnz  .none
    shr  ecx, 3
    lea  rsi, [rbx + 36]
.xsdt_next:
    test ecx, ecx
    jz   .none
    mov  rdx, [rsi]
    test rdx, rdx
    jz   .xsdt_advance
    mov  rax, 0x400000000 - 36
    cmp  rdx, rax                         ; complete SDT header must be identity mapped
    ja   .xsdt_advance
    cmp  dword [rdx], 'DMAR'
    je   .dmar
.xsdt_advance:
    add  rsi, 8
    dec  ecx
    jmp  .xsdt_next
.dmar:
    mov  ecx, [rdx + 4]
    cmp  ecx, 48
    jb   .none
    cmp  ecx, 0x100000                   ; firmware table walk stays bounded
    ja   .none
    lea  rax, [rdx + rcx]
    mov  r9, 0x400000000
    cmp  rax, r9
    ja   .none
    mov  r8d, ecx
    mov  r9, rdx
    xor  eax, eax
.dmar_checksum:
    add  al, [r9]
    inc  r9
    dec  r8d
    jnz  .dmar_checksum
    test al, al
    jnz  .none
    mov  rax, rdx
    pop  rbx
    ret
.none:
    xor  eax, eax
    pop  rbx
    ret

; RAX = live INCLUDE_PCI_ALL unit, or a fully covered supported scoped unit.
; Zero means no usable native topology. The historical symbol is retained.
vtd_find_include_all_drhd:
    call vtd_dmar_locate
    test rax, rax
    jz   .none
    mov  rdx, rax
    lea  rsi, [rdx + 48]
    add  rdx, rcx
.drhd_next:
    cmp  rsi, rdx
    jae  .none
    lea  rax, [rsi + 4]
    cmp  rax, rdx
    ja   .none
    movzx ecx, word [rsi + 2]
    cmp  ecx, 16
    jb   .none
    lea  rax, [rsi + rcx]
    cmp  rax, rdx
    ja   .none
    cmp  word [rsi], 0                    ; DRHD
    jne  .drhd_advance
%ifndef PAOS_VTD_QEMU_SCOPED_DRHD
    test byte [rsi + 4], 1                ; INCLUDE_PCI_ALL
    jz   .drhd_advance
%endif
    ; NASM_EXTRA=-DPAOS_VTD_QEMU_SCOPED_DRHD is a QEMU-harness variant only
    ; (gauntlet_v2/tools/vtd_ccmd_iommu_qemu_check.py): QEMU's q35 DMAR names
    ; its single segment-0 unit by explicit device scope with flags=0.  No
    ; shipped or lab build defines it.
    cmp  word [rsi + 6], 0                ; this PCI seam owns segment zero only
    jne  .drhd_advance
    mov  rax, [rsi + 8]
    ret
.drhd_advance:
    add  rsi, rcx
    jmp  .drhd_next
.none:
    jmp  vtd_find_scoped_drhd

; Native bounded scoped prerequisite: one segment-zero DRHD, no other
; remapping structures, explicit one-hop scopes covering the complete live
; inventory. Retains flat root-bus endpoints and additionally accepts exactly
; one root-bus PCI bridge with a single bus and one explicitly scoped Ethernet
; endpoint at child device0/function0. No nested/shared bus or implied coverage.
; The optional root-complex IOAPIC is resolved against the validated MADT.
; This is not PAOS_VTD_QEMU_SCOPED_DRHD; no PCI/MMIO writes here. All unit,
; lifeline, group, CAP/TE/DID, assignment and reset gates remain authoritative.
vtd_find_scoped_drhd:
    push r12
    push r13
    call vtd_ioapic_discover              ; optional for endpoint-only, mandatory for type3
    call vtd_dmar_locate
    test rax, rax
    jz   .none
    mov  r12, rax
    mov  r13d, ecx
    ; Discovery is read-only. No allocation, MMIO access or DMA binding until
    ; a complete supported unit covers every function and every lifeline.
    lea  rdi, [rel vtd_find_secondary_cb]
    call pci_scan_with_filter
    call vtd_native_nic_bind
    call vtd_native_nic_optional_current
    test eax, eax
    jz   .none
    mov  rdi, r12
    mov  esi, r13d
    call vtd_scoped_drhd_validate
    test rax, rax
    jz   .none
    mov  byte [rel vtd_scoped_unit], 1
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret

; RDI = accessible DMAR span, ESI = exact bounded length -> RAX = unit or 0.
; Match each scope to one index in the complete <=256-function inventory,
; rather than truncating packed BDF to a root-bus bitmap. A 256-bit seen set
; rejects duplicate scopes. A type2 bridge also covers its independently
; enumerated sole Ethernet child (VT-d 8.3.1); an explicit child is optional.
; Equal covered cardinality proves no inventory omission or duplicate entry.
; Full 16-bit BDF identity survives every comparison.
; Only one sole-bus/sole-Ethernet child bridge is supported beyond bus zero.
vtd_scoped_drhd_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    call vtd_native_nic_optional_current
    pop  rsi
    pop  rdi
    test eax, eax
    jz   .no_witness
    sub  rsp, 72                         ; seen[32], PCI count, bridge bus, child bus, IOAPIC, census count
    xor  eax, eax
    mov  [rsp], rax
    mov  [rsp + 8], rax
    mov  [rsp + 16], rax
    mov  [rsp + 24], rax
    mov  [rsp + 32], rax
    mov  [rsp + 40], rax
    cmp  byte [rel vtd_bdf_overflow], 0
    jne  .bad
    mov  eax, [rel vtd_bdf_count]
    test eax, eax
    jz   .bad
    cmp  eax, 256
    ja   .bad
    mov  [rsp + 48], eax
    test rdi, rdi
    jz   .bad
    cmp  esi, 72                         ; header + DRHD + at least one scope
    jb   .bad
    cmp  esi, VTD_DMAR_SNAP_PAGES * 4096
    ja   .bad
    cmp  dword [rdi], 'DMAR'
    jne  .bad
    cmp  [rdi + 4], esi
    jne  .bad
    mov  ecx, esi
    xor  edx, edx
    xor  eax, eax
.checksum:
    add  al, [rdi + rdx]
    inc  edx
    loop .checksum
    test al, al
    jnz  .bad
    lea  r12, [rdi + 48]
    sub  esi, 48
    cmp  word [r12], 0                   ; exactly one DRHD, no ignored tail
    jne  .bad
    movzx eax, word [r12 + 2]
    cmp  eax, esi
    jne  .bad
    cmp  dword [r12 + 4], 0              ; flags=0, reserved=0, segment=0
    jne  .bad
    mov  r15, [r12 + 8]
    test r15, r15
    jz   .bad
    test r15, 4095
    jnz  .bad
    mov  rax, 0x400000000 - 4096          ; complete MMIO page identity mapped
    cmp  r15, rax
    ja   .bad
    sub  esi, 16
    test esi, 7
    jnz  .bad
    shr  esi, 3
    cmp  esi, 257                        ; <=256 PCI scopes plus one IOAPIC
    ja   .bad
    mov  r13d, esi
    add  r12, 16
.scope:
    cmp  dword [r12], 0x00000803         ; IOAPIC, length8, reserved0
    je   .ioapic
    mov  ebp, [r12]
    cmp  ebp, 0x00000801                ; endpoint, length8, reserved0
    je   .pci_scope
    cmp  ebp, 0x00000802                ; sub-hierarchy, length8, reserved0
    jne  .bad
.pci_scope:
    cmp  byte [r12 + 4], 0              ; PCI enumeration ID reserved
    jne  .bad
    movzx ebx, byte [r12 + 5]           ; full starting bus, no truncation
    shl  ebx, 8
    movzx eax, byte [r12 + 6]
    cmp  eax, 31
    ja   .bad
    shl  eax, 3
    or   ebx, eax
    movzx eax, byte [r12 + 7]
    cmp  eax, 7
    ja   .bad
    or   ebx, eax
    lea  rdx, [rel vtd_bdf_list]
    xor  ecx, ecx
.find_scope:
    cmp  ecx, [rsp + 48]
    jae  .bad                           ; scope without an enumerated function
    cmp  ebx, [rdx + rcx*4]
    je   .scope_member
    inc  ecx
    jmp  .find_scope
.scope_member:
    bts  qword [rsp], rcx
    jc   .bad                           ; duplicate scope / ambiguous identity
    inc  dword [rsp + 32]
    mov  edi, ebx
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0xFFFF
    je   .bad
    test ax, ax
    jz   .bad
    mov  edi, ebx
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    and  eax, 0x7F
    cmp  ebp, 0x00000802
    je   .bridge
    test eax, eax                       ; endpoint scope must name header0
    jnz  .bad
    cmp  ebx, 255
    jbe  .scope_next                    ; retained root-bus endpoint
    test bl, bl                         ; only child device0/function0
    jnz  .bad
    cmp  dword [rsp + 40], 0
    jne  .bad                           ; exactly one downstream endpoint
    mov  eax, ebx
    shr  eax, 8
    mov  [rsp + 40], eax
    mov  edi, ebx
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 8
    cmp  eax, 0x020000                  ; Ethernet only, exact class/prog-if
    jne  .bad
    jmp  .scope_next
.bridge:
    cmp  eax, 1
    jne  .bad
    cmp  ebx, 255                       ; no nested bridge or multihop paths
    ja   .bad
    test bl, 7                         ; root port function0 only
    jnz  .bad
    cmp  dword [rsp + 36], 0
    jne  .bad                           ; exactly one downstream bus/bridge
    mov  edi, ebx
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 16
    cmp  eax, 0x0604                    ; genuine PCI-to-PCI bridge
    jne  .bad
    mov  edi, ebx
    mov  esi, 0x18
    call pci_bdf_read
    test al, al                         ; primary bus zero
    jnz  .bad
    shr  eax, 8
    test al, al                         ; nonzero secondary
    jz   .bad
    movzx edx, al
    shr  eax, 8
    cmp  al, dl                         ; secondary == subordinate, no hidden bus range
    jne  .bad
    mov  [rsp + 36], edx
    jmp  .scope_next
.ioapic:
    cmp  dword [rsp + 44], 0
    jne  .bad                           ; exactly zero or one IOAPIC
    ; The static Q35 root-complex source ff:00.0 must resolve to the MADT ID.
    cmp  byte [r12 + 5], 0xFF
    jne  .bad
    cmp  word [r12 + 6], 0
    jne  .bad
    mov  rdi, [rel vtd_ioapic_madt]
    mov  esi, [rel vtd_ioapic_madt_len]
    call vtd_ioapic_madt_validate
    test eax, eax
    jz   .bad
    dec  eax
    cmp  al, [r12 + 4]
    jne  .bad
    mov  edi, 0xFF00
    xor  esi, esi
    call pci_bdf_read
    cmp  eax, -1
    jne  .bad                           ; pseudo-source cannot alias live PCI
    mov  dword [rsp + 44], 1
.scope_next:
    add  r12, 8
    dec  r13d
    jnz  .scope
    cmp  dword [rsp + 36], 0
    je   .coverage_count                ; retained flat-bus form
    cmp  dword [rsp + 40], 0
    jne  .coverage_count                ; retained explicit-child form
    ; The checked type2 bridge scope includes downstream devices. Admit only
    ; the same bounded sole device0/function0 Ethernet child as above. Neither
    ; a live config response nor a bridge window invents census membership.
    mov  ebx, [rsp + 36]
    shl  ebx, 8
    lea  rdx, [rel vtd_bdf_list]
    xor  ecx, ecx
.implicit_find:
    cmp  ecx, [rsp + 48]
    jae  .bad
    cmp  ebx, [rdx + rcx*4]
    je   .implicit_member
    inc  ecx
    jmp  .implicit_find
.implicit_member:
    bts  qword [rsp], rcx
    jc   .bad
    mov  edi, ebx
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0xFFFF
    je   .bad
    test ax, ax
    jz   .bad
    mov  edi, ebx
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    and  eax, 0x7F
    jnz  .bad                           ; independently live header0
    mov  edi, ebx
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 8
    cmp  eax, 0x020000                  ; Ethernet only, exact class/prog-if
    jne  .bad
    inc  dword [rsp + 32]
    mov  eax, [rsp + 36]
    mov  [rsp + 40], eax
.coverage_count:
    mov  eax, [rsp + 32]
    cmp  eax, [rsp + 48]
    jne  .bad                           ; all inventory indices covered once
    mov  eax, [rsp + 36]
    cmp  eax, [rsp + 40]
    jne  .bad                           ; bridge and sole child must name the same bus
    cmp  byte [rel vtd_sata_found], 1
    jne  .bad
    cmp  byte [rel vtd_xhci_found], 1
    jne  .bad
    cmp  byte [rel vtd_native_nic_found], 0
    je   .storage_lifelines
    cmp  byte [rel vtd_native_nic_found], 1
    jne  .bad
    mov  edi, [rel vtd_native_nic_bdf]
    call .member
    test eax, eax
    jz   .bad
.storage_lifelines:
    mov  edi, [rel vtd_sata_bdf]
    call .member
    test eax, eax
    jz   .bad
    mov  edi, [rel vtd_xhci_bdf]
    call .member
    test eax, eax
    jz   .bad
    cmp  byte [rel vtd_nvme_found], 0
    je   .ok
    cmp  byte [rel vtd_nvme_found], 1
    jne  .bad
    mov  edi, [rel vtd_nvme_bdf]
    call .member
    test eax, eax
    jz   .bad
.ok:
    mov  rax, r15
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 72
.no_witness:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.member:
    ; Every inventory entry already has checked scope coverage. A lifeline
    ; must still have its recorded full BDF in that census; never infer it.
    xor  ecx, ecx
    lea  rdx, [rel vtd_bdf_list]
.member_next:
    cmp  ecx, [rsp + 56]                ; caller census at +48, return address adds8
    jae  .member_missing
    cmp  edi, [rdx + rcx*4]
    je   .member_found
    inc  ecx
    jmp  .member_next
.member_found:
    mov  eax, 1
    ret
.member_missing:
    xor  eax, eax
    ret

; Optional boot lookup through native ACPI's unique, checksummed, RAM-bounded
; lookup. No live ACPI lookup is permitted after the protected copy is taken.
; The validator below checks the selected MADT body again, including the copy.
vtd_ioapic_discover:
    mov  qword [rel vtd_ioapic_madt], 0
    mov  dword [rel vtd_ioapic_madt_len], 0
    mov  edi, 'APIC'
    call acpi_find_table
    cmp  edx, 1                         ; AF_VALID, not an ambiguous/partial table
    jne  .out
    test rax, rax
    jz   .out
    mov  ecx, [rax + 4]
    cmp  ecx, VTD_IOAPIC_SNAP_PAGES * 4096
    ja   .out
    mov  [rel vtd_ioapic_madt], rax
    mov  [rel vtd_ioapic_madt_len], ecx
.out:
    ret

; RDI/ESI = accessible MADT/exact length, return EAX = singleton IOAPIC ID+1
; or 0. Q35's primary IOAPIC is at fec00000, GSI base0. Multiple IOAPICs,
; SAPIC (which overrides IOAPIC per ACPI), unknown controller structures and
; malformed tails are unsupported. Known non-IOAPIC x86 records are walked
; by their exact standard lengths; none contributes to this source identity.
; Does not read or program IOAPIC MMIO or enable interrupt remapping.
vtd_ioapic_madt_validate:
    xor  r8d, r8d                       ; no singleton identity until full walk ends
    test rdi, rdi
    jz   .bad
    cmp  esi, 56                        ; MADT header44 + IOAPIC12
    jb   .bad
    cmp  esi, VTD_IOAPIC_SNAP_PAGES * 4096
    ja   .bad
    cmp  dword [rdi], 'APIC'
    jne  .bad
    cmp  [rdi + 4], esi
    jne  .bad
    test dword [rdi + 40], 0xFFFFFFFE   ; MADT flags: only PCAT_COMPAT defined
    jnz  .bad
    xor  eax, eax
    xor  edx, edx
    mov  ecx, esi
.checksum:
    add  al, [rdi + rdx]
    inc  edx
    loop .checksum
    test al, al
    jnz  .bad
    add  rdi, 44
    sub  esi, 44
.next:
    test esi, esi
    jz   .done
    cmp  esi, 2
    jb   .bad
    movzx ecx, byte [rdi + 1]
    cmp  ecx, 2
    jb   .bad
    cmp  ecx, esi
    ja   .bad
    movzx eax, byte [rdi]
    cmp  eax, 1
    je   .ioapic
    ; Explicit x86 ancillary structures, not an open-ended unknown-type skip.
    cmp  eax, 0                         ; processor local APIC
    je   .len8
    cmp  eax, 2                         ; interrupt source override
    je   .len10
    cmp  eax, 3                         ; NMI source
    je   .len8
    cmp  eax, 4                         ; local APIC NMI
    je   .len6
    cmp  eax, 5                         ; local APIC address override
    je   .len12
    cmp  eax, 9                         ; processor local x2APIC
    je   .len16
    cmp  eax, 10                        ; local x2APIC NMI
    je   .len12
    jmp  .bad
.len6:
    cmp  ecx, 6
    jne  .bad
    jmp  .advance
.len8:
    cmp  ecx, 8
    jne  .bad
    jmp  .advance
.len10:
    cmp  ecx, 10
    jne  .bad
    jmp  .advance
.len12:
    cmp  ecx, 12
    jne  .bad
    jmp  .advance
.len16:
    cmp  ecx, 16
    jne  .bad
    jmp  .advance
.ioapic:
    cmp  ecx, 12
    jne  .bad
    test r8d, r8d
    jnz  .bad                           ; even a different ID/base is unsupported ambiguity
    cmp  byte [rdi + 3], 0
    jne  .bad
    cmp  dword [rdi + 4], 0xFEC00000
    jne  .bad
    cmp  dword [rdi + 8], 0
    jne  .bad
    movzx r8d, byte [rdi + 2]
    inc  r8d
.advance:
    add  rdi, rcx
    sub  esi, ecx
    jmp  .next
.done:
    mov  eax, r8d
    ret
.bad:
    xor  eax, eax
    ret

; Boot after the DID1 arena carve, before PMEN/RTADDR/GCMD. Re-resolve the
; unique readable MADT, copy <=4KiB after the existing DMAR pages, then expose
; only that protected copy to scoped selection/HDA. Final pre-TE validation
; checks both copied bodies; an absent/oversize MADT cannot retain live facts.
vtd_ioapic_snap_take:
    call vtd_ioapic_discover
    mov  rsi, [rel vtd_ioapic_madt]
    mov  ecx, [rel vtd_ioapic_madt_len]
    mov  rdi, [rel vtd_dmaviol_target_page]
    add  rdi, (1 + VTD_DMAR_SNAP_PAGES) * 4096
    mov  [rel vtd_ioapic_madt], rdi
    test ecx, ecx
    jz   .out
    mov  edx, ecx
    cld
    rep  movsb
    mov  [rel vtd_ioapic_madt_len], edx
.out:
    ret

; Protected copy must name the same complete unit before first hardware write.
; Include-all keeps its existing validated ownership path.
vtd_scoped_snapshot_ok:
    cmp  byte [rel vtd_scoped_unit], 0
    je   .ok
    mov  rdi, [rel vtd_dmar_snap]
    mov  esi, [rel vtd_dmar_snap_len]
    call vtd_scoped_drhd_validate
    test rax, rax
    jz   .bad
    cmp  rax, [rel vtd_unitb_base]
    jne  .bad
.ok:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; RCQ-19 S1 isolation precondition (root 2026-10-08 15:36). Before the
; secondary function is touched, its live topology goes through
; hv/device_assignment's builder and classifier; any refusal (shared, aliased,
; RMRR, protected peer, no IOMMU, incomplete facts) keeps it host-owned and is
; reported by VTD POLICY. Conf1 supplies topology; native VT-d ownership
; also permits the admitted ECAM ACS reader. Each gate takes fresh stable
; Capability/Control bytes, with no write in the snapshot or classifier.
; Everything below reads config space and ACPI only.
; ---------------------------------------------------------------------------

; EDI = packed BDF -> EAX = 1 for a lifeline function (command NIC, boot
; storage, xHCI) discovered at ownership time.
vtd_iso_is_lifeline:
    cmp  byte [rel vtd_native_nic_found], 1
    jne  .intel
    cmp  edi, [rel vtd_native_nic_bdf]
    je   .yes
.intel:
    cmp  byte [rel vtd_e1000e_found], 1
    jne  .sata
    cmp  edi, [rel vtd_e1000e_bdf]
    je   .yes
.sata:
    cmp  byte [rel vtd_sata_found], 1
    jne  .nvme
    cmp  edi, [rel vtd_sata_bdf]
    je   .yes
.nvme:
    cmp  byte [rel vtd_nvme_found], 1
    jne  .xhci
    cmp  edi, [rel vtd_nvme_bdf]
    je   .yes
.xhci:
    cmp  byte [rel vtd_xhci_found], 1
    jne  .no
    cmp  edi, [rel vtd_xhci_bdf]
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; EDI = packed BDF -> RAX = its snapshot entry, else 0.
vtd_iso_snap_find:
    mov  ecx, [rel vtd_iso_snap_n]
    lea  rax, [rel vtd_iso_snap]
.next:
    test ecx, ecx
    jz   .none
    cmp  [rax], di
    je   .found
    add  rax, DA_SNAP_SZ
    dec  ecx
    jmp  .next
.none:
    xor  eax, eax
.found:
    ret

; RDI = DMAR device scope (length already bounded, >= 8, even) -> EAX = the
; BDF its path names, or -1 when a bridge on the path is absent.
vtd_iso_scope_bdf:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    movzx r13d, byte [r12 + 1]
    sub  r13d, 6
    shr  r13d, 1                         ; path hops
    movzx ebx, byte [r12 + 5]            ; start bus
    add  r12, 6
.hop:
    movzx eax, byte [r12]
    and  eax, 0x1F
    shl  eax, 3
    movzx ecx, byte [r12 + 1]
    and  ecx, 7
    or   eax, ecx
    mov  edx, ebx
    shl  edx, 8
    or   eax, edx
    mov  r14d, eax
    dec  r13d
    jz   .named
    mov  edi, r14d
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0xFFFF
    je   .absent
    mov  edi, r14d
    mov  esi, 0x18
    call pci_bdf_read
    shr  eax, 8
    movzx ebx, al                        ; follow the bridge's secondary bus
    add  r12, 2
    jmp  .hop
.named:
    mov  eax, r14d
    jmp  .out
.absent:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Boot, before TE (RCQ-18 DMAR snapshot, root 01:31:41): copy the checksummed
; DMAR into the arena's snapshot pages, which the carve took out of DID 1 and
; which no device domain maps. The live table stays in DID 1's identity map,
; where a compat device could rewrite it, checksum included. A DMAR larger
; than the snapshot leaves vtd_dmar_snap_len 0 and assignment refuses.
; Clobbers RAX, RCX, RDX, RSI, RDI, R8, R9.
vtd_dmar_snap_take:
    mov  dword [rel vtd_dmar_snap_len], 0
    mov  rdi, [rel vtd_dmaviol_target_page]
    add  rdi, 4096
    mov  [rel vtd_dmar_snap], rdi
    call vtd_dmar_locate
    test rax, rax
    jz   .out
    cmp  ecx, VTD_DMAR_SNAP_PAGES * 4096
    ja   .out
    mov  rsi, rax
    mov  rdi, [rel vtd_dmar_snap]
    mov  edx, ecx
    cld
    rep  movsb
    mov  [rel vtd_dmar_snap_len], edx
.out:
    ret

; Mark each snapshot function that a segment-0 RMRR device scope names. A
; structure or scope that does not parse within its bounds leaves the facts
; incomplete (refusal); a path to an absent function names nothing. The RMRRs
; come only from the boot DMAR snapshot: without one the facts are incomplete.
vtd_iso_mark_rmrr:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ecx, [rel vtd_dmar_snap_len]
    cmp  ecx, 48
    jb   .bad
    cmp  ecx, VTD_DMAR_SNAP_PAGES * 4096
    ja   .bad
    mov  rax, [rel vtd_dmar_snap]
    test rax, rax
    jz   .bad
    lea  r12, [rax + 48]
    lea  r13, [rax + rcx]
.struct:
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .done
    movzx r14d, word [r12 + 2]
    cmp  r14d, 8
    jb   .bad
    lea  rax, [r12 + r14]
    cmp  rax, r13
    ja   .bad
    cmp  word [r12], 1                   ; RMRR
    jne  .advance
    cmp  r14d, 24
    jb   .bad
    cmp  word [r12 + 6], 0               ; the owned unit is segment 0
    jne  .advance
    lea  r15, [r12 + 24]
.scope:
    lea  rax, [r12 + r14]
    cmp  r15, rax
    jae  .advance
    lea  rdx, [r15 + 2]
    cmp  rdx, rax
    ja   .bad
    movzx ebx, byte [r15 + 1]
    cmp  ebx, 8
    jb   .bad
    cmp  ebx, 6 + 2 * DA_CHAIN_MAX
    ja   .bad
    test ebx, 1
    jnz  .bad
    lea  rdx, [r15 + rbx]
    cmp  rdx, rax
    ja   .bad
    movzx eax, byte [r15]
    cmp  eax, 1                          ; PCI endpoint
    je   .resolve
    cmp  eax, 2                          ; PCI sub-hierarchy (its bridge)
    jne  .scope_next
.resolve:
    mov  rdi, r15
    call vtd_iso_scope_bdf
    cmp  eax, -1
    je   .scope_next
    mov  edi, eax
    call vtd_iso_snap_find
    test rax, rax
    jz   .scope_next
    or   byte [rax + 2], DA_S_RMRR
.scope_next:
    add  r15, rbx
    jmp  .scope
.advance:
    add  r12, r14
    jmp  .struct
.bad:
    mov  byte [rel vtd_iso_incomplete], 1
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Snapshot every present function from the ownership-time BDF list.
; EAX = entries. More functions than DA_SNAP_MAX, a truncated BDF list or an
; unparseable RMRR scope set vtd_iso_incomplete.
vtd_iso_snapshot:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 72                         ; aligned calls and private ACS sample[64]
    xor  r12d, r12d
    xor  r13d, r13d
    mov  byte [rel vtd_iso_incomplete], 0
    cmp  byte [rel vtd_bdf_overflow], 0
    je   .walk
    mov  byte [rel vtd_iso_incomplete], 1
.walk:
    cmp  r12d, [rel vtd_bdf_count]
    jae  .walked
    cmp  r12d, VTD_BDF_MAX
    jae  .walked
    lea  rax, [rel vtd_bdf_list]
    mov  ebx, [rax + r12*4]
    mov  edi, ebx
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0xFFFF
    je   .next
    cmp  r13d, DA_SNAP_MAX
    jae  .overflow
    lea  r14, [rel vtd_iso_snap]
    lea  r14, [r14 + r13*8]
    mov  qword [r14], 0
    mov  [r14], bx
    mov  edi, ebx
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    and  eax, 0x7F                       ; header type
    cmp  eax, 1
    jne  .caps
    or   byte [r14 + 2], DA_S_BRIDGE
    mov  edi, ebx
    mov  esi, 0x18
    call pci_bdf_read
    shr  eax, 8
    mov  [r14 + 3], al                   ; secondary bus
    shr  eax, 8
    mov  [r14 + 4], al                   ; subordinate bus
.caps:
    mov  edi, ebx
    mov  esi, 0x10                       ; PCI Express capability
    call pci_find_cap
    test eax, eax
    jz   .lifeline
    or   byte [r14 + 2], DA_S_PCIE
    mov  esi, eax
    mov  edi, ebx
    call pci_bdf_read
    shr  eax, 20
    and  eax, 0xF                        ; device/port type
    mov  [r14 + 6], al                   ; private port type, not a fact flag
    cmp  eax, 7                          ; PCIe to PCI/PCI-X bridge
    je   .pci_bridge
    cmp  eax, 8                          ; PCI/PCI-X to PCIe bridge
    je   .pci_bridge
    test byte [r14 + 2], DA_S_BRIDGE
    jz   .lifeline
    cmp  byte [rel vtd_native_ready], 1
    jne  .lifeline
    cmp  eax, 4
    je   .acs
    cmp  eax, 5
    je   .acs
    cmp  eax, 6
    jne  .lifeline
.acs:
    mov  edi, ebx
    mov  rsi, rsp
    call pci_ecam_acs_snapshot
    test eax, eax
    jnz  .lifeline                      ; never use stale output on a refusal
    mov  eax, [rsp + 8]
    mov  edx, eax
    and  eax, 0x1D                      ; SV | RR | CR | UF capabilities
    cmp  eax, 0x1D
    jne  .lifeline
    shr  edx, 16
    and  edx, 0x5D                      ; required controls enabled, DT disabled
    cmp  edx, 0x1D
    jne  .lifeline
    mov  byte [r14 + 5], 1               ; fresh per-port proof for the NIC path
    cmp  byte [r14 + 6], 4               ; group cuts only at a top Root Port
    jne  .lifeline
    test bh, bh                         ; packed BDF bus must be zero
    jnz  .lifeline
    or   byte [r14 + 2], DA_S_ACS
    jmp  .lifeline
.pci_bridge:
    or   byte [r14 + 2], DA_S_PCI_BRIDGE
.lifeline:
    mov  edi, ebx
    call vtd_iso_is_lifeline
    test eax, eax
    jz   .counted
    or   byte [r14 + 2], DA_S_PROTECTED
.counted:
    inc  r13d
.next:
    inc  r12d
    jmp  .walk
.overflow:
    mov  byte [rel vtd_iso_incomplete], 1
.walked:
    mov  [rel vtd_iso_snap_n], r13d
    call vtd_iso_mark_rmrr
    mov  eax, [rel vtd_iso_snap_n]
    add  rsp, 72
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Fresh VT-d ACS proof for one target after vtd_iso_snapshot. EDI=BDF,
; EAX=0 only for a complete path to bus 0 with ACS on EVERY intervening
; PCIe port. Private snapshot bytes 5/6 carry proof/type; no cached enable
; record is consulted. Only the top Root Port receives DA_S_ACS, so the
; existing group builder still includes all downstream DMA peers. Missing,
; ambiguous, over-depth, malformed, absent or disabled ACS always refuses.
; Read-only hardware; writes only this snapshot's derived DA_S_ACS flag.
vtd_iso_acs_target:
    lea  rsi, [rel vtd_iso_snap]
    xor  ecx, ecx
.clear:
    cmp  ecx, [rel vtd_iso_snap_n]
    jae  .start
    cmp  ecx, DA_SNAP_MAX
    jae  .refuse
    and  byte [rsi + rcx*8 + 2], ~DA_S_ACS & 0xFF
    inc  ecx
    jmp  .clear
.start:
    cmp  byte [rel vtd_native_ready], 1
    jne  .refuse
    cmp  byte [rel vtd_iso_incomplete], 0
    jne  .refuse
    movzx edi, di
    shr  edi, 8                         ; target bus (all windows must cover it)
    mov  r9d, edi
    xor  r10d, r10d
.up:
    test r9d, r9d
    jz   .refuse                        ; bus-zero endpoint has no proven port
    cmp  r10d, DA_CHAIN_MAX
    jae  .refuse
    inc  r10d
    xor  ecx, ecx
    mov  edx, -1
.find:
    cmp  ecx, [rel vtd_iso_snap_n]
    jae  .found
    test byte [rsi + rcx*8 + 2], DA_S_BRIDGE
    jz   .next
    movzx eax, byte [rsi + rcx*8 + 3]
    cmp  eax, r9d
    jne  .next
    cmp  edx, -1
    jne  .refuse
    mov  edx, ecx
.next:
    inc  ecx
    jmp  .find
.found:
    cmp  edx, -1
    je   .refuse
    lea  r11, [rsi + rdx*8]
    test byte [r11 + 2], DA_S_PCIE
    jz   .refuse
    cmp  byte [r11 + 5], 1              ; exact success from THIS fresh read
    jne  .refuse
    movzx eax, byte [r11 + 3]
    cmp  edi, eax
    jb   .refuse
    movzx eax, byte [r11 + 4]
    cmp  edi, eax
    ja   .refuse
    movzx eax, word [r11]
    shr  eax, 8
    test eax, eax
    jz   .root
    cmp  eax, r9d
    je   .refuse
    cmp  byte [r11 + 6], 5
    je   .parent
    cmp  byte [r11 + 6], 6
    jne  .refuse                        ; a non-root cannot impersonate Root Port
.parent:
    mov  r9d, eax
    jmp  .up
.root:
    cmp  byte [r11 + 6], 4
    jne  .refuse
    or   byte [r11 + 2], DA_S_ACS
    xor  eax, eax
    ret
.refuse:
    mov  eax, ISO_SHARED_DMA
    ret

; EAX = ISO_* verdict for the secondary function (ISO_ELIGIBLE = 0). Also
; leaves vtd_iso_record (the fact record) for VTD POLICY. Read-only.
vtd_iso_check:
    push rbx                           ; align calls, including the ACS snapshot
    mov  byte [rel vtd_iso_valid], 0
    call vtd_native_nic_current
    test eax, eax
    jz   .no_target
    cmp  byte [rel vtd_secondary_found], 1
    jne  .no_target
    call vtd_iso_snapshot
    xor  r8d, r8d
    cmp  qword [rel vtd_unitb_base], 0
    je   .unit
    or   r8d, DA_H_IOMMU
.unit:
    cmp  byte [rel vtd_ready], 1
    jne  .backend
    or   r8d, DA_H_BACKEND
.backend:
    cmp  byte [rel vtd_iso_incomplete], 0
    je   .facts
    or   r8d, DA_H_INCOMPLETE
.facts:
    lea  rdi, [rel vtd_iso_record]
    lea  rsi, [rel vtd_iso_snap]
    mov  edx, [rel vtd_iso_snap_n]
    mov  ecx, [rel vtd_secondary_bdf]
    call devassign_build_facts
    test eax, eax
    jnz  .verdict
    lea  rdi, [rel vtd_iso_record]
    call devassign_classify
    test eax, eax
    jnz  .verdict                       ; preserve RMRR/lifeline/fact refusals
    mov  edi, [rel vtd_secondary_bdf]
    call vtd_iso_acs_target             ; singleton needs the whole fresh path
.verdict:
    mov  [rel vtd_iso_reason], al
    mov  byte [rel vtd_iso_valid], 1
    pop  rbx
    ret
.no_target:
    mov  byte [rel vtd_iso_valid], 2
    mov  eax, ISO_TRUNC_ACPI             ; nothing to assign is never eligible
    pop  rbx
    ret

; Append " assign_iso=<verdict> iso_parent=<bb:dd.f|root|none> iso_group=<n>
; iso_acs=unknown" for the last vtd_iso_check.
vtd_append_iso_fields:
    push rbx
    lea  rdi, [rel str_vtd_iso_field]
    call vtd_out_str
    cmp  byte [rel vtd_iso_valid], 1
    je   .verdict
    lea  rdi, [rel str_vtd_iso_unchecked]
    cmp  byte [rel vtd_iso_valid], 2
    jne  .unverdicted
    lea  rdi, [rel str_vtd_iso_no_target]
.unverdicted:
    call vtd_out_str
    jmp  .done
.verdict:
    movzx eax, byte [rel vtd_iso_reason]
    cmp  eax, ISO_SEGMENT
    jbe  .named
    mov  eax, ISO_SEGMENT + 1
.named:
    imul eax, eax, VTD_ISO_NAME_STRIDE   ; fixed-stride names: no pointer table
    lea  rdi, [rel vtd_iso_reason_names]
    add  rdi, rax
    call vtd_out_str
    lea  rdi, [rel str_vtd_iso_parent]
    call vtd_out_str
    lea  rbx, [rel vtd_iso_record]
    cmp  byte [rbx + 3], 0
    je   .no_parent
    cmp  byte [rbx + 16 + 4], 1          ; target's parent is record 1
    jne  .root
    movzx edi, byte [rbx + 24 + 2]
    call vtd_out_hex_byte
    lea  rdi, [rel str_vtd_colon]
    call vtd_out_str
    movzx edi, byte [rbx + 24 + 3]
    shr  edi, 3
    call vtd_out_hex_byte
    lea  rdi, [rel str_vtd_dot]
    call vtd_out_str
    movzx edi, byte [rbx + 24 + 3]
    and  edi, 7
    call vtd_out_dec
    jmp  .group
.root:
    lea  rdi, [rel str_vtd_iso_root]
    call vtd_out_str
    jmp  .group
.no_parent:
    lea  rdi, [rel str_ddom_none]
    call vtd_out_str
.group:
    ; members that share the target's group, the target excluded
    lea  rdi, [rel str_vtd_iso_group]
    call vtd_out_str
    movzx ecx, byte [rbx + 3]
    xor  edi, edi
    mov  edx, 1
.member:
    cmp  edx, ecx
    jae  .count
    cmp  byte [rbx + 16 + rdx*8 + 7], 1
    jne  .member_next
    inc  edi
.member_next:
    inc  edx
    jmp  .member
.count:
    call vtd_out_dec
    lea  rdi, [rel str_vtd_iso_acs]
    call vtd_out_str
.done:
    pop  rbx
    ret

vtd_groups_native_code:
%include "hv/device_groups.inc"

vtd_alloc_page:
    mov  eax, [rel vtd_native_pool_next]
    cmp  eax, VTD_NATIVE_POOL_PAGES
    jae  .bad
    inc  dword [rel vtd_native_pool_next]
    shl  rax, 12
    add  rax, [rel vtd_native_pool_base]
    push rax
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, 512
    cld
    rep  stosq
    mov  rdi, [rsp]
    call vtd_flush_page
    mfence
    pop  rax
    ret
.bad:
    xor  eax, eax
    ret

; vtd_compat_carve(RDI = first byte, ESI = bytes) -> EAX = 1, or 0 when a
; segment-0 RMRR overlaps the range (firmware's DMA keeps its map: fail
; closed), the unit has no 2 MiB second-level leaves to split into, or the
; arena is exhausted. Every 4 KiB page of the range becomes not present in
; DID 1; a 1 GiB or 2 MiB identity leaf over it is first split into 512
; identity leaves one level down, filled and flushed before its parent points
; at it. A page at or above 512 GiB is already outside DID 1. Runs before
; SRTP, so nothing is cached. Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
vtd_compat_carve:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    and  rbx, -4096                      ; the first page
    lea  r12, [rdi + rsi + 4095]
    and  r12, -4096                      ; the end, exclusive
    bt   qword [rel vtd_cap], 34         ; SLLPS: 2 MiB second-level leaves
    jnc  .fail
    mov  rdi, rbx
    mov  rsi, r12
    call vtd_carve_rmrr_clear
    test eax, eax
    jz   .fail
.page:
    cmp  rbx, r12
    jae  .ok
    mov  rax, rbx
    shr  rax, 39
    jnz  .ok                             ; 512 GiB and up: outside DID 1 already
    mov  rax, rbx
    shr  rax, 30
    and  eax, 0x1FF
    mov  r13, [rel vtd_id_pdpt]
    lea  r13, [r13 + rax*8]              ; the PDPT entry
    mov  r8d, 30
    call .split
    test eax, eax
    jz   .fail
    mov  rax, [r13]
    and  rax, -4096
    mov  rcx, rbx
    shr  rcx, 21
    and  ecx, 0x1FF
    lea  r13, [rax + rcx*8]              ; the PD entry
    mov  r8d, 21
    call .split
    test eax, eax
    jz   .fail
    mov  rax, [r13]
    and  rax, -4096
    mov  rcx, rbx
    shr  rcx, 12
    and  ecx, 0x1FF
    lea  r13, [rax + rcx*8]              ; the PT entry
    mov  qword [r13], 0
    clflush [r13]
    inc  dword [rel vtd_carve_holes]
    add  rbx, 4096
    jmp  .page
.ok:
    mfence
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
; R13 = &entry covering 1 << R8 bytes (R8 = 30 or 21). A leaf (PS) becomes a
; pointer to 512 identity leaves of 1 << (R8 - 9) bytes; a pointer stays.
; EAX = 1, or 0 when the arena is exhausted (the leaf is left as it was).
.split:
    test byte [r13], 0x80                ; PS: a leaf
    jz   .split_ok
    push r8
    call vtd_alloc_page                  ; zeroed and flushed
    pop  r8
    test rax, rax
    jz   .split_out
    mov  r9, [r13]
    and  r9, -4096                       ; the leaf's base
    mov  r11d, 0x83                      ; R|W|PS: 2 MiB leaves under a PDPT entry
    cmp  r8d, 30
    je   .split_fill
    mov  r11d, 3                         ; R|W: 4 KiB leaves under a PD entry
.split_fill:
    or   r9, r11
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
    push rax
    mov  rdi, rax
    call vtd_flush_page                  ; the child is in memory before the parent names it
    pop  rax
    or   rax, 3                          ; R|W pointer
    mov  [r13], rax
    clflush [r13]
    inc  dword [rel vtd_carve_splits]
.split_ok:
    mov  eax, 1
.split_out:
    ret

; RDI = first byte, RSI = end (exclusive) -> EAX = 1 when no segment-0 RMRR
; [base, limit] intersects it; 0 on an overlap, a structure that does not
; parse within the table, or no DMAR (fail closed).
vtd_carve_rmrr_clear:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    call vtd_dmar_locate
    test rax, rax
    jz   .bad
    lea  rsi, [rax + 48]
    lea  rdx, [rax + rcx]
.struct:
    cmp  rsi, rdx
    jae  .clear
    lea  rax, [rsi + 4]
    cmp  rax, rdx
    ja   .clear                          ; a 1-3 byte tail: no structure left (as vtd_iso_mark_rmrr)
    movzx ecx, word [rsi + 2]
    cmp  ecx, 8                          ; the spec's smallest structure: an 8-byte ATSR (ALL_PORTS)
    jb   .bad
    lea  rax, [rsi + rcx]
    cmp  rax, rdx
    ja   .bad
    cmp  word [rsi], 1                   ; RMRR
    jne  .advance
    cmp  ecx, 24
    jb   .bad
    cmp  word [rsi + 6], 0               ; the owned unit is segment 0
    jne  .advance
    cmp  [rsi + 8], r12                  ; base at or past the end: clear
    jae  .advance
    cmp  [rsi + 16], rbx                 ; limit (inclusive) at or past the start: overlap
    jae  .bad
.advance:
    add  rsi, rcx
    jmp  .struct
.clear:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

vtd_flush_page:
    mov  ecx, 64
.loop:
    clflush [rdi]
    add  rdi, 64
    dec  ecx
    jnz  .loop
    ret

; ---------------------------------------------------------------------------
; 1111 native-driver domain. This ports Classic's proven minimal 4 KiB tree,
; while core/dma's recorded allocation table supplies the complete valid-set.
; DID 1 remains the broad compatibility domain; DID 2 protects the native NIC/AHCI/NVMe.
; ---------------------------------------------------------------------------

; Alias retained to make native table ownership explicit at call sites.
vtd_native_take_page:
    jmp  vtd_alloc_page

; RDI=IOVA -> RAX=&leaf slot when every intermediate level exists, else zero.
vtd_native_leaf_slot:
    mov  r11, [rel vtd_native_pml4]
; vtd_dom_leaf_slot(RDI=IOVA, R11=domain PML4): the same walk for any domain
; tree. Second-level entries exist when either R or W is set; a write-only
; entry must not look like a free slot. A PS bit at the PDPTE or PDE level is
; never a 4 KiB leaf (rc-sec C1).
; Clobbers R9, R10.
vtd_dom_leaf_slot:
    test r11, r11
    jz   .none
    mov  r9, rdi
    shr  r9, 39
    and  r9, 0x1FF
    mov  r10, [r11 + r9*8]
    test r10b, 3                         ; second-level R|W, not CPU Present
    jz   .none
    and  r10, -4096
    mov  r9, rdi
    shr  r9, 30
    and  r9, 0x1FF
    mov  r10, [r10 + r9*8]
    test r10b, 3
    jz   .none
    test r10b, 0x80
    jnz  .none
    and  r10, -4096
    mov  r9, rdi
    shr  r9, 21
    and  r9, 0x1FF
    mov  r10, [r10 + r9*8]
    test r10b, 3
    jz   .none
    test r10b, 0x80
    jnz  .none
    and  r10, -4096
    mov  r9, rdi
    shr  r9, 12
    and  r9, 0x1FF
    lea  rax, [r10 + r9*8]
    ret
.none:
    xor  eax, eax
    ret

; RDI=IOVA -> RAX=&occupied 4 KiB leaf PTE (R or W), else zero.
vtd_native_leaf_ptr:
    mov  r11, [rel vtd_native_pml4]
; vtd_dom_leaf_ptr(RDI=IOVA, R11=domain PML4).
vtd_dom_leaf_ptr:
    call vtd_dom_leaf_slot
    test rax, rax
    jz   .none
    test byte [rax], 3
    jz   .none
    ret
.none:
    xor  eax, eax
    ret

; Domain-selective invalidation after a live DID-2 leaf edit. Before TE no
; translation can be cached, so the construction path is a no-op success.
; vtd_native_iotlb_invalidate.domain(EDI=DID, ESI=drain hints from
; vtd_drain_hint: bit 1 DR, bit 0 DW) is the same invalidation for any domain;
; DID 2 always passes no hints. A local entry so the routine stays one unit.
vtd_native_iotlb_invalidate:
    mov  edi, VTD_DID_NATIVE
    xor  esi, esi
.domain:
    push rbx
    cmp  byte [rel vtd_enabled], 1
    jne  .yes
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel vtd_qi_on], 1
    je   .qi                               ; SEC-D3a: no register invalidation once QIE is set
    mov  rax, [rel vtd_ecap]
    shr  rax, 8
    and  eax, 0x3FF
    shl  eax, 4
    add  rax, rbx
    mov  edx, edi
    shl  rdx, 32
    mov  r8, 0xA000000000000000         ; IVT | IIRG=domain
    or   rdx, r8
    mov  ecx, esi
    and  ecx, 3
    shl  rcx, 48                         ; DR 49, DW 48
    or   rdx, rcx
    mov  [rax + 8], rdx
    mfence
    mov  ecx, VTD_WAIT_SPINS
.wait:
    bt   qword [rax + 8], 63
    jnc  .yes
    pause
    dec  ecx
    jnz  .wait
.bad:
    xor  eax, eax
    pop  rbx
    ret
.yes:
    mov  eax, 1
    pop  rbx
    ret
.qi:
    call vtd_qi_iotlb_desc                ; EDI = DID
    mov  ecx, esi
    and  ecx, 3
    shl  ecx, 6                          ; descriptor DR 7, DW 6
    or   rax, rcx
    mov  rdi, rax
    call vtd_qi_invalidate                ; EAX = 1 completed / 0 failed
    pop  rbx
    ret

; ESI = 1 asks for drain hints -> ESI = DR<<1 | DW, each only where CAP.DRD
; (bit 55) / CAP.DWD (bit 54) reports support (rc-sec C3); else 0. Flags only.
vtd_drain_hint:
    test esi, esi
    jz   .out
    xor  esi, esi
    bt   qword [rel vtd_cap], 54
    adc  esi, 0
    bt   qword [rel vtd_cap], 55
    jnc  .out
    or   esi, 2
.out:
    ret

; core/dma map hook: RDI=virt, RSI=len, EDX=record tag. Tag 0 maps into the
; native DID 2, tag 1 into the HDA-only DID 3 (its PML4 is taken on first use),
; any other tag is refused. One tag never reaches the other tree.
vtd_dma_map_hook:
    cmp  edx, VTD_DOM_HDA
    ja   .refuse
    ; Admit the entire span before the HDA hook can allocate its lazy root.
    ; The domain entry repeats the guard for direct native/boot callers.
    test rdi, rdi
    jz   .refuse
    test rdi, 0x0FFF
    jnz  .refuse
    test rsi, rsi
    jz   .refuse
    test rsi, 0x0FFF
    jnz  .refuse
    mov  rax, rdi
    add  rax, rsi
    jc   .refuse
    dec  rax
    shr  rax, 48
    jnz  .refuse
    cmp  edx, VTD_DOM_HDA
    jb   vtd_native_map_range
    cmp  qword [rel vtd_hda_pml4], 0
    jne  vtd_dom_map_range
    push rdi
    push rsi
    call vtd_native_take_page
    pop  rsi
    pop  rdi
    test rax, rax
    jz   .refuse
    mov  [rel vtd_hda_pml4], rax
    mov  edx, VTD_DOM_HDA
    jmp  vtd_dom_map_range
.refuse:
    xor  eax, eax
    ret

; core/dma unmap hook: RDI=iova, RSI=len, EDX=the RECORDED tag.
vtd_dma_unmap_hook:
    cmp  edx, VTD_DOM_HDA
    jbe  vtd_dom_unmap_range
    xor  eax, eax
    ret

; RDI=IOVA, EBP=domain index (0 = DID 2, 1 = DID 3) -> as vtd_dom_leaf_slot/ptr.
vtd_dom_leaf_slot_i:
    lea  r11, [rel vtd_native_pml4]       ; vtd_hda_pml4 follows it
    mov  r11, [r11 + rbp*8]
    jmp  vtd_dom_leaf_slot
vtd_dom_leaf_ptr_i:
    lea  r11, [rel vtd_native_pml4]
    mov  r11, [r11 + rbp*8]
    jmp  vtd_dom_leaf_ptr

; vtd_native_map_range(RDI=virt, RSI=len) -> identity-valued enforced IOVA.
; Intermediate levels are allocated lazily from the bounded table pool.
vtd_native_map_range:
    xor  edx, edx
; vtd_dom_map_range(RDI=virt, RSI=len, EDX=domain index: 0 = DID 2, 1 = DID 3).
; The domain's PML4 already exists (vtd_native_domain_build / the map hook).
; A DID-3 success bumps vtd_hda_map_serial (the receipt's replay token).
vtd_dom_map_range:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebp, edx
    call vtdg_range_overlap
    test eax,eax
    jnz .bad
    cmp  ebp, VTD_DOM_HDA
    ja   .bad
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
    ; dma_alloc ranges never overlap. Prove that before changing a leaf so any
    ; later construction/invalidation failure can roll back only this request.
    mov  r14, rdi
.preflight:
    cmp  r14, r13
    jae  .preflight_done
    mov  rdi, r14
    ; Occupancy accepts either R or W. A new R/W mapping instead requires
    ; both permissions at every existing upper level. Check the entire span
    ; before allocation/publication, including later branches and huge leaves.
    call .admit_path
    test eax, eax
    jz   .bad
    call vtd_dom_leaf_ptr_i
    test rax, rax
    jnz  .bad
    add  r14, 4096
    jmp  .preflight
.preflight_done:
    mov  r14, r12
.page:
    cmp  r14, r13
    jae  .mapped
    lea  r15, [rel vtd_native_pml4]
    mov  r15, [r15 + rbp*8]
    test r15, r15
    jz   .rollback

    ; PML4 -> PDPT
    mov  rax, r14
    shr  rax, 39
    and  eax, 0x1FF
    lea  rbx, [r15 + rax*8]
    mov  r15, [rbx]
    test r15b, 3                         ; any permission means an occupied link
    jnz  .have_pdpt
    call vtd_native_take_page
    test rax, rax
    jz   .rollback
    mov  r15, rax
    or   rax, 3
    mov  [rbx], rax
    clflush [rbx]
.have_pdpt:
    mov  r15, [rbx]                      ; new or reused link; never widen it
    mov  eax, r15d
    and  eax, 3
    cmp  eax, 3
    jne  .rollback
    and  r15, -4096

    ; PDPT -> PD
    mov  rax, r14
    shr  rax, 30
    and  eax, 0x1FF
    lea  rbx, [r15 + rax*8]
    mov  r15, [rbx]
    test r15b, 3
    jnz  .have_pd
    call vtd_native_take_page
    test rax, rax
    jz   .rollback
    mov  r15, rax
    or   rax, 3
    mov  [rbx], rax
    clflush [rbx]
.have_pd:
    mov  r15, [rbx]
    mov  eax, r15d
    and  eax, 3
    cmp  eax, 3
    jne  .rollback
    test r15b, 0x80
    jnz  .rollback
    and  r15, -4096

    ; PD -> PT
    mov  rax, r14
    shr  rax, 21
    and  eax, 0x1FF
    lea  rbx, [r15 + rax*8]
    mov  r15, [rbx]
    test r15b, 3
    jnz  .have_pt
    call vtd_native_take_page
    test rax, rax
    jz   .rollback
    mov  r15, rax
    or   rax, 3
    mov  [rbx], rax
    clflush [rbx]
.have_pt:
    mov  r15, [rbx]
    mov  eax, r15d
    and  eax, 3
    cmp  eax, 3
    jne  .rollback
    test r15b, 0x80
    jnz  .rollback
    and  r15, -4096

    ; PT -> 4 KiB identity-valued leaf
    mov  rax, r14
    shr  rax, 12
    and  eax, 0x1FF
    lea  rbx, [r15 + rax*8]
    mov  rax, [rbx]
    test al, 3                          ; an existing W-only leaf is occupied
    jz   .new_leaf
    and  rax, -4096
    cmp  rax, r14
    jne  .rollback                       ; never admit an alias
    jmp  .next
.new_leaf:
    mov  rax, r14
    or   rax, 3                          ; read + write
    mov  [rbx], rax
    clflush [rbx]
    lea  rax, [rel vtd_native_mapped_pages] ; vtd_hda_mapped_pages follows it
    inc  dword [rax + rbp*4]
.next:
    add  r14, 4096
    jmp  .page
.mapped:
    mfence
    lea  edi, [rbp + VTD_DID_NATIVE]      ; DID 2 or DID 3
    xor  esi, esi
    call vtd_native_iotlb_invalidate.domain
    test eax, eax
    jz   .rollback
    test ebp, ebp
    jz   .mapped_ok
    inc  qword [rel vtd_hda_map_serial]
.mapped_ok:
    mov  rax, r12
    jmp  .out
.rollback:
    ; No device has received this IOVA yet. Remove every exact leaf installed
    ; for this request, flush them, and retry the selective invalidation once.
    mov  r14, r12
.rollback_page:
    cmp  r14, r13
    jae  .rollback_invalidate
    mov  rdi, r14
    call vtd_dom_leaf_ptr_i
    test rax, rax
    jz   .rollback_next
    mov  rdx, [rax]
    and  rdx, -4096
    cmp  rdx, r14
    jne  .rollback_next
    mov  qword [rax], 0
    clflush [rax]
    lea  rcx, [rel vtd_native_mapped_pages]
    cmp  dword [rcx + rbp*4], 0
    je   .rollback_next
    dec  dword [rcx + rbp*4]
.rollback_next:
    add  r14, 4096
    jmp  .rollback_page
.rollback_invalidate:
    mfence
    lea  edi, [rbp + VTD_DID_NATIVE]
    xor  esi, esi
    call vtd_native_iotlb_invalidate.domain ; best effort; result remains failure
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=page, EBP=domain. A missing link can be constructed; an existing link
; must admit both R and W and the next 4 KiB table. This is map admission,
; separate from the any-permission occupancy/retirement walk above.
; Clobbers RAX, RCX, R9, R10, R11; preserves the request and domain registers.
.admit_path:
    lea  r11, [rel vtd_native_pml4]
    mov  r11, [r11 + rbp*8]
    test r11, r11
    jz   .path_bad
    mov  ecx, 39
.path_level:
    mov  r9, rdi
    shr  r9, cl
    and  r9, 0x1FF
    mov  r10, [r11 + r9*8]
    mov  eax, r10d
    and  eax, 3
    jz   .path_ok                       ; absent, not an occupied restricted tree
    cmp  eax, 3
    jne  .path_bad
    cmp  ecx, 39
    je   .path_table
    test r10b, 0x80                     ; PDPTE/PDE huge leaf is not a table
    jnz  .path_bad
.path_table:
    mov  r11, r10
    and  r11, -4096
    sub  ecx, 9
    cmp  ecx, 12
    jne  .path_level
.path_ok:
    mov  eax, 1
    ret
.path_bad:
    xor  eax, eax
    ret

; vtd_native_unmap_range(RDI=iova, RSI=len) -> RAX=1/0. Preflight every leaf
; so a malformed request cannot partially tear down the domain.
vtd_native_unmap_range:
    xor  edx, edx
; vtd_dom_unmap_range(RDI=iova, RSI=len, EDX=domain index). The owner quiesces
; first; a DID-3 unmap invalidates with drain hints where CAP.DRD/DWD report
; them, and a DID-3 success bumps vtd_hda_map_serial.
vtd_dom_unmap_range:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  ebp, edx
    cmp  ebp, VTD_DOM_HDA
    ja   .bad
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
    mov  r14, r12
.preflight:
    cmp  r14, r13
    jae  .clear_start
    mov  rdi, r14
    call vtd_dom_leaf_ptr_i
    test rax, rax
    jz   .bad
    ; Failure restoration below reconstructs address|3, not arbitrary leaf
    ; metadata/permissions. Admit only that exact encoding before clearing any
    ; page. Other occupied entries remain live and unchanged on refusal.
    mov  rdx, r14
    or   rdx, 3
    cmp  [rax], rdx
    jne  .bad
    add  r14, 4096
    jmp  .preflight
.clear_start:
    mov  r14, r12
.clear:
    cmp  r14, r13
    jae  .invalidate
    mov  rdi, r14
    call vtd_dom_leaf_ptr_i
    mov  qword [rax], 0
    clflush [rax]
    lea  rcx, [rel vtd_native_mapped_pages]
    cmp  dword [rcx + rbp*4], 0
    je   .clear_next
    dec  dword [rcx + rbp*4]
.clear_next:
    add  r14, 4096
    jmp  .clear
.invalidate:
    mfence
    mov  esi, ebp                         ; DID 3 asks for drain, DID 2 does not
    call vtd_drain_hint
    lea  edi, [rbp + VTD_DID_NATIVE]
    call vtd_native_iotlb_invalidate.domain
    test eax, eax
    jz   .restore
    test ebp, ebp
    jz   .unmapped_ok
    inc  qword [rel vtd_hda_map_serial]
.unmapped_ok:
    mov  eax, 1
    jmp  .out
.restore:
    ; The core record is still live until this hook returns success. If the
    ; invalidation could not be proven, restore the exact address|3 encoding
    ; admitted across the whole span by preflight. No permission is widened.
    mov  r14, r12
.restore_page:
    cmp  r14, r13
    jae  .restore_invalidate
    mov  rdi, r14
    call vtd_dom_leaf_slot_i
    test rax, rax
    jz   .bad
    mov  rdx, r14
    or   rdx, 3
    mov  [rax], rdx
    clflush [rax]
    lea  rcx, [rel vtd_native_mapped_pages]
    inc  dword [rcx + rbp*4]
    add  r14, 4096
    jmp  .restore_page
.restore_invalidate:
    mfence
    lea  edi, [rbp + VTD_DID_NATIVE]
    xor  esi, esi
    call vtd_native_iotlb_invalidate.domain ; best effort; mapping remains live
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Attach one packed BDF to DID 2. Each targeted bus receives a private copy of
; its current context page, leaving same-devfn requesters on other buses alone.
vtd_native_attach_bdf:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  eax, edi
    shr  eax, 8
    and  eax, 0xFF
    lea  rbx, [rel vtd_native_bus_ctx]
    mov  r13, [rbx + rax*8]
    test r13, r13
    jnz  .have_ctx
    push rax
    call vtd_native_take_page
    mov  r13, rax
    pop  rax
    test r13, r13
    jz   .bad
    mov  rcx, rax
    shl  rcx, 4
    add  rcx, [rel vtd_root]
    mov  rsi, [rcx]
    test sil, 1
    jz   .bad
    and  rsi, -4096
    mov  rdi, r13
    mov  ecx, 512
    cld
    rep  movsq
    mov  eax, r12d
    shr  eax, 8
    and  eax, 0xFF
    mov  [rbx + rax*8], r13
    mov  rcx, rax
    shl  rcx, 4
    add  rcx, [rel vtd_root]
    mov  rdx, r13
    or   rdx, 1
    mov  [rcx], rdx
    mov  qword [rcx + 8], 0
    clflush [rcx]
.have_ctx:
    mov  eax, r12d
    and  eax, 0xFF
    shl  eax, 4
    add  rax, r13
    mov  rdx, [rel vtd_native_pml4]
    or   rdx, 1
    mov  [rax], rdx
    mov  qword [rax + 8], 0x202          ; DID=2, AW=2
    mov  rdi, r13
    call vtd_flush_page
    mfence
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=packed BDF -> EAX=1 iff its live context resolves to native DID 2.
vtd_native_ctx_ok:
    mov  rdx, [rel vtd_root]
    test rdx, rdx
    jz   .bad
    mov  eax, edi
    shr  eax, 8
    and  eax, 0xFF
    shl  eax, 4
    add  rax, rdx
    mov  rdx, [rax]
    test dl, 1
    jz   .bad
    and  rdx, -4096
    mov  eax, edi
    and  eax, 0xFF
    shl  eax, 4
    add  rdx, rax
    mov  rax, [rdx]
    test al, 1
    jz   .bad
    and  rax, -4096
    cmp  rax, [rel vtd_native_pml4]
    jne  .bad
    cmp  qword [rdx + 8], 0x202
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; RCQ-36 S5b: the HDA-only DID 3 (root L12871 design, L12913 R1-R3/F1/C1-C4).
; HDA's buffer carries core/dma tag 1 and lives only in DID 3; HDA's context
; entry moves from DID 1 to DID 3 while the controller is held in reset, and
; the owner programs no DMA register until vtd_hda_receipt says state=ok.
; Scope (C4): every DID-1 requester still reaches DID 2 and DID 3 pages below
; 512 GiB. DID 3 confines HDA's own DMA; it does not hide its buffer from
; DID-1 requesters. R1: ats=unread is admitted only because the entry is
; TT=00 (untranslated requests only); any TT=01 entry or ECAP.DT use voids it.
; ---------------------------------------------------------------------------

; EDI = packed BDF -> RAX = &its live context entry (through the LIVE root
; entry, never a cached table pointer), RCX = that context table page, RDX =
; &the root entry; RAX = 0 when the root entry is not present.
vtd_hda_ctx_entry:
    mov  rdx, [rel vtd_root]
    test rdx, rdx
    jz   .none
    mov  eax, edi
    shr  eax, 8
    and  eax, 0xFF
    shl  eax, 4
    add  rdx, rax
    mov  rcx, [rdx]
    test cl, 1
    jz   .none
    and  rcx, -4096
    mov  eax, edi
    and  eax, 0xFF
    shl  eax, 4
    add  rax, rcx
    ret
.none:
    xor  eax, eax
    ret

; vtd_dev_cc(EDI=DID, ESI=SID) -> EAX 1 completed / 0. One device-selective
; context-cache invalidation (FM=0): queued once QIE is set, else CCMD.
vtd_dev_cc:
    push rbx
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel vtd_qi_on], 1
    je   .qi
    xor  edx, edx
    call vtd_ccmd_device_value
    mov  [rbx + VTD_REG_CCMD], rax
    mfence
    mov  ecx, VTD_WAIT_SPINS
.wait:
    bt   qword [rbx + VTD_REG_CCMD], 63
    jnc  .yes
    pause
    dec  ecx
    jnz  .wait
.bad:
    xor  eax, eax
    pop  rbx
    ret
.yes:
    mov  eax, 1
    pop  rbx
    ret
.qi:
    xor  edx, edx
    call vtd_qi_cc_desc
    mov  rdi, rax
    call vtd_qi_invalidate                ; EAX = 1 completed / 0 failed
    pop  rbx
    ret

; R11 = domain PML4 -> EAX = 1 iff no present PDPTE or PDE in the tree has PS
; set (rc-sec C1: DID 2 and DID 3 hold 4 KiB leaves only). An unbuilt tree
; (R11 = 0) holds nothing. Clobbers RAX, RCX, RDX, R8-R10.
vtd_dom_nops:
    test r11, r11
    jz   .yes
    xor  r8d, r8d
.l4:
    cmp  r8d, 512
    jae  .yes
    mov  r9, [r11 + r8*8]
    test r9b, 1
    jz   .n4
    and  r9, -4096
    xor  r10d, r10d
.l3:
    cmp  r10d, 512
    jae  .n4
    mov  rax, [r9 + r10*8]
    test al, 1
    jz   .n3
    test al, 0x80
    jnz  .no
    and  rax, -4096
    xor  ecx, ecx
.l2:
    cmp  ecx, 512
    jae  .n3
    mov  rdx, [rax + rcx*8]
    test dl, 1
    jz   .n2
    test dl, 0x80
    jnz  .no
.n2:
    inc  ecx
    jmp  .l2
.n3:
    inc  r10d
    jmp  .l3
.n4:
    inc  r8d
    jmp  .l4
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; EAX = 1 iff the two domains are disjoint both ways (rc-sec C1): every page
; of a tag-1 record is an exact DID-3 leaf and absent from DID 2, every page
; of a tag-0 record is absent from DID 3, vtd_hda_mapped_pages equals the
; tag-1 page count, and the trusted arena (metadata, DMAVIOL and DMAR snapshot
; pages) is absent from DID 3.
vtd_hda_disjoint:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    xor  ebp, ebp
    xor  r12d, r12d
.record:
    cmp  r12d, DMA_IOMMU_SLOTS
    jae  .records_done
    mov  edi, r12d
    call dma_iommu_record
    test rdx, rdx
    jz   .record_next
    mov  ebx, ecx
    mov  r14, rax
    mov  r15, rax
    add  r15, rdx
    jc   .bad
.page:
    cmp  r14, r15
    jae  .record_next
    mov  rdi, r14
    mov  r11, [rel vtd_hda_pml4]
    call vtd_dom_leaf_ptr
    test ebx, ebx
    jnz  .tagged
    test rax, rax
    jnz  .bad
    jmp  .page_next
.tagged:
    cmp  ebx, VTD_DOM_HDA
    jne  .bad
    test rax, rax
    jz   .bad
    mov  rdx, [rax]
    and  rdx, -4096
    cmp  rdx, r14
    jne  .bad
    inc  ebp
    mov  rdi, r14
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .bad
.page_next:
    add  r14, 4096
    jmp  .page
.record_next:
    inc  r12d
    jmp  .record
.records_done:
    cmp  ebp, [rel vtd_hda_mapped_pages]
    jne  .bad
    mov  r14, [rel vtd_native_pool_base]
    test r14, r14
    jz   .bad
    mov  r15, r14
    add  r15, VTD_NATIVE_POOL_BYTES
    jc   .bad
.arena:
    cmp  r14, r15
    jae  .yes
    mov  rdi, r14
    mov  r11, [rel vtd_hda_pml4]
    call vtd_dom_leaf_ptr
    test rax, rax
    jnz  .bad
    add  r14, 4096
    jmp  .arena
.yes:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI = packed BDF -> EAX = 0, or VTD_HDA_R_RMRR / _ALIAS / _FACTS from the
; live topology snapshot: an RMRR on the function or on a bridge above it
; (rc-sec R2), a PCIe<->PCI or conventional PCI bridge on its path (requester
; aliasing), two bridges claiming one bus, a chain deeper than DA_CHAIN_MAX, or
; incomplete facts. Sibling functions do not refuse: a sibling keeps its own
; requester ID, and DID 3 confines HDA's DMA, not a sibling's (C4).
vtd_hda_iso:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    call vtd_iso_snapshot
    cmp  byte [rel vtd_iso_incomplete], 0
    jne  .facts
    mov  edi, r12d
    call vtd_iso_snap_find
    test rax, rax
    jz   .facts
    test byte [rax + 2], DA_S_RMRR
    jnz  .rmrr
    test byte [rax + 2], DA_S_BRIDGE
    jnz  .alias
    mov  ebx, r12d
    shr  ebx, 8                          ; the bus being resolved upward
    xor  r13d, r13d
.up:
    mov  ecx, [rel vtd_iso_snap_n]
    lea  rax, [rel vtd_iso_snap]
    xor  edx, edx
.find:
    test ecx, ecx
    jz   .found
    test byte [rax + 2], DA_S_BRIDGE
    jz   .find_next
    movzx r8d, byte [rax + 3]            ; secondary bus
    cmp  r8d, ebx
    jne  .find_next
    test rdx, rdx
    jnz  .facts                          ; two bridges claim one bus
    mov  rdx, rax
.find_next:
    add  rax, DA_SNAP_SZ
    dec  ecx
    jmp  .find
.found:
    test rdx, rdx
    jz   .clean                          ; no bridge claims it: a root bus
    inc  r13d
    cmp  r13d, DA_CHAIN_MAX
    ja   .facts
    test byte [rdx + 2], DA_S_RMRR
    jnz  .rmrr
    test byte [rdx + 2], DA_S_PCI_BRIDGE
    jnz  .alias
    test byte [rdx + 2], DA_S_PCIE
    jz   .alias                          ; a conventional bridge takes ownership of IDs
    movzx ebx, byte [rdx + 1]            ; the bridge's own bus
    jmp  .up
.clean:
    xor  eax, eax
    jmp  .out
.rmrr:
    mov  eax, VTD_HDA_R_RMRR
    jmp  .out
.alias:
    mov  eax, VTD_HDA_R_ALIAS
    jmp  .out
.facts:
    mov  eax, VTD_HDA_R_FACTS
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI = packed BDF -> EAX = 0 when no other segment-0 DRHD in the boot DMAR
; snapshot names the function (directly, or by a sub-hierarchy scope whose
; bridge window holds its bus), 1 when one does (its translations would not
; use unit B's tables), 2 when there is no snapshot or a structure does not
; parse.
vtd_hda_foreign_drhd:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebp, edi
    mov  ecx, [rel vtd_dmar_snap_len]
    test ecx, ecx
    jz   .facts
    mov  rax, [rel vtd_dmar_snap]
    lea  r12, [rax + 48]
    lea  r13, [rax + rcx]
.struct:
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .clean
    movzx r14d, word [r12 + 2]
    cmp  r14d, 8
    jb   .facts
    lea  rax, [r12 + r14]
    cmp  rax, r13
    ja   .facts
    cmp  word [r12], 0                   ; DRHD
    jne  .advance
    cmp  r14d, 16
    jb   .facts
    cmp  word [r12 + 6], 0
    jne  .advance
    mov  rax, [r12 + 8]
    cmp  rax, [rel vtd_unitb_base]
    jne  .other_unit
    test byte [r12 + 4], 1
    jnz  .advance                        ; retained include-all unit
    mov  rdi, [rel vtd_dmar_snap]
    mov  esi, [rel vtd_dmar_snap_len]
    call vtd_scoped_drhd_validate
    test rax, rax
    jz   .facts
    cmp  rax, [rel vtd_unitb_base]
    jne  .facts
    mov  ecx, [rel vtd_bdf_count]
    lea  rdx, [rel vtd_bdf_list]
.owned_requester:
    test ecx, ecx
    jz   .facts
    cmp  [rdx], ebp
    je   .clean
    add  rdx, 4
    dec  ecx
    jmp  .owned_requester
.other_unit:
    test byte [r12 + 4], 1
    jnz  .facts                          ; a second segment-0 INCLUDE_PCI_ALL unit
    lea  r15, [r12 + 16]
.scope:
    lea  rax, [r12 + r14]
    cmp  r15, rax
    jae  .advance
    lea  rdx, [r15 + 2]
    cmp  rdx, rax
    ja   .facts
    movzx ebx, byte [r15 + 1]
    cmp  ebx, 8
    jb   .facts
    cmp  ebx, 6 + 2 * DA_CHAIN_MAX
    ja   .facts
    test ebx, 1
    jnz  .facts
    lea  rdx, [r15 + rbx]
    cmp  rdx, rax
    ja   .facts
    movzx eax, byte [r15]
    cmp  eax, 1                          ; PCI endpoint
    je   .endpoint
    cmp  eax, 2                          ; PCI sub-hierarchy
    jne  .scope_next
    mov  rdi, r15
    call vtd_iso_scope_bdf
    cmp  eax, -1
    je   .scope_next
    mov  edi, eax
    mov  esi, 0x18
    call pci_bdf_read
    mov  ecx, ebp
    shr  ecx, 8
    and  ecx, 0xFF                       ; the function's bus
    mov  edx, eax
    shr  edx, 8
    and  edx, 0xFF                       ; secondary
    cmp  ecx, edx
    jb   .scope_next
    shr  eax, 16
    and  eax, 0xFF                       ; subordinate
    cmp  ecx, eax
    ja   .scope_next
    jmp  .foreign
.endpoint:
    mov  rdi, r15
    call vtd_iso_scope_bdf
    cmp  eax, ebp
    je   .foreign
.scope_next:
    add  r15, rbx
    jmp  .scope
.advance:
    add  r12, r14
    jmp  .struct
.clean:
    xor  eax, eax
    jmp  .out
.foreign:
    mov  eax, 1
    jmp  .out
.facts:
    mov  eax, 2
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI = packed BDF -> EAX = ATS state: VTD_HDA_ATS_ABSENT, _DISABLED, _UNREAD
; (no segment-0 MCFG window holds the bus, its page is not an identity UC
; mapping, or the window does not answer for the function; rc-sec R1 admits it
; on TT=00 and it is never reported as absent) or _ENABLED. Reads only: PaOS
; never writes the ATS control.
vtd_hda_ats_state:
    push rbx
    push r12
    mov  r12d, edi
    mov  r10d, [rel acpi_mcfg_count]
    lea  r9, [rel acpi_mcfg_entries]
    xor  r8d, r8d
    mov  eax, r12d
    shr  eax, 8
.mcfg:
    cmp  r8d, r10d
    jae  .unread
    mov  edx, r8d
    shl  edx, 4
    cmp  word [r9 + rdx + 8], 0          ; segment 0
    jne  .mcfg_next
    cmp  al, [r9 + rdx + 10]
    jb   .mcfg_next
    cmp  al, [r9 + rdx + 11]
    ja   .mcfg_next
    mov  rbx, [r9 + rdx]
    jmp  .window
.mcfg_next:
    inc  r8d
    jmp  .mcfg
.window:
    mov  eax, r12d
    shl  rax, 12                         ; bus<<20 | dev<<15 | fn<<12
    add  rbx, rax
    mov  rdi, rbx
    call paging_pd_entry_ptr
    test rax, rax
    jz   .unread
    mov  rax, [rax]
    mov  ecx, eax
    and  ecx, 0x93
    cmp  ecx, 0x93                       ; P/RW/PCD/2 MiB
    jne  .unread
    mov  rcx, 0x000FFFFFFFE00000
    and  rax, rcx
    and  rcx, rbx
    cmp  rax, rcx                        ; identity
    jne  .unread
    mov  edi, r12d
    xor  esi, esi
    call pci_bdf_read
    cmp  eax, [rbx]
    jne  .unread
    mov  ecx, 0x100
    mov  r8d, 64
.cap:
    mov  eax, [rbx + rcx]
    test eax, eax
    jz   .absent
    cmp  eax, -1
    je   .absent
    cmp  ax, 0x000F                      ; ATS extended capability
    je   .ats
    shr  eax, 20
    and  eax, 0xFFC
    cmp  eax, 0x100
    jb   .absent
    mov  ecx, eax
    dec  r8d
    jnz  .cap
    jmp  .unread
.ats:
    test word [rbx + rcx + 6], 0x8000    ; ATS control: Enable
    jnz  .enabled
    mov  eax, VTD_HDA_ATS_DISABLED
    jmp  .out
.absent:
    mov  eax, VTD_HDA_ATS_ABSENT
    jmp  .out
.unread:
    mov  eax, VTD_HDA_ATS_UNREAD
    jmp  .out
.enabled:
    mov  eax, VTD_HDA_ATS_ENABLED
.out:
    pop  r12
    pop  rbx
    ret

; RDI = HDA MMIO -> EAX = 1 iff the controller reads back DMA-idle (rc-sec C3):
; GCTL.CRST = 0, CORBRUN = 0, RIRBDMAEN = 0, the DMA position buffer off, and
; RUN = 0 in every stream descriptor GCAP counts (at most 30).
vtd_hda_quiesced:
    test rdi, rdi
    jz   .no
    test dword [rdi + 0x08], 1           ; GCTL.CRST: held in reset
    jnz  .no
    test byte [rdi + 0x4C], 2            ; CORBCTL.CORBRUN
    jnz  .no
    test byte [rdi + 0x5C], 2            ; RIRBCTL.RIRBDMAEN
    jnz  .no
    test dword [rdi + 0x70], 1           ; DPLBASE enable
    jnz  .no
    movzx eax, word [rdi]                ; GCAP
    mov  ecx, eax
    shr  ecx, 8
    and  ecx, 0xF                        ; input streams
    mov  edx, eax
    shr  edx, 12
    and  edx, 0xF                        ; output streams
    add  ecx, edx
    shr  eax, 3
    and  eax, 0x1F                       ; bidirectional streams
    add  ecx, eax
    cmp  ecx, 30
    ja   .no
    lea  rax, [rdi + 0x80]
.sd:
    test ecx, ecx
    jz   .yes
    test byte [rax], 2                   ; SDnCTL.RUN
    jnz  .no
    add  rax, 0x20
    dec  ecx
    jmp  .sd
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; vtd_hda_attach(EDI=packed BDF, RSI=HDA MMIO, EDX=tag) -> EAX = 0 attached
; to DID 3, else a VTD_HDA_R_* refusal. core/dma's domain attach hook; the
; caller holds the controller in reset (GCTL.CRST = 0), which is the C3
; quiesce when the unit reports no drain support. Preconditions refuse with
; no hardware change. From the moment the old DID-1 entry is cleared, any
; failure leaves the entry NOT PRESENT and the state POISON: no retry, no
; fallback to DID 1 or DID 2 (R3). vtd_qi_invalidate takes vtd_qi_lock per
; submission; the attach runs on the command task and nothing else maps or
; unmaps tag 1 meanwhile, so the sequence takes no wider lock.
vtd_hda_attach:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    and  r12d, 0xFFFF
    mov  r13, rsi
    mov  ebp, VTD_HDA_R_POISONED
    cmp  byte [rel vtd_hda_state], VTD_HDA_POISON
    je   .refuse_keep                    ; POISON is final for this boot
    mov  ebp, VTD_HDA_R_ATTACHED
    cmp  byte [rel vtd_hda_state], VTD_HDA_OK
    je   .refuse_keep                    ; one HDA function, attached once
    mov  ebp, VTD_HDA_R_NO_ENFORCEMENT
    cmp  edx, VTD_DOM_HDA
    jne  .refuse
    cmp  byte [rel vtd_native_ready], 1
    jne  .refuse
    cmp  byte [rel vtd_enabled], 1
    jne  .refuse
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .refuse
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_TES
    jz   .refuse
    mov  ebp, VTD_HDA_R_GUEST_LIVE
    cmp  byte [rel vtd_owner_guest], 0
    jne  .refuse
    mov  ebp, VTD_HDA_R_NOT_FOUND
    mov  edx, [rel vtd_bdf_count]
    cmp  edx, VTD_BDF_MAX
    jbe  .listed
    mov  edx, VTD_BDF_MAX
.listed:
    lea  rax, [rel vtd_bdf_list]
    xor  ecx, ecx
.find:
    cmp  ecx, edx
    jae  .refuse
    cmp  [rax + rcx*4], r12d
    je   .found
    inc  ecx
    jmp  .find
.found:
    mov  ebp, VTD_HDA_R_CLASS
    mov  edi, r12d
    mov  esi, 0x08
    call pci_bdf_read
    shr  eax, 8
    and  eax, 0xFFFF7F                   ; admit HDA progIF00/80 only
    cmp  eax, 0x040300                   ; multimedia / HD Audio / interface 00/80
    jne  .refuse
    mov  edi, r12d
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    test eax, 0x7F                       ; header type 0
    jnz  .refuse
    mov  ebp, VTD_HDA_R_BAR
    test r13, r13
    jz   .refuse
    test r13, 0x0FFF
    jnz  .refuse
    mov  edi, r12d
    mov  esi, 0x10
    call pci_bdf_read
    test al, 1
    jnz  .refuse                         ; an I/O BAR is not the MMIO it names
    mov  r15d, eax
    and  r15d, 0xFFFFFFF0
    and  eax, 6
    cmp  eax, 4
    jne  .bar_have
    mov  edi, r12d
    mov  esi, 0x14
    call pci_bdf_read
    mov  eax, eax
    shl  rax, 32
    or   r15, rax
.bar_have:
    cmp  r15, r13                        ; the MMIO the caller quiesced is this function's
    jne  .refuse
    mov  edi, r12d
    call vtd_hda_iso
    mov  ebp, eax
    test eax, eax
    jnz  .refuse
    mov  edi, r12d
    call vtd_hda_foreign_drhd
    mov  ebp, VTD_HDA_R_FOREIGN_DRHD
    cmp  eax, 1
    je   .refuse
    mov  ebp, VTD_HDA_R_FACTS
    test eax, eax
    jnz  .refuse
    mov  edi, r12d
    call vtd_hda_ats_state
    mov  ebp, VTD_HDA_R_ATS_ENABLED
    cmp  eax, VTD_HDA_ATS_ENABLED
    je   .refuse
    mov  ebp, VTD_HDA_R_CTX_STATE
    mov  edi, r12d
    call vtd_identity_ctx_ok             ; the boot DID-1 identity entry, nothing else
    test eax, eax
    jz   .refuse
    mov  ebp, VTD_HDA_R_NOT_QUIESCED      ; C3, before any table work
    mov  rdi, r13
    call vtd_hda_quiesced
    test eax, eax
    jz   .refuse
    mov  ebp, VTD_HDA_R_POOL
    cmp  qword [rel vtd_hda_pml4], 0
    jne  .tree
    call vtd_native_take_page
    test rax, rax
    jz   .refuse
    mov  [rel vtd_hda_pml4], rax
.tree:
    ; A tag-1 record from before the bind is not in DID 3 yet: map it now.
    xor  r15d, r15d
.map:
    cmp  r15d, DMA_IOMMU_SLOTS
    jae  .mapped
    mov  edi, r15d
    call dma_iommu_record
    test rdx, rdx
    jz   .map_next
    cmp  ecx, VTD_DOM_HDA
    jne  .map_next
    mov  r14, rax
    mov  rbx, rdx
    mov  rdi, rax
    mov  r11, [rel vtd_hda_pml4]
    call vtd_dom_leaf_ptr
    test rax, rax
    jnz  .map_next
    mov  rdi, r14
    mov  rsi, rbx
    mov  edx, VTD_DOM_HDA
    call vtd_dom_map_range
    test rax, rax
    jz   .refuse
.map_next:
    inc  r15d
    jmp  .map
.mapped:
    mov  ebp, VTD_HDA_R_DISJOINT
    call vtd_hda_disjoint
    test eax, eax
    jz   .refuse
    mov  ebp, VTD_HDA_R_NOPS
    mov  r11, [rel vtd_native_pml4]
    call vtd_dom_nops
    test eax, eax
    jz   .refuse
    mov  r11, [rel vtd_hda_pml4]
    call vtd_dom_nops
    test eax, eax
    jz   .refuse
    ; The LIVE context table for the bus. A bus still on the shared DID-1
    ; table gets a private copy first, so no other bus's devfn changes.
    mov  ebp, VTD_HDA_R_CTX_STATE
    mov  edi, r12d
    call vtd_hda_ctx_entry
    test rax, rax
    jz   .refuse
    mov  r14, rax
    cmp  rcx, [rel vtd_shared_ctx]
    jne  .private
    mov  ebp, VTD_HDA_R_POOL
    mov  rbx, rdx                         ; &root entry
    call vtd_native_take_page
    test rax, rax
    jz   .refuse
    mov  r15, rax
    mov  rsi, [rel vtd_shared_ctx]
    mov  rdi, r15
    mov  ecx, 512
    cld
    rep  movsq
    mov  rdi, r15
    call vtd_flush_page
    mfence
    mov  rax, r15
    or   rax, 1
    mov  [rbx], rax
    mov  qword [rbx + 8], 0
    clflush [rbx]
    mfence
    mov  ebp, VTD_HDA_R_CTX_STATE
    mov  edi, r12d
    call vtd_hda_ctx_entry
    test rax, rax
    jz   .refuse
    cmp  rcx, r15
    jne  .refuse
    mov  r14, rax
.private:
    ; ---- no return from here (R3): the old entry goes not present ----
    mov  qword [r14], 0
    clflush [r14]
    mfence
    mov  ebp, VTD_HDA_R_INVAL_TIMEOUT
    mov  edi, VTD_DID_IDENTITY
    mov  esi, r12d
    call vtd_dev_cc
    test eax, eax
    jz   .poison
    mov  esi, 1
    call vtd_drain_hint
    mov  edi, VTD_DID_IDENTITY
    call vtd_native_iotlb_invalidate.domain
    test eax, eax
    jz   .poison
    mov  qword [r14 + 8], (VTD_DID_HDA << 8) | 2 ; DID 3, AW 2 (48-bit)
    mov  rax, [rel vtd_hda_pml4]
    or   rax, 1                          ; P; TT = 00: untranslated requests only (R1)
    mov  [r14], rax
    clflush [r14]
    mfence
    mov  edi, VTD_DID_HDA
    mov  esi, r12d
    call vtd_dev_cc
    test eax, eax
    jz   .poison
    bt   qword [rel vtd_cap], 7           ; CAP.CM: a cached not-present context is tagged DID 0 (I2)
    jnc  .cm_done
    xor  edi, edi                        ; DID 0, the same SID, FM 0 via the canonical CCMD/QI helper
    mov  esi, r12d
    call vtd_dev_cc
    test eax, eax
    jz   .poison                         ; completion required; HDA remains held in reset
.cm_done:
    mov  edi, VTD_DID_HDA                 ; caching mode may cache not-present entries
    xor  esi, esi
    call vtd_native_iotlb_invalidate.domain
    test eax, eax
    jz   .poison
    mov  ebp, VTD_HDA_R_READBACK
    mov  edi, r12d
    call vtd_hda_ctx_entry
    cmp  rax, r14
    jne  .poison
    mov  rax, [rel vtd_hda_pml4]
    or   rax, 1
    cmp  [r14], rax
    jne  .poison
    cmp  qword [r14 + 8], (VTD_DID_HDA << 8) | 2
    jne  .poison
    mov  [rel vtd_hda_bdf], r12d
    mov  [rel vtd_hda_mmio], r13
    inc  qword [rel vtd_hda_map_serial]
    mov  byte [rel vtd_hda_reason], 0
    mov  byte [rel vtd_hda_state], VTD_HDA_OK
    xor  eax, eax
    jmp  .out
.poison:
    mov  qword [r14], 0                  ; left NOT PRESENT: HDA DMA faults
    clflush [r14]
    mfence
    mov  [rel vtd_hda_bdf], r12d
    mov  [rel vtd_hda_reason], bpl
    mov  byte [rel vtd_hda_state], VTD_HDA_POISON
    mov  eax, ebp
    jmp  .out
.refuse:
    mov  [rel vtd_hda_reason], bpl
    mov  byte [rel vtd_hda_state], VTD_HDA_REFUSED
.refuse_keep:
    mov  eax, ebp
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI = VTD_HDA_R_* -> appends its fixed-stride name.
vtd_hda_out_reason:
    cmp  edi, VTD_HDA_R_LAST
    jbe  .named
    mov  edi, VTD_HDA_R_LAST
.named:
    imul edi, edi, VTD_HDA_NAME_STRIDE
    lea  rax, [rel vtd_hda_reason_names]
    add  rdi, rax
    jmp  vtd_out_str

; vtd_hda_receipt(EDI=tag) -> EAX 1 ok / 0, RDX = vtd_hda_map_serial,
; RSI = vtd_hda_line. core/dma's domain receipt hook (F1: the owner programs
; no DMA register before EAX = 1). Every field is re-read live: enforcement,
; the context entry through the live root, class, both-ways disjointness, no
; PS bit in either tree, the controller quiesce, ATS and FSTS; any missing or
; stale field refuses without changing the attach state. The line is built in
; vtd_out_buf and copied out; a staged VTD line there is dropped (no verb that
; reaches this one carries one).
vtd_hda_receipt:
    push r14
    xor  r14d, r14d
    call vtd_hda_receipt_body
    pop  r14
    ret

; An active controller retains the strict attachment's DID and mapping. Re-read
; all ownership checks, but do not require reset or DMA engines to be stopped.
vtd_hda_live_receipt:
    push r14
    mov  r14d, 1
    call vtd_hda_receipt_body
    pop  r14
    ret

vtd_hda_receipt_body:
    push rbx
    push rbp
    push r12
    push r13
    sub  rsp, 8                         ; actual live PCI class, preserve across calls
    xor  ebp, ebp
    call vtd_out_reset
    lea  rdi, [rel str_vtd_hda_prefix]
    call vtd_out_str
    mov  ebx, VTD_HDA_R_NO_ENFORCEMENT    ; core/dma passes only tag 1 here
    movzx eax, byte [rel vtd_hda_state]
    cmp  eax, VTD_HDA_OK
    je   .live
    mov  ebx, VTD_HDA_R_NOT_ATTACHED
    cmp  eax, VTD_HDA_IDLE
    je   .refused
    movzx ebx, byte [rel vtd_hda_reason]
    cmp  eax, VTD_HDA_POISON
    jne  .refused
    lea  rdi, [rel str_vtd_hda_poison]
    call vtd_out_str
    mov  edi, ebx
    call vtd_hda_out_reason
    jmp  .finish
.live:
    mov  r12d, [rel vtd_hda_bdf]
    cmp  byte [rel vtd_native_ready], 1
    jne  .refused
    cmp  byte [rel vtd_enabled], 1
    jne  .refused
    mov  rax, [rel vtd_unitb_base]
    test rax, rax
    jz   .refused
    test dword [rax + VTD_REG_GSTS], VTD_GSTS_TES
    jz   .refused
    mov  ebx, VTD_HDA_R_READBACK
    mov  edi, r12d
    call vtd_hda_ctx_entry
    test rax, rax
    jz   .refused
    mov  rdx, [rel vtd_hda_pml4]
    or   rdx, 1
    cmp  [rax], rdx
    jne  .refused
    cmp  qword [rax + 8], (VTD_DID_HDA << 8) | 2
    jne  .refused
    mov  ebx, VTD_HDA_R_CLASS
    mov  edi, r12d
    mov  esi, 0x08
    call pci_bdf_read
    shr  eax, 8
    mov  [rsp], eax
    and  eax, 0xFFFF7F                   ; same bounded class predicate as attach
    cmp  eax, 0x040300
    jne  .refused
    mov  ebx, VTD_HDA_R_DISJOINT
    call vtd_hda_disjoint
    test eax, eax
    jz   .refused
    mov  ebx, VTD_HDA_R_NOPS
    mov  r11, [rel vtd_native_pml4]
    call vtd_dom_nops
    test eax, eax
    jz   .refused
    mov  r11, [rel vtd_hda_pml4]
    call vtd_dom_nops
    test eax, eax
    jz   .refused
    test r14d, r14d
    jnz  .lifecycle_ok
    mov  ebx, VTD_HDA_R_NOT_QUIESCED
    mov  rdi, [rel vtd_hda_mmio]
    call vtd_hda_quiesced
    test eax, eax
    jz   .refused
.lifecycle_ok:
    mov  ebx, VTD_HDA_R_ATS_ENABLED
    mov  edi, r12d
    call vtd_hda_ats_state
    mov  r13d, eax
    cmp  eax, VTD_HDA_ATS_ENABLED
    je   .refused
    mov  ebx, VTD_HDA_R_FSTS
    mov  rax, [rel vtd_unitb_base]
    test dword [rax + VTD_REG_FSTS], 0xFF
    jnz  .refused
    ; every field above is asserted; the line prints only now
    lea  rdi, [rel str_vtd_hda_ok_bdf]
    cmp  dword [rsp], 0x040380
    jne  .class_text
    lea  rdi, [rel str_vtd_hda_ok80_bdf]
.class_text:
    call vtd_out_str
    mov  edi, r12d
    shr  edi, 8
    call vtd_out_hex_byte
    lea  rdi, [rel str_vtd_colon]
    call vtd_out_str
    mov  edi, r12d
    shr  edi, 3
    and  edi, 0x1F
    call vtd_out_hex_byte
    lea  rdi, [rel str_vtd_dot]
    call vtd_out_str
    mov  edi, r12d
    and  edi, 7
    call vtd_out_dec
    lea  rdi, [rel str_vtd_hda_sid]
    call vtd_out_str
    mov  edi, r12d
    shr  edi, 8
    call vtd_out_hex_byte
    mov  edi, r12d
    call vtd_out_hex_byte
    lea  rdi, [rel str_vtd_hda_ctx_qi]
    call vtd_out_str
    movzx edi, byte [rel vtd_qi_on]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_hda_drain]
    call vtd_out_str
    mov  esi, 1
    call vtd_drain_hint
    imul edi, esi, VTD_HDA_NAME_STRIDE
    lea  rax, [rel vtd_hda_drain_names]
    add  rdi, rax
    call vtd_out_str
    lea  rdi, [rel str_vtd_hda_ats]
    test r14d, r14d
    jz   .receipt_mode
    lea  rdi, [rel str_vtd_hda_live_ats]
.receipt_mode:
    call vtd_out_str
    imul edi, r13d, VTD_HDA_NAME_STRIDE
    lea  rax, [rel vtd_hda_ats_names]
    add  rdi, rax
    call vtd_out_str
    lea  rdi, [rel str_vtd_hda_serial]
    call vtd_out_str
    mov  edi, [rel vtd_hda_map_serial]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_hda_tail]
    call vtd_out_str
    mov  edi, [rel vtd_native_pool_next]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_hda_slash]
    call vtd_out_str
    mov  edi, VTD_NATIVE_POOL_PAGES
    call vtd_out_dec
    mov  ebp, 1
    jmp  .finish
.refused:
    lea  rdi, [rel str_vtd_hda_refused]
    call vtd_out_str
    mov  edi, ebx
    call vtd_hda_out_reason
.finish:
    lea  rsi, [rel vtd_out_buf]
    lea  rdi, [rel vtd_hda_line]
    mov  ecx, VTD_HDA_LINE_MAX
.copy:
    mov  al, [rsi]
    mov  [rdi], al
    test al, al
    jz   .copied
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .copy
    mov  byte [rdi], 0
.copied:
    mov  byte [rel vtd_out_ready], 0
    mov  eax, ebp
    mov  rdx, [rel vtd_hda_map_serial]
    lea  rsi, [rel vtd_hda_line]
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Prove every recorded allocation resolves exactly, while the IOMMU metadata
; and runtime-aligned deliberate-violation page remain outside the valid-set.
; Only tag-0 records belong to DID 2: a record with another tag must have no
; page in it, and no present DID-2 PDPTE/PDE may carry PS (rc-sec C1).
vtd_native_domain_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    call vtd_native_nic_optional_current
    test eax, eax
    jz   .bad
    cmp  byte [rel vtd_sata_found], 1
    jne  .bad
    cmp  byte [rel vtd_native_nic_found], 0
    je   .storage
    mov  edi, [rel vtd_native_nic_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .bad
.storage:
    mov  edi, [rel vtd_sata_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .bad
    ; Never validate default BDF zero when no NVM requester was enumerated.
    ; A witnessed NVM function still has to resolve through restrictive DID 2.
    cmp  byte [rel vtd_nvme_found], 1
    jne  .records
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .bad
.records:
    xor  ebx, ebx
    xor  ebp, ebp
    xor  r12d, r12d
.record:
    cmp  r12d, DMA_IOMMU_SLOTS
    jae  .records_done
    mov  edi, r12d
    call dma_iommu_record
    test rdx, rdx
    jz   .record_next
    test ecx, ecx
    jnz  .foreign
    inc  ebx
    mov  r14, rax
    mov  r15, rax
    add  r15, rdx
    jc   .bad
.record_page:
    cmp  r14, r15
    jae  .record_next
    mov  rdi, r14
    call vtd_native_leaf_ptr
    test rax, rax
    jz   .bad
    mov  r13, [rax]
    and  r13, -4096
    cmp  r13, r14
    jne  .bad
    inc  ebp
    add  r14, 4096
    jmp  .record_page
.record_next:
    inc  r12d
    jmp  .record
.foreign:
    mov  r14, rax
    mov  r15, rax
    add  r15, rdx
    jc   .bad
.foreign_page:
    cmp  r14, r15
    jae  .record_next
    mov  rdi, r14
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .bad
    add  r14, 4096
    jmp  .foreign_page
.records_done:
    cmp  ebx, [rel vtd_native_record_count]
    jne  .bad
    mov  r11, [rel vtd_native_pml4]
    call vtd_dom_nops
    test eax, eax
    jz   .bad
    test ebx, ebx
    jz   .bad
    cmp  ebp, [rel vtd_native_mapped_pages]
    jne  .bad
    test ebp, ebp
    jz   .bad
    cmp  dword [rel vtd_native_pool_next], VTD_NATIVE_POOL_PAGES
    ja   .bad
    ; The complete trusted arena, including every metadata page and the final
    ; violation page, must remain absent from the native device valid-set.
    mov  r14, [rel vtd_native_pool_base]
    test r14, r14
    jz   .bad
    mov  r15, r14
    add  r15, VTD_NATIVE_POOL_BYTES
    jc   .bad
.trusted_page:
    cmp  r14, r15
    jae  .trusted_done
    mov  rdi, r14
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .bad
    add  r14, 4096
    jmp  .trusted_page
.trusted_done:
    mov  rdi, [rel vtd_dmaviol_target_page]
    test rdi, rdi
    jz   .bad
    test rdi, 0x0FFF                    ; runtime alignment, never NASM align
    jnz  .bad
    mov  rax, [rel vtd_native_pool_base]
    add  rax, VTD_NATIVE_POOL_PAGES * 4096
    cmp  rdi, rax                       ; target is the reserved page after the metadata
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

vtd_native_domain_build:
    push rbx
    push r12
    push r13
    call vtd_native_nic_optional_current
    test eax, eax
    jz   .bad
    ; The init-time trusted arena is runtime aligned; static NASM alignment is
    ; never treated as a loaded-PE VA guarantee.
    cmp  qword [rel vtd_native_pool_base], 0
    je   .bad
    cmp  qword [rel vtd_dmaviol_target_page], 0
    je   .bad
    call vtd_native_take_page
    test rax, rax
    jz   .bad
    mov  [rel vtd_native_pml4], rax

    xor  r12d, r12d
    mov  dword [rel vtd_native_record_count], 0
.map_record:
    cmp  r12d, DMA_IOMMU_SLOTS
    jae  .attach
    mov  edi, r12d
    call dma_iommu_record
    test rdx, rdx
    jz   .map_next
    test ecx, ecx                         ; DID 2 maps tag-0 records only
    jnz  .map_next
    mov  rdi, rax
    mov  rsi, rdx
    call vtd_native_map_range
    test rax, rax
    jz   .bad
    inc  dword [rel vtd_native_record_count]
.map_next:
    inc  r12d
    jmp  .map_record

.attach:
    cmp  byte [rel vtd_native_nic_found], 0
    je   .storage
    mov  edi, [rel vtd_native_nic_bdf]
    call vtd_native_attach_bdf
    test eax, eax
    jz   .bad
.storage:
    mov  edi, [rel vtd_sata_bdf]
    call vtd_native_attach_bdf
    test eax, eax
    jz   .bad
    ; Optional devices are attached only from a witnessed live BDF.
    cmp  byte [rel vtd_nvme_found], 1
    jne  .validate
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_native_attach_bdf
    test eax, eax
    jz   .bad
.validate:
    call vtd_native_domain_validate
    test eax, eax
    jz   .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Retain only the first boot validator result. Reasons/indices below identify
; existing predicates; no table/device re-read is performed for diagnostics.
vtd_validate_coverage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  edi, -1                         ; no requester at table/global checks
    mov  r15d, -1                        ; no table index
    xor  r11d, r11d                      ; expected aligned low bits = 0
    mov  rax, [rel vtd_root]
    mov  r14d, 1
    mov  r10, rax
    and  r10d, 0x0FFF
    test ax, 0x0FFF
    jnz  .bad
    mov  rdx, [rel vtd_shared_ctx]
    mov  r14d, 2
    mov  r10, rdx
    and  r10d, 0x0FFF
    test dx, 0x0FFF
    jnz  .bad
    mov  rcx, [rel vtd_id_pml4]
    mov  r14d, 3
    mov  r10, rcx
    and  r10d, 0x0FFF
    test cx, 0x0FFF
    jnz  .bad
    mov  r8, [rel vtd_id_pdpt]
    mov  r14d, 4
    mov  r10, r8
    and  r10d, 0x0FFF
    test r8w, 0x0FFF
    jnz  .bad

    ; INCLUDE_PCI_ALL can issue a walk for any bus.  Every one of the 256
    ; legacy root entries must therefore resolve before TE, and every devfn in
    ; the shared context table must resolve into the identity domain.
    mov  r12, rdx
    xor  ecx, ecx
.root:
    mov  r15d, ecx
    shr  r15d, 4                        ; first bus/root or devfn/context index
    mov  rbx, [rax + rcx]
    mov  r14d, 5
    mov  r11d, 1
    mov  r10, rbx
    and  r10d, 1
    test bl, 1
    jz   .bad
    and  rbx, -4096
    mov  r14d, 6
    mov  r11, r12
    mov  r10, rbx
    cmp  rbx, r12
    jne  .bad
    mov  r14d, 7
    mov  r11d, 0
    mov  r10, [rax + rcx + 8]          ; same single operand read as before
    cmp  r10, 0
    jne  .bad
    add  ecx, 16
    cmp  ecx, 4096
    jb   .root

    mov  r13, [rel vtd_id_pml4]
    xor  ecx, ecx
.ctx:
    mov  r15d, ecx
    shr  r15d, 4                        ; first bus/root or devfn/context index
    mov  rbx, [r12 + rcx]
    mov  r14d, 8
    mov  r11d, 1
    mov  r10, rbx
    and  r10d, 1
    test bl, 1
    jz   .bad
    and  rbx, -4096
    mov  r14d, 9
    mov  r11, r13
    mov  r10, rbx
    cmp  rbx, r13
    jne  .bad
    mov  r14d, 10
    mov  r11d, 0x102
    mov  r10, [r12 + rcx + 8]          ; same single operand read as before
    cmp  r10, 0x102
    jne  .bad
    add  ecx, 16
    cmp  ecx, 4096
    jb   .ctx

    ; Content-grade the policy against the functions actually enumerated on
    ; this boot.  A full root table alone cannot honestly prove that the live
    ; native NIC/xHCI/storage BDFs resolve through the expected domain.
    mov  r15d, -1
    mov  r11d, 1
    mov  r14d, 11
    call vtd_native_nic_optional_current
    mov  r10d, eax
    cmp  r10b, 1
    jne  .bad
    mov  r14d, 12
    movzx r10d, byte [rel vtd_xhci_found]
    cmp  r10b, 1
    jne  .bad
    mov  r14d, 13
    movzx r10d, byte [rel vtd_sata_found]
    cmp  r10b, 1
    jne  .bad
    mov  r14d, 14
    xor  r11d, r11d
    movzx r10d, byte [rel vtd_bdf_overflow]
    cmp  r10b, 0
    jne  .bad
    mov  r14d, 15
    mov  r11d, 1                         ; predicate: list count != 0
    mov  r10d, [rel vtd_bdf_count]
    cmp  r10d, 0
    je   .bad
    cmp  byte [rel vtd_native_nic_found], 0
    je   .xhci
    mov  r14d, 16
    mov  r11d, 1                         ; expected helper verdict (not a reprobe)
    mov  edi, [rel vtd_native_nic_bdf]
    call vtd_identity_ctx_ok
    mov  r10d, eax                       ; retain the already-returned predicate
    test eax, eax
    jz   .bad
.xhci:
    mov  r14d, 17
    mov  r11d, 1                         ; expected helper verdict (not a reprobe)
    mov  edi, [rel vtd_xhci_bdf]
    call vtd_identity_ctx_ok
    mov  r10d, eax                       ; retain the already-returned predicate
    test eax, eax
    jz   .bad
    mov  r14d, 18
    mov  r11d, 1                         ; expected helper verdict (not a reprobe)
    mov  edi, [rel vtd_sata_bdf]
    call vtd_identity_ctx_ok
    mov  r10d, eax                       ; retain the already-returned predicate
    test eax, eax
    jz   .bad
    cmp  byte [rel vtd_nvme_found], 1
    jne  .nvme_done
    mov  r14d, 19
    mov  r11d, 1                         ; expected helper verdict (not a reprobe)
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_identity_ctx_ok
    mov  r10d, eax                       ; retain the already-returned predicate
    test eax, eax
    jz   .bad
    mov  byte [rel vtd_nvme_covered], 1
.nvme_done:

    mov  rax, [rel vtd_root]
    mov  r9, [rel vtd_unitb_base]
    mov  r10, [r9 + VTD_REG_RTADDR]
    and  r10, -4096
    mov  edi, -1
    mov  r14d, 20
    mov  r11, rax
    cmp  r10, rax
    jne  .bad
    mov  al, [rel vtd_native_nic_found]   ; absence never advertises NIC coverage
    mov  [rel vtd_native_nic_covered], al
    mov  byte [rel vtd_xhci_covered], 1
    mov  byte [rel vtd_sata_covered], 1
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    call vtd_coverage_record
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EAX=unchanged validator verdict; R14D=reason, R15D=index (or -1),
; EDI=requester (or -1), R11=expected, R10=observed. Fixed 64-byte boot record.
; State 0=not reached, 1=passed, 2=refused. Success is coverage only, never TE
; or assignment authority. Later calls cannot overwrite the first result.
vtd_coverage_record:
    pushfq
    push rax
    cmp  dword [rel vtd_cov_record], 0
    jne  .out
    test eax, eax
    jnz  .pass
    mov  [rel vtd_cov_record + 4], r14d
    mov  [rel vtd_cov_record + 8], r15d
    mov  [rel vtd_cov_record + 12], edi
    mov  [rel vtd_cov_record + 16], r11
    mov  [rel vtd_cov_record + 24], r10
    jmp  .snapshot
.pass:
    mov  dword [rel vtd_cov_record + 8], -1
    mov  dword [rel vtd_cov_record + 12], -1
.snapshot:
    ; These are discovery RAM witnesses, never fresh PCI/config/MMIO reads.
    mov  al, [rel vtd_native_nic_found]
    mov  [rel vtd_cov_record + 32], al
    mov  al, [rel vtd_xhci_found]
    mov  [rel vtd_cov_record + 33], al
    mov  al, [rel vtd_sata_found]
    mov  [rel vtd_cov_record + 34], al
    mov  al, [rel vtd_nvme_found]
    mov  [rel vtd_cov_record + 35], al
    mov  al, [rel vtd_bdf_overflow]
    mov  [rel vtd_cov_record + 36], al
    mov  eax, [rel vtd_bdf_count]
    mov  [rel vtd_cov_record + 40], eax
    mov  eax, [rel vtd_native_nic_bdf]
    mov  [rel vtd_cov_record + 44], eax
    mov  eax, [rel vtd_xhci_bdf]
    mov  [rel vtd_cov_record + 48], eax
    mov  eax, [rel vtd_sata_bdf]
    mov  [rel vtd_cov_record + 52], eax
    mov  eax, [rel vtd_nvme_bdf]
    mov  [rel vtd_cov_record + 56], eax
    cmp  dword [rsp], 0
    mov  eax, 1
    jne  .publish
    mov  eax, 2
.publish:
    mov  [rel vtd_cov_record], eax         ; publish only after all fields
.out:
    pop  rax
    popfq
    ret

; EDI=packed BDF -> EAX=1 iff its current root/context resolves to DID 1.
; Unlike the boot-wide assertion this follows the live root pointer, so it
; remains valid after the secondary bus gets its private context-table copy.
vtd_identity_ctx_ok:
    mov  rdx, [rel vtd_root]
    test rdx, rdx
    jz   .bad
    mov  eax, edi
    shr  eax, 8
    shl  eax, 4
    add  rax, rdx
    mov  rdx, [rax]
    test dl, 1
    jz   .bad
    and  rdx, -4096
    mov  eax, edi
    and  eax, 0xFF
    shl  eax, 4
    add  rdx, rax
    mov  rax, [rdx]
    test al, 1
    jz   .bad
    and  rax, -4096
    cmp  rax, [rel vtd_id_pml4]
    jne  .bad
    cmp  qword [rdx + 8], 0x102
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Context Command Register (CCMD_REG, offset 0x28) device-selective value.
; Intel VT-d Architecture Specification, "Context Command Register"
; (rev 3.x section 10.4.7; chapter 11 register descriptions in rev 4.x+):
;   63 ICC | 62:61 CIRG (11b = device-selective) | 60:59 CAIG (RO)
;   58:34 RsvdZ | 33:32 FM | 31:16 SID | 15:0 DID
; This is NOT the queued-invalidation context-cache descriptor (section
; 6.5.2.1: G 5:4, DID 31:16, SID 47:32, FM 49:48).  PaOS invalidates through
; the register only; the descriptor layout's "SID 47:32" once leaked in here
; and aimed every device-selective invalidate at SID 0 (Dell 7ad3f94d).
; EDI=DID, ESI=SID (bus<<8 | dev<<3 | fn), EDX=FM -> RAX.  Clobbers RCX only.
vtd_ccmd_device_value:
    movzx eax, di                         ; DID -> 15:0
    movzx ecx, si
    shl  ecx, 16                          ; SID -> 31:16
    or   eax, ecx                         ; (32-bit op clears 63:32)
    mov  ecx, edx
    and  ecx, 3
    shl  rcx, 32                          ; FM -> 33:32
    or   rax, rcx
    mov  rcx, 0xE000000000000000          ; ICC | CIRG=device
    or   rax, rcx
    ret
; end vtd_ccmd_device_value

; Field-layout KAT for vtd_ccmd_device_value against constants hand-derived
; from the spec table above.  Pure register math, no MMIO and no state, so it
; runs on every boot (QEMU and metal) before any remapping unit is touched.
; The 47:32 SID placement fails every vector.  EAX=1 iff all vectors match.
vtd_ccmd_layout_kat:
    push rbx
    push r12
    lea  rbx, [rel vtd_ccmd_kat_vectors]
    xor  r12d, r12d
.vec:
    mov  edi, [rbx]
    mov  esi, [rbx + 4]
    mov  edx, [rbx + 8]
    call vtd_ccmd_device_value
    cmp  rax, [rbx + 16]
    jne  .bad
    add  rbx, 24
    inc  r12d
    cmp  r12d, VTD_CCMD_KAT_VECTORS
    jb   .vec
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Boot-only selective invalidation.  Every enumerated segment-0 source gets a
; device-selective context invalidate; shared DID 1 and native DID 2 each get
; a domain IOTLB invalidate. No Unit-B global invalidation exists here.
vtd_boot_selective_invalidate:
    push rbx
    push r12
    push r13
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel vtd_bdf_overflow], 0
    jne  .bad
    mov  r13d, [rel vtd_bdf_count]
    test r13d, r13d
    jz   .bad
    cmp  r13d, VTD_BDF_MAX
    ja   .bad
    xor  r12d, r12d
    cmp  byte [rel vtd_qi_on], 1
    je   .qi_source
.source:
    lea  rdx, [rel vtd_bdf_list]
    mov  esi, [rdx + r12*4]
    mov  edi, VTD_DID_IDENTITY
    xor  edx, edx                         ; FM=0: exactly this function
    call vtd_ccmd_device_value
    mov  [rbx + VTD_REG_CCMD], rax
    mfence
    mov  ecx, VTD_WAIT_SPINS
.cc_wait:
    bt   qword [rbx + VTD_REG_CCMD], 63
    jnc  .source_done
    pause
    dec  ecx
    jnz  .cc_wait
    jmp  .bad
.source_done:
    inc  r12d
    cmp  r12d, r13d
    jb   .source

    mov  rax, [rel vtd_ecap]
    shr  rax, 8
    and  eax, 0x3FF
    shl  eax, 4
    add  rax, rbx
    mov  rdx, VTD_DID_IDENTITY
    shl  rdx, 32
    mov  r8, 0xA000000000000000           ; IVT | IIRG=domain
    or   rdx, r8
    mov  [rax + 8], rdx
    mfence
    mov  ecx, VTD_WAIT_SPINS
.iotlb_wait:
    bt   qword [rax + 8], 63
    jnc  .native_iotlb
    pause
    dec  ecx
    jnz  .iotlb_wait
    jmp  .bad
.native_iotlb:
    mov  rdx, VTD_DID_NATIVE
    shl  rdx, 32
    mov  r8, 0xA000000000000000           ; IVT | IIRG=domain
    or   rdx, r8
    mov  [rax + 8], rdx
    mfence
    mov  ecx, VTD_WAIT_SPINS
.native_wait:
    bt   qword [rax + 8], 63
    jnc  .yes
    pause
    dec  ecx
    jnz  .native_wait
.bad:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret
.yes:
    mov  eax, 1
    pop  r13
    pop  r12
    pop  rbx
    ret
.qi_source:                                ; SEC-D3a: the same selective scope, queued
    mov  esi, r13d
    sub  esi, r12d
    cmp  esi, VTD_QI_BOOT_BATCH
    jbe  .qi_count
    mov  esi, VTD_QI_BOOT_BATCH
.qi_count:
    ; The helper preserves RSI, so only a completed batch advances coverage.
    mov  edi, r12d
    call vtd_qi_boot_context_batch
    test eax, eax
    jz   .bad
    add  r12d, esi
    cmp  r12d, r13d
    jb   .qi_source
    mov  edi, VTD_DID_IDENTITY
    call vtd_qi_iotlb_desc
    mov  rdi, rax
    call vtd_qi_invalidate
    test eax, eax
    jz   .bad
    mov  edi, VTD_DID_NATIVE
    call vtd_qi_iotlb_desc
    mov  rdi, rax
    call vtd_qi_invalidate
    test eax, eax
    jz   .bad
    jmp  .yes

; Boot-only selective context batch: EDI=first BDF index, ESI=count (1..128).
; Preserves RSI and all nonvolatile GPRs; EAX=1 only after the fresh status
; write. Called before TE, after QIE is confirmed. Runtime invalidation keeps
; its existing per-descriptor submission/wait ABI below.
;
; Intel VT-d rev5 sections 6.5.2 / 6.5.2.9 / 6.5.2.12: IQH releases fetched
; valid descriptors, not completed invalidations; N-1 slots are usable. Reserve
; the entire batch + WAIT from one checked full-width IQH under the shared lock
; before any queue write. WAIT completion covers every earlier context. The
; boot caller submits no later batch until that status arrives, then retains
; separate DID1/DID2 IOTLB completion waits. No global invalidate or scope change.
vtd_qi_boot_context_batch:
    push rbx
    push rsi
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    test r13d, r13d
    jz   .bad_unlocked
    cmp  r13d, VTD_QI_BOOT_BATCH
    ja   .bad_unlocked
    cmp  byte [rel vtd_bdf_overflow], 0
    jne  .bad_unlocked
    mov  eax, [rel vtd_bdf_count]
    cmp  eax, VTD_BDF_MAX
    ja   .bad_unlocked
    cmp  r12d, eax
    jae  .bad_unlocked
    sub  eax, r12d
    cmp  r13d, eax
    ja   .bad_unlocked
    lea  rdi, [rel vtd_qi_lock]
    call spin_acquire
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel vtd_qi_on], 1
    jne  .bad
    mov  eax, [rbx + VTD_REG_GSTS]
    and  eax, VTD_GSTS_TES | VTD_GSTS_QIES
    cmp  eax, VTD_GSTS_QIES                ; never a live-runtime batching path
    jne  .bad
    test dword [rbx + VTD_REG_FSTS], VTD_FSTS_IQE_ITE
    jnz  .bad
    mov  r14, [rel vtd_qi_queue]
    mov  r15, [rel vtd_qi_status]
    test r14, r14
    jz   .bad
    test r15, r15
    jz   .bad
    mov  eax, [rel vtd_qi_tail]
    cmp  eax, VTD_QI_ENTRIES
    jae  .bad
    mov  r8d, eax
    mov  rax, [rbx + VTD_REG_IQH]
    cmp  rax, (VTD_QI_ENTRIES - 1) * 16
    ja   .bad
    test al, 15
    jnz  .bad
    shr  eax, 4
    sub  eax, r8d
    dec  eax
    and  eax, VTD_QI_ENTRIES - 1           ; free = (head-tail-1) mod N
    lea  ecx, [r13d + 1]                   ; count contexts and one WAIT
    cmp  eax, ecx
    jb   .bad                             ; no partial admission or tail publication
    lea  r9, [rel vtd_bdf_list]
.source:
    mov  esi, [r9 + r12*4]
    mov  edi, VTD_DID_IDENTITY
    xor  edx, edx                         ; same device-selective FM=0 descriptor
    call vtd_qi_cc_desc
    mov  ecx, r8d
    shl  ecx, 4
    mov  [r14 + rcx], rax
    mov  qword [r14 + rcx + 8], 0
    inc  r8d
    and  r8d, VTD_QI_ENTRIES - 1
    inc  r12d
    dec  r13d
    jnz  .source
    inc  dword [rel vtd_qi_token]
    mov  edx, [rel vtd_qi_token]
    test edx, edx
    jnz  .token_ok
    inc  edx                               ; zero remains cleared/not-completed
    mov  [rel vtd_qi_token], edx
.token_ok:
    mov  dword [r15], 0
    mov  ecx, r8d
    shl  ecx, 4
    mov  rax, rdx
    shl  rax, 32
    or   rax, VTD_QI_DESC_WAIT | (1 << 5)
    mov  [r14 + rcx], rax
    mov  [r14 + rcx + 8], r15
    inc  r8d
    and  r8d, VTD_QI_ENTRIES - 1
    mov  [rel vtd_qi_tail], r8d
    mfence                                ; all descriptor/status stores before IQT
    mov  eax, r8d
    shl  eax, 4
    mov  [rbx + VTD_REG_IQT], rax
    mov  ecx, VTD_WAIT_SPINS
.wait:
    test dword [rbx + VTD_REG_FSTS], VTD_FSTS_IQE_ITE
    jnz  .bad
    cmp  [r15], edx
    je   .done
    pause
    dec  ecx
    jnz  .wait
.bad:
    xor  eax, eax
    jmp  .unlock
.done:
    mov  eax, 1
.unlock:
    push rax
    lea  rdi, [rel vtd_qi_lock]
    call spin_release
    pop  rax
    jmp  .out
.bad_unlocked:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbx
    ret

vtd_wait_gsts_set:
    push rbx
    mov  rbx, [rel vtd_unitb_base]
    mov  ecx, VTD_WAIT_SPINS
.loop:
    mov  eax, [rbx + VTD_REG_GSTS]
    test eax, edi
    jnz  .yes
    pause
    dec  ecx
    jnz  .loop
    xor  eax, eax
    pop  rbx
    ret
.yes:
    mov  eax, 1
    pop  rbx
    ret

vtd_disable_te:
    push rbx
    cmp  byte [rel vtd_enabled], 1
    jne  .off
    mov  rbx, [rel vtd_unitb_base]
    call vtd_gcmd_persistent               ; GCMD is write-only (a read is not the state)
    and  eax, ~VTD_GCMD_TE
    mov  [rbx + VTD_REG_GCMD], eax
    mov  ecx, VTD_WAIT_SPINS
.wait:
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_TES
    jz   .off
    pause
    dec  ecx
    jnz  .wait
    ; TES is still observable: report not-ready but retain enabled=1 so no
    ; later policy can mistake an unproven disable for a clean state.
    mov  byte [rel vtd_ready], 0
    mov  byte [rel vtd_native_ready], 0
    pop  rbx
    ret
.off:
    mov  byte [rel vtd_enabled], 0
    mov  byte [rel vtd_ready], 0
    mov  byte [rel vtd_native_ready], 0
    xor  edi, edi
    xor  esi, esi
    call dma_iommu_bind
    pop  rbx
    ret

; vtd_reset_te_off: the warm-reset hand-off (BOOT WIN/LINUX/DIAG and REBOOT in
; command_udp, the hub's power_warm_reset), interrupts off, after the key wipe.
; EfiResetWarm need not reset the remapping unit (a CPU-only warm reset would
; leave TE on into firmware and the next OS, with storage still in DID 2), so
; translation is turned off here and TES is polled clear within the same bound
; as vtd_disable_te. Untranslated, a guest domain's posted descriptors would
; name raw host addresses (SEC F1): every function a guest has owned (DID 0x10
; secondary while owner=guest, live or stranded; DID 17 in any live, retired or
; poisoned state) is first taken off the bus, and if any cannot be read back
; off, TE stays on. Nothing resumes after it, so no PaOS state, hook or policy
; changes. EAX 1 = off or never enabled, 0 = TE left on (no unit, a guest
; function not proven off, or TES still set at the bound; the reset proceeds
; and the platform reset is then the only path that clears it).
vtd_reset_te_off:
    push rbx
    mov  eax, 1
    cmp  byte [rel vtd_enabled], 1
    jne  .out
    xor  eax, eax                          ; enabled without a unit: not proven off
    cmp  qword [rel vtd_unitb_base], 0
    je   .out
    cmp  byte [rel vtd_owner_guest], 0
    je   .driver_domain
    call vtd_secondary_bus_off             ; EAX 1 iff IO/MEM/BME read back clear
    test eax, eax
    jz   .out
.driver_domain:
    cmp  byte [rel vtdg_state], 0
    je   .translate_off
    mov  edi, [rel vtdg_bdf]
    mov  esi, 4
    mov  edx, 0x400                        ; INTx off, IO/MEM/BME clear; Status RW1C bits stay
    call pci_bdf_write
    mov  edi, [rel vtdg_bdf]
    mov  esi, 4
    call pci_bdf_read
    test eax, 7
    mov  eax, 0
    jnz  .out
.translate_off:
    mov  rbx, [rel vtd_unitb_base]
    call vtd_gcmd_persistent               ; GCMD is write-only: keep QIE/IRE as they are
    and  eax, ~VTD_GCMD_TE
    mov  [rbx + VTD_REG_GCMD], eax
    mov  ecx, VTD_WAIT_SPINS
.wait:
    mov  eax, 1
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_TES
    jz   .out
    pause
    dec  ecx
    jnz  .wait
    xor  eax, eax
.out:
    pop  rbx
    ret

; Clear pre-existing firmware status before first enable so STAT reports only
; faults generated by this ownership epoch. A fault wiped here while a guest
; domain is live is first latched for that domain (vtdg_fault_note, T1-4).
vtd_clear_faults:
    push rbx
    mov  rbx, [rel vtd_unitb_base]
    mov  eax, [rbx + VTD_REG_FSTS]
    mov  r8d, eax                         ; clear status after its FRCD sources
    xor  r9d, r9d                         ; 2 once any FRCD F bit is seen
    mov  rax, [rel vtd_cap]
    mov  rcx, rax
    shr  rcx, 24
    and  ecx, 0x3FF
    shl  ecx, 4                          ; FRO is in 16-byte units
    add  rcx, rbx
    shr  rax, 40
    and  eax, 0xFF
    inc  eax
    cmp  eax, 16
    jbe  .fr_loop
    mov  eax, 16
.fr_loop:
    test eax, eax
    jz   .status
    mov  rdx, [rcx + 8]
    bt   rdx, 63
    jnc  .next
    mov  r9d, 2
    mov  [rcx + 8], rdx                 ; W1C F bit
.next:
    add  rcx, 16
    dec  eax
    jmp  .fr_loop
.status:
    mov  edi, r8d
    or   edi, r9d
    call vtdg_fault_note                ; touches EAX only
    test r8d, r8d
    jz   .done
    mov  [rbx + VTD_REG_FSTS], r8d
.done:
    mfence
    pop  rbx
    ret

; Snapshot FSTS plus first live FRCD entries.  No fault is hidden or cleared.
vtd_capture_faults:
    push rbx
    mov  dword [rel vtd_fault_count], 0
    mov  qword [rel vtd_last_frcd_lo], 0
    mov  qword [rel vtd_last_frcd_hi], 0
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .absent
    mov  eax, [rbx + VTD_REG_FSTS]
    mov  [rel vtd_fsts], eax
    mov  rax, [rel vtd_cap]
    mov  rcx, rax
    shr  rcx, 24
    and  ecx, 0x3FF
    shl  ecx, 4
    add  rcx, rbx
    shr  rax, 40
    and  eax, 0xFF
    inc  eax
    cmp  eax, 16
    jbe  .loop
    mov  eax, 16
.loop:
    test eax, eax
    jz   .done
    mov  rdx, [rcx + 8]
    bt   rdx, 63
    jnc  .next
    inc  dword [rel vtd_fault_count]
    mov  [rel vtd_last_frcd_hi], rdx
    mov  rdx, [rcx]
    mov  [rel vtd_last_frcd_lo], rdx
.next:
    add  rcx, 16
    dec  eax
    jmp  .loop
.done:
    pop  rbx
    ret
.absent:
    mov  dword [rel vtd_fsts], 0
    mov  qword [rel vtd_last_frcd_lo], 0
    mov  qword [rel vtd_last_frcd_hi], 0
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; Domain-table construction (the vendor-neutral PCI helpers live in bus/pci_bdf).
; Packed BDF is bus:8, dev:5, fn:3.
; ---------------------------------------------------------------------------
; Return the RTL's BAR2 MMIO base from the pre-quiesce config snapshot.
vtd_secondary_bar2:
    mov  eax, [rel vtd_secondary_cfg + 0x18]
    test al, 1
    jnz  .bad
    mov  edx, eax
    and  edx, 6
    and  eax, 0xFFFFFFF0
    cmp  edx, 4
    jne  .check
    mov  edx, [rel vtd_secondary_cfg + 0x1C]
    shl  rdx, 32
    or   rax, rdx
.check:
    test rax, rax
    jz   .bad
    mov  rdx, rax
    shr  rdx, 34                         ; outside rework's 16 GiB identity map
    jnz  .bad
    ret
.bad:
    xor  eax, eax
    ret

; Find a segment-0 bridge whose secondary==subordinate==the RTL bus and prove
; that the RTL is the only function below it.  This is the safety gate for SBR:
; no xHCI/storage/lifeline function can share the reset domain.
vtd_find_safe_bridge:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel vtd_secondary_bdf]
    shr  r12d, 8                         ; target bus
    xor  r13d, r13d                      ; bus-0 devfn
.bridge:
    mov  edi, r13d
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0xFFFF
    je   .bridge_next
    mov  edi, r13d
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 16
    cmp  ax, 0x0604                      ; PCI-to-PCI bridge
    jne  .bridge_next
    mov  edi, r13d
    mov  esi, 0x18
    call pci_bdf_read
    mov  edx, eax
    shr  edx, 8
    and  edx, 0xFF                       ; secondary bus
    cmp  edx, r12d
    jne  .bridge_next
    shr  eax, 16
    and  eax, 0xFF                       ; subordinate bus
    cmp  eax, r12d
    jne  .bridge_next                   ; nested/shared hierarchy: refuse SBR

    xor  r14d, r14d
.function:
    mov  edi, r12d
    shl  edi, 8
    or   edi, r14d
    cmp  edi, [rel vtd_secondary_bdf]
    je   .function_next
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0xFFFF
    jne  .none                           ; another requester shares reset domain
.function_next:
    inc  r14d
    cmp  r14d, 256
    jb   .function
    mov  [rel vtd_secondary_bridge], r13d
    mov  eax, 1
    jmp  .out
.bridge_next:
    inc  r13d
    cmp  r13d, 256
    jb   .bridge
.none:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Restore the standard config header after FLR/SBR, keeping Command quiesced.
vtd_restore_config_after_reset:
    push rbx
    push r12
    mov  r12d, 0x0C
.header:
    lea  rbx, [rel vtd_secondary_cfg]
    mov  edx, [rbx + r12]
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, r12d
    call pci_bdf_write
    add  r12d, 4
    cmp  r12d, 0x40
    jb   .header
    movzx esi, byte [rel vtd_secondary_pcie_cap]
    test esi, esi
    jz   .done
    add  esi, 8
    movzx edx, word [rel vtd_secondary_devctl]
    mov  edi, [rel vtd_secondary_bdf]
    call pci_bdf_write                    ; upper DevSta half stays zero (RW1C-safe)
.done:
    pop  r12
    pop  rbx
    ret

; Reset the quiesced spare function.  Prefer FLR; the Lenovo RTL8161 advertises
; FLReset-, so the proven sole-device SBR is the expected fallback there.
vtd_reset_secondary:
    push rbx
    push r12
    push r13
    call hv_vcon_proof_roll_state_reset
    mov  byte [rel vtd_reset_verified], 0
    mov  byte [rel vtd_reset_method], 0
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_NO_TIMEBASE
    cmp  qword [rel tsc_khz], 0
    je   .bad                            ; never collapse mandatory settle delays
    ; RCQ-19 C-R1a: bus-off/quiesce left Command.INTx-disable (bit 10) set and
    ; FLR/SBR clears it.  Without that marker no reset could be evidenced.
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_ABSENT
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_read
    cmp  eax, 0xFFFFFFFF
    je   .bad
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_NO_MARKER
    test eax, 0x400
    jz   .bad
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 0x10                       ; PCI Express capability
    call pci_find_cap
    mov  r12d, eax
    mov  [rel vtd_secondary_pcie_cap], al
    test r12d, r12d
    jz   .sbr
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r12 + 8]
    call pci_bdf_read
    mov  [rel vtd_secondary_devctl], ax
    ; With BME already clear, require PCIe Transactions Pending to drain before
    ; either FLR or SBR.  A timeout leaves the function quiesced and owned by
    ; the guest state machine; it is never waved through as a verified reclaim.
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_TP_STUCK
    mov  r13d, 1000
.transactions:
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r12 + 8]
    call pci_bdf_read
    test eax, 0x00200000                 ; Device Status.Transactions Pending
    jz   .transactions_done
    mov  edi, 100
    call tsc_delay_us
    dec  r13d
    jnz  .transactions
    jmp  .bad
.transactions_done:
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r12 + 4]
    call pci_bdf_read
    bt   eax, 28                         ; Device Capabilities.FLR
    jnc  .sbr
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r12 + 8]
    call pci_bdf_read
    and  eax, 0xFFFF                     ; do not W1C Device Status
    or   eax, 0x8000                     ; Device Control.BCR_FLR
    mov  edx, eax
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r12 + 8]
    call pci_bdf_write
    mov  edi, 120000                     ; PCIe requires <=100 ms + margin
    call tsc_delay_us
    mov  byte [rel vtd_reset_method], 1
    jmp  .ready_poll
.sbr:
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_NO_BRIDGE
    call vtd_find_safe_bridge
    test eax, eax
    jz   .bad
    mov  r13d, [rel vtd_secondary_bridge]
    mov  edi, r13d
    mov  esi, 0x3C
    call pci_bdf_read
    or   eax, 0x00400000                 ; Bridge Control.SBR (word bit 6)
    mov  edx, eax
    mov  edi, r13d
    mov  esi, 0x3C
    call pci_bdf_write
    mov  edi, 3000                       ; hold >=2 ms
    call tsc_delay_us
    mov  edi, r13d
    mov  esi, 0x3C
    call pci_bdf_read
    and  eax, 0xFFBFFFFF
    mov  edx, eax
    mov  edi, r13d
    mov  esi, 0x3C
    call pci_bdf_write
    mov  edi, 120000                     ; post-reset settle >=100 ms
    call tsc_delay_us
    mov  byte [rel vtd_reset_method], 2
.ready_poll:
    mov  r13d, 100                       ; bounded additional 1 s readiness poll
.ready:
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_BAD_ANSWER
    mov  edi, [rel vtd_secondary_bdf]
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0x10EC
    je   .restore
    cmp  eax, 0xFFFFFFFF
    jne  .bad
    mov  edi, 10000
    call tsc_delay_us
    dec  r13d
    jnz  .ready
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_NEVER_READY
    jmp  .bad
.restore:
    ; RCQ-19 C-R1a: a function that answers but still holds bit 10 ignored the
    ; FLR/SBR and keeps the guest's state: not verified, the context stays blocked.
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_IGNORED
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_read
    test eax, 0x400
    jnz  .bad
    call vtd_restore_config_after_reset
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_RESTORE
    mov  edi, [rel vtd_secondary_bdf]
    xor  esi, esi
    call pci_bdf_read
    cmp  ax, 0x10EC
    jne  .bad
    mov  byte [rel vtd_reset_refusal], VTD_REFUSE_NONE
    mov  byte [rel vtd_reset_verified], 1
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

vtd_snapshot_secondary:
    push rbx
    mov  byte [rel vtd_vpci_identity_open], 0
    cld
    lea  rdi, [rel vtd_vpci_bar_probe]
    xor  eax, eax
    mov  ecx, 6
    rep  stosb
    lea  rdi, [rel vtd_secondary_bar_size]
    mov  ecx, 6
    rep  stosd
    xor  esi, esi
    lea  rbx, [rel vtd_secondary_cfg]
.loop:
    mov  edi, [rel vtd_secondary_bdf]
    call pci_bdf_read
    mov  [rbx + rsi], eax
    add  esi, 4
    cmp  esi, VTD_CFG_BYTES
    jb   .loop
    mov  eax, [rbx + 4]
    and  eax, 0xFFFF                     ; never replay W1C Status bits
    mov  [rel vtd_secondary_cmd], eax
    ; The class rewrite is only a no-bind hint: r8169 matches supported 10ec
    ; device IDs directly. vtd_vpci_in therefore withholds the device half
    ; until /init is live, while retaining the real vendor throughout.
    ; Physical config is untouched.
    mov  eax, [rbx + 8]
    and  eax, 0x00FFFFFF
    or   eax, 0xFF000000
    mov  [rbx + 8], eax
    ; Preserve the physical snapshot as the restore oracle. Linux sees an
    ; independent guest BAR shadow; relocation never reaches real config.
    lea  rsi, [rbx + 0x10]
    lea  rdi, [rel vtd_vpci_guest_bar]
    mov  ecx, 6
    rep  movsd
    pop  rbx
    ret

; Port Classic pt_bar_probe's proven sizing sequence while IO/MEM/BME decode
; is quiesced. Only memory-BAR low halves retain measured byte sizes.
vtd_probe_secondary_bars:
    push rbx
    push r12
    push r13
    push r14
    lea  rbx, [rel vtd_secondary_cfg + 0x10]
    lea  r12, [rel vtd_secondary_bar_size]
    xor  r13d, r13d
.loop:
    cmp  r13d, 6
    jae  .done
    mov  r14d, [rbx + r13*4]
    test r14d, r14d
    jz   .next
    test r14b, 1
    jnz  .next
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r13*4 + 0x10]
    mov  edx, 0xFFFFFFFF
    call pci_bdf_write
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r13*4 + 0x10]
    call pci_bdf_read
    push rax
    mov  edi, [rel vtd_secondary_bdf]
    lea  esi, [r13*4 + 0x10]
    mov  edx, r14d
    call pci_bdf_write
    pop  rax
    and  eax, 0xFFFFFFF0
    jz   .consume
    not  eax
    inc  eax
    mov  [r12 + r13*4], eax
.consume:
    mov  eax, r14d
    and  eax, 6
    cmp  eax, 4
    jne  .next
    inc  r13d
.next:
    inc  r13d
    jmp  .loop
.done:
    mov  eax, 1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

vtd_quiesce_secondary:
    ; Stop the RTL MAC before withdrawing bus mastering (the proven vfio/RTL
    ; order); BAR2 is the Realtek MMIO register window, not BAR0 I/O space.
    call vtd_secondary_bar2
    test rax, rax
    jz   .bad
    mov  [rel vtd_secondary_bar2_mmio], rax
    mov  rdi, rax
    call mmio_mark_uc
    test eax, eax
    jz   .bad
    ; Firmware may leave the spare function's Memory Space Enable clear.  Turn
    ; on decode only long enough to reach ChipCmd; the saved command is restored
    ; on every rollback and normal reclaim.
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    mov  edx, [rel vtd_secondary_cmd]
    or   edx, 2
    call pci_bdf_write
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_read
    test eax, 2
    jz   .bad
    mov  rax, [rel vtd_secondary_bar2_mmio]
    mov  byte [rax + 0x37], 0             ; ChipCmd: stop TX/RX
    mfence
    movzx eax, byte [rax + 0x37]
    test al, 0x0C                         ; TE|RE must read back clear
    jnz  .bad
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    mov  edx, [rel vtd_secondary_cmd]
    and  edx, ~7                         ; no I/O, memory decode, or bus master
    or   edx, 0x400                      ; INTx disable
    call pci_bdf_write
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_read
    test eax, 7
    jnz  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

vtd_restore_secondary:
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    mov  edx, [rel vtd_secondary_cmd]
    call pci_bdf_write
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_read
    and  eax, 0xFFFF
    mov  edx, [rel vtd_secondary_cmd]
    and  edx, 0xFFFF
    cmp  eax, edx
    sete al
    movzx eax, al
    ret

vtd_prepare_guest_domain:
    mov  qword [rel vtd_guest_dom_bytes], 0   ; no recorded domain unless this succeeds
    cmp  byte [rel vtd_guest_tables_ready], 1
    je   .map
    call vtd_alloc_page
    test rax, rax
    jz   .bad
    mov  [rel vtd_guest_pml4], rax
    call vtd_alloc_page
    test rax, rax
    jz   .bad
    mov  [rel vtd_guest_pdpt], rax
    xor  ecx, ecx
.alloc_pd:
    push rcx
    call vtd_alloc_page
    pop  rcx
    test rax, rax
    jz   .bad
    lea  rdx, [rel vtd_guest_pd]
    mov  [rdx + rcx*8], rax
    inc  ecx
    cmp  ecx, VTD_GUEST_RAM_PDS
    jb   .alloc_pd
    mov  rdi, [rel vtd_guest_pml4]
    mov  rax, [rel vtd_guest_pdpt]
    or   rax, 3
    mov  [rdi], rax
    mov  byte [rel vtd_guest_tables_ready], 1
.map:
    mov  edi, VTD_GUEST_RAM_BYTES         ; RC-speed-reserve: the span holds the legacy RAM
    call hv_linux_reserve_dma
    test rax, rax
    jz   .bad
    test rax, 0x1FFFFF                    ; 2 MiB leaves require aligned RAM
    jnz  .bad
    ; RCQ-50 F1R: DID 0x10 maps VTD_GUEST_RAM_BYTES from hv_linux_ram = base +
    ; HV_LINUX_CTRL_BYTES. The span request above includes that RAM; still refuse,
    ; before any table write, unless the whole range lies inside the held span.
    cmp  qword [rel hv_linux_region_capacity], HV_LINUX_CTRL_BYTES + VTD_GUEST_RAM_BYTES
    jb   .bad
    ; RCQ-50 F1: DID 0x10 is the legacy guest's NIC domain. Every assign path's START
    ; is a fresh generation, which vm_profile_bind_launch gives the legacy shape, so map
    ; exactly GPA 0..VTD_GUEST_RAM_BYTES, never a previous profile's hv_linux_ram_bytes.
    ; The range is recorded; hv_linux_prepare refuses a START whose final RAM differs.
    mov  esi, VTD_GUEST_RAM_BYTES
    shr  rsi, 21                          ; leaves still to map
    mov  rdx, [rel hv_linux_ram]
    or   rdx, 0x83                       ; R/W, 2 MiB leaf
    cld
    xor  r8d, r8d                        ; PD index
.pd:
    lea  rax, [rel vtd_guest_pd]
    mov  rdi, [rax + r8*8]
    push rdi
    xor  eax, eax
    mov  ecx, 512
    rep  stosq
    pop  rdi
    xor  r9d, r9d                        ; PDPT entry: 0 unless this PD holds a leaf
    test rsi, rsi
    jz   .link
    lea  r9, [rdi + 3]
    xor  ecx, ecx
.leaf:
    mov  [rdi + rcx*8], rdx
    add  rdx, 0x200000
    dec  rsi
    jz   .link
    inc  ecx
    cmp  ecx, 512
    jb   .leaf
.link:
    mov  rax, [rel vtd_guest_pdpt]
    mov  [rax + r8*8], r9
    call vtd_flush_page                  ; RDI = this PD
    inc  r8d
    cmp  r8d, VTD_GUEST_RAM_PDS
    jb   .pd
    mov  rdi, [rel vtd_guest_pml4]
    call vtd_flush_page
    mov  rdi, [rel vtd_guest_pdpt]
    call vtd_flush_page
    mfence
    mov  rax, [rel hv_linux_ram]
    mov  [rel vtd_guest_dom_hpa], rax
    mov  qword [rel vtd_guest_dom_bytes], VTD_GUEST_RAM_BYTES
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; vtd_guest_domain_check(RDI = final guest-RAM HPA, RSI = final RAM bytes) -> EAX 0 when
; no guest owns the NIC, or its DID 0x10 domain is exactly that RAM; 1 = the START must
; not run (RCQ-50 F1). Clobbers EAX only.
vtd_guest_domain_check:
    xor  eax, eax
    cmp  byte [rel vtd_owner_guest], 1
    jne  .out
    inc  eax
    cmp  rdi, [rel vtd_guest_dom_hpa]
    jne  .out
    cmp  rsi, [rel vtd_guest_dom_bytes]
    jne  .out
    xor  eax, eax
.out:
    ret

; Install a private context table for the secondary's actual bus by cloning the
; LIVE root-selected table. This preserves any DID-2 native entries that share
; the bus; cloning vtd_shared_ctx here would silently demote them to DID 1.
vtd_prepare_secondary_bus:
    cmp  byte [rel vtd_bus_ctx_ready], 1
    je   .yes
    call vtd_alloc_page
    test rax, rax
    jz   .bad
    mov  [rel vtd_bus_ctx], rax
    mov  eax, [rel vtd_secondary_bdf]
    shr  eax, 8
    shl  eax, 4
    add  rax, [rel vtd_root]
    mov  rsi, [rax]
    test sil, 1
    jz   .bad
    and  rsi, -4096
    cld
    mov  rdi, [rel vtd_bus_ctx]
    mov  ecx, 512
    rep  movsq
    mov  rdi, [rel vtd_bus_ctx]
    call vtd_flush_page
    mfence
    mov  eax, [rel vtd_secondary_bdf]
    shr  eax, 8
    shl  eax, 4
    mov  rdi, [rel vtd_root]
    add  rdi, rax
    mov  rax, [rel vtd_bus_ctx]
    or   rax, 1
    mov  [rdi], rax
    mov  qword [rdi + 8], 0
    clflush [rdi]
    mfence
    mov  byte [rel vtd_bus_ctx_ready], 1
.yes:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; EDI=old DID, ESI=source-id. Device-selective context + domain-selective IOTLB.
vtd_selective_invalidate:
    push rbx
    cmp  byte [rel vtd_enabled], 1
    jne  .bad
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    cmp  byte [rel vtd_qi_on], 1
    je   .qi
    xor  edx, edx                         ; FM=0: exactly this function
    call vtd_ccmd_device_value            ; preserves RDI (old DID) for IOTLB
    mov  [rbx + VTD_REG_CCMD], rax
    mfence
    mov  ecx, VTD_WAIT_SPINS
.cc_wait:
    bt   qword [rbx + VTD_REG_CCMD], 63
    jnc  .iotlb
    pause
    dec  ecx
    jnz  .cc_wait
    jmp  .bad
.iotlb:
    mov  rax, [rel vtd_ecap]
    shr  rax, 8
    and  eax, 0x3FF
    shl  eax, 4                          ; IRO in 16-byte units
    add  rax, rbx
    mov  rdx, rdi
    shl  rdx, 32
    mov  r8, 0xA000000000000000           ; IVT + IIRG=domain
    or   rdx, r8
    mov  [rax + 8], rdx
    mfence
    mov  ecx, VTD_WAIT_SPINS
.iotlb_wait:
    bt   qword [rax + 8], 63
    jnc  .yes
    pause
    dec  ecx
    jnz  .iotlb_wait
    jmp  .bad
.yes:
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret
.qi:                                       ; SEC-D3a: same scope, queued
    push rdi                              ; old DID for the IOTLB
    xor  edx, edx
    call vtd_qi_cc_desc
    mov  rdi, rax
    call vtd_qi_invalidate
    pop  rdi
    test eax, eax
    jz   .bad
    call vtd_qi_iotlb_desc
    mov  rdi, rax
    call vtd_qi_invalidate
    test eax, eax
    jz   .bad
    jmp  .yes

; ---------------------------------------------------------------------------
; SEC-D3a VT-d Queued Invalidation (VT-d spec 6.5.2). Interrupt remapping needs
; it (the interrupt-entry-cache flush has no register form), and once QIE is set
; register-based invalidation must not be used. Single context: VT-d setup and
; assignment/reclaim run on the BSP. RBX = unit register base for all of these.
; ---------------------------------------------------------------------------

; vtd_gcmd_persistent -> EAX = the persistent command bits now in effect (TE,
;   QIE, IRE) read from GSTS. GCMD is write-only: every command write carries
;   them. CFI is deliberately never carried: every PaOS command write leaves
;   compatibility-format interrupts blocked (SEC-D3b).
vtd_gcmd_persistent:
    mov  eax, [rbx + VTD_REG_GSTS]
    and  eax, VTD_GSTS_TES | VTD_GSTS_QIES | VTD_GSTS_IRES
    ret

; vtd_qi_enable -> EAX 1 (QI on, or the unit lacks QI and the register path
;   stays) / 0 (a stale queue could not be turned off: VT-d is not enabled).
vtd_qi_enable:
    mov  byte [rel vtd_qi_on], 0
    test qword [rel vtd_ecap], VTD_ECAP_QI
    jz   .register
    cmp  qword [rel vtd_qi_queue], 0
    je   .register
    cmp  qword [rel vtd_qi_status], 0
    je   .register
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_QIES
    jz   .program
    ; Firmware left QI on: let its queue drain (IQH == IQT) before QIE is
    ; cleared, then reprogram IQA, which is writable only with QIE clear.
    mov  ecx, VTD_WAIT_SPINS
.drain:
    mov  rax, [rbx + VTD_REG_IQH]
    cmp  rax, [rbx + VTD_REG_IQT]
    je   .drained
    pause
    dec  ecx
    jnz  .drain
    xor  eax, eax
    ret
.drained:
    call vtd_gcmd_persistent
    and  eax, ~VTD_GCMD_QIE
    mov  [rbx + VTD_REG_GCMD], eax
    mov  ecx, VTD_WAIT_SPINS
.off_wait:
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_QIES
    jz   .program
    pause
    dec  ecx
    jnz  .off_wait
    xor  eax, eax
    ret
.program:
    mov  qword [rbx + VTD_REG_IQT], 0
    mov  rax, [rel vtd_qi_queue]           ; 4 KiB aligned; DW=0 (128-bit), QS=0 (256)
    mov  [rbx + VTD_REG_IQA], rax
    mov  dword [rel vtd_qi_tail], 0
    call vtd_gcmd_persistent
    or   eax, VTD_GCMD_QIE
    mov  [rbx + VTD_REG_GCMD], eax
    mfence
    mov  edi, VTD_GSTS_QIES
    call vtd_wait_gsts_set
    test eax, eax
    jz   .fail
    mov  byte [rel vtd_qi_on], 1
    lea  rdi, [rel str_vtd_qi_on]
    call serial_string
.register:
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; vtd_host_irq_path_ok -> EAX = 1 iff no host interrupt PaOS relies on would
;   cross interrupt remapping. PaOS's only host interrupt is the legacy PIC
;   timer (core/time); it bypasses remapping when it reaches the CPU through
;   LAPIC LINT0 in ExtINT mode (virtual wire A) or with the LAPIC disabled. A
;   PIC routed through an IOAPIC (virtual wire B) would arrive as a
;   compatibility-format message, which CFI=0 blocks, so IR is then refused.
vtd_host_irq_path_ok:
    mov  ecx, 0x1B                        ; IA32_APIC_BASE
    rdmsr
    test eax, (1 << 11)
    jz   .yes                             ; LAPIC off: PIC drives INTR directly
    test eax, (1 << 10)
    jz   .xapic
    mov  ecx, 0x835                       ; x2APIC LVT LINT0
    rdmsr
    jmp  .check
.xapic:
    and  eax, 0xFFFFF000
    mov  eax, [rax + 0x350]               ; LVT LINT0
.check:
    test eax, 0x10000                     ; masked: the PIC cannot be on LINT0
    jnz  .no
    and  eax, 0x700
    cmp  eax, 0x700                       ; delivery mode ExtINT
    jne  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; vtd_ir_enable — SEC-D3b interrupt remapping (VT-d spec 5.1, 6.5.2.7).
;   Admin 00:46 scope: IRTA + IRTE, SIRTP, IRE, CFI=0, posture flips only after
;   IRE and QI read back active. PaOS programs no host MSI (its devices are
;   polled and the guest's NIC interrupts are injected by PaOS), so the table
;   holds no present entry: every MSI-format request from a device under this
;   unit, including a guest-driven device DMA-writing the 0xFEEx_xxxx window,
;   is blocked and faulted instead of reaching a CPU (D-NEW). Requires ECAP.IR,
;   QI on, the IRT page and vtd_host_irq_path_ok. A firmware-left IRE is turned
;   off before the table pointer changes. Any failure turns IRE off again and
;   leaves vtd_ir_on = 0 (posture 'absent'); VT-d itself continues.
;   RBX = unit register base. -> EAX = 1 IR on / 0 not on. clobbers: caller-saved.
vtd_ir_enable:
    mov  byte [rel vtd_ir_on], 0
    mov  byte [rel vtd_ir_reason], VTD_IR_R_ECAP
    test qword [rel vtd_ecap], VTD_ECAP_IR
    jz   .no
    mov  byte [rel vtd_ir_reason], VTD_IR_R_QI
    cmp  byte [rel vtd_qi_on], 1
    jne  .no
    cmp  qword [rel vtd_irt], 0
    je   .no
    mov  byte [rel vtd_ir_reason], VTD_IR_R_HOSTPATH
    call vtd_host_irq_path_ok
    test eax, eax
    jz   .no
    mov  byte [rel vtd_ir_reason], VTD_IR_R_HW
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_IRES
    jz   .program
    call vtd_ir_off                       ; firmware left IR on: off before IRTA changes
    test eax, eax
    jz   .no
.program:
    mov  rax, [rel vtd_irt]               ; 4 KiB aligned, EIME=0 (xAPIC), S=7
    or   rax, VTD_IRT_S
    mov  [rbx + VTD_REG_IRTA], rax
    mfence
    call vtd_gcmd_persistent
    or   eax, VTD_GCMD_SIRTP
    mov  [rbx + VTD_REG_GCMD], eax
    mfence
    mov  edi, VTD_GSTS_IRTPS
    call vtd_wait_gsts_set
    test eax, eax
    jz   .fail
    mov  edi, VTD_QI_DESC_IEC             ; global interrupt entry cache flush
    call vtd_qi_invalidate
    test eax, eax
    jz   .fail
    call vtd_gcmd_persistent              ; CFI is never carried: compatibility format blocked
    or   eax, VTD_GCMD_IRE
    mov  [rbx + VTD_REG_GCMD], eax
    mfence
    mov  edi, VTD_GSTS_IRES
    call vtd_wait_gsts_set
    test eax, eax
    jz   .fail
    ; Read back the whole posture before claiming it.
    mov  eax, [rbx + VTD_REG_GSTS]
    and  eax, VTD_GSTS_IRES | VTD_GSTS_QIES | VTD_GSTS_CFIS
    cmp  eax, VTD_GSTS_IRES | VTD_GSTS_QIES
    jne  .fail
    mov  rax, [rbx + VTD_REG_IRTA]
    mov  rcx, [rel vtd_irt]
    or   rcx, VTD_IRT_S
    cmp  rax, rcx
    jne  .fail
    mov  byte [rel vtd_ir_on], 1
    mov  byte [rel vtd_ir_reason], VTD_IR_R_ON
    lea  rdi, [rel str_vtd_ir_on]
    call serial_string
    mov  eax, 1
    ret
.fail:
    call vtd_ir_off
.no:
    lea  rdi, [rel str_vtd_ir_absent]
    call serial_string
    xor  eax, eax
    ret

; vtd_ir_off — clear IRE (keeping TE/QIE) and wait for IRES to drop.
;   -> EAX = 1 off / 0 still on. clobbers: RAX,RCX,RDI.
vtd_ir_off:
    cmp byte [rel vtdg_state],VTDG_LIVE
    je .guest_pinned
    cmp byte [rel vtdg_state],VTDG_POISON
    je .guest_pinned
    call vtd_gcmd_persistent
    and  eax, ~VTD_GCMD_IRE
    mov  [rbx + VTD_REG_GCMD], eax
    mfence
    mov  ecx, VTD_WAIT_SPINS
.wait:
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_IRES
    jz   .off
    pause
    dec  ecx
    jnz  .wait
    xor  eax, eax
    ret
.off:
    mov  eax, 1
    ret

.guest_pinned:
    xor eax,eax
    ret

; vtd_qi_cc_desc(EDI=DID, ESI=SID, EDX=FM) -> RAX = device-selective
;   context-cache invalidate descriptor (low qword; high qword is 0):
;   type 1 | G=11b (5:4) | DID 31:16 | SID 47:32 | FM 49:48.
vtd_qi_cc_desc:
    movzx eax, di
    shl  eax, 16
    or   eax, VTD_QI_DESC_CC | (3 << 4)
    movzx ecx, si
    shl  rcx, 32
    or   rax, rcx
    mov  ecx, edx
    and  ecx, 3
    shl  rcx, 48
    or   rax, rcx
    ret

; vtd_qi_iotlb_desc(EDI=DID) -> RAX = domain-selective IOTLB invalidate
;   descriptor (low qword; high qword 0): type 2 | G=10b (5:4) | DID 31:16.
;   Same scope as the register path (IVT | IIRG=domain, no drain hints).
vtd_qi_iotlb_desc:
    movzx eax, di
    shl  eax, 16
    or   eax, VTD_QI_DESC_IOTLB | (2 << 4)
    ret

; vtd_qi_invalidate(RDI = descriptor low qword) -> EAX 1 completed / 0 timeout or
;   queue error. Queues the descriptor and an invalidation-wait descriptor that
;   writes a fresh token to the status page, advances IQT once and polls.
;   One submitter at a time (vtd_qi_lock, held through the bounded wait): the
;   tail, the token and the single status dword are shared, and dma_alloc /
;   dma_iommu_unmap reach this at runtime (srcreview D3a N7). No interrupt
;   handler invalidates, so the spin lock cannot self-deadlock.
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8-R11.
vtd_qi_invalidate:
    push rdi
    lea  rdi, [rel vtd_qi_lock]
    call spin_acquire
    pop  rdi
    mov  r9, [rel vtd_qi_queue]
    mov  r10, [rel vtd_qi_status]
    mov  eax, [rel vtd_qi_tail]
    mov  ecx, eax
    shl  ecx, 4
    mov  [r9 + rcx], rdi
    mov  qword [r9 + rcx + 8], 0
    inc  eax
    and  eax, VTD_QI_ENTRIES - 1
    inc  dword [rel vtd_qi_token]
    mov  edx, [rel vtd_qi_token]
    test edx, edx
    jnz  .token_ok
    inc  edx                               ; never 0: 0 is the cleared status
    mov  [rel vtd_qi_token], edx
.token_ok:
    mov  dword [r10], 0
    mov  ecx, eax
    shl  ecx, 4
    mov  r11, rdx
    shl  r11, 32
    or   r11, VTD_QI_DESC_WAIT | (1 << 5)  ; status data 63:32, SW
    mov  [r9 + rcx], r11
    mov  [r9 + rcx + 8], r10               ; status address (4-byte aligned)
    inc  eax
    and  eax, VTD_QI_ENTRIES - 1
    mov  [rel vtd_qi_tail], eax
    mfence
    shl  eax, 4
    mov  [rbx + VTD_REG_IQT], rax
    mov  ecx, VTD_WAIT_SPINS
.wait:
    cmp  [r10], edx
    je   .done
    test dword [rbx + VTD_REG_FSTS], VTD_FSTS_IQE_ITE
    jnz  .bad
    pause
    dec  ecx
    jnz  .wait
.bad:
    xor  eax, eax
    jmp  .unlock
.done:
    mov  eax, 1
.unlock:
    push rax
    lea  rdi, [rel vtd_qi_lock]
    call spin_release
    pop  rax
    ret

vtd_secondary_ctx_ptr:
    mov  eax, [rel vtd_secondary_bdf]
    and  eax, 0xFF
    shl  eax, 4
    add  rax, [rel vtd_bus_ctx]
    ret

; EAX=1 iff the secondary's live context is the bounded guest DID/domain.
vtd_guest_ctx_ok:
    mov  rdx, [rel vtd_root]
    test rdx, rdx
    jz   .bad
    mov  edi, [rel vtd_secondary_bdf]
    mov  eax, edi
    shr  eax, 8
    shl  eax, 4
    add  rax, rdx
    mov  rdx, [rax]
    test dl, 1
    jz   .bad
    and  rdx, -4096
    mov  eax, edi
    and  eax, 0xFF
    shl  eax, 4
    add  rdx, rax
    mov  rax, [rdx]
    test al, 1
    jz   .bad
    and  rax, -4096
    cmp  rax, [rel vtd_guest_pml4]
    jne  .bad
    cmp  qword [rdx + 8], 0x1002
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; RCQ-19 R1: no translation at all for the function (context not present).  DMA
; it still has in flight faults instead of reaching guest or host memory.
vtd_set_secondary_blocked:
    call vtd_secondary_ctx_ptr
    mov  rdi, rax
    mov  qword [rdi], 0                  ; P=0 first
    mov  qword [rdi + 8], 0
    clflush [rdi]
    mfence
    mov  edi, VTD_DID_GUEST
    mov  esi, [rel vtd_secondary_bdf]
    call vtd_selective_invalidate
    ret

; RCQ-19 R1: config space only (the guest owned the BARs): no I/O, memory
; decode or bus master, INTx disabled.  EAX=1 iff IO/MEM/BME read back clear.
vtd_secondary_bus_off:
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    mov  edx, [rel vtd_secondary_cmd]
    and  edx, ~7
    or   edx, 0x400
    call pci_bdf_write
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_read
    test eax, 7
    jnz  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; RCQ-19 R1: the one way a guest-touched function returns to DID 1.  Block the
; context while still confined, stop bus mastering, drain and reset, and only
; then map identity and restore the host command register.  A failure up to and
; including the evidenced reset leaves the context blocked; a later one leaves
; the reset function on DID 1.  Either way EAX=0 and the caller keeps owner=guest.
vtd_secondary_return_identity:
    call vtd_set_secondary_blocked
    test eax, eax
    jz   .bad
    call vtd_secondary_bus_off
    test eax, eax
    jz   .bad
    call vtd_reset_secondary
    test eax, eax
    jz   .bad
    call vtd_set_secondary_identity
    test eax, eax
    jz   .bad
    call vtd_restore_secondary
    test eax, eax
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Restore the secondary context to DID 1 and invalidate any cached guest DID.
; Only vtd_secondary_return_identity calls this, after a verified reset.
vtd_set_secondary_identity:
    call vtd_secondary_ctx_ptr
    mov  rdi, rax
    mov  rax, [rel vtd_id_pml4]
    or   rax, 1
    mov  [rdi], rax
    mov  qword [rdi + 8], 0x102
    clflush [rdi]
    mfence
    mov  edi, VTD_DID_GUEST
    mov  esi, [rel vtd_secondary_bdf]
    call vtd_selective_invalidate
    test eax, eax
    jz   .done
    mov  edi, [rel vtd_secondary_bdf]
    call vtd_identity_ctx_ok
.done:
    ret

vtd_assign_context_only:
    call hv_vcon_proof_roll_state_reset
    mov  word [rel vtd_assign_refusal], VTD_REFUSE_NOT_READY ; and assign_reset = none
    cmp  byte [rel vtd_ready], 1
    jne  .bad
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_NO_TIMEBASE
    cmp  qword [rel tsc_khz], 0             ; no lease without a live timebase
    je   .bad
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_OWNED
    cmp  byte [rel vtd_owner_guest], 0
    jne  .bad
    cmp byte [rel vtdg_state],VTDG_LIVE
    je .bad
    cmp byte [rel vtdg_state],VTDG_POISON
    je .bad
    ; RCQ-19: an isolation refusal leaves the function exactly as found.
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_ISOLATION
    call vtd_iso_check
    test eax, eax
    jnz  .isolation_refused
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_GUEST_DOMAIN
    call vtd_prepare_guest_domain
    test eax, eax
    jz   .bad
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_BUS_CTX
    call vtd_prepare_secondary_bus
    test eax, eax
    jz   .bad
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_QUIESCE
    call vtd_snapshot_secondary
    call vtd_quiesce_secondary
    test eax, eax
    jz   .quiesce_bad
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_HANDOFF_RESET
    call vtd_probe_secondary_bars
    call vtd_reset_secondary                ; clean VFIO-style handoff state
    mov  cl, [rel vtd_reset_refusal]
    mov  [rel vtd_assign_reset_refusal], cl
    test eax, eax
    jz   .handoff_reset_bad
    ; SEC-D3b: before the guest can drive the function, block every MSI-format
    ; request it could emit (no present IRTE, CFI=0). A failure keeps the
    ; assignment with the truthful intr_remap=absent posture.
    push rbx
    mov  rbx, [rel vtd_unitb_base]
    call vtd_ir_enable
    pop  rbx
    call vtd_secondary_ctx_ptr
    mov  rdi, rax
    mov  rax, [rel vtd_guest_pml4]
    or   rax, 1
    mov  [rdi], rax
    mov  qword [rdi + 8], 0x1002         ; DID=0x10, AW=2
    clflush [rdi]
    mfence
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_CTX_INVAL
    mov  edi, VTD_DID_IDENTITY
    mov  esi, [rel vtd_secondary_bdf]
    call vtd_selective_invalidate
    test eax, eax
    jz   .undo
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_CTX_VERIFY
    call vtd_guest_ctx_ok
    test eax, eax
    jz   .undo
    mov  byte [rel vtd_assign_refusal], VTD_REFUSE_NONE
    mov  byte [rel vtd_vpci_active], 1
    mov  byte [rel vtd_vpci_identity_open], 0
    mov  dword [rel vtd_deadman_limit_ms], VTD_DEADMAN_MS
    cmp  byte [rel vtd_network_mode], 1
    jne  .ownership_live
    mov  byte [rel vtd_vpci_identity_open], 1
    mov  dword [rel vtd_deadman_limit_ms], VTD_NET_DEADMAN_MS
.ownership_live:
    mov  byte [rel vtd_owner_guest], 1
    call tsc_now
    mov  [rel vtd_deadman_tsc], rax
    mov  byte [rel vtd_deadman_armed], 1
    mov  eax, 1
    ret
.undo:
    ; The physical function remains quiesced until identity restoration and
    ; its invalidation are both proven.  If rollback itself fails, retain
    ; owner=guest so the caller/deadman can retry canonical reclaim.
    mov  byte [rel vtd_owner_guest], 1
    mov  byte [rel vtd_vpci_active], 0
    mov  byte [rel vtd_vpci_identity_open], 0
    call vtd_secondary_return_identity
    test eax, eax
    jz   .stranded
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_deadman_armed], 0
    jmp  .bad
.quiesce_bad:
    call vtd_restore_secondary
    jmp  .bad
.handoff_reset_bad:
    ; A fired-but-unverified reset may have cleared BARs.  Do not re-enable the
    ; saved Command register; retain logical custody and let canonical reclaim
    ; retry config restoration from the snapshot.
    mov  byte [rel vtd_owner_guest], 1
    mov  byte [rel vtd_vpci_active], 0
    mov  byte [rel vtd_vpci_identity_open], 0
    jmp  .stranded
.stranded:
    call tsc_now
    mov  [rel vtd_deadman_tsc], rax
    mov  byte [rel vtd_deadman_armed], 1
    jmp  .bad
.isolation_refused:
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_ISOLATION
.bad:
    xor  eax, eax
    ret

vtd_reclaim_internal:
    call hv_vcon_proof_roll_state_reset
    cmp  byte [rel vtd_owner_guest], 1
    jne  .already
    mov  byte [rel hv_linux_stop_req], 1
    mov  byte [rel vtd_vpci_identity_open], 0
    mov  byte [rel vtd_vpci_active], 0
    call vtd_secondary_return_identity   ; RCQ-19 R1: DMA stopped before DID 1
    test eax, eax
    jz   .bad
    mov  edi, [rel vtd_secondary_bdf]
    call vtd_identity_ctx_ok
    test eax, eax
    jz   .bad
    ; SEC-D3b: the function is back on DID 1 and reset: IR off again, before
    ; the fault epoch is re-read (a host device's blocked MSI must not strand
    ; reclaim). If IRES will not drop, IR simply stays on and is reported.
    cmp  byte [rel vtd_ir_on], 1
    jne  .ir_done
    push rbx
    mov  rbx, [rel vtd_unitb_base]
    call vtd_ir_off
    pop  rbx
    test eax, eax
    jz   .ir_done
    mov  byte [rel vtd_ir_on], 0
    mov  byte [rel vtd_ir_reason], VTD_IR_R_IDLE
.ir_done:
    call vtd_capture_faults
    cmp  dword [rel vtd_fsts], 0
    jne  .clear_fault_epoch
    cmp  dword [rel vtd_fault_count], 0
    je   .fault_epoch_clean
.clear_fault_epoch:
    ; A guest-domain fault is evidence about the failed ownership epoch, not a
    ; reason to strand the function there forever.  The command path snapshots
    ; FSTS/FRCD before reclaim.  Once DID 1 and device reset/config restoration
    ; are proven, clear the old RW1C records and require a clean re-read so the
    ; deadman can actually return custody to PaOS.
    call vtd_clear_faults
    call vtd_capture_faults
    cmp  dword [rel vtd_fsts], 0
    jne  .bad
    cmp  dword [rel vtd_fault_count], 0
    jne  .bad
.fault_epoch_clean:
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_network_mode], 0
    mov  byte [rel vtd_domain_l2_active], 0
    mov  byte [rel vtd_domain_bridge_ready], 0
    mov  byte [rel vtd_deadman_armed], 0
    mov  byte [rel vtd_reclaim_verified], 1
    inc  dword [rel vtd_reclaim_count]
.already:
    cmp  byte [rel vtd_ready], 1
    jne  .bad
    cmp  byte [rel vtd_secondary_found], 1
    jne  .bad
    mov  edi, [rel vtd_secondary_bdf]
    call vtd_identity_ctx_ok
    test eax, eax
    jz   .bad
    mov  byte [rel vtd_network_mode], 0
    mov  byte [rel vtd_domain_l2_active], 0
    mov  byte [rel vtd_domain_bridge_ready], 0
    mov  byte [rel vtd_reclaim_verified], 1
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Actual unattended reclaim. Called from the host idle path and VM host slices.
; RCQ-19: while the standing domain serves, the same deadman is its liveness
; lease (vtd_dd_lease_tick renews it); expiry or a crash goes through the
; bounded-restart path instead of a bare reclaim.
vtd_deadman_check:
    cmp  byte [rel vtd_deadman_armed], 1
    jne  .ret
    cmp  byte [rel vtd_owner_guest], 1
    jne  .disarm
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jz   .ret
    cmp  byte [rel vtd_dd_state], VTD_DD_SERVING
    jne  .limit
    call vtd_dd_lease_tick
    test eax, eax
    jnz  .dd_fire                        ; the guest left its run loop
    mov  rdx, [rel tsc_khz]
.limit:
    mov  eax, [rel vtd_deadman_limit_ms]
    imul rdx, rax
    call tsc_now
    sub  rax, [rel vtd_deadman_tsc]
    cmp  rax, rdx
    jb   .ret
    mov  byte [rel vtd_deadman_fired], 1
    mov  eax, VTD_DD_CAUSE_HANG
    cmp  byte [rel vtd_dd_state], VTD_DD_SERVING
    je   .dd_fire
    mov  eax, VTD_DD_CAUSE_BOOT
    cmp  byte [rel vtd_dd_state], VTD_DD_RESTARTING
    je   .dd_fire
    cmp  byte [rel vtd_dd_state], VTD_DD_STRANDED
    je   .stranded
    call vtd_reclaim_internal
    test eax, eax
    jz   .stranded_again                 ; RCQ-19: once per period, never every idle tick
    ret
.dd_fire:
    mov  byte [rel vtd_deadman_fired], 1
    mov  edi, eax
    call vtd_dd_fail
    ret
.stranded:
    ; A restart is never attempted after a failed reclaim: retry custody only.
    call vtd_reclaim_internal
    test eax, eax
    jz   .stranded_again
    mov  byte [rel vtd_dd_state], VTD_DD_EXHAUSTED
    ret
.stranded_again:
    call tsc_now
    mov  [rel vtd_deadman_tsc], rax
    ret
.disarm:
    mov  byte [rel vtd_deadman_armed], 0
.ret:
    ret

; ---------------------------------------------------------------------------
; RCQ-19 S1 standing driver domain: lease, bounded restart, fault injection.
; Every decision here runs from host timers and VM exits; nothing waits for
; the guest. The e1000e command path is never touched.
; ---------------------------------------------------------------------------

; SERVING only. EAX = VTD_DD_CAUSE_CRASH when the guest has left its run loop
; while it still owns the function, else 0. Guest-to-PaOS frames renew the
; lease (vtd_deadman_tsc); a quiet domain is asked to resolve the gateway once
; per VTD_DD_PROBE_MS, so a live bridge always produces a renewal.
vtd_dd_lease_tick:
    cmp  byte [rel hv_linux_running], 0
    jne  .alive
    cmp  byte [rel hv_linux_start_active], 0
    jne  .alive
    mov  eax, VTD_DD_CAUSE_CRASH
    ret
.alive:
    call virtio_domain_guest_progress
    cmp  rax, [rel vtd_dd_progress]
    je   .quiet
    mov  [rel vtd_dd_progress], rax
    call tsc_now
    mov  [rel vtd_deadman_tsc], rax
    mov  [rel vtd_dd_renew_tsc], rax
    inc  qword [rel vtd_dd_renewals]
    xor  eax, eax
    ret
.quiet:
    call tsc_now
    cmp  rax, [rel vtd_dd_probe_tsc]
    jb   .done
    mov  rdx, [rel tsc_khz]
    imul rdx, VTD_DD_PROBE_MS
    mov  rcx, rax
    sub  rcx, [rel vtd_deadman_tsc]
    cmp  rcx, rdx
    jb   .done                           ; renewed within the last probe period
    add  rax, rdx
    mov  [rel vtd_dd_probe_tsc], rax
    inc  dword [rel vtd_dd_probes]
    call virtio_domain_gateway_resolution_start
.done:
    xor  eax, eax
    ret

; EAX = restarts still allowed in the current window (VTD_DD_BUDGET minus the
; relaunches started during the last VTD_DD_WINDOW_MS).
vtd_dd_budget_left:
    call tsc_now
    mov  rdx, [rel tsc_khz]
    imul rdx, VTD_DD_WINDOW_MS
    mov  r8, rdx
    lea  rsi, [rel vtd_dd_ring]
    xor  ecx, ecx
    mov  r9d, VTD_DD_BUDGET
.slot:
    cmp  ecx, VTD_DD_BUDGET
    jae  .out
    mov  rdx, [rsi + rcx*8]
    test rdx, rdx
    jz   .next
    mov  r10, rax
    sub  r10, rdx
    cmp  r10, r8
    jae  .next                           ; aged out of the window
    dec  r9d
.next:
    inc  ecx
    jmp  .slot
.out:
    mov  eax, r9d
    ret

; EDI = VTD_DD_CAUSE_*. Reclaim the function, then either keep the capstone
; bound for a relaunch (budget left) or leave it host-owned (budget spent: the
; transport pump sees the domain gone and rolls egress back to native).
vtd_dd_fail:
    push rbx
    mov  ebx, edi
    mov  [rel vtd_dd_cause], bl
    inc  dword [rel vtd_dd_failures]
    call tsc_now
    mov  [rel vtd_dd_detect_tsc], rax
    ; Detection latency: from an injected fault when it is newer than the last
    ; renewal, otherwise from the last renewal (the lease's own view).
    mov  rdx, [rel vtd_dd_renew_tsc]
    mov  rcx, [rel vtd_dd_fault_tsc]
    cmp  rcx, rdx
    jbe  .from
    mov  rdx, rcx
.from:
    mov  dword [rel vtd_dd_detect_ms], 0
    test rdx, rdx
    jz   .reclaim
    cmp  rax, rdx
    jb   .reclaim
    sub  rax, rdx
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .reclaim
    xor  edx, edx
    div  rcx
    mov  [rel vtd_dd_detect_ms], eax
.reclaim:
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_reclaim_internal
    test eax, eax
    jz   .stranded
    call vtd_dd_budget_left
    test eax, eax
    jz   .exhausted
    mov  byte [rel vtd_domain_l2_active], 1   ; keep the capstone bound
    mov  byte [rel vtd_dd_state], VTD_DD_RECOVERING
    call tsc_now
    mov  rdx, [rel tsc_khz]
    imul rdx, VTD_DD_BACKOFF_MS
    add  rax, rdx
    mov  [rel vtd_dd_restart_due], rax
    xor  edi, edi
    call virtio_domain_service_health          ; degraded during the outage
    jmp  .out
.exhausted:
    mov  byte [rel vtd_dd_state], VTD_DD_EXHAUSTED
    jmp  .out
.stranded:
    mov  byte [rel vtd_dd_state], VTD_DD_STRANDED
    call tsc_now
    mov  [rel vtd_deadman_tsc], rax            ; retry custody one lease later
    xor  edi, edi
    call virtio_domain_service_health
.out:
    pop  rbx
    ret

; Called from vtd_net_task before it looks for work. A RECOVERING domain whose
; backoff has elapsed relaunches as a fresh generation through the ordinary
; assign -> proof path (the isolation precondition runs again).
vtd_dd_supervise:
    cmp  byte [rel vtd_dd_state], VTD_DD_RECOVERING
    jne  .ret
    cmp  byte [rel vtd_owner_guest], 0
    jne  .ret
    cmp  byte [rel vtd_net_task_active], 0
    jne  .ret
    call tsc_now
    cmp  rax, [rel vtd_dd_restart_due]
    jb   .ret
    call vtd_dd_budget_left
    test eax, eax
    jz   .exhausted
    call tsc_now
    movzx ecx, byte [rel vtd_dd_ring_pos]
    lea  rdx, [rel vtd_dd_ring]
    mov  [rdx + rcx*8], rax
    inc  ecx
    cmp  ecx, VTD_DD_BUDGET
    jb   .pos
    xor  ecx, ecx
.pos:
    mov  [rel vtd_dd_ring_pos], cl
    inc  dword [rel vtd_dd_restarts]
    call vtd_net_reset_session
    mov  byte [rel vtd_domain_l2_active], 1
    mov  byte [rel vtd_network_mode], 1
    mov  byte [rel vtd_dd_state], VTD_DD_RESTARTING
    mov  byte [rel vtd_net_start_pending], 1
    ret
.exhausted:
    mov  byte [rel vtd_dd_state], VTD_DD_EXHAUSTED
    mov  byte [rel vtd_domain_l2_active], 0
.ret:
    ret

; The DOMAINNET bridge proof passed: this generation serves, and the lease
; replaces the boot budget.
vtd_dd_on_proof_ok:
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .ret                            ; DDOM NET proof runs are not a service
    inc  dword [rel vtd_dd_gen]
    call tsc_now
    mov  [rel vtd_dd_renew_tsc], rax
    mov  [rel vtd_deadman_tsc], rax
    mov  qword [rel vtd_dd_probe_tsc], 0
    cmp  byte [rel vtd_dd_state], VTD_DD_RESTARTING
    jne  .serving
    mov  rdx, [rel vtd_dd_detect_tsc]
    test rdx, rdx
    jz   .serving
    sub  rax, rdx
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .serving
    xor  edx, edx
    div  rcx
    mov  [rel vtd_dd_restore_ms], eax
.serving:
    mov  dword [rel vtd_deadman_limit_ms], VTD_DD_LEASE_MS
    call virtio_domain_guest_progress
    mov  [rel vtd_dd_progress], rax
    mov  byte [rel vtd_dd_state], VTD_DD_SERVING
    mov  edi, 1
    call virtio_domain_service_health
.ret:
    ret

; A fresh standing service (DOMAINNET start): zero the restart history.
vtd_dd_reset:
    mov  byte [rel vtd_dd_state], VTD_DD_IDLE
    mov  byte [rel vtd_dd_cause], VTD_DD_CAUSE_NONE
    mov  byte [rel vtd_dd_ring_pos], 0
    mov  byte [rel vtd_dd_fault_kind], 0
    xor  eax, eax
    mov  [rel vtd_dd_gen], eax
    mov  [rel vtd_dd_restarts], eax
    mov  [rel vtd_dd_failures], eax
    mov  [rel vtd_dd_detect_ms], eax
    mov  [rel vtd_dd_restore_ms], eax
    mov  [rel vtd_dd_probes], eax
    mov  [rel vtd_dd_faults], eax
    mov  [rel vtd_dd_ring], rax
    mov  [rel vtd_dd_ring + 8], rax
    mov  [rel vtd_dd_ring + 16], rax
    mov  [rel vtd_dd_detect_tsc], rax
    mov  [rel vtd_dd_fault_tsc], rax
    mov  [rel vtd_dd_renew_tsc], rax
    mov  [rel vtd_dd_probe_tsc], rax
    mov  [rel vtd_dd_restart_due], rax
    mov  [rel vtd_dd_renewals], rax
    ret

; Sample fresh r8169 causes without consuming ENTRY_INTR. The level tracker
; prunes guest-ACKed bits while a new edge enters a sticky pending word.
vtd_rtl_prepare_irq:
    mov  rdx, [rel vtd_secondary_bar2_mmio]
    test rdx, rdx
    jz   .pending
    movzx r8d, word [rdx + 0x3E]
    mov  r10d, r8d
    and  r10d, 0x002F                     ; raw live causes, excluding RDU
    cmp  byte [rel vtd_net_phy_edge_state], 1
    jne  .linkchg_sampled
    test r10d, 0x0020                     ; genuine MAC LinkChg after BMCR edge
    jz   .linkchg_sampled
    mov  byte [rel vtd_net_phy_edge_linkchg_seen], 1
.linkchg_sampled:
    movzx eax, word [rdx + 0x3C]
    and  r8d, eax                          ; currently deliverable edges
    and  r8d, 0x002F
    movzx ecx, word [rel vtd_net_irq_level]
    ; r8169 masks IMR while servicing. Only raw IntrStatus ACKs may clear the
    ; level, otherwise unmasking recreates the IRQ storm that starves NAPI.
    and  ecx, r10d
    mov  word [rel vtd_net_irq_level], cx
    mov  eax, r8d
    not  ecx
    and  eax, ecx                          ; fresh edges only
    or   word [rel vtd_net_irq_pending], ax
.pending:
    xor  eax, eax
    cmp  word [rel vtd_net_irq_pending], 0
    setne al
    ret

; Deliver one retained RTL edge only after the general IRQ0 path declined.
vtd_rtl_try_inject_pending:
    movzx r9d, word [rel vtd_net_irq_pending]
    test r9d, r9d
    jz   .idle
    inc  dword [rel vtd_net_irq_attempts]
    mov  edi, VTD_NET_GUEST_IRQ
    call hv_pic_try_inject                  ; RCQ-18 S0: queues the edge, else EDX = why
    test eax, eax
    jz   .rejected
    call vtd_net_intr_window_disarm
    cmp  byte [rel vtd_net_phy_edge_state], 1
    jne  .linkchg_accounted
    test r9d, 0x0020
    jz   .linkchg_accounted
    mov  byte [rel vtd_net_phy_edge_linkchg_injected], 1
.linkchg_accounted:
    or   word [rel vtd_net_irq_level], r9w
    mov  word [rel vtd_net_irq_pending], 0
    inc  dword [rel vtd_net_irq_injections]
    mov  eax, 1
    ret
.rejected:
    cmp  edx, HV_PICINJ_NOVEC
    jb   .reject_entry
    je   .reject_vec
    cmp  edx, HV_PICINJ_IF
    jb   .reject_mask
    je   .reject_if0
.reject_shadow:
    inc  dword [rel vtd_net_irq_reject_shadow]
    call vtd_net_intr_window_arm
    jmp  .no
.reject_entry:
    inc  dword [rel vtd_net_irq_reject_entry]
    jmp  .reject_no_window
.reject_vec:
    inc  dword [rel vtd_net_irq_reject_vec]
    jmp  .reject_no_window
.reject_mask:
    inc  dword [rel vtd_net_irq_reject_mask]
    jmp  .reject_no_window
.reject_if0:
    inc  dword [rel vtd_net_irq_reject_if0]
    call vtd_net_intr_window_arm
    jmp  .no
.reject_no_window:
    call vtd_net_intr_window_disarm
    jmp  .no
.idle:
    call vtd_net_intr_window_disarm
.no:
    xor  eax, eax
    ret

; Port Classic gl_iw_arm/gl_iw_disarm exactly at the hv_ops seam. The
; retained RTL edge is the work item; this only asks the backend for the first
; precise boundary at which an external interrupt may legally be injected.
vtd_net_intr_window_arm:
    cmp  byte [rel vtd_net_intr_window_armed], 1
    je   .done
    mov  edi, 1
    call hv_intr_window
    mov  byte [rel vtd_net_intr_window_armed], 1
    inc  dword [rel vtd_net_intr_window_arms]
.done:
    ret

vtd_net_intr_window_disarm:
    cmp  byte [rel vtd_net_intr_window_armed], 0
    je   .done
    xor  edi, edi
    call hv_intr_window
    mov  byte [rel vtd_net_intr_window_armed], 0
.done:
    ret

; VM-exit reason 7. Disarm before normal resume arbitration; leaving the bit
; set would create an immediate-exit storm and starve both guest and host.
vtd_guest_dataplane_intr_window_exit:
    cmp  byte [rel vtd_net_intr_window_armed], 1
    jne  .done
    inc  dword [rel vtd_net_intr_window_exits]
    call vtd_net_intr_window_disarm
.done:
    ret

; RDI=fault GPA. Recover only a measured page of the assigned secondary
; Realtek. The resolver accepts either the immutable saved BAR or a bounded
; alias proven by the current generation's vPCI write ledger; both map to the
; immutable saved HPA. Unknown GPAs remain terminal.
vtd_guest_bar_ept_service:
    cmp  byte [rel vtd_network_mode], 1
    jne  .not_ours
    cmp  byte [rel vtd_owner_guest], 1
    jne  .not_ours
    call vtd_guest_bar_resolve_page
    test eax, eax
    jz   .not_ours
    mov  rdi, [rel vtd_ept_root]
    call vtd_ept_map_bar_page
    cmp  eax, VTD_EPT_MAP_LEAF_WRITTEN
    je   .invalidate
    cmp  eax, VTD_EPT_MAP_LEAF_ALREADY_EXACT
    jne  .commit_reject
.invalidate:
    call hv_slat_flush                    ; RCQ-18 S1b (F2): the vendor's flush, never a raw INVEPT
    test eax, eax
    jz   .commit_reject
    call vtd_trace_commit_map
    mov  eax, 1
    ret
.commit_reject:
    call vtd_trace_commit_map
.not_ours:
    xor  eax, eax
    ret

; AL=one byte from the real guest virtio-console stream. Sticky,
; generation-local latches survive later DHCP chatter.
vtd_guest_console_byte:
    cmp  byte [rel vtd_network_mode], 1
    jne  .inactive
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  bl, al

    ; Transparent-L2 boots the existing /bin/sh directly, then discovers the
    ; passed interface from live sysfs before any guest L3 configuration. A
    ; negative receipt carries the attempted interface plus a typed reason.
    ; It never opens the bridge gate, but it is retained and retried instead of
    ; leaving console-queue acceptance permanently latched as completion.
    movzx ecx, byte [rel vtd_domain_iface_fail_parse]
    test ecx, ecx
    jz   .domain_iface_ok_parse
    cmp  ecx, 1
    jne  .domain_iface_fail_reason
    cmp  bl, ' '
    je   .domain_iface_fail_name_done
    cmp  bl, 0x21
    jb   .domain_iface_fail_bad
    cmp  bl, 0x7E
    ja   .domain_iface_fail_bad
    inc  byte [rel vtd_domain_iface_fail_iface_len]
    cmp  byte [rel vtd_domain_iface_fail_iface_len], 15
    ja   .domain_iface_fail_bad
    jmp  .carrier_parse
.domain_iface_fail_name_done:
    cmp  byte [rel vtd_domain_iface_fail_iface_len], 0
    je   .domain_iface_fail_bad
    mov  byte [rel vtd_domain_iface_fail_parse], 2
    jmp  .carrier_parse
.domain_iface_fail_reason:
    cmp  ecx, 2
    jne  .domain_iface_fail_lf
    cmp  bl, 13
    je   .domain_iface_fail_cr
    cmp  bl, 10
    je   .domain_iface_fail_complete
    cmp  bl, 0x21
    jb   .domain_iface_fail_bad
    cmp  bl, 0x7E
    ja   .domain_iface_fail_bad
    movzx ecx, byte [rel vtd_domain_iface_fail_reason_len]
    cmp  ecx, 15
    jae  .domain_iface_fail_bad
    lea  rdi, [rel vtd_domain_iface_fail_reason]
    mov  [rdi + rcx], bl
    inc  ecx
    mov  [rel vtd_domain_iface_fail_reason_len], cl
    jmp  .carrier_parse
.domain_iface_fail_cr:
    mov  byte [rel vtd_domain_iface_fail_parse], 3
    jmp  .carrier_parse
.domain_iface_fail_lf:
    cmp  ecx, 3
    jne  .domain_iface_fail_bad
    cmp  bl, 10
    jne  .domain_iface_fail_bad
.domain_iface_fail_complete:
    movzx ecx, byte [rel vtd_domain_iface_fail_reason_len]
    test ecx, ecx
    jz   .domain_iface_fail_bad
    lea  rdi, [rel vtd_domain_iface_fail_reason]
    mov  byte [rdi + rcx], 0
    lea  rsi, [rel str_vtd_domain_iface_not_found]
    call vtd_string_equal
    test eax, eax
    jnz  .domain_iface_fail_not_found
    lea  rdi, [rel vtd_domain_iface_fail_reason]
    lea  rsi, [rel str_vtd_domain_iface_link_up]
    call vtd_string_equal
    test eax, eax
    jnz  .domain_iface_fail_link_up
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_MALFORMED
    jmp  .domain_iface_fail_reset
.domain_iface_fail_not_found:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_NOT_FOUND
    jmp  .domain_iface_fail_reset
.domain_iface_fail_link_up:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_LINK_UP_FAILED
.domain_iface_fail_reset:
    mov  byte [rel vtd_domain_iface_fail_parse], 0
    mov  byte [rel vtd_domain_iface_fail_iface_len], 0
    mov  byte [rel vtd_domain_iface_fail_reason_len], 0
    mov  byte [rel vtd_domain_iface_ready], 0
    mov  byte [rel vtd_net_iface], 0
    jmp  .carrier_parse
.domain_iface_fail_bad:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_MALFORMED
    mov  byte [rel vtd_domain_iface_fail_parse], 0
    mov  byte [rel vtd_domain_iface_fail_iface_len], 0
    mov  byte [rel vtd_domain_iface_fail_reason_len], 0
    mov  byte [rel vtd_domain_iface_ready], 0
    mov  byte [rel vtd_net_iface], 0
    jmp  .carrier_parse

    ; A positive receipt is accepted only as
    ; `PAOS_DOMAIN_IFACE_OK <ifname> r8169`, with a bounded Linux IFNAMSIZ
    ; name and an exact driver suffix. The command assembles its prefix from a
    ; variable, so tty input echo cannot satisfy this parser.
.domain_iface_ok_parse:
    movzx ecx, byte [rel vtd_domain_iface_parse]
    test ecx, ecx
    jz   .carrier_parse
    cmp  ecx, 1
    jne  .domain_iface_driver
    cmp  bl, ' '
    je   .domain_iface_name_done
    cmp  bl, 0x21
    jb   .domain_iface_bad
    cmp  bl, 0x7E
    ja   .domain_iface_bad
    movzx ecx, byte [rel vtd_domain_iface_len]
    cmp  ecx, 15
    jae  .domain_iface_bad
    lea  rdi, [rel vtd_net_iface]
    mov  [rdi + rcx], bl
    inc  ecx
    mov  [rel vtd_domain_iface_len], cl
    jmp  .carrier_parse
.domain_iface_name_done:
    movzx ecx, byte [rel vtd_domain_iface_len]
    test ecx, ecx
    jz   .domain_iface_bad
    lea  rdi, [rel vtd_net_iface]
    mov  byte [rdi + rcx], 0
    mov  byte [rel vtd_domain_iface_parse], 2
    jmp  .carrier_parse
.domain_iface_driver:
    cmp  ecx, 7
    jae  .domain_iface_line_end
    sub  ecx, 2
    lea  rdi, [rel str_vtd_net_r8169]
    cmp  bl, [rdi + rcx]
    jne  .domain_iface_bad
    inc  byte [rel vtd_domain_iface_parse]
    jmp  .carrier_parse
.domain_iface_line_end:
    cmp  ecx, 7
    jne  .domain_iface_wait_lf
    cmp  bl, 13
    je   .domain_iface_cr
    cmp  bl, 10
    je   .domain_iface_complete
    jmp  .domain_iface_bad
.domain_iface_cr:
    mov  byte [rel vtd_domain_iface_parse], 8
    jmp  .carrier_parse
.domain_iface_wait_lf:
    cmp  ecx, 8
    jne  .domain_iface_bad
    cmp  bl, 10
    jne  .domain_iface_bad
.domain_iface_complete:
    mov  byte [rel vtd_domain_iface_parse], 0
    mov  byte [rel vtd_domain_iface_ready], 1
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_READY
    mov  byte [rel vtd_net_driver_r8169], 1
    mov  byte [rel vtd_guest_vendor_seen], 1
    jmp  .carrier_parse
.domain_iface_bad:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_MALFORMED
    mov  byte [rel vtd_domain_iface_parse], 0
    mov  byte [rel vtd_domain_iface_len], 0
    mov  byte [rel vtd_domain_iface_ready], 0
    mov  byte [rel vtd_net_iface], 0

    ; A carrier sample is admissible only after this generation successfully
    ; dispatched the dedicated post-DHCP probe. Parse the whole line before
    ; changing the canonical carrier latch: exact expected interface, exactly
    ; one value byte, then line end. Wrong/malformed samples leave the probe
    ; pending so a later valid line can still recover from console chatter.
.carrier_parse:
    movzx ecx, byte [rel vtd_net_carrier_now_parse]
    test ecx, ecx
    jz   .lease_parse
    cmp  ecx, 1
    jne  .carrier_now_value
    cmp  bl, ' '
    je   .carrier_now_iface_done
    cmp  bl, 0x21
    jb   .carrier_now_bad
    cmp  bl, 0x7E
    ja   .carrier_now_bad
    movzx ecx, byte [rel vtd_net_carrier_now_iface_len]
    cmp  ecx, 15
    jae  .carrier_now_bad
    lea  rdi, [rel vtd_net_carrier_now_iface]
    mov  [rdi + rcx], bl
    inc  ecx
    mov  [rel vtd_net_carrier_now_iface_len], cl
    jmp  .lease_parse
.carrier_now_iface_done:
    movzx ecx, byte [rel vtd_net_carrier_now_iface_len]
    test ecx, ecx
    jz   .carrier_now_bad
    lea  rdi, [rel vtd_net_carrier_now_iface]
    mov  byte [rdi + rcx], 0
    mov  byte [rel vtd_net_carrier_now_parse], 2
    jmp  .lease_parse
.carrier_now_value:
    cmp  ecx, 2
    jne  .carrier_now_line_end
    cmp  bl, '0'
    je   .carrier_now_zero
    cmp  bl, '1'
    jne  .carrier_now_bad
    mov  byte [rel vtd_net_carrier_now_value], 1
    jmp  .carrier_now_value_saved
.carrier_now_zero:
    mov  byte [rel vtd_net_carrier_now_value], 0
.carrier_now_value_saved:
    mov  byte [rel vtd_net_carrier_now_parse], 3
    jmp  .lease_parse
.carrier_now_line_end:
    cmp  ecx, 3
    jne  .carrier_now_lf
    cmp  bl, 13
    je   .carrier_now_wait_lf
    cmp  bl, 10
    je   .carrier_now_complete
    jmp  .carrier_now_bad
.carrier_now_wait_lf:
    mov  byte [rel vtd_net_carrier_now_parse], 4
    jmp  .lease_parse
.carrier_now_lf:
    cmp  ecx, 4
    jne  .carrier_now_bad
    cmp  bl, 10
    jne  .carrier_now_bad
.carrier_now_complete:
    mov  byte [rel vtd_net_carrier_now_parse], 0
    lea  rdi, [rel vtd_net_carrier_now_iface]
    lea  rsi, [rel vtd_net_iface]
    call vtd_string_equal
    test eax, eax
    jz   .carrier_now_wrong_iface
    mov  byte [rel vtd_net_carrier_sample_seen], 1
    mov  byte [rel vtd_net_carrier_probe_pending], 0
    cmp  byte [rel vtd_net_carrier_now_value], 1
    jne  .lease_parse
    mov  byte [rel vtd_net_carrier], 1
    cmp  byte [rel vtd_net_marker_carrier], 1
    je   .lease_parse
    mov  byte [rel vtd_net_marker_carrier], 1
    lea  rdi, [rel str_vtd_net_carrier_marker]
    call serial_string
    jmp  .lease_parse
.carrier_now_wrong_iface:
    mov  byte [rel vtd_net_carrier_now_iface_len], 0
    mov  byte [rel vtd_net_carrier_now_iface], 0
    jmp  .lease_parse
.carrier_now_bad:
    mov  byte [rel vtd_net_carrier_now_parse], 0
    mov  byte [rel vtd_net_carrier_now_iface_len], 0
    mov  byte [rel vtd_net_carrier_now_iface], 0

    ; Parse and retain both fields from
    ; `PAOS_DDOM_LINK_UP <ifname> <IPv4>`. The interface becomes the exact
    ; expected r8169 identity for the later direct carrier receipt.
.lease_parse:
    movzx ecx, byte [rel vtd_net_lease_parse]
    test ecx, ecx
    jz   .tokens
    cmp  ecx, 1
    jne  .lease_ip_start
    cmp  bl, ' '
    je   .lease_iface_done
    cmp  bl, 0x21
    jb   .lease_bad
    cmp  bl, 0x7E
    ja   .lease_bad
    movzx ecx, byte [rel vtd_net_lease_iface_len]
    cmp  ecx, 15
    jae  .lease_bad
    lea  rdi, [rel vtd_net_iface]
    mov  [rdi + rcx], bl
    inc  ecx
    mov  [rel vtd_net_lease_iface_len], cl
    jmp  .tokens
.lease_iface_done:
    movzx ecx, byte [rel vtd_net_lease_iface_len]
    test ecx, ecx
    jz   .lease_bad
    lea  rdi, [rel vtd_net_iface]
    mov  byte [rdi + rcx], 0
    mov  byte [rel vtd_net_lease_parse], 2
    jmp  .tokens
.lease_ip_start:
    cmp  ecx, 2
    jne  .lease_ip
    cmp  bl, ' '
    je   .tokens
    cmp  bl, '0'
    jb   .lease_bad
    cmp  bl, '9'
    ja   .lease_bad
    mov  byte [rel vtd_net_lease_parse], 3
.lease_ip:
    cmp  bl, '.'
    je   .lease_store
    cmp  bl, '0'
    jb   .lease_finish
    cmp  bl, '9'
    ja   .lease_finish
.lease_store:
    movzx ecx, byte [rel vtd_net_lease_len]
    cmp  ecx, 15
    jae  .lease_bad
    lea  rdi, [rel vtd_net_lease]
    mov  [rdi + rcx], bl
    inc  ecx
    mov  [rel vtd_net_lease_len], cl
    jmp  .tokens
.lease_finish:
    movzx ecx, byte [rel vtd_net_lease_len]
    cmp  ecx, 7
    jb   .lease_bad
    lea  rdi, [rel vtd_net_lease]
    mov  byte [rdi + rcx], 0
    mov  byte [rel vtd_net_lease_parse], 0
    cmp  byte [rel vtd_net_marker_dhcp], 1
    je   .tokens
    mov  byte [rel vtd_net_marker_dhcp], 1
    lea  rdi, [rel str_vtd_net_dhcp_marker]
    call serial_string
    jmp  .tokens
.lease_bad:
    mov  byte [rel vtd_net_lease_parse], 0
    mov  byte [rel vtd_net_lease_len], 0
    mov  byte [rel vtd_net_lease_iface_len], 0
    mov  byte [rel vtd_net_lease], 0
    mov  byte [rel vtd_net_iface], 0

.tokens:
    mov  al, bl
    lea  rdi, [rel str_vtd_domain_shell_ready]
    lea  rsi, [rel vtd_net_match_domain_shell]
    call vtd_stream_match
    test eax, eax
    jz   .domain_iface
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .domain_iface
    mov  byte [rel vtd_domain_shell_ready], 1
.domain_iface:
    mov  al, bl
    lea  rdi, [rel str_vtd_domain_iface_ok]
    lea  rsi, [rel vtd_net_match_domain_iface]
    call vtd_stream_match
    test eax, eax
    jz   .domain_iface_fail
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .uplink
    cmp  byte [rel vtd_domain_shell_ready], 1
    jne  .uplink
    mov  byte [rel vtd_domain_iface_parse], 1
    mov  byte [rel vtd_domain_iface_len], 0
    mov  byte [rel vtd_domain_iface_ready], 0
    mov  byte [rel vtd_net_iface], 0
.domain_iface_fail:
    mov  al, bl
    lea  rdi, [rel str_vtd_domain_iface_fail]
    lea  rsi, [rel vtd_net_match_domain_iface_fail]
    call vtd_stream_match
    test eax, eax
    jz   .uplink
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .uplink
    cmp  byte [rel vtd_domain_shell_ready], 1
    jne  .uplink
    mov  byte [rel vtd_domain_iface_fail_parse], 1
    mov  byte [rel vtd_domain_iface_fail_iface_len], 0
    mov  byte [rel vtd_domain_iface_fail_reason_len], 0
    mov  byte [rel vtd_domain_iface_ready], 0
    mov  byte [rel vtd_net_iface], 0
.uplink:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_uplink]
    lea  rsi, [rel vtd_net_match_uplink]
    call vtd_stream_match
    test eax, eax
    jz   .driver
    mov  byte [rel vtd_net_uplink_line], 1
.driver:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_r8169]
    lea  rsi, [rel vtd_net_match_driver]
    call vtd_stream_match
    test eax, eax
    jz   .cwait_enter
    cmp  byte [rel vtd_net_uplink_line], 1
    jne  .cwait_enter
    mov  byte [rel vtd_net_driver_r8169], 1
    mov  byte [rel vtd_guest_vendor_seen], 1
.cwait_enter:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_cwait_enter]
    lea  rsi, [rel vtd_net_match_cwait_enter]
    call vtd_stream_match
    test eax, eax
    jz   .cwait_tick
    mov  byte [rel vtd_net_cwait_enter_seen], 1
.cwait_tick:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_cwait_tick]
    lea  rsi, [rel vtd_net_match_cwait_tick]
    call vtd_stream_match
    test eax, eax
    jz   .cwait_carrier
    mov  byte [rel vtd_net_cwait_tick_seen], 1
.cwait_carrier:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_cwait_carr]
    lea  rsi, [rel vtd_net_match_cwait_carr]
    call vtd_stream_match
    test eax, eax
    jz   .carrier_line
    mov  byte [rel vtd_net_cwait_carr_seen], 1
.carrier_line:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_carrier_stable]
    lea  rsi, [rel vtd_net_match_carrier]
    call vtd_stream_match
    test eax, eax
    jz   .carrier_value
    mov  byte [rel vtd_net_carrier_line], 1
.carrier_value:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_stable_five]
    lea  rsi, [rel vtd_net_match_stable]
    call vtd_stream_match
    test eax, eax
    jz   .carrier_timeout
    cmp  byte [rel vtd_net_carrier_line], 1
    jne  .carrier_timeout
    ; Diagnostic only: this is sampled before DHCP and can be stale by the
    ; physical proof. Only an exact CARRIER_NOW receipt may set carrier=1.
    mov  byte [rel vtd_net_carrier_early], 1
.carrier_timeout:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_carrier_timeout]
    lea  rsi, [rel vtd_net_match_carrier_timeout]
    call vtd_stream_match
    test eax, eax
    jz   .link_up
    mov  byte [rel vtd_net_carrier_timeout_seen], 1
.link_up:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_link_up]
    lea  rsi, [rel vtd_net_match_link_up]
    call vtd_stream_match
    test eax, eax
    jz   .carrier_now
    mov  byte [rel vtd_net_lease_parse], 1
    mov  byte [rel vtd_net_lease_len], 0
    mov  byte [rel vtd_net_lease_iface_len], 0
    mov  byte [rel vtd_net_lease], 0
    mov  byte [rel vtd_net_iface], 0
.carrier_now:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_carrier_now]
    lea  rsi, [rel vtd_net_match_carrier_now]
    call vtd_stream_match
    test eax, eax
    jz   .arp
    cmp  byte [rel vtd_net_carrier_probe_pending], 1
    jne  .arp
    cmp  byte [rel vtd_net_driver_r8169], 1
    jne  .arp
    cmp  byte [rel vtd_domain_l2_active], 1
    je   .carrier_now_begin
    cmp  byte [rel vtd_net_lease], 0
    je   .arp
.carrier_now_begin:
    mov  byte [rel vtd_net_carrier_now_parse], 1
    mov  byte [rel vtd_net_carrier_now_iface_len], 0
    mov  byte [rel vtd_net_carrier_now_value], 0xFF
    mov  byte [rel vtd_net_carrier_now_iface], 0
.arp:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_arp_ok]
    lea  rsi, [rel vtd_net_match_arp]
    call vtd_stream_match
    test eax, eax
    jz   .sent
    mov  byte [rel vtd_net_gateway_arp], 1
.sent:
    mov  al, bl
    lea  rdi, [rel str_vtd_net_sent_ok]
    lea  rsi, [rel vtd_net_match_sent]
    call vtd_stream_match
    test eax, eax
    jz   .domain_bridge
    mov  byte [rel vtd_net_udp_sent], 1
    cmp  byte [rel vtd_net_marker_udp], 1
    je   .domain_bridge
    mov  byte [rel vtd_net_marker_udp], 1
    lea  rdi, [rel str_vtd_net_udp_marker]
    call serial_string
.domain_bridge:
    mov  al, bl
    lea  rdi, [rel str_vtd_domain_bridge_ok]
    lea  rsi, [rel vtd_net_match_domain_bridge]
    call vtd_stream_match
    test eax, eax
    jz   .newline
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .newline
    mov  byte [rel vtd_domain_bridge_ready], 1
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_READY
.newline:
    cmp  bl, 10
    jne  .out
    mov  byte [rel vtd_net_uplink_line], 0
    mov  byte [rel vtd_net_carrier_line], 0
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.inactive:
    ret

; AL=stream byte, RDI=NUL token, RSI=one-byte rolling match index.
vtd_stream_match:
    movzx ecx, byte [rsi]
    cmp  al, [rdi + rcx]
    jne  .restart
    inc  ecx
    cmp  byte [rdi + rcx], 0
    je   .matched
    mov  [rsi], cl
    xor  eax, eax
    ret
.restart:
    xor  ecx, ecx
    cmp  al, [rdi]
    jne  .store
    inc  ecx
.store:
    mov  [rsi], cl
    xor  eax, eax
    ret
.matched:
    mov  byte [rsi], 0
    mov  eax, 1
    ret

; RDI/RSI=NUL strings. EAX=1 only for byte-exact equality.
vtd_string_equal:
.loop:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .no
    test al, al
    jz   .yes
    inc  rdi
    inc  rsi
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Read-only PCI mechanism #1 projection used by the living Linux guest.
; EDX=port, R8D=VM-exit qualification. OUT value is guest RAX low dword.
; ---------------------------------------------------------------------------
vtd_vpci_out:
    cmp  byte [rel vtd_vpci_active], 1
    jne  .done
    cmp  edx, 0xCF8
    jne  .data
    mov  eax, [rel hv_linux_gpr]
    mov  [rel vtd_vpci_addr], eax
    ret
.data:
    cmp  edx, 0xCFC
    jb   .done
    cmp  edx, 0xCFF
    ja   .done
    test r8d, 0x10
    jnz  .done                            ; string OUTS: the data is guest memory, not RAX
    test dword [rel vtd_vpci_addr], 0x80000000
    jz   .done
    call vtd_vpci_offset
    test eax, eax
    js   .done
    mov  ecx, eax
    ; SEC-D1: qualification bits 2:0 = size-1 (0/1/3 = 1/2/4 bytes). Any other
    ; code, or an access crossing its dword ((offset&3) + size-1 > 3), writes
    ; nothing. That keeps every store inside vtd_secondary_cfg (offset <= 0xFF)
    ; and keeps BAR programming aligned.
    mov  r9d, r8d
    and  r9d, 7
    cmp  r9d, 2
    je   .done
    cmp  r9d, 3
    ja   .done
    mov  eax, ecx
    and  eax, 3
    add  eax, r9d
    cmp  eax, 3
    ja   .done
    cmp  ecx, 0x10
    jb   .write
    cmp  ecx, 0x27
    ja   .write
    mov  eax, [rel hv_linux_gpr]
    cmp  eax, 0xFFFFFFFF
    je   .bar_probe
    mov  r9d, r8d
    and  r9d, 7
    cmp  r9d, 3
    jne  .done                            ; BAR programming is dword-only
    mov  edx, eax
    mov  eax, ecx
    sub  eax, 0x10
    shr  eax, 2
    call vtd_vpci_bar_write
    ret
.bar_probe:
    mov  eax, ecx
    sub  eax, 0x10
    shr  eax, 2
    lea  rdi, [rel vtd_vpci_bar_probe]
    mov  byte [rdi + rax], 1
    ret
.write:
    lea  rdi, [rel vtd_secondary_cfg]
    add  rdi, rcx
    mov  eax, [rel hv_linux_gpr]
    mov  ecx, r8d
    and  ecx, 7
    cmp  ecx, 0
    je   .byte
    cmp  ecx, 1
    je   .word
    mov  [rdi], eax
    jmp  .forward
.byte:
    mov  [rdi], al
    jmp  .forward
.word:
    mov  [rdi], ax
.forward:
    cmp  byte [rel vtd_network_mode], 1
    jne  .done
    call vtd_vpci_forward_command
.done:
    ret

; Forward only IO/MEM/BME from Linux's shadow Command register. Physical INTx
; stays disabled because PaOS injects the guest's master-PIC IRQ6 itself.
vtd_vpci_forward_command:
    movzx edx, word [rel vtd_secondary_cfg + 4]
    and  edx, 7
    or   edx, 0x400
    mov  edi, [rel vtd_secondary_bdf]
    mov  esi, 4
    call pci_bdf_write
    inc  dword [rel vtd_net_command_writes]
    ret

; Return ECX as expected by vmx.asm's common PIO store path.
vtd_vpci_in:
    cmp  byte [rel vtd_vpci_active], 1
    jne  .ones
    cmp  edx, 0xCF8
    jne  .data
    mov  ecx, [rel vtd_vpci_addr]
    ret
.data:
    cmp  edx, 0xCFC
    jb   .ones
    cmp  edx, 0xCFF
    ja   .ones
    test dword [rel vtd_vpci_addr], 0x80000000
    jz   .ones
    ; Port Classic's proven minimal 00:00.0 host bridge. Linux's conf1 probe
    ; reads this before walking 00:01.0; returning all-ones here leaves the
    ; real 10ec snapshot unreachable even though CONFIG_ADDRESS itself works.
    mov  eax, [rel vtd_vpci_addr]
    mov  ecx, eax
    shr  ecx, 16
    and  ecx, 0xFF
    test ecx, ecx
    jnz  .ones                           ; only guest bus 0 exists
    mov  ecx, eax
    shr  ecx, 8
    and  ecx, 7
    test ecx, ecx
    jnz  .ones                           ; only function 0 exists
    mov  ecx, eax
    shr  ecx, 11
    and  ecx, 0x1F
    test ecx, ecx
    jz   .host_bridge
    call vtd_vpci_offset
    test eax, eax
    js   .ones
    mov  ecx, eax
    cmp  ecx, 0x10
    jb   .normal
    cmp  ecx, 0x27
    ja   .normal
    mov  eax, ecx
    sub  eax, 0x10
    shr  eax, 2
    lea  rdi, [rel vtd_vpci_bar_probe]
    cmp  byte [rdi + rax], 1
    jne  .normal
    mov  byte [rdi + rax], 0
    call vtd_vpci_bar_sizing_value
    ret
.normal:
    mov  eax, ecx                         ; restore config offset after BAR-index probe
    mov  esi, eax
    and  esi, 0xFC
    and  eax, 3
    shl  eax, 3
    mov  edx, eax
    cmp  esi, 0x10
    jb   .normal_cfg
    cmp  esi, 0x24
    ja   .normal_cfg
    sub  esi, 0x10
    ; Keep the physical snapshot guest-visible. Linux assignment writes remain
    ; virtual, while the generation ledger may authorize a bounded EPT alias
    ; back to this immutable physical aperture.
    lea  rdi, [rel vtd_secondary_cfg + 0x10]
    mov  eax, [rdi + rsi]
    jmp  .normal_shift
.normal_cfg:
    lea  rdi, [rel vtd_secondary_cfg]
    mov  eax, [rdi + rsi]
    cmp  byte [rel vtd_network_mode], 1
    jne  .identity
    cmp  esi, 0x3C
    jne  .identity
    and  eax, 0xFFFF0000
    or   eax, (1 << 8) | VTD_NET_GUEST_IRQ ; IRQ6, INTA
.identity:
    test esi, esi
    jnz  .normal_shift
    cmp  byte [rel vtd_vpci_identity_open], 1
    je   .normal_shift
    ; Keep the real vendor visible for enumeration but make the device ID
    ; non-matchable while built-in drivers initialize. The exact saved dword
    ; becomes visible only after the guest reaches /init.
    or   eax, 0xFFFF0000
.normal_shift:
    mov  ecx, edx
    shr  eax, cl
    mov  ecx, eax
    ret
.host_bridge:
    and  eax, 0xFC                       ; dword-aligned config register
    cmp  eax, 0x00
    jne  .host_bridge_class
    mov  eax, 0x71908086                 ; proven synthetic Intel host bridge
    jmp  .host_bridge_shift
.host_bridge_class:
    cmp  eax, 0x08
    jne  .host_bridge_zero
    mov  eax, 0x06000000                 ; class 06/00: host bridge, rev 0
    jmp  .host_bridge_shift
.host_bridge_zero:
    xor  eax, eax                        ; type-0 header, no BARs or caps
.host_bridge_shift:
    mov  ecx, edx
    sub  ecx, 0xCFC
    shl  ecx, 3
    shr  eax, cl
    mov  ecx, eax
    ret
.ones:
    mov  ecx, 0xFFFFFFFF
    ret

; Resolve a guest-programmed BAR alias from the bounded vPCI ledger.
; IN: RDI=fault GPA. OUT: EAX=1, RSI=guest page, RDX=immutable saved HPA page.
; The newest write for each BAR wins. A 64-bit BAR is eligible only after both
; halves have same-generation dword-write evidence, independent of write order.
; Overflow, stale generations, incomplete pairs, zero/unaligned bases, and
; unknown GPAs all fail closed.
vtd_guest_bar_trace_alias_resolve:
    cmp  byte [rel vtd_vpci_active], 1
    jne  .no
    cmp  byte [rel vtd_vpci_trace_overflow], 0
    jne  .no
    mov  eax, [rel vtd_vpci_trace_run_gen]
    test eax, eax
    jz   .no
    mov  ecx, [rel vtd_vpci_trace_count]
    test ecx, ecx
    jz   .no
    cmp  ecx, VTD_VPCI_TRACE_MAX
    ja   .no
    mov  qword [rel vtd_vpci_trace_current], 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push r8
    push r9
    push r10
    push r11
    mov  r15, rdi                         ; fault GPA
    mov  r12d, eax                        ; accepted run generation
    mov  r13d, ecx
    dec  r13d
    xor  ebx, ebx                         ; newest-entry-seen BAR bitmap
.scan:
    mov  eax, r13d
    imul rax, VTD_TRACE_ENTRY_BYTES
    lea  r14, [rel vtd_vpci_trace_entries]
    add  r14, rax
    cmp  dword [r14 + VTD_TRACE_GEN], r12d
    jne  .next
    movzx r8d, byte [r14 + VTD_TRACE_BAR]
    cmp  r8d, 5
    ja   .next
    mov  eax, 1
    mov  ecx, r8d
    shl  eax, cl
    test ebx, eax
    jnz  .next
    or   ebx, eax                         ; older aliases for this BAR are stale
    cmp  byte [r14 + VTD_TRACE_WIDTH], 4
    jne  .next

    ; Bind the trace's immutable HPA snapshot back to the live saved config.
    lea  r11, [rel vtd_secondary_cfg + 0x10]
    mov  r10d, [r14 + VTD_TRACE_SAVED_LOW]
    cmp  r10d, [r11 + r8*4]
    jne  .next
    test r10d, r10d
    jz   .next
    cmp  r10d, 0xFFFFFFFF
    je   .next
    test r10b, 1                          ; I/O BARs never enter EPT
    jnz  .next
    mov  ebp, r10d
    and  ebp, 6
    cmp  ebp, 6                           ; reserved memory type
    je   .next
    cmp  ebp, 4
    jne  .prove_writes
    cmp  r8d, 5
    jae  .next
    mov  eax, [r14 + VTD_TRACE_SAVED_HIGH]
    cmp  eax, [r11 + r8*4 + 4]
    jne  .next

.prove_writes:
    ; The entry contains the latest accumulated low/high values. Prove the
    ; required source writes exist in this same bounded generation.
    xor  r9d, r9d
    xor  ecx, ecx
    lea  rdx, [rel vtd_vpci_trace_entries]
.proof_scan:
    cmp  ecx, [rel vtd_vpci_trace_count]
    jae  .proof_done
    cmp  dword [rdx + VTD_TRACE_GEN], r12d
    jne  .proof_next
    cmp  byte [rdx + VTD_TRACE_BAR], r8b
    jne  .proof_next
    cmp  byte [rdx + VTD_TRACE_WIDTH], 4
    jne  .proof_next
    movzx eax, byte [rdx + VTD_TRACE_CFG_OFF]
    lea  edi, [r8*4 + 0x10]
    cmp  eax, edi
    jne  .proof_high
    or   r9d, 1
    jmp  .proof_next
.proof_high:
    cmp  ebp, 4
    jne  .proof_next
    add  edi, 4
    cmp  eax, edi
    jne  .proof_next
    or   r9d, 2
.proof_next:
    add  rdx, VTD_TRACE_ENTRY_BYTES
    inc  ecx
    jmp  .proof_scan
.proof_done:
    test r9d, 1
    jz   .next
    cmp  ebp, 4
    jne  .build_alias
    and  r9d, 3
    cmp  r9d, 3
    jne  .next

.build_alias:
    ; Canonical low type bits must still describe the saved BAR type.
    mov  eax, [r14 + VTD_TRACE_WRITE_LOW]
    mov  edx, eax
    xor  edx, r10d
    test edx, 0xF
    jnz  .next
    and  eax, 0xFFFFFFF0
    mov  esi, eax
    cmp  ebp, 4
    jne  .alias_ready
    mov  eax, [r14 + VTD_TRACE_WRITE_HIGH]
    shl  rax, 32
    or   rsi, rax
.alias_ready:
    test rsi, rsi
    jz   .next
    test rsi, 0xFFF
    jnz  .next
    mov  rdx, [r14 + VTD_TRACE_SAVED_HPA]
    test rdx, rdx
    jz   .next
    test rdx, 0xFFF
    jnz  .next
    lea  r11, [rel vtd_secondary_bar_size]
    mov  ebp, [r11 + r8*4]
    test ebp, ebp
    jz   .next
    cmp  ebp, VTD_BAR_MAP_MAX_BYTES
    jbe  .round_size
    mov  ebp, VTD_BAR_MAP_MAX_BYTES
.round_size:
    add  ebp, 0xFFF
    and  ebp, -4096
    mov  rax, r15
    sub  rax, rsi
    cmp  rax, rbp
    jae  .next
    and  rax, -4096
    add  rsi, rax                         ; faulting guest page
    add  rdx, rax                         ; same offset in saved physical BAR
    mov  [rel vtd_vpci_trace_current], r14
    mov  rdi, r14
    call vtd_trace_copy_entry_to_summary
    mov  eax, 1
    jmp  .out
.next:
    dec  r13d
    jns  .scan
    xor  eax, eax
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.no:
    mov  qword [rel vtd_vpci_trace_current], 0
    xor  eax, eax
    ret

; Resolve one faulting secondary-device BAR page.
; IN: RDI=fault GPA. OUT: EAX=1, RSI=guest page, RDX=physical page.
; Prefer the immutable identity aperture; otherwise require the trace-derived
; alias above. Both paths are bounded by the measured saved BAR size.
vtd_guest_bar_resolve_page:
    cmp  byte [rel vtd_vpci_active], 1
    jne  .no
    push rbx
    push r12
    push r14
    push r15
    push r8
    push r10
    push r11
    mov  r12, rdi
    lea  r14, [rel vtd_secondary_cfg + 0x10]
    lea  r11, [rel vtd_secondary_bar_size]
    xor  ebx, ebx
.bar:
    test ebx, ebx
    jz   .low
    mov  eax, [r14 + rbx*4 - 4]
    and  eax, 6
    cmp  eax, 4
    je   .next                           ; consumed 64-bit BAR high dword
.low:
    mov  eax, [r14 + rbx*4]
    test eax, eax
    jz   .next
    cmp  eax, 0xFFFFFFFF
    je   .next
    test al, 1                           ; port-I/O BARs cannot cause EPT exits
    jnz  .next
    mov  r10d, eax
    and  r10d, 6
    cmp  r10d, 6                         ; reserved memory BAR type
    je   .next
    mov  r8d, eax
    and  r8d, 0xFFFFFFF0                 ; saved physical base
    cmp  r10d, 4                         ; 64-bit memory BAR
    jne  .size
    cmp  ebx, 5
    jae  .next
    mov  eax, [r14 + rbx*4 + 4]
    shl  rax, 32
    or   r8, rax
.size:
    mov  r15d, [r11 + rbx*4]
    test r15d, r15d
    jz   .next
    cmp  r15d, VTD_BAR_MAP_MAX_BYTES
    jbe  .round
    mov  r15d, VTD_BAR_MAP_MAX_BYTES
.round:
    add  r15d, 0xFFF
    and  r15d, -4096
    test r8, r8
    jz   .next                           ; never resolve a BAR to physical zero
    mov  rax, r12
    sub  rax, r8
    cmp  rax, r15
    jae  .next
    and  rax, -4096
    lea  rsi, [r8 + rax]
    lea  rdx, [r8 + rax]
    jmp  .yes
.next:
    inc  ebx
    cmp  ebx, 6
    jb   .bar
    mov  rdi, r12
    call vtd_guest_bar_trace_alias_resolve
    jmp  .out
.yes:
    mov  eax, 1
.out:
    pop  r11
    pop  r10
    pop  r8
    pop  r15
    pop  r14
    pop  r12
    pop  rbx
    ret
.no:
    xor  eax, eax
    ret

; EAX=1 only when RDI lies in a measured assigned-RTL BAR aperture.
vtd_guest_gpa_is_secondary_bar:
    call vtd_guest_bar_resolve_page
    ret

; EAX=BAR dword index, EDX=guest write. Record the canonical virtual value
; without touching physical config. Readback stays at the saved layout, while
; the bounded ledger can authorize a guest-GPA alias to that immutable HPA.
vtd_vpci_bar_write:
    push rbx
    push r12
    mov  ebx, eax
    cmp  ebx, 5
    ja   .done
    lea  r12, [rel vtd_secondary_cfg + 0x10]
    test ebx, ebx
    jz   .low
    mov  eax, [r12 + rbx*4 - 4]
    and  eax, 6
    cmp  eax, 4
    je   .high
.low:
    mov  eax, [r12 + rbx*4]
    test al, 1
    jnz  .io
    and  edx, 0xFFFFFFF0
    and  eax, 0xF
    or   edx, eax
    jmp  .store_low
.io:
    and  edx, 0xFFFFFFFC
    and  eax, 3
    or   edx, eax
.store_low:
    mov  ecx, ebx                         ; actual written dword index
    mov  eax, ebx                         ; low BAR index
    call vtd_trace_bar_write
    mov  qword [rel vtd_vpci_trace_current], 0
    jmp  .done
.high:
    mov  ecx, ebx                         ; actual high dword index
    lea  eax, [ebx - 1]                   ; paired low BAR index
    call vtd_trace_bar_write
    mov  qword [rel vtd_vpci_trace_current], 0
.done:
    pop  r12
    pop  rbx
    ret

; Reset the bounded generation ledger. Overflow never wraps into old entries.
vtd_bar_trace_reset:
    lea  rdi, [rel vtd_vpci_trace_entries]
    xor  eax, eax
    mov  ecx, VTD_VPCI_TRACE_MAX * VTD_TRACE_ENTRY_BYTES / 8
    cld
    rep  stosq
    mov  [rel vtd_vpci_trace_current], rax
    mov  [rel vtd_vpci_shadow_gpa], rax
    mov  [rel vtd_vpci_saved_hpa], rax
    mov  [rel vtd_ept_map_gpa], rax
    mov  [rel vtd_ept_map_hpa], rax
    mov  [rel vtd_ept_leaf_addr], rax
    mov  [rel vtd_ept_leaf_value], rax
    mov  [rel vtd_ept_leaf_readback], rax
    mov  [rel vtd_vpci_trace_run_gen], eax
    mov  [rel vtd_vpci_trace_gen], eax
    mov  [rel vtd_vpci_trace_count], eax
    mov  [rel vtd_vpci_trace_ordinal], eax
    mov  [rel vtd_vpci_write_low], eax
    mov  [rel vtd_vpci_write_high], eax
    mov  [rel vtd_vpci_shadow_low], eax
    mov  [rel vtd_vpci_shadow_high], eax
    mov  [rel vtd_vpci_saved_low], eax
    mov  [rel vtd_vpci_saved_high], eax
    mov  [rel vtd_ept_map_attempts], eax
    mov  [rel vtd_ept_invept_error], eax
    lea  rdi, [rel vtd_vpci_last_write]
    mov  ecx, 6
    rep  stosd
    mov  [rel vtd_vpci_trace_overflow], al
    mov  [rel vtd_vpci_bar_index], al
    mov  [rel vtd_vpci_cfg_off], al
    mov  [rel vtd_vpci_pio_width], al
    mov  [rel vtd_ept_map_result], al
    mov  [rel vtd_ept_invept_attempted], al
    mov  [rel vtd_ept_invept_ok], al
    ret

; RDI=immutable trace entry. Copy it into the fixed TRACE projection.
vtd_trace_copy_entry_to_summary:
    mov  eax, [rdi + VTD_TRACE_GEN]
    mov  [rel vtd_vpci_trace_gen], eax
    mov  al, [rdi + VTD_TRACE_BAR]
    mov  [rel vtd_vpci_bar_index], al
    mov  al, [rdi + VTD_TRACE_CFG_OFF]
    mov  [rel vtd_vpci_cfg_off], al
    mov  al, [rdi + VTD_TRACE_WIDTH]
    mov  [rel vtd_vpci_pio_width], al
    mov  eax, [rdi + VTD_TRACE_WRITE_LOW]
    mov  [rel vtd_vpci_write_low], eax
    mov  eax, [rdi + VTD_TRACE_WRITE_HIGH]
    mov  [rel vtd_vpci_write_high], eax
    mov  eax, [rdi + VTD_TRACE_SHADOW_LOW]
    mov  [rel vtd_vpci_shadow_low], eax
    mov  eax, [rdi + VTD_TRACE_SHADOW_HIGH]
    mov  [rel vtd_vpci_shadow_high], eax
    mov  eax, [rdi + VTD_TRACE_SAVED_LOW]
    mov  [rel vtd_vpci_saved_low], eax
    mov  eax, [rdi + VTD_TRACE_SAVED_HIGH]
    mov  [rel vtd_vpci_saved_high], eax
    mov  rax, [rdi + VTD_TRACE_SHADOW_GPA]
    mov  [rel vtd_vpci_shadow_gpa], rax
    mov  rax, [rdi + VTD_TRACE_SAVED_HPA]
    mov  [rel vtd_vpci_saved_hpa], rax
    mov  al, [rdi + VTD_TRACE_MAP_RESULT]
    mov  [rel vtd_ept_map_result], al
    mov  rax, [rdi + VTD_TRACE_MAP_GPA]
    mov  [rel vtd_ept_map_gpa], rax
    mov  rax, [rdi + VTD_TRACE_MAP_HPA]
    mov  [rel vtd_ept_map_hpa], rax
    mov  rax, [rdi + VTD_TRACE_LEAF_ADDR]
    mov  [rel vtd_ept_leaf_addr], rax
    mov  rax, [rdi + VTD_TRACE_LEAF_VALUE]
    mov  [rel vtd_ept_leaf_value], rax
    mov  rax, [rdi + VTD_TRACE_LEAF_READBACK]
    mov  [rel vtd_ept_leaf_readback], rax
    mov  eax, [rdi + VTD_TRACE_INVEPT_ERROR]
    mov  [rel vtd_ept_invept_error], eax
    mov  al, [rdi + VTD_TRACE_INVEPT_ATTEMPTED]
    mov  [rel vtd_ept_invept_attempted], al
    mov  al, [rdi + VTD_TRACE_INVEPT_OK]
    mov  [rel vtd_ept_invept_ok], al
    movzx eax, word [rdi + VTD_TRACE_ORDINAL]
    mov  [rel vtd_vpci_trace_ordinal], eax
    ret

; EAX=low BAR index, ECX=actual dword index, EDX=canonical guest write.
vtd_trace_bar_write:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, eax
    mov  r13d, ecx
    mov  r14d, edx
    mov  eax, [rel vtd_vpci_trace_count]
    cmp  eax, VTD_VPCI_TRACE_MAX
    jae  .overflow
    mov  ebx, eax
    inc  eax
    mov  [rel vtd_vpci_trace_count], eax
    imul rbx, VTD_TRACE_ENTRY_BYTES
    lea  r15, [rel vtd_vpci_trace_entries]
    add  r15, rbx
    mov  eax, [rel vtd_vpci_trace_run_gen]
    mov  [r15 + VTD_TRACE_GEN], eax
    mov  eax, [rel vtd_vpci_trace_count]
    mov  [r15 + VTD_TRACE_ORDINAL], ax
    mov  [r15 + VTD_TRACE_BAR], r12b
    mov  eax, r13d
    shl  eax, 2
    add  eax, 0x10
    mov  [r15 + VTD_TRACE_CFG_OFF], al
    mov  byte [r15 + VTD_TRACE_WIDTH], 4
    lea  rbx, [rel vtd_vpci_last_write]
    mov  [rbx + r13*4], r14d
    mov  eax, [rbx + r12*4]
    mov  [r15 + VTD_TRACE_WRITE_LOW], eax
    xor  eax, eax
    cmp  r12d, 5
    jae  .writes_ready
    mov  eax, [rbx + r12*4 + 4]
.writes_ready:
    mov  [r15 + VTD_TRACE_WRITE_HIGH], eax
    lea  rbx, [rel vtd_vpci_guest_bar]
    mov  eax, [rbx + r12*4]
    mov  [r15 + VTD_TRACE_SHADOW_LOW], eax
    xor  edx, edx
    mov  ecx, eax
    and  ecx, 6
    cmp  ecx, 4
    jne  .shadow_ready
    cmp  r12d, 5
    jae  .shadow_ready
    mov  edx, [rbx + r12*4 + 4]
.shadow_ready:
    mov  [r15 + VTD_TRACE_SHADOW_HIGH], edx
    and  eax, 0xFFFFFFF0
    shl  rdx, 32
    or   rax, rdx
    mov  [r15 + VTD_TRACE_SHADOW_GPA], rax
    lea  rbx, [rel vtd_secondary_cfg + 0x10]
    mov  eax, [rbx + r12*4]
    mov  [r15 + VTD_TRACE_SAVED_LOW], eax
    xor  edx, edx
    mov  ecx, eax
    and  ecx, 6
    cmp  ecx, 4
    jne  .saved_ready
    cmp  r12d, 5
    jae  .saved_ready
    mov  edx, [rbx + r12*4 + 4]
.saved_ready:
    mov  [r15 + VTD_TRACE_SAVED_HIGH], edx
    and  eax, 0xFFFFFFF0
    shl  rdx, 32
    or   rax, rdx
    mov  [r15 + VTD_TRACE_SAVED_HPA], rax
    mov  [rel vtd_vpci_trace_current], r15
    mov  rdi, r15
    call vtd_trace_copy_entry_to_summary
    jmp  .done
.overflow:
    mov  byte [rel vtd_vpci_trace_overflow], 1
    mov  qword [rel vtd_vpci_trace_current], 0
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bind mapper/readback/invalidation to the write that immediately caused it.
vtd_trace_commit_map:
    push rdi
    mov  rdi, [rel vtd_vpci_trace_current]
    test rdi, rdi
    jz   .done
    movzx eax, byte [rel vtd_ept_map_result]
    mov  [rdi + VTD_TRACE_MAP_RESULT], eax
    mov  rax, [rel vtd_ept_map_gpa]
    mov  [rdi + VTD_TRACE_MAP_GPA], rax
    mov  rax, [rel vtd_ept_map_hpa]
    mov  [rdi + VTD_TRACE_MAP_HPA], rax
    mov  rax, [rel vtd_ept_leaf_addr]
    mov  [rdi + VTD_TRACE_LEAF_ADDR], rax
    mov  rax, [rel vtd_ept_leaf_value]
    mov  [rdi + VTD_TRACE_LEAF_VALUE], rax
    mov  rax, [rel vtd_ept_leaf_readback]
    mov  [rdi + VTD_TRACE_LEAF_READBACK], rax
    mov  eax, [rel vtd_ept_invept_error]
    mov  [rdi + VTD_TRACE_INVEPT_ERROR], eax
    mov  al, [rel vtd_ept_invept_attempted]
    mov  [rdi + VTD_TRACE_INVEPT_ATTEMPTED], al
    mov  al, [rel vtd_ept_invept_ok]
    mov  [rdi + VTD_TRACE_INVEPT_OK], al
    call vtd_trace_copy_entry_to_summary
    mov  qword [rel vtd_vpci_trace_current], 0
.done:
    pop  rdi
    ret

; RDI=terminal GPA. Prefer the newest same-generation entry containing it;
; otherwise retain the newest entry so a non-match remains explicit.
; EAX=1 only when the bounded ledger scan found a containing recorded range.
vtd_trace_select_for_ept:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, [rel vtd_vpci_trace_count]
    test r13d, r13d
    jz   .no_match
    xor  ebx, ebx
    xor  r15d, r15d
    lea  r14, [rel vtd_vpci_trace_entries]
.scan:
    cmp  ebx, r13d
    jae  .selected
    mov  eax, [r14 + VTD_TRACE_GEN]
    cmp  eax, [rel vtd_vpci_trace_run_gen]
    jne  .next
    mov  rcx, [r14 + VTD_TRACE_MAP_GPA]
    test rcx, rcx
    jz   .shadow
    mov  rax, r12
    sub  rax, rcx
    cmp  rax, 0x1000
    jb   .match
.shadow:
    mov  rcx, [r14 + VTD_TRACE_SHADOW_GPA]
    test rcx, rcx
    jz   .next
    mov  rax, r12
    sub  rax, rcx
    cmp  rax, 0x1000
    jb   .match
    jmp  .next
.match:
    mov  r15, r14
.next:
    add  r14, VTD_TRACE_ENTRY_BYTES
    inc  ebx
    jmp  .scan
.selected:
    test r15, r15
    jnz  .copy_match
    dec  r13d
    imul r13, VTD_TRACE_ENTRY_BYTES
    lea  r15, [rel vtd_vpci_trace_entries]
    add  r15, r13
    mov  rdi, r15
    call vtd_trace_copy_entry_to_summary
    xor  eax, eax
    jmp  .done
.copy_match:
    mov  rdi, r15
    call vtd_trace_copy_entry_to_summary
    mov  eax, 1
    jmp  .done
.no_match:
    xor  eax, eax
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EAX=BAR dword index -> ECX=measured sizing response.
vtd_vpci_bar_sizing_value:
    cmp  eax, 5
    ja   .ones
    mov  edx, eax
    test edx, edx
    jz   .low
    lea  rdi, [rel vtd_secondary_cfg + 0x10]
    mov  esi, edx
    dec  esi
    mov  ecx, [rdi + rsi*4]
    and  ecx, 6
    cmp  ecx, 4
    je   .ones
.low:
    lea  rdi, [rel vtd_secondary_bar_size]
    mov  ecx, [rdi + rdx*4]
    test ecx, ecx
    jz   .shadow
    dec  ecx
    not  ecx
    and  ecx, 0xFFFFFFF0
    lea  rdi, [rel vtd_secondary_cfg + 0x10]
    mov  esi, [rdi + rdx*4]
    and  esi, 0xF
    or   ecx, esi
    ret
.shadow:
    lea  rdi, [rel vtd_vpci_guest_bar]
    mov  ecx, [rdi + rdx*4]
    ret
.ones:
    mov  ecx, 0xFFFFFFFF
    ret

; Allocate one zeroed EPT table page from the bounded Linux reservation.
vtd_ept_take_page:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    movzx eax, byte [rel vtd_ept_pool_used]
    cmp  eax, VTD_EPT_POOL_PAGES
    jae  .none
    inc  byte [rel vtd_ept_pool_used]
    shl  rax, 12
    add  rax, [rel vtd_ept_pool_base]
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

; RDI=EPT PML4, RSI=guest GPA, RDX=physical BAR HPA. EAX returns exactly one
; closed VTD_EPT_MAP_* result and every successful leaf is read back.
vtd_ept_map_bar_page:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13, rdi
    mov  r15, rdx
    mov  r14, 0x000FFFFFFFFFF000
    inc  dword [rel vtd_ept_map_attempts]
    mov  [rel vtd_ept_map_gpa], r12
    mov  [rel vtd_ept_map_hpa], r15
    xor  eax, eax
    mov  [rel vtd_ept_leaf_addr], rax
    mov  [rel vtd_ept_leaf_value], rax
    mov  [rel vtd_ept_leaf_readback], rax
    mov  [rel vtd_ept_invept_error], eax
    mov  [rel vtd_ept_invept_attempted], al
    mov  [rel vtd_ept_invept_ok], al
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_INVALID_INPUT
    test r12, r12
    jz   .done
    test r15, r15
    jz   .done
    test r12, 0xFFF
    jnz  .done
    test r15, 0xFFF
    jnz  .done
    test r13, r13
    jnz  .root_present
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_NO_ROOT
    jmp  .done
.root_present:
    mov  rax, r12
    shr  rax, 39
    and  eax, 0x1FF
    mov  rcx, [r13 + rax*8]
    test cl, 7
    jnz  .pml4_present
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_PML4_ABSENT
    jmp  .done
.pml4_present:
    mov  rbx, rcx
    and  rbx, r14
    mov  rax, r12
    shr  rax, 30
    and  eax, 0x1FF
    lea  r13, [rbx + rax*8]
    mov  rcx, [r13]
    test cl, 7
    jnz  .have_pd
    call vtd_ept_take_page
    test rax, rax
    jnz  .pd_allocated
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_POOL_EXHAUSTED
    jmp  .done
.pd_allocated:
    push rax
    mov  edi, HV_SLAT_TABLE               ; RCQ-18 S2-3: the active backend's format
    call hv_slat_bits
    pop  rcx
    or   rcx, rax
    mov  [r13], rcx
.have_pd:
    test rcx, 0x80
    jz   .pd_table
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_LARGE_LEAF_CONFLICT
    jmp  .done
.pd_table:
    mov  rbx, rcx
    and  rbx, r14
    mov  rax, r12
    shr  rax, 21
    and  eax, 0x1FF
    lea  r13, [rbx + rax*8]
    mov  rcx, [r13]
    test cl, 7
    jnz  .have_pt
    call vtd_ept_take_page
    test rax, rax
    jnz  .pt_allocated
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_POOL_EXHAUSTED
    jmp  .done
.pt_allocated:
    push rax
    mov  edi, HV_SLAT_TABLE
    call hv_slat_bits
    pop  rcx
    or   rcx, rax
    mov  [r13], rcx
.have_pt:
    test rcx, 0x80
    jz   .pt_table
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_LARGE_LEAF_CONFLICT
    jmp  .done
.pt_table:
    mov  rbx, rcx
    and  rbx, r14
    mov  rax, r12
    shr  rax, 12
    and  eax, 0x1FF
    lea  r13, [rbx + rax*8]
    mov  edi, HV_SLAT_MMIO_4K             ; R|W, UC, !X (EPT 0x3; NPT adds U and NX)
    call hv_slat_bits
    mov  rcx, r15
    and  rcx, r14
    or   rcx, rax
    mov  rax, [r13]
    test rax, rax
    jz   .write
    cmp  rax, rcx
    je   .already_exact
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_LEAF_CONFLICT
    jmp  .done
.write:
    mov  [r13], rcx
    mfence
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_LEAF_WRITTEN
    jmp  .record_leaf
.already_exact:
    mov  byte [rel vtd_ept_map_result], VTD_EPT_MAP_LEAF_ALREADY_EXACT
.record_leaf:
    mov  [rel vtd_ept_leaf_addr], r13
    mov  [rel vtd_ept_leaf_value], rcx
    mov  rax, [r13]
    mov  [rel vtd_ept_leaf_readback], rax
.done:
    movzx eax, byte [rel vtd_ept_map_result]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Invalidate after a dynamic VM-exit-time leaf change. Prefer the narrower
; single-context form; Classic's proven Lenovo path uses the all-context form,
; so retain that architectural fallback when bit 25 is absent but bit 26 is
; present.
vtd_invept_current_ept:
    mov  byte [rel vtd_ept_invept_attempted], 1
    mov  byte [rel vtd_ept_invept_ok], 0
    mov  dword [rel vtd_ept_invept_error], 0
    mov  rdx, [rel hv_linux_eptp]
    test rdx, rdx
    jnz  .have_eptp
    mov  dword [rel vtd_ept_invept_error], 2
    ret
.have_eptp:
    mov  ecx, 0x48C
    rdmsr
    bt   eax, 20                          ; INVEPT supported
    jnc  .unsupported
    bt   eax, 25                          ; single-context supported
    jnc  .try_all_context
    mov  rdx, [rel hv_linux_eptp]
    lea  rax, [rel vtd_invept_desc]
    mov  [rax], rdx
    mov  qword [rax + 8], 0
    mov  ecx, 1
    jmp  .invalidate
.try_all_context:
    bt   eax, 26                          ; proven Lenovo all-context form
    jnc  .unsupported
    lea  rax, [rel vtd_invept_desc]
    mov  qword [rax], 0
    mov  qword [rax + 8], 0
    mov  ecx, 2
.invalidate:
    invept rcx, [rax]
    jc   .vmfail_invalid
    jz   .vmfail_valid
    mov  byte [rel vtd_ept_invept_ok], 1
    ret
.unsupported:
    mov  dword [rel vtd_ept_invept_error], 3
    ret
.vmfail_invalid:
    mov  dword [rel vtd_ept_invept_error], 4
    ret
.vmfail_valid:
    mov  edi, 0x4400
    vmread rax, rdi
    test eax, eax
    jnz  .store_error
    mov  eax, 5
.store_error:
    mov  [rel vtd_ept_invept_error], eax
    ret

; EAX=low BAR index. Identity-map the whole measured saved physical aperture,
; bounded exactly like Classic. I/O, absent, reserved, and consumed-high slots
; never receive EPT leaves.
vtd_map_fixed_bar:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebx, eax
    xor  r13d, r13d
    xor  r14d, r14d
    xor  ebp, ebp
    cmp  ebx, 5
    ja   .done
    cmp  byte [rel vtd_vpci_active], 1
    jne  .done
    lea  r12, [rel vtd_secondary_cfg + 0x10]
    test ebx, ebx
    jz   .low_slot
    mov  eax, [r12 + rbx*4 - 4]
    and  eax, 6
    cmp  eax, 4
    je   .done                            ; consumed high slot
.low_slot:
    mov  eax, [r12 + rbx*4]
    test eax, eax
    jz   .done
    cmp  eax, 0xFFFFFFFF
    je   .done
    test al, 1
    jnz  .done                            ; I/O BAR
    mov  edx, eax
    and  edx, 6
    cmp  edx, 6
    je   .done                            ; reserved memory type
    mov  r13d, eax
    and  r13d, 0xFFFFFFF0
    cmp  edx, 4
    jne  .base_ready
    cmp  ebx, 5
    jae  .done
    mov  eax, [r12 + rbx*4 + 4]
    shl  rax, 32
    or   r13, rax
.base_ready:
    mov  r14, r13                         ; fixed identity GPA=HPA
    lea  r15, [rel vtd_secondary_bar_size]
    mov  ebp, [r15 + rbx*4]
    test ebp, ebp
    jz   .done
    cmp  ebp, VTD_BAR_MAP_MAX_BYTES
    jbe  .round
    mov  ebp, VTD_BAR_MAP_MAX_BYTES
.round:
    add  ebp, 0xFFF
    and  ebp, -4096
    test r13, r13
    jz   .done
.page:
    mov  rdi, [rel vtd_ept_root]
    mov  rsi, r14
    mov  rdx, r13
    call vtd_ept_map_bar_page
    cmp  eax, VTD_EPT_MAP_LEAF_WRITTEN
    je   .mapped
    cmp  eax, VTD_EPT_MAP_LEAF_ALREADY_EXACT
    jne  .done                            ; fail closed; terminal path localizes
.mapped:
    add  r13, 0x1000
    add  r14, 0x1000
    sub  ebp, 0x1000
    jnz  .page
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Retain each fresh Linux EPT and pre-map every measured saved BAR at GPA=HPA.
; Preserve the EPT builder's live registers, matching Classic's consumer seam.
vtd_map_secondary_bars_ept:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  [rel vtd_ept_root], rdi
    lea  rax, [rdi - 0x2000 + VTD_EPT_POOL_OFF]
    mov  [rel vtd_ept_pool_base], rax
    mov  byte [rel vtd_ept_pool_used], 0
    cmp  byte [rel vtd_vpci_active], 1
    jne  .done
    xor  ebx, ebx
.bar:
    mov  eax, ebx
    call vtd_map_fixed_bar
    inc  ebx
    cmp  ebx, 6
    jb   .bar
    mfence
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; EAX=config-byte offset for guest 00:01.0, or -1. Guest 00:00.0 is handled
; separately by vtd_vpci_in using Classic's proven minimal host-bridge shape.
vtd_vpci_offset:
    mov  eax, [rel vtd_vpci_addr]
    mov  ecx, eax
    shr  ecx, 16
    and  ecx, 0xFF
    test ecx, ecx
    jnz  .bad
    mov  ecx, eax
    shr  ecx, 11
    and  ecx, 0x1F
    cmp  ecx, 1
    jne  .bad
    mov  ecx, eax
    shr  ecx, 8
    and  ecx, 7
    test ecx, ecx
    jnz  .bad
    and  eax, 0xFC
    mov  ecx, edx
    sub  ecx, 0xCFC
    add  eax, ecx
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; Living-guest proof: restart with PCI enabled, inject a shell command through
; virtio-console, then require both real sysfs vendor output and nonce output.
; ---------------------------------------------------------------------------
; EAX=1 when the same run has enough evidence to dispatch the direct carrier
; measurement. The stale early carrier latch is intentionally not consulted.
vtd_post_dhcp_carrier_dispatch_ready:
    xor  eax, eax
    cmp  byte [rel vtd_network_mode], 1
    jne  .done
    cmp  byte [rel vtd_net_driver_r8169], 1
    jne  .done
    cmp  byte [rel vtd_net_lease], 0
    je   .done
    cmp  byte [rel vtd_net_iface], 0
    je   .done
    cmp  byte [rel vtd_net_carrier_probe_dispatched], 0
    jne  .done
    mov  eax, 1
.done:
    ret

; Transparent L2 is a host-facing bridge: once the content-verified r8169
; interface exists, carrier/bridge setup must run before either the guest or
; PaOS has an L3 lease.  Keep this predicate separate from the legacy DDOM
; post-DHCP gate above so l3_relay retains its established ordering.
vtd_domain_l2_carrier_dispatch_ready:
    xor  eax, eax
    cmp  byte [rel vtd_network_mode], 1
    jne  .done
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .done
    cmp  byte [rel vtd_domain_shell_ready], 1
    jne  .done
    cmp  byte [rel vtd_domain_iface_ready], 1
    jne  .done
    cmp  byte [rel vtd_net_driver_r8169], 1
    jne  .done
    cmp  byte [rel vtd_net_iface], 0
    je   .done
    cmp  byte [rel vtd_net_carrier_probe_dispatched], 0
    jne  .done
    mov  eax, 1
.done:
    ret

vtd_guest_proof:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    je   .seam_free
    xor  eax, eax                          ; RCQ-37: the media owner holds the vCPU seam; nothing touched
    ret
.seam_free:
%endif
%endif
    call hv_vcon_proof_roll_state_reset
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_STOP_WAIT
    mov  byte [rel vtd_guest_inject_accepted], 0
    mov  dword [rel vtd_guest_start_gen], 0
    mov  dword [rel vtd_first_ud_diag_gen], 0
    mov  byte [rel hv_linux_stop_req], 1
    mov  byte [rel hv_linux_run_req], 0
    call vtd_deadline_guest_allow
.stop_wait:
    cmp  byte [rel hv_linux_running], 0
    je   .start
    call sched_yield
    call vtd_deadline_expired
    test eax, eax
    jz   .stop_wait
    jmp  .bad
.start:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_SPAWN
    mov  byte [rel hv_linux_stop_req], 0
    call vtd_bar_trace_reset
    call hv_guest_linux_request_start
    mov  [rel vtd_guest_start_gen], eax
    cmp  byte [rel vtd_first_ud_diag_requested], 1
    jne  .ordinary_generation
    mov  [rel vtd_first_ud_diag_gen], eax
.ordinary_generation:
    mov  [rel vtd_vpci_trace_run_gen], eax
    mov  [rel vtd_vpci_trace_gen], eax
    cmp  byte [rel hv_linux_task_started], 1
    je   .request_stage
    lea  rdi, [rel hv_guest_linux_task]
    call sched_spawn
    cmp  eax, -1
    jne  .spawned
    mov  byte [rel hv_linux_run_req], 0
    jmp  .bad
.spawned:
    mov  byte [rel hv_linux_task_started], 1
.request_stage:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_RUN_NOT_CONSUMED
.request_wait:
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel vtd_guest_start_gen]
    je   .boot_stage
    call sched_yield
    call vtd_deadline_expired
    test eax, eax
    jz   .request_wait
    jmp  .bad
.boot_stage:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_BOOT_WAIT
.boot_wait:
    cmp  byte [rel hv_linux_running], 1
    je   .boot_live
    cmp  byte [rel hv_linux_start_active], 1
    je   .boot_yield                       ; accepted request is still loading
    jmp  .boot_exit                       ; loader/VM returned after consumption
.boot_live:
    cmp  byte [rel hv_linux_kboot], 1
    jne  .boot_yield
    cmp  byte [rel hv_vcon_ready], 1
    je   .inject
.boot_yield:
    call sched_yield
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel vtd_guest_start_gen]
    jne  .request_lost
    cmp  byte [rel hv_linux_running], 1
    je   .boot_budget
    cmp  byte [rel hv_linux_start_active], 1
    jne  .boot_exit
.boot_budget:
    call vtd_deadline_expired
    test eax, eax
    jz   .boot_wait
    jmp  .bad
.request_lost:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_RUN_NOT_CONSUMED
    jmp  .bad
.boot_exit:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_BOOT_EXIT
    jmp  .bad
.inject:
    cmp  byte [rel vtd_network_mode], 1
    je   .net_begin
    ; Built-in driver initcalls are complete once the kernel has entered /init.
    ; Expose the saved identity before lspci reads it; no device rescan is
    ; requested, so this remains identity proof rather than an RTL network test.
    mov  byte [rel vtd_vpci_identity_open], 1
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_INJECT
    call hv_vcon_proof_roll_begin
.inject_wait:
    lea  rdi, [rel vtd_guest_command]
    call hv_vcon_rx_line
    test eax, eax
    jnz  .injected
    call sched_yield
    call vtd_deadline_expired
    test eax, eax
    jz   .inject_wait
    jmp  .bad
.injected:
    mov  byte [rel vtd_guest_inject_accepted], 1
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_VENDOR_WAIT
.vendor_wait:
    lea  rdi, [rel hv_vcon_capture]
    lea  rsi, [rel str_vtd_guest_vendor]
    call hv_str_has
    test al, al
    jz   .vendor_yield
    mov  byte [rel vtd_guest_vendor_seen], 1
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_ECHO_WAIT
.echo_wait:
    lea  rdi, [rel hv_vcon_capture]
    lea  rsi, [rel vtd_guest_expected]
    call hv_str_has
    test al, al
    jz   .echo_yield
    mov  byte [rel vtd_guest_echo_seen], 1
    jmp  .yes
.echo_yield:
    call sched_yield
    call vtd_deadline_expired
    test eax, eax
    jz   .echo_wait
    jmp  .bad
.vendor_yield:
    call sched_yield
    call vtd_deadline_expired
    test eax, eax
    jz   .vendor_wait
    jmp  .bad
.net_begin:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_CARRIER_WAIT
    call hv_vcon_proof_roll_begin
.net_wait:
    cmp  byte [rel vtd_domain_l2_active], 1
    je   .domain_shell
    cmp  byte [rel vtd_net_carrier_probe_dispatched], 1
    je   .net_sample_wait
    call vtd_post_dhcp_carrier_dispatch_ready
    test eax, eax
    jz   .net_yield
    mov  byte [rel vtd_net_carrier_probe_pending], 1
    lea  rdi, [rel str_vtd_net_carrier_probe_cmd]
    call hv_vcon_rx_line
    test eax, eax
    jz   .net_probe_retry
    mov  byte [rel vtd_net_carrier_probe_dispatched], 1
    jmp  .net_yield
.net_probe_retry:
    mov  byte [rel vtd_net_carrier_probe_pending], 0
    jmp  .net_yield
.domain_shell:
    cmp  byte [rel vtd_domain_shell_ready], 1
    je   .domain_iface
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_SHELL_WAIT
    cmp  byte [rel vtd_domain_shell_cmd_dispatched], 1
    je   .net_yield
    lea  rdi, [rel str_vtd_domain_shell_cmd]
    call hv_vcon_rx_line
    test eax, eax
    jz   .net_yield
    mov  byte [rel vtd_domain_shell_cmd_dispatched], 1
    jmp  .net_yield
.domain_iface:
    cmp  byte [rel vtd_domain_iface_ready], 1
    je   .domain_carrier
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_IFACE_WAIT
    cmp  byte [rel vtd_domain_iface_cmd_dispatched], 1
    jne  .domain_iface_dispatch
    call tsc_now
    cmp  rax, [rel vtd_domain_iface_next_tsc]
    jb   .net_yield
    cmp  byte [rel vtd_domain_iface_attempts], VTD_DOMAIN_IFACE_MAX_ATTEMPTS
    jae  .domain_iface_timeout
    mov  byte [rel vtd_domain_iface_cmd_dispatched], 0
.domain_iface_dispatch:
    lea  rdi, [rel str_vtd_domain_iface_cmd]
    call hv_vcon_rx_line
    test eax, eax
    jz   .net_yield
    inc  byte [rel vtd_domain_iface_attempts]
    call tsc_now
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jnz  .domain_iface_retry_scaled
    mov  rdx, 1000000
.domain_iface_retry_scaled:
    imul rdx, VTD_DOMAIN_IFACE_RETRY_MS
    add  rax, rdx
    mov  [rel vtd_domain_iface_next_tsc], rax
    mov  byte [rel vtd_domain_iface_cmd_dispatched], 1
    jmp  .net_yield
.domain_carrier:
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_CARRIER_WAIT
    cmp  byte [rel vtd_net_carrier_probe_dispatched], 1
    je   .net_sample_wait
    call vtd_domain_l2_carrier_dispatch_ready
    test eax, eax
    jz   .net_yield
    mov  byte [rel vtd_net_carrier_probe_pending], 1
    lea  rdi, [rel str_vtd_domain_carrier_cmd]
    call hv_vcon_rx_line
    test eax, eax
    jz   .net_probe_retry
    mov  byte [rel vtd_net_carrier_probe_dispatched], 1
    jmp  .net_yield
.net_sample_wait:
    cmp  byte [rel vtd_net_carrier_sample_seen], 1
    jne  .net_yield
    cmp  byte [rel vtd_net_carrier], 1
    jne  .net_carrier_zero
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .net_have_command
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_BRIDGE_WAIT
    call vtd_build_domain_bridge_command
    test rax, rax
    jz   .bad
    mov  [rel vtd_net_command_ptr], rax
.net_have_command:
    mov  rdi, [rel vtd_net_command_ptr]
    test rdi, rdi
    jz   .bad
    call hv_vcon_rx_line
    test eax, eax
    jz   .net_yield
    mov  byte [rel vtd_guest_inject_accepted], 1
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_ECHO_WAIT
.net_result_wait:
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .net_datagram_result
    cmp  byte [rel vtd_domain_bridge_ready], 1
    je   .yes
    jmp  .net_result_yield
.net_datagram_result:
    cmp  byte [rel vtd_net_gateway_arp], 1
    jne  .net_result_yield
    cmp  byte [rel vtd_net_udp_sent], 1
    je   .yes
.net_result_yield:
    call sched_yield
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    call vtd_deadline_expired
    test eax, eax
    jz   .net_result_wait
    jmp  .bad
.net_carrier_zero:
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_CARRIER_ZERO
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .bad
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_CARRIER_ZERO
    jmp  .bad
.net_yield:
    call sched_yield
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    call vtd_deadline_expired
    test eax, eax
    jz   .net_wait
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .bad
    cmp  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_IFACE_WAIT
    jne  .bad
.domain_iface_timeout:
    cmp  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_NOT_FOUND
    je   .domain_iface_timeout_not_found
    cmp  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_LINK_UP_FAILED
    je   .domain_iface_timeout_link_up
    cmp  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_MALFORMED
    je   .domain_iface_timeout_malformed
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_TIMEOUT_NO_RECEIPT
    jmp  .bad
.domain_iface_timeout_not_found:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_TIMEOUT_NOT_FOUND
    jmp  .bad
.domain_iface_timeout_link_up:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_TIMEOUT_LINK_UP
    jmp  .bad
.domain_iface_timeout_malformed:
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_TIMEOUT_MALFORMED
.bad:
    call hv_vcon_proof_roll_abort
    xor  eax, eax
    ret
.yes:
    call hv_vcon_proof_roll_finish
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_NONE
    mov  eax, 1
    ret

vtd_deadline_guest_allow:
    call tsc_now
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jnz  .scaled
    mov  rdx, 1000000
.scaled:
    mov  ecx, VTD_GUEST_BOOT_ALLOW_MS
    cmp  byte [rel vtd_network_mode], 1
    jne  .budget
    mov  ecx, VTD_NET_DEADMAN_MS - VTD_MIN_RECLAIM_MARGIN_MS
.budget:
    imul rdx, rcx
    add  rax, rdx
    mov  [rel vtd_wait_deadline], rax
    ret

vtd_deadline_expired:
    call tsc_now
    cmp  rax, [rel vtd_wait_deadline]
    setae al
    movzx eax, al
    ret

; ---------------------------------------------------------------------------
; VTD command registry surface and UDP staging.
; ---------------------------------------------------------------------------
vtd_register_verb:
    lea  rdi, [rel str_vtd_verb]
    lea  rsi, [rel vtd_command]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_ddom_verb]
    lea  rsi, [rel vtd_ddom_command]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_dmaviol_verb]
    lea  rsi, [rel cmd_verb_dmaviol]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_dmaviol_check_verb]
    lea  rsi, [rel cmd_verb_dmaviol_check]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; Separate owner-authenticated AMD-only bounded read-only challenge.
    lea  rdi, [rel str_dmaviol4_verb]
    lea  rsi, [rel cmd_verb_amd_dmaviol4]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_dmaviol4_check_verb]
    lea  rsi, [rel cmd_verb_amd_dmaviol4_check]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; The AHCI twin for a target whose native storage is SATA only (AMD or Intel).
    lea  rdi, [rel str_dmaviola_verb]
    lea  rsi, [rel cmd_verb_dmaviola]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_dmaviola_check_verb]
    lea  rsi, [rel cmd_verb_dmaviola_check]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; T1-4: the assigned-function guest's IOMMU owner after its exit (hv/iommu_owner_witness).
    lea  rdi, [rel str_staleowner_verb]
    lea  rsi, [rel cmd_verb_staleowner]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    call hv_vcon_proof_roll_fixture_selftest
    cmp  byte [rel hv_vcon_proof_roll_fixture_ok], 1
    jne  .done
    call vtd_identity_guard_fixture_selftest
    cmp  byte [rel vtd_identity_guard_fixture_ok], 1
    jne  .done
    lea  rdi, [rel str_vtd_identity_guard_marker]
    call serial_string
    call vtd_failure_fixture_selftest
    cmp  byte [rel vtd_failure_fixture_ok], 1
    jne  .done
    lea  rdi, [rel str_vtd_guest_substages_marker]
    call serial_string
    call vtd_observability_fixture_selftest
    cmp  byte [rel vtd_observability_fixture_ok], 1
    jne  .done
    lea  rdi, [rel str_vtd_guest_observability_marker]
    call serial_string
    call vtd_ept_detail_fixture_selftest
    cmp  byte [rel vtd_ept_detail_fixture_ok], 1
    jne  .done
    lea  rdi, [rel str_vtd_guest_ept_detail_marker]
    call serial_string
    lea  rdi, [rel vtd_bar_alias_fixture_pages]
    call hv_first_ud_fixture_selftest
    cmp  byte [rel hv_first_ud_fixture_ok], 1
    jne  .first_ud_fixture_failed
    lea  rdi, [rel str_vtd_first_ud_marker]
    call serial_string
    call vtd_bar_alias_activation_fixture_selftest
    cmp  byte [rel vtd_bar_alias_fixture_ok], 1
    jne  .bar_fixture_failed
    lea  rdi, [rel str_vtd_bar_alias_marker]
    call serial_string
    call vtd_post_dhcp_carrier_fixture_selftest
    cmp  byte [rel vtd_post_dhcp_carrier_fixture_ok], 1
    jne  .post_dhcp_carrier_fixture_failed
    lea  rdi, [rel str_vtd_post_dhcp_carrier_marker]
    call serial_string
    jmp  .done
.post_dhcp_carrier_fixture_failed:
    lea  rdi, [rel str_vtd_post_dhcp_carrier_fail]
    call serial_string
    movzx edi, byte [rel vtd_post_dhcp_carrier_fixture_stage]
    call serial_hex64
    call serial_newline
    jmp  .done
.bar_fixture_failed:
    lea  rdi, [rel str_vtd_bar_alias_fail]
    call serial_string
    movzx edi, byte [rel vtd_bar_alias_fixture_stage]
    call serial_hex64
    call serial_newline
    jmp  .done
.first_ud_fixture_failed:
    lea  rdi, [rel str_vtd_first_ud_fail]
    call serial_string
    mov  edi, [rel hv_first_ud_fixture_stage]
    call serial_hex64
    call serial_newline
.done:
    ret

; Local driver-domain lifecycle for 1013b. Unlike DDOM NET, this entry point is
; invoked in-process by virtio_domain and therefore has no native-UDP bootstrap
; dependency. The existing bounded ownership worker still owns assignment,
; guest launch, failure capture, and canonical reclaim.
vtd_domainnet_start:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .busy                             ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    cmp  byte [rel vtd_domain_l2_active], 1
    je   .already
    cmp  byte [rel vtd_net_task_active], 1
    je   .busy
    cmp  byte [rel vtd_net_start_pending], 1
    je   .busy
    cmp  byte [rel vtd_owner_guest], 1
    je   .busy
    call vtd_net_reset_session
    call vtd_dd_reset
    mov  byte [rel vtd_dd_state], VTD_DD_STARTING
    mov  byte [rel vtd_domain_l2_active], 1
    mov  byte [rel vtd_network_mode], 1
    mov  byte [rel vtd_net_start_pending], 1
    cmp  byte [rel vtd_net_task_started], 1
    je   .already
    lea  rdi, [rel vtd_net_task]
    call sched_spawn
    cmp  eax, -1
    je   .spawn_fail
    mov  byte [rel vtd_net_task_started], 1
.already:
    xor  eax, eax
    ret
.spawn_fail:
    mov  byte [rel vtd_net_start_pending], 0
    mov  byte [rel vtd_network_mode], 0
    mov  byte [rel vtd_domain_l2_active], 0
    mov  byte [rel vtd_dd_state], VTD_DD_IDLE
.busy:
    mov  rax, -1
    ret

vtd_domainnet_stop:
    ; An owner stop is never restarted. A spent budget stays visible: the
    ; capstone rollback lands here after EXHAUSTED.
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .stop_fail                        ; RCQ-37: never stops the media owner's guest
%endif
%endif
    cmp  byte [rel vtd_dd_state], VTD_DD_EXHAUSTED
    je   .stop_state
    mov  byte [rel vtd_dd_state], VTD_DD_IDLE
.stop_state:
    mov  byte [rel vtd_net_start_pending], 0
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_linux_stop_req], 1
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_reclaim_internal
    mov  byte [rel vtd_domain_l2_active], 0
    mov  byte [rel vtd_domain_bridge_ready], 0
    test eax, eax
    jz   .stop_fail
    xor  eax, eax
    ret
.stop_fail:
    mov  rax, -1
    ret

; Live physical bridge identity, not the asynchronous worker's alive latch.
; EAX=exact consumed START generation, or 0. No launch/probe/guest action.
; Existing assignment, shell/interface receipts and bridge completion own this
; authority; a thin CLI or an absent physical attachment cannot satisfy it.
vtd_domainnet_ready_generation:
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .missing
    cmp  byte [rel vtd_owner_guest], 1
    jne  .missing
    cmp  byte [rel vtd_network_mode], 1
    jne  .missing
    cmp  byte [rel vtd_domain_bridge_ready], 1
    jne  .missing
    cmp  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_READY
    jne  .missing
    cmp  byte [rel vtd_domain_shell_ready], 1
    jne  .missing
    cmp  byte [rel vtd_domain_iface_ready], 1
    jne  .missing
    cmp  byte [rel vtd_net_driver_r8169], 1
    jne  .missing
    cmp  byte [rel vtd_net_iface], 0
    je   .missing
    cmp  byte [rel hv_linux_running], 1
    jne  .missing
    cmp  byte [rel hv_linux_kboot], 1
    jne  .missing
    cmp  byte [rel hv_vcon_ready], 1
    jne  .missing
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .missing
    cmp  byte [rel vtd_deadman_fired], 0
    jne  .missing
    mov  eax, [rel vtd_guest_start_gen]
    test eax, eax
    jz   .missing
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .missing
    ret
.missing:
    xor  eax, eax
    ret

; EAX=1 while the local domain lifecycle still owns an in-progress or live
; bridge. Canonical reclaim clears this latch on every asynchronous failure.
vtd_domainnet_alive:
    movzx eax, byte [rel vtd_domain_l2_active]
    ret

; Build a <=255-byte console command after the proven carrier parser has
; discovered the live r8169 interface. The virtio interface is discovered from
; sysfs on every launch; no example interface name is trusted.
vtd_build_domain_bridge_command:
    cmp  byte [rel vtd_net_iface], 0
    je   .build_fail
    lea  rdi, [rel vtd_domain_bridge_command]
    lea  rsi, [rel str_vtd_domain_bridge_pre]
    call vtd_copy_string
    lea  rsi, [rel vtd_net_iface]
    call vtd_copy_string
    lea  rsi, [rel str_vtd_domain_bridge_post]
    call vtd_copy_string
    mov  byte [rdi], 0
    lea  rax, [rel vtd_domain_bridge_command]
    ret
.build_fail:
    xor  eax, eax
    ret

; DMAVIOL <nonce> — issue a non-destructive NVMe Identify whose PRP points at
; a runtime-aligned heap page deliberately absent from native DID 2. A genuine
; pass requires matching live FRCD source/address, unchanged randomized content,
; one 1066 containment record, and a still-returning command path.
cmd_verb_dmaviol:
    cmp qword [rel amdvi_mmio],0
    jne cmd_verb_amd_dmaviol
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r12 + RSP_VAL], rbx
    mov  rdi, rbx
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce

    lea  rsi, [rel vtd_nonce]
    lea  rdi, [rel vtd_dmaviol_nonce]
    mov  ecx, 8
    cld
    rep  movsq
    mov  byte [rel vtd_dmaviol_valid], 0
    mov  byte [rel vtd_dmaviol_blocked], 0
    mov  byte [rel vtd_dmaviol_landed], 1
    mov  dword [rel vtd_dmaviol_fault_delta], 0
    mov  dword [rel vtd_dmaviol_nvme_status], 0xFFFF
    mov  dword [rel vtd_dmaviol_stage], 1
    mov  qword [rel vtd_dmaviol_frcd_lo], 0
    mov  qword [rel vtd_dmaviol_frcd_hi], 0

    cmp  byte [rel vtd_ready], 1
    jne  .failed
    cmp  byte [rel vtd_native_ready], 1
    jne  .failed
    cmp  byte [rel vtd_enabled], 1
    jne  .failed
    cmp  byte [rel vtd_owner_guest], 0
    jne  .failed
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .failed
    mov  dword [rel vtd_dmaviol_stage], 2

    mov  r13, [rel vtd_dmaviol_target_page]
    test r13, r13
    jz   .failed
    test r13, 0x0FFF
    jnz  .failed
    mov  rdi, r13
    call dma_virt_to_phys
    cmp  rax, r13
    jne  .failed
    mov  rdi, r13
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .failed                         ; proof target must remain unmapped
    mov  dword [rel vtd_dmaviol_stage], 3

    ; Fresh sentinel: nonce/TSC-derived qword repeated over the complete page.
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel vtd_dmaviol_nonce]
    mov  rdx, 0x9E3779B97F4A7C15
    xor  rax, rdx
    test rax, rax
    jnz  .canary_ready
    mov  rax, rdx
.canary_ready:
    mov  [rel vtd_dmaviol_canary], rax
    mov  rdi, r13
    mov  ecx, 4096 / 8
    cld
    rep  stosq
    mov  rdi, r13
    call vtd_flush_page
    mfence

    ; A stale record cannot earn this nonce.
    call vtd_clear_faults
    call vtd_capture_faults
    cmp  dword [rel vtd_fault_count], 0
    jne  .failed_clear
    call iommu_fault_count
    mov  [rel vtd_dmaviol_fault_before], rax
    mov  dword [rel vtd_dmaviol_stage], 4

    mov  rdi, r13
    mov  esi, 0xD111
    call nvme_identify_dma_to
    mov  [rel vtd_dmaviol_nvme_status], eax
    mov  dword [rel vtd_dmaviol_stage], 5
    call vtd_capture_faults
    mov  rax, [rel vtd_last_frcd_lo]
    mov  [rel vtd_dmaviol_frcd_lo], rax
    mov  rax, [rel vtd_last_frcd_hi]
    mov  [rel vtd_dmaviol_frcd_hi], rax
    mov  rdi, r13
    call vtd_flush_page
    mfence

    ; Any successful Identify payload write changes at least one qword.
    mov  byte [rel vtd_dmaviol_landed], 0
    mov  rax, [rel vtd_dmaviol_canary]
    mov  rsi, r13
    mov  ecx, 4096 / 8
.check_page:
    cmp  [rsi], rax
    jne  .page_changed
    add  rsi, 8
    dec  ecx
    jnz  .check_page
    jmp  .page_checked
.page_changed:
    mov  byte [rel vtd_dmaviol_landed], 1
.page_checked:
    cmp  byte [rel vtd_dmaviol_landed], 0
    jne  .failed_clear
    cmp  dword [rel vtd_fault_count], 0
    je   .failed_clear

    mov  r14, [rel vtd_dmaviol_frcd_hi]
    bt   r14, 63                         ; live FRCD.F
    jnc  .failed_clear
    movzx eax, r14w                     ; FRCD.SID
    cmp  eax, [rel vtd_nvme_bdf]
    jne  .failed_clear
    mov  rax, r14
    shr  rax, 32
    and  eax, 0xFF
    test eax, eax                        ; non-zero VT-d fault reason
    jz   .failed_clear
    mov  r15, [rel vtd_dmaviol_frcd_lo]
    and  r15, -4096
    cmp  r15, r13
    jne  .failed_clear
    mov  dword [rel vtd_dmaviol_stage], 6

    lea  rdi, [rel vtd_dmaviol_nonce]
    mov  esi, [rel vtd_nvme_bdf]
    mov  rdx, r15
    mov  rcx, r14                       ; validated FRCD reason, numeric only
    shr  rcx, 32
    and  ecx, 0xFF
    call iommu_capture_live
    call iommu_fault_count
    sub  rax, [rel vtd_dmaviol_fault_before]
    mov  [rel vtd_dmaviol_fault_delta], eax
    cmp  eax, 1
    jne  .failed_clear
    mov  dword [rel vtd_dmaviol_stage], 7
    mov  byte [rel vtd_dmaviol_blocked], 1
    mov  byte [rel vtd_dmaviol_valid], 1
    call vtd_clear_faults
    jmp  .render

.failed_clear:
    call vtd_clear_faults
.failed:
    mov  byte [rel vtd_dmaviol_blocked], 0
    mov  byte [rel vtd_dmaviol_valid], 1
.render:
    call vtd_out_reset
    lea  rdi, [rel str_dmaviol_head]
    call vtd_out_str
    lea  rdi, [rel vtd_dmaviol_nonce]
    call vtd_out_str
    cmp  byte [rel vtd_dmaviol_blocked], 1
    jne  .render_failed
    lea  rdi, [rel str_dmaviol_blocked]
    call vtd_out_str
    jmp  .ready
.render_failed:
    lea  rdi, [rel str_dmaviol_failed]
    call vtd_out_str
    mov  edi, [rel vtd_dmaviol_fault_delta]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_stage]
    call vtd_out_str
    mov  edi, [rel vtd_dmaviol_stage]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_landed]
    call vtd_out_str
    movzx edi, byte [rel vtd_dmaviol_landed]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_nvme_status]
    call vtd_out_str
    mov  edi, [rel vtd_dmaviol_nvme_status]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_target]
    call vtd_out_str
    mov  rdi, [rel vtd_dmaviol_target_page]
    call vtd_out_hex_compact
    lea  rdi, [rel str_dmaviol_fsts]
    call vtd_out_str
    mov  edi, [rel vtd_fsts]
    call vtd_out_hex_compact
    lea  rdi, [rel str_dmaviol_frcd_lo]
    call vtd_out_str
    mov  rdi, [rel vtd_dmaviol_frcd_lo]
    call vtd_out_hex_compact
    lea  rdi, [rel str_dmaviol_frcd_hi]
    call vtd_out_str
    mov  rdi, [rel vtd_dmaviol_frcd_hi]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    jmp  .ready
.bad_nonce:
    call vtd_out_reset
    lea  rdi, [rel str_dmaviol_bad_nonce]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; DMAVIOL_CHECK <nonce> — re-read the complete retained canary under the
; same native admission checks. Never issue another Identify or clear faults.
cmd_verb_dmaviol_check:
    cmp qword [rel amdvi_mmio],0
    jne cmd_verb_amd_dmaviol_check
    push rbx
    push r12
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r12 + RSP_VAL], rbx
    mov  rdi, rbx
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce
    lea  rdi, [rel vtd_nonce]
    lea  rsi, [rel vtd_dmaviol_nonce]
    call strcmp
    test rax, rax
    jnz  .stale
    cmp  byte [rel vtd_dmaviol_valid], 1
    jne  .stale
    cmp  byte [rel vtd_dmaviol_blocked], 1
    jne  .render                        ; a failed attempt cannot become a pass
    cmp  byte [rel vtd_ready], 1
    jne  .stale
    cmp  byte [rel vtd_native_ready], 1
    jne  .stale
    cmp  byte [rel vtd_enabled], 1
    jne  .stale
    cmp  byte [rel vtd_owner_guest], 0
    jne  .stale
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .stale
    mov  rbx, [rel vtd_dmaviol_target_page]
    test rbx, rbx
    jz   .stale
    test rbx, 0x0FFF
    jnz  .stale
    mov  rdi, rbx
    call dma_virt_to_phys
    cmp  rax, rbx
    jne  .stale
    mov  rdi, rbx
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .stale                         ; retained target must still be unmapped
    mov  rdi, rbx
    call vtd_flush_page
    mfence
    mov  rax, [rel vtd_dmaviol_canary]
    mov  rsi, rbx
    mov  ecx, 4096 / 8
.check_page:
    cmp  [rsi], rax
    jne  .page_changed
    add  rsi, 8
    dec  ecx
    jnz  .check_page
    jmp  .render
.page_changed:
    mov  byte [rel vtd_dmaviol_landed], 1
    mov  byte [rel vtd_dmaviol_blocked], 0
.render:
    call vtd_out_reset
    lea  rdi, [rel str_dmaviol_check_head]
    call vtd_out_str
    lea  rdi, [rel vtd_dmaviol_nonce]
    call vtd_out_str
    lea  rdi, [rel str_dmaviol_landed]
    call vtd_out_str
    movzx edi, byte [rel vtd_dmaviol_landed]
    call vtd_out_dec
    cmp  byte [rel vtd_dmaviol_blocked], 1
    jne  .check_failed
    lea  rdi, [rel str_dmaviol_check_blocked]
    call vtd_out_str
    jmp  .ready
.check_failed:
    lea  rdi, [rel str_dmaviol_check_failed]
    call vtd_out_str
    jmp  .ready
.stale:
    call vtd_out_reset
    lea  rdi, [rel str_dmaviol_check_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_dmaviol_check_stale]
    call vtd_out_str
    jmp  .ready
.bad_nonce:
    call vtd_out_reset
    lea  rdi, [rel str_dmaviol_check_bad_nonce]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

; DMAVIOLA <nonce> on Intel — the VT-d twin of the AMD AHCI challenge, for a
; target whose only native storage is SATA (Dell ahci0, FS 74564). One read-only
; IDENTIFY DEVICE (512 B) through ahci_identify_dma_to into the DMAVIOL canary
; page, which native DID 2 never maps. The requester is the HBA the AHCI backend
; drives, and it must be the discovered SATA function in DID 2. A 512 B write may
; reach the unit as several requests, so after a bounded wait for the first
; record every live FRCD must name that requester, a non-zero reason and an
; address inside the page; a primary-fault overflow is never a pass. The HBA
; completion is recorded, not graded; a poisoned port is never BLOCKED. The page
; and its current canary value are shared with DMAVIOL: DMAVIOLA_CHECK is STALE
; once DMAVIOL has rewritten the page.
VTD_DMAVIA_SETTLE equ 4096
cmd_verb_dmaviola:
    call vtd_dmavia_amd_route
    test eax, eax
    jnz  cmd_verb_amd_dmaviola
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r12 + RSP_VAL], rbx
    mov  rdi, rbx
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce

    lea  rsi, [rel vtd_nonce]
    lea  rdi, [rel vtd_dmavia_nonce]
    mov  ecx, 8
    cld
    rep  movsq
    mov  byte [rel vtd_dmavia_valid], 0
    mov  byte [rel vtd_dmavia_blocked], 0
    mov  byte [rel vtd_dmavia_landed], 1
    mov  dword [rel vtd_dmavia_fault_delta], 0
    mov  dword [rel vtd_dmavia_ahci_status], 0xFFFF
    mov  dword [rel vtd_dmavia_stage], 1
    mov  qword [rel vtd_dmavia_frcd_lo], 0
    mov  qword [rel vtd_dmavia_frcd_hi], 0

    cmp  byte [rel vtd_ready], 1
    jne  .failed
    cmp  byte [rel vtd_native_ready], 1
    jne  .failed
    cmp  byte [rel vtd_enabled], 1
    jne  .failed
    cmp  byte [rel vtd_owner_guest], 0
    jne  .failed
    cmp  byte [rel ahci_present], 1
    jne  .failed
    cmp  byte [rel ahci_vmd_child], 0
    jne  .failed                         ; a VMD child is not its own requester
    call vtd_dmavia_requester
    cmp  eax, -1
    je   .failed
    mov  [rel vtd_dmavia_bdf], eax
    mov  r14d, eax
    mov  edi, eax
    call vtd_native_ctx_ok
    test eax, eax
    jz   .failed
    mov  dword [rel vtd_dmavia_stage], 2

    mov  r13, [rel vtd_dmaviol_target_page]
    test r13, r13
    jz   .failed
    test r13, 0x0FFF
    jnz  .failed
    mov  rdi, r13
    call dma_virt_to_phys
    cmp  rax, r13
    jne  .failed
    mov  rdi, r13
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .failed                         ; proof target must remain unmapped
    mov  dword [rel vtd_dmavia_stage], 3

    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel vtd_dmavia_nonce]
    mov  rdx, 0x9E3779B97F4A7C15
    xor  rax, rdx
    test rax, rax
    jnz  .canary_ready
    mov  rax, rdx
.canary_ready:
    mov  [rel vtd_dmavia_canary], rax
    mov  [rel vtd_dmaviol_canary], rax   ; the page's current value, for both CHECKs
    mov  rdi, r13
    mov  ecx, 4096 / 8
    cld
    rep  stosq
    mov  rdi, r13
    call vtd_flush_page
    mfence

    ; A stale record cannot earn this nonce.
    call vtd_clear_faults
    call vtd_capture_faults
    cmp  dword [rel vtd_fault_count], 0
    jne  .failed_clear
    call iommu_fault_count
    mov  [rel vtd_dmavia_fault_before], rax
    mov  dword [rel vtd_dmavia_stage], 4

    mov  rdi, r13
    call ahci_identify_dma_to
    mov  [rel vtd_dmavia_ahci_status], eax
    mov  dword [rel vtd_dmavia_stage], 5
    call vtd_dmavia_page_intact
    test eax, eax
    jz   .failed_clear
    mov  byte [rel vtd_dmavia_landed], 0
    cmp  dword [rel vtd_dmavia_ahci_status], 0xFFFE
    je   .failed_clear                   ; refused: nothing reached the device

    ; The fault record can lag the HBA. Poll a finite bound for the first one,
    ; then until the live count holds still (one restart per FRCD slot at most).
    mov  r15d, VTD_WAIT_SPINS
.wait:
    call vtd_capture_faults
    cmp  dword [rel vtd_fault_count], 0
    jne  .settle_first
    pause
    dec  r15d
    jnz  .wait
    jmp  .failed_clear
.settle_first:
    mov  r15d, 17
.settle_start:
    mov  ebx, [rel vtd_fault_count]
    mov  ecx, VTD_DMAVIA_SETTLE
.settle:
    pause
    push rcx
    call vtd_capture_faults
    pop  rcx
    cmp  [rel vtd_fault_count], ebx
    je   .still
    dec  r15d
    jz   .failed_clear
    jmp  .settle_start
.still:
    dec  ecx
    jnz  .settle
    mov  rax, [rel vtd_last_frcd_lo]
    mov  [rel vtd_dmavia_frcd_lo], rax
    mov  rax, [rel vtd_last_frcd_hi]
    mov  [rel vtd_dmavia_frcd_hi], rax
    call vtd_dmavia_records
    test eax, eax
    jz   .failed_clear
    mov  dword [rel vtd_dmavia_stage], 6

    lea  rdi, [rel vtd_dmavia_nonce]
    mov  esi, r14d
    mov  rdx, r13
    mov  rcx, [rel vtd_dmavia_frcd_hi]  ; validated FRCD reason, numeric only
    shr  rcx, 32
    and  ecx, 0xFF
    call iommu_capture_live
    call iommu_fault_count
    sub  rax, [rel vtd_dmavia_fault_before]
    mov  [rel vtd_dmavia_fault_delta], eax
    cmp  eax, 1
    jne  .failed_clear
    call vtd_dmavia_page_intact
    test eax, eax
    jz   .landed_late
    cmp  dword [rel vtd_dmavia_ahci_status], 1
    ja   .failed_clear                   ; a poisoned port is not a serviceable device
    mov  dword [rel vtd_dmavia_stage], 7
    mov  byte [rel vtd_dmavia_blocked], 1
    mov  byte [rel vtd_dmavia_valid], 1
    call vtd_clear_faults
    jmp  .render

.landed_late:
    mov  byte [rel vtd_dmavia_landed], 1  ; the stage-5 IDENTIFY reached the page
    mov  dword [rel vtd_dmavia_stage], 5
.failed_clear:
    call vtd_clear_faults
.failed:
    mov  byte [rel vtd_dmavia_blocked], 0
    mov  byte [rel vtd_dmavia_valid], 1
.render:
    call vtd_out_reset
    lea  rdi, [rel str_dmavia_head]
    call vtd_out_str
    lea  rdi, [rel vtd_dmavia_nonce]
    call vtd_out_str
    cmp  byte [rel vtd_dmavia_blocked], 1
    jne  .render_failed
    lea  rdi, [rel str_dmavia_blocked]
    call vtd_out_str
    mov  edi, [rel vtd_dmavia_ahci_status]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    jmp  .ready
.render_failed:
    lea  rdi, [rel str_dmavia_failed]
    call vtd_out_str
    mov  edi, [rel vtd_dmavia_fault_delta]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_stage]
    call vtd_out_str
    mov  edi, [rel vtd_dmavia_stage]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_landed]
    call vtd_out_str
    movzx edi, byte [rel vtd_dmavia_landed]
    call vtd_out_dec
    lea  rdi, [rel str_dmavia_status]
    call vtd_out_str
    mov  edi, [rel vtd_dmavia_ahci_status]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_target]
    call vtd_out_str
    mov  rdi, [rel vtd_dmaviol_target_page]
    call vtd_out_hex_compact
    lea  rdi, [rel str_dmaviol_fsts]
    call vtd_out_str
    mov  edi, [rel vtd_fsts]
    call vtd_out_hex_compact
    lea  rdi, [rel str_dmaviol_frcd_lo]
    call vtd_out_str
    mov  rdi, [rel vtd_dmavia_frcd_lo]
    call vtd_out_hex_compact
    lea  rdi, [rel str_dmaviol_frcd_hi]
    call vtd_out_str
    mov  rdi, [rel vtd_dmavia_frcd_hi]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    jmp  .ready
.bad_nonce:
    call vtd_out_reset
    lea  rdi, [rel str_dmavia_bad_nonce]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EAX = packed BDF of the HBA the AHCI backend drives when it is the discovered
; SATA function, else -1. Clobbers ECX, EDX.
vtd_dmavia_requester:
    cmp  byte [rel vtd_sata_found], 1
    jne  .bad
    mov  eax, [rel ahci_busno]
    cmp  eax, 255
    ja   .bad
    mov  ecx, [rel ahci_devno]
    cmp  ecx, 31
    ja   .bad
    mov  edx, [rel ahci_fn]
    cmp  edx, 7
    ja   .bad
    shl  eax, 8
    shl  ecx, 3
    or   eax, ecx
    or   eax, edx
    cmp  eax, [rel vtd_sata_bdf]
    jne  .bad
    ret
.bad:
    mov  eax, -1
    ret

; EAX = number of live FRCD records when every one is a write (T=0) by
; requester R14D with a non-zero reason and an address inside page R13; 0 when
; any differs or none is live. The slot geometry comes from CAP read live now,
; which must still equal the boot read (an all-ones or changed CAP refuses).
; FSTS.PFO (a record was lost) is admitted only when every one of the unit's
; CAP.NFR+1 slots holds such a record: after the stage-3 clear the unit drops a
; fault only once the slot at FRI is full, and a 512 B write arrives as several
; faulting TLPs (Dell 252, one slot, root 76630, SEC 76637). The dropped faults
; cannot be attributed; a PFO with a free or unscanned slot still refuses. The
; caller's vtd_clear_faults writes FSTS back, clearing PFO, after this read.
; Clobbers RCX, RDX, R8, R9, R10, R11.
vtd_dmavia_records:
    push rbx
    xor  r8d, r8d
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    mov  r11d, [rbx + VTD_REG_FSTS]
    mov  rax, [rbx + VTD_REG_CAP]
    cmp  rax, [rel vtd_cap]               ; an all-ones read differs from the boot read
    jne  .bad
    mov  rcx, rax
    shr  rcx, 24
    and  ecx, 0x3FF
    shl  ecx, 4
    add  rcx, rbx
    shr  rax, 40
    and  eax, 0xFF
    inc  eax
    mov  r10d, eax                       ; CAP.NFR+1 recording slots
    cmp  eax, 16
    jbe  .loop
    mov  eax, 16
.loop:
    test eax, eax
    jz   .done
    mov  rdx, [rcx + 8]
    bt   rdx, 63
    jnc  .next
    bt   rdx, 62                         ; FRCD.T: 1 is a read request
    jc   .bad
    movzx r9d, dx                        ; FRCD.SID
    cmp  r9d, r14d
    jne  .bad
    mov  r9, rdx
    shr  r9, 32
    test r9d, 0xFF                       ; FRCD.FR
    jz   .bad
    mov  r9, [rcx]
    and  r9, -4096
    cmp  r9, r13
    jne  .bad
    inc  r8d
.next:
    add  rcx, 16
    dec  eax
    jmp  .loop
.done:
    test r11d, 1                         ; FSTS.PFO
    jz   .counted
    cmp  r8d, r10d
    jne  .bad
.counted:
    mov  eax, r8d
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; EAX = 1 when the whole retained page still holds this probe's canary.
vtd_dmavia_page_intact:
    mov  rdi, [rel vtd_dmaviol_target_page]
    test rdi, rdi
    jz   .no
    call vtd_flush_page
    mfence
    mov  rsi, [rel vtd_dmaviol_target_page]
    mov  rax, [rel vtd_dmavia_canary]
    mov  ecx, 4096 / 8
.check:
    cmp  [rsi], rax
    jne  .no
    add  rsi, 8
    dec  ecx
    jnz  .check
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; EAX = 1 when DMAVIOLA and its CHECK belong to the AMD probe: an AMD-Vi unit is
; up, or the CPU is AMD and no VT-d unit was found (an AMD box whose AMD-Vi did
; not come up keeps the ivrs grammar, AMD 76324). The vendor alone never picks:
; a QEMU twin reports the host vendor under KVM and AMD under TCG, whatever
; IOMMU it carries. Clobbers RAX only.
vtd_dmavia_amd_route:
    mov  eax, 1
    cmp  qword [rel amdvi_mmio], 0
    jne  .out
    cmp  qword [rel vtd_unitb_base], 0
    jne  .intel
    cmp  byte [rel smp_cpu_vendor], SMP_VENDOR_AMD
    je   .out
.intel:
    xor  eax, eax
.out:
    ret

; DMAVIOLA_CHECK <nonce> on Intel — re-read the retained page under the same
; admission and requester checks. Never issues another IDENTIFY or clears faults.
cmd_verb_dmaviola_check:
    call vtd_dmavia_amd_route
    test eax, eax
    jnz  cmd_verb_amd_dmaviola_check
    push rbx
    push r12
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r12 + RSP_VAL], rbx
    mov  rdi, rbx
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce
    lea  rdi, [rel vtd_nonce]
    lea  rsi, [rel vtd_dmavia_nonce]
    call strcmp
    test rax, rax
    jnz  .stale
    cmp  byte [rel vtd_dmavia_valid], 1
    jne  .stale
    cmp  byte [rel vtd_dmavia_blocked], 1
    jne  .render                        ; a failed attempt cannot become a pass
    cmp  byte [rel vtd_ready], 1
    jne  .stale
    cmp  byte [rel vtd_native_ready], 1
    jne  .stale
    cmp  byte [rel vtd_enabled], 1
    jne  .stale
    cmp  byte [rel vtd_owner_guest], 0
    jne  .stale
    call vtd_dmavia_requester
    cmp  eax, [rel vtd_dmavia_bdf]
    jne  .stale
    mov  edi, eax
    call vtd_native_ctx_ok
    test eax, eax
    jz   .stale
    mov  rbx, [rel vtd_dmaviol_target_page]
    test rbx, rbx
    jz   .stale
    test rbx, 0x0FFF
    jnz  .stale
    mov  rdi, rbx
    call dma_virt_to_phys
    cmp  rax, rbx
    jne  .stale
    mov  rdi, rbx
    call vtd_native_leaf_ptr
    test rax, rax
    jnz  .stale                         ; retained target must still be unmapped
    mov  rax, [rel vtd_dmavia_canary]
    cmp  rax, [rel vtd_dmaviol_canary]
    jne  .stale                         ; DMAVIOL rewrote the page since
    call vtd_dmavia_page_intact
    test eax, eax
    jnz  .render
    mov  byte [rel vtd_dmavia_landed], 1
    mov  byte [rel vtd_dmavia_blocked], 0
.render:
    call vtd_out_reset
    lea  rdi, [rel str_dmavia_check_head]
    call vtd_out_str
    lea  rdi, [rel vtd_dmavia_nonce]
    call vtd_out_str
    lea  rdi, [rel str_dmaviol_landed]
    call vtd_out_str
    movzx edi, byte [rel vtd_dmavia_landed]
    call vtd_out_dec
    lea  rdi, [rel str_dmaviol_check_failed]
    cmp  byte [rel vtd_dmavia_blocked], 1
    jne  .verdict
    lea  rdi, [rel str_dmaviol_check_blocked]
.verdict:
    call vtd_out_str
    jmp  .ready
.stale:
    call vtd_out_reset
    lea  rdi, [rel str_dmavia_check_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_dmaviol_check_stale]
    call vtd_out_str
    jmp  .ready
.bad_nonce:
    call vtd_out_reset
    lea  rdi, [rel str_dmavia_check_bad_nonce]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

str_dmavia_head:      db " DMAVIOLA nonce=", 0
str_dmavia_blocked:   db " VERDICT=BLOCKED source=dmar fault_delta=1 landed=0 ahci_status=", 0
str_dmavia_failed:    db " VERDICT=FAILED source=dmar fault_delta=", 0
str_dmavia_status:    db " ahci_status=", 0
str_dmavia_bad_nonce: db " DMAVIOLA ERR bad_nonce", 13, 10, 0
str_dmavia_check_head: db " DMAVIOLA_CHECK nonce=", 0
str_dmavia_check_bad_nonce: db " DMAVIOLA_CHECK ERR bad_nonce", 13, 10, 0

; Target-free proof of the identity-only binding boundary. Drive the real
; CF8/CFC projection: init sees 10ec:ffff, then /init sees the exact saved
; vendor/device dword. Exercise dword and word reads because Linux may use both.
vtd_identity_guard_fixture_selftest:
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel vtd_identity_guard_fixture_ok], 0
    mov  ebx, [rel vtd_vpci_addr]
    movzx r12d, byte [rel vtd_vpci_active]
    movzx r13d, byte [rel vtd_vpci_identity_open]
    mov  r14d, [rel vtd_secondary_cfg]

    mov  byte [rel vtd_vpci_active], 1
    mov  byte [rel vtd_vpci_identity_open], 0
    mov  dword [rel vtd_secondary_cfg], 0x816810EC
    mov  dword [rel vtd_vpci_addr], 0x80000800
    mov  edx, 0xCFC
    call vtd_vpci_in
    cmp  ecx, 0xFFFF10EC
    jne  .restore
    mov  edx, 0xCFE
    call vtd_vpci_in
    cmp  ecx, 0x0000FFFF
    jne  .restore

    mov  byte [rel vtd_vpci_identity_open], 1
    mov  edx, 0xCFC
    call vtd_vpci_in
    cmp  ecx, 0x816810EC
    jne  .restore
    mov  edx, 0xCFE
    call vtd_vpci_in
    cmp  ecx, 0x00008168
    jne  .restore
    mov  byte [rel vtd_identity_guard_fixture_ok], 1
.restore:
    mov  [rel vtd_secondary_cfg], r14d
    mov  [rel vtd_vpci_addr], ebx
    mov  [rel vtd_vpci_identity_open], r13b
    mov  [rel vtd_vpci_active], r12b
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; QEMU/host-safe formatter fixture.  It forces all three bounded assign-failure
; classes and all six guest-proof substages using memory state only, verifies
; their fixed shapes, and proves the expected nonce output is not present in the
; injected input line.  vtd_ownership_init resets synthetic state before hardware.
vtd_failure_fixture_selftest:
    mov  byte [rel vtd_failure_fixture_ok], 0
    lea  rdi, [rel vtd_nonce]
    lea  rsi, [rel str_vtd_fixture_nonce]
    call vtd_copy_string
    mov  byte [rdi], 0
    call vtd_build_guest_strings
    lea  rdi, [rel vtd_guest_command]
    lea  rsi, [rel vtd_guest_expected]
    call hv_str_has
    test al, al
    jnz  .cleanup                         ; input echo must not satisfy output proof
    mov  byte [rel vtd_ready], 1
    mov  byte [rel vtd_secondary_found], 1
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_reclaim_verified], 1
    mov  byte [rel vtd_assign_secondary_found], 1
    mov  byte [rel vtd_assign_ready], 1
    mov  byte [rel vtd_assign_reset_verified], 1
    mov  byte [rel vtd_assign_guest_vendor], 1
    mov  byte [rel vtd_assign_guest_echo], 1
    mov  byte [rel vtd_assign_linux_running], 1
    mov  byte [rel vtd_assign_linux_kboot], 1
    mov  byte [rel vtd_assign_vcon_ready], 1
    mov  byte [rel vtd_assign_inject_accepted], 1
    mov  dword [rel vtd_assign_capture_len], 37
    mov  dword [rel vtd_assign_fsts], 0
    mov  dword [rel vtd_assign_fault_count], 0
    mov  qword [rel vtd_assign_frcd_lo], 0
    mov  qword [rel vtd_assign_frcd_hi], 0

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_CONTEXT_ASSIGN
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_stage_context]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_owner_host_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_reclaim_verified_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_secondary_found_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_ready_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_reset_verified_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_vendor_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_echo_seen_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fsts]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_faults]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_frcd_lo]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_frcd_hi]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; Keep the six substage checks unrolled.  Each forced value must survive
    ; rendering and be observed in the fixed response independently; no loop
    ; index or callee-saved scratch register can silently alias the next case.
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_STOP_WAIT
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_stop_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    call vtd_guest_failure_shape_ok
    test eax, eax
    jz   .cleanup

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_SPAWN
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_spawn_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    call vtd_guest_failure_shape_ok
    test eax, eax
    jz   .cleanup

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_BOOT_WAIT
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_boot_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    call vtd_guest_failure_shape_ok
    test eax, eax
    jz   .cleanup

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_INJECT
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_inject_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    call vtd_guest_failure_shape_ok
    test eax, eax
    jz   .cleanup

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_VENDOR_WAIT
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_vendor_wait_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    call vtd_guest_failure_shape_ok
    test eax, eax
    jz   .cleanup

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_ECHO_WAIT
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_guest_echo_wait_field]
    call hv_str_has
    test al, al
    jz   .cleanup
    call vtd_guest_failure_shape_ok
    test eax, eax
    jz   .cleanup

    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_IOMMU_FAULT
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_stage_iommu]
    call hv_str_has
    test al, al
    jz   .cleanup
    mov  byte [rel vtd_failure_fixture_ok], 1
.cleanup:
    mov  byte [rel vtd_ready], 0
    mov  byte [rel vtd_secondary_found], 0
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_reclaim_verified], 0
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_NONE
    mov  byte [rel vtd_assign_secondary_found], 0
    mov  byte [rel vtd_assign_ready], 0
    mov  byte [rel vtd_assign_reset_verified], 0
    mov  byte [rel vtd_assign_guest_vendor], 0
    mov  byte [rel vtd_assign_guest_echo], 0
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_assign_linux_running], 0
    mov  byte [rel vtd_assign_linux_kboot], 0
    mov  byte [rel vtd_assign_vcon_ready], 0
    mov  byte [rel vtd_assign_inject_accepted], 0
    mov  dword [rel vtd_assign_capture_len], 0
    mov  dword [rel vtd_assign_fsts], 0
    mov  dword [rel vtd_assign_fault_count], 0
    mov  qword [rel vtd_assign_frcd_lo], 0
    mov  qword [rel vtd_assign_frcd_hi], 0
    mov  byte [rel vtd_nonce], 0
    mov  byte [rel vtd_guest_command], 0
    mov  byte [rel vtd_guest_expected], 0
    call vtd_out_reset
    ret

; 1012a1 host-safe lifecycle fixture.  The three cases deliberately use
; different fixed values, then content-match the complete lifecycle segment;
; merely rendering a stage label cannot earn the observability marker.
vtd_observability_fixture_selftest:
    mov  byte [rel vtd_observability_fixture_ok], 0
    lea  rdi, [rel vtd_nonce]
    lea  rsi, [rel str_vtd_fixture_nonce]
    call vtd_copy_string
    mov  byte [rdi], 0
    mov  byte [rel vtd_ready], 1
    mov  byte [rel vtd_secondary_found], 1
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_reclaim_verified], 1
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_secondary_found], 1
    mov  byte [rel vtd_assign_ready], 1
    mov  byte [rel vtd_assign_reset_verified], 1
    mov  byte [rel vtd_assign_guest_vendor], 0
    mov  byte [rel vtd_assign_guest_echo], 0
    mov  byte [rel vtd_assign_inject_accepted], 0
    mov  dword [rel vtd_assign_fsts], 0
    mov  dword [rel vtd_assign_fault_count], 0
    mov  qword [rel vtd_assign_frcd_lo], 0
    mov  qword [rel vtd_assign_frcd_hi], 0

    ; Published request exists, but the task still acknowledges its predecessor.
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_RUN_NOT_CONSUMED
    mov  byte [rel vtd_assign_run_req], 1
    mov  byte [rel vtd_assign_task_started], 1
    mov  dword [rel vtd_assign_start_gen], 101
    mov  dword [rel vtd_assign_start_consumed], 100
    mov  byte [rel vtd_assign_load_err], 0
    mov  byte [rel vtd_assign_launch_refused], 0
    mov  byte [rel vtd_assign_vmxon_fail], 0
    mov  byte [rel vtd_assign_vmcs_fail], 0
    mov  dword [rel vtd_assign_instr_err], 0
    mov  dword [rel vtd_assign_vmwrite_fails], 0
    mov  dword [rel vtd_assign_last_exit], 0
    mov  byte [rel vtd_assign_linux_running], 0
    mov  byte [rel vtd_assign_linux_kboot], 0
    mov  byte [rel vtd_assign_vcon_ready], 0
    mov  byte [rel vtd_assign_vcon_rx_ready], 0
    mov  byte [rel vtd_assign_vcon_tx_ready], 0
    mov  dword [rel vtd_assign_capture_len], 0
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_run_not_consumed]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; The exact request was consumed and remains resident inside its boot wait.
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_BOOT_WAIT
    mov  byte [rel vtd_assign_run_req], 0
    mov  dword [rel vtd_assign_start_gen], 202
    mov  dword [rel vtd_assign_start_consumed], 202
    mov  dword [rel vtd_assign_last_exit], 10
    mov  byte [rel vtd_assign_linux_running], 1
    mov  byte [rel vtd_assign_vcon_ready], 1
    mov  byte [rel vtd_assign_vcon_rx_ready], 1
    mov  byte [rel vtd_assign_vcon_tx_ready], 1
    mov  dword [rel vtd_assign_capture_len], 23
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_boot_wait]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; The same acknowledged request returned through an entry/exit error path.
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_BOOT_EXIT
    mov  dword [rel vtd_assign_start_gen], 303
    mov  dword [rel vtd_assign_start_consumed], 303
    mov  byte [rel vtd_assign_load_err], 6
    mov  byte [rel vtd_assign_vmcs_fail], 1
    mov  dword [rel vtd_assign_instr_err], 7
    mov  dword [rel vtd_assign_vmwrite_fails], 2
    mov  dword [rel vtd_assign_last_exit], 18
    mov  byte [rel vtd_assign_linux_running], 0
    mov  byte [rel vtd_assign_linux_kboot], 0
    mov  byte [rel vtd_assign_vcon_ready], 0
    mov  byte [rel vtd_assign_vcon_rx_ready], 0
    mov  byte [rel vtd_assign_vcon_tx_ready], 0
    mov  dword [rel vtd_assign_capture_len], 37
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_boot_exit]
    call hv_str_has
    test al, al
    jz   .cleanup
    mov  byte [rel vtd_observability_fixture_ok], 1
.cleanup:
    mov  byte [rel vtd_ready], 0
    mov  byte [rel vtd_secondary_found], 0
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_reclaim_verified], 0
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_NONE
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_assign_secondary_found], 0
    mov  byte [rel vtd_assign_ready], 0
    mov  byte [rel vtd_assign_reset_verified], 0
    mov  byte [rel vtd_assign_guest_vendor], 0
    mov  byte [rel vtd_assign_guest_echo], 0
    mov  byte [rel vtd_assign_inject_accepted], 0
    mov  byte [rel vtd_assign_run_req], 0
    mov  byte [rel vtd_assign_task_started], 0
    mov  byte [rel vtd_assign_load_err], 0
    mov  byte [rel vtd_assign_launch_refused], 0
    mov  byte [rel vtd_assign_vmxon_fail], 0
    mov  byte [rel vtd_assign_vmcs_fail], 0
    mov  byte [rel vtd_assign_linux_running], 0
    mov  byte [rel vtd_assign_linux_kboot], 0
    mov  byte [rel vtd_assign_vcon_ready], 0
    mov  byte [rel vtd_assign_vcon_rx_ready], 0
    mov  byte [rel vtd_assign_vcon_tx_ready], 0
    mov  dword [rel vtd_assign_start_gen], 0
    mov  dword [rel vtd_assign_start_consumed], 0
    mov  dword [rel vtd_assign_instr_err], 0
    mov  dword [rel vtd_assign_vmwrite_fails], 0
    mov  dword [rel vtd_assign_last_exit], 0
    mov  dword [rel vtd_assign_capture_len], 0
    mov  dword [rel vtd_assign_fsts], 0
    mov  dword [rel vtd_assign_fault_count], 0
    mov  qword [rel vtd_assign_frcd_lo], 0
    mov  qword [rel vtd_assign_frcd_hi], 0
    mov  byte [rel vtd_nonce], 0
    call vtd_out_reset
    ret

; Target-free BAR-alias fixture for the exact 1012b failure shape. Pre-map the
; saved 64-bit BAR at GPA=HPA, drive Linux-style low=0/high=1 assignment writes
; through real CF8/CFC decode, and prove that only the complete same-generation
; pair maps guest GPA 4 GiB back to the immutable saved HPA. I/O, absent,
; incomplete, stale-generation, and unknown ranges must never gain leaves.
vtd_bar_alias_activation_fixture_selftest:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel vtd_bar_alias_fixture_ok], 0
    mov  byte [rel vtd_bar_alias_fixture_stage], 1
    cld
    lea  rsi, [rel vtd_secondary_cfg + 0x10]
    lea  rdi, [rel vtd_fixture_save_cfg]
    mov  ecx, 3
    rep  movsq
    lea  rsi, [rel vtd_vpci_guest_bar]
    lea  rdi, [rel vtd_fixture_save_shadow]
    mov  ecx, 3
    rep  movsq
    lea  rsi, [rel vtd_secondary_bar_size]
    lea  rdi, [rel vtd_fixture_save_bar_size]
    mov  ecx, 3
    rep  movsq
    lea  rsi, [rel vtd_vpci_bar_probe]
    lea  rdi, [rel vtd_fixture_save_bar_probe]
    mov  ecx, 6
    rep  movsb
    lea  rdi, [rel vtd_vpci_bar_probe]
    xor  eax, eax
    mov  ecx, 6
    rep  stosb
    mov  rax, [rel vtd_ept_root]
    mov  [rel vtd_fixture_save_root], rax
    mov  rax, [rel vtd_ept_pool_base]
    mov  [rel vtd_fixture_save_pool], rax
    mov  rax, [rel hv_linux_gpr]
    mov  [rel vtd_fixture_save_gpr], rax
    mov  eax, [rel vtd_vpci_addr]
    mov  [rel vtd_fixture_save_vpci_addr], eax
    mov  al, [rel vtd_vpci_active]
    mov  [rel vtd_fixture_save_active], al
    mov  al, [rel vtd_ept_pool_used]
    mov  [rel vtd_fixture_save_pool_used], al
    mov  al, [rel hv_linux_vmx_live]
    mov  [rel vtd_fixture_save_vmx_live], al
    xor  ebx, ebx

    ; PE section/file alignment does not guarantee the loaded VA is page
    ; aligned. Round inside the slack-backed reservation before the real EPT
    ; walker masks table pointers to 4 KiB boundaries.
    lea  r12, [rel vtd_bar_alias_fixture_pages]
    add  r12, 4095
    and  r12, -4096
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, 6 * 4096 / 8
    cld
    rep  stosq
    call vtd_bar_trace_reset
    mov  dword [rel vtd_vpci_trace_run_gen], 707
    mov  dword [rel vtd_vpci_trace_gen], 707
    mov  byte [rel vtd_vpci_active], 1
    mov  byte [rel hv_linux_vmx_live], 0
    mov  dword [rel vtd_secondary_cfg + 0x10], 0xE3200004
    mov  dword [rel vtd_secondary_cfg + 0x14], 0
    mov  dword [rel vtd_secondary_cfg + 0x18], 0x0000C001
    mov  dword [rel vtd_secondary_cfg + 0x1C], 0
    mov  qword [rel vtd_secondary_cfg + 0x20], 0
    mov  dword [rel vtd_vpci_guest_bar], 0xE3200004
    mov  dword [rel vtd_vpci_guest_bar + 4], 0
    mov  dword [rel vtd_vpci_guest_bar + 8], 0x0000C001
    mov  dword [rel vtd_vpci_guest_bar + 12], 0
    mov  qword [rel vtd_vpci_guest_bar + 16], 0
    mov  dword [rel vtd_secondary_bar_size], 0x1000
    mov  dword [rel vtd_secondary_bar_size + 4], 0
    mov  dword [rel vtd_secondary_bar_size + 8], 0x100
    mov  dword [rel vtd_secondary_bar_size + 12], 0
    mov  qword [rel vtd_secondary_bar_size + 16], 0

    ; PML4[0] -> PDPT. The pool has two table pages for the saved BAR and two
    ; more for the separately evidenced 4-GiB alias.
    lea  r13, [r12 + 0x1000]
    lea  r14, [r12 + 0x2000]
    mov  rax, r13
    or   rax, 7
    mov  [r12], rax
    mov  [rel vtd_ept_root], r12
    mov  [rel vtd_ept_pool_base], r14
    mov  byte [rel vtd_ept_pool_used], 0

    ; Pre-VMLAUNCH fixed identity mapping: saved HPA is also guest GPA.
    mov  byte [rel vtd_bar_alias_fixture_stage], 2
    xor  eax, eax
    call vtd_map_fixed_bar
    cmp  dword [rel vtd_ept_map_attempts], 1
    jne  .cleanup
    cmp  byte [rel vtd_ept_map_result], VTD_EPT_MAP_LEAF_WRITTEN
    jne  .cleanup
    mov  edx, 0xE3200000
    cmp  qword [rel vtd_ept_map_gpa], rdx
    jne  .cleanup
    cmp  qword [rel vtd_ept_map_hpa], rdx
    jne  .cleanup
    cmp  byte [rel vtd_ept_pool_used], 2
    jne  .cleanup

    ; Resolve and retain the exact leaf containing saved_hpa+0x40.
    mov  eax, 0xE3200000
    mov  edx, eax
    shr  rdx, 30
    and  edx, 0x1FF
    mov  rbp, [r13 + rdx*8]
    mov  rdx, 0x000FFFFFFFFFF000
    and  rbp, rdx
    test rbp, rbp
    jz   .cleanup
    mov  edx, eax
    shr  rdx, 21
    and  edx, 0x1FF
    mov  rbp, [rbp + rdx*8]
    mov  rdx, 0x000FFFFFFFFFF000
    and  rbp, rdx
    test rbp, rbp
    jz   .cleanup
    shr  rax, 12
    and  eax, 0x1FF
    lea  r15, [rbp + rax*8]
    call .want_leaf
    cmp  qword [r15], rdx
    jne  .cleanup

    ; Consumed high, I/O, and absent slots leave the attempt count unchanged.
    mov  eax, 1
    call vtd_map_fixed_bar
    mov  eax, 2
    call vtd_map_fixed_bar
    mov  eax, 3
    call vtd_map_fixed_bar
    cmp  dword [rel vtd_ept_map_attempts], 1
    jne  .cleanup

    ; Real mechanism-1 dword writes to guest 00:01.0 BAR0 low/high.
    mov  byte [rel vtd_bar_alias_fixture_stage], 3
    mov  dword [rel vtd_vpci_addr], 0x80000810
    mov  qword [rel hv_linux_gpr], 0x00000004
    mov  edx, 0xCFC
    mov  r8d, 3
    call vtd_vpci_out

    ; A lone low-half write is not sufficient evidence for a 64-bit alias.
    mov  byte [rel vtd_bar_alias_fixture_stage], 0x31
    mov  rdi, 0x0000000100000040
    call vtd_guest_bar_trace_alias_resolve
    test eax, eax
    jnz  .cleanup

    mov  dword [rel vtd_vpci_addr], 0x80000814
    mov  qword [rel hv_linux_gpr], 0x00000001
    mov  edx, 0xCFC
    mov  r8d, 3
    call vtd_vpci_out

    ; Config readback remains the saved layout, never the rejected 4-GiB base.
    mov  byte [rel vtd_bar_alias_fixture_stage], 0x41
    mov  dword [rel vtd_vpci_addr], 0x80000810
    mov  edx, 0xCFC
    call vtd_vpci_in
    cmp  ecx, 0xE3200004
    jne  .cleanup
    mov  byte [rel vtd_bar_alias_fixture_stage], 0x42
    mov  dword [rel vtd_vpci_addr], 0x80000814
    mov  edx, 0xCFC
    call vtd_vpci_in
    test ecx, ecx
    jnz  .cleanup
    mov  byte [rel vtd_bar_alias_fixture_stage], 0x43
    cmp  dword [rel vtd_vpci_guest_bar], 0xE3200004
    jne  .cleanup
    mov  byte [rel vtd_bar_alias_fixture_stage], 0x44
    cmp  dword [rel vtd_vpci_guest_bar + 4], 0
    jne  .cleanup

    ; A different accepted generation cannot consume these writes.
    mov  byte [rel vtd_bar_alias_fixture_stage], 5
    mov  dword [rel vtd_vpci_trace_run_gen], 708
    mov  rdi, 0x0000000100000040
    call vtd_guest_bar_trace_alias_resolve
    test eax, eax
    jnz  .cleanup
    mov  dword [rel vtd_vpci_trace_run_gen], 707

    ; The complete low/high pair now resolves exactly one bounded page from
    ; guest GPA 4 GiB to the saved E3200000 physical BAR.
    mov  rdi, 0x0000000100000040
    call vtd_guest_bar_trace_alias_resolve
    cmp  eax, 1
    jne  .cleanup
    mov  rax, 0x0000000100000000
    cmp  rsi, rax
    jne  .cleanup
    mov  eax, 0xE3200000
    cmp  rdx, rax
    jne  .cleanup
    mov  rdi, [rel vtd_ept_root]
    call vtd_ept_map_bar_page
    cmp  eax, VTD_EPT_MAP_LEAF_WRITTEN
    jne  .cleanup
    call vtd_trace_commit_map
    cmp  byte [rel vtd_ept_pool_used], 4
    jne  .cleanup

    ; The committed mapping makes the same-generation trace selectable.
    mov  rdi, 0x0000000100000040
    call vtd_trace_select_for_ept
    cmp  eax, 1
    jne  .cleanup
    cmp  dword [rel vtd_vpci_trace_gen], 707
    jne  .cleanup
    cmp  dword [rel vtd_vpci_trace_count], 2
    jne  .cleanup
    cmp  dword [rel vtd_vpci_trace_ordinal], 2
    jne  .cleanup
    cmp  byte [rel vtd_vpci_trace_overflow], 0
    jne  .cleanup
    cmp  byte [rel vtd_vpci_bar_index], 0
    jne  .cleanup
    cmp  byte [rel vtd_vpci_cfg_off], 0x14
    jne  .cleanup
    cmp  byte [rel vtd_vpci_pio_width], 4
    jne  .cleanup

    cmp  dword [rel vtd_vpci_write_low], 0x00000004
    jne  .cleanup
    cmp  dword [rel vtd_vpci_write_high], 0x00000001
    jne  .cleanup
    cmp  dword [rel vtd_vpci_shadow_low], 0xE3200004
    jne  .cleanup
    cmp  dword [rel vtd_vpci_shadow_high], 0
    jne  .cleanup
    mov  rax, [rel vtd_vpci_shadow_gpa]
    mov  edx, 0xE3200000
    cmp  rax, rdx
    jne  .cleanup

    mov  byte [rel vtd_bar_alias_fixture_stage], 6
    cmp  dword [rel vtd_vpci_saved_low], 0xE3200004
    jne  .cleanup
    cmp  dword [rel vtd_vpci_saved_high], 0
    jne  .cleanup
    mov  rax, [rel vtd_vpci_saved_hpa]
    mov  edx, 0xE3200000
    cmp  rax, rdx
    jne  .cleanup
    mov  rax, [rel vtd_ept_map_gpa]
    mov  rdx, 0x0000000100000000
    cmp  rax, rdx
    jne  .cleanup
    mov  rax, [rel vtd_ept_map_hpa]
    mov  edx, 0xE3200000
    cmp  rax, rdx
    jne  .cleanup

    ; Walk the new alias leaf: its value names the saved HPA, never the alias.
    mov  rdx, 0x000FFFFFFFFFF000
    mov  rbp, [r13 + 4*8]                 ; PDPT[4] covers GPA 4 GiB
    and  rbp, rdx
    test rbp, rbp
    jz   .cleanup
    mov  rbp, [rbp]                       ; PD[0] -> PT
    and  rbp, rdx
    test rbp, rbp
    jz   .cleanup
    call .want_leaf
    cmp  qword [rbp], rdx                 ; PT[0] -> saved BAR page, R|W|UC
    jne  .cleanup

    ; Saved and proven-alias ranges classify; a neighboring unknown page does
    ; not inherit the alias.
    mov  rdi, 0xE3200040
    call vtd_guest_gpa_is_secondary_bar
    cmp  eax, 1
    jne  .cleanup
    mov  rdi, 0x0000000100000040
    call vtd_guest_gpa_is_secondary_bar
    cmp  eax, 1
    jne  .cleanup
    mov  rdi, 0x0000000100002040
    call vtd_guest_gpa_is_secondary_bar
    test eax, eax
    jnz  .cleanup

    ; The exact saved_hpa+0x40 leaf survives both ignored writes.
    mov  byte [rel vtd_bar_alias_fixture_stage], 7
    call .want_leaf
    cmp  qword [r15], rdx
    jne  .cleanup
    cmp  byte [rel vtd_ept_invept_attempted], 0
    jne  .cleanup
    mov  bl, 1
    mov  byte [rel vtd_bar_alias_fixture_stage], 0
.cleanup:
    call vtd_bar_trace_reset
    cld
    lea  rsi, [rel vtd_fixture_save_cfg]
    lea  rdi, [rel vtd_secondary_cfg + 0x10]
    mov  ecx, 3
    rep  movsq
    lea  rsi, [rel vtd_fixture_save_shadow]
    lea  rdi, [rel vtd_vpci_guest_bar]
    mov  ecx, 3
    rep  movsq
    lea  rsi, [rel vtd_fixture_save_bar_size]
    lea  rdi, [rel vtd_secondary_bar_size]
    mov  ecx, 3
    rep  movsq
    lea  rsi, [rel vtd_fixture_save_bar_probe]
    lea  rdi, [rel vtd_vpci_bar_probe]
    mov  ecx, 6
    rep  movsb
    mov  rax, [rel vtd_fixture_save_root]
    mov  [rel vtd_ept_root], rax
    mov  rax, [rel vtd_fixture_save_pool]
    mov  [rel vtd_ept_pool_base], rax
    mov  rax, [rel vtd_fixture_save_gpr]
    mov  [rel hv_linux_gpr], rax
    mov  eax, [rel vtd_fixture_save_vpci_addr]
    mov  [rel vtd_vpci_addr], eax
    mov  al, [rel vtd_fixture_save_active]
    mov  [rel vtd_vpci_active], al
    mov  al, [rel vtd_fixture_save_pool_used]
    mov  [rel vtd_ept_pool_used], al
    mov  al, [rel vtd_fixture_save_vmx_live]
    mov  [rel hv_linux_vmx_live], al
    mov  [rel vtd_bar_alias_fixture_ok], bl
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDX = the saved BAR page's leaf in the active backend's format (RCQ-18 S2-3):
; EPT 0xE3200003 on VMX, 0x80000000E320001F under NPT. Clobbers RAX, RCX, RDI, R11.
.want_leaf:
    mov  edi, HV_SLAT_MMIO_4K
    call hv_slat_bits
    mov  edx, 0xE3200000
    or   rdx, rax
    ret

; 1012b target-free content fixture. It uses the live dispatch predicate and
; byte-stream parser, never a parallel test-only implementation. It proves:
; stale early carrier cannot latch; DHCP permits probe dispatch; exact zero,
; wrong and missing samples fail closed; a later exact one sample recovers.
vtd_post_dhcp_carrier_fixture_selftest:
    push rbx
    xor  ebx, ebx
    mov  byte [rel vtd_post_dhcp_carrier_fixture_ok], 0
    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 0x10
    call vtd_net_reset_session
    mov  byte [rel vtd_network_mode], 1
    mov  byte [rel vtd_domain_l2_active], 1
    mov  byte [rel vtd_domain_shell_ready], 1
    mov  byte [rel vtd_domain_iface_ready], 1
    mov  byte [rel vtd_net_driver_r8169], 1
    lea  rsi, [rel str_vtd_fixture_carrier_iface]
    lea  rdi, [rel vtd_net_iface]
.copy_iface:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    test al, al
    jnz  .copy_iface
    ; The transparent-L2 route is intentionally admissible with no guest
    ; lease. This is the precise regression gate for 1013b revision 9.
    call vtd_domain_l2_carrier_dispatch_ready
    cmp  eax, 1
    jne  .cleanup
    cmp  byte [rel vtd_net_lease], 0
    jne  .cleanup

    ; Preserve the older DDOM/NAT proof: it still requires the guest's lease
    ; before dispatching its direct post-DHCP carrier measurement.
    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 1
    mov  byte [rel vtd_domain_l2_active], 0
    mov  byte [rel vtd_net_lease], '1'
    mov  byte [rel vtd_net_lease + 1], 0
    call vtd_post_dhcp_carrier_dispatch_ready
    cmp  eax, 1
    jne  .cleanup

    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 2
    lea  rdi, [rel str_vtd_fixture_carrier_stale]
    call vtd_fixture_feed_console
    cmp  byte [rel vtd_net_carrier_early], 1
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier], 0
    jne  .cleanup

    mov  byte [rel vtd_net_carrier_timeout_seen], 1
    mov  byte [rel vtd_net_carrier_probe_dispatched], 1
    mov  byte [rel vtd_net_carrier_probe_pending], 1
    mov  byte [rel vtd_net_marker_carrier], 1
    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 3
    lea  rdi, [rel str_vtd_fixture_carrier_zero]
    call vtd_fixture_feed_console
    cmp  byte [rel vtd_net_carrier_sample_seen], 1
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier], 0
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier_probe_pending], 0
    jne  .cleanup

    mov  byte [rel vtd_net_carrier_sample_seen], 0
    mov  byte [rel vtd_net_carrier_probe_pending], 1
    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 4
    lea  rdi, [rel str_vtd_fixture_carrier_wrong]
    call vtd_fixture_feed_console
    cmp  byte [rel vtd_net_carrier_sample_seen], 0
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier], 0
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier_probe_pending], 1
    jne  .cleanup
    lea  rdi, [rel str_vtd_fixture_carrier_missing]
    call vtd_fixture_feed_console
    cmp  byte [rel vtd_net_carrier_sample_seen], 0
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier_probe_pending], 1
    jne  .cleanup

    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 5
    lea  rdi, [rel str_vtd_fixture_carrier_one]
    call vtd_fixture_feed_console
    cmp  byte [rel vtd_net_carrier_sample_seen], 1
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier], 1
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier_probe_pending], 0
    jne  .cleanup
    cmp  byte [rel vtd_net_carrier_timeout_seen], 1
    jne  .cleanup
    mov  bl, 1
    mov  byte [rel vtd_post_dhcp_carrier_fixture_stage], 0
.cleanup:
    call vtd_net_reset_session
    mov  [rel vtd_post_dhcp_carrier_fixture_ok], bl
    pop  rbx
    ret

; RDI=NUL fixture line. Feed the production byte-stream parser verbatim.
vtd_fixture_feed_console:
    push rbx
    mov  rbx, rdi
.loop:
    mov  al, [rbx]
    test al, al
    jz   .done
    call vtd_guest_console_byte
    inc  rbx
    jmp  .loop
.done:
    pop  rbx
    ret

; 1012a3 memory-only content fixture. It drives the live classifier and
; renderer, proves one resume plus four distinct safe-stop classes, and never
; reads VMCS or touches hardware. The synthetic BAR changes only saved/shadow
; memory and restores both before returning.
vtd_ept_detail_fixture_selftest:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel vtd_ept_detail_fixture_ok], 0
    movzx r12d, byte [rel vtd_vpci_active]
    mov  r13d, [rel hv_linux_start_consumed]
    mov  rbx, [rel vtd_secondary_cfg + 0x10]
    mov  rbp, [rel vtd_secondary_bar_size]
    mov  r15, [rel vtd_vpci_guest_bar]
    movzx r14d, byte [rel vtd_ready]
    movzx eax, byte [rel vtd_secondary_found]
    shl  eax, 8
    or   r14d, eax
    movzx eax, byte [rel vtd_owner_guest]
    shl  eax, 16
    or   r14d, eax
    movzx eax, byte [rel vtd_reclaim_verified]
    shl  eax, 24
    or   r14d, eax

    mov  byte [rel vtd_vpci_active], 1
    mov  dword [rel vtd_secondary_cfg + 0x10], 0xE3200004
    mov  dword [rel vtd_secondary_cfg + 0x14], 0
    mov  dword [rel vtd_secondary_bar_size], 0x1000
    mov  dword [rel vtd_secondary_bar_size + 4], 0
    mov  dword [rel vtd_vpci_guest_bar], 0x00000004
    mov  dword [rel vtd_vpci_guest_bar + 4], 1
    mov  dword [rel hv_linux_start_consumed], 404
    mov  byte [rel vtd_ready], 1
    mov  byte [rel vtd_secondary_found], 1
    mov  byte [rel vtd_owner_guest], 0
    mov  byte [rel vtd_reclaim_verified], 1
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_BOOT_EXIT
    mov  byte [rel vtd_assign_run_req], 0
    mov  byte [rel vtd_assign_task_started], 1
    mov  dword [rel vtd_assign_start_gen], 404
    mov  dword [rel vtd_assign_start_consumed], 404
    mov  byte [rel vtd_assign_load_err], 7
    mov  byte [rel vtd_assign_launch_refused], 0
    mov  byte [rel vtd_assign_vmxon_fail], 0
    mov  byte [rel vtd_assign_vmcs_fail], 0
    mov  dword [rel vtd_assign_instr_err], 0
    mov  dword [rel vtd_assign_vmwrite_fails], 0
    mov  dword [rel vtd_assign_last_exit], 48
    mov  byte [rel vtd_assign_linux_running], 0
    mov  byte [rel vtd_assign_linux_kboot], 0
    mov  byte [rel vtd_assign_vcon_ready], 1
    mov  byte [rel vtd_assign_vcon_rx_ready], 1
    mov  byte [rel vtd_assign_vcon_tx_ready], 1
    mov  byte [rel vtd_assign_inject_accepted], 0
    mov  dword [rel vtd_assign_capture_len], 17
    mov  dword [rel vtd_assign_fsts], 0
    mov  dword [rel vtd_assign_fault_count], 0
    mov  qword [rel vtd_assign_frcd_lo], 0
    mov  qword [rel vtd_assign_frcd_hi], 0

    xor  eax, eax
    call vtd_vpci_bar_sizing_value
    cmp  ecx, 0xFFFFF004
    jne  .cleanup
    mov  eax, 1
    call vtd_vpci_bar_sizing_value
    cmp  ecx, 0xFFFFFFFF
    jne  .cleanup

    ; Valid decoded virtio write: the only case allowed to resume. Preserve a
    ; raw VMCS length of zero to prove decode length is the trusted value.
    mov  edi, HV_VCON_GPA + 0x44
    mov  esi, 2
    xor  edx, edx
    call hv_linux_ept_classify
    cmp  eax, 1
    jne  .cleanup
    mov  edi, 1
    mov  esi, 3
    call hv_linux_ept_note_decode
    cmp  eax, 1
    jne  .cleanup
    call vtd_snapshot_ept_detail
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_ept_resume]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; Known virtio page, but a read access: stop before store decode.
    mov  edi, HV_VCON_GPA + 0x48
    mov  esi, 1
    mov  edx, 3
    call hv_linux_ept_classify
    test eax, eax
    jnz  .cleanup
    call vtd_snapshot_ept_detail
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_ept_access]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; Known virtio write whose store cannot be decoded: distinct safe stop.
    mov  edi, HV_VCON_GPA + 0x4C
    mov  esi, 2
    mov  edx, 3
    call hv_linux_ept_classify
    cmp  eax, 1
    jne  .cleanup
    xor  edi, edi
    xor  esi, esi
    call hv_linux_ept_note_decode
    test eax, eax
    jnz  .cleanup
    call vtd_snapshot_ept_detail
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_ept_decode]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; The immutable saved BAR page is classified even if the rejected guest
    ; relocation shadow contains a different address.
    mov  edi, 0xE3200050
    mov  esi, 2
    mov  edx, 4
    call hv_linux_ept_classify
    test eax, eax
    jnz  .cleanup
    call vtd_snapshot_ept_detail
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_ept_bar]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; An unrelated GPA remains foreign and stops safely.
    mov  edi, 0xFEE000B0
    mov  esi, 4
    mov  edx, 5
    call hv_linux_ept_classify
    test eax, eax
    jnz  .cleanup
    call vtd_snapshot_ept_detail
    call vtd_render_assign_failure
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_fixture_ept_foreign]
    call hv_str_has
    test al, al
    jz   .cleanup
    mov  byte [rel vtd_ept_detail_fixture_ok], 1
.cleanup:
    mov  byte [rel vtd_vpci_active], r12b
    mov  [rel hv_linux_start_consumed], r13d
    mov  [rel vtd_secondary_cfg + 0x10], rbx
    mov  [rel vtd_secondary_bar_size], rbp
    mov  [rel vtd_vpci_guest_bar], r15
    mov  eax, r14d
    mov  [rel vtd_ready], al
    shr  eax, 8
    mov  [rel vtd_secondary_found], al
    shr  eax, 8
    mov  [rel vtd_owner_guest], al
    shr  eax, 8
    mov  [rel vtd_reclaim_verified], al
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_NONE
    mov  byte [rel vtd_assign_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_assign_run_req], 0
    mov  byte [rel vtd_assign_task_started], 0
    mov  byte [rel vtd_assign_load_err], 0
    mov  dword [rel vtd_assign_start_gen], 0
    mov  dword [rel vtd_assign_start_consumed], 0
    mov  dword [rel vtd_assign_last_exit], 0
    mov  qword [rel hv_ept_exit_gpa], 0
    mov  qword [rel hv_ept_exit_qual], 0
    mov  qword [rel hv_ept_exit_rip], 0
    mov  qword [rel hv_ept_exit_gla], 0
    mov  qword [rel hv_ept_exit_insn], 0
    mov  dword [rel hv_ept_exit_ilen], 0
    mov  dword [rel hv_ept_exit_insn_len], 0
    mov  dword [rel hv_ept_exit_decode_len], 0
    mov  dword [rel hv_ept_exit_gen], 0
    mov  byte [rel hv_ept_exit_access], 0
    mov  byte [rel hv_ept_exit_decode], 0
    mov  byte [rel hv_ept_exit_class], 0
    mov  byte [rel hv_ept_exit_action], 0
    mov  byte [rel hv_ept_exit_bar_match], 0
    call vtd_out_reset
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Return EAX=1 only when every guest-proof diagnostic has a fixed field.
vtd_guest_failure_shape_ok:
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_linux_running_field]
    call hv_str_has
    test al, al
    jz   .bad
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_linux_kboot_field]
    call hv_str_has
    test al, al
    jz   .bad
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_vcon_ready_field]
    call hv_str_has
    test al, al
    jz   .bad
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_inject_accepted_field]
    call hv_str_has
    test al, al
    jz   .bad
    lea  rdi, [rel vtd_out_buf]
    lea  rsi, [rel str_vtd_capture_len_field]
    call hv_str_has
    test al, al
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Re-grade the advertised policy from live tables and fault registers.  The
; response never relies on the boot-time marker alone.
vtd_policy_live_ok:
    push rbx
    call vtd_native_nic_current
    test eax, eax
    jz   .bad
    cmp  byte [rel hv_vcon_proof_roll_fixture_ok], 1
    jne  .bad
    cmp  byte [rel vtd_identity_guard_fixture_ok], 1
    jne  .bad
    cmp  byte [rel vtd_failure_fixture_ok], 1
    jne  .bad
    cmp  byte [rel vtd_observability_fixture_ok], 1
    jne  .bad
    cmp  byte [rel vtd_ept_detail_fixture_ok], 1
    jne  .bad
    cmp  byte [rel hv_first_ud_fixture_ok], 1
    jne  .bad
    cmp  byte [rel vtd_bar_alias_fixture_ok], 1
    jne  .bad
    cmp  byte [rel vtd_ready], 1
    jne  .bad
    cmp  byte [rel vtd_enabled], 1
    jne  .bad
    cmp  byte [rel vtd_native_ready], 1
    jne  .bad
    cmp  byte [rel vtd_coverage_before_te], 1
    jne  .bad
    cmp  byte [rel vtd_native_nic_covered], 1
    jne  .bad
    cmp  byte [rel vtd_xhci_covered], 1
    jne  .bad
    cmp  byte [rel vtd_sata_covered], 1
    jne  .bad
    ; An absent NVMe stays explicitly uncovered; it is not a policy failure.
    ; If discovery witnessed one, both its coverage bit and DID-2 context are
    ; still mandatory below.
    cmp  byte [rel vtd_nvme_found], 1
    jne  .coverage_ok
    cmp  byte [rel vtd_nvme_covered], 1
    jne  .bad
.coverage_ok:
    cmp  qword [rel tsc_khz], 0
    je   .bad
    mov  rbx, [rel vtd_unitb_base]
    test rbx, rbx
    jz   .bad
    test dword [rbx + VTD_REG_GSTS], VTD_GSTS_TES
    jz   .bad
    mov  edi, [rel vtd_native_nic_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .bad
    mov  edi, [rel vtd_xhci_bdf]
    call vtd_identity_ctx_ok
    test eax, eax
    jz   .bad
    mov  edi, [rel vtd_sata_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .bad
    cmp  byte [rel vtd_nvme_found], 1
    jne  .faults
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_native_ctx_ok
    test eax, eax
    jz   .bad
.faults:
    call vtd_capture_faults
    cmp  dword [rel vtd_fsts], 0
    jne  .bad
    cmp  dword [rel vtd_fault_count], 0
    jne  .bad
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Publish the constants actually used by the wait/deadman code rather than a
; duplicated example string.  The public probe independently enforces the host
; receive window outside both values.
vtd_append_policy_budgets:
    lea  rdi, [rel str_vtd_guest_boot_allow_field]
    call vtd_out_str
    mov  edi, VTD_GUEST_BOOT_ALLOW_MS
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ownership_deadman_field]
    call vtd_out_str
    mov  edi, VTD_DEADMAN_MS
    call vtd_out_dec
    ; SEC-D4 (RC spec 10: missing isolation is never represented as protection).
    ; "covered" means a context entry exists; host devices are IDENTITY-mapped
    ; (DMA to all memory), only the assigned guest device is restricted, and no
    ; interrupt remapping is programmed, so a guest-driven device's MSI writes
    ; are not isolated.
    lea  rdi, [rel str_vtd_policy_truth]
    cmp  byte [rel vtd_ir_on], 1
    jne  .truth
    lea  rdi, [rel str_vtd_policy_truth_ir]
.truth:
    call vtd_out_str
    cmp  byte [rel vtd_ir_on], 1
    je   .reason_done
    lea  rdi, [rel str_vtd_ir_reason_field]  ; why remapping is absent (VTD_IR_R_*)
    call vtd_out_str
    movzx edi, byte [rel vtd_ir_reason]
    call vtd_out_dec
.reason_done:
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    ret

; DDOM NET delegates ownership through 1012 and waits for durable guest
; evidence. START is asynchronous because guest wall time is intentionally
; dilated; STOP always traverses the canonical reclaim routine.
vtd_ddom_command:
    push rbx
    push r12
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    lea  rsi, [rel str_ddom_net_start]
    call hv_tok_is
    test al, al
    jnz  .start
    mov  rdi, rbx
    lea  rsi, [rel str_ddom_net_stat]
    call hv_tok_is
    test al, al
    jnz  .stat
    mov  rdi, rbx
    lea  rsi, [rel str_ddom_net_stop]
    call hv_tok_is
    test al, al
    jnz  .stop
    mov  rdi, rbx
    lea  rsi, [rel str_ddom_net_fault]
    call hv_tok_is
    test al, al
    jnz  .fault
    call vtd_out_reset
    lea  rdi, [rel str_ddom_usage]
    call vtd_out_str
    jmp  .ready

.start:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .media_busy                       ; RCQ-37: no driver domain under the media owner
%endif
%endif
    cmp  byte [rel vtd_net_task_active], 1
    je   .busy
    cmp  byte [rel vtd_net_start_pending], 1
    je   .busy
    cmp  byte [rel vtd_owner_guest], 1
    je   .busy
    cmp  byte [rel vtd_dd_state], VTD_DD_RECOVERING
    je   .busy                           ; a standing domain holds the backoff slot
    call vtd_net_reset_session
    mov  rdi, rbx
    mov  ecx, 2
    call vtd_after_tokens
    mov  rdi, rax
    call guestnet_physical_dataplane_step
    test rax, rax
    jz   .bad_args
    mov  [rel vtd_net_command_ptr], rax
    mov  rdi, rbx
    mov  ecx, 2
    call vtd_after_tokens
    mov  rdi, rax
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_args
    mov  byte [rel vtd_network_mode], 1
    mov  byte [rel vtd_net_start_pending], 1
    cmp  byte [rel vtd_net_task_started], 1
    je   .start_queued
    lea  rdi, [rel vtd_net_task]
    call sched_spawn
    cmp  eax, -1
    je   .spawn_failed
    mov  byte [rel vtd_net_task_started], 1
.start_queued:
    call vtd_out_reset
    lea  rdi, [rel str_ddom_start_ok]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    call vtd_append_net_fields
    jmp  .ready
.spawn_failed:
    mov  byte [rel vtd_net_start_pending], 0
    mov  byte [rel vtd_network_mode], 0
    call vtd_out_reset
    lea  rdi, [rel str_ddom_spawn_fail]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    jmp  .ready
.busy:
    call vtd_out_reset
    lea  rdi, [rel str_ddom_busy]
    call vtd_out_str
    jmp  .ready
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
.media_busy:
    call vtd_out_reset
    lea  rdi, [rel str_ddom_media_busy]
    call vtd_out_str
    jmp  .ready
%endif
%endif

.stat:
    call vtd_capture_faults
    call vtd_render_net_stat
    jmp  .ready

.stop:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .media_busy                       ; RCQ-37: never stops the media owner's guest
%endif
%endif
    mov  rdi, rbx
    mov  ecx, 2
    call vtd_after_tokens
    mov  rdi, rax
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_args
    mov  byte [rel vtd_dd_state], VTD_DD_IDLE
    mov  byte [rel vtd_net_start_pending], 0
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_linux_stop_req], 1
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_reclaim_internal
    test eax, eax
    jz   .stop_failed
    call vtd_out_reset
    lea  rdi, [rel str_ddom_stop_ok]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    call vtd_append_net_fields
    jmp  .ready
.stop_failed:
    call vtd_out_reset
    lea  rdi, [rel str_ddom_stop_fail]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    call vtd_append_net_fields
    jmp  .ready

; RCQ-19 witness: NET FAULT crash|hang <nonce> breaks a SERVING domain from
; inside the guest (the shell is PID 1: "exit" kills init; downing the bridge
; stops the data path with the vCPU alive). Recovery is the lease's job; this
; only records when the fault was injected.
.fault:
    mov  rdi, rbx
    mov  ecx, 3
    call vtd_after_tokens
    mov  rdi, rax
    call vtd_copy_nonce
    test eax, eax
    jz   .fault_bad_args
    mov  rdi, rbx
    mov  ecx, 2
    call vtd_after_tokens
    mov  rbx, rax                        ; the fault kind token
    mov  rdi, rbx
    lea  rsi, [rel str_ddom_fault_crash]
    call hv_tok_is
    test al, al
    jnz  .fault_crash
    mov  rdi, rbx
    lea  rsi, [rel str_ddom_fault_hang]
    call hv_tok_is
    test al, al
    jz   .fault_bad_args
    mov  byte [rel vtd_dd_fault_kind], VTD_DD_FAULT_HANG
    lea  rbx, [rel str_vtd_dd_hang_cmd]
    jmp  .fault_state
.fault_crash:
    mov  byte [rel vtd_dd_fault_kind], VTD_DD_FAULT_CRASH
    lea  rbx, [rel str_vtd_dd_crash_cmd]
.fault_state:
    cmp  byte [rel vtd_dd_state], VTD_DD_SERVING
    jne  .fault_refused
    mov  rdi, rbx
    call hv_vcon_rx_line
    test eax, eax
    jz   .fault_busy
    call tsc_now
    mov  [rel vtd_dd_fault_tsc], rax
    inc  dword [rel vtd_dd_faults]
    lea  rdi, [rel str_vtd_dd_fault_log]
    call serial_string
    call vtd_out_reset
    lea  rdi, [rel str_ddom_fault_ok]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    call vtd_append_net_fields
    jmp  .ready
.fault_busy:                             ; RCQ-19 C2: every use is logged
    lea  rdi, [rel str_vtd_dd_fault_busy_log]
    call serial_string
    call vtd_out_reset
    lea  rdi, [rel str_ddom_fault_busy]
    jmp  .fault_reply
.fault_refused:
    lea  rdi, [rel str_vtd_dd_fault_refused_log]
    call serial_string
    call vtd_out_reset
    lea  rdi, [rel str_ddom_fault_refused]
.fault_reply:
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    call vtd_append_net_fields
    jmp  .ready

.fault_bad_args:
    lea  rdi, [rel str_vtd_dd_fault_args_log]
    call serial_string
    jmp  .bad_args
.bad_args:
    call vtd_out_reset
    lea  rdi, [rel str_ddom_bad_args]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

; Persistent worker owns the slow guest run so START can acknowledge promptly.
vtd_net_task:
.loop:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .yield                            ; RCQ-37: nothing runs while the media owner holds the seam
%endif
%endif
    call vtd_dd_supervise                ; RCQ-19: due relaunch of a standing domain
    cmp  byte [rel vtd_net_start_pending], 1
    jne  .yield
    mov  byte [rel vtd_net_start_pending], 0
    cmp  byte [rel vtd_network_mode], 1
    jne  .yield
    mov  byte [rel vtd_net_task_active], 1
    mov  byte [rel vtd_net_task_result], 0
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_CONTEXT_ASSIGN
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_assign_context_only
    test eax, eax
    jz   .failed
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    call vtd_guest_proof
    test eax, eax
    jz   .failed
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_IOMMU_FAULT
    call vtd_capture_faults
    cmp  dword [rel vtd_fsts], 0
    jne  .failed_captured
    cmp  dword [rel vtd_fault_count], 0
    jne  .failed_captured
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_NONE
    call vtd_dd_on_proof_ok
    mov  byte [rel vtd_net_task_result], 1
    mov  byte [rel vtd_net_task_active], 0
    jmp  .yield
.failed:
    call vtd_capture_faults
.failed_captured:
    call vtd_snapshot_assign_failure
    ; A relaunched generation that fails its proof spends restart budget; a
    ; failure the deadman already handled keeps its RECOVERING custody. Any
    ; other start (first start, or an owner proof run after EXHAUSTED) keeps
    ; the original fail-and-reclaim semantics (RCQ-19 R2). STRANDED never gets
    ; here: DDOM START refuses while the guest owns the function, and DOMAINNET
    ; START resets the state.
    cmp  byte [rel vtd_dd_state], VTD_DD_RESTARTING
    je   .dd_failed
    cmp  byte [rel vtd_dd_state], VTD_DD_RECOVERING
    je   .dd_settled
    mov  byte [rel vtd_dd_state], VTD_DD_IDLE
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_reclaim_internal
    mov  byte [rel vtd_net_task_result], 2
    mov  byte [rel vtd_net_task_active], 0
    jmp  .yield
.dd_failed:
    mov  edi, VTD_DD_CAUSE_PROOF
    call vtd_dd_fail
.dd_settled:
    mov  byte [rel vtd_net_task_result], 2
    mov  byte [rel vtd_net_task_active], 0
.yield:
    call sched_yield
    jmp  .loop

vtd_net_reset_session:
    mov  byte [rel vtd_network_mode], 0
    mov  byte [rel vtd_net_start_pending], 0
    mov  byte [rel vtd_net_task_active], 0
    mov  dword [rel vtd_deadman_limit_ms], VTD_DEADMAN_MS
    mov  byte [rel vtd_reclaim_verified], 0
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_guest_inject_accepted], 0
    mov  byte [rel vtd_guest_vendor_seen], 0
    mov  byte [rel vtd_guest_echo_seen], 0
    mov  byte [rel vtd_net_driver_r8169], 0
    mov  byte [rel vtd_net_carrier], 0
    mov  byte [rel vtd_net_carrier_early], 0
    mov  byte [rel vtd_net_gateway_arp], 0
    mov  byte [rel vtd_net_udp_sent], 0
    mov  byte [rel vtd_net_marker_carrier], 0
    mov  byte [rel vtd_net_marker_dhcp], 0
    mov  byte [rel vtd_net_marker_udp], 0
    mov  byte [rel vtd_net_service_result], 0
    mov  byte [rel vtd_net_task_result], 0
    mov  byte [rel vtd_domain_l2_active], 0
    mov  byte [rel vtd_domain_bridge_ready], 0
    mov  byte [rel vtd_domain_bridge_stage], VTD_DOMAIN_STAGE_NONE
    mov  byte [rel vtd_domain_shell_cmd_dispatched], 0
    mov  byte [rel vtd_domain_iface_cmd_dispatched], 0
    mov  byte [rel vtd_domain_shell_ready], 0
    mov  byte [rel vtd_domain_iface_ready], 0
    mov  byte [rel vtd_domain_iface_parse], 0
    mov  byte [rel vtd_domain_iface_len], 0
    mov  byte [rel vtd_domain_iface_fail_parse], 0
    mov  byte [rel vtd_domain_iface_fail_iface_len], 0
    mov  byte [rel vtd_domain_iface_fail_reason_len], 0
    mov  byte [rel vtd_domain_iface_attempts], 0
    mov  byte [rel vtd_domain_iface_result], VTD_DOMAIN_IFACE_RESULT_NONE
    mov  qword [rel vtd_domain_iface_next_tsc], 0
    mov  byte [rel vtd_domain_iface_fail_reason], 0
    mov  byte [rel vtd_deadman_fired], 0
    mov  byte [rel vtd_net_carrier_timeout_seen], 0
    mov  byte [rel vtd_net_cwait_enter_seen], 0
    mov  byte [rel vtd_net_cwait_tick_seen], 0
    mov  byte [rel vtd_net_cwait_carr_seen], 0
    mov  byte [rel vtd_net_uplink_line], 0
    mov  byte [rel vtd_net_carrier_line], 0
    mov  byte [rel vtd_net_lease_parse], 0
    mov  byte [rel vtd_net_lease_len], 0
    mov  byte [rel vtd_net_lease_iface_len], 0
    mov  byte [rel vtd_net_carrier_probe_dispatched], 0
    mov  byte [rel vtd_net_carrier_probe_pending], 0
    mov  byte [rel vtd_net_carrier_sample_seen], 0
    mov  byte [rel vtd_net_carrier_now_parse], 0
    mov  byte [rel vtd_net_carrier_now_iface_len], 0
    mov  byte [rel vtd_net_carrier_now_value], 0xFF
    mov  byte [rel vtd_net_lease], 0
    mov  byte [rel vtd_net_iface], 0
    mov  byte [rel vtd_net_carrier_now_iface], 0
    mov  qword [rel vtd_net_command_ptr], 0
    mov  dword [rel vtd_net_timer_due], 0
    mov  dword [rel vtd_net_timer_injections], 0
    mov  dword [rel vtd_net_irq0_deferrals], 0
    mov  dword [rel vtd_net_irq_attempts], 0
    mov  dword [rel vtd_net_irq_injections], 0
    mov  dword [rel vtd_net_irq_reject_entry], 0
    mov  dword [rel vtd_net_irq_reject_vec], 0
    mov  dword [rel vtd_net_irq_reject_mask], 0
    mov  dword [rel vtd_net_irq_reject_if0], 0
    mov  dword [rel vtd_net_irq_reject_shadow], 0
    mov  dword [rel vtd_net_intr_window_arms], 0
    mov  dword [rel vtd_net_intr_window_exits], 0
    mov  dword [rel vtd_net_command_writes], 0
    mov  dword [rel vtd_net_phy_edge_predelays], 0
    mov  dword [rel vtd_net_phy_edge_fires], 0
    mov  dword [rel vtd_net_phy_edge_txblocks], 0
    mov  dword [rel vtd_net_phy_edge_txown], 0
    mov  word [rel vtd_net_irq_level], 0
    mov  word [rel vtd_net_irq_pending], 0
    mov  word [rel vtd_net_imr], 0
    mov  word [rel vtd_net_isr], 0
    mov  word [rel vtd_net_phy_edge_isr], 0
    mov  word [rel vtd_net_phy_edge_imr], 0
    mov  byte [rel vtd_net_chipcmd], 0
    mov  byte [rel vtd_net_physts], 0
    mov  byte [rel vtd_net_phy_edge_state], 0
    mov  byte [rel vtd_net_phy_edge_physts], 0
    mov  byte [rel vtd_net_phy_edge_chipcmd], 0
    mov  byte [rel vtd_net_phy_edge_tppoll], 0
    mov  byte [rel vtd_net_phy_edge_txring], 0
    mov  byte [rel vtd_net_phy_edge_linkchg_seen], 0
    mov  byte [rel vtd_net_phy_edge_linkchg_injected], 0
    mov  qword [rel vtd_net_phy_edge_tnpds], 0
    mov  byte [rel vtd_net_intr_window_armed], 0
    lea  rdi, [rel vtd_net_match_uplink]
    xor  eax, eax
    mov  ecx, 16
    cld
    rep  stosb
    ret

; RCQ-19 standing-domain receipt: " dd_state=<name> dd_gen=N dd_restarts=N
; dd_budget_left=N dd_cause=<name> dd_detect_ms=N dd_restore_ms=N
; dd_lease_ms=5000 dd_faults=N dd_renewals=N dd_probes=N" plus the verdict of
; the last isolation precondition (not re-read while the guest owns it).
vtd_append_dd_fields:
    lea  rdi, [rel str_vtd_dd_state]
    call vtd_out_str
    movzx eax, byte [rel vtd_dd_state]
    cmp  eax, VTD_DD_STRANDED
    jbe  .state
    mov  eax, VTD_DD_STRANDED + 1
.state:
    imul eax, eax, VTD_DD_NAME_STRIDE
    lea  rdi, [rel vtd_dd_state_names]
    add  rdi, rax
    call vtd_out_str
    lea  rdi, [rel str_vtd_dd_gen]
    call vtd_out_str
    mov  edi, [rel vtd_dd_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_restarts]
    call vtd_out_str
    mov  edi, [rel vtd_dd_restarts]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_budget_left]
    call vtd_out_str
    call vtd_dd_budget_left
    mov  edi, eax
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_cause]
    call vtd_out_str
    movzx eax, byte [rel vtd_dd_cause]
    cmp  eax, VTD_DD_CAUSE_BOOT
    jbe  .cause
    mov  eax, VTD_DD_CAUSE_BOOT + 1
.cause:
    imul eax, eax, VTD_DD_NAME_STRIDE
    lea  rdi, [rel vtd_dd_cause_names]
    add  rdi, rax
    call vtd_out_str
    lea  rdi, [rel str_vtd_dd_detect_ms]
    call vtd_out_str
    mov  edi, [rel vtd_dd_detect_ms]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_restore_ms]
    call vtd_out_str
    mov  edi, [rel vtd_dd_restore_ms]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_lease_ms]
    call vtd_out_str
    mov  edi, VTD_DD_LEASE_MS
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_faults]
    call vtd_out_str
    mov  edi, [rel vtd_dd_faults]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_failures]
    call vtd_out_str
    mov  edi, [rel vtd_dd_failures]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_renewals]
    call vtd_out_str
    mov  edi, [rel vtd_dd_renewals]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_probes]
    call vtd_out_str
    mov  edi, [rel vtd_dd_probes]
    call vtd_out_dec
    ; refusal=<assignment>.<its handoff reset>.<last reset>.<last reset method>:
    ; VTD_REFUSE_* codes, then 0 none / 1 FLR / 2 SBR. Numbers, not names: the
    ; whole DDOM NET STAT line must fit one reply under the widest ARG.
    lea  rdi, [rel str_ddom_refusal]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_refusal]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_refusal_dot]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_reset_refusal]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_refusal_dot]
    call vtd_out_str
    movzx edi, byte [rel vtd_reset_refusal]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_refusal_dot]
    call vtd_out_str
    movzx edi, byte [rel vtd_reset_method]
    call vtd_out_dec
    call vtd_append_iso_fields
    ret

; VTD POLICY: the isolation verdict for the secondary function as assignment
; would see it now, and the standing-domain lease and restart budget.
vtd_append_policy_isolation:
    cmp  byte [rel vtd_owner_guest], 1
    je   .fields                         ; keep the verdict taken at assignment
    call vtd_iso_check
.fields:
    call vtd_append_iso_fields
    lea  rdi, [rel str_vtd_dd_policy_lease]
    call vtd_out_str
    mov  edi, VTD_DD_LEASE_MS
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_policy_budget]
    call vtd_out_str
    mov  edi, VTD_DD_BUDGET
    call vtd_out_dec
    lea  rdi, [rel str_vtd_dd_policy_window]
    call vtd_out_str
    mov  edi, VTD_DD_WINDOW_MS
    call vtd_out_dec
    ret

vtd_render_net_stat:
    call vtd_out_reset
    lea  rdi, [rel str_ddom_stat_head]
    call vtd_out_str
    call vtd_append_net_fields
    ret

vtd_append_net_fields:
    lea  rdi, [rel str_ddom_vendor]
    call vtd_out_str
    lea  rdi, [rel str_ddom_owner]
    call vtd_out_str
    cmp  byte [rel vtd_owner_guest], 1
    jne  .owner_host
    lea  rdi, [rel str_vtd_guest]
    call vtd_out_str
    jmp  .carrier
.owner_host:
    lea  rdi, [rel str_vtd_host]
    call vtd_out_str
.carrier:
    call vtd_append_dd_fields
    lea  rdi, [rel str_ddom_carrier]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_carrier]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_lease]
    call vtd_out_str
    cmp  byte [rel vtd_net_lease], 0
    je   .no_lease
    lea  rdi, [rel vtd_net_lease]
    call vtd_out_str
    jmp  .arp
.no_lease:
    lea  rdi, [rel str_ddom_zero_ip]
    call vtd_out_str
.arp:
    lea  rdi, [rel str_ddom_gateway_arp]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_gateway_arp]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_driver]
    call vtd_out_str
    cmp  byte [rel vtd_net_driver_r8169], 1
    jne  .no_driver
    lea  rdi, [rel str_vtd_net_r8169]
    call vtd_out_str
    jmp  .udp
.no_driver:
    lea  rdi, [rel str_ddom_none]
    call vtd_out_str
.udp:
    lea  rdi, [rel str_ddom_udp_sent]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_udp_sent]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_timer_due]
    call vtd_out_str
    mov  edi, [rel vtd_net_timer_due]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_timer_injected]
    call vtd_out_str
    mov  edi, [rel vtd_net_timer_injections]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq_attempts]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_attempts]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_injections]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq_reject_entry]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_reject_entry]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq_reject_vec]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_reject_vec]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq_reject_mask]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_reject_mask]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq_reject_if0]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_reject_if0]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq_reject_shadow]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq_reject_shadow]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pic_mask]
    call vtd_out_str
    movzx edi, byte [rel hv_pic_mask]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pic_vec]
    call vtd_out_str
    movzx edi, byte [rel hv_pic_vec_base]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_intx_armed]
    call vtd_out_str
    xor  edi, edi
    cmp  byte [rel hv_pic_vec_base], 0
    je   .intx_value
    test byte [rel hv_pic_mask], (1 << VTD_NET_GUEST_IRQ)
    jnz  .intx_value
    test byte [rel vtd_secondary_cfg + 4], 0x04
    jz   .intx_value
    test word [rel vtd_secondary_cfg + 4], 0x0400
    jnz  .intx_value
    mov  edi, 1
.intx_value:
    call vtd_out_dec
    lea  rdi, [rel str_ddom_vpci_cmd]
    call vtd_out_str
    movzx edi, word [rel vtd_secondary_cfg + 4]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_command_writes]
    call vtd_out_str
    mov  edi, [rel vtd_net_command_writes]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_iw_arms]
    call vtd_out_str
    mov  edi, [rel vtd_net_intr_window_arms]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_iw_exits]
    call vtd_out_str
    mov  edi, [rel vtd_net_intr_window_exits]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_irq0_deferrals]
    call vtd_out_str
    mov  edi, [rel vtd_net_irq0_deferrals]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_te]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_chipcmd]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_imr]
    call vtd_out_str
    movzx edi, word [rel vtd_net_imr]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_isr]
    call vtd_out_str
    movzx edi, word [rel vtd_net_isr]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_physts]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_physts]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pcfired]
    call vtd_out_str
    mov  edi, [rel vtd_net_phy_edge_fires]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pcpredelay]
    call vtd_out_str
    mov  edi, [rel vtd_net_phy_edge_predelays]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pctxblock]
    call vtd_out_str
    mov  edi, [rel vtd_net_phy_edge_txblocks]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pctxring]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_phy_edge_txring]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pctxown]
    call vtd_out_str
    mov  edi, [rel vtd_net_phy_edge_txown]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pctppoll]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_phy_edge_tppoll]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pcchipcmd]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_phy_edge_chipcmd]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pcimr]
    call vtd_out_str
    movzx edi, word [rel vtd_net_phy_edge_imr]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pcphysts]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_phy_edge_physts]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pcisr]
    call vtd_out_str
    movzx edi, word [rel vtd_net_phy_edge_isr]
    call vtd_out_hex_compact
    lea  rdi, [rel str_ddom_pclive]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_phy_edge_linkchg_seen]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_pcinj]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_phy_edge_linkchg_injected]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_cwait_enter]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_cwait_enter_seen]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_cwait_tick]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_cwait_tick_seen]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_cwait_carr]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_cwait_carr_seen]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_ctmo]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_carrier_timeout_seen]
    call vtd_out_dec
    lea  rdi, [rel str_ddom_reclaim]
    call vtd_out_str
    cmp  byte [rel vtd_reclaim_verified], 1
    jne  .reclaim_pending
    lea  rdi, [rel str_ddom_verified]
    call vtd_out_str
    jmp  .task
.reclaim_pending:
    lea  rdi, [rel str_ddom_pending]
    call vtd_out_str
.task:
    lea  rdi, [rel str_ddom_task]
    call vtd_out_str
    movzx edi, byte [rel vtd_net_task_result]
    call vtd_out_dec
    cmp  byte [rel vtd_net_task_result], 2
    jne  .line_end
    lea  rdi, [rel str_ddom_fail_stage]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_fail_stage]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_guest_stage_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_guest_stage]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_last_exit_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_last_exit]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_gpa_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_gpa]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ept_class_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_class]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_action_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_action]
    call vtd_out_dec
    cmp  dword [rel vtd_assign_last_exit], 48
    jne  .line_end
    lea  rdi, [rel str_vtd_ept_qual_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_qual]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ept_access_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_access]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_ilen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_ilen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_decode_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_decode]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_decode_len_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_decode_len]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_exit_rip_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_exit_rip]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_exit_gla_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_exit_gla]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_exit_insn_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_exit_insn]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_exit_insn_len_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_exit_insn_len]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_bar_match_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_bar_match]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_trace_ordinal_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_trace_ordinal]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_trace_count_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_trace_count]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_cfg_off_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vpci_cfg_off]
    call vtd_out_dec
    call vtd_append_raw_bar_receipt
.line_end:
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    ret

; Append all six immutable saved BARs, guest-visible readbacks, and measured
; apertures from the failure snapshot. Avoid static symbol-pointer tables:
; baked dq symbol values are not runtime VAs in PaOS PE images.
vtd_append_raw_bar_receipt:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
    lea  r12, [rel vtd_assign_saved_bar]
    lea  r13, [rel str_vtd_raw_saved_bar_field]
.saved:
    cmp  ebx, 6
    jae  .guest_setup
    mov  rdi, r13
    call vtd_out_str
    mov  edi, ebx
    call vtd_out_dec
    lea  rdi, [rel str_vtd_raw_hex_value]
    call vtd_out_str
    mov  edi, [r12 + rbx*4]
    call vtd_out_hex_compact
    inc  ebx
    jmp  .saved
.guest_setup:
    xor  ebx, ebx
    lea  r12, [rel vtd_assign_guest_bar]
    lea  r13, [rel str_vtd_raw_guest_bar_field]
.guest:
    cmp  ebx, 6
    jae  .size_setup
    mov  rdi, r13
    call vtd_out_str
    mov  edi, ebx
    call vtd_out_dec
    lea  rdi, [rel str_vtd_raw_hex_value]
    call vtd_out_str
    mov  edi, [r12 + rbx*4]
    call vtd_out_hex_compact
    inc  ebx
    jmp  .guest
.size_setup:
    xor  ebx, ebx
    lea  r12, [rel vtd_assign_bar_size]
    lea  r13, [rel str_vtd_raw_bar_size_field]
.size:
    cmp  ebx, 6
    jae  .done
    mov  rdi, r13
    call vtd_out_str
    mov  edi, ebx
    call vtd_out_dec
    lea  rdi, [rel str_vtd_raw_hex_value]
    call vtd_out_str
    mov  edi, [r12 + rbx*4]
    call vtd_out_hex_compact
    inc  ebx
    jmp  .size
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

vtd_command:
    push rbx
    push r12
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    lea  rsi, [rel dg_s_keyword]
    call hv_tok_is
    test al, al
    jnz  .groups
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_policy]
    call hv_tok_is
    test al, al
    jnz  .policy
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_coverage]
    call hv_tok_is
    test al, al
    jnz  .coverage
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_stat]
    call hv_tok_is
    test al, al
    jnz  .stat
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_trace_first_ud]
    call hv_tok_is
    test al, al
    jnz  .trace_first_ud
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_trace_context]
    call hv_tok_is
    test al, al
    jnz  .trace_context
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_trace]
    call hv_tok_is
    test al, al
    jnz  .trace
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_diag_first_ud]
    call hv_tok_is
    test al, al
    jnz  .diag_first_ud
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_assign]
    call hv_tok_is
    test al, al
    jnz  .assign
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_reclaim]
    call hv_tok_is
    test al, al
    jnz  .reclaim
    mov  rdi, rbx
    lea  rsi, [rel str_vtd_deadman]
    call hv_tok_is
    test al, al
    jnz  .deadman
    call vtd_out_reset
    lea  rdi, [rel str_vtd_usage]
    call vtd_out_str
    jmp  .ready

.groups:
    mov  rdi, rbx
    call vtd_groups_request
    jmp  .ready

.policy:
    call vtd_out_reset
    call vtd_policy_live_ok
    test eax, eax
    jz   .policy_missing
    cmp  byte [rel vtd_nvme_found], 1
    jne  .policy_no_nvme
    lea  rdi, [rel str_vtd_policy_ok]
    call vtd_out_str
    call vtd_append_policy_isolation
    call vtd_append_policy_budgets
    jmp  .ready
.policy_no_nvme:
    lea  rdi, [rel str_vtd_policy_ok_no_nvme]
    call vtd_out_str
    call vtd_append_policy_isolation
    call vtd_append_policy_budgets
    jmp  .ready
.policy_missing:
    lea  rdi, [rel str_vtd_policy_missing]
    call vtd_out_str
    call vtd_append_policy_isolation
    call vtd_append_policy_budgets
    jmp  .ready

.coverage:
    ; Retained boot RAM only: unlike STAT, never capture live fault registers.
    call vtd_out_reset
    lea  rdi, [rel str_vtd_cov_head]
    call vtd_out_str
    call vtd_append_coverage_record
    call vtd_append_probe_steps
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    jmp  .ready

.stat:
    call vtd_capture_faults
    call vtd_render_stat
    jmp  .ready

.trace:
    call vtd_render_trace
    jmp  .ready
.trace_first_ud:
    call vtd_render_first_ud_trace
    jmp  .ready
.trace_context:
    call vtd_render_first_ud_context
    jmp  .ready

.assign:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .media_busy                       ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    mov  byte [rel vtd_first_ud_diag_requested], 0
    mov  dword [rel vtd_first_ud_diag_gen], 0
    mov  rdi, rbx
    mov  ecx, 2
    jmp  .assign_nonce
.diag_first_ud:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .media_busy
%endif
%endif
    mov  byte [rel vtd_first_ud_diag_requested], 1
    mov  dword [rel vtd_first_ud_diag_gen], 0
    mov  rdi, rbx
    mov  ecx, 3
.assign_nonce:
    call vtd_after_tokens
    mov  rdi, rax
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce
    call vtd_build_guest_strings
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_CONTEXT_ASSIGN
    mov  byte [rel vtd_guest_stage], VTD_GUEST_STAGE_NONE
    mov  byte [rel vtd_guest_inject_accepted], 0
    mov  byte [rel vtd_guest_vendor_seen], 0
    mov  byte [rel vtd_guest_echo_seen], 0
    mov  byte [rel vtd_reset_verified], 0
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_assign_context_only
    test eax, eax
    jz   .assign_failed
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    call vtd_guest_proof
    test eax, eax
    jz   .assign_failed
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_IOMMU_FAULT
    call vtd_capture_faults
    cmp  dword [rel vtd_fsts], 0
    jne  .assign_failed_captured
    cmp  dword [rel vtd_fault_count], 0
    jne  .assign_failed_captured
    mov  byte [rel vtd_assign_fail_stage], VTD_FAIL_NONE
    call vtd_out_reset
    lea  rdi, [rel str_vtd_assign_ok]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_assign_tail]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_assign_end]
    call vtd_out_str
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    jmp  .ready
.assign_failed:
    call vtd_capture_faults
.assign_failed_captured:
    call vtd_snapshot_assign_failure
    ; Snapshot first so run_req=1 remains diagnostic evidence for an
    ; unconsumed generation, then cancel it before ownership is reclaimed.
    mov  byte [rel hv_linux_run_req], 0
    ; Context/quiesce/guest/fault failures can deliberately retain owner=guest.
    ; Always retry canonical reclaim, but render the pre-reclaim fault evidence.
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_reclaim_internal
    call vtd_render_assign_failure
    jmp  .ready

.reclaim:
    mov  rdi, rbx
    mov  ecx, 2
    call vtd_after_tokens
    mov  rdi, rax
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce
    mov  byte [rel vtd_dd_state], VTD_DD_IDLE   ; an owner reclaim ends the service
    mov  byte [rel vtd_reclaim_verified], 0
    call vtd_reclaim_internal
    test eax, eax
    jz   .reclaim_fail
    call vtd_out_reset
    lea  rdi, [rel str_vtd_reclaim_ok]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_owner_host]
    call vtd_out_str
    jmp  .ready
.reclaim_fail:
    call vtd_out_reset
    lea  rdi, [rel str_vtd_reclaim_fail]
    call vtd_out_str
    jmp  .ready

.deadman:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .media_busy                       ; RCQ-37: no function assignment under the media owner
%endif
%endif
    mov  rdi, rbx
    mov  ecx, 3
    call vtd_after_tokens
    mov  rdi, rax
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce
    mov  byte [rel vtd_deadman_fired], 0
    call vtd_assign_context_only
    test eax, eax
    jz   .deadman_fail
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jnz  .dm_scaled
    mov  rdx, 1000000
.dm_scaled:
    imul rdx, VTD_DEADMAN_MS + 1
    call tsc_now
    sub  rax, rdx
    mov  [rel vtd_deadman_tsc], rax
    call vtd_deadman_check
    cmp  byte [rel vtd_deadman_fired], 1
    jne  .deadman_fail
    cmp  byte [rel vtd_owner_guest], 0
    jne  .deadman_fail
    call vtd_out_reset
    lea  rdi, [rel str_vtd_deadman_ok]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_deadman_tail]
    call vtd_out_str
    jmp  .ready
.deadman_fail:
    call vtd_reclaim_internal
    call vtd_out_reset
    lea  rdi, [rel str_vtd_deadman_fail]
    call vtd_out_str
    jmp  .ready

%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
.media_busy:
    call vtd_out_reset
    lea  rdi, [rel str_vtd_media_busy]
    call vtd_out_str
    jmp  .ready
%endif
%endif
.bad_nonce:
    call vtd_out_reset
    lea  rdi, [rel str_vtd_bad_nonce]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

vtd_render_stat:
    call vtd_out_reset
    lea  rdi, [rel str_vtd_stat_head]
    call vtd_out_str
    cmp  byte [rel vtd_ready], 1
    jne  .unavailable
    cmp  byte [rel vtd_secondary_found], 1
    jne  .unavailable
    cmp  byte [rel vtd_owner_guest], 1
    jne  .host
    lea  rdi, [rel str_vtd_guest]
    call vtd_out_str
    jmp  .fault
.host:
    lea  rdi, [rel str_vtd_host]
    call vtd_out_str
    jmp  .fault
.unavailable:
    lea  rdi, [rel str_vtd_unavailable]
    call vtd_out_str
.fault:
    ; Bind readiness to live topology. A zero BDF is evidence of absence only
    ; with nvme_found=0; the attach paths never consume it as a requester.
    lea  rdi, [rel str_vtd_nvme_found]
    call vtd_out_str
    movzx edi, byte [rel vtd_nvme_found]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_nvme_bdf]
    call vtd_out_str
    mov  edi, [rel vtd_nvme_bdf]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_fsts]
    call vtd_out_str
    mov  edi, [rel vtd_fsts]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_faults]
    call vtd_out_str
    mov  edi, [rel vtd_fault_count]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_frcd_lo]
    call vtd_out_str
    mov  rdi, [rel vtd_last_frcd_lo]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_frcd_hi]
    call vtd_out_str
    mov  rdi, [rel vtd_last_frcd_hi]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_nfr]          ; raw CAP.NFR: the unit has nfr+1 FRCD slots
    call vtd_out_str
    mov  rdi, [rel vtd_cap]
    shr  rdi, 40
    and  edi, 0xFF
    call vtd_out_dec
    call vtd_append_coverage_record
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    ret

; Preserve the failing ownership epoch before canonical reclaim changes live
; owner/reset/fault state.  This is the bounded diagnostic payload's source.
; Pure RAM formatter of the retained boot record, including a coverage skip.
; Existing vtd_out_* routines cap the complete STAT reply at VTD_OUT_MAX.
vtd_append_coverage_record:
    lea  rdi, [rel str_vtd_cov_state]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_reason]
    call vtd_out_str
    mov  eax, [rel vtd_cov_record + 4]
    cmp  eax, 20
    ja   .unknown
    shl  eax, 5                         ; fixed 32-byte reason slots
    lea  rdi, [rel str_vtd_cov_reasons]
    add  rdi, rax
    jmp  .reason
.unknown:
    lea  rdi, [rel str_vtd_cov_unknown]
.reason:
    call vtd_out_str
    lea  rdi, [rel str_vtd_cov_index]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 8]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_requester]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 12]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_cov_expected]
    call vtd_out_str
    mov  rdi, [rel vtd_cov_record + 16]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_cov_observed]
    call vtd_out_str
    mov  rdi, [rel vtd_cov_record + 24]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_cov_native_nic_found]
    call vtd_out_str
    movzx edi, byte [rel vtd_cov_record + 32]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_xhci_found]
    call vtd_out_str
    movzx edi, byte [rel vtd_cov_record + 33]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_sata_found]
    call vtd_out_str
    movzx edi, byte [rel vtd_cov_record + 34]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_nvme_found]
    call vtd_out_str
    movzx edi, byte [rel vtd_cov_record + 35]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_overflow]
    call vtd_out_str
    movzx edi, byte [rel vtd_cov_record + 36]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_count]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 40]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_native_nic_bdf]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 44]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_cov_xhci_bdf]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 48]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_cov_sata_bdf]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 52]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_cov_nvme_bdf]
    call vtd_out_str
    mov  edi, [rel vtd_cov_record + 56]
    call vtd_out_hex64
    ret

; VTD COVERAGE only: where the boot NIC probe and the VMD SATA select stopped.
; Pure RAM. nic_backend 0 other, 1 e1000e, 2 e5000b, 3 rtl8168. nic_step is the
; last check reached: 1 backend, 2 driver witnesses, 3 BDF/netdev member,
; 4 inventory, 5 claim census, 6 claim bound, 7 vendor, 8 class, 9 admitted.
; sata_vmd_step: 1 legacy SATA kept, 2 AHCI present, 3 VMD child, 4 one VMD
; root, 5 ECAM mapped, 6 root BDF, 7 inventory hits, 8 vendor, 9 class,
; 10 selected. 0 = never ran.
vtd_append_probe_steps:
    lea  rdi, [rel str_vtd_cov_nic_backend]
    call vtd_out_str
    movzx edi, byte [rel vtd_nic_boot_backend]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_nic_step]
    call vtd_out_str
    movzx edi, byte [rel vtd_nic_boot_step]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_nic_step_now]
    call vtd_out_str
    movzx edi, byte [rel vtd_nic_probe_step]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_nic_link_wait]
    call vtd_out_str
    movzx edi, byte [rel vtd_nic_boot_link_wait]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_vmd_step]
    call vtd_out_str
    movzx edi, byte [rel vtd_sata_vmd_step]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_cov_vmd_hits]
    call vtd_out_str
    movzx edi, byte [rel vtd_sata_vmd_hits]
    call vtd_out_dec
    ret

vtd_snapshot_assign_failure:
    mov  al, [rel vtd_secondary_found]
    mov  [rel vtd_assign_secondary_found], al
    mov  al, [rel vtd_ready]
    mov  [rel vtd_assign_ready], al
    mov  al, [rel vtd_reset_verified]
    mov  [rel vtd_assign_reset_verified], al
    mov  al, [rel vtd_guest_vendor_seen]
    mov  [rel vtd_assign_guest_vendor], al
    mov  al, [rel vtd_guest_echo_seen]
    mov  [rel vtd_assign_guest_echo], al
    mov  al, [rel vtd_guest_stage]
    mov  [rel vtd_assign_guest_stage], al
    mov  al, [rel hv_linux_run_req]
    mov  [rel vtd_assign_run_req], al
    mov  al, [rel hv_linux_task_started]
    mov  [rel vtd_assign_task_started], al
    mov  eax, [rel vtd_guest_start_gen]
    mov  [rel vtd_assign_start_gen], eax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel vtd_assign_start_consumed], eax
    mov  al, [rel hv_linux_load_err]
    mov  [rel vtd_assign_load_err], al
    mov  al, [rel hv_launch_refused]
    mov  [rel vtd_assign_launch_refused], al
    mov  al, [rel hv_launch_vmxonfail]
    mov  [rel vtd_assign_vmxon_fail], al
    mov  al, [rel hv_launch_vmcsfail]
    mov  [rel vtd_assign_vmcs_fail], al
    mov  eax, [rel hv_instr_err]
    mov  [rel vtd_assign_instr_err], eax
    mov  eax, [rel hv_vmwrite_fails]
    mov  [rel vtd_assign_vmwrite_fails], eax
    mov  eax, [rel hv_exit_reason]
    mov  [rel vtd_assign_last_exit], eax
    mov  al, [rel hv_linux_running]
    mov  [rel vtd_assign_linux_running], al
    mov  al, [rel hv_linux_kboot]
    mov  [rel vtd_assign_linux_kboot], al
    mov  al, [rel hv_vcon_ready]
    mov  [rel vtd_assign_vcon_ready], al
    mov  al, [rel hv_vcon_q_ready]
    mov  [rel vtd_assign_vcon_rx_ready], al
    mov  al, [rel hv_vcon_q_ready + 1]
    mov  [rel vtd_assign_vcon_tx_ready], al
    mov  al, [rel vtd_guest_inject_accepted]
    mov  [rel vtd_assign_inject_accepted], al
    mov  eax, [rel hv_vcon_capture_len]
    mov  [rel vtd_assign_capture_len], eax
    call vtd_snapshot_ept_detail
    call vtd_snapshot_bar_trace
    mov  eax, [rel vtd_fsts]
    mov  [rel vtd_assign_fsts], eax
    mov  eax, [rel vtd_fault_count]
    mov  [rel vtd_assign_fault_count], eax
    mov  rax, [rel vtd_last_frcd_lo]
    mov  [rel vtd_assign_frcd_lo], rax
    mov  rax, [rel vtd_last_frcd_hi]
    mov  [rel vtd_assign_frcd_hi], rax
    ret

; Copy the generation-scoped reason-48 latch before reclaim/formatting changes
; surrounding lifecycle state. It is rendered only with last_exit=48.
vtd_snapshot_ept_detail:
    mov  rax, [rel hv_ept_exit_gpa]
    mov  [rel vtd_assign_ept_gpa], rax
    mov  rax, [rel hv_ept_exit_qual]
    mov  [rel vtd_assign_ept_qual], rax
    mov  eax, [rel hv_ept_exit_ilen]
    mov  [rel vtd_assign_ept_ilen], eax
    mov  eax, [rel hv_ept_exit_decode_len]
    mov  [rel vtd_assign_ept_decode_len], eax
    mov  eax, [rel hv_ept_exit_gen]
    mov  [rel vtd_assign_ept_gen], eax
    mov  al, [rel hv_ept_exit_access]
    mov  [rel vtd_assign_ept_access], al
    mov  al, [rel hv_ept_exit_decode]
    mov  [rel vtd_assign_ept_decode], al
    mov  al, [rel hv_ept_exit_class]
    mov  [rel vtd_assign_ept_class], al
    mov  al, [rel hv_ept_exit_action]
    mov  [rel vtd_assign_ept_action], al
    mov  rax, [rel hv_ept_exit_rip]
    mov  [rel vtd_assign_ept_exit_rip], rax
    mov  rax, [rel hv_ept_exit_gla]
    mov  [rel vtd_assign_ept_exit_gla], rax
    mov  rax, [rel hv_ept_exit_insn]
    mov  [rel vtd_assign_ept_exit_insn], rax
    mov  eax, [rel hv_ept_exit_insn_len]
    mov  [rel vtd_assign_ept_exit_insn_len], eax
    mov  al, [rel hv_ept_exit_bar_match]
    mov  [rel vtd_assign_ept_bar_match], al
    ret

; Preserve the selected config-write -> fixed-readback -> checked-map record
; before reclaim can change the live vPCI state.
vtd_snapshot_bar_trace:
    mov  eax, [rel vtd_vpci_trace_gen]
    mov  [rel vtd_assign_vpci_trace_gen], eax
    mov  eax, [rel vtd_vpci_trace_count]
    mov  [rel vtd_assign_vpci_trace_count], eax
    mov  eax, [rel vtd_vpci_trace_ordinal]
    mov  [rel vtd_assign_vpci_trace_ordinal], eax
    mov  al, [rel vtd_vpci_trace_overflow]
    mov  [rel vtd_assign_vpci_trace_overflow], al
    mov  al, [rel vtd_vpci_bar_index]
    mov  [rel vtd_assign_vpci_bar_index], al
    mov  al, [rel vtd_vpci_cfg_off]
    mov  [rel vtd_assign_vpci_cfg_off], al
    mov  al, [rel vtd_vpci_pio_width]
    mov  [rel vtd_assign_vpci_pio_width], al
    mov  eax, [rel vtd_vpci_write_low]
    mov  [rel vtd_assign_vpci_write_low], eax
    mov  eax, [rel vtd_vpci_write_high]
    mov  [rel vtd_assign_vpci_write_high], eax
    mov  eax, [rel vtd_vpci_shadow_low]
    mov  [rel vtd_assign_vpci_shadow_low], eax
    mov  eax, [rel vtd_vpci_shadow_high]
    mov  [rel vtd_assign_vpci_shadow_high], eax
    mov  rax, [rel vtd_vpci_shadow_gpa]
    mov  [rel vtd_assign_vpci_shadow_gpa], rax
    mov  eax, [rel vtd_vpci_saved_low]
    mov  [rel vtd_assign_vpci_saved_low], eax
    mov  eax, [rel vtd_vpci_saved_high]
    mov  [rel vtd_assign_vpci_saved_high], eax
    mov  rax, [rel vtd_vpci_saved_hpa]
    mov  [rel vtd_assign_vpci_saved_hpa], rax
    mov  eax, [rel vtd_ept_map_attempts]
    mov  [rel vtd_assign_ept_map_attempts], eax
    mov  al, [rel vtd_ept_map_result]
    mov  [rel vtd_assign_ept_map_result], al
    mov  rax, [rel vtd_ept_map_gpa]
    mov  [rel vtd_assign_ept_map_gpa], rax
    mov  rax, [rel vtd_ept_map_hpa]
    mov  [rel vtd_assign_ept_map_hpa], rax
    mov  rax, [rel vtd_ept_leaf_addr]
    mov  [rel vtd_assign_ept_leaf_addr], rax
    mov  rax, [rel vtd_ept_leaf_value]
    mov  [rel vtd_assign_ept_leaf_value], rax
    mov  rax, [rel vtd_ept_leaf_readback]
    mov  [rel vtd_assign_ept_leaf_readback], rax
    mov  al, [rel vtd_ept_invept_attempted]
    mov  [rel vtd_assign_ept_invept_attempted], al
    mov  al, [rel vtd_ept_invept_ok]
    mov  [rel vtd_assign_ept_invept_ok], al
    mov  eax, [rel vtd_ept_invept_error]
    mov  [rel vtd_assign_ept_invept_error], eax
    cld
    lea  rsi, [rel vtd_secondary_cfg + 0x10]
    lea  rdi, [rel vtd_assign_saved_bar]
    mov  ecx, 6
    rep  movsd
    lea  rsi, [rel vtd_vpci_guest_bar]
    lea  rdi, [rel vtd_assign_guest_bar]
    mov  ecx, 6
    rep  movsd
    lea  rsi, [rel vtd_secondary_bar_size]
    lea  rdi, [rel vtd_assign_bar_size]
    mov  ecx, 6
    rep  movsd
    ret

; Render one fixed-shape failure line.  Owner/reclaim describe the canonical
; post-failure custody result; all other values describe the preserved failure.
vtd_render_assign_failure:
    call vtd_out_reset
    lea  rdi, [rel str_vtd_assign_fail_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_assign_fail_stage]
    call vtd_out_str
    movzx eax, byte [rel vtd_assign_fail_stage]
    cmp  eax, VTD_FAIL_CONTEXT_ASSIGN
    je   .stage_context
    cmp  eax, VTD_FAIL_GUEST_PROOF
    je   .stage_guest
    cmp  eax, VTD_FAIL_IOMMU_FAULT
    je   .stage_iommu
    cmp  eax, VTD_FAIL_ISOLATION
    je   .stage_isolation
    lea  rdi, [rel str_vtd_stage_unknown]
    jmp  .stage_emit
.stage_isolation:
    lea  rdi, [rel str_vtd_stage_isolation]
    call vtd_out_str
    call vtd_append_iso_fields           ; the verdict that refused it
    jmp  .guest_evidence_done
.stage_context:
    lea  rdi, [rel str_vtd_stage_context]
    jmp  .stage_emit
.stage_guest:
    lea  rdi, [rel str_vtd_stage_guest]
    jmp  .stage_emit
.stage_iommu:
    lea  rdi, [rel str_vtd_stage_iommu]
.stage_emit:
    call vtd_out_str
    cmp  byte [rel vtd_assign_fail_stage], VTD_FAIL_GUEST_PROOF
    jne  .guest_evidence_done
    lea  rdi, [rel str_vtd_guest_stage_field]
    call vtd_out_str
    movzx eax, byte [rel vtd_assign_guest_stage]
    cmp  eax, VTD_GUEST_STAGE_RUN_NOT_CONSUMED
    je   .guest_run_not_consumed
    cmp  eax, VTD_GUEST_STAGE_STOP_WAIT
    je   .guest_stop
    cmp  eax, VTD_GUEST_STAGE_SPAWN
    je   .guest_spawn
    cmp  eax, VTD_GUEST_STAGE_BOOT_WAIT
    je   .guest_boot
    cmp  eax, VTD_GUEST_STAGE_BOOT_EXIT
    je   .guest_boot_exit
    cmp  eax, VTD_GUEST_STAGE_INJECT
    je   .guest_inject
    cmp  eax, VTD_GUEST_STAGE_VENDOR_WAIT
    je   .guest_vendor_wait
    cmp  eax, VTD_GUEST_STAGE_ECHO_WAIT
    je   .guest_echo_wait
    cmp  eax, VTD_GUEST_STAGE_CARRIER_WAIT
    je   .guest_carrier_wait
    cmp  eax, VTD_GUEST_STAGE_CARRIER_ZERO
    je   .guest_carrier_zero
    lea  rdi, [rel str_vtd_stage_unknown]
    jmp  .guest_stage_emit
.guest_run_not_consumed:
    lea  rdi, [rel str_vtd_guest_run_not_consumed]
    jmp  .guest_stage_emit
.guest_stop:
    lea  rdi, [rel str_vtd_guest_stop]
    jmp  .guest_stage_emit
.guest_spawn:
    lea  rdi, [rel str_vtd_guest_spawn]
    jmp  .guest_stage_emit
.guest_boot:
    lea  rdi, [rel str_vtd_guest_boot]
    jmp  .guest_stage_emit
.guest_boot_exit:
    lea  rdi, [rel str_vtd_guest_boot_exit]
    jmp  .guest_stage_emit
.guest_inject:
    lea  rdi, [rel str_vtd_guest_inject]
    jmp  .guest_stage_emit
.guest_vendor_wait:
    lea  rdi, [rel str_vtd_guest_vendor_wait]
    jmp  .guest_stage_emit
.guest_echo_wait:
    lea  rdi, [rel str_vtd_guest_echo_wait]
    jmp  .guest_stage_emit
.guest_carrier_wait:
    lea  rdi, [rel str_vtd_guest_carrier_wait]
    jmp  .guest_stage_emit
.guest_carrier_zero:
    lea  rdi, [rel str_vtd_guest_carrier_zero]
.guest_stage_emit:
    call vtd_out_str
    lea  rdi, [rel str_vtd_run_req_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_run_req]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_task_started_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_task_started]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_start_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_start_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_start_consumed_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_start_consumed]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_load_err_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_load_err]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_launch_refused_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_launch_refused]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vmxon_fail_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vmxon_fail]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vmcs_fail_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vmcs_fail]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_instr_err_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_instr_err]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vmwrite_fails_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vmwrite_fails]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_last_exit_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_last_exit]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_linux_running_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_linux_running]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_linux_kboot_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_linux_kboot]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vcon_ready_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vcon_ready]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vcon_rx_ready_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vcon_rx_ready]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vcon_tx_ready_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vcon_tx_ready]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_inject_accepted_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_inject_accepted]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_capture_len_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_capture_len]
    call vtd_out_dec
    cmp  dword [rel vtd_assign_last_exit], 48
    jne  .guest_evidence_done
    cmp  byte [rel vtd_assign_ept_class], VTD_EPT_CLASS_NONE
    je   .guest_evidence_done
    lea  rdi, [rel str_vtd_ept_gpa_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_gpa]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ept_qual_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_qual]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ept_access_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_access]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_ilen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_ilen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_decode_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_decode]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_decode_len_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_decode_len]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_action_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_action]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_class_field]
    call vtd_out_str
    movzx eax, byte [rel vtd_assign_ept_class]
    cmp  eax, VTD_EPT_CLASS_VIRTIO_RESUME
    je   .ept_resume
    cmp  eax, VTD_EPT_CLASS_VIRTIO_ACCESS
    je   .ept_access
    cmp  eax, VTD_EPT_CLASS_VIRTIO_DECODE
    je   .ept_decode
    cmp  eax, VTD_EPT_CLASS_ASSIGNED_BAR
    je   .ept_bar
    lea  rdi, [rel str_vtd_ept_foreign]
    jmp  .ept_class_emit
.ept_resume:
    lea  rdi, [rel str_vtd_ept_resume]
    jmp  .ept_class_emit
.ept_access:
    lea  rdi, [rel str_vtd_ept_access]
    jmp  .ept_class_emit
.ept_decode:
    lea  rdi, [rel str_vtd_ept_decode]
    jmp  .ept_class_emit
.ept_bar:
    lea  rdi, [rel str_vtd_ept_bar]
.ept_class_emit:
    call vtd_out_str
    lea  rdi, [rel str_vtd_ept_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_gen]
    call vtd_out_dec
.guest_evidence_done:
    lea  rdi, [rel str_vtd_owner_field]
    call vtd_out_str
    cmp  byte [rel vtd_ready], 1
    jne  .owner_unavailable
    cmp  byte [rel vtd_secondary_found], 1
    jne  .owner_unavailable
    cmp  byte [rel vtd_owner_guest], 1
    je   .owner_guest
    lea  rdi, [rel str_vtd_host]
    jmp  .owner_emit
.owner_guest:
    lea  rdi, [rel str_vtd_guest]
    jmp  .owner_emit
.owner_unavailable:
    lea  rdi, [rel str_vtd_unavailable]
.owner_emit:
    call vtd_out_str
    cmp  byte [rel vtd_reclaim_verified], 1
    jne  .reclaim_failed
    lea  rdi, [rel str_vtd_reclaim_verified_field]
    jmp  .reclaim_emit
.reclaim_failed:
    lea  rdi, [rel str_vtd_reclaim_failed_field]
.reclaim_emit:
    call vtd_out_str
    lea  rdi, [rel str_vtd_secondary_found_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_secondary_found]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ready_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ready]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_reset_verified_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_reset_verified]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_guest_vendor_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_guest_vendor]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_guest_echo_seen_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_guest_echo]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_fsts]
    call vtd_out_str
    mov  edi, [rel vtd_assign_fsts]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_faults]
    call vtd_out_str
    mov  edi, [rel vtd_assign_fault_count]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_frcd_lo]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_frcd_lo]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_frcd_hi]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_frcd_hi]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_assign_end]
    call vtd_out_str
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    ret

; The activation chain is deliberately projected separately from ASSIGN so
; both fixed-shape responses retain their terminal sentinels below UDP_PAY_MAX.
; The nonce and generation link this immutable post-failure snapshot to the
; exact canonical assignment lifecycle that produced it.
; FIRSTUD projects immutable VM-exit-time latches. Host grading supplies the
; independently hash-bound expected vmlinux address and bytes.
vtd_render_first_ud_trace:
    push rbx
    push r12
    call vtd_out_reset
    lea  rdi, [rel str_vtd_first_ud_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_trace_gen_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_diag_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_first_ud_diag_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_assign_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_start_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_consumed_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_start_consumed]
    call vtd_out_dec

    lea  rdi, [rel str_vtd_ud_valid_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_valid]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_info_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_info]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_error_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_error]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_idt_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_idt_info]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_idt_error_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_idt_error]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_ordinal_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_ordinal]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_no_reinject_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_no_reinject]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_exit_reason_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_exit_reason]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_bitmap_req_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_bitmap_requested]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_bitmap_live_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_bitmap_readback]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_first_r0_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_first_r0_info]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_first_r0_gen_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_first_r0_gen]
    call vtd_out_dec

    lea  rdi, [rel str_vtd_ud_rip_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_rip]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_rsp_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_rsp]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_rflags_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_rflags]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_cr2_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_cr2]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_cr3_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_cr3]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_cr4_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_cr4]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_cs_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_cs]
    call vtd_out_hex64

    lea  rdi, [rel str_vtd_ud_walker_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_walker_valid]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_page_size_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_page_size]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_gpa_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_gpa]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_offset_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_offset]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_pml4e_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_pml4e]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_pdpte_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_pdpte]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_pde_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_pde]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_pte_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_pte]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_insn_len_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_insn_len]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_insn0_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_insn]
    call vtd_out_hex64
    lea  rdi, [rel str_vtd_ud_insn1_field]
    call vtd_out_str
    mov  rdi, [rel hv_first_ud_insn + 8]
    call vtd_out_hex64

    xor  ebx, ebx
    lea  r12, [rel hv_first_ud_gpr]
.gpr:
    lea  rdi, [rel str_vtd_ud_gpr_field]
    call vtd_out_str
    mov  edi, ebx
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ud_hex_value]
    call vtd_out_str
    mov  rdi, [r12 + rbx*8]
    call vtd_out_hex64
    inc  ebx
    cmp  ebx, 15
    jb   .gpr
    lea  rdi, [rel str_vtd_first_ud_end]
    call vtd_out_str
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    pop  r12
    pop  rbx
    ret

; Separate bounded console-tail reply. Bytes are frozen before teardown.
vtd_render_first_ud_context:
    push rbx
    push r12
    call vtd_out_reset
    lea  rdi, [rel str_vtd_first_ud_context_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_trace_gen_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_console_len_field]
    call vtd_out_str
    xor  r12d, r12d
    cmp  qword [rel hv_first_ud_valid], 1
    jne  .length_ready
    mov  r12d, [rel hv_first_ud_console_len]
    cmp  r12d, HV_VCON_CAP_MAX - 1
    jbe  .length_ready
    mov  r12d, HV_VCON_CAP_MAX - 1
.length_ready:
    mov  edi, r12d
    call vtd_out_dec
    lea  rdi, [rel str_vtd_console_overflow_field]
    call vtd_out_str
    mov  edi, [rel hv_first_ud_console_overflow]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_console_hex_field]
    call vtd_out_str
    xor  ebx, ebx
.console:
    cmp  ebx, r12d
    jae  .context_done
    lea  rdx, [rel hv_first_ud_console]
    movzx edi, byte [rdx + rbx]
    call vtd_out_hex_byte
    inc  ebx
    jmp  .console
.context_done:
    lea  rdi, [rel str_vtd_first_ud_context_end]
    call vtd_out_str
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    pop  r12
    pop  rbx
    ret

vtd_render_trace:
    call vtd_out_reset
    lea  rdi, [rel str_vtd_trace_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_vtd_trace_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_start_gen]
    call vtd_out_dec
    call vtd_append_bar_activation_receipt
    lea  rdi, [rel str_vtd_trace_end]
    call vtd_out_str
    lea  rdi, [rel str_vtd_eol]
    call vtd_out_str
    ret

; Append the same-generation vPCI transaction, checked mapper, leaf readback,
; invalidation, and first terminal instruction as one fixed schema.
vtd_append_bar_activation_receipt:
    lea  rdi, [rel str_vtd_vpci_trace_gen_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_trace_gen]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_trace_count_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_trace_count]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_trace_overflow_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vpci_trace_overflow]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_bar_index_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vpci_bar_index]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_cfg_off_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vpci_cfg_off]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_pio_width_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_vpci_pio_width]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_vpci_write_low_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_write_low]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_write_high_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_write_high]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_shadow_low_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_shadow_low]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_shadow_high_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_shadow_high]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_shadow_gpa_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_vpci_shadow_gpa]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_saved_low_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_saved_low]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_saved_high_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_vpci_saved_high]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_vpci_saved_hpa_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_vpci_saved_hpa]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_map_attempts_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_map_attempts]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_map_result_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_map_result]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_map_gpa_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_map_gpa]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_map_hpa_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_map_hpa]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_leaf_addr_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_leaf_addr]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_leaf_value_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_leaf_value]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_leaf_readback_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_leaf_readback]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_invept_attempted_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_invept_attempted]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_invept_ok_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_invept_ok]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_invept_error_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_invept_error]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_exit_rip_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_exit_rip]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_exit_gla_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_exit_gla]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_exit_insn_field]
    call vtd_out_str
    mov  rdi, [rel vtd_assign_ept_exit_insn]
    call vtd_out_hex_compact
    lea  rdi, [rel str_vtd_ept_exit_insn_len_field]
    call vtd_out_str
    mov  edi, [rel vtd_assign_ept_exit_insn_len]
    call vtd_out_dec
    lea  rdi, [rel str_vtd_ept_bar_match_field]
    call vtd_out_str
    movzx edi, byte [rel vtd_assign_ept_bar_match]
    call vtd_out_dec
    ret

; vtd_data_pending — RCQ-19: EAX=1 when a VTD/DDOM/DMAVIOL line is staged, else 0.
;   Writes nothing. clobbers: RAX
vtd_data_pending:
    xor  eax, eax
    cmp  byte [rel vtd_out_ready], 1
    sete al
    ret

; vtd_data_line — RCQ-19: append a staged VTD/DDOM/DMAVIOL line and consume it.
;   EAX=1 when a line was appended (udp_send_reply finishes the lean data reply),
;   else EAX=0 and nothing is written. Never emits the BOOTLOG ownership markers.
;   clobbers: RAX,RSI,RDI
vtd_data_line:
    xor  eax, eax
    cmp  byte [rel vtd_out_ready], 1
    jne  .none
    lea  rdi, [rel vtd_out_buf]
    call udp_put_str
    mov  byte [rel vtd_out_ready], 0
    mov  eax, 1
.none:
    ret

; vtd_data_drop — RCQ-19: discard a staged line no reply may carry (another verb's reply,
;   or BOOTLOG FULL). clobbers: none
vtd_data_drop:
    mov  byte [rel vtd_out_ready], 0
    ret

; vtd_status_line — the BOOTLOG VT-d ownership markers. A staged VTD/DDOM/DMAVIOL line
;   never leaves here: the RCQ-19 envelope emits it for its own verb or drops it.
vtd_status_line:
    lea  rdi, [rel udp_line]
    lea  rsi, [rel str_verb_bootlog]
    call strcmp
    test rax, rax
    jnz  .done
    cmp  byte [rel vtd_marker_ready], 1
    jne  .assigned
    lea  rdi, [rel str_vtd_udp_ready]
    call udp_put_str
.assigned:
    cmp  byte [rel vtd_marker_assigned], 1
    jne  .reclaimed
    lea  rdi, [rel str_vtd_udp_assigned]
    call udp_put_str
.reclaimed:
    cmp  byte [rel vtd_marker_reclaimed], 1
    jne  .native_domains
    lea  rdi, [rel str_vtd_udp_reclaimed]
    call udp_put_str
.native_domains:
    cmp  byte [rel vtd_native_marker_domains], 1
    jne  .native_mapped
    lea  rdi, [rel str_vtd_udp_native_domains]
    call udp_put_str
.native_mapped:
    cmp  byte [rel vtd_native_marker_mapped], 1
    jne  .observability
    lea  rdi, [rel str_vtd_udp_dma_mapped]
    call udp_put_str
.observability:
    cmp  byte [rel vtd_observability_fixture_ok], 1
    jne  .done
    lea  rdi, [rel str_vtd_udp_observability]
    call udp_put_str
.done:
    xor  eax, eax                         ; no staged response consumed
    ret

; RDI=text, ECX=count -> RAX after count tokens and following spaces.
vtd_after_tokens:
    mov  rax, rdi
.token:
    test ecx, ecx
    jz   .done
.chars:
    mov  dl, [rax]
    test dl, dl
    jz   .done
    cmp  dl, ' '
    je   .spaces
    inc  rax
    jmp  .chars
.spaces:
    cmp  byte [rax], ' '
    jne  .next
    inc  rax
    jmp  .spaces
.next:
    dec  ecx
    jmp  .token
.done:
    ret

vtd_copy_nonce:
    lea  rdx, [rel vtd_nonce]
    xor  ecx, ecx
.loop:
    mov  al, [rdi + rcx]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    cmp  al, 0x21
    jb   .bad
    cmp  al, 0x7E
    ja   .bad
    cmp  ecx, 63
    jae  .bad
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .loop
.end:
    test ecx, ecx
    jz   .bad
    mov  byte [rdx + rcx], 0
    mov  eax, 1
    ret
.bad:
    mov  byte [rdx], 0
    xor  eax, eax
    ret

vtd_build_guest_strings:
    lea  rdi, [rel vtd_guest_command]
    lea  rsi, [rel str_vtd_guest_cmd_prefix]
    call vtd_copy_string
    lea  rsi, [rel vtd_nonce]
    call vtd_copy_string
    lea  rsi, [rel str_vtd_guest_cmd_suffix]
    call vtd_copy_string
    mov  byte [rdi], 0
    lea  rdi, [rel vtd_guest_expected]
    lea  rsi, [rel str_vtd_guest_expect_prefix]
    call vtd_copy_string
    lea  rsi, [rel vtd_nonce]
    call vtd_copy_string
    mov  byte [rdi], 0
    ret

; RDI=dest, RSI=src -> RDI=end (NUL not copied).
vtd_copy_string:
.loop:
    mov  al, [rsi]
    test al, al
    jz   .done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    jmp  .loop
.done:
    ret

vtd_out_reset:
    lea  rax, [rel vtd_out_buf]
    mov  [rel vtd_out_cur], rax
    mov  byte [rax], 0
    ret

vtd_out_str:
    mov  rax, [rel vtd_out_cur]
    lea  rdx, [rel vtd_out_buf + VTD_OUT_MAX]
.loop:
    cmp  rax, rdx
    jae  .done
    mov  cl, [rdi]
    test cl, cl
    jz   .done
    mov  [rax], cl
    inc  rax
    inc  rdi
    jmp  .loop
.done:
    mov  byte [rax], 0
    mov  [rel vtd_out_cur], rax
    ret

vtd_out_dec:
    mov  eax, edi
    lea  rsi, [rel vtd_dec_tmp + 15]
    mov  byte [rsi], 0
    test eax, eax
    jnz  .digits
    dec  rsi
    mov  byte [rsi], '0'
    jmp  .emit
.digits:
    mov  ecx, 10
.one:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test eax, eax
    jnz  .one
.emit:
    mov  rdi, rsi
    jmp  vtd_out_str

; Append RDI as exactly 16 lowercase hexadecimal digits.
vtd_out_hex64:
    mov  r8, rdi
    mov  ecx, 16
.digit:
    rol  r8, 4
    mov  eax, r8d
    and  eax, 0xF
    cmp  al, 9
    jbe  .numeric
    add  al, 'a' - 10
    jmp  .put
.numeric:
    add  al, '0'
.put:
    mov  rdx, [rel vtd_out_cur]
    lea  r9, [rel vtd_out_buf + VTD_OUT_MAX]
    cmp  rdx, r9
    jae  .done
    mov  [rdx], al
    inc  rdx
    mov  byte [rdx], 0
    mov  [rel vtd_out_cur], rdx
    dec  ecx
    jnz  .digit
.done:
    ret

; Append RDI without leading zeroes. Field strings supply the 0x prefix, and
; compact values keep the complete causal receipt below UDP_PAY_MAX.
vtd_out_hex_compact:
    mov  rax, rdi
    lea  rsi, [rel vtd_hex_tmp + 16]
    mov  byte [rsi], 0
    test rax, rax
    jnz  .digits
    dec  rsi
    mov  byte [rsi], '0'
    jmp  .emit
.digits:
    mov  edx, eax
    and  edx, 0xF
    cmp  dl, 9
    jbe  .numeric
    add  dl, 'a' - 10
    jmp  .store
.numeric:
    add  dl, '0'
.store:
    dec  rsi
    mov  [rsi], dl
    shr  rax, 4
    jnz  .digits
.emit:
    mov  rdi, rsi
    jmp  vtd_out_str

; Append exactly two lowercase hexadecimal digits from DIL.
vtd_out_hex_byte:
    push rbx
    movzx ebx, dil
    mov  eax, ebx
    shr  eax, 4
    and  eax, 0xF
    cmp  al, 9
    jbe  .high_numeric
    add  al, 'a' - 10
    jmp  .high_put
.high_numeric:
    add  al, '0'
.high_put:
    mov  rdx, [rel vtd_out_cur]
    lea  rcx, [rel vtd_out_buf + VTD_OUT_MAX]
    cmp  rdx, rcx
    jae  .done
    mov  [rdx], al
    inc  rdx
    mov  [rel vtd_out_cur], rdx
    mov  eax, ebx
    and  eax, 0xF
    cmp  al, 9
    jbe  .low_numeric
    add  al, 'a' - 10
    jmp  .low_put
.low_numeric:
    add  al, '0'
.low_put:
    cmp  rdx, rcx
    jae  .done
    mov  [rdx], al
    inc  rdx
    mov  byte [rdx], 0
    mov  [rel vtd_out_cur], rdx
.done:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; State and immutable strings.
; ---------------------------------------------------------------------------
%include "hv/vtd_guest.asm"

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; RCQ-18 VT-d DID 1 carve: its own block, so the zero-storage split of
; WDATA_hv_vtd_0 still rebuilds that block's base layout.
%macro WDATA_hv_vtd_2 0
str_vtd_skip_carve:    db "[PAOS64] vtd.ownership.skip reason=carve", 13, 10, 0
str_vtd_carve_pages:   db "[PAOS64] vtd.carve pages=", 0
str_vtd_carve_splits:  db " splits=", 0
; RCQ-37 media-owner refusals: here, outside the split WDATA_hv_vtd_0, so its base layout still rebuilds.
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
str_ddom_media_busy:   db " DDOM ERR busy=media_guest", 13, 10, 0
str_vtd_media_busy:    db " VTD ERR busy=media_guest", 13, 10, 0
%endif
%endif
align 4
vtd_carve_holes:       dd 0                ; boot census: pages made not present
vtd_carve_splits:      dd 0                ; boot census: split tables taken
vtd_ioapic_madt_len:   dd 0                ; exact MADT size, 0 means unresolved
align 8
vtd_ioapic_madt:       dq 0                ; live only at discovery, carved copy before TE
vtd_dmar_snap_len:     dd 0                ; RCQ-18 DMAR snapshot: bytes copied at boot (0: none)
align 8
vtd_dmar_snap:         dq 0                ; the snapshot pages (after the DMAVIOL page)
%endmacro
WDATA_DEFER WDATA_hv_vtd_2
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_vtd_0 0
align 8
vtd_unitb_base:        dq 0
vtd_cap:               dq 0
vtd_ecap:              dq 0
vtd_root:              dq 0
vtd_qi_queue:          dq 0                ; SEC-D3a invalidation queue page (0 = register path)
vtd_qi_status:         dq 0                ; SEC-D3a invalidation-wait status page
vtd_qi_tail:           dd 0
vtd_qi_token:          dd 0
vtd_qi_on:             db 0
vtd_qi_lock:           db 0                ; SEC-D3b (D3a N7): one queue submitter at a time
vtd_ir_on:             db 0                ; SEC-D3b: IRE + QIE read back active, CFIS clear
vtd_ir_reason:         db VTD_IR_R_IDLE
align 8
times 36 db 0                  ; vtd_irt..vtd_reclaim_count moved to WDATA_hv_vtd_0_bss1: keeps the labels below at their offset mod 64
vtd_deadman_limit_ms:  dd VTD_DEADMAN_MS
vtd_net_timer_due:     dd 0
vtd_net_timer_injections: dd 0
vtd_net_irq0_deferrals: dd 0
vtd_net_irq_attempts:  dd 0
vtd_net_irq_injections: dd 0
vtd_net_irq_reject_entry: dd 0
vtd_net_irq_reject_vec: dd 0
vtd_net_irq_reject_mask: dd 0
vtd_net_irq_reject_if0: dd 0
vtd_net_irq_reject_shadow: dd 0
vtd_net_intr_window_arms: dd 0
vtd_net_intr_window_exits: dd 0
vtd_net_command_writes: dd 0
vtd_net_phy_edge_predelays: dd 0
vtd_net_phy_edge_fires: dd 0
vtd_net_phy_edge_txblocks: dd 0
vtd_net_phy_edge_txown: dd 0
align 8
vtd_cov_record:       times 64 db 0
vtd_bdf_count:         dd 0
vtd_secondary_bar_size: times 6 dd 0
vtd_secondary_devctl:  dw 0
vtd_net_irq_level:     dw 0
vtd_net_irq_pending:   dw 0
vtd_net_imr:           dw 0
vtd_net_isr:           dw 0
vtd_net_phy_edge_isr:  dw 0
vtd_net_phy_edge_imr:  dw 0
vtd_ready:             db 0
vtd_enabled:           db 0
vtd_owner_guest:       db 0
vtd_coverage_before_te: db 0
vtd_secondary_found:   db 0
vtd_bus_ctx_ready:     db 0
vtd_guest_tables_ready: db 0
vtd_vpci_active:       db 0
vtd_vpci_identity_open: db 0
vtd_deadman_armed:     db 0
vtd_deadman_fired:     db 0
vtd_reclaim_verified:  db 0
vtd_assign_fail_stage: db 0
vtd_guest_stage:       db 0
vtd_guest_inject_accepted: db 0
vtd_guest_vendor_seen: db 0
vtd_guest_echo_seen:   db 0
vtd_assign_secondary_found: db 0
vtd_assign_ready:      db 0
vtd_assign_reset_verified: db 0
vtd_assign_guest_vendor: db 0
vtd_assign_guest_echo: db 0
vtd_assign_guest_stage: db 0
vtd_assign_linux_running: db 0
vtd_assign_linux_kboot: db 0
vtd_assign_vcon_ready: db 0
vtd_assign_inject_accepted: db 0
vtd_assign_run_req:    db 0
vtd_assign_task_started: db 0
vtd_assign_load_err:   db 0
vtd_assign_launch_refused: db 0
vtd_assign_vmxon_fail: db 0
vtd_assign_vmcs_fail:  db 0
vtd_assign_vcon_rx_ready: db 0
vtd_assign_vcon_tx_ready: db 0
vtd_first_ud_diag_requested: db 0
vtd_failure_fixture_ok: db 0
vtd_observability_fixture_ok: db 0
vtd_ept_detail_fixture_ok: db 0
vtd_assign_ept_access: db 0
vtd_assign_ept_decode: db 0
vtd_assign_ept_class: db 0
vtd_assign_ept_action: db 0
vtd_assign_ept_bar_match: db 0
vtd_vpci_trace_overflow: db 0
vtd_vpci_bar_index:    db 0
vtd_vpci_cfg_off:      db 0
vtd_vpci_pio_width:    db 0
vtd_ept_map_result:    db 0
vtd_ept_invept_attempted: db 0
vtd_ept_invept_ok:     db 0
vtd_assign_vpci_trace_overflow: db 0
vtd_assign_vpci_bar_index: db 0
vtd_assign_vpci_cfg_off: db 0
vtd_assign_vpci_pio_width: db 0
vtd_assign_ept_map_result: db 0
vtd_assign_ept_invept_attempted: db 0
vtd_assign_ept_invept_ok: db 0
vtd_fixture_save_active: db 0
vtd_fixture_save_pool_used: db 0
vtd_fixture_save_vmx_live: db 0
vtd_fixture_save_bar_probe: times 6 db 0
vtd_bar_alias_fixture_ok: db 0
vtd_identity_guard_fixture_ok: db 0
vtd_bar_alias_fixture_stage: db 0
vtd_post_dhcp_carrier_fixture_ok: db 0
vtd_post_dhcp_carrier_fixture_stage: db 0
vtd_out_ready:         db 0
vtd_marker_ready:      db 0
vtd_marker_assigned:   db 0
vtd_marker_reclaimed:  db 0
vtd_native_ready:      db 0
vtd_native_marker_domains: db 0
vtd_native_marker_mapped: db 0
vtd_dmaviol_landed:    db 1
vtd_dmaviol_blocked:   db 0
vtd_dmaviol_valid:     db 0
vtd_kat_owner:         db 0
vtd_native_nic_found: db 0
vtd_native_nic_covered: db 0
align 8
vtd_native_nic_handle: dq 0
vtd_native_nic_generation: dq 0
vtd_native_nic_bdf: dd 0
vtd_e1000e_found:      db 0
vtd_xhci_found:        db 0
vtd_sata_found:        db 0
vtd_nvme_found:        db 0
vtd_e1000e_covered:    db 0
vtd_xhci_covered:      db 0
vtd_sata_covered:      db 0
vtd_nvme_covered:      db 0
vtd_secondary_pcie_cap: db 0
vtd_reset_method:      db 0
vtd_reset_verified:    db 0
vtd_bdf_overflow:      db 0
vtd_scoped_unit:       db 0
vtd_ept_pool_used:     db 0
vtd_network_mode:      db 0
vtd_net_driver_r8169:  db 0
vtd_net_carrier:       db 0
vtd_net_carrier_early: db 0
vtd_net_gateway_arp:   db 0
vtd_net_udp_sent:      db 0
vtd_net_marker_carrier: db 0
vtd_net_marker_dhcp:   db 0
vtd_net_marker_udp:    db 0
vtd_net_service_result: db 0
vtd_net_intr_window_armed: db 0
vtd_net_task_started:  db 0
vtd_net_start_pending: db 0
vtd_net_task_active:   db 0
vtd_net_task_result:   db 0
vtd_domain_l2_active:  db 0
vtd_domain_bridge_ready: db 0
vtd_domain_bridge_stage: db 0
vtd_domain_shell_cmd_dispatched: db 0
vtd_domain_iface_cmd_dispatched: db 0
vtd_domain_shell_ready: db 0
vtd_domain_iface_ready: db 0
vtd_domain_iface_parse: db 0
vtd_domain_iface_len: db 0
vtd_domain_iface_fail_parse: db 0
vtd_domain_iface_fail_iface_len: db 0
vtd_domain_iface_fail_reason_len: db 0
vtd_domain_iface_attempts: db 0
vtd_domain_iface_result: db 0
vtd_net_carrier_timeout_seen: db 0
vtd_net_cwait_enter_seen: db 0
vtd_net_cwait_tick_seen: db 0
vtd_net_cwait_carr_seen: db 0
vtd_net_uplink_line:   db 0
vtd_net_carrier_line:  db 0
vtd_net_lease_parse:   db 0
vtd_net_lease_len:     db 0
vtd_net_lease_iface_len: db 0
vtd_net_carrier_probe_dispatched: db 0
vtd_net_carrier_probe_pending: db 0
vtd_net_carrier_sample_seen: db 0
vtd_net_carrier_now_parse: db 0
vtd_net_carrier_now_iface_len: db 0
vtd_net_carrier_now_value: db 0xFF
times 6 db 0                  ; vtd_net_chipcmd..vtd_hex_tmp moved to WDATA_hv_vtd_0_bss3: keeps the labels below at their offset mod 64

str_vtd_verb:          db "VTD", 0
str_ddom_verb:         db "DDOM", 0
str_ddom_net_start:    db "NET START", 0
str_ddom_net_stat:     db "NET STAT", 0
str_ddom_net_stop:     db "NET STOP", 0
str_ddom_usage:        db " DDOM ERR usage=NET_START_nonce_ip_port|NET_STAT|NET_STOP_nonce|NET_FAULT_crash|hang_nonce", 13, 10, 0
str_ddom_bad_args:     db " DDOM NET ERR invalid_nonce_ip_port", 13, 10, 0
str_ddom_start_ok:     db " DDOM NET START nonce=", 0
str_ddom_spawn_fail:   db " DDOM NET START ERR task_spawn_failed nonce=", 0
str_ddom_busy:         db " DDOM NET START ERR busy", 13, 10, 0
str_ddom_stat_head:    db " DDOM NET STAT", 0
str_ddom_stop_ok:      db " DDOM NET STOP nonce=", 0
str_ddom_stop_fail:    db " DDOM NET STOP ERR nonce=", 0
str_ddom_vendor:       db " vendor=10ec", 0
str_ddom_owner:        db " owner=", 0
str_ddom_carrier:      db " carrier=", 0
str_ddom_lease:        db " lease=", 0
str_ddom_gateway_arp:  db " gateway_arp=", 0
str_ddom_driver:       db " driver=", 0
str_ddom_udp_sent:     db " udp_sent=", 0
str_ddom_timer_due:    db " timer_due=", 0
str_ddom_timer_injected: db " timer_injected=", 0
str_ddom_irq_attempts: db " rtl_irq_attempts=", 0
str_ddom_irq:          db " irq_injections=", 0
str_ddom_irq_reject_entry: db " irq_reject_entry_busy=", 0
str_ddom_irq_reject_vec: db " irq_reject_no_vecbase=", 0
str_ddom_irq_reject_mask: db " irq_reject_pic6_masked=", 0
str_ddom_irq_reject_if0: db " irq_reject_if0=", 0
str_ddom_irq_reject_shadow: db " irq_reject_shadow=", 0
str_ddom_pic_mask:     db " pic_mask=0x", 0
str_ddom_pic_vec:      db " pic_vec=0x", 0
str_ddom_intx_armed:   db " intx_armed=", 0
str_ddom_vpci_cmd:     db " vpci_cmd=0x", 0
str_ddom_command_writes: db " cmd_writes=", 0
str_ddom_iw_arms:      db " iw_arms=", 0
str_ddom_iw_exits:     db " iw_exits=", 0
str_ddom_irq0_deferrals: db " irq0_over_rtl=", 0
str_ddom_te:           db " chipcmd=0x", 0
str_ddom_imr:          db " imr=0x", 0
str_ddom_isr:          db " isr=0x", 0
str_ddom_physts:       db " physts=0x", 0
str_ddom_pcfired:      db " pcfired=", 0
str_ddom_pcpredelay:   db " pcpredelay=", 0
str_ddom_pctxblock:    db " pctxblock=", 0
str_ddom_pctxring:     db " pctxring=", 0
str_ddom_pctxown:      db " pctxown=", 0
str_ddom_pctppoll:     db " pctppoll=0x", 0
str_ddom_pcchipcmd:    db " pcchipcmd=0x", 0
str_ddom_pcimr:        db " pcimr=0x", 0
str_ddom_pcphysts:     db " pcphysts=0x", 0
str_ddom_pcisr:        db " pcisr=0x", 0
str_ddom_pclive:       db " pclive=", 0
str_ddom_pcinj:        db " pcinj=", 0
str_ddom_cwait_enter:  db " cwait_enter=", 0
str_ddom_cwait_tick:   db " cwait_tick1=", 0
str_ddom_cwait_carr:   db " cwait_carr1=", 0
str_ddom_ctmo:         db " carrier_timeout=", 0
str_ddom_fail_stage:   db " fail_stage=", 0
str_ddom_reclaim:      db " reclaim=", 0
str_ddom_verified:     db "verified", 0
str_ddom_pending:      db "pending", 0
str_ddom_task:         db " task_result=", 0
str_ddom_zero_ip:      db "0.0.0.0", 0
str_ddom_none:         db "none", 0
str_vtd_net_uplink:    db "PAOS_DDOM_UPLINK_FOUND ", 0
str_vtd_net_r8169:     db "r8169", 0
str_vtd_net_cwait_enter: db "PAOS_DDOM_CWAIT_ENTER", 0
str_vtd_net_cwait_tick: db "PAOS_DDOM_CWAIT_TICK1", 0
str_vtd_net_cwait_carr: db "PAOS_DDOM_CWAIT_CARR1", 0
str_vtd_net_carrier_stable: db "PAOS_DDOM_CARRIER_STABLE", 0
str_vtd_net_stable_five: db "stable=5", 0
str_vtd_net_carrier_timeout: db "PAOS_DDOM_CARRIER_TIMEOUT", 0
str_vtd_net_link_up:   db "PAOS_DDOM_LINK_UP ", 0
str_vtd_net_carrier_now: db "PAOS_DDOM_CARRIER_NOW ", 0
str_vtd_net_arp_ok:    db "PAOS_DDOM_ARP_OK", 0
str_vtd_net_sent_ok:   db "PAOS_DDOM_SENT_RC=0", 0
str_vtd_net_carrier_marker: db "[PAOS64] passed RTL guest r8169 observed physical carrier [ddom.secondary.carrier]", 13, 10, 0
str_vtd_net_dhcp_marker: db "[PAOS64] passed RTL guest r8169 obtained LAN DHCP lease [ddom.secondary.dhcp]", 13, 10, 0
str_vtd_net_udp_marker: db "[PAOS64] passed RTL guest UDP sender returned success [ddom.secondary.udp.egress]", 13, 10, 0
; Re-discover the live r8169 interface rather than trusting /init's shell
; variable (it is not exported across exec sh). Length is 226 bytes, below the
; virtio-console's strict 255-byte line limit.
str_vtd_net_carrier_probe_cmd: db 'D=/sys/class/net;I=;for P in $D/*;do R=$(/bin/busybox readlink $P/device/driver 2>/dev/null);[ "${R##*/}" = r8169 ]&&I=${P##*/};done;C=$(/bin/busybox cat $D/$I/carrier 2>/dev/null);echo PAOS_DDOM_CARRIER_NOW ${I:-none} ${C:-x}', 0
; Domain-L2 uses the existing BusyBox/initramfs but bypasses /init's guest-DHCP
; loop. Each line is below hv_vcon_rx_line's 255-byte ceiling (the interface
; command is 249 bytes). Interface probes
; always return a typed receipt: OK carries the exact r8169 identity; FAIL
; distinguishes discovery from link-up. X keeps tty echo from forging either.
str_vtd_domain_shell_cmd: db 'B=/bin/busybox;$B mount -t sysfs sysfs /sys&&$B mount -t proc proc /proc&&$B mount -t devtmpfs dev /dev&&X=SHELL_READY&&echo PAOS_DOMAIN_$X', 0
str_vtd_domain_iface_cmd: db 'D=/sys/class/net;A=;for P in $D/*;do R=$($B readlink $P/device/driver 2>/dev/null);[ "${R##*/}" = r8169 ]&&A=${P##*/};done;X=IFACE_FAIL;E=not_found;[ "$A" ]&&{ E=link_up;$B ip link set "$A" up&&X=IFACE_OK&&E=r8169;};echo PAOS_DOMAIN_$X ${A:-none} $E', 0
str_vtd_domain_carrier_cmd: db 'N=0;while [ $N -lt 50 ]&&[ "$($B cat $D/$A/carrier 2>/dev/null)" != 1 ];do $B usleep 200000;N=$((N+1));done;X=CARRIER_NOW;echo PAOS_DDOM_$X $A $($B cat $D/$A/carrier 2>/dev/null)', 0
str_vtd_domain_shell_ready: db 'PAOS_DOMAIN_SHELL_READY', 0
str_vtd_domain_iface_ok: db 'PAOS_DOMAIN_IFACE_OK ', 0
str_vtd_domain_iface_fail: db 'PAOS_DOMAIN_IFACE_FAIL ', 0
str_vtd_domain_iface_not_found: db 'not_found', 0
str_vtd_domain_iface_link_up: db 'link_up', 0
str_vtd_domain_bridge_pre: db 'A=', 0
; The LAN DHCP server returns OFFER/ACK as L2 unicast to chaddr.  A bridge port
; therefore must accept PaOS's second MAC, not just the passed RTL's own MAC.
; Request UP+PROMISC explicitly on both ports while enslaving them; relying on
; bridge auto-promisc left r8169 at AcceptMyPhys, while relying on /init for UP
; is invalid in the direct-shell path. One combined ip-link operation keeps the
; generated command bounded and makes the ready token fail closed.
str_vtd_domain_bridge_post: db ';C=/bin/busybox;for P in /sys/bus/virtio/devices/*/net/*;do B=${P##*/};done;$C ip link add br0 type bridge;[ $B ]||exit;for I in $A $B;do $C ip link set $I up promisc on master br0||exit;done;$C ip link set br0 up&&X=BRIDGE_OK&&echo PAOS_DOMAIN_$X', 0
str_vtd_domain_bridge_ok: db 'PAOS_DOMAIN_BRIDGE_OK', 0
str_dmaviol4_verb: db "DMAVIOL4", 0
str_dmaviol4_check_verb: db "DMAVIOL4_CHECK", 0
str_dmaviola_verb: db "DMAVIOLA", 0
str_dmaviola_check_verb: db "DMAVIOLA_CHECK", 0
str_staleowner_verb: db "STALEOWNER", 0
str_dmaviol_verb:      db "DMAVIOL", 0
str_dmaviol_check_verb: db "DMAVIOL_CHECK", 0
str_dmaviol_head:      db " DMAVIOL nonce=", 0
str_dmaviol_blocked:   db " VERDICT=BLOCKED source=dmar fault_delta=1 landed=0", 13, 10, 0
str_dmaviol_failed:    db " VERDICT=FAILED source=dmar fault_delta=", 0
str_dmaviol_stage:     db " stage=", 0
str_dmaviol_landed:    db " landed=", 0
str_dmaviol_nvme_status: db " nvme_status=", 0
str_dmaviol_target:    db " target=0x", 0
str_dmaviol_fsts:      db " fsts=0x", 0
str_dmaviol_frcd_lo:   db " frcd_lo=0x", 0
str_dmaviol_frcd_hi:   db " frcd_hi=0x", 0
str_dmaviol_bad_nonce: db " DMAVIOL ERR bad_nonce", 13, 10, 0
str_dmaviol_check_head: db " DMAVIOL_CHECK nonce=", 0
str_dmaviol_check_blocked: db " VERDICT=BLOCKED", 13, 10, 0
str_dmaviol_check_failed: db " VERDICT=FAILED", 13, 10, 0
str_dmaviol_check_stale: db " landed=1 VERDICT=STALE", 13, 10, 0
str_dmaviol_check_bad_nonce: db " DMAVIOL_CHECK ERR bad_nonce", 13, 10, 0
str_vtd_policy:        db "POLICY", 0
str_vtd_coverage:      db "COVERAGE", 0
str_vtd_cov_head:      db " VTD COVERAGE", 0
str_vtd_stat:          db "STAT SECONDARY", 0
str_vtd_trace:         db "TRACE", 0
str_vtd_trace_first_ud: db "TRACE FIRSTUD", 0
str_vtd_trace_context: db "TRACE CONTEXT", 0
str_vtd_diag_first_ud: db "DIAG FIRSTUD SECONDARY", 0
str_vtd_assign:        db "ASSIGN SECONDARY", 0
str_vtd_reclaim:       db "RECLAIM SECONDARY", 0
str_vtd_deadman:       db "DEADMAN TEST SECONDARY", 0
str_vtd_usage:         db " VTD ERR usage=GROUPS_[generation_cursor]|POLICY|COVERAGE|STAT_SECONDARY|TRACE|TRACE_FIRSTUD|TRACE_CONTEXT|DIAG_FIRSTUD_SECONDARY_nonce|ASSIGN_SECONDARY_nonce|RECLAIM_SECONDARY_nonce|DEADMAN_TEST_SECONDARY_nonce", 13, 10, 0
str_vtd_policy_ok:     db " VTD POLICY native_nic=protected native_nic_owner=host xhci=covered sata=covered nvme=covered unit_b_include_all=covered coverage_before_te=1 failure_fixture=1 identity_guard_fixture=1 observability_fixture=1 first_ud_fixture=1 bar_alias_fixture=1", 0
str_vtd_policy_ok_no_nvme: db " VTD POLICY native_nic=protected native_nic_owner=host xhci=covered sata=covered nvme=absent unit_b_include_all=covered coverage_before_te=1 failure_fixture=1 identity_guard_fixture=1 observability_fixture=1 first_ud_fixture=1 bar_alias_fixture=1", 0
str_vtd_policy_missing: db " VTD POLICY native_nic=unverified native_nic_owner=unverified xhci=missing sata=missing nvme=missing unit_b_include_all=missing coverage_before_te=0 failure_fixture=0 identity_guard_fixture=0 observability_fixture=0 first_ud_fixture=0 bar_alias_fixture=0", 0
str_vtd_guest_boot_allow_field: db " guest_boot_allow_ms=", 0
str_vtd_ownership_deadman_field: db " ownership_deadman_ms=", 0
str_vtd_policy_truth:  db " host_dev_dma=identity guest_dev_dma=restricted intr_remap=absent irq_isolation=none", 0
str_vtd_policy_truth_ir: db " host_dev_dma=identity guest_dev_dma=restricted intr_remap=enabled irq_isolation=remapped", 0
str_vtd_ir_on:     db "[PAOS64] vtd: interrupt remapping enabled (IRE+QIE read back, CFI=0, no present IRTE: device MSIs blocked) [vtd.ir.enabled]", 13, 10, 0
str_vtd_ir_reason_field: db " ir_reason=", 0
str_vtd_ir_absent: db "[PAOS64] vtd: interrupt remapping not enabled; posture intr_remap=absent [vtd.ir.absent]", 13, 10, 0
str_vtd_cov_state: db " cov_state=", 0
str_vtd_cov_reason: db " cov_reason=", 0
str_vtd_cov_unknown: db "unknown", 0
str_vtd_cov_index: db " cov_index=", 0
str_vtd_cov_requester: db " cov_requester=0x", 0
str_vtd_cov_expected: db " cov_expected=0x", 0
str_vtd_cov_observed: db " cov_observed=0x", 0
str_vtd_cov_native_nic_found: db " cov_native_nic_found=", 0
str_vtd_cov_xhci_found: db " cov_xhci_found=", 0
str_vtd_cov_sata_found: db " cov_sata_found=", 0
str_vtd_cov_nvme_found: db " cov_nvme_found=", 0
str_vtd_cov_overflow: db " cov_overflow=", 0
str_vtd_cov_count: db " cov_count=", 0
str_vtd_cov_native_nic_bdf: db " cov_native_nic_bdf=0x", 0
str_vtd_cov_xhci_bdf: db " cov_xhci_bdf=0x", 0
str_vtd_cov_sata_bdf: db " cov_sata_bdf=0x", 0
str_vtd_cov_nvme_bdf: db " cov_nvme_bdf=0x", 0
str_vtd_cov_nic_backend: db " nic_backend=", 0
str_vtd_cov_nic_step: db " nic_step=", 0
str_vtd_cov_nic_step_now: db " nic_step_now=", 0
str_vtd_cov_vmd_step: db " sata_vmd_step=", 0
str_vtd_cov_vmd_hits: db " sata_vmd_hits=", 0
str_vtd_cov_nic_link_wait: db " nic_link_wait=", 0
str_vtd_cov_reasons:
    db "none", 0
    times 27 db 0
    db "root_align", 0
    times 21 db 0
    db "ctx_align", 0
    times 22 db 0
    db "pml4_align", 0
    times 21 db 0
    db "pdpt_align", 0
    times 21 db 0
    db "root_present", 0
    times 19 db 0
    db "root_pointer", 0
    times 19 db 0
    db "root_upper", 0
    times 21 db 0
    db "ctx_present", 0
    times 20 db 0
    db "ctx_pointer", 0
    times 20 db 0
    db "ctx_upper", 0
    times 22 db 0
    db "native_nic_witness", 0
    times 13 db 0
    db "xhci_found", 0
    times 21 db 0
    db "sata_found", 0
    times 21 db 0
    db "list_overflow", 0
    times 18 db 0
    db "list_nonzero", 0
    times 19 db 0
    db "native_nic_context", 0
    times 13 db 0
    db "xhci_context", 0
    times 19 db 0
    db "sata_context", 0
    times 19 db 0
    db "nvme_context", 0
    times 19 db 0
    db "rtaddr", 0
    times 25 db 0
str_vtd_stat_head:     db " VTD STAT SECONDARY owner=", 0
str_vtd_guest:         db "guest", 0
str_vtd_host:          db "host", 0
str_vtd_unavailable:   db "unavailable", 0
str_vtd_nvme_found:    db " nvme_found=", 0
str_vtd_nvme_bdf:      db " nvme_bdf=0x", 0
str_vtd_fsts:          db " fsts=", 0
str_vtd_faults:        db " faults=", 0
str_vtd_frcd_lo:       db " frcd_lo=0x", 0
str_vtd_frcd_hi:       db " frcd_hi=0x", 0
str_vtd_nfr:           db " nfr=", 0
str_vtd_eol:           db 13, 10, 0
str_vtd_trace_head:    db " VTD TRACE nonce=", 0
str_vtd_trace_gen_field: db " trace_gen=", 0
str_vtd_diag_gen_field: db " diag_gen=", 0
str_vtd_trace_end:     db " trace_end=1", 0
str_vtd_first_ud_head: db " VTD TRACE FIRSTUD nonce=", 0
str_vtd_first_ud_context_head: db " VTD TRACE CONTEXT nonce=", 0
str_vtd_assign_gen_field: db " assign_gen=", 0
str_vtd_consumed_gen_field: db " consumed_gen=", 0
str_vtd_ud_valid_field: db " ud_valid=", 0
str_vtd_ud_info_field: db " ud_info=0x", 0
str_vtd_ud_error_field: db " ud_error=0x", 0
str_vtd_ud_idt_field: db " ud_idt=0x", 0
str_vtd_ud_idt_error_field: db " ud_idt_error=0x", 0
str_vtd_ud_ordinal_field: db " ud_ordinal=", 0
str_vtd_ud_no_reinject_field: db " ud_no_reinject=", 0
str_vtd_ud_exit_reason_field: db " ud_exit_reason=", 0
str_vtd_ud_bitmap_req_field: db " bitmap_req=0x", 0
str_vtd_ud_bitmap_live_field: db " bitmap_live=0x", 0
str_vtd_ud_first_r0_field: db " first_r0_info=0x", 0
str_vtd_ud_first_r0_gen_field: db " first_r0_gen=", 0
str_vtd_ud_rip_field: db " ud_rip=0x", 0
str_vtd_ud_rsp_field: db " ud_rsp=0x", 0
str_vtd_ud_rflags_field: db " ud_rflags=0x", 0
str_vtd_ud_cr2_field: db " ud_cr2=0x", 0
str_vtd_ud_cr3_field: db " ud_cr3=0x", 0
str_vtd_ud_cr4_field: db " ud_cr4=0x", 0
str_vtd_ud_cs_field: db " ud_cs=0x", 0
str_vtd_ud_walker_field: db " walker_valid=", 0
str_vtd_ud_page_size_field: db " page_size=0x", 0
str_vtd_ud_gpa_field: db " translated_gpa=0x", 0
str_vtd_ud_offset_field: db " page_offset=0x", 0
str_vtd_ud_pml4e_field: db " pml4e=0x", 0
str_vtd_ud_pdpte_field: db " pdpte=0x", 0
str_vtd_ud_pde_field: db " pde=0x", 0
str_vtd_ud_pte_field: db " pte=0x", 0
str_vtd_ud_insn_len_field: db " insn_len=", 0
str_vtd_ud_insn0_field: db " insn0=0x", 0
str_vtd_ud_insn1_field: db " insn1=0x", 0
str_vtd_ud_gpr_field: db " g", 0
str_vtd_ud_hex_value: db "=0x", 0
str_vtd_console_len_field: db " console_len=", 0
str_vtd_console_overflow_field: db " console_overflow=", 0
str_vtd_console_hex_field: db " console_hex=", 0
str_vtd_first_ud_end: db " fault_end=1", 0
str_vtd_first_ud_context_end: db " context_end=1", 0
str_vtd_assign_end:    db " assign_end=1", 0
str_vtd_assign_ok:     db " VTD ASSIGN SECONDARY nonce=", 0
str_vtd_assign_tail:   db " vendor=10ec owner=guest config_read=10ec root_present=1 context_present=1 guest_echo=", 0
str_vtd_assign_fail_head: db " VTD ASSIGN SECONDARY nonce=", 0
str_vtd_assign_fail_stage: db " ERR fail_stage=", 0
str_vtd_stage_context: db "context_assign", 0
str_vtd_stage_guest:   db "guest_proof", 0
str_vtd_stage_iommu:   db "iommu_fault", 0
str_vtd_stage_unknown: db "unknown", 0
str_vtd_guest_stage_field: db " guest_stage=", 0
str_vtd_guest_run_not_consumed: db "run_not_consumed", 0
str_vtd_guest_stop:    db "stop_wait", 0
str_vtd_guest_spawn:   db "spawn", 0
str_vtd_guest_boot:    db "boot_wait", 0
str_vtd_guest_boot_exit: db "boot_exit", 0
str_vtd_guest_inject:  db "inject", 0
str_vtd_guest_vendor_wait: db "vendor_wait", 0
str_vtd_guest_echo_wait: db "echo_wait", 0
str_vtd_guest_carrier_wait: db "carrier_wait", 0
str_vtd_guest_carrier_zero: db "carrier_zero", 0
str_vtd_guest_stop_field: db " guest_stage=stop_wait", 0
str_vtd_guest_spawn_field: db " guest_stage=spawn", 0
str_vtd_guest_boot_field: db " guest_stage=boot_wait", 0
str_vtd_guest_inject_field: db " guest_stage=inject", 0
str_vtd_guest_vendor_wait_field: db " guest_stage=vendor_wait", 0
str_vtd_guest_echo_wait_field: db " guest_stage=echo_wait", 0
str_vtd_guest_run_not_consumed_field: db " guest_stage=run_not_consumed", 0
str_vtd_guest_boot_exit_field: db " guest_stage=boot_exit", 0
str_vtd_run_req_field: db " run_req=", 0
str_vtd_task_started_field: db " task_started=", 0
str_vtd_start_gen_field: db " start_gen=", 0
str_vtd_start_consumed_field: db " start_consumed=", 0
str_vtd_load_err_field: db " load_err=", 0
str_vtd_launch_refused_field: db " launch_refused=", 0
str_vtd_vmxon_fail_field: db " vmxon_fail=", 0
str_vtd_vmcs_fail_field: db " vmcs_fail=", 0
str_vtd_instr_err_field: db " instr_err=", 0
str_vtd_vmwrite_fails_field: db " vmwrite_fails=", 0
str_vtd_last_exit_field: db " last_exit=", 0
str_vtd_linux_running_field: db " linux_running=", 0
str_vtd_linux_kboot_field: db " linux_kboot=", 0
str_vtd_vcon_ready_field: db " vcon_ready=", 0
str_vtd_vcon_rx_ready_field: db " vcon_rx_ready=", 0
str_vtd_vcon_tx_ready_field: db " vcon_tx_ready=", 0
str_vtd_inject_accepted_field: db " inject_accepted=", 0
str_vtd_capture_len_field: db " capture_len=", 0
str_vtd_ept_gpa_field: db " ept_gpa=0x", 0
str_vtd_ept_qual_field: db " ept_qual=0x", 0
str_vtd_ept_access_field: db " ept_access=", 0
str_vtd_ept_ilen_field: db " ept_ilen=", 0
str_vtd_ept_decode_field: db " ept_decode=", 0
str_vtd_ept_decode_len_field: db " ept_decode_len=", 0
str_vtd_ept_action_field: db " ept_action=", 0
str_vtd_ept_class_field: db " ept_class=", 0
str_vtd_ept_gen_field: db " ept_gen=", 0
str_vtd_vpci_trace_gen_field: db " vpci_trace_gen=", 0
str_vtd_vpci_trace_count_field: db " vpci_trace_count=", 0
str_vtd_vpci_trace_ordinal_field: db " vpci_write_ordinal=", 0
str_vtd_vpci_trace_overflow_field: db " vpci_trace_overflow=", 0
str_vtd_vpci_bar_index_field: db " vpci_bar_index=", 0
str_vtd_vpci_cfg_off_field: db " vpci_cfg_off=", 0
str_vtd_vpci_pio_width_field: db " vpci_pio_width=", 0
str_vtd_vpci_write_low_field: db " vpci_write_low=0x", 0
str_vtd_vpci_write_high_field: db " vpci_write_high=0x", 0
str_vtd_vpci_shadow_low_field: db " vpci_shadow_low=0x", 0
str_vtd_vpci_shadow_high_field: db " vpci_shadow_high=0x", 0
str_vtd_vpci_shadow_gpa_field: db " vpci_shadow_gpa=0x", 0
str_vtd_vpci_saved_low_field: db " vpci_saved_low=0x", 0
str_vtd_vpci_saved_high_field: db " vpci_saved_high=0x", 0
str_vtd_vpci_saved_hpa_field: db " vpci_saved_hpa=0x", 0
str_vtd_ept_map_attempts_field: db " ept_map_attempts=", 0
str_vtd_ept_map_result_field: db " ept_map_result=", 0
str_vtd_ept_map_gpa_field: db " ept_map_gpa=0x", 0
str_vtd_ept_map_hpa_field: db " ept_map_hpa=0x", 0
str_vtd_ept_leaf_addr_field: db " ept_leaf_addr=0x", 0
str_vtd_ept_leaf_value_field: db " ept_leaf_value=0x", 0
str_vtd_ept_leaf_readback_field: db " ept_leaf_readback=0x", 0
str_vtd_ept_invept_attempted_field: db " ept_invept_attempted=", 0
str_vtd_ept_invept_ok_field: db " ept_invept_ok=", 0
str_vtd_ept_invept_error_field: db " ept_invept_error=", 0
str_vtd_ept_exit_rip_field: db " ept_exit_rip=0x", 0
str_vtd_ept_exit_gla_field: db " ept_exit_gla=0x", 0
str_vtd_ept_exit_insn_field: db " ept_exit_insn=0x", 0
str_vtd_ept_exit_insn_len_field: db " ept_exit_insn_len=", 0
str_vtd_ept_bar_match_field: db " ept_bar_match=", 0
str_vtd_raw_saved_bar_field: db " saved_bar", 0
str_vtd_raw_guest_bar_field: db " guest_bar", 0
str_vtd_raw_bar_size_field: db " bar_size", 0
str_vtd_raw_hex_value: db "=0x", 0
str_vtd_ept_resume:    db "virtio_resume", 0
str_vtd_ept_access:    db "virtio_access", 0
str_vtd_ept_decode:    db "virtio_decode", 0
str_vtd_ept_bar:       db "assigned_bar", 0
str_vtd_ept_foreign:   db "foreign_gpa", 0
str_vtd_owner_field:   db " owner=", 0
str_vtd_owner_host_field: db " owner=host", 0
str_vtd_reclaim_verified_field: db " reclaim=verified", 0
str_vtd_reclaim_failed_field: db " reclaim=failed", 0
str_vtd_secondary_found_field: db " secondary_found=", 0
str_vtd_ready_field:   db " ready=", 0
str_vtd_reset_verified_field: db " reset_verified=", 0
str_vtd_guest_vendor_field: db " guest_vendor=", 0
str_vtd_guest_echo_seen_field: db " guest_echo_seen=", 0
str_vtd_reclaim_ok:    db " VTD RECLAIM SECONDARY nonce=", 0
str_vtd_owner_host:    db " owner=host reclaim=verified", 13, 10, 0
str_vtd_reclaim_fail:  db " VTD RECLAIM SECONDARY ERR reclaim=failed", 13, 10, 0
str_vtd_deadman_ok:    db " VTD DEADMAN TEST SECONDARY nonce=", 0
str_vtd_deadman_tail:  db " timed_out=1 deadman_reclaim=1 owner=host", 13, 10, 0
str_vtd_deadman_fail:  db " VTD DEADMAN TEST SECONDARY ERR", 13, 10, 0
str_vtd_bad_nonce:     db " VTD ERR bad_nonce", 13, 10, 0
str_vtd_guest_cmd_prefix: db "VTDN=", 0
str_vtd_guest_cmd_suffix: db "; echo VTDPCI=$(/bin/busybox cat /sys/bus/pci/devices/0000:00:01.0/vendor); echo VTDNONCE=$VTDN", 0
str_vtd_guest_expect_prefix: db "VTDNONCE=", 0
str_vtd_guest_vendor:  db "0x10ec", 0
str_vtd_fixture_nonce: db "FIXTURE-NONCE-1012", 0
str_vtd_fixture_run_not_consumed: db " guest_stage=run_not_consumed run_req=1 task_started=1 start_gen=101 start_consumed=100 load_err=0 launch_refused=0 vmxon_fail=0 vmcs_fail=0 instr_err=0 vmwrite_fails=0 last_exit=0 linux_running=0 linux_kboot=0 vcon_ready=0 vcon_rx_ready=0 vcon_tx_ready=0 inject_accepted=0 capture_len=0", 0
str_vtd_fixture_boot_wait: db " guest_stage=boot_wait run_req=0 task_started=1 start_gen=202 start_consumed=202 load_err=0 launch_refused=0 vmxon_fail=0 vmcs_fail=0 instr_err=0 vmwrite_fails=0 last_exit=10 linux_running=1 linux_kboot=0 vcon_ready=1 vcon_rx_ready=1 vcon_tx_ready=1 inject_accepted=0 capture_len=23", 0
str_vtd_fixture_boot_exit: db " guest_stage=boot_exit run_req=0 task_started=1 start_gen=303 start_consumed=303 load_err=6 launch_refused=0 vmxon_fail=0 vmcs_fail=1 instr_err=7 vmwrite_fails=2 last_exit=18 linux_running=0 linux_kboot=0 vcon_ready=0 vcon_rx_ready=0 vcon_tx_ready=0 inject_accepted=0 capture_len=37", 0
str_vtd_fixture_ept_resume: db " ept_gpa=0x00000000d0000044 ept_qual=0x0000000000000002 ept_access=2 ept_ilen=0 ept_decode=1 ept_decode_len=3 ept_action=1 ept_class=virtio_resume ept_gen=404", 0
str_vtd_fixture_ept_access: db " ept_gpa=0x00000000d0000048 ept_qual=0x0000000000000001 ept_access=1 ept_ilen=3 ept_decode=0 ept_decode_len=0 ept_action=0 ept_class=virtio_access ept_gen=404", 0
str_vtd_fixture_ept_decode: db " ept_gpa=0x00000000d000004c ept_qual=0x0000000000000002 ept_access=2 ept_ilen=3 ept_decode=2 ept_decode_len=0 ept_action=0 ept_class=virtio_decode ept_gen=404", 0
str_vtd_fixture_ept_bar: db " ept_gpa=0x00000000e3200050 ept_qual=0x0000000000000002 ept_access=2 ept_ilen=4 ept_decode=0 ept_decode_len=0 ept_action=0 ept_class=assigned_bar ept_gen=404", 0
str_vtd_fixture_ept_foreign: db " ept_gpa=0x00000000fee000b0 ept_qual=0x0000000000000004 ept_access=4 ept_ilen=5 ept_decode=0 ept_decode_len=0 ept_action=0 ept_class=foreign_gpa ept_gen=404", 0

str_vtd_ready_marker:     db "[PAOS64] vtd.ownership.ready Unit-B INCLUDE_PCI_ALL identity coverage before TE PASS", 13, 10, 0
str_vtd_assigned_marker:  db "[PAOS64] vtd.secondary.assigned state-machine KAT PASS", 13, 10, 0
str_vtd_reclaimed_marker: db "[PAOS64] vtd.secondary.reclaimed state-machine KAT PASS", 13, 10, 0
str_vtd_guest_substages_marker: db "[PAOS64] vtd.guest.failure.substages.ready six forced failure shapes PASS", 13, 10, 0
; vtd_ccmd_layout_kat vectors: DID, SID, FM (dwords; upper garbage must be
; masked), pad, then the CCMD qword derived by hand from the spec field table.
align 8
vtd_ccmd_kat_vectors:
    dd 0x0000BEEF, 0x00001234, 2, 0
    dq 0xE0000002_1234BEEF                ; 12:06.4, FM=2 (mask fn bit 2)
    dd 0x00000001, 0x000000FA, 0, 0
    dq 0xE0000000_00FA0001                ; DID 1, 00:1f.2 (boot path shape)
    dd 0x00000010, 0x00000300, 0, 0
    dq 0xE0000000_03000010                ; DID 0x10 guest, 03:00.0
    dd 0xFFFF0002, 0xABCD00FE, 0xFFFFFFFD, 0
    dq 0xE0000001_00FE0002                ; upper bits masked, FM=1
    dd 0x0000FFFF, 0x0000FFFF, 3, 0
    dq 0xE0000003_FFFFFFFF                ; all-ones fields, RsvdZ 58:34 clear
str_vtd_qi_on: db "[PAOS64] vtd: queued invalidation enabled (QI; register CCMD/IOTLB retired for this unit) [vtd.qi.enabled]", 13, 10, 0
str_vtd_ccmd_kat_pass: db "[PAOS64] vtd: CCMD device-selective layout KAT PASS vectors=5 DID=15:0 SID=31:16 FM=33:32 [vtd.ctx.inv.desc.kat]", 13, 10, 0
str_vtd_ccmd_kat_fail: db "[PAOS64] vtd: CCMD device-selective layout KAT FAIL remapping left off [vtd.ctx.inv.desc.fail]", 13, 10, 0
str_vtd_skip_no_drhd:  db "[PAOS64] vtd.ownership.skip reason=no_drhd", 13, 10, 0
str_vtd_skip_mmio_uc:  db "[PAOS64] vtd.ownership.skip reason=mmio_uc", 13, 10, 0
str_vtd_skip_sllps1g:  db "[PAOS64] vtd.ownership.skip reason=sllps1g", 13, 10, 0
str_vtd_skip_sagaw48:  db "[PAOS64] vtd.ownership.skip reason=sagaw48", 13, 10, 0
str_vtd_skip_tes_fw:   db "[PAOS64] vtd.ownership.skip reason=tes_fw", 13, 10, 0
str_vtd_skip_alloc:    db "[PAOS64] vtd.ownership.skip reason=alloc", 13, 10, 0
str_vtd_skip_pmen:     db "[PAOS64] vtd.ownership.skip reason=pmen", 13, 10, 0
str_vtd_skip_srtp:     db "[PAOS64] vtd.ownership.skip reason=srtp", 13, 10, 0
str_vtd_skip_coverage: db "[PAOS64] vtd.ownership.skip reason=coverage", 13, 10, 0
str_vtd_skip_domain:   db "[PAOS64] vtd.ownership.skip reason=domain", 13, 10, 0
str_vtd_skip_qi:       db "[PAOS64] vtd.ownership.skip reason=qi", 13, 10, 0
str_vtd_skip_inval:    db "[PAOS64] vtd.ownership.skip reason=inval", 13, 10, 0
str_vtd_skip_te_timeout: db "[PAOS64] vtd.ownership.skip reason=te_timeout", 13, 10, 0
str_vtd_skip_te_faults: db "[PAOS64] vtd.ownership.skip reason=te_faults", 13, 10, 0
str_vtd_skip_te_bind:  db "[PAOS64] vtd.ownership.skip reason=te_bind", 13, 10, 0
str_vtd_identity_guard_marker: db "[PAOS64] vtd.guest.identity.guard.ready init 10ec:ffff then exact saved identity PASS", 13, 10, 0
str_vtd_guest_observability_marker: db "[PAOS64] vtd.guest.bootwait.observability.ready request-not-consumed boot-wait early-exit fixed shapes PASS", 13, 10, 0
str_vtd_guest_ept_detail_marker: db "[PAOS64] vtd.guest.ept.exit.detail.ready virtio-resume access decode assigned-bar foreign-gpa fixed shapes PASS", 13, 10, 0
str_vtd_first_ud_marker: db "[PAOS64] vtd.guest.reason0.first_ud.ready assigned-generation #UD decoder walker transport fixtures PASS", 13, 10, 0
str_vtd_first_ud_fail: db "[PAOS64] vtd.guest.reason0.first_ud.fail stage=0x", 0
str_vtd_bar_alias_marker: db "[PAOS64] vtd.bar.alias.trace.ready config-write mapper readback fixture PASS", 13, 10, 0
str_vtd_bar_alias_fail: db "[PAOS64] vtd.bar.alias.trace.fail stage=0x", 0
str_vtd_post_dhcp_carrier_marker: db "[PAOS64] vtd.guest.post_dhcp_carrier.ready direct post-DHCP carrier fixture PASS [vtd.guest.post_dhcp_carrier.ready]", 13, 10, 0
str_vtd_post_dhcp_carrier_fail: db "[PAOS64] vtd.guest.post_dhcp_carrier.fail stage=0x", 0
str_vtd_fixture_carrier_iface: db "enp0s1", 0
str_vtd_fixture_carrier_stale: db "PAOS_DDOM_CARRIER_STABLE enp0s1 stable=5", 10, 0
str_vtd_fixture_carrier_zero: db "PAOS_DDOM_CARRIER_NOW enp0s1 0", 10, 0
str_vtd_fixture_carrier_wrong: db "PAOS_DDOM_CARRIER_NOW eth9 1", 10, 0
str_vtd_fixture_carrier_missing: db "PAOS_DDOM_UNRELATED enp0s1 1", 10, 0
str_vtd_fixture_carrier_one: db "PAOS_DDOM_CARRIER_NOW enp0s1 1", 10, 0
str_vtd_native_domains_marker: db "[PAOS64] iommu.native.domains DID=2 native_nic+ahci+nvme restrictive 4K valid-set armed", 13, 10, 0
str_vtd_dma_mapped_marker: db "[PAOS64] iommu.dma.mapped dma_alloc records installed into VT-d native domain", 13, 10, 0
str_vtd_udp_ready:        db " vtd.ownership.ready", 13, 10, 0
str_vtd_udp_assigned:     db " vtd.secondary.assigned", 13, 10, 0
str_vtd_udp_reclaimed:    db " vtd.secondary.reclaimed", 13, 10, 0
str_vtd_udp_observability: db " vtd.guest.bootwait.observability.ready", 13, 10, 0
str_vtd_udp_native_domains: db " iommu.native.domains", 13, 10, 0
str_vtd_udp_dma_mapped:    db " iommu.dma.mapped", 13, 10, 0
; ---- RCQ-19 S1: isolation precondition and standing-domain lifecycle ----
align 8
times 8 db 0                  ; vtd_iso_snap..vtd_dd_fault_kind moved to WDATA_hv_vtd_0_bss2: keeps the labels below at their offset mod 64
vtd_iso_reason_names:   db "eligible", 0
                        times 15 db 0
                        db "no_iommu", 0
                        times 15 db 0
                        db "unsupported_backend", 0
                        times 4 db 0
                        db "facts_incomplete", 0
                        times 7 db 0
                        db "cycle", 0
                        times 18 db 0
                        db "rmrr", 0
                        times 19 db 0
                        db "alias", 0
                        times 18 db 0
                        db "protected_peer", 0
                        times 9 db 0
                        db "shared_dma", 0
                        times 13 db 0
                        db "segment", 0
                        times 16 db 0
                        db "unknown", 0
                        times 16 db 0
vtd_dd_state_names:     db "idle", 0
                        times 7 db 0
                        db "starting", 0
                        times 3 db 0
                        db "serving", 0
                        times 4 db 0
                        db "restarting", 0
                        times 1 db 0
                        db "recovering", 0
                        times 1 db 0
                        db "exhausted", 0
                        times 2 db 0
                        db "stranded", 0
                        times 3 db 0
                        db "unknown", 0
                        times 4 db 0
vtd_dd_cause_names:     db "none", 0
                        times 7 db 0
                        db "crash", 0
                        times 6 db 0
                        db "hang", 0
                        times 7 db 0
                        db "proof", 0
                        times 6 db 0
                        db "boot", 0
                        times 7 db 0
                        db "unknown", 0
                        times 4 db 0
str_vtd_iso_field:      db " assign_iso=", 0
str_vtd_iso_no_target:  db "no_target", 0
str_vtd_iso_unchecked:  db "unchecked", 0
str_vtd_iso_parent:     db " iso_parent=", 0
str_vtd_iso_root:       db "root", 0
str_vtd_iso_group:      db " iso_group=", 0
str_vtd_iso_acs:        db " iso_acs=unknown", 0
str_vtd_colon:          db ":", 0
str_vtd_dot:            db ".", 0
str_vtd_stage_isolation: db "isolation", 0
str_vtd_dd_state:       db " dd_state=", 0
str_vtd_dd_gen:         db " dd_gen=", 0
str_vtd_dd_restarts:    db " dd_restarts=", 0
str_vtd_dd_budget_left: db " dd_budget_left=", 0
str_vtd_dd_cause:       db " dd_cause=", 0
str_vtd_dd_detect_ms:   db " dd_detect_ms=", 0
str_vtd_dd_restore_ms:  db " dd_restore_ms=", 0
str_vtd_dd_lease_ms:    db " dd_lease_ms=", 0
str_vtd_dd_faults:      db " dd_faults=", 0
str_vtd_dd_failures:    db " dd_failures=", 0
str_vtd_dd_renewals:    db " dd_renewals=", 0
str_vtd_dd_probes:      db " dd_probes=", 0
str_vtd_dd_policy_lease: db " domain_lease_ms=", 0
str_vtd_dd_policy_budget: db " domain_restart_budget=", 0
str_vtd_dd_policy_window: db " domain_restart_window_ms=", 0
str_vtd_dd_crash_cmd:   db "exit", 0
str_vtd_dd_hang_cmd:    db "/bin/busybox ip link set br0 down", 0
str_vtd_dd_fault_log:   db "[PAOS64] vtd.domain.fault injected", 13, 10, 0
str_vtd_dd_fault_refused_log: db "[PAOS64] vtd.domain.fault refused state", 13, 10, 0
str_vtd_dd_fault_busy_log: db "[PAOS64] vtd.domain.fault refused busy", 13, 10, 0
str_vtd_dd_fault_args_log: db "[PAOS64] vtd.domain.fault refused args", 13, 10, 0
str_ddom_net_fault:     db "NET FAULT", 0
str_ddom_fault_crash:   db "crash", 0
str_ddom_fault_hang:    db "hang", 0
str_ddom_fault_ok:      db " DDOM NET FAULT nonce=", 0
str_ddom_fault_refused: db " DDOM NET FAULT ERR not_serving nonce=", 0
str_ddom_fault_busy:    db " DDOM NET FAULT ERR console_busy nonce=", 0
%endmacro
WDATA_DEFER WDATA_hv_vtd_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_hv_vtd_0_bss1 0
alignb 8
vtd_irt:               resq 1              ; SEC-D3b interrupt remapping table page
vtd_shared_ctx:        resq 1
vtd_id_pml4:           resq 1
vtd_id_pdpt:           resq 1
vtd_bus_ctx:           resq 1
vtd_native_pool_base:  resq 1
vtd_native_pml4:       resq 1
vtd_hda_pml4:          resq 1              ; RCQ-36 DID 3; must follow vtd_native_pml4 (domain index)
vtd_dmaviol_target_page: resq 1
vtd_dmaviol_canary:    resq 1
vtd_dmaviol_fault_before: resq 1
vtd_dmaviol_frcd_lo:   resq 1
vtd_dmaviol_frcd_hi:   resq 1
vtd_native_bus_ctx:    resq 256
vtd_guest_pml4:        resq 1
vtd_guest_pdpt:        resq 1
vtd_guest_dom_hpa:     resq 1          ; RCQ-50 F1: DID 0x10's recorded guest RAM
vtd_guest_dom_bytes:   resq 1
vtd_guest_pd:          resq VTD_GUEST_RAM_PDS   ; RCQ-50: PDPT[0..2]
vtd_secondary_bar2_mmio: resq 1
vtd_deadman_tsc:       resq 1
vtd_wait_deadline:     resq 1
vtd_net_command_ptr:   resq 1
vtd_net_phy_edge_tnpds: resq 1
vtd_last_frcd_lo:      resq 1
vtd_last_frcd_hi:      resq 1
vtd_assign_frcd_lo:    resq 1
vtd_assign_frcd_hi:    resq 1
vtd_assign_ept_gpa:    resq 1
vtd_assign_ept_qual:   resq 1
vtd_ept_root:          resq 1
vtd_ept_pool_base:     resq 1
vtd_vpci_trace_current: resq 1
vtd_vpci_shadow_gpa:   resq 1
vtd_vpci_saved_hpa:    resq 1
vtd_ept_map_gpa:       resq 1
vtd_ept_map_hpa:       resq 1
vtd_ept_leaf_addr:     resq 1
vtd_ept_leaf_value:    resq 1
vtd_ept_leaf_readback: resq 1
vtd_assign_vpci_shadow_gpa: resq 1
vtd_assign_vpci_saved_hpa: resq 1
vtd_assign_ept_map_gpa: resq 1
vtd_assign_ept_map_hpa: resq 1
vtd_assign_ept_leaf_addr: resq 1
vtd_assign_ept_leaf_value: resq 1
vtd_assign_ept_leaf_readback: resq 1
vtd_assign_ept_exit_rip: resq 1
vtd_assign_ept_exit_gla: resq 1
vtd_assign_ept_exit_insn: resq 1
vtd_fixture_save_cfg: resq 3
vtd_fixture_save_shadow: resq 3
vtd_fixture_save_bar_size: resq 3
vtd_fixture_save_root: resq 1
vtd_fixture_save_pool: resq 1
vtd_fixture_save_gpr: resq 1
alignb 16
vtd_invept_desc:      resq 2
vtd_out_cur:           resq 1
vtd_secondary_bdf:     resd 1
vtd_secondary_bridge:  resd 1
vtd_e1000e_bdf:        resd 1
vtd_xhci_bdf:          resd 1
vtd_sata_bdf:          resd 1
vtd_nvme_bdf:          resd 1
vtd_secondary_cmd:     resd 1
vtd_vpci_addr:         resd 1
vtd_fsts:              resd 1
vtd_fault_count:       resd 1
vtd_native_pool_next:  resd 1
vtd_native_record_count: resd 1
vtd_native_mapped_pages: resd 1
vtd_hda_mapped_pages:  resd 1              ; must follow vtd_native_mapped_pages (domain index)
vtd_dmaviol_fault_delta: resd 1
vtd_dmaviol_nvme_status: resd 1
vtd_dmaviol_stage:     resd 1
vtd_assign_fsts:       resd 1
vtd_assign_fault_count: resd 1
vtd_guest_start_gen:   resd 1
vtd_first_ud_diag_gen: resd 1
vtd_assign_start_gen:  resd 1
vtd_assign_start_consumed: resd 1
vtd_assign_instr_err:  resd 1
vtd_assign_vmwrite_fails: resd 1
vtd_assign_last_exit:  resd 1
vtd_assign_capture_len: resd 1
vtd_assign_ept_ilen:   resd 1
vtd_assign_ept_decode_len: resd 1
vtd_assign_ept_gen:    resd 1
vtd_vpci_trace_run_gen: resd 1
vtd_vpci_trace_gen:    resd 1
vtd_vpci_trace_count:  resd 1
vtd_vpci_trace_ordinal: resd 1
vtd_vpci_write_low:    resd 1
vtd_vpci_write_high:   resd 1
vtd_vpci_shadow_low:   resd 1
vtd_vpci_shadow_high:  resd 1
vtd_vpci_saved_low:    resd 1
vtd_vpci_saved_high:   resd 1
vtd_ept_map_attempts:  resd 1
vtd_ept_invept_error:  resd 1
vtd_vpci_last_write:   resd 6
vtd_assign_vpci_trace_gen: resd 1
vtd_assign_vpci_trace_count: resd 1
vtd_assign_vpci_trace_ordinal: resd 1
vtd_assign_vpci_write_low: resd 1
vtd_assign_vpci_write_high: resd 1
vtd_assign_vpci_shadow_low: resd 1
vtd_assign_vpci_shadow_high: resd 1
vtd_assign_vpci_saved_low: resd 1
vtd_assign_vpci_saved_high: resd 1
vtd_assign_ept_map_attempts: resd 1
vtd_assign_ept_invept_error: resd 1
vtd_assign_ept_exit_insn_len: resd 1
vtd_assign_saved_bar:   resd 6
vtd_assign_guest_bar:   resd 6
vtd_assign_bar_size:    resd 6
vtd_fixture_save_vpci_addr: resd 1
vtd_reclaim_count:     resd 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_0_bss1
%macro WDATA_hv_vtd_0_bss2 0
resb 56                 ; keeps vtd_iso_snap at its WDATA offset mod 64
alignb 8
vtd_iso_snap:           resb DA_SNAP_MAX * DA_SNAP_SZ
vtd_iso_record:         resb DA_REC_BYTES
vtd_iso_snap_n:         resd 1
vtd_iso_incomplete:     resb 1
vtd_iso_reason:         resb 1
vtd_iso_valid:          resb 1             ; 0 never checked, 1 verdict, 2 no target
alignb 8
vtd_dd_ring:            resq VTD_DD_BUDGET         ; relaunch TSCs (budget window)
vtd_dd_detect_tsc:      resq 1
vtd_dd_fault_tsc:       resq 1
vtd_dd_renew_tsc:       resq 1
vtd_dd_probe_tsc:       resq 1
vtd_dd_restart_due:     resq 1
vtd_dd_progress:        resq 1             ; virtio_domain_guest_progress at last renewal
vtd_dd_renewals:        resq 1
vtd_dd_gen:             resd 1
vtd_dd_restarts:        resd 1
vtd_dd_failures:        resd 1
vtd_dd_detect_ms:       resd 1
vtd_dd_restore_ms:      resd 1
vtd_dd_probes:          resd 1
vtd_dd_faults:          resd 1
vtd_dd_state:           resb 1
vtd_dd_cause:           resb 1
vtd_dd_ring_pos:        resb 1
vtd_dd_fault_kind:      resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_0_bss2
%macro WDATA_hv_vtd_0_bss3 0
resb 34                 ; keeps vtd_net_chipcmd at its WDATA offset mod 64
vtd_net_chipcmd:       resb 1
vtd_net_physts:        resb 1
vtd_net_phy_edge_state: resb 1
vtd_net_phy_edge_physts: resb 1
vtd_net_phy_edge_chipcmd: resb 1
vtd_net_phy_edge_tppoll: resb 1
vtd_net_phy_edge_txring: resb 1
vtd_net_phy_edge_linkchg_seen: resb 1
vtd_net_phy_edge_linkchg_injected: resb 1
; Kept contiguous: vtd_net_reset_session clears all sixteen rolling indices.
vtd_net_match_uplink:  resb 1
vtd_net_match_driver:  resb 1
vtd_net_match_cwait_enter: resb 1
vtd_net_match_cwait_tick: resb 1
vtd_net_match_cwait_carr: resb 1
vtd_net_match_carrier: resb 1
vtd_net_match_stable:  resb 1
vtd_net_match_carrier_timeout: resb 1
vtd_net_match_link_up: resb 1
vtd_net_match_arp:     resb 1
vtd_net_match_sent:    resb 1
vtd_net_match_carrier_now: resb 1
vtd_net_match_domain_bridge: resb 1
vtd_net_match_domain_shell: resb 1
vtd_net_match_domain_iface: resb 1
vtd_net_match_domain_iface_fail: resb 1
vtd_vpci_bar_probe:    resb 6
alignb 4
vtd_vpci_guest_bar:    resd 6
alignb 8
vtd_bdf_list:          resd VTD_BDF_MAX
vtd_nic_probe_step:    resb 1             ; VTD COVERAGE diagnostics (vtd_append_probe_steps)
vtd_nic_probe_backend: resb 1
vtd_nic_boot_step:     resb 1
vtd_nic_boot_backend:  resb 1
vtd_sata_vmd_step:     resb 1
vtd_sata_vmd_hits:     resb 1
vtd_nic_probe_link_wait: resb 1           ; the Killer was taken DEGRADED only for its link
vtd_nic_boot_link_wait:  resb 1
alignb 8
vtd_secondary_cfg:     resb VTD_CFG_BYTES
vtd_nonce:             resb 64
vtd_net_lease:         resb 16
vtd_net_iface:         resb 16
vtd_net_carrier_now_iface: resb 16
vtd_domain_iface_fail_reason: resb 16
vtd_dmaviol_nonce:     resb 64
vtd_guest_command:     resb 256
vtd_guest_expected:    resb 96
vtd_domain_bridge_command: resb 256
alignb 8
vtd_domain_iface_next_tsc: resq 1
alignb 8
vtd_vpci_trace_entries: resb VTD_VPCI_TRACE_MAX * VTD_TRACE_ENTRY_BYTES
alignb 8
; The boot-only fixture borrows the response-buffer reservation before any
; VTD command can run. The extra 4095 bytes let the fixture round the loaded
; address up at runtime and still own six complete synthetic table pages.
vtd_bar_alias_fixture_pages:
vtd_out_buf:           resb VTD_OUT_MAX + 1
                       resb 5 * 4096 + 4095
vtd_dec_tmp:           resb 16
vtd_hex_tmp:           resb 17
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_0_bss3

; RCQ-19 Lenovo 0.0.65 (root 00:26:37): the typed refusal behind DDOM NET STAT's
; refusal= field. Its own block, outside the
; zero-storage split of WDATA_hv_vtd_0.
; RCQ-12 0.0.68: the recorded outcome. Its own block, outside the zero-storage split of _0.
%macro WDATA_hv_vtd_3 0
alignb 8
vtd_out_line:          resq 1                ; set only from a str_vtd_skip_* lea at .skip_say/.skip_record_disable
vtd_outcome:           resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_3

; Intel DMAVIOLA state, its own block outside the zero-storage split of _0.
%macro WDATA_hv_vtd_dmavia 0
alignb 8
vtd_dmavia_canary:      resq 1
vtd_dmavia_fault_before: resq 1
vtd_dmavia_frcd_lo:     resq 1
vtd_dmavia_frcd_hi:     resq 1
vtd_dmavia_bdf:         resd 1
vtd_dmavia_fault_delta: resd 1
vtd_dmavia_ahci_status: resd 1
vtd_dmavia_stage:       resd 1
vtd_dmavia_valid:       resb 1
vtd_dmavia_blocked:     resb 1
vtd_dmavia_landed:      resb 1
vtd_dmavia_nonce:       resb 64
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_dmavia

; RCQ-36 S5b DID 3: fixed strings and fixed-stride name tables (no pointer table).
%macro WDATA_hv_vtd_hda 0
str_vtd_hda_prefix:     db "vtd.hda ", 0
str_vtd_hda_refused:    db "state=refused reason=", 0
str_vtd_hda_poison:     db "state=poison reason=", 0
str_vtd_hda_ok_bdf:     db "state=ok class=040300 bdf=", 0
str_vtd_hda_ok80_bdf:   db "state=ok class=040380 bdf=", 0
str_vtd_hda_sid:        db " sid=", 0
str_vtd_hda_ctx_qi:     db " ctx=P1,TT0,DID3,AW2 enforcing=1 qi=", 0
str_vtd_hda_drain:      db " inval=completed drain=", 0
str_vtd_hda_ats:        db " quiesce=1 ats=", 0
str_vtd_hda_live_ats:   db " lifecycle=active ats=", 0
str_vtd_hda_serial:     db " map_serial=", 0
str_vtd_hda_tail:       db " disjoint=1 nops=1 fsts=0 pool=", 0
str_vtd_hda_slash:      db "/", 0
vtd_hda_reason_names:   db "ok", 0
                        times 13 db 0
                        db "poisoned", 0
                        times 7 db 0
                        db "attached", 0
                        times 7 db 0
                        db "no_enforcement", 0
                        times 1 db 0
                        db "not_found", 0
                        times 6 db 0
                        db "class", 0
                        times 10 db 0
                        db "guest_live", 0
                        times 5 db 0
                        db "bar", 0
                        times 12 db 0
                        db "foreign_drhd", 0
                        times 3 db 0
                        db "not_quiesced", 0
                        times 3 db 0
                        db "ats_enabled", 0
                        times 4 db 0
                        db "ctx_state", 0
                        times 6 db 0
                        db "pool", 0
                        times 11 db 0
                        db "inval_timeout", 0
                        times 2 db 0
                        db "readback", 0
                        times 7 db 0
                        db "rmrr", 0
                        times 11 db 0
                        db "alias", 0
                        times 10 db 0
                        db "facts", 0
                        times 10 db 0
                        db "disjoint", 0
                        times 7 db 0
                        db "nops", 0
                        times 11 db 0
                        db "fsts", 0
                        times 11 db 0
                        db "not_attached", 0
                        times 3 db 0
                        db "unknown", 0
                        times 8 db 0
vtd_hda_drain_names:    db "none", 0
                        times 11 db 0
                        db "dw", 0
                        times 13 db 0
                        db "dr", 0
                        times 13 db 0
                        db "dr,dw", 0
                        times 10 db 0
vtd_hda_ats_names:      db "absent", 0
                        times 9 db 0
                        db "disabled", 0
                        times 7 db 0
                        db "unread", 0
                        times 9 db 0
%endmacro
WDATA_DEFER WDATA_hv_vtd_hda
%macro WDATA_hv_vtd_hda_bss 0
alignb 8
vtd_hda_map_serial:    resq 1              ; bumped by every DID-3 map/unmap and the attach
vtd_hda_mmio:          resq 1
vtd_hda_bdf:           resd 1
vtd_hda_state:         resb 1              ; VTD_HDA_IDLE/OK/REFUSED/POISON
vtd_hda_reason:        resb 1              ; VTD_HDA_R_* of the last refusal or poison
vtd_hda_line:          resb VTD_HDA_LINE_MAX + 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_hda_bss
%macro WDATA_hv_vtd_1 0
str_ddom_refusal:       db " refusal=", 0
str_ddom_refusal_dot:   db ".", 0
vtd_assign_refusal:     db 0            ; VTD_REFUSE_* of the last assignment,
vtd_assign_reset_refusal: db 0          ;   its handoff reset's (both cleared as one word)
vtd_reset_refusal:      db 0            ;   and the last reset's, from any caller
%endmacro
WDATA_DEFER WDATA_hv_vtd_1
