;; MODULE hv/vmx
%include "core/abi/build_profile.inc"
%include "hv/guest_power.inc"
%include "core/abi/memory_budget.inc"
%include "hv/boot_guest_lab_profile.inc"

;; LAYER 5
;; EXPORTS hv_linux_kernel_size, hv_linux_initrd_size, hv_linux_initrd_gpa, hv_guest_panic_request, hv_panic_armed, hv_panic_injected, hv_panic_text, hv_terminal_status, hv_terminal_attach, hv_terminal_read, hv_terminal_write, hv_terminal_resize, hv_terminal_detach, hv_linux_exit_hex, hv_linux_exits, hv_linux_host_slices, hv_linux_mb_token, hv_linux_mb_gen, hv_vcon_pmr_bind, hv_vcon_pmr_stop, hv_vcon_pmr_unbind, hv_vcon_pmr_retry, hv_media_guest_select, hv_media_guest_launch, hv_media_window_release, hv_linux_boot_start, hv_linux_boot_poll, hv_linux_load_yield, hv_vmx_detect, hv_guest_linux_start, hv_linux_region, hv_linux_region_capacity, hv_linux_region_resident, hv_linux_gpr, hv_linux_exit_dispatch, hv_linux_host_slice, hv_linux_save_host_msrs, hv_linux_restore_host, hv_linux_restore_host_quiet, hv_linux_host_xsave, hv_linux_xcr0_to_host, hv_linux_xcr0_to_guest, hv_linux_vector_scrub, hv_linux_cr_gpr_map, hv_linux_arm_deadline, hv_linux_wrmsr_rax, hv_launch_mode, hv_launches, hv_launch_rflags, hv_launch_cr0, hv_launch_cr4, hv_launch_hcr0, hv_launch_hcr4, hv_first_ud_bitmap_value, hv_first_ud_latch_arm, hv_vmx_enable, hv_vmx_setup, hv_vmx_map, hv_vmx_launch, hv_vmx_exit_dispatch, hv_vmx_selftest, hv_vmx_can_inject_extint, hv_vmx_inject_extint, hv_vmx_intr_window, hv_vmx_slat_flush, hv_vmx_slat_bits, hv_vmx_guest_cr3, hv_vmx_guest_read, hv_w, hv_register_verbs, hv_status_line, hv_out_ready, hv_out_buf, hv_out_reset, hv_out_str, hv_out_dec, hv_tok_is, hv_skip_spaces, hv_vcon_pmr_bound, hv_vcon_pmr_pending, hv_vcon_pmr_fault, hv_vmx_present, hv_vmxon_ok, hv_ept_built, hv_linux_kboot, hv_guest_launched, hv_guest_booted, hv_guest_launched_ms, hv_vcon_ready, hv_linux_running, hv_linux_vmx_live, hv_linux_eptp, hv_linux_run_req, hv_linux_stop_req, hv_linux_task_started, hv_linux_start_active, hv_linux_start_gen, hv_linux_start_consumed, hv_linux_run_start_tsc, hv_linux_panicked, hv_guest_linux_request_start, hv_guest_linux_task, hv_linux_gpa2hva, hv_linux_gva2hva, hv_vcon_rx_line, hv_vcon_q_ready, hv_vcon_capture_len, hv_vcon_capture_overflow, hv_vcon_capture, hv_vcon_proof_roll_begin, hv_vcon_proof_roll_finish, hv_vcon_proof_roll_abort, hv_vcon_proof_roll_state_reset, hv_vcon_proof_roll_fixture_selftest, hv_vcon_proof_roll_fixture_ok, hv_linux_load_err, hv_launch_refused, hv_launch_vmcsfail, hv_launch_vmxonfail, hv_instr_err, hv_vmwrite_fails, hv_exit_reason, hv_guestcpu_run_tsc_accum, hv_guestcpu_last_progress_tsc, hv_guestcpu_interrupts, hv_guestcpu_halt_wakes, hv_guestcpu_faults, hv_linux_ept_classify, hv_linux_ept_note_decode, hv_ept_exit_gpa, hv_ept_exit_qual, hv_ept_exit_rip, hv_ept_exit_gla, hv_ept_exit_insn, hv_ept_exit_gen, hv_ept_exit_ilen, hv_ept_exit_insn_len, hv_ept_exit_decode_len, hv_ept_exit_access, hv_ept_exit_decode, hv_ept_exit_class, hv_ept_exit_action, hv_ept_exit_bar_match, hv_first_ud_fixture_selftest, hv_first_ud_fixture_ok, hv_first_ud_fixture_stage, hv_first_ud_valid, hv_first_ud_info, hv_first_ud_error, hv_first_ud_idt_info, hv_first_ud_idt_error, hv_first_ud_rip, hv_first_ud_rsp, hv_first_ud_rflags, hv_first_ud_cr2, hv_first_ud_cr3, hv_first_ud_cr4, hv_first_ud_cs, hv_first_ud_gen, hv_first_ud_ordinal, hv_first_ud_no_reinject, hv_first_ud_exit_reason, hv_first_ud_walker_valid, hv_first_ud_page_size, hv_first_ud_gpa, hv_first_ud_offset, hv_first_ud_pml4e, hv_first_ud_pdpte, hv_first_ud_pde, hv_first_ud_pte, hv_first_ud_insn_len, hv_first_ud_console_len, hv_first_ud_console_overflow, hv_first_ud_bitmap_requested, hv_first_ud_bitmap_readback, hv_first_ud_first_r0_info, hv_first_ud_first_r0_gen, hv_first_ud_insn, hv_first_ud_gpr, hv_first_ud_console
;; IMPORTS hv/driver_domain_restart, hv/interpreter_execution, hv/context_execution, hv/boundary_execution, hv/guest_transport, hv/vcpu_svm_dispatch, svc/command_auth, hv/vcpu_status, hv/vcpu_observe, hv/vcpu_start_admit, hv/vcpu_start_close, hv/vcpu_write_guard, hv/vcpu_bsp_context, hv/vcpu_bsp_state, hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, hv/boundary, hv/warm_lifecycle, media/pmr1_host_private, boot/boot_v2_handoff, boot/boot_esp_guid, boot/header, hv/guest_power, boot/serial, boot/gdt, core/dma, core/memmap, core/time, core/sched, svc/command, svc/command_udp, fs/vfs, svc/command_guestfile, hv/vtd, hv/guest_surface, hv/cdp_bridge, hv/domain_channel, hv/hv_ops, hv/guestdisplay, hv/svm, hv/vm_profile, hv/guestentropy, hv/guestrestore, hv/guestsnap, hv/pad_channel, hv/pci_assign, core/memory_budget, hv/input_domain_command, hv/driver_domain, hv/wifi_channel, hv/guestwifi, hv/nic_observation, hv/capability_observation
;; CAPS
;; OWNER saga:hv
%include "hv/vcpu_bsp.inc"
;; CONTEXT: bsp_only
%include "hv/guest_media_contract.inc"
; ============================================================================
; hv/vmx.asm — M4 hypervisor: the VMX ROOT-MODE FOUNDATION (contract 1011 v1).
;
; This is the honest FIRST RUNG of the four-pillar VM thesis (driver-domain,
; sandbox, compute-market airlock, hatch). It ports the PROVEN monolith bring-up
; SEQUENCE (drivers/vmx_hypervisor: shipped 9257 v0.7.258 VMX core, 9370 EPT) —
; the CPUID/feature-control/CR0-CR4-fixed-bits/VMXON dance that already ran on
; THIS class of hardware — and adapts it to the rework seams (core/dma phys==virt
; buffers, the svc/command verb registry).
;
; WHAT v1 GENUINELY DELIVERS (bare-metal verifiable, ZERO hard-hang risk):
;   - hv.vmx.detected   : CPUID VMX + IA32_FEATURE_CONTROL honestly read
;   - hv.vmxon.ok       : a REAL VMXON->VMCLEAR->VMPTRLD->VMXOFF round-trip
;                         (CPU actually enters + leaves VMX root operation)
;   - hv.ept.mapped     : a REAL 4-level EPT structure (PML4/PDPT/PD/PT) built +
;                         a valid EPTP composed (GPA 0 -> an HPA guest page)
;
; R2-R4 ADDITIONS (1095b/1095c): GUESTVM START streams the staged Linux pair,
; then keeps it scheduler-resident behind a PIT/PIC IRQ0 clock and a real
; virtio-mmio console. Queue-used deltas grade input/output, while PANIC injects
; a CPL0 #UD and latches failure only from the guest's fatal console evidence.
;
; ⭐ WHY NO VMLAUNCH IN v1 (ESSENCE hard-won knowledge #4): a bad VMCS HOST-state
;   field on vmlaunch = "nowhere sane to return on VM-exit" = a host HARD-HANG the
;   watchdog cannot catch (the monolith took 2 during bring-up, KP115-recovered).
;   On a SHARED autonomous-loop box that would wedge every other contract. VMXON +
;   VMXOFF (no control transfer) is the proven-safe rung; we take exactly that.
;
; DEGRADE POSTURE (honest, never hangs boot): if VMX is absent (AMD/old CPU/QEMU-TCG)
;   or the BIOS locked VT-x off, we emit hv.vmx.absent / hv.vmx.locked and return
;   cleanly. Every CR0/CR4 mutation is saved + RESTORED; VMXOFF always runs on the
;   success path so the CPU is left exactly as found.
; ============================================================================

; --- EPT entry bits ---
HV_EPT_RWX      equ 0x07                    ; read+write+execute (all levels)
HV_EPT_WB_LEAF  equ 0x37                    ; RWX + memtype WB(6<<3) on a leaf PTE
HV_EPTP_WB_4LVL equ 0x1E                    ; EPTP: memtype WB(6) + walk-length-1=3(<<3)
HV_EPT_RAM_2M   equ 0xB7                    ; WB + PS + RWX, proven Classic 2 MiB leaf
HV_EPT_TRAP_RO  equ 0x01                    ; R, !W, !X, UC: free reads, trapped writes
HV_EPT_MMIO_4K  equ 0x03                    ; R, W, !X, UC: an assigned BAR page (RCQ-18 S2-3)
HV_VMX_IW_BIT   equ 0x00000004              ; CPU_BASED_INTR_WINDOW_EXITING
HV_R0_CLASS_UD  equ 6                       ; exact valid hardware-exception #UD
HV_FIRST_UD_BYTES equ 16
HV_OUT_BYTES      equ 1024                  ; hv_out_buf; its last byte is kept for the terminator

; --- VMCS field encodings (Intel SDM Vol 3C App. B) — ported from the proven
;     monolith drivers/vmx_hypervisor. Shared by the bounded HLT rung and the
;     R2 Linux launcher; the boot foundation (hv_init) itself does not launch. ---
VMXF_GUEST_ES_SEL   equ 0x0800
VMXF_GUEST_CS_SEL   equ 0x0802
VMXF_GUEST_SS_SEL   equ 0x0804
VMXF_GUEST_DS_SEL   equ 0x0806
VMXF_GUEST_FS_SEL   equ 0x0808
VMXF_GUEST_GS_SEL   equ 0x080A
VMXF_GUEST_LDTR_SEL equ 0x080C
VMXF_GUEST_TR_SEL   equ 0x080E
VMXF_HOST_ES_SEL    equ 0x0C00
VMXF_HOST_CS_SEL    equ 0x0C02
VMXF_HOST_SS_SEL    equ 0x0C04
VMXF_HOST_DS_SEL    equ 0x0C06
VMXF_HOST_FS_SEL    equ 0x0C08
VMXF_HOST_GS_SEL    equ 0x0C0A
VMXF_HOST_TR_SEL    equ 0x0C0C
VMXF_LINK_PTR       equ 0x2800
VMXF_G_DEBUGCTL     equ 0x2802
VMXF_PIN_CTLS       equ 0x4000
VMXF_PROC_CTLS      equ 0x4002
VMXF_EXC_BITMAP     equ 0x4004
VMXF_PF_MASK        equ 0x4006
VMXF_PF_MATCH       equ 0x4008
VMXF_CR3_TARGETS    equ 0x400A
VMXF_EXIT_CTLS      equ 0x400C
VMXF_EXIT_MSR_ST    equ 0x400E
VMXF_EXIT_MSR_LD    equ 0x4010
VMXF_ENTRY_CTLS     equ 0x4012
VMXF_ENTRY_MSR_LD   equ 0x4014
VMXF_ENTRY_INTR     equ 0x4016
VMXF_ENTRY_ERRCODE  equ 0x4018
VMXF_ENTRY_ILEN     equ 0x401A
VMXF_PROC_CTLS2     equ 0x401E
VMXF_VMINSTR_ERR    equ 0x4400
VMXF_EXIT_REASON    equ 0x4402
VMXF_EXIT_INTR_INFO equ 0x4404
VMXF_EXIT_INTR_ERR  equ 0x4406
VMXF_IDT_VEC_INFO   equ 0x4408
VMXF_IDT_VEC_ERR    equ 0x440A
VMXF_EXIT_ILEN      equ 0x440C
VMXF_G_ES_LIMIT     equ 0x4800
VMXF_G_CS_LIMIT     equ 0x4802
VMXF_G_SS_LIMIT     equ 0x4804
VMXF_G_DS_LIMIT     equ 0x4806
VMXF_G_FS_LIMIT     equ 0x4808
VMXF_G_GS_LIMIT     equ 0x480A
VMXF_G_LDTR_LIMIT   equ 0x480C
VMXF_G_TR_LIMIT     equ 0x480E
VMXF_G_GDTR_LIMIT   equ 0x4810
VMXF_G_IDTR_LIMIT   equ 0x4812
VMXF_G_ES_AR        equ 0x4814
VMXF_G_CS_AR        equ 0x4816
VMXF_G_SS_AR        equ 0x4818
VMXF_G_DS_AR        equ 0x481A
VMXF_G_FS_AR        equ 0x481C
VMXF_G_GS_AR        equ 0x481E
VMXF_G_LDTR_AR      equ 0x4820
VMXF_G_TR_AR        equ 0x4822
VMXF_G_INTERRUPT    equ 0x4824             ; guest interruptibility-state (STI/MOV-SS shadow)
VMXF_G_ACTIVITY     equ 0x4826
VMXF_G_SYSENTER_CS  equ 0x482A
VMXF_PREEMPT_TIMER  equ 0x482E
VMXF_EPTP           equ 0x201A
VMXF_G_PHYS_ADDR    equ 0x2400
VMXF_EXIT_QUAL      equ 0x6400
VMXF_G_LINEAR_ADDR  equ 0x640A
VMXF_H_SYSENTER_CS  equ 0x4C00
VMXF_G_CR0          equ 0x6800
VMXF_G_CR3          equ 0x6802
VMXF_G_CR4          equ 0x6804
VMXF_G_ES_BASE      equ 0x6806
VMXF_G_CS_BASE      equ 0x6808
VMXF_G_SS_BASE      equ 0x680A
VMXF_G_DS_BASE      equ 0x680C
VMXF_G_FS_BASE      equ 0x680E
VMXF_G_GS_BASE      equ 0x6810
VMXF_G_LDTR_BASE    equ 0x6812
VMXF_G_TR_BASE      equ 0x6814
VMXF_G_GDTR_BASE    equ 0x6816
VMXF_G_IDTR_BASE    equ 0x6818
VMXF_G_DR7          equ 0x681A
VMXF_G_RSP          equ 0x681C
VMXF_G_RIP          equ 0x681E
VMXF_G_RFLAGS       equ 0x6820
VMXF_G_PEND_DBG     equ 0x6822
VMXF_G_SYSENTER_ESP equ 0x6824
VMXF_G_SYSENTER_EIP equ 0x6826
VMXF_H_CR0          equ 0x6C00
VMXF_H_CR3          equ 0x6C02
VMXF_H_CR4          equ 0x6C04
VMXF_H_FS_BASE      equ 0x6C06
VMXF_H_GS_BASE      equ 0x6C08
VMXF_H_TR_BASE      equ 0x6C0A
VMXF_H_GDTR_BASE    equ 0x6C0C
VMXF_H_IDTR_BASE    equ 0x6C0E
VMXF_H_SYSENTER_ESP equ 0x6C10
VMXF_H_SYSENTER_EIP equ 0x6C12
VMXF_H_RSP          equ 0x6C14
VMXF_H_RIP          equ 0x6C16

HV_LAUNCH_HLT_TARGET equ 4                  ; bounded HLT-exit loop (exercises E3 skip+shadow-clear)

; Artifact sizes are discovered on every START. These constants describe only
; the bounded guest-physical layout and the post-EBS reservation capacity.
HV_LINUX_CTRL_BYTES       equ 0x200000        ; VMXON/VMCS/EPT live in first 2 MiB
HV_LINUX_NORMAL_RAM_BYTES equ 0x4000000       ; 64 MiB for the existing minimal guest
HV_LINUX_BROWSER_RAM_BYTES equ 0x40000000     ; 1 GiB for Chromium's measured working set
HV_LINUX_BP_GPA      equ 0x10000
HV_LINUX_CMD_GPA     equ 0x20000
HV_LINUX_HDR_GPA     equ 0x30000
HV_LINUX_KERN_GPA    equ 0x1000000           ; appliance CONFIG_PHYSICAL_START
HV_LINUX_INITRD_GPA  equ 0x3000000
HV_LINUX_IO_CHUNK    equ 0x10000
%assign HV_LINUX_RUN_MS 180000                ; ESSENCE E8 dilation-aware ceiling
HV_LINUX_BOOT_GRACE_MS equ 2000               ; Classic: flat-out timer calibration
HV_LINUX_LOAD_QUANTUM_MS equ 100             ; a loading START gives the host a turn at least this often
HV_VMX_GUEST_FLOOR_SHIFT equ 2               ; SEC109922 G1: Q_min = 1 ms >> 2, 250 us of guest time per entry
HV_LINUX_CLEAR_SLICE equ 0x200000            ; guest-RAM bytes zeroed between START load turns
HV_VCON_GPA          equ 0xD0000000           ; virtio-mmio console window
HV_VCON_PAGE         equ 0x5000               ; guest-readable register page
HV_VCON_EPT_PD       equ 0x6000               ; PDPT[3] subtree
HV_VCON_EPT_PT       equ 0x7000               ; PT for GPA 0xD0000000
HV_GUESTNET_GPA      equ 0xD0001000           ; virtio-mmio net window (1109)
HV_GUESTNET_PAGE     equ 0x8000               ; guest-readable net register page
HV_GUESTIN_GPA       equ 0xD0002000           ; RCQ-23 virtio-mmio input window
HV_GUESTIN_PAGE      equ 0x19000              ; its register page (above the VT-d EPT pool)
HV_GUESTRNG_GPA      equ 0xD0003000           ; opt-in entropy, unused master-PIC IRQ3
HV_GUESTSND_GPA      equ 0xD0004000           ; opt-in virtio-snd, IRQ7
HV_GUESTSND_PAGE     equ 0x20000              ; above SVM host/IOPM/MSRPM (1a000..1ffff)
HV_GUESTRNG_PAGE     equ 0x21000              ; host-only backing after SVM and sound; wire GPA unchanged
; Guest device layout guard (also exercised by the inert layout controls).
%if (HV_GUESTRNG_PAGE & 0xFFF) || HV_GUESTRNG_PAGE != HV_GUESTSND_PAGE + 0x1000 || HV_GUESTRNG_PAGE + 0x1000 > HV_LINUX_CTRL_BYTES
    %error "entropy register page must follow sound, aligned and inside control reserve"
%endif
HV_GUESTRST_GPA      equ 0xD0005000           ; opt-in paos.restore control port, IRQ5 shared
HV_GUESTFSC_PAGE     equ 0x88000              ; explicit filesystem hvc1 backing
HV_GUESTFSB_PAGE     equ 0x89000              ; explicit leased-block backing
HV_GUESTWIFI_PAGE equ 0x8A000
HV_GUESTPWR_GPA      equ 0xD0009000           ; C10b-1a paos.power port, driver-domain closure only, IRQ5 shared
HV_GUESTPWR_PAGE     equ 0x8B000              ; host-only backing after Wi-Fi, below the NIC pool
HV_GUESTRST_PAGE     equ 0x22000              ; host-only backing after entropy; wire GPA above
%if (HV_GUESTRST_PAGE & 0xFFF) || HV_GUESTRST_PAGE != HV_GUESTRNG_PAGE + 0x1000 || HV_GUESTRST_PAGE + 0x1000 > HV_LINUX_CTRL_BYTES
    %error "restore-port register page must follow entropy, aligned and inside control reserve"
%endif
HV_SLAT_RAM_PD1      equ 0x24000              ; RCQ-50: SLAT PD for PDPT[1], guest RAM 1..2 GiB
HV_SLAT_RAM_PD2      equ 0x25000              ; RCQ-50: SLAT PD for PDPT[2], guest RAM 2..3 GiB
HV_SLAT_RAM_HI_MAX   equ 1152                 ; PD1/PD2 + 128 leaves at GPA4GiB (3328 MiB RAM)
HV_SLAT_RAM_PD4      equ 0xA0000              ; after NIC private pool; GPA4..4.25GiB, compact host backing
%if HV_SLAT_RAM_PD4 < 0x90000 + 16*4096 || HV_SLAT_RAM_PD4 + 4096 > HV_LINUX_CTRL_BYTES
    %error "high RAM PD overlaps NIC pool or exceeds control reserve"
%endif
%if HV_SLAT_RAM_PD1 < HV_GUESTRST_PAGE + 0x1000 || HV_SLAT_RAM_PD2 != HV_SLAT_RAM_PD1 + 0x1000 || HV_SLAT_RAM_PD2 + 0x1000 > HV_LINUX_CTRL_BYTES
    %error "RAM PDs for PDPT[1..2] must follow the register pages, adjacent, inside control reserve"
%endif
HV_NIC_POOL          equ 0x90000              ; selected NIC SLAT private16pages; after S7/F11
HV_NIC_POOL_PAGES    equ 16
HV_PCIA_POOL         equ 0x26000              ; RCQ-36 V2 c2: SLAT tables for the assigned BAR (PCIA_POOL_PAGES)
%if HV_PCIA_POOL < HV_SLAT_RAM_PD2 + 0x1000 || (HV_PCIA_POOL & 0xFFF) || HV_PCIA_POOL + 2 * 0x1000 > HV_LINUX_CTRL_BYTES
    %error "assigned-BAR table pool must follow the RAM PDs, aligned, inside control reserve"
%endif
%include "hv/vcpu_start.inc"
%if HV_NIC_POOL < VST_END || HV_NIC_POOL+HV_NIC_POOL_PAGES*4096 > HV_LINUX_CTRL_BYTES
%error "NIC pool overlaps vCPU state or control reserve"
%endif
%if HV_PCIA_POOL + 2 * 0x1000 > VST_ON1 || VST_END > HV_LINUX_CTRL_BYTES
    %error "S7 private objects must follow every existing control-reservation user"
%endif
HV_LINUX_JIFFIES_GPA equ 0x18C3480            ; live System.map 2026-07-16; nokaslr
HV_VCON_INDIRECT     equ 1 << 28             ; VIRTIO_RING_F_INDIRECT_DESC
HV_VCON_QMAX         equ 64
HV_VCON_TX_MAX       equ 4096                  ; one bounded descriptor-chain drain
HV_VCON_CAP_MAX      equ 512                   ; reply-visible rolling operation window
HV_GUEST_UD_INFO     equ 0x80000306            ; valid | hardware exception | #UD
HV_GUEST_GP_INFO     equ 0x80000B0D            ; valid | error code | hardware exception | #GP (RCQ-50 S4)
; RCQ-24 V5: guests get neither protection keys nor Key Locker. PKRU and the
; IWKey are per-core state outside every saved/scrubbed XSAVE path, so a guest
; that could load them would hand them to the next START generation.
HV_CR4_GUEST_DENIED  equ (1 << 19) | (1 << 22) | (1 << 23) ; KL, PKE, CET
HV_CR4_HOST_OWNED    equ (1 << 13) | HV_CR4_GUEST_DENIED ; + VMXE; read shadow 0
HV_XCR0_GUEST_DENIED equ 1 << 9                 ; PKRU

HV_EPT_CLASS_NONE          equ 0
HV_EPT_CLASS_VIRTIO_RESUME equ 1
HV_EPT_CLASS_VIRTIO_ACCESS equ 2
HV_EPT_CLASS_VIRTIO_DECODE equ 3
HV_EPT_CLASS_ASSIGNED_BAR  equ 4
HV_EPT_CLASS_FOREIGN_GPA   equ 5
HV_EPT_DECODE_NONE         equ 0
HV_EPT_DECODE_OK           equ 1
HV_EPT_DECODE_REFUSED      equ 2
HV_EPT_ACTION_STOP         equ 0
HV_EPT_ACTION_RESUME       equ 1

; ---------------------------------------------------------------------------
; hv_vmx_detect — the read-only Intel/VMX capability op exposed through hv_ops.
;   Returns RAX=1 only for GenuineIntel with CPUID.1:ECX.VMX, else 0.
; ---------------------------------------------------------------------------
%include "hv/terminal_console.inc"
%include "hv/guest_request.asm"
%include "hv/guest_transport.asm"
%include "hv/terminal_transport.asm"

hv_vmx_detect:
    push rbx
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547                    ; 'Genu'
    jne  .no
    cmp  edx, 0x49656E69                    ; 'ineI'
    jne  .no
    cmp  ecx, 0x6C65746E                    ; 'ntel'
    jne  .no
    mov  eax, 1
    cpuid
    bt   ecx, 5
    jnc  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; hv_vmx_setup / hv_vmx_map expose live results from the proven VMX/VMCS/EPT
;   path without replaying hardware operations.
hv_vmx_setup:
    movzx eax, byte [rel hv_vmxon_ok]
    ret

hv_vmx_map:
    movzx eax, byte [rel hv_ept_built]
    ret

; hv_vmx_selftest(RDI=nonce ptr) -> RAX=the same unpredictable nonce pointer
;   only when the real VMXON + VMCS + EPT boot path completed this boot.
hv_vmx_selftest:
    cmp  byte [rel hv_vmx_present], 1
    jne  .unavailable
    cmp  byte [rel hv_vmxon_ok], 1
    jne  .unavailable
    cmp  byte [rel hv_ept_built], 1
    jne  .unavailable
    mov  rax, rdi
    ret
.unavailable:
    xor  eax, eax
    ret

; hv_vmx_enable — the VMX root-mode foundation bring-up. Called INDIRECTLY
;   through the CPU-vendor-selected hv_ops table after the comms surface exists.
;   clobbers: caller-saved; preserves RBX/R12-R15.
; ---------------------------------------------------------------------------
hv_vmx_enable:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; --- step 1: is this an Intel CPU with VMX? (CPUID.0 vendor + CPUID.1 ECX.5) ---
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547                    ; 'Genu'
    jne  .absent
    cmp  edx, 0x49656E69                    ; 'ineI'
    jne  .absent
    cmp  ecx, 0x6C65746E                    ; 'ntel'
    jne  .absent
    mov  eax, 1
    cpuid
    bt   ecx, 5                             ; VMX
    jnc  .absent

    ; --- IA32_FEATURE_CONTROL (0x3A): lock(bit0) + VMXON-outside-SMX(bit2) ---
    mov  ecx, 0x3A
    rdmsr
    test eax, 1                             ; lock?
    jz   .fc_unlocked
    test eax, 4                             ; VMXON-outside-SMX enabled?
    jnz  .detected
    ; lock=1, enable=0 -> BIOS locked VT-x OFF. Honest degrade.
    lea  rdi, [rel str_hv_locked]
    call serial_string
    jmp  .done
.fc_unlocked:
    or   eax, 5                             ; set lock(0) + VMXON-outside-SMX(2)
    wrmsr

.detected:
    mov  byte [rel hv_vmx_present], 1
    lea  rdi, [rel str_hv_detected]
    call serial_string

    ; --- step 2: buffers. One 8 KiB alloc: +0 VMXON region, +0x1000 VMCS. ---
    mov  rdi, 0x2000
    call dma_alloc
    test rax, rax
    jz   .done                             ; pool exhausted -> stay "detected only"
    mov  [rel hv_vmxon_pa], rax
    lea  rcx, [rax + 0x1000]
    mov  [rel hv_vmcs_pa], rcx
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, 0x2000 / 8
    rep  stosq

    ; --- revision id (IA32_VMX_BASIC 0x480, low 31 bits) into both regions ---
    mov  ecx, 0x480
    rdmsr
    and  eax, 0x7FFFFFFF
    mov  rcx, [rel hv_vmxon_pa]
    mov  [rcx], eax
    mov  rcx, [rel hv_vmcs_pa]
    mov  [rcx], eax

    ; --- quiet window across the VMX excursion ---
    ; Markers are held in R14/R15 and emitted after RFLAGS is restored. A
    ; serial_string at IF=0 drains the complete deferred UART prefix first, so
    ; logging inside this window stalled the BSP for the whole boot backlog.
    xor  r15d, r15d                        ; EPT marker (none unless built/failed)
    pushfq
    pop  rax
    mov  [rel hv_saved_rflags], rax
    cli

    ; --- CR0 fixed bits (MSRs 0x486/0x487); save original ---
    mov  ecx, 0x486
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax                          ; CR0_FIXED0
    mov  ecx, 0x487
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax                          ; CR0_FIXED1
    mov  rax, cr0
    mov  [rel hv_saved_cr0], rax
    or   rax, r12
    and  rax, r13
    mov  cr0, rax

    ; --- CR4 fixed bits (MSRs 0x488/0x489, forces VMXE); save original ---
    mov  ecx, 0x488
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax                          ; CR4_FIXED0 (includes VMXE)
    mov  ecx, 0x489
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax                          ; CR4_FIXED1
    mov  rax, cr4
    mov  [rel hv_saved_cr4], rax
    or   rax, r12
    and  rax, r13
    mov  cr4, rax

    ; --- step 3: VMXON (enter VMX root operation) ---
    vmxon [rel hv_vmxon_pa]
    jc   .vmxon_fail
    jz   .vmxon_fail

    ; --- VMCS clear + load (proves VMCS management works; NO launch) ---
    vmclear [rel hv_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    vmptrld [rel hv_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail

    mov  byte [rel hv_vmxon_ok], 1
    lea  r14, [rel str_hv_vmxon]

    ; --- step 4: build a REAL 4-level EPT (GPA 0 -> a guest HPA page) ---
    call hv_build_ept
    mov  r15, rax                          ; its marker, emitted after restore

    ; --- clean teardown: clear the current VMCS, leave VMX root, restore CRs ---
    vmclear [rel hv_vmcs_pa]
    vmxoff
    jmp  .restore

.vmcs_fail:
    ; VMXON succeeded but VMCS op failed — still leave VMX root cleanly.
    lea  r14, [rel str_hv_vmcs_fail]
    vmxoff
    jmp  .restore

.vmxon_fail:
    lea  r14, [rel str_hv_vmxon_fail]
    ; fall through to restore (VMXON did not take effect)

.restore:
    mov  rax, [rel hv_saved_cr0]
    mov  cr0, rax
    mov  rax, [rel hv_saved_cr4]
    mov  cr4, rax
    push qword [rel hv_saved_rflags]
    popfq
    ; Caller's IF again: normal FIFO enqueue, same texts and order as before.
    mov  rdi, r14
    call serial_string
    test r15, r15
    jz   .done
    mov  rdi, r15
    call serial_string
    jmp  .done

.absent:
    lea  rdi, [rel str_hv_absent]
    call serial_string

.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hv_build_ept — build a valid 4-level EPT structure + compose an EPTP.
;   PML4[0]->PDPT[0]->PD[0]->PT[0]-> a fresh guest RAM page. Pure RAM writes
;   (no INVEPT, no VMCS EPTP load — that belongs to the VMLAUNCH tier). Sets
;   hv_ept_built + hv_eptp. Runs inside the IF=0 VMX window, so it does not log:
;   RAX = its hv.ept.mapped/hv.ept.fail marker for the caller to emit after the
;   window. clobbers: caller-saved.
; ---------------------------------------------------------------------------
hv_build_ept:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    ; five 4 KiB pages: PML4, PDPT, PD, PT, guest RAM page
    mov  rdi, 0x5000
    call dma_alloc
    test rax, rax
    jz   .fail
    mov  rbx, rax                          ; base
    ; zero all five pages
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, 0x5000 / 8
    rep  stosq
    ; page layout
    mov  [rel hv_ept_pml4_pa], rbx
    lea  rax, [rbx + 0x1000]               ; PDPT
    lea  rcx, [rbx + 0x2000]               ; PD
    lea  rdx, [rbx + 0x3000]               ; PT
    lea  r8,  [rbx + 0x4000]               ; guest RAM page (HPA backing GPA 0)
    ; PML4[0] = PDPT | RWX
    mov  r9, rax
    or   r9, HV_EPT_RWX
    mov  [rbx], r9
    ; PDPT[0] = PD | RWX
    mov  r9, rcx
    or   r9, HV_EPT_RWX
    mov  [rax], r9
    ; PD[0] = PT | RWX
    mov  r9, rdx
    or   r9, HV_EPT_RWX
    mov  [rcx], r9
    ; PT[0] = guest_hpa | RWX + WB (leaf)
    mov  r9, r8
    or   r9, HV_EPT_WB_LEAF
    mov  [rdx], r9
    ; EPTP = PML4 | WB + 4-level
    mov  r9, rbx
    or   r9, HV_EPTP_WB_4LVL
    mov  [rel hv_eptp], r9
    mov  byte [rel hv_ept_built], 1
    lea  rax, [rel str_hv_ept]
    pop  rbx
    ret
.fail:
    lea  rax, [rel str_hv_ept_fail]
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; GUEST verbs — the honest command seam. They dispatch through the ONE registry
;   (svc/command) and report the REAL hv tier state. Linux R2 is content-gated;
;   later input/virtio/liveness rungs remain explicitly unclaimed.
;   Register order proves the §9.4 degenerate-Nth seam (no registry-core edit).
; ---------------------------------------------------------------------------
hv_register_verbs:
    push rbx
    call hv_linux_select_default_artifacts
    lea  rdi, [rel str_verb_guestvm]
    lea  rsi, [rel cmd_verb_guestvm]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_guestlinux]
    lea  rsi, [rel cmd_verb_guestlinux]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_guestkey]
    lea  rsi, [rel cmd_verb_guestkey]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
%ifdef PAOS_NIC_ASSIGNMENT
    call nd_register_verbs
    call nics_register_verbs
    call pcc_register_verbs
%endif
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_register
%endif
    call guest_surface_init
    call cdp_bridge_init
    call guest_transport_init
    pop  rbx
    ret

; Artifact selection is runtime data: static dq symbol initializers would retain
; image RVAs instead of relocated VAs.  The ordinary guest always restores this
; profile before START; the browser verb selects its isolated pair explicitly.
hv_linux_select_default_artifacts:
    sub  rsp, 8
    call vm_profile_reset_legacy             ; admission precedes every selector write
    add  rsp, 8
    test eax, eax
    jnz  .out
    lea  rax, [rel gf_name_bz]
    mov  [rel hv_linux_kernel_name_ptr], rax
    lea  rax, [rel gf_name_initrd]
    mov  [rel hv_linux_initrd_name_ptr], rax
    mov  qword [rel hv_linux_ram_bytes], HV_LINUX_NORMAL_RAM_BYTES
    xor  eax, eax
.out:
    ret

; GUESTVM <VALIDATE [--inject-bad-rsp] | LAUNCH | START | RECOVER good|recovery | STAT | AUDIOSTAT | EXITSTAT | PANIC>.
;   VALIDATE : run hv_validate_host_state; clean -> hoststate=ok, --inject-bad-rsp
;              -> REFUSED field=rsp (proves the validator inspects + refuses rather
;              than launching into an uncatchable hard-hang, ESSENCE E1).
;   LAUNCH   : real VMLAUNCH into an in-image HLT stub; decoded reason-12 exit.
;   START    : stream bzImage+initramfs through vfs_stat/read_at, build boot_params
;              and EPT, then enter the Linux appliance through the hv_ops vtable.
;   STAT     : render the LIVE launch counters (vmexit_reason / hlt_exits / launches).
;   AUDIOSTAT: bounded, read-only PAD/channel/device lifecycle observation.
;   No arg defaults to VALIDATE (clean). clobbers: caller-saved.
cmd_verb_guestvm:
    push rbx
    push r12
    push r13
    call cmd_handler_prologue
    mov  r13, rdi                        ; retain request for owner-only VCPUSTAT
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]                ; arg text ptr (sub-verb + flags)
    mov  rdi, rbx
    lea  rsi, [rel str_sub_start]
    call hv_tok_is
    test al, al
    jnz  .do_start
    mov  rdi, rbx
    lea  rsi, [rel str_sub_recover]
    call hv_tok_is
    test al, al
    jnz  .do_recover
    mov  rdi, rbx
    lea  rsi, [rel str_sub_launch]
    call hv_tok_is
    test al, al
    jnz  .do_launch
    mov  rdi, rbx
    lea  rsi, [rel str_sub_stat]
    call hv_tok_is
    test al, al
    jnz  .do_stat
    mov  rdi, rbx
    lea  rsi, [rel str_sub_warmstat]
    call hv_tok_is
    test al, al
    jnz  .do_warmstat
    mov  rdi, rbx
    lea  rsi, [rel str_sub_vcpustat]
    call hv_tok_is
    test al, al
    jnz  .do_vcpustat
    mov  rdi, rbx
    lea  rsi, [rel str_sub_audiostat]
    call hv_tok_is
    test al, al
    jnz  .do_audiostat
    mov rdi,rbx
    lea rsi,[rel str_sub_capcase]
    call hv_tok_is
    test al,al
    jnz .do_capcase
    mov  rdi, rbx
    lea  rsi, [rel str_sub_boundcost]
    call hv_tok_is
    test al, al
    jnz  .do_boundcost
    mov  rdi, rbx
    lea  rsi, [rel str_sub_ctxexec]
    call hv_tok_is
    test al, al
    jnz .do_ctxexec
    mov rdi,rbx
    lea  rsi, [rel str_sub_boundexec]
    call hv_tok_is
    test al, al
    jnz  .do_boundexec
    mov  rdi, rbx
    lea  rsi, [rel str_sub_boundstat]
    call hv_tok_is
    test al, al
    jnz  .do_boundstat
    mov  rdi, rbx
    lea  rsi, [rel str_sub_exitstat]
    call hv_tok_is
    test al, al
    jnz  .do_exitstat
    mov  rdi, rbx
    lea  rsi, [rel str_sub_panic]
    call hv_tok_is
    test al, al
    jnz  .do_panic
    mov  rdi, rbx
    lea  rsi, [rel str_sub_profiles]
    call hv_tok_is
    test al, al
    jnz  .do_profiles
    mov  rdi, rbx
    lea  rsi, [rel str_sub_plan]
    call hv_tok_is
    test al, al
    jnz  .do_plan
    mov  rdi, rbx
    lea  rsi, [rel str_sub_gate]
    call hv_tok_is
    test al, al
    jnz  .do_gate
    mov  rdi, rbx
    lea  rsi, [rel str_sub_stop]
    call hv_tok_is
    test al, al
    jnz  .do_stop
    mov  rdi, rbx
    lea  rsi, [rel str_sub_input]
    call hv_tok_is
    test al, al
    jnz  .do_input
    mov  rdi, rbx
    lea  rsi, [rel str_sub_pin1]
    call hv_tok_is
    test al, al
    jnz  .do_pin1
    mov  rdi, rbx
    lea  rsi, [rel str_sub_restoreport]
    call hv_tok_is
    test al, al
    jnz  .do_restoreport
    mov  rdi, rbx
    lea  rsi, [rel str_sub_snapshot]
    call hv_tok_is
    test al, al
    jnz  .do_snapshot
    mov  rdi, rbx
    lea  rsi, [rel str_sub_resume]
    call hv_tok_is
    test al, al
    jnz  .do_resume
    ; default / "VALIDATE": inspect host state, honour --inject-bad-rsp
    mov  rdi, rbx
    lea  rsi, [rel str_sub_badrsp]
    call hv_str_has
    movzx edi, al                            ; edi = 1 if a bad RSP was requested
    call hv_render_validate
    jmp  .done
.do_launch:
    cmp  byte [rel hvp_bound], 0
    jne  .do_stat                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .do_stat
    HV_POWER_CHECK hv_guest_power_admit, .do_stat
    movzx eax, byte [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]  ; a loading START yields between chunks
    or   al, [rel hv_linux_run_req]
    jnz  .do_stat                         ; never nest VMX under the resident guest
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .do_stat                         ; RCQ-37: the media owner holds the vCPU seam until its teardown
%endif
%endif
    mov  byte [rel hv_launch_mode], 0
    mov  byte [rel hv_linux_release_deferred], 1 ; RC-speed-reserve: STAT reads guest RAM first
    call hv_ops_launch_active                ; vendor-neutral vtable dispatch
    call hv_render_stat                      ; report the live result of THIS launch
    call hv_linux_release_after_fixture
    jmp  .done
.do_recover:
    cmp  byte [rel hvp_bound], 0
    jne  .do_stat
    ; Additive selector only: never configures/blesses a pair or bypasses the
    ; registry's existing owner/capability/session boundary.
    lea  rdi, [rbx + 7]                   ; text after RECOVER
    call hv_skip_spaces
    mov  rdi, rax
    call hv_recover_selector              ; exact good|recovery, no extra tokens
    test eax, eax
    jz   .recover_admit
    mov  esi, eax
    jmp  .profile_refused
.recover_admit:
    mov  ecx, esi                         ; which survives the non-yielding checks
    mov  esi, VP_E_BUSY
    HV_POWER_CHECK hv_guest_power_admit, .profile_refused
    movzx eax, byte [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    or   al, [rel vtd_owner_guest]
    jnz  .profile_refused                 ; any nonzero owned seam refuses intact
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .profile_refused                 ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    mov  rdx, [rel vm_profile_pair_state]
    mov  esi, VP_E_STATE
    test rdx, rdx
    jz   .profile_refused                 ; trusted signed boot config is required
    mov  esi, VP_E_BUSY
    cmp  dword [rdx + VPS_PHASE], 0
    jne  .profile_refused                 ; no armed request supersession here
    mov  ebx, [rel hv_linux_start_gen]
    inc  ebx
    mov  esi, VP_E_GENERATION
    jz   .profile_refused                 ; never wrap the global START generation
    mov  edi, ebx
    mov  esi, ecx
    call vm_profile_pair_recover
    test eax, eax
    jnz  .recover_select_failed
    ; The API installed this exact full tuple and vm_profile_gen. Do not call
    ; default/browser/named selectors after it. No yield before publication.
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    call guestnet_detach
    call hv_guest_linux_request_start
    test eax, eax
    jnz  .start_task
    mov  edi, ebx                         ; cancel only our original armed generation
    call vm_profile_pair_finish
    mov  esi, VP_E_BUSY
    jmp  .profile_refused
.recover_select_failed:
    mov  r13d, eax
    mov  edi, ebx                         ; also covers interrupted API publication
    call vm_profile_pair_finish
    mov  esi, r13d
    xor  r13d, r13d
    jmp  .profile_refused
.do_start:
    cmp  byte [rel hvp_bound], 0
    jne  .do_stat                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .do_stat
    HV_POWER_CHECK hv_guest_power_admit, .do_stat
    mov  byte [rel gsn_resume_armed], 0   ; RCQ-18 S2: only RESUME arms a resume
    movzx eax, byte [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    jnz  .do_stat                         ; queued recovery also owns the next load
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .do_stat                         ; RCQ-37: the media owner holds hvc0 until its teardown
%endif
%endif
    mov  rdx, [rel vm_profile_pair_state]
    test rdx, rdx
    jz   .start_idle
    cmp  dword [rdx + VPS_PHASE], 0
    jne  .do_stat                         ; never replace an armed/bound paired run
.start_idle:
    lea  rdi, [rbx + 5]                   ; text after START
    call hv_skip_spaces
    cmp  byte [rax], 0
    jne  .start_profile
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    call hv_linux_select_default_artifacts
    call hv_guest_linux_request_start
    jmp  .start_task
.start_profile:
    ; RCQ-18: START <profile>. Resolve, validate and bind before any resource.
    mov  rdi, rax
.start_named:
    call vm_profile_find
    test rax, rax
    jz   .profile_unknown
    mov  r13, rax
    mov  esi, VP_E_BUSY
    cmp  byte [rel vtd_owner_guest], 1    ; an assigned device belongs to the legacy rail
    je   .profile_refused
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    mov  rdi, r13
    mov  esi, [rel hv_linux_start_gen]
    inc  esi
    call vm_profile_request              ; opt-in whole-pair trial, legacy unchanged
    mov  esi, eax
    test eax, eax
    jnz  .profile_refused
    call guestnet_detach                  ; no GUESTNET session rides a profile
    mov  eax, [rel hv_linux_start_gen]
    inc  eax
    mov  [rel vm_profile_gen], eax        ; the exact generation published next
    call hv_guest_linux_request_start
    test eax, eax
    jnz  .start_task
    mov  edi, [rel vm_profile_gen]        ; power admission may revoke before publish
    call vm_profile_pair_finish
    mov  esi, VP_E_BUSY
    jmp  .profile_refused
.start_task:
    mov  ebx, [rel hv_linux_start_gen]     ; preserve this publisher across spawn
    cmp  byte [rel hv_linux_task_started], 1
    je   .kick
    lea  rdi, [rel hv_guest_linux_task]
    call sched_spawn
    cmp  eax, -1
    jne  .spawned
    cmp  ebx, [rel hv_linux_start_gen]
    jne  .do_stat                         ; foreign publication owns its own cleanup
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_linux_load_err], 9
    mov  edi, ebx                         ; never cancel a different generation
    call vm_profile_pair_finish
    jmp  .do_stat
.spawned:
    mov  byte [rel hv_linux_task_started], 1
.kick:
    ; Publication/spawn admits a queued request, not a loaded/running guest.
    ; Return its current state before the cooperative scheduler enters the full
    ; loader; otherwise a large verified image can outlive the command reply.
    ; The resident task consumes this exact generation on normal scheduling.
    call hv_render_stat
    jmp  .done
.do_stat:
    call hv_render_stat
    jmp  .done
; Read-only at the same cooperative stopped-vCPU boundary as STAT, on VMX or
; SVM. Separate bounded reply: the existing STAT plus SVM floor can fill 1024.
.do_warmstat:
    lea  rdi, [rbx + 8]
    call hvw_status_verb
    jmp  .done
.do_audiostat:
    lea  rdi, [rbx + 9]
    call hv_skip_spaces
    cmp  byte [rax], 0
    je   .audio_render
    call hv_out_reset
    lea  rdi, [rel str_hv_audio_args]
    call hv_out_str
    jmp  .done
.audio_render:
    call hv_render_audiostat
    jmp  .done
.do_capcase:
    lea rdi,[rbx+7]
    call hv_skip_spaces
    movzx edx,byte [rax]
    sub edx,'0'
    cmp edx,1
    ja .cap_args
    cmp byte [rax+1],' '
    jne .cap_args
    movzx esi,byte [rax+2]
    sub esi,'0'
    cmp esi,2
    ja .cap_args
    cmp byte [rax+3],0
    jne .cap_args
    mov edi,edx
    call capability_case_render
    jmp .done
.cap_args:
    call hv_out_reset
    lea rdi,[rel str_hv_cap_args]
    call hv_out_str
    jmp .done
.do_boundcost:
    mov r11d,1
    jmp .exec_cpu
.do_ctxexec:
    lea rdi,[rbx+7]
    call hv_skip_spaces
    movzx edi,byte [rax]
    sub edi,'0'
    cmp edi,9
    ja .ctx_args
    cmp byte [rax+1],0
    je .ctx_number
    cmp edi,1
    jne .ctx_args
    movzx edx,byte [rax+1]
    sub edx,'0'
    cmp edx,3
    ja .ctx_args
    cmp byte [rax+2],0
    jne .ctx_args
    lea edi,[rdx+10]
.ctx_number:
    cmp edi,6
    jae .ctx_interpreter
    call context_execution_render
    jmp .done
.ctx_interpreter:
    call interpreter_execution_render
    jmp .done
.ctx_args:
    call hv_out_reset
    lea rdi,[rel str_hv_ctx_args]
    call hv_out_str
    jmp .done
.do_boundexec:
    xor r11d,r11d
.exec_cpu:
    lea rdi,[rbx+9]
    call hv_skip_spaces
    movzx edi,byte [rax]
    sub edi,'0'
    cmp edi,9
    ja .exec_args
    inc rax
    cmp byte [rax],0
    je .exec_render
    test edi,edi
    jz .exec_args
    movzx ecx,byte [rax]
    sub ecx,'0'
    cmp ecx,9
    ja .exec_args
    imul edi,10
    add edi,ecx
    inc rax
    cmp byte [rax],0
    jne .exec_args
    cmp edi,31
    ja .exec_args
.exec_render:
    test r11d,r11d
    jnz .cost_render
    call hv_boundary_exec_render
    jmp .done
.cost_render:
    call hv_boundary_cost_render
    jmp .done
.exec_args:
    call hv_out_reset
    lea rdi,[rel str_hv_exec_args]
    call hv_out_str
    jmp .done
.do_boundstat:
    lea  rdi, [rbx + 9]
    call hv_skip_spaces
    cmp  byte [rax], 0
    je   .boundary_render
    mov  rdi, rax
    lea  rsi, [rel str_sub_boundstat_amd]
    call hv_tok_is
    test al, al
    jz   .boundary_intel_token
    call hv_skip_spaces                 ; hv_tok_is leaves RDI at token end
    cmp  byte [rax], 0
    jne  .boundary_args
    call hv_boundary_render_amd
    jmp  .done
.boundary_intel_token:
    ; A partial token match may advance RDI; retry from the original argument.
    lea  rdi, [rbx + 9]
    call hv_skip_spaces
    mov  rdi, rax
    lea  rsi, [rel str_sub_boundstat_intel]
    call hv_tok_is
    test al, al
    jz   .boundary_args
    call hv_skip_spaces
    cmp  byte [rax], 0
    jne  .boundary_args
    call hv_boundary_render_intel
    jmp  .done
.boundary_args:
    call hv_out_reset
    lea  rdi, [rel str_hv_boundary_args]
    call hv_out_str
    jmp  .done
.boundary_render:
    call hv_boundary_render
    jmp  .done
.do_exitstat:
    call hv_linux_exit_render
    call hv_linux_async_render
    call hv_linux_startup_render
    jmp  .done
.do_profiles:
    call vm_profile_render_list
    jmp  .done
; Read-only assignment isolation verdict (pcia_render_gate); no trailing argument.
.do_gate:
    lea  rdi, [rbx + 4]                   ; text after GATE
    call hv_skip_spaces
    cmp  byte [rax], 0
    jne  .gate_args
    call hv_out_reset
    call pcia_render_gate
    jmp  .done
.gate_args:
    call hv_out_reset
    lea  rdi, [rel str_sub_gate_args]
    call hv_out_str
    jmp  .done
.do_input:
    lea  rdi, [rbx + 5]                   ; text after INPUT (RCQ-23)
    call guestinput_verb
    jmp  .done
.do_pin1:
    lea  rdi, [rbx + 4]
    call pinj_command                      ; bounded explicit DOMAIN caller, no guest entry
    jmp  .done
.do_restoreport:
    lea  rdi, [rbx + 11]                  ; text after RESTOREPORT
    call guestrestore_verb
    jmp  .done
.do_snapshot:
    lea  rdi, [rbx + 8]                   ; text after SNAPSHOT
    call guestsnap_verb
    jmp  .done
.do_resume:
    ; RCQ-18 S2: RESUME <profile> is START <profile> from the bound snapshot.
    HV_POWER_CHECK hv_guest_power_admit, .do_stat
    mov  byte [rel gsn_resume_armed], 0
    movzx eax, byte [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    jnz  .do_stat
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .do_stat                         ; RCQ-37: RESUME enters START at .start_named; same seam gate
%endif
%endif
    mov  rdx, [rel vm_profile_pair_state]
    test rdx, rdx
    jz   .resume_idle
    cmp  dword [rdx + VPS_PHASE], 0
    jne  .do_stat
.resume_idle:
    lea  rdi, [rbx + 6]                   ; text after RESUME
    call hv_skip_spaces
    cmp  byte [rax], 0
    je   .profile_unknown
    mov  r13, rax                         ; name, kept across lookup/admission
    mov  rdi, rax
    call vm_profile_find
    test rax, rax
    jz   .profile_unknown
    mov  rdi, rax
    call guestsnap_resume_admit
    test eax, eax
    jnz  .resume_refused
    mov  rdi, r13
    jmp  .start_named
.resume_refused:
    mov  r13d, eax                        ; GSN_E_* reason
    call hv_out_reset
    lea  rdi, [rel str_sub_resume_refused]
    call hv_out_str
    mov  eax, r13d
    call hv_out_dec
    jmp  .done
.do_plan:
    lea  rdi, [rbx + 4]                   ; text after PLAN
    call hv_skip_spaces
    cmp  byte [rax], 0
    jne  .plan_named
    xor  edi, edi                         ; no name: the legacy fixed shape
    xor  esi, esi
    call vm_profile_render_plan
    jmp  .done
.plan_named:
    mov  rdi, rax
    call vm_profile_find
    test rax, rax
    jz   .profile_unknown
    mov  r13, rax
    mov  rdi, rax
    mov  esi, VP_BYTES
    call vm_profile_validate
    mov  esi, eax
    mov  rdi, r13
    call vm_profile_render_plan
    jmp  .done
.profile_unknown:
    xor  edi, edi
    mov  esi, VP_E_UNKNOWN
.profile_refused:
    ; EDI/R13 = record (or none), ESI = status; nothing was selected or queued.
    mov  byte [rel gsn_resume_armed], 0   ; RCQ-18 S2: a refused RESUME arms nothing
    mov  rdi, r13
    cmp  esi, VP_E_UNKNOWN
    jne  .refused_render
    xor  edi, edi
.refused_render:
    call vm_profile_render_plan
    lea  rdi, [rel str_hv_profile_refused]
    call hv_out_str
    jmp  .done
.do_stop:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .do_stat                         ; RCQ-37: the media owner stops its own guest
%endif
%endif
    HV_POWER_CHECK hv_guest_power_admit, .do_stat
    call guest_request_retire             ; revoke before STOP can yield
    ; Cooperative active stop retains loader/terminal ownership. Only an exact
    ; queued, unconsumed managed request may restore good here; a stale STOP
    ; must not finish a bound/foreign generation or strand an armed selection.
    movzx eax, byte [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    jnz  .stop_active
    cmp  byte [rel hv_linux_run_req], 1
    jne  .stop_render
    mov  rdx, [rel vm_profile_pair_state]
    test rdx, rdx
    jz   .stop_clear                       ; legacy request has no paired owner
    cmp  dword [rdx + VPS_PHASE], 0
    je   .stop_clear
    cmp  dword [rdx + VPS_PHASE], 1
    je   .stop_armed
    cmp  dword [rdx + VPS_PHASE], 4
    jne  .stop_render                      ; bound run finishes at its terminal
.stop_armed:
    mov  edi, [rel hv_linux_start_gen]
    test edi, edi
    jz   .stop_render
    cmp  edi, [rel hv_linux_start_consumed]
    je   .stop_render
    cmp  edi, [rel vm_profile_gen]
    jne  .stop_render
    cmp  edi, [rdx + VPS_GEN]
    jne  .stop_render
    call vm_profile_pair_finish            ; exact original armed generation
    test eax, eax
    jnz  .stop_render                      ; failed publication retains request
.stop_clear:
    cmp dword [rel fsg_state],0
    je .stop_clear_native
    mov rdi,[rel fsg_generation]
    call fsg_stop
.stop_clear_native:
    mov  byte [rel hv_linux_run_req], 0
    jmp  .stop_render
.stop_active:
    cmp dword [rel fsg_state],0
    je .stop_native
    mov rdi,[rel fsg_generation]
    call fsg_stop
.stop_native:
    mov  byte [rel hv_linux_run_req], 0
    cmp  byte [rel hv_linux_running], 1
    jne  .stop_render
    mov  byte [rel hv_linux_stop_req], 1
    call sched_yield
.stop_render:
    call hv_render_stat
    jmp  .done
.do_panic:
    HV_POWER_CHECK hv_guest_power_admit, .do_stat
    call hv_out_reset
    cmp  byte [rel hv_linux_running], 1
    jne  .panic_no
    cmp  byte [rel hv_vcon_ready], 1
    jne  .panic_no
    call hv_guest_panic_request
    cmp eax,1
    jne .panic_no
    lea  rdi, [rel str_hv_panic_armed]
    call hv_out_str
    jmp  .done
.panic_no:
    lea  rdi, [rel str_hv_panic_refused]
    call hv_out_str
    jmp  .done
.do_vcpustat:
    mov  rdi, r13
    call command_auth_ticket_owner
    mov  esi, eax
    lea  rdi, [rbx + 8]
    call vst_status_verb
    mov  [r12 + RSP_CODE], rax
    jmp  .reply_ready
.done:
    mov  qword [r12 + RSP_CODE], CMDE_OK
.reply_ready:
    mov  byte [rel hv_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared real guest failure request; no success flag until backend fatal output.
hv_guest_panic_request:
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_vcon_ready],1
    jne .bad
    cmp byte [rel hv_linux_panicked],0
    jne .bad
    sub rsp,8
    call hv_vcon_capture_reset             ; fatal evidence must follow this request
    mov  dword [rel hv_panic_match], 0
    mov  byte [rel hv_panic_text], 0
    mov  byte [rel hv_panic_injected], 0
    mov  byte [rel hv_panic_armed], 1       ; request only; guest evidence earns state
    add rsp,8
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; hv_skip_spaces(RDI=text) -> RAX=first non-space byte (may be the NUL).
hv_skip_spaces:
    mov  rax, rdi
.skip:
    cmp  byte [rax], ' '
    jne  .out
    inc  rax
    jmp  .skip
.out:
    ret

; hv_recover_selector(RDI=argument) -> EAX=status, ESI=0 good / 1 recovery.
; Only exact lowercase selectors and optional trailing ASCII spaces. Reads one
; byte at a time through the native NUL-terminated command argument.
hv_recover_selector:
    mov  r8, rdi
    xor  r9d, r9d
    lea  rsi, [rel str_recover_good]
.match:
    mov  al, [rsi]
    test al, al
    jz   .tail
    cmp  al, [rdi]
    jne  .miss
    inc  rsi
    inc  rdi
    jmp  .match
.tail:
    cmp  byte [rdi], ' '
    jne  .end
    inc  rdi
    jmp  .tail
.end:
    cmp  byte [rdi], 0
    jne  .miss
    mov  esi, r9d
    xor  eax, eax
    ret
.miss:
    test r9d, r9d
    jnz  .bad
    mov  r9d, 1
    mov  rdi, r8
    lea  rsi, [rel str_recover_recovery]
    jmp  .match
.bad:
    mov  eax, VP_E_UNKNOWN
    ret

; ============================================================================
; 1095b R2 Linux loader. This ports Classic vmx_guestlinux_selftest's proven
; boot-protocol sequence and changes only its seams: storage is vfs_stat/read_at,
; and guest RAM comes from a live post-EBS conventional-memory descriptor.
; ============================================================================

; Resident vCPU task. START arms this task; the real launch remains routed
; through the selected vendor operation table. Completed runs park here so a
; restart does not consume another scheduler slot.
; The caller publishes a monotonically increasing generation before run_req.
; The resident task copies that exact generation to start_consumed before it
; clears run_req and enters the loader.  Observers can therefore distinguish a
; stale ready bit from a request that this task actually consumed.
; RCQ-18 early Linux boot policy, covered by the signed payload. A validated
; normal Manager launch starts the full built-in driver domain once. Safe,
; Try and direct-entry boots stay on their existing rails. This is an appliance
; readiness path, not evidence of the same-Linux cold benchmark (spec 7.6).
; Existing profile validation, exact artifact hashes, power admission, generation
; binding, resident task and finite VM exit/deadline/STOP paths remain authoritative.
hv_linux_boot_start:
    cmp  byte [rel hv_linux_boot_attempted], 0
    jne  .out
    mov  byte [rel hv_linux_boot_attempted], 1
%ifdef PAOS_LAB_BOOT_GUEST_OFF
%if PAOS_LAB_BOOT_GUEST_OFF
    ; HP input discriminator: no automatic profile/request/task publication.
    ; The earlier shared foundation and later owner START remain unchanged.
    lea  rdi, [rel str_hv_boot_skipped]
    call serial_string
    jmp  .out
%endif
%endif
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    jmp nd_boot_start
%else
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .out
    cmp  byte [rel pbm_try_media], 0
    jne  .out
    cmp  byte [rel boot_hv_foundation_ready], 1
    jne  .out
    cmp  byte [rel hv_linux_running], 0
    jne  .out
    cmp  byte [rel hv_linux_start_active], 0
    jne  .out
    cmp  byte [rel hv_linux_run_req], 0
    jne  .out
    cmp  byte [rel vtd_owner_guest], 0
    jne  .out
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .out                              ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    cmp  dword [rel vfs_disk_handle], -1
    jne  .storage_candidate
    cmp  byte [rel boot_esp_part_guid_ok], 1  ; installed guests need no selected root volume
    jne  .out
.storage_candidate:
    HV_POWER_CHECK hv_guest_power_admit, .out
    push rbx
    lea  rdi, [rel str_hv_boot_profile]
    call vm_profile_find
    test rax, rax
    jz   .done
    mov  rbx, rax
    mov  rdi, rax
    call vm_profile_select
    test eax, eax
    jnz  .done
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    call guestnet_detach
    mov  eax, [rel hv_linux_start_gen]
    inc  eax
    mov  [rel vm_profile_gen], eax
    call hv_guest_linux_request_start
    cmp  byte [rel hv_linux_run_req], 1
    jne  .done
    mov  eax, [rel hv_linux_start_gen]
    mov  [rel hv_linux_boot_gen], eax
    cmp  byte [rel hv_linux_task_started], 1
    je   .accepted
    lea  rdi, [rel hv_guest_linux_task]
    call sched_spawn
    cmp  eax, -1
    je   .spawn_refused
    mov  byte [rel hv_linux_task_started], 1
.accepted:
    mov  byte [rel hv_linux_boot_queued], 1
    lea  rdi, [rel str_hv_boot_requested]
    call serial_string
    pop  rbx
    jmp  hv_linux_boot_poll
.spawn_refused:
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_linux_load_err], 9
.done:
    pop  rbx
%endif
.out:
    ret

; Call at boot work boundaries, never inside a transport/IRQ frame. A later
; owner START generation cannot inherit the early-boot polling request.
hv_linux_boot_poll:
    cmp  byte [rel hv_linux_boot_queued], 1
    jne  .out
    mov  eax, [rel hv_linux_boot_gen]
    cmp  eax, [rel hv_linux_start_gen]
    jne  .out
    cmp  byte [rel hv_linux_task_started], 1
    jne  .out
    jmp  sched_yield
.out:
    ret

hv_guest_linux_request_start:
    mov eax,[rel wfc_state]
    test eax,eax
    jz .wifi_idle
    cmp eax,6
    jne .power_refused
.wifi_idle:
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel nd_start_authority],1
    je .nd_admitted
    cmp dword [rel nd_state],1
    je .power_refused
    cmp dword [rel nd_state],2
    je .power_refused
    cmp dword [rel nd_state],3
    je .power_refused
    cmp dword [rel nd_state],6
    je .power_refused
.nd_admitted:
%endif
    cmp dword [rel fsg_state],0
    jne .power_refused                    ; original filesystem custody owns this VM
    cmp  byte [rel hvp_bound], 0
    jne  .power_refused                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .power_refused                    ; only physical retirement releases the warm owner
    HV_POWER_CHECK hv_guest_power_admit, .power_refused
    call guest_request_retire             ; old endpoint cannot survive START/wrap
    inc  dword [rel hv_linux_start_gen]
    mov  byte [rel hv_linux_run_req], 1
    mov  eax, [rel hv_linux_start_gen]
    ret

.power_refused:
    xor eax, eax
    ret

hv_guest_linux_task:
.wait:
    cmp  byte [rel hvw_bound], 1
    jne  .request
    cmp  byte [rel hv_linux_running], 0
    jne  .yield
    call hv_linux_release_idle              ; one bounded scrub quantum per task turn
    jmp  .yield
.request:
    cmp  byte [rel hv_linux_run_req], 1
    jne  .yield
    HV_POWER_CHECK hv_guest_power_admit, .yield
    mov  eax, [rel hv_linux_start_gen]
    ; Publish active before consumed. Artifact streaming may yield before
    ; hv_linux_running becomes 1; that accepted loader window is not an exit.
    mov  byte [rel hv_linux_start_active], 1
    mov  [rel hv_linux_start_consumed], eax
    mov  dword [rel hv_linux_start_refusal], 0
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_launch_mode], 1
    call hv_ops_launch_active
    mov  byte [rel hv_launch_mode], 0
    mov  byte [rel hv_linux_start_active], 0
.yield:
    call sched_yield
    jmp  .wait

; hv_guest_linux_start — hv_ops launch entry for GUESTVM START. EDI = 0 for
;   VMX; 1 for SVM (RCQ-18 S1b), which runs the SVM floor in place of the VMX
;   host-state checks and enters through hv_svm_linux_enter.
hv_guest_linux_start:
    mov eax,[rel wfc_state]
    test eax,eax
    jz .wifi_idle
    cmp eax,6
    jne .power_refused
.wifi_idle:
%ifdef PAOS_NIC_ASSIGNMENT
    push rdi
    call nd_reserve_allowed
    pop rdi
    test eax,eax
    jz .power_refused
%endif
    cmp dword [rel fsg_state],0
    je .filesystem_admitted
    cmp dword [rel fsg_state],1
    jne .power_refused
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel fsg_generation]
    jne .power_refused
.filesystem_admitted:
    ; A new START cannot repair an uncertain previous exit by clearing its
    ; native flags or foreign reader binding. Refuse before pair/device resets.
    ; Zero observations are admission guards, never proof of SLAT retirement.
    cmp  byte [rel hv_linux_running], 0
    jne  .power_refused
    cmp  byte [rel hv_linux_vmx_live], 0
    jne  .power_refused
    cmp  qword [rel hv_svm_cur_vmcb], 0
    jne  .power_refused
    cmp  byte [rel cdp_bound], 0
    jne  .power_refused
    cmp  byte [rel gws_bound], 0
    jne  .power_refused
    cmp  byte [rel hvp_bound], 0
    jne  .power_refused                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .power_refused                    ; cannot replace an owned warm span
    HV_POWER_CHECK hv_guest_power_admit, .power_refused
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    ; Refuse a duplicate/foreign entry before touching an owned managed run.
    mov  edi, [rel hv_linux_start_consumed]
    call vm_profile_bind_launch
    cmp  eax, -1
    jne  .pair_admitted
    mov  eax, VP_E_BUSY
    jmp  .power_retained
.pair_admitted:
    call vst_admit                         ; before foreign bindings can be reset
    cmp  eax, 2
    jne  .s7_admitted
    ; This generation was consumed and its pair bound, but no loader/device
    ; work began. Publish a terminal refusal instead of the prior load's PASS.
    mov  [rel hv_linux_start_refusal], edx
    mov  byte [rel hv_linux_load_err], 17    ; S7 admission refused before the loader
    mov  byte [rel hv_launch_refused], 1
    lea  rax, [rel str_hv_s7_admission]
    mov  [rel hv_val_field], rax
    mov  edi, [rel hv_linux_start_consumed]
    call vm_profile_pair_finish          ; exact owned trial, no foreign cleanup
    mov  eax, VP_E_UNSUPPORTED
    jmp  .power_retained
.s7_admitted:
    mov  edi, r12d
    call guestsnap_start_prepare            ; RCQ-18 S2: resume only the armed generation
    call guestsound_state_zero
    call guestentropy_state_zero            ; revoke before every admitted START
    call guestrestore_state_zero            ; same: no restore port before START binding
    call guestpower_start                   ; C10b-1a: no power port, request or old clean result
    call padc_state_zero                    ; RCQ-36: no PAD1 binding before START binding
    call guestdisplay_reset                 ; revoke before any START preparation
    call vm_profile_live_reset
    call guest_surface_foreign_start
    call cdp_bridge_foreign_start
    xor  eax, eax
    mov  [rel hv_linux_kboot], al
    mov  [rel hv_linux_load_err], al
    mov  [rel hv_linux_vmx_live], al
    mov  [rel hv_linux_xcr0_saved], al
    mov  [rel hv_linux_match], eax
    mov  [rel hv_linux_exits], eax
    mov  [rel hv_linux_intr_exits], eax
    mov  [rel hv_linux_host_slices], eax
    mov  [rel hv_linux_slice_begin_tsc], rax  ; T2-4 D8: same per-START reset (RAX=0)
    mov  [rel hv_linux_slice_end_tsc], rax
    mov  [rel hv_linux_slice_yield_tsc], rax
    mov  [rel hv_linux_slice_max_gap_tsc], rax
    mov  [rel hv_linux_kernel_size], eax
    mov  [rel hv_linux_initrd_size], eax
    mov  [rel hv_tick_inj_ct], eax
    mov  [rel hv_vcon_rx_used], eax
    mov  [rel hv_vcon_tx_used], eax
    mov  [rel hv_exit_reason], eax
    mov  [rel hv_instr_err], eax
    mov  [rel hv_vmwrite_fails], eax
    call hv_linux_exit_reset
    call hv_linux_async_reset
    call hv_linux_ept_detail_reset
    call hv_first_ud_reset
    ; A diagnostic generation needs the bytes immediately preceding #UD.
    ; Ordinary START retains the existing prefix-capture semantics.
    call hv_first_ud_bitmap_value
    cmp  eax, 0x40140
    jne  .first_ud_console_ready
    call hv_vcon_capture_reset
.first_ud_console_ready:
    xor  eax, eax
    mov  qword [rel hv_linux_uart], 0
    mov  word [rel hv_uart_thre], 0          ; RCQ-36: THRE asserted, not yet injected
    mov  qword [rel hv_last_tick_tsc], 0
    mov  byte [rel hv_linux_running], 0
    mov  byte [rel hv_linux_stop_req], 0
    mov  byte [rel hv_linux_panicked], 0
    mov  byte [rel hv_panic_armed], 0
    mov  byte [rel hv_panic_injected], 0
    mov  byte [rel hv_panic_text], 0
    mov  dword [rel hv_panic_match], 0
    mov  byte [rel hv_pic_state_m], 0
    mov  byte [rel hv_pic_state_s], 0
    mov  byte [rel hv_pic_icw1_m], 0
    mov  byte [rel hv_pic_icw1_s], 0
    mov  byte [rel hv_pic_vec_base], 0
    mov  byte [rel hv_pic_mask], 0xFF
    mov  byte [rel hv_pic_mask_s], 0xFF
    mov  byte [rel hv_port61], 0
    mov  byte [rel hv_pit2_mode0], 0
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
    mov  qword [rel hv_pit2_deadline], 0
    mov  dword [rel hv_pit_reload], 0
    mov  word [rel hv_pit_reload + 4], 0
    mov  dword [rel hv_pit_latch], 0
    mov  word [rel hv_pit_latch + 4], 0
    mov  word [rel hv_pit_ff], 0
    mov  byte [rel hv_pit_ff + 2], 0
    mov  word [rel hv_pit_latched], 0
    mov  byte [rel hv_pit_latched + 2], 0
    xor  edi, edi
    call glapic_start                        ; RCQ-50 S4: no guest LAPIC until a profile selects one
    call hv_vcon_state_zero
    call guestnet_state_zero
    mov  byte [rel hv_launch_refused], 0
    mov  byte [rel hv_launch_vmcsfail], 0
    mov  byte [rel hv_launch_vmxonfail], 0
    test r12d, r12d
    jz   .vmx_host
    call hv_svm_floor                        ; before any SVM state changes; load_err 12
    test eax, eax
    jnz  .done
    jmp  .backend_ok
.vmx_host:
    mov  rdi, rsp
    call hv_validate_host_state              ; ESSENCE E1: refuse before VMLAUNCH
    cmp  qword [rel hv_val_ok], 1
    je   .host_ok
    mov  byte [rel hv_launch_refused], 1
    mov  byte [rel hv_linux_load_err], 1
    jmp  .done
.host_ok:
    cmp  byte [rel hv_vmx_present], 1
    jne  .unavailable
    cmp  byte [rel hv_vmxon_ok], 1
    jne  .unavailable
.backend_ok:
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_prelaunch_verify
    test eax, eax
    jnz  .browser_bundle_bad
%endif
    call hv_linux_prepare
    test eax, eax
    jnz  .done
    mov  byte [rel hv_linux_running], 1
    test r12d, r12d
    jz   .vmx_enter
    call hv_svm_linux_enter
    jmp  .entered
.vmx_enter:
    call hv_linux_enter
.entered:
    call hv_guestcpu_account_run_stop
    mov  byte [rel hv_linux_running], 0
    jmp  .done
.unavailable:
    mov  byte [rel hv_linux_load_err], 1
    jmp  .done
.browser_bundle_bad:
    mov  byte [rel hv_linux_load_err], 9
.done:
%ifdef PAOS_NIC_ASSIGNMENT
    call nd_backend_stopped                 ; actual CPUoff before device/RAM release
%endif
    call wfc_backend_stopped                 ; original CPU and NIC DMA retired first
.wifi_scrub:
    cmp dword [rel wfc_state],8
    jne .wifi_retired
    call wfc_retire_step                     ; <=2MiB; exact profile/RAM remain held
    cmp dword [rel wfc_state],8
    jne .wifi_retired
    call sched_yield                        ; original start_active stays set
    jmp .wifi_scrub
.wifi_retired:
    call fsg_backend_stopped                 ; native terminal boundary, not peer terminal
    mov  byte [rel hvw_stopped], 1           ; terminal loader/backend boundary, never a process ACK
    call hv_pin_backend_stopped             ; exact CPU-off terminal receipt, never peer ACK
    mov  edi, [rel hv_linux_start_consumed]
    call hv_pin_retire                      ; refuses unknown exit; retains exclusive owner/RAM
    call pcia_release                       ; RCQ-36 V2 c2: after the actual stop, before any fence
    call pinj_backend_stopped                ; consumer retires only after exact native owner
    cmp byte [rel hv_guest_power_fenced], 0
    jne .power_retained
    mov  edi, [rel hv_linux_start_consumed]
    call vm_profile_pair_finish           ; terminal unqualified trial restores prior pair
    call guestsound_state_zero
    call guestentropy_state_zero            ; no old queue/IRQ/scratch after STOP or failure
    call guestrestore_state_zero            ; no restore port/request after STOP or failure
    call guestpower_state_zero              ; C10b-1a S3: disarm after nd_backend_stopped recorded clean
    call padc_state_zero                    ; RCQ-36: detach + retire after the actual stop
    call guestdisplay_reset                 ; stop, launch failure and refused START
    cmp  byte [rel hv_linux_release_deferred], 0
    jne  .power_retained                    ; a fixture launcher reads its result first, then releases
    call hv_linux_release_mem               ; RC-speed-reserve: last, after every user of the span
 .power_retained:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

.power_refused:
    mov eax, -1
    ret

; hv_linux_slat_ram_hi(RDI=control base, RSI=next RAM leaf, HPA|leaf bits) -> EAX=1/0.
; RCQ-50: the second and third GiB of guest RAM continue flat in PDPT[1] and PDPT[2],
; below the PDPT[3] MMIO hole. Every entry of all RAM PDs is written (leaf or 0) and
; an unused PDPT slot is 0, so no leaf survives from a larger earlier START.
; Excess RAM uses PDPT[4], compact HPA after low3GiB; PDPT[3] stays MMIO.
; A RAM size beyond 3328 MiB is refused before any write.
hv_linux_slat_ram_hi:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  rcx, [rel hv_linux_ram_bytes]
    shr  rcx, 21
    sub  rcx, 512                            ; leaves past PD0 (negative: none)
    xor  eax, eax
    cmp  rcx, HV_SLAT_RAM_HI_MAX
    jg   .out
    mov  r13, rcx
    mov  edi, HV_SLAT_TABLE
    call hv_slat_bits
    lea  r8, [rbx + HV_SLAT_RAM_PD1]
    lea  r9, [rbx + 0x3000 + 1*8]
    mov  r10d, 3
.pd:
    xor  ecx, ecx
    test r13, r13
    jle  .link
    lea  rcx, [r8]
    or   rcx, rax
.link:
    mov  [r9], rcx
    xor  edx, edx
.entry:
    xor  ecx, ecx
    cmp  rdx, r13
    jge  .store
    mov  rcx, r12
    add  r12, 0x200000
.store:
    mov  [r8 + rdx*8], rcx
    inc  edx
    cmp  edx, 512
    jb   .entry
    sub  r13, 512
    add  r8, 0x1000
    add  r9, 8
    dec  r10d
    jz   .done
    cmp  r10d, 1
    jne  .pd
    lea  r8, [rbx + HV_SLAT_RAM_PD4]
    lea  r9, [rbx + 0x3000 + 4*8]             ; skip existing device subtree
    jmp  .pd
.done:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RC-speed-reserve (spec 7.6.7): the guest's control + RAM + framebuffer is one
; shared span from core/memory_budget (owner HV_LINUX, kind GUEST, 2 MiB aligned
; for EPT leaves, guest RAM as the resident subset). No raw map scan. The span
; is returned by hv_linux_release_mem after the actual stop unless a device
; domain still translates DMA onto it (hv_linux_span_pinned); a held span is
; reused in place while capacity AND resident RAM match, and never moved while pinned.
;   hv_linux_reserve      START prepare (the previous run has stopped): may also
;                         return a held, unpinned span with changed geometry (an
;                         earlier refused release) and acquire a new one.
;   hv_linux_reserve_dma  NIC assignment, RDI = minimum guest-RAM bytes (DID 0x10
;                         maps the legacy RAM; a guest may still be running):
;                         only reuses a span that fits or acquires a new one.
; Generation: the consumed START, or 1 before any START (boot-time assignment).
; hv_media_guest_select (RCQ-37, lab) reserves before its START and pins the
; span until the media owner has scrubbed the MEDIA window (hv_media_window_release).
; Every user initializes the span before exposing it (prepare clears control and
; RAM). RAX = control base or 0.
hv_linux_reserve:
    xor  edi, edi
    mov  esi, 1
    jmp  hv_linux_reserve_span
hv_linux_reserve_dma:
    xor  esi, esi
hv_linux_reserve_span:
%ifdef PAOS_NIC_ASSIGNMENT
    sub rsp,8
    call nd_reserve_allowed
    add rsp,8
    test eax,eax
    jz .none
%endif
    ; An F11 lease owns its RAM until actual retire; only its exact original
    ; loader may reserve. A DMA/foreign caller cannot reuse quarantined RAM.
    cmp dword [rel fsg_state],0
    je .filesystem_reserve
    cmp dword [rel fsg_state],1
    jne .none
    cmp esi,1
    jne .none
    cmp byte [rel hv_linux_start_active],1
    jne .none
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel fsg_generation]
    jne .none
.filesystem_reserve:
    ; S7: retain the exact held geometry until both CPUs retire.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    ; A failed native EPT revoke retains these mappings after CPU stop.
    ; Neither held-span reuse nor replacement/acquisition may overwrite them.
    ; Do not use the complete warm reader census here: PMR may legitimately
    ; bind before its initial launch, and DMA reservation may reuse live RAM.
    cmp  byte [rel cdp_bound], 0
    jne  .none
    cmp  byte [rel gws_bound], 0
    jne  .none
    cmp  byte [rel hvp_bound], 0
    jne  .none                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .none                            ; never reuse a retiring/executing warm span
    mov  r9, [rel hv_linux_ram_bytes]
    cmp  r9, rdi
    cmovb r9, rdi                            ; resident subset: guest RAM
    mov  rcx, r9
    add  rcx, HV_LINUX_CTRL_BYTES
    jc   .none
    add  rcx, [rel hv_linux_fb_bytes]        ; RCQ-23: the display follows guest RAM
    jc   .none
    cmp  qword [rel hv_linux_mb_token], 0
    je   .acquire
    cmp  r9, [rel hv_linux_region_resident]
    jne  .replace                           ; old allocator record has a different RAM subset
    cmp  rcx, [rel hv_linux_region_capacity]
    jbe  .held
.replace:
    test esi, esi
    jz   .none                               ; a running guest may still use it
    push rcx
    push r9
    sub  rsp, 8
    call hv_linux_span_pinned
    test eax, eax
    jnz  .pinned
    call hv_linux_release_mem
    add  rsp, 8
    pop  r9
    pop  rcx
    cmp  qword [rel hv_linux_mb_token], 0
    jne  .none                               ; still held: refuse, never a second span
.acquire:
    mov  esi, [rel hv_linux_start_consumed]
    test esi, esi
    jnz  .gen
    mov  esi, 1
.gen:
    mov  [rel hv_linux_mb_gen], rsi
    mov  edi, MB_OWNER_HV_LINUX
    mov  edx, MB_KIND_GUEST
    mov  r8d, 0x200000
    push r9                                 ; acquisition returns rounded total bytes in R9
    call mb_acquire
    pop  r10                                ; preserve the exact requested resident subset
    test eax, eax
    jnz  .refused
    mov  [rel hv_linux_region_resident], r10
    mov  [rel hv_linux_mb_token], rdx
    mov  [rel hv_linux_region], r8
    mov  [rel hv_linux_region_capacity], r9
    lea  rax, [r8 + HV_LINUX_CTRL_BYTES]
    mov  [rel hv_linux_ram], rax
.held:
    mov  rax, [rel hv_linux_region]
    ret
.pinned:
    add  rsp, 24
    jmp  .none                               ; the held span and its key stay as they are
.refused:
    mov  qword [rel hv_linux_mb_gen], 0
    inc  dword [rel hv_linux_mb_acquire_refused]
.none:
    xor  eax, eax
    ret

; EAX=1 while a user outside the START still holds the span: a device domain
; that may translate DMA onto it (the assigned NIC's DID 0x10, vtd_owner_guest
; until reclaim; a V2C2 function not back to idle after its release, pcia_state
; POISON), or a live guest surface whose pixel grant lives in guest RAM between
; its fixture runs (gws_active, until GWSURFACE STOP), or (RCQ-37 lab) a media
; session whose owner still scrubs the MEDIA window (hv_media_window_held).
hv_linux_span_pinned:
    xor  eax, eax
    cmp  byte [rel vtd_owner_guest], 0
    setne al
    cmp  byte [rel pcia_state], 0           ; PCIA_IDLE
    setne cl
    or   al, cl
    cmp  byte [rel gws_active], 0
    setne cl
    or   al, cl
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_media_window_held], 0
    setne cl                                ; RCQ-37: the media owner scrubs its window after the stop
    or   al, cl
%endif
%endif
    ret

; RC-speed-reserve: a fixture launcher (cdp_run, gws_run, the LAUNCH verb) sets
; hv_linux_release_deferred before hv_ops_launch_active, reads the guest's
; result record from guest RAM after the stop, then calls this on every exit:
; the deferred release happens here instead of at .done. hv_linux_release_idle
; releases only with no START requested, starting, running or power-retained.
; Both preserve every register but RAX.
hv_linux_release_after_fixture:
    cmp  byte [rel hv_linux_release_deferred], 0
    je   .out
    mov  byte [rel hv_linux_release_deferred], 0
    jmp  hv_linux_release_idle
.out:
    ret
hv_linux_release_idle:
    cmp  byte [rel hv_linux_running], 0
    jne  .out
    cmp  byte [rel hv_linux_start_active], 0
    jne  .out
    cmp  byte [rel hv_linux_run_req], 0
    jne  .out
    cmp  byte [rel hv_guest_power_fenced], 0
    jne  .out
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call hv_linux_release_mem
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
.out:
    ret

; RC-speed-reserve: return the span after the actual stop (vCPU off, assigned
; function released, every device helper zeroed) or a failed prepare. A pinned
; span stays held, addresses included. Execution, power/deferred custody and
; native readers must also be retired before even invalidating cached views.
; Reuse the warm reader census for ordinary guests: failed EPT revocation can
; leave a CDP/GWS binding after the CPU stops. This is a nonyielding native
; terminal/idle step, not a new quiescence or physical-stop receipt.
; Once all users detach, cached addresses are cleared before allocator release;
; BUSY/stale release retains the token for the next exact-key retry.
hv_linux_release_mem:
    mov eax,[rel wfc_state]
    test eax,eax
    jz .wifi_idle
    cmp eax,6
    jne .pinned
.wifi_idle:
%ifdef PAOS_NIC_ASSIGNMENT
    cmp dword [rel nd_state],1
    je .out
    cmp dword [rel nd_state],2
    je .out
    cmp dword [rel nd_state],3
    je .out
    cmp dword [rel nd_state],6
    je .out
%endif
    cmp dword [rel fsg_state],6
    je fsg_memory_retained
    cmp dword [rel fsg_state],3
    je fsg_memory_retained
    ; S7: retain the exact held geometry until both CPUs retire.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  byte [rel hvp_bound], 0
    jne  .out                              ; unknown/unfinished PIN1 exit retains its RAM
    cmp  byte [rel hvw_bound], 1
    je   hvw_release_step                  ; keep exact key/addresses until physical return
    cmp  qword [rel hv_linux_mb_token], 0
    je   .out
    cmp  byte [rel hv_linux_running], 0
    jne  .pinned
    cmp  byte [rel hv_linux_vmx_live], 0
    jne  .pinned
    cmp  qword [rel hv_svm_cur_vmcb], 0
    jne  .pinned
    cmp  byte [rel hv_guest_power_fenced], 0
    jne  .pinned
    cmp  byte [rel hv_linux_release_deferred], 0
    jne  .pinned
    call hv_linux_span_pinned
    test eax, eax
    jnz  .pinned
    call hvw_readers_idle
    test eax, eax
    jz   .pinned
    mov  qword [rel hv_linux_region_resident], 0
    mov  qword [rel hv_linux_region], 0
    mov  qword [rel hv_linux_region_capacity], 0
    mov  qword [rel hv_linux_ram], 0
    mov  edi, MB_OWNER_HV_LINUX
    mov  rsi, [rel hv_linux_mb_gen]
    mov  rdx, [rel hv_linux_mb_token]
    call mb_release
    test eax, eax
    jnz  .refused
    mov  qword [rel hv_linux_mb_token], 0
    mov  qword [rel hv_linux_mb_gen], 0
.out:
    ret
.pinned:
    inc  dword [rel hv_linux_mb_release_pinned]
    ret
.refused:
    inc  dword [rel hv_linux_mb_release_refused]
    ret

; hv_linux_load_yield — the START loader's one cooperative point (RAM-clear slices,
; artifact chunks and pin-hash slices). Only the guest task's START
; (hv_linux_start_active) yields: every other launcher and read-routing change
; refuses while it is set. Fixture launchers run the loader inline with it clear
; and keep the BSP. A turn costs a full scheduler round (milliseconds with the
; desktop up), so it is taken only once HV_LINUX_LOAD_QUANTUM_MS of TSC has passed
; since the last one. Preserves all GPRs and flags.
hv_linux_load_yield:
%ifdef PAOS_NIC_ASSIGNMENT
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
    sub rsp,8
    call nd_tick
    add rsp,8
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
%endif
    cmp  byte [rel hv_linux_start_active], 1
    jne  .out
    pushfq
    push rax
    push rcx
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel hv_linux_load_tsc]       ; ticks since the loader's last turn
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .rate
    mov  rcx, 3000000                       ; bounded degrade if calibration failed
.rate:
    imul rcx, rcx, HV_LINUX_LOAD_QUANTUM_MS
    cmp  rax, rcx
    jb   .keep
    call sched_yield
    rdtsc                                   ; the next quantum is loader time only
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_load_tsc], rax
.keep:
    pop  rdx
    pop  rcx
    pop  rax
    popfq
.out:
    ret

; Installation delivery: select both files once, before the first byte is read.
; The directory key is the lowercase full file SHA from the Manager handoff,
; not the per-boot journal generation or the unrelated PREL1 generation.
; Missing/incomplete boot-ESP pairs try the explicit SOURCE.BIN hint; only a
; proven absent hint falls back together to the selected root volume.
; Present but wrongly sized pairs refuse; all full-file hashes remain checked
; by vm_profile_dep_verify below. Never change FSSEL or mix the two sources.
hv_guest_files_begin:
    push rbx
    mov  byte [rel hv_guest_files_nested], 0
    mov  eax, [rel vfs_disk_handle]
    mov  [rel hv_guest_files_handle], eax
    mov  rax, [rel hv_linux_kernel_name_ptr]
    mov  [rel hv_guest_files_kernel], rax
    mov  rax, [rel hv_linux_initrd_name_ptr]
    mov  [rel hv_guest_files_initrd], rax
    cmp  byte [rel pbm_manager_launch], 1
    jne  .root
    cmp  byte [rel boot_esp_part_guid_ok], 1
    jne  .root
    cmp  qword [rel vm_profile_kdep], 0
    je   .root                             ; the unpinned legacy fixture stays on its root
    cmp  qword [rel vm_profile_idep], 0
    je   .root
    mov  rax, [rel pbm_payload_sha]
    or   rax, [rel pbm_payload_sha+8]
    or   rax, [rel pbm_payload_sha+16]
    or   rax, [rel pbm_payload_sha+24]
    jz   .root
    lea  rdi, [rel hv_guest_files_kpath]
    mov  rsi, [rel hv_guest_files_kernel]
    call hv_guest_files_path
    test eax, eax
    js   .bad
    mov  [rel hv_guest_files_klen], eax
    lea  rdi, [rel hv_guest_files_ipath]
    mov  rsi, [rel hv_guest_files_initrd]
    call hv_guest_files_path
    test eax, eax
    js   .bad
    mov  [rel hv_guest_files_ilen], eax
    lea  rdi, [rel boot_esp_part_guid]
    call vfs_open_boot_esp
    cmp  rax, -1
    je   .root
    mov  ebx, eax
    call hv_guest_files_pair
    test eax, eax
    jz   .publish
    js   .bad                              ; a present conflicting size is never a fallback
    call hv_guest_files_source             ; missing boot pair: explicit alternate location hint
    test eax, eax
    js   .bad
    jnz  .root                             ; only proven selector absence preserves legacy root
.publish:
    mov  [rel hv_guest_files_handle], ebx
    mov  byte [rel hv_guest_files_nested], 1 ; publish only after the complete pair matches
    xor  eax, eax
    jmp  .out
.root:
    cmp  dword [rel hv_guest_files_handle], -1
    je   .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; EBX=one retained read-only source handle; EAX=0 complete pair, 1 missing,
; -1 size conflict. No cross-volume member selection or FSSEL mutation.
hv_guest_files_pair:
    sub  rsp, 8
    mov  edi, ebx
    lea  rsi, [rel hv_guest_files_kpath]
    mov  edx, [rel hv_guest_files_klen]
    lea  rcx, [rel hv_guest_files_stat]
    call vfs_stat_path
    test rax, rax
    jnz  .missing
    mov  rax, [rel vm_profile_kdep]
    mov  rax, [rax + VPD_SIZE]
    cmp  rax, [rel hv_guest_files_stat]
    jne  .bad
    mov  edi, ebx
    lea  rsi, [rel hv_guest_files_ipath]
    mov  edx, [rel hv_guest_files_ilen]
    lea  rcx, [rel hv_guest_files_stat]
    call vfs_stat_path
    test rax, rax
    jnz  .missing
    mov  rax, [rel vm_profile_idep]
    mov  rax, [rax + VPD_SIZE]
    cmp  rax, [rel hv_guest_files_stat]
    jne  .bad
    xor  eax, eax
    jmp  .out
.missing:
    mov  eax, 1
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    ret

; EBX=actual bootESP read-only handle. SOURCE.BIN is an UNTRUSTED read
; location hint, not a grant or artifact authority. The signed native profile's
; exact sizes and full kernel/initrd hashes remain mandatory before execution.
; EAX=0 with EBX=alternate complete pair, 1 proven absent hint, -1 all failures.
; No yield here: freeze the exact 64-byte hint before selecting its one volume.
hv_guest_files_source:
    sub  rsp, 8
    lea  rdi, [rel hv_guest_files_spath]
    lea  rsi, [rel hv_guest_files_source_name]
    call hv_guest_files_path
    test eax, eax
    js   .bad
    mov  edx, eax
    mov  edi, ebx
    lea  rsi, [rel hv_guest_files_spath]
    lea  rcx, [rel hv_guest_files_hint]
    call vfs_guest_source_hint
    cmp  eax, 1
    je   .out                              ; complete absence, never I/O or a short read
    test eax, eax
    jnz  .bad
    lea  rsi, [rel hv_guest_files_hint]
    mov  rax, 'PGSRC001'
    cmp  [rsi], rax
    jne  .bad
    cmp  dword [rsi + 8], 1
    jne  .bad
    cmp  dword [rsi + 12], 64
    jne  .bad
    lea  rdi, [rel pbm_payload_sha]
    add  rsi, 16
    mov  ecx, 32
    cld
    repe cmpsb
    jne  .bad
    mov  rax, [rel hv_guest_files_hint + 48]
    or   rax, [rel hv_guest_files_hint + 56]
    jz   .bad
    lea  rdi, [rel hv_guest_files_hint + 48]
    call vfs_open_guest_source
    test rax, rax
    js   .bad
    mov  ebx, eax
    call hv_guest_files_pair
    test eax, eax
    jnz  .bad                              ; present hint commits to both files on this source
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    ret

; RDI=96-byte destination, RSI=canonical name11 -> EAX=length/-1.
; 16-byte prefix + 64 hex digits + slash + at most 12 filename bytes + NUL.
hv_guest_files_path:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    mov  rdi, rsi
    call vm_profile_name83_valid
    test eax, eax
    jz   .bad
    mov  rdi, rbx
    lea  rsi, [rel hv_guest_files_prefix]
    mov  ecx, 16
    cld
    rep  movsb
    lea  rsi, [rel pbm_payload_sha]
    lea  r8, [rel hv_guest_files_hex]
    mov  ecx, 32
.hex:
    lodsb
    movzx edx, al
    shr  edx, 4
    mov  dl, [r8+rdx]
    mov  [rdi], dl
    inc  rdi
    and  eax, 15
    mov  al, [r8+rax]
    stosb
    loop .hex
    mov  al, '/'
    stosb
    xor  ecx, ecx
.stem:
    mov  al, [r12+rcx]
    cmp  al, ' '
    je   .extension
    stosb
    inc  ecx
    cmp  ecx, 8
    jb   .stem
.extension:
    cmp  byte [r12+8], ' '
    je   .term
    mov  al, '.'
    stosb
    mov  ecx, 8
.ext:
    mov  al, [r12+rcx]
    cmp  al, ' '
    je   .term
    stosb
    inc  ecx
    cmp  ecx, 11
    jb   .ext
.term:
    mov  byte [rdi], 0
    sub  rdi, rbx
    mov  eax, edi
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; RSI is one of this START's captured name pointers. EAX=path length,
; RSI=path, or EAX=-1. No name supplied by a caller becomes a path fragment.
hv_guest_files_lookup:
    cmp  rsi, [rel hv_guest_files_kernel]
    je   .kernel
    cmp  rsi, [rel hv_guest_files_initrd]
    jne  .bad
    lea  rsi, [rel hv_guest_files_ipath]
    mov  eax, [rel hv_guest_files_ilen]
    ret
.kernel:
    lea  rsi, [rel hv_guest_files_kpath]
    mov  eax, [rel hv_guest_files_klen]
    ret
.bad:
    mov  eax, -1
    ret

; Same ABI as vfs_stat/read_at; route through the START's retained handle.
hv_guest_file_stat:
    mov  edi, [rel hv_guest_files_handle]
    cmp  byte [rel hv_guest_files_nested], 1
    je   .path
    jmp  vfs_stat
.path:
    sub  rsp, 8
    call hv_guest_files_lookup
    add  rsp, 8
    test eax, eax
    js   .bad
    mov  rcx, rdx
    mov  edx, eax
    jmp  vfs_stat_path
.bad:
    mov  rax, -1
    ret

hv_guest_file_read:
    mov  edi, [rel hv_guest_files_handle]
    cmp  byte [rel hv_guest_files_nested], 1
    je   .path
    jmp  vfs_read_at
.path:
    sub  rsp, 8
    call hv_guest_files_lookup
    add  rsp, 8
    test eax, eax
    js   .bad
    mov  r9, r8
    mov  r8, rcx
    mov  rcx, rdx
    mov  edx, eax
    jmp  vfs_read_at_path
.bad:
    mov  rax, -1
    ret

hv_guest_files_prefix: db '/EFI/PaOS/guest/'
hv_guest_files_source_name: db 'SOURCE  BIN'
hv_guest_files_hex: db '0123456789abcdef'

; hv_linux_stream(RSI=name11,RDX=file_off,RCX=dest,R8=len) -> RAX=0/-1.
; Every artifact byte crosses the shipped VFS read_at seam. On the guest task's
; START (hv_linux_start_active) each chunk reaches the quantum-gated cooperative
; point, so a large artifact never holds the BSP silent; every launcher and
; read-routing change refuses while active.
hv_linux_stream:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
.loop:
    test r15, r15
    jz   .ok
    mov  rbx, r15
    cmp  rbx, HV_LINUX_IO_CHUNK
    jbe  .chunk
    mov  rbx, HV_LINUX_IO_CHUNK
.chunk:
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    mov  r8, rbx
    call hv_guest_file_read
    cmp  rax, rbx
    jne  .fail
    add  r13, rbx
    add  r14, rbx
    sub  r15, rbx
    call hv_linux_load_yield
    jmp  .loop
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

; Discover sizes, stream the non-protected staged pair, build boot_params,
; guest paging, and a 64 MiB EPT. Returns EAX=0 or -1 with load_err set.
hv_linux_prepare:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Read-only STAT observation of this preparation, including a failed one.
    ; Bind before the first potentially long operation; never infer VM entry
    ; or a completed load from a phase. Existing kboot/load_err remain decisive.
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel hv_linux_load_gen], eax
    mov  byte [rel hv_linux_load_phase], 1    ; reserve
    call hv_linux_reserve
    test rax, rax
    jnz  .have_mem
    mov  byte [rel hv_linux_load_err], 2
    jmp  .fail
.have_mem:
    mov  r15, rax                            ; control base
    mov  r14, [rel hv_linux_ram]             ; guest-RAM HPA base
    call hvw_prepare                        ; warm-only policy + exact physical fence
    test eax, eax
    jnz  .display_bad
    mov  rdi, r14
    mov  rsi, [rel hv_linux_ram_bytes]
    call vtd_guest_domain_check              ; RCQ-50 F1: an assigned NIC's DID 0x10 is this RAM
    test eax, eax
    jnz  .domain_bad
    mov  rdi, r15
    call guestsnap_after_reserve            ; RCQ-18 S2: an overlapping region drops it
    mov  byte [rel hv_linux_load_phase], 2    ; prepare owned display/control span
    call guestdisplay_clear                 ; validate/scrub future owned leaf first
    test eax, eax
    jz   .display_bad
    ; Reused regions carry prior guest state: clear control pages and all RAM.
    mov  rdi, r15
    xor  eax, eax
    mov  ecx, 0x9000 / 8                    ; VMX/EPT plus console+net pages + EPT subtree
    rep  stosq
    cmp  byte [rel gsn_resume_live], 1
    jne  .cold_ram
    ; RCQ-18 S2: resumed START. Bound RAM replaces load + boot paging; the
    ; guest's own page tables and boot area are part of that RAM.
    mov  rdi, r14
    call guestsnap_resume_ram
    test eax, eax
    jz   .resume_bad
    jmp  .slat
.cold_ram:
    ; The embedded 2716 producer uses this SAME EPT/VMCS and console ring.
    ; Preserve its bounded pixel storage between invocations, never load an
    ; appliance or publish Linux boot milestones for this deterministic guest.
    cmp  byte [rel cdp_fixture_mode], 1
    jne  .surface_fixture
    call cdp_bridge_prepare
    test eax, eax
    jnz  .fail
    jmp  .guest_paging
.surface_fixture:
    cmp  byte [rel gws_fixture_mode], 1
    jne  .ordinary_ram
    call guest_surface_prepare
    test eax, eax
    jnz  .fail
    jmp  .guest_paging
.ordinary_ram:
    ; Sliced: a START's first touch of a large profile's RAM is a load span too.
    mov  byte [rel hv_linux_load_phase], 3    ; clear guest RAM
    mov  rdi, r14
    mov  rdx, [rel hv_linux_ram_bytes]
.clear_ram:
    mov  rcx, rdx
    cmp  rcx, HV_LINUX_CLEAR_SLICE
    jbe  .clear_slice
    mov  rcx, HV_LINUX_CLEAR_SLICE
.clear_slice:
    sub  rdx, rcx
    shr  rcx, 3
    xor  eax, eax
    rep  stosq
    call hv_linux_load_yield
    test rdx, rdx
    jnz  .clear_ram
    mov  byte [rel hv_linux_load_phase], 4    ; choose pair, stat/read kernel setup
    call hv_guest_files_begin               ; choose one pair/handle for this entire START
    test eax, eax
    jnz  .bz_bad

    ; Stat + read only the setup header first; sizes remain live values.
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, [rel hv_linux_kernel_name_ptr]
    lea  rdx, [rel hv_linux_stat]
    call hv_guest_file_stat
    test rax, rax
    jnz  .bz_bad
    mov  r12, [rel hv_linux_stat]            ; fs_stat.size is ABI offset zero
    cmp  r12, 0x271
    jb   .bz_bad
    mov  rax, [rel vm_profile_kdep]          ; RCQ-18: a profile pins the exact file
    test rax, rax
    jz   .kernel_size_ok
    cmp  r12, [rax + VPD_SIZE]
    jne  .pin_bad
.kernel_size_ok:
    mov  rsi, [rel hv_linux_kernel_name_ptr]
    xor  edx, edx
    lea  rcx, [r14 + HV_LINUX_HDR_GPA]
    mov  r8d, 0x271
    call hv_linux_stream
    test rax, rax
    jnz  .bz_bad
    lea  rbx, [r14 + HV_LINUX_HDR_GPA]
    cmp  dword [rbx + 0x202], 0x53726448     ; "HdrS"
    jne  .bz_bad
    movzx eax, byte [rbx + 0x1F1]           ; setup_sects; zero means four
    test al, al
    jnz  .setup_count
    mov  al, 4
.setup_count:
    inc  eax
    shl  eax, 9
    mov  r13, rax                            ; protected-mode payload file offset
    cmp  r13, r12
    jae  .bz_bad
    cmp  qword [rel vm_profile_kdep], 0
    je   .setup_done
    ; A pinned kernel is hashed whole: read every setup sector, not just the
    ; header, into the (otherwise unused) area below the kernel load address.
    mov  rsi, [rel hv_linux_kernel_name_ptr]
    xor  edx, edx
    lea  rcx, [r14 + HV_LINUX_HDR_GPA]
    mov  r8, r13
    call hv_linux_stream
    test rax, rax
    jnz  .kernel_io
.setup_done:
    mov  byte [rel hv_linux_load_phase], 5    ; stream kernel payload
    sub  r12, r13                            ; payload length
    cmp  r12, HV_LINUX_INITRD_GPA - HV_LINUX_KERN_GPA
    ja   .bz_bad
    mov  [rel hv_linux_kernel_size], r12d
    mov  rsi, [rel hv_linux_kernel_name_ptr]
    mov  rdx, r13
    lea  rcx, [r14 + HV_LINUX_KERN_GPA]
    mov  r8, r12
    call hv_linux_stream
    test rax, rax
    jnz  .kernel_io
    mov  rdi, [rel vm_profile_kdep]
    test rdi, rdi
    jz   .kernel_pinned
    mov  byte [rel hv_linux_load_phase], 6    ; verify whole kernel pin
    lea  rsi, [r14 + HV_LINUX_HDR_GPA]       ; setup sectors || payload == the file
    mov  rdx, r13
    lea  rcx, [r14 + HV_LINUX_KERN_GPA]
    mov  r8, r12
    call vm_profile_dep_verify
    test eax, eax
    jnz  .pin_bad
.kernel_pinned:
    mov  byte [rel hv_linux_load_phase], 7    ; boot parameters and command line

    ; Proven Classic boot_params/zero-page shape.
    lea  r13, [r14 + HV_LINUX_BP_GPA]
    lea  rsi, [rbx + 0x1F1]
    lea  rdi, [r13 + 0x1F1]
    mov  ecx, 0x80
    rep  movsb
    mov  byte [r13 + 0x210], 0xFF            ; type_of_loader
    or   byte [r13 + 0x211], 0x01            ; LOADED_HIGH
    mov  dword [r13 + 0x228], HV_LINUX_CMD_GPA
    mov  byte [r13 + 0x1E8], 2               ; e820_entries
    mov  qword [r13 + 0x2D0], 0
    mov  qword [r13 + 0x2D8], 0x9FC00
    mov  dword [r13 + 0x2E0], 1
    mov  qword [r13 + 0x2E4], 0x100000
    mov  rax, [rel hv_linux_ram_bytes]        ; RAM amount, not final GPA
    mov  edx, 0xC0000000
    cmp  rax, rdx
    jbe  .e820_low
    mov  byte [r13 + 0x1E8], 3
    sub  rax, rdx
    mov  qword [r13 + 0x2F8], 0              ; third range begins at 4GiB
    mov  dword [r13 + 0x2FC], 1
    mov  [r13 + 0x300], rax
    mov  dword [r13 + 0x308], 1
    mov  rax, rdx
.e820_low:
    sub  rax, 0x100000
    mov  qword [r13 + 0x2EC], rax
    mov  dword [r13 + 0x2F4], 1
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    ; G3b media_e820_begin: reserve the entire PMR1 window, independently of memmap=.
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .media_e820_done
    cmp  byte [rax + VP_CLASS], VP_CLASS_MEDIA
    jne  .media_e820_done
    mov  byte [r13 + 0x1E8], 4
    mov  qword [r13 + 0x2EC], VP_MEDIA_GPA - 0x100000
    mov  qword [r13 + 0x2F8], VP_MEDIA_GPA
    mov  qword [r13 + 0x300], VP_MEDIA_WINDOW
    mov  dword [r13 + 0x308], 2              ; E820_TYPE_RESERVED
    mov  qword [r13 + 0x30C], VP_MEDIA_GPA + VP_MEDIA_WINDOW
    mov  qword [r13 + 0x314], VP_MEDIA_GUARD
    mov  dword [r13 + 0x31C], 1
.media_e820_done:
    ; G3b media_e820_end
%endif
%endif
    mov  rdi, r13
    call guestdisplay_screen_info            ; only the validated future reservation
    test eax, eax
    jz   .display_bad
    cmp  qword [rel vm_profile_active], 0
    je   .cmdline_legacy
    ; RCQ-36: a private PAD1 channel binds this START before its cmdline names it.
    test dword [rel vm_profile_dev_mask], VP_DEV_PADCHAN
    jz   .pad_none
    call padc_prepare
    test eax, eax
    jnz  .pad_bad
.pad_none:
    ; RCQ-18: the guest is told about exactly the selected devices.
    lea  rdi, [r14 + HV_LINUX_CMD_GPA]
    mov  esi, VP_CMDLINE_CAP
    call vm_profile_compose_cmdline
    test rax, rax
    js   .bz_bad
    jmp  .initrd_stat
.cmdline_legacy:
    lea  rsi, [rel str_hv_linux_cmdline]
    cmp  byte [rel vtd_owner_guest], 1
    jne  .cmdline_selected
    lea  rsi, [rel str_hv_linux_cmdline_vtd]  ; PCI mechanism #1, no NIC bind
    cmp  byte [rel vtd_network_mode], 1
    jne  .cmdline_selected
    lea  rsi, [rel str_hv_linux_cmdline_vtd_net]
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .cmdline_selected
    ; Transparent L2 must build the bridge before any guest L3/DHCP. The
    ; initramfs already contains /bin/sh; launch it directly and let vtd's
    ; local-console state machine mount sysfs, discover r8169, and bridge.
    lea  rsi, [rel str_hv_linux_cmdline_vtd_domain]
.cmdline_selected:
    lea  rdi, [r14 + HV_LINUX_CMD_GPA]
.cmdline:
    lodsb
    stosb
    test al, al
    jnz  .cmdline

    ; Initramfs is independently stat'ed and streamed to its bounded GPA.
.initrd_stat:
    mov  byte [rel hv_linux_load_phase], 8    ; stat/place/stream initramfs
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, [rel hv_linux_initrd_name_ptr]
    lea  rdx, [rel hv_linux_stat]
    call hv_guest_file_stat
    test rax, rax
    jnz  .initrd_bad
    mov  r12, [rel hv_linux_stat]            ; fs_stat.size is ABI offset zero
    test r12, r12
    jz   .initrd_bad
    mov  rax, [rel vm_profile_idep]
    test rax, rax
    jnz  .initrd_profile
    mov  rax, [rel hv_linux_ram_bytes]
    sub  rax, HV_LINUX_INITRD_GPA
    cmp  r12, rax
    ja   .initrd_bad
    mov  qword [rel hv_linux_initrd_gpa], HV_LINUX_INITRD_GPA
    jmp  .initrd_place
.initrd_profile:
    ; RCQ-18: exact pinned size, placed at the top of the profile's RAM and
    ; strictly above everything the kernel claims (its boot-protocol init_size).
    cmp  r12, [rax + VPD_SIZE]
    jne  .pin_bad
    mov  rax, [rel hv_linux_ram_bytes]
    mov  edx, 0xC0000000                    ; initrd always in contiguous low RAM
    cmp  rax, rdx
    cmova rax, rdx
    mov  edx, [rbx + 0x22C]                  ; RCQ-50: initrd_addr_max (protocol >= 2.03)
    inc  rdx                                 ; exclusive end, no 32-bit wrap
    cmp  rax, rdx
    cmova rax, rdx                           ; RAM past 2 GiB never holds the initrd
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    mov  rdx, [rel vm_profile_active]
    test rdx, rdx
    jz   .initrd_ceiling
    cmp  byte [rdx + VP_CLASS], VP_CLASS_MEDIA
    jne  .initrd_ceiling
    mov  eax, VP_MEDIA_GPA                  ; top-of-RAM placement overlaps the 4 MiB window
.initrd_ceiling:
%endif
%endif
    sub  rax, r12
    jb   .fit_bad
    and  rax, -0x1000
    mov  edx, [rbx + 0x260]                  ; init_size (protocol >= 2.10)
    mov  ecx, [rel hv_linux_kernel_size]
    cmp  rdx, rcx
    jae  .kernel_span
    mov  rdx, rcx
.kernel_span:
    add  rdx, HV_LINUX_KERN_GPA + 0xFFF
    and  rdx, -0x1000
    cmp  rax, rdx
    jb   .fit_bad
    mov  [rel hv_linux_initrd_gpa], rax
.initrd_place:
    mov  [rel hv_linux_initrd_size], r12d
    mov  rsi, [rel hv_linux_initrd_name_ptr]
    xor  edx, edx
    mov  rcx, r14
    add  rcx, [rel hv_linux_initrd_gpa]
    mov  r8, r12
    call hv_linux_stream
    test rax, rax
    jnz  .initrd_bad
    mov  rdi, [rel vm_profile_idep]
    test rdi, rdi
    jz   .initrd_pinned
    mov  byte [rel hv_linux_load_phase], 9    ; verify whole initramfs pin
    mov  rsi, r14
    add  rsi, [rel hv_linux_initrd_gpa]
    mov  rdx, r12
    xor  ecx, ecx
    xor  r8d, r8d
    call vm_profile_dep_verify
    test eax, eax
    jnz  .pin_bad
.initrd_pinned:
    mov  eax, [rel hv_linux_initrd_gpa]
    mov  [r13 + 0x218], eax
    mov  [r13 + 0x21C], r12d

.guest_paging:
    mov  byte [rel hv_linux_load_phase], 10   ; initial guest page tables
    ; Guest CR3 paging: identity-map GPA 0..64 MiB with 2 MiB leaves.
    mov  qword [r14 + 0x1000], 0x2003
    mov  qword [r14 + 0x2000], 0x3003
    lea  rdi, [r14 + 0x3000]
    mov  rax, 0x83
    mov  rcx, [rel hv_linux_ram_bytes]
    shr  rcx, 21
    mov  edx, 512                            ; RCQ-50: boot paging maps the first GiB only;
    cmp  ecx, edx                            ; kernel, boot_params and cmdline lie below 64 MiB
    cmova ecx, edx
.guest_pd:
    mov  [rdi], rax
    add  rax, 0x200000
    add  rdi, 8
    dec  ecx
    jnz  .guest_pd

.slat:
    mov  byte [rel hv_linux_load_phase], 11   ; SLAT and selected device preparation
    ; The SLAT maps guest GPAs onto the dynamically discovered, aligned HPA
    ; range, in the active backend's format (EPT: RWX tables, 0xB7 leaves).
    mov  edi, HV_SLAT_TABLE
    call hv_slat_bits
    lea  rcx, [r15 + 0x3000]
    or   rcx, rax
    mov  [r15 + 0x2000], rcx                 ; PML4[0] -> PDPT
    lea  rcx, [r15 + 0x4000]
    or   rcx, rax
    mov  [r15 + 0x3000], rcx                 ; PDPT[0] -> PD
    mov  edi, HV_SLAT_RAM_2M
    call hv_slat_bits
    lea  rdi, [r15 + 0x4000]
    or   rax, r14
    mov  rcx, [rel hv_linux_ram_bytes]
    shr  rcx, 21
    mov  edx, 512                            ; PD0 holds the first GiB
    cmp  ecx, edx
    cmova ecx, edx
.ept_pd:
    mov  [rdi], rax
    add  rax, 0x200000
    add  rdi, 8
    dec  ecx
    jnz  .ept_pd
    mov  rdi, r15
    mov  rsi, rax                            ; the next RAM leaf
    call hv_linux_slat_ram_hi
    test eax, eax
    jz   .fit_bad
    ; RCQ-18: only the selected devices' register pages exist in the EPT.
    mov  rdi, r15
    call hv_linux_map_devices
    call guestdisplay_ready                 ; a refused display map cannot boot
    test eax, eax
    jz   .display_bad
    cmp  qword [rel vm_profile_active], 0
    jne  .devices_reset                     ; a profile never carries a VT-d secondary BAR (V2: pcia_attach)
    ; Retain the freshly built EPT and seed only the assigned secondary
    ; function's bounded fixed BAR mappings. Host e1000e is never in this seam.
    lea  rdi, [r15 + 0x2000]
    call vtd_map_secondary_bars_ept
.devices_reset:
    mov  edi, [rel vm_profile_live_devices]
    and  edi, VP_DEV_LAPIC
    call glapic_start                        ; RCQ-50 S4: the x2APIC exits exist only when selected
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .s7_mp_done
    cmp  dword [rax + VP_VCPUS], 2
    jne  .s7_mp_done
    mov  edi, 2
    call glapic_set_vcpus
    test eax, eax
    jnz  .display_bad
    mov  rdi, [rel hv_linux_ram]
    add  rdi, GLAPIC_MP_GPA
    mov  esi, 2
    call glapic_mptable                     ; before seal: actual guest discovery
    cmp  eax, GLAPIC_MP_BYTES
    jne  .display_bad
.s7_mp_done:
%ifdef PAOS_NIC_ASSIGNMENT
    test dword [rel vm_profile_dev_mask],VP_DEV_NIC
    jz .nd_prepared
    lea rdi,[r15+0x2000]
    call nd_prepare
    test eax,eax
    jz .assign_bad
    cmp byte [rel guestpower_live],1
    jne .nd_prepared
    call guestpower_device_reset             ; C10b-1a: paos.power bound to this attached START
    test eax,eax
    jz .assign_bad
.nd_prepared:
%endif
    test dword [rel vm_profile_live_devices],VP_DEV_WIFI
    jz .wifi_prepared
    call wfc_prepare
    test eax,eax
    jz .assign_bad
.wifi_prepared:
    test dword [rel vm_profile_dev_mask], VP_DEV_PCIHDA
    jz   .no_assign
    lea  rdi, [r15 + 0x2000]
    lea  rsi, [r15 + HV_PCIA_POOL]
    call pcia_attach                         ; RCQ-36 V2 c2: the host HDA function, IOMMU + BAR
    test eax, eax
    jnz  .assign_bad
%ifidn RCQ50_G0_FLR_LAB,1
    ; The lab FLR kind shares this attach seam with HDA. Publish every selected
    ; attach-owned bit only after success, so console ownership sees the full
    ; profile without weakening its exact selected/live device-mask check.
    mov  eax, [rel vm_profile_dev_mask]
    and  eax, VP_DEV_PCIHDA | VP_DEV_PCIFLR
    or   [rel vm_profile_live_devices], eax
%else
    or   dword [rel vm_profile_live_devices], VP_DEV_PCIHDA
%endif
.no_assign:
    test dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    jz   .no_vcon
    call hv_vcon_reset
.no_vcon:
    test dword [rel vm_profile_live_devices], VP_DEV_NET
    jz   .no_net
    call guestnet_device_reset
.no_net:
    test dword [rel vm_profile_live_devices], VP_DEV_INPUT
    jz   .no_input
    call guestinput_device_reset
.no_input:
    test dword [rel vm_profile_live_devices], VP_DEV_ENTROPY
    jz   .no_entropy
    call guestentropy_device_reset
    test eax, eax
    jz   .display_bad
.no_entropy:
    test dword [rel vm_profile_live_devices], VP_DEV_SOUND
    jz .no_sound
    call guestsound_device_reset
    test eax,eax
    jz .display_bad
.no_sound:
    test dword [rel vm_profile_live_devices], VP_DEV_RESTORE
    jz   .no_restore
    call guestrestore_device_reset
    test eax, eax
    jz   .display_bad
.no_restore:
    test dword [rel vm_profile_live_devices],VP_DEV_FILESYSTEM
    jz .no_filesystem
    call fsg_prepare
    test eax,eax
    jz .display_bad
.no_filesystem:
    cmp  byte [rel gsn_resume_live], 1
    jne  .eptp
    mov  rdi, r15
    call guestsnap_restore_devices          ; RCQ-18 S2: transport + register pages
    test eax, eax
    jz   .resume_bad
.eptp:
    mov  edi, HV_SLAT_ROOT
    call hv_slat_bits
    lea  rcx, [r15 + 0x2000]
    or   rax, rcx
    mov  [rel hv_linux_eptp], rax
    mov  byte [rel hv_linux_load_phase], 12   ; prepared, not yet VM entry
    xor  eax, eax
    jmp  .out
.display_bad:
    mov  byte [rel hv_linux_load_err], 2
    jmp  .fail
.bz_bad:
    mov  byte [rel hv_linux_load_err], 3
    jmp  .fail
.kernel_io:
    mov  byte [rel hv_linux_load_err], 4
    jmp  .fail
.initrd_bad:
    mov  byte [rel hv_linux_load_err], 5
    jmp  .fail
.pin_bad:
    mov  byte [rel hv_linux_load_err], 10    ; RCQ-18: bytes differ from the profile pin
    jmp  .fail
.fit_bad:
    mov  byte [rel hv_linux_load_err], 11    ; RCQ-18: artifacts do not fit the profile RAM
    jmp  .fail
.resume_bad:
    mov  byte [rel hv_linux_load_err], 13    ; RCQ-18 S2: snapshot binding refused
    jmp  .fail
.domain_bad:
    mov  byte [rel hv_linux_load_err], 16    ; RCQ-50 F1: DID 0x10 is not this START's RAM
    jmp  .fail
.pad_bad:
    mov  byte [rel hv_linux_load_err], 14    ; RCQ-36: private PAD1 channel bind refused
    jmp  .fail
.assign_bad:
    mov  byte [rel hv_linux_load_err], 15    ; RCQ-36 V2 c2: host function assignment refused
.fail:
    call pcia_release                        ; nothing assigned: a no-op
    call guestsound_state_zero
    call guestentropy_state_zero
    call guestrestore_state_zero
    call guestpower_state_zero              ; C10b-1a S3: a failed loader disarms
    call guestdisplay_reset                 ; failed loader never exports a frame
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hv_linux_map_devices(RDI=control base) — RCQ-18. Build the virtio-mmio EPT
; subtree for exactly the selected devices (vm_profile_dev_mask), then account
; from the built tables themselves: present RAM leaves in the guest PD plus
; present register pages. An omitted device has no EPT entry at all, so any
; guest access to its GPA exits and is classed foreign. Pure memory writes.
hv_linux_map_devices:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    mov  edx, [rel vm_profile_dev_mask]
    mov  eax, edx
    and  eax, VP_DEV_TIMER | VP_DEV_LAPIC | VP_DEV_WARMCHAN | VP_DEV_PINCHAN ; PIT/PIC-lite and the guest LAPIC are reset on every START
    mov  [rel vm_profile_live_devices], eax
    mov  byte [rel guestpower_live], 0 ; C10b-1a: set only by .power below
    test edx, VP_DEV_CONSOLE | VP_DEV_NET | VP_DEV_INPUT | VP_DEV_DISPLAY | VP_DEV_ENTROPY | VP_DEV_SOUND | VP_DEV_RESTORE | VP_DEV_FILESYSTEM | VP_DEV_WIFI
    jz   .count
    ; Classic's proven virtio-mmio EPT shape: reads hit a real register page;
    ; writes fault into the emulator. Never map this GPA as ordinary RAM.
    push rdi
    push rdx
    mov  edi, HV_SLAT_TRAP_RO
    call hv_slat_bits
    push rax
    mov  edi, HV_SLAT_TABLE
    call hv_slat_bits
    pop  r8                                 ; register-page leaf bits
    pop  rdx
    pop  rdi
    lea  rcx, [rdi + HV_VCON_EPT_PD]
    or   rcx, rax
    mov  [rdi + 0x3000 + 3*8], rcx          ; PDPT[3] -> vcon PD
    lea  rcx, [rdi + HV_VCON_EPT_PT]
    or   rcx, rax
    mov  [rdi + HV_VCON_EPT_PD + 128*8], rcx
    test edx, VP_DEV_CONSOLE
    jz   .net
    lea  rax, [rdi + HV_VCON_PAGE]
    or   rax, r8                            ; R, !W, !X, UC: free reads, trapped writes
    mov  [rdi + HV_VCON_EPT_PT], rax
    or   dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    test edx, VP_DEV_PADCHAN                ; RCQ-36: the console page is the PAD1 port
    jz   .net
    or   dword [rel vm_profile_live_devices], VP_DEV_PADCHAN
.net:
    test edx, VP_DEV_NET
    jz   .input
    lea  rax, [rdi + HV_GUESTNET_PAGE]
    or   rax, r8                            ; second page: virtio-net, same trap contract
    mov  [rdi + HV_VCON_EPT_PT + 8], rax
    or   dword [rel vm_profile_live_devices], VP_DEV_NET
.input:
    test edx, VP_DEV_INPUT
    jz   .entropy
    lea  rax, [rdi + HV_GUESTIN_PAGE]
    or   rax, r8                            ; RCQ-23 third page: virtio-input, same trap contract
    mov  [rdi + HV_VCON_EPT_PT + 16], rax
    or   dword [rel vm_profile_live_devices], VP_DEV_INPUT
.entropy:
    test edx, VP_DEV_ENTROPY
    jz   .sound
    lea  rax, [rdi + HV_GUESTRNG_PAGE]
    or   rax, r8
    mov  [rdi + HV_VCON_EPT_PT + 24], rax
    or   dword [rel vm_profile_live_devices], VP_DEV_ENTROPY
.sound:
    test edx, VP_DEV_SOUND
    jz .restore
    lea rax, [rdi + HV_GUESTSND_PAGE]
    or rax,r8
    mov [rdi + HV_VCON_EPT_PT + 32],rax
    or dword [rel vm_profile_live_devices],VP_DEV_SOUND
.restore:
    test edx, VP_DEV_RESTORE
    jz   .filesystem
    lea  rax, [rdi + HV_GUESTRST_PAGE]
    or   rax, r8                            ; sixth page: paos.restore port, same trap contract
    mov  [rdi + HV_VCON_EPT_PT + 40], rax
    or   dword [rel vm_profile_live_devices], VP_DEV_RESTORE
.filesystem:
    test edx,VP_DEV_FILESYSTEM
    jz .wifi
    lea rax,[rdi+HV_GUESTFSC_PAGE]
    or rax,r8
    mov [rdi+HV_VCON_EPT_PT+48],rax
    lea rax,[rdi+HV_GUESTFSB_PAGE]
    or rax,r8
    mov [rdi+HV_VCON_EPT_PT+56],rax
    or dword [rel vm_profile_live_devices],VP_DEV_FILESYSTEM
.wifi:
    test edx,VP_DEV_WIFI
    jz .power
    lea rax,[rdi+HV_GUESTWIFI_PAGE]
    or rax,r8
    mov [rdi+HV_VCON_EPT_PT+64],rax
    or dword [rel vm_profile_live_devices],VP_DEV_WIFI
.power:
    call guestpower_selected                 ; C10b-1a B1: the exact driver-domain closure only
    test eax,eax
    jz .display
    lea rax,[rdi+HV_GUESTPWR_PAGE]
    or rax,r8                                ; tenth page: paos.power port, same trap contract
    mov [rdi+HV_VCON_EPT_PT+72],rax
    mov byte [rel guestpower_live],1   ; no profile bit: the mapped page is the datum
.display:
    test edx, VP_DEV_DISPLAY
    jz   .count
    push rdi
    call guestdisplay_map                   ; RCQ-23: one 2 MiB framebuffer leaf
    pop  rdi
    test eax, eax
    jz   .count
    or   dword [rel vm_profile_live_devices], VP_DEV_DISPLAY
.count:
    xor  ecx, ecx                           ; index
    xor  r8d, r8d                           ; present RAM leaves (guest PD)
    xor  r9d, r9d                           ; present register pages
    xor  r10d, r10d                         ; present display leaves (PDPT[3] PD below 0xD0000000)
.scan:
    cmp  qword [rdi + 0x4000 + rcx*8], 0
    je   .scan_hi1
    inc  r8d
.scan_hi1:
    cmp  qword [rdi + 0x3000 + 1*8], 0
    je   .scan_hi2                          ; RCQ-50: no PDPT[1] subtree, its PD holds nothing
    cmp  qword [rdi + HV_SLAT_RAM_PD1 + rcx*8], 0
    je   .scan_hi2
    inc  r8d
.scan_hi2:
    cmp  qword [rdi + 0x3000 + 2*8], 0
    je   .scan_hi4
    cmp  qword [rdi + HV_SLAT_RAM_PD2 + rcx*8], 0
    je   .scan_hi4
    inc  r8d
.scan_hi4:
    cmp  qword [rdi + 0x3000 + 4*8], 0
    je   .scan_pt
    cmp  qword [rdi + HV_SLAT_RAM_PD4 + rcx*8], 0
    je   .scan_pt
    inc  r8d
.scan_pt:
    cmp  qword [rdi + HV_VCON_EPT_PT + rcx*8], 0
    je   .scan_fb
    inc  r9d
.scan_fb:
    cmp  ecx, 128
    jae  .scan_next
    cmp  qword [rdi + 0x3000 + 3*8], 0
    je   .scan_next                         ; no subtree: the PD page holds nothing
    cmp  qword [rdi + HV_VCON_EPT_PD + rcx*8], 0
    je   .scan_next
    inc  r10d
.scan_next:
    inc  ecx
    cmp  ecx, 512
    jb   .scan
    mov  [rel vm_profile_live_mmio], r9d
    add  r8d, r9d
    add  r8d, r10d
    mov  [rel vm_profile_live_leaves], r8d
    mov  rax, [rel hv_linux_ram_bytes]
    add  rax, HV_LINUX_CTRL_BYTES
    shl  r10, 21                            ; each display leaf is 2 MiB of reserve
    add  rax, r10
    mov  [rel vm_profile_live_reserve], rax
    ret

; GUESTLINUX RUN — report the guest-boot tier state honestly.
cmd_verb_guestlinux:
    push r12
    mov  r12, rsi
    call cmd_handler_prologue
    call hv_out_reset
    lea  rdi, [rel str_hv_guestlinux_line]
    call hv_out_str
    call hv_append_state
    call hv_guest_identity_append
    lea  rdi, [rel str_hv_guest_output]
    call hv_out_str
    call hv_vcon_run_tail_append
    mov  byte [rel hv_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    ret

; GUESTKEY <text> — deliver one line through virtio-console queue 0. The ack
; is earned only when a real writable guest descriptor moved to the used ring.
cmd_verb_guestkey:
    push rbx
    push r12
    mov  r12, rsi
    call cmd_handler_prologue
    mov  rbx, [rdi + REQ_ARG]
    call hv_out_reset
    mov  rdi, rbx
    call hv_vcon_line_length
    cmp  eax, -1
    je   .too_long
    call hv_vcon_capture_reset
    mov  rdi, rbx
    call hv_vcon_rx_line
    test eax, eax
    jz   .no_buffer
    lea  rdi, [rel str_hv_guestkey_ok]
    call hv_out_str
    jmp  .done
.no_buffer:
    lea  rdi, [rel str_hv_guestkey_no]
    call hv_out_str
    jmp  .done
.too_long:
    lea  rdi, [rel str_hv_guestkey_long]
    call hv_out_str
.done:
    mov  byte [rel hv_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

; Append the live foundation and terminal guest-tier identity.
hv_append_state:
    lea  rdi, [rel str_hv_s_vmx]
    call hv_out_str
    movzx eax, byte [rel hv_vmx_present]
    call hv_out_digit
    lea  rdi, [rel str_hv_s_vmxon]
    call hv_out_str
    movzx eax, byte [rel hv_vmxon_ok]
    call hv_out_digit
    lea  rdi, [rel str_hv_s_ept]
    call hv_out_str
    movzx eax, byte [rel hv_ept_built]
    call hv_out_digit
    lea  rdi, [rel str_hv_s_tier]
    call hv_out_str
    ret

; hv_status_line — append the hv one-liner onto the UDP reply cursor via udp_put_str
;   (called from udp_send_reply). clobbers: RAX,RSI,RDI
hv_status_line:
    cmp  byte [rel hv_out_ready], 1
    jne  .none
    lea  rdi, [rel hv_out_buf]
    call udp_put_str
    mov  byte [rel hv_out_ready], 0
.none:
    ret

; --- staged out-buffer helpers (mirror the reinit_out_* pattern) ---
hv_out_reset:
    lea  rax, [rel hv_out_buf]
    mov  [rel hv_out_cur], rax
    mov  byte [rax], 0
    mov  qword [rel hv_out_clipped], 0
    ret

; hv_out_str(RDI=cstr) — bounded append through hv_out_putc. clobbers: RAX,RSI,RDI
hv_out_str:
.cp:
    mov  al, [rdi]
    test al, al
    jz   .end
    call hv_out_putc
    inc  rdi
    jmp  .cp
.end:
    ret

; hv_out_digit(AL=0..9) — append one ascii digit. clobbers: RAX,RSI
hv_out_digit:
    add  al, '0'
    jmp  hv_out_putc

; hv_out_putc(AL=byte) — the one writer of hv_out_buf (srcreview ranks 1+2 F4). Append AL and re-terminate
;   only while the cursor is inside the buffer and in front of its last byte, which stays the terminator;
;   otherwise drop AL and count it in hv_out_clipped. One unsigned offset test also refuses a cursor that
;   was never reset. clobbers: RSI
hv_out_putc:
    push rax
    mov  rsi, [rel hv_out_cur]
    lea  rax, [rel hv_out_buf]
    sub  rsi, rax
    cmp  rsi, HV_OUT_BYTES - 1
    pop  rax
    jae  .clip
    mov  rsi, [rel hv_out_cur]
    mov  [rsi], al
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel hv_out_cur], rsi
    ret
.clip:
    inc  qword [rel hv_out_clipped]
    ret

; ===========================================================================
; 1095 R1 — VMLAUNCH -> HLT guest tier. Ports the PROVEN monolith
;   drivers/vmx_hypervisor/vmx_selftest SEQUENCE onto the rework seams. The
;   ONLY departure: host-state is VALIDATED before the first VMLAUNCH (E1), so a
;   bad field is a diagnosable REFUSAL, not an uncatchable host hard-hang.
; ===========================================================================

; --- small token helpers (avoid pulling core/lib/str import into this L5 seam) ---

; hv_tok_is(RDI=text, RSI=keyword) -> AL=1 if text starts with keyword and the
;   next char is NUL or space (a whole leading token match). clobbers RAX,RCX,RDI,RSI
hv_tok_is:
    mov  al, [rsi]
    test al, al
    jz   .kw_end
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    inc  rsi
    jmp  hv_tok_is
.kw_end:
    movzx ecx, byte [rdi]                    ; char in text right after the keyword
    test cl, cl
    jz   .yes
    cmp  cl, ' '
    je   .yes
.no:
    xor  al, al
    ret
.yes:
    mov  al, 1
    ret

; hv_str_has(RDI=haystack, RSI=needle) -> AL=1 if needle occurs anywhere in
;   haystack. clobbers RAX,RCX,RDX,RDI,RSI
hv_str_has:
    mov  rdx, rdi                            ; scan cursor
.at:
    movzx eax, byte [rdx]
    test al, al
    jz   .miss
    mov  rdi, rdx
    mov  rcx, rsi
.cmp:
    movzx eax, byte [rcx]
    test al, al
    jz   .hit                                ; reached needle end -> matched
    cmp  al, [rdi]
    jne  .next
    inc  rdi
    inc  rcx
    jmp  .cmp
.next:
    inc  rdx
    jmp  .at
.hit:
    mov  al, 1
    ret
.miss:
    xor  al, al
    ret

; hv_validate_host_state(RDI = candidate host RSP) — assert the SDM Vol 3C §26.5
;   host-state fields we own are sane BEFORE any VMLAUNCH. Sets hv_val_ok=1 and
;   returns RAX=0 on success; on the first violation sets hv_val_ok=0 +
;   hv_val_field=<name ptr> and returns RAX=field ptr. Never launches; pure reads.
;   VMX must have been detected/enabled before reading its capability MSRs.
;   clobbers RAX,RCX,RDX,R8,R9,R10; preserves RBX.
hv_validate_host_state:
    push rbx
    mov  rbx, rdi                            ; candidate RSP
    mov  qword [rel hv_val_ok], 0
    ; All callers (early Linux, VALIDATE and legacy launch) share this guard.
    ; An absent/firmware-locked VMX backend must degrade without #GP on 0x486.
    cmp  byte [rel hv_vmx_present], 1
    jne  .bad_vmx
    ; --- CR0 fixed bits (0x486 must-be-1, 0x487 may-be-1). Validate the FORCED value
    ;     that hv_guest_launch actually loads as HOST_CR0 = (cr0|fixed0)&fixed1 — the
    ;     raw live CR0 may legitimately lack a fixed bit (e.g. NE) that the launch path
    ;     sets, so checking the raw value would falsely refuse a launchable host. ---
    mov  ecx, 0x486
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r8, rax                             ; CR0_FIXED0
    mov  ecx, 0x487
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r9, rax                             ; CR0_FIXED1
    mov  rax, cr0
    or   rax, r8                             ; force must-be-1
    and  rax, r9                             ; force may-be-1 (clear must-be-0)
    mov  r10, rax
    and  r10, r8
    cmp  r10, r8                             ; forced CR0 satisfies fixed0 ?
    jne  .bad_cr0
    mov  r10, r9
    not  r10
    and  r10, rax                            ; forced CR0 sets no must-be-0 bit ?
    jnz  .bad_cr0
    ; --- CR4 fixed bits (0x488/0x489; includes VMXE must-be-1). Same forced-value
    ;     validation as CR0 above. ---
    mov  ecx, 0x488
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r8, rax                             ; CR4_FIXED0
    mov  ecx, 0x489
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r9, rax                             ; CR4_FIXED1
    mov  rax, cr4
    or   rax, r8
    and  rax, r9
    mov  r10, rax
    and  r10, r8
    cmp  r10, r8
    jne  .bad_cr4
    mov  r10, r9
    not  r10
    and  r10, rax
    jnz  .bad_cr4
    ; --- CR3 reserved bits 63:52 must be zero ---
    mov  rax, cr3
    mov  rcx, 0xFFF0000000000000
    test rax, rcx
    jnz  .bad_cr3
    ; --- host TR selector must be present + nonzero (1101 seam; TR=0 hard-hangs) ---
    str  ax
    test ax, ax
    jz   .bad_tr
    ; --- host CS must be the kernel code selector 0x08 (RPL0/TI0) ---
    mov  ax, cs
    cmp  ax, 0x08
    jne  .bad_cs
    ; --- host SS must be the kernel data selector 0x10 ---
    mov  ax, ss
    cmp  ax, 0x10
    jne  .bad_ss
    ; --- host RSP must be CANONICAL (bits 63:47 all equal) — the injectable field ---
    mov  rax, rbx
    shl  rax, 16
    sar  rax, 16
    cmp  rax, rbx
    jne  .bad_rsp
    ; all fields sane
    mov  qword [rel hv_val_ok], 1
    xor  eax, eax
    pop  rbx
    ret
.bad_vmx:
    lea  rax, [rel str_hv_f_vmx]
    jmp  .refuse
.bad_cr0:
    lea  rax, [rel str_hv_f_cr0]
    jmp  .refuse
.bad_cr4:
    lea  rax, [rel str_hv_f_cr4]
    jmp  .refuse
.bad_cr3:
    lea  rax, [rel str_hv_f_cr3]
    jmp  .refuse
.bad_tr:
    lea  rax, [rel str_hv_f_tr]
    jmp  .refuse
.bad_cs:
    lea  rax, [rel str_hv_f_cs]
    jmp  .refuse
.bad_ss:
    lea  rax, [rel str_hv_f_ss]
    jmp  .refuse
.bad_rsp:
    lea  rax, [rel str_hv_f_rsp]
.refuse:
    mov  [rel hv_val_field], rax
    pop  rbx
    ret

; hv_render_validate(EDI = bad-rsp requested) — run the validator against the live
;   RSP (or a deliberately NON-CANONICAL RSP when --inject-bad-rsp) and stage the
;   verdict line into hv_out_buf. clobbers caller-saved.
hv_render_validate:
    push rbx
    mov  ebx, edi
    test ebx, ebx
    jz   .live
    mov  rdi, 0x0001000000000000            ; bit48 set / bit47 clear => non-canonical
    jmp  .go
.live:
    mov  rdi, rsp                            ; the real host RSP (canonical)
.go:
    call hv_validate_host_state
    call hv_out_reset
    lea  rdi, [rel str_hv_val_pre]
    call hv_out_str
    cmp  qword [rel hv_val_ok], 1
    jne  .refused
    lea  rdi, [rel str_hv_val_ok]
    call hv_out_str
    pop  rbx
    ret
.refused:
    lea  rdi, [rel str_hv_val_refused]
    call hv_out_str
    mov  rdi, [rel hv_val_field]             ; names the offending field (field=rsp)
    call hv_out_str
    pop  rbx
    ret

; hv_guest_launch — the load-bearing rung: a REAL VMLAUNCH into an in-image HLT
;   stub, host-state validated first. HLT-exiting proc control => the guest HLT
;   VM-exits with basic reason 12; we decode it from the VMCS exit-reason field,
;   advance guest RIP past HLT + clear the STI interrupt-shadow (E3), and resume a
;   bounded number of times, then VMXOFF and restore the CPU exactly as found.
;   Sets hv_launches/hv_hlt_exits/hv_exit_reason/hv_hlt_exit_seen. Never resumes on
;   a non-HLT exit. clobbers: caller-saved.
hv_guest_launch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HVB_HLT_SIZE
    mov  qword [rsp + HVB_ACTIVE], 0
    mov  qword [rsp + HVB_GUARD], 0
    mov  qword [rsp + HVB_REQUEST], 0
    mov  qword [rsp + HVB_LEASE], 0
    mov  qword [rsp + HVB_FRONTIER], 0
    ; --- E1: validate host state with the LIVE RSP BEFORE touching VMX. A bad
    ;     field REFUSES here (host stays up) instead of hard-hanging on VMLAUNCH. ---
    mov  rdi, rsp
    call hv_validate_host_state
    cmp  qword [rel hv_val_ok], 1
    je   .host_ok
    mov  byte [rel hv_launch_refused], 1
    jmp  .ret_only
.host_ok:
    mov  byte [rel hv_launch_refused], 0
    ; --- lazy-alloc a dedicated 12 KiB launch region (+0 VMXON, +0x1000 VMCS,
    ;     +0x2000 guest stack), independent of the boot foundation regions ---
    mov  rax, [rel hv_launch_base]
    test rax, rax
    jnz  .have_base
    mov  rdi, 0x3000
    call dma_alloc
    test rax, rax
    jz   .ret_only                           ; pool exhausted -> cannot launch, host fine
    mov  [rel hv_launch_base], rax
.have_base:
    mov  r15, [rel hv_launch_base]           ; r15 = launch region base (== phys)
    ; zero the three pages
    mov  rdi, r15
    xor  eax, eax
    mov  ecx, 0x3000 / 8
    rep  stosq
    ; revision id (IA32_VMX_BASIC low 31 bits) into VMXON + VMCS regions
    mov  ecx, 0x480
    rdmsr
    and  eax, 0x7FFFFFFF
    mov  [r15], eax
    mov  [r15 + 0x1000], eax
    ; --- quiet window across the whole VMX excursion ---
    pushfq
    pop  rax
    mov  [rel hv_launch_rflags], rax
    cli
    mov  rdi, rsp
    call hv_boundary_arm
    test rax, rax
    jnz  .guard_refused
    ; --- CR0/CR4 fixed bits; save originals for restore ---
    mov  ecx, 0x486
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x487
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  rax, cr0
    mov  [rel hv_launch_cr0], rax
    or   rax, r12
    and  rax, r13
    mov  cr0, rax
    mov  [rel hv_launch_hcr0], rax
    mov  ecx, 0x488
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x489
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  rax, cr4
    mov  [rel hv_launch_cr4], rax
    or   rax, r12
    and  rax, r13
    mov  cr4, rax
    mov  [rel hv_launch_hcr4], rax
    ; --- VMXON + VMCS clear/load (this launch's own regions) ---
    mov  rax, r15
    mov  [rel hv_launch_vmxon_pa], rax
    lea  rcx, [r15 + 0x1000]
    mov  [rel hv_launch_vmcs_pa], rcx
    vmxon [rel hv_launch_vmxon_pa]
    jc   .vmxon_fail
    jz   .vmxon_fail
    vmclear [rel hv_launch_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    vmptrld [rel hv_launch_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    mov  dword [rel hv_vmwrite_fails], 0
    ; --- VM-execution / exit / entry controls (folded against capability MSRs) ---
    mov  edi, 0x481                          ; owner IRQ/NMI must exit to LAND
    mov  esi, 9
    call hv_adjust_ctls
    mov  ecx, eax
    and  ecx, 9
    cmp  ecx, 9
    jne  .vmcs_fail
    mov  edi, VMXF_PIN_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_PIN_CTLS
    vmread rax, rdi
    jc   .vmcs_fail
    jz   .vmcs_fail
    and  eax, 9
    cmp  eax, 9
    jne  .vmcs_fail
    mov  edi, 0x482                          ; proc-based: HLT-exiting (bit 7)
    mov  esi, 0x80
    call hv_adjust_ctls
    mov  edi, VMXF_PROC_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, 0x483                          ; exit: host address-space size (bit 9)
    mov  esi, 0x200
    call hv_adjust_ctls
    mov  edi, VMXF_EXIT_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, 0x484                          ; entry: IA-32e mode guest (bit 9)
    mov  esi, 0x200
    call hv_adjust_ctls
    mov  edi, VMXF_ENTRY_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_EXC_BITMAP                ; intercept every guest exception (a
    mov  esi, 0xFFFFFFFF                     ; sick guest EXITS, not into our IDT)
    call hv_w
    mov  edi, VMXF_PF_MASK
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_PF_MATCH
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_CR3_TARGETS
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_EXIT_MSR_ST
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_EXIT_MSR_LD
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_ENTRY_MSR_LD
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_ENTRY_INTR
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_LINK_PTR                  ; must be all-1s
    mov  rsi, -1
    call hv_w
    mov  edi, VMXF_G_DEBUGCTL
    xor  esi, esi
    call hv_w
    ; --- host state (where the CPU lands on VM-exit) ---
    mov  edi, VMXF_HOST_CS_SEL
    mov  esi, 0x08
    call hv_w
    mov  edi, VMXF_HOST_SS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_HOST_ES_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_HOST_DS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_HOST_FS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_HOST_GS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_HOST_TR_SEL
    mov  esi, 0x18                           ; host TSS (1101) — TR must be nonzero
    call hv_w
    mov  edi, VMXF_H_CR0
    mov  rsi, [rel hv_launch_hcr0]
    call hv_w
    mov  edi, VMXF_H_CR3
    mov  rsi, cr3
    mov  [rel hv_launch_hcr3], rsi
    call hv_w
    mov  edi, VMXF_H_CR4
    mov  rsi, [rel hv_launch_hcr4]
    call hv_w
    sgdt [rel hv_dtr_buf]
    mov  rsi, [rel hv_dtr_buf + 2]
    mov  [rel hv_gdt_base], rsi
    movzx eax, word [rel hv_dtr_buf]
    mov  [rel hv_gdt_limit], eax
    mov  edi, VMXF_H_GDTR_BASE
    call hv_w
    sidt [rel hv_dtr_buf]
    mov  rsi, [rel hv_dtr_buf + 2]
    mov  [rel hv_idt_base], rsi
    movzx eax, word [rel hv_dtr_buf]
    mov  [rel hv_idt_limit], eax
    mov  edi, VMXF_H_IDTR_BASE
    call hv_w
    mov  edi, VMXF_H_TR_BASE
    lea  rsi, [rel tss_struct]               ; the 1101 host TSS base
    call hv_w
    mov  edi, VMXF_H_FS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_H_GS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_H_SYSENTER_CS
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_H_SYSENTER_ESP
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_H_SYSENTER_EIP
    xor  esi, esi
    call hv_w
    ; --- guest state: a 64-bit twin of the host sharing host page tables, RIP at
    ;     the in-image HLT stub (no EPT for this tier — the HLT stub needs none) ---
    mov  edi, VMXF_G_CR0
    mov  rsi, [rel hv_launch_hcr0]
    call hv_w
    mov  edi, VMXF_G_CR3
    mov  rsi, [rel hv_launch_hcr3]
    call hv_w
    mov  edi, VMXF_G_CR4
    mov  rsi, [rel hv_launch_hcr4]
    and  rsi, ~HV_CR4_GUEST_DENIED           ; V5: a host PKE/KL never leaks in
    call hv_w
    mov  edi, VMXF_G_DR7
    mov  esi, 0x400
    call hv_w
    mov  edi, VMXF_GUEST_CS_SEL
    mov  esi, 0x08
    call hv_w
    mov  edi, VMXF_G_CS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_CS_LIMIT
    mov  esi, 0xFFFFFFFF
    call hv_w
    mov  edi, VMXF_G_CS_AR
    mov  esi, 0xA09B
    call hv_w
    mov  edi, VMXF_GUEST_SS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_G_SS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_SS_LIMIT
    mov  esi, 0xFFFFFFFF
    call hv_w
    mov  edi, VMXF_G_SS_AR
    mov  esi, 0xC093
    call hv_w
    mov  edi, VMXF_GUEST_DS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_G_DS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_DS_LIMIT
    mov  esi, 0xFFFFFFFF
    call hv_w
    mov  edi, VMXF_G_DS_AR
    mov  esi, 0xC093
    call hv_w
    mov  edi, VMXF_GUEST_ES_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_G_ES_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_ES_LIMIT
    mov  esi, 0xFFFFFFFF
    call hv_w
    mov  edi, VMXF_G_ES_AR
    mov  esi, 0xC093
    call hv_w
    mov  edi, VMXF_GUEST_FS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_G_FS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_FS_LIMIT
    mov  esi, 0xFFFFFFFF
    call hv_w
    mov  edi, VMXF_G_FS_AR
    mov  esi, 0xC093
    call hv_w
    mov  edi, VMXF_GUEST_GS_SEL
    mov  esi, 0x10
    call hv_w
    mov  edi, VMXF_G_GS_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_GS_LIMIT
    mov  esi, 0xFFFFFFFF
    call hv_w
    mov  edi, VMXF_G_GS_AR
    mov  esi, 0xC093
    call hv_w
    mov  edi, VMXF_GUEST_LDTR_SEL
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_LDTR_BASE
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_LDTR_LIMIT
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_LDTR_AR
    mov  esi, 0x10000                        ; unusable
    call hv_w
    mov  edi, VMXF_GUEST_TR_SEL
    mov  esi, 0x18
    call hv_w
    mov  edi, VMXF_G_TR_BASE
    lea  rsi, [rel tss_struct]
    call hv_w
    mov  edi, VMXF_G_TR_LIMIT
    mov  esi, 0x67
    call hv_w
    mov  edi, VMXF_G_TR_AR
    mov  esi, 0x8B                           ; present 64-bit busy TSS
    call hv_w
    mov  edi, VMXF_G_GDTR_BASE
    mov  rsi, [rel hv_gdt_base]
    call hv_w
    mov  edi, VMXF_G_GDTR_LIMIT
    mov  esi, [rel hv_gdt_limit]
    call hv_w
    mov  edi, VMXF_G_IDTR_BASE
    mov  rsi, [rel hv_idt_base]
    call hv_w
    mov  edi, VMXF_G_IDTR_LIMIT
    mov  esi, [rel hv_idt_limit]
    call hv_w
    mov  edi, VMXF_G_RSP                     ; guest stack = top of the 3rd page
    lea  rsi, [r15 + 0x2FF0]
    call hv_w
    mov  edi, VMXF_G_RIP
    lea  rsi, [rel hv_guest_code]
    call hv_w
    mov  edi, VMXF_G_RFLAGS
    mov  esi, 2                              ; IF=0 (bit1 reserved-1)
    call hv_w
    mov  edi, VMXF_G_INTERRUPT
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_ACTIVITY
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_PEND_DBG
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_SYSENTER_CS
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_SYSENTER_ESP
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_G_SYSENTER_EIP
    xor  esi, esi
    call hv_w
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .vmcs_fail
    ; count this launch attempt now that the VMCS is fully populated
    inc  dword [rel hv_launches]
    ; --- host RSP/RIP written LAST so the VM-exit landing matches THIS frame ---
    mov  edi, VMXF_H_RSP
    mov  rsi, rsp
    call hv_w
    mov  edi, VMXF_H_RIP
    lea  rsi, [rel .exit_landing]
    call hv_w
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .vmcs_fail
    mov  rdi, rsp
    call hv_vmx_boundary_enter
    test rax, rax
    jnz  .boundary_refused
    HV_BOUNDARY_FINAL
    VCB_ENTRY_GUARD
    vmlaunch
    mov  byte [rel vcg_root], 1          ; first instruction on VMfail
    ; fell through -> VM entry failed (never entered the guest)
    jnz  .entry_noerr
    mov  edi, VMXF_VMINSTR_ERR
    vmread rax, rdi
    mov  [rel hv_instr_err], eax
.entry_noerr:
    HV_BOUNDARY_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    jmp  .teardown

.exit_landing:
    mov  byte [rel vcg_root], 1          ; first instruction at HOST_RIP
    ; VM-exit lands here with rsp == HOST_RSP (this frame; guest only ran HLT, so
    ; nothing was pushed and rsp is unchanged across resumes).
    HV_BOUNDARY_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    mov rdi,rsp
    mov edx,1
    call hv_boundary_exec_vmx
    call hv_ops_exit_dispatch_active
    test eax, eax
    jz   .teardown
    mov  rdi, rsp
    call hv_vmx_boundary_enter
    test rax, rax
    jnz  .boundary_refused
    HV_BOUNDARY_FINAL
    VCB_ENTRY_GUARD
    vmresume
    mov  byte [rel vcg_root], 1          ; first instruction on VMfail
    ; fell through -> resume failed
    jnz  .resume_noerr
    mov  edi, VMXF_VMINSTR_ERR
    vmread rax, rdi
    mov  [rel hv_instr_err], eax
.resume_noerr:
    HV_BOUNDARY_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    jmp  .teardown
.boundary_refused:
    lea  rax, [rel str_hv_boundary_refused]
    mov  [rel hv_val_field], rax
    mov  byte [rel hv_launch_refused], 1
.teardown:
    vmxoff
    mov  rax, [rel hv_launch_cr0]
    mov  cr0, rax
    mov  rax, [rel hv_launch_cr4]
    mov  cr4, rax
    mov  rdi, rsp
    call hv_boundary_finish
    push qword [rel hv_launch_rflags]
    popfq
    ; --- earned marker: only a DECODED reason-12 exit with >=1 HLT exit lights it
    ;     (serial is polled I/O — safe now that interrupts are restored) ---
    cmp  byte [rel hv_launch_refused], 0
    jne  .ret_only
    cmp  dword [rel hv_exit_reason], 12
    jne  .ret_only
    cmp  dword [rel hv_hlt_exits], 1
    jb   .ret_only
    mov  byte [rel hv_hlt_exit_seen], 1
    lea  rdi, [rel str_hv_hlt_marker]
    call serial_string
    jmp  .ret_only

.vmcs_fail:
    mov  byte [rel hv_launch_vmcsfail], 1
    vmxoff                                   ; in VMX root -> leave it before restore
    jmp  .fail_restore
.vmxon_fail:
    mov  byte [rel hv_launch_vmxonfail], 1
.fail_restore:
    mov  rax, [rel hv_launch_cr0]
    mov  cr0, rax
    mov  rax, [rel hv_launch_cr4]
    mov  cr4, rax
    mov  rdi, rsp
    call hv_boundary_finish
    push qword [rel hv_launch_rflags]
    popfq
    jmp  .ret_only
.guard_refused:
    lea  rax, [rel str_hv_guard_refused]
    mov  [rel hv_val_field], rax
    mov  byte [rel hv_launch_refused], 1
    push qword [rel hv_launch_rflags]
    popfq
.ret_only:
    add  rsp, HVB_HLT_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Enter the prepared Linux image, remain resident after decoded kboot evidence,
; and stop on a proved panic or the pre-kboot budget. Restore shared CPU state.
hv_linux_enter:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HVB_SIZE
    mov  [rel hv_vmx_boundary_frame], rsp
    mov  qword [rsp + HVB_ACTIVE], 0
    mov  qword [rsp + HVB_GUARD], 0
    mov  qword [rsp + HVB_REQUEST], 0
    mov  qword [rsp + HVB_LEASE], 0
    mov  qword [rsp + HVB_FRONTIER], 0
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop                       ; a START never inherits a live pair
    mov  r15, [rel hv_linux_region]
    mov  ecx, 0x480
    rdmsr
    and  eax, 0x7FFFFFFF
    mov  [r15], eax
    mov  [r15 + 0x1000], eax
    mov  [rel hv_launch_vmxon_pa], r15
    lea  rax, [r15 + 0x1000]
    mov  [rel hv_launch_vmcs_pa], rax

    pushfq
    pop  rax
    mov  [rel hv_launch_rflags], rax
    cli
    mov  rdi, rsp
    call hv_boundary_arm
    ; Preserve the actual return and retained frame before teardown/guest GPR load.
    push rdi
    push rsi
    lea rdi, [rsp + 16]
    mov esi, 1
    call hv_boundary_observe
    pop rsi
    pop rdi
    test rax, rax
    jnz  .guard_refused
    ; VMX fixed-bit discipline, preserving exact host CR0/CR4 for teardown.
    mov  ecx, 0x486
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x487
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  rax, cr0
    mov  [rel hv_launch_cr0], rax
    or   rax, r12
    and  rax, r13
    mov  cr0, rax
    mov  [rel hv_launch_hcr0], rax
    mov  ecx, 0x488
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x489
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  rax, cr4
    mov  [rel hv_launch_cr4], rax
    or   rax, r12
    and  rax, r13
    mov  cr4, rax
    mov  [rel hv_launch_hcr4], rax

    call vst_select                         ; private decision BEFORE legacy state
    cmp  eax, 2
    je   .s7_start_refused
    test eax, eax
    jnz  .xsave_ready                        ; private native context owns MSRs/XSAVE
    call hv_linux_save_host_msrs
    call hv_linux_host_xsave
.xsave_ready:
    vmxon [rel hv_launch_vmxon_pa]
    jc   .vmxon_fail
    jz   .vmxon_fail
    mov  byte [rel hv_linux_vmx_live], 1
    cmp  byte [rel hvw_bound], 1
    jne  .warm_vmx_ready
    mov  byte [rel hvw_slat_retired], 0
.warm_vmx_ready:
    vmclear [rel hv_launch_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    vmptrld [rel hv_launch_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    mov  dword [rel hv_vmwrite_fails], 0
    call hv_linux_write_controls
    call hv_linux_write_state
    cmp  byte [rel gsn_resume_live], 1
    jne  .state_written
    call guestsnap_enter_state               ; RCQ-18 S2: captured guest area + CPU state
    call hv_linux_xcr0_adopt                 ; HV-XCR0 V2: the restored XCR0 is the guest's; host code on host|guest
.state_written:
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .vmcs_fail
    inc  dword [rel hv_launches]

    mov  edi, VMXF_H_RSP
    mov  rsi, rsp
    call hv_w
    mov  edi, VMXF_H_RIP
    lea  rsi, [rel .exit_landing]
    call hv_w
    call hv_linux_arm_deadline
    call hv_linux_reset_timer
    call hv_vmx_host_deadline_renew          ; ROOT109896 (4): first host deadline, 1 ms after START's turn
    call hv_vmx_host_timer_arm               ; time left to it, floor Q_min (SEC109899 H1, SEC109922 G1)
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .vmcs_fail
    cmp  qword [rel vst_native_restore], 1
    jne  .legacy_scrub
    mov  rdi, rsp
    call vst_activate                       ; complete prepare/seal, then READY1
    cmp  eax, 1
    jne  .s7_start_refused
    call vst_status_start
    jmp  .scrubbed
.legacy_scrub:
    cmp  byte [rel gsn_resume_live], 1
    je   .scrubbed                           ; a resume keeps the vector state guestsnap restored
    call hv_linux_vector_scrub               ; HV-XCR0 V3: no earlier guest's or host task's vector state
.scrubbed:
    call vst_status_bsp_begin
    call vcb_context_save
    mov  rdi, rsp
    call hv_vmx_boundary_enter
    ; Preserve the actual return and retained frame before teardown/guest GPR load.
    push rdi
    push rsi
    lea rdi, [rsp + 16]
    mov esi, 1
    call hv_boundary_observe
    pop rsi
    pop rdi
    test rax, rax
    jnz  .boundary_refused
    mov  rdi, rsp
    lea  rsi, [rel .exit_landing]
    call vcb_context_host_write
    call vcb_context_guest                  ; private S7 context or legacy guest XCR0
    mov  rdi, rsp
    call vcb_go

    cmp  byte [rel gsn_resume_live], 1
    je   .resume_gprs
    HV_BOUNDARY_FINAL
    ; Linux 64-bit boot ABI: RSI=boot_params GPA, other guest GPRs zero.
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  ebp, ebp
    xor  edi, edi
    xor  r8d, r8d
    xor  r9d, r9d
    xor  r10d, r10d
    xor  r11d, r11d
    xor  r12d, r12d
    xor  r13d, r13d
    xor  r14d, r14d
    xor  r15d, r15d
    mov  esi, HV_LINUX_BP_GPA
.launch:
    VCB_ENTRY_GUARD
    vmlaunch
    mov  byte [rel vcg_root], 1          ; first instruction on VMfail
    ; Fall-through means VM entry failed; capture the architectural reason.
    jnz  .entry_noerr
    mov  edi, VMXF_VMINSTR_ERR
    vmread rax, rdi
    mov  [rel hv_instr_err], eax
.entry_noerr:
    VCB_GANG_DOWN
    HV_BOUNDARY_LAND
    VCB_CONTEXT_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    call vcb_context_host
    mov  byte [rel hv_linux_load_err], 6
    jmp  .teardown

.exit_landing:
    mov  byte [rel vcg_root], 1          ; first instruction at HOST_RIP
    ; VM-exit preserves guest GPRs; save them before using host scratch.
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 8], rbx
    mov  [rel hv_linux_gpr + 16], rcx
    mov  [rel hv_linux_gpr + 24], rdx
    mov  [rel hv_linux_gpr + 32], rsi
    mov  [rel hv_linux_gpr + 40], rdi
    mov  [rel hv_linux_gpr + 48], rbp
    mov  [rel hv_linux_gpr + 56], r8
    mov  [rel hv_linux_gpr + 64], r9
    mov  [rel hv_linux_gpr + 72], r10
    mov  [rel hv_linux_gpr + 80], r11
    mov  [rel hv_linux_gpr + 88], r12
    mov  [rel hv_linux_gpr + 96], r13
    mov  [rel hv_linux_gpr + 104], r14
    mov  [rel hv_linux_gpr + 112], r15
    VCB_GANG_DOWN
    HV_BOUNDARY_LAND
    VCB_CONTEXT_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    mov rdi,rsp
    mov edx,2
    call hv_boundary_exec_vmx
    call vcb_context_host
    call vst_status_bsp_end
    call vcb_dispatch
    test eax, eax
    jz   .teardown
    call hv_ops_exit_dispatch_active
    test eax, eax
    jz   .teardown
    call vst_status_bsp_begin
    call vcb_context_save
    mov  rdi, rsp
    call hv_vmx_boundary_enter
    ; Preserve the actual return and retained frame before teardown/guest GPR load.
    push rdi
    push rsi
    lea rdi, [rsp + 16]
    mov esi, 1
    call hv_boundary_observe
    pop rsi
    pop rdi
    test rax, rax
    jnz  .boundary_refused
    mov  rdi, rsp
    lea  rsi, [rel .exit_landing]
    call vcb_context_host_write
    call vcb_context_guest                  ; private S7 context or legacy guest XCR0
    cmp  byte [rel gsn_capture_req], 0
    je   .reload
    call guestsnap_capture                   ; RCQ-18 S2: handled, resuming exit only
.reload:
    mov  rdi, rsp
    call vcb_go
    HV_BOUNDARY_FINAL
    mov  rbx, [rel hv_linux_gpr + 8]
    mov  rcx, [rel hv_linux_gpr + 16]
    mov  rdx, [rel hv_linux_gpr + 24]
    mov  rsi, [rel hv_linux_gpr + 32]
    mov  rdi, [rel hv_linux_gpr + 40]
    mov  rbp, [rel hv_linux_gpr + 48]
    mov  r8,  [rel hv_linux_gpr + 56]
    mov  r9,  [rel hv_linux_gpr + 64]
    mov  r10, [rel hv_linux_gpr + 72]
    mov  r11, [rel hv_linux_gpr + 80]
    mov  r12, [rel hv_linux_gpr + 88]
    mov  r13, [rel hv_linux_gpr + 96]
    mov  r14, [rel hv_linux_gpr + 104]
    mov  r15, [rel hv_linux_gpr + 112]
    mov  rax, [rel hv_linux_gpr + 0]
    VCB_ENTRY_GUARD
    vmresume
    mov  byte [rel vcg_root], 1          ; first instruction on VMfail
    jnz  .resume_noerr
    mov  edi, VMXF_VMINSTR_ERR
    vmread rax, rdi
    mov  [rel hv_instr_err], eax
.resume_noerr:
    VCB_GANG_DOWN
    HV_BOUNDARY_LAND
    VCB_CONTEXT_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    call vcb_context_host
.boundary_refused:
    lea  rax, [rel str_hv_boundary_refused]
    mov  [rel hv_val_field], rax
    mov  byte [rel hv_linux_load_err], 6
    mov  byte [rel hv_launch_refused], 1
.teardown:
    call vcb_context_cancel
    mov  rdi, rsp
    call vst_close                       ; AP own VMXOFF before frozen-table thaw
    cmp  byte [rel hv_linux_vmx_live], 1
    jne  .restore
    call guest_surface_revoke_ept
    call cdp_bridge_revoke_ept
    call hvw_before_vmxoff                   ; unmap + verified INVEPT before VMXOFF
    vmxoff
    mov  byte [rel hv_linux_vmx_live], 0
.restore:
    cmp  qword [rel vst_native_restore], 0
    je   .legacy_restore
    cmp  qword [rel vst_native_restore], 1
    jne  vcb_fail_stop
    mov  rax, [rel hv_launch_cr0]
    mov  cr0, rax
    mov  rax, [rel hv_launch_cr4]
    mov  cr4, rax
    jmp  .host_restored
.legacy_restore:
    call hv_linux_restore_host_quiet
.host_restored:
    mov  rdi, rsp
    call hv_boundary_finish
    call vst_finish
    push qword [rel hv_launch_rflags]
    popfq
    jmp  .ret
.s7_start_refused:
    mov  byte [rel hv_launch_refused], 1
    mov  byte [rel hv_linux_load_err], 6
    jmp  .teardown
.vmcs_fail:
    mov  byte [rel hv_launch_vmcsfail], 1
    mov  byte [rel hv_linux_load_err], 6
    jmp  .teardown
.vmxon_fail:
    mov  byte [rel hv_launch_vmxonfail], 1
    mov  byte [rel hv_linux_load_err], 6
    jmp  .restore
.guard_refused:
    lea  rax, [rel str_hv_guard_refused]
    mov  [rel hv_val_field], rax
    mov  byte [rel hv_linux_load_err], 6
    mov  byte [rel hv_launch_refused], 1
    push qword [rel hv_launch_rflags]
    popfq
    jmp  .ret
.resume_gprs:
    HV_BOUNDARY_FINAL
    ; RCQ-18 S2: the captured guest GPRs (gsn_enter_state copied them here).
    mov  rbx, [rel hv_linux_gpr + 8]
    mov  rcx, [rel hv_linux_gpr + 16]
    mov  rdx, [rel hv_linux_gpr + 24]
    mov  rsi, [rel hv_linux_gpr + 32]
    mov  rdi, [rel hv_linux_gpr + 40]
    mov  rbp, [rel hv_linux_gpr + 48]
    mov  r8,  [rel hv_linux_gpr + 56]
    mov  r9,  [rel hv_linux_gpr + 64]
    mov  r10, [rel hv_linux_gpr + 72]
    mov  r11, [rel hv_linux_gpr + 80]
    mov  r12, [rel hv_linux_gpr + 88]
    mov  r13, [rel hv_linux_gpr + 96]
    mov  r14, [rel hv_linux_gpr + 104]
    mov  r15, [rel hv_linux_gpr + 112]
    mov  rax, [rel hv_linux_gpr + 0]
    jmp  .launch
.ret:
    mov  qword [rel hv_vmx_boundary_frame], 0
    add  rsp, HVB_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Checked actual VMX entry: event controls and CET state precede acquisition.
; The fresh selector repeats this check after entry and on the landed side.
hv_vmx_boundary_enter:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_GUARD], 0
    jne .armed
    ; A host opening retired this resident frame's lease and guard. Take a
    ; fresh guard generation; VMCS, guest GPRs and the run deadline stay.
    cmp rbx, [rel hv_vmx_boundary_frame]
    jne .refused
    cmp qword [rbx + HVB_LEASE], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_ACTIVE], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_FRONTIER], 0
    jne cpu_boundary_fail_stop
    mov rdi, rbx
    call hv_boundary_arm
    test eax, eax
    jnz .refused
.armed:
    mov rdi, rbx
    call hv_vmx_boundary_owner_check
    cmp eax, 1
    jne .refused
    mov rdi, rbx
    call hv_boundary_intel_acquire
    test eax, eax
    jnz .out
    mov rdi, rbx
    call hv_boundary_enter
.out:
    pop rbx
    ret
.refused:
    mov eax, 1
    jmp .out

; Shared dispatcher/scheduler calls on both vendors. Only a real resident
; VMX frame owns an Intel token. Drop the closed pair's absence generation
; AND disarm its guard before ordinary host IRQ service or scheduling, as
; SVM does: host work may take expected, recoverable faults (pmod_init's
; guard-page negative), which an armed guard turns into BOUNDSTOP (Lenovo
; 0.0.243). Re-arm and reacquire at the next entry. Repeated openings are
; harmless; a failed release keeps lease and guard and never returns.
hv_vmx_host_release:
    push rbx
    mov rbx, [rel hv_vmx_boundary_frame]
    test rbx, rbx
    jz .done
    cmp qword [rbx + HVB_FRONTIER], 0
    jne cpu_boundary_fail_stop
    mov rdi, rbx
    call hv_boundary_finish
.done:
    pop rbx
    ret

; Guest XSETBV executes in host context. Preserve XCR0 and make OSXSAVE part of
; the host CR4 (VMX: HOST_CR4), matching the proven Classic sequence. Shared by
; both enter paths. Clobbers RAX, RBX, RCX, RDX.
hv_linux_host_xsave:
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    bt   ecx, 26
    jnc  .no_xsave
    mov  rax, cr4
    or   rax, 1 << 18
    mov  cr4, rax
    mov  [rel hv_launch_hcr4], rax
    xor  ecx, ecx
    xgetbv
    mov  [rel hv_linux_saved_xcr0], eax
    mov  [rel hv_linux_saved_xcr0 + 4], edx
    mov  byte [rel hv_linux_xcr0_saved], 1
    call hv_linux_xcr0_init                  ; V4: initial guest state is bounded too (both vendors)
.no_xsave:
    ret

; The run deadline from the live TSC calibration (kHz == ticks/ms). Shared by
; both enter paths. -> RAX = the run's start TSC. Clobbers RCX, RDX.
hv_linux_arm_deadline:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_run_start_tsc], rax
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .deadline_rate
    mov  rcx, 3000000                       ; bounded degrade if calibration failed
.deadline_rate:
    cmp  byte [rel cdp_fixture_mode], 1
    je   .control_deadline
    cmp  byte [rel gws_fixture_mode], 1
    jne  .ordinary_deadline
.control_deadline:
    ; This tiny producer must stop before the diagnostic's collection timeout.
    imul rcx, rcx, GWS_RUN_MS
    jmp  .deadline_ready
.ordinary_deadline:
    imul rcx, rcx, HV_LINUX_RUN_MS
.deadline_ready:
    add  rcx, rax
    mov  [rel hv_linux_deadline], rcx
    ret

; Save/restore host MSRs that the minimal guest is allowed to mutate.
hv_linux_save_host_msrs:
    mov  ecx, 0xC0000080
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_saved_efer], rax
    mov  ecx, 0xC0000081
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_saved_star], rax
    mov  ecx, 0xC0000082
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_saved_lstar], rax
    mov  ecx, 0xC0000083
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_saved_cstar], rax
    mov  ecx, 0xC0000084
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_saved_fmask], rax
    mov  ecx, 0xC0000102
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_saved_kgs], rax
    ret

hv_linux_restore_host:
    sub  rsp, 8
    call hv_linux_restore_host_quiet
    add  rsp, 8
    push qword [rel hv_launch_rflags]
    popfq
    ret

; Boundary callers must keep IF0 until their exact guard has been disarmed.
hv_linux_restore_host_quiet:
    sub  rsp, 8
    cmp  byte [rel hv_linux_xcr0_saved], 1
    jne  .msrs
    mov  eax, [rel hv_linux_saved_xcr0]
    mov  edx, [rel hv_linux_saved_xcr0 + 4]
    xor  ecx, ecx
    xsetbv
.msrs:
    mov  rax, [rel hv_linux_saved_efer]
    call hv_linux_wrmsr_efer
    mov  rax, [rel hv_linux_saved_star]
    mov  ecx, 0xC0000081
    call hv_linux_wrmsr_rax
    mov  rax, [rel hv_linux_saved_lstar]
    mov  ecx, 0xC0000082
    call hv_linux_wrmsr_rax
    mov  rax, [rel hv_linux_saved_cstar]
    mov  ecx, 0xC0000083
    call hv_linux_wrmsr_rax
    mov  rax, [rel hv_linux_saved_fmask]
    mov  ecx, 0xC0000084
    call hv_linux_wrmsr_rax
    mov  rax, [rel hv_linux_saved_kgs]
    mov  ecx, 0xC0000102
    call hv_linux_wrmsr_rax
    mov  rax, [rel hv_launch_cr0]
    mov  cr0, rax
    mov  rax, [rel hv_launch_cr4]
    mov  cr4, rax
    add  rsp, 8
    ret
hv_linux_wrmsr_efer:
    mov  ecx, 0xC0000080
hv_linux_wrmsr_rax:
    mov  rdx, rax
    shr  rdx, 32
    wrmsr
    ret

; Linux VMCS execution controls, ported from Classic. External interrupts exit
; to the host, EPT is mandatory, and the preemption timer bounds every slice.
hv_linux_write_controls:
    mov  edi, 0x481
    mov  esi, 0x49                           ; ext-int + NMI + preemption timer
    call hv_adjust_ctls
    mov  ecx, eax
    and  ecx, 0x49                           ; IRQ + NMI isolation + timer mandatory
    cmp  ecx, 0x49
    jne  .bad
    mov  edi, VMXF_PIN_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_PIN_CTLS
    vmread rax, rdi
    jc   .bad
    jz   .bad
    and  eax, 0x49
    cmp  eax, 0x49
    jne  .bad
    call hv_linux_reset_timer
    mov  ecx, 0x480
    rdmsr
    mov  edi, 0x482
    bt   edx, 23                             ; IA32_VMX_BASIC[55] => TRUE controls
    jnc  .proc_msr
    mov  edi, 0x48E
.proc_msr:
    mov  esi, 0x81000080                    ; HLT + unconditional I/O + secondary
    call hv_adjust_ctls
    test eax, 0x80000000
    jz   .bad
    test eax, 0x01000000
    jz   .bad
    mov  edi, VMXF_PROC_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, 0x48B
    mov  esi, 0x100A                        ; EPT + RDTSCP + INVPCID
    call hv_adjust_ctls
    test eax, 2
    jz   .bad
    mov  edi, VMXF_PROC_CTLS2
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_EPTP
    mov  rsi, [rel hv_linux_eptp]
    call hv_w
    mov  edi, 0x483
    ; Retain unspent time on every VM exit. Without this bit and with a
    ; reload on every I/O exit, an I/O-heavy guest can postpone host service
    ; indefinitely. Unsupported save-timer capability refuses guest launch.
    mov  esi, 0x400200                      ; save timer + 64-bit host; host IRQ pending
    call hv_adjust_ctls
    test eax, 0x8000                         ; mandatory ACK-on-exit cannot serve host IDT
    jnz  .bad
    test eax, 0x400000
    jz   .bad
    mov  edi, VMXF_EXIT_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_EXIT_CTLS
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test eax, 0x8000                         ; mandatory ACK-on-exit cannot serve host IDT
    jnz  .bad
    test eax, 0x400000
    jz   .bad
    mov  edi, 0x484
    mov  esi, 0x200                         ; IA-32e guest
    call hv_adjust_ctls
    mov  edi, VMXF_ENTRY_CTLS
    mov  esi, eax
    call hv_w
    ; Linux handles normal exceptions. The ordinary bitmap catches only
    ; catastrophic #DF/#MC. Exactly one secondary-RTL diagnostic generation
    ; adds #UD so Task9792 stops before Linux's recursive die cascade.
    call hv_first_ud_bitmap_value
    mov  [rel hv_first_ud_bitmap_requested], eax
    mov  edi, VMXF_EXC_BITMAP
    mov  esi, eax
    call hv_w
    ; Arm only from the VMCS readback. This turns the prior ud_valid=0 result
    ; into a causal receipt: requested and effective bitmaps are independent.
    mov  edi, VMXF_EXC_BITMAP
    vmread rax, rdi
    mov  [rel hv_first_ud_bitmap_readback], eax
    call hv_first_ud_latch_arm
    mov  edi, 0x6000                        ; CR0 guest/host mask
    xor  esi, esi
    call hv_w
    mov  edi, 0x6002                        ; CR4 guest/host mask: host-required VMXE
    mov  esi, HV_CR4_HOST_OWNED              ; and the denied PKE/KL (V5); shadow 0
    call hv_w
    mov  edi, 0x6004
    mov  rsi, [rel hv_launch_hcr0]
    call hv_w
    mov  edi, 0x6006
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_PF_MASK
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_PF_MATCH
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_CR3_TARGETS
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_EXIT_MSR_ST
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_EXIT_MSR_LD
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_ENTRY_MSR_LD
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_ENTRY_INTR
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_LINK_PTR
    mov  rsi, -1
    call hv_w
    mov  edi, VMXF_G_DEBUGCTL
    xor  esi, esi
    call hv_w
    ret
.bad:
    inc  dword [rel hv_vmwrite_fails]
    ret

; Reload a roughly 1 ms VMX preemption timer from live TSC calibration.
; Ordinary exits retain the unexpired CPU slice (Task1088).
hv_linux_reset_timer:
    mov  ecx, 0x485
    rdmsr
    and  eax, 0x1F
    mov  ecx, eax
    mov  rax, [rel tsc_khz]
    test rax, rax
    jnz  .rate
    mov  rax, 3000000
.rate:
    shr  rax, cl
    test eax, eax
    jnz  .write
    mov  eax, 1
.write:
    mov  edi, VMXF_PREEMPT_TIMER
    mov  esi, eax
    call hv_w
    ret

; Numeric constant table avoids baked runtime pointers; descriptor bases and
; host control registers are populated from live state below.
hv_linux_write_state:
    push rbx
    lea  rbx, [rel hv_linux_vmcs_const_table]
.const:
    mov  rdi, [rbx]
    cmp  rdi, -1
    je   .dynamic
    mov  rsi, [rbx + 8]
    call hv_w
    add  rbx, 16
    jmp  .const
.dynamic:
    mov  edi, VMXF_H_CR0
    mov  rsi, [rel hv_launch_hcr0]
    call hv_w
    mov  edi, VMXF_H_CR3
    mov  rsi, cr3
    mov  [rel hv_launch_hcr3], rsi
    call hv_w
    mov  edi, VMXF_H_CR4
    mov  rsi, [rel hv_launch_hcr4]
    call hv_w
    sgdt [rel hv_dtr_buf]
    mov  rsi, [rel hv_dtr_buf + 2]
    mov  edi, VMXF_H_GDTR_BASE
    call hv_w
    sidt [rel hv_dtr_buf]
    mov  rsi, [rel hv_dtr_buf + 2]
    mov  edi, VMXF_H_IDTR_BASE
    call hv_w
    mov  edi, VMXF_H_TR_BASE
    lea  rsi, [rel tss_struct]
    call hv_w
    mov  edi, VMXF_G_CR0
    mov  rsi, [rel hv_launch_hcr0]
    call hv_w
    mov  edi, VMXF_G_CR4
    mov  rsi, [rel hv_launch_hcr4]
    and  rsi, ~HV_CR4_GUEST_DENIED           ; V5: coherent with the 0 read shadow
    call hv_w
    pop  rbx
    ret

; hv_vmx_exit_dispatch — the Intel VM-exit decoder behind the vendor vtable.
;   RAX=1 only for a bounded HLT exit that is safe to resume; otherwise 0.
hv_vmx_exit_dispatch:
    cmp  byte [rel hv_launch_mode], 1
    je   hv_linux_exit_dispatch
    mov  edi, VMXF_EXIT_REASON
    vmread rax, rdi
    and  eax, 0xFFFF                         ; basic exit reason (low 16 bits)
    mov  [rel hv_exit_reason], eax
    cmp  eax, 12                             ; 12 = HLT
    jne  .stop                               ; non-HLT exit: do NOT resume
    inc  dword [rel hv_hlt_exits]
    inc  qword [rel hv_guestcpu_halt_wakes]
    mov  eax, [rel hv_hlt_exits]
    cmp  eax, HV_LAUNCH_HLT_TARGET
    jae  .stop
    ; --- E3: advance guest RIP past HLT AND clear the STI interrupt-shadow so a
    ;     resumed guest (and R3's IRQ0 injection) is not refused every HLT. ---
    call hv_skip_instr
    mov  eax, 1
    ret
.stop:
    xor  eax, eax
    ret

; Minimal Linux-facing decoder, ported from the proven Classic appliance
; runner. EAX=1 resumes; zero tears VMX down and restores host state.
; R4 virtio-mmio console. This is the Classic live-device shape with the net
; payload removed: version-2 transport, DeviceID 3, queues 0=input/RX and
; 1=output/TX. The register page is guest-readable but EPT write-trapped.
hv_vcon_state_zero:
    HV_POWER_WORK hv_vcon_state_zero, 0, hv_guest_power_admit
    call hv_terminal_reset
    inc  qword [rel hv_vcon_epoch]          ; reset invalidates in-flight snapshots
    mov  dword [rel hv_vcon_feat_bad], 0
    xor  eax, eax
    mov  [rel hv_vcon_qsel], eax
    mov  [rel hv_vcon_dfsel], eax
    mov  [rel hv_vcon_drvfsel], eax
    mov  [rel hv_vcon_drvfeat], eax
    mov  [rel hv_vcon_drvfeat + 4], eax
    mov  [rel hv_vcon_status], eax
    mov  [rel hv_vcon_isr], eax
    mov  [rel hv_vcon_q_num], eax
    mov  [rel hv_vcon_q_num + 4], eax
    mov  [rel hv_vcon_wr_ct], eax
    mov  [rel hv_vcon_badop], eax
    ; In-flight MMIO length belongs to the exit handler, not device state.
    mov  qword [rel hv_vcon_q_desc], 0
    mov  qword [rel hv_vcon_q_desc + 8], 0
    mov  qword [rel hv_vcon_q_avail], 0
    mov  qword [rel hv_vcon_q_avail + 8], 0
    mov  qword [rel hv_vcon_q_used], 0
    mov  qword [rel hv_vcon_q_used + 8], 0
    mov  word [rel hv_vcon_q_lastav], 0
    mov  word [rel hv_vcon_q_lastav + 2], 0
    mov  word [rel hv_vcon_q_usedidx], 0
    mov  word [rel hv_vcon_q_usedidx + 2], 0
    mov  [rel hv_vcon_q_ready], al
    mov  [rel hv_vcon_q_ready + 1], al
    mov  [rel hv_vcon_ready], al
    mov  [rel hv_vcon_irq_pend], al
    mov  [rel hv_vcon_irq_inj], al
    call hv_vcon_capture_reset
    ret

hv_vcon_reset:
    HV_POWER_WORK hv_vcon_reset, 0, hv_guest_power_admit
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .done
    lea  rdx, [rdx + HV_VCON_PAGE]
    mov  dword [rdx + 0x000], 0x74726976  ; MagicValue "virt"
    mov  dword [rdx + 0x004], 2           ; modern transport
    mov  dword [rdx + 0x008], 3           ; virtio console
    mov  dword [rdx + 0x00C], 0x536F6150  ; vendor "PaOS"
    mov  dword [rdx + 0x010], HV_VCON_INDIRECT | 1 ; INDIRECT + CONSOLE_F_SIZE
    mov  dword [rdx + 0x034], HV_VCON_QMAX
    mov  dword [rdx + 0x044], 0
    mov  dword [rdx + 0x060], 0
    mov  dword [rdx + 0x070], 0
    mov  dword [rdx + 0x0FC], 0
    call hv_vcon_state_zero
.done:
    ret

; RDI=guest physical address, ESI=len -> RAX=host VA or zero.
hv_linux_gpa2hva:
    cmp  qword [rel hv_linux_ram], 0         ; RC-speed-reserve: no span outside a START
    je   .bad
    push r11
    push r8
    push r9
    mov  r8, [rel hv_linux_ram]
    mov  r9, [rel hv_linux_ram_bytes]
    mov  rax, rdi
    mov  ecx, esi
    call .offset
    jc   .range_bad
    add  rax, r8
    jc   .range_bad
    pop  r9
    pop  r8
    pop  r11
    ret
.range_bad:
    pop  r9
    pop  r8
    pop  r11
    jmp  .bad
.bad:
    xor  eax, eax
    ret

; RAX=GPA, RCX=extent, R9=RAM amount -> RAX=compact HPA offset, CF refusal.
; Low3GiB ends before the device hole; high RAM starts at4GiB. No extent may
; bridge the hole, wrap, or exceed the actual resident subset. R11 scratch.
.offset:
    mov  r11d, 0xC0000000
    cmp  rax, r11
    jb   .offset_low
    mov  r11, 0x100000000
    cmp  rax, r11
    jb   .offset_bad
    sub  rax, 0x40000000
    jmp  .offset_end
.offset_low:
    mov  r11, rax
    add  r11, rcx
    jc   .offset_bad
    push rax
    mov  eax, 0xC0000000
    cmp  r11, rax
    pop  rax
    ja   .offset_bad
.offset_end:
    mov  r11, rax
    add  r11, rcx
    jc   .offset_bad
    cmp  r11, r9
    ja   .offset_bad
    clc
    ret
.offset_bad:
    stc
    ret

; RDI=guest virtual address -> RAX=host VA through the live guest page tables.
; The core is the proven Classic walk made fixture-callable. RSI=CR3 GPA,
; R8=RAM HVA, R9=RAM bytes. Every raw level and exact leaf offset is retained
; before any content claim is made.
hv_linux_gva2hva:
    mov  r10, rdi
    call hv_guest_cr3
    mov  rsi, rax
    mov  rdi, r10
    mov  r8, [rel hv_linux_ram]
    mov  r9, [rel hv_linux_ram_bytes]
    jmp  hv_linux_gva_walk_core

hv_linux_gva_walk_core:
    push rbx
    push r12
    mov  r12, rdi
    mov  byte [rel hv_gva_walk_valid], 0
    mov  byte [rel hv_gva_walk_fail_level], 4
    mov  qword [rel hv_gva_walk_pml4e], 0
    mov  qword [rel hv_gva_walk_pdpte], 0
    mov  qword [rel hv_gva_walk_pde], 0
    mov  qword [rel hv_gva_walk_pte], 0
    mov  qword [rel hv_gva_walk_page_size], 0
    mov  qword [rel hv_gva_walk_gpa], 0
    mov  qword [rel hv_gva_walk_offset], 0
    test r8, r8
    jz   .bad
    test r9, r9
    jz   .bad
    mov  rax, r12
    shl  rax, 16
    sar  rax, 16
    cmp  rax, r12                         ; reject noncanonical 48-bit GVAs
    jne  .bad
    mov  rax, 0x000FFFFFFFFFF000
    and  rsi, rax
    mov  rax, rsi
    mov  ecx, 4096
    call .offset
    jc   .bad
    lea  rbx, [r8 + rax]
    mov  rcx, r12
    shr  rcx, 39
    and  ecx, 511
    mov  rdx, [rbx + rcx*8]
    mov  [rel hv_gva_walk_pml4e], rdx
    test dl, 1
    jz   .bad
    test dl, 0x80                         ; PS is reserved at PML4 level
    jnz  .bad
    mov  rax, 0x000FFFFFFFFFF000
    and  rdx, rax
    mov  rax, rdx
    mov  ecx, 4096
    call .offset
    jc   .bad

    mov  byte [rel hv_gva_walk_fail_level], 3
    lea  rbx, [r8 + rax]
    mov  rcx, r12
    shr  rcx, 30
    and  ecx, 511
    mov  rdx, [rbx + rcx*8]
    mov  [rel hv_gva_walk_pdpte], rdx
    test dl, 1
    jz   .bad
    test dl, 0x80
    jz   .l2
    mov  rax, 0x000FFFFFC0000000
    and  rdx, rax
    mov  rax, r12
    and  rax, 0x3FFFFFFF
    mov  [rel hv_gva_walk_offset], rax
    or   rdx, rax
    mov  qword [rel hv_gva_walk_page_size], 0x40000000
    jmp  .final

.l2:
    mov  rax, 0x000FFFFFFFFFF000
    and  rdx, rax
    mov  rax, rdx
    mov  ecx, 4096
    call .offset
    jc   .bad
    mov  byte [rel hv_gva_walk_fail_level], 2
    lea  rbx, [r8 + rax]
    mov  rcx, r12
    shr  rcx, 21
    and  ecx, 511
    mov  rdx, [rbx + rcx*8]
    mov  [rel hv_gva_walk_pde], rdx
    test dl, 1
    jz   .bad
    test dl, 0x80
    jz   .l1
    mov  rax, 0x000FFFFFFFE00000
    and  rdx, rax
    mov  rax, r12
    and  rax, 0x1FFFFF
    mov  [rel hv_gva_walk_offset], rax
    or   rdx, rax
    mov  qword [rel hv_gva_walk_page_size], 0x200000
    jmp  .final

.l1:
    mov  rax, 0x000FFFFFFFFFF000
    and  rdx, rax
    mov  rax, rdx
    mov  ecx, 4096
    call .offset
    jc   .bad
    mov  byte [rel hv_gva_walk_fail_level], 1
    lea  rbx, [r8 + rax]
    mov  rcx, r12
    shr  rcx, 12
    and  ecx, 511
    mov  rdx, [rbx + rcx*8]
    mov  [rel hv_gva_walk_pte], rdx
    test dl, 1
    jz   .bad
    mov  rax, 0x000FFFFFFFFFF000
    and  rdx, rax
    mov  rax, r12
    and  rax, 0xFFF
    mov  [rel hv_gva_walk_offset], rax
    or   rdx, rax
    mov  qword [rel hv_gva_walk_page_size], 0x1000

.final:
    mov  rax, rdx
    mov  ecx, 1
    call .offset
    jc   .bad
    mov  [rel hv_gva_walk_gpa], rdx
    add  rax, r8
    jc   .bad
    mov  byte [rel hv_gva_walk_valid], 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RAX=GPA, RCX=extent, R9=RAM amount -> RAX=compact HPA offset, CF refusal.
; Low3GiB ends before the device hole; high RAM starts at4GiB. No extent may
; bridge the hole, wrap, or exceed the actual resident subset. R11 scratch.
.offset:
    mov  r11d, 0xC0000000
    cmp  rax, r11
    jb   .offset_low
    mov  r11, 0x100000000
    cmp  rax, r11
    jb   .offset_bad
    sub  rax, 0x40000000
    jmp  .offset_end
.offset_low:
    mov  r11, rax
    add  r11, rcx
    jc   .offset_bad
    push rax
    mov  eax, 0xC0000000
    cmp  r11, rax
    pop  rax
    ja   .offset_bad
.offset_end:
    mov  r11, rax
    add  r11, rcx
    jc   .offset_bad
    cmp  r11, r9
    ja   .offset_bad
    clc
    ret
.offset_bad:
    stc
    ret

; Copy ECX bytes from a GVA, re-walking every byte so a page boundary is
; explicit and bounded. RDX=destination; other inputs match the core walker.
hv_linux_gva_copy_core:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx
    mov  rbx, r8
    mov  rbp, r9
.copy:
    test r15d, r15d
    jz   .copy_ok
    mov  rdi, r12
    mov  rsi, r13
    mov  r8, rbx
    mov  r9, rbp
    call hv_linux_gva_walk_core
    test rax, rax
    jz   .copy_bad
    mov  dl, [rax]
    mov  [r14], dl
    inc  r12
    inc  r14
    dec  r15d
    jmp  .copy
.copy_ok:
    mov  eax, 1
    jmp  .copy_out
.copy_bad:
    xor  eax, eax
.copy_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Return the exact exception bitmap for this generation. The ordinary value
; is byte-for-byte unchanged; bit 6 exists only while the secondary RTL is
; guest-owned and the requested diagnostic generation is being consumed.
hv_first_ud_bitmap_value:
    mov  eax, 0x40100
    cmp  byte [rel vtd_owner_guest], 1
    jne  .out
    mov  ecx, [rel vtd_guest_start_gen]
    test ecx, ecx
    jz   .out
    cmp  ecx, [rel vtd_first_ud_diag_gen]
    jne  .out
    cmp  ecx, [rel hv_linux_start_consumed]
    jne  .out
    or   eax, 1 << HV_R0_CLASS_UD
.out:
    ret

; EAX is the VMCS bitmap readback. Publish the immutable generation only when
; hardware reports the exact diagnostic bitmap.
hv_first_ud_latch_arm:
    cmp  eax, 0x40140
    sete byte [rel hv_first_ud_diag_active]
    jne  .out
    mov  ecx, [rel hv_linux_start_consumed]
    mov  [rel hv_first_ud_gen], rcx
.out:
    ret

; EDI=raw VM-exit interruption information. Accept only valid hardware
; exception vector 6, with no error-code-valid or reserved bits.
hv_first_ud_info_is_exact:
    xor  eax, eax
    cmp  edi, HV_GUEST_UD_INFO
    sete al
    ret

; RDI points to a reservation large enough that aligning it upward leaves four
; pages. This fixture drives the real walker core; receipt globals are never
; seeded to earn the marker.
hv_first_ud_fixture_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel hv_first_ud_fixture_ok], 0
    mov  dword [rel hv_first_ud_fixture_stage], 1
    movzx ebx, byte [rel vtd_owner_guest]
    mov  r13d, [rel vtd_guest_start_gen]
    mov  r14d, [rel hv_linux_start_consumed]
    mov  eax, [rel vtd_first_ud_diag_gen]
    mov  [rel hv_first_ud_fixture_diag_save], eax
    push qword [rel hv_first_ud_gen]
    movzx eax, byte [rel hv_first_ud_diag_active]
    push rax
    lea  r15, [rdi + 4095]
    and  r15, -4096

    ; Valid 4 KiB translation plus exact content and offset.
    call .clear_pages
    call .build_4k
    mov  byte [r15 + 0x123], 0x5A
    mov  byte [r15 + 0x124], 0xA5
    mov  r12, 0x0000008040200123
    mov  rdi, r12
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    lea  rdx, [r15 + 0x123]
    cmp  rax, rdx
    jne  .restore
    cmp  byte [rax], 0x5A
    jne  .restore
    cmp  qword [rel hv_gva_walk_page_size], 0x1000
    jne  .restore
    cmp  qword [rel hv_gva_walk_gpa], 0x123
    jne  .restore
    cmp  qword [rel hv_gva_walk_offset], 0x123
    jne  .restore
    cmp  qword [rel hv_gva_walk_pml4e], 0x1003
    jne  .restore
    cmp  qword [rel hv_gva_walk_pdpte], 0x2003
    jne  .restore
    cmp  qword [rel hv_gva_walk_pde], 0x3003
    jne  .restore
    cmp  qword [rel hv_gva_walk_pte], 0x3
    jne  .restore

    ; Wrong-offset content must resolve independently.
    mov  dword [rel hv_first_ud_fixture_stage], 2
    lea  rdi, [r12 + 1]
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    lea  rdx, [r15 + 0x124]
    cmp  rax, rdx
    jne  .restore
    cmp  byte [rax], 0xA5
    jne  .restore
    cmp  qword [rel hv_gva_walk_offset], 0x124
    jne  .restore

    ; Valid 2 MiB leaf.
    mov  dword [rel hv_first_ud_fixture_stage], 3
    mov  qword [r15 + 0x2000 + 8], 0x83
    mov  rdi, r12
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    lea  rdx, [r15 + 0x123]
    cmp  rax, rdx
    jne  .restore
    cmp  qword [rel hv_gva_walk_page_size], 0x200000
    jne  .restore
    cmp  qword [rel hv_gva_walk_pte], 0
    jne  .restore

    ; Valid 1 GiB leaf.
    mov  dword [rel hv_first_ud_fixture_stage], 4
    mov  qword [r15 + 0x1000 + 8], 0x83
    mov  rdi, 0x0000008040000123
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    lea  rdx, [r15 + 0x123]
    cmp  rax, rdx
    jne  .restore
    cmp  qword [rel hv_gva_walk_page_size], 0x40000000
    jne  .restore
    cmp  qword [rel hv_gva_walk_pde], 0
    jne  .restore

    ; Non-present and out-of-range table pointers must fail closed.
    mov  dword [rel hv_first_ud_fixture_stage], 5
    mov  qword [r15 + 8], 0
    mov  rdi, r12
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    test rax, rax
    jnz  .restore
    cmp  byte [rel hv_gva_walk_valid], 0
    jne  .restore

    mov  dword [rel hv_first_ud_fixture_stage], 6
    mov  qword [r15 + 8], 0x4003
    mov  rdi, r12
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    test rax, rax
    jnz  .restore

    ; Noncanonical GVA must fail before dereference.
    mov  dword [rel hv_first_ud_fixture_stage], 7
    mov  rdi, 0x0001000000000000
    xor  esi, esi
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_walk_core
    test rax, rax
    jnz  .restore

    ; A 16-byte window crossing two 4 KiB leaves must retain exact bytes.
    mov  dword [rel hv_first_ud_fixture_stage], 8
    call .clear_pages
    call .build_4k
    mov  qword [r15 + 0x3000], 0x3
    mov  qword [r15 + 0x3008], 0x1003
    mov  rax, 0x0807060504030201
    mov  [r15 + 0x0FF8], rax
    mov  rax, 0x100F0E0D0C0B0A09
    mov  [r15 + 0x1000], rax
    mov  rdi, 0x0000008040200FF8
    xor  esi, esi
    lea  rdx, [rel hv_first_ud_fixture_copy]
    mov  ecx, 16
    mov  r8, r15
    mov  r9, 0x4000
    call hv_linux_gva_copy_core
    test eax, eax
    jz   .restore
    mov  rax, 0x0807060504030201
    cmp  [rel hv_first_ud_fixture_copy], rax
    jne  .restore
    mov  rax, 0x100F0E0D0C0B0A09
    cmp  [rel hv_first_ud_fixture_copy + 8], rax
    jne  .restore

    ; Exact VM-exit interruption-info classification.
    mov  dword [rel hv_first_ud_fixture_stage], 9
    mov  edi, HV_GUEST_UD_INFO
    call hv_first_ud_info_is_exact
    cmp  eax, 1
    jne  .restore
    mov  edi, 0x00000306                 ; invalid bit clear
    call hv_first_ud_info_is_exact
    test eax, eax
    jnz  .restore
    mov  edi, 0x80000606                 ; software exception, not hardware
    call hv_first_ud_info_is_exact
    test eax, eax
    jnz  .restore
    mov  edi, 0x80000B08                 ; valid #DF is not first #UD
    call hv_first_ud_info_is_exact
    test eax, eax
    jnz  .restore

    ; Bitmap is ordinary unless owner, requested, and consumed generations
    ; all match. Arming additionally requires the exact effective readback.
    mov  dword [rel hv_first_ud_fixture_stage], 10
    mov  byte [rel vtd_owner_guest], 0
    mov  dword [rel vtd_guest_start_gen], 77
    mov  dword [rel hv_linux_start_consumed], 77
    mov  dword [rel vtd_first_ud_diag_gen], 0
    call hv_first_ud_bitmap_value
    call hv_first_ud_latch_arm
    cmp  eax, 0x40100
    jne  .restore
    cmp  byte [rel hv_first_ud_diag_active], 0
    jne  .restore
    mov  byte [rel vtd_owner_guest], 1
    mov  dword [rel hv_linux_start_consumed], 76
    mov  dword [rel vtd_first_ud_diag_gen], 77
    call hv_first_ud_bitmap_value
    call hv_first_ud_latch_arm
    cmp  eax, 0x40100
    jne  .restore
    cmp  byte [rel hv_first_ud_diag_active], 0
    jne  .restore

    mov  dword [rel hv_first_ud_fixture_stage], 11
    mov  qword [rel hv_first_ud_gen], 0
    mov  dword [rel hv_linux_start_consumed], 77
    call hv_first_ud_bitmap_value
    cmp  eax, 0x40140
    jne  .restore
    call hv_first_ud_latch_arm
    cmp  byte [rel hv_first_ud_diag_active], 1
    jne  .restore
    cmp  qword [rel hv_first_ud_gen], 77
    jne  .restore
    mov  byte [rel hv_first_ud_fixture_ok], 1
    jmp  .restore

.clear_pages:
    push rdi
    push rcx
    xor  eax, eax
    mov  rdi, r15
    mov  ecx, 0x4000 / 8
    cld
    rep  stosq
    pop  rcx
    pop  rdi
    ret
.build_4k:
    mov  qword [r15 + 8], 0x1003
    mov  qword [r15 + 0x1000 + 8], 0x2003
    mov  qword [r15 + 0x2000 + 8], 0x3003
    mov  qword [r15 + 0x3000], 0x3
    ret
.restore:
    pop  rax
    mov  [rel hv_first_ud_diag_active], al
    pop  rax
    mov  [rel hv_first_ud_gen], rax
    mov  [rel vtd_owner_guest], bl
    mov  [rel vtd_guest_start_gen], r13d
    mov  [rel hv_linux_start_consumed], r14d
    mov  eax, [rel hv_first_ud_fixture_diag_save]
    mov  [rel vtd_first_ud_diag_gen], eax
    movzx eax, byte [rel hv_first_ud_fixture_ok]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Decode Linux writel's [REX] 89 /r store at guest RIP.
; EAX=value, ECX=decoded length, R8B=1 on success.
hv_vcon_decode_store:
    push rbx
    push r12
    mov  edi, VMXF_G_RIP
    call hv_guest_read
    mov  r12, rax
    xor  ebx, ebx
.fetch:
    cmp  ebx, 10
    jae  .fetched
    lea  rdi, [r12 + rbx]
    call hv_linux_gva2hva
    test rax, rax
    jz   .refuse_empty
    mov  al, [rax]
    lea  rcx, [rel hv_vcon_ibuf]
    mov  [rcx + rbx], al
    inc  ebx
    jmp  .fetch
.fetched:
    lea  rbx, [rel hv_vcon_ibuf]
    xor  ecx, ecx
    xor  r9d, r9d
    xor  r12d, r12d                       ; RCQ-23: bit 8 = REX seen, low byte = width
    mov  al, [rbx]
    mov  dl, al
    and  dl, 0xF0
    cmp  dl, 0x40
    jne  .opcode
    or   r12d, 0x100
    shr  al, 2
    and  eax, 1
    shl  eax, 3
    mov  r9d, eax
    inc  ecx
.opcode:
    mov  r12b, 4
    cmp  byte [rbx + rcx], 0x89
    je   .opcode_ok
    mov  r12b, 1                          ; 88 /r: the byte store virtio-input config uses
    cmp  byte [rbx + rcx], 0x88
    jne  .refuse
.opcode_ok:
    inc  ecx
    movzx eax, byte [rbx + rcx]
    inc  ecx
    mov  edx, eax
    shr  edx, 6
    cmp  edx, 3
    je   .refuse
    mov  r10d, eax
    shr  r10d, 3
    and  r10d, 7
    or   r10d, r9d
    mov  r11d, eax
    and  r11d, 7
    cmp  r11d, 4
    jne  .no_sib
    movzx r8d, byte [rbx + rcx]           ; SIB
    inc  ecx
    ; SEC-D2: mod=00 with SIB.base=101 has no base register and a disp32
    ; (e.g. 89 04 25 <disp32>, 7 bytes); the decoder used to return 3.
    test edx, edx
    jnz  .no_sib
    and  r8d, 7
    cmp  r8d, 5
    jne  .no_sib
    add  ecx, 4
.no_sib:
    cmp  edx, 1
    jne  .mod2
    inc  ecx
    jmp  .len_done
.mod2:
    cmp  edx, 2
    jne  .mod0
    add  ecx, 4
    jmp  .len_done
.mod0:
    test edx, edx
    jnz  .len_done
    cmp  r11d, 5
    jne  .len_done
    add  ecx, 4
.len_done:
    cmp  r12b, 1
    jne  .reg_full
    test r12d, 0x100
    jnz  .reg_full
    cmp  r10d, 4                          ; without REX, byte regs 4..7 are AH, CH, DH, BH
    jb   .reg_full
    lea  rdx, [rel hv_linux_cr_gpr_map]
    movzx edx, byte [rdx + r10 - 4]
    lea  rax, [rel hv_linux_gpr]
    movzx eax, byte [rax + rdx + 1]
    jmp  .reg_done
.reg_full:
    lea  rdx, [rel hv_linux_cr_gpr_map]
    movzx edx, byte [rdx + r10]
    cmp  edx, 0xFF
    je   .refuse
    lea  rax, [rel hv_linux_gpr]
    mov  eax, [rax + rdx]
    cmp  r12b, 1
    jne  .reg_done
    movzx eax, al
.reg_done:
    movzx r9d, r12b                       ; decoded store width (1 or 4)
    mov  r8d, 1
    jmp  .done
.refuse:
    movzx eax, byte [rbx]
    mov  [rel hv_vcon_badop], eax
.refuse_empty:
    xor  r8d, r8d
    xor  ecx, ecx
    xor  eax, eax
    xor  r9d, r9d
.done:
    pop  r12
    pop  rbx
    ret

hv_vcon_raise_irq:
    or   dword [rel hv_vcon_isr], 1
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .done
    mov  eax, [rel hv_vcon_isr]
    mov  [rdx + HV_VCON_PAGE + 0x60], eax
    mov  byte [rel hv_vcon_irq_pend], 1
.done:
    ret

; Readiness is earned anew from accepted modern features and both queues.
; EAX=1 only for supported driver features; an invalid write needs a reset.
hv_vcon_features_ok:
    cmp  dword [rel hv_vcon_feat_bad], 0
    jne  .bad
    cmp  dword [rel hv_vcon_drvfeat + 4], 1 ; VERSION_1 is mandatory
    jne  .bad
    mov  eax, [rel hv_vcon_drvfeat]
    test eax, ~(HV_VCON_INDIRECT | 1)
    jnz  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

hv_vcon_eval_ready:
    sub  rsp, 8
    movzx edx, byte [rel hv_vcon_ready]
    mov  byte [rel hv_vcon_ready], 0
    call hv_vcon_features_ok
    test eax, eax
    jz   .done
    cmp  dword [rel hv_vcon_status], 15
    jne  .done
    cmp  word [rel hv_vcon_q_ready], 0x0101
    jne  .done
    mov  byte [rel hv_vcon_ready], 1
    cmp  edx, 1
    je   .done
    lea  rdi, [rel str_hv_vcon_marker]
    call serial_string
.done:
    add  rsp, 8
    ret

; EDI=MMIO offset, ESI=value.
hv_vcon_write:
    HV_POWER_WORK hv_vcon_write, 0, hv_guest_power_io_admit
    push rbx
    mov  rbx, [rel hv_linux_region]
    lea  rbx, [rbx + HV_VCON_PAGE]
    cmp  edi, 0x014
    je   .dfsel
    cmp  edi, 0x020
    je   .drvfeat
    cmp  edi, 0x024
    je   .drvfsel
    cmp  edi, 0x030
    je   .qsel
    cmp  edi, 0x038
    je   .qnum
    cmp  edi, 0x044
    je   .qready
    cmp  edi, 0x050
    je   .notify
    cmp  edi, 0x064
    je   .intack
    cmp  edi, 0x070
    je   .status
    cmp  edi, 0x080
    je   .desclo
    cmp  edi, 0x084
    je   .deschi
    cmp  edi, 0x090
    je   .avail_lo
    cmp  edi, 0x094
    je   .avail_hi
    cmp  edi, 0x0A0
    je   .used_lo
    cmp  edi, 0x0A4
    je   .used_hi
    jmp  .done
.dfsel:
    mov  [rel hv_vcon_dfsel], esi
    mov  eax, HV_VCON_INDIRECT | 1
    test esi, esi
    jz   .df_store
    xor  eax, eax
    cmp  esi, 1
    jne  .df_store
    mov  eax, 1                             ; VIRTIO_F_VERSION_1, bit 32
.df_store:
    mov  [rbx + 0x10], eax
    jmp  .done
.drvfeat:
    test dword [rel hv_vcon_status], 8
    jnz  .features_bad                    ; accepted negotiation is immutable
    mov  eax, [rel hv_vcon_drvfsel]
    cmp  eax, 1
    ja   .features_bad
    lea  rdx, [rel hv_vcon_drvfeat]
    mov  [rdx + rax*4], esi
    jmp  .done
.drvfsel:
    mov  [rel hv_vcon_drvfsel], esi
    cmp  esi, 1
    ja   .features_bad
    jmp  .done
.features_bad:
    mov  dword [rel hv_vcon_feat_bad], 1
    and  dword [rel hv_vcon_status], ~12
    mov  eax, [rel hv_vcon_status]
    mov  [rbx + 0x70], eax
    mov  byte [rel hv_vcon_ready], 0
    jmp  .done
.qsel:
    mov  [rel hv_vcon_qsel], esi
    cmp  esi, 2
    jae  .qsel_bad
    mov  dword [rbx + 0x34], HV_VCON_QMAX
    lea  rdx, [rel hv_vcon_q_ready]
    movzx eax, byte [rdx + rsi]
    mov  [rbx + 0x44], eax
    jmp  .done
.qsel_bad:
    mov  dword [rbx + 0x34], 0
    mov  dword [rbx + 0x44], 0
    jmp  .done
.qnum:
    mov  eax, [rel hv_vcon_qsel]
    cmp  eax, 2
    jae  .done
    cmp  esi, HV_VCON_QMAX
    jbe  .qnum_ok
    mov  esi, HV_VCON_QMAX
.qnum_ok:
    lea  rdx, [rel hv_vcon_q_num]
    mov  [rdx + rax*4], esi
    jmp  .done
.qready:
    mov  eax, [rel hv_vcon_qsel]
    cmp  eax, 2
    jae  .done
    and  esi, 1
    lea  rdx, [rel hv_vcon_q_ready]
    mov  [rdx + rax], sil
    mov  [rbx + 0x44], esi
    call hv_vcon_eval_ready
    jmp  .done
.notify:
    test esi, esi
    jnz  .notify_tx
    cmp byte [rel cdp_bound], 1
    jne .done
    call cdp_bridge_pump
    jmp .done
.notify_tx:
    cmp  esi, 1
    jne  .done
    call hv_vcon_serve_tx
    jmp  .done
.intack:
    mov  eax, esi
    not  eax
    and  [rel hv_vcon_isr], eax
    mov  eax, [rel hv_vcon_isr]
    mov  [rbx + 0x60], eax
    mov  byte [rel hv_vcon_irq_inj], 0
    test eax, eax
    jnz  .done
    mov  byte [rel hv_vcon_irq_pend], 0
    jmp  .done
.status:
    test esi, esi
    jnz  .status_set
    call hv_vcon_state_zero               ; addresses/features/indices reclaimed
    mov  dword [rbx + 0x10], HV_VCON_INDIRECT | 1
    mov  dword [rbx + 0x60], 0
    mov  dword [rbx + 0x44], 0
    mov  dword [rbx + 0x70], 0
    jmp  .done
.status_set:
    mov  eax, [rel hv_vcon_status]
    and  eax, esi
    cmp  eax, [rel hv_vcon_status]        ; only reset may clear status bits
    jne  .features_bad
    test esi, ~0x8F
    jnz  .features_bad
    test esi, 8
    jz   .without_features
    mov  eax, esi
    and  eax, 3
    cmp  eax, 3
    jne  .features_bad
    call hv_vcon_features_ok
    test eax, eax
    jz   .features_bad
    jmp  .status_store
.without_features:
    test esi, 4
    jnz  .features_bad                    ; DRIVER_OK requires FEATURES_OK
.status_store:
    mov  [rel hv_vcon_status], esi
    mov  [rbx + 0x70], esi
    call hv_vcon_eval_ready
    jmp  .done
.desclo:
    lea  rdx, [rel hv_vcon_q_desc]
    jmp  .addr_lo
.deschi:
    lea  rdx, [rel hv_vcon_q_desc]
    jmp  .addr_hi
.avail_lo:
    lea  rdx, [rel hv_vcon_q_avail]
    jmp  .addr_lo
.avail_hi:
    lea  rdx, [rel hv_vcon_q_avail]
    jmp  .addr_hi
.used_lo:
    lea  rdx, [rel hv_vcon_q_used]
    jmp  .addr_lo
.used_hi:
    lea  rdx, [rel hv_vcon_q_used]
.addr_hi:
    mov  eax, [rel hv_vcon_qsel]
    cmp  eax, 2
    jae  .done
    shl  eax, 3
    add  rdx, rax
    mov  [rdx + 4], esi
    jmp  .done
.addr_lo:
    mov  eax, [rel hv_vcon_qsel]
    cmp  eax, 2
    jae  .done
    shl  eax, 3
    add  rdx, rax
    mov  [rdx], esi
.done:
    pop  rbx
    ret

; Reset the generation-scoped EPT receipt before accepting another Linux run.
hv_linux_ept_detail_reset:
    xor  eax, eax
    mov  [rel hv_ept_exit_gpa], rax
    mov  [rel hv_ept_exit_qual], rax
    mov  [rel hv_ept_exit_rip], rax
    mov  [rel hv_ept_exit_gla], rax
    mov  [rel hv_ept_exit_insn], rax
    mov  [rel hv_ept_exit_ilen], eax
    mov  [rel hv_ept_exit_insn_len], eax
    mov  [rel hv_ept_exit_decode_len], eax
    mov  [rel hv_ept_exit_gen], eax
    mov  [rel hv_ept_exit_access], al
    mov  [rel hv_ept_exit_decode], al
    mov  [rel hv_ept_exit_class], al
    mov  [rel hv_ept_exit_action], al
    mov  [rel hv_ept_exit_bar_match], al
    ret

; Bounded classifier shared by the live reason-48 path and memory fixture.
; RDI=GPA, RSI=EPT exit qualification, EDX=raw VMCS instruction length. The
; raw length may be zero for EPT exits; decoded length remains authoritative.
; EAX=1 only when a known virtio page may proceed to store decode.
hv_linux_ept_classify:
    mov  [rel hv_ept_exit_gpa], rdi
    mov  [rel hv_ept_exit_qual], rsi
    mov  [rel hv_ept_exit_ilen], edx
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel hv_ept_exit_gen], eax
    mov  eax, esi
    and  eax, 7                           ; qualification R/W/X access bits
    mov  [rel hv_ept_exit_access], al
    mov  byte [rel hv_ept_exit_decode], HV_EPT_DECODE_NONE
    mov  dword [rel hv_ept_exit_decode_len], 0
    mov  byte [rel hv_ept_exit_action], HV_EPT_ACTION_STOP
    mov  byte [rel hv_ept_exit_class], HV_EPT_CLASS_FOREIGN_GPA
    mov  byte [rel hv_ept_exit_bar_match], 0
    call vtd_trace_select_for_ept
    mov  [rel hv_ept_exit_bar_match], al
    mov  rdi, [rel hv_ept_exit_gpa]

    mov  rax, rdi
    mov  ecx, HV_VCON_GPA                 ; zero-extend: do not sign-extend imm32
    sub  rax, rcx
    cmp  rax, 0xA000                     ; selected optional pages, same write-only gate
    jae  .non_virtio
    cmp  eax, 0x9000                     ; C10b-1a S7: paos.power only when B1 mapped it;
    jb   .bank                           ; otherwise exactly the base classification
    cmp  byte [rel guestpower_live], 1
    jne  .non_virtio
.bank:
    ; RCQ-18: an omitted device's page is a foreign GPA, never emulated.
    mov  edi, eax
    call vm_profile_page_selected
    test eax, eax
    jz   .stop
    mov  byte [rel hv_ept_exit_class], HV_EPT_CLASS_VIRTIO_ACCESS
    test byte [rel hv_ept_exit_access], 2 ; preserve the proven write-only gate
    jz   .stop
    mov  byte [rel hv_ept_exit_class], HV_EPT_CLASS_VIRTIO_DECODE
    mov  eax, 1
    ret
.non_virtio:
    call vtd_guest_gpa_is_secondary_bar  ; classify current guest-visible BARs
    test eax, eax
    jz   .stop
    mov  byte [rel hv_ept_exit_class], HV_EPT_CLASS_ASSIGNED_BAR
.stop:
    xor  eax, eax
    ret

; EDI=decode succeeded, ESI=decoded length. EAX=resume decision.
; SEC-D2: the raw VM-exit instruction length is advisory only (the SDM leaves
; it undefined for EPT violations, and it may be 0), so the decoded length
; stays authoritative; a nonzero disagreement is counted for the receipt.
hv_linux_ept_note_decode:
    mov  [rel hv_ept_exit_decode_len], esi
    test edi, edi
    jz   .refused
    mov  eax, [rel hv_ept_exit_ilen]
    test eax, eax
    jz   .len_ok
    cmp  eax, esi
    je   .len_ok
    inc  dword [rel hv_ept_ilen_mismatch]
.len_ok:
    mov  byte [rel hv_ept_exit_decode], HV_EPT_DECODE_OK
    mov  byte [rel hv_ept_exit_class], HV_EPT_CLASS_VIRTIO_RESUME
    mov  byte [rel hv_ept_exit_action], HV_EPT_ACTION_RESUME
    mov  eax, 1
    ret
.refused:
    mov  byte [rel hv_ept_exit_decode], HV_EPT_DECODE_REFUSED
    mov  byte [rel hv_ept_exit_class], HV_EPT_CLASS_VIRTIO_DECODE
    mov  byte [rel hv_ept_exit_action], HV_EPT_ACTION_STOP
    xor  eax, eax
    ret

; Snapshot the first terminal EPT instruction before dispatch helpers can
; change VMCS state. The prefix is bounded to one qword.
hv_linux_ept_capture_instruction:
    push rbx
    push r12
    push r13
    xor  eax, eax
    mov  [rel hv_ept_exit_insn], rax
    mov  [rel hv_ept_exit_insn_len], eax
    mov  edi, VMXF_G_RIP
    call hv_guest_read
    mov  r13, rax
    mov  [rel hv_ept_exit_rip], r13
    mov  edi, VMXF_G_LINEAR_ADDR
    call hv_guest_read
    mov  [rel hv_ept_exit_gla], rax
    mov  edi, VMXF_EXIT_ILEN
    call hv_guest_read
    test eax, eax
    jz   .done
    mov  r12d, eax
    cmp  r12d, 8
    jbe  .bounded
    mov  r12d, 8
.bounded:
    xor  ebx, ebx
.fetch:
    cmp  ebx, r12d
    jae  .done
    lea  rdi, [r13 + rbx]
    call hv_linux_gva2hva
    test rax, rax
    jz   .done
    mov  al, [rax]
    lea  rdx, [rel hv_ept_exit_insn]
    mov  [rdx + rbx], al
    inc  ebx
    mov  [rel hv_ept_exit_insn_len], ebx
    jmp  .fetch
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EPT-violation service. EAX=1 resumes; zero stops with exact bounded detail.
hv_linux_virtio_mmio:
    mov  edi, VMXF_G_PHYS_ADDR
    call hv_guest_read
    mov  r12, rax                         ; capture before any later VMREAD
    mov  edi, VMXF_EXIT_QUAL
    call hv_guest_read
    mov  r13, rax
    call hv_linux_ept_capture_instruction
    mov  rdi, r12
    mov  rsi, r13
    call vtd_guest_bar_ept_service          ; fail-closed saved/ledger BAR service
    test eax, eax
    jnz  .bar_resume
    mov  edi, VMXF_EXIT_ILEN
    call hv_guest_read
    mov  edx, eax
    mov  rdi, r12
    mov  rsi, r13
    call hv_linux_ept_classify
    test eax, eax
    jz   .bad
    mov  r15, r12
    mov  ecx, HV_VCON_GPA                 ; same safe zero-extended subtraction
    sub  r15, rcx
    call hv_vcon_decode_store
    mov  r14d, eax                        ; preserve decoded store value
    mov  [rel hv_vcon_ilen], ecx          ; preserve decoder length across note call
    mov  [rel hv_vcon_iwidth], r9d
    movzx edi, r8b
    cmp  r9d, 1
    jne  .width_ok
    cmp  r15d, 0x2000                     ; RCQ-23: byte stores exist only for
    jb   .byte_bad
    cmp  r15d, 0x3000
    jb   .width_ok                        ; bytes only in virtio-input config
.byte_bad:
    xor  edi, edi
.width_ok:
    mov  esi, ecx
    call hv_linux_ept_note_decode
    test eax, eax
    jz   .bad
    mov  edi, r15d
    mov  esi, r14d
    cmp  edi, 0x1000
    jae  .net_write
    call hv_vcon_write
    jmp  .write_done
.net_write:
    cmp  edi, 0x2000
    jae  .input_write
    sub  edi, 0x1000
    call guestnet_mmio_write
    jmp  .write_done
.input_write:
    cmp  edi, 0x3000
    jae  .entropy_write
    sub  edi, 0x2000
    mov  edx, [rel hv_vcon_iwidth]
    call guestinput_mmio_write
    jmp  .write_done
.entropy_write:
    cmp edi,0x4000
    jae .sound_write
    sub  edi, 0x3000
    call guestentropy_mmio_write
    jmp .write_done
.sound_write:
    cmp  edi, 0x5000
    jae  .restore_write
    sub edi,0x4000
    call guestsound_mmio_write
    jmp  .write_done
.restore_write:
    cmp edi,0x6000
    jae .filesystem_write
    sub  edi, 0x5000
    call guestrestore_mmio_write
    jmp .write_done
.filesystem_write:
    cmp edi,0x8000
    jae .wifi_write
    sub edi,0x6000
    call guestfilesystem_mmio_write
    jmp .write_done
.wifi_write:
    cmp edi,0x9000
    jae .power_write
    sub edi,0x8000
    call guestwifi_mmio_write
    jmp .write_done
.power_write:
    sub edi,0x9000
    call guestpower_mmio_write               ; C10b-1a: reached only when B1 selected the page
.write_done:
    mov  edi, VMXF_G_RIP
    call hv_guest_read
    mov  ecx, [rel hv_vcon_ilen]
    add  rax, rcx
    mov  edi, VMXF_G_RIP
    mov  rsi, rax
    call hv_guest_write
    cmp  r15d, 0x1000
    jae  .net_count
    inc  dword [rel hv_vcon_wr_ct]
    jmp  .resume_ok
.net_count:
    cmp  r15d, 0x2000
    jae  .resume_ok                       ; guestinput counts its own writes
    inc  dword [rel guestnet_mmio_writes]
.resume_ok:
    mov  eax, 1
    ret
.bar_resume:
    mov  eax, 1
    ret
.bad:
    mov  byte [rel hv_linux_load_err], 7
    xor  eax, eax
    ret

hv_vcon_capture_reset:
    ; GUESTLINUX RUN has an independent bounded recent-output view. Reset it
    ; at every existing console operation/reset boundary, with START custody.
    mov  dword [rel hv_vcon_run_tail_len], 0
    mov  dword [rel hv_vcon_run_tail_write], 0
    push rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel hv_vcon_run_tail_gen], eax
    pop  rax
    mov  dword [rel hv_vcon_capture_len], 0
    mov  dword [rel hv_vcon_capture_overflow], 0
    mov  byte [rel hv_vcon_capture], 0
    mov  dword [rel hv_panic_match], 0
    ret

; Append the current generation's recent console bytes to the bounded RUN
; reply. No yield occurs in capture or render: guest TX is drained while the
; vCPU is stopped on the cooperative host task. Reading never consumes output.
hv_vcon_run_tail_append:
    push rbx
    push rcx
    push rdx
    push rdi
    mov  edx, [rel hv_linux_start_consumed]
    cmp  edx, [rel hv_linux_start_gen]
    jne  .out
    cmp  edx, [rel hv_vcon_run_tail_gen]
    jne  .out
    mov  ecx, [rel hv_vcon_run_tail_len]
    cmp  ecx, HV_VCON_CAP_MAX - 1
    ja   .out
    mov  edx, [rel hv_vcon_run_tail_write]
    cmp  edx, HV_VCON_CAP_MAX
    jae  .out
    sub  edx, ecx
    and  edx, HV_VCON_CAP_MAX - 1
    lea  rdi, [rel hv_vcon_run_tail]
.byte:
    test ecx, ecx
    jz   .out
    mov  al, [rdi + rdx]
    call hv_out_putc
    inc  edx
    and  edx, HV_VCON_CAP_MAX - 1
    dec  ecx
    jmp  .byte
.out:
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; Ordinary console capture is prefix-only. Task 1012 may temporarily retain a
; rolling tail only after its proof command is ready to inject; DIAG keeps its
; separate generation-bound latch and semantics.
hv_vcon_proof_roll_begin:
    mov  byte [rel hv_vcon_proof_roll_active], 1
    call hv_vcon_capture_reset
    ret

hv_vcon_proof_roll_finish:
    mov  byte [rel hv_vcon_proof_roll_active], 0
    ret

hv_vcon_proof_roll_abort:
    mov  byte [rel hv_vcon_proof_roll_active], 0
    ret

hv_vcon_proof_roll_state_reset:
    mov  byte [rel hv_vcon_proof_roll_active], 0
    ret

; AL=one byte captured from the guest's TX virtqueue. Preserve the caller's
; stream cursor/count and earn panic_text only from the real console phrase.
hv_vcon_capture_byte:
    call hv_terminal_byte                 ; real validated hvc0 output, no GUI callback
    push rbx
    push rcx
    push rdx
    push rsi                              ; preserve the TX descriptor stream cursor
    push rax                              ; serial marker emission may clobber the byte
    call hv_linux_console_char              ; hvc0 is primary; UART remains fallback
    pop  rax
    push rax
    cmp  byte [rel gbr_feed_on], 0
    je   .no_bundle_rx
    call gbr_feed                            ; owner-armed only; rings bytes, parses nothing
.no_bundle_rx:
%ifdef PAOS_NIC_ASSIGNMENT
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub rsp,8
    movzx edi,al
    call nd_learn_feed
    add rsp,8
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    mov rax,[rsp]
%endif
    call nd_console_byte
    call nd_restart_byte
%endif
    call guestnet_console_byte               ; only real guest TX may ack shell probe
    pop  rax
    call hv_vcon_capture_core
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; AL=one real console TX byte, from either virtio or the UART THR. Retain
; only the existing generation-bound RUN view; UART must not feed the virtio
; proof buffer, fatal-text matcher or protocol consumers. Preserve registers.
hv_vcon_run_tail_byte:
    push rbx
    push rdx
    ; Keep the newest 511 bytes for ordinary RUN polls in O(1) per TX byte.
    ; Preserve the legacy prefix/DIAG/proof buffer and fatal-text matcher.
    mov  edx, [rel hv_linux_start_consumed]
    cmp  edx, [rel hv_vcon_run_tail_gen]
    je   .tail_current
    mov  [rel hv_vcon_run_tail_gen], edx
    mov  dword [rel hv_vcon_run_tail_len], 0
    mov  dword [rel hv_vcon_run_tail_write], 0
.tail_current:
    mov  edx, [rel hv_vcon_run_tail_write]
    lea  rbx, [rel hv_vcon_run_tail]
    mov  [rbx + rdx], al
    inc  edx
    and  edx, HV_VCON_CAP_MAX - 1
    mov  [rel hv_vcon_run_tail_write], edx
    cmp  dword [rel hv_vcon_run_tail_len], HV_VCON_CAP_MAX - 1
    jae  .tail_full
    inc  dword [rel hv_vcon_run_tail_len]
.tail_full:
    pop  rdx
    pop  rbx
    ret

; AL=one byte. This is the real bounded capture/matcher core used by both the
; virtio TX path and the target-free overrun fixture.
hv_vcon_capture_core:
    push rbx
    push rcx
    push rdx
    push rsi
    call vtd_guest_console_byte             ; durable 1012b gate latches
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_console_char
%endif
    call hv_vcon_run_tail_byte
    mov  edx, [rel hv_vcon_capture_len]
    cmp  edx, HV_VCON_CAP_MAX - 1
    jb   .append
    cmp  byte [rel hv_first_ud_diag_active], 1
    je   .roll
    cmp  byte [rel hv_vcon_proof_roll_active], 1
    jne  .match                           ; ordinary capture remains prefix-only
.roll:
    ; Only DIAG or the scoped ordinary-assignment proof keeps a rolling tail.
    push rdi
    lea  rsi, [rel hv_vcon_capture + 1]
    lea  rdi, [rel hv_vcon_capture]
    mov  ecx, HV_VCON_CAP_MAX - 2
    cld
    rep  movsb
    pop  rdi
    inc  dword [rel hv_vcon_capture_overflow]
    mov  edx, HV_VCON_CAP_MAX - 2
.append:
    lea  rbx, [rel hv_vcon_capture]
    mov  [rbx + rdx], al
    inc  edx
    mov  [rel hv_vcon_capture_len], edx
    mov  byte [rbx + rdx], 0
.match:
    mov  ecx, [rel hv_panic_match]
    lea  rbx, [rel str_hv_panic_prefix]
    cmp  al, [rbx + rcx]
    jne  .restart
    inc  ecx
    mov  [rel hv_panic_match], ecx
    cmp  ecx, 12                         ; strlen("Kernel panic")
    jne  .out
    mov  byte [rel hv_panic_text], 1
    jmp  .out
.restart:
    xor  ecx, ecx
    cmp  al, 'K'
    jne  .store
    inc  ecx
.store:
    mov  [rel hv_panic_match], ecx
.out:
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; Exercise the real capture core beyond its 511-byte bound. Prove ordinary
; prefix semantics, proof-scoped tail searchability, and all three disarm
; paths without launching a guest or touching hardware.
hv_vcon_proof_roll_fixture_selftest:
    push rbx
    push r12
    mov  byte [rel hv_vcon_proof_roll_fixture_ok], 0
    mov  byte [rel hv_vcon_proof_roll_fixture_stage], 1
    movzx r12d, byte [rel hv_first_ud_diag_active]
    cmp  byte [rel hv_vcon_proof_roll_active], 0
    jne  .cleanup
    mov  byte [rel hv_first_ud_diag_active], 0
    call hv_vcon_capture_reset

    ; Outside either scoped mode, the first 511 bytes remain frozen.
    mov  ebx, HV_VCON_CAP_MAX - 1
.prefix_fill:
    mov  al, 'P'
    call hv_vcon_capture_core
    dec  ebx
    jnz  .prefix_fill
    mov  al, 'X'
    call hv_vcon_capture_core
    cmp  dword [rel hv_vcon_capture_len], HV_VCON_CAP_MAX - 1
    jne  .cleanup
    cmp  dword [rel hv_vcon_capture_overflow], 0
    jne  .cleanup
    cmp  byte [rel hv_vcon_capture + HV_VCON_CAP_MAX - 2], 'P'
    jne  .cleanup

    ; During the proof window, late real vendor/nonce text survives saturation.
    mov  byte [rel hv_vcon_proof_roll_fixture_stage], 2
    call hv_vcon_proof_roll_begin
    mov  ebx, HV_VCON_CAP_MAX - 1
.roll_fill:
    mov  al, 'P'
    call hv_vcon_capture_core
    dec  ebx
    jnz  .roll_fill
    lea  rbx, [rel str_hv_vcon_proof_roll_tail]
.tail:
    mov  al, [rbx]
    test al, al
    jz   .tail_done
    call hv_vcon_capture_core
    inc  rbx
    jmp  .tail
.tail_done:
    cmp  dword [rel hv_vcon_capture_len], HV_VCON_CAP_MAX - 1
    jne  .cleanup
    cmp  dword [rel hv_vcon_capture_overflow], 0
    je   .cleanup
    lea  rdi, [rel hv_vcon_capture]
    lea  rsi, [rel str_hv_vcon_proof_roll_vendor]
    call hv_str_has
    test al, al
    jz   .cleanup
    lea  rdi, [rel hv_vcon_capture]
    lea  rsi, [rel str_hv_vcon_proof_roll_nonce]
    call hv_str_has
    test al, al
    jz   .cleanup

    ; The actual success, failure, and ownership-reset helpers each disarm it.
    mov  byte [rel hv_vcon_proof_roll_fixture_stage], 3
    call hv_vcon_proof_roll_finish
    cmp  byte [rel hv_vcon_proof_roll_active], 0
    jne  .cleanup
    call hv_vcon_proof_roll_begin
    call hv_vcon_proof_roll_abort
    cmp  byte [rel hv_vcon_proof_roll_active], 0
    jne  .cleanup
    call hv_vcon_proof_roll_begin
    call hv_vcon_proof_roll_state_reset
    cmp  byte [rel hv_vcon_proof_roll_active], 0
    jne  .cleanup
    mov  byte [rel hv_vcon_proof_roll_fixture_ok], 1
.cleanup:
    call hv_vcon_proof_roll_state_reset
    call hv_vcon_capture_reset
    mov  [rel hv_first_ud_diag_active], r12b
    pop  r12
    pop  rbx
    ret

%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
; Native media owner APIs; stopped-vCPU command/idle turn only, never yield.
; Binding retains only the native PMH context, never a guest pointer. The owner
; keeps that lazy-once allocation alive through guest STOP and unbind.
hv_vcon_pmr_bind:                          ; RDI=initialized PMH ctx -> EAX=0/-1
    cmp  byte [rel hvp_bound], 0
    jne  .busy                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .busy
    test rdi, rdi
    jz   .busy
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .busy
    cmp  byte [rel cdp_bound], 0
    jne  .busy
    cmp  byte [rel gws_bound], 0
    jne  .busy
    cmp  byte [rel padc_bound], 0
    jne  .busy                              ; RCQ-36 PAD1 owns hvc0 exclusively too
    mov  [rel hv_vcon_pmr_ctx], rdi
    mov  byte [rel hv_vcon_pmr_pending], 0
    mov  byte [rel hv_vcon_pmr_retained], 0
    mov  byte [rel hv_vcon_pmr_retrying], 0
    mov  byte [rel hv_vcon_pmr_fault], 0
    mov  byte [rel hv_vcon_pmr_discard], 0
    mov  byte [rel hv_vcon_pmr_bound], 1
    xor  eax, eax
    ret
.busy:
    mov  eax, -1
    ret

hv_vcon_pmr_retry:                         ; after owner drains RX, at most one bounded drain
    cmp  byte [rel hv_vcon_pmr_bound], 1
    jne  .done
    cmp  byte [rel hv_vcon_pmr_pending], 1
    jne  .done
.drain:
    mov  byte [rel hv_vcon_pmr_retrying], 1
    sub  rsp, 8
    call hv_vcon_serve_tx
    add  rsp, 8
    mov  byte [rel hv_vcon_pmr_retrying], 0
.done:
    ret

hv_vcon_pmr_stop:                          ; stop RX delivery, release/drop retained TX chain
    cmp  byte [rel hv_vcon_pmr_bound], 1
    jne  .done
    mov  byte [rel hv_vcon_pmr_discard], 1
    sub  rsp, 8
    call hv_vcon_pmr_retry.drain
    add  rsp, 8
    mov  byte [rel hv_vcon_pmr_pending], 0
    mov  byte [rel hv_vcon_pmr_retained], 0   ; invalid/reset queue: explicit drop, never wrong-ring release
.done:
    ret

hv_vcon_pmr_unbind:                        ; only after guest STOP; never returns to text early
    sub  rsp, 8
    call hv_vcon_pmr_stop
    add  rsp, 8
    mov  byte [rel hv_vcon_pmr_bound], 0
    mov  qword [rel hv_vcon_pmr_ctx], 0
    ret

; RCQ-37 G3b media owner seams; command context, never yield. Selection binds
; the media profile and its guest-RAM reservation before any guest exists, so
; the owner configures PMH with the final window mapping, then launches.
; hv_media_guest_select(RDI=media profile record) -> RAX=host mapping of the
; MEDIA window, or 0 with EDX=owner reason (4 busy, 5 rail_unavailable, 8 memory).
hv_media_guest_select:
    push rbx
    mov  rbx, rdi
    mov  edx, 4
    cmp  byte [rel hvp_bound], 0
    jne  .refuse                          ; retain profile and backing until exact PIN1 stop
    mov  edx, 5
    HV_POWER_CHECK hv_guest_power_admit, .refuse   ; same power admission as GUESTVM START
    mov  edx, 4
    cmp  byte [rel hv_linux_running], 0
    jne  .refuse
    cmp  byte [rel hv_linux_start_active], 0
    jne  .refuse
    cmp  byte [rel hv_linux_run_req], 0
    jne  .refuse
    cmp  byte [rel vtd_owner_guest], 0
    jne  .refuse
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .refuse
    cmp  byte [rel cdp_bound], 0
    jne  .refuse
    cmp  byte [rel gws_bound], 0
    jne  .refuse
    cmp  byte [rel padc_bound], 0
    jne  .refuse                          ; RCQ-36 PAD1 owns hvc0 exclusively too
    mov  rax, [rel vm_profile_pair_state]
    test rax, rax
    jz   .pair_idle
    cmp  dword [rax + VPS_PHASE], 0
    jne  .refuse                          ; never replace an armed/bound paired run
.pair_idle:
    mov  edx, 5
    cmp  byte [rel hv_vmx_present], 1
    jne  .refuse
    lea  rax, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], rax          ; the PMR1 seam is VMX-only
    jne  .refuse
    mov  byte [rel gsn_resume_armed], 0   ; RCQ-18 S2: only RESUME arms a resume
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    mov  rdi, rbx
    call vm_profile_select
    mov  edx, 5
    test eax, eax
    jnz  .refuse
    call guestnet_detach                  ; no GUESTNET session rides a profile
    call hv_linux_reserve
    mov  edx, 8
    test rax, rax
    jz   .refuse
    cmp  qword [rel hv_linux_ram_bytes], VP_MEDIA_RAM
    jne  .refuse_span
    mov  rax, [rel hv_linux_ram]
    test rax, rax
    jz   .refuse_span
    add  rax, VP_MEDIA_GPA
    mov  byte [rel hv_media_window_held], 1 ; RC-speed-reserve: the owner releases after its scrub
    xor  edx, edx
    pop  rbx
    ret
.refuse_span:
    call hv_linux_release_idle            ; RC-speed-reserve: nothing was handed out (EDX kept)
.refuse:
    xor  eax, eax
    pop  rbx
    ret

; hv_media_window_release: the media owner no longer touches the MEDIA window
; (scrubbed, or the session never launched). Drops the pin; the span returns now
; if no START is requested, starting, running or power-retained, else at that
; START's own release. Preserves every register but RAX.
hv_media_window_release:
    mov  byte [rel hv_media_window_held], 0
    jmp  hv_linux_release_idle

; hv_media_guest_launch -> EAX=published START generation, EDX=0 queued or -1
; refused (no scheduler slot; the request is withdrawn). Same publication as
; GUESTVM START <profile>, without its yield.
hv_media_guest_launch:
    push rbx
    mov  eax, [rel hv_linux_start_gen]
    inc  eax
    mov  [rel vm_profile_gen], eax        ; the exact generation published next
    call hv_guest_linux_request_start
    mov  ebx, eax
    test eax, eax
    jz   .refused                          ; power admission revoked before publish
    cmp  byte [rel hv_linux_task_started], 1
    je   .queued
    lea  rdi, [rel hv_guest_linux_task]
    call sched_spawn
    cmp  eax, -1
    jne  .spawned
    cmp  ebx, [rel hv_linux_start_gen]
    jne  .refused                          ; foreign publication owns its own cleanup
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_linux_load_err], 9
.refused:
    mov  eax, ebx
    mov  edx, -1
    pop  rbx
    ret
.spawned:
    mov  byte [rel hv_linux_task_started], 1
.queued:
    mov  eax, ebx
    xor  edx, edx
    pop  rbx
    ret
%endif
%endif


; Drain at most one queue-size of heads at the stopped-vCPU notify boundary.
; A malformed head is retired with used.len=0 and NO consumer invocation; a
; bad queue/ownership snapshot retires nothing. This lets later valid work run.
; Valid content is fully preflighted/snapshotted before capture/CDP/GWS effects.
hv_vcon_serve_tx:
    HV_POWER_WORK hv_vcon_serve_tx, 0, hv_guest_power_io_admit
    push rbx
    push r12
    push r13
    push r14
    push r15
    pushfq
    cld
    sub  rsp, HV_VCON_RX_WORK_size        ; reuse pending RX parent's span layout
    xor  r15d, r15d                      ; serviced heads / bounded storm budget
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 1
    jne  .pmr_entry_ready
    cmp  byte [rel hv_vcon_pmr_pending], 1
    jne  .pmr_entry_ready
    cmp  byte [rel hv_vcon_pmr_retrying], 1
    jne  .done                             ; notify cannot retry a retained chain
.pmr_entry_ready:
    cmp  byte [rel hv_vcon_pmr_retained], 1
    jne  .pmr_snapshot_ready
    ; A retained native copy belongs to this queue/generation only. Refuse
    ; changed/reset queues before another RX copy or any used-ring write.
    cmp  byte [rel hv_vcon_q_ready + 1], 1
    jne  .pmr_queue_bad
    mov  eax, [rel hv_linux_start_gen]
    cmp  eax, [rel hv_vcon_pmr_saved_gen]
    jne  .pmr_queue_bad
    mov  eax, [rel hv_vcon_q_num + 4]
    cmp  eax, [rel hv_vcon_pmr_saved_num]
    jne  .pmr_queue_bad
    mov  ax, [rel hv_vcon_q_lastav + 2]
    cmp  ax, [rel hv_vcon_pmr_saved_lastav]
    jne  .pmr_queue_bad
    mov  ax, [rel hv_vcon_q_usedidx + 2]
    cmp  ax, [rel hv_vcon_pmr_saved_usedidx]
    jne  .pmr_queue_bad
    mov  rax, [rel hv_linux_ram]
    cmp  rax, [rel hv_vcon_pmr_saved_ram]
    jne  .pmr_queue_bad
    mov  rax, [rel hv_vcon_q_avail + 8]
    cmp  rax, [rel hv_vcon_pmr_saved_avail]
    jne  .pmr_queue_bad
    mov  rax, [rel hv_vcon_q_used + 8]
    cmp  rax, [rel hv_vcon_pmr_saved_used]
    jne  .pmr_queue_bad
    mov  rax, [rel hv_vcon_q_desc + 8]
    cmp  rax, [rel hv_vcon_pmr_saved_desc]
    jne  .pmr_queue_bad
.pmr_snapshot_ready:
%endif
%endif
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rsp + HV_VCON_RX_WORK.generation], eax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .done
    mov  [rsp + HV_VCON_RX_WORK.region], rax
    mov  rax, [rel hv_linux_ram]
    test rax, rax
    jz   .done
    mov  [rsp + HV_VCON_RX_WORK.ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rsp + HV_VCON_RX_WORK.ram_bytes], rax
    cmp  byte [rel hv_linux_running], 1
    jne  .done
    test dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    jz   .done
    cmp  byte [rel hv_vcon_ready], 1
    jne  .done
    cmp  word [rel hv_vcon_q_ready], 0x0101
    jne  .done
    mov  dword [rsp + HV_VCON_RX_WORK.padding], 0   ; byte 3 too: the indirect check reads the dword
    movzx eax, byte [rel cdp_bound]
    mov  [rsp + HV_VCON_RX_WORK.padding], al
    movzx eax, byte [rel gws_bound]
    mov  [rsp + HV_VCON_RX_WORK.padding + 1], al
    movzx eax, byte [rel padc_bound]
    mov  [rsp + HV_VCON_RX_WORK.padding + 2], al
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    movzx eax, byte [rel hv_vcon_pmr_bound]
    mov  [rsp + HV_VCON_RX_WORK.padding + 3], al
%endif
%endif
    mov  rdi, rsp
    call hv_vcon_owner_take
    test eax, eax
    jz   .done
    mov  dword [rsp + HV_VCON_RX_WORK.nmeta], 0
    xor  ebx, ebx                        ; both queues' metadata are protected
.queue:
    lea  rax, [rel hv_vcon_q_num]
    mov  r14d, [rax + rbx*4]
    test r14d, r14d
    jz   .done
    cmp  r14d, HV_VCON_QMAX
    ja   .done
    lea  eax, [r14d - 1]
    test eax, r14d
    jnz  .done
    cmp  ebx, 1
    jne  .queue_size_ready
    mov  [rsp + HV_VCON_RX_WORK.qsize], r14d
.queue_size_ready:
    xor  r12d, r12d
.metadata:
    lea  rax, [rel hv_vcon_q_desc]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 4
    test r12d, r12d
    jz   .metadata_span
    lea  rax, [rel hv_vcon_q_avail]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 1
    add  esi, 6
    cmp  r12d, 1
    je   .metadata_span
    lea  rax, [rel hv_vcon_q_used]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 3
    add  esi, 6
.metadata_span:
    call hv_linux_gpa2hva                 ; full metadata extents, not one entry
    test rax, rax
    jz   .done
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rsp + HV_VCON_RX_WORK.metadata]
    mov  esi, [rsp + HV_VCON_RX_WORK.nmeta]
    call hv_vcon_rx_disjoint
    test eax, eax
    jz   .done
    mov  eax, [rsp + HV_VCON_RX_WORK.nmeta]
    shl  eax, 4
    mov  [rsp + HV_VCON_RX_WORK.metadata + rax], rdx
    mov  [rsp + HV_VCON_RX_WORK.metadata + rax + 8], rcx
    inc  dword [rsp + HV_VCON_RX_WORK.nmeta]
    inc  r12d
    cmp  r12d, 3
    jb   .metadata
    inc  ebx
    cmp  ebx, 2
    jb   .queue

    mov  r14d, [rsp + HV_VCON_RX_WORK.qsize]
    mov  rbx, [rsp + HV_VCON_RX_WORK.metadata + 64] ; TX avail
    mov  r12, [rsp + HV_VCON_RX_WORK.metadata + 80] ; TX used
.loop:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_retained], 1
    jne  .pmr_new_chain
    mov  eax, [rel hv_vcon_pmr_head]          ; the retained head, checked against the saved queue at entry
    mov  [rsp + HV_VCON_RX_WORK.head], eax
    movzx eax, word [rel hv_vcon_q_lastav + 2]
    mov  [rsp + HV_VCON_RX_WORK.lastav], eax
    movzx eax, word [rel hv_vcon_q_usedidx + 2]
    mov  [rsp + HV_VCON_RX_WORK.usedidx], eax
    mov  dword [rsp + HV_VCON_RX_WORK.flags], 1
    jmp  .head_ready                       ; never reread guest bytes or replay the accepted prefix
.pmr_new_chain:
%endif
%endif
    movzx eax, word [rbx + 2]
    movzx ecx, word [rel hv_vcon_q_lastav + 2]
    mov  [rsp + HV_VCON_RX_WORK.lastav], ecx
    sub  ax, cx                          ; unsigned modulo-16 producer distance
    jz   .flush
    movzx eax, ax
    cmp  eax, r14d
    ja   .flush                          ; overrun/stale avail is not a head
    lfence                               ; acquire complete descriptors/payload
    lea  eax, [r14d - 1]
    and  ecx, eax
    movzx r9d, word [rbx + 4 + rcx*2]
    mov  [rsp + HV_VCON_RX_WORK.head], r9d
    movzx eax, word [rel hv_vcon_q_usedidx + 2]
    mov  [rsp + HV_VCON_RX_WORK.usedidx], eax
    mov  qword [rsp + HV_VCON_RX_WORK.visited], 0
    mov  qword [rsp + HV_VCON_RX_WORK.capacity], 0
    mov  dword [rsp + HV_VCON_RX_WORK.count], 0
    mov  dword [rsp + HV_VCON_RX_WORK.nmeta], 6
    mov  dword [rsp + HV_VCON_RX_WORK.indirect], 0
    mov  [rsp + HV_VCON_RX_WORK.limit], r14d
    mov  rax, [rsp + HV_VCON_RX_WORK.metadata + 48]
    mov  [rsp + HV_VCON_RX_WORK.descbase], rax
.chain:
    cmp  r9d, [rsp + HV_VCON_RX_WORK.limit]
    jae  .malformed
    bts  qword [rsp + HV_VCON_RX_WORK.visited], r9
    jc   .malformed
    cmp  [rsp + HV_VCON_RX_WORK.count], r14d
    jae  .malformed
    mov  eax, r9d
    shl  eax, 4
    add  rax, [rsp + HV_VCON_RX_WORK.descbase]
    test word [rax + 12], 4
    jz   .direct
    cmp  dword [rsp + HV_VCON_RX_WORK.padding], 0
    jne  .malformed                      ; typed paths keep their direct shape
    mov  rdi, rsp
    call hv_vcon_indirect_snapshot
    test eax, eax
    jz   .malformed
    xor  r9d, r9d
    jmp  .chain
.direct:
    movzx ecx, word [rax + 12]
    test ecx, ~1                         ; readable, optional NEXT only
    jnz  .malformed                      ; WRITE/reserved unsupported
    mov  [rsp + HV_VCON_RX_WORK.flags], ecx
    movzx edx, word [rax + 14]
    mov  [rsp + HV_VCON_RX_WORK.next], edx
    mov  esi, [rax + 8]
    cmp  byte [rsp + HV_VCON_RX_WORK.padding], 1
    jne  .surface_shape
    test ecx, ecx                        ; CDP stays strictly one descriptor
    jnz  .malformed
    cmp  esi, DC_HEADER
    jb   .malformed
    cmp  esi, DC_FRAME
    ja   .malformed
.surface_shape:
    cmp  byte [rsp + HV_VCON_RX_WORK.padding + 1], 1
    jne  .span
    test ecx, ecx                        ; GWS stays exactly one 256-byte record
    jnz  .malformed
    cmp  esi, 256
    jne  .malformed
.span:
    mov  rdi, [rax]
    call hv_linux_gpa2hva                 ; complete full64 span, even empty tail
    test rax, rax
    jz   .malformed
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rsp + HV_VCON_RX_WORK.metadata]
    mov  esi, [rsp + HV_VCON_RX_WORK.nmeta]
    call hv_vcon_rx_disjoint              ; same full metadata protection as RX
    test eax, eax
    jz   .malformed
    cmp  dword [rsp + HV_VCON_RX_WORK.indirect], 0
    je   .payload_disjoint
    lea  rdi, [rsp + HV_VCON_RX_WORK.segments]
    mov  esi, [rsp + HV_VCON_RX_WORK.count]
    call hv_vcon_rx_disjoint
    test eax, eax
    jz   .malformed
.payload_disjoint:
    add  [rsp + HV_VCON_RX_WORK.capacity], rcx
    cmp  qword [rsp + HV_VCON_RX_WORK.capacity], HV_VCON_TX_MAX
    ja   .malformed                      ; no silently skipped oversized segment
    mov  eax, [rsp + HV_VCON_RX_WORK.count]
    shl  eax, 4
    mov  [rsp + HV_VCON_RX_WORK.segments + rax], rdx
    mov  [rsp + HV_VCON_RX_WORK.segments + rax + 8], rcx
    inc  dword [rsp + HV_VCON_RX_WORK.count]
    test dword [rsp + HV_VCON_RX_WORK.flags], 1
    jz   .preflight_done
    mov  r9d, [rsp + HV_VCON_RX_WORK.next]
    jmp  .chain
.preflight_done:
    mov  dword [rsp + HV_VCON_RX_WORK.flags], 1 ; valid disposition
    jmp  .head_ready
.malformed:
    mov  dword [rsp + HV_VCON_RX_WORK.flags], 0 ; retire, no downstream effect
.head_ready:
    ; Never continue a snapshot across START/STOP or a changed RAM backing.
    mov  eax, [rsp + HV_VCON_RX_WORK.generation]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .done
    mov  rax, [rsp + HV_VCON_RX_WORK.region]
    cmp  rax, [rel hv_linux_region]
    jne  .done
    mov  rax, [rsp + HV_VCON_RX_WORK.ram]
    cmp  rax, [rel hv_linux_ram]
    jne  .done
    mov  rax, [rsp + HV_VCON_RX_WORK.ram_bytes]
    cmp  rax, [rel hv_linux_ram_bytes]
    jne  .done
    cmp  byte [rel hv_linux_running], 1
    jne  .done
    test dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    jz   .done
    cmp  byte [rel hv_vcon_ready], 1
    jne  .done
    cmp  word [rel hv_vcon_q_ready], 0x0101
    jne  .done

    mov  rdi, rsp
    call hv_vcon_owner_current
    test eax, eax
    jz   .done

    mov  al, [rsp + HV_VCON_RX_WORK.padding]
    cmp  al, [rel cdp_bound]
    jne  .done
    mov  al, [rsp + HV_VCON_RX_WORK.padding + 1]
    cmp  al, [rel gws_bound]
    jne  .done
    mov  al, [rsp + HV_VCON_RX_WORK.padding + 2]
    cmp  al, [rel padc_bound]
    jne  .done
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    mov  al, [rsp + HV_VCON_RX_WORK.padding + 3]
    cmp  al, [rel hv_vcon_pmr_bound]
    jne  .done
%endif
%endif
    cmp  dword [rsp + HV_VCON_RX_WORK.flags], 0
    je   .push_used
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_retained], 1
    je   .pmr_dispatch                     ; the frozen native suffix only: no new copy
%endif
%endif

    ; No failure/yield/guest metadata reads after this point. Exact private
    ; snapshot completes before ANY capture or typed consumer is invoked.
    lea  rdi, [rel hv_vcon_txbuf]
    xor  r9d, r9d
.copy:
    mov  eax, r9d
    shl  eax, 4
    mov  rsi, [rsp + HV_VCON_RX_WORK.segments + rax]
    mov  rcx, [rsp + HV_VCON_RX_WORK.segments + rax + 8]
    rep  movsb
    inc  r9d
    cmp  r9d, [rsp + HV_VCON_RX_WORK.count]
    jb   .copy
    mov  r13d, [rsp + HV_VCON_RX_WORK.capacity]
    cmp  byte [rel hvp_bound], 0
    jne  .pin_channel                       ; retained ownership survives profile drift
    test dword [rsp + HV_VCON_RX_WORK.devices], VP_DEV_PINCHAN
    jz   .not_pin_channel
.pin_channel:
    mov  ecx, r13d
    call hv_pin_receive                     ; exact private snapshot only, no text fallback
    jmp  .push_used
.not_pin_channel:
    test dword [rsp + HV_VCON_RX_WORK.devices], VP_DEV_WARMCHAN
    jz   .not_warm_channel
    mov  ecx, r13d
    call hvcw_receive                      ; exclusively owned native snapshot
    jmp  .push_used
.not_warm_channel:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rsp + HV_VCON_RX_WORK.padding + 3], 1
    jne  .pmr_not_bound
.pmr_dispatch:
    cmp  byte [rel hv_vcon_pmr_discard], 1
    je   .pmr_complete                     ; STOP releases without delivering to any consumer
    cmp  byte [rel hv_vcon_pmr_retained], 1
    je   .pmr_copy_suffix
    mov  [rel hv_vcon_pmr_total], r13d
    mov  dword [rel hv_vcon_pmr_pos], 0
    mov  eax, [rsp + HV_VCON_RX_WORK.head]
    mov  [rel hv_vcon_pmr_head], eax
    mov  eax, [rel hv_linux_start_gen]
    mov  [rel hv_vcon_pmr_saved_gen], eax
    mov  [rel hv_vcon_pmr_saved_num], r14d
    mov  ax, [rel hv_vcon_q_lastav + 2]
    mov  [rel hv_vcon_pmr_saved_lastav], ax
    mov  ax, [rel hv_vcon_q_usedidx + 2]
    mov  [rel hv_vcon_pmr_saved_usedidx], ax
    mov  rax, [rel hv_linux_ram]
    mov  [rel hv_vcon_pmr_saved_ram], rax
    mov  rax, [rel hv_vcon_q_avail + 8]
    mov  [rel hv_vcon_pmr_saved_avail], rax
    mov  rax, [rel hv_vcon_q_used + 8]
    mov  [rel hv_vcon_pmr_saved_used], rax
    mov  rax, [rel hv_vcon_q_desc + 8]
    mov  [rel hv_vcon_pmr_saved_desc], rax
.pmr_copy_suffix:
    mov  ecx, [rel hv_vcon_pmr_pos]
    mov  edx, [rel hv_vcon_pmr_total]
    sub  edx, ecx
    mov  rdi, [rel hv_vcon_pmr_ctx]
    lea  rsi, [rel hv_vcon_txbuf]
    add  rsi, rcx
    call pmr1h_rx                           ; real ABI: copied prefix byte count, including zero
    test eax, eax
    js   .pmr_complete                     ; stopped/refused: explicit drop and release
    mov  edx, [rel hv_vcon_pmr_total]
    sub  edx, [rel hv_vcon_pmr_pos]
    cmp  eax, edx
    ja   .pmr_count_bad
    add  [rel hv_vcon_pmr_pos], eax
    cmp  eax, edx
    je   .pmr_complete
    mov  byte [rel hv_vcon_pmr_retained], 1
    mov  byte [rel hv_vcon_pmr_pending], 1
    jmp  .flush                            ; unaccepted native suffix stays owned; no used advance
.pmr_count_bad:
    mov  byte [rel hv_vcon_pmr_discard], 1
    mov  byte [rel hv_vcon_pmr_fault], 1
.pmr_complete:
    mov  byte [rel hv_vcon_pmr_retained], 0
    mov  byte [rel hv_vcon_pmr_pending], 0
    jmp  .push_used
.pmr_not_bound:
%endif
%endif
    cmp  byte [rsp + HV_VCON_RX_WORK.padding], 1
    jne  .surface_capture
    mov  ecx, r13d
    call cdp_bridge_receive
    jmp  .push_used
.surface_capture:
    cmp  byte [rsp + HV_VCON_RX_WORK.padding + 1], 1
    jne  .text_capture
    mov  ecx, r13d
    call guest_surface_receive
    jmp  .push_used
.text_capture:
    cmp  byte [rsp + HV_VCON_RX_WORK.padding + 2], 1
    jne  .text_bytes
    mov  ecx, r13d
    call padc_receive                    ; RCQ-36: PAD1 owns hvc0, no text capture
    jmp  .push_used
.text_bytes:
    lea  rsi, [rel hv_vcon_txbuf]
    mov  ecx, r13d
.capture:
    test ecx, ecx
    jz   .push_used
    lodsb
    call hv_vcon_capture_byte
    dec  ecx
    jmp  .capture
.push_used:
    mov  ecx, [rsp + HV_VCON_RX_WORK.usedidx]
    lea  eax, [r14d - 1]
    and  eax, ecx
    lea  rdi, [r12 + 4 + rax*8]
    mov  edx, [rsp + HV_VCON_RX_WORK.head]
    mov  [rdi], edx
    mov  dword [rdi + 4], 0               ; TX writes no bytes to guest payload
    inc  ecx
    mov  [rel hv_vcon_q_usedidx + 2], cx
    sfence                               ; complete consumption before release
    mov  [r12 + 2], cx
    mov  ecx, [rsp + HV_VCON_RX_WORK.lastav]
    inc  ecx
    mov  [rel hv_vcon_q_lastav + 2], cx
    inc  dword [rel hv_vcon_tx_used]
    inc  r15d
    cmp  r15d, r14d
    jb   .loop
.flush:
    test r15d, r15d
    jz   .done
    call hv_vcon_raise_irq
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    jmp  .done
.pmr_queue_bad:
    mov  byte [rel hv_vcon_pmr_fault], 1      ; owner must stop with visible record refusal
    mov  byte [rel hv_vcon_pmr_discard], 1
    mov  byte [rel hv_vcon_pmr_pending], 0
    mov  byte [rel hv_vcon_pmr_retained], 0
%endif
%endif
.done:
    add  rsp, HV_VCON_RX_WORK_size
    popfq
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RCQ-19 RX chain preflight
; Private bounded stack snapshot, valid only at the stopped-vCPU boundary.
; Each span is {host address, full byte length}; no guest pointer is retained.
struc HV_VCON_RX_WORK
    .segments: resq HV_VCON_QMAX * 2
    .metadata: resq 7 * 2               ; seventh span protects indirect storage
    .generation: resd 1
    .head: resd 1
    .lastav: resd 1
    .usedidx: resd 1
    .visited: resq 1
    .count: resd 1
    .nmeta: resd 1
    .capacity: resq 1
    .region: resq 1
    .ram: resq 1
    .ram_bytes: resq 1
    .next: resd 1
    .flags: resd 1
    .qsize: resd 1
    .padding: resd 1
    .descbase: resq 1
    .limit: resd 1
    .indirect: resd 1
    .epoch: resq 1
    .backend: resq 1
    .profile: resq 1
    .devices: resd 1
    .features: resd 1
    .config: resq 7                      ; both queues' addresses and sizes
    .geometry: resd 1                    ; cols/rows pair, not a guest pointer
    .config_generation: resd 1
    .table: resq HV_VCON_QMAX * 2         ; one private bounded descriptor table
endstruc

; RDI=work snapshot. Called only with a stopped vCPU, no yielding calls.
; Bind features/reset epoch, actual backend/profile/START and queue configuration
; as well as the existing RAM/region checks in each consumer.
hv_vcon_owner_take:
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   hv_vcon_owner_current.bad
    mov  eax, [rdx + HV_VCON_PAGE + 0x100]
    mov  [rdi + HV_VCON_RX_WORK.geometry], eax
    mov  eax, [rdx + HV_VCON_PAGE + 0xFC]
    mov  [rdi + HV_VCON_RX_WORK.config_generation], eax
    mov  eax, [rel hv_vcon_drvfeat]
    mov  [rdi + HV_VCON_RX_WORK.features], eax
    mov  rax, [rel hv_vcon_epoch]
    mov  [rdi + HV_VCON_RX_WORK.epoch], rax
    mov  rax, [rel hv_ops_active]
    mov  [rdi + HV_VCON_RX_WORK.backend], rax
    mov  rax, [rel vm_profile_active]
    mov  [rdi + HV_VCON_RX_WORK.profile], rax
    mov  eax, [rel vm_profile_live_devices]
    mov  [rdi + HV_VCON_RX_WORK.devices], eax
    mov  rax, [rel hv_vcon_q_num]
    mov  [rdi + HV_VCON_RX_WORK.config + 48], rax
    xor  ecx, ecx
.copy_config:
    lea  rdx, [rel hv_vcon_q_desc]         ; six consecutive qwords, desc/avail/used
    mov  rax, [rdx + rcx*8]
    mov  [rdi + HV_VCON_RX_WORK.config + rcx*8], rax
    inc  ecx
    cmp  ecx, 6
    jb   .copy_config
    jmp  hv_vcon_owner_current

hv_vcon_owner_current:
    sub  rsp, 8
    call hv_vcon_features_ok
    add  rsp, 8
    test eax, eax
    jz   .bad
    cmp  dword [rel hv_vcon_status], 15
    jne  .bad
    mov  eax, [rdi + HV_VCON_RX_WORK.features]
    cmp  eax, [rel hv_vcon_drvfeat]
    jne  .bad
    mov  rax, [rdi + HV_VCON_RX_WORK.epoch]
    cmp  rax, [rel hv_vcon_epoch]
    jne  .bad
    mov  rax, [rdi + HV_VCON_RX_WORK.backend]
    test rax, rax
    jz   .bad
    cmp  rax, [rel hv_ops_active]
    jne  .bad
    mov  rax, [rdi + HV_VCON_RX_WORK.profile]
    cmp  rax, [rel vm_profile_active]
    jne  .bad
    mov  eax, [rdi + HV_VCON_RX_WORK.generation]
    test eax, eax
    jz   .bad
    cmp  eax, [rel hv_linux_start_gen]
    jne  .bad
    cmp  qword [rdi + HV_VCON_RX_WORK.profile], 0
    je   .legacy
    cmp  eax, [rel vm_profile_gen]
    jne  .bad
    jmp  .profile_bound
.legacy:
    cmp  dword [rel vm_profile_gen], 0     ; unselected launches use legacy shape
    jne  .bad
    cmp  dword [rel vm_profile_dev_mask], VP_DEV_LEGACY
    jne  .bad
.profile_bound:
    mov  eax, [rdi + HV_VCON_RX_WORK.devices]
    cmp  eax, [rel vm_profile_live_devices]
    jne  .bad
    cmp  eax, [rel vm_profile_dev_mask]
    jne  .bad
    mov  rax, [rdi + HV_VCON_RX_WORK.ram]
    add  rax, [rdi + HV_VCON_RX_WORK.ram_bytes]
    jc   .bad                            ; full host backing must not wrap
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .bad
    mov  eax, [rdi + HV_VCON_RX_WORK.geometry]
    cmp  eax, [rdx + HV_VCON_PAGE + 0x100]
    jne  .bad
    mov  eax, [rdi + HV_VCON_RX_WORK.config_generation]
    cmp  eax, [rdx + HV_VCON_PAGE + 0xFC]
    jne  .bad
    mov  rax, [rdi + HV_VCON_RX_WORK.config + 48]
    cmp  rax, [rel hv_vcon_q_num]
    jne  .bad
    xor  ecx, ecx
.config:
    lea  rdx, [rel hv_vcon_q_desc]
    mov  rax, [rdi + HV_VCON_RX_WORK.config + rcx*8]
    cmp  rax, [rdx + rcx*8]
    jne  .bad
    inc  ecx
    cmp  ecx, 6
    jb   .config
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; RDI=work, RAX=outer descriptor. One negotiated table; outer WRITE ignored.
; Table storage is a seventh protected metadata span. Snapshot it once before
; interpreting entries; payload preflight subsequently uses only private bytes.
; Direct prefixes are allowed; NEXT on the table descriptor is not.
hv_vcon_indirect_snapshot:
    push rbx
    mov  rbx, rdi
    cmp  dword [rbx + HV_VCON_RX_WORK.indirect], 0
    jne  .bad
    test dword [rbx + HV_VCON_RX_WORK.features], HV_VCON_INDIRECT
    jz   .bad
    movzx ecx, word [rax + 12]
    and  ecx, ~2                         ; outer WRITE is ignored (virtio2.7.5.3.2)
    cmp  ecx, 4
    jne  .bad
    mov  esi, [rax + 8]
    test esi, esi
    jz   .bad
    test esi, 15
    jnz  .bad
    cmp  esi, HV_VCON_QMAX * 16
    ja   .bad
    mov  edx, esi
    shr  edx, 4
    cmp  edx, [rbx + HV_VCON_RX_WORK.qsize]
    ja   .bad
    mov  [rbx + HV_VCON_RX_WORK.limit], edx
    mov  rdi, [rax]
    test rdi, 15
    jnz  .bad
    call hv_linux_gpa2hva
    test rax, rax
    jz   .bad
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rbx + HV_VCON_RX_WORK.metadata]
    mov  esi, 6
    call hv_vcon_rx_disjoint
    test eax, eax
    jz   .bad
    lea  rdi, [rbx + HV_VCON_RX_WORK.segments]
    mov  esi, [rbx + HV_VCON_RX_WORK.count]
    call hv_vcon_rx_disjoint
    test eax, eax
    jz   .bad
    mov  [rbx + HV_VCON_RX_WORK.metadata + 96], rdx
    mov  [rbx + HV_VCON_RX_WORK.metadata + 104], rcx
    mov  dword [rbx + HV_VCON_RX_WORK.nmeta], 7
    mov  rsi, rdx
    lea  rdi, [rbx + HV_VCON_RX_WORK.table]
    mov  [rbx + HV_VCON_RX_WORK.descbase], rdi
    shr  ecx, 3
    rep  movsq
    mov  qword [rbx + HV_VCON_RX_WORK.visited], 0
    mov  dword [rbx + HV_VCON_RX_WORK.indirect], 1
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; RDI=span array, ESI=count, RDX=new HVA, RCX=full length. EAX=disjoint.
; Empty spans do not alias; endpoints cannot wrap. RDX/RCX are preserved.
hv_vcon_rx_disjoint:
    lea r8, [rdx + rcx]
    cmp r8, rdx
    jb .bad
    test rcx, rcx
    jz .good
    xor r9d, r9d
.loop:
    cmp r9d, esi
    jae .good
    mov r10, [rdi]
    mov r11, [rdi + 8]
    test r11, r11
    jz .next
    add r11, r10
    jc .bad
    cmp rdx, r11
    jae .next
    cmp r10, r8
    jb .bad
.next:
    add rdi, 16
    inc r9d
    jmp .loop
.good:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

; RDI=owned command text. Read at most 256 bytes, preserving the pointer.
; EAX=0..255 text bytes, or -1 if no NUL fits before the appended newline.
; A rejected command must not become an executable, silently truncated prefix.
hv_vcon_line_length:
    xor  eax, eax
.scan:
    cmp  byte [rdi + rax], 0
    je   .done
    inc  eax
    cmp  eax, 256
    jb   .scan
    mov  eax, -1                        ; no NUL within the 256-byte prefix
.done:
    ret

; RDI=NUL-terminated command text. Consume one real queue-0 chain and
; append newline so BusyBox executes the whole line. EAX=1 delivered / 0 refused.
hv_vcon_rx_line:
    cmp qword [rel hv_terminal_owner], 0
    jne .warm_refused                     ; public Terminal owns this shell
    test dword [rel vm_profile_live_devices], VP_DEV_PINCHAN
    jnz  .warm_refused                       ; exclusive even before owner bind
    cmp  byte [rel hvp_bound], 0
    jne  .warm_refused                         ; PIN1 retains ownership through actual retirement
    cmp  byte [rel hvw_bound], 0
    jne  .warm_refused
    HV_POWER_WORK hv_vcon_rx_line, 0, hv_guest_power_io_admit
    cmp  byte [rel padc_bound], 0
    je   .text_admitted
    xor  eax, eax                        ; RCQ-36: PAD1 owns hvc0, no text line enters it
    ret
.text_admitted:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 1
    jne  .line_available
    xor  eax, eax                          ; media owns hvc0; shell lines cannot corrupt PMR1
    ret
.line_available:
%endif
%endif
    push rbx
    push r12
    push r13
    push r14
    push r15
    pushfq
    cld
    call hv_vcon_line_length
    cmp  eax, -1
    jne  .valid_line
    xor  eax, eax
    jmp  .restore                       ; no scratch/queue/capture publication
.valid_line:
    mov  ecx, eax                        ; all validated bytes, no truncation
    lea  r13d, [eax + 1]                 ; text + newline, at most 256 bytes
    mov  rsi, rdi
    lea  rdi, [rel hv_vcon_rxbuf]
    rep  movsb
    mov  byte [rdi], 10
.send:
    sub  rsp, HV_VCON_RX_WORK_size
    xor  r15d, r15d                       ; result, unchanged until publication
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rsp + HV_VCON_RX_WORK.generation], eax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .out
    mov  [rsp + HV_VCON_RX_WORK.region], rax
    mov  rax, [rel hv_linux_ram]
    test rax, rax
    jz   .out
    mov  [rsp + HV_VCON_RX_WORK.ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rsp + HV_VCON_RX_WORK.ram_bytes], rax
    cmp  byte [rel hv_linux_running], 1
    jne  .out
    test dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    jz   .out
    cmp  byte [rel hv_vcon_ready], 1
    jne  .out
    cmp  word [rel hv_vcon_q_ready], 0x0101
    jne  .out
    mov  rdi, rsp
    call hv_vcon_owner_take
    test eax, eax
    jz   .out
    mov  dword [rsp + HV_VCON_RX_WORK.nmeta], 0
    xor  ebx, ebx                        ; both queues' metadata are protected
.queue:
    lea  rax, [rel hv_vcon_q_num]
    mov  r14d, [rax + rbx*4]
    test r14d, r14d
    jz   .out
    cmp  r14d, HV_VCON_QMAX
    ja   .out
    lea  eax, [r14d - 1]
    test eax, r14d
    jnz  .out
    test ebx, ebx
    jnz  .queue_size_ready
    mov  [rsp + HV_VCON_RX_WORK.qsize], r14d
.queue_size_ready:
    xor  r12d, r12d
.metadata:
    lea  rax, [rel hv_vcon_q_desc]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 4
    test r12d, r12d
    jz   .metadata_span
    lea  rax, [rel hv_vcon_q_avail]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 1
    add  esi, 6
    cmp  r12d, 1
    je   .metadata_span
    lea  rax, [rel hv_vcon_q_used]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 3
    add  esi, 6
.metadata_span:
    call hv_linux_gpa2hva                 ; full metadata extents, not one entry
    test rax, rax
    jz   .out
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rsp + HV_VCON_RX_WORK.metadata]
    mov  esi, [rsp + HV_VCON_RX_WORK.nmeta]
    call hv_vcon_rx_disjoint
    test eax, eax
    jz   .out
    mov  eax, [rsp + HV_VCON_RX_WORK.nmeta]
    shl  eax, 4
    mov  [rsp + HV_VCON_RX_WORK.metadata + rax], rdx
    mov  [rsp + HV_VCON_RX_WORK.metadata + rax + 8], rcx
    inc  dword [rsp + HV_VCON_RX_WORK.nmeta]
    inc  r12d
    cmp  r12d, 3
    jb   .metadata
    inc  ebx
    cmp  ebx, 2
    jb   .queue

    mov  r14d, [rsp + HV_VCON_RX_WORK.qsize]
    mov  rbx, [rsp + HV_VCON_RX_WORK.metadata + 16] ; RX avail
    mov  r12, [rsp + HV_VCON_RX_WORK.metadata + 32] ; RX used
    movzx eax, word [rbx + 2]
    movzx ecx, word [rel hv_vcon_q_lastav]
    mov  [rsp + HV_VCON_RX_WORK.lastav], ecx
    sub  ax, cx                          ; modulo-16-bit producer distance
    jz   .out
    movzx eax, ax
    cmp  eax, r14d                       ; no overrun/stale ring replay
    ja   .out
    lfence
    lea  eax, [r14d - 1]
    and  ecx, eax
    movzx r9d, word [rbx + 4 + rcx*2]
    mov  [rsp + HV_VCON_RX_WORK.head], r9d
    movzx eax, word [rel hv_vcon_q_usedidx]
    mov  [rsp + HV_VCON_RX_WORK.usedidx], eax
    mov  qword [rsp + HV_VCON_RX_WORK.visited], 0
    mov  qword [rsp + HV_VCON_RX_WORK.capacity], 0
    mov  dword [rsp + HV_VCON_RX_WORK.count], 0
    mov  dword [rsp + HV_VCON_RX_WORK.nmeta], 6
    mov  dword [rsp + HV_VCON_RX_WORK.indirect], 0
    mov  [rsp + HV_VCON_RX_WORK.limit], r14d
    mov  rax, [rsp + HV_VCON_RX_WORK.metadata + 0]
    mov  [rsp + HV_VCON_RX_WORK.descbase], rax
.chain:
    cmp  r9d, [rsp + HV_VCON_RX_WORK.limit]
    jae  .out
    bts  qword [rsp + HV_VCON_RX_WORK.visited], r9
    jc   .out                            ; duplicate/cycle
    cmp  [rsp + HV_VCON_RX_WORK.count], r14d
    jae  .out
    mov  eax, r9d
    shl  eax, 4
    add  rax, [rsp + HV_VCON_RX_WORK.descbase]
    test word [rax + 12], 4
    jz   .direct
    mov  rdi, rsp
    call hv_vcon_indirect_snapshot
    test eax, eax
    jz   .out
    xor  r9d, r9d
    jmp  .chain
.direct:
    movzx ecx, word [rax + 12]
    mov  edx, ecx
    and  edx, ~1                         ; WRITE, optionally NEXT, nothing else
    cmp  edx, 2                          ; only WRITE and optional NEXT
    jne  .out
    mov  [rsp + HV_VCON_RX_WORK.flags], ecx
    movzx ecx, word [rax + 14]
    mov  [rsp + HV_VCON_RX_WORK.next], ecx
    mov  rdi, [rax]
    mov  esi, [rax + 8]
    call hv_linux_gpa2hva                 ; preflight FULL 64-bit guest span
    test rax, rax
    jz   .out
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rsp + HV_VCON_RX_WORK.metadata]
    mov  esi, [rsp + HV_VCON_RX_WORK.nmeta]
    call hv_vcon_rx_disjoint              ; protect RX and TX shared metadata
    test eax, eax
    jz   .out
    lea  rdi, [rsp + HV_VCON_RX_WORK.segments]
    mov  esi, [rsp + HV_VCON_RX_WORK.count]
    call hv_vcon_rx_disjoint
    test eax, eax
    jz   .out
    mov  eax, [rsp + HV_VCON_RX_WORK.count]
    shl  eax, 4
    mov  [rsp + HV_VCON_RX_WORK.segments + rax], rdx
    mov  [rsp + HV_VCON_RX_WORK.segments + rax + 8], rcx
    add  [rsp + HV_VCON_RX_WORK.capacity], rcx
    inc  dword [rsp + HV_VCON_RX_WORK.count]
    test dword [rsp + HV_VCON_RX_WORK.flags], 1
    jz   .preflight_done
    mov  r9d, [rsp + HV_VCON_RX_WORK.next]
    jmp  .chain
.preflight_done:
    cmp  [rsp + HV_VCON_RX_WORK.capacity], r13
    jb   .out
    ; Never continue a snapshot across START/STOP or a changed RAM backing.
    mov  eax, [rsp + HV_VCON_RX_WORK.generation]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .out
    mov  rax, [rsp + HV_VCON_RX_WORK.region]
    cmp  rax, [rel hv_linux_region]
    jne  .out
    mov  rax, [rsp + HV_VCON_RX_WORK.ram]
    cmp  rax, [rel hv_linux_ram]
    jne  .out
    mov  rax, [rsp + HV_VCON_RX_WORK.ram_bytes]
    cmp  rax, [rel hv_linux_ram_bytes]
    jne  .out
    cmp  byte [rel hv_linux_running], 1
    jne  .out
    test dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    jz   .out
    cmp  byte [rel hv_vcon_ready], 1
    jne  .out
    cmp  word [rel hv_vcon_q_ready], 0x0101
    jne  .out

    mov  rdi, rsp
    call hv_vcon_owner_current
    test eax, eax
    jz   .out

    ; No failure, guest metadata reads, or yielding call after the first copy.
    lea  rsi, [rel hv_vcon_rxbuf]
    mov  r8d, r13d
    xor  r9d, r9d
.scatter:
    mov  eax, r9d
    shl  eax, 4
    mov  rdi, [rsp + HV_VCON_RX_WORK.segments + rax]
    mov  rcx, [rsp + HV_VCON_RX_WORK.segments + rax + 8]
    cmp  rcx, r8
    cmova rcx, r8
    sub  r8, rcx
    rep  movsb
    inc  r9d
    test r8d, r8d
    jnz  .scatter
    mov  ecx, [rsp + HV_VCON_RX_WORK.usedidx]
    lea  eax, [r14d - 1]
    and  eax, ecx
    lea  rdi, [r12 + 4 + rax*8]
    mov  edx, [rsp + HV_VCON_RX_WORK.head]
    mov  [rdi], edx
    mov  [rdi + 4], r13d
    inc  ecx
    mov  [rel hv_vcon_q_usedidx], cx
    sfence                               ; all payload + used entry before idx
    mov  [r12 + 2], cx
    mov  ecx, [rsp + HV_VCON_RX_WORK.lastav]
    inc  ecx
    mov  [rel hv_vcon_q_lastav], cx
    inc  dword [rel hv_vcon_rx_used]
    call hv_vcon_raise_irq
    mov  r15d, 1
.out:
    mov  eax, r15d
    add  rsp, HV_VCON_RX_WORK_size
.restore:
    popfq
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

.warm_refused:
    xor  eax, eax
    ret

; Binary ingress shares the proven line sender's split-ring walker. No LF/NUL
; is appended. RDI=owned bytes, ESI=1..256; EAX=1 accepted, 0 backpressure.
hv_vcon_rx_bytes:
    cmp qword [rel hv_terminal_owner], 0
    jne .bad                              ; no other producer interleaves shell input
    cmp  byte [rel hvp_bound], 0
    jne  .bad
    test dword [rel vm_profile_live_devices], VP_DEV_PINCHAN
    jnz  .bad
    test dword [rel vm_profile_live_devices], VP_DEV_WARMCHAN
    jnz  .bad                              ; private native owner only
.private_warm:
.private_pin:                               ; only hv_pin_send after complete owner check
.terminal_owned:                           ; hv_terminal_write checked exact shell owner
    HV_POWER_WORK hv_vcon_rx_bytes, 0, hv_guest_power_io_admit
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_discard], 1
    jne  .binary_available
    cmp  byte [rel hv_vcon_pmr_bound], 1
    je   .bad                              ; no queued host record crosses STOP
.binary_available:
%endif
%endif
    test esi, esi
    jz .bad
    cmp esi, 256
    ja .bad
    push rbx
    push r12
    push r13
    push r14
    push r15
    pushfq
    cld
    mov r13d, esi
    mov ecx, esi
    mov rsi, rdi
    lea rdi, [rel hv_vcon_rxbuf]
    rep movsb
    jmp hv_vcon_rx_line.send
.bad:
    xor eax, eax
    ret

; Inject the console's IRQ5 only when the guest's real PIC/IF/shadow admits it.
hv_try_inject_vcon:
    HV_POWER_WORK hv_try_inject_vcon, 0, hv_guest_power_io_admit
    cmp  byte [rel hv_vcon_irq_pend], 1
    jne  .no
    cmp  byte [rel hv_vcon_irq_inj], 0
    jne  .no
    mov  edi, 5
    call hv_pic_try_inject
    test eax, eax
    jz   .no
    mov  byte [rel hv_vcon_irq_inj], 1
    ret
.no:
    xor  eax, eax
    ret

; RCQ-36: the guest UART's THRE interrupt on IRQ4, as a 16550 raises it: IER
; ETBEI and MCR OUT2 gate the line, and because THR drains at once THRE is
; asserted after every THR write or ETBEI 0->1 edge until an IIR read reports
; it. One injection per assertion. Without it Linux's 8250 tty layer (not the
; polled printk console) sends one byte and waits forever for TX interrupts.
hv_try_inject_uart:
    HV_POWER_WORK hv_try_inject_uart, 0, hv_guest_power_io_admit
    test byte [rel hv_linux_uart + 3], 0x80  ; DLAB: offset 1 is DLM
    jnz  .no
    test byte [rel hv_linux_uart + 1], 2     ; IER ETBEI
    jz   .no
    test byte [rel hv_linux_uart + 4], 8     ; MCR OUT2
    jz   .no
    cmp  word [rel hv_uart_thre], 0          ; asserted, not yet reported or injected
    jne  .no
    mov  edi, 4
    call hv_pic_try_inject
    test eax, eax
    jz   .no
    mov  byte [rel hv_uart_thre + 1], 1
    ret
.no:
    xor  eax, eax
    ret

; Classic E2/E3 IRQ0 gate: a tick is counted only after a valid VM-entry
; external-interrupt field is written while PIC, IF, and shadow all admit it.
hv_try_inject_tick:
    xor  edi, edi
    call hv_pic_try_inject
    test eax, eax
    jz   .no
    inc  dword [rel hv_tick_inj_ct]
    inc  qword [rel hv_guestcpu_interrupts]
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_last_tick_tsc], rax
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hv_glapic_msr(ECX = MSR, EDX = 1 for WRMSR) -> EAX = GLAPIC_MSR_* (RCQ-50 S4).
; The WRMSR value is the guest's EDX:EAX; time is the guest's TSC.
hv_glapic_msr:
    mov  r8d, edx
    mov  r9d, ecx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rax, [rel gsn_tsc_offset]
    mov  rcx, rax
    mov  esi, [rel hv_linux_gpr + 0]
    mov  eax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax
    mov  edi, r9d
    mov  edx, r8d
    cmp  qword [rel vca_ready], 0
    je   .legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    push rdx
    call vcb_lapic_msr
    pop  rcx
    test ecx, ecx
    jnz  .out
    cmp  eax, GLAPIC_MSR_NONE
    je   .out
    mov  [rel glapic_msr_value], rdx
.out:
    ret
.legacy:
    jmp  glapic_msr

; hv_inject_gp: #GP(0) on the next VM entry (RCQ-50 S4: a refused x2APIC MSR).
hv_inject_gp:
    mov  edi, VMXF_ENTRY_ERRCODE
    xor  esi, esi
    call hv_guest_write
    mov  edi, VMXF_ENTRY_INTR
    mov  esi, HV_GUEST_GP_INFO
    jmp  hv_guest_write

; hv_glapic_try_inject -> EAX = 1 when a guest LAPIC vector was injected (RCQ-50 S4).
hv_glapic_try_inject:
    xor  eax, eax
    cmp  byte [rel glapic_on], 1
    jne  .out
    call hv_can_inject_extint
    mov  esi, eax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rax, [rel gsn_tsc_offset]
    mov  rdi, rax
    cmp  qword [rel vca_ready], 0
    je   .legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    call vcb_lapic_pick
    jmp  .picked
.legacy:
    call glapic_inject_pick
.picked:
    cmp  eax, -1
    je   .none
    mov  edi, eax
    call hv_inject_extint
    inc  qword [rel hv_guestcpu_interrupts]
    mov  eax, 1
    ret
.none:
    xor  eax, eax
.out:
    ret

hv_try_inject_tick_due:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, [rel hv_last_tick_tsc]
    test rcx, rcx
    jz   .due
    mov  rdx, [rel tsc_khz]                 ; ticks per millisecond
    test rdx, rdx
    jnz  .rate
    mov  rdx, 3000000
.rate:
    add  rcx, rdx
    cmp  rax, rcx
    jae  .due
    xor  eax, eax
    ret
.due:
    call vtd_guest_dataplane_timer_due
    jmp  hv_try_inject_tick

; Yield only from a clean VM-exit boundary. Classic proved that yielding during
; Linux's initial timer calibration can freeze jiffies, so run flat-out through
; kboot (with a two-second fail-open grace if init never appears). IF is enabled
; for host tasks and disabled again before VMCS/VMRESUME.
hv_linux_host_slice:
    ; A handoff owns the AP VMCS: never release custody, STI or schedule here.
    cmp  dword [rel vcb_handoff_active], 0
    jne  .handoff_return
%ifidn RCQ_SERVICE_PROGRESS_PRERX,1
    call service_progress_prerx_slice_enter
%endif
    cmp  byte [rel hvw_bound], 1
    jne  .warm_policy_done
    call hvw_policy
    test eax, eax
    jnz  .warm_policy_done
    call hvw_revoke
.warm_policy_done:
    call vtd_deadman_check                   ; VM-exit heartbeat owns lease expiry
    call hv_vmx_two_vcpu                     ; ROOT109896 (4) H2/H4: VMX two-vCPU never waits on kboot
    test eax, eax                            ; or the grace, as SVM vsm_enter already runs
    jnz  .yield
    cmp  byte [rel hv_linux_kboot], 1
    je   .yield
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel hv_linux_run_start_tsc]
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .rate
    mov  rcx, 3000000
.rate:
    imul rcx, rcx, HV_LINUX_BOOT_GRACE_MS
    cmp  rax, rcx
    jb   .grace
.yield:
    call hv_svm_host_release                ; full SVM host restore/AP release before scheduling
    call hv_vmx_host_release                ; closed Intel pair/writer gate before STI/yield
    inc  dword [rel hv_linux_host_slices]    ; RCQ-18 S2-0: a slice that ran host work
    call hv_linux_slice_yield_begin          ; T2-4 D8: passive timing only
    sti
    call sched_yield
    cli
    call hv_linux_slice_yield_end
    call hv_vmx_host_deadline_renew          ; SEC109922 G1: the next deadline runs from this turn's END
.done:
%ifidn RCQ_SERVICE_PROGRESS_PRERX,1
    call service_progress_prerx_slice_return
%endif
    ret

.handoff_return:
    ret

.grace:
    ; Single-vCPU Classic grace (SEC109914 named residual): no host turn, and the
    ; guest keeps a whole window, as before the deadline existed. Never reached
    ; by the two-vCPU profile, and it ends 2 s after hv_linux_arm_deadline.
    call hv_vmx_host_deadline_renew
    jmp  .done

; ROOT109896 (4), SEC109899 H1-H4, SEC109922 G1: the VMX host-turn deadline.
; hv_vmx_host_deadline is set at launch and at the END of each host turn, and
; nowhere else on the two-vCPU profile. Every resuming VMX exit checks it, and
; every BSP entry programs the preemption timer to the time left, never less
; than Q_min of guest time. None of this acts during an AP handoff (the AP VMCS
; is current and there is no guest entry; the owed turn is taken at the first
; BSP exit after it) or on SVM, which keeps its own runners.

; EAX = 1 on VMX with the two-vCPU profile: the same profile test that
; hv_svm_linux_enter uses to route to vsm_enter.
hv_vmx_two_vcpu:
    xor  eax, eax
    lea  rdx, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], rdx
    jne  .out
    mov  rdx, [rel vm_profile_active]
    test rdx, rdx
    jz   .out
    cmp  dword [rdx + 36], 2
    jne  .out
    mov  eax, 1
.out:
    ret

; RAX = TSC ticks in one 1 ms window: tsc_khz, or the file's bounded fallback.
hv_vmx_turn_rate:
    mov  rax, [rel tsc_khz]
    test rax, rax
    jnz  .out
    mov  eax, 3000000
.out:
    ret

; Deadline = now + one window. Clobbers RAX, RCX, RDX.
hv_vmx_host_deadline_renew:
    call hv_vmx_turn_rate
    mov  rcx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rax, rcx
    mov  [rel hv_vmx_host_deadline], rax
    ret

; First instruction of every resuming exit (hv_linux_exit_dispatch .resume),
; whatever the reason: a due deadline takes the host turn before resuming.
hv_vmx_host_turn_due:
    lea  rax, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], rax
    jne  .out
    cmp  dword [rel vcb_handoff_active], 0
    jne  .out                                ; H3(b): no turn and no window spent here
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel hv_vmx_host_deadline]
    jb   .out
    call hv_linux_host_slice                 ; renews the deadline at the turn's end
.out:
    ret

; Before every VMX BSP entry: preemption timer = the time left to the deadline,
; at most one window, at least Q_min (G1: the guest always progresses), at
; least one tick. Never during a handoff: the AP VMCS is current then.
hv_vmx_host_timer_arm:
    lea  rax, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], rax
    jne  .out
    cmp  dword [rel vcb_handoff_active], 0
    jne  .out
    push rbx
    call hv_vmx_turn_rate
    mov  rbx, rax                            ; one window
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rsi, [rel hv_vmx_host_deadline]
    sub  rsi, rax
    jae  .left
    xor  esi, esi                            ; already due
.left:
    cmp  rsi, rbx
    jbe  .capped
    mov  rsi, rbx
.capped:
    mov  rax, rbx
    shr  rax, HV_VMX_GUEST_FLOOR_SHIFT        ; Q_min
    cmp  rsi, rax
    jae  .floored
    mov  rsi, rax
.floored:
    mov  ecx, 0x485
    rdmsr                                    ; IA32_VMX_MISC[4:0]: timer rate
    and  eax, 0x1F
    mov  ecx, eax
    shr  rsi, cl
    test rsi, rsi
    jnz  .write
    mov  esi, 1
.write:
    mov  edi, VMXF_PREEMPT_TIMER
    call hv_w
    pop  rbx
.out:
    ret

; T2-4 D8 (VM 107717) passive host-slice timing. Diagnostic only: nothing reads
; these values except hv_render_stat. Begin records the yield start and the gap
; since the previous yield's end; the first yield of a START only sets the
; baseline, so the designed pre-kboot grace is never a gap. Clobbers RAX,RCX,RDX.
hv_linux_slice_yield_begin:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_slice_begin_tsc], rax
    mov  rcx, [rel hv_linux_slice_end_tsc]
    test rcx, rcx
    jz   .out
    sub  rax, rcx
    jb   .out                                ; a backwards TSC records nothing
    cmp  rax, [rel hv_linux_slice_max_gap_tsc]
    jbe  .out
    mov  [rel hv_linux_slice_max_gap_tsc], rax
.out:
    ret

; End adds the time spent in sched_yield and sets the next gap's start.
hv_linux_slice_yield_end:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_slice_end_tsc], rax
    sub  rax, [rel hv_linux_slice_begin_tsc]
    jb   .out
    add  [rel hv_linux_slice_yield_tsc], rax
    jnc  .out
    mov  qword [rel hv_linux_slice_yield_tsc], -1 ; saturate
.out:
    ret

; Preserve an event interrupted during delivery. Without this Classic-proven
; reinjection, a host external interrupt can swallow guest IRQ0/IRQ5 after VM
; entry accepted it but before the guest reached its handler.
hv_linux_reinject_vectoring:
    mov  edi, VMXF_IDT_VEC_INFO
    call hv_guest_read
    test eax, 0x80000000
    jz   .done
    mov  ebx, eax
    test eax, 0x800
    jz   .no_error
    mov  edi, VMXF_IDT_VEC_ERR
    call hv_guest_read
    mov  edi, VMXF_ENTRY_ERRCODE
    mov  esi, eax
    call hv_guest_write
.no_error:
    mov  ecx, ebx
    shr  ecx, 8
    and  ecx, 7
    cmp  ecx, 4
    jb   .write
    mov  edi, VMXF_EXIT_ILEN
    call hv_guest_read
    mov  edi, VMXF_ENTRY_ILEN
    mov  esi, eax
    call hv_guest_write
.write:
    mov  esi, ebx
    and  esi, 0x80000FFF
    mov  edi, VMXF_ENTRY_INTR
    call hv_guest_write
.done:
    ret

hv_first_ud_reset:
    push rdi
    push rcx
    xor  eax, eax
    mov  byte [rel hv_first_ud_diag_active], al
    lea  rdi, [rel hv_first_ud_receipt_begin]
    mov  ecx, (hv_first_ud_receipt_end - hv_first_ud_receipt_begin) / 8
    cld
    rep  stosq
    pop  rcx
    pop  rdi
    ret

; Capture the exact first #UD while the VMCS and saved GPR image still belong
; to the armed VTD generation. Registers, raw translation, instruction bytes,
; and preceding console are frozen before the valid bit is published.
hv_first_ud_capture:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel hv_first_ud_gen]
    jne  .out
    mov  edi, VMXF_EXIT_REASON
    call hv_guest_read
    and  eax, 0xFFFF
    mov  [rel hv_first_ud_exit_reason], rax
    mov  edi, VMXF_EXIT_INTR_INFO
    call hv_guest_read
    mov  eax, eax
    mov  [rel hv_first_ud_info], rax
    xor  ebx, ebx
    test eax, 0x800
    jz   .no_exit_error
    mov  edi, VMXF_EXIT_INTR_ERR
    call hv_guest_read
    mov  rbx, rax
.no_exit_error:
    mov  [rel hv_first_ud_error], rbx
    mov  edi, VMXF_IDT_VEC_INFO
    call hv_guest_read
    mov  eax, eax
    mov  [rel hv_first_ud_idt_info], rax
    xor  ebx, ebx
    test eax, 0x800
    jz   .no_idt_error
    mov  edi, VMXF_IDT_VEC_ERR
    call hv_guest_read
    mov  rbx, rax
.no_idt_error:
    mov  [rel hv_first_ud_idt_error], rbx

    mov  edi, VMXF_G_RIP
    call hv_guest_read
    mov  [rel hv_first_ud_rip], rax
    mov  edi, VMXF_G_RSP
    call hv_guest_read
    mov  [rel hv_first_ud_rsp], rax
    mov  edi, VMXF_G_RFLAGS
    call hv_guest_read
    mov  [rel hv_first_ud_rflags], rax
    mov  rax, cr2
    mov  [rel hv_first_ud_cr2], rax
    mov  edi, VMXF_G_CR3
    call hv_guest_read
    mov  [rel hv_first_ud_cr3], rax
    mov  edi, VMXF_G_CR4
    call hv_guest_read
    mov  [rel hv_first_ud_cr4], rax
    mov  edi, VMXF_GUEST_CS_SEL
    call hv_guest_read
    mov  [rel hv_first_ud_cs], rax
    mov  eax, [rel hv_vcon_capture_len]
    mov  [rel hv_first_ud_console_len], rax
    mov  eax, [rel hv_vcon_capture_overflow]
    mov  [rel hv_first_ud_console_overflow], rax
    inc  qword [rel hv_first_ud_ordinal]

    lea  rsi, [rel hv_linux_gpr]
    lea  rdi, [rel hv_first_ud_gpr]
    mov  ecx, 15
    cld
    rep  movsq

    mov  ecx, [rel hv_vcon_capture_len]
    cmp  ecx, HV_VCON_CAP_MAX - 1
    jbe  .console_len_ok
    mov  ecx, HV_VCON_CAP_MAX - 1
.console_len_ok:
    lea  rsi, [rel hv_vcon_capture]
    lea  rdi, [rel hv_first_ud_console]
    rep  movsb

    mov  rdi, [rel hv_first_ud_rip]
    mov  rsi, [rel hv_first_ud_cr3]
    lea  rdx, [rel hv_first_ud_insn]
    mov  ecx, HV_FIRST_UD_BYTES
    mov  r8, [rel hv_linux_ram]
    mov  r9, [rel hv_linux_ram_bytes]
    call hv_linux_gva_copy_core
    mov  r15d, eax

    ; Re-walk RIP after the cross-page copy so raw levels describe byte zero.
    mov  rdi, [rel hv_first_ud_rip]
    mov  rsi, [rel hv_first_ud_cr3]
    mov  r8, [rel hv_linux_ram]
    mov  r9, [rel hv_linux_ram_bytes]
    call hv_linux_gva_walk_core
    mov  rax, [rel hv_gva_walk_pml4e]
    mov  [rel hv_first_ud_pml4e], rax
    mov  rax, [rel hv_gva_walk_pdpte]
    mov  [rel hv_first_ud_pdpte], rax
    mov  rax, [rel hv_gva_walk_pde]
    mov  [rel hv_first_ud_pde], rax
    mov  rax, [rel hv_gva_walk_pte]
    mov  [rel hv_first_ud_pte], rax
    mov  rax, [rel hv_gva_walk_page_size]
    mov  [rel hv_first_ud_page_size], rax
    mov  rax, [rel hv_gva_walk_gpa]
    mov  [rel hv_first_ud_gpa], rax
    mov  rax, [rel hv_gva_walk_offset]
    mov  [rel hv_first_ud_offset], rax
    test r15d, r15d
    jz   .walker_done
    cmp  byte [rel hv_gva_walk_valid], 1
    jne  .walker_done
    mov  qword [rel hv_first_ud_insn_len], HV_FIRST_UD_BYTES
    mov  qword [rel hv_first_ud_walker_valid], 1
.walker_done:
    mov  qword [rel hv_first_ud_no_reinject], 1
    mov  qword [rel hv_first_ud_valid], 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

hv_linux_exit_dispatch:
    mov  edi, VMXF_EXIT_REASON
    call hv_guest_read
    test eax, 0x80000000
    jnz  .entry_fail
    and  eax, 0xFFFF
    mov  [rel hv_exit_reason], eax
    inc  dword [rel hv_linux_exits]
    call hv_linux_exit_observe
    call hv_linux_async_observe
    cmp  byte [rel hv_panic_injected], 1
    jne  .decode
    cmp  byte [rel hv_panic_text], 1
    jne  .decode
    mov  byte [rel hv_linux_panicked], 1     ; real guest console fatal evidence
    inc  qword [rel hv_guestcpu_faults]
    xor  eax, eax
    ret
.decode:
    cmp  eax, 0
    je   .reason0
    cmp  eax, 1
    je   .extint
    cmp  eax, 7
    je   .intrwin
    cmp  eax, 10
    je   .cpuid
    cmp  eax, 12
    je   .hlt
    cmp  eax, 28
    je   .craccess
    cmp  eax, 29
    je   .draccess
    cmp  eax, 30
    je   .pio
    cmp  eax, 31
    je   .rdmsr
    cmp  eax, 32
    je   .wrmsr
    cmp  eax, 48
    je   .eptviol
    cmp  eax, 52
    je   .timer
    cmp  eax, 55
    je   .xsetbv
    ; EPT violations and unknown exits stop cleanly.
    mov  byte [rel hv_linux_load_err], 7
    xor  eax, eax
    ret

.reason0:
    mov  edi, VMXF_EXIT_INTR_INFO
    call hv_guest_read
    mov  ebx, eax
    ; Retain the first reason-0 event independently of #UD validity. This is
    ; diagnostic only and never changes stop/reinjection behavior.
    cmp  byte [rel hv_first_ud_diag_active], 1
    jne  .reason0_classify
    cmp  qword [rel hv_first_ud_first_r0_info], 0
    jne  .reason0_classify
    mov  [rel hv_first_ud_first_r0_info], rax
    mov  ecx, [rel hv_linux_start_consumed]
    mov  [rel hv_first_ud_first_r0_gen], rcx
.reason0_classify:
    mov  edi, ebx
    call hv_first_ud_info_is_exact
    test eax, eax
    jz   .reason0_stop
    cmp  byte [rel hv_first_ud_diag_active], 1
    jne  .reason0_stop
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel hv_first_ud_gen]
    jne  .reason0_stop
    call hv_first_ud_capture
.reason0_stop:
    mov  byte [rel hv_linux_load_err], 7
    xor  eax, eax
    ret

.eptviol:
    call hv_linux_virtio_mmio
    test eax, eax
    jz   .stop
    jmp  .resume
.stop:
    ret
.entry_fail:
    mov  byte [rel hv_linux_load_err], 6
    inc  qword [rel hv_guestcpu_faults]
    xor  eax, eax
    ret

.extint:
    inc  dword [rel hv_linux_intr_exits]     ; RCQ-18 S2-0: the M3 heartbeat (both vendors)
    ; ACK-on-exit is disabled and checked at VMCS setup: this host IRQ is
    ; still pending, not a vector to EOI here. Let the ordinary host IDT
    ; handler service its device and owning controller (PIC/xAPIC/x2APIC).
    ; An EOI alone used to discard PS/2 IRQ1 without consuming port 0x60;
    ; input then stopped while the Linux guest was CPU-bound. Match SVM's
    ; host window. NOP crosses STI's shadow; CLI restores the VM-exit IF=0
    ; contract before touching VMCS or resuming guest vector state.
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_fail_stop                     ; AP handles its own external IRQ locally
    call hv_vmx_host_release                ; exact closed Intel generation before STI
    sti
    nop
    cli
    jmp  .resume

.cpuid:
    mov  eax, [rel hv_linux_gpr + 0]
    mov  ecx, [rel hv_linux_gpr + 16]
    mov  edi, eax
    mov  esi, ecx
    cmp  qword [rel vca_ready], 0
    je   .cpuid_legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    call vcb_cpuid                         ; frozen two-CPU model, no native CPUID
    jmp  .cpuid_save
.cpuid_legacy:
    ; Neither VMX nor SVM implements an outer hypervisor's paravirtual ABI.
    ; Do not forward its vendor/features (including offset KVM namespaces):
    ; Linux would otherwise use KVM pvclock pages/MSRs that we never service.
    cmp  edi, 0x40000000
    jb   .cpuid_native
    cmp  edi, 0x50000000
    jae  .cpuid_native
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    jmp  .cpuid_store
.cpuid_native:
    cpuid
    call hv_linux_cpuid_filter               ; V4: enumerate only scheduler-switched state
.cpuid_store:
    call hv_svm_cpuid_mask                   ; RCQ-18 S1b: an SVM guest sees no SVM
    call glapic_cpuid                        ; RCQ-50 S4: selected single LAPIC
.cpuid_save:
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 8], rbx
    mov  [rel hv_linux_gpr + 16], rcx
    mov  [rel hv_linux_gpr + 24], rdx
    call hv_skip_instr
    jmp  .resume

.rdmsr:
    cmp  qword [rel vca_ready], 0
    je   .rdmsr_legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    mov  ecx, [rel hv_linux_gpr + 16]
    xor  edx, edx
    call hv_glapic_msr
    cmp  eax, GLAPIC_MSR_DONE
    je   .rd_glapic
    ja   .msr_gp
    mov  edi, [rel hv_linux_gpr + 16]
    xor  edx, edx
    xor  esi, esi
    call vcb_msr
    cmp  eax, 1
    jne  .msr_gp
    mov  rax, rdx
    shr  rdx, 32
    mov  eax, eax
    mov  [rel hv_linux_gpr], rax
    mov  [rel hv_linux_gpr + 24], rdx
    call hv_skip_instr
    jmp  .resume
.rdmsr_legacy:
    mov  ecx, [rel hv_linux_gpr + 16]
    xor  edx, edx
    call hv_glapic_msr                       ; RCQ-50 S4: APIC_BASE and x2APIC MSRs of a selected LAPIC
    cmp  eax, GLAPIC_MSR_DONE
    je   .rd_glapic
    ja   .msr_gp
    mov  ecx, [rel hv_linux_gpr + 16]
    cmp  ecx, 0x174
    je   .rd_syscs
    cmp  ecx, 0x175
    je   .rd_sysesp
    cmp  ecx, 0x176
    je   .rd_syseip
    cmp  ecx, 0xC0000100
    je   .rd_fs
    cmp  ecx, 0xC0000101
    je   .rd_gs
    cmp  ecx, 0xE7
    je   .rd_perf
    cmp  ecx, 0xE8
    je   .rd_perf
    cmp  ecx, 0x10
    je   .rd_tsc
    cmp  ecx, 0x1B
    je   .rd_pass
    cmp  ecx, 0x1A0
    je   .rd_pass
    cmp  ecx, 0xFE
    je   .rd_pass
    cmp  ecx, 0x2FF
    je   .rd_pass
    cmp  ecx, 0x277
    je   .rd_pass
    cmp  ecx, 0xC0000080
    je   .rd_pass
    ; Match the existing syscall-MSR write allowlist. VMX keeps these guest
    ; hardware values live until hv_linux_restore_host at teardown; returning
    ; unsupported-zero here loses an accepted write. SVM already clears both
    ; intercept bits and swaps this state through VMLOAD/VMSAVE.
    cmp  ecx, 0xC0000081
    je   .rd_pass
    cmp  ecx, 0xC0000082
    je   .rd_pass
    cmp  ecx, 0xC0000083
    je   .rd_pass
    cmp  ecx, 0xC0000084
    je   .rd_pass
    cmp  ecx, 0xC0000102
    je   .rd_pass
    cmp  ecx, 0x8B
    je   .rd_pass
    cmp  ecx, 0xCE
    je   .rd_pass
    mov  qword [rel hv_linux_gpr + 0], 0
    mov  qword [rel hv_linux_gpr + 24], 0
    call hv_skip_instr                       ; unsupported MSRs read zero
    jmp  .resume
.rd_glapic:
    mov  rax, [rel glapic_msr_value]
    mov  rdx, rax
    shr  rdx, 32
    mov  eax, eax
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 24], rdx
    call hv_skip_instr
    jmp  .resume
.msr_gp:
    call hv_inject_gp                        ; the instruction faults: RIP stays on it
    jmp  .resume
.rd_perf:
    rdtsc
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 24], rdx
    call hv_skip_instr
    jmp  .resume
.rd_tsc:
    rdtsc                                    ; RCQ-18 S2: same offset as guest RDTSC
    shl  rdx, 32
    or   rax, rdx
    add  rax, [rel gsn_tsc_offset]
    mov  rdx, rax
    shr  rdx, 32
    mov  eax, eax
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 24], rdx
    call hv_skip_instr
    jmp  .resume
.rd_pass:
    mov  ecx, [rel hv_linux_gpr + 16]
    call hv_svm_msr_read                     ; RCQ-18 S1b: SVM's EFER/PAT and the Intel-only
    test eax, eax                            ; 0xCE/0x1A0 never reach a host RDMSR on AMD
    jnz  .rd_served
    rdmsr
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 24], rdx
.rd_served:
    call hv_skip_instr
    jmp  .resume
.rd_fs:
    mov  edi, VMXF_G_FS_BASE
    jmp  .rd_vmcs
.rd_gs:
    mov  edi, VMXF_G_GS_BASE
    jmp  .rd_vmcs
.rd_syscs:
    mov  edi, VMXF_G_SYSENTER_CS
    jmp  .rd_vmcs
.rd_sysesp:
    mov  edi, VMXF_G_SYSENTER_ESP
    jmp  .rd_vmcs
.rd_syseip:
    mov  edi, VMXF_G_SYSENTER_EIP
.rd_vmcs:
    call hv_guest_read
    mov  rdx, rax
    shr  rdx, 32
    mov  eax, eax
    mov  [rel hv_linux_gpr + 0], rax
    mov  [rel hv_linux_gpr + 24], rdx
    call hv_skip_instr
    jmp  .resume

.wrmsr:
    cmp  qword [rel vca_ready], 0
    je   .wrmsr_legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    mov  ecx, [rel hv_linux_gpr + 16]
    mov  edx, 1
    call hv_glapic_msr
    cmp  eax, GLAPIC_MSR_DONE
    je   .wr_glapic
    ja   .msr_gp
    mov  edi, [rel hv_linux_gpr + 16]
    mov  esi, [rel hv_linux_gpr]
    mov  eax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax
    mov  edx, 1
    call vcb_msr
    cmp  eax, 1
    jne  .msr_gp
    call hv_skip_instr
    jmp  .resume
.wrmsr_legacy:
    mov  ecx, [rel hv_linux_gpr + 16]
    mov  edx, 1
    call hv_glapic_msr                       ; RCQ-50 S4
    cmp  eax, GLAPIC_MSR_DONE
    je   .wr_glapic
    ja   .msr_gp
    mov  ecx, [rel hv_linux_gpr + 16]
    cmp  ecx, 0xC0000100
    je   .wr_fs
    cmp  ecx, 0xC0000101
    je   .wr_gs
    cmp  ecx, 0x174
    je   .wr_syscs
    cmp  ecx, 0x175
    je   .wr_sysesp
    cmp  ecx, 0x176
    je   .wr_syseip
    cmp  ecx, 0xC0000080
    je   .wr_efer
    cmp  ecx, 0xC0000102
    je   .wr_pass
    cmp  ecx, 0xC0000081
    je   .wr_pass
    cmp  ecx, 0xC0000082
    je   .wr_pass
    cmp  ecx, 0xC0000083
    je   .wr_pass
    cmp  ecx, 0xC0000084
    je   .wr_pass
    call hv_skip_instr                       ; unsupported MSRs write-ignore
    jmp  .resume
.wr_glapic:
    call hv_skip_instr
    jmp  .resume
.wr_fs:
    mov  edi, VMXF_G_FS_BASE
    jmp  .wr_vmcs
.wr_gs:
    mov  edi, VMXF_G_GS_BASE
    jmp  .wr_vmcs
.wr_sysesp:
    mov  edi, VMXF_G_SYSENTER_ESP
    jmp  .wr_vmcs
.wr_syseip:
    mov  edi, VMXF_G_SYSENTER_EIP
    jmp  .wr_vmcs
.wr_syscs:
    mov  edi, VMXF_G_SYSENTER_CS
    mov  esi, [rel hv_linux_gpr + 0]
    call hv_guest_write
    call hv_skip_instr
    jmp  .resume
.wr_vmcs:
    mov  esi, [rel hv_linux_gpr + 0]
    mov  eax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax
    call hv_guest_write
    call hv_skip_instr
    jmp  .resume
.wr_efer:
    call hv_svm_efer_write                   ; RCQ-18 S1b: SVM's guest EFER is the VMCB's
    test eax, eax
    jnz  .wr_efer_done
    mov  ebx, [rel hv_linux_gpr + 0]
    and  ebx, 0x801                          ; SCE + NXE only
    mov  ecx, 0xC0000080
    rdmsr
    or   eax, ebx
    wrmsr
.wr_efer_done:
    call hv_skip_instr
    jmp  .resume
.wr_pass:
    mov  ecx, [rel hv_linux_gpr + 16]
    mov  eax, [rel hv_linux_gpr + 0]
    mov  edx, [rel hv_linux_gpr + 24]
    wrmsr
    call hv_skip_instr
    jmp  .resume

.pio:
    mov  edi, VMXF_EXIT_QUAL
    call hv_guest_read
    push rax                            ; retain original qualification
    mov  edi,eax
    mov  esi,[rel hv_linux_gpr]
    call guest_transport_pio             ; stopped vCPU, scalar dedicated ports
    test eax,eax
    jnz .pio_snapshot_checked
    mov edi,[rsp]
    mov esi,[rel hv_linux_gpr]
    call snapshot_driver_pio
    test eax,eax
    jnz .pio_snapshot_checked
    mov edi,[rsp]
    mov esi,[rel hv_linux_gpr]
    call terminal_driver_pio
.pio_snapshot_checked:
    pop  rcx
    test eax,eax
    jz   .pio_legacy
    test ecx,8
    jz   .pio_done
    mov  [rel hv_linux_gpr],edx
    mov  dword [rel hv_linux_gpr+4],0      ; x86 IN EAX zero extends
    jmp  .pio_done
.pio_legacy:
    mov  eax,ecx
    mov  r8d, eax                            ; size/direction in qualification
    mov  edx, eax
    shr  edx, 16
    and  edx, 0xFFFF                         ; port
    test r8d, 8
    jnz  .pio_in
    cmp  edx, 0xCF8
    je   .pio_out_vtd
    cmp  edx, 0xCFC
    jb   .pio_out_normal
    cmp  edx, 0xCFF
    jbe  .pio_out_vtd
.pio_out_normal:
    mov  eax, edx
    sub  eax, 0x3F8
    cmp  eax, 8
    jae  .pio_out_pitpic                     ; non-UART OUT: proven PIC/PIT-lite
    test eax, eax
    jnz  .pio_reg_out
    test byte [rel hv_linux_uart + 3], 0x80  ; DLAB overlays divisor latch
    jnz  .pio_reg_out
    mov  al, [rel hv_linux_gpr + 0]
    mov  word [rel hv_uart_thre], 0          ; RCQ-36: THR drains at once, THRE reasserts
    call hv_vcon_run_tail_byte              ; RUN observes real UART TX as well as hvc0
    call hv_linux_console_char
    jmp  .pio_done
.pio_reg_out:
    mov  cl, [rel hv_linux_gpr + 0]
    lea  rdi, [rel hv_linux_uart]
    cmp  eax, 1
    jne  .pio_reg_store
    test byte [rdi + 3], 0x80                ; DLM, not IER
    jnz  .pio_reg_store
    test byte [rdi + 1], 2
    jnz  .pio_reg_store
    test cl, 2
    jz   .pio_reg_store
    mov  word [rel hv_uart_thre], 0          ; RCQ-36: ETBEI 0->1 with THR empty asserts THRE
.pio_reg_store:
    mov  [rdi + rax], cl
    jmp  .pio_done
.pio_out_vtd:
    call hv_vpci_out                         ; RCQ-36 V2: assigned-function shadow, else VT-d
    jmp  .pio_done
.pio_in:
    cmp  edx, 0xCF8
    je   .pio_in_vtd
    cmp  edx, 0xCFC
    jb   .pio_in_normal
    cmp  edx, 0xCFF
    jbe  .pio_in_vtd
.pio_in_normal:
    mov  eax, edx
    sub  eax, 0x3F8
    cmp  eax, 8
    jae  .pio_in_pitpic
    cmp  eax, 5
    je   .pio_lsr
    cmp  eax, 2
    je   .pio_iir
    lea  rdi, [rel hv_linux_uart]
    movzx ecx, byte [rdi + rax]
    jmp  .pio_store
.pio_lsr:
    mov  ecx, 0x60                           ; THR empty + transmitter empty
    jmp  .pio_store
.pio_iir:
    mov  ecx, 1                              ; no pending interrupt
    test byte [rel hv_linux_uart + 1], 2     ; RCQ-36: ETBEI (IER; IIR ignores DLAB)
    jz   .pio_store
    cmp  byte [rel hv_uart_thre], 0
    jne  .pio_store
    mov  byte [rel hv_uart_thre], 1          ; reading IIR clears a THRE source
    mov  ecx, 2                              ; THR empty
    jmp  .pio_store
.pio_in_vtd:
    call hv_vpci_in                          ; RCQ-36 V2: assigned-function shadow, else VT-d
    jmp  .pio_store
.pio_in_ff:
    mov  ecx, -1
.pio_store:
    mov  rax, [rel hv_linux_gpr + 0]
    mov  edx, r8d
    and  edx, 7
    cmp  edx, 0
    je   .pio_byte
    cmp  edx, 1
    je   .pio_word
    mov  eax, ecx                            ; dword IN zero-extends
    jmp  .pio_store_done
.pio_byte:
    and  rax, -256
    movzx ecx, cl
    or   rax, rcx
    jmp  .pio_store_done
.pio_word:
    and  rax, -65536
    movzx ecx, cx
    or   rax, rcx
.pio_store_done:
    mov  [rel hv_linux_gpr + 0], rax
.pio_done:
    call hv_skip_instr
    jmp  .resume

    ; Real 8259A/8254-lite state, ported from Classic's live appliance path.
    ; ICW2 supplies the guest vector base; OCW1 supplies the real IRQ gates.
.pio_out_pitpic:
    mov  al, [rel hv_linux_gpr + 0]
    cmp  edx, 0x20
    je   .pic_m_cmd
    cmp  edx, 0x21
    je   .pic_m_data
    cmp  edx, 0xA0
    je   .pic_s_cmd
    cmp  edx, 0xA1
    je   .pic_s_data
    cmp  edx, 0x43
    je   .pit_ctl_wr
    cmp  edx, 0x61
    je   .p61_wr
    mov  ecx, edx
    sub  ecx, 0x40
    cmp  ecx, 3
    jb   .pit_data_wr
    jmp  .pio_done
.pic_m_cmd:
    test al, 0x10
    jz   .pio_done                         ; statelessly accept OCW2/OCW3
    mov  [rel hv_pic_icw1_m], al
    mov  byte [rel hv_pic_state_m], 1
    jmp  .pio_done
.pic_m_data:
    movzx ecx, byte [rel hv_pic_state_m]
    test ecx, ecx
    jz   .pic_m_mask
    cmp  ecx, 1
    jne  .pic_m_seq
    and  al, 0xF8
    mov  [rel hv_pic_vec_base], al
.pic_m_seq:
    movzx ecx, byte [rel hv_pic_state_m]
    cmp  ecx, 3
    jae  .pic_m_done
    cmp  ecx, 1
    jne  .pic_m_to4
    test byte [rel hv_pic_icw1_m], 2
    jz   .pic_m_expect3
.pic_m_to4:
    test byte [rel hv_pic_icw1_m], 1
    jz   .pic_m_done
    mov  byte [rel hv_pic_state_m], 3
    jmp  .pio_done
.pic_m_expect3:
    mov  byte [rel hv_pic_state_m], 2
    jmp  .pio_done
.pic_m_done:
    mov  byte [rel hv_pic_state_m], 0
    jmp  .pio_done
.pic_m_mask:
    mov  [rel hv_pic_mask], al
    jmp  .pio_done
.pic_s_cmd:
    test al, 0x10
    jz   .pio_done
    mov  [rel hv_pic_icw1_s], al
    mov  byte [rel hv_pic_state_s], 1
    jmp  .pio_done
.pic_s_data:
    movzx ecx, byte [rel hv_pic_state_s]
    test ecx, ecx
    jz   .pic_s_mask
    cmp  ecx, 3
    jae  .pic_s_done
    cmp  ecx, 1
    jne  .pic_s_to4
    test byte [rel hv_pic_icw1_s], 2
    jz   .pic_s_expect3
.pic_s_to4:
    test byte [rel hv_pic_icw1_s], 1
    jz   .pic_s_done
    mov  byte [rel hv_pic_state_s], 3
    jmp  .pio_done
.pic_s_expect3:
    mov  byte [rel hv_pic_state_s], 2
    jmp  .pio_done
.pic_s_done:
    mov  byte [rel hv_pic_state_s], 0
    jmp  .pio_done
.pic_s_mask:
    mov  [rel hv_pic_mask_s], al
    jmp  .pio_done
.p61_wr:
    call hv_pit2_gate_write
    jmp  .pio_done
.pit_ctl_wr:
    movzx ecx, al
    shr  ecx, 6
    cmp  ecx, 3
    je   .pio_done
    test al, 0x30
    jz   .pit_latch_cmd
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 0
    lea  rdi, [rel hv_pit_latched]
    mov  byte [rdi + rcx], 0
    cmp  ecx, 2
    jne  .pio_done
    ; Exact implemented form: binary channel 2, low/high bytes, mode 0.
    ; Other PIT modes retain their existing, separately unqualified model.
    mov  byte [rel hv_pit2_mode0], 0
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
    and  byte [rel hv_port61], 0xDF
    and  al, 0x3F
    cmp  al, 0x30
    jne  .pio_done
    mov  byte [rel hv_pit2_mode0], 1
    jmp  .pio_done
.pit_latch_cmd:
    push rdx
    call hv_pit_cur
    pop  rdx
    lea  rdi, [rel hv_pit_latch]
    mov  [rdi + rcx*2], ax
    lea  rdi, [rel hv_pit_latched]
    mov  byte [rdi + rcx], 1
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 0
    jmp  .pio_done
.pit_data_wr:
    lea  rdi, [rel hv_pit_ff]
    cmp  byte [rdi + rcx], 0
    jne  .pit_wr_hi
    lea  rdi, [rel hv_pit_reload]
    mov  [rdi + rcx*2], al
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 1
    cmp  ecx, 2
    jne  .pio_done
    cmp  byte [rel hv_pit2_mode0], 1
    jne  .pio_done
    ; Mode 0 stops on the first byte and restarts after the second.
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
    and  byte [rel hv_port61], 0xDF
    jmp  .pio_done
.pit_wr_hi:
    lea  rdi, [rel hv_pit_reload]
    mov  [rdi + rcx*2 + 1], al
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 0
    cmp  ecx, 2
    jne  .pio_done
    call hv_pit2_load
    jmp  .pio_done

.pio_in_pitpic:
    cmp  edx, 0x21
    je   .in_maskm
    cmp  edx, 0xA1
    je   .in_masks
    cmp  edx, 0x20
    je   .in_zero
    cmp  edx, 0xA0
    je   .in_zero
    cmp  edx, 0x61
    je   .in_p61
    mov  ecx, edx
    sub  ecx, 0x40
    cmp  ecx, 3
    jb   .in_pit
    jmp  .pio_in_ff
.in_maskm:
    movzx ecx, byte [rel hv_pic_mask]
    jmp  .pio_store
.in_masks:
    movzx ecx, byte [rel hv_pic_mask_s]
    jmp  .pio_store
.in_zero:
    xor  ecx, ecx
    jmp  .pio_store
.in_p61:
    call hv_pit2_update
    movzx ecx, byte [rel hv_port61]
    jmp  .pio_store
.in_pit:
    lea  rdi, [rel hv_pit_latched]
    cmp  byte [rdi + rcx], 0
    je   .in_pit_live
    lea  rdi, [rel hv_pit_latch]
    movzx eax, word [rdi + rcx*2]
    jmp  .in_pit_ff
.in_pit_live:
    push rcx
    push rdx
    call hv_pit_cur
    pop  rdx
    pop  rcx
    movzx eax, ax
.in_pit_ff:
    lea  rdi, [rel hv_pit_ff]
    cmp  byte [rdi + rcx], 0
    jne  .in_pit_hi
    mov  byte [rdi + rcx], 1
    movzx ecx, al
    jmp  .pio_store
.in_pit_hi:
    mov  byte [rdi + rcx], 0
    lea  rdi, [rel hv_pit_latched]
    mov  byte [rdi + rcx], 0
    movzx ecx, ah
    jmp  .pio_store

.draccess:
    cmp  qword [rel vca_ready], 0
    je   .draccess_legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    mov  edi, VMXF_EXIT_QUAL
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rdi, rax
    call vcb_dr
    cmp  eax, 4
    je   .dr_db
    cmp  eax, 3
    je   .xset_ud
    cmp  eax, 2
    je   .msr_gp
    cmp  eax, 1
    jne  vcb_fail_stop
    call hv_skip_instr
    jmp  .resume
.dr_db:
    mov  edi, VMXF_ENTRY_INTR
    mov  esi, 0x80000301               ; GD #DB, hardware exception/no error
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    jmp  .resume                       ; fault: retain original RIP
.draccess_legacy:
    mov  byte [rel hv_linux_load_err], 7 ; legacy unknown-exit behavior retained
    xor  eax, eax
    ret

.craccess:
    cmp  qword [rel vca_ready], 0
    je   .craccess_legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    mov  edi, VMXF_EXIT_QUAL
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rdi, rax
    call vcb_cr
    cmp  eax, 3
    je   .xset_ud
    cmp  eax, 2
    je   .msr_gp
    cmp  eax, 1
    jne  vcb_fail_stop
    call hv_skip_instr
    jmp  .resume
.craccess_legacy:
    mov  edi, VMXF_EXIT_QUAL
    call hv_guest_read
    mov  ecx, eax
    and  ecx, 0xF
    cmp  ecx, 4
    je   .cr4
    cmp  ecx, 3                              ; only CR3 is relevant here
    jne  .cr_skip
    mov  edx, eax
    shr  edx, 8
    and  edx, 0xF
    lea  rdi, [rel hv_linux_cr_gpr_map]
    movzx edx, byte [rdi + rdx]
    cmp  edx, 0xFF
    je   .cr_skip
    test eax, 0x30
    jnz  .cr_read
    lea  rcx, [rel hv_linux_gpr]
    mov  rsi, [rcx + rdx]
    mov  edi, VMXF_G_CR3
    call hv_guest_write
    jmp  .cr_skip
.cr_read:
    mov  edi, VMXF_G_CR3
    call hv_guest_read
    lea  rcx, [rel hv_linux_gpr]
    mov  [rcx + rdx], rax
.cr_skip:
    call hv_skip_instr
    jmp  .resume
.cr4:
    ; V5: CR4 exits come only from the host-owned bits. A MOV to CR4 setting
    ; PKE or KL gets #GP(0) with no write and RIP left on the MOV, as on a CPU
    ; without them (CPUID hides both). Other CR4 exits keep their old handling.
    test eax, 0x30                           ; access type 0 = MOV to CR
    jnz  .cr_skip
    mov  edx, eax
    shr  edx, 8
    and  edx, 0xF
    lea  rdi, [rel hv_linux_cr_gpr_map]
    movzx edx, byte [rdi + rdx]
    cmp  edx, 0xFF
    je   .cr4_rsp
    lea  rcx, [rel hv_linux_gpr]
    mov  rax, [rcx + rdx]
    jmp  .cr4_value
.cr4_rsp:
    mov  edi, VMXF_G_RSP                     ; RSP lives in the VMCS
    call hv_guest_read
.cr4_value:
    test eax, HV_CR4_GUEST_DENIED
    jz   .cr_skip
    inc  dword [rel hv_cr4_refused]
    mov  edi, VMXF_ENTRY_ERRCODE
    xor  esi, esi
    call hv_guest_write                      ; shared exit path: through hv_ops (S1a)
    mov  edi, VMXF_ENTRY_INTR
    mov  esi, HV_GUEST_GP_INFO
    call hv_guest_write
    jmp  .resume

.xsetbv:
    cmp  qword [rel vca_ready], 0
    je   .xset_legacy
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    mov  edi, [rel hv_linux_gpr + 16]
    mov  esi, [rel hv_linux_gpr]
    mov  eax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax
    call vcb_xsetbv
    cmp  eax, 9
    je   .xset_ud
    test eax, eax
    jnz  .xset_gp
    jmp  .xset_done
.xset_ud:
    mov  edi, VMXF_ENTRY_INTR
    mov  esi, 0x80000306                 ; hardware exception #UD, no error code
    call hv_guest_write
    jmp  .resume
.xset_legacy:
    ; HV-XCR0 V1: the guest's XCR0 is checked exactly as hardware checks it; a
    ; value hardware would refuse becomes #GP(0) in the guest, never a host write.
    cmp  byte [rel hv_linux_xcr0_saved], 1
    jne  .xset_done
    mov  eax, 0xD
    xor  ecx, ecx
    cpuid
    and  eax, [rel sched_xsave_mask_lo]       ; V4: hidden components also refuse manual XSETBV
    and  edx, [rel sched_xsave_mask_hi]
    and  eax, ~HV_XCR0_GUEST_DENIED          ; V5: PKRU is never admitted
    shl  rdx, 32
    mov  eax, eax
    or   rdx, rax                            ; RDX = CPU-supported AND scheduler-switched bits
    mov  edi, [rel hv_linux_gpr + 16]        ; guest ECX
    mov  esi, [rel hv_linux_gpr + 0]         ; guest EAX
    mov  rax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax                            ; RSI = guest EDX:EAX
    push rsi
    call hv_linux_xcr0_check
    pop  rdi
    test eax, eax
    jnz  .xset_gp
    call hv_linux_xcr0_apply
.xset_done:
    call hv_skip_instr
    jmp  .resume
.xset_gp:
    inc  dword [rel hv_xsetbv_refused]
    mov  [rel hv_xsetbv_last_refusal], al
    mov  edi, VMXF_ENTRY_ERRCODE
    xor  esi, esi
    call hv_guest_write                      ; shared exit path: VMCS or VMCB EVENTINJ via hv_ops
    mov  edi, VMXF_ENTRY_INTR
    mov  esi, HV_GUEST_GP_INFO               ; RIP stays on the XSETBV, as on hardware
    call hv_guest_write
    jmp  .resume

.hlt:
    inc  dword [rel hv_hlt_exits]
    inc  qword [rel hv_guestcpu_halt_wakes]
    cmp  byte [rel cdp_fixture_mode], 1
    je   .control_hlt
    cmp  byte [rel gws_fixture_mode], 1
    jne  .ordinary_hlt
.control_hlt:
    ; A fixture invocation ends only at a real guest HLT after queue notify.
    ; No Linux shell/boot flag is fabricated to bypass its watchdog.
    xor  eax, eax
    ret
.ordinary_hlt:
    ; The explicit PANIC request becomes a real guest failure: inject #UD only
    ; at a confirmed CPL0 idle boundary; the artifact's oops=panic path owns it.
    cmp  byte [rel hv_panic_armed], 1
    jne  .hlt_normal
    mov  edi, VMXF_GUEST_CS_SEL
    call hv_guest_read
    test eax, 3
    jnz  .hlt_normal
    mov  edi, VMXF_ENTRY_INTR
    call hv_guest_read
    test eax, 0x80000000
    jnz  .hlt_normal
    mov  edi, VMXF_ENTRY_INTR
    mov  esi, HV_GUEST_UD_INFO
    call hv_guest_write
    mov  byte [rel hv_panic_armed], 0
    mov  byte [rel hv_panic_injected], 1
    jmp  .resume
.hlt_normal:
    call hv_skip_instr                       ; ESSENCE E3 clears interrupt shadow
    cmp  dword [rel vcb_handoff_active], 0
    je   .bsp_power
    call vcl_hlt                            ; root-emulated AP idle, never physical HLT
    jmp  .bsp_hlt
.bsp_power:
    call guestpower_hlt_exit                 ; C10b-1a: an armed clean halt only sets STOP
    test eax, eax
    jnz  .resume                             ; S5: nd_backend_stopped still retires
.bsp_hlt:
    call hv_linux_host_slice                 ; host services stay co-resident
    jmp  .resume
.timer:
    call hv_linux_host_slice                 ; preemption timer is the host heartbeat
    call hv_linux_reset_timer                ; new budget only after an actual expiry
    jmp  .resume
.intrwin:
    ; Classic's proven IRQ-window path: bit 2 must be cleared on reason 7 or
    ; every subsequent entry exits immediately. The normal resume arbitration
    ; then retries retained RTL work at this exact IF=1/no-shadow boundary.
    call vtd_guest_dataplane_intr_window_exit
    jmp  .resume
.resume:
    call hv_vmx_host_turn_due                ; ROOT109896 (4): every resuming exit, any reason
    call hv_linux_reinject_vectoring         ; interrupted event owns this entry
    cmp  dword [rel vcb_handoff_active], 0
    jne  .ap_resume
%ifdef PAOS_NIC_ASSIGNMENT
    call nd_tick
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    call nd_learn_pump                    ; clean exit, never console/IRQ frame
%endif
%endif
    call guestnet_pump                       ; deferred DHCP/shell injection at a clean exit
    call guestinput_pump                     ; RCQ-23: posted input events into eventq
    call guestsound_pump
    call padc_pump                           ; RCQ-36: at most one PAD1 chunk/reply
    call guestentropy_pump                   ; at most one bounded private CSPRNG request
    call guestrestore_pump                   ; control handshake and one pending restore line
    call fsg_tick                            ; original F11 owner, bounded block/control turn
    call wfc_tick                            ; private READY/request/ACK, clean BSP exit only
    call guestpower_pump                     ; C10b-1a: control handshake and the one shutdown line
    call vtd_guest_dataplane_prepare         ; retain RTL work without consuming ENTRY_INTR
    call hv_glapic_try_inject                ; RCQ-50 S4: a pending LAPIC vector goes first
    test eax, eax
    jnz  .budget
    call hv_try_inject_vcon
    test eax, eax
    jnz  .budget
    call guestwifi_irq                       ; private IRQ5 also in physical NIC mode
    test eax,eax
    jnz .budget
    call guestpower_irq                      ; C10b-1a: private IRQ5 also in physical NIC mode
    test eax,eax
    jnz .budget
    cmp  byte [rel vtd_network_mode], 1
    je   .physical_irqs
    ; Preserve the established virtio-NAT ordering outside DDOM NET.
    call guestnet_try_inject_irq
    test eax, eax
    jnz  .budget
    call guestinput_try_inject_irq           ; RCQ-23: IRQ1, a no-op without the device
    test eax, eax
    jnz  .budget
    call guestsound_try_inject_irq
    test eax,eax
    jnz .budget
    call guestentropy_try_inject_irq
    test eax, eax
    jnz  .budget
    call guestrestore_try_inject_irq         ; IRQ5 shared with the console line
    test eax, eax
    jnz  .budget
    call guestfilesystem_irq
    test eax,eax
    jnz .budget
    call hv_try_inject_uart                  ; RCQ-36: IRQ4 THRE, userspace ttyS0 output
    test eax, eax
    jnz  .budget
    call pcia_try_inject_irq                 ; RCQ-36 V2 c2: assigned HDA level line, IRQ6
    test eax, eax
    jnz  .budget
    call hv_try_inject_tick_due
    jmp  .budget
.physical_irqs:
    call hv_try_inject_tick_due              ; IRQ0 wins over RTL so irq_exit can run NAPI
    test eax, eax
    jz   .try_rtl
    call vtd_guest_dataplane_irq0_injected   ; retained RTL cause moves to a later entry
    jmp  .budget
.try_rtl:
    call vtd_guest_dataplane_try_inject
    test eax, eax
    jnz  .budget
    call guestnet_try_inject_irq
    test eax, eax
    jnz  .budget
    call guestsound_try_inject_irq
    test eax,eax
    jnz .budget
    call guestentropy_try_inject_irq           ; also fence a retained physical-mode selector
    test eax, eax
    jnz  .budget
    call guestrestore_try_inject_irq           ; same fence for the restore port
    jmp  .budget
.ap_resume:
    call hv_glapic_try_inject                ; AP has only its local LAPIC/timer
    jmp  .budget_check
.budget:
    call hvcw_pump                          ; one bounded private service opportunity
.budget_check:
    cmp  byte [rel hv_linux_stop_req], 1
    jne  .not_stopping
    mov  byte [rel hv_linux_stop_req], 0
    xor  eax, eax
    ret
.not_stopping:
    cmp  byte [rel hv_linux_kboot], 1
    je   .within_budget                      ; resident after proven guest boot
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel hv_linux_deadline]
    jb   .within_budget
    mov  byte [rel hv_linux_load_err], 8
    xor  eax, eax
    ret
.within_budget:
    ; The timer is the time left to the host deadline, floor Q_min (ROOT109896 (4));
    ; a failed write refuses below like any other VMCS write.
    call hv_vmx_host_timer_arm
    cmp  dword [rel hv_vmwrite_fails], 0
    je   .resume_ready
    mov  byte [rel hv_linux_load_err], 7
    xor  eax, eax
    ret
.resume_ready:
    mov  eax, 1
    ret

; Channel-2 mode-0 timing is measured from the completed counter write.
; Intel 8254: OUT low until terminal count; GATE low pauses counting; OUT
; stays high after completion until a new counter/control word. Port 61
; exposes OUT on bit 5 (read-only) and the gate on writable bit 0.
; This deliberately does not claim a complete 8254 implementation.
; Helpers preserve R8, the caller's VM-exit I/O qualification.
hv_pit2_update:
    cmp  byte [rel hv_pit2_armed], 1
    jne  .done
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel hv_pit2_deadline]
    jb   .done
    or   byte [rel hv_port61], 0x20
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
.done:
    ret

hv_pit2_load:
    cmp  byte [rel hv_pit2_mode0], 1
    jne  .done
    mov  byte [rel hv_pit2_armed], 0
    and  byte [rel hv_port61], 0xDF
    movzx eax, word [rel hv_pit_reload + 4]
    test eax, eax
    jnz  .count
    mov  eax, 65536
.count:
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .rate
    mov  ecx, 3000000
.rate:
    ; ceil(count * TSC-Hz / PIT-Hz), retaining sub-millisecond precision.
    imul rcx, rcx, 1000
    mul  rcx
    add  rax, 1193181
    adc  rdx, 0
    mov  ecx, 1193182
    div  rcx
    mov  [rel hv_pit2_remaining], rax
    test byte [rel hv_port61], 1
    jz   .done
    mov  rcx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rax, rcx
    mov  [rel hv_pit2_deadline], rax
    mov  byte [rel hv_pit2_armed], 1
.done:
    ret

; AL=new port value. Only gate/speaker bits are writable in this model.
hv_pit2_gate_write:
    movzx r11d, al
    call hv_pit2_update
    movzx r10d, byte [rel hv_port61]
    and  r11d, 3
    mov  eax, r10d
    and  eax, 0x20
    or   eax, r11d
    mov  [rel hv_port61], al
    xor  r10d, r11d
    test r10d, 1
    jz   .done
    cmp  byte [rel hv_pit2_mode0], 1
    jne  .done
    test r11d, 1
    jnz  .rise
    cmp  byte [rel hv_pit2_armed], 1
    jne  .done
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, [rel hv_pit2_deadline]
    sub  rcx, rax
    jbe  .terminal
    mov  [rel hv_pit2_remaining], rcx
    mov  byte [rel hv_pit2_armed], 0
    ret
.terminal:
    or   byte [rel hv_port61], 0x20
    mov  qword [rel hv_pit2_remaining], 0
    mov  byte [rel hv_pit2_armed], 0
    ret
.rise:
    mov  rcx, [rel hv_pit2_remaining]
    test rcx, rcx
    jz   .done
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rax, rcx
    mov  [rel hv_pit2_deadline], rax
    mov  byte [rel hv_pit2_armed], 1
.done:
    ret

; ECX=PIT channel -> AX=current emulated down-counter. The live TSC is reduced
; to milliseconds then scaled by the 1.193182 MHz PIT rate. Reload 0 means
; 65536, exactly as on the 8254. Preserves ECX for the PIO caller.
hv_pit_cur:
    push r8                                 ; retain PIO width/direction qualification
    mov  r9, rcx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r8, [rel tsc_khz]
    test r8, r8
    jz   .zero
    xor  edx, edx
    div  r8
    imul rax, rax, 1193
    lea  rdi, [rel hv_pit_reload]
    movzx r8d, word [rdi + r9*2]
    test r8d, r8d
    jnz  .mod
    mov  r8d, 0x10000
.mod:
    xor  edx, edx
    div  r8
    mov  rax, r8
    sub  rax, rdx
    mov  rcx, r9
    pop  r8
    ret
.zero:
    xor  eax, eax
    mov  rcx, r9
    pop  r8
    ret

; Feed one real guest console TX byte (UART fallback or virtio hvc0) into the
; exact boot prefix matcher. The first byte earns guest.launched because this
; function is reached only from a live VM-exit console path; no request, loader
; state, exit counter, or host command can earn either guest latch.
hv_linux_console_char:
    call hv_guest_identity_byte
    call padc_uart_byte                      ; RCQ-36: exact PAD1 ready line only
    call hvcw_uart_byte                      ; warm init made hvc0 raw before marker
    push rbx
    push rax
    cmp  byte [rel hv_linux_vmx_live], 1
    jne  .launch_checked
    cmp  byte [rel hv_guest_launched], 1
    je   .launch_checked
    mov  byte [rel hv_guest_launched], 1
    call boot_ms_now
    mov  [rel hv_guest_launched_ms], rax
    lea  rdi, [rel str_hv_guest_launched_marker]
    call serial_string
.launch_checked:
    pop  rax
    mov  ecx, [rel hv_linux_match]
    lea  rbx, [rel str_hv_linux_kboot]
    mov  edx, 9
    cmp  byte [rel vtd_domain_l2_active], 1
    jne  .expected
    lea  rbx, [rel str_hv_linux_domain_kboot]
    mov  edx, 11
.expected:
    cmp  al, [rbx + rcx]
    jne  .restart
    inc  ecx
    mov  [rel hv_linux_match], ecx
    cmp  ecx, edx
    jne  .out
    mov  byte [rel hv_linux_kboot], 1
    cmp  byte [rel hv_guest_booted], 1
    je   .out
    mov  byte [rel hv_guest_booted], 1
    push rax
    lea  rdi, [rel str_hv_guest_boot_marker]
    call serial_string                       ; exact decoded guest-console evidence only
    pop  rax
    jmp  .out
.restart:
    xor  ecx, ecx
    cmp  al, 'R'
    jne  .store
    inc  ecx
.store:
    mov  [rel hv_linux_match], ecx
.out:
    pop  rbx
    ret

; Public identity receipt only: bounded guest-reported console observability,
; never authentication. Bind both matcher and retained receipt to a live accepted
; START and console reset epoch. Ordinary capture resets (GUESTKEY) do not erase it.
hv_guest_identity_sync:
    cmp  byte [rel hv_linux_running], 1
    jne  .inactive
    mov  eax, [rel hv_linux_start_consumed]
    test eax, eax
    jz   .inactive
    cmp  eax, [rel hv_linux_start_gen]
    jne  .inactive
    mov  rdx, [rel hv_vcon_epoch]
    cmp  eax, [rel hv_guest_identity_gen]
    jne  .new
    cmp  rdx, [rel hv_guest_identity_epoch]
    je   .ok
.new:
    mov  [rel hv_guest_identity_gen], eax
    mov  [rel hv_guest_identity_epoch], rdx
    mov  dword [rel hv_guest_identity_pos], 0
    mov  byte [rel hv_guest_identity_cr], 0
    mov  byte [rel hv_guest_identity_state], 0
.ok:
    mov  eax, 1
    ret
.inactive:
    mov  dword [rel hv_guest_identity_gen], 0
    mov  dword [rel hv_guest_identity_pos], 0
    mov  byte [rel hv_guest_identity_cr], 0
    mov  byte [rel hv_guest_identity_state], 0
    xor  eax, eax
    ret

; AL is one actual decoded console byte. Preserve registers and flags, including
; DF, across this tap. At most 149 public bytes are compared/copied per newline.
hv_guest_identity_byte:
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    mov  bl, al
    call hv_guest_identity_sync
    test eax, eax
    jz   .out
    mov  ecx, [rel hv_guest_identity_pos]
    cmp  ecx, 149
    ja   .restart
    je   .end
    cmp  ecx, 32
    jb   .literal
    cmp  ecx, 68
    jae  .after_uuid
    cmp  ecx, 40
    je   .hyphen
    cmp  ecx, 45
    je   .hyphen
    cmp  ecx, 50
    je   .hyphen
    cmp  ecx, 55
    je   .hyphen
    cmp  bl, '0'
    jb   .restart
    cmp  bl, '9'
    jbe  .store
    cmp  bl, 'a'
    jb   .restart
    cmp  bl, 'f'
    jbe  .store
    jmp  .restart
.hyphen:
    cmp  bl, '-'
    je   .store
    jmp  .restart
.after_uuid:
    cmp  ecx, 106
    jb   .literal
    cmp  bl, '+'
    je   .store
    cmp  bl, '/'
    je   .store
    cmp  bl, '0'
    jb   .restart
    cmp  bl, '9'
    jbe  .store
    cmp  bl, 'A'
    jb   .restart
    cmp  bl, 'Z'
    jbe  .store
    cmp  bl, 'a'
    jb   .restart
    cmp  bl, 'z'
    jbe  .store
    jmp  .restart
.literal:
    lea  rsi, [rel str_hv_guest_identity_template]
    cmp  bl, [rsi + rcx]
    jne  .restart
.store:
    lea  rsi, [rel hv_guest_identity_candidate]
    mov  [rsi + rcx], bl
    inc  ecx
    mov  [rel hv_guest_identity_pos], ecx
    jmp  .out
.end:
    cmp  bl, 10
    je   .complete
    cmp  bl, 13
    jne  .restart
    inc  byte [rel hv_guest_identity_cr]
    cmp  byte [rel hv_guest_identity_cr], 2 ; LF, CRLF or console CRCRLF
    ja   .restart
    jmp  .out
.complete:
    mov  dword [rel hv_guest_identity_pos], 0
    mov  byte [rel hv_guest_identity_cr], 0
    cmp  byte [rel hv_guest_identity_state], 0
    je   .first
    cmp  byte [rel hv_guest_identity_state], 1
    jne  .out                            ; conflict is sticky until new context
    lea  rsi, [rel hv_guest_identity_candidate]
    lea  rdi, [rel hv_guest_identity_receipt]
    mov  ecx, 149
    cld
    repe cmpsb
    je   .out
    mov  byte [rel hv_guest_identity_state], 2
    jmp  .out
.first:
    lea  rsi, [rel hv_guest_identity_candidate]
    lea  rdi, [rel hv_guest_identity_receipt]
    mov  ecx, 149
    cld
    rep movsb
    mov  byte [rel hv_guest_identity_state], 1
    jmp  .out
.restart:
    mov  dword [rel hv_guest_identity_pos], 0
    mov  byte [rel hv_guest_identity_cr], 0
    cmp  bl, 'P'
    jne  .out
    xor  ecx, ecx
    jmp  .store
.out:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    popfq
    ret

hv_guest_identity_append:
    call hv_guest_identity_sync
    test eax, eax
    jz   .out
    cmp  byte [rel hv_guest_identity_state], 1
    je   .valid
    cmp  byte [rel hv_guest_identity_state], 2
    jne  .out
    lea  rdi, [rel str_hv_guest_identity_conflict]
    jmp  hv_out_str
.valid:
    lea  rdi, [rel str_hv_guest_identity_gen]
    call hv_out_str
    mov  eax, [rel hv_guest_identity_gen]
    call hv_out_dec
    lea  rdi, [rel str_hv_guest_identity_field]
    call hv_out_str
    lea  rdi, [rel hv_guest_identity_receipt]
    mov  ecx, 149
.loop:
    mov  al, [rdi]
    call hv_out_putc
    inc  rdi
    dec  ecx
    jnz  .loop
.out:
    ret

; Stable vtable-facing entry: tail-dispatch to the proven Intel launcher.
hv_vmx_launch:
    xor  edi, edi                            ; EDI = 0: the VMX checks and hv_linux_enter
    cmp  byte [rel hv_launch_mode], 1
    je   hv_guest_linux_start
    jmp  hv_guest_launch

; hv_skip_instr — advance guest RIP by the VM-exit instruction length, then clear
;   the STI/MOV-SS interruptibility-shadow (bits 0..1). Mirrors KVM
;   vmx_set_interrupt_shadow(vcpu, 0) — ESSENCE E3, the one-line fix that unbroke
;   the monolith's IRQ0 injection. clobbers RAX,RCX,RDI,RSI
hv_skip_instr:
    mov  edi, VMXF_EXIT_ILEN
    call hv_guest_read
    mov  rcx, rax
    mov  edi, VMXF_G_RIP
    call hv_guest_read
    add  rcx, rax
    mov  edi, VMXF_G_RIP
    mov  rsi, rcx
    call hv_guest_write
    mov  edi, VMXF_G_INTERRUPT
    call hv_guest_read
    and  rax, ~3                             ; clear STI-blocking(0) + MOV-SS-blocking(1)
    mov  edi, VMXF_G_INTERRUPT
    mov  rsi, rax
    call hv_guest_write
    ret

; hv_adjust_ctls(EDI=MSR index, ESI=desired bits) -> EAX = (allowed0|desired)&allowed1.
;   clobbers EAX,ECX,EDX
hv_adjust_ctls:
    mov  ecx, edi
    rdmsr
    or   eax, esi
    and  eax, edx
    ret

; hv_w(RDI=field encoding, RSI=value) — vmwrite with failure accounting. clobbers flags only
hv_w:
    cmp  qword [rel vca_ready], 0
    je   .write
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    call vcb_write_check
    cmp  eax, 1
    jne  vcb_fail_stop
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rax
.write:
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    ret
.bad:
    inc  dword [rel hv_vmwrite_fails]
    ret

; ---------------------------------------------------------------------------
; RCQ-18 S0: the VMX entries of the hv_ops per-vCPU accessors. They are the
; exact VMCS reads and writes the guest devices issued themselves before the
; seam. Each touches only RAX, RCX, RDI, RSI (slat_flush: also RDX).
; ---------------------------------------------------------------------------

; -> EAX = 0, or the first of: an event already in the VM-entry interruption
; field, guest RFLAGS.IF = 0, an STI/MOV SS shadow.
hv_vmx_can_inject_extint:
    mov  edi, VMXF_ENTRY_INTR
    vmread rax, rdi
    test eax, 0x80000000
    jnz  .pending
    mov  edi, VMXF_G_RFLAGS
    vmread rax, rdi
    test rax, 0x200
    jz   .if0
    mov  edi, VMXF_G_INTERRUPT
    vmread rax, rdi
    test eax, 3
    jnz  .shadow
    xor  eax, eax
    ret
.pending:
    mov  eax, HV_INJ_BLOCK_PENDING
    ret
.if0:
    mov  eax, HV_INJ_BLOCK_IF
    ret
.shadow:
    mov  eax, HV_INJ_BLOCK_SHADOW
    ret

; EDI = vector -> a valid external-interrupt event for the next VM entry.
hv_vmx_inject_extint:
    mov  esi, edi
    or   esi, 0x80000000
    mov  edi, VMXF_ENTRY_INTR
    jmp  hv_w

; EDI = 1 arms, 0 disarms the interrupt-window exit (Classic gl_iw_arm/disarm).
hv_vmx_intr_window:
    mov  ecx, edi
    mov  edi, VMXF_PROC_CTLS
    vmread rax, rdi
    and  eax, ~HV_VMX_IW_BIT
    test ecx, ecx
    jz   .write
    or   eax, HV_VMX_IW_BIT
.write:
    mov  esi, eax
    mov  edi, VMXF_PROC_CTLS
    jmp  hv_w

; -> EAX = 1 when INVEPT dropped the guest's EPT translations.
hv_vmx_slat_flush:
    call vtd_invept_current_ept
    movzx eax, byte [rel vtd_ept_invept_ok]
    ret

; EDI = HV_SLAT_* -> RAX = the EPT bits for that entry kind (0 for an unknown kind).
hv_vmx_slat_bits:
    xor  eax, eax
    mov  ecx, edi
    cmp  ecx, HV_SLAT_KINDS
    jae  .out
    lea  rax, [rel hv_vmx_slat_tbl]
    mov  rax, [rax + rcx*8]
.out:
    ret

hv_vmx_guest_cr3:
    mov  edi, VMXF_G_CR3
    vmread rax, rdi
    ret

; Exit record (RCQ-18 S1a): EDI = VMXF_* field -> RAX. VMREAD's flags reach the
; caller unchanged. The write half is hv_w.
hv_vmx_guest_read:
    vmread rax, rdi
    ret

; HV_SLAT_* order. The framebuffer leaf's EPT encoding stays owned by guestdisplay.
align 8
hv_vmx_slat_tbl:
    dq HV_EPT_RWX, HV_EPT_RAM_2M, HV_EPT_TRAP_RO, GD_EPT_LEAF, HV_EPTP_WB_4LVL, HV_EPT_MMIO_4K

; Existing latches only; does not pump PAD1, touch PCI/MMIO or launch/stop.
; START generations are u32 throughout the VM owner (including padc/pcia).
; A live pad_play=2 means validated DRAIN0+STOP0, never physical output.
; After STOP, pad_bound=0 and pcia_state=0 observe channel/device teardown.
hv_render_audiostat:
    call hv_out_reset
    lea  rdi, [rel str_hv_audio_pre]
    call hv_out_str
    mov  eax, [rel hv_linux_start_gen]
    call hv_out_dec
    lea  rdi, [rel str_hv_audio_consumed]
    call hv_out_str
    mov  eax, [rel hv_linux_start_consumed]
    call hv_out_dec
    lea  rdi, [rel str_hv_audio_queued]
    call hv_out_str
    movzx eax, byte [rel hv_linux_run_req]
    call hv_out_dec
    ; Refusal belongs to consumed_gen; a newer queued START has not run yet.
    lea  rdi, [rel str_hv_audio_admission]
    call hv_out_str
    mov  eax, [rel hv_linux_start_refusal]
    call hv_out_dec
    lea  rdi, [rel str_hv_audio_starting]
    call hv_out_str
    movzx eax, byte [rel hv_linux_start_active]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_loaderr]
    call hv_out_str
    movzx eax, byte [rel hv_linux_load_err]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_running]
    call hv_out_str
    movzx eax, byte [rel hv_linux_running]
    call hv_out_dec
    call padc_render_stat
    call pcia_render_stat
    ; Closed-BSP SVM snapshots survive STOP. Their own generation may differ
    ; from consumed_gen after a queued/refused/Intel START. Hex preserves RIP.
    lea  rdi, [rel str_hv_svm_gen]
    call hv_out_str
    mov  rax, [rel vsm_progress_gen]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_returns0]
    call hv_out_str
    mov  rax, [rel vsm_progress_returns0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_first0]
    call hv_out_str
    mov  rax, [rel vsm_progress_first0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_rip0]
    call hv_out_str
    mov  rax, [rel vsm_progress_rip0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_exit0]
    call hv_out_str
    mov  rax, [rel vsm_progress_exit0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_returns1]
    call hv_out_str
    mov  rax, [rel vsm_progress_returns1]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_rip1]
    call hv_out_str
    mov  rax, [rel vsm_progress_rip1]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_exit1]
    call hv_out_str
    mov  rax, [rel vsm_progress_exit1]
    call hv_linux_exit_hex
    ret

; hv_render_stat — stage the LIVE launch counters into hv_out_buf. Un-fakeable:
;   the numbers come from the VMCS-decoded fields the launch just wrote, and
;   host=alive proves the resident VM yielded at a clean VM-exit boundary.
;   clobbers caller-saved.
hv_render_stat:
    call hv_out_reset
    lea  rdi, [rel str_hv_stat_pre]
    call hv_out_str
    cmp  byte [rel hv_launch_refused], 1
    jne  .not_refused
    lea  rdi, [rel str_hv_stat_refused]
    call hv_out_str
    mov  rdi, [rel hv_val_field]
    call hv_out_str
.not_refused:
    lea  rdi, [rel str_hv_stat_launches]
    call hv_out_str
    mov  eax, [rel hv_launches]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_hlt]
    call hv_out_str
    mov  eax, [rel hv_hlt_exits]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_reason]
    call hv_out_str
    mov  eax, [rel hv_exit_reason]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_kboot]
    call hv_out_str
    movzx eax, byte [rel hv_linux_kboot]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_loaderr]
    call hv_out_str
    movzx eax, byte [rel hv_linux_load_err]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_loadgen]
    call hv_out_str
    mov  eax, [rel hv_linux_load_gen]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_loadphase]
    call hv_out_str
    movzx eax, byte [rel hv_linux_load_phase]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_starting]
    call hv_out_str
    movzx eax, byte [rel hv_linux_start_active]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_linux_exits]
    call hv_out_str
    mov  eax, [rel hv_linux_exits]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_intr_exits]
    call hv_out_str
    mov  eax, [rel hv_linux_intr_exits]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_host_slices]
    call hv_out_str
    mov  eax, [rel hv_linux_host_slices]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_running]
    call hv_out_str
    movzx eax, byte [rel hv_linux_running]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_ticks]
    call hv_out_str
    mov  eax, [rel hv_tick_inj_ct]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_jiffies]
    call hv_out_str
    xor  eax, eax
    mov  rdx, [rel hv_linux_ram]
    test rdx, rdx
    jz   .jiffies_done
    cmp  qword [rel vm_profile_active], 0    ; the System.map address is the legacy kernel's
    jne  .jiffies_done
    ; Current staged 6.6.32 System.map: jiffies=ffffffff818c3480;
    ; nokaslr makes its live GPA 0x18c3480. This is guest memory, not a host latch.
    mov  eax, [rdx + HV_LINUX_JIFFIES_GPA]
.jiffies_done:
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_console]
    call hv_out_str
    lea  rdi, [rel str_hv_stat_uart]
    call hv_out_str
    lea  rdi, [rel str_hv_stat_vstatus]
    call hv_out_str
    mov  eax, [rel hv_vcon_status]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_vrxq]
    call hv_out_str
    movzx eax, byte [rel hv_vcon_q_ready]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_vtxq]
    call hv_out_str
    movzx eax, byte [rel hv_vcon_q_ready + 1]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_vrxused]
    call hv_out_str
    mov  eax, [rel hv_vcon_rx_used]
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_vtxused]
    call hv_out_str
    mov  eax, [rel hv_vcon_tx_used]
    call hv_out_dec
    cmp  byte [rel hv_linux_panicked], 1
    jne  .not_panicked
    lea  rdi, [rel str_hv_stat_panicked]
    call hv_out_str
.not_panicked:
    call vm_profile_render_live              ; RCQ-18: selection + what was mapped
    call guestdisplay_render_stat            ; RCQ-23: mode + fb_sum when a display is live
    call guestinput_render_stat              ; RCQ-23: event counters when input is live
    lea  rdi, [rel str_hv_stat_host]
    call hv_out_str
    call hv_render_slice_diag                ; T2-4 D8: Intel S7 only, so never beside an AMD floor
    call hv_svm_stat_text                    ; RCQ-18 SVM: the floor's raw bits for serial-dark AMD
    test rax, rax                            ; metal; 0 on VMX. Last, so a clip never displaces a field
    jz   .no_svm_floor
    mov  rdi, rax
    call hv_out_str
.no_svm_floor:
    call guestdisplay_render_stage_stat      ; passive tail; never displaces existing status fields
    ret

; T2-4 D8 (VM 107717): Intel S7 two-vCPU live STAT only (hv_ops_active ==
; hv_ops_vmx and vca_ready == 1), after host=alive. The AMD-only floor slot
; follows it in hv_render_stat, but the gate excludes AMD, so on every STAT that
; carries these keys they precede passive stage diagnostics; the AMD floor
; also precedes those diagnostics. Existing fields retain their output priority.
; The slice fields appear on no other STAT. Timer =
; existing per-START reason-52 count; nonroot = existing BSP vob row 0
; interval_tsc (entry-to-exit, includes boundary overhead); yield/gap from
; hv_linux_host_slice. ms = TSC / tsc_khz, saturated u32. Clobbers caller-saved.
hv_render_slice_diag:
    lea  rax, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], rax
    jne  .out
    cmp  qword [rel vca_ready], 1
    jne  .out
    lea  rdi, [rel str_hv_stat_slice_timer]
    call hv_out_str
    mov  rax, [rel hv_linux_exit_timer]
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    jbe  .timer
    mov  rax, rcx
.timer:
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_slice_nonroot]
    call hv_out_str
    mov  rax, [rel vob_records + 40]
    call hv_slice_tsc_ms
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_slice_yield]
    call hv_out_str
    mov  rax, [rel hv_linux_slice_yield_tsc]
    call hv_slice_tsc_ms
    call hv_out_dec
    lea  rdi, [rel str_hv_stat_slice_gap]
    call hv_out_str
    mov  rax, [rel hv_linux_slice_max_gap_tsc]
    call hv_slice_tsc_ms
    call hv_out_dec
.out:
    ret

; RAX = TSC ticks -> EAX = ms, saturated at 0xFFFFFFFF. Uses tsc_khz, or the
; 3 GHz fallback hv_linux_host_slice already uses. Clobbers RAX,RCX,RDX.
hv_slice_tsc_ms:
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .rate
    mov  ecx, 3000000
.rate:
    xor  edx, edx
    div  rcx
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    jbe  .out
    mov  rax, rcx
.out:
    ret

; hv_out_dec(EAX = unsigned value) — append its decimal text via the out cursor.
;   clobbers RAX,RCX,RDX,RSI,RDI
hv_out_dec:
    push rbx
    mov  eax, eax                            ; zero-extend to 64
    lea  rcx, [rel hv_dec_buf + 23]
    mov  byte [rcx], 0
    mov  ebx, 10
.dloop:
    xor  edx, edx
    div  ebx                                 ; eax/=10, edx=remainder
    add  dl, '0'
    dec  rcx
    mov  [rcx], dl
    test eax, eax
    jnz  .dloop
    mov  rdi, rcx
    call hv_out_str
    pop  rbx
    ret

; Passive evidence for a pre-console loop. STAT's last reason is often just
; the timer exit that yielded to its reader, not the cause of guest activity.
; Count every decoded exit; sample the first and each 1024th subsequent
; synchronous exit before emulation advances RIP. No guest instruction/data
; fetch, host address, VMCS write, scheduler call or boot-state assertion.
hv_linux_exit_reset:
    pushfq
    push rax
    push rcx
    push rdi
    lea  rdi, [rel hv_linux_exit_evidence]
    xor  eax, eax
    mov  ecx, (hv_linux_exit_evidence_end - hv_linux_exit_evidence) / 8
    cld
    rep  stosq
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel hv_linux_exit_gen], rax
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; EAX = normalized exit reason. Keep all decoder inputs and flags intact.
; Counters saturate; a saturated sync counter leaves its last sample intact.
hv_linux_exit_observe:
    pushfq
    push rax
    push rcx
    push rdi
    push r11
    lea  rdi, [rel hv_linux_exit_total]
    cmp  qword [rdi], -1
    je   .classify
    inc  qword [rdi]
.classify:
    lea  rdi, [rel hv_linux_exit_other]
    cmp  eax, 30
    jne  .class_timer
    lea  rdi, [rel hv_linux_exit_pio]
    jmp  .count
.class_timer:
    cmp  eax, 52
    jne  .interrupt
    lea  rdi, [rel hv_linux_exit_timer]
    jmp  .count
.interrupt:
    cmp  eax, 1
    jne  .count
    lea  rdi, [rel hv_linux_exit_intr]
.count:
    cmp  qword [rdi], -1
    je   .sample
    inc  qword [rdi]
.sample:
    cmp  eax, 1
    je   .done
    cmp  eax, 7
    je   .done
    cmp  eax, 52
    je   .done
    mov  rcx, [rel hv_linux_exit_sync]
    cmp  rcx, -1
    je   .done
    inc  qword [rel hv_linux_exit_sync]
    test ecx, 1023
    jnz  .done
    mov  [rel hv_linux_exit_sample_reason], rax
    inc  rcx
    mov  [rel hv_linux_exit_sample_n], rcx
    mov  edi, VMXF_G_RIP
    call hv_guest_read
    mov  [rel hv_linux_exit_sample_rip], rax
    mov  edi, VMXF_EXIT_QUAL
    call hv_guest_read
    mov  [rel hv_linux_exit_sample_qual], rax
    mov  edi, VMXF_EXIT_ILEN
    call hv_guest_read
    mov  [rel hv_linux_exit_sample_ilen], rax
    mov  rax, [rel hv_linux_gpr]
    mov  [rel hv_linux_exit_sample_rax], rax
    mov  rax, [rel hv_linux_gpr + 24]
    mov  [rel hv_linux_exit_sample_rdx], rax
.done:
    pop  r11
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; Async exits can continue after synchronous I/O has stopped. Keep a separate
; first/every-1024th async sample: overwriting the last PIO sample would lose
; useful history, while treating it as current execution mislocates a stall.
; Read only the vCPU's existing VMCS/VMCB fields before emulation. Preserve the
; decoder inputs and flags; no guest-memory access, injection or host yield.
hv_linux_async_reset:
    pushfq
    push rax
    push rcx
    push rdi
    lea  rdi, [rel hv_linux_async_evidence]
    xor  eax, eax
    mov  ecx, (hv_linux_async_end - hv_linux_async_evidence) / 8
    cld
    rep  stosq
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; EAX = normalized reason. Async means external interrupt, interrupt window,
; or preemption timer (1/7/52), matching the synchronous sampler's exclusions.
; Saturation retains the last sample; async_n binds its age to async count.
hv_linux_async_observe:
    pushfq
    push rax
    push rcx
    push rdi
    push r11
    cmp  eax, 1
    je   .async
    cmp  eax, 7
    je   .async
    cmp  eax, 52
    jne  .done
.async:
    mov  rcx, [rel hv_linux_async_count]
    cmp  rcx, -1
    je   .done
    inc  qword [rel hv_linux_async_count]
    test ecx, 1023
    jnz  .done
    mov  [rel hv_linux_async_reason], rax
    inc  rcx
    mov  [rel hv_linux_async_n], rcx
    mov  edi, VMXF_G_RIP
    call hv_guest_read
    mov  [rel hv_linux_async_rip], rax
    mov  edi, VMXF_G_RFLAGS
    call hv_guest_read
    mov  [rel hv_linux_async_flags], rax
    mov  edi, VMXF_G_INTERRUPT
    call hv_guest_read
    mov  [rel hv_linux_async_block], rax
    mov  edi, VMXF_ENTRY_INTR
    call hv_guest_read
    mov  [rel hv_linux_async_entry], rax
.done:
    pop  r11
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; Append only retained values to EXITSTAT. The BSP never reads a live VMCS.
; an/asn/arsn/arip/arfl/ablk/aent are count, sample index, reason, RIP,
; RFLAGS, interruptibility and entry-interrupt info; all belong to gen above.
hv_linux_async_render:
    push rbx
    xor  ebx, ebx
.field:
    lea  rdi, [rel hv_linux_async_names]
    add  rdi, rbx
    call hv_out_str
    lea  rax, [rel hv_linux_async_evidence]
    mov  rax, [rax + rbx]
    call hv_linux_exit_hex
    add  ebx, 8
    cmp  ebx, hv_linux_async_end - hv_linux_async_evidence
    jb   .field
    pop  rbx
    ret

; The BSP reader never touches a live VMCS/VMCB or yields. These are retained
; values, also available after STOP; the next actual START clears them.
; QUAL/ILEN applicability follows sample_reason (in particular QUAL for PIO).
hv_linux_exit_render:
    push rbx
    call hv_out_reset
    lea  rdi, [rel str_hv_exit_pre]
    call hv_out_str
    mov  eax, [rel hv_linux_exit_gen]
    call hv_out_dec
    xor  ebx, ebx
.field:
    lea  rdi, [rel hv_linux_exit_names]
    add  rdi, rbx
    call hv_out_str
    lea  rax, [rel hv_linux_exit_evidence]
    mov  rax, [rax + rbx]
    call hv_linux_exit_hex
    add  ebx, 8
    cmp  ebx, hv_linux_exit_evidence_end - hv_linux_exit_evidence
    jb   .field
    pop  rbx
    ret

; Same passive pre-STOP slot as AUDIOSTAT, now joined to EXITSTAT. All cells
; are already retained at owner/closed-executor boundaries; no live VMCS/VMCB,
; guest bytes, host pointers, scheduling, entry or mutation. SVM gen is separate:
; stale records after a different backend or refused START are not current proof.
hv_linux_startup_render:
    lea  rdi, [rel str_hv_startup_start_gen]
    call hv_out_str
    mov  eax, [rel hv_linux_start_gen]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_consumed_gen]
    call hv_out_str
    mov  eax, [rel hv_linux_start_consumed]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_queued]
    call hv_out_str
    movzx eax, byte [rel hv_linux_run_req]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_admission]
    call hv_out_str
    mov  eax, [rel hv_linux_start_refusal]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_starting]
    call hv_out_str
    movzx eax, byte [rel hv_linux_start_active]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_load_err]
    call hv_out_str
    movzx eax, byte [rel hv_linux_load_err]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_running]
    call hv_out_str
    movzx eax, byte [rel hv_linux_running]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_kboot]
    call hv_out_str
    movzx eax, byte [rel hv_linux_kboot]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_con_match]
    call hv_out_str
    mov  eax, [rel hv_linux_match]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_con_len]
    call hv_out_str
    mov  eax, [rel hv_vcon_capture_len]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_con_dropped]
    call hv_out_str
    mov  eax, [rel hv_vcon_capture_overflow]
    call hv_out_dec
    lea  rdi, [rel str_hv_startup_svm_pair]
    call hv_out_str
    mov  rax, [rel vsr_enabled]
    call hv_out_dec
    lea  rdi, [rel str_hv_svm_gen]
    call hv_out_str
    mov  rax, [rel vsm_progress_gen]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_returns0]
    call hv_out_str
    mov  rax, [rel vsm_progress_returns0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_first0]
    call hv_out_str
    mov  rax, [rel vsm_progress_first0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_rip0]
    call hv_out_str
    mov  rax, [rel vsm_progress_rip0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_exit0]
    call hv_out_str
    mov  rax, [rel vsm_progress_exit0]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_returns1]
    call hv_out_str
    mov  rax, [rel vsm_progress_returns1]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_rip1]
    call hv_out_str
    mov  rax, [rel vsm_progress_rip1]
    call hv_linux_exit_hex
    lea  rdi, [rel str_hv_svm_exit1]
    call hv_out_str
    mov  rax, [rel vsm_progress_exit1]
    call hv_linux_exit_hex
    ret

; Fixed-width hexadecimal keeps full guest virtual addresses and u64 counts.
hv_linux_exit_hex:
    push rbx
    mov  rbx, rax
    mov  ecx, 16
.digit:
    rol  rbx, 4
    mov  eax, ebx
    and  eax, 15
    cmp  al, 10
    jb   .number
    add  al, 'a' - 10
    jmp  .put
.number:
    add  al, '0'
.put:
    call hv_out_putc
    dec  ecx
    jnz  .digit
    pop  rbx
    ret

; Account one completed resident interval without changing Task1234's existing
; per-run performance counters or guest lifecycle state.
hv_guestcpu_account_run_stop:
    mov  rcx, [rel hv_linux_run_start_tsc]
    test rcx, rcx
    jz   .out
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, rcx
    jb   .clear
    sub  rax, rcx
    add  [rel hv_guestcpu_run_tsc_accum], rax
.clear:
    mov  qword [rel hv_linux_run_start_tsc], 0
.out:
    ret

; ---------------------------------------------------------------------------
; HV-XCR0 (RCQ-24-HV-guest-vector-state). XCR0 is per core, the vCPU is one
; host task, and the scheduler's XSAVE mask is the boot XCR0. So:
;   V1 a guest XSETBV is checked like hardware before anything is written;
;   V2 host code (exit handlers, the host-slice yield and every task it lets
;      run) runs on host|guest, a valid superset of both: no guest component is
;      cleared under live guest state and no scheduler XRSTOR meets a component
;      XCR0 lacks; the exact guest value is reloaded just before VMRESUME;
;   V3 vector state is reset to its init state before every VMLAUNCH;
;   V4 CPUID, XSETBV and initial XCR0 are bounded by the scheduler save mask.
;   V5 PKRU and Key Locker are never admitted: CR4.PKE/KL are host-owned with
;      a 0 shadow and refused with #GP(0), CPUID hides PKU/OSPKE/KL and leaf
;      0x19, and XCR0 bit 9 is neither initial nor settable.
; ---------------------------------------------------------------------------

; V4: each generation starts with host & scheduler, before any guest XSETBV.
; Keep the host value live until the vector scrub, then load guest before launch.
hv_linux_xcr0_init:
    mov  eax, [rel hv_linux_saved_xcr0]
    mov  edx, [rel hv_linux_saved_xcr0 + 4]
    and  eax, [rel sched_xsave_mask_lo]
    and  edx, [rel sched_xsave_mask_hi]
    and  eax, ~HV_XCR0_GUEST_DENIED          ; V5: not even when the host XCR0 has PKRU
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_linux_guest_xcr0], rax
    mov  rdx, [rel hv_linux_saved_xcr0]
    mov  [rel hv_linux_exit_xcr0], rdx
    cmp  rax, rdx
    setne byte [rel hv_linux_xcr0_swap]
    ret

; EDI=leaf, ESI=subleaf, EAX/EBX/ECX/EDX=native reply. Do not add CPU features.
; Intel SDM rev089, CPUID tables21-19..21-21,21-34..21-36. Supervisor state,
; compacted XSAVE and XFD are not virtualized. Only leaf7 subleaf0 is exposed;
; later subleaves contain additional vector features needing separate admission.
hv_linux_cpuid_filter:
    push rdi                                ; EDI/ESI stay the leaf/subleaf for hv_svm_cpuid_mask
    push rsi
    push r8
    push r9
    mov  r8d, [rel sched_xsave_mask_lo]
    and  r8d, ~HV_XCR0_GUEST_DENIED          ; V5: PKRU is never a guest component
    cmp  edi, 0x19
    je   .zero                              ; V5: no Key Locker leaf
    cmp  edi, 0xD
    je   .xstate
    cmp  edi, 1
    je   .leaf1
    cmp  edi, 6
    je   .leaf6
    cmp  edi, 7
    jne  .out
    test esi, esi
    jnz  .zero
    xor  eax, eax                           ; highest exposed leaf7 subleaf = 0
    and  ebx, ~(1 << 25)                    ; no processor-trace supervisor state
    and  ecx, ~((1 << 5) | (1 << 7) | (1 << 29)) ; WAITPKG, CET_SS, PASID/ENQCMD
    and  edx, ~((1 << 5) | (1 << 19) | (1 << 20)) ; UINTR, architectural LBR, CET_IBT
    and  ecx, ~((1 << 3) | (1 << 4) | (1 << 23)) ; V5: PKU, OSPKE and KL, unconditionally
    test r8d, 4
    jnz  .avx512
    and  ebx, ~(1 << 5)                     ; AVX2 needs saved YMM
    and  ecx, ~((1 << 9) | (1 << 10))        ; VAES, VPCLMULQDQ
.avx512:
    mov  r9d, r8d
    and  r9d, 0xE6
    cmp  r9d, 0xE6
    je   .mpx
    and  ebx, ~((1 << 16) | (1 << 17) | (1 << 21) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 30) | (1 << 31))
    and  ecx, ~((1 << 1) | (1 << 6) | (1 << 11) | (1 << 12) | (1 << 14))
    and  edx, ~((1 << 2) | (1 << 3) | (1 << 8) | (1 << 23))
.mpx:
    mov  r9d, r8d
    and  r9d, 0x18
    cmp  r9d, 0x18
    je   .amx
    and  ebx, ~(1 << 14)
    and  ecx, ~(0x1F << 17)                 ; MPX MAWAU
.amx:
    and  r8d, 0x60000
    cmp  r8d, 0x60000
    je   .out
    and  edx, ~((1 << 22) | (1 << 24) | (1 << 25))
    jmp  .out
.leaf1:
    ; A virtual CPU must report its own hypervisor presence, even on metal.
    ; Linux uses this to avoid probing unassigned model-specific platform MMIO.
    ; Presence does not expose the outer hypervisor's paravirtual namespace.
    and  ecx, 0xFFFFFFDF                    ; no unsupported nested VMX
    or   ecx, 0x80000000                    ; this CPU runs under PaOS
    test r8d, 4
    jnz  .out
    and  ecx, ~((1 << 12) | (1 << 28) | (1 << 29)) ; FMA, AVX, F16C
    jmp  .out
.leaf6:
    and  ecx, ~1                            ; retain the APERF/MPERF exclusion
    jmp  .out
.xstate:
    test esi, esi
    jz   .xstate0
    cmp  esi, 1
    je   .xstate1
    cmp  esi, 64
    jae  .zero                              ; BT register indices otherwise wrap
    mov  r9d, [rel sched_xsave_mask_hi]
    shl  r9, 32
    or   r8, r9
    bt   r8, rsi
    jnc  .zero
    test ecx, 1                             ; never expose IA32_XSS components
    jnz  .zero
    and  ecx, ~4                            ; no XFD per-component admission
    jmp  .out
.xstate1:
    and  eax, 5                             ; XSAVEOPT and XGETBV1 only
    xor  ebx, ebx                           ; neither XSAVEC nor XSAVES -> size0
    xor  ecx, ecx                           ; no IA32_XSS bits
    xor  edx, edx
    jmp  .out
.xstate0:
    and  eax, r8d
    and  edx, [rel sched_xsave_mask_hi]
    mov  r8d, eax
    shl  rdx, 32
    or   r8, rdx                            ; CPU-supported & scheduler-switched
    mov  rdi, [rel hv_linux_guest_xcr0]
    and  rdi, r8
    call hv_linux_xstate_size
    mov  ebx, eax                           ; bytes for guest-enabled components
    mov  rdi, r8
    call hv_linux_xstate_size
    mov  ecx, eax                           ; bytes for all advertised components
    mov  eax, r8d
    mov  rdx, r8
    shr  rdx, 32
    jmp  .out
.zero:
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
.out:
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    ret

; RDI=XCR0 component mask -> EAX=standard XSAVE area size. Preserve the other
; CPUID reply registers. Native component offsets remain the standard format;
; the end is max(576, offset+size) over the selected extended components.
hv_linux_xstate_size:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    mov  r8, rdi
    xor  r10d, r10d
    test r8, r8
    jz   .done
    mov  r10d, 576
    mov  r9d, 2
.next:
    bt   r8, r9
    jnc  .advance
    mov  eax, 0xD
    mov  ecx, r9d
    cpuid
    add  eax, ebx
    cmp  eax, r10d
    cmova r10d, eax
.advance:
    inc  r9d
    cmp  r9d, 64
    jb   .next
.done:
    mov  eax, r10d
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; hv_linux_xcr0_check(EDI=XCR index, RSI=value, RDX=supported) -> EAX=0 when
; hardware would accept XSETBV, else the first rule it breaks:
;   1 index != 0, 2 unsupported bit, 3 x87 clear, 4 AVX without SSE,
;   5 AVX-512 partial, 6 AVX-512 without AVX, 7 MPX pair split, 8 AMX pair split
hv_linux_xcr0_check:
    mov  eax, 1
    test edi, edi
    jnz  .out
    mov  eax, 2
    mov  rcx, rdx
    not  rcx
    test rsi, rcx
    jnz  .out
    mov  eax, 3
    test esi, 1
    jz   .out
    mov  eax, 4
    mov  ecx, esi
    and  ecx, 6
    cmp  ecx, 4
    je   .out
    mov  eax, 5
    mov  ecx, esi
    and  ecx, 0xE0
    jz   .mpx
    cmp  ecx, 0xE0
    jne  .out
    mov  eax, 6
    test esi, 4
    jz   .out
.mpx:
    mov  eax, 7
    mov  ecx, esi
    and  ecx, 0x18
    jz   .amx
    cmp  ecx, 0x18
    jne  .out
.amx:
    mov  eax, 8
    mov  ecx, esi
    and  ecx, 0x60000
    jz   .ok
    cmp  ecx, 0x60000
    jne  .out
.ok:
    xor  eax, eax
.out:
    ret

; hv_linux_xcr0_apply(RDI=checked guest XCR0): record it, derive the exit value
; host|guest, and leave the core on the exit value (the guest value is loaded
; by hv_linux_xcr0_to_guest right before VMRESUME).
hv_linux_xcr0_apply:
    mov  [rel hv_linux_guest_xcr0], rdi
    mov  rax, [rel hv_linux_saved_xcr0]
    or   rax, rdi
    mov  [rel hv_linux_exit_xcr0], rax
    cmp  rax, rdi
    setne byte [rel hv_linux_xcr0_swap]
    ; A completed SVM host slice restored the native XCR0 and released its
    ; guard. An XSETBV exit decoded after that slice updates guest bookkeeping
    ; only: do not turn its union into the next native-host snapshot. Fresh
    ; guarded SVM re-entry recomputes/applies the union after capturing the host.
    mov  rdx, [rel hv_svm_boundary_frame]
    test rdx, rdx
    jz   .apply
    cmp  qword [rdx + HVB_GUARD], 0
    je   .out
.apply:
    mov  rdx, rax
    shr  rdx, 32
    xor  ecx, ecx
    xsetbv
.out:
    ret

hv_linux_xcr0_to_host:
    cmp  byte [rel hv_linux_xcr0_swap], 1
    jne  .out
    mov  eax, [rel hv_linux_exit_xcr0]
    mov  edx, [rel hv_linux_exit_xcr0 + 4]
    xor  ecx, ecx
    xsetbv
.out:
    ret

hv_linux_xcr0_to_guest:
    cmp  byte [rel hv_linux_xcr0_swap], 1
    jne  .out
    mov  eax, [rel hv_linux_guest_xcr0]
    mov  edx, [rel hv_linux_guest_xcr0 + 4]
    xor  ecx, ecx
    xsetbv
.out:
    ret

; hv_linux_xcr0_adopt: guestsnap_cpu_load left the core on the restored guest
; XCR0. Record it as the guest value exactly as a checked XSETBV would, so the
; host runs on host|guest and the guest value is reloaded before entry.
hv_linux_xcr0_adopt:
    cmp  byte [rel hv_linux_xcr0_saved], 1
    jne  .out
    xor  ecx, ecx
    xgetbv
    shl  rdx, 32
    mov  eax, eax
    or   rax, rdx
    mov  rdi, rax
    jmp  hv_linux_xcr0_apply
.out:
    ret

; hv_linux_vector_scrub — x87/SSE/AVX… to their init state, MXCSR 0x1F80.
; XRSTOR with XSTATE_BV=0 initialises every component in RFBM (= the live XCR0);
; without XSAVE, FXRSTOR loads the zero image. Both are unprivileged.
hv_linux_vector_scrub:
    ; XCR0.SSE may be clear while SSE instructions remain usable. An XRSTOR
    ; mask taken from XCR0=1 resets only x87: explicitly reset x87/SSE first.
    fxrstor [rel hv_scrub_area]
    cmp  byte [rel hv_linux_xcr0_saved], 1
    jne  .out
    xor  ecx, ecx
    xgetbv
    xrstor [rel hv_scrub_area]
.out:
    ret

align 64
hv_scrub_area:                               ; read-only XSAVE standard-form image
    dw 0x037F                                ; FCW: the FNINIT value
    times 22 db 0
    dd 0x1F80                                ; MXCSR (offset 24): the reset value
    dd 0                                     ; MXCSR_MASK (ignored by restore)
    times 512 - 32 db 0                      ; ST0-7, XMM0-15 zero
    times 64 db 0                            ; XSAVE header: XSTATE_BV = XCOMP_BV = 0
.end:
%if hv_scrub_area.end - hv_scrub_area != 576
    %error "hv_scrub_area must be the 512-byte legacy image plus the 64-byte header"
%endif

; --- the guest: entered in 64-bit mode sharing host page tables; HLT-exiting is
;     set so HLT immediately VM-exits with basic reason 12. Skipping past HLT lands
;     on the jmp, which loops back for the next bounded resume. ---
align 16
hv_guest_code:
    hlt
    jmp  hv_guest_code

; --- hv/vmx state (post-paging RW; in-image data our page tables map RW) ---
; RCQ-18 S2-0 STAT fields. Read-only, so outside the WDATA blocks (whose layout
; test_rc_zero_storage_bss_host.py pins).
str_hv_stat_intr_exits: db " intr_exits=", 0
str_hv_stat_host_slices: db " host_slices=", 0
; T2-4 D8 Intel S7 slice diagnostic (VM 107717): read-only, same placement rule.
str_hv_stat_slice_timer: db " slice_timer_exits=", 0
str_hv_stat_slice_nonroot: db " slice_nonroot_ms=", 0
str_hv_stat_slice_yield: db " slice_yield_ms=", 0
str_hv_stat_slice_gap: db " slice_max_gap_ms=", 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_vmx_0 0
times 7 db 0                  ; hv_vmx_present..hv_pic_vec_base moved to WDATA_hv_vmx_0_bss1: keeps the labels below at their offset mod 64
hv_pic_mask:       db 0xFF
hv_pic_mask_s:     db 0xFF
hv_port61:         db 0
hv_pit2_mode0:     db 0
hv_pit2_armed:     db 0
                  align 8
hv_pit2_remaining: dq 0
hv_pit2_deadline:  dq 0
hv_pit_ff:         times 3 db 0
hv_pit_latched:    times 3 db 0
                  align 8
hv_vmxon_pa:      dq 0
hv_vmcs_pa:       dq 0
hv_ept_pml4_pa:   dq 0
hv_eptp:          dq 0
hv_saved_cr0:     dq 0
hv_saved_cr4:     dq 0
hv_saved_rflags:  dq 0
hv_out_cur:       dq 0
; --- 1095 launch tier state ---
hv_val_ok:        dq 0                       ; 1 = last validate found host-state sane
hv_val_field:     dq 0                       ; ptr to the offending field name on refusal
hv_launch_base:   dq 0                       ; lazily-allocated 12 KiB launch region
hv_launch_vmxon_pa: dq 0
hv_launch_vmcs_pa:  dq 0
hv_launch_rflags: dq 0
hv_launch_cr0:    dq 0                       ; saved host CR0/CR4 (restore after excursion)
hv_launch_cr4:    dq 0
hv_launch_hcr0:   dq 0                       ; VMX-fixed host CR0/CR3/CR4 (VMCS host+guest)
hv_launch_hcr3:   dq 0
hv_launch_hcr4:   dq 0
hv_linux_region:  dq 0                       ; this START's shared span (0 outside a START)
hv_linux_region_capacity: dq 0               ; page-rounded span bytes from the control base
hv_linux_region_resident: dq 0               ; exact resident subset bound to the held allocator token
hv_linux_ram:     dq 0                       ; region + HV_LINUX_CTRL_BYTES
hv_linux_ram_bytes: dq HV_LINUX_NORMAL_RAM_BYTES
; hv_linux_kernel_name_ptr..hv_out_buf moved to WDATA_hv_vmx_0_bss2 (zero-fill tail)

str_hv_vcon_proof_roll_tail: db " vendor=0x10ec echo=FIXTURE-NONCE-1012", 13, 10, 0
str_hv_vcon_proof_roll_vendor: db "0x10ec", 0
str_hv_vcon_proof_roll_nonce: db "FIXTURE-NONCE-1012", 0

; Numeric-only VMCS pairs, terminated by -1. Runtime addresses are written
; separately with LEA/live register reads; no static symbol is used as a VA.
align 8
hv_linux_vmcs_const_table:
    dq VMXF_HOST_CS_SEL, 0x08, VMXF_HOST_SS_SEL, 0x10
    dq VMXF_HOST_ES_SEL, 0x10, VMXF_HOST_DS_SEL, 0x10
    dq VMXF_HOST_FS_SEL, 0x10, VMXF_HOST_GS_SEL, 0x10
    dq VMXF_HOST_TR_SEL, 0x18
    dq VMXF_H_FS_BASE, 0, VMXF_H_GS_BASE, 0
    dq VMXF_H_SYSENTER_CS, 0, VMXF_H_SYSENTER_ESP, 0, VMXF_H_SYSENTER_EIP, 0
    dq VMXF_G_CR3, 0x1000, VMXF_G_DR7, 0x400
    dq VMXF_GUEST_CS_SEL, 0x08, VMXF_G_CS_BASE, 0
    dq VMXF_G_CS_LIMIT, 0xFFFFFFFF, VMXF_G_CS_AR, 0xA09B
    dq VMXF_GUEST_SS_SEL, 0x10, VMXF_G_SS_BASE, 0
    dq VMXF_G_SS_LIMIT, 0xFFFFFFFF, VMXF_G_SS_AR, 0xC093
    dq VMXF_GUEST_DS_SEL, 0x10, VMXF_G_DS_BASE, 0
    dq VMXF_G_DS_LIMIT, 0xFFFFFFFF, VMXF_G_DS_AR, 0xC093
    dq VMXF_GUEST_ES_SEL, 0x10, VMXF_G_ES_BASE, 0
    dq VMXF_G_ES_LIMIT, 0xFFFFFFFF, VMXF_G_ES_AR, 0xC093
    dq VMXF_GUEST_FS_SEL, 0x10, VMXF_G_FS_BASE, 0
    dq VMXF_G_FS_LIMIT, 0xFFFFFFFF, VMXF_G_FS_AR, 0xC093
    dq VMXF_GUEST_GS_SEL, 0x10, VMXF_G_GS_BASE, 0
    dq VMXF_G_GS_LIMIT, 0xFFFFFFFF, VMXF_G_GS_AR, 0xC093
    dq VMXF_GUEST_LDTR_SEL, 0, VMXF_G_LDTR_BASE, 0
    dq VMXF_G_LDTR_LIMIT, 0, VMXF_G_LDTR_AR, 0x10000
    dq VMXF_GUEST_TR_SEL, 0x18, VMXF_G_TR_BASE, 0
    dq VMXF_G_TR_LIMIT, 0x67, VMXF_G_TR_AR, 0x8B
    dq VMXF_G_GDTR_BASE, 0, VMXF_G_GDTR_LIMIT, 0
    dq VMXF_G_IDTR_BASE, 0, VMXF_G_IDTR_LIMIT, 0
    dq VMXF_G_RSP, 0x8000, VMXF_G_RIP, HV_LINUX_KERN_GPA + 0x200
    dq VMXF_G_RFLAGS, 2, VMXF_G_INTERRUPT, 0, VMXF_G_ACTIVITY, 0
    dq VMXF_G_PEND_DBG, 0
    dq VMXF_G_SYSENTER_CS, 0, VMXF_G_SYSENTER_ESP, 0, VMXF_G_SYSENTER_EIP, 0
    dq -1, 0

; --- serial markers (regression_tests.txt: hw-only; QEMU-TCG has no VMX) ---
str_hv_detected:   db "[PAOS64] P8 hv: Intel VMX present, IA32_FEATURE_CONTROL ok [hv.vmx.detected]", 13, 10, 0
str_hv_absent:     db "[PAOS64] P8 hv: no Intel VMX (AMD/old/QEMU-TCG) — degrade, host-only [hv.vmx.absent]", 13, 10, 0
str_hv_locked:     db "[PAOS64] P8 hv: VT-x BIOS-locked off (FEATURE_CONTROL lock=1 en=0) — degrade [hv.vmx.locked]", 13, 10, 0
str_hv_vmxon:      db "[PAOS64] P8 hv: VMXON->VMCLEAR->VMPTRLD ok, in VMX root (no launch) [hv.vmxon.ok]", 13, 10, 0
str_hv_vmxon_fail: db "[PAOS64] P8 hv: VMXON failed (CF/ZF) — degrade, host-only [hv.vmxon.fail]", 13, 10, 0
str_hv_vmcs_fail:  db "[PAOS64] P8 hv: VMCS clear/load failed — VMXOFF, degrade [hv.vmxon.fail]", 13, 10, 0
str_hv_ept:        db "[PAOS64] P8 hv: 4-level EPT built (PML4/PDPT/PD/PT), EPTP composed WB [hv.ept.mapped]", 13, 10, 0
str_hv_ept_fail:   db "[PAOS64] P8 hv: EPT alloc failed — degrade [hv.ept.fail]", 13, 10, 0
str_hv_initdone:   db "[PAOS64] P8 hv: foundation bring-up complete (VMX-root + Linux R2 loader) [hv.init.done]", 13, 10, 0

; --- GUEST verb names + honest reply lines ---
str_verb_guestvm:    db "GUESTVM", 0
str_hv_boot_profile: db "thin-cli", 0
str_hv_boot_requested: db "[PAOS64] boot.guest.early.requested profile=thin-cli", 13, 10, 0
%if PAOS_LAB_BOOT_GUEST_OFF
str_hv_boot_skipped: db "[PAOS64] boot.guest.early.skip reason=lab_diagnostic", 13, 10, 0
%endif
str_verb_guestlinux: db "GUESTLINUX", 0
str_verb_guestkey:   db "GUESTKEY", 0
str_hv_guestvm_line:    db " GUESTVM vmx_root_foundation v1;", 0
str_hv_guestlinux_line: db " GUESTLINUX guest_boot_tier=linux_lives_virtio;", 0
str_hv_guest_identity_template: db "PAOS_GUEST_SSH_IDENTITY boot_id=", "00000000-0000-0000-0000-000000000000", " algorithm=ED25519 fingerprint=SHA256:"
str_hv_guest_identity_gen: db " guest_ssh_identity_gen=", 0
str_hv_guest_identity_field: db " guest_ssh_identity=", 0
str_hv_guest_identity_conflict: db " guest_ssh_identity=conflict", 0
str_hv_guest_output:    db " output=", 0
str_hv_guestkey_ok:     db " GUESTKEY delivered=1 transport=virtio_mmio", 0
str_hv_guestkey_no:     db " GUESTKEY delivered=0 transport=virtio_mmio no_rx_buffer=1", 0
str_hv_guestkey_long:   db " GUESTKEY delivered=0 transport=virtio_mmio line_too_long=1 max_text=255", 0
str_hv_s_vmx:   db " vmx=", 0
str_hv_s_vmxon: db " vmxon=", 0
str_hv_s_ept:   db " ept=", 0
str_hv_s_tier:  db " guest_tier=linux_lives_virtio", 0

; --- 1095 R1 sub-verb tokens + verdict lines ---
str_sub_launch:   db "LAUNCH", 0
str_sub_start:    db "START", 0
str_sub_recover:  db "RECOVER", 0
str_recover_good: db "good", 0
str_recover_recovery: db "recovery", 0
str_sub_stat:     db "STAT", 0
str_sub_warmstat: db "WARMSTAT", 0
str_sub_vcpustat: db "VCPUSTAT", 0
str_sub_audiostat: db "AUDIOSTAT", 0
str_hv_audio_pre: db " GUESTVM AUDIOSTAT rev=1 start_gen=", 0
str_hv_audio_consumed: db " consumed_gen=", 0
str_hv_audio_queued: db " queued=", 0
str_hv_audio_starting: db " starting=", 0
str_hv_audio_args: db " GUESTVM AUDIOSTAT error=args", 0
str_hv_svm_gen: db " svm_gen=0x", 0
str_hv_svm_returns0: db " svm_returns0=0x", 0
str_hv_svm_first0: db " svm_first0=0x", 0
str_hv_svm_rip0: db " svm_rip0=0x", 0
str_hv_svm_exit0: db " svm_exit0=0x", 0
str_hv_svm_returns1: db " svm_returns1=0x", 0
str_hv_svm_rip1: db " svm_rip1=0x", 0
str_hv_svm_exit1: db " svm_exit1=0x", 0
str_hv_boundary_args: db " GUESTVM BOUNDSTAT error=args", 0
str_hv_exec_args: db " GUESTVM BOUNDEXEC error=args",0
str_sub_ctxexec: db "CTXEXEC",0
str_hv_ctx_args: db " GUESTVM CTXEXEC error=args",0
str_sub_capcase: db "CAPCASE",0
str_hv_cap_args: db " GUESTVM CAPCASE error=args",0
str_sub_boundexec: db "BOUNDEXEC",0
str_sub_boundcost: db "BOUNDCOST",0
str_sub_boundstat: db "BOUNDSTAT", 0
str_sub_boundstat_amd: db "AMD", 0
str_sub_boundstat_intel: db "INTEL", 0
str_sub_exitstat: db "EXITSTAT", 0
str_sub_profiles: db "PROFILES", 0           ; RCQ-18 profile verbs
str_sub_plan:     db "PLAN", 0
str_sub_gate:     db "GATE", 0             ; read-only assignment isolation verdict
str_sub_gate_args: db " GUESTVM GATE REFUSED args", 0
str_sub_stop:     db "STOP", 0
str_sub_input:   db "INPUT", 0
str_sub_pin1:    db "PIN1", 0
str_sub_restoreport: db "RESTOREPORT", 0
str_sub_snapshot: db "SNAPSHOT", 0
str_sub_resume:   db "RESUME", 0
str_sub_resume_refused: db " GUESTVM RESUME refused=1 err=", 0
str_hv_profile_refused: db " REFUSED", 0
str_sub_panic:    db "PANIC", 0
str_sub_badrsp:   db "inject-bad", 0        ; substring of --inject-bad-rsp

str_hv_val_pre:      db " GUESTVM VALIDATE ", 0
str_hv_val_ok:       db "hoststate=ok host_tr_present=1 rsp_canonical=1", 0
str_hv_val_refused:  db "hoststate=bad REFUSED field=", 0

str_hv_f_vmx:   db "vmx", 0
str_hv_f_cr0:   db "cr0", 0
str_hv_f_cr4:   db "cr4", 0
str_hv_f_cr3:   db "cr3", 0
str_hv_f_tr:    db "tr", 0
str_hv_f_cs:    db "cs", 0
str_hv_f_ss:    db "ss", 0
str_hv_f_rsp:   db "rsp", 0

str_hv_stat_pre:      db " GUESTVM STAT vmx_root=1", 0
str_hv_startup_start_gen: db " start_gen=", 0
str_hv_startup_consumed_gen: db " consumed_gen=", 0
str_hv_startup_queued: db " queued=", 0
str_hv_startup_admission: db " admission=", 0
str_hv_startup_starting: db " starting=", 0
str_hv_startup_load_err: db " load_err=", 0
str_hv_startup_running: db " running=", 0
str_hv_startup_kboot: db " kboot=", 0
str_hv_startup_con_match: db " con_match=", 0
str_hv_startup_con_len: db " con_len=", 0
str_hv_startup_con_dropped: db " con_dropped=", 0
str_hv_startup_svm_pair: db " svm_pair=", 0
str_hv_exit_pre: db " GUESTVM EXITSTAT rev=1 gen=", 0
; Eight-byte NUL-terminated labels in the same order as the retained values.
hv_linux_exit_names:
    db " total=", 0
    db " pio=", 0, 0, 0
    db " timer=", 0
    db " intr=", 0, 0
    db " other=", 0
    db " sync=", 0, 0
    db " n=", 0, 0, 0, 0, 0
    db " rsn=", 0, 0, 0
    db " rip=", 0, 0, 0
    db " qual=", 0, 0
    db " ilen=", 0, 0
    db " rax=", 0, 0, 0
    db " rdx=", 0, 0, 0
%if $ - hv_linux_exit_names != 13 * 8
    %error "exit evidence labels must match the thirteen retained qwords"
%endif
hv_linux_async_names:
    db " an=", 0, 0, 0, 0
    db " asn=", 0, 0, 0
    db " arsn=", 0, 0
    db " arip=", 0, 0
    db " arfl=", 0, 0
    db " ablk=", 0, 0
    db " aent=", 0, 0
%if $ - hv_linux_async_names != 7 * 8
    %error "async exit labels must match seven retained qwords"
%endif
str_hv_stat_refused:  db " last_launch=REFUSED field=", 0
; Same fixed diagnostic contract as SVM: never render a stale host-validator pointer.
str_hv_guard_refused: db "vmx_guard", 0
str_hv_boundary_refused: db "vmx_boundary", 0
str_hv_stat_launches: db " launches=", 0
str_hv_stat_hlt:      db " hlt_exits=", 0
str_hv_stat_reason:   db " vmexit_reason=", 0
str_hv_stat_kboot:    db " kboot=", 0
str_hv_stat_loaderr:  db " load_err=", 0
str_hv_s7_admission: db "s7_admission", 0
str_hv_audio_admission: db " admission=", 0
str_hv_stat_loadgen:  db " load_gen=", 0
str_hv_stat_loadphase: db " load_phase=", 0
str_hv_stat_starting: db " starting=", 0
str_hv_stat_linux_exits: db " linux_exits=", 0
str_hv_stat_running:  db " running=", 0
str_hv_stat_ticks:    db " inj_ticks=", 0
str_hv_stat_jiffies:  db " guest_jiffies=", 0
str_hv_stat_console:  db " console_backend=virtio_mmio", 0
str_hv_stat_uart:     db " uart_fallback=ttyS0", 0
str_hv_stat_vstatus:  db " vcon_status=", 0
str_hv_stat_vrxq:     db " vcon_rxq_ready=", 0
str_hv_stat_vtxq:     db " vcon_txq_ready=", 0
str_hv_stat_vrxused:  db " vcon_rx_used=", 0
str_hv_stat_vtxused:  db " vcon_tx_used=", 0
str_hv_stat_panicked: db " state=panicked panic_source=guest_kernel panic_text=1", 0
str_hv_stat_host:     db " host=alive", 0

str_hv_panic_armed:   db " GUESTVM PANIC panic_armed=1", 0
str_hv_panic_refused: db " GUESTVM PANIC panic_armed=0 REFUSED", 0
str_hv_panic_prefix:  db "Kernel panic", 0

str_hv_hlt_marker: db "[PAOS64] P8 hv: VMLAUNCH->HLT decoded VM-exit reason 12 (HLT), host survived [hv.vmlaunch.hlt_exit]", 13, 10, 0
str_hv_guest_launched_marker: db "[PAOS64] P8 hv: first staged Linux console byte observed after VMLAUNCH [guest.launched]", 13, 10, 0
str_hv_guest_boot_marker: db "[PAOS64] P8 hv: staged Linux console reached its configured init entry, guest resident [guest.booted] [hv.guest.boot]", 13, 10, 0
str_hv_vcon_marker: db "[PAOS64] P8 hv: Linux negotiated virtio-mmio console status 15 with RX/TX queues [hv.virtio.console.ready]", 13, 10, 0
str_hv_linux_cmdline: db "earlycon=uart8250,io,0x3f8 console=ttyS0 console=hvc0 rdinit=/init panic=-1 oops=panic loglevel=8 nolapic noapic no_timer_check lpj=4000000 tsc=reliable idle=halt clearcpuid=124 pci=off nokaslr virtio_mmio.device=4K@0xD0000000:5 virtio_mmio.device=4K@0xD0001000:6", 0
str_hv_linux_cmdline_vtd: db "earlycon=uart8250,io,0x3f8 console=ttyS0 console=hvc0 rdinit=/init panic=-1 oops=panic loglevel=8 nolapic noapic no_timer_check lpj=4000000 tsc=reliable idle=halt clearcpuid=124 pci=conf1 nokaslr virtio_mmio.device=4K@0xD0000000:5 virtio_mmio.device=4K@0xD0001000:6", 0
; This first physical rung uses the faithfully-emulated dual-8259 path. Keep
; MSI disabled until a guest LAPIC model exists; the vPCI capability remains.
str_hv_linux_cmdline_vtd_net: db "earlycon=uart8250,io,0x3f8 console=ttyS0 console=hvc0 rdinit=/init panic=-1 oops=panic loglevel=8 nolapic noapic no_timer_check lpj=4000000 tsc=reliable idle=halt clearcpuid=124 pci=conf1 pci=nomsi nokaslr virtio_mmio.device=4K@0xD0000000:5 virtio_mmio.device=4K@0xD0001000:6", 0
str_hv_linux_cmdline_vtd_domain: db "earlycon=uart8250,io,0x3f8 console=ttyS0 console=hvc0 rdinit=/bin/sh panic=-1 oops=panic loglevel=8 nolapic noapic no_timer_check lpj=4000000 tsc=reliable idle=halt clearcpuid=124 pci=conf1 pci=nomsi virtio_mmio.device=4K@0xD0000000:5 virtio_mmio.device=4K@0xD0001000:6", 0
str_hv_linux_kboot: db "Run /init", 0
str_hv_linux_domain_kboot: db "Run /bin/sh", 0
hv_linux_cr_gpr_map: db 0,16,24,8,0xFF,48,32,40,56,64,72,80,88,96,104,112
%endmacro
WDATA_DEFER WDATA_hv_vmx_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_hv_vmx_0_bss1 0
hv_vmx_present:   resb 1
hv_vmxon_ok:      resb 1
hv_ept_built:     resb 1
hv_out_ready:     resb 1
hv_hlt_exit_seen: resb 1                     ; earned: a decoded reason-12 exit fired (BOOTLOG/serial)
hv_linux_kboot:    resb 1                     ; exact configured guest init-console phrase only
hv_guest_launched: resb 1                     ; sticky: first real post-VMLAUNCH console byte
hv_guest_booted:   resb 1                     ; sticky: exact guest console reached init
hv_linux_load_err: resb 1                     ; 0=loaded/launched; nonzero failed rung
hv_linux_load_phase: resb 1                   ; last preparation phase; see load_gen
hv_linux_load_gen: resd 1                     ; consumed START generation at prepare entry
hv_launch_mode:    resb 1                     ; 0=R1 HLT stub, 1=R2 Linux appliance
hv_linux_vmx_live: resb 1
hv_linux_xcr0_saved: resb 1
hv_launch_refused: resb 1                    ; last LAUNCH refused by host-state validation
hv_launch_vmcsfail: resb 1
hv_launch_vmxonfail: resb 1
hv_linux_running:  resb 1                     ; live only while resident vCPU owns VMX
hv_linux_stop_req: resb 1                     ; cooperative teardown at next clean VM-exit
hv_linux_start_refusal: resd 1            ; consumed generation S7 pre-loader refusal
hv_linux_task_started: resb 1                 ; scheduler slot installed once
hv_linux_run_req:  resb 1
hv_linux_start_active: resb 1                 ; accepted request is loading or in VMX
hv_first_ud_diag_active: resb 1               ; effective VMCS bitmap owns #UD bit
hv_vcon_proof_roll_active: resb 1             ; ordinary Task1012 injection window only
hv_vcon_proof_roll_fixture_ok: resb 1
hv_vcon_proof_roll_fixture_stage: resb 1
hv_first_ud_fixture_ok: resb 1
                  alignb 4
hv_first_ud_fixture_stage: resd 1
                  alignb 8
hv_gva_walk_pml4e: resq 1
hv_gva_walk_pdpte: resq 1
hv_gva_walk_pde: resq 1
hv_gva_walk_pte: resq 1
hv_gva_walk_page_size: resq 1
hv_gva_walk_gpa: resq 1
hv_gva_walk_offset: resq 1
hv_gva_walk_valid: resb 1
hv_gva_walk_fail_level: resb 1
                  alignb 8
hv_first_ud_receipt_begin:
hv_first_ud_valid: resq 1
hv_first_ud_info: resq 1
hv_first_ud_error: resq 1
hv_first_ud_idt_info: resq 1
hv_first_ud_idt_error: resq 1
hv_first_ud_rip: resq 1
hv_first_ud_rsp: resq 1
hv_first_ud_rflags: resq 1
hv_first_ud_cr2: resq 1
hv_first_ud_cr3: resq 1
hv_first_ud_cr4: resq 1
hv_first_ud_cs: resq 1
hv_first_ud_gen: resq 1
hv_first_ud_ordinal: resq 1
hv_first_ud_no_reinject: resq 1
hv_first_ud_exit_reason: resq 1
hv_first_ud_walker_valid: resq 1
hv_first_ud_page_size: resq 1
hv_first_ud_gpa: resq 1
hv_first_ud_offset: resq 1
hv_first_ud_pml4e: resq 1
hv_first_ud_pdpte: resq 1
hv_first_ud_pde: resq 1
hv_first_ud_pte: resq 1
hv_first_ud_insn_len: resq 1
hv_first_ud_console_len: resq 1
hv_first_ud_console_overflow: resq 1
hv_first_ud_bitmap_requested: resq 1
hv_first_ud_bitmap_readback: resq 1
hv_first_ud_first_r0_info: resq 1
hv_first_ud_first_r0_gen: resq 1
hv_first_ud_insn: resq 2
hv_first_ud_gpr: resq 15
hv_first_ud_console: resb HV_VCON_CAP_MAX
hv_first_ud_receipt_end:
hv_first_ud_fixture_copy: resq 2
hv_first_ud_fixture_diag_save: resd 1
                  alignb 8
hv_ept_exit_gpa:   resq 1                     ; latched before EPT dispatch/formatting
hv_ept_exit_qual:  resq 1
hv_ept_exit_rip:   resq 1
hv_ept_exit_gla:   resq 1
hv_ept_exit_insn:  resq 1                     ; little-endian instruction prefix
hv_ept_exit_gen:   resd 1                     ; binds detail to accepted start generation
hv_ept_exit_ilen:  resd 1                     ; raw VMCS field; zero is retained
hv_ept_ilen_mismatch: resd 1                  ; SEC-D2: nonzero raw ILEN != decoded length (advisory)
hv_ept_exit_insn_len: resd 1
hv_ept_exit_decode_len: resd 1
hv_ept_exit_access: resb 1
hv_ept_exit_decode: resb 1
hv_ept_exit_class:  resb 1
hv_ept_exit_action: resb 1
hv_ept_exit_bar_match: resb 1
hv_linux_panicked: resb 1                     ; earned from injected #UD + console text
hv_panic_armed:    resb 1
hv_panic_injected: resb 1
hv_panic_text:     resb 1
hv_vcon_ready:     resb 1                     ; status=15 and both queues ready
hv_vcon_irq_pend:  resb 1
hv_vcon_irq_inj:   resb 1
hv_vcon_q_ready:   resb 2
hv_pic_state_m:    resb 1                     ; 8259 ICW phase
hv_pic_state_s:    resb 1
hv_pic_icw1_m:     resb 1
hv_pic_icw1_s:     resb 1
hv_pic_vec_base:   resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_vmx_0_bss1
%macro WDATA_hv_vmx_0_bss2 0
resb 32                 ; keeps hv_linux_kernel_name_ptr at its WDATA offset mod 64
hv_linux_kernel_name_ptr: resq 1             ; populated with relocated VA at registration
hv_linux_initrd_name_ptr: resq 1              ; populated with relocated VA at registration
hv_linux_initrd_gpa: resq 1                  ; RCQ-18: where the last START placed the initramfs
hv_linux_eptp:    resq 1
hv_linux_deadline: resq 1
hv_linux_run_start_tsc: resq 1
hv_vmx_host_deadline: resq 1                 ; ROOT109896 (4): TSC by which the host is owed a turn
hv_linux_load_tsc: resq 1                    ; TSC at the START loader's last host turn
hv_guestcpu_run_tsc_accum: resq 1            ; boot-monotonic resident VMX time
hv_guestcpu_last_progress_tsc: resq 1         ; latest completed common VM-exit
hv_guestcpu_interrupts: resq 1                ; successful guest IRQ0 injections
hv_guestcpu_halt_wakes: resq 1                ; decoded guest HLT exits
hv_guestcpu_faults: resq 1                    ; fatal guest/VM-entry failures
hv_last_tick_tsc: resq 1
hv_linux_saved_efer: resq 1
hv_linux_saved_xcr0: resq 1
hv_linux_saved_star: resq 1
hv_linux_saved_lstar: resq 1
hv_linux_saved_cstar: resq 1
hv_linux_saved_fmask: resq 1
hv_linux_saved_kgs: resq 1
hv_gdt_base:      resq 1
hv_idt_base:      resq 1
hv_gdt_limit:     resd 1
hv_idt_limit:     resd 1
hv_launches:      resd 1                     ; VMLAUNCH attempts this session
hv_linux_boot_attempted: resb 1
hv_linux_boot_queued: resb 1
alignb 4
hv_linux_boot_gen: resd 1
hv_linux_start_gen: resd 1                   ; caller-published restart generation
hv_linux_start_consumed: resd 1              ; generation accepted by resident task
                  alignb 8
hv_guest_launched_ms: resq 1                 ; zero until guest output proves a launch
hv_hlt_exits:     resd 1                     ; decoded reason-12 exits (live counter)
hv_exit_reason:   resd 1                     ; last decoded basic exit reason
hv_linux_exits:   resd 1                     ; exits handled during last Linux START
hv_linux_match:   resd 1                     ; active init-entry prefix length
hv_linux_kernel_size: resd 1
hv_linux_initrd_size: resd 1
hv_instr_err:     resd 1                     ; VM-instruction error on a failed entry
hv_vmwrite_fails: resd 1
hv_tick_inj_ct:   resd 1                     ; exact successful IRQ0 VMCS writes
hv_panic_match:   resd 1
hv_vcon_rx_used:  resd 1                     ; real queue-0 used advances
hv_vcon_tx_used:  resd 1                     ; real queue-1 used advances
hv_vcon_capture_len: resd 1
hv_vcon_capture_overflow: resd 1              ; dropped prefix bytes in diagnostic tail mode
hv_vcon_run_tail_len: resd 1                 ; recent RUN bytes, at most 511
hv_vcon_run_tail_write: resd 1               ; next ring slot, masked to 0..511
hv_vcon_run_tail_gen: resd 1                 ; accepted START owning recent bytes
hv_vcon_qsel:     resd 1
hv_vcon_dfsel:    resd 1
hv_vcon_drvfsel:  resd 1
hv_vcon_drvfeat:  resd 2
hv_guest_identity_epoch: resq 1
hv_guest_identity_gen: resd 1
hv_guest_identity_pos: resd 1
hv_guest_identity_state: resb 1
hv_guest_identity_cr: resb 1
hv_guest_identity_candidate: resb 149
hv_guest_identity_receipt: resb 149
hv_vcon_epoch:    resq 1
hv_vcon_feat_bad: resd 1
hv_vcon_status:   resd 1
hv_vcon_isr:      resd 1
hv_vcon_q_num:    resd 2
hv_vcon_wr_ct:    resd 1
hv_vcon_badop:    resd 1
hv_vcon_ilen:     resd 1
hv_vcon_iwidth:   resd 1                       ; RCQ-23: decoded store width (1|4)
hv_pit_reload:    resw 3
hv_pit_latch:     resw 3
hv_vcon_q_lastav: resw 2
hv_vcon_q_usedidx: resw 2
                  alignb 8
hv_vcon_q_desc:   resq 2
hv_vcon_q_avail:  resq 2
hv_vcon_q_used:   resq 2
hv_dtr_buf:       resb 16                    ; sgdt/sidt scratch (2-byte limit + 8-byte base)
hv_linux_gpr:     resq 15                     ; RAX,RBX,RCX,RDX,RSI,RDI,RBP,R8..R15
hv_linux_uart:    resb 8
hv_linux_stat:    resb 16                     ; fs_stat: qword size + flags + reserved
hv_vcon_ibuf:     resb 16                     ; trapped-store decode window
hv_vcon_rxbuf:    resb 256
hv_vcon_txbuf:    resb HV_VCON_TX_MAX
hv_vcon_capture:  resb HV_VCON_CAP_MAX
hv_vcon_run_tail: resb HV_VCON_CAP_MAX        ; RUN view; legacy capture above retained
hv_dec_buf:       resb 24                    ; decimal render scratch
hv_out_buf:       resb HV_OUT_BYTES           ; status plus captured operation window
hv_out_clipped:   resq 1                      ; bytes hv_out_putc dropped since hv_out_reset (0 = whole)
%endmacro
WDATA_BSS_DEFER WDATA_hv_vmx_0_bss2
; RCQ-18 S2-0: the M3 heartbeat counters, in their own block so the split blocks
; above keep the layout they were cut with.
%macro WDATA_BSS_hv_vmx_m3 0
alignb 4
alignb 8
hv_vmx_boundary_frame: resq 1             ; zero outside actual resident VMX
hv_linux_intr_exits: resd 1                  ; reason-1 exits during the last START
hv_linux_host_slices: resd 1                 ; host slices that yielded, same START
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_m3

; T2-4 D8 (VM 107717): passive host-slice timing for the last START, in its own
; block so every pinned block keeps its layout. Zeroed with host_slices.
%macro WDATA_BSS_hv_vmx_slicediag 0
alignb 8
hv_linux_slice_begin_tsc: resq 1             ; TSC at the current yield's start
hv_linux_slice_end_tsc: resq 1               ; TSC at the last yield's end; 0 = none yet
hv_linux_slice_yield_tsc: resq 1             ; sum of TSC spent inside sched_yield
hv_linux_slice_max_gap_tsc: resq 1           ; max TSC from one yield's end to the next start
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_slicediag

; HV-XCR0 (RCQ-24): guest/exit XCR0 and XSETBV refusal state, outside the pinned split blocks.
%macro WDATA_BSS_hv_vmx_xcr0 0
alignb 8
hv_linux_guest_xcr0: resq 1                  ; the guest's checked XCR0
hv_linux_exit_xcr0: resq 1                   ; host|guest, live while host code runs
hv_xsetbv_refused: resd 1                    ; guest XSETBVs answered with #GP(0)
hv_cr4_refused: resd 1                       ; V5: guest CR4 PKE/KL writes answered with #GP(0)
hv_linux_xcr0_swap: resb 1                   ; exit value != guest value
hv_xsetbv_last_refusal: resb 1               ; hv_linux_xcr0_check reason of the last #GP
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_xcr0

; RC-speed-reserve: the live START's core/memory_budget key, in its own block so
; the split blocks above keep the layout they were cut with.
%macro WDATA_BSS_hv_vmx_mb 0
alignb 8
hv_linux_mb_token: resq 1                    ; 0 = no span held
hv_linux_mb_gen:   resq 1                    ; the START generation that acquired it
hv_linux_mb_release_refused: resd 1          ; releases refused by the owner table
hv_linux_mb_release_pinned: resd 1           ; stops that kept a DMA-pinned span
hv_linux_mb_acquire_refused: resd 1          ; acquisitions the owner table refused
hv_linux_release_deferred: resb 1            ; a fixture launcher releases after its result read
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_mb

; RCQ-36: guest UART THRE interrupt state. Zero means asserted and not yet
; injected, so a reset or a snapshot resume can only add one harmless THRE IRQ.
%macro WDATA_BSS_hv_vmx_uart_thre 0
alignb 2
hv_uart_thre:     resb 2                     ; +0: an IIR read reported this THRE; +1: IRQ4 injected for it
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_uart_thre

%macro WDATA_BSS_hv_vmx_exit_evidence 0
alignb 8
hv_linux_exit_evidence:
hv_linux_exit_total: resq 1
hv_linux_exit_pio: resq 1
hv_linux_exit_timer: resq 1
hv_linux_exit_intr: resq 1
hv_linux_exit_other: resq 1
hv_linux_exit_sync: resq 1
hv_linux_exit_sample_n: resq 1
hv_linux_exit_sample_reason: resq 1
hv_linux_exit_sample_rip: resq 1
hv_linux_exit_sample_qual: resq 1
hv_linux_exit_sample_ilen: resq 1
hv_linux_exit_sample_rax: resq 1
hv_linux_exit_sample_rdx: resq 1
hv_linux_exit_evidence_end:
hv_linux_exit_gen: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_exit_evidence

; Separate block keeps the established synchronous evidence layout intact.
%macro WDATA_BSS_hv_vmx_async_evidence 0
alignb 8
hv_linux_async_evidence:
hv_linux_async_count: resq 1
hv_linux_async_n: resq 1
hv_linux_async_reason: resq 1
hv_linux_async_rip: resq 1
hv_linux_async_flags: resq 1
hv_linux_async_block: resq 1
hv_linux_async_entry: resq 1
hv_linux_async_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_async_evidence
; Own block: the existing VMX/PMR receipt and cache-line offsets stay fixed.
%macro WDATA_BSS_hv_guest_files 0
alignb 8
hv_guest_files_kernel: resq 1
hv_guest_files_initrd: resq 1
hv_guest_files_handle: resd 1
hv_guest_files_klen: resd 1
hv_guest_files_ilen: resd 1
hv_guest_files_nested: resb 1
alignb 8
hv_guest_files_stat: resb 16
hv_guest_files_kpath: resb 96
hv_guest_files_ipath: resb 96
hv_guest_files_spath: resb 96
hv_guest_files_hint: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_guest_files
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
%macro WDATA_BSS_hv_vmx_pmr 0
alignb 8
hv_vcon_pmr_ctx: resq 1
hv_vcon_pmr_saved_ram: resq 1
hv_vcon_pmr_saved_avail: resq 1
hv_vcon_pmr_saved_used: resq 1
hv_vcon_pmr_saved_desc: resq 1
hv_vcon_pmr_total: resd 1
hv_vcon_pmr_pos: resd 1
hv_vcon_pmr_head: resd 1
hv_vcon_pmr_saved_gen: resd 1
hv_vcon_pmr_saved_num: resd 1
hv_vcon_pmr_saved_lastav: resw 1
hv_vcon_pmr_saved_usedidx: resw 1
hv_vcon_pmr_retained: resb 1
hv_vcon_pmr_retrying: resb 1
hv_vcon_pmr_fault: resb 1
hv_vcon_pmr_bound: resb 1
hv_vcon_pmr_pending: resb 1
hv_vcon_pmr_discard: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_pmr
; RC-speed-reserve: its own block, so the PMR block above keeps its layout.
%macro WDATA_BSS_hv_vmx_media_span 0
hv_media_window_held: resb 1                ; select .. the owner's window scrub
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vmx_media_span
%endif
%endif

%include "hv/boundary.asm"
%include "hv/boundary_owner.asm"   ; T1-5 S7 P4: AP-reachable, outside bsp_only vmx.asm
%include "hv/boundary_observation.asm"
%include "hv/boundary_execution.asm"
%include "hv/capability_observation.asm"
%include "hv/context_execution.asm" ; read-only actual context observations
%include "hv/interpreter_execution.asm" ; actual native content-feed hardening

%include "hv/warm_lifecycle.asm"

%include "hv/warm_channel.asm"

%include "hv/input_owner.asm"

fsg_memory_retained:
    ret
