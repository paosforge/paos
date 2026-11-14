;; MODULE boot/header
%include "core/abi/build_profile.inc"
;; LAYER 0
;; EXPORTS boot_guest_foundation_init, efi_entry, boot_services, runtime_services, image_handle, system_table, boot_ms_now, boot_idle_compositor_ticks, boot_bg4_ebs_tsc, boot_bg5_ready_tsc, boot_bg5b_ack_tsc, boot_bg6_pixel_tsc, boot_p7_tsc, boot_prepixel_tsc, boot_device_cuts_tsc, boot_p1_ckpt_tsc, boot_native_cost_tsc, boot_native_cost_done, boot_nic_ready_tsc, boot_nic_ready_observed, boot_hv_foundation_ready_tsc, boot_hv_foundation_ready_ms, boot_hv_foundation_ready, boot_budget_run_full, boot_budget_gated, boot_budget_class, boot_budget_full_failures, boot_settle_tsc, boot_settle_state
;; IMPORTS gui/format_confirm, gui/adopt_confirm, sec/node_identity_store, gui/app_isolation, hv/app_vm, gui/app_remove, gui/app_install, gui/app_ingress, gui/app_launch_flow, hv/app_transport, gui/app_launcher, boot/native_driver_preload, boot/native_driver_report, svc/boot_failure_control, core/crash_identity, core/maintenance_sources, core/boot_maintenance_source, svc/command_memory_consumer, svc/service_progress, svc/recovery_boot, svc/recovery_controller, svc/device_failure_record, hv/warm_lifecycle, svc/lab_return, gui/power_exec, gui/lock_fade, core/mca_poll, core/mca_init, cognition/ai_intent_controller, hv/vmx, hv/hv_ops, sec/airlock, svc/boot_clock, boot/boot_menu, boot/serial, boot/paging, boot/pmod_loader, boot/gdt, boot/gop, boot/boot_v2_health, boot/menu_labels_qemu, bus/acpi, config/keep_config, core/idt, core/diag, core/lib/str, core/lib/fmt, core/lib/strmem_kat, core/log, core/heap, core/memmap, core/time, core/sched, core/dma, net/tls13, gui/console, gui/liveness_panel, sec/job_receipt, svc/hotpatch, svc/command_filmstrip, svc/command_compat, dev/net/e1000e, dev/net/cdc_ecm, dev/net/cdc_ncm, dev/net/ax88179, net/netdev, hv/vtd, hv/amdvi, gui/lock_screen, sec/session, core/reset_wipe, sec/owner_stage_key, sec/app_store_seal, dev/snd/hda_boot_handoff, boot/firmware_logo, boot/indicator, core/deadman_identity, svc/normal_deadman_live, gui/config_prefs, gui/command_idle_service, gui/terminal_consent, gui/account_local
;; (boot/header is the boot orchestrator — the upward L0->L1 call to core/idt is
;;  the documented modlint exception, like the L3->L4 register() edge)
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/header.asm — hand-crafted PE32+ header + the UEFI entry point.
;
; Ported from the old tree's PROVEN header (boots on real hardware + OVMF) —
; MIGRATION.md §1 "port, don't re-derive". This is the FIRST module in the link
; map: mz_header MUST be at file offset 0. (.inc headers emit no bytes, so the
; ABI header included before this does not shift it.)
;
; M1 FIRST-LIGHT scope: valid PE32+ image + UEFI entry + serial marker + halt.
; Still TODO for M1 (next, loop-friendly once the gate exists): GOP init,
; ExitBootServices, boot/paging.asm (long mode + W^X), the phase ladder.
; ============================================================================

; --- 1051 P7/P8 split constants (BOOT_SEQUENCE note 2 per-driver budget). equ emits
;     no bytes, so mz_header stays at file offset 0. ---
NIC_ST_WARMING   equ 0
NIC_ST_READY     equ 1
NIC_ST_PARKED    equ 2
P8_NIC_BUDGET_MS equ 30000            ; a NIC that never links within 30s is PARKED (desktop stays live)
P8_NIC_RECHECK_MS equ 1000            ; parked recovery: at most one live check per second
BOOT_CLASS_CONFIRMED equ 0
BOOT_CLASS_TRIAL     equ 1
BOOT_BUDGET_TRIAL_ONLY   equ 0
BOOT_BUDGET_CLASS_ALWAYS equ 1
; The R6 host-stable update rail has no journal Trial state.  Its successful
; in-band BOOT LINUX transition arms this otherwise-invalid legacy value for
; exactly the next Manager-launched PaOS boot.  The ordinary A/B code
; sanitizes it to zero, so an intentional first boot is not reported as a
; recovered crash; boot_budget_p0_snapshot has already retained the class.
BOOT_BUDGET_TRIAL_ARM equ 6

; Stable ids and the default/ALWAYS policy both come from the single shared
; X-macro table in src/paos.asm. Reclassification therefore edits only that
; data macro, never this gate or the boot callsites.
%assign BOOT_BUDGET_NEXT_ID 0
%assign BOOT_BUDGET_TRIAL_COUNT 0
%macro BOOT_BUDGET_ROW 2
    %1 equ BOOT_BUDGET_NEXT_ID
    %assign BOOT_BUDGET_NEXT_ID BOOT_BUDGET_NEXT_ID + 1
    %assign BOOT_BUDGET_TRIAL_COUNT BOOT_BUDGET_TRIAL_COUNT + 1
%endmacro
%macro BOOT_BUDGET_ALWAYS 2
    %1 equ BOOT_BUDGET_NEXT_ID
    %assign BOOT_BUDGET_NEXT_ID BOOT_BUDGET_NEXT_ID + 1
%endmacro
BOOT_BUDGET_ROWS
%unmacro BOOT_BUDGET_ROW 2
%unmacro BOOT_BUDGET_ALWAYS 2
BOOT_BUDGET_COUNT equ BOOT_BUDGET_NEXT_ID

; Every boot-path selftest uses this one dispatcher seam.  The table owns all
; policy; callsites supply only the stable row id.
%macro BOOT_SELFTEST 1
    mov  r10d, %1
    call boot_budget_gate
%endmacro
%macro BOOT_PHASE_SELFTEST 2
    mov  edi, %1
    call diag_phase_enter
    BOOT_SELFTEST %2
    mov  edi, %1
    call diag_phase_exit
%endmacro

; Stable ids for earned phase markers outside core/log's verdict catalog.
BOOT_TIMELINE_SPECIAL_BASE equ 0x8000
BOOT_TIMELINE_ID_AB_VERIFY equ BOOT_TIMELINE_SPECIAL_BASE + 0
BOOT_TIMELINE_ID_AB_LOADED equ BOOT_TIMELINE_SPECIAL_BASE + 1
BOOT_TIMELINE_ID_WDOG_ARM  equ BOOT_TIMELINE_SPECIAL_BASE + 2
BOOT_TIMELINE_ID_WDOG_NONE equ BOOT_TIMELINE_SPECIAL_BASE + 3
BOOT_TIMELINE_ID_AB_COMMIT equ BOOT_TIMELINE_SPECIAL_BASE + 4
BOOT_TIMELINE_ID_P7        equ BOOT_TIMELINE_SPECIAL_BASE + 5
BOOT_TIMELINE_ID_P8_WARM   equ BOOT_TIMELINE_SPECIAL_BASE + 6
BOOT_TIMELINE_ID_P8_READY  equ BOOT_TIMELINE_SPECIAL_BASE + 7
BOOT_TIMELINE_ID_HV_READY  equ BOOT_TIMELINE_SPECIAL_BASE + 8
BOOT_TIMELINE_ID_LOG_MODE_LEAN equ BOOT_TIMELINE_SPECIAL_BASE + 9
BOOT_TIMELINE_ID_LOG_MODE_VERBOSE equ BOOT_TIMELINE_SPECIAL_BASE + 10
BOOT_TIMELINE_ID_INPUT_KBD_LIVE equ BOOT_TIMELINE_SPECIAL_BASE + 11
BOOT_TIMELINE_ID_INPUT_PTR_LIVE equ BOOT_TIMELINE_SPECIAL_BASE + 12
BOOT_TIMELINE_ID_SSH_READY equ BOOT_TIMELINE_SPECIAL_BASE + 13
BOOT_TIMELINE_ID_TERMINAL_USABLE equ BOOT_TIMELINE_SPECIAL_BASE + 14
BOOT_TIMELINE_ID_DHCP_BOUND equ BOOT_TIMELINE_SPECIAL_BASE + 15
BOOT_TIMELINE_ID_DHCP_DISCOVER equ BOOT_TIMELINE_SPECIAL_BASE + 16
BOOT_TIMELINE_ID_DHCP_OFFER equ BOOT_TIMELINE_SPECIAL_BASE + 17

; Generated build intent may override this for a descriptor with no native NIC.
; Keep policy separate from whether hardware happens to enumerate this boot.
; Spec rev 0.70: only lab builds, where the network is the test channel, require it.
%ifndef PAOS_NET_REQUIRED
%if PAOS_PUBLIC_BUILD != 0
%define PAOS_NET_REQUIRED 0
%else
%define PAOS_NET_REQUIRED 1
%endif
%endif
%if PAOS_NET_REQUIRED != 0 && PAOS_NET_REQUIRED != 1
%error "PAOS_NET_REQUIRED must be the descriptor value 0 or 1"
%endif
%if PAOS_PUBLIC_BUILD != 0 && PAOS_NET_REQUIRED != 0
%error "public build must not require the network"
%endif

; Session-shell policy is compile-time explicit and default-off. Autologin is
; a lab/dev convenience only; a shipped-posture request is a build refusal.
%ifndef PAOS_SESSION_DEV_AUTOLOGIN
%define PAOS_SESSION_DEV_AUTOLOGIN 0
%endif
%if PAOS_SESSION_DEV_AUTOLOGIN != 0 && PAOS_SESSION_DEV_AUTOLOGIN != 1
%error "PAOS_SESSION_DEV_AUTOLOGIN must be 0 or 1"
%endif
%if PAOS_SESSION_DEV_AUTOLOGIN && !PAOS_PUBLICITY_LAB_PROFILE
%error "PAOS_SESSION_DEV_AUTOLOGIN requires PAOS_PUBLIC_FLOOR=lab"
%endif

; B1_LAB_FAILURE_CONFIG_BEGIN
; An explicit diagnostic payload only. No fault-control bytes in default images.
%ifndef PAOS_LAB_B1_STARTING_FAILURE
%define PAOS_LAB_B1_STARTING_FAILURE 0
%endif
%if PAOS_LAB_B1_STARTING_FAILURE != 0 && PAOS_LAB_B1_STARTING_FAILURE != 1
%error "PAOS_LAB_B1_STARTING_FAILURE must be 0 or 1"
%endif
%ifndef PAOS_LAB_B1_STARTING_STAGE
%define PAOS_LAB_B1_STARTING_STAGE 0
%endif
%if PAOS_LAB_B1_STARTING_STAGE != 0 && PAOS_LAB_B1_STARTING_STAGE != 2
%error "B1 startup failure stage must be P0 or P2"
%endif
%if PAOS_LAB_B1_STARTING_STAGE != 0 && !PAOS_LAB_B1_STARTING_FAILURE
%error "B1 stage selection requires the explicit failure control"
%endif
%if PAOS_LAB_B1_STARTING_FAILURE
%if PAOS_PUBLICITY_LAB_PROFILE != 1 || PAOS_SCAP_LAB_PROFILE != 1
%error "B1 startup failure control requires both explicit LAB profiles"
%endif
%ifdef PAOS_EARLY_TRAP_INJECT
%error "B1 startup failure control cannot share the unconditional trap fixture"
%endif
%endif
; B1_LAB_FAILURE_CONFIG_END

; D4_NORMAL_DEADMAN_CONFIG_BEGIN
; Default OFF: there is no universal legitimate command-duration bound.
%ifndef PAOS_NORMAL_DEADMAN_MS
%define PAOS_NORMAL_DEADMAN_MS 0
%endif
%if PAOS_NORMAL_DEADMAN_MS < 0 || PAOS_NORMAL_DEADMAN_MS > 600000
%error "PAOS_NORMAL_DEADMAN_MS must be 0..600000"
%endif
%ifndef PAOS_LAB_D4_IFON_STALL
%define PAOS_LAB_D4_IFON_STALL 0
%endif
%if PAOS_LAB_D4_IFON_STALL != 0 && PAOS_LAB_D4_IFON_STALL != 1
%error "PAOS_LAB_D4_IFON_STALL must be 0 or 1"
%endif
%if PAOS_LAB_D4_IFON_STALL
%if PAOS_NORMAL_DEADMAN_MS == 0
%error "D4 IF-on stall requires an explicit nonzero Normal heartbeat budget"
%endif
%if PAOS_PUBLICITY_LAB_PROFILE != 1 || PAOS_SCAP_LAB_PROFILE != 1
%error "D4 IF-on stall requires both explicit LAB profiles"
%endif
%endif
; D4_NORMAL_DEADMAN_CONFIG_END

; D8_HID_REJECT_CONFIG_BEGIN
; Controlled consumed class rejection is absent from ordinary payloads.
%ifndef PAOS_LAB_D8_HID_REJECT
%define PAOS_LAB_D8_HID_REJECT 0
%endif
%if PAOS_LAB_D8_HID_REJECT != 0 && PAOS_LAB_D8_HID_REJECT != 1
%error "PAOS_LAB_D8_HID_REJECT must be 0 or 1"
%endif
%if PAOS_LAB_D8_HID_REJECT
%if PAOS_PUBLICITY_LAB_PROFILE != 1 || PAOS_SCAP_LAB_PROFILE != 1
%error "D8 HID rejection requires both explicit LAB profiles"
%endif
%endif
; D8_HID_REJECT_CONFIG_END

; GE C3: one readable call shape for the existing P0-P8 durable graph.  The
; helper is a no-op outside a Manager-owned mutable Normal attempt and latches
; its first fatal persistence/budget error so strong health fails closed.
%macro C3WD_EDGE 2
    mov  edi, %1
    mov  esi, %2
    xor  edx, edx
    call software_stop_checkpoint
    mov  edi, %1
    mov  esi, %2
    call boot_v2_face_checkpoint_observe ; actual milestone; source rc preserved
%endmacro

; RCQ32_PREPIXEL_BEGIN
; Five BSP-only raw cuts within the otherwise coarse P5 interval. The existing
; PHASES/WAITLEDGER gives P0-P8, and P7/pixel already have raw stamps. Preserve
; all registers/flags; no allocation, serial I/O, waiting, or policy change.
; Elapsed intervals include IRQ/preemption. Zero remains not reached.
%macro BOOT_PREPIXEL_STAMP 1
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_prepixel_tsc + %1*8], rax
    pop rdx
    pop rax
    popfq
%endmacro
; RCQ32_PREPIXEL_END

; RCQ-32: split the compound USB and NIC-prepare intervals without changing
; their work. These are BSP control-return cuts, including gated/absent paths,
; not hardware-success milestones. Same TSC domain as PREPIXEL; zero unreached.
%macro BOOT_DEVICE_STAMP 1
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_device_cuts_tsc + %1*8], rax
    pop rdx
    pop rax
    popfq
%endmacro

; RCQ-32 (root 2026-10-17 01:16): one raw cut after the P1 STARTING checkpoint
; edge returns. boot_phase_tsc[P1 start] is stamped before that edge's NV
; persistence, so done-start is the persistence edge and EBS-done is memory
; setup. Same contract as BOOT_PREPIXEL_STAMP: registers/flags preserved, no
; allocation, serial I/O, waiting or policy change. Zero remains not reached.
%macro BOOT_P1CKPT_STAMP 0
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_p1_ckpt_tsc], rax
    pop rdx
    pop rax
    popfq
%endmacro

; RCQ32_NATIVE_COST_BEGIN
; Observation-only BSP call brackets. Fixed slots; preserve every register and
; flags, including the measured call's return. Elapsed includes IRQ/preemption,
; not CPU-exclusive cost. No waits, allocations, logging, or policy changes.
%macro BOOT_NATIVE_COST_BEGIN 1
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_native_cost_tsc + %1*16], rax
    pop rdx
    pop rax
    popfq
%endmacro
%macro BOOT_NATIVE_COST_END 1
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_native_cost_tsc + %1*16 + 8], rax
    mov qword [rel boot_native_cost_done + %1*8], 1
    pop rdx
    pop rax
    popfq
%endmacro
; RCQ32_NATIVE_COST_END

; --- MZ DOS Stub (64 bytes) ---
mz_header:
    dw 0x5A4D                       ; "MZ"
    times 29 dw 0
    dd pe_header                    ; e_lfanew

; --- PE Signature ---
pe_header:
    dd 0x00004550                   ; "PE\0\0"

; --- COFF Header ---
coff_header:
    dw 0x8664                       ; Machine: AMD64
    dw 1                            ; NumberOfSections
    dd 0                            ; TimeDateStamp
    dd 0                            ; PointerToSymbolTable
    dd 0                            ; NumberOfSymbols
    dw optional_header_size         ; SizeOfOptionalHeader
    dw 0x0022                       ; EXECUTABLE | LARGE_ADDRESS_AWARE

; --- Optional Header (PE32+) ---
optional_header:
    dw 0x020B                       ; PE32+ magic
    db 1
    db 0
    dd code_size                    ; SizeOfCode
    dd 0
    dd 0
    dd 0x1000                       ; AddressOfEntryPoint (RVA)
    dd 0x1000                       ; BaseOfCode (RVA)
    dq 0x100000                     ; ImageBase
    dd 0x1000                       ; SectionAlignment
    dd 0x200                        ; FileAlignment
    dw 0
    dw 0
    dw 0
    dw 0
    dw 0
    dw 0
    dd 0
    dd image_size                   ; SizeOfImage
    dd 0x200                        ; SizeOfHeaders
    dd 0
    dw 10                           ; Subsystem: EFI Application
    dw 0
    dq 0
    dq 0
    dq 0
    dq 0
    dd 0
    dd 16                           ; NumberOfRvaAndSizes
    times 16 dq 0                   ; Data Directories (all zero)
optional_header_size equ $ - optional_header

; --- Section Header (.text) ---
section_header:
    db ".text", 0, 0, 0
    dd code_size                    ; VirtualSize
    dd 0x1000                       ; VirtualAddress
    dd code_file_size               ; SizeOfRawData
    dd 0x200                        ; PointerToRawData
    dd 0
    dd 0
    dw 0
    dw 0
    dd 0x60000020                   ; CODE | EXECUTE | READ

; --- Pad to FileAlignment ---
times 0x200 - ($ - $$) db 0

; ============================================================================
%include "boot/native_handoff_trace.inc"
%include "boot/health_progress.inc"
%include "boot/parked_watch_diag.inc"

; .text begins at file offset 0x200 / RVA 0x1000. efi_entry MUST be first
; (AddressOfEntryPoint = 0x1000).
; ============================================================================
code_start:

; UEFI entry — MS x64 ABI: RCX = ImageHandle, RDX = SystemTable
efi_entry:
    ; --- 1272 FIX (data-backed 2026-08-06): normalize the loader stack to
    ;     the ABI-standard callee residue mod 16 == 8. MEASURED efi_entry
    ;     RSP: direct load 0x..AC8 (mod 16 = 8, WORKS); Manager StartImage
    ;     0x..FD0 (mod 16 = 0, CRASHES). PaOS's downstream stack math is
    ;     written for the mod-16==8 entry, so force any loader's handoff to
    ;     match it. The earlier fix forced mod-16==0 (the wrong direction)
    ;     and reproduced the be8e721 direct-boot #GP.
    and  rsp, -16                       ; -> mod 16 == 0
    sub  rsp, 8                          ; -> mod 16 == 8 (the working residue)
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; SEC-pbh1-acceptance-identity: measure the loaded bytes BEFORE the first
    ; store into the image (core/build_id.asm). RCX/RDX ride in the callee-saved
    ; RBX/RBP (already saved above), so the stack and its residue are unchanged.
    mov  rbx, rcx
    mov  rbp, rdx
    ; Capture EFI-entry time without an image store: the hash below must see
    ; pristine D. R12 is saved above and preserved by build_id_measure/SHA-256.
    ; This includes identity measurement and watchdog setup in all boot gates.
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    call build_id_measure
    mov  [rel boot_tsc_start], r12
    mov  rcx, rbx
    mov  rdx, rbp

    mov [rel image_handle], rcx
    mov [rel system_table], rdx

    ; Extract BootServices pointer (SystemTable + 96) — needed by boot/paging.asm
    ; for AllocatePool/GetMemoryMap/ExitBootServices.
    mov rax, [rdx + 96]
    mov [rel boot_services], rax
    mov rax, [rdx + 88]
    mov [rel runtime_services], rax

    ; Diagnostic-only earliest firmware-table-ready entry, after pristine D hash.
    PAOS_NATIVE_TRACE 1

    ; Pre-ExitBootServices recovery (MSI spoke handoff 6a, admin 2026-10-01 12:25):
    ; arm the UEFI watchdog ourselves instead of relying on the boot manager's
    ; default. A wedge before ExitBootServices is then reset by the firmware
    ; within PREEBS_WDT_S. It stays armed through ExitBootServices, which disables
    ; it on success (UEFI); a failure resets at once (exit_boot_and_page_fail).
%ifndef PAOS_LAB_WDT_NOT_ARMED
    call preebs_wdt_arm
    PAOS_NATIVE_PROGRESS 2       ; watchdog call returned, not success/health
%endif

    ; --- serial up + first-light marker (the M1 gate seed) ---
    call boot_timeline_init
%ifdef PAOS_LAB_PREEBS_HANG
    ; QEMU-lab only, never a shipped build: a deliberate pre-EBS wedge, so the
    ; watchdog arm above can be shown to reset it (and its absence not to).
    lea  rdi, [rel str_lab_preebs_hang]
    call serial_string
.lab_preebs_hang:
    pause
    jmp  .lab_preebs_hang
%endif
    ; Capture the retained trial byte at P0, before firmware/display/storage
    ; work can hang or a later recovery path can alter CMOS. Selection waits
    ; for diag_init's prior-ring snapshot, but this value remains the true
    ; pre-work, pre-increment boot outcome.
    call boot_budget_p0_snapshot
    call boot_ab_prior_snapshot
    ; A one-boot LOGMODE override is decoded at the same P0 boundary even if
    ; this launch later selects the Manager safe profile, and cleared right
    ; after the handoff probe (boot_log_override_clear).  Normal P2 selection
    ; uses the immutable decoded byte below; no override can leak to boot N+2.
    call boot_log_override_consume
    mov  [rel boot_log_override_policy], cl
    call serial_init
    lea  rdi, [rel str_firstlight]
    call serial_string

    ; 2301: clear/arm before the first selftest verdict.  First-light above is
    ; deliberately outside the verdict catalog and also proves UART first.
    call selftest_verdict_init

    ; --- 1273a EARLY TRAP (must be the FIRST thing after serial, and BEFORE
    ;     every call below — that is the entire point). Hooks the FIRMWARE's
    ;     IDT fault gates so a pre-EBS #GP/#PF/#UD/#DF is delivered to PaOS
    ;     (record -> count -> demote -> CF9 warm reset) instead of to EDK2's
    ;     DefaultExceptionHandler, which ends in CpuDeadLoop() and leaves the
    ;     box dark forever. That dark box is the 2026-08-06 incident: the fault
    ;     hit gop_query below, and every PaOS recovery mechanism (idt_init,
    ;     boot_ab_early, fault_warmreset_arm) arms AFTER it. Ordering was the
    ;     whole bug. See BOOT_SEQUENCE.md "Early-arm doctrine". ---
    call early_trap_install
    call build_id_report                ; SEC-pbh1: the measured build id, once serial and the early trap are up
    ; Read the exact firmware boot volume while Boot Services are live, before
    ; the first device probe/activation. An invalid selected file stays refused;
    ; the compatibility caller must observe policy=1, never infer it from boot.
    call native_driver_preload
    call native_driver_report_selection

    ; Register exact runtime message pointers. Pointer identity, not dotted
    ; text parsing, decides which earned phase markers enter the timeline.
    lea  rdi, [rel str_ab_v_post]
    mov  esi, BOOT_TIMELINE_ID_AB_VERIFY
    call boot_timeline_special_register
    lea  rdi, [rel str_ab_s_post]
    mov  esi, BOOT_TIMELINE_ID_AB_LOADED
    call boot_timeline_special_register
    lea  rdi, [rel str_ab_w_ok_post]
    mov  esi, BOOT_TIMELINE_ID_WDOG_ARM
    call boot_timeline_special_register
    lea  rdi, [rel str_ab_w_absent_locked]
    mov  esi, BOOT_TIMELINE_ID_WDOG_NONE
    call boot_timeline_special_register
    lea  rdi, [rel str_ab_w_absent_gated]
    mov  esi, BOOT_TIMELINE_ID_WDOG_NONE
    call boot_timeline_special_register
    lea  rdi, [rel str_ab_w_absent_backend]
    mov  esi, BOOT_TIMELINE_ID_WDOG_NONE
    call boot_timeline_special_register
    lea  rdi, [rel str_ab_c_ctr]
    mov  esi, BOOT_TIMELINE_ID_AB_COMMIT
    call boot_timeline_special_register
    lea  rdi, [rel str_p7_interactive]
    mov  esi, BOOT_TIMELINE_ID_P7
    call boot_timeline_special_register
    lea  rdi, [rel str_p8_warming]
    mov  esi, BOOT_TIMELINE_ID_P8_WARM
    call boot_timeline_special_register
    lea  rdi, [rel str_p8_ready_hv]
    mov  esi, BOOT_TIMELINE_ID_HV_READY
    call boot_timeline_special_register
    lea  rdi, [rel str_p8_ready_hv]
    mov  esi, BOOT_TIMELINE_ID_P8_READY
    call boot_timeline_special_register
    lea  rdi, [rel str_p8_ready_nic]
    mov  esi, BOOT_TIMELINE_ID_P8_READY
    call boot_timeline_special_register
    lea  rdi, [rel str_p8_park_nic]
    mov  esi, BOOT_TIMELINE_ID_P8_READY
    call boot_timeline_special_register
    ; --- Boot Manager v2 additive handoff probe. A direct firmware launch has
    ;     no valid PBH1 LoadOptions and therefore follows the bit-for-bit legacy
    ;     selector calls below. A genuine Manager launch carries a versioned,
    ;     CRC-protected handoff; only then does PaOS bypass its embedded
    ;     selection layer. Payload-owned health/watchdog work remains below.
    ;     OVERRIDE_PROTECT: boot_menu_run — the protected function is not edited;
    ;     this migration follows "bypass first, prove, remove last". ---
    call boot_v2_handoff_probe
    ; RCQ-29: the LOGMODE clear waits for the probe; a live Try boot keeps CMOS.
    call boot_log_override_clear
    ; Classify only after the CRC-bound Manager handoff is available.  Direct
    ; boots still use the immutable P0 CMOS 0x74 sample exactly; a Manager
    ; TRIAL flag or non-HEALTHY reason is the current-attempt witness for the
    ; first inactive-slot boot, before the legacy counter can become positive.
    call boot_budget_init
    BOOT_SELFTEST ST_TIMELINE_OVERFLOW
    cmp  byte [rel pbm_manager_launch], 1
    je   .manager_selection_complete

    ; --- 9702 boot-canon ESCALATION (must be PRE-EBS: LoadImage/StartImage are
    ;     boot services): an UNCONFIRMED keep whose CMOS trial counter (0x74,
    ;     svc/boot_ab 1014) exhausted its trials chainloads bootmgfw_orig.efi
    ;     (Windows) instead of fault-reboot-looping forever. Confirmed keep or
    ;     trials under the cap -> prints the live decision + continues. ---
    call chainload_escalate_check

    ; --- 1015 boot-canon 3-OS MENU (PRE-EBS: chainload + ConIn/ConOut/Stall are
    ;     boot services): honor a one-shot CMOS BOOT-verb override, render the
    ;     PaOS/Windows/Linux/Diagnostics menu (firmware console + serial), poll
    ;     keys through a 2s countdown, default -> PaOS. Runs AFTER the 9702
    ;     escalate-check so the crash-ladder decision precedes the user's.
    ;     Emits the 4 boot-menu markers (qemu-only: pre-EBS serial). ---
    call boot_menu_run
    jmp  .selection_complete

.manager_selection_complete:
    lea  rdi, [rel str_pbm_selection_bypass]
    call serial_string
.selection_complete:
    C3WD_EDGE PBM_INIT_STAGE_P0, PBM_INIT_TRANSITION_STARTING
%if PAOS_LAB_B1_STARTING_FAILURE && PAOS_LAB_B1_STARTING_STAGE == 0
    ; Only after the real P0 transition's durable readback. Safe/recovery bypass.
    call boot_b1_failure_control
%endif

%ifdef PAOS_EARLY_TRAP_INJECT
    ; --- 1273a NEGATIVE-TEST FIXTURE (build-time gated, never in a release).
    ;     Reproduces the 2026-08-06 incident shape EXACTLY: a #GP raised in the
    ;     pre-EBS window, at the same point in the sequence (immediately before
    ;     gop_query). Without boot/early_trap this hangs the box forever on the
    ;     firmware's IDT; with it, the fault must be caught, counted, demoted
    ;     and warm-reset. Enable with: make build NASM_EXTRA=-DPAOS_EARLY_TRAP_INJECT
    ;     A far-return to a garbage selector is the cleanest deterministic #GP
    ;     that needs no memory mapping assumptions. ---
    call early_trap_verify
    lea  rdi, [rel str_et_inject]
    call serial_string
    ; ud2 is the unambiguous fault-injection instruction: architecturally
    ; guaranteed #UD(6), no operand/state ambiguity. (An earlier fixture wrote
    ; garbage to CR4 -- that is NOT a reliable fault: parts of the value are
    ; legal and the CPU can end up wedged instead of trapping, which is exactly
    ; what it did. Fixture correctness matters as much as the code under test.)
%ifdef PAOS_EARLY_TRAP_INJECT_GP
    mov  rax, 0x8000000000000000          ; non-canonical target -> #GP(0)
    jmp  rax
%else
    ud2                                   ; guaranteed #UD(6)
%endif
%endif

    ; --- grab the framebuffer BEFORE EBS (GOP is a boot service) ---
    call firmware_logo_capture          ; copy admitted BGRT bitmap before BS memory can be reclaimed
    call gop_query                      ; saves fb base/res/stride (or skips)
%if !PAOS_PUBLIC_BUILD
    call pmod_preload                   ; bounded read-only ESP preload; missing media degrades after EBS
%endif
    call ucode_preload                  ; RCQ-42 2b-2: the slot's microcode pack, read + digest only (no WRMSR pre-EBS)
    call manager_heal_preload           ; read-only bootmgfw SHA-256 before EBS: is the vault Manager misplaced there?
    call recovery_state_preload         ; GE C2: read-only journal copy matching the CRC-bound Manager handoff
    call system_secret_preebs           ; SEC slice 2: the SYSTEM secret's NV|BS copy (only reachable before EBS) + the scrub gate
    call owner_stage_key_preebs         ; owner S1b-2c-0: the owner stage key Z (NV|BS, born pre-EBS from EFI_RNG/RDSEED/RDRAND, never from Y)
    call app_install_grants_preebs      ; PaOSAppGrants MAC key: HKDF(Z, own label); owner_store below discards Z
    call app_store_seal_preebs          ; app catalog MAC: separate HKDF(Z) domain before Z discard
    call terminal_grants_store_preebs   ; distinct Terminal consent key domain before Z discard
    call public_documents_seal_preebs   ; independent public Documents key domain before Z discard
    call owner_store_preebs             ; owner S1b-1: PaOSOwner A/B (NV|BS) select + PaOSOwnerStage commit, needs Z above
    call terminal_grants_store_after_owner_preebs ; bind committed owner without consuming principal's handoff
    call public_documents_seal_after_owner_preebs ; bind public Documents to committed owner handoff
    call replay_floor_preebs            ; SEC-replay-record-mac S1: PaOSReplayFloor (NV|BS) B/F' + RT mirror, needs ows_floor_seeded above
    call secureboot_snapshot           ; SB-sense: capture SecureBoot/SetupMode/MokListRT pre-EBS (firmware runtime live)
    call node_identity_store_preebs    ; read-only authenticated identity before SYSTEM Y is taken
    call recovery_boot_preload          ; after Secure Boot + SMBIOS snapshot; optional owner-RSA grant stays OFF absent
    call usb_boot_media_snapshot        ; HUB0: read-only LoadedImage DevicePath -> USB boot-media port chain (hub policy)
    call boot_esp_guid_capture          ; RCQ-38 G1b: read-only boot-ESP partition GUID + removable bit (res_pack locator, Try admission)

    ; --- 1273a: hand the firmware its own fault gates back before EBS. Past
    ;     this point core/idt.asm installs PaOS's real IDT, and a stale hook
    ;     into code whose mapping is about to change is exactly the latent trap
    ;     this module exists to remove. ---
    call early_trap_uninstall

    C3WD_EDGE PBM_INIT_STAGE_P0, PBM_INIT_TRANSITION_COMPLETED
    C3WD_EDGE PBM_INIT_STAGE_P1, PBM_INIT_TRANSITION_STARTING
    BOOT_P1CKPT_STAMP                   ; RCQ-32: P1 checkpoint persistence has returned

    ; --- leave Boot Services + install our W^X page tables (boot/paging.asm) ---
    PAOS_NATIVE_PROGRESS 4       ; accepted handoff; pre-EBS path intent only
    call exit_boot_and_page             ; emits paging + W^X markers; returns owning the CPU
    ; The loader frame is retired forever: efi_entry never returns after EBS.
    mov  rsp, [rel percpu_stack_base]
    add  rsp, PERCPU_STACK_BSP_TOP
    sub  rsp, 8                          ; preserve established header residue
    call filmstrip_init                 ; bind/clear Task2302's pre-reserved RAM arena before checkpoint 0

    ; --- 1076/1083 boot_beacon: derive the per-boot nonce, then PAINT the on-screen
    ;     boot-confirm badge (known color rgb(0,180,90) @ 24,24 + nonce hex). Runs
    ;     POST-paging so the fb window (mapped RW+NX by boot/paging.asm above) is
    ;     writable. This is the keep's FIRST serial/NIC-independent boot-confirm
    ;     channel — GLKVM reads the badge on the M720s (settles 1080's screen axis).
    ;     Degrades cleanly if GOP is absent (serial notes it, boot continues). ---
    call beacon_nonce_init              ; emit [beacon.nonce] (TSC-seeded per-boot nonce)
    ; --- Repair display-plane geometry BEFORE the first PaOS paint. The
    ;     firmware ConOut/ClearScreen calls (pre-EBS boot-face prints) leave
    ;     the plane at the 800x600 console default (stride 0x32) while PaOS
    ;     draws 1920-wide rows -> every early frame tiles/garbles until the
    ;     late beacon-dismiss repair. ConOut cannot run post-EBS, so repairing
    ;     here (verify-then-repair, unknown GPUs skip+report) makes the FIRST
    ;     painted frame clean. The late dump in command_udp stays as audit.
    call gop_plane_dump
    call gop_health_evaluate            ; 1249 P52/P53: read-only register fact + self-detection verdict
    ; Boot audit item 3 (root 2026-10-17 23:25:51, spec 7.6.10): the badge, the PLV1 panel and the
    ; first-GOP crop are lab-floor diagnostics. The shipped floor paints none of them and says so
    ; on serial with the same nonce; the wire beacon, LOCKSTATE and BOOTCLOCK keep boot_nonce.
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
%if PAOS_PUBLICITY_LAB_PROFILE
    call beacon_gop_paint               ; paint badge + nonce -> [beacon.gop.painted]
    call liveness_panel_draw_beacon_nonce ; reuse Task2100 PLV1 renderer with zero-left-padded beacon nonce
    call filmstrip_capture_first_gop    ; frame + native origin crop, still before any beacon dismiss
%else
    call beacon_gop_floor_skip          ; nothing painted -> [beacon.gop.floor_skipped] nonce=...
%endif
    call beacon_wire_send               ; P5 wire beacon RUNG: always the honest skip (egress warms at P8 per the 1051 split) -> [beacon.wire.skipped]. The REAL send is udp_boot_beacon_tick in the .halt loop (1094) once link is up -> [beacon.wire.sent]

    ; --- own the GDT (drop the firmware GDT dependency) BEFORE the IDT, so the
    ;     IDT's gate selectors reference our kernel code segment (0x08) ---
    call gdt_init                       ; lgdt + far-reload CS to 0x08, SS/DS/...=0x10

    ; --- core L1: interrupt descriptor table + fault handlers (core/idt.asm) ---
    call idt_init                       ; faults are now diagnosable, not silent reboots

    ; --- DEBUG-INFO foundation: bind the persistent diag ring FIRST (core/diag.asm),
    ;     so from here every phase breadcrumbs enter/exit into it (the PHASE macro)
    ;     and every fault writes its register dump to it. Brought up right after the
    ;     IDT so a fault in ANY subsequent phase is captured. ---
    call diag_init
    xor edi,edi
    call mca_boot_init                  ; boot STATUS logs, CTLs, then CR4.MCE
    call diag_crash_record_project      ; RCQ-41: prior boot's fatal fault -> PaOSCrashRecord (diagnostic only)
    lea rdi,[rel diag_crash_record]
    call crash_identity_project         ; retained prior-fault identity ONLY
    lea rdi,[rel crash_identity_record]
    call deadman_identity_project        ; exact prior ring/PBCI-bound D4 source

    ; --- Boot Manager v2 SAFE PROFILE.  Branch at the smallest honest runtime
    ;     floor: Manager handoff validated, GOP acquired/painted, Boot Services
    ;     exited, our W^X paging/GDT/IDT installed, and the persistent diagnostic
    ;     ring bound.  Do not run the normal boot's fault-injection selftests,
    ;     legacy A/B CMOS mutation, heap/timer/governor, buses/drivers, storage,
    ;     network, hypervisor, GUI, cognition, hotpatch, or applications.  Expose
    ;     only the read-only STATUS/PING registry over the already-owned COM1.
    ;     This is a bounded diagnostic environment inside either full PaOS slot;
    ;     independent Rescue remains a separate payload and trust boundary. ---
    C3WD_EDGE PBM_INIT_STAGE_P1, PBM_INIT_TRANSITION_COMPLETED
    cmp  byte [rel pbm_manager_launch], 1
    jne  .normal_profile
    cmp  byte [rel pbm_profile], PBM_PROFILE_SAFE
    jne  .normal_profile
    call command_registry_safe_init
    call command_serial_init
    call command_serial_beacon
    lea  rdi, [rel str_pbm_safe_reachable]
    call serial_string
    jmp  .safe_halt
.normal_profile:
    ; Select serial presentation from PREVIOUS-boot evidence before ordinary
    ; normal-profile fault/driver work. boot_ab_early later increments the same
    ; retained trial snapshot; this read is deliberately pre-increment.
    movzx ecx, byte [rel boot_log_override_policy] ; P0-consumed AUTO/LEAN/VERBOSE/malformed
    movzx edi, byte [rel boot_log_prior_trial]
    cmp  byte [rel boot_log_prior_valid], 1
    je   .log_trial_ready
    mov  edi, -1                         ; unreadable CMOS => fail-open VERBOSE
.log_trial_ready:
    movzx esi, byte [rel diag_prev_valid]
    mov  rdx, [rel diag_prev_faults]
    cmp  esi, DIAG_PREV_VALID
    jne  .log_health_ready
    cmp  byte [rel diag_prev_health_valid], 1
    jne  .log_health_bad
    mov  rdx, [rel diag_prev_health_faults]
    jmp  .log_health_ready
.log_health_bad:
    mov  esi, DIAG_PREV_BAD_FAULT_COUNT   ; ambiguous retained baseline => fail open
.log_health_ready:
    call boot_log_mode_select
    ; Detail and UART scheduling are independent: native ordinary writers use
    ; the image-owned FIFO in VERBOSE as well as LEAN. IF=0/fault output keeps
    ; its synchronous boundary; the binder keeps hypervisor markers synchronous.
    ; No heap dependency delays binding through the early core phases.
    lea  rdi, [rel serial_lean_buf]
    mov  esi, SERIAL_LEAN_CAPACITY
    call serial_deferred_bind
.log_mode_bound:
    call boot_budget_emit_armed
    BOOT_SELFTEST ST_LOG_MODE_POLICY
    C3WD_EDGE PBM_INIT_STAGE_P2, PBM_INIT_TRANSITION_STARTING
%if PAOS_LAB_B1_STARTING_FAILURE && PAOS_LAB_B1_STARTING_STAGE == 2
    ; Native IDT and persistent diag ring now own fatal faults. The firmware
    ; trap hook remains retired; no new handler or recovery authority.
    call boot_b1_failure_control
%endif

    ; --- core self-tests, each bracketed by a diag-ring phase breadcrumb (PHASE) ---
    BOOT_PHASE_SELFTEST PH_IDT_ST, ST_IDT    ; int3 round-trip proves the IDT works
    BOOT_PHASE_SELFTEST PH_WX_ST,  ST_WX_NX  ; exec-from-NX must #PF — proves the NX half only

    ; --- FAULT DURABILITY (core/idt.asm, 9701 tournament-#2 'recovery' winner):
    ;     prove uncontained CPU fault classes DEGRADE (diag-dump + recover/gated
    ;     warm-reset) rather than hard-hang. Plain calls (no diag PHASE — keeps
    ;     DIAG_NPHASES ring geometry). fault_contain_selftest traps #UD(6) via the
    ;     same trapped-fault contract diag/wx use (-> [fault.contain.ud]);
    ;     fault_recover_selftest forces an UNCONTAINED #DE(0) through .panic to
    ;     prove the recover-instead-of-hang path (-> [fault.recover.warmreset]).
    ;     PaOS principle: no fault should hard-hang (RESILIENCE.md). The real CF9
    ;     fire + crash-counter escalation is the deliberate bare-metal leg. ---
    BOOT_SELFTEST ST_FAULT_UD
    BOOT_SELFTEST ST_FAULT_RECOVER
    ; 9702: the nastiest class — #DF(8) via the IST1 stack (boot/gdt.asm TSS).
    ; Breaks its own stack (non-canonical RSP + push), requires the CPU to
    ; deliver #DF over IST and the handler to fix the frame -> [fault.contain.df].
    BOOT_SELFTEST ST_FAULT_DF

    ; --- C3 (1014) boot-canon BARE-METAL live-wire, P0/P1 half: verify-then-jump
    ;     hash (good keep matches manifest, one-byte-corrupt keep REJECTED) + load
    ;     the CMOS trial/good state (0x74/0x75) and count this boot as a trial +
    ;     MEASURE the Intel PCH TCO hardware watchdog off the LPC ACPI base (armed-safe:
    ;     briefly run it for a bounded decrement proof, then restore TMR_HLT so a
    ;     mis-kick can't brick the shared loop box; live-firing arm is supervised
    ;     1014b). Placed here — right
    ;     after EBS/paging (exit_boot_and_page above) and the fault-durability floor,
    ;     BEFORE the P3+ device-discovery selftests — so the watchdog covers the
    ;     driver-init window (known_trap: arm at P1, not P2). Emits boot.ab.verify +
    ;     boot.ab.state.loaded + boot.watchdog.armed|absent. The trial->good COMMIT
    ;     (boot.ab.committed) fires after every selftest passes, below. ---
    call boot_ab_early
%ifdef PAOS_TCO_DEADMAN
    ; --- hub packet 0011: the PCH TCO hardware deadman (core/tco_deadman.asm).
    ;     Arms after boot_ab's halted TCO measurement (its last TCO write); the
    ;     idle loop kicks it. UNAVAILABLE where the firmware set TCO_LOCK (the
    ;     MSI and the Lenovo M720s): that path only reads. ---
%ifdef PAOS_LAB_TCO_FW_LOCK
    call tco_lab_firmware_lock           ; lab: leave TCO1_CNT as the MSI firmware does
%endif
    call tco_deadman_arm
%endif

    ; --- 9702: ARM the CF9 warm-reset — BARE METAL ONLY (CPUID hypervisor bit
    ;     clear AND the real PCH TCO found), and only NOW, after boot_ab_early
    ;     persisted this boot's trial count: every armed fault-reset therefore
    ;     climbs the CMOS ladder toward the pre-EBS Windows escalation, so a
    ;     fault-looping keep is BOUNDED (never an infinite reboot loop). Also
    ;     installs the demote hook (.panic clears the confirmed magic pre-CF9). ---
    call fault_warmreset_arm

    ; --- RCQ-42: checked BSP apply (sec/cpu_microcode_bsp_checked).
    ;     After the trial count, TCO deadman and CF9 arm (a load that wedges
    ;     the CPU is bounded by the CMOS ladder), before ST_LIB and any
    ;     consumer of CPUID-derived caps. Normal profile only (Safe branched
    ;     above). No admitted pack = one report line, no update trigger. ---
    call cpu_microcode_boot_bsp_checked

    ; --- core/lib primitives self-test (core/lib/str.asm) ---
    BOOT_PHASE_SELFTEST PH_LIB, ST_LIB

    ; --- observability + anti-duplication root: fmt vectors + structured log
    ;     (core/lib/fmt.asm + core/log.asm). Every later task logs through here. ---
    BOOT_PHASE_SELFTEST PH_LOGFMT, ST_LOGFMT
    BOOT_PHASE_SELFTEST PH_KAT, ST_STRMEM     ; str+mem known-answer-test table (G1 hardening)
    BOOT_SELFTEST ST_NET_CKSUM16              ; 1408 tournament: RFC1071 KAT
    BOOT_SELFTEST ST_FMT_DEC                  ; 1430 tournament: formatter KAT + fault battery
    ; 9703: prove the primitives' register-clobber contract (touch only rax/rcx/rdx/rsi/rdi,
    ; never r8-r15/rbx/rbp — callers stash live cluster ptrs in r8 across these calls). Plain
    ; call (no diag PHASE) to keep DIAG_NPHASES ring geometry.
    BOOT_SELFTEST ST_LIB_CLOBBER

    ; --- kernel heap up + self-test (core/heap.asm) ---
    PHASE PH_HEAP_INIT,  heap_init
    BOOT_PHASE_SELFTEST PH_HEAP_ST, ST_HEAP
    call diag_failure_begin             ; exclude initial KAT OOM, read prior scalar record
    BOOT_PHASE_SELFTEST PH_MEMMAP, ST_MEMMAP  ; own the UEFI map post-EBS; sum conventional RAM
    BOOT_SELFTEST ST_MEMMAP_OWNER             ; RC s21.1: owned regions vs the published final map (read-only)
    BOOT_SELFTEST ST_MMAP_REFUSAL             ; T1-4.8: the final-map validator refuses unsupported layouts

    ; --- L1 mem (qemu rung): relocatable hot-data layout descriptor + layout_resolve
    ;     (mem/layout.asm, 1069). Plain call (no diag PHASE — keeps DIAG_NPHASES ring
    ;     geometry); the selftest builds the descriptor, resolves+fills+checksums a hot
    ;     region, RELOCATES it (descriptor base swap = the forge's move, simulated),
    ;     re-resolves+re-checksums, and prints the KAT (base_pre!=base_post, cksum
    ;     identical) + the degenerate-second-region seam gate. The per-machine cache-
    ;     tuned relayout (PMU-measured) is a later apex; this proves only the SEAM. ---
    BOOT_SELFTEST ST_MEM_LAYOUT

    ; --- time base: calibrate TSC (core/time.asm) ---
    BOOT_PHASE_SELFTEST PH_TIME, ST_TIME
    call hda_boot_handoff

    ; --- first hardware interrupt: PIT timer tick (core/time.asm) ---
    call boot_indicator_bind             ; final post-paging GOP snapshot, before IRQs
    PHASE PH_TIMER_INIT, timer_init
    BOOT_PHASE_SELFTEST PH_TIMER_ST, ST_TIMER
%ifdef PAOS_TCO_DEADMAN
    call tco_proof_hang                  ; 0011: PAOS_TCO_PROOF builds only, the deliberate wedge (clock calibrated: its CF9 safety can fire)
%endif

    ; --- 1050 GOVERNOR (GOVERNOR.md): detect+enable HWP and request the BOOT SPRINT
    ;     here (right after TSC/timer are up) so the ENTIRE remaining boot runs at full
    ;     turbo (within-spec, hardware-clamped). gov_selftest then proves the
    ;     request/clamp/measure-and-revert LOGIC deterministically (QEMU-safe). The
    ;     boot-sprint is relaxed to the quiet balanced policy at the interactive-ready
    ;     point below (gov_relax). Plain calls (no diag PHASE) to keep the ring geometry.
    ;     A no-HWP box degrades visibly (gov.hwp.detect 'skipped no-HWP') — never dark. ---
    call gov_init                        ; -> gov.hwp.detect (present or skipped) + boot-sprint
    BOOT_SELFTEST ST_GOVERNOR            ; -> gov.aperf.kat (clamp/order/instability-revert KAT)

    ; --- 1041 THERMAL: arm the DTS monitor (MSR 0x19C/0x1A2) then run the READ ->
    ;     INDUCE+LOG throttle -> P-state build-gate KAT. Deterministic + QEMU-safe (no
    ;     DTS/APERF -> synthetic sensor for the LOGIC, degrade honestly on the wire).
    ;     Plain calls (no diag PHASE) to keep the ring geometry. Reuses gov_rd_aperf/
    ;     mperf for the live P-state; additive to the IRQ0 cadence (never perturbs it). ---
    call thermal_init                    ; -> thermal.monitor.armed (present or degraded)
    BOOT_SELFTEST ST_THERMAL             ; -> thermal.read.ok + thermal.throttle.logged + power.pstate.ok

    ; --- 1066 RESILIENCE: install the PCIe AER + IOMMU/VT-d DMAR + root-port CTO handlers
    ;     (extends the C38 fault surface to the transport-layer error classes). Enumerates
    ;     real bus-0 PCIe root ports (pci_cfg_read32), installs the catch/log/contain path
    ;     (reuses the C2 diag ring), configures a bounded CTO, then the contained self-test
    ;     injects a simulated error through the SAME path. Plain calls (no diag PHASE) to
    ;     keep the ring geometry. QEMU-safe (no root ports -> honest degrade, markers still
    ;     fire as a build gate; the random-tag round-trip is the bare-metal content grade). ---
    call resilience_init                 ; -> aer.handler.registered + iommu.fault.registered + pcie.cto.configured
    BOOT_SELFTEST ST_RESILIENCE          ; -> aer.contained.selftest

    BOOT_PHASE_SELFTEST PH_SCHED,   ST_SCHED
    BOOT_PHASE_SELFTEST PH_PREEMPT, ST_PREEMPT
    BOOT_PHASE_SELFTEST PH_DMA,     ST_DMA

    ; --- DEBUG-INFO acceptance: force a trapped fault, prove the dump + ring
    ;     readback (core/diag.asm), then report the PREVIOUS boot's ring. ---
    BOOT_PHASE_SELFTEST PH_DIAG, ST_DIAG
    call diag_report_prev                ; P2: read + report the previous boot's ring

    ; --- P2 core done: boot + all core self-tests passed. Minimal keep halts here.
    ;     The loop builds UP from here (bus -> class seams -> drivers -> net -> gui ->
    ;     guest), hot-patch-primary + bare-metal-gated (SKELETON.md). ---
    lea  rdi, [rel str_p2ok]
    call serial_string
    C3WD_EDGE PBM_INIT_STAGE_P2, PBM_INIT_TRANSITION_COMPLETED
    C3WD_EDGE PBM_INIT_STAGE_P3, PBM_INIT_TRANSITION_STARTING

    ; --- P3 LOOP ACCELERATOR: function-level live hot-patch (svc/hotpatch.asm,
    ;     LIVE_FORGE §4.5). Prove a live patch takes effect (content-graded: the
    ;     patched fn returns a per-boot random nonce) and that a bad patch auto-
    ;     reverts (self-test-or-revert watchdog). Runs last: it mutates image code
    ;     in place, so every core self-test above is already green first. ---
    BOOT_PHASE_SELFTEST PH_HOTPATCH, ST_HOTPATCH

    ; --- 1018 hot-patch GENERATOR (QEMU-gradeable half): eligibility gate + C1
    ;     per-function reloc consumption + end-to-end nonce round-trip, all in RAM.
    ;     Plain call (no diag PHASE — keeps DIAG_NPHASES); emits its own three
    ;     hotpatch.gen.* markers. The LIVE UDP delivery half is bare-metal (probe). ---
    BOOT_SELFTEST ST_HOTPATCH_GEN

    ; --- 1106 hot-patch GENERAL PATCHER (QEMU-gradeable half): target-by-symbol
    ;     resolve + full live patch/nonce/revert on a NON-hook slot fn + the
    ;     address-stable slot-region property. Plain call (no diag PHASE); emits
    ;     hotpatch.target.by_symbol + hotpatch.build.addr_stable itself. ---
    BOOT_SELFTEST ST_HOTPATCH_SYMBOL

    ; --- L4 net (qemu rung): TCP 3-way-handshake state machine LOGIC over canned
    ;     SYN/ACK segments (net/tcp.asm, 1044). Plain call (no diag PHASE — keeps
    ;     the ring geometry at DIAG_NPHASES); the selftest prints its own KAT +
    ;     marker. Live `nc` connect on the real NIC is the bare-metal rung (1026). ---
    BOOT_SELFTEST ST_TCP_HANDSHAKE
    BOOT_SELFTEST ST_TCP_SYNACK

    ; --- L4 net (qemu rung): ARP resolution CACHE table LOGIC over canned ARP
    ;     replies (net/arp_cache.asm, 1045). Plain call (no diag PHASE); the
    ;     selftest prints its own KAT + marker. Live-wire ARP resolution/cache hit
    ;     over the real NIC is the bare-metal rung (1022/1024/1025). ---
    BOOT_SELFTEST ST_ARP_CACHE
    BOOT_SELFTEST ST_ARP_LOOKUP
    BOOT_SELFTEST ST_ARP_INSERT

    ; --- L4 net (qemu rung): DHCP client message LOGIC — parse a canned OFFER,
    ;     BUILD the matching REQUEST (echo xid + opt50=offered-yiaddr + opt54),
    ;     parse a canned ACK (net/dhcp.asm, 1046). Plain call (no diag PHASE); the
    ;     selftest prints its own KAT + marker. The live-wire DORA lease over the
    ;     real NIC is the bare-metal rung (1022/1024/1025). ---
    BOOT_SELFTEST ST_DHCP_CLIENT

    ; --- TOURNAMENT 1307: dhcp_find_option known-answer gate — 18 vectors through
    ;     the real TLV walk (bit-exact finds, clean misses, contained rejects for
    ;     NULL/short/truncated/len-less hostile frames) with the find/miss/reject
    ;     telemetry counters delta-checked to (8,5,5)
    ;     ([tourn.dhcp_find_option.kat] [tourn.dhcp_find_option.guard]). ---
    BOOT_SELFTEST ST_DHCP_FIND_OPTION

    ; --- TOURNAMENT 1407: dhcp_parse_ack known-answer gate — the SINGLE-PASS ACK
    ;     parser is driven over the canned DHCPACK (lease yiaddr/mask/gw/dns read
    ;     back bit-exact) plus four contained rejects (bad magic cookie, short
    ;     frame, an OFFER with the wrong msg-type, an ACK missing a required
    ;     option) — proves the fast path returns the SAME answers as the proven
    ;     4-walk baseline ([tourn.dhcp_parse_ack.kat] [tourn.dhcp_parse_ack.guard]). ---
    BOOT_SELFTEST ST_DHCP_PARSE_ACK

    ; --- TOURNAMENT 1410: dhcp_parse_offer known-answer gate (MOST-DURABLE variant) —
    ;     the atomic single-pass OFFER parser is driven over the canned DHCPOFFER
    ;     (xid/yiaddr/server-id read back bit-exact) + 9 contained rejects (one per
    ;     distinct reason) with the ok/per-reason telemetry delta-checked, plus an
    ;     ATOMICITY gate proving a rejected frame (missing opt54 / zero yiaddr) never
    ;     perturbs dhcp_parsed_* ([tourn.dhcp_parse_offer.kat] [.guard] [.atomic]). ---
    BOOT_SELFTEST ST_DHCP_PARSE_OFFER

    ; --- TOURNAMENT 1411: dhcp_wr_u8 known-answer gate (MOST-DURABLE variant) —
    ;     the shared 0..255 decimal formatter (fan-in 5) is driven over 8 vectors
    ;     content-graded byte-for-byte across all three write paths, plus two
    ;     durability gates the leaner variants skip: a BOUNDED-WRITE guard (RDI
    ;     advance exact + 0xEE sentinel one-past-end untouched = no overrun) and a
    ;     fault-CONTAINMENT clamp (out-of-range / dirty-high input folded to its
    ;     low byte still emits only digits) ([tourn.dhcp_wr_u8.kat] [.guard] [.clamp]). ---
    BOOT_SELFTEST ST_DHCP_WR_U8

    ; --- L4 net (qemu rung): DNS A-record query/response LOGIC — encode the QNAME
    ;     for "example.com", parse a canned response + extract the A record, and
    ;     FOLLOW the 0xC0 compression pointer (net/dns.asm, 1047). Plain call (no
    ;     diag PHASE); the selftest prints its own KAT + marker. The live-wire DNS
    ;     resolution over the real NIC is the bare-metal rung (1022/1024/1025). ---
    BOOT_SELFTEST ST_DNS_RESOLVER

    ; --- TOURNAMENT 1308: dns_decode_name known-answer gate — 11 vectors through
    ;     the real decoder (bit-exact pointer/direct/mid/root/chain decodes, plus
    ;     contained rejects for loop/out-of-frame/reserved-bit/truncated-label/
    ;     cut-pointer/amplification hostile frames, canary-checked) + a TSC-timed
    ;     64-decode hot-path measurement ([tourn.dns_decode_name.kat]
    ;     [tourn.dns_decode_name.guard] [tourn.dns_decode_name.perf]). ---
    BOOT_SELFTEST ST_DNS_DECODE_NAME

    ; --- TOURNAMENT 1428 v2 FASTEST: dns_streq known-answer + fixed fault gate —
    ;     4 ordinary and 8 hostile exact-result vectors through the page-safe
    ;     qword comparator, then 512 fenced live calls for the latency axis
    ;     ([tourn.dns_streq.kat] [.fault] [.perf]). ---
    BOOT_SELFTEST ST_DNS_STREQ

    ; --- TOURNAMENT 1310 (durable): dns_parse_response hostile-shape gate — 11
    ;     table-driven contained rejects + dns_a_ip poison guard + bit-exact
    ;     positive + TSC 64-parse measurement ([tourn.dns_parse_response.kat]
    ;     [tourn.dns_parse_response.guard] [tourn.dns_parse_response.perf]). ---
    BOOT_SELFTEST ST_DNS_PARSE_RESPONSE

    ; --- TOURNAMENT 1417 (durable): dns_wr_u8 known-answer gate — 9 bit-exact
    ;     positive vectors (every branch) + 2 out-of-range DEGRADE gates + a NULL-
    ;     dst CONTAINMENT guard + an overrun canary, all through the live formatter
    ;     ([tourn.dns_wr_u8.kat] [tourn.dns_wr_u8.guard] [tourn.dns_wr_u8.perf]). ---
    BOOT_SELFTEST ST_DNS_WR_U8

    ; --- TOURNAMENT 1425 (durable): dns_skip_name known-answer + fault-battery gate
    ;     — 3 bit-exact positive vectors (multi-label QNAME / 0xC0 compression
    ;     pointer / lone-zero root) + a FIXED battery of 6 hostile vectors
    ;     (reserved-bit len / truncated pointer / label-past-end / cursor-at-end /
    ;     unterminated-run / NULL frame), each contained to -1 with no OOB read
    ;     ([tourn.dns_skip_name.kat] [tourn.dns_skip_name.guard]
    ;     [tourn.dns_skip_name.fault contained=N total=6]). ---
    BOOT_SELFTEST ST_DNS_SKIP_NAME

    ; --- TOURNAMENT 1421 (durable): dns_encode_qname known-answer + fault-battery
    ;     gate — 2 bit-exact positive vectors (example.com byte-for-byte vs the
    ;     canned wire QNAME / single-label "com") + a FIXED battery of 8 hostile
    ;     vectors (label>63 / 64-byte-boundary / name>255-with-overrun-canary /
    ;     empty / trailing-dot / leading-dot / NULL dst / NULL src — a superset of
    ;     the smallest variant's 6, adding the two NULL-ptr containments), each
    ;     content-checked ([tourn.dns_encode_qname.kat] [tourn.dns_encode_qname.guard]
    ;     [tourn.dns_encode_qname.fault contained=N total=8]). ---
    BOOT_SELFTEST ST_DNS_ENCODE_QNAME

    ; --- TOURNAMENT 1429 (durability, SMALLEST variant): icmp_build_reply known-
    ;     answer + fault-battery gate — the canned echo REQUEST builds a byte-exact
    ;     echo REPLY (type 0 / code 0 / checksum 0xEE97 / id+seq preserved / payload
    ;     echoed verbatim / RFC1071 self-fold to 0) + a FIXED battery of 5 hostile
    ;     vectors (empty / len=7 boundary / len=1 / type=0 echo-reply / type=13
    ;     non-echo), each contained to -1 with the dst scratch canary intact
    ;     ([tourn.icmp_build_reply.kat] [tourn.icmp_build_reply.guard]
    ;     [tourn.icmp_build_reply.fault contained=N total=5]). ---
    BOOT_SELFTEST ST_ICMP_BUILD_REPLY

    ; --- L1 sched (qemu rung): SCHEDULER §4.6 CADENCE REGISTRY — register TWO
    ;     cadences at different declared periods, DRIVE both from ONE tickless
    ;     deadline authority, TSC-measure each fire interval (core/cadence.asm,
    ;     1070). Plain call (no diag PHASE — keeps the ring geometry); the selftest
    ;     prints its own KAT (declared vs measured period + fire counts) + markers.
    ;     LLM policy tuning + the escalation nervous system's higher tiers are the
    ;     apex (§4.6), later contracts; this proves the SEAM (one registry, >=2
    ;     registrants, rate-follows-declaration) exists. ---
    BOOT_SELFTEST ST_CADENCE_REGISTRY

    ; --- L5 svc (qemu rung): THE COMMAND MODEL — transport-agnostic verb registry
    ;     + capability gate + non-blocking job model (svc/command.asm, 1077,
    ;     COMMANDS.md §1-3,§9.4). Plain call (no diag PHASE — keeps the ring
    ;     geometry). Proven IN-PROCESS (no NIC, no serial-as-transport): register 3
    ;     verbs through ONE registry, PING echoes a fresh rdtsc nonce (real
    ;     dispatch, not a latch), a slow verb returns accepted+job_id while STATUS
    ;     still answers (the "wedged vs slow" cure), and every run routes through
    ;     the ONE dispatch (single-vocabulary). 1010(UDP)/1078(serial)/1079(ACP)
    ;     are PROJECTIONS over this table, graded in their own contracts. ---
    C3WD_EDGE PBM_INIT_STAGE_P3, PBM_INIT_TRANSITION_COMPLETED
    C3WD_EDGE PBM_INIT_STAGE_P4, PBM_INIT_TRANSITION_STARTING
    BOOT_SELFTEST ST_COMMAND_REGISTRY

    ; --- L5 svc (qemu rung): THE AI-HOOK PROJECTION over the 1077 registry
    ;     (svc/command_aihook.asm, 1079, COMMANDS.md §5,§9.3) — the surface that
    ;     makes a WEAK local LLM competent. Plain call (no diag PHASE — keeps the
    ;     ring geometry). Runs right after the registry selftest so the 3 verbs are
    ;     live. Proves IN-PROCESS (no transport — the point of the native surface):
    ;     (1) an in-proc PING <fresh nonce> submitted as a TYPED envelope echoes the
    ;     nonce back through the ONE dispatch (real dispatch, not a latch); (2) a
    ;     plain-language INTENT ("the data array") resolves to a registered handle
    ;     ("md0") — the model names intent, not a device path; (3) CATALOG is
    ;     GENERATED from the registry's self-description (count == verb_count, can't
    ;     drift); (4) a bad selector returns an actionable {code,expected,hint} and a
    ;     retry with the hint resolves in ONE turn. Emits the four cmd.aihook.* markers
    ;     the probe content-grades. The remote ACP/MCP tool-list export is an additive
    ;     follow-on rung on this same generated description, not a reshape. ---
    BOOT_SELFTEST ST_COMMAND_AIHOOK

    ; --- L5 sched (1048): THE MULTI-CLASS SCHEDULER POLICY LAYER over the C3 SMP
    ;     foundation (svc/command_sched.asm, SCHEDULER.md §2-4,§8). Plain call (no
    ;     diag PHASE — keeps the ring geometry). Runs after the registry is live so
    ;     it can register SCHEDPLACE/SCHEDSTAT. Builds the declarative class table
    ;     (owner/forge/throughput/realtime + the grid-ready "borrowed" row), arms the
    ;     placement-policy HOOK (jobs PLACED through a fn ptr, not invoked), reads the
    ;     real CPUID topology, then the SPREAD KAT places SCHED_KAT_JOBS throughput
    ;     jobs and proves they land on >1 core (cores=1 honest degenerate). Emits
    ;     sched.classes/sched.place.hook/sched.spread.kat + the sched.kat cores_used
    ;     print the probe content-grades. Bare-metal per-class placement (nonce echo
    ;     + real core id) is the deliverable, graded in 1048's own probe over UDP. ---
    BOOT_SELFTEST ST_SCHED_CLASS

    ; --- L5 sched (1049): THE HARD-REAL-TIME DEADLINE CLASS characterizing the 1048
    ;     'realtime' row (svc/command_rt.asm, SCHEDULER.md §2 hard-RT delta / §8 v1 seam).
    ;     THE non-retrofit property: a deterministic-first realtime class can't be bolted
    ;     onto a cooperative scheduler later, so the SEAM exists now (degenerate-to-one):
    ;     admission table (default-deny over-budget), shield/affinity on the PINned top
    ;     core, a priority-inversion-safe CEILING lock, and a TSC worst-case-jitter
    ;     instrument. The boot characterization runs the shielded periodic canary UNDER a
    ;     contending load and measures its worst-case wake-to-run lateness; emits
    ;     sched.rt.admit/sched.rt.jitter.kat/sched.rt.invert + the sched.rt.kat print the
    ;     probe content-grades. Bare-metal RTLAT (MEASURED jitter + nonce) / RTADMIT
    ;     (default-deny) are the deliverable, graded over UDP. Runs after the class table
    ;     + registry exist (uses the 'realtime' row + registers RTLAT/RTADMIT). ---
    BOOT_SELFTEST ST_SCHED_RT

    ; --- L5 svc (1314): PER-ACTION AUDIT RECEIPT ring (owned/auditable-AI capdemo).
    ;     KATs the receipt write->readback path with a CONTENT compare (strcmp the
    ;     known line back out of the ring -> audit.ring.kat) and registers the AUDIT
    ;     readback verb. The UDP projection logs every dispatched line into this ring
    ;     BEFORE the verb split, so N nonce-tagged actions = N nonce-bearing receipts
    ;     — the §9 Pillar-4 demo's content grade. Needs only the registry (1077). ---
    BOOT_SELFTEST ST_AUDIT

    ; --- L5 svc (1078): THE SERIAL PROJECTION over the 1077 registry — the EARLIEST
    ;     bare-metal comms-back surface (COM1 0x3F8, up before NIC and GOP). Plain call
    ;     (no diag PHASE — keeps the ring geometry). command_serial_init arms the COM1
    ;     receiver (rx.init); command_serial_beacon emits "PAOS_BOOT_BEACON <nonce>" on
    ;     0x3F8 (the 3rd beacon leg 1076 lacks — NIC-less signal-back); command_serial_
    ;     selftest content-grades the WHOLE pipeline with a fresh rdtsc nonce fed through
    ;     the IDENTICAL rx path live UART drives (PING <nonce> -> registry -> echoed reply;
    ;     a fresh-per-boot nonce that survives text->parse->registry->reply can't be a
    ;     latch). command_serial_poll is pumped in the .halt idle loop so the channel is
    ;     LIVE post-boot for real UART RX. NOTE: the EARLY beacon leg is a DEAD instrument
    ;     on the M720s (firmware owns COM1 across the pre-EBS window; memory
    ;     m720s-early-serial-lost) — the binding bare-metal instrument is the LATE PING
    ;     round-trip over the live FTDI, graded post-boot. Markers: cmd.serial.rx.init +
    ;     cmd.serial.verb.dispatched + beacon.serial.sent (last two hw-only on QEMU). ---
    call command_serial_init
    call command_serial_beacon
    BOOT_SELFTEST ST_COMMAND_SERIAL
    C3WD_EDGE PBM_INIT_STAGE_P4, PBM_INIT_TRANSITION_COMPLETED
    C3WD_EDGE PBM_INIT_STAGE_P5, PBM_INIT_TRANSITION_STARTING

    ; --- L1 sched (qemu rung): SCHEDULER §4.5 RESIDENT-vCPU BOUNDED-QUANTUM FAIRNESS
    ;     SEAM — a resident guest vCPU is a first-class scheduling entity with a
    ;     BOUNDED, DECLARED quantum (preemptible at quantum end) and the host's
    ;     driver-class heartbeat gets a GUARANTEED interleaved slice, so a greedy
    ;     resident consumer can NOT starve the host (the structural cure for the
    ;     9374j 1%-CPU starvation family). Plain call (no diag PHASE — keeps the ring
    ;     geometry). v1 is the 9390 sim-drives-real pattern: a SIMULATED CPU-bound
    ;     consumer drives the REAL bounded-quantum interleave; the selftest TSC-
    ;     measures the host heartbeat and PRINTS a KAT (declared bound + heartbeat
    ;     count + max inter-beat gap for BOTH the bounded and the UNBOUNDED negative
    ;     run) that the probe content-grades: bounded max-gap <= bound (host lived)
    ;     AND unbounded max-gap > bound (starvation demonstrated — negative-as-gate,
    ;     not a latch). The real resident-Linux-guest interleave is the hv contracts
    ;     (1011/1012); this proves the fairness SEAM exists (core/vcpu_quantum.asm, 1071). ---
    BOOT_SELFTEST ST_VCPU_QUANTUM

    ; --- L1 boot-canon (qemu rung): the A/B fault-tolerant boot-canon STATE MACHINE
    ;     + safety checks over canned in-memory keeps (core/boot_canon.asm, 1073).
    ;     Plain call (no diag PHASE — keeps the ring geometry). Proves the three
    ;     pillars IN QEMU without real firmware/ESP/NVRAM/PCH watchdog: (1) verify-
    ;     then-jump hash (good verifies+selected; a one-byte-corrupt keep hash-
    ;     mismatches + is REJECTED, never jumped to), (2) A/B slot selection with
    ;     fall-through to last-good, (3) trial/good boot-attempt counter that ARMS
    ;     on selftest-pass and ROLLS BACK to last-good after N no-good trials. The
    ;     selftest PRINTS the hashes + counter transitions the probe content-grades.
    ;     The live-wire re-verify (AB_STATE/AB_COUNTER UDP nonce + PCH TCO watchdog
    ;     CRASHES gate at the target's configured address) is the bare-metal rung 1014. ---
    BOOT_SELFTEST ST_BOOT_CANON

    ; --- L1 security foundation (1237): published RFC 5869 HKDF-SHA256 and
    ;     NIST AES-256-GCM KATs, hostile AEAD rejects, and authenticated DEK
    ;     wrap/unwrap with a caller-supplied nonce and same-state duplicate
    ;     rejection. This KAT does not establish production nonce ownership or
    ;     persistence across caller reinitialization. ---
    BOOT_SELFTEST ST_CRYPTO_STANDARD

    ; --- M4 net (1058): standards-vector gate for the native TLS 1.3 client.
    ; Run in the proven deterministic crypto-KAT window: before the slower
    ; identity tests, and expose retained bytes independently through TLSKAT. ---
    BOOT_SELFTEST ST_TLS13

    ; --- M4 net (1059): HTTP/1.1 GET client over the TLS 1.3 session. Boot KAT
    ;     builds a request line + headers and drives the streaming status/header/
    ;     chunked response parser over fixture bytes (no wire). The live HTTPS
    ;     fetch (HTTPGET/HTTPSTAT/HTTPBODY) is graded on bare metal. ---
    BOOT_SELFTEST ST_HTTP

    ; --- L1/L5 identity foundation (1239): exact RFC 8032 Ed25519 vectors and
    ;     a deterministic node-envelope KAT, not a CSPRNG owner bootstrap.  The
    ;     synthetic identity is cleared before this selftest returns. ---
    BOOT_SELFTEST ST_ED25519
    test eax, eax
    jnz  .identity_foundation_done
    BOOT_SELFTEST ST_NODE_IDENTITY
.identity_foundation_done:

    ; --- L2 data legacy compatibility KAT (1074).  This retains the old
    ;     deterministic envelope-layout round trip until its caller migrates;
    ;     it is NOT evidence of encryption or authenticated storage.  Security
    ;     callers bind to the standard foundation proven immediately above. ---
    BOOT_SELFTEST ST_CRYPTO_ENVELOPE

    ; --- L2 sec (1053): the NON-RETROFITTABLE PRINCIPAL seam. Establishes the
    ;     OWNER (non-NULL id), proves task/log/row carry the owning-principal
    ;     field, runs the OWNER->OWNER paging-domain switch (real CR3 reload),
    ;     and runs the KDF auth derive KAT. Emits principal.owner/tagged/switch/
    ;     kdf iff every seam holds. ---
    BOOT_SELFTEST ST_PRINCIPAL

    ; --- L2/L3 DATA crypto foundation (1054): RFC5869 auth->KEK,
    ;     authenticated DEK wrap and AES-256-GCM record envelope. The KAT also
    ;     proves foreign-principal + wrong-credential authentication refusal. ---
    BOOT_SELFTEST ST_DATA_CRYPTO

    ; --- L2/L5 DATA store (1057): a forever-header KV row is sealed through the
    ;     1054 envelope in RAM, opened byte-identical, scanned to prove its value
    ;     is absent from ciphertext, and refused under a foreign principal. ---
    BOOT_SELFTEST ST_KVSTORE

    ; --- M-sec (1055): portable JOB + signed metering receipt.  A separate
    ;     fresh non-test identity fixture drives this existing KAT after its
    ;     principal/data prerequisites, then is cleared on return. ---
    lea  rdi, [rel job_receipt_selftest]
    BOOT_SELFTEST ST_NODE_ID_CONSUMER
    call node_identity_store_activate ; KAT cleared synthetic identity; import only authenticated durable handoff

    ; --- L1 core (1075, qemu rung): SMP lock-SITE RETRO-AUDIT of the pre-C3
    ;     subsystems (bus/hal 1005 + net/netdev 1009). Each retro-declared lock
    ;     SITE is EXERCISED once (acquire/guarded-write/release) and prints its
    ;     per-subsystem coverage line (bus + netdev sites=1 exercised>=1); the
    ;     report then walks the site registry and FLAGS the intentional canary
    ;     (hal_bypass — a real unguarded shared write with no ;; LOCK:), proving
    ;     the audit DETECTS a gap (flagged>=1), not a rubber-stamp. Real multi-core
    ;     lock contention is 1037 (SMP scale-out), a later rung. ---
    call hal_lock_audit                  ; bus coverage line + exercise
    call netdev_lock_audit               ; netdev coverage line + exercise
    call smp_lock_audit_report           ; negative gate: flag undeclared write + [smp.lock.audit]
    ; --- L1/L5 sched (1037 + 1114): compose the proven AP trampoline, then
    ;     replace its terminal park with AP-owned per-core queue pulls. Each
    ;     structured epoch waits for the stable post-bring-up AP set and is frozen
    ;     before serial/UDP formatting. Realtime and boot/control remain BSP-owned. ---
    BOOT_PREPIXEL_STAMP 0
    BOOT_SELFTEST ST_SMP
    BOOT_SELFTEST ST_SMP_STACKS               ; guarded arena lifetime + live page tables
    call boot_settle_cpus                ; settled: every discovered CPU online (report-only)
    call smpwork_declare
    BOOT_PREPIXEL_STAMP 1
    call acpi_irqmap_report              ; RCQ-12 S-IRQMAP: read-only interrupt-routing map -> [PAOS64] irqmap

    ; --- C22 ladder-compose (1093): fire the shipped foundation seams that went
    ;     green IN ISOLATION (their contracts 1005-1009,1042 are closed) TOGETHER in
    ;     this one boot, so the read-only skeleton_walks_audit scanner (1072) can see
    ;     them and auto-green. Each is a self-contained selftest (sets up its own
    ;     state, emits its own marker, returns). Dependency order: pci -> hal ->
    ;     netdev -> net-stack -> blockdev -> vfs (vfs reads back over the block layer,
    ;     so blockdev first). apic/cap (bus/irq apic_cap_selftest) is the MED-HIGH
    ;     LAPIC-timer-conflict seam — held out of this batch (1093 STRETCH). ---
    BOOT_SELFTEST ST_PCI                 ; C5 (1005): PCI config-space scan
    BOOT_SELFTEST ST_ACPI                ; live XSDT pointer for DMAR/VT-d discovery
    call hal_init                        ; C5 (1005): bounds-checked MMIO ring init -> [hal.init]
    BOOT_SELFTEST ST_NETDEV              ; C9 (1009): N-ary NIC table
    BOOT_SELFTEST ST_VIRTIO_DOMAIN       ; 1013: netdev_ops -> domain TX/RX rings KAT
    BOOT_SELFTEST ST_NET_STACK           ; C10a (1042): ARP reply + dispatch
    BOOT_SELFTEST ST_BLOCK               ; C7 (1007): blockdev class + reinit
    BOOT_SELFTEST ST_SND                 ; A1 (3201): snd class core + nullsnd ABI-v2 accounting KAT (self-contained; serial + driver ABI framework are up here)
    call reinit_declare                  ; C7/1065: DECLARE + self-test the driver reinit contract -> reinit.contract.declared/idempotent.selftest/quiesce_resume/verify_after
    call command_blk_init                ; C7/1027b: BLK* verbs over the blockdev dispatch + earned blk.* BOOTLOG flags -> blk.verbs.registered
    call command_pci_mmio_init           ; 1117b: PCISCAN/PCICFG_SAFE/MMIOCAP metal proof surface
    BOOT_SELFTEST ST_HOTPATCH_PERSIST
%if !PAOS_PUBLIC_BUILD
    call hotpatch_persist_replay         ; 1107: re-apply any ESP-persisted patch so it's live before the STATUS surface answers (quiet no-op if none)
%endif
    call dsec_declare                    ; 1054: DSECPUT/GET/GETAS/UNWRAP/DEL over the encrypted persistent fs seam
    call kvstore_declare                 ; 1057: DBPUT/DBGET/DBRAW/DBGETAS/DBPUTKILL owned-store verbs
    call command_video_playback_init      ; owner/MUTATE; unavailable when native video built=0
    call guest_frame_measure_init          ; owner-only native frame-copy observation
    call command_auth_init               ; 2020: load durable replay floor + declare public HELP/AUTHSTAT
    call keep_presentation_load           ; 2505: validate persisted target; missing/corrupt stays GUI
    call filmstrip_declare               ; 2302: canonical public T0 FILMSTRIP registry metadata
    ; 2100: reserve the ladder vocabulary early enough that bounded generated
    ; CATALOG output cannot truncate these names behind the older registry tail.
    call gui_ladder_declare
    ; 2502: cons_declare also creates the default user session. Its registry
    ; and initialization run together after login in lock_screen_desktop_start.
    ; Pre-login CATALOG intentionally has no user-console verbs.
    call command_aihook_auth_probe_declare ; 2020: nonce-driven live proof of the in-process AI ingress
    call command_udp_auth_declare_intercepts ; 2020: live pre-registry inventory; undeclared intercepts default-deny
    call thermal_declare                 ; 1041: register THERM/THERM_INDUCE/THROTTLE_LOG/PSTATE? (additive, no registry-core edit)
    call power_mode_declare              ; RC power P1: register POWERMODE (owner only)
    call idle_probe_declare              ; RCQ-27 B2: register IDLEPROBE (owner read, additive)
    call history_declare                 ; RC-history H1: register HISTCFG (owner only, additive)
    call resilience_declare              ; 1066: register AERINJECT/AERLOG/IOMMUINJECT/IOMMULOG/PCIECTO/PCIECTOINJECT (additive, no registry-core edit)
    call boot_ab_declare                 ; 1014: register AB_STATE/AB_COUNTER (live A/B keep decision + boot counter, additive)
    call bootmenu_declare                ; 1015+1040: register CRASH_STATUS/BOOT_MODE/BOOT + BOOTMENU_RENDER/BOOTMENU_SELECT/CHAINPATH (boot-menu projection, additive)
    BOOT_SELFTEST ST_BOOTMENU            ; 1040: exercise the render/canon-check/select code paths
    call manager_heal_declare           ; MGRSCRUB: read-only boot-canon observation of bootmgfw (MGRRESTORE retired)
    BOOT_SELFTEST ST_MANAGER_HEAL_QEMU
    BOOT_SELFTEST ST_MENU_LABELS_QEMU
    call recovery_state_declare         ; GE C2: C2RECOVERY read-only journal/policy observation
    BOOT_SELFTEST ST_RECOVERY_STATE_QEMU
    call software_stop_declare          ; GE C3: C3WATCH durable checkpoint + bounded Manager ladder observation
    BOOT_SELFTEST ST_SOFTWARE_STOP_QEMU
    BOOT_SELFTEST ST_VAULT_RESTORE_QEMU
    BOOT_SELFTEST ST_BOOT_BLACKBOX_QEMU
    BOOT_SELFTEST ST_BOOT_GE_C5_QEMU
    BOOT_SELFTEST ST_BOOT_GE_C7_QEMU
    call boot_blackbox_declare          ; GE C6: action-free C6BLACKBOX live PBMH-v2 projection
    call health_verdict_declare         ; GE C7: action-free C7HEALTH eight-dimension projection
    call optional_fault_declare         ; T2-1: authenticated disposable RAM backend runtime probe
    call principal_declare               ; 1053: register PRINWRITE/PRINREAD/PRINSWITCH/PRINKDF (principal seam live surface, additive)
    call owner_stat_declare              ; owner S1b-2: OWNERSTAT (owner-only owner store state)
    call hp_perf_declare                 ; 1312: register PERF (crc32 rdtsc micro-bench verb) + earn tourn.hotpatch_crc32.kat/guard/perf
    call fault_verb_declare              ; 1116a: arp_cache_insert adversarial battery + earn cmd.fault.verb.ok on FAULT row and contained==total
    BOOT_SELFTEST ST_VFS                 ; C8 (1008): VFS write/read-back over block layer
    call filmstrip_capture_storage       ; checkpoint 1: storage/VFS stack has earned readback
    call filmstrip_capture_net           ; checkpoint 2: the software net stack is already initialized and ready
    call guestfile_declare               ; 1095a2: register GUESTFILE STAT/READAT/KAT over the mounted fs_ops handle
    call fsarm_declare                   ; RCQ-20: register FSARM (owner-signed ext4 write arm)
    call fsown_declare                   ; RCQ-21: register FSOWN/FSOWNSTAT
    call memcon_declare                  ; common headless/GUI OWNER MUTATE declaration
    call app_bundle_declare              ; APP (EXTENSION) + APPKEY (SOVEREIGN_CONTROL), enrolled-owner trust
    call app_install_declare             ; owner console APPINSTALL, opens the decision card only
    call app_isolation_declare
    call app_ingress_declare             ; owner console APPSCRIPT, signed script staging only
    ; --- M-usb (1031): xHCI controller bring-up + USB device-enumeration seam. Needs
    ;     PCI(pci_selftest)+HAL(hal_init) above + DMA(dma_selftest) + command registry.
    ;     xhci brings up the controller (-> xhci.controller.up) + registers behind the
    ;     enum seam; usb_enum_selftest registers usb_nulldev + enumerates ALL controllers
    ;     (-> usb.enum.device / usb.descriptor.read, or the documented skip line); then the
    ;     USBLIST/USBDESC observability verbs register over the seam. ---
    BOOT_PREPIXEL_STAMP 2
    BOOT_SELFTEST ST_XHCI
    BOOT_DEVICE_STAMP 0
    BOOT_SELFTEST ST_USB_ENUM
    BOOT_DEVICE_STAMP 1
    call command_usb_register            ; 1031: register USBLIST/USBDESC (additive, no registry-core edit)
    call i2c_hid_dell_witness            ; exact DELL0816+PNP0C50 and 8086:9D61 route only
    BOOT_DEVICE_STAMP 2
    call ax88179_selftest                 ; ASIX AX88179 USB-GbE: post-enum netdev bind (degrade-never-wedge; metal-only; vendor driver probes BEFORE the class driver: the AX88179 also exposes a CDC-ECM config)
    call ax88179b_selftest                ; exact newer0200 profile, checked controls and SS companions
    call cdc_ecm_selftest                 ; USB CDC-ECM Ethernet: post-enum netdev bind (degrade-never-wedge; TASK_20260906)
    call cdc_ncm_selftest                 ; USB CDC-NCM Ethernet: class driver after ax88179/cdc_ecm (RCQ-10; all-or-nothing bind)
    BOOT_DEVICE_STAMP 3
%ifdef PAOS_LAB_EP0_PROBE
    call usb_ep0_lab_probe               ; lab: post-init EP0 GET_DESCRIPTOR + STALL-recovery probe (hub packet 0006)
%endif
%if !PAOS_PUBLIC_BUILD
    call airlock_declare                 ; 1316: AIRLOCKSTATUS/AIRLOCKFILE; FAULTINJ xhci uses real containment
%endif
    call command_compat_init             ; 2908: retained PCI/GOP/block/xHCI snapshot + CPUID-only KAT
    BOOT_PREPIXEL_STAMP 3

    ; The native NIC MAC/rings/BOUND claim must precede IOMMU coverage proof.
    ; PHY negotiation was kicked at P5; the bounded carrier wait remains P8.
    call e1000e_hw_prepare
    BOOT_DEVICE_STAMP 4
    ; RCQ-18: the earliest shared floor with storage, auth and native DMA ready.
    call boot_guest_foundation_init
    BOOT_PREPIXEL_STAMP 4
    call hv_linux_boot_start             ; signed normal boot only; no prompt claim

    ; --- L3 dev/input (1016b, qemu rung): PS/2 keyboard (IRQ1) + mouse (IRQ12) input floor.
    ;     Installs the IRQ1/IRQ12 handlers (IDT built by core/idt, PIC remapped + sti by
    ;     core/time timer_init), enables the 8042 aux device, then sits in a BOUNDED poll
    ;     loop content-grading the harness-injected input: keyboard.input fires only when
    ;     the QMP send-key 'down' (SET-1 make 0x50) lands in the scancode ring; mouse.input
    ;     fires only when the 6 input-send-event relative motions accumulate to dx=+144.
    ;     Emits keyboard.irq/keyboard.input/mouse.driver/mouse.input. Runs LAST so every core
    ;     self-test above is green before device IRQs are enabled. Degrade-dont-crash: no
    ;     8042 -> bounded timeout -> logged skip, boot continues. The bare-metal
    ;     KBINJ/MOUSEINJ UDP round-trip (KBDBUF/MOUSESTAT on .50) is 1016 (needs 1010). ---

    ; Task2505 selects presentation only after the shared core, storage, USB,
    ; command/auth registry, and device services above are live. CLI skips the
    ; desktop/window group; it does not select a different kernel or boot path.
    call bm_face_retire                 ; final GUI/CLI now owns every framebuffer write
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .gui_presentation_floor
    call ps2_input_selftest
    call session_shell_init
    call headless_cli_declare
    call cons_declare
    call headless_cli_init
    jmp  .presentation_p7_ready

.gui_presentation_floor:
    ; --- L6 gui (1016, qemu rung): the M6 GUI substrate FLOOR. Runs post-GOP +
    ;     post-paging (fb window mapped RW+NX) and BEFORE ps2_input_selftest so
    ;     the desktop/windows are on-screen when the cursor sprite (drawn by the
    ;     input selftest after the injected motion) lands on top. Paints desktop
    ;     bg + fb primitives + double-buffer/dirty-rect present + taskbar clock +
    ;     the two verify_gui-sampled windows (w/ open animation) + DPMS tickle +
    ;     flicker sample. Emits the M6 GUI markers; degrades cleanly with no GOP. ---
    BOOT_SELFTEST ST_GUI_COMPOSITOR
    call filmstrip_capture_desktop       ; checkpoint 3: first complete P7 desktop paint
    BOOT_SELFTEST ST_FILMSTRIP            ; synthetic capture -> chunk reassembly -> shared crc32 KAT

.presentation_p7_ready:
    call hv_linux_boot_poll              ; another clean vCPU slice while desktop starts
    ; ========================================================================
    ; 2316 P7/P8 HONEST SPLIT — sample and announce interactive readiness only
    ; after either the first real desktop paint or the headless login paint.
    ; The registry and serial control path are already live here. The secondary
    ; QEMU KAT retains its ordering contract: P7 is sampled before P8 warming.
    ; ========================================================================
    rdtsc                                ; RCQ-32: raw P7 stamp (BG6 for CLI presentation)
    shl  rdx, 32
    or   rax, rdx
    mov  [rel boot_p7_tsc], rax
    call boot_ms_now                     ; RAX = ms since boot_tsc_start (0 if TSC uncalibrated)
    mov  [rel boot_p7_ms], rax
    mov  byte [rel boot_p7_reached], 1
    imul rax, rax, 1000                  ; ms -> us (KAT precision is not the deliverable)
    mov  [rel boot_p7_us], rax
    lea  rdi, [rel str_boot_kat_pre]
    call serial_string
    mov  rdi, [rel boot_p7_us]
    lea  rsi, [rel bootreport_numbuf]
    call fmt_dec
    lea  rdi, [rel bootreport_numbuf]
    call serial_string
    lea  rdi, [rel str_boot_kat_post]    ; " deferred=1\r\n"
    call serial_string
    lea  rdi, [rel str_p7_interactive]
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .p7_report
    lea  rdi, [rel str_p7_cli_interactive]
.p7_report:
    call serial_string
    ; msi-b70 (root 18:35 (3)): P7 no longer claims "painted". It reports what reached the
    ; scanout, the same DISPLAY verdict STATUS gives. A locked boot holds every present until
    ; the sign-in surface composes (after P7), so DISPLAY=suppressed here is the truth; the
    ; LOGINBOOT line carries the verdict after the first sign-in paint. Tokens unchanged.
    call lock_screen_display_serial
    lea  rdi, [rel str_p7_tail]
    call serial_string
    ; Seal the normal lean queue without a boot-path drain. P8/runtime output
    ; remains FIFO-owned until bounded idle polls physically empty the queue.
    ; Critical phase/fault/backpressure boundaries retain synchronous flushing.
    call serial_deferred_finish
    ; --- P8 warming begins only after the truthful P7 paint boundary. ---
    mov  byte [rel boot_p8_warming], 1
    mov  byte [rel boot_nic_state], NIC_ST_WARMING
    lea  rdi, [rel str_p8_warming]
    call serial_string
    cmp  byte [rel net_required], 0
    je   .net_gate_not_armed
    lea  rdi, [rel str_net_health_gate_armed]
    call serial_string
.net_gate_not_armed:

    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .presentation_group_done

    ; --- 1317 tournament (metal-perf): kmalloc the off-screen fb_fill_rect bench
    ;     scratch + run the KAT (elected chunked fill vs naive reference: correct,
    ;     no overrun, they agree) -> earns tourn.fb_fill_rect.kat. Runs after the
    ;     compositor so the desktop bg is already down (the KAT's just-outside
    ;     sentinel pixels sit on painted background). PERF fb_fill_rect /
    ;     fb_fill_rect_ref are read over :9997 (registered by hp_perf_declare). ---
    call fb_fill_rect_declare
    ; --- C17 (1017) chat tile: the 2nd app window through the C16 floor — window
    ;     TABLE (state/geometry/title per slot) + the chat widget (8x16 glyph text,
    ;     1-turn local-model chat w/ honest offline degrade) + its boot self-turn.
    ;     Runs right after the floor paint so the tile lands on the fresh desktop;
    ;     chat_declare registers the 7 WM/chat verbs through the ONE 1077 registry. ---
    call chat_app_init
    call chat_declare
    ; --- C-1064 desktop window management: register the WM-geometry verbs (RAISE/
    ;     WINNEW/WINMOVE/WINRESIZE/WINGEOM/ALTTAB/FOCUSED) through the ONE registry,
    ;     then boot-exercise raise/move/resize/alttab on a scratch slot to EARN the
    ;     four wm.* markers (the scratch slot is freed afterward -> the boot desktop
    ;     stays A/B/chat, verify_gui-clean). ---
    call wmx_declare
    BOOT_SELFTEST ST_WMX
    ; --- C-1105 desktop SESSION RESTORE: register WINOPEN/WINLIST/WINCLOSE/SESSSAVE/
    ;     SESSINFO through the ONE registry; QEMU build-gate the persist write+readback+
    ;     re-parse path (desktop.session.persist/restored, throwaway namespace).
    ;     The session shell later observes/caches the document while locked and
    ;     re-opens its windows only after authenticate_bind crosses the login gate.
    ;     After wmx_selftest (needs the wm_* table + fb + free slots 3..7). ---
    call session_declare
    BOOT_SELFTEST ST_SESSION_PERSIST
    ; --- 1110/F1 widget/ELEMENT library: register button+textfield+label through the ONE
    ;     type vtable + draw a demo of each (shared primitives, wm slot 0) ->
    ;     ui.widget.library; then register the element verbs (WIDGETTYPES/NEW/
    ;     SET/GET/LIST + generated CATALOG) through the ONE 1077 registry ->
    ;     ui.widget.registry. After chat_app_init: widgets attach to its wm_*
    ;     slot table (geometry read live per draw). ---
    call wgt_library_init
    call wgt_f2_register_types
    call wgt_declare
    ; --- F1 (2110): repair the orphaned input observability verbs, initialize
    ;     the ONE pointer dispatcher, then replace A/B/chat visual scaffolding
    ;     with three overlapping API-only kit windows. Session replay follows
    ;     and skips restore_class=always demo windows by construction. ---
    call app_widget_init               ; guest widget text: NULL refuses until here
    call snapshot_declare              ; Peter87189 finite native gui.read command
    call f1_ladder_activate
    call form_loader_declare
    call netmon_form_declare
    BOOT_SELFTEST ST_FORM_LOADER
    call form_cadence_live_init
    call gui_declare
    call gui_dpms_declare               ; RCQ-27 L3: DPMS [BLANK|WAKE] (owner-signed)
    call command_hook_declare           ; RCQ-15: HOOK <op> <edge>[:<inst>] (public; native authority)
    call hook_gui_edges_declare         ; RCQ-15 S1: term, widget, dpms edges
    call hook_svc_edges_declare         ; RCQ-15 S2: fs, fsjob, net, guest, job edges
    call hook_dev_edges_declare         ; RCQ-15 S3: usb, aer, pci, backlight, session edges
    call hook_hw_edge_declare           ; RCQ-29: hw edge (COMPAT HW, the hardware report)
    call hook_state_edges_declare       ; RCQ-15 S4: netcheck, ntp, dns, tcp, ssh, idle edges
    call hook_desk_edges_declare        ; RCQ-15 S5/S6: clock, taskbar, lock, wallpaper, clipboard, window edges
    call hook_cognition_edges_declare   ; cached MODELKAT; native registry gate stays authoritative
    call hook_console_edge_declare      ; read-only CONS_LIST inventory; native owner gate
    call hook_image_edge_declare        ; built-in image service, native command gates
    call hook_partition_edge_declare    ; selected-volume PARTLS; native authority
    call hook_ntfsstate_edge_declare    ; saved NTFS selection; native read authority
    call hook_classifier_edge_declare   ; typed native classifier lifecycle, no new authority
    call hook_forms_edge_declare        ; read-only current native FORMLIST inventory
    call hook_forminfo_edge_declare     ; native FORMINFO read-only chunks
    call hook_formload_edge_declare     ; native FORMLOAD open, original mutation gate
    call hook_display_edge_declare      ; native RESINFO/RESMODES read-only observations
    call card_declare                   ; RCQ-40 J2a: CARDPROPOSE/CARDSTAT/CARDCANCEL/AITAINT (+ lab CARDPROBE)
%if !PAOS_PUBLIC_BUILD
    call household_declare              ; RC household voice principal: HHMARK/HHMARKS, generation 1 (marks saved=boot)
%endif
    call clock_prefs_load               ; RCQ-17: the saved display zone (ST_PRINCIPAL made the machine secret)
    call lang_prefs_load                ; RCQ-38 R0: the saved language (same machine secret; English on any failure)
    call kbd_prefs_load                 ; RCQ-38 L2: the saved keyboard layout, in force before the sign-in form (en-US on any failure)
    call config_prefs_load              ; T5-14: valid provisioned DATA preferences override legacy NVRAM, before locale/sign-in
    call idle_prefs_load                ; RC-lock-screen: the owner's saved IDLELOCK value (the 600 s default on any failure)
    call history_cfg_load               ; RC-history H1: the saved history settings (same machine secret; off on any failure)
    call wm_pointer_init
    ; Physical input is available to the sign-in form. The two workspace
    ; textfields and their routing KAT are created after the session bind.
    call ps2_input_selftest
    call res_pack_boot                  ; RCQ-38 R1: bind a validated pack for the saved language, else English
    call lock_screen_init               ; compose/register before the sole gate decides boot policy
    call lock_screen_sync               ; render the locked floor before either policy transition
    call session_shell_init             ; SS-1 owns locked boot and post-bind restore
    call headless_cli_declare            ; same persistent target verb/KAT on the GUI front end
    call lock_screen_sync
    call lock_screen_desktop_start       ; dev policy only; default remains locked
    BOOT_SELFTEST ST_WINTREE
    ; GUI rung 0: byte-layout KAT for the owner-signed command-painted panel.
    BOOT_SELFTEST ST_LIVENESS_PANEL
    ; Boot audit item 3 (root 2026-10-17 17:53:44): the diagnostic badge is never painted over
    ; the sign-in. The only badge paint is the early one after EBS; the first composed present
    ; covers it. The 1094 re-assert that used to sit here (badge + present after the sign-in
    ; was composed) is gone; the wire beacon and LOCKSTATE badge_* carry the nonce instead.
.presentation_group_done:
    call hv_linux_boot_poll              ; sign-in/input are now composed
    ; GOP mode discovery is a shared service projection, not desktop startup.
    ; Keep it present in both GUI and CLI registries.
    call gres_declare
    C3WD_EDGE PBM_INIT_STAGE_P5, PBM_INIT_TRANSITION_COMPLETED

    ; --- C22 ladder-compose STRETCH (1093): the C6 (1006) capability/LAPIC seam.
    ;     Placed DEAD LAST (after every PIT/preempt/PS-2 IRQ-dependent selftest has
    ;     finished) because apic_init arms the LAPIC periodic timer — documented
    ;     conflict risk with the existing PIT IRQ0 path. Emits cap.mmio.enforced +
    ;     cap.violation.blocked. If this destabilizes the boot, back out the call +
    ;     the bus/irq.asm %include and file a NEEDS_INVESTIGATION for the timer conflict. ---
    BOOT_SELFTEST ST_APIC_CAP            ; security capability/LAPIC floor
%if !PAOS_PUBLIC_BUILD
    BOOT_SELFTEST ST_PMOD_FLOOR          ; bounded signature/Merkle/native-format proof
    BOOT_SELFTEST ST_PMOD_FULL           ; TRIAL/FULL: includes the 500 ms EB-FE negative
    BOOT_SELFTEST ST_SCHED_POST_PMOD
%endif

    ; PMOD's earned negative KAT executes EB FE until its own 500 ms TSC-deadline
    ; watchdog contains it.  That intentional, locally recovered wait is not a
    ; PaOS software stop and must not consume P6's separate 5000 ms mandatory
    ; update budget.  Until PMOD returns, durable P5 COMPLETED plus Manager BIP
    ; truthfully identifies the last-good boundary; P6 starts at its real commit.
    C3WD_EDGE PBM_INIT_STAGE_P6, PBM_INIT_TRANSITION_STARTING

    ; --- C3 (1014) boot-canon COMMIT (P6): every boot + core/device self-test above
    ;     passed, so promote this keep trial->good — write the confirmed magic + reset
    ;     the CMOS trial counter to 0 (a keep that crashed before reaching this point
    ;     would boot next in an un-confirmed 'trial' state, and after AB_MAX_TRIALS
    ;     no-good boots the state machine reads FALLBACK = auto-rollback). Emits
    ;     boot.ab.committed. AB_STATE now reads CONFIRMED, AB_COUNTER reads 0. ---
    call boot_ab_commit
    BOOT_SELFTEST ST_SERIAL_EQUIVALENCE
    BOOT_SELFTEST ST_TIMELINE_ORDERING
    ; This is the final TRIAL_ONLY row on the boot path.  Publish the honest
    ; class/count before P8's unrelated heavy tail so the P7 result cannot be
    ; lost behind a later device/domain stall.
    call boot_budget_emit_result
    call native_driver_report           ; policy/counters only, not a compatibility PASS
    call diag_mark_boot_healthy          ; successful P6->P7 boundary; records remain retained
    C3WD_EDGE PBM_INIT_STAGE_P6, PBM_INIT_TRANSITION_COMPLETED
    C3WD_EDGE PBM_INIT_STAGE_P7, PBM_INIT_TRANSITION_STARTING

    ; --- 1068 BOOT-REPORT INSTRUMENT: capture boot_tsc_end at the interactive-ready
    ;     point (every selftest above is done; we are about to enter the live command
    ;     idle loop) and compute BOOT_MS = (end-start)/tsc_khz. This is the rework's
    ;     missing boot-time measurement surface — the truthful "how long did you take
    ;     to boot?" instrument (contract 1068, needed by 1021 crucible_vs_monolith).
    ;     Emitted as a serial marker so it is verifiable over the LIVE bare-metal
    ;     serial channel (/dev/ttyUSB0, 1078) AND in QEMU — NO NIC needed. The
    ;     BOOTREPORT verb (svc/command.asm) reports the SAME BOOT_MS + HEAP_MB through
    ;     the 1077 registry, reachable by every live projection (serial now; UDP :9997
    ;     once the live NIC RX/TX lands, 1029/1030). Writes land in in-image data that
    ;     our page tables map RW (same region the command registry writes post-paging). ---
    rdtsc                                ; EDX:EAX = TSC at interactive-ready
    shl  rdx, 32
    or   rax, rdx
    mov  [rel boot_tsc_end], rax
    push rdi
    mov  rdi, rax
    call boot_clock_boot_ms              ; checked coherent snapshot; legacy invalid remains0
    pop  rdi
    mov  [rel boot_ms], rax
.boot_ms_done:
    mov  rax, [rel heap_size]            ; boot/paging.asm heap region size (bytes)
    shr  rax, 20                         ; -> MB
    mov  [rel heap_mb], rax
    lea  rdi, [rel str_bootreport_pre]   ; "[PAOS64] P4 boot-report: BOOT_MS="
    call serial_string
    mov  rdi, [rel boot_ms]
    lea  rsi, [rel bootreport_numbuf]
    call fmt_dec                         ; the ONE canonical decimal formatter (G1)
    lea  rdi, [rel bootreport_numbuf]
    call serial_string
    lea  rdi, [rel str_bootreport_mid]   ; " HEAP_MB="
    call serial_string
    mov  rdi, [rel heap_mb]
    lea  rsi, [rel bootreport_numbuf]
    call fmt_dec
    lea  rdi, [rel bootreport_numbuf]
    call serial_string
    lea  rdi, [rel str_bootreport_post]  ; " [boot.report.ready]\r\n"
    call serial_string

    ; --- C3-live (1099): bind the UDP :9997 command surface LAST, immediately before
    ;     the idle loop that pumps it. The surface cannot ANSWER until command_udp_poll
    ;     runs (below), so firing net.udp.surface.up here — right before .halt — is the
    ;     honest "the box is now live on the wire" point (no dead gap where the marker
    ;     is up but boot's slow tail still starves the RX pump). boot_ms/heap_mb are
    ;     already computed above, so replies carry them. ---
    ; --- 1050 GOVERNOR P7 relax: boot is complete (every selftest done, about to enter
    ;     the interactive idle loop) — drop the boot-sprint to the quiet balanced policy
    ;     (min=lowest max=highest EPP=0x80): cool + snappy-on-demand. -> gov.sprint ---
    call gov_relax
    C3WD_EDGE PBM_INIT_STAGE_P7, PBM_INIT_TRANSITION_COMPLETED
    C3WD_EDGE PBM_INIT_STAGE_P8, PBM_INIT_TRANSITION_STARTING

    ; Foundation was initialized before presentation. This P8 marker only
    ; publishes phase readiness; the actual foundation timestamp stays early.
    mov  byte [rel boot_p8_ready_any], 1
    lea  rdi, [rel str_p8_ready_hv]
    call serial_string

    ; --- P8 NIC warming: observe carrier over the pre-foundation rings. PHY
    ;     negotiation started at P5; its bounded wait stays AFTER P7 first-paint.
    ;     Its bounded link poll is P8 (P7 already fired); a late/never link is caught
    ;     non-blocking by boot_p8_nic_watch in the .halt loop below. ---
    BOOT_NATIVE_COST_BEGIN 1
    call e1000e_hw_bringup               ; carrier observation; existing MAC/rings/claim stay intact
    BOOT_NATIVE_COST_END 1
    ; A required native path with no usable MAC/rings cannot become READY.
    ; Resolve absence now; an armed NIC remains WARMING for late autoneg.
    cmp  byte [rel net_required], 0
    je   .net_presence_resolved
    cmp  byte [rel e1000e_mac_ok], 1
    jne  .net_check_other_native         ; Intel NIC absent -> is another NATIVE member bound?
    cmp  byte [rel e1000e_rings_ok], 1
    je   .net_presence_resolved
    jmp  .net_absent_parked              ; Intel NIC present but rings failed -> park (unchanged)
.net_check_other_native:
    ; A present native member may still be DEGRADED solely for link negotiation.
    ; Keep HEALTH_OK or LINK_WAIT/non-ABSENT members WARMING so the existing UDP
    ; re-probe can promote them and boot_p8_nic_watch can earn READY on live link.
    ; Absent, DEAD, non-link failures and loopnet/domain relays still cannot count.
    call netdev_has_native_present
    test eax, eax
    jnz  .net_presence_resolved
.net_absent_parked:
    mov  byte [rel boot_nic_state], NIC_ST_PARKED
    HP_PARKED_ORIGIN 1             ; first initial required-native rejection
    PW_EDGE 0,1                    ; initial required-native presence/rings refusal
.net_presence_resolved:
    ; RCQ-29: one sweep, one [hw.report] line per class.  Here, after the deferred
    ; e1000e bring-up (the last PCI driver to claim): earlier it would print the
    ; NIC as driver=none; after P7, so never in first paint's time.
    call hw_report_boot_log
    mov  edi, BOOT_SETTLE_CENSUS          ; settled: device census swept (report-only)
    mov  esi, BOOT_SETTLE_COMPLETE
    call boot_settle_mark
    call command_udp_init                ; -> net.udp.surface.up / net.eth.rx.loop / net.ip.configured (+ gratuitous ARP)
%ifidn RCQ_NET_RETURN_DIAG,1
    call netreturn_init_capture
%endif
    call scap_init                       ; 1108: screenshot server surface (UDP :9996 fb dump) -> scap.server.ready (earned on fb_base)
    ; --- 1022 net_arp_cache_seam: exercise the LIVE ARP resolver over the SAME functions
    ;     that handle real inbound traffic (request-TX / reply-ingest+readback / who-has
    ;     answer / table-ready), earning the four arp.* wire markers. NIC-absent -> no
    ;     markers, boot continues (degrade). Live wire round-trip is bare-metal probe-graded. ---
    call udp_arp_wire_exercise           ; -> arp.request.tx / arp.reply.rx / arp.reply.tx / arp.cache.table
    call boot_ms_now                     ; P8 NIC warming start (park-budget clock)
    mov  [rel boot_nic_warm_start_ms], rax
    C3WD_EDGE PBM_INIT_STAGE_P8, PBM_INIT_TRANSITION_COMPLETED

    ; --- M16-cognition (1061b): register MODELRUN/MODELOUT/MODELKAT, stream the
    ;     descriptor-bound MODEL.PXG when present, and earn the numeric KAT before
    ;     strong health is published.  Keep the potentially long disk+SHA+forward
    ;     work outside P8's 30-second Manager checkpoint budget: the P8 edge above
    ;     measures its declared machine-foundation work, while strong health below
    ;     still cannot publish until cognition has returned. Missing/invalid model
    ;     remains an honest online tile with present=0 and no inference marker. ---
    call cog_declare
    ; PMOD is intentionally absent in the QEMU profile, so exercise the pure
    ; capability-mask predicate directly rather than treating PMOD absence as a
    ; capability failure. A present PMOD may already have emitted the same row.
%if !PAOS_PUBLIC_BUILD
    cmp  byte [rel pmod_cap_blocked], 1
    je   .security_capability_ready
%endif
%if PAOS_PUBLIC_BUILD
    call pmod_watchdog_init
%endif
    BOOT_SELFTEST ST_CAPABILITY_FLOOR
.security_capability_ready:
    BOOT_SELFTEST ST_SECURITY_TRUTH       ; 3019: six earned PASS rows or explicit FAIL alternatives
    BOOT_SELFTEST ST_VERDICT_BIJECTION    ; 2301: final bijection after last boot-time selftest
    ; Long boot work is not repaint jitter. Start the one cadence registry's
    ; resident measurements at the exact interactive handoff.
    call cadence_live_rearm

    ; --- Boot Manager v2 STRONG HEALTH checkpoint. This is intentionally later
    ;     than the legacy A/B confirmation: all boot self-tests, P7 desktop,
    ;     P8 guest foundation, device bring-up, and both command surfaces have
    ;     returned, and the next instruction enters the live idle/poll loop.
    ;     Direct, Safe, Rescue, and old read-only handoffs no-op in the publisher.
    ;     A runtime-variable failure leaves BIP set, so the next Manager remains
    ;     conservative instead of treating a partial boot as healthy. ---
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .gui_boot_report
    call headless_cli_boot_report
    jmp  .boot_report_done
.gui_boot_report:
    call lock_screen_boot_report        ; late live state, after all boot writers
.boot_report_done:
    call software_stop_publish_strong_health
    call smp_bsp_tick_handover           ; RC power I2: one BSP tick after every boot selftest
%ifidn RCQ_NET_RETURN_DIAG,1
    call netreturn_boot_publish
%endif

    call lab_return_init                 ; once, at live handoff; explicit lab opt-in only
    call recovery_boot_init              ; signed NEXT grant only; no implicit healthy-use timer
    call diag_service_failure_begin     ; exclude initial boot tests; report prior service record
    call diag_device_failure_begin       ; read prior diagnostic/exclude initial HDA snapshots
    call boot_v2_maintenance_events_import ; validated archive/refusal records only; no health authority
    call maintenance_crash_import        ; finite prior PBCR import, explicit truncated identity

; DHCP client gap, measurement only (rc-boot plan 2026-10-17 21:12:55 step 2; core/idle_prof.asm): one
; IDLE_PROF_MARK per owner call, ids in loop order, 0 = pass start. A mark preserves flags and registers.
IDLE_PROF_OWNERS equ 48
%macro IDLE_PROF_MARK 1
%if %1 >= IDLE_PROF_OWNERS
%error "IDLE_PROF_MARK id out of range"
%endif
    push rdi
    mov  edi, %1
    call idle_prof_mark
    pop  rdi
%endmacro
.halt:
    cmp  byte [rel reset_wipe_done], 0
    jne  reset_wipe_halt                 ; a CPU wiped the keys (fatal fault): PaOS stops (srcreview R2)
%if PAOS_NORMAL_DEADMAN_MS
    call boot_d4_deadman_live           ; only the real completed idle sweep renews
%endif
    IDLE_PROF_MARK 0                     ; no telemetry/report calls after a completed wipe
    IDLE_PROF_MARK 1
    call sched_interactive_begin         ; snapshot before any input consumer
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .presentation_synced
    IDLE_PROF_MARK 2
    call lock_screen_sync                ; reconcile before any input is consumed
    IDLE_PROF_MARK 3
    call lock_screen_desktop_start       ; deferred first-login creation outside transport frames
.presentation_synced:
    IDLE_PROF_MARK 4
    call command_serial_poll             ; 1078: drain COM1 RBR -> registry dispatch (live post-boot serial command channel)
    IDLE_PROF_MARK 5
    call serial_deferred_finish          ; retry a contended seal; idempotent once sealed/complete
    IDLE_PROF_MARK 6
    call serial_drain_poll               ; non-blocking TX drain; preserves boot byte order without THRE spinning
    IDLE_PROF_MARK 7
    call virtio_domain_autoboot_tick      ; 1013b: no healthy native netdev -> local domain launch
    IDLE_PROF_MARK 8
%ifidn RCQ_SERVICE_PROGRESS_DIAG,1
    call service_progress_enter
%endif
    PW_EDGE 2
    call ax88179_lifecycle_poll           ; class-owned exact root retirement/fresh rebind
    call ax88179b_lifecycle_poll          ; same owner as native TX/RX/link
    call command_udp_poll                ; 1099: drain the e1000e RX ring -> eth/UDP -> registry dispatch (live UDP :9997 command channel)
    call scap_poll                       ; one paced screenshot packet after RX unwinds
    PW_EDGE 3
%ifidn RCQ_SERVICE_PROGRESS_DIAG,1
    call service_progress_exit
%endif
%ifidn RCQ_NET_RETURN_DIAG,1
    call netreturn_poll_exit
%endif
    IDLE_PROF_MARK 9
    call summon_palette_flush_deferred   ; erase a closed overlay only after command/input frames unwind
%ifidn RCQ37_VIDEO_BUILT,1
    IDLE_PROF_MARK 10
    call video_player_poll               ; bounded owner, transport frames unwound
    IDLE_PROF_MARK 11
    call video_file_poll                 ; explicit file producer, one foreground stage
    IDLE_PROF_MARK 12
    call command_video_playback_tick      ; one bounded preparation/retirement action
%endif
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    IDLE_PROF_MARK 13
    call media_guest_poll                ; RCQ-37 G3b: one bounded media-guest owner turn
%endif
%endif
    IDLE_PROF_MARK 14
    call wmx_draw_flush_deferred         ; compose registry-triggered GUI state after bounded command frames unwind
    inc  qword [rel boot_idle_compositor_ticks] ; G9: the compositor path ran in this idle tick
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .gui_console_tick
    IDLE_PROF_MARK 15
    call headless_cli_tick
    jmp  .login_input
.gui_console_tick:
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .login_input
    cmp  byte [rel lock_desktop_created], 1
    jne  .login_input                   ; AUTHLOGIN may have returned in this frame
    IDLE_PROF_MARK 16
    call console_app_tick                ; 2152: only a bound session owns the console
.login_input:
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .presentation_idle_done         ; headless_cli_tick already drained the shared ring
    IDLE_PROF_MARK 17
    call gui_input_route_tick            ; 2151: bounded idle-context keyboard consumer
    IDLE_PROF_MARK 18
    call ps2_pointer_pump                ; 2026-09-08: the ONE GUI context drains physical pointer input
    call lock_fade_tick                  ; bounded presentation after both input consumers
.presentation_idle_done:
    call command_idle_service_tick
    IDLE_PROF_MARK 19
    call ps2_input_pending
    mov  edi, eax
    IDLE_PROF_MARK 20
    call sched_interactive_end           ; preserve priority until bounded queues drain
    IDLE_PROF_MARK 21
    call cog_ai_intent_tick              ; native gestures -> intent only, after input
    IDLE_PROF_MARK 22
    call sched_preempt_post_pmod_poll     ; deferred runtime-PMOD KAT, after the reply-producing poll frame
    IDLE_PROF_MARK 23
    call sched_watchdog_safe_frame        ; claim/reap only after IRQ/IPI frames have returned
    IDLE_PROF_MARK 24
    call vtd_deadman_check               ; bounded secondary ownership cannot outlive its lease
    IDLE_PROF_MARK 25
    call terminal_app_tick               ; 0009: Terminal windows (blink, repaint, title, close); no-op without one
    IDLE_PROF_MARK 26
    call start_programs_tick             ; 0010: a confirmed/cancelled power dialog acts here, after the input path unwound
    IDLE_PROF_MARK 27
    call card_surface_tick               ; RCQ-40 J2b: the owner's Confirm/Deny of an action card acts here, at depth 0
    call app_package_card_tick           ; close stale disclosure, bounded page navigation
    call adopt_confirm_tick
    call format_confirm_tick
    call app_confirm_tick               ; frozen guest approval, after input frames unwind
    call terminal_consent_tick          ; Terminal consent effects after input unwinds
    call gbr_tick                        ; owner-armed guest bundle lines, one compare unarmed
    call app_install_tick                ; offer read, idle decision effects
    call account_local_tick              ; bounded native account decision at depth0
    call app_isolation_tick
    call app_ingress_tick                ; bounded signed publication before desktop intent
    call app_launcher_tick              ; spend desktop launch intent at depth0 only
    call app_widget_tick                 ; guest widget SET budget for this tick
    call app_launch_flow_tick            ; sole original appVM bounded idle turn
    call app_remove_tick                 ; one confirmed removal phase at depth0
    IDLE_PROF_MARK 28
    call power_events_tick               ; RCQ-27: EC battery/AC + fixed power button (one compare without a descriptor)
    IDLE_PROF_MARK 29
    call session_idle_tick               ; RC-lock-screen: owner idle timeout (human input only) -> session_shell_lock
    IDLE_PROF_MARK 30
    call power_remote_shutdown_tick      ; RCQ-27: an accepted owner-signed remote SHUTDOWN, after its reply frame
    call recovery_controller_tick        ; signed policy claim, after all request frames
    test eax,eax
    jz .recovery_controller_done
    call power_recovery_controller       ; one quiesce/route/reset attempt or terminal refusal
.recovery_controller_done:
    call lab_return_tick                 ; request/driver frames unwound; one claim only
    test eax, eax
    jz .lab_return_done
    call power_lab_return                ; quiesce refusal resets nothing
.lab_return_done:
    IDLE_PROF_MARK 31
    call smpbench_reap_tick              ; SMPBENCH-slot-leak-dos: once per second, free old finished SMPBENCH slots
    IDLE_PROF_MARK 32
    call nd_boot_record_tick             ; spec 0.70: evidence only, never health
    call boot_p8_nic_watch               ; 1051: flip net tile warming->ready when autoneg completes (or park) — non-blocking
    IDLE_PROF_MARK 33
    call software_stop_stability_tick    ; G9: publish the strong health ack only after the stability window (or never)
    IDLE_PROF_MARK 34
    call boot_gates_tick                 ; RCQ-32: stamp BG5b once the publish latch is first seen
    IDLE_PROF_MARK 35
    call udp_boot_beacon_tick            ; 1094: once link is up, broadcast the boot beacon (gARP + UDP :9998, SAME nonce as the GOP badge) + re-beacon ~10s -> [beacon.wire.sent]
    IDLE_PROF_MARK 36
    call arp_cache_age_tick              ; SEC-S7a: age the solicited-only ARP cache (~5 min binding life)
    IDLE_PROF_MARK 37
    call audit_guardian_watch_tick       ; SEC-GA1: Guardian watch tier (shadow, no authority)
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .chat_idle_done
    IDLE_PROF_MARK 38
    call chat_app_tick                   ; 1017: living-tile respawn of a CLOSEd chat window (~8s) — cheap no-op otherwise
.chat_idle_done:
    IDLE_PROF_MARK 39
    call tco_deadman_kick                ; 0011: reload the PCH TCO (a no-op unless armed; at most every 1 s)
    IDLE_PROF_MARK 40
    call cadence_poll                    ; one registry drives clock + attention + netmon live edges
    IDLE_PROF_MARK 41
    call boot_settle_tick                ; settled: storage replay / deferred checks, observed after the sweep step
    call hvw_idle_tick                   ; observe BOOT/session idle before any warm START, no launch
    call diag_service_failure_poll      ; BSP task context; <=1 service failure variable write/boot
    call diag_failure_poll              ; BSP task context; <=1 persistent exhaustion record/boot
    call diag_device_failure_poll        ; read-only HDA snapshot -> one bounded scalar write/boot
    IDLE_PROF_MARK 42
    call sched_yield                     ; resident vCPU and cooperative tasks get a bounded slice
    call memcon_idle                     ; optional CPU scratch after input/session/return and guest yield
    xor edi, edi                        ; BSP is dense logical CPU zero
    call mca_corrected_tick              ; <=1 read-only MCA scan/s on this CPU
    call sched_unified_soak_bsp_service ; existing finite SOAK, one BSP quantum
    test eax, eax
    jnz .halt                           ; service again instead of voluntary HLT
    call scap_pending                   ; finite paced capture needs sweeps, not timer-rate packets
    test eax, eax
    jnz .halt                           ; all input/recovery/network service runs on each pass
    call app_vm_runnable                ; bounded app work gets another full desktop sweep
    test eax,eax
    jnz .halt                           ; preserve input/session/recovery service each pass
    IDLE_PROF_MARK 43
    call smp_bsp_idle_hlt                ; RCQ-27 B1: hlt with residency accounting (STATUS BSP_HLT_*)
    jmp .halt

; Safe Mode deliberately has no timer/scheduler/driver initialization.  Polling
; with PAUSE keeps the serial recovery surface live without depending on an IRQ
; that this profile intentionally did not arm.
.safe_halt:
    call command_serial_poll
    call serial_drain_poll
    pause
    jmp .safe_halt

; ============================================================================
; 2306 boot-budget gate. Callers pass a stable table id in R10D. Each table row
; stores a rel32 callback delta, never an unrelocated static runtime pointer.
; ============================================================================
; Snapshot the same legacy CMOS trial byte used by the P0 logging selector.
; Values 1..5 are the existing crash/trial ladder. Value 6 is the one-boot R6
; first-candidate arm; svc/boot_ab deliberately sanitizes it before publishing
; CRASHES, while this immutable P0 copy remains the current-boot discriminator.
; The shared auth/storage/USB floor is complete before this call. Establish
; native DMA ownership before admitting a guest. dma_init reserves a fresh heap
; pool and retains earlier records; the prepared native NIC records are covered
; before remapping is enabled. Later allocations use the live IOMMU hook. Never
; re-run this foundation while the resident VM is live. Link polling stays P8.
boot_guest_foundation_init:
    BOOT_NATIVE_COST_BEGIN 0
    call hv_ops_init
    BOOT_NATIVE_COST_END 0
    call hv_register_verbs
    call guest_transport_app_init        ; after driver init, before any app prepare/binding
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    call media_guest_register_verb           ; RCQ-37 G3b: GUESTMEDIA, lab-profile images only
%endif
%endif
    call hv_ops_register_verbs
%if !PAOS_PUBLIC_BUILD
    call airlock_register_verbs              ; 1056: AIRSEED/HOSTILE/CANARY/BENIGN/HANG via one registry
%endif
    call guestnet_register_verbs              ; 1109: GUESTNET START/STAT/NONCE/STOP
    call vtd_register_verb                    ; 1012: VTD POLICY/ASSIGN/STAT/RECLAIM/DEADMAN
    call virtio_domain_register_verb          ; 1013b: local DOMAINNET START/STAT/STOP
    BOOT_NATIVE_COST_BEGIN 2
    call vtd_ownership_init
    BOOT_NATIVE_COST_END 2
    ; RCQ-18-AMDVI-S3a: the AMD-Vi counterpart (silent where a DMAR exists). After
    ; vtd_ownership_init, whose dma_iommu_bind(0,0) would otherwise clear its hooks.
    BOOT_NATIVE_COST_BEGIN 3
    call amdvi_ownership_init
    BOOT_NATIVE_COST_END 3
    ; AIRLOCK must finish its canned VM before the resident Linux guest owns VMX.
    BOOT_NATIVE_COST_BEGIN 4
%if !PAOS_PUBLIC_BUILD
    call airlock_init
%endif
    BOOT_NATIVE_COST_END 4
    call boot_ms_now
    mov  [rel boot_hv_foundation_ready_ms], rax
; RCQ32_P8_RAW_BEGIN
    call boot_foundation_stamp           ; raw first arrival before existing ready publication
; RCQ32_P8_RAW_END
    mov  byte [rel boot_hv_foundation_ready], 1
    ret

PAOS_NATIVE_TRACE_CODE 0
PAOS_HEALTH_PROGRESS_CODE
%include "boot/parked_watch_diag_code.inc"

boot_budget_p0_snapshot:
    mov  byte [rel boot_budget_p0_valid], 0
    mov  dil, PBM_CMOS_LEGACY_TRIAL
    call chainload_cmos_rd
    mov  [rel boot_budget_p0_trial], al
    cmp  al, BOOT_BUDGET_TRIAL_ARM
    ja   .done                           ; corrupt CMOS fails open to TRIAL
    mov  byte [rel boot_budget_p0_valid], 1
.done:
    ret

boot_budget_init:
    push rbx
    mov  byte [rel boot_budget_class], BOOT_CLASS_TRIAL
    mov  byte [rel boot_budget_force_full], 0
    mov  byte [rel boot_budget_full_busy], 0
    mov  byte [rel boot_budget_armed_emitted], 0
    mov  byte [rel boot_budget_qemu_fixture], 0
    mov  qword [rel boot_budget_gated], 0
    mov  qword [rel boot_budget_trial_seen], 0
    mov  qword [rel boot_budget_executed], 0
    cmp  byte [rel boot_budget_p0_valid], 1
    jne  .class_ready                    ; unreadable CMOS fails open to TRIAL
    cmp  byte [rel boot_budget_p0_trial], 0
    je   .clean_byte
    cmp  byte [rel boot_budget_p0_trial], BOOT_BUDGET_TRIAL_ARM
    jne  .class_ready                    ; 1..5 = crash/trial ladder: TRIAL class
    ; 6 = the one-boot BOOT LINUX arm.  It exists so the R6 candidate's FIRST
    ; boot runs the full ladder; a healthy round trip that returns the SAME
    ; payload claimed by the CRC-only handoff is not a candidate and must match a BOOT WIN
    ; return (clean byte, CONFIRMED).  Any read/identity doubt stays TRIAL.
    call boot_budget_arm_same_payload
    test eax, eax
    jz   .arm_trial
    call boot_budget_arm_disarm
    jmp  .confirmed
.arm_trial:
    lea  rdi, [rel str_boot_budget_arm_trial]
    call serial_string
    jmp  .class_ready
.clean_byte:
    ; A clean byte proves only that the previous native boot committed.  When
    ; the Manager names this attempt a Trial or unclean, run the full ladder
    ; (root 73326): a first Trial after BOOT WIN or power-off is a candidate.
    call boot_budget_manager_unclean
    test eax, eax
    jz   .confirmed
    lea  rdi, [rel str_boot_budget_manager_trial]
    call serial_string
    jmp  .class_ready
.confirmed:
    mov  byte [rel boot_budget_class], BOOT_CLASS_CONFIRMED
.class_ready:
    ; The global QEMU pre-flight must retain every historic selftest marker and
    ; this contract's TRIAL negative control.  This execution override does not
    ; alter boot_budget_class: that observable remains the P0 CMOS decision.
    mov  eax, 1
    cpuid
    test ecx, 0x80000000
    jz   .done
    mov  byte [rel boot_budget_qemu_fixture], 1
    mov  byte [rel boot_budget_force_full], 1
.done:
    pop  rbx
    ret

boot_budget_emit_armed:
    push rbx
    cmp  byte [rel boot_budget_armed_emitted], 1
    je   .done
    mov  byte [rel boot_budget_armed_emitted], 1
    lea  rdi, [rel str_boot_budget_armed]
    call serial_string
.done:
    pop  rbx
    ret

; The mutable Manager's R6 update path stages Linux without a journal Trial.
; Arm the P0 discriminator before BootNext, and clear it if BootNext cannot be
; proven.  command_bootmenu reaches this wrapper only for its Manager-runtime
; BOOT LINUX path; direct/legacy transitions retain their existing behavior.
; The arm is bound to the exiting payload first (boot_budget_arm_bind_payload)
; so the next P0 can tell the R6 candidate (different payload: TRIAL) from a
; healthy same-payload return (CONFIRMED, the BOOT WIN-equivalent state).
boot_budget_linux_arm_bootnext:
    sub  rsp, 8                         ; preserve Win64 call alignment for UEFI work below
    call boot_budget_arm_bind_payload   ; best effort; an unbound arm stays TRIAL
    mov  dil, PBM_CMOS_LEGACY_TRIAL
    mov  sil, BOOT_BUDGET_TRIAL_ARM
    call chainload_cmos_wr
    mov  dil, PBM_CMOS_LEGACY_TRIAL
    call chainload_cmos_rd
    cmp  al, BOOT_BUDGET_TRIAL_ARM
    jne  .failed
    call chainload_linux_arm_bootnext_impl
    test rax, rax
    jz   .done
    mov  r8, rax
    mov  dil, PBM_CMOS_LEGACY_TRIAL
    xor  esi, esi
    call chainload_cmos_wr
    mov  rax, r8
    add  rsp, 8
    ret
.failed:
    mov  eax, 1
.done:
    add  rsp, 8
    ret

; boot_budget_arm_bind_payload — runtime (post-EBS, runtime code mapped).
; Publish which payload is leaving through the BOOT LINUX arm.  Only a boot that
; earned boot.ab.committed (P6: every selftest passed, trial counter reset) AND
; claims a Manager launch (CRC-only handoff) with a payload digest binds that exact
; SHA-256; every other exit publishes 32 zero bytes, which can never match a
; claimed digest, so its next boot stays TRIAL exactly as before.
; PaOS-namespace NVRAM is NORMAL class (storage gate, PETER 2026-09-30).
; RAX=0 published, 1 not published (the arm then stays unbound or stale; see
; boot_budget_arm_same_payload).  Preserves callee-saved registers.
boot_budget_arm_bind_payload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 48
    lea  rdi, [rel boot_budget_arm_id]
    xor  eax, eax
    mov  ecx, 4
    rep  stosq                           ; default: unbound (all-zero) identity
    cmp  byte [rel ab_m_commit], 1
    jne  .content_ready                  ; never reached P6 commit -> unbound
    cmp  byte [rel pbm_manager_launch], 1
    jne  .content_ready                  ; no Manager-verified digest -> unbound
    lea  rsi, [rel pbm_payload_sha]
    lea  rdi, [rel boot_budget_arm_id]
    mov  ecx, 4
    rep  movsq
.content_ready:
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .fail
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .fail
    lea  rdi, [rel boot_budget_arm_var_guid]
    lea  rsi, [rel boot_budget_arm_var_name]
    xor  edx, edx                        ; SA_INTENT_IMPLICIT: PaOS-namespace -> NORMAL
    lea  rcx, [rel str_boot_budget_arm_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .fail
    lea  rcx, [rel boot_budget_arm_var_name]
    lea  rdx, [rel boot_budget_arm_var_guid]
    mov  r8d, 0x07                       ; NV | BOOTSERVICE | RUNTIME
    mov  r9d, 32
    lea  rax, [rel boot_budget_arm_id]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                    ; EFI_RUNTIME_SERVICES.SetVariable
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; boot_budget_arm_same_payload — PRE-EBS, after the CRC-bound Manager handoff.
; EAX=1 iff this is a healthy (reason=HEALTHY, no journal-Trial flag) Manager
; launch with a non-zero payload digest claimed by the CRC-only handoff and the arm's published
; identity is byte-identical to it.  Every failure (direct launch, non-healthy
; Manager reason, missing/short/foreign-attribute variable, firmware error,
; unbound or different digest) returns 0 and keeps the Task 2306 TRIAL class.  A failed
; publish can leave an older identity behind; that can only match when the
; returning payload is the same one that earlier exited healthy through this arm.
boot_budget_arm_same_payload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 48
    cmp  byte [rel pbm_manager_launch], 1
    jne  .no
    ; Only an ordinary healthy Manager launch may disarm.
    call boot_budget_manager_unclean
    test eax, eax
    jnz  .no
    lea  rbx, [rel pbm_payload_sha]
    xor  edx, edx
    xor  ecx, ecx
.digest_nonzero:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .digest_nonzero
    test dl, dl
    jz   .no
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .no
    mov  qword [rel boot_budget_arm_size], 32
    mov  dword [rel boot_budget_arm_attrs], 0
    lea  rcx, [rel boot_budget_arm_var_name]
    lea  rdx, [rel boot_budget_arm_var_guid]
    lea  r8,  [rel boot_budget_arm_attrs]
    lea  r9,  [rel boot_budget_arm_size]
    lea  rax, [rel boot_budget_arm_seen]
    mov  [rsp + 32], rax
    call [r12 + 0x48]                    ; EFI_RUNTIME_SERVICES.GetVariable
    test rax, rax
    jnz  .no
    cmp  qword [rel boot_budget_arm_size], 32
    jne  .no
    cmp  dword [rel boot_budget_arm_attrs], 0x07
    jne  .no
    lea  rsi, [rel boot_budget_arm_seen]
    xor  ecx, ecx
.compare:
    mov  al, [rsi + rcx]
    cmp  al, [rbx + rcx]
    jne  .no
    inc  ecx
    cmp  ecx, 32
    jb   .compare
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; boot_budget_manager_unclean -> EAX = 1 when the CRC-bound Manager handoff
; (pbm_manager_launch = 1) carries PBM_HF_TRIAL or any reason but HEALTHY.
; Rollback, Safe retry, previous-BIP, invalid-state, owner-request and Trial
; launches are the Manager's own evidence of an unclean or candidate attempt.
; A direct launch returns 0: its pbm_reason/pbm_flags are not CRC-bound.
; Clobbers RAX only.
boot_budget_manager_unclean:
    xor  eax, eax
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out
    cmp  byte [rel pbm_reason], PBM_REASON_HEALTHY
    jne  .unclean
    test byte [rel pbm_flags], PBM_HF_TRIAL
    jz   .out
.unclean:
    mov  eax, 1
.out:
    ret

; boot_budget_arm_disarm — the same-payload return consumes its arm exactly as
; a BOOT WIN return finds the byte: 0x74 = 0.  boot_ab_early's CRASHES value is
; unchanged (it already sanitized 6 to 0), and the adaptive-logging sample is
; re-pointed at the clean byte so presentation matches the BOOT WIN path too.
; boot_budget_p0_trial keeps the raw P0 value as forensic evidence.
boot_budget_arm_disarm:
    push rbx
    mov  dil, PBM_CMOS_LEGACY_TRIAL
    xor  esi, esi
    call chainload_cmos_wr
    mov  byte [rel boot_log_prior_trial], 0
    mov  byte [rel boot_log_prior_valid], 1
    lea  rdi, [rel str_boot_budget_arm_same]
    call serial_string
    pop  rbx
    ret

; Confirmed boots keep this bounded PMOD security floor while the table gates
; the loader's deliberate EB-FE watchdog-negative separately.
%if !PAOS_PUBLIC_BUILD
boot_budget_pmod_floor:
    push rbx
    ; A TRIAL boot (including the QEMU negative control) immediately executes
    ; ST_PMOD_FULL, whose pmod_init repeats these signature/native checks before
    ; the EB-FE watchdog negative.  Do not pay the RSA floor twice.  CONFIRMED
    ; boots skip ST_PMOD_FULL and therefore must execute this bounded floor.
    cmp  byte [rel boot_budget_force_full], 1
    je   .covered_by_full
    cmp  byte [rel boot_budget_class], BOOT_CLASS_TRIAL
    je   .covered_by_full
    lea  rdi, [rel pmod_fixture_diag]
    call pmod_verify_bundle
    test rax, rax
    jnz  .failed
    lea  rdi, [rel pmod_fixture_nonce]
    call pmod_validate_native
    test rax, rax
    jnz  .failed
    lea  rdi, [rel str_pmod_merkle_ok]
    call serial_string
    lea  rdi, [rel str_pmod_sig_ok]
    call serial_string
    xor  eax, eax
    pop  rbx
    ret
.covered_by_full:
    xor  eax, eax
    pop  rbx
    ret
.failed:
    lea  rdi, [rel str_pmod_fail]
    call serial_string
    mov  rax, -1
    pop  rbx
    ret

%endif
; boot_budget_gate(R10D=row id) -> callback result, or zero when gated.
; This is the sole current-class conditional in the boot selftest path.
boot_budget_gate:
    push rbx
    mov  ebx, r10d
    cmp  ebx, BOOT_BUDGET_COUNT
    jae  .bad_id
    lea  rdx, [rel boot_budget_table]
    movzx ecx, byte [rdx + rbx * 8 + 4]
    cmp  ecx, BOOT_BUDGET_TRIAL_ONLY
    jne  .execute
    cmp  byte [rel boot_budget_full_busy], 1
    je   .class_ready                     ; on-demand accounting is per command
    inc  qword [rel boot_budget_trial_seen]
.class_ready:
    cmp  byte [rel boot_budget_force_full], 1
    je   .execute
    cmp  byte [rel boot_budget_class], BOOT_CLASS_TRIAL
    je   .execute
    inc  qword [rel boot_budget_gated]
    xor  eax, eax
    pop  rbx
    ret
.execute:
    movsxd rax, dword [rdx + rbx * 8]
    add  rax, rdx
    call rax
    inc  qword [rel boot_budget_executed]
    pop  rbx
    ret
.bad_id:
    mov  rax, -1
    pop  rbx
    ret

; Re-run every normally gated row through the same dispatcher. ALWAYS rows
; already ran on this confirmed boot and remain in the verdict ledger.
boot_budget_run_full:
    push rbx
    push r12
    push r13
    cmp  byte [rel boot_budget_class], BOOT_CLASS_CONFIRMED
    jne  .refused
    cmp  byte [rel boot_budget_full_busy], 0
    jne  .refused
    ; A pre-existing or newly-created PASS/FAIL conflict makes a content-grade
    ; impossible.  Repeated identical verdicts are idempotent in core/log.
    cmp  byte [rel selftest_verdict_conflict], 0
    jne  .refused
    mov  byte [rel boot_budget_full_busy], 1
    mov  byte [rel boot_budget_force_full], 1
    mov  rax, [rel boot_budget_executed]
    mov  [rel boot_budget_full_start_executed], rax
    mov  eax, [rel selftest_verdict_fails]
    mov  [rel boot_budget_full_start_failures], eax
    mov  dword [rel boot_budget_full_failures], 0
    xor  ebx, ebx
    xor  r12d, r12d
    lea  r13, [rel boot_budget_table]
.next:
    cmp  ebx, BOOT_BUDGET_COUNT
    jae  .complete
    cmp  byte [r13 + rbx * 8 + 4], BOOT_BUDGET_TRIAL_ONLY
    jne  .advance
    mov  r10d, ebx
    call boot_budget_gate
    inc  r12d
.advance:
    inc  ebx
    jmp  .next
.complete:
    mov  byte [rel boot_budget_force_full], 0
    mov  byte [rel boot_budget_full_busy], 0
    mov  rax, [rel boot_budget_executed]
    sub  rax, [rel boot_budget_full_start_executed]
    cmp  rax, r12
    jne  .refused
    mov  edx, [rel selftest_verdict_fails]
    sub  edx, [rel boot_budget_full_start_failures]
    mov  [rel boot_budget_full_failures], edx
    cmp  byte [rel selftest_verdict_conflict], 0
    jne  .conflict
    inc  qword [rel boot_budget_full_runs]
    mov  eax, r12d
    pop  r13
    pop  r12
    pop  rbx
    ret
.conflict:
    inc  dword [rel boot_budget_full_failures]
    inc  qword [rel boot_budget_full_runs]
    mov  eax, r12d
    pop  r13
    pop  r12
    pop  rbx
    ret
.refused:
    mov  eax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; Publish the measured count and immutable P0 class after the boot path's final
; TRIAL_ONLY row.  This witnesses the gate, not unrelated P8 platform verdicts:
; some rows are behind hardware/profile branches, so the proof is actual rows
; seen/skipped rather than the table's static total.
boot_budget_emit_result:
    push rbx
    lea  rdi, [rel str_boot_budget_count]
    call serial_string
    mov  rdi, [rel boot_budget_gated]
    lea  rsi, [rel bootreport_numbuf]
    call fmt_dec
    lea  rdi, [rel bootreport_numbuf]
    call serial_string
    cmp  byte [rel boot_budget_class], BOOT_CLASS_TRIAL
    je   .trial_text
    lea  rdi, [rel str_boot_budget_cls_confirmed]
    jmp  .class_text
.trial_text:
    lea  rdi, [rel str_boot_budget_cls_trial]
.class_text:
    call serial_string
    cmp  qword [rel boot_budget_trial_seen], 0
    je   .fail
    cmp  byte [rel boot_budget_qemu_fixture], 1
    je   .qemu_dual_leg
    cmp  byte [rel boot_budget_class], BOOT_CLASS_TRIAL
    je   .trial
    cmp  qword [rel boot_budget_gated], 0
    je   .fail
    lea  rdi, [rel str_boot_budget_confirmed]
    call serial_string
    jmp  .done
.trial:
    cmp  qword [rel boot_budget_gated], 0
    jne  .fail
    lea  rdi, [rel str_boot_budget_trial]
    call serial_string
    jmp  .done
.qemu_dual_leg:
    ; Main QEMU boot executed the complete TRIAL_ONLY ladder.  Now switch only the gate's
    ; inputs long enough to prove a default row is skipped under CONFIRMED.
    ; Restore every observable counter/class before publishing both fixture
    ; witnesses, so this KAT cannot masquerade as boot accounting.
    cmp  qword [rel boot_budget_gated], 0
    jne  .fail
    mov  rax, [rel boot_budget_gated]
    mov  [rel boot_budget_fixture_saved_gated], rax
    mov  al, [rel boot_budget_class]
    mov  [rel boot_budget_fixture_saved_class], al
    mov  byte [rel boot_budget_full_busy], 1
    mov  byte [rel boot_budget_force_full], 0
    mov  byte [rel boot_budget_class], BOOT_CLASS_CONFIRMED
    mov  r10d, ST_TIMELINE_OVERFLOW
    call boot_budget_gate
    mov  rax, [rel boot_budget_fixture_saved_gated]
    inc  rax
    cmp  [rel boot_budget_gated], rax
    jne  .qemu_restore_fail
    mov  al, [rel boot_budget_fixture_saved_class]
    mov  [rel boot_budget_class], al
    mov  rax, [rel boot_budget_fixture_saved_gated]
    mov  [rel boot_budget_gated], rax
    mov  byte [rel boot_budget_force_full], 1
    mov  byte [rel boot_budget_full_busy], 0
    lea  rdi, [rel str_boot_budget_confirmed]
    call serial_string
    ; Content-bearing negative-control receipt: QEMU executed every
    ; TRIAL_ONLY row under force_full above, and the one-row confirmed
    ; gate probe just proved the opposite branch. Keep this fixture line
    ; distinct from the immutable P0 class/count line emitted earlier.
    lea  rdi, [rel str_boot_budget_qemu_trial_count]
    call serial_string
    lea  rdi, [rel str_boot_budget_trial]
    call serial_string
    jmp  .done
.qemu_restore_fail:
    mov  al, [rel boot_budget_fixture_saved_class]
    mov  [rel boot_budget_class], al
    mov  rax, [rel boot_budget_fixture_saved_gated]
    mov  [rel boot_budget_gated], rax
    mov  byte [rel boot_budget_force_full], 1
    mov  byte [rel boot_budget_full_busy], 0
    jmp  .fail
.fail:
    lea  rdi, [rel str_boot_budget_failed]
    call serial_string
.done:
    pop  rbx
    ret

; ============================================================================
; 1051 P7/P8 helpers — boot-time measurement + the non-blocking P8 NIC watcher.
; ============================================================================
%include "core/abi/wdata.inc"
; G9 (RCQ-28): idle ticks in which the compositor path ran; the post-readiness
; stability window requires it to advance (GUI presentation). Hot store: WDATA.
%macro WDATA_boot_header_g9 0
boot_idle_compositor_ticks: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_boot_header_g9
; RCQ-32 boot-gate stamps (raw TSC, 0 = not reached). Each writer owns its moment;
; svc/boot_gates converts against boot_tsc_start when it reports.
%macro WDATA_boot_header_bg 0
boot_bg4_ebs_tsc:   resq 1          ; boot/paging: ExitBootServices returned success
boot_bg5_ready_tsc: resq 1          ; svc/boot_gates: readiness gate passed (G9 arm edge)
boot_bg5b_ack_tsc:  resq 1          ; svc/boot_gates: PaOSBootReady publish first seen
boot_bg6_pixel_tsc: resq 1          ; gui/lock_screen: first presented sign-in frame
boot_p7_tsc:        resq 1          ; P7 interactive paint (CLI login / GUI desktop)
boot_prepixel_tsc:  resq 5          ; pre/post SMP, pre/post USB, post guest foundation
boot_device_cuts_tsc: resq 5        ; xHCI/enum/I2C/USB NIC/native NIC return cuts
; RCQ32_NATIVE_COST_BEGIN
boot_native_cost_tsc: resq 10      ; five begin/end pairs, raw TSC
boot_native_cost_done: resq 5      ; completion publication, raw zero still present
; RCQ32_NATIVE_COST_END
; RCQ32_P8_RAW_BEGIN
boot_nic_ready_tsc: resq 1         ; selected native-egress link_status bit0 earned
boot_hv_foundation_ready_tsc: resq 1 ; host setup returned, including absence/degradation
boot_nic_ready_observed: resb 1    ; one-shot presence, even if raw TSC is zero
; RCQ32_P8_RAW_END
%endmacro
WDATA_BSS_DEFER WDATA_boot_header_bg
; RCQ32_SETTLE spec 7.6.5 settled producers (BOOTCLOCK v5): raw TSC per slot and
; state 0 pending / 1 complete / 2 not-required. Producers are boot_settle_* below.
%macro WDATA_boot_header_settle 0
boot_settle_tsc:   resq 4
boot_settle_state: resb 4
boot_settle_seen:  resb 1          ; first idle observation done: not-required is final
%endmacro
WDATA_BSS_DEFER WDATA_boot_header_settle
; RCQ-32 (root 2026-10-17 01:16): P1 STARTING checkpoint edge returned, raw TSC,
; 0 = not reached. Own block so the pinned boot-gate block layout is unchanged.
%macro WDATA_boot_header_p1ckpt 0
boot_p1_ckpt_tsc:  resq 1
%endmacro
WDATA_BSS_DEFER WDATA_boot_header_p1ckpt

; RCQ32_P8_RAW_BEGIN
; Latch raw TSC at the existing producer moments, never reconstruct from ms.
; BSP first-arrival publication only. Preserve flags and ALL registers so the
; preceding legacy boot_ms_now sample/value and following policy are unchanged.
; Foundation's existing ready flag is published immediately after this call.
boot_foundation_stamp:
    pushfq
    cmp byte [rel boot_hv_foundation_ready], 0
    jne .out
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_hv_foundation_ready_tsc], rax
    pop rdx
    pop rax
.out:
    popfq
    ret

boot_nic_stamp:
    pushfq
    cmp byte [rel boot_nic_ready_observed], 0
    jne .out
    push rax
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel boot_nic_ready_tsc], rax
    mov byte [rel boot_nic_ready_observed], 1
    pop rdx
    pop rax
.out:
    popfq
    ret

; RCQ32_P8_RAW_END

; RCQ32_SETTLE_BEGIN
; Spec 7.6.5 settled producers, reported only (BOOTCLOCK v5); nothing waits on
; them. Raw TSC first-arrival latches per slot, written by the BSP only: the TSC
; is stored before its state byte. State 0 pending, 1 complete, 2 not-required.
BOOT_SETTLE_CPUS     equ 0
BOOT_SETTLE_STORAGE  equ 1
BOOT_SETTLE_CENSUS   equ 2
BOOT_SETTLE_CHECKS   equ 3
BOOT_SETTLE_COMPLETE equ 1
BOOT_SETTLE_NOT_REQUIRED equ 2

; EDI=slot, ESI=BOOT_SETTLE_COMPLETE (stamp now) or BOOT_SETTLE_NOT_REQUIRED.
; Write-once per slot. Preserves flags and all registers.
boot_settle_mark:
    pushfq
    push rax
    push rdx
    push rdi
    cmp  edi, BOOT_SETTLE_CHECKS
    ja   .out
    cmp  esi, BOOT_SETTLE_COMPLETE
    jb   .out
    cmp  esi, BOOT_SETTLE_NOT_REQUIRED
    ja   .out
    lea  rax, [rel boot_settle_state]
    cmp  byte [rax + rdi], 0
    jne  .out
    cmp  esi, BOOT_SETTLE_COMPLETE
    jne  .state
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    lea  rdx, [rel boot_settle_tsc]
    mov  [rdx + rdi*8], rax
    lea  rax, [rel boot_settle_state]
.state:
    mov  [rax + rdi], sil
.out:
    pop  rdi
    pop  rdx
    pop  rax
    popfq
    ret

; After smp_selftest: the bounded bring-up scan is over and a late AP is parked,
; never onlined, so the set is final. Complete only if every discovered CPU is
; online with no failed row; otherwise the row stays pending (never settled).
boot_settle_cpus:
    pushfq
    push rax
    mov  eax, [rel smp_topology_online]
    test eax, eax
    jz   .out
    cmp  eax, [rel smp_discovered_count]
    jne  .out
    cmp  dword [rel smp_failed_count], 0
    jne  .out
    push rdi
    push rsi
    mov  edi, BOOT_SETTLE_CPUS
    mov  esi, BOOT_SETTLE_COMPLETE
    call boot_settle_mark
    pop  rsi
    pop  rdi
.out:
    pop  rax
    popfq
    ret

; Idle loop, right after cadence_poll (where the fs.orphan sweep step runs) and
; after the deferred runtime-PMOD KAT poll. Not-required is accepted only at the
; first observation, so a KAT armed later by a runtime PMOD is not this boot's
; deferred work. Storage is not-required only in a build without exact DATA.
boot_settle_tick:
    cmp  byte [rel boot_settle_state + BOOT_SETTLE_STORAGE], 0
    jne  .checks
    call fat32_disk_replay_state
    mov  edi, BOOT_SETTLE_STORAGE
    call .apply
.checks:
    cmp  byte [rel boot_settle_state + BOOT_SETTLE_CHECKS], 0
    jne  .seen
    call sched_preempt_post_pmod_settle_state
    mov  edi, BOOT_SETTLE_CHECKS
    call .apply
.seen:
    mov  byte [rel boot_settle_seen], 1
    ret
; EAX=producer state, EDI=slot.
.apply:
    cmp  eax, BOOT_SETTLE_COMPLETE
    je   .mark
    cmp  eax, BOOT_SETTLE_NOT_REQUIRED
    jne  .none
    cmp  byte [rel boot_settle_seen], 0
    jne  .none
.mark:
    mov  esi, eax
    jmp  boot_settle_mark
.none:
    ret
; RCQ32_SETTLE_END
; boot_ms_now -> RAX = milliseconds since boot_tsc_start (0 if TSC uncalibrated
;   or the sample precedes boot_tsc_start, matching boot_gates_ms).
;   clobbers RAX,RCX,RDX.
boot_ms_now:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel boot_tsc_start]
    jb   .zero
    xor  rdx, rdx
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .zero
    div  rcx
    ret
.zero:
    xor  eax, eax
    ret

; boot_p8_nic_watch — P8 background step (called every idle tick): while the net tile
;   is WARMING, re-read the live link state; when autoneg completes latch nic_ready_ms
;   + flip to READY (emit boot.p8.ready); if the per-driver P8 budget is exceeded PARK
;   it (the desktop stays interactive — STATUS keeps answering, never a hung boot;
;   BOOT_SEQUENCE note 2). PARKED remains truthful until a rate-limited fresh
;   selected healthy native link earns READY. READY is terminal. Caller-saved.
boot_p8_nic_watch:
    cmp  byte [rel boot_nic_state], NIC_ST_WARMING
    je   .warming
    cmp  byte [rel boot_nic_state], NIC_ST_PARKED
    jne  .out                            ; READY/unknown never reopen
    PW_EDGE 10
    call boot_ms_now
    test rax, rax
    PW_BRANCH jnz,jz,11,.out                            ; unmeasured time cannot earn recovery
    mov  rcx, [rel boot_nic_park_poll_ms]
    test rcx, rcx
    jz   .park_anchor
    mov  rdx, rax
    sub  rdx, rcx
    PW_BRANCH jae,jb,13,.out              ; regressed time cannot open a poll
    cmp  rdx, P8_NIC_RECHECK_MS
    PW_BRANCH jae,jb,14,.out
    mov  [rel boot_nic_park_poll_ms], rax ; consume cadence before driver IO
    PW_EDGE 15
    PW_EDGE 16
    call e1000e_link_refresh
    PW_EDGE 17
    xor  edi, edi
    call netdev_egress_select            ; existing registry selection; no bind/takeover
    PW_EDGE 18
    test rax, rax
    PW_BRANCH jnz,jz,18,.out,1
    cmp  dword [rax + dev.health], HEALTH_OK
    PW_BRANCH je,jne,19,.out              ; soft-DEGRADED fallback cannot earn READY
    cmp  dword [rax + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    PW_BRANCH jae,jb,20,.out              ; relay/domain is not native readiness
    test dword [rax + dev.flags], NETDEV_F_ABSENT
    PW_BRANCH jz,jnz,21,.out
    mov  rdi, rax
    call netdev_selected_link_ready      ; registered/class/ops, ONE live read, reselect
    test rax, rax
    PW_BRANCH jnz,jz,26,.out,1
    cmp  dword [rax + dev.health], HEALTH_OK
    PW_BRANCH je,jne,26,.out,2            ; foreign link call may have changed health
    cmp  dword [rax + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    PW_BRANCH jae,jb,26,.out,3
    test dword [rax + dev.flags], NETDEV_F_ABSENT
    PW_BRANCH jz,jnz,26,.out,4
    call boot_ms_now
    test rax, rax
    PW_BRANCH jnz,jz,27,.out,1
    cmp  rax, [rel boot_nic_park_poll_ms]
    PW_BRANCH jae,jb,27,.out,2            ; no readiness on a regressed completion sample
    jmp  .nic_ready
.park_anchor:
    PW_EDGE 12
    mov  [rel boot_nic_park_poll_ms], rax ; first valid parked sample only anchors
    ret
.warming:
    call e1000e_link_refresh             ; live STATUS.LU latch (catches late I219 autoneg)
    ; usbnic-late-bind: readiness = the SELECTED egress netdev's link_status, not
    ; e1000e alone, so a late-bound USB NIC (cdc_ecm/ax88179) can flip net->ready.
    ; The I219 path is unchanged: e1000e is still selected first when present and its
    ; link_status reads the latch refreshed above.
    xor  edi, edi
    call netdev_egress_select            ; RAX = highest-prio HEALTHY netdev (0 = none)
    test rax, rax
    jz   .budget
    cmp  dword [rax + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    jb   .budget                         ; loopnet/domain relay (always "up") is NOT a NIC -> never READY
    mov  r10, [rax + dev.ops]
    test r10, r10
    jz   .budget
    mov  r11, [r10 + netdev_ops.link_status]
    test r11, r11
    jz   .budget
    mov  rdi, rax                        ; self
    call r11                             ; RAX bit0 = link up
    cmp  rax, -1
    je   .budget                         ; unavailable status cannot earn READY
    test al, 1
    jz   .budget
    call boot_ms_now
.nic_ready:
    PW_EDGE 28
    mov  [rel boot_nic_ready_ms], rax
; RCQ32_P8_RAW_BEGIN
    call boot_nic_stamp                  ; raw first arrival, independent of later link state
; RCQ32_P8_RAW_END
    mov  byte [rel boot_nic_state], NIC_ST_READY
    mov  byte [rel boot_p8_ready_any], 1
    lea  rdi, [rel str_p8_ready_nic]     ; [boot.p8.ready] (nic)
    call serial_string
    cmp  byte [rel net_required], 0
    je   .out
    sub  rsp, 8                          ; align nested SetVariable call chain
    call software_stop_publish_strong_health
    add  rsp, 8
    PW_EDGE 31
    ret
.budget:
    call boot_ms_now
    sub  rax, [rel boot_nic_warm_start_ms]
    jb   .out                            ; unavailable/regressed clock is not an expired budget
    cmp  rax, P8_NIC_BUDGET_MS
    jb   .out
    mov  byte [rel boot_nic_state], NIC_ST_PARKED
    HP_PARKED_ORIGIN 2             ; first warming-budget expiry
    PW_EDGE 0
    mov  byte [rel boot_p8_ready_any], 1 ; boot.p8.ready still fires (state resolved -> parked)
    lea  rdi, [rel str_p8_park_nic]      ; [boot.p8.ready] (nic parked)
    call serial_string
    cmp  byte [rel net_required], 0
    je   .out
    PW_EDGE 30                         ; actual original publisher call intent
    sub  rsp, 8                          ; record the resolved refusal exactly once
    call software_stop_publish_strong_health
    add  rsp, 8
    PW_EDGE 1
.out:
    PW_EDGE 29
    ret

; --- boot/header data (in-image for first-light; pre-paging, OVMF maps the
;     image writable). W^X model (MEMORY_MAP §3.1, lands WITH boot/paging.asm):
;     image = code + rodata (R+X); WRITABLE state migrates to a fixed BSS region
;     (RW+NX) that only exists once our page tables map it. Until paging, these
;     three writable vars stay here. ---
image_handle:    dq 0
system_table:    dq 0

boot_services:   dq 0
runtime_services: dq 0
boot_tsc_start:  dq 0
; --- 1068 boot-report state (written post-paging at the interactive-ready point;
;     in-image data our page tables map RW, same as the command registry's data) ---
boot_tsc_end:      dq 0
boot_ms:           dq 0             ; (boot_tsc_end - boot_tsc_start) / tsc_khz
heap_mb:           dq 0             ; heap_size >> 20
bootreport_numbuf: times 24 db 0    ; u64 decimal scratch (max 20 digits + NUL)
str_bootreport_pre:  db "[PAOS64] P4 boot-report: BOOT_MS=", 0
str_bootreport_mid:  db " HEAP_MB=", 0
str_bootreport_post: db " [boot.report.ready]", 13, 10, 0
; --- 1051 P7/P8 split state (in-image RW, same region as boot_ms above) ---
boot_p7_ms:             dq 0            ; interactive-ready (P7) boot time in ms == p7_ms
boot_p7_us:             dq 0            ; P7 in microseconds (qemu ordering KAT only)
boot_hv_foundation_ready_ms: dq 0        ; P8 foundation ready; never guest-launch proof
boot_nic_ready_ms:      dq 0            ; P8 NIC link-up (autoneg complete) — 0 while warming/parked
boot_nic_warm_start_ms: dq 0            ; when P8 NIC warming began (park-budget clock)
boot_nic_park_poll_ms:  dq 0            ; last valid parked poll/anchor (no retry writes)
boot_nic_state:         db NIC_ST_WARMING
net_required:           db PAOS_NET_REQUIRED ; descriptor intent; never inferred from link state
boot_hv_foundation_ready: db 0           ; set only after the P8 foundation path returns
boot_p7_reached:        db 0
boot_p8_warming:        db 0
boot_p8_ready_any:      db 0
; Each row is {rel32 callback, class byte, 3 pad bytes}. Expanding the shared
; policy macro again keeps ids, callbacks, and classes in one source.
align 8
boot_budget_table:
%assign BOOT_BUDGET_EMITTED_COUNT 0
%macro BOOT_BUDGET_ROW 2
    dd %2 - boot_budget_table
    db BOOT_BUDGET_TRIAL_ONLY, 0, 0, 0
    %assign BOOT_BUDGET_EMITTED_COUNT BOOT_BUDGET_EMITTED_COUNT + 1
%endmacro
%macro BOOT_BUDGET_ALWAYS 2
    dd %2 - boot_budget_table
    db BOOT_BUDGET_CLASS_ALWAYS, 0, 0, 0
    %assign BOOT_BUDGET_EMITTED_COUNT BOOT_BUDGET_EMITTED_COUNT + 1
%endmacro
BOOT_BUDGET_ROWS
%unmacro BOOT_BUDGET_ROW 2
%unmacro BOOT_BUDGET_ALWAYS 2
%if BOOT_BUDGET_EMITTED_COUNT != BOOT_BUDGET_COUNT
    %error "boot budget id/table count mismatch"
%endif
boot_budget_table_end:
%if (boot_budget_table_end - boot_budget_table) != (BOOT_BUDGET_COUNT * 8)
    %error "boot budget table row size mismatch"
%endif

boot_budget_gated:         dq 0
boot_budget_trial_seen:    dq 0
boot_budget_executed:      dq 0
boot_budget_full_runs:     dq 0
boot_budget_full_start_executed: dq 0
boot_budget_full_start_failures: dd 0
boot_budget_full_failures: dd 0
boot_budget_class:         db BOOT_CLASS_TRIAL
boot_budget_force_full:    db 0
boot_budget_full_busy:     db 0
boot_budget_armed_emitted: db 0
boot_budget_qemu_fixture:  db 0
boot_budget_fixture_saved_class: db 0
boot_budget_p0_trial:      db 0
boot_budget_p0_valid:      db 0
align 8
boot_budget_fixture_saved_gated: dq 0
boot_budget_arm_size:      dq 0
boot_budget_arm_attrs:     dd 0
align 8
boot_budget_arm_id:        times 32 db 0   ; identity published by this boot's BOOT LINUX arm
boot_budget_arm_seen:      times 32 db 0   ; identity read back at the next P0
; PaOSBootArm under the registered PaOS boot GUID (nvg_paos_guids #6,
; c4a7c2f1-4bb5-4ae8-9c4f-6f76f7c2a051, EFI mixed-endian layout).
boot_budget_arm_var_guid:
    dd 0xC4A7C2F1
    dw 0x4BB5, 0x4AE8
    db 0x9C,0x4F,0x6F,0x76,0xF7,0xC2,0xA0,0x51
boot_budget_arm_var_name:
    dw 'P','a','O','S','B','o','o','t','A','r','m',0
str_boot_budget_arm_nvg_tag: db "boot_budget_arm",0
str_boot_budget_arm_same: db "[PAOS64] P0 boot: BOOT LINUX arm returned to the same verified payload -> disarmed, CONFIRMED [boot.budget.arm.same_payload]",13,10,0
str_boot_budget_arm_trial: db "[PAOS64] P0 boot: BOOT LINUX arm not bound to this payload -> TRIAL [boot.budget.arm.trial]",13,10,0
str_boot_budget_manager_trial: db "[PAOS64] P0 boot: Manager Trial or unclean launch on a clean byte -> TRIAL [boot.budget.manager.trial]",13,10,0

str_boot_budget_armed: db "[PAOS64] P2 boot: budget gate armed (table-driven selftest classes) [boot.budget.gate.armed]",13,10,0
str_boot_budget_count: db "[PAOS64] P7 boot: boot.budget.gated=",0
str_boot_budget_cls_confirmed: db " cls=confirmed",13,10,0
str_boot_budget_cls_trial: db " cls=trial",13,10,0
str_boot_budget_confirmed: db "[PAOS64] P7 boot: confirmed boot skipped trial-only selftests (security floor kept) [boot.budget.confirmed.fast]",13,10,0
str_boot_budget_qemu_trial_count: db "[PAOS64] P7 boot fixture: boot.budget.gated=0 cls=trial source=qemu-forced-full",13,10,0
str_boot_budget_trial: db "[PAOS64] P7 boot: TRIAL boot ran the full ladder [boot.budget.trial.full]",13,10,0
str_boot_budget_failed: db "[PAOS64] P7 boot: budget ladder INCOMPLETE (class/count/security verdict mismatch)",13,10,0
str_p7_interactive: db "[PAOS64] P7 shell: interactive desktop ready (drivable)", 0
str_p7_cli_interactive: db "[PAOS64] P7 shell: interactive CLI login ready (drivable)", 0
str_p7_tail: db " [boot.p7.after_paint] [boot.p7.interactive]", 13, 10, 0
str_boot_kat_pre:   db "[PAOS64] P7 boot.kat p7_us=", 0
str_boot_kat_post:  db " deferred=1", 13, 10, 0
str_p8_warming:     db "[PAOS64] P8 forge: background warming started (NIC/hypervisor foundation deferred, never gates P7) [boot.p8.warming]", 13, 10, 0
str_p8_ready_hv:    db "[PAOS64] P8 hv: foundation ready [hv.foundation.ready] [boot.p8.ready]", 13, 10, 0
str_p8_ready_nic:   db "[PAOS64] P8 forge: NIC link up (autoneg complete) warmed -> ready [boot.p8.ready]", 13, 10, 0
str_p8_park_nic:    db "[PAOS64] P8 forge: NIC exceeded P8 budget -> PARKED (desktop stays interactive) [boot.p8.ready]", 13, 10, 0
str_net_health_gate_armed: db "[PAOS64] P8 health: net-required publish gate armed (descriptor-driven) [net.health.gate.armed]", 13, 10, 0
str_et_inject: db "[PAOS64] P0 early-trap INJECT: raising a deliberate pre-EBS fault (ud2) in the 2026-08-06 window", 13, 10, 0
str_firstlight:  db "[PAOS64] M1 first-light: keep booted, serial up", 13, 10, 0
str_p2ok:        db "[PAOS64] P2 core ok: boot+core self-tests passed [p2_core_ok]", 13, 10, 0
