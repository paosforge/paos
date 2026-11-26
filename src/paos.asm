; ============================================================================
; paos.asm — THE LINK MAP (PaOS rework, v0.0.1). Minimal boot+core keep.
;
; Per MODULES.md §1: an ordered list of %includes, NOTHING else. One `nasm -f bin`
; pass over this tree produces the keep. SKELETON.md: this is M0/M1 — boot -> core
; -> "[PAOS64] P2 core ok" -> halt, no features. The loop builds UP from here
; (bus -> class seams -> drivers -> net -> gui -> guest), hot-patch-primary,
; bare-metal-gated. Single-pass assembler: .inc headers (struc/equ/macro) first.
; ============================================================================
%include "core/abi/build_profile.inc"
bits 64
org 0
%define PAOS_NIC_ASSIGNMENT 1 ; common selected-NIC supervisor, both CPU backends
; Native drivers remain compiled into this one image. Admission is selected
; before hardware probes; standalone module fixtures may omit this boot graph.
%define PAOS_NATIVE_DRIVER_POLICY_LINKED 1
%define PAOS_A1_SERVICE_LINKED 1
%define PAOS_DRIVER_DOMAIN_EVERYBOOT 1
%define WIFI_LOCAL_GUI_BUILT 1 ; local private editor, never a public credential command

%ifndef RCQ_NET_RETURN_DIAG
%define RCQ_NET_RETURN_DIAG 0
%endif
%ifndef RCQ_SERVICE_PROGRESS_DIAG
%define RCQ_SERVICE_PROGRESS_DIAG 0
%endif

%ifndef RCQ37_VIDEO_BUILT
%define RCQ37_VIDEO_BUILT 0
%endif
%include "hv/guest_media_contract.inc" ; RCQ-37 G3b: RCQ37_MEDIA_PROFILE needs both build flags (no bytes)
%include "hv/pcia_grp.inc" ; W4c-2 ABI v1: whole-group record equates for pci_assign/vtd_guest/amdvi_guest (no bytes)
%ifdef RCQ37_MEDIA_PROFILE                ; link-map projections without the contract see the OFF path
%if RCQ37_MEDIA_PROFILE
%define PAOS_CRC32_UPDATE ; PMH's DATA CRC uses the streaming form
%endif
%endif
; Ordinary product wallpaper work is incremental on every profile, independent
; of the guest-media or lab build switches.
%define PAOS_IMG_COLD_WORK 1
%define PAOS_IMG_COLD_FAT 1
%define PAOS_IMG_COLD_LIVE 1
%define PAOS_IMG_COLD_LOCK 1
%ifndef PAOS_CRC32_UPDATE
%define PAOS_CRC32_UPDATE ; incremental image CRC uses the streaming primitive
%endif

; ---- headers (.inc — emit no bytes; the device-class ABI seam, DRIVER_MODEL.md) ----
%include "core/abi/driver_classes.inc"
%include "core/abi/diag.inc" ; diag-ring geometry + PHASE breadcrumb macro (shared)
%define PAOS_WDATA_REGION 1 ; this link map emits the deferred writable-data region at the tail
%include "core/abi/wdata.inc" ; WDATA_DEFER: page-isolated writable data (TCG SMC hazard fix)
%include "boot/boot_v2_contract.inc" ; data-only Manager/PaOS/Rescue state + LoadOptions ABI (emits no bytes)
%include "version-identity.inc" ; generated once per build; shared by all wire identities
%include "boot-v2-owner-key.inc" ; generated from BOOT_V2_OWNER_PUBLIC_KEY: owner trust-root %define byte lists only (no bytes)
%ifdef PAOS_LAB_CHANNEL ; lab builds only; the lab command channel is not in the public source
%include "svc/command_auth_lab.inc" ; W2 lab command channel: equates + hook macros only (no bytes); empty unless make PAOS_LAB_CHANNEL=on
%endif
; Contract 2306's single boot-selftest classification table. It is a macro
; because boot/header expands the same data once for stable ids and once for
; rel32 callbacks/classes; no runtime pointer relocation is required.
%macro BOOT_BUDGET_ROWS 0
BOOT_BUDGET_ROW ST_TIMELINE_OVERFLOW,       boot_timeline_overflow_kat
BOOT_BUDGET_ROW ST_LOG_MODE_POLICY,         boot_log_mode_policy_kat

BOOT_BUDGET_ALWAYS ST_IDT,                  idt_selftest
BOOT_BUDGET_ALWAYS ST_WX_NX,                wx_selftest
BOOT_BUDGET_ALWAYS ST_FAULT_UD,             fault_contain_selftest
BOOT_BUDGET_ALWAYS ST_FAULT_RECOVER,        fault_recover_selftest
BOOT_BUDGET_ALWAYS ST_FAULT_DF,             fault_df_selftest

BOOT_BUDGET_ROW ST_LIB,                     lib_selftest
BOOT_BUDGET_ROW ST_LOGFMT,                  logfmt_selftest
BOOT_BUDGET_ROW ST_STRMEM,                  strmem_kat_selftest
BOOT_BUDGET_ROW ST_NET_CKSUM16,             net_cksum16_kat
BOOT_BUDGET_ROW ST_FMT_DEC,                 fmt_dec_kat
BOOT_BUDGET_ROW ST_LIB_CLOBBER,             lib_clobber_selftest
; Bounded memory-safety floor on every normal boot, before IRQs and APs.
; Reuse the KAT/guard/alignment/exhaustion-recovery checks; CONFIRMED must
; earn its own heap verdicts just as it earns DMA verdicts. ALWAYS also keeps
; signed on-demand FULL from changing live allocator bounds after startup.
BOOT_BUDGET_ALWAYS ST_HEAP,                 heap_selftest
BOOT_BUDGET_ROW ST_MEMMAP,                  memmap_selftest
BOOT_BUDGET_ROW ST_MEMMAP_OWNER,            memmap_owner_selftest
BOOT_BUDGET_ROW ST_MMAP_REFUSAL,            mmap_refusal_selftest
BOOT_BUDGET_ROW ST_MEM_LAYOUT,              mem_layout_selftest

; Named selftests that also establish live kernel foundations stay ALWAYS.
BOOT_BUDGET_ALWAYS ST_TIME,                 time_selftest
BOOT_BUDGET_ALWAYS ST_TIMER,                timer_selftest
BOOT_BUDGET_ROW ST_GOVERNOR,                gov_selftest
BOOT_BUDGET_ROW ST_THERMAL,                 thermal_selftest
BOOT_BUDGET_ALWAYS ST_RESILIENCE,           resilience_selftest
BOOT_BUDGET_ALWAYS ST_SCHED,                sched_selftest
BOOT_BUDGET_ALWAYS ST_PREEMPT,              preempt_selftest
BOOT_BUDGET_ALWAYS ST_DMA,                  dma_selftest
BOOT_BUDGET_ALWAYS ST_DIAG,                 diag_selftest

BOOT_BUDGET_ROW ST_HOTPATCH,                hotpatch_selftest
BOOT_BUDGET_ROW ST_HOTPATCH_GEN,            hotpatch_gen_selftest
BOOT_BUDGET_ROW ST_HOTPATCH_SYMBOL,         hotpatch_symbol_selftest
BOOT_BUDGET_ROW ST_TCP_HANDSHAKE,           tcp_handshake_selftest
BOOT_BUDGET_ROW ST_TCP_SYNACK,              tcp_build_synack_kat
BOOT_BUDGET_ROW ST_ARP_CACHE,               arp_cache_selftest
BOOT_BUDGET_ROW ST_ARP_LOOKUP,              arp_cache_lookup_kat
BOOT_BUDGET_ROW ST_ARP_INSERT,              arp_cache_insert_kat
BOOT_BUDGET_ROW ST_DHCP_CLIENT,             dhcp_client_selftest
BOOT_BUDGET_ROW ST_DHCP_FIND_OPTION,        dhcp_find_option_kat
BOOT_BUDGET_ROW ST_DHCP_PARSE_ACK,          dhcp_parse_ack_kat
BOOT_BUDGET_ROW ST_DHCP_PARSE_OFFER,        dhcp_parse_offer_kat
BOOT_BUDGET_ROW ST_DHCP_WR_U8,              dhcp_wr_u8_kat
BOOT_BUDGET_ROW ST_DNS_RESOLVER,            dns_resolver_selftest
BOOT_BUDGET_ROW ST_DNS_DECODE_NAME,         dns_decode_name_kat
BOOT_BUDGET_ROW ST_DNS_STREQ,               dns_streq_kat
BOOT_BUDGET_ROW ST_DNS_PARSE_RESPONSE,      dns_parse_response_kat
BOOT_BUDGET_ROW ST_DNS_WR_U8,               dns_wr_u8_kat
BOOT_BUDGET_ROW ST_DNS_SKIP_NAME,           dns_skip_name_kat
BOOT_BUDGET_ROW ST_DNS_ENCODE_QNAME,        dns_encode_qname_kat
BOOT_BUDGET_ROW ST_ICMP_BUILD_REPLY,        icmp_build_reply_kat

; Registry/scheduler/audit rows build live state as well as grading it.
BOOT_BUDGET_ALWAYS ST_CADENCE_REGISTRY,     cadence_registry_selftest
BOOT_BUDGET_ALWAYS ST_COMMAND_REGISTRY,     command_registry_selftest
BOOT_BUDGET_ROW ST_COMMAND_AIHOOK,          command_aihook_selftest
BOOT_BUDGET_ALWAYS ST_SCHED_CLASS,          sched_class_selftest
BOOT_BUDGET_ALWAYS ST_SCHED_RT,             sched_rt_selftest
BOOT_BUDGET_ALWAYS ST_AUDIT,                audit_selftest
BOOT_BUDGET_ROW ST_COMMAND_SERIAL,          command_serial_selftest
BOOT_BUDGET_ROW ST_VCPU_QUANTUM,            vcpu_quantum_selftest
BOOT_BUDGET_ROW ST_BOOT_CANON,              boot_canon_selftest

; Security whitelist: confirmed boots continue to prove the complete floor.
BOOT_BUDGET_ALWAYS ST_CRYPTO_STANDARD,      crypto_standard_selftest
BOOT_BUDGET_ALWAYS ST_TLS13,                tls13_selftest_once
BOOT_BUDGET_ALWAYS ST_HTTP,                 http_selftest_once
BOOT_BUDGET_ALWAYS ST_ED25519,              ed25519_selftest
BOOT_BUDGET_ALWAYS ST_NODE_IDENTITY,        node_identity_selftest
BOOT_BUDGET_ALWAYS ST_CRYPTO_ENVELOPE,      crypto_envelope_selftest
BOOT_BUDGET_ALWAYS ST_PRINCIPAL,            principal_selftest
BOOT_BUDGET_ALWAYS ST_DATA_CRYPTO,          data_crypto_selftest
BOOT_BUDGET_ALWAYS ST_KVSTORE,              kvstore_selftest
BOOT_BUDGET_ALWAYS ST_NODE_ID_CONSUMER,     node_identity_selftest_consumer

; These rows also discover/register live hardware and service foundations.
BOOT_BUDGET_ALWAYS ST_SMP,                  smp_selftest
BOOT_BUDGET_ALWAYS ST_SMP_STACKS,           smp_stack_census_selftest
BOOT_BUDGET_ALWAYS ST_PCI,                  pci_selftest
BOOT_BUDGET_ALWAYS ST_ACPI,                 acpi_selftest
BOOT_BUDGET_ALWAYS ST_NETDEV,               netdev_selftest
BOOT_BUDGET_ALWAYS ST_VIRTIO_DOMAIN,        virtio_domain_selftest
BOOT_BUDGET_ALWAYS ST_NET_STACK,            net_stack_selftest
BOOT_BUDGET_ALWAYS ST_BLOCK,                blk_selftest
BOOT_BUDGET_ALWAYS ST_SND,                  snd_selftest
BOOT_BUDGET_ROW ST_HOTPATCH_PERSIST,        hotpatch_persist_selftest
BOOT_BUDGET_ROW ST_BOOTMENU,                bootmenu_selftest
BOOT_BUDGET_ROW ST_MANAGER_HEAL_QEMU,       manager_heal_qemu_selftest
BOOT_BUDGET_ROW ST_MENU_LABELS_QEMU,        menu_labels_qemu_selftest
BOOT_BUDGET_ROW ST_RECOVERY_STATE_QEMU,     recovery_state_qemu_selftest
BOOT_BUDGET_ROW ST_SOFTWARE_STOP_QEMU,      software_stop_qemu_selftest
BOOT_BUDGET_ROW ST_VAULT_RESTORE_QEMU,      vault_restore_qemu_selftest
BOOT_BUDGET_ROW ST_BOOT_BLACKBOX_QEMU,      boot_v2_blackbox_qemu_selftest
BOOT_BUDGET_ROW ST_BOOT_GE_C5_QEMU,         boot_v2_ge_c5_qemu_selftest
BOOT_BUDGET_ROW ST_BOOT_GE_C7_QEMU,         boot_v2_ge_c7_qemu_selftest
BOOT_BUDGET_ALWAYS ST_VFS,                  vfs_selftest
BOOT_BUDGET_ALWAYS ST_XHCI,                 xhci_usb_selftest
BOOT_BUDGET_ALWAYS ST_USB_ENUM,             usb_enum_selftest
BOOT_BUDGET_ALWAYS ST_GUI_COMPOSITOR,       gui_compositor_selftest
BOOT_BUDGET_ROW ST_FILMSTRIP,                filmstrip_selftest

BOOT_BUDGET_ROW ST_WMX,                     wmx_selftest
BOOT_BUDGET_ROW ST_SESSION_PERSIST,         session_persist_selftest
BOOT_BUDGET_ROW ST_FORM_LOADER,             form_loader_selftest
BOOT_BUDGET_ROW ST_WINTREE,                 wintree_selftest
BOOT_BUDGET_ROW ST_LIVENESS_PANEL,          liveness_panel_selftest
; Input-arrival waits deliberately are not rows: Task2317 owns that removal.
BOOT_BUDGET_ALWAYS ST_APIC_CAP,             apic_cap_selftest

; PMOD's five-second EB-FE negative is TRIAL-only; confirmed keeps its floor.
%if !PAOS_PUBLIC_BUILD
BOOT_BUDGET_ALWAYS ST_PMOD_FLOOR,           boot_budget_pmod_floor
BOOT_BUDGET_ROW ST_PMOD_FULL,               pmod_init
BOOT_BUDGET_ROW ST_SCHED_POST_PMOD,         sched_preempt_post_pmod_selftest
%endif
BOOT_BUDGET_ROW ST_SERIAL_EQUIVALENCE,      serial_equivalence_kat
BOOT_BUDGET_ROW ST_TIMELINE_ORDERING,       boot_timeline_ordering_kat

BOOT_BUDGET_ALWAYS ST_CAPABILITY_FLOOR,     capability_selftest
BOOT_BUDGET_ALWAYS ST_SECURITY_TRUTH,       security_truth_catalog_selftest
BOOT_BUDGET_ALWAYS ST_VERDICT_BIJECTION,    selftest_verdict_kat
%endmacro

; ---- L0  boot ----
%define serial_string serial_string_projected
; Run the UART ownership KAT at the existing post-core/pre-AP seam, then retain
; the established ACPI-discovery wrapper and SMP bring-up order.
%define smp_selftest serial_lock_kat_then_smp
; Task2904 keeps boot/header.asm outside its transaction: redirect the two
; existing boot calls to HID-owned wrappers, then restore the canonical names.
%define usb_enum_selftest usb_hid_enum_selftest
%define ps2_input_selftest usb_hid_input_selftest
; Task3020 grades the policy only after UDP has declared every late registry
; row and interceptor. The wrapper also scopes the legacy BOOTLOG KAT adapter.
%define command_udp_init command_publicity_udp_init
; Task2402: register bounded idle cleanup at the existing late cadence seam.
; RCQ-20: the verb-registry census observer is installed first, then the same chain.
%define cadence_live_rearm command_hda_probe_arm
%define command_pci_mmio_init command_hda_probe_init
; Task3346: initialize class shapes and run action-free QEMU KATs immediately
; before the existing guest verb registration; retain its original behavior.
; Task3347: pure XML corpus KAT at the same QEMU-only seam, then retain
; Task3346 class initialization and the original guest verb registration.
%define hv_register_verbs android_a11y_boot_init
%include "boot/header.asm"   ; PE32+ header + UEFI entry (mz_header MUST be first)
%undef hv_register_verbs
%undef cadence_live_rearm
%undef command_pci_mmio_init
%unmacro BOOT_BUDGET_ROWS 0
%undef command_udp_init
%undef ps2_input_selftest
%undef usb_enum_selftest
%undef smp_selftest
%undef serial_string
%define serial_string serial_string_raw
%include "boot/serial.asm"   ; COM1 UART (first-light output)
%undef serial_string
%define serial_string serial_string_projected
%include "boot/menu_labels_qemu.asm" ; 1311: action-free Phase-6 marker earned by compiled label-model KAT
%include "boot/boot_v2_handoff.asm" ; additive migration seam: validate Manager LoadOptions; direct boots retain the embedded selector unchanged
%include "boot/boot_v2_health.asm" ; post-EBS nonce-bound strong-health publish; Manager alone reconciles the disk journal
%include "boot/smbios.asm"   ; ADMIN Q5: minimal bounds-checked SMBIOS type 1/2/3 identity (pre-EBS); HP EliteDesk 705 G5 -> BSP-only Phase-0
%include "boot/rescue0_snp.asm" ; Rescue-0 R0-0: read-only pre-EBS firmware SNP discovery record (R0STAT); no SNP state change, no traffic
%include "boot/native_driver_policy.asm"
%include "boot/native_driver_preload.asm"
%include "boot/native_driver_gate.asm"
%include "boot/native_driver_report.asm"
%include "boot/paging.asm"   ; ExitBootServices + our W^X page tables
%include "core/percpu_stack.asm" ; permanently owned guarded CPU stacks + live witness
%include "boot/gdt.asm"      ; our own GDT (kernel CS 0x08 / DS 0x10)
%include "boot/gop.asm"      ; UEFI GOP framebuffer grab
%include "boot/firmware_logo_draw.asm" ; boot-only owned BMP consumer
%include "boot/firmware_logo.asm" ; bounded owned BGRT capture before Boot Services reclaim
%include "boot/paging_xhci_late.asm" ; paging-owned code after layout-sensitive GOP list
%include "boot/beacon.asm"   ; 1076/1083 boot_beacon: on-screen GOP boot-confirm badge + per-boot nonce (serial/NIC-independent)
%include "core/idle_prof.asm" ; DHCP client gap step 2: BSP idle-loop owner profile, first 5 s, one serial line
%define chainload_linux_arm_bootnext chainload_linux_arm_bootnext_impl
%include "boot/chainload.asm" ; 9702 boot-canon escalation: pre-EBS CMOS trial/confirmed check -> chainload bootmgfw_orig (Windows) on FALLBACK (ported monolith device-path LoadImage/StartImage); closes the armed-CF9 reboot ladder
%undef chainload_linux_arm_bootnext
%include "boot/early_trap.asm" ; 1273a PRE-EBS FAULT TRAP: hook the FIRMWARE IDT fault gates before the first risky boot-services call so a pre-EBS #GP reaches PaOS (demote + CF9) instead of EDK2 CpuDeadLoop. Closes the 2026-08-06 F12 gap; the PCH-TCO watchdog alternative was refuted on this board (TCO_LOCK set, countdown gated)
%include "boot/indicator.asm" ; bounded BSP-timed normal boot dots
%include "boot/boot_face.asm" ; T6-1 public loading face renderer (GOP only, B4-checked)
%include "boot/boot_menu.asm" ; 1015 boot-canon 3-OS MENU (pre-EBS): PaOS/Windows/Linux/Diagnostics with 2s countdown + ConIn keys + one-shot CMOS override (BOOT verb) -> chainload via boot/chainload; emits the 4 boot-menu markers

; ---- L1  core ----
%include "core/lib/mem.asm"  ; canonical memcpy/memset/memcmp (G1 MERGE)
%include "core/lib/str.asm"  ; canonical strlen/strcmp (G1) + lib_selftest
%include "lib/safe_buffer.asm" ; 9523 destination-bounded copy/span/TLV safety floor + KAT
%include "core/lib/fmt.asm"  ; canonical int->dec/hex + pad formatting (G1)
%include "sec/cpu_security.asm" ; RCQ-42 calling-CPU observation; no early-entry policy change
%include "sec/cpu_boundary_policy.asm" ; RCQ-42 shared finite policy validator
%include "sec/cpu_boundary_selector.asm" ; T1-6 explicit paired untrusted-VM policy
%include "sec/cpu_boundary_executor.asm" ; RCQ-42 callable native host floor/IBPB executor
%include "sec/cpu_microcode.asm" ; RCQ-42 update validation/selection + the guarded per-CPU load
%include "sec/cpu_microcode_boot.asm" ; raw BSP compatibility, admitted pack and boot-report helpers
%include "sec/cpu_microcode_checked.asm" ; checked CPU-local I/O, observation and load/postsample API
%include "sec/cpu_intel_checked.asm" ; additive checked Intel capture/scoped plan; no VMX admission
%include "sec/cpu_boundary_full.asm" ; spec073 capability-derived full default
%include "sec/cpu_idle_tsa.asm" ; checked TSA final HLT/MONITOR/IO idle frontier (SEC-owned policy)
%include "sec/cpu_security_live.asm" ; checked live AUDIT/GUI observation, raw ABI retained
%include "sec/cpu_microcode_percpu.asm" ; normal-profile early AP attempt and immutable outcome records
%include "sec/cpu_microcode_bsp_checked.asm" ; deployed BSP checked I/O and fresh post-load evidence
%include "sec/cpu_microcode_bsp_report.asm" ; bounded immutable checked BSP evidence, no I/O or address output
%include "sec/cpu_security_report.asm" ; T1-6 read-only calling-CPU and BSP update report
%include "sec/cpu_security_percpu.asm" ; retained observations from validated CPU-local initialization
%include "sec/ucode_preload.asm" ; RCQ-42 2b-2: pre-EBS read of the slot's pack, admitted only by the compiled-in digest
%include "core/lib/crc32.asm" ; canonical zlib/IEEE CRC32 shared by hotpatch + GUI PLV1 witness (G1)
%include "core/lib/cksum.asm" ; canonical RFC1071 16-bit one's-complement checksum (G1, net/*)
%include "core/lib/fixed.asm" ; canonical Q32.32 + big-endian u64 helpers (SNTP/G1)
%include "core/lib/crypto.asm" ; legacy deterministic mixing helpers for non-security compatibility checks only
%include "core/lib/sha256.asm" ; proven FIPS SHA-256 transform + bounded incremental context (1095a2 physical-file stream hash)
%include "core/build_id.asm" ; SEC-pbh1: the image measures its own identity (SHA-256 of [code_start, wdata_region)) before its first store
%include "core/lib/ustar.asm" ; Task1230a: deterministic ustar archiver
%include "core/lib/hmac_sha256.asm" ; RFC 2104 HMAC over the shared SHA-256 primitive (1236 CSPRNG)
%include "core/lib/sha1.asm" ; WPA2 interoperability only, caller-private scratch
%include "core/lib/hmac_sha1.asm"
%include "core/lib/wpa2_psk.asm" ; private local password to existing PSK32 ABI
%include "core/lib/pbkdf2_sha256.asm" ; RFC 8018 PBKDF2-HMAC-SHA256 credential stretching (2501)
%include "core/lib/hkdf_sha256.asm" ; RFC 5869 HKDF-SHA256 shared key-derivation foundation (1237)
%include "core/lib/auth_derive.asm" ; canonical 1053 credential+salt -> auth key seam shared by principal and DATA crypto
%include "core/lib/aes256_gcm.asm" ; FIPS AES-256 + NIST SP 800-38D authenticated-envelope foundation (1237)
%include "data/backup_export.asm" ; Task1230a: BACKUP EXPORT crypto seam + KAT
%include "core/lib/aes128_gcm.asm" ; TLS_AES_128_GCM_SHA256 reuses the canonical GHASH/AEAD seam (1058)
%include "core/lib/x25519.asm" ; RFC 7748 X25519 canonical scalar-multiplication primitive (1058)
%include "core/lib/ed25519.asm" ; RFC 8032 strict Ed25519 sign/verify foundation (1239)
%include "bootmgr/rsa2048_verify.asm" ; proven strict RSA-2048/PKCS1v1.5/SHA-256 verifier reused by signed BUNDLE roots
%include "core/log.asm"      ; structured leveled logging -> serial (one path)
%include "core/lib/strmem_kat.asm" ; str+mem known-answer-test harness (G1 hardening)
%include "core/reset_wipe.asm" ; SEC-pre-reset-wipe-hook: the one pre-reset key wipe (point of no return)
%include "core/idt.asm"      ; IDT + exception handlers (writes the diag ring on faults)
%include "core/crash_identity.asm" ; additive full fatal identity; PBCR/H2 unchanged
%include "core/deadman_identity.asm" ; full retained actual D4 attempt, no fault-time EFI
%include "core/diag.asm"     ; persistent diag ring + fault dump (DEBUG-INFO foundation)
%include "core/failure_record.asm" ; BSP-only bounded nonfatal diagnostic persistence
%include "core/runtime_failure_record.asm" ; additive full-identity typed diagnostic, bounded BSP EFI
%include "core/maintenance_record.asm" ; bounded typed durable event store and exact preview
%include "core/maintenance_sources.asm" ; read-only prior fatal record adapter
%include "core/boot_maintenance_source.asm" ; retained startup/image-refusal event adapters
%include "core/lock.asm"     ; THE single reusable SMP spinlock primitive (1003 discipline, parameterized) — reused by every declared lock SITE
%include "core/csprng.asm"   ; keep-owned HMAC_DRBG + health-tested entropy provider (1236)
%include "core/heap.asm"     ; kmalloc bump allocator
%include "core/memmap.asm"   ; own the UEFI map post-EBS
%include "core/memmap_owner.asm" ; RC s21.1: PaOS pre-EBS regions are loader-typed in the published map
%include "core/mmap_refusal.asm" ; T1-4.8: the boot validator refuses malformed final maps (private input)
%include "core/memory_budget.asm" ; shared physical ownership ABI; no boot caller
%include "core/memory_consumer.asm" ; finite trusted optional CPU storage; no command/idle binding
%include "core/memory_observability.asm" ; Task1481: MEMORY_V1/MEMORY_TEST_V1 observability protocol + content KAT
%include "core/time.asm"     ; TSC + PIT timer
%include "core/normal_deadman.asm" ; opt-in BSP Normal live-loop TSC lease
%include "core/capability.asm" ; PMOD Tier-1 per-invocation capability gate (honest-mistake containment)
%include "boot/pmod_loader.asm" ; built-in L3-L5 PMOD/BUNDLE verify+sandbox+integration seam
%include "boot/model_volume_config.asm"
%include "boot/model_preload.asm" ; S1c fixed-hash file from signed exact-GUID data volume, pre-EBS
%include "boot/boot_esp_guid.asm" ; RCQ-38 G1b: pre-EBS read-only GPT GUID + removable bit of the volume PaOS was loaded from
%include "core/native_app.asm" ; bounded restartable native-module execution
%include "svc/native_fault.asm" ; fixed owner module fault/hang and explicit restart control
%include "svc/runtime_failure_sources.asm" ; original post-containment scalar observations
%include "core/sched.asm"    ; cooperative scheduler
; Extend the shipped eight-entry boot/GDT owner through an SMP-local wrapper.
; CPUs 0..7 retain the proven implementation; only 8..31 use the bounded
; capacity extension in core/smp.asm.
boot_gdt_percpu_prepare equ gdt_percpu_prepare
boot_gdt_percpu_load equ gdt_percpu_load
%define gdt_percpu_prepare smp_gdt_percpu_prepare
%define gdt_percpu_load smp_gdt_percpu_load
%define gdt_percpu_ready smp_gdt_percpu_ready
%include "core/smp.asm"      ; real AP INIT-SIPI-SIPI + per-core compounding worker queues + frozen SMPWORK snapshots
%include "core/smp_stack_census.asm" ; live guarded CPU stack owner census
%undef gdt_percpu_ready
%undef gdt_percpu_load
%undef gdt_percpu_prepare
%include "core/mca_cmci.asm" ; HEST-qualified CMCI route, bounded bank claims and IRQ marker
%include "core/mca_control.asm" ; CPU-local retained MCA control readbacks
%include "core/mca_init.asm" ; log boot status before OS MCA control enablement
%include "core/mca_poll.asm" ; CPU-local, read-only corrected MCA observations
%include "core/cadence.asm"  ; SCHEDULER §4.6 cadence registry: every periodic loop registers its rate, ONE tickless driver (1070)
%include "core/vcpu_quantum.asm" ; SCHEDULER §4.5 resident-vCPU bounded-quantum fairness seam: guest gets a bounded slice, host heartbeat never starves (1071)
%include "core/dma.asm"      ; page-aligned identity-mapped DMA buffers
%include "core/boot_canon.asm" ; A/B fault-tolerant boot-canon state machine LOGIC (1073, qemu rung): verify-then-jump hash + slot select + trial/good boot-attempt counter selftest

; ---- L1  mem ----
%include "mem/layout.asm"    ; relocatable/parameterized hot-data layout descriptor + layout_resolve (LOCALITY §10 seam, 1069)

; ---- L2  data ----
%include "data/crypto_envelope.asm" ; 1074 compatibility KAT + 1054 RFC5869/AES-256-GCM per-principal DATA envelope (plaintext keys remain RAM-only)

; ---- L4  web (2701: pure caller-bytes structured-data core; no live fetch) ----
%include "web/bounded_field_reader.asm"
%include "web/light_extract.asm"
%include "web/light_kat.asm"
%include "web/action_binding.asm"
%include "web/structured_data.asm"
%include "web/structured_kat.asm"

; ---- L4/5 mobile: pure caller bytes and ordinary QEMU fixture proof ----
%include "mobile/android_a11y_digest.asm"
%include "mobile/android_a11y_digest_kat.asm"
%include "security/sensitive_classifier.asm" ; 3305: pure bounded spans and fixed synthetic KATs

; ---- L5  svc ----
%include "svc/hotpatch.asm" ; live function hot-patch: detour+arena, self-test-or-revert (loop accelerator)
; 2150 extends the exact public-observation hook with six byte-exact T0 names.
; Every other name still delegates to the frozen SMP matcher and fail-closed auth.
%define command_smp_public_observation command_guestcpu_public_observation
; 2716/2717/3305/2908/3029/3418 each add one registry verb. Reserve six 48-byte entries at this
; boundary so the fixed registry keeps its previous declaration headroom.
; Intercept only the constant declaration; its capacity check AND table size
; then use the same expanded value. No alternate registry or dispatch path.
%macro VERB_MAX 1
    ; 2122 + 2502 + 2504: reserve WALLPAPER, LOCKSTATE, LOCK and the single
    ; PUSHAUTH row without evicting late image or post-login console verbs.
    ; Rescue-0 R0-0: +1 row for public R0STAT keeps the pre-R0 free-row count (S11);
    ; measured live 0.0.46 QEMU: 237 rows used of 238 before, 238 of 239 after.
    ; AUTHSTAT split (0.0.50): +1 row for the public AUTHVERBS census keeps the free-row
    ; count (S11); measured live QEMU on dea268050+AUTH2: 238 of 239 before, 239 of 239 with
    ; AUTHVERBS and no reserve -> 239 of 240 with this reserve.
    ; RCQ-20: FSCOPY/FSJOB/FSCANCEL (+3). Basis: 239 of 240 measured at 0.0.50, +2 rows
    ; since, +3 copy rows = 244; +32 keeps 12 free and covers the 255 assembled
    ; command_register_verb sites of the shipped profile (static ceiling, all paths).
    ; The live count is printed by [cmd.registry.census] after the last registration.
    ; RCQ-20: the saved 174 LAB census has 289 sites against 288 rows.
    ; Add 96 rows (4608 bytes), retaining one bound for allocation and admission.
    ; The unchanged build census checks every assembled profile.
    ; B1/P0 310: the actual LAB listing has 386 registration sites versus 385
    ; rows. Add 16 rows (768 bytes): 401 total, 15 spare at that static ceiling.
    ; Allocation and the original full-registry refusal share this same bound.
    VERB_MAX %1 + 176                  ; 225 + 176 = 401 rows
%endmacro
%define command_dispatch command_dispatch_registry
%include "svc/command.asm"  ; THE command MODEL, with a transport-independent session entry gate
%undef command_dispatch
%unmacro VERB_MAX 1
%undef command_smp_public_observation
%include "svc/command_cons.asm" ; 2150: L5 registry/parsing/paged-output half; L6 binds one runtime dump callback
; Contract 2800 extends the exact public-observation chain with the two bounded
; display reads its shipped, identity-less QEMU oracle must consume. Metadata
; stays authoritative: command_auth checks cap=0/destr=0 before this name hook.
; AF0 adds ACPIINFO through a metadata-checked wrapper, then delegates to that
; unchanged display/guest/console/SMP observation chain.
%define command_guestcpu_public_observation command_acpi_public_observation
%include "sec/platform_key_health.asm" ; read-only pre-EBS PK warning; never a trust verdict
%include "svc/command_auth.asm" ; Task2020: one owner-signed, exact-capability, bounded-expiry, durable anti-replay boundary for every remote mutator/intercept
%ifdef PAOS_LAB_CHANNEL ; lab builds only; the lab command channel is not in the public source
%include "svc/command_auth_lab.asm" ; W2: LAB1 envelope (separate lab key, node + boot bound, no seq/TTL), lab builds only
%endif
%include "bootmgr/recovery_grant.asm" ; R5 shared strict signed grant/request contract
%include "bootmgr/recovery_route.asm" ; exact same-medium pre-EBS route admission
%include "svc/recovery_controller.asm" ; explicitly owner-armed finite policy
%include "svc/recovery_boot.asm" ; grant admission and one-shot request
%include "svc/lab_return.asm" ; explicit lab-only first-contact recovery timer
%undef command_guestcpu_public_observation
%include "svc/clipboard.asm" ; 3373: typed clipboard verbs; GUI binds its narrow textfield callbacks later
%if !PAOS_PUBLIC_BUILD
%include "svc/command_web.asm" ; 2701: WEBSTRUCT INFO/HEX diagnostic projection over the allocation-free offline structured-data core
%endif
%include "svc/command_privacy.asm" ; 3305: nonce-only public synthetic matrix receipt
%include "svc/command_ai_file.asm" ; bounded installed file -> no-authority advisory projection
%include "svc/command_aihook.asm" ; THE AI-hook PROJECTION over the registry: in-proc verb submit + selector resolver + generated CATALOG + actionable errors (1079, COMMANDS.md §5,§9.3) — the small-model multiplier
%include "svc/command_hook.asm" ; RCQ-15: HOOK typed edge namespace; every edge op re-dispatches its native verb (authority=native)
%include "svc/command_card.asm" ; RCQ-40 J2a: the owner action card (record, CARDPROPOSE/CARDSTAT/CARDCANCEL/AITAINT, one dispatch path, web taint)
%include "svc/command_serial.asm" ; THE SERIAL PROJECTION over the registry: COM1 0x3F8 line-oriented verb RX -> registry dispatch + boot-beacon leg (1078, COMMANDS.md §1-3) — the earliest bare-metal comms-back surface
%include "svc/governor.asm"  ; THE performance governor (1050, GOVERNOR.md): HWP detect/enable + boot-sprint/relax + APERF/MPERF truth-oracle (FREQMSR verb) — within-spec, measure-and-revert
%include "svc/power_mode.asm" ; RC power P1: owner-only POWERMODE eff|bal|perf over the governor's HWP/CPPC request (RAM only, Balanced at boot)
%include "svc/thermal.asm"   ; 1041 thermal-throttle DETECTION+LOGGING + live P-state: DTS monitor (0x19C/0x1A2) + induce/observe/log throttle to the diag ring + APERF/MPERF P-state — THERM/THERM_INDUCE/THROTTLE_LOG/PSTATE? verbs (reuses governor rd_aperf/mperf; AFTER governor)
%include "svc/idle_probe.asm" ; RCQ-27 B2: IDLEPROBE, read-only idle-depth discovery (CPUID + gated MSR reads on every CPU + AMD port check); never enters a deep state (AFTER thermal: shares its staged reply)
%include "svc/power_stat.asm" ; RC power T1: owner-only POWERSTAT, package energy over 100 ms + temperatures (read-only; AFTER thermal and idle_probe)

; ---- L2+ (bus/dev/net/fs/gui/app) — built by the loop from here. ----

; ---- L2  bus (1005): the pre-C3 HAL/PCI subsystem, retro-audited for lock SITES (1075) ----
%include "bus/hal.asm"       ; bounds-checked MMIO ring — shared state: hal_ring/hal_head/hal_oob_count (1075 LOCK site)
%include "bus/pci.asm"       ; PCI config-space scan — shared state: scan result/callback (1075 LOCK site)
%include "bus/pci_claim.asm" ; RCQ-29: which driver took which PCI function (hardware report record)
%include "bus/hest.asm" ; bounded HEST CPU-error ownership decode
%include "bus/acpi.asm"      ; ACPI 2.0 XSDT discovery; exports the live XSDT for DMAR ownership
%include "bus/acpi_table_spans.asm" ; qualified ordered native AML source spans; no namespace/evaluation
%include "dev/power/ec_power.asm" ; RCQ-27: SMBIOS-keyed laptop EC battery/AC + FADT fixed power button (no I/O without a descriptor)
%include "bus/superio.asm"   ; BS0: bounded identity discovery + cleanup KAT (initialized by command_udp)
%include "bus/pci_contain.asm" ; uncorrected AER subtree config stop and boot-local re-arm fence
%include "svc/aer_dma_probe.asm"
%include "svc/aer_poll.asm" ; bounded root-port observations, config stop before Guardian
%include "svc/resilience.asm" ; L5 (1066): PCIe AER + IOMMU/VT-d DMAR fault + root-port completion-timeout handlers — caught+logged+contained, no hard hang. AERINJECT/AERLOG/IOMMUINJECT/IOMMULOG/PCIECTO/PCIECTOINJECT verbs (extends C38 fault surface; reuses C2 diag ring; enumerates real root ports via bus/pci; data defined BEFORE command_udp references its staged-reply buffers)
%include "sec/principal.asm" ; L2 sec (1053): NON-RETROFITTABLE PRINCIPAL seam — owner-tagged task/log/row field + OWNER->OWNER paging-domain switch (CR3 save/reload/restore) + KDF auth derive (reuses crypto_kdf). PRINWRITE/PRINREAD/PRINSWITCH/PRINKDF verbs (additive). Data defined BEFORE command_udp references prin_out_buf/prin_m_* staged-reply state
%include "sec/system_secret.asm" ; SEC slice 2: the SYSTEM secret in an NV|BS variable (pre-EBS load/migrate + the manifest scrub gate); after principal for its record constants
%include "sec/owner_record.asm" ; owner S1a/D5: PaOSOwner record validate/select, stage validate, D5 confirmation classifier
%include "sec/owner_stage_key.asm" ; owner S1b-2c-0: the owner stage key Z, born pre-EBS, NV|BS only (stage MAC + name root)
%include "sec/owner_store.asm" ; owner S1b-1: the pre-EBS owner store pass (after owner_stage_key: needs Z)
%include "sec/replay_floor.asm" ; SEC-replay-record-mac S1: PaOSReplayFloor (NV|BS) pre-EBS signed-request replay floor (after owner_store: needs ows_floor_seeded)
%include "svc/command_owner_stat.asm" ; owner S1b-2: OWNERSTAT, the owner store state after EBS (owner only)
%include "sec/node_identity.asm" ; authenticated wrapped node signing identity (1239)
%include "sec/node_identity_store.asm" ; fixed read-only machine/lifecycle-bound production identity consumer
%include "sec/update_public_policy.asm" ; immutable installed release/channel public authority; default refuses
%include "sec/wifi_store.asm" ; internal owner-bound sealed profile donor; no public verb/private receiver
%include "sec/wifi_profile.asm" ; private local owner profile and revocable opaque intent
%include "sec/job_receipt.asm" ; M-sec (1055): portable owner/cap-scoped scheduler JOB + TSC metering hook + node-identity Ed25519 receipt; JOBRUN/JOBPUB data before command_udp projection
%include "svc/command_sched.asm" ; L5 sched (1048): MULTI-CLASS SCHEDULER POLICY LAYER — declarative sched_class table (owner/forge/throughput/realtime + grid-ready borrowed) + placement-policy HOOK (jobs PLACED not invoked), CPUID topology-aware SPREAD. SCHEDPLACE/SCHEDSTAT registry verbs. Data (sched_m_*/sched_out_buf) defined BEFORE command_udp references them
; 1330b replaces only SMPSTAT's registered handler with the topology-aware
; projection from core/smp; SMPWORK/SMPBENCH and all shared framing stay owned
; by this existing module.
%define command_register_verb smp_command_register_verb
%include "svc/command_smp.asm" ; L5 sched (1114): SMPWORK read/measure verb over frozen AP-owned proof slots
%undef command_register_verb
%define command_guestcpu_public_observation command_guestcpu_public_observation_base
%include "svc/command_guestcpu.asm" ; 1330h0: public read-only single-vCPU registry/AI observability
%undef command_guestcpu_public_observation
%include "svc/command_ssh.asm" ; 2141 SSHHOSTKEY registry projection + exact public-observation-chain extension
; command_auth_required_cap has already required cap=0 and destr=0 before it
; reaches this hook. Match only complete EDID/RESINFO/BROWSERIMG spellings, and
; otherwise keep the established guest/console/SMP public-observation chain
; byte-for-byte. The browser handler applies the existing AUTH1 extension gate
; to parsed START/STOP immediately before either lifecycle mutation.
command_display_public_observation:
    cmp  dword [rdi], 'EDID'
    jne  .resinfo
    cmp  byte [rdi + 4], 0
    je   .public
.resinfo:
    cmp  dword [rdi], 'RESI'
    jne  .browserimg
    cmp  dword [rdi + 4], 'NFO'
    jne  .browserimg
    jmp  .public
.browserimg:
    cmp  dword [rdi], 'BROW'
    jne  .delegate
    cmp  dword [rdi + 4], 'SERI'
    jne  .delegate
    cmp  word [rdi + 8], 'MG'
    jne  .delegate
    cmp  byte [rdi + 10], 0
    jne  .delegate
.public:
    mov  eax, 1
    ret
.delegate:
    jmp  command_guestcpu_public_observation
%include "svc/command_rt.asm" ; L5 sched (1049): HARD-REAL-TIME DEADLINE CLASS — characterizes the 1048 'realtime' row: admission table (default-deny over-budget) + shield/affinity + priority-INVERSION-safe ceiling lock + TSC worst-case-jitter-under-load instrument (non-retrofit seam, SCHEDULER §2). RTLAT/RTADMIT verbs. AFTER command_sched (uses sched_ncores/SC_RT/SC_TPUT); data (rt_m_*/rt_out_buf) defined BEFORE command_udp references them
%if !PAOS_PUBLIC_BUILD
%include "svc/guardian_alert.asm" ; SEC-GA0-lite: Guardian owner-alert data seam over the GD1 spine (no pixels)
%endif
%include "svc/command_audit.asm" ; L5 svc (1314): PER-ACTION AUDIT RECEIPT ring — every UDP-projected registry line leaves a content-bearing receipt (full command text incl. caller nonce) BEFORE dispatch; AUDIT verb reads receipts back for content grading (owned/auditable-AI capdemo §9 Pillar-4). Data (audit_ring/audit_out_buf) defined BEFORE command_udp references them
%include "svc/boot_ab.asm"   ; C3 (1014): BARE-METAL live-wire A/B boot canon — CMOS trial/good counter (0x74/0x75) + verify-then-jump hash + Intel PCH TCO watchdog arm (armed-safe) + AB_STATE/AB_COUNTER verbs. Needs bus/pci (ABASE) + svc/command; data defined BEFORE command_udp references ab_out_buf/ab_m_* staged-reply state
%include "core/tco_deadman.asm" ; hub packet 0011: Intel PCH TCO hardware deadman (opt-in PAOS_TCO_DEADMAN; UNAVAILABLE where the firmware set TCO_LOCK)
%define chainload_linux_arm_bootnext boot_budget_linux_arm_bootnext
%include "svc/command_bootmenu.asm" ; L5 (1015): boot-menu PROJECTION over the registry — MENU_QUERY:<nonce> intercept (live menu snapshot, earned "Chainload ready") + CRASH_STATUS/BOOT_MODE/BOOT verbs (one-shot CMOS 0x76 override + ack-first warm CF9). Data (bm_out_buf/bm_out_ready/bm_reboot_pending) defined BEFORE command_udp references them
%undef chainload_linux_arm_bootnext
%include "svc/m1_checkpoint.asm" ; RCQ-27 POWER-06/07 slice 1: M1 checkpoint format, A/B slot plan, restore rule, wake ledger (pure; no caller yet)
%include "svc/command_shutdown.asm" ; RCQ-27: owner-signed remote SHUTDOWN <nonce> [force-trial] (decide + stage the reply; gui/power_button runs power_execute)
%include "svc/command_manager_heal.asm" ; L5: pre-EBS read-only bootmgfw SHA-256 + MGRSCRUB canon observation (misplaced Manager = violation); no write path
%include "svc/command_recovery_state.asm" ; L5 GE C2: read-only Manager-journal observation + C2RECOVERY policy/health surface
%include "svc/command_software_stop.asm" ; L5 GE C3: read-only durable checkpoint + bounded Manager Safe/known-good/Rescue policy projection; no reset/TCO authority
%include "svc/boot_failure_control.asm" ; LAB-only actual incomplete-P0 startup fault control

%include "svc/normal_deadman_live.asm" ; Normal arming/live pulse + two-LAB IF-on stall control
%include "svc/boot_gates.asm" ; L5 RCQ-32 slice 1: boot-gate stamps (BG4-BG8) + D1-D3 cell keys on replies/serial; measurement only
%include "svc/boot_clock.asm" ; checked EFI-entry clock report, observation only
%include "svc/reserve_gate.asm" ; spec 7.6.7: read-only speed-reserve gate (desktop-ready idle latch); rc-resource kind-3 admission calls it
%include "svc/command_vault_restore.asm" ; L5 GE C4: signed immutable-Vault exact-target restore decision KAT; Manager retains all ESP write authority
%include "svc/command_boot_blackbox.asm" ; L5 GE C6: read-only live PBMH-v2 generation-ring/reset-cause projection
%include "svc/command_health_verdict.asm" ; L5 GE C7: identity-bound boot health projection
%include "svc/optional_fault.asm" ; L5 T2-1: owner-only disposable RAM backend fault

; ---- L4  net ----
%include "net/tcp.asm"       ; TCP 3-way-handshake state machine LOGIC (1044, qemu rung)
%include "svc/ssh.asm"       ; 2141 RFC4253/8731/5647 SSH server transport over the shipped TCP service ABI
%include "svc/ssh_auth.asm"  ; 2142 RFC4252 publickey userauth -> authenticate_bind(ED25519) -> connection-bound principal; PaOSSshKeys store; audit + backoff
%include "svc/ssh_channel.asm" ; 2143 RFC4254 session channel + exec -> the ONE registry dispatch with the connection's principal
%include "core/lib/ssh_crypto_work.asm" ; private compute only; guarded original-D caller below
%include "svc/ssh_client.asm" ; hub packet 0014: the outbound SSH client behind the Terminal's `ssh` (MSI Task3494); defines PAOS_TERMINAL_SSH
%include "net/tls13_certificate_policy.asm" ; bounded native name/date/CA admission
%include "net/tls13.asm"     ; 9523 hostile TLS record-framing floor; Task1058 owns the client
%include "net/http.asm"      ; 9523 bounded HTTP header/chunk framing floor; Task1059 owns fetch
%include "net/arp_cache.asm"  ; ARP resolution CACHE table (insert/hit/age-evict) LOGIC (1045, qemu rung)
%include "net/dhcp.asm"      ; DHCP client OFFER->REQUEST build + ACK parse LOGIC (1046, qemu rung)
%include "net/udp.asm"       ; shared bounded Ethernet/IPv4/UDP framing + parse view
%include "net/dns.asm"       ; DNS A-record query build + response parse LOGIC (1047, qemu rung)
%include "net/notify_http.asm" ; 2504: bounded, pinned TLS provider-neutral POST
%include "data/config_store.asm" ; 2504: protected endpoint/policy envelope
%include "config/keep_config.asm" ; independent default-off push switches
%if !PAOS_PUBLIC_BUILD
%include "svc/push_auth.asm" ; 2504: hashed one-use approval through Task2501
%endif
%include "net/ntp.asm"       ; SNTP four-timestamp offset/delay + absolute epoch anchor (1060)
%include "net/icmp.asm"      ; ICMP echo request->reply LOGIC (1043) + build_reply tournament KAT (1429)

; ---- L4 net class core (1009) + L3 backends — the pre-C3 netdev subsystem, retro-audited (1075) ----
%include "dev/net/loopnet.asm" ; loopnet reference backend (netdev_ops vtable)
%include "dev/net/e1000e_bus_route.asm" ; off-bus-0 single-82574L routing for e1000e (MSI CT @81:00.0); OFF when bus 0 has Intel Ethernet
%define pci_cfg_read32 e1000e_bus_cfg_read32
%define pci_cfg_write32 e1000e_bus_cfg_write32
%include "dev/net/e1000e.asm"  ; e1000e native backend stub (registers into the N-ary table)
%undef pci_cfg_read32
%undef pci_cfg_write32
%include "dev/net/rtl8168.asm" ; runtime-selected RTL8168H backend (strict PCI/MAC identity)
%include "dev/net/rtl8126_profile.inc" ; clean default; explicit lab-only external fallback
%include "dev/net/rtl8125.asm" ; Realtek RTL8125A/B 2.5GbE onboard backend (10ec:8125, XID-gated; absent elsewhere)
%include "dev/net/cdc_ecm.asm" ; USB CDC-ECM Ethernet backend (post-enum netdev bind; TASK_20260906)
%include "dev/net/ax88179b_attach.asm" ; newer AX descriptor/SS plan
%include "dev/net/ax88179b_control.asm" ; checked newer AX initialization; leaves datapath parked
%include "dev/net/ax88179b_link.asm" ; checked newer AX link setup
%include "dev/net/ax_lifetime_observation.asm" ; read-only selected class lifetime/counters
%include "dev/net/ax_lifecycle.asm" ; exact class-owned root retirement and wire rebind
%include "dev/net/ax88179b.asm" ; distinct0200 native backend; precedes CDC class binding
%include "dev/net/cdc_ncm.asm" ; USB CDC-NCM 1.0 Ethernet backend (RCQ-10; e.g. RTL8156B NCM config)
%include "dev/net/ax88179.asm" ; ASIX AX88179 USB-GbE backend (post-enum netdev bind; metal-only validation)
%include "dev/net/ax88179b_codec.asm" ; newer AX packet format only; attachment remains separate
%include "net/netdev.asm"    ; N-ary NIC TABLE + egress-select — shared state: netdev_table/netdev_egress_calls (1075 LOCK site)
%include "net/carrier_drill.asm" ; owned, epoch-bound real PHY outage/restoration primitive
%include "net/usb_command_member.asm" ; read-only USB NIC member projection for the secondary command endpoint
%include "dev/net/virtio_domain.asm" ; 1013: guest-ring backend behind ordinary netdev_ops
%include "net/stack.asm"     ; C10a (1042): ARP reply + 2-verb dispatch registry — emits arp.stack + framework.dispatch (1093 ladder-compose)
%include "svc/command_dns.asm" ; 1025: RESOLVE/DNSCACHE registry projection over the live L4 DNS resolver
%include "svc/command_ntp.asm" ; 1060: NTPSYNC/NTPSTAT registry projection over the live SNTP client
%include "svc/ntp_receipt_store.asm" ; dedicated PaOS-owned NTP audit receipt, exact EFI readback
%include "svc/command_netcheck.asm" ; RCQ-40 J3: NETCHECK, the read-only Network Check over STATUS/NETMON/RESOLVE/HTTPSTAT facts
%include "svc/command_parser_census.asm" ; T1-6.X7 compiled parser limit census
%include "svc/command_hp_serial.asm" ; T6-7.P3 selected HP UART operation
%include "svc/command_tls13.asm" ; 1058: TLSCONNECT/TLSSTAT/TLSKAT registry projection
%include "svc/command_tls13_probe.asm" ; N3 existing NET-authorized observation/exact close
%include "svc/command_net_diag.asm" ; 2140: bounded TCP lifecycle/status projection
%include "svc/command_scap.asm" ; 1108 NATIVE SCREENSHOT SERVER: UDP :9996 dumps the live GOP framebuffer (SCREEN -> START/DATA/COMMIT chunk protocol, monolith port) — the loop's visual-pipeline capture floor. BEFORE command_udp (its :9996 branch fills scap_* route state)
%include "svc/command_filmstrip.asm" ; 2302: fixed-RAM boot checkpoint self-capture + chunked FILMSTRIP read surface
; Task2300's embedded KAT predates the shipped confidentiality floor and calls
; the classifier directly. Redirect only those three in-module KAT calls; live
; dispatch and AUTHSTAT continue to call command_auth_required_cap itself.
%define command_auth_required_cap command_auth_legacy_read_kat_cap
%include "svc/guest_failure_record.asm" ; fixed original guest-failure observation
%include "svc/guest_restart_record.asm" ; fixed original guest-restart observation
%include "svc/driver_domain_return.asm" ; exact post-ACK retirement + retained observation
%include "svc/command_udp.asm" ; THE UDP :9997 PROJECTION over the registry (1099): eth/ARP/IPv4/UDP RX engine + reply datagram over the real e1000e ring — the live comms-back surface
%include "svc/netreturn_diag.asm" ; optional nonce-bound return-readable native NIC diagnostic
%include "svc/service_progress.asm" ; optional bounded return-readable BSP service-gap witness
%undef command_auth_required_cap
%include "svc/command_srvstat.asm" ; 3040: public status, actual auth classifier (outside KAT alias)
%include "svc/hw_report.asm" ; RCQ-29: read-only hardware report (COMPAT HW, [hw.report] boot lines)
%include "svc/command_compat.asm" ; 2908: native read-only compatibility inventory
%include "svc/hook_edge_hw.asm" ; RCQ-29: the typed hw HOOK edge over COMPAT HW (registered from its owner module)
%include "hv/domain_channel.asm" ; 2717 bounded typed console channel framing
%include "svc/cpu_policy_report.asm" ; read-only cached per-CPU policy/execution pages
%include "hv/vmx.asm"        ; L5 hv (1011): proven REAL Intel VMX/VMCS/EPT backend + GUEST* verbs
%include "hv/vm_profile.asm" ; RCQ-18: typed VM profiles (thin-cli), fail-closed parse + cost plan
%include "hv/a1_service_selection.asm" ; signed pre-bind guest reservation, no DMA authority
%include "hv/a1_transaction.asm" ; original START custody only, no effects
%include "hv/a1_policy.asm" ; A1: separate signed policy and complete network profile binding
%include "hv/app_runtime.asm" ; signed candidate's separate bash runtime pair; absent pins refuse
%include "hv/guest_surface.asm" ; 2716: completed guest flips over the existing console split ring
%include "hv/cdp_bridge.asm" ; 2717 isolated parser agent + authenticated diagnostics
%include "hv/svm.asm"        ; L5 hv (1067): declared-but-degenerate AMD SVM peer
%include "hv/hv_ops.asm"     ; L5 hv (1067): CPU-vendor-selected hv_ops vtable + HVOPS registry verb
%include "hv/slat_mmio.asm"  ; RCQ-50 S2: assigned-BAR SLAT range mapper (1 GiB/2 MiB/4 KiB leaves, bounded pool)
%include "hv/guest_lapic.asm" ; RCQ-50 S3: guest virtual x2APIC state and rules (MSI delivery target)
%include "hv/vcpu_ap.asm"   ; T1-5 S7: vCPU1 on a designated AP inside the BSP's custody epoch (gang)
%include "hv/vcpu_svm_record.asm" ; explicit-state helpers shared by both owned CPUs
%include "hv/vcpu_svm_life.asm" ; S7: private CPU-local SVM lifetime, AMD SMP admission remains closed
%include "hv/vcpu_svm_reset.asm" ; S7: owned virtual INIT/SIPI images
%include "hv/vcpu_svm_sample.asm"
%include "hv/vcpu_svm_inputs.asm"
%include "hv/vcpu_svm_prepare.asm"
%include "hv/vcpu_svm_run.asm"
%include "hv/vcpu_svm_dispatch.asm"
%include "hv/vcpu_svm_start.asm"
%include "hv/vcpu_ap_vmx.asm" ; S7: AP-local VMX lifetime (no entry until the gang cycle is wired)
%include "hv/vcpu_ap_host.asm" ; S7 E3: AP-local host-state rewrite before each entry
%include "hv/vcpu_ap_mode.asm" ; S7 checked state helper
%include "hv/vcpu_ap_efer.asm" ; S7 checked state helper
%include "hv/vcpu_ap_controls.asm" ; S7 checked state helper
%include "hv/vcpu_ap_caps.asm" ; S7 checked state helper
%include "hv/vcpu_ap_activity.asm" ; S7 checked state helper
%include "hv/vcpu_ap_hash.asm" ; S7 checked state helper
%include "hv/vcpu_ap_frozen.asm" ; S7 checked state helper
%include "hv/vcpu_ap_go.asm"
%include "hv/vcpu_ap_xstate.asm"
%include "hv/vcpu_ap_msrs.asm"
%include "hv/vcpu_ap_run.asm" ; S7 retained AP executor and exit path
%include "hv/vcpu_bsp.asm" ; S7 BSP GO and cleared VMCS handoff
%include "hv/vcpu_bsp_fault.asm" ; BSP epoch fault retirement
%include "hv/vcpu_cpuid.asm" ; fixed two-CPU feature model and native sampling
%include "hv/vcpu_cpuid_sample.asm" ; generation-bound owned-AP collection
%include "hv/vcpu_bsp_state.asm" ; private selected-vCPU MSR/XCR0/LAPIC dispatch
%include "hv/vcpu_write_guard.asm" ; S7 central BSP VMCS frozen-write gate
%include "hv/vcpu_bsp_context.asm" ; own BSP debug/CR2/XSAVE/automatic MSR state
%include "hv/vcpu_start_resources.asm" ; START private carve in held control span
%include "hv/vcpu_start_controls.asm" ; closed common two-core VMX controls
%include "hv/vcpu_start_vmcs.asm" ; checked dual guest/control VMCS initialization
%include "hv/vcpu_start_close.asm" ; retire AP ownership before table thaw
%include "hv/vcpu_start_seal.asm"
%include "hv/vcpu_start_inputs.asm"
%include "hv/vcpu_start_epoch.asm" ; exact thin SMP2 EPT/epoch table seal
%include "hv/vcpu_start_prepare.asm" ; guarded two-core START preparation
%include "hv/vcpu_observe.asm"
%include "hv/vcpu_status.asm"
%include "hv/vcpu_start_admit.asm" ; exact signed SMP2 admission and READY publication
%include "hv/vcpu_bsp_lifecycle.asm" ; virtual AP reset, SIPI and root-idle wake
%include "hv/vcpu_bsp_dispatch.asm" ; closed deferred AP exit service
%if !PAOS_PUBLIC_BUILD
%include "sec/airlock.asm"   ; M-sec (1056): manifest-selected VMX/EPT airlock + denied host-canary proof
%endif
%include "hv/guestnet.asm"   ; M4 (1109): guest virtio-net + host NAT command/datapath seam
%include "hv/guestsound.asm" ; explicit opt-in bounded playback transport
%include "hv/audio_domain.asm" ; native PAD1 peer; VM owner supplies private channel binding
%include "svc/service_failure_record.asm" ; bounded BSP persistence of native PADN terminal reasons
%include "hv/audio_sound.asm" ; explicitly attached ABI-v2 private PCM queue
%include "hv/audio_playback.asm" ; explicit VM-owned cooperative playback caller
%include "hv/audio_capture.asm" ; explicit VM-owned finite capture caller
%include "hv/pad_channel.asm" ; RCQ-36: VM-owned private PAD1 channel lifecycle
%include "hv/filesystem_wire.asm"
%include "hv/filesystem_queue.asm"
%include "hv/filesystem_domain.asm"
%include "hv/guestfilesystem.asm"
%include "hv/guestentropy.asm" ; opt-in owner-bound RNG through the keep CSPRNG service
%include "hv/guestrestore.asm" ; opt-in private paos.restore control port (snapshot recovery)
%include "hv/guestsnap.asm" ; RCQ-18 S2 in-memory guest snapshot/resume (VMX)
%include "hv/guest_power.asm" ; explicit driver_power v1 resident-vCPU participant
%include "hv/guestinput.asm" ; RCQ-23: virtio-input keyboard+pointer for the desktop-linux guest
%include "hv/input_domain.asm" ; inactive reverse PIN1 typed input; explicit VM-owned binding
%include "hv/input_domain_consumer.asm" ; isolated DOMAIN state, no HUMAN routing
%include "hv/input_domain_bridge.asm" ; checked VM/DOMAIN request+poll, no activation
%include "hv/input_domain_command.asm" ; explicit bounded GUESTVM PIN1 caller, no GUI authority
%include "hv/guestdisplay.asm" ; RCQ-23: private framebuffer (simplefb via screen_info) for the desktop-linux guest
%include "bus/pci_aer_control.asm" ; qualified read-only PCIe/AER controls
%include "bus/pci_bdf.asm"   ; RCQ-18-AMDVI-S3a D-pci: vendor-neutral BDF config access + MMIO UC (moved from hv/vtd;
                              ; placed just before it so the move is byte-neutral: no alignment pad between shifts)
%include "hv/vtd.asm"        ; 1012: Unit-B VT-d bounded secondary-Realtek ownership + reclaim/deadman
%include "hv/amdvi.asm"      ; RCQ-18-AMDVI-S3a: AMD-Vi host DMA protection (IVRS, device table, flush)
%include "hv/amdvi_dma_probe.asm" ; T1-4: signed actual AMD fault/canary Identify diagnostic
%include "hv/device_assignment.asm" ; Task3250: read-only PCIe/IOMMU isolation topology classifier + content KAT (iommu.isolation.topology.kat)
%include "hv/a1_topology.asm" ; separate trusted-peer topology predicate, no START/attach grant
%include "hv/a1_dma_tree.asm" ; unpublished A1 table construction/readback only, no install or START
%include "hv/nic_selection.asm" ; common selected NIC/group identity
%include "hv/a1_nic_selection.asm" ; signed A1 observation, original shared facts; no START grant
%include "hv/driver_domain.asm" ; exact native Linux NIC lifecycle
%include "hv/wifi_wire.asm" ; private fixed association frames, no public secret getter
%include "hv/wifi_channel.asm" ; original owner/START/cutoff and terminal RAM custody
%include "hv/guestwifi.asm" ; separate private hvc1, selected D0008000 only
%include "hv/guestpower.asm" ; C10b-1a paos.power port D0009000 + clean HLT rule, driver domain only
%include "hv/driver_domain_failure.asm" ; selected actual guest failure at signed return
%include "hv/driver_domain_restart.asm" ; selected same-profile guest restart and work
%include "hv/driver_domain_return.asm" ; exact bounded native return quiescence
%include "hv/driver_domain_contained.asm" ; SEC110010 contained-quarantine predicate (outcome 5)
%include "hv/driver_domain_contained_amdvi.asm" ; AMD fresh backend counterparts
%include "hv/driver_domain_boot.asm" ; normal verified boot, full domain once
%include "hv/nd_isolation.asm" ; NDISO1: isolation-refusal record + the one user-text producer (ROOT110035)
%include "hv/driver_domain_net.asm" ; exact same-guest bridge observation
%include "hv/driver_domain_command.asm" ; original authenticated command registry
%include "hv/driver_domain_power.asm" ; bounded driver-domain Shut down (T5-1.C10b-1b)
%include "hv/nic_observation.asm" ; read-only selected NICS export, no START
%include "hv/hp_tcr_observe.asm" ; accepted private observation leaf, no START/scope
%include "hv/pci_census_observation.asm" ; complete read-only eight-function census
%include "hv/driver_domain_learned.asm" ; bounded full census, native node signature
%include "hv/guest_bundle_rx.asm" ; owner-armed Terminal bundle lines, hash only
%include "hv/driver_domain_data.asm"    ; sealed DATA role, signed alternating records
%include "hv/driver_domain_properties.asm" ; existing System Properties facts consumer
%include "hv/nic_assignment.asm" ; physical reset/BAR/IRQ/IOMMU leaf
%include "hv/a1_reset_hp.asm" ; A1: read-only HP reset-method discovery, no qualification
%include "hv/a1_reset_i219.asm" ; A1: Dell discovery linked; dispatcher op1 only
%include "hv/a1_reset_rtl8161.asm" ; A1: Lenovo RTL8161 read-only discovery
%include "hv/a1_reset_rtl8168h.asm" ; A1: Beelink RTL8168H read-only discovery
%include "hv/a1_reset_e5000b.asm" ; A1: MSI E5000B PCI config-only discovery
%include "hv/a1_reset_rtl8125.asm" ; A1: Reatan RTL8125B read-only discovery
%include "hv/a1_reset_dispatch.asm" ; A1: explicit observation routes; mutating routes refuse
%include "hv/driver_domain_a1probe.asm" ; A1: original START R2 op1 caller, reads only
%include "hv/a1_pci_census.asm" ; A1: bounded explicit eight-function config observation
%include "hv/pci_assign.asm"   ; RCQ-36 V2: generic conf1 shadow of one assigned PCI function (HDA now, RCQ-50 GPU)
%include "hv/iommu_owner_witness.asm" ; T1-4: STALEOWNER, retired/poisoned guest IOMMU owner after a guest exit
%include "cognition/gpt2_engine.asm" ; M16-cognition (1061): fp32 CPU transformer (distilgpt2 PXG2 blob) — MODELRUN/MODELOUT/MODELKAT verbs + boot KAT; weights absent -> honest degrade (cog_model_present=0). The 1017 chat tile binds its local-model seam here. AFTER command_udp (uses registry ABI like hv)
%include "cognition/inference_scaling.asm" ; T1-5: real model serial/parallel execution and exact logits witness
%include "cognition/rank_int8.asm" ; RCQ-25 slice 1: bounded ADVISORY int8 prototype rank (choose/abstain); no model, no verb, no caller; advice grants no authority
%include "cognition/tokenize_ascii.asm" ; RCQ-25 native ASCII WordPiece seam; caller authenticates vocabulary; no model/authority
%include "cognition/matmul_u8s8.asm" ; RCQ-25 bounded scalar integer encoder kernel; no model/authority
%include "cognition/matmul_dispatch.asm" ; RCQ-25 explicit CPU/OS/scheduler-gated AVX2 matmul
%include "cognition/dequant_bias.asm" ; RCQ-25 scalar matrix-output scale/bias stage; no model/authority
%include "cognition/encoder_layernorm.asm" ; RCQ-25 caller-owned 384-wide row normalization; no model/authority
%include "cognition/encoder_embedding.asm" ; RCQ-25 PEM1 token sum -> native embedding LayerNorm
%include "cognition/encoder_gelu.asm" ; RCQ-25 scalar erf-form feed-forward activation; no model/authority
%include "cognition/encoder_residual_norm.asm" ; RCQ-25 caller-owned residual Add -> LayerNorm; no model/authority
%include "cognition/encoder_softmax.asm" ; RCQ-25 bounded scalar attention probabilities; no model/authority
%include "cognition/encoder_masked_softmax.asm" ; RCQ-25 native mask -> Softmax with caller scratch
%include "cognition/encoder_batched_matmul.asm" ; RCQ-25 bounded scalar attention QK/PV matmul
%include "cognition/encoder_qkv_layout.asm" ; RCQ-25 pinned Q/K scaling and twelve-head layout
%include "cognition/encoder_attention_unlayout.asm" ; RCQ-25 inverse attention context layout
%include "cognition/encoder_attention.asm" ; RCQ-25 native attention-core composition, caller workspace
%include "cognition/encoder_projection.asm" ; RCQ-25 native quantized projection, caller workspace
%include "cognition/encoder_feedforward.asm" ; RCQ-25 native FFN/GELU/residual LayerNorm block
%include "cognition/encoder_layer.asm" ; RCQ-25 full native BGE layer, caller model/workspace
%include "cognition/encoder_stack.asm" ; RCQ-25 native ordered encoder layers, shared caller workspace
%include "cognition/encoder_token_cls.asm" ; RCQ-25 native token embedding -> encoder -> first-token CLS
%include "cognition/encoder_ascii_cls.asm" ; RCQ-25 native ASCII tokenizer -> caller-admitted CLS
%include "cognition/encoder_text_shape.asm" ; RCQ-25 optional exact-shape preparation and ASCII inference
%include "cognition/encoder_cooperative.asm" ; RCQ-24 caller-owned one-stage inference and cancellation
%include "cognition/encoder_rank_cooperative.asm" ; RCQ-24/25 cooperative text-to-advice with private CLS
%include "cognition/encoder_binding_cooperative.asm" ; RCQ-24/25 bounded incremental digest admission and continuation
%include "cognition/classifier_artifact_admission.asm" ; RCQ-25 owned selected-volume artifacts/lifetime (policy unfrozen)
%include "cognition/router_meter.asm" ; RCQ51 pure router/meter design kernel, no production caller
%include "cognition/router_meter_text.asm" ; RCQ51 callable bounded meter projection, UI join open
%include "cognition/ai_key_consumer.asm" ; RCQ51 callable native queue consumer
%include "cognition/ai_intent_controller.asm" ; RCQ51 BSP idle intent join, no UI/mic backend
%include "cognition/classifier_service.asm" ; authenticated bounded advisory caller
%include "cognition/encoder_pack.asm" ; RCQ-25 native PMW1/BLP1 descriptor and packed ASCII consumer
%include "cognition/encoder_score.asm" ; RCQ-25 normalized prototype scores and packed advisory result
%include "cognition/encoder_packed_shape.asm" ; RCQ-25 prepared exact-shape packed classifier advice
%include "cognition/encoder_score_batch.asm" ; RCQ-25 bounded atomic batch prototype decisions
%include "cognition/encoder_binding.asm" ; RCQ-25 trusted artifact digests before packed advice (BSP only)
%include "cognition/encoder_binding_shape.asm" ; RCQ-25 trusted digests with prepared exact-shape arena
%include "cognition/quantize_f32.asm" ; RCQ-25 SSE2 activation quantizer; no model/authority

; ---- L3 fs (1007,1008): the pre-C3 blockdev class + VFS — composed into the boot by 1093 ----
%include "dev/blk/ramblk.asm" ; C7 (1007): RAM reference backend (healthy) — ramblk_create/ramblk_wedge
%include "dev/blk/vmd.asm"    ; 2026-09-08: Intel VMD domain driver in front of nvme/ahci (child ECAM walk, desktop Z890)
%include "dev/blk/nvme.asm"   ; C7 (1027): NVMe backend — real PCI detect + CC enable + admin/IO queues + IDENTIFY + PRP read/write/flush (QEMU nvme content-graded); degrades to skip when no disk — nvme_blk_create/nvme_self_exercise
%include "dev/blk/nullblk.asm" ; C7 (1027): nullblk DEGENERATE-Nth backend (seam-2nd witness) — nullblk_create
%include "dev/blk/usb_msd.asm" ; Try/Install K W3 (MSI spoke packet 0005): USB mass-storage BOT backend (class bind after HID/NIC; usbmsd0, BLKF_RO, PRIO_DOMAIN)
%include "dev/blk/ahci.asm"   ; C7/1028: AHCI/SATA backend — real HBA port bring-up + IDENTIFY + DMA rw/flush (QEMU ich9-ahci content-graded); degrades to skip when no disk — ahci_blk_create/ahci_self_exercise
%include "fs/storage_access.asm" ; ROB-03/PETER 21:25: ONE storage-access permission gate (live-GPT classify; implicit writes only to PaOS-owned or QEMU test scratch)
%include "fs/volume_pin.asm"     ; T5-15.4: lab MSI writes only its reserved partition
%include "boot/nvram_access.asm" ; PETER 2026-09-30 06:22: NVRAM class of the same gate (PaOS-namespace variables NORMAL; firmware-global/Secure Boot/shim/foreign SENSITIVE -> SPECIAL only, audited)
%include "fs/blockdev.asm"   ; C7 (1007): blockdev class core + ramblk/nvme/ahci backends — emits blockdev.class.seam.init + blockdev.reinit.verify
%include "dev/snd/nullsnd.asm" ; A1 (3201): nullsnd discard/accounting reference backend — nullsnd_create/nullsnd_create_fixture (registers UP into snd/core)
%include "dev/snd/hda_transport.asm" ; RCQ-36 S1 command DMA
%include "dev/snd/hda_codec.asm" ; RCQ-36 S2 bounded inventory
%include "dev/snd/hda_binding.asm" ; RCQ-36: verified reset and secondary-codec policy
%include "dev/snd/hda_route.asm" ; RCQ-36: codec/AFG-bound direct or one-hop analog route planning
%include "dev/snd/hda_conn.asm" ; RCQ-36: packed short connection replies to scoped route edges
%include "dev/snd/hda_capture.asm" ; RCQ-36: cooperative connection graph request/reply acquisition
%include "dev/snd/hda_session.asm" ; RCQ-36: epoch-owned cooperative discovery and graph transport session
%include "dev/snd/hda_route_program.asm" ; RCQ-36: capability-checked cooperative analog codec programming
%include "dev/snd/hda_output.asm" ; RCQ-36 S3 output DMA lifecycle
%include "dev/snd/hda_pcm.asm" ; RCQ-36: owned PCM queue and guarded stop/reset refill
%include "dev/snd/hda_input_route.asm" ; RCQ-36: typed ADC upstream microphone/line-in route
%include "dev/snd/hda_input.asm" ; RCQ-36: cooperative analog input programming and stopped capture batches
%include "dev/snd/hda_backend.asm" ; RCQ-36: trusted-controller cooperative sound backend
%include "dev/snd/hda_loopback.asm"
%include "dev/snd/hda_loopback_native.asm"
%include "dev/snd/hda_runtime.asm" ; RCQ-36 S4 explicit QEMU direct-route tone probe
%include "dev/snd/hda_boot_handoff.asm" ; RCQ-36: one normal post-EBS/pre-IRQ command-engine STOP
%include "snd/core.asm"
%include "snd/uac1_input_sound.asm" ; explicit capture ABI, no boot binding
%include "snd/uac1_sound.asm" ; explicit native USB sound ABI, no boot binding        ; A1 (3201): sounddev CLASS CORE + ABI-v2 stream contract; snd_selftest drives the nullsnd content KAT -> snd.core.nullsnd.kat (ST_SND)
%include "snd/mixer.asm"       ; RCQ-36: caller-owned S16 blocks, per-stream volume/mute and saturating mix
%include "snd/resample.asm"    ; RCQ-36: S16 linear interpolation with exact rational phase across blocks
%include "snd/mix_submit.asm"  ; RCQ-36: staged mixer cursors committed only for whole frames accepted by snd_ops
%include "svc/reinit_power.asm" ; RCQ-27: opt-in bounded extension of driver reinit, no default power execution
%include "svc/command_reinit.asm" ; C7/1065: DRIVER REINIT CONTRACT (declared + honored) over the blockdev seam — REINITINFO/REINIT/REINITCANARY/REINITWORK/REINITSTATE + reinit.* markers (needs ramblk+blockdev)
%include "svc/reinit_power_ahci.asm" ; RCQ27 trusted opt-in AHCI aggregate, no boot call
%include "svc/reinit_power_ram.asm" ; RCQ-27: existing REINIT RAM reference adapter, opt-in only
%include "svc/reinit_power_nvme.asm" ; RCQ-27: opt-in cooperative NVMe pause, controller stays enabled
%include "svc/reinit_power_hda.asm" ; RCQ-27: explicit native polling idle audio participant
%include "svc/reinit_power_loopnet.asm" ; RCQ-27: existing loopnet power reference, opt-in only
%include "svc/reinit_power_e1000e.asm" ; RCQ-27: opt-in retained polling 82574 network power participant
%include "fs/nvme_geometry_probe.asm"
%include "svc/command_blk.asm"    ; C7/1027b: generic block-scratch verb surface BLKINFO/BLKREAD/BLKWRITE/BLKFLUSH over the blockdev DISPATCH (reserved-LBA write allowlist) - command_blk_init
%include "svc/command_storage_inventory.asm" ; Task3470: read-only NVMe identity inventory — GPT/MBR/FS classifier + content KAT (storage.lenovo_nvme.inventory.ok)
%include "svc/command_hda_loopback.asm"
%include "svc/device_failure_record.asm" ; BSP-only persistence of existing HDA snapshots
%include "svc/command_uac1_input_probe.asm" ; owner ABI2 capture and whole drain readback
%include "svc/command_uac1_capture.asm" ; owner finite USB capture and immutable readback
%include "svc/command_uac1_sound.asm" ; explicit owner finite USB sound ABI probe
%include "svc/command_uac1_tone.asm" ; explicit owner finite USB PCM48k probe
%include "svc/command_hda_probe.asm" ; owner-gated HDA_TONE and explicit test-image boot fixture
%include "svc/command_pci_mmio.asm" ; 1117b: real-PCI safe cfg round-trip + LAPIC-ID CAP_MMIO proof verbs
%include "svc/command_hppersist.asm" ; 1107: hot-patch ESP PERSISTENCE — HOTPATCH_PERSIST/CLEAR fold the active patch into a GPT-gap scratch manifest (temp-then-swap safe write) + boot re-apply (hotpatch_persist_replay) so a live patch survives reboot. Needs blockdev+nvme (BEFORE) + hotpatch + command_udp hp_rec_* state
%include "fs/vfs.asm"        ; C8 (1008): VFS write/read-back over the block layer — emits vfs.readback.match (needs blockdev first)
%include "fs/vfs_copy_service.asm"
%include "fs/copy_service_config.asm"
%if !PAOS_PUBLIC_BUILD
%include "hv/browser_appliance.asm" ; 2715: signed minimized Chromium guest artifact + authenticated lifecycle; after VFS for fs_stat layout
%endif
%include "hv/guest_class.asm" ; 3346: versioned class registry + pre-resource encrypted-launch gate
%include "hv/guest_class_kat.asm" ; 3346: isolated QEMU schema/launch boundary controls
%include "fs/fat32_disk.asm" ; 1095a2: read-only MBR/GPT FAT32 stat/read_at over an explicit blk_ops handle
%include "fs/ntfs_disk.asm"   ; 2026-09-07 desktop bring-up: NTFS backend (read + SAFE in-place write) on the fs_ops seam
%include "fs/ext4_disk.asm"
%include "fs/ext4_refusal.asm"   ; RCQ-20 E1: read-only ext2/ext3/ext4 backend (mounts ext0/ext1) on the fs_ops seam
%include "fs/exfat_disk.asm"  ; RCQ-20 exFAT S1: read-only exFAT backend (mounts exfat0/exfat1) on the fs_ops seam
%include "fs/fs_identify.asm" ; RCQ-20 S2: read-only encrypted-volume identification ([fs.refused] markers; never mounts)
%include "fs/ext4_write.asm"  ; RCQ-20 E2a: armed, journaled copy-on-write content writes for ext4 regular files
%include "fs/ext4_ns.asm"     ; RCQ-20 E2b: create/unlink/rename/mkdir/rmdir on the E2a transaction engine
%include "fs/ext4_copy.asm"   ; RCQ-20: the copy job (fs_ops.copy) for armed ext4 mounts
%include "fs/small_copy.asm"  ; bounded native NTFS/FAT copy under current OWNER
%include "svc/command_fs.asm" ; 2400: public read-only FS verbs + owner-gated honest mutator skeletons
%include "svc/hook_edges_svc.asm" ; RCQ-15 S2: fs, fsjob, net, guest, job HOOK edges (native FS*, NETCFG, GUESTVM, JOBPUB/JOBRUN)
%include "cognition/hook_edges_cognition.asm" ; RCQ-15 latched MODELKAT observation, native authority
%include "svc/hook_edge_console.asm" ; RCQ-15 bounded CONS_LIST inventory, native authority
%include "gui/img/hook_edge_image.asm" ; RCQ-15 built-in image service, native authority
%include "svc/hook_edge_partition.asm" ; RCQ-15 selected-volume native PARTLS facts
%include "svc/hook_edge_ntfsstate.asm" ; RCQ-15 saved native NTFS binding facts
%include "svc/hook_edge_classifier.asm" ; RCQ-15 bounded native classifier lifecycle
%include "svc/hook_edges_dev.asm" ; RCQ-15 S3: usb, aer, pci, backlight, session HOOK edges (native USB*, AERLOG/PCIECTO, PCISCAN, BACKLIGHT, SESSIONINFO)
%include "svc/hook_edge_smpstat.asm" ; RCQ-15 passive native SMPSTAT GET/OBSERVE
%include "svc/hook_edges_state.asm" ; RCQ-15 S4: netcheck, ntp, dns, tcp, ssh, idle HOOK edges (native NETCHECK, NTPSTAT/NTPSYNC, DNSCACHE/RESOLVE, TCPSTAT, SSHSTAT/SSHKEYLIST, IDLEPROBE/IDLEDEPTH)
%include "fs/data_crypto_store.asm" ; 1054 marker-selected DATA-volume ciphertext-sector seam; plaintext is never a block-layer argument
%include "fs/safe_write.asm" ; 1057 ONE journal-ready durable envelope path: WAL insertion seam + verified TMP/PRIMARY commit
%include "svc/command_datacrypto.asm" ; 1054 DSECPUT/DSECGET compatibility projection, now routed through fs/safe_write
%include "data/kvstore.asm" ; 1057 OWNED KV store: forever header + principal boundary + encrypted-at-rest DB* registry verbs
%include "svc/command_guestfile.asm" ; 1095a2: GUESTFILE projection over VFS stat/read_at + streaming SHA-256
%include "svc/command_fs_arm.asm" ; RCQ-20: FSARM owner-signed per-volume ext4 write arm
%include "fs/vol_owner.asm"       ; RCQ-21: volume ownership and serialized live identity checks
%include "fs/fs_format.asm"       ; Format F1: removable classification, custody and re-probe (ROOT 108207)
%include "fs/format_job.asm"      ; confirmed F1 custody -> frozen F2 format job
%include "svc/command_fs_own.asm" ; RCQ-21: FSOWN/FSOWNSTAT registry commands
%include "svc/command_memory_consumer.asm" ; authenticated finite CPU scratch; settled idle only
%include "svc/app_bundle.asm" ; signed recipes; per-install enrolled owner trust in every profile
%include "svc/app_execution_state.asm" ; native catalog pre-effect generation and uncertain-result barrier
%include "svc/app_script.asm" ; signed isolated-guest bash snapshots; no native executor
%include "svc/app_package.asm" ; immutable shareable package candidates, no approval/launch
%include "svc/app_analysis.asm" ; content-bound disclosure; no grants or effects
; Separate signed app VM alongside the full driver guest. No shared app authority.
%include "hv/app_vm_memory.asm"
%include "hv/app_vm_payload.asm"
%include "hv/app_vm_cpuid.asm"
%include "hv/app_vm_boot.asm"
%include "hv/app_vm_cpu.asm"
%include "hv/app_vm_amd.asm"
%include "hv/app_vm_intel.asm"
%include "hv/app_vm_dispatch.asm"
%include "hv/app_network.asm" ; scoped app mediation; no NIC or driver VM runtime
%include "hv/app_clock.asm" ; genuine UTC for isolated trusted PID1
%include "hv/app_vm_devices.asm"
%include "hv/settings_update_service.asm" ; qualified updater original-request handoff
%include "hv/app_vm_events.asm"
%include "hv/app_vm.asm"
%include "hv/chat_transport.asm" ; bounded native PCHAT quarantine, no send authority
%include "hv/app_transport.asm" ; actual closed app-vCPU endpoint, prebound WAIT only
%include "svc/command_backup.asm" ; Task1230a: owner-consented RFC9180 keep archive -> bounded TCP + exact receiver ACK

; ---- L4 usb (1031): USB host-controller bring-up + the DEVICE-ENUMERATION SEAM ----
; enum.asm defines the USB_PORT_* equs + usbdev struc, so it MUST precede the xhci
; backend (single-pass). xhci (L3) registers behind the seam via the sanctioned
; L3->L4 usb_hc_register edge; command_usb (L5) projects USBLIST/USBDESC over it.
%include "usb/enum.asm"       ; M-usb (1031): generic port-scan->address->GET_DESCRIPTOR core + usb_nulldev degenerate-2nd
%include "dev/usb/xhci.asm"   ; M-usb (1031): native xHCI controller backend (ported from ../../paos/drivers/xhci/source/*)
%include "svc/reinit_power_xhci.asm" ; explicit native USB participant, no boot attachment
%include "dev/input/hid_rdesc.asm" ; shared finite descriptor/contact layout
%include "dev/usb/hid.asm"    ; USB U3: boot keyboard/mouse consumers over Task2903 interrupt-IN ownership
%include "svc/device_reconnect.asm" ; selected class coordinator, sole INPUT root power
%include "svc/device_reconnect_request.asm" ; strict owner SELFTEST grammar
%include "dev/usb/uac1_stream.asm" ; pure full-speed UAC1 stream descriptor candidate
%include "dev/usb/uac2_stream.asm" ; pure UAC2 PCM16 FS/HS candidate, no activation
%include "dev/usb/uac1_function.asm" ; complete config/AC-scoped terminal provenance
%include "dev/usb/uac2_clock.asm" ; pure UAC2 source controls and RANGE membership
%include "dev/usb/uac2_graph.asm"
%include "dev/usb/uac2_function.asm" ; pure AC clock graph, no activation
%include "dev/usb/uac1_packet.asm" ; fractional FS PCM16 packet geometry
%include "dev/usb/uac1_activate.asm" ; explicit actual-device EP0 activation before ISO
%include "dev/usb/uac1_retire.asm" ; explicit finite owner STOP/AS-alt0 retirement
%include "dev/usb/uac2_prepare.asm" ; owner-bound FS UAC2 EP0 preparation, no PCM backend
%include "svc/uac1_input_probe.asm" ; finite actual capture ABI2 journey
%include "svc/uac1_capture.asm" ; explicit finite native USB input, no boot action
%include "svc/command_usb.asm" ; M-usb (1031): USBLIST/USBDESC observability projection (usb_out_buf framed by command_udp)
%if !PAOS_PUBLIC_BUILD
%include "svc/command_airlock.asm" ; 1316: real xHCI halt->reset containment + VFS nonce continuity proof
%endif
%if !PAOS_PUBLIC_BUILD
%include "svc/kde_phone_identity.asm" ; Task3330: RSA-2048 self-signed X.509 KDE phone-link identity + KATs
%endif

; ---- L2 bus (1006): capability-gated MMIO + LAPIC — composed LAST (arms LAPIC timer; 1093 STRETCH) ----
%include "bus/irq.asm"       ; C6 (1006): CAP_MMIO runtime guard over the LAPIC — emits cap.mmio.enforced + cap.violation.blocked

; ---- L1 core (1075): the SMP lock-SITE retro-audit report + negative canary gate ----
%include "core/smp_audit.asm" ; walks the site registry, flags undeclared shared writes (flagged>=1), emits [smp.lock.audit]

; ---- L6 gui (1016, qemu rung): GUI substrate floor — framebuffer/compositor/WM + vitals ----
%include "gui/theme_tokens.inc" ; F1/D1: the single chrome/taskbar/widget token table (0x00RRGGBB)
%include "gui/cadence_mark.asm" ; 2131: ONE fixed paint-damage/TSC ring + CADMARK/CADSTAT projection
%include "gui/clock_paint.asm" ; T1-3 C5b bounded native scanout record, CLOCK PAINT
%include "gui/present_idle.asm"
%include "gui/compose_idle.asm"
%include "gui/compose_job.asm"
%include "gui/compose_scene.asm"
%include "gui/compose_glyph.asm"
%include "gui/window.asm"     ; M6 (1016): GOP fb primitives + double-buffer/dirty-rect + desktop bg + taskbar clock + window manager w/ open-animation + DPMS tickle + flicker detector (content-graded: verify_gui pixel-checks the two title bars)
%include "gui/shared_surface_portal.asm" ; Task3456: shared surface/portal widget type + slot-14 handle ABI + KAT
; 2122: retain C17's token-only implementation as reference; the public erase
; symbol now lives beside the WM damage path and paints the standing desktop.
%define wm_erase_slot wm_erase_slot_token_legacy
%include "gui/font_aa.asm"    ; D2 (PETER RULING 2026-09-29): 9x19 AA monospace atlas + fb_draw_glyph_aa/str + E5 KAT
%include "gui/chat_app.asm"   ; C17: shared window table, text and chat
%undef wm_erase_slot
%define IMAGE_VIEWER_BUILT 1
%define TEXT_VIEW_BUILT 1
%include "gui/window_mgmt.asm" ; C-1064: desktop window management over the C17 table — RAISE (z-order) + WINNEW/WINMOVE/WINRESIZE/WINGEOM (geometry) + ALTTAB/FOCUSED (focus cycle); 2x titled paint for the GLKVM nonce z-order proof; boot selftest earns wm.multi_window/wm.zorder.raise/wm.move_resize/wm.alttab. AFTER chat_app (reuses wm_* table + chat_out_buf + wm_paint_window/fb_draw_*)
%include "gui/session_restore.asm" ; C-1105/SS-1: durable desktop document on ahci0 GPT-gap LBAs 0x700/0x708; locked boot observes/caches only, and authenticated session restore re-opens document-owned windows. Verbs WINOPEN/WINLIST/WINCLOSE/SESSSAVE/SESSINFO; QEMU session_persist_selftest gates desktop.session.persist. AFTER window_mgmt + blockdev/ahci
%include "sec/app_grants.asm" ; native bounded WAIT grants
%include "fs/app_store_layout.asm"
%include "fs/app_store_data.asm"
%include "sec/app_store_authority.asm"
%include "sec/app_store_seal.asm" ; fixed aggregate MAC, separate Z domain
%include "sec/app_store_intent.asm" ; synchronous fixed original GUI effect scope
%include "svc/app_store.asm" ; authenticated installed inventory and snapshot
%include "sec/app_install_grants.asm" ; owner consent; current instance proof still required
%include "sec/terminal_network_record.asm" ; provider-policy identity/MAC; DATA/Settings enforce Save
%include "sec/terminal_network_store.asm" ; native read/enforcement cache; no Save or tools caller yet
%include "sec/terminal_grants_store.asm" ; separate authenticated read selections; SEC owns live policy
%include "sec/app_binding.asm" ; actual VM/signed snapshot/full window identity
%include "sec/session.asm" ; SS-1: sole login-bound lock/unlock owner; consumes authenticate_bind output and gates session_restore
%include "sec/adopt_decision.asm" ; fixed native decision bridge; no GUI import from FS
%if !PAOS_PUBLIC_BUILD
%include "sec/household.asm" ; RC household voice principal 5: owner marks, one admitted request, the one household dispatch path
%endif
%include "sec/keyprov.asm" ; GA0-K: keystroke provenance (origin slots, line taint, injected-line dispatch as the injecting principal); before the line editors for KT_SIZE
%include "core/unicode_edit.asm" ; RCQ-38 L3b: UTF-8 / grapheme / cell-width primitives (relops, LAYER 1)
%include "fs/terminal_read.asm" ; bounded native public-document leaf names, no authority
%include "svc/terminal_scoped_read.asm" ; private staged reads with mandatory current/copyout proofs
%include "fs/terminal_list.asm" ; pointer-free classified list serialization
%include "fs/public_documents_read.asm" ; authenticated native Documents root callbacks
%include "svc/command_documents.asm" ; DOCNEW/DOCLIST/DOCREAD six-callback native Terminal provider
%include "fs/public_documents.asm" ; distinct native ordinary Documents creator / authenticated DATA record
%include "sec/public_documents_seal.asm" ; independent owner-generation creator-provenance key domain
%include "gui/widget.asm"     ; 1110/F1/F2: stable 80-byte widget prefix + additive form-state tail and type VTABLE
%include "gui/widget_console_grid.asm" ; 2150: allocation-free console_grid over the one shared font8x16 renderer
%include "gui/ansi_interp.asm"         ; 2155: bounded ANSI/VT mode over the shared console_grid cells
%include "gui/interpreter_feed.asm"    ; native stack-owned boundary execution
%include "gui/widget_listview.asm" ; F2: the one bounded table/list view (selection + scroll state)
%include "gui/widget_progress.asm" ; F2: scalar 0..max progress, token-backed shared primitives
%include "gui/widget_chart.asm"
%include "gui/widget_tabstrip.asm" ; D2 (PETER RULING 2026-09-29): tabstrip + menu flyout vtable types (Windows Terminal reference) ; GK1-6: bounded native sparkline/bar chart v1
%include "gui/widget_scalar_inputs.asm" ; GK1-1: shared bounded toggle/slider/numeric state + separator
%include "gui/widget_containers.asm" ; F2: row/col/status registrations and stock rendering
%include "gui/img/img_core.asm" ; 2120: pure bounded BMP/PNG/JPEG decode contract + embedded-fixture verbs/KAT
%include "media/pcm_stream.asm" ; caller-owned native feeder used by opt-in guest PCM
%ifidn RCQ37_VIDEO_BUILT,1
%include "media/av_clock_private.asm"
%include "media/avi_demux_private.asm"
%include "media/mp3_header_private.asm" ; native MPEG1/L3 validated header dependency
%include "media/mp3_bits_private.asm" ; bounded native bitreader
%include "media/mp3_math.asm" ; Classic native entropy/filterbank port, no mutable globals
%include "media/mp3_producer.asm" ; caller-owned bounded MP3 PCM producer/consumer API
%include "gui/img/img_video_bridge.asm"
%include "gui/img/img_mjpeg_frame.asm" ; bounded JPEG -> independently owned native video frame
%include "gui/img/video_frame_queue_private.asm"
%include "gui/shared_surface_pixels.asm"
%include "gui/video_player_private.asm"
%include "gui/video_file_private.asm"
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
%define PMH_MAGIC PMR1H_MAGIC                      ; boot/pmod_loader owns the flat PMH_MAGIC
%include "media/pmr1_host_private.asm"           ; G3a PMR1 host session (pure)
%undef PMH_MAGIC
%include "gui/guest_media_owner_private.asm"     ; G3b media-guest owner + GUESTMEDIA lab verb
%include "gui/guest_media_producer_private.asm"  ; G3b W1 producer seam
%endif
%endif
%endif
; Native file playback: accepted CELT/SILK producer and actual owner consumer.
%if !PAOS_PUBLIC_BUILD
%include "media/opus_packet.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_range.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_celt_energy.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_tf.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_rate.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_cwrs.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_pvq.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_theta.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_tf_shape.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_stereo.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_partition.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_partition_recursive.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_band.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_stereo_band.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_allocation.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_multiband.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_collapse.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_denorm.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_imdct.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_postfilter.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_deemphasis.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_synthesis.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_frame.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/ogg_opus.asm"
%endif
; SILK flat-image section binding: generated ELF code keeps its reviewed text
; and read-only tables; the product PE maps ONE section, so emit both into it.
; Scope only this include. Standalone ELF controls retain original sections.
%define .rodata .text
%if !PAOS_PUBLIC_BUILD
%include "media/opus_silk.asm"
%endif
%undef .rodata
%if !PAOS_PUBLIC_BUILD
%include "media/opus_producer.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "media/opus_playback.asm"
%endif
%if !PAOS_PUBLIC_BUILD
%include "svc/command_opus_playback.asm"
%endif
%include "media/wav_producer.asm"
%include "media/wav_record.asm" ; bounded memory recorder; no capture or storage activation
%include "media/hda_capture_sound.asm" ; explicit stopped HDA batch sound-class view
%include "media/sound_record.asm" ; explicit sound capture -> mixer -> memory WAV consumer
%include "svc/command_wav_playback.asm"
%include "gui/command_video_playback.asm"
%include "hv/guestsound_sink.asm" ; explicit already-open native PCM sink, no activation
%include "gui/img/img_cache.asm" ; 2121: 24 MiB bounded decode/scale-once LRU cache + IMGCACHE
%include "gui/widget_image.asm" ; 2121: stock image vtable type; paint is cache lookup + blit only
%include "gui/img/img_source.asm" ; RCQ-16: bounded native VFS wallpaper snapshots
%include "gui/img/img_cold_idle.asm"
%include "gui/img/img_cold_work.asm"
%include "gui/img/img_cold_cache.asm"
%include "gui/img/img_cold_heap.asm"
%include "gui/img/img_cold_fat.asm"
%include "gui/img/img_cold_job.asm"
%include "gui/img/img_cold_lock.asm"
%include "gui/image_viewer.asm" ; view-only native snapshot window, Explorer caller owns dispatch
%define taskbar_draw_registry taskbar_draw_registry_workspace
%define taskbar_attention_tick taskbar_attention_tick_workspace
%include "gui/calendar.asm" ; clock month flyout, no notifications
%include "gui/taskbar.asm"    ; F1: taskbar registry consumer + TASKBAR/WINATTN bodies
%undef taskbar_draw_registry
%undef taskbar_attention_tick
%include "gui/wintree.asm"    ; F1: bounded UTF-8/%XX WINTREE v1 serialization
%include "gui/snapshot.asm"
%include "hv/snapshot_transport.asm"
%include "gui/app_widget.asm"
%include "hv/app_widget_transport.asm"
%include "gui/treecheck.asm"  ; 2133: WINTREE flat claims checked against framebuffer pixels
%include "gui/wm_pointer.asm" ; F1: ONE human/injected pointer-to-WM dispatcher
%include "gui/demo_three_windows.asm" ; F1: API-only three-window acceptance demo (zero draw calls)
%include "gui/clock_prefs.asm" ; RCQ-17: the TZSET display zone survives a restart (MACed PaOSClockPrefs, storage gate)
%include "core/localization.asm" ; RCQ-38 S1: PCAT1/PRVA1 validation + exact-pointer resolve (no I/O, no allocation)
%include "core/keyboard_layout.asm" ; RCQ-38 L1: Latin layout unit (HID usage -> scalars, dead keys) behind gui/input_route
%include "gui/lang_prefs.asm" ; RCQ-38 S1 R0: MACed PaOSLangPrefs stable-tag selection (separate from PaOSClockPrefs)
%include "gui/kbd_prefs.asm" ; RCQ-38 L2: MACed PaOSKbdPrefs keyboard layout (separate from language and zone)
%include "sec/idle_prefs.asm" ; RC-lock-screen: MACed PaOSIdleLock (the owner's IDLELOCK value)
%include "svc/history.asm" ; RC-history H1: owner activity history, sealed RAM ring, bounded owner/AI query, HISTCFG (PaOSHistCfg)
%include "gui/resource_text.asm" ; RCQ-38 S1: res_text C-string adapter over one bound, validated context
%include "gui/res_pack_boot.asm" ; RCQ-38 S1 R1: the one boot bind point; English needs no I/O, never a boot failure
%include "gui/l10n_paint.asm" ; RCQ-38 l10n L2: the catalog-text painters + the 16x16 UI glyph subset (first caller: H2 gui/help_view)
%include "gui/input_domain_pad.asm" ; explicit DOMN-only native GUI pad
%include "gui/command_gui.asm" ; F1 repairs the orphaned MOUSEINJ/MOUSESTAT/KBINJ/KBDBUF/FLICKER surface
%include "gui/command_res.asm" ; 1104: native-resolution autodetect PROJECTION — RESINFO/RESMODES over the 1077 registry (detection itself is pre-EBS in boot/gop.asm gop_autodetect: EDID preferred, else max GOP mode, SetMode + mode-list capture)
%include "gui/liveness_panel.asm" ; 2100: ladder verb skeletons + owner-signed PLV1 framebuffer liveness witness
%include "gui/form_events.asm"          ; T6-3 bounded per-owner form events/WAIT
%include "gui/form_loader.asm" ; F2: form_spec v1 table/parser, lint-before-allocate loader + FORMLIST/INFO/LOAD/CADENCE
%include "gui/naming_picker.asm" ; 3433: shared live window/form naming projection
%include "gui/summon_palette.asm" ; 3433: desktop-hosted Start/Talk form composition
%if !PAOS_PUBLIC_BUILD
%include "gui/guardian_indicator.asm" ; SEC-GA0-lite: allowlisted tray-cell witness painter (admin ruling 10/08 01:57)
%endif
%include "gui/netmon_form.asm" ; F2: LAUNCH app_sysprops/app_netmon + NETMON_STAT compatibility over forms
%include "gui/command_idle_service.asm" ; T5-11: one presentation-independent command job/calibration turn
%include "gui/console_app.asm" ; 2152: form-backed local verb prompt -> the ONE registry dispatch
%include "gui/lock_fade.asm" ; non-blocking normal sign-in fade, input live first
%include "gui/recovery_notice.asm" ; public fallback notice, ordinary closable form
%include "gui/lock_screen.asm" ; 2502: stock composition over the sole session gate
%include "bus/acpi_hp_s5.asm" ; HP-only hash-pinned fixed preparation, no AML evaluator
%include "gui/power_exec.asm" ; hub packet 0009: leave on purpose after a y/N (BOOT WIN + warm reset, warm reset, ACPI S5)
%include "gui/terminal_app.asm" ; hub packet 0009: the MSI spoke's xterm-compatible Terminal (VT engine + Unicode font) via LAUNCH app_terminal + TERMFEED
%include "gui/start_programs.asm" ; hub packet 0010: Start entries (terminal, settings, restart, shut_down, return_to_windows) as Summon rows + the power confirmation
%include "gui/wifi_local.asm" ; captured local OWNER password/profile action
%include "gui/app_package_disclosure.asm" ; immutable escaped report, no approval
%include "gui/app_package_card.asm" ; native read-only paginated disclosure
%include "gui/adopt_confirm.asm"
%include "gui/format_confirm.asm"
%include "gui/app_confirm.asm" ; native human one-invocation approval
%include "gui/terminal_consent.asm" ; distinct Terminal physical consent/continuous notice
%include "sec/terminal_policy.asm" ; SEC-owned native Terminal policy and callback composition
%include "sec/terminal_network_gate.asm" ; pure native hostname/ClientHello leaves; tools broker composition follows
%include "sec/terminal_network_session.asm"
%include "hv/terminal_network.asm" ; native-only staging core; callbacks default NULL, no endpoint
%include "gui/terminal_provider.asm" ; native GUI provider; SEC registers its table
%include "gui/app_launcher.asm" ; checked bundle desktop entry, native exact-attempt callback
%include "gui/chat_send.asm" ; native human exact-question confirmation for paos.chat
%include "gui/app_launch_flow.asm" ; human native policy -> actual isolated appVM lifecycle
%include "gui/app_install.asm" ; owner install decision for a checked package candidate
%include "sec/account_secret.asm" ; session-only sealed record, no public secret getter
%include "gui/account_local.asm" ; native account approval; actual operation offer remains separate
%include "gui/app_store_install.asm" ; fixed signed candidate catalog writer
%include "gui/app_remove.asm" ; confirmed exact removal, bounded durable phases
%include "gui/app_isolation.asm" ; local deny-only signed APP admission proof
%include "gui/app_ingress.asm" ; owner console selected-VFS signed bundle ingress
%include "gui/card_surface.asm" ; RCQ-40 J2b: the owner action card's window and the owner's key Confirm
%include "gui/config_prefs.asm" ; T5-14: authenticated owner preferences on explicitly provisioned DATA
%include "gui/wallpaper_prefs.asm"
%define SETTINGS_UPDATE_DAILY_POLICY_BUILT 1
%include "gui/settings_updates.asm" ; native Updates front door, trusted backend seam
%include "gui/settings_update_policy.asm" ; exact local-owner signed DATA consent, no restart
%include "gui/settings_terminal_network_consent.asm" ; private native Save custody
%include "gui/settings_terminal_network.asm" ; actual Settings pane, deferred Save
%include "gui/settings_update_daily_policy.asm" ; separate signed daily choice, real original consent
%include "svc/settings_update_app_source.asm" ; fixed signed source readiness, unconfigured refuses
%include "gui/settings_update_backend.asm" ; bounded native updater coordinator, independent FS completion
%include "gui/settings_prefs.asm" ; RCQ-17: the Settings Preferences apply/cancel/reset the display time zone (saved like TZSET)
%include "gui/text_view.asm" ; T5-15: the Text Viewer (textview type, read-once, line Markdown)
%include "gui/app_reader.asm" ; G37: bounded app-fed read-only text
%include "gui/settings_apps.asm" ; Settings > Apps (T5-14)
%include "gui/settings_apps_share.asm" ; physical destination decision, existing tick
; Share's standalone read-only section belongs to the single mapped PE section.
; Keep this binding local: a separate NASM section would append an unmapped tail
; and also capture subsequent modules until their next explicit section switch.
%define .rodata .text
%include "gui/app_share.asm" ; exact installed bytes, native removable frame
%undef .rodata
%include "gui/help_view.asm" ; RCQ-38 H2: the native Help surface (helptext type, Contents / pages), l10n_paint's first caller
%include "gui/power_button.asm" ; RCQ-27: idle-loop power button/battery tick -> the existing Shut down? confirmation
%include "gui/console.asm" ; 2505: quiet non-window login + principal-bound registry projection
%include "gui/hook_edges_gui.asm" ; RCQ-15 S1: term/widget/dpms HOOK edge descriptors
%include "gui/hook_edges_forms.asm" ; current native FORMLIST inventory, unchanged authority
%include "gui/hook_edge_formload.asm" ; bounded FORMLOAD open through original native authority
%include "gui/hook_edges_forminfo.asm" ; native FORMINFO bounded page chunks
%include "gui/hook_edges_display.asm" ; native RESINFO/RESMODES read-only observations
%include "gui/hook_edges_desk.asm" ; RCQ-15 S5: clock, taskbar, lock, wallpaper, clipboard HOOK edges (native CLOCK/TZSET, TASKBAR/WINATTN, LOCKSTATE/LOCK, WALLPAPER, CLIPINFO)

; ---- L3 dev/input (1016b/1016, qemu rung): PS/2 keyboard (IRQ1) + mouse (IRQ12) input floor ----
%include "dev/input/ps2.asm"  ; 8042: IRQ1 scancode ring + IRQ12 aux-packet decode selftest (harness QMP-injected key + motion, content-graded); post-motion draws the mouse cursor sprite -> mouse.cursor/mouse.desktop
%include "dev/input/i2c_hid.asm" ; runtime ACPI+PCI-bound Dell 5490 I2C-HID witness; strict no-op on every foreign platform
%include "dev/input/i2c_dw.asm" ; explicit caller-owned bounded controller ops
%include "dev/input/i2c_hid_session.asm" ; inert generic protocol backend; no discovery/activation
%include "gui/input_route.asm" ; 2151: idle-context kbd_ring drain -> focused textfield
%if IME_BUILT                   ; RCQ-38 I3b-1 (root 15:25 Q1): set in gui/input_route.asm, one value for every floor
%include "gauntlet_v2/docs/ime/generated/ja.inc" ; relops' immutable romaji->kana table (Mozc-derived, BSD-3-Clause)
%include "gauntlet_v2/docs/ime/generated/zh.inc" ; relops' immutable pinyin syllable table (Apache-2.0)
%include "gui/ime_core.asm"     ; RCQ-38 I2: the pre-edit state machine and conversion
%include "gui/ime_view.asm"     ; RCQ-38 I3a: the candidate window and pre-edit layout model
%include "gui/res_pack_image.asm" ; RCQ-38 I1 join: the starter set compiled into the signed image (generated)
%include "gui/res_pack.asm"     ; RCQ-38 I1 join: PREL1 on the boot ESP, else the image set, decided once per boot
%include "gui/ime_dict.asm"     ; RCQ-38 I1: the PDCT1 dictionary through res_pack (defines IME_DICT_LINKED)
%include "gui/ime_route.asm"    ; RCQ-38 I3b-1: the router stage, commit pump, Win+Space and cancels
%endif
%include "gui/guest_desktop.asm" ; RCQ-23: the desktop-linux guest's window, capture and input translation
%include "gui/guest_frame_measure.asm"

; ============================================================================
; Image tail — single-section size symbols. (W^X note: nasm -f bin groups
; section bytes but treats inter-section label math as non-constant, so equ/times
; for these size fields require ONE section. The W^X split is done at RUNTIME by
; boot/paging.asm — image=code+rodata R+X, writable state in a fixed BSS region
; RW+NX — NOT via PE sections. MEMORY_MAP §3.1.)
; ============================================================================
; Writable-data region (core/abi/wdata.inc): every WDATA_DEFER block, after the
; last instruction, starting and ending on an in-memory 4 KiB page boundary so no
; page holds both translated code and hot stores (TCG SMC slow path).
WDATA_EMIT_REGION
; code_end = end of the file-backed bytes.
code_end:
; Zero-fill tail (WDATA_BSS_DEFER blocks): reserved after code_end with no file
; bytes; VirtualSize covers it and the PE loader zero-fills it. Empty -> identical image.
WDATA_EMIT_BSS code_end
code_size      equ wdata_bss_end - code_start            ; VirtualSize / SizeOfCode
code_file_size equ ((code_end - code_start + 0x1FF) & ~0x1FF) ; SizeOfRawData
image_size     equ 0x1000 + ((code_size + 0xFFF) & ~0xFFF)
; Pad .text raw data to FileAlignment so SizeOfRawData bytes exist in the file.
times code_file_size - (code_end - code_start) db 0
