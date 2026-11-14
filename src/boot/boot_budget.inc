; Contract 2306 boot self-test classification table (X-macro source).
;
; BOOT_BUDGET_ROW is the default: run on a current TRIAL boot and through the
; signed on-demand full ladder, but skip on a CONFIRMED boot.  The explicit
; BOOT_BUDGET_ALWAYS whitelist is reserved for a security/fault proof or for a
; historical "selftest" that also constructs a required live subsystem.  This
; file is included twice by boot/header.asm: once to assign stable class ids and
; once to emit the relative-callback table consumed by the single gate.

; Task2324 advisory wait-lint policy. Enforcement stays disabled until metal
; shadow reports prove that protected waits are never blocked.
BOOT_WAIT_LEDGER_MAX             equ 32
BOOT_WAIT_RECONCILE_TOLERANCE_MS equ 2
BOOT_WAIT_OBSERVER_TAX_BUDGET_MS equ 20
BOOT_WAIT_STATIC_LINT_ENFORCE     equ 0

; stable owner, class, explicit budget-ms, protected/advisory-only
%macro BOOT_WAIT_OWNER_ROWS 0
BOOT_WAIT_OWNER 1, io,       5000, 0     ; projected bounded UART writes / phase
BOOT_WAIT_OWNER 2, watchdog, 5000, 1     ; mandatory software-stop watchdog
BOOT_WAIT_OWNER 3, recovery, 500, 1      ; PMOD recovered-hang proof (PMOD_DRILL_TIMEOUT_MS, audit 2(b))
BOOT_WAIT_OWNER 4, security, 5000, 1     ; security/durability floor
%endmacro

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
BOOT_BUDGET_ROW ST_HEAP,                    heap_selftest
BOOT_BUDGET_ROW ST_MEMMAP,                  memmap_selftest
BOOT_BUDGET_ROW ST_MEM_LAYOUT,              mem_layout_selftest

; These named selftests also establish live kernel foundations.
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
BOOT_BUDGET_ROW ST_TCP_HANDSHAKE,            tcp_handshake_selftest
BOOT_BUDGET_ROW ST_TCP_SYNACK,               tcp_build_synack_kat
BOOT_BUDGET_ROW ST_ARP_CACHE,                arp_cache_selftest
BOOT_BUDGET_ROW ST_ARP_LOOKUP,               arp_cache_lookup_kat
BOOT_BUDGET_ROW ST_ARP_INSERT,               arp_cache_insert_kat
BOOT_BUDGET_ROW ST_DHCP_CLIENT,              dhcp_client_selftest
BOOT_BUDGET_ROW ST_DHCP_FIND_OPTION,         dhcp_find_option_kat
BOOT_BUDGET_ROW ST_DHCP_PARSE_ACK,           dhcp_parse_ack_kat
BOOT_BUDGET_ROW ST_DHCP_PARSE_OFFER,         dhcp_parse_offer_kat
BOOT_BUDGET_ROW ST_DHCP_WR_U8,               dhcp_wr_u8_kat
BOOT_BUDGET_ROW ST_DNS_RESOLVER,             dns_resolver_selftest
BOOT_BUDGET_ROW ST_DNS_DECODE_NAME,          dns_decode_name_kat
BOOT_BUDGET_ROW ST_DNS_STREQ,                dns_streq_kat
BOOT_BUDGET_ROW ST_DNS_PARSE_RESPONSE,       dns_parse_response_kat
BOOT_BUDGET_ROW ST_DNS_WR_U8,                dns_wr_u8_kat
BOOT_BUDGET_ROW ST_DNS_SKIP_NAME,            dns_skip_name_kat
BOOT_BUDGET_ROW ST_DNS_ENCODE_QNAME,         dns_encode_qname_kat
BOOT_BUDGET_ROW ST_ICMP_BUILD_REPLY,         icmp_build_reply_kat

; Registry/scheduler/audit rows build live state as well as grading it.
BOOT_BUDGET_ALWAYS ST_CADENCE_REGISTRY,      cadence_registry_selftest
BOOT_BUDGET_ALWAYS ST_COMMAND_REGISTRY,      command_registry_selftest
BOOT_BUDGET_ROW ST_COMMAND_AIHOOK,           command_aihook_selftest
BOOT_BUDGET_ALWAYS ST_SCHED_CLASS,           sched_class_selftest
BOOT_BUDGET_ALWAYS ST_SCHED_RT,              sched_rt_selftest
BOOT_BUDGET_ALWAYS ST_AUDIT,                 audit_selftest
BOOT_BUDGET_ROW ST_COMMAND_SERIAL,            command_serial_selftest
BOOT_BUDGET_ROW ST_VCPU_QUANTUM,              vcpu_quantum_selftest
BOOT_BUDGET_ROW ST_BOOT_CANON,                boot_canon_selftest

; Security whitelist: confirmed boots continue to prove the complete floor.
BOOT_BUDGET_ALWAYS ST_CRYPTO_STANDARD,        crypto_standard_selftest
BOOT_BUDGET_ALWAYS ST_TLS13,                  tls13_selftest_once
BOOT_BUDGET_ALWAYS ST_ED25519,                ed25519_selftest
BOOT_BUDGET_ALWAYS ST_NODE_IDENTITY,          node_identity_selftest
BOOT_BUDGET_ALWAYS ST_CRYPTO_ENVELOPE,        crypto_envelope_selftest
BOOT_BUDGET_ALWAYS ST_PRINCIPAL,              principal_selftest
BOOT_BUDGET_ALWAYS ST_DATA_CRYPTO,            data_crypto_selftest
BOOT_BUDGET_ALWAYS ST_KVSTORE,                kvstore_selftest
BOOT_BUDGET_ALWAYS ST_NODE_ID_CONSUMER,       node_identity_selftest_consumer

; These rows also discover/register the live hardware and service foundations.
BOOT_BUDGET_ALWAYS ST_SMP,                    smp_selftest
BOOT_BUDGET_ALWAYS ST_PCI,                    pci_selftest
BOOT_BUDGET_ALWAYS ST_ACPI,                   acpi_selftest
BOOT_BUDGET_ALWAYS ST_NETDEV,                 netdev_selftest
BOOT_BUDGET_ALWAYS ST_VIRTIO_DOMAIN,          virtio_domain_selftest
BOOT_BUDGET_ALWAYS ST_NET_STACK,              net_stack_selftest
BOOT_BUDGET_ALWAYS ST_BLOCK,                  blk_selftest
BOOT_BUDGET_ROW ST_HOTPATCH_PERSIST,          hotpatch_persist_selftest
BOOT_BUDGET_ROW ST_BOOTMENU,                  bootmenu_selftest
BOOT_BUDGET_ROW ST_MANAGER_HEAL_QEMU,         manager_heal_qemu_selftest
BOOT_BUDGET_ROW ST_MENU_LABELS_QEMU,          menu_labels_qemu_selftest
BOOT_BUDGET_ROW ST_RECOVERY_STATE_QEMU,       recovery_state_qemu_selftest
BOOT_BUDGET_ROW ST_SOFTWARE_STOP_QEMU,        software_stop_qemu_selftest
BOOT_BUDGET_ROW ST_VAULT_RESTORE_QEMU,        vault_restore_qemu_selftest
BOOT_BUDGET_ROW ST_BOOT_BLACKBOX_QEMU,        boot_v2_blackbox_qemu_selftest
BOOT_BUDGET_ROW ST_BOOT_GE_C5_QEMU,           boot_v2_ge_c5_qemu_selftest
BOOT_BUDGET_ROW ST_BOOT_GE_C7_QEMU,           boot_v2_ge_c7_qemu_selftest
BOOT_BUDGET_ALWAYS ST_VFS,                    vfs_selftest
BOOT_BUDGET_ALWAYS ST_XHCI,                   xhci_usb_selftest
BOOT_BUDGET_ALWAYS ST_USB_ENUM,               usb_enum_selftest
BOOT_BUDGET_ALWAYS ST_GUI_COMPOSITOR,         gui_compositor_selftest

BOOT_BUDGET_ROW ST_WMX,                       wmx_selftest
BOOT_BUDGET_ROW ST_SESSION_PERSIST,           session_persist_selftest
BOOT_BUDGET_ROW ST_FORM_LOADER,               form_loader_selftest
BOOT_BUDGET_ROW ST_WINTREE,                   wintree_selftest
BOOT_BUDGET_ROW ST_LIVENESS_PANEL,            liveness_panel_selftest
; Input-arrival waits deliberately are not rows: Task2317 owns that removal.
BOOT_BUDGET_ALWAYS ST_APIC_CAP,               apic_cap_selftest

; PMOD's EB-FE negative (PMOD_DRILL_TIMEOUT_MS, 500 ms) dominates the removable budget.  Skipping
; pmod_init on confirmed boots retains a bounded signature/Merkle/native-format
; proof plus capability_selftest as its non-hanging security floor.  TRIAL and
; signed FULL additionally run the complete loader + deliberate-hang drill.
BOOT_BUDGET_ALWAYS ST_PMOD_FLOOR,              boot_budget_pmod_floor
BOOT_BUDGET_ROW ST_PMOD_FULL,                  pmod_init
BOOT_BUDGET_ROW ST_SCHED_POST_PMOD,            sched_preempt_post_pmod_selftest
BOOT_BUDGET_ROW ST_SERIAL_EQUIVALENCE,         serial_equivalence_kat
BOOT_BUDGET_ROW ST_TIMELINE_ORDERING,          boot_timeline_ordering_kat

BOOT_BUDGET_ALWAYS ST_CAPABILITY_FLOOR,        capability_selftest
BOOT_BUDGET_ALWAYS ST_SECURITY_TRUTH,          security_truth_catalog_selftest
BOOT_BUDGET_ALWAYS ST_VERDICT_BIJECTION,       selftest_verdict_kat
