; PaOS Boot Manager v2 shared wire/storage contract.
;
; This file is deliberately data-only: the standalone manager, full PaOS,
; Rescue, probes, and host tooling must use these exact values.  It does not
; alter the current embedded boot path.  The migration remains additive until
; the protected cutover gate is earned.

; header.asm is assembled before boot/gop.asm. Route its one pre-EBS GOP
; acquisition through the A1 wrapper; boot_v2_health undefines this alias
; before the proven gop_query implementation itself is assembled.
%define gop_query pbm_a1_gop_query_entry

%define PBM_CONTRACT_VERSION          1

; Firmware-honoured compatibility path and manager-owned payload namespace.
%define PBM_PATH_MANAGER              "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
%define PBM_PATH_WINDOWS              "\\EFI\\Microsoft\\Boot\\bootmgfw_orig.efi"
%define PBM_PATH_SLOT_A               "\\EFI\\PaOS\\slots\\paos-a.efi"
%define PBM_PATH_SLOT_B               "\\EFI\\PaOS\\slots\\paos-b.efi"
%define PBM_PATH_RESCUE               "\\EFI\\PaOS\\rescue\\paos-rescue.efi"
%define PBM_PATH_RECOVERY_DESCRIPTOR  "\\EFI\\PaOS\\rescue\\rescue-descriptor.bin"
%define PBM_PATH_STATE0               "\\EFI\\PaOS\\state\\state0.bin"
%define PBM_PATH_STATE1               "\\EFI\\PaOS\\state\\state1.bin"
%define PBM_PATH_MANIFEST             "\\EFI\\PaOS\\vault\\manifest.bin"
%define PBM_PATH_VAULT_MANAGER        "\\EFI\\PaOS\\vault\\manager-recovery.efi"
%define PBM_PATH_VAULT_RESCUE         "\\EFI\\PaOS\\vault\\rescue-recovery.efi"
%define PBM_PATH_VAULT_BASELINE       "\\EFI\\PaOS\\vault\\baseline-paos.efi"
%define PBM_PATH_VAULT_PUBLIC_KEY     "\\EFI\\PaOS\\vault\\owner-public.pem"
%define PBM_PATH_VAULT_RECEIPT        "\\EFI\\PaOS\\vault\\recovery.json"
%define PBM_PATH_VAULT_SIGNATURE      "\\EFI\\PaOS\\vault\\recovery.sig"

; Entry identifiers. Mutable state can select only one of these signed-manifest
; identities; it never carries an arbitrary path.
%define PBM_ENTRY_NONE                0
%define PBM_ENTRY_PAOS_A              1
%define PBM_ENTRY_PAOS_B              2
%define PBM_ENTRY_RESCUE              3
%define PBM_ENTRY_WINDOWS             4
%define PBM_ENTRY_LINUX               5
%define PBM_ENTRY_MAX                 5

%define PBM_PROFILE_NORMAL            0
%define PBM_PROFILE_SAFE              1
%define PBM_PROFILE_RESCUE            2
%define PBM_PROFILE_EXTERNAL          3

%define PBM_MENU_AUTOMATIC            0
%define PBM_MENU_ALWAYS               1
%define PBM_MENU_SHOW_NEXT            2
%define PBM_MENU_DETAILED             3
%define PBM_MENU_TIMEOUT_DEFAULT      5
%define PBM_MENU_TIMEOUT_MIN          3
%define PBM_MENU_TIMEOUT_MAX          30

; A1 keeps its pre-display input window on the monotonic seam.  The visible
; loading denominator is aliased to the canonical graph below so it cannot
; drift independently from P0-P8.
%define PBM_A1_KEY_TICK_US            50000
%define PBM_A1_KEY_WINDOW_TICKS       100

%define PBM_REASON_HEALTHY            0
%define PBM_REASON_OWNER_REQUEST      1
%define PBM_REASON_TRIAL              2
%define PBM_REASON_PREVIOUS_BIP       3
%define PBM_REASON_SAFE_RETRY         4
%define PBM_REASON_ROLLBACK           5
%define PBM_REASON_INVALID_STATE      6
%define PBM_REASON_INVALID_PAYLOAD    7
%define PBM_REASON_RESCUE             8
%define PBM_REASON_CMOS_UNTRUSTED     9

; Canonical CMOS address map.  Do not implement the conversationally inverted
; 0x72/0x73 map.  CMOS is only an early hint; the redundant state journal is
; authoritative.  0x74..0x76 remain migration-era compatibility bytes.
%define PBM_CMOS_BOOT_IN_PROGRESS     0x70
%define PBM_CMOS_LAST_STAGE           0x71
%define PBM_CMOS_CRASH_COUNTER        0x72
%define PBM_CMOS_RESET_REASON         0x73
%define PBM_CMOS_LEGACY_TRIAL         0x74
%define PBM_CMOS_LEGACY_CONFIRMED     0x75
%define PBM_CMOS_LEGACY_ONE_SHOT      0x76

; Redundant state journal.  Each copy is exactly one sector.  CRC32 is over
; bytes [0, PBM_STATE_CRC32); the CRC field itself is not included.
%define PBM_STATE_MAGIC               0x4A534250 ; "PBSJ" little-endian
%define PBM_STATE_SIZE                512
%define PBM_STATE_MAGIC_OFF           0
%define PBM_STATE_VERSION_OFF         4
%define PBM_STATE_SIZE_OFF            6
%define PBM_STATE_GENERATION_OFF      8
%define PBM_STATE_ACTIVE_OFF          16
%define PBM_STATE_PREVIOUS_OFF        17
%define PBM_STATE_TRIAL_OFF           18
%define PBM_STATE_TRIES_LEFT_OFF      19
%define PBM_STATE_VERIFIED_MASK_OFF   20
%define PBM_STATE_QUARANTINE_MASK_OFF 21
%define PBM_STATE_FAILURE_COUNT_OFF   22
%define PBM_STATE_MENU_POLICY_OFF     23
%define PBM_STATE_MENU_TIMEOUT_OFF    24
%define PBM_STATE_PENDING_ENTRY_OFF   25
%define PBM_STATE_PENDING_PROFILE_OFF 26
%define PBM_STATE_BIP_OFF             27
%define PBM_STATE_LAST_ENTRY_OFF      28
%define PBM_STATE_LAST_PROFILE_OFF    29
%define PBM_STATE_SAFE_ATTEMPTED_OFF  30
; The persisted selection reason disambiguates a successful rollback from an
; owner-requested one-shot to Previous.  Existing v1 records have zero here,
; which is PBM_REASON_HEALTHY and remains backward compatible.
%define PBM_STATE_LAST_REASON_OFF     31
%define PBM_STATE_LAST_STARTED_OFF    32
%define PBM_STATE_LAST_COMPLETED_OFF  34
; Manager-written attempt flags (byte 36; v1 records are zero here and older Managers
; ignore it). DELIBERATE_RESCUE marks a Rescue attempt the owner chose in that boot's
; Manager menu (ruling 2026-10-07 23:32, step b): its unacknowledged BIP is cleared
; without counting a failure. A journal one-shot to Rescue is unauthenticated and stays
; counted, as does every automatic fallback to Rescue. Also failure-neutral: an
; owner-chosen Rescue whose StartImage returns (the attempt stays armed, BIP set).
; Residual: older Managers keep byte 36 but never rewrite it, so after a
; new->old->new Manager swap one stale flag can make a single later owner-reason
; Rescue boot failure-neutral; the next arm by this Manager rewrites it.
%define PBM_STATE_LAST_FLAGS_OFF      36
%define PBM_LAST_F_DELIBERATE_RESCUE  0x01
%define PBM_LAST_F_MASK               0x01
; v0.69 physical recovery gesture, independent of A/B failure/quarantine.
; These formerly ignored bytes are zero in existing v1 records. START_ARMED
; records admission before USB/menu; the next admission counts an unresolved
; start, saturating at two. Validated health or an admitted local recovery
; choice closes both bytes. Absence of health cannot distinguish power loss
; from other interrupted/unreported starts; it never grants payload trust.
%define PBM_STATE_START_COUNT_OFF     37
%define PBM_STATE_START_ARMED_OFF     38
%define PBM_STATE_ATTEMPT_NONCE_OFF   40
%define PBM_STATE_READY_NONCE_OFF     48
%define PBM_STATE_EXTERNAL_ENTRY_OFF  56
%define PBM_STATE_EXTERNAL_PENDING_OFF 57
%define PBM_STATE_EXTERNAL_STATUS_OFF 58
%define PBM_STATE_EXTERNAL_NONCE_OFF  64
%define PBM_STATE_EXTERNAL_READY_OFF  72
%define PBM_STATE_QUARANTINED_SHA_OFF 80
%define PBM_STATE_MANIFEST_SEQ_OFF    112
%define PBM_STATE_MANIFEST_SHA_OFF    120
%define PBM_STATE_CRC32               508

; External availability is observational and never aliases PaOS health.
%define PBM_EXTERNAL_STATUS_NONE       0
%define PBM_EXTERNAL_STATUS_READY      1
%define PBM_EXTERNAL_STATUS_UNAVAILABLE 2
%define PBM_EXTERNAL_STATUS_INVALID_PAYLOAD 3

; Owner-signed payload manifest. Bytes [0,768) are signed with RSA-2048
; PKCS#1 v1.5/SHA-256; the exact 256-byte signature occupies [768,1024).
%define PBM_MANIFEST_MAGIC             0x464D4250 ; "PBMF" little-endian
%define PBM_MANIFEST_VERSION           1
%define PBM_MANIFEST_SIZE              1024
%define PBM_MANIFEST_SIGNED_SIZE       768
%define PBM_MANIFEST_SIGNATURE_OFF     768
%define PBM_MANIFEST_SIGNATURE_SIZE    256
%define PBM_MANIFEST_ENTRY_OFF         128
%define PBM_MANIFEST_ENTRY_SIZE        128
%define PBM_MANIFEST_ENTRY_MAX         5
%define PBM_MANIFEST_SEQUENCE_OFF      8
%define PBM_MANIFEST_COUNT_OFF         18
%define PBM_MANIFEST_ENTRY_SHA_OFF     16  ; within an entry
; Header flags (u16, inside the owner signature). PaOS reads SYSTEM_SECRET_MIGRATION_AWARE, and only
; from a manifest it verified itself (boot_v2_manifest_migration_aware, SEC-system-secret-migration-flag).
; The sequence and launched payload that check binds to are claims of the CRC-only handoff (SEC-pbh1).
; TRY_MEDIA (RCQ-29 live Try USB) is the one flag a Manager reads: a Manager that verified the manifest
; takes the read-only try_media_launch and hands PaOS PBM_HF_TRY_MEDIA. Managers before RCQ-29 ignore
; it and boot the media as an ordinary estate. Release tooling never signs both bits together.
%define PBM_MANIFEST_FLAGS_OFF         22
%define PBM_MANIFEST_FLAG_SYSTEM_SECRET_MIGRATION_AWARE 0x0001
%define PBM_MANIFEST_FLAG_TRY_MEDIA    0x0002
; RCQ-29 S2(a): on Try media every slot file is the release PE with bytes [0,16) ("MZ" + 14 zero bytes)
; replaced by "PAOSTRY1" + 8 zero bytes, so firmware, shim or any other loader refuses to start it directly.
; The owner-signed manifest binds the container's size and SHA-256. Only a Manager in an authenticated
; TRY_MEDIA boot accepts the envelope, and it restores qword 0 to "MZ" only after the full container verified.
%define PBM_TRY_ENVELOPE_MAGIC         0x31595254534F4150 ; "PAOSTRY1" little-endian

; Independent owner-signed Rescue descriptor.  Unlike the mutable A/B
; manifest, this read-mostly record names only the canonical Rescue payload.
; Bytes [0,256) are signed and the RSA-2048 signature occupies [256,512).
; Its single entry at offset 128 uses the ordinary 128-byte manifest-entry
; encoding so payload verification has one exact implementation.
%define PBM_RECOVERY_MAGIC             0x44524250 ; "PBRD" little-endian
%define PBM_RECOVERY_VERSION           1
%define PBM_RECOVERY_SIZE              512
%define PBM_RECOVERY_SIGNED_SIZE       256
%define PBM_RECOVERY_SIGNATURE_OFF     256
%define PBM_RECOVERY_SIGNATURE_SIZE    256
%define PBM_RECOVERY_ENTRY_OFF         128

; EFI_LOADED_IMAGE_PROTOCOL.LoadOptions handoff.  Manager creates this before
; StartImage; full PaOS and Rescue reject an unknown version/size.
%define PBM_HANDOFF_MAGIC             0x31484250 ; "PBH1" little-endian
%define PBM_HANDOFF_SIZE              128
%define PBM_HANDOFF_MAGIC_OFF         0
%define PBM_HANDOFF_VERSION_OFF       4
%define PBM_HANDOFF_SIZE_OFF          6
%define PBM_HANDOFF_MANAGER_SEQ_OFF   8
%define PBM_HANDOFF_ATTEMPT_NONCE_OFF 16
%define PBM_HANDOFF_STATE_GEN_OFF     24
%define PBM_HANDOFF_ENTRY_OFF         32
%define PBM_HANDOFF_PROFILE_OFF       33
%define PBM_HANDOFF_REASON_OFF        34
%define PBM_HANDOFF_FLAGS_OFF         35
%define PBM_HANDOFF_LAST_STAGE_OFF    36
%define PBM_HANDOFF_PAYLOAD_SHA_OFF   40
; Non-authoritative GOP observation, CRC-covered and ignored by boot policy.
%define PBM_HANDOFF_GOP_TAG_OFF       72
%define PBM_HANDOFF_GOP_STATUS_OFF    80
%define PBM_HANDOFF_GOP_TAG           0x504F474D ; "MGOP" little-endian
%define PBM_HANDOFF_CRC32             124
; RCQ-28 C1 (admin 2026-10-12 11:40:55): the Manager reports the PaOSManifestFloor
; state after its own entry (load, check and any raise), so PaOS can show it to
; the owner (STATUS manifest_floor=). Zero means not reported: an older Manager
; leaves the byte clear. The floor is defense-in-depth, not a closed downgrade
; control.
%define PBM_HANDOFF_MFLOOR_OFF        88
; Optional reader capability, not authority. Legacy Manager leaves byte89 zero.
; Native emits PBICv2 only for explicit2; all other values keep live PBICv1.
%define PBM_HANDOFF_INIT_READER_OFF   89
; Same-boot Try projection only. Never a saved enrollment/launch authorization.
%define PBM_HANDOFF_TRY_TRUST_OFF     90
%define PBM_HANDOFF_TRY_TRUST_TAG     0x3154 ; T1
%define PBM_HANDOFF_TRY_CERT_OFF      92     ; exact selected DER SHA256, ends before CRC
%define PBM_MFLOOR_UNREAD             0
%define PBM_MFLOOR_HELD               1
%define PBM_MFLOOR_ABSENT             2
%define PBM_MFLOOR_FOREIGN            3     ; ignored; the next healthy commit replaces it
%define PBM_MFLOOR_UNAVAILABLE        4     ; no variable store, or a raise not read back
%define PBM_MFLOOR_SQUATTED           5     ; foreign and undeletable: journal only until the owner clears it

%define PBM_HF_MANAGER_LAUNCHED       0x01
%define PBM_HF_MENU_WAS_VISIBLE       0x02
%define PBM_HF_CMOS_UNTRUSTED         0x04
%define PBM_HF_TRIAL                   0x08
%define PBM_HF_MUTABLE_ATTEMPT         0x10
; RCQ-29 live Try: the Manager launched from media whose owner-signed manifest
; carries PBM_MANIFEST_FLAG_TRY_MEDIA.  It wrote no journal, NVRAM or CMOS and
; never sets MUTABLE_ATTEMPT/TRIAL beside this flag; PaOS then refuses every
; persistent write (internal disks, NVRAM, CMOS) for the whole boot.
%define PBM_HF_TRY_MEDIA               0x80
; B1 recovery projection (Manager B1 policy); ignored safely by pre-B1 children.
%define PBM_HF_B1_MEMTEST_PRESELECT    0x20
%define PBM_HF_B1_SAFE_VIDEO           0x40
; Every handoff flag is its own bit (RCQ-29 srcreview R7: TRY_MEDIA = 0x40 would
; have read as B1 safe video): their sum equals their OR only when none overlap.
%if (PBM_HF_MANAGER_LAUNCHED + PBM_HF_MENU_WAS_VISIBLE + PBM_HF_CMOS_UNTRUSTED + PBM_HF_TRIAL + PBM_HF_MUTABLE_ATTEMPT + PBM_HF_B1_MEMTEST_PRESELECT + PBM_HF_B1_SAFE_VIDEO + PBM_HF_TRY_MEDIA) != (PBM_HF_MANAGER_LAUNCHED | PBM_HF_MENU_WAS_VISIBLE | PBM_HF_CMOS_UNTRUSTED | PBM_HF_TRIAL | PBM_HF_MUTABLE_ATTEMPT | PBM_HF_B1_MEMTEST_PRESELECT | PBM_HF_B1_SAFE_VIDEO | PBM_HF_TRY_MEDIA)
%error "PBM_HF_* handoff flags overlap"
%endif

; PAX1 direct-entry contract. This is deliberately one frozen current-PaOS
; profile, not a general PE loader ABI. The Manager-to-bridge call carries
; RCX=SystemTable, RDX=PBM_HANDOFF, and R8D=PBM_HANDOFF_SIZE; the bridge then
; supplies the compatibility ImageHandle expected by today's PaOS entrypoint.
%define PAX1_ABI_VERSION                1
%define PAX1_IMAGE_BASE                 0x00100000
; When firmware owns part of [PAX1_IMAGE_BASE, +SizeOfImage) (OVMF keeps its
; SEC/PEI/DXE memory from 8 MiB, so more than 7 MiB cannot sit at 1 MiB there)
; the Manager places the same bytes below PAX1_PLACE_CEILING instead, never
; below PAX1_IMAGE_BASE nor across PaOS's fixed AllocateAddress reservations:
; [DIAG_RING_BASE, FILMSTRIP_RING_BASE + FILMSTRIP_RING_PAGES pages)
; (core/abi/diag.inc; test_pax1_placement_host pins the equality).
; The ceiling is the last byte below the PMOD module window at 1 GiB
; (PMOD_REGION_BASE, boot/pmod_loader.asm): the PMOD sandbox CR3 replaces the
; whole 1-2 GiB identity range with that window, so a PaOS image placed there
; loses its own code, stack and IDT on the first sandbox call and the CPU
; resets (QEMU 2 GiB guest, base 0x7C21A000, 2026-10-17).
%define PAX1_PLACE_CEILING              0x3FFFFFFF
%define PAX1_KEEP_OUT_START             0x02000000
%define PAX1_KEEP_OUT_END               0x021EA000
%define PAX1_SECTION_ALIGNMENT          0x1000
%define PAX1_FILE_ALIGNMENT             0x200
%define PAX1_MAX_IMAGE_SIZE             (64 * 1024 * 1024)
%define PAX1_CURRENT_SECTION_FLAGS      0x60000020
%define PAX1_EFI_LOADED_IMAGE_REVISION  0x1000

; Full PaOS publishes this nonce-bound record through the PaOSBootReady UEFI
; runtime variable only after its established strong boot checkpoint. On the
; next entry the Manager matches it to the authoritative BIP journal record,
; persists health/promotion, then consumes the variable. The CRC covers bytes
; [0,124); unused bytes must remain zero.
%define PBM_HEALTH_MAGIC               0x52484250 ; "PBHR" little-endian
%define PBM_HEALTH_SIZE                128
%define PBM_HEALTH_MAGIC_OFF           0
%define PBM_HEALTH_VERSION_OFF         4
%define PBM_HEALTH_SIZE_OFF            6
%define PBM_HEALTH_MANAGER_SEQ_OFF     8
%define PBM_HEALTH_ATTEMPT_NONCE_OFF   16
%define PBM_HEALTH_STATE_GEN_OFF       24
%define PBM_HEALTH_ENTRY_OFF           32
%define PBM_HEALTH_PROFILE_OFF         33
%define PBM_HEALTH_FLAGS_OFF           34
%define PBM_HEALTH_CHECKPOINT_OFF      36
%define PBM_HEALTH_PAYLOAD_SHA_OFF     40
%define PBM_HEALTH_CRC32               124
%define PBM_HEALTH_CHECKPOINT_STRONG   1

; Versioned PaOS initialization checkpoint graph.  This is a bounded runtime
; record, not another boot payload or a general log.  PaOS publishes it through
; the PaOSInitCheckpoint EFI variable; the Manager remains the sole writer of
; PBM_STATE0/PBM_STATE1. CRC32 covers bytes [0,124), including the versioned
; gate extension and reserved zero tail; malformed values earn no admission.
%define PBM_INIT_MAGIC                  0x43494250 ; "PBIC" little-endian
%define PBM_INIT_VERSION                1
; v1 remains readable; v2 adds an explicitly produced last-reached gate.
%define PBM_INIT_GRAPH_VERSION          2
%define PBM_INIT_GATE_OFF               112
%define PBM_INIT_GATE_SOURCE_OFF        113
%define PBM_INIT_GATE_UNKNOWN           255
%define PBM_INIT_GATE_NATIVE            1
%define PBM_INIT_RECORD_SIZE            128
%define PBM_INIT_MAGIC_OFF              0
%define PBM_INIT_VERSION_OFF            4
%define PBM_INIT_SIZE_OFF               6
%define PBM_INIT_GENERATION_OFF         8
%define PBM_INIT_MANAGER_SEQ_OFF        16
%define PBM_INIT_ATTEMPT_NONCE_OFF      24
%define PBM_INIT_STAGE_OFF              32
%define PBM_INIT_TRANSITION_OFF         33
%define PBM_INIT_RESULT_OFF             34
%define PBM_INIT_FLAGS_OFF              35
%define PBM_INIT_SUBSYSTEM_OFF          36
%define PBM_INIT_IMPLICATED_OFF         38
%define PBM_INIT_DEPENDENCIES_OFF       40
%define PBM_INIT_COMPLETED_MASK_OFF     42
%define PBM_INIT_BUDGET_MS_OFF          44
%define PBM_INIT_STARTED_TSC_OFF        48
%define PBM_INIT_FINISHED_TSC_OFF       56
%define PBM_INIT_ELAPSED_MS_OFF         64
%define PBM_INIT_HEALTH_PREDICATE_OFF   68
%define PBM_INIT_FAILURE_POLICY_OFF     69
%define PBM_INIT_PROFILE_OFF            70
%define PBM_INIT_ENTRY_OFF              71
%define PBM_INIT_PAYLOAD_SHA_OFF        72
%define PBM_INIT_STARTED_MS_OFF         104
%define PBM_INIT_CRC32                  124

; P0-P8 are stable wire identities.  Dependency masks use (1 << stage).
%define PBM_INIT_STAGE_P0               0
%define PBM_INIT_STAGE_P1               1
%define PBM_INIT_STAGE_P2               2
%define PBM_INIT_STAGE_P3               3
%define PBM_INIT_STAGE_P4               4
%define PBM_INIT_STAGE_P5               5
%define PBM_INIT_STAGE_P6               6
%define PBM_INIT_STAGE_P7               7
%define PBM_INIT_STAGE_P8               8
%define PBM_INIT_STAGE_COUNT            9
%define PBM_A1_LOADING_CELL_COUNT       PBM_INIT_STAGE_COUNT
%define PBM_A1_FACE_CHECKPOINT_COUNT    PBM_A1_LOADING_CELL_COUNT
%define PBM_INIT_STAGE_NONE             0xFF
%define PBM_INIT_STAGE_ALL_MASK         0x01FF

%define PBM_INIT_TRANSITION_NONE        0
%define PBM_INIT_TRANSITION_STARTING    1
%define PBM_INIT_TRANSITION_COMPLETED   2

%define PBM_INIT_RESULT_NONE            0
%define PBM_INIT_RESULT_HEALTHY         1
%define PBM_INIT_RESULT_DEFERRED        2
%define PBM_INIT_RESULT_DISABLED        3
%define PBM_INIT_RESULT_FAILED          4

; Every graph row explicitly says whether init/reinit is idempotent and whether
; a failed subsystem can be deferred or disabled without losing the boot floor.
%define PBM_INIT_F_MANDATORY            0x01
%define PBM_INIT_F_OPTIONAL             0x02
%define PBM_INIT_F_INIT_IDEMPOTENT      0x04
%define PBM_INIT_F_REINIT_IDEMPOTENT    0x08
%define PBM_INIT_F_DEFER_SAFE           0x10
%define PBM_INIT_F_DISABLE_SAFE         0x20

%define PBM_INIT_HEALTH_HANDOFF         1
%define PBM_INIT_HEALTH_CORE            2
%define PBM_INIT_HEALTH_SERVICES        3
%define PBM_INIT_HEALTH_COMMAND         4
%define PBM_INIT_HEALTH_DISPLAY         5
%define PBM_INIT_HEALTH_UPDATE          6
%define PBM_INIT_HEALTH_DESKTOP         7
%define PBM_INIT_HEALTH_MACHINE         8

%define PBM_INIT_FAILURE_ESCALATE       1
%define PBM_INIT_FAILURE_DEGRADE        2

%define PBM_INIT_RC_OK                  0
%define PBM_INIT_RC_DEGRADED            1
%define PBM_INIT_RC_ESCALATE            2
%define PBM_INIT_RC_ARGUMENT            3
%define PBM_INIT_RC_PERSIST             4
%define PBM_INIT_RC_DEPENDENCY          5
%define PBM_INIT_RC_TRANSITION          6

; Primary subsystem identities are diagnostic keys, not function pointers.
; Runtime code resolves real addresses with LEA and never dereferences a baked
; dq-symbol RVA.
%define PBM_INIT_SUBSYS_BOOT_AUTH        1
%define PBM_INIT_SUBSYS_RECOVERY_FLOOR   2
%define PBM_INIT_SUBSYS_CORE             3
%define PBM_INIT_SUBSYS_SERVICES         4
%define PBM_INIT_SUBSYS_COMMAND          5
%define PBM_INIT_SUBSYS_DISPLAY          6
%define PBM_INIT_SUBSYS_UPDATE           7
%define PBM_INIT_SUBSYS_DESKTOP          8
%define PBM_INIT_SUBSYS_MACHINE          9
%define PBM_INIT_SUBSYS_NONE             0

; Fixed graph-row ABI used by PaOS and host content tests.
%define PBM_INIT_DESC_SIZE               16
%define PBM_INIT_DESC_STAGE_OFF          0
%define PBM_INIT_DESC_FLAGS_OFF          1
%define PBM_INIT_DESC_DEPENDENCIES_OFF   2
%define PBM_INIT_DESC_BUDGET_MS_OFF      4
%define PBM_INIT_DESC_HEALTH_OFF         8
%define PBM_INIT_DESC_FAILURE_OFF        9
%define PBM_INIT_DESC_SUBSYSTEM_OFF      10
