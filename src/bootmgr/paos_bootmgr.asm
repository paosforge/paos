;; MODULE bootmgr/paos_bootmgr
;; LAYER 0
;; EXPORTS
;; IMPORTS core/lib/sha256, bootmgr/rsa2048_verify, bootmgr/pax1_loader
;; CAPS
;; OWNER saga:boot
;; LOCK: pbm_rsa_verify_lock PROTECTS pbm_rsa_verify_scratch_domain
; PaOS Boot Manager v2 — independent UEFI selector and recovery control plane.
;
; PBM_PRODUCTION is emitted only by the guarded release build.  The same stable
; feature macros are exercised individually by the fault/QEMU campaigns; test
; corruption and stop switches are deliberately absent from production builds.
; Deployment remains a separate, protected transaction.

bits 64
%ifdef PBM_MSI_COMBINED_OBJECT
%if PBM_MSI_COMBINED_OBJECT != 1
%error "combined Manager object switch must be 1"
%endif
%ifndef PBM_PRODUCTION
%error "combined Manager requires ordinary production policy"
%endif
%ifndef PBM_DIAG_SB_PAIR
%error "combined qualification requires strict firmware pair"
%endif
%ifnidn __OUTPUT_FORMAT__,elf64
%error "combined Manager must be linked as an ELF64 object"
%endif
%else
org 0
%endif

%include "boot/boot_v2_contract.inc"
%include "boot/native_handoff_trace.inc"

%ifdef PBM_PLATFORM_HP_Q8
%ifndef PBM_PRODUCTION
%error "PBM_PLATFORM_HP_Q8 requires production owner-bound policy"
%endif
%if PBM_PLATFORM_HP_Q8 != 1
%error "PBM_PLATFORM_HP_Q8 must be 1 when defined"
%endif
%endif

; Production carries A1. The immutable OVMF gate enables the same behavior on
; its feature-parity test build, while older focused menu tests retain their
; historical 250 ms reveal-before-select semantics.
%ifdef PBM_PRODUCTION
%define PBM_A1_FACE_ENABLED 1
%endif

%ifdef PBM_PRODUCTION_WITNESS
%ifndef PBM_PRODUCTION
%error "production entry witness requires production policy"
%endif
%ifndef PBM_DIAG_ENTRY_NONCE
%error "production entry witness requires bounded nonce"
%endif
%ifndef PBM_DIAG_ENTRY_CONTINUE
%error "production entry witness must continue through signed policy"
%endif
%endif
%ifdef PBM_TEST_A1_FACE_ORACLE
%define PBM_A1_FACE_ENABLED 1
%endif

; The flat PaOS child prefers its 0x00100000 ImageBase; pax1_prepare_verified_paos
; places it elsewhere below 1 GiB only when firmware owns that range (see
; pax1_loader.asm for the bounds and why PaOS runs there).  PaOS also reserves [0x02000000,0x02010000) as its
; fixed persistent diagnostic ring during P2.  Keep the independent Manager
; above both ranges so firmware can preserve the child base and PaOS can claim
; DIAG_RING_BASE after StartImage without colliding with its resident parent.
PBM_IMAGE_BASE equ 0x02010000
; RCQ-28 finite return: every pre-child boot-services call runs under a
; firmware watchdog. A hang then ends in a firmware reset, which resumes the
; Windows-first BootOrder. The menu is bounded at 30 s; verification of the
; largest slot fits well inside. Firmware children get the UEFI boot-option
; convention (5 min) right before StartImage. The PAX1 direct entry is
; disarmed first, because PaOS owns the machine from then on.
%define PBM_WATCHDOG_SECONDS 120
%define PBM_WATCHDOG_CHILD_SECONDS 300
%define PBM_WATCHDOG_CODE 0x50424D57          ; "PBMW"; codes <= 0xFFFF are firmware-reserved
%if (PBM_WATCHDOG_SECONDS < 60) || (PBM_WATCHDOG_SECONDS > 180)
%error "PBM_WATCHDOG_SECONDS must be 60..180"
%endif

; Bundle-B1 policy consumes the independently published Task1224 records
; without changing their shared v1 boot contract.  Only stable comparison
; bytes enter policy; nonce, journal generation, manifest sequence and payload
; digest remain mandatory identity gates around that comparison.
PBM_B1_EFI_ATTRS                    equ 7
PBM_B1_EVIDENCE_NONE                equ 0
PBM_B1_EVIDENCE_FAILURE             equ 1
PBM_B1_EVIDENCE_SAFE_VIDEO          equ 2
PBM_B1_FAILURE_THRESHOLD            equ 2
PBM_B1_FAILURE_FINGERPRINT_TAG      equ 0xB1000000
PBM_INIT_FAILURE_FINGERPRINT_OFF    equ 108

; PaOSHealthVector v2 (Task1224).  This detailed record is evidence only; the
; compact PaOSBootReady record remains the sole Trial-promotion authority.
PBM_B1_MH_MAGIC                     equ 0x484D4250 ; "PBMH"
PBM_B1_MH_VERSION                   equ 2
PBM_B1_MH_SIZE                      equ 128
PBM_B1_MH_MANAGER_SEQ_OFF           equ 16
PBM_B1_MH_ATTEMPT_NONCE_OFF         equ 24
PBM_B1_MH_STATE_GEN_OFF             equ 32
PBM_B1_MH_INIT_GEN_OFF              equ 40
PBM_B1_MH_PAYLOAD_SHA_OFF           equ 48
PBM_B1_MH_ENTRY_OFF                 equ 80
PBM_B1_MH_PROFILE_OFF               equ 81
PBM_B1_MH_REASON_OFF                equ 82
PBM_B1_MH_STAGE_OFF                 equ 83
PBM_B1_MH_IMAGE_OFF                 equ 84
PBM_B1_MH_CORE_OFF                  equ 85
PBM_B1_MH_DESKTOP_OFF               equ 86
PBM_B1_MH_COMMAND_OFF               equ 87
PBM_B1_MH_STORAGE_OFF               equ 88
PBM_B1_MH_NETWORK_OFF               equ 89
PBM_B1_MH_DISPLAY_OFF               equ 90
PBM_B1_MH_MACHINE_OFF               equ 91
PBM_B1_MH_DIM_COUNT_OFF             equ 92
PBM_B1_MH_COMPLETED_MASK_OFF        equ 94
PBM_B1_MH_FLAGS_OFF                 equ 100
PBM_B1_MH_FAILURE_FINGERPRINT_OFF   equ 112
PBM_B1_MH_CRC32                     equ 124
PBM_B1_MH_DIM_COUNT                 equ 8
PBM_B1_MH_READY                     equ 1
PBM_B1_MH_DEGRADED                  equ 2
PBM_B1_MH_UNAVAILABLE               equ 3
PBM_B1_MH_F_STRONG_CORE             equ 0x0001
PBM_B1_MH_F_OPTIONAL_DEGRADED       equ 0x0002
PBM_B1_MH_F_DISPLAY_ESTABLISHED     equ 0x0004

; Manager-private extension inside the journal's formerly unused, CRC-covered
; tail.  Stored fingerprints are useful only while their exact signed payload
; digests still match the current manifest entries.
PBM_B1_STATE_MAGIC                  equ 0x31503142 ; "B1P1"
PBM_B1_STATE_OFF                    equ 152
PBM_B1_STATE_MAGIC_OFF              equ 152
PBM_B1_STATE_VERSION_OFF            equ 156
PBM_B1_STATE_FLAGS_OFF              equ 157
PBM_B1_STATE_EVIDENCE_MASK_OFF      equ 158
PBM_B1_STATE_SAFE_ENTRY_OFF         equ 159
PBM_B1_STATE_FP_A_OFF               equ 160
PBM_B1_STATE_FP_B_OFF               equ 164
PBM_B1_STATE_SHA_A_OFF              equ 168
PBM_B1_STATE_SHA_B_OFF              equ 200
PBM_B1_STATE_SAFE_SHA_OFF           equ 232
PBM_B1_STATE_END_OFF                equ 264
PBM_B1_STATE_VERSION                equ 1
PBM_B1_F_SUSPECT_HARDWARE           equ 0x01
PBM_B1_F_MEMTEST_PRESELECT          equ 0x02
PBM_B1_F_SAFE_VIDEO_PENDING         equ 0x04
PBM_B1_SLOT_BOTH_MASK               equ ((1 << PBM_ENTRY_PAOS_A) | (1 << PBM_ENTRY_PAOS_B))

; PBM_HF_B1_MEMTEST_PRESELECT / PBM_HF_B1_SAFE_VIDEO: boot/boot_v2_contract.inc,
; beside every other handoff flag and its overlap check (RCQ-29 srcreview R7).

%if PBM_B1_STATE_END_OFF > PBM_STATE_CRC32
%error "B1 Manager policy state overlaps journal CRC"
%endif

; RCQ-29 srcreview N1: the Try handoff flags (prepare_handoff) are assembled
; only with mutable policy; the Try branch exists only with full policy.
%ifdef PBM_FEATURE_FULL_POLICY
%ifndef PBM_FEATURE_MUTABLE
%error "full policy requires mutable policy (the Try handoff flags live there)"
%endif
%endif

; RCQ-29 G1 (root ruling 2026-10-08 17:47): the Try floor is compiled in,
; because Try media has no trusted journal to hold one.  A TRY manifest whose
; signed sequence is below it is refused [boot.v2.try.revoked]: anti-rollback
; for THIS Manager.  It does not revoke an old Try USB, which carries its own
; old Manager; nothing PaOS ships revokes that today (stock shim has no
; paos.manager SBAT entry, no PaOS code writes SbatLevel, .sbat stays
; paos.manager,1).  Per-machine revocation is the owner's: mokutil --mokx the
; old Manager hash, or rotate the MOK.  INVENTORY section 6 (srcreview F1).
%ifndef PBM_TRY_MIN_SEQUENCE
%define PBM_TRY_MIN_SEQUENCE 1
%endif
%if PBM_TRY_MIN_SEQUENCE < 1
%error "PBM_TRY_MIN_SEQUENCE must be at least 1"
%endif

%ifdef PBM_PRODUCTION
%ifndef PBM_FEATURE_MANIFEST
%error "production Manager requires manifest policy"
%endif
%ifndef PBM_FEATURE_MUTABLE
%error "production Manager requires mutable policy"
%endif
%ifndef PBM_FEATURE_HEALTH
%error "production Manager requires health policy"
%endif
%ifndef PBM_FEATURE_FULL_POLICY
%error "production Manager requires full policy"
%endif
%ifndef PBM_FEATURE_MENU
%error "production Manager requires menu policy"
%endif
%ifndef PBM_FEATURE_EXTERNAL
%error "production Manager requires external policy"
%endif
%endif

; Combined mode links the SAME policy into the recorder's signed first child.
; No PE is loaded/mapped manually, and the original loaded-image handle stays
; valid. ELF relocations resolve cross-section RIP-relative references at link.
%ifdef PBM_MSI_COMBINED_OBJECT
section .text align=16
    global pbm_manager_entry:function hidden
%else
; --- MZ + PE32+ header ------------------------------------------------------
mz_header:
    dw 0x5A4D
    times 29 dw 0
    dd pe_header

pe_header:
    dd 0x00004550
    dw 0x8664
    dw 4
    dd 0
    dd 0
    dd 0
    dw optional_header_size
    dw 0x0022

optional_header:
    dw 0x020B
    db 1, 0
    dd text_file_size
    dd rdata_file_size + data_file_size + sbat_file_size
    dd 0
    dd text_rva
    dd text_rva
    dq PBM_IMAGE_BASE
    dd 0x1000
    dd headers_size
    times 6 dw 0
    dd 0
    dd image_size
    dd 0x200
    dd 0
    dw 10
    dw 0
    times 4 dq 0
    dd 0
    dd 16
    times 16 dq 0
optional_header_size equ $ - optional_header

section_headers:
    ; Table and physical order both follow ascending RVA. Keeping them in
    ; lockstep is part of the flat-image displacement invariant below.
    db ".text", 0, 0, 0
    dd text_size
    dd text_rva
    dd text_file_size
    dd text_file_offset
    dd 0, 0
    dw 0, 0
    dd 0x60000020                   ; code + execute + read

    db ".rdata", 0, 0
    dd rdata_size
    dd rdata_rva
    dd rdata_file_size
    dd rdata_file_offset
    dd 0, 0
    dw 0, 0
    dd 0x40000040                   ; initialized data + read

    db ".data", 0, 0, 0
    dd data_size
    dd data_rva
    dd data_file_size
    dd data_file_offset
    dd 0, 0
    dw 0, 0
    dd 0xC0000040                   ; initialized data + read + write

    db ".sbat", 0, 0, 0
    dd sbat_size
    dd sbat_rva
    dd sbat_file_size
    dd sbat_file_offset
    dd 0, 0
    dw 0, 0
    dd 0x40000040                   ; authenticated CSV metadata + read

headers_end:
headers_size equ 0x200
%if (headers_end - $$) > headers_size
%error "Manager PE headers exceed FileAlignment"
%endif
times headers_size - ($ - $$) db 0
%endif

code_start:

%ifdef PBM_DIAG_PREHEALTH_TRACE
; Trace-only witness: nonce-bound SetVariable+GetVariable readback must pass
; before the next operation. Every refusal enters the finite diagnostic
; return, never the ordinary halt or payload launch.
%macro PBM_TRACE_WITNESS 1
    lea  rax, [rel %1]
    mov  [rel diag_current_record], rax
    call diag_persist_entry
    test eax, eax
%ifdef PBM_DIAG_CMOS_IMPORT_REFUSAL
    jnz  diag_trace_failure_return
%else
    jnz  manager_stop
%endif
%endmacro
%endif

; MS x64 firmware calls need RSP = 0 mod 16 at the call. This Manager mixes caller
; parities (efi_entry's 8 pushes enter its callees at 0 mod 16, other paths at 8), so a
; fixed `sub rsp, K` cannot be right on every path: 49 firmware calls ran misaligned on
; at least one path (msi-r4.1, option B). PBM_FW_ENTER/LEAVE replace `sub rsp, K` /
; `add rsp, K` around one firmware call and align it from either parity: the original
; RSP is kept on the aligned stack and restored exactly by `pop rsp`. Stack arguments
; still go to [rsp + 32 ...]. R11 is the scratch (volatile and clobbered by the call
; anyway); nothing between ENTER and the call may read the caller's rsp-relative locals.
%macro PBM_FW_ENTER 1
    mov  r11, rsp
    and  rsp, -16
    push r11
    sub  rsp, ((%1 + 8) & ~15) + 8
%endmacro
%macro PBM_FW_LEAVE 1
    add  rsp, ((%1 + 8) & ~15) + 8
    pop  rsp
%endmacro
; The one deliberate exception: StartImage of a frozen PaOS A/B payload keeps its
; historically proven legacy parity, RSP = 8 mod 16 at the call (32-byte home area).
%macro PBM_FW_ENTER_LEGACY_CHILD 0
    mov  r11, rsp
    and  rsp, -16
    push r11
    sub  rsp, 32
%endmacro
%macro PBM_FW_LEAVE_LEGACY_CHILD 0
    add  rsp, 32
    pop  rsp
%endmacro

; msi-r4.1 diagnostic stage trace (admin 04:04, option A). Only with the production
; entry witness: diag_stage_mark rewrites the PaOSMgrDiag record's phase with a
; strictly increasing stage, best effort and never an authorization input or a
; policy branch. Without PBM_DIAG_STAGE_TRACE every PBM_STAGE expands to nothing,
; so the production image is byte-identical.
%ifdef PBM_DIAG_STAGE_TRACE
%ifndef PBM_PRODUCTION_WITNESS
%error "the stage trace extends the production entry witness only"
%endif
%ifdef PBM_DIAG_PRESELECT_TRACE
PBM_DIAG_STAGE_MAX_WRITES equ 32
%else
PBM_DIAG_STAGE_MAX_WRITES equ 16
%endif
%macro PBM_STAGE 1
    pushfq
    push rax
    mov  eax, %1
    call diag_stage_mark
    pop  rax
    popfq
%endmacro
%else
%macro PBM_STAGE 1
%endmacro
%endif

; Optional preselection observation shares the continuing production witness.
; New phases dominate legacy stages. No policy input, bypass or early stop.
%ifdef PBM_DIAG_PRESELECT_TRACE
%ifndef PBM_DIAG_STAGE_TRACE
%error "preselection trace requires production stage witness"
%endif
%macro PBM_PRESELECT 1
    PBM_STAGE %1
%endmacro
%macro PBM_PRESELECT_RESULT 2
    pushfq
    push rax
    test rax, rax
    mov eax, %1
    jz %%mark
    mov eax, %2
%%mark:
    call diag_stage_mark
    pop rax
    popfq
%endmacro
%else
%macro PBM_PRESELECT 1
%endmacro
%macro PBM_PRESELECT_RESULT 2
%endmacro
%endif

; UEFI entry: RCX=ImageHandle, RDX=SystemTable (MS x64 ABI).
%ifdef PBM_MSI_COMBINED_OBJECT
pbm_manager_entry:
%endif
efi_entry:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  [rel image_handle], rcx
    mov  [rel system_table], rdx
    mov  rax, [rdx + 96]
    mov  [rel boot_services], rax
    mov  rax, [rdx + 88]
    mov  [rel runtime_services], rax

%ifdef PBM_PLATFORM_HP_Q8
    ; A dedicated HP artifact never touches CMOS, including its index port.
    ; Refuse a foreign/unknown platform before diagnostics, serial or policy I/O.
    call manager_hp_platform_valid
    test eax, eax
    jnz  .hp_platform_ok
    mov  rax, 0x8000000000000003     ; EFI_UNSUPPORTED; firmware owns next boot
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret
.hp_platform_ok:
%endif

%ifdef PBM_RESCUE_CAPTURE_NONCE
    call capture_boot_init
%endif

%ifdef PBM_DIAG_ENTRY_NONCE
    lea  rax, [rel diag_record]
    mov  [rel diag_current_record], rax
    ; Nonce-bound entry witness before serial, boot-volume discovery, manifest
    ; or journal I/O. The diagnostic default returns before slots/journals.
    ; Production qualification explicitly requires CONTINUE and exact NVRAM
    ; readback, then enters the unchanged signed policy path.
    call diag_persist_entry
    mov  r12, rax
    call serial_init
    test r12, r12
    jnz  .diag_failed
%ifdef PBM_PRODUCTION_WITNESS
    lea  rdi, [rel str_prod_entry_persisted]
%else
    lea  rdi, [rel str_diag_persisted]
%endif
    call serial_string
%ifdef PBM_DIAG_PRESELECT_TRACE
    lea  rdi, [rel str_preselect_trace_build]
    call serial_string
%endif
%ifdef PBM_DIAG_STAGE_TRACE
    lea  rdi, [rel str_stage_trace_build]  ; this image is the diagnostic trace build
    call serial_string
%endif
%ifdef PBM_DIAG_ENTRY_CONTINUE
    lea  rdi, [rel str_diag_continue]
    call serial_string
    jmp  .diag_continue
%else
    lea  rdi, [rel str_diag_return]
    call serial_string
    mov  rax, 0x8000000000000015    ; EFI_ABORTED: diagnostic, not a boot
    jmp  .diag_return
%endif
.diag_failed:
    lea  rdi, [rel str_diag_failed]
    call serial_string
    mov  rax, 0x8000000000000007    ; EFI_DEVICE_ERROR: no witness credit
.diag_return:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret
%ifdef PBM_DIAG_ENTRY_CONTINUE
.diag_continue:
%endif
%endif

%ifdef PBM_DIAG_PREHEALTH_TRACE
    mov  rax, [rel boot_services]
    mov  ecx, 90
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 32
    call [rax + 0x100]             ; SetWatchdogTimer
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  manager_stop
%endif
    call serial_init
    lea  rdi, [rel str_enter]
    call serial_string
%ifndef PBM_DIAG_PREHEALTH_TRACE
%ifndef PBM_DIAG_RESOLVE_ONLY
    ; Arm before any device/volume/GOP/input protocol call (R2). The two DIAG
    ; trace builds keep their own 90 s watchdog and are not re-armed here.
    PBM_PRESELECT 0x201
    mov  ecx, PBM_WATCHDOG_SECONDS
    call manager_watchdog_set
    PBM_PRESELECT_RESULT 0x202, 0x203
    lea  rdi, [rel str_watchdog_armed]
    test rax, rax
    jz   .watchdog_reported
    lea  rdi, [rel str_watchdog_unavailable]
.watchdog_reported:
    call serial_string
%endif
%endif
    PBM_STAGE 0x101                    ; watchdog armed
%ifdef PBM_DIAG_SB_PAIR
    ; Diagnostic-only actual firmware refusal, before journal/attempt mutation.
    ; No test image entry point runs; failure uses the prelaunch finite return.
    call pbm_sb_negative_probe
    test eax, eax
    jnz manager_stop
%endif
%ifdef PBM_DIAG_RESOLVE_ONLY
    ; Nonproduction Dell hardware discriminator: only resolve the signed
    ; Manager's boot device. A firmware watchdog bounds a stuck protocol
    ; call; every explicit result records a nonce-bound EFI variable and
    ; returns to Windows-first firmware instead of manager_stop/hlt.
    mov  rax, [rel boot_services]
    mov  ecx, 90                    ; seconds; no payload or journal I/O
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 32
    call [rax + 0x100]             ; SetWatchdogTimer
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .diag_resolve_watchdog_error
    call resolve_boot_device
    test eax, eax
    jnz  .diag_resolve_error
    lea  rax, [rel diag_record_resolve_ok]
    mov  [rel diag_current_record], rax
%ifdef PBM_DIAG_VOLUME_ONLY
    ; Preserve the already-proven resolver checkpoint before the one new
    ; SimpleFileSystem call, so a firmware wedge leaves an independent phase.
    call diag_persist_entry
    test eax, eax
    jnz  .diag_volume_pre_witness_error
    call open_boot_volume
    test eax, eax
    jnz  .diag_volume_error
    lea  rax, [rel diag_record_volume_ok]
    mov  [rel diag_current_record], rax
%ifdef PBM_DIAG_MANIFEST_ONLY
    ; Commit the volume checkpoint before touching signed manifest bytes.
    call diag_persist_entry
    test eax, eax
    jnz  .diag_volume_pre_witness_error
    mov  rax, [rel boot_root]
    mov  [rel payload_root], rax
    call load_verify_manifest
    test eax, eax
    jnz  .diag_manifest_error
    lea  rax, [rel diag_record_manifest_ok]
    mov  [rel diag_current_record], rax
    lea  rdi, [rel str_diag_manifest_ok]
    jmp  .diag_resolve_record
.diag_manifest_error:
    lea  rax, [rel diag_record_manifest_error]
    mov  [rel diag_current_record], rax
    lea  rdi, [rel str_diag_manifest_error]
    jmp  .diag_resolve_record
%else
    lea  rdi, [rel str_diag_volume_ok]
    jmp  .diag_resolve_record
%endif
.diag_volume_error:
    lea  rax, [rel diag_record_volume_error]
    mov  [rel diag_current_record], rax
    lea  rdi, [rel str_diag_volume_error]
    jmp  .diag_resolve_record
.diag_volume_pre_witness_error:
    lea  rdi, [rel str_diag_resolve_witness_error]
    call serial_string
    mov  r12d, 1
    jmp  .diag_resolve_disarm
%else
    lea  rdi, [rel str_diag_resolve_ok]
    jmp  .diag_resolve_record
%endif
.diag_resolve_error:
    lea  rax, [rel diag_record_resolve_error]
    mov  [rel diag_current_record], rax
    lea  rdi, [rel str_diag_resolve_error]
.diag_resolve_record:
    call serial_string
    call diag_persist_entry
    mov  r12, rax                   ; preserve result across disarm
.diag_resolve_disarm:
    mov  rax, [rel boot_services]
    xor  ecx, ecx                   ; disarm before returning to firmware
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 32
    call [rax + 0x100]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .diag_resolve_watchdog_error
    test r12, r12
    jnz  .diag_resolve_witness_error
    mov  rax, 0x8000000000000015  ; EFI_ABORTED: diagnostic only
    jmp  .diag_return
.diag_resolve_witness_error:
    lea  rdi, [rel str_diag_resolve_witness_error]
    call serial_string
.diag_resolve_watchdog_error:
    mov  rax, 0x8000000000000007  ; EFI_DEVICE_ERROR; no result credit
    jmp  .diag_return
%endif
%ifdef PBM_A1_FACE_ENABLED
    ; A1 owns one RTC sample and the fixed display-blind key window. Both are
    ; established before any console presentation; policy and payload I/O stay
    ; on the already-proven Manager path below.
    call face_clock_init
%endif

    PBM_PRESELECT 0x204
    call resolve_boot_device
    PBM_PRESELECT_RESULT 0x205, 0x206
    test eax, eax
%ifdef PBM_DIAG_PREHEALTH_TRACE
    jz   .diag_trace_device_ok
    PBM_TRACE_WITNESS diag_trace_3
    jmp  manager_stop
.diag_trace_device_ok:
    PBM_TRACE_WITNESS diag_trace_2
%else
    jnz  manager_stop
%endif
    mov  rax, [rel self_loaded_image]
    lea  rdi, [rel str_self_load_base]
    call serial_string
    mov  rdi, [rax + 64]              ; EFI_LOADED_IMAGE_PROTOCOL.ImageBase
    call serial_hex64
    lea  rdi, [rel str_self_load_base_tail]
    call serial_string
    PBM_PRESELECT 0x207
    call open_boot_volume
    PBM_PRESELECT_RESULT 0x208, 0x209
%ifdef PBM_DIAG_PREHEALTH_TRACE
    test eax, eax
    jz   .diag_trace_volume_ok
    PBM_TRACE_WITNESS diag_trace_5
    jmp  manager_stop
.diag_trace_volume_ok:
    PBM_TRACE_WITNESS diag_trace_4
%endif
    mov  rax, [rel boot_root]
    mov  [rel payload_root], rax
    PBM_STAGE 0x102                    ; boot volume opened
%ifdef PBM_RESCUE_CAPTURE_NONCE
    call capture_export
    cmp byte [rel capture_pending],0
    je .capture_policy
    ; Warm recovery is a diagnostic-only second boot, never a second Rescue
    ; launch or a journal consumption. Return to Windows-first firmware.
    xor ecx,ecx
    call manager_watchdog_set
    mov rax,0x8000000000000015          ; EFI_ABORTED
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
.capture_policy:
%endif
%ifdef PBM_FEATURE_MANIFEST
    PBM_PRESELECT 0x20A
    call load_verify_manifest
    PBM_PRESELECT_RESULT 0x20B, 0x20C
    test eax, eax
    jz   .manifest_ready
%ifdef PBM_DIAG_PREHEALTH_TRACE
    PBM_TRACE_WITNESS diag_trace_7
    jmp  manager_stop
%endif
%ifdef PBM_FEATURE_FULL_POLICY
    ; A live legacy request is itself state that must survive a trust refusal.
    ; Observe it before the Rescue-only manifest fallback: the transactional
    ; importer returns nonzero when a bounded request cannot be adopted, which
    ; deliberately stops this boot without launching another identity.
    call import_legacy_cmos_oneshot
    test eax, eax
    jnz  manager_stop
%endif
    ; The mutable A/B manifest and journal are not the recovery trust root.
    ; If that normal metadata is corrupt, authenticate the separate read-mostly
    ; Rescue descriptor and launch only its canonical Rescue identity without
    ; consulting or mutating normal state.
    call load_verify_recovery_descriptor
    test eax, eax
    jnz  manager_stop
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    mov  qword [rel selected_state_ptr], 0
    mov  qword [rel attempt_state_ptr], 0
    mov  edi, PBM_ENTRY_RESCUE
    call launch_entry
    jmp  manager_stop
.manifest_ready:
%ifdef PBM_DIAG_PREHEALTH_TRACE
    PBM_TRACE_WITNESS diag_trace_6
%endif
%endif
    PBM_STAGE 0x103                    ; manifest verified
%ifdef PBM_FEATURE_MANIFEST
%ifdef PBM_FEATURE_FULL_POLICY
    ; RCQ-29 live Try: an authenticated TRY_MEDIA manifest never reaches the
    ; journal, health, CMOS or menu code below.
    cmp  byte [rel manifest_verified], 1
    jne  .not_try_media
    test word [rel manifest + PBM_MANIFEST_FLAGS_OFF], PBM_MANIFEST_FLAG_TRY_MEDIA
    jnz  try_media_launch
.not_try_media:
%endif
%endif
    PBM_PRESELECT 0x20D
    call select_policy
    PBM_PRESELECT_RESULT 0x20E, 0x20F
%ifdef PBM_DIAG_PREHEALTH_TRACE
    test eax, eax
    jnz  .diag_trace_policy_refused
    PBM_TRACE_WITNESS diag_trace_8
%ifdef PBM_DIAG_HEALTH_INSPECT_TRACE
    ; Extend only the read-only portion of the full-policy path. Compact
    ; health consumption and B1 journal application remain unentered.
    jmp  .policy_ready
%else
    lea  rdi, [rel str_diag_prehealth_loaded]
    call serial_string
    mov  rax, 0x8000000000000015  ; EFI_ABORTED before health/final selection
    jmp  diag_trace_return
%endif
.diag_trace_policy_refused:
    PBM_TRACE_WITNESS diag_trace_9
    lea  rdi, [rel str_diag_prehealth_refused]
    call serial_string
    jmp  manager_stop
%else
    test eax, eax
    jnz  manager_stop
%endif
    PBM_STAGE 0x104                    ; journal selected
%ifdef PBM_FEATURE_MANIFEST
%ifndef PBM_FEATURE_FULL_POLICY
    call enforce_manifest_state_floor
    test eax, eax
    jz   .policy_ready
    mov  byte [rel manifest_verified], 0
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
%endif
%endif
.policy_ready:
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call r5_manager_consume_request
    test eax,eax
    jnz manager_stop
%endif
%endif
%ifdef PBM_FEATURE_HEALTH
%ifdef PBM_FEATURE_FULL_POLICY
    ; Inspect detailed B1 evidence while the exact BIP identity is still the
    ; authoritative journal state.  Persistence waits until after compact
    ; strong-health consumption so this inspection cannot invalidate the
    ; generation that grants promotion authority.
    PBM_PRESELECT 0x210
    call b1_inspect_policy_evidence
    PBM_PRESELECT 0x211
%ifdef PBM_DIAG_HEALTH_INSPECT_TRACE
    PBM_TRACE_WITNESS diag_trace_10
%ifdef PBM_DIAG_HEALTH_CONSUME_TRACE
    call diag_require_bootready_absent
    test eax, eax
    jz   .diag_health_absent
    PBM_TRACE_WITNESS diag_trace_13
    lea  rdi, [rel str_diag_bootready_refused]
    call serial_string
    jmp  manager_stop
.diag_health_absent:
    PBM_TRACE_WITNESS diag_trace_11
%else
    lea  rdi, [rel str_diag_health_inspected]
    call serial_string
    mov  rax, 0x8000000000000015  ; no health/journal mutation or slot launch
    jmp  diag_trace_return
%endif
%endif
%endif
    PBM_PRESELECT 0x213
    call consume_strong_health
    PBM_PRESELECT_RESULT 0x214, 0x215
%ifdef PBM_DIAG_HEALTH_CONSUME_TRACE
    test eax, eax
    jnz  manager_stop
    cmp  byte [rel health_consumed], 0
    jne  manager_stop
    PBM_TRACE_WITNESS diag_trace_12
%ifdef PBM_DIAG_CMOS_PEEK_TRACE
    ; Continue through B1 apply/external reconciliation only on the copied
    ; gen38 no-BIP/no-external-pending estate; both must be quiet there.
%else
    lea  rdi, [rel str_diag_health_consumed_quiet]
    call serial_string
    mov  rax, 0x8000000000000015  ; before B1 application/journal mutation
    jmp  diag_trace_return
%endif
%else
    test eax, eax
    jnz  manager_stop
%endif
%ifdef PBM_FEATURE_FULL_POLICY
    PBM_PRESELECT 0x216
    call b1_apply_policy_evidence
    PBM_PRESELECT_RESULT 0x217, 0x218
    test eax, eax
    jnz  manager_stop
%endif
%ifdef PBM_TEST_STOP_AFTER_HEALTH_CHECK
    jmp  manager_stop
%endif
    PBM_STAGE 0x105                    ; strong health consumed/ignored, B1 applied
    cmp  byte [rel health_consumed], 1
    jne  .health_ready
%ifdef PBM_TEST_STOP_AFTER_HEALTH_CONSUME
    jmp  manager_stop
%else
%ifndef PBM_FEATURE_FULL_POLICY
    ; Re-read the durable journal rather than trusting only our work buffer.
    call select_policy
    test eax, eax
    jnz  manager_stop
    call enforce_manifest_state_floor
    test eax, eax
    jnz  manager_stop
%endif
%endif
.health_ready:
%ifdef PBM_FEATURE_EXTERNAL
    PBM_PRESELECT 0x219
    call reconcile_external_health
    PBM_PRESELECT_RESULT 0x21A, 0x21B
    test eax, eax
    jnz  manager_stop
%endif
%ifdef PBM_FEATURE_FULL_POLICY
    ; Full PaOS sends BOOT WIN and (with runtime services) BOOT LINUX through a
    ; verified firmware BootNext straight to the OS loader, never CMOS
    ; (command_bootmenu.asm .win/.linux), so that switch never enters this
    ; Manager: the journal keeps BIP=1 beside a PaOSBootReady record, which
    ; consume_strong_health folds above on the next entry. The historical CMOS
    ; byte still carries BOOT DIAG and BOOT LINUX without runtime services:
    ; transactionally adopt that bounded request into the authoritative journal
    ; before final policy selection so in-band target control needs no GLKVM.
%ifdef PBM_DIAG_CMOS_PEEK_TRACE
    PBM_TRACE_WITNESS diag_trace_14
%ifdef PBM_DIAG_CMOS_IMPORT_REFUSAL
%ifdef PBM_TEST_LEGACY_TXN_CASE
    ; QEMU-only mutable CMOS fixture. Production diagnostic reads the live
    ; one-shot byte; this never runs on a signed metal sidecar.
    call legacy_txn_fixture_seed
%endif
%endif
    call legacy_cmos_oneshot_read
    cmp  al, 0
    je   .diag_cmos_zero
    cmp  al, 1
    je   .diag_cmos_request_1
    cmp  al, 2
    je   .diag_cmos_request_2
    cmp  al, 3
    je   .diag_cmos_request_3
    PBM_TRACE_WITNESS diag_trace_24
    lea  rdi, [rel str_diag_cmos_invalid]
    jmp  .diag_cmos_emit
.diag_cmos_zero:
    PBM_TRACE_WITNESS diag_trace_20
    lea  rdi, [rel str_diag_cmos_zero]
    jmp  .diag_cmos_emit
.diag_cmos_request_1:
    PBM_TRACE_WITNESS diag_trace_21
%ifdef PBM_DIAG_CMOS_IMPORT_REFUSAL
    lea  rdi, [rel str_diag_cmos_request]
    call serial_string
    ; The exact gen38 probe may enter the real importer only when the
    ; authenticated manifest lacks Windows. This makes the diagnostic
    ; observational: import must refuse before any journal/CMOS write.
    mov  edi, PBM_ENTRY_WINDOWS
    call integrity_vault_select_entry
    test rax, rax
    jnz  .diag_import_guard_refused
    PBM_TRACE_WITNESS diag_trace_25
    lea  rdi, [rel str_diag_import_enter]
    call serial_string
    call import_legacy_cmos_oneshot
    test eax, eax
    jz   .diag_import_unexpected
    call legacy_cmos_oneshot_raw_read
    cmp  al, 1
    jne  .diag_import_unexpected
    PBM_TRACE_WITNESS diag_trace_26
    lea  rdi, [rel str_diag_import_refused]
    jmp  .diag_cmos_emit
.diag_import_guard_refused:
    PBM_TRACE_WITNESS diag_trace_27
    lea  rdi, [rel str_diag_import_ineligible]
    jmp  .diag_cmos_emit
.diag_import_unexpected:
    PBM_TRACE_WITNESS diag_trace_28
    lea  rdi, [rel str_diag_import_unexpected]
    jmp  .diag_cmos_emit
%else
    lea  rdi, [rel str_diag_cmos_request]
    jmp  .diag_cmos_emit
%endif
.diag_cmos_request_2:
    PBM_TRACE_WITNESS diag_trace_22
    lea  rdi, [rel str_diag_cmos_request]
    jmp  .diag_cmos_emit
.diag_cmos_request_3:
    PBM_TRACE_WITNESS diag_trace_23
    lea  rdi, [rel str_diag_cmos_request]
.diag_cmos_emit:
    call serial_string
    mov  rax, 0x8000000000000015  ; no legacy import/final selection/launch
    jmp  diag_trace_return
%endif
    PBM_PRESELECT 0x21C
    call import_legacy_cmos_oneshot
    PBM_PRESELECT_RESULT 0x21D, 0x21E
    test eax, eax
    jnz  manager_stop
%endif
    PBM_STAGE 0x106                    ; legacy CMOS request handled
    mov  byte [rel health_checked], 1
%ifdef PBM_FEATURE_FULL_POLICY
    ; The first pass deliberately only loads the journal so health can close a
    ; pending attempt before failure or one-shot policy runs.
    PBM_PRESELECT 0x21F
    call select_policy
    PBM_PRESELECT_RESULT 0x225, 0x226
    test eax, eax
    jnz  manager_stop
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_final_select]
    call serial_string
%endif
%endif
%endif
%ifdef PBM_DIAG_STOP_AFTER_POLICY
    ; Dell gen38 trial-B discriminator. No journal mutation or slot launch:
    ; only the exact expected selected identity earns phase 2, then firmware
    ; resumes Windows-first BootOrder via EFI_ABORTED.
    cmp  byte [rel selected_entry], PBM_ENTRY_PAOS_B
    jne  .diag_policy_refused
    cmp  byte [rel selected_reason], PBM_REASON_TRIAL
    jne  .diag_policy_refused
    lea  rax, [rel diag_record_phase2]
    mov  [rel diag_current_record], rax
    call diag_persist_entry
    test eax, eax
    jnz  .diag_policy_refused
    lea  rdi, [rel str_diag_policy_persisted]
    call serial_string
    mov  rax, 0x8000000000000015
    jmp  .diag_return
.diag_policy_refused:
    lea  rdi, [rel str_diag_policy_refused]
    call serial_string
    mov  rax, 0x8000000000000007
    jmp  .diag_return
%endif

    PBM_STAGE 0x107                    ; policy decided
%ifdef PBM_TEST_STATE_WRITE
    call test_journal_write
    test eax, eax
    jnz  manager_stop
%endif

%ifdef PBM_FEATURE_FULL_POLICY
    ; Publish before controller discovery/countdown: even a cut before the
    ; payload's BIP arm must count as an interrupted Manager start. The normal
    ; policy above still accounts Trial/Safe/quarantine before this override.
    call record_manager_start
    test eax, eax
    jnz  manager_stop
%ifdef PBM_FEATURE_MENU
    cmp  byte [rel power_rescue_due], 1
    je   .power_rescue_launch
    call menu_connect_usb_console
    call present_menu_if_needed
    test eax, eax
    jnz  manager_stop
%ifdef PBM_TEST_STOP_AFTER_MENU_PRESENT
    cmp  byte [rel menu_visible], 1
    je   manager_stop
%endif
%endif
.power_rescue_launch:
    PBM_STAGE 0x10C                    ; menu done (hidden, accepted or timed out)
    call launch_mutable_sequence
    jmp  manager_stop
%else
    movzx edi, byte [rel selected_entry]
    call launch_entry
    cmp  byte [rel fatal_policy_failure], 1
    je   manager_stop
    lea  rdi, [rel str_selected_failed]
    call serial_string

    movzx edi, byte [rel fallback_entry]
    test edi, edi
    jz   .rescue
    cmp  dil, [rel selected_entry]
    je   .rescue
    call launch_entry
    cmp  byte [rel fatal_policy_failure], 1
    je   manager_stop
    lea  rdi, [rel str_fallback_failed]
    call serial_string

.rescue:
    cmp  byte [rel selected_entry], PBM_ENTRY_RESCUE
    je   manager_stop
    mov  edi, PBM_ENTRY_RESCUE
    call launch_entry
%endif

%ifdef PBM_DIAG_PREHEALTH_TRACE
%ifdef PBM_DIAG_CMOS_IMPORT_REFUSAL
diag_trace_failure_return:
    mov  rax, 0x8000000000000007  ; failed witness: finite Device Error
    jmp  diag_trace_return
%endif
diag_trace_return:
    mov  r12, rax
    mov  rax, [rel boot_services]
    xor  ecx, ecx                   ; disarm watchdog before firmware return
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 32
    call [rax + 0x100]
    PBM_FW_LEAVE 32
    test rax, rax
    jz   .disarmed
    mov  r12, 0x8000000000000007
.disarmed:
    mov  rax, r12
    jmp  efi_entry.diag_return
%endif

%ifdef PBM_DIAG_HEALTH_CONSUME_TRACE
; EAX=0 only when the compact health variable is actually absent. A present,
; oversized or unreadable record refuses before consume_strong_health can
; delete a stale value or commit a valid one to the journal.
diag_require_bootready_absent:
    push rbx
    mov  rbx, [rel runtime_services]
    test rbx, rbx
    jz   .refused
    mov  qword [rel health_size], PBM_HEALTH_SIZE
    mov  dword [rel health_attributes], 0
    lea  rcx, [rel health_var_name]
    lea  rdx, [rel health_var_guid]
    lea  r8, [rel health_attributes]
    lea  r9, [rel health_size]
    PBM_FW_ENTER 40
    lea  rax, [rel health_record]
    mov  [rsp + 32], rax
    call [rbx + 0x48]             ; GetVariable, never SetVariable
    PBM_FW_LEAVE 40
    mov  rdx, 0x800000000000000E ; EFI_NOT_FOUND, no other error admits consume
    cmp  rax, rdx
    jne  .refused
    xor  eax, eax
    pop  rbx
    ret
.refused:
    mov  eax, 1
    pop  rbx
    ret
%endif

%include "bootmgr/sb_negative_probe.inc"

manager_stop:
%ifdef PBM_DIAG_PREHEALTH_TRACE
    mov  rax, 0x8000000000000007  ; never halt or launch on trace failure
    jmp  diag_trace_return
%else
    ; Before any LoadImage/StartImage, firmware boot services are still ours.
    ; A refused signed request must not strand a Windows-first machine in HLT.
    ; A failed LoadImage with no child handle is also pre-child. Other firmware
    ; loads and actual child entry retain the conservative post-launch stop.
    cmp  byte [rel manager_launch_entered], 0
    jne  .halt
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call r5_manager_budget_close
%endif
%endif
    xor  ecx, ecx                 ; disarm: firmware owns the next BootOrder step
    call manager_watchdog_set
    lea  rdi, [rel str_prelaunch_finite_return]
    call serial_string
    mov  rax, 0x8000000000000015  ; EFI_ABORTED; firmware resumes BootOrder
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret
.halt:
    lea  rdi, [rel str_stop]
    call serial_string
.halt_wait:
    hlt                           ; print once: each wakeup reprinted (rc-qemu 2026-10-09 21:19:19)
    jmp  .halt_wait
%endif

%ifdef PBM_DIAG_ENTRY_NONCE
; diag_persist_entry -> EAX=0 only after SetVariable and exact GetVariable
; readback.  This is an observation marker, never an authorization input.
diag_persist_entry:
    push rbx
    mov  rbx, [rel runtime_services]
    test rbx, rbx
    jz   .bad
    lea  rcx, [rel diag_var_name]
    lea  rdx, [rel diag_var_guid]
    mov  r8d, 7                     ; NV | boot-service | runtime
    mov  r9d, 32
    PBM_FW_ENTER 40
    mov  rax, [rel diag_current_record]
    mov  [rsp + 32], rax
    call [rbx + 0x58]               ; SetVariable
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .bad
    mov  qword [rel diag_read_size], 32
    mov  dword [rel diag_read_attrs], 0
    lea  rcx, [rel diag_var_name]
    lea  rdx, [rel diag_var_guid]
    lea  r8, [rel diag_read_attrs]
    lea  r9, [rel diag_read_size]
    PBM_FW_ENTER 40
    lea  rax, [rel diag_readback]
    mov  [rsp + 32], rax
    call [rbx + 0x48]               ; GetVariable
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .bad
    cmp  qword [rel diag_read_size], 32
    jne  .bad
    cmp  dword [rel diag_read_attrs], 7
    jne  .bad
    mov  rsi, [rel diag_current_record]
    lea  rdi, [rel diag_readback]
    mov  ecx, 4
    repe cmpsq
    jne  .bad
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  eax, 1
    pop  rbx
    ret
%endif

%ifdef PBM_DIAG_STAGE_TRACE
; diag_stage_mark(EAX=stage) -> nothing; preserves every register (PBM_STAGE saves
; RAX and flags). Writes only a stage above the highest already written (menu
; polling and launch retries cannot rewrite) and at most PBM_DIAG_STAGE_MAX_WRITES
; times; the SetVariable status is ignored (observation only). Self-aligning: the
; firmware call runs at RSP = 0 mod 16 whatever the caller's parity.
diag_stage_mark:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 48
    cmp  eax, [rel diag_stage_high]
    jbe  .out
    cmp  byte [rel diag_stage_writes], PBM_DIAG_STAGE_MAX_WRITES
    jae  .out
    mov  rbx, [rel runtime_services]
    test rbx, rbx
    jz   .out
    mov  [rel diag_stage_high], eax
    mov  [rel diag_stage_record + 16], rax
    inc  byte [rel diag_stage_writes]
    lea  rcx, [rel diag_var_name]
    lea  rdx, [rel diag_var_guid]
    mov  r8d, 7                     ; NV | boot-service | runtime
    mov  r9d, 32
    lea  rax, [rel diag_stage_record]
    mov  [rsp + 32], rax
    call [rbx + 0x58]               ; SetVariable (status ignored)
.out:
    mov  rsp, rbp
    pop  rbp
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    ret
%endif

PAOS_NATIVE_TRACE_CODE 1

; resolve_boot_device -> EAX=0 success.  Retains the parent device path without
; its END node so a MEDIA_FILEPATH node can be appended for each payload.
resolve_boot_device:
    push rbx
    sub  rsp, 32
    mov  rax, [rel boot_services]
    mov  rcx, [rel image_handle]
    lea  rdx, [rel loaded_image_guid]
    lea  r8, [rel self_loaded_image]
    PBM_FW_ENTER 32
    call [rax + 0x98]                ; HandleProtocol
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .out
    mov  rax, [rel self_loaded_image]
    mov  rbx, [rax + 24]             ; DeviceHandle
    test rbx, rbx
    jz   .fail
    mov  [rel boot_device_handle], rbx
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    lea  rdx, [rel device_path_guid]
    lea  r8, [rel device_path]
    PBM_FW_ENTER 32
    call [rax + 0x98]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .out
    mov  rsi, [rel device_path]
    xor  ecx, ecx
.measure:
    cmp  byte [rsi], 0x7F
    je   .measured
    movzx eax, word [rsi + 2]
    cmp  eax, 4
    jb   .fail
    add  ecx, eax
    add  rsi, rax
    cmp  ecx, 4096
    jb   .measure
    jmp  .fail
.measured:
    mov  [rel device_path_len], ecx
    xor  eax, eax
.out:
    add  rsp, 32
    pop  rbx
    ret
.fail:
    mov  eax, 1
    jmp  .out

; Open the manager's boot volume. Failure leaves boot_root=0; policy then
; selects the compiled-in Rescue identity and LoadImage still gets a chance.
open_boot_volume:
    push rbx
    sub  rsp, 32
    mov  rax, [rel boot_services]
    mov  rcx, [rel boot_device_handle]
    lea  rdx, [rel simple_fs_guid]
    lea  r8, [rel simple_fs]
    PBM_FW_ENTER 32
    call [rax + 0x98]                ; HandleProtocol(SimpleFileSystem)
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .fail
    mov  rax, [rel simple_fs]
    mov  rcx, rax
    lea  rdx, [rel boot_root]
    PBM_FW_ENTER 32
    call [rax + 8]                   ; OpenVolume
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  qword [rel boot_root], 0
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret

%ifdef PBM_FEATURE_EXTERNAL
; select_external_volume: locate exactly one SimpleFileSystem volume containing
; the owner-signed external path with the exact signed size/PE/SHA-256 identity.
; R13/R14/R15 retain path/path-bytes/entry.  The winning volume becomes the
; source for both the second exact verification and LoadImage device path.
; Zero or multiple matches fail closed and restore the Manager's original
; volume so durable invalid-payload evidence can still be committed.
select_external_volume:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  rax, [rel boot_root]
    mov  [rel scan_original_root], rax
    mov  rax, [rel boot_device_handle]
    mov  [rel scan_original_handle], rax
    mov  rax, [rel device_path]
    mov  [rel scan_original_device_path], rax
    mov  eax, [rel device_path_len]
    mov  [rel scan_original_device_path_len], eax
    mov  qword [rel fs_handle_count], 0
    mov  qword [rel fs_handle_buffer], 0
    mov  qword [rel selected_external_root], 0
    mov  qword [rel selected_external_handle], 0
    mov  byte [rel external_volume_matches], 0

    mov  rax, [rel boot_services]
    mov  ecx, 2                       ; ByProtocol
    lea  rdx, [rel simple_fs_guid]
    xor  r8d, r8d                     ; SearchKey
    lea  r9, [rel fs_handle_count]
    PBM_FW_ENTER 40
    lea  rbx, [rel fs_handle_buffer]
    mov  [rsp + 32], rbx
    call [rax + 0x138]                ; LocateHandleBuffer
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .finish_scan
    mov  r12, [rel fs_handle_buffer]
    mov  rbp, [rel fs_handle_count]

.next_volume:
    test rbp, rbp
    jz   .finish_scan
    mov  rbx, [r12]
    mov  [rel boot_device_handle], rbx
    call open_boot_volume
    test eax, eax
    jnz  .advance
    mov  rax, [rel boot_root]
    mov  [rel payload_root], rax
    call verify_payload_file
    test eax, eax
    jnz  .close_current
    call free_verified_source_buffer
    cmp  byte [rel external_volume_matches], 0
    jne  .ambiguous
    mov  byte [rel external_volume_matches], 1
    mov  [rel selected_external_handle], rbx
    mov  rax, [rel boot_root]
    mov  [rel selected_external_root], rax
    jmp  .advance

.close_current:
    mov  rbx, [rel boot_root]
    test rbx, rbx
    jz   .advance
    cmp  rbx, [rel scan_original_root]
    je   .advance
    mov  rcx, rbx
    PBM_FW_ENTER 32
    call [rbx + 16]                   ; EFI_FILE_PROTOCOL.Close
    PBM_FW_LEAVE 32
    jmp  .advance

.ambiguous:
    mov  byte [rel external_volume_matches], 2
    lea  rdi, [rel str_external_volume_ambiguous]
    call serial_string
    mov  rbx, [rel boot_root]
    test rbx, rbx
    jz   .close_first
    cmp  rbx, [rel scan_original_root]
    je   .close_first
    mov  rcx, rbx
    PBM_FW_ENTER 32
    call [rbx + 16]
    PBM_FW_LEAVE 32
.close_first:
    mov  rbx, [rel selected_external_root]
    test rbx, rbx
    jz   .finish_scan
    cmp  rbx, [rel scan_original_root]
    je   .finish_scan
    mov  rcx, rbx
    PBM_FW_ENTER 32
    call [rbx + 16]
    PBM_FW_LEAVE 32
    mov  qword [rel selected_external_root], 0
    jmp  .finish_scan

.advance:
    add  r12, 8
    dec  rbp
    jmp  .next_volume

.finish_scan:
    mov  rbx, [rel fs_handle_buffer]
    test rbx, rbx
    jz   .evaluate
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    PBM_FW_ENTER 32
    call [rax + 0x48]                 ; FreePool handle array
    PBM_FW_LEAVE 32
.evaluate:
    cmp  byte [rel external_volume_matches], 1
    jne  .fail
    call resolve_selected_device_path
    test eax, eax
    jnz  .fail
    mov  rax, [rel selected_external_root]
    mov  [rel payload_root], rax
    mov  rax, [rel scan_original_root]
    mov  [rel boot_root], rax
    mov  rax, [rel scan_original_handle]
    mov  [rel boot_device_handle], rax
    lea  rdi, [rel str_external_volume_selected]
    call serial_string
    xor  eax, eax
    jmp  .out

.fail:
    mov  rax, [rel scan_original_root]
    mov  [rel boot_root], rax
    mov  [rel payload_root], rax
    mov  rax, [rel scan_original_handle]
    mov  [rel boot_device_handle], rax
    mov  rax, [rel scan_original_device_path]
    mov  [rel device_path], rax
    mov  eax, [rel scan_original_device_path_len]
    mov  [rel device_path_len], eax
    mov  eax, 1
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Resolve and bound the device path of selected_external_handle.
resolve_selected_device_path:
    push rbx
    sub  rsp, 32
    mov  rbx, [rel selected_external_handle]
    test rbx, rbx
    jz   .fail
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    lea  rdx, [rel device_path_guid]
    lea  r8, [rel device_path]
    PBM_FW_ENTER 32
    call [rax + 0x98]                 ; HandleProtocol(DevicePath)
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .out
    mov  rsi, [rel device_path]
    xor  ecx, ecx
.measure:
    cmp  byte [rsi], 0x7F
    je   .measured
    movzx eax, word [rsi + 2]
    cmp  eax, 4
    jb   .fail
    add  ecx, eax
    add  rsi, rax
    cmp  ecx, 4096
    jb   .measure
    jmp  .fail
.measured:
    mov  [rel device_path_len], ecx
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret
%endif

%ifdef PBM_FEATURE_EXTERNAL
%include "bootmgr/existing_os_observation.inc"
%endif

; read_exact(R13=UCS-2 path, R12=buffer, EBX=expected bytes) -> EAX=0 success.
read_exact:
    push r14
    sub  rsp, 32
    mov  qword [rel opened_file], 0
    mov  rax, [rel boot_root]
    test rax, rax
    jz   .fail
    mov  rcx, rax
    lea  rdx, [rel opened_file]
    mov  r8, r13
    mov  r9d, 1                      ; EFI_FILE_MODE_READ
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0         ; attributes
    call [rax + 8]                   ; EFI_FILE_PROTOCOL.Open
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .fail
    mov  [rel read_size], rbx
    mov  r14, [rel opened_file]
    mov  rcx, r14
    lea  rdx, [rel read_size]
    mov  r8, r12
    PBM_FW_ENTER 32
    call [r14 + 32]                  ; Read
    PBM_FW_LEAVE 32
    mov  [rel read_status], rax
    test rax, rax
    jnz  .close
    cmp  [rel read_size], rbx
    jne  .close
    mov  qword [rel tail_size], 1
    mov  rcx, r14
    lea  rdx, [rel tail_size]
    lea  r8, [rel read_tail]
    PBM_FW_ENTER 32
    call [r14 + 32]                  ; exact-size contract: next Read must be EOF
    PBM_FW_LEAVE 32
    mov  [rel read_status], rax
.close:
    mov  rcx, r14
    PBM_FW_ENTER 32
    call [r14 + 16]                  ; Close
    PBM_FW_LEAVE 32
    cmp  qword [rel read_status], 0
    jnz  .fail
    cmp  [rel read_size], rbx
    jne  .fail
    cmp  qword [rel tail_size], 0
    jne  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  r14
    ret

; write_exact_verified(R13=UCS-2 path, R12=buffer, EBX=expected bytes)
; -> EAX=0 only after Write, Flush, exact EOF-bounded read-back, byte compare,
; and state semantic validation. The caller writes only the older journal copy.
write_exact_verified:
    push r14
    push r15
    sub  rsp, 32
    mov  byte [rel write_ok], 0
    mov  qword [rel opened_file], 0
    mov  rax, [rel boot_root]
    test rax, rax
    jz   .out
    mov  rcx, rax
    lea  rdx, [rel opened_file]
    mov  r8, r13
    mov  r9, 0x8000000000000003       ; READ | WRITE | CREATE
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0
    call [rax + 8]                    ; EFI_FILE_PROTOCOL.Open
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .out
    mov  r14, [rel opened_file]

    mov  [rel write_size], rbx
    mov  rcx, r14
    lea  rdx, [rel write_size]
    mov  r8, r12
    PBM_FW_ENTER 32
    call [r14 + 40]                   ; Write
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    cmp  [rel write_size], rbx
    jne  .close

    mov  rcx, r14
    PBM_FW_ENTER 32
    call [r14 + 80]                   ; Flush before trusting read-back
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close

    mov  rcx, r14
    xor  edx, edx
    PBM_FW_ENTER 32
    call [r14 + 56]                   ; SetPosition(0)
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close

    mov  [rel verify_size], rbx
    mov  rcx, r14
    lea  rdx, [rel verify_size]
    lea  r8, [rel state_verify]
    PBM_FW_ENTER 32
    call [r14 + 32]                   ; Read exact state body
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    cmp  [rel verify_size], rbx
    jne  .close

    mov  qword [rel verify_tail_size], 1
    mov  rcx, r14
    lea  rdx, [rel verify_tail_size]
    lea  r8, [rel read_tail]
    PBM_FW_ENTER 32
    call [r14 + 32]                   ; Reject a stale tail on longer files
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    cmp  qword [rel verify_tail_size], 0
    jne  .close

    mov  rsi, r12
    lea  rdi, [rel state_verify]
    mov  ecx, PBM_STATE_SIZE / 8
    repe cmpsq
    jne  .close
    lea  rdi, [rel state_verify]
    call state_valid
    test eax, eax
    jz   .close
    mov  byte [rel write_ok], 1
.close:
    mov  rcx, r14
    PBM_FW_ENTER 32
    call [r14 + 16]
    PBM_FW_LEAVE 32
.out:
    xor  eax, eax
    cmp  byte [rel write_ok], 1
    je   .done
    mov  eax, 1
.done:
    add  rsp, 32
    pop  r15
    pop  r14
    ret

; journal_commit(R12=desired semantic state) -> EAX=0 success.
; Assigns max(valid generation)+1 and overwrites only the older/invalid copy.
journal_commit:
    push rbx
    push r13
    push r14
    push r15
    xor  r14d, r14d                 ; max generation
    xor  r15d, r15d                 ; target index defaults to state0
    cmp  byte [rel state0_valid], 1
    jne  .check1_only
    mov  r14, [rel state0 + PBM_STATE_GENERATION_OFF]
    mov  r15d, 1                    ; valid state0 => preserve it, target state1
.check1_only:
    cmp  byte [rel state1_valid], 1
    jne  .have_target
    cmp  byte [rel state0_valid], 1
    jne  .only1
    mov  rax, [rel state1 + PBM_STATE_GENERATION_OFF]
    cmp  rax, r14
    jbe  .have_target               ; state0 newest/equal => target state1
    mov  r14, rax
    xor  r15d, r15d                 ; state1 newest => target state0
    jmp  .have_target
.only1:
    mov  r14, [rel state1 + PBM_STATE_GENERATION_OFF]
    xor  r15d, r15d
.have_target:
    cmp  r14, -1
    je   .fail
    inc  r14
    mov  [r12 + PBM_STATE_GENERATION_OFF], r14
    mov  dword [r12 + PBM_STATE_CRC32], 0
    mov  rdi, r12
    mov  ecx, PBM_STATE_CRC32
    call crc32
    mov  [r12 + PBM_STATE_CRC32], eax

    lea  r13, [rel ucs2_state0]
    test r15d, r15d
    jz   .write
    lea  r13, [rel ucs2_state1]
.write:
    mov  ebx, PBM_STATE_SIZE
    call write_exact_verified
    test eax, eax
    jnz  .fail

    lea  rdi, [rel state0]
    test r15d, r15d
    jz   .copy
    lea  rdi, [rel state1]
.copy:
    mov  rbx, rdi
    mov  [rel selected_state_ptr], rbx
    mov  rsi, r12
    mov  ecx, PBM_STATE_SIZE / 8
    rep movsq
    lea  rax, [rel state0_valid]
    mov  byte [rax + r15], 1
    lea  rdi, [rel str_state_write_ok]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail:
    PBM_PRESELECT 0xF002
    lea  rdi, [rel str_state_write_fail]
    call serial_string
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

%ifdef PBM_TEST_STATE_WRITE
; QEMU-only harness: preserve all policy fields, set an unmistakable legal
; counter value, and exercise the production journal commit primitive.
test_journal_write:
    mov  rsi, [rel selected_state_ptr]
    test rsi, rsi
    jz   .fail
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep movsq
    mov  byte [rel state_work + PBM_STATE_FAILURE_COUNT_OFF], 0x5A
    lea  r12, [rel state_work]
    call journal_commit
    ret
.fail:
    mov  eax, 1
    ret
%endif

; Structural validation for the optional B1 journal tail.  Pre-B1 all-zero
; records remain valid.  Once initialized, flags, fingerprints, digests and the
; ordinary pending fields must describe one coherent fail-closed policy state.
b1_state_extension_valid:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    cmp  dword [r12 + PBM_B1_STATE_MAGIC_OFF], 0
    je   .good
    cmp  dword [r12 + PBM_B1_STATE_MAGIC_OFF], PBM_B1_STATE_MAGIC
    jne  .bad
    cmp  byte [r12 + PBM_B1_STATE_VERSION_OFF], PBM_B1_STATE_VERSION
    jne  .bad
    mov  al, [r12 + PBM_B1_STATE_FLAGS_OFF]
    test al, 0xF8
    jnz  .bad
    mov  al, [r12 + PBM_B1_STATE_EVIDENCE_MASK_OFF]
    test al, 0xF9
    jnz  .bad

    test al, (1 << PBM_ENTRY_PAOS_A)
    jz   .slot_b
    mov  eax, [r12 + PBM_B1_STATE_FP_A_OFF]
    and  eax, 0xFF000000
    cmp  eax, PBM_B1_FAILURE_FINGERPRINT_TAG
    jne  .bad
    lea  rbx, [r12 + PBM_B1_STATE_SHA_A_OFF]
    xor  edx, edx
    xor  ecx, ecx
.sha_a:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .sha_a
    test dl, dl
    jz   .bad
.slot_b:
    mov  al, [r12 + PBM_B1_STATE_EVIDENCE_MASK_OFF]
    test al, (1 << PBM_ENTRY_PAOS_B)
    jz   .safe_video
    mov  eax, [r12 + PBM_B1_STATE_FP_B_OFF]
    and  eax, 0xFF000000
    cmp  eax, PBM_B1_FAILURE_FINGERPRINT_TAG
    jne  .bad
    lea  rbx, [r12 + PBM_B1_STATE_SHA_B_OFF]
    xor  edx, edx
    xor  ecx, ecx
.sha_b:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .sha_b
    test dl, dl
    jz   .bad

.safe_video:
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SAFE_VIDEO_PENDING
    jz   .safe_absent
    movzx eax, byte [r12 + PBM_B1_STATE_SAFE_ENTRY_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  eax, PBM_ENTRY_PAOS_B
    ja   .bad
    cmp  al, [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    jne  .bad
    cmp  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_SAFE
    jne  .bad
    lea  rbx, [r12 + PBM_B1_STATE_SAFE_SHA_OFF]
    xor  edx, edx
    xor  ecx, ecx
.safe_sha:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .safe_sha
    test dl, dl
    jz   .bad
    jmp  .suspect
.safe_absent:
    cmp  byte [r12 + PBM_B1_STATE_SAFE_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .bad
    lea  rbx, [r12 + PBM_B1_STATE_SAFE_SHA_OFF]
    xor  edx, edx
    xor  ecx, ecx
.safe_zero:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .safe_zero
    test dl, dl
    jnz  .bad

.suspect:
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_MEMTEST_PRESELECT
    jz   .suspect_flag
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SUSPECT_HARDWARE
    jz   .bad
.suspect_flag:
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SUSPECT_HARDWARE
    jz   .good
    mov  al, [r12 + PBM_B1_STATE_EVIDENCE_MASK_OFF]
    and  al, PBM_B1_SLOT_BOTH_MASK
    cmp  al, PBM_B1_SLOT_BOTH_MASK
    jne  .bad
    mov  eax, [r12 + PBM_B1_STATE_FP_A_OFF]
    cmp  eax, [r12 + PBM_B1_STATE_FP_B_OFF]
    je   .bad
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_MEMTEST_PRESELECT
    jz   .bad
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SAFE_VIDEO_PENDING
    jnz  .bad
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    je   .suspect_pending
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 1
    jne  .bad
    ; After terminal selection the ordinary attempt transaction arms the
    ; verified Rescue child.  That BIP is coherent only for Rescue itself and
    ; must never reopen either PaOS slot.
    cmp  byte [r12 + PBM_STATE_LAST_ENTRY_OFF], PBM_ENTRY_RESCUE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_RESCUE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_RESCUE
    jne  .bad
.suspect_pending:
    cmp  byte [r12 + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    jne  .bad
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; state_valid(RDI=512-byte record) -> EAX=1 valid, 0 rejected.
state_valid:
    push rbx
    push r12
    mov  r12, rdi
    cmp  dword [r12 + PBM_STATE_MAGIC_OFF], PBM_STATE_MAGIC
    jne  .bad
    cmp  word [r12 + PBM_STATE_VERSION_OFF], PBM_CONTRACT_VERSION
    jne  .bad
    cmp  word [r12 + PBM_STATE_SIZE_OFF], PBM_STATE_SIZE
    jne  .bad
    mov  ebx, [r12 + PBM_STATE_CRC32]
    mov  rdi, r12
    mov  ecx, PBM_STATE_CRC32
    call crc32
    cmp  eax, ebx
    jne  .bad
    movzx eax, byte [r12 + PBM_STATE_ACTIVE_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .active_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .bad
.active_ok:
    movzx eax, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .previous_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .bad
.previous_ok:
    movzx eax, byte [r12 + PBM_STATE_TRIAL_OFF]
    cmp  eax, PBM_ENTRY_PAOS_B
    ja   .bad
    movzx edx, byte [r12 + PBM_STATE_ACTIVE_OFF]
    cmp  dl, [r12 + PBM_STATE_PREVIOUS_OFF]
    jne  .roles_ok
    test al, al
    jz   .bad
    cmp  al, dl
    je   .bad
.roles_ok:
    movzx eax, byte [r12 + PBM_STATE_MENU_POLICY_OFF]
    cmp  eax, PBM_MENU_DETAILED
    ja   .bad
    movzx eax, byte [r12 + PBM_STATE_MENU_TIMEOUT_OFF]
    cmp  eax, PBM_MENU_TIMEOUT_MIN
    jb   .bad
    cmp  eax, PBM_MENU_TIMEOUT_MAX
    ja   .bad
    movzx eax, byte [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    cmp  eax, PBM_ENTRY_MAX
    ja   .bad
    movzx edx, byte [r12 + PBM_STATE_PENDING_PROFILE_OFF]
    cmp  edx, PBM_PROFILE_EXTERNAL
    ja   .bad
    test eax, eax
    jnz  .pending_nonempty
    test edx, edx
    jnz  .bad
    jmp  .pending_ok
.pending_nonempty:
    cmp  eax, PBM_ENTRY_PAOS_B
    ja   .pending_rescue
    cmp  edx, PBM_PROFILE_SAFE
    ja   .bad
    jmp  .pending_ok
.pending_rescue:
    cmp  eax, PBM_ENTRY_RESCUE
    jne  .pending_external
    cmp  edx, PBM_PROFILE_RESCUE
    jne  .bad
    jmp  .pending_ok
.pending_external:
    cmp  edx, PBM_PROFILE_EXTERNAL
    jne  .bad
.pending_ok:
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 1
    ja   .bad
    cmp  byte [r12 + PBM_STATE_LAST_ENTRY_OFF], PBM_ENTRY_MAX
    ja   .bad
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_EXTERNAL
    ja   .bad
    cmp  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_CMOS_UNTRUSTED
    ja   .bad
    test byte [r12 + PBM_STATE_LAST_FLAGS_OFF], ~PBM_LAST_F_MASK & 0xFF
    jnz  .bad
    cmp  byte [r12 + PBM_STATE_START_COUNT_OFF], 2
    ja   .bad
    cmp  byte [r12 + PBM_STATE_START_ARMED_OFF], 1
    ja   .bad
    mov  al, [r12 + PBM_STATE_VERIFIED_MASK_OFF]
    or   al, [r12 + PBM_STATE_QUARANTINE_MASK_OFF]
    or   al, [r12 + PBM_STATE_SAFE_ATTEMPTED_OFF]
    test al, 0xF9                    ; only slot A/B bits 1 and 2 are legal
    jnz  .bad
    movzx eax, byte [r12 + PBM_STATE_EXTERNAL_ENTRY_OFF]
    test eax, eax
    jz   .external_empty
    cmp  eax, PBM_ENTRY_WINDOWS
    je   .external_identity
    cmp  eax, PBM_ENTRY_LINUX
    jne  .bad
.external_identity:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 1
    ja   .bad
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_INVALID_PAYLOAD
    ja   .bad
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_INVALID_PAYLOAD
    je   .external_invalid
    mov  rax, [r12 + PBM_STATE_EXTERNAL_NONCE_OFF]
    test rax, rax
    jz   .bad
    mov  rdx, [r12 + PBM_STATE_EXTERNAL_READY_OFF]
    test rdx, rdx
    jz   .external_domains
    cmp  rdx, rax
    jne  .bad
.external_domains:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    je   .external_closed
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_NONE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    jne  .bad
    jmp  .external_ok
.external_closed:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_READY
    je   .external_closed_ready
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_UNAVAILABLE
    jne  .external_ok
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    jmp  .external_ok
.external_closed_ready:
    cmp  rdx, rax
    jne  .bad
    jmp  .external_ok
.external_invalid:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_NONCE_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    jmp  .external_ok
.external_empty:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_NONCE_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_NONE
    jne  .bad
.external_ok:
    cmp  dword [r12 + 59], 0
    jne  .bad
    cmp  byte [r12 + 63], 0
    jne  .bad
    mov  rax, [r12 + PBM_STATE_MANIFEST_SEQ_OFF]
    xor  edx, edx
    xor  ecx, ecx
.manifest_digest:
    or   dl, [r12 + PBM_STATE_MANIFEST_SHA_OFF + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .manifest_digest
    test rax, rax
    jz   .manifest_unbound
    test dl, dl
    jz   .bad
    jmp  .manifest_ok
.manifest_unbound:
    test dl, dl
    jnz  .bad
.manifest_ok:
    mov  rdi, r12
    call b1_state_extension_valid
    test eax, eax
    jz   .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Share the actual parser and anchored verification with native update readers.
; The standalone Manager keeps its existing independent crypto lock domain.
%define PBM_MANIFEST_RSA_VERIFY pbm_rsa2048_verify_sha256_locked
%include "bootmgr/pbm_manifest_verify.inc"
%undef PBM_MANIFEST_RSA_VERIFY

; recovery_descriptor_struct_valid(RDI=exact 512-byte descriptor) -> EAX=1/0.
; The signature and enrolled-key identity are checked separately.  The one
; embedded entry uses the ordinary manifest-entry encoding but may name only
; the canonical Rescue identity/profile.
recovery_descriptor_struct_valid:
    push rbx
    push r12
    mov  r12, rdi
    cmp  dword [r12], PBM_RECOVERY_MAGIC
    jne  .bad
    cmp  word [r12 + 4], PBM_RECOVERY_VERSION
    jne  .bad
    cmp  word [r12 + 6], PBM_RECOVERY_SIZE
    jne  .bad
    cmp  qword [r12 + 8], 0
    je   .bad
    cmp  word [r12 + 16], 1
    jne  .bad
    cmp  byte [r12 + 18], 1
    jne  .bad
    cmp  byte [r12 + 19], 0
    jne  .bad
    cmp  dword [r12 + 20], 0
    jne  .bad
    lea  rsi, [r12 + 64]
    mov  ecx, 64
.header_zero:
    cmp  byte [rsi], 0
    jne  .bad
    inc  rsi
    dec  ecx
    jnz  .header_zero

    lea  rbx, [r12 + PBM_RECOVERY_ENTRY_OFF]
    cmp  byte [rbx], PBM_ENTRY_RESCUE
    jne  .bad
    movzx eax, byte [rbx + 1]
    test eax, 0xFFFFFFF8
    jnz  .bad
    mov  edx, eax
    and  edx, 6                       ; Bootable + Required are mandatory
    cmp  edx, 6
    jne  .bad
    cmp  byte [rbx + 2], 4            ; Rescue profile only
    jne  .bad
    cmp  byte [rbx + 3], 0
    jne  .bad
    mov  edx, [rbx + 4]
    cmp  edx, 512
    jb   .bad
    cmp  edx, 64 * 1024 * 1024
    ja   .bad
    xor  edx, edx
    xor  ecx, ecx
.digest_nonzero:
    or   dl, [rbx + 16 + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .digest_nonzero
    test dl, dl
    jz   .bad
    movzx edx, word [rbx + 48]
    cmp  edx, 1
    jb   .bad
    cmp  edx, 37
    ja   .bad
    cmp  word [rbx + 50], 10
    jne  .bad
    cmp  word [rbx + 52], '\'
    jne  .bad
    xor  ecx, ecx
.path:
    movzx eax, word [rbx + 52 + rcx*2]
    cmp  ecx, edx
    je   .path_nul
    test ah, ah
    jnz  .bad
    cmp  al, 0x20
    jb   .bad
    cmp  al, 0x7E
    ja   .bad
    cmp  al, '/'
    je   .bad
    cmp  al, '.'
    jne  .path_next
    mov  esi, ecx
    inc  esi
    cmp  esi, edx
    jae  .path_next
    cmp  word [rbx + 52 + rsi*2], '.'
    je   .bad
.path_next:
    inc  ecx
    jmp  .path
.path_nul:
    test eax, eax
    jnz  .bad
    inc  ecx
.path_padding:
    cmp  ecx, 38
    jae  .good
    cmp  word [rbx + 52 + rcx*2], 0
    jne  .bad
    inc  ecx
    jmp  .path_padding
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; load_verify_manifest -> EAX=0 only for exact structure, compiled owner key ID,
; and strict RSA-2048 PKCS#1 v1.5/SHA-256 signature.
load_verify_manifest:
%ifndef PBM_OWNER_KEY
    mov  byte [rel manifest_verified], 0
    mov  byte [rel recovery_descriptor_verified], 0
    mov  qword [rel trust_sequence], 0
    lea  rdi, [rel str_manifest_no_key]
    call serial_string
    mov  eax, 1
    ret
%else
    push rbx
    push r12
    push r13
    mov  byte [rel manifest_verified], 0
    mov  byte [rel recovery_descriptor_verified], 0
    mov  qword [rel trust_sequence], 0
    lea  r13, [rel ucs2_manifest]
    lea  r12, [rel manifest]
    mov  ebx, PBM_MANIFEST_SIZE
    call read_exact
    test eax, eax
    jnz  .bad
    lea  rdi, [rel manifest]
    mov  esi, PBM_MANIFEST_SIZE
    lea  rdx, [rel pbm_owner_key_id]
    lea  rcx, [rel pbm_owner_modulus]
    call pbm_manifest_verify_anchored
    test eax, eax
    jz   .bad
    lea  rdi, [rel verified_manifest_sha]
    lea  rsi, [rel manifest]
    mov  edx, PBM_MANIFEST_SIZE
    call sha256_hash
    test rax, rax
    jnz  .bad
    mov  rax, [rel manifest + 8]
    mov  [rel trust_sequence], rax
    mov  byte [rel manifest_verified], 1
    lea  rdi, [rel str_manifest_valid]
    call serial_string
    xor  eax, eax
    jmp  .out
.bad:
    lea  rdi, [rel str_manifest_invalid]
    call serial_string
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
%endif

; load_verify_recovery_descriptor -> EAX=0 only for the independently signed,
; canonical single-Rescue descriptor.  It does not consult or bind mutable A/B
; state and is therefore usable when the normal manifest is unreadable.
load_verify_recovery_descriptor:
%ifndef PBM_OWNER_KEY
    mov  byte [rel recovery_descriptor_verified], 0
    lea  rdi, [rel str_recovery_descriptor_no_key]
    call serial_string
    mov  eax, 1
    ret
%else
    push rbx
    push r12
    push r13
    mov  byte [rel recovery_descriptor_verified], 0
    mov  qword [rel trust_sequence], 0
    lea  r13, [rel ucs2_recovery_descriptor]
    lea  r12, [rel recovery_descriptor]
    mov  ebx, PBM_RECOVERY_SIZE
    call read_exact
    test eax, eax
    jnz  .bad
    lea  rdi, [rel recovery_descriptor]
    call recovery_descriptor_struct_valid
    test eax, eax
    jz   .bad
%ifdef PBM_RESCUE_KEY
    ; K19 (Peter ruling B3): the descriptor's key id (+32) selects the verifying
    ; key. The rescue key is separate from the release key, so revoking a
    ; compromised release key cannot invalidate Rescue on every machine. A
    ; release-signed descriptor is accepted only by a transitional Manager
    ; (PBM_RESCUE_ACCEPT_LEGACY) while estates are re-signed with the rescue key.
    lea  rdi, [rel recovery_descriptor + 32]
    lea  rsi, [rel pbm_rescue_key_id]
    mov  edx, 32
    call pbm_bytes_differ
    lea  rcx, [rel pbm_rescue_modulus]
    test eax, eax
    jz   .key_selected
%ifdef PBM_RESCUE_ACCEPT_LEGACY
    lea  rdi, [rel recovery_descriptor + 32]
    lea  rsi, [rel pbm_owner_key_id]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
    lea  rdi, [rel str_recovery_descriptor_legacy]
    call serial_string
    lea  rcx, [rel pbm_owner_modulus]
    jmp  .key_selected
%else
    jmp  .bad
%endif
.key_selected:
    lea  rdi, [rel recovery_descriptor + PBM_RECOVERY_SIGNATURE_OFF]
    lea  rsi, [rel recovery_descriptor]
    mov  edx, PBM_RECOVERY_SIGNED_SIZE
    call pbm_rsa2048_verify_sha256_locked
%else
    ; Without PBM_RESCUE_KEY the bytes are exactly the pre-K19 release-key path.
    lea  rdi, [rel recovery_descriptor + 32]
    lea  rsi, [rel pbm_owner_key_id]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
    lea  rdi, [rel recovery_descriptor + PBM_RECOVERY_SIGNATURE_OFF]
    lea  rsi, [rel recovery_descriptor]
    mov  edx, PBM_RECOVERY_SIGNED_SIZE
    lea  rcx, [rel pbm_owner_modulus]
    call pbm_rsa2048_verify_sha256_locked
%endif
    test eax, eax
    jnz  .bad
    mov  rax, [rel recovery_descriptor + 8]
    mov  [rel trust_sequence], rax
    mov  byte [rel recovery_descriptor_verified], 1
    lea  rdi, [rel str_recovery_descriptor_valid]
    call serial_string
    xor  eax, eax
    jmp  .out
.bad:
    lea  rdi, [rel str_recovery_descriptor_invalid]
    call serial_string
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
%endif

; integrity_vault_select_entry(EDI=entry ID) -> RAX=authenticated entry, or 0.
; Exactly one trust source may be active.  A valid normal owner manifest owns
; its complete entry set; only when it is absent may the independent read-mostly
; Vault descriptor select its one canonical Rescue identity.  Missing,
; malformed, stale, or ambiguously dual-active trust always fails closed.
integrity_vault_select_entry:
    cmp  byte [rel manifest_verified], 1
    je   .normal_candidate
    cmp  byte [rel manifest_verified], 0
    jne  .missing
    cmp  byte [rel recovery_descriptor_verified], 1
    jne  .missing
    cmp  edi, PBM_ENTRY_RESCUE
    jne  .missing
    lea  rax, [rel recovery_descriptor + PBM_RECOVERY_ENTRY_OFF]
    ret
.normal_candidate:
    cmp  byte [rel recovery_descriptor_verified], 0
    jne  .missing
    movzx ecx, byte [rel manifest + 18]
    lea  rax, [rel manifest + PBM_MANIFEST_ENTRY_OFF]
.next:
    test ecx, ecx
    jz   .missing
    cmp  byte [rax], dil
    je   .out
    add  rax, PBM_MANIFEST_ENTRY_SIZE
    dec  ecx
    jmp  .next
.missing:
    xor  eax, eax
.out:
    ret

; payload_pe_valid(RDI=verified image bytes, EDX=image bytes, RSI=manifest entry)
; -> EAX=1 only for a bounded PE32+ x86-64 EFI application header.
; RCQ-29 S2(a): in an authenticated Try boot the bytes must be the Try envelope
; (PBM_TRY_ENVELOPE_MAGIC, then a zero qword) in place of "MZ", with every other
; PE check unchanged at the original offsets; a raw MZ image is refused there.
; Outside Try the envelope is refused (no MZ).
payload_pe_valid:
    cmp  edx, 0x100
    jb   .bad
%ifdef PBM_FEATURE_MUTABLE
    cmp  byte [rel try_media_boot], 1
    jne  .mz
    mov  rax, PBM_TRY_ENVELOPE_MAGIC
    cmp  [rdi], rax
    jne  .bad
    cmp  qword [rdi + 8], 0
    jne  .bad
    jmp  .header
.mz:
%endif
    cmp  word [rdi], 0x5A4D
    jne  .bad
.header:
    mov  eax, [rdi + 0x3C]
    mov  ecx, eax
    add  ecx, 94
    jc   .bad
    cmp  ecx, edx
    ja   .bad
    cmp  dword [rdi + rax], 0x00004550
    jne  .bad
    cmp  word [rdi + rax + 4], 0x8664
    jne  .bad
    cmp  word [rdi + rax + 20], 70
    jb   .bad
    cmp  word [rdi + rax + 24], 0x020B
    jne  .bad
    mov  dx, [rsi + 50]
    cmp  word [rdi + rax + 92], dx
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; verify_payload_file: R13=canonical UCS-2 path, R14D=path bytes including NUL,
; R15D=entry ID. Returns EAX=0 only after the signed entry path matches, the
; file is read exactly once in bounded chunks, PE identity matches, EOF occurs
; at the signed size, and SHA-256 matches the signed digest.
verify_payload_file:
%ifndef PBM_OWNER_KEY
    mov  eax, 1
    ret
%else
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  byte [rel payload_verify_ok], 0
    mov  qword [rel opened_file], 0
    cmp  byte [rel manifest_verified], 1
    je   .trust_ready
    cmp  byte [rel recovery_descriptor_verified], 1
    jne  .out
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .out
.trust_ready:

    mov  edi, r15d
    call integrity_vault_select_entry
    test rax, rax
    jz   .out
    mov  rbp, rax
    movzx eax, word [rbp + 48]
    inc  eax
    shl  eax, 1
    cmp  eax, r14d
    jne  .out
    lea  rdi, [rbp + 52]
    mov  rsi, r13
    mov  edx, r14d
    call pbm_bytes_differ
    test eax, eax
    jnz  .out

    mov  rax, [rel boot_services]
    mov  ecx, 2                       ; EfiLoaderData
    mov  edx, [rbp + 4]
    lea  r8, [rel verified_source_buffer]
    PBM_FW_ENTER 32
    call [rax + 0x40]                 ; AllocatePool exact signed size
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .out

    mov  rax, [rel payload_root]
    test rax, rax
    jz   .out
    mov  rcx, rax
    lea  rdx, [rel opened_file]
    mov  r8, r13
    mov  r9d, 1                      ; EFI_FILE_MODE_READ
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0
    call [rax + 8]
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .out
    mov  r12, [rel opened_file]

    lea  rdi, [rel payload_sha_ctx]
    call sha256_stream_init
    mov  ebx, [rbp + 4]              ; exact signed image size, already bounded
    mov  dword [rel payload_bytes_read], 0
.read_chunk:
    test ebx, ebx
    jz   .check_eof
    mov  eax, 4096
    cmp  ebx, eax
    cmovb eax, ebx
    mov  r14d, eax                    ; preserve exact UINTN request across Read
    mov  [rel payload_read_size], rax
    mov  rcx, r12
    lea  rdx, [rel payload_read_size]
    mov  r8, [rel verified_source_buffer]
    mov  eax, [rel payload_bytes_read]
    add  r8, rax
    PBM_FW_ENTER 32
    call [r12 + 32]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    mov  rdx, [rel payload_read_size]
    test rdx, rdx
    jz   .close
    ; A successful firmware Read still supplies an untrusted UINTN count.
    ; Bound all 64 bits to this chunk before hashing or advancing the buffer.
    cmp  rdx, r14
    jbe  .size_bounded
    jmp  .close
.size_bounded:
    lea  rdi, [rel payload_sha_ctx]
    mov  rsi, [rel verified_source_buffer]
    mov  eax, [rel payload_bytes_read]
    add  rsi, rax
    mov  rdx, [rel payload_read_size]
    call sha256_stream_update
    test rax, rax
    jnz  .close
    mov  eax, [rel payload_read_size]
    add  [rel payload_bytes_read], eax
    sub  ebx, eax
    jmp  .read_chunk

.check_eof:
    mov  qword [rel payload_read_size], 1
    mov  rcx, r12
    lea  rdx, [rel payload_read_size]
    lea  r8, [rel read_tail]
    PBM_FW_ENTER 32
    call [r12 + 32]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    cmp  qword [rel payload_read_size], 0
    jne  .close
    mov  rdi, [rel verified_source_buffer]
    mov  edx, [rbp + 4]
    mov  rsi, rbp
    call payload_pe_valid
    test eax, eax
    jz   .close
    lea  rdi, [rel payload_sha_ctx]
    lea  rsi, [rel verified_payload_sha]
    call sha256_stream_final
    test rax, rax
    jnz  .close
    lea  rdi, [rel verified_payload_sha]
    lea  rsi, [rbp + 16]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .close
    mov  eax, [rbp + 4]
    mov  [rel verified_payload_size], eax
    mov  [rel verified_payload_entry], r15b
    mov  byte [rel payload_verify_ok], 1
.close:
    mov  rcx, r12
    PBM_FW_ENTER 32
    call [r12 + 16]
    PBM_FW_LEAVE 32
.out:
    xor  eax, eax
    cmp  byte [rel payload_verify_ok], 1
    je   .done
    call free_verified_source_buffer
    mov  eax, 1
.done:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
%endif

; Release the exact verified source buffer after LoadImage has consumed it, or
; on any verification/load failure. It is never reused across fallback tries.
free_verified_source_buffer:
    push rbx
    mov  rbx, [rel verified_source_buffer]
    test rbx, rbx
    jz   .done
    mov  rcx, rbx
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x48]                 ; FreePool
    PBM_FW_LEAVE 32
    mov  qword [rel verified_source_buffer], 0
.done:
    pop  rbx
    ret

; rescue_shim_loader_probe -> EAX=1 and rescue_direct_uki=1 when a first-stage
; shim >= 16.1 has installed SHIM_IMAGE_LOADER (its gBS->LoadImage replacement);
; otherwise EAX=0 and Rescue keeps the nested-shim launch.  Only a successful
; LocateProtocol with a non-NULL interface selects the direct UKI load.  The
; conditional sits inside the label so label-bounded cuts of neighbours stay balanced.
rescue_shim_loader_probe:
%ifdef PBM_FEATURE_MANIFEST
    mov  byte [rel rescue_direct_uki], 0
    mov  qword [rel rescue_shim_loader_proto], 0
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .absent
    lea  rcx, [rel shim_image_loader_guid]
    xor  edx, edx
    lea  r8, [rel rescue_shim_loader_proto]
    PBM_FW_ENTER 40
    call [rax + 0x140]                  ; LocateProtocol(SHIM_IMAGE_LOADER)
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .absent
    cmp  qword [rel rescue_shim_loader_proto], 0
    je   .absent
    mov  byte [rel rescue_direct_uki], 1
    lea  rdi, [rel str_rescue_shim16_direct]
    call serial_string
    mov  eax, 1
    ret
.absent:
    xor  eax, eax
    ret
%endif
; end rescue_shim_loader_probe

; The independent Rescue shim is immutable MS-signed Ubuntu shim 15.8, not
; an arbitrary firmware-db image.  Bound it to the same 966664-byte SHA256
; as the live Boot0002 shim before allowing it to select the manifest UKI.
verify_rescue_shim:
    push rbx
    push r12
    sub  rsp, 32
    mov  qword [rel rescue_shim_buffer], 0
    mov  qword [rel opened_file], 0
    mov  rax, [rel boot_services]
    mov  ecx, 2
    mov  edx, 966664
    lea  r8, [rel rescue_shim_buffer]
    PBM_FW_ENTER 32
    call [rax + 0x40]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .bad
    mov  rax, [rel payload_root]
    test rax, rax
    jz   .bad
    mov  rcx, rax
    lea  rdx, [rel opened_file]
    lea  r8, [rel ucs2_rescue_shim]
    mov  r9d, 1
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0
    call [rax + 8]
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .bad
    mov  r12, [rel opened_file]
    xor  ebx, ebx
.read:
    cmp  ebx, 966664
    je   .eof
    mov  eax, 966664
    sub  eax, ebx
    mov  [rel payload_read_size], rax
    mov  rcx, r12
    lea  rdx, [rel payload_read_size]
    mov  r8, [rel rescue_shim_buffer]
    add  r8, rbx
    PBM_FW_ENTER 32
    call [r12 + 32]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close_bad
    mov  rax, [rel payload_read_size]
    test rax, rax
    jz   .close_bad
    mov  edx, 966664
    sub  rdx, rbx                    ; exact remaining request, full UINTN bound
    cmp  rax, rdx
    ja   .close_bad
    add  rbx, rax                    ; advance only after full-width validation
    jmp  .read
.eof:
    mov  qword [rel payload_read_size], 1
    mov  rcx, r12
    lea  rdx, [rel payload_read_size]
    lea  r8, [rel read_tail]
    PBM_FW_ENTER 32
    call [r12 + 32]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close_bad
    cmp  qword [rel payload_read_size], 0
    jne  .close_bad
    mov  rcx, r12
    PBM_FW_ENTER 32
    call [r12 + 16]
    PBM_FW_LEAVE 32
    mov  qword [rel opened_file], 0
    lea  rdi, [rel rescue_shim_sha]
    mov  rsi, [rel rescue_shim_buffer]
    mov  edx, 966664
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel rescue_shim_sha]
    lea  rsi, [rel pinned_rescue_shim_sha]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
    xor  ebx, ebx
    jmp  .free
.close_bad:
    mov  rcx, r12
    PBM_FW_ENTER 32
    call [r12 + 16]
    PBM_FW_LEAVE 32
.bad:
    mov  ebx, 1
.free:
    mov  rcx, [rel rescue_shim_buffer]
    test rcx, rcx
    jz   .done
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x48]
    PBM_FW_LEAVE 32
    mov  qword [rel rescue_shim_buffer], 0
.done:
    mov  eax, ebx
    add  rsp, 32
    pop  r12
    pop  rbx
    ret

; PaOSManifestFloor: the highest owner-manifest sequence and digest that a
; healthy boot committed, in an NV|BS variable (attributes exactly 3). After
; ExitBootServices no OS can read or write it, unlike the ESP journal. Raised only
; after a durable healthy journal commit (never at attempt start), by max only,
; with readback. A copy with other attributes, size or contents is not ours: it
; is ignored and replaced at the next raise. No variable store or a read error
; leaves the journal floor alone in force, with a marker; the boot is not blocked.
PBM_MFLOOR_ATTRS        equ 3
PBM_MFLOOR_MAGIC        equ 0x31464D50  ; "PMF1"
PBM_MFLOOR_VERSION      equ 1
PBM_MFLOOR_SIZE         equ 64
PBM_MFLOOR_SEQ_OFF      equ 8
PBM_MFLOOR_SHA_OFF      equ 16          ; 48..59 zero
PBM_MFLOOR_CRC_OFF      equ 60          ; CRC32 over [0, 60)
PBM_MFLOOR_AUTH_ATTRS   equ 0x30        ; AUTHENTICATED_WRITE | TIME_BASED_AUTHENTICATED_WRITE

; manifest_floor_load -> nothing; sets mfloor_state once per boot. Preserves
; every register except RAX and flags.
manifest_floor_load:
    cmp  byte [rel mfloor_state], PBM_MFLOOR_UNREAD
    jne  .ret
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  bl, PBM_MFLOOR_UNAVAILABLE
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .set
    mov  qword [rel mfloor_size], PBM_MFLOOR_SIZE
    mov  dword [rel mfloor_attrs], 0
    lea  rcx, [rel mfloor_var_name]
    lea  rdx, [rel health_var_guid]
    lea  r8, [rel mfloor_attrs]
    lea  r9, [rel mfloor_size]
    PBM_FW_ENTER 40
    lea  r10, [rel mfloor_blob]
    mov  [rsp + 32], r10
    call [rax + 0x48]                 ; GetVariable
    PBM_FW_LEAVE 40
    mov  bl, PBM_MFLOOR_ABSENT
    mov  rdx, 0x800000000000000E      ; EFI_NOT_FOUND
    cmp  rax, rdx
    je   .set
    mov  bl, PBM_MFLOOR_FOREIGN
    mov  rdx, 0x8000000000000005      ; EFI_BUFFER_TOO_SMALL: oversized, not ours
    cmp  rax, rdx
    je   .foreign
    mov  bl, PBM_MFLOOR_UNAVAILABLE
    test rax, rax
    jnz  .set                         ; a device error decides nothing
    mov  bl, PBM_MFLOOR_FOREIGN
    cmp  dword [rel mfloor_attrs], PBM_MFLOOR_ATTRS
    jne  .foreign                     ; RT-visible or otherwise foreign: never trusted
    cmp  qword [rel mfloor_size], PBM_MFLOOR_SIZE
    jne  .set
    lea  rdi, [rel mfloor_blob]
    call manifest_floor_blob_valid
    test eax, eax
    jz   .set
    mov  bl, PBM_MFLOOR_HELD
    jmp  .set
.foreign:
    ; An authenticated-write copy cannot be removed by the Manager's unsigned
    ; delete: report it as SQUATTED (loud-open, admin C1), never as a floor.
    test dword [rel mfloor_attrs], PBM_MFLOOR_AUTH_ATTRS
    jz   .set
    mov  bl, PBM_MFLOOR_SQUATTED
.set:
    mov  [rel mfloor_state], bl
    lea  rdi, [rel str_mfloor_held]
    cmp  bl, PBM_MFLOOR_HELD
    je   .marker
    lea  rdi, [rel str_mfloor_squatted]
    cmp  bl, PBM_MFLOOR_SQUATTED
    je   .marker
    lea  rdi, [rel str_mfloor_absent]
    cmp  bl, PBM_MFLOOR_ABSENT
    je   .marker
    lea  rdi, [rel str_mfloor_foreign]
    cmp  bl, PBM_MFLOOR_FOREIGN
    je   .marker
    lea  rdi, [rel str_mfloor_unavailable]
.marker:
    call serial_string
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
.ret:
    ret

; manifest_floor_blob_valid(RDI=blob) -> EAX=1 for an exact PMF1 record with a
; nonzero sequence. Clobbers RCX, RDX.
manifest_floor_blob_valid:
    cmp  dword [rdi], PBM_MFLOOR_MAGIC
    jne  .bad
    cmp  dword [rdi + 4], PBM_MFLOOR_VERSION | (PBM_MFLOOR_SIZE << 16)
    jne  .bad
    cmp  qword [rdi + PBM_MFLOOR_SEQ_OFF], 0
    je   .bad
    mov  ecx, 48
.pad:
    cmp  byte [rdi + rcx], 0
    jne  .bad
    inc  ecx
    cmp  ecx, PBM_MFLOOR_CRC_OFF
    jb   .pad
    push rdi
    mov  ecx, PBM_MFLOOR_CRC_OFF
    call crc32
    pop  rdi
    cmp  eax, [rdi + PBM_MFLOOR_CRC_OFF]
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; manifest_floor_raise -> nothing. Called only after a durable healthy journal
; commit bound to the verified manifest. Writes {seq, digest} of that manifest
; when it is above the held floor (or none is held), deleting a foreign copy
; first, and keeps it only after an exact readback. Any failure is a marker and
; leaves this boot's policy unchanged.
manifest_floor_raise:
    push rbx
    call manifest_floor_load
    mov  rbx, [rel runtime_services]
    mov  al, [rel mfloor_state]
    cmp  al, PBM_MFLOOR_UNAVAILABLE
    je   .unavailable
    cmp  al, PBM_MFLOOR_HELD
    jne  .not_held
    mov  rax, [rel manifest + 8]
    cmp  rax, [rel mfloor_blob + PBM_MFLOOR_SEQ_OFF]
    jbe  .out                         ; max only: never rewrite at or below the floor
    jmp  .build
.not_held:
    cmp  al, PBM_MFLOOR_FOREIGN
    je   .delete
    cmp  al, PBM_MFLOOR_SQUATTED
    jne  .build
.delete:
    lea  rcx, [rel mfloor_var_name]
    lea  rdx, [rel health_var_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0
    call [rbx + 0x58]                 ; SetVariable(name,guid,0,0,NULL): delete
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .squatted
.build:
    lea  rdi, [rel mfloor_new]
    xor  eax, eax
    mov  ecx, PBM_MFLOOR_SIZE / 8
    rep  stosq
    mov  dword [rel mfloor_new], PBM_MFLOOR_MAGIC
    mov  dword [rel mfloor_new + 4], PBM_MFLOOR_VERSION | (PBM_MFLOOR_SIZE << 16)
    mov  rax, [rel manifest + 8]
    mov  [rel mfloor_new + PBM_MFLOOR_SEQ_OFF], rax
    lea  rsi, [rel verified_manifest_sha]
    lea  rdi, [rel mfloor_new + PBM_MFLOOR_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    lea  rdi, [rel mfloor_new]
    mov  ecx, PBM_MFLOOR_CRC_OFF
    call crc32
    mov  [rel mfloor_new + PBM_MFLOOR_CRC_OFF], eax
    ; From here the cached copy is no longer trusted until the readback matches.
    mov  byte [rel mfloor_state], PBM_MFLOOR_UNAVAILABLE
    lea  rcx, [rel mfloor_var_name]
    lea  rdx, [rel health_var_guid]
    mov  r8d, PBM_MFLOOR_ATTRS
    mov  r9d, PBM_MFLOOR_SIZE
    PBM_FW_ENTER 40
    lea  rax, [rel mfloor_new]
    mov  [rsp + 32], rax
    call [rbx + 0x58]                 ; SetVariable
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .failed
    mov  qword [rel mfloor_size], PBM_MFLOOR_SIZE
    mov  dword [rel mfloor_attrs], 0
    lea  rcx, [rel mfloor_var_name]
    lea  rdx, [rel health_var_guid]
    lea  r8, [rel mfloor_attrs]
    lea  r9, [rel mfloor_size]
    PBM_FW_ENTER 40
    lea  rax, [rel mfloor_blob]
    mov  [rsp + 32], rax
    call [rbx + 0x48]                 ; GetVariable readback
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .failed
    cmp  qword [rel mfloor_size], PBM_MFLOOR_SIZE
    jne  .failed
    cmp  dword [rel mfloor_attrs], PBM_MFLOOR_ATTRS
    jne  .failed
    lea  rdi, [rel mfloor_blob]
    lea  rsi, [rel mfloor_new]
    mov  edx, PBM_MFLOOR_SIZE
    call pbm_bytes_differ
    test eax, eax
    jnz  .failed
    mov  byte [rel mfloor_state], PBM_MFLOOR_HELD
    lea  rdi, [rel str_mfloor_raised]
    call serial_string
    jmp  .out
.failed:
    lea  rdi, [rel str_mfloor_raise_failed]
    call serial_string
    jmp  .out
.squatted:
    mov  byte [rel mfloor_state], PBM_MFLOOR_SQUATTED
    lea  rdi, [rel str_mfloor_squatted]
    call serial_string
    jmp  .out
.unavailable:
    lea  rdi, [rel str_mfloor_unavailable]
    call serial_string
.out:
    pop  rbx
    ret

; manifest_floor_check -> EAX=0 when no floor is held, or the verified manifest
; is above it, or at its sequence with its exact digest; else EAX=1 + marker.
manifest_floor_check:
    call manifest_floor_load
    cmp  byte [rel mfloor_state], PBM_MFLOOR_HELD
    jne  .ok
    mov  rcx, [rel manifest + 8]
    cmp  rcx, [rel mfloor_blob + PBM_MFLOOR_SEQ_OFF]
    ja   .ok
    jb   .bad
    lea  rdi, [rel verified_manifest_sha]
    lea  rsi, [rel mfloor_blob + PBM_MFLOOR_SHA_OFF]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
.ok:
    xor  eax, eax
    ret
.bad:
    PBM_PRESELECT 0xF001
    lea  rdi, [rel str_mfloor_rejected]
    call serial_string
    mov  eax, 1
    ret

; enforce_manifest_state_floor -> EAX=0 when an unbound migration state, a
; strictly newer owner manifest, or the exact same-sequence manifest digest is
; present. A rollback or same-sequence substitution invalidates all transfer,
; including Rescue, because no payload may be authenticated by a rejected
; manifest.
; The ESP journal is CRC-only, so a runtime OS can reset it to seq 0 beside an
; older owner-signed manifest. PaOSManifestFloor (NV|BS, hidden after EBS) is
; checked first and is not bypassed by a NULL or unbound journal.
enforce_manifest_state_floor:
    call manifest_floor_check
    test eax, eax
    jnz  .bad
    mov  rax, [rel selected_state_ptr]
    test rax, rax
    jz   .good                         ; no trusted state floor: Rescue bootstrap
    mov  rdx, [rax + PBM_STATE_MANIFEST_SEQ_OFF]
    test rdx, rdx
    jz   .good                         ; explicit initial migration/unbound state
    mov  rcx, [rel manifest + 8]
    cmp  rcx, rdx
    ja   .good
    jb   .bad
    lea  rdi, [rel verified_manifest_sha]
    lea  rsi, [rax + PBM_STATE_MANIFEST_SHA_OFF]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
.good:
    lea  rdi, [rel str_manifest_state_bound]
    call serial_string
    xor  eax, eax
    ret
.bad:
    lea  rdi, [rel str_manifest_state_rejected]
    call serial_string
    mov  eax, 1
    ret

; health_record_valid -> EAX=1 only when the bounded runtime-variable record
; names the exact durable BIP attempt and the exact currently verified signed
; manifest entry. A newer manifest is deliberately not accepted while an older
; attempt is pending: deployment must not replace its evidence mid-transaction.
health_record_valid:
    push rbx
    push r12
    push r13
    push r14
    lea  r12, [rel health_record]
    cmp  dword [r12 + PBM_HEALTH_MAGIC_OFF], PBM_HEALTH_MAGIC
    jne  .bad
    cmp  word [r12 + PBM_HEALTH_VERSION_OFF], PBM_CONTRACT_VERSION
    jne  .bad
    cmp  word [r12 + PBM_HEALTH_SIZE_OFF], PBM_HEALTH_SIZE
    jne  .bad
    cmp  word [r12 + PBM_HEALTH_FLAGS_OFF], 0
    jne  .bad
    cmp  word [r12 + PBM_HEALTH_CHECKPOINT_OFF], PBM_HEALTH_CHECKPOINT_STRONG
    jne  .bad
    cmp  word [r12 + 38], 0
    jne  .bad
    lea  rsi, [r12 + 72]
    mov  ecx, PBM_HEALTH_CRC32 - 72
.reserved_zero:
    cmp  byte [rsi], 0
    jne  .bad
    inc  rsi
    dec  ecx
    jnz  .reserved_zero
    mov  ebx, [r12 + PBM_HEALTH_CRC32]
    mov  rdi, r12
    mov  ecx, PBM_HEALTH_CRC32
    call crc32
    cmp  eax, ebx
    jne  .bad

    cmp  byte [rel manifest_verified], 1
    jne  .bad
    mov  r13, [rel selected_state_ptr]
    test r13, r13
    jz   .bad
    cmp  byte [r13 + PBM_STATE_BIP_OFF], 1
    jne  .bad
    cmp  byte [r13 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    movzx eax, byte [r12 + PBM_HEALTH_ENTRY_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .entry_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .bad
.entry_ok:
    cmp  byte [r12 + PBM_HEALTH_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    cmp  al, [r13 + PBM_STATE_LAST_ENTRY_OFF]
    jne  .bad
    mov  rax, [r12 + PBM_HEALTH_ATTEMPT_NONCE_OFF]
    test rax, rax
    jz   .bad
    cmp  rax, [r13 + PBM_STATE_ATTEMPT_NONCE_OFF]
    jne  .bad
    mov  rax, [r12 + PBM_HEALTH_STATE_GEN_OFF]
    test rax, rax
    jz   .bad
    cmp  rax, [r13 + PBM_STATE_GENERATION_OFF]
    jne  .bad
    mov  rax, [r12 + PBM_HEALTH_MANAGER_SEQ_OFF]
    test rax, rax
    jz   .bad
    cmp  rax, [rel manifest + 8]
    jne  .bad
    cmp  rax, [r13 + PBM_STATE_MANIFEST_SEQ_OFF]
    jne  .bad
    lea  rdi, [rel verified_manifest_sha]
    lea  rsi, [r13 + PBM_STATE_MANIFEST_SHA_OFF]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
    movzx edi, byte [r12 + PBM_HEALTH_ENTRY_OFF]
    call integrity_vault_select_entry
    test rax, rax
    jz   .bad
    mov  r14, rax
    lea  rdi, [r12 + PBM_HEALTH_PAYLOAD_SHA_OFF]
    lea  rsi, [r14 + 16]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; delete_health_variable -> EFI status. Deletion happens only after a durable
; healthy journal commit, or when a record is structurally invalid/stale. If a
; crash leaves a valid record behind after commit, BIP/state-generation mismatch
; makes it stale on the next boot, so replay cannot promote twice.
delete_health_variable:
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .missing
    lea  rcx, [rel health_var_name]
    lea  rdx, [rel health_var_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0
    call [rax + 0x58]                 ; SetVariable(name,guid,0,0,NULL)
    PBM_FW_LEAVE 40
    ret
.missing:
    mov  rax, -1
    ret

; consume_strong_health -> EAX=1 only on a fatal journal-commit failure.
; Missing/unreadable/invalid records never clear BIP. Exact valid records are
; journaled first and only then consumed from NVRAM.  The result markers name
; the winning authority explicitly so candidate evidence can distinguish an
; exact current-attempt checkpoint from stale evidence without inference.
consume_strong_health:
    push rbx
    push r12
    mov  byte [rel health_consumed], 0
    mov  qword [rel health_size], PBM_HEALTH_SIZE
    mov  dword [rel health_attributes], 0
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .ignored
    lea  rcx, [rel health_var_name]
    lea  rdx, [rel health_var_guid]
    lea  r8, [rel health_attributes]
    lea  r9, [rel health_size]
    PBM_FW_ENTER 40
    lea  rbx, [rel health_record]
    mov  [rsp + 32], rbx
    call [rax + 0x48]                 ; GetVariable
    PBM_FW_LEAVE 40
    test rax, rax
    jz   .read
    cmp  qword [rel health_size], PBM_HEALTH_SIZE
    ja   .stale                       ; bounded namespace: discard oversized data
    jmp  .quiet
.read:
    cmp  qword [rel health_size], PBM_HEALTH_SIZE
    jne  .stale
    cmp  dword [rel health_attributes], 7
    jne  .stale
%ifdef PBM_TEST_CORRUPT_HEALTH_NONCE
    ; QEMU rejection oracle: keep the record structurally valid while breaking
    ; only its binding to the authoritative pending attempt.
    xor  qword [rel health_record + PBM_HEALTH_ATTEMPT_NONCE_OFF], 1
    lea  rdi, [rel health_record]
    mov  ecx, PBM_HEALTH_CRC32
    call crc32
    mov  [rel health_record + PBM_HEALTH_CRC32], eax
%endif
    call health_record_valid
    test eax, eax
    jz   .stale

    mov  rsi, [rel selected_state_ptr]
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    movzx ecx, byte [rel health_record + PBM_HEALTH_ENTRY_OFF]
    mov  al, 1
    shl  al, cl
    or   byte [rel state_work + PBM_STATE_VERIFIED_MASK_OFF], al
    mov  dl, al
    not  dl
    and  byte [rel state_work + PBM_STATE_QUARANTINE_MASK_OFF], dl
    mov  byte [rel state_work + PBM_STATE_FAILURE_COUNT_OFF], 0
    mov  byte [rel state_work + PBM_STATE_BIP_OFF], 0
    mov  word [rel state_work + PBM_STATE_START_COUNT_OFF], 0
    mov  rax, [rel health_record + PBM_HEALTH_ATTEMPT_NONCE_OFF]
    mov  [rel state_work + PBM_STATE_READY_NONCE_OFF], rax
    mov  al, [rel health_record + PBM_HEALTH_ENTRY_OFF]
    cmp  al, [rel state_work + PBM_STATE_TRIAL_OFF]
    jne  .not_trial
    mov  dl, [rel state_work + PBM_STATE_ACTIVE_OFF]
    mov  [rel state_work + PBM_STATE_PREVIOUS_OFF], dl
    mov  [rel state_work + PBM_STATE_ACTIVE_OFF], al
    mov  byte [rel state_work + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    mov  byte [rel state_work + PBM_STATE_TRIES_LEFT_OFF], 0
    mov  byte [rel state_work + PBM_STATE_SAFE_ATTEMPTED_OFF], 0
    jmp  .commit
.not_trial:
    cmp  byte [rel state_work + PBM_STATE_LAST_REASON_OFF], PBM_REASON_ROLLBACK
    jne  .clear_safe
    cmp  al, [rel state_work + PBM_STATE_PREVIOUS_OFF]
    jne  .clear_safe
    cmp  al, [rel state_work + PBM_STATE_ACTIVE_OFF]
    je   .clear_safe
    mov  cl, [rel state_work + PBM_STATE_ACTIVE_OFF]
    mov  [rel state_work + PBM_STATE_PREVIOUS_OFF], cl
    mov  [rel state_work + PBM_STATE_ACTIVE_OFF], al
.clear_safe:
%ifdef PBM_FEATURE_FULL_POLICY
    ; A strong NORMAL boot can still carry an exact display-only B1 vector.
    ; If this slot already spent its one video-Safe attempt, retain that
    ; durable bit through the health commit so b1_apply_policy_evidence can
    ; reject another no-network Safe one-shot for the same payload/attempt.
    ; Ordinary healthy and Trial promotion keep their existing clear path.
    cmp  byte [rel b1_evidence_kind], PBM_B1_EVIDENCE_SAFE_VIDEO
    jne  .clear_safe_bit
    mov  al, [rel health_record + PBM_HEALTH_ENTRY_OFF]
    cmp  al, [rel b1_evidence_entry]
    jne  .clear_safe_bit
    mov  rax, [rel health_record + PBM_HEALTH_ATTEMPT_NONCE_OFF]
    cmp  rax, [rel b1_evidence_nonce]
    je   .commit
%endif
.clear_safe_bit:
    movzx ecx, byte [rel health_record + PBM_HEALTH_ENTRY_OFF]
    mov  dl, 1
    shl  dl, cl
    not  dl
    and  byte [rel state_work + PBM_STATE_SAFE_ATTEMPTED_OFF], dl
.commit:
    lea  r12, [rel state_work]
    call journal_commit
    test eax, eax
    jnz  .commit_failed
    mov  byte [rel health_consumed], 1
    call manifest_floor_raise
    call delete_health_variable
    test rax, rax
    jz   .consumed
    lea  rdi, [rel str_health_delete_failed]
    call serial_string
.consumed:
    lea  rdi, [rel str_health_consumed]
    call serial_string
    xor  eax, eax
    jmp  .out
.stale:
    call delete_health_variable
.ignored:
    lea  rdi, [rel str_health_ignored]
    call serial_string
.quiet:
    xor  eax, eax
    jmp  .out
.commit_failed:
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_health_commit_failed]
    call serial_string
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

; Read one fixed 128-byte B1 runtime record.  Rcx=name, Rdx=GUID, Rdi=buffer;
; EAX=1 only for the established nonvolatile/boot/runtime attributes and exact
; size.  The content validators below independently authenticate every byte.
b1_read_record:
    push rbx
    mov  rbx, rdi
    mov  qword [rel b1_io_size], 128
    mov  dword [rel b1_io_attrs], 0
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .bad
    lea  r8, [rel b1_io_attrs]
    lea  r9, [rel b1_io_size]
    PBM_FW_ENTER 40
    mov  [rsp + 32], rbx
    call [rax + 0x48]                 ; EFI_RUNTIME_SERVICES.GetVariable
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .bad
    cmp  qword [rel b1_io_size], 128
    jne  .bad
    cmp  dword [rel b1_io_attrs], PBM_B1_EFI_ATTRS
    jne  .bad
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Return EAX=1 only when RSI's digest is the signed digest for EDI's current
; manifest identity.  This is used both at evidence admission and whenever a
; persisted cross-slot fact is reconsidered after a manifest update.
b1_manifest_sha_matches:
    push rbx
    mov  rbx, rsi
    call integrity_vault_select_entry
    test rax, rax
    jz   .different
    mov  rdi, rbx
    lea  rsi, [rax + 16]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .different
    mov  eax, 1
    pop  rbx
    ret
.different:
    xor  eax, eax
    pop  rbx
    ret

; PaOSHealthVector v2 is eligible for safe-video only when the exact normal
; BIP reached every non-display dimension, including network, and an acquired
; display is the sole degraded result.  UNAVAILABLE means there is no linear
; framebuffer to salvage; a serial-only Safe boot would strand a headless
; customer without network or an automatic Windows return.  A mode-set result,
; another mandatory failure, Safe profile, stale nonce, or foreign payload
; cannot reach .good.
b1_display_only_vector_valid:
    push rbx
    push r12
    push r13
    lea  r13, [rel b1_health_vector]
    mov  r12, [rel b1_inspect_state_ptr]
    test r12, r12
    jz   .bad
    cmp  dword [r13], PBM_B1_MH_MAGIC
    jne  .bad
    cmp  word [r13 + 4], PBM_B1_MH_VERSION
    jne  .bad
    cmp  word [r13 + 6], PBM_B1_MH_SIZE
    jne  .bad
    mov  ebx, [r13 + PBM_B1_MH_CRC32]
    mov  rdi, r13
    mov  ecx, PBM_B1_MH_CRC32
    call crc32
    cmp  eax, ebx
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_ENTRY_OFF], PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  byte [r13 + PBM_B1_MH_ENTRY_OFF], PBM_ENTRY_PAOS_B
    ja   .bad
    cmp  byte [r13 + PBM_B1_MH_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_STAGE_OFF], PBM_INIT_STAGE_P8
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_DIM_COUNT_OFF], PBM_B1_MH_DIM_COUNT
    jne  .bad
    cmp  word [r13 + PBM_B1_MH_COMPLETED_MASK_OFF], PBM_INIT_STAGE_ALL_MASK
    jne  .bad
    cmp  qword [r13 + PBM_B1_MH_INIT_GEN_OFF], 0
    je   .bad
    cmp  dword [r13 + PBM_B1_MH_FAILURE_FINGERPRINT_OFF], 0
    jne  .bad
    cmp  word [r13 + PBM_B1_MH_FLAGS_OFF], (PBM_B1_MH_F_STRONG_CORE | PBM_B1_MH_F_OPTIONAL_DEGRADED)
    jne  .bad
    test word [r13 + PBM_B1_MH_FLAGS_OFF], PBM_B1_MH_F_DISPLAY_ESTABLISHED
    jnz  .bad
    cmp  byte [r13 + PBM_B1_MH_IMAGE_OFF], PBM_B1_MH_READY
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_CORE_OFF], PBM_B1_MH_READY
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_DESKTOP_OFF], PBM_B1_MH_READY
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_COMMAND_OFF], PBM_B1_MH_READY
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_STORAGE_OFF], PBM_B1_MH_READY
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_NETWORK_OFF], PBM_B1_MH_READY
    jne  .bad
    mov  al, [r13 + PBM_B1_MH_DISPLAY_OFF]
    cmp  al, PBM_B1_MH_DEGRADED
    jne  .bad
    cmp  byte [r13 + PBM_B1_MH_MACHINE_OFF], PBM_B1_MH_DEGRADED
    jne  .bad

    cmp  byte [r12 + PBM_STATE_BIP_OFF], 1
    jne  .bad
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    mov  al, [r13 + PBM_B1_MH_ENTRY_OFF]
    cmp  al, [r12 + PBM_STATE_LAST_ENTRY_OFF]
    jne  .bad
    mov  al, [r13 + PBM_B1_MH_REASON_OFF]
    cmp  al, [r12 + PBM_STATE_LAST_REASON_OFF]
    jne  .bad
    mov  rax, [r13 + PBM_B1_MH_ATTEMPT_NONCE_OFF]
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + PBM_STATE_ATTEMPT_NONCE_OFF]
    jne  .bad
    mov  rax, [r13 + PBM_B1_MH_STATE_GEN_OFF]
    cmp  rax, [r12 + PBM_STATE_GENERATION_OFF]
    jne  .bad
    mov  rax, [r13 + PBM_B1_MH_MANAGER_SEQ_OFF]
    cmp  rax, [r12 + PBM_STATE_MANIFEST_SEQ_OFF]
    jne  .bad
    cmp  rax, [rel manifest + 8]
    jne  .bad
    movzx edi, byte [r13 + PBM_B1_MH_ENTRY_OFF]
    lea  rsi, [r13 + PBM_B1_MH_PAYLOAD_SHA_OFF]
    call b1_manifest_sha_matches
    test eax, eax
    jz   .bad
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate the exact PaOSInitCheckpoint B1 failure record and return its
; normalized nonzero fingerprint.  Comparison input is only
; {stage,result,implicated}; all volatile/exact identity fields remain gates.
b1_failure_checkpoint_valid:
    push rbx
    push r12
    push r13
    push r14
    lea  r13, [rel b1_init_record]
    mov  r12, [rel b1_inspect_state_ptr]
    test r12, r12
    jz   .bad
    cmp  dword [r13 + PBM_INIT_MAGIC_OFF], PBM_INIT_MAGIC
    jne  .bad
    cmp  word [r13 + PBM_INIT_VERSION_OFF], PBM_INIT_VERSION
    je   .b1gate_v1
    cmp  word [r13 + PBM_INIT_VERSION_OFF], PBM_INIT_GRAPH_VERSION
    jne  .bad
    cmp  byte [r13 + PBM_INIT_GATE_OFF], PBM_INIT_GATE_UNKNOWN
    je   .b1gate_unknown
    cmp  byte [r13 + PBM_INIT_GATE_OFF], 11
    ja   .bad
    cmp  byte [r13 + PBM_INIT_GATE_SOURCE_OFF], PBM_INIT_GATE_NATIVE
    jne  .bad
    jmp  .b1gate_tail
.b1gate_unknown:
    cmp  byte [r13 + PBM_INIT_GATE_SOURCE_OFF], 0
    jne  .bad
.b1gate_tail:
    cmp  word [r13 + 114], 0
    jne  .bad
    jmp  .b1gate_zero
.b1gate_v1:
    cmp  dword [r13 + 112], 0
    jne  .bad
.b1gate_zero:
    cmp  qword [r13 + 116], 0
    jne  .bad
.b1gate_valid:
    cmp  word [r13 + PBM_INIT_SIZE_OFF], PBM_INIT_RECORD_SIZE
    jne  .bad
    mov  ebx, [r13 + PBM_INIT_CRC32]
    mov  rdi, r13
    mov  ecx, PBM_INIT_CRC32
    call crc32
    cmp  eax, ebx
    jne  .bad
    cmp  qword [r13 + PBM_INIT_GENERATION_OFF], 0
    je   .bad
    cmp  byte [r13 + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    jne  .bad
    movzx r14d, byte [r13 + PBM_INIT_STAGE_OFF]
    cmp  r14d, PBM_INIT_STAGE_P8
    ja   .bad
    movzx ecx, byte [r13 + PBM_INIT_RESULT_OFF]
    cmp  ecx, PBM_INIT_RESULT_NONE
    je   .result_ok
    cmp  ecx, PBM_INIT_RESULT_FAILED
    jne  .bad
.result_ok:
    movzx edx, word [r13 + PBM_INIT_IMPLICATED_OFF]
    test edx, edx
    jz   .bad
    cmp  edx, PBM_INIT_SUBSYS_MACHINE
    ja   .bad
    cmp  dx, [r13 + PBM_INIT_SUBSYSTEM_OFF]
    jne  .bad
    shl  ecx, 8
    shl  edx, 16
    or   r14d, ecx
    or   r14d, edx
    or   r14d, PBM_B1_FAILURE_FINGERPRINT_TAG
    cmp  r14d, [r13 + PBM_INIT_FAILURE_FINGERPRINT_OFF]
    jne  .bad

    cmp  byte [r12 + PBM_STATE_BIP_OFF], 1
    jne  .bad
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    cmp  byte [r13 + PBM_INIT_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    mov  al, [r13 + PBM_INIT_ENTRY_OFF]
    cmp  al, PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  al, PBM_ENTRY_PAOS_B
    ja   .bad
    cmp  al, [r12 + PBM_STATE_LAST_ENTRY_OFF]
    jne  .bad
    mov  rax, [r13 + PBM_INIT_ATTEMPT_NONCE_OFF]
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + PBM_STATE_ATTEMPT_NONCE_OFF]
    jne  .bad
    mov  rax, [r13 + PBM_INIT_MANAGER_SEQ_OFF]
    cmp  rax, [r12 + PBM_STATE_MANIFEST_SEQ_OFF]
    jne  .bad
    cmp  rax, [rel manifest + 8]
    jne  .bad
    movzx edi, byte [r13 + PBM_INIT_ENTRY_OFF]
    lea  rsi, [r13 + PBM_INIT_PAYLOAD_SHA_OFF]
    call b1_manifest_sha_matches
    test eax, eax
    jz   .bad
    mov  eax, r14d
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Inspect but do not mutate.  This split is load-bearing: compact strong-health
; must consume against the original BIP generation before B1 policy appends a
; CRC-protected journal fact.
b1_inspect_policy_evidence:
    mov  byte [rel b1_evidence_kind], PBM_B1_EVIDENCE_NONE
    mov  byte [rel b1_evidence_entry], PBM_ENTRY_NONE
    mov  dword [rel b1_evidence_fingerprint], 0
    mov  qword [rel b1_evidence_nonce], 0
    mov  qword [rel b1_inspect_state_ptr], 0
    cmp  byte [rel manifest_verified], 1
    jne  .out
    mov  rax, [rel selected_state_ptr]
    test rax, rax
    jz   .out
    cmp  byte [rax + PBM_STATE_BIP_OFF], 1
    jne  .out
    cmp  byte [rax + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .out
    mov  [rel b1_inspect_state_ptr], rax

    lea  rcx, [rel b1_health_vector_name]
    lea  rdx, [rel b1_telemetry_var_guid]
    lea  rdi, [rel b1_health_vector]
    call b1_read_record
    test eax, eax
    jz   .failure_record
    call b1_display_only_vector_valid
    test eax, eax
    jz   .failure_record
    mov  byte [rel b1_evidence_kind], PBM_B1_EVIDENCE_SAFE_VIDEO
    mov  al, [rel b1_health_vector + PBM_B1_MH_ENTRY_OFF]
    mov  [rel b1_evidence_entry], al
    mov  rax, [rel b1_health_vector + PBM_B1_MH_ATTEMPT_NONCE_OFF]
    mov  [rel b1_evidence_nonce], rax
    lea  rsi, [rel b1_health_vector + PBM_B1_MH_PAYLOAD_SHA_OFF]
    lea  rdi, [rel b1_evidence_sha]
    mov  ecx, 4
    rep  movsq
    jmp  .out

.failure_record:
    lea  rcx, [rel b1_init_var_name]
    lea  rdx, [rel b1_init_var_guid]
    lea  rdi, [rel b1_init_record]
    call b1_read_record
    test eax, eax
    jz   .out
    call b1_failure_checkpoint_valid
    test eax, eax
    jz   .out
    mov  [rel b1_evidence_fingerprint], eax
    mov  byte [rel b1_evidence_kind], PBM_B1_EVIDENCE_FAILURE
    mov  al, [rel b1_init_record + PBM_INIT_ENTRY_OFF]
    mov  [rel b1_evidence_entry], al
    mov  rax, [rel b1_init_record + PBM_INIT_ATTEMPT_NONCE_OFF]
    mov  [rel b1_evidence_nonce], rax
    lea  rsi, [rel b1_init_record + PBM_INIT_PAYLOAD_SHA_OFF]
    lea  rdi, [rel b1_evidence_sha]
    mov  ecx, 4
    rep  movsq
.out:
    ret

; Initialize only the Manager-private B1 journal tail.  Earlier v1 records are
; intentionally compatible because this range was reserved and zero-filled.
b1_prepare_work_state:
    cmp  dword [rel state_work + PBM_B1_STATE_MAGIC_OFF], PBM_B1_STATE_MAGIC
    jne  .initialize
    cmp  byte [rel state_work + PBM_B1_STATE_VERSION_OFF], PBM_B1_STATE_VERSION
    je   .done
.initialize:
    lea  rdi, [rel state_work + PBM_B1_STATE_OFF]
    mov  ecx, (PBM_B1_STATE_END_OFF - PBM_B1_STATE_OFF) / 8
    xor  eax, eax
    rep  stosq
    mov  dword [rel state_work + PBM_B1_STATE_MAGIC_OFF], PBM_B1_STATE_MAGIC
    mov  byte [rel state_work + PBM_B1_STATE_VERSION_OFF], PBM_B1_STATE_VERSION
.done:
    ret

; Drop cross-slot facts whose digest no longer names the current signed slot.
; A manifest update therefore cannot inherit an old failure classification.
b1_prune_stale_failure_evidence:
    test byte [rel state_work + PBM_B1_STATE_EVIDENCE_MASK_OFF], (1 << PBM_ENTRY_PAOS_A)
    jz   .slot_b
    mov  edi, PBM_ENTRY_PAOS_A
    lea  rsi, [rel state_work + PBM_B1_STATE_SHA_A_OFF]
    call b1_manifest_sha_matches
    test eax, eax
    jnz  .slot_b
    and  byte [rel state_work + PBM_B1_STATE_EVIDENCE_MASK_OFF], 0xFD
    mov  dword [rel state_work + PBM_B1_STATE_FP_A_OFF], 0
    lea  rdi, [rel state_work + PBM_B1_STATE_SHA_A_OFF]
    mov  ecx, 4
    xor  eax, eax
    rep  stosq
.slot_b:
    test byte [rel state_work + PBM_B1_STATE_EVIDENCE_MASK_OFF], (1 << PBM_ENTRY_PAOS_B)
    jz   .done
    mov  edi, PBM_ENTRY_PAOS_B
    lea  rsi, [rel state_work + PBM_B1_STATE_SHA_B_OFF]
    call b1_manifest_sha_matches
    test eax, eax
    jnz  .done
    and  byte [rel state_work + PBM_B1_STATE_EVIDENCE_MASK_OFF], 0xFB
    mov  dword [rel state_work + PBM_B1_STATE_FP_B_OFF], 0
    lea  rdi, [rel state_work + PBM_B1_STATE_SHA_B_OFF]
    mov  ecx, 4
    xor  eax, eax
    rep  stosq
.done:
    ret

; Classify the current work journal at the established terminal retry count.
; EAX=0 incomplete/one-slot, 1 matching software fingerprint, 2 divergent
; hardware suspicion.  Only the divergent result closes BIP/Trial and prevents
; another automatic slot or Safe attempt.
b1_classify_work_terminal:
    call b1_prune_stale_failure_evidence
    mov  al, [rel state_work + PBM_B1_STATE_EVIDENCE_MASK_OFF]
    and  al, PBM_B1_SLOT_BOTH_MASK
    cmp  al, PBM_B1_SLOT_BOTH_MASK
    jne  .incomplete
    cmp  byte [rel state_work + PBM_STATE_FAILURE_COUNT_OFF], PBM_B1_FAILURE_THRESHOLD
    jb   .incomplete
    mov  eax, [rel state_work + PBM_B1_STATE_FP_A_OFF]
    cmp  eax, [rel state_work + PBM_B1_STATE_FP_B_OFF]
    je   .matching
    or   byte [rel state_work + PBM_B1_STATE_FLAGS_OFF], (PBM_B1_F_SUSPECT_HARDWARE | PBM_B1_F_MEMTEST_PRESELECT)
    and  byte [rel state_work + PBM_B1_STATE_FLAGS_OFF], 0xFB
    mov  byte [rel state_work + PBM_B1_STATE_SAFE_ENTRY_OFF], PBM_ENTRY_NONE
    lea  rdi, [rel state_work + PBM_B1_STATE_SAFE_SHA_OFF]
    mov  ecx, 4
    xor  eax, eax
    rep  stosq
    mov  byte [rel state_work + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    mov  byte [rel state_work + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_NORMAL
    mov  byte [rel state_work + PBM_STATE_BIP_OFF], 0
    ; Closing the Trial in the arm_trial shape (active == previous) must restore Previous
    ; to the Trial slot first, as .failed_trial does; otherwise this commit fails the
    ; journal role check and the evidence is lost (RCQ-28-b1-suspect-sticky).
    mov  al, [rel state_work + PBM_STATE_PREVIOUS_OFF]
    cmp  al, [rel state_work + PBM_STATE_ACTIVE_OFF]
    jne  .roles_kept
    mov  al, [rel state_work + PBM_STATE_TRIAL_OFF]
    test al, al
    jz   .roles_kept
    mov  [rel state_work + PBM_STATE_PREVIOUS_OFF], al
.roles_kept:
    mov  byte [rel state_work + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    mov  byte [rel state_work + PBM_STATE_TRIES_LEFT_OFF], 0
    mov  eax, 2
    ret
.matching:
    mov  eax, 1
    ret
.incomplete:
    xor  eax, eax
    ret

; Persist the already identity-validated evidence after compact health had its
; chance to promote.  Returns EAX=1 only for a fatal journal write failure.
b1_apply_policy_evidence:
    push rbx
    push r12
    push r13
    mov  byte [rel b1_apply_result], 0
    movzx ebx, byte [rel b1_evidence_kind]
    test ebx, ebx
    jz   .quiet
    mov  r13, [rel selected_state_ptr]
    test r13, r13
    jz   .quiet
    cmp  ebx, PBM_B1_EVIDENCE_SAFE_VIDEO
    je   .safe_video

    ; Failure evidence remains admissible only if compact health did not clear
    ; BIP and the exact nonce/slot inspected above is still authoritative.
    cmp  byte [rel health_consumed], 0
    jne  .quiet
    cmp  byte [r13 + PBM_STATE_BIP_OFF], 1
    jne  .quiet
    mov  rax, [rel b1_evidence_nonce]
    cmp  rax, [r13 + PBM_STATE_ATTEMPT_NONCE_OFF]
    jne  .quiet
    mov  al, [rel b1_evidence_entry]
    cmp  al, [r13 + PBM_STATE_LAST_ENTRY_OFF]
    jne  .quiet
    jmp  .copy

.safe_video:
    ; A display-only vector carries NETWORK=READY by construction, i.e. the box
    ; is remotely operable.  The Safe profile halts with no network and can
    ; never earn health, so arming it stranded headless targets (Beelink: no
    ; established compositor on its GOP path) until power loss and then
    ; quarantined a healthy slot.  Record the fact on serial and keep NORMAL.
    lea  rdi, [rel str_b1_safe_video_suppressed]
    call serial_string
    jmp  .quiet
    ; Historical arming path, retained unreachable for review/forensics.
    ; A display-only vector must have accompanied the compact strong record
    ; just consumed.  READY_NONCE is the durable bridge across that commit.
    cmp  byte [rel health_consumed], 1
    jne  .quiet
    cmp  byte [r13 + PBM_STATE_BIP_OFF], 0
    jne  .quiet
    mov  rax, [rel b1_evidence_nonce]
    cmp  rax, [r13 + PBM_STATE_READY_NONCE_OFF]
    jne  .quiet
    mov  al, [rel b1_evidence_entry]
    cmp  al, [r13 + PBM_STATE_LAST_ENTRY_OFF]
    jne  .quiet
    ; Never repeat a video Safe attempt that already failed and returned to
    ; the verified normal slot.  The bit is durable failure accounting, not a
    ; claim that Safe health was earned.
    movzx ecx, al
    mov  edx, 1
    shl  edx, cl
    test byte [r13 + PBM_STATE_SAFE_ATTEMPTED_OFF], dl
    jnz  .quiet

.copy:
    mov  rsi, r13
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    call b1_prepare_work_state
    cmp  ebx, PBM_B1_EVIDENCE_SAFE_VIDEO
    je   .store_safe_video

    movzx eax, byte [rel b1_evidence_entry]
    cmp  eax, PBM_ENTRY_PAOS_A
    jne  .store_failure_b
    mov  edx, [rel b1_evidence_fingerprint]
    mov  [rel state_work + PBM_B1_STATE_FP_A_OFF], edx
    lea  rsi, [rel b1_evidence_sha]
    lea  rdi, [rel state_work + PBM_B1_STATE_SHA_A_OFF]
    jmp  .copy_failure_sha
.store_failure_b:
    mov  edx, [rel b1_evidence_fingerprint]
    mov  [rel state_work + PBM_B1_STATE_FP_B_OFF], edx
    lea  rsi, [rel b1_evidence_sha]
    lea  rdi, [rel state_work + PBM_B1_STATE_SHA_B_OFF]
.copy_failure_sha:
    mov  ecx, 4
    rep  movsq
    mov  ecx, eax
    mov  edx, 1
    shl  edx, cl
    or   byte [rel state_work + PBM_B1_STATE_EVIDENCE_MASK_OFF], dl
    mov  byte [rel b1_apply_result], 1 ; one-slot/incomplete is not hardware
    call b1_classify_work_terminal
    cmp  eax, 2
    je   .suspect_hardware
    cmp  eax, 1
    jne  .commit
    mov  byte [rel b1_apply_result], 2 ; matching deterministic software fault
    jmp  .commit

.suspect_hardware:
    mov  byte [rel b1_apply_result], 3
    jmp  .commit

.store_safe_video:
    ; Owner one-shots retain precedence.  The stale vector cannot replay after
    ; that different exact attempt changes BIP identity.
    cmp  byte [rel state_work + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .quiet
    mov  al, [rel b1_evidence_entry]
    mov  [rel state_work + PBM_STATE_PENDING_ENTRY_OFF], al
    mov  byte [rel state_work + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_SAFE
    or   byte [rel state_work + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SAFE_VIDEO_PENDING
    mov  [rel state_work + PBM_B1_STATE_SAFE_ENTRY_OFF], al
    lea  rsi, [rel b1_evidence_sha]
    lea  rdi, [rel state_work + PBM_B1_STATE_SAFE_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    mov  byte [rel b1_apply_result], 4

.commit:
    lea  r12, [rel state_work]
    call journal_commit
    test eax, eax
    jnz  .fatal
    movzx eax, byte [rel b1_apply_result]
    cmp  eax, 2
    je   .matching
    cmp  eax, 3
    je   .suspect_marker
    cmp  eax, 4
    je   .safe_marker
    lea  rdi, [rel str_b1_one_slot]
    jmp  .emit
.matching:
    lea  rdi, [rel str_b1_software_revert]
    jmp  .emit
.suspect_marker:
    lea  rdi, [rel str_b1_suspect_hardware]
    jmp  .emit
.safe_marker:
    lea  rdi, [rel str_b1_safe_video_earned]
.emit:
    call serial_string
.quiet:
    xor  eax, eax
    jmp  .out
.fatal:
    mov  byte [rel fatal_policy_failure], 1
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

%ifdef PBM_FEATURE_EXTERNAL
; Close the previous external-OS attempt on the next Manager entry. A matching
; Agent nonce is availability evidence for that OS only.  With no match, the
; external Agent's opportunity has ended: record UNAVAILABLE and arm one
; bounded menu interval so a human can retry the signed external identity or
; accept the normal verified-PaOS/Rescue fallback.  This never enters the PaOS
; BIP/Verified/Trial policy domain.
reconcile_external_health:
    push r12
    mov  r12, [rel selected_state_ptr]
    test r12, r12
    jz   .quiet
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 1
    jne  .quiet
    mov  rsi, r12
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    mov  rax, [rel state_work + PBM_STATE_EXTERNAL_NONCE_OFF]
    cmp  rax, [rel state_work + PBM_STATE_EXTERNAL_READY_OFF]
    jne  .unavailable
    mov  byte [rel state_work + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_READY
    mov  word [rel state_work + PBM_STATE_START_COUNT_OFF], 0
    lea  rdi, [rel str_external_ready]
    jmp  .commit
.unavailable:
    mov  byte [rel state_work + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_UNAVAILABLE
    ; Preserve persistent owner presentation choices.  AUTOMATIC alone needs
    ; a clear-before-act SHOW_NEXT arm; its validated 3..30 second timeout is
    ; consumed by present_menu_if_needed before the fallback is launched.
    cmp  byte [rel state_work + PBM_STATE_MENU_POLICY_OFF], PBM_MENU_AUTOMATIC
    jne  .unavailable_policy_ready
    mov  byte [rel state_work + PBM_STATE_MENU_POLICY_OFF], PBM_MENU_SHOW_NEXT
.unavailable_policy_ready:
    lea  rdi, [rel str_external_unavailable]
.commit:
    push rdi
    mov  byte [rel state_work + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    lea  r12, [rel state_work]
    call journal_commit
    pop  rdi
    test eax, eax
    jnz  .fatal
    call serial_string
    cmp  byte [rel state_work + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_UNAVAILABLE
    jne  .quiet
    lea  rdi, [rel str_external_fallback]
    call serial_string
.quiet:
    xor  eax, eax
    jmp  .out
.fatal:
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_external_commit_failed]
    call serial_string
    mov  eax, 1
.out:
    pop  r12
    ret
%endif

%ifdef PBM_FEATURE_MUTABLE
; record_manager_start -> EAX=0 only after the early-start marker is durable.
; Preserve the final policy's work buffer, including failure/quarantine/Trial
; accounting. This is not a payload attempt or a health acknowledgment: BIP,
; nonces and all trust/launch guards remain owned by arm_selected_attempt.
; Two unresolved admissions make THIS third admission choose only Rescue.
; A no-journal Rescue bootstrap remains read-only. Failure stops this boot.
record_manager_start:
    push r12
    mov  byte [rel power_rescue_due], 0
    mov  rsi, [rel selected_state_ptr]
    test rsi, rsi
    jz   .quiet
    mov  rax, [rel attempt_state_ptr]
    test rax, rax
    jz   .copy
    mov  rsi, rax
.copy:
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    lea  r12, [rel state_work]
    xor  eax, eax
    cmp  byte [r12 + PBM_STATE_START_ARMED_OFF], 1
    jne  .counted
    movzx eax, byte [r12 + PBM_STATE_START_COUNT_OFF]
    cmp  eax, 2
    jae  .saturated
    inc  eax
    jmp  .counted
.saturated:
    mov  eax, 2
.counted:
    mov  [r12 + PBM_STATE_START_COUNT_OFF], al
    mov  byte [r12 + PBM_STATE_START_ARMED_OFF], 1
    call journal_commit
    test eax, eax
    jnz  .fatal
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call r7_serial_journal_admission    ; actual durable admission; observation only
%endif
%endif
    lea  r12, [rel state_work]
    mov  [rel attempt_state_ptr], r12
    cmp  byte [r12 + PBM_STATE_START_COUNT_OFF], 2
    jb   .armed
    mov  byte [rel power_rescue_due], 1
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    mov  byte [rel policy_abnormal], 1
    lea  rdi, [rel str_power_rescue]
    call serial_string
    jmp  .quiet
.armed:
    lea  rdi, [rel str_power_start_armed]
    call serial_string
.quiet:
    xor  eax, eax
    pop  r12
    ret
.fatal:
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_power_start_failed]
    call serial_string
    mov  eax, 1
    pop  r12
    ret

; handoff_trial_flag(R15B=launched entry): HF_TRIAL for a journal Trial launch,
; and for a NORMAL launch of the journal's pending TRIAL entry for any other
; reason (an owner one-shot). The ack of that entry promotes it whatever the
; reason, so PaOS must apply its Trial-only rules to it. Safe never carries
; HF_TRIAL: PaOS refuses that handoff. Clobbers RAX only.
handoff_trial_flag:
    cmp  byte [rel handoff + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .out
    cmp  byte [rel selected_reason], PBM_REASON_TRIAL
    je   .set
    mov  rax, [rel selected_state_ptr]
    test rax, rax
    jz   .out
    cmp  r15b, [rax + PBM_STATE_TRIAL_OFF]
    jne  .out
.set:
    or   byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_TRIAL
.out:
    ret
%endif

; arm_selected_attempt(R15D=verified entry) -> EAX=0 only after the selected
; state is updated in the older journal copy, flushed, exact-read-verified, and
; rebound as selected_state_ptr. A no-state Rescue bootstrap remains read-only;
; a full PaOS identity is never transferred without a durable attempt record.
arm_selected_attempt:
    mov  qword [rel current_attempt_nonce], 0
    mov  rax, [rel selected_state_ptr]
    test rax, rax
    jnz  .have_state
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .fail
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    test rax, rax
    jnz  .bootstrap_nonce
    inc  rax
.bootstrap_nonce:
    mov  [rel current_attempt_nonce], rax
    lea  rdi, [rel str_attempt_rescue_untracked]
    call serial_string
    xor  eax, eax
    ret

.have_state:
    mov  rsi, [rel attempt_state_ptr]
    test rsi, rsi
    jnz  .copy_state
    mov  rsi, rax
.copy_state:
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    ; A journal generation is monotonic even on firmware whose TSC restarts at
    ; a repeatable value. Mix the generation that this commit will receive and
    ; the signed manifest sequence into the nonce so a delayed ready report
    ; cannot accidentally match a later boot attempt.
    mov  rcx, [rel state_work + PBM_STATE_GENERATION_OFF]
    inc  rcx
    rol  rcx, 17
    xor  rax, rcx
    xor  rax, [rel manifest + 8]
    test rax, rax
    jnz  .nonce_ok
    inc  rax
.nonce_ok:
    mov  [rel current_attempt_nonce], rax
%ifdef PBM_FEATURE_EXTERNAL
    cmp  r15d, PBM_ENTRY_WINDOWS
    jae  .external_attempt
%endif
    mov  [rel state_work + PBM_STATE_ATTEMPT_NONCE_OFF], rax
    mov  qword [rel state_work + PBM_STATE_READY_NONCE_OFF], 0
    mov  byte [rel state_work + PBM_STATE_BIP_OFF], 1
    jmp  .attempt_common
%ifdef PBM_FEATURE_EXTERNAL
.external_attempt:
    cmp  r15d, PBM_ENTRY_LINUX
    ja   .fail
    mov  [rel state_work + PBM_STATE_EXTERNAL_ENTRY_OFF], r15b
    mov  byte [rel state_work + PBM_STATE_EXTERNAL_PENDING_OFF], 1
    mov  byte [rel state_work + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_NONE
    mov  [rel state_work + PBM_STATE_EXTERNAL_NONCE_OFF], rax
    mov  qword [rel state_work + PBM_STATE_EXTERNAL_READY_OFF], 0
    mov  byte [rel state_work + PBM_STATE_BIP_OFF], 0
%endif
.attempt_common:
    mov  byte [rel state_work + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    mov  byte [rel state_work + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_NORMAL
    mov  [rel state_work + PBM_STATE_LAST_ENTRY_OFF], r15b
    mov  al, [rel selected_profile]
    mov  [rel state_work + PBM_STATE_LAST_PROFILE_OFF], al
    mov  al, [rel selected_reason]
    mov  [rel state_work + PBM_STATE_LAST_REASON_OFF], al
    ; DELIBERATE_RESCUE only for Rescue chosen in this boot's menu (owner input),
    ; never from journal or CMOS one-shots; every other attempt clears it.
    xor  eax, eax
%ifdef PBM_FEATURE_MENU
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .attempt_flags
    cmp  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    jne  .attempt_flags
    cmp  byte [rel menu_rescue_chosen], 1
    jne  .attempt_flags
    mov  al, PBM_LAST_F_DELIBERATE_RESCUE
.attempt_flags:
%endif
    mov  [rel state_work + PBM_STATE_LAST_FLAGS_OFF], al
%ifdef PBM_TEST_SAFE_PROFILE
    mov  byte [rel state_work + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_SAFE
    mov  byte [rel state_work + PBM_STATE_LAST_REASON_OFF], PBM_REASON_SAFE_RETRY
%endif
    mov  rax, [rel manifest + 8]
    mov  [rel state_work + PBM_STATE_MANIFEST_SEQ_OFF], rax
    lea  rsi, [rel verified_manifest_sha]
    lea  rdi, [rel state_work + PBM_STATE_MANIFEST_SHA_OFF]
    mov  ecx, 4
    rep  movsq
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call r5_manager_bind_grant
    call dd_oracle_bind                ; U4b: PDS1 in this same attempt commit, or nothing
%endif
%endif
    PBM_STAGE 0x10E                    ; about to commit the attempt
    lea  r12, [rel state_work]
    call journal_commit
    test eax, eax
    jnz  .fail
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call r5_serial_journal_after_commit ; raw observation; preserves flags/GPRs
%endif
%endif
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call r7_serial_journal_after_arm    ; exact automatic Rescue before return reset
%endif
%endif
%ifdef PBM_FEATURE_EXTERNAL
    cmp  r15d, PBM_ENTRY_WINDOWS
    jae  .external_armed
%endif
    lea  rdi, [rel str_attempt_armed]
    call serial_string
    xor  eax, eax
    ret
%ifdef PBM_FEATURE_EXTERNAL
.external_armed:
    lea  rdi, [rel str_external_armed]
    call serial_string
    xor  eax, eax
    ret
%endif
.fail:
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_attempt_failed]
    call serial_string
    mov  eax, 1
    ret

buffers_equal_512:
    lea  rsi, [rel state0]
    lea  rdi, [rel state1]
    mov  ecx, PBM_STATE_SIZE / 8
    repe cmpsq
    sete al
    movzx eax, al
    ret

select_policy:
%ifdef PBM_FEATURE_FULL_POLICY
    jmp  select_mutable_policy
%else
    jmp  select_readonly_policy
%endif

; load_select_state -> EAX=0 with selected_state_ptr naming the newest
; unambiguous valid copy, EAX=1 with no trusted journal. This is the one shared
; read/classify primitive for both the compatibility and mutable evaluators.
load_select_state:
    push rbx
    push r12
    push r13
    mov  qword [rel selected_state_ptr], 0
    mov  byte [rel state0_valid], 0
    mov  byte [rel state1_valid], 0
    cmp  qword [rel boot_root], 0
    je   .missing

    lea  r13, [rel ucs2_state0]
    lea  r12, [rel state0]
    mov  ebx, PBM_STATE_SIZE
    call read_exact
    test eax, eax
    jnz  .read1
    lea  rdi, [rel state0]
    call state_valid
    mov  [rel state0_valid], al
.read1:
    lea  r13, [rel ucs2_state1]
    lea  r12, [rel state1]
    mov  ebx, PBM_STATE_SIZE
    call read_exact
    test eax, eax
    jnz  .choose
    lea  rdi, [rel state1]
    call state_valid
    mov  [rel state1_valid], al
.choose:
    cmp  byte [rel state0_valid], 1
    jne  .only1
    cmp  byte [rel state1_valid], 1
    jne  .use0
    mov  rax, [rel state0 + PBM_STATE_GENERATION_OFF]
    mov  rdx, [rel state1 + PBM_STATE_GENERATION_OFF]
    cmp  rax, rdx
    ja   .use0
    jb   .use1
    call buffers_equal_512
    test eax, eax
    jz   .ambiguous
    jmp  .use0
.only1:
    cmp  byte [rel state1_valid], 1
    je   .use1
    jmp  .missing
.use0:
    lea  r12, [rel state0]
    jmp  .selected
.use1:
    lea  r12, [rel state1]
    jmp  .selected
.ambiguous:
    lea  rdi, [rel str_state_ambiguous]
    call serial_string
    jmp  .missing
.selected:
    mov  [rel selected_state_ptr], r12
    xor  eax, eax
    jmp  .out
.missing:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; The rollback-fixture manifest rung needs to exercise all three internal
; direct routes before the mutable production policy exists.  Admit only its
; exact owner-manifest-bound pending identity over three byte-identical
; internal payloads: no Trial/BIP/external state and no quarantined PaOS slot.
; The identical size+digest condition makes this route evidence, not an A/B
; content choice.  PBM_PRODUCTION requires MUTABLE+FULL_POLICY above, so this
; read-only projection cannot enter a release Manager or weaken its durable
; one-shot transaction.
%ifdef PBM_ROLLBACK_FIXTURE
%ifdef PBM_FEATURE_MANIFEST
%ifndef PBM_FEATURE_MUTABLE
select_readonly_pax1_fixture_pending:
    push rbx
    push r13
    push r14
    push r15
    cmp  byte [rel manifest_verified], 1
    jne  .refused
    cmp  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    jne  .refused
    cmp  byte [r12 + PBM_STATE_TRIES_LEFT_OFF], 0
    jne  .refused
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    jne  .refused
    cmp  byte [r12 + PBM_STATE_EXTERNAL_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .refused
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    jne  .refused
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_NONE
    jne  .refused
    cmp  qword [r12 + PBM_STATE_EXTERNAL_NONCE_OFF], 0
    jne  .refused
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .refused
    movzx ebx, byte [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    cmp  ebx, PBM_ENTRY_PAOS_A
    jb   .refused
    cmp  ebx, PBM_ENTRY_RESCUE
    ja   .refused
    mov  rax, [r12 + PBM_STATE_MANIFEST_SEQ_OFF]
    test rax, rax
    jz   .refused
    cmp  rax, [rel manifest + 8]
    jne  .refused
    lea  rdi, [r12 + PBM_STATE_MANIFEST_SHA_OFF]
    lea  rsi, [rel verified_manifest_sha]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .refused

    ; This exception exists only to project A/B/Rescue routing over one exact
    ; frozen payload.  If any content identity differs, ordinary read-only
    ; policy keeps refusing the pending request.
    mov  edi, PBM_ENTRY_PAOS_A
    call integrity_vault_select_entry
    test rax, rax
    jz   .refused
    mov  r13, rax
    mov  edi, PBM_ENTRY_PAOS_B
    call integrity_vault_select_entry
    test rax, rax
    jz   .refused
    mov  r14, rax
    mov  edi, PBM_ENTRY_RESCUE
    call integrity_vault_select_entry
    test rax, rax
    jz   .refused
    mov  r15, rax
    mov  eax, [r13 + 4]
    cmp  eax, [r14 + 4]
    jne  .refused
    cmp  eax, [r15 + 4]
    jne  .refused
    lea  rdi, [r13 + 16]
    lea  rsi, [r14 + 16]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .refused
    lea  rdi, [r13 + 16]
    lea  rsi, [r15 + 16]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .refused

    cmp  ebx, PBM_ENTRY_RESCUE
    je   .selected
    mov  ecx, ebx
    mov  eax, 1
    shl  eax, cl
    test byte [r12 + PBM_STATE_QUARANTINE_MASK_OFF], al
    jnz  .refused
.selected:
    mov  [rel selected_entry], bl
    mov  al, [r12 + PBM_STATE_PENDING_PROFILE_OFF]
    mov  [rel selected_profile], al
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    lea  rdi, [rel str_state_pax1_fixture_pending]
    call serial_string
    xor  eax, eax
    jmp  .out
.refused:
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret
%endif
%endif
%endif

; Until full mutation is policy-active, accept only a stable verified Active.
; Pending/Trial/ambiguous/corrupt state selects Rescue. Previous BIP selects
; verified Previous without pretending this compatibility evaluator repaired
; persistent state.  The one rollback-fixture exception above is exact-bound
; route evidence, not a durable-policy substitute.
select_readonly_policy:
    push r12
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_INVALID_STATE
    mov  qword [rel attempt_state_ptr], 0
    call load_select_state
    test eax, eax
    jnz  .rescue
    mov  r12, [rel selected_state_ptr]
    mov  [rel attempt_state_ptr], r12
    cmp  byte [r12 + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .needs_write
    cmp  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    jne  .needs_write
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    jne  .previous

    movzx eax, byte [r12 + PBM_STATE_ACTIVE_OFF]
    mov  edx, 1
    mov  ecx, eax
    shl  edx, cl
    test byte [r12 + PBM_STATE_VERIFIED_MASK_OFF], dl
    jz   .previous
    mov  [rel selected_entry], al
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_HEALTHY
    mov  al, [r12 + PBM_STATE_PREVIOUS_OFF]
    mov  [rel fallback_entry], al
    lea  rdi, [rel str_state_active]
    call serial_string
    jmp  .out
.previous:
    movzx eax, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    mov  edx, 1
    mov  ecx, eax
    shl  edx, cl
    test byte [r12 + PBM_STATE_VERIFIED_MASK_OFF], dl
    jz   .rescue
    mov  [rel selected_entry], al
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_ROLLBACK
    lea  rdi, [rel str_state_previous]
    call serial_string
    jmp  .out
.needs_write:
%ifdef PBM_ROLLBACK_FIXTURE
%ifdef PBM_FEATURE_MANIFEST
%ifndef PBM_FEATURE_MUTABLE
    call select_readonly_pax1_fixture_pending
    test eax, eax
    jz   .out
%endif
%endif
%endif
    lea  rdi, [rel str_state_needs_write]
    call serial_string
    jmp  .rescue
.rescue:
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_INVALID_STATE
    lea  rdi, [rel str_state_rescue]
    call serial_string
.out:
    pop  r12
    xor  eax, eax
    ret

%ifdef PBM_FEATURE_FULL_POLICY
; slot_verified_usable(EDI=slot, R12=state) -> EAX=1 only for a Verified,
; non-quarantined full PaOS identity. Payload bytes are authenticated later,
; before any attempt commit.
slot_verified_usable:
    cmp  edi, PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  edi, PBM_ENTRY_PAOS_B
    ja   .bad
    mov  ecx, edi
    mov  edx, 1
    shl  edx, cl
    test byte [r12 + PBM_STATE_VERIFIED_MASK_OFF], dl
    jz   .bad
    test byte [r12 + PBM_STATE_QUARANTINE_MASK_OFF], dl
    jnz  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

slot_unquarantined:
    cmp  edi, PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  edi, PBM_ENTRY_PAOS_B
    ja   .bad
    mov  ecx, edi
    mov  edx, 1
    shl  edx, cl
    test byte [r12 + PBM_STATE_QUARANTINE_MASK_OFF], dl
    jnz  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

increment_work_failure:
    cmp  byte [rel state_work + PBM_STATE_FAILURE_COUNT_OFF], 0xFF
    je   .done
    inc  byte [rel state_work + PBM_STATE_FAILURE_COUNT_OFF]
.done:
    ret

bind_work_manifest:
    mov  rax, [rel manifest + 8]
    mov  [rel state_work + PBM_STATE_MANIFEST_SEQ_OFF], rax
    lea  rsi, [rel verified_manifest_sha]
    lea  rdi, [rel state_work + PBM_STATE_MANIFEST_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    ret

; Clear a B1 safe-video intent in the same durable clear-before-act transaction
; as the ordinary pending one-shot.  The cached verdict distinguishes a valid
; exact slot/payload request from a stale or forged claim after the clear.
b1_consume_safe_video_intent:
    push rbx
    mov  byte [rel b1_safe_video_claimed], 0
    mov  byte [rel b1_safe_video_identity_ok], 0
    cmp  dword [r12 + PBM_B1_STATE_MAGIC_OFF], PBM_B1_STATE_MAGIC
    jne  .out
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SAFE_VIDEO_PENDING
    jz   .out
    mov  byte [rel b1_safe_video_claimed], 1
    cmp  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_SAFE
    jne  .clear
    movzx ebx, byte [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    cmp  bl, [r12 + PBM_B1_STATE_SAFE_ENTRY_OFF]
    jne  .clear
    mov  edi, ebx
    lea  rsi, [r12 + PBM_B1_STATE_SAFE_SHA_OFF]
    call b1_manifest_sha_matches
    test eax, eax
    jz   .clear
    mov  byte [rel b1_safe_video_identity_ok], 1
.clear:
    and  byte [r12 + PBM_B1_STATE_FLAGS_OFF], 0xFB
    mov  byte [r12 + PBM_B1_STATE_SAFE_ENTRY_OFF], PBM_ENTRY_NONE
    lea  rdi, [r12 + PBM_B1_STATE_SAFE_SHA_OFF]
    mov  ecx, 4
    xor  eax, eax
    rep  stosq
.out:
    pop  rbx
    ret

; Import the migration-era PaOS BOOT verb (CMOS 0x76) into the v2 journal.
; Values are intentionally bounded to the established contract:
;   1 = Windows, 2 = external Linux, 3 = Rescue diagnostics.
; Request ownership moves in one replay-safe direction: validate the live
; request and journal, durably adopt into Pending, then clear CMOS and verify
; the zero read-back.  A matching Pending is an interrupted adoption; a
; different Pending retains precedence and leaves CMOS untouched.  Any trust,
; BIP, journal-commit, or clear-read-back refusal launches nothing while CMOS,
; Pending, or both still represent the request.
; This bridge can be removed only after every supported PaOS payload projects
; boot requests directly into the v2 state protocol.
import_legacy_cmos_oneshot:
    push rbx
    push r12
%ifdef PBM_TEST_LEGACY_TXN_CASE
    call legacy_txn_fixture_seed
%endif
    call legacy_cmos_oneshot_read
    movzx ebx, al
    test ebx, ebx
    jz   .none
    cmp  ebx, 3
    ja   .none
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_read]
    call serial_string
%endif
    lea  rdi, [rel str_legacy_oneshot_seen]
    call serial_string

    cmp  ebx, 1
    je   .want_windows
    cmp  ebx, 2
    je   .want_linux
    mov  ebx, PBM_ENTRY_RESCUE
    jmp  .trust
.want_windows:
    mov  ebx, PBM_ENTRY_WINDOWS
    jmp  .trust
.want_linux:
    mov  ebx, PBM_ENTRY_LINUX
.trust:
    cmp  byte [rel manifest_verified], 1
    jne  .refused
    call load_select_state
    test eax, eax
    jnz  .refused
    call enforce_manifest_state_floor
    test eax, eax
    jnz  .refused
    mov  r12, [rel selected_state_ptr]
    movzx eax, byte [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    test eax, eax
    jz   .new_adoption
    cmp  eax, ebx
    jne  .preserved
    cmp  ebx, PBM_ENTRY_RESCUE
    je   .matching_rescue
    cmp  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_EXTERNAL
    jne  .preserved
    jmp  .matching
.matching_rescue:
    cmp  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_RESCUE
    jne  .preserved
.matching:
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    jne  .deferred_bip
    mov  edi, ebx
    call integrity_vault_select_entry
    test rax, rax
    jz   .refused
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_validated]
    call serial_string
%endif
    jmp  .clear

.new_adoption:
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    jne  .deferred_bip
    mov  edi, ebx
    call integrity_vault_select_entry
    test rax, rax
    jz   .refused
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_validated]
    call serial_string
%if PBM_TEST_LEGACY_TXN_CASE = 9
    call legacy_txn_fixture_interrupt
%endif
%endif
    mov  rsi, r12
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    lea  r12, [rel state_work]
    mov  [r12 + PBM_STATE_PENDING_ENTRY_OFF], bl
    mov  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_EXTERNAL
    cmp  ebx, PBM_ENTRY_RESCUE
    jne  .commit
    mov  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_RESCUE
.commit:
    call bind_work_manifest
%ifdef PBM_TEST_LEGACY_TXN_CASE
%if PBM_TEST_LEGACY_TXN_CASE = 7
    mov  eax, 1
%else
    call journal_commit
%endif
%else
    call journal_commit
%endif
    test eax, eax
    jnz  .fatal
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_committed]
    call serial_string
%if PBM_TEST_LEGACY_TXN_CASE = 10
    call legacy_txn_fixture_interrupt
%endif
%endif

.clear:
    call legacy_cmos_oneshot_clear
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_clear_written]
    call serial_string
%endif
%ifdef PBM_TEST_LEGACY_ONESHOT
    ; Compatibility-only legacy suite: its historical constant/no-op fixture
    ; cannot expose mutable read-back.  Task1512's fixture never defines it.
    xor  eax, eax
%else
    call legacy_cmos_oneshot_raw_read
%endif
    test al, al
    jnz  .fatal
%ifdef PBM_TEST_LEGACY_TXN_CASE
    lea  rdi, [rel str_legacy_txn_clear_verified]
    call serial_string
%if PBM_TEST_LEGACY_TXN_CASE = 11
    call legacy_txn_fixture_interrupt
%endif
%if PBM_TEST_LEGACY_TXN_CASE = 3
    call legacy_txn_fixture_complete
    mov  eax, 1
    jmp  .out
%endif
%endif
    lea  rdi, [rel str_legacy_oneshot_imported]
    call serial_string
    xor  eax, eax
    jmp  .out
.preserved:
    lea  rdi, [rel str_legacy_oneshot_preserved]
    call serial_string
%ifdef PBM_TEST_LEGACY_TXN_CASE
    call legacy_txn_fixture_retain_complete
    mov  eax, 1
    jmp  .out
%endif
    xor  eax, eax
    jmp  .out
.deferred_bip:
    ; A live BIP is an earlier attempt that never reported health (e.g. a
    ; networkless Safe boot ended by power loss).  Refusing here stopped every
    ; later entry before the abnormal-BIP policy could account that attempt:
    ; CMOS and BIP then pinned each other forever (Beelink gen241, 2026-09-29).
    ; Leave CMOS and Pending untouched, let ordinary policy account the BIP,
    ; and adopt the request on the next entry that starts without one.
    lea  rdi, [rel str_legacy_oneshot_deferred]
    call serial_string
%ifdef PBM_TEST_LEGACY_TXN_CASE
    call legacy_txn_fixture_retain_complete
    mov  eax, 1
    jmp  .out
%endif
    xor  eax, eax
    jmp  .out
.refused:
    lea  rdi, [rel str_legacy_oneshot_refused]
    call serial_string
%ifdef PBM_TEST_LEGACY_TXN_CASE
    call legacy_txn_fixture_retain_complete
%endif
    mov  eax, 1
    jmp  .out
.none:
    xor  eax, eax
    jmp  .out
.fatal:
    lea  rdi, [rel str_legacy_oneshot_refused]
    call serial_string
%ifdef PBM_TEST_LEGACY_TXN_CASE
    call legacy_txn_fixture_retain_complete
%endif
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

legacy_cmos_oneshot_read:
%ifdef PBM_TEST_LEGACY_ONESHOT
    mov  al, PBM_TEST_LEGACY_ONESHOT
    ret
%else
    jmp  legacy_cmos_oneshot_raw_read
%endif

legacy_cmos_oneshot_clear:
%ifdef PBM_TEST_LEGACY_ONESHOT
    ret
%else
%ifdef PBM_TEST_LEGACY_TXN_CASE
%if PBM_TEST_LEGACY_TXN_CASE = 8
    mov  ax, (1 << 8) | PBM_CMOS_LEGACY_ONE_SHOT
%else
    mov  ax, PBM_CMOS_LEGACY_ONE_SHOT
%endif
%else
    mov  ax, PBM_CMOS_LEGACY_ONE_SHOT
%endif
    jmp  legacy_cmos_index_write
%endif

legacy_cmos_oneshot_raw_read:
    mov  al, PBM_CMOS_LEGACY_ONE_SHOT
    jmp  legacy_cmos_index_read

; legacy_cmos_index_read(AL=index) -> AL=value.  The NMI-disable bit matches
; the established PaOS writer and is intentionally left set across access.
legacy_cmos_index_read:
%ifdef PBM_PLATFORM_HP_Q8
    ; Even a CMOS read writes port 0x70. Q8 forbids that on this HP.
    xor  eax, eax                   ; no legacy request; signed policy continues
    ret
%else
    or   al, 0x80
    mov  dx, 0x70
    out  dx, al
    inc  dx
    in   al, dx
    ret

%endif

; legacy_cmos_index_write(AL=index, AH=value).
legacy_cmos_index_write:
%ifdef PBM_PLATFORM_HP_Q8
    ret                            ; no index or data port writes, for any index
%else
    or   al, 0x80
    mov  dx, 0x70
    out  dx, al
    mov  al, ah
    inc  dx
    out  dx, al
    ret

%endif

%ifdef PBM_TEST_LEGACY_TXN_CASE
; The immutable Task1512 harness launches a fresh QEMU process per case.  Two
; otherwise-unused migration bytes make fixture initialization and one warm
; interruption persistent inside that process, while byte 0x76 remains the
; real independently observed CMOS oracle.
PBM_LEGACY_TXN_FIXTURE_MAGIC equ (0xA0 + PBM_TEST_LEGACY_TXN_CASE)

legacy_txn_fixture_seed:
    mov  al, PBM_CMOS_LEGACY_TRIAL
    call legacy_cmos_index_read
    cmp  al, PBM_LEGACY_TXN_FIXTURE_MAGIC
    je   .out
    mov  ax, (PBM_LEGACY_TXN_FIXTURE_MAGIC << 8) | PBM_CMOS_LEGACY_TRIAL
    call legacy_cmos_index_write
    mov  ax, PBM_CMOS_LEGACY_CONFIRMED
    call legacy_cmos_index_write
%if PBM_TEST_LEGACY_TXN_CASE = 14
    mov  ax, (3 << 8) | PBM_CMOS_LEGACY_ONE_SHOT
%else
    mov  ax, (1 << 8) | PBM_CMOS_LEGACY_ONE_SHOT
%endif
    call legacy_cmos_index_write
.out:
    ret

%if (PBM_TEST_LEGACY_TXN_CASE = 9) || (PBM_TEST_LEGACY_TXN_CASE = 10) || (PBM_TEST_LEGACY_TXN_CASE = 11)
legacy_txn_fixture_interrupt:
    mov  al, PBM_CMOS_LEGACY_CONFIRMED
    call legacy_cmos_index_read
    test al, al
    jnz  .already_injected
    mov  ax, (1 << 8) | PBM_CMOS_LEGACY_CONFIRMED
    call legacy_cmos_index_write
%if PBM_TEST_LEGACY_TXN_CASE = 9
    lea  rdi, [rel str_legacy_txn_reset_before_commit]
%elif PBM_TEST_LEGACY_TXN_CASE = 10
    lea  rdi, [rel str_legacy_txn_reset_after_commit]
%elif PBM_TEST_LEGACY_TXN_CASE = 11
    lea  rdi, [rel str_legacy_txn_reset_after_clear]
%endif
    call serial_string
    mov  dx, 0xCF9
    mov  al, 0x06                    ; QEMU full warm-machine reset
    out  dx, al
.wait_for_reset:
    hlt
    jmp  .wait_for_reset
.already_injected:
    ret
%endif

legacy_txn_fixture_complete:
    lea  rdi, [rel str_legacy_txn_case_complete]
    call serial_string
    ret

legacy_txn_fixture_retain_complete:
    lea  rdi, [rel str_legacy_txn_retained]
    call serial_string
    jmp  legacy_txn_fixture_complete
%endif

; quarantine_work_slot(EDI=A/B) binds quarantine to the digest authenticated by
; the current owner manifest, so replacing bytes cannot inherit the failure.
quarantine_work_slot:
    push rbx
    mov  ebx, edi
    mov  ecx, edi
    mov  eax, 1
    shl  eax, cl
    or   byte [rel state_work + PBM_STATE_QUARANTINE_MASK_OFF], al
    call integrity_vault_select_entry
    test rax, rax
    jz   .done
    lea  rsi, [rax + 16]
    lea  rdi, [rel state_work + PBM_STATE_QUARANTINED_SHA_OFF]
    mov  ecx, 4
    rep  movsq
.done:
    mov  edi, ebx
    pop  rbx
    ret

; set_fallback_other_verified(R12=state, EDI=selected) chooses at most one
; other verified slot. Rescue remains the final explicit floor in the caller.
set_fallback_other_verified:
    push rbx
    mov  ebx, edi
    movzx edi, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    cmp  edi, ebx
    je   .active
    call slot_verified_usable
    test eax, eax
    jnz  .use
.active:
    movzx edi, byte [r12 + PBM_STATE_ACTIVE_OFF]
    cmp  edi, ebx
    je   .none
    call slot_verified_usable
    test eax, eax
    jz   .none
.use:
    mov  [rel fallback_entry], dil
    jmp  .out
.none:
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
.out:
    mov  edi, ebx
    pop  rbx
    ret

; Full test-policy evaluator. Every returned PaOS/Rescue choice names
; state_work in attempt_state_ptr; arm_selected_attempt combines these semantic
; changes with BIP/nonce in one older-copy durable commit.
select_mutable_policy:
    push rbx
    push r12
    push r13
    mov  byte [rel b1_safe_video_launch], 0
    mov  byte [rel b1_memtest_preselect], 0
    mov  byte [rel b1_safe_video_claimed], 0
    mov  byte [rel b1_safe_video_identity_ok], 0
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_INVALID_STATE
    mov  byte [rel policy_abnormal], 0
    mov  qword [rel attempt_state_ptr], 0
    cmp  byte [rel manifest_verified], 1
    jne  .fatal
    call load_select_state
    test eax, eax
    jnz  .rescue_no_state
    call enforce_manifest_state_floor
    test eax, eax
    jnz  .fatal
    mov  r12, [rel selected_state_ptr]
%ifdef PBM_FEATURE_HEALTH
    cmp  byte [rel health_checked], 0
    je   .defer_health
%endif
.copy:
    mov  rsi, r12
    lea  rdi, [rel state_work]
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
    lea  r12, [rel state_work]
    mov  [rel attempt_state_ptr], r12

    ; Hardware suspicion is terminal for automatic A/B selection.  Its journal
    ; state was earned only from two exact current-manifest slot identities.
    cmp  dword [r12 + PBM_B1_STATE_MAGIC_OFF], PBM_B1_STATE_MAGIC
    jne  .pending
    test byte [r12 + PBM_B1_STATE_FLAGS_OFF], PBM_B1_F_SUSPECT_HARDWARE
    jnz  .b1_suspect_state

    ; One-shot requests are their own transaction.  Internal identities retain
    ; the established clear commit here.  External identities keep Pending
    ; durable through signed payload verification; arm_selected_attempt then
    ; replaces it atomically with the nonce-bound external attempt record.
.pending:
    movzx ebx, byte [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    test ebx, ebx
    jz   .bip
    movzx r13d, byte [r12 + PBM_STATE_PENDING_PROFILE_OFF]
%ifdef PBM_FEATURE_EXTERNAL
    cmp  ebx, PBM_ENTRY_WINDOWS
    je   .oneshot_external
    cmp  ebx, PBM_ENTRY_LINUX
    je   .oneshot_external
%endif
    call b1_consume_safe_video_intent
    mov  byte [r12 + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    mov  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_NORMAL
    call bind_work_manifest
    call journal_commit
    test eax, eax
    jnz  .fatal
    lea  r12, [rel state_work]
    mov  [rel attempt_state_ptr], r12
    lea  rdi, [rel str_policy_oneshot_consumed]
    call serial_string
%ifdef PBM_FEATURE_EXTERNAL
    cmp  ebx, PBM_ENTRY_WINDOWS
    je   .oneshot_external
    cmp  ebx, PBM_ENTRY_LINUX
    je   .oneshot_external
%endif
    cmp  ebx, PBM_ENTRY_RESCUE
    je   .oneshot_rescue
    cmp  ebx, PBM_ENTRY_PAOS_A
    jb   .oneshot_invalid
    cmp  ebx, PBM_ENTRY_PAOS_B
    ja   .oneshot_invalid
    mov  edi, ebx
    call slot_unquarantined
    test eax, eax
    jz   .oneshot_invalid
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    cmp  r13d, PBM_PROFILE_SAFE
    jne  .oneshot_paos_profile
    cmp  byte [rel b1_safe_video_claimed], 1
    jne  .oneshot_owner_safe
    cmp  byte [rel b1_safe_video_identity_ok], 1
    jne  .oneshot_safe_invalid
    mov  byte [rel selected_profile], PBM_PROFILE_SAFE
    mov  byte [rel selected_reason], PBM_REASON_SAFE_RETRY
    mov  byte [rel b1_safe_video_launch], 1
    lea  rdi, [rel str_b1_safe_video_bound]
    call serial_string
    jmp  .oneshot_paos_profile
.oneshot_owner_safe:
    mov  byte [rel selected_profile], PBM_PROFILE_SAFE
.oneshot_paos_profile:
    mov  edi, ebx
    call set_fallback_other_verified
    jmp  .success
.oneshot_safe_invalid:
    lea  rdi, [rel str_b1_safe_video_rejected]
    call serial_string
    jmp  .oneshot_invalid
.oneshot_rescue:
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    jmp  .success
%ifdef PBM_FEATURE_EXTERNAL
.oneshot_external:
    cmp  r13d, PBM_PROFILE_EXTERNAL
    jne  .oneshot_external_refused
    mov  edi, ebx
    call integrity_vault_select_entry
    test rax, rax
    jz   .oneshot_external_refused
    ; Keep the historical selection-generation checkpoint without erasing the
    ; request.  A failed write leaves the older valid Pending authoritative.
    call bind_work_manifest
    PBM_PRESELECT 0x222
    call journal_commit
    PBM_PRESELECT_RESULT 0x223, 0x224
    test eax, eax
    jnz  .fatal
    lea  r12, [rel state_work]
    mov  [rel attempt_state_ptr], r12
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_EXTERNAL
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    lea  rdi, [rel str_policy_external]
    call serial_string
    jmp  .success
.oneshot_external_refused:
    mov  byte [rel policy_abnormal], 1
    lea  rdi, [rel str_policy_external_retained]
    call serial_string
    jmp  .fatal
%endif
.oneshot_invalid:
    mov  byte [rel policy_abnormal], 1
    lea  rdi, [rel str_policy_oneshot_invalid]
    call serial_string

.bip:
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    je   .trial
    mov  byte [rel policy_abnormal], 1
    movzx ebx, byte [r12 + PBM_STATE_LAST_ENTRY_OFF]
    cmp  ebx, PBM_ENTRY_PAOS_A
    jb   .clear_nonpaos_bip
    cmp  ebx, PBM_ENTRY_PAOS_B
    ja   .clear_nonpaos_bip
    cmp  bl, [r12 + PBM_STATE_TRIAL_OFF]
    je   .failed_trial
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_NORMAL
    je   .normal_bip
    ; B1's display-only Safe one-shot does not set SAFE_ATTEMPTED.  A failed
    ; ordinary crash-ladder Safe does, and must retain the terminal/quarantine
    ; behavior below.  If the verified peer is already quarantined, let one
    ; automatic video-Safe failure return to the same verified NORMAL slot so
    ; network and signed Windows return remain available without customer KVM.
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_SAFE
    jne  .failed_terminal
    cmp  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_SAFE_RETRY
    jne  .failed_terminal
    cmp  bl, [r12 + PBM_STATE_ACTIVE_OFF]
    jne  .failed_terminal
    cmp  byte [r12 + PBM_STATE_FAILURE_COUNT_OFF], 0
    jne  .failed_terminal
    mov  ecx, ebx
    mov  edx, 1
    shl  edx, cl
    test byte [r12 + PBM_STATE_SAFE_ATTEMPTED_OFF], dl
    jnz  .failed_terminal
    mov  edi, ebx
    call slot_verified_usable
    test eax, eax
    jz   .failed_terminal
    movzx edi, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    cmp  edi, ebx
    je   .failed_terminal
    call slot_verified_usable
    test eax, eax
    jnz  .failed_terminal
    mov  ecx, ebx
    mov  edx, 1
    shl  edx, cl
    or   byte [r12 + PBM_STATE_SAFE_ATTEMPTED_OFF], dl
    mov  byte [r12 + PBM_STATE_BIP_OFF], 0
    call increment_work_failure
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_PREVIOUS_BIP
    mov  edi, ebx
    call set_fallback_other_verified
    lea  rdi, [rel str_policy_safe_video_normal_retry]
    call serial_string
    jmp  .success
.normal_bip:
    mov  edi, ebx
    call slot_verified_usable
    test eax, eax
    jz   .failed_terminal
    mov  ecx, ebx
    mov  eax, 1
    shl  eax, cl
    test byte [r12 + PBM_STATE_SAFE_ATTEMPTED_OFF], al
    jnz  .failed_terminal
    or   byte [r12 + PBM_STATE_SAFE_ATTEMPTED_OFF], al
    mov  byte [r12 + PBM_STATE_BIP_OFF], 0
    call increment_work_failure
    call b1_classify_work_terminal
    cmp  eax, 2
    je   .b1_suspect_state
    cmp  eax, 1
    jne  .b1_after_normal_threshold
    lea  rdi, [rel str_b1_software_revert]
    call serial_string
.b1_after_normal_threshold:
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_SAFE
    mov  byte [rel selected_reason], PBM_REASON_SAFE_RETRY
    mov  edi, ebx
    call set_fallback_other_verified
    lea  rdi, [rel str_policy_safe]
    call serial_string
    jmp  .success
.failed_trial:
    mov  edi, ebx
    call quarantine_work_slot
    mov  [r12 + PBM_STATE_PREVIOUS_OFF], bl
    mov  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    mov  byte [r12 + PBM_STATE_TRIES_LEFT_OFF], 0
    jmp  .failed_common
.failed_terminal:
    mov  edi, ebx
    call quarantine_work_slot
.failed_common:
    call increment_work_failure
    mov  byte [r12 + PBM_STATE_BIP_OFF], 0
    call b1_classify_work_terminal
    cmp  eax, 2
    je   .b1_suspect_state
    cmp  eax, 1
    jne  .b1_after_terminal_threshold
    lea  rdi, [rel str_b1_software_revert]
    call serial_string
.b1_after_terminal_threshold:
    mov  [rel failed_entry], bl
    jmp  .rollback
.clear_nonpaos_bip:
    mov  byte [r12 + PBM_STATE_BIP_OFF], 0
    ; Ruling 2026-10-07 23:32 (b): a Rescue attempt the owner chose in that boot's
    ; Manager menu is failure-neutral. The flag is honoured only with the owner reason
    ; this Manager writes beside it; the next arm rewrites it.
    cmp  ebx, PBM_ENTRY_RESCUE
    jne  .count_nonpaos_bip
    cmp  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_OWNER_REQUEST
    jne  .count_nonpaos_bip
    test byte [r12 + PBM_STATE_LAST_FLAGS_OFF], PBM_LAST_F_DELIBERATE_RESCUE
    jz   .count_nonpaos_bip
    lea  rdi, [rel str_policy_rescue_deliberate]
    call serial_string
    jmp  .trial
.count_nonpaos_bip:
    call increment_work_failure

.trial:
    movzx ebx, byte [r12 + PBM_STATE_TRIAL_OFF]
    test ebx, ebx
    jz   .stable
    cmp  byte [r12 + PBM_STATE_TRIES_LEFT_OFF], 0
    je   .expired_trial
    mov  edi, ebx
    call slot_unquarantined
    test eax, eax
    jz   .expired_trial
    dec  byte [r12 + PBM_STATE_TRIES_LEFT_OFF]
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_TRIAL
    movzx edi, byte [r12 + PBM_STATE_ACTIVE_OFF]
    call slot_verified_usable
    test eax, eax
    jz   .trial_selected
    mov  [rel fallback_entry], dil
.trial_selected:
    lea  rdi, [rel str_policy_trial]
    call serial_string
    jmp  .success
.expired_trial:
    mov  edi, ebx
    call quarantine_work_slot
    mov  [r12 + PBM_STATE_PREVIOUS_OFF], bl
    mov  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    mov  byte [r12 + PBM_STATE_TRIES_LEFT_OFF], 0
    mov  [rel failed_entry], bl
    mov  byte [rel policy_abnormal], 1

.rollback:
    movzx edi, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    cmp  dil, [rel failed_entry]
    je   .rollback_active
    call slot_verified_usable
    test eax, eax
    jnz  .rollback_selected
.rollback_active:
    movzx edi, byte [r12 + PBM_STATE_ACTIVE_OFF]
    cmp  dil, [rel failed_entry]
    je   .rescue_state
    call slot_verified_usable
    test eax, eax
    jz   .rescue_state
.rollback_selected:
    mov  [rel selected_entry], dil
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_ROLLBACK
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    lea  rdi, [rel str_policy_rollback]
    call serial_string
    jmp  .success

.stable:
    movzx edi, byte [r12 + PBM_STATE_ACTIVE_OFF]
    call slot_verified_usable
    test eax, eax
    jz   .stable_previous
    mov  [rel selected_entry], dil
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_HEALTHY
    cmp  byte [rel policy_abnormal], 0
    je   .stable_reason
    mov  byte [rel selected_reason], PBM_REASON_INVALID_PAYLOAD
.stable_reason:
    call set_fallback_other_verified
    lea  rdi, [rel str_policy_active]
    call serial_string
    jmp  .success
.stable_previous:
    movzx edi, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    call slot_verified_usable
    test eax, eax
    jz   .rescue_state
    mov  [rel selected_entry], dil
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_ROLLBACK
    lea  rdi, [rel str_policy_rollback]
    call serial_string
    jmp  .success

.b1_suspect_state:
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    mov  byte [rel b1_memtest_preselect], 1
    lea  rdi, [rel str_b1_suspect_hardware]
    call serial_string
    jmp  .success

.rescue_state:
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_RESCUE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    lea  rdi, [rel str_policy_rescue_prefix]
    call serial_string
    movzx edi, byte [r12 + PBM_STATE_QUARANTINE_MASK_OFF]
    call serial_hex64
    lea  rdi, [rel str_policy_rescue_suffix]
    call serial_string
    jmp  .success
.rescue_no_state:
    ; No journal is no floor bypass: a held PaOSManifestFloor still refuses an
    ; older (or same-sequence substituted) manifest, Rescue included.
    call manifest_floor_check
    test eax, eax
    jnz  .fatal
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_INVALID_STATE
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    lea  rdi, [rel str_state_rescue]
    call serial_string
    xor  eax, eax
    jmp  .out
%ifdef PBM_FEATURE_HEALTH
.defer_health:
    mov  [rel attempt_state_ptr], r12
    xor  eax, eax
    jmp  .out
%endif
.success:
    xor  eax, eax
    jmp  .out
.fatal:
    mov  byte [rel fatal_policy_failure], 1
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

%ifdef PBM_FEATURE_MENU
; A1's display-blind Space/Escape/R/S/W window is a fixed five seconds. Its clock is the
; Manager-private monotonic microsecond counter advanced only by bounded Stall
; requests; the wall offset seeded below is never consulted for a duration.
%ifdef PBM_A1_FACE_ENABLED
PBM_MENU_EARLY_POLLS    equ (PBM_A1_KEY_WINDOW_TICKS + 1)
%else
PBM_MENU_EARLY_POLLS    equ 6       ; legacy focused-menu gate: 250 ms
%endif
PBM_MENU_EARLY_STALL_US equ PBM_A1_KEY_TICK_US
; PETER RULING 2026-10-01 14:10 (Manager growth grant (b), Task2307): a HEALTHY
; automatic boot no longer waits the fixed A1 window. It keeps a short held-key
; window (the 8/30 ruling: "menu=never still honors the blind-key window"): a
; key held from power-on is already queued and is read by the first poll.
; Owner-request boots keep the full A1 window; trial, Safe, rollback, failure
; and every explicit menu policy still reveal the visible menu.
PBM_MENU_HELD_POLLS     equ 6       ; 250 ms: five 50 ms stalls between six polls
PBM_MENU_VISIBLE_POLLS_PER_SEC equ 20
PBM_MENU_VISIBLE_STALL_US      equ 50000
PBM_FACE_WALL_YEAR_MIN equ 2026
PBM_FACE_WALL_YEAR_MAX equ 2038
PBM_FACE_ATTR_DIM         equ 0x00A0A0A0
PBM_FACE_ATTR_ENTRY       equ 0x00E6E6E6
PBM_FACE_ATTR_WHITE       equ 0x00FFFFFF
; Selection remains one uninterrupted raised field. Keep it below the raster
; luminance threshold so the same bright glyph polarity used by every other
; OCR-readable row remains independently shaped inside the visible bar.
PBM_FACE_ATTR_SELECTED_BG equ 0x00606060
PBM_FACE_ATTR_SELECTED_FG equ PBM_FACE_ATTR_WHITE
PBM_FACE_FONT_ROWS        equ 16
PBM_FACE_RASTER_SCALE_X   equ 2
PBM_FACE_RASTER_SCALE_Y   equ 2
PBM_FACE_RASTER_W         equ (8 * PBM_FACE_RASTER_SCALE_X)
; A compact 2x raster leaves a full black inter-cell gutter. Fifty cells keep
; the complete live-countdown sentence inside a bounded 950x356 footprint.
PBM_FACE_GLYPH_GAP        equ 3
PBM_FACE_GLYPH_W          equ (PBM_FACE_RASTER_W + PBM_FACE_GLYPH_GAP)
PBM_FACE_GLYPH_H          equ (PBM_FACE_FONT_ROWS * PBM_FACE_RASTER_SCALE_Y)
PBM_FACE_LINE_STEP        equ (PBM_FACE_GLYPH_H + 4)
PBM_FACE_FRAME_CHARS      equ 50
PBM_FACE_FRAME_WIDTH      equ (PBM_FACE_FRAME_CHARS * PBM_FACE_GLYPH_W)
PBM_FACE_LAYOUT_HEIGHT    equ (PBM_FACE_LINE_STEP * 10 + PBM_FACE_GLYPH_H)

; face_clock_init reads EFI_TIME exactly once, treats the dual-boot RTC sample
; as local calendar time, and stores wall_offset = rtc_wall - monotonic. The
; Manager never calls SetTime. Bad or implausible wall time is presentation
; evidence only: warn, retain the offset seam, and continue boot.
face_clock_init:
    push rbx
    push r12
    mov  byte [rel face_rtc_reads], 0
    mov  byte [rel face_rtc_writes], 0
    mov  byte [rel face_clock_warning_pending], 0
    mov  qword [rel face_monotonic_us], 0
    mov  qword [rel face_wall_offset_us], 0
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .invalid
    mov  rax, [rax + 0x18]             ; EFI_RUNTIME_SERVICES.GetTime
    test rax, rax
    jz   .invalid
    inc  byte [rel face_rtc_reads]
    lea  rcx, [rel face_efi_time]
    xor  edx, edx                      ; capabilities are optional
    PBM_FW_ENTER 32
    call rax
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .invalid
%ifdef PBM_TEST_CLOCK_YEAR
    ; Immutable negatives still execute one real GetTime call; only the
    ; observed sample is replaced, so no host or target RTC is mutated.
    mov  word [rel face_efi_time], PBM_TEST_CLOCK_YEAR
%endif
    movzx ebx, word [rel face_efi_time]
    movzx eax, byte [rel face_efi_time + 2]
    cmp  eax, 1
    jb   .invalid
    cmp  eax, 12
    ja   .invalid
    movzx eax, byte [rel face_efi_time + 3]
    cmp  eax, 1
    jb   .invalid
    cmp  eax, 31
    ja   .invalid
    movzx eax, byte [rel face_efi_time + 4]
    cmp  eax, 23
    ja   .invalid
    movzx eax, byte [rel face_efi_time + 5]
    cmp  eax, 59
    ja   .invalid
    movzx eax, byte [rel face_efi_time + 6]
    cmp  eax, 59
    ja   .invalid
    call face_rtc_to_wall_us
    mov  r12, rax
    call face_monotonic_now
    sub  r12, rax
    mov  [rel face_wall_offset_us], r12
    cmp  ebx, PBM_FACE_WALL_YEAR_MIN
    jb   .old
    cmp  ebx, PBM_FACE_WALL_YEAR_MAX
    ja   .future
    lea  rdi, [rel str_face_clock_healthy]
    call serial_string
    jmp  .duration
.old:
    mov  byte [rel face_clock_warning_pending], 1
    lea  rdi, [rel str_face_clock_old]
    call serial_string
    jmp  .duration
.future:
    mov  byte [rel face_clock_warning_pending], 1
    lea  rdi, [rel str_face_clock_future]
    call serial_string
    jmp  .duration
.invalid:
    mov  byte [rel face_clock_warning_pending], 1
    lea  rdi, [rel str_face_clock_old]
    call serial_string
.duration:
    lea  rdi, [rel str_face_duration_monotonic]
    call serial_string
    pop  r12
    pop  rbx
    ret

; Convert the one EFI_TIME sample to microseconds since 1970. A1's accepted
; range ends before 2100, so the Gregorian four-year leap cadence is exact for
; every healthy or fixture year this face admits.
face_rtc_to_wall_us:
    movzx r8d, word [rel face_efi_time]
    mov  eax, r8d
    sub  eax, 1970
    imul rax, rax, 31536000
    mov  ecx, r8d
    sub  ecx, 1969
    shr  ecx, 2
    imul rcx, rcx, 86400
    add  rax, rcx
    movzx ecx, byte [rel face_efi_time + 2]
    dec  ecx
    lea  r10, [rel face_month_days]
    xor  r11d, r11d
.month:
    cmp  r11d, ecx
    jae  .months_done
    movzx edx, byte [r10 + r11]
    imul rdx, rdx, 86400
    add  rax, rdx
    inc  r11d
    jmp  .month
.months_done:
    cmp  ecx, 2
    jb   .day
    test r8b, 3
    jnz  .day
    add  rax, 86400
.day:
    movzx edx, byte [rel face_efi_time + 3]
    dec  edx
    imul rdx, rdx, 86400
    add  rax, rdx
    movzx edx, byte [rel face_efi_time + 4]
    imul rdx, rdx, 3600
    add  rax, rdx
    movzx edx, byte [rel face_efi_time + 5]
    imul rdx, rdx, 60
    add  rax, rdx
    movzx edx, byte [rel face_efi_time + 6]
    add  rax, rdx
    imul rax, rax, 1000000
    ret

face_monotonic_now:
    mov  rax, [rel face_monotonic_us]
    ret

face_wall_now:
    call face_monotonic_now
    add  rax, [rel face_wall_offset_us]
    ret

face_clock_warn_if_pending:
    cmp  byte [rel face_clock_warning_pending], 1
    jne  .out
    mov  byte [rel face_clock_warning_pending], 0
    lea  rdi, [rel ucs2_face_clock_warning]
    ; Restore console_output's normal leaf-entry parity before its call.
    sub  rsp, 8
    call console_output
    add  rsp, 8
.out:
    ret

; present_menu_if_needed -> EAX=0 continue, 1 fatal durable-state failure.
; Automatic healthy/clean-Trial and owner-request paths remain quiet unless a
; local key is already queued. Abnormal Trial/Safe/rollback/Rescue and explicit
; menu policies reveal a bounded console menu. SHOW_NEXT is cleared durably so
; a reset in the menu cannot replay it forever.
%ifdef PBM_DIAG_INPUT
%include "bootmgr/input_diagnostics.inc"
%endif
%include "bootmgr/usb_console_connect.inc"

present_menu_if_needed:
    push rbx
    push r12
    mov  byte [rel menu_visible], 0
    mov  byte [rel menu_recovery_visible], 0
    mov  byte [rel menu_timeout], PBM_MENU_TIMEOUT_DEFAULT
    mov  word [rel menu_initial_char], 0
    mov  byte [rel menu_cursor_key], 0 ; arrows are tentative until Enter
    mov  byte [rel menu_show_after_blind], 0
    mov  r12, [rel attempt_state_ptr]
    test r12, r12
    jnz  .have_state
    mov  r12, [rel selected_state_ptr]
.have_state:
    test r12, r12
    jz   .want_show
    mov  al, [r12 + PBM_STATE_MENU_TIMEOUT_OFF]
    mov  [rel menu_timeout], al
    mov  al, [r12 + PBM_STATE_MENU_POLICY_OFF]
    cmp  al, PBM_MENU_AUTOMATIC
    jne  .want_show
    mov  al, [rel selected_reason]
    cmp  al, PBM_REASON_HEALTHY
    je   .blind
    cmp  al, PBM_REASON_OWNER_REQUEST
    je   .blind
    cmp  al, PBM_REASON_TRIAL
    jne  .want_show
    ; A newly armed update is not a failure. Keep the existing held-key entry
    ; gesture, without the 5 s blind grace plus visible countdown. Unresolved
    ; failures and non-normal profiles still get the recovery menu.
    cmp  byte [rel policy_abnormal], 0
    jne  .want_show
    cmp  byte [r12 + PBM_STATE_FAILURE_COUNT_OFF], 0
    jne  .want_show
    cmp  byte [rel selected_profile], PBM_PROFILE_NORMAL
    jne  .want_show
.blind:
    cmp  byte [rel menu_show_after_blind], 0
    jne  .blind_full
    cmp  byte [rel selected_reason], PBM_REASON_HEALTHY
    je   .blind_healthy
    cmp  byte [rel selected_reason], PBM_REASON_TRIAL
    jne  .blind_full
    lea  rdi, [rel str_menu_trial_held]
    jmp  .blind_held
.blind_healthy:
    lea  rdi, [rel str_menu_healthy_held]
.blind_held:
    call serial_string
    call menu_poll_key_held
    jmp  .blind_polled
.blind_full:
    call menu_poll_key_grace
.blind_polled:
    cmp  eax, -1
    je   .after_blind
    ; Space avoids POST Escape hotkeys; both reveal without selecting a route.
    cmp  eax, 32
    je   .reveal
    cmp  eax, 27
    je   .reveal
    mov  [rel menu_initial_char], ax
%ifdef PBM_A1_FACE_ENABLED
    call menu_dispatch_key
    test eax, eax
    jz   .after_blind
    call menu_emit_blind_route
    call face_clock_warn_if_pending
    xor  eax, eax
    jmp  .out
%else
    mov  byte [rel menu_show_after_blind], 1
    jmp  .render
%endif
.reveal:
    mov  byte [rel menu_show_after_blind], 1
    jmp  .render
.after_blind:
    cmp  byte [rel menu_show_after_blind], 1
    je   .render
    call face_clock_warn_if_pending
    lea  rdi, [rel str_menu_hidden]
    call serial_string
    xor  eax, eax
    jmp  .out
.want_show:
    mov  byte [rel menu_show_after_blind], 1
    test r12, r12
    jz   .blind
    cmp  byte [r12 + PBM_STATE_MENU_POLICY_OFF], PBM_MENU_SHOW_NEXT
    jne  .blind
    call consume_show_next
    test eax, eax
    jnz  .fatal
    mov  r12, [rel attempt_state_ptr]
    jmp  .blind
.render:
    mov  al, [rel menu_timeout]
    mov  [rel menu_remaining], al       ; presentation only: never rewrite the policy timeout
%ifdef PBM_DIAG_INPUT
    ; A new presentation may change GOP geometry or fall back to ConOut.
    mov  byte [rel menu_diag_gop_ready], 0
%endif
    mov  byte [rel face_countdown_graphics], 0
    mov  dword [rel face_countdown_row], -1
    mov  byte [rel menu_visible], 1
    lea  rdi, [rel str_menu_visible]
    call serial_string
    ; A prior EFI image (including direct PaOS) may leave live GOP pixels
    ; behind when firmware launches Manager without resetting the display.
    ; Clear through ConOut before the first menu OutputString.  Missing ConOut
    ; and firmware refusal are both non-fatal: serial/input/policy still run.
%ifndef PBM_PREFIX_NO_MENU_CLEAR
    call prepare_menu_console
%endif
    ; Retain the established direct OutputString seam after ClearScreen so its
    ; firmware-call ABI/order guard remains meaningful. Suppress this empty
    ; call's observer marker; menu_render_face emits the settled boundary only
    ; after every R2 line is on screen.
    mov  byte [rel face_output_rendering], 1
    lea  rdi, [rel ucs2_face_empty]
    call console_output
    call menu_render_face
    PBM_STAGE 0x108                    ; visible menu rendered
%ifdef PBM_TEST_STOP_AFTER_MENU_PRESENT
    lea  rdi, [rel str_menu_present_stop]
    call serial_string
    xor  eax, eax
    jmp  .out
%endif
    movzx eax, word [rel menu_initial_char]
    test eax, eax
    jz   .wait_setup
    call menu_dispatch_key
    test eax, eax
    jnz  .selected
.wait_setup:
    ; A per-wait budget (root 2026-10-08 20:09:57 (2)(c)): each visible menu
    ; starts a fresh PBM_WATCHDOG_SECONDS, so a human at a menu, or a chain of
    ; external retries, never spends the entry budget. Input cannot extend one
    ; wait past menu_timeout (<= 30 s, .tick), so a wedge is still reset.
    mov  ecx, PBM_WATCHDOG_SECONDS
    call manager_watchdog_set
    movzx ebx, byte [rel menu_timeout]
    imul ebx, ebx, PBM_MENU_VISIBLE_POLLS_PER_SEC
    lea  rdi, [rel str_menu_input_service]
    call serial_string
.wait:
    PBM_STAGE 0x109                    ; before the first CheckEvent(ConIn.WaitForKey)
    call menu_check_key_event
    PBM_STAGE 0x10A                    ; first CheckEvent returned
    test eax, eax
    jnz  .tick
    call menu_poll_key
    cmp  eax, -1
    je   .tick
    call menu_dispatch_key
    test eax, eax
    jnz  .selected
.tick:
    ; Every pass consumes one fixed tick, including an invalid key or a
    ; transient console miss.  Input therefore cannot extend the configured
    ; 3..30 second bound.
    call menu_visible_stall
    PBM_STAGE 0x10B                    ; first visible-menu Stall returned
    dec  ebx
    jz   .timed_out
    call menu_countdown_tick
    jmp  .wait
.timed_out:
    lea  rdi, [rel str_menu_timeout]
    call serial_string
    xor  eax, eax
    jmp  .out
.selected:
    xor  eax, eax
    jmp  .out
.fatal:
    mov  byte [rel fatal_policy_failure], 1
    mov  eax, 1
.out:
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_final
%endif
    pop  r12
    pop  rbx
    ret

; EBX=remaining fixed 50 ms polls. Display ceil(polls/20) only on a second
; boundary, without changing EBX, policy, watchdog or input service. Redraw just
; the footer; a countdown refresh must not clear the menu or probe GOP again.
menu_countdown_tick:
    lea  eax, [rbx + PBM_MENU_VISIBLE_POLLS_PER_SEC - 1]
    xor  edx, edx
    mov  ecx, PBM_MENU_VISIBLE_POLLS_PER_SEC
    div  ecx
    cmp  al, [rel menu_remaining]
    je   .out
    mov  [rel menu_remaining], al
    push r12
    push r13
    push r14
    cmp  byte [rel face_countdown_graphics], 1
    jne  .console
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP * 8
    mov  ecx, PBM_FACE_FRAME_WIDTH
    mov  r8d, PBM_FACE_GLYPH_H
    xor  eax, eax
    call face_fb_fill_rect              ; erase old suffix when 10 becomes 9
    call menu_render_face_footer
    jmp  .done
.console:
    call menu_countdown_console
.done:
    pop  r14
    pop  r13
    pop  r12
.out:
    ret

; Remember the actual console footer row at its initial presentation. The
; cursor is firmware-owned; missing Mode/SetCursorPosition is a nonfatal no-op.
menu_countdown_bind_console:
    mov  dword [rel face_countdown_row], -1
    mov  rax, [rel system_table]
    test rax, rax
    jz   .out
    mov  rax, [rax + 64]
    test rax, rax
    jz   .out
    mov  rax, [rax + 72]
    test rax, rax
    jz   .out
    mov  eax, [rax + 16]                ; SIMPLE_TEXT_OUTPUT_MODE.CursorRow
    test eax, eax
    js   .out
    mov  [rel face_countdown_row], eax
.out:
    ret

; Update the existing console footer in place, then restore the cursor below
; the hints. No ClearScreen, SetMode, new event, key read or timeout extension.
menu_countdown_console:
    push r12
    push r13
    push r14
    cmp  dword [rel face_countdown_row], 0
    jl   .out
    mov  rax, [rel system_table]
    test rax, rax
    jz   .out
    mov  r12, [rax + 64]
    test r12, r12
    jz   .out
    cmp  qword [r12 + 56], 0            ; SetCursorPosition
    je   .out
    cmp  qword [r12 + 8], 0             ; OutputString
    je   .out
    mov  rax, [r12 + 72]
    test rax, rax
    jz   .out
    mov  r13d, [rax + 12]               ; preserve the live cursor, not a guessed row
    mov  r14d, [rax + 16]
    test r13d, r13d
    js   .out
    test r14d, r14d
    js   .out
    mov  rcx, r12
    xor  edx, edx
    mov  r8d, [rel face_countdown_row]
    PBM_FW_ENTER 32
    call [r12 + 56]
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .out                          ; do not print into a different row on refusal
    mov  byte [rel face_output_rendering], 1
    call menu_render_console_countdown
    mov  byte [rel face_output_rendering], 0
    mov  rcx, r12
    mov  edx, r13d
    mov  r8d, r14d
    PBM_FW_ENTER 32
    call [r12 + 56]
    PBM_FW_LEAVE 32
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

menu_render_console_countdown:
    lea  rdi, [rel face_footer_prefix]
    call menu_console_output_ascii
    call menu_face_timeout_ascii
    call menu_console_output_ascii
    lea  rdi, [rel face_footer_suffix]
    call menu_console_output_ascii
    lea  rdi, [rel face_countdown_padding]
    call menu_console_output_ascii       ; remove the old last cell at 10 -> 9
    ret

; Clear SHOW_NEXT in its own verified journal transaction before displaying.
consume_show_next:
    mov  rsi, r12
    lea  rdi, [rel state_work]
    cmp  rsi, rdi
    je   .have_work
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
.have_work:
    mov  byte [rel state_work + PBM_STATE_MENU_POLICY_OFF], PBM_MENU_AUTOMATIC
    call bind_work_manifest
    lea  r12, [rel state_work]
    call journal_commit
    test eax, eax
    jnz  .out
    mov  rax, [rel selected_state_ptr]
    mov  [rel attempt_state_ptr], rax
    lea  rdi, [rel str_menu_show_next_consumed]
    call serial_string
    xor  eax, eax
.out:
    ret

; Poll the fixed held-key or A1 blind window. Space/Escape reveal the menu; R/S/W
; retain their validated direct routes. Other queued keys consume the same finite
; budget; the monotonic deadline remains unchanged.
menu_poll_key_held:
    push rbx
    mov  ebx, PBM_MENU_HELD_POLLS
    jmp  menu_poll_key_grace.poll

menu_poll_key_grace:
    push rbx
    mov  ebx, PBM_MENU_EARLY_POLLS
.poll:
    call menu_poll_key
    cmp  eax, -1
    je   .wait
    mov  edx, eax
    cmp  eax, 32
    je   .accepted
    cmp  eax, 27
    je   .accepted
    or   al, 0x20
    cmp  al, 'r'
    je   .accepted
    cmp  al, 's'
    je   .accepted
%ifdef PBM_FEATURE_EXTERNAL
    cmp  al, 'w'
    je   .accepted
%endif
.wait:
    dec  ebx
    jz   .none
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .none
    add  qword [rel face_monotonic_us], PBM_MENU_EARLY_STALL_US
    mov  ecx, PBM_MENU_EARLY_STALL_US
    ; This helper's saved RBX leaves RSP eight bytes off the firmware-call
    ; boundary.  Reserve the 32-byte x64 home area plus eight-byte alignment;
    ; OVMF tolerated the old 32-byte call while Lenovo firmware raised #GP.
    PBM_FW_ENTER 40
    call [rax + 0xF8]                ; Stall(50 ms)
    PBM_FW_LEAVE 40
    jmp  .poll
.accepted:
    mov  eax, edx
    jmp  .out
.none:
    mov  eax, -1
.out:
    pop  rbx
    ret

; Explicitly check ConIn.WaitForKey before each visible-menu read.  CheckEvent
; runs an unsignaled EVT_NOTIFY_WAIT event's firmware notification function,
; allowing the USB console driver to publish queued input without allocating
; any Manager event.  This avoids the Lenovo M720s fault observed inside
; CreateEvent after GRUB chainload while preserving delayed-key service.
; menu_check_key_event -> EAX=0 ConIn ready or extended readers available,
; 1 no dispatch. Extended readers are polled even if ConIn is unsignaled.
menu_check_key_event:
    mov  rax, [rel system_table]
    test rax, rax
    jz   .not_ready
    mov  rcx, [rax + 48]              ; ConIn
    test rcx, rcx
    jz   .not_ready
    mov  rcx, [rcx + 16]              ; ConIn.WaitForKey
    test rcx, rcx
    jz   .not_ready
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .not_ready
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_check_enter
%endif
    PBM_FW_ENTER 32
    call [rax + 0x78]                 ; CheckEvent(ConIn.WaitForKey)
    PBM_FW_LEAVE 32
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_check_return
%endif
    test rax, rax
    jnz  .not_ready
    xor  eax, eax
    ret
.not_ready:
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_check_missing
%endif
    ; An extended keyboard need not be included in the ConIn event.
    cmp qword [rel menu_ex_count], 0
    sete al
    movzx eax, al
    ret

; One fixed delay per visible-menu pass supplies the independent 3..30 second
; deadline.  The loop count, not firmware timer state, is authoritative.
menu_visible_stall:
    add  qword [rel face_monotonic_us], PBM_MENU_VISIBLE_STALL_US
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .out
    mov  ecx, PBM_MENU_VISIBLE_STALL_US
    PBM_FW_ENTER 32
    call [rax + 0xF8]                 ; Stall(50 ms)
    PBM_FW_LEAVE 32
.out:
    ret

; Read every discovered extended keyboard directly until one supplies a key.
; ConIn may exclude a keyboard bound after firmware console initialization.
; EFI_KEY_DATA is 12 bytes (GNU-EFI eficonex.h); use private stack storage so
; the legacy four-byte EFI_INPUT_KEY and its adjacent data remain unchanged.
menu_read_key_ex:
    push rbx
    push r12
    sub rsp, 16
    xor ebx, ebx
.next:
    cmp rbx, [rel menu_ex_count]
    jae .none
    mov rax, [rel menu_ex_inputs]
    mov r12, [rax + rbx * 8]
    inc rbx
    test r12, r12
    jz .next
    cmp qword [r12 + 8], 0
    je .next
    mov qword [rsp], 0
    mov qword [rsp + 8], 0
    mov rcx, r12
    mov rdx, rsp
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_read_enter
%endif
    PBM_FW_ENTER 32
    call [r12 + 8]                 ; ReadKeyStrokeEx, no ConIn event gate
    PBM_FW_LEAVE 32
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_read_return
%endif
    test rax, rax
    jnz .next
    mov edx, [rsp]
    test edx, edx                  ; exposed modifier state alone is not a key
    jz .next
    mov [rel menu_input_key], edx
    jmp .out
.none:
    mov rax, 0x8000000000000006    ; EFI_NOT_READY
.out:
    add rsp, 16
    pop r12
    pop rbx
    ret

; menu_poll_key -> UCS-2, private Up/Down tokens 0x10001/0x10002, or -1.
; EFI scan codes are considered only when UnicodeChar is zero.
menu_poll_key:
    cmp qword [rel menu_ex_count], 0
    je .legacy
    call menu_read_key_ex
    test rax, rax
    jz .decode
.legacy:
    mov  rax, [rel system_table]
    test rax, rax
    jz   .none
    mov  rcx, [rax + 48]
    test rcx, rcx
    jz   .none
    lea  rdx, [rel menu_input_key]
    mov  rax, [rcx + 8]              ; ReadKeyStroke
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_read_enter
%endif
    PBM_FW_ENTER 32
    call rax
    PBM_FW_LEAVE 32
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_read_return
%endif
    test rax, rax
    jnz  .none
.decode:
    movzx eax, word [rel menu_input_key + 2]
    test eax, eax
    jnz  .key
    movzx eax, word [rel menu_input_key]
    cmp  eax, 1                       ; EFI_SCAN_UP
    je   .arrow
    cmp  eax, 2                       ; EFI_SCAN_DOWN
    je   .arrow
    cmp  eax, 23                      ; EFI_SCAN_ESC (UnicodeChar is zero)
    jne  .unknown
    mov  eax, 27
    ret
.arrow:
    add  eax, 0x10000                ; outside the UCS-2 character range
.key:
    ret
.unknown:
    xor  eax, eax
    ret
.none:
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_read_missing
%endif
    mov  eax, -1
    ret

menu_recovery_helpers:
%include "bootmgr/recovery_menu.inc"

; menu_apply_key(EAX=UCS-2) -> EAX=1 accepted, 0 ignored.
menu_apply_key:
    push rbx
    push r12
    cmp  eax, 0x10001
    je   .up
    cmp  eax, 0x10002
    je   .down
    cmp  ax, 13
    jne  .dispatch
    cmp  byte [rel menu_cursor_key], 0
    je   .accept_default
    movzx eax, byte [rel menu_cursor_key]
.dispatch:
    or   al, 0x20
    cmp  al, 'r'
    je   .rescue
    cmp  al, 's'
    je   .safe
%ifdef PBM_FEATURE_EXTERNAL
    cmp  al, 'w'
    je   .windows
    cmp  al, 'l'
    je   .linux
%endif
    cmp  al, 'p'
    je   .active
    cmp  al, 'o'
    je   .standby
    cmp  al, 'a'
    je   .a
    cmp  al, 'b'
    je   .b
    jmp  .ignore
.active:
    movzx ebx, byte [rel menu_active_entry]
    cmp  byte [rel menu_show_active], 1
    jne  .ignore
    jmp  .paos
.standby:
    movzx ebx, byte [rel menu_standby_entry]
    cmp  byte [rel menu_show_standby], 1
    jne  .ignore
    jmp  .paos
.a:
    mov  ebx, PBM_ENTRY_PAOS_A
    jmp  .paos
.b:
    mov  ebx, PBM_ENTRY_PAOS_B
.paos:
    mov  r12, [rel attempt_state_ptr]
    test r12, r12
    jz   .ignore
    mov  edi, ebx
    call slot_unquarantined
    test eax, eax
    jz   .ignore
    mov  edi, ebx
    call integrity_vault_select_entry
    test rax, rax
    jz   .ignore
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    mov  edi, ebx
    call set_fallback_other_verified
    jmp  .override
.safe:
    mov  r12, [rel attempt_state_ptr]
    test r12, r12
    jz   .ignore
    movzx ebx, byte [r12 + PBM_STATE_ACTIVE_OFF]
    mov  edi, ebx
    call slot_verified_usable
    test eax, eax
    jz   .ignore
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_SAFE
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    mov  edi, ebx
    call set_fallback_other_verified
    jmp  .override
.rescue:
    mov  edi, PBM_ENTRY_RESCUE
    call integrity_vault_select_entry
    test rax, rax
    jz   .ignore
    mov  byte [rel selected_entry], PBM_ENTRY_RESCUE
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
%ifdef PBM_FEATURE_EXTERNAL
    jmp  .override
.windows:
    mov  ebx, PBM_ENTRY_WINDOWS
    jmp  .external
.linux:
    mov  ebx, PBM_ENTRY_LINUX
.external:
    mov  edi, ebx
    call menu_external_allowed
    test eax, eax
    jz   .ignore
    mov  [rel selected_entry], bl
    mov  byte [rel selected_profile], PBM_PROFILE_EXTERNAL
    mov  byte [rel selected_reason], PBM_REASON_OWNER_REQUEST
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
%endif
.override:
    mov  byte [rel menu_rescue_chosen], 0
    cmp  byte [rel selected_entry], PBM_ENTRY_RESCUE
    jne  .override_emit
    mov  byte [rel menu_rescue_chosen], 1
.override_emit:
    lea  rdi, [rel str_menu_override]
    call serial_string
    mov  eax, 1
    jmp  .out
.accept_default:
    lea  rdi, [rel str_menu_accept]
    call serial_string
    mov  eax, 1
    jmp  .out
.up:
    mov  edi, -1
    jmp  .navigate
.down:
    mov  edi, 1
.navigate:
    cmp  byte [rel menu_visible], 1
    jne  .ignore
    call menu_move_cursor
    test eax, eax
    jz   .ignore
    call menu_redraw_selection
    jmp  .ignore
.ignore:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Tentative focus only. No selected route/profile, journal, timeout or trust
; state changes until Enter dispatches the existing validated letter path.
; EDI=-1/+1, EAX=1 when a visible row was found. At most six probes.
menu_move_cursor:
    push rbx
    push r12
    mov  ebx, edi
    movzx eax, byte [rel menu_cursor_key]
    test eax, eax
    jnz  .find
    call menu_cursor_default_key
.find:
    lea  rdx, [rel menu_nav_rows]
    xor  ecx, ecx
.find_loop:
    cmp  al, [rdx + rcx * 2]
    je   .start
    inc  ecx
    cmp  ecx, 6
    jb   .find_loop
    ; No visible default: Down starts at the first row, Up at the last.
    xor  ecx, ecx
    test ebx, ebx
    js   .start
    dec  ecx
.start:
    mov  r12d, 6
.next:
    add  ecx, ebx
    cmp  ecx, 6
    jl   .not_high
    xor  ecx, ecx
.not_high:
    test ecx, ecx
    jns  .probe
    mov  ecx, 5
.probe:
    movzx eax, byte [rdx + rcx * 2 + 1]
    lea  r8, [rel menu_show_active]
    cmp  byte [r8 + rax], 1
    je   .found
    dec  r12d
    jnz  .next
    xor  eax, eax
    jmp  .out
.found:
    mov  al, [rdx + rcx * 2]
    mov  [rel menu_cursor_key], al
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

menu_cursor_default_key:
    mov  eax, 's'
    cmp  byte [rel selected_profile], PBM_PROFILE_SAFE
    je   .out
    movzx eax, byte [rel selected_entry]
    cmp  al, [rel menu_active_entry]
    je   .active
    cmp  al, [rel menu_standby_entry]
    je   .standby
    cmp  al, PBM_ENTRY_RESCUE
    je   .rescue
    cmp  al, PBM_ENTRY_WINDOWS
    je   .windows
    cmp  al, PBM_ENTRY_LINUX
    je   .linux
    xor  eax, eax
    ret
.active: mov eax, 'p'
    ret
.standby: mov eax, 'o'
    ret
.rescue: mov eax, 'r'
    ret
.windows: mov eax, 'w'
    ret
.linux: mov eax, 'l'
.out: ret

; Repaint only the entry rectangle on GOP. Keep title, frame, countdown and
; reason untouched; never locate GOP, clear the framebuffer or set a mode.
menu_redraw_selection:
    push rbx
    cmp  byte [rel face_countdown_graphics], 1
    jne  .console
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W * 2
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP
    mov  ecx, PBM_FACE_FRAME_WIDTH - PBM_FACE_GLYPH_W * 4
    mov  r8d, PBM_FACE_LINE_STEP * 6
    xor  eax, eax
    call face_fb_fill_rect
    call menu_render_face_entries
    jmp  .out
.console:
    call prepare_menu_console
    call menu_render_console_face
.out:
    pop  rbx
    ret

; Independent observer marker for the three accepted pre-display routes. The
; selection has already passed the normal manifest/state checks in
; menu_apply_key; no blind shortcut bypasses payload validation.
menu_emit_blind_route:
    movzx eax, word [rel menu_initial_char]
    or   al, 0x20
    cmp  al, 'r'
    je   .rescue
    cmp  al, 's'
    je   .safe
    lea  rdi, [rel str_face_blind_windows]
    jmp  .emit
.rescue:
    lea  rdi, [rel str_face_blind_rescue]
    jmp  .emit
.safe:
    lea  rdi, [rel str_face_blind_safe]
.emit:
    call serial_string
    ret

%ifdef PBM_FEATURE_EXTERNAL
; External entries appear only when the owner manifest marks them Visible, or
; when explicit Detailed policy reveals hidden signed identities.
menu_external_allowed:
    push rbx
    mov  ebx, edi
    call integrity_vault_select_entry
    test rax, rax
    jz   .no
    test byte [rax + 1], 1            ; manifest Visible flag
    jnz  .yes
    mov  rax, [rel attempt_state_ptr]
    test rax, rax
    jz   .no
    cmp  byte [rax + PBM_STATE_MENU_POLICY_OFF], PBM_MENU_DETAILED
    jne  .no
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    mov  edi, ebx
    pop  rbx
    ret

%endif

; Build the face exclusively from the state and manifest that have already
; passed the Manager's journal/signature gates. No presentation bytes are
; read from the ESP. The authenticated manifest entry SHA-256 at +16 is the
; content identity used to decide whether a healthy standby is meaningfully
; different from Active.
menu_prepare_user_labels:
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel menu_active_entry], PBM_ENTRY_NONE
    mov  byte [rel menu_standby_entry], PBM_ENTRY_NONE
    mov  byte [rel menu_show_active], 0
    mov  byte [rel menu_show_standby], 0
    mov  byte [rel menu_show_safe], 0
    mov  byte [rel menu_show_rescue], 0
    mov  byte [rel menu_show_windows], 0
    mov  byte [rel menu_show_linux], 0
    mov  r12, [rel attempt_state_ptr]
    test r12, r12
    jnz  .have_state
    mov  r12, [rel selected_state_ptr]
.have_state:
    test r12, r12
    jz   .rescue
    movzx ebx, byte [r12 + PBM_STATE_ACTIVE_OFF]
    mov  edi, ebx
    call slot_verified_usable
    test eax, eax
    jz   .rescue
    mov  [rel menu_active_entry], bl
    mov  byte [rel menu_show_active], 1
    mov  byte [rel menu_show_safe], 1

    ; A and B are the fixed IDs 1 and 2, so 3-active is the other slot.
    mov  r13d, 3
    sub  r13d, ebx
    mov  edi, r13d
    call slot_verified_usable
    test eax, eax
    jz   .rescue
    mov  edi, ebx
    call integrity_vault_select_entry
    test rax, rax
    jz   .rescue
    mov  r14, rax
    mov  edi, r13d
    call integrity_vault_select_entry
    test rax, rax
    jz   .rescue
    lea  rdi, [rax + 16]
    lea  rsi, [r14 + 16]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jz   .rescue
    mov  [rel menu_standby_entry], r13b
    mov  byte [rel menu_show_standby], 1
.rescue:
    mov  edi, PBM_ENTRY_RESCUE
    call integrity_vault_select_entry
    test rax, rax
    setnz al
    mov  [rel menu_show_rescue], al
%ifdef PBM_FEATURE_EXTERNAL
    mov  edi, PBM_ENTRY_WINDOWS
    call menu_external_allowed
    test eax, eax
    setnz al
    mov  [rel menu_show_windows], al
    mov  edi, PBM_ENTRY_LINUX
    call menu_external_allowed
    test eax, eax
    setnz al
    mov  [rel menu_show_linux], al
%endif
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Pure R2 renderer. Small GOPs use native Spleen 8x16 and halved logical
; coordinates; wider GOPs retain the existing 2x face. No mode change.
; Both retain an explicit gutter. Lightgray is near-white while staying
; inside the fixture's lightgray band, preserving both readable OCR and R2 ink.
menu_render_face:
    push rbx
    push r12
    push r13
    push r14
    push r15                         ; odd save count preserves firmware-call ABI
    call menu_prepare_user_labels
    call face_gop_init
    test eax, eax
    jnz  .console_fallback
    mov  byte [rel face_countdown_graphics], 1
    call face_fb_clear

    mov  eax, [rel face_fb_width]
    cmp  byte [rel face_compact], 0
    je   .width_ready
    add  eax, eax
.width_ready:
    sub  eax, PBM_FACE_FRAME_WIDTH
    jbe  .left_edge
    shr  eax, 1
    mov  [rel face_layout_x], eax
    jmp  .x_ready
.left_edge:
    mov  dword [rel face_layout_x], 0
.x_ready:
    mov  eax, [rel face_fb_height]
    cmp  byte [rel face_compact], 0
    je   .height_ready
    add  eax, eax
.height_ready:
    sub  eax, PBM_FACE_LAYOUT_HEIGHT
    jbe  .top_edge
    shr  eax, 1
    mov  [rel face_layout_y], eax
    jmp  .layout_ready
.top_edge:
    mov  dword [rel face_layout_y], 0
.layout_ready:
    cmp  byte [rel face_ascii_frame], 1
    je   .ascii_frame
    call face_draw_double_frame
    ; Cut one continuous black title opening. The OCR cell gaps must
    ; not leave pieces of the upper rails running between title glyphs.
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W * 2
    mov  edx, [rel face_layout_y]
    mov  ecx, PBM_FACE_GLYPH_W * 23
    mov  r8d, PBM_FACE_GLYPH_H
    xor  eax, eax
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W * 3
    mov  edx, [rel face_layout_y]
    lea  rdi, [rel face_title]
    mov  r8d, PBM_FACE_ATTR_WHITE
    xor  r9d, r9d
    call face_fb_string
    jmp  .entries
.ascii_frame:
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    lea  rdi, [rel face_ascii_top]
    mov  r8d, PBM_FACE_ATTR_WHITE
    xor  r9d, r9d
    call face_fb_string
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP
    mov  ecx, 6
.ascii_sides:
    push rcx
    call face_draw_ascii_sides
    pop  rcx
    add  edx, PBM_FACE_LINE_STEP
    loop .ascii_sides
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP * 7
    lea  rdi, [rel face_ascii_bottom]
    mov  r8d, PBM_FACE_ATTR_WHITE
    xor  r9d, r9d
    call face_fb_string

.entries:
    call menu_render_face_entries

    call menu_render_face_footer
    call menu_render_face_reason
    call face_clock_warn_if_pending
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_gop_begin
%endif
    mov  byte [rel face_output_rendering], 0
    ; The immutable gate captures only after this settled presentation marker.
    lea  rdi, [rel ucs2_face_empty]
    call console_output
    cmp  byte [rel face_ascii_frame], 1
    je   .ascii_marker
    lea  rdi, [rel str_face_frame_double]
    call serial_string
    xor  eax, eax
    jmp  .out
.ascii_marker:
    lea  rdi, [rel str_face_frame_ascii]
    call serial_string
    xor  eax, eax
    jmp  .out

.console_fallback:
    ; GOP absence cannot turn presentation into a boot failure. The text
    ; fallback selects the same compiled fragments as the raster face.
    mov  byte [rel face_ascii_frame], 1
    mov  byte [rel face_output_rendering], 1
    call menu_render_console_face
    call face_clock_warn_if_pending
    mov  byte [rel face_output_rendering], 0
    lea  rdi, [rel ucs2_face_empty]
    call console_output
    lea  rdi, [rel str_face_frame_ascii]
    call serial_string
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared initial and cursor-only row renderer; layout/availability already bound.
menu_render_face_entries:
    push r15
    mov  r15d, [rel face_layout_y]
    add  r15d, PBM_FACE_LINE_STEP
    cmp  byte [rel menu_show_active], 1
    jne  .standby_entry
    movzx eax, byte [rel menu_active_entry]
    lea  rdi, [rel face_entry_active]
    mov  edx, r15d
    call menu_render_face_entry
    add  r15d, PBM_FACE_LINE_STEP
.standby_entry:
    cmp  byte [rel menu_show_standby], 1
    jne  .safe_entry
    movzx eax, byte [rel menu_standby_entry]
    lea  rdi, [rel face_entry_standby]
    mov  edx, r15d
    call menu_render_face_entry
    add  r15d, PBM_FACE_LINE_STEP
.safe_entry:
    cmp  byte [rel menu_show_safe], 1
    jne  .rescue_entry
    mov  eax, 0x100                    ; safe-profile row token
    lea  rdi, [rel face_entry_safe]
    mov  edx, r15d
    call menu_render_face_entry
    add  r15d, PBM_FACE_LINE_STEP
.rescue_entry:
    cmp  byte [rel menu_show_rescue], 1
    jne  .windows_entry
    mov  eax, PBM_ENTRY_RESCUE
    lea  rdi, [rel face_entry_rescue]
    mov  edx, r15d
    call menu_render_face_entry
    add  r15d, PBM_FACE_LINE_STEP
.windows_entry:
    cmp  byte [rel menu_show_windows], 1
    jne  .linux_entry
    mov  eax, PBM_ENTRY_WINDOWS
    lea  rdi, [rel face_entry_windows]
    mov  edx, r15d
    call menu_render_face_entry
    add  r15d, PBM_FACE_LINE_STEP
.linux_entry:
    cmp  byte [rel menu_show_linux], 1
    jne  .entries_done
    mov  eax, PBM_ENTRY_LINUX
    lea  rdi, [rel face_entry_linux]
    mov  edx, r15d
    call menu_render_face_entry
.entries_done:
    pop  r15
    ret

menu_select_frame:
    mov  byte [rel face_ascii_frame], 0
%ifdef PBM_TEST_ASCII_FRAME
    mov  byte [rel face_ascii_frame], 1
%endif
    ret

; Diagnostic-only firmware GOP observation just before the mutable attempt.
; No mode set, policy branch, NVRAM write, or probe after attempt arming.
manager_gop_probe:
    mov  byte [rel manager_gop_valid], 0
    mov  qword [rel manager_gop_status], -1
    mov  qword [rel manager_gop_proto], 0
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .out
    lea  rcx, [rel manager_gop_guid]
    xor  edx, edx
    lea  r8, [rel manager_gop_proto]
    PBM_FW_ENTER 40
    call [rax + 0x140]                  ; LocateProtocol(GraphicsOutput)
    PBM_FW_LEAVE 40
    mov  [rel manager_gop_status], rax
    mov  byte [rel manager_gop_valid], 1
.out:
    ret
; end manager_gop_probe

; Locate GOP without changing its established mode. EAX=0 usable framebuffer.
face_gop_init:
    mov  byte [rel face_compact], 0
    call menu_select_frame
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .fail
    lea  rcx, [rel face_gop_guid]
    xor  edx, edx
    lea  r8, [rel face_gop_proto]
    PBM_FW_ENTER 40
    call [rax + 0x140]                  ; LocateProtocol
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .fail
    mov  rax, [rel face_gop_proto]
    test rax, rax
    jz   .fail
    mov  rax, [rax + 0x18]             ; GOP Mode
    test rax, rax
    jz   .fail
    mov  rdx, [rax + 0x18]
    mov  [rel face_fb_base], rdx
    cmp  qword [rax + 16], 36          ; live Info must contain the complete v0 prefix
    jb   .fail
    mov  rax, [rax + 8]                ; Mode Info
    test rax, rax
    jz   .fail
    mov  edx, [rax + 4]
    mov  [rel face_fb_width], edx
    mov  edx, [rax + 8]
    mov  [rel face_fb_height], edx
    mov  edx, [rax + 12]
    mov  [rel face_fb_format], edx
    cmp  edx, 1                         ; RGBX/BGRX only; BltOnly uses fallback
    ja   .fail
    mov  edx, [rax + 0x20]
    mov  [rel face_fb_stride], edx
    cmp  dword [rel face_fb_width], PBM_FACE_FRAME_WIDTH
    jae  .full_size
    cmp  dword [rel face_fb_width], 800
    jb   .fail
    cmp  dword [rel face_fb_height], 600
    jb   .fail
    mov  byte [rel face_compact], 1
.full_size:
    cmp  dword [rel face_fb_height], PBM_FACE_LAYOUT_HEIGHT
    jb   .fail
    cmp  qword [rel face_fb_base], 0
    je   .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, 1
    ret

face_fb_clear:
    mov  rdi, [rel face_fb_base]
    mov  eax, [rel face_fb_stride]
    imul eax, [rel face_fb_height]
    mov  ecx, eax
    xor  eax, eax
    rep  stosd
    ret

; Draw the bright-white double-line frame as real parallel pixel rails. The
; title's black glyph cells cut a clean label opening into the upper border.
face_draw_double_frame:
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, 14
    mov  ecx, PBM_FACE_FRAME_WIDTH
    mov  r8d, 2
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, 19
    mov  ecx, PBM_FACE_FRAME_WIDTH
    mov  r8d, 2
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP * 7
    mov  ecx, PBM_FACE_FRAME_WIDTH
    mov  r8d, 2
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP * 7 + 5
    mov  ecx, PBM_FACE_FRAME_WIDTH
    mov  r8d, 2
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, 14
    mov  ecx, 2
    mov  r8d, PBM_FACE_LINE_STEP * 7 - 7
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    add  esi, 5
    mov  edx, [rel face_layout_y]
    add  edx, 14
    mov  ecx, 2
    mov  r8d, PBM_FACE_LINE_STEP * 7 - 7
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_FRAME_WIDTH - 7
    mov  edx, [rel face_layout_y]
    add  edx, 14
    mov  ecx, 2
    mov  r8d, PBM_FACE_LINE_STEP * 7 - 7
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_FRAME_WIDTH - 2
    mov  edx, [rel face_layout_y]
    add  edx, 14
    mov  ecx, 2
    mov  r8d, PBM_FACE_LINE_STEP * 7 - 7
    mov  eax, PBM_FACE_ATTR_WHITE
    call face_fb_fill_rect
    ret

face_draw_ascii_sides:
    push rdx
    mov  esi, [rel face_layout_x]
    lea  rdi, [rel face_pipe]
    mov  r8d, PBM_FACE_ATTR_WHITE
    xor  r9d, r9d
    call face_fb_string
    pop  rdx
    push rdx
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_FRAME_WIDTH - PBM_FACE_GLYPH_W
    lea  rdi, [rel face_pipe]
    mov  r8d, PBM_FACE_ATTR_WHITE
    xor  r9d, r9d
    call face_fb_string
    pop  rdx
    ret

; EAX=row token, RDI=full exact line, EDX=y.
menu_render_face_entry:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, eax
    mov  r12, rdi
    mov  r13d, edx
    xor  r14d, r14d
    cmp  byte [rel menu_cursor_key], 0
    je   .default_selection
    movzx eax, byte [r12]
    or   al, 0x20
    cmp  al, [rel menu_cursor_key]
    sete r14b
    jmp  .selection_ready
.default_selection:
    cmp  ebx, 0x100
    jne  .normal_token
    cmp  byte [rel selected_profile], PBM_PROFILE_SAFE
    jne  .selection_ready
    mov  r14d, 1
    jmp  .selection_ready
.normal_token:
    cmp  byte [rel selected_profile], PBM_PROFILE_SAFE
    je   .selection_ready
    cmp  bl, [rel selected_entry]
    jne  .selection_ready
    mov  r14d, 1
.selection_ready:
    test r14d, r14d
    jz   .plain
    ; Preserve the same fixed-cell geometry as every unselected row.  The
    ; dedicated helper adds one continuous selection field behind those cells.
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W * 2
    mov  edx, r13d
    mov  rdi, r12
    call face_fb_selected_string
    jmp  .out
.plain:
    movzx eax, byte [r12]
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W * 2
    mov  edx, r13d
    mov  r8d, PBM_FACE_ATTR_WHITE
    xor  r9d, r9d
    call face_fb_char_scaled
    lea  rdi, [r12 + 1]
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W * 3
    ; The isolated full-width W plus a whole blank cell is consistently split
    ; by psm-6 as "Wo".  Keep the label bytes exact, but render that one word
    ; separator as the raster gutter before the hyphen instead of a blank cell.
    cmp  byte [r12], 'W'
    jne  .plain_tail_ready
    inc  rdi
    add  esi, PBM_FACE_GLYPH_GAP
.plain_tail_ready:
    mov  edx, r13d
    mov  r8d, PBM_FACE_ATTR_ENTRY
    xor  r9d, r9d
    call face_fb_string
.out:
    mov  edx, r13d
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

menu_render_face_footer:
    mov  r12d, [rel face_layout_x]
    add  r12d, PBM_FACE_GLYPH_W
    mov  r13d, [rel face_layout_y]
    add  r13d, PBM_FACE_LINE_STEP * 8
    lea  rdi, [rel face_footer_prefix]
    mov  esi, r12d
    mov  edx, r13d
    mov  r8d, PBM_FACE_ATTR_ENTRY
    xor  r9d, r9d
    call face_fb_string
    add  r12d, 17 * PBM_FACE_GLYPH_W
    call menu_face_timeout_ascii       ; RDI=digits, ECX=length
    mov  r14d, ecx
    mov  esi, r12d
    mov  edx, r13d
    mov  r8d, PBM_FACE_ATTR_ENTRY
    xor  r9d, r9d
    call face_fb_string
    imul r14d, r14d, PBM_FACE_GLYPH_W
    add  r12d, r14d
    lea  rdi, [rel face_footer_suffix]
    mov  esi, r12d
    mov  edx, r13d
    mov  r8d, PBM_FACE_ATTR_ENTRY
    xor  r9d, r9d
    call face_fb_string
    mov  r12d, [rel face_layout_x]
    add  r12d, PBM_FACE_GLYPH_W
    mov  r13d, [rel face_layout_y]
    add  r13d, PBM_FACE_LINE_STEP * 9
    cmp  byte [rel menu_show_active], 1
    jne  .hint_o
    lea  rdi, [rel face_hint_p]
    mov  ecx, 1
    call menu_render_face_hint_fragment
.hint_o:
    cmp  byte [rel menu_show_standby], 1
    jne  .hint_s
    lea  rdi, [rel face_hint_o]
    mov  ecx, 2
    call menu_render_face_hint_fragment
.hint_s:
    cmp  byte [rel menu_show_safe], 1
    jne  .hint_r
    lea  rdi, [rel face_hint_s]
    mov  ecx, 2
    call menu_render_face_hint_fragment
.hint_r:
    cmp  byte [rel menu_show_rescue], 1
    jne  .hint_w
    lea  rdi, [rel face_hint_r]
    mov  ecx, 2
    call menu_render_face_hint_fragment
.hint_w:
    cmp  byte [rel menu_show_windows], 1
    jne  .hint_l
    lea  rdi, [rel face_hint_w]
    mov  ecx, 2
    call menu_render_face_hint_fragment
.hint_l:
    cmp  byte [rel menu_show_linux], 1
    jne  .hint_done
    lea  rdi, [rel face_hint_l]
    mov  ecx, 2
    call menu_render_face_hint_fragment
.hint_done:
    lea  rdi, [rel face_hint_suffix]
    mov  ecx, 7
    call menu_render_face_hint_fragment
    ret

; RDI=compiled fragment, ECX=characters, R12D=x, R13D=y.
menu_render_face_hint_fragment:
    mov  r14d, ecx
    mov  esi, r12d
    mov  edx, r13d
    mov  r8d, PBM_FACE_ATTR_DIM
    xor  r9d, r9d
    call face_fb_string
    imul r14d, r14d, PBM_FACE_GLYPH_W
    add  r12d, r14d
    ret

menu_face_timeout_ascii:
    movzx eax, byte [rel menu_remaining]
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    add  al, '0'
    add  dl, '0'
    mov  [rel face_timeout_ascii], al
    mov  [rel face_timeout_ascii + 1], dl
    lea  rdi, [rel face_timeout_ascii]
    mov  ecx, 2
    cmp  byte [rel face_timeout_ascii], '0'
    jne  .out
    inc  rdi
    dec  ecx
.out:
    ret

; Console fallback assembled from the same compiled db fragments as the GOP
; face. The adapter is bounded to the 50-character face width and performs no
; parse or read: it only widens already-selected in-image ASCII to UCS-2.
; A static explanation of the already-selected route, never a policy decision.
; Keep unknown/future reasons neutral rather than inventing a failure or trust
; claim. Both renderers use the same text; no journal fields are exposed.
menu_reason_text:
    movzx eax, byte [rel selected_reason]
    lea  rdi, [rel face_reason_requested]
    cmp  eax, PBM_REASON_HEALTHY
    je   .out
    cmp  eax, PBM_REASON_OWNER_REQUEST
    je   .out
    lea  rdi, [rel face_reason_trial]
    cmp  eax, PBM_REASON_TRIAL
    je   .out
    lea  rdi, [rel face_reason_previous_bip]
    cmp  eax, PBM_REASON_PREVIOUS_BIP
    je   .out
    lea  rdi, [rel face_reason_safe]
    cmp  eax, PBM_REASON_SAFE_RETRY
    je   .out
    lea  rdi, [rel face_reason_rollback]
    cmp  eax, PBM_REASON_ROLLBACK
    je   .out
    lea  rdi, [rel face_reason_state]
    cmp  eax, PBM_REASON_INVALID_STATE
    je   .out
    lea  rdi, [rel face_reason_payload]
    cmp  eax, PBM_REASON_INVALID_PAYLOAD
    je   .out
    lea  rdi, [rel face_reason_rescue]
    cmp  eax, PBM_REASON_RESCUE
    je   .out
    lea  rdi, [rel face_reason_attention]
.out:
    ret

menu_render_face_reason:
    call menu_reason_text
    mov  esi, [rel face_layout_x]
    mov  edx, [rel face_layout_y]
    add  edx, PBM_FACE_LINE_STEP * 10
    mov  r8d, PBM_FACE_ATTR_ENTRY
    xor  r9d, r9d
    jmp  face_fb_string

menu_render_console_face:
    lea  rdi, [rel face_title]
    call menu_console_output_ascii
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
    call menu_reason_text
    call menu_console_output_ascii
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
    cmp  byte [rel menu_show_active], 1
    jne  .standby
    lea  rdi, [rel face_entry_active]
    call menu_console_output_entry
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.standby:
    cmp  byte [rel menu_show_standby], 1
    jne  .safe
    lea  rdi, [rel face_entry_standby]
    call menu_console_output_entry
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.safe:
    cmp  byte [rel menu_show_safe], 1
    jne  .rescue
    lea  rdi, [rel face_entry_safe]
    call menu_console_output_entry
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.rescue:
    cmp  byte [rel menu_show_rescue], 1
    jne  .windows
    lea  rdi, [rel face_entry_rescue]
    call menu_console_output_entry
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.windows:
    cmp  byte [rel menu_show_windows], 1
    jne  .linux
    lea  rdi, [rel face_entry_windows]
    call menu_console_output_entry
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.linux:
    cmp  byte [rel menu_show_linux], 1
    jne  .footer
    lea  rdi, [rel face_entry_linux]
    call menu_console_output_entry
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.footer:
    call menu_countdown_bind_console
    call menu_render_console_countdown
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
    cmp  byte [rel menu_show_active], 1
    jne  .hint_o
    lea  rdi, [rel face_hint_p]
    call menu_console_output_ascii
.hint_o:
    cmp  byte [rel menu_show_standby], 1
    jne  .hint_s
    lea  rdi, [rel face_hint_o]
    call menu_console_output_ascii
.hint_s:
    cmp  byte [rel menu_show_safe], 1
    jne  .hint_r
    lea  rdi, [rel face_hint_s]
    call menu_console_output_ascii
.hint_r:
    cmp  byte [rel menu_show_rescue], 1
    jne  .hint_w
    lea  rdi, [rel face_hint_r]
    call menu_console_output_ascii
.hint_w:
    cmp  byte [rel menu_show_windows], 1
    jne  .hint_l
    lea  rdi, [rel face_hint_w]
    call menu_console_output_ascii
.hint_l:
    cmp  byte [rel menu_show_linux], 1
    jne  .hint_done
    lea  rdi, [rel face_hint_l]
    call menu_console_output_ascii
.hint_done:
    lea  rdi, [rel face_hint_suffix]
    call menu_console_output_ascii
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
    ret

; Console fallback makes tentative focus explicit without altering label bytes.
menu_console_output_entry:
    push rdi
    cmp  byte [rel menu_cursor_key], 0
    je   .label
    movzx eax, byte [rdi]
    or   al, 0x20
    cmp  al, [rel menu_cursor_key]
    jne  .label
    lea  rdi, [rel face_cursor_marker]
    call menu_console_output_ascii
.label:
    pop  rdi
    jmp  menu_console_output_ascii

; RDI=null-terminated in-image ASCII db string. console_output aligns its
; firmware boundary from either caller parity, including a footer-only refresh.
menu_console_output_ascii:
    lea  r8, [rel face_console_ucs2]
    mov  r9d, PBM_FACE_FRAME_CHARS
.copy:
    movzx eax, byte [rdi]
    mov  [r8], ax
    test al, al
    jz   .emit
    inc  rdi
    add  r8, 2
    dec  r9d
    jnz  .copy
    mov  word [r8], 0
.emit:
    lea  rdi, [rel face_console_ucs2]
    call console_output
    ret

; ESI=x, EDX=y, ECX=w, R8D=h, EAX=color.
face_fb_fill_rect:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, esi
    mov  r12d, edx
    mov  r13d, ecx
    mov  r14d, r8d
    mov  r15d, eax
    cmp  byte [rel face_compact], 0
    je   .physical
    shr  ebx, 1
    shr  r12d, 1
    shr  r13d, 1
    shr  r14d, 1
.physical:
    xor  r10d, r10d
.row:
    cmp  r10d, r14d
    jae  .out
    mov  eax, r12d
    add  eax, r10d
    imul eax, dword [rel face_fb_stride]
    add  eax, ebx
    shl  rax, 2
    mov  rdi, [rel face_fb_base]
    add  rdi, rax
    mov  eax, r15d
    mov  ecx, r13d
    rep  stosd
    inc  r10d
    jmp  .row
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ASCII, ESI=x, EDX=y, R8D=fg, R9D=bg.
face_fb_string:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, r8d
    mov  ebx, r9d
.next:
    movzx eax, byte [r12]
    test eax, eax
    jz   .out
    inc  r12
    mov  esi, r13d
    mov  edx, r14d
    mov  r8d, r15d
    mov  r9d, ebx
    call face_fb_char_scaled
    add  r13d, PBM_FACE_GLYPH_W
    jmp  .next
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ASCII, ESI=x, EDX=y. Draw one continuous inverse-video field using the
; exact same fixed-cell geometry and bright foreground polarity as a plain
; row. Do not cut word-space slits into the field: those become false glyphs
; in the immutable whole-screen OCR pass.
face_fb_selected_string:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    xor  ecx, ecx
.measure:
    cmp  byte [r12 + rcx], 0
    je   .measured
    inc  ecx
    jmp  .measure
.measured:
    imul ecx, ecx, PBM_FACE_GLYPH_W
    mov  esi, r13d
    mov  edx, r14d
    mov  r8d, PBM_FACE_GLYPH_H
    mov  eax, PBM_FACE_ATTR_SELECTED_BG
    call face_fb_fill_rect
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r14d
    mov  r8d, PBM_FACE_ATTR_SELECTED_FG
    mov  r9d, PBM_FACE_ATTR_SELECTED_BG
    call face_fb_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EAX=ASCII, ESI=x, EDX=y, R8D=fg, R9D=bg. Expand one Spleen 8x16
; console glyph by the declared integer scales. The loop is intentionally
; scale-generic so layout constants and physical writes cannot diverge.
face_fb_char_scaled:
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  eax, 0x7F
    imul eax, eax, PBM_FACE_FONT_ROWS
    lea  r12, [rel face_ocr_font]
    add  r12, rax
    mov  r13d, esi
    mov  r14d, edx
    cmp  byte [rel face_compact], 0
    je   .physical
    shr  r13d, 1
    shr  r14d, 1
.physical:
    xor  r15d, r15d
.row:
    movzx ebx, byte [r12 + r15]
    xor  r10d, r10d
.col:
    mov  edx, 0x80
    mov  ecx, r10d
    shr  edx, cl
    mov  eax, r9d
    test ebx, edx
    jz   .color_ready
    mov  eax, r8d
.color_ready:
    mov  r11d, r15d
    cmp  byte [rel face_compact], 0
    jne  .row_position
    imul r11d, r11d, PBM_FACE_RASTER_SCALE_Y
.row_position:
    add  r11d, r14d
    imul r11d, dword [rel face_fb_stride]
    mov  edi, r10d
    cmp  byte [rel face_compact], 0
    jne  .col_position
    imul edi, edi, PBM_FACE_RASTER_SCALE_X
.col_position:
    add  edi, r13d
    add  r11d, edi
    shl  r11, 2
    add  r11, [rel face_fb_base]
    mov  edx, PBM_FACE_RASTER_SCALE_Y
    cmp  byte [rel face_compact], 0
    je   .scale_y
    mov  edx, 1
.scale_y:
    mov  rdi, r11
    mov  ecx, PBM_FACE_RASTER_SCALE_X
    cmp  byte [rel face_compact], 0
    je   .scale_x
    mov  ecx, 1
.scale_x:
    mov  [rdi], eax
    add  rdi, 4
    loop .scale_x
    mov  ecx, [rel face_fb_stride]
    shl  rcx, 2
    add  r11, rcx
    dec  edx
    jnz  .scale_y
    inc  r10d
    cmp  r10d, 8
    jb   .col
    inc  r15d
    cmp  r15d, PBM_FACE_FONT_ROWS
    jb   .row
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; prepare_menu_console clears inherited GOP/console contents before any menu
; OutputString.  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.ClearScreen is method +48.
; EFI_STATUS is intentionally ignored so a null/refusing console cannot turn
; a recoverable serial-only Manager into a boot stop.
prepare_menu_console:
    mov  rax, [rel system_table]
    test rax, rax
    jz   .out
    mov  rcx, [rax + 64]              ; ConOut
    test rcx, rcx
    jz   .out
    mov  rax, [rcx + 48]              ; ClearScreen
    test rax, rax
    jz   .out
    lea  rdi, [rel str_clearscreen_before]
    call serial_string
    ; ConOut->ClearScreen through RAX: aligned from either caller parity.
    PBM_FW_ENTER 32
    call rax
    PBM_FW_LEAVE 32
    lea  rdi, [rel str_clearscreen_after]
    call serial_string
.out:
    ret

console_output:
    mov  rax, [rel system_table]
    test rax, rax
    jz   .out
    mov  rcx, [rax + 64]
    test rcx, rcx
    jz   .out
    mov  rax, [rcx + 8]              ; OutputString
    mov  rdx, rdi
    lea  rdi, [rel str_outputstring_before]
    call serial_string
    ; serial_string preserves RAX/RCX/RDX; ConOut->OutputString through RAX,
    ; aligned from either caller parity.
    PBM_FW_ENTER 32
    call rax
    PBM_FW_LEAVE 32
    cmp  byte [rel face_output_rendering], 1
    je   .out
    lea  rdi, [rel str_outputstring_after]
    call serial_string
.out:
    ret
%endif

; A selected payload that fails authentication or LoadImage before BIP is
; durably quarantined before policy chooses another identity. Rescue has no
; alternate digest slot; its failure is a visible stop.
record_prelaunch_invalid:
    push r12
    movzx edi, byte [rel selected_entry]
%ifdef PBM_FEATURE_EXTERNAL
    cmp  edi, PBM_ENTRY_WINDOWS
    je   .external
    cmp  edi, PBM_ENTRY_LINUX
    je   .external
%endif
    cmp  edi, PBM_ENTRY_PAOS_A
    jb   .stop
    cmp  edi, PBM_ENTRY_PAOS_B
    ja   .stop
    mov  rsi, [rel attempt_state_ptr]
    test rsi, rsi
    jz   .stop
    lea  rdi, [rel state_work]
    cmp  rsi, rdi
    je   .have_work
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
.have_work:
    lea  r12, [rel state_work]
    movzx edi, byte [rel selected_entry]
    call quarantine_work_slot
    mov  al, [rel selected_entry]
    cmp  al, [r12 + PBM_STATE_TRIAL_OFF]
    jne  .not_trial
    mov  [r12 + PBM_STATE_PREVIOUS_OFF], al
    mov  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    mov  byte [r12 + PBM_STATE_TRIES_LEFT_OFF], 0
.not_trial:
    mov  byte [r12 + PBM_STATE_BIP_OFF], 0
    call increment_work_failure
    call bind_work_manifest
    call journal_commit
    test eax, eax
    jnz  .fatal
    lea  rdi, [rel str_policy_prelaunch_quarantine]
    call serial_string
    xor  eax, eax
    jmp  .out
%ifdef PBM_FEATURE_EXTERNAL
.external:
    mov  rsi, [rel attempt_state_ptr]
    test rsi, rsi
    jz   .stop
    lea  rdi, [rel state_work]
    cmp  rsi, rdi
    je   .external_work
    mov  ecx, PBM_STATE_SIZE / 8
    rep  movsq
.external_work:
    lea  r12, [rel state_work]
    ; Payload validation or LoadImage refusal replaces the selected Pending
    ; only in this same durable commit, where INVALID_PAYLOAD becomes the retry
    ; representation and SHOW_NEXT provides the bounded verified-PaOS route.
    mov  byte [r12 + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    mov  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_NORMAL
    mov  al, [rel selected_entry]
    mov  [r12 + PBM_STATE_LAST_ENTRY_OFF], al
    mov  [r12 + PBM_STATE_EXTERNAL_ENTRY_OFF], al
    mov  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    mov  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_INVALID_PAYLOAD
    mov  qword [r12 + PBM_STATE_EXTERNAL_NONCE_OFF], 0
    mov  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    mov  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_EXTERNAL
    mov  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_INVALID_PAYLOAD
    mov  byte [r12 + PBM_STATE_MENU_POLICY_OFF], PBM_MENU_SHOW_NEXT
    call bind_work_manifest
    call journal_commit
    test eax, eax
    jnz  .fatal
    lea  rdi, [rel str_external_prelaunch_invalid]
    call serial_string
    mov  eax, 3
    jmp  .out
%endif
.stop:
    mov  eax, 2
    jmp  .out
.fatal:
    mov  byte [rel fatal_policy_failure], 1
    mov  eax, 1
.out:
    pop  r12
    ret

; Bounded A/B/Rescue authentication loop. Once StartImage is armed, its return
; sets fatal_policy_failure and the loop never tries a second identity.
launch_mutable_sequence:
    push rbx
    mov  ebx, 3
.try:
    movzx edi, byte [rel selected_entry]
    call launch_entry
    cmp  byte [rel fatal_policy_failure], 1
    je   .out
    call record_prelaunch_invalid
%ifdef PBM_FEATURE_EXTERNAL
    cmp  eax, 3
    je   .external_invalid
%endif
    test eax, eax
    jnz  .out
    dec  ebx
    jz   .out
    call select_mutable_policy
    test eax, eax
    jnz  .out
    jmp  .try
%ifdef PBM_FEATURE_EXTERNAL
.external_invalid:
    dec  ebx
    jz   .out
    call select_mutable_policy
    test eax, eax
    jnz  .out
    call present_menu_if_needed
    test eax, eax
    jnz  .out
    jmp  .try
%endif
.out:
    pop  rbx
    ret

%ifdef PBM_FEATURE_MANIFEST
; RCQ-29 live Try (try_media_launch, jumped to from efi_entry; never returns).
; Reached only after load_verify_manifest authenticated, under the compiled
; owner key, a manifest whose signed header carries PBM_MANIFEST_FLAG_TRY_MEDIA.
; The journal is never read or written, PaOSBootReady is neither consumed nor
; deleted, CMOS is neither imported nor cleared and no menu is shown, so this
; boot changes no persistent state at all.  The owner-signed default slot is
; verified and launched, then the other slot; Rescue is not tried (Try media
; carries no Rescue shim).  try_media_boot makes try_payload skip the durable
; attempt and prepare_handoff send TRY_MEDIA without MUTABLE_ATTEMPT/TRIAL,
; which also keeps PaOS's runtime-services publishers unmapped.
%include "bootmgr/try_current_boot.inc"

try_media_launch:
    ; G2: honoured only from the media itself (USB / removable), never from an
    ; internal ESP that a copied TRY manifest would turn into an untracked boot.
    call try_media_removable
    test eax, eax
    jz   .not_removable
    ; G1: the compiled revocation floor (no journal is trusted on Try media).
    mov  rax, [rel manifest + PBM_MANIFEST_SEQUENCE_OFF]
    mov  rcx, PBM_TRY_MIN_SEQUENCE
    cmp  rax, rcx
    jb   .revoked
    mov  byte [rel try_media_boot], 1
    lea  rdi, [rel str_try_media]
    call serial_string
    mov  qword [rel selected_state_ptr], 0
    mov  qword [rel attempt_state_ptr], 0
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_HEALTHY
    mov  byte [rel fallback_entry], PBM_ENTRY_NONE
    movzx edi, byte [rel manifest + 19]  ; signed default: A or B (manifest_struct_valid)
    mov  [rel selected_entry], dil
    call try_current_launch_entry
    cmp  byte [rel fatal_policy_failure], 1
    je   manager_stop
    movzx edi, byte [rel selected_entry]
    xor  edi, PBM_ENTRY_PAOS_A ^ PBM_ENTRY_PAOS_B
    call try_current_launch_entry
    jmp  manager_stop
.not_removable:                          ; a manifest refusal: nothing launched
    lea  rdi, [rel str_try_not_removable]
    call serial_string
    jmp  manager_stop
.revoked:
    lea  rdi, [rel str_try_revoked]
    call serial_string
    jmp  manager_stop

; try_media_removable -> EAX 1 when the Manager's OWN boot device (its LoadedImage
;   DeviceHandle; never boot_device_handle, which an external-volume scan may move)
;   is USB (a USB messaging node in its device path) or its BlockIo media reports
;   RemovableMedia; else 0 (no handle, no protocol, internal disk: refuse).
;   Preserves RBX; clobbers RAX, RCX, RDX, RSI, R8-R11.
try_media_removable:
    push rbx
    mov  rax, [rel self_loaded_image]
    test rax, rax
    jz   .no
    mov  rbx, [rax + 24]               ; EFI_LOADED_IMAGE_PROTOCOL.DeviceHandle
    test rbx, rbx
    jz   .no
    mov  qword [rel try_device_path], 0
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    lea  rdx, [rel device_path_guid]
    lea  r8, [rel try_device_path]
    PBM_FW_ENTER 32
    call [rax + 0x98]                  ; HandleProtocol(DevicePath)
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .block_io
    mov  rsi, [rel try_device_path]
    test rsi, rsi
    jz   .block_io
    xor  ecx, ecx                      ; bytes walked: bounded as resolve_boot_device
.node:
    cmp  byte [rsi], 0x7F              ; END
    je   .block_io
    cmp  byte [rsi], 0x03              ; MESSAGING_DEVICE_PATH
    jne  .next
    mov  al, [rsi + 1]
    cmp  al, 0x05                      ; MSG_USB_DP
    je   .yes
    cmp  al, 0x0F                      ; MSG_USB_CLASS_DP
    je   .yes
    cmp  al, 0x10                      ; MSG_USB_WWID_DP
    je   .yes
.next:
    movzx eax, word [rsi + 2]
    cmp  eax, 4
    jb   .block_io                     ; malformed: the path proves nothing
    add  ecx, eax
    cmp  ecx, 4096
    jae  .block_io
    add  rsi, rax
    jmp  .node
.block_io:
    mov  qword [rel try_block_io], 0
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    lea  rdx, [rel block_io_guid]
    lea  r8, [rel try_block_io]
    PBM_FW_ENTER 32
    call [rax + 0x98]                  ; HandleProtocol(BlockIo)
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .no
    mov  rax, [rel try_block_io]
    test rax, rax
    jz   .no
    mov  rax, [rax + 8]                ; EFI_BLOCK_IO_PROTOCOL.Media
    test rax, rax
    jz   .no
    cmp  byte [rax + 4], 0             ; EFI_BLOCK_IO_MEDIA.RemovableMedia
    je   .no
.yes:
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret
%endif
%endif

; manager_watchdog_set(ECX=seconds, 0 disarms) -> RAX=EFI_STATUS.
; Alignment-independent like preebs_wdt_set: callers' stack parity is not assumed.
manager_watchdog_set:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    mov  rax, [rel boot_services]
    mov  edx, PBM_WATCHDOG_CODE
    xor  r8d, r8d
    xor  r9d, r9d
    call [rax + 0x100]                ; SetWatchdogTimer
    mov  rsp, rbp
    pop  rbp
    ret

; launch_entry(EDI=entry) -> returns only when load/start fails.
launch_entry:
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    push rdi
    call r5_manager_launch_guard
    pop rdi
    test eax,eax
    jz .r5_entry_ok
    mov byte [rel fatal_policy_failure],1
    mov eax,1
    ret
.r5_entry_ok:
%endif
%endif
    ; R1: the child-launch flag is set only immediately before a child's
    ; LoadImage or PAX1 entry (try_payload). Every refusal before that point
    ; reaches manager_stop's finite EFI_ABORTED return, not its HLT.
    mov  r15d, edi
    lea  rdi, [rel str_stage_launch_entry]
    call serial_string
    mov  edi, r15d
    cmp  dil, [rel selected_entry]
    je   .profile_ready
    ; A pre-StartImage verification/load fallback is a new selection reason;
    ; keep the handoff and durable attempt truthful about that identity.
    mov  byte [rel selected_profile], PBM_PROFILE_NORMAL
    mov  byte [rel selected_reason], PBM_REASON_INVALID_PAYLOAD
    cmp  edi, PBM_ENTRY_RESCUE
    jne  .profile_ready
    mov  byte [rel selected_profile], PBM_PROFILE_RESCUE
.profile_ready:
    cmp  edi, PBM_ENTRY_PAOS_A
    je   .a
    cmp  edi, PBM_ENTRY_PAOS_B
    je   .b
%ifdef PBM_FEATURE_EXTERNAL
    cmp  edi, PBM_ENTRY_WINDOWS
    je   .external
    cmp  edi, PBM_ENTRY_LINUX
    je   .external
%endif
    lea  r13, [rel ucs2_rescue]
    mov  r14d, ucs2_rescue_end - ucs2_rescue
    lea  rdi, [rel str_try_rescue]
    jmp  try_payload
.a:
    lea  r13, [rel ucs2_slot_a]
    mov  r14d, ucs2_slot_a_end - ucs2_slot_a
    lea  rdi, [rel str_try_a]
    jmp  try_payload
.b:
    lea  r13, [rel ucs2_slot_b]
    mov  r14d, ucs2_slot_b_end - ucs2_slot_b
    lea  rdi, [rel str_try_b]
    jmp  try_payload
%ifdef PBM_FEATURE_EXTERNAL
.external:
    mov  edi, r15d
    call integrity_vault_select_entry
    test rax, rax
    jz   .missing
    lea  r13, [rax + 52]             ; owner-signed bounded UCS-2 path
    movzx r14d, word [rax + 48]
    inc  r14d
    shl  r14d, 1
    lea  rdi, [rel str_try_windows]
    cmp  r15d, PBM_ENTRY_WINDOWS
    je   try_payload
    lea  rdi, [rel str_try_linux]
    jmp  try_payload
.missing:
    ret
%endif

; try_payload: R13=UCS-2 path, R14D=byte length including NUL, R15D=entry ID.
; Returns only if LoadImage or StartImage failed.
try_payload:
    push rbx
    sub  rsp, 32
    call serial_string

%ifdef PBM_FEATURE_MANIFEST
%ifdef PBM_FEATURE_EXTERNAL
    cmp  r15d, PBM_ENTRY_WINDOWS
    jb   .volume_ready
    call select_external_volume
    test eax, eax
    jnz  .payload_invalid
    lea  rdi, [rel str_stage_volume_selected]
    call serial_string
.volume_ready:
%endif
    call verify_payload_file
    test eax, eax
    jz   .payload_verified
.payload_invalid:
    mov edi,1
    xor esi,esi
    call manager_image_refusal_record
    lea  rdi, [rel str_payload_invalid]
    call serial_string
    jmp  .out
.payload_verified:
    lea  rdi, [rel str_payload_valid]
    call serial_string
    lea  rdi, [rel str_stage_payload_verified]
    call serial_string
    PBM_STAGE 0x10D                    ; selected payload verified
%ifdef PBM_TEST_PRELAUNCH_SPIN
.prelaunch_spin:                     ; test-only hang; the watchdog must reset
    pause
    jmp  .prelaunch_spin
%endif
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .rescue_shim_ready
    call verify_rescue_shim
    test eax, eax
    jz   .rescue_shim_ready
    call free_verified_source_buffer
    jmp  .payload_invalid
.rescue_shim_ready:
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .direct_rescue_ready
    call direct_rescue_prepare       ; optional authenticated .pinitrd, no reread
    test eax, eax
    jz   .direct_rescue_ready
    lea  rdi, [rel str_payload_invalid]
    call serial_string
    jmp  .free                       ; unregister before freeing authenticated bytes
.direct_rescue_ready:

    ; PAX1 directly enters only the frozen PaOS A/B image shape.  Rescue is a
    ; separately signed GRUB/Linux EFI application: after the owner manifest
    ; has authenticated its bytes, let firmware LoadImage enforce Secure Boot
    ; on that PE instead of mis-parsing it as a PaOS PAX1 image.  External
    ; Windows/Linux peers use this same firmware-authenticated branch.
    cmp  r15d, PBM_ENTRY_RESCUE
    jb   .pax1_payload
    jne  .firmware_payload
%ifdef PBM_FEATURE_MANIFEST
    ; A first-stage shim >= 16.1 replaces gBS->LoadImage itself.  A nested
    ; shim 15.8 would load the UKI with its own loader, so that LoadImage never
    ; allowlists the UKI's sections and refuses systemd-stub's load of the
    ; unsigned embedded kernel (HP, 2026-10-17).  There the manifest-verified
    ; UKI buffer goes straight to the replaced LoadImage, which MOK-verifies it.
    call rescue_shim_loader_probe
    test eax, eax
    jnz  .firmware_payload
%endif
    ; Shim 15.8 MOK trust is not inherited by ordinary LoadImage.  Rescue's
    ; exact manifest-bound UKI must be launched by a separate signed shim,
    ; with its canonical path passed as bounded UTF-16 LoadOptions.
    lea  r13, [rel ucs2_rescue_shim]
    mov  r14d, ucs2_rescue_shim_end - ucs2_rescue_shim
    jmp  .firmware_payload
.pax1_payload:
%ifdef PBM_FEATURE_MUTABLE
    ; RCQ-29 S2(a): verify_payload_file has matched the signed container's
    ; path, entry, size, EOF and SHA-256 (verified_payload_sha stays that outer
    ; digest).  Only now restore "MZ" + 6 zero bytes over the envelope magic in
    ; the Manager-owned copy; bytes 8..15 are already zero (payload_pe_valid).
    cmp  byte [rel try_media_boot], 1
    jne  .pax1_unwrapped
    mov  rax, [rel verified_source_buffer]
    mov  qword [rax], 0x5A4D
.pax1_unwrapped:
%endif
    call pax1_prepare_verified_paos
    test rax, rax
    jnz  .pax1_invalid
    lea  rdi, [rel str_pax1_accepted]
    call serial_string
    lea  rdi, [rel str_stage_pax1_prepared]
    call serial_string
    lea  rdi, [rel str_child_load_base]
    call serial_string
    mov  rdi, [rel pax1_image_base]
    call serial_hex64
    lea  rdi, [rel str_child_load_base_tail]
    call serial_string
    call pax1_report_placement_size
%ifdef PBM_FEATURE_MENU
    call manager_gop_probe               ; before durable attempt; evidence only
    lea  rdi, [rel str_stage_gop_probed]
    call serial_string
%endif
%ifdef PBM_FEATURE_MUTABLE
    cmp  byte [rel try_media_boot], 1    ; RCQ-29 Try: no durable attempt, no write
    je   .pax1_try_media_handoff
    lea  rdi, [rel str_stage_attempt_arming]
    call serial_string
    call arm_selected_attempt
    test eax, eax
    jnz  .pax1_discard
.pax1_try_media_handoff:
%endif
    call prepare_handoff
%ifdef PBM_TEST_CORRUPT_ATTEMPT_HANDOFF
    xor  qword [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF], 1
%endif
%ifdef PBM_FEATURE_MUTABLE
    cmp  byte [rel try_media_boot], 1
    je   .pax1_handoff_ready
    call validate_attempt_handoff
    test eax, eax
    jnz  .pax1_discard
.pax1_handoff_ready:
%endif
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call dd_oracle_publish            ; U4b: PDH1 for the validated PBH1; never fails
%endif
%endif
    lea  rdi, [rel str_start]
    call serial_string
    lea  rdi, [rel str_pax1_direct]
    call serial_string
%ifdef PBM_TEST_PAX1_BRIDGE_REJECT
    xor  word [rel handoff + PBM_HANDOFF_VERSION_OFF], 0xFFFF   ; the bridge's version check refuses
%endif
    ; pax1_start_prepared_paos refuses an unprepared image (.not_ready). Check
    ; that here, before re-arming and flagging, so such a refusal stays a
    ; pre-child, finite return instead of an unbounded post-flag HLT.
    cmp  qword [rel pax1_entry_address], 0
    je   .pax1_not_ready
    cmp  qword [rel pax1_child_handle], 0
    je   .pax1_not_ready
    ; Re-arm (never disarm) to the PaOS budget: boot services stay live across
    ; the direct entry until PaOS's own arm, so no window runs unwatched (root
    ; 2026-10-08 20:09:57 (2)(b)). The StartImage path below does the same.
    mov  ecx, PBM_WATCHDOG_CHILD_SECONDS
    call manager_watchdog_set
    mov  byte [rel manager_launch_entered], 1
    call pax1_start_prepared_paos
    ; The bridge refuses its own ABI inputs BEFORE it enters the child, with
    ; boot services untouched: that is a pre-child refusal, so clear the flag,
    ; discard the prepared image and return finitely (F3, root 2026-10-09 17:56:41).
    cmp  byte [rel pax1_bridge_rejected], 0
    jne  .pax1_bridge_rejected
    ; The direct ABI defines every child return as a failed boot attempt. The
    ; child may already have exited BootServices, so retain the prepared image
    ; and stop without calling firmware cleanup services after its return.
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_start_returned]
    call serial_string
    lea  rdi, [rel str_pax1_returned]
    call serial_string
%ifdef PBM_TEST_LEGACY_TXN_CASE
%if (PBM_TEST_LEGACY_TXN_CASE = 12) || (PBM_TEST_LEGACY_TXN_CASE = 14)
    call legacy_txn_fixture_complete
%endif
%endif
    jmp  .out
.pax1_bridge_rejected:
    mov  byte [rel manager_launch_entered], 0
    lea  rdi, [rel str_pax1_bridge_rejected]
    call serial_string
.pax1_not_ready:
    ; A durable attempt may already be armed: no fallback may arm a second
    ; identity in this boot.
    mov  byte [rel fatal_policy_failure], 1
.pax1_discard:
    call pax1_discard_prepared_paos
    call pax1_release_verified_source
    jmp  .free
.pax1_invalid:
    mov edi,2
    xor esi,esi
    call manager_image_refusal_record
    lea  rdi, [rel str_pax1_invalid]
    call serial_string
    call pax1_report_placement_size
    call pax1_release_verified_source
    jmp  .free
%endif

.firmware_payload:
    mov  eax, [rel device_path_len]
    lea  edx, [eax + r14d + 8]
    mov  [rel composite_size], edx
    mov  rax, [rel boot_services]
    mov  ecx, 2                       ; EfiLoaderData
    lea  r8, [rel composite_path]
    PBM_FW_ENTER 32
    call [rax + 0x40]                 ; AllocatePool
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .free

    mov  rdi, [rel composite_path]
    mov  rsi, [rel device_path]
    mov  ecx, [rel device_path_len]
    rep movsb
    mov  byte [rdi], 0x04             ; MEDIA_DEVICE_PATH
    mov  byte [rdi + 1], 0x04         ; MEDIA_FILEPATH_DP
    lea  eax, [r14d + 4]
    mov  word [rdi + 2], ax
    add  rdi, 4
    mov  rsi, r13
    mov  ecx, r14d
    rep movsb
    mov  byte [rdi], 0x7F
    mov  byte [rdi + 1], 0xFF
    mov  word [rdi + 2], 4

    mov  qword [rel child_image], 0
    mov  rax, [rel boot_services]
%ifdef PBM_FEATURE_MANIFEST
    xor  ecx, ecx                     ; verified memory buffer, not boot-policy search
%else
    mov  ecx, 1                       ; development path-based boot policy
%endif
    mov  rdx, [rel image_handle]
    mov  r8, [rel composite_path]
%ifdef PBM_FEATURE_MANIFEST
    mov  r9, [rel verified_source_buffer]
%else
    xor  r9, r9
%endif
    PBM_FW_ENTER 48
%ifdef PBM_FEATURE_MANIFEST
    mov  r10d, [rel verified_payload_size]
    mov  [rsp + 32], r10
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .load_verified_buffer
    cmp  byte [rel rescue_direct_uki], 1
    je   .load_verified_buffer       ; shim >= 16.1 authenticates the UKI bytes
    xor  r9d, r9d                    ; firmware db authenticates the shim path
    mov  qword [rsp + 32], 0         ; shim then MOK-authenticates its UKI child
.load_verified_buffer:
%else
    mov  qword [rsp + 32], 0
%endif
    mov  qword [rel child_image], 0  ; failures may leave the output untouched
    lea  rbx, [rel child_image]
    mov  [rsp + 40], rbx
    mov  r11b, [rel manager_launch_entered]
    mov  [rel manager_load_prior_entered], r11b
    mov  byte [rel manager_launch_entered], 1   ; a firmware child may run from here on
    call [rax + 0xC8]                 ; LoadImage
    PBM_FW_LEAVE 48
    mov  rbx, rax
%ifdef PBM_FEATURE_MANIFEST
    cmp  qword [rel direct_initrd_address], 0
    jne  .source_held_for_initrd
    call free_verified_source_buffer
.source_held_for_initrd:
%endif
    test rbx, rbx
    jz   .firmware_loaded
    mov edi,3
    mov rsi,rbx
    call manager_image_refusal_record
    lea  rdi, [rel str_firmware_load_refused]
    call serial_string
    mov  rdi, rbx
    call serial_hex64
    lea  rdi, [rel str_firmware_load_refused_tail]
    call serial_string
    ; A failed NULL output adds no loaded image. Restore the pre-call guard:
    ; an earlier fallback may still own a nonNULL refused image. Its stop
    ; remains latched until that image has a qualified cleanup/return path.
    cmp  qword [rel child_image], 0
    jne  .free
    mov  al, [rel manager_load_prior_entered]
    mov  [rel manager_launch_entered], al
    jmp  .free
.firmware_loaded:

%ifdef PBM_FEATURE_EXTERNAL
    cmp  r15d, PBM_ENTRY_WINDOWS
    jae  .child_ready
%endif
    mov  rax, [rel boot_services]
    mov  rcx, [rel child_image]
    lea  rdx, [rel loaded_image_guid]
    lea  r8, [rel child_loaded_image]
    PBM_FW_ENTER 32
    call [rax + 0x98]                 ; HandleProtocol(child, LoadedImage)
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .free
    mov  rax, [rel child_loaded_image]
    lea  rdi, [rel str_child_load_base]
    call serial_string
    mov  rdi, [rax + 64]              ; EFI_LOADED_IMAGE_PROTOCOL.ImageBase
    call serial_hex64
    lea  rdi, [rel str_child_load_base_tail]
    call serial_string
.child_ready:
%ifdef PBM_FEATURE_MUTABLE
    lea  rdi, [rel str_stage_attempt_arming]
    call serial_string
    ; Load and inspect the child before claiming that a boot is in progress.
    ; From the durable commit through StartImage only local, non-failing
    ; handoff construction remains.
    cmp  byte [rel try_media_boot], 1    ; RCQ-29 Try: no durable attempt, no write
    je   .firmware_try_media_handoff
    call arm_selected_attempt
    test eax, eax
    jnz  .free
.firmware_try_media_handoff:
%endif
    call prepare_handoff
%ifdef PBM_TEST_CORRUPT_ATTEMPT_HANDOFF
    xor  qword [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF], 1
%endif
%ifdef PBM_FEATURE_MUTABLE
    cmp  byte [rel try_media_boot], 1
    je   .firmware_handoff_ready
    call validate_attempt_handoff
    test eax, eax
    jnz  .free
.firmware_handoff_ready:
%endif
%ifdef PBM_FEATURE_MANIFEST
    cmp  r15d, PBM_ENTRY_RESCUE
    je   .rescue_load_options
%endif
    cmp  r15d, PBM_ENTRY_RESCUE
    jae  .external_no_options
    mov  rax, [rel child_loaded_image]
    mov  dword [rax + 48], PBM_HANDOFF_SIZE
    lea  rbx, [rel handoff]
    mov  [rax + 56], rbx              ; LoadOptions pointer
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    call dd_oracle_publish            ; U4b: PDH1 for the validated PBH1; never fails
%endif
%endif
    jmp  .start_child
%ifdef PBM_FEATURE_MANIFEST
.rescue_load_options:
    mov  rax, [rel child_loaded_image]
    cmp  qword [rel direct_initrd_address], 0
    je   .ordinary_rescue_options
    call direct_rescue_set_options   ; native kernel or shim path + cmdline
    jmp  .start_child
.ordinary_rescue_options:
    cmp  byte [rel rescue_direct_uki], 1
    jne  .rescue_shim_options
    mov  dword [rax + 48], 0          ; the UKI runs its own signed .cmdline
    mov  qword [rax + 56], 0
    jmp  .start_child
.rescue_shim_options:
    mov  dword [rax + 48], ucs2_rescue_end - ucs2_rescue
    lea  rbx, [rel ucs2_rescue]
    mov  [rax + 56], rbx              ; shim selects verified full path
    jmp  .start_child
%endif
.external_no_options:
%ifdef PBM_FEATURE_EXTERNAL
    lea  rdi, [rel str_external_no_load_options]
    call serial_string
%endif
.start_child:

    lea  rdi, [rel str_start]
    call serial_string
    mov  ecx, PBM_WATCHDOG_CHILD_SECONDS  ; ordinary child convention
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    cmp byte [rel r5_manager_active],0
    je .r5_child_ordinary
    push rdi
    mov edi,r15d
    call r5_manager_launch_guard
    pop rdi
    test eax,eax
    jnz .r5_child_refused
    mov ecx,120                     ; R5 Rescue usable-or-explicit-failure ceiling
.r5_child_ordinary:
%endif
%endif
    call manager_watchdog_set
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    cmp byte [rel r5_manager_active],0
    je .r5_child_armed
    test rax,rax
    jnz .r5_child_refused           ; never silently continue an unbounded R5 child
    jmp .r5_child_armed
.r5_child_refused:
    mov byte [rel fatal_policy_failure],1
    mov eax,1
    jmp .out
.r5_child_armed:
%endif
%endif
%ifdef PBM_RESCUE_CAPTURE_NONCE
    cmp r15d,PBM_ENTRY_RESCUE
    jne .capture_not_rescue
    call capture_begin
    test eax,eax
    jz .capture_not_rescue
    mov byte [rel fatal_policy_failure],1
    jmp .free
.capture_not_rescue:
%endif
%ifdef PBM_FEATURE_EXTERNAL
    call external_launch_observe      ; observation only, preserves launch registers/flags
%endif
    mov  rax, [rel boot_services]
    mov  rcx, [rel child_image]
    xor  edx, edx
    xor  r8, r8
    ; The frozen PaOS A/B payloads require the historically proven legacy
    ; child-entry parity; Rescue and external EFI peers use the x64 ABI parity.
    ; Both are now pinned from either caller parity: the legacy variant reproduces
    ; the RSP = 8 mod 16 at the call that the frozen payloads were proven with
    ; (the old path without the extra `sub rsp, 8`); the gate allows only this call.
    cmp  r15d, PBM_ENTRY_RESCUE
    jb   .start_child_paos_legacy
    ; Diagnostic-only: the selected attempt and handoff are now validated,
    ; LoadOptions are installed and the child watchdog has been re-armed.
    ; This marker proves call intent, not execution inside the child.
    PBM_STAGE 0x10F
    PBM_FW_ENTER 32
    call [rax + 0xD0]                 ; StartImage (x64 ABI parity)
    PBM_FW_LEAVE 32
    PBM_STAGE 0x110                    ; firmware child returned; preserves EFI status
    jmp  .start_child_stack_restored
.start_child_paos_legacy:
    PAOS_NATIVE_TRACE 1          ; current-attempt call intent only
    PBM_FW_ENTER_LEGACY_CHILD
    call [rax + 0xD0]                 ; StartImage (frozen PaOS A/B legacy parity)
    PBM_FW_LEAVE_LEGACY_CHILD
    PAOS_NATIVE_TRACE 2          ; full returned status; never health
.start_child_stack_restored:
%ifdef PBM_RESCUE_CAPTURE_NONCE
    cmp r15d,PBM_ENTRY_RESCUE
    jne .capture_child_disarmed
    push rax
    call capture_tco_disarm
    pop rax
.capture_child_disarmed:
%endif
%ifdef PBM_FEATURE_MUTABLE
    ; Once a durable attempt exists, a child return is itself a failed attempt.
    ; Never overwrite that evidence by trying another identity in this boot.
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_start_returned]
    call serial_string
%ifdef PBM_TEST_LEGACY_TXN_CASE
%if (PBM_TEST_LEGACY_TXN_CASE = 1) || (PBM_TEST_LEGACY_TXN_CASE = 9) || (PBM_TEST_LEGACY_TXN_CASE = 10) || (PBM_TEST_LEGACY_TXN_CASE = 11) || (PBM_TEST_LEGACY_TXN_CASE = 14)
    call legacy_txn_fixture_complete
%endif
%endif
%endif
.free:
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
    push rax
    call dd_oracle_withdraw           ; U4b: no PDH1 outlives a launch that did not enter PaOS
    pop  rax
%endif
%endif
%ifdef PBM_FEATURE_MANIFEST
    call direct_rescue_cleanup
    test rax, rax
    jz   .direct_rescue_released
    mov  byte [rel fatal_policy_failure], 1
    mov  byte [rel manager_launch_entered], 1  ; existing stop, never return/free
    jmp  .out
.direct_rescue_released:
    call free_verified_source_buffer
%endif
    mov  rax, [rel composite_path]
    test rax, rax
    jz   .out
    mov  rcx, rax
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x48]                 ; FreePool
    PBM_FW_LEAVE 32
    mov  qword [rel composite_path], 0
.out:
    add  rsp, 32
    pop  rbx
    ret

prepare_handoff:
    lea  rdi, [rel handoff]
    mov  ecx, PBM_HANDOFF_SIZE / 8
    xor  eax, eax
    rep stosq
    mov  dword [rel handoff + PBM_HANDOFF_MAGIC_OFF], PBM_HANDOFF_MAGIC
    mov  word [rel handoff + PBM_HANDOFF_VERSION_OFF], PBM_CONTRACT_VERSION
    mov  word [rel handoff + PBM_HANDOFF_SIZE_OFF], PBM_HANDOFF_SIZE
    mov  qword [rel handoff + PBM_HANDOFF_MANAGER_SEQ_OFF], 1
%ifdef PBM_FEATURE_MANIFEST
    mov  rax, [rel trust_sequence]
    mov  [rel handoff + PBM_HANDOFF_MANAGER_SEQ_OFF], rax
    mov  rax, [rel selected_state_ptr]
    test rax, rax
    jz   .no_state_generation
    mov  rax, [rax + PBM_STATE_GENERATION_OFF]
    mov  [rel handoff + PBM_HANDOFF_STATE_GEN_OFF], rax
.no_state_generation:
    lea  rsi, [rel verified_payload_sha]
    lea  rdi, [rel handoff + PBM_HANDOFF_PAYLOAD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
%ifdef PBM_FEATURE_MENU
    cmp  byte [rel manager_gop_valid], 1
    jne  .no_gop_observation
    mov  dword [rel handoff + PBM_HANDOFF_GOP_TAG_OFF], PBM_HANDOFF_GOP_TAG
    mov  rax, [rel manager_gop_status]
    mov  [rel handoff + PBM_HANDOFF_GOP_STATUS_OFF], rax
.no_gop_observation:
%endif
%endif
%ifdef PBM_FEATURE_MUTABLE
    mov  rax, [rel current_attempt_nonce]
%else
    rdtsc
    shl  rdx, 32
    or   rax, rdx
%endif
    mov  [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF], rax
    mov  byte [rel handoff + PBM_HANDOFF_ENTRY_OFF], r15b
    mov  al, [rel selected_profile]
    mov  [rel handoff + PBM_HANDOFF_PROFILE_OFF], al
    mov  al, [rel selected_reason]
    mov  [rel handoff + PBM_HANDOFF_REASON_OFF], al
%ifdef PBM_TEST_SAFE_PROFILE
    mov  byte [rel handoff + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_SAFE
    mov  byte [rel handoff + PBM_HANDOFF_REASON_OFF], PBM_REASON_SAFE_RETRY
%endif
    mov  byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_MANAGER_LAUNCHED
%ifdef PBM_FEATURE_MUTABLE
    cmp  byte [rel try_media_boot], 1
    je   .try_media_flags
    or   byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_MUTABLE_ATTEMPT
%ifdef PBM_FEATURE_MENU
    cmp  byte [rel menu_visible], 1
    jne  .menu_flag_done
    or   byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_MENU_WAS_VISIBLE
.menu_flag_done:
%endif
    call handoff_trial_flag
    cmp  byte [rel b1_memtest_preselect], 1
    jne  .b1_safe_flag
    or   byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_B1_MEMTEST_PRESELECT
.b1_safe_flag:
    cmp  byte [rel b1_safe_video_launch], 1
    jne  .flags_done
    or   byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_B1_SAFE_VIDEO
    jmp  .flags_done
.try_media_flags:
    ; RCQ-29 Try: never MUTABLE_ATTEMPT/TRIAL/menu/B1 beside TRY_MEDIA, and a
    ; fresh nonce because no durable attempt (current_attempt_nonce) exists.
    or   byte [rel handoff + PBM_HANDOFF_FLAGS_OFF], PBM_HF_TRY_MEDIA
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF], rax
.flags_done:
%endif
    mov  al, [rel mfloor_state]
    mov  [rel handoff + PBM_HANDOFF_MFLOOR_OFF], al
    mov byte [rel handoff + PBM_HANDOFF_INIT_READER_OFF],PBM_INIT_GRAPH_VERSION
%ifdef PBM_FEATURE_MANIFEST
%ifdef PBM_FEATURE_FULL_POLICY
    call try_current_handoff
%endif
%endif
    lea  rdi, [rel handoff]
    mov  ecx, PBM_HANDOFF_CRC32
    call crc32
    mov  [rel handoff + PBM_HANDOFF_CRC32], eax
%ifdef PBM_TEST_CORRUPT_HANDOFF
    xor  dword [rel handoff + PBM_HANDOFF_CRC32], 1
%endif
    lea  rdi, [rel str_handoff_a]
    cmp  r15d, PBM_ENTRY_PAOS_A
    jne  .handoff_b
    cmp  byte [rel handoff + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_SAFE
    jne  .emit
    lea  rdi, [rel str_handoff_a_safe]
    jmp  .emit
.handoff_b:
    lea  rdi, [rel str_handoff_b]
    cmp  r15d, PBM_ENTRY_PAOS_B
    jne  .handoff_rescue
    cmp  byte [rel handoff + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_SAFE
    jne  .emit
    lea  rdi, [rel str_handoff_b_safe]
    jmp  .emit
.handoff_rescue:
    lea  rdi, [rel str_handoff_rescue]
    cmp  r15d, PBM_ENTRY_RESCUE
    je   .emit
%ifdef PBM_FEATURE_EXTERNAL
    lea  rdi, [rel str_handoff_windows]
    cmp  r15d, PBM_ENTRY_WINDOWS
    je   .emit
    lea  rdi, [rel str_handoff_linux]
%endif
.emit:
    call serial_string
    ret

; validate_attempt_handoff -> EAX=0 only when the exact durable attempt is what
; the child will receive. This closes the in-memory seam between the flushed
; journal record and StartImage. A no-state bootstrap is valid only for Rescue
; with state generation zero.
validate_attempt_handoff:
    mov  rax, [rel current_attempt_nonce]
    test rax, rax
    jz   .bad
    cmp  rax, [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF]
    jne  .bad
    mov  al, [rel handoff + PBM_HANDOFF_ENTRY_OFF]
    cmp  al, r15b
    jne  .bad
    mov  rax, [rel trust_sequence]
    cmp  rax, [rel handoff + PBM_HANDOFF_MANAGER_SEQ_OFF]
    jne  .bad
    lea  rdi, [rel handoff + PBM_HANDOFF_PAYLOAD_SHA_OFF]
    lea  rsi, [rel verified_payload_sha]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .bad

    mov  rdx, [rel selected_state_ptr]
    test rdx, rdx
    jz   .bootstrap
%ifdef PBM_FEATURE_EXTERNAL
    cmp  r15d, PBM_ENTRY_WINDOWS
    jae  .external_state
%endif
    mov  rax, [rel current_attempt_nonce]
    cmp  rax, [rdx + PBM_STATE_ATTEMPT_NONCE_OFF]
    jne  .bad
    mov  rax, [rdx + PBM_STATE_GENERATION_OFF]
    cmp  rax, [rel handoff + PBM_HANDOFF_STATE_GEN_OFF]
    jne  .bad
    mov  al, [rdx + PBM_STATE_LAST_ENTRY_OFF]
    cmp  al, [rel handoff + PBM_HANDOFF_ENTRY_OFF]
    jne  .bad
    mov  al, [rdx + PBM_STATE_LAST_PROFILE_OFF]
    cmp  al, [rel handoff + PBM_HANDOFF_PROFILE_OFF]
    jne  .bad
    mov  al, [rdx + PBM_STATE_LAST_REASON_OFF]
    cmp  al, [rel handoff + PBM_HANDOFF_REASON_OFF]
    jne  .bad
    jmp  .good
%ifdef PBM_FEATURE_EXTERNAL
.external_state:
    cmp  r15d, PBM_ENTRY_LINUX
    ja   .bad
    cmp  byte [rdx + PBM_STATE_BIP_OFF], 0
    jne  .bad
    cmp  byte [rdx + PBM_STATE_EXTERNAL_PENDING_OFF], 1
    jne  .bad
    mov  al, [rdx + PBM_STATE_EXTERNAL_ENTRY_OFF]
    cmp  al, r15b
    jne  .bad
    mov  rax, [rel current_attempt_nonce]
    cmp  rax, [rdx + PBM_STATE_EXTERNAL_NONCE_OFF]
    jne  .bad
    cmp  qword [rdx + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    mov  rax, [rdx + PBM_STATE_GENERATION_OFF]
    cmp  rax, [rel handoff + PBM_HANDOFF_STATE_GEN_OFF]
    jne  .bad
    mov  al, [rdx + PBM_STATE_LAST_ENTRY_OFF]
    cmp  al, [rel handoff + PBM_HANDOFF_ENTRY_OFF]
    jne  .bad
    cmp  byte [rdx + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_EXTERNAL
    jne  .bad
    mov  al, [rdx + PBM_STATE_LAST_REASON_OFF]
    cmp  al, [rel handoff + PBM_HANDOFF_REASON_OFF]
    jne  .bad
    jmp  .good
%endif
.bootstrap:
    cmp  r15d, PBM_ENTRY_RESCUE
    jne  .bad
    cmp  qword [rel handoff + PBM_HANDOFF_STATE_GEN_OFF], 0
    jne  .bad
    cmp  byte [rel handoff + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_RESCUE
    jne  .bad
.good:
    lea  rdi, [rel str_attempt_handoff_bound]
    call serial_string
    xor  eax, eax
    ret
.bad:
    mov  byte [rel fatal_policy_failure], 1
    lea  rdi, [rel str_attempt_handoff_mismatch]
    call serial_string
    mov  eax, 1
    ret

%include "bootmgr/image_refusal.inc"

; crc32(RDI=data, ECX=len) -> EAX IEEE CRC32.
crc32:
    push rbx
    push rdx
    mov  eax, 0xFFFFFFFF
.byte:
    test ecx, ecx
    jz   .done
    movzx edx, byte [rdi]
    xor  eax, edx
    mov  ebx, 8
.bit:
    mov  edx, eax
    and  edx, 1
    shr  eax, 1
    test edx, edx
    jz   .next_bit
    xor  eax, 0xEDB88320
.next_bit:
    dec  ebx
    jnz  .bit
    inc  rdi
    dec  ecx
    jmp  .byte
.done:
    not  eax
    pop  rdx
    pop  rbx
    ret

; pbm_bytes_differ(RDI=a, RSI=b, RDX=len) -> EAX=0 equal, 1 different.
; This early standalone Manager helper is deliberately namespaced and is not
; PaOS's canonical core/lib memory primitive.
pbm_bytes_differ:
    test rdx, rdx
    jz   .equal
.next_byte:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .different
    inc  rdi
    inc  rsi
    dec  rdx
    jnz  .next_byte
.equal:
    xor  eax, eax
    ret
.different:
    mov  eax, 1
    ret

; Crypto code is included with PAX1 below so its proven mixed-layout source can
; emit constants and writable scratch under honest PE permissions.

; Bounded COM1 first-light, independent of PaOS payload code.
serial_init:
    mov  dx, 0x3F9
    xor  al, al
    out  dx, al
    mov  dx, 0x3FB
    mov  al, 0x80
    out  dx, al
    mov  dx, 0x3F8
    mov  al, 1
    out  dx, al
    mov  dx, 0x3F9
    xor  al, al
    out  dx, al
    mov  dx, 0x3FB
    mov  al, 3
    out  dx, al
    mov  dx, 0x3FA
    mov  al, 0xC7
    out  dx, al
    mov  dx, 0x3FC
    mov  al, 0x0B
    out  dx, al
    ret

serial_char:
    push rax
    push rcx
    push rdx
    mov  ecx, 100000
.wait:
    mov  dx, 0x3FD
    in   al, dx
    test al, 0x20
    jnz  .ready
    dec  ecx
    jnz  .wait
    jmp  .out
.ready:
    mov  al, dil
    mov  dx, 0x3F8
    out  dx, al
.out:
    pop  rdx
    pop  rcx
    pop  rax
    ret

serial_string:
    push rax
    push rdi
.next:
    movzx eax, byte [rdi]
    test al, al
    jz   .done
    push rdi
    mov  dil, al
    call serial_char
    pop  rdi
    inc  rdi
    jmp  .next
.done:
    pop  rdi
    pop  rax
    ret

; pax1_loader is an independent Manager link unit with its own RSA scratch.
; These are its only two verifier call paths; this declared lock serializes the
; complete duplicate rather than relying on current UEFI call ordering.
pbm_rsa_verify_lock_acquire:
.spin:
    lock bts qword [rel pbm_rsa_verify_lock], 0
    jnc  .acquired
    pause
    jmp  .spin
.acquired:
    ret

pbm_rsa_verify_lock_release:
    mov  qword [rel pbm_rsa_verify_lock], 0
    ret

pbm_rsa2048_verify_sha256_locked:
    call pbm_rsa_verify_lock_acquire
    call rsa2048_verify_sha256
    call pbm_rsa_verify_lock_release
    ret

; serial_hex64(RDI=value) — bounded standalone Manager diagnostic.
serial_hex64:
    push rax
    push rbx
    push rcx
    push rdi
    mov  rbx, rdi
    mov  dil, '0'
    call serial_char
    mov  dil, 'x'
    call serial_char
    mov  ecx, 16
.nibble:
    rol  rbx, 4
    mov  eax, ebx
    and  al, 0x0F
    cmp  al, 10
    jb   .digit
    add  al, 'A' - 10
    jmp  .emit
.digit:
    add  al, '0'
.emit:
    mov  dil, al
    call serial_char
    loop .nibble
    pop  rdi
    pop  rcx
    pop  rbx
    pop  rax
    ret

%ifdef PBM_FEATURE_MANIFEST
; pax1_report_placement_size: one bounded line with the SizeOfImage the PAX1
; loader placed or tried to place; nothing when it refused before placement.
; Candidate diagnostic for firmware placement limits (root 2026-10-17 05:56).
pax1_report_placement_size:
    push rdi
    cmp  dword [rel pax1_placement_size], 0
    je   .out
    lea  rdi, [rel str_pax1_size]
    call serial_string
    mov  edi, [rel pax1_placement_size]
    call serial_hex64
    lea  rdi, [rel str_pax1_size_tail]
    call serial_string
    ; Firmware's AllocatePages answers, so a refusal names its cause on metal
    ; (Lenovo203 refused with no status, rc-target 2026-10-17 12:48).
    lea  rdi, [rel str_pax1_alloc]
    call serial_string
    mov  rdi, [rel pax1_alloc_status_1m]
    call serial_hex64
    lea  rdi, [rel str_pax1_alloc_max]
    call serial_string
    mov  rdi, [rel pax1_alloc_status_max]
    call serial_hex64
    lea  rdi, [rel str_pax1_alloc_base]
    call serial_string
    mov  rdi, [rel pax1_alloc_max_base]
    call serial_hex64
    lea  rdi, [rel str_pax1_alloc_tail]
    call serial_string
.out:
    pop  rdi
    ret
%endif

; PAX1 and the proven crypto instruction sequences remain in the RX section.
; The shared SHA-256 self-test's memcmp call binds to the namespaced early
; helper; crypto constants/scratch are emitted later by layout macros.
%define memcmp pbm_bytes_differ
%include "bootmgr/pax1_loader.asm"
%undef memcmp

%ifdef PBM_FEATURE_MANIFEST
%include "bootmgr/rescue_direct.inc"
%endif

%ifdef PBM_PLATFORM_HP_Q8
; Production profile binding, independent of manifest/descriptor authentication.
; Unknown SMBIOS is refused, rather than taking the kernel's HP-safe fallback.
manager_hp_platform_valid:
    push rbx
    push rsi
    push rdi
    xor  eax, eax
    cpuid
    cmp  ebx, 0x68747541             ; AuthenticAMD
    jne  .bad
    cmp  edx, 0x69746e65
    jne  .bad
    cmp  ecx, 0x444d4163
    jne  .bad
    mov  rax, [rel system_table]
    test rax, rax
    jz   .bad
    mov  rdi, [rax + SMB_EST_CFG]
    mov  rsi, [rax + SMB_EST_NUM]
    call smbios_identity_from_config
    test eax, eax
    jnz  .bad
    cmp  byte [rel smbios_hp_phase0], 1
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rdi
    pop  rsi
    pop  rbx
    ret

%endif
; R5 node/medium binding uses the same bounded SMBIOS parser on every platform.
%define SMBIOS_IDENTITY_CORE_ONLY 1
%include "boot/smbios.asm"
%undef SMBIOS_IDENTITY_CORE_ONLY
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
%include "bootmgr/recovery_controller.inc"
%include "bootmgr/dd_oracle.inc"
%include "bootmgr/silent_recovery_witness.inc"
%include "bootmgr/recovery_gesture_witness.inc"
%endif
%endif

%ifdef PBM_RESCUE_CAPTURE_NONCE
%include "bootmgr/rescue_capture.inc"
%endif

; Every raw boundary is also SectionAlignment-aligned. With this hand-written
; flat image, that preserves one RVA-to-file bias across mapped sections so
; all existing RIP-relative references retain their assembled displacement.
text_end:
text_size        equ text_end - code_start
text_file_size   equ (text_size + 0xFFF) & ~0xFFF
%ifndef PBM_MSI_COMBINED_OBJECT
times text_file_size - text_size db 0
%endif

; Define mutable storage here but emit it after the read-only region. This
; keeps related state declarations together without violating the PE oracle's
; ascending .text/.rdata/.data/.sbat section order.
%macro PBM_MUTABLE_DATA 0
PBM_IMAGE_REFUSAL_DATA
%ifdef PBM_FEATURE_MANIFEST
%ifdef PBM_FEATURE_FULL_POLICY
PBM_TRY_CURRENT_DATA
%endif
%endif
%ifdef PBM_RESCUE_CAPTURE_NONCE
PBM_CAPTURE_DATA
%endif
%ifdef PBM_FEATURE_MENU
PBM_USB_CONSOLE_DATA
%ifdef PBM_DIAG_INPUT
PBM_INPUT_DIAG_DATA
%endif
%endif
SBPROBE_MUTABLE
align 8
pbm_rsa_verify_lock: dq 0
; Modlint-visible domain name for pax1_loader's macro-emitted rsa_* scratch.
pbm_rsa_verify_scratch_domain: db 0
align 8
image_handle:       dq 0
system_table:       dq 0
boot_services:      dq 0
%ifdef PBM_FEATURE_EXTERNAL
%define PBM_EXTERNAL_OBSERVATION_DATA 1
%include "bootmgr/existing_os_observation.inc"
%undef PBM_EXTERNAL_OBSERVATION_DATA
%endif
runtime_services:   dq 0
%ifdef PBM_DIAG_ENTRY_NONCE
diag_current_record: dq 0
diag_read_size:     dq 32
diag_read_attrs:    dd 0
align 8
diag_readback:      times 32 db 0
%ifdef PBM_DIAG_STAGE_TRACE
; Written at every stage mark, so it must live here (writable .data), never in .rdata:
; a loader enforcing section permissions would fault on the first mark.
align 8
diag_stage_record:               ; the witness record; phase = the highest stage reached
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 0
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_stage_high:   dd 1          ; phase 1 = the entry witness itself
diag_stage_writes: db 0
align 8
%endif
%endif
self_loaded_image:  dq 0
child_loaded_image: dq 0
boot_device_handle: dq 0
device_path:        dq 0
device_path_len:    dd 0
composite_size:     dd 0
composite_path:     dq 0
child_image:        dq 0
simple_fs:          dq 0
boot_root:          dq 0
payload_root:       dq 0
%ifdef PBM_FEATURE_EXTERNAL
fs_handle_count:    dq 0
fs_handle_buffer:   dq 0
scan_original_root: dq 0
scan_original_handle: dq 0
scan_original_device_path: dq 0
scan_original_device_path_len: dd 0
external_volume_matches: db 0
align 8
selected_external_root: dq 0
selected_external_handle: dq 0
%endif
opened_file:        dq 0
read_size:          dq 0
tail_size:          dq 0
read_status:        dq 0
read_tail:          db 0
write_ok:           db 0
align 8
write_size:         dq 0
verify_size:        dq 0
verify_tail_size:   dq 0
selected_state_ptr: dq 0
attempt_state_ptr:  dq 0
selected_entry:     db PBM_ENTRY_RESCUE
fallback_entry:     db PBM_ENTRY_NONE
selected_profile:   db PBM_PROFILE_RESCUE
selected_reason:    db PBM_REASON_INVALID_STATE
state0_valid:       db 0
state1_valid:       db 0
manifest_verified:  db 0
recovery_descriptor_verified: db 0
payload_verify_ok:  db 0
verified_payload_entry: db 0
align 8
payload_read_size:  dq 0
payload_bytes_read: dd 0
verified_payload_size: dd 0
verified_source_buffer: dq 0
rescue_shim_buffer: dq 0
rescue_shim_sha: times 32 db 0
current_attempt_nonce: dq 0
trust_sequence:     dq 0
try_device_path:    dq 0                 ; RCQ-29 G2: the Manager's own device path / BlockIo
try_block_io:       dq 0
fatal_policy_failure: db 0
try_media_boot:     db 0                 ; RCQ-29: owner-signed TRY_MEDIA manifest on the boot volume
manager_launch_entered: db 0
manager_load_prior_entered: db 0
pax1_bridge_rejected: db 0        ; set only by the bridge's pre-entry .reject
health_consumed:    db 0
health_checked:     db 0
policy_abnormal:    db 0
power_rescue_due:   db 0
failed_entry:       db PBM_ENTRY_NONE
b1_evidence_kind:   db PBM_B1_EVIDENCE_NONE
b1_evidence_entry:  db PBM_ENTRY_NONE
b1_apply_result:    db 0
b1_safe_video_claimed: db 0
b1_safe_video_identity_ok: db 0
b1_safe_video_launch: db 0
b1_memtest_preselect: db 0
%ifdef PBM_FEATURE_MANIFEST
rescue_direct_uki:  db 0                 ; 1: shim >= 16.1 LoadImage takes the verified UKI
align 8
rescue_shim_loader_proto: dq 0
%endif
%ifdef PBM_FEATURE_MENU
menu_visible:       db 0
menu_timeout:       db PBM_MENU_TIMEOUT_DEFAULT
menu_remaining:     db PBM_MENU_TIMEOUT_DEFAULT
face_countdown_graphics: db 0
align 4
face_countdown_row: dd -1
menu_input_key:     dw 0, 0
menu_cursor_key:    db 0                ; tentative lowercase key, zero=boot default
menu_initial_char:  dw 0
menu_show_after_blind: db 0
menu_active_entry:  db PBM_ENTRY_NONE
menu_standby_entry: db PBM_ENTRY_NONE
menu_show_active:   db 0
menu_show_standby:  db 0
menu_show_safe:     db 0
menu_show_rescue:   db 0
menu_rescue_chosen: db 0                ; owner pressed R in this boot (arm_selected_attempt)
menu_show_windows:  db 0
menu_show_linux:    db 0
face_compact:       db 0               ; 0=2x, 1=native-size compact graphical face
; Lowercase hotkey and relative availability-byte offset, in rendered order.
menu_nav_rows: db 'p',menu_show_active-menu_show_active, 'o',menu_show_standby-menu_show_active, 's',menu_show_safe-menu_show_active, 'r',menu_show_rescue-menu_show_active, 'w',menu_show_windows-menu_show_active, 'l',menu_show_linux-menu_show_active
face_cursor_marker: db '> ',0
face_ascii_frame:   db 0
face_rtc_reads:     db 0
face_rtc_writes:    db 0
face_clock_warning_pending: db 0
face_output_rendering: db 0
face_efi_time:      times 16 db 0
align 8
face_monotonic_us:  dq 0
face_wall_offset_us: dq 0
face_gop_proto:     dq 0
manager_gop_proto:  dq 0
manager_gop_status: dq -1
manager_gop_valid:  db 0
face_fb_base:       dq 0
face_fb_width:      dd 0
face_fb_height:     dd 0
face_fb_stride:     dd 0
face_fb_format:     dd 0
face_layout_x:      dd 0
face_layout_y:      dd 0
face_timeout_ascii: db '0','0',0
face_countdown_padding: db ' ',0
align 2
face_console_ucs2:  times (PBM_FACE_FRAME_CHARS + 1) dw 0
%endif
align 8
health_size:        dq PBM_HEALTH_SIZE
health_attributes:  dd 0
b1_io_size:         dq 128
b1_io_attrs:        dd 0
b1_evidence_fingerprint: dd 0
align 8
b1_evidence_nonce:  dq 0
b1_inspect_state_ptr: dq 0
b1_evidence_sha:    times 32 db 0
b1_health_vector:   times PBM_B1_MH_SIZE db 0
b1_init_record:     times PBM_INIT_RECORD_SIZE db 0
align 8
state0:             times PBM_STATE_SIZE db 0
state1:             times PBM_STATE_SIZE db 0
state_work:         times PBM_STATE_SIZE db 0
state_verify:       times PBM_STATE_SIZE db 0
manifest:           times PBM_MANIFEST_SIZE db 0
recovery_descriptor: times PBM_RECOVERY_SIZE db 0
handoff:            times PBM_HANDOFF_SIZE db 0
payload_sha_ctx:    times S256_CTX_SZ db 0
verified_payload_sha: times 32 db 0
verified_manifest_sha: times 32 db 0
health_record:      times PBM_HEALTH_SIZE db 0
align 8
mfloor_blob:        times 64 db 0
mfloor_new:         times 64 db 0
mfloor_size:        dq 0
mfloor_attrs:       dd 0
mfloor_state:       db 0

; PAX1 preparation state and the synthetic LoadedImage protocol used solely
; to preserve today's PaOS pre-EBS compatibility seam.
align 8
pax1_image_base:       dq 0
pax1_image_pages:      dq 0
pax1_entry_address:    dq 0
pax1_child_handle:     dq 0
pax1_alloc_status_1m:  dq 0              ; AllocatePages status at 1 MiB (-1 not attempted)
pax1_alloc_status_max: dq 0              ; fallback AllocateMaxAddress status (-1 not attempted)
pax1_alloc_max_base:   dq 0              ; base the fallback returned (0 = none)
pax1_placement_size:   dd 0              ; SizeOfImage once the profile passed
pax1_loaded_image:     times 96 db 0
%endmacro

%ifdef PBM_MSI_COMBINED_OBJECT
section .pbmrdat align=16
%endif
rdata_start:

PBM_CRYPTO_RDATA
%ifdef PBM_FEATURE_MANIFEST
%ifdef PBM_FEATURE_FULL_POLICY
PBM_TRY_CURRENT_RDATA
%endif
%endif
SBPROBE_RDATA

%ifdef PBM_OWNER_KEY
%include "pbm-owner-key.inc"
%endif
%ifdef PBM_RESCUE_KEY
%include "pbm-rescue-key.inc"                  ; K19: pbm_rescue_modulus / pbm_rescue_key_id
%endif

loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B
%ifdef PBM_FEATURE_MANIFEST
shim_image_loader_guid:                 ; 1f492041-fadb-4e59-9e57-7cafe73a55ab (shim >= 16.1)
    dd 0x1F492041
    dw 0xFADB, 0x4E59
    db 0x9E,0x57,0x7C,0xAF,0xE7,0x3A,0x55,0xAB
%endif
block_io_guid:                          ; 964e5b21-6459-11d2-8e39-00a0c969723b (RCQ-29 G2)
    dd 0x964E5B21
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
%ifdef PBM_DIAG_ENTRY_NONCE
; d9e0b7ac-86c9-481b-97dd-355f57b0c263, diagnostic namespace only.
diag_var_guid:
    dd 0xD9E0B7AC
    dw 0x86C9, 0x481B
    db 0x97,0xDD,0x35,0x5F,0x57,0xB0,0xC2,0x63
diag_var_name:
    dw 'P','a','O','S','M','g','r','D','i','a','g',0
align 8
diag_record:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 1                         ; phase=Manager entry, pre-manifest
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_STAGE_TRACE
%ifdef PBM_DIAG_PRESELECT_TRACE
str_preselect_trace_build: db "[PBM] DIAGNOSTIC preselection trace; ordinary signed policy continues [boot.v2.diag.preselect-trace]",13,10,0
%endif
str_stage_trace_build: db "[PBM] DIAGNOSTIC stage-trace build: PaOSMgrDiag phase = highest stage 0x101..0x110 [boot.v2.diag.stage-trace]",13,10,0
%endif
%ifdef PBM_DIAG_PREHEALTH_TRACE
diag_trace_2:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 2                         ; boot-device resolved
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_3:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 3                         ; boot-device refused
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_4:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 4                         ; boot volume opened
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_5:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 5                         ; boot volume refused
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_6:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 6                         ; manifest verified
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_7:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 7                         ; manifest refused
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_8:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 8                         ; initial policy load returned successfully
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_9:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 9                         ; initial policy load returned error
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_HEALTH_INSPECT_TRACE
diag_trace_10:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 10                        ; read-only B1 evidence inspection returned
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_HEALTH_CONSUME_TRACE
diag_trace_11:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 11                        ; BootReady absent before compact consume
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_12:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 12                        ; compact health returned without consumption
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_13:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 13                        ; BootReady present/unknown: refused
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_CMOS_PEEK_TRACE
diag_trace_14:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 14                        ; B1 apply/external reconciliation returned
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_20:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 20                        ; CMOS one-shot value 0
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_21:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 21                        ; CMOS one-shot value 1 (Windows)
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_22:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 22                        ; CMOS one-shot value 2 (Linux)
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_23:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 23                        ; CMOS one-shot value 3 (Rescue)
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_24:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 24                        ; CMOS one-shot value outside 0..3
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_CMOS_IMPORT_REFUSAL
diag_trace_25:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 25                        ; absent Windows row; before actual import
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_26:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 26                        ; actual import refused, CMOS1 retained
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_27:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 27                        ; Windows row present; importer not entered
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_trace_28:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 28                        ; unexpected importer outcome
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%endif
%endif
%endif
%endif
%endif
%ifdef PBM_DIAG_RESOLVE_ONLY
diag_record_resolve_ok:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 2                         ; boot-device resolver returned success
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_record_resolve_error:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 3                         ; boot-device resolver returned error
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_VOLUME_ONLY
diag_record_volume_ok:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 4                         ; SimpleFileSystem OpenVolume success
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_record_volume_error:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 5                         ; SimpleFileSystem OpenVolume error
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%ifdef PBM_DIAG_MANIFEST_ONLY
diag_record_manifest_ok:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 6                         ; owner-signed manifest verified
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
diag_record_manifest_error:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 7                         ; manifest read/signature refusal
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%endif
%endif
%endif
%ifdef PBM_DIAG_STOP_AFTER_POLICY
diag_record_phase2:
    db 'P','M','G','R','D','0','0','1'
    dq PBM_DIAG_ENTRY_NONCE
    dq 2                         ; selected trial B, before attempt journal
    dq PBM_DIAG_ENTRY_NONCE ^ 0xFFFFFFFFFFFFFFFF
%endif
%endif
device_path_guid:
%ifdef PBM_DIAG_BAD_DEVICE_PATH_GUID
    dd 0xFFFFFFFF                ; resolver error negative control only
%else
    dd 0x09576E91
%endif
    dw 0x6D3F, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
simple_fs_guid:
%ifdef PBM_DIAG_BAD_SIMPLE_FS_GUID
    dd 0xFFFFFFFF                ; SimpleFS refusal negative control only
%else
    dd 0x964E5B22
%endif
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
%ifdef PBM_FEATURE_MENU
face_gop_guid:
    dd 0x9042A9DE
    dw 0x23DC, 0x4A38
    db 0x96,0xFB,0x7A,0xDE,0xD0,0x80,0x51,0x6A
manager_gop_guid:
    dd 0x9042A9DE
    dw 0x23DC, 0x4A38
    db 0x96,0xFB,0x7A,0xDE,0xD0,0x80,0x51,0x6A
%endif
; c4a7c2f1-4bb5-4ae8-9c4f-6f76f7c2a051 (EFI mixed-endian GUID layout)
health_var_guid:
    dd 0xC4A7C2F1
    dw 0x4BB5, 0x4AE8
    db 0x9C,0x4F,0x6F,0x76,0xF7,0xC2,0xA0,0x51
health_var_name:
    dw 'P','a','O','S','B','o','o','t','R','e','a','d','y',0
mfloor_var_name:
    dw 'P','a','O','S','M','a','n','i','f','e','s','t','F','l','o','o','r',0
; 9d783c42-4cf3-44e8-a996-86a384c24ec1 (Task1224 telemetry namespace)
b1_telemetry_var_guid:
    dd 0x9D783C42
    dw 0x4CF3, 0x44E8
    db 0xA9,0x96,0x86,0xA3,0x84,0xC2,0x4E,0xC1
b1_health_vector_name:
    dw 'P','a','O','S','H','e','a','l','t','h','V','e','c','t','o','r',0
; 7a965d12-c839-4a77-b1e2-906ef724438c (checkpoint namespace)
b1_init_var_guid:
    dd 0x7A965D12
    dw 0xC839, 0x4A77
    db 0xB1,0xE2,0x90,0x6E,0xF7,0x24,0x43,0x8C
b1_init_var_name:
    dw 'P','a','O','S','I','n','i','t','C','h','e','c','k','p','o','i','n','t',0

ucs2_slot_a:
    dw '\','E','F','I','\','P','a','O','S','\','s','l','o','t','s','\','p','a','o','s','-','a','.','e','f','i',0
ucs2_slot_a_end:
ucs2_slot_b:
    dw '\','E','F','I','\','P','a','O','S','\','s','l','o','t','s','\','p','a','o','s','-','b','.','e','f','i',0
ucs2_slot_b_end:
ucs2_rescue:
    dw '\','E','F','I','\','P','a','O','S','\','r','e','s','c','u','e','\','p','a','o','s','-','r','e','s','c','u','e','.','e','f','i',0
ucs2_rescue_end:
ucs2_rescue_shim:
    dw '\','E','F','I','\','P','a','O','S','\','r','e','s','c','u','e','\','s','h','i','m','x','6','4','.','e','f','i',0
ucs2_rescue_shim_end:
ucs2_state0:
    dw '\','E','F','I','\','P','a','O','S','\','s','t','a','t','e','\','s','t','a','t','e','0','.','b','i','n',0
ucs2_state1:
    dw '\','E','F','I','\','P','a','O','S','\','s','t','a','t','e','\','s','t','a','t','e','1','.','b','i','n',0
ucs2_manifest:
    dw '\','E','F','I','\','P','a','O','S','\','v','a','u','l','t','\','m','a','n','i','f','e','s','t','.','b','i','n',0
ucs2_recovery_descriptor:
    dw '\','E','F','I','\','P','a','O','S','\','r','e','s','c','u','e','\','r','e','s','c','u','e','-','d','e','s','c','r','i','p','t','o','r','.','b','i','n',0

%ifdef PBM_FEATURE_MENU
ucs2_face_empty: dw 0
ucs2_face_clock_warning:
    dw 'W','a','r','n','i','n','g',':',' ','s','y','s','t','e','m',' ','c','l','o','c','k',' ','i','s',' ','o','u','t','s','i','d','e',' ','t','h','e',' ','u','s','a','b','l','e',' ','r','a','n','g','e',';',' ','b','o','o','t',' ','w','i','l','l',' ','c','o','n','t','i','n','u','e','.',13,10,0
face_title:          db "PaOS Boot Manager 0.1",0
face_ascii_top:      db "+-- PaOS Boot Manager 0.1 "
                     times 23 db "-"
                     db "+",0
face_ascii_bottom:   db "+"
                     times 48 db "-"
                     db "+",0
face_pipe:           db "|",0
face_entry_active:   db "P - PaOS",0
face_entry_standby:  db "O - PaOS (previous version)",0
face_entry_safe:     db "S - Safe Mode",0
face_entry_rescue:   db "R - PaOS Rescue",0
face_entry_windows:  db "W - Windows",0
face_entry_linux:    db "L - Linux",0
face_footer_prefix:  db "Starting PaOS in ",0
face_footer_suffix:  db "s - press a key for options",0
face_hint_p:         db "P",0
face_hint_o:         db "/O",0
face_hint_s:         db "/S",0
face_hint_r:         db "/R",0
face_hint_w:         db "/W",0
face_hint_l:         db "/L",0
face_hint_suffix:    db " select | D Details",0
face_reason_requested: db "Why: menu requested.",0
face_reason_trial:     db "Why: update trial.",0
face_reason_previous_bip: db "Why: unfinished boot.",0
face_reason_safe:      db "Why: Safe retry.",0
face_reason_rollback:  db "Why: PaOS rollback.",0
face_reason_state:     db "Why: no valid state.",0
face_reason_payload:   db "Why: image unverified.",0
face_reason_rescue:    db "Why: recovery selected.",0
face_reason_attention: db "Why: needs attention.",0
face_console_newline: db 13,10,0
face_month_days:     db 31,28,31,30,31,30,31,31,30,31,30,31

; Spleen 8x16 glyphs (BSD-2-Clause, (c) 2018-2024 Frederic Cambus; release 2.1.0;
; see THIRD_PARTY_NOTICES.md). The settled face uses only U+0020..U+007E; the
; full ASCII block is kept so control bytes and U+007F are deterministic blanks.
face_ocr_font:
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0000
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0001
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0002
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0003
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0004
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0005
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0006
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0007
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0008
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0009
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+000a
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+000b
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+000c
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+000d
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+000e
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+000f
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0010
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0011
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0012
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0013
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0014
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0015
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0016
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0017
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0018
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0019
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+001a
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+001b
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+001c
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+001d
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+001e
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+001f
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0020
    db 0x00,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00 ; U+0021
    db 0x00,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0022
    db 0x00,0x00,0x6c,0x6c,0xfe,0x6c,0x6c,0x6c,0x6c,0xfe,0x6c,0x6c,0x00,0x00,0x00,0x00 ; U+0023
    db 0x00,0x10,0x7e,0xd0,0xd0,0xd0,0x7c,0x16,0x16,0x16,0x16,0xfc,0x10,0x00,0x00,0x00 ; U+0024
    db 0x00,0x00,0x06,0x66,0x6c,0x0c,0x18,0x18,0x30,0x36,0x66,0x60,0x00,0x00,0x00,0x00 ; U+0025
    db 0x00,0x00,0x38,0x6c,0x6c,0x6c,0x38,0x70,0xda,0xcc,0xcc,0x7a,0x00,0x00,0x00,0x00 ; U+0026
    db 0x00,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0027
    db 0x00,0x0e,0x18,0x30,0x30,0x60,0x60,0x60,0x60,0x30,0x30,0x18,0x0e,0x00,0x00,0x00 ; U+0028
    db 0x00,0x70,0x18,0x0c,0x0c,0x06,0x06,0x06,0x06,0x0c,0x0c,0x18,0x70,0x00,0x00,0x00 ; U+0029
    db 0x00,0x00,0x00,0x00,0x66,0x3c,0x18,0xff,0x18,0x3c,0x66,0x00,0x00,0x00,0x00,0x00 ; U+002a
    db 0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x7e,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00 ; U+002b
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00 ; U+002c
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+002d
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00 ; U+002e
    db 0x00,0x06,0x06,0x0c,0x0c,0x18,0x18,0x30,0x30,0x60,0x60,0xc0,0xc0,0x00,0x00,0x00 ; U+002f
    db 0x00,0x00,0x7c,0xc6,0xc6,0xce,0xde,0xf6,0xe6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0030
    db 0x00,0x00,0x18,0x38,0x78,0x58,0x18,0x18,0x18,0x18,0x18,0x7e,0x00,0x00,0x00,0x00 ; U+0031
    db 0x00,0x00,0x7c,0xc6,0x06,0x06,0x0c,0x18,0x30,0x60,0xc6,0xfe,0x00,0x00,0x00,0x00 ; U+0032
    db 0x00,0x00,0x7c,0xc6,0x06,0x06,0x3c,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0033
    db 0x00,0x00,0xc0,0xc0,0xcc,0xcc,0xcc,0xcc,0xfe,0x0c,0x0c,0x0c,0x00,0x00,0x00,0x00 ; U+0034
    db 0x00,0x00,0xfe,0xc6,0xc0,0xc0,0xfc,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0035
    db 0x00,0x00,0x7c,0xc6,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0036
    db 0x00,0x00,0xfe,0xc6,0x06,0x06,0x0c,0x18,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00 ; U+0037
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0x7c,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0038
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0039
    db 0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00 ; U+003a
    db 0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00 ; U+003b
    db 0x00,0x00,0x06,0x0c,0x18,0x30,0x60,0x60,0x30,0x18,0x0c,0x06,0x00,0x00,0x00,0x00 ; U+003c
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+003d
    db 0x00,0x00,0x60,0x30,0x18,0x0c,0x06,0x06,0x0c,0x18,0x30,0x60,0x00,0x00,0x00,0x00 ; U+003e
    db 0x00,0x00,0x7c,0xc6,0x06,0x0c,0x18,0x30,0x30,0x00,0x30,0x30,0x00,0x00,0x00,0x00 ; U+003f
    db 0x00,0x00,0x00,0x7c,0xc2,0xda,0xda,0xda,0xda,0xde,0xc0,0x7c,0x00,0x00,0x00,0x00 ; U+0040
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0041
    db 0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xfc,0xc6,0xc6,0xc6,0xc6,0xfc,0x00,0x00,0x00,0x00 ; U+0042
    db 0x00,0x00,0x7e,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+0043
    db 0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xfc,0x00,0x00,0x00,0x00 ; U+0044
    db 0x00,0x00,0x7e,0xc0,0xc0,0xc0,0xf8,0xc0,0xc0,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+0045
    db 0x00,0x00,0x7e,0xc0,0xc0,0xc0,0xf8,0xc0,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00 ; U+0046
    db 0x00,0x00,0x7e,0xc0,0xc0,0xc0,0xde,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0047
    db 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0048
    db 0x00,0x00,0x7e,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7e,0x00,0x00,0x00,0x00 ; U+0049
    db 0x00,0x00,0x7e,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0xf0,0x00,0x00,0x00,0x00 ; U+004a
    db 0x00,0x00,0xc6,0xc6,0xc6,0xcc,0xf8,0xcc,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+004b
    db 0x00,0x00,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+004c
    db 0x00,0x00,0xc6,0xee,0xfe,0xd6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+004d
    db 0x00,0x00,0xc6,0xc6,0xe6,0xe6,0xd6,0xd6,0xce,0xce,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+004e
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+004f
    db 0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xfc,0xc0,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00 ; U+0050
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xd6,0xd6,0x7c,0x18,0x0c,0x00,0x00 ; U+0051
    db 0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0052
    db 0x00,0x00,0x7e,0xc0,0xc0,0xc0,0x7c,0x06,0x06,0x06,0x06,0xfc,0x00,0x00,0x00,0x00 ; U+0053
    db 0x00,0x00,0xff,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00 ; U+0054
    db 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0055
    db 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x10,0x00,0x00,0x00,0x00 ; U+0056
    db 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xd6,0xfe,0xee,0xc6,0x00,0x00,0x00,0x00 ; U+0057
    db 0x00,0x00,0xc6,0xc6,0xc6,0x6c,0x38,0x6c,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0058
    db 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0x06,0x06,0xfc,0x00,0x00,0x00,0x00 ; U+0059
    db 0x00,0x00,0xfe,0x06,0x06,0x0c,0x18,0x30,0x60,0xc0,0xc0,0xfe,0x00,0x00,0x00,0x00 ; U+005a
    db 0x00,0x3e,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3e,0x00,0x00,0x00 ; U+005b
    db 0x00,0xc0,0xc0,0x60,0x60,0x30,0x30,0x18,0x18,0x0c,0x0c,0x06,0x06,0x00,0x00,0x00 ; U+005c
    db 0x00,0x7c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x7c,0x00,0x00,0x00 ; U+005d
    db 0x00,0x10,0x38,0x6c,0xc6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+005e
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x00 ; U+005f
    db 0x00,0x30,0x18,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0060
    db 0x00,0x00,0x00,0x00,0x00,0x7c,0x06,0x7e,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0061
    db 0x00,0x00,0xc0,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xfc,0x00,0x00,0x00,0x00 ; U+0062
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc0,0xc0,0xc0,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+0063
    db 0x00,0x00,0x06,0x06,0x06,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0064
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xfe,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+0065
    db 0x00,0x00,0x1e,0x30,0x30,0x30,0x7c,0x30,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00 ; U+0066
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x06,0x06,0xfc,0x00 ; U+0067
    db 0x00,0x00,0xc0,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0068
    db 0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x1c,0x00,0x00,0x00,0x00 ; U+0069
    db 0x00,0x00,0x18,0x18,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x70,0x00 ; U+006a
    db 0x00,0x00,0xc0,0xc0,0xc0,0xcc,0xd8,0xf0,0xf0,0xd8,0xcc,0xc6,0x00,0x00,0x00,0x00 ; U+006b
    db 0x00,0x00,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x1c,0x00,0x00,0x00,0x00 ; U+006c
    db 0x00,0x00,0x00,0x00,0x00,0xec,0xd6,0xd6,0xd6,0xd6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+006d
    db 0x00,0x00,0x00,0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+006e
    db 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+006f
    db 0x00,0x00,0x00,0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xfc,0xc0,0xc0,0xc0,0x00 ; U+0070
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0x06,0x00 ; U+0071
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc0,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00 ; U+0072
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc0,0xc0,0x7c,0x06,0x06,0xfc,0x00,0x00,0x00,0x00 ; U+0073
    db 0x00,0x00,0x30,0x30,0x30,0x7c,0x30,0x30,0x30,0x30,0x30,0x1e,0x00,0x00,0x00,0x00 ; U+0074
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0075
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x10,0x00,0x00,0x00,0x00 ; U+0076
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xd6,0xd6,0xd6,0xd6,0x6e,0x00,0x00,0x00,0x00 ; U+0077
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0x6c,0x38,0x38,0x6c,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0078
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0xfc,0x00 ; U+0079
    db 0x00,0x00,0x00,0x00,0x00,0xfe,0x06,0x0c,0x18,0x30,0x60,0xfe,0x00,0x00,0x00,0x00 ; U+007a
    db 0x00,0x0e,0x18,0x18,0x18,0x18,0x70,0x70,0x18,0x18,0x18,0x18,0x0e,0x00,0x00,0x00 ; U+007b
    db 0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00 ; U+007c
    db 0x00,0x70,0x18,0x18,0x18,0x18,0x0e,0x0e,0x18,0x18,0x18,0x18,0x70,0x00,0x00,0x00 ; U+007d
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x32,0x7e,0x4c,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+007e
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+007f

ucs2_menu:
    dw 13,10,'P','a','O','S',' ','B','o','o','t',' ','M','a','n','a','g','e','r',13,10
    dw 'A',' ','-',' ','P','a','O','S',' ','S','l','o','t',' ','A',13,10
    dw 'B',' ','-',' ','P','a','O','S',' ','S','l','o','t',' ','B',13,10
    dw 'S',' ','-',' ','S','a','f','e',' ','M','o','d','e',13,10
    dw 'R',' ','-',' ','P','a','O','S',' ','R','e','s','c','u','e',13,10,0
%ifdef PBM_FEATURE_EXTERNAL
ucs2_menu_windows:
    dw 'W',' ','-',' ','W','i','n','d','o','w','s',13,10,0
ucs2_menu_linux:
    dw 'L',' ','-',' ','E','x','t','e','r','n','a','l',' ','L','i','n','u','x',13,10,0
%endif
ucs2_menu_enter:
    dw 'E','n','t','e','r',' ','-',' ','c','o','n','t','i','n','u','e',' ','d','e','f','a','u','l','t',13,10,0
%endif

; Passive E02 candidate manifest projection.  E02 must never freeze the
; feature-trimmed Manager profile: activation requires the same manifest,
; mutable-health/full-policy, menu, and external handoff surface that the
; production deployment uses.  These compile-time guards make that profile
; part of the candidate identity instead of leaving it to an unverified build
; environment.  No control flow references the projection; the protected
; campaign still binds the resulting artifact by hash before fresh authority.
%ifdef PBM_E02_PROJECTION
%ifndef PBM_FEATURE_MANIFEST
%error "E02 production candidate requires manifest verification"
%endif
%ifndef PBM_FEATURE_MUTABLE
%error "E02 production candidate requires mutable state"
%endif
%ifndef PBM_FEATURE_HEALTH
%error "E02 production candidate requires health arbitration"
%endif
%ifndef PBM_FEATURE_FULL_POLICY
%error "E02 production candidate requires full policy"
%endif
%ifndef PBM_FEATURE_MENU
%error "E02 production candidate requires the owner menu"
%endif
%ifndef PBM_FEATURE_EXTERNAL
%error "E02 production candidate requires external OS handoff"
%endif
align 8
pbm_e02_activation_projection:
    db "PAOS-E02-PROJECTION",0
    dd pbm_e02_activation_projection_fields_end - pbm_e02_activation_projection_fields
    dd 15
pbm_e02_activation_projection_fields:
    db "schema=paos.boot-v2-e02-activation-candidate.v1",0
    db "candidate_task=boot_v2_e02_activation_candidate",0
    db "candidate_task_id=1188",0
    db "primary_subsystem=manager_efi",0
    db "reversible_change=manager_activation_manifest_projection_only",0
    db "final_protected_task=boot_v2_campaign_e02_manager_activation",0
    db "artifact_role=manager_activation_manifest_projection",0
    db "source_scope=src/bootmgr/paos_bootmgr.asm",0
    db "profile=production_full_policy_menu_external",0
    db "activation_action=none",0
    db "canon_mutation=none",0
    db "product_release=false",0
    db "known_good=false",0
    db "target_actions=0",0
    db "protected_authority_actions=0",0
pbm_e02_activation_projection_fields_end:
pbm_e02_activation_projection_end:
%if (pbm_e02_activation_projection_end - pbm_e02_activation_projection) > 4096
%error "E02 activation candidate projection exceeds Task1188 budget"
%endif
%endif

; Passive pre-E02 rollback fixture.  The shared Task1207 campaign consumes
; this independently built candidate together with freshly discovered
; identities; the image itself performs no activation, rollback, or canon
; mutation.  The E02 identity projection remains the independently reversible
; Task1188 activation profile and excludes these rollback-fixture-only bytes.
%ifdef PBM_ROLLBACK_FIXTURE
align 8
pbm_rollback_fixture_projection:
    db "PAOS-ROLLBACK-FIXTURE",0
    dd pbm_rollback_fixture_projection_fields_end - pbm_rollback_fixture_projection_fields
    dd 33
pbm_rollback_fixture_projection_fields:
    db "schema=paos.boot-v2-rollback-fixture-candidate.v1",0
    db "candidate_task=boot_v2_rollback_fixture_candidate",0
    db "candidate_task_id=1189",0
    db "primary_subsystem=manager_efi",0
    db "reversible_change=pre_e02_canon_rollback_fixture_and_comparison_only",0
    db "activation_candidate=boot_v2_e02_activation_candidate",0
    db "final_campaign=boot_v2_campaign_rollback_interrupted_activation",0
    db "artifact_role=pre_e02_canon_rollback_fixture",0
    db "source_scope=src/bootmgr/paos_bootmgr.asm",0
    db "execution_target=qemu_only",0
    db "live_identity=EFI/Microsoft/Boot/bootmgfw.efi",0
    db "manager_identity=EFI/PaOS/vault/manager-recovery.efi",0
    db "baseline_identity=EFI/PaOS/vault/baseline-paos.efi",0
    db "comparison=expected_live_sha256_then_exact_readback",0
    db "rollback_source=baseline_identity",0
    db "fault_boundaries=before-live,after-live",0
    db "protected_anchor_windows=EFI/Microsoft/Boot/bootmgfw_orig.efi",0
    db "protected_anchor_bcd=EFI/Microsoft/Boot/BCD",0
    db "protected_anchor_fallback=EFI/Boot/bootx64.efi",0
    db "stable_inventory=live_excluded_non_paos_unchanged",0
    db "staged_substrate=all_allowed_files_exact_bytes",0
    db "qemu_behavior_test=gauntlet_v2/tests/test_boot_v2_target_cutover.py",0
    db "qemu_expect=BOOT_V2_TARGET_CUTOVER_PASS",0
    db "activation_action=none",0
    db "rollback_action=none",0
    db "canon_mutation=none",0
    db "version_action=none",0
    db "tag_action=none",0
    db "product_release=false",0
    db "known_good=false",0
    db "metal_credit=false",0
    db "target_actions=0",0
    db "protected_authority_actions=0",0
pbm_rollback_fixture_projection_fields_end:
pbm_rollback_fixture_projection_end:
%if (pbm_rollback_fixture_projection_end - pbm_rollback_fixture_projection) > 4096
%error "Rollback fixture candidate projection exceeds Task1189 budget"
%endif
%endif

align 8
pbm_b1_manager_policy_candidate:
    db "PAOS-B1-MANAGER-POLICY",0
    dd pbm_b1_manager_policy_candidate_fields_end - pbm_b1_manager_policy_candidate_fields
    dd 14
pbm_b1_manager_policy_candidate_fields:
    db "schema=paos.boot-v2-b1-manager-policy-candidate.v1",0
    db "candidate_task=boot_v2_b1_manager_policy_candidate",0
    db "candidate_task_id=1225",0
    db "primary_subsystem=manager_efi",0
    db "reversible_change=B1-manager-policy-only",0
    db "cross_slot_inconsistent_suspect_hardware=1",0
    db "matching_fingerprint_software_revert=1",0
    db "slot_flipping_stops_on_suspect_hardware=1",0
    db "rescue_memtest_preselected=1",0
    db "one_slot_cannot_accuse_hardware=1",0
    db "display_only_failure_safe_video=1",0
    db "safe_video_identity_bound=1",0
    db "non_display_failure_cannot_force_safe_video=1",0
    db "final_campaign=boot_v2_campaign_advanced_update_health",0
pbm_b1_manager_policy_candidate_fields_end:
pbm_b1_manager_policy_candidate_end:
%if (pbm_b1_manager_policy_candidate_end - pbm_b1_manager_policy_candidate) > 4096
%error "B1 Manager policy candidate projection exceeds Task1225 budget"
%endif

str_enter:           db "[PBM] v2 manager entered [boot.v2.manager.enter]",13,10,0
%ifdef PBM_DIAG_ENTRY_NONCE
str_diag_persisted:  db "[PBM] diagnostic entry NVRAM readback [boot.v2.diag.entry.persisted]",13,10,0
str_prod_entry_persisted: db "[PBM] production entry NVRAM readback [boot.v2.prod.entry.persisted]",13,10,0
str_diag_return:     db "[PBM] diagnostic EFI_ABORTED return [boot.v2.diag.entry.return]",13,10,0
%ifdef PBM_DIAG_ENTRY_CONTINUE
str_diag_continue:   db "[PBM] witness then verified path [boot.v2.diag.entry.continue]",13,10,0
%endif
%ifdef PBM_DIAG_RESOLVE_ONLY
str_diag_resolve_ok: db "[PBM] boot-device resolver succeeded [boot.v2.diag.resolve.ok]",13,10,0
str_diag_resolve_error: db "[PBM] boot-device resolver refused [boot.v2.diag.resolve.error]",13,10,0
str_diag_resolve_witness_error: db "[PBM] resolver witness write/read refused [boot.v2.diag.resolve.witness-refused]",13,10,0
%ifdef PBM_DIAG_VOLUME_ONLY
str_diag_volume_ok: db "[PBM] boot volume opened [boot.v2.diag.volume.ok]",13,10,0
str_diag_volume_error: db "[PBM] boot volume refused [boot.v2.diag.volume.error]",13,10,0
%ifdef PBM_DIAG_MANIFEST_ONLY
str_diag_manifest_ok: db "[PBM] signed manifest verified [boot.v2.diag.manifest.ok]",13,10,0
str_diag_manifest_error: db "[PBM] signed manifest refused [boot.v2.diag.manifest.error]",13,10,0
%endif
%endif
%endif
%ifdef PBM_DIAG_PREHEALTH_TRACE
str_diag_prehealth_loaded: db "[PBM] first journal policy loaded; finite return [boot.v2.diag.prehealth.loaded]",13,10,0
str_diag_prehealth_refused: db "[PBM] first journal policy refused [boot.v2.diag.prehealth.refused]",13,10,0
%ifdef PBM_DIAG_HEALTH_INSPECT_TRACE
str_diag_health_inspected: db "[PBM] read-only B1 evidence inspection returned [boot.v2.diag.health-inspected]",13,10,0
%ifdef PBM_DIAG_HEALTH_CONSUME_TRACE
str_diag_health_consumed_quiet: db "[PBM] compact health absent, no consumption [boot.v2.diag.health-consumed-quiet]",13,10,0
str_diag_bootready_refused: db "[PBM] BootReady present or unreadable; health probe refused [boot.v2.diag.bootready-refused]",13,10,0
%ifdef PBM_DIAG_CMOS_PEEK_TRACE
str_diag_cmos_zero: db "[PBM] CMOS one-shot value zero; no import [boot.v2.diag.cmos-zero]",13,10,0
str_diag_cmos_request: db "[PBM] CMOS one-shot bounded request; no import [boot.v2.diag.cmos-request]",13,10,0
str_diag_cmos_invalid: db "[PBM] CMOS one-shot out of range; no import [boot.v2.diag.cmos-invalid]",13,10,0
%ifdef PBM_DIAG_CMOS_IMPORT_REFUSAL
str_diag_import_enter: db "[PBM] missing signed Windows row; entering bounded importer refusal [boot.v2.diag.import-enter]",13,10,0
str_diag_import_refused: db "[PBM] actual importer refused missing signed Windows row; CMOS1 retained [boot.v2.diag.import-refused]",13,10,0
str_diag_import_ineligible: db "[PBM] signed Windows row present; diagnostic import forbidden [boot.v2.diag.import-ineligible]",13,10,0
str_diag_import_unexpected: db "[PBM] importer result differs from refusal contract [boot.v2.diag.import-unexpected]",13,10,0
%endif
%endif
%endif
%endif
%endif
%ifdef PBM_DIAG_STOP_AFTER_POLICY
str_diag_policy_persisted: db "[PBM] trial-B policy witness; finite return [boot.v2.diag.policy.persisted]",13,10,0
str_diag_policy_refused:   db "[PBM] trial-B policy witness refused [boot.v2.diag.policy.refused]",13,10,0
%endif
str_diag_failed:     db "[PBM] diagnostic entry NVRAM refused [boot.v2.diag.entry.refused]",13,10,0
%endif
str_state_active:    db "[PBM] journal: newest valid stable state selected verified Active",13,10,0
str_state_previous:  db "[PBM] journal: previous BIP/invalid Active selected verified Previous",13,10,0
str_state_ambiguous: db "[PBM] journal: equal-generation split brain; refusing to guess",13,10,0
str_state_needs_write: db "[PBM] journal: pending/Trial requires atomic mutation; read-only rung refuses replay",13,10,0
%ifdef PBM_ROLLBACK_FIXTURE
%ifdef PBM_FEATURE_MANIFEST
%ifndef PBM_FEATURE_MUTABLE
str_state_pax1_fixture_pending: db "[PBM] rollback fixture: exact manifest-bound internal PAX1 route selected [boot.v2.pax1.fixture-route]",13,10,0
%endif
%endif
%endif
str_state_rescue:    db "[PBM] journal: no safe stable selection; fail-closed Rescue",13,10,0
str_policy_active:   db "[PBM] mutable policy selected verified Active [boot.v2.policy.active]",13,10,0
str_policy_trial:    db "[PBM] mutable policy selected bounded Trial [boot.v2.policy.trial]",13,10,0
str_policy_rescue_deliberate: db "[PBM] owner-chosen Rescue attempt cleared failure-neutral [boot.v2.policy.rescue-deliberate]",13,10,0
str_policy_safe:     db "[PBM] mutable policy selected one bounded Safe attempt [boot.v2.policy.safe]",13,10,0
str_policy_rollback: db "[PBM] mutable policy selected verified rollback [boot.v2.policy.rollback]",13,10,0
str_power_start_armed: db "[PBM] early start durably armed [boot.v2.power.start-armed]",13,10,0
str_power_rescue: db "[PBM] two interrupted starts: Rescue choices [boot.v2.power.rescue]",13,10,0
str_power_start_failed: db "[PBM] early start commit refused; no transfer [boot.v2.power.commit-failed]",13,10,0
str_policy_rescue_prefix: db "[PBM] mutable policy quarantine_mask=",0
str_policy_rescue_suffix: db "; no verified usable full slot; selecting Rescue [boot.v2.policy.rescue]",13,10,0
str_policy_oneshot_consumed: db "[PBM] one-shot durably consumed before validation [boot.v2.policy.oneshot-consumed]",13,10,0
str_policy_oneshot_invalid: db "[PBM] consumed one-shot identity unavailable; opening recovery policy [boot.v2.policy.oneshot-invalid]",13,10,0
str_policy_prelaunch_quarantine: db "[PBM] invalid selected payload durably quarantined [boot.v2.policy.payload-quarantined]",13,10,0
%ifdef PBM_FEATURE_MANIFEST
str_rescue_shim16_direct: db "[PBM] Rescue: shim image loader present; verified UKI goes to its LoadImage [boot.v2.rescue.shim16-direct]",13,10,0
%endif
%ifdef PBM_FEATURE_EXTERNAL
str_policy_external: db "[PBM] mutable policy selected owner-requested external OS [boot.v2.policy.external]",13,10,0
str_policy_external_retained: db "[PBM] external one-shot identity refused with Pending retained [boot.v2.policy.external-retained]",13,10,0
str_external_ready: db "[PBM] external OS Agent nonce matched; availability recorded separately [boot.v2.external.ready]",13,10,0
str_external_unavailable: db "[PBM] external OS health reporting unavailable; PaOS health unchanged [boot.v2.external.unavailable]",13,10,0
str_external_fallback: db "[PBM] external Agent absent at next Manager entry; bounded menu fallback armed [boot.v2.external.fallback]",13,10,0
str_external_commit_failed: db "[PBM] external health reconciliation write failed; refusing transfer [boot.v2.external.commit-failed]",13,10,0
str_external_armed: db "[PBM] external attempt nonce journaled with PaOS BIP clear [boot.v2.external.armed]",13,10,0
str_external_prelaunch_invalid: db "[PBM] external payload invalid; failure recorded and detailed menu requested [boot.v2.external.prelaunch-invalid]",13,10,0
str_external_no_load_options: db "[PBM] external child keeps native LoadOptions; PaOS handoff not injected [boot.v2.external.native-options]",13,10,0
str_external_volume_selected: db "[PBM] exactly one filesystem matched signed external identity [boot.v2.external.volume-selected]",13,10,0
str_external_volume_ambiguous: db "[PBM] multiple filesystems matched signed external identity; refusing ambiguous device context [boot.v2.external.volume-ambiguous]",13,10,0
%endif
str_legacy_oneshot_seen: db "[PBM] legacy PaOS CMOS one-shot observed before adoption [boot.v2.legacy-oneshot.seen]",13,10,0
str_legacy_oneshot_imported: db "[PBM] legacy PaOS boot request durably adopted then CMOS clear verified [boot.v2.legacy-oneshot.imported]",13,10,0
str_legacy_oneshot_preserved: db "[PBM] existing different v2 one-shot retained precedence; legacy CMOS preserved [boot.v2.legacy-oneshot.preserved]",13,10,0
str_legacy_oneshot_deferred: db "[PBM] legacy PaOS boot request deferred behind an unreconciled attempt; CMOS retained [boot.v2.legacy-oneshot.deferred-bip]",13,10,0
str_legacy_oneshot_refused: db "[PBM] legacy PaOS boot request refused without transfer; durable retry retained [boot.v2.legacy-oneshot.refused]",13,10,0
str_prelaunch_finite_return: db "[PBM] prelaunch refusal returned to firmware BootOrder [boot.v2.prelaunch.finite-return]",13,10,0
str_watchdog_armed: db "[PBM] pre-child watchdog armed [boot.v2.watchdog.armed]",13,10,0
str_watchdog_unavailable: db "[PBM] firmware watchdog unavailable; continuing unbounded [boot.v2.watchdog.unavailable]",13,10,0
str_stage_launch_entry: db "[PBM] stage launch-entry [boot.v2.stage.launch-entry]",13,10,0
str_stage_volume_selected: db "[PBM] stage volume-selected [boot.v2.stage.volume-selected]",13,10,0
str_stage_payload_verified: db "[PBM] stage payload-verified [boot.v2.stage.payload-verified]",13,10,0
str_stage_pax1_prepared: db "[PBM] stage pax1-prepared [boot.v2.stage.pax1-prepared]",13,10,0
str_stage_gop_probed: db "[PBM] stage gop-probed [boot.v2.stage.gop-probed]",13,10,0
str_stage_attempt_arming: db "[PBM] stage attempt-arming [boot.v2.stage.attempt-arming]",13,10,0
%ifdef PBM_TEST_LEGACY_TXN_CASE
str_legacy_txn_read: db "[PBM] mutable CMOS request read [boot.v2.legacy-txn.read]",13,10,0
str_legacy_txn_validated: db "[PBM] request and adoption preconditions validated [boot.v2.legacy-txn.validated]",13,10,0
str_legacy_txn_committed: db "[PBM] adoption journal commit verified [boot.v2.legacy-txn.adoption-committed]",13,10,0
str_legacy_txn_clear_written: db "[PBM] CMOS clear written [boot.v2.legacy-txn.clear-written]",13,10,0
str_legacy_txn_clear_verified: db "[PBM] CMOS zero read-back verified [boot.v2.legacy-txn.clear-verified]",13,10,0
str_legacy_txn_retained: db "[PBM] refusal retained durable request ownership [boot.v2.legacy-txn.retained]",13,10,0
str_legacy_txn_final_select: db "[PBM] transactional request reached final policy [boot.v2.legacy-txn.final-select]",13,10,0
str_legacy_txn_reset_before_commit: db "[PBM] injected reset before adoption commit [boot.v2.legacy-txn.reset-before-commit]",13,10,0
str_legacy_txn_reset_after_commit: db "[PBM] injected reset after adoption commit [boot.v2.legacy-txn.reset-after-commit]",13,10,0
str_legacy_txn_reset_after_clear: db "[PBM] injected reset after verified clear [boot.v2.legacy-txn.reset-after-clear]",13,10,0
str_legacy_txn_case_complete: db "[PBM] immutable transaction case complete [boot.v2.legacy-txn.case-complete]",13,10,0
%endif
%ifdef PBM_FEATURE_MENU
str_menu_hidden:      db "[PBM] automatic path; menu presentation skipped [boot.v2.menu.hidden]",13,10,0
str_menu_visible:     db "[PBM] bounded owner menu presented [boot.v2.menu.visible]",13,10,0
str_clearscreen_before: db "[PBM] firmware ClearScreen call before menu [boot.v2.clearscreen.before]",13,10,0
str_clearscreen_after:  db "[PBM] firmware ClearScreen returned before menu [boot.v2.clearscreen.after]",13,10,0
str_outputstring_before: db "[PBM] firmware OutputString call [boot.v2.outputstring.before]",13,10,0
str_outputstring_after:  db "[PBM] firmware OutputString return [boot.v2.outputstring.after]",13,10,0
str_menu_input_service: db "[PBM] existing WaitForKey event serviced with bounded polling [boot.v2.menu.input-service]",13,10,0
str_menu_timeout:     db "[PBM] menu timeout accepted policy default [boot.v2.menu.timeout]",13,10,0
str_menu_healthy_held: db "[PBM] healthy automatic boot: 250 ms held-key window [boot.v2.menu.healthy-held-window]",13,10,0
str_menu_trial_held: db "[PBM] clean automatic trial: 250 ms held-key window [boot.v2.menu.trial-held-window]",13,10,0
str_menu_override:    db "[PBM] local menu override selected validated identity [boot.v2.menu.override]",13,10,0
str_menu_accept:      db "[PBM] local menu accepted policy default [boot.v2.menu.accept]",13,10,0
str_menu_show_next_consumed: db "[PBM] show-next request durably consumed before presentation [boot.v2.menu.show-next-consumed]",13,10,0
str_menu_present_stop: db "[PBM] test stop after menu presentation [boot.v2.menu.present-stop]",13,10,0
str_face_frame_double: db "[PBM] A1 classic frame rendered [boot.v2.face.frame] mode=double",13,10,0
str_face_frame_ascii: db "[PBM] A1 classic frame rendered [boot.v2.face.frame] mode=ascii",13,10,0
str_face_blind_rescue: db "[PBM] [boot.v2.face.blind] key=R route=rescue display_ready=0",13,10,0
str_face_blind_safe: db "[PBM] [boot.v2.face.blind] key=S route=safe display_ready=0",13,10,0
str_face_blind_windows: db "[PBM] [boot.v2.face.blind] key=W route=external display_ready=0",13,10,0
str_face_clock_healthy: db "[PBM] [boot.v2.face.clock] case=healthy reads=1 writes=0 action=continue",13,10,0
str_face_clock_old: db "[PBM] [boot.v2.face.clock] case=old reads=1 writes=0 action=warn_continue",13,10,0
str_face_clock_future: db "[PBM] [boot.v2.face.clock] case=future reads=1 writes=0 action=warn_continue",13,10,0
str_face_duration_monotonic: db "[PBM] [boot.v2.face.duration] clock=monotonic",13,10,0
%endif
str_state_write_ok:  db "[PBM] journal older-copy Flush/read-back verified [boot.v2.state.write-verified]",13,10,0
str_state_write_fail: db "[PBM] journal write/Flush/read-back failed; refusing transfer [boot.v2.state.write-failed]",13,10,0
str_manifest_valid:   db "[PBM] owner-signed manifest RSA-2048/SHA-256 verified [boot.v2.manifest.valid]",13,10,0
str_manifest_invalid: db "[PBM] manifest missing/invalid; no unauthenticated transfer [boot.v2.manifest.invalid]",13,10,0
str_manifest_no_key:  db "[PBM] no enrolled owner manifest key; no unauthenticated transfer [boot.v2.manifest.no-key]",13,10,0
str_recovery_descriptor_valid: db "[PBM] independent owner-signed Rescue descriptor verified [boot.v2.recovery-descriptor.valid]",13,10,0
str_recovery_descriptor_invalid: db "[PBM] independent Rescue descriptor missing/invalid; visible stop [boot.v2.recovery-descriptor.invalid]",13,10,0
%ifdef PBM_RESCUE_ACCEPT_LEGACY
str_recovery_descriptor_legacy: db "[PBM] Rescue descriptor signed by the release key (transitional; re-sign with the rescue key) [boot.v2.recovery-descriptor.legacy-release-key]",13,10,0
%endif
str_recovery_descriptor_no_key: db "[PBM] no enrolled owner recovery key; visible stop [boot.v2.recovery-descriptor.no-key]",13,10,0
str_payload_valid:    db "[PBM] selected payload exact size/PE64/SHA-256 verified [boot.v2.payload.valid]",13,10,0
str_payload_invalid:  db "[PBM] selected payload missing/invalid; refusing LoadImage [boot.v2.payload.invalid]",13,10,0
str_try_media:        db "[PBM] owner-signed TRY_MEDIA manifest; read-only launch, no journal/NVRAM/CMOS write [boot.v2.try.media]",13,10,0
str_try_not_removable: db "[PBM] TRY_MEDIA manifest on a non-removable, non-USB boot device: refused, nothing launched [boot.v2.try.not-removable]",13,10,0
str_try_revoked:      db "[PBM] TRY_MEDIA manifest below the compiled Try floor: revoked, nothing launched [boot.v2.try.revoked]",13,10,0
str_manifest_state_bound: db "[PBM] manifest sequence/digest accepted against state floor [boot.v2.manifest.state-bound]",13,10,0
str_mfloor_held:    db "[PBM] manifest floor held [boot.v2.manifest.floor-held]",13,10,0
str_mfloor_absent:  db "[PBM] manifest floor absent; journal only [boot.v2.manifest.floor-absent]",13,10,0
str_mfloor_foreign: db "[PBM] manifest floor foreign; ignored [boot.v2.manifest.floor-foreign]",13,10,0
str_mfloor_unavailable: db "[PBM] manifest floor unavailable; journal only [boot.v2.manifest.floor-unavailable]",13,10,0
str_mfloor_rejected: db "[PBM] manifest refused by the NV floor [boot.v2.manifest.floor-rejected]",13,10,0
str_mfloor_raised:  db "[PBM] manifest floor raised [boot.v2.manifest.floor-raised]",13,10,0
str_mfloor_raise_failed: db "[PBM] manifest floor not raised [boot.v2.manifest.floor-raise-failed]",13,10,0
str_mfloor_squatted: db "[PBM] manifest floor squatted by an undeletable variable; journal only, owner action needed [boot.v2.manifest.floor-squatted]",13,10,0
str_manifest_state_rejected: db "[PBM] manifest rollback/substitution rejected; no transfer [boot.v2.manifest.state-rejected]",13,10,0
str_attempt_armed:     db "[PBM] nonce-bound attempt journaled before transfer [boot.v2.attempt.armed]",13,10,0
str_attempt_failed:    db "[PBM] attempt journal write failed; refusing transfer [boot.v2.attempt.failed]",13,10,0
str_attempt_rescue_untracked: db "[PBM] no trusted journal; verified Rescue bootstrap remains read-only [boot.v2.attempt.rescue-untracked]",13,10,0
str_attempt_handoff_bound: db "[PBM] flushed attempt nonce/generation bound to child handoff [boot.v2.attempt.handoff-bound]",13,10,0
str_attempt_handoff_mismatch: db "[PBM] attempt/handoff mismatch; refusing transfer [boot.v2.attempt.handoff-mismatch]",13,10,0
str_health_consumed: db "[PBM] nonce-bound strong health durably reconciled [boot.v2.health.consumed] checkpoint=consumed precedence=current-attempt",13,10,0
str_health_ignored: db "[PBM] stale/invalid health record ignored; BIP remains authoritative [boot.v2.health.ignored] checkpoint=stale precedence=current-bip",13,10,0
str_health_commit_failed: db "[PBM] strong-health journal commit failed; refusing transfer [boot.v2.health.commit-failed]",13,10,0
str_health_delete_failed: db "[PBM] health journal committed; stale NVRAM record could not be deleted [boot.v2.health.delete-failed]",13,10,0
str_b1_suspect_hardware: db "[PBM] inconsistent A/B failures: suspect hardware; Rescue memtest preselected [boot.v2.b1.suspect-hardware]",13,10,0
str_b1_software_revert: db "[PBM] matching A/B fingerprints retain software revert [boot.v2.b1.software-revert]",13,10,0
str_b1_one_slot: db "[PBM] one-slot evidence cannot accuse hardware [boot.v2.b1.one-slot]",13,10,0
str_b1_safe_video_suppressed: db "[PBM] display-only evidence on a network-ready boot; networkless video-Safe not armed [boot.v2.b1.safe-video-suppressed]",13,10,0
str_b1_safe_video_earned: db "[PBM] display-only failure earned one safe-video boot [boot.v2.b1.safe-video-earned]",13,10,0
str_b1_safe_video_bound: db "[PBM] safe-video consumed for exact slot/payload [boot.v2.b1.safe-video-bound]",13,10,0
str_b1_safe_video_rejected: db "[PBM] stale/foreign safe-video rejected clear-before-act [boot.v2.b1.safe-video-rejected]",13,10,0
str_policy_safe_video_normal_retry: db "[PBM] failed display-only Safe returned to verified normal slot, failure accounted [boot.v2.policy.safe-video-normal-retry]",13,10,0
str_try_a:           db "[PBM] try verified identity slot A",13,10,0
str_try_b:           db "[PBM] try verified identity slot B",13,10,0
str_try_rescue:      db "[PBM] try independent Rescue identity",13,10,0
%ifdef PBM_FEATURE_EXTERNAL
str_try_windows:     db "[PBM] try owner-signed Windows identity",13,10,0
str_try_linux:       db "[PBM] try owner-signed external Linux identity",13,10,0
%endif
str_selected_failed: db "[PBM] selected payload LoadImage/StartImage failed",13,10,0
str_firmware_load_refused: db "[PBM] firmware LoadImage refused status=",0
str_firmware_load_refused_tail: db " [boot.v2.load-image.refused]",13,10,0
pinned_rescue_shim_sha:
    db 0x6f,0xe6,0xe1,0xbc,0xbe,0x6c,0xf6,0xba,0xec,0x8e,0x05,0x6d,0x40,0x36,0x1c,0xa1
    db 0xaa,0x71,0x5c,0xc0,0x4d,0xdc,0xc2,0x85,0x53,0x51,0xde,0x06,0x0b,0x84,0x35,0x0b
str_fallback_failed: db "[PBM] Previous payload LoadImage/StartImage failed",13,10,0
str_handoff_a:       db "[PBM] handoff entry=A profile=normal dev-smoke CRC32 ready [boot.v2.handoff]",13,10,0
str_handoff_a_safe:  db "[PBM] handoff entry=A profile=safe dev-smoke CRC32 ready [boot.v2.handoff]",13,10,0
str_handoff_b:       db "[PBM] handoff entry=B profile=normal dev-smoke CRC32 ready [boot.v2.handoff]",13,10,0
str_handoff_b_safe:  db "[PBM] handoff entry=B profile=safe dev-smoke CRC32 ready [boot.v2.handoff]",13,10,0
str_handoff_rescue:  db "[PBM] handoff entry=Rescue profile=rescue dev-smoke CRC32 ready [boot.v2.handoff]",13,10,0
%ifdef PBM_FEATURE_EXTERNAL
str_handoff_windows: db "[PBM] handoff entry=Windows profile=external CRC32 bound internally [boot.v2.handoff]",13,10,0
str_handoff_linux:   db "[PBM] handoff entry=Linux profile=external CRC32 bound internally [boot.v2.handoff]",13,10,0
%endif
str_start:           db "[PBM] StartImage [boot.v2.start-image]",13,10,0
str_start_returned:  db "[PBM] armed child returned; preserving attempt and refusing fallback [boot.v2.start-image-returned]",13,10,0
str_stop:            db "[PBM] no payload started; visible-stop",13,10,0
str_self_load_base:  db "[PBM] self load-base=",0
str_self_load_base_tail: db " [boot.v2.load-base.self]",13,10,0
str_child_load_base: db "[PBM] child load-base=",0
str_child_load_base_tail: db " [boot.v2.load-base.child]",13,10,0

str_pax1_accepted: db "[PBM] PAX1 current-PaOS profile accepted; RX flag is identity-only [boot.v2.pax1.accepted]",13,10,0
str_pax1_direct:   db "[PBM] PAX1 direct entry abi=1 firmware-LoadImage=0 [boot.v2.pax1.direct-entry]",13,10,0
str_pax1_invalid:  db "[PBM] PAX1 profile refused; no direct entry [boot.v2.pax1.refused]",13,10,0
str_pax1_size:     db "[PBM] PAX1 SizeOfImage=",0
str_pax1_size_tail: db " [boot.v2.pax1.size]",13,10,0
str_pax1_alloc:      db "[PBM] PAX1 AllocatePages at1m=",0
str_pax1_alloc_max:  db " max=",0
str_pax1_alloc_base: db " base=",0
str_pax1_alloc_tail: db " [boot.v2.pax1.alloc]",13,10,0
str_pax1_returned: db "[PBM] PAX1 direct child returned; no post-EBS cleanup or fallback [boot.v2.pax1.returned]",13,10,0
str_pax1_bridge_rejected: db "[PBM] PAX1 bridge refused the handoff before entry; finite return [boot.v2.pax1.bridge-reject]",13,10,0

%ifdef PBM_FEATURE_MANIFEST
PBM_DIRECT_RESCUE_RDATA
%endif
rdata_end:
rdata_size        equ rdata_end - rdata_start
rdata_file_size   equ (rdata_size + 0xFFF) & ~0xFFF
%ifndef PBM_MSI_COMBINED_OBJECT
times rdata_file_size - rdata_size db 0
%else
section .data align=16
%endif

data_start:
PBM_CRYPTO_MUTABLE
PBM_MUTABLE_DATA
%ifdef PBM_FEATURE_MENU
PBM_RECOVERY_MENU_DATA
%endif
SMBIOS_IDENTITY_DATA
%ifdef PBM_FEATURE_FULL_POLICY
%ifdef PBM_OWNER_KEY
R5_GRANT_DATA
R5_ROUTE_DATA
r5_manager_event: dq 0
r5_manager_active: db 0
r5_manager_consumed: db 0
DD_ORACLE_DATA
%endif
%endif
%ifdef PBM_FEATURE_MANIFEST
PBM_DIRECT_RESCUE_DATA
%endif
data_end:
data_size         equ data_end - data_start
data_file_size    equ (data_size + 0xFFF) & ~0xFFF
%ifndef PBM_MSI_COMBINED_OBJECT
times data_file_size - data_size db 0
%else
section .sbat align=1
%endif

sbat_start:
    db "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md",10
    db "paos.manager,1,PaOS Boot Manager,paos,1,https://github.com/paosforge/paos",10
sbat_end:
sbat_size         equ sbat_end - sbat_start
sbat_file_size    equ (sbat_size + 0x1FF) & ~0x1FF
%ifndef PBM_MSI_COMBINED_OBJECT
times sbat_file_size - sbat_size db 0

text_rva          equ 0x1000
text_file_offset  equ code_start - $$
rdata_rva         equ text_rva + text_file_size
rdata_file_offset equ rdata_start - $$
data_rva          equ rdata_rva + rdata_file_size
data_file_offset  equ data_start - $$
sbat_rva          equ data_rva + data_file_size
sbat_file_offset  equ sbat_start - $$
image_size        equ (sbat_rva + sbat_size + 0xFFF) & ~0xFFF

; Cross-section RIP-relative references are correct only while all mapped
; starts have the same RVA-to-file bias. Fail assembly rather than emit an
; image whose PE permissions silently remap code or data to another address.
%if (text_rva - text_file_offset) != (rdata_rva - rdata_file_offset)
%error "Manager .text/.rdata RVA-to-file bias differs"
%endif
%if (text_rva - text_file_offset) != (data_rva - data_file_offset)
%error "Manager .text/.data RVA-to-file bias differs"
%endif
%if (text_rva - text_file_offset) != (sbat_rva - sbat_file_offset)
%error "Manager .text/.sbat RVA-to-file bias differs"
%endif

%else
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
