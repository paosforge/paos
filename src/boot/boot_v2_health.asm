;; MODULE boot/boot_v2_health
;; LAYER 0
;; EXPORTS pbm_persist_count, pbm_persist_rows, pbm_persist_subrows, pbm_a1_gop_query_entry, boot_v2_normalize_failure_fingerprint, boot_v2_face_progress_observe, boot_v2_face_checkpoint_observe, boot_v2_display_output_status, boot_v2_health_vector_core_valid, boot_v2_publish_strong_health, boot_v2_publish_health_blackbox, boot_v2_ge_c7_qemu_selftest, boot_v2_blackbox_validate, boot_v2_blackbox_qemu_selftest, boot_v2_ge_c5_qemu_selftest, pbm_health_vector_published, pbm_blackbox_record, pbm_blackbox_last_valid, boot_v2_init_checkpoint_load, boot_v2_init_checkpoint_transition, boot_v2_init_checkpoint_resolve, pbm_init_checkpoint_record, pbm_init_last_implicated, pbm_runtime_code_mapped, pbm_strong_health_published, pbm_init_checkpoint_loaded, pbm_init_checkpoint_durable
;; IMPORTS boot/header, boot/boot_v2_handoff, boot/serial, boot/gop, boot/boot_menu, boot/nvram_access, sec/replay_floor
;; CAPS
;; OWNER saga:boot
; Publish one bounded, nonce-bound strong-health acknowledgement through an EFI
; runtime variable. The Manager remains the only writer of its disk journal:
; it validates and consumes this record on the next boot, then performs the
; durable promotion/health commit. Direct boots, Rescue, Safe Mode, and old
; read-only Manager handoffs cannot publish.

; The byte-free shared contract aliases header.asm's earlier call site. Drop
; the alias before boot/gop.asm defines the proven implementation itself.
%undef gop_query

PBM_EFI_VAR_NON_VOLATILE       equ 0x00000001
PBM_EFI_VAR_BOOTSERVICE_ACCESS equ 0x00000002
PBM_EFI_VAR_RUNTIME_ACCESS     equ 0x00000004
PBM_EFI_HEALTH_ATTRS           equ (PBM_EFI_VAR_NON_VOLATILE | PBM_EFI_VAR_BOOTSERVICE_ACCESS | PBM_EFI_VAR_RUNTIME_ACCESS)
PBM_EFI_BUFFER_TOO_SMALL       equ 0x8000000000000005
PBM_EFI_NOT_FOUND              equ 0x800000000000000E

; The detailed vector is diagnostic evidence, never a second promotion token.
; PaOSBootReady remains the only object the Manager may consume for promotion.
PBM_MH_MAGIC                    equ 0x484D4250 ; "PBMH"
PBM_MH_VERSION                  equ 2
PBM_MH_SIZE                     equ 128
PBM_MH_MAGIC_OFF                equ 0
PBM_MH_VERSION_OFF              equ 4
PBM_MH_SIZE_OFF                 equ 6
PBM_MH_GENERATION_OFF           equ 8
PBM_MH_MANAGER_SEQ_OFF          equ 16
PBM_MH_ATTEMPT_NONCE_OFF        equ 24
PBM_MH_STATE_GEN_OFF            equ 32
PBM_MH_INIT_GEN_OFF             equ 40
PBM_MH_PAYLOAD_SHA_OFF          equ 48
PBM_MH_ENTRY_OFF                equ 80
PBM_MH_PROFILE_OFF              equ 81
PBM_MH_REASON_OFF               equ 82
PBM_MH_STAGE_OFF                equ 83
PBM_MH_IMAGE_OFF                equ 84
PBM_MH_CORE_OFF                 equ 85
PBM_MH_DESKTOP_OFF              equ 86
PBM_MH_COMMAND_OFF              equ 87
PBM_MH_STORAGE_OFF              equ 88
PBM_MH_NETWORK_OFF              equ 89
PBM_MH_DISPLAY_OFF              equ 90
PBM_MH_MACHINE_OFF              equ 91
PBM_MH_DIM_COUNT_OFF            equ 92
PBM_MH_COMPLETED_MASK_OFF       equ 94
PBM_MH_IMPLICATED_OFF           equ 96
PBM_MH_PREVIOUS_STAGE_OFF       equ 98
PBM_MH_FLAGS_OFF                equ 100
PBM_MH_PUBLISHED_TSC_OFF        equ 104
PBM_MH_FAILURE_FINGERPRINT_OFF  equ 112
PBM_MH_CRC32                    equ 124

PBM_MH_DIM_COUNT                equ 8
PBM_MH_READY                    equ 1
PBM_MH_DEGRADED                 equ 2
PBM_MH_UNAVAILABLE              equ 3
PBM_MH_F_STRONG_CORE            equ 0x0001
PBM_MH_F_OPTIONAL_DEGRADED      equ 0x0002
PBM_MH_F_DISPLAY_ESTABLISHED    equ 0x0004

; B1 activates one previously reserved dword in the v1 checkpoint record.  A
; zero value is deliberately backward compatible and means pre-B1/incomplete
; evidence: it can never participate in cross-slot hardware classification.
; Nonzero comparison bytes are only {stage, result class, implicated subsystem};
; the surrounding record retains exact slot/nonce/generation/payload identity.
PBM_INIT_FAILURE_FINGERPRINT_OFF equ 108
PBM_FAILURE_FINGERPRINT_TAG      equ 0xB1000000

; The black box is a bounded eight-record ring stored as two alternating EFI
; variables.  Header and slot offsets deliberately use separate namespaces:
; confusing them was the prior iteration's assembler failure.
PBM_BB_MAGIC                     equ 0x58424250 ; "PBBX"
PBM_BB_VERSION                   equ 1
PBM_BB_SIZE                      equ 1024
PBM_BB_HEADER_SIZE               equ 64
PBM_BB_SLOT_SIZE                 equ 120
PBM_BB_SLOT_COUNT                equ 8
PBM_BB_HDR_MAGIC_OFF             equ 0
PBM_BB_HDR_VERSION_OFF           equ 4
PBM_BB_HDR_SIZE_OFF              equ 6
PBM_BB_HDR_GENERATION_OFF        equ 8
PBM_BB_HDR_MANAGER_SEQ_OFF       equ 16
PBM_BB_HDR_ATTEMPT_NONCE_OFF     equ 24
PBM_BB_HDR_WRITE_INDEX_OFF       equ 32
PBM_BB_HDR_COUNT_OFF             equ 34
PBM_BB_HDR_SLOT_COUNT_OFF        equ 36
PBM_BB_HDR_SLOT_SIZE_OFF         equ 38
PBM_BB_HDR_CRC32_OFF             equ 60

PBM_BB_SLOT_MAGIC_OFF            equ 0
PBM_BB_SLOT_VERSION_OFF          equ 4
PBM_BB_SLOT_SIZE_OFF             equ 6
PBM_BB_SLOT_GENERATION_OFF       equ 8
PBM_BB_SLOT_NONCE_OFF            equ 16
PBM_BB_SLOT_MANAGER_SEQ_OFF      equ 24
PBM_BB_SLOT_STATE_GEN_OFF        equ 32
PBM_BB_SLOT_BUILD_SHA_OFF        equ 40
PBM_BB_SLOT_ENTRY_OFF            equ 72
PBM_BB_SLOT_PROFILE_OFF          equ 73
PBM_BB_SLOT_REASON_OFF           equ 74
PBM_BB_SLOT_RESET_CAUSE_OFF      equ 75
PBM_BB_SLOT_STARTED_STAGE_OFF    equ 76
PBM_BB_SLOT_COMPLETED_STAGE_OFF  equ 77
PBM_BB_SLOT_RECOVERY_OFF         equ 78
PBM_BB_SLOT_DIM_COUNT_OFF        equ 79
PBM_BB_SLOT_DIMS_OFF             equ 80
PBM_BB_SLOT_INIT_GEN_OFF         equ 88
PBM_BB_SLOT_COMPLETED_MASK_OFF   equ 96
PBM_BB_SLOT_IMPLICATED_OFF       equ 98
PBM_BB_SLOT_PREVIOUS_STAGE_OFF   equ 100
PBM_BB_SLOT_FLAGS_OFF            equ 102
PBM_BB_SLOT_PUBLISHED_TSC_OFF    equ 104
PBM_BB_SLOT_FAILURE_FINGERPRINT_OFF equ 112
PBM_BB_SLOT_CRC32                equ 116

PBM_BB_RECOVERY_NONE             equ 0
PBM_BB_RECOVERY_ROLLBACK         equ 1
PBM_BB_RECOVERY_SAFE             equ 2
PBM_BB_RECOVERY_RESCUE           equ 3
PBM_BB_RECOVERY_INVALID          equ 4
PBM_BB_LOAD_VALID                equ 0
PBM_BB_LOAD_MISSING              equ 1
PBM_BB_LOAD_INVALID              equ 2
PBM_BB_LOAD_INCOMPATIBLE         equ 3
PBM_BB_GEN_EQUAL                 equ 0
PBM_BB_GEN_FIRST_NEWER           equ 1
PBM_BB_GEN_AMBIGUOUS             equ 2
PBM_BB_GEN_SECOND_NEWER          equ -1

; GE C5's pure resume selector models only durable transaction roles.  The
; production writers remain the host's inactive-slot transaction and the
; canonical gated cutover adapter; PaOS gains no ESP write authority here.
C5_TX_STABLE                     equ 0
C5_TX_CANDIDATE_EXACT            equ 1
C5_TX_MANIFEST_EXACT             equ 2
C5_TX_TRIAL_ARMED                equ 3
C5_TX_TRIAL_ENTERED              equ 4
C5_TX_PROMOTED                   equ 5
C5_TX_ACTION_WRITE_CANDIDATE     equ 1
C5_TX_ACTION_WRITE_MANIFEST      equ 2
C5_TX_ACTION_WRITE_JOURNAL       equ 3
C5_TX_ACTION_BOOT_TRIAL          equ 4
C5_TX_ACTION_PROMOTE             equ 5
C5_TX_ACTION_ROLLBACK            equ 6
C5_TX_ACTION_DONE                equ 7
C5_TX_ACTION_REFUSE              equ 0xFF

%if (PBM_MH_CRC32 + 4) != PBM_MH_SIZE
    %error "boot-v2 multidimensional-health record size drift"
%endif
%if (PBM_MH_IMAGE_OFF + PBM_MH_DIM_COUNT) != PBM_MH_DIM_COUNT_OFF
    %error "boot-v2 health dimensions are not contiguous"
%endif
%if (PBM_INIT_FAILURE_FINGERPRINT_OFF + 4) > PBM_INIT_CRC32
    %error "boot-v2 failure fingerprint overlaps checkpoint CRC"
%endif
%if (PBM_BB_HEADER_SIZE + PBM_BB_SLOT_COUNT * PBM_BB_SLOT_SIZE) != PBM_BB_SIZE
    %error "boot-v2 black-box ring geometry drift"
%endif
%if (PBM_BB_SLOT_DIMS_OFF + PBM_MH_DIM_COUNT) != PBM_BB_SLOT_INIT_GEN_OFF
    %error "boot-v2 black-box dimensions overlap init generation"
%endif
%if (PBM_BB_SLOT_CRC32 + 4) != PBM_BB_SLOT_SIZE
    %error "boot-v2 black-box slot size drift"
%endif

; Return the stable comparison fingerprint for the current checkpoint record.
; Layout: bits 7:0 checkpoint-of-death, 15:8 result/fault class, 23:16
; implicated subsystem, 31:24 constant B1 format tag. STARTING+NONE means an interrupted checkpoint;
; STARTING+FAILED means an explicitly failed predicate.  Completed/degraded
; work is not a failed boot.  Volatile nonce, time, generation and payload
; identity remain beside this value in the CRC-bound record but never enter it.
boot_v2_normalize_failure_fingerprint:
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF]
    cmp  eax, PBM_INIT_TRANSITION_STARTING
    jne  .none
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF]
    cmp  eax, PBM_INIT_STAGE_P8
    ja   .none
    movzx ecx, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    cmp  ecx, PBM_INIT_RESULT_NONE
    je   .result_ok
    cmp  ecx, PBM_INIT_RESULT_FAILED
    jne  .none
.result_ok:
    movzx edx, word [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF]
    test edx, edx
    jz   .none
    cmp  edx, PBM_INIT_SUBSYS_MACHINE
    ja   .none
    cmp  dx, [rel pbm_init_checkpoint_record + PBM_INIT_SUBSYSTEM_OFF]
    jne  .none
    shl  ecx, 8
    shl  edx, 16
    or   eax, ecx
    or   eax, edx
    or   eax, PBM_FAILURE_FINGERPRINT_TAG
    ret
.none:
    xor  eax, eax
    ret

; Acquire/mode-set GOP exactly as before, then display the bounded P0-P8 face
; while firmware text services and the linear framebuffer are both available.
pbm_a1_gop_query_entry:
    cmp  byte [rel bm_face_owner], 0
    jne  .out
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .face_only
    ; Task1272 normalizes either observed firmware/Manager entry residue to
    ; efi_entry RSP mod 16 = 8.  The fixed eight-register header frame enters
    ; this wrapper at mod 16 = 0, so give gop_query its current proven entry
    ; residue, then restore the wrapper entry residue before starting the A1
    ; face.  Do not carry the GOP-only adjustment across the face boundary.
    sub  rsp, 8
    call gop_query
    add  rsp, 8
.face_only:
    call bm_face_progress_run
.out:
    ret

; Called ONLY from actual header C3WD edges, after the unchanged persistence
; policy. EDI=stage, ESI=edge, EAX=source rc (preserved). Direct/readonly boots
; still report actual work boundaries. A matching current managed checkpoint
; refines the result to degraded/failed; old records/KAT snapshots never drive
; the face by themselves. Generic checkpoint tests do not paint production UI.
boot_v2_face_checkpoint_observe:
    push rax
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    test eax, eax
    jnz  .failed
    xor  edx, edx
    cmp  esi, PBM_INIT_TRANSITION_COMPLETED
    jne  .result_ready
    mov  edx, PBM_INIT_RESULT_HEALTHY
.result_ready:
    cmp  byte [rel pbm_manager_launch], 1
    jne  .project
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz   .project
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .project
    cmp  byte [rel pbm_init_checkpoint_loaded], 1
    jne  .project
    mov  rax, [rel pbm_attempt_nonce]
    test rax, rax
    jz   .project
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_ATTEMPT_NONCE_OFF]
    jne  .project
    mov  rax, [rel pbm_manager_sequence]
    test rax, rax
    jz   .project
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_MANAGER_SEQ_OFF]
    jne  .project
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], r12b
    jne  .project
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_FAILED
    je   .failed
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], r13b
    jne  .failed
    movzx edx, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    jmp  .project
.failed:
    ; A refused real begin is a failed attempt at this checkpoint, not a
    ; completed phase or an unexplained pending cell. The bounded state owner
    ; still enforces predecessors, so a latched earlier failure cannot advance.
    cmp  r13d, PBM_INIT_TRANSITION_STARTING
    jne  .failure_result
    mov  edi, r12d
    mov  esi, PBM_INIT_TRANSITION_STARTING
    xor  edx, edx
    call bm_face_milestone
.failure_result:
    mov  r13d, PBM_INIT_TRANSITION_COMPLETED
    mov  edx, PBM_INIT_RESULT_FAILED
.project:
    mov  edi, r12d
    mov  esi, r13d
    call bm_face_milestone
    pop  r13
    pop  r12
    pop  rbx
    pop  rax
    ret

; EDI=stage, ESI=cell glyph from real state; render status says whether
; pixels/text were established or the face has yielded to the final owner.
boot_v2_face_progress_observe:
    cmp  edi, PBM_A1_FACE_CHECKPOINT_COUNT
    jae  .out
    cmp  sil, '.'
    je   .valid
    cmp  sil, 'X'
    je   .valid
    cmp  sil, '|'
    je   .valid
    cmp  sil, '/'
    je   .valid
    cmp  sil, '-'
    je   .valid
    cmp  sil, 0x5C
    jne  .out
.valid:
    push rbx
    mov  ebx, edi
    mov  ecx, esi
    mov  [rel pbm_face_stage], bl
    mov  [rel pbm_face_active], cl
    lea  rdi, [rel str_pbm_face_progress_pre]
    call serial_string
    mov  eax, ebx
    add  eax, '0'
    mov  dil, al
    call serial_char
    lea  rdi, [rel str_pbm_face_progress_mid]
    call serial_string
    mov  dil, cl
    call serial_char
    lea  rdi, [rel str_pbm_face_progress_render]
    call serial_string
    movzx edi, byte [rel bm_face_draw_status]
    add  edi, '0'
    call serial_char
    lea  rdi, [rel str_pbm_face_progress_post]
    call serial_string
    pop  rbx
.out:
    ret

; Grade established output, not GOP discovery or a mode-set return.  P7 is set
; only after the real compositor has run; its three independently earned paint
; latches prove backdrop, clock and windows traversed the framebuffer path.  A
; separate display-engine readback then proves that the plane is fetching that
; same geometry.  This second check is load-bearing: firmware can leave PaOS's
; framebuffer globals intact while reverting the live plane to its console
; geometry, making framebuffer-only readback falsely claim a visible desktop.
; QEMU/unknown hardware without a readable plane degrades honestly; the final
; campaign owns the independent physical-display observation.
boot_v2_display_output_status:
    mov  al, PBM_MH_UNAVAILABLE
    cmp  qword [rel fb_base], 0
    je   .out
    cmp  dword [rel fb_width], 0
    je   .degraded
    cmp  dword [rel fb_height], 0
    je   .degraded
    mov  edx, [rel fb_width]
    cmp  edx, [rel fb_stride]
    ja   .degraded
    cmp  byte [rel boot_p7_reached], 1
    jne  .degraded
    cmp  byte [rel gui_m_bg], 1
    jne  .degraded
    cmp  byte [rel gui_m_clock], 1
    jne  .degraded
    cmp  byte [rel gui_m_wm], 1
    jne  .degraded
    call gop_plane_geom
    cmp  eax, 0xFFFFFFFF
    je   .degraded
    mov  ecx, [rel fb_stride]
    cmp  byte [rel fb_scale], 2
    jne  .stride_mode
    mov  ecx, [rel fb_out_stride]       ; RCQ-16 2x GUI: the plane fetches the scanout mode
.stride_mode:
    shr  ecx, 4                         ; (pixels * 4 bytes) / 64-byte units
    cmp  eax, ecx
    jne  .degraded
    mov  ecx, [rel fb_height]
    mov  r8d, [rel fb_width]
    cmp  byte [rel fb_scale], 2
    jne  .size_mode
    mov  ecx, [rel fb_out_height]
    mov  r8d, [rel fb_out_width]
.size_mode:
    dec  ecx
    shl  ecx, 16
    dec  r8d
    or   ecx, r8d
    cmp  edx, ecx
    jne  .degraded
    mov  al, PBM_MH_READY
    ret
.degraded:
    mov  al, PBM_MH_DEGRADED
.out:
    ret

; Load the last fixed-size checkpoint record.  A missing, torn, or unknown
; value starts a fresh in-memory record; it is never guessed into policy.
boot_v2_init_checkpoint_load:
    push rbx
    push r12
    cmp  byte [rel pbm_init_checkpoint_loaded], 1
    je   .ok
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .fresh
    mov  qword [rel pbm_init_var_size], PBM_INIT_RECORD_SIZE
    mov  dword [rel pbm_init_var_attrs], 0
    lea  rcx, [rel pbm_init_var_name]
    lea  rdx, [rel pbm_init_var_guid]
    lea  r8, [rel pbm_init_var_attrs]
    lea  r9, [rel pbm_init_var_size]
    sub  rsp, 40
    lea  rbx, [rel pbm_init_checkpoint_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 40
    test rax, rax
    jnz  .fresh
    cmp  dword [rel pbm_init_var_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .fresh
    cmp  qword [rel pbm_init_var_size], PBM_INIT_RECORD_SIZE
    jne  .fresh
    cmp  dword [rel pbm_init_checkpoint_record + PBM_INIT_MAGIC_OFF], PBM_INIT_MAGIC
    jne  .fresh
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_VERSION_OFF], PBM_INIT_VERSION
    je   .loadgate_v1
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_VERSION_OFF], PBM_INIT_GRAPH_VERSION
    jne  .fresh
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_GATE_OFF], PBM_INIT_GATE_UNKNOWN
    je   .loadgate_unknown
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_GATE_OFF], 11
    ja   .fresh
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_GATE_SOURCE_OFF], PBM_INIT_GATE_NATIVE
    jne  .fresh
    jmp  .loadgate_tail
.loadgate_unknown:
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_GATE_SOURCE_OFF], 0
    jne  .fresh
.loadgate_tail:
    cmp  word [rel pbm_init_checkpoint_record + 114], 0
    jne  .fresh
    jmp  .loadgate_zero
.loadgate_v1:
    cmp  dword [rel pbm_init_checkpoint_record + 112], 0
    jne  .fresh
.loadgate_zero:
    cmp  qword [rel pbm_init_checkpoint_record + 116], 0
    jne  .fresh
.loadgate_valid:
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_SIZE_OFF], PBM_INIT_RECORD_SIZE
    jne  .fresh
    mov  ebx, [rel pbm_init_checkpoint_record + PBM_INIT_CRC32]
    lea  rdi, [rel pbm_init_checkpoint_record]
    mov  esi, PBM_INIT_CRC32
    call pbm_crc32
    cmp  eax, ebx
    jne  .fresh
    ; Pre-B1 records have a zero reserved dword and remain valid but incomplete.
    ; Once present, the normalized value must be exactly derivable from the
    ; CRC-bound stable fields; consumers never trust a caller-supplied hash.
    mov  ebx, [rel pbm_init_checkpoint_record + PBM_INIT_FAILURE_FINGERPRINT_OFF]
    test ebx, ebx
    jz   .fingerprint_compatible
    call boot_v2_normalize_failure_fingerprint
    cmp  eax, ebx
    jne  .fresh
.fingerprint_compatible:
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF]
    cmp  eax, PBM_INIT_STAGE_P8
    ja   .fresh
    mov  ecx, eax
    movzx edx, word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF]
    test edx, ~PBM_INIT_STAGE_ALL_MASK
    jnz  .fresh
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF]
    cmp  eax, PBM_INIT_TRANSITION_STARTING
    je   .validate_starting
    cmp  eax, PBM_INIT_TRANSITION_COMPLETED
    jne  .fresh
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    cmp  eax, PBM_INIT_RESULT_HEALTHY
    je   .completed_result_ok
    cmp  eax, PBM_INIT_RESULT_DEFERRED
    je   .completed_result_ok
    cmp  eax, PBM_INIT_RESULT_DISABLED
    jne  .fresh
.completed_result_ok:
    bt   edx, ecx
    jnc  .fresh
    jmp  .accepted
.validate_starting:
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    cmp  eax, PBM_INIT_RESULT_NONE
    je   .starting_result_ok
    cmp  eax, PBM_INIT_RESULT_FAILED
    jne  .fresh
.starting_result_ok:
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_SUBSYSTEM_OFF], PBM_INIT_SUBSYS_NONE
    je   .fresh
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF], PBM_INIT_SUBSYS_NONE
    je   .fresh
.accepted:
    mov  ax, [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF]
    mov  [rel pbm_init_last_implicated], ax
    mov  byte [rel pbm_init_checkpoint_loaded], 1
    mov  byte [rel pbm_init_checkpoint_durable], 1
    ; Retain the previous attempt's sanitized failure before a new nonce can
    ; reset PBIC. This diagnostic never changes checkpoint/health authority.
    mov  rax, [rel pbm_attempt_nonce]
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_ATTEMPT_NONCE_OFF]
    jne  .archive_previous
    mov  rax, [rel pbm_manager_sequence]
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_MANAGER_SEQ_OFF]
    je   .ok
.archive_previous:
    call boot_v2_failure_checkpoint_archive
.ok:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.fresh:
    mov  qword [rel pbm_init_checkpoint_record + PBM_INIT_GENERATION_OFF], 0
    call boot_v2_init_checkpoint_new_attempt
    jmp  .ok

; Sanitized diagnostic retains validated PBIC v1/v2; no nonce, raw TSC, address, free text
; or secret is retained. Input RSI=128 readable bytes, output RDI=128 distinct
; bytes. EAX=1 only for a well-formed incomplete/failed PaOS checkpoint.
; This is not authentication and is never consumed by boot selection policy.
boot_v2_failure_checkpoint_prepare:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdi
    cmp  dword [r12], PBM_INIT_MAGIC
    jne  .skip
    cmp  word [r12 + PBM_INIT_VERSION_OFF], PBM_INIT_VERSION
    je   .archivegate_v1
    cmp  word [r12 + PBM_INIT_VERSION_OFF], PBM_INIT_GRAPH_VERSION
    jne  .skip
    cmp  byte [r12 + PBM_INIT_GATE_OFF], PBM_INIT_GATE_UNKNOWN
    je   .archivegate_unknown
    cmp  byte [r12 + PBM_INIT_GATE_OFF], 11
    ja   .skip
    cmp  byte [r12 + PBM_INIT_GATE_SOURCE_OFF], PBM_INIT_GATE_NATIVE
    jne  .skip
    jmp  .archivegate_tail
.archivegate_unknown:
    cmp  byte [r12 + PBM_INIT_GATE_SOURCE_OFF], 0
    jne  .skip
.archivegate_tail:
    cmp  word [r12 + 114], 0
    jne  .skip
    jmp  .archivegate_zero
.archivegate_v1:
    cmp  dword [r12 + 112], 0
    jne  .skip
.archivegate_zero:
    cmp  qword [r12 + 116], 0
    jne  .skip
.archivegate_valid:
    cmp  word [r12 + 6], PBM_INIT_RECORD_SIZE
    jne  .skip
    mov  rdi, r12
    mov  esi, PBM_INIT_CRC32
    call pbm_crc32
    cmp  eax, [r12 + PBM_INIT_CRC32]
    jne  .skip
    cmp  qword [r12 + PBM_INIT_GENERATION_OFF], 0
    je   .skip
    cmp  byte [r12 + PBM_INIT_STAGE_OFF], PBM_INIT_STAGE_P8
    ja   .skip
    cmp  byte [r12 + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    jne  .skip
    movzx eax, byte [r12 + PBM_INIT_RESULT_OFF]
    test eax, eax
    jz   .result_ok
    cmp  eax, PBM_INIT_RESULT_FAILED
    jne  .skip
.result_ok:
    test byte [r12 + PBM_INIT_FLAGS_OFF], ~0x3F
    jnz  .skip
    movzx eax, word [r12 + PBM_INIT_SUBSYSTEM_OFF]
    dec  eax
    cmp  eax, PBM_INIT_SUBSYS_MACHINE - 1
    ja   .skip
    movzx eax, word [r12 + PBM_INIT_IMPLICATED_OFF]
    dec  eax
    cmp  eax, PBM_INIT_SUBSYS_MACHINE - 1
    ja   .skip
    movzx eax, word [r12 + PBM_INIT_DEPENDENCIES_OFF]
    or   ax, [r12 + PBM_INIT_COMPLETED_MASK_OFF]
    test eax, ~PBM_INIT_STAGE_ALL_MASK
    jnz  .skip
    movzx eax, byte [r12 + PBM_INIT_ENTRY_OFF]
    dec  eax
    cmp  eax, 1
    ja   .skip
    cmp  byte [r12 + PBM_INIT_PROFILE_OFF], PBM_PROFILE_SAFE
    ja   .skip
    movzx eax, byte [r12 + PBM_INIT_HEALTH_PREDICATE_OFF]
    dec  eax
    cmp  eax, PBM_INIT_HEALTH_MACHINE - 1
    ja   .skip
    movzx eax, byte [r12 + PBM_INIT_FAILURE_POLICY_OFF]
    dec  eax
    cmp  eax, PBM_INIT_FAILURE_DEGRADE - 1
    ja   .skip
    mov  rax, [r12 + PBM_INIT_PAYLOAD_SHA_OFF]
    or   rax, [r12 + PBM_INIT_PAYLOAD_SHA_OFF + 8]
    or   rax, [r12 + PBM_INIT_PAYLOAD_SHA_OFF + 16]
    or   rax, [r12 + PBM_INIT_PAYLOAD_SHA_OFF + 24]
    jz   .skip
    mov  rdi, r13
    mov  ecx, PBM_INIT_RECORD_SIZE / 8
    xor  eax, eax
    rep  stosq
    ; Exact allowlist of public scalar fields from the accepted checkpoint.
    mov  rsi, r12
    mov  rdi, r13
    mov  ecx, 24                        ; envelope, generation, Manager sequence
    rep  movsb
    lea  rsi, [r12 + 32]
    lea  rdi, [r13 + 32]
    mov  ecx, 16                        ; phase/result, subsystem, mask, budget
    rep  movsb
    lea  rsi, [r12 + 64]
    lea  rdi, [r13 + 64]
    mov  ecx, 40                        ; elapsed, policy, entry, payload SHA
    rep  movsb
    ; Retain only the validated v2 public gate extension. v1 stays byte exact.
    cmp  word [r12 + 4], PBM_INIT_GRAPH_VERSION
    jne  .gate_copied
    mov  ax, [r12 + PBM_INIT_GATE_OFF]
    mov  [r13 + PBM_INIT_GATE_OFF], ax
.gate_copied:
    mov  rdi, r13
    mov  esi, PBM_INIT_CRC32
    call pbm_crc32
    mov  [r13 + PBM_INIT_CRC32], eax
    mov  eax, 1
    jmp  .out
.skip:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Best effort, once on loading a DIFFERENT attempt. One SetVariable at most;
; no retry, erase, eviction, boot gate, or health acknowledgement. Existing
; unknown/corrupt archive is preserved. Returned write errors are uncertain.
; status:0=no eligible record,1=verified saved,2=unavailable/refused,3=uncertain.
boot_v2_failure_checkpoint_archive:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    push r13
    sub  rsp, 8
    mov  byte [rel pbm_failure_checkpoint_status], 0
    lea  rsi, [rel pbm_init_checkpoint_record]
    lea  rdi, [rel pbm_failure_checkpoint_record]
    call boot_v2_failure_checkpoint_prepare
    test eax, eax
    jz   .out
    mov  byte [rel pbm_failure_checkpoint_status], 2
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .out
    ; Refuse unknown existing archive schemas/errors, without repairing them.
    call boot_v2_failure_checkpoint_read
    mov  rbx, 0x800000000000000E          ; EFI_NOT_FOUND only creates genesis
    cmp  rax, rbx
    je   .write
    test rax, rax
    jnz  .out
    cmp  dword [rel pbm_failure_checkpoint_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .out
    cmp  qword [rel pbm_failure_checkpoint_size], PBM_INIT_RECORD_SIZE
    jne  .out
    lea  rsi, [rel pbm_failure_checkpoint_verify]
    lea  rdi, [rel pbm_failure_checkpoint_old]
    call boot_v2_failure_checkpoint_prepare
    test eax, eax
    jz   .out
    ; An archive must itself already be the exact sanitized projection.
    lea  rsi, [rel pbm_failure_checkpoint_verify]
    lea  rdi, [rel pbm_failure_checkpoint_old]
    mov  ecx, PBM_INIT_RECORD_SIZE / 8
    repe cmpsq
    jne  .out
.write:
    lea  rdi, [rel pbm_init_var_guid]
    lea  rsi, [rel pbm_failure_checkpoint_name]
    xor  edx, edx
    lea  rcx, [rel str_pbm_failure_checkpoint_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .out
    mov  byte [rel pbm_failure_checkpoint_status], 3
    lea  rcx, [rel pbm_failure_checkpoint_name]
    lea  rdx, [rel pbm_init_var_guid]
    mov  r8d, PBM_EFI_HEALTH_ATTRS
    mov  r9d, PBM_INIT_RECORD_SIZE
    sub  rsp, 48
    lea  rbx, [rel pbm_failure_checkpoint_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]
    add  rsp, 48
    test rax, rax
    jnz  .out
    call boot_v2_failure_checkpoint_read
    test rax, rax
    jnz  .out
    cmp  dword [rel pbm_failure_checkpoint_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .out
    cmp  qword [rel pbm_failure_checkpoint_size], PBM_INIT_RECORD_SIZE
    jne  .out
    lea  rsi, [rel pbm_failure_checkpoint_record]
    lea  rdi, [rel pbm_failure_checkpoint_verify]
    mov  ecx, PBM_INIT_RECORD_SIZE / 8
    repe cmpsq
    jne  .out
    mov  byte [rel pbm_failure_checkpoint_status], 1
.out:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

; R12=runtime table. Exact owned name/GUID, bounded read, no mutation.
boot_v2_failure_checkpoint_read:
    mov  qword [rel pbm_failure_checkpoint_size], PBM_INIT_RECORD_SIZE
    mov  dword [rel pbm_failure_checkpoint_attrs], 0
    lea  rcx, [rel pbm_failure_checkpoint_name]
    lea  rdx, [rel pbm_init_var_guid]
    lea  r8, [rel pbm_failure_checkpoint_attrs]
    lea  r9, [rel pbm_failure_checkpoint_size]
    sub  rsp, 40
    lea  rax, [rel pbm_failure_checkpoint_verify]
    mov  [rsp + 32], rax
    call [r12 + 0x48]
    add  rsp, 40
    ret

; Runtime observed native OS entry, independent of every P phase. Only a
; Manager explicitly advertising its v2 reader gets the extended live schema.
; Old/unknown/direct launch keeps byte-exact v1 tail and unchanged B1 behavior.
boot_v2_init_checkpoint_set_gate:
    mov word [rel pbm_init_checkpoint_record + PBM_INIT_VERSION_OFF],PBM_INIT_VERSION
    mov dword [rel pbm_init_checkpoint_record + 112],0
    mov qword [rel pbm_init_checkpoint_record + 116],0
    cmp byte [rel pbm_init_writer_version],PBM_INIT_GRAPH_VERSION
    jne .out
    mov word [rel pbm_init_checkpoint_record + PBM_INIT_VERSION_OFF],PBM_INIT_GRAPH_VERSION
    mov byte [rel pbm_init_checkpoint_record + PBM_INIT_GATE_OFF],4
    mov byte [rel pbm_init_checkpoint_record + PBM_INIT_GATE_SOURCE_OFF],PBM_INIT_GATE_NATIVE
.out:
    ret

; Start a new attempt while retaining only the monotonic record generation.
; The current PBH1 identity is copied so stale records cannot be attributed to
; a different Manager attempt or payload.
boot_v2_init_checkpoint_new_attempt:
    mov  rbx, [rel pbm_init_checkpoint_record + PBM_INIT_GENERATION_OFF]
    lea  rdi, [rel pbm_init_checkpoint_record]
    mov  ecx, PBM_INIT_RECORD_SIZE / 8
    xor  eax, eax
    rep  stosq
    mov  dword [rel pbm_init_checkpoint_record + PBM_INIT_MAGIC_OFF], PBM_INIT_MAGIC
    call boot_v2_init_checkpoint_set_gate
    mov  word [rel pbm_init_checkpoint_record + PBM_INIT_SIZE_OFF], PBM_INIT_RECORD_SIZE
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_GENERATION_OFF], rbx
    mov  rax, [rel pbm_manager_sequence]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_MANAGER_SEQ_OFF], rax
    mov  rax, [rel pbm_attempt_nonce]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_ATTEMPT_NONCE_OFF], rax
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], PBM_INIT_STAGE_NONE
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_NONE
    mov  word [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF], PBM_INIT_SUBSYS_NONE
    mov  al, [rel pbm_profile]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_PROFILE_OFF], al
    mov  al, [rel pbm_entry]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_ENTRY_OFF], al
    lea  rsi, [rel pbm_payload_sha]
    lea  rdi, [rel pbm_init_checkpoint_record + PBM_INIT_PAYLOAD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    mov  word [rel pbm_init_last_implicated], PBM_INIT_SUBSYS_NONE
    mov  byte [rel pbm_init_checkpoint_loaded], 1
    mov  byte [rel pbm_init_checkpoint_durable], 0
    ret

; RCQ-32 (root 2026-10-17 02:08, extends the P1CKPT contract): raw per-call
; duration of boot_v2_init_checkpoint_persist. One TSC at entry and one at the
; single exit, with the persist result and the record's own stage/transition.
; The first PBM_PERSIST_SLOTS calls are kept; pbm_persist_count counts every
; call. RAM only, read by BOOTLOG FULL. All registers and flags are preserved:
; no allocation, serial I/O, waiting, persistent write or policy change, and the
; persisted record bytes, write count and order are unchanged.
PBM_PERSIST_SLOTS    equ 32
PBM_PERSIST_ROW_SIZE equ 24             ; start q, end q, result d, stage b, transition b, pad w
%macro PBM_PERSIST_OPEN 0
    pushfq
    push rax
    push rdx
    mov  qword [rel pbm_persist_subcuts], 0
    mov  qword [rel pbm_persist_subcuts + 8], 0
    mov  qword [rel pbm_persist_subcuts + 16], 0
    mov  qword [rel pbm_persist_subcuts + 24], 0
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pbm_persist_start], rax
    pop  rdx
    pop  rax
    popfq
%endmacro
; RCQ-32: four RAM-only subcall boundaries, indexed with the existing PERSIST
; rows. Zero means not reached, including every early refusal. Prepare includes
; generation/fingerprint/CRC; gate includes argument setup; write/read include
; their argument setup and firmware return. The existing end includes exact
; compare. These are elapsed intervals, never exclusive CPU/firmware costs.
%macro PBM_PERSIST_CUT 1
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pbm_persist_subcuts + %1 * 8], rax
    pop  rdx
    pop  rax
    popfq
%endmacro
%macro PBM_PERSIST_CLOSE 0
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    mov  r8d, eax                       ; persist result (0 or PBM_INIT_RC_PERSIST)
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  ecx, [rel pbm_persist_count]
    inc  dword [rel pbm_persist_count]
    cmp  ecx, PBM_PERSIST_SLOTS
    jae  %%kept
    imul ecx, ecx, PBM_PERSIST_ROW_SIZE
    lea  rdx, [rel pbm_persist_rows]
    add  rdx, rcx
    mov  rcx, [rel pbm_persist_start]
    mov  [rdx], rcx
    mov  [rdx + 8], rax
    mov  [rdx + 16], r8d
    mov  cl, [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF]
    mov  [rdx + 20], cl
    mov  cl, [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF]
    mov  [rdx + 21], cl
    mov  ecx, [rel pbm_persist_count]
    dec  ecx
    shl  ecx, 5                        ; four qword cuts per kept entry
    lea  rdx, [rel pbm_persist_subrows]
    add  rdx, rcx
%assign cut 0
%rep 4
    mov  rax, [rel pbm_persist_subcuts + cut * 8]
    mov  [rdx + cut * 8], rax
%assign cut cut + 1
%endrep
%%kept:
    pop  r8
    pop  rdx
    pop  rcx
    pop  rax
    popfq
%endmacro

; Persist and exact-read-back one transition.  The EFI variable is the bounded
; state object; PBM_STATE0/PBM_STATE1 and all payload files remain untouched.
boot_v2_init_checkpoint_persist:
    push rbx
    push r12
    push r13
    PBM_PERSIST_OPEN
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .failed
    mov  byte [rel pbm_init_checkpoint_durable], 0
    inc  qword [rel pbm_init_checkpoint_record + PBM_INIT_GENERATION_OFF]
    ; Same existing write only, preserve deployed old Manager's B1 reader.
    call boot_v2_init_checkpoint_set_gate
    call boot_v2_normalize_failure_fingerprint
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_FAILURE_FINGERPRINT_OFF], eax
    mov  dword [rel pbm_init_checkpoint_record + PBM_INIT_CRC32], 0
    lea  rdi, [rel pbm_init_checkpoint_record]
    mov  esi, PBM_INIT_CRC32
    call pbm_crc32
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_CRC32], eax
    PBM_PERSIST_CUT 0                   ; prepared, before NVRAM admission

    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL;
    ; a refusal (registry drift) fails closed exactly like a firmware error.
    lea  rdi, [rel pbm_init_var_guid]
    lea  rsi, [rel pbm_init_var_name]
    xor  edx, edx                       ; SA_INTENT_IMPLICIT (boot-time publisher)
    lea  rcx, [rel str_pbm_nvg_tag_init]
    call storage_access_nvram_require
    PBM_PERSIST_CUT 1                   ; admission returned, preserve RAX/flags
    test rax, rax
    jnz  .failed
    lea  rcx, [rel pbm_init_var_name]
    lea  rdx, [rel pbm_init_var_guid]
    mov  r8d, PBM_EFI_HEALTH_ATTRS
    mov  r9d, PBM_INIT_RECORD_SIZE
    sub  rsp, 40
    lea  rbx, [rel pbm_init_checkpoint_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    PBM_PERSIST_CUT 2                   ; write returned, preserve EFI status
    add  rsp, 40
    test rax, rax
    jnz  .failed

    mov  qword [rel pbm_init_verify_size], PBM_INIT_RECORD_SIZE
    mov  dword [rel pbm_init_verify_attrs], 0
    lea  rcx, [rel pbm_init_var_name]
    lea  rdx, [rel pbm_init_var_guid]
    lea  r8, [rel pbm_init_verify_attrs]
    lea  r9, [rel pbm_init_verify_size]
    sub  rsp, 40
    lea  rbx, [rel pbm_init_verify_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; exact read-back
    PBM_PERSIST_CUT 3                   ; read returned, before exact validation
    add  rsp, 40
    test rax, rax
    jnz  .failed
    cmp  dword [rel pbm_init_verify_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .failed
    cmp  qword [rel pbm_init_verify_size], PBM_INIT_RECORD_SIZE
    jne  .failed
    lea  rbx, [rel pbm_init_checkpoint_record]
    lea  r13, [rel pbm_init_verify_record]
    mov  ecx, PBM_INIT_RECORD_SIZE / 8
.compare:
    mov  rax, [rbx]
    cmp  rax, [r13]
    jne  .failed
    add  rbx, 8
    add  r13, 8
    dec  ecx
    jnz  .compare
    mov  byte [rel pbm_init_checkpoint_durable], 1
    xor  eax, eax
    jmp  .out
.failed:
    mov  eax, PBM_INIT_RC_PERSIST
.out:
    PBM_PERSIST_CLOSE
    pop  r13
    pop  r12
    pop  rbx
    ret

; Close the transition's clock without waiting.  boot_ms_now is the established
; L0 time seam; before calibration it returns zero, while the raw TSC pair still
; preserves ordering evidence.
boot_v2_init_checkpoint_finish_clock:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_FINISHED_TSC_OFF], rax
    call boot_ms_now
    mov  ecx, [rel pbm_init_checkpoint_record + PBM_INIT_STARTED_MS_OFF]
    test eax, eax
    jz   .uncalibrated
    test ecx, ecx
    jz   .uncalibrated
    cmp  eax, ecx
    jb   .uncalibrated
    sub  eax, ecx
.store:
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF], eax
    ret
.uncalibrated:
    mov  dword [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF], 0
    xor  eax, eax
    ret

; boot_v2_init_checkpoint_transition
;   EDI=stage P0..P8, ESI=STARTING|COMPLETED, EDX=subsystem (0=stage primary)
; Returns PBM_INIT_RC_*.  Repeating an identical STARTING or COMPLETED edge is
; a no-write success: init and reinit callers can be safely replayed.
boot_v2_init_checkpoint_transition:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    cmp  r12d, PBM_INIT_STAGE_P8
    ja   .bad_arg
    cmp  r13d, PBM_INIT_TRANSITION_STARTING
    je   .args_ok
    cmp  r13d, PBM_INIT_TRANSITION_COMPLETED
    jne  .bad_arg
.args_ok:
    call boot_v2_init_checkpoint_load

    ; A new Manager nonce is an unambiguous new attempt.  P0 after a completed
    ; direct boot also starts a new record; an identical interrupted P0 start is
    ; intentionally idempotent and remains implicated.
    mov  rax, [rel pbm_attempt_nonce]
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_ATTEMPT_NONCE_OFF]
    jne  .new_attempt
    mov  rax, [rel pbm_manager_sequence]
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_MANAGER_SEQ_OFF]
    jne  .new_attempt
    cmp  r12d, PBM_INIT_STAGE_P0
    jne  .have_attempt
    cmp  r13d, PBM_INIT_TRANSITION_STARTING
    jne  .have_attempt
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    jne  .have_attempt
.new_attempt:
    call boot_v2_init_checkpoint_new_attempt
.have_attempt:
    lea  rbx, [rel pbm_init_graph]
    mov  eax, r12d
    shl  eax, 4
    add  rbx, rax
    test r14d, r14d
    jnz  .subsystem_ready
    movzx r14d, word [rbx + PBM_INIT_DESC_SUBSYSTEM_OFF]
.subsystem_ready:
    cmp  r14d, 0xFFFF
    ja   .bad_arg
    cmp  r13d, PBM_INIT_TRANSITION_COMPLETED
    je   .complete

    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], r12b
    jne  .check_dependencies
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    jne  .check_dependencies
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_SUBSYSTEM_OFF], r14w
    je   .ok
.check_dependencies:
    movzx r15d, word [rbx + PBM_INIT_DESC_DEPENDENCIES_OFF]
    movzx eax, word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF]
    and  eax, r15d
    cmp  eax, r15d
    jne  .dependency
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], r12b
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_NONE
    mov  al, [rbx + PBM_INIT_DESC_FLAGS_OFF]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_FLAGS_OFF], al
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_SUBSYSTEM_OFF], r14w
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF], r14w
    mov  [rel pbm_init_last_implicated], r14w
    mov  ax, [rbx + PBM_INIT_DESC_DEPENDENCIES_OFF]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_DEPENDENCIES_OFF], ax
    mov  eax, [rbx + PBM_INIT_DESC_BUDGET_MS_OFF]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_BUDGET_MS_OFF], eax
    mov  al, [rbx + PBM_INIT_DESC_HEALTH_OFF]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_HEALTH_PREDICATE_OFF], al
    mov  al, [rbx + PBM_INIT_DESC_FAILURE_OFF]
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_FAILURE_POLICY_OFF], al
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_STARTED_TSC_OFF], rax
    call boot_ms_now
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_STARTED_MS_OFF], eax
    mov  qword [rel pbm_init_checkpoint_record + PBM_INIT_FINISHED_TSC_OFF], 0
    mov  dword [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF], 0
    call boot_v2_init_checkpoint_persist
    jmp  .out

.complete:
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], r12b
    jne  .transition
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_SUBSYSTEM_OFF], r14w
    jne  .transition
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    je   .ok
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    jne  .transition
    call boot_v2_init_checkpoint_finish_clock
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF]
    test eax, eax
    jz   .complete_healthy
    cmp  eax, [rel pbm_init_checkpoint_record + PBM_INIT_BUDGET_MS_OFF]
    ja   .budget_exceeded
.complete_healthy:
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_HEALTHY
    mov  word [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF], PBM_INIT_SUBSYS_NONE
    mov  word [rel pbm_init_last_implicated], PBM_INIT_SUBSYS_NONE
    bts  word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF], r12w
    call boot_v2_init_checkpoint_persist
    jmp  .out

.budget_exceeded:
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_FAILED
    test byte [rbx + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_OPTIONAL
    jz   .budget_mandatory
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_DEFERRED
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    bts  word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF], r12w
    call boot_v2_init_checkpoint_persist
    test eax, eax
    jnz  .out
    mov  eax, PBM_INIT_RC_DEGRADED
    jmp  .out
.budget_mandatory:
    call boot_v2_init_checkpoint_persist
    test eax, eax
    jnz  .out
    mov  eax, PBM_INIT_RC_ESCALATE
    jmp  .out

.bad_arg:
    mov  eax, PBM_INIT_RC_ARGUMENT
    jmp  .out
.dependency:
    mov  eax, PBM_INIT_RC_DEPENDENCY
    jmp  .out
.transition:
    mov  eax, PBM_INIT_RC_TRANSITION
    jmp  .out
.ok:
    cmp  byte [rel pbm_init_checkpoint_durable], 1
    je   .durable_ok
    call boot_v2_init_checkpoint_persist
    jmp  .out
.durable_ok:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Resolve a STARTING edge without inventing success.
;   EDI=stage, ESI=DEFERRED|DISABLED|FAILED, EDX=subsystem.
; Optional failures become a persisted degraded completion; mandatory failures
; remain STARTING+FAILED so Safe/Manager sees the exact implicated subsystem.
boot_v2_init_checkpoint_resolve:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    cmp  r12d, PBM_INIT_STAGE_P8
    ja   .bad_arg
    cmp  r13d, PBM_INIT_RESULT_DEFERRED
    je   .result_ok
    cmp  r13d, PBM_INIT_RESULT_DISABLED
    je   .result_ok
    cmp  r13d, PBM_INIT_RESULT_FAILED
    jne  .bad_arg
.result_ok:
    call boot_v2_init_checkpoint_load
    lea  rbx, [rel pbm_init_graph]
    mov  eax, r12d
    shl  eax, 4
    add  rbx, rax
    test r14d, r14d
    jnz  .subsystem_ready
    movzx r14d, word [rbx + PBM_INIT_DESC_SUBSYSTEM_OFF]
.subsystem_ready:
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], r12b
    jne  .transition
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_SUBSYSTEM_OFF], r14w
    jne  .transition
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    jne  .need_starting
    movzx eax, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    cmp  eax, PBM_INIT_RESULT_DEFERRED
    je   .replay_degraded
    cmp  eax, PBM_INIT_RESULT_DISABLED
    jne  .transition
.replay_degraded:
    cmp  r13d, PBM_INIT_RESULT_FAILED
    je   .replay_persist
    cmp  eax, r13d
    jne  .transition
.replay_persist:
    cmp  byte [rel pbm_init_checkpoint_durable], 1
    je   .replay_done
    call boot_v2_init_checkpoint_persist
    test eax, eax
    jnz  .out
.replay_done:
    mov  eax, PBM_INIT_RC_DEGRADED
    jmp  .out
.need_starting:
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    jne  .transition
    call boot_v2_init_checkpoint_finish_clock

    cmp  r13d, PBM_INIT_RESULT_FAILED
    je   .failure
    test byte [rbx + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_OPTIONAL
    jz   .transition
    cmp  r13d, PBM_INIT_RESULT_DEFERRED
    jne  .want_disabled
    test byte [rbx + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_DEFER_SAFE
    jz   .transition
    jmp  .degraded
.want_disabled:
    test byte [rbx + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_DISABLE_SAFE
    jz   .transition
    jmp  .degraded

.failure:
    test byte [rbx + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_OPTIONAL
    jz   .mandatory
    test byte [rbx + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_DISABLE_SAFE
    jz   .optional_defer
    mov  r13d, PBM_INIT_RESULT_DISABLED
    jmp  .degraded
.optional_defer:
    mov  r13d, PBM_INIT_RESULT_DEFERRED
.degraded:
    mov  [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], r13b
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    bts  word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF], r12w
    call boot_v2_init_checkpoint_persist
    test eax, eax
    jnz  .out
    mov  eax, PBM_INIT_RC_DEGRADED
    jmp  .out
.mandatory:
    mov  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_FAILED
    call boot_v2_init_checkpoint_persist
    test eax, eax
    jnz  .out
    mov  eax, PBM_INIT_RC_ESCALATE
    jmp  .out
.bad_arg:
    mov  eax, PBM_INIT_RC_ARGUMENT
    jmp  .out
.transition:
    mov  eax, PBM_INIT_RC_TRANSITION
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Return EAX=1 only for the exact strong-core boundary. Optional network,
; display, and aggregate machine dimensions remain independently truthful and
; may degrade without minting or erasing core authority.
boot_v2_health_vector_core_valid:
    lea  rdx, [rel pbm_health_vector_record]
    cmp  dword [rdx + PBM_MH_MAGIC_OFF], PBM_MH_MAGIC
    jne  .bad
    cmp  word [rdx + PBM_MH_VERSION_OFF], PBM_MH_VERSION
    jne  .bad
    cmp  word [rdx + PBM_MH_SIZE_OFF], PBM_MH_SIZE
    jne  .bad
    cmp  byte [rdx + PBM_MH_ENTRY_OFF], PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  byte [rdx + PBM_MH_ENTRY_OFF], PBM_ENTRY_PAOS_B
    ja   .bad
    cmp  byte [rdx + PBM_MH_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne  .bad
    cmp  byte [rdx + PBM_MH_STAGE_OFF], PBM_INIT_STAGE_P8
    jne  .bad
    cmp  byte [rdx + PBM_MH_DIM_COUNT_OFF], PBM_MH_DIM_COUNT
    jne  .bad
    cmp  word [rdx + PBM_MH_COMPLETED_MASK_OFF], PBM_INIT_STAGE_ALL_MASK
    jne  .bad
    cmp  dword [rdx + PBM_MH_FAILURE_FINGERPRINT_OFF], 0
    jne  .bad
    cmp  qword [rdx + PBM_MH_MANAGER_SEQ_OFF], 0
    je   .bad
    cmp  qword [rdx + PBM_MH_ATTEMPT_NONCE_OFF], 0
    je   .bad
    cmp  qword [rdx + PBM_MH_STATE_GEN_OFF], 0
    je   .bad
    cmp  qword [rdx + PBM_MH_INIT_GEN_OFF], 0
    je   .bad
    mov  ax, [rdx + PBM_MH_FLAGS_OFF]
    test ax, 0xFFF8
    jnz  .bad
    test ax, PBM_MH_F_STRONG_CORE
    jz   .bad
    cmp  byte [rdx + PBM_MH_IMAGE_OFF], PBM_MH_READY
    jne  .bad
    cmp  byte [rdx + PBM_MH_CORE_OFF], PBM_MH_READY
    jne  .bad
    cmp  byte [rdx + PBM_MH_DESKTOP_OFF], PBM_MH_READY
    jne  .bad
    cmp  byte [rdx + PBM_MH_COMMAND_OFF], PBM_MH_READY
    jne  .bad
    cmp  byte [rdx + PBM_MH_STORAGE_OFF], PBM_MH_READY
    jne  .bad
    mov  al, [rdx + PBM_MH_NETWORK_OFF]
    cmp  al, PBM_MH_READY
    jb   .bad
    cmp  al, PBM_MH_UNAVAILABLE
    ja   .bad
    mov  cl, [rdx + PBM_MH_DISPLAY_OFF]
    cmp  cl, PBM_MH_READY
    jb   .bad
    cmp  cl, PBM_MH_UNAVAILABLE
    ja   .bad
    cmp  cl, PBM_MH_READY
    jne  .display_not_ready
    test word [rdx + PBM_MH_FLAGS_OFF], PBM_MH_F_DISPLAY_ESTABLISHED
    jz   .bad
    jmp  .optional_relation
.display_not_ready:
    test word [rdx + PBM_MH_FLAGS_OFF], PBM_MH_F_DISPLAY_ESTABLISHED
    jnz  .bad
.optional_relation:
    cmp  al, PBM_MH_READY
    jne  .optional_degraded
    cmp  cl, PBM_MH_READY
    jne  .optional_degraded
    cmp  byte [rdx + PBM_MH_MACHINE_OFF], PBM_MH_READY
    jne  .bad
    test word [rdx + PBM_MH_FLAGS_OFF], PBM_MH_F_OPTIONAL_DEGRADED
    jnz  .bad
    jmp  .digest
.optional_degraded:
    cmp  byte [rdx + PBM_MH_MACHINE_OFF], PBM_MH_DEGRADED
    jne  .bad
    test word [rdx + PBM_MH_FLAGS_OFF], PBM_MH_F_OPTIONAL_DEGRADED
    jz   .bad
.digest:
    lea  r8, [rdx + PBM_MH_PAYLOAD_SHA_OFF]
    xor  eax, eax
    xor  ecx, ecx
.digest_byte:
    or   al, [r8 + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .digest_byte
    test al, al
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

boot_v2_publish_strong_health:
    push rbx
    push r12
    HP_PUBLISH_BEGIN
    mov  byte [rel pbm_strong_health_published], 0
    ; Defense in depth: the Safe runtime latch is set only by a coherent,
    ; CRC-checked PBH1 Safe handoff. Even if a later refactor accidentally
    ; reaches this normal-only checkpoint, Safe remains BIP and cannot promote.
    HP_CURSOR 1
    cmp  byte [rel pbm_safe_runtime_active], 0
    jne  .safe_refused
    cmp  byte [rel pbm_manager_launch], 1
    jne  .skip
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz   .skip
    movzx eax, byte [rel pbm_entry]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .entry_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .skip
.entry_ok:
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .skip
    ; RCQ-28 (admin 2026-10-12 11:01:06): a Trial whose pre-EBS replay floor is
    ; FAILED or LOST has no signed remote route (command_auth refuses it), so it
    ; must not earn promotion; without the ack the Manager rolls back to the
    ; active slot. Only Trial launches are gated: on a committed slot a missing
    ; ack is a failed boot (Safe retry, rollback, then Rescue), and LOST stays
    ; sticky until an owner reseed. This writer is the only PaOSBootReady
    ; publisher, so this covers every caller. NONE, HELD and MIRROR_FAILED
    ; publish as before.
    HP_CURSOR 2
    test byte [rel pbm_flags], PBM_HF_TRIAL
    jz   .replay_floor_ok
    cmp  byte [rel rpf_state], RPF_FAILED
    je   .replay_floor_refused
    cmp  byte [rel rpf_state], RPF_LOST
    je   .replay_floor_refused
.replay_floor_ok:
    HP_CURSOR 3
    cmp  qword [rel pbm_manager_sequence], 0
    je   .fail
    cmp  qword [rel pbm_attempt_nonce], 0
    je   .fail
    cmp  qword [rel pbm_state_generation], 0
    je   .fail
    lea  rbx, [rel pbm_payload_sha]
    xor  edx, edx
    xor  ecx, ecx
.digest_nonzero:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .digest_nonzero
    test dl, dl
    jz   .fail
    HP_CURSOR 4
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .fail
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .fail

    ; Detailed evidence is published first. Required core dimensions may veto
    ; the compact promotion acknowledgement; optional dimensions may degrade.
    ; The bounded black box remains telemetry and never mints authority.
    sub  rsp, 8
    HP_CURSOR 5
    call boot_v2_publish_health_blackbox
    add  rsp, 8
    test eax, eax
    jnz  .fail

    lea  rdi, [rel pbm_health_record]
    mov  ecx, PBM_HEALTH_SIZE / 8
    xor  eax, eax
    rep  stosq
    mov  dword [rel pbm_health_record + PBM_HEALTH_MAGIC_OFF], PBM_HEALTH_MAGIC
    mov  word [rel pbm_health_record + PBM_HEALTH_VERSION_OFF], PBM_CONTRACT_VERSION
    mov  word [rel pbm_health_record + PBM_HEALTH_SIZE_OFF], PBM_HEALTH_SIZE
    mov  rax, [rel pbm_manager_sequence]
    mov  [rel pbm_health_record + PBM_HEALTH_MANAGER_SEQ_OFF], rax
    mov  rax, [rel pbm_attempt_nonce]
    mov  [rel pbm_health_record + PBM_HEALTH_ATTEMPT_NONCE_OFF], rax
    mov  rax, [rel pbm_state_generation]
    mov  [rel pbm_health_record + PBM_HEALTH_STATE_GEN_OFF], rax
    mov  al, [rel pbm_entry]
    mov  [rel pbm_health_record + PBM_HEALTH_ENTRY_OFF], al
    mov  al, [rel pbm_profile]
    mov  [rel pbm_health_record + PBM_HEALTH_PROFILE_OFF], al
    mov  word [rel pbm_health_record + PBM_HEALTH_CHECKPOINT_OFF], PBM_HEALTH_CHECKPOINT_STRONG
    lea  rsi, [rel pbm_payload_sha]
    lea  rdi, [rel pbm_health_record + PBM_HEALTH_PAYLOAD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    lea  rdi, [rel pbm_health_record]
    mov  esi, PBM_HEALTH_CRC32
    call pbm_crc32
    mov  [rel pbm_health_record + PBM_HEALTH_CRC32], eax

    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL;
    ; a refusal (registry drift) fails closed exactly like a firmware error.
    lea  rdi, [rel pbm_health_var_guid]
    lea  rsi, [rel pbm_health_var_name]
    xor  edx, edx                       ; SA_INTENT_IMPLICIT (boot-time publisher)
    lea  rcx, [rel str_pbm_nvg_tag_health]
    HP_CURSOR 6
    call storage_access_nvram_require
    HP_RETURNED 3
    test rax, rax
    jnz  .fail
    lea  rcx, [rel pbm_health_var_name]
    lea  rdx, [rel pbm_health_var_guid]
    mov  r8d, PBM_EFI_HEALTH_ATTRS
    mov  r9d, PBM_HEALTH_SIZE
    sub  rsp, 40
    lea  rbx, [rel pbm_health_record]
    mov  [rsp + 32], rbx
    HP_CURSOR 7
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    HP_RETURNED 4
    add  rsp, 40
    test rax, rax
    jnz  .fail
    mov  byte [rel pbm_strong_health_published], 1
    lea  rdi, [rel str_pbm_health_published]
    call serial_string
    HP_OUTCOME 1
    xor  eax, eax
    jmp  .out
.fail:
    HP_OUTCOME 2
    lea  rdi, [rel str_pbm_health_failed]
    call serial_string
    mov  eax, 1
    jmp  .out
.skip:
    HP_OUTCOME 3
    xor  eax, eax
    jmp  .out
.replay_floor_refused:
    HP_OUTCOME 4
    lea  rdi, [rel str_pbm_health_replay_floor_refused]
    call serial_string
    mov  eax, 1
    jmp  .out
.safe_refused:
    HP_OUTCOME 5
    lea  rdi, [rel str_pbm_health_safe_refused]
    call serial_string
    xor  eax, eax
.out:
    HP_RETURNED 7
    pop  r12
    pop  rbx
    ret

; Independently reversible multidimensional-health and bounded-black-box seam.
boot_v2_publish_health_blackbox:
    push rbx
    push r12
    push r13
    push r14
    push r15

    HP_CURSOR 10
    mov  byte [rel pbm_health_vector_published], 0
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .vector_failed
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .vector_failed

    ; The exact image digest/Manager identity were checked by the caller.  These
    ; live latches independently prove desktop, command, and storage readiness.
    HP_CURSOR 11
    cmp  byte [rel boot_p7_reached], 1
    jne  .vector_failed
    HP_CURSOR 12
    call command_verb_count
    test rax, rax
    jz   .vector_failed
    HP_CURSOR 13
    call blk_select
    test rax, rax
    jz   .vector_failed

    lea  rdi, [rel pbm_health_vector_record]
    mov  ecx, PBM_MH_SIZE / 8
    xor  eax, eax
    rep  stosq
    mov  dword [rel pbm_health_vector_record + PBM_MH_MAGIC_OFF], PBM_MH_MAGIC
    mov  word [rel pbm_health_vector_record + PBM_MH_VERSION_OFF], PBM_MH_VERSION
    mov  word [rel pbm_health_vector_record + PBM_MH_SIZE_OFF], PBM_MH_SIZE
    mov  rax, [rel pbm_state_generation]
    mov  [rel pbm_health_vector_record + PBM_MH_GENERATION_OFF], rax
    mov  [rel pbm_health_vector_record + PBM_MH_STATE_GEN_OFF], rax
    mov  rax, [rel pbm_manager_sequence]
    mov  [rel pbm_health_vector_record + PBM_MH_MANAGER_SEQ_OFF], rax
    mov  rax, [rel pbm_attempt_nonce]
    mov  [rel pbm_health_vector_record + PBM_MH_ATTEMPT_NONCE_OFF], rax
    mov  rax, [rel pbm_init_checkpoint_record + PBM_INIT_GENERATION_OFF]
    mov  [rel pbm_health_vector_record + PBM_MH_INIT_GEN_OFF], rax
    lea  rsi, [rel pbm_payload_sha]
    lea  rdi, [rel pbm_health_vector_record + PBM_MH_PAYLOAD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    mov  al, [rel pbm_entry]
    mov  [rel pbm_health_vector_record + PBM_MH_ENTRY_OFF], al
    mov  al, [rel pbm_profile]
    mov  [rel pbm_health_vector_record + PBM_MH_PROFILE_OFF], al
    mov  al, [rel pbm_reason]
    mov  [rel pbm_health_vector_record + PBM_MH_REASON_OFF], al
    mov  byte [rel pbm_health_vector_record + PBM_MH_STAGE_OFF], PBM_INIT_STAGE_P8
    mov  byte [rel pbm_health_vector_record + PBM_MH_IMAGE_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_CORE_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_DESKTOP_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_COMMAND_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_STORAGE_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_DIM_COUNT_OFF], PBM_MH_DIM_COUNT
    mov  word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], PBM_MH_F_STRONG_CORE
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_FAILURE_FINGERPRINT_OFF]
    mov  [rel pbm_health_vector_record + PBM_MH_FAILURE_FINGERPRINT_OFF], eax

    ; Network is optional at the strong core checkpoint.  Preserve WARMING as
    ; DEGRADED and PARKED as UNAVAILABLE; neither may impersonate READY.
    mov  al, PBM_MH_DEGRADED
    cmp  byte [rel boot_nic_state], NIC_ST_READY
    je   .network_ready
    cmp  byte [rel boot_nic_state], NIC_ST_PARKED
    jne  .network_store
    mov  al, PBM_MH_UNAVAILABLE
    jmp  .network_store
.network_ready:
    mov  al, PBM_MH_READY
.network_store:
    mov  [rel pbm_health_vector_record + PBM_MH_NETWORK_OFF], al

    ; Display is an independent optional dimension.  It is earned only after
    ; the established compositor path, never from GOP discovery/mode-set alone.
    call boot_v2_display_output_status
    mov  [rel pbm_health_vector_record + PBM_MH_DISPLAY_OFF], al
    cmp  al, PBM_MH_READY
    jne  .display_stored
    or   word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], PBM_MH_F_DISPLAY_ESTABLISHED
.display_stored:

    ; Full-machine READY additionally requires the separately published display
    ; and network facts. Storage was proven through the block-class seam above.
    mov  byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF], PBM_MH_READY
    cmp  byte [rel pbm_health_vector_record + PBM_MH_NETWORK_OFF], PBM_MH_READY
    jne  .machine_degraded
    cmp  byte [rel pbm_health_vector_record + PBM_MH_DISPLAY_OFF], PBM_MH_READY
    je   .machine_done
.machine_degraded:
    mov  byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF], PBM_MH_DEGRADED
    or   word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], PBM_MH_F_OPTIONAL_DEGRADED
.machine_done:
    mov  ax, [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF]
    mov  [rel pbm_health_vector_record + PBM_MH_COMPLETED_MASK_OFF], ax
    mov  ax, [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF]
    mov  [rel pbm_health_vector_record + PBM_MH_IMPLICATED_OFF], ax
    mov  ax, [rel pbm_last_stage]
    mov  [rel pbm_health_vector_record + PBM_MH_PREVIOUS_STAGE_OFF], ax
    HP_CURSOR 14
    call boot_v2_health_vector_core_valid
    HP_RETURNED 5
    test eax, eax
    jz   .vector_failed
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pbm_health_vector_record + PBM_MH_PUBLISHED_TSC_OFF], rax
    lea  rdi, [rel pbm_health_vector_record]
    mov  esi, PBM_MH_CRC32
    call pbm_crc32
    mov  [rel pbm_health_vector_record + PBM_MH_CRC32], eax

    ; Fixed name/size/attributes and byte-exact read-back: record content can
    ; never redirect this write into a payload path.
    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL;
    ; a refusal (registry drift) fails closed exactly like a firmware error.
    lea  rdi, [rel pbm_telemetry_var_guid]
    lea  rsi, [rel pbm_health_vector_name]
    xor  edx, edx                       ; SA_INTENT_IMPLICIT (boot-time publisher)
    lea  rcx, [rel str_pbm_nvg_tag_vector]
    HP_CURSOR 15
    call storage_access_nvram_require
    HP_RETURNED 0
    test rax, rax
    jnz  .vector_failed
    lea  rcx, [rel pbm_health_vector_name]
    lea  rdx, [rel pbm_telemetry_var_guid]
    mov  r8d, PBM_EFI_HEALTH_ATTRS
    mov  r9d, PBM_MH_SIZE
    sub  rsp, 48
    lea  rbx, [rel pbm_health_vector_record]
    mov  [rsp + 32], rbx
    HP_CURSOR 16
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    HP_RETURNED 1
    add  rsp, 48
    test rax, rax
    jnz  .vector_failed

    mov  qword [rel pbm_health_vector_size], PBM_MH_SIZE
    mov  dword [rel pbm_health_vector_attrs], 0
    lea  rcx, [rel pbm_health_vector_name]
    lea  rdx, [rel pbm_telemetry_var_guid]
    lea  r8, [rel pbm_health_vector_attrs]
    lea  r9, [rel pbm_health_vector_size]
    sub  rsp, 48
    lea  rbx, [rel pbm_health_vector_verify]
    mov  [rsp + 32], rbx
    HP_CURSOR 17
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    HP_RETURNED 2
    add  rsp, 48
    test rax, rax
    jnz  .vector_failed
    HP_CURSOR 18
    cmp  dword [rel pbm_health_vector_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .vector_failed
    HP_CURSOR 19
    cmp  qword [rel pbm_health_vector_size], PBM_MH_SIZE
    jne  .vector_failed
    lea  rbx, [rel pbm_health_vector_record]
    lea  r13, [rel pbm_health_vector_verify]
    mov  ecx, PBM_MH_SIZE / 8
.vector_compare:
    HP_CURSOR 20
    mov  rax, [rbx]
    cmp  rax, [r13]
    jne  .vector_failed
    add  rbx, 8
    add  r13, 8
    dec  ecx
    jnz  .vector_compare
    HP_READBACK_OK
    mov  byte [rel pbm_health_vector_published], 1
    lea  rdi, [rel str_pbm_health_vector_published]
    call serial_string

    ; A black-box failure is reported but cannot inflate or erase the already
    ; proven strong-core result; this telemetry is not promotion authority.
    call boot_v2_blackbox_append
    test eax, eax
    jz   .ok
    lea  rdi, [rel str_pbm_blackbox_failed]
    call serial_string
.ok:
    xor  eax, eax
    jmp  .out
.vector_failed:
    lea  rdi, [rel str_pbm_health_vector_failed]
    call serial_string
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; boot_v2_blackbox_load(RDI=fixed name, RSI=PBM_BB_SIZE buffer)
;   -> EAX=VALID|MISSING|INVALID|INCOMPATIBLE.  Only two genuinely absent
;      copies may initialize a new history.
boot_v2_blackbox_load:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r13, rsi
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .invalid
    mov  qword [rel pbm_blackbox_io_size], PBM_BB_SIZE
    mov  dword [rel pbm_blackbox_io_attrs], 0
    mov  rcx, rbx
    lea  rdx, [rel pbm_telemetry_var_guid]
    lea  r8, [rel pbm_blackbox_io_attrs]
    lea  r9, [rel pbm_blackbox_io_size]
    sub  rsp, 48
    mov  [rsp + 32], r13
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 48
    test rax, rax
    jz   .returned
    mov  rdx, PBM_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .missing
    mov  rdx, PBM_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .incompatible
    jmp  .invalid
.returned:
    cmp  dword [rel pbm_blackbox_io_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .invalid
    cmp  qword [rel pbm_blackbox_io_size], PBM_BB_SIZE
    jne  .incompatible
    cmp  dword [r13 + PBM_BB_HDR_MAGIC_OFF], PBM_BB_MAGIC
    jne  .invalid
    cmp  word [r13 + PBM_BB_HDR_VERSION_OFF], PBM_BB_VERSION
    ja   .incompatible
    mov  rdi, r13
    call boot_v2_blackbox_validate
    test eax, eax
    jnz  .invalid
    jmp  .out
.missing:
    mov  eax, PBM_BB_LOAD_MISSING
    jmp  .out
.incompatible:
    mov  eax, PBM_BB_LOAD_INCOMPATIBLE
    jmp  .out
.invalid:
    mov  eax, PBM_BB_LOAD_INVALID
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Validate the fixed geometry, whole-copy CRC, and newest immutable slot.
boot_v2_blackbox_validate:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    cmp  dword [r12 + PBM_BB_HDR_MAGIC_OFF], PBM_BB_MAGIC
    jne  .invalid
    cmp  word [r12 + PBM_BB_HDR_VERSION_OFF], PBM_BB_VERSION
    jne  .invalid
    cmp  word [r12 + PBM_BB_HDR_SIZE_OFF], PBM_BB_SIZE
    jne  .invalid
    cmp  word [r12 + PBM_BB_HDR_SLOT_COUNT_OFF], PBM_BB_SLOT_COUNT
    jne  .invalid
    cmp  word [r12 + PBM_BB_HDR_SLOT_SIZE_OFF], PBM_BB_SLOT_SIZE
    jne  .invalid
    mov  ebx, [r12 + PBM_BB_HDR_CRC32_OFF]
    mov  dword [r12 + PBM_BB_HDR_CRC32_OFF], 0
    mov  rdi, r12
    mov  esi, PBM_BB_SIZE
    call pbm_crc32
    mov  [r12 + PBM_BB_HDR_CRC32_OFF], ebx
    cmp  eax, ebx
    jne  .invalid
    movzx ebx, word [r12 + PBM_BB_HDR_COUNT_OFF]
    cmp  ebx, PBM_BB_SLOT_COUNT
    ja   .invalid
    test ebx, ebx
    jz   .empty
    movzx r15d, word [r12 + PBM_BB_HDR_WRITE_INDEX_OFF]
    cmp  r15d, PBM_BB_SLOT_COUNT
    jae  .invalid
    mov  r14, [r12 + PBM_BB_HDR_GENERATION_OFF]
.slot_loop:
    mov  eax, r15d
    imul eax, eax, PBM_BB_SLOT_SIZE
    lea  r13, [r12 + PBM_BB_HEADER_SIZE]
    add  r13, rax
    cmp  dword [r13 + PBM_BB_SLOT_MAGIC_OFF], PBM_BB_MAGIC
    jne  .invalid
    cmp  word [r13 + PBM_BB_SLOT_VERSION_OFF], PBM_BB_VERSION
    jne  .invalid
    cmp  word [r13 + PBM_BB_SLOT_SIZE_OFF], PBM_BB_SLOT_SIZE
    jne  .invalid
    cmp  [r13 + PBM_BB_SLOT_GENERATION_OFF], r14
    jne  .invalid
    mov  ebp, [r13 + PBM_BB_SLOT_CRC32]
    mov  rdi, r13
    mov  esi, PBM_BB_SLOT_CRC32
    call pbm_crc32
    cmp  eax, ebp
    jne  .invalid
    dec  r14                              ; serial arithmetic wraps naturally
    dec  r15d
    and  r15d, PBM_BB_SLOT_COUNT - 1
    dec  ebx
    jnz  .slot_loop
    xor  eax, eax
    jmp  .out
.empty:
    cmp  qword [r12 + PBM_BB_HDR_GENERATION_OFF], 0
    jne  .invalid
    xor  eax, eax
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Compare two uint64 generations using half-range serial arithmetic.
; RAX=first, RDX=second; EAX={FIRST_NEWER,SECOND_NEWER,EQUAL,AMBIGUOUS}.
; Exactly 2^63 apart has no deterministic order and is refused by the caller.
boot_v2_blackbox_generation_compare:
    cmp  rax, rdx
    je   .equal
    mov  rcx, rax
    sub  rcx, rdx
    mov  rax, 0x8000000000000000
    cmp  rcx, rax
    je   .ambiguous
    test rcx, rcx
    js   .second_newer
    mov  eax, PBM_BB_GEN_FIRST_NEWER
    ret
.second_newer:
    mov  eax, PBM_BB_GEN_SECOND_NEWER
    ret
.ambiguous:
    mov  eax, PBM_BB_GEN_AMBIGUOUS
    ret
.equal:
    mov  eax, PBM_BB_GEN_EQUAL
    ret

; Read reset-cause CMOS through the project's proven NMI-safe 0x70/0x71
; sequence.  This helper is read-only and cannot affect boot selection state.
boot_v2_blackbox_read_reset_cause:
    mov  al, PBM_CMOS_RESET_REASON
    or   al, 0x80
    mov  dx, 0x70
    out  dx, al
    mov  dx, 0x71
    in   al, dx
    ret

; QEMU-only product KAT for the generation relation used by selection.  The
; host scenario owns every write cut/corruption replay; this marker is earned
; only when the production comparator proves equality, wrap, and ambiguity.
boot_v2_blackbox_qemu_selftest:
%ifdef PAOS_GE_C6_QEMU_SCENARIO
    xor  eax, eax
    xor  edx, edx
    call boot_v2_blackbox_generation_compare
    cmp  eax, PBM_BB_GEN_EQUAL
    jne  .out
    mov  rax, 1
    xor  edx, edx
    call boot_v2_blackbox_generation_compare
    cmp  eax, PBM_BB_GEN_FIRST_NEWER
    jne  .out
    xor  eax, eax
    mov  rdx, -1
    call boot_v2_blackbox_generation_compare
    cmp  eax, PBM_BB_GEN_FIRST_NEWER
    jne  .out
    mov  rax, -1
    xor  edx, edx
    call boot_v2_blackbox_generation_compare
    cmp  eax, PBM_BB_GEN_SECOND_NEWER
    jne  .out
    xor  eax, eax
    mov  rdx, 0x8000000000000000
    call boot_v2_blackbox_generation_compare
    cmp  eax, PBM_BB_GEN_AMBIGUOUS
    jne  .out
    mov  eax, PBM_BB_SLOT_COUNT - 1
    inc  eax
    and  eax, PBM_BB_SLOT_COUNT - 1
    jnz  .out
    mov  rax, -1
    inc  rax
    jnz  .out
    lea  rdi, [rel str_pbm_ge_c6_qemu_pass]
    call serial_string
.out:
%endif
    ret

; Append one record and alternate whole-copy destinations.  Equal-generation
; split brain and newer incompatible schemas are refused instead of guessed.
boot_v2_blackbox_append:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel pbm_blackbox_last_valid], 0
    lea  rdi, [rel pbm_blackbox_name0]
    lea  rsi, [rel pbm_blackbox_record]
    call boot_v2_blackbox_load
    mov  r14d, eax
    lea  rdi, [rel pbm_blackbox_name1]
    lea  rsi, [rel pbm_blackbox_verify]
    call boot_v2_blackbox_load
    mov  r13d, eax

    test r14d, r14d
    jnz  .copy0_not_valid
    test r13d, r13d
    jnz  .copy1_not_valid
    mov  rax, [rel pbm_blackbox_record + PBM_BB_HDR_GENERATION_OFF]
    mov  rdx, [rel pbm_blackbox_verify + PBM_BB_HDR_GENERATION_OFF]
    call boot_v2_blackbox_generation_compare
    cmp  eax, PBM_BB_GEN_FIRST_NEWER
    je   .use_copy0
    cmp  eax, PBM_BB_GEN_SECOND_NEWER
    je   .use_copy1
    cmp  eax, PBM_BB_GEN_AMBIGUOUS
    je   .failed
    lea  rbx, [rel pbm_blackbox_record]
    lea  r12, [rel pbm_blackbox_verify]
    mov  ecx, PBM_BB_SIZE / 8
.equal_compare:
    mov  rax, [rbx]
    cmp  rax, [r12]
    jne  .failed
    add  rbx, 8
    add  r12, 8
    dec  ecx
    jnz  .equal_compare
    jmp  .use_copy0
.copy1_not_valid:
    cmp  r13d, PBM_BB_LOAD_INCOMPATIBLE
    je   .failed
.use_copy0:
    lea  r15, [rel pbm_blackbox_name1]
    jmp  .selected
.copy0_not_valid:
    test r13d, r13d
    jnz  .neither_valid
    cmp  r14d, PBM_BB_LOAD_INCOMPATIBLE
    je   .failed
    jmp  .use_copy1
.neither_valid:
    cmp  r14d, PBM_BB_LOAD_MISSING
    jne  .failed
    cmp  r13d, PBM_BB_LOAD_MISSING
    jne  .failed
    lea  rdi, [rel pbm_blackbox_record]
    mov  ecx, PBM_BB_SIZE / 8
    xor  eax, eax
    rep  stosq
    mov  dword [rel pbm_blackbox_record + PBM_BB_HDR_MAGIC_OFF], PBM_BB_MAGIC
    mov  word [rel pbm_blackbox_record + PBM_BB_HDR_VERSION_OFF], PBM_BB_VERSION
    mov  word [rel pbm_blackbox_record + PBM_BB_HDR_SIZE_OFF], PBM_BB_SIZE
    mov  word [rel pbm_blackbox_record + PBM_BB_HDR_WRITE_INDEX_OFF], PBM_BB_SLOT_COUNT - 1
    mov  word [rel pbm_blackbox_record + PBM_BB_HDR_SLOT_COUNT_OFF], PBM_BB_SLOT_COUNT
    mov  word [rel pbm_blackbox_record + PBM_BB_HDR_SLOT_SIZE_OFF], PBM_BB_SLOT_SIZE
    lea  r15, [rel pbm_blackbox_name0]
    jmp  .selected
.use_copy1:
    lea  rsi, [rel pbm_blackbox_verify]
    lea  rdi, [rel pbm_blackbox_record]
    mov  ecx, PBM_BB_SIZE / 8
    rep  movsq
    lea  r15, [rel pbm_blackbox_name0]
.selected:
    lea  r12, [rel pbm_blackbox_record]
    mov  r14, [r12 + PBM_BB_HDR_GENERATION_OFF]
    inc  r14
    mov  [r12 + PBM_BB_HDR_GENERATION_OFF], r14
    mov  rax, [rel pbm_manager_sequence]
    mov  [r12 + PBM_BB_HDR_MANAGER_SEQ_OFF], rax
    mov  rax, [rel pbm_attempt_nonce]
    mov  [r12 + PBM_BB_HDR_ATTEMPT_NONCE_OFF], rax
    movzx eax, word [r12 + PBM_BB_HDR_WRITE_INDEX_OFF]
    inc  eax
    and  eax, PBM_BB_SLOT_COUNT - 1
    mov  [r12 + PBM_BB_HDR_WRITE_INDEX_OFF], ax
    movzx edx, word [r12 + PBM_BB_HDR_COUNT_OFF]
    cmp  edx, PBM_BB_SLOT_COUNT
    jae  .count_done
    inc  edx
    mov  [r12 + PBM_BB_HDR_COUNT_OFF], dx
.count_done:
    imul eax, eax, PBM_BB_SLOT_SIZE
    lea  r13, [r12 + PBM_BB_HEADER_SIZE]
    add  r13, rax
    mov  rdi, r13
    mov  ecx, PBM_BB_SLOT_SIZE / 8
    xor  eax, eax
    rep  stosq
    mov  dword [r13 + PBM_BB_SLOT_MAGIC_OFF], PBM_BB_MAGIC
    mov  word [r13 + PBM_BB_SLOT_VERSION_OFF], PBM_BB_VERSION
    mov  word [r13 + PBM_BB_SLOT_SIZE_OFF], PBM_BB_SLOT_SIZE
    mov  [r13 + PBM_BB_SLOT_GENERATION_OFF], r14
    mov  rax, [rel pbm_attempt_nonce]
    mov  [r13 + PBM_BB_SLOT_NONCE_OFF], rax
    mov  rax, [rel pbm_manager_sequence]
    mov  [r13 + PBM_BB_SLOT_MANAGER_SEQ_OFF], rax
    mov  rax, [rel pbm_state_generation]
    mov  [r13 + PBM_BB_SLOT_STATE_GEN_OFF], rax
    lea  rsi, [rel pbm_payload_sha]
    lea  rdi, [r13 + PBM_BB_SLOT_BUILD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    mov  al, [rel pbm_entry]
    mov  [r13 + PBM_BB_SLOT_ENTRY_OFF], al
    mov  al, [rel pbm_profile]
    mov  [r13 + PBM_BB_SLOT_PROFILE_OFF], al
    mov  al, [rel pbm_reason]
    mov  [r13 + PBM_BB_SLOT_REASON_OFF], al
    xor  ecx, ecx
    cmp  al, PBM_REASON_ROLLBACK
    je   .recovery_rollback
    cmp  al, PBM_REASON_SAFE_RETRY
    je   .recovery_safe
    cmp  al, PBM_REASON_RESCUE
    je   .recovery_rescue
    cmp  al, PBM_REASON_INVALID_STATE
    je   .recovery_invalid
    cmp  al, PBM_REASON_INVALID_PAYLOAD
    jne  .recovery_store
.recovery_invalid:
    mov  cl, PBM_BB_RECOVERY_INVALID
    jmp  .recovery_store
.recovery_rollback:
    mov  cl, PBM_BB_RECOVERY_ROLLBACK
    jmp  .recovery_store
.recovery_safe:
    mov  cl, PBM_BB_RECOVERY_SAFE
    jmp  .recovery_store
.recovery_rescue:
    mov  cl, PBM_BB_RECOVERY_RESCUE
.recovery_store:
    mov  [r13 + PBM_BB_SLOT_RECOVERY_OFF], cl
    call boot_v2_blackbox_read_reset_cause
    mov  [r13 + PBM_BB_SLOT_RESET_CAUSE_OFF], al
    mov  byte [r13 + PBM_BB_SLOT_STARTED_STAGE_OFF], PBM_INIT_STAGE_P8
    mov  al, PBM_INIT_STAGE_P7
    cmp  byte [rel boot_nic_state], NIC_ST_WARMING
    je   .completed_stage_store
    mov  al, PBM_INIT_STAGE_P8
.completed_stage_store:
    mov  [r13 + PBM_BB_SLOT_COMPLETED_STAGE_OFF], al
    mov  byte [r13 + PBM_BB_SLOT_DIM_COUNT_OFF], PBM_MH_DIM_COUNT
    lea  rsi, [rel pbm_health_vector_record + PBM_MH_IMAGE_OFF]
    lea  rdi, [r13 + PBM_BB_SLOT_DIMS_OFF]
    mov  ecx, PBM_MH_DIM_COUNT
    rep  movsb
    mov  rax, [rel pbm_init_checkpoint_record + PBM_INIT_GENERATION_OFF]
    mov  [r13 + PBM_BB_SLOT_INIT_GEN_OFF], rax
    mov  ax, [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF]
    mov  [r13 + PBM_BB_SLOT_COMPLETED_MASK_OFF], ax
    mov  ax, [rel pbm_init_checkpoint_record + PBM_INIT_IMPLICATED_OFF]
    mov  [r13 + PBM_BB_SLOT_IMPLICATED_OFF], ax
    mov  ax, [rel pbm_last_stage]
    mov  [r13 + PBM_BB_SLOT_PREVIOUS_STAGE_OFF], ax
    mov  ax, [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF]
    mov  [r13 + PBM_BB_SLOT_FLAGS_OFF], ax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [r13 + PBM_BB_SLOT_PUBLISHED_TSC_OFF], rax
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_FAILURE_FINGERPRINT_OFF]
    mov  [r13 + PBM_BB_SLOT_FAILURE_FINGERPRINT_OFF], eax
    mov  rdi, r13
    mov  esi, PBM_BB_SLOT_CRC32
    call pbm_crc32
    mov  [r13 + PBM_BB_SLOT_CRC32], eax
    mov  dword [r12 + PBM_BB_HDR_CRC32_OFF], 0
    mov  rdi, r12
    mov  esi, PBM_BB_SIZE
    call pbm_crc32
    mov  [r12 + PBM_BB_HDR_CRC32_OFF], eax

    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL;
    ; a refusal (registry drift) fails closed exactly like a firmware error.
    lea  rdi, [rel pbm_telemetry_var_guid]
    mov  rsi, r15
    xor  edx, edx                       ; SA_INTENT_IMPLICIT (boot-time publisher)
    lea  rcx, [rel str_pbm_nvg_tag_blackbox]
    call storage_access_nvram_require
    test rax, rax
    jnz  .failed
    mov  rcx, r15
    lea  rdx, [rel pbm_telemetry_var_guid]
    mov  r8d, PBM_EFI_HEALTH_ATTRS
    mov  r9d, PBM_BB_SIZE
    sub  rsp, 48
    mov  [rsp + 32], r12
    mov  rbx, [rel runtime_services]
    call [rbx + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    add  rsp, 48
    test rax, rax
    jnz  .failed
    mov  qword [rel pbm_blackbox_io_size], PBM_BB_SIZE
    mov  dword [rel pbm_blackbox_io_attrs], 0
    mov  rcx, r15
    lea  rdx, [rel pbm_telemetry_var_guid]
    lea  r8, [rel pbm_blackbox_io_attrs]
    lea  r9, [rel pbm_blackbox_io_size]
    sub  rsp, 48
    lea  rbx, [rel pbm_blackbox_verify]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 48
    test rax, rax
    jnz  .failed
    cmp  dword [rel pbm_blackbox_io_attrs], PBM_EFI_HEALTH_ATTRS
    jne  .failed
    cmp  qword [rel pbm_blackbox_io_size], PBM_BB_SIZE
    jne  .failed
    lea  rbx, [rel pbm_blackbox_record]
    lea  r13, [rel pbm_blackbox_verify]
    mov  ecx, PBM_BB_SIZE / 8
.readback_compare:
    mov  rax, [rbx]
    cmp  rax, [r13]
    jne  .failed
    add  rbx, 8
    add  r13, 8
    dec  ecx
    jnz  .readback_compare
    mov  byte [rel pbm_blackbox_last_valid], 1
    lea  rdi, [rel str_pbm_blackbox_published]
    call serial_string
    xor  eax, eax
    jmp  .append_out
.failed:
    mov  eax, 1
.append_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Select the sole safe next action after a persistent cut.
;   EDI=cut, ESI=candidate readback exact, EDX=manifest exact,
;   ECX=strong health, R8D=failed Trial.
; Manifest and journal ordering are explicit: neither Trial nor promotion can
; be selected from an unverified predecessor state.
boot_v2_ge_c5_resume_action:
    cmp  edi, C5_TX_STABLE
    je   .write_candidate
    cmp  edi, C5_TX_CANDIDATE_EXACT
    je   .candidate
    cmp  edi, C5_TX_MANIFEST_EXACT
    je   .manifest
    cmp  edi, C5_TX_TRIAL_ARMED
    je   .trial_armed
    cmp  edi, C5_TX_TRIAL_ENTERED
    je   .trial_entered
    cmp  edi, C5_TX_PROMOTED
    je   .done
    jmp  .refuse
.candidate:
    cmp  esi, 1
    jne  .write_candidate
    mov  eax, C5_TX_ACTION_WRITE_MANIFEST
    ret
.manifest:
    cmp  esi, 1
    jne  .write_candidate
    cmp  edx, 1
    jne  .write_manifest
    mov  eax, C5_TX_ACTION_WRITE_JOURNAL
    ret
.trial_armed:
    cmp  esi, 1
    jne  .refuse
    cmp  edx, 1
    jne  .refuse
    mov  eax, C5_TX_ACTION_BOOT_TRIAL
    ret
.trial_entered:
    cmp  r8d, 1
    je   .rollback
    cmp  ecx, 1
    jne  .rollback
    mov  eax, C5_TX_ACTION_PROMOTE
    ret
.write_candidate:
    mov  eax, C5_TX_ACTION_WRITE_CANDIDATE
    ret
.write_manifest:
    mov  eax, C5_TX_ACTION_WRITE_MANIFEST
    ret
.rollback:
    mov  eax, C5_TX_ACTION_ROLLBACK
    ret
.done:
    mov  eax, C5_TX_ACTION_DONE
    ret
.refuse:
    mov  eax, C5_TX_ACTION_REFUSE
    ret

; QEMU-only product KAT.  The Phase-6 host scenario tears every durable cut,
; replays failed/healthy Trial outcomes, and models the canonical rollback /
; reactivation interval.  This marker is earned only when the production
; checkpoint graph and the fail-closed next-action selector retain their shape.
boot_v2_ge_c5_qemu_selftest:
%ifdef PAOS_GE_C5_QEMU_SCENARIO
    cmp  byte [rel pbm_init_graph + PBM_INIT_DESC_STAGE_OFF], PBM_INIT_STAGE_P0
    jne  .out
    test byte [rel pbm_init_graph + PBM_INIT_DESC_FLAGS_OFF], PBM_INIT_F_MANDATORY
    jz   .out
    cmp  byte [rel pbm_init_graph + (PBM_INIT_STAGE_P8 * PBM_INIT_DESC_SIZE) + PBM_INIT_DESC_STAGE_OFF], PBM_INIT_STAGE_P8
    jne  .out
    mov  al, [rel pbm_init_graph + (PBM_INIT_STAGE_P8 * PBM_INIT_DESC_SIZE) + PBM_INIT_DESC_FLAGS_OFF]
    and  al, PBM_INIT_F_OPTIONAL | PBM_INIT_F_DEFER_SAFE | PBM_INIT_F_DISABLE_SAFE
    cmp  al, PBM_INIT_F_OPTIONAL | PBM_INIT_F_DEFER_SAFE | PBM_INIT_F_DISABLE_SAFE
    jne  .out

    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
    xor  r8d, r8d
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_WRITE_CANDIDATE
    jne  .out
    mov  edi, C5_TX_CANDIDATE_EXACT
    mov  esi, 1
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_WRITE_MANIFEST
    jne  .out
    mov  edi, C5_TX_MANIFEST_EXACT
    mov  edx, 1
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_WRITE_JOURNAL
    jne  .out
    mov  edi, C5_TX_TRIAL_ARMED
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_BOOT_TRIAL
    jne  .out
    mov  edi, C5_TX_TRIAL_ENTERED
    mov  ecx, 1
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_PROMOTE
    jne  .out
    mov  r8d, 1
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_ROLLBACK
    jne  .out
    mov  edi, C5_TX_PROMOTED
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_DONE
    jne  .out
    mov  edi, C5_TX_TRIAL_ARMED
    xor  edx, edx
    call boot_v2_ge_c5_resume_action
    cmp  eax, C5_TX_ACTION_REFUSE
    jne  .out
    lea  rdi, [rel str_pbm_ge_c5_qemu_pass]
    call serial_string
.out:
%endif
    ret

; QEMU-only product KAT over the same fail-closed predicate used by production.
; It leaves the record clear for the real P8 publication later in boot.
boot_v2_ge_c7_qemu_selftest:
%ifdef PAOS_GE_C7_QEMU_SCENARIO
    lea  rdi, [rel pbm_health_vector_record]
    mov  ecx, PBM_MH_SIZE / 8
    xor  eax, eax
    rep  stosq
    mov  dword [rel pbm_health_vector_record + PBM_MH_MAGIC_OFF], PBM_MH_MAGIC
    mov  word [rel pbm_health_vector_record + PBM_MH_VERSION_OFF], PBM_MH_VERSION
    mov  word [rel pbm_health_vector_record + PBM_MH_SIZE_OFF], PBM_MH_SIZE
    mov  qword [rel pbm_health_vector_record + PBM_MH_MANAGER_SEQ_OFF], 7
    mov  qword [rel pbm_health_vector_record + PBM_MH_ATTEMPT_NONCE_OFF], 8
    mov  qword [rel pbm_health_vector_record + PBM_MH_STATE_GEN_OFF], 9
    mov  qword [rel pbm_health_vector_record + PBM_MH_INIT_GEN_OFF], 10
    mov  qword [rel pbm_health_vector_record + PBM_MH_PAYLOAD_SHA_OFF], 11
    mov  byte [rel pbm_health_vector_record + PBM_MH_ENTRY_OFF], PBM_ENTRY_PAOS_A
    mov  byte [rel pbm_health_vector_record + PBM_MH_PROFILE_OFF], PBM_PROFILE_NORMAL
    mov  byte [rel pbm_health_vector_record + PBM_MH_STAGE_OFF], PBM_INIT_STAGE_P8
    mov  byte [rel pbm_health_vector_record + PBM_MH_DIM_COUNT_OFF], PBM_MH_DIM_COUNT
    mov  word [rel pbm_health_vector_record + PBM_MH_COMPLETED_MASK_OFF], PBM_INIT_STAGE_ALL_MASK
    mov  word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], (PBM_MH_F_STRONG_CORE | PBM_MH_F_DISPLAY_ESTABLISHED)
    mov  byte [rel pbm_health_vector_record + PBM_MH_IMAGE_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_CORE_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_DESKTOP_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_COMMAND_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_STORAGE_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_NETWORK_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_DISPLAY_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF], PBM_MH_READY
    call boot_v2_health_vector_core_valid
    cmp  eax, 1
    jne  .clear

    mov  byte [rel pbm_health_vector_record + PBM_MH_STAGE_OFF], PBM_INIT_STAGE_P7
    call boot_v2_health_vector_core_valid
    test eax, eax
    jnz  .clear
    mov  byte [rel pbm_health_vector_record + PBM_MH_STAGE_OFF], PBM_INIT_STAGE_P8
    mov  byte [rel pbm_health_vector_record + PBM_MH_PROFILE_OFF], PBM_PROFILE_SAFE
    call boot_v2_health_vector_core_valid
    test eax, eax
    jnz  .clear
    mov  byte [rel pbm_health_vector_record + PBM_MH_PROFILE_OFF], PBM_PROFILE_NORMAL
    mov  qword [rel pbm_health_vector_record + PBM_MH_ATTEMPT_NONCE_OFF], 0
    call boot_v2_health_vector_core_valid
    test eax, eax
    jnz  .clear
    mov  qword [rel pbm_health_vector_record + PBM_MH_ATTEMPT_NONCE_OFF], 8

    mov  byte [rel pbm_health_vector_record + PBM_MH_NETWORK_OFF], PBM_MH_DEGRADED
    mov  byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF], PBM_MH_DEGRADED
    mov  word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], (PBM_MH_F_STRONG_CORE | PBM_MH_F_OPTIONAL_DEGRADED | PBM_MH_F_DISPLAY_ESTABLISHED)
    call boot_v2_health_vector_core_valid
    cmp  eax, 1
    jne  .clear
    mov  dword [rel pbm_health_vector_record + PBM_MH_FAILURE_FINGERPRINT_OFF], PBM_FAILURE_FINGERPRINT_TAG
    call boot_v2_health_vector_core_valid
    test eax, eax
    jnz  .clear
    mov  dword [rel pbm_health_vector_record + PBM_MH_FAILURE_FINGERPRINT_OFF], 0
    mov  byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF], PBM_MH_READY
    call boot_v2_health_vector_core_valid
    test eax, eax
    jnz  .clear

    mov  byte [rel pbm_health_vector_record + PBM_MH_NETWORK_OFF], PBM_MH_READY
    mov  byte [rel pbm_health_vector_record + PBM_MH_DISPLAY_OFF], PBM_MH_DEGRADED
    mov  byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF], PBM_MH_DEGRADED
    mov  word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], (PBM_MH_F_STRONG_CORE | PBM_MH_F_OPTIONAL_DEGRADED)
    call boot_v2_health_vector_core_valid
    cmp  eax, 1
    jne  .clear
    lea  rdi, [rel str_pbm_ge_c7_qemu_pass]
    call serial_string
.clear:
    lea  rdi, [rel pbm_health_vector_record]
    mov  ecx, PBM_MH_SIZE / 8
    xor  eax, eax
    rep  stosq
%endif
    ret

align 8
pbm_health_vector_record: times PBM_MH_SIZE db 0
pbm_health_vector_verify: times PBM_MH_SIZE db 0
pbm_health_vector_size:   dq PBM_MH_SIZE
pbm_health_vector_attrs:  dd 0
pbm_health_vector_published: db 0
align 8
pbm_blackbox_record:      times PBM_BB_SIZE db 0
pbm_blackbox_verify:      times PBM_BB_SIZE db 0
pbm_blackbox_io_size:     dq PBM_BB_SIZE
pbm_blackbox_io_attrs:    dd 0
pbm_blackbox_last_valid:  db 0
align 8
; 9d783c42-4cf3-44e8-a996-86a384c24ec1 (telemetry namespace)
pbm_telemetry_var_guid:
    dd 0x9D783C42
    dw 0x4CF3, 0x44E8
    db 0xA9,0x96,0x86,0xA3,0x84,0xC2,0x4E,0xC1
pbm_health_vector_name:
    dw 'P','a','O','S','H','e','a','l','t','h','V','e','c','t','o','r',0
pbm_blackbox_name0:
    dw 'P','a','O','S','B','o','o','t','B','l','a','c','k','B','o','x','0',0
pbm_blackbox_name1:
    dw 'P','a','O','S','B','o','o','t','B','l','a','c','k','B','o','x','1',0
str_pbm_health_vector_published: db "[PAOS64] Boot v2 health vector image/core/desktop/command/storage/network/display/machine nonce-bound and read back [boot.v2.health.vector]",13,10,0
str_pbm_health_vector_failed: db "[PAOS64] Boot v2 health vector refused: required dimension or exact read-back failed; Trial remains BIP [boot.v2.health.vector-failed]",13,10,0
str_pbm_blackbox_published: db "[PAOS64] Boot v2 bounded black box appended with alternating-copy read-back [boot.v2.blackbox.appended]",13,10,0
str_pbm_blackbox_failed: db "[PAOS64] Boot v2 bounded black box append failed; strong-core health remains independently valid [boot.v2.blackbox.failed]",13,10,0
str_pbm_ge_c5_qemu_pass: db "[boot.v2.ge.c5.scenario] GE C5 QEMU scenario PASS [boot.v2.ge.c5.scenario]",13,10,0
str_pbm_ge_c6_qemu_pass: db "[boot.v2.ge.c6.scenario] GE C6 QEMU scenario PASS [boot.v2.ge.c6.scenario]",13,10,0
str_pbm_ge_c7_qemu_pass: db "[boot.v2.ge.c7.scenario] GE C7 QEMU scenario PASS [boot.v2.ge.c7.scenario]",13,10,0

align 8
pbm_health_record: times PBM_HEALTH_SIZE db 0
pbm_runtime_code_mapped: db 0
pbm_runtime_reset_usable: db 0        ; ResetSystem lies in a covered executable runtime descriptor
pbm_strong_health_published: db 0
align 8
; c4a7c2f1-4bb5-4ae8-9c4f-6f76f7c2a051 (EFI mixed-endian GUID layout)
pbm_health_var_guid:
    dd 0xC4A7C2F1
    dw 0x4BB5, 0x4AE8
    db 0x9C,0x4F,0x6F,0x76,0xF7,0xC2,0xA0,0x51
pbm_health_var_name:
    dw 'P','a','O','S','B','o','o','t','R','e','a','d','y',0
str_pbm_health_published: db "[PAOS64] Boot v2 strong health nonce published for Manager reconciliation [boot.v2.health.published]",13,10,0
str_pbm_health_failed: db "[PAOS64] Boot v2 strong health runtime publish failed; BIP remains set [boot.v2.health.publish-failed]",13,10,0
str_pbm_health_safe_refused: db "[PAOS64] Boot v2 Safe runtime refused normal strong-health publication; Manager BIP remains authoritative [boot.v2.safe.health-refused]",13,10,0
str_pbm_health_replay_floor_refused: db "[PAOS64] Boot v2 Trial strong health withheld: replay floor FAILED/LOST, no signed remote route; BIP remains set [boot.v2.health.replay-floor-withheld]",13,10,0

align 8
; Stage, flags, dependencies, budget_ms, health, failure, primary subsystem,
; reserved.  Dependencies are cumulative: a later stage cannot be recorded as
; started while any earlier stage remains unresolved.
pbm_init_graph:
    db PBM_INIT_STAGE_P0, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0
    dd 5000
    db PBM_INIT_HEALTH_HANDOFF, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_BOOT_AUTH
    dd 0
    db PBM_INIT_STAGE_P1, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0x0001
    dd 5000
    db PBM_INIT_HEALTH_HANDOFF, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_RECOVERY_FLOOR
    dd 0
    db PBM_INIT_STAGE_P2, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0x0003
    dd 15000
    db PBM_INIT_HEALTH_CORE, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_CORE
    dd 0
    db PBM_INIT_STAGE_P3, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0x0007
    dd 5000
    db PBM_INIT_HEALTH_SERVICES, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_SERVICES
    dd 0
    db PBM_INIT_STAGE_P4, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0x000F
    dd 5000
    db PBM_INIT_HEALTH_COMMAND, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_COMMAND
    dd 0
    db PBM_INIT_STAGE_P5, PBM_INIT_F_OPTIONAL | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT | PBM_INIT_F_DEFER_SAFE | PBM_INIT_F_DISABLE_SAFE
    dw 0x001F
    dd 2000
    db PBM_INIT_HEALTH_DISPLAY, PBM_INIT_FAILURE_DEGRADE
    dw PBM_INIT_SUBSYS_DISPLAY
    dd 0
    db PBM_INIT_STAGE_P6, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0x003F
    dd 5000
    db PBM_INIT_HEALTH_UPDATE, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_UPDATE
    dd 0
    db PBM_INIT_STAGE_P7, PBM_INIT_F_MANDATORY | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT
    dw 0x007F
    dd 10000
    db PBM_INIT_HEALTH_DESKTOP, PBM_INIT_FAILURE_ESCALATE
    dw PBM_INIT_SUBSYS_DESKTOP
    dd 0
    db PBM_INIT_STAGE_P8, PBM_INIT_F_OPTIONAL | PBM_INIT_F_INIT_IDEMPOTENT | PBM_INIT_F_REINIT_IDEMPOTENT | PBM_INIT_F_DEFER_SAFE | PBM_INIT_F_DISABLE_SAFE
    dw 0x00FF
    dd 30000
    db PBM_INIT_HEALTH_MACHINE, PBM_INIT_FAILURE_DEGRADE
    dw PBM_INIT_SUBSYS_MACHINE
    dd 0
pbm_init_graph_end:

%if (pbm_init_graph_end - pbm_init_graph) != (PBM_INIT_STAGE_COUNT * PBM_INIT_DESC_SIZE)
    %error "boot-v2 P0-P8 init graph descriptor size drift"
%endif

align 8
pbm_failure_checkpoint_record: times PBM_INIT_RECORD_SIZE db 0
pbm_failure_checkpoint_verify: times PBM_INIT_RECORD_SIZE db 0
pbm_failure_checkpoint_old: times PBM_INIT_RECORD_SIZE db 0
pbm_failure_checkpoint_size: dq PBM_INIT_RECORD_SIZE
pbm_failure_checkpoint_attrs: dd 0
pbm_failure_checkpoint_status: db 0
align 2
pbm_failure_checkpoint_name:
    dw 'P','a','O','S','F','a','i','l','u','r','e','C','h','e','c','k','p','o','i','n','t',0
str_pbm_failure_checkpoint_tag: db "boot_v2_failure_checkpoint",0
pbm_init_checkpoint_record: times PBM_INIT_RECORD_SIZE db 0
pbm_init_verify_record:     times PBM_INIT_RECORD_SIZE db 0
pbm_init_var_size:          dq PBM_INIT_RECORD_SIZE
pbm_init_verify_size:       dq PBM_INIT_RECORD_SIZE
pbm_init_var_attrs:         dd 0
pbm_init_verify_attrs:      dd 0
pbm_init_last_implicated:   dw PBM_INIT_SUBSYS_NONE
pbm_init_checkpoint_loaded: db 0
pbm_init_checkpoint_durable: db 0
str_pbm_face_progress_pre:   db "[PAOS64] [boot.v2.face.progress] checkpoint=P",0
str_pbm_face_progress_mid:   db " denominator=9 cell=",0
str_pbm_face_progress_render: db " render=",0
str_pbm_face_progress_post:  db 13,10,0
align 8
; 7a965d12-c839-4a77-b1e2-906ef724438c (independent from PaOSBootReady)
pbm_init_var_guid:
    dd 0x7A965D12
    dw 0xC839, 0x4A77
    db 0xB1,0xE2,0x90,0x6E,0xF7,0x24,0x43,0x8C
pbm_init_var_name:
    dw 'P','a','O','S','I','n','i','t','C','h','e','c','k','p','o','i','n','t',0
str_pbm_nvg_tag_init: db "boot_v2_init_checkpoint",0
str_pbm_nvg_tag_health: db "boot_v2_strong_health",0
str_pbm_nvg_tag_vector: db "boot_v2_health_vector",0
str_pbm_nvg_tag_blackbox: db "boot_v2_blackbox",0

%include "core/abi/wdata.inc"
%macro WDATA_boot_face_observer 0
pbm_face_stage:              db PBM_INIT_STAGE_NONE
pbm_face_active:             db ' '
%endmacro
WDATA_DEFER WDATA_boot_face_observer
; RCQ-32 per-persist duration ledger (see PBM_PERSIST_OPEN/CLOSE); zero = none.
%macro WDATA_boot_persist_ledger 0
alignb 8
pbm_persist_start: resq 1
pbm_persist_rows:  resb PBM_PERSIST_SLOTS * PBM_PERSIST_ROW_SIZE
pbm_persist_count: resd 1
alignb 8
pbm_persist_subcuts: resq 4
pbm_persist_subrows: resb PBM_PERSIST_SLOTS * 32
%endmacro
WDATA_BSS_DEFER WDATA_boot_persist_ledger
