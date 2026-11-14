;; MODULE boot/boot_v2_handoff
;; LAYER 0
;; EXPORTS boot_v2_command_pair_get, boot_v2_command_pair_count, boot_v2_command_pair_epoch, boot_v2_command_pair_role, boot_v2_command_replay_domain_id, boot_v2_auth2_replay_domain_id, boot_v2_command_pair_digest, boot_v2_command_pair_entries, boot_v2_handoff_probe, boot_v2_manifest_migration_aware, boot_v2_owner_modulus, boot_v2_apply_safe_runtime_profile, pbm_crc32, pbm_manager_launch, pbm_manager_sequence, pbm_attempt_nonce, pbm_state_generation, pbm_entry, pbm_profile, pbm_reason, pbm_flags, pbm_last_stage, pbm_safe_runtime_active, pbm_payload_sha, pbm_image_base, pbm_image_size, pbm_manager_gop_valid, pbm_manager_gop_status, pbm_try_media, pbm_try_current, pbm_try_cert_sha, pbm_manifest_floor, pbm_init_writer_version
;; IMPORTS boot/header, boot/serial, bootmgr/rsa2048_verify
;; CAPS
;; OWNER saga:boot
; ============================================================================
; Validate the standalone Boot Manager's EFI_LOADED_IMAGE.LoadOptions handoff.
; This is an additive migration seam: no/invalid handoff means a direct firmware
; launch and the existing embedded selector runs unchanged. Only a valid PBH1,
; exact version/size, IEEE-CRC32, manager-launched flag, and coherent PaOS/Rescue
; entry/profile earns pbm_manager_launch=1 and bypasses embedded selection.
;
; The early bitwise CRC is artifact-boundary code. It cannot import the later L5
; hotpatch service before EBS and the standalone manager cannot link PaOS code;
; the Python oracle content-checks both against zlib CRC32.
; ============================================================================

boot_v2_handoff_probe:
    push rbx
    push r12
    push r13
    sub  rsp, 32
    mov byte [rel pbm_init_writer_version],PBM_INIT_VERSION
    mov  byte [rel pbm_manager_launch], 0
    mov  byte [rel pbm_flags], 0
    mov  byte [rel pbm_try_media], 0
    mov  byte [rel pbm_try_current], 0
    lea rdi,[rel pbm_try_cert_sha]
    xor eax,eax
    mov ecx,4
    rep stosq
    mov  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    mov  byte [rel pbm_reason], PBM_REASON_HEALTHY
    mov  word [rel pbm_last_stage], 0
    mov  byte [rel pbm_safe_runtime_active], 0
    mov  byte [rel pbm_manager_gop_valid], 0
    mov  qword [rel pbm_manager_gop_status], -1
    mov  byte [rel pbm_manifest_floor], PBM_MFLOOR_UNREAD

    mov  rax, [rel boot_services]
    test rax, rax
    jz   .direct
    mov  rcx, [rel image_handle]
    lea  rdx, [rel pbm_loaded_image_guid]
    lea  r8, [rel pbm_loaded_image]
    sub  rsp, 32
    call [rax + 0x98]                 ; HandleProtocol(self, LoadedImage)
    add  rsp, 32
    test rax, rax
    jnz  .direct
    mov  rbx, [rel pbm_loaded_image]
    test rbx, rbx
    jz   .direct
    ; Record the firmware-selected load range even for a direct launch.  A child
    ; StartImage commonly cannot occupy PaOS's preferred 1 MiB base because the
    ; standalone Manager is there already.  Paging must therefore make the
    ; *actual* image range executable rather than assuming physical page zero.
    mov  rax, [rbx + 64]              ; EFI_LOADED_IMAGE.ImageBase
    mov  [rel pbm_image_base], rax
    mov  rax, [rbx + 72]              ; EFI_LOADED_IMAGE.ImageSize
    mov  [rel pbm_image_size], rax
    cmp  dword [rbx + 48], PBM_HANDOFF_SIZE
    jne  .direct
    mov  r12, [rbx + 56]              ; LoadOptions
    test r12, r12
    jz   .direct
    cmp  dword [r12 + PBM_HANDOFF_MAGIC_OFF], PBM_HANDOFF_MAGIC
    jne  .invalid
    cmp  word [r12 + PBM_HANDOFF_VERSION_OFF], PBM_CONTRACT_VERSION
    jne  .invalid
    cmp  word [r12 + PBM_HANDOFF_SIZE_OFF], PBM_HANDOFF_SIZE
    jne  .invalid
    test byte [r12 + PBM_HANDOFF_FLAGS_OFF], PBM_HF_MANAGER_LAUNCHED
    jz   .invalid

    mov  r13d, [r12 + PBM_HANDOFF_CRC32]
    mov  rdi, r12
    mov  esi, PBM_HANDOFF_CRC32
    call pbm_crc32
    cmp  eax, r13d
    jne  .invalid

    movzx eax, byte [r12 + PBM_HANDOFF_ENTRY_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .full_paos
    cmp  eax, PBM_ENTRY_PAOS_B
    je   .full_paos
    cmp  eax, PBM_ENTRY_RESCUE
    jne  .invalid                     ; external OS must never launch PaOS payload
    cmp  byte [r12 + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_RESCUE
    jne  .invalid
    jmp  .coherent
.full_paos:
    movzx edx, byte [r12 + PBM_HANDOFF_PROFILE_OFF]
    cmp  edx, PBM_PROFILE_NORMAL
    je   .coherent
    cmp  edx, PBM_PROFILE_SAFE
    jne  .invalid
    ; Safe is either an explicit owner request or the Manager's one bounded
    ; retry after stopped progress. It never inherits Trial semantics.
    test byte [r12 + PBM_HANDOFF_FLAGS_OFF], PBM_HF_TRIAL
    jnz  .invalid
    mov  al, [r12 + PBM_HANDOFF_REASON_OFF]
    cmp  al, PBM_REASON_OWNER_REQUEST
    je   .coherent
    cmp  al, PBM_REASON_SAFE_RETRY
    jne  .invalid
.coherent:
    ; Only reached after exact PBH1 CRC and entry/profile validation. An old
    ; or unknown Manager capability keeps the legacy B1 live wire unchanged.
    cmp byte [r12 + PBM_HANDOFF_INIT_READER_OFF],PBM_INIT_GRAPH_VERSION
    jne .init_reader_ready
    mov byte [rel pbm_init_writer_version],PBM_INIT_GRAPH_VERSION
.init_reader_ready:
    mov  rax, [r12 + PBM_HANDOFF_MANAGER_SEQ_OFF]
    mov  [rel pbm_manager_sequence], rax
    mov  al, [r12 + PBM_HANDOFF_ENTRY_OFF]
    mov  [rel pbm_entry], al
    mov  al, [r12 + PBM_HANDOFF_PROFILE_OFF]
    mov  [rel pbm_profile], al
    mov  al, [r12 + PBM_HANDOFF_REASON_OFF]
    mov  [rel pbm_reason], al
    mov  al, [r12 + PBM_HANDOFF_FLAGS_OFF]
    test al, PBM_HF_TRY_MEDIA
    jz   .flags_plain
    ; RCQ-29 live Try: the Manager saw an owner-signed TRY_MEDIA manifest on its
    ; own boot volume. Try wins over any attempt/trial bit, so no BootReady ack
    ; and no runtime NV writer can be armed; the storage gates refuse the rest.
    and  al, ~(PBM_HF_MUTABLE_ATTEMPT | PBM_HF_TRIAL) & 0xFF
    mov  byte [rel pbm_try_media], 1
.flags_plain:
    mov  [rel pbm_flags], al
    mov  ax, [r12 + PBM_HANDOFF_LAST_STAGE_OFF]
    mov  [rel pbm_last_stage], ax
    mov  rax, [r12 + PBM_HANDOFF_ATTEMPT_NONCE_OFF]
    mov  [rel pbm_attempt_nonce], rax
    ; Projection of the actual Manager gate on this validated in-memory PBH1.
    ; It is not a saved-proof import. Old Manager handoffs keep Try read-only
    ; but cannot open its local session; no enrollment/restart is attempted.
    cmp byte [rel pbm_try_media],1
    jne .try_current_done
    test rax,rax
    jz .try_current_done
    cmp word [r12 + PBM_HANDOFF_TRY_TRUST_OFF],PBM_HANDOFF_TRY_TRUST_TAG
    jne .try_current_done
    mov rax,[r12 + PBM_HANDOFF_TRY_CERT_OFF]
    or rax,[r12 + PBM_HANDOFF_TRY_CERT_OFF + 8]
    or rax,[r12 + PBM_HANDOFF_TRY_CERT_OFF + 16]
    or rax,[r12 + PBM_HANDOFF_TRY_CERT_OFF + 24]
    jz .try_current_done
    lea rsi,[r12 + PBM_HANDOFF_TRY_CERT_OFF]
    lea rdi,[rel pbm_try_cert_sha]
    mov ecx,4
    rep movsq
    mov byte [rel pbm_try_current],1
.try_current_done:
    mov  rax, [r12 + PBM_HANDOFF_STATE_GEN_OFF]
    mov  [rel pbm_state_generation], rax
    lea  rsi, [r12 + PBM_HANDOFF_PAYLOAD_SHA_OFF]
    lea  rdi, [rel pbm_payload_sha]
    mov  ecx, 4
    rep  movsq
    ; A valid PBH1 CRC was checked above. Missing/foreign diagnostic tags
    ; remain unknown without rejecting an otherwise valid boot handoff.
    cmp  dword [r12 + PBM_HANDOFF_GOP_TAG_OFF], PBM_HANDOFF_GOP_TAG
    jne  .no_manager_gop
    mov  rax, [r12 + PBM_HANDOFF_GOP_STATUS_OFF]
    mov  [rel pbm_manager_gop_status], rax
    mov  byte [rel pbm_manager_gop_valid], 1
.no_manager_gop:
    mov  al, [r12 + PBM_HANDOFF_MFLOOR_OFF]   ; RCQ-28 C1: 0 from an older Manager
    mov  [rel pbm_manifest_floor], al
    mov  byte [rel pbm_manager_launch], 1
    PAOS_NATIVE_ACCEPT_HANDOFF r12 ; exact input accepted by the validator above
    call pbm_emit_r3_trial             ; observation only; no pause/health or policy effect

    lea  rdi, [rel str_pbm_accept_pre]
    call serial_string
    movzx edi, byte [rel pbm_entry]
    call pbm_emit_digit
    lea  rdi, [rel str_pbm_accept_profile]
    call serial_string
    movzx edi, byte [rel pbm_profile]
    call pbm_emit_digit
    lea  rdi, [rel str_pbm_accept_reason]
    call serial_string
    movzx edi, byte [rel pbm_reason]
    call pbm_emit_digit
    lea  rdi, [rel str_pbm_accept_post]
    call serial_string
    call boot_v2_apply_safe_runtime_profile
    cmp  byte [rel pbm_try_media], 1
    jne  .try_reported
    lea  rdi, [rel str_pbm_try_media]
    call serial_string
.try_reported:
    test byte [rel pbm_flags], PBM_HF_MENU_WAS_VISIBLE
    jz   .done
    lea  rdi, [rel str_pbm_menu_visible]
    call serial_string
    jmp  .done

.invalid:
    lea  rdi, [rel str_pbm_invalid]
    call serial_string
    jmp  .done
.direct:
    lea  rdi, [rel str_pbm_direct]
    call serial_string
.done:
    add  rsp, 32
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exact accepted PBH1 before startup health. A capture is only a positive
; observation: missing/truncated/delayed UART output never proves a stopped boot.
; R3 additionally needs raw physical OFF and the SAME unfinished journal/Ready
; state after the cut. No journal/variable write, retry, hold or health change.
pbm_emit_r3_trial:
    pushfq
    push rax
    push rbx
    push rdi
    push r13
    sub rsp, 32
    cmp byte [r12 + PBM_HANDOFF_PROFILE_OFF], PBM_PROFILE_NORMAL
    jne .out
    cmp byte [r12 + PBM_HANDOFF_REASON_OFF], PBM_REASON_TRIAL
    jne .out
    mov al, [r12 + PBM_HANDOFF_FLAGS_OFF]
    and al, PBM_HF_MANAGER_LAUNCHED | PBM_HF_MUTABLE_ATTEMPT | PBM_HF_TRIAL | PBM_HF_TRY_MEDIA
    cmp al, PBM_HF_MANAGER_LAUNCHED | PBM_HF_MUTABLE_ATTEMPT | PBM_HF_TRIAL
    jne .out
    lea rdi, [rel pbm_r3_prefix]
    call serial_string
    xor r13d, r13d
.byte:
    movzx ebx, byte [r12 + r13]
    lea rax, [rel pbm_r3_hex]
    mov edi, ebx
    shr edi, 4
    movzx edi, byte [rax + rdi]
    call serial_char
    lea rax, [rel pbm_r3_hex]
    mov edi, ebx
    and edi, 15
    movzx edi, byte [rax + rdi]
    call serial_char
    inc r13d
    cmp r13d, PBM_HANDOFF_SIZE
    jb .byte
    lea rdi, [rel pbm_r3_end]
    call serial_string
.out:
    add rsp, 32
    pop r13
    pop rdi
    pop rbx
    pop rax
    popfq
    ret

pbm_r3_prefix: db "[PAOS-R3-PBH1] ", 0
pbm_r3_hex: db "0123456789abcdef"
pbm_r3_end: db 13, 10, 0

; pbm_crc32(RDI=data, ESI=len) -> EAX, zlib/IEEE reflected CRC32.
pbm_crc32:
    push rcx
    mov  eax, 0xFFFFFFFF
    test esi, esi
    jz   .finish
.byte:
    xor  al, [rdi]
    mov  ecx, 8
.bit:
    shr  eax, 1
    jnc  .next
    xor  eax, 0xEDB88320
.next:
    dec  ecx
    jnz  .bit
    inc  rdi
    dec  esi
    jnz  .byte
.finish:
    not  eax
    pop  rcx
    ret

pbm_emit_digit:
    push rax
    cmp  edi, 9
    jbe  .bounded
    mov  edi, 9
.bounded:
    add  edi, '0'
    call serial_char
    pop  rax
    ret

; Latch and report the independently reversible Safe runtime policy at the
; accepted PBH1 seam. The Manager owns the retry bound and durable journal;
; PaOS consumes its CRC-bound reason/checkpoint without writing state, resetting,
; or granting a Safe attempt normal strong-health authority.
; SEC-system-secret-migration-flag (root GO 2026-10-08 12:58): may this boot scrub the runtime copy
; of the SYSTEM secret?  The owner-signed manifest header flag says every PaOS slot can run with the
; BS-only secret.  The handoff carries no manifest digest (that would be a Manager change), so PaOS
; verifies the manifest itself and binds it to what the CRC-only handoff CLAIMS was launched
; (PBH1 carries no signature or MAC and any launcher can supply it, so pbm_* are claims and
; this gate stays availability-only, root 14:05; SEC-pbh1-claim-wording):
;   boot_v2_manifest_migration_aware(RDI = the 1024-byte \EFI\PaOS\vault\manifest.bin image)
;   The trust root is fixed here, never the caller's: boot_v2_owner_modulus (below), the Boot-v2
;   owner key that signs manifests and that command_auth also verifies with (srcreview R2).
;   -> EAX = 1 only for a valid Manager handoff to slot A/B, a PBMF v1 1024-byte manifest whose
;      sequence is the handoff's claimed sequence, whose entry for the launched slot names exactly
;      the launched payload SHA-256, whose header carries SYSTEM_SECRET_MIGRATION_AWARE, and whose
;      owner PKCS#1 v1.5 SHA-256 signature over [0,768) verifies; EAX = 0 otherwise (fail closed).
boot_v2_manifest_migration_aware:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    xor  r13d, r13d
    test rbx, rbx
    jz   .mma_done
    cmp  byte [rel pbm_manager_launch], 1
    jne  .mma_done
    cmp  byte [rel pbm_try_media], 1      ; RCQ-29: a live Try boot never runs a secret migration
    je   .mma_done
    cmp  dword [rbx], PBM_MANIFEST_MAGIC
    jne  .mma_done
    cmp  word [rbx + 4], PBM_MANIFEST_VERSION
    jne  .mma_done
    cmp  word [rbx + 6], PBM_MANIFEST_SIZE
    jne  .mma_done
    test word [rbx + PBM_MANIFEST_FLAGS_OFF], PBM_MANIFEST_FLAG_SYSTEM_SECRET_MIGRATION_AWARE
    jz   .mma_done
    test word [rbx + PBM_MANIFEST_FLAGS_OFF], PBM_MANIFEST_FLAG_TRY_MEDIA
    jnz  .mma_done                        ; never both bits (release tooling refuses to sign them)
    mov  rax, [rbx + PBM_MANIFEST_SEQUENCE_OFF]
    cmp  rax, [rel pbm_manager_sequence]
    jne  .mma_done
    movzx eax, byte [rel pbm_entry]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .mma_slot
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .mma_done
.mma_slot:
    movzx ecx, byte [rbx + PBM_MANIFEST_COUNT_OFF]
    cmp  ecx, PBM_MANIFEST_ENTRY_MAX
    ja   .mma_done
    lea  rdx, [rbx + PBM_MANIFEST_ENTRY_OFF]
.mma_find:
    test ecx, ecx
    jz   .mma_done
    cmp  [rdx], al
    je   .mma_found
    add  rdx, PBM_MANIFEST_ENTRY_SIZE
    dec  ecx
    jmp  .mma_find
.mma_found:
    lea  rsi, [rel pbm_payload_sha]
    mov  rax, [rdx + PBM_MANIFEST_ENTRY_SHA_OFF]
    cmp  rax, [rsi]
    jne  .mma_done
    mov  rax, [rdx + PBM_MANIFEST_ENTRY_SHA_OFF + 8]
    cmp  rax, [rsi + 8]
    jne  .mma_done
    mov  rax, [rdx + PBM_MANIFEST_ENTRY_SHA_OFF + 16]
    cmp  rax, [rsi + 16]
    jne  .mma_done
    mov  rax, [rdx + PBM_MANIFEST_ENTRY_SHA_OFF + 24]
    cmp  rax, [rsi + 24]
    jne  .mma_done
    lea  rdi, [rbx + PBM_MANIFEST_SIGNATURE_OFF]
    mov  rsi, rbx
    mov  edx, PBM_MANIFEST_SIGNED_SIZE
    lea  rcx, [rel boot_v2_owner_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jnz  .mma_done
    mov  r13d, 1
.mma_done:
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret
; end boot_v2_manifest_migration_aware

boot_v2_apply_safe_runtime_profile:
    mov  byte [rel pbm_safe_runtime_active], 0
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out
    cmp  byte [rel pbm_profile], PBM_PROFILE_SAFE
    jne  .out
    mov  byte [rel pbm_safe_runtime_active], 1

    lea  rdi, [rel str_pbm_safe_policy_pre]
    call serial_string
    lea  rdi, [rel str_pbm_safe_reason_retry]
    cmp  byte [rel pbm_reason], PBM_REASON_SAFE_RETRY
    je   .reason_ready
    lea  rdi, [rel str_pbm_safe_reason_owner]
.reason_ready:
    call serial_string
    lea  rdi, [rel str_pbm_safe_policy_stage]
    call serial_string
    movzx edi, word [rel pbm_last_stage]
    call serial_hex64
    lea  rdi, [rel str_pbm_safe_policy_post]
    call serial_string
.out:
    xor  eax, eax
    ret

; The Boot-v2 owner public key: the manifest signer. Its bytes are GENERATED from the build's
; BOOT_V2_OWNER_PUBLIC_KEY (build/boot-v2-owner-key.inc, included by paos.asm at layer 0;
; gauntlet_v2/tools/emit_boot_v2_public_key.py), never a source constant, and the release gate
; (owner_key_binding_check.py) refuses a payload whose modulus is not the ceremony key's. Public
; verification material only. Its layer-0 home (svc/command_auth.asm aliases it and keeps the DER key
; id) lets the pre-EBS manifest check pin the same key without a caller-chosen trust root.
%ifndef BOOT_V2_OWNER_MODULUS_BYTES
%error "boot-v2-owner-key.inc is not included (make build generates it from BOOT_V2_OWNER_PUBLIC_KEY)"
%endif
align 8
boot_v2_owner_modulus:
    db BOOT_V2_OWNER_MODULUS_BYTES
    times -((($ - boot_v2_owner_modulus) - 256) * (($ - boot_v2_owner_modulus) - 256)) db 0  ; exactly 256 B
; BEGIN COMMAND AUTHORITY PAIR ABI
; Compiled public AUTH2 membership only; never grants PBMF, PMOD, release or DATA.
; No default feature or emitted bytes. Legacy consumers keep the existing primary
; ID. INPUT exports the stable replay label to SEC in both modes; D is not a key.
%ifdef BOOT_V2_COMMAND_PAIR_ABI
%if BOOT_V2_COMMAND_PAIR_ABI != 1
%error "unsupported command pair ABI"
%endif
; RDI=index; RAX=modulus, RDX=SPKI ID, or both zero. No writes/calls.
boot_v2_command_pair_get:
    xor eax,eax
    xor edx,edx
    cmp rdi,2
    jae .out
    mov ecx,[rel boot_v2_command_pair_count]
    cmp ecx,1
    jb .out
    cmp ecx,2
    ja .out
    cmp edi,ecx
    jae .out
    imul rcx,rdi,320
    lea rax,[rel boot_v2_command_pair_entries]
    add rax,rcx
    cmp dword [rax+288],1
    jne .refuse
    cmp dword [rax+292],edi
    jne .refuse
    lea rdx,[rax+256]
.out:
    ret
.refuse:
    xor eax,eax
    xor edx,edx
    ret
align 8
boot_v2_command_pair_count:
    db BOOT_V2_COMMAND_PAIR_COUNT_BYTES
boot_v2_command_pair_epoch:
    db BOOT_V2_COMMAND_PAIR_EPOCH_BYTES
boot_v2_command_pair_role:
    db BOOT_V2_COMMAND_PAIR_ROLE_BYTES
boot_v2_auth2_replay_domain_id:
boot_v2_command_replay_domain_id:
    db BOOT_V2_COMMAND_REPLAY_DOMAIN_ID_BYTES
boot_v2_command_pair_digest:
    db BOOT_V2_COMMAND_PAIR_DIGEST_BYTES
boot_v2_command_pair_entries:
    db BOOT_V2_COMMAND_PAIR_ENTRIES_BYTES
    times -((($ - boot_v2_command_pair_entries) - 640) * (($ - boot_v2_command_pair_entries) - 640)) db 0
%endif
; END COMMAND AUTHORITY PAIR ABI
pbm_loaded_image:     dq 0
pbm_image_base:       dq 0
pbm_image_size:       dq 0
pbm_manager_sequence: dq 0
pbm_attempt_nonce:    dq 0
pbm_state_generation: dq 0
pbm_payload_sha:      times 32 db 0
pbm_manager_gop_status: dq -1
pbm_manager_gop_valid: db 0
pbm_manager_launch:   db 0
pbm_entry:            db PBM_ENTRY_NONE
pbm_profile:          db PBM_PROFILE_NORMAL
pbm_reason:           db PBM_REASON_HEALTHY
pbm_flags:            db 0
pbm_last_stage:       dw 0
pbm_safe_runtime_active: db 0
pbm_try_current:      db 0
pbm_try_cert_sha:     times 32 db 0
pbm_try_media:        db 0          ; RCQ-29: 1 = live Try boot; every persistent write refused
pbm_init_writer_version: db PBM_INIT_VERSION
pbm_manifest_floor:   db PBM_MFLOOR_UNREAD

pbm_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B

str_pbm_direct:         db "[PAOS64] P0 boot-v2: no Manager handoff; embedded selector remains authoritative [boot.v2.direct]",13,10,0
str_pbm_invalid:        db "[PAOS64] P0 boot-v2: invalid Manager handoff rejected; embedded selector remains authoritative [boot.v2.handoff.reject]",13,10,0
str_pbm_accept_pre:     db "[PAOS64] P0 boot-v2: handoff accepted entry=",0
str_pbm_accept_profile: db " profile=",0
str_pbm_accept_reason:  db " reason=",0
str_pbm_accept_post:    db " CRC32=ok [boot.v2.handoff.accepted]",13,10,0
str_pbm_try_media:     db "[PAOS64] P0 boot-v2: live Try media; internal disks, NVRAM and CMOS are read-only this boot [boot.v2.try.media.guard]",13,10,0
str_pbm_menu_visible:   db "[PAOS64] P0 boot-v2: Manager menu-visible handoff flag accepted [boot.v2.menu.handoff-visible]",13,10,0
str_pbm_selection_bypass: db "[PAOS64] P0 boot-v2: Manager selection complete; embedded menu/escalation bypassed [boot.v2.selection.bypassed]",13,10,0
str_pbm_safe_policy_pre: db "[PAOS64] P0 boot-v2: Safe runtime accepted bounded software-stop handoff reason=",0
str_pbm_safe_reason_owner: db "owner-request",0
str_pbm_safe_reason_retry: db "safe-retry",0
str_pbm_safe_policy_stage: db " previous-stage=",0
str_pbm_safe_policy_post: db " manager-owns-recovery=1 enabled=cpu+gop+paging+gdt+idt+diag+serial+status+ping disabled=normal-init+smp+gpu+audio+usb+storage+network+hotpatch+vtd+passthrough+vm+services+apps strong-health=forbidden [boot.v2.safe.policy]",13,10,0
str_pbm_safe_reachable: db "[PAOS64] Boot Manager v2 Safe Mode reachable: enabled=cpu+gop+paging+gdt+idt+diag+serial+status+ping; disabled=normal-init+smp+gpu+audio+usb+storage+network+hotpatch+vtd+passthrough+vm+services+apps; strong-health=forbidden [boot.v2.safe.reachable]",13,10,0
