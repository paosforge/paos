;; MODULE svc/command_recovery_state
;; LAYER 5
;; EXPORTS recovery_state_preload, recovery_state_declare, recovery_state_qemu_selftest, recovery_notice_get, c2rs_out_buf, c2rs_out_ready, c2rs_out_cur
;; IMPORTS boot/header, boot/serial, boot/boot_v2_handoff, boot/boot_v2_health, svc/command
;; CAPS
;; OWNER saga:boot_v2_ge_c2_recovery_state_machine
; ============================================================================
; GE C2 recovery-state observation.
;
; While Boot Services are still live, read the redundant Manager journal and
; accept only a CRC-valid record whose generation exactly matches the already
; CRC-validated PBH1 handoff.  This is observation only: the module never opens
; a file for write and never selects or repairs a slot.  C2RECOVERY projects the
; measured masks together with the live strong-health publication latch.  The
; only mutation path remains paos_boot_admin.recover_quarantine_deadlock, which
; validates the Vault digest and commits through JournalStore with readback.
; ============================================================================

C2RS_OUT_CAP equ 480

%macro C2RS_TRY_STATE 2
    mov  qword [rel c2rs_file], 0
    mov  rax, [rel c2rs_root]
    mov  rcx, rax
    lea  rdx, [rel c2rs_file]
    lea  r8, [rel %1]
    mov  r9d, 1                          ; EFI_FILE_MODE_READ
    mov  qword [rsp + 32], 0             ; attributes (fifth argument)
    call [rax + 8]                       ; root.Open
    test rax, rax
    jnz  %%done
    mov  qword [rel c2rs_io_size], PBM_STATE_SIZE
    mov  r12, [rel c2rs_file]
    mov  rcx, r12
    lea  rdx, [rel c2rs_io_size]
    lea  r8, [rel %2]
    sub  rsp, 32
    call [r12 + 32]                      ; file.Read
    add  rsp, 32
    mov  rbx, rax
    mov  rcx, r12
    sub  rsp, 32
    call [r12 + 16]                      ; file.Close
    add  rsp, 32
    mov  qword [rel c2rs_file], 0
    test rbx, rbx
    jnz  %%done
    cmp  qword [rel c2rs_io_size], PBM_STATE_SIZE
    jne  %%done
    lea  rdi, [rel %2]
    call recovery_state_accept
    test eax, eax
    jnz  .matched
%%done:
%endmacro

; Read the journal copy selected by the Manager handoff.  A direct boot or any
; filesystem/CRC/generation mismatch remains honestly unavailable.
recovery_state_preload:
    push rbx
    push r12
    sub  rsp, 48
    mov  byte [rel c2rs_available], 0
    mov  byte [rel c2rs_verified_mask], 0
    mov  byte [rel c2rs_quarantine_mask], 0
    mov  byte [rel c2rs_failure_count], 0
    mov  byte [rel c2rs_boot_in_progress], 0
    mov  qword [rel c2rs_generation], 0
    mov  qword [rel c2rs_loaded_image], 0
    mov  qword [rel c2rs_simple_fs], 0
    mov  qword [rel c2rs_root], 0
    mov  qword [rel c2rs_file], 0
    cmp  byte [rel pbm_manager_launch], 1
    jne  .return
    cmp  qword [rel pbm_state_generation], 0
    je   .return

    mov  rax, [rel boot_services]
    test rax, rax
    jz   .return
    mov  rcx, [rel image_handle]
    lea  rdx, [rel c2rs_loaded_image_guid]
    lea  r8, [rel c2rs_loaded_image]
    sub  rsp, 32
    call [rax + 0x98]                    ; HandleProtocol(LoadedImage)
    add  rsp, 32
    test rax, rax
    jnz  .return
    mov  rbx, [rel c2rs_loaded_image]
    mov  rcx, [rbx + 24]                 ; LoadedImage.DeviceHandle
    mov  rax, [rel boot_services]
    lea  rdx, [rel c2rs_simple_fs_guid]
    lea  r8, [rel c2rs_simple_fs]
    sub  rsp, 32
    call [rax + 0x98]                    ; HandleProtocol(SimpleFileSystem)
    add  rsp, 32
    test rax, rax
    jnz  .return
    mov  rax, [rel c2rs_simple_fs]
    mov  rcx, rax
    lea  rdx, [rel c2rs_root]
    sub  rsp, 32
    call [rax + 8]                       ; OpenVolume
    add  rsp, 32
    test rax, rax
    jnz  .return

    C2RS_TRY_STATE c2rs_state0_path, c2rs_state_buf
    C2RS_TRY_STATE c2rs_state1_path, c2rs_state_buf
    jmp  .close_root
.matched:
    ; recovery_state_accept copied the exact measured fields.
.close_root:
    mov  r12, [rel c2rs_root]
    test r12, r12
    jz   .return
    mov  rcx, r12
    sub  rsp, 32
    call [r12 + 16]                      ; root.Close
    add  rsp, 32
    mov  qword [rel c2rs_root], 0
.return:
    xor  eax, eax
    add  rsp, 48
    pop  r12
    pop  rbx
    ret

; recovery_state_accept(RDI=512-byte record) -> EAX=1 only for the handoff's
; exact CRC-valid generation.  The selection authority is still the Manager;
; PaOS merely observes that already-bound record.
recovery_state_accept:
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
    mov  esi, PBM_STATE_CRC32
    call pbm_crc32
    cmp  eax, ebx
    jne  .bad
    mov  rax, [r12 + PBM_STATE_GENERATION_OFF]
    cmp  rax, [rel pbm_state_generation]
    jne  .bad
    mov  al, [r12 + PBM_STATE_VERIFIED_MASK_OFF]
    test al, 0xF9                       ; only PAOS_A/PAOS_B bits are valid here
    jnz  .bad
    mov  al, [r12 + PBM_STATE_QUARANTINE_MASK_OFF]
    test al, 0xF9
    jnz  .bad
    mov  rax, [r12 + PBM_STATE_GENERATION_OFF]
    mov  [rel c2rs_generation], rax
    mov  al, [r12 + PBM_STATE_VERIFIED_MASK_OFF]
    mov  [rel c2rs_verified_mask], al
    mov  al, [r12 + PBM_STATE_QUARANTINE_MASK_OFF]
    mov  [rel c2rs_quarantine_mask], al
    mov  al, [r12 + PBM_STATE_FAILURE_COUNT_OFF]
    mov  [rel c2rs_failure_count], al
    mov  al, [r12 + PBM_STATE_BIP_OFF]
    mov  [rel c2rs_boot_in_progress], al
    mov  byte [rel c2rs_available], 1
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Pure eligibility predicate used only by the QEMU marker selftest.
; EDI=verified mask, ESI=quarantine mask, EDX=selected-slot bit.
recovery_state_deadlock_eligible:
    and  edi, 0x06
    cmp  esi, 0x06
    jne  .no
    test edi, edi
    jz   .no
    mov  eax, edi
    dec  eax
    test eax, edi                       ; exactly one Verified bit
    jnz  .no
    test edx, edi                       ; selected slot is that Verified bit
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

recovery_state_declare:
    mov  byte [rel c2rs_out_ready], 0
    lea  rdi, [rel str_c2rs_verb]
    lea  rsi, [rel cmd_verb_c2recovery]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                           ; read-only observation
    call command_register_verb
    ret

; Read-only presentation seam for spec 7.6.10(6). Uses only the accepted PBH1
; owner fields, never the now-mutating journal or the strong-health latch.
; EAX=kind (0 means no notice), RDX=NUL-terminated English fallback, ECX=byte
; length excluding NUL, R8=localization key. Pointers/length are zero for kind0.
; Clobbers RAX/RCX/RDX/R8/R9/flags. No allocation, EFI, I/O, acknowledgement,
; retry or selection authority. The UI may dismiss its own presentation only.
; Unknown/incoherent handoffs produce no invented explanation. OWNER_REQUEST,
; healthy, trial and live Try are not automatic fallback evidence.
recovery_notice_get:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    xor  r8d, r8d
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out
    cmp  byte [rel pbm_try_media], 0
    jne  .out
    movzx r9d, byte [rel pbm_entry]
    cmp  r9d, PBM_ENTRY_RESCUE
    je   .rescue
    cmp  r9d, PBM_ENTRY_PAOS_A
    jb   .out
    cmp  r9d, PBM_ENTRY_PAOS_B
    ja   .out
    cmp  byte [rel pbm_profile], PBM_PROFILE_SAFE
    je   .safe
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .out
    cmp  byte [rel pbm_reason], PBM_REASON_PREVIOUS_BIP
    je   .interrupted
    cmp  byte [rel pbm_reason], PBM_REASON_ROLLBACK
    je   .rollback
    cmp  byte [rel pbm_reason], PBM_REASON_INVALID_PAYLOAD
    je   .check
    ret
.safe:
    cmp  byte [rel pbm_reason], PBM_REASON_SAFE_RETRY
    jne  .out
    mov  eax, 2
    lea  rdx, [rel c2rs_notice_safe]
    lea  r8, [rel c2rs_notice_key_safe]
    jmp  .length
.rescue:
    cmp  byte [rel pbm_profile], PBM_PROFILE_RESCUE
    jne  .out
    cmp  byte [rel pbm_reason], PBM_REASON_INVALID_STATE
    je   .state
    cmp  byte [rel pbm_reason], PBM_REASON_INVALID_PAYLOAD
    je   .rescue_check
    cmp  byte [rel pbm_reason], PBM_REASON_RESCUE
    jne  .out
    mov  eax, 6
    lea  rdx, [rel c2rs_notice_rescue]
    lea  r8, [rel c2rs_notice_key_rescue]
    jmp  .length
.interrupted:
    mov  eax, 1
    lea  rdx, [rel c2rs_notice_interrupted]
    lea  r8, [rel c2rs_notice_key_interrupted]
    jmp  .length
.rollback:
    ; ROLLBACK also covers an unusable Active with a usable Previous. PBH1
    ; does not say that an update failed, so do not make that stronger claim.
    mov  eax, 3
    lea  rdx, [rel c2rs_notice_rollback]
    lea  r8, [rel c2rs_notice_key_rollback]
    jmp  .length
.check:
    ; INVALID_PAYLOAD also covers abnormal state/pending-request validation;
    ; it is not proof of a bad signature, malicious bytes or a failed update.
    mov  eax, 4
    lea  rdx, [rel c2rs_notice_check]
    lea  r8, [rel c2rs_notice_key_check]
    jmp  .length
.state:
    mov  eax, 5
    lea  rdx, [rel c2rs_notice_state]
    lea  r8, [rel c2rs_notice_key_state]
    jmp  .length
.rescue_check:
    mov  eax, 7
    lea  rdx, [rel c2rs_notice_rescue_check]
    lea  r8, [rel c2rs_notice_key_rescue_check]
.length:
    ; Fixed, trusted ASCII fallbacks below; no external string is scanned.
    cmp  byte [rdx + rcx], 0
    je   .out
    inc  ecx
    jmp  .length
.out:
    ret

cmd_verb_c2recovery:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call c2rs_out_reset
    lea  rdi, [rel str_c2rs_pre]
    call c2rs_out_str
    cmp  byte [rel c2rs_available], 1
    jne  .unavailable
    lea  rdi, [rel str_c2rs_matched]
    call c2rs_out_str
    lea  rdi, [rel str_c2rs_generation]
    call c2rs_out_str
    mov  rdi, [rel c2rs_generation]
    call c2rs_out_hex64
    lea  rdi, [rel str_c2rs_verified]
    call c2rs_out_str
    movzx edi, byte [rel c2rs_verified_mask]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_quarantine]
    call c2rs_out_str
    movzx edi, byte [rel c2rs_quarantine_mask]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_failures]
    call c2rs_out_str
    movzx edi, byte [rel c2rs_failure_count]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_bip]
    call c2rs_out_str
    movzx edi, byte [rel c2rs_boot_in_progress]
    call c2rs_out_hex8
    jmp  .common
.unavailable:
    lea  rdi, [rel str_c2rs_unavailable]
    call c2rs_out_str
.common:
    lea  rdi, [rel str_c2rs_launch]
    call c2rs_out_str
    movzx edi, byte [rel pbm_manager_launch]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_entry]
    call c2rs_out_str
    movzx edi, byte [rel pbm_entry]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_profile]
    call c2rs_out_str
    movzx edi, byte [rel pbm_profile]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_reason]
    call c2rs_out_str
    movzx edi, byte [rel pbm_reason]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_published]
    call c2rs_out_str
    movzx edi, byte [rel pbm_strong_health_published]
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_notice]
    call c2rs_out_str
    call recovery_notice_get
    mov  edi, eax
    call c2rs_out_hex8
    lea  rdi, [rel str_c2rs_policy]
    call c2rs_out_str
    mov  byte [rel c2rs_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    movzx eax, byte [rel c2rs_available]
    mov  [r12 + RSP_VAL], rax
    pop  r12
    ret

; QEMU-only product marker.  The host scenario performs the complete
; JournalStore replay; this local KAT prevents an unconditional marker from
; claiming the exact one-Verified/two-quarantined predicate.
recovery_state_qemu_selftest:
%ifdef PAOS_GE_C2_QEMU_SCENARIO
    mov  edi, 0x02
    mov  esi, 0x06
    mov  edx, 0x02
    call recovery_state_deadlock_eligible
    cmp  eax, 1
    jne  .out
    mov  edi, 0x06
    mov  esi, 0x06
    mov  edx, 0x02
    call recovery_state_deadlock_eligible
    test eax, eax
    jnz  .out
    mov  edi, 0x02
    mov  esi, 0x02
    mov  edx, 0x02
    call recovery_state_deadlock_eligible
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_c2rs_qemu_pass]
    call serial_string
.out:
%endif
    ret

c2rs_out_reset:
    lea  rax, [rel c2rs_out_buf]
    mov  [rel c2rs_out_cur], rax
    mov  byte [rax], 0
    ret

c2rs_out_str:
    mov  rsi, [rel c2rs_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rdi
    inc  rsi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel c2rs_out_cur], rsi
    ret

c2rs_out_hex8:
    mov  rsi, [rel c2rs_out_cur]
    lea  r8, [rel c2rs_hex]
    mov  byte [rsi], '0'
    mov  byte [rsi + 1], 'x'
    mov  eax, edi
    mov  edx, eax
    shr  eax, 4
    and  eax, 0x0F
    mov  al, [r8 + rax]
    mov  [rsi + 2], al
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rsi + 3], dl
    mov  byte [rsi + 4], 0
    add  rsi, 4
    mov  [rel c2rs_out_cur], rsi
    ret

c2rs_out_hex64:
    mov  rsi, [rel c2rs_out_cur]
    lea  r8, [rel c2rs_hex]
    mov  byte [rsi], '0'
    mov  byte [rsi + 1], 'x'
    add  rsi, 2
    mov  rax, rdi
    mov  ecx, 16
.nibble:
    rol  rax, 4
    mov  rdx, rax
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rsi], dl
    inc  rsi
    dec  ecx
    jnz  .nibble
    mov  byte [rsi], 0
    mov  [rel c2rs_out_cur], rsi
    ret

align 8
c2rs_loaded_image:    dq 0
c2rs_simple_fs:       dq 0
c2rs_root:            dq 0
c2rs_file:            dq 0
c2rs_io_size:         dq 0
c2rs_generation:      dq 0
c2rs_out_cur:         dq 0
c2rs_available:       db 0
c2rs_verified_mask:   db 0
c2rs_quarantine_mask: db 0
c2rs_failure_count:   db 0
c2rs_boot_in_progress: db 0
c2rs_out_ready:       db 0
align 8
c2rs_state_buf:       times PBM_STATE_SIZE db 0
c2rs_out_buf:         times C2RS_OUT_CAP db 0

c2rs_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B
c2rs_simple_fs_guid:
    dd 0x964E5B22
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
c2rs_state0_path:
    dw '\','E','F','I','\','P','a','O','S','\','s','t','a','t','e','\'
    dw 's','t','a','t','e','0','.','b','i','n',0
c2rs_state1_path:
    dw '\','E','F','I','\','P','a','O','S','\','s','t','a','t','e','\'
    dw 's','t','a','t','e','1','.','b','i','n',0

c2rs_hex: db "0123456789abcdef"
str_c2rs_verb:        db "C2RECOVERY",0
str_c2rs_pre:         db " c2_recovery journal=",0
str_c2rs_matched:     db "matched",0
str_c2rs_unavailable: db "unavailable",0
str_c2rs_generation:  db " generation=",0
str_c2rs_verified:    db " verified_mask=",0
str_c2rs_quarantine:  db " quarantine_mask=",0
str_c2rs_failures:    db " failure_count=",0
str_c2rs_bip:         db " boot_in_progress=",0
str_c2rs_launch:      db " manager_launch=",0
str_c2rs_entry:       db " entry=",0
str_c2rs_profile:     db " profile=",0
str_c2rs_reason:      db " reason=",0
str_c2rs_published:   db " strong_health_published=",0
str_c2rs_notice:      db " notice_kind=",0
str_c2rs_policy:      db " recovery_policy=vault-digest+verified-slot+journalstore-readback failure_evidence=preserve-until-strong-health direct_bootmgfw_write=0 writes=0",0
str_c2rs_qemu_pass:   db "[boot.v2.ge.c2.scenario] GE C2 QEMU scenario PASS [boot.v2.ge.c2.scenario]",13,10,0

; Stable backend keys; the desktop owns rendering, dismissal and translation.
; No label/action here grants retry or changes the selected boot identity.
c2rs_notice_interrupted: db "PaOS recovered after the previous start did not finish.",0
c2rs_notice_safe: db "PaOS started in Safe mode after the previous start did not finish.",0
c2rs_notice_rollback: db "PaOS used another verified version because the usual version was unavailable.",0
c2rs_notice_check: db "PaOS recovered after a start-up check failed.",0
c2rs_notice_state: db "PaOS started Rescue because its start-up state could not be used.",0
c2rs_notice_rescue: db "PaOS started Rescue because normal start-up was unavailable.",0
c2rs_notice_rescue_check: db "PaOS started Rescue after a start-up check failed.",0
c2rs_notice_key_interrupted: db "boot.notice.interrupted",0
c2rs_notice_key_safe: db "boot.notice.safe_retry",0
c2rs_notice_key_rollback: db "boot.notice.rollback",0
c2rs_notice_key_check: db "boot.notice.check_failed",0
c2rs_notice_key_state: db "boot.notice.state_unavailable",0
c2rs_notice_key_rescue: db "boot.notice.rescue",0
c2rs_notice_key_rescue_check: db "boot.notice.rescue_check_failed",0
