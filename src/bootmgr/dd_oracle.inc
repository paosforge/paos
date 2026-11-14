; U4b driver-domain boot oracle: Manager consume, delete and PDH1 publication (BOOT).
; Contract: BOOT LEDGER 106350 (CONTRACT.md 90515ef5) + amendment 106359 (Trial admission);
; SEC 106354 K1-K7. Included in the Manager code section under PBM_FEATURE_FULL_POLICY and
; PBM_OWNER_KEY only. Nothing here can fail, delay or reroute a boot: every absence or refusal
; leaves state_work and the launch byte-identical and runs no oracle (K7).
%include "boot/dd_oracle_contract.inc"
%if (PDS1_MAGIC_OFF < R5_STATE_END) || (PDS1_END > PBM_STATE_CRC32)
%error "PDS1 overlaps the R5 tail or the PBSJ CRC"
%endif
%if (PDH1_SIZE != PDH1_HEADER_SIZE + PDO1_SIZE) || (PDH1_RECORD_OFF != PDH1_HEADER_SIZE)
%error "PDH1 is not one 128-byte header plus the exact PDO1"
%endif
%include "bootmgr/pdo1_valid.asm"

; dd_oracle_bind(R15D = verified entry). arm_selected_attempt calls it after
; r5_manager_bind_grant, with state_work already the exact about-to-commit attempt.
; Admission (amendment 106359): verified PaOS A/B, profile NORMAL, reason HEALTHY or
; TRIAL, not Try media, no R5 operation for this attempt. Then the exact 1024-byte
; \EFI\PaOS\vault\ddoracle.bin on the Manager's own volume must pass the shared
; validator, name this boot's verified manifest sequence and launched payload, stand
; above the PDS1 floor, and verify with the key that verified this boot's PBMF. Only
; then PDS1 is written into state_work, so the consume and the attempt are ONE commit.
dd_oracle_bind:
    push rbx
    push r12
    push r13
    mov  byte [rel dd_oracle_pending], 0
    mov  byte [rel dd_oracle_published], 0
    cmp  r15d, PBM_ENTRY_PAOS_A
    jb   .quiet
    cmp  r15d, PBM_ENTRY_PAOS_B
    ja   .quiet
    cmp  byte [rel try_media_boot], 0
    jne  .quiet
    cmp  byte [rel selected_profile], PBM_PROFILE_NORMAL
    jne  .quiet
    mov  al, [rel selected_reason]
    cmp  al, PBM_REASON_HEALTHY
    je   .reason_ok
    cmp  al, PBM_REASON_TRIAL
    jne  .quiet
.reason_ok:
    cmp  byte [rel manifest_verified], 1
    jne  .quiet
    ; R5 wins: a consumed request this boot, or an owner grant bound to this attempt.
    cmp  byte [rel r5_manager_consumed], 0
    jne  .quiet
    cmp  dword [rel state_work + R5_STATE_MAGIC_OFF], R5_STATE_MAGIC
    jne  .r5_clear
    cmp  dword [rel state_work + R5_STATE_STATUS], R5_STATE_BOUND
    jne  .r5_clear
    mov  rax, [rel state_work + R5_STATE_NONCE]
    cmp  rax, [rel current_attempt_nonce]
    je   .quiet
.r5_clear:
    ; An unknown occupant of [328,392) is never overwritten.
    cmp  dword [rel state_work + PDS1_MAGIC_OFF], PDS1_MAGIC
    jne  .tail_empty
    cmp  dword [rel state_work + PDS1_STATUS_OFF], PDS1_STATUS_CONSUMED
    jne  .quiet
    jmp  .tail_ok
.tail_empty:
    lea  rdx, [rel state_work + PDS1_MAGIC_OFF]
    xor  ecx, ecx
.tail_zero:
    cmp  qword [rdx + rcx], 0
    jne  .quiet
    add  ecx, 8
    cmp  ecx, PDS1_END - PDS1_MAGIC_OFF
    jb   .tail_zero
.tail_ok:
    lea  r13, [rel dd_oracle_path]
    lea  r12, [rel dd_oracle_record]
    mov  ebx, PDO1_SIZE
    call read_exact
    test eax, eax
    jnz  .quiet                       ; absent or not exactly 1024 B: no oracle
    lea  rdi, [rel dd_oracle_record]
    call pdo1_record_valid
    test eax, eax
    jz   .refused
    mov  rax, [rel dd_oracle_record + PDO1_MANIFEST_SEQ_OFF]
    cmp  rax, [rel manifest + PBM_MANIFEST_SEQUENCE_OFF]
    jne  .refused
    lea  rdi, [rel dd_oracle_record + PDO1_BUILD_SHA_OFF]
    lea  rsi, [rel verified_payload_sha]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .refused
    cmp  dword [rel state_work + PDS1_MAGIC_OFF], PDS1_MAGIC
    jne  .floor_ok
    mov  rax, [rel dd_oracle_record + PDO1_ORACLE_SEQ_OFF]
    cmp  rax, [rel state_work + PDS1_ORACLE_SEQ_OFF]
    jbe  .refused                     ; consumed floor: a leftover or replay never reruns
.floor_ok:
    lea  rdi, [rel dd_oracle_record + PDO1_SIGNATURE_OFF]
    lea  rsi, [rel dd_oracle_record]
    mov  edx, PDO1_SIGNED_SIZE
    lea  rcx, [rel pbm_owner_modulus] ; the key that verified this boot's PBMF
    call pbm_rsa2048_verify_sha256_locked
    test eax, eax
    jnz  .refused
    lea  rdi, [rel dd_oracle_digest]
    lea  rsi, [rel dd_oracle_record]
    mov  edx, PDO1_SIZE
    call sha256_hash
    test rax, rax
    jnz  .refused
    ; The generation journal_commit assigns: max(valid copy generation) + 1.
    xor  eax, eax
    cmp  byte [rel state0_valid], 1
    jne  .gen1
    mov  rax, [rel state0 + PBM_STATE_GENERATION_OFF]
.gen1:
    cmp  byte [rel state1_valid], 1
    jne  .gen_have
    cmp  rax, [rel state1 + PBM_STATE_GENERATION_OFF]
    jae  .gen_have
    mov  rax, [rel state1 + PBM_STATE_GENERATION_OFF]
.gen_have:
    inc  rax
    jz   .refused                     ; journal_commit refuses a wrapped generation
    mov  [rel state_work + PDS1_GEN_OFF], rax
    mov  dword [rel state_work + PDS1_MAGIC_OFF], PDS1_MAGIC
    mov  dword [rel state_work + PDS1_STATUS_OFF], PDS1_STATUS_CONSUMED
    mov  rax, [rel dd_oracle_record + PDO1_ORACLE_SEQ_OFF]
    mov  [rel state_work + PDS1_ORACLE_SEQ_OFF], rax
    lea  rdi, [rel state_work + PDS1_RECORD_SHA_OFF]
    lea  rsi, [rel dd_oracle_digest]
    mov  ecx, 4
    rep  movsq
    mov  rax, [rel current_attempt_nonce]
    mov  [rel state_work + PDS1_NONCE_OFF], rax
    mov  byte [rel dd_oracle_pending], 1
    lea  rdi, [rel dd_oracle_bound_text]
    call serial_string
    jmp  .quiet
.refused:
    lea  rdi, [rel dd_oracle_refused_text]
    call serial_string
.quiet:
    pop  r13
    pop  r12
    pop  rbx
    ret

; dd_oracle_publish(R15D = entry about to be entered). Called once, immediately before
; the PaOS A/B child is entered, after validate_attempt_handoff accepted the PBH1. The
; durable selected state must carry exactly this boot's PDS1, joined to the PBH1 about to
; be handed over. Then the request is deleted (B2/K4) and PDH1 is published as one EFI
; configuration table (K5). Never fails the launch.
dd_oracle_publish:
    push rbx
    cmp  byte [rel dd_oracle_pending], 1
    jne  .out
    mov  byte [rel dd_oracle_pending], 0  ; at most once per boot
    cmp  byte [rel try_media_boot], 0
    jne  .out
    cmp  r15b, [rel handoff + PBM_HANDOFF_ENTRY_OFF]
    jne  .out
    mov  rbx, [rel selected_state_ptr]
    test rbx, rbx
    jz   .out
    cmp  dword [rbx + PDS1_MAGIC_OFF], PDS1_MAGIC
    jne  .out
    cmp  dword [rbx + PDS1_STATUS_OFF], PDS1_STATUS_CONSUMED
    jne  .out
    mov  rax, [rel current_attempt_nonce]
    cmp  rax, [rbx + PDS1_NONCE_OFF]
    jne  .out
    cmp  rax, [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF]
    jne  .out
    mov  rax, [rbx + PBM_STATE_GENERATION_OFF]
    cmp  rax, [rbx + PDS1_GEN_OFF]
    jne  .out
    cmp  rax, [rel handoff + PBM_HANDOFF_STATE_GEN_OFF]
    jne  .out
    mov  rax, [rbx + PDS1_ORACLE_SEQ_OFF]
    cmp  rax, [rel dd_oracle_record + PDO1_ORACLE_SEQ_OFF]
    jne  .out
    lea  rdi, [rbx + PDS1_RECORD_SHA_OFF]
    lea  rsi, [rel dd_oracle_digest]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .out
    lea  rdi, [rel handoff + PBM_HANDOFF_PAYLOAD_SHA_OFF]
    lea  rsi, [rel dd_oracle_record + PDO1_BUILD_SHA_OFF]
    mov  edx, 32
    call pbm_bytes_differ
    test eax, eax
    jnz  .out
    call dd_oracle_delete             ; result never matters: the floor refuses a leftover
    lea  rdi, [rel dd_oracle_table]
    xor  eax, eax
    mov  ecx, PDH1_HEADER_SIZE / 8
    rep  stosq
    mov  dword [rel dd_oracle_table], PDH1_MAGIC
    mov  word [rel dd_oracle_table + 4], PDH1_VERSION
    mov  word [rel dd_oracle_table + 6], PDH1_SIZE
    mov  rax, [rel handoff + PBM_HANDOFF_ATTEMPT_NONCE_OFF]
    mov  [rel dd_oracle_table + PDH1_NONCE_OFF], rax
    mov  rax, [rel handoff + PBM_HANDOFF_STATE_GEN_OFF]
    mov  [rel dd_oracle_table + PDH1_GEN_OFF], rax
    mov  rax, [rel handoff + PBM_HANDOFF_MANAGER_SEQ_OFF]
    mov  [rel dd_oracle_table + PDH1_MANAGER_SEQ_OFF], rax
    mov  rax, [rel dd_oracle_record + PDO1_ORACLE_SEQ_OFF]
    mov  [rel dd_oracle_table + PDH1_ORACLE_SEQ_OFF], rax
    lea  rsi, [rel handoff + PBM_HANDOFF_PAYLOAD_SHA_OFF]
    lea  rdi, [rel dd_oracle_table + PDH1_PAYLOAD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    lea  rsi, [rel dd_oracle_digest]
    lea  rdi, [rel dd_oracle_table + PDH1_RECORD_SHA_OFF]
    mov  ecx, 4
    rep  movsq
    lea  rsi, [rel dd_oracle_record]
    lea  rdi, [rel dd_oracle_table + PDH1_RECORD_OFF]
    mov  ecx, PDO1_SIZE / 8
    rep  movsq
    lea  rdi, [rel dd_oracle_table]
    mov  ecx, PDH1_CRC32
    call crc32
    mov  [rel dd_oracle_table + PDH1_CRC32], eax
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .unpublished
    lea  rcx, [rel dd_oracle_guid]
    lea  rdx, [rel dd_oracle_table]
    PBM_FW_ENTER 32
    call [rax + 0xC0]                 ; InstallConfigurationTable
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .unpublished
    mov  byte [rel dd_oracle_published], 1
    lea  rdi, [rel dd_oracle_published_text]
    call serial_string
    jmp  .out
.unpublished:
    mov  dword [rel dd_oracle_table], 0
    lea  rdi, [rel dd_oracle_unpublished_text]
    call serial_string
.out:
    pop  rbx
    ret

; dd_oracle_withdraw: a pre-child refusal after publication (PAX1 bridge reject) removes
; the table and invalidates its bytes, so no later child of this boot can join it.
dd_oracle_withdraw:
    cmp  byte [rel dd_oracle_published], 1
    jne  .out
    mov  byte [rel dd_oracle_published], 0
    mov  dword [rel dd_oracle_table], 0
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .out
    lea  rcx, [rel dd_oracle_guid]
    xor  edx, edx
    PBM_FW_ENTER 32
    call [rax + 0xC0]                 ; InstallConfigurationTable(GUID, NULL) removes it
    PBM_FW_LEAVE 32
.out:
    ret

; dd_oracle_delete: the one EFI_FILE_PROTOCOL.Delete in the Manager (K4). One constant
; path on the Manager's own boot volume, opened READ|WRITE without CREATE, deleted only
; when it still holds exactly the consumed 1024 bytes. Any other outcome closes it.
dd_oracle_delete:
    push r14
    mov  qword [rel dd_oracle_file], 0
    mov  rax, [rel boot_root]
    test rax, rax
    jz   .out
    mov  rcx, rax
    lea  rdx, [rel dd_oracle_file]
    lea  r8, [rel dd_oracle_path]
    mov  r9d, 3                       ; EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE
    PBM_FW_ENTER 40
    mov  qword [rsp + 32], 0
    call [rax + 8]                    ; EFI_FILE_PROTOCOL.Open
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .out
    mov  r14, [rel dd_oracle_file]
    mov  qword [rel dd_oracle_io_size], PDO1_SIZE
    mov  rcx, r14
    lea  rdx, [rel dd_oracle_io_size]
    lea  r8, [rel dd_oracle_check]
    PBM_FW_ENTER 32
    call [r14 + 32]                   ; Read
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    cmp  qword [rel dd_oracle_io_size], PDO1_SIZE
    jne  .close
    mov  qword [rel dd_oracle_io_size], 1
    mov  rcx, r14
    lea  rdx, [rel dd_oracle_io_size]
    lea  r8, [rel dd_oracle_check + PDO1_SIZE]
    PBM_FW_ENTER 32
    call [r14 + 32]                   ; exactly 1024 B: the next Read is EOF
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .close
    cmp  qword [rel dd_oracle_io_size], 0
    jne  .close
    lea  rdi, [rel dd_oracle_check]
    lea  rsi, [rel dd_oracle_record]
    mov  edx, PDO1_SIZE
    call pbm_bytes_differ
    test eax, eax
    jnz  .close
    mov  rcx, r14
    PBM_FW_ENTER 32
    call [r14 + 24]                   ; Delete (also closes the handle)
    PBM_FW_LEAVE 32
    lea  rdi, [rel dd_oracle_deleted_text]
    test rax, rax
    jz   .report
    lea  rdi, [rel dd_oracle_kept_text]
.report:
    call serial_string
    jmp  .out
.close:
    mov  rcx, r14
    PBM_FW_ENTER 32
    call [r14 + 16]                   ; Close
    PBM_FW_LEAVE 32
    lea  rdi, [rel dd_oracle_kept_text]
    call serial_string
.out:
    pop  r14
    ret

dd_oracle_bound_text:       db '[PBM] Driver-domain oracle request consumed with this attempt. [boot.v2.dd-oracle.consumed]',13,10,0
dd_oracle_refused_text:     db '[PBM] Driver-domain oracle request refused; boot unchanged. [boot.v2.dd-oracle.refused]',13,10,0
dd_oracle_published_text:   db '[PBM] Driver-domain oracle handed to PaOS. [boot.v2.dd-oracle.published]',13,10,0
dd_oracle_unpublished_text: db '[PBM] Driver-domain oracle not handed over; boot unchanged. [boot.v2.dd-oracle.unpublished]',13,10,0
dd_oracle_deleted_text:     db '[PBM] Consumed driver-domain oracle request deleted. [boot.v2.dd-oracle.deleted]',13,10,0
dd_oracle_kept_text:        db '[PBM] Consumed driver-domain oracle request left in place; its sequence is spent. [boot.v2.dd-oracle.kept]',13,10,0

%macro DD_ORACLE_DATA 0
align 8
dd_oracle_guid: dd PDH1_GUID_D1
    dw PDH1_GUID_D2, PDH1_GUID_D3
    db PDH1_GUID_D4
dd_oracle_path: dw __utf16__('\EFI\PaOS\vault\ddoracle.bin'), 0
align 8
dd_oracle_record: times PDO1_SIZE db 0
dd_oracle_check: times PDO1_SIZE + 8 db 0
dd_oracle_table: times PDH1_SIZE db 0
dd_oracle_digest: times 32 db 0
dd_oracle_file: dq 0
dd_oracle_io_size: dq 0
dd_oracle_pending: db 0
dd_oracle_published: db 0
%endmacro
