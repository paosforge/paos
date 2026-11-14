;; MODULE fs/safe_write
;; LAYER 4
;; EXPORTS safe_write_wal_reserve, safe_write_wal_selftest, safe_write_commit_record, safe_write_stage_record, safe_write_open_record, safe_write_unwrap_record, safe_write_copy_raw, safe_write_records_empty, safe_write_preserve_system_records, safe_write_migrate_owner_records, safe_write_clear_records, safe_write_copy_receipt
;; IMPORTS data/crypto_envelope, fs/data_crypto_store, fs/blockdev, core/lib/sha256, core/lib/mem, core/lock
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:data
;; LOCK: safe_write_lock PROTECTS safe_write_sector_buf,safe_write_verify_buf,safe_write_open_record_buf,safe_write_receipt_digest,safe_write_wal_sequence,safe_write_commit_phase,safe_write_first_open_error,safe_write_open_cap,safe_write_sha_ctx,safe_write_rekey_old_cred,safe_write_rekey_old_len,safe_write_rekey_new_cred,safe_write_rekey_new_len,safe_write_rekey_record_buf
; ============================================================================
; fs/safe_write.asm — contract 1057's ONE journal-ready durable record path.
;
; The selected physical DATA-volume seam (1054) exposes two authenticated-record
; slots.  This module owns the only transition from an in-RAM encrypted envelope
; to those slots:
;   WAL insertion point -> complete TMP -> flush+readback -> complete PRIMARY ->
;   flush+readback.  A reset can therefore expose the prior PRIMARY or the fully
;   written TMP, never a half-row.  The reserved WAL call is intentionally a
;   scale-1 sequence reservation today; a future WAL replaces its body without
;   changing any caller.
;
; Plaintext is never accepted here.  Callers must first use data_crypto_seal_record
; and pass exactly one complete DCE_RECORD_SIZE authenticated envelope.
; ============================================================================

SAFE_SECTOR_SIZE equ 512
SAFE_RECORD_OFF  equ 344

%if SAFE_RECORD_OFF + DCE_RECORD_SIZE != SAFE_SECTOR_SIZE
    %error "safe_write record must exactly fill the reserved DATA-sector tail"
%endif

safe_write_lock_acquire:
    lea  rdi, [rel safe_write_lock]
    jmp  spin_acquire

safe_write_lock_release:
    lea  rdi, [rel safe_write_lock]
    jmp  spin_release

; Reserved insertion point for the future write-ahead log. Caller holds the
; store lock, so sequence allocation is already SMP-safe at scale 1 and beyond.
safe_write_wal_reserve:
    inc  qword [rel safe_write_wal_sequence]
    jnz  .ok
    inc  qword [rel safe_write_wal_sequence] ; zero is reserved as "no txn"
.ok:
    xor  eax, eax
    ret

; Pure scale-1 seam KAT: reserve exactly one non-zero sequence while holding the
; same lock real commits use. It never touches the disk.
safe_write_wal_selftest:
    push rbx
    call safe_write_lock_acquire
    mov  rbx, [rel safe_write_wal_sequence]
    call safe_write_wal_reserve
    test eax, eax
    jnz  .fail
    inc  rbx
    jnz  .compare
    inc  rbx
.compare:
    cmp  rbx, [rel safe_write_wal_sequence]
    jne  .fail
    xor  ebx, ebx
    jmp  .out
.fail:
    mov  ebx, -1
.out:
    call safe_write_lock_release
    mov  eax, ebx
    pop  rbx
    ret

safe_write_sector_read:
    jmp  data_crypto_block_read

safe_write_sector_write:
    jmp  data_crypto_block_write

; Caller holds safe_write_lock + persist_gap_lock.
safe_write_slot_locked:
    push rbx
    push r12
    mov  r12, rdi                         ; LBA
    mov  rbx, rsi                         ; authenticated record
    test rbx, rbx
    jz   .fail
    mov  rdi, r12
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail                            ; prefix cannot be preserved safely
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  rsi, rbx
    mov  edx, DCE_RECORD_SIZE
    call memcpy
    mov  rdi, r12
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_write          ; includes media flush
    test eax, eax
    jnz  .fail
    mov  rdi, r12
    lea  rsi, [rel safe_write_verify_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail
    lea  rdi, [rel safe_write_sector_buf]
    lea  rsi, [rel safe_write_verify_buf]
    mov  edx, SAFE_SECTOR_SIZE
    call memcmp                           ; content-grade the complete sector
    test eax, eax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Caller holds safe_write_lock. Copies one structurally complete envelope into
; RSI. Authentication remains mandatory at the consumer boundary.
safe_write_load_lba_locked:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    test rbx, rbx
    jz   .fail
    call persist_gap_lock_acquire
    mov  rdi, r12
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail_unlock
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    call data_crypto_record_valid
    test eax, eax
    jz   .fail_unlock
    mov  rdi, rbx
    lea  rsi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  edx, DCE_RECORD_SIZE
    call memcpy
    call persist_gap_lock_release
    xor  eax, eax
    jmp  .out
.fail_unlock:
    call persist_gap_lock_release
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

safe_write_hash_verified:
    lea  rdi, [rel safe_write_sha_ctx]
    call sha256_stream_init
    lea  rdi, [rel safe_write_sha_ctx]
    lea  rsi, [rel safe_write_verify_buf]
    mov  edx, SAFE_SECTOR_SIZE
    call sha256_stream_update
    test eax, eax
    jnz  .fail
    lea  rdi, [rel safe_write_sha_ctx]
    lea  rsi, [rel safe_write_receipt_digest]
    call sha256_stream_final
    ret
.fail:
    mov  eax, -1
    ret

; safe_write_stage_record(RDI=encrypted_record) -> 0/-1.  Writes and verifies
; only TMP. DBPUTKILL uses this exact mid-commit boundary before a warm reset.
safe_write_stage_record:
    push rbx
    mov  rbx, rdi
    call safe_write_lock_acquire
    mov  byte [rel safe_write_commit_phase], 1
    call safe_write_wal_reserve
    test eax, eax
    jnz  .fail
    call persist_gap_lock_acquire
    mov  rdi, DCB_LBA_TMP
    mov  rsi, rbx
    call safe_write_slot_locked
    test eax, eax
    jnz  .fail_persist
    mov  byte [rel safe_write_commit_phase], 2
    call safe_write_hash_verified
    test eax, eax
    jnz  .fail_persist
    call persist_gap_lock_release
    xor  ebx, ebx
    jmp  .out
.fail_persist:
    call persist_gap_lock_release
.fail:
    mov  ebx, -1
.out:
    call safe_write_lock_release
    mov  eax, ebx
    pop  rbx
    ret

; safe_write_commit_record(RDI=encrypted_record, RSI=optional receipt32) ->
; 0/-1. Every durable write reaches media only here. If requested, the receipt
; is copied while the store lock is still held, so another core cannot race it.
safe_write_commit_record:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    call safe_write_lock_acquire
    mov  byte [rel safe_write_commit_phase], 1
    call safe_write_wal_reserve
    test eax, eax
    jnz  .fail
    call persist_gap_lock_acquire
    mov  rdi, DCB_LBA_TMP
    mov  rsi, rbx
    call safe_write_slot_locked
    test eax, eax
    jnz  .fail_persist
    mov  byte [rel safe_write_commit_phase], 2
    mov  rdi, DCB_LBA_PRIMARY
    mov  rsi, rbx
    call safe_write_slot_locked
    test eax, eax
    jnz  .fail_persist
    mov  byte [rel safe_write_commit_phase], 3
    call safe_write_hash_verified
    test eax, eax
    jnz  .fail_persist
    test r12, r12
    jz   .receipt_done
    mov  rdi, r12
    lea  rsi, [rel safe_write_receipt_digest]
    mov  edx, 32
    call memcpy
.receipt_done:
    mov  byte [rel safe_write_commit_phase], 0
    call persist_gap_lock_release
    xor  ebx, ebx
    jmp  .out
.fail_persist:
    call persist_gap_lock_release
.fail:
    mov  ebx, -1
.out:
    call safe_write_lock_release
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; safe_write_open_record(pid,key,key_len,out,cap, stack cred,cred_len)
; -> plaintext length / -1 invalid-or-absent / -2 authenticated denial.
; PRIMARY is authoritative when it authenticates; a complete TMP is the crash
; fallback when PRIMARY is absent, for another key, or authentication-torn.
safe_write_open_record:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  [rel safe_write_open_cap], r8
    call safe_write_lock_acquire
    mov  qword [rel safe_write_first_open_error], 0
    mov  rdi, DCB_LBA_PRIMARY
    lea  rsi, [rel safe_write_open_record_buf]
    call safe_write_load_lba_locked
    test eax, eax
    jnz  .tmp
    sub  rsp, 16
    mov  rax, [rbp + 16]
    mov  [rsp], rax
    mov  rax, [rbp + 24]
    mov  [rsp + 8], rax
    lea  rdi, [rel safe_write_open_record_buf]
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    mov  r8, r15
    mov  r9, [rel safe_write_open_cap]
    call data_crypto_open_record
    add  rsp, 16
    test rax, rax
    jns  .finish
    mov  [rel safe_write_first_open_error], rax
.tmp:
    mov  rdi, DCB_LBA_TMP
    lea  rsi, [rel safe_write_open_record_buf]
    call safe_write_load_lba_locked
    test eax, eax
    jnz  .none
    sub  rsp, 16
    mov  rax, [rbp + 16]
    mov  [rsp], rax
    mov  rax, [rbp + 24]
    mov  [rsp + 8], rax
    lea  rdi, [rel safe_write_open_record_buf]
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    mov  r8, r15
    mov  r9, [rel safe_write_open_cap]
    call data_crypto_open_record
    add  rsp, 16
    test rax, rax
    jns  .finish
    cmp  rax, -2
    je   .finish
    cmp  qword [rel safe_write_first_open_error], -2
    jne  .finish
    mov  rax, -2
    jmp  .finish
.none:
    mov  rax, [rel safe_write_first_open_error]
    test rax, rax
    js   .finish
    mov  rax, -1
.finish:
    mov  rbx, rax
    mov  qword [rel safe_write_first_open_error], 0
    call safe_write_lock_release
    mov  rax, rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; safe_write_unwrap_record(RDI=credential,RSI=len) -> 0/-1/-2.
safe_write_unwrap_record:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call safe_write_lock_acquire
    mov  qword [rel safe_write_first_open_error], 0
    mov  rdi, DCB_LBA_PRIMARY
    lea  rsi, [rel safe_write_open_record_buf]
    call safe_write_load_lba_locked
    test eax, eax
    jnz  .tmp
    lea  rdi, [rel safe_write_open_record_buf]
    mov  rsi, r12
    mov  rdx, r13
    call data_crypto_unwrap_credential
    test eax, eax
    jz   .finish
    movsxd rax, eax
    mov  [rel safe_write_first_open_error], rax
.tmp:
    mov  rdi, DCB_LBA_TMP
    lea  rsi, [rel safe_write_open_record_buf]
    call safe_write_load_lba_locked
    test eax, eax
    jnz  .none
    lea  rdi, [rel safe_write_open_record_buf]
    mov  rsi, r12
    mov  rdx, r13
    call data_crypto_unwrap_credential
    cdqe
    jmp  .finish
.none:
    mov  rax, [rel safe_write_first_open_error]
    test rax, rax
    js   .finish
    mov  rax, -1
.finish:
    mov  rbx, rax
    mov  qword [rel safe_write_first_open_error], 0
    call safe_write_lock_release
    mov  rax, rbx
    pop  r13
    pop  r12
    pop  rbx
    ret

; safe_write_copy_raw(RDI=out,RSI=cap,RDX=key,RCX=key_len) ->
; DCE_RECORD_SIZE/-1. The caller authenticates the principal boundary first;
; this layer additionally selects the exact requested key so a valid PRIMARY
; for another row cannot mask the requested crash-fallback record in TMP.
safe_write_copy_raw:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  rbx, rsi
    mov  r13, rdx
    mov  r14, rcx
    test r12, r12
    jz   .fail
    cmp  rbx, DCE_RECORD_SIZE
    jb   .fail
    test r13, r13
    jz   .fail
    test r14, r14
    jz   .fail
    call safe_write_lock_acquire
    mov  rdi, DCB_LBA_PRIMARY
    mov  rsi, r12
    call safe_write_load_lba_locked
    test eax, eax
    jnz  .tmp
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call data_crypto_record_matches_key
    test eax, eax
    jnz  .ok_unlock
.tmp:
    mov  rdi, DCB_LBA_TMP
    mov  rsi, r12
    call safe_write_load_lba_locked
    test eax, eax
    jnz  .fail_unlock
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call data_crypto_record_matches_key
    test eax, eax
    jz   .fail_unlock
.ok_unlock:
    call safe_write_lock_release
    mov  eax, DCE_RECORD_SIZE
    jmp  .out
.fail_unlock:
    call safe_write_lock_release
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; safe_write_records_empty -> EAX=1 only when both durable slots were read and
; every record byte is zero, 0 when any prior record exists, -1 on I/O error.
; Password enrollment uses this fresh-appliance proof before changing the owner
; credential source; unreadable media never masquerades as an empty store.
safe_write_records_empty:
    push rbx
    call safe_write_lock_acquire
    call persist_gap_lock_acquire
    mov  edi, DCB_LBA_PRIMARY
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .io
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  ecx, DCE_RECORD_SIZE
    call .slot_nonzero
    test eax, eax
    jnz  .occupied
    mov  edi, DCB_LBA_TMP
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .io
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  ecx, DCE_RECORD_SIZE
    call .slot_nonzero
    test eax, eax
    jnz  .occupied
    mov  ebx, 1
    jmp  .unlock
.occupied:
    xor  ebx, ebx
    jmp  .unlock
.io:
    mov  ebx, -1
.unlock:
    call persist_gap_lock_release
    call safe_write_lock_release
    mov  eax, ebx
    pop  rbx
    ret
.slot_nonzero:
    xor  eax, eax
.scan:
    or   al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .scan
    movzx eax, al
    ret

; Caller holds safe_write_lock + persist_gap_lock. RDI=LBA.
; Returns 0 with a verified transformed record in safe_write_rekey_record_buf,
; 1 for an all-zero slot, or -1 for malformed/foreign/unauthenticated/I/O state.
; No media byte changes here: source selection completes before the normal
; TMP->PRIMARY safe-write transaction begins.
safe_write_rekey_source_locked:
    push rbx
    push r12
    mov  r12, rdi
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail
    lea  rbx, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  rdi, rbx
    call data_crypto_record_valid
    test eax, eax
    jnz  .record
    mov  rdi, rbx
    mov  ecx, DCE_RECORD_SIZE
    xor  eax, eax
.zero_scan:
    or   al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .zero_scan
    test al, al
    jnz  .fail
    mov  ebx, 1
    jmp  .out
.record:
    lea  rdi, [rel safe_write_rekey_record_buf]
    mov  rsi, rbx
    mov  edx, DCE_RECORD_SIZE
    call memcpy
    lea  rdi, [rel safe_write_rekey_record_buf]
    ; Preserve the authenticated record's principal domain.  The Dell durable
    ; row is a SYSTEM-owned (pid 2) envelope; forcing OWNER here derives a
    ; different KEK and falsely classifies valid owner data as foreign.  The
    ; structural validator above already required a nonzero low-24-bit pid and
    ; bounded nonzero length; the unwrap/data tags authenticate this value.
    mov  esi, [rel safe_write_rekey_record_buf + DCE_PIDLEN]
    and  esi, 0x00ffffff
    mov  rdx, [rel safe_write_rekey_old_cred]
    mov  rcx, [rel safe_write_rekey_old_len]
    mov  r8, [rel safe_write_rekey_new_cred]
    mov  r9, [rel safe_write_rekey_new_len]
    call data_crypto_rekey_record
    test eax, eax
    jnz  .fail
    ; data_crypto_rekey_record earned a new-key unwrap plus full plaintext-open
    ; comparison; this buffer is now safe to hand to the durable commit path.
    xor  ebx, ebx
    jmp  .out
.fail:
    mov  ebx, -1
.out:
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; safe_write_migrate_owner_records(old_credential,old_len,new_credential,new_len)
; -> 0 when both slots are proven all-zero, 1 when every present generation is
; represented by a verified rewrap, -1 on any unreadable/foreign state. PRIMARY
; is the authoritative committed record; TMP is consulted only as its normal
; crash fallback. The transformed record then uses the existing TMP->PRIMARY
; transaction, keeping old PRIMARY retryable until the final replacement.
;
; safe_write_preserve_system_records(system_credential,len) -> 1 only when the
; two existing tails are byte-identical PID2 records authenticated under the
; persisted SYSTEM credential; 0 when PRIMARY is empty or a PID1 record; -1
; for unreadable, foreign, divergent, or unauthenticated media. A SYSTEM keep
; has no dependency on the owner's password. Verify the full unwrap/data tags
; in a scratch copy, then leave BOTH media copies untouched during enrollment.
; The same-credential rekey is never persisted: it is a bounded way to reuse
; data_crypto_rekey_record's complete authenticated-open/readback proof.
safe_write_preserve_system_records:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    test r12, r12
    jz   .bad_unlocked
    cmp  r13, 32
    jne  .bad_unlocked
    call safe_write_lock_acquire
    call persist_gap_lock_acquire
    mov  edi, DCB_LBA_PRIMARY
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail_locked
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    call data_crypto_record_valid
    test eax, eax
    jz   .zero_or_foreign
    mov  eax, [rel safe_write_sector_buf + SAFE_RECORD_OFF + DCE_PIDLEN]
    and  eax, 0x00ffffff
    cmp  eax, 2
    je   .verify_system
    cmp  eax, DCE_OWNER_PID
    jne  .fail_locked
    xor  ebx, ebx
    jmp  .unlock
.zero_or_foreign:
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  ecx, DCE_RECORD_SIZE
    xor  eax, eax
.zero_scan:
    or   al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .zero_scan
    test al, al
    jnz  .fail_locked
    xor  ebx, ebx
    jmp  .unlock
.verify_system:
    lea  rdi, [rel safe_write_verify_buf]
    lea  rsi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    mov  edx, DCE_RECORD_SIZE
    call memcpy
    lea  rdi, [rel safe_write_rekey_record_buf]
    lea  rsi, [rel safe_write_verify_buf]
    mov  edx, DCE_RECORD_SIZE
    call memcpy
    lea  rdi, [rel safe_write_rekey_record_buf]
    mov  esi, 2
    mov  rdx, r12
    mov  rcx, r13
    mov  r8, r12
    mov  r9, r13
    call data_crypto_rekey_record
    test eax, eax
    jnz  .fail_locked
    mov  edi, DCB_LBA_TMP
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail_locked
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    lea  rsi, [rel safe_write_verify_buf]
    mov  edx, DCE_RECORD_SIZE
    call memcmp
    test eax, eax
    jnz  .fail_locked
    mov  ebx, 1
    jmp  .unlock
.fail_locked:
    mov  ebx, -1
.unlock:
    lea  rdi, [rel safe_write_verify_buf]
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
    lea  rdi, [rel safe_write_rekey_record_buf]
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
    call persist_gap_lock_release
    call safe_write_lock_release
    mov  eax, ebx
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad_unlocked:
    mov  eax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

safe_write_migrate_owner_records:
    push rbx
    push r12
    mov  [rel safe_write_rekey_old_cred], rdi
    mov  [rel safe_write_rekey_old_len], rsi
    mov  [rel safe_write_rekey_new_cred], rdx
    mov  [rel safe_write_rekey_new_len], rcx
    test rdi, rdi
    jz   .fail_unlocked
    test rsi, rsi
    jz   .fail_unlocked
    test rdx, rdx
    jz   .fail_unlocked
    test rcx, rcx
    jz   .fail_unlocked
    call safe_write_lock_acquire
    call persist_gap_lock_acquire
    mov  edi, DCB_LBA_PRIMARY
    call safe_write_rekey_source_locked
    test eax, eax
    jz   .commit
    mov  r12d, eax                         ; PRIMARY empty(1) or unusable(-1)
    mov  edi, DCB_LBA_TMP
    call safe_write_rekey_source_locked
    test eax, eax
    js   .fail_locked
    jz   .commit
    ; Both are empty only when PRIMARY was also positively all-zero. An empty
    ; TMP cannot erase evidence of an unreadable/foreign PRIMARY.
    cmp  r12d, 1
    jne  .fail_locked
    xor  ebx, ebx
    jmp  .unlock
.commit:
    ; The ordinary commit order preserves old PRIMARY until a fully read-back
    ; new-key TMP exists, then advances PRIMARY and read-backs it too.
    mov  edi, DCB_LBA_TMP
    lea  rsi, [rel safe_write_rekey_record_buf]
    call safe_write_slot_locked
    test eax, eax
    jnz  .fail_locked
    mov  edi, DCB_LBA_PRIMARY
    lea  rsi, [rel safe_write_rekey_record_buf]
    call safe_write_slot_locked
    test eax, eax
    jnz  .fail_locked
    mov  ebx, 1
    jmp  .unlock
.fail_locked:
    mov  ebx, -1
.unlock:
    call persist_gap_lock_release
    call safe_write_lock_release
    jmp  .wipe
.fail_unlocked:
    mov  ebx, -1
.wipe:
    mov  qword [rel safe_write_rekey_old_cred], 0
    mov  qword [rel safe_write_rekey_old_len], 0
    mov  qword [rel safe_write_rekey_new_cred], 0
    mov  qword [rel safe_write_rekey_new_len], 0
    lea  rdi, [rel safe_write_rekey_record_buf]
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; Caller holds safe_write_lock + persist_gap_lock.
safe_write_clear_slot_locked:
    push r12
    mov  r12, rdi
    mov  rdi, r12
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail
    lea  rdi, [rel safe_write_sector_buf + SAFE_RECORD_OFF]
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
    mov  rdi, r12
    lea  rsi, [rel safe_write_sector_buf]
    call safe_write_sector_write
    test eax, eax
    jnz  .fail
    mov  rdi, r12
    lea  rsi, [rel safe_write_verify_buf]
    call safe_write_sector_read
    test eax, eax
    jnz  .fail
    lea  rdi, [rel safe_write_verify_buf + SAFE_RECORD_OFF]
    lea  rsi, [rel safe_write_zero_record]
    mov  edx, DCE_RECORD_SIZE
    call memcmp
    test eax, eax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    ret

safe_write_clear_records:
    push rbx
    call safe_write_lock_acquire
    call safe_write_wal_reserve
    test eax, eax
    jnz  .fail_locked
    call persist_gap_lock_acquire
    mov  rdi, DCB_LBA_TMP
    call safe_write_clear_slot_locked
    test eax, eax
    jnz  .fail
    mov  rdi, DCB_LBA_PRIMARY
    call safe_write_clear_slot_locked
    test eax, eax
    jnz  .fail
    xor  ebx, ebx
    jmp  .unlock
.fail:
    mov  ebx, -1
.unlock:
    call persist_gap_lock_release
.finish:
    call safe_write_lock_release
    mov  eax, ebx
    pop  rbx
    ret
.fail_locked:
    mov  ebx, -1
    jmp  .finish

safe_write_copy_receipt:
    push rbx
    mov  rbx, rdi
    test rbx, rbx
    jz   .fail
    call safe_write_lock_acquire
    mov  rdi, rbx
    lea  rsi, [rel safe_write_receipt_digest]
    mov  edx, 32
    call memcpy
    call safe_write_lock_release
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  rbx
    ret

align 8
safe_write_lock:             db 0
safe_write_commit_phase:     db 0
align 8
safe_write_wal_sequence:     dq 0
safe_write_first_open_error: dq 0
safe_write_open_cap:         dq 0
safe_write_rekey_old_cred:   dq 0
safe_write_rekey_old_len:    dq 0
safe_write_rekey_new_cred:   dq 0
safe_write_rekey_new_len:    dq 0
safe_write_sector_buf:       times SAFE_SECTOR_SIZE db 0
safe_write_verify_buf:       times SAFE_SECTOR_SIZE db 0
safe_write_open_record_buf:  times DCE_RECORD_SIZE db 0
safe_write_zero_record:      times DCE_RECORD_SIZE db 0
safe_write_rekey_record_buf: times DCE_RECORD_SIZE db 0
safe_write_receipt_digest:   times 32 db 0
safe_write_sha_ctx:          times S256_CTX_SZ db 0
