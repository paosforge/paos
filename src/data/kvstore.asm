;; MODULE data/kvstore
;; LAYER 5
;; EXPORTS kvstore_selftest, kvstore_system_attribution_selftest, kvstore_declare, kv_internal_blob_get, kv_internal_blob_put, cmd_verb_dbput, cmd_verb_dbget, cmd_verb_dbraw, cmd_verb_dbgetas, cmd_verb_dbputkill, kv_out_buf, kv_out_ready, kv_reboot_pending, kv_m_header, kv_m_durable, kv_m_atrest
;; IMPORTS data/crypto_envelope, fs/safe_write, sec/principal, svc/command, core/capability, core/lib/crypto, core/lib/fmt, core/lib/mem, core/lock, boot/serial
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:data
;; LOCK: kv_store_lock PROTECTS kv_store_state,kv_plain_buf,kv_old_plain_buf,kv_open_buf,kv_envelope_buf,kv_raw_buf,kv_tok_ptr,kv_tok_len,kv_tok_count,kv_out_buf,kv_out_cur,kv_out_ready,kv_reboot_pending,kv_plain_len,kv_next_objid,kv_kat_saved_qword,kv_next_version,kv_m_header,kv_m_durable,kv_m_atrest
; ============================================================================
; data/kvstore.asm — contract 1057 persistent OWNED key/value store.
;
; The FIRST encrypted plaintext record carries the forever header below.  No
; durable call site can bypass the sequence:
;   principal/capability boundary -> full header -> 1054 authenticated envelope
;   -> fs/safe_write WAL insertion point + verified TMP/PRIMARY commit.
;
; Header (21 bytes, followed immediately by the value):
;   +0  stable object id       qword (deterministic per owner+key, never zero)
;   +8  version / txn id       dword (0 at first write, increments on update)
;   +12 owner principal        24-bit (same width as the crypto envelope)
;   +15 schema / type tag      byte  (1 = opaque KV bytes)
;   +16 integrity checksum     dword (low FNV-1a hash of plaintext value)
;   +20 value length           byte
;
; The compact fixed header leaves 35 bytes for the caller's value inside 1054's
; 56-byte authenticated ciphertext capacity.  Key identity remains in the outer
; envelope's authenticated SHA-256 selector; no plaintext key reaches disk.
; ============================================================================

KV_OBJID       equ 0
KV_VERSION     equ 8
KV_OWNER       equ 12
KV_SCHEMA      equ 15
KV_CHECKSUM    equ 16
KV_VALUE_LEN   equ 20
KV_VALUE       equ 21
KV_HEADER_SIZE equ 21
KV_VALUE_CAP   equ (DCE_CIPHER_CAP - KV_HEADER_SIZE)
KV_SCHEMA_BLOB equ 1
KV_TOKEN_MAX   equ 2
KV_OUT_CAP     equ 512

kv_store_lock_acquire:
    lea  rdi, [rel kv_store_lock]
    jmp  spin_acquire

kv_store_lock_release:
    lea  rdi, [rel kv_store_lock]
    jmp  spin_release

kv_header_owner:
    xor  eax, eax
    mov  ax, [rdi + KV_OWNER]
    movzx edx, byte [rdi + KV_OWNER + 2]
    shl  edx, 16
    or   eax, edx
    ret

; kv_header_valid(RDI=plain,RSI=len) -> EAX=1/0.  Every field is required and
; the value checksum is re-earned on each read; authenticated-but-malformed rows
; never escape the store boundary.
kv_header_valid:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    test rbx, rbx
    jz   .bad
    cmp  r12, KV_HEADER_SIZE
    jb   .bad
    cmp  r12, DCE_CIPHER_CAP
    ja   .bad
    cmp  qword [rbx + KV_OBJID], 0
    je   .bad
    mov  rdi, rbx
    call kv_header_owner
    test eax, eax
    jz   .bad
    cmp  byte [rbx + KV_SCHEMA], 0
    je   .bad
    movzx ecx, byte [rbx + KV_VALUE_LEN]
    test ecx, ecx
    jz   .bad
    cmp  ecx, KV_VALUE_CAP
    ja   .bad
    mov  eax, ecx
    add  eax, KV_HEADER_SIZE
    cmp  rax, r12
    jne  .bad
    lea  rdi, [rbx + KV_VALUE]
    mov  esi, ecx
    call crypto_hash64
    cmp  eax, [rbx + KV_CHECKSUM]
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Return 1 when needle occurs in haystack, otherwise 0.
kv_contains:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi                         ; haystack
    mov  r12, rsi                         ; haystack len
    mov  r13, rdx                         ; needle
    mov  r14, rcx                         ; needle len
    test r14, r14
    jz   .no
    cmp  r12, r14
    jb   .no
    sub  r12, r14
    xor  r8d, r8d
.at:
    xor  r9d, r9d
.byte:
    lea  r10, [rbx + r8]
    mov  al, [r10 + r9]
    cmp  al, [r13 + r9]
    jne  .next
    inc  r9
    cmp  r9, r14
    jb   .byte
    mov  eax, 1
    jmp  .out
.next:
    inc  r8
    cmp  r8, r12
    jbe  .at
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Open through both mandatory boundaries.  A foreign principal is denied by
; the capability checkpoint here and, independently, by pid-derived AEAD in the
; 1054 envelope (exercised by kvstore_selftest).
kv_open_owned:
    push rbx
    push r12
    push r13
    mov  r12, rdi                         ; requested pid
    mov  r13, rsi                         ; key
    mov  rbx, rdx                         ; key len
    mov  rdi, r12
    call principal_capabilities
    test rax, PMCAP_BLOCK_READ
    jz   .denied
    mov  rdi, r12
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    lea  rcx, [rel kv_open_buf]
    mov  r8d, DCE_CIPHER_CAP
    call safe_write_open_record
    add  rsp, 16
    test rax, rax
    js   .out
    mov  rbx, rax
    lea  rdi, [rel kv_open_buf]
    mov  rsi, rbx
    call kv_header_valid
    test eax, eax
    jz   .corrupt
    lea  rdi, [rel kv_open_buf]
    call kv_header_owner
    cmp  rax, r12
    jne  .denied
    mov  rax, rbx
    jmp  .out
.corrupt:
    mov  rax, -3
    jmp  .out
.denied:
    mov  rax, -2
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Build a complete forever-header plaintext. Existing same-key rows preserve
; objid and advance version; first writes derive a stable non-zero id from the
; owner+key so it survives reboot without separate allocator metadata.
kv_prepare_plain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                         ; key
    mov  r13, rsi                         ; key len
    mov  r14, rdx                         ; value
    mov  r15, rcx                         ; value len
    test r12, r12
    jz   .bad
    test r13, r13
    jz   .bad
    cmp  r13, DCE_KEY_MAX
    ja   .bad
    test r14, r14
    jz   .bad
    test r15, r15
    jz   .bad
    cmp  r15, KV_VALUE_CAP
    ja   .bad
    call principal_current
    test rax, rax
    jz   .denied
    mov  rbx, rax
    mov  rdi, rbx
    call principal_capabilities
    test rax, PMCAP_BLOCK_WRITE
    jz   .denied

    ; Default first-write identity/version.
    mov  rdi, r12
    mov  rsi, r13
    call crypto_hash64
    mov  rdx, 0x4b5653544f524531     ; "KVSTORE1" domain
    xor  rax, rdx
    xor  rax, rbx
    test rax, rax
    jnz  .new_id_ok
    mov  eax, 1
.new_id_ok:
    mov  [rel kv_next_objid], rax
    mov  dword [rel kv_next_version], 0

    ; Preserve identity on an update of the same authenticated key.
    mov  rdi, rbx
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    lea  rcx, [rel kv_old_plain_buf]
    mov  r8d, DCE_CIPHER_CAP
    call safe_write_open_record
    add  rsp, 16
    test rax, rax
    js   .compose
    mov  rcx, rax
    lea  rdi, [rel kv_old_plain_buf]
    mov  rsi, rcx
    call kv_header_valid
    test eax, eax
    jz   .compose
    mov  rax, [rel kv_old_plain_buf + KV_OBJID]
    mov  [rel kv_next_objid], rax
    mov  eax, [rel kv_old_plain_buf + KV_VERSION]
    inc  eax
    mov  [rel kv_next_version], eax

.compose:
    lea  rdi, [rel kv_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    mov  rax, [rel kv_next_objid]
    mov  [rel kv_plain_buf + KV_OBJID], rax
    mov  eax, [rel kv_next_version]
    mov  [rel kv_plain_buf + KV_VERSION], eax
    mov  eax, ebx
    mov  [rel kv_plain_buf + KV_OWNER], ax
    shr  eax, 16
    mov  [rel kv_plain_buf + KV_OWNER + 2], al
    mov  byte [rel kv_plain_buf + KV_SCHEMA], KV_SCHEMA_BLOB
    mov  byte [rel kv_plain_buf + KV_VALUE_LEN], r15b
    mov  rdi, r14
    mov  rsi, r15
    call crypto_hash64
    mov  [rel kv_plain_buf + KV_CHECKSUM], eax
    lea  rdi, [rel kv_plain_buf + KV_VALUE]
    mov  rsi, r14
    mov  rdx, r15
    call memcpy
    lea  rax, [r15 + KV_HEADER_SIZE]
    jmp  .out
.denied:
    mov  rax, -2
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exercise the exact production header + AEAD path without committing a record.
; The authenticated SYSTEM caller must stamp/open pid=2, while the same bytes
; requested as OWNER must fail the pid-domain-separated unwrap. RDI/RSI carry
; an already-authenticated OWNER session handle for the reverse-direction gate.
kvstore_system_attribution_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi
    test r15, r15
    jz   .fail_unlocked
    cmp  rsi, 32
    jne  .fail_unlocked
    call kv_store_lock_acquire
    lea  rdi, [rel str_kv_system_probe_key]
    mov  esi, str_kv_system_probe_key.len
    lea  rdx, [rel str_kv_system_probe_value]
    mov  ecx, str_kv_system_probe_value.len
    call kv_prepare_plain
    test rax, rax
    js   .fail
    mov  r12, rax
    movzx ebx, word [rel kv_plain_buf + KV_OWNER]
    movzx eax, byte [rel kv_plain_buf + KV_OWNER + 2]
    shl  eax, 16
    or   ebx, eax
    cmp  ebx, PRIN_SYSTEM
    jne  .fail
    call principal_current
    cmp  rax, PRIN_SYSTEM
    jne  .fail
    mov  rbx, rax
    call principal_system_auth_credential
    test rax, rax
    jz   .fail
    mov  r13, rax
    mov  r14, rdx
    sub  rsp, 16
    mov  [rsp], r13
    mov  [rsp + 8], r14
    lea  rdi, [rel kv_envelope_buf]
    mov  rsi, rbx
    lea  rdx, [rel str_kv_system_probe_key]
    mov  ecx, str_kv_system_probe_key.len
    lea  r8, [rel kv_plain_buf]
    mov  r9, r12
    call data_crypto_seal_record
    add  rsp, 16
    test eax, eax
    jnz  .fail
    sub  rsp, 16
    mov  [rsp], r13
    mov  [rsp + 8], r14
    lea  rdi, [rel kv_envelope_buf]
    mov  rsi, rbx
    lea  rdx, [rel str_kv_system_probe_key]
    mov  ecx, str_kv_system_probe_key.len
    lea  r8, [rel kv_open_buf]
    mov  r9d, DCE_CIPHER_CAP
    call data_crypto_open_record
    add  rsp, 16
    cmp  rax, r12
    jne  .fail
    lea  rdi, [rel kv_open_buf]
    mov  rsi, r12
    call kv_header_valid
    test eax, eax
    jz   .fail
    lea  rdi, [rel kv_open_buf]
    call kv_header_owner
    cmp  eax, PRIN_SYSTEM
    jne  .fail
    sub  rsp, 16
    mov  [rsp], r13
    mov  [rsp + 8], r14
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, PRIN_OWNER
    lea  rdx, [rel str_kv_system_probe_key]
    mov  ecx, str_kv_system_probe_key.len
    lea  r8, [rel kv_open_buf]
    mov  r9d, DCE_CIPHER_CAP
    call data_crypto_open_record
    add  rsp, 16
    cmp  eax, -2
    jne  .fail

    ; Reverse the witness exactly as the contract states: an OWNER session
    ; seals a keep, then the authenticated SYSTEM principal attempts to open
    ; those same bytes and must be refused by the pid-bound AEAD envelope.
    ; The owner session exists only after a successful PASSWORD bind; this
    ; diagnostic therefore cannot manufacture the required owner key.
    call principal_leave_system
    lea  rdi, [rel str_kv_system_probe_key]
    mov  esi, str_kv_system_probe_key.len
    lea  rdx, [rel str_kv_system_probe_value]
    mov  ecx, str_kv_system_probe_value.len
    call kv_prepare_plain
    test rax, rax
    js   .fail
    mov  r12, rax
    lea  rdi, [rel kv_plain_buf]
    call kv_header_owner
    cmp  eax, PRIN_OWNER
    jne  .fail
    sub  rsp, 16
    mov  [rsp], r15
    mov  qword [rsp + 8], 32
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, PRIN_OWNER
    lea  rdx, [rel str_kv_system_probe_key]
    mov  ecx, str_kv_system_probe_key.len
    lea  r8, [rel kv_plain_buf]
    mov  r9, r12
    call data_crypto_seal_record
    add  rsp, 16
    test eax, eax
    jnz  .fail
    call principal_enter_system
    call principal_system_auth_credential
    test rax, rax
    jz   .fail
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, PRIN_SYSTEM
    lea  rdx, [rel str_kv_system_probe_key]
    mov  ecx, str_kv_system_probe_key.len
    lea  r8, [rel kv_open_buf]
    mov  r9d, DCE_CIPHER_CAP
    call data_crypto_open_record
    add  rsp, 16
    cmp  eax, -2
    jne  .fail
    mov  ebx, PRIN_SYSTEM
    jmp  .out
.fail:
    xor  ebx, ebx
.out:
    ; AUTHSYS owns this helper and expects the authenticated system context on
    ; return, including every failure path after the temporary owner leg.
    call principal_enter_system
    call kv_store_lock_release
    jmp  .return
.fail_unlocked:
    xor  ebx, ebx
.return:
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; kv_store_put(key,keylen,value,valuelen,stage_only) -> 0/-1/-2.
kv_store_put:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    call kv_prepare_plain
    test rax, rax
    js   .out
    mov  [rel kv_plain_len], rax
    call principal_current
    mov  [rel kv_active_pid], rax
    mov  rdi, rax
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    lea  rdi, [rel kv_envelope_buf]
    mov  rsi, [rel kv_active_pid]
    mov  rdx, r12
    mov  rcx, r13
    lea  r8, [rel kv_plain_buf]
    mov  r9, [rel kv_plain_len]
    call data_crypto_seal_record
    add  rsp, 16
    test eax, eax
    jnz  .crypto_fail
    lea  rdi, [rel kv_envelope_buf]
    test rbx, rbx
    jnz  .stage
    xor  esi, esi                         ; no commit receipt needed by DBPUT
    call safe_write_commit_record
    jmp  .io_done
.stage:
    call safe_write_stage_record
.io_done:
    test eax, eax
    jnz  .io_fail
    cmp  qword [rel kv_active_pid], PRIN_OWNER
    jne  .stored
    mov  byte [rel prin_owner_keeps_present], 1
.stored:
    xor  eax, eax
    jmp  .out
.crypto_fail:
    mov  rax, -2
    jmp  .out
.io_fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Narrow internal opaque-blob seam for keep services. It reuses the exact
; authenticated principal, envelope, and safe-write path used by DBPUT/DBGET.
; RDI=key, RSI=key_len, RDX=out, RCX=out_cap -> len/-1/-2/-3.
kv_internal_blob_get:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rbx, rcx
    test r14, r14
    jz   .bad
    call kv_store_lock_acquire
    call principal_current
    test rax, rax
    jz   .locked_denied
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, r13
    call kv_open_owned
    test rax, rax
    js   .locked_out
    movzx ecx, byte [rel kv_open_buf + KV_VALUE_LEN]
    cmp  rcx, rbx
    ja   .locked_bad
    mov  rdi, r14
    lea  rsi, [rel kv_open_buf + KV_VALUE]
    mov  edx, ecx
    push rcx
    call memcpy
    pop  rax
    jmp  .wipe
.locked_denied:
    mov  rax, -2
    jmp  .locked_out
.locked_bad:
    mov  rax, -1
    jmp  .wipe
.locked_out:
    push rax
    lea  rdi, [rel kv_open_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call kv_store_lock_release
    pop  rax
    jmp  .out
.wipe:
    push rax
    lea  rdi, [rel kv_open_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call kv_store_lock_release
    pop  rax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=key, RSI=key_len, RDX=value, RCX=value_len -> 0/-1/-2.
kv_internal_blob_put:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rbx, rcx
    test r14, r14
    jz   .bad
    test rbx, rbx
    jz   .bad
    cmp  rbx, KV_VALUE_CAP
    ja   .bad
    call kv_store_lock_acquire
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, rbx
    xor  r8d, r8d
    call kv_store_put
    push rax
    call kv_store_lock_release
    pop  rax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Boot KAT: header completeness + authenticated envelope round-trip + ciphertext
; plaintext-absence + foreign-principal AEAD denial. No disk is mutated at boot.
; ---------------------------------------------------------------------------
kvstore_selftest:
    push rbx
    push r12
    call kv_store_lock_acquire
    mov  byte [rel kv_m_header], 0
    mov  byte [rel kv_m_durable], 0
    mov  byte [rel kv_m_atrest], 0
    lea  rdi, [rel kv_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    mov  rax, 0x1057000000000001
    mov  [rel kv_plain_buf + KV_OBJID], rax
    mov  dword [rel kv_plain_buf + KV_VERSION], 0
    mov  word [rel kv_plain_buf + KV_OWNER], DCE_OWNER_PID
    mov  byte [rel kv_plain_buf + KV_OWNER + 2], 0
    mov  byte [rel kv_plain_buf + KV_SCHEMA], KV_SCHEMA_BLOB
    mov  byte [rel kv_plain_buf + KV_VALUE_LEN], str_kv_kat_value.len
    lea  rdi, [rel str_kv_kat_value]
    mov  esi, str_kv_kat_value.len
    call crypto_hash64
    mov  [rel kv_plain_buf + KV_CHECKSUM], eax
    lea  rdi, [rel kv_plain_buf + KV_VALUE]
    lea  rsi, [rel str_kv_kat_value]
    mov  edx, str_kv_kat_value.len
    call memcpy
    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE + str_kv_kat_value.len
    call kv_header_valid
    test eax, eax
    jz   .fail

    ; Negative header battery: every forever field is structurally mandatory.
    mov  rax, [rel kv_plain_buf + KV_OBJID]
    mov  [rel kv_kat_saved_qword], rax
    mov  qword [rel kv_plain_buf + KV_OBJID], 0
    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE + str_kv_kat_value.len
    call kv_header_valid
    test eax, eax
    jnz  .fail
    mov  rax, [rel kv_kat_saved_qword]
    mov  [rel kv_plain_buf + KV_OBJID], rax

    mov  word [rel kv_plain_buf + KV_OWNER], 0
    mov  byte [rel kv_plain_buf + KV_OWNER + 2], 0
    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE + str_kv_kat_value.len
    call kv_header_valid
    test eax, eax
    jnz  .fail
    mov  word [rel kv_plain_buf + KV_OWNER], DCE_OWNER_PID

    mov  byte [rel kv_plain_buf + KV_SCHEMA], 0
    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE + str_kv_kat_value.len
    call kv_header_valid
    test eax, eax
    jnz  .fail
    mov  byte [rel kv_plain_buf + KV_SCHEMA], KV_SCHEMA_BLOB

    mov  byte [rel kv_plain_buf + KV_VALUE_LEN], 0
    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE + str_kv_kat_value.len
    call kv_header_valid
    test eax, eax
    jnz  .fail
    mov  byte [rel kv_plain_buf + KV_VALUE_LEN], str_kv_kat_value.len

    xor  dword [rel kv_plain_buf + KV_CHECKSUM], 1
    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE + str_kv_kat_value.len
    call kv_header_valid
    test eax, eax
    jnz  .fail
    xor  dword [rel kv_plain_buf + KV_CHECKSUM], 1

    lea  rdi, [rel kv_plain_buf]
    mov  esi, KV_HEADER_SIZE - 1          ; missing tail byte of forever header
    call kv_header_valid
    test eax, eax
    jnz  .fail

    mov  edi, PRIN_OWNER
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, DCE_OWNER_PID
    lea  rdx, [rel str_kv_kat_key]
    mov  ecx, str_kv_kat_key.len
    lea  r8, [rel kv_plain_buf]
    mov  r9d, KV_HEADER_SIZE + str_kv_kat_value.len
    call data_crypto_seal_record_selftest
    add  rsp, 16
    test eax, eax
    jnz  .fail

    ; The exact KAT value must be absent from every durable envelope byte.
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, DCE_RECORD_SIZE
    lea  rdx, [rel str_kv_kat_value]
    mov  ecx, str_kv_kat_value.len
    call kv_contains
    test eax, eax
    jnz  .fail

    mov  edi, PRIN_OWNER
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, DCE_OWNER_PID
    lea  rdx, [rel str_kv_kat_key]
    mov  ecx, str_kv_kat_key.len
    lea  r8, [rel kv_old_plain_buf]
    mov  r9d, DCE_CIPHER_CAP
    call data_crypto_open_record
    add  rsp, 16
    cmp  eax, KV_HEADER_SIZE + str_kv_kat_value.len
    jne  .fail
    lea  rdi, [rel kv_old_plain_buf]
    mov  esi, eax
    call kv_header_valid
    test eax, eax
    jz   .fail
    lea  rdi, [rel kv_old_plain_buf + KV_VALUE]
    lea  rsi, [rel str_kv_kat_value]
    mov  edx, str_kv_kat_value.len
    call memcmp
    test eax, eax
    jnz  .fail

    ; Crypto boundary independently refuses the same row for a foreign pid.
    mov  edi, PRIN_OWNER
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    lea  rdi, [rel kv_envelope_buf]
    mov  esi, 424242
    lea  rdx, [rel str_kv_kat_key]
    mov  ecx, str_kv_kat_key.len
    lea  r8, [rel kv_old_plain_buf]
    mov  r9d, DCE_CIPHER_CAP
    call data_crypto_open_record
    add  rsp, 16
    cmp  eax, -2
    jne  .fail

    ; Exercise the reserved WAL insertion point and its SMP lock without media.
    call safe_write_wal_selftest
    test eax, eax
    jnz  .fail

    mov  byte [rel kv_m_header], 1
    mov  byte [rel kv_m_durable], 1
    mov  byte [rel kv_m_atrest], 1
    lea  rdi, [rel str_db_header]
    call serial_string
    lea  rdi, [rel str_db_durable]
    call serial_string
    lea  rdi, [rel str_db_atrest]
    call serial_string
    xor  ebx, ebx
    jmp  .out
.fail:
    lea  rdi, [rel str_db_fail]
    call serial_string
    mov  ebx, -1
.out:
    lea  rdi, [rel kv_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    lea  rdi, [rel kv_old_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call kv_store_lock_release
    call principal_boot_fixture_close
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Registry projection helpers.
; ---------------------------------------------------------------------------
kv_tokenize:
    lea  r9, [rel kv_tok_ptr]
    lea  r10, [rel kv_tok_len]
    xor  ecx, ecx
.clear:
    cmp  ecx, KV_TOKEN_MAX
    jae  .scan
    mov  qword [r9 + rcx*8], 0
    mov  dword [r10 + rcx*4], 0
    inc  ecx
    jmp  .clear
.scan:
    xor  r8d, r8d
    test rdi, rdi
    jz   .done
.skip:
    cmp  byte [rdi], ' '
    jne  .start
    inc  rdi
    jmp  .skip
.start:
    cmp  byte [rdi], 0
    je   .done
    cmp  r8d, KV_TOKEN_MAX
    jb   .room
    mov  r8d, KV_TOKEN_MAX + 1
    jmp  .done
.room:
    mov  [r9 + r8*8], rdi
    mov  rdx, rdi
.chars:
    cmp  byte [rdi], 0
    je   .end
    cmp  byte [rdi], ' '
    je   .end
    inc  rdi
    jmp  .chars
.end:
    mov  rax, rdi
    sub  rax, rdx
    mov  [r10 + r8*4], eax
    inc  r8d
    jmp  .skip
.done:
    mov  [rel kv_tok_count], r8d
    ret

kv_parse_u64:
    xor  eax, eax
    test esi, esi
    jz   .bad
.digit:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .bad
    imul rax, rax, 10
    jo   .bad
    add  rax, rcx
    jc   .bad
    inc  rdi
    dec  esi
    jnz  .digit
    xor  edx, edx
    ret
.bad:
    mov  edx, -1
    xor  eax, eax
    ret

kv_out_reset:
    lea  rax, [rel kv_out_buf]
    mov  [rel kv_out_cur], rax
    mov  byte [rax], 0
    ret

kv_out_str:
    mov  rsi, [rel kv_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel kv_out_cur], rsi
    ret

kv_out_token:
    mov  rax, [rel kv_out_cur]
.copy:
    test esi, esi
    jz   .done
    mov  dl, [rdi]
    mov  [rax], dl
    inc  rdi
    inc  rax
    dec  esi
    jmp  .copy
.done:
    mov  byte [rax], 0
    mov  [rel kv_out_cur], rax
    ret

kv_out_dec:
    mov  rsi, [rel kv_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel kv_out_cur], rsi
    ret

kv_out_hex:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    mov  rdx, [rel kv_out_cur]
    lea  r9, [rel kv_hex]
    xor  ecx, ecx
.byte:
    cmp  rcx, r12
    jae  .done
    movzx eax, byte [rbx + rcx]
    mov  r8d, eax
    shr  r8d, 4
    and  eax, 15
    mov  r8b, [r9 + r8]
    mov  [rdx], r8b
    mov  al, [r9 + rax]
    mov  [rdx + 1], al
    add  rdx, 2
    inc  rcx
    jmp  .byte
.done:
    mov  byte [rdx], 0
    mov  [rel kv_out_cur], rdx
    pop  r12
    pop  rbx
    ret

kv_error:
    call kv_out_reset
    call kv_out_str
    mov  byte [rel kv_out_ready], 1
    ret

kvstore_declare:
    lea  rdi, [rel str_verb_dbput]
    lea  rsi, [rel cmd_verb_dbput]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    lea  rdi, [rel str_verb_dbget]
    lea  rsi, [rel cmd_verb_dbget]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dbraw]
    lea  rsi, [rel cmd_verb_dbraw]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dbgetas]
    lea  rsi, [rel cmd_verb_dbgetas]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dbputkill]
    lea  rsi, [rel cmd_verb_dbputkill]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    ret

cmd_verb_dbput:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call kv_store_lock_acquire
    mov  rdi, [rbx + REQ_ARG]
    call kv_tokenize
    cmp  dword [rel kv_tok_count], 2
    jne  .bad
    mov  esi, [rel kv_tok_len]
    test esi, esi
    jz   .bad
    cmp  esi, DCE_KEY_MAX
    ja   .bad
    mov  ecx, [rel kv_tok_len + 4]
    test ecx, ecx
    jz   .bad
    cmp  ecx, KV_VALUE_CAP
    ja   .bad
    mov  rdi, [rel kv_tok_ptr]
    mov  rdx, [rel kv_tok_ptr + 8]
    xor  r8d, r8d
    call kv_store_put
    test eax, eax
    jnz  .put_fail
    call kv_out_reset
    lea  rdi, [rel str_dbput_ok]
    call kv_out_str
    mov  byte [rel kv_out_ready], 1
    jmp  .out
.bad:
    lea  rdi, [rel str_db_err_args]
    call kv_error
    jmp  .out
.put_fail:
    cmp  eax, -2
    je   .denied
    lea  rdi, [rel str_db_err_io]
    call kv_error
    jmp  .out
.denied:
    lea  rdi, [rel str_db_err_denied]
    call kv_error
.out:
    call kv_store_lock_release
    pop  rbx
    ret

cmd_verb_dbget:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call kv_store_lock_acquire
    mov  rdi, [rbx + REQ_ARG]
    call kv_tokenize
    cmp  dword [rel kv_tok_count], 1
    jne  .bad
    call principal_current
    mov  rdi, rax
    mov  rsi, [rel kv_tok_ptr]
    mov  edx, [rel kv_tok_len]
    call kv_open_owned
    test rax, rax
    js   .open_fail
    call kv_out_reset
    lea  rdi, [rel str_dbget_ok]
    call kv_out_str
    lea  rdi, [rel kv_open_buf + KV_VALUE]
    movzx esi, byte [rel kv_open_buf + KV_VALUE_LEN]
    call kv_out_token
    lea  rdi, [rel str_db_principal]
    call kv_out_str
    lea  rdi, [rel kv_open_buf]
    call kv_header_owner
    mov  rdi, rax
    call kv_out_dec
    lea  rdi, [rel str_db_objid]
    call kv_out_str
    mov  rdi, [rel kv_open_buf + KV_OBJID]
    call kv_out_dec
    lea  rdi, [rel str_db_version]
    call kv_out_str
    mov  edi, [rel kv_open_buf + KV_VERSION]
    call kv_out_dec
    lea  rdi, [rel str_db_schema]
    call kv_out_str
    movzx edi, byte [rel kv_open_buf + KV_SCHEMA]
    call kv_out_dec
    mov  byte [rel kv_out_ready], 1
    jmp  .out
.open_fail:
    cmp  eax, -2
    je   .denied
    cmp  eax, -3
    je   .corrupt
    lea  rdi, [rel str_db_err_notfound]
    call kv_error
    jmp  .out
.denied:
    lea  rdi, [rel str_db_err_denied]
    call kv_error
    jmp  .out
.corrupt:
    lea  rdi, [rel str_db_err_corrupt]
    call kv_error
    jmp  .out
.bad:
    lea  rdi, [rel str_db_err_args]
    call kv_error
.out:
    lea  rdi, [rel kv_open_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call kv_store_lock_release
    pop  rbx
    ret

cmd_verb_dbgetas:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  rbx, rdi
    call kv_store_lock_acquire
    mov  rdi, [rbx + REQ_ARG]
    call kv_tokenize
    cmp  dword [rel kv_tok_count], 2
    jne  .bad
    mov  rdi, [rel kv_tok_ptr]
    mov  esi, [rel kv_tok_len]
    call kv_parse_u64
    test edx, edx
    jnz  .bad
    mov  r12, rax
    mov  rdi, r12
    mov  rsi, [rel kv_tok_ptr + 8]
    mov  edx, [rel kv_tok_len + 4]
    call kv_open_owned
    test rax, rax
    js   .open_fail
    ; Unexpected success is explicit; the probe will reject any leaked value.
    lea  rdi, [rel str_dbgetas_unexpected]
    call kv_error
    jmp  .out
.open_fail:
    cmp  eax, -2
    jne  .notfound
    lea  rdi, [rel str_db_err_cross]
    call kv_error
    jmp  .out
.notfound:
    lea  rdi, [rel str_db_err_notfound]
    call kv_error
    jmp  .out
.bad:
    lea  rdi, [rel str_db_err_args]
    call kv_error
.out:
    lea  rdi, [rel kv_open_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call kv_store_lock_release
    pop  r12
    pop  rbx
    ret

cmd_verb_dbraw:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call kv_store_lock_acquire
    mov  rdi, [rbx + REQ_ARG]
    call kv_tokenize
    cmp  dword [rel kv_tok_count], 1
    jne  .bad
    call principal_current
    mov  rdi, rax
    mov  rsi, [rel kv_tok_ptr]
    mov  edx, [rel kv_tok_len]
    call kv_open_owned                    ; authenticate key before exposing raw
    test rax, rax
    js   .open_fail
    lea  rdi, [rel kv_raw_buf]
    mov  esi, DCE_RECORD_SIZE
    mov  rdx, [rel kv_tok_ptr]
    mov  ecx, [rel kv_tok_len]
    call safe_write_copy_raw
    test rax, rax
    js   .io_fail
    call kv_out_reset
    lea  rdi, [rel str_dbraw_ok]
    call kv_out_str
    lea  rdi, [rel kv_raw_buf]
    mov  esi, DCE_RECORD_SIZE
    call kv_out_hex
    mov  byte [rel kv_out_ready], 1
    jmp  .out
.open_fail:
    cmp  eax, -2
    je   .denied
    lea  rdi, [rel str_db_err_notfound]
    call kv_error
    jmp  .out
.denied:
    lea  rdi, [rel str_db_err_denied]
    call kv_error
    jmp  .out
.io_fail:
    lea  rdi, [rel str_db_err_io]
    call kv_error
    jmp  .out
.bad:
    lea  rdi, [rel str_db_err_args]
    call kv_error
.out:
    lea  rdi, [rel kv_open_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call kv_store_lock_release
    pop  rbx
    ret

cmd_verb_dbputkill:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call kv_store_lock_acquire
    mov  rdi, [rbx + REQ_ARG]
    call kv_tokenize
    cmp  dword [rel kv_tok_count], 2
    jne  .bad
    mov  esi, [rel kv_tok_len]
    test esi, esi
    jz   .bad
    cmp  esi, DCE_KEY_MAX
    ja   .bad
    mov  ecx, [rel kv_tok_len + 4]
    test ecx, ecx
    jz   .bad
    cmp  ecx, KV_VALUE_CAP
    ja   .bad
    mov  rdi, [rel kv_tok_ptr]
    mov  rdx, [rel kv_tok_ptr + 8]
    mov  r8d, 1
    call kv_store_put                   ; verified TMP only: deliberate tear point
    test eax, eax
    jnz  .put_fail
    call kv_out_reset
    lea  rdi, [rel str_dbputkill_ok]
    call kv_out_str
    mov  byte [rel kv_out_ready], 1
    mov  byte [rel kv_reboot_pending], 1 ; UDP sends ACK, then warm CF9
    jmp  .out
.bad:
    lea  rdi, [rel str_db_err_args]
    call kv_error
    jmp  .out
.put_fail:
    cmp  eax, -2
    je   .denied
    lea  rdi, [rel str_db_err_io]
    call kv_error
    jmp  .out
.denied:
    lea  rdi, [rel str_db_err_denied]
    call kv_error
.out:
    call kv_store_lock_release
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_data_kvstore_0 0
align 8
kv_store_lock:       db 0
kv_out_ready:        db 0
kv_reboot_pending:   db 0
kv_m_header:         db 0
kv_m_durable:        db 0
kv_m_atrest:         db 0
align 8
kv_store_state:      dq 0
kv_out_cur:          dq 0
kv_plain_len:        dq 0
kv_active_pid:       dq PRIN_OWNER
times 40 db 0                  ; kv_next_objid..kv_out_buf moved to WDATA_data_kvstore_0_bss1: keeps the labels below at their offset mod 64

kv_hex:                 db "0123456789abcdef"
str_kv_kat_key:         db "db-kat"
.len equ $ - str_kv_kat_key
str_kv_kat_value:       db "KV-RANDOM-KAT"
.len equ $ - str_kv_kat_value
str_kv_system_probe_key: db "system-attribution"
.len equ $ - str_kv_system_probe_key
str_kv_system_probe_value: db "pid2"
.len equ $ - str_kv_system_probe_value

str_verb_dbput:         db "DBPUT",0
str_verb_dbget:         db "DBGET",0
str_verb_dbraw:         db "DBRAW",0
str_verb_dbgetas:       db "DBGETAS",0
str_verb_dbputkill:     db "DBPUTKILL",0

str_dbput_ok:           db "DBPUT STORED",0
str_dbget_ok:           db "DBGET OK value=",0
str_db_principal:       db " principal=",0
str_db_objid:           db " objid=",0
str_db_version:         db " version=",0
str_db_schema:          db " schema=",0
str_dbraw_ok:           db "DBRAW CIPHERTEXT=",0
str_dbputkill_ok:       db "DBPUTKILL STAGED tear=after_tmp",0
str_dbgetas_unexpected: db "ERR cross_principal_unexpected_success",0
str_db_err_args:        db "ERR bad_args",0
str_db_err_denied:      db "ERR access_denied",0
str_db_err_cross:       db "ERR cross_principal_denied",0
str_db_err_notfound:    db "ERR NOTFOUND",0
str_db_err_io:          db "ERR storage_io",0
str_db_err_corrupt:     db "ERR CORRUPT checksum_fail",0

str_db_header:  db "[PAOS64] P2 db: forever record header present [db.header]",13,10,0
str_db_durable: db "[PAOS64] P2 db: journal-ready durable write path [db.durable]",13,10,0
str_db_atrest:  db "[PAOS64] P2 db: rows encrypted at rest [db.atrest]",13,10,0
str_db_fail:    db "[PAOS64] P2 db: selftest FAIL",13,10,0
%endmacro
WDATA_DEFER WDATA_data_kvstore_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_data_kvstore_0_bss1 0
resb 40                 ; keeps kv_next_objid at its WDATA offset mod 64
kv_next_objid:       resq 1
kv_kat_saved_qword:  resq 1
kv_next_version:     resd 1
kv_tok_count:        resd 1
alignb 8
kv_tok_ptr:          resq KV_TOKEN_MAX
kv_tok_len:          resd KV_TOKEN_MAX
kv_plain_buf:        resb DCE_CIPHER_CAP
kv_old_plain_buf:    resb DCE_CIPHER_CAP
kv_open_buf:         resb DCE_CIPHER_CAP
kv_envelope_buf:     resb DCE_RECORD_SIZE
kv_raw_buf:          resb DCE_RECORD_SIZE
kv_out_buf:          resb KV_OUT_CAP
%endmacro
WDATA_BSS_DEFER WDATA_data_kvstore_0_bss1
