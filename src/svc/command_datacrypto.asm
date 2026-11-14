;; MODULE svc/command_datacrypto
;; LAYER 5
;; EXPORTS dsec_declare, cmd_verb_dsecput, cmd_verb_dsecget, cmd_verb_dsecgetas, cmd_verb_dsecunwrap, cmd_verb_dsecdel, dsec_out_buf, dsec_out_ready
;; IMPORTS data/crypto_envelope, fs/data_crypto_store, fs/safe_write, sec/principal, svc/command, core/lib/fmt, core/lib/mem, core/lock
;; CAPS
;; OWNER saga:sec
;; LOCK: dsec_store_lock PROTECTS dsec_record_buf,dsec_plain_buf,dsec_receipt_digest,dsec_out_buf,dsec_tok_ptr,dsec_tok_len
; ============================================================================
; Contract 1054's single owned-data write/read seam.  Plaintext enters only at
; data_crypto_seal_record and the returned 168-byte authenticated envelope is
; inserted into a persistent sector before blk_write is reachable.  Reads make
; the inverse transition only after authenticated DEK unwrap and data open.
;
; Persistent placement: the two record slots (PRIMARY/TMP) live in the PaOS-
; owned NVRAM variable PaOSDataRecord (PETER 2026-09-30 06:22 storage ruling);
; fs/data_crypto_store migrated any legacy GPT-gap (0x700/0x708 bytes 344..511)
; record there by read-and-copy and never writes the gap.  Without runtime NVRAM
; only a QEMU test-scratch device keeps the legacy raw slots.  All paths
; serialize through fs/blockdev's persist_gap_lock.
; ============================================================================

DSEC_OUT_CAP     equ 512
DSEC_TOK_MAX     equ 3

dsec_store_lock_acquire:
    lea  rdi, [rel dsec_store_lock]
    jmp  spin_acquire

dsec_store_lock_release:
    lea  rdi, [rel dsec_store_lock]
    jmp  spin_release

; Compatibility adapters: contract 1057 moved every durable record mutation
; behind fs/safe_write.  The 1054 command vocabulary remains unchanged.
dsec_commit_record:
    lea  rsi, [rel dsec_receipt_digest]
    jmp  safe_write_commit_record

; dsec_try_open(pid,key,key_len,out,cap) -> len/-1/-2.
dsec_try_open:
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
    mov  rdi, r12
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, rbx
    call safe_write_open_record
    add  rsp, 16
    mov  r10, rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  rax, r10
    ret

; dsec_try_unwrap(credential,len) -> 0/-1/-2.
dsec_try_unwrap:
    jmp  safe_write_unwrap_record

; dsec_delete_key(key,key_len) authenticates the named record before deletion.
dsec_delete_key:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    call principal_current
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, rbx
    lea  rcx, [rel dsec_plain_buf]
    mov  r8d, DCE_CIPHER_CAP
    call dsec_try_open
    test rax, rax
    js   .fail
    lea  rdi, [rel dsec_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call safe_write_clear_records
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

; ---------------------------------------------------------------------------
; Command parsing/output.
; ---------------------------------------------------------------------------
dsec_tokenize:
    lea  r9, [rel dsec_tok_ptr]
    lea  r10, [rel dsec_tok_len]
    xor  ecx, ecx
.clear:
    cmp  ecx, DSEC_TOK_MAX
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
    cmp  r8d, DSEC_TOK_MAX
    jb   .room
    mov  r8d, DSEC_TOK_MAX + 1
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
    mov  [rel dsec_tok_count], r8d
    ret

dsec_parse_u64:
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

dsec_out_reset:
    lea  rax, [rel dsec_out_buf]
    mov  [rel dsec_out_cur], rax
    mov  byte [rax], 0
    ret

dsec_out_str:
    mov  rsi, [rel dsec_out_cur]
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
    mov  [rel dsec_out_cur], rsi
    ret

dsec_out_token:
    mov  rax, [rel dsec_out_cur]
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
    mov  [rel dsec_out_cur], rax
    ret

dsec_out_dec:
    mov  rsi, [rel dsec_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel dsec_out_cur], rsi
    ret

dsec_out_digest:
    push rbx
    mov  rdx, [rel dsec_out_cur]
    lea  rbx, [rel dsec_hex]
    xor  ecx, ecx
.byte:
    cmp  ecx, 32
    jae  .done
    movzx eax, byte [rdi + rcx]
    mov  r8d, eax
    shr  r8d, 4
    and  eax, 15
    mov  r8b, [rbx + r8]
    mov  [rdx], r8b
    mov  al, [rbx + rax]
    mov  [rdx + 1], al
    add  rdx, 2
    inc  ecx
    jmp  .byte
.done:
    mov  byte [rdx], 0
    mov  [rel dsec_out_cur], rdx
    pop  rbx
    ret

dsec_error:
    call dsec_out_reset
    call dsec_out_str
    mov  byte [rel dsec_out_ready], 1
    ret

; ---------------------------------------------------------------------------
; Registry declaration + verbs.
; ---------------------------------------------------------------------------
dsec_declare:
    lea  rdi, [rel str_verb_dsecput]
    lea  rsi, [rel cmd_verb_dsecput]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    lea  rdi, [rel str_verb_dsecget]
    lea  rsi, [rel cmd_verb_dsecget]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dsecgetas]
    lea  rsi, [rel cmd_verb_dsecgetas]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dsecunwrap]
    lea  rsi, [rel cmd_verb_dsecunwrap]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_dsecdel]
    lea  rsi, [rel cmd_verb_dsecdel]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    ret

; RDI=request -> EAX 0 proceed, 1 refused with the reply written. Runs before any record is
; opened. Peter 87337: no sealed data over SSH before first local unlock. A later lock wipes the
; key, so the same answer holds until the owner unlocks again. A restricted key never reads.
dsec_ssh_gate:
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_SSH
    jne  .open
    lea  rdi, [rel str_dsec_err_sealed]
    cmp  byte [rel session_local_unlock_seen], 1
    jne  .refuse
    mov  edi, PRIN_OWNER
    call principal_credential
    lea  rdi, [rel str_dsec_err_sealed]
    test rax, rax
    jz   .refuse
    call command_auth_owner_request
    lea  rdi, [rel str_dsec_err_key]
    cmp  eax, 2
    jne  .refuse
.open:
    xor  eax, eax
    ret
.refuse:
    call dsec_error
    ; SEC 89788: a script over SSH sees a refusal, not exit 0. Only ssh_channel dispatches this source.
    mov  qword [rel ssh_exec_rsp + RSP_CODE], CMDE_AUTHDENY
    mov  eax, 1
    ret

cmd_verb_dsecput:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call dsec_store_lock_acquire
    mov  rdi, rbx
    call dsec_ssh_gate
    test eax, eax
    jnz  .out
    mov  rdi, [rbx + REQ_ARG]
    call dsec_tokenize
    cmp  dword [rel dsec_tok_count], 2
    jne  .bad_args
    mov  eax, [rel dsec_tok_len]
    test eax, eax
    jz   .bad_args
    cmp  eax, DCE_KEY_MAX
    ja   .bad_args
    mov  eax, [rel dsec_tok_len + 4]
    test eax, eax
    jz   .bad_args
    cmp  eax, DCE_CIPHER_CAP
    ja   .bad_args
    call principal_current
    mov  [rel dsec_active_pid], rax
    mov  rdi, rax
    call principal_credential
    sub  rsp, 16
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    lea  rdi, [rel dsec_record_buf]
    mov  rsi, [rel dsec_active_pid]
    mov  rdx, [rel dsec_tok_ptr]
    mov  ecx, [rel dsec_tok_len]
    mov  r8, [rel dsec_tok_ptr + 8]
    mov  r9d, [rel dsec_tok_len + 4]
    call data_crypto_seal_record
    add  rsp, 16
    test eax, eax
    jnz  .crypto_fail
    lea  rdi, [rel dsec_record_buf]
    call dsec_commit_record
    test eax, eax
    jnz  .io_fail
    call dsec_out_reset
    lea  rdi, [rel str_dsec_put_ok]
    call dsec_out_str
    call data_crypto_block_name
    test rax, rax
    jz   .io_fail
    mov  rdi, rax
    call dsec_out_str
    call data_crypto_backend_is_nvram
    test eax, eax
    jz   .raw_slot
    ; PaOS-owned NVRAM backend: the receipt names the slot, not a disk LBA.
    lea  rdi, [rel str_dsec_nv_slot]
    call dsec_out_str
    jmp  .receipt
.raw_slot:
    lea  rdi, [rel str_dsec_lba]
    call dsec_out_str
    mov  edi, DCB_LBA_PRIMARY
    call dsec_out_dec
    lea  rdi, [rel str_dsec_sectors]
    call dsec_out_str
    mov  edi, 1
    call dsec_out_dec
.receipt:
    lea  rdi, [rel str_dsec_sha]
    call dsec_out_str
    lea  rdi, [rel dsec_receipt_digest]
    call dsec_out_digest
    mov  byte [rel dsec_out_ready], 1
    jmp  .out
.bad_args:
    lea  rdi, [rel str_dsec_err_args]
    call dsec_error
    jmp  .out
.crypto_fail:
    lea  rdi, [rel str_dsec_err_crypto]
    call dsec_error
    jmp  .out
.io_fail:
    lea  rdi, [rel str_dsec_err_io]
    call dsec_error
.out:
    call dsec_store_lock_release
    pop  rbx
    ret

cmd_verb_dsecget:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call dsec_store_lock_acquire
    mov  rdi, rbx
    call dsec_ssh_gate
    test eax, eax
    jnz  .wipe
    mov  rdi, [rbx + REQ_ARG]
    call dsec_tokenize
    cmp  dword [rel dsec_tok_count], 1
    jne  .bad
    call principal_current
    mov  rdi, rax
    mov  rsi, [rel dsec_tok_ptr]
    mov  edx, [rel dsec_tok_len]
    lea  rcx, [rel dsec_plain_buf]
    mov  r8d, DCE_CIPHER_CAP
    call dsec_try_open
    test rax, rax
    js   .open_fail
    mov  ebx, eax
    call dsec_out_reset
    lea  rdi, [rel str_dsec_get_ok]
    call dsec_out_str
    lea  rdi, [rel dsec_plain_buf]
    mov  esi, ebx
    call dsec_out_token
    mov  byte [rel dsec_out_ready], 1
    jmp  .wipe
.open_fail:
    cmp  eax, -2
    je   .denied
    lea  rdi, [rel str_dsec_err_no_record]
    call dsec_error
    jmp  .wipe
.denied:
    lea  rdi, [rel str_dsec_err_decrypt]
    call dsec_error
    jmp  .wipe
.bad:
    lea  rdi, [rel str_dsec_err_args]
    call dsec_error
.wipe:
    lea  rdi, [rel dsec_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call dsec_store_lock_release
    pop  rbx
    ret

cmd_verb_dsecgetas:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  rbx, rdi
    call dsec_store_lock_acquire
    mov  rdi, rbx
    call dsec_ssh_gate
    test eax, eax
    jnz  .wipe
    mov  rdi, [rbx + REQ_ARG]
    call dsec_tokenize
    cmp  dword [rel dsec_tok_count], 2
    jne  .bad
    mov  rdi, [rel dsec_tok_ptr]
    mov  esi, [rel dsec_tok_len]
    call dsec_parse_u64
    test edx, edx
    jnz  .bad
    mov  r12, rax
    mov  rdi, r12
    mov  rsi, [rel dsec_tok_ptr + 8]
    mov  edx, [rel dsec_tok_len + 4]
    lea  rcx, [rel dsec_plain_buf]
    mov  r8d, DCE_CIPHER_CAP
    call dsec_try_open
    test rax, rax
    js   .open_fail
    mov  ebx, eax                         ; unexpected success is surfaced, never hidden
    call dsec_out_reset
    lea  rdi, [rel str_dsec_getas_ok]
    call dsec_out_str
    lea  rdi, [rel dsec_plain_buf]
    mov  esi, ebx
    call dsec_out_token
    mov  byte [rel dsec_out_ready], 1
    jmp  .wipe
.open_fail:
    cmp  eax, -2
    jne  .no_record
    lea  rdi, [rel str_dsec_err_decrypt]
    call dsec_error
    jmp  .wipe
.no_record:
    lea  rdi, [rel str_dsec_err_no_record]
    call dsec_error
    jmp  .wipe
.bad:
    lea  rdi, [rel str_dsec_err_args]
    call dsec_error
.wipe:
    lea  rdi, [rel dsec_plain_buf]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP
    call memset
    call dsec_store_lock_release
    pop  r12
    pop  rbx
    ret

cmd_verb_dsecunwrap:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call dsec_store_lock_acquire
    mov  rdi, rbx
    call dsec_ssh_gate
    test eax, eax
    jnz  .out
    mov  rdi, [rbx + REQ_ARG]
    call dsec_tokenize
    cmp  dword [rel dsec_tok_count], 1
    jne  .bad
    mov  rdi, [rel dsec_tok_ptr]
    mov  esi, [rel dsec_tok_len]
    call dsec_try_unwrap
    test eax, eax
    jnz  .denied
    lea  rdi, [rel str_dsec_unwrap_ok]
    call dsec_error
    jmp  .out
.denied:
    lea  rdi, [rel str_dsec_err_unwrap]
    call dsec_error
    jmp  .out
.bad:
    lea  rdi, [rel str_dsec_err_args]
    call dsec_error
.out:
    call dsec_store_lock_release
    pop  rbx
    ret

cmd_verb_dsecdel:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rdi
    call dsec_store_lock_acquire
    mov  rdi, rbx
    call dsec_ssh_gate
    test eax, eax
    jnz  .out
    mov  rdi, [rbx + REQ_ARG]
    call dsec_tokenize
    cmp  dword [rel dsec_tok_count], 1
    jne  .bad
    mov  rdi, [rel dsec_tok_ptr]
    mov  esi, [rel dsec_tok_len]
    call dsec_delete_key
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_dsec_del_ok]
    call dsec_error
    jmp  .out
.fail:
    lea  rdi, [rel str_dsec_err_no_record]
    call dsec_error
    jmp  .out
.bad:
    lea  rdi, [rel str_dsec_err_args]
    call dsec_error
.out:
    call dsec_store_lock_release
    pop  rbx
    ret

align 8
dsec_store_lock:       db 0
dsec_out_ready:        db 0
align 8
dsec_out_cur:          dq 0
dsec_active_pid:       dq PRIN_OWNER
dsec_tok_count:        dd 0
align 8
dsec_tok_ptr:          times DSEC_TOK_MAX dq 0
dsec_tok_len:          times DSEC_TOK_MAX dd 0
dsec_record_buf:       times DCE_RECORD_SIZE db 0
dsec_plain_buf:        times DCE_CIPHER_CAP db 0
dsec_receipt_digest:   times 32 db 0
dsec_out_buf:          times DSEC_OUT_CAP db 0

dsec_hex:              db "0123456789abcdef"
str_verb_dsecput:      db "DSECPUT",0
str_verb_dsecget:      db "DSECGET",0
str_verb_dsecgetas:    db "DSECGETAS",0
str_verb_dsecunwrap:   db "DSECUNWRAP",0
str_verb_dsecdel:      db "DSECDEL",0

str_dsec_put_ok:       db "DSECPUT STORED BACKEND=",0
str_dsec_lba:          db " LBA=",0
str_dsec_sectors:      db " SECTORS=",0
str_dsec_sha:          db " CIPHER_SHA256=",0
str_dsec_nv_slot:      db " SLOT=PRIMARY",0
str_dsec_get_ok:       db "DSECGET OK ",0
str_dsec_getas_ok:     db "DSECGETAS OK ",0
str_dsec_unwrap_ok:    db "DSECUNWRAP OK",0
str_dsec_del_ok:       db "DSECDEL OK",0
str_dsec_err_args:     db "ERR bad_args",0
str_dsec_err_crypto:   db "ERR crypto_unavailable",0
str_dsec_err_io:       db "ERR storage_io",0
str_dsec_err_no_record: db "ERR no_record",0
str_dsec_err_decrypt:  db "ERR decrypt_denied",0
str_dsec_err_sealed:   db "ERR sealed_until_local_unlock: unlock at this computer first",0
str_dsec_err_key:      db "ERR key_not_allowed: this SSH key cannot read sealed data",0
str_dsec_err_unwrap:   db "ERR unwrap_denied",0
