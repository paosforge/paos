;; MODULE svc/command_backup
;; LAYER 5
;; EXPORTS backup_command_init, backup_command_tick, backup_out_buf, backup_out_ready, backup_out_cur
;; IMPORTS boot/header, core/lib/mem, core/lib/fmt, core/lib/sha256, core/lib/ustar, core/csprng, core/time, data/backup_export, fs/vfs, net/tcp, svc/command
;; CAPS
;; OWNER saga:user_data_backup
; ============================================================================
; Task1230a — one-shot, owner-consented keep export over the existing bounded
; TCP client.  The one registry verb has four subcommands:
;
;   BACKUP CONSENT <absolute-path> <ipv4> <port> <recipient-pub-hex>
;                  <positive-generation> <nonce>
;   BACKUP EXPORT  <generation> <nonce>
;   BACKUP CANCEL  <generation> <nonce>
;   BACKUP STAT    <nonce>
;
; CONSENT reads and freezes exactly one selected regular file, builds one
; complete deterministic ustar archive, and enumerates the source manifest,
; destination and recipient fingerprint without opening TCP. EXPORT must match
; that one generation, obtains its ephemeral scalar only through csprng_generate,
; RFC9180-seals the archive with the complete binary header as AAD, and sends a
; single bounded frame in paced TCP flights.  Success exists only after the LAN
; receiver returns the exact manifest+ciphertext-digest+generation ACK. CANCEL
; aborts the tuple immediately and consumes consent. No keep byte or path enters
; telemetry; the local owner-only STAT record is the receipt.
; ============================================================================

BACKUP_TOKEN_MAX  equ 7
BACKUP_PATH_CAP   equ 96
BACKUP_SOURCE_CAP equ 2048
BACKUP_HEADER_LEN equ 256
BACKUP_FRAME_CAP  equ 4096
BACKUP_CHUNK      equ 1024
BACKUP_ACK_LEN    equ 88
BACKUP_OUT_CAP    equ 1408
BACKUP_TIMEOUT_MS equ 30000

; These lifetimes are disjoint by construction: bx_ct stages the selected file
; only until the archive is built, then holds ciphertext; its upper 2048 bytes
; are free for the command response after either operation. bx_plain is used
; only by the one-time boot KAT, before commands are admitted, and then becomes
; the immutable outbound frame. Reusing the proven crypto workspaces avoids
; growing the flat PE with 7.5 KiB of duplicate zero-filled buffers.
backup_source  equ bx_ct
backup_out_buf equ bx_ct + BACKUP_SOURCE_CAP
backup_frame   equ bx_plain
%if BACKUP_SOURCE_CAP + BACKUP_OUT_CAP > BX_ARCHIVE_CAP
%error "BACKUP source/receipt workspace exceeds bx_ct"
%endif
%if BACKUP_FRAME_CAP > BX_ARCHIVE_CAP
%error "BACKUP frame workspace exceeds bx_plain"
%endif

BACKUP_ST_IDLE       equ 0
BACKUP_ST_CONSENTED  equ 1
BACKUP_ST_CONNECTING equ 2
BACKUP_ST_SENDING    equ 3
BACKUP_ST_WAIT_ACK   equ 4
BACKUP_ST_ACKED      equ 5
BACKUP_ST_FAILED     equ 6
BACKUP_ST_CANCELLED  equ 7
BACKUP_ST_COMPLETE   equ 8

backup_command_init:
    mov  byte [rel backup_out_ready], 0
    mov  byte [rel backup_state], BACKUP_ST_IDLE
    mov  byte [rel backup_consent_active], 0
    mov  qword [rel backup_tcb], 0
    mov  byte [rel backup_ack_kat_state], 0
    mov  byte [rel bx_kat_armed], 0
    mov  byte [rel bx_kat_state], 0
    lea  rdi, [rel str_backup_verb]
    lea  rsi, [rel backup_command_handler]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; owner AUTH1 MUTATE; receipt is SELF
    call command_register_verb
    ret

backup_command_handler:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    cmp  byte [rel bx_kat_state], 1
    jne  .kat_unready
    mov  rdi, [r12 + REQ_ARG]
    call backup_tokenize
    cmp  dword [rel backup_tok_count], 0
    je   .bad_args
    mov  rdi, [rel backup_tok_ptr]
    mov  esi, [rel backup_tok_len]
    lea  rdx, [rel str_backup_consent]
    mov  ecx, 7
    call backup_token_is
    test eax, eax
    jnz  .consent
    mov  rdi, [rel backup_tok_ptr]
    mov  esi, [rel backup_tok_len]
    lea  rdx, [rel str_backup_export]
    mov  ecx, 6
    call backup_token_is
    test eax, eax
    jnz  .export
    mov  rdi, [rel backup_tok_ptr]
    mov  esi, [rel backup_tok_len]
    lea  rdx, [rel str_backup_cancel]
    mov  ecx, 6
    call backup_token_is
    test eax, eax
    jnz  .cancel
    mov  rdi, [rel backup_tok_ptr]
    mov  esi, [rel backup_tok_len]
    lea  rdx, [rel str_backup_stat]
    mov  ecx, 4
    call backup_token_is
    test eax, eax
    jnz  .stat
    jmp  .bad_args
.consent:
    call backup_handle_consent
    jmp  .result
.export:
    call backup_handle_export
    jmp  .result
.cancel:
    call backup_handle_cancel
    jmp  .result
.stat:
    call backup_handle_stat
    jmp  .result
.bad_args:
    lea  rdi, [rel str_backup_bad_args]
    call backup_stage_error
    mov  eax, CMDE_BADARG
    jmp  .result
.kat_unready:
    lea  rdi, [rel str_backup_kat_unready]
    call backup_stage_error
    mov  eax, CMDE_BADARG
.result:
    mov  [r13 + RSP_CODE], rax
    test eax, eax
    jnz  .done
    mov  qword [r13 + RSP_ACCEPTED], 1
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Parse tokens in-place without modifying the stable request copy.
backup_tokenize:
    lea  r9, [rel backup_tok_ptr]
    lea  r10, [rel backup_tok_len]
    xor  ecx, ecx
.clear:
    cmp  ecx, BACKUP_TOKEN_MAX
    jae  .scan
    mov  qword [r9 + rcx*8], 0
    mov  dword [r10 + rcx*4], 0
    inc  ecx
    jmp  .clear
.scan:
    xor  r8d, r8d
    test rdi, rdi
    jz   .done
.spaces:
    cmp  byte [rdi], ' '
    jne  .start
    inc  rdi
    jmp  .spaces
.start:
    cmp  byte [rdi], 0
    je   .done
    cmp  r8d, BACKUP_TOKEN_MAX
    jae  .overflow
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
    jmp  .spaces
.overflow:
    mov  r8d, BACKUP_TOKEN_MAX + 1
.done:
    mov  [rel backup_tok_count], r8d
    ret

backup_token_is:
    cmp  esi, ecx
    jne  .no
.loop:
    test ecx, ecx
    jz   .yes
    dec  ecx
    mov  al, [rdi + rcx]
    or   al, 0x20
    cmp  al, [rdx + rcx]
    jne  .no
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Parse an unsigned decimal token. EDX=0 success / 1 failure.
backup_parse_u64:
    xor  eax, eax
    xor  edx, edx
    test esi, esi
    jz   .bad
    xor  ecx, ecx
.loop:
    cmp  ecx, esi
    jae  .ok
    movzx r8d, byte [rdi + rcx]
    sub  r8d, '0'
    cmp  r8d, 9
    ja   .bad
    mov  r9, rax
    mov  r10, 10
    mul  r10
    test rdx, rdx
    jnz  .bad
    add  rax, r8
    jc   .bad
    inc  ecx
    jmp  .loop
.ok:
    xor  edx, edx
    ret
.bad:
    xor  eax, eax
    mov  edx, 1
    ret

backup_hex_nibble:
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    movzx eax, al
    ret
.digit:
    sub  al, '0'
    movzx eax, al
    ret
.bad:
    mov  eax, -1
    ret

; Decode exactly 32 bytes from a 64-character hex token.
backup_decode_pub:
    cmp  esi, 64
    jne  .bad
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rdx
    xor  ecx, ecx
.loop:
    cmp  ecx, 32
    jae  .nonzero
    movzx eax, byte [r12 + rcx*2]
    call backup_hex_nibble
    test eax, eax
    js   .pop_bad
    shl  eax, 4
    mov  r8d, eax
    movzx eax, byte [r12 + rcx*2 + 1]
    call backup_hex_nibble
    test eax, eax
    js   .pop_bad
    or   eax, r8d
    mov  [rbx + rcx], al
    inc  ecx
    jmp  .loop
.nonzero:
    xor  eax, eax
    xor  ecx, ecx
.or:
    or   al, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .or
    test al, al
    jz   .pop_bad
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.pop_bad:
    pop  r12
    pop  rbx
.bad:
    mov  eax, -1
    ret

; Parse dotted IPv4 into the layout consumed by tcp_client_open.
backup_parse_ipv4:
    push rbx
    push r12
    mov  r12, rdi
    mov  ebx, esi
    xor  ecx, ecx                       ; source index
    xor  r8d, r8d                       ; component index
.component:
    cmp  r8d, 4
    jae  .bad
    xor  eax, eax
    xor  r9d, r9d
.digit:
    cmp  ecx, ebx
    jae  .component_done
    movzx edx, byte [r12 + rcx]
    cmp  dl, '.'
    je   .component_done
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    imul eax, eax, 10
    add  eax, edx
    cmp  eax, 255
    ja   .bad
    inc  ecx
    inc  r9d
    cmp  r9d, 3
    ja   .bad
    jmp  .digit
.component_done:
    test r9d, r9d
    jz   .bad
    lea  rdx, [rel backup_ip_bytes]
    mov  [rdx + r8], al
    inc  r8d
    cmp  r8d, 4
    je   .last
    cmp  ecx, ebx
    jae  .bad
    cmp  byte [r12 + rcx], '.'
    jne  .bad
    inc  ecx
    jmp  .component
.last:
    cmp  ecx, ebx
    jne  .bad
    mov  eax, [rel backup_ip_bytes]
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  r12
    pop  rbx
    ret

backup_copy_token:
    ; RDI=src, ESI=len, RDX=dst, ECX=cap including NUL.
    test esi, esi
    jz   .bad
    cmp  esi, ecx
    jae  .bad
    mov  r8d, esi
    push rdx
    mov  ecx, r8d
    mov  rsi, rdi
    mov  rdi, rdx
    rep  movsb
    pop  rdx
    mov  byte [rdx + r8], 0
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; CONSENT performs no network action. It freezes bytes and exact manifest.
backup_handle_consent:
    cmp  dword [rel backup_tok_count], 7
    jne  .args
    movzx eax, byte [rel backup_state]
    cmp  eax, BACKUP_ST_CONNECTING
    jb   .parse
    cmp  eax, BACKUP_ST_WAIT_ACK
    jbe  .busy
.parse:
    mov  rdi, [rel backup_tok_ptr + 8]
    mov  esi, [rel backup_tok_len + 4]
    test esi, esi
    jz   .source
    cmp  esi, BACKUP_PATH_CAP
    jae  .source
    cmp  byte [rdi], '/'
    jne  .source
    mov  [rel backup_path_len], esi
    lea  rdx, [rel backup_path]
    mov  ecx, BACKUP_PATH_CAP
    call backup_copy_token
    test eax, eax
    jnz  .source

    mov  rdi, [rel backup_tok_ptr + 16]
    mov  esi, [rel backup_tok_len + 8]
    call backup_parse_ipv4
    cmp  eax, -1
    je   .destination
    test eax, eax
    jz   .destination
    mov  [rel backup_dest_ip], eax
    mov  rdi, [rel backup_tok_ptr + 24]
    mov  esi, [rel backup_tok_len + 12]
    call backup_parse_u64
    test edx, edx
    jnz  .destination
    test eax, eax
    jz   .destination
    cmp  rax, 65535
    ja   .destination
    mov  [rel backup_dest_port], ax
    mov  rdi, [rel backup_tok_ptr + 32]
    mov  esi, [rel backup_tok_len + 16]
    lea  rdx, [rel backup_recipient_pub]
    call backup_decode_pub
    test eax, eax
    jnz  .recipient
    mov  rdi, [rel backup_tok_ptr + 40]
    mov  esi, [rel backup_tok_len + 20]
    call backup_parse_u64
    test edx, edx
    jnz  .generation
    test rax, rax
    jz   .generation
    mov  [rel backup_generation], rax
    mov  rdi, [rel backup_tok_ptr + 48]
    mov  esi, [rel backup_tok_len + 24]
    lea  rdx, [rel backup_nonce]
    mov  ecx, 65
    call backup_copy_token
    test eax, eax
    jnz  .args

    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel backup_path]
    mov  edx, [rel backup_path_len]
    lea  rcx, [rel backup_stat]
    call vfs_stat_path
    test eax, eax
    jnz  .source
    cmp  dword [rel backup_stat + fs_stat.reserved], 0
    jne  .source                       ; directory, not a regular selected file
    mov  rax, [rel backup_stat + fs_stat.size]
    test rax, rax
    jz   .source
    cmp  rax, BACKUP_SOURCE_CAP
    ja   .source
    mov  [rel backup_source_len], rax
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel backup_path]
    mov  edx, [rel backup_path_len]
    xor  ecx, ecx
    lea  r8, [rel backup_source]
    mov  r9, [rel backup_source_len]
    call vfs_read_at_path
    cmp  rax, [rel backup_source_len]
    jne  .source

    lea  rdi, [rel bx_archive]
    lea  rsi, [rel backup_path + 1]     ; tar member names are relative
    mov  edx, [rel backup_path_len]
    dec  edx
    lea  rcx, [rel backup_source]
    mov  r8, [rel backup_source_len]
    call ustar_build_member
    cmp  rax, BACKUP_FRAME_CAP - BACKUP_HEADER_LEN - 16
    ja   .source
    mov  [rel bx_archive_len], rax
    mov  [rel backup_archive_len], rax
    lea  rdi, [rel backup_manifest]
    lea  rsi, [rel bx_archive]
    mov  rdx, rax
    call sha256_hash
    lea  rdi, [rel backup_fingerprint]
    lea  rsi, [rel backup_recipient_pub]
    mov  edx, 32
    call sha256_hash

    mov  qword [rel backup_sent_bytes], 0
    mov  qword [rel backup_frame_offset], 0
    mov  qword [rel backup_frame_len], 0
    mov  byte [rel backup_ack_exact], 0
    mov  dword [rel backup_ack_len], 0
    lea  rdi, [rel backup_cipher_digest]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  qword [rel backup_rtc_reads_before], 0
    mov  qword [rel backup_rtc_reads_after], 0
    mov  qword [rel backup_rtc_writes_before], 0
    mov  qword [rel backup_rtc_writes_after], 0
    mov  qword [rel backup_receipt_time_us], 0
    mov  byte [rel backup_consent_active], 1
    mov  byte [rel backup_state], BACKUP_ST_CONSENTED
    call backup_stage_status
    xor  eax, eax
    ret
.busy:
    lea  rdi, [rel str_backup_busy]
    jmp  .error
.args:
    lea  rdi, [rel str_backup_bad_args]
    jmp  .error
.source:
    lea  rdi, [rel str_backup_source_refused]
    jmp  .error
.destination:
    lea  rdi, [rel str_backup_destination_refused]
    jmp  .error
.recipient:
    lea  rdi, [rel str_backup_recipient_refused]
    jmp  .error
.generation:
    lea  rdi, [rel str_backup_generation_refused]
.error:
    call backup_stage_error
    mov  eax, CMDE_BADARG
    ret

backup_handle_export:
    cmp  dword [rel backup_tok_count], 3
    jne  .args
    mov  rdi, [rel backup_tok_ptr + 8]
    mov  esi, [rel backup_tok_len + 4]
    call backup_parse_u64
    test edx, edx
    jnz  .args
    cmp  rax, [rel backup_generation]
    jne  .no_consent
    cmp  byte [rel backup_consent_active], 1
    jne  .no_consent
    cmp  byte [rel backup_state], BACKUP_ST_CONSENTED
    jne  .no_consent
    mov  rdi, [rel backup_tok_ptr + 16]
    mov  esi, [rel backup_tok_len + 8]
    lea  rdx, [rel backup_nonce]
    mov  ecx, 65
    call backup_copy_token
    test eax, eax
    jnz  .args

    mov  rax, [rel time_rtc_read_count]
    mov  [rel backup_rtc_reads_before], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel backup_rtc_writes_before], rax
    call time_wall_now_us
    mov  [rel backup_receipt_time_us], rax
    lea  rdi, [rel backup_ephemeral]
    mov  esi, 34
    call csprng_generate
    test eax, eax
    jnz  .csprng
    lea  rdi, [rel backup_recipient_pub]
    lea  rsi, [rel backup_ephemeral]
    call bx_prepare_sender
    test eax, eax
    jnz  .crypto
    call backup_build_header
    lea  rdi, [rel bx_archive]
    mov  rsi, [rel backup_archive_len]
    lea  rdx, [rel backup_frame]
    mov  ecx, BACKUP_HEADER_LEN
    call bx_encrypt
    test eax, eax
    jnz  .crypto
    lea  rdi, [rel bx_manifest]
    lea  rsi, [rel backup_manifest]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .crypto
    lea  rdi, [rel backup_frame + BACKUP_HEADER_LEN]
    lea  rsi, [rel bx_ct]
    mov  rdx, [rel backup_archive_len]
    call memcpy
    lea  rdi, [rel backup_frame + BACKUP_HEADER_LEN]
    add  rdi, [rel backup_archive_len]
    lea  rsi, [rel bx_tag]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel backup_cipher_digest]
    lea  rsi, [rel backup_frame + BACKUP_HEADER_LEN]
    mov  rdx, [rel backup_archive_len]
    add  rdx, 16
    call sha256_hash
    mov  rax, [rel backup_archive_len]
    add  rax, BACKUP_HEADER_LEN + 16
    mov  [rel backup_frame_len], rax
    mov  [rel backup_frame + 140], eax

    movzx eax, word [rel backup_ephemeral + 32]
    and  eax, 0x3fff
    add  eax, 49152
    mov  [rel backup_local_port], ax
    mov  edi, [rel backup_dest_ip]
    movzx esi, word [rel backup_dest_port]
    movzx edx, word [rel backup_local_port]
    lea  rcx, [rel backup_tcp_connected]
    lea  r8, [rel backup_tcp_receive]
    call tcp_client_open
    test rax, rax
    jz   .route
    mov  [rel backup_tcb], rax
    call boot_ms_now
    add  rax, BACKUP_TIMEOUT_MS
    mov  [rel backup_deadline_ms], rax
    mov  qword [rel backup_frame_offset], 0
    mov  qword [rel backup_sent_bytes], 0
    mov  dword [rel backup_ack_len], 0
    mov  byte [rel backup_ack_exact], 0
    mov  byte [rel backup_state], BACKUP_ST_CONNECTING
    lea  rdi, [rel backup_ephemeral]
    xor  esi, esi
    mov  edx, 34
    call memset
    call backup_stage_status
    xor  eax, eax
    ret
.no_consent:
    lea  rdi, [rel str_backup_no_consent]
    jmp  .error
.csprng:
    lea  rdi, [rel str_backup_csprng_refused]
    jmp  .consume_error
.crypto:
    lea  rdi, [rel str_backup_crypto_refused]
    jmp  .consume_error
.route:
    lea  rdi, [rel str_backup_route_refused]
.consume_error:
    push rdi
    mov  byte [rel backup_consent_active], 0
    mov  byte [rel backup_state], BACKUP_ST_FAILED
    lea  rdi, [rel backup_ephemeral]
    xor  esi, esi
    mov  edx, 34
    call memset
    pop  rdi
.error:
    call backup_stage_error
    mov  eax, CMDE_BADARG
    ret
.args:
    lea  rdi, [rel str_backup_bad_args]
    jmp  .error

backup_handle_cancel:
    cmp  dword [rel backup_tok_count], 3
    jne  .args
    mov  rdi, [rel backup_tok_ptr + 8]
    mov  esi, [rel backup_tok_len + 4]
    call backup_parse_u64
    test edx, edx
    jnz  .args
    cmp  rax, [rel backup_generation]
    jne  .no_consent
    cmp  byte [rel backup_consent_active], 1
    jne  .no_consent
    mov  rdi, [rel backup_tok_ptr + 16]
    mov  esi, [rel backup_tok_len + 8]
    lea  rdx, [rel backup_nonce]
    mov  ecx, 65
    call backup_copy_token
    test eax, eax
    jnz  .args
    mov  rdi, [rel backup_tcb]
    test rdi, rdi
    jz   .no_abort
    call tcp_client_abort
    mov  qword [rel backup_tcb], 0
.no_abort:
    mov  byte [rel backup_consent_active], 0
    mov  byte [rel backup_state], BACKUP_ST_CANCELLED
    call backup_capture_rtc_after
    call backup_stage_status
    xor  eax, eax
    ret
.no_consent:
    lea  rdi, [rel str_backup_no_consent]
    call backup_stage_error
    mov  eax, CMDE_BADARG
    ret
.args:
    lea  rdi, [rel str_backup_bad_args]
    call backup_stage_error
    mov  eax, CMDE_BADARG
    ret

backup_handle_stat:
    cmp  dword [rel backup_tok_count], 2
    jne  .args
    mov  rdi, [rel backup_tok_ptr + 8]
    mov  esi, [rel backup_tok_len + 4]
    lea  rdx, [rel backup_nonce]
    mov  ecx, 65
    call backup_copy_token
    test eax, eax
    jnz  .args
    call backup_stage_status
    xor  eax, eax
    ret
.args:
    lea  rdi, [rel str_backup_bad_args]
    call backup_stage_error
    mov  eax, CMDE_BADARG
    ret

; Construct the 256-byte authenticated header. Multi-byte lengths/generation
; are little-endian; suite identifiers are the RFC network-order bytes.
backup_build_header:
    lea  rdi, [rel backup_frame]
    xor  esi, esi
    mov  edx, BACKUP_HEADER_LEN
    call memset
    lea  rdi, [rel backup_frame]
    lea  rsi, [rel backup_header_prefix]
    mov  edx, 16
    call memcpy
    mov  dword [rel backup_frame + 16], BACKUP_HEADER_LEN
    mov  eax, [rel backup_archive_len]
    mov  [rel backup_frame + 20], eax
    mov  [rel backup_frame + 24], eax
    mov  ax, [rel backup_path_len]
    mov  [rel backup_frame + 28], ax
    mov  ax, [rel backup_dest_port]
    xchg al, ah
    mov  [rel backup_frame + 30], ax
    mov  rax, [rel backup_generation]
    mov  [rel backup_frame + 32], rax
    lea  rdi, [rel backup_frame + 40]
    lea  rsi, [rel backup_manifest]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel backup_frame + 72]
    lea  rsi, [rel backup_fingerprint]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel backup_frame + 104]
    lea  rsi, [rel bx_enc]
    mov  edx, 32
    call memcpy
    mov  eax, [rel backup_dest_ip]
    mov  [rel backup_frame + 136], eax
    mov  rax, [rel backup_archive_len]
    add  rax, BACKUP_HEADER_LEN + 16
    mov  [rel backup_frame + 140], eax
    lea  rdi, [rel backup_frame + 144]
    lea  rsi, [rel backup_path]
    mov  edx, [rel backup_path_len]
    call memcpy
    ret

backup_tcp_connected:
    mov  [rel backup_tcb], rdi
    cmp  byte [rel backup_state], BACKUP_ST_CONNECTING
    jne  .out
    mov  byte [rel backup_state], BACKUP_ST_SENDING
.out:
    ret

; Exact ACK = "PBX1ACK\0" || status(1) || seven zero bytes || manifest32 ||
; ciphertext_digest32 || consent_generation_le64.
backup_tcp_receive:
    push rbx
    push r12
    mov  rbx, rsi
    mov  r12d, edx
    cmp  byte [rel backup_state], BACKUP_ST_WAIT_ACK
    jne  .retry
    mov  eax, [rel backup_ack_len]
    add  eax, r12d
    jc   .invalid
    cmp  eax, BACKUP_ACK_LEN
    ja   .invalid
    lea  rdi, [rel backup_ack_buf]
    ; backup_ack_len is a dword immediately followed by backup_dest_ip.  Load
    ; it at its declared width before pointer arithmetic: a qword memory add
    ; would splice the destination IPv4 into the high half and #GP in memcpy.
    mov  eax, [rel backup_ack_len]
    add  rdi, rax
    mov  rsi, rbx
    mov  edx, r12d
    call memcpy
    add  [rel backup_ack_len], r12d
    cmp  dword [rel backup_ack_len], BACKUP_ACK_LEN
    jb   .ok
    lea  rdi, [rel backup_ack_buf]
    lea  rsi, [rel backup_ack_prefix]
    mov  edx, 16
    call memcmp
    test eax, eax
    jnz  .invalid
    lea  rdi, [rel backup_ack_buf + 16]
    lea  rsi, [rel backup_manifest]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .invalid
    lea  rdi, [rel backup_ack_buf + 48]
    lea  rsi, [rel backup_cipher_digest]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .invalid
    mov  rax, [rel backup_ack_buf + 80]
    cmp  rax, [rel backup_generation]
    jne  .invalid
    mov  byte [rel backup_ack_exact], 1
    mov  byte [rel backup_consent_active], 0
    mov  byte [rel backup_state], BACKUP_ST_ACKED
    call backup_capture_rtc_after
.ok:
    xor  eax, eax                       ; consume this exact TCP prefix
    pop  r12
    pop  rbx
    ret
.retry:
    mov  eax, -1                        ; no ACK accepted before full send
    pop  r12
    pop  rbx
    ret
.invalid:
    mov  byte [rel backup_consent_active], 0
    mov  byte [rel backup_state], BACKUP_ST_FAILED
    call backup_capture_rtc_after
    xor  eax, eax                       ; consume hostile bytes, then tick aborts
    pop  r12
    pop  rbx
    ret

; Exercise the exact live ACK callback with a deliberately nonzero adjacent
; destination IPv4.  This makes a width regression in the pointer offset
; deterministic under QEMU instead of waiting for the first metal receiver.
backup_ack_parser_selftest:
    push rbx
    lea  rdi, [rel backup_ack_buf]
    xor  esi, esi
    mov  edx, BACKUP_ACK_LEN
    call memset
    lea  rdi, [rel backup_ack_buf]
    lea  rsi, [rel backup_ack_prefix]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel backup_manifest]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel backup_cipher_digest]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  rbx, 0x1122334455667788
    mov  [rel backup_generation], rbx
    mov  [rel backup_ack_buf + 80], rbx
    mov  dword [rel backup_dest_ip], 0xf00200c0
    mov  dword [rel backup_ack_len], 0
    mov  byte [rel backup_ack_exact], 0
    mov  byte [rel backup_consent_active], 1
    mov  byte [rel backup_state], BACKUP_ST_WAIT_ACK
    xor  edi, edi
    lea  rsi, [rel backup_ack_buf]
    mov  edx, BACKUP_ACK_LEN
    call backup_tcp_receive
    test eax, eax
    jnz  .failed
    cmp  dword [rel backup_ack_len], BACKUP_ACK_LEN
    jne  .failed
    cmp  byte [rel backup_ack_exact], 1
    jne  .failed
    cmp  byte [rel backup_state], BACKUP_ST_ACKED
    jne  .failed
    xor  ebx, ebx
    jmp  .cleanup
.failed:
    mov  ebx, -1
.cleanup:
    mov  byte [rel backup_state], BACKUP_ST_IDLE
    mov  byte [rel backup_consent_active], 0
    mov  byte [rel backup_ack_exact], 0
    mov  dword [rel backup_ack_len], 0
    mov  dword [rel backup_dest_ip], 0
    mov  qword [rel backup_generation], 0
    lea  rdi, [rel backup_ack_buf]
    xor  esi, esi
    mov  edx, BACKUP_ACK_LEN
    call memset
    mov  eax, ebx
    pop  rbx
    ret

; Cooperative bounded progress; called once per command UDP poll after tcp_poll.
backup_command_tick:
    cmp  byte [rel backup_ack_kat_state], 0
    jne  .ack_kat_checked
    cmp  byte [rel boot_p7_reached], 1
    jne  .out
    call backup_ack_parser_selftest
    test eax, eax
    jnz  .ack_kat_failed
    mov  byte [rel backup_ack_kat_state], 1
    lea  rdi, [rel str_backup_ack_kat_ok]
    call serial_string
    jmp  .ack_kat_checked
.ack_kat_failed:
    mov  byte [rel backup_ack_kat_state], 2
    mov  byte [rel bx_kat_state], 2
    jmp  .out
.ack_kat_checked:
    cmp  byte [rel backup_ack_kat_state], 1
    jne  .out
    cmp  byte [rel bx_kat_state], 0
    jne  .kat_checked
    ; command_udp_poll also runs during early network bring-up.  Do not arm this
    ; comparatively expensive KAT until the boot path has completed the real
    ; PS/2/USB input observer and published interactive readiness.
    cmp  byte [rel boot_p7_reached], 1
    jne  .out
    mov  byte [rel bx_kat_armed], 1
    call backup_export_kat
.kat_checked:
    cmp  byte [rel bx_kat_state], 1
    jne  .out
    movzx eax, byte [rel backup_state]
    cmp  eax, BACKUP_ST_CONNECTING
    jb   .out
    cmp  eax, BACKUP_ST_WAIT_ACK
    ja   .terminal
    call boot_ms_now
    cmp  rax, [rel backup_deadline_ms]
    jae  .timeout
    cmp  byte [rel backup_state], BACKUP_ST_SENDING
    jne  .out
    mov  rax, [rel backup_frame_offset]
    cmp  rax, [rel backup_frame_len]
    jae  .waiting
    mov  rdx, [rel backup_frame_len]
    sub  rdx, rax
    cmp  rdx, BACKUP_CHUNK
    jbe  .chunk
    mov  edx, BACKUP_CHUNK
.chunk:
    push rdx
    mov  rdi, [rel backup_tcb]
    lea  rsi, [rel backup_frame]
    add  rsi, rax
    call tcp_client_send
    pop  rdx
    test eax, eax
    jnz  .out                           ; ordinary one-flight backpressure
    add  [rel backup_frame_offset], rdx
    add  [rel backup_sent_bytes], rdx
    mov  rax, [rel backup_frame_offset]
    cmp  rax, [rel backup_frame_len]
    jb   .out
.waiting:
    mov  byte [rel backup_state], BACKUP_ST_WAIT_ACK
    jmp  .out
.timeout:
    mov  byte [rel backup_consent_active], 0
    mov  byte [rel backup_state], BACKUP_ST_FAILED
    call backup_capture_rtc_after
.terminal:
    cmp  byte [rel backup_state], BACKUP_ST_ACKED
    jne  .abort_terminal
    mov  rdi, [rel backup_tcb]
    test rdi, rdi
    jz   .complete
    call tcp_close
    test eax, eax
    jnz  .out
    mov  qword [rel backup_tcb], 0
.complete:
    mov  byte [rel backup_state], BACKUP_ST_COMPLETE
    jmp  .out
.abort_terminal:
    cmp  byte [rel backup_state], BACKUP_ST_FAILED
    jne  .out
    mov  rdi, [rel backup_tcb]
    test rdi, rdi
    jz   .out
    call tcp_client_abort
    mov  qword [rel backup_tcb], 0
.out:
    ret

backup_capture_rtc_after:
    mov  rax, [rel time_rtc_read_count]
    mov  [rel backup_rtc_reads_after], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel backup_rtc_writes_after], rax
    ret

; ---- owner-only local receipt rendering ----
backup_out_reset:
    lea  rax, [rel backup_out_buf]
    mov  [rel backup_out_cur], rax
    mov  byte [rax], 0
    ret

backup_out_text:
    mov  rsi, [rel backup_out_cur]
    lea  rdx, [rel backup_out_buf + BACKUP_OUT_CAP - 1]
.loop:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rdx
    jae  .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.done:
    mov  byte [rsi], 0
    mov  [rel backup_out_cur], rsi
    ret

backup_out_dec:
    mov  rsi, [rel backup_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel backup_out_cur], rsi
    ret

backup_out_hex:
    ; RDI=bytes, ESI=len.
    mov  rdx, [rel backup_out_cur]
    lea  r8, [rel backup_out_buf + BACKUP_OUT_CAP - 1]
    lea  r9, [rel backup_hex]
    xor  ecx, ecx
.loop:
    cmp  ecx, esi
    jae  .done
    lea  r10, [rdx + 2]
    cmp  r10, r8
    ja   .done
    movzx eax, byte [rdi + rcx]
    mov  r11d, eax
    shr  eax, 4
    mov  al, [r9 + rax]
    mov  [rdx], al
    and  r11d, 15
    mov  al, [r9 + r11]
    mov  [rdx + 1], al
    add  rdx, 2
    inc  ecx
    jmp  .loop
.done:
    mov  byte [rdx], 0
    mov  [rel backup_out_cur], rdx
    ret

backup_out_ip:
    push rbx
    push r12
    lea  rbx, [rel backup_ip_bytes]
    mov  eax, [rel backup_dest_ip]
    mov  [rbx], eax
    xor  r12d, r12d
.octet:
    movzx edi, byte [rbx + r12]
    call backup_out_dec
    inc  r12d
    cmp  r12d, 4
    jae  .done
    lea  rdi, [rel str_backup_dot]
    call backup_out_text
    jmp  .octet
.done:
    pop  r12
    pop  rbx
    ret

backup_stage_error:
    push rdi
    call backup_out_reset
    lea  rdi, [rel str_backup_error]
    call backup_out_text
    pop  rdi
    call backup_out_text
    lea  rdi, [rel str_backup_sent]
    call backup_out_text
    mov  rdi, [rel backup_sent_bytes]
    call backup_out_dec
    lea  rdi, [rel str_backup_nonce]
    call backup_out_text
    lea  rdi, [rel backup_nonce]
    call backup_out_text
    mov  byte [rel backup_out_ready], 1
    ret

backup_stage_status:
    call backup_out_reset
    lea  rdi, [rel str_backup_state]
    call backup_out_text
    movzx eax, byte [rel backup_state]
    lea  rdi, [rel str_backup_idle]
    cmp  eax, BACKUP_ST_IDLE
    je   .state
    lea  rdi, [rel str_backup_consented]
    cmp  eax, BACKUP_ST_CONSENTED
    je   .state
    lea  rdi, [rel str_backup_connecting]
    cmp  eax, BACKUP_ST_CONNECTING
    je   .state
    lea  rdi, [rel str_backup_sending]
    cmp  eax, BACKUP_ST_SENDING
    je   .state
    lea  rdi, [rel str_backup_wait_ack]
    cmp  eax, BACKUP_ST_WAIT_ACK
    je   .state
    lea  rdi, [rel str_backup_acked]
    cmp  eax, BACKUP_ST_ACKED
    je   .state
    lea  rdi, [rel str_backup_failed]
    cmp  eax, BACKUP_ST_FAILED
    je   .state
    lea  rdi, [rel str_backup_cancelled]
    cmp  eax, BACKUP_ST_CANCELLED
    je   .state
    lea  rdi, [rel str_backup_complete]
.state:
    call backup_out_text
    lea  rdi, [rel str_backup_generation_field]
    call backup_out_text
    mov  rdi, [rel backup_generation]
    call backup_out_dec
    lea  rdi, [rel str_backup_source]
    call backup_out_text
    lea  rdi, [rel backup_path]
    call backup_out_text
    lea  rdi, [rel str_backup_source_bytes]
    call backup_out_text
    mov  rdi, [rel backup_source_len]
    call backup_out_dec
    lea  rdi, [rel str_backup_archive_bytes]
    call backup_out_text
    mov  rdi, [rel backup_archive_len]
    call backup_out_dec
    lea  rdi, [rel str_backup_destination]
    call backup_out_text
    call backup_out_ip
    lea  rdi, [rel str_backup_colon]
    call backup_out_text
    movzx edi, word [rel backup_dest_port]
    call backup_out_dec
    lea  rdi, [rel str_backup_fingerprint]
    call backup_out_text
    lea  rdi, [rel backup_fingerprint]
    mov  esi, 32
    call backup_out_hex
    lea  rdi, [rel str_backup_manifest]
    call backup_out_text
    lea  rdi, [rel backup_manifest]
    mov  esi, 32
    call backup_out_hex
    lea  rdi, [rel str_backup_cipher]
    call backup_out_text
    lea  rdi, [rel backup_cipher_digest]
    mov  esi, 32
    call backup_out_hex
    lea  rdi, [rel str_backup_ack]
    call backup_out_text
    movzx edi, byte [rel backup_ack_exact]
    call backup_out_dec
    lea  rdi, [rel str_backup_sent]
    call backup_out_text
    mov  rdi, [rel backup_sent_bytes]
    call backup_out_dec
    lea  rdi, [rel str_backup_frame_bytes]
    call backup_out_text
    mov  rdi, [rel backup_frame_len]
    call backup_out_dec
    lea  rdi, [rel str_backup_rtc_rb]
    call backup_out_text
    mov  rdi, [rel backup_rtc_reads_before]
    call backup_out_dec
    lea  rdi, [rel str_backup_rtc_ra]
    call backup_out_text
    mov  rdi, [rel backup_rtc_reads_after]
    call backup_out_dec
    lea  rdi, [rel str_backup_rtc_wb]
    call backup_out_text
    mov  rdi, [rel backup_rtc_writes_before]
    call backup_out_dec
    lea  rdi, [rel str_backup_rtc_wa]
    call backup_out_text
    mov  rdi, [rel backup_rtc_writes_after]
    call backup_out_dec
    lea  rdi, [rel str_backup_rtc_same]
    call backup_out_text
    xor  edi, edi
    mov  rax, [rel backup_rtc_reads_before]
    cmp  rax, [rel backup_rtc_reads_after]
    jne  .rtc
    mov  rax, [rel backup_rtc_writes_before]
    cmp  rax, [rel backup_rtc_writes_after]
    jne  .rtc
    mov  edi, 1
.rtc:
    call backup_out_dec
    lea  rdi, [rel str_backup_receipt_time]
    call backup_out_text
    mov  rdi, [rel backup_receipt_time_us]
    call backup_out_dec
    lea  rdi, [rel str_backup_fixed_facts]
    call backup_out_text
    lea  rdi, [rel str_backup_nonce]
    call backup_out_text
    lea  rdi, [rel backup_nonce]
    call backup_out_text
    mov  byte [rel backup_out_ready], 1
    ret

; ---- immutable protocol/status strings ----
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_backup_0 0
backup_header_prefix:
    db 'P','A','O','S','B','X','1',0
    db 1,0, 0,0x20, 0,1, 0,2
backup_ack_prefix:
    db 'P','B','X','1','A','C','K',0, 1,0,0,0,0,0,0,0
backup_hex: db "0123456789abcdef"
str_backup_verb: db "BACKUP",0
str_backup_consent: db "consent"
str_backup_export: db "export"
str_backup_cancel: db "cancel"
str_backup_stat: db "stat"
str_backup_error: db "BACKUP ERR reason=",0
str_backup_bad_args: db "bad_args",0
str_backup_busy: db "busy",0
str_backup_source_refused: db "source_refused",0
str_backup_destination_refused: db "destination_refused",0
str_backup_recipient_refused: db "recipient_refused",0
str_backup_generation_refused: db "generation_refused",0
str_backup_no_consent: db "no_consent",0
str_backup_csprng_refused: db "csprng_refused",0
str_backup_crypto_refused: db "crypto_refused",0
str_backup_route_refused: db "route_refused",0
str_backup_state: db "BACKUP state=",0
str_backup_idle: db "idle",0
str_backup_consented: db "consented",0
str_backup_connecting: db "connecting",0
str_backup_sending: db "sending",0
str_backup_wait_ack: db "awaiting_ack",0
str_backup_acked: db "acked",0
str_backup_failed: db "failed",0
str_backup_cancelled: db "cancelled",0
str_backup_complete: db "complete",0
str_backup_generation_field: db " consent_generation=",0
str_backup_source: db " source=",0
str_backup_source_bytes: db " source_bytes=",0
str_backup_archive_bytes: db " archive_bytes=",0
str_backup_destination: db " destination=",0
str_backup_fingerprint: db " recipient_fingerprint=",0
str_backup_manifest: db " manifest=",0
str_backup_cipher: db " ciphertext_digest=",0
str_backup_ack: db " receiver_ack_exact=",0
str_backup_sent: db " sent_bytes=",0
str_backup_frame_bytes: db " frame_bytes=",0
str_backup_rtc_rb: db " rtc_reads_before=",0
str_backup_rtc_ra: db " rtc_reads_after=",0
str_backup_rtc_wb: db " rtc_writes_before=",0
str_backup_rtc_wa: db " rtc_writes_after=",0
str_backup_rtc_same: db " rtc_unchanged=",0
str_backup_receipt_time: db " receipt_utc_us=",0
str_backup_fixed_facts: db " hpke=RFC9180-X25519-HKDF-SHA256-AES256GCM hpke_mode=0 hpke_seq=0 csprng_service_only=1 telemetry_self=0 involvement_authorizes_self=0 archive=ustar-complete",0
str_backup_kat_unready: db "kat_unready",0
str_backup_ack_kat_ok: db "[PAOS64] backup export: exact ACK parser width KAT PASS [backup.export.ack.parser.ok]",13,10,0
str_backup_nonce: db " nonce=",0
str_backup_dot: db ".",0
str_backup_colon: db ":",0

; ---- one bounded export state (RW+NX) ----
align 8
backup_out_ready: db 0
backup_state: db 0
backup_consent_active: db 0
backup_ack_exact: db 0
backup_ack_kat_state: db 0
backup_path_len: dd 0
backup_ack_len: dd 0
backup_dest_ip: dd 0
backup_dest_port: dw 0
backup_local_port: dw 0
backup_generation: dq 0
backup_source_len: dq 0
backup_archive_len: dq 0
backup_frame_len: dq 0
backup_frame_offset: dq 0
backup_sent_bytes: dq 0
backup_deadline_ms: dq 0
backup_receipt_time_us: dq 0
backup_rtc_reads_before: dq 0
backup_rtc_reads_after: dq 0
backup_rtc_writes_before: dq 0
backup_rtc_writes_after: dq 0
backup_tcb: dq 0
backup_out_cur: dq 0
backup_tok_count: dd 0
backup_tok_ptr: times BACKUP_TOKEN_MAX dq 0
backup_tok_len: times BACKUP_TOKEN_MAX dd 0
backup_stat: times fs_stat_size db 0
backup_ip_bytes: times 4 db 0
backup_recipient_pub: times 32 db 0
backup_ephemeral: times 34 db 0
backup_manifest: times 32 db 0
backup_fingerprint: times 32 db 0
backup_cipher_digest: times 32 db 0
backup_path: times BACKUP_PATH_CAP db 0
backup_nonce: times 65 db 0
backup_ack_buf: times BACKUP_ACK_LEN db 0
%endmacro
WDATA_DEFER WDATA_svc_command_backup_0
