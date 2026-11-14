;; MODULE net/tls13
;; LAYER 4
;; PURPOSE Native TLS framing/handshake plus one bounded pinned application owner.
;; EXPORTS tls13_record_view, tls13_record_framing_kat, tls13_application_transition_kat, tls13_init, tls13_selftest_once, tls13_selftest, tls13_connect_start, tls13_app_start, tls13_app_prepare, tls13_app_flush, tls13_app_close, tls13_app_owner, tls13_app_peer_closed, tls13_state, tls13_error, tls13_established, tls13_cert_verified, tls13_entropy_degraded, tls13_sni, tls13_kat_flags, tls13_kat_ks_out, tls13_kat_x_out, tls13_kat_gcm_ct, tls13_kat_gcm_tag, tls13_tcp_connected_seen, tls13_records_rx, tls13_handshake_messages_rx, tls13_last_record_type, tls13_last_handshake_type, tls13_peer_finished_ok, tls13_trust_path, tls13_rx_len, tls13_hs_len, tls13_policy_ok, tls13_policy_reason, tls13_observe, tls13_close_attempt
;; IMPORTS boot/serial, core/heap, core/csprng, core/lib/mem, core/lib/sha256, core/lib/hkdf_sha256, core/lib/aes256_gcm, core/lib/aes128_gcm, core/lib/x25519, lib/safe_buffer, bootmgr/rsa2048_verify, net/tcp, core/time, net/tls13_certificate_policy
;; CAPS
;; OWNER saga:net
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; RFC 8446 TLS 1.3 client over the callback-driven active TCP seam.  No crypto
; primitive is redefined here: transcript SHA-256, HMAC/HKDF, AES-GCM, X25519,
; and RSA verification are imported from their single canonical modules.

TLS13_ST_IDLE        equ 0
TLS13_ST_TCP         equ 1
TLS13_ST_SERVER_HELLO equ 2
TLS13_ST_ENC_EXT     equ 3
TLS13_ST_CERT        equ 4
TLS13_ST_CERT_VERIFY equ 5
TLS13_ST_FINISHED    equ 6
TLS13_ST_ESTABLISHED equ 7
TLS13_ST_FAILED      equ 8

TLS13_ERR_NONE       equ 0
TLS13_ERR_ARGUMENT   equ 1
TLS13_ERR_ROUTE      equ 2
TLS13_ERR_TCP        equ 3
TLS13_ERR_RECORD     equ 4
TLS13_ERR_SERVER_HELLO equ 5
TLS13_ERR_KEY_SCHEDULE equ 6
TLS13_ERR_CERT_CHAIN equ 7
TLS13_ERR_CERT_VERIFY equ 8
TLS13_ERR_FINISHED   equ 9
TLS13_ERR_OVERFLOW   equ 10

TLS13_CT_ALERT       equ 21
TLS13_CT_HANDSHAKE   equ 22
TLS13_CT_APPLICATION equ 23
TLS13_CT_CHANGE_CIPHER equ 20
TLS13_HS_CLIENT_HELLO equ 1
TLS13_HS_SERVER_HELLO equ 2
TLS13_HS_ENC_EXT      equ 8
TLS13_HS_CERTIFICATE  equ 11
TLS13_HS_CERT_VERIFY  equ 15
TLS13_HS_FINISHED     equ 20

; TLSCiphertext may carry 2^14 bytes plus 256 bytes of expansion. Certificate
; messages routinely span several such records, so keep a distinct bounded
; reassembly arena instead of rejecting ordinary public chains at 4 KiB.
TLS13_RX_CAP         equ 18432
TLS13_HS_CAP         equ 32768
TLS13_SEAL_CAP       equ 1152            ; bounded notification application record
TLS13_TX_CAP         equ 384             ; max v1 ClientHello is 328 bytes
TLS13_SNI_CAP        equ 200
TLS13_RECORD_HEADER  equ 5
TLS13_MAX_PLAINTEXT  equ 16384
TLS13_MAX_CIPHERTEXT equ TLS13_MAX_PLAINTEXT + 256

; Contract 9523 hostile-record floor, retained as the canonical framing seam
; used by this full client.  It validates the header and declared span before
; the receive path forms or consumes a payload pointer.
; tls13_record_view(RDI=record, RSI=available)
;   out: EAX=SAFE_BUF_OK/TRUNCATED/BOUNDS/INVALID,
;        RDX=payload pointer, ECX=declared payload length, R8D=content type
tls13_record_view:
    test rdi, rdi
    jz   .invalid
    cmp  rsi, TLS13_RECORD_HEADER
    jb   .truncated
    push r9
    mov  r9, rdi
    xor  edx, edx
    mov  ecx, TLS13_RECORD_HEADER
    call safe_span_validate
    test eax, eax
    jnz  .bounds_pop
    movzx r8d, byte [r9]
    cmp  r8d, TLS13_CT_CHANGE_CIPHER
    jb   .invalid_pop
    cmp  r8d, TLS13_CT_APPLICATION
    ja   .invalid_pop
    cmp  word [r9 + 1], 0x0303
    jne  .invalid_pop
    movzx ecx, byte [r9 + 3]
    shl  ecx, 8
    mov  cl, [r9 + 4]
    cmp  ecx, TLS13_MAX_CIPHERTEXT
    ja   .bounds_pop
    mov  rax, rsi
    sub  rax, TLS13_RECORD_HEADER
    cmp  rcx, rax
    ja   .truncated_pop
    mov  rdi, r9
    mov  edx, TLS13_RECORD_HEADER
    call safe_span_validate
    test eax, eax
    jnz  .bounds_pop
    xor  eax, eax
    pop  r9
    ret
.truncated_pop:
    pop  r9
    jmp  .truncated
.bounds_pop:
    pop  r9
    jmp  .bounds
.invalid_pop:
    pop  r9
    jmp  .invalid
.truncated:
    mov  eax, SAFE_BUF_TRUNCATED
    jmp  .reject
.bounds:
    mov  eax, SAFE_BUF_BOUNDS
    jmp  .reject
.invalid:
    mov  eax, SAFE_BUF_INVALID
.reject:
    xor  edx, edx
    xor  ecx, ecx
    xor  r8d, r8d
    ret

tls13_record_framing_kat:
    lea  rdi, [rel tls13_framing_kat_good]
    mov  esi, tls13_framing_kat_good_end - tls13_framing_kat_good
    call tls13_record_view
    test eax, eax
    jnz  .fail
    cmp  ecx, 4
    jne  .fail
    cmp  r8d, TLS13_CT_APPLICATION
    jne  .fail
    lea  rax, [rel tls13_framing_kat_good + TLS13_RECORD_HEADER]
    cmp  rdx, rax
    jne  .fail
    lea  rdi, [rel tls13_framing_kat_good]
    mov  esi, 4
    call tls13_record_view
    cmp  eax, SAFE_BUF_TRUNCATED
    jne  .fail
    lea  rdi, [rel tls13_framing_kat_short]
    mov  esi, tls13_framing_kat_short_end - tls13_framing_kat_short
    call tls13_record_view
    cmp  eax, SAFE_BUF_TRUNCATED
    jne  .fail
    lea  rdi, [rel tls13_framing_kat_oversize]
    mov  esi, tls13_framing_kat_oversize_end - tls13_framing_kat_oversize
    call tls13_record_view
    cmp  eax, SAFE_BUF_BOUNDS
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

tls13_framing_kat_good: db TLS13_CT_APPLICATION,3,3,0,4,0x11,0x22,0x33,0x44
tls13_framing_kat_good_end:
tls13_framing_kat_short: db TLS13_CT_APPLICATION,3,3,0,5,0x11,0x22,0x33,0x44
tls13_framing_kat_short_end:
tls13_framing_kat_oversize: db TLS13_CT_APPLICATION,3,3,0x41,0x01
tls13_framing_kat_oversize_end:

; Allocate the bounded wire arenas once, after the kernel heap is available.
; Partial allocation is retained so a later retry only requests the missing
; arena; no pointer is published until kmalloc succeeds.
tls13_init:
    cmp  qword [rel tls13_rx_buf], 0
    jne  .plain
    mov  edi, TLS13_RX_CAP
    call kmalloc
    test rax, rax
    jz   .fail
    mov  [rel tls13_rx_buf], rax
.plain:
    cmp  qword [rel tls13_plain_buf], 0
    jne  .tx
    mov  edi, TLS13_HS_CAP
    call kmalloc
    test rax, rax
    jz   .fail
    mov  [rel tls13_plain_buf], rax
.tx:
    cmp  qword [rel tls13_tx_buf], 0
    jne  .ok
    mov  edi, TLS13_TX_CAP
    call kmalloc
    test rax, rax
    jz   .fail
    mov  [rel tls13_tx_buf], rax
.ok:
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; tls13_random32(RDI=out32) -> EAX=0, or nonzero with the 32 bytes zeroed.
; The ClientHello random and the X25519 ephemeral scalar come from the keep's
; HMAC_DRBG (core/csprng), never from RDRAND or the TSC directly: the DRBG is
; the one health-tested consumer of the CPU sources. While it is degraded the
; draw is refused and the caller fails closed (tls13_build_client_hello's
; .entropy_fail). Clobbers caller-saved registers.
tls13_random32:
    mov  esi, 32
    jmp  csprng_generate

; tls13_hmac(RDI=key, RSI=key_len, RDX=data, RCX=data_len, R8=out32).
tls13_hmac:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HMAC256_CTX_SZ
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    mov  rdi, rsp
    mov  rsi, r12
    mov  rdx, r13
    call hmac256_init
    test rax, rax
    jnz  .fail
    mov  rdi, rsp
    mov  rsi, r14
    mov  rdx, r15
    call hmac256_update
    test rax, rax
    jnz  .fail
    mov  rdi, rsp
    mov  rsi, rbx
    call hmac256_final
    test rax, rax
    jnz  .fail
    xor  r12d, r12d
    jmp  .wipe
.fail:
    mov  r12d, -1
.wipe:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, HMAC256_CTX_SZ
    call memset
    mov  eax, r12d
    add  rsp, HMAC256_CTX_SZ
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; HKDF-Extract(Salt, IKM). RDI=salt32, RSI=ikm, EDX=ikm_len, RCX=out32.
tls13_hkdf_extract:
    mov  r8, rcx
    mov  rcx, rdx
    mov  rdx, rsi
    mov  esi, 32
    jmp  hkdf_sha256_extract

; One-block HKDF-Expand, sufficient for every SHA-256 TLS 1.3 output here
; (key=16, iv=12, traffic/finished secret=32). RDI=PRK32, RSI=info,
; EDX=info_len, RCX=out, R8D=out_len.
tls13_hkdf_expand:
    mov  r9, r8
    mov  r8, rcx
    mov  rcx, rdx
    mov  rdx, rsi
    mov  esi, 32
    jmp  hkdf_sha256_expand_one

; HKDF-Expand-Label(Secret, Label, Context, Length). RDI=secret32,
; RSI=label, EDX=label_len, RCX=context, R8D=context_len, R9=out,
; stack arg7=out_len.
tls13_expand_label:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 320
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  r15, rcx
    mov  ebx, r8d
    mov  [rsp + 304], r9
    mov  eax, [rbp + 16]
    test eax, eax
    jz   .fail
    cmp  eax, 32
    ja   .fail
    cmp  r14d, 249                       ; 6-byte "tls13 " prefix + u8 length
    ja   .fail
    cmp  ebx, 255
    ja   .fail
    mov  [rsp + 312], eax
    ror  ax, 8
    mov  [rsp], ax                       ; uint16 output length, network order
    mov  eax, r14d
    add  eax, 6
    mov  [rsp + 2], al
    mov  dword [rsp + 3], 0x31736c74     ; "tls1"
    mov  word  [rsp + 7], 0x2033         ; "3 "
    lea  rdi, [rsp + 9]
    mov  rsi, r13
    mov  edx, r14d
    call memcpy
    mov  r10d, r14d
    add  r10d, 9
    mov  [rsp + r10], bl                 ; context length
    inc  r10d
    test ebx, ebx
    jz   .derive
    lea  rdi, [rsp + r10]
    mov  rsi, r15
    mov  edx, ebx
    call memcpy
    add  r10d, ebx
.derive:
    mov  rdi, r12
    mov  rsi, rsp
    mov  edx, r10d
    mov  rcx, [rsp + 304]
    mov  r8d, [rsp + 312]
    call tls13_hkdf_expand
    mov  r12d, eax
    jmp  .wipe
.fail:
    mov  r12d, -1
.wipe:
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 320
    call memset
    mov  eax, r12d
    add  rsp, 320
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Snapshot the running transcript without consuming it. RDI=out32.
tls13_transcript_digest:
    push r12
    sub  rsp, S256_CTX_SZ
    mov  r12, rdi
    mov  rdi, rsp
    lea  rsi, [rel tls13_transcript]
    mov  edx, S256_CTX_SZ
    call memcpy
    mov  rdi, rsp
    mov  rsi, r12
    call sha256_stream_final
    push rax
    mov  rdi, rsp
    add  rdi, 8
    xor  esi, esi
    mov  edx, S256_CTX_SZ
    call memset
    pop  rax
    add  rsp, S256_CTX_SZ
    pop  r12
    ret

; Build a complete plaintext ClientHello record and seed the running transcript.
; RDI=out>=TLS13_TX_CAP, RSI=SNI, EDX=SNI len -> RAX=record bytes/-1.
tls13_build_client_hello:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    test rbx, rbx
    jz   .fail
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, TLS13_SNI_CAP
    ja   .fail
    lea  rdi, [rel tls13_client_random]
    call tls13_random32
    test eax, eax
    jnz  .entropy_fail
    mov  [rel tls13_entropy_degraded], al
    lea  rdi, [rel tls13_private]
    call tls13_random32
    test eax, eax
    jnz  .entropy_fail
    lea  rdi, [rel tls13_public]
    lea  rsi, [rel tls13_private]
    lea  rdx, [rel tls13_basepoint]
    call x25519
    test rax, rax
    jnz  .fail
    mov  byte [rbx], TLS13_CT_HANDSHAKE
    mov  byte [rbx + 1], 0x03
    mov  byte [rbx + 2], 0x01            ; TLSPlaintext legacy record version
    mov  byte [rbx + 5], TLS13_HS_CLIENT_HELLO
    mov  byte [rbx + 9], 0x03
    mov  byte [rbx + 10], 0x03           ; ClientHello legacy_version
    lea  rdi, [rbx + 11]
    lea  rsi, [rel tls13_client_random]
    mov  edx, 32
    call memcpy
    mov  byte [rbx + 43], 0              ; legacy_session_id
    mov  word [rbx + 44], 0x0200         ; cipher_suites length 2
    mov  word [rbx + 46], 0x0113         ; TLS_AES_128_GCM_SHA256 (wire 13 01)
    mov  byte [rbx + 48], 1
    mov  byte [rbx + 49], 0              ; null legacy compression
    lea  r14, [rbx + 52]
    ; server_name
    mov  word [r14], 0
    mov  eax, r13d
    add  eax, 5
    ror  ax, 8
    mov  [r14 + 2], ax
    ror  ax, 8
    sub  eax, 2
    ror  ax, 8
    mov  [r14 + 4], ax
    mov  byte [r14 + 6], 0
    mov  eax, r13d
    ror  ax, 8
    mov  [r14 + 7], ax
    lea  rdi, [r14 + 9]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    add  r14, 9
    add  r14, r13
    ; supported_groups: x25519
    mov  dword [r14], 0x04000a00         ; type=0x000a, ext len=4
    mov  dword [r14 + 4], 0x1d000200     ; list len=2, x25519=0x001d
    add  r14, 8
    ; signature_algorithms: TLS CertificateVerify plus the RSA/SHA-256 chain
    ; signature accepted by the strict X.509 path below.
    mov  word [r14], 0x0d00
    mov  word [r14 + 2], 0x0600
    mov  word [r14 + 4], 0x0400
    mov  word [r14 + 6], 0x0408
    mov  word [r14 + 8], 0x0104
    add  r14, 10
    ; supported_versions: vector { TLS 1.3 }
    mov  word [r14], 0x2b00
    mov  word [r14 + 2], 0x0300
    mov  byte [r14 + 4], 2
    mov  word [r14 + 5], 0x0403
    add  r14, 7
    ; key_share: vector length 36, group x25519, key length 32
    mov  word [r14], 0x3300
    mov  word [r14 + 2], 0x2600
    mov  word [r14 + 4], 0x2400
    mov  word [r14 + 6], 0x1d00
    mov  word [r14 + 8], 0x2000
    lea  rdi, [r14 + 10]
    lea  rsi, [rel tls13_public]
    mov  edx, 32
    call memcpy
    add  r14, 42
    ; Fill all nested lengths from the actual cursor (never a parallel constant).
    mov  rax, r14
    sub  rax, rbx
    mov  r12, rax                        ; total record bytes
    mov  eax, r12d
    sub  eax, 52
    ror  ax, 8
    mov  [rbx + 50], ax
    mov  eax, r12d
    sub  eax, 9                          ; ClientHello body bytes
    mov  [rbx + 8], al
    shr  eax, 8
    mov  [rbx + 7], al
    shr  eax, 8
    mov  [rbx + 6], al
    mov  eax, r12d
    sub  eax, 5
    ror  ax, 8
    mov  [rbx + 3], ax
    lea  rdi, [rel tls13_transcript]
    call sha256_stream_init
    lea  rdi, [rel tls13_transcript]
    lea  rsi, [rbx + 5]
    mov  rdx, r12
    sub  rdx, 5
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    mov  rax, r12
    jmp  .out
.fail:
    mov  rax, -1
    jmp  .out
.entropy_fail:
    mov  byte [rel tls13_entropy_degraded], 1
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Derive-Secret(Secret, Label, Transcript-Hash). R8=out32.
tls13_derive_secret:
    sub  rsp, 8
    mov  qword [rsp], 32
    mov  r9, r8
    mov  r8d, 32
    call tls13_expand_label
    add  rsp, 8
    ret

tls13_expand_key_iv_finished:
    ; RDI=traffic secret, RSI=key16, RDX=iv12, RCX=finished32 (or NULL).
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    sub  rsp, 8
    mov  qword [rsp], 16
    mov  rdi, rbx
    lea  rsi, [rel tls13_label_key]
    mov  edx, 3
    xor  ecx, ecx
    xor  r8d, r8d
    mov  r9, r12
    call tls13_expand_label
    test rax, rax
    jnz  .fail
    mov  qword [rsp], 12
    mov  rdi, rbx
    lea  rsi, [rel tls13_label_iv]
    mov  edx, 2
    xor  ecx, ecx
    xor  r8d, r8d
    mov  r9, r13
    call tls13_expand_label
    test rax, rax
    jnz  .fail
    test r14, r14
    jz   .ok
    mov  qword [rsp], 32
    mov  rdi, rbx
    lea  rsi, [rel tls13_label_finished]
    mov  edx, 8
    xor  ecx, ecx
    xor  r8d, r8d
    mov  r9, r14
    call tls13_expand_label
    test rax, rax
    jnz  .fail
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; CH+SH are already in the running transcript and tls13_shared is populated.
tls13_key_schedule_handshake:
    push r12
    ; early_secret = Extract(0, 0^Hash.length) for a non-PSK handshake.
    lea  rdi, [rel tls13_zero32]
    lea  rsi, [rel tls13_zero32]
    mov  edx, 32
    lea  rcx, [rel tls13_early_secret]
    call tls13_hkdf_extract
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_early_secret]
    lea  rsi, [rel tls13_label_derived]
    mov  edx, 7
    lea  rcx, [rel tls13_empty_hash]
    lea  r8, [rel tls13_derived_secret]
    call tls13_derive_secret
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_derived_secret]
    lea  rsi, [rel tls13_shared]
    mov  edx, 32
    lea  rcx, [rel tls13_handshake_secret]
    call tls13_hkdf_extract
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_transcript_hash]
    call tls13_transcript_digest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_handshake_secret]
    lea  rsi, [rel tls13_label_c_hs]
    mov  edx, 12
    lea  rcx, [rel tls13_transcript_hash]
    lea  r8, [rel tls13_c_hs_secret]
    call tls13_derive_secret
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_handshake_secret]
    lea  rsi, [rel tls13_label_s_hs]
    mov  edx, 12
    lea  rcx, [rel tls13_transcript_hash]
    lea  r8, [rel tls13_s_hs_secret]
    call tls13_derive_secret
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_c_hs_secret]
    lea  rsi, [rel tls13_c_hs_key]
    lea  rdx, [rel tls13_c_hs_iv]
    lea  rcx, [rel tls13_c_finished_key]
    call tls13_expand_key_iv_finished
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_s_hs_secret]
    lea  rsi, [rel tls13_s_hs_key]
    lea  rdx, [rel tls13_s_hs_iv]
    lea  rcx, [rel tls13_s_finished_key]
    call tls13_expand_key_iv_finished
    test rax, rax
    jnz  .fail
    ; master_secret = Extract(Derive-Secret(handshake,"derived",Hash("")), 0).
    lea  rdi, [rel tls13_handshake_secret]
    lea  rsi, [rel tls13_label_derived]
    mov  edx, 7
    lea  rcx, [rel tls13_empty_hash]
    lea  r8, [rel tls13_derived_secret]
    call tls13_derive_secret
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_derived_secret]
    lea  rsi, [rel tls13_zero32]
    mov  edx, 32
    lea  rcx, [rel tls13_master_secret]
    call tls13_hkdf_extract
    test rax, rax
    jnz  .fail
    mov  qword [rel tls13_server_seq], 0
    mov  qword [rel tls13_client_seq], 0
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    ret

; Traffic secrets for application data use the transcript through server
; Finished (before the client Finished is appended), per RFC 8446 section 7.1.
tls13_key_schedule_application:
    lea  rdi, [rel tls13_transcript_hash]
    call tls13_transcript_digest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_master_secret]
    lea  rsi, [rel tls13_label_c_ap]
    mov  edx, 12
    lea  rcx, [rel tls13_transcript_hash]
    lea  r8, [rel tls13_c_ap_secret]
    call tls13_derive_secret
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_master_secret]
    lea  rsi, [rel tls13_label_s_ap]
    mov  edx, 12
    lea  rcx, [rel tls13_transcript_hash]
    lea  r8, [rel tls13_s_ap_secret]
    call tls13_derive_secret
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_c_ap_secret]
    lea  rsi, [rel tls13_c_ap_key]
    lea  rdx, [rel tls13_c_ap_iv]
    xor  ecx, ecx
    call tls13_expand_key_iv_finished
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_s_ap_secret]
    lea  rsi, [rel tls13_s_ap_key]
    lea  rdx, [rel tls13_s_ap_iv]
    xor  ecx, ecx
    call tls13_expand_key_iv_finished
    test rax, rax
    jnz  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; Parse a complete ServerHello handshake message and derive handshake keys.
tls13_parse_server_hello:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    test rbx, rbx
    jz   .fail
    cmp  r12, 44
    jb   .fail
    cmp  byte [rbx], TLS13_HS_SERVER_HELLO
    jne  .fail
    movzx eax, byte [rbx + 1]
    shl  eax, 8
    mov  al, [rbx + 2]
    shl  eax, 8
    mov  al, [rbx + 3]
    add  eax, 4
    cmp  rax, r12
    jne  .fail
    cmp  word [rbx + 4], 0x0303
    jne  .fail
    lea  r13, [rbx + 38]                ; legacy_session_id_echo length
    movzx eax, byte [r13]
    inc  r13
    add  r13, rax
    lea  rax, [rbx + r12]
    mov  r15, rax
    lea  rax, [r13 + 5]
    cmp  rax, r15
    ja   .fail
    cmp  word [r13], 0x0113             ; TLS_AES_128_GCM_SHA256
    jne  .fail
    cmp  byte [r13 + 2], 0
    jne  .fail
    movzx eax, byte [r13 + 3]
    shl  eax, 8
    mov  al, [r13 + 4]
    lea  r14, [r13 + 5]
    lea  rdx, [r14 + rax]
    cmp  rdx, r15
    jne  .fail                           ; extensions exactly fill ServerHello
    xor  r12d, r12d                     ; bit0 version, bit1 key_share
.ext:
    cmp  r14, r15
    jae  .ext_done
    lea  rax, [r14 + 4]
    cmp  rax, r15
    ja   .fail
    movzx eax, byte [r14]
    shl  eax, 8
    mov  al, [r14 + 1]
    mov  r13d, eax                       ; type
    movzx eax, byte [r14 + 2]
    shl  eax, 8
    mov  al, [r14 + 3]
    lea  rcx, [r14 + 4]
    lea  rax, [rcx + rax]
    cmp  rax, r15
    ja   .fail
    cmp  r13d, 43
    jne  .maybe_share
    lea  rdx, [rcx + 2]
    cmp  rax, rdx
    jne  .fail
    cmp  word [rcx], 0x0403
    jne  .fail
    or   r12d, 1
    jmp  .next
.maybe_share:
    cmp  r13d, 51
    jne  .next
    lea  r13, [rcx + 36]
    cmp  rax, r13
    jne  .fail
    cmp  word [rcx], 0x1d00
    jne  .fail
    cmp  word [rcx + 2], 0x2000
    jne  .fail
    lea  rdi, [rel tls13_server_public]
    lea  rsi, [rcx + 4]
    mov  edx, 32
    push rax
    call memcpy
    pop  rax
    or   r12d, 2
.next:
    mov  r14, rax
    jmp  .ext
.ext_done:
    cmp  r12d, 3
    jne  .fail
    lea  rdi, [rel tls13_shared]
    lea  rsi, [rel tls13_private]
    lea  rdx, [rel tls13_server_public]
    call x25519
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_shared]
    xor  eax, eax
    mov  ecx, 32
.nz:
    or   al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .nz
    test al, al
    jz   .fail                           ; RFC 7748 all-zero shared secret reject
    lea  rdi, [rel tls13_transcript]
    mov  rsi, rbx
    mov  rdx, r15
    sub  rdx, rbx
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    call tls13_key_schedule_handshake
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_state], TLS13_ST_ENC_EXT
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Nonce = static_iv XOR padded_record_sequence_number (RFC 8446 5.3).
tls13_make_nonce:
    mov  rax, [rsi]
    mov  [rdi], rax
    mov  eax, [rsi + 8]
    mov  [rdi + 8], eax
    bswap rdx
    xor  [rdi + 4], rdx
    ret

; Open one complete encrypted server record into tls13_plain_buf.
; RDI=record, ESI=total bytes -> RAX=content length, RDX=inner type, or -1.
tls13_open_server_record:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12d, esi
    cmp  r12d, 5 + 17
    jb   .fail
    cmp  byte [rbx], TLS13_CT_APPLICATION
    jne  .fail
    cmp  word [rbx + 1], 0x0303
    jne  .fail
    movzx eax, byte [rbx + 3]
    shl  eax, 8
    mov  al, [rbx + 4]
    add  eax, 5
    cmp  eax, r12d
    jne  .fail
    sub  eax, 5 + 16                    ; authenticated plaintext length
    cmp  eax, TLS13_RX_CAP - 5
    ja   .fail
    mov  r13d, eax
    lea  r12, [rel tls13_s_hs_key]
    lea  r14, [rel tls13_s_hs_iv]
    cmp  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    jne  .key_ready
    lea  r12, [rel tls13_s_ap_key]
    lea  r14, [rel tls13_s_ap_iv]
.key_ready:
    lea  rdi, [rel tls13_nonce]
    mov  rsi, r14
    mov  rdx, [rel tls13_server_seq]
    call tls13_make_nonce
    lea  rax, [rel tls13_aead_req]
    mov  [rax + AEAD_KEY], r12
    lea  rcx, [rel tls13_nonce]
    mov  [rax + AEAD_NONCE], rcx
    mov  [rax + AEAD_AAD], rbx
    mov  qword [rax + AEAD_AAD_LEN], 5
    lea  rcx, [rbx + 5]
    mov  [rax + AEAD_INPUT], rcx
    mov  [rax + AEAD_INPUT_LEN], r13
    lea  rcx, [rbx + 5]                 ; authenticate first, then decrypt in place
    mov  [rax + AEAD_OUTPUT], rcx
    lea  rcx, [rbx + 5 + r13]
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes128_gcm_open
    test rax, rax
    jnz  .fail
    inc  qword [rel tls13_server_seq]
    test r13d, r13d
    jz   .fail
    mov  ecx, r13d
    lea  r8, [rbx + 5]
.strip_padding:
    dec  ecx
    movzx edx, byte [r8 + rcx]
    test dl, dl
    jnz  .inner
    test ecx, ecx
    jnz  .strip_padding
    jmp  .fail
.inner:
    cmp  edx, TLS13_CT_ALERT
    je   .ok
    cmp  edx, TLS13_CT_HANDSHAKE
    je   .ok
    cmp  edx, TLS13_CT_APPLICATION
    jne  .fail
.ok:
    mov  eax, ecx                       ; bytes before inner content type
    jmp  .out
.fail:
    mov  rax, -1
    xor  edx, edx
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Seal content with the current client traffic key. RDI=content, ESI=len,
; EDX=inner content type, RCX=out record -> RAX=record bytes/-1.
tls13_seal_client_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14, rcx
    test r14, r14
    jz   .fail
    cmp  r12d, TLS13_SEAL_CAP - 1
    ja   .fail
    test r12d, r12d
    jz   .copied
    test rbx, rbx
    jz   .fail
    lea  rdi, [rel tls13_seal_plain]
    mov  rsi, rbx
    mov  edx, r12d
    call memcpy
.copied:
    lea  rax, [rel tls13_seal_plain]
    mov  byte [rax + r12], r13b
    inc  r12d
    mov  byte [r14], TLS13_CT_APPLICATION
    mov  word [r14 + 1], 0x0303
    mov  eax, r12d
    add  eax, 16
    ror  ax, 8
    mov  [r14 + 3], ax
    lea  rbx, [rel tls13_c_hs_key]
    lea  r15, [rel tls13_c_hs_iv]
    cmp  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    jne  .key_ready
    lea  rbx, [rel tls13_c_ap_key]
    lea  r15, [rel tls13_c_ap_iv]
.key_ready:
    lea  rdi, [rel tls13_nonce]
    mov  rsi, r15
    mov  rdx, [rel tls13_client_seq]
    call tls13_make_nonce
    lea  rax, [rel tls13_aead_req]
    mov  [rax + AEAD_KEY], rbx
    lea  rcx, [rel tls13_nonce]
    mov  [rax + AEAD_NONCE], rcx
    mov  [rax + AEAD_AAD], r14
    mov  qword [rax + AEAD_AAD_LEN], 5
    lea  rcx, [rel tls13_seal_plain]
    mov  [rax + AEAD_INPUT], rcx
    mov  [rax + AEAD_INPUT_LEN], r12
    lea  rcx, [r14 + 5]
    mov  [rax + AEAD_OUTPUT], rcx
    lea  rcx, [r14 + 5 + r12]
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes128_gcm_seal
    test rax, rax
    jnz  .fail
    inc  qword [rel tls13_client_seq]
    mov  eax, r12d
    add  eax, 21
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Dedicated bounded application owner. External TLSCONNECT cannot replace its
; tuple or pin. RDI=connect arg, RSI=pin32, RDX=authenticated RX callback.
tls13_app_start:
    cmp byte [rel tls13_app_owned], 0
    jne tls13_app_busy
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rdx
    lea rdi, [rel tls13_app_pin]
    mov edx, 32
    call memcpy
    mov [rel tls13_app_receive], r12
    mov byte [rel tls13_app_owned], 1
    mov byte [rel tls13_app_peer_closed], 0
    mov dword [rel tls13_app_wire_len], 0
    mov rdi, rbx
    call tls13_connect_start_owned
    pop r12
    pop rbx
    ret

; RDI=plaintext, ESI=len. Seal ONCE, then retry the exact ciphertext through
; TCP's one-flight pacing. Resealing on backpressure would skip TLS sequences.
tls13_app_prepare:
    cmp byte [rel tls13_app_owned], 1
    jne tls13_app_busy
    cmp byte [rel tls13_established], 1
    jne tls13_app_busy
    cmp byte [rel tls13_trust_path], 3
    jne tls13_app_busy
    cmp dword [rel tls13_app_wire_len], 0
    jne tls13_app_busy
    mov edx, TLS13_CT_APPLICATION
    lea rcx, [rel tls13_app_wire]
    call tls13_seal_client_record
    test rax, rax
    js tls13_app_busy
    mov [rel tls13_app_wire_len], eax
    lea rdi, [rel tls13_seal_plain]
    xor esi, esi
    mov edx, TLS13_SEAL_CAP
    call memset
    xor eax, eax
    ret

tls13_app_flush:
    cmp byte [rel tls13_established], 1
    jne tls13_app_busy
    mov edx, [rel tls13_app_wire_len]
    test edx, edx
    jz tls13_app_busy
    mov rdi, [rel tls13_tcb]
    lea rsi, [rel tls13_app_wire]
    call tls13_send_owned
    test rax, rax
    jnz tls13_app_busy
    mov dword [rel tls13_app_wire_len], 0
    xor eax, eax
    ret

; Exercise the exact encrypted application-record and TLS->TCP callback seam.
; TCP commits a pinned receive prefix only when the callback returns RAX=0.
; This fixture feeds a sealed record through tls13_tcp_receive itself, so a
; regression to the old RAX=1 convention cannot earn Task2504 boot markers.
tls13_application_transition_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, -1
    cmp  qword [rel tls13_tcb], 0
    jne  .out
    cmp  byte [rel tls13_app_owned], 0
    jne  .out
    mov  r15, [rel tls13_rx_buf]
    lea  rax, [rel tls13_kat_app_rx]
    mov  [rel tls13_rx_buf], rax
    mov  dword [rel tls13_rx_len], 0
    mov  dword [rel tls13_hs_len], 0
    mov  dword [rel tls13_records_rx], 0
    mov  qword [rel tls13_client_seq], 0
    mov  qword [rel tls13_server_seq], 0
    mov  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    mov  byte [rel tls13_error], TLS13_ERR_NONE
    mov  byte [rel tls13_established], 1
    mov  byte [rel tls13_trust_path], 3
    mov  byte [rel tls13_app_owned], 1
    mov  byte [rel tls13_app_peer_closed], 0
    mov  byte [rel tls13_kat_app_seen], 0
    lea  rax, [rel tls13_kat_app_receive]
    mov  [rel tls13_app_receive], rax
    mov  dword [rel tls13_app_wire_len], 0
    lea  rdi, [rel tls13_c_ap_key]
    lea  rsi, [rel tls13_kat_key_expected]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel tls13_s_ap_key]
    lea  rsi, [rel tls13_kat_key_expected]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel tls13_c_ap_iv]
    lea  rsi, [rel tls13_kat_iv_expected]
    mov  edx, 12
    call memcpy
    lea  rdi, [rel tls13_s_ap_iv]
    lea  rsi, [rel tls13_kat_iv_expected]
    mov  edx, 12
    call memcpy
    lea  rdi, [rel tls13_kat_app_plain]
    mov  esi, tls13_kat_app_plain_end - tls13_kat_app_plain
    call tls13_app_prepare
    test rax, rax
    jnz  .cleanup
    mov  r13d, [rel tls13_app_wire_len]
    test r13d, r13d
    jz   .cleanup
    xor  edi, edi
    lea  rsi, [rel tls13_app_wire]
    mov  edx, r13d
    call tls13_tcp_receive
    test rax, rax
    jnz  .cleanup
    cmp  byte [rel tls13_kat_app_seen], 1
    jne  .cleanup
    cmp  dword [rel tls13_rx_len], 0
    jne  .cleanup
    cmp  dword [rel tls13_records_rx], 1
    jne  .cleanup
    cmp  byte [rel tls13_last_record_type], TLS13_CT_APPLICATION
    jne  .cleanup
    cmp  qword [rel tls13_client_seq], 1
    jne  .cleanup
    cmp  qword [rel tls13_server_seq], 1
    jne  .cleanup
    xor  r12d, r12d
.cleanup:
    mov  [rel tls13_rx_buf], r15
    mov  dword [rel tls13_rx_len], 0
    mov  dword [rel tls13_hs_len], 0
    mov  dword [rel tls13_records_rx], 0
    mov  qword [rel tls13_client_seq], 0
    mov  qword [rel tls13_server_seq], 0
    mov  byte [rel tls13_state], TLS13_ST_IDLE
    mov  byte [rel tls13_error], TLS13_ERR_NONE
    mov  byte [rel tls13_established], 0
    mov  byte [rel tls13_trust_path], 0
    mov  byte [rel tls13_last_record_type], 0
    mov  byte [rel tls13_app_owned], 0
    mov  byte [rel tls13_app_peer_closed], 0
    mov  byte [rel tls13_kat_app_seen], 0
    mov  qword [rel tls13_app_receive], 0
    mov  dword [rel tls13_app_wire_len], 0
    call tls13_wipe_secrets
    lea  rdi, [rel tls13_app_wire]
    xor  esi, esi
    mov  edx, TLS13_SEAL_CAP + 32
    call memset
    lea  rdi, [rel tls13_kat_app_rx]
    xor  esi, esi
    mov  edx, TLS13_SEAL_CAP + 32
    call memset
.out:
    mov  eax, r12d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

tls13_kat_app_receive:
    cmp  esi, tls13_kat_app_plain_end - tls13_kat_app_plain
    jne  .bad
    mov  rax, 0x54414b2d48535550       ; little-endian "PUSH-KAT"
    cmp  [rdi], rax
    jne  .bad
    mov  byte [rel tls13_kat_app_seen], 1
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; tls13_app_owner -> RAX = the RX callback of the application owner holding the
; session, or 0 when none does. Read-only: lets a caller refuse instead of
; closing a session it did not open.
tls13_app_owner:
    xor eax, eax
    cmp byte [rel tls13_app_owned], 1
    jne .done
    mov rax, [rel tls13_app_receive]
.done:
    ret

tls13_app_close:
    cmp byte [rel tls13_app_owned], 1
    jne .done
    mov edi, TLS13_ERR_NONE
    call tls13_fail
    mov byte [rel tls13_app_owned], 0
    mov byte [rel tls13_app_peer_closed], 0
    mov qword [rel tls13_app_receive], 0
    mov dword [rel tls13_app_wire_len], 0
    lea rdi, [rel tls13_app_pin]
    xor esi, esi
    mov edx, 32
    call memset
    lea rdi, [rel tls13_app_wire]
    xor esi, esi
    mov edx, TLS13_SEAL_CAP + 32
    call memset
    lea rdi, [rel tls13_seal_plain]
    xor esi, esi
    mov edx, TLS13_SEAL_CAP
    call memset
    mov rdi, [rel tls13_rx_buf]
    test rdi, rdi
    jz .done
    xor esi, esi
    mov edx, TLS13_RX_CAP
    call memset
.done:
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_tls13_0 0
align 8
tls13_app_receive: dq 0
tls13_app_owned: db 0
tls13_app_peer_closed: db 0
tls13_app_pin: times 32 db 0
tls13_app_wire_len: dd 0
tls13_app_wire: times TLS13_SEAL_CAP + 32 db 0
tls13_kat_app_seen: db 0
tls13_kat_app_plain: db 'PUSH-KAT'
tls13_kat_app_plain_end:
align 16
; tls13_kat_app_rx..tls13_kat_app_rx moved to WDATA_net_tls13_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_net_tls13_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_net_tls13_0_bss1 0
resb 32                 ; keeps tls13_kat_app_rx at its WDATA offset mod 64
alignb 16
tls13_kat_app_rx: resb TLS13_SEAL_CAP + 32
%endmacro
WDATA_BSS_DEFER WDATA_net_tls13_0_bss1

tls13_fail:
    mov byte [rel tls13_policy_ok], 0
    ; EDI=TLS13_ERR_*.  Fail closed: erase the established TCP tuple and never
    ; retain a certificate-success bit from an earlier attempt.
    mov  [rel tls13_error], dil
    mov  byte [rel tls13_state], TLS13_ST_FAILED
    mov  byte [rel tls13_established], 0
    mov  byte [rel tls13_cert_verified], 0
    call tls13_wipe_secrets
    call tls13_retire_transport
    ret

; Keep the pair on try-lock contention: a subsequent close/start can retry.
; Stale ownership is already retired, so forgetting it cannot touch a new flow.
tls13_retire_transport:
    mov  rdi, [rel tls13_tcb]
    test rdi, rdi
    jz   .clear
    mov  rsi, [rel tls13_tcb_epoch]
    xor  edx, edx
    xor  ecx, ecx
    mov  r8d, 2
    call tcp_client_epoch_io
    cmp  rax, -1
    je   .out
.clear:
    mov  qword [rel tls13_tcb], 0
    mov  qword [rel tls13_tcb_epoch], 0
    xor  eax, eax
.out:
    ret

; Original TLS send convention; preserve exact ciphertext ownership on refusal.
tls13_send_owned:
    mov  rcx, rdx
    mov  rdx, rsi
    mov  rsi, [rel tls13_tcb_epoch]
    mov  r8d, 1
    jmp  tcp_client_epoch_io

tls13_wipe_secrets:
    mov byte [rel tls13_cert_verified], 0
    mov byte [rel tls13_policy_ok], 0
    lea  rdi, [rel tls13_private]
    xor  esi, esi
    mov  edx, tls13_client_finished + 36 - tls13_private
    call memset
    ret

TLS13_XI_TBS_PTR equ 0
TLS13_XI_TBS_LEN equ 8
TLS13_XI_SIG_PTR equ 16
TLS13_XI_SIG_LEN equ 24
TLS13_XI_MOD_LEN equ 32
TLS13_XI_SIZE    equ 40

; Minimal definite-length DER cursor (X.690 10.1 shortest length encoding).
; RDI=cursor, RSI=end. Success returns
; RAX=value, RDX=value_len, RCX=next, R8D=tag; failure returns RAX=0.
tls13_der_read:
    mov  rax, rdi
    add  rax, 2
    cmp  rax, rsi
    ja   .bad
    movzx r8d, byte [rdi]
    movzx edx, byte [rdi + 1]
    lea  rcx, [rdi + 2]
    test dl, 0x80
    jz   .bounded
    cmp  edx, 0x81
    je   .len1
    cmp  edx, 0x82
    je   .len2
    jmp  .bad                           ; indefinite/>64KiB DER is outside v1
.len1:
    lea  rax, [rdi + 3]
    cmp  rax, rsi
    ja   .bad
    movzx edx, byte [rdi + 2]
    cmp  edx, 128                       ; short form is required below 128
    jb   .bad
    lea  rcx, [rdi + 3]
    jmp  .bounded
.len2:
    lea  rax, [rdi + 4]
    cmp  rax, rsi
    ja   .bad
    movzx edx, byte [rdi + 2]
    shl  edx, 8
    mov  dl, [rdi + 3]
    cmp  edx, 256                       ; no leading zero length octet
    jb   .bad
    lea  rcx, [rdi + 4]
.bounded:
    mov  rax, rcx
    add  rcx, rdx
    cmp  rcx, rsi
    ja   .bad
    ret
.bad:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    xor  r8d, r8d
    ret

; Parse RSA-2048/RSA-4096 material and signed spans from one X.509 certificate.
; RDI=cert, RSI=len, RDX=modulus_le512 out, RCX=TLS13_XI info out -> 0/-1.
tls13_x509_parse:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  rbx, rdi
    lea  r12, [rdi + rsi]
    mov  r13, rdx
    mov  r14, rcx
    test rbx, rbx
    jz   .fail
    test r13, r13
    jz   .fail
    test r14, r14
    jz   .fail
    mov  rdi, rbx
    mov  rsi, r12
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x30
    jne  .fail
    cmp  rcx, r12
    jne  .fail
    mov  r15, rax                       ; Certificate SEQUENCE value
    lea  rbp, [rax + rdx]               ; outer end
    mov  [rsp], r15                     ; TBSCertificate full start
    mov  rdi, r15
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x30
    jne  .fail
    mov  [rsp + 8], rax                 ; TBS value
    lea  rdi, [rax + rdx]
    mov  [rsp + 16], rdi                ; TBS value end
    mov  [r14 + TLS13_XI_TBS_PTR], r15
    mov  rdi, rcx
    sub  rdi, r15
    mov  [r14 + TLS13_XI_TBS_LEN], rdi
    ; outer signatureAlgorithm must be sha256WithRSAEncryption.
    mov  rdi, rcx
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x30
    jne  .fail
    cmp  edx, 13
    jne  .fail
    cmp  byte [rax], 0x06
    jne  .fail
    cmp  byte [rax + 1], 9
    jne  .fail
    mov  rdx, 0x01010df78648862a
    cmp  qword [rax + 2], rdx
    jne  .fail
    cmp  byte [rax + 10], 0x0b
    jne  .fail
    cmp  word [rax + 11], 0x0005        ; DER NULL parameters
    jne  .fail
    mov  rdi, rcx
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x03
    jne  .fail
    cmp  edx, 257
    je   .signature_size
    cmp  edx, 513
    jne  .fail
.signature_size:
    cmp  byte [rax], 0
    jne  .fail
    inc  rax
    dec  rdx
    mov  [r14 + TLS13_XI_SIG_PTR], rax
    mov  [r14 + TLS13_XI_SIG_LEN], rdx
    cmp  rcx, rbp
    jne  .fail

    ; Locate SubjectPublicKeyInfo by the fixed TBSCertificate child order.
    mov  r15, [rsp + 8]
    mov  rdi, r15
    mov  rsi, [rsp + 16]
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0xa0
    jne  .no_version
    mov  r15, rcx
.no_version:
    mov  ebx, 5                         ; serial, sigalg, issuer, validity, subject
.skip_tbs:
    mov  rdi, r15
    mov  rsi, [rsp + 16]
    call tls13_der_read
    test rax, rax
    jz   .fail
    mov  r15, rcx
    dec  ebx
    jnz  .skip_tbs
    mov  rdi, r15                       ; SubjectPublicKeyInfo
    mov  rsi, [rsp + 16]
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x30
    jne  .fail
    mov  r15, rax
    lea  rbp, [rax + rdx]
    mov  rdi, r15                       ; algorithm identifier
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x30
    jne  .fail
    cmp  edx, 13
    jne  .fail
    cmp  byte [rax], 0x06
    jne  .fail
    cmp  byte [rax + 1], 9
    jne  .fail
    mov  rdx, 0x01010df78648862a
    cmp  qword [rax + 2], rdx
    jne  .fail
    cmp  byte [rax + 10], 0x01          ; rsaEncryption
    jne  .fail
    cmp  word [rax + 11], 0x0005
    jne  .fail
    mov  rdi, rcx                       ; subjectPublicKey BIT STRING
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x03
    jne  .fail
    cmp  byte [rax], 0
    jne  .fail
    inc  rax
    dec  rdx
    lea  rsi, [rax + rdx]
    mov  rdi, rax                       ; RSAPublicKey SEQUENCE
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x30
    jne  .fail
    mov  r15, rax
    lea  rbp, [rax + rdx]
    mov  rdi, r15                       ; modulus INTEGER
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x02
    jne  .fail
    cmp  edx, 257
    je   .strip_mod_zero
    cmp  edx, 513
    jne  .mod_width
.strip_mod_zero:
    cmp  byte [rax], 0
    jne  .fail
    inc  rax
    dec  edx
.mod_width:
    cmp  edx, 256
    je   .mod_ok
    cmp  edx, 512
    jne  .fail
.mod_ok:
    mov  [r14 + TLS13_XI_MOD_LEN], rdx
    mov  [rsp + 32], rax                ; modulus big-endian bytes
    mov  [rsp + 24], rcx                ; exponent cursor
    mov  rdi, r13
    xor  esi, esi
    mov  edx, 512
    call memset
    mov  r15, [rsp + 32]
    xor  ecx, ecx
.reverse_mod:
    mov  edx, [r14 + TLS13_XI_MOD_LEN]
    dec  edx
    sub  edx, ecx
    mov  sil, [r15 + rcx]
    mov  [r13 + rdx], sil
    inc  ecx
    cmp  rcx, [r14 + TLS13_XI_MOD_LEN]
    jb   .reverse_mod
    mov  rdi, [rsp + 24]
    mov  rsi, rbp
    call tls13_der_read
    test rax, rax
    jz   .fail
    cmp  r8d, 0x02
    jne  .fail
    cmp  edx, 3
    jne  .fail
    cmp  byte [rax], 1
    jne  .fail
    cmp  byte [rax + 1], 0
    jne  .fail
    cmp  byte [rax + 2], 1
    jne  .fail
    cmp  rcx, rbp
    jne  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Parse one TLS CertificateEntry. RDI=cursor, RSI=list_end ->
; RAX=cert ptr, RDX=cert len, RCX=next entry; RAX=0 reject.
tls13_cert_entry:
    lea  rax, [rdi + 3]
    cmp  rax, rsi
    ja   .bad
    movzx edx, byte [rdi]
    shl  edx, 8
    mov  dl, [rdi + 1]
    shl  edx, 8
    mov  dl, [rdi + 2]
    test edx, edx
    jz   .bad
    lea  rax, [rdi + 3]
    lea  rcx, [rax + rdx]
    lea  r8, [rcx + 2]
    cmp  r8, rsi
    ja   .bad
    movzx r9d, byte [rcx]
    shl  r9d, 8
    mov  r9b, [rcx + 1]
    add  rcx, 2
    add  rcx, r9
    cmp  rcx, rsi
    ja   .bad
    ret
.bad:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    ret

; Verify an RSA/SHA-256 certificate chain and pin the final root fingerprint.
; The single-certificate/self-signed negative is rejected even before the pin.
tls13_verify_certificate_chain:
    mov byte [rel tls13_cert_verified], 0
    mov byte [rel tls13_established], 0
    mov byte [rel tls13_chain_ok], 0
    mov byte [rel tls13_policy_ok], 0
    mov dword [rel tls13_policy_reason], 0
    mov dword [rel tls13_policy_count], 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  rbx, rdi
    mov  rbp, rsi
    cmp  rbp, 9
    jb   .fail
    cmp  byte [rbx], TLS13_HS_CERTIFICATE
    jne  .fail
    lea  r12, [rbx + 4]
    lea  r13, [rbx + rbp]
    movzx eax, byte [r12]
    inc  r12
    add  r12, rax                       ; certificate_request_context
    lea  rax, [r12 + 3]
    cmp  rax, r13
    ja   .fail
    movzx eax, byte [r12]
    shl  eax, 8
    mov  al, [r12 + 1]
    shl  eax, 8
    mov  al, [r12 + 2]
    add  r12, 3
    lea  r13, [r12 + rax]
    lea  rax, [rbx + rbp]
    cmp  r13, rax
    jne  .fail
    xor  ebx, ebx                       ; certificate count
.cert:
    cmp  r12, r13
    jae  .fail
    mov  rdi, r12
    mov  rsi, r13
    call tls13_cert_entry
    test rax, rax
    jz   .fail
    mov  r14, rax                       ; child DER
    mov  r15d, edx                      ; child len
    ; Views live only through this synchronous callback, before HS buffer reuse.
    mov eax, [rel tls13_policy_count]
    cmp eax, 8
    jae .fail
    shl eax, 4
    lea rdx, [rel tls13_policy_views]
    add rdx, rax
    mov [rdx], r14
    mov [rdx+8], r15
    inc dword [rel tls13_policy_count]
    mov  [rsp], rcx                     ; next entry
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel tls13_child_modulus]
    lea  rcx, [rel tls13_child_info]
    call tls13_x509_parse
    test rax, rax
    jnz  .fail
    test ebx, ebx
    jnz  .leaf_saved
    cmp  qword [rel tls13_child_info + TLS13_XI_MOD_LEN], 256
    jne  .fail                           ; v1 CertificateVerify is RSA-2048/PSS
    lea  rdi, [rel tls13_leaf_modulus]
    lea  rsi, [rel tls13_child_modulus]
    mov  edx, 256
    call memcpy
    lea rdi, [rel tls13_leaf_hash]
    mov rsi, r14
    mov edx, r15d
    call sha256_hash
    test eax, eax
    jnz .fail
    ; Task2504 uses an explicit owner-provisioned leaf pin. This is a separate
    ; trust decision from the legacy chain path, never a cert_verified claim.
    ; CertificateVerify and Finished still prove possession and transcript.
    cmp byte [rel tls13_app_owned], 1
    jne .leaf_saved
    lea rdi, [rel tls13_root_hash]
    mov rsi, r14
    mov edx, r15d
    call sha256_hash
    test eax, eax
    jnz .fail
    lea rdi, [rel tls13_root_hash]
    lea rsi, [rel tls13_app_pin]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .fail
    mov byte [rel tls13_trust_path], 3
    jmp .trusted
.leaf_saved:
    inc  ebx
    mov  r12, [rsp]
    cmp  r12, r13
    jae  .root
    ; Parse the issuer (the next CertificateEntry) and verify the child TBS.
    mov  rdi, r12
    mov  rsi, r13
    call tls13_cert_entry
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel tls13_issuer_modulus]
    lea  rcx, [rel tls13_issuer_info]
    call tls13_x509_parse
    test rax, rax
    jnz  .fail
    mov  rax, [rel tls13_issuer_info + TLS13_XI_MOD_LEN]
    cmp  rax, [rel tls13_child_info + TLS13_XI_SIG_LEN]
    jne  .fail
    cmp  eax, 256
    je   .verify_rsa2048
    cmp  eax, 512
    jne  .fail
    mov  rdi, [rel tls13_child_info + TLS13_XI_SIG_PTR]
    mov  rsi, [rel tls13_child_info + TLS13_XI_TBS_PTR]
    mov  rdx, [rel tls13_child_info + TLS13_XI_TBS_LEN]
    lea  rcx, [rel tls13_issuer_modulus]
    call rsa4096_verify_sha256
    jmp  .issuer_verified
.verify_rsa2048:
    mov  rdi, [rel tls13_child_info + TLS13_XI_SIG_PTR]
    mov  rsi, [rel tls13_child_info + TLS13_XI_TBS_PTR]
    mov  rdx, [rel tls13_child_info + TLS13_XI_TBS_LEN]
    lea  rcx, [rel tls13_issuer_modulus]
    call rsa2048_verify_sha256
.issuer_verified:
    test rax, rax
    jnz  .fail
    jmp  .cert
.root:
    ; RFC 8446 servers normally omit the self-signed trust anchor. First accept
    ; the byte-exact anchor when a fixture includes it, then handle the normal
    ; leaf+intermediate chain by verifying the last presented certificate with
    ; the locally trusted ISRG Root X1 RSA-4096 key. A lone self-signed leaf
    ; matches neither condition and remains rejected.
    lea  rdi, [rel tls13_root_hash]
    mov  rsi, r14
    mov  edx, r15d
    call sha256_hash
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_root_hash]
    lea  rsi, [rel tls13_anchor_isrg_root_x1]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .anchor_omitted
    cmp  ebx, 2
    jb   .fail                           ; presented anchor cannot also be the leaf
    mov  byte [rel tls13_trust_path], 1
    jmp  .trusted
.anchor_omitted:
    cmp  qword [rel tls13_child_info + TLS13_XI_SIG_LEN], 512
    jne  .fail                           ; ISRG Root X1 signatures are RSA-4096
    mov  rdi, [rel tls13_child_info + TLS13_XI_SIG_PTR]
    mov  rsi, [rel tls13_child_info + TLS13_XI_TBS_PTR]
    mov  rdx, [rel tls13_child_info + TLS13_XI_TBS_LEN]
    lea  rcx, [rel tls13_anchor_isrg_root_x1_modulus]
    call rsa4096_verify_sha256
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_trust_path], 2
.trusted:
    ; Owner-pinned applications retain their separate leaf-pin trust decision.
    cmp byte [rel tls13_app_owned], 1
    je .admitted
    ; Signatures and the fixed local anchor have succeeded. Add ordinary
    ; name/date/CA policy before accepting CertificateVerify or app data.
    call time_wall_utc_now_s
    mov [rel tls13_policy_utc], rax
    mov r8, rax
    lea rdi, [rel tls13_policy_views]
    mov esi, [rel tls13_policy_count]
    lea rdx, [rel tls13_sni]
    mov ecx, [rel tls13_sni_len]
    movzx r9d, byte [rel tls13_trust_path]
    call tls13_cert_policy
    mov [rel tls13_policy_reason], edx
    test rax, rax
    jnz .fail
    mov byte [rel tls13_policy_ok], 1
.admitted:
    mov  byte [rel tls13_chain_ok], 1
    xor  eax, eax
    jmp  .out
.fail:
    mov  byte [rel tls13_chain_ok], 0
    mov  eax, -1
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

tls13_transcript_add:
    lea  rax, [rel tls13_transcript]
    xchg rax, rdi                       ; preserve caller data ptr in RAX
    mov  rdx, rsi
    mov  rsi, rax
    call sha256_stream_update
    ret

; CertificateVerify is checked over the transcript BEFORE this message.
tls13_verify_certverify:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    cmp  r12, 4 + 2 + 2 + 256
    jne  .fail
    cmp  byte [rbx], TLS13_HS_CERT_VERIFY
    jne  .fail
    cmp  word [rbx + 4], 0x0408         ; rsa_pss_rsae_sha256 (wire 08 04)
    jne  .fail
    cmp  word [rbx + 6], 0x0001         ; signature length 0x0100
    jne  .fail
    lea  rdi, [rel tls13_transcript_hash]
    call tls13_transcript_digest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_cv_input]
    mov  esi, 0x20
    mov  edx, 64
    call memset
    lea  rdi, [rel tls13_cv_input + 64]
    lea  rsi, [rel tls13_cv_context]
    mov  edx, 33
    call memcpy
    mov  byte [rel tls13_cv_input + 97], 0
    lea  rdi, [rel tls13_cv_input + 98]
    lea  rsi, [rel tls13_transcript_hash]
    mov  edx, 32
    call memcpy
    lea  rdi, [rbx + 8]
    lea  rsi, [rel tls13_cv_input]
    mov  edx, 130
    lea  rcx, [rel tls13_leaf_modulus]
    call rsa2048_verify_pss_sha256
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  rsi, r12
    call tls13_transcript_add
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_certverify_ok], 1
    xor  eax, eax
    jmp  .out
.fail:
    mov  byte [rel tls13_certverify_ok], 0
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Verify server Finished, derive application keys, send client Finished under
; client_handshake_traffic_secret, then publish the established state.
tls13_finish_handshake:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    cmp  r12, 36
    jne  .fail
    cmp  byte [rbx], TLS13_HS_FINISHED
    jne  .fail
    cmp  byte [rbx + 1], 0
    jne  .fail
    cmp  byte [rbx + 2], 0
    jne  .fail
    cmp  byte [rbx + 3], 32
    jne  .fail
    cmp  byte [rel tls13_chain_ok], 1
    jne  .fail
    cmp  byte [rel tls13_certverify_ok], 1
    jne  .fail
    cmp byte [rel tls13_app_owned], 1
    je .policy_admitted
    cmp byte [rel tls13_policy_ok], 1
    jne .fail
.policy_admitted:
    lea  rdi, [rel tls13_transcript_hash]
    call tls13_transcript_digest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_s_finished_key]
    mov  esi, 32
    lea  rdx, [rel tls13_transcript_hash]
    mov  ecx, 32
    lea  r8, [rel tls13_verify_data]
    call tls13_hmac
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_verify_data]
    lea  rsi, [rbx + 4]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_peer_finished_ok], 1
    mov  rdi, rbx
    mov  rsi, r12
    call tls13_transcript_add
    test rax, rax
    jnz  .fail
    call tls13_key_schedule_application
    test rax, rax
    jnz  .fail
    ; Client Finished verify_data covers transcript through server Finished.
    lea  rdi, [rel tls13_transcript_hash]
    call tls13_transcript_digest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_c_finished_key]
    mov  esi, 32
    lea  rdx, [rel tls13_transcript_hash]
    mov  ecx, 32
    lea  r8, [rel tls13_client_finished + 4]
    call tls13_hmac
    test rax, rax
    jnz  .fail
    mov  dword [rel tls13_client_finished], 0x20000014
    lea  rdi, [rel tls13_client_finished]
    mov  esi, 36
    mov  rcx, [rel tls13_tx_buf]
    mov  edx, TLS13_CT_HANDSHAKE
    call tls13_seal_client_record
    test rax, rax
    js   .fail
    mov  r13, rax
    mov  rdi, [rel tls13_tcb]
    mov  rsi, [rel tls13_tx_buf]
    mov  edx, r13d
    call tls13_send_owned
    test rax, rax
    jnz  .fail
    lea  rdi, [rel tls13_client_finished]
    mov  esi, 36
    call tls13_transcript_add
    test rax, rax
    jnz  .fail
    ; Publish ordinary certificate success only after same-attempt policy,
    ; CertificateVerify and Finished. A pinned application remains path3.
    mov byte [rel tls13_cert_verified], 0
    cmp byte [rel tls13_app_owned], 1
    je .certificate_ready
    mov byte [rel tls13_cert_verified], 1
.certificate_ready:
    mov  byte [rel tls13_established], 1
    mov  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    mov  byte [rel tls13_error], TLS13_ERR_NONE
    mov  qword [rel tls13_client_seq], 0  ; application epoch starts at sequence 0
    mov  qword [rel tls13_server_seq], 0
    xor  eax, eax
    jmp  .out
.fail:
    mov byte [rel tls13_cert_verified], 0
    mov byte [rel tls13_established], 0
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Consume a handshake byte stream.  RFC 8446 permits a message (notably the
; Certificate chain) to span records, so incomplete tails are retained until
; the next authenticated record.  No parser sees a partial message.
tls13_process_handshake_messages:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  eax, [rel tls13_hs_len]
    add  rax, r12
    cmp  rax, TLS13_HS_CAP
    ja   .fail
    mov  rdi, [rel tls13_plain_buf]
    mov  ecx, [rel tls13_hs_len]
    add  rdi, rcx
    mov  rsi, rbx
    mov  rdx, r12
    call memcpy
    add  [rel tls13_hs_len], r12d
    mov  rbx, [rel tls13_plain_buf]
    mov  r12d, [rel tls13_hs_len]
.next:
    test r12, r12
    jz   .retain
    cmp  r12, 4
    jb   .retain
    movzx eax, byte [rbx + 1]
    shl  eax, 8
    mov  al, [rbx + 2]
    shl  eax, 8
    mov  al, [rbx + 3]
    add  eax, 4
    cmp  eax, TLS13_HS_CAP
    ja   .fail
    cmp  rax, r12
    ja   .retain
    mov  r13, rax
    inc  dword [rel tls13_handshake_messages_rx]
    mov  al, [rbx]
    mov  [rel tls13_last_handshake_type], al
    cmp  byte [rel tls13_state], TLS13_ST_SERVER_HELLO
    je   .server_hello
    cmp  byte [rel tls13_state], TLS13_ST_ENC_EXT
    je   .enc_ext
    cmp  byte [rel tls13_state], TLS13_ST_CERT
    je   .certificate
    cmp  byte [rel tls13_state], TLS13_ST_CERT_VERIFY
    je   .certverify
    cmp  byte [rel tls13_state], TLS13_ST_FINISHED
    je   .finished
    cmp  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    je   .post_handshake
    jmp  .fail
.server_hello:
    mov  rdi, rbx
    mov  rsi, r13
    call tls13_parse_server_hello
    test rax, rax
    jnz  .fail
    jmp  .advance
.enc_ext:
    cmp  byte [rbx], TLS13_HS_ENC_EXT
    jne  .fail
    cmp  r13, 6
    jb   .fail
    movzx eax, byte [rbx + 4]
    shl  eax, 8
    mov  al, [rbx + 5]
    add  eax, 6
    cmp  rax, r13
    jne  .fail                          ; extension vector exactly fills message
    mov  rdi, rbx
    mov  rsi, r13
    call tls13_transcript_add
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_state], TLS13_ST_CERT
    jmp  .advance
.certificate:
    cmp  byte [rbx], TLS13_HS_CERTIFICATE
    jne  .fail
    mov  rdi, rbx
    mov  rsi, r13
    call tls13_verify_certificate_chain
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  rsi, r13
    call tls13_transcript_add
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_state], TLS13_ST_CERT_VERIFY
    jmp  .advance
.certverify:
    mov  rdi, rbx
    mov  rsi, r13
    call tls13_verify_certverify
    test rax, rax
    jnz  .fail
    mov  byte [rel tls13_state], TLS13_ST_FINISHED
    jmp  .advance
.finished:
    mov  rdi, rbx
    mov  rsi, r13
    call tls13_finish_handshake
    test rax, rax
    jnz  .fail
    jmp  .advance
.post_handshake:
    cmp  byte [rbx], 4                  ; NewSessionTicket: valid, not retained
    jne  .fail                          ; unsupported KeyUpdate stays fail-closed
.advance:
    add  rbx, r13
    sub  r12, r13
    jmp  .next
.retain:
    mov  [rel tls13_hs_len], r12d
    test r12d, r12d
    jz   .ok
    mov  rdi, [rel tls13_plain_buf]
    cmp  rbx, rdi
    je   .ok
    mov  rsi, rbx
    mov  rdx, r12
    call memcpy                         ; forward overlap is safe: dst<src
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

tls13_process_record:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    cmp  byte [rel tls13_app_peer_closed], 0
    jne  .fail
    cmp  byte [rbx], TLS13_CT_HANDSHAKE
    je   .plain
    cmp  byte [rbx], TLS13_CT_CHANGE_CIPHER
    je   .change_cipher
    cmp  byte [rbx], TLS13_CT_APPLICATION
    jne  .fail
    mov  rdi, rbx
    mov  esi, r12d
    call tls13_open_server_record
    test rax, rax
    js   .fail
    cmp  edx, TLS13_CT_ALERT
    je   .peer_close
    cmp edx, TLS13_CT_APPLICATION
    je .application
    cmp  edx, TLS13_CT_HANDSHAKE
    jne  .fail                           ; no application data before established
    mov  rsi, rax
    lea  rdi, [rbx + 5]
    call tls13_process_handshake_messages
    jmp  .out
.application:
    cmp byte [rel tls13_state], TLS13_ST_ESTABLISHED
    jne .fail
    cmp byte [rel tls13_app_owned], 1
    jne .fail
    mov rcx, [rel tls13_app_receive]
    test rcx, rcx
    jz .fail
    mov rsi, rax
    lea rdi, [rbx + 5]
    call rcx
    jmp .out
; Only an authenticated, established two-byte close_notify can
; finalize an application. NULL/0 is an explicit EOF callback event; non-null
; zero-length application records remain ordinary data. No raw FIN or local
; cancellation is closure authority. The owner/tick retains tuple cleanup.
.peer_close:
    cmp  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    jne  .fail
    cmp  byte [rel tls13_app_owned], 1
    jne  .fail
    cmp  rax, 2
    jne  .fail
    ; TLS1.3 severity is implicit in the alert description (RFC8446 section6).
    ; Legacy AlertLevel does not turn close_notify(description0) into an error.
    cmp  byte [rbx + 6], 0
    jne  .fail
    mov  rcx, [rel tls13_app_receive]
    test rcx, rcx
    jz   .fail
    mov  byte [rel tls13_app_peer_closed], 1
    xor  edi, edi
    xor  esi, esi
    call rcx
    jmp  .out
.change_cipher:
    ; RFC 8446 compatibility-mode dummy CCS: one byte 0x01, after ServerHello.
    cmp  byte [rel tls13_state], TLS13_ST_ENC_EXT
    jne  .fail
    cmp  r12d, 6
    jne  .fail
    cmp  word [rbx + 1], 0x0303
    jne  .fail
    cmp  byte [rbx + 5], 1
    jne  .fail
    xor  eax, eax
    jmp  .out
.plain:
    cmp  byte [rel tls13_state], TLS13_ST_SERVER_HELLO
    jne  .fail
    cmp  word [rbx + 1], 0x0303
    jne  .fail
    movzx eax, byte [rbx + 3]
    shl  eax, 8
    mov  al, [rbx + 4]
    lea  rdi, [rbx + 5]
    mov  rsi, rax
    call tls13_process_handshake_messages
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; TCP receive callback. It assembles TLS records across arbitrary TCP segment
; boundaries, then removes each consumed prefix before returning to the RX pump.
tls13_tcp_receive:
    push rbx
    push r12
    push r13
    cmp  rdi, [rel tls13_tcb]
    jne  .stale
    cmp  byte [rel tls13_state], TLS13_ST_SERVER_HELLO
    jb   .stale
    cmp  byte [rel tls13_state], TLS13_ST_ESTABLISHED
    ja   .stale
    mov  rbx, rsi
    mov  r12d, edx
    mov  eax, [rel tls13_rx_len]
    add  eax, r12d
    cmp  eax, TLS13_RX_CAP
    ja   .overflow
    mov  rdi, [rel tls13_rx_buf]
    mov  ecx, [rel tls13_rx_len]
    add  rdi, rcx
    mov  rsi, rbx
    mov  edx, r12d
    call memcpy
    add  [rel tls13_rx_len], r12d
.record:
    mov  eax, [rel tls13_rx_len]
    cmp  eax, TLS13_RECORD_HEADER
    jb   .ok
    mov  r13, [rel tls13_rx_buf]
    mov  rdi, r13
    mov  esi, eax
    call tls13_record_view
    cmp  eax, SAFE_BUF_TRUNCATED
    je   .ok
    test eax, eax
    jnz  .record_fail
    inc  dword [rel tls13_records_rx]
    mov  al, [r13]
    mov  [rel tls13_last_record_type], al
    add  ecx, TLS13_RECORD_HEADER
    mov  rdi, r13
    mov  esi, ecx
    push rcx
    call tls13_process_record
    pop  rcx
    test rax, rax
    jnz  .record_fail
    mov  eax, [rel tls13_rx_len]
    sub  eax, ecx
    mov  [rel tls13_rx_len], eax
    test eax, eax
    jz   .record
    mov  rdi, [rel tls13_rx_buf]
    lea  rsi, [r13 + rcx]
    mov  edx, eax
    call memcpy                         ; forward copy is overlap-safe dst<src
    jmp  .record
.stale:
    mov  eax, -1
    jmp  .out
.overflow:
    mov  edi, TLS13_ERR_OVERFLOW
    call tls13_fail
    mov  eax, -1                        ; tuple was erased; TCP must not ACK through it
    jmp  .out
.record_fail:
    mov  edi, TLS13_ERR_RECORD
    cmp  byte [rel tls13_state], TLS13_ST_SERVER_HELLO
    jne  .not_sh
    mov  edi, TLS13_ERR_SERVER_HELLO
    jmp  .record_error_ready
.not_sh:
    cmp  byte [rel tls13_state], TLS13_ST_CERT
    jne  .not_cert
    mov  edi, TLS13_ERR_CERT_CHAIN
    jmp  .record_error_ready
.not_cert:
    cmp  byte [rel tls13_state], TLS13_ST_CERT_VERIFY
    jne  .not_cv
    mov  edi, TLS13_ERR_CERT_VERIFY
    jmp  .record_error_ready
.not_cv:
    cmp  byte [rel tls13_state], TLS13_ST_FINISHED
    jne  .record_error_ready
    mov  edi, TLS13_ERR_FINISHED
.record_error_ready:
    call tls13_fail
    mov  eax, -1                        ; tuple was erased; TCP must not ACK through it
    jmp  .out
.ok:
    ; TCP consumes and ACKs a pinned service prefix only on zero.  Nonzero is
    ; retry/backpressure, so returning one here replayed the whole handshake.
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Connected callback from the active TCP seam.  The ClientHello is sent only
; after the peer's SYN|ACK has been acknowledged; no handshake-ready state is
; published merely because a TCB was allocated.
tls13_tcp_connected:
    push rbx
    mov  rbx, rdi
    cmp  rbx, [rel tls13_tcb]
    jne  .out
    cmp  byte [rel tls13_state], TLS13_ST_TCP
    jne  .out
    mov  byte [rel tls13_tcp_connected_seen], 1
    mov  byte [rel tls13_state], TLS13_ST_SERVER_HELLO
    mov  rdi, rbx
    mov  rsi, [rel tls13_tx_buf]
    mov  edx, [rel tls13_tx_len]
    call tls13_send_owned
    test rax, rax
    jz   .out
    mov  edi, TLS13_ERR_TCP
    call tls13_fail
.out:
    pop  rbx
    ret

; Parse "A.B.C.D:port SNI".  EAX=wire-layout IPv4, EDX=port, RSI=SNI,
; ECX=SNI length; EAX=-1 on malformed input.  Every field is bounded before
; publication so the live command cannot overrun the fixed handshake buffers.
tls13_parse_connect_arg:
    push rbx
    push r12
    mov  r12, rdi
    test r12, r12
    jz   .bad
    xor  ebx, ebx
    xor  r8d, r8d
.component:
    xor  eax, eax
    xor  r9d, r9d
.digit:
    movzx ecx, byte [r12]
    cmp  cl, '0'
    jb   .component_done
    cmp  cl, '9'
    ja   .component_done
    cmp  r9d, 3
    jae  .bad
    imul eax, eax, 10
    sub  ecx, '0'
    add  eax, ecx
    cmp  eax, 255
    ja   .bad
    inc  r12
    inc  r9d
    jmp  .digit
.component_done:
    test r9d, r9d
    jz   .bad
    mov  ecx, r8d
    shl  ecx, 3
    shl  eax, cl
    or   ebx, eax
    cmp  r8d, 3
    je   .port_sep
    cmp  byte [r12], '.'
    jne  .bad
    inc  r12
    inc  r8d
    jmp  .component
.port_sep:
    cmp  byte [r12], ':'
    jne  .bad
    inc  r12
    xor  edx, edx
    xor  r9d, r9d
.port_digit:
    movzx eax, byte [r12]
    cmp  al, '0'
    jb   .port_done
    cmp  al, '9'
    ja   .port_done
    cmp  r9d, 5
    jae  .bad
    imul edx, edx, 10
    sub  eax, '0'
    add  edx, eax
    cmp  edx, 65535
    ja   .bad
    inc  r12
    inc  r9d
    jmp  .port_digit
.port_done:
    test r9d, r9d
    jz   .bad
    test edx, edx
    jz   .bad
    cmp  byte [r12], ' '
    jne  .bad
    inc  r12
    mov  rsi, r12
    xor  ecx, ecx
.sni:
    movzx eax, byte [r12 + rcx]
    test al, al
    jz   .sni_done
    cmp  al, '!'
    jb   .bad
    cmp  al, '~'
    ja   .bad
    inc  ecx
    cmp  ecx, TLS13_SNI_CAP
    ja   .bad
    jmp  .sni
.sni_done:
    test ecx, ecx
    jz   .bad
    mov  eax, ebx
    jmp  .out
.bad:
    mov  eax, -1
    xor  edx, edx
    xor  esi, esi
    xor  ecx, ecx
.out:
    pop  r12
    pop  rbx
    ret

; Start one asynchronous TLS connection.  A new request fail-closes and erases
; the previous tuple before publishing the caller's fresh SNI.
tls13_connect_start:
    cmp byte [rel tls13_app_owned], 0
    jne tls13_app_busy
    jmp tls13_connect_start_owned

tls13_app_busy:
    mov eax, -1
    ret

tls13_connect_start_owned:
    ; Epochs span ordinary AND pinned starts, never reset by init/close.
    ; Rejected public app-busy requests never enter this seam.
    mov byte [rel tls13_cert_verified], 0
    mov byte [rel tls13_established], 0
    cmp qword [rel tls13_attempt_counter], -1
    je .epoch_exhausted
    inc qword [rel tls13_attempt_counter]
    mov rax, [rel tls13_attempt_counter]
    mov [rel tls13_attempt], rax
    mov qword [rel tls13_policy_utc], 0
    mov dword [rel tls13_target_ip], 0
    mov word [rel tls13_target_port], 0
    mov dword [rel tls13_sni_len], 0
    mov byte [rel tls13_sni], 0
    mov byte [rel tls13_chain_ok], 0
    mov byte [rel tls13_certverify_ok], 0
    mov byte [rel tls13_peer_finished_ok], 0
    mov byte [rel tls13_trust_path], 0
    mov qword [rel tls13_leaf_hash], 0
    mov qword [rel tls13_leaf_hash+8], 0
    mov qword [rel tls13_leaf_hash+16], 0
    mov qword [rel tls13_leaf_hash+24], 0
    mov byte [rel tls13_cert_verified], 0
    mov byte [rel tls13_policy_ok], 0
    mov dword [rel tls13_policy_reason], 0
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    call tls13_retire_transport
    test rax, rax
    jnz  .retire_busy
    call tls13_wipe_secrets
    call tls13_init
    test rax, rax
    jnz  .storage
    mov  rdi, r12
    call tls13_parse_connect_arg
    cmp  eax, -1
    je   .argument
    mov  ebx, eax
    mov  r13d, edx
    mov  r14, rsi
    mov  r12d, ecx
    lea  rdi, [rel tls13_sni]
    mov  rsi, r14
    mov  edx, r12d
    call memcpy
    lea  rax, [rel tls13_sni]
    mov  byte [rax + r12], 0
    mov  [rel tls13_sni_len], r12d
    mov  [rel tls13_target_ip], ebx
    mov  [rel tls13_target_port], r13w
    mov  byte [rel tls13_state], TLS13_ST_TCP
    mov  byte [rel tls13_error], TLS13_ERR_NONE
    mov  byte [rel tls13_established], 0
    mov  byte [rel tls13_cert_verified], 0
    mov  byte [rel tls13_chain_ok], 0
    mov  byte [rel tls13_certverify_ok], 0
    mov  byte [rel tls13_tcp_connected_seen], 0
    mov  byte [rel tls13_last_record_type], 0
    mov  byte [rel tls13_last_handshake_type], 0
    mov  byte [rel tls13_peer_finished_ok], 0
    mov  byte [rel tls13_trust_path], 0
    mov  dword [rel tls13_records_rx], 0
    mov  dword [rel tls13_handshake_messages_rx], 0
    mov  dword [rel tls13_rx_len], 0
    mov  dword [rel tls13_hs_len], 0
    mov  rdi, [rel tls13_tx_buf]
    lea  rsi, [rel tls13_sni]
    mov  edx, r12d
    call tls13_build_client_hello
    test rax, rax
    js   .argument
    mov  [rel tls13_tx_len], eax
    ; RFC 6056: the ephemeral port comes from the keep's CSPRNG, never the TSC,
    ; so an off-path peer cannot narrow the tuple. A failed draw fails closed
    ; like the ClientHello's own entropy (degraded flag, ARGUMENT).
    sub  rsp, 8
    mov  rdi, rsp
    mov  esi, 2
    call csprng_generate
    movzx edx, word [rsp]
    add  rsp, 8
    test rax, rax
    jnz  .port_entropy
    and  edx, 0x3fff
    add  edx, 49152
    mov  edi, ebx
    mov  esi, r13d
    lea  rcx, [rel tls13_tcp_connected]
    lea  r8, [rel tls13_tcp_receive]
    lea  r9, [rel tls13_tcb]
    call tcp_client_open_tracked
    test rax, rax
    jz   .route
    xor  eax, eax
    jmp  .out
.epoch_exhausted:
    mov qword [rel tls13_attempt], 0
    mov byte [rel tls13_policy_ok], 0
    mov byte [rel tls13_state], TLS13_ST_FAILED
    mov byte [rel tls13_error], TLS13_ERR_ARGUMENT
    ; Existing transport capability remains for owned retirement; never reused.
    jmp tls13_epoch_exhausted_return
.retire_busy:
    mov  byte [rel tls13_state], TLS13_ST_FAILED
    mov  byte [rel tls13_error], TLS13_ERR_TCP
    mov  byte [rel tls13_established], 0
    mov  byte [rel tls13_cert_verified], 0
    call tls13_wipe_secrets
    mov  eax, -1
    jmp  .out
.port_entropy:
    mov  byte [rel tls13_entropy_degraded], 1
.argument:
    mov  edi, TLS13_ERR_ARGUMENT
    call tls13_fail
    mov  eax, -1
    jmp  .out
.route:
    mov  edi, TLS13_ERR_ROUTE
    call tls13_fail
    mov  eax, -2
    jmp  .out
.storage:
    mov  edi, TLS13_ERR_OVERFLOW
    call tls13_fail
    mov  eax, -3
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

tls13_epoch_exhausted_return:
    call tls13_wipe_secrets
    mov eax, -1
    ret

; BSP-only read-only observation, ABI v1 exactly288B. Caller owns output buffer.
; No callback/key/raw TCP pointer is exported. Snapshot is sequential with all
; native TLS mutations on this BSP, never callable by AP/IRQ.
tls13_observe:
    cmp esi, 288
    jb .bad
    test rdi, rdi
    jz .bad
    push rbx
    mov rbx, rdi
    xor eax, eax
    mov ecx, 36
    rep stosq
    mov dword [rbx], 1
    mov dword [rbx+4], 288
    mov rax, [rel tls13_attempt]
    mov [rbx+8], rax
    mov rax, [rel tls13_policy_utc]
    mov [rbx+16], rax
    mov eax, [rel tls13_target_ip]
    mov [rbx+24], eax
    mov ax, [rel tls13_target_port]
    mov [rbx+28], ax
    mov eax, [rel tls13_sni_len]
    mov [rbx+30], ax
    mov eax, [rel tls13_policy_reason]
    mov [rbx+32], eax
    mov al, [rel tls13_state]
    mov [rbx+36], al
    mov al, [rel tls13_error]
    mov [rbx+37], al
    mov al, [rel tls13_established]
    mov [rbx+38], al
    mov al, [rel tls13_cert_verified]
    mov [rbx+39], al
    mov al, [rel tls13_chain_ok]
    mov [rbx+40], al
    mov al, [rel tls13_certverify_ok]
    mov [rbx+41], al
    mov al, [rel tls13_peer_finished_ok]
    mov [rbx+42], al
    mov al, [rel tls13_trust_path]
    mov [rbx+43], al
    mov al, [rel tls13_policy_ok]
    mov [rbx+44], al
    mov al, [rel tls13_app_owned]
    mov [rbx+45], al
    cmp qword [rel tls13_tcb], 0
    je .copy
    cmp qword [rel tls13_tcb_epoch], 0
    je .copy
    mov byte [rbx+46], 1
.copy:
    lea rdi, [rbx+48]
    lea rsi, [rel tls13_leaf_hash]
    mov ecx, 32
    rep movsb
    lea rdi, [rbx+80]
    lea rsi, [rel tls13_sni]
    mov ecx, [rel tls13_sni_len]
    cmp ecx, TLS13_SNI_CAP
    ja .invalid
    rep movsb
    xor eax, eax
    pop rbx
    ret
.invalid:
    xor eax, eax
    mov [rbx+30], ax
    mov eax, -1
    pop rbx
    ret
.bad:
    mov eax, -1
    ret

; Ordinary exact-attempt close. Wrong epoch/app owner: no writes or TCP calls.
; Busy capability is retained and authorization cleared; caller treats -2 as U.
tls13_close_attempt:
    test rdi, rdi
    jz .refused
    cmp byte [rel tls13_app_owned], 0
    jne .refused
    cmp rdi, [rel tls13_attempt]
    jne .refused
    call tls13_retire_transport
    test rax, rax
    jnz .busy
    mov edi, TLS13_ERR_NONE
    call tls13_fail
    xor eax, eax
    ret
.busy:
    mov byte [rel tls13_state], TLS13_ST_FAILED
    mov byte [rel tls13_error], TLS13_ERR_TCP
    mov byte [rel tls13_established], 0
    call tls13_wipe_secrets
    mov eax, -2
    ret
.refused:
    mov eax, -1
    ret

; Published-vector arithmetic gate.  The key-schedule inputs and outputs are
; RFC 8448 section 3; X25519 is RFC 7748 section 6.1.  The GCM case is RFC
; 8448's encrypted client Finished record.  Markers fire only after exact
; byte comparisons, and TLSKAT exposes the bytes retained by these operations.
; The boot header invokes this before the unrelated Ed25519 hostile-case suite,
; which keeps the contract's four serial markers deterministic in the QEMU
; evidence window. Clearing first makes this a fail-stop one-shot.
tls13_selftest_once:
    cmp  byte [rel tls13_selftest_pending], 0
    je   .done
    mov  byte [rel tls13_selftest_pending], 0
    call tls13_selftest
.done:
    ret

; Emit one content-bearing KAT line in wire byte order.  Missing PASS markers
; alone collapsed every crypto failure into the same symptom in Phase 6; these
; bytes let the outer serial gate distinguish HKDF, X25519, and GCM directly.
; RDI=zero-terminated prefix, RSI=bytes, EDX=count.
tls13_serial_kat_bytes:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  rdi, r12
    call serial_string
    lea  rbx, [rel tls13_kat_hex_digits]
.byte:
    test r14d, r14d
    jz   .newline
    movzx eax, byte [r13]
    mov  edx, eax
    shr  eax, 4
    movzx edi, byte [rbx + rax]
    call serial_char
    and  edx, 0x0f
    movzx edi, byte [rbx + rdx]
    call serial_char
    inc  r13
    dec  r14d
    jmp  .byte
.newline:
    call serial_newline
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

tls13_selftest:
    mov  byte [rel tls13_kat_flags], 0
    ; RFC 8448: Derive-Secret(handshake_secret,"c hs traffic",CH..SH).
    lea  rdi, [rel tls13_kat_handshake_secret]
    lea  rsi, [rel tls13_label_c_hs]
    mov  edx, 12
    lea  rcx, [rel tls13_kat_transcript_hash]
    lea  r8, [rel tls13_kat_ks_out]
    call tls13_derive_secret
    push rax
    lea  rdi, [rel tls13_kat_prefix_ks]
    lea  rsi, [rel tls13_kat_ks_out]
    mov  edx, 32
    call tls13_serial_kat_bytes
    pop  rax
    test rax, rax
    jnz  .x25519
    lea  rdi, [rel tls13_kat_ks_out]
    lea  rsi, [rel tls13_kat_traffic_secret]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .x25519
    lea  rdi, [rel tls13_kat_ks_out]
    lea  rsi, [rel tls13_kat_key_out]
    lea  rdx, [rel tls13_kat_iv_out]
    xor  ecx, ecx
    call tls13_expand_key_iv_finished
    push rax
    lea  rdi, [rel tls13_kat_prefix_key]
    lea  rsi, [rel tls13_kat_key_out]
    mov  edx, 16
    call tls13_serial_kat_bytes
    lea  rdi, [rel tls13_kat_prefix_iv]
    lea  rsi, [rel tls13_kat_iv_out]
    mov  edx, 12
    call tls13_serial_kat_bytes
    pop  rax
    test rax, rax
    jnz  .x25519
    lea  rdi, [rel tls13_kat_key_out]
    lea  rsi, [rel tls13_kat_key_expected]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .x25519
    lea  rdi, [rel tls13_kat_iv_out]
    lea  rsi, [rel tls13_kat_iv_expected]
    mov  edx, 12
    call memcmp
    test rax, rax
    jnz  .x25519
    or   byte [rel tls13_kat_flags], 1
    lea  rdi, [rel tls13_marker_keyschedule]
    call serial_string
.x25519:
    lea  rdi, [rel tls13_kat_x_out]
    lea  rsi, [rel tls13_kat_x_scalar]
    lea  rdx, [rel tls13_kat_x_peer]
    call x25519
    push rax
    lea  rdi, [rel tls13_kat_prefix_x]
    lea  rsi, [rel tls13_kat_x_out]
    mov  edx, 32
    call tls13_serial_kat_bytes
    pop  rax
    test rax, rax
    jnz  .gcm
    lea  rdi, [rel tls13_kat_x_out]
    lea  rsi, [rel tls13_kat_x_expected]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .gcm
    or   byte [rel tls13_kat_flags], 2
    lea  rdi, [rel tls13_marker_x25519]
    call serial_string
.gcm:
    lea  rax, [rel tls13_kat_aead_req]
    lea  rcx, [rel tls13_kat_key_expected]
    mov  [rax + AEAD_KEY], rcx
    lea  rcx, [rel tls13_kat_iv_expected]
    mov  [rax + AEAD_NONCE], rcx
    lea  rcx, [rel tls13_kat_gcm_aad]
    mov  [rax + AEAD_AAD], rcx
    mov  qword [rax + AEAD_AAD_LEN], 5
    lea  rcx, [rel tls13_kat_gcm_plain_expected]
    mov  [rax + AEAD_INPUT], rcx
    mov  qword [rax + AEAD_INPUT_LEN], 37
    lea  rcx, [rel tls13_kat_gcm_ct]
    mov  [rax + AEAD_OUTPUT], rcx
    lea  rcx, [rel tls13_kat_gcm_tag]
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes128_gcm_seal
    push rax
    lea  rdi, [rel tls13_kat_prefix_gcmct]
    lea  rsi, [rel tls13_kat_gcm_ct]
    mov  edx, 37
    call tls13_serial_kat_bytes
    lea  rdi, [rel tls13_kat_prefix_gcmtag]
    lea  rsi, [rel tls13_kat_gcm_tag]
    mov  edx, 16
    call tls13_serial_kat_bytes
    pop  rax
    test rax, rax
    jnz  .verdict
    lea  rdi, [rel tls13_kat_gcm_ct]
    lea  rsi, [rel tls13_kat_gcm_ct_expected]
    mov  edx, 37
    call memcmp
    test rax, rax
    jnz  .verdict
    lea  rdi, [rel tls13_kat_gcm_tag]
    lea  rsi, [rel tls13_kat_gcm_tag_expected]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .verdict
    ; Authenticate and decrypt the ciphertext too; a seal-only test can miss
    ; the fail-closed open path used on every server handshake record.
    lea  rax, [rel tls13_kat_aead_req]
    lea  rcx, [rel tls13_kat_gcm_ct]
    mov  [rax + AEAD_INPUT], rcx
    lea  rcx, [rel tls13_kat_gcm_plain]
    mov  [rax + AEAD_OUTPUT], rcx
    mov  rdi, rax
    call aes128_gcm_open
    test rax, rax
    jnz  .verdict
    lea  rdi, [rel tls13_kat_gcm_plain]
    lea  rsi, [rel tls13_kat_gcm_plain_expected]
    mov  edx, 37
    call memcmp
    test rax, rax
    jnz  .verdict
    or   byte [rel tls13_kat_flags], 4
    lea  rdi, [rel tls13_marker_record]
    call serial_string
.verdict:
    cmp  byte [rel tls13_kat_flags], 7
    jne  .fail
    lea  rdi, [rel tls13_marker_ready]
    call serial_string
    ret
.fail:
    lea  rdi, [rel tls13_marker_fail]
    call serial_string
    ret

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_tls13_1 0
align 8
; Monotonic BSP-owned observation identity, independent of reusable TCP slots.
tls13_attempt_counter: dq 0
tls13_attempt:         dq 0
tls13_policy_utc:      dq 0
tls13_leaf_hash:       times 32 db 0
; Contiguous capability pair published under TCP table lock.
tls13_tcb:              dq 0
tls13_tcb_epoch:        dq 0
tls13_client_seq:       dq 0
tls13_server_seq:       dq 0
tls13_aead_req:         times AEAD_REQ_SZ db 0
tls13_transcript:       times S256_CTX_SZ db 0
tls13_state:            db TLS13_ST_IDLE
tls13_error:            db TLS13_ERR_NONE
tls13_established:      db 0
tls13_cert_verified:    db 0
tls13_chain_ok:         db 0
tls13_policy_ok:        db 0
align 4
tls13_policy_reason:    dd 0
tls13_policy_count:     dd 0
align 8
tls13_policy_views:     times 8*2 dq 0
tls13_certverify_ok:    db 0
tls13_entropy_degraded: db 0
tls13_kat_flags:        db 0
tls13_selftest_pending: db 1
tls13_tcp_connected_seen: db 0
tls13_last_record_type: db 0
tls13_last_handshake_type: db 0
tls13_peer_finished_ok: db 0
tls13_trust_path:       db 0            ; 1=anchor presented, 2=anchor omitted
align 4
tls13_target_ip:        dd 0
tls13_sni_len:          dd 0
tls13_rx_len:           dd 0
tls13_hs_len:           dd 0
tls13_tx_len:           dd 0
tls13_records_rx:       dd 0
tls13_handshake_messages_rx: dd 0
tls13_target_port:      dw 0

align 16
tls13_zero32:           times 32 db 0
tls13_empty_hash:       db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
                        db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
tls13_basepoint:        db 9
                        times 31 db 0
tls13_client_random:    times 32 db 0
tls13_private:          times 32 db 0
tls13_public:           times 32 db 0
tls13_server_public:    times 32 db 0
tls13_shared:           times 32 db 0
tls13_early_secret:     times 32 db 0
tls13_derived_secret:   times 32 db 0
tls13_handshake_secret: times 32 db 0
tls13_master_secret:    times 32 db 0
tls13_transcript_hash:  times 32 db 0
tls13_c_hs_secret:      times 32 db 0
tls13_s_hs_secret:      times 32 db 0
tls13_c_ap_secret:      times 32 db 0
tls13_s_ap_secret:      times 32 db 0
tls13_c_finished_key:   times 32 db 0
tls13_s_finished_key:   times 32 db 0
tls13_verify_data:      times 32 db 0
tls13_c_hs_key:         times 16 db 0
tls13_s_hs_key:         times 16 db 0
tls13_c_ap_key:         times 16 db 0
tls13_s_ap_key:         times 16 db 0
tls13_c_hs_iv:          times 12 db 0
tls13_s_hs_iv:          times 12 db 0
tls13_c_ap_iv:          times 12 db 0
tls13_s_ap_iv:          times 12 db 0
tls13_nonce:            times 12 db 0
tls13_client_finished:  times 36 db 0

align 16
tls13_child_modulus:    times 512 db 0
tls13_issuer_modulus:   times 512 db 0
tls13_leaf_modulus:     times 512 db 0
tls13_child_info:       times TLS13_XI_SIZE db 0
tls13_issuer_info:      times TLS13_XI_SIZE db 0
tls13_root_hash:        times 32 db 0
tls13_cv_input:         times 130 db 0
tls13_cv_context:       db "TLS 1.3, server CertificateVerify"
tls13_anchor_isrg_root_x1:
    db 0x96,0xbc,0xec,0x06,0x26,0x49,0x76,0xf3,0x74,0x60,0x77,0x9a,0xcf,0x28,0xc5,0xa7
    db 0xcf,0xe8,0xa3,0xc0,0xaa,0xe1,0x1a,0x8f,0xfc,0xee,0x05,0xc0,0xbd,0xdf,0x08,0xc6
; RSA modulus from the same ISRG Root X1 certificate, little-endian for the
; canonical fixed-e=65537 verifier. This is the trust anchor used when the
; server correctly omits the root certificate from Certificate.certificate_list.
tls13_anchor_isrg_root_x1_modulus:
    db 0x4f,0x43,0x33,0xf5,0x64,0xbc,0xff,0x6e,0x51,0x27,0xdd,0xc6,0x3a,0x8b,0xd9,0xe6
    db 0x4e,0xad,0x88,0x70,0xe7,0x18,0xfe,0x79,0xe1,0x5d,0x27,0xd0,0x22,0xd4,0x42,0x15
    db 0xe2,0xdb,0xf7,0xff,0x28,0x0a,0x0d,0x2b,0xc8,0xde,0x64,0xf3,0x38,0xeb,0x8f,0x19
    db 0x3d,0xa5,0x6a,0x1f,0xbf,0x76,0x9a,0x76,0xdc,0x88,0x2a,0x48,0xa8,0x46,0x3b,0x86
    db 0x7c,0xa8,0xf0,0xb6,0xc2,0x1b,0xf1,0x05,0xd6,0xa1,0x41,0x03,0x83,0xa2,0x1b,0x04
    db 0x83,0xbd,0xba,0xcc,0x82,0x29,0xa3,0xa2,0x8a,0x60,0x7d,0xa6,0x98,0x3b,0x82,0xb7
    db 0x48,0x5c,0x30,0x30,0xc1,0xba,0x07,0xb4,0x36,0x71,0x5b,0xd4,0x30,0xd0,0x08,0x01
    db 0x1f,0x8e,0xe7,0x74,0xca,0xb3,0x74,0x93,0x43,0x7c,0x13,0x50,0xe0,0xea,0xc6,0xfc
    db 0x12,0x05,0x73,0x4b,0x1c,0x4a,0x7b,0x3e,0xb2,0x05,0x2f,0xd0,0x8d,0x8f,0x03,0x0b
    db 0x15,0x78,0x51,0x3e,0xed,0x59,0x78,0x05,0x12,0xa7,0x72,0x7d,0x9e,0x3b,0x86,0x6e
    db 0x51,0x3a,0xa7,0xb5,0x99,0xa1,0x46,0x1f,0x40,0x4c,0xa3,0x5a,0xa7,0x11,0xc9,0x24
    db 0xf5,0x26,0xdd,0x3e,0x59,0x3e,0x29,0x41,0x06,0xc5,0x89,0xd6,0x72,0x7f,0x9d,0x68
    db 0x5e,0x59,0xac,0xce,0xba,0x37,0x47,0x6e,0x77,0x64,0x09,0xa8,0xc1,0x98,0xd2,0x6c
    db 0x17,0x28,0x2f,0x35,0x1f,0x12,0xbd,0xd5,0xdf,0xd8,0x0f,0x0a,0x95,0x76,0x01,0xac
    db 0xe9,0x41,0xd6,0x2a,0xb4,0x05,0xdd,0x81,0xd8,0x05,0x49,0xf9,0x03,0xbc,0x9b,0x1d
    db 0xb1,0x72,0x0e,0xfb,0x9e,0x75,0x36,0x0d,0x96,0x37,0xe2,0xe7,0x95,0x08,0x36,0x8f
    db 0x98,0x07,0x02,0xe5,0xc7,0xf7,0xa8,0xf7,0xb7,0xfb,0x16,0x8e,0x10,0xd9,0xde,0x0e
    db 0xe1,0x10,0xd0,0xc5,0x26,0x2f,0x9a,0xa4,0xdb,0xe6,0x79,0x62,0x90,0x3b,0xef,0x76
    db 0x6c,0x79,0x34,0x5c,0x89,0xe1,0x81,0x98,0x5b,0x6f,0xe2,0x2e,0xec,0x71,0x63,0xf4
    db 0x94,0x07,0x87,0xac,0xde,0x51,0x61,0xa3,0x89,0x3f,0x8c,0x4a,0xb3,0x10,0xbf,0x19
    db 0xee,0xd9,0x13,0xec,0x24,0x53,0xe1,0xa0,0x29,0x03,0x8d,0x70,0x0c,0x25,0x12,0x4c
    db 0xe0,0x4a,0x7b,0xb2,0xf4,0x2e,0x77,0xb5,0xff,0xe8,0x0b,0xcf,0x7e,0x4b,0x11,0x8e
    db 0xc2,0x4f,0x16,0xeb,0xab,0x63,0xda,0xdd,0xae,0x8f,0xfa,0x3c,0x30,0xf2,0x75,0x1b
    db 0x21,0x70,0x03,0x7b,0x8d,0x38,0xd0,0x2f,0xda,0xb6,0x74,0x80,0x8c,0x57,0x49,0xd1
    db 0x2e,0x83,0x6f,0x0a,0x4f,0xae,0x38,0xe8,0x53,0x23,0x48,0x99,0x7c,0x97,0x47,0xd3
    db 0x9f,0x03,0x94,0x7e,0x99,0xb7,0x8f,0x4b,0xe2,0xae,0x80,0xe6,0xc0,0xe4,0xf3,0x06
    db 0x22,0x29,0xad,0xbf,0x70,0x3c,0x7e,0x8f,0x6c,0x66,0x66,0x4a,0x69,0x71,0x86,0x8a
    db 0xc1,0x4b,0x9a,0x21,0xf1,0x12,0xff,0xb8,0xb3,0xdf,0x79,0xdd,0xf5,0x48,0xba,0x3c
    db 0x33,0xd1,0x7e,0x21,0x9b,0x31,0xea,0xd2,0x1f,0xbf,0x6b,0x12,0x14,0xfd,0x63,0xb1
    db 0xb6,0x93,0x44,0x6c,0x86,0x68,0xde,0xdb,0x28,0x4f,0x00,0xf6,0x6e,0x6a,0xf5,0xfe
    db 0xa2,0xc2,0x75,0xf7,0x78,0xa0,0x57,0xe6,0x3c,0x6e,0x8c,0x90,0x38,0xdf,0xb7,0xdc
    db 0xbe,0x87,0x1c,0x28,0x57,0x2b,0x9e,0x9b,0xf3,0x37,0x14,0xf4,0x73,0x24,0xe8,0xad

tls13_label_derived:    db "derived"
tls13_label_c_hs:       db "c hs traffic"
tls13_label_s_hs:       db "s hs traffic"
tls13_label_c_ap:       db "c ap traffic"
tls13_label_s_ap:       db "s ap traffic"
tls13_label_key:        db "key"
tls13_label_iv:         db "iv"
tls13_label_finished:   db "finished"

align 16
tls13_sni:              times TLS13_SNI_CAP + 1 db 0
align 8
tls13_rx_buf:           dq 0
tls13_plain_buf:        dq 0
tls13_tx_buf:           dq 0
tls13_seal_plain:       times TLS13_SEAL_CAP db 0

; RFC 8448 section 3 values (simple 1-RTT handshake).
tls13_kat_handshake_secret:
    db 0x1d,0xc8,0x26,0xe9,0x36,0x06,0xaa,0x6f,0xdc,0x0a,0xad,0xc1,0x2f,0x74,0x1b,0x01
    db 0x04,0x6a,0xa6,0xb9,0x9f,0x69,0x1e,0xd2,0x21,0xa9,0xf0,0xca,0x04,0x3f,0xbe,0xac
tls13_kat_transcript_hash:
    db 0x86,0x0c,0x06,0xed,0xc0,0x78,0x58,0xee,0x8e,0x78,0xf0,0xe7,0x42,0x8c,0x58,0xed
    db 0xd6,0xb4,0x3f,0x2c,0xa3,0xe6,0xe9,0x5f,0x02,0xed,0x06,0x3c,0xf0,0xe1,0xca,0xd8
tls13_kat_traffic_secret:
    db 0xb3,0xed,0xdb,0x12,0x6e,0x06,0x7f,0x35,0xa7,0x80,0xb3,0xab,0xf4,0x5e,0x2d,0x8f
    db 0x3b,0x1a,0x95,0x07,0x38,0xf5,0x2e,0x96,0x00,0x74,0x6a,0x0e,0x27,0xa5,0x5a,0x21
tls13_kat_key_expected:
    db 0xdb,0xfa,0xa6,0x93,0xd1,0x76,0x2c,0x5b,0x66,0x6a,0xf5,0xd9,0x50,0x25,0x8d,0x01
tls13_kat_iv_expected:
    db 0x5b,0xd3,0xc7,0x1b,0x83,0x6e,0x0b,0x76,0xbb,0x73,0x26,0x5f
tls13_kat_ks_out:       times 32 db 0
tls13_kat_key_out:      times 16 db 0
tls13_kat_iv_out:       times 12 db 0

; RFC 7748 Alice scalar, Bob public key, and shared secret.
tls13_kat_x_scalar:
    db 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    db 0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
tls13_kat_x_peer:
    db 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
    db 0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
tls13_kat_x_expected:
    db 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
    db 0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
tls13_kat_x_out:        times 32 db 0

align 16
tls13_kat_gcm_aad:      db 0x17,0x03,0x03,0x00,0x35
tls13_kat_gcm_plain_expected:
    db 0x14,0x00,0x00,0x20
    db 0xa8,0xec,0x43,0x6d,0x67,0x76,0x34,0xae,0x52,0x5a,0xc1,0xfc,0xeb,0xe1,0x1a,0x03
    db 0x9e,0xc1,0x76,0x94,0xfa,0xc6,0xe9,0x85,0x27,0xb6,0x42,0xf2,0xed,0xd5,0xce,0x61
    db TLS13_CT_HANDSHAKE
tls13_kat_gcm_ct_expected:
    db 0x75,0xec,0x4d,0xc2,0x38,0xcc,0xe6,0x0b,0x29,0x80,0x44,0xa7,0x1e,0x21,0x9c,0x56
    db 0xcc,0x77,0xb0,0x51,0x7f,0xe9,0xb9,0x3c,0x7a,0x4b,0xfc,0x44,0xd8,0x7f,0x38,0xf8
    db 0x03,0x38,0xac,0x98,0xfc
tls13_kat_gcm_tag_expected:
    db 0x46,0xde,0xb3,0x84,0xbd,0x1c,0xae,0xac,0xab,0x68,0x67,0xd7,0x26,0xc4,0x05,0x46
tls13_kat_gcm_ct:       times 37 db 0
tls13_kat_gcm_tag:      times 16 db 0
tls13_kat_gcm_plain:    times 37 db 0
tls13_kat_aead_req:     times AEAD_REQ_SZ db 0

tls13_kat_prefix_ks:     db "TLS13_KAT ks=",0
tls13_kat_prefix_key:    db "TLS13_KAT key=",0
tls13_kat_prefix_iv:     db "TLS13_KAT iv=",0
tls13_kat_prefix_x:      db "TLS13_KAT x25519=",0
tls13_kat_prefix_gcmct:  db "TLS13_KAT gcmct=",0
tls13_kat_prefix_gcmtag: db "TLS13_KAT gcmtag=",0
tls13_kat_hex_digits:    db "0123456789abcdef"
tls13_marker_keyschedule: db "[PAOS64] P8 tls13: HKDF-Expand-Label key schedule KAT (RFC 8448) PASS [tls13.keyschedule.kat]",13,10,0
tls13_marker_x25519:      db "[PAOS64] P8 tls13: x25519 shared-secret KAT PASS [tls13.x25519.kat]",13,10,0
tls13_marker_record:      db "[PAOS64] P8 tls13: AES-128-GCM record KAT PASS [tls13.record.kat]",13,10,0
tls13_marker_ready:       db "[PAOS64] P8 tls13: client handshake state machine ready [tls13.handshake.ready]",13,10,0
tls13_marker_fail:        db "[PAOS64] P8 tls13: selftest FAIL",13,10,0
%endmacro
WDATA_DEFER WDATA_net_tls13_1
