;; MODULE svc/ssh
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS ssh_server_init, ssh_server_public_init, ssh_ready_timeline_tick, ssh_transport_selftest, ssh_host_fingerprint, ssh_host_fingerprint_len, ssh_hostkey_ready, ssh_kex_witness_ready, ssh_kex_witness_len, ssh_kex_witness_data, ssh_queue_gcm, ssh_queue_gcm_room, ssh_flush, ssh_string_read, ssh_b64, ssh_contexts_base, ssh_record_event, ssh_record_ready, ssh_record_connection, ssh_record_previous_bytes, ssh_record_previous_ordinal, ssh_record_rejected_bytes, ssh_record_rejected_ordinal, ssh_record_state, ssh_record_principal, ssh_record_bound, ssh_record_exec, ssh_record_auth_ok, ssh_record_nvram_writes, ssh_record_local_ip, ssh_record_remote_ip, ssh_record_local_port, ssh_record_remote_port, ssh_record_previous, ssh_record_rejected, ssh_presence_connection, ssh_presence_line, ssh_presence_prepare, ssh_presence_audited, ssh_presence_snapshot, ssh_presence_present, ssh_presence_cache, SSH_PRESENCE_CACHE_SZ
;; IMPORTS svc/command_audit, core/log, svc/ssh_auth, svc/ssh_channel, net/tcp, core/csprng, core/time, core/lib/mem, core/lib/str, core/lib/fmt, core/lib/sha256, core/lib/hkdf_sha256, core/lib/x25519, core/lib/ed25519, core/lib/aes256_gcm, data/kvstore, sec/principal, boot/serial, core/heap
;; CAPS PMCAP_NET
;; OWNER saga:ssh_server
; RFC 4253/8731/5647 transport. TCP's bounded callback pump and at most one
; idle rekey transition per owned TCB keep crypto serialized on the BSP.
; The idle table walk is bounded by TCP_TCB_N; it never interrupts a consumer.

SSH_PORT                 equ 22
SSH_CTX_N                equ TCP_TCB_N
SSH_STATE_VERSION        equ 1
SSH_STATE_KEXINIT        equ 2
SSH_STATE_ECDH           equ 3
SSH_STATE_NEWKEYS        equ 4
SSH_STATE_SERVICE        equ 5
SSH_STATE_USERAUTH       equ 6
SSH_STATE_DISCONNECT     equ 7
SSH_STATE_CLOSE_PENDING  equ 8
SSH_STATE_CLOSED         equ 9
SSH_STATE_CONNECTION     equ 10               ; 2142: userauth bound a principal
SSH_MSG_DISCONNECT       equ 1
SSH_MSG_KEXINIT          equ 20
SSH_MSG_NEWKEYS          equ 21
SSH_MSG_KEX_ECDH_INIT    equ 30
SSH_MSG_KEX_ECDH_REPLY   equ 31
SSH_MSG_SERVICE_REQUEST  equ 5
SSH_MSG_SERVICE_ACCEPT   equ 6
SSH_MSG_USERAUTH_REQUEST equ 50
SSH_MSG_USERAUTH_FAILURE equ 51
SSH_MSG_IGNORE           equ 2
SSH_MSG_UNIMPLEMENTED    equ 3
SSH_MSG_DEBUG            equ 4
SSH_MSG_USERAUTH_SUCCESS equ 52
SSH_MSG_USERAUTH_PK_OK   equ 60
SSH_MSG_GLOBAL_REQUEST   equ 80
SSH_MSG_REQUEST_FAILURE  equ 82
SSH_MSG_CHANNEL_OPEN     equ 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION equ 91
SSH_MSG_CHANNEL_OPEN_FAILURE equ 92
SSH_MSG_CHANNEL_WINDOW_ADJUST equ 93
SSH_MSG_CHANNEL_DATA     equ 94
SSH_MSG_CHANNEL_EXTENDED_DATA equ 95
SSH_MSG_CHANNEL_EOF      equ 96
SSH_MSG_CHANNEL_CLOSE    equ 97
SSH_MSG_CHANNEL_REQUEST  equ 98
SSH_MSG_CHANNEL_SUCCESS  equ 99
SSH_MSG_CHANNEL_FAILURE  equ 100
SSH_MAX_PACKET           equ 4096
SSH_HOST_BLOB_LEN        equ 51
SSH_SIG_BLOB_LEN         equ 83
SSH_ECDH_REPLY_LEN       equ 179
SSH_EXCHANGE_CAP         equ 4096
SSH_KEX_WITNESS_N        equ 10

SSH_C_TCB                equ 0
SSH_C_STATE              equ 8
SSH_C_ENC_IN             equ 9
SSH_C_ENC_OUT            equ 10
SSH_C_BANNER_SENT        equ 11
SSH_C_RX_LEN             equ 12
SSH_C_VC_LEN             equ 16
SSH_C_IC_LEN             equ 20
SSH_C_RX_PACKETS         equ 24
SSH_C_TX_PACKETS         equ 15488          ; packet sequence, separated from retry bytes at29/30
SSH_C_RETRY_PENDING      equ 29
SSH_C_RETRY_LEN          equ 30
SSH_C_VC                 equ 32
SSH_C_VC_CAP             equ 256
SSH_C_IC                 equ 288
SSH_C_IC_CAP             equ 3072
SSH_C_IS                 equ 3360
SSH_C_IS_CAP             equ 512
SSH_C_C2S_IV             equ 3872
SSH_C_S2C_IV             equ 3884
SSH_C_C2S_KEY            equ 3896
SSH_C_S2C_KEY            equ 3928
SSH_C_CLIENT_Q           equ 3960
SSH_C_SERVER_Q           equ 3992
SSH_C_SHARED             equ 4024
SSH_C_H                  equ 4056
SSH_C_SESSION_ID         equ 4088
SSH_C_RX                 equ 4128
SSH_C_RX_CAP             equ 4096
SSH_C_OUT                equ 8224
SSH_C_OUT_CAP            equ 1460
SSH_C_PLAIN              equ 9684
SSH_C_PLAIN_CAP          equ 1460
; 2142/2143 connection state. The bound principal belongs to THIS connection
; (never the global local-session principal); every exec inherits it.
SSH_C_PID                equ 11152            ; qword authenticate_bind output pid
SSH_C_CAPMASK            equ 11160            ; qword enrolled-key capability restriction
SSH_C_AUTH_FAILS         equ 11168            ; byte failed userauth requests on this connection
SSH_C_CHAN_STATE         equ 11169            ; byte SSH_CH_*
SSH_C_KEY_INDEX          equ 11170            ; byte enrolled-key slot that authenticated
SSH_C_PEER_CHAN          equ 11172            ; dword client's channel id
SSH_C_PEER_WINDOW        equ 11176            ; dword client's receive window (bytes)
SSH_C_PEER_MAXPKT        equ 11180            ; dword client's max packet
SSH_C_OUTQ_LEN           equ 11184            ; dword sealed bytes waiting for TCP
SSH_C_OUTQ               equ 11200            ; sealed RFC5647 records, FIFO
SSH_C_OUTQ_CAP           equ 4096
SSH_C_FP                 equ 15296            ; last offered user-key SHA256 fingerprint (b64, NUL)
SSH_C_FP_CAP             equ 48
SSH_C_AUTH_PUB           equ 15344            ; exact 32-byte verified enrolled public key
SSH_C_AUTH_BOUND         equ 15376            ; byte: successful signed USERAUTH captured it
; Per-connection rekey tail is heap-zeroed, never raw image zeros.
SSH_C_RK_ACTIVE          equ 15377
SSH_C_RK_FLAGS           equ 15378
SSH_C_RK_GUESS           equ 15379
SSH_C_RK_DEADLINE        equ 15384
SSH_C_RK_C2S_IV          equ 15392
SSH_C_RK_S2C_IV          equ 15404
SSH_C_RK_C2S_KEY         equ 15416
SSH_C_RK_S2C_KEY         equ 15448
SSH_C_RX_PERKEY          equ 15480
SSH_C_TX_PERKEY          equ 15484
SSH_C_RK_STARTED         equ 15496
SSH_C_RK_REPLY           equ 15504
SSH_C_RK_DEFER_LEN       equ 15684
SSH_C_RK_DEFER           equ 15688
SSH_RK_DEFER_CAP         equ 4096
; One overall accepted-connection lifetime, not a packet/KEX inactivity timer.
SSH_C_PREAUTH_LEFT       equ 19792
SSH_C_PREAUTH_LAST       equ 19800
; One admitted exec reply per existing connection; no allocation or idle timer.
SSH_C_EXEC_PHASE        equ 19808             ; 0 idle, 1 ack, 2 data, 3 status, 4 eof, 5 close
SSH_C_EXEC_USED         equ 19809             ; one command even while DATA is stalled
SSH_C_EXEC_LEN          equ 19812
SSH_C_EXEC_OFF          equ 19816
SSH_C_EXEC_STATUS       equ 19820
SSH_C_EXEC_REPLY        equ 19824
SSH_EXEC_RESPONSE_CAP   equ 1792
; Bounded wire-only observation, wiped by the original context retirement.
SSH_C_REC_SERIAL         equ 21616
SSH_C_REC_DIGEST         equ 21624
SSH_C_REC_BYTES          equ 21656
SSH_C_REC_ORD            equ 21664
SSH_CTX_SIZE             equ 21680
SSH_PREAUTH_BUDGET_US    equ 60000000
SSH_RK_SENT_KEX          equ 1
SSH_RK_HAVE_IC           equ 2
SSH_RK_HAVE_REPLY        equ 4
SSH_RK_SENT_REPLY        equ 8
SSH_RK_TX_NEW            equ 16
SSH_RK_RX_NEW            equ 32
SSH_REKEY_SOFT_LIMIT     equ 0x3fffff00 ; reserve256 old-key records for bounded in-flight/KEX
SSH_REKEY_HARD_LIMIT     equ 0x40000000 ; original conservative per-key ceiling
SSH_REKEY_TIMEOUT_US     equ 30000000
SSH_CH_NONE              equ 0
SSH_CH_OPEN              equ 1
SSH_CH_CLOSE_SENT        equ 2
SSH_CH_CLOSED            equ 3

ssh_ctx_for_tcb:
    lea  rax, [rel tcp_tcbs]
    mov  rcx, rdi
    sub  rcx, rax
    jc   .bad
    test rcx, TCP_TCB_SIZE - 1
    jnz  .bad
    shr  rcx, 7
    cmp  rcx, SSH_CTX_N
    jae  .bad
    imul rcx, rcx, SSH_CTX_SIZE
    call ssh_contexts_base
    test rax, rax
    jz   .bad
    add  rax, rcx
    ret
.bad:
    xor  eax, eax
    ret

; ssh_contexts_base -> RAX = the per-connection context table (SSH_CTX_N x SSH_CTX_SIZE, zeroed), or 0 if the heap
; refused. One kernel-heap allocation at first use (after PH_HEAP_INIT; the table used to be 245,504 zero bytes in
; the image — the Dell ESP could no longer hold a temp copy of the payload). Preserves every register except RAX.
ssh_contexts_base:
    mov  rax, [rel ssh_contexts_ptr]
    test rax, rax
    jnz  .have
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 8                             ; 16-align the kmalloc/memset calls
    mov  edi, SSH_CTX_N * SSH_CTX_SIZE
    call kmalloc
    test rax, rax
    jz   .fail
    push rax
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_N * SSH_CTX_SIZE
    call memset
    pop  rax
    mov  [rel ssh_contexts_ptr], rax
    jmp  .done
.fail:
    lea  rdi, [rel str_ssh_ctx_alloc_fail]
    call serial_string
    xor  eax, eax
.done:
    add  rsp, 8
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
.have:
    ret

ssh_be32_store:
    bswap esi
    mov  [rdi], esi
    ret

; Protocol KATs stay deterministic when QEMU intentionally has no live entropy
; provider. Production handshakes never take this branch: a live CSPRNG refusal
; still fails key generation or closes the connection.
ssh_random_fill:
    cmp  byte [rel ssh_selftest_mode], 1
    jne  csprng_generate
    mov  rcx, rsi
    mov  al, 0xa5
    rep  stosb
    xor  eax, eax
    ret

; Consume ESI bytes from the context receive prefix (overlap is forward-safe).
ssh_rx_consume:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    mov  eax, [rbx + SSH_C_RX_LEN]
    cmp  r12d, eax
    ja   .bad
    sub  eax, r12d
    mov  [rbx + SSH_C_RX_LEN], eax
    test eax, eax
    jz   .ok
    lea  rdi, [rbx + SSH_C_RX]
    lea  rsi, [rdi + r12]
    mov  edx, eax
    call memcpy
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Build an RFC4253 clear packet in context OUT. RDI=ctx, RSI=payload, EDX=len.
ssh_packet_clear_build:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    test r13d, r13d
    jz   .bad
    cmp  r13d, SSH_C_OUT_CAP - 32
    ja   .bad
    lea  eax, [r13d + 5]
    and  eax, 7
    mov  r14d, 8
    sub  r14d, eax
    cmp  r14d, 4
    jae  .pad_ok
    add  r14d, 8
.pad_ok:
    lea  eax, [r13d + r14d + 1]
    lea  rdi, [rbx + SSH_C_OUT]
    mov  esi, eax
    call ssh_be32_store
    mov  byte [rbx + SSH_C_OUT + 4], r14b
    lea  rdi, [rbx + SSH_C_OUT + 5]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  rdi, [rbx + SSH_C_OUT + 5]
    add  rdi, r13
    mov  esi, r14d
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  eax, [r13d + r14d + 5]
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx -> RAX=payload, EDX=len, 0=incomplete, -1=malformed.
ssh_packet_clear_read:
    push rbx
    mov  rbx, rdi
    mov  ecx, [rbx + SSH_C_RX_LEN]
    cmp  ecx, 4
    jb   .more
    mov  eax, [rbx + SSH_C_RX]
    bswap eax
    cmp  eax, 6
    jb   .bad
    cmp  eax, SSH_MAX_PACKET
    ja   .bad
    lea  edx, [eax + 4]
    cmp  ecx, edx
    jb   .more
    movzx ecx, byte [rbx + SSH_C_RX + 4]
    cmp  ecx, 4
    jb   .bad
    cmp  ecx, eax
    jae  .bad
    sub  eax, ecx
    dec  eax
    mov  edx, eax
    lea  rax, [rbx + SSH_C_RX + 5]
    pop  rbx
    ret
.more:
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

ssh_packet_clear_consume:
    inc  dword [rdi + SSH_C_RX_PACKETS]
    mov  eax, [rdi + SSH_C_RX]
    bswap eax
    lea  esi, [eax + 4]
    jmp  ssh_rx_consume

; Increment RFC5647's 64-bit invocation counter (last 8 nonce bytes, BE).
ssh_nonce_inc:
    mov  ecx, 11
.loop:
    inc  byte [rdi + rcx]
    jnz  .ok
    dec  ecx
    cmp  ecx, 3
    ja   .loop
    mov  eax, -1
    ret
.ok:
    xor  eax, eax
    ret

; Start before the original hard ceiling, leaving bounded old-key KEX room.
; Packet sequence counters never reset; only per-direction per-key counts do.
ssh_rekey_due:
    cmp  dword [rdi + SSH_C_RX_PERKEY], SSH_REKEY_SOFT_LIMIT
    jae  .yes
    cmp  dword [rdi + SSH_C_TX_PERKEY], SSH_REKEY_SOFT_LIMIT
    jae  .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; RFC5647: clear packet length is AAD; encrypt the rest and append a 16-byte tag.
ssh_packet_gcm_build:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    cmp  dword [rbx + SSH_C_TX_PERKEY], SSH_REKEY_HARD_LIMIT
    jae  .bad
    cmp  r13d, SSH_C_OUT_CAP - 32
    ja   .bad
    ; RFC 5647 keeps the four-byte packet_length clear as AAD.  Align only
    ; the encrypted body (padding_length + payload + padding), not AAD+body.
    lea  eax, [r13d + 1]
    and  eax, 15
    mov  r14d, 16
    sub  r14d, eax
    cmp  r14d, 4
    jae  .pad_ok
    add  r14d, 16
.pad_ok:
    lea  eax, [r13d + r14d + 21]
    cmp  eax, SSH_C_OUT_CAP
    ja   .bad
    lea  eax, [r13d + r14d + 1]
    lea  rdi, [rbx + SSH_C_OUT]
    mov  esi, eax
    call ssh_be32_store
    mov  byte [rbx + SSH_C_PLAIN], r14b
    lea  rdi, [rbx + SSH_C_PLAIN + 1]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  rdi, [rbx + SSH_C_PLAIN + 1]
    add  rdi, r13
    mov  esi, r14d
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rax, [rel ssh_aead_req]
    lea  rcx, [rbx + SSH_C_S2C_KEY]
    mov  [rax + AEAD_KEY], rcx
    lea  rcx, [rbx + SSH_C_S2C_IV]
    mov  [rax + AEAD_NONCE], rcx
    lea  rcx, [rbx + SSH_C_OUT]
    mov  [rax + AEAD_AAD], rcx
    mov  qword [rax + AEAD_AAD_LEN], 4
    lea  rcx, [rbx + SSH_C_PLAIN]
    mov  [rax + AEAD_INPUT], rcx
    lea  ecx, [r13d + r14d + 1]
    mov  [rax + AEAD_INPUT_LEN], rcx
    lea  rcx, [rbx + SSH_C_OUT + 4]
    mov  [rax + AEAD_OUTPUT], rcx
    add  rcx, [rax + AEAD_INPUT_LEN]
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes256_gcm_seal
    test eax, eax
    jnz  .bad
    lea  eax, [r13d + r14d + 21]
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_plain_scrub(RDI=ctx) — wipe the decrypted-packet / reply-staging buffer
; (SSH_C_PLAIN). Called once per processed encrypted packet, success or failure
; (w045, SSHUNLOCK_REPORT risk 5). Canonical core/lib memset.
; clobbers: RAX,RCX,RDX,RSI,RDI.
ssh_plain_scrub:
    add  rdi, SSH_C_PLAIN
    xor  esi, esi
    mov  edx, SSH_C_PLAIN_CAP
    jmp  memset

; Authenticate/decrypt and consume one RFC5647 packet.
ssh_packet_gcm_read:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    cmp  dword [rbx + SSH_C_RX_PERKEY], SSH_REKEY_HARD_LIMIT
    jae  .bad
    mov  ecx, [rbx + SSH_C_RX_LEN]
    cmp  ecx, 4
    jb   .more
    mov  r12d, [rbx + SSH_C_RX]
    bswap r12d
    cmp  r12d, 6
    jb   .bad
    cmp  r12d, SSH_MAX_PACKET
    ja   .bad
    cmp  r12d, SSH_C_PLAIN_CAP
    ja   .bad
    lea  eax, [r12d + 20]
    cmp  ecx, eax
    jb   .more
    lea  rax, [rel ssh_aead_req]
    lea  rcx, [rbx + SSH_C_C2S_KEY]
    mov  [rax + AEAD_KEY], rcx
    lea  rcx, [rbx + SSH_C_C2S_IV]
    mov  [rax + AEAD_NONCE], rcx
    lea  rcx, [rbx + SSH_C_RX]
    mov  [rax + AEAD_AAD], rcx
    mov  qword [rax + AEAD_AAD_LEN], 4
    lea  rcx, [rbx + SSH_C_RX + 4]
    mov  [rax + AEAD_INPUT], rcx
    mov  [rax + AEAD_INPUT_LEN], r12
    lea  rcx, [rbx + SSH_C_PLAIN]
    mov  [rax + AEAD_OUTPUT], rcx
    lea  rcx, [rbx + SSH_C_RX + 4]
    add  rcx, r12
    mov  [rax + AEAD_TAG], rcx
    mov  rdi, rax
    call aes256_gcm_open
    test eax, eax
    jnz  .aead_bad
    movzx ecx, byte [rbx + SSH_C_PLAIN]
    cmp  ecx, 4
    jb   .bad
    cmp  ecx, r12d
    jae  .bad
    mov  r13d, r12d
    sub  r13d, ecx
    dec  r13d
    lea  rdi, [rbx + SSH_C_C2S_IV]
    call ssh_nonce_inc
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    lea  esi, [r12d + 20]
    call ssh_record_success                 ; ciphertext only, at most16 per connection
    lea  esi, [r12d + 20]
    mov  rdi, rbx
    call ssh_rx_consume
    inc  dword [rbx + SSH_C_RX_PACKETS]
    inc  dword [rbx + SSH_C_RX_PERKEY]
    mov  edx, r13d
    lea  rax, [rbx + SSH_C_PLAIN + 1]
    pop  r13
    pop  r12
    pop  rbx
    ret
.more:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret
.aead_bad:
    mov  rdi, rbx
    lea  esi, [r12d + 20]
    call ssh_record_failure                 ; before existing scrub/retire, no new refusal
.bad:
    mov  rax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=list, ESI=len, RDX=token, ECX=token_len -> EAX=1 exact CSV member.
ssh_namelist_has:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    xor  r8d, r8d
.member:
    mov  r9d, r8d
.scan:
    cmp  r9d, r12d
    jae  .end
    cmp  byte [rbx + r9], ','
    je   .end
    inc  r9d
    jmp  .scan
.end:
    mov  eax, r9d
    sub  eax, r8d
    cmp  eax, r14d
    jne  .next
    lea  rdi, [rbx + r8]
    mov  rsi, r13
    mov  edx, r14d
    call memcmp
    test eax, eax
    jz   .yes
.next:
    cmp  r9d, r12d
    jae  .no
    lea  r8d, [r9d + 1]
    jmp  .member
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=cursor, RSI=end -> RAX=data, EDX=len, R8=next or -1.
ssh_string_read:
    ; Reject a wrapped header before dereferencing the caller cursor.
    mov  rax, rdi
    add  rax, 4
    jc   .bad
    cmp  rax, rsi
    ja   .bad
    mov  edx, [rdi]
    bswap edx
    mov  r8, rax
    add  r8, rdx
    jc   .bad
    cmp  r8, rsi
    ja   .bad
    ret
.bad:
    mov  rax, -1
    ret

; Validate the complete I_C shape before deciding negotiation. Return 0 for
; accepted, -2 for a well-formed proposal with no overlap, and -1 for malformed.
; Keeping these outcomes distinct is load-bearing: no-overlap earns an RFC4253
; key-exchange-failed refusal, while malformed traffic only fails closed.
ssh_accept_client_kexinit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    xor  r15d, r15d
    cmp  r13d, 22
    jb   .bad
    cmp  byte [r12], SSH_MSG_KEXINIT
    jne  .bad
    cmp  r13d, SSH_C_IC_CAP
    ja   .bad
    lea  r14, [r12 + r13]
    lea  rdi, [r12 + 17]
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    push r8
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel ssh_alg_kex]
    mov  ecx, ssh_alg_kex.len
    call ssh_namelist_has
    pop  rdi
    test eax, eax
    jnz  .kex_ok
    mov  r15b, 1
.kex_ok:
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    push r8
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel ssh_alg_host]
    mov  ecx, ssh_alg_host.len
    call ssh_namelist_has
    pop  rdi
    test eax, eax
    jnz  .host_ok
    mov  r15b, 1
.host_ok:
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    push r8
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel ssh_alg_cipher]
    mov  ecx, ssh_alg_cipher.len
    call ssh_namelist_has
    pop  rdi
    test eax, eax
    jnz  .c2s_cipher_ok
    mov  r15b, 1
.c2s_cipher_ok:
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    push r8
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel ssh_alg_cipher]
    mov  ecx, ssh_alg_cipher.len
    call ssh_namelist_has
    pop  rdi
    test eax, eax
    jnz  .s2c_cipher_ok
    mov  r15b, 1
.s2c_cipher_ok:
    ; AEAD ignores the negotiated MAC names, but both name-lists are still
    ; mandatory RFC4253 fields and must be structurally bounded.
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    mov  rdi, r8
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    mov  rdi, r8
    ; Compression is negotiated independently in both directions.
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    push r8
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel ssh_alg_none]
    mov  ecx, ssh_alg_none.len
    call ssh_namelist_has
    pop  rdi
    test eax, eax
    jnz  .c2s_compression_ok
    mov  r15b, 1
.c2s_compression_ok:
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    push r8
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel ssh_alg_none]
    mov  ecx, ssh_alg_none.len
    call ssh_namelist_has
    pop  rdi
    test eax, eax
    jnz  .s2c_compression_ok
    mov  r15b, 1
.s2c_compression_ok:
    ; Consume the two language name-lists and require exactly the trailing
    ; first_kex_packet_follows byte plus reserved uint32.
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    mov  rdi, r8
    mov  rsi, r14
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    lea  rax, [r8 + 5]
    cmp  rax, r14
    jne  .bad
    cmp  byte [r8], 1
    ja   .bad
    cmp  dword [r8 + 1], 0
    jne  .bad
    test r15d, r15d
    jnz  .no_overlap
    lea  rdi, [rbx + SSH_C_IC]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    mov  [rbx + SSH_C_IC_LEN], r13d
    mov  rdi, rbx
    call ssh_kex_guess_status
    xor  eax, eax
    jmp  .out
.no_overlap:
    mov  eax, -2
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_build_server_kexinit:
    push rbx
    mov  rbx, rdi
    mov  byte [rbx + SSH_C_IS], SSH_MSG_KEXINIT
    lea  rdi, [rbx + SSH_C_IS + 1]
    mov  esi, 16
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_IS + 17]
    lea  rsi, [rel ssh_kex_suffix]
    mov  edx, SSH_KEX_SUFFIX_LEN
    call memcpy
    mov  eax, SSH_KEX_PAYLOAD_LEN
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret

; Append one RFC4251 string to the bounded exchange-hash witness. Building the
; exact wire image first makes field order/length independently testable; the
; old sign-then-self-verify KAT could bless a mutually wrong transcript.
ssh_exchange_append_string:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, [rel ssh_exchange_len]
    lea  eax, [r13d + r12d + 4]
    cmp  eax, SSH_EXCHANGE_CAP
    ja   .bad
    mov  [rel ssh_exchange_len], eax
    lea  rdi, [rel ssh_exchange_buf]
    add  rdi, r13
    mov  esi, r12d
    call ssh_be32_store
    lea  rdi, [rel ssh_exchange_buf + 4]
    add  rdi, r13
    mov  rsi, rbx
    mov  edx, r12d
    call memcpy
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Append an already encoded RFC4251 value (the mpint K includes its uint32).
ssh_exchange_append_raw:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, [rel ssh_exchange_len]
    lea  eax, [r13d + r12d]
    cmp  eax, SSH_EXCHANGE_CAP
    ja   .bad
    mov  [rel ssh_exchange_len], eax
    lea  rdi, [rel ssh_exchange_buf]
    add  rdi, r13
    mov  rsi, rbx
    mov  edx, r12d
    call memcpy
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Record one public live-handshake component without exposing K. Slots 0..7
; contain SHA256(component), slot 8 contains H itself, and slot 9 contains
; SHA256(the exact signature bytes copied to the wire reply). RDI=data,
; ESI=len, EDX=slot. The read-only diagnostic projection lets the independent
; host oracle name the first divergent RFC8731 field instead of guessing.
ssh_kex_witness_hash:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    cmp  r13d, SSH_KEX_WITNESS_N
    jae  .bad
    lea  rax, [rel ssh_kex_witness_len]
    mov  [rax + r13*4], r12d
    mov  eax, r13d
    shl  eax, 5
    lea  rdi, [rel ssh_kex_witness_data]
    add  rdi, rax
    mov  rsi, rbx
    mov  edx, r12d
    call sha256_hash
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RFC 8731 deliberately interprets X25519's fixed 32-octet result as an
; unsigned *big-endian* integer before RFC 4251 mpint encoding.  This is not
; X25519's native little-endian numeric interpretation: preserve byte order,
; trim leading zero octets, and add a sign-protecting zero when bit 255 is set.
; Q_C/Q_S likewise keep their original 32 wire bytes.
ssh_build_k_mpint:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    xor  ecx, ecx
.trim:
    cmp  ecx, 32
    jae  .zero
    cmp  byte [rbx + SSH_C_SHARED + rcx], 0
    jne  .nonzero
    inc  ecx
    jmp  .trim
.nonzero:
    mov  r13d, ecx
    mov  r12d, 32
    sub  r12d, r13d
    lea  rdi, [rel ssh_k_mpint]
    test byte [rbx + SSH_C_SHARED + r13], 0x80
    jz   .plain
    lea  esi, [r12d + 1]
    call ssh_be32_store
    mov  byte [rel ssh_k_mpint + 4], 0
    lea  rdi, [rel ssh_k_mpint + 5]
    lea  rsi, [rbx + SSH_C_SHARED]
    add  rsi, r13
    mov  edx, r12d
    call memcpy
    lea  eax, [r12d + 5]
    jmp  .out
.plain:
    mov  esi, r12d
    call ssh_be32_store
    lea  rdi, [rel ssh_k_mpint + 4]
    lea  rsi, [rbx + SSH_C_SHARED]
    add  rsi, r13
    mov  edx, r12d
    call memcpy
    lea  eax, [r12d + 4]
    jmp  .out
.zero:
    lea  rdi, [rel ssh_k_mpint]
    xor  esi, esi
    call ssh_be32_store
    mov  eax, 4
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RFC8731 exchange hash: V_C,V_S,I_C,I_S,K_S,Q_C,Q_S,K.
ssh_compute_exchange_hash:
    push rbx
    push r12
    mov  rbx, rdi
    mov  dword [rel ssh_exchange_len], 0
    cmp  byte [rel ssh_selftest_mode], 1
    je   .witness_reset_done
    mov  byte [rel ssh_kex_witness_ready], 0
    lea  rdi, [rel ssh_kex_witness_len]
    xor  esi, esi
    mov  edx, SSH_KEX_WITNESS_N * 4
    call memset
.witness_reset_done:
    lea  rdi, [rbx + SSH_C_VC]
    mov  esi, [rbx + SSH_C_VC_LEN]
    cmp  byte [rel ssh_selftest_mode], 1
    je   .vc_recorded
    xor  edx, edx
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_VC]
    mov  esi, [rbx + SSH_C_VC_LEN]
.vc_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    cmp  byte [rel ssh_selftest_mode], 1
    jne  .live_vs
    lea  rdi, [rel ssh_transport_kat_version]
    mov  esi, ssh_transport_kat_version.len
    jmp  .append_vs
.live_vs:
    lea  rdi, [rel ssh_server_version]
    mov  esi, ssh_server_version.len
.append_vs:
    cmp  byte [rel ssh_selftest_mode], 1
    je   .vs_recorded
    mov  edx, 1
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_server_version]
    mov  esi, ssh_server_version.len
.vs_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_IC]
    mov  esi, [rbx + SSH_C_IC_LEN]
    cmp  byte [rel ssh_selftest_mode], 1
    je   .ic_recorded
    mov  edx, 2
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_IC]
    mov  esi, [rbx + SSH_C_IC_LEN]
.ic_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_IS]
    mov  esi, SSH_KEX_PAYLOAD_LEN
    cmp  byte [rel ssh_selftest_mode], 1
    je   .is_recorded
    mov  edx, 3
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_IS]
    mov  esi, SSH_KEX_PAYLOAD_LEN
.is_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_host_blob]
    mov  esi, SSH_HOST_BLOB_LEN
    cmp  byte [rel ssh_selftest_mode], 1
    je   .ks_recorded
    mov  edx, 4
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_host_blob]
    mov  esi, SSH_HOST_BLOB_LEN
.ks_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    mov  esi, 32
    cmp  byte [rel ssh_selftest_mode], 1
    je   .qc_recorded
    mov  edx, 5
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    mov  esi, 32
.qc_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_SERVER_Q]
    mov  esi, 32
    cmp  byte [rel ssh_selftest_mode], 1
    je   .qs_recorded
    mov  edx, 6
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_SERVER_Q]
    mov  esi, 32
.qs_recorded:
    call ssh_exchange_append_string
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    call ssh_build_k_mpint
    mov  r12d, eax
    cmp  byte [rel ssh_selftest_mode], 1
    je   .k_recorded
    lea  rdi, [rel ssh_k_mpint]
    mov  esi, r12d
    mov  edx, 7
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .out
.k_recorded:
    lea  rdi, [rel ssh_k_mpint]
    mov  esi, r12d
    call ssh_exchange_append_raw
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + SSH_C_H]
    lea  rsi, [rel ssh_exchange_buf]
    mov  edx, [rel ssh_exchange_len]
    call sha256_hash
    test eax, eax
    jnz  .out
    cmp  byte [rel ssh_selftest_mode], 1
    je   .h_recorded
    mov  dword [rel ssh_kex_witness_len + 8*4], 32
    lea  rdi, [rel ssh_kex_witness_data + 8*32]
    lea  rsi, [rbx + SSH_C_H]
    mov  edx, 32
    call memcpy
.h_recorded:
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .session_id_kept
    lea  rdi, [rbx + SSH_C_SESSION_ID]
    lea  rsi, [rbx + SSH_C_H]
    mov  edx, 32
    call memcpy
.session_id_kept:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RFC4253 section 7.2 first block: HASH(K || H || letter || session_id).
ssh_derive_one:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    lea  rdi, [rel ssh_hash_ctx]
    call sha256_stream_init
    mov  rdi, rbx
    call ssh_build_k_mpint
    lea  rdi, [rel ssh_hash_ctx]
    lea  rsi, [rel ssh_k_mpint]
    mov  edx, eax
    call sha256_stream_update
    lea  rdi, [rel ssh_hash_ctx]
    lea  rsi, [rbx + SSH_C_H]
    mov  edx, 32
    call sha256_stream_update
    mov  [rel ssh_kdf_letter], r12b
    lea  rdi, [rel ssh_hash_ctx]
    lea  rsi, [rel ssh_kdf_letter]
    mov  edx, 1
    call sha256_stream_update
    lea  rdi, [rel ssh_hash_ctx]
    lea  rsi, [rbx + SSH_C_SESSION_ID]
    mov  edx, 32
    call sha256_stream_update
    lea  rdi, [rel ssh_hash_ctx]
    mov  rsi, r13
    call sha256_stream_final
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_derive_keys:
    push rbx
    mov  rbx, rdi
    mov  esi, 'A'
    lea  rdx, [rel ssh_kdf_out]
    call ssh_derive_one
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_C2S_IV]
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    je   .c2s_iv_target
    lea  rdi, [rbx + SSH_C_RK_C2S_IV]
.c2s_iv_target:
    lea  rsi, [rel ssh_kdf_out]
    mov  edx, 12
    call memcpy
    mov  rdi, rbx
    mov  esi, 'B'
    lea  rdx, [rel ssh_kdf_out]
    call ssh_derive_one
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_S2C_IV]
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    je   .s2c_iv_target
    lea  rdi, [rbx + SSH_C_RK_S2C_IV]
.s2c_iv_target:
    lea  rsi, [rel ssh_kdf_out]
    mov  edx, 12
    call memcpy
    mov  rdi, rbx
    mov  esi, 'C'
    lea  rdx, [rbx + SSH_C_C2S_KEY]
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    je   .c2s_key_target
    lea  rdx, [rbx + SSH_C_RK_C2S_KEY]
.c2s_key_target:
    call ssh_derive_one
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    mov  esi, 'D'
    lea  rdx, [rbx + SSH_C_S2C_KEY]
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    je   .s2c_key_target
    lea  rdx, [rbx + SSH_C_RK_S2C_KEY]
.s2c_key_target:
    call ssh_derive_one
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    push rax
    call ssh_kex_scrub
    pop  rax
    pop  rbx
    ret

; ssh_kex_scrub — end of every KEX (server, client, KAT; success or failure):
;   zero the transcript statics that hold the shared secret K. With K, H and
;   every derived key follow from a capture, so none outlives the derivation
;   (SEC-pre-reset-wipe-hook G1; reset_wipe_all wipes them as well).
;   clobbers: caller-saved.
ssh_kex_scrub:
    lea  rdi, [rel ssh_k_mpint]         ; mpint(K)
    xor  esi, esi
    mov  edx, 37
    call memset
    lea  rdi, [rel ssh_exchange_buf]    ; V_C..Q_S || K
    xor  esi, esi
    mov  edx, SSH_EXCHANGE_CAP
    call memset
    mov  dword [rel ssh_exchange_len], 0
    lea  rdi, [rel ssh_hash_ctx]        ; the last HASH(K || H || letter || session_id) state
    xor  esi, esi
    mov  edx, S256_CTX_SZ
    call memset
    lea  rdi, [rel ssh_kdf_out]         ; the IV blocks' source
    xor  esi, esi
    mov  edx, 32
    call memset
    ret

ssh_make_ecdh_reply:
    push rbx
    push r12
    mov  rbx, rdi
    lea  rdi, [rel ssh_ephemeral]
    mov  esi, 32
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_SERVER_Q]
    lea  rsi, [rel ssh_ephemeral]
    lea  rdx, [rel ssh_x25519_base]
    call x25519
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_SHARED]
    lea  rsi, [rel ssh_ephemeral]
    lea  rdx, [rbx + SSH_C_CLIENT_Q]
    call x25519
    test eax, eax
    jnz  .bad
    xor  eax, eax
    xor  ecx, ecx
.zero:
    or   al, [rbx + SSH_C_SHARED + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .zero
    test al, al
    jz   .bad
    mov  rdi, rbx
    call ssh_compute_exchange_hash
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_seed]
    mov  esi, 32
    lea  rdx, [rbx + SSH_C_H]
    mov  ecx, 32
    lea  r8, [rel ssh_signature]
    mov  r9d, 64
    call ed25519_sign
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_public]
    mov  esi, 32
    lea  rdx, [rbx + SSH_C_H]
    mov  ecx, 32
    lea  r8, [rel ssh_signature]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ssh_derive_keys
    test eax, eax
    jnz  .bad
    lea  r12, [rel ssh_reply_payload]
    mov  byte [r12], SSH_MSG_KEX_ECDH_REPLY
    lea  rdi, [r12 + 1]
    mov  esi, SSH_HOST_BLOB_LEN
    call ssh_be32_store
    lea  rdi, [r12 + 5]
    lea  rsi, [rel ssh_host_blob]
    mov  edx, SSH_HOST_BLOB_LEN
    call memcpy
    lea  rdi, [r12 + 5 + SSH_HOST_BLOB_LEN]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [r12 + 9 + SSH_HOST_BLOB_LEN]
    lea  rsi, [rbx + SSH_C_SERVER_Q]
    mov  edx, 32
    call memcpy
    lea  rdi, [r12 + 41 + SSH_HOST_BLOB_LEN]
    mov  esi, SSH_SIG_BLOB_LEN
    call ssh_be32_store
    lea  rdi, [r12 + 45 + SSH_HOST_BLOB_LEN]
    mov  esi, ssh_alg_host.len
    call ssh_be32_store
    lea  rdi, [r12 + 49 + SSH_HOST_BLOB_LEN]
    lea  rsi, [rel ssh_alg_host]
    mov  edx, ssh_alg_host.len
    call memcpy
    lea  rdi, [r12 + 49 + SSH_HOST_BLOB_LEN + ssh_alg_host.len]
    mov  esi, 64
    call ssh_be32_store
    lea  rdi, [r12 + 53 + SSH_HOST_BLOB_LEN + ssh_alg_host.len]
    lea  rsi, [rel ssh_signature]
    mov  edx, 64
    call memcpy
    cmp  byte [rel ssh_selftest_mode], 1
    je   .witness_done
    lea  rdi, [r12 + 53 + SSH_HOST_BLOB_LEN + ssh_alg_host.len]
    mov  esi, 64
    mov  edx, 9
    call ssh_kex_witness_hash
    test eax, eax
    jnz  .bad
    mov  byte [rel ssh_kex_witness_ready], 1
.witness_done:
    mov  eax, SSH_ECDH_REPLY_LEN
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rdi, [rel ssh_ephemeral]
    xor  esi, esi
    mov  edx, 32
    push rax
    call memset
    pop  rax
    pop  r12
    pop  rbx
    ret

ssh_send_clear:
    push rbx
    mov  rbx, rdi
    call ssh_packet_clear_build
    test eax, eax
    js   .out
    mov  edx, eax
    mov  rdi, [rbx + SSH_C_TCB]
    lea  rsi, [rbx + SSH_C_OUT]
    call tcp_send
    test eax, eax
    jnz  .out
    inc  dword [rbx + SSH_C_TX_PACKETS]
.out:
    pop  rbx
    ret

; RFC 4253 section 4.2 permits either side to speak first, and standard scanners
; wait for the server identification. Reserve exactly one banner through the
; public TCP seam. tcp_poll owns emission; its queued-flight sentinel prevents
; a later handshake ACK from retiring these bytes before they reach the NIC.
ssh_send_banner:
    push rbx
    mov  rbx, rdi
    cmp  byte [rbx + SSH_C_BANNER_SENT], 1
    je   .already
    mov  rdi, [rbx + SSH_C_TCB]
    lea  rsi, [rel ssh_server_banner]
    mov  edx, ssh_server_banner.len
    call tcp_send
    test eax, eax
    jnz  .out
    mov  byte [rbx + SSH_C_BANNER_SENT], 1
    xor  eax, eax
    jmp  .out
.already:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Once V_C is present, send I_S as the next independently paced SSH packet.
ssh_send_kexinit:
    push rbx
    mov  rbx, rdi
    call ssh_build_server_kexinit
    test eax, eax
    js   .out
    mov  edx, eax
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_IS]
    call ssh_send_clear
.out:
    pop  rbx
    ret

ssh_send_gcm:
    push rbx
    mov  rbx, rdi
    call ssh_packet_gcm_build
    test eax, eax
    js   .out
    mov  edx, eax
    mov  rdi, [rbx + SSH_C_TCB]
    lea  rsi, [rbx + SSH_C_OUT]
    call tcp_send
    test eax, eax
    jnz  .out
    ; Commit nonce/counter only after TCP accepted the exact ciphertext. A
    ; backpressured send can then be retried or closed without nonce skew.
    lea  rdi, [rbx + SSH_C_S2C_IV]
    call ssh_nonce_inc
    test eax, eax
    jnz  .out
    inc  dword [rbx + SSH_C_TX_PACKETS]
    inc  dword [rbx + SSH_C_TX_PERKEY]
.out:
    pop  rbx
    ret

; ssh_queue_gcm_room(RDI=ctx, EDX=payload length) -> EAX 1 fits / 0 wait.
; Exact GCM record geometry, before touching PLAIN, entropy or AEAD. The
; serialized service owns OUTQ until enqueue; queue pressure cannot reseal a
; record with the same nonce or advance a response/credit frontier.
ssh_queue_gcm_room:
    lea  eax, [rdx + 1]
    and  eax, 15
    mov  ecx, 16
    sub  ecx, eax
    cmp  ecx, 4
    jae  .padding
    add  ecx, 16
.padding:
    lea  eax, [rdx + rcx + 21]
    add  eax, [rdi + SSH_C_OUTQ_LEN]
    jc   .wait
    cmp  eax, SSH_C_OUTQ_CAP
    seta al
    xor  al, 1
    movzx eax, al
    ret
.wait:
    xor  eax, eax
    ret

; ssh_queue_gcm(RDI=ctx, RSI=payload, EDX=len) -> EAX 0 / -1.
; Seal one RFC5647 record and append it to OUTQ. The nonce/counter commit at
; seal time: every queued record is either delivered in order or the
; connection closes, so there is no skew between records and wire order.
ssh_queue_gcm:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    test edx, edx
    jz   .bad
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    je   .seal
    movzx eax, byte [rsi]
    cmp  eax, 20
    jb   .generic
    cmp  eax, 49
    ja   .bad
    jmp  .seal
.generic:
    cmp  eax, SSH_MSG_DISCONNECT
    jb   .bad
    cmp  eax, SSH_MSG_DEBUG
    ja   .bad
.seal:
    call ssh_packet_gcm_build
    test eax, eax
    js   .bad
    mov  r12d, eax
    mov  r13d, [rbx + SSH_C_OUTQ_LEN]
    lea  eax, [r13d + r12d]
    cmp  eax, SSH_C_OUTQ_CAP
    ja   .bad
    lea  rdi, [rbx + SSH_C_OUTQ]
    add  rdi, r13
    lea  rsi, [rbx + SSH_C_OUT]
    mov  edx, r12d
    call memcpy
    add  [rbx + SSH_C_OUTQ_LEN], r12d
    lea  rdi, [rbx + SSH_C_S2C_IV]
    call ssh_nonce_inc
    test eax, eax
    jnz  .bad
    inc  dword [rbx + SSH_C_TX_PACKETS]
    inc  dword [rbx + SSH_C_TX_PERKEY]
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_flush(RDI=ctx) -> EAX 0 drained, 2 still pending, -1 closed/error.
; Hands at most one MSS/window-bounded chunk to TCP (one flight per TCB).
ssh_flush:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, [rbx + SSH_C_OUTQ_LEN]
    test r12d, r12d
    jz   .drained
    mov  rdi, [rbx + SSH_C_TCB]
    test rdi, rdi
    jz   .bad
    cmp  dword [rdi + TCB_TX_LEN], 0
    jne  .pending
    movzx eax, word [rdi + TCB_PEER_WINDOW]
    test eax, eax
    jz   .pending
    cmp  r12d, TCP_WIRE_MAX_PAYLOAD
    jbe  .mss_ok
    mov  r12d, TCP_WIRE_MAX_PAYLOAD
.mss_ok:
    cmp  r12d, eax
    jbe  .window_ok
    mov  r12d, eax
.window_ok:
    lea  rsi, [rbx + SSH_C_OUTQ]
    mov  edx, r12d
    call tcp_send
    test rax, rax
    jnz  .pending
    mov  r13d, [rbx + SSH_C_OUTQ_LEN]
    sub  r13d, r12d
    mov  [rbx + SSH_C_OUTQ_LEN], r13d
    jz   .queue_tail
    lea  rdi, [rbx + SSH_C_OUTQ]
    lea  rsi, [rdi + r12]
    mov  edx, r13d
    call memcpy                            ; forward overlap-safe (rep movsb)
.queue_tail:
    lea  rdi, [rbx + SSH_C_OUTQ]
    add  rdi, r13
    xor  esi, esi
    mov  edx, r12d
    call memset                            ; no duplicate retired ciphertext tail
    test r13d, r13d
    jz   .drained
.pending:
    mov  eax, 2
    jmp  .out
.drained:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RFC4253 7.1: only a wrong guessed method/host-key packet is ignored once.
; Full shape, boolean and reserved word were already checked by canonical parser.
ssh_kex_guess_status:
    push rbx
    mov  rbx, rdi
    mov  byte [rbx + SSH_C_RK_GUESS], 0
    mov  eax, [rbx + SSH_C_IC_LEN]
    lea  rdx, [rbx + SSH_C_IC]
    cmp  byte [rdx + rax - 5], 1
    jne  .out
    lea  rdi, [rdx + 21]
    lea  rsi, [rel ssh_alg_kex]
    mov  ecx, ssh_alg_kex.len
    cld
    repe cmpsb
    jne  .wrong
    mov  eax, [rdx + 17]
    bswap eax
    cmp  eax, ssh_alg_kex.len
    jb   .wrong
    je   .host
    cmp  byte [rdi], ','
    jne  .wrong
.host:
    lea  rdx, [rdx + rax + 21]
    mov  eax, [rdx]
    bswap eax
    cmp  eax, ssh_alg_host.len
    jb   .wrong
    lea  rdi, [rdx + 4]
    lea  rsi, [rel ssh_alg_host]
    mov  ecx, ssh_alg_host.len
    repe cmpsb
    jne  .wrong
    cmp  eax, ssh_alg_host.len
    je   .out
    cmp  byte [rdi], ','
    je   .out
.wrong:
    mov  byte [rbx + SSH_C_RK_GUESS], 1
.out:
    pop  rbx
    ret

; RDI=ctx, RSI=authenticated peer KEXINIT or0 for local initiation, EDX=len.
; No transport/key/auth/channel state is reset. IS and deadline are made once.
ssh_rekey_begin:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .bad
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    mov  [rbx + SSH_C_RK_STARTED], rax
    add  rax, SSH_REKEY_TIMEOUT_US
    jc   .bad
    mov  [rbx + SSH_C_RK_DEADLINE], rax
    mov  byte [rbx + SSH_C_RK_ACTIVE], 1
    mov  byte [rbx + SSH_C_RK_FLAGS], 0
    mov  byte [rbx + SSH_C_RK_GUESS], 0
    test r12, r12
    jz   .build
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, r13d
    call ssh_accept_client_kexinit
    test eax, eax
    jnz  .bad
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_IC
.build:
    mov  rdi, rbx
    call ssh_build_server_kexinit
    test eax, eax
    js   .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Stage/queue at most the three finite server KEX records. Queue capacity is
; checked before sealing, so backpressure never re-derives/re-signs/reseals.
; A direction commits only after its old-key NEWKEYS is irrevocably queued.
ssh_rekey_step:
    push rbx
    mov  rbx, rdi
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    je   .ok
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    cmp  rax, [rbx + SSH_C_RK_STARTED]
    jb   .bad
    cmp  rax, [rbx + SSH_C_RK_DEADLINE]
    jae  .bad
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_SENT_KEX
    jnz  .reply
    cmp  dword [rbx + SSH_C_OUTQ_LEN], SSH_C_OUTQ_CAP - SSH_KEX_PAYLOAD_LEN - 52
    ja   .ok
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_IS]
    mov  edx, SSH_KEX_PAYLOAD_LEN
    call ssh_queue_gcm
    test eax, eax
    jnz  .bad
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_SENT_KEX
.reply:
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_REPLY
    jz   .ok
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_SENT_REPLY
    jnz  .newkeys
    cmp  dword [rbx + SSH_C_OUTQ_LEN], SSH_C_OUTQ_CAP - SSH_ECDH_REPLY_LEN - 52
    ja   .ok
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_RK_REPLY]
    mov  edx, SSH_ECDH_REPLY_LEN
    call ssh_queue_gcm
    test eax, eax
    jnz  .bad
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_SENT_REPLY
    lea  rdi, [rbx + SSH_C_RK_REPLY]
    xor  esi, esi
    mov  edx, SSH_ECDH_REPLY_LEN
    call memset
.newkeys:
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_TX_NEW
    jnz  .finish
    cmp  dword [rbx + SSH_C_OUTQ_LEN], SSH_C_OUTQ_CAP - 52
    ja   .ok
    mov  byte [rel ssh_onebyte_payload], SSH_MSG_NEWKEYS
    mov  rdi, rbx
    lea  rsi, [rel ssh_onebyte_payload]
    mov  edx, 1
    call ssh_queue_gcm                    ; old S2C key/nonce, immutable FIFO ciphertext
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_S2C_IV]
    lea  rsi, [rbx + SSH_C_RK_S2C_IV]
    mov  edx, 12
    call memcpy
    lea  rdi, [rbx + SSH_C_S2C_KEY]
    lea  rsi, [rbx + SSH_C_RK_S2C_KEY]
    mov  edx, 32
    call memcpy
    lea  rdi, [rbx + SSH_C_RK_S2C_IV]
    xor  esi, esi
    mov  edx, 12
    call memset
    lea  rdi, [rbx + SSH_C_RK_S2C_KEY]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  dword [rbx + SSH_C_TX_PERKEY], 0  ; sequence is deliberately untouched
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_TX_NEW
.finish:
    movzx eax, byte [rbx + SSH_C_RK_FLAGS]
    and  eax, SSH_RK_TX_NEW | SSH_RK_RX_NEW
    cmp  eax, SSH_RK_TX_NEW | SSH_RK_RX_NEW
    jne  .ok
    mov  byte [rbx + SSH_C_RK_ACTIVE], 0
    mov  byte [rbx + SSH_C_RK_FLAGS], 0
    mov  byte [rbx + SSH_C_RK_GUESS], 0
    mov  qword [rbx + SSH_C_RK_DEADLINE], 0
    mov  qword [rbx + SSH_C_RK_STARTED], 0
    lea  rdi, [rbx + SSH_C_IS]
    xor  esi, esi
    mov  edx, SSH_C_IS_CAP
    call memset                       ; eager peer may have completed before IS was queued
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rbx
    ret

; Authenticated payload during rekey. Accept ordinary in-flight packets before
; peer IC, or after its NEWKEYS, into a bounded private FIFO, never dispatching
; authority/channel actions until both directions have handed off.
ssh_rekey_packet:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    test r13d, r13d
    jz   .bad
    movzx eax, byte [r12]
    cmp  eax, SSH_MSG_KEXINIT
    je   .ic
    cmp  eax, SSH_MSG_NEWKEYS
    je   .newkeys
    cmp  eax, SSH_MSG_KEX_ECDH_INIT
    je   .ecdh
    cmp  eax, SSH_MSG_DISCONNECT
    je   .bad
    cmp  eax, SSH_MSG_IGNORE
    je   .ignore
    cmp  eax, SSH_MSG_DEBUG
    je   .debug
    cmp  eax, SSH_MSG_UNIMPLEMENTED
    je   .unimplemented
    cmp  eax, 30
    jb   .ordinary
    cmp  eax, 49
    ja   .ordinary
    cmp  byte [rbx + SSH_C_RK_GUESS], 1
    jne  .bad
    jmp  .guess_skip
.ordinary:
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_IC
    jz   .defer
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_RX_NEW
    jz   .bad
.defer:
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, r13d
    call ssh_rekey_defer_push
    jmp  .out
.ic:
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_IC
    jnz  .bad                         ; duplicate/simultaneous reply is never another exchange
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, r13d
    call ssh_accept_client_kexinit
    test eax, eax
    jnz  .bad
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_IC
    jmp  .ok
.ecdh:
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_IC
    jz   .bad
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_REPLY
    jnz  .bad
    cmp  byte [rbx + SSH_C_RK_GUESS], 1
    je   .guess_skip
    cmp  r13d, 37
    jne  .bad
    cmp  dword [r12 + 1], 0x20000000
    jne  .bad
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    lea  rsi, [r12 + 5]
    mov  edx, 32
    call memcpy
    mov  rdi, rbx
    call ssh_make_ecdh_reply          ; derives only staging slots while active
    test eax, eax
    js   .bad
    lea  rdi, [rbx + SSH_C_RK_REPLY]
    lea  rsi, [rel ssh_reply_payload]
    mov  edx, SSH_ECDH_REPLY_LEN
    call memcpy
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_HAVE_REPLY
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    xor  esi, esi
    mov  edx, SSH_C_SESSION_ID - SSH_C_CLIENT_Q ; Q_C,Q_S,K,H, not sessionID
    call memset
    lea  rdi, [rbx + SSH_C_IC]
    xor  esi, esi
    mov  edx, SSH_C_IC_CAP
    call memset
    lea  rdi, [rbx + SSH_C_IS]
    xor  esi, esi
    mov  edx, SSH_C_IS_CAP
    ; IS cannot be scrubbed until its exact record was queued (eager guess).
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_SENT_KEX
    jz   .keep_is
    call memset
.keep_is:
    call ssh_rekey_scratch_scrub
    jmp  .ok
.guess_skip:
    mov  byte [rbx + SSH_C_RK_GUESS], 0
    jmp  .ok
.newkeys:
    cmp  r13d, 1
    jne  .bad
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_SENT_REPLY
    jz   .bad
    test byte [rbx + SSH_C_RK_FLAGS], SSH_RK_RX_NEW
    jnz  .bad
    lea  rdi, [rbx + SSH_C_C2S_IV]
    lea  rsi, [rbx + SSH_C_RK_C2S_IV]
    mov  edx, 12
    call memcpy
    lea  rdi, [rbx + SSH_C_C2S_KEY]
    lea  rsi, [rbx + SSH_C_RK_C2S_KEY]
    mov  edx, 32
    call memcpy
    lea  rdi, [rbx + SSH_C_RK_C2S_IV]
    xor  esi, esi
    mov  edx, 12
    call memset
    lea  rdi, [rbx + SSH_C_RK_C2S_KEY]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  dword [rbx + SSH_C_RX_PERKEY], 0
    or   byte [rbx + SSH_C_RK_FLAGS], SSH_RK_RX_NEW
    jmp  .ok
.ignore:
    ; SSH_MSG_IGNORE: one bounded string, no trailing bytes.
    cmp  r13d, 5
    jb   .bad
    mov  eax, [r12 + 1]
    bswap eax
    add  rax, 5
    cmp  rax, r13
    jne  .bad
    jmp  .ok
.unimplemented:
    cmp  r13d, 5
    jne  .bad
    jmp  .ok
.debug:
    cmp  r13d, 10
    jb   .bad
    cmp  byte [r12 + 1], 1
    ja   .bad
    lea  rdi, [r12 + 2]
    lea  rsi, [r12 + r13]
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    mov  rdi, r8
    lea  rsi, [r12 + r13]
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    lea  rax, [r12 + r13]
    cmp  r8, rax
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_rekey_defer_push:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    test r13d, r13d
    jz   .bad
    cmp  r13d, SSH_C_PLAIN_CAP - 1
    ja   .bad
    mov  eax, [rbx + SSH_C_RK_DEFER_LEN]
    cmp  eax, SSH_RK_DEFER_CAP
    ja   .bad
    lea  ecx, [eax + r13d + 4]
    cmp  ecx, SSH_RK_DEFER_CAP
    ja   .bad
    lea  rdi, [rbx + SSH_C_RK_DEFER + rax]
    mov  [rdi], r13d                   ; private native-endian bounded FIFO length
    add  rdi, 4
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  eax, [r13d + 4]
    add  [rbx + SSH_C_RK_DEFER_LEN], eax
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_rekey_defer_pop:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, [rbx + SSH_C_RK_DEFER_LEN]
    cmp  r12d, SSH_RK_DEFER_CAP
    ja   .bad
    cmp  r12d, 4
    jb   .bad
    mov  r13d, [rbx + SSH_C_RK_DEFER]
    test r13d, r13d
    jz   .bad
    cmp  r13d, SSH_C_PLAIN_CAP - 1
    ja   .bad
    lea  eax, [r13d + 4]
    cmp  eax, r12d
    ja   .bad
    sub  r12d, eax
    lea  rdi, [rbx + SSH_C_PLAIN + 1]
    lea  rsi, [rbx + SSH_C_RK_DEFER + 4]
    mov  edx, r13d
    call memcpy
    lea  rdi, [rbx + SSH_C_RK_DEFER]
    lea  rsi, [rdi + r13 + 4]
    mov  edx, r12d
    call memcpy
    lea  rdi, [rbx + SSH_C_RK_DEFER + r12]
    xor  esi, esi
    lea  edx, [r13d + 4]
    call memset
    mov  [rbx + SSH_C_RK_DEFER_LEN], r12d
    lea  rax, [rbx + SSH_C_PLAIN + 1]
    mov  edx, r13d
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_rekey_scratch_scrub:
    sub  rsp, 8
    call ssh_kex_scrub
    lea  rdi, [rel ssh_signature]
    xor  esi, esi
    mov  edx, 64
    call memset
    lea  rdi, [rel ssh_reply_payload]
    xor  esi, esi
    mov  edx, SSH_ECDH_REPLY_LEN
    call memset
    lea  rdi, [rel ssh_ephemeral]
    xor  esi, esi
    mov  edx, 32
    call memset
    add  rsp, 8
    ret

; ssh_connection_retire(RDI=ctx, ESI=1 drain / 0 terminal).
; The serialized SSH/TCP service owns ctx; no active handler is interrupted.
; Drain retains only TCB, close state and the exact bounded sealed OUTQ. TCP
; owns any already accepted flight independently. Everything else (including
; keys, IVs, transcript, auth identity, RX and plaintext staging) is revoked.
; Terminal retirement retains only TCB + CLOSED until slot reuse. Shared host
; credentials/KEX scratch and other connections are never touched here.
ssh_connection_retire:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    test esi, esi
    jz   .terminal
    mov  r12d, [rbx + SSH_C_OUTQ_LEN]
    cmp  r12d, SSH_C_OUTQ_CAP
    jbe  .drain
    xor  r12d, r12d                        ; invalid extent cannot be drained
    mov  dword [rbx + SSH_C_OUTQ_LEN], 0
.drain:
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSE_PENDING
    lea  rdi, [rbx + SSH_C_STATE + 1]
    xor  esi, esi
    mov  edx, SSH_C_OUTQ_LEN - SSH_C_STATE - 1
    call memset
    lea  rdi, [rbx + SSH_C_OUTQ_LEN + 4]
    xor  esi, esi
    mov  edx, SSH_C_OUTQ - SSH_C_OUTQ_LEN - 4
    call memset
    lea  rdi, [rbx + SSH_C_OUTQ]
    add  rdi, r12
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE - SSH_C_OUTQ
    sub  edx, r12d
    call memset
    jmp  .out
.terminal:
    mov  r12, [rbx + SSH_C_TCB]
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    mov  [rbx + SSH_C_TCB], r12
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSED
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

ssh_fail_close:
    push rbx
    mov  rbx, rdi
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSED
    je   .closed
    mov  esi, 1
    call ssh_connection_retire              ; revoke before waiting for any ACK
    mov  rdi, [rbx + SSH_C_TCB]
    test rdi, rdi
    jz   .terminal
    cmp  byte [rdi + TCB_STATE], TCP_ESTABLISHED
    jne  .terminal                         ; reset/EOF/FIN/reap owns TCP teardown
    mov  rdi, rbx
    call ssh_flush                         ; drain sealed reply/exit/close in order
    test eax, eax
    js   .terminal
    jnz  .retry
.close_tcp:
    mov  rdi, [rbx + SSH_C_TCB]
    cmp  dword [rdi + TCB_TX_LEN], 0
    jne  .retry
    call tcp_close
    test eax, eax
    jz   .terminal
    mov  rdi, [rbx + SSH_C_TCB]
    cmp  byte [rdi + TCB_STATE], TCP_ESTABLISHED
    je   .retry                            ; lock refusal: retry without authority
    ; A failed FIN transmission can still have entered FIN_WAIT_1. TCP's own
    ; retry timer now owns the FIN; SSH must not retain secrets for that timer.
.terminal:
    mov  rdi, rbx
    xor  esi, esi
    call ssh_connection_retire
.closed:
    mov  eax, -1
    jmp  .out
.retry:
    mov  eax, 2
.out:
    pop  rbx
    ret

; Parse only the RFC4253 identification prefix, not the whole buffered TCP
; stream.  An eager peer may coalesce V_C and I_C while our server banner is
; still in flight.  RDI=buffer, ESI=aggregate bytes.  Returns EAX=1 complete,
; 0 incomplete, -1 overlong, -2 malformed; EDX=LF offset and R8D=V_C length
; excluding an optional CR when complete.
ssh_version_prefix_read:
    test esi, esi
    jz   .incomplete
    mov  ecx, esi
    cmp  ecx, SSH_C_VC_CAP
    jbe  .bounded
    mov  ecx, SSH_C_VC_CAP
.bounded:
    xor  edx, edx
.scan:
    cmp  edx, ecx
    jae  .no_lf
    cmp  byte [rdi + rdx], 10
    je   .found
    inc  edx
    jmp  .scan
.no_lf:
    cmp  esi, SSH_C_VC_CAP
    jae  .overlong
.incomplete:
    xor  eax, eax
    ret
.found:
    cmp  edx, 8
    jb   .malformed
    cmp  dword [rdi], 'SSH-'
    jne  .malformed
    cmp  dword [rdi + 4], '2.0-'
    jne  .malformed
    mov  r8d, edx
    cmp  byte [rdi + rdx - 1], 13
    jne  .complete
    dec  r8d
.complete:
    mov  eax, 1
    ret
.overlong:
    mov  eax, -1
    ret
.malformed:
    mov  eax, -2
    ret

; Advance buffered input without waiting. Returns 1 progress, 0 incomplete,
; 2 when the same TCP prefix must be retried after the current flight drains,
; or -1 after TCP close started. Eight transitions maximum per callback.
ssh_process_one:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    call ssh_preauth_check
    test eax, eax
    jnz  .bad
    movzx eax, byte [rbx + SSH_C_STATE]
    cmp  eax, SSH_STATE_VERSION
    je   .version
    cmp  eax, SSH_STATE_KEXINIT
    je   .kexinit
    cmp  eax, SSH_STATE_ECDH
    je   .ecdh
    cmp  eax, SSH_STATE_NEWKEYS
    je   .newkeys
    cmp  eax, SSH_STATE_SERVICE
    je   .encrypted
    cmp  eax, SSH_STATE_USERAUTH
    je   .encrypted
    cmp  eax, SSH_STATE_CONNECTION
    je   .encrypted
    cmp  eax, SSH_STATE_DISCONNECT
    je   .disconnect
    cmp  eax, SSH_STATE_CLOSE_PENDING
    je   .close_pending
    jmp  .bad
.version:
    lea  rdi, [rbx + SSH_C_RX]
    mov  esi, [rbx + SSH_C_RX_LEN]
    call ssh_version_prefix_read
    test eax, eax
    jz   .wait
    js   .bad
    mov  r13d, r8d
    lea  rdi, [rbx + SSH_C_VC]
    lea  rsi, [rbx + SSH_C_RX]
    mov  edx, r13d
    call memcpy
    mov  [rbx + SSH_C_VC_LEN], r13d
    mov  rdi, rbx
    call ssh_send_kexinit
    test eax, eax
    jnz  .bad
    mov  esi, [rbx + SSH_C_VC_LEN]
    cmp  byte [rbx + SSH_C_RX + rsi], 13
    jne  .only_lf
    add  esi, 2
    jmp  .consume_banner
.only_lf:
    inc  esi
.consume_banner:
    mov  rdi, rbx
    call ssh_rx_consume
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_KEXINIT
    mov  eax, 1
    jmp  .out
.kexinit:
    ; I_S is a separate paced flight. An eager peer can coalesce V_C and I_C;
    ; retain that TCP prefix until I_S was actually emitted and acknowledged.
    mov  rdi, [rbx + SSH_C_TCB]
    cmp  dword [rdi + TCB_TX_LEN], 0
    jne  .retry
    mov  rdi, rbx
    call ssh_packet_clear_read
    test rax, rax
    jz   .wait
    js   .bad
    mov  r12, rax
    mov  r13d, edx
    mov  rdi, rbx
    mov  rsi, r12
    call ssh_accept_client_kexinit
    cmp  eax, -2
    je   .no_overlap
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ssh_packet_clear_consume
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_ECDH
    mov  eax, 1
    jmp  .out
.no_overlap:
    mov  rdi, rbx
    call ssh_packet_clear_consume
    mov  rdi, rbx
    lea  rsi, [rel ssh_kex_disconnect]
    mov  edx, SSH_KEX_DISCONNECT_LEN
    call ssh_send_clear
    test eax, eax
    jnz  .bad
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_DISCONNECT
    mov  rdi, rbx
    call ssh_fail_close                     ; scrub now; TCP still owns refusal ACK
    jmp  .out
.disconnect:
    ; Retirement keeps TCP's accepted refusal flight until its ACK, then FIN.
.close_pending:
    mov  rdi, rbx
    call ssh_fail_close
    jmp  .out
.ecdh:
    mov  rdi, rbx
    call ssh_packet_clear_read
    test rax, rax
    jz   .wait
    js   .bad
    cmp  byte [rbx + SSH_C_RK_GUESS], 0
    je   .initial_guess_done
    cmp  byte [rax], 30
    jb   .bad
    cmp  byte [rax], 49
    ja   .bad
    mov  byte [rbx + SSH_C_RK_GUESS], 0
    mov  rdi, rbx
    call ssh_packet_clear_consume
    mov  eax, 1
    jmp  .out
.initial_guess_done:
    cmp  edx, 37
    jne  .bad
    cmp  byte [rax], SSH_MSG_KEX_ECDH_INIT
    jne  .bad
    cmp  dword [rax + 1], 0x20000000
    jne  .bad
    push rax
    mov  rdi, [rbx + SSH_C_TCB]
    mov  esi, 3                         ; complete ECDH_INIT validated, pre-crypto
    xor  edx, edx
    call tcp_ssh_trace_event
    pop  rax
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    lea  rsi, [rax + 5]
    mov  edx, 32
    call memcpy
    mov  rdi, rbx
    call ssh_packet_clear_consume
    mov  rdi, rbx
    call ssh_make_ecdh_reply
    test eax, eax
    js   .bad
    push rax
    mov  rdi, [rbx + SSH_C_TCB]
    mov  esi, 4                         ; X25519/signature/derivation complete
    xor  edx, edx
    call tcp_ssh_trace_event
    pop  rax
    mov  edx, eax
    mov  rdi, rbx
    lea  rsi, [rel ssh_reply_payload]
    call ssh_send_clear
    test eax, eax
    jnz  .bad
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_NEWKEYS
    mov  eax, 1
    jmp  .out
.newkeys:
    mov  rdi, rbx
    call ssh_packet_clear_read
    test rax, rax
    jz   .wait
    js   .bad
    cmp  edx, 1
    jne  .bad
    cmp  byte [rax], SSH_MSG_NEWKEYS
    jne  .bad
    mov  rdi, rbx
    call ssh_packet_clear_consume
    mov  byte [rel ssh_onebyte_payload], SSH_MSG_NEWKEYS
    mov  rdi, rbx
    lea  rsi, [rel ssh_onebyte_payload]
    mov  edx, 1
    call ssh_send_clear
    test eax, eax
    jnz  .bad
    mov  byte [rbx + SSH_C_ENC_IN], 1
    mov  byte [rbx + SSH_C_ENC_OUT], 1
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_SERVICE
    mov  byte [rel ssh_live_newkeys], 1
    mov  eax, 1
    jmp  .out
.encrypted:
    mov  rdi, rbx
    call ssh_flush
    test eax, eax
    js   .bad
    mov  r13d, eax                       ; remember ordinary-output backpressure
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .rekey_progress
    mov  rdi, rbx
    call ssh_rekey_due
    test eax, eax
    jz   .not_due
    mov  rdi, rbx
    xor  esi, esi
    xor  edx, edx
    call ssh_rekey_begin
    test eax, eax
    jnz  .bad
.rekey_progress:
    mov  rdi, rbx
    call ssh_rekey_step
    test eax, eax
    jnz  .bad
.not_due:
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .read_encrypted
    test r13d, r13d
    jnz  .read_encrypted                ; only queue authenticated in-flight data
    cmp  dword [rbx + SSH_C_RK_DEFER_LEN], 0
    je   .read_encrypted
    mov  rdi, rbx
    call ssh_rekey_defer_pop
    test rax, rax
    js   .bad
    jmp  .encrypted_payload
.read_encrypted:
    mov  rdi, rbx
    call ssh_packet_gcm_read
    test rax, rax
    jz   .encrypted_wait
    js   .bad
    test edx, edx
    jz   .bad
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .rekey_packet
    cmp  byte [rax], SSH_MSG_KEXINIT
    je   .peer_rekey
    cmp  byte [rax], SSH_MSG_NEWKEYS
    je   .bad
    cmp  byte [rax], 30
    jb   .ordinary
    cmp  byte [rax], 49
    jbe  .bad
.ordinary:
    test r13d, r13d
    jnz  .defer_packet
.encrypted_payload:
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_SERVICE
    jne  .userauth
    cmp  byte [rax], SSH_MSG_SERVICE_REQUEST
    jne  .bad
    cmp  edx, SSH_SERVICE_REQ_LEN
    jne  .bad
    lea  rdi, [rax + 1]
    lea  rsi, [rel ssh_service_req_tail]
    mov  edx, SSH_SERVICE_REQ_LEN - 1
    call memcmp
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    lea  rsi, [rel ssh_service_accept]
    mov  edx, SSH_SERVICE_ACCEPT_LEN
    call ssh_queue_gcm
    test eax, eax
    jnz  .bad
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_USERAUTH
    jmp  .flush_progress
.userauth:
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_USERAUTH
    jne  .connection
    ; RFC 4252: ssh_auth parses/verifies and queues exactly one reply. Only
    ; a verified ssh-ed25519 signature over THIS session id binds a principal.
    mov  rdi, rbx
    mov  rsi, rax
    call ssh_userauth_packet
    test eax, eax
    jnz  .bad
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CONNECTION
    jne  .flush_progress
    ; Only signed USERAUTH binding enters CONNECTION. Channel/rekey work has
    ; no preauth timer, including when time later becomes unavailable.
    mov  qword [rbx + SSH_C_PREAUTH_LEFT], 0
    mov  qword [rbx + SSH_C_PREAUTH_LAST], 0
    jmp  .flush_progress
.connection:
    ; RFC 4254 connection layer; reachable only after USERAUTH_SUCCESS.
    mov  rdi, rbx
    mov  rsi, rax
    call ssh_connection_packet
    test eax, eax
    jnz  .bad
    jmp  .flush_progress
.peer_rekey:
    mov  rsi, rax
    mov  rdi, rbx
    call ssh_rekey_begin
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ssh_rekey_step
    test eax, eax
    jnz  .bad
    jmp  .flush_progress
.rekey_packet:
    mov  rsi, rax
    mov  rdi, rbx
    call ssh_rekey_packet
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ssh_rekey_step
    test eax, eax
    jnz  .bad
    jmp  .flush_progress
.defer_packet:
    mov  rsi, rax
    mov  rdi, rbx
    call ssh_rekey_defer_push
    test eax, eax
    jnz  .bad
    jmp  .flush_progress
.encrypted_wait:
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .retry                        ; timer/ACK service owns further progress
    test r13d, r13d
    jnz  .retry
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CONNECTION
    jne  .wait
    mov  rdi, rbx
    call ssh_exec_response_step            ; no input needed after queue/credit resumes
    test eax, eax
    js   .bad
    jnz  .flush_progress
    ; A blocked response may already have sealed bytes awaiting TCP space.
    mov  rdi, rbx
    call ssh_flush
    test eax, eax
    js   .bad
    jmp  .wait
.flush_progress:
    ; w045 secret hygiene: the packet (and every reply sealed through the same
    ; PLAIN staging) is fully consumed; an exec line may carry a credential.
    mov  rdi, rbx
    call ssh_plain_scrub
    mov  rdi, rbx
    call ssh_flush
    test eax, eax
    js   .bad
    mov  eax, 1
    jmp  .out
.wait:
    xor  eax, eax
    jmp  .out
.retry:
    mov  eax, 2
    jmp  .out
.bad:
    call ssh_rekey_scratch_scrub
    mov  rdi, rbx
    call ssh_plain_scrub                   ; refused/garbled packets too
    mov  rdi, rbx
    call ssh_fail_close
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx -> EAX=0 live/not preauth, -1 retire. Only strictly forward
; calibrated samples consume the bounded remaining budget. Repeated samples
; earn nothing. Zero/backward time refuses preauth work (no invented elapsed
; time or finite wall deadline without a clock). Never rearms at transitions.
ssh_preauth_check:
    movzx eax, byte [rdi + SSH_C_STATE]
    cmp  eax, SSH_STATE_VERSION
    jb   .ok
    cmp  eax, SSH_STATE_USERAUTH
    ja   .ok
    push rbx
    mov  rbx, rdi
    call time_monotonic_now_us
    test rax, rax
    jz   .refuse
    mov  rcx, [rbx + SSH_C_PREAUTH_LAST]
    test rcx, rcx
    jz   .refuse
    cmp  rax, rcx
    jb   .refuse
    mov  [rbx + SSH_C_PREAUTH_LAST], rax
    sub  rax, rcx
    cmp  rax, [rbx + SSH_C_PREAUTH_LEFT]
    jae  .refuse
    sub  [rbx + SSH_C_PREAUTH_LEFT], rax
    pop  rbx
.ok:
    xor  eax, eax
    ret
.refuse:
    pop  rbx
    mov  eax, -1
    ret

ssh_accept_cb:
    push rbx
    push r12
    mov  rbx, rdi
    call ssh_ctx_for_tcb
    test rax, rax
    jz   .out
    mov  r12, rax
    ; TCP zeroes RECV_CB when it claims a new tuple. A duplicate accept for
    ; the still-owned tuple must not reset a budget or resurrect retirement.
    cmp  [r12 + SSH_C_TCB], rbx
    jne  .fresh
    lea  rcx, [rel ssh_receive_cb]
    cmp  [rbx + TCB_RECV_CB], rcx
    je   .out
.fresh:
    mov  rdi, rax
    xor  esi, esi
    call ssh_connection_retire              ; canonical terminal wipe on reuse
    mov  rax, r12
    mov  [rax + SSH_C_TCB], rbx
    mov  byte [rax + SSH_C_STATE], SSH_STATE_VERSION
    ; Peter 87337: SSH is off until an owner key is enrolled. TCP has already
    ; completed; no SSH byte leaves, and an empty or unreadable store counts 0.
    call ssh_keystore_count
    test eax, eax
    jz   .refuse
    mov  rdi, r12
    call ssh_record_accept
    mov  rdi, rbx
    mov  esi, 1                         ; admitted native SSH connection
    movzx edx, word [rbx + TCB_REMOTE_PORT]
    mov  rcx, [r12 + SSH_C_REC_SERIAL]
    call tcp_ssh_trace_event
    lea  rcx, [rel ssh_receive_cb]
    mov  [rbx + TCB_RECV_CB], rcx
    call time_monotonic_now_us
    test rax, rax
    jz   .refuse                           ; no unbounded preauth admission
    mov  qword [r12 + SSH_C_PREAUTH_LEFT], SSH_PREAUTH_BUDGET_US
    mov  [r12 + SSH_C_PREAUTH_LAST], rax
    mov  rdi, r12
    call ssh_send_banner
    test eax, eax
    jz   .out
.refuse:
    mov  rdi, r12
    call ssh_fail_close
.out:
    pop  r12
    pop  rbx
    ret

; TCP service ABI: RDI=TCB, RSI=bytes, EDX=len -> 0 consume / -1 retry.
ssh_receive_cb:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14d, edx
    call ssh_ctx_for_tcb
    test rax, rax
    jz   .consume
    mov  rbx, rax
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSED
    je   .consume
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSE_PENDING
    je   .close                            ; never append/dispatch after revocation
    mov  rdi, rbx
    call ssh_preauth_check
    test eax, eax
    jnz  .close                            ; revoke before appending a late prefix
    cmp  byte [rbx + SSH_C_RETRY_PENDING], 1
    jne  .append
    movzx eax, word [rbx + SSH_C_RETRY_LEN]
    cmp  eax, r13d
    ja   .short_retry
    mov  byte [rbx + SSH_C_RETRY_PENDING], 0
    mov  word [rbx + SSH_C_RETRY_LEN], 0
    add  r12, rax
    sub  r13d, eax
    jz   .pump_start
    jmp  .append
.short_retry:
    ; TCP may offer a smaller retained prefix after the peer window shrinks.
    ; These bytes already belong to private RX/OUTQ: consume that prefix once,
    ; retain the remaining skip count, and never append/decrypt/dispatch twice.
    sub  eax, r13d
    mov  [rbx + SSH_C_RETRY_LEN], ax
    jmp  .consume
.append:
    mov  eax, [rbx + SSH_C_RX_LEN]
    cmp  eax, SSH_C_RX_CAP
    ja   .close
    cmp  r13d, SSH_C_RX_CAP
    ja   .close
    lea  ecx, [eax + r13d]
    cmp  ecx, SSH_C_RX_CAP
    ja   .close
    mov  [rbx + SSH_C_RX_LEN], ecx
    lea  rdi, [rbx + SSH_C_RX]
    add  rdi, rax
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
.pump_start:
    mov  r12d, 8
.pump:
    mov  rdi, rbx
    call ssh_process_one
    cmp  eax, 2
    je   .retry
    test eax, eax
    js   .consume
    jz   .post_pump
    dec  r12d
    jnz  .pump
    ; Budget spent with input possibly still buffered: ask TCP to call back.
    jmp  .retry
.post_pump:
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 1
    je   .consume                        ; private RX owns bytes; bounded idle rekey tick owns TX
    ; A queued reply larger than one TCP flight keeps the callback prefix
    ; pinned, so TCP re-invokes us after the ACK and OUTQ keeps draining.
    cmp  dword [rbx + SSH_C_OUTQ_LEN], 0
    jne  .retry
    jmp  .consume
.close:
    mov  rdi, rbx
    call ssh_fail_close
    cmp  eax, 2
    je   .retry
.consume:
    xor  eax, eax
    jmp  .out
.retry:
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSE_PENDING
    je   .retry_return                     ; closing never consumes another prefix
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 1
    je   .consume                          ; do not pin old prefix ahead of the peer's next KEX record
    ; TCP's callback contract retains the exact pinned prefix on -1. Mark it so
    ; the next callback processes our private remainder without appending the
    ; same prefix twice. Record the whole pinned TCP prefix: a later retry may
    ; include fresh client bytes after it, and only that suffix is appended.
    mov  byte [rbx + SSH_C_RETRY_PENDING], 1
    mov  [rbx + SSH_C_RETRY_LEN], r14w
.retry_return:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded wire observation. It never drives TCP/SSH, hashes plaintext, exports
; keys/nonces, changes a security decision or retries a packet. Limit applies
; across rekey (the original connection RX sequence), not the per-key counter.
; Sequence exhaustion disables telemetry only; product lifetime is unchanged.
ssh_record_accept:
    cmp  qword [rel ssh_record_serial], -1
    je   .out
    inc  qword [rel ssh_record_serial]
    mov  rax, [rel ssh_record_serial]
    mov  [rdi + SSH_C_REC_SERIAL], rax
.out:
    ret

; RDI=ctx, ESI=complete encrypted record size including length/AAD/tag.
ssh_record_success:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    cmp  qword [rbx + SSH_C_REC_SERIAL], 0
    je   .out
    cmp  dword [rbx + SSH_C_RX_PACKETS], 16
    jae  .out
    lea  rdi, [rbx + SSH_C_REC_DIGEST]
    lea  rsi, [rbx + SSH_C_RX]
    mov  edx, r12d
    call sha256_hash
    test eax, eax
    jnz  .unavailable
    mov  [rbx + SSH_C_REC_BYTES], r12
    mov  eax, [rbx + SSH_C_RX_PACKETS]
    mov  [rbx + SSH_C_REC_ORD], rax
    jmp  .out
.unavailable:
    mov  qword [rbx + SSH_C_REC_BYTES], 0
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Only actual AES-GCM authentication failure reaches here. Cache is global
; last-event, intentionally conservative: an unrelated later failure replaces
; it, so the raw consumer cannot invent the missing original observation.
ssh_record_failure:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    cmp  qword [rbx + SSH_C_REC_SERIAL], 0
    je   .out
    cmp  dword [rbx + SSH_C_RX_PACKETS], 16
    jae  .out
    cmp  qword [rel ssh_record_event], -1
    je   .out
    ; Publish0 first so no partial/hash-failed cache is an event.
    mov  qword [rel ssh_record_ready], 0
    lea  rdi, [rel ssh_record_rejected]
    lea  rsi, [rbx + SSH_C_RX]
    mov  edx, r12d
    call sha256_hash
    test eax, eax
    jnz  .out
    lea  rdi, [rel ssh_record_previous]
    lea  rsi, [rbx + SSH_C_REC_DIGEST]
    mov  edx, 32
    call memcpy
    mov  rax, [rbx + SSH_C_REC_SERIAL]
    mov  [rel ssh_record_connection], rax
    mov  rax, [rbx + SSH_C_REC_BYTES]
    mov  [rel ssh_record_previous_bytes], rax
    mov  rax, [rbx + SSH_C_REC_ORD]
    mov  [rel ssh_record_previous_ordinal], rax
    mov  [rel ssh_record_rejected_bytes], r12
    mov  eax, [rbx + SSH_C_RX_PACKETS]
    mov  [rel ssh_record_rejected_ordinal], rax
    movzx eax, byte [rbx + SSH_C_STATE]
    mov  [rel ssh_record_state], rax
    mov  rax, [rbx + SSH_C_PID]
    mov  [rel ssh_record_principal], rax
    movzx eax, byte [rbx + SSH_C_AUTH_BOUND]
    mov  [rel ssh_record_bound], rax
    mov  rax, [rel ssh_exec_count]
    mov  [rel ssh_record_exec], rax
    mov  rax, [rel ssh_auth_ok_count]
    mov  [rel ssh_record_auth_ok], rax
    mov  rax, [rel ssh_keys_nvram_writes]
    mov  [rel ssh_record_nvram_writes], rax
    mov  r13, [rbx + SSH_C_TCB]
    test r13, r13
    jz   .out
    mov  eax, [r13 + TCB_LOCAL_IP]
    mov  [rel ssh_record_local_ip], rax
    mov  eax, [r13 + TCB_REMOTE_IP]
    mov  [rel ssh_record_remote_ip], rax
    movzx eax, word [r13 + TCB_LOCAL_PORT]
    mov  [rel ssh_record_local_port], rax
    movzx eax, word [r13 + TCB_REMOTE_PORT]
    mov  [rel ssh_record_remote_port], rax
    inc  qword [rel ssh_record_event]
    mov  qword [rel ssh_record_ready], 1       ; publication last
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Base64 without '=' for OpenSSH's SHA256 fingerprint display.
ssh_fingerprint_build:
    push rbx
    push r12
    push r13
    lea  rdi, [rel ssh_host_digest]
    lea  rsi, [rel ssh_host_blob]
    mov  edx, SSH_HOST_BLOB_LEN
    call sha256_hash
    test eax, eax
    jnz  .bad
    lea  rbx, [rel ssh_host_digest]
    lea  r12, [rel ssh_host_fingerprint]
    lea  r13, [rel ssh_b64]
    xor  ecx, ecx
.triplet:
    cmp  ecx, 30
    jae  .tail
    movzx eax, byte [rbx + rcx]
    movzx edx, byte [rbx + rcx + 1]
    movzx r8d, byte [rbx + rcx + 2]
    mov  r9d, eax
    shr  r9d, 2
    mov  r9b, [r13 + r9]
    mov  [r12], r9b
    and  eax, 3
    shl  eax, 4
    mov  r9d, edx
    shr  r9d, 4
    or   eax, r9d
    mov  al, [r13 + rax]
    mov  [r12 + 1], al
    and  edx, 15
    shl  edx, 2
    mov  eax, r8d
    shr  eax, 6
    or   edx, eax
    mov  dl, [r13 + rdx]
    mov  [r12 + 2], dl
    and  r8d, 63
    mov  al, [r13 + r8]
    mov  [r12 + 3], al
    add  ecx, 3
    add  r12, 4
    jmp  .triplet
.tail:
    movzx eax, byte [rbx + 30]
    movzx edx, byte [rbx + 31]
    mov  ecx, eax
    shr  ecx, 2
    mov  cl, [r13 + rcx]
    mov  [r12], cl
    and  eax, 3
    shl  eax, 4
    mov  ecx, edx
    shr  ecx, 4
    or   eax, ecx
    mov  al, [r13 + rax]
    mov  [r12 + 1], al
    and  edx, 15
    shl  edx, 2
    mov  dl, [r13 + rdx]
    mov  [r12 + 2], dl
    mov  byte [r12 + 3], 0
    mov  dword [rel ssh_host_fingerprint_len], 43
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_hostkey_init:
    push rbx
    ; The host key identifies this machine before any human authenticates. The
    ; interactive principal is intentionally NULL while Session Shell is locked.
    ; Accept that locked state (and the legacy OWNER bootstrap state), use the
    ; machine-held SYSTEM credential only around a domain-separated derivation,
    ; then restore the exact incoming state before exposing the listener. The
    ; old single-slot DATA-backed host key could be overwritten by an ordinary
    ; owner write (or evict owner DATA on first boot). A deterministic key from
    ; the separately persisted machine secret survives both cases without a
    ; DATA write. This is a one-time host-key migration: clients must verify
    ; the new SSHHOSTKEY fingerprint, never auto-accept a changed TOFU pin.
    ; No system credential crosses this module or grants ambient OWNER power.
    call principal_current
    mov  rbx, rax
    test rax, rax
    jz   .enter_system
    cmp  rax, PRIN_OWNER
    jne  .bad_unbound
.enter_system:
    ; Public sync calls this from every poll. The key is fixed for the boot, so
    ; derive and print its marker once; reset_wipe and the KAT clear ready.
    cmp  byte [rel ssh_hostkey_ready], 1
    je   .held
    call principal_enter_system
    call principal_system_auth_credential
    test rax, rax
    jz   .bad
    cmp  edx, 32
    jne  .bad
    mov  rdi, rax
    mov  rsi, rdx
    xor  edx, edx                        ; RFC 5869 zero-salt extract
    xor  ecx, ecx
    lea  r8, [rel ssh_hostkey_derive_info]
    mov  r9d, ssh_hostkey_derive_info.len
    sub  rsp, 16
    lea  rax, [rel ssh_host_seed]
    mov  [rsp], rax
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    add  rsp, 16
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_seed]
    mov  esi, 32
    lea  rdx, [rel ssh_host_public]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_blob]
    mov  esi, ssh_alg_host.len
    call ssh_be32_store
    lea  rdi, [rel ssh_host_blob + 4]
    lea  rsi, [rel ssh_alg_host]
    mov  edx, ssh_alg_host.len
    call memcpy
    lea  rdi, [rel ssh_host_blob + 4 + ssh_alg_host.len]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_host_blob + 8 + ssh_alg_host.len]
    lea  rsi, [rel ssh_host_public]
    mov  edx, 32
    call memcpy
    call ssh_fingerprint_build
    test eax, eax
    jnz  .bad
    mov  byte [rel ssh_hostkey_ready], 1
    lea  rdi, [rel str_ssh_hostkey_marker]
    call serial_string
    xor  eax, eax
    jmp  .restore
.bad:
    mov  byte [rel ssh_hostkey_ready], 0
    lea  rdi, [rel ssh_host_seed]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
    jmp  .restore
.held:
    xor  eax, eax
    pop  rbx
    ret
.bad_unbound:
    mov  eax, -1
.restore:
    push rax
    cmp  rbx, PRIN_OWNER
    je   .restore_owner
    test rbx, rbx
    jnz  .restored                       ; rejected state was never transitioned
    call principal_clear_bound
    jmp  .restored
.restore_owner:
    call principal_leave_system
.restored:
    pop  rax
    pop  rbx
    ret

; Boot KAT: shipped X25519 -> SHA-256 exchange digest -> Ed25519 signature,
; then the exact RFC5647 clear-length/AAD geometry.
ssh_transport_selftest:
    cmp  byte [rel ssh_selftest_done], 1
    je   .already
    push rbx
    mov  byte [rel ssh_selftest_mode], 1
    call ssh_contexts_base
    mov  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset

    ; A valid short identification followed by already-buffered packet bytes
    ; must be judged by its LF boundary, not by the aggregate callback size.
    lea  rdi, [rbx + SSH_C_RX]
    mov  esi, 0x5a
    mov  edx, 300
    call memset
    lea  rdi, [rbx + SSH_C_RX]
    lea  rsi, [rel ssh_transport_kat_version]
    mov  edx, ssh_transport_kat_version.len
    call memcpy
    mov  byte [rbx + SSH_C_RX + ssh_transport_kat_version.len], 13
    mov  byte [rbx + SSH_C_RX + ssh_transport_kat_version.len + 1], 10
    lea  rdi, [rbx + SSH_C_RX]
    mov  esi, 300
    call ssh_version_prefix_read
    cmp  eax, 1
    jne  .bad
    cmp  edx, ssh_transport_kat_version.len + 1
    jne  .bad
    cmp  r8d, ssh_transport_kat_version.len
    jne  .bad
    cmp  byte [rbx + SSH_C_RX + ssh_transport_kat_version.len + 2], 0x5a
    jne  .bad
    ; The same cap still rejects a genuinely unterminated 256-byte line.
    lea  rdi, [rbx + SSH_C_RX]
    mov  esi, 'A'
    mov  edx, SSH_C_VC_CAP
    call memset
    lea  rdi, [rbx + SSH_C_RX]
    mov  esi, SSH_C_VC_CAP
    call ssh_version_prefix_read
    cmp  eax, -1
    jne  .bad
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset

    ; No-overlap is a semantic outcome only after the whole KEXINIT shape is
    ; proven valid. It must not be collapsed into malformed input.
    mov  rdi, rbx
    lea  rsi, [rel ssh_transport_kat_no_overlap]
    mov  edx, SSH_TRANSPORT_KAT_NO_OVERLAP_LEN
    call ssh_accept_client_kexinit
    cmp  eax, -2
    jne  .bad
    cmp  dword [rbx + SSH_C_IC_LEN], 0
    jne  .bad
    mov  rdi, rbx
    lea  rsi, [rel ssh_transport_kat_no_overlap]
    mov  edx, 21
    call ssh_accept_client_kexinit
    cmp  eax, -1
    jne  .bad

    %if PAOS_PUBLIC_BUILD
%define SSH_TRANSPORT_KAT_TCB ssh_transport_kat_tcb
%else
%define SSH_TRANSPORT_KAT_TCB tcp_canary_tcb
%endif
; A coalesced I_C cannot advance while the separately paced I_S flight is
    ; queued or emitted. Returning 2 binds the callback retry contract that
    ; preserves the client prefix until TCP retires I_S by a real ACK.
    ; This synthetic connection reaches the same preauth guard as a live
    ; accepted peer. Give it a real clock baseline and the normal bounded
    ; budget; a missing clock must still fail the KAT and listener admission.
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    mov  [rbx + SSH_C_PREAUTH_LAST], rax
    mov  qword [rbx + SSH_C_PREAUTH_LEFT], SSH_PREAUTH_BUDGET_US
    lea  rax, [rel SSH_TRANSPORT_KAT_TCB]
    mov  [rbx + SSH_C_TCB], rax
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_KEXINIT
    mov  dword [rel SSH_TRANSPORT_KAT_TCB + TCB_TX_LEN], 1
    mov  rdi, rbx
    call ssh_process_one
    cmp  eax, 2
    jne  .bad_canary
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_KEXINIT
    jne  .bad_canary
    mov  dword [rel SSH_TRANSPORT_KAT_TCB + TCB_TX_LEN], 0
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    jmp  .kex_order_ok
.bad_canary:
    mov  dword [rel SSH_TRANSPORT_KAT_TCB + TCB_TX_LEN], 0
    jmp  .bad
.kex_order_ok:

    ; Exercise the exact 32-byte owned-store geometry already proven by the
    ; KV header/envelope/WAL KAT, without mutating QEMU media.  The live init
    ; below still requires a real read-back or verified commit before it binds.
    cmp  byte [rel kv_m_header], 1
    jne  .bad
    cmp  byte [rel kv_m_durable], 1
    jne  .bad
    cmp  byte [rel kv_m_atrest], 1
    jne  .bad
    lea  rdi, [rel ssh_host_seed]
    lea  rsi, [rel ssh_transport_kat_host_seed]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel ssh_host_seed]
    mov  esi, 32
    lea  rdx, [rel ssh_host_public]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_public]
    lea  rsi, [rel ssh_transport_kat_host_public]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_blob]
    mov  esi, ssh_alg_host.len
    call ssh_be32_store
    lea  rdi, [rel ssh_host_blob + 4]
    lea  rsi, [rel ssh_alg_host]
    mov  edx, ssh_alg_host.len
    call memcpy
    lea  rdi, [rel ssh_host_blob + 4 + ssh_alg_host.len]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_host_blob + 8 + ssh_alg_host.len]
    lea  rsi, [rel ssh_host_public]
    mov  edx, 32
    call memcpy
    call ssh_fingerprint_build
    test eax, eax
    jnz  .bad
    lea  rdi, [rel str_ssh_hostkey_marker]
    call serial_string

    lea  rdi, [rel ssh_ephemeral]
    lea  rsi, [rel ssh_transport_kat_x_scalar]
    lea  rdx, [rel ssh_x25519_base]
    call x25519
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_ephemeral]
    lea  rsi, [rel ssh_transport_kat_x_public]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_VC]
    lea  rsi, [rel ssh_transport_kat_version]
    mov  edx, ssh_transport_kat_version.len
    call memcpy
    mov  dword [rbx + SSH_C_VC_LEN], ssh_transport_kat_version.len
    mov  rdi, rbx
    call ssh_build_server_kexinit
    test eax, eax
    js   .bad
    lea  rdi, [rbx + SSH_C_IC]
    lea  rsi, [rbx + SSH_C_IS]
    mov  edx, SSH_KEX_PAYLOAD_LEN
    call memcpy
    mov  dword [rbx + SSH_C_IC_LEN], SSH_KEX_PAYLOAD_LEN
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    lea  rsi, [rel ssh_ephemeral]
    mov  edx, 32
    call memcpy
    lea  rdi, [rbx + SSH_C_SERVER_Q]
    lea  rsi, [rel ssh_ephemeral]
    mov  edx, 32
    call memcpy
    ; Unlike X25519's native field encoding, RFC 8731 consumes its shared
    ; result as a fixed big-endian octet string.  The fixture is chosen so the
    ; rest of this established transcript/signature oracle remains stable.
    lea  rdi, [rbx + SSH_C_SHARED]
    lea  rsi, [rel ssh_transport_kat_shared_be]
    mov  edx, 32
    call memcpy
    mov  rdi, rbx
    call ssh_build_k_mpint
    cmp  eax, 36
    jne  .bad
    lea  rdi, [rel ssh_k_mpint]
    lea  rsi, [rel ssh_transport_kat_k_mpint]
    mov  edx, 36
    call memcmp
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ssh_compute_exchange_hash
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_H]
    lea  rsi, [rel ssh_transport_kat_exchange_hash]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_seed]
    mov  esi, 32
    lea  rdx, [rbx + SSH_C_H]
    mov  ecx, 32
    lea  r8, [rel ssh_signature]
    mov  r9d, 64
    call ed25519_sign
    test eax, eax
    jnz  .bad
    ; Independent host-derived Ed25519 oracle for this exact 32-byte H. The
    ; primitive's RFC vectors cover 0/1-byte messages; this closes the live
    ; transport's message-length gap without another sign-then-verify loop.
    lea  rdi, [rel ssh_signature]
    lea  rsi, [rel ssh_transport_kat_signature]
    mov  edx, 64
    call memcmp
    test eax, eax
    jnz  .bad
    lea  rdi, [rel ssh_host_public]
    mov  esi, 32
    lea  rdx, [rbx + SSH_C_H]
    mov  ecx, 32
    lea  r8, [rel ssh_signature]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ssh_derive_keys
    test eax, eax
    jnz  .bad
    lea  rdi, [rel str_ssh_kex_marker]
    call serial_string
    ; Geometry KAT 1: one encrypted message byte + padding-length byte needs
    ; 14 padding bytes: packet_length=16, complete AEAD wire record=36.
    mov  byte [rel ssh_onebyte_payload], SSH_MSG_SERVICE_ACCEPT
    mov  rdi, rbx
    lea  rsi, [rel ssh_onebyte_payload]
    mov  edx, 1
    call ssh_packet_gcm_build
    cmp  eax, 36
    jne  .bad
    cmp  dword [rbx + SSH_C_OUT], 0x10000000
    jne  .bad
    cmp  byte [rbx + SSH_C_PLAIN], 14
    jne  .bad
    ; Geometry KAT 2 is the exact first post-NEWKEYS server packet rejected
    ; by OpenSSH before this fix: type 6 + string "ssh-userauth" is 17 bytes.
    ; It must advertise 32 encrypted bytes and occupy 52 wire bytes with tag.
    mov  rdi, rbx
    lea  rsi, [rel ssh_service_accept]
    mov  edx, SSH_SERVICE_ACCEPT_LEN
    call ssh_packet_gcm_build
    cmp  eax, 52
    jne  .bad
    cmp  dword [rbx + SSH_C_OUT], 0x20000000
    jne  .bad
    cmp  byte [rbx + SSH_C_PLAIN], 14
    jne  .bad
    mov  eax, [rbx + SSH_C_OUT]
    bswap eax
    test eax, 15
    jne  .bad
    lea  rdi, [rel str_ssh_newkeys_marker]
    call serial_string
    mov  byte [rel ssh_selftest_done], 1
    xor  eax, eax
    jmp  .finish
.bad:
    mov  eax, -1
.finish:
    push rax
    mov  byte [rel ssh_selftest_mode], 0
    mov  byte [rel ssh_hostkey_ready], 0
    lea  rdi, [rel ssh_host_seed]
    xor  esi, esi
    mov  edx, 64
    call memset
    lea  rdi, [rel ssh_host_blob]
    xor  esi, esi
    mov  edx, SSH_HOST_BLOB_LEN
    call memset
    lea  rdi, [rel ssh_host_fingerprint]
    xor  esi, esi
    mov  edx, 44
    call memset
    mov  dword [rel ssh_host_fingerprint_len], 0
    call ssh_contexts_base                  ; allocate the table at init (heap is up since PH_HEAP_INIT)
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    pop  rax
    pop  rbx
    ret
.already:
    xor  eax, eax
    ret

; Retire server contexts after TCP ingress/poll, even when TCP initiated reset,
; EOF, timeout or reap without an SSH callback. SERVICE_ACTIVE=1 protects an
; admitted handler; =2 means it returned and only TCP prefix commit is pending.
; Use the existing table only; never allocate from the idle service pass.
ssh_retire_tick:
    push rbx
    push r12
    push r13
    mov  rbx, [rel ssh_contexts_ptr]
    test rbx, rbx
    jz   .out
    lea  r12, [rel tcp_tcbs]
    mov  r13d, SSH_CTX_N
.slot:
    cmp  qword [rbx + SSH_C_TCB], 0
    je   .next
    cmp  [rbx + SSH_C_TCB], r12
    jne  .terminal                         ; no dereference of a stale foreign TCB
    cmp  byte [r12 + TCB_SERVICE_ACTIVE], 1
    je   .next                             ; live consumer still owns this context
    cmp  byte [r12 + TCB_STATE], TCP_ESTABLISHED
    jne  .terminal
    lea  rax, [rel ssh_receive_cb]
    cmp  [r12 + TCB_RECV_CB], rax
    jne  .terminal                         ; slot was reused by another service
    mov  rdi, rbx
    call ssh_preauth_check
    test eax, eax
    jnz  .closing                          ; silent/blocked preauth also expires
    cmp  dword [rbx + SSH_C_OUTQ_LEN], 0
    jne  .rekey_service                    ; terminal records still need idle TCP drain
    cmp  byte [rbx + SSH_C_EXEC_PHASE], 0
    jne  .rekey_service                    ; finite per-context reply continuation
    cmp  byte [rbx + SSH_C_RK_ACTIVE], 0
    jne  .rekey_service
    cmp  dword [rbx + SSH_C_RK_DEFER_LEN], 0
    jne  .rekey_service
    mov  rdi, rbx
    call ssh_rekey_due
    test eax, eax
    jz   .existing_close
.rekey_service:
    movzx eax, byte [rbx + SSH_C_STATE]
    cmp  eax, SSH_STATE_SERVICE
    je   .service_owned
    cmp  eax, SSH_STATE_USERAUTH
    je   .service_owned
    cmp  eax, SSH_STATE_CONNECTION
    jne  .existing_close
.service_owned:
    sub  rsp, 16
    movzx eax, byte [r12 + TCB_SERVICE_ACTIVE]
    mov  [rsp], rax                    ; keep TCP's returned-prefix commit state2
    mov  byte [r12 + TCB_SERVICE_ACTIVE], 1 ; retirement cannot interrupt this consumer
    mov  rdi, rbx
    call ssh_process_one
    mov  rax, [rsp]
    mov  [r12 + TCB_SERVICE_ACTIVE], al
    add  rsp, 16
    jmp  .next
.existing_close:
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_DISCONNECT
    je   .closing
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CLOSE_PENDING
    jne  .next
.closing:
    mov  rdi, rbx
    call ssh_fail_close
    jmp  .next
.terminal:
    mov  rdi, rbx
    xor  esi, esi
    call ssh_connection_retire
.next:
    add  rbx, SSH_CTX_SIZE
    add  r12, TCP_TCB_SIZE
    dec  r13d
    jnz  .slot
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Server lifecycle tick plus boot-timeline mark boot.ssh.ready (no wait/serial).
; command_udp_poll calls this after each complete RX drain + tcp_poll pass.
; It latches at the end of the first pass that finds the persisted ssh-ed25519
; host key ready and the port-22 listener registered: from that idle frame on,
; an inbound SYN to :22 is drained, answered by the TCB service and handed to
; ssh_accept_cb every frame, i.e. a client can open a session (key exchange;
; userauth still needs an enrolled key). Preserves all registers but flags.
ssh_ready_timeline_tick:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call ssh_retire_tick                    ; runs even after readiness is latched
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    cmp  byte [rel ssh_ready_tl_latched], 1
    je   .out
    cmp  byte [rel ssh_server_registered], 1
    jne  .out
    cmp  byte [rel ssh_hostkey_ready], 1
    jne  .out
    mov  byte [rel ssh_ready_tl_latched], 1
    push rdi
    mov  edi, BOOT_TIMELINE_ID_SSH_READY
    call boot_timeline_latch
    pop  rdi
.out:
    ret

ssh_server_init:
    cmp  byte [rel ssh_server_registered], 1
    je   .ok
    cmp  byte [rel ssh_selftest_done], 1
    jnz  .bad
    call ssh_hostkey_init
    test eax, eax
    jnz  .bad
    mov  edi, SSH_PORT
    lea  rsi, [rel ssh_accept_cb]
    call tcp_listener_register
    test eax, eax
    jnz  .bad
    mov  byte [rel ssh_server_registered], 1
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Ordinary DHCP/static public primary. Every successful owner sync revalidates
; the exact tuple against TCP's scoped port-22 service grant. Do not use the
; fleet once-latch: public retirement/rebind and a later lawful fleet init may
; replace the live endpoint/listener table. No second TCP initialization, new
; key identity, auth policy, or alias listener is introduced here.
; In: rdi = expected six-byte MAC, esi = expected wire-order IPv4.
ssh_server_public_init:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  ebx, esi
    cmp  byte [rel ssh_selftest_done], 1
    jne  .bad
    call ssh_hostkey_init
    test eax, eax
    jnz  .bad
    mov  rdi, r12
    mov  esi, ebx
    lea  rdx, [rel ssh_accept_cb]
    call tcp_public_ssh_bind
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_ssh_0 0
; Only ciphertext digests and public transport/authority metadata survive
; connection retirement. No keys, IV, session-id, plaintext or pointer.
%if PAOS_PUBLIC_BUILD
; Private SSH preauth KAT scratch, independent of the lab TCP7000 canary.
ssh_transport_kat_tcb: times TCP_TCB_SIZE db 0
%endif
ssh_record_serial: dq 0
ssh_record_event: dq 0
ssh_record_ready: dq 0
ssh_record_connection: dq 0
ssh_record_previous_bytes: dq 0
ssh_record_previous_ordinal: dq 0
ssh_record_rejected_bytes: dq 0
ssh_record_rejected_ordinal: dq 0
ssh_record_state: dq 0
ssh_record_principal: dq 0
ssh_record_bound: dq 0
ssh_record_exec: dq 0
ssh_record_auth_ok: dq 0
ssh_record_nvram_writes: dq 0
ssh_record_local_ip: dq 0
ssh_record_remote_ip: dq 0
ssh_record_local_port: dq 0
ssh_record_remote_port: dq 0
ssh_record_previous: times 32 db 0
ssh_record_rejected: times 32 db 0

align 16
ssh_contexts_ptr: dq 0                     ; -> heap table (ssh_contexts_base); was 245,504 image bytes
ssh_aead_req: times AEAD_REQ_SZ db 0
ssh_hash_ctx: times S256_CTX_SZ db 0
ssh_exchange_buf: times SSH_EXCHANGE_CAP db 0
ssh_exchange_len: dd 0
ssh_host_seed: times 32 db 0
ssh_host_public: times 32 db 0
ssh_host_digest: times 32 db 0
ssh_signature: times 64 db 0
ssh_ephemeral: times 32 db 0
ssh_k_mpint: times 37 db 0
ssh_host_blob: times SSH_HOST_BLOB_LEN db 0
ssh_reply_payload: times SSH_ECDH_REPLY_LEN db 0
ssh_host_fingerprint: times 44 db 0
ssh_host_fingerprint_len: dd 0
ssh_kdf_letter: db 0
ssh_kdf_out: times 32 db 0
ssh_onebyte_payload: db 0
ssh_hostkey_ready: db 0
ssh_server_registered: db 0
ssh_ready_tl_latched: db 0
ssh_live_newkeys: db 0
ssh_selftest_mode: db 0
ssh_selftest_done: db 0
ssh_kex_witness_ready: db 0
align 4
ssh_kex_witness_len: times SSH_KEX_WITNESS_N dd 0
ssh_kex_witness_data: times (SSH_KEX_WITNESS_N * 32) db 0
ssh_x25519_base: db 9
                  times 31 db 0
; RFC 8032 section 7.1 test 1 seed/public and RFC 7748 section 6.1 Alice
; scalar/public. The fixed H was independently computed over the exact RFC
; 8731 V_C,V_S,I_C,I_S,K_S,Q_C,Q_S,K serialization used by this KAT.
ssh_transport_kat_host_seed:
    db 0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4
    db 0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
ssh_transport_kat_host_public:
    db 0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a
    db 0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
ssh_transport_kat_x_scalar:
    db 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    db 0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
ssh_transport_kat_x_public:
    db 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
    db 0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
; Direction-sensitive RFC 8731 K fixture.  Its first/last bytes make an
; accidental X25519-native little-endian reversal fail the explicit mpint KAT.
ssh_transport_kat_shared_be:
    db 0x6a,0x4e,0x9b,0xaa,0x8e,0xa9,0xa4,0xeb,0xf4,0x1a,0x38,0x26,0x0d,0x3a,0xbf,0x0d
    db 0x5a,0xf7,0x3e,0xb4,0xdc,0x7d,0x8b,0x74,0x54,0xa7,0x30,0x89,0x09,0xf0,0x20,0x85
ssh_transport_kat_k_mpint:
    dd 0x20000000
    db 0x6a,0x4e,0x9b,0xaa,0x8e,0xa9,0xa4,0xeb,0xf4,0x1a,0x38,0x26,0x0d,0x3a,0xbf,0x0d
    db 0x5a,0xf7,0x3e,0xb4,0xdc,0x7d,0x8b,0x74,0x54,0xa7,0x30,0x89,0x09,0xf0,0x20,0x85
ssh_transport_kat_exchange_hash:
    db 0x73,0x4b,0x10,0x47,0xd2,0x26,0x9c,0xa2,0xeb,0x8a,0x68,0xf8,0xa3,0x65,0x8c,0x93
    db 0x2d,0xd8,0x6b,0xfd,0x79,0x31,0x20,0x1f,0x6b,0x2c,0x64,0xe9,0xfd,0xea,0xd7,0xf2
ssh_transport_kat_signature:
    db 0xd0,0xf2,0xe5,0x68,0xc6,0x0d,0x0a,0xb3,0x34,0x44,0x39,0x6c,0xb8,0x5d,0xcb,0x8e
    db 0x51,0x62,0x36,0x97,0x83,0x56,0x1d,0x43,0x0c,0x82,0x91,0x78,0x29,0x8f,0x55,0xb8
    db 0x6e,0x94,0x8f,0xfc,0x9f,0x40,0x80,0x52,0x2b,0x16,0x9b,0x21,0xf2,0x37,0x15,0x7b
    db 0xa8,0xf7,0x72,0x05,0x38,0x9d,0x7c,0x31,0xb8,0x33,0x60,0x3d,0x90,0x2f,0x95,0x0b
ssh_transport_kat_version: db "SSH-2.0-PaOS-KAT"
.len equ $ - ssh_transport_kat_version
%endmacro
WDATA_DEFER WDATA_svc_ssh_0
ssh_transport_kat_no_overlap:
    db SSH_MSG_KEXINIT
    times 16 db 0x3c
    dd 0x1d000000
    db "diffie-hellman-group14-sha256"
    dd 0x0b000000
    db "ssh-ed25519"
    dd 0x16000000
    db "aes256-gcm@openssh.com"
    dd 0x16000000
    db "aes256-gcm@openssh.com"
    dd 0x0d000000
    db "hmac-sha2-256"
    dd 0x0d000000
    db "hmac-sha2-256"
    dd 0x04000000
    db "none"
    dd 0x04000000
    db "none"
    dd 0
    dd 0
    db 0
    dd 0
SSH_TRANSPORT_KAT_NO_OVERLAP_LEN equ $ - ssh_transport_kat_no_overlap
ssh_b64: db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

ssh_alg_kex: db "curve25519-sha256"
.len equ $ - ssh_alg_kex
ssh_alg_host: db "ssh-ed25519"
.len equ $ - ssh_alg_host
ssh_alg_cipher: db "aes256-gcm@openssh.com"
.len equ $ - ssh_alg_cipher
ssh_alg_none: db "none"
.len equ $ - ssh_alg_none
ssh_server_version: db "SSH-2.0-PaOS_", PAOS_VERSION_TEXT
.len equ $ - ssh_server_version
ssh_server_banner: db "SSH-2.0-PaOS_", PAOS_VERSION_TEXT,13,10
.len equ $ - ssh_server_banner
; This derivation domain is distinct from the legacy DATA-backed host-key row.
; The persistent SYSTEM machine secret roots the stable identity.
ssh_hostkey_derive_info: db "PaOS/SSH/Ed25519/system-secret/v2"
.len equ $ - ssh_hostkey_derive_info

ssh_kex_suffix:
    dd 0x11000000
    db "curve25519-sha256"
    dd 0x0b000000
    db "ssh-ed25519"
    dd 0x16000000
    db "aes256-gcm@openssh.com"
    dd 0x16000000
    db "aes256-gcm@openssh.com"
    dd 0x0d000000
    db "hmac-sha2-256"
    dd 0x0d000000
    db "hmac-sha2-256"
    dd 0x04000000
    db "none"
    dd 0x04000000
    db "none"
    dd 0
    dd 0
    db 0
    dd 0
SSH_KEX_SUFFIX_LEN equ $ - ssh_kex_suffix
SSH_KEX_PAYLOAD_LEN equ 17 + SSH_KEX_SUFFIX_LEN

ssh_service_req_tail:
    dd 0x0c000000
    db "ssh-userauth"
SSH_SERVICE_REQ_LEN equ 1 + ($ - ssh_service_req_tail)
ssh_service_accept:
    db SSH_MSG_SERVICE_ACCEPT
    dd 0x0c000000
    db "ssh-userauth"
SSH_SERVICE_ACCEPT_LEN equ $ - ssh_service_accept
ssh_userauth_failure:
    db SSH_MSG_USERAUTH_FAILURE
    dd 0x09000000
    db "publickey"
    db 0
SSH_USERAUTH_FAILURE_LEN equ $ - ssh_userauth_failure
ssh_kex_disconnect:
    db SSH_MSG_DISCONNECT
    dd 0x03000000                     ; SSH_DISCONNECT_KEY_EXCHANGE_FAILED
    dd 0x1f000000
    db "no matching key exchange method"
    dd 0                              ; empty language tag
SSH_KEX_DISCONNECT_LEN equ $ - ssh_kex_disconnect

str_ssh_kex_marker: db "[PAOS64] SSH rung 1: curve25519-sha256 kex + ssh-ed25519 host-key signature selftest (RFC 4253 exchange hash) [ssh.transport.kex]",13,10,0
str_ssh_newkeys_marker: db "[PAOS64] SSH rung 1: NEWKEYS -> aes256-gcm encrypted packet framing selftest [ssh.transport.newkeys]",13,10,0
str_ssh_hostkey_marker: db "[PAOS64] SSH rung 1: ssh-ed25519 host key generated + persisted owner-rooted, SSHHOSTKEY fingerprint verb [ssh.hostkey.persist]",13,10,0
str_ssh_ctx_alloc_fail: db "[PAOS64] ssh: context table allocation refused by the heap [ssh.ctx.alloc.fail]", 13, 10, 0

%include "svc/ssh_presence.inc"
