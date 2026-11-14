; Client-owned encrypted transport rekey. No server context/ABI extension.
; The slot tail is parked with its context; retirement wipes SSH_CLI_SLOT_SIZE.
SSH_CLI_RK_PHASE       equ 0       ; 0 idle,1 send I_C,2 wait I_S,3 send Q_C,4 wait reply,5 send NEWKEYS,6 wait NEWKEYS
SSH_CLI_RK_PEER        equ 1
SSH_CLI_RK_RX_NEW      equ 2
SSH_CLI_RK_SKIP        equ 3       ; one wrong first_kex_packet_follows guess
SSH_CLI_RK_EPHEMERAL   equ 4
SSH_CLI_RK_BOUND       equ 5
SSH_CLI_RK_CID_STATE   equ 6
SSH_CLI_RK_CID_GEN     equ 8
SSH_CLI_RK_DEADLINE    equ 16
SSH_CLI_RK_STARTED     equ 24
SSH_CLI_RK_TX_BYTES    equ 32
SSH_CLI_RK_RX_BYTES    equ 40
SSH_CLI_RK_TX_TOTAL    equ 48      ; transport packet accounting, never reset at rekey
SSH_CLI_RK_RX_TOTAL    equ 56
SSH_CLI_RK_HOST        equ 64      ; original verified host blob digest
SSH_CLI_RK_KEYS        equ 96      ; staged A32,B32,C32,D32 from canonical ssh_derive_one
SSH_CLI_RK_TX_KEY_PKTS equ 224      ; per-key limits, distinct from transport sequence
SSH_CLI_RK_RX_KEY_PKTS equ 228
SSH_CLI_RK_SIZE        equ 232
SSH_CLI_RK_PLAIN       equ SSH_CLI_RK_SIZE
SSH_CLI_RK_PLAIN_CAP   equ SSH_C_RX_CAP - 20
SSH_CLI_RK_PACKETS     equ 0x100000
SSH_CLI_RK_BYTES       equ 0x40000000
SSH_CLI_RK_INTERVAL_US equ 3600000000
SSH_CLI_RK_TIMEOUT_US  equ 20000000

ssh_cli_rekey_reset:
    mov  rdi, [rel ssh_cli_ctx_ptr]
    test rdi, rdi
    jz   .out
    add  rdi, SSH_CLI_SLOT_RK
    xor  esi, esi
    mov  edx, SSH_CLI_RK_SIZE
    jmp  memset
.out:
    ret

; Initial verified KEX binds its original host/owner identity without any new
; store, pin insertion or signing. Subsequent rekeys cannot replace this bind.
ssh_cli_rekey_bind:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    lea  rdi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_HOST]
    lea  rsi, [rel ssh_cli_ks_buf]
    mov  edx, [rel ssh_cli_ks_len]
    call sha256_hash
    test eax, eax
    jnz  .out
    mov  eax, [rel ssh_cli_cid_gen]
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_CID_GEN], eax
    mov  al, [rel ssh_cli_cid_state]
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_CID_STATE], al
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_BOUND], 1
    xor  eax, eax
.out:
    pop  rbx
    ret

ssh_cli_rekey_authority:
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .bad
    cmp  byte [rel ssh_cli_owner_armed], 1
    jne  .bad
    mov  rax, [rel ssh_cli_ctx_ptr]
    test rax, rax
    jz   .bad
    cmp  byte [rax + SSH_CLI_SLOT_RK + SSH_CLI_RK_BOUND], 1
    jne  .bad
    mov  ecx, [rel ssh_cli_cid_gen]
    cmp  [rax + SSH_CLI_SLOT_RK + SSH_CLI_RK_CID_GEN], ecx
    jne  .bad
    mov  cl, [rel ssh_cli_cid_state]
    cmp  cl, SSH_CID_ST_UNVERIFIED
    je   .bad
    cmp  [rax + SSH_CLI_SLOT_RK + SSH_CLI_RK_CID_STATE], cl
    jne  .bad
    jmp  ssh_cli_kh_admission_current
.bad:
    mov  eax, -1
    ret

; Every received transport step and deferred send obeys the same total bound.
ssh_cli_rekey_current:
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .out
    call time_monotonic_now_us
    mov  rdx, [rel ssh_cli_ctx_ptr]
    cmp  rax, [rdx + SSH_CLI_SLOT_RK + SSH_CLI_RK_DEADLINE]
    jae  .bad
    xor  eax, eax
.out:
    ret
.bad:
    mov  eax, -1
    ret

ssh_cli_rekey_fault:
    mov  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    mov  byte [rel ssh_cli_error], 21       ; transport rekey failed, never a remote exit
    mov  byte [rel ssh_cli_chan_ready], 0
    mov  byte [rel ssh_cli_chan_closed], 1
    mov  eax, -1
    ret

; RDI=12-byte nonce. Reserve64 invocation values for bounded KEX transport.
ssh_cli_rekey_nonce_due:
    cmp  dword [rdi + 4], -1
    jne  .no
    cmp  word [rdi + 8], -1
    jne  .no
    cmp  byte [rdi + 10], 255
    jne  .no
    cmp  byte [rdi + 11], 192
    jae  .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; RDI=ctx. Counts are per key, transport totals are independent of key epoch.
ssh_cli_rekey_due:
    push rbx
    mov  rbx, rdi
    cmp  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_KEY_PKTS], SSH_CLI_RK_PACKETS
    jae  .yes
    cmp  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_KEY_PKTS], SSH_CLI_RK_PACKETS
    jae  .yes
    cmp  qword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_BYTES], SSH_CLI_RK_BYTES
    jae  .yes
    cmp  qword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_BYTES], SSH_CLI_RK_BYTES
    jae  .yes
    lea  rdi, [rbx + SSH_C_C2S_IV]
    call ssh_cli_rekey_nonce_due
    test eax, eax
    jnz  .yes
    lea  rdi, [rbx + SSH_C_S2C_IV]
    call ssh_cli_rekey_nonce_due
    test eax, eax
    jnz  .yes
    call time_monotonic_now_us
    sub  rax, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_STARTED]
    mov  ecx, SSH_CLI_RK_INTERVAL_US
    cmp  rax, rcx
    jae  .yes
    xor  eax, eax
    jmp  .out
.yes:
    mov  eax, 1
.out:
    pop  rbx
    ret

ssh_cli_rekey_begin:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    jne  .bad
    call ssh_cli_build_kexinit              ; fresh I_C exactly once, not each retry
    test eax, eax
    jnz  .bad
    call time_monotonic_now_us
    add  rax, SSH_CLI_RK_TIMEOUT_US
    jc   .bad
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_DEADLINE], rax
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PEER], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_NEW], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_EPHEMERAL], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_SKIP], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 1
    xor  eax, eax
    pop  rbx
    ret
.bad:
    pop  rbx
    jmp  ssh_cli_rekey_fault

; Read-only validation of server proposal using canonical list/string helpers.
; Client preference has exactly one algorithm per negotiated category. Bound
; all ten lists/trailer, require supported kex/host/ciphers/compression and
; remember one wrong optimistic guess. RDI=payload, ESI=len -> 0/-1.
ssh_cli_rekey_proposal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov  rbx, rdi
    mov  r12d, esi
    cmp  r12d, 62
    jb   .bad
    cmp  r12d, SSH_CLI_IS_CAP
    ja   .bad
    add  r12, rbx
    jc   .bad
    lea  rdi, [rbx + 17]
    xor  r13d, r13d
    xor  r15d, r15d
.list:
    mov  rsi, r12
    call ssh_string_read
    cmp  rax, -1
    je   .bad
    mov  r14, r8
    ; Printable RFC name-list tokens, no empty comma member.
    xor  ecx, ecx
.chars:
    cmp  ecx, edx
    jae  .algorithm
    mov  r9b, [rax + rcx]
    cmp  r9b, 33
    jb   .bad
    cmp  r9b, 126
    ja   .bad
    cmp  r9b, ','
    jne  .char_next
    test ecx, ecx
    jz   .bad
    cmp  byte [rax + rcx - 1], ','
    je   .bad
    lea  r9d, [rcx + 1]
    cmp  r9d, edx
    je   .bad
.char_next:
    inc  ecx
    jmp  .chars
.algorithm:
    mov  rdi, rax
    mov  esi, edx
    cmp  r13d, 4
    jb   .required
    cmp  r13d, 6
    jb   .next
    cmp  r13d, 8
    jae  .next
.required:
    lea  rdx, [rel ssh_alg_none]
    mov  ecx, ssh_alg_none.len
    cmp  r13d, 6
    jae  .has
    lea  rdx, [rel ssh_alg_cipher]
    mov  ecx, ssh_alg_cipher.len
    cmp  r13d, 2
    jae  .has
    lea  rdx, [rel ssh_alg_host]
    mov  ecx, ssh_alg_host.len
    cmp  r13d, 1
    je   .guess
    lea  rdx, [rel ssh_alg_kex]
    mov  ecx, ssh_alg_kex.len
.guess:
    ; First advertised kex/host must equal our chosen token for a correct guess.
    cmp  esi, ecx
    jb   .wrong_guess
    push rsi
    push rdi
    mov  rsi, rdx
    repe cmpsb
    pop  rdi
    pop  rsi
    jne  .wrong_guess
    mov  ecx, ssh_alg_kex.len
    test r13d, r13d
    jz   .guess_end
    mov  ecx, ssh_alg_host.len
.guess_end:
    cmp  esi, ecx
    je   .guess_restore
    cmp  byte [rdi + rcx], ','
    je   .guess_restore
.wrong_guess:
    mov  r15d, 1
.guess_restore:
    lea  rdx, [rel ssh_alg_kex]
    mov  ecx, ssh_alg_kex.len
    test r13d, r13d
    jz   .has
    lea  rdx, [rel ssh_alg_host]
    mov  ecx, ssh_alg_host.len
.has:
    call ssh_namelist_has
    test eax, eax
    jz   .bad
.next:
    mov  rdi, r14
    inc  r13d
    cmp  r13d, 10
    jb   .list
    lea  rax, [r14 + 5]
    cmp  rax, r12
    jne  .bad
    cmp  byte [r14], 1
    ja   .bad
    cmp  dword [r14 + 1], 0
    jne  .bad
    mov  rax, [rel ssh_cli_ctx_ptr]
    movzx ecx, byte [r14]
    and  ecx, r15d
    mov  [rax + SSH_CLI_SLOT_RK + SSH_CLI_RK_SKIP], cl
    xor  eax, eax
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

; Actual decrypted dispatch gate. RDI=payload, ESI=len. 0 normal dispatch,
; 1 transport handled, -1 failed. Never seal over callback-owned PLAIN here.
ssh_cli_rekey_packet:
    push rbx
    push r12
    push r13
    cld
    mov  rbx, [rel ssh_cli_ctx_ptr]
    mov  r12, rdi
    mov  r13d, esi
    movzx eax, byte [r12]
    cmp  eax, SSH_MSG_KEXINIT
    je   .proposal
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    je   .idle
    call ssh_cli_rekey_current
    test eax, eax
    jnz  .bad
    movzx eax, byte [r12]
    cmp  eax, SSH_MSG_DISCONNECT
    je   .pass
    cmp  eax, 2                          ; IGNORE
    je   .handled
    cmp  eax, 4                          ; DEBUG
    je   .handled
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_SKIP], 0
    je   .reply
    cmp  eax, 30
    jb   .bad
    cmp  eax, 49
    ja   .bad
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_SKIP], 0
    jmp  .handled
.reply:
    cmp  eax, SSH_MSG_KEX_ECDH_REPLY
    jne  .newkeys
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 4
    jne  .bad
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, r13d
    call ssh_cli_process_ecdh_reply
    test eax, eax
    jnz  .bad
    jmp  .handled
.newkeys:
    cmp  eax, SSH_MSG_NEWKEYS
    jne  .other
    cmp  r13d, 1
    jne  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_NEW], 0
    jne  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 5
    je   .install_rx
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 6
    jne  .bad
.install_rx:
    mov  rdi, rbx
    call ssh_cli_rekey_install_rx
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_NEW], 1
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 6
    jne  .handled
    call ssh_cli_rekey_finish
    jmp  .handled
.other:
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PEER], 0
    jne  .bad                           ; peer began KEX: no application packets until NEWKEYS
    jmp  .pass                          ; still-ordered traffic before peer I_S is valid
.idle:
    cmp  eax, SSH_MSG_NEWKEYS
    je   .bad
    cmp  eax, 30
    jb   .pass
    cmp  eax, 49
    jbe  .bad
.pass:
    xor  eax, eax
    jmp  .out
.proposal:
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    jne  .started
    call ssh_cli_rekey_begin
    test eax, eax
    jnz  .bad
.started:
    call ssh_cli_rekey_current
    test eax, eax
    jnz  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PEER], 0
    jne  .bad
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 2
    ja   .bad
    mov  rdi, r12
    mov  esi, r13d
    call ssh_cli_rekey_proposal
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_CLI_SLOT_IS]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    mov  [rel ssh_cli_is_len], r13d
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PEER], 1
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 2
    jne  .handled
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 3
.handled:
    mov  eax, 1
    jmp  .out
.bad:
    call ssh_cli_rekey_fault
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Canonical KDF A/B/C/D into slot-owned staging, never live transport keys.
ssh_cli_rekey_derive:
    push rbx
    push r12
    mov  rbx, rdi
    xor  r12d, r12d
.next:
    mov  rdi, rbx
    lea  esi, [r12 + 'A']
    mov  eax, r12d
    shl  eax, 5
    lea  rdx, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_KEYS + rax]
    call ssh_derive_one
    test eax, eax
    jnz  .bad
    inc  r12d
    cmp  r12d, 4
    jb   .next
    call ssh_kex_scrub
    lea  rdi, [rel ssh_cli_ephemeral]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rbx + SSH_C_SHARED]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 5
    xor  eax, eax
    jmp  .out
.bad:
    call ssh_kex_scrub
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

ssh_cli_rekey_install_rx:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rbx + SSH_C_S2C_IV]
    lea  rsi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_KEYS + 32]
    mov  edx, 12
    call memcpy
    lea  rdi, [rbx + SSH_C_S2C_KEY]
    lea  rsi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_KEYS + 96]
    mov  edx, 32
    call memcpy
    mov  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_KEY_PKTS], 0
    mov  qword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_BYTES], 0
    pop  rbx
    ret

ssh_cli_rekey_finish:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    lea  rdi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_KEYS]
    xor  esi, esi
    mov  edx, 128
    call memset
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PEER], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_NEW], 0
    call time_monotonic_now_us
    mov  [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_STARTED], rax
    pop  rbx
    ret

; Poll returns1 while rekey consumes this tick;0 permits ordinary sends.
ssh_cli_rekey_poll:
    push rbx
    mov  rbx, [rel ssh_cli_ctx_ptr]
    test rbx, rbx
    jz   .idle
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_ENC
    jb   .idle
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .idle
    cmp  byte [rel ssh_cli_retiring], 0
    jne  .idle
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 0
    jne  .active
    mov  rdi, rbx
    call ssh_cli_rekey_due
    test eax, eax
    jz   .globals
    call ssh_cli_rekey_begin
    test eax, eax
    jnz  .consumed
.active:
    call ssh_cli_rekey_authority
    test eax, eax
    jnz  .bad
    call time_monotonic_now_us
    cmp  rax, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_DEADLINE]
    jae  .bad
    movzx eax, byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE]
    cmp  eax, 1
    je   .kexinit
    cmp  eax, 3
    je   .ecdh
    cmp  eax, 5
    je   .newkeys
    jmp  .consumed
.kexinit:
    mov  rdi, rbx
    lea  rsi, [rbx + SSH_C_IC]
    mov  edx, [rbx + SSH_C_IC_LEN]
    call ssh_cli_gcm_send
    test eax, eax
    js   .bad
    jnz  .consumed
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 2
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PEER], 0
    je   .consumed
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 3
    jmp  .consumed
.ecdh:
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_EPHEMERAL], 1
    je   .ecdh_ready
    lea  rdi, [rel ssh_cli_ephemeral]
    mov  esi, 32
    call ssh_random_fill
    test eax, eax
    jnz  .bad
    lea  rdi, [rbx + SSH_C_CLIENT_Q]
    lea  rsi, [rel ssh_cli_ephemeral]
    lea  rdx, [rel ssh_x25519_base]
    call x25519
    test eax, eax
    jnz  .bad
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_EPHEMERAL], 1
.ecdh_ready:
    mov  byte [rel ssh_cli_pkt], SSH_MSG_KEX_ECDH_INIT
    lea  rdi, [rel ssh_cli_pkt + 1]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_cli_pkt + 5]
    lea  rsi, [rbx + SSH_C_CLIENT_Q]
    mov  edx, 32
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_pkt]
    mov  edx, 37
    call ssh_cli_gcm_send
    test eax, eax
    js   .bad
    jnz  .consumed
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 4
    jmp  .consumed
.newkeys:
    mov  byte [rel ssh_cli_pkt], SSH_MSG_NEWKEYS
    mov  rdi, rbx
    lea  rsi, [rel ssh_cli_pkt]
    mov  edx, 1
    call ssh_cli_gcm_send                  ; old outbound key until accepted by TCP
    test eax, eax
    js   .bad
    jnz  .consumed
    lea  rdi, [rbx + SSH_C_C2S_IV]
    lea  rsi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_KEYS]
    mov  edx, 12
    call memcpy
    lea  rdi, [rbx + SSH_C_C2S_KEY]
    lea  rsi, [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_KEYS + 64]
    mov  edx, 32
    call memcpy
    mov  dword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_KEY_PKTS], 0
    mov  qword [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_TX_BYTES], 0
    mov  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_PHASE], 6
    cmp  byte [rbx + SSH_CLI_SLOT_RK + SSH_CLI_RK_RX_NEW], 0
    je   .consumed
    call ssh_cli_rekey_finish
    ; Peer NEWKEYS and new ciphertext may share one callback. Resume retained
    ; RX only after both directional transitions, through the actual consumer.
    mov  rdi, [rel ssh_cli_tcb]
    xor  esi, esi
    xor  edx, edx
    call ssh_cli_on_receive
    jmp  .consumed
.globals:
    jmp  .idle
.bad:
    call ssh_cli_rekey_fault
.consumed:
    mov  eax, 1
    pop  rbx
    ret
.idle:
    xor  eax, eax
    pop  rbx
    ret
