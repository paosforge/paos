; Live public SSH presence. Serialized on the existing BSP network/UI pump.
; No allocation, admission, unlock, retirement or additional audit write.
; Cache is observation only: every use rejoins original context serial/key/tuple.
SSH_PRESENCE_CACHE_SZ equ 144
; cache: serial0, seq8, presented frame16/us24, text32[72], pub104[32], valid136

; EDI original TCP/context index -> RAX live authenticated ctx or0, RDX owned TCB.
ssh_presence_connection:
    xor  eax, eax
    cmp  edi, SSH_CTX_N
    jae  .out
    mov  rdx, [rel ssh_contexts_ptr]
    test rdx, rdx
    jz   .out
    imul rax, rdi, SSH_CTX_SIZE
    add  rax, rdx
    cmp  byte [rax + SSH_C_STATE], SSH_STATE_CONNECTION
    jne  .no
    cmp  byte [rax + SSH_C_AUTH_BOUND], 1
    jne  .no
    cmp  byte [rax + SSH_C_KEY_INDEX], 3
    ja   .no
    cmp  qword [rax + SSH_C_PID], 0
    je   .no
    cmp  qword [rax + SSH_C_REC_SERIAL], 0
    je   .no
    imul rdx, rdi, TCP_TCB_SIZE
    lea  rcx, [rel tcp_tcbs]
    add  rdx, rcx
    cmp  [rax + SSH_C_TCB], rdx
    jne  .no
    cmp  byte [rdx + TCB_STATE], TCP_ESTABLISHED
    jne  .no
    cmp  word [rdx + TCB_LOCAL_PORT], SSH_PORT
    jne  .no
    ret
.no:
    xor  eax, eax
.out:
    ret

; RDI ctx -> EAX original slot or-1, without dereferencing supplied pointer.
ssh_presence_index:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.loop:
    mov  edi, ebx
    call ssh_presence_connection
    test rax, rax
    jz   .next
    cmp  rax, r12
    je   .found
.next:
    inc  ebx
    cmp  ebx, SSH_CTX_N
    jb   .loop
    mov  eax, -1
    jmp  .out
.found:
    mov  eax, ebx
.out:
    pop  r12
    pop  rbx
    ret

; RDI validated ctx, RSI72B destination. Complete human public identity/endpoint
; <=65 chars, no truncation, no unverified offered-key fingerprint or secrets.
ssh_presence_line:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, rsi
    xor  esi, esi
    mov  edx, 72
    call memset
    mov  dword [r13], 'SSH '
    lea  rsi, [r13 + 4]
    mov  rdi, [r12 + SSH_C_REC_SERIAL]
    mov  edx, 16
    call fmt_hex
    lea  r13, [r13 + 20]
    mov  dword [r13], ' key'
    movzx eax, byte [r12 + SSH_C_KEY_INDEX]
    add  al, '0'
    mov  [r13 + 4], al
    mov  byte [r13 + 5], ' '
    add  r13, 6
    cmp  qword [r12 + SSH_C_CAPMASK], -1
    jne  .limited
    mov  dword [r13], 'owne'
    mov  word [r13 + 4], 'r '
    add  r13, 6
    jmp  .ip
.limited:
    mov  dword [r13], 'limi'
    mov  dword [r13 + 4], 'ted '
    add  r13, 8
.ip:
    mov  r14, [r12 + SSH_C_TCB]
    xor  ebx, ebx
.octet:
    movzx edi, byte [r14 + TCB_REMOTE_IP + rbx]
    mov  rsi, r13
    call fmt_dec
    add  r13, rax
    inc  ebx
    cmp  ebx, 4
    jae  .port
    mov  byte [r13], '.'
    inc  r13
    jmp  .octet
.port:
    mov  byte [r13], ':'
    inc  r13
    movzx edi, word [r14 + TCB_REMOTE_PORT]
    mov  rsi, r13
    call fmt_dec
    mov  byte [r13 + rax], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Replace only a genuine successful live login's existing bounded audit text.
; Selftests retain their historical audit text/counters and mint no presence.
ssh_presence_prepare:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    cmp  byte [rel ssh_selftest_mode], 0
    jne  .out
    call ssh_presence_index
    cmp  eax, -1
    je   .out
    mov  rdi, rbx
    mov  rsi, r12
    call ssh_presence_line
.out:
    pop  r12
    pop  rbx
    ret

; Immediate existing audit_log_net result. Sequence zero is valid. Exhaustion
; or missing telemetry never changes successful authentication or queues a retry.
ssh_presence_audited:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    cmp  byte [rel ssh_selftest_mode], 0
    jne  .out
    call ssh_presence_index
    cmp  eax, -1
    je   .out
    imul ebx, eax, SSH_PRESENCE_CACHE_SZ
    lea  rax, [rel ssh_presence_cache]
    add  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, SSH_PRESENCE_CACHE_SZ
    call memset
    cmp  r13d, 1
    jne  .out
    mov  rax, [rel audit_seq]
    test rax, rax
    jz   .out
    dec  rax
    mov  [rbx + 8], rax
    mov  rax, [r12 + SSH_C_REC_SERIAL]
    mov  [rbx], rax
    lea  rdi, [rbx + 104]
    lea  rsi, [r12 + SSH_C_AUTH_PUB]
    mov  edx, 32
    call memcpy
    lea  rsi, [rbx + 32]
    mov  rdi, r12
    call ssh_presence_line
    mov  qword [rbx + 136], 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

 ; Original UI present observation, not a new connection or authority table.
; EDI actual slot, RSI serial, RDX actual successful frame, RCX monotonic us.
ssh_presence_present:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    call ssh_presence_connection
    test rax, rax
    jz   .out
    cmp  [rax + SSH_C_REC_SERIAL], r12
    jne  .out
    imul ebx, SSH_PRESENCE_CACHE_SZ
    lea  rdx, [rel ssh_presence_cache]
    add  rbx, rdx
    cmp  qword [rbx + 136], 1
    jne  .out
    cmp  [rbx], r12
    jne  .out
    lea  rdi, [rax + SSH_C_AUTH_PUB]
    lea  rsi, [rbx + 104]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .out
    mov  [rbx + 16], r13
    mov  [rbx + 24], r14
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI enrolled selector0..3, RSI exact280B public snapshot -> EAX0/-1.
; Snapshot never allocates contexts, mutates authentication or fabricates a peer.
ssh_presence_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edi
    mov  rdi, rsi
    xor  esi, esi
    mov  edx, 280
    call memset
    cmp  r13d, 3
    ja   .bad
    mov  dword [r12], 1
    mov  [r12 + 4], r13d
    xor  ebx, ebx
    xor  r14d, r14d
.loop:
    mov  edi, ebx
    call ssh_presence_connection
    test rax, rax
    jz   .next
    inc  dword [r12 + 8]
    cmp  [rax + SSH_C_KEY_INDEX], r13b
    jne  .next
    inc  dword [r12 + 12]
    mov  r14, rax
    mov  r15d, ebx
.next:
    inc  ebx
    cmp  ebx, SSH_CTX_N
    jb   .loop
    cmp  dword [r12 + 12], 1
    jne  .done
    mov  rax, [r14 + SSH_C_REC_SERIAL]
    mov  [r12 + 16], rax
    mov  rax, [r14 + SSH_C_PID]
    mov  [r12 + 24], rax
    mov  rax, [r14 + SSH_C_CAPMASK]
    mov  [r12 + 32], rax
    mov  rbx, [r14 + SSH_C_TCB]
    mov  eax, [rbx + TCB_LOCAL_IP]
    mov  [r12 + 40], eax
    mov  eax, [rbx + TCB_REMOTE_IP]
    mov  [r12 + 44], eax
    mov  ax, [rbx + TCB_LOCAL_PORT]
    mov  [r12 + 48], ax
    mov  ax, [rbx + TCB_REMOTE_PORT]
    mov  [r12 + 50], ax
    mov  al, [r14 + SSH_C_STATE]
    mov  [r12 + 52], al
    mov  al, [r14 + SSH_C_AUTH_BOUND]
    mov  [r12 + 53], al
    mov  [r12 + 54], r13b
    lea  rdi, [r12 + 56]
    lea  rsi, [r14 + SSH_C_AUTH_PUB]
    mov  edx, 32
    call memcpy
    imul r15, SSH_PRESENCE_CACHE_SZ
    lea  rbx, [rel ssh_presence_cache]
    add  rbx, r15
    cmp  qword [rbx + 136], 1
    jne  .done
    mov  rax, [r14 + SSH_C_REC_SERIAL]
    cmp  [rbx], rax
    jne  .done
    lea  rdi, [rbx + 104]
    lea  rsi, [r14 + SSH_C_AUTH_PUB]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .done
    ; Complete current tuple/role must still match the authenticated receipt.
    sub  rsp, 72
    mov  rdi, r14
    mov  rsi, rsp
    call ssh_presence_line
    mov  rdi, rsp
    lea  rsi, [rbx + 32]
    mov  edx, 72
    call memcmp
    add  rsp, 72
    test eax, eax
    jnz  .done
    mov  rax, [rbx + 8]
    mov  rcx, [rel audit_seq]
    cmp  rax, rcx
    jae  .display
    sub  rcx, rax
    cmp  rcx, AUDIT_NREC
    ja   .display
    mov  rdx, rax
    and  edx, AUDIT_NREC - 1
    imul rdx, AUDIT_REC_SZ
    lea  r15, [rel audit_ring]
    add  r15, rdx
    cmp  [r15 + AR_SEQ], rax
    jne  .display
    cmp  byte [r15 + AR_KIND], AUDIT_KIND_NET
    jne  .display
    cmp  byte [r15 + AR_SRC], AUDIT_NSRC_SSH
    jne  .display
    cmp  byte [r15 + AR_SVC], AUDIT_NSVC_SSH
    jne  .display
    cmp  byte [r15 + AR_RES], AUDIT_NRES_ADMIT
    jne  .display
    cmp  dword [r15 + AR_COUNT], 1
    jne  .display
    cmp  qword [r15 + AR_REASON], 0
    jne  .display
    mov  rdx, [r14 + SSH_C_PID]
    cmp  [r15 + AR_PID], rdx
    jne  .display
    lea  rdi, [r15 + AR_VERB]
    lea  rsi, [rel ssh_presence_userauth]
    call strcmp
    test eax, eax
    jnz  .display
    lea  rdi, [r15 + AR_TEXT]
    lea  rsi, [rbx + 32]
    mov  edx, 72
    call memcmp
    test eax, eax
    jnz  .display
    mov  rax, [rbx + 8]
    mov  [r12 + 88], rax
    mov  qword [r12 + 96], 1
    lea  rdi, [r12 + 120]
    lea  rsi, [r15 + AR_TEXT]
    mov  edx, 72
    call memcpy
.display:
    cmp  qword [rbx + 16], 0
    je   .done
    mov  rax, [rbx + 16]
    mov  [r12 + 104], rax
    mov  rax, [rbx + 24]
    mov  [r12 + 112], rax
    lea  rdi, [r12 + 192]
    lea  rsi, [rbx + 32]
    mov  edx, 72
    call memcpy
    mov  qword [r12 + 264], 1
.done:
    call time_monotonic_now_us
    mov  [r12 + 272], rax
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

ssh_presence_userauth: db "userauth",0
align 8
ssh_presence_cache: times SSH_CTX_N * SSH_PRESENCE_CACHE_SZ db 0
