; Owner-only public observation of the actual loaded outgoing identity/trust.
; EDI page0..7, RSI writable240B -> EAX0/-1. No identity_ensure, entropy,
; signing, SetVariable, enrollment, admission or connection operation.
; Existing authenticated loads may initialize public caches and report failure;
; they do NOT repair or retry an uncertain store. Never export private scratch.
%if SSH_CLI_PINS != 32 || SSH_CLI_PIN_SZ != 44
    %error "SSHCLIPROFILE v1 requires reviewed32x44 pin layout"
%endif
ssh_cli_profile_snapshot:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    cmp  edi, 7
    ja   .refused
    test rsi, rsi
    jz   .refused
    call principal_current
    test rax, rax
    jz   .owner
    cmp  rax, PRIN_OWNER
    jne  .refused
.owner:
    call ssh_cli_cid_load
    test eax, eax
    jnz  .refused
    call ssh_cli_kh_load
    mov  rdi, r13
    xor  esi, esi
    mov  edx, 240
    call memset
    mov  dword [r13], 1
    mov  al, [rel pbm_runtime_code_mapped]
    mov  [r13 + 4], al
    mov  al, [rel ssh_cli_cid_state]
    mov  [r13 + 5], al
    mov  al, [rel ssh_cli_id_ready]
    mov  [r13 + 6], al
    mov  al, [rel ssh_cli_kh_state]
    mov  [r13 + 7], al
    mov  eax, [rel ssh_cli_cid_gen]
    mov  [r13 + 8], eax
    mov  eax, [rel ssh_cli_kh_gen]
    mov  [r13 + 12], eax
    mov  rax, [rel ssh_cli_kh_epoch]
    mov  [r13 + 16], rax
    cmp  byte [rel ssh_cli_cid_state], SSH_CID_ST_ENROLLED
    jne  .boot_key
    lea  rsi, [rel ssh_cli_cid_pub]
    jmp  .public
.boot_key:
    cmp  byte [rel ssh_cli_id_ready], 1
    jne  .pins
    lea  rsi, [rel ssh_cli_id_pub]
.public:
    lea  rdi, [r13 + 24]
    mov  edx, 32
    call memcpy
.pins:
    imul eax, r12d, 4 * SSH_CLI_PIN_SZ
    lea  rsi, [rel ssh_cli_pins]
    add  rsi, rax
    lea  rdi, [r13 + 56]
    mov  edx, 4 * SSH_CLI_PIN_SZ
    call memcpy
    mov  dword [r13 + 232], SSH_CLI_PINS
    mov  dword [r13 + 236], SSH_CLI_PIN_SZ
    xor  eax, eax
    jmp  .out
.refused:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
