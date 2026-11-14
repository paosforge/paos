;; MODULE sec/node_identity
;; LAYER 5
;; EXPORTS node_identity_generate_proof, node_identity_bootstrap, node_identity_active, node_identity_public, node_identity_sign, node_identity_sign_active, node_identity_verify, node_identity_envelope_export, node_identity_envelope_import, node_identity_clear_runtime, node_identity_selftest, node_identity_selftest_consumer
;; IMPORTS core/lib/ed25519, core/lib/aes256_gcm, core/csprng, core/lib/mem, boot/serial
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only  (SEC-S10-ext: unlocked module-static scratch; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; ============================================================================
; Durable node signing identity foundation (contract 1239).
;
; Durable bytes are an opaque, authenticated 112-byte record only:
;   +0 magic[8], +8 version/reserved[8], +16 nonce[12]/reserved[4],
;   +32 wrapped_seed[32], +64 GCM tag[16], +80 public_key[32].
; The public key is part of the 48-byte AAD (domain string || public key), so a
; substituted public identity cannot authenticate.  A record is committed only
; after GCM authentication and public-key re-derivation both succeed.
;
; node_identity_bootstrap(kek32, kek_len=32) creates only when no record exists;
; otherwise it authenticates the durable record.  The CSPRNG-generated seed is
; plaintext only in serialized scratch while deriving/signing and is wiped on
; every exit.  Export/import expose only the opaque record.  Storage I/O and key
; rotation remain the owner/consumer's policy; this module owns the format and
; fail-closed cryptographic transition.  The authenticated wrapping key remains
; keep-owned while the runtime identity is active so subsystems can request a
; signature without learning either the wrapping key or the node seed.
; ============================================================================

NID_RECORD_MAGIC   equ 0
NID_RECORD_VERSION equ 8
NID_RECORD_NONCE   equ 16
NID_RECORD_CIPHER  equ 32
NID_RECORD_TAG     equ 64
NID_RECORD_PUBLIC  equ 80
NID_RECORD_SIZE    equ 112

NID_AEAD_KEY       equ 0
NID_AEAD_NONCE     equ 8
NID_AEAD_AAD       equ 16
NID_AEAD_AAD_LEN   equ 24
NID_AEAD_INPUT     equ 32
NID_AEAD_INPUT_LEN equ 40
NID_AEAD_OUTPUT    equ 48
NID_AEAD_TAG       equ 56
NID_AEAD_REQ_SIZE  equ 64
NID_OWNER_SIZE     equ 24

NID_MAGIC_VALUE    equ 0x3144494e534f4150 ; "PAOSNID1" little-endian

nid_build_aad:
    push r12
    mov  r12, rdi                       ; record
    lea  rdi, [rel nid_aad]
    lea  rsi, [rel nid_aad_domain]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel nid_aad + 16]
    lea  rsi, [r12 + NID_RECORD_PUBLIC]
    mov  edx, 32
    call memcpy
    pop  r12
    ret

nid_record_header_valid:
    test rdi, rdi
    jz   .bad
    mov  rax, NID_MAGIC_VALUE
    cmp  [rdi + NID_RECORD_MAGIC], rax
    jne  .bad
    cmp  byte [rdi + NID_RECORD_VERSION], 1
    jne  .bad
    cmp  dword [rdi + 9], 0
    jne  .bad
    cmp  word [rdi + 13], 0
    jne  .bad
    cmp  byte [rdi + 15], 0
    jne  .bad
    cmp  dword [rdi + 28], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; nid_unwrap_seed(RDI=kek,RSI=kek_len,RDX=record,RCX=seed_out32) -> 0/-1.
; Authentication precedes public-key derivation and record commitment.
nid_unwrap_seed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rdx
    mov  r14, rcx
    test r12, r12
    jz   .fail
    cmp  rsi, 32
    jne  .fail
    test r14, r14
    jz   .fail
    mov  rdi, r13
    call nid_record_header_valid
    test eax, eax
    jz   .fail
    mov  rdi, r13
    call nid_build_aad
    mov  qword [rel nid_request + NID_AEAD_KEY], r12
    lea  rax, [r13 + NID_RECORD_NONCE]
    mov  [rel nid_request + NID_AEAD_NONCE], rax
    lea  rax, [rel nid_aad]
    mov  [rel nid_request + NID_AEAD_AAD], rax
    mov  qword [rel nid_request + NID_AEAD_AAD_LEN], 48
    lea  rax, [r13 + NID_RECORD_CIPHER]
    mov  [rel nid_request + NID_AEAD_INPUT], rax
    mov  qword [rel nid_request + NID_AEAD_INPUT_LEN], 32
    mov  [rel nid_request + NID_AEAD_OUTPUT], r14
    lea  rax, [r13 + NID_RECORD_TAG]
    mov  [rel nid_request + NID_AEAD_TAG], rax
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel nid_request]
    call aes256_gcm_unwrap_dek
    test eax, eax
    jnz  .fail
    mov  rdi, r14
    mov  esi, 32
    lea  rdx, [rel nid_public_check]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_public_check]
    lea  rsi, [r13 + NID_RECORD_PUBLIC]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .fail
    xor  ebx, ebx
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rel nid_public_check]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel nid_aad]
    xor  esi, esi
    mov  edx, 48
    call memset
    test ebx, ebx
    jz   .out
    test r14, r14
    jz   .out
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 32
    call memset
.out:
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Seal one seed into the private durable record.  This is deliberately not an
; exported API: production creation reaches it only after csprng_generate, and
; the deterministic self-test reaches it only with RFC 8032's published TEST 1
; seed.  Keeping the deterministic seam below node_identity_bootstrap prevents
; QEMU's entropy-less CPU model from becoming a production entropy fallback.
; nid_seal_seed(RDI=kek,RSI=kek_len,RDX=seed32,RCX=nonce12) -> 0/-1.
; SEC-S2-nonce: the GCM nonce is the caller's, never a constant. Production
; (nid_create) draws it from csprng_generate, so two records ever sealed under
; one KEK (a re-create after loss, a future rotation) never share (key, nonce).
; Only the self-tests pass nid_test_nonce. A null or all-zero nonce is refused.
nid_seal_seed:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rdx
    mov  r14, rcx
    cmp  rsi, 32
    jne  .fail
    test r12, r12
    jz   .fail
    test r13, r13
    jz   .fail
    test r14, r14
    jz   .fail
    mov  rax, [r14]
    or   eax, [r14 + 8]
    mov  rdx, [r14]
    shr  rdx, 32
    or   eax, edx
    jz   .fail                             ; all-zero nonce
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
    mov  rax, NID_MAGIC_VALUE
    mov  [rel nid_record + NID_RECORD_MAGIC], rax
    mov  byte [rel nid_record + NID_RECORD_VERSION], 1
    lea  rdi, [rel nid_record + NID_RECORD_NONCE]
    mov  rsi, r14
    mov  edx, 12
    call memcpy
    lea  rdi, [rel nid_seed_scratch]
    mov  rsi, r13
    mov  edx, 32
    call memcpy
    lea  rdi, [rel nid_seed_scratch]
    mov  esi, 32
    lea  rdx, [rel nid_record + NID_RECORD_PUBLIC]
    call ed25519_public_from_seed
    test eax, eax
    jnz  .fail_clear
    lea  rdi, [rel nid_record]
    call nid_build_aad
    lea  rdi, [rel nid_owner_state]
    xor  esi, esi
    mov  edx, NID_OWNER_SIZE
    call memset
    mov  qword [rel nid_request + NID_AEAD_KEY], r12
    lea  rax, [rel nid_record + NID_RECORD_NONCE]
    mov  [rel nid_request + NID_AEAD_NONCE], rax
    lea  rax, [rel nid_aad]
    mov  [rel nid_request + NID_AEAD_AAD], rax
    mov  qword [rel nid_request + NID_AEAD_AAD_LEN], 48
    lea  rax, [rel nid_seed_scratch]
    mov  [rel nid_request + NID_AEAD_INPUT], rax
    mov  qword [rel nid_request + NID_AEAD_INPUT_LEN], 32
    lea  rax, [rel nid_record + NID_RECORD_CIPHER]
    mov  [rel nid_request + NID_AEAD_OUTPUT], rax
    lea  rax, [rel nid_record + NID_RECORD_TAG]
    mov  [rel nid_request + NID_AEAD_TAG], rax
    lea  rdi, [rel nid_owner_state]
    lea  rsi, [rel nid_request]
    call aes256_gcm_wrap_dek
    test eax, eax
    jnz  .fail_clear
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_record + NID_RECORD_PUBLIC]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel nid_active_kek]
    mov  rsi, r12
    mov  edx, 32
    call memcpy
    mov  byte [rel nid_active_kek_valid], 1
    mov  byte [rel nid_runtime_valid], 1
    xor  ebx, ebx
    jmp  .wipe
.fail_clear:
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
.fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel nid_aad]
    xor  esi, esi
    mov  edx, 48
    call memset
    mov  eax, ebx
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Create the first production record.  There is no caller-provided seed and no
; degraded-mode fallback: failure of the keep CSPRNG leaves no identity record.
; Existing/corrupt records never silently rotate.
nid_create:
    push r12
    mov  r12, rdi
    cmp  rsi, 32
    jne  .fail
    test r12, r12
    jz   .fail
    lea  rdi, [rel nid_seed_scratch]
    mov  esi, 32
    call csprng_generate
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_nonce_scratch]      ; SEC-S2-nonce: a fresh 96-bit GCM nonce
    mov  esi, 12
    call csprng_generate
    test eax, eax
    jnz  .fail
    mov  rdi, r12
    mov  esi, 32
    lea  rdx, [rel nid_seed_scratch]
    lea  rcx, [rel nid_nonce_scratch]
    call nid_seal_seed
    pop  r12
    ret
.fail:
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
    pop  r12
    ret

; One-shot production key operation. RDI=public message96, RSI=96,
; RDX=public32||signature64 output (distinct, keep-owned extent) -> 0/-1.
; No seed input, envelope import, installed identity mutation or durable write.
; Caller is the serialized BSP command owner, as for the other Ed25519 users.
nid_fresh_health:
    sub rsp, 8
    call csprng_status_snapshot
    add rsp, 8
    cmp eax, 1                         ; CSPRNG_READY
    jne .bad
    test rdx, rdx                      ; no recorded source failure
    jnz .bad
    cmp r8d, 1                         ; provider initialized
    jne .bad
    cmp r9d, 1                         ; KAT passed
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; Reject the compiled RFC fixtures and the installed node identity, rather
; than allowing a fixture or an active-key signature to masquerade as creation.
nid_fresh_public_allowed:
    push rdi
    lea rsi, [rel nid_fresh_fixture_public1]
    call nid_fresh_equal32
    test eax, eax
    jnz .bad
    lea rsi, [rel nid_fresh_fixture_public2]
    call nid_fresh_equal32
    test eax, eax
    jnz .bad
    cmp byte [rel nid_runtime_valid], 1
    jne .ok
    lea rsi, [rel nid_runtime_public]
    call nid_fresh_equal32
    test eax, eax
    jnz .bad
.ok:
    xor eax, eax
    pop rdi
    ret
.bad:
    mov eax, -1
    pop rdi
    ret

nid_fresh_equal32:                      ; public bytes, preserves RDI
    xor ecx, ecx
    xor r8d, r8d
.loop:
    mov al, [rdi+rcx]
    xor al, [rsi+rcx]
    movzx eax, al
    or r8d, eax
    inc ecx
    cmp ecx, 32
    jb .loop
    xor eax, eax
    test r8d, r8d
    sete al
    ret

node_identity_generate_proof:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rdx
    mov r14, rsi
    mov ebx, -1
    test r13, r13
    jz .wipe
    mov rdi, r13
    xor esi, esi
    mov edx, 96
    call memset
    test r12, r12
    jz .wipe
    cmp r14, 96
    jne .wipe
    call nid_fresh_health
    test eax, eax
    jnz .wipe
    lea rdi, [rel nid_seed_scratch]
    mov esi, 32
    call csprng_generate
    test eax, eax
    jnz .wipe
    lea rdi, [rel nid_seed_scratch]
    mov esi, 32
    mov rdx, r13
    call ed25519_public_from_seed
    test eax, eax
    jnz .wipe
    mov rdi, r13
    call nid_fresh_public_allowed
    test eax, eax
    jnz .wipe
    lea rdi, [rel nid_seed_scratch]
    mov esi, 32
    mov rdx, r12
    mov ecx, 96
    lea r8, [r13+32]
    mov r9d, 64
    call ed25519_sign
    test eax, eax
    jnz .wipe
    mov rdi, r13
    mov esi, 32
    mov rdx, r12
    mov ecx, 96
    lea r8, [r13+32]
    mov r9d, 64
    call ed25519_verify
    test eax, eax
    jnz .wipe
    lea rdi, [rel nid_fresh_message]
    mov rsi, r12
    mov edx, 96
    call memcpy
    xor byte [rel nid_fresh_message+56], 1 ; altered challenge must refuse
    mov rdi, r13
    mov esi, 32
    lea rdx, [rel nid_fresh_message]
    mov ecx, 96
    lea r8, [r13+32]
    mov r9d, 64
    call ed25519_verify
    test eax, eax
    jz .wipe
    call nid_fresh_health
    test eax, eax
    jnz .wipe
    xor ebx, ebx
.wipe:
    lea rdi, [rel nid_seed_scratch]
    xor esi, esi
    mov edx, 32
    call memset
    ; Primitive error exits are also wiped; no source/crypto fault leaves an
    ; expanded secret behind. The helpers themselves export no private bytes.
    call ed_wipe_secret_scratch
    lea rdi, [rel nid_fresh_message]
    xor esi, esi
    mov edx, 96
    call memset
    test ebx, ebx
    jz .out
    test r13, r13
    jz .out
    mov rdi, r13
    xor esi, esi
    mov edx, 96
    call memset
.out:
    mov eax, ebx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

node_identity_bootstrap:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    cmp  qword [rel nid_record + NID_RECORD_MAGIC], 0
    jne  .load_existing
    mov  rdi, r12
    mov  rsi, r13
    call nid_create
    jmp  .done
.load_existing:
    lea  rdi, [rel nid_record]
    mov  esi, NID_RECORD_SIZE
    mov  rdx, r12
    mov  rcx, r13
    call node_identity_envelope_import
.done:
    pop  r13
    pop  r12
    ret

node_identity_clear_runtime:
    mov  byte [rel nid_runtime_valid], 0
    mov  byte [rel nid_active_kek_valid], 0
    lea  rdi, [rel nid_runtime_public]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel nid_active_kek]
    xor  esi, esi
    mov  edx, 32
    call memset
    xor  eax, eax
    ret

; Return 1 only for the runtime-valid state accepted by node_identity_public.
; Observers must not infer Ed25519 enrollment from the RSA owner key id.
node_identity_active:
    xor  eax, eax
    cmp  byte [rel nid_runtime_valid], 1
    sete al
    ret

node_identity_public:
    test rdi, rdi
    jz   .bad
    cmp  rsi, 32
    jne  .bad
    cmp  byte [rel nid_runtime_valid], 1
    jne  .bad
    lea  rsi, [rel nid_runtime_public]
    mov  edx, 32
    call memcpy
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

node_identity_envelope_export:
    test rdi, rdi
    jz   .bad
    cmp  rsi, NID_RECORD_SIZE
    jne  .bad
    push rdi
    lea  rdi, [rel nid_record]
    call nid_record_header_valid
    pop  rdi
    test eax, eax
    jz   .bad
    lea  rsi, [rel nid_record]
    mov  edx, NID_RECORD_SIZE
    call memcpy
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; envelope_import(record,len,kek,kek_len) authenticates before commit.
node_identity_envelope_import:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rdx
    mov  r14, rcx
    cmp  rsi, NID_RECORD_SIZE
    jne  .fail
    test r12, r12
    jz   .fail
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, r12
    lea  rcx, [rel nid_seed_scratch]
    call nid_unwrap_seed
    test eax, eax
    jnz  .fail
    ; Import may source nid_record itself; memmove semantics are unnecessary for
    ; exact self-copy and external records do not overlap this private object.
    lea  rdi, [rel nid_record]
    mov  rsi, r12
    mov  edx, NID_RECORD_SIZE
    call memcpy
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_record + NID_RECORD_PUBLIC]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel nid_active_kek]
    mov  rsi, r13
    mov  edx, 32
    call memcpy
    mov  byte [rel nid_active_kek_valid], 1
    mov  byte [rel nid_runtime_valid], 1
    xor  ebx, ebx
    jmp  .wipe
.fail:
    call node_identity_clear_runtime
    mov  ebx, -1
.wipe:
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, ebx
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; sign(kek,kek_len,msg,msg_len,sig,sig_len) unwraps only for this operation.
node_identity_sign:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, r9
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    cmp  rsi, 32
    jne  .fail
    cmp  r13, 64
    jne  .fail
    cmp  byte [rel nid_runtime_valid], 1
    jne  .fail
    mov  rdi, r12
    mov  esi, 32
    lea  rdx, [rel nid_record]
    lea  rcx, [rel nid_seed_scratch]
    call nid_unwrap_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_seed_scratch]
    mov  esi, 32
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, rbx
    mov  r9, r13
    call ed25519_sign
    mov  ebx, eax
    jmp  .wipe
.fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; node_identity_sign_active(RDI=msg,RSI=msg_len,RDX=sig64,RCX=sig_len)
; signs through the keep-owned active identity.  Callers never receive the KEK
; or plaintext seed; node_identity_sign unwraps into the serialized scratch and
; wipes it on every exit.
node_identity_sign_active:
    cmp  byte [rel nid_active_kek_valid], 1
    jne  .bad
    ; A validity byte is state, not authorization.  Refuse either compiled KAT
    ; half independently even if another path accidentally publishes an
    ; otherwise coherent identity around it.
    mov  rax, [rel nid_active_kek]
    xor  rax, [rel nid_test_kek]
    mov  r10, [rel nid_active_kek + 8]
    xor  r10, [rel nid_test_kek + 8]
    or   rax, r10
    mov  r10, [rel nid_active_kek + 16]
    xor  r10, [rel nid_test_kek + 16]
    or   rax, r10
    mov  r10, [rel nid_active_kek + 24]
    xor  r10, [rel nid_test_kek + 24]
    or   rax, r10
    jz   .bad
    mov  rax, [rel nid_runtime_public]
    xor  rax, [rel nid_fresh_fixture_public1]
    mov  r10, [rel nid_runtime_public + 8]
    xor  r10, [rel nid_fresh_fixture_public1 + 8]
    or   rax, r10
    mov  r10, [rel nid_runtime_public + 16]
    xor  r10, [rel nid_fresh_fixture_public1 + 16]
    or   rax, r10
    mov  r10, [rel nid_runtime_public + 24]
    xor  r10, [rel nid_fresh_fixture_public1 + 24]
    or   rax, r10
    jz   .bad
    mov  r9, rcx
    mov  r8, rdx
    mov  rdx, rdi
    mov  rcx, rsi
    lea  rdi, [rel nid_active_kek]
    mov  esi, 32
    jmp  node_identity_sign
.bad:
    mov  eax, -1
    ret

; verify(msg,msg_len,sig,sig_len) against the stable public identity.
node_identity_verify:
    cmp  byte [rel nid_runtime_valid], 1
    jne  .bad
    mov  r9, rcx
    mov  r8, rdx
    mov  rcx, rsi
    mov  rdx, rdi
    mov  esi, 32
    lea  rdi, [rel nid_runtime_public]
    jmp  ed25519_verify
.bad:
    mov  eax, -1
    ret

nid_hex_public:
    lea  r8, [rel nid_hex_digits]
    lea  r9, [rel nid_runtime_public]
    lea  r10, [rel nid_public_hex]
    xor  ecx, ecx
.loop:
    movzx eax, byte [r9 + rcx]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    mov  al, [r8 + rax]
    mov  [r10 + rcx*2], al
    mov  dl, [r8 + rdx]
    mov  [r10 + rcx*2 + 1], dl
    inc  ecx
    cmp  ecx, 32
    jb   .loop
    mov  byte [r10 + 64], 0
    ret

; Return 1 only if the 32-byte seed occurs verbatim in the opaque record.
nid_record_contains_seed:
    lea  r9, [rel nid_disk_image]
    lea  r10, [rel nid_seed_scratch]
    xor  ecx, ecx
.offset:
    lea  r11, [r9 + rcx]
    xor  eax, eax
    xor  edx, edx
.byte:
    mov  r8b, [r11 + rdx]
    xor  r8b, [r10 + rdx]
    or   al, r8b
    inc  edx
    cmp  edx, 32
    jb   .byte
    test al, al
    jz   .yes
    inc  ecx
    cmp  ecx, NID_RECORD_SIZE - 31
    jb   .offset
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

node_identity_selftest:
    push rbx
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
    call node_identity_clear_runtime
    call node_identity_active
    test eax, eax
    jnz  .fail
    ; no_bootstrap_refusal: an unprovisioned boot must not sign.
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jz   .fail
    ; The standard QEMU CPU intentionally has no live entropy provider (the
    ; CSPRNG contract marks service-ready hardware-only).  Exercise the exact
    ; same public-key derivation, authenticated sealing, reload, and hostile
    ; envelope paths with RFC 8032 TEST 1's published seed.  Production callers
    ; cannot select this path: node_identity_bootstrap -> nid_create always
    ; obtains its seed from csprng_generate and fails closed otherwise.
    lea  rdi, [rel nid_test_kek]
    mov  esi, 32
    lea  rdx, [rel ed_test_seed1]
    lea  rcx, [rel nid_test_nonce]
    call nid_seal_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_expected_public]
    mov  esi, 32
    call node_identity_public
    test eax, eax
    jnz  .fail
    call node_identity_active
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel nid_disk_image]
    mov  esi, NID_RECORD_SIZE
    call node_identity_envelope_export
    test eax, eax
    jnz  .fail

    ; Demonstrate that the durable record contains no plaintext seed bytes.
    lea  rdi, [rel nid_test_kek]
    mov  esi, 32
    lea  rdx, [rel nid_disk_image]
    lea  rcx, [rel nid_seed_scratch]
    call nid_unwrap_seed
    test eax, eax
    jnz  .fail
    call nid_record_contains_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset

    ; Simulated reboot: only exported durable bytes survive.
    call node_identity_clear_runtime
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
    lea  rdi, [rel nid_record]
    lea  rsi, [rel nid_disk_image]
    mov  edx, NID_RECORD_SIZE
    call memcpy
    lea  rdi, [rel nid_test_kek]
    mov  esi, 32
    call node_identity_bootstrap
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_expected_public]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .fail

    ; Ciphertext alteration authenticates to nothing and publishes no identity.
    lea  rdi, [rel nid_bad_record]
    lea  rsi, [rel nid_disk_image]
    mov  edx, NID_RECORD_SIZE
    call memcpy
    xor  byte [rel nid_bad_record + NID_RECORD_CIPHER + 7], 0x80
    lea  rdi, [rel nid_bad_record]
    mov  esi, NID_RECORD_SIZE
    lea  rdx, [rel nid_test_kek]
    mov  ecx, 32
    call node_identity_envelope_import
    test eax, eax
    jz   .fail
    cmp  byte [rel nid_runtime_valid], 0
    jne  .fail

    ; Wrong wrapping key likewise refuses before plaintext release.
    lea  rdi, [rel nid_disk_image]
    mov  esi, NID_RECORD_SIZE
    lea  rdx, [rel nid_wrong_kek]
    mov  ecx, 32
    call node_identity_envelope_import
    test eax, eax
    jz   .fail
    cmp  byte [rel nid_runtime_valid], 0
    jne  .fail

    ; Restore the authenticated record and prove the public identity is stable.
    lea  rdi, [rel nid_disk_image]
    mov  esi, NID_RECORD_SIZE
    lea  rdx, [rel nid_test_kek]
    mov  ecx, 32
    call node_identity_envelope_import
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_expected_public]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .fail

    ; The stable identity APIs sign only after authenticated unwrap and verify
    ; through the published key.  A wrong KEK never reaches the signer.
    lea  rdi, [rel nid_test_kek]
    mov  esi, 32
    lea  rdx, [rel nid_test_message]
    mov  ecx, 17
    lea  r8, [rel nid_test_signature]
    mov  r9d, 64
    call node_identity_sign
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_verify
    test eax, eax
    jnz  .fail
    xor  byte [rel nid_test_message], 1
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_verify
    xor  byte [rel nid_test_message], 1
    test eax, eax
    jz   .fail
    lea  rdi, [rel nid_wrong_kek]
    mov  esi, 32
    lea  rdx, [rel nid_test_message]
    mov  ecx, 17
    lea  r8, [rel nid_test_signature]
    mov  r9d, 64
    call node_identity_sign
    test eax, eax
    jz   .fail

    ; test_key_refusal, public half: seal the RFC seed under a non-test KEK.
    ; The record is authenticated and active, so only the explicit public-key
    ; guard can make this refusal pass.
    lea  rdi, [rel nid_wrong_kek]
    mov  esi, 32
    lea  rdx, [rel ed_test_seed1]
    lea  rcx, [rel nid_test_nonce]
    call nid_seal_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jz   .fail

    ; test_key_refusal, KEK half: pair the compiled KAT KEK with a non-test
    ; public identity.  This independently proves the KEK guard is effective.
    lea  rdi, [rel nid_test_kek]
    mov  esi, 32
    lea  rdx, [rel nid_wrong_kek]
    lea  rcx, [rel nid_test_nonce]
    call nid_seal_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_fresh_fixture_public1]
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .fail
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jz   .fail

    ; fresh_bootstrap_positive: build a distinct artificial record for QEMU,
    ; clear the live view, reload through the public bootstrap path, then sign
    ; and verify.  A permanent refusal cannot satisfy this positive gate.
    lea  rdi, [rel nid_wrong_kek]
    mov  esi, 32
    lea  rdx, [rel nid_wrong_kek]
    lea  rcx, [rel nid_test_nonce]
    call nid_seal_seed
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_fresh_fixture_public1]
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .fail
    call node_identity_clear_runtime
    lea  rdi, [rel nid_wrong_kek]
    mov  esi, 32
    call node_identity_bootstrap
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_verify
    test eax, eax
    jnz  .fail
    call nid_hex_public
    lea  rdi, [rel str_nid_prefix]
    call serial_string
    lea  rdi, [rel nid_public_hex]
    call serial_string
    lea  rdi, [rel str_nid_tail]
    call serial_string
    lea  rdi, [rel str_nid_marker]
    call serial_string
    ; Successful selftest publication occurs only after the artificial active
    ; identity is gone and the no-identity signing refusal is re-observed.
    call node_identity_clear_runtime
    call node_identity_active
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nid_test_message]
    mov  esi, 17
    lea  rdx, [rel nid_test_signature]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jz   .fail
    lea  rdi, [rel str_nid_security_marker]
    call serial_string
    xor  ebx, ebx
    jmp  .done
.fail:
    lea  rdi, [rel str_nid_fail]
    call serial_string
    mov  ebx, -1
.done:
    ; Every exit leaves neither active state nor a synthetic durable record
    ; which could block a later real owner bootstrap.
    call node_identity_clear_runtime
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
    lea  rdi, [rel nid_disk_image]
    xor  esi, esi
    mov  edx, (NID_RECORD_SIZE * 2) + 32
    call memset
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, ebx
    pop  rbx
    ret

; Run an established consumer KAT under a separate fresh, non-forbidden
; identity fixture.  This keeps node_identity_selftest's security verdict in
; the early crypto window while preserving later signed-receipt coverage.
; RDI=callback returning 0/-1.  Synthetic state is cleared on every normal
; exit; the explicitly named negative-build fixture below is the sole exception.
node_identity_selftest_consumer:
    push rbx
    push r12
    push r13                         ; preserve 16-byte call alignment
    mov  r12, rdi
    test r12, r12
    jz   .fail
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
    call node_identity_clear_runtime
    lea  rdi, [rel nid_wrong_kek]
    mov  esi, 32
    lea  rdx, [rel nid_wrong_kek]
    lea  rcx, [rel nid_test_nonce]
    call nid_seal_seed
    test eax, eax
    jnz  .fail
    call node_identity_clear_runtime
    lea  rdi, [rel nid_wrong_kek]
    mov  esi, 32
    call node_identity_bootstrap
    test eax, eax
    jnz  .fail
    call r12
    mov  ebx, eax
    jmp  .done
.fail:
    mov  ebx, -1
.done:
    call node_identity_clear_runtime
    lea  rdi, [rel nid_record]
    xor  esi, esi
    mov  edx, NID_RECORD_SIZE
    call memset
    lea  rdi, [rel nid_seed_scratch]
    xor  esi, esi
    mov  edx, 32
    call memset
%ifdef PAOS_NODE_IDENTITY_TEST_ACTIVE_FIXTURE
    ; JOBPUB is registered by the successful consumer callback above.  Only
    ; the negative QEMU build now reactivates RFC8032 TEST 1 and deliberately
    ; leaves it visible for command_auth's production AUTHSTAT/JOBPUB fixture.
    test ebx, ebx
    jnz  .fixture_done
    lea  rdi, [rel nid_test_kek]
    mov  esi, 32
    lea  rdx, [rel ed_test_seed1]
    lea  rcx, [rel nid_test_nonce]
    call nid_seal_seed
    test eax, eax
    jnz  .fixture_fail
    call node_identity_active
    cmp  eax, 1
    jne  .fixture_fail
    lea  rdi, [rel nid_runtime_public]
    lea  rsi, [rel nid_fresh_fixture_public1]
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .fixture_done
.fixture_fail:
    call node_identity_clear_runtime
    mov  ebx, -1
.fixture_done:
%endif
    mov  eax, ebx
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_sec_node_identity_0 0
align 16
; Public RFC8032 test-vector denylist, never a seed/signing fallback.
nid_fresh_fixture_public1: db 0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a
                 db 0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
nid_fresh_fixture_public2: db 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc
                 db 0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c
align 16
nid_fresh_message: times 96 db 0
nid_record:         times NID_RECORD_SIZE db 0
nid_runtime_public: times 32 db 0
nid_runtime_valid:  db 0
align 8
nid_active_kek:     times 32 db 0
nid_active_kek_valid: db 0
align 8
nid_request:        times NID_AEAD_REQ_SIZE db 0
nid_owner_state:    times NID_OWNER_SIZE db 0
nid_seed_scratch:   times 32 db 0
nid_nonce_scratch:  times 12 db 0          ; SEC-S2-nonce: nid_create's fresh nonce
nid_public_check:   times 32 db 0
nid_aad:            times 48 db 0

nid_aad_domain: db "PaOS-node-id-v1!"
nid_test_nonce: db 0,0,0,0,0,0,0,0,0,0,0,1 ; SELF-TEST ONLY (fixed vectors); production never seals with it
nid_hex_digits: db "0123456789abcdef"
nid_public_hex: times 65 db 0

nid_test_kek: db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
              db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
              db 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27
              db 0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
nid_wrong_kek: times 31 db 0
               db 1
nid_disk_image:     times NID_RECORD_SIZE db 0
nid_bad_record:     times NID_RECORD_SIZE db 0
nid_expected_public: times 32 db 0
nid_test_message: db "node-identity-kat"
nid_test_signature: times 64 db 0

str_nid_prefix: db "IDENTITY_KAT NODE_WRAP public=",0
str_nid_tail: db " fixture_seed=rfc8032_test1 export_import=matched envelope_tamper=refused wrong_kek=refused seed_absent_from_record=1 PASS",13,10,0
str_nid_marker: db "[PAOS64] P2 identity: node private seed wrapped [identity.node.wrapped]",13,10,0
str_nid_security_marker: db "[PAOS64] M6 security: test identity cleared and active signer test-key refusal PASS [security.node_identity.no_test_key]",13,10,0
str_nid_fail: db "[PAOS64] P2 identity: node envelope KAT FAIL (marker withheld)",13,10,0
%endmacro
WDATA_DEFER WDATA_sec_node_identity_0
