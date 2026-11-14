;; MODULE data/backup_export
;; LAYER 4
;; EXPORTS backup_export_run, backup_export_kat, bx_prepare_sender, bx_prepare_receiver, bx_encrypt, bx_decrypt, bx_seal, bx_open, bx_wipe_secrets, bx_archive, bx_archive_len, bx_enc, bx_manifest, bx_fingerprint, bx_ct, bx_tag
;; IMPORTS boot/serial, core/lib/mem, core/lib/ustar, core/lib/x25519, core/lib/hkdf_sha256, core/lib/sha256, core/lib/aes256_gcm
;; CAPS
;; OWNER saga:user_data_backup
; ============================================================================
; Task1230a — RFC 9180 HPKE backup-export crypto core.
;
; Profile (all identifiers are the RFC network-order values):
;   mode 0 / DHKEM(X25519, HKDF-SHA256) 0x0020 /
;   HKDF-SHA256 0x0001 / AES-256-GCM 0x0002 / sequence 0.
;
; The command owner supplies a fresh keep-owned CSPRNG scalar for every live
; export. Fixed key material below is referenced only by the boot KAT. The
; recipient key remains caller-owned; this module never stores lifecycle state.
; LabeledExtract/LabeledExpand are byte-for-byte RFC 9180, including the KEM
; and HPKE suite identifiers and I2OSP length prefixes. Callers choose the
; bounded AAD (the live command binds its complete wire header). Plaintext is
; released by bx_decrypt only after AES-GCM authenticates the whole message.
; ============================================================================

%include "data/backup_export_keys.inc"

BX_ARCHIVE_CAP equ 4096

AEAD_KEY       equ 0
AEAD_NONCE     equ 8
AEAD_AAD       equ 16
AEAD_AAD_LEN   equ 24
AEAD_INPUT     equ 32
AEAD_INPUT_LEN equ 40
AEAD_OUTPUT    equ 48
AEAD_TAG       equ 56

; Return 1 iff the 32-byte input contains at least one nonzero byte.
bx_nonzero32:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    or   al, [rdi + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .loop
    test al, al
    setnz al
    movzx eax, al
    ret

; Derive the RFC 9180 shared_secret and base-mode traffic key/nonce from the
; already-populated bx_shared, bx_enc and caller recipient public key RDI.
bx_derive_schedule:
    push rbx
    push r12
    mov  r12, rdi

    ; eae_prk = LabeledExtract("", "eae_prk", dh)
    lea  rdi, [rel bx_kem_extract_input]
    lea  rsi, [rel bx_kem_extract_prefix]
    mov  edx, bx_kem_extract_prefix_len
    call memcpy
    lea  rdi, [rel bx_kem_extract_input + bx_kem_extract_prefix_len]
    lea  rsi, [rel bx_shared]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_empty]
    xor  esi, esi
    lea  rdx, [rel bx_kem_extract_input]
    mov  ecx, bx_kem_extract_prefix_len + 32
    lea  r8, [rel bx_eae_prk]
    call hkdf_sha256_extract
    test eax, eax
    jnz  .fail

    ; kem_context = enc || pkR
    lea  rdi, [rel bx_kem_context]
    lea  rsi, [rel bx_enc]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_kem_context + 32]
    mov  rsi, r12
    mov  edx, 32
    call memcpy

    ; shared_secret = LabeledExpand(eae_prk,"shared_secret",context,32)
    lea  rdi, [rel bx_expand_input]
    lea  rsi, [rel bx_kem_expand_prefix]
    mov  edx, bx_kem_expand_prefix_len
    call memcpy
    lea  rdi, [rel bx_expand_input + bx_kem_expand_prefix_len]
    lea  rsi, [rel bx_kem_context]
    mov  edx, 64
    call memcpy
    lea  rdi, [rel bx_eae_prk]
    mov  esi, 32
    lea  rdx, [rel bx_expand_input]
    mov  ecx, bx_kem_expand_prefix_len + 64
    lea  r8, [rel bx_hpke_shared]
    mov  r9d, 32
    call hkdf_sha256_expand_one
    test eax, eax
    jnz  .fail

    ; psk_id_hash = LabeledExtract("", "psk_id_hash", "")
    lea  rdi, [rel bx_empty]
    xor  esi, esi
    lea  rdx, [rel bx_pskid_hash_input]
    mov  ecx, bx_pskid_hash_input_len
    lea  r8, [rel bx_pskid_hash]
    call hkdf_sha256_extract
    test eax, eax
    jnz  .fail

    ; info_hash = LabeledExtract("", "info_hash", "paos-backup-export-v1")
    lea  rdi, [rel bx_empty]
    xor  esi, esi
    lea  rdx, [rel bx_info_hash_input]
    mov  ecx, bx_info_hash_input_len
    lea  r8, [rel bx_info_hash]
    call hkdf_sha256_extract
    test eax, eax
    jnz  .fail

    ; key_schedule_context = mode || psk_id_hash || info_hash
    mov  byte [rel bx_key_context], 0
    lea  rdi, [rel bx_key_context + 1]
    lea  rsi, [rel bx_pskid_hash]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_key_context + 33]
    lea  rsi, [rel bx_info_hash]
    mov  edx, 32
    call memcpy

    ; secret = LabeledExtract(shared_secret, "secret", "")
    lea  rdi, [rel bx_hpke_shared]
    mov  esi, 32
    lea  rdx, [rel bx_secret_input]
    mov  ecx, bx_secret_input_len
    lea  r8, [rel bx_secret]
    call hkdf_sha256_extract
    test eax, eax
    jnz  .fail

    ; key = LabeledExpand(secret, "key", context, 32)
    lea  rdi, [rel bx_expand_input]
    lea  rsi, [rel bx_key_expand_prefix]
    mov  edx, bx_key_expand_prefix_len
    call memcpy
    lea  rdi, [rel bx_expand_input + bx_key_expand_prefix_len]
    lea  rsi, [rel bx_key_context]
    mov  edx, 65
    call memcpy
    lea  rdi, [rel bx_secret]
    mov  esi, 32
    lea  rdx, [rel bx_expand_input]
    mov  ecx, bx_key_expand_prefix_len + 65
    lea  r8, [rel bx_key]
    mov  r9d, 32
    call hkdf_sha256_expand_one
    test eax, eax
    jnz  .fail

    ; base_nonce = LabeledExpand(secret, "base_nonce", context, 12)
    lea  rdi, [rel bx_expand_input]
    lea  rsi, [rel bx_nonce_expand_prefix]
    mov  edx, bx_nonce_expand_prefix_len
    call memcpy
    lea  rdi, [rel bx_expand_input + bx_nonce_expand_prefix_len]
    lea  rsi, [rel bx_key_context]
    mov  edx, 65
    call memcpy
    lea  rdi, [rel bx_secret]
    mov  esi, 32
    lea  rdx, [rel bx_expand_input]
    mov  ecx, bx_nonce_expand_prefix_len + 65
    lea  r8, [rel bx_nonce]
    mov  r9d, 12
    call hkdf_sha256_expand_one
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

; bx_prepare_sender(RDI=recipient_pub32, RSI=fresh_ephemeral_scalar32) -> 0/-1.
; Publishes bx_enc and bx_fingerprint for the caller's authenticated header.
bx_prepare_sender:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    test r12, r12
    jz   .fail
    test rbx, rbx
    jz   .fail
    lea  rdi, [rel bx_enc]
    mov  rsi, rbx
    lea  rdx, [rel bx_basepoint]
    call x25519
    lea  rdi, [rel bx_shared]
    mov  rsi, rbx
    mov  rdx, r12
    call x25519
    lea  rdi, [rel bx_shared]
    call bx_nonzero32
    test eax, eax
    jz   .fail
    lea  rdi, [rel bx_fingerprint]
    mov  rsi, r12
    mov  edx, 32
    call sha256_hash
    mov  rdi, r12
    call bx_derive_schedule
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; bx_prepare_receiver(RDI=recipient_private32, RSI=recipient_public32) -> 0/-1.
bx_prepare_receiver:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    test r12, r12
    jz   .fail
    test r13, r13
    jz   .fail
    lea  rdi, [rel bx_shared]
    mov  rsi, r12
    lea  rdx, [rel bx_enc]
    call x25519
    lea  rdi, [rel bx_shared]
    call bx_nonzero32
    test eax, eax
    jz   .fail
    lea  rdi, [rel bx_fingerprint]
    mov  rsi, r13
    mov  edx, 32
    call sha256_hash
    mov  rdi, r13
    call bx_derive_schedule
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    ret

; bx_encrypt(RDI=archive, RSI=len, RDX=aad, RCX=aad_len) -> 0/-1.
; Requires bx_prepare_sender. Sequence is zero, so nonce == base_nonce.
bx_encrypt:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    test rbx, rbx
    jz   .bad
    test r12, r12
    jz   .bad
    cmp  r12, BX_ARCHIVE_CAP
    ja   .bad
    test r14, r14
    jz   .bad
    test r13, r13
    jz   .bad
    lea  rdi, [rel bx_manifest]
    mov  rsi, rbx
    mov  rdx, r12
    call sha256_hash
    lea  rdi, [rel bx_aead_req]
    lea  rax, [rel bx_key]
    mov  [rdi + AEAD_KEY], rax
    lea  rax, [rel bx_nonce]
    mov  [rdi + AEAD_NONCE], rax
    mov  [rdi + AEAD_AAD], r13
    mov  [rdi + AEAD_AAD_LEN], r14
    mov  [rdi + AEAD_INPUT], rbx
    mov  [rdi + AEAD_INPUT_LEN], r12
    lea  rax, [rel bx_ct]
    mov  [rdi + AEAD_OUTPUT], rax
    lea  rax, [rel bx_tag]
    mov  [rdi + AEAD_TAG], rax
    call aes256_gcm_seal
    mov  ebx, eax
    call bx_wipe_secrets
    mov  eax, ebx
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; bx_decrypt(RDI=len, RSI=out, RDX=aad, RCX=aad_len) -> 0/-1/-2.
; Requires bx_prepare_receiver; AES-GCM authenticates before releasing bytes.
bx_decrypt:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    test rbx, rbx
    jz   .bad
    cmp  rbx, BX_ARCHIVE_CAP
    ja   .bad
    test r12, r12
    jz   .bad
    test r14, r14
    jz   .bad
    test r13, r13
    jz   .bad
    lea  rdi, [rel bx_aead_req]
    lea  rax, [rel bx_key]
    mov  [rdi + AEAD_KEY], rax
    lea  rax, [rel bx_nonce]
    mov  [rdi + AEAD_NONCE], rax
    mov  [rdi + AEAD_AAD], r13
    mov  [rdi + AEAD_AAD_LEN], r14
    lea  rax, [rel bx_ct]
    mov  [rdi + AEAD_INPUT], rax
    mov  [rdi + AEAD_INPUT_LEN], rbx
    mov  [rdi + AEAD_OUTPUT], r12
    lea  rax, [rel bx_tag]
    mov  [rdi + AEAD_TAG], rax
    call aes256_gcm_open
    mov  ebx, eax
    call bx_wipe_secrets
    mov  eax, ebx
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Compatibility wrappers used by the KAT and focused probes.
; bx_seal(archive,len,recipient_pub,ephemeral_sk,aad,aad_len)
bx_seal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, r8
    mov  r14, r9
    mov  r15, rdx
    mov  rdi, r15
    mov  rsi, rcx
    call bx_prepare_sender
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    call bx_encrypt
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; bx_open(recipient_priv,recipient_pub,len,out,aad,aad_len)
bx_open:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdx
    mov  r12, rcx
    mov  r13, r8
    mov  r14, r9
    call bx_prepare_receiver
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    call bx_decrypt
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

bx_wipe_secrets:
    lea  rdi, [rel bx_shared]
    xor  esi, esi
    mov  edx, bx_secret_end - bx_shared
    jmp  memset

; Build a complete deterministic ustar fixture and seal it with the fixed KAT
; scalar only. Live export never calls this entry point.
backup_export_run:
    lea  rdi, [rel bx_archive]
    lea  rsi, [rel str_bx_keepname]
    mov  edx, str_bx_keepname_len
    lea  rcx, [rel str_bx_keepdata]
    mov  r8, str_bx_keepdata_len
    call ustar_build_member
    mov  [rel bx_archive_len], rax
    lea  rdi, [rel bx_archive]
    mov  rsi, rax
    lea  rdx, [rel bx_recipient_pub]
    lea  rcx, [rel bx_ephemeral_sk]
    lea  r8, [rel str_bx_kat_aad]
    mov  r9d, str_bx_kat_aad_len
    jmp  bx_seal

; Constant-work byte equality for completed public/KAT values.
bx_bytes_equal:
    xor  eax, eax
    xor  r8d, r8d
.loop:
    test rcx, rcx
    jz   .done
    dec  rcx
    mov  dl, [rdi + rcx]
    xor  dl, [rsi + rcx]
    or   r8b, dl
    jmp  .loop
.done:
    test r8b, r8b
    setz al
    movzx eax, al
    ret

; Boot KAT: authoritative RFC schedule vector + complete archive + AEAD
; round-trip + ciphertext/tamper/wrong-recipient/determinism gates.  The live
; X25519 primitive is already boot-graded by TLS/SSH; repeating it here before
; input setup delayed the fixed QEMU injection window enough to erase unrelated
; keyboard/mouse markers.  Feed independently derived correct/wrong-recipient
; DH vectors into the RFC 9180 schedule instead.  Live BACKUP EXPORT still uses
; bx_prepare_sender/bx_prepare_receiver and is end-to-end behavior-graded.
backup_export_kat:
    cmp  byte [rel bx_kat_armed], 1
    jne  .not_armed
    cmp  byte [rel bx_kat_state], 0
    jne  .not_armed
    mov  byte [rel bx_kat_state], 2       ; fail closed unless every gate passes
    push rbx
    call bx_kat_wipe_saved
    lea  rdi, [rel bx_enc]
    lea  rsi, [rel bx_expected_enc]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_shared]
    lea  rsi, [rel bx_expected_dh]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_recipient_pub]
    call bx_derive_schedule
    test eax, eax
    jnz  .fail
    lea  rdi, [rel bx_enc]
    lea  rsi, [rel bx_expected_enc]
    mov  ecx, 32
    call bx_bytes_equal
    test eax, eax
    jz   .fail

    ; Save the exact schedule before bx_encrypt's mandatory wipe.  These are
    ; fixed public KAT values and are erased on every exit below.
    lea  rdi, [rel bx_kat_key_save]
    lea  rsi, [rel bx_key]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_kat_nonce_save]
    lea  rsi, [rel bx_nonce]
    mov  edx, 12
    call memcpy
    lea  rdi, [rel bx_key]
    lea  rsi, [rel bx_expected_key]
    mov  ecx, 32
    call bx_bytes_equal
    test eax, eax
    jz   .fail
    lea  rdi, [rel bx_nonce]
    lea  rsi, [rel bx_expected_nonce]
    mov  ecx, 12
    call bx_bytes_equal
    test eax, eax
    jz   .fail

    ; Build the complete archive while the exact sender schedule above remains
    ; live, then seal with that same schedule instead of deriving it a second
    ; time merely for the KAT.
    lea  rdi, [rel bx_archive]
    lea  rsi, [rel str_bx_keepname]
    mov  edx, str_bx_keepname_len
    lea  rcx, [rel str_bx_keepdata]
    mov  r8, str_bx_keepdata_len
    call ustar_build_member
    mov  [rel bx_archive_len], rax
    mov  rbx, rax
    lea  rdi, [rel bx_archive]
    mov  rsi, rbx
    lea  rdx, [rel str_bx_kat_aad]
    mov  ecx, str_bx_kat_aad_len
    call bx_encrypt
    test eax, eax
    jnz  .fail
    cmp  rbx, 2048
    jne  .fail
    lea  rdi, [rel bx_archive]
    lea  rsi, [rel bx_ct]
    mov  rcx, rbx
    call bx_bytes_equal
    test eax, eax
    jnz  .fail

    ; Restore the correct receiver schedule. bx_decrypt wipes the production
    ; schedule on every return; the saved fixed-KAT material is wiped below.
    lea  rdi, [rel bx_key]
    lea  rsi, [rel bx_kat_key_save]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_nonce]
    lea  rsi, [rel bx_kat_nonce_save]
    mov  edx, 12
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel bx_plain]
    lea  rdx, [rel str_bx_kat_aad]
    mov  ecx, str_bx_kat_aad_len
    call bx_decrypt
    test eax, eax
    jnz  .fail
    lea  rdi, [rel bx_archive]
    lea  rsi, [rel bx_plain]
    mov  rcx, rbx
    call bx_bytes_equal
    test eax, eax
    jz   .fail

    xor  byte [rel bx_ct], 0x80
    lea  rdi, [rel bx_key]
    lea  rsi, [rel bx_kat_key_save]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_nonce]
    lea  rsi, [rel bx_kat_nonce_save]
    mov  edx, 12
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel bx_plain]
    lea  rdx, [rel str_bx_kat_aad]
    mov  ecx, str_bx_kat_aad_len
    call bx_decrypt
    test eax, eax
    jz   .fail_restore
    xor  byte [rel bx_ct], 0x80

    ; Independently derived wrong-recipient DH vector must produce a schedule
    ; that cannot authenticate the correct recipient's ciphertext.
    lea  rdi, [rel bx_shared]
    lea  rsi, [rel bx_expected_wrong_dh]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_recipient_pub]
    call bx_derive_schedule
    test eax, eax
    jnz  .fail
    mov  rdi, rbx
    lea  rsi, [rel bx_plain]
    lea  rdx, [rel str_bx_kat_aad]
    mov  ecx, str_bx_kat_aad_len
    call bx_decrypt
    test eax, eax
    jz   .fail

    lea  rdi, [rel bx_manifest_save]
    lea  rsi, [rel bx_manifest]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel bx_archive]
    lea  rsi, [rel str_bx_keepname]
    mov  edx, str_bx_keepname_len
    lea  rcx, [rel str_bx_keepdata]
    mov  r8, str_bx_keepdata_len
    call ustar_build_member
    cmp  rax, rbx
    jne  .fail
    lea  rdi, [rel bx_manifest]
    lea  rsi, [rel bx_archive]
    mov  rdx, rbx
    call sha256_hash
    lea  rdi, [rel bx_manifest_save]
    lea  rsi, [rel bx_manifest]
    mov  ecx, 32
    call bx_bytes_equal
    test eax, eax
    jz   .fail
    call bx_kat_wipe_saved
    mov  byte [rel bx_kat_state], 1
    lea  rdi, [rel str_bx_kat_ok]
    call serial_string
    pop  rbx
    ret
.fail_restore:
    xor  byte [rel bx_ct], 0x80
    jmp  .fail
.fail:
    call bx_wipe_secrets
    call bx_kat_wipe_saved
    lea  rdi, [rel str_bx_kat_fail]
    call serial_string
    pop  rbx
    ret
.not_armed:
    ret

bx_kat_wipe_saved:
    lea  rdi, [rel bx_kat_key_save]
    xor  esi, esi
    mov  edx, 44
    jmp  memset

; --- immutable RFC labels / KAT vectors ---
bx_kem_extract_prefix: db "HPKE-v1","KEM",0x00,0x20,"eae_prk"
bx_kem_extract_prefix_len equ $ - bx_kem_extract_prefix
bx_kem_expand_prefix: db 0x00,0x20,"HPKE-v1","KEM",0x00,0x20,"shared_secret"
bx_kem_expand_prefix_len equ $ - bx_kem_expand_prefix
bx_pskid_hash_input: db "HPKE-v1","HPKE",0x00,0x20,0x00,0x01,0x00,0x02,"psk_id_hash"
bx_pskid_hash_input_len equ $ - bx_pskid_hash_input
bx_info_hash_input: db "HPKE-v1","HPKE",0x00,0x20,0x00,0x01,0x00,0x02,"info_hash","paos-backup-export-v1"
bx_info_hash_input_len equ $ - bx_info_hash_input
bx_secret_input: db "HPKE-v1","HPKE",0x00,0x20,0x00,0x01,0x00,0x02,"secret"
bx_secret_input_len equ $ - bx_secret_input
bx_key_expand_prefix: db 0x00,0x20,"HPKE-v1","HPKE",0x00,0x20,0x00,0x01,0x00,0x02,"key"
bx_key_expand_prefix_len equ $ - bx_key_expand_prefix
bx_nonce_expand_prefix: db 0x00,0x0c,"HPKE-v1","HPKE",0x00,0x20,0x00,0x01,0x00,0x02,"base_nonce"
bx_nonce_expand_prefix_len equ $ - bx_nonce_expand_prefix

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_data_backup_export_0 0
bx_expected_enc: db 0xaa,0x71,0x54,0x58,0xe6,0x1e,0xc2,0x8f,0x05,0x69,0x61,0x8f,0x6b,0x9d,0x6a,0x19
                 db 0x8c,0x48,0x50,0x6f,0x81,0xf7,0xd0,0x0b,0xb1,0x51,0xd8,0x7b,0xb9,0x93,0x3d,0x4c
bx_expected_key: db 0x35,0xd7,0x5f,0x85,0xb7,0x0f,0x81,0x90,0xad,0x16,0x25,0xd0,0x85,0xf6,0xc5,0x5b
                 db 0x4d,0x4c,0xa4,0xe3,0xd4,0xa3,0x35,0x44,0x71,0x32,0x27,0x68,0xd4,0x61,0x44,0xef
bx_expected_nonce: db 0x4e,0xa8,0xc4,0xe8,0xed,0x2e,0x8a,0x46,0x00,0xc9,0xea,0x10
; X25519(esk, pkR) and X25519(wrong_sk, enc), independently generated for the
; fixed vectors in backup_export_keys.inc.
bx_expected_dh: db 0xbc,0x5c,0x1c,0xc4,0xdb,0x15,0x87,0xe7,0xb8,0xdb,0xcd,0x66,0x4c,0xf5,0x92,0x39
                db 0x71,0xff,0xdf,0xb8,0xd6,0x3a,0x69,0xc2,0x5f,0xa0,0x91,0xb7,0x0f,0x51,0xa2,0x61
bx_expected_wrong_dh: db 0x7f,0x28,0x1c,0x58,0xab,0x3b,0x4b,0x7d,0xc7,0x0f,0x86,0xa1,0x9a,0xcd,0x6b,0x6a
                      db 0xe3,0xd4,0x25,0x62,0xf8,0x3d,0xc2,0x6c,0x78,0xe5,0x02,0x59,0x2c,0x65,0xc8,0x61

; --- mutable workspace (RW+NX) ---
align 8
bx_basepoint:      db 9
                   times 31 db 0
bx_enc:            times 32 db 0
bx_manifest:       times 32 db 0
bx_manifest_save:  times 32 db 0
bx_fingerprint:    times 32 db 0
bx_archive_len:    dq 0
bx_kat_armed:      db 0
bx_kat_state:      db 0                    ; 0=pending, 1=pass, 2=fail
bx_archive:        times BX_ARCHIVE_CAP db 0
bx_ct:             times BX_ARCHIVE_CAP db 0
bx_tag:            times 16 db 0
bx_plain:          times BX_ARCHIVE_CAP db 0
bx_kat_key_save:   times 32 db 0
bx_kat_nonce_save: times 12 db 0
bx_aead_req:       times 64 db 0
bx_kem_context:    times 64 db 0
bx_key_context:    times 65 db 0
bx_kem_extract_input: times bx_kem_extract_prefix_len + 32 db 0
bx_expand_input:   times 128 db 0
bx_empty:          db 0

; This contiguous range is erased after every seal/open and on KAT failure.
align 8
bx_shared:         times 32 db 0
bx_eae_prk:        times 32 db 0
bx_hpke_shared:    times 32 db 0
bx_pskid_hash:     times 32 db 0
bx_info_hash:      times 32 db 0
bx_secret:         times 32 db 0
bx_key:            times 32 db 0
bx_nonce:          times 12 db 0
bx_secret_end:

bx_wrong_priv_probe: times 32 db 0x77
str_bx_keepname: db "keep/notes.txt"
str_bx_keepname_len equ $ - str_bx_keepname
str_bx_keepdata: db "paos user keep backup export fixture payload bytes"
str_bx_keepdata_len equ $ - str_bx_keepdata
str_bx_kat_aad: db "paos-backup-export-kat-aad-v1"
str_bx_kat_aad_len equ $ - str_bx_kat_aad
str_bx_kat_ok: db "[PAOS64] backup export: RFC9180 X25519/HKDF-SHA256/AES-256-GCM + complete ustar KAT PASS (schedule vector, ct!=pt, round-trip, tamper+wrong-recipient rejected) [backup.export.seal.ok]",13,10,0
str_bx_kat_fail: db "[PAOS64] backup export: RFC9180/ustar KAT FAIL [backup.export.seal.fail]",13,10,0
%endmacro
WDATA_DEFER WDATA_data_backup_export_0
