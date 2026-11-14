;; MODULE data/crypto_envelope
;; LAYER 2
;; EXPORTS crypto_envelope_selftest, data_crypto_selftest, data_crypto_record_valid, data_crypto_record_matches_key, data_crypto_seal_record, data_crypto_seal_record_selftest, data_crypto_open_record, data_crypto_unwrap_credential, data_crypto_rekey_record, dce_m_guest
;; IMPORTS core/lib/crypto, core/lib/auth_derive, core/lib/hkdf_sha256, core/lib/aes256_gcm, core/lib/sha256, core/lib/fmt, core/lib/mem, core/csprng, core/lock, boot/serial
;; CAPS
;; OWNER saga:sec
;; LOCK: data_crypto_lock PROTECTS dce_aead_req,dce_owner_state,dce_auth_key,dce_kek,dce_dek,dce_key_hash_check,dce_kat_record,dce_kat_open,dce_kat_foreign,dce_random_material_live,dce_rekey_plain_len,dce_rekey_new_cred_len,dce_rekey_plain,dce_rekey_verify_plain,dce_rekey_verify_dek,dce_rekey_nonces
; ============================================================================
; data/crypto_envelope.asm — the 1074 QEMU LOGIC rung for the per-principal
; CRYPTO DATA-key hierarchy + at-rest ENVELOPE. Proves the key-hierarchy + cipher
; MATH in QEMU via a boot-time known-answer test (KAT), WITHOUT a real disk or a
; reboot (the at-rest ciphertext-on-disk + cross-REBOOT persistence re-verify is
; 1054, bare_metal). DATA §7 / SECURITY §8 / FOUNDATION_CONTRACT_CHECKLIST §2:
; the key-HIERARCHY (cred -> KDF -> KEK -> wrapped DEK) and the crypto envelope
; must EXIST at v1 — encrypt-later = re-encrypt-everything (PRINCIPLES §1).
;
; THREE seams, each content-graded (TESTING §1 — a random per-boot plaintext, so a
; latch cannot fake a matching round-trip):
;   (1) KEY HIERARCHY  — an authenticated OWNER session handle reaches the KDF;
;       a per-boot RANDOM DEK is WRAPPED under the KEK (wrapped = DEK ^ ks(KEK));
;       a KAT unwraps and proves unwrap(wrap(DEK)) == DEK. Prints non-zero KEK/DEK
;       fingerprints + dek_unwrap_ok=1.  marker [crypto.key.logic]
;   (2) LEGACY TRANSFORM ROUND-TRIP — a random token is transformed with the
;       compatibility FNV-1a/SplitMix64 XOR stream and transformed back; the
;       recovered token is byte-identical (rt == pt) and output differs from
;       input. This is an unregistered compatibility diagnostic, not crypto.
;   (3) DIFFERENT-KEY SHAPE — applying a different XOR stream does not reproduce
;       the token (wrongkey_rt != pt). This is not authentication or a wrong-key
;       rejection property and earns no security marker.
;
; The selftest PRINTS one KAT line the probe (probe_data_crypto_key_logic.sh)
; re-checks byte-for-byte:
;   dcrypt.kat kek_fp=0x.. dek_fp=0x.. dek_unwrap_ok=1 pt=0x.. ct=0x.. rt=0x.. wrongkey_rt=0x..
; Any failed invariant falls through WITHOUT emitting the markers (fail-closed) so
; a broken cipher cannot earn a green tag.
;
; LAYER NOTE: L2 (data/) — a foundation seam ABOVE core that REUSES the one
; core/lib crypto primitive (G1); no data-local cipher variant. The envelope FORMAT
; here is crypto-correct so 1054 reuses it verbatim (salt + wrapped-DEK + IV +
; ciphertext; only the WRAPPED DEK + salt would ever touch disk, never plaintext).
; ============================================================================

DE_KEK_LEN    equ 32
DE_DEK_LEN    equ 32
DE_SALT_LEN   equ 16
DE_WRAP_NONCE equ 0x5741524b4e4f4e43     ; fixed DEK-wrap nonce ("WARKNONC")
DE_OWNER_PID  equ 1                       ; v1: one principal (the OWNER)

; crypto_envelope_selftest — the 1074 acceptance gate. Runs the three seams over a
;   per-boot RANDOM DEK + plaintext, PRINTS the KAT the probe content-grades, then
;   earns the three markers iff every invariant holds. Sequenced by boot/header.asm
;   after the other qemu-rung selftests. Preserves rbx,r12-r15 (saved here).
crypto_envelope_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---- salt || DEK || IV || plaintext from the one CSPRNG service --------
    ; Bare metal consumes fresh HMAC_DRBG bytes. QEMU may intentionally lack a
    ; hardware entropy provider; this module is a deterministic crypto-math KAT,
    ; so only that selftest case uses an explicit fixture. The live CSPRNG never
    ; falls back and never returns fixture bytes.
    lea  rdi, [rel de_random_material]
    mov  esi, 64
    call csprng_generate
    test rax, rax
    jz   .material_ready
    ; A physical-machine entropy failure is terminal for this consumer. The
    ; fixed fixture exists only to keep this explicitly QEMU-only math KAT
    ; deterministic when its virtual CPU has no hardware entropy instruction.
    mov  eax, 1
    cpuid
    bt   ecx, 31                         ; CPUID.1:ECX.HYPERVISOR
    jnc  .done
    lea  rdi, [rel de_random_material]
    lea  rsi, [rel de_kat_material]
    mov  edx, 64
    call memcpy
.material_ready:
    lea  rdi, [rel de_salt]
    lea  rsi, [rel de_random_material]
    mov  edx, DE_SALT_LEN
    call memcpy
    lea  rdi, [rel de_dek]
    lea  rsi, [rel de_random_material + DE_SALT_LEN]
    mov  edx, DE_DEK_LEN
    call memcpy
    mov  rax, [rel de_random_material + DE_SALT_LEN + DE_DEK_LEN]
    mov  [rel de_iv], rax
    mov  rax, [rel de_random_material + DE_SALT_LEN + DE_DEK_LEN + 8]
    mov  [rel de_pt], rax

    ; ================= (1) KEY HIERARCHY: cred -> KDF -> KEK -> wrap(DEK) =====
    ; KEK = kdf(OWNER cred, salt)
    ; This is a layout/math fixture, not a live credential source.  Production
    ; callers select the authenticated principal credential above this L2 seam
    ; and pass it into data_crypto_{seal,open}_record explicitly.
    lea  rdi, [rel de_kat_credential]
    mov  esi, de_kat_credential.len
    lea  rdx, [rel de_salt]
    mov  rcx, DE_SALT_LEN
    lea  r8,  [rel de_kek]
    mov  r9,  DE_KEK_LEN
    call crypto_kdf

    ; wrapped_DEK = DEK ^ keystream(KEK, WRAP_NONCE)  (only this + salt touch disk)
    lea  rdi, [rel de_wrapped]
    lea  rsi, [rel de_dek]
    mov  rdx, DE_DEK_LEN
    call memcpy
    lea  rdi, [rel de_kek]
    mov  rsi, DE_KEK_LEN
    mov  rdx, DE_WRAP_NONCE
    lea  rcx, [rel de_wrapped]
    mov  r8,  DE_DEK_LEN
    call crypto_keystream_xor

    ; unwrap: dek_chk = wrapped ^ keystream(KEK, WRAP_NONCE)  -> must recover DEK
    lea  rdi, [rel de_dek_chk]
    lea  rsi, [rel de_wrapped]
    mov  rdx, DE_DEK_LEN
    call memcpy
    lea  rdi, [rel de_kek]
    mov  rsi, DE_KEK_LEN
    mov  rdx, DE_WRAP_NONCE
    lea  rcx, [rel de_dek_chk]
    mov  r8,  DE_DEK_LEN
    call crypto_keystream_xor

    ; dek_unwrap_ok = (unwrap(wrap(DEK)) == DEK)
    lea  rdi, [rel de_dek_chk]
    lea  rsi, [rel de_dek]
    mov  rdx, DE_DEK_LEN
    call memcmp
    test rax, rax
    setz al
    mov  [rel de_unwrap_ok], al

    ; fingerprints (non-zero) of the derived keys
    lea  rdi, [rel de_kek]
    mov  rsi, DE_KEK_LEN
    call crypto_hash64
    mov  [rel de_kek_fp], rax
    lea  rdi, [rel de_dek]
    mov  rsi, DE_DEK_LEN
    call crypto_hash64
    mov  [rel de_dek_fp], rax

    ; ================= (2) ENVELOPE ROUND-TRIP on the random token ============
    ; ct = encrypt(DEK, IV, pt)
    mov  rax, [rel de_pt]
    mov  [rel de_row], rax
    lea  rdi, [rel de_dek]
    mov  rsi, DE_DEK_LEN
    mov  rdx, [rel de_iv]
    lea  rcx, [rel de_row]
    mov  r8,  8
    call crypto_keystream_xor
    mov  rax, [rel de_row]
    mov  [rel de_ct], rax

    ; rt = decrypt(DEK, IV, ct)  (symmetric — recovers pt)
    lea  rdi, [rel de_dek]
    mov  rsi, DE_DEK_LEN
    mov  rdx, [rel de_iv]
    lea  rcx, [rel de_row]
    mov  r8,  8
    call crypto_keystream_xor
    mov  rax, [rel de_row]
    mov  [rel de_rt], rax

    ; ================= (3) NEGATIVE: wrong-key decrypt must NOT recover pt =====
    ; wrong_DEK = DEK with byte 0 flipped (a genuinely different key)
    lea  rdi, [rel de_wrong_dek]
    lea  rsi, [rel de_dek]
    mov  rdx, DE_DEK_LEN
    call memcpy
    mov  al, [rel de_wrong_dek]
    xor  al, 0xFF
    mov  [rel de_wrong_dek], al
    ; wrongkey_rt = decrypt(wrong_DEK, IV, ct)
    mov  rax, [rel de_ct]
    mov  [rel de_row], rax
    lea  rdi, [rel de_wrong_dek]
    mov  rsi, DE_DEK_LEN
    mov  rdx, [rel de_iv]
    lea  rcx, [rel de_row]
    mov  r8,  8
    call crypto_keystream_xor
    mov  rax, [rel de_row]
    mov  [rel de_wrt], rax

    ; ---- PRINT the KAT line the probe content-grades ----
    call de_print_kat

    ; ================= validate invariants (fail-closed) ======================
    cmp  byte [rel de_unwrap_ok], 1      ; (1) unwrap recovered the DEK
    jne  .done
    cmp  qword [rel de_kek_fp], 0        ; (1) non-zero KEK fingerprint
    je   .done
    cmp  qword [rel de_dek_fp], 0        ; (1) non-zero DEK fingerprint
    je   .done
    mov  rax, [rel de_rt]                ; (2) round-trip recovered the plaintext
    cmp  rax, [rel de_pt]
    jne  .done
    mov  rax, [rel de_ct]                ; (2) ciphertext is NOT the plaintext
    cmp  rax, [rel de_pt]
    je   .done
    mov  rax, [rel de_wrt]               ; (3) wrong-key did NOT recover plaintext
    cmp  rax, [rel de_pt]
    je   .done

    ; ===== all invariants held: earn the three markers =====
    lea  rdi, [rel str_de_key]
    call serial_string
    lea  rdi, [rel str_de_rt]
    call serial_string
    lea  rdi, [rel str_de_wrong]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; de_print_kat — render the single KAT line (LIVE values) through the canonical
;   fmt_str/fmt_hex/fmt_dec (G1), then serial_string it. Fixed 16-hex-digit width
;   so equal values print identical strings (pt/rt) — the probe's rt==pt / ct!=pt
;   comparison is then pure value equality. clobbers caller-saved (r12 cursor saved).
de_print_kat:
    push rbx
    push r12
    lea  r12, [rel de_line]

    lea  rdi, [rel str_de_kek_fp]        ; "dcrypt.kat kek_fp=0x"
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, [rel de_kek_fp]
    mov  rsi, r12
    mov  rdx, 16
    call fmt_hex
    add  r12, rax

    lea  rdi, [rel str_de_dek_fp]        ; " dek_fp=0x"
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, [rel de_dek_fp]
    mov  rsi, r12
    mov  rdx, 16
    call fmt_hex
    add  r12, rax

    lea  rdi, [rel str_de_unwrap]        ; " dek_unwrap_ok="
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    movzx edi, byte [rel de_unwrap_ok]
    mov  rsi, r12
    call fmt_dec
    add  r12, rax

    lea  rdi, [rel str_de_pt]            ; " pt=0x"
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, [rel de_pt]
    mov  rsi, r12
    mov  rdx, 16
    call fmt_hex
    add  r12, rax

    lea  rdi, [rel str_de_ct]            ; " ct=0x"
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, [rel de_ct]
    mov  rsi, r12
    mov  rdx, 16
    call fmt_hex
    add  r12, rax

    lea  rdi, [rel str_de_rt_f]          ; " rt=0x"
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, [rel de_rt]
    mov  rsi, r12
    mov  rdx, 16
    call fmt_hex
    add  r12, rax

    lea  rdi, [rel str_de_wrt]           ; " wrongkey_rt=0x"
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, [rel de_wrt]
    mov  rsi, r12
    mov  rdx, 16
    call fmt_hex
    add  r12, rax

    mov  byte [r12],     13
    mov  byte [r12 + 1], 10
    mov  byte [r12 + 2], 0
    lea  rdi, [rel de_line]
    call serial_string

    pop  r12
    pop  rbx
    ret

; --- Legacy 1074 compatibility-KAT state (writable, in-image).  None of these
;     bytes is a durable security format or reachable from the 1054 storage
;     path; the authenticated DSE2 format and RAM-only working keys begin below.
de_kat_credential: db "crypto-envelope-layout-kat" ; compatibility KAT only, never a live credential
.len equ $ - de_kat_credential
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_data_crypto_envelope_0 0
align 8
de_random_material: times 64 db 0                ; salt || DEK || IV || KAT token
; Deterministic selftest fixture for QEMU configurations without a live entropy
; provider. It is never installed into the CSPRNG and never used by live callers.
de_kat_material:
    db 0x06,0x03,0x2c,0xd5,0xee,0xd3,0x3f,0x39
    db 0x26,0x5f,0x49,0xec,0xb1,0x42,0xc5,0x11
    db 0xda,0x9a,0xff,0x2a,0xf7,0x12,0x03,0xbf
    db 0xfa,0xf3,0x4a,0x9c,0xa5,0xbd,0x9c,0x0d
    db 0x0e,0x66,0xf7,0x1e,0xdc,0x43,0xe4,0x2a
    db 0x45,0xad,0x3c,0x6f,0xc6,0xcd,0xc4,0xdf
    db 0x76,0xfc,0x79,0xfe,0x9b,0x50,0xbe,0xcc
    db 0xc9,0x91,0xa1,0x1b,0x56,0x35,0x78,0x3a
; --- envelope header (on-disk format; here in RAM for the qemu KAT) ---
de_salt:        times DE_SALT_LEN db 0           ; KDF salt (header)
de_wrapped:     times DE_DEK_LEN  db 0           ; wrapped DEK (header — never plaintext)
de_iv:          dq 0                             ; envelope IV/nonce (header)
de_pid:         dq DE_OWNER_PID                  ; principal id (header)
; --- working key material (RAM-only; the plaintext DEK/KEK never reach disk) ---
de_kek:         times DE_KEK_LEN  db 0           ; re-derived each boot from cred+salt
de_dek:         times DE_DEK_LEN  db 0           ; per-boot random data key
de_dek_chk:     times DE_DEK_LEN  db 0           ; unwrap(wrap(DEK)) — must == DEK
de_wrong_dek:   times DE_DEK_LEN  db 0           ; a deliberately wrong key (negative)
de_row:         times 8 db 0                     ; working row buffer (pt/ct/rt)
; --- KAT scalars printed + graded ---
de_kek_fp:      dq 0
de_dek_fp:      dq 0
de_unwrap_ok:   db 0
de_pt:          dq 0
de_ct:          dq 0
de_rt:          dq 0
de_wrt:         dq 0
de_line:        times 256 db 0                   ; KAT line render buffer

str_de_kek_fp:  db "dcrypt.kat kek_fp=0x", 0
str_de_dek_fp:  db " dek_fp=0x", 0
str_de_unwrap:  db " dek_unwrap_ok=", 0
str_de_pt:      db " pt=0x", 0
str_de_ct:      db " ct=0x", 0
str_de_rt_f:    db " rt=0x", 0
str_de_wrt:     db " wrongkey_rt=0x", 0

str_de_key:     db "[PAOS64] P2 dcrypt: KDF->KEK->wrapped-DEK hierarchy KAT PASS [crypto.key.logic]", 13, 10, 0
str_de_rt:      db "[PAOS64] P2 dcrypt compatibility: FNV/SplitMix XOR transform round-trip observed diagnostic_only=1", 13, 10, 0
str_de_wrong:   db "[PAOS64] P2 dcrypt compatibility: different-key XOR output differs non_authenticated=1 diagnostic_only=1", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_data_crypto_envelope_0

; ============================================================================
; Contract 1054: authenticated, persistent DATA envelope format.
;
; The durable v2 record is exactly 168 bytes, fitting the genuinely unused tail
; (344..511) of each proven DATA-disk gap sector without narrowing the existing
; five-window session manifest. No plaintext key is serialized:
;   +0   versioned magic "DSE2"                    (4)
;   +4   principal id (low 24), data_len (high 8) (4)
;   +8   HKDF salt                                (8)
;   +16  DEK-wrap nonce                           (12)
;   +28  wrapped DEK ciphertext                   (32)
;   +60  wrapped DEK authentication tag           (16)
;   +76  data nonce / IV                          (12)
;   +88  SHA-256 key-name selector                (8, 64-bit)
;   +96  data ciphertext                          (56 max)
;   +152 data authentication tag                  (16)
;
; The data AEAD authenticates bytes 0..95, binding salt, wrapped DEK, both
; nonces, principal id and key identity to the ciphertext.  The wrap AEAD has a
; separate domain-bound AAD.  Working KEK/DEK bytes are lock-protected RAM only
; and are wiped on every exit.
; ============================================================================

DCE_RECORD_SIZE    equ 168
DCE_MAGIC          equ 0                    ; dword "DSE2"
DCE_PIDLEN         equ 4                    ; low24=pid, high8=data length
DCE_SALT           equ 8
DCE_WRAP_NONCE     equ 16
DCE_WRAPPED_DEK    equ 28
DCE_WRAP_TAG       equ 60
DCE_DATA_NONCE     equ 76
DCE_KEY_HASH       equ 88                   ; 64-bit SHA-256 row-name selector
DCE_CIPHERTEXT     equ 96
DCE_DATA_TAG       equ 152
DCE_CIPHER_CAP     equ 56
DCE_KEY_MAX        equ 31
DCE_OWNER_PID      equ 1
DCE_MAGIC_VALUE    equ 0x32455344            ; "DSE2" little-endian
DCE_SALT_LEN       equ 8
DCE_KEY_HASH_LEN   equ 8
DCE_WRAP_AAD_LEN   equ 40
DCE_KEK_INFO_LEN   equ 24
DCE_RANDOM_LEN     equ 64                  ; salt8 + DEK32 + wrap nonce12 + data nonce12

data_crypto_lock_acquire:
    lea  rdi, [rel data_crypto_lock]
    jmp  spin_acquire

data_crypto_lock_release:
    lea  rdi, [rel data_crypto_lock]
    jmp  spin_release

; dce_hash16_internal(RDI=data,RSI=len,RDX=out16) -> 0/-1. Caller holds lock.
dce_hash16_internal:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    lea  rdi, [rel dce_sha_ctx]
    call sha256_stream_init
    lea  rdi, [rel dce_sha_ctx]
    mov  rsi, r12
    mov  rdx, r13
    call sha256_stream_update
    test eax, eax
    jnz  .fail
    lea  rdi, [rel dce_sha_ctx]
    lea  rsi, [rel dce_hash_digest]
    call sha256_stream_final
    test eax, eax
    jnz  .fail
    mov  rax, [rel dce_hash_digest]
    mov  [r14], rax
    mov  rax, [rel dce_hash_digest + 8]
    mov  [r14 + 8], rax
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; dce_record_header_valid(RDI=record) -> EAX=1/0.
dce_record_header_valid:
    test rdi, rdi
    jz   .bad
    cmp  dword [rdi + DCE_MAGIC], DCE_MAGIC_VALUE
    jne  .bad
    mov  eax, [rdi + DCE_PIDLEN]
    mov  edx, eax
    and  eax, 0x00ffffff
    test eax, eax
    jz   .bad
    shr  edx, 24
    mov  eax, edx
    test eax, eax
    jz   .bad
    cmp  eax, DCE_CIPHER_CAP
    ja   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; data_crypto_record_valid(RDI=record) -> EAX=1/0.  Structural only; callers
; must still authenticate unwrap/open before trusting any durable field.
data_crypto_record_valid:
    push rbx
    mov  rbx, rdi
    call data_crypto_lock_acquire
    mov  rdi, rbx
    call dce_record_header_valid
    mov  ebx, eax
    call data_crypto_lock_release
    mov  eax, ebx
    pop  rbx
    ret

; data_crypto_record_matches_key(RDI=record,RSI=key,RDX=key_len) -> EAX=1/0.
; The selector is part of the authenticated envelope header.  Raw-at-rest
; diagnostics use this only after the principal boundary authenticated the same
; key, ensuring a crash fallback cannot accidentally expose a different slot.
data_crypto_record_matches_key:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    test rbx, rbx
    jz   .no_lock
    test r12, r12
    jz   .no_lock
    test r13, r13
    jz   .no_lock
    cmp  r13, DCE_KEY_MAX
    ja   .no_lock
    call data_crypto_lock_acquire
    mov  rdi, rbx
    call dce_record_header_valid
    test eax, eax
    jz   .no
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rel dce_key_hash_check]
    call dce_hash16_internal
    test eax, eax
    jnz  .no
    lea  rdi, [rel dce_key_hash_check]
    lea  rsi, [rbx + DCE_KEY_HASH]
    mov  edx, DCE_KEY_HASH_LEN
    call memcmp
    test eax, eax
    setz bl
    movzx ebx, bl
    jmp  .unlock
.no:
    xor  ebx, ebx
.unlock:
    call data_crypto_lock_release
    mov  eax, ebx
    pop  r13
    pop  r12
    pop  rbx
    ret
.no_lock:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret

; dce_build_wrap_aad(RDI=record). Caller holds lock.
dce_build_wrap_aad:
    push r12
    mov  r12, rdi
    lea  rdi, [rel dce_wrap_aad]
    lea  rsi, [rel dce_wrap_domain]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel dce_wrap_aad + 16]
    mov  rsi, r12
    mov  edx, 16                         ; magic, pid/len and salt
    call memcpy
    lea  rdi, [rel dce_wrap_aad + 32]
    lea  rsi, [r12 + DCE_KEY_HASH]
    mov  edx, DCE_KEY_HASH_LEN
    call memcpy
    pop  r12
    ret

; dce_wipe_keys — clear every RAM-only credential-derived/key buffer.
dce_wipe_keys:
    lea  rdi, [rel dce_auth_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel dce_kek]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel dce_dek]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel dce_wrap_aad]
    xor  esi, esi
    mov  edx, DCE_WRAP_AAD_LEN
    call memset
    lea  rdi, [rel dce_kek_info]
    xor  esi, esi
    mov  edx, DCE_KEK_INFO_LEN
    call memset
    lea  rdi, [rel dce_aead_req]
    xor  esi, esi
    mov  edx, AEAD_REQ_SZ
    call memset
    ret

; dce_derive_kek_internal(RDI=pid,RSI=cred,RDX=cred_len,RCX=salt8,R8=out32)
; First invokes the canonical L1 implementation behind the 1053 auth-derive
; seam, then domain-separates the DATA KEK by
; principal id.  A foreign id therefore reaches the authenticated unwrap with a
; different cryptographic key; it is not rejected by a permission comparison.
dce_derive_kek_internal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                         ; pid
    mov  r13, rsi                         ; credential
    mov  r14, rdx                         ; credential length
    mov  r15, rcx                         ; salt
    mov  rbx, r8                          ; output KEK
    ; NULL principal/credential is the explicit guest hook. It has no durable
    ; KEK and therefore cannot create or open a persistent record.
    test r12, r12
    jz   .ephemeral
    test r13, r13
    jz   .ephemeral
    test r14, r14
    jz   .ephemeral
    lea  rdi, [rel dce_kek_info]
    lea  rsi, [rel dce_kek_domain]
    mov  edx, 16
    call memcpy
    mov  [rel dce_kek_info + 16], r12
    mov  rdi, r15
    mov  esi, DCE_SALT_LEN
    mov  rdx, r13
    mov  rcx, r14
    lea  r8, [rel dce_auth_key]
    mov  r9d, 32
    call auth_derive_key
    test eax, eax
    jnz  .fail
    sub  rsp, 16
    mov  [rsp], rbx                       ; HKDF stack arg7: output
    mov  qword [rsp + 8], 32              ; HKDF stack arg8: output length
    lea  rdi, [rel dce_auth_key]
    mov  esi, 32
    mov  rdx, r15
    mov  ecx, DCE_SALT_LEN
    lea  r8, [rel dce_kek_info]
    mov  r9d, DCE_KEK_INFO_LEN
    call hkdf_sha256_derive
    add  rsp, 16
    test eax, eax
    jnz  .fail
    xor  ebx, ebx
    jmp  .wipe_auth
.fail:
    mov  ebx, -1
    jmp  .wipe_auth
.ephemeral:
    mov  ebx, -3
.wipe_auth:
    lea  rdi, [rel dce_auth_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel dce_kek_info]
    xor  esi, esi
    mov  edx, DCE_KEK_INFO_LEN
    call memset
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dce_unwrap_internal(record,pid,credential,credential_len,dek_out32) -> 0/-1/-2.
; Authentication happens before a byte of the DEK is released.
dce_unwrap_internal:
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
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, r15
    lea  rcx, [r12 + DCE_SALT]
    lea  r8, [rel dce_kek]
    call dce_derive_kek_internal
    test eax, eax
    jnz  .bad
    mov  rdi, r12
    call dce_build_wrap_aad
    lea  rax, [rel dce_kek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_WRAP_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    lea  rax, [rel dce_wrap_aad]
    mov  [rel dce_aead_req + AEAD_AAD], rax
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_WRAP_AAD_LEN
    lea  rax, [r12 + DCE_WRAPPED_DEK]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  qword [rel dce_aead_req + AEAD_INPUT_LEN], 32
    mov  [rel dce_aead_req + AEAD_OUTPUT], rbx
    lea  rax, [r12 + DCE_WRAP_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel dce_aead_req]
    call aes256_gcm_unwrap_dek
    mov  ebx, eax
    jmp  .out
.bad:
    mov  ebx, -1
.out:
    lea  rdi, [rel dce_kek]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel dce_wrap_aad]
    xor  esi, esi
    mov  edx, DCE_WRAP_AAD_LEN
    call memset
    lea  rdi, [rel dce_aead_req]
    xor  esi, esi
    mov  edx, AEAD_REQ_SZ
    call memset
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; data_crypto_rekey_record(record,pid,old_credential,old_len,
;                          new_credential,new_len) -> 0/-1/-2.
; Rewrap the existing DEK and re-authenticate the unchanged plaintext under
; the new header AAD. The 168-byte envelope format and selector are unchanged.
; SEC-B1: both nonces are fresh CSPRNG bytes, drawn after the old-key open and
; before any record byte changes. Keeping the data nonce resealed the same
; plaintext under the same (DEK, nonce) with a different AAD, which leaks the
; GHASH key from two disk images. An entropy failure refuses with the record
; untouched; any later -1 may leave the buffer modified, so callers pass a
; scratch copy (safe_write does). The caller persists only after the new-key
; readback below passes.
data_crypto_rekey_record:
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
    mov  [rel dce_rekey_new_cred_len], r9
    test r12, r12
    jz   .invalid_unlocked
    test r13, r13
    jz   .invalid_unlocked
    test r14, r14
    jz   .invalid_unlocked
    test r15, r15
    jz   .invalid_unlocked
    test rbx, rbx
    jz   .invalid_unlocked
    test r9, r9
    jz   .invalid_unlocked
    call data_crypto_lock_acquire
    mov  rdi, r12
    call dce_record_header_valid
    test eax, eax
    jz   .invalid

    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    lea  r8, [rel dce_dek]
    call dce_unwrap_internal
    test eax, eax
    jnz  .denied

    ; Open before changing any byte covered by the data authentication tag.
    lea  rax, [rel dce_dek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_DATA_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    mov  [rel dce_aead_req + AEAD_AAD], r12
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_CIPHERTEXT
    lea  rax, [r12 + DCE_CIPHERTEXT]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  eax, [r12 + DCE_PIDLEN]
    shr  eax, 24
    mov  [rel dce_rekey_plain_len], rax
    mov  [rel dce_aead_req + AEAD_INPUT_LEN], rax
    lea  rax, [rel dce_rekey_plain]
    mov  [rel dce_aead_req + AEAD_OUTPUT], rax
    lea  rax, [r12 + DCE_DATA_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_aead_req]
    call aes256_gcm_open
    test eax, eax
    jnz  .denied

    ; SEC-B1: fresh wrap + data nonces before the first record byte changes.
    lea  rdi, [rel dce_rekey_nonces]
    mov  esi, 24
    call csprng_generate
    test eax, eax
    jnz  .invalid
    lea  rdi, [r12 + DCE_WRAP_NONCE]
    lea  rsi, [rel dce_rekey_nonces]
    mov  edx, 12
    call memcpy
    lea  rdi, [r12 + DCE_DATA_NONCE]
    lea  rsi, [rel dce_rekey_nonces + 12]
    mov  edx, 12
    call memcpy

    ; Rewrap the same DEK with the password-session credential.
    mov  rdi, r13
    mov  rsi, rbx
    mov  rdx, [rel dce_rekey_new_cred_len]
    lea  rcx, [r12 + DCE_SALT]
    lea  r8, [rel dce_kek]
    call dce_derive_kek_internal
    test eax, eax
    jnz  .invalid
    mov  rdi, r12
    call dce_build_wrap_aad
    lea  rdi, [rel dce_owner_state]
    xor  esi, esi
    mov  edx, AEAD_OWNER_SZ
    call memset
    lea  rax, [rel dce_kek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_WRAP_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    lea  rax, [rel dce_wrap_aad]
    mov  [rel dce_aead_req + AEAD_AAD], rax
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_WRAP_AAD_LEN
    lea  rax, [rel dce_dek]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  qword [rel dce_aead_req + AEAD_INPUT_LEN], 32
    lea  rax, [r12 + DCE_WRAPPED_DEK]
    mov  [rel dce_aead_req + AEAD_OUTPUT], rax
    lea  rax, [r12 + DCE_WRAP_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_owner_state]
    lea  rsi, [rel dce_aead_req]
    call aes256_gcm_wrap_dek
    test eax, eax
    jnz  .invalid

    ; Wrapped-DEK bytes are data AAD, so reseal with the preserved plaintext.
    lea  rax, [rel dce_dek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_DATA_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    mov  [rel dce_aead_req + AEAD_AAD], r12
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_CIPHERTEXT
    lea  rax, [rel dce_rekey_plain]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  rax, [rel dce_rekey_plain_len]
    mov  [rel dce_aead_req + AEAD_INPUT_LEN], rax
    lea  rax, [r12 + DCE_CIPHERTEXT]
    mov  [rel dce_aead_req + AEAD_OUTPUT], rax
    lea  rax, [r12 + DCE_DATA_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_aead_req]
    call aes256_gcm_seal
    test eax, eax
    jnz  .invalid

    ; Verify both layers under the new credential before returning bytes.
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    mov  rcx, [rel dce_rekey_new_cred_len]
    lea  r8, [rel dce_rekey_verify_dek]
    call dce_unwrap_internal
    test eax, eax
    jnz  .invalid
    lea  rdi, [rel dce_dek]
    lea  rsi, [rel dce_rekey_verify_dek]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .invalid
    lea  rax, [rel dce_rekey_verify_dek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_DATA_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    mov  [rel dce_aead_req + AEAD_AAD], r12
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_CIPHERTEXT
    lea  rax, [r12 + DCE_CIPHERTEXT]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  rax, [rel dce_rekey_plain_len]
    mov  [rel dce_aead_req + AEAD_INPUT_LEN], rax
    lea  rax, [rel dce_rekey_verify_plain]
    mov  [rel dce_aead_req + AEAD_OUTPUT], rax
    lea  rax, [r12 + DCE_DATA_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_aead_req]
    call aes256_gcm_open
    test eax, eax
    jnz  .invalid
    lea  rdi, [rel dce_rekey_plain]
    lea  rsi, [rel dce_rekey_verify_plain]
    mov  rdx, [rel dce_rekey_plain_len]
    call memcmp
    test eax, eax
    jnz  .invalid
    xor  ebx, ebx
    jmp  .wipe
.denied:
    mov  ebx, -2
    jmp  .wipe
.invalid:
    mov  ebx, -1
.wipe:
    call dce_wipe_keys
    lea  rdi, [rel dce_rekey_plain]
    xor  esi, esi
    mov  edx, DCE_CIPHER_CAP * 2
    call memset
    lea  rdi, [rel dce_rekey_verify_dek]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  qword [rel dce_rekey_plain_len], 0
    mov  qword [rel dce_rekey_new_cred_len], 0
    call data_crypto_lock_release
    mov  eax, ebx
    jmp  .out
.invalid_unlocked:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dce_seal_material_internal(record,pid,key,key_len,plain,plain_len,
;                            stack arg7=random64,arg8=credential,
;                            arg9=credential_len) -> 0/-1. Caller holds lock.
dce_seal_material_internal:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                         ; record
    mov  r13, rsi                         ; pid
    mov  r14, rdx                         ; key
    mov  r15, rcx                         ; key length
    mov  [rel dce_plain_ptr], r8
    mov  [rel dce_plain_len], r9
    mov  rbx, [rbp + 16]                 ; random material
    mov  rax, [rbp + 24]
    mov  [rel dce_seal_cred], rax
    mov  rax, [rbp + 32]
    mov  [rel dce_seal_cred_len], rax
    test r12, r12
    jz   .fail
    test r13, r13
    jz   .ephemeral                       ; guest branch is ephemeral/no-record
    cmp  r13, 0x00ffffff
    ja   .fail
    test r14, r14
    jz   .fail
    test r15, r15
    jz   .fail
    cmp  r15, DCE_KEY_MAX
    ja   .fail
    cmp  qword [rel dce_plain_ptr], 0
    je   .fail
    mov  rax, [rel dce_plain_len]
    test rax, rax
    jz   .fail
    cmp  rax, DCE_CIPHER_CAP
    ja   .fail
    test rbx, rbx
    jz   .fail
    cmp  qword [rel dce_seal_cred], 0
    je   .fail
    cmp  qword [rel dce_seal_cred_len], 0
    je   .fail
    mov  rdi, r12
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
    mov  dword [r12 + DCE_MAGIC], DCE_MAGIC_VALUE
    mov  eax, r13d
    mov  rdx, [rel dce_plain_len]
    shl  edx, 24
    or   eax, edx
    mov  [r12 + DCE_PIDLEN], eax
    lea  rdi, [r12 + DCE_SALT]
    mov  rsi, rbx
    mov  edx, DCE_SALT_LEN
    call memcpy
    lea  rdi, [rel dce_dek]
    lea  rsi, [rbx + DCE_SALT_LEN]
    mov  edx, 32
    call memcpy
    lea  rdi, [r12 + DCE_WRAP_NONCE]
    lea  rsi, [rbx + DCE_SALT_LEN + 32]
    mov  edx, 12
    call memcpy
    lea  rdi, [r12 + DCE_DATA_NONCE]
    lea  rsi, [rbx + DCE_SALT_LEN + 44]
    mov  edx, 12
    call memcpy
    mov  rdi, r14
    mov  rsi, r15
    lea  rdx, [rel dce_key_hash_check]
    call dce_hash16_internal
    test eax, eax
    jnz  .fail_clear
    lea  rdi, [r12 + DCE_KEY_HASH]
    lea  rsi, [rel dce_key_hash_check]
    mov  edx, DCE_KEY_HASH_LEN
    call memcpy

    mov  rdi, r13
    mov  rsi, [rel dce_seal_cred]
    mov  rdx, [rel dce_seal_cred_len]
    lea  rcx, [r12 + DCE_SALT]
    lea  r8, [rel dce_kek]
    call dce_derive_kek_internal
    test eax, eax
    jnz  .fail_clear

    ; Non-secret fingerprints are retained only for the boot content grade.
    lea  rdi, [rel dce_kek]
    mov  esi, 32
    lea  rdx, [rel dce_fp_digest]
    call dce_hash16_internal
    mov  rax, [rel dce_fp_digest]
    mov  [rel dce_last_kek_fp], rax
    lea  rdi, [rel dce_dek]
    mov  esi, 32
    lea  rdx, [rel dce_fp_digest]
    call dce_hash16_internal
    mov  rax, [rel dce_fp_digest]
    mov  [rel dce_last_dek_fp], rax

    ; Authenticated DEK wrap under the credential-derived KEK.
    mov  rdi, r12
    call dce_build_wrap_aad
    lea  rdi, [rel dce_owner_state]
    xor  esi, esi
    mov  edx, AEAD_OWNER_SZ
    call memset
    lea  rax, [rel dce_kek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_WRAP_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    lea  rax, [rel dce_wrap_aad]
    mov  [rel dce_aead_req + AEAD_AAD], rax
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_WRAP_AAD_LEN
    lea  rax, [rel dce_dek]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  qword [rel dce_aead_req + AEAD_INPUT_LEN], 32
    lea  rax, [r12 + DCE_WRAPPED_DEK]
    mov  [rel dce_aead_req + AEAD_OUTPUT], rax
    lea  rax, [r12 + DCE_WRAP_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_owner_state]
    lea  rsi, [rel dce_aead_req]
    call aes256_gcm_wrap_dek
    test eax, eax
    jnz  .fail_clear

    ; Owned data is encrypted before the storage caller can reach blk_write.
    lea  rax, [rel dce_dek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_DATA_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    mov  [rel dce_aead_req + AEAD_AAD], r12
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_CIPHERTEXT
    mov  rax, [rel dce_plain_ptr]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  rax, [rel dce_plain_len]
    mov  [rel dce_aead_req + AEAD_INPUT_LEN], rax
    lea  rax, [r12 + DCE_CIPHERTEXT]
    mov  [rel dce_aead_req + AEAD_OUTPUT], rax
    lea  rax, [r12 + DCE_DATA_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_aead_req]
    call aes256_gcm_seal
    test eax, eax
    jnz  .fail_clear
    xor  ebx, ebx
    jmp  .wipe
.ephemeral:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
    mov  ebx, -3
    jmp  .wipe
.fail_clear:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, DCE_RECORD_SIZE
    call memset
.fail:
    mov  ebx, -1
.wipe:
    call dce_wipe_keys
    mov  qword [rel dce_plain_ptr], 0
    mov  qword [rel dce_plain_len], 0
    mov  qword [rel dce_seal_cred], 0
    mov  qword [rel dce_seal_cred_len], 0
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; data_crypto_seal_record(record,pid,key,key_len,plain,plain_len,
;                         stack credential,credential_len) -> 0/-1/-3 guest.
; Production entropy is exclusively the keep CSPRNG; there is no live fallback.
data_crypto_seal_record:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  [rsp], r8
    mov  [rsp + 8], r9
    call data_crypto_lock_acquire
    lea  rdi, [rel dce_random_material_live]
    mov  esi, DCE_RANDOM_LEN
    call csprng_generate
    test eax, eax
    jnz  .entropy_fail
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, [rsp]
    mov  r9, [rsp + 8]
    sub  rsp, 24
    lea  rax, [rel dce_random_material_live]
    mov  [rsp], rax
    mov  rax, [rbp + 16]
    mov  [rsp + 8], rax
    mov  rax, [rbp + 24]
    mov  [rsp + 16], rax
    call dce_seal_material_internal
    add  rsp, 24
    mov  ebx, eax
    jmp  .wipe
.entropy_fail:
    mov  ebx, -1
.wipe:
    lea  rdi, [rel dce_random_material_live]
    xor  esi, esi
    mov  edx, DCE_RANDOM_LEN
    call memset
    call data_crypto_lock_release
    mov  eax, ebx
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; data_crypto_seal_record_selftest has the production sealer's ABI but uses a
; private, deterministic material block reserved for boot KATs.  QEMU does not
; claim production entropy (`crypto.csprng.ready` is hardware-only), so a
; both-target consumer KAT must not weaken data_crypto_seal_record's live
; CSPRNG-only contract merely to run there.  The material never leaves RAM and
; is distinct from data_crypto_selftest's fixture, avoiding nonce/key reuse.
data_crypto_seal_record_selftest:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  [rsp], r8
    mov  [rsp + 8], r9
    call data_crypto_lock_acquire
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, [rsp]
    mov  r9, [rsp + 8]
    sub  rsp, 24
    lea  rax, [rel dce_store_kat_material]
    mov  [rsp], rax
    mov  rax, [rbp + 16]
    mov  [rsp + 8], rax
    mov  rax, [rbp + 24]
    mov  [rsp + 16], rax
    call dce_seal_material_internal
    add  rsp, 24
    mov  ebx, eax
    call data_crypto_lock_release
    mov  eax, ebx
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; dce_open_internal(record,requested_pid,key,key_len,out,cap) -> len/-1/-2.
; Caller holds lock and has installed dce_active_cred{,_len}.
dce_open_internal:
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
    mov  [rel dce_open_cap], r9
    test r13, r13
    jz   .ephemeral
    cmp  qword [rel dce_active_cred], 0
    je   .denied
    cmp  qword [rel dce_active_cred_len], 0
    je   .denied
    mov  rdi, r12
    call dce_record_header_valid
    test eax, eax
    jz   .invalid
    mov  rdi, r14
    mov  rsi, r15
    lea  rdx, [rel dce_key_hash_check]
    call dce_hash16_internal
    test eax, eax
    jnz  .invalid
    lea  rdi, [rel dce_key_hash_check]
    lea  rsi, [r12 + DCE_KEY_HASH]
    mov  edx, DCE_KEY_HASH_LEN
    call memcmp
    test eax, eax
    jnz  .invalid
    mov  eax, [r12 + DCE_PIDLEN]
    shr  eax, 24
    cmp  rax, [rel dce_open_cap]
    ja   .invalid
    test rbx, rbx
    jz   .invalid
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, [r12 + DCE_PIDLEN]
    shr  edx, 24
    call memset

    ; Do not compare requested_pid with record.pid.  The requested principal is
    ; fed into KEK derivation and an alien principal fails authenticated unwrap.
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, [rel dce_active_cred]
    mov  rcx, [rel dce_active_cred_len]
    lea  r8, [rel dce_dek]
    call dce_unwrap_internal
    test eax, eax
    jnz  .denied
    lea  rax, [rel dce_dek]
    mov  [rel dce_aead_req + AEAD_KEY], rax
    lea  rax, [r12 + DCE_DATA_NONCE]
    mov  [rel dce_aead_req + AEAD_NONCE], rax
    mov  [rel dce_aead_req + AEAD_AAD], r12
    mov  qword [rel dce_aead_req + AEAD_AAD_LEN], DCE_CIPHERTEXT
    lea  rax, [r12 + DCE_CIPHERTEXT]
    mov  [rel dce_aead_req + AEAD_INPUT], rax
    mov  eax, [r12 + DCE_PIDLEN]
    shr  eax, 24
    mov  [rel dce_aead_req + AEAD_INPUT_LEN], rax
    mov  [rel dce_aead_req + AEAD_OUTPUT], rbx
    lea  rax, [r12 + DCE_DATA_TAG]
    mov  [rel dce_aead_req + AEAD_TAG], rax
    lea  rdi, [rel dce_aead_req]
    call aes256_gcm_open
    test eax, eax
    jnz  .denied
    mov  ebx, [r12 + DCE_PIDLEN]
    shr  ebx, 24
    jmp  .wipe
.denied:
    mov  ebx, -2
    jmp  .wipe
.ephemeral:
    mov  ebx, -3
    jmp  .wipe
.invalid:
    mov  ebx, -1
.wipe:
    call dce_wipe_keys
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; data_crypto_open_record(record,requested_pid,key,key_len,out,cap,
;                         stack credential,credential_len) -> len/-1/-2/-3 guest.
data_crypto_open_record:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    mov  [rsp], r9
    call data_crypto_lock_acquire
    mov  rax, [rbp + 16]
    mov  [rel dce_active_cred], rax
    mov  rax, [rbp + 24]
    mov  [rel dce_active_cred_len], rax
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, rbx
    mov  r9, [rsp]
    call dce_open_internal
    mov  ebx, eax
    mov  qword [rel dce_active_cred], 0
    mov  qword [rel dce_active_cred_len], 0
    call data_crypto_lock_release
    movsxd rax, ebx
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; data_crypto_unwrap_credential(record,credential,credential_len) -> 0/-1/-2.
; Used by the live negative gate; a wrong credential reaches AEAD and is refused.
data_crypto_unwrap_credential:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    call data_crypto_lock_acquire
    mov  rdi, r12
    call dce_record_header_valid
    test eax, eax
    jz   .invalid
    mov  rdi, r12
    mov  esi, DCE_OWNER_PID
    mov  rdx, r13
    mov  rcx, r14
    lea  r8, [rel dce_dek]
    call dce_unwrap_internal
    mov  ebx, eax
    jmp  .wipe
.invalid:
    mov  ebx, -1
.wipe:
    call dce_wipe_keys
    call data_crypto_lock_release
    movsxd rax, ebx
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Return 1 only if the 8-byte KAT plaintext occurs anywhere in the durable bytes.
dce_record_contains_kat_plain:
    xor  ecx, ecx
.offset:
    lea  r8, [rel dce_kat_record]
    add  r8, rcx
    lea  r9, [rel dce_kat_plain]
    xor  edx, edx
.byte:
    mov  al, [r8 + rdx]
    cmp  al, [r9 + rdx]
    jne  .next
    inc  edx
    cmp  edx, 8
    jb   .byte
    mov  eax, 1
    ret
.next:
    inc  ecx
    cmp  ecx, DCE_RECORD_SIZE - 7
    jb   .offset
    xor  eax, eax
    ret

; Boot KAT for the 1054 format and negative boundaries.  Fixed material is
; confined to this selftest; production creation above always calls CSPRNG.
data_crypto_selftest:
    push rbx
    push r12
    call data_crypto_lock_acquire
    mov  byte [rel dce_m_dek], 0
    mov  byte [rel dce_m_envelope], 0
    mov  byte [rel dce_m_owner], 0
    mov  byte [rel dce_m_guest], 0
    lea  rdi, [rel dce_kat_record]
    mov  esi, DCE_OWNER_PID
    lea  rdx, [rel dce_kat_key]
    mov  ecx, dce_kat_key.len
    lea  r8, [rel dce_kat_plain]
    mov  r9d, 8
    sub  rsp, 24
    lea  rax, [rel dce_kat_material]
    mov  [rsp], rax
    lea  rax, [rel dce_kat_cred]
    mov  [rsp + 8], rax
    mov  qword [rsp + 16], dce_kat_cred.len
    call dce_seal_material_internal
    add  rsp, 24
    test eax, eax
    jnz  .fail
    lea  rax, [rel dce_kat_cred]
    mov  [rel dce_active_cred], rax
    mov  qword [rel dce_active_cred_len], dce_kat_cred.len
    lea  rdi, [rel dce_kat_record]
    mov  esi, DCE_OWNER_PID
    lea  rdx, [rel dce_kat_key]
    mov  ecx, dce_kat_key.len
    lea  r8, [rel dce_kat_open]
    mov  r9d, DCE_CIPHER_CAP
    call dce_open_internal
    cmp  eax, 8
    jne  .fail
    lea  rdi, [rel dce_kat_open]
    lea  rsi, [rel dce_kat_plain]
    mov  edx, 8
    call memcmp
    test eax, eax
    jnz  .fail
    mov  rax, [rel dce_kat_record + DCE_CIPHERTEXT]
    cmp  rax, [rel dce_kat_plain]
    je   .fail
    call dce_record_contains_kat_plain
    test eax, eax
    jnz  .fail
    cmp  qword [rel dce_last_kek_fp], 0
    je   .fail
    cmp  qword [rel dce_last_dek_fp], 0
    je   .fail

    ; Wrong credential: authenticated DEK unwrap refuses before data release.
    lea  rdi, [rel dce_kat_record]
    mov  esi, DCE_OWNER_PID
    lea  rdx, [rel dce_kat_wrong_cred]
    mov  ecx, dce_kat_wrong_cred.len
    lea  r8, [rel dce_dek]
    call dce_unwrap_internal
    cmp  eax, -2
    jne  .fail

    ; Foreign principal: same credential, different pid-derived KEK -> AEAD deny.
    lea  rdi, [rel dce_kat_record]
    mov  esi, 424242
    lea  rdx, [rel dce_kat_key]
    mov  ecx, dce_kat_key.len
    lea  r8, [rel dce_kat_foreign]
    mov  r9d, DCE_CIPHER_CAP
    call dce_open_internal
    cmp  eax, -2
    jne  .fail

    ; Malformed header is rejected before any key or payload access.
    xor  byte [rel dce_kat_record + DCE_MAGIC], 0x7f
    lea  rdi, [rel dce_kat_record]
    mov  esi, DCE_OWNER_PID
    lea  rdx, [rel dce_kat_key]
    mov  ecx, dce_kat_key.len
    lea  r8, [rel dce_kat_foreign]
    mov  r9d, DCE_CIPHER_CAP
    call dce_open_internal
    xor  byte [rel dce_kat_record + DCE_MAGIC], 0x7f
    cmp  eax, -1
    jne  .fail

    ; The reserved NULL-credential consumer is executable from day one but is
    ; explicitly ephemeral: seal/open return the distinct no-record result and
    ; a seal attempt leaves every durable-envelope byte zero.
    lea  rdi, [rel dce_kat_record]
    xor  esi, esi
    lea  rdx, [rel dce_kat_key]
    mov  ecx, dce_kat_key.len
    lea  r8, [rel dce_kat_plain]
    mov  r9d, 8
    sub  rsp, 24
    lea  rax, [rel dce_kat_material]
    mov  [rsp], rax
    mov  qword [rsp + 8], 0
    mov  qword [rsp + 16], 0
    call dce_seal_material_internal
    add  rsp, 24
    cmp  eax, -3
    jne  .fail
    lea  rdi, [rel dce_kat_record]
    lea  rsi, [rel dce_kat_zero]
    mov  edx, DCE_RECORD_SIZE
    call memcmp
    test eax, eax
    jnz  .fail
    mov  qword [rel dce_active_cred], 0
    mov  qword [rel dce_active_cred_len], 0
    lea  rdi, [rel dce_kat_record]
    xor  esi, esi
    lea  rdx, [rel dce_kat_key]
    mov  ecx, dce_kat_key.len
    lea  r8, [rel dce_kat_foreign]
    mov  r9d, DCE_CIPHER_CAP
    call dce_open_internal
    cmp  eax, -3
    jne  .fail
    mov  byte [rel dce_m_guest], 1

    lea  rdi, [rel str_dce_m_dek]
    call serial_string
    lea  rdi, [rel str_dce_m_envelope]
    call serial_string
    lea  rdi, [rel str_dce_m_owner]
    call serial_string
    mov  byte [rel dce_m_dek], 1
    mov  byte [rel dce_m_envelope], 1
    mov  byte [rel dce_m_owner], 1
    xor  ebx, ebx
    jmp  .out
.fail:
    lea  rdi, [rel str_dce_fail]
    call serial_string
    mov  ebx, -1
.out:
    mov  qword [rel dce_active_cred], 0
    mov  qword [rel dce_active_cred_len], 0
    call dce_wipe_keys
    call data_crypto_lock_release
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_data_crypto_envelope_1 0
align 8
data_crypto_lock:         db 0
dce_m_dek:                db 0
dce_m_envelope:           db 0
dce_m_owner:              db 0
dce_m_guest:              db 0
align 8
dce_plain_ptr:            dq 0
dce_plain_len:            dq 0
dce_seal_cred:            dq 0
dce_seal_cred_len:        dq 0
dce_open_cap:             dq 0
dce_active_cred:          dq 0
dce_active_cred_len:      dq 0
dce_last_kek_fp:          dq 0
dce_last_dek_fp:          dq 0
dce_aead_req:             times AEAD_REQ_SZ db 0
dce_owner_state:          times AEAD_OWNER_SZ db 0
dce_auth_key:             times 32 db 0
dce_kek:                  times 32 db 0
dce_dek:                  times 32 db 0
dce_wrap_aad:             times DCE_WRAP_AAD_LEN db 0
dce_kek_info:             times DCE_KEK_INFO_LEN db 0
dce_sha_ctx:              times S256_CTX_SZ db 0
dce_hash_digest:          times 32 db 0
dce_fp_digest:            times 16 db 0
dce_key_hash_check:       times 16 db 0
dce_random_material_live: times DCE_RANDOM_LEN db 0
dce_rekey_plain_len:      dq 0
dce_rekey_new_cred_len:   dq 0
dce_rekey_plain:          times DCE_CIPHER_CAP db 0
dce_rekey_verify_plain:   times DCE_CIPHER_CAP db 0
dce_rekey_verify_dek:     times 32 db 0
dce_rekey_nonces:         times 24 db 0          ; SEC-B1: fresh wrap||data nonces for one rekey

dce_wrap_domain: db "PaOS-DATA-WRAP1!"       ; 16 bytes
dce_kek_domain:  db "PaOS-DATA-KEK1!!"       ; 16 bytes; pid follows in info

; Deterministic boot-only material: salt8 || DEK32 || wrap nonce12 || data nonce12.
dce_kat_material:
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    db 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    db 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    db 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
; Separate 1057 boot-KAT material; never used by a live durable write.
dce_store_kat_material:
    db 0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
    db 0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f
    db 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
    db 0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f
dce_kat_key:        db "kat-key"
.len equ $ - dce_kat_key
dce_kat_plain:      db "DSEC-KAT"
dce_kat_cred:       db "kat-owner-credential"
.len equ $ - dce_kat_cred
dce_kat_wrong_cred: db "not-the-owner"
.len equ $ - dce_kat_wrong_cred
dce_kat_record:     times DCE_RECORD_SIZE db 0
dce_kat_zero:       times DCE_RECORD_SIZE db 0
dce_kat_open:       times DCE_CIPHER_CAP db 0
dce_kat_foreign:    times DCE_CIPHER_CAP db 0

str_dce_m_dek:      db "[PAOS64] P2 dcrypt: per-principal DEK wrap/unwrap KAT PASS [crypto.dek]",13,10,0
str_dce_m_envelope: db "[PAOS64] P2 dcrypt: at-rest encrypt/decrypt envelope KAT PASS [crypto.envelope]",13,10,0
str_dce_m_owner:    db "[PAOS64] P2 dcrypt: OWNER key hierarchy established [crypto.owner]",13,10,0
str_dce_fail:       db "[PAOS64] P2 dcrypt: authenticated DATA envelope KAT FAIL",13,10,0
%endmacro
WDATA_DEFER WDATA_data_crypto_envelope_1
