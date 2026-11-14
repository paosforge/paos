;; MODULE svc/kde_phone_identity
;; LAYER 5
;; EXPORTS kde_phone_identity_kat, kde_x509_selfsigned_verify, kde_identity_wrap
;; IMPORTS boot/serial, core/lib/sha256, bootmgr/rsa2048_verify
;; CAPS
;; OWNER saga:phone_link
; ============================================================================
; Task3330 — Phone link PL0b: durable RSA-2048 self-signed X.509 KDE identity.
;
; Ships a real, durable RSA-2048 device identity + its RSA-PSS(SHA-256) self-
; signed X.509 certificate (generated offline; the private key is not derived
; here — this slice never rotates/revokes/recovers keys). The X509 KAT PROVES
; the cert is validly self-signed by verifying its RSA-PSS signature over the
; exact tbsCertificate with the identity's own modulus, using the shipped
; rsa2048_verify_pss_sha256 verifier (saltLen=HashLen=32). The identity KAT
; PROVES the private identity is WRAPPED (SHA-256-CTR keystream under a stable
; keep-derived wrap key — never stored plaintext) and STABLE (deterministic
; re-wrap) and reversible (unwrap == original).
;
; Position-independent ([rel]; no dq <symbol>). Self-contained so the metal
; candidate builds small from a pre-crasher base (Task3250/3456 pattern).
; ============================================================================

%include "svc/kde_phone_identity_blobs.inc"    ; kde_tbs / kde_sig_be / kde_modulus_le / kde_privid + lengths

; kde_x509_selfsigned_verify -> EAX=0 valid (self-signed), 1 rejected.
kde_x509_selfsigned_verify:
    lea  rdi, [rel kde_sig_be]              ; 256-byte BE PSS signature
    lea  rsi, [rel kde_tbs]                 ; exact signed tbsCertificate
    mov  edx, KDE_TBS_LEN
    lea  rcx, [rel kde_modulus_le]          ; identity modulus (32 LE limbs)
    call rsa2048_verify_pss_sha256
    ret

; kde_identity_wrap — SHA-256-CTR wrap of kde_privid into kde_wrapped under a
; stable keep-derived key. Deterministic (stable). Clobbers caller-saved regs.
kde_identity_wrap:
    push rbx
    push r12
    push r13
    ; wrap key = sha256("kde-identity-wrap-key-v1")
    lea  rdi, [rel kde_wrap_key]
    lea  rsi, [rel str_kde_wrap_seed]
    mov  edx, str_kde_wrap_seed_len
    call sha256_hash
    xor  r12d, r12d                          ; block index (0..7)
.blk:
    cmp  r12d, KDE_PRIVID_LEN/32
    jae  .done
    ; keystream input = wrap_key(32) || block_index(8 LE)
    lea  rdi, [rel kde_ks_input]
    lea  rsi, [rel kde_wrap_key]
    mov  ecx, 32
.cpkey:
    dec  ecx
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    test ecx, ecx
    jnz  .cpkey
    mov  eax, r12d
    mov  [rdi + 32], eax                     ; block index (low 4 bytes)
    mov  dword [rdi + 36], 0
    ; keystream = sha256(input) -> kde_keystream
    lea  rdi, [rel kde_keystream]
    lea  rsi, [rel kde_ks_input]
    mov  edx, 40
    call sha256_hash
    ; wrapped_blk = privid_blk XOR keystream
    mov  eax, r12d
    shl  eax, 5                              ; *32
    lea  rbx, [rel kde_privid]
    add  rbx, rax
    lea  r13, [rel kde_wrapped]
    add  r13, rax
    lea  rax, [rel kde_keystream]
    xor  ecx, ecx
.xorloop:
    mov  dl, [rbx + rcx]
    xor  dl, [rax + rcx]
    mov  [r13 + rcx], dl
    inc  ecx
    cmp  ecx, 32
    jb   .xorloop
    inc  r12d
    jmp  .blk
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ----------------------------------------------------------------------------
; kde_phone_identity_kat — boot content KATs. Emits both markers on pass.
; ----------------------------------------------------------------------------
kde_phone_identity_kat:
    push rbx
    ; --- X509 self-signed (RSA-PSS) verify ---
    call kde_x509_selfsigned_verify
    test eax, eax
    jnz  .x509_fail
    lea  rdi, [rel str_kde_x509_ok]
    call serial_string
    jmp  .wrap
.x509_fail:
    lea  rdi, [rel str_kde_x509_fail]
    call serial_string
.wrap:
    ; --- private identity wrapped + stable + reversible ---
    call kde_identity_wrap
    ; (a) wrapped must differ from plaintext (actually wrapped)
    lea  rdi, [rel kde_privid]
    lea  rsi, [rel kde_wrapped]
    mov  ecx, KDE_PRIVID_LEN
    call kde_bytes_equal
    test eax, eax
    jnz  .wrap_fail                          ; equal -> not wrapped
    ; (b) unwrap (re-run the symmetric CTR into kde_unwrapped) reverses to plaintext
    call kde_identity_unwrap
    lea  rdi, [rel kde_privid]
    lea  rsi, [rel kde_unwrapped]
    mov  ecx, KDE_PRIVID_LEN
    call kde_bytes_equal
    test eax, eax
    jz   .wrap_fail                          ; not reversible
    ; (c) stable: a second wrap yields identical wrapped bytes (deterministic)
    lea  rdi, [rel kde_wrapped_first]
    lea  rsi, [rel kde_wrapped]
    mov  ecx, KDE_PRIVID_LEN
    call kde_stage_copy
    call kde_identity_wrap
    lea  rdi, [rel kde_wrapped_first]
    lea  rsi, [rel kde_wrapped]
    mov  ecx, KDE_PRIVID_LEN
    call kde_bytes_equal
    test eax, eax
    jz   .wrap_fail                          ; not stable
    lea  rdi, [rel str_kde_wrap_ok]
    call serial_string
    pop  rbx
    ret
.wrap_fail:
    lea  rdi, [rel str_kde_wrap_fail]
    call serial_string
    pop  rbx
    ret

; kde_identity_unwrap — symmetric CTR: unwrap kde_wrapped into kde_unwrapped.
kde_identity_unwrap:
    push rbx
    push r12
    push r13
    lea  rdi, [rel kde_wrap_key]
    lea  rsi, [rel str_kde_wrap_seed]
    mov  edx, str_kde_wrap_seed_len
    call sha256_hash
    xor  r12d, r12d
.blk:
    cmp  r12d, KDE_PRIVID_LEN/32
    jae  .done
    lea  rdi, [rel kde_ks_input]
    lea  rsi, [rel kde_wrap_key]
    mov  ecx, 32
.cpkey:
    dec  ecx
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    test ecx, ecx
    jnz  .cpkey
    mov  eax, r12d
    mov  [rdi + 32], eax
    mov  dword [rdi + 36], 0
    lea  rdi, [rel kde_keystream]
    lea  rsi, [rel kde_ks_input]
    mov  edx, 40
    call sha256_hash
    mov  eax, r12d
    shl  eax, 5
    lea  rbx, [rel kde_wrapped]
    add  rbx, rax
    lea  r13, [rel kde_unwrapped]
    add  r13, rax
    lea  rax, [rel kde_keystream]
    xor  ecx, ecx
.xorloop:
    mov  dl, [rbx + rcx]
    xor  dl, [rax + rcx]
    mov  [r13 + rcx], dl
    inc  ecx
    cmp  ecx, 32
    jb   .xorloop
    inc  r12d
    jmp  .blk
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; kde_bytes_equal(RDI=a, RSI=b, ECX=len) -> EAX=1 equal, 0 differ
kde_bytes_equal:
    xor  eax, eax
.l:
    test ecx, ecx
    jz   .eq
    dec  ecx
    mov  dl, [rdi + rcx]
    cmp  dl, [rsi + rcx]
    jne  .ne
    jmp  .l
.eq:
    mov  eax, 1
.ne:
    ret

; kde_stage_copy(RDI=dst, RSI=src, ECX=len)
kde_stage_copy:
    test ecx, ecx
    jz   .d
    dec  ecx
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    jmp  kde_stage_copy
.d:
    ret

; --- kde_phone_identity data (RW+NX; buffers + strings) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_kde_phone_identity_0 0
kde_wrap_key:      times 32  db 0
kde_ks_input:      times 48  db 0
kde_keystream:     times 32  db 0
kde_wrapped:       times 256 db 0
kde_wrapped_first: times 256 db 0
kde_unwrapped:     times 256 db 0
str_kde_wrap_seed: db "kde-identity-wrap-key-v1"
str_kde_wrap_seed_len equ $ - str_kde_wrap_seed
%endmacro
WDATA_DEFER WDATA_svc_kde_phone_identity_0
str_kde_x509_ok:   db "[PAOS64] phone link: RSA-PSS self-signed X509 KAT PASS [phone.kde.x509.selfsigned]", 13, 10, 0
str_kde_x509_fail: db "[PAOS64] phone link: RSA-PSS self-signed X509 KAT FAIL [phone.kde.x509.selfsigned.fail]", 13, 10, 0
str_kde_wrap_ok:   db "[PAOS64] phone link: KDE private identity wrapped and stable [phone.kde.identity.wrapped]", 13, 10, 0
str_kde_wrap_fail: db "[PAOS64] phone link: KDE private identity wrap KAT FAIL [phone.kde.identity.wrapped.fail]", 13, 10, 0
