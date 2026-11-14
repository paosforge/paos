;; MODULE svc/m1_checkpoint
;; LAYER 5
;; EXPORTS m1_push_record_present, m1_commit, m1_restore_candidate, m1_next_generation, m1_var_get, m1_seal, m1_open, m1_ckpt_check, m1_pair_plan, m1_restore_decide, m1_ledger_init, m1_ledger_append, m1_ledger_verify, m1_history_append, m1_history_status
;; IMPORTS core/lib/sha256, core/lib/mem, core/lib/aes256_gcm, core/lib/auth_derive, core/csprng, sec/principal, boot/boot_v2_handoff, boot/boot_v2_health, boot/header, boot/nvram_access, fs/storage_access
;; CAPS
;; OWNER saga:rc_power
; ============================================================================
; svc/m1_checkpoint.asm — RCQ-27 POWER-06/07 slice 1 (root 2026-10-08 08:32 (b)):
; the M1 checkpoint + off format, decisions, sealing and runtime persistence.
; The pure format/decision region remains independently host-tested. Seals under
; the OWNER's key hierarchy (root 2026-10-08 10:22, D1): owner credential ->
; auth_derive_key(salt) -> HKDF -> AES-256-GCM; no owner key = no checkpoint (the
; trigger takes the plain safe off). Slice 3 runs the S5 quiesce and the qualified
; power-off. Design:
; gauntlet_v2/docs/rc_standing_source/RCQ-27-m1-checkpoint/M1_CHECKPOINT_DESIGN.md
;
; Checkpoint slot image. One logical checkpoint per owner, written with the
; fs/safe_write protocol over two PaOS NVRAM variables (admin 09:57): TMP first,
; read back and verified (check + AEAD open), then PRIMARY, read back and verified;
; PRIMARY is last-good until TMP verifies. Restore needs both to verify and be
; byte-identical (m1_pair_plan); a torn or interrupted commit boots fresh.
;   +0   magic 'PAOSCKP1'     +8  version (dw 2)   +10 header length (dw 128)
;   +12  payload length (dd, ciphertext bytes, >= 1)
;   +16  generation (dq, > 0)
;   +24  key fingerprint (dq, nonzero; identifies the sealing key)
;   +32  build: SHA-256 of the Manager-verified payload (32 B, nonzero)
;   +64  AES-GCM nonce (12 B)
;   +76  owner principal (dd)   +80 enrollment identity (dq)   (root D4)
;   +88  key-derivation salt (16 B, fresh per seal)
;   +104 reserved (24 B, zero)
;   +128 ciphertext [payload length]   then the GCM tag (16 B)
; The whole header is the AEAD's additional data, so the tag covers it.
; Version 2 (M1-2): v1 was integrated with no caller and never written.
; ============================================================================

M1_MAGIC          equ 0x31504B43534F4150    ; "PAOSCKP1"
M1_VERSION        equ 2
M1_HDR_LEN        equ 128
M1_TAG_LEN        equ 16
M1_SLOT_CAP       equ 2048                  ; bytes per NVRAM variable, header + ciphertext + tag (admin 09:57: well under 8 KiB)
M1_H_VERSION      equ 8
M1_H_HDRLEN       equ 10
M1_H_PAYLOAD      equ 12
M1_H_GEN          equ 16
M1_H_KEYFP        equ 24
M1_H_BUILD        equ 32
M1_H_NONCE        equ 64
M1_H_OWNER        equ 76
M1_H_ENROLL       equ 80
M1_H_SALT         equ 88
M1_SALT_LEN       equ 16
M1_H_RESERVED     equ 104
M1_RESERVED_LEN   equ 24
; m1_ckpt_check reasons (0 = header acceptable; the AEAD tag is checked by the opener)
M1_OK             equ 0
M1_R_SHORT        equ 1                     ; fewer bytes than a header
M1_R_MAGIC        equ 2
M1_R_VERSION      equ 3                     ; version or header length not this build's format
M1_R_RESERVED     equ 4
M1_R_EMPTY        equ 5                     ; no payload or generation 0
M1_R_CAPACITY     equ 6                     ; would not fit a slot
M1_R_TRUNCATED    equ 7                     ; the bytes read are not exactly the declared size
M1_R_BUILD        equ 8                     ; another build, or this build is unverified
M1_R_KEY          equ 9                     ; sealed under another (or no) key
M1_R_OWNER        equ 10                    ; another principal or enrollment (root D4), or no owner this boot
; expected identity passed to m1_ckpt_check
M1_X_BUILD        equ 0                     ; 32 B: this boot's verified payload SHA-256 (zero if unbound)
M1_X_KEYFP        equ 32                    ; dq: this boot's sealing-key fingerprint (zero if unavailable)
M1_X_OWNER        equ 40                    ; dd: the expected principal (zero: no owner signed in)
M1_X_ENROLL       equ 48                    ; dq: the expected enrollment identity (zero: none)
M1_X_SIZE         equ 56
; slot summaries for m1_pair_plan: [0] TMP, [1] PRIMARY, each { dd status (0 = valid), dd 0, dq generation }
M1_S_STATUS       equ 0
M1_S_GEN          equ 8
M1_S_SIZE         equ 16
M1_P_OK           equ 0                     ; m1_pair_plan reasons (EDX)
M1_P_NONE         equ 1                     ; neither variable holds a valid checkpoint
M1_P_DISAGREE     equ 2                     ; torn or interrupted commit: the two differ
; m1_restore_decide inputs (EDI bits) and results
M1_IN_VALID       equ 1                     ; header OK and the AEAD tag verified
M1_IN_ATTEMPTED   equ 2                     ; this generation's restore was already attempted
M1_IN_SIGNED_IN   equ 4                     ; the owner has signed in this boot
M1_IN_FRESH_ASKED equ 8                     ; the owner chose a fresh session
M1_D_FRESH        equ 0                     ; discard (never delete): boot fresh
M1_D_RESTORE      equ 1
M1_D_WAIT         equ 2                     ; keep the lock boundary: nothing applies before sign-in
M1_F_NONE         equ 0                     ; fresh reasons (EDX)
M1_F_INVALID      equ 1
M1_F_ATTEMPTED    equ 2
M1_F_ASKED        equ 3
; wake ledger (append-only; one NVRAM variable): header + M1_LEDGER_CAP entries
M1_LEDGER_MAGIC   equ 0x31474C57534F4150    ; "PAOSWLG1"
M1_LEDGER_CAP     equ 32
M1_L_MAGIC        equ 0
M1_L_COUNT        equ 8                     ; dd entries held
M1_L_CAPF         equ 12                    ; dd capacity (== M1_LEDGER_CAP)
M1_L_NEXT         equ 16                    ; dq next sequence number (first is 1)
M1_L_DROPPED      equ 24                    ; dq entries evicted, oldest first, never silently
M1_L_ANCHOR       equ 32                    ; 32 B: SHA-256 of the last evicted entry (zero if none)
M1_L_HDR          equ 64
M1_E_SEQ          equ 0                     ; dq
M1_E_BODY         equ 8                     ; 24 B caller record (kind, wake source, energy, reason, times)
M1_E_PREV         equ 32                    ; 32 B: SHA-256 of the previous entry (the anchor for the first held)
M1_E_SIZE         equ 64
M1_E_BODY_LEN     equ 24
M1_LEDGER_SIZE    equ M1_L_HDR + M1_LEDGER_CAP * M1_E_SIZE
M1_PAYLOAD_CAP    equ M1_SLOT_CAP - M1_HDR_LEN - M1_TAG_LEN
M1_R_TAG          equ 11                    ; m1_open: the AEAD tag did not verify
M1_R_OUTPUT       equ 12                    ; m1_open: the caller's buffer is too small
M1_SEAL_BAD       equ -1                    ; m1_seal results (RAX < 0)
M1_SEAL_NO_KEY    equ -2                    ; no owner key: the trigger takes the plain safe off
M1_SEAL_RNG       equ -3                    ; the CSPRNG refused (unseeded / unhealthy): nothing sealed
M1_HASH_IN_LEN    equ 48                    ; the longest tag (14) + a 32-byte key
; M1-3 storage (admin 09:57; root 10:22 D3): EFI runtime variables, PaOS vendor GUID
M1_RT_GETVAR      equ 0x48                  ; EFI_RUNTIME_SERVICES.GetVariable
M1_RT_SETVAR      equ 0x58                  ; .SetVariable
M1_RT_QVI         equ 0x80                  ; .QueryVariableInfo (UEFI >= 2.0)
M1_RT_REV_QVI     equ 0x00020000
M1_VAR_ATTRS      equ 7                     ; NV | BS | RT, as every PaOS NVRAM record
M1_EFI_NOT_FOUND  equ 0x800000000000000E
M1_EFI_NO_SPACE   equ 0x8000000000000009    ; EFI_OUT_OF_RESOURCES
M1_SPACE_MARGIN   equ 4096                  ; leave this much variable storage for other records
M1_VAR_ERR        equ -1                    ; m1_var_set / m1_commit results
M1_VAR_NO_SPACE   equ -2                    ; the firmware reports too little space: nothing written
M1_PLAIN_CAP      equ M1_PAYLOAD_CAP
; m1_restore_candidate fresh reasons (EDX when EAX = 0)
M1_C_NONE         equ 1                     ; no checkpoint
M1_C_DOUBT        equ 2                     ; invalid, torn or disagreeing TMP/PRIMARY
M1_C_ATTEMPTED    equ 3                     ; generation <= the attempted high-water mark
M1_C_MARK_FAILED  equ 4                     ; the high-water mark could not be written first
M1_C_NO_RUNTIME   equ 5                     ; no runtime variable services on this boot

; BEGIN PURE M1 CHECKPOINT -- the host fixture assembles this region.

; m1_ckpt_check(RDI = slot image, ESI = bytes read, RDX = expected identity) -> EAX
;   M1_OK or the first refusal reason, in the order listed above. Reads only.
m1_ckpt_check:
    mov  eax, M1_R_SHORT
    test rdi, rdi
    jz   .out
    test rdx, rdx
    jz   .out
    cmp  esi, M1_HDR_LEN
    jb   .out
    mov  eax, M1_R_MAGIC
    mov  rcx, M1_MAGIC
    cmp  [rdi], rcx
    jne  .out
    mov  eax, M1_R_VERSION
    cmp  word [rdi + M1_H_VERSION], M1_VERSION
    jne  .out
    cmp  word [rdi + M1_H_HDRLEN], M1_HDR_LEN
    jne  .out
    mov  eax, M1_R_RESERVED
    xor  ecx, ecx
.reserved:
    cmp  byte [rdi + M1_H_RESERVED + rcx], 0
    jne  .out
    inc  ecx
    cmp  ecx, M1_RESERVED_LEN
    jb   .reserved
    mov  eax, M1_R_EMPTY
    mov  ecx, [rdi + M1_H_PAYLOAD]
    test ecx, ecx
    jz   .out
    cmp  qword [rdi + M1_H_GEN], 0
    je   .out
    mov  eax, M1_R_CAPACITY
    cmp  ecx, M1_SLOT_CAP - M1_HDR_LEN - M1_TAG_LEN
    ja   .out                               ; also keeps the sum below from wrapping
    add  ecx, M1_HDR_LEN + M1_TAG_LEN
    mov  eax, M1_R_TRUNCATED
    cmp  ecx, esi
    jne  .out                               ; exactly the declared size (srcreview NIT: no trailing bytes)
    mov  eax, M1_R_BUILD
    xor  r8d, r8d
    xor  ecx, ecx
.build:
    mov  r9, [rdx + M1_X_BUILD + rcx]
    or   r8, r9                             ; this boot's build must be bound (nonzero)
    cmp  r9, [rdi + M1_H_BUILD + rcx]
    jne  .out
    add  ecx, 8
    cmp  ecx, 32
    jb   .build
    test r8, r8
    jz   .out
    mov  eax, M1_R_OWNER                    ; root D4: the same owner and enrollment
    mov  ecx, [rdx + M1_X_OWNER]
    test ecx, ecx
    jz   .out
    cmp  ecx, [rdi + M1_H_OWNER]
    jne  .out
    mov  rcx, [rdx + M1_X_ENROLL]
    test rcx, rcx
    jz   .out
    cmp  rcx, [rdi + M1_H_ENROLL]
    jne  .out
    mov  eax, M1_R_KEY
    mov  rcx, [rdx + M1_X_KEYFP]
    test rcx, rcx
    jz   .out                               ; no key this boot: never a plaintext fallback
    cmp  rcx, [rdi + M1_H_KEYFP]
    jne  .out
    xor  eax, eax
.out:
    ret

; m1_pair_plan(RDI = summaries [TMP, PRIMARY], ESI = 1 when the two variables
;   are byte-identical) -> EAX 1 restore PRIMARY / 0 none, EDX M1_P_* reason, RCX
;   the generation to write next (newest valid + 1; UINT64_MAX: refuse, exhausted).
;   Restore only after a completed commit: both valid and identical. Anything else
;   (only one valid, different bytes, a torn PRIMARY or TMP) is doubt: fresh.
m1_pair_plan:
    xor  r8d, r8d                           ; r8 = TMP generation if valid, else 0
    xor  r10d, r10d                         ; valid count
    cmp  dword [rdi + M1_S_STATUS], 0
    jne  .p
    mov  r8, [rdi + M1_S_GEN]
    inc  r10d
.p:
    xor  r9d, r9d
    cmp  dword [rdi + M1_S_SIZE + M1_S_STATUS], 0
    jne  .gen
    mov  r9, [rdi + M1_S_SIZE + M1_S_GEN]
    inc  r10d
.gen:
    mov  rcx, r8
    cmp  r9, rcx
    jbe  .have_max
    mov  rcx, r9
.have_max:
    cmp  rcx, -1
    je   .decide
    inc  rcx
.decide:
    xor  eax, eax
    mov  edx, M1_P_NONE
    test r10d, r10d
    jz   .out
    mov  edx, M1_P_DISAGREE
    cmp  r10d, 2
    jne  .out
    cmp  esi, 1
    jne  .out
    cmp  r8, r9
    jne  .out                               ; identical bytes carry one generation
    mov  eax, 1
    xor  edx, edx
.out:
    ret

; m1_restore_decide(EDI = M1_IN_* bits) -> EAX M1_D_*, EDX M1_F_* reason.
;   "Any doubt -> discard and boot fresh": only a valid, not yet attempted
;   checkpoint restores, and only after the owner signs in (before that: wait).
m1_restore_decide:
    mov  eax, M1_D_FRESH
    mov  edx, M1_F_INVALID
    test edi, M1_IN_VALID
    jz   .out
    mov  edx, M1_F_ATTEMPTED
    test edi, M1_IN_ATTEMPTED
    jnz  .out                               ; a restore that did not finish never loops
    mov  edx, M1_F_ASKED
    test edi, M1_IN_FRESH_ASKED
    jnz  .out
    xor  edx, edx
    mov  eax, M1_D_WAIT
    test edi, M1_IN_SIGNED_IN
    jz   .out
    mov  eax, M1_D_RESTORE
.out:
    ret

; m1_ledger_init(RDI = M1_LEDGER_SIZE buffer): an empty ledger. Clobbers RAX, RCX, RDI.
m1_ledger_init:
    push rdi
    xor  eax, eax
    mov  ecx, M1_LEDGER_SIZE / 8
    rep  stosq
    pop  rdi
    mov  rax, M1_LEDGER_MAGIC
    mov  [rdi + M1_L_MAGIC], rax
    mov  dword [rdi + M1_L_CAPF], M1_LEDGER_CAP
    mov  qword [rdi + M1_L_NEXT], 1
    ret

; m1_ledger_append(RDI = ledger, RSI = 24-byte body) -> EAX 0, or -1 if the ledger
;   does not verify or its sequence is exhausted (nothing is changed then).
;   Held entries are never rewritten:
;   when full, the oldest is evicted into the anchor (its SHA-256) and counted.
m1_ledger_append:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    call m1_ledger_verify
    test eax, eax
    jnz  .bad
    cmp  qword [rbx + M1_L_NEXT], -1         ; never wrap the append-only sequence
    je   .bad
    cmp  dword [rbx + M1_L_COUNT], M1_LEDGER_CAP
    jb   .room
    lea  rdi, [rbx + M1_L_ANCHOR]           ; evict the oldest: anchor = SHA-256(entry 0)
    lea  rsi, [rbx + M1_L_HDR]
    mov  edx, M1_E_SIZE
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rbx + M1_L_HDR]
    lea  rsi, [rbx + M1_L_HDR + M1_E_SIZE]
    mov  ecx, (M1_LEDGER_CAP - 1) * M1_E_SIZE / 8
    rep  movsq
    inc  qword [rbx + M1_L_DROPPED]
    dec  dword [rbx + M1_L_COUNT]
.room:
    mov  eax, [rbx + M1_L_COUNT]
    shl  eax, 6                             ; * M1_E_SIZE
    lea  r13, [rbx + M1_L_HDR + rax]        ; the new entry
    mov  rax, [rbx + M1_L_NEXT]
    mov  [r13 + M1_E_SEQ], rax
    mov  rax, [r12]
    mov  [r13 + M1_E_BODY], rax
    mov  rax, [r12 + 8]
    mov  [r13 + M1_E_BODY + 8], rax
    mov  rax, [r12 + 16]
    mov  [r13 + M1_E_BODY + 16], rax
    cmp  dword [rbx + M1_L_COUNT], 0
    jne  .chain
    lea  rsi, [rbx + M1_L_ANCHOR]           ; the first held entry links to the anchor
    lea  rdi, [r13 + M1_E_PREV]
    mov  ecx, 4
    rep  movsq
    jmp  .linked
.chain:
    lea  rdi, [r13 + M1_E_PREV]
    lea  rsi, [r13 - M1_E_SIZE]
    mov  edx, M1_E_SIZE
    call sha256_hash
    test rax, rax
    jnz  .bad
.linked:
    inc  qword [rbx + M1_L_NEXT]
    inc  dword [rbx + M1_L_COUNT]
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; m1_ledger_verify(RDI = ledger) -> EAX 0 when the header is sane, every held
;   entry's sequence is dropped+i+1, next == dropped+count+1, and every link is the
;   SHA-256 of its predecessor (the anchor for the first). Else EAX = 1 (header),
;   or 2 + the index of the first bad entry. Reads only.
m1_ledger_verify:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 40                            ; 32-byte digest scratch, 16-aligned frame
    mov  rbx, rdi
    mov  eax, 1
    mov  rcx, M1_LEDGER_MAGIC
    cmp  [rbx + M1_L_MAGIC], rcx
    jne  .out
    cmp  dword [rbx + M1_L_CAPF], M1_LEDGER_CAP
    jne  .out
    mov  r12d, [rbx + M1_L_COUNT]
    cmp  r12d, M1_LEDGER_CAP
    ja   .out
    mov  rcx, [rbx + M1_L_DROPPED]
    add  rcx, r12
    jc   .out
    add  rcx, 1
    jc   .out
    cmp  rcx, [rbx + M1_L_NEXT]
    jne  .out
    cmp  qword [rbx + M1_L_DROPPED], 0
    jne  .anchored
    mov  rcx, [rbx + M1_L_ANCHOR]           ; genesis is pinned: no eviction, no anchor
    or   rcx, [rbx + M1_L_ANCHOR + 8]
    or   rcx, [rbx + M1_L_ANCHOR + 16]
    or   rcx, [rbx + M1_L_ANCHOR + 24]
    jnz  .out
.anchored:
    xor  r13d, r13d                         ; entry index
.entry:
    cmp  r13d, r12d
    jae  .ok
    mov  r14d, r13d
    shl  r14d, 6
    lea  r14, [rbx + M1_L_HDR + r14]
    lea  eax, [r13 + 2]
    mov  rcx, [rbx + M1_L_DROPPED]
    add  rcx, r13
    inc  rcx
    cmp  rcx, [r14 + M1_E_SEQ]
    jne  .out
    test r13d, r13d
    jnz  .hash_prev
    lea  rsi, [rbx + M1_L_ANCHOR]
    jmp  .compare
.hash_prev:
    mov  rdi, rsp
    lea  rsi, [r14 - M1_E_SIZE]
    mov  edx, M1_E_SIZE
    call sha256_hash
    test rax, rax
    jnz  .out_bad_hash
    mov  rsi, rsp
.compare:
    lea  eax, [r13 + 2]
    xor  ecx, ecx
.cmp_loop:
    mov  rdx, [rsi + rcx]
    cmp  rdx, [r14 + M1_E_PREV + rcx]
    jne  .out
    add  ecx, 8
    cmp  ecx, 32
    jb   .cmp_loop
    inc  r13d
    jmp  .entry
.out_bad_hash:
    lea  eax, [r13 + 2]
    jmp  .out
.ok:
    xor  eax, eax
.out:
    add  rsp, 40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; END PURE M1 CHECKPOINT

; ---------------------------------------------------------------------------
; Slice M1-2: seal and open under the OWNER's key hierarchy (root 10:22, D1/D4/D5).
;   cred   = principal_credential(PRIN_OWNER): the signed-in owner's session key
;            (HKDF of the password master; stable across sign-ins of one
;            enrollment). No owner session -> no key -> no checkpoint.
;   enroll = SHA-256("paos.m1.enroll" || cred)[:8]: the enrollment identity (a
;            re-enrollment changes the salt, hence cred, hence this) (D4).
;   auth   = auth_derive_key(salt16, cred)        (the 1053 auth-derive seam)
;   key    = HKDF-SHA256(auth, salt16, "paos.m1.checkpoint.v2" || pid)
;   fp     = SHA-256("paos.m1.fp" || key)[:8]
;   AEAD   = AES-256-GCM, 96-bit nonce, the 128-byte header as AAD.
; salt and nonce come from the CSPRNG only; if it refuses (unseeded/unhealthy)
; nothing is sealed (D5). This is crypto_envelope's credential -> auth_derive ->
; HKDF KEK chain; the per-record DEK wrap is not needed for a record that is
; rewritten whole on every sleep. All derived bytes are wiped on every exit.
; ---------------------------------------------------------------------------

; m1_derive_key(RDI = 16-byte salt) -> EAX 0 with m1_key / m1_key_fp / m1_enroll
;   set, or -1 (no owner credential, KDF failure) with m1_key_fp = m1_enroll = 0.
m1_derive_key:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    mov  qword [rel m1_key_fp], 0
    mov  qword [rel m1_enroll], 0
    mov  edi, PRIN_OWNER
    call principal_credential               ; RAX = owner session key, RDX = length (0/0: none)
    test rax, rax
    jz   .none
    cmp  rdx, 32
    jne  .none
    mov  rbx, rax
    lea  rdi, [rel m1_hash_in]              ; enrollment identity
    lea  rsi, [rel m1_enroll_tag]
    mov  ecx, m1_enroll_tag.len
    rep  movsb
    mov  rsi, rbx
    mov  ecx, 32
    rep  movsb
    lea  rdi, [rel m1_hash_out]
    lea  rsi, [rel m1_hash_in]
    mov  edx, m1_enroll_tag.len + 32
    call sha256_hash
    test rax, rax
    jnz  .none
    mov  r12, [rel m1_hash_out]
    mov  rdi, r13                           ; auth = auth_derive_key(salt, cred)
    mov  esi, M1_SALT_LEN
    mov  rdx, rbx
    mov  ecx, 32
    lea  r8, [rel m1_auth]
    mov  r9d, 32
    call auth_derive_key
    test eax, eax
    jnz  .none
    lea  rdi, [rel m1_auth]                 ; key = HKDF(auth, salt, domain || pid)
    mov  esi, 32
    mov  rdx, r13
    mov  ecx, M1_SALT_LEN
    lea  r8, [rel m1_info]
    mov  r9d, m1_info.len
    sub  rsp, 8
    lea  rax, [rel m1_key]
    mov  [rsp], rax
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .none
    lea  rdi, [rel m1_hash_in]              ; fingerprint
    lea  rsi, [rel m1_fp_tag]
    mov  ecx, m1_fp_tag.len
    rep  movsb
    lea  rsi, [rel m1_key]
    mov  ecx, 32
    rep  movsb
    lea  rdi, [rel m1_hash_out]
    lea  rsi, [rel m1_hash_in]
    mov  edx, m1_fp_tag.len + 32
    call sha256_hash
    test rax, rax
    jnz  .none
    mov  rax, [rel m1_hash_out]
    test rax, rax
    jz   .none                              ; zero means "no key"
    test r12, r12
    jz   .none                              ; zero means "no enrollment"
    mov  [rel m1_key_fp], rax
    mov  [rel m1_enroll], r12
    call m1_wipe_scratch
    xor  eax, eax
    jmp  .out
.none:
    call m1_wipe_key
    mov  qword [rel m1_key_fp], 0
    mov  qword [rel m1_enroll], 0
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; m1_wipe_scratch: the auth key and the hash buffers. m1_wipe_key: those + the key.
m1_wipe_key:
    lea  rdi, [rel m1_key]
    xor  esi, esi
    mov  edx, 32
    call memset
m1_wipe_scratch:
    lea  rdi, [rel m1_auth]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel m1_hash_in]
    xor  esi, esi
    mov  edx, M1_HASH_IN_LEN
    call memset
    lea  rdi, [rel m1_hash_out]
    xor  esi, esi
    mov  edx, 32
    jmp  memset

; m1_expect_fill -> m1_expect = { this boot's verified payload SHA-256, m1_key_fp,
;   PRIN_OWNER (0 when no owner key), m1_enroll }.
m1_expect_fill:
    lea  rdi, [rel m1_expect + M1_X_BUILD]
    lea  rsi, [rel pbm_payload_sha]         ; all zero unless the Manager verified this payload
    mov  ecx, 32
    rep  movsb
    mov  rax, [rel m1_key_fp]
    mov  [rel m1_expect + M1_X_KEYFP], rax
    xor  eax, eax
    cmp  qword [rel m1_enroll], 0
    je   .owner
    mov  eax, PRIN_OWNER
.owner:
    mov  qword [rel m1_expect + M1_X_OWNER], rax
    mov  rax, [rel m1_enroll]
    mov  [rel m1_expect + M1_X_ENROLL], rax
    ret

; m1_seal(RDI = slot buffer of M1_SLOT_CAP bytes, RSI = plaintext, EDX = plaintext
;   length 1..M1_PAYLOAD_CAP, RCX = generation > 0) -> RAX = slot image length, or
;   M1_SEAL_BAD (arguments, unbound build, AEAD), M1_SEAL_NO_KEY (no owner key:
;   checkpoint skipped), M1_SEAL_RNG (the CSPRNG refused). Nothing is left
;   half-sealed that m1_open would accept.
m1_seal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, M1_SEAL_BAD
    test rbx, rbx
    jz   .out
    test r12, r12
    jz   .out
    test r13d, r13d
    jz   .out
    cmp  r13d, M1_PAYLOAD_CAP
    ja   .out
    test r14, r14
    jz   .out
    xor  eax, eax
    xor  ecx, ecx
    lea  rsi, [rel pbm_payload_sha]
.bound:
    or   rax, [rsi + rcx]
    add  ecx, 8
    cmp  ecx, 32
    jb   .bound
    test rax, rax
    jz   .out                               ; an unverified build seals nothing it could never restore
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, M1_HDR_LEN
    rep  stosb
    mov  r15, M1_SEAL_RNG
    lea  rdi, [rbx + M1_H_SALT]
    mov  esi, M1_SALT_LEN
    call csprng_generate
    test eax, eax
    jnz  .out
    mov  r15, M1_SEAL_NO_KEY
    lea  rdi, [rbx + M1_H_SALT]
    call m1_derive_key
    test eax, eax
    jnz  .out
    mov  r15, M1_SEAL_RNG
    lea  rdi, [rbx + M1_H_NONCE]
    mov  esi, 12
    call csprng_generate
    test eax, eax
    jnz  .out
    mov  rax, M1_MAGIC
    mov  [rbx], rax
    mov  word [rbx + M1_H_VERSION], M1_VERSION
    mov  word [rbx + M1_H_HDRLEN], M1_HDR_LEN
    mov  [rbx + M1_H_PAYLOAD], r13d
    mov  [rbx + M1_H_GEN], r14
    mov  rax, [rel m1_key_fp]
    mov  [rbx + M1_H_KEYFP], rax
    mov  dword [rbx + M1_H_OWNER], PRIN_OWNER
    mov  rax, [rel m1_enroll]
    mov  [rbx + M1_H_ENROLL], rax
    lea  rdi, [rbx + M1_H_BUILD]
    lea  rsi, [rel pbm_payload_sha]
    mov  ecx, 32
    rep  movsb
    lea  r15, [rel m1_req]
    lea  rax, [rel m1_key]
    mov  [r15 + AEAD_KEY], rax
    lea  rax, [rbx + M1_H_NONCE]
    mov  [r15 + AEAD_NONCE], rax
    mov  [r15 + AEAD_AAD], rbx
    mov  qword [r15 + AEAD_AAD_LEN], M1_HDR_LEN
    mov  [r15 + AEAD_INPUT], r12
    mov  [r15 + AEAD_INPUT_LEN], r13
    lea  rax, [rbx + M1_HDR_LEN]
    mov  [r15 + AEAD_OUTPUT], rax
    lea  rax, [rbx + M1_HDR_LEN + r13]
    mov  [r15 + AEAD_TAG], rax
    mov  rdi, r15
    call aes256_gcm_seal
    mov  r15, M1_SEAL_BAD
    test eax, eax
    jnz  .out
    lea  r15d, [r13d + M1_HDR_LEN + M1_TAG_LEN]
.out:
    call m1_wipe_key
    mov  rax, r15
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; m1_open(RDI = slot image, ESI = bytes read, RDX = plaintext out, ECX = its
;   capacity) -> EAX = plaintext length (>= 1), or -reason: -M1_R_* from
;   m1_ckpt_check (no owner key reads -M1_R_OWNER), -M1_R_OUTPUT, -M1_R_TAG.
;   Nothing is written to the output unless the tag verifies (aes256_gcm_open).
;   The plaintext is the caller's to treat as untrusted (root D2).
m1_open:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    mov  qword [rel m1_key_fp], 0
    mov  qword [rel m1_enroll], 0
    test rbx, rbx
    jz   .check
    cmp  r12d, M1_HDR_LEN
    jb   .check
    lea  rdi, [rbx + M1_H_SALT]
    call m1_derive_key                      ; failure leaves fp/enroll 0 -> OWNER below
.check:
    call m1_expect_fill
    mov  rdi, rbx
    mov  esi, r12d
    lea  rdx, [rel m1_expect]
    call m1_ckpt_check
    test eax, eax
    jnz  .reason
    mov  eax, M1_R_OUTPUT
    test r13, r13
    jz   .reason
    mov  r15d, [rbx + M1_H_PAYLOAD]
    cmp  r15d, r14d
    ja   .reason
    lea  rdi, [rel m1_req]
    lea  rax, [rel m1_key]
    mov  [rdi + AEAD_KEY], rax
    lea  rax, [rbx + M1_H_NONCE]
    mov  [rdi + AEAD_NONCE], rax
    mov  [rdi + AEAD_AAD], rbx
    mov  qword [rdi + AEAD_AAD_LEN], M1_HDR_LEN
    lea  rax, [rbx + M1_HDR_LEN]
    mov  [rdi + AEAD_INPUT], rax
    mov  [rdi + AEAD_INPUT_LEN], r15
    mov  [rdi + AEAD_OUTPUT], r13
    lea  rax, [rbx + M1_HDR_LEN + r15]
    mov  [rdi + AEAD_TAG], rax
    call aes256_gcm_open
    test eax, eax
    jz   .opened
    mov  eax, M1_R_TAG
.reason:
    neg  eax
    mov  r15d, eax
.opened:
    call m1_wipe_key
    mov  eax, r15d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; M1-3 storage: one logical checkpoint per owner under fs/safe_write's protocol
; (admin 09:57) over two PaOS NVRAM variables; plus the non-evictable attempted-
; generation high-water mark (root 10:22 D3). Runtime variable services exist
; only when the Manager mapped the firmware runtime code (pbm_runtime_code_mapped,
; the PaOSClockPrefs gate); every SetVariable goes through the storage-access gate.
; One write pair per SLEEP, never on a timer.
; ---------------------------------------------------------------------------

; m1_var_get(RDI = CHAR16 name, RSI = buffer, EDX = capacity) -> RAX = bytes read
;   (> 0), 0 when the variable is absent, -1 on any other outcome (no runtime
;   services, too small, wrong attributes, an empty variable).
m1_var_get:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov  rbp, rsp
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  rax, -1
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .out
    mov  r14, [rel runtime_services]
    test r14, r14
    jz   .out
    mov  [rel m1_var_size], r13
    mov  dword [rel m1_var_attr], 0
    and  rsp, -16
    sub  rsp, 48
    mov  rcx, rbx
    lea  rdx, [rel m1_vendor_guid]
    lea  r8, [rel m1_var_attr]
    lea  r9, [rel m1_var_size]
    mov  [rsp + 32], r12
    call [r14 + M1_RT_GETVAR]
    mov  rsp, rbp
    test rax, rax
    jz   .got
    mov  rcx, M1_EFI_NOT_FOUND
    cmp  rax, rcx
    mov  rax, -1
    jne  .out
    xor  eax, eax
    jmp  .out
.got:
    mov  rax, -1
    cmp  dword [rel m1_var_attr], M1_VAR_ATTRS
    jne  .out
    mov  rcx, [rel m1_var_size]
    test rcx, rcx
    jz   .out
    cmp  rcx, r13
    ja   .out
    mov  rax, rcx
.out:
    mov  rsp, rbp
    pop  rbp
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; m1_var_set(RDI = CHAR16 name, RSI = data, EDX = size 1..M1_LEDGER_SIZE) -> EAX 0
;   (written and read back byte-exact), M1_VAR_NO_SPACE (QueryVariableInfo or
;   SetVariable reports too little space: nothing written, nothing evicted), or
;   M1_VAR_ERR (no runtime, the storage gate refused, the write or readback failed).
m1_var_set:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov  rbp, rsp
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  eax, M1_VAR_ERR
    test r13d, r13d
    jz   .out
    cmp  r13d, M1_LEDGER_SIZE                ; checkpoint format stays capped at M1_SLOT_CAP
    ja   .out
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .out
    mov  r14, [rel runtime_services]
    test r14, r14
    jz   .out
    cmp  dword [r14 + 8], M1_RT_REV_QVI     ; EFI_TABLE_HEADER.Revision
    jb   .gate                              ; pre-2.0 firmware: SetVariable alone reports space
    and  rsp, -16
    sub  rsp, 32
    mov  ecx, M1_VAR_ATTRS
    lea  rdx, [rel m1_qvi_max]
    lea  r8, [rel m1_qvi_remaining]
    lea  r9, [rel m1_qvi_maxvar]
    call [r14 + M1_RT_QVI]
    mov  rsp, rbp
    test rax, rax
    jnz  .gate                              ; unsupported / failed query: SetVariable decides
    mov  eax, M1_VAR_NO_SPACE
    mov  ecx, r13d
    cmp  [rel m1_qvi_maxvar], rcx
    jb   .out
    add  rcx, M1_SPACE_MARGIN
    cmp  [rel m1_qvi_remaining], rcx
    jb   .out
.gate:
    call storage_access_request_intent      ; storage canon: PaOS-namespace NVRAM = NORMAL
    mov  edx, eax
    lea  rdi, [rel m1_vendor_guid]
    mov  rsi, rbx
    lea  rcx, [rel m1_nvg_tag]
    call storage_access_nvram_require
    mov  rcx, rax
    mov  eax, M1_VAR_ERR
    test rcx, rcx
    jnz  .out
    and  rsp, -16
    sub  rsp, 48
    mov  rcx, rbx
    lea  rdx, [rel m1_vendor_guid]
    mov  r8d, M1_VAR_ATTRS
    mov  r9d, r13d
    mov  [rsp + 32], r12
    call [r14 + M1_RT_SETVAR]
    mov  rsp, rbp
    test rax, rax
    jz   .readback
    mov  rcx, M1_EFI_NO_SPACE
    cmp  rax, rcx
    mov  eax, M1_VAR_NO_SPACE
    je   .out
    mov  eax, M1_VAR_ERR
    jmp  .out
.readback:
    mov  rdi, rbx
    lea  rsi, [rel m1_rb_buf]
    mov  edx, M1_LEDGER_SIZE
    call m1_var_get
    cmp  rax, r13
    mov  eax, M1_VAR_ERR
    jne  .out
    mov  rdi, r12
    lea  rsi, [rel m1_rb_buf]
    mov  edx, r13d
    call memcmp
    test eax, eax
    mov  eax, M1_VAR_ERR
    jnz  .out
    xor  eax, eax
.out:
    mov  rsp, rbp
    pop  rbp
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Persistent POWER07 history: the EXISTING ring, not checkpoint plaintext.
; The 24-byte body is: kind:u8, wake-source:u8 (0 unknown), energy:u8
; (0 unavailable), trigger:u8 (0 none, 1 verb, 2 lid, 3 critical), reason:u32,
; boot-ms:u64 (0 uncalibrated/unknown), wall-time:u64 (0 unavailable).
; No RTC/energy/wake-cause inference. Old/unknown body kinds are retained as bytes.
M1_HIST_SLEEP       equ 1                   ; checkpoint/off transaction attempted
M1_HIST_OFF_ISSUED  equ 2                   ; about to call normal quiesced shutdown
M1_HIST_RETURNED    equ 3                   ; that call returned; no physical off claimed
M1_HIST_RESTORE     equ 4                   ; about to ask secured restore candidate
M1_HIST_INSTALLED   equ 5                   ; RAM manifest installed, not physical wake proof
M1_HIST_FRESH       equ 6
M1_HIST_REFUSED     equ 7                   ; owner-authorized verb busy
M1_HIST_SUPERSEDED  equ 8
M1_HIST_DEFERRED    equ 9                   ; no owner key, once per boot
M1_HIST_PROBLEM     equ 10                  ; checkpoint skipped, reason is PWR_M1_S_*
M1_HIST_READ        equ -3
M1_HIST_CORRUPT     equ -4
M1_HIST_EXHAUSTED   equ -5
M1_HIST_BAD_EVENT   equ -6

; m1_history_append(EDI=kind, ESI=reason, EDX=trigger, RCX=boot ms) -> EAX
; 0 verified durable append, else a latched failure (above or M1_VAR_*).
; Read anew on each event. Only EFI_NOT_FOUND creates a genesis. Any read,
; verify, capacity, custody, write or readback failure disables further history
; writes this boot: a returned firmware error may still have written bytes.
; One SetVariable at most; no retry, erase, repair, or eviction of other vars.
; This diagnostic history is best effort under the existing root-amended M1
; policy: failure never bypasses checkpoint crypto/mark/auth or safe off.
m1_history_append:
    cmp  byte [rel m1_history_blocked], 0
    jne  .latched
    push rbx
    mov  eax, M1_HIST_BAD_EVENT
    cmp  edi, M1_HIST_SLEEP
    jb   .failed
    cmp  edi, M1_HIST_PROBLEM
    ja   .failed
    cmp  edx, 3
    ja   .failed
    mov  qword [rel m1_history_body], 0
    mov  [rel m1_history_body], dil
    mov  [rel m1_history_body + 3], dl
    mov  [rel m1_history_body + 4], esi
    mov  [rel m1_history_body + 8], rcx
    mov  qword [rel m1_history_body + 16], 0
    lea  rdi, [rel m1_name_ledger]
    lea  rsi, [rel m1_history_buf]
    mov  edx, M1_LEDGER_SIZE
    call m1_var_get
    test rax, rax
    jz   .absent
    mov  ebx, M1_HIST_READ
    js   .bad
    mov  ebx, M1_HIST_CORRUPT
    cmp  rax, M1_LEDGER_SIZE
    jne  .bad
    lea  rdi, [rel m1_history_buf]
    call m1_ledger_verify
    test eax, eax
    jnz  .bad
    jmp  .append
.absent:
    lea  rdi, [rel m1_history_buf]
    call m1_ledger_init
.append:
    mov  ebx, M1_HIST_EXHAUSTED
    cmp  qword [rel m1_history_buf + M1_L_NEXT], -1
    je   .bad
    lea  rdi, [rel m1_history_buf]
    lea  rsi, [rel m1_history_body]
    call m1_ledger_append
    mov  ebx, M1_HIST_CORRUPT
    test eax, eax
    jnz  .bad
    lea  rdi, [rel m1_name_ledger]
    lea  rsi, [rel m1_history_buf]
    mov  edx, M1_LEDGER_SIZE
    call m1_var_set
    test eax, eax
    jnz  .failed
    mov  dword [rel m1_history_status], 0
    pop  rbx
    ret
.bad:
    mov  eax, ebx
.failed:
    mov  [rel m1_history_status], eax
    mov  byte [rel m1_history_blocked], 1
    pop  rbx
    ret
.latched:
    mov  eax, [rel m1_history_status]
    ret

; m1_commit(RDI = sealed image, ESI = its length) -> EAX 0, M1_VAR_NO_SPACE or
;   M1_VAR_ERR. TMP is written, read back and OPENED (the owner key is available
;   at seal time) before PRIMARY is touched; PRIMARY is then written, read back
;   and opened. PRIMARY stays last-good until TMP verifies; a torn PRIMARY leaves a
;   disagreeing pair, which restore treats as doubt (fresh boot).
m1_commit:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    lea  rdi, [rel m1_name_tmp]
    call .write_verify
    test eax, eax
    jnz  .out
    lea  rdi, [rel m1_name_primary]
    call .write_verify
.out:
    pop  r12
    pop  rbx
    ret
.write_verify:                              ; RDI = name -> EAX 0 / error
    mov  rsi, rbx
    mov  edx, r12d
    call m1_var_set                         ; m1_rb_buf = the exact readback
    test eax, eax
    jnz  .wv_out
    lea  rdi, [rel m1_rb_buf]
    mov  esi, r12d
    lea  rdx, [rel m1_plain_chk]
    mov  ecx, M1_PLAIN_CAP
    call m1_open
    test eax, eax
    mov  eax, M1_VAR_ERR
    jle  .wv_wipe
    xor  eax, eax
.wv_wipe:
    push rax
    lea  rdi, [rel m1_plain_chk]
    xor  esi, esi
    mov  edx, M1_PLAIN_CAP
    call memset
    pop  rax
.wv_out:
    ret

; m1_push_record_present -> EAX 0 only when the PaOSPush1 variable is ABSENT; 1 when
;   it is present or cannot be read (fail-closed). srcreview M1-3 R1 / root C2(a):
;   the record (not the runtime keep_push_modes byte) is what escrows the owner key
;   under an NVRAM-recoverable key, so its mere presence refuses the checkpoint.
m1_push_record_present:
    lea  rdi, [rel m1_name_push]
    lea  rsi, [rel m1_rb_buf]
    mov  edx, M1_SLOT_CAP
    call m1_var_get
    test rax, rax
    setnz al
    movzx eax, al                           ; > 0 present, -1 unknown: both refuse
    ret

; m1_mark_get -> RAX = the attempted-generation high-water mark (0 when absent),
;   or -1 when it cannot be read (doubt).
m1_mark_get:
    lea  rdi, [rel m1_name_mark]
    lea  rsi, [rel m1_mark_buf]
    mov  edx, 8
    call m1_var_get
    test rax, rax
    jz   .zero
    cmp  rax, 8
    jne  .bad
    mov  rax, [rel m1_mark_buf]
    cmp  rax, -1
    je   .bad
    ret
.zero:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; m1_next_generation -> RAX = 1 + the highest generation seen in TMP, PRIMARY
;   (plain header fields; no key needed) or the high-water mark; -1 if exhausted.
m1_next_generation:
    push rbx
    xor  ebx, ebx
    call m1_mark_get
    cmp  rax, -1
    je   .tmp
    mov  rbx, rax
.tmp:
    lea  rdi, [rel m1_name_tmp]
    call .gen_of
    lea  rdi, [rel m1_name_primary]
    call .gen_of
    mov  rax, rbx
    cmp  rax, -1
    je   .out
    inc  rax
.out:
    pop  rbx
    ret
.gen_of:                                    ; RDI = name; RBX = max(RBX, its generation)
    lea  rsi, [rel m1_rb_buf]
    mov  edx, M1_SLOT_CAP
    call m1_var_get
    cmp  rax, M1_H_GEN + 8
    jl   .g_out
    mov  rax, [rel m1_rb_buf + M1_H_GEN]
    cmp  rax, rbx
    jbe  .g_out
    mov  rbx, rax
.g_out:
    ret

; m1_restore_candidate(RDI = plaintext out, ESI = capacity >= M1_PLAIN_CAP) -> EAX =
;   plaintext length (> 0): restore it; or EAX = 0 with EDX = M1_C_* (boot fresh).
;   Called once after the owner signs in (the key exists only then). Both
;   variables must open and be byte-identical (m1_pair_plan); the generation must
;   be above the high-water mark, which is raised to it BEFORE anything is applied
;   (root D3: a restore that crashes is never retried). The plaintext is untrusted
;   (root D2): the caller validates it with its own bounded parser.
m1_restore_candidate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  edx, M1_C_NO_RUNTIME
    xor  eax, eax
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .fresh
    cmp  r13d, M1_PLAIN_CAP
    jb   .fresh
    lea  rdi, [rel m1_name_tmp]
    lea  rsi, [rel m1_tmp_buf]
    mov  edx, M1_SLOT_CAP
    call m1_var_get
    mov  r14, rax                           ; TMP length (<= 0: none)
    lea  rdi, [rel m1_name_primary]
    lea  rsi, [rel m1_rb_buf]
    mov  edx, M1_SLOT_CAP
    call m1_var_get
    mov  r15, rax                           ; PRIMARY length
    mov  dword [rel m1_pair + M1_S_STATUS], 1
    mov  qword [rel m1_pair + M1_S_GEN], 0
    mov  dword [rel m1_pair + M1_S_SIZE + M1_S_STATUS], 1
    mov  qword [rel m1_pair + M1_S_SIZE + M1_S_GEN], 0
    test r14, r14
    jle  .primary
    lea  rdi, [rel m1_tmp_buf]
    mov  esi, r14d
    lea  rdx, [rel m1_plain_chk]
    mov  ecx, M1_PLAIN_CAP
    call m1_open
    test eax, eax
    jle  .primary
    mov  dword [rel m1_pair + M1_S_STATUS], 0
    mov  rax, [rel m1_tmp_buf + M1_H_GEN]
    mov  [rel m1_pair + M1_S_GEN], rax
.primary:
    test r15, r15
    jle  .plan
    lea  rdi, [rel m1_rb_buf]
    mov  esi, r15d
    mov  rdx, r12
    mov  ecx, r13d
    call m1_open
    test eax, eax
    jle  .plan
    mov  ebx, eax                           ; plaintext length
    mov  dword [rel m1_pair + M1_S_SIZE + M1_S_STATUS], 0
    mov  rax, [rel m1_rb_buf + M1_H_GEN]
    mov  [rel m1_pair + M1_S_SIZE + M1_S_GEN], rax
.plan:
    xor  esi, esi                           ; byte-identical?
    cmp  r14, r15
    jne  .call_plan
    test r14, r14
    jle  .call_plan
    lea  rdi, [rel m1_tmp_buf]
    lea  rsi, [rel m1_rb_buf]
    mov  edx, r14d
    call memcmp
    xor  esi, esi
    test eax, eax
    jnz  .call_plan
    mov  esi, 1
.call_plan:
    lea  rdi, [rel m1_pair]
    call m1_pair_plan
    test eax, eax
    jz   .doubt_reason                      ; EDX = M1_P_NONE / M1_P_DISAGREE
    call m1_mark_get                        ; D3
    mov  edx, M1_C_MARK_FAILED
    cmp  rax, -1
    je   .fresh_wipe
    mov  rcx, [rel m1_pair + M1_S_SIZE + M1_S_GEN]
    mov  edx, M1_C_ATTEMPTED
    cmp  rcx, rax
    jbe  .fresh_wipe
    mov  [rel m1_mark_buf], rcx             ; raise the mark BEFORE anything is applied
    lea  rdi, [rel m1_name_mark]
    lea  rsi, [rel m1_mark_buf]
    mov  edx, 8
    call m1_var_set
    mov  edx, M1_C_MARK_FAILED
    test eax, eax
    jnz  .fresh_wipe
    mov  eax, ebx
    xor  edx, edx
    jmp  .out
.doubt_reason:
    mov  ecx, edx
    mov  edx, M1_C_DOUBT
    cmp  ecx, M1_P_NONE
    jne  .fresh_wipe
    test r14, r14                           ; nothing valid: absent, or present but unopenable
    jg   .fresh_wipe
    test r15, r15
    jg   .fresh_wipe
    mov  edx, M1_C_NONE
.fresh_wipe:
    push rdx
    mov  rdi, r12
    xor  esi, esi
    mov  edx, r13d
    call memset
    pop  rdx
.fresh:
    xor  eax, eax
.out:
    push rax
    push rdx
    lea  rdi, [rel m1_plain_chk]
    xor  esi, esi
    mov  edx, M1_PLAIN_CAP
    call memset
    pop  rdx
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

align 8, db 0                           ; EFI_GUID 8-aligned; the CHAR16 names after it even
; 5a6ec129-2554-494c-99bd-b03960df4704: the data/config PaOS vendor GUID (nvg_paos_guids #3).
m1_vendor_guid:
    dd 0x5a6ec129
    dw 0x2554, 0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
m1_name_tmp:
    dw 'P','a','O','S','C','h','e','c','k','p','o','i','n','t','T','m','p',0
m1_name_primary:
    dw 'P','a','O','S','C','h','e','c','k','p','o','i','n','t','P','r','i','m','a','r','y',0
m1_name_mark:
    dw 'P','a','O','S','C','h','e','c','k','p','o','i','n','t','M','a','r','k',0
m1_name_ledger:
    dw 'P','a','O','S','W','a','k','e','L','e','d','g','e','r',0
m1_name_push:                           ; data/config_store's PUSH policy record (same GUID)
    dw 'P','a','O','S','P','u','s','h','1',0
m1_nvg_tag: db "m1_checkpoint", 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_m1_checkpoint_0 0
align 8
m1_key:     times 32 db 0                   ; derived per call, wiped on every exit
m1_auth:    times 32 db 0
m1_key_fp:  dq 0
m1_enroll:  dq 0
m1_expect:  times M1_X_SIZE db 0
m1_hash_out: times 32 db 0
m1_req:     times AEAD_REQ_SZ db 0
m1_hash_in: times M1_HASH_IN_LEN db 0
m1_fp_tag:  db "paos.m1.fp"
.len equ $ - m1_fp_tag
m1_enroll_tag: db "paos.m1.enroll"
.len equ $ - m1_enroll_tag
m1_var_size: dq 0
m1_var_attr: dd 0
align 8
m1_qvi_max:       dq 0
m1_qvi_remaining: dq 0
m1_qvi_maxvar:    dq 0
m1_mark_buf:      dq 0
m1_pair:          times 2 * M1_S_SIZE db 0
m1_history_blocked: db 0
align 4
m1_history_status: dd 0                    ; retained first failure for diagnostics
align 8
m1_history_body: times 24 db 0
m1_history_buf:  times M1_LEDGER_SIZE db 0
m1_rb_buf:        times M1_LEDGER_SIZE db 0
m1_tmp_buf:       times M1_SLOT_CAP db 0
m1_plain_chk:     times M1_PLAIN_CAP db 0
m1_info:    db "paos.m1.checkpoint.v2"
            dq PRIN_OWNER
.len equ $ - m1_info
%endmacro
WDATA_DEFER WDATA_svc_m1_checkpoint_0
