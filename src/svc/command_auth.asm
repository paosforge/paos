;; MODULE svc/command_auth
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS net_audit_verb_name, net_audit_reason_name, net_audit_refusal_meta, command_auth_ssh_active, command_auth_owner_request, command_auth_owner_envelope, command_auth_injection_gate, command_session_sync_active, command_auth_parse_hex64, command_auth_init, command_publicity_udp_init, command_auth_legacy_read_kat_cap, command_auth_remote_begin, command_auth_remote_end, command_auth_ticket_owner, command_auth_unwrap_line, command_auth_gate, command_auth_consume_public, command_auth_required_cap, command_auth_register_intercept, command_auth_route_gate, command_auth_refuse, command_auth_note_aihook_proof, command_auth_note_serial_proof, command_auth_stage_refusal, command_auth_stage_ai_probe, command_auth_out_buf, command_auth_out_ready, command_auth_refusal_ready, command_auth_ticket_size, command_auth_message, command_auth_last_sequence, pbm_sb_secureboot, command_session_allow_op, command_session_sync_op, command_dispatch, command_auth_node_id_ensure, command_auth_node_hex
;; IMPORTS sec/platform_key_health, svc/lab_return, boot/smbios, boot/rescue0_snp, core/lib/mem, core/lib/sha256, core/lib/str, core/lib/fmt, core/time, core/lock, core/capability, boot/header, boot/paging, boot/boot_v2_handoff, bootmgr/rsa2048_verify, data/crypto_envelope, sec/job_receipt, sec/node_identity, sec/principal, svc/command, svc/command_udp, svc/command_guestcpu, svc/command_web, svc/command_fs, svc/command_backup, svc/push_auth, web/structured_kat, svc/command_privacy, security/sensitive_classifier, fs/storage_access, boot/nvram_access, sec/session, svc/command_card, sec/owner_store, sec/replay_floor
;; CAPS CAP_BLOCK_WRITE
;; OWNER saga:secure_boot
;; LOCK: command_auth_lock PROTECTS command_auth_last_sequence, command_auth_accept_count, command_auth_deny_count, command_auth_replay_state, command_auth_replay_record, command_auth_reserved_through, command_auth_resv_state, command_auth_resv_error, command_auth_seal
; ============================================================================
; One remote-mutation authorization boundary (Task 2020).
;
; Wire envelope (ASCII fields, one space between fields), AUTH2 (security scan
; F3, gauntlet_v2/docs/DESIGN_AUTH2_NODE_BINDING.md, PETER 2026-10-01 18:59):
;   AUTH2 <node_id:32hex> <cap:16hex> <seq:16hex> <issued_unix:8hex>
;         <expires_unix:8hex> <rsa2048-signature:342base64url-no-padding>
;         <command and arguments>
;
; The RSA signature is over this canonical binary message:
;   "PAOS-CMD-AUTH2\0\0" || u8(2) || node_id[16] || le64(cap) || le64(seq) ||
;   le64(issued) || le64(expires) || command_bytes_without_NUL
; and is verified by the same enrolled owner RSA-2048 key used by Boot-v2.
; node_id is THIS node's identity (command_auth_node_id_ensure). The wire copy is
; compared with it before any RSA work (cheap refusal, reason=wrong_node) and the
; signature then binds it, so an envelope signed for node A never runs on node B.
; The retired v1 envelope ("AUTH1 ...", no node identity) is refused before any
; field parse or RSA work with reason=auth1_retired; there is no fallback flag.
; The private key is never present here.  A valid signature is not sufficient:
; the requested capability must be EXACT, the wall-clock interval must be live
; and at most five minutes, and seq must be durably committed above the prior
; accepted sequence before the mutation is dispatched.
;
; Registry verbs are classified from the live VERB_DESTR/VERB_CAP metadata.
; Task2504: PUSHAUTH uses the registered public-query / gated-action shape.
; Pre-registry intercept owners declare into the table below.  Anything absent
; from both tables is refused before any intercept runs, which makes a newly
; added/unknown direct interceptor fail closed by construction.
; ============================================================================

AUTH_T_CAP       equ 0
AUTH_T_SEQ       equ 8
AUTH_T_ISSUED    equ 16
AUTH_T_EXPIRES   equ 24
AUTH_T_COMMAND   equ 32
AUTH_T_STATE     equ 40
AUTH_T_PRINCIPAL equ 48
AUTH_T_SIZE      equ 56
command_auth_ticket_size equ AUTH_T_SIZE

; Shared identity ABI must exist before command_aihook allocates its bind
; context; sec/principal consumes the same guarded constants later.
%ifndef AUTH_CTX_SIZE
AUTH_BIND_OWNER_RSA equ 1
AUTH_BIND_PASSWORD equ 2
AUTH_BIND_SYSTEM_KEY equ 3
AUTH_BIND_ED25519 equ 4
AUTH_CTX_CREDENTIAL equ 0
AUTH_CTX_CRED_LEN equ 8
AUTH_CTX_SEQUENCE equ 16
AUTH_CTX_ISSUED equ 24
AUTH_CTX_EXPIRES equ 32
AUTH_CTX_ASSERTED_PID equ 40
AUTH_CTX_TEMP_CAP equ 48
AUTH_CTX_TEMP_EXPIRY equ 56
AUTH_CTX_AUDIT_REF equ 64
AUTH_CTX_SIZE equ 72
%endif

AUTH_TS_UNSIGNED equ 0
AUTH_TS_VALID    equ 1
AUTH_TS_MALFORMED equ 2
AUTH_TS_WRONG_KEY equ 3
AUTH_TS_EXPIRED  equ 4
AUTH_TS_CONSUMED equ 5
; Task2142/2143: a request-scoped ticket minted by the SSH projection for ONE
; exec on a connection whose RFC 4252 publickey signature bound PRINCIPAL.
; CAP carries the enrolled key's restriction mask (not an exact AUTH1 scope);
; there is no per-command signature, sequence, or expiry: the SSH transport's
; per-session AEAD already makes each exec unique to the live connection.
AUTH_TS_SSH      equ 6
AUTH_TS_RETIRED  equ 7                 ; AUTH2 cutover: a v1 ("AUTH1 ...") envelope, refused unparsed
AUTH_TS_WRONG_NODE equ 8               ; AUTH2 node_id missing, malformed or not this node's
; GA0-K (sec/keyprov): the request-scoped ticket of a line typed by a remote
; injection. PRINCIPAL = the injecting principal, CAP = its mask (an SSH key's,
; else -1), SEQ = the injecting request's CMD_SOURCE_*. Authorized like an
; SSH-bound principal; never owner intent, never consumable.
AUTH_TS_INJECTED equ 9
AUTH_TS_GUEST    equ 10                ; native guest_request ticket; no wire credentials

AUTHR_UNSIGNED   equ 1
AUTHR_MALFORMED  equ 2
AUTHR_WRONG_KEY  equ 3
AUTHR_EXPIRED    equ 4
AUTHR_WRONG_CAP  equ 5
AUTHR_REPLAY     equ 6
AUTHR_DURABLE    equ 7
AUTHR_UNKNOWN    equ 8
AUTHR_PRINCIPAL  equ 9
AUTHR_DESKTOP_LOCKED equ 10            ; remote caller asked for local-desktop authority while locked
AUTHR_AUTH1_RETIRED equ 11             ; v1 envelope after the AUTH2 cutover (no node binding)
AUTHR_WRONG_NODE equ 12                ; AUTH2 envelope not bound to this node's node_id
AUTHR_CARD_REQUIRED equ 13             ; RCQ-40 J6: a non-OWNER ticket asked for a verb only an owner action card runs

; Owner scopes which had no pre-existing PMCAP bit.  Registry verbs that already
; declare a nonzero cap keep that exact value; destructive cap=0 verbs receive
; CMD_AUTH_CAP_MUTATE automatically.
CMD_AUTH_CAP_MUTATE  equ 0x0001000000000000
CMD_AUTH_CAP_HOTPATCH equ 0x0002000000000000
CMD_AUTH_CAP_PERSIST  equ 0x0004000000000000
CMD_AUTH_CAP_BOOT     equ 0x0008000000000000
CMD_AUTH_CAP_EXTENSION equ 0x0010000000000000
; GUI_FOUNDATION slot 20: clipboard content is an exfiltration surface. Keep
; this bit separate from mutation so CLIPGET requests only read authority.
CMD_AUTH_CAP_CLIPBOARD_READ equ (1 << 20)
; SELFTEST FULL is owner-signed boot-maintenance work and can exercise
; deliberate fault/watchdog negatives; it is never a public query.
CMD_AUTH_CAP_SELFTEST equ CMD_AUTH_CAP_BOOT
; Reserved authority-floor bits.  No verb requires these in rung 2500; their
; presence now makes later sovereign/recovery policy a table-data change.
CMD_AUTH_CAP_SOVEREIGN_CONTROL equ 0x0020000000000000
CMD_AUTH_CAP_RECOVERY_REMOVAL  equ 0x0040000000000000

AUTH_MAX_TTL_S   equ 300
AUTH_MSG_MAX     equ 1536
; Canonical AUTH2 message layout (command_auth_build_message).
AUTH2_FORMAT_VERSION equ 2
AUTH_NODE_ID_LEN equ 16
AUTH_MSG_VER_OFF equ 16                ; after the 16-byte domain tag
AUTH_MSG_NODE_OFF equ 17
AUTH_MSG_CAP_OFF equ (AUTH_MSG_NODE_OFF + AUTH_NODE_ID_LEN)
AUTH_MSG_SEQ_OFF equ (AUTH_MSG_CAP_OFF + 8)
AUTH_MSG_ISSUED_OFF equ (AUTH_MSG_SEQ_OFF + 8)
AUTH_MSG_EXPIRES_OFF equ (AUTH_MSG_ISSUED_OFF + 8)
AUTH_MSG_HDR     equ (AUTH_MSG_EXPIRES_OFF + 8)
AUTH_CMD_MAX     equ (AUTH_MSG_MAX - AUTH_MSG_HDR)
%if AUTH_MSG_HDR != 65
    %error "AUTH2 canonical header drift"
%endif
AUTH_OUT_MAX     equ 1280              ; AUTHSTAT + masked principal roles stay under UDP clamp
AUTH_REFLECT_TOKEN_MAX equ 64

AUTH_INT_NAME    equ 0
AUTH_INT_CAP     equ 8
AUTH_INT_DESTR   equ 16
AUTH_INT_MATCH   equ 24
AUTH_INT_LEN     equ 32
AUTH_INT_SIZE    equ 40
AUTH_INT_MAX     equ 24                ; EPHFORM START/DATA/COMMIT/INLINE/CLOSE; RCQ-27 SHUTDOWN took the 20th
AUTH_MATCH_EXACT equ 0
AUTH_MATCH_PREFIX equ 1

; The Makefile owns the only posture selector. Direct assembler invocations
; retain the shipped, fail-closed posture.
%ifndef PAOS_PUBLICITY_LAB_PROFILE
    %define PAOS_PUBLICITY_LAB_PROFILE 0
%endif

; Independent, CRC-bound replay floor.  The user KV store has one shared
; durable record and therefore cannot also own command authorization state:
; either subsystem could otherwise displace the other's record.  This fixed
; EFI variable follows boot_v2_init_checkpoint_persist's proven contract:
; nonvolatile attributes, a fixed name/GUID/size, CRC, and byte-exact readback.
AUTH_REPLAY_MAGIC       equ 0x52414350 ; "PCAR" little-endian
AUTH_REPLAY_VERSION     equ 1
AUTH_REPLAY_SIZE        equ 64
AUTH_REPLAY_MAGIC_OFF   equ 0
AUTH_REPLAY_VERSION_OFF equ 4
AUTH_REPLAY_SIZE_OFF    equ 6
AUTH_REPLAY_KEY_ID_OFF  equ 8
AUTH_REPLAY_SEQ_OFF     equ 40
AUTH_REPLAY_TIME_OFF    equ 48
AUTH_REPLAY_FLAGS_OFF   equ 56
AUTH_REPLAY_CRC32_OFF   equ 60
AUTH_REPLAY_EMPTY       equ 0
AUTH_REPLAY_VALID       equ 1
AUTH_REPLAY_POISONED    equ 2
AUTH_EFI_ATTRS          equ 0x00000007
; Reservation before use (SEC-signed-read-nvram-persist; design 07b0c885, root
; 13:38 ruling).  The record's sequence field holds R, the highest sequence a
; verified write has reserved; H (command_auth_last_sequence) is the highest
; admitted this boot.  H < q <= R is admitted in RAM; q > R first reserves
; min(UINT64_MAX, q+SPAN-1) with exact readback.  Boot sets H = R = record.
AUTH_RESV_SPAN          equ 256
AUTH_RESV_NONE          equ 0          ; R is the boot floor; no write yet
AUTH_RESV_HELD          equ 1          ; R came from a verified write this boot
AUTH_RESV_FAILED        equ 2          ; no reservation beyond R until reboot
AUTH_RESV_E_NONE        equ 0
AUTH_RESV_E_RECORD      equ 1          ; boot record not validated (POISONED)
AUTH_RESV_E_RUNTIME     equ 2          ; runtime services not callable
AUTH_RESV_E_GATE        equ 3          ; storage gate refused the write
AUTH_RESV_E_SET         equ 4          ; SetVariable returned an error
AUTH_RESV_E_GET         equ 5          ; readback GetVariable returned an error
AUTH_RESV_E_COMPARE     equ 6          ; readback attrs/size/bytes differ
AUTH_RESV_E_LOST        equ 7          ; sec/replay_floor: seeded estate lost its floor (until owner reseed)
AUTH_RESV_E_FLOOR       equ 8          ; sec/replay_floor: F' not committed pre-EBS this boot
; SEC-replay-record-mac S1 (sec/replay_floor): the pre-EBS step reads the RT
; record itself and commits F' = B + 2^24 to the NV|BS PaOSReplayFloor.  HELD:
; H = B, R = F' and the boot is SEALED (command_auth_seal = F': q > R refused,
; never extended at runtime).  MIRROR_FAILED: H = R = B, the runtime
; reservation below still keeps the RT record ahead for older images, sealed at
; F'.  LOST / FAILED: no admission this boot.
AUTH_EFI_NOT_FOUND      equ 0x800000000000000E

%if (AUTH_REPLAY_CRC32_OFF + 4) != AUTH_REPLAY_SIZE
    %error "command auth replay record size drift"
%endif

command_auth_lock_acquire:
    lea  rdi, [rel command_auth_lock]
    jmp  spin_acquire

command_auth_lock_release:
    lea  rdi, [rel command_auth_lock]
    jmp  spin_release

; Load the replay floor once at boot.  A genuinely absent variable permits the
; first owner command.  An unreadable, malformed, wrong-key, or torn variable
; is POISONED and remains fail-closed; it is never silently overwritten with a
; lower sequence.  A valid record sets H = R = its sequence: every number up
; to the last reservation counts as used.  A POISONED record earns no
; reservation, so the reservation path is FAILED for this boot.
command_auth_replay_load:
    push rbx
    push r12
    mov  byte [rel command_auth_replay_state], AUTH_REPLAY_POISONED
    mov  byte [rel command_auth_durable_ready], 0
    mov  qword [rel command_auth_last_sequence], 0
    mov  qword [rel command_auth_reserved_through], 0
    mov  byte [rel command_auth_resv_state], AUTH_RESV_NONE
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_NONE
    mov  qword [rel command_auth_seal], -1
    ; Direct/non-mutable boots deliberately leave firmware runtime code NX.
    ; Never branch into that code after exit_boot_and_page: only the mutable
    ; Manager handoff earns pbm_runtime_code_mapped.  Remaining POISONED is the
    ; fail-closed result, not permission to fall back to a volatile sequence.
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .out
    ; The pre-EBS floor already read the RT record and committed F' (or not).
    ; Only a boot where it never ran (RPF_NONE) reads the RT record here.
    movzx eax, byte [rel rpf_state]
    cmp  eax, RPF_HELD
    je   .floor_held
    cmp  eax, RPF_MIRROR_FAILED
    je   .floor_mirror
    cmp  eax, RPF_LOST
    je   .floor_lost
    cmp  eax, RPF_FAILED
    je   .floor_failed
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .out
    mov  qword [rel command_auth_replay_size], AUTH_REPLAY_SIZE
    mov  dword [rel command_auth_replay_attrs], 0
    lea  rcx, [rel command_auth_replay_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel command_auth_replay_attrs]
    lea  r9, [rel command_auth_replay_size]
    sub  rsp, 40
    lea  rbx, [rel command_auth_replay_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 40
    test rax, rax
    jz   .validate
    mov  rdx, AUTH_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .out
    mov  byte [rel command_auth_replay_state], AUTH_REPLAY_EMPTY
    xor  eax, eax
    jmp  .out
.validate:
    cmp  dword [rel command_auth_replay_attrs], AUTH_EFI_ATTRS
    jne  .out
    cmp  qword [rel command_auth_replay_size], AUTH_REPLAY_SIZE
    jne  .out
    cmp  dword [rel command_auth_replay_record + AUTH_REPLAY_MAGIC_OFF], AUTH_REPLAY_MAGIC
    jne  .out
    cmp  word [rel command_auth_replay_record + AUTH_REPLAY_VERSION_OFF], AUTH_REPLAY_VERSION
    jne  .out
    cmp  word [rel command_auth_replay_record + AUTH_REPLAY_SIZE_OFF], AUTH_REPLAY_SIZE
    jne  .out
    lea  rbx, [rel command_auth_owner_key_id]
    mov  rax, [rbx]
    cmp  [rel command_auth_replay_record + AUTH_REPLAY_KEY_ID_OFF], rax
    jne  .out
    mov  rax, [rbx + 8]
    cmp  [rel command_auth_replay_record + AUTH_REPLAY_KEY_ID_OFF + 8], rax
    jne  .out
    mov  rax, [rbx + 16]
    cmp  [rel command_auth_replay_record + AUTH_REPLAY_KEY_ID_OFF + 16], rax
    jne  .out
    mov  rax, [rbx + 24]
    cmp  [rel command_auth_replay_record + AUTH_REPLAY_KEY_ID_OFF + 24], rax
    jne  .out
    mov  ebx, [rel command_auth_replay_record + AUTH_REPLAY_CRC32_OFF]
    lea  rdi, [rel command_auth_replay_record]
    mov  esi, AUTH_REPLAY_CRC32_OFF
    call pbm_crc32
    cmp  eax, ebx
    jne  .out
    mov  rax, [rel command_auth_replay_record + AUTH_REPLAY_SEQ_OFF]
    test rax, rax
    jz   .out
    mov  [rel command_auth_last_sequence], rax
    mov  [rel command_auth_reserved_through], rax
    mov  byte [rel command_auth_replay_state], AUTH_REPLAY_VALID
    mov  byte [rel command_auth_durable_ready], 1
    xor  eax, eax
.out:
    cmp  byte [rel command_auth_replay_state], AUTH_REPLAY_POISONED
    jne  .ret
    mov  byte [rel command_auth_resv_state], AUTH_RESV_FAILED
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_RECORD
    jmp  .ret
.floor_held:
    mov  rax, [rel rpf_b]
    mov  [rel command_auth_last_sequence], rax
    mov  rax, [rel rpf_f]
    mov  [rel command_auth_reserved_through], rax
    mov  [rel command_auth_seal], rax
    mov  byte [rel command_auth_resv_state], AUTH_RESV_HELD
    jmp  .floor_valid
.floor_mirror:
    mov  rax, [rel rpf_b]
    mov  [rel command_auth_last_sequence], rax
    mov  [rel command_auth_reserved_through], rax
    mov  rax, [rel rpf_f]
    mov  [rel command_auth_seal], rax
.floor_valid:
    mov  byte [rel command_auth_replay_state], AUTH_REPLAY_VALID
    mov  byte [rel command_auth_durable_ready], 1
    xor  eax, eax
    jmp  .ret
.floor_lost:
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_LOST
    jmp  .floor_refused
.floor_failed:
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_FLOOR
.floor_refused:
    ; H = R = B keeps sequence_next_min honest; FAILED admits nothing above R.
    mov  rax, [rel rpf_b]
    mov  [rel command_auth_last_sequence], rax
    mov  [rel command_auth_reserved_through], rax
    mov  byte [rel command_auth_resv_state], AUTH_RESV_FAILED
.ret:
    pop  r12
    pop  rbx
    ret

; Persist RDI=reservation bound U while command_auth_lock is held.  The bound
; is durable before any command it covers runs, so an acknowledged command can
; execute at most once even if the reply is lost.  EAX=0 only after exact
; firmware readback; a poisoned prior record is never replaced.  A failure is
; the reservation path's own state (FAILED + last error), not POISONED: the
; earlier verified R stays a valid budget (root 13:38 (2)).
command_auth_replay_persist:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_RUNTIME
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .failed
    cmp  byte [rel command_auth_replay_state], AUTH_REPLAY_POISONED
    je   .failed
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .failed
    lea  rdi, [rel command_auth_replay_record]
    xor  esi, esi
    mov  edx, AUTH_REPLAY_SIZE
    call memset
    mov  dword [rel command_auth_replay_record + AUTH_REPLAY_MAGIC_OFF], AUTH_REPLAY_MAGIC
    mov  word [rel command_auth_replay_record + AUTH_REPLAY_VERSION_OFF], AUTH_REPLAY_VERSION
    mov  word [rel command_auth_replay_record + AUTH_REPLAY_SIZE_OFF], AUTH_REPLAY_SIZE
    lea  rdi, [rel command_auth_replay_record + AUTH_REPLAY_KEY_ID_OFF]
    lea  rsi, [rel command_auth_owner_key_id]
    mov  edx, 32
    call memcpy
    mov  [rel command_auth_replay_record + AUTH_REPLAY_SEQ_OFF], r13
    call time_wall_now_s
    mov  [rel command_auth_replay_record + AUTH_REPLAY_TIME_OFF], rax
    mov  dword [rel command_auth_replay_record + AUTH_REPLAY_FLAGS_OFF], 1
    lea  rdi, [rel command_auth_replay_record]
    mov  esi, AUTH_REPLAY_CRC32_OFF
    call pbm_crc32
    mov  [rel command_auth_replay_record + AUTH_REPLAY_CRC32_OFF], eax

    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL.
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_GATE
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel command_auth_replay_guid]
    lea  rsi, [rel command_auth_replay_name]
    lea  rcx, [rel str_auth_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .failed
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_SET
    lea  rcx, [rel command_auth_replay_name]
    lea  rdx, [rel command_auth_replay_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, AUTH_REPLAY_SIZE
    ; Three saved registers leave RSP 16-byte aligned here.  Reserve the
    ; 32-byte Microsoft-x64 shadow area, the fifth argument slot, and eight
    ; bytes of padding so the UEFI firmware call itself stays 16-byte aligned.
    sub  rsp, 48
    lea  rbx, [rel command_auth_replay_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    add  rsp, 48
    test rax, rax
    jnz  .failed

    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_GET
    mov  qword [rel command_auth_verify_size], AUTH_REPLAY_SIZE
    mov  dword [rel command_auth_verify_attrs], 0
    lea  rcx, [rel command_auth_replay_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel command_auth_verify_attrs]
    lea  r9, [rel command_auth_verify_size]
    sub  rsp, 48
    lea  rbx, [rel command_auth_replay_verify]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; exact readback
    add  rsp, 48
    test rax, rax
    jnz  .failed
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_COMPARE
    cmp  dword [rel command_auth_verify_attrs], AUTH_EFI_ATTRS
    jne  .failed
    cmp  qword [rel command_auth_verify_size], AUTH_REPLAY_SIZE
    jne  .failed
    lea  rbx, [rel command_auth_replay_record]
    lea  r12, [rel command_auth_replay_verify]
    mov  ecx, AUTH_REPLAY_SIZE / 8
.compare:
    mov  rax, [rbx]
    cmp  rax, [r12]
    jne  .failed
    add  rbx, 8
    add  r12, 8
    dec  ecx
    jnz  .compare
    mov  byte [rel command_auth_replay_state], AUTH_REPLAY_VALID
    mov  byte [rel command_auth_durable_ready], 1
    mov  byte [rel command_auth_resv_state], AUTH_RESV_HELD
    mov  byte [rel command_auth_resv_error], AUTH_RESV_E_NONE
    xor  eax, eax
    jmp  .out
.failed:
    ; The candidate may have reached firmware even though it was not verified;
    ; it can only be higher than R.  replay_state keeps the last verified view.
    mov  byte [rel command_auth_durable_ready], 0
    mov  byte [rel command_auth_resv_state], AUTH_RESV_FAILED
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; command_auth_init -- establish the fail-closed boundary and recover the last
; durable owner sequence from the dedicated replay record.
command_auth_init:
    mov  byte [rel command_auth_remote_active], 0
    mov  qword [rel command_auth_remote_ticket], 0
    mov  dword [rel command_auth_intercept_count], 0
    mov  qword [rel command_auth_last_sequence], 0
    mov  qword [rel command_auth_reserved_through], 0
    mov  qword [rel command_auth_seal], -1
    mov  qword [rel command_auth_accept_count], 0
    mov  qword [rel command_auth_deny_count], 0
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_refusal_ready], 0
    mov  byte [rel command_auth_m_principal_table], 0
    mov  byte [rel command_auth_m_principal_bound], 0
    mov  byte [rel command_auth_m_principal_gate], 0
    mov  byte [rel command_auth_m_principal_deny], 0
    ; AUTH2: latch this boot's node_id from the pre-EBS SMBIOS snapshot now (a
    ; degenerate-SMBIOS node latches its MAC id on first use after the NIC is up).
    call command_auth_node_id_ensure
    call rsa_verify_reentrancy_selftest
    call command_auth_replay_load
    call command_auth_principal_selftest
    ; 2504 is an authentication surface, so reserve its one registry row at
    ; the authentication boundary. The later UDP projection had already
    ; reached VERB_MAX; push_auth_init verifies append + exact-name lookup
    ; before its KAT can emit any login.push marker.
%if !PAOS_PUBLIC_BUILD
    call push_auth_init
%endif
    ; The synthetic refusal proves policy but is not an operator request.  Do
    ; not leak its staged receipt or count it in the live AUTHSTAT counters.
    mov  qword [rel command_auth_deny_count], 0
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_refusal_ready], 0
    ; HELP and AUTHSTAT are ordinary read-only registry verbs.  Their output is
    ; generated from the live registry and live intercept table at request time.
    lea  rdi, [rel str_auth_verb_help]
    lea  rsi, [rel command_auth_status_verb]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_auth_verb_status]
    lea  rsi, [rel command_auth_status_verb]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; AUTHSTAT split (ADMIN 2026-10-01 23:2x): the public-verb census moved out of
    ; the bounded AUTHSTAT reply into this one read-only sibling with AUTHSTAT's
    ; exact exposure (cap=0/destr=0 registry row, exact-name public grant, the
    ; same locked-session allowlists, the same transport audit rows).
    lea  rdi, [rel str_auth_verb_verbs]
    lea  rsi, [rel command_auth_verbs_verb]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; AUTHFLOOR RESEED (SEC-replay-record-mac §9.5): console OWNER only; the
    ; handler refuses every other ingress and keyprov refuses injected lines.
    lea  rdi, [rel str_verb_authfloor]
    lea  rsi, [rel command_authfloor_verb]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; owner mutation: stages the floor reseed
    call command_register_verb
    lea  rdi, [rel str_verb_secureboot]
    lea  rsi, [rel command_secureboot_verb]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; Rescue-0 R0-0: public read-only projection of the pre-EBS SNP record.
    lea  rdi, [rel str_verb_r0stat]
    lea  rsi, [rel command_r0stat_verb]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; Metadata and this exact-name floor are independent publication keys.
    call fs_command_init
    call backup_command_init              ; 1230a: owner-only BACKUP subcommands
    ; 2701 stays inside the authorized service seam: exercise the bounded
    ; offline core, then publish its read-only diagnostic adapter.  Keeping
    ; this beside the other public registry initialization avoids modifying
    ; the boot entrypoint while preserving the original startup order.
    call web_structured_selftest
%if !PAOS_PUBLIC_BUILD
    call command_web_register
%endif
%if !PAOS_PUBLIC_BUILD
    call command_http_register              ; 1059: HTTPGET/HTTPSTAT/HTTPBODY
%endif
    call sensitive_classifier_selftest
    call command_privacy_register
    call command_auth_owner_keyid_selftest
    xor  eax, eax
    ret

; boot/header's Task3020 alias lands here. UDP first declares its late
; BOOTLOG/DIAGRING/IMG rows and intercept table; only then can the posture KAT
; grade the completed live registry.
command_publicity_udp_init:
    call command_udp_init
    call command_auth_publicity_selftest
    ret

; Task2300's bootlog_full_selftest predates S4 and directly asserts that its
; two read handlers are public. Keep that mechanical KAT alive without
; weakening the shipped remote classifier used by dispatch and AUTHSTAT.
command_auth_legacy_read_kat_cap:
    test rsi, rsi
    jnz  command_auth_required_cap
    test rdx, rdx
    jnz  command_auth_required_cap
    cmp  dword [rdi], 'BOOT'
    jne  .diagring
    cmp  dword [rdi + 4], 'LOG'
    jne  command_auth_required_cap
    cmp  byte [rdi + 7], 0
    je   .public
.diagring:
    cmp  dword [rdi], 'DIAG'
    jne  command_auth_required_cap
    cmp  dword [rdi + 4], 'RING'
    jne  command_auth_required_cap
    cmp  byte [rdi + 8], 0
    jne  command_auth_required_cap
.public:
    xor  eax, eax
    ret

; Rung-2500 boot fixture.  SYSTEM has deliberately no wire credential, so its
; sovereign denial is exercised here and labelled NON-WIRE.  The real owner
; allow remains the unchanged AUTH1 UDP path and is graded externally.
command_auth_principal_selftest:
    push rbx
    call principal_authorization_selftest
    test eax, eax
    jnz  .done

    lea  rdi, [rel command_auth_principal_test_ticket]
    xor  esi, esi
    mov  edx, AUTH_T_SIZE
    call memset
    mov  rax, CMD_AUTH_CAP_BOOT
    mov  [rel command_auth_principal_test_ticket + AUTH_T_CAP], rax
    lea  rax, [rel str_auth_principal_test_verb]
    mov  [rel command_auth_principal_test_ticket + AUTH_T_COMMAND], rax
    mov  byte [rel command_auth_principal_test_ticket + AUTH_T_STATE], AUTH_TS_VALID
    mov  qword [rel command_auth_principal_test_ticket + AUTH_T_PRINCIPAL], PRIN_SYSTEM
    mov  byte [rel command_auth_last_reason], 0
    lea  rdi, [rel command_auth_principal_test_ticket]
    mov  rsi, CMD_AUTH_CAP_BOOT
    lea  rdx, [rel str_auth_principal_test_verb]
    call command_auth_authorize
    cmp  eax, -1
    jne  .done
    cmp  byte [rel command_auth_last_reason], AUTHR_PRINCIPAL
    jne  .done

    lea  rdi, [rel str_auth_m_principal_table]
    call serial_string
    lea  rdi, [rel str_auth_m_principal_bound]
    call serial_string
    lea  rdi, [rel str_auth_m_principal_gate]
    call serial_string
    lea  rdi, [rel str_auth_m_principal_deny]
    call serial_string
    mov  byte [rel command_auth_m_principal_table], 1
    mov  byte [rel command_auth_m_principal_bound], 1
    mov  byte [rel command_auth_m_principal_gate], 1
    mov  byte [rel command_auth_m_principal_deny], 1
.done:
    pop  rbx
    ret

; Exercise the exact production AUTHSTAT and AUTH_REFUSED builders at boot.
; Each builder must call command_auth_put_owner_key_id: the witness pointer is
; cleared before the call, then its 64 rendered bytes are compared with a
; fresh rendering of the compiled 32-byte key id.  Nothing is emitted unless
; both paths match, so the marker cannot mask a copied operator-visible id.
command_auth_owner_keyid_selftest:
%ifdef PAOS_NODE_IDENTITY_TEST_ACTIVE_FIXTURE
    jmp  command_auth_node_identity_forbidden_selftest
%endif
    push rbx

    ; Produce the expected string through the same bounded production seam.
    mov  qword [rel command_auth_owner_keyid_last_start], 0
    call command_auth_out_reset
    call command_auth_put_owner_key_id
    lea  rax, [rel command_auth_out_buf]
    cmp  [rel command_auth_owner_keyid_last_start], rax
    jne  .done
    mov  rdx, [rel command_auth_out_cur]
    sub  rdx, rax
    cmp  rdx, 64
    jne  .done
    lea  rdi, [rel command_auth_keyid_kat_expected]
    mov  rsi, rax
    mov  edx, 65
    call memcpy

    ; AUTHSTAT: invoke its production inventory/append path, not a test clone.
    mov  qword [rel command_auth_owner_keyid_last_start], 0
    call command_auth_inventory_stage
    lea  rdi, [rel command_auth_keyid_kat_authstat]
    call command_auth_owner_keyid_selftest_capture
    test eax, eax
    jz   .done

    ; Select the AUTHSTAT word from the same validity bit as JOBPUB.  Validate
    ; the production builder before publishing its QEMU regression row; the
    ; live probe independently cross-checks this word against JOBPUB's reply.
    call node_identity_active
    lea  rbx, [rel str_auth_node_absent]
    test eax, eax
    jz   .node_state_expected
    lea  rbx, [rel str_auth_node_active]
.node_state_expected:
    lea  rdi, [rel command_auth_out_buf]
    lea  rsi, [rel str_auth_stat_node]
    call str_find
    test rax, rax
    jz   .done
    cmp  byte [rax + str_auth_stat_node.len + 6], ' '
    jne  .done
    lea  rdi, [rax + str_auth_stat_node.len]
    mov  rsi, rbx
    mov  edx, 6
    call memcmp
    test eax, eax
    jnz  .done
    lea  rdi, [rel str_auth_node_state_marker]
    call serial_string

    ; AUTH_REFUSED: format first, then let the unchanged production path sign
    ; the exact accumulated text.  This synthetic boot receipt is not counted.
    mov  qword [rel command_auth_owner_keyid_last_start], 0
    mov  qword [rel command_auth_ref_required], 0
    mov  edi, AUTHR_WRONG_KEY
    lea  rsi, [rel str_auth_keyid_kat_verb]
    xor  edx, edx
    call command_auth_stage_refusal
    lea  rdi, [rel command_auth_keyid_kat_refused]
    call command_auth_owner_keyid_selftest_capture
    test eax, eax
    jz   .done

    ; A deterministic runtime nonce derived from all compiled key-id qwords
    ; binds the row to runtime data while the random-key probe supplies entropy.
    mov  rbx, [rel command_auth_owner_key_id]
    or   rbx, [rel command_auth_owner_key_id + 8]
    or   rbx, [rel command_auth_owner_key_id + 16]
    or   rbx, [rel command_auth_owner_key_id + 24]
    jz   .done
    lea  rdi, [rel str_auth_keyid_kat_row]
    call serial_string
    mov  rdi, rbx
    lea  rsi, [rel command_auth_num_buf]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel command_auth_num_buf]
    call serial_string
    lea  rdi, [rel str_auth_keyid_kat_expected]
    call serial_string
    lea  rdi, [rel command_auth_keyid_kat_expected]
    call serial_string
    lea  rdi, [rel str_auth_keyid_kat_authstat]
    call serial_string
    lea  rdi, [rel command_auth_keyid_kat_authstat]
    call serial_string
    lea  rdi, [rel str_auth_keyid_kat_refused]
    call serial_string
    lea  rdi, [rel command_auth_keyid_kat_refused]
    call serial_string
    lea  rdi, [rel str_auth_keyid_kat_hardcoded]
    call serial_string
    call serial_newline
    lea  rdi, [rel str_auth_keyid_kat_marker]
    call serial_string
    call serial_newline
.done:
    ; Do not publish either synthetic boot response to a live requester.
    call command_auth_out_reset
    mov  byte [rel command_auth_out_ready], 0
    pop  rbx
    ret

%ifdef PAOS_NODE_IDENTITY_TEST_ACTIVE_FIXTURE
; Negative-only QEMU handler/output control.  node_identity_selftest_consumer
; deliberately retained RFC8032 TEST 1; require the registered production
; JOBPUB handler's exact public reply plus AUTHSTAT=active.  The Phase-8 probe
; separately proves reachability through the remote AUTH1 authorization gate.
command_auth_node_identity_forbidden_selftest:
    push rbx                            ; preserve ABI call alignment
    call command_auth_inventory_stage
    call node_identity_active
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel command_auth_out_buf]
    lea  rsi, [rel str_auth_fixture_active]
    call str_find
    test rax, rax
    jz   .fail

    lea  rdi, [rel command_auth_node_fixture_req]
    xor  esi, esi
    mov  edx, REQ_SZ
    call memset
    lea  rdi, [rel command_auth_node_fixture_rsp]
    xor  esi, esi
    mov  edx, RSP_SZ
    call memset
    lea  rdi, [rel str_auth_fixture_jobpub]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel command_auth_node_fixture_req + REQ_VERB], rax
    lea  rdi, [rel command_auth_node_fixture_req]
    lea  rsi, [rel command_auth_node_fixture_rsp]
    call command_dispatch
    test eax, eax
    jnz  .fail
    cmp  byte [rel job_out_ready], 1
    jne  .fail
    lea  rdi, [rel job_out_buf]
    lea  rsi, [rel str_auth_fixture_jobpub_expected]
    call strcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_auth_node_fixture_marker]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_auth_node_fixture_fail]
    call serial_string
.done:
    mov  byte [rel job_out_ready], 0
    call command_auth_out_reset
    mov  byte [rel command_auth_out_ready], 0
    pop  rbx
    ret
%endif

; RDI=65-byte destination.  Capture the most recent production owner-id span
; and return EAX=1 only when it is in-bounds and byte-equal to the expected id.
command_auth_owner_keyid_selftest_capture:
    push rbx
    mov  rbx, rdi
    mov  rsi, [rel command_auth_owner_keyid_last_start]
    lea  rax, [rel command_auth_out_buf]
    cmp  rsi, rax
    jb   .fail
    lea  rax, [rel command_auth_out_buf + AUTH_OUT_MAX - 65]
    cmp  rsi, rax
    ja   .fail
    mov  rdi, rbx
    mov  edx, 64
    call memcpy
    mov  byte [rbx + 64], 0
    mov  rdi, rbx
    lea  rsi, [rel command_auth_keyid_kat_expected]
    mov  edx, 64
    call memcmp
    test eax, eax
    jnz  .fail
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  rbx
    ret

command_auth_remote_begin:
    mov  [rel command_auth_remote_ticket], rdi
    mov  byte [rel command_auth_remote_active], 1
    mov  byte [rel command_auth_refusal_ready], 0
    mov  byte [rel net_access_last_blocked], 0
    ; Storage-access canon (PETER 2026-09-29 21:25): only a request carrying a VERIFIED OWNER ticket holds
    ; explicit special permission for sensitive writes; everything else is implicit.
    mov  eax, SA_INTENT_IMPLICIT
    test rdi, rdi
    jz   .intent
    cmp  qword [rdi + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .intent
    cmp  qword [rdi + AUTH_T_STATE], AUTH_TS_VALID
    je   .owner
    cmp  qword [rdi + AUTH_T_STATE], AUTH_TS_CONSUMED
    je   .owner
    ; An SSH-bound OWNER holds special intent only when its enrolled key is
    ; unrestricted; a capability-restricted key stays implicit.
    cmp  qword [rdi + AUTH_T_STATE], AUTH_TS_SSH
    jne  .intent
    cmp  qword [rdi + AUTH_T_CAP], -1
    jne  .intent
.owner:
    mov  eax, SA_INTENT_SPECIAL
.intent:
    mov  edi, eax
    jmp  storage_access_set_request_intent

command_auth_remote_end:
%ifdef PAOS_LAB_RETURN_SECONDS
%if PAOS_LAB_RETURN_SECONDS
    call lab_return_contact                  ; lab-only, preserves registers/flags; before ticket retirement
%endif
%endif
    mov  byte [rel command_auth_remote_active], 0
    mov  qword [rel command_auth_floor_ticket], 0   ; a hand-off never outlives its request. Not in remote_begin:
                                                    ; keyprov re-begins the outer request after its nested line.
    mov  byte [rel command_auth_floor_handoff], 0
    mov  byte [rel net_access_last_blocked], 0
    mov  qword [rel command_auth_remote_ticket], 0
    mov  edi, SA_INTENT_IMPLICIT
    jmp  storage_access_set_request_intent

; command_auth_ticket_owner(RDI=req) -> EAX 1: this request is the verified OWNER principal / 0. RCQ-21 SA2b
;   (rc-sec S1, 16:00:57 / 16:42:03): command_dispatch computes it for every frame and hands it to the owned-volume
;   writers through storage_access_request_owner_swap. An allow-list over the request and the IN-FLIGHT ticket only,
;   never ambient principal state: REQ_PRINCIPAL is CMD_PRINCIPAL_OWNER, and either a remote request
;   (remote_begin..remote_end) whose ticket is the OWNER's and VALID, CONSUMED or SSH-bound (any capability:
;   a restricted owner key may write owner-adopted storage, RC spec 7.5), or otherwise the local console. A
;   frame the post-reply session sync dispatches (command_session_sync_active, still inside remote_begin..
;   remote_end) is a console frame, never judged by the outer request's ticket (RCQ-27-M1's definition of a
;   remote frame; rc-sec c3 R1, 19:23:15). A console frame inside a line keyprov dispatches as tainted
;   (keyprov_active_taint != 0: typed, whole or in part, by injection, tethered or not, and every frame nested
;   in it) is 0, whoever its principal (srcreview c3 F1, admin 19:36:22). Everything else is 0: SYSTEM, ADVISOR,
;   the AI hook, any other ticket state (an injected line, an unsigned, expired, retired or wrong-node envelope),
;   and a local internal or serial request. Clobbers RAX, RCX.
command_auth_ticket_owner:
    xor  eax, eax
    cmp  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .out
    cmp  byte [rel command_auth_remote_active], 1
    jne  .console
    cmp  byte [rel command_session_sync_active], 0
    je   .remote                         ; a sync-dispatched frame is a console frame
.console:
    cmp  qword [rel keyprov_active_taint], 0
    jne  .out                            ; an injected line is never the owner's
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .out
    inc  eax
    ret
.remote:
    mov  rcx, [rel command_auth_remote_ticket]
    test rcx, rcx
    jz   .out
    cmp  qword [rcx + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .out
    cmp  qword [rcx + AUTH_T_STATE], AUTH_TS_VALID
    je   .yes
    cmp  qword [rcx + AUTH_T_STATE], AUTH_TS_CONSUMED
    je   .yes
    cmp  qword [rcx + AUTH_T_STATE], AUTH_TS_SSH
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

command_auth_note_aihook_proof:
    mov  byte [rel command_auth_aihook_gate_proved], 1
    ret

command_auth_note_serial_proof:
    mov  byte [rel command_auth_serial_gate_proved], 1
    ret

; Parse exactly sixteen hexadecimal digits.  RAX=value, RDX=next pointer,
; CF clear on success; CF set on malformed input.
command_auth_parse_hex64:
    mov  r9, rdi
    xor  r8, r8
    mov  ecx, 16
.next:
    movzx eax, byte [r9]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    jmp  .have
.digit:
    sub  al, '0'
.have:
    movzx eax, al
    shl  r8, 4
    or   r8, rax
    inc  r9
    dec  ecx
    jnz  .next
    mov  rax, r8
    mov  rdx, r9
    clc
    ret
.bad:
    stc
    ret

; Exact eight-digit Unix-second field.  Keeping wall times at their natural
; 32-bit wire width preserves enough of one MTU for the existing BLKWRITE
; payload; the canonical signed message still widens them to LE64.
command_auth_parse_hex32:
    mov  r9, rdi
    xor  r8, r8
    mov  ecx, 8
.next:
    movzx eax, byte [r9]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    jmp  .have
.digit:
    sub  al, '0'
.have:
    movzx eax, al
    shl  r8, 4
    or   r8, rax
    inc  r9
    dec  ecx
    jnz  .next
    mov  rax, r8
    mov  rdx, r9
    clc
    ret
.bad:
    stc
    ret

; command_auth_unwrap_line(RDI=mutable line, RSI=ticket) -> EAX=AUTH_TS_*.
; A syntactically complete envelope is shifted in-place to leave only the inner
; command, so every existing projection continues to parse the same grammar.
command_auth_unwrap_line:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, r13
    xor  esi, esi
    mov  edx, AUTH_T_SIZE
    call memset
    cmp  dword [r12], 'AUTH'
    jne  .unsigned
    cmp  byte [r12 + 4], '2'
    je   .v2
    cmp  byte [r12 + 4], '1'
    jne  .unsigned
    cmp  byte [r12 + 5], ' '
    jne  .malformed
    ; AUTH2 cutover: a v1 envelope carries no node identity. Refuse it before
    ; any field parse or RSA work; the ticket stays zero (no seq, no principal).
    mov  byte [r13 + AUTH_T_STATE], AUTH_TS_RETIRED
    mov  eax, AUTH_TS_RETIRED
    jmp  .out
.v2:
    cmp  byte [r12 + 5], ' '
    jne  .malformed
    ; node_id first: a missing/malformed/foreign id is refused before the RSA work.
    lea  rdi, [r12 + 6]
    call command_auth_parse_node_id         ; -> command_auth_wire_node, RDX = next
    jc   .wrong_node
    cmp  byte [rdx], ' '
    jne  .wrong_node
    lea  r14, [rdx + 1]
    call command_auth_node_id_ensure
    test eax, eax
    jz   .wrong_node                        ; no identity latched yet: fail closed
    lea  rdi, [rel command_auth_wire_node]
    lea  rsi, [rel command_auth_node_id]
    mov  edx, AUTH_NODE_ID_LEN
    call memcmp
    test eax, eax
    jnz  .wrong_node

    mov  rdi, r14
    call command_auth_parse_hex64
    jc   .malformed
    mov  [r13 + AUTH_T_CAP], rax
    cmp  byte [rdx], ' '
    jne  .malformed
    lea  r14, [rdx + 1]
    mov  rdi, r14
    call command_auth_parse_hex64
    jc   .malformed
    mov  [r13 + AUTH_T_SEQ], rax
    cmp  byte [rdx], ' '
    jne  .malformed
    lea  r14, [rdx + 1]
    mov  rdi, r14
    call command_auth_parse_hex32
    jc   .malformed
    mov  [r13 + AUTH_T_ISSUED], rax
    cmp  byte [rdx], ' '
    jne  .malformed
    lea  r14, [rdx + 1]
    mov  rdi, r14
    call command_auth_parse_hex32
    jc   .malformed
    mov  [r13 + AUTH_T_EXPIRES], rax
    cmp  byte [rdx], ' '
    jne  .malformed
    lea  r14, [rdx + 1]

    ; Fixed 256-byte RSA signatures use unpadded base64url on the text wire:
    ; 85 complete quanta (255 bytes) plus one two-character tail (one byte).
    ; This is encoding only; rsa2048_verify_sha256 still consumes the exact
    ; conventional big-endian signature bytes.  The compact representation is
    ; what lets the existing ~1060-byte BLKWRITE command remain a one-datagram
    ; authenticated request under the Ethernet MTU.
    lea  rbx, [rel command_auth_signature]
    xor  r15d, r15d
.sig_group:
    movzx eax, byte [r14]
    call command_auth_b64url_value
    test eax, eax
    js   .malformed
    mov  r10d, eax
    movzx eax, byte [r14 + 1]
    call command_auth_b64url_value
    test eax, eax
    js   .malformed
    mov  r11d, eax
    movzx eax, byte [r14 + 2]
    call command_auth_b64url_value
    test eax, eax
    js   .malformed
    mov  r8d, eax
    movzx eax, byte [r14 + 3]
    call command_auth_b64url_value
    test eax, eax
    js   .malformed
    mov  r9d, eax
    mov  eax, r10d
    shl  eax, 2
    mov  edx, r11d
    shr  edx, 4
    or   eax, edx
    mov  [rbx], al
    mov  eax, r11d
    shl  eax, 4
    mov  edx, r8d
    shr  edx, 2
    or   eax, edx
    mov  [rbx + 1], al
    mov  eax, r8d
    shl  eax, 6
    or   eax, r9d
    mov  [rbx + 2], al
    add  r14, 4
    add  rbx, 3
    inc  r15d
    cmp  r15d, 85
    jb   .sig_group
    movzx eax, byte [r14]
    call command_auth_b64url_value
    test eax, eax
    js   .malformed
    mov  r10d, eax
    movzx eax, byte [r14 + 1]
    call command_auth_b64url_value
    test eax, eax
    js   .malformed
    test eax, 0x0f                       ; unused tail bits must be canonical zero
    jnz  .malformed
    mov  edx, eax
    mov  eax, r10d
    shl  eax, 2
    shr  edx, 4
    or   eax, edx
    mov  [rbx], al
    add  r14, 2
    cmp  byte [r14], ' '
    jne  .malformed
    inc  r14
    cmp  byte [r14], 0
    je   .malformed
    mov  rdi, r14
    call strlen
    mov  r15, rax
    test r15, r15
    jz   .malformed
    cmp  r15, AUTH_CMD_MAX
    ja   .malformed

    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, r15
    call command_auth_build_message

    lea  rdi, [rel command_auth_signature]
    lea  rsi, [rel command_auth_message]
    lea  rdx, [r15 + AUTH_MSG_HDR]
    lea  rcx, [rel command_auth_owner_modulus]
    call rsa2048_verify_sha256
    ; w045 secret hygiene: the signed message copy (and the one-shot SHA-256
    ; block/schedule that hashed it) hold the inner command, which may carry a
    ; credential. Nothing reads them after the verdict: wipe on EVERY outcome
    ; before a forged/expired/replayed envelope can leave them resident.
    mov  ebx, eax
    call command_auth_scrub_verifier
    test ebx, ebx
    jnz  .wrong_key
    ; The verified method selects the principal. The caller's asserted PID is
    ; deliberately zero/non-authoritative; authenticate_bind returns the PID.
    lea  rax, [rel command_auth_owner_key_id]
    mov  [rel command_auth_bind_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  qword [rel command_auth_bind_ctx + AUTH_CTX_CRED_LEN], 32
    mov  qword [rel command_auth_bind_ctx + AUTH_CTX_ASSERTED_PID], 0
    mov  edi, AUTH_BIND_OWNER_RSA
    lea  rsi, [rel command_auth_bind_ctx]
    call authenticate_bind
    test rax, rax
    jz   .wrong_key
    mov  [r13 + AUTH_T_PRINCIPAL], rax
    mov  rdi, r13
    call command_auth_ticket_time_valid
    test eax, eax
    jz   .expired
    mov  byte [r13 + AUTH_T_STATE], AUTH_TS_VALID
    jmp  .copy_inner
.wrong_key:
    mov  byte [r13 + AUTH_T_STATE], AUTH_TS_WRONG_KEY
    jmp  .copy_inner
.expired:
    mov  byte [r13 + AUTH_T_STATE], AUTH_TS_EXPIRED
.copy_inner:
    mov  rdi, r12
    mov  rsi, r14
    lea  rcx, [r15 + 1]
    cld
    rep  movsb
    mov  [r13 + AUTH_T_COMMAND], r12
    movzx eax, byte [r13 + AUTH_T_STATE]
    jmp  .out
.malformed:
    mov  byte [r13 + AUTH_T_STATE], AUTH_TS_MALFORMED
    mov  eax, AUTH_TS_MALFORMED
    jmp  .out
.wrong_node:
    mov  byte [r13 + AUTH_T_STATE], AUTH_TS_WRONG_NODE
    mov  eax, AUTH_TS_WRONG_NODE
    jmp  .out
.unsigned:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; command_auth_parse_node_id(RDI=text) -> exactly 32 hex digits into
;   command_auth_wire_node[16]; RDX = next pointer, CF clear on success, CF set
;   on a short/non-hex field. Clobbers RAX, RCX, RDX, R8-R11.
command_auth_parse_node_id:
    lea  r10, [rel command_auth_wire_node]
    xor  r11d, r11d
.byte:
    movzx eax, byte [rdi]
    call command_auth_hex_nibble
    test eax, eax
    js   .bad
    mov  r8d, eax
    movzx eax, byte [rdi + 1]
    call command_auth_hex_nibble
    test eax, eax
    js   .bad
    shl  r8d, 4
    or   r8d, eax
    mov  [r10 + r11], r8b
    add  rdi, 2
    inc  r11d
    cmp  r11d, AUTH_NODE_ID_LEN
    jb   .byte
    mov  rdx, rdi
    clc
    ret
.bad:
    stc
    ret

; >>> AUTH2-KAT-BEGIN canonical message (host KAT extracts this block verbatim)
; command_auth_build_message(RDI=ticket, RSI=command bytes, RDX=command length
;   <= AUTH_CMD_MAX) -> RAX = message length. Writes the canonical AUTH2 message
;   into command_auth_message:
;   "PAOS-CMD-AUTH2\0\0" || u8 2 || node_id[16] || le64 cap || le64 seq ||
;   le64 issued || le64 expires || command
;   node_id is THIS node's latched id (the caller already compared the wire copy).
;   Preserves RBX, RBP, R12-R15.
command_auth_build_message:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    lea  rdi, [rel command_auth_message]
    lea  rsi, [rel command_auth_domain]
    mov  edx, 16
    call memcpy
    mov  byte [rel command_auth_message + AUTH_MSG_VER_OFF], AUTH2_FORMAT_VERSION
    lea  rdi, [rel command_auth_message + AUTH_MSG_NODE_OFF]
    lea  rsi, [rel command_auth_node_id]
    mov  edx, AUTH_NODE_ID_LEN
    call memcpy
    mov  rax, [rbx + AUTH_T_CAP]
    mov  [rel command_auth_message + AUTH_MSG_CAP_OFF], rax
    mov  rax, [rbx + AUTH_T_SEQ]
    mov  [rel command_auth_message + AUTH_MSG_SEQ_OFF], rax
    mov  rax, [rbx + AUTH_T_ISSUED]
    mov  [rel command_auth_message + AUTH_MSG_ISSUED_OFF], rax
    mov  rax, [rbx + AUTH_T_EXPIRES]
    mov  [rel command_auth_message + AUTH_MSG_EXPIRES_OFF], rax
    lea  rdi, [rel command_auth_message + AUTH_MSG_HDR]
    mov  rsi, r12
    mov  rdx, r13
    call memcpy
    lea  rax, [r13 + AUTH_MSG_HDR]
    pop  r13
    pop  r12
    pop  rbx
    ret
; <<< AUTH2-KAT-END canonical message

; >>> AUTH2-KAT-BEGIN node identity (host KAT extracts this block verbatim)
; node_id (16 bytes), computed once per boot from the pre-EBS SMBIOS snapshot:
;   SHA-256("PAOS-NODE-ID-V1\0" || uuid[16] || le16 len || serial)[0..16]
; uuid = the raw type-1 UUID in table byte order (16 x 00 when the structure has
; none); serial = the type-1 serial string exactly as boot/smbios captured it
; (clipped to 63 bytes, non-printables as '?'). Degenerate SMBIOS (UUID absent,
; all-00 or all-FF AND serial empty, filler-only or a known placeholder) falls
; back to the primary NIC's permanent MAC:
;   SHA-256("PAOS-NODE-ID-MAC1\0" || mac[6])[0..16]
; and an all-00/all-FF MAC is no identity at all (src none: AUTH2 fails closed).
AUTH_NODE_SRC_NONE   equ 0
AUTH_NODE_SRC_SMBIOS equ 1
AUTH_NODE_SRC_MAC    equ 2
AUTH_NODE_SERIAL_MAX equ 63
AUTH_NODE_SCRATCH    equ 168                ; 32 digest + 16 dom + 16 uuid + 2 len + 63 serial, aligned
AUTH_NODE_PH_EXACT   equ 1
AUTH_NODE_PH_PREFIX  equ 2

; command_auth_node_id_derive(RDI=out16, RSI=uuid16 or 0 (absent), RDX=serial
;   cstr, RCX=mac6 or 0 (no NIC)) -> EAX = AUTH_NODE_SRC_*; out16 is written
;   only when EAX != NONE. Pure (stack scratch only). Preserves RBX, RBP, R12-R15.
command_auth_node_id_derive:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, AUTH_NODE_SCRATCH
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    xor  r15d, r15d                         ; bounded serial length
.slen:
    cmp  r15d, AUTH_NODE_SERIAL_MAX
    jae  .slen_done
    cmp  byte [r13 + r15], 0
    je   .slen_done
    inc  r15d
    jmp  .slen
.slen_done:
    mov  rdi, r12
    call command_auth_node_uuid_degenerate
    test eax, eax
    jz   .smbios
    mov  rdi, r13
    mov  esi, r15d
    call command_auth_node_serial_degenerate
    test eax, eax
    jz   .smbios
    test r14, r14
    jz   .none
    mov  rdi, r14
    mov  esi, 6
    call command_auth_node_bytes_uniform
    test eax, eax
    jnz  .none
    lea  rdi, [rsp + 32]
    lea  rsi, [rel command_auth_node_dom_mac]
    mov  edx, command_auth_node_dom_mac.len
    call memcpy
    mov  eax, [r14]
    mov  [rsp + 32 + command_auth_node_dom_mac.len], eax
    movzx eax, word [r14 + 4]
    mov  [rsp + 32 + command_auth_node_dom_mac.len + 4], ax
    mov  rdi, rsp
    lea  rsi, [rsp + 32]
    mov  edx, command_auth_node_dom_mac.len + 6
    call sha256_hash
    mov  ebp, AUTH_NODE_SRC_MAC
    jmp  .emit
.smbios:
    lea  rdi, [rsp + 32]
    lea  rsi, [rel command_auth_node_dom_smbios]
    mov  edx, 16
    call memcpy
    xor  eax, eax
    xor  edx, edx
    test r12, r12
    jz   .uuid_put
    mov  rax, [r12]
    mov  rdx, [r12 + 8]
.uuid_put:
    mov  [rsp + 48], rax
    mov  [rsp + 56], rdx
    mov  [rsp + 64], r15w                   ; le16 serial length
    lea  rdi, [rsp + 66]
    mov  rsi, r13
    mov  edx, r15d
    call memcpy
    mov  rdi, rsp
    lea  rsi, [rsp + 32]
    lea  edx, [r15 + 34]
    call sha256_hash
    mov  ebp, AUTH_NODE_SRC_SMBIOS
.emit:
    mov  rax, [rsp]
    mov  [rbx], rax
    mov  rax, [rsp + 8]
    mov  [rbx + 8], rax
    mov  eax, ebp
    jmp  .out
.none:
    xor  eax, eax
.out:
    add  rsp, AUTH_NODE_SCRATCH
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=uuid16 or 0 -> EAX=1 when absent, all-00 or all-FF. Clobbers RAX,RCX,RDX,RSI.
command_auth_node_uuid_degenerate:
    mov  eax, 1
    test rdi, rdi
    jz   .out
    mov  esi, 16
    jmp  command_auth_node_bytes_uniform
.out:
    ret

; command_auth_node_bytes_uniform(RDI=bytes, ESI=len>0) -> EAX=1 when every byte
;   is 00 or every byte is FF. Clobbers RAX, RCX, RDX.
command_auth_node_bytes_uniform:
    movzx edx, byte [rdi]
    cmp  edx, 0x00
    je   .scan
    cmp  edx, 0xFF
    jne  .no
.scan:
    xor  ecx, ecx
.loop:
    cmp  ecx, esi
    jae  .yes
    cmp  [rdi + rcx], dl
    jne  .no
    inc  ecx
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; command_auth_node_serial_degenerate(RDI=serial, ESI=len) -> EAX=1 when the
;   serial cannot identify a machine: empty, only filler (' ', '0', '?', '.',
;   '-', '_'), or a known firmware placeholder (ASCII case-insensitive; exact
;   or prefix per command_auth_node_placeholders). Clobbers caller-saved.
command_auth_node_serial_degenerate:
    test esi, esi
    jz   .yes
    xor  ecx, ecx
.filler:
    cmp  ecx, esi
    jae  .yes                               ; nothing but filler
    movzx eax, byte [rdi + rcx]
    cmp  al, ' '
    je   .filler_next
    cmp  al, '0'
    je   .filler_next
    cmp  al, '?'
    je   .filler_next
    cmp  al, '.'
    je   .filler_next
    cmp  al, '-'
    je   .filler_next
    cmp  al, '_'
    jne  .table
.filler_next:
    inc  ecx
    jmp  .filler
.table:
    lea  r8, [rel command_auth_node_placeholders]
.entry:
    movzx r9d, byte [r8]                    ; mode, 0 = end of table
    test r9d, r9d
    jz   .no
    inc  r8
    xor  ecx, ecx                           ; index into pattern and serial
.cmp:
    movzx eax, byte [r8 + rcx]
    test eax, eax
    jz   .pattern_end
    cmp  ecx, esi
    jae  .mismatch
    movzx edx, byte [rdi + rcx]
    cmp  edx, 'A'
    jb   .lowered
    cmp  edx, 'Z'
    ja   .lowered
    or   edx, 0x20
.lowered:
    cmp  eax, edx
    jne  .mismatch
    inc  ecx
    jmp  .cmp
.pattern_end:
    cmp  r9d, AUTH_NODE_PH_PREFIX
    je   .yes
    cmp  ecx, esi
    je   .yes
.mismatch:
.skip:                                      ; advance r8 past this pattern's NUL
    cmp  byte [r8], 0
    je   .skipped
    inc  r8
    jmp  .skip
.skipped:
    inc  r8
    jmp  .entry
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

command_auth_node_dom_smbios: db "PAOS-NODE-ID-V1", 0
%if ($ - command_auth_node_dom_smbios) != 16
    %error "node_id SMBIOS domain must be 16 bytes"
%endif
command_auth_node_dom_mac: db "PAOS-NODE-ID-MAC1", 0
.len equ $ - command_auth_node_dom_mac
; {mode, lowercase pattern, 0}..., 0. Patterns seen as SMBIOS fillers on OEM boards.
command_auth_node_placeholders:
    db AUTH_NODE_PH_PREFIX, "to be filled", 0
    db AUTH_NODE_PH_EXACT, "default string", 0
    db AUTH_NODE_PH_EXACT, "system serial number", 0
    db AUTH_NODE_PH_EXACT, "chassis serial number", 0
    db AUTH_NODE_PH_EXACT, "not specified", 0
    db AUTH_NODE_PH_EXACT, "not applicable", 0
    db AUTH_NODE_PH_EXACT, "not available", 0
    db AUTH_NODE_PH_EXACT, "none", 0
    db AUTH_NODE_PH_EXACT, "n/a", 0
    db AUTH_NODE_PH_EXACT, "invalid", 0
    db AUTH_NODE_PH_EXACT, "0123456789", 0
    db AUTH_NODE_PH_EXACT, "123456789", 0
    db 0
; <<< AUTH2-KAT-END node identity

; command_auth_node_id_ensure -> EAX = 1 once this boot's node_id is latched in
;   command_auth_node_id (+ command_auth_node_hex, command_auth_node_src).
;   SMBIOS-derived ids latch at the first call (command_auth_init). The MAC
;   fallback latches only once the primary NIC's MAC is known (udp_primary_mac);
;   until then EAX = 0 and every AUTH2 envelope is refused wrong_node.
;   Preserves RBX, RBP, R12-R15.
command_auth_node_id_ensure:
    cmp  byte [rel command_auth_node_src], AUTH_NODE_SRC_NONE
    jne  .ready
    push rbx
    lea  rdi, [rel command_auth_node_id]
    xor  esi, esi
    cmp  byte [rel smbios_sys_uuid_present], 1
    jne  .uuid_ready
    lea  rsi, [rel smbios_sys_uuid]
.uuid_ready:
    lea  rdx, [rel smbios_sys_serial]
    lea  rcx, [rel udp_primary_mac]
    call command_auth_node_id_derive
    test eax, eax
    jz   .none
    mov  ebx, eax
    lea  rsi, [rel command_auth_node_id]
    lea  rdi, [rel command_auth_node_hex]
    lea  r8, [rel command_auth_hex_digits]
    xor  ecx, ecx
.hex:
    movzx eax, byte [rsi + rcx]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    movzx eax, byte [r8 + rax]
    mov  [rdi + rcx * 2], al
    movzx edx, byte [r8 + rdx]
    mov  [rdi + rcx * 2 + 1], dl
    inc  ecx
    cmp  ecx, AUTH_NODE_ID_LEN
    jb   .hex
    mov  byte [rdi + AUTH_NODE_ID_LEN * 2], 0
    mov  [rel command_auth_node_src], bl    ; publish last: the id + hex are complete
    pop  rbx
.ready:
    mov  eax, 1
    ret
.none:
    pop  rbx
    xor  eax, eax
    ret

; command_auth_scrub_verifier — wipe the AUTH1 verifier workspace after the
; RSA verdict. command_auth_message holds domain||ticket||inner command; the
; shared one-shot SHA-256 context (block tail) and its message schedule
; (byte-swapped block words) still hold the last message bytes it hashed.
; A zero-length sha256_hash rewrites the whole 64-byte block (0x80 pad + zero
; + length) and all 64 schedule words through the module's own API.
; Preserves RBX/R12-R15. clobbers: caller-saved.
command_auth_scrub_verifier:
    sub  rsp, 40
    lea  rdi, [rel command_auth_message]
    xor  esi, esi
    mov  edx, AUTH_MSG_MAX
    call memset
    mov  rdi, rsp                          ; 32-byte digest scratch (SHA-256(""))
    mov  rsi, rsp
    xor  edx, edx
    call sha256_hash
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 32
    call memset
    add  rsp, 40
    ret

command_auth_hex_nibble:
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    movzx eax, al
    ret
.digit:
    sub  al, '0'
    movzx eax, al
    ret
.bad:
    mov  eax, -1
    ret

; RFC 4648 base64url alphabet value.  Padding is deliberately not accepted:
; the RSA-2048 field has one exact 342-character representation.
command_auth_b64url_value:
    cmp  al, 'A'
    jb   .digits
    cmp  al, 'Z'
    jbe  .upper
    cmp  al, 'a'
    jb   .symbols
    cmp  al, 'z'
    jbe  .lower
    jmp  .bad
.digits:
    cmp  al, '0'
    jb   .symbols
    cmp  al, '9'
    ja   .bad
    sub  al, '0' - 52
    movzx eax, al
    ret
.symbols:
    cmp  al, '-'
    je   .dash
    cmp  al, '_'
    je   .underscore
    jmp  .bad
.upper:
    sub  al, 'A'
    movzx eax, al
    ret
.lower:
    sub  al, 'a' - 26
    movzx eax, al
    ret
.dash:
    mov  eax, 62
    ret
.underscore:
    mov  eax, 63
    ret
.bad:
    mov  eax, -1
    ret

command_auth_ticket_time_valid:
    push rbx
    mov  rbx, rdi
    mov  rax, [rbx + AUTH_T_SEQ]
    test rax, rax
    jz   .bad
    mov  r8, [rbx + AUTH_T_ISSUED]
    mov  r9, [rbx + AUTH_T_EXPIRES]
    cmp  r9, r8
    jb   .bad
    mov  rax, r9
    sub  rax, r8
    cmp  rax, AUTH_MAX_TTL_S
    ja   .bad
    ; The window holds in the current wall frame, or in the one an NTP step
    ; replaced at most one TTL ago: a ticket signed against AUTHSTAT just
    ; before an asynchronous step keeps only its own real 300 s, and a
    ; backward step never revives one (time_wall_window_now_s).
    mov  rdi, r8
    mov  rsi, r9
    mov  edx, AUTH_MAX_TTL_S
    call time_wall_window_now_s
    test rax, rax
    jz   .bad
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Return the exact required remote capability. Publicity requires BOTH cap=0
; (integrity) and destr=0 (confidentiality), followed by one live-registry name
; decision. The bounded SMP/console/guest observation mux remains public in both
; postures; lab additionally retains the former broad read surface. Metadata
; may only increase protection, and BOOT remains separate from generic mutation.
command_auth_required_cap:
    ; Capability classification is independent of session availability. In
    ; particular, locking must not replace a declared capability with MUTATE
    ; or change the production publicity KAT/inventory. Dispatch and routing
    ; apply the additional session restriction before a handler can execute.
    test rsi, rsi
    jnz  .declared
%if PAOS_PUBLICITY_LAB_PROFILE
    ; Exact lab-only diagnostic exception. The live row remains destructive=1;
    ; shipped bytes omit this exception and do not register SESSIONPROBE.
    cmp  dword [rdi], 'SESS'
    jne  .not_sessionprobe
    cmp  dword [rdi + 4], 'IONP'
    jne  .not_sessionprobe
    cmp  dword [rdi + 8], 'ROBE'
    jne  .not_sessionprobe
    cmp  byte [rdi + 12], 0
    je   .public
.not_sessionprobe:
%endif
    test rdx, rdx
    jnz  .boot_check
    ; BOOTCLOCK: bounded public clock facts only. Both metadata checks above
    ; remain authoritative; prefixes/suffixes and destructive/capped rows refuse.
    cmp dword [rdi], 'BOOT'
    jne .not_bootclock
    cmp dword [rdi + 4], 'CLOC'
    jne .not_bootclock
    cmp byte [rdi + 8], 'K'
    jne .not_bootclock
    cmp byte [rdi + 9], 0
    je .public
.not_bootclock:
    ; IRQ0OBS exposes only a bounded first-boot ISR witness and public build/
    ; boot identity. Exact name only; cap/destructive metadata still dominate.
    cmp dword [rdi], 'IRQ0'
    jne .not_irq0obs
    cmp word [rdi + 4], 'OB'
    jne .not_irq0obs
    cmp byte [rdi + 6], 'S'
    jne .not_irq0obs
    cmp byte [rdi + 7], 0
    je .public
.not_irq0obs:
    ; 3305: nonce-only compiled synthetic matrix, public in both postures.
    ; The cap=0/destr=0 checks above remain authoritative.
    cmp  dword [rdi], 'PRIV'
    jne  .not_privacytest
    cmp  dword [rdi + 4], 'ACYT'
    jne  .not_privacytest
    cmp  word [rdi + 8], 'ES'
    jne  .not_privacytest
    cmp  byte [rdi + 10], 'T'
    jne  .not_privacytest
    cmp  byte [rdi + 11], 0
    je   .public
.not_privacytest:
%if PAOS_PUBLICITY_LAB_PROFILE
    ; Task1059 HTTP client public floor. The probe drives HTTPGET/HTTPSTAT/
    ; HTTPBODY over UNSIGNED UDP; each is registered cap=0/destr=0, so the
    ; exact-name grant here keeps them on the public read floor (fails closed if
    ; a later rung raises either metadata field). Dword-compares like STATUS.
    ; SEC-P1: lab only. Unsigned HTTPGET opens a TCP connection to a caller-chosen
    ; host:port once a pin is provisioned (RCQ-39-Fc: it refuses while the pin is
    ; unset or another owner holds the TLS session); HTTPBODY returns the last
    ; fetched body.
    cmp  dword [rdi], 'HTTP'
    jne  .status
    cmp  dword [rdi + 4], 'GET'          ; HTTPGET + NUL
    je   .public
    cmp  dword [rdi + 4], 'STAT'         ; HTTPSTAT...
    jne  .http_body
    cmp  byte [rdi + 8], 0
    je   .public
.http_body:
    cmp  dword [rdi + 4], 'BODY'         ; HTTPBODY...
    jne  .status
    cmp  byte [rdi + 8], 0
    je   .public
%endif
.status:
    ; STATUS
    cmp  dword [rdi], 'STAT'
    jne  .srvstat
    cmp  word [rdi + 4], 'US'
    jne  .observation_floor
    cmp  byte [rdi + 6], 0
    je   .public
.srvstat:
    ; Task3040: only the exact read-only registry spelling is public. Preserve
    ; the cap=0/destr=0 checks above and reject SRVSTATX/prefix aliases.
    cmp  dword [rdi], 'SRVS'
    jne  .ping
    cmp  word [rdi + 4], 'TA'
    jne  .observation_floor
    cmp  byte [rdi + 6], 'T'
    jne  .observation_floor
    cmp  byte [rdi + 7], 0
    je   .public
.ping:
    cmp  dword [rdi], 'PING'
    jne  .help
    cmp  byte [rdi + 4], 0
    je   .public
.help:
    cmp  dword [rdi], 'HELP'
    jne  .catalog
    cmp  byte [rdi + 4], 0
    je   .public
.catalog:
    cmp  dword [rdi], 'CATA'
    jne  .authstat
    cmp  word [rdi + 4], 'LO'
    jne  .observation_floor
    cmp  byte [rdi + 6], 'G'
    jne  .observation_floor
    cmp  byte [rdi + 7], 0
    je   .public
.authstat:
    cmp  dword [rdi], 'AUTH'
    jne  .filmstrip
    cmp  dword [rdi + 4], 'STAT'
    jne  .authverbs
    cmp  byte [rdi + 8], 0
    je   .public
.authverbs:
    ; AUTHVERBS: AUTHSTAT's census sibling, public only as the exact spelling.
    cmp  dword [rdi + 4], 'VERB'
    jne  .filmstrip
    cmp  byte [rdi + 8], 'S'
    jne  .filmstrip
    cmp  byte [rdi + 9], 0
    je   .public
.filmstrip:
    ; WALLPAPER's empty-argument query is public. Its handler gates every
    ; nonempty argument through command_auth_gate before parsing/binding.
    cmp  dword [rdi], 'WALL'
    jne  .filmstrip_name
    cmp  dword [rdi + 4], 'PAPE'
    jne  .filmstrip_name
    cmp  byte [rdi + 8], 'R'
    jne  .filmstrip_name
    cmp  byte [rdi + 9], 0
    je   .public
.filmstrip_name:
%if PAOS_PUBLICITY_LAB_PROFILE
    ; Task2302a: FILMSTRIP is public only as the exact NUL-terminated
    ; registry spelling. The cap=0/destr=0 gates above stay authoritative,
    ; so tightened metadata automatically removes this grant.
    ; SEC-P1: lab only. FILMSTRIP GET streams ~263 KB of boot frames to the
    ; request's source address (a reflector) and stalls the receive path.
    cmp  dword [rdi], 'FILM'
    jne  .secureboot
    cmp  dword [rdi + 4], 'STRI'
    jne  .secureboot
    cmp  byte [rdi + 8], 'P'
    jne  .secureboot
    cmp  byte [rdi + 9], 0
    je   .public
%endif
.secureboot:
    cmp  dword [rdi], 'SECU'
    jne  .r0stat
    cmp  dword [rdi + 4], 'REBO'
    jne  .r0stat
    cmp  word [rdi + 8], 'OT'
    jne  .r0stat
    cmp  byte [rdi + 10], 0
    je   .public
.r0stat:
    ; Rescue-0 R0-0: exact read-only spelling of the pre-EBS SNP record. The
    ; cap=0/destr=0 metadata gates above still take precedence over this grant.
    cmp  dword [rdi], 'R0ST'
    jne  .compat
    cmp  word [rdi + 4], 'AT'
    jne  .compat
    cmp  byte [rdi + 6], 0
    je   .public
.compat:
    ; 2908: exact public read-only spelling. The capability/destructive
    ; metadata gates above still take precedence over this grant.
    cmp  dword [rdi], 'COMP'
    jne  .clipinfo
    cmp  word [rdi + 4], 'AT'
    jne  .clipinfo
    cmp  byte [rdi + 6], 0
    je   .public
.clipinfo:
    ; Metadata only: no inline bytes and no slot-14 handle value. This exact
    ; spelling is public; CLIPGET remains protected by its declared slot 20.
    cmp  dword [rdi], 'CLIP'
    jne  .sessioninfo
    cmp  dword [rdi + 4], 'INFO'
    jne  .sessioninfo
    cmp  byte [rdi + 8], 0
    je   .public
.sessioninfo:
    ; PUSHAUTH publishes only status; its handler gates every other operation
    ; with CMD_AUTH_CAP_MUTATE, including malformed tokens (like WALLPAPER).
    cmp dword [rdi], 'PUSH'
    jne .pushauth_done
    cmp dword [rdi + 4], 'AUTH'
    jne .pushauth_done
    cmp byte [rdi + 8], 0
    je .public
.pushauth_done:
    cmp  dword [rdi], 'LOCK'
    jne  .sessioninfo_name
    cmp  dword [rdi + 4], 'STAT'
    jne  .sessioninfo_name
    cmp  word [rdi + 8], 'E'
    je   .public
.sessioninfo_name:
    cmp  dword [rdi], 'SESS'
    jne  .chartread
    cmp  dword [rdi + 4], 'IONI'
    jne  .chartread
    cmp  word [rdi + 8], 'NF'
    jne  .chartread
    cmp  byte [rdi + 10], 'O'
    jne  .chartread
    cmp  byte [rdi + 11], 0
    je   .public
.chartread:
    ; RCQ-15: HOOK is public only as the exact spelling, like WALLPAPER. Its own
    ; effect is none: every edge op is dispatched as the edge's native verb, whose
    ; gate then consumes this request's ticket, and EVENTS (the one hook-owned
    ; read) runs this gate in its handler, as WALLPAPER does. The metadata checks
    ; above stay authoritative, so a destructive or capped HOOK row loses this grant.
    cmp  dword [rdi], 'HOOK'
    jne  .chartread_name
    cmp  byte [rdi + 4], 0
    je   .public
.chartread_name:
    ; GK1-6: numeric chart state is public T0. Metadata checks above remain
    ; authoritative; CHARTPUSH declares MUTATE and can never reach this grant.
    cmp  dword [rdi], 'CHAR'
    jne  .observation_floor
    cmp  dword [rdi + 4], 'TREA'
    jne  .observation_floor
    cmp  byte [rdi + 8], 'D'
    jne  .observation_floor
    cmp  byte [rdi + 9], 0
    je   .public
.observation_floor:
    ; This replaces command_dispatch's former side bypass: the mux now feeds
    ; the same classifier used by dispatch and AUTHSTAT. Preserve the name
    ; because the mux performs a live cap/destr registry lookup on a match.
    push rdi
    call command_guestcpu_public_observation
    pop  rdi
    test eax, eax
    jnz  .public
%if PAOS_PUBLICITY_LAB_PROFILE
.ai_probe:
    ; AUTHAIPROBE remains a lab-only, bounded in-process gate receipt.
    cmp  dword [rdi], 'AUTH'
    jne  .tlsstat
    cmp  dword [rdi + 4], 'AIPR'
    jne  .tlsstat
    cmp  word [rdi + 8], 'OB'
    jne  .tlsstat
    cmp  byte [rdi + 10], 'E'
    jne  .tlsstat
    cmp  byte [rdi + 11], 0
    je   .public
.tlsstat:
    ; TLSSTAT/TLSKAT expose only bounded, retained diagnostic state.  Keep
    ; TLSCONNECT out of this exact floor: opening a peer is a PMCAP_NET action.
    cmp  dword [rdi], 'TLSS'
    jne  .tlskat
    cmp  word [rdi + 4], 'TA'
    jne  .gui_t0_check
    cmp  byte [rdi + 6], 'T'
    jne  .gui_t0_check
    cmp  byte [rdi + 7], 0
    je   .public
.tlskat:
    cmp  dword [rdi], 'TLSK'
    jne  .gui_t0_check
    cmp  word [rdi + 4], 'AT'
    jne  .gui_t0_check
    cmp  byte [rdi + 6], 0
    je   .public
.gui_t0_check:
    ; Publicity is earned from the live registry declaration: both capability
    ; and destructiveness must be zero, then the exact T0 read name must match.
    ; A later rung that changes either metadata field automatically fails closed.
    call command_auth_is_gui_t0_read
    test eax, eax
    jnz  .public
    call command_auth_is_fs_t0_read
    test eax, eax
    jnz  .public
%endif
.boot_check:
    cmp  dword [rdi], 'BOOT'
    jne  .effect_class
    cmp  byte [rdi + 4], 0
    je   .boot
.effect_class:
    ; Existing subsystem capability bits remain the exact least-authority
    ; scope where legacy registrations omitted them.  Destructiveness is
    ; required as well, so BLKINFO/BLKREAD/PCISCAN do not inherit a write cap
    ; merely because of their names (they remain protected by the generic
    ; remote floor, but never become public accidentally).
    test rdx, rdx
    jz   .generic
    cmp  word [rdi], 'BL'
    jne  .pci_check
    cmp  byte [rdi + 2], 'K'
    je   .block
.pci_check:
    cmp  word [rdi], 'PC'
    jne  .generic
    cmp  byte [rdi + 2], 'I'
    je   .mmio
.generic:
    mov  rax, CMD_AUTH_CAP_MUTATE
    ret
.boot:
    mov  rax, CMD_AUTH_CAP_BOOT
    ret
.block:
    mov  rax, PMCAP_BLOCK_WRITE
    ret
.mmio:
    mov  rax, PMCAP_MMIO
    ret
.declared:
    mov  rax, rsi
    ret
.public:
    xor  eax, eax
    ret

; command_auth_is_gui_t0_read(RDI=registered verb name) -> EAX=1 exact match.
; Historical symbol name retained; this is the registry-backed lab read set,
; not a transport/probe bypass. The shipped classifier never calls it.
command_auth_is_gui_t0_read:
    cmp  dword [rdi], 'BOOT'
    jne  .diagring
    cmp  dword [rdi + 4], 'LOG'
    je   .yes
.diagring:
    cmp  dword [rdi], 'DIAG'
    jne  .webstruct
    cmp  dword [rdi + 4], 'RING'
    jne  .webstruct
    cmp  byte [rdi + 8], 0
    je   .yes
.webstruct:
    cmp  dword [rdi], 'WEBS'
    jne  .winchrome
    cmp  dword [rdi + 4], 'TRUC'
    jne  .no
    cmp  byte [rdi + 8], 'T'
    jne  .no
    cmp  byte [rdi + 9], 0
    je   .yes
.winchrome:
    cmp  dword [rdi], 'WINC'
    jne  .wintree
    cmp  dword [rdi + 4], 'HROM'
    jne  .no
    cmp  word [rdi + 8], 'E'
    je   .yes
.wintree:
    cmp  dword [rdi], 'WINT'
    jne  .treecheck
    cmp  dword [rdi + 4], 'REE'
    je   .yes
.treecheck:
    cmp  dword [rdi], 'TREE'
    jne  .taskbar
    cmp  dword [rdi + 4], 'CHEC'
    jne  .taskbar
    cmp  byte [rdi + 8], 'K'
    jne  .taskbar
    cmp  byte [rdi + 9], 0
    je   .yes
.taskbar:
    cmp  dword [rdi], 'TASK'
    jne  .formlist
    cmp  dword [rdi + 4], 'BAR'
    je   .yes
.formlist:
    cmp  dword [rdi], 'FORM'
    jne  .cadence
    cmp  dword [rdi + 4], 'LIST'
    jne  .forminfo
    cmp  byte [rdi + 8], 0
    je   .yes
.forminfo:
    cmp  dword [rdi + 4], 'INFO'
    jne  .no
    cmp  byte [rdi + 8], 0
    je   .yes
    jmp  .no
.cadence:
    cmp  dword [rdi], 'CADE'
    jne  .cadmark
    cmp  dword [rdi + 4], 'NCE'
    je   .yes
.cadmark:
    cmp  dword [rdi], 'CADM'
    jne  .cadstat
    cmp  word [rdi + 4], 'AR'
    jne  .no
    cmp  byte [rdi + 6], 'K'
    jne  .no
    cmp  byte [rdi + 7], 0
    je   .yes
.cadstat:
    cmp  dword [rdi], 'CADS'
    jne  .resinfo
    cmp  word [rdi + 4], 'TA'
    jne  .no
    cmp  byte [rdi + 6], 'T'
    jne  .no
    cmp  byte [rdi + 7], 0
    je   .yes
.resinfo:
    cmp  dword [rdi], 'RESI'
    jne  .gophealth
    cmp  dword [rdi + 4], 'NFO'
    je   .yes
.gophealth:
    ; 1249 P53: GOPHEALTH is a bounded read of boot-time self-detection facts.
    cmp  dword [rdi], 'GOPH'
    jne  .wingeom
    cmp  dword [rdi + 4], 'EALT'
    jne  .no
    cmp  byte [rdi + 8], 'H'
    jne  .no
    cmp  byte [rdi + 9], 0
    je   .yes
.wingeom:
    cmp  dword [rdi], 'WING'
    jne  .windows
    cmp  dword [rdi + 4], 'EOM'
    je   .yes
.windows:
    cmp  dword [rdi], 'WIND'
    jne  .focused
    cmp  dword [rdi + 4], 'OWS'
    je   .yes
.focused:
    cmp  dword [rdi], 'FOCU'
    jne  .widget
    cmp  dword [rdi + 4], 'SED'
    je   .yes
.widget:
    cmp  dword [rdi], 'WIDG'
    jne  .image
    cmp  dword [rdi + 4], 'ETGE'
    jne  .widget_list
    cmp  word [rdi + 8], 'T'
    je   .yes
.widget_list:
    cmp  dword [rdi + 4], 'ETLI'
    jne  .widget_types
    cmp  word [rdi + 8], 'ST'
    jne  .widget_types
    cmp  byte [rdi + 10], 0
    je   .yes
.widget_types:
    cmp  dword [rdi + 4], 'ETTY'
    jne  .image
    cmp  dword [rdi + 8], 'PES'
    je   .yes
.image:
    cmp  dword [rdi], 'IMGL'
    jne  .imginfo
    cmp  word [rdi + 4], 'IS'
    jne  .no
    cmp  byte [rdi + 6], 'T'
    jne  .no
    cmp  byte [rdi + 7], 0
    je   .yes
.imginfo:
    cmp  dword [rdi], 'IMGI'
    jne  .imgdec
    cmp  word [rdi + 4], 'NF'
    jne  .no
    cmp  byte [rdi + 6], 'O'
    jne  .no
    cmp  byte [rdi + 7], 0
    je   .yes
.imgdec:
    cmp  dword [rdi], 'IMGD'
    jne  .imgcache
    cmp  word [rdi + 4], 'EC'
    jne  .no
    cmp  byte [rdi + 6], 0
    je   .yes
.imgcache:
    cmp  dword [rdi], 'IMGC'
    jne  .no
    cmp  dword [rdi + 4], 'ACHE'
    jne  .no
    cmp  byte [rdi + 8], 0
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Exact Task2400 lab read set. cap=0/destr=0 metadata alone may never publish a
; spelling, and tightened metadata is still rejected above.
command_auth_is_fs_t0_read:
    cmp  dword [rdi], 'FSIN'
    jne  .fsls
    cmp  word [rdi + 4], 'FO'
    jne  .no
    cmp  byte [rdi + 6], 0
    je   .yes
.fsls:
    cmp  dword [rdi], 'FSLS'
    jne  .fsstat
    cmp  byte [rdi + 4], 0
    je   .yes
.fsstat:
    cmp  dword [rdi], 'FSST'
    jne  .fsread
    cmp  word [rdi + 4], 'AT'
    jne  .no
    cmp  byte [rdi + 6], 0
    je   .yes
.fsread:
    cmp  dword [rdi], 'FSRE'
    jne  .fshash
    cmp  word [rdi + 4], 'AD'
    jne  .no
    cmp  byte [rdi + 6], 0
    je   .yes
.fshash:
    cmp  dword [rdi], 'FSHA'
    jne  .fssel
    cmp  word [rdi + 4], 'SH'
    jne  .no
    cmp  byte [rdi + 6], 0
    je   .yes
.fssel:
    ; FSSEL re-routes the FS read verbs to a named mount (fat32 / ntfs0): no I/O, no
    ; mutation — the same lab read floor as FSINFO.
    cmp  dword [rdi], 'FSSE'
    jne  .fscd
    cmp  byte [rdi + 4], 'L'
    jne  .no
    cmp  byte [rdi + 5], 0
    je   .yes
.fscd:
    ; FSCD <path> sets the Explorer's directory: GUI view state, no I/O at verb time.
    cmp  dword [rdi], 'FSCD'
    jne  .fswrite_test
    cmp  byte [rdi + 4], 0
    je   .yes
.fswrite_test:
%ifdef PAOS_NTFS_UNSIGNED_TEST
    ; QEMU ORACLE ONLY: QEMU has no durable store, so the signed path cannot commit there.
    ; A shipped build never defines this; FSWRITE stays a signed mutator.
    cmp  dword [rdi], 'FSWR'
    jne  .partls
    cmp  word [rdi + 4], 'IT'
    jne  .no
    cmp  byte [rdi + 6], 'E'
    jne  .no
    cmp  byte [rdi + 7], 0
    je   .yes
%endif
.partls:
    cmp  dword [rdi], 'PART'
    jne  .no
    cmp  word [rdi + 4], 'LS'
    jne  .no
    cmp  byte [rdi + 6], 0
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Called by command_dispatch.  Internal kernel calls are trusted; every remote
; call is bound to the verified ticket installed by its projection.
command_auth_gate:
    push rdi
    push rsi
    mov  rdi, rsi
    call command_session_name_allowed
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .session_allowed
    jmp  command_session_refuse
.session_allowed:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .internal
    mov  rdx, rsi
    mov  rsi, rdi
    mov  rdi, [rel command_auth_remote_ticket]
    jmp  command_auth_authorize
.internal:
    xor  eax, eax
    ret

; GUI binds policy/presentation callbacks downward at the boot session boundary.
; They consult sec/session; this transport never owns another locked flag.
command_session_name_allowed:
    ; ONE service-agnostic network-access gate (PETER RULING 2026-09-29 20:54/20:57): an AUTHENTICATED remote
    ; request (verified AUTH1 ticket in flight) is admitted by its own authentication, whenever PaOS runs and
    ; regardless of the local console lock, unless the account's network policy blocks it. Its per-verb
    ; capability/authority check (command_auth_authorize) still applies, and desktop-surface handlers keep their
    ; own local-session checks, so the local desktop stays locked. Unauthenticated/local callers fall through to
    ; the unchanged console-lock rules below. Future servers (SSH exec, file server) call net_access_gate too.
    ; RCQ-40 G7 (rc-sec ruling 2026-10-10 02:45:34, the account policy that ruling names): while the session is
    ; locked, only an OWNER ticket is admitted by its authentication. Any other authenticated principal (the AI
    ; operator's SYSTEM ticket, remote or the in-image aihook) gets the console-lock rules, as a local frame does.
    push rdi
    mov  esi, NET_SVC_AUTH1
    call net_access_gate
    pop  rdi
    cmp  eax, NET_GATE_ADMIT
    jne  .not_admitted
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    je   .push_allowed
    mov  rax, [rel command_auth_remote_ticket]
    cmp  qword [rax + AUTH_T_PRINCIPAL], PRIN_OWNER
    je   .push_allowed
    jmp  .console_rules
.not_admitted:
    cmp  eax, NET_GATE_BLOCKED
    je   .blocked
.console_rules:
    ; GK1-6: CHARTREAD remains an exact public-T0 observation while the
    ; desktop session is locked. Keep the live registry authoritative: a
    ; later cap/destructiveness increase closes this admission automatically.
    cmp  dword [rdi], 'CHAR'
    jne  .push_auth
    cmp  dword [rdi + 4], 'TREA'
    jne  .push_auth
    cmp  byte [rdi + 8], 'D'
    jne  .push_auth
    cmp  byte [rdi + 9], 0
    jne  .push_auth
    push rdi
    call command_auth_registry_name_is_public
    pop  rdi
    test eax, eax
    jnz  .push_allowed
.push_auth:
%if !PAOS_PUBLIC_BUILD
    push rdi
    call push_auth_name_allowed
    pop rdi
    test eax, eax
    jnz .push_allowed
%endif
    mov  rax, [rel command_session_allow_op]
    test rax, rax
    jz   .unbound
    jmp  rax
.unbound:
.push_allowed:
    mov  eax, 1
    ret
.blocked:
    xor  eax, eax
    ret

NET_GATE_NOT_AUTHENTICATED equ 0
NET_GATE_ADMIT             equ 1
NET_GATE_BLOCKED           equ 2
NET_SVC_AUTH1              equ 1      ; AUTH1-signed UDP/serial commands
NET_SVC_SSH                equ 2      ; SSH exec (rungs 2142/2143): AUTH_TS_SSH tickets

; net_access_gate(ESI=service id) -> EAX NET_GATE_*. Reads the in-flight request's ticket; never the local
; session. Counts every decision (audit counters; the command audit ring records the command text).
net_access_gate:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .not_auth
    mov  rdx, [rel command_auth_remote_ticket]
    test rdx, rdx
    jz   .not_auth
    mov  rdi, [rdx + AUTH_T_PRINCIPAL]
    test rdi, rdi
    jz   .not_auth
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_SSH
    jne  .injected
    mov  esi, NET_SVC_SSH                   ; the service is the ticket's, never the caller's claim
    jmp  .authenticated
.injected:
    ; GA0-K: an injected line is admitted under the service of the request that
    ; typed it (keyprov records that source in AUTH_T_SEQ).
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_INJECTED
    jne  .auth1
    mov  esi, NET_SVC_AUTH1
    cmp  qword [rdx + AUTH_T_SEQ], CMD_SOURCE_SSH
    jne  .authenticated
    mov  esi, NET_SVC_SSH
    jmp  .authenticated
.auth1:
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_VALID
    je   .authenticated
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_CONSUMED
    jne  .not_auth
.authenticated:
    call net_access_policy_allows           ; RDI=principal, ESI=service
    test eax, eax
    jz   .blocked
    inc  qword [rel net_access_admitted]
    mov  eax, NET_GATE_ADMIT
    ret
.blocked:
    inc  qword [rel net_access_blocked]
    mov  byte [rel net_access_last_blocked], 1   ; the audit row says res=blocked, not refused
    mov  eax, NET_GATE_BLOCKED
    ret
.not_auth:
    xor  eax, eax
    ret

; net_access_policy_allows(RDI=principal, ESI=service) -> EAX 1 allow / 0 blocked.
; HOOK for the per-account network-access policy that SUPERIOR accounts manage (ruling 20:57). No account
; hierarchy or signed policy record exists yet (planner/Guardian saga): documented default = an authenticated
; principal may use the services its credentials authorize.
net_access_policy_allows:
    mov  eax, 1
    ret

; ---------------------------------------------------------------------------
; Network-access gate rule 3 (audit): helpers the transports (svc/command_udp,
; svc/ssh_channel) use to describe ONE remote attempt to audit_log_net.
; ---------------------------------------------------------------------------
NET_AUDIT_TOK_MAX equ 64

; net_audit_verb_name(RDI = verb token or whole command line, or 0) -> RAX =
;   the CANONICAL name the first token resolves to (a declared intercept, in
;   command_auth_route_gate order, else the live registry), "?" for a token no
;   route declares, "-" for none. Never returns caller bytes: the verb field of
;   an audit row cannot carry an argument, a credential or attacker free text.
;   clobbers: caller-saved (RBX,R12 preserved).
net_audit_verb_name:
    push rbx
    push r12
    test rdi, rdi
    jz   .none
    lea  rsi, [rel net_audit_tok]
    xor  ecx, ecx
.copy:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .term
    cmp  eax, ' '
    je   .term
    cmp  ecx, NET_AUDIT_TOK_MAX - 1
    jae  .unknown                       ; longer than any declared route
    mov  [rsi + rcx], al
    inc  ecx
    jmp  .copy
.term:
    mov  byte [rsi + rcx], 0
    test ecx, ecx
    jz   .none
    lea  r12, [rel command_auth_intercepts]
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel command_auth_intercept_count]
    jae  .registry
    cmp  qword [r12 + AUTH_INT_MATCH], AUTH_MATCH_PREFIX
    je   .prefix
    mov  rdi, [r12 + AUTH_INT_NAME]
    lea  rsi, [rel net_audit_tok]
    call strcmp
    test eax, eax
    jz   .matched
    jmp  .next
.prefix:
    lea  rdi, [rel net_audit_tok]
    mov  rsi, [r12 + AUTH_INT_NAME]
    mov  rdx, [r12 + AUTH_INT_LEN]
    call command_auth_prefix_equal
    test eax, eax
    jnz  .matched
.next:
    add  r12, AUTH_INT_SIZE
    inc  ebx
    jmp  .scan
.matched:
    mov  rax, [r12 + AUTH_INT_NAME]
    jmp  .out
.registry:
    lea  rdi, [rel net_audit_tok]
    call command_lookup
    cmp  eax, -1
    je   .unknown
    mov  edi, eax
    call command_verb_name
    jmp  .out
.unknown:
    lea  rax, [rel str_net_audit_unknown]
    jmp  .out
.none:
    lea  rax, [rel str_net_audit_none]
.out:
    push rax                            ; the scratch held caller bytes: wipe it whole
    lea  rdi, [rel net_audit_tok]
    xor  esi, esi
    mov  edx, NET_AUDIT_TOK_MAX
    call memset
    pop  rax
    pop  r12
    pop  rbx
    ret

; net_audit_reason_name(EDI = AUTHR_*) -> RAX = compact row reason cstr.
;   clobbers: RAX.
net_audit_reason_name:
    lea  rax, [rel str_auth_reason_unsigned]
    cmp  edi, AUTHR_UNSIGNED
    je   .out
    lea  rax, [rel str_auth_reason_malformed]
    cmp  edi, AUTHR_MALFORMED
    je   .out
    lea  rax, [rel str_auth_reason_wrong_key]
    cmp  edi, AUTHR_WRONG_KEY
    je   .out
    lea  rax, [rel str_auth_reason_expired]
    cmp  edi, AUTHR_EXPIRED
    je   .out
    lea  rax, [rel str_net_audit_wrong_cap]
    cmp  edi, AUTHR_WRONG_CAP
    je   .out
    lea  rax, [rel str_auth_reason_replay]
    cmp  edi, AUTHR_REPLAY
    je   .out
    lea  rax, [rel str_net_audit_durable]
    cmp  edi, AUTHR_DURABLE
    je   .out
    lea  rax, [rel str_net_audit_capability]
    cmp  edi, AUTHR_PRINCIPAL
    je   .out
    lea  rax, [rel str_auth_reason_desktop_locked]
    cmp  edi, AUTHR_DESKTOP_LOCKED
    je   .out
    lea  rax, [rel str_net_audit_unknown_verb]
    cmp  edi, AUTHR_UNKNOWN
    je   .out
    lea  rax, [rel str_auth_reason_auth1_retired]
    cmp  edi, AUTHR_AUTH1_RETIRED
    je   .out
    lea  rax, [rel str_auth_reason_wrong_node]
    cmp  edi, AUTHR_WRONG_NODE
    je   .out
    lea  rax, [rel str_auth_reason_card_required]
    cmp  edi, AUTHR_CARD_REQUIRED
    je   .out
    lea  rax, [rel str_net_audit_refused]
.out:
    ret

; net_audit_refusal_meta -> EAX = AUDIT_NRES_BLOCKED (the account's network
;   policy blocked an authenticated principal) or AUDIT_NRES_REFUSED, RDX = the
;   reason cstr for the refusal the in-flight request just staged.
;   clobbers: RAX,RDX,RDI.
net_audit_refusal_meta:
    cmp  byte [rel net_access_last_blocked], 1
    je   .blocked
    movzx edi, byte [rel command_auth_last_reason]
    call net_audit_reason_name
    mov  rdx, rax
    mov  eax, AUDIT_NRES_REFUSED
    ret
.blocked:
    lea  rdx, [rel str_net_audit_policy]
    mov  eax, AUDIT_NRES_BLOCKED
    ret

; command_auth_owner_request -> EAX: 0 = the in-flight request carries no
; owner authority for a credential verb (AUTHLOGIN / PUSHAUTH), 1 = its OWN
; AUTH1 ticket (UDP, serial or aihook projection) was consumed by the gate for
; THIS request and names OWNER, 2 = SSH exec bound to OWNER through an
; UNRESTRICTED enrolled key.
; Every projection is judged ONLY by the ticket it registered with
; command_auth_remote_begin (security scan F4, CWE-863): a stale AUTH1 ticket
; left by an earlier datagram can never lend owner authority to another
; request, a ticket the gate did not consume never counts, and with no remote
; request in flight there is no remote owner authority at all. A
; capability-restricted SSH key never reaches a credential verb's effect.
; Clobbers RAX, RDX.
command_auth_owner_request:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .none
    mov  rdx, [rel command_auth_remote_ticket]
    test rdx, rdx
    jz   .none
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_SSH
    je   .ssh
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_CONSUMED
    jne  .none
    cmp  qword [rdx + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .none
    mov  eax, 1
    ret
.ssh:
    cmp  qword [rdx + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .none
    cmp  qword [rdx + AUTH_T_CAP], -1
    jne  .none
    mov  eax, 2
    ret
.none:
    xor  eax, eax
    ret

; command_auth_owner_envelope -> EAX 1 when the in-flight remote request
; arrived inside its OWN verified owner envelope, else 0. Unlike
; command_auth_owner_request this does not need the gate to have consumed the
; ticket: public-floor reads (STATUS) never reach the gate, yet a reply may
; carry owner-only projections when the request itself was signed by the owner.
; Criterion = command_auth_remote_begin's owner intent: this request's ticket
; (never a stale one: begin/end bracket it) is AUTH_TS_VALID or AUTH_TS_CONSUMED
; with PRIN_OWNER, or AUTH_TS_SSH with PRIN_OWNER and an unrestricted key.
; Uses: owner-only read projections (RCQ-27 power fields) and lifting a public
; verb's unsigned resource bound (SEC-P2b SMPBENCH: a replayed START re-submits
; the same nonce, and slots are keyed by nonce, so a replay cannot amplify).
; An unconsumed VALID envelope can be replayed until it expires, so never gate an
; effect with it (effects keep command_auth_owner_request / the gate). Clobbers RAX, RDX.
command_auth_owner_envelope:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .none
    mov  rdx, [rel command_auth_remote_ticket]
    test rdx, rdx
    jz   .none
    cmp  qword [rdx + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .none
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_VALID
    je   .yes
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_CONSUMED
    je   .yes
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_SSH
    jne  .none
    cmp  qword [rdx + AUTH_T_CAP], -1
    jne  .none
.yes:
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; command_auth_injection_gate(RDI=verb name) -> EAX 0 proceed / -1 refused.
; Remote KBINJ/MOUSEINJ/PTRINJ/TERMFEED while the local console is LOCKED can type or
; click into the lock screen. That is a TEST instrument, never a human and
; never a remote unlock (ADMIN 2026-09-30 06:22):
;   shipped floor -> refused `desktop_locked` (CMDE_DESKTOP_LOCKED), zero effect;
;   lab/dev floor -> admitted, and sec/session is tainted so an unlock that the
;                    injected input produces is audited `UNLOCK test_only`.
; Local/in-image callers and an unlocked console are untouched.
command_auth_injection_gate:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .allow
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .allow
    lea  rsi, [rel command_auth_injection_names]
.scan:
    cmp  byte [rsi], 0
    je   .allow
    push rdi
    push rsi
    call strcmp
    pop  rsi
    pop  rdi
    test eax, eax
    jz   .injection
.skip:
    inc  rsi
    cmp  byte [rsi - 1], 0
    jne  .skip
    jmp  .scan
.injection:
%if PAOS_PUBLICITY_LAB_PROFILE
    mov  byte [rel session_injected_input], 1
    inc  qword [rel command_auth_injection_test_only]
.allow:
    xor  eax, eax
    ret
%else
    inc  qword [rel command_auth_injection_refused]
    mov  rsi, rdi
    mov  edi, AUTHR_DESKTOP_LOCKED
    mov  rdx, [rel command_auth_remote_ticket]
    xor  ecx, ecx
    call command_auth_refuse
    mov  eax, -1
    ret
.allow:
    xor  eax, eax
    ret
%endif

command_auth_injection_names:
    db "KBINJ",0,"MOUSEINJ",0,"PTRINJ",0,"TERMFEED",0,0   ; GA0-K: TERMFEED @KEY types like KBINJ

align 8
net_access_admitted: dq 0
net_access_blocked:  dq 0
command_auth_ssh_accept_count: dq 0
command_auth_injected_accept_count: dq 0
command_auth_injection_test_only: dq 0
command_auth_injection_refused:   dq 0
; 1 only while an SSH exec is inside dispatch (request source attribution for
; the unlock audit record; sec/session's remote-unlock rule covers every
; remote transport through command_auth_remote_active).
command_auth_ssh_active: db 0
; 1 only while a transport runs its post-reply presentation sync
; (command_session_sync_op). That sync may consume a credential typed at the
; LOCAL lock screen; it is not the remote request's own authority.
command_session_sync_active: db 0
align 8

; RDI=required cap, RSI=verb. The ordinary auth refusal serializer owns output.
command_session_refuse:
    mov  rcx, rdi
    mov  edi, AUTHR_PRINCIPAL
    mov  rdx, [rel command_auth_remote_ticket]
    call command_auth_refuse
    mov  eax, -1
    ret

command_session_allow_op: dq 0
command_session_sync_op: dq 0
align 8
command_auth_unsigned_ticket: times AUTH_T_SIZE db 0   ; never written: an unsigned frame

; All external projections, including the local serial/console paths, enter
; the one registry through this session predicate. Registry internals and
; boot KATs retain their implementation; no second command table is created.
command_dispatch:
    push rdi
    push rsi
    mov  rax, [rdi + REQ_VERB]
    mov  ecx, [rel verb_count]
    cmp  rax, rcx
    jae  .registry
    imul rax, VERB_ENT_SZ
    lea  rdx, [rel verb_table]
    mov  rdi, [rdx + rax + VERB_NAME]
    test rdi, rdi
    jz   .registry                     ; the registry owns vacant-id refusal
    call command_session_name_allowed
    test eax, eax
    jnz  .registry
    pop  rsi
    pop  rdi
    mov  qword [rsi + RSP_CODE], CMDE_AUTHDENY
    mov  qword [rsi + RSP_ACCEPTED], 0
    mov  qword [rsi + RSP_JOBID], 0
    mov  qword [rsi + RSP_VAL], 0
    mov  qword [rsi + RSP_EXPECTED], 0
    lea  rax, [rel str_command_session_locked]
    mov  [rsi + RSP_HINT], rax
    mov  eax, CMDE_AUTHDENY
    ret
.registry:
    pop  rsi
    pop  rdi
    jmp  command_dispatch_registry
str_command_session_locked: db "session=locked",0

; command_auth_consume_public(RDI = req, RSI = verb name) -> EAX 0 continue, -1 refused.
;   SEC-authverbs-locked-floor F1 (root 2026-10-10 10:32:37): a public verb needs no
;   envelope, but a VALID UDP/serial envelope that admits one is still consumed, so
;   the verified sequence advances and a byte-identical replay gets AUTHR_REPLAY.
;   The scope compared is the ticket's own signed cap: a public verb requires none.
;   Unsigned requests, SSH, injected and in-image tickets are unchanged, as is a
;   ticket this request already consumed.
;   SEC-authverbs-hook-handoff (rc-ai 02:03:05): a public verb may gate inside (HOOK's nested native dispatch,
;   hook_owner_read, a handler's non-public forms). The admitted ticket is recorded with a hand-off armed, so
;   ONE inner gate of this same request is admitted at the exact signed cap, as before the floor consumed it.
command_auth_consume_public:
    mov  rax, [rdi + REQ_SOURCE]
    cmp  rax, CMD_SOURCE_UDP
    je   .wire
    cmp  rax, CMD_SOURCE_SERIAL
    jne  .pass
.wire:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .pass
    mov  rdi, [rel command_auth_remote_ticket]
    test rdi, rdi
    jz   .pass
    cmp  qword [rdi + AUTH_T_STATE], AUTH_TS_VALID
    jne  .pass
    mov  rdx, rsi
    mov  rsi, [rdi + AUTH_T_CAP]
    push rdi
    call command_auth_authorize
    pop  rdi
    test eax, eax
    jnz  .out
    mov  [rel command_auth_floor_ticket], rdi
    mov  byte [rel command_auth_floor_handoff], 1
.out:
    ret
.pass:
    xor  eax, eax
    ret

; command_auth_authorize(ticket, required_cap, verb) -- exact cap + live time +
; durable strictly-increasing sequence.  On any refusal no target mutation has
; run, and the generated receipt explicitly records mutation_effects=0.
command_auth_authorize:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test r12, r12
    jz   .unsigned
    movzx eax, byte [r12 + AUTH_T_STATE]
    test eax, eax
    jz   .unsigned
    cmp  eax, AUTH_TS_VALID
    je   .state_ok
    cmp  eax, AUTH_TS_WRONG_KEY
    je   .wrong_key
    cmp  eax, AUTH_TS_EXPIRED
    je   .expired
    cmp  eax, AUTH_TS_CONSUMED
    je   .consumed
    cmp  eax, AUTH_TS_GUEST
    je   .guest_principal
    cmp  eax, AUTH_TS_SSH
    je   .ssh_principal
    cmp  eax, AUTH_TS_INJECTED
    je   .injected_principal
    cmp  eax, AUTH_TS_RETIRED
    je   .retired
    cmp  eax, AUTH_TS_WRONG_NODE
    je   .wrong_node
    jmp  .malformed
.guest_principal:
    ; No static guest capability row, OWNER credential, or SSH projection.
    ; Only the adapter's exact in-flight native ticket can reach its grant hook.
    mov  rdi, [r12 + AUTH_T_PRINCIPAL]
    mov  rsi, r14
    call card_required_for
    test eax, eax
    jnz  .card_required
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call guest_request_authorize
    test eax, eax
    jnz  .principal_denied
    jmp  .out
.ssh_principal:
    ; The authority is the SSH-bound principal's own standing capability word,
    ; narrowed by the enrolled key's mask. The required word must be covered in
    ; full; the local console session is never consulted.
    mov  rdi, [r12 + AUTH_T_PRINCIPAL]
    test rdi, rdi
    jz   .unsigned
    cmp  rdi, PRIN_ADVISOR
    je   .principal_denied                ; GA2(b): never any verb, even cap 0
    mov  rsi, r14
    call card_required_for                ; RCQ-40 J6 (checklist s3.2): a card verb runs for a
    test eax, eax                         ; non-OWNER only through its confirmed card
    jnz  .card_required
    mov  rdi, [r12 + AUTH_T_PRINCIPAL]
    call principal_capabilities
    and  rax, [r12 + AUTH_T_CAP]
    and  rax, r13
    cmp  rax, r13
    jne  .principal_denied
    inc  qword [rel command_auth_ssh_accept_count]
    xor  eax, eax
    jmp  .out
.injected_principal:
    ; GA0-K: a line typed by a remote injection runs as the injecting
    ; principal: its standing capability word narrowed by the injecting
    ; ticket's mask must cover the required word in full. Never owner intent,
    ; never consumed (it is rebuilt per line by sec/keyprov).
    mov  rdi, [r12 + AUTH_T_PRINCIPAL]
    test rdi, rdi
    jz   .unsigned
    cmp  rdi, PRIN_ADVISOR
    je   .principal_denied
    mov  rsi, r14
    call card_required_for                ; RCQ-40 J6: an injected SYSTEM line, as any ticket
    test eax, eax
    jnz  .card_required
    mov  rdi, [r12 + AUTH_T_PRINCIPAL]
    call principal_capabilities
    and  rax, [r12 + AUTH_T_CAP]
    and  rax, r13
    cmp  rax, r13
    jne  .principal_denied
    inc  qword [rel command_auth_injected_accept_count]
    xor  eax, eax
    jmp  .out
.consumed:
    ; SEC-authverbs-hook-handoff: the ticket THIS request's public floor consumed admits ONE inner gate through
    ; every check below except the sequence step, which the floor already took and persisted for this exact
    ; ticket. Any other consumed ticket, or a second admission, is a replay. Disarmed only on admission: a
    ; refused inner gate leaves it for the next one, as an unconsumed ticket did before.
    cmp  r12, [rel command_auth_floor_ticket]
    jne  .replay
    cmp  byte [rel command_auth_floor_handoff], 1
    jne  .replay
    mov  byte [rel command_auth_handoff_now], 1
    jmp  .checks
.state_ok:
    mov  byte [rel command_auth_handoff_now], 0
.checks:
    ; GA2(b): the in-process advisor holds no verb authority at all. Refuse it
    ; first, whatever cap the verb needs (cap 0 included), before the ticket's
    ; sequence or time is looked at.
    cmp  qword [r12 + AUTH_T_PRINCIPAL], PRIN_ADVISOR
    je   .principal_denied
    mov  rdi, [r12 + AUTH_T_PRINCIPAL]
    mov  rsi, r14
    call card_required_for                ; RCQ-40 J6: before the cap compare, so no cap word opens it
    test eax, eax
    jnz  .card_required
    cmp  [r12 + AUTH_T_CAP], r13
    jne  .wrong_cap
    ; Preserve the already-proven owner path exactly once the byte-for-byte
    ; cap check succeeds.  Every non-owner (including unknown pid 0) must earn
    ; the requested word from the authoritative principal table.
    mov  rax, [r12 + AUTH_T_PRINCIPAL]
    cmp  rax, PRIN_OWNER
    je   .principal_ok
    mov  rdi, rax
    call principal_capabilities
    and  rax, r13
    cmp  rax, r13
    jne  .principal_denied
.principal_ok:
    mov  rdi, r12
    call command_auth_ticket_time_valid
    test eax, eax
    jz   .expired
    cmp  byte [rel command_auth_handoff_now], 1
    je   .handoff_admit
    call command_auth_lock_acquire
    mov  rax, [r12 + AUTH_T_SEQ]
    cmp  rax, [rel command_auth_last_sequence]
    jbe  .replay_locked
    ; H < q <= R: a verified reservation already covers q.  No firmware call.
    cmp  rax, [rel command_auth_reserved_through]
    jbe  .admit_locked
    ; q > R: reserve U = min(UINT64_MAX, q+SPAN-1, seal) durably before
    ; anything in it runs.  After a failed extension there is no retry this
    ; boot: q > R is refused (and so stays unexecuted) until a reboot reloads
    ; the record.  Nothing above this boot's committed floor window
    ; (sec/replay_floor): R itself never passes the seal, or a later q <= R
    ; would be admitted above F' without the seal check.
    cmp  rax, [rel command_auth_seal]
    ja   .durable_locked
    cmp  byte [rel command_auth_resv_state], AUTH_RESV_FAILED
    je   .durable_locked
    mov  rbx, rax
    add  rbx, AUTH_RESV_SPAN - 1
    jnc  .reserve
    mov  rbx, -1
.reserve:
    cmp  rbx, [rel command_auth_seal]
    jbe  .persist
    mov  rbx, [rel command_auth_seal]
.persist:
    mov  rdi, rbx
    call command_auth_replay_persist
    test eax, eax
    jnz  .durable_locked
    mov  [rel command_auth_reserved_through], rbx
.admit_locked:
    mov  rax, [r12 + AUTH_T_SEQ]
    mov  [rel command_auth_last_sequence], rax
    inc  qword [rel command_auth_accept_count]
    mov  byte [rel command_auth_durable_ready], 1
    mov  byte [r12 + AUTH_T_STATE], AUTH_TS_CONSUMED
    mov  byte [rel command_auth_floor_handoff], 0   ; an ordinary consumption leaves no hand-off armed
    call command_auth_lock_release
    xor  eax, eax
    jmp  .out
.handoff_admit:
    mov  byte [rel command_auth_handoff_now], 0
    mov  byte [rel command_auth_floor_handoff], 0
    xor  eax, eax
    jmp  .out
.replay_locked:
    call command_auth_lock_release
    mov  edi, AUTHR_REPLAY
    jmp  .refuse
.durable_locked:
    call command_auth_lock_release
    mov  edi, AUTHR_DURABLE
    jmp  .refuse
.unsigned:
    mov  edi, AUTHR_UNSIGNED
    jmp  .refuse
.malformed:
    mov  edi, AUTHR_MALFORMED
    jmp  .refuse
.wrong_key:
    mov  edi, AUTHR_WRONG_KEY
    jmp  .refuse
.expired:
    mov  edi, AUTHR_EXPIRED
    jmp  .refuse
.wrong_cap:
    mov  edi, AUTHR_WRONG_CAP
    jmp  .refuse
.principal_denied:
    mov  edi, AUTHR_PRINCIPAL
    jmp  .refuse
.card_required:
    mov  edi, AUTHR_CARD_REQUIRED
    jmp  .refuse
.retired:
    mov  edi, AUTHR_AUTH1_RETIRED
    jmp  .refuse
.wrong_node:
    mov  edi, AUTHR_WRONG_NODE
    jmp  .refuse
.replay:
    mov  edi, AUTHR_REPLAY
.refuse:
    mov  rsi, r14
    mov  rdx, r12
    mov  rcx, r13
    call command_auth_refuse
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; command_auth_register_intercept(name,cap,destr,match_kind,match_len)
command_auth_register_intercept:
    mov  eax, [rel command_auth_intercept_count]
    cmp  eax, AUTH_INT_MAX
    jae  .full
    imul r10, rax, AUTH_INT_SIZE
    lea  r11, [rel command_auth_intercepts]
    add  r11, r10
    mov  [r11 + AUTH_INT_NAME], rdi
    mov  [r11 + AUTH_INT_CAP], rsi
    mov  [r11 + AUTH_INT_DESTR], rdx
    mov  [r11 + AUTH_INT_MATCH], rcx
    mov  [r11 + AUTH_INT_LEN], r8
    inc  dword [rel command_auth_intercept_count]
    xor  eax, eax
    ret
.full:
    mov  eax, -1
    ret

; command_auth_route_gate(verb,ticket) -> 0 may continue, -1 refuse now.
; Registry matches defer to command_dispatch so the metadata gate executes once.
; Intercept matches are authorized here; no match is default-deny.
command_auth_route_gate:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    ; Match the actual UDP execution order: pre-registry intercepts win name
    ; collisions.  Looking in the registry first would let a future verb named
    ; REBOOT shadow the stricter boot scope even though the REBOOT interceptor
    ; (not that new handler) would still be the code that executes.
    lea  r14, [rel command_auth_intercepts]
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel command_auth_intercept_count]
    jae  .registry
    cmp  qword [r14 + AUTH_INT_MATCH], AUTH_MATCH_PREFIX
    je   .prefix
    mov  rdi, [r14 + AUTH_INT_NAME]
    mov  rsi, r12
    call strcmp
    test eax, eax
    jz   .matched
    jmp  .next
.prefix:
    mov  rdi, r12
    mov  rsi, [r14 + AUTH_INT_NAME]
    mov  rdx, [r14 + AUTH_INT_LEN]
    call command_auth_prefix_equal
    test eax, eax
    jnz  .matched
.next:
    add  r14, AUTH_INT_SIZE
    inc  ebx
    jmp  .scan
.registry:
    mov  rdi, r12
    call command_lookup
    cmp  eax, -1
    jne  .allow_registry
    jmp  .unknown
.matched:
    ; Intercepts are not registry rows, so they cannot truthfully appear in
    ; the AUTHVERBS census. Shipped protects every interceptor; lab retains
    ; the previously declared read-only intercept floor.
    mov  rsi, [r14 + AUTH_INT_CAP]
    test rsi, rsi
    jnz  .authorize_intercept
    cmp  qword [r14 + AUTH_INT_DESTR], 0
    jne  .generic_intercept_cap
%if PAOS_PUBLICITY_LAB_PROFILE
    jmp  .allow
%endif
.generic_intercept_cap:
    mov  rsi, CMD_AUTH_CAP_MUTATE
.authorize_intercept:
    mov  rdi, r13
    mov  rdx, r12
    call command_auth_authorize
    test eax, eax
    jnz  .out
    ; A valid transport ticket still cannot open a locked session. Unsigned,
    ; stale and wrong-capability tickets retain their existing refusal reason.
    jmp  .allow
.unknown:
    mov  edi, AUTHR_UNKNOWN
    mov  rsi, r12
    mov  rdx, r13
    xor  ecx, ecx
    call command_auth_refuse
    mov  eax, -1
    jmp  .out
.allow_registry:
.allow:
    mov  rdi, r12
    call command_session_name_allowed
    test eax, eax
    jnz  .session_allowed
    mov  edi, AUTHR_PRINCIPAL
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, CMD_AUTH_CAP_MUTATE
    call command_auth_refuse
    mov  eax, -1
    jmp  .out
.session_allowed:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

command_auth_prefix_equal:
    test rdx, rdx
    jz   .yes
.loop:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .no
    inc  rdi
    inc  rsi
    dec  rdx
    jnz  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Public helper for parser failures before routing.
; RDI=AUTHR_*, RSI=verb (or outer line), RDX=ticket.
command_auth_refuse:
    inc  qword [rel command_auth_deny_count]
    mov  [rel command_auth_last_reason], dil
    mov  [rel command_auth_ref_required], rcx
    jmp  command_auth_stage_refusal

command_auth_stage_refusal:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    mov  rbx, rdx
    call command_auth_out_reset
    lea  rdi, [rel str_auth_refused]
    call command_auth_put_str
    mov  edi, r12d
    call command_auth_reason_ptr
    mov  rdi, rax
    call command_auth_put_str
    lea  rdi, [rel str_auth_verb]
    call command_auth_put_str
    test r13, r13
    jz   .no_verb
    mov  rdi, r13
    call command_auth_put_token
    jmp  .seq
.no_verb:
    lea  rdi, [rel str_auth_unknown]
    call command_auth_put_str
.seq:
    lea  rdi, [rel str_auth_seq]
    call command_auth_put_str
    xor  edi, edi
    test rbx, rbx
    jz   .seq_put
    mov  rdi, [rbx + AUTH_T_SEQ]
.seq_put:
    call command_auth_put_dec
    lea  rdi, [rel str_auth_required]
    call command_auth_put_str
    mov  rdi, [rel command_auth_ref_required]
    call command_auth_put_hex16
    lea  rdi, [rel str_auth_presented]
    call command_auth_put_str
    xor  edi, edi
    test rbx, rbx
    jz   .cap_put
    mov  rdi, [rbx + AUTH_T_CAP]
.cap_put:
    call command_auth_put_hex16
    lea  rdi, [rel str_auth_zero_effect]
    call command_auth_put_str
    call command_auth_put_owner_key_id

    ; The node identity signs the exact refusal receipt accumulated so far.  It
    ; authenticates PaOS's response without exposing the node seed.
    mov  rax, [rel command_auth_out_cur]
    lea  rdi, [rel command_auth_out_buf]
    sub  rax, rdi
    mov  rsi, rax
    lea  rdx, [rel command_auth_receipt_signature]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jnz  .unsigned_receipt
    lea  rdi, [rel str_auth_receipt_sig]
    call command_auth_put_str
    lea  rdi, [rel command_auth_receipt_signature]
    mov  esi, 64
    call command_auth_put_bytes
    jmp  .ready
.unsigned_receipt:
    lea  rdi, [rel str_auth_receipt_unavailable]
    call command_auth_put_str
.ready:
    mov  byte [rel command_auth_refusal_ready], 1
    mov  byte [rel command_auth_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

; Live, nonce-bound evidence for the in-process AI ingress.  The AI adapter
; calls this only after it has attempted the real SLOWJOB registry dispatch;
; the response carries the observed dispatcher code and job counts, so the
; acceptance driver does not trust a boot marker or source assertion.
; RDI=nonce token, RSI=jobs_before, RDX=jobs_after, RCX=dispatch code.
command_auth_stage_ai_probe:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    call command_auth_out_reset
    lea  rdi, [rel str_auth_ai_probe]
    call command_auth_put_str
    mov  rdi, rbx
    call command_auth_put_token
    lea  rdi, [rel str_auth_ai_code]
    call command_auth_put_str
    mov  rdi, r14
    call command_auth_put_dec
    lea  rdi, [rel str_auth_ai_before]
    call command_auth_put_str
    mov  rdi, r12
    call command_auth_put_dec
    lea  rdi, [rel str_auth_ai_after]
    call command_auth_put_str
    mov  rdi, r13
    call command_auth_put_dec
    mov  byte [rel command_auth_out_ready], 1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

command_auth_reason_ptr:
    lea  rax, [rel str_auth_reason_unsigned]
    cmp  edi, AUTHR_UNSIGNED
    je   .out
    lea  rax, [rel str_auth_reason_malformed]
    cmp  edi, AUTHR_MALFORMED
    je   .out
    lea  rax, [rel str_auth_reason_wrong_key]
    cmp  edi, AUTHR_WRONG_KEY
    je   .out
    lea  rax, [rel str_auth_reason_expired]
    cmp  edi, AUTHR_EXPIRED
    je   .out
    lea  rax, [rel str_auth_reason_wrong_cap]
    cmp  edi, AUTHR_WRONG_CAP
    je   .out
    lea  rax, [rel str_auth_reason_replay]
    cmp  edi, AUTHR_REPLAY
    je   .out
    lea  rax, [rel str_auth_reason_durable]
    cmp  edi, AUTHR_DURABLE
    je   .out
    lea  rax, [rel str_auth_reason_principal]
    cmp  edi, AUTHR_PRINCIPAL
    je   .out
    lea  rax, [rel str_auth_reason_desktop_locked]
    cmp  edi, AUTHR_DESKTOP_LOCKED
    je   .out
    lea  rax, [rel str_auth_reason_auth1_retired]
    cmp  edi, AUTHR_AUTH1_RETIRED
    je   .out
    lea  rax, [rel str_auth_reason_wrong_node]
    cmp  edi, AUTHR_WRONG_NODE
    je   .out
    lea  rax, [rel str_auth_reason_card_required]
    cmp  edi, AUTHR_CARD_REQUIRED
    je   .out
    lea  rax, [rel str_auth_reason_unknown]
.out:
    ret

; ---------------------------------------------------------------------------
; Secure Boot sense (route-independent). secureboot_snapshot runs ONCE pre-EBS
; from header.asm while firmware Runtime Services are live, so GetVariable works
; even on the PAX1 direct-entry chain (which never maps runtime code post-EBS,
; leaving the AUTH1 replay POISONED). The captured bytes are reported by the
; PUBLIC read-only SECUREBOOT verb. Every read is bounded and degrades to 0xFF;
; a missing/short variable never faults.
; ---------------------------------------------------------------------------

; Task3024's catalog-wide negative image fails the exact SecureBoot
; GetVariable boundary. Plain builds leave the firmware call untouched.
%ifdef PAOS_SECURITY_TRUTH_FORCE_FAIL
%ifndef PAOS_SECUREBOOT_SNAPSHOT_FORCE_FAIL
%define PAOS_SECUREBOOT_SNAPSHOT_FORCE_FAIL 1
%endif
%endif

; sb_getvar_byte(RDI=CHAR16 name, RSI=EFI_GUID*)
;   -> AL = captured byte or 0xFF, EDX = 1 only when GetVariable succeeded.
;   Leaf: entry RSP mod16==8, sub 40 -> mod16==0 at the firmware call.
;   clobbers rax,rcx,rdx,r8,r9,r10
sb_getvar_byte:
    mov  r10, [rel runtime_services]
    mov  qword [rel sb_snap_size], 1
    mov  byte  [rel sb_snap_databuf], 0
    mov  rcx, rdi
    mov  rdx, rsi
    lea  r8,  [rel sb_snap_attrs]
    lea  r9,  [rel sb_snap_size]
    sub  rsp, 40
    lea  rax, [rel sb_snap_databuf]
    mov  [rsp + 32], rax
%ifdef PAOS_SECUREBOOT_SNAPSHOT_FORCE_FAIL
    ; Fail only GetVariable(SecureBoot), immediately before the firmware call.
    ; Later observations still use their production firmware boundaries.
    lea  rax, [rel sb_name_secureboot]
    cmp  rcx, rax
    je   .forced_miss
%endif
    call [r10 + 0x48]                    ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 40
    test rax, rax
    jnz  .miss
    movzx eax, byte [rel sb_snap_databuf]
    mov  edx, 1
    ret
%ifdef PAOS_SECUREBOOT_SNAPSHOT_FORCE_FAIL
.forced_miss:
    add  rsp, 40
%endif
.miss:
    mov  eax, 0xFF
    xor  edx, edx
    ret

; sb_getvar_present(RDI=CHAR16 name, RSI=EFI_GUID*) -> AL = 1 present / 0 absent.
;   EFI_SUCCESS or EFI_BUFFER_TOO_SMALL both prove the variable exists.
;   clobbers rax,rcx,rdx,r8,r9,r10
sb_getvar_present:
    mov  r10, [rel runtime_services]
    mov  qword [rel sb_snap_size], 1
    mov  rcx, rdi
    mov  rdx, rsi
    lea  r8,  [rel sb_snap_attrs]
    lea  r9,  [rel sb_snap_size]
    sub  rsp, 40
    lea  rax, [rel sb_snap_databuf]
    mov  [rsp + 32], rax
    call [r10 + 0x48]
    add  rsp, 40
    test rax, rax
    jz   .present
    mov  rdx, 0x8000000000000005         ; EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .present
    xor  eax, eax
    ret
.present:
    mov  eax, 1
    ret

; secureboot_snapshot — pre-EBS capture + serial marker. The alignment push is
; load-bearing: it keeps every child pre-call RSP 16-aligned on all boot routes.
secureboot_snapshot:
    push rbx
    ; ADMIN Q5: the SMBIOS platform identity is captured in the same pre-EBS
    ; platform-facts pass (config table + firmware memory still live). The HP
    ; EliteDesk 705 G5 identity makes core/smp run BSP-only for Phase-0.
    call smbios_identity_snapshot
    call platform_key_health_snapshot
    mov  byte [rel pbm_sb_snapshot_valid], 0
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .marker
    lea  rdi, [rel sb_name_secureboot]
    lea  rsi, [rel sb_efi_global_guid]
    call sb_getvar_byte
    mov  [rel pbm_sb_secureboot], al
    test edx, edx
    jz   .secureboot_observation_done
    mov  byte [rel pbm_sb_snapshot_valid], 1
.secureboot_observation_done:
    lea  rdi, [rel sb_name_setupmode]
    lea  rsi, [rel sb_efi_global_guid]
    call sb_getvar_byte
    mov  [rel pbm_sb_setupmode], al
    lea  rdi, [rel sb_name_moklistrt]
    lea  rsi, [rel sb_moklist_guid]
    call sb_getvar_present
    mov  [rel pbm_sb_mok_present], al
.marker:
    lea  rdi, [rel str_sb_snap_pre]
    call serial_string
    movzx edi, byte [rel pbm_sb_secureboot]
    lea  rsi, [rel sb_num_buf]
    call fmt_dec
    lea  rdi, [rel sb_num_buf]
    call serial_string
    lea  rdi, [rel str_sb_snap_setup]
    call serial_string
    movzx edi, byte [rel pbm_sb_setupmode]
    lea  rsi, [rel sb_num_buf]
    call fmt_dec
    lea  rdi, [rel sb_num_buf]
    call serial_string
    lea  rdi, [rel str_sb_snap_mok]
    call serial_string
    movzx edi, byte [rel pbm_sb_mok_present]
    lea  rsi, [rel sb_num_buf]
    call fmt_dec
    lea  rdi, [rel sb_num_buf]
    call serial_string
    call serial_newline
    ; Rescue-0 R0-0 (PETER DECISION 2026-09-30 22:31): read-only firmware SNP
    ; discovery in the same pre-EBS platform-facts pass (boot services live,
    ; early trap armed). Record + [rescue0.snp.discovery] only; no SNP call
    ; beyond HandleProtocol/LocateDevicePath, no frames, no NVRAM.
    call rescue0_snp_discover
    call rescue0_snp_report
    pop  rbx
    ret

; SECUREBOOT verb: public read-only. Mirrors command_auth_status_verb — stage
; the reply text into command_auth_out_buf, flip out_ready, echo the arg.
command_secureboot_verb:
    call cmd_handler_prologue
    push rdi
    push rsi
    call secureboot_stage
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; AUTHFLOOR RESEED: console OWNER only. Stages the HMAC-bound reseed of this
; boot's LOST replay floor for the next pre-EBS step (sec/replay_floor). The
; dispatcher already requires CMD_PRINCIPAL_OWNER on console ingress; any other
; ingress (UDP, SSH, serial, AI hook, internal) is refused here, whatever its
; ticket, and an injected line never reaches here (keyprov owner-change list).
command_authfloor_verb:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    call command_auth_out_reset
    mov  r13d, CMDE_AUTHDENY
    lea  rdi, [rel str_auth_floor_not_console]
    cmp  qword [rbx + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .refuse
    cmp  qword [rbx + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .refuse
    mov  r13d, CMDE_BADARG
    lea  rdi, [rel str_auth_floor_usage]
    mov  rax, [rbx + REQ_ARG]
    test rax, rax
    jz   .refuse
    mov  rdi, rax
    lea  rsi, [rel str_auth_floor_arg]
    call strcmp
    lea  rdi, [rel str_auth_floor_usage]
    test eax, eax
    jnz  .refuse
    mov  r13d, CMDE_AUTHDENY
    lea  rdi, [rel str_auth_floor_not_lost]
    cmp  byte [rel rpf_state], RPF_LOST
    jne  .refuse
    call replay_floor_stage_reseed
    lea  rdi, [rel str_auth_floor_failed]
    test eax, eax
    jnz  .refuse
    lea  rdi, [rel str_auth_floor_staged]
    call command_auth_put_str
    mov  rdi, [rel rpf_f]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_floor_gen]
    call command_auth_put_str
    mov  rdi, [rel ows_generation]
    call command_auth_put_dec
    xor  r13d, r13d                     ; CMDE_OK
    jmp  .ready
.refuse:
    call command_auth_put_str
.ready:
    mov  byte [rel command_auth_out_ready], 1
    mov  rax, [rbx + REQ_ARG]
    mov  [r12 + RSP_VAL], rax
    mov  [r12 + RSP_CODE], r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; R0STAT <nonce>: public read-only. Projects the record rescue0_snp_discover
; rendered pre-EBS (boot/rescue0_snp.asm); nothing is re-read from firmware.
; Reply conventions follow STATUS: version prefix, ARG=<nonce> echo and the
; boot's BOOT_SESSION, all ahead of the record so a clip never removes them.
command_r0stat_verb:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rdi, [rdi + REQ_ARG]
    call r0stat_stage
    pop  rsi
    pop  rdi
    mov  rcx, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rcx
    mov  qword [rsi + RSP_CODE], CMDE_OK
    test eax, eax
    jz   .done
    mov  qword [rsi + RSP_CODE], CMDE_BADARG
.done:
    ret

; r0stat_stage(RDI=nonce or NULL) -> EAX=0 staged, -1 refused (bad nonce).
r0stat_stage:
    push rbx
    mov  rbx, rdi
    call command_auth_out_reset
    test rbx, rbx
    jz   .bad
    mov  rdi, rbx
    call session_nonce_valid
    test eax, eax
    jnz  .bad
    lea  rdi, [rel str_udp_r_pre]
    call command_auth_put_str
    lea  rdi, [rel str_r0stat_ok]
    call command_auth_put_str
    mov  rdi, rbx
    call command_auth_put_str
    lea  rdi, [rel str_r0stat_session]
    call command_auth_put_str
    mov  rdi, [rel boot_tsc_start]
    call command_auth_put_dec
    lea  rdi, [rel str_r0stat_rung]
    call command_auth_put_str
    movzx edi, byte [rel rescue0_snp_ran]
    call command_auth_put_dec
    cmp  byte [rel rescue0_snp_ran], 1
    jne  .ready
    lea  rdi, [rel str_r0stat_sep]
    call command_auth_put_str
    lea  rdi, [rel rescue0_snp_text]
    call command_auth_put_str
.ready:
    mov  byte [rel command_auth_out_ready], 1
    xor  eax, eax
    pop  rbx
    ret
.bad:
    lea  rdi, [rel str_r0stat_bad]
    call command_auth_put_str
    mov  byte [rel command_auth_out_ready], 1
    mov  eax, -1
    pop  rbx
    ret

secureboot_stage:
    call command_auth_out_reset
    lea  rdi, [rel str_sb_pre]
    call command_auth_put_str
    movzx edi, byte [rel pbm_sb_snapshot_valid]
    call command_auth_put_dec
    lea  rdi, [rel str_sb_secureboot]
    call command_auth_put_str
    movzx edi, byte [rel pbm_sb_secureboot]
    call command_auth_put_dec
    lea  rdi, [rel str_sb_setupmode]
    call command_auth_put_str
    movzx edi, byte [rel pbm_sb_setupmode]
    call command_auth_put_dec
    lea  rdi, [rel str_sb_mok]
    call command_auth_put_str
    movzx edi, byte [rel pbm_sb_mok_present]
    call command_auth_put_dec
    lea  rdi, [rel str_sb_pk_health]
    call command_auth_put_str
    movzx edi, byte [rel platform_key_health_state]
    call command_auth_put_dec
    lea  rdi, [rel str_sb_rtmap]
    call command_auth_put_str
    movzx edi, byte [rel pbm_runtime_code_mapped]
    call command_auth_put_dec
    lea  rdi, [rel str_sb_replay]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_replay_state]
    call command_auth_put_dec
    mov  byte [rel command_auth_out_ready], 1
    ret

command_auth_status_verb:
    call cmd_handler_prologue
    push rdi
    push rsi
    call command_auth_inventory_stage
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; EDI=live registry id -> EAX=1 iff the same effective classifier used by
; command_dispatch says the row is public. This is the sole inventory seam.
command_auth_registry_id_is_public:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    call command_verb_name
    mov  r12, rax
    mov  edi, ebx
    call command_verb_cap
    mov  r13, rax
    mov  edi, ebx
    call command_verb_destr
    mov  rdx, rax
    mov  rdi, r12
    mov  rsi, r13
    call command_auth_required_cap
    test rax, rax
    setz al
    movzx eax, al
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=exact name -> EAX=1 iff that name resolves to a live public row.
command_auth_registry_name_is_public:
    call command_lookup
    cmp  eax, -1
    je   .no
    mov  edi, eax
    jmp  command_auth_registry_id_is_public
.no:
    xor  eax, eax
    ret

; Late-boot profile KAT. Both postures retain the bounded health and live
; observation floor. Shipped refuses FSLS plus the non-registry ADDRSTAB
; interceptor; lab retains both former read paths.
command_auth_publicity_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, 1                       ; bounded failure-stage diagnostic
    call command_verb_count
    mov  ebx, eax
    xor  r12d, r12d
    xor  ecx, ecx
.count:
    cmp  ecx, ebx
    jae  .counted
    push rcx
    mov  edi, ecx
    call command_auth_registry_id_is_public
    pop  rcx
    add  r12d, eax
    inc  ecx
    jmp  .count
.counted:
    ; Six bounded health verbs are the irreducible floor. Observation verbs
    ; are intentionally counted from their live declarations, never duplicated
    ; here as a second inventory table.
    cmp  r12d, 6
    jb   .fail
    mov  r15d, 2
    call command_auth_filmstrip_policy_selftest
    test eax, eax
    jz   .fail
    mov  r15d, 3
    lea  rdi, [rel str_fsls]
    call command_auth_registry_name_is_public
%if PAOS_PUBLICITY_LAB_PROFILE
    test eax, eax
    jz   .fail
%else
    test eax, eax
    jnz  .fail
%endif
    ; Exercise the real pre-registry route with an unsigned ticket, then erase
    ; the synthetic refusal so boot starts with truthful operator counters.
    mov  r15d, 4
    mov  r13, [rel command_auth_deny_count]
    movzx r14d, byte [rel command_auth_last_reason]
    lea  rdi, [rel command_auth_principal_test_ticket]
    xor  esi, esi
    mov  edx, AUTH_T_SIZE
    call memset
%if PAOS_PUBLICITY_LAB_PROFILE
    ; Lab admits the cap-0 ADDRSTAB intercept through the session gate, so a
    ; locked normal boot refuses it as AUTHR_PRINCIPAL, never as unsigned.
    lea  rdi, [rel str_hpv_addrstab]
    call command_session_name_allowed
    mov  ebx, eax                      ; stage 5 reloads ebx
%endif
    lea  rdi, [rel str_hpv_addrstab]
    lea  rsi, [rel command_auth_principal_test_ticket]
    call command_auth_route_gate
%if PAOS_PUBLICITY_LAB_PROFILE
    test ebx, ebx
    jnz  .addrstab_admitted
    cmp  eax, -1
    jne  .intercept_bad
    cmp  byte [rel command_auth_last_reason], AUTHR_PRINCIPAL
    jne  .intercept_bad
    jmp  .addrstab_pass
.addrstab_admitted:
    test eax, eax
    jnz  .intercept_bad
.addrstab_pass:
%else
    cmp  eax, -1
    jne  .intercept_bad
    cmp  byte [rel command_auth_last_reason], AUTHR_UNSIGNED
    jne  .intercept_bad
%endif
    ; The public classifier above must stay independent of session policy,
    ; while the actual route must still refuse FILMSTRIP when locked. Exercise
    ; routing only: no capture handler or target action runs in this KAT.
    mov  r15d, 5
    lea  rdi, [rel str_auth_filmstrip_exact]
    call command_session_name_allowed
    mov  ebx, eax
    lea  rdi, [rel str_auth_filmstrip_exact]
    lea  rsi, [rel command_auth_principal_test_ticket]
    call command_auth_route_gate
    test ebx, ebx
    jnz  .workspace_route
    cmp  eax, -1
    jne  .intercept_bad
    cmp  byte [rel command_auth_last_reason], AUTHR_PRINCIPAL
    jne  .intercept_bad
    jmp  .route_pass
.workspace_route:
    test eax, eax
    jnz  .intercept_bad
.route_pass:
    ; A locked boot must remain identifiable to the canonical deploy observer,
    ; which uses PING nonce. Exercise the actual route as well as publicity;
    ; an inventory-only KAT cannot catch a later session-policy refusal.
    mov  r15d, 6
    lea  rdi, [rel str_verb_ping]
    call command_auth_registry_name_is_public
    test eax, eax
    jz   .intercept_bad
    lea  rdi, [rel str_verb_ping]
    lea  rsi, [rel command_auth_principal_test_ticket]
    call command_auth_route_gate
    test eax, eax
    jnz  .intercept_bad
    ; Recovery observation remains session-available but owner-authenticated.
    ; Do not call its handler or perform any boot/recovery operation here.
    mov  r15d, 7
    lea  rdi, [rel str_auth_recovery_floor]
    call command_session_name_allowed
    test eax, eax
    jz   .intercept_bad
    lea  rdi, [rel str_auth_recovery_floor]
    call command_lookup
    cmp  eax, -1
    je   .intercept_bad
    mov  edi, eax
    call command_auth_registry_id_is_public
    test eax, eax
    jnz  .intercept_bad
    mov  ebx, 1
    jmp  .restore_intercept
.intercept_bad:
    xor  ebx, ebx
.restore_intercept:
    mov  [rel command_auth_deny_count], r13
    mov  [rel command_auth_last_reason], r14b
    call command_auth_out_reset
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_refusal_ready], 0
    test ebx, ebx
    jz   .fail
%if PAOS_PUBLICITY_LAB_PROFILE
    lea  rdi, [rel str_auth_publicity_lab]
%else
    lea  rdi, [rel str_auth_publicity_shipped]
%endif
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_auth_publicity_fail]
    call serial_string
    lea  rdi, [rel str_auth_publicity_stage]
    call serial_string
    mov  edi, r15d
    call serial_hex64
    call serial_newline
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exercise the production classifier with the exact Task2302a matrix, then
; require the retained Task2302 live row to resolve public. AUTHSTAT's inventory
; uses this same registry-backed decision, so no second name table can drift.
command_auth_filmstrip_policy_selftest:
    ; SEC-P1: the exact spelling is public on the lab floor only. Shipped bytes
    ; must classify it owner-gated; the near-miss and metadata checks below are
    ; the same on both floors.
    lea  rdi, [rel str_auth_filmstrip_exact]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
%if PAOS_PUBLICITY_LAB_PROFILE
    jnz  .fail
%else
    jz   .fail
%endif

    lea  rdi, [rel str_auth_filmstrip_prefix]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_auth_filmstrip_suffix]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_auth_filmstrip_near]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jz   .fail

    lea  rdi, [rel str_auth_filmstrip_exact]
    mov  rsi, CMD_AUTH_CAP_HOTPATCH
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_auth_filmstrip_exact]
    xor  esi, esi
    mov  edx, 1
    call command_auth_required_cap
    test rax, rax
    jz   .fail

    ; BOOT represents a known mutator whose special authority must remain
    ; nonzero even when synthetic zero metadata is presented to the classifier.
    lea  rdi, [rel str_auth_verb_boot]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jz   .fail

    ; Require the live registry row as well as the spelling classifier. This
    ; must fail loudly if the retained Task2302 frontier was not adopted.
    lea  rdi, [rel str_auth_filmstrip_exact]
    call command_auth_registry_name_is_public
    test eax, eax
%if PAOS_PUBLICITY_LAB_PROFILE
    jz   .fail
%else
    jnz  .fail
%endif
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; Registry counts walk metadata through the same required-capability classifier
; used by dispatch; the AUTHVERBS census is emitted by another pass over those
; same live rows, never by a hand-maintained string.
command_auth_inventory_stage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call command_auth_out_reset
    xor  r12d, r12d
    xor  r13d, r13d
    call command_verb_count
    mov  ebx, eax
    xor  ecx, ecx
.verbs:
    cmp  ecx, ebx
    jae  .intercepts
    push rcx
    mov  edi, ecx
    call command_auth_registry_id_is_public
    pop  rcx
    test eax, eax
    jnz  .vread
    inc  r13d
    jmp  .vnext
.vread:
    inc  r12d
.vnext:
    inc  ecx
    jmp  .verbs
.intercepts:
    xor  r8d, r8d
    xor  r9d, r9d
    lea  r10, [rel command_auth_intercepts]
    xor  ecx, ecx
.ints:
    cmp  ecx, [rel command_auth_intercept_count]
    jae  .emit
    cmp  qword [r10 + AUTH_INT_DESTR], 0
    je   .iread
    inc  r9d
    jmp  .inext
.iread:
    inc  r8d
.inext:
    add  r10, AUTH_INT_SIZE
    inc  ecx
    jmp  .ints
.emit:
    mov  [rel command_auth_inv_iread], r8d
    mov  [rel command_auth_inv_imut], r9d
    lea  rdi, [rel str_auth_stat_pre]
    call command_auth_put_str
    mov  edi, r12d
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_rmut]
    call command_auth_put_str
    mov  edi, r13d
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_iread]
    call command_auth_put_str
    mov  edi, [rel command_auth_inv_iread]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_imut]
    call command_auth_put_str
    mov  edi, [rel command_auth_inv_imut]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_signing]
    call command_auth_put_str
    call command_auth_put_owner_key_id
    lea  rdi, [rel str_auth_stat_replay]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_replay_state]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_last]
    call command_auth_put_str
    mov  rdi, [rel command_auth_last_sequence]
    ; Local PASSWORD ingress shares the durable replay order with AUTH1.
    cmp  rdi, [rel prin_password_last_sequence]
    jae  .login_sequence_ready
    mov  rdi, [rel prin_password_last_sequence]
.login_sequence_ready:
    call command_auth_put_dec
    ; Security identity precedes the variable-length public-name census so
    ; registry growth cannot truncate credential evidence from AUTHSTAT.
    lea  rdi, [rel str_auth_stat_principals]
    call command_auth_put_str
    movzx edi, byte [rel prin_system_secret_ready]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_principal_ready]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_m_principal_table]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_bind_ready]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_m_principal_bound]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_gate_ready]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_m_principal_gate]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_lock_ready]
    call command_auth_put_str
    movzx edi, byte [rel prin_authz_lock_ready]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_guest]
    call command_auth_put_str
    movzx edi, byte [rel dce_m_guest]
    call command_auth_put_dec
    ; Project only already-earned boot KAT bits onto the live channel.
    cmp  byte [rel command_auth_m_principal_table], 1
    jne  .no_auth2500_1
    lea  rdi, [rel str_auth_stat_2500_table]
    call command_auth_put_str
.no_auth2500_1:
    cmp  byte [rel command_auth_m_principal_bound], 1
    jne  .no_auth2500_2
    lea  rdi, [rel str_auth_stat_2500_bound]
    call command_auth_put_str
.no_auth2500_2:
    cmp  byte [rel command_auth_m_principal_gate], 1
    jne  .no_auth2500_3
    lea  rdi, [rel str_auth_stat_2500_gate]
    call command_auth_put_str
.no_auth2500_3:
    cmp  byte [rel command_auth_m_principal_deny], 1
    jne  .no_auth2500_4
    lea  rdi, [rel str_auth_stat_2500_deny]
    call command_auth_put_str
.no_auth2500_4:
    cmp  byte [rel dce_m_dek], 1
    jne  .no_auth1054_1
    lea  rdi, [rel str_auth_stat_1054_dek]
    call command_auth_put_str
.no_auth1054_1:
    cmp  byte [rel dce_m_envelope], 1
    jne  .no_auth1054_2
    lea  rdi, [rel str_auth_stat_1054_envelope]
    call command_auth_put_str
.no_auth1054_2:
    cmp  byte [rel dce_m_owner], 1
    jne  .no_auth1054_3
    lea  rdi, [rel str_auth_stat_1054_owner]
    call command_auth_put_str
.no_auth1054_3:
    cmp  byte [rel kv_m_header], 1
    jne  .no_auth1057_1
    lea  rdi, [rel str_auth_stat_1057_header]
    call command_auth_put_str
.no_auth1057_1:
    cmp  byte [rel kv_m_durable], 1
    jne  .no_auth1057_2
    lea  rdi, [rel str_auth_stat_1057_durable]
    call command_auth_put_str
.no_auth1057_2:
    cmp  byte [rel kv_m_atrest], 1
    jne  .no_auth1057_3
    lea  rdi, [rel str_auth_stat_1057_atrest]
    call command_auth_put_str
.no_auth1057_3:
    cmp  byte [rel prin_m_auth_bind], 1
    jne  .no_auth2501_1
    lea  rdi, [rel str_auth_stat_2501_bind]
    call command_auth_put_str
.no_auth2501_1:
    cmp  byte [rel prin_m_auth_method], 1
    jne  .no_auth2501_2
    lea  rdi, [rel str_auth_stat_2501_method]
    call command_auth_put_str
.no_auth2501_2:
    cmp  byte [rel prin_m_auth_pbkdf2], 1
    jne  .no_auth2501_3
    lea  rdi, [rel str_auth_stat_2501_pbkdf2]
    call command_auth_put_str
.no_auth2501_3:
    cmp  byte [rel prin_m_auth_system], 1
    jne  .no_auth2501_4
    lea  rdi, [rel str_auth_stat_2501_system]
    call command_auth_put_str
.no_auth2501_4:
    lea  rdi, [rel str_auth_stat_policy]
    call command_auth_put_str
    lea  rdi, [rel str_auth_stat_node]
    call command_auth_put_str
    call node_identity_active
    test eax, eax
    jz   .node_absent
    lea  rdi, [rel str_auth_node_active]
    jmp  .node_emit
.node_absent:
    lea  rdi, [rel str_auth_node_absent]
.node_emit:
    call command_auth_put_str
    ; AUTH2: the only accepted envelope format and THIS node's binding id, so a
    ; signer picks the format from observed firmware and checks its pin. Lying
    ; here can only make this node refuse, never accept a foreign envelope.
    lea  rdi, [rel str_auth_stat_format]
    call command_auth_put_str
    call command_auth_node_id_ensure
    test eax, eax
    jz   .node_id_none
    lea  rdi, [rel command_auth_node_hex]
    call command_auth_put_str
    lea  rdi, [rel str_auth_stat_node_src]
    call command_auth_put_str
    lea  rdi, [rel str_auth_node_src_smbios]
    cmp  byte [rel command_auth_node_src], AUTH_NODE_SRC_SMBIOS
    je   .node_src_emit
    lea  rdi, [rel str_auth_node_src_mac]
.node_src_emit:
    call command_auth_put_str
    jmp  .node_id_done
.node_id_none:
    lea  rdi, [rel str_auth_stat_node_none]
    call command_auth_put_str
.node_id_done:
    lea  rdi, [rel str_auth_stat_accept]
    call command_auth_put_str
    mov  rdi, [rel command_auth_accept_count]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_deny]
    call command_auth_put_str
    mov  rdi, [rel command_auth_deny_count]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_jobs]
    call command_auth_put_str
    mov  edi, [rel job_count]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_wall]
    call command_auth_put_str
    call time_wall_now_s
    mov  rdi, rax
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_aihook]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_aihook_gate_proved]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_serial]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_serial_gate_proved]
    call command_auth_put_dec
    call command_auth_put_reservation
    ; AUTHSTAT split: the variable-length public-name census is NOT part of
    ; AUTHSTAT any more (it truncated at AUTH_OUT_MAX); AUTHVERBS serves it.
    ; AUTHSTAT is now fixed-shape and ends with the reservation fields above.
    mov  byte [rel command_auth_out_ready], 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Reservation view, appended last so existing AUTHSTAT parsers keep their
; offsets.  last_seq above is sequence_last_admitted (H, max'd with the local
; PASSWORD floor).  sequence_next_min is the least sequence any signed owner
; envelope may use now: max(H, PASSWORD floor)+1, or "none" at UINT64_MAX.
; Signer helpers resync to it after reconnect, reboot or a replay refusal.
command_auth_put_reservation:
    lea  rdi, [rel str_auth_stat_reserved]
    call command_auth_put_str
    mov  rdi, [rel command_auth_reserved_through]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_next_min]
    call command_auth_put_str
    mov  rdi, [rel command_auth_last_sequence]
    cmp  rdi, [rel prin_password_last_sequence]
    jae  .next
    mov  rdi, [rel prin_password_last_sequence]
.next:
    add  rdi, 1
    jc   .next_none
    call command_auth_put_dec
    jmp  .state
.next_none:
    lea  rdi, [rel str_auth_stat_next_none]
    call command_auth_put_str
.state:
    lea  rdi, [rel str_auth_stat_resv_state]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_resv_state]
    call command_auth_put_dec
    lea  rdi, [rel str_auth_stat_resv_error]
    call command_auth_put_str
    movzx edi, byte [rel command_auth_resv_error]
    jmp  command_auth_put_dec

; AUTHVERBS — the bounded public read-only verb census (ADMIN 2026-10-01 23:2x).
;   "AUTHVERBS registry_rows=<R> public=<N> names=<A,B,...>"
; R = live registry rows, N = rows the dispatch classifier
; (command_auth_registry_id_is_public, the same seam AUTHSTAT's registry_read
; counts) says are public; names lists every public row in registry order.
; When the full list cannot fit the bounded reply, it stops at a whole name and
; adds the explicit line "AUTHVERBS truncated shown=<K> public=<N>" — a client
; must treat that as incomplete. No data that AUTHSTAT did not already publish.
; "AUTHVERBS locked" (the exact argument) answers the session gate's view of the
; same census instead (command_auth_verbs_locked_stage); any other argument keeps
; the census reply above byte for byte.
command_auth_verbs_verb:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .census
    cmp  dword [rax], 'lock'
    jne  .census
    cmp  word [rax + 4], 'ed'
    jne  .census
    cmp  byte [rax + 6], 0
    jne  .census
    call command_auth_verbs_locked_stage
    jmp  .staged
.census:
    call command_auth_verbs_stage
.staged:
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; >>> AUTH2-KAT-BEGIN authverbs census (host KAT extracts this block verbatim)
AUTH_VERBS_TAIL_RESERVE equ 64          ; CRLF + truncation line + two decimals, always fits

command_auth_verbs_stage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call command_auth_out_reset
    call command_verb_count
    mov  ebx, eax                         ; live registry rows
    xor  r12d, r12d                       ; public rows
    xor  r14d, r14d
.count:
    cmp  r14d, ebx
    jae  .counted
    mov  edi, r14d
    call command_auth_registry_id_is_public
    add  r12d, eax
    inc  r14d
    jmp  .count
.counted:
    lea  rdi, [rel str_auth_verbs_pre]
    call command_auth_put_str
    mov  edi, ebx
    call command_auth_put_dec
    lea  rdi, [rel str_auth_verbs_public]
    call command_auth_put_str
    mov  edi, r12d
    call command_auth_put_dec
    lea  rdi, [rel str_auth_verbs_names]
    call command_auth_put_str
    xor  r13d, r13d                       ; names shown
    xor  r14d, r14d                       ; live registry id
.names:
    cmp  r14d, ebx
    jae  .names_done
    mov  edi, r14d
    call command_auth_registry_id_is_public
    test eax, eax
    jz   .name_next
    mov  edi, r14d
    call command_verb_name
    mov  r15, rax
    mov  rdi, rax
    call strlen
    test r13d, r13d
    jz   .room
    inc  rax                              ; the separating comma
.room:
    mov  rdx, [rel command_auth_out_cur]
    lea  rcx, [rel command_auth_out_buf + AUTH_OUT_MAX - 1 - AUTH_VERBS_TAIL_RESERVE]
    sub  rcx, rdx
    jb   .names_done
    cmp  rax, rcx
    ja   .names_done                      ; whole names only: stop, report below
    test r13d, r13d
    jz   .name_emit
    lea  rdi, [rel str_auth_stat_comma]
    call command_auth_put_str
.name_emit:
    mov  rdi, r15
    call command_auth_put_str
    inc  r13d
.name_next:
    inc  r14d
    jmp  .names
.names_done:
    cmp  r13d, r12d
    je   .complete
    lea  rdi, [rel str_auth_verbs_trunc]
    call command_auth_put_str
    mov  edi, r13d
    call command_auth_put_dec
    lea  rdi, [rel str_auth_verbs_public]
    call command_auth_put_str
    mov  edi, r12d
    call command_auth_put_dec
.complete:
    mov  byte [rel command_auth_out_ready], 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; <<< AUTH2-KAT-END authverbs census

; AUTHVERBS locked — SEC-authverbs-locked-floor F2 (root 2026-10-10 10:32:37):
;   "AUTHVERBS locked=<0|1> locked_public=<K> locked_names=<A,B,...>"
; locked = the desktop session is locked. K counts the public rows (the same
; classifier as the census) whose name the session gate admits for an UNSIGNED
; request now: command_session_name_allowed itself, over an unsigned frame (the
; console-lock rules while locked; every public row while open). A producer on a
; locked box reads locked_names, or signs. Whole-name truncation as the census,
; with "AUTHVERBS truncated shown=<K'> locked_public=<K>".
command_auth_verbs_locked_stage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call command_auth_out_reset
    call command_verb_count
    mov  ebx, eax                         ; live registry rows
    xor  r12d, r12d                       ; public rows an unsigned request is admitted for
    xor  r14d, r14d
.count:
    cmp  r14d, ebx
    jae  .counted
    mov  edi, r14d
    call command_auth_unsigned_public_id
    add  r12d, eax
    inc  r14d
    jmp  .count
.counted:
    lea  rdi, [rel str_auth_verbs_locked]
    call command_auth_put_str
    xor  edi, edi
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    setne dil
    call command_auth_put_dec
    lea  rdi, [rel str_auth_verbs_locked_public]
    call command_auth_put_str
    mov  edi, r12d
    call command_auth_put_dec
    lea  rdi, [rel str_auth_verbs_locked_names]
    call command_auth_put_str
    xor  r13d, r13d                       ; names shown
    xor  r14d, r14d                       ; live registry id
.names:
    cmp  r14d, ebx
    jae  .names_done
    mov  edi, r14d
    call command_auth_unsigned_public_id
    test eax, eax
    jz   .name_next
    mov  edi, r14d
    call command_verb_name
    mov  r15, rax
    mov  rdi, rax
    call strlen
    test r13d, r13d
    jz   .room
    inc  rax                              ; the separating comma
.room:
    mov  rdx, [rel command_auth_out_cur]
    lea  rcx, [rel command_auth_out_buf + AUTH_OUT_MAX - 1 - AUTH_VERBS_TAIL_RESERVE]
    sub  rcx, rdx
    jb   .names_done
    cmp  rax, rcx
    ja   .names_done                      ; whole names only: stop, report below
    test r13d, r13d
    jz   .name_emit
    lea  rdi, [rel str_auth_stat_comma]
    call command_auth_put_str
.name_emit:
    mov  rdi, r15
    call command_auth_put_str
    inc  r13d
.name_next:
    inc  r14d
    jmp  .names
.names_done:
    cmp  r13d, r12d
    je   .complete
    lea  rdi, [rel str_auth_verbs_trunc]
    call command_auth_put_str
    mov  edi, r13d
    call command_auth_put_dec
    lea  rdi, [rel str_auth_verbs_locked_public]
    call command_auth_put_str
    mov  edi, r12d
    call command_auth_put_dec
.complete:
    mov  byte [rel command_auth_out_ready], 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; command_auth_unsigned_public_id(EDI = registry id) -> EAX 1 when the row is
; public and the session gate admits its name for an unsigned request now. The
; gate runs unchanged with the in-flight ticket pointer swapped for a zeroed
; (unsigned) ticket and restored after; nothing else is written.
command_auth_unsigned_public_id:
    push rbx
    push r12
    mov  ebx, edi
    call command_auth_registry_id_is_public
    test eax, eax
    jz   .out
    mov  edi, ebx
    call command_verb_name
    test rax, rax
    jz   .no
    mov  rdi, rax
    mov  r12, [rel command_auth_remote_ticket]
    lea  rax, [rel command_auth_unsigned_ticket]
    mov  [rel command_auth_remote_ticket], rax
    call command_session_name_allowed
    mov  [rel command_auth_remote_ticket], r12
    test eax, eax
    setnz al
    movzx eax, al
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

command_auth_out_reset:
    lea  rax, [rel command_auth_out_buf]
    mov  [rel command_auth_out_cur], rax
    mov  byte [rax], 0
    mov  byte [rel command_auth_refusal_ready], 0
    ret

command_auth_put_str:
    mov  rsi, [rel command_auth_out_cur]
    lea  rdx, [rel command_auth_out_buf + AUTH_OUT_MAX - 1]
.loop:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.done:
    mov  byte [rsi], 0
    mov  [rel command_auth_out_cur], rsi
    ret

; Bounded token append: stop at NUL or space, so a refusal never reflects an
; entire attacker-controlled envelope/signature.
command_auth_put_token:
    mov  rsi, [rel command_auth_out_cur]
    lea  rdx, [rel command_auth_out_buf + AUTH_OUT_MAX - 1]
    mov  ecx, AUTH_REFLECT_TOKEN_MAX
.loop:
    test ecx, ecx
    jz   .done
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  al, ' '
    je   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jmp  .loop
.done:
    mov  byte [rsi], 0
    mov  [rel command_auth_out_cur], rsi
    ret

command_auth_put_dec:
    lea  rsi, [rel command_auth_num_buf]
    call fmt_dec
    lea  rdi, [rel command_auth_num_buf]
    jmp  command_auth_put_str

command_auth_put_hex16:
    lea  rsi, [rel command_auth_num_buf]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel command_auth_num_buf]
    jmp  command_auth_put_str

; Append the compiled owner key identity through one production seam.  The
; underlying helper bounds every write against AUTH_OUT_MAX and renders only
; through command_auth_hex_digits, so both operator paths stay lowercase and
; cannot drift to a copied or pre-rendered identifier.
command_auth_put_owner_key_id:
    mov  rax, [rel command_auth_out_cur]
    mov  [rel command_auth_owner_keyid_last_start], rax
    lea  rdi, [rel command_auth_owner_key_id]
    mov  esi, 32
    jmp  command_auth_put_bytes

command_auth_put_bytes:
    mov  r8, rdi
    mov  r9, rsi
    mov  r10, [rel command_auth_out_cur]
    lea  r11, [rel command_auth_out_buf + AUTH_OUT_MAX - 1]
    lea  rcx, [rel command_auth_hex_digits]
.loop:
    test r9, r9
    jz   .done
    lea  rax, [r10 + 2]
    cmp  rax, r11
    ja   .done
    movzx eax, byte [r8]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    mov  al, [rcx + rax]
    mov  [r10], al
    mov  dl, [rcx + rdx]
    mov  [r10 + 1], dl
    add  r10, 2
    inc  r8
    dec  r9
    jmp  .loop
.done:
    mov  byte [r10], 0
    mov  [rel command_auth_out_cur], r10
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_auth_0 0
align 8
command_auth_lock:          dq 0
net_access_last_blocked:    db 0      ; 1 = this request's principal was blocked by its network policy
net_audit_tok:              times NET_AUDIT_TOK_MAX db 0
align 8
command_auth_remote_ticket: dq 0
command_auth_last_sequence: dq 0      ; H: highest admitted this boot (internal minters read H, never R)
command_auth_reserved_through: dq 0   ; R: highest sequence a verified write reserved
command_auth_seal:          dq -1     ; sec/replay_floor F': nothing above it is admitted this boot
command_auth_accept_count:  dq 0
command_auth_deny_count:    dq 0
command_auth_ref_required:  dq 0
command_auth_remote_active: db 0
command_auth_durable_ready: db 0
command_auth_out_ready:     db 0
command_auth_refusal_ready: db 0
command_auth_replay_state:  db AUTH_REPLAY_POISONED
command_auth_resv_state:    db AUTH_RESV_FAILED
command_auth_resv_error:    db AUTH_RESV_E_RECORD
command_auth_aihook_gate_proved: db 0
command_auth_serial_gate_proved: db 0
command_auth_last_reason: db 0
command_auth_node_src:    db AUTH_NODE_SRC_NONE   ; latched once per boot (command_auth_node_id_ensure)
times 41 db 0                  ; command_auth_node_id..command_auth_replay_verify moved to WDATA_svc_command_auth_0_bss1: keeps the labels below at their offset mod 64
command_auth_replay_size:   dq AUTH_REPLAY_SIZE
command_auth_verify_size:   dq AUTH_REPLAY_SIZE
times 28 db 0                  ; command_auth_replay_attrs..command_auth_keyid_kat_refused moved to WDATA_svc_command_auth_0_bss2: keeps the labels below at their offset mod 64

; The Boot-v2 owner public modulus lives at layer 0 (boot/boot_v2_handoff.asm,
; boot_v2_owner_modulus) so the pre-EBS manifest check pins the same key; this
; module keeps its historical name for it.
command_auth_owner_modulus equ boot_v2_owner_modulus
%ifndef BOOT_V2_OWNER_KEY_ID_BYTES
%error "boot-v2-owner-key.inc is not included (make build generates it from BOOT_V2_OWNER_PUBLIC_KEY)"
%endif
align 8
command_auth_owner_key_id:
    db BOOT_V2_OWNER_KEY_ID_BYTES           ; SHA-256 of the owner key's DER SubjectPublicKeyInfo, generated with
                                            ; boot_v2_owner_modulus from BOOT_V2_OWNER_PUBLIC_KEY
    times -((($ - command_auth_owner_key_id) - 32) * (($ - command_auth_owner_key_id) - 32)) db 0  ; exactly 32 B

command_auth_domain: db "PAOS-CMD-AUTH2",0,0
command_auth_hex_digits: db "0123456789abcdef"

; 6c619bd2-4254-4c7c-a28e-e1ba71e443d8 (command replay namespace)
command_auth_replay_guid:
    dd 0x6C619BD2
    dw 0x4254, 0x4C7C
    db 0xA2,0x8E,0xE1,0xBA,0x71,0xE4,0x43,0xD8
command_auth_replay_name:
    dw 'P','a','O','S','C','o','m','m','a','n','d','A','u','t','h','R','e','p','l','a','y',0
str_auth_nvg_tag: db "command_auth_replay_floor",0

; --- Secure Boot sense data (snapshot captured pre-EBS, reported by SECUREBOOT) ---
sb_efi_global_guid:                       ; EFI_GLOBAL_VARIABLE 8be4df61-93ca-11d2-aa0d-00e098032b8c
    dd 0x8be4df61
    dw 0x93ca, 0x11d2
    db 0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c
sb_moklist_guid:                          ; MOK RT 605dab50-e046-4300-abb6-3dd810dd8b23
    dd 0x605dab50
    dw 0xe046, 0x4300
    db 0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23
sb_name_secureboot: dw 'S','e','c','u','r','e','B','o','o','t',0
sb_name_setupmode:  dw 'S','e','t','u','p','M','o','d','e',0
sb_name_moklistrt:  dw 'M','o','k','L','i','s','t','R','T',0
sb_snap_attrs:      dd 0
sb_snap_size:       dq 0
sb_snap_databuf:    times 8 db 0
sb_num_buf:         times 24 db 0
pbm_sb_snapshot_valid: db 0               ; 1 = SecureBoot GetVariable value captured successfully
pbm_sb_secureboot:     db 0xFF            ; 0=off 1=on 0xFF=unread
pbm_sb_setupmode:      db 0xFF            ; 0=user-mode 1=setup-mode 0xFF=unread
pbm_sb_mok_present:    db 0xFF            ; 1=MokListRT present at runtime 0xFF=unread
str_verb_secureboot: db "SECUREBOOT",0
str_verb_authfloor: db "AUTHFLOOR",0
str_auth_floor_arg: db "RESEED",0
str_auth_floor_usage: db "AUTHFLOOR REFUSED usage=AUTHFLOOR_RESEED",0
str_auth_floor_not_console: db "AUTHFLOOR REFUSED console_owner_only",0
str_auth_floor_not_lost: db "AUTHFLOOR REFUSED floor_not_lost",0
str_auth_floor_failed: db "AUTHFLOOR REFUSED stage_failed",0
str_auth_floor_staged: db "AUTHFLOOR RESEED staged floor=",0
str_auth_floor_gen: db " generation=",0
str_verb_r0stat:     db "R0STAT",0
str_r0stat_ok:       db "R0STAT OK ARG=",0
str_r0stat_session:  db " BOOT_SESSION=",0
str_r0stat_rung:     db " rung=R0-0 read_only=1 source=pre_ebs ran=",0
str_r0stat_sep:      db " ",0
str_r0stat_bad:      db "R0STAT REFUSED bad_nonce",0
str_sb_pre:        db "SECUREBOOT snapshot=",0
str_sb_secureboot: db " secureboot=",0
str_sb_setupmode:  db " setupmode=",0
str_sb_mok:        db " mok_present=",0
str_sb_pk_health: db " pk_health=",0
str_sb_rtmap:      db " runtime_mapped=",0
str_sb_replay:     db " replay_state=",0
str_sb_snap_pre:   db "[secureboot.snapshot] sb=",0
str_sb_snap_setup: db " setup=",0
str_sb_snap_mok:   db " mok=",0

str_auth_verb_help:   db "HELP",0
str_auth_verb_status: db "AUTHSTAT",0
str_auth_verb_verbs:  db "AUTHVERBS",0
str_auth_verbs_pre:   db "AUTHVERBS registry_rows=",0
str_auth_verbs_public: db " public=",0
str_auth_verbs_names: db " names=",0
str_auth_verbs_trunc: db 13,10,"AUTHVERBS truncated shown=",0
str_auth_verbs_locked: db "AUTHVERBS locked=",0
str_auth_verbs_locked_public: db " locked_public=",0
str_auth_verbs_locked_names: db " locked_names=",0
str_auth_verb_boot:   db "BOOT",0
str_auth_refused: db "AUTH_REFUSED reason=",0
str_auth_verb: db " verb=",0
str_auth_seq: db " seq=",0
str_auth_required: db " required_cap=",0
str_auth_presented: db " presented_cap=",0
str_auth_zero_effect: db " mutation_effects=0 owner_key_id=",0
str_auth_receipt_sig: db " receipt_sig=",0
str_auth_receipt_unavailable: db " receipt_sig=unavailable",0
str_auth_unknown: db "unknown",0
str_auth_reason_unsigned: db "unsigned",0
str_auth_reason_malformed: db "malformed",0
str_auth_reason_wrong_key: db "wrong_key",0
str_auth_reason_expired: db "expired",0
str_auth_reason_wrong_cap: db "wrong_capability",0
str_auth_reason_replay: db "replay",0
str_auth_reason_durable: db "durable_commit_failed",0
str_auth_reason_principal: db "principal_capability_denied",0
str_auth_reason_desktop_locked: db "desktop_locked",0
str_auth_reason_unknown: db "unknown_destructive_verb",0
str_auth_reason_auth1_retired: db "auth1_retired",0
str_auth_reason_wrong_node: db "wrong_node",0
str_auth_reason_card_required: db "card_required",0
str_auth_stat_format: db " auth_format=2 node_id=",0
str_auth_stat_node_src: db " node_id_src=",0
str_auth_stat_node_none: db "none node_id_src=none",0
str_auth_node_src_smbios: db "smbios",0
str_auth_node_src_mac: db "mac",0
str_net_audit_unknown: db "?",0
str_net_audit_none: db "-",0
str_net_audit_wrong_cap: db "wrong_cap",0
str_net_audit_durable: db "durable",0
str_net_audit_capability: db "capability",0
str_net_audit_unknown_verb: db "unknown_verb",0
str_net_audit_refused: db "refused",0
str_net_audit_policy: db "policy",0
str_auth_stat_pre: db "AUTHSTAT registry_classifier_counts=live registry_read=",0
str_auth_stat_rmut: db " registry_mut=",0
str_auth_stat_iread: db " intercept_read=",0
str_auth_stat_imut: db " intercept_mut=",0
str_auth_stat_comma: db ",",0
str_auth_stat_signing: db " owner_key_id=",0
str_auth_stat_policy: db " policy_classifier=command_auth_required_cap default=deny signature=rsa2048 capability=exact sequence_check=1 expiry_max_s=300 replay_floor=state_dependent persisted_when_valid=1",0
str_auth_stat_node: db " node_identity="
.len equ $ - str_auth_stat_node
db 0
str_auth_node_absent: db "absent",0
str_auth_node_active: db "active",0
str_auth_stat_replay: db " replay_state=",0
str_auth_stat_last: db " last_seq=",0
str_auth_stat_accept: db " accepted=",0
str_auth_stat_deny: db " denied=",0
str_auth_stat_jobs: db " jobs=",0
str_auth_stat_wall: db " wall_now=",0
str_auth_stat_aihook: db " aihook_unsigned_mutator_denied=",0
str_auth_stat_serial: db " serial_unsigned_mutator_denied=",0
str_auth_stat_reserved: db " sequence_reserved_through=",0
str_auth_stat_next_min: db " sequence_next_min=",0
str_auth_stat_next_none: db "none",0
str_auth_stat_resv_state: db " reservation_state=",0
str_auth_stat_resv_error: db " last_reservation_error=",0
str_auth_stat_principals: db " principal_owner_id=1 owner_role=sovereign principal_system_id=2 system_role=operator system_credential_ready=",0
str_auth_stat_principal_ready: db " principal_table_ready=",0
str_auth_stat_bind_ready: db " principal_bind_ready=",0
str_auth_stat_gate_ready: db " principal_gate_ready=",0
str_auth_stat_lock_ready: db " principal_lock_ready=",0
str_auth_stat_guest: db " guest_ephemeral_kat=",0
str_auth_stat_2500_table: db " authz.principal.table",0
str_auth_stat_2500_bound: db " authz.principal.bound",0
str_auth_stat_2500_gate: db " authz.principal.gate",0
str_auth_stat_2500_deny: db " authz.principal.deny",0
str_auth_stat_1054_dek: db " crypto.dek",0
str_auth_stat_1054_envelope: db " crypto.envelope",0
str_auth_stat_1054_owner: db " crypto.owner",0
str_auth_stat_1057_header: db " db.header",0
str_auth_stat_1057_durable: db " db.durable",0
str_auth_stat_1057_atrest: db " db.atrest",0
str_auth_stat_2501_bind: db " auth.seam.bind",0
str_auth_stat_2501_method: db " auth.seam.method",0
str_auth_stat_2501_pbkdf2: db " auth.password.pbkdf2",0
str_auth_stat_2501_system: db " auth.system.credential",0
str_auth_filmstrip_exact:  db "FILMSTRIP",0
str_auth_filmstrip_prefix: db "FILMSTRI",0
str_auth_filmstrip_suffix: db "FILMSTRIPX",0
str_auth_filmstrip_near:   db "FILMSTRIQ",0
str_auth_keyid_kat_verb: db "AUTHKEYFMT_KAT",0
str_auth_keyid_kat_row: db "AUTHKEYFMT_V1 nonce=",0
str_auth_keyid_kat_expected: db " expected=",0
str_auth_keyid_kat_authstat: db " authstat=",0
str_auth_keyid_kat_refused: db " refused=",0
str_auth_keyid_kat_hardcoded: db " hardcoded_old=0",0
str_auth_keyid_kat_marker: db "[PAOS64] auth: runtime owner key-id formatting KAT PASS [auth.owner_keyid.runtime]",0
str_auth_node_state_marker: db "[PAOS64] M6 security: runtime node identity state observable PASS [security.node_identity.state.observable]",13,10,0
%endmacro
WDATA_DEFER WDATA_svc_command_auth_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_auth_0_bss1 0
resb 19                 ; keeps command_auth_node_id at its WDATA offset mod 64
command_auth_node_id:     resb AUTH_NODE_ID_LEN
command_auth_wire_node:   resb AUTH_NODE_ID_LEN
command_auth_node_hex:    resb (AUTH_NODE_ID_LEN * 2 + 1)
command_auth_m_principal_table: resb 1
command_auth_m_principal_bound: resb 1
command_auth_m_principal_gate:  resb 1
command_auth_m_principal_deny:  resb 1
alignb 8
command_auth_intercept_count: resd 1
command_auth_inv_iread:       resd 1
command_auth_inv_imut:        resd 1
command_auth_intercepts: resb (AUTH_INT_MAX * AUTH_INT_SIZE)
command_auth_message:    resb AUTH_MSG_MAX
command_auth_signature:  resb 256
command_auth_receipt_signature: resb 64
command_auth_principal_test_ticket: resb AUTH_T_SIZE
command_auth_bind_ctx: resb AUTH_CTX_SIZE
command_auth_num_buf: resb 24
command_auth_replay_record: resb AUTH_REPLAY_SIZE
command_auth_replay_verify: resb AUTH_REPLAY_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_auth_0_bss1
%macro WDATA_svc_command_auth_0_bss2 0
resb 12                 ; keeps command_auth_replay_attrs at its WDATA offset mod 64
command_auth_replay_attrs:  resd 1
command_auth_verify_attrs:  resd 1
command_auth_out_cur: resq 1
command_auth_owner_keyid_last_start: resq 1
command_auth_out_buf: resb AUTH_OUT_MAX
command_auth_keyid_kat_expected: resb 65
command_auth_keyid_kat_authstat: resb 65
command_auth_keyid_kat_refused: resb 65
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_auth_0_bss2
; SEC-authverbs-hook-handoff: the ticket this request's public floor consumed, its one inner admission, and
; authorize's per-call mode. remote_end and every ordinary consumption clear the hand-off.
%macro WDATA_svc_command_auth_handoff_bss 0
alignb 8
command_auth_floor_ticket:  resq 1
command_auth_floor_handoff: resb 1
command_auth_handoff_now:   resb 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_auth_handoff_bss
%ifdef PAOS_NODE_IDENTITY_TEST_ACTIVE_FIXTURE
str_auth_fixture_active: db " node_identity=active ",0
str_auth_fixture_jobpub: db "JOBPUB",0
str_auth_fixture_jobpub_expected: db "PUB=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a ALG=ed25519",0
str_auth_node_fixture_marker: db "[PAOS64] M6 security: forbidden identity fixture observed AUTHSTAT node_identity=active JOBPUB=PUB=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a ALG=ed25519 [security.node_identity.state.forbidden_control]",13,10,0
str_auth_node_fixture_fail: db "[PAOS64] M6 security: forbidden identity fixture did not traverse AUTHSTAT and JOBPUB handler/output control FAIL",13,10,0
align 8
command_auth_node_fixture_req: times REQ_SZ db 0
command_auth_node_fixture_rsp: times RSP_SZ db 0
%endif
str_auth_ai_probe: db "AUTHAIPROBE nonce=",0
str_auth_ai_code: db " dispatch_code=",0
str_auth_ai_before: db " jobs_before=",0
str_auth_ai_after: db " jobs_after=",0
str_auth_principal_test_verb: db "BOOT NON-WIRE-WHITEBOX",0

str_auth_m_principal_table: db "[PAOS64] identity rung 2500: fail-closed pid to capability-word table live [authz.principal.table]",13,10,0
str_auth_m_principal_bound: db "[PAOS64] identity rung 2500: verified owner credential bound through authenticate_bind [authz.principal.bound]",13,10,0
str_auth_m_principal_gate: db "[PAOS64] identity rung 2500: command authorization keyed to ticket principal [authz.principal.gate]",13,10,0
str_auth_m_principal_deny: db "[PAOS64] identity rung 2500: NON-WIRE whitebox system principal denied sovereign BOOT capability [authz.principal.deny]",13,10,0
str_auth_publicity_shipped: db "[PAOS64] M6 security: shipped public floor confidentiality and live inventory PASS [security.publicity.confidentiality]",13,10,0
str_auth_publicity_lab: db "[PAOS64] M6 security: lab public floor FSLS control PASS [security.publicity.lab]",13,10,0
; SEC-P2-release: the payload states its public floor in plain bytes, exactly once,
; so release tooling (gauntlet_v2/tools/release_floor_guard.py) can refuse a lab build.
%if PAOS_PUBLICITY_LAB_PROFILE
str_auth_floor_identity: db "PAOS-FLOOR publicity=lab", 0
%else
str_auth_floor_identity: db "PAOS-FLOOR publicity=shipped", 0
%endif
str_auth_publicity_fail: db "[PAOS64] M6 security: public floor profile/inventory KAT FAIL",13,10,0
str_auth_publicity_stage: db "[PAOS64] public floor failure stage (1=census 2=filmstrip 3=fsls 4=intercept 5=session 6=ping 7=recovery): ",0
str_auth_recovery_floor: db "C2RECOVERY",0
