;; MODULE sec/principal
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS principal_try_local_begin, principal_first_owner_available, principal_first_owner_stage, principal_selftest, principal_authorization_selftest, principal_declare, principal_switch, principal_current, principal_execution_snapshot, principal_restore_execution, principal_restore_active, principal_capabilities, principal_derive, principal_credential, principal_system_auth_credential, principal_credentials_init, principal_enter_system, principal_leave_system, principal_clear_bound, principal_boot_fixture_begin, principal_boot_fixture_end, principal_boot_fixture_close, authenticate_bind, cmd_verb_prinwrite, cmd_verb_prinread, cmd_verb_prinswitch, cmd_verb_prinkdf, principal_local_password, principal_push_handle, principal_wipe_owner_boot_key, principal_system_status_append
;; IMPORTS sec/wifi_profile, boot/boot_v2_handoff, core/capability, core/lock, core/lib/ed25519, svc/ssh_auth, core/lib/auth_derive, core/lib/pbkdf2_sha256, core/lib/hkdf_sha256, core/lib/aes256_gcm, core/csprng, core/time, core/lib/fmt, core/lib/mem, data/kvstore, fs/safe_write, sec/session, svc/command, svc/command_auth, svc/command_aihook, svc/command_udp, svc/push_auth, boot/serial, fs/storage_access, boot/nvram_access, config/keep_config, core/reset_wipe, sec/system_secret, sec/replay_floor, sec/owner_store, sec/wifi_store
;; CAPS
;; OWNER saga:sec
;; LOCK: prin_state_lock PROTECTS principal_cap_table, authenticate_bind_table
;; LOCK: prin_credential_lock PROTECTS prin_password_salt, prin_password_iterations, prin_password_verifier, prin_password_enrolled, prin_owner_session_ready, prin_system_secret_ready, prin_password_failures, prin_password_last_sequence, prin_password_backoff_until, prin_owner_session_key, prin_system_secret, prin_owner_boot_key, prin_owner_boot_ready, prin_system_bs, prin_record_moved, prin_system_lost, prin_sysx_scrub_tried, prin_sysx_scrub_result, prin_sysx_rt_version, prin_moved_seq
; ============================================================================
; sec/principal.asm — the NON-RETROFITTABLE PRINCIPAL seam (contract 1053,
; SECURITY §8 / FOUNDATION_CONTRACT_CHECKLIST §2 / PRINCIPLES §1). Every
; task/log/row carries an owning-principal id from v1; v1 is degenerate-to-one
; (a single OWNER, id=1). Three seams EXIST at v1 so principal #2 / guest /
; steward add later as DATA, not as a format change (encrypt/tag-later =
; rewrite-every-record):
;   (1) OWNER established — a fixed non-NULL principal id (principal_current).
;       marker [principal.owner]
;   (2) TAGGED task/log/row — the owning-principal id field is IN the header of
;       the task descriptor (core/sched task.principal), the log line
;       (log_current_principal -> "[pid=N]"), and the stored data row (a
;       WRITTEN row round-trips its pid + a random token). marker [principal.tagged]
;   (3) PAGING-DOMAIN SWITCH PATH — principal_switch() saves CR3, RELOADS the
;       page-table root (a real `mov cr3` — TLB flush, the switch SITE executes),
;       and restores it. v1 = OWNER->OWNER (target==current: degenerate-to-one),
;       so cr3_restored == cr3_saved. marker [principal.switch]
;   (4) AUTH KDF DERIVE — authenticate() DERIVES a key via RFC5869 HKDF-SHA256
;       (cred+salt -> key material), it does NOT verify a stored hash. A KAT
;       proves the derive is real, deterministic arithmetic (1054's crypto DATA
;       key keys off THIS derived key). marker [principal.kdf]
;
; LIVE UDP surface (staged into prin_out_buf, framed by command_udp.asm — the
; SAME per-command staging pattern thermal/reinit/boot_ab/command_gui use):
;   PRINWRITE <pid> <token>  -> store a row tagged with pid carrying token; the
;       DETERMINISTIC BARRIER rejects any pid != OWNER (cross-principal write
;       denied — the barrier is code, never the AI, SECURITY §8). Reply
;       "PRINWRITE ACK pid=N token=..." or "ERR cross_principal_write_denied".
;   PRINREAD  <pid>          -> "pid=N token=..." (the exact stored token +
;       the pid it was written under; per-principal read-back). A foreign pid
;       with no row -> "pid=N no row" (the forged token is absent).
;   PRINSWITCH               -> "SW=ok cr3_saved=0x.. cr3_restored=0x.."
;   PRINKDF <salt_hex> <cred>-> "DK=<hex>" (the derived key, real arithmetic).
;       A wrong cred derives a DIFFERENT key (never the owner key).
;
; PORT NOTE (M16): this REUSES the reviewed RFC5869 HKDF-SHA256 primitive from
; core/lib. The former SplitMix compatibility KDF is not a security boundary.
; command_udp.asm is %included AFTER this module so its [rel prin_out_buf] /
; [rel prin_m_*] references resolve to data defined here (mirrors the
; resilience/boot_ab ordering note).
; ============================================================================

PRIN_OWNER       equ 1               ; human owner: sovereign principal
PRIN_SYSTEM      equ 2               ; AI operator, distinct from the sovereign owner
PRIN_TRY         equ 4               ; volatile local desktop; no standing caps or bind method
PRIN_ADVISOR     equ 3               ; in-process Guardian advisor: NO verb authority (GA2(b))
; RC household voice user (sec/household). Like Try it has no principal_cap_table
; row, so principal_capabilities gives it the empty word; it acts only through
; sec/household's admitted request for an owner-marked public-floor verb.
PRIN_HOUSEHOLD   equ 5
%ifndef AUTH_BIND_OWNER_RSA
AUTH_BIND_OWNER_RSA equ 1            ; verified Boot-v2/AUTH1 owner RSA method
AUTH_BIND_PASSWORD  equ 2
AUTH_BIND_SYSTEM_KEY equ 3
AUTH_BIND_ED25519   equ 4
%endif

PRIN_PMCAPS equ (PMCAP_LOG | PMCAP_MMIO | PMCAP_BLOCK_READ | PMCAP_BLOCK_WRITE | PMCAP_NET | PMCAP_COMPUTE)
PRIN_OPERATIONAL_CAPS equ (PRIN_PMCAPS | CMD_AUTH_CAP_MUTATE | CMD_AUTH_CAP_HOTPATCH | CMD_AUTH_CAP_PERSIST | CMD_AUTH_CAP_EXTENSION)
PRIN_REQUIRED_CAPS equ (PRIN_OPERATIONAL_CAPS | CMD_AUTH_CAP_BOOT)
PRIN_SOVEREIGN_FLOORS equ (CMD_AUTH_CAP_BOOT | CMD_AUTH_CAP_SOVEREIGN_CONTROL | CMD_AUTH_CAP_RECOVERY_REMOVAL)
PRIN_OWNER_CAPS  equ (PRIN_REQUIRED_CAPS | CMD_AUTH_CAP_SOVEREIGN_CONTROL | CMD_AUTH_CAP_RECOVERY_REMOVAL)
; SEC-S5cap (Peter ruling A1, 2026-08-28): the machine-owner key is the sole
; authority for live code execution. The AI operator principal never holds
; HOTPATCH (ring-0 detour) or PERSIST (its boot-replayed form), whatever route a
; later rung opens to the hotpatch intercepts.
PRIN_SYSTEM_CAPS equ (PRIN_OPERATIONAL_CAPS & ~(CMD_AUTH_CAP_HOTPATCH | CMD_AUTH_CAP_PERSIST))
; SEC-GA2(b) (admin 10/08 01:26, RC spec 10.5): the advisor's capability word
; is EMPTY. It holds no verb authority at all - command_auth_authorize refuses
; every advisor ticket before any cap check - and reads the security spine only
; through the in-process audit_sec_advisor_view.
PRIN_ADVISOR_CAPS equ 0

%if (PRIN_OWNER_CAPS & PRIN_REQUIRED_CAPS) != PRIN_REQUIRED_CAPS
    %error "owner principal does not cover the closed required-cap vocabulary"
%endif
%if (PRIN_SYSTEM_CAPS & PRIN_SOVEREIGN_FLOORS) != 0
    %error "system principal acquired a sovereign/recovery floor"
%endif
%if (PRIN_SYSTEM_CAPS & (CMD_AUTH_CAP_HOTPATCH | CMD_AUTH_CAP_PERSIST)) != 0
    %error "system principal acquired live code execution (HOTPATCH/PERSIST are owner-only, Peter A1)"
%endif
%if PRIN_ADVISOR_CAPS != 0
    %error "advisor principal acquired a capability (GA2(b): its word is empty)"
%endif

PRIN_CAP_ROW_PID  equ 0
PRIN_CAP_ROW_CAPS equ 8
PRIN_CAP_ROW_SIZE equ 16
AUTH_BIND_ROW_METHOD equ 0
AUTH_BIND_ROW_PID    equ 8
AUTH_BIND_ROW_SIZE   equ 16
%ifndef AUTH_CTX_SIZE
AUTH_CTX_CREDENTIAL  equ 0
AUTH_CTX_CRED_LEN    equ 8
AUTH_CTX_SEQUENCE    equ 16
AUTH_CTX_ISSUED      equ 24
AUTH_CTX_EXPIRES     equ 32
AUTH_CTX_ASSERTED_PID equ 40          ; input is deliberately ignored for binding
AUTH_CTX_TEMP_CAP    equ 48           ; reserved elevation context, inactive in v1
AUTH_CTX_TEMP_EXPIRY equ 56
AUTH_CTX_AUDIT_REF   equ 64
AUTH_CTX_SIZE        equ 72
%endif
PRIN_CREDENTIAL_LEN  equ 32
; Task2142 AUTH_BIND_ED25519 credential: a pointer to this proof. The seam
; itself checks that PUB is an enrolled SSH user key AND that SIG verifies
; over MSG (the caller's RFC 4252 session-bound blob); the caller supplies
; evidence, never the principal.
AUTH_ED25519_PROOF_PUB     equ 0
AUTH_ED25519_PROOF_MSG     equ 8
AUTH_ED25519_PROOF_MSG_LEN equ 16
AUTH_ED25519_PROOF_SIG     equ 24
AUTH_ED25519_PROOF_SIZE    equ 32
PRIN_PASSWORD_SALT_LEN equ 16
PRIN_PASSWORD_VERIFIER_LEN equ 32
; S1b-2c: who holds the local password this boot (prin_owner_authority_apply)
PRIN_PWA_RT          equ 0              ; no owner store decision: the RT verifier (UNOWNED residual)
PRIN_PWA_STORE       equ 1              ; owner store LOADED: the BS record decides
PRIN_PWA_LOCKED      equ 2              ; owner store CORRUPT/FAILED: no local password
PRIN_ENROLL_STORE_OWNED equ -2          ; enroll refused: the owner store holds the password
PRIN_OWNER_PW_LEN    equ 52             ; = OWS_PW_LEN: iterations, salt, verifier
; owner_store's states, mirrored (it is included after this module and asserts them)
PRIN_OWS_LOADED      equ 1
PRIN_OWS_UNOWNED     equ 2
PRIN_OWS_CORRUPT     equ 3
PRIN_OWS_FAILED      equ 4
PRIN_OWS_STUCK_SLOTS equ 0x30                ; ows_planted bits 4+5: both slot names undeletable
PRIN_OWS_STUCK_STAGE equ 0x40                ; ows_planted bit 6: the stage name undeletable
%define PRIN_OWS_MIRROR 1
PRIN_AUTH_MAX_TTL    equ 300
PRIN_PASSWORD_MAX    equ 128             ; private credential snapshot bound
PRIN_RECORD_MAGIC    equ 0x52444950      ; "PIDR"
PRIN_RECORD_VERSION  equ 2
PRIN_RECORD_SIZE     equ 208
PRIN_V1_SIZE         equ 128
PRIN_REC_MAGIC       equ 0
PRIN_REC_VERSION     equ 4
PRIN_REC_SIZE        equ 6
PRIN_REC_FLAGS       equ 8
PRIN_REC_ITERATIONS  equ 12
PRIN_REC_SALT        equ 16
PRIN_REC_VERIFIER    equ 32
%if PRIN_REC_SALT + PRIN_PASSWORD_SALT_LEN != PRIN_REC_VERIFIER
    %error "S1b-2c persist copies RT salt+verifier as one run"
%endif
PRIN_REC_SYSTEM      equ 64
PRIN_REC_FAILURES    equ 96
PRIN_REC_LAST_SEQ    equ 104
PRIN_REC_BACKOFF     equ 112
PRIN_REC_CRC         equ 204
PRIN_REC_PASSWORD    equ 1
PRIN_REC_DATA_WRAP   equ 2
PRIN_REC_WRAP        equ 128
PRIN_WRAP_SIZE       equ 64            ; nonce12 + reserved4 + ct32 + tag16
PRIN_EFI_NOT_FOUND   equ 0x800000000000000E
; SEC slice 2 (root GO 12:58, 14:05 (b)): once this boot holds the SYSTEM secret's
; NV|BS copy (sec/system_secret) and its verified manifest is migration-aware, the
; record is rewritten as version 3 (either size): flag PRIN_REC_SYSTEM_MOVED set,
; no SYSTEM bytes, and the authorizing manifest sequence at PRIN_REC_MOVED_SEQ
; (the durable log of the scrub). Older images accept only v1/v2, so they refuse
; a v3 record instead of reading a zero secret.
PRIN_RECORD_VERSION_MOVED equ 3
PRIN_REC_SYSTEM_MOVED equ 4
PRIN_REC_MOVED_SEQ   equ PRIN_REC_SYSTEM ; dq; bytes +8..+31 of the old SYSTEM field stay zero

%if (PRIN_REC_CRC + 4) != PRIN_RECORD_SIZE
    %error "principal durable credential record size drift"
%endif
PRIN_TOKEN_MAX   equ 72              ; max stored token length (XYZZY-<16hex> + slack)
PRIN_DK_LEN      equ 16              ; derived-key length in bytes (32 hex chars)
PRIN_SALT_MAX    equ 16              ; max KDF salt bytes (32 hex chars)

; principal_current -> RAX = the active authenticated execution principal.
principal_current:
    mov  rax, [rel prin_active_pid]
    ret

; BSP request frame snapshot: RAX=execution PID, RDX=local-session epoch.
; The epoch prevents teardown from resurrecting authority after lock/rebind.
principal_execution_snapshot:
    mov  rax, [rel prin_active_pid]
    mov  rdx, [rel session_authority_epoch]
    ret

; RDI=saved execution PID, RSI=saved local-session epoch. A local-session
; transition owns its new state; otherwise restore this frame's exact PID.
principal_restore_execution:
    cmp  rsi, [rel session_authority_epoch]
    jne  .changed
    jmp  principal_restore_active
.changed:
    ret

; principal_restore_active(RDI=pid) — a request-scoped remote projection (SSH
; exec) restores the local-session principal it observed before dispatch, so
; no remote request can leave authority behind in the local session.
principal_restore_active:
    push rdi
    call prin_state_lock_acquire
    pop  rdi
    mov  [rel prin_active_pid], rdi
    jmp  prin_state_lock_release

; principal_credential(RDI=pid) -> RAX=session key handle, RDX=len, or 0/0.
; OWNER never returns a password, PBKDF2 master, verifier, or KEK-input bytes.
; NULL is the reserved guest consumer hook and therefore has no durable key.
principal_credential:
    test rdi, rdi
    jz   .none
    cmp  rdi, [rel prin_active_pid]
    jne  .none
    cmp  rdi, PRIN_OWNER
    je   .owner
    cmp  rdi, PRIN_SYSTEM
    jne  .none
    cmp  byte [rel prin_system_secret_ready], 1
    jne  .none
    lea  rax, [rel prin_system_secret]
    mov  edx, PRIN_CREDENTIAL_LEN
    ret
.owner:
    cmp  byte [rel prin_owner_session_ready], 1
    jne  .none
    lea  rax, [rel prin_owner_session_key]
    mov  edx, PRIN_CREDENTIAL_LEN
    ret
.none:
    xor  eax, eax
    xor  edx, edx
    ret

; Internal AI ingress credential source. It is never projected onto a wire or
; returned in a command response; authenticate_bind compares it in constant time.
principal_system_auth_credential:
    cmp  byte [rel prin_system_secret_ready], 1
    jne  .none
    lea  rax, [rel prin_system_secret]
    mov  edx, PRIN_CREDENTIAL_LEN
    ret
.none:
    xor  eax, eax
    xor  edx, edx
    ret

; A public Try desktop has a distinct principal, never OWNER or SYSTEM.
; Only the native boot/local frame may establish it, from an accepted Manager
; Try handoff. No authentication method, standing-capability row or credential
; is added: principal_capabilities and principal_credential both return zero.
; RAX=PRIN_TRY/0; caller owns the local session epoch, not a credential grant.
principal_try_local_begin:
    cmp  byte [rel pbm_manager_launch], 1
    jne  .bad
    cmp  byte [rel pbm_try_media], 1
    jne  .bad
    cmp  byte [rel command_auth_remote_active], 0
    jne  .bad
    cmp  byte [rel session_injected_input], 0
    jne  .bad
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .bad
    call prin_state_lock_acquire
    cmp  qword [rel prin_active_pid], 0
    jne  .busy
    mov  qword [rel prin_active_pid], PRIN_TRY
    call prin_state_lock_release
    mov  eax, PRIN_TRY
    ret
.busy:
    call prin_state_lock_release
.bad:
    xor  eax, eax
    ret

principal_enter_system:
    mov  qword [rel prin_active_pid], PRIN_SYSTEM
    ret

principal_leave_system:
    mov  qword [rel prin_active_pid], PRIN_OWNER
    ret

; Clear the live principal and every transient OWNER session-key byte. The
; machine-held SYSTEM credential remains available for a later authenticated bind.
principal_clear_bound:
    ; Locked presentation clears the transient principal on every refresh.
    ; Push challenges instead track the session authority epoch, so a refresh
    ; cannot destroy an approval before the owner can consume it.
    call prin_state_lock_acquire
    mov  qword [rel prin_active_pid], 0
    call prin_state_lock_release
    call prin_credential_lock_acquire
    mov  byte [rel prin_owner_session_ready], 0
    lea  rdi, [rel prin_owner_session_key]
    xor  esi, esi
    mov  edx, PRIN_CREDENTIAL_LEN
    call memset
    call prin_credential_lock_release
    ret

; Caller holds prin_credential_lock and has just set prin_owner_session_ready.
; Root 12:58 (P1 consequence a): after a password sign-in the owner's key stays
; in RAM for this boot, so a later PUSH unlock of a LOCKED session regains DATA.
prin_owner_boot_capture:
    lea  rdi, [rel prin_owner_boot_key]
    lea  rsi, [rel prin_owner_session_key]
    mov  edx, PRIN_CREDENTIAL_LEN
    call memcpy
    mov  byte [rel prin_owner_boot_ready], 1
    ret

; Wipe the boot copy and the 2FA stage before anything leaves DRAM to a reset
; or another OS: power_execute (and the M1 seal through it), the serial BOOT WIN
; reset and the UDP REBOOT/DBPUTKILL/BOOT reset (root 14:10: no remanence of O
; across a warm reset). The live session key is principal_clear_bound's.
principal_wipe_owner_boot_key:
    call prin_credential_lock_acquire
    mov  byte [rel prin_owner_boot_ready], 0
    lea  rdi, [rel prin_owner_boot_key]
    xor  esi, esi
    mov  edx, PRIN_CREDENTIAL_LEN
    call memset
    call prin_credential_lock_release
%if !PAOS_PUBLIC_BUILD
    jmp  push_auth_wipe_stage
%else
    ret
%endif

; principal_push_handle(RDI=out32) -> EAX=0 and out = H, the push record's
; one-way handle HKDF-SHA256(IKM=owner key, salt=password salt,
; info='paos-push-handle-v1'); EAX=-1 with out untouched when no owner key is
; in RAM. H names the key without revealing it.
%if !PAOS_PUBLIC_BUILD
principal_push_handle:
    push rbx
    push r12                            ; alignment: principal_hkdf32 is called at rsp%16 == 0
    mov  rbx, rdi
    call prin_credential_lock_acquire
    mov  eax, -1
    cmp  byte [rel prin_owner_session_ready], 1
    jne  .out
    lea  rdi, [rel prin_owner_session_key]
    mov  esi, PRIN_CREDENTIAL_LEN
    lea  rdx, [rel prin_password_salt]
    mov  ecx, PRIN_PASSWORD_SALT_LEN
    lea  r8, [rel prin_push_handle_domain]
    mov  r9d, prin_push_handle_domain.len
    sub  rsp, 8
    mov  [rsp], rbx
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jz   .out
    mov  rdi, rbx                       ; a failed derive leaves no partial handle
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
.out:
    mov  r12d, eax
    call prin_credential_lock_release
    mov  eax, r12d
    pop  r12
    pop  rbx
    ret
%endif

; Promote a completed identity reply into command_auth's exclusive wire buffer.
; The generic UDP envelope is already near its clamp and previously truncated
; pid/key-handle evidence after the handler had actually succeeded. Keeping the
; identity record exclusive also prevents the scrubbed command argument from
; being reflected as an empty, ambiguous ARG field.
principal_publish_wire_reply:
    call command_auth_out_reset
    lea  rdi, [rel prin_out_buf]
    call command_auth_put_str
    mov  byte [rel prin_out_ready], 0
    mov  byte [rel command_auth_out_ready], 1
    ret

prin_state_lock_acquire:
    lea  rdi, [rel prin_state_lock]
    jmp  spin_acquire

prin_state_lock_release:
    lea  rdi, [rel prin_state_lock]
    jmp  spin_release

prin_credential_lock_acquire:
    lea  rdi, [rel prin_credential_lock]
    jmp  spin_acquire

prin_credential_lock_release:
    lea  rdi, [rel prin_credential_lock]
    jmp  spin_release

; principal_capabilities(RDI=principal id) -> RAX = authoritative cap word.
; The locked static table is the single standing-authority source.  A missing
; pid (including NULL) fails closed with an empty word.
principal_capabilities:
    mov  r10, rdi
    call prin_state_lock_acquire
    lea  r11, [rel principal_cap_table]
    mov  ecx, PRIN_CAP_TABLE_ROWS
.scan:
    test ecx, ecx
    jz   .none
    cmp  [r11 + PRIN_CAP_ROW_PID], r10
    je   .found
    add  r11, PRIN_CAP_ROW_SIZE
    dec  ecx
    jmp  .scan
.found:
    mov  rax, [r11 + PRIN_CAP_ROW_CAPS]
    call prin_state_lock_release
    ret
.none:
    xor  eax, eax
    call prin_state_lock_release
    ret

; Constant-time fixed-length equality. RDI=a, RSI=b, RDX=len -> EAX=1/0.
principal_ct_equal:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    test rdx, rdx
    jz   .done
    mov  r8b, [rdi]
    xor  r8b, [rsi]
    or   cl, r8b
    inc  rdi
    inc  rsi
    dec  rdx
    jmp  .loop
.done:
    test cl, cl
    setz al
    ret

; Derive a domain-separated 32-byte session key from IKM and salt.
; RDI=ikm,RSI=ikm_len,RDX=salt,RCX=salt_len,R8=info,R9=info_len,
; stack out32 -> 0/-1.
principal_hkdf32:
    push rbp
    mov  rbp, rsp
    sub  rsp, 16
    mov  rax, [rbp + 16]
    mov  [rsp], rax
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    add  rsp, 16
    pop  rbp
    ret

; authenticate_bind(RDI=method, RSI=verified AUTH_CTX)
; -> RAX=bound pid (0 on refusal), RDI=the same output-only pid,
;    RDX=session key HANDLE or 0. The ctx asserted-pid field is never read.
authenticate_bind:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, PRIN_CREDENTIAL_LEN       ; PUSH candidate; wiped before return
    mov  r12, rdi
    mov  r13, rsi
    test rsi, rsi
    jz   .miss_unlocked
    mov  r10, r12
    call prin_state_lock_acquire
    lea  r11, [rel authenticate_bind_table]
    mov  ecx, AUTH_BIND_TABLE_ROWS
.scan:
    test ecx, ecx
    jz   .miss
    cmp  [r11 + AUTH_BIND_ROW_METHOD], r10
    je   .found
    add  r11, AUTH_BIND_ROW_SIZE
    dec  ecx
    jmp  .scan
.found:
    mov  rbx, [r11 + AUTH_BIND_ROW_PID]
    call prin_state_lock_release
    ; PUSH verification opens the protected policy envelope and crosses the
    ; audit/notification teardown seams.  Never hold prin_credential_lock
    ; across that external call graph: stage the one-use result first, then
    ; install it atomically below.  The serialized command consumer and the
    ; challenge's session-epoch check remain the authority boundary.
    ; SEC-owner-key-in-push-record (P1): a PUSH approval is owner AUTHORITY
    ; only. The push record no longer holds the owner's DATA key, so the bind
    ; installs one only from RAM: the key a correct password staged for this
    ; very 2FA challenge, else the boot copy a password sign-in earlier in this
    ; boot left. Neither: the owner is bound without DATA until a password.
%if !PAOS_PUBLIC_BUILD
    cmp  r12, AUTH_BIND_PUSH
    jne  .credential_locked
    mov  rdi, r13
    mov  rsi, rsp
    call push_auth_take                 ; EDX=1: the candidate is this challenge's staged key
    test eax, eax
    jnz  .push_prepare_fail
    mov  r14d, edx
    call prin_credential_lock_acquire
    test r14d, r14d
    jz   .push_boot_key
    lea  rdi, [rel prin_owner_session_key]
    mov  rsi, rsp
    mov  edx, PRIN_CREDENTIAL_LEN
    call memcpy
    mov  byte [rel prin_owner_session_ready], 1
    call prin_owner_boot_capture        ; a completed 2FA is a password sign-in
    jmp  .push_wipe
.push_boot_key:
    cmp  byte [rel prin_owner_boot_ready], 1
    jne  .push_wipe                     ; authority only: no DATA handle
    lea  rdi, [rel prin_owner_session_key]
    lea  rsi, [rel prin_owner_boot_key]
    mov  edx, PRIN_CREDENTIAL_LEN
    call memcpy
    mov  byte [rel prin_owner_session_ready], 1
.push_wipe:
    lea  rdi, [rsp]
    xor  esi, esi
    mov  edx, PRIN_CREDENTIAL_LEN
    call memset
    jmp  .bound
.push_prepare_fail:
    lea  rdi, [rsp]
    xor  esi, esi
    mov  edx, PRIN_CREDENTIAL_LEN
    call memset
    jmp  .miss_unlocked
%endif
.credential_locked:
    call prin_credential_lock_acquire
    cmp  r12, AUTH_BIND_OWNER_RSA
    je   .owner_rsa
    cmp  r12, AUTH_BIND_PASSWORD
    je   .password
    cmp  r12, AUTH_BIND_SYSTEM_KEY
    je   .system
    cmp  r12, AUTH_BIND_ED25519
    je   .ed25519
    jmp  .miss_credential
.owner_rsa:
    mov  rdi, [r13 + AUTH_CTX_CREDENTIAL]
    mov  rsi, [r13 + AUTH_CTX_CRED_LEN]
    test rdi, rdi
    jz   .miss_credential
    test rsi, rsi
    jz   .miss_credential
    ; RSA proves sovereign command authority, but its public key identifier is
    ; not a DATA secret. Only PASSWORD may mint the owner's persistent-data
    ; session handle. Like SSH-key verification, this is OUTPUT-ONLY: AUTH_T
    ; carries the verified request principal, never the ambient local PID.
    ; In particular, later time/capability/replay refusals must leave no OWNER
    ; authority behind. A pre-existing password session is left untouched.
    jmp  .authority_only
.password:
    cmp  byte [rel prin_password_enrolled], 1
    jne  .miss_credential
    mov  byte [rel prin_pw_fail_step], 1
    mov  rdi, [r13 + AUTH_CTX_CREDENTIAL]
    mov  rsi, [r13 + AUTH_CTX_CRED_LEN]
    test rdi, rdi
    jz   .password_fail
    test rsi, rsi
    jz   .password_fail
    cmp  rsi, PRIN_PASSWORD_MAX
    ja   .password_fail
    mov  [rel prin_password_copy_len], rsi
    mov  rdx, rsi
    mov  rsi, rdi
    lea  rdi, [rel prin_password_copy]
    call memcpy
    mov  byte [rel prin_pw_fail_step], 2
    mov  rax, [r13 + AUTH_CTX_EXPIRES]
    sub  rax, [r13 + AUTH_CTX_ISSUED]
    cmp  rax, PRIN_AUTH_MAX_TTL
    ja   .password_fail
    mov  byte [rel prin_pw_fail_step], 3
    ; The window holds in the current wall frame, or in the one an NTP step
    ; replaced at most one TTL ago, and never after a backward step revived it
    ; (time_wall_window_now_s, as command_auth tickets).
    mov  rdi, [r13 + AUTH_CTX_ISSUED]
    mov  rsi, [r13 + AUTH_CTX_EXPIRES]
    mov  edx, PRIN_AUTH_MAX_TTL
    call time_wall_window_now_s
    test rax, rax
    jnz  .password_window
    call time_wall_now_s                  ; refused: keep the step that names why
    test rax, rax
    jz   .password_fail
    mov  byte [rel prin_pw_fail_step], 4
    cmp  rax, [r13 + AUTH_CTX_ISSUED]
    jb   .password_fail
    mov  byte [rel prin_pw_fail_step], 5
    jmp  .password_fail
.password_window:
    mov  byte [rel prin_pw_fail_step], 5
    call time_wall_now_s                  ; backoff stays in the current frame
    mov  [rel prin_password_now], rax
    mov  byte [rel prin_pw_fail_step], 12 ; durable password replay floor
    mov  rax, [r13 + AUTH_CTX_SEQUENCE]
    cmp  rax, [rel prin_password_last_sequence]
    jbe  .miss_credential
    ; SEC-replay-record-mac §9.3: like a command, nothing above this boot's
    ; committed floor window, so the next boot's B covers every sequence used.
    mov  byte [rel prin_pw_fail_step], 13 ; committed command seal
    cmp  rax, [rel command_auth_seal]
    ja   .miss_credential
    mov  [rel prin_password_last_sequence], rax
    mov  rax, [rel prin_password_now]
    mov  byte [rel prin_pw_fail_step], 6
    cmp  rax, [rel prin_password_backoff_until]
    jb   .password_fail
    ; Derive from the private snapshot (never from the transport-owned wire buffer).
    lea  rdx, [rel prin_password_copy]
    mov  rcx, [rel prin_password_copy_len]
    sub  rsp, 8
    mov  eax, [rel prin_password_iterations]
    mov  [rsp], rax
    lea  rdi, [rel prin_password_master]
    mov  esi, 32
    lea  r8, [rel prin_password_salt]
    mov  r9d, PRIN_PASSWORD_SALT_LEN
    mov  byte [rel prin_pw_fail_step], 7
    call pbkdf2_sha256
    add  rsp, 8
    test eax, eax
    jnz  .password_fail
    lea  rdi, [rel prin_password_master]
    mov  esi, 32
    lea  rdx, [rel prin_password_salt]
    mov  ecx, PRIN_PASSWORD_SALT_LEN
    lea  r8, [rel prin_verify_domain]
    mov  r9d, prin_verify_domain.len
    sub  rsp, 8
    lea  rax, [rel prin_password_check]
    mov  [rsp], rax
    mov  byte [rel prin_pw_fail_step], 8
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .password_fail
    lea  rdi, [rel prin_password_check]
    lea  rsi, [rel prin_password_verifier]
    mov  edx, PRIN_PASSWORD_VERIFIER_LEN
    mov  byte [rel prin_pw_fail_step], 9
    call principal_ct_equal
    test eax, eax
    jz   .password_fail
    mov  qword [rel prin_password_failures], 0
    mov  qword [rel prin_password_backoff_until], 0
    mov  byte [rel prin_pw_fail_step], 10
    call principal_record_persist
    test eax, eax
    jnz  .password_fail
    ; Publish the transient KEK input only after the durable anti-replay state
    ; has committed. A failed record write can therefore never mint a session.
    lea  rdi, [rel prin_password_master]
    mov  esi, 32
    lea  rdx, [rel prin_password_salt]
    mov  ecx, PRIN_PASSWORD_SALT_LEN
    lea  r8, [rel prin_kek_domain]
    mov  r9d, prin_kek_domain.len
    sub  rsp, 8
    lea  rax, [rel prin_owner_session_key]
    mov  [rsp], rax
    mov  byte [rel prin_pw_fail_step], 11
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .password_fail
    mov  byte [rel prin_pw_fail_step], 14 ; wrapped DATA key open
    call principal_open_data_key
    test eax, eax
    jnz .password_fail
    call principal_wipe_password_scratch
%if !PAOS_PUBLIC_BUILD
    mov  byte [rel prin_pw_fail_step], 15 ; second-factor policy
    call push_auth_password_gate
    test eax, eax
    jnz .push_pending
%endif
%if PAOS_PUBLIC_BUILD
    call keep_presentation_auth_allowed
    test eax, eax
    jnz .password_fail
%endif
    mov byte [rel prin_owner_session_ready], 1
    call prin_owner_boot_capture
    jmp .bound
%if !PAOS_PUBLIC_BUILD
.push_pending:
    ; The 2FA challenge just issued holds the key until it is approved,
    ; expires or is cancelled; the password alone does not open DATA.
    lea rdi, [rel prin_owner_session_key]
    call push_auth_stage_owner
    mov byte [rel prin_owner_session_ready], 0
    mov qword [rel prin_active_pid], 0
    lea rdi, [rel prin_owner_session_key]
    xor esi, esi
    mov edx, 32
    call memset
    jmp .miss_credential
%endif
.password_fail:
    ; serial-only diagnostic: which check refused (the wire reply stays wrong_password)
    lea  rdi, [rel str_pr_pw_fail_step]
    call serial_string
    movzx edi, byte [rel prin_pw_fail_step]
    call serial_hex64
    call serial_newline
    inc  qword [rel prin_password_failures]
    mov  rcx, [rel prin_password_failures]
    cmp  rcx, 8
    jbe  .backoff_bounded
    mov  ecx, 8
.backoff_bounded:
    mov  rax, 1
    shl  rax, cl
    add  rax, [rel prin_password_now]
    mov  [rel prin_password_backoff_until], rax
    call principal_record_persist         ; durable hammer/replay advance
    call principal_wipe_password_scratch
    jmp  .miss_credential
.system:
    cmp  byte [rel prin_system_secret_ready], 1
    jne  .miss_credential
    cmp  qword [r13 + AUTH_CTX_CRED_LEN], PRIN_CREDENTIAL_LEN
    jne  .miss_credential
    mov  rdi, [r13 + AUTH_CTX_CREDENTIAL]
    test rdi, rdi
    jz   .miss_credential
    lea  rsi, [rel prin_system_secret]
    mov  edx, PRIN_CREDENTIAL_LEN
    call principal_ct_equal
    test eax, eax
    jz   .miss_credential
    jmp  .bound
.ed25519:
    ; Task2142: the proof must name an ENROLLED SSH user key and carry a valid
    ; Ed25519 signature over the caller's session-bound message. The table row
    ; selects the principal. This method is OUTPUT-ONLY: it binds the remote
    ; connection that asked, never the global local-session principal, and
    ; mints no DATA session-key handle (a key proves command authority only).
    mov  r14, [r13 + AUTH_CTX_CREDENTIAL]
    test r14, r14
    jz   .miss_credential
    cmp  qword [r13 + AUTH_CTX_CRED_LEN], AUTH_ED25519_PROOF_SIZE
    jne  .miss_credential
    mov  rdi, [r14 + AUTH_ED25519_PROOF_PUB]
    test rdi, rdi
    jz   .miss_credential
    call ssh_keystore_find
    cmp  eax, -1
    je   .miss_credential
    mov  rdi, [r14 + AUTH_ED25519_PROOF_PUB]
    mov  esi, 32
    mov  rdx, [r14 + AUTH_ED25519_PROOF_MSG]
    mov  rcx, [r14 + AUTH_ED25519_PROOF_MSG_LEN]
    mov  r8, [r14 + AUTH_ED25519_PROOF_SIG]
    mov  r9d, 64
    call ed25519_verify
    test eax, eax
    jnz  .miss_credential
.authority_only:
    call prin_credential_lock_release
    mov  rax, rbx
    mov  rdi, rbx
    xor  edx, edx
    jmp  .out
.bound:
    mov  [rel prin_active_pid], rbx
    xor  r14d, r14d
    cmp  rbx, PRIN_OWNER
    je   .owner_handle
    cmp  rbx, PRIN_SYSTEM
    jne  .bound_release
    lea  r14, [rel prin_system_secret]
    jmp  .bound_release
.owner_handle:
    cmp  byte [rel prin_owner_session_ready], 1
    jne  .bound_release
    lea  r14, [rel prin_owner_session_key]
.bound_release:
    call prin_credential_lock_release
    test r14, r14
    jz   .bound_out
    cmp  rbx, PRIN_OWNER
    jne  .bound_out
    ; The owner's key is in RAM: bind the push record to it (one-way handle)
    ; and retire a PaOSPush1 that may still escrow it. No lock is held here.
%if !PAOS_PUBLIC_BUILD
    call keep_push_migrate
%endif
.bound_out:
    mov  rax, rbx
    mov  rdi, rbx
    mov  rdx, r14
    jmp  .out
.miss:
    call prin_state_lock_release
    jmp  .miss_unlocked
.miss_credential:
    call prin_credential_lock_release
.miss_unlocked:
    xor  eax, eax
    xor  edi, edi
    xor  edx, edx
.out:
    add  rsp, PRIN_CREDENTIAL_LEN
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

principal_wipe_password_scratch:
    lea  rdi, [rel prin_password_master]
    xor  esi, esi
    mov  edx, 64
    call memset
    lea  rdi, [rel prin_password_copy]
    xor  esi, esi
    mov  edx, PRIN_PASSWORD_MAX
    call memset
    mov  qword [rel prin_password_copy_len], 0
    ret

; Scrub the raw credential token and replace the UDP audit copy with a bounded
; method-only receipt. RDI=secret ptr, RSI=len, RDX=redacted cstr, RCX=cstr len.
principal_scrub_wire_secret:
    push rbx
    push r12
    mov  rbx, rdx
    mov  r12, rcx
    test rdi, rdi
    jz   .audit
    mov  rdx, rsi
    xor  esi, esi
    call memset
.audit:
    lea  rdi, [rel udp_auth_audit_line]
    xor  esi, esi
    mov  edx, AUTH_MSG_MAX
    call memset
    lea  rdi, [rel udp_auth_audit_line]
    mov  rsi, rbx
    mov  rdx, r12
    call memcpy
    lea  rax, [rel udp_auth_audit_line]
    mov  byte [rax + r12], 0
    mov  byte [rel udp_audit_redacted], 1    ; the transport's credential-verb guard sees the receipt
    ; AUTH1 enrollment copied its signed inner command into this verifier
    ; workspace before dispatch; it is no longer needed once the handler runs.
    lea  rdi, [rel command_auth_message]
    xor  esi, esi
    mov  edx, AUTH_MSG_MAX
    call memset
    pop  r12
    pop  rbx
    ret

; Bounded boot-only bridge for legacy crypto/store KATs that must exercise the
; production principal_credential consumer. It is permanently closed after the
; final KV KAT, and can never coexist with a real password session.
principal_boot_fixture_begin:
    cmp  byte [rel prin_boot_fixture_allowed], 1
    jne  .fail
    cmp  byte [rel prin_boot_fixture_active], 0
    jne  .fail
    cmp  byte [rel prin_owner_session_ready], 0
    jne  .fail
    test rdi, rdi
    jz   .fail
    test rsi, rsi
    jz   .fail
    lea  rdx, [rel prin_boot_fixture_salt]
    mov  ecx, prin_boot_fixture_salt.len
    lea  r8, [rel prin_boot_fixture_domain]
    mov  r9d, prin_boot_fixture_domain.len
    sub  rsp, 8
    lea  rax, [rel prin_owner_session_key]
    mov  [rsp], rax
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .fail
    mov  byte [rel prin_boot_fixture_active], 1
    mov  byte [rel prin_owner_session_ready], 1
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

principal_boot_fixture_end:
    cmp  byte [rel prin_boot_fixture_active], 1
    jne  .done
    mov  byte [rel prin_owner_session_ready], 0
    mov  byte [rel prin_boot_fixture_active], 0
    lea  rdi, [rel prin_owner_session_key]
    xor  esi, esi
    mov  edx, PRIN_CREDENTIAL_LEN
    jmp  memset
.done:
    ret

principal_boot_fixture_close:
    mov  byte [rel prin_boot_fixture_allowed], 0
    jmp  principal_boot_fixture_end

; Load the dedicated credential/hammer record. EAX=0 valid, 1 absent/unmapped
; hypervisor fixture, -1 malformed/unreadable. A malformed physical record is
; never replaced silently.
principal_record_load:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .unmapped
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    mov  qword [rel prin_record_size], PRIN_RECORD_SIZE
    mov  dword [rel prin_record_attrs], 0
    lea  rcx, [rel prin_record_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel prin_record_attrs]
    lea  r9, [rel prin_record_size]
    ; AUTHENROLL and boot initialization reach this function with different
    ; caller stack parities.  Align independently and retain the pre-firmware
    ; stack in a Microsoft-x64 nonvolatile register, never in firmware's
    ; outgoing home/argument area.
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel prin_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jz   .validate
    mov  rdx, PRIN_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    xor  edi, edi                       ; no RT record: nothing to snapshot
    call prin_owner_authority_apply
    mov  eax, 1
    jmp  .out
.validate:
    xor  r12d, r12d                     ; r12d = 1: a v3 record (no SYSTEM bytes)
    cmp  dword [rel prin_record_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  dword [rel prin_record + PRIN_REC_MAGIC], PRIN_RECORD_MAGIC
    jne  .bad
    cmp qword [rel prin_record_size], PRIN_V1_SIZE
    je .v1
    cmp qword [rel prin_record_size], PRIN_RECORD_SIZE
    jne .bad
    cmp  word [rel prin_record + PRIN_REC_VERSION], PRIN_RECORD_VERSION
    je   .v2_sized
    cmp  word [rel prin_record + PRIN_REC_VERSION], PRIN_RECORD_VERSION_MOVED
    jne  .bad
    mov  r12d, 1
.v2_sized:
    cmp  word [rel prin_record + PRIN_REC_SIZE], PRIN_RECORD_SIZE
    jne  .bad
    mov  ebx, [rel prin_record + PRIN_REC_CRC]
    mov  esi, PRIN_REC_CRC
    jmp .crc
.v1:
    cmp word [rel prin_record + PRIN_REC_VERSION], 1
    je .v1_sized
    cmp word [rel prin_record + PRIN_REC_VERSION], PRIN_RECORD_VERSION_MOVED
    jne .bad
    mov r12d, 1
.v1_sized:
    cmp word [rel prin_record + PRIN_REC_SIZE], PRIN_V1_SIZE
    jne .bad
    test dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_DATA_WRAP
    jnz .bad
    mov ebx, [rel prin_record + 124]
    mov esi, 124
.crc:
    lea rdi, [rel prin_record]
    call pbm_crc32
    cmp  eax, ebx
    jne  .bad
    ; v3 <=> the MOVED flag, and a v3 record carries nothing past its sequence
    test dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_SYSTEM_MOVED
    setnz al
    movzx eax, al
    cmp  eax, r12d
    jne  .bad
    test r12d, r12d
    jz   .shape_ok
    mov  rax, [rel prin_record + PRIN_REC_MOVED_SEQ + 8]
    or   rax, [rel prin_record + PRIN_REC_MOVED_SEQ + 16]
    or   rax, [rel prin_record + PRIN_REC_MOVED_SEQ + 24]
    jnz  .bad
.shape_ok:
    mov byte [rel prin_data_wrap_ready], 0
    lea rdi, [rel prin_data_wrap]
    xor esi, esi
    mov edx, PRIN_WRAP_SIZE
    call memset
    test dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_DATA_WRAP
    jz .wrap_loaded
    lea rdi, [rel prin_data_wrap]
    lea rsi, [rel prin_record + PRIN_REC_WRAP]
    mov edx, PRIN_WRAP_SIZE
    call memcpy
    mov byte [rel prin_data_wrap_ready], 1
.wrap_loaded:
    ; SEC slice 2: Y comes from the BS-only copy whenever this boot holds it.
    mov  byte [rel prin_system_lost], 0
    mov  byte [rel prin_record_moved], 0
    mov  qword [rel prin_moved_seq], 0
    test r12d, r12d
    jz   .y_select
    mov  byte [rel prin_record_moved], 1
    mov  rax, [rel prin_record + PRIN_REC_MOVED_SEQ]
    mov  [rel prin_moved_seq], rax
.y_select:
    cmp  byte [rel prin_system_bs], 1
    je   .y_held                        ; a reload (AUTHENROLL failure): keep the BS Y
    lea  rdi, [rel prin_system_secret]
    call system_secret_take
    test eax, eax
    jz   .y_no_bs
    mov  byte [rel prin_system_bs], 1
.y_held:
    test r12d, r12d
    jnz  .y_done
    lea  rdi, [rel prin_system_secret]
    lea  rsi, [rel prin_record + PRIN_REC_SYSTEM]
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .y_done
    ; An RT record whose Y is not the BS copy was not written by this estate
    ; (a runtime OS can forge one; it cannot know Y). The BS copy wins and the
    ; record is never again given Y: the next persist writes v3, sequence 0.
    mov  byte [rel prin_record_moved], 1
    mov  qword [rel prin_moved_seq], 0
    lea  rdi, [rel str_prin_sysx_disagree]
    call serial_string
    jmp  .y_done
.y_no_bs:
    test r12d, r12d
    jz   .y_from_record
    ; v3 and no BS copy: only a firmware NVRAM loss leaves the store empty
    ; (SYSX_ABSENT); any firmware error refuses the record (fail closed).
    cmp  byte [rel sysx_state], SYSX_ABSENT
    jne  .bad
    mov  byte [rel prin_system_lost], 1
    mov  byte [rel prin_system_secret_ready], 0
    lea  rdi, [rel prin_system_secret]
    xor  esi, esi
    mov  edx, 32
    call memset
    jmp  .y_done
.y_from_record:
    lea  rdi, [rel prin_system_secret]
    lea  rsi, [rel prin_record + PRIN_REC_SYSTEM]
    mov  edx, 32
    call memcpy
.y_done:
    mov  eax, [rel prin_record + PRIN_REC_FLAGS]
    and  eax, PRIN_REC_PASSWORD
    setnz byte [rel prin_password_enrolled]
    mov  eax, [rel prin_record + PRIN_REC_ITERATIONS]
    test eax, eax
    jz   .bad
    mov  [rel prin_password_iterations], eax
    lea  rdi, [rel prin_password_salt]
    lea  rsi, [rel prin_record + PRIN_REC_SALT]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel prin_password_verifier]
    lea  rsi, [rel prin_record + PRIN_REC_VERIFIER]
    mov  edx, 32
    call memcpy
    mov  rax, [rel prin_record + PRIN_REC_FAILURES]
    mov  [rel prin_password_failures], rax
    mov  rax, [rel prin_record + PRIN_REC_LAST_SEQ]
    ; SEC-replay-record-mac §9.3: never below the pre-EBS floor B, so a
    ; rolled-back record cannot reopen PASSWORD envelopes of earlier boots.
    cmp  rax, [rel rpf_b]
    jae  .pw_floor
    mov  rax, [rel rpf_b]
.pw_floor:
    mov  [rel prin_password_last_sequence], rax
    mov  rax, [rel prin_record + PRIN_REC_BACKOFF]
    mov  [rel prin_password_backoff_until], rax
    cmp  byte [rel prin_system_lost], 1
    je   .loaded                        ; credentials_init makes a new Y
    mov  byte [rel prin_system_secret_ready], 1
.loaded:
    ; Observation only: version from the fully validated RT record, never the
    ; policy flag (a disagreement can schedule v3 without writing it yet).
    mov  al, [rel prin_record + PRIN_REC_VERSION]
    mov  [rel prin_sysx_rt_version], al
    mov  edi, 1
    call prin_owner_authority_apply
    call principal_wrapnext_promote
    jmp  .out
.unmapped:
    mov  eax, 1
    cpuid
    bt   ecx, 31
    jnc  .bad
    xor  edi, edi
    call prin_owner_authority_apply
    mov  eax, 1
    jmp  .out
.bad:
    xor  edi, edi                       ; srcreview c-1 L1: a malformed RT record never leaves RT authority
    call prin_owner_authority_apply     ; standing once the store decided
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; prin_owner_authority_apply(EDI = 1 when prin_password_* were just loaded
;   from a valid RT record, else 0) — S1b-2c consumer (plan §3, srcreview
;   S1b-2 D4). prin_credential_lock held. The owner store decides who holds
;   the local password, from ows_state (set pre-EBS, never RT-writable):
;   - LOADED with a Z-bound record (ows_zbound, OWR_VERSION_Z; S1b-2c-0,
;     root 11:25:44): the BS PaOSOwner record is the authority. With OWR_LOCAL its
;     iterations/salt/verifier (taken once from owner_store's hand-off) are
;     installed; without it there is no local password. The RT verifier is
;     ignored either way (a mismatch is logged), so a runtime OS that forges
;     PaOSPrincipalCred no longer replaces the password.
;   - LOADED with a v1 record: the RT verifier stands, as before S1b-2c. A v1
;     record's LOCAL block may come from a stage MACed under Y, which a runtime
;     OS could read (srcreview c-1 M1); the owner can still re-enroll over RT.
;   - CORRUPT/FAILED: no local password at all (fail closed, design §3.6);
;     nothing falls back to the RT verifier.
;   - UNOWNED/NONE: today's RT verifier, unchanged. Stated residual until the
;     M3 migration (root 2026-10-09 14:26) seals it. EXCEPT an UNOWNED store
;     whose first setup is blocked by plants the firmware will not delete
;     (both slot names, or the stage name; plan §9): there M3 can never commit,
;     so a runtime OS that planted them would keep the forgeable RT verifier
;     for good. That is LOCKED instead, until firmware setup clears the plant.
;   Under STORE/LOCKED the RT record's own password fields are snapshotted
;   here and principal_record_persist writes them back unchanged: the sealed
;   verifier never reaches RT, and an older image (rollback, replay design
;   §9.9a (v)) still reads the RT fields it read before. Their scrub is the
;   M3 commit's, under a migration-aware gate (S1b-2c-2).
prin_owner_authority_apply:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel prin_rt_pw]
    xor  esi, esi
    mov  edx, PRIN_OWNER_PW_LEN
    call memset
    mov  byte [rel prin_rt_pw_flag], 0
    test ebx, ebx
    jz   .snapped
    mov  al, [rel prin_password_enrolled]
    mov  [rel prin_rt_pw_flag], al
    mov  eax, [rel prin_password_iterations]
    mov  [rel prin_rt_pw], eax
    lea  rdi, [rel prin_rt_pw + 4]
    lea  rsi, [rel prin_password_salt]
    mov  edx, PRIN_PASSWORD_SALT_LEN
    call memcpy
    lea  rdi, [rel prin_rt_pw + 4 + PRIN_PASSWORD_SALT_LEN]
    lea  rsi, [rel prin_password_verifier]
    mov  edx, PRIN_PASSWORD_VERIFIER_LEN
    call memcpy
.snapped:
    mov  byte [rel prin_pw_authority], PRIN_PWA_RT
    movzx eax, byte [rel ows_state]
    cmp  eax, PRIN_OWS_LOADED
    je   .store
    cmp  eax, PRIN_OWS_CORRUPT
    je   .locked
    cmp  eax, PRIN_OWS_FAILED
    je   .locked
    cmp  eax, PRIN_OWS_UNOWNED
    jne  .out                           ; NONE (no pass): the RT verifier stands
    movzx eax, byte [rel ows_planted]
    test al, PRIN_OWS_STUCK_STAGE
    jnz  .locked                        ; first setup blocked: never the RT verifier
    and  al, PRIN_OWS_STUCK_SLOTS
    cmp  al, PRIN_OWS_STUCK_SLOTS
    jne  .out                           ; UNOWNED: the RT verifier stands (until M3)
.locked:
    mov  byte [rel prin_pw_authority], PRIN_PWA_LOCKED
    jmp  .none
.store:
    cmp  byte [rel ows_zbound], 1
    jne  .not_zbound
    mov  byte [rel prin_pw_authority], PRIN_PWA_STORE
    cmp  byte [rel prin_owner_pw_state], 0
    jne  .taken                         ; a reload (enroll failure) reuses this boot's copy
    mov  byte [rel prin_owner_pw_state], 2
    lea  rdi, [rel prin_owner_pw]
    call owner_password_take
    test eax, eax
    jz   .taken
    mov  byte [rel prin_owner_pw_state], 1
.taken:
    cmp  byte [rel prin_owner_pw_state], 1
    jne  .none
    cmp  dword [rel prin_owner_pw], 0
    je   .none                          ; a zero iteration count is never a verifier
    cmp  byte [rel prin_rt_pw_flag], 1
    jne  .install
    ; constant-time: the RT side is attacker-chosen, the store side is sealed
    xor  eax, eax
    xor  ecx, ecx
    lea  rdi, [rel prin_rt_pw]          ; [rel X + rcx] is not RIP-relative: bases first
    lea  rsi, [rel prin_owner_pw]
.cmp:
    mov  dl, [rdi + rcx]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, PRIN_OWNER_PW_LEN
    jb   .cmp
    test al, al
    jz   .install
    lea  rdi, [rel str_prin_owner_rt_ignored]
    call serial_string
.install:
    mov  byte [rel prin_password_enrolled], 1
    mov  eax, [rel prin_owner_pw]
    mov  [rel prin_password_iterations], eax
    lea  rdi, [rel prin_password_salt]
    lea  rsi, [rel prin_owner_pw + 4]
    mov  edx, PRIN_PASSWORD_SALT_LEN
    call memcpy
    lea  rdi, [rel prin_password_verifier]
    lea  rsi, [rel prin_owner_pw + 4 + PRIN_PASSWORD_SALT_LEN]
    mov  edx, PRIN_PASSWORD_VERIFIER_LEN
    call memcpy
    jmp  .out
.not_zbound:
    lea  rdi, [rel str_prin_owner_not_zbound]
    call serial_string
    jmp  .out                           ; the RT verifier stands
.none:
    mov  byte [rel prin_password_enrolled], 0
    mov  dword [rel prin_password_iterations], 600000
    lea  rdi, [rel prin_password_salt]
    xor  esi, esi
    mov  edx, PRIN_PASSWORD_SALT_LEN
    call memset
    lea  rdi, [rel prin_password_verifier]
    xor  esi, esi
    mov  edx, PRIN_PASSWORD_VERIFIER_LEN
    call memset
.out:
    pop  rbx
    ret

; Persist current non-secret verifier metadata, machine SYSTEM secret, and
; anti-hammer/replay state with byte-exact readback. EAX=0/-1.
principal_record_persist:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .qemu
    ; SEC-pre-reset-wipe-hook (srcreview R2): no write after any CPU wiped the
    ; keys, and none without a loaded SYSTEM secret. Either would make a zero
    ; verifier or SYSTEM secret durable (a permanent owner lockout).
    cmp  byte [rel reset_wipe_done], 0
    jne  .bad
    cmp  byte [rel prin_system_secret_ready], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    lea  rdi, [rel prin_record]
    xor  esi, esi
    mov  edx, PRIN_RECORD_SIZE
    call memset
    mov  dword [rel prin_record + PRIN_REC_MAGIC], PRIN_RECORD_MAGIC
    ; Keep v1 byte format until reset actually needs the data-key wrapper.
    mov word [rel prin_record + PRIN_REC_VERSION], 1
    mov word [rel prin_record + PRIN_REC_SIZE], PRIN_V1_SIZE
    cmp byte [rel prin_data_wrap_ready], 1
    jne .wrap_saved
    mov word [rel prin_record + PRIN_REC_VERSION], PRIN_RECORD_VERSION
    mov word [rel prin_record + PRIN_REC_SIZE], PRIN_RECORD_SIZE
    or dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_DATA_WRAP
    lea rdi, [rel prin_record + PRIN_REC_WRAP]
    lea rsi, [rel prin_data_wrap]
    mov edx, PRIN_WRAP_SIZE
    call memcpy
.wrap_saved:
    ; SEC slice 2: a moved record is v3 at either size and never holds Y.
    cmp  byte [rel prin_record_moved], 1
    jne  .version_done
    mov  word [rel prin_record + PRIN_REC_VERSION], PRIN_RECORD_VERSION_MOVED
    or   dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_SYSTEM_MOVED
.version_done:
    cmp  byte [rel prin_pw_authority], PRIN_PWA_RT
    jne  .rt_snapshot                   ; S1b-2c: the store holds the password
    cmp  byte [rel prin_password_enrolled], 1
    jne  .flags_done
    or   dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_PASSWORD
.flags_done:
    mov  eax, [rel prin_password_iterations]
    mov  [rel prin_record + PRIN_REC_ITERATIONS], eax
    lea  rdi, [rel prin_record + PRIN_REC_SALT]
    lea  rsi, [rel prin_password_salt]
    mov  edx, 16
    call memcpy
    lea  rdi, [rel prin_record + PRIN_REC_VERIFIER]
    lea  rsi, [rel prin_password_verifier]
    mov  edx, 32
    call memcpy
    jmp  .pw_fields_done
.rt_snapshot:
    ; what the RT record held at load, never the sealed verifier
    cmp  byte [rel prin_rt_pw_flag], 1
    jne  .rt_flag_done
    or   dword [rel prin_record + PRIN_REC_FLAGS], PRIN_REC_PASSWORD
.rt_flag_done:
    mov  eax, [rel prin_rt_pw]
    test eax, eax
    jnz  .rt_iter
    mov  eax, 600000                    ; no RT record was loaded: the load rule refuses 0
.rt_iter:
    mov  [rel prin_record + PRIN_REC_ITERATIONS], eax
    lea  rdi, [rel prin_record + PRIN_REC_SALT]
    lea  rsi, [rel prin_rt_pw + 4]
    mov  edx, 16 + 32                   ; salt then verifier, contiguous in both
    call memcpy
.pw_fields_done:
    cmp  byte [rel prin_record_moved], 1
    je   .moved_seq
    lea  rdi, [rel prin_record + PRIN_REC_SYSTEM]
    lea  rsi, [rel prin_system_secret]
    mov  edx, 32
    call memcpy
    jmp  .system_done
.moved_seq:
    mov  rax, [rel prin_moved_seq]
    mov  [rel prin_record + PRIN_REC_MOVED_SEQ], rax
.system_done:
    mov  rax, [rel prin_password_failures]
    mov  [rel prin_record + PRIN_REC_FAILURES], rax
    mov  rax, [rel prin_password_last_sequence]
    mov  [rel prin_record + PRIN_REC_LAST_SEQ], rax
    mov  rax, [rel prin_password_backoff_until]
    mov  [rel prin_record + PRIN_REC_BACKOFF], rax
    lea  rdi, [rel prin_record]
    movzx esi, word [rel prin_record + PRIN_REC_SIZE]
    sub esi, 4
    call pbm_crc32
    movzx ecx, word [rel prin_record + PRIN_REC_SIZE]
    sub ecx, 4
    lea rdi, [rel prin_record]
    mov [rdi + rcx], eax
    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL for
    ; implicit and explicit intent; a refusal (registry drift) fails closed.
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel prin_record_guid]
    lea  rsi, [rel prin_record_name]
    lea  rcx, [rel str_prin_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    ; srcreview C1: DataSize is read from the record BEFORE the re-check. A wipe
    ; after the re-check would give size 0, and SetVariable with size 0 DELETES
    ; PaOSPrincipal (the next boot re-mints SYSTEM with no password). Only the
    ; two built sizes are ever passed.
    movzx r9d, word [rel prin_record + PRIN_REC_SIZE]
    cmp  r9d, PRIN_RECORD_SIZE
    je   .size_ok
    cmp  r9d, PRIN_V1_SIZE
    jne  .bad
.size_ok:
    ; srcreview G2: once more after the record is built. reset_wipe_all stores
    ; reset_wipe_done before it zeroes anything (TSO keeps that order, and keeps
    ; this load after the size load above), so if any secret copied above or
    ; the size was already zeroed, this load sees 1. A wipe that lands after
    ; this check can still tear the data bytes; the torn record fails its CRC at
    ; load (stated residual, fails closed).
    cmp  byte [rel reset_wipe_done], 0
    jne  .bad
    lea  rcx, [rel prin_record_name]
    lea  rdx, [rel prin_record_guid]
    mov  r8d, AUTH_EFI_ATTRS
    ; The enrollment path does not promise the same incoming parity as the
    ; boot-time path.  Build a fresh aligned Win64 frame while keeping the
    ; original stack only in nonvolatile R13.
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel prin_record]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    mov  qword [rel prin_record_verify_size], PRIN_RECORD_SIZE
    mov  dword [rel prin_record_verify_attrs], 0
    lea  rcx, [rel prin_record_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel prin_record_verify_attrs]
    lea  r9, [rel prin_record_verify_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel prin_record_verify]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    cmp  dword [rel prin_record_verify_attrs], AUTH_EFI_ATTRS
    jne  .bad
    movzx eax, word [rel prin_record + PRIN_REC_SIZE]
    cmp qword [rel prin_record_verify_size], rax
    jne  .bad
    lea  rdi, [rel prin_record]
    lea  rsi, [rel prin_record_verify]
    movzx edx, word [rel prin_record + PRIN_REC_SIZE]
    call memcmp
    test eax, eax
    jnz  .bad
    mov  al, [rel prin_record_verify + PRIN_REC_VERSION]
    mov  [rel prin_sysx_rt_version], al
    xor  eax, eax
    jmp  .out
.qemu:
    mov  eax, 1
    cpuid
    bt   ecx, 31
    jnc  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Scale-1 table/bind/lock KAT used by command_auth's NON-WIRE denial fixture.
; It proves both declared rows exactly, unknown-pid fail-closed behavior, the
; sole owner verifier binding, and that the lock site acquires and releases.
principal_authorization_selftest:
    push rbx
    mov  byte [rel prin_authz_table_ready], 0
    mov  byte [rel prin_authz_bind_ready], 0
    mov  byte [rel prin_authz_lock_ready], 0

    call prin_state_lock_acquire
    movzx ebx, byte [rel prin_state_lock]
    call prin_state_lock_release
    cmp  ebx, 1
    jne  .fail
    cmp  byte [rel prin_state_lock], 0
    jne  .fail
    mov  byte [rel prin_authz_lock_ready], 1

    mov  edi, PRIN_OWNER
    call principal_capabilities
    mov  rbx, PRIN_OWNER_CAPS
    cmp  rax, rbx
    jne  .fail
    mov  edi, PRIN_SYSTEM
    call principal_capabilities
    mov  rbx, PRIN_SYSTEM_CAPS
    cmp  rax, rbx
    jne  .fail
    mov  rdi, -1
    call principal_capabilities
    test rax, rax
    jnz  .fail
    mov  byte [rel prin_authz_table_ready], 1

    lea  rax, [rel prin_kat_owner_proof]
    mov  [rel prin_kat_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  qword [rel prin_kat_auth_ctx + AUTH_CTX_CRED_LEN], prin_kat_owner_proof.len
    mov  edi, AUTH_BIND_OWNER_RSA
    lea  rsi, [rel prin_kat_auth_ctx]
    call authenticate_bind
    cmp  rax, PRIN_OWNER
    jne  .fail
    mov  edi, AUTH_BIND_ED25519 + 1
    lea  rsi, [rel prin_kat_auth_ctx]
    call authenticate_bind
    test rax, rax
    jnz  .fail
    test rdx, rdx
    jnz  .fail
    mov  byte [rel prin_authz_bind_ready], 1
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; principal_switch — the paging-domain switch SITE. Saves CR3, reloads the
;   page-table root (real `mov cr3` => TLB flush; the mechanism RUNS), restores.
;   v1 OWNER->OWNER (target==current, degenerate-to-one), so restored==saved.
;   out: [prin_cr3_saved], [prin_cr3_restored] populated. clobbers RAX.
; ---------------------------------------------------------------------------
principal_switch:
    mov  rax, cr3                          ; save the current (OWNER) domain root
    mov  [rel prin_cr3_saved], rax
    ; --- switch: reload CR3 with the target domain root. v1 target == current
    ;     (OWNER->OWNER); the `mov cr3` genuinely executes (flushes the TLB) so
    ;     the switch SITE is real. Principal #2 supplies a DISTINCT valid root
    ;     here later as DATA — no code change (non-retrofittable seam). ---
    mov  cr3, rax
    ; --- restore + read back the effective root ---
    mov  rax, cr3
    mov  [rel prin_cr3_restored], rax
    ret

; ---------------------------------------------------------------------------
; principal_derive(RDI=salt_ptr, RSI=salt_len, RDX=cred_ptr, RCX=cred_len,
;                  R8=out_ptr, R9=out_len) — DERIVE a key via the canonical KDF
;   (RFC5869 HKDF-SHA256: cred+salt+domain -> key material; a wrong cred yields
;   an unrelated key). The AUTH seam derives, it does not verify a stored hash.
;   clobbers caller-saved.
; ---------------------------------------------------------------------------
principal_derive:
    jmp  auth_derive_key

; ---------------------------------------------------------------------------
; principal_selftest — the boot acceptance gate. Establishes OWNER, proves the
;   task/log/row carry the pid field, runs the OWNER->OWNER paging-domain switch,
;   and runs the KDF derive KAT. Emits the four [PAOS64] markers (serial, for the
;   regression harness) AND sets the BOOTLOG ride-along flags (for the probe)
;   IFF every invariant holds (fail-closed). Preserves rbx,r12-r15.
; ---------------------------------------------------------------------------
principal_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    call principal_credentials_init
    test eax, eax
    jnz  .done

    ; ===== (1) OWNER established — a fixed, non-NULL principal id =====
    call principal_current                 ; RAX = OWNER
    test rax, rax
    jz   .done                             ; NULL owner => fail-closed
    mov  [rel prin_owner_id], rax

    ; ===== (2) TAGGED — a data ROW carries {pid, token}; write+read-back =====
    ; write a fixed boot token under OWNER, then read the row back and confirm
    ; the stored pid == OWNER and the token bytes match (the field is real).
    mov  rax, PRIN_OWNER
    mov  [rel prin_row_pid], rax
    lea  rdi, [rel prin_row_token]         ; copy the boot KAT token into the row
    lea  rsi, [rel str_prin_boot_token]
    mov  rdx, str_prin_boot_token.len
    call memcpy
    mov  byte [rel prin_row_present], 1
    ; read-back check: pid field == OWNER
    mov  rax, [rel prin_row_pid]
    cmp  rax, PRIN_OWNER
    jne  .done
    ; read-back check: the token bytes round-trip byte-for-byte
    lea  rdi, [rel prin_row_token]
    lea  rsi, [rel str_prin_boot_token]
    mov  rdx, str_prin_boot_token.len
    call memcmp
    test rax, rax
    jnz  .done                             ; token mismatch => fail-closed
    ; tag the log line + the boot task with the owning principal (the field
    ; EXISTS in every subsequent log line header and task descriptor)
    mov  rax, PRIN_OWNER
    mov  [rel log_current_principal], rax

    ; ===== (3) PAGING-DOMAIN SWITCH — OWNER->OWNER, cr3 restored == saved =====
    call principal_switch
    mov  rax, [rel prin_cr3_saved]
    test rax, rax
    jz   .done                             ; CR3 read as 0 => something wrong
    mov  rbx, [rel prin_cr3_restored]
    cmp  rax, rbx                           ; restored must equal saved (no-op switch)
    jne  .done

    ; ===== (4) AUTH KDF DERIVE KAT — real, deterministic derivation =====
    ; derive twice over the fixed KAT (salt+cred); the two derivations MUST be
    ; byte-identical (deterministic real arithmetic) and non-zero.
    lea  rdi, [rel prin_kat_salt]
    mov  rsi, PRIN_KAT_SALT_LEN
    lea  rdx, [rel str_prin_kat_cred]
    mov  rcx, str_prin_kat_cred.len
    lea  r8,  [rel prin_dk_a]
    mov  r9,  PRIN_DK_LEN
    call principal_derive
    lea  rdi, [rel prin_kat_salt]
    mov  rsi, PRIN_KAT_SALT_LEN
    lea  rdx, [rel str_prin_kat_cred]
    mov  rcx, str_prin_kat_cred.len
    lea  r8,  [rel prin_dk_b]
    mov  r9,  PRIN_DK_LEN
    call principal_derive
    ; determinism: dk_a == dk_b
    lea  rdi, [rel prin_dk_a]
    lea  rsi, [rel prin_dk_b]
    mov  rdx, PRIN_DK_LEN
    call memcmp
    test rax, rax
    jnz  .done
    ; non-zero: at least one byte of dk_a is set
    xor  ecx, ecx
    xor  r10d, r10d
.dk_nz:
    cmp  ecx, PRIN_DK_LEN
    jae  .dk_checked
    lea  r8, [rel prin_dk_a]
    movzx eax, byte [r8 + rcx]
    or   r10d, eax
    inc  ecx
    jmp  .dk_nz
.dk_checked:
    test r10d, r10d
    jz   .done                             ; all-zero derived key => fail-closed

    ; ===== all invariants held: emit markers (serial) + set BOOTLOG flags =====
    lea  rdi, [rel str_prin_m_owner]
    call serial_string
    lea  rdi, [rel str_prin_m_tagged]
    call serial_string
    lea  rdi, [rel str_prin_m_switch]
    call serial_string
    lea  rdi, [rel str_prin_m_kdf]
    call serial_string
    mov  byte [rel prin_m_owner],  1
    mov  byte [rel prin_m_tagged], 1
    mov  byte [rel prin_m_switch], 1
    mov  byte [rel prin_m_kdf],    1
    call principal_credentials_selftest
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Initialize the machine-held SYSTEM secret once. Production uses the one
; CSPRNG seam. An entropy-less hypervisor receives a KAT-only fixture; physical
; entropy failure remains fail-closed.
principal_credentials_init:
    call prin_credential_lock_acquire
    cmp  byte [rel prin_system_secret_ready], 1
    je   .ready
    call principal_record_load
    test eax, eax
    jz   .loaded
    cmp  eax, 1
    jne  .fail
    ; No RT record (a fresh estate, or one deleted from a runtime OS): a BS copy
    ; this boot holds is still Y, so nothing derived from it rotates.
    lea  rdi, [rel prin_system_secret]
    call system_secret_take
    test eax, eax
    jz   .generate
    mov  byte [rel prin_system_bs], 1
    lea  rdi, [rel str_prin_sysx_restored]
    call serial_string
    jmp  .set
.loaded:
    cmp  byte [rel prin_system_lost], 1
    jne  .ready
    ; v3 record, BS copy gone with the firmware store: Y is unrecoverable by
    ; design. Make a new one; the record carries it until the next boot moves it.
    lea  rdi, [rel str_prin_sysx_lost]
    call serial_string
    mov  byte [rel prin_system_lost], 0
    mov  byte [rel prin_record_moved], 0
    mov  qword [rel prin_moved_seq], 0
.generate:
    lea  rdi, [rel prin_system_secret]
    mov  esi, PRIN_CREDENTIAL_LEN
    call csprng_generate
    test eax, eax
    jz   .set
    mov  eax, 1
    cpuid
    bt   ecx, 31
    jnc  .fail
    lea  rdi, [rel prin_system_secret]
    lea  rsi, [rel prin_system_kat_secret]
    mov  edx, PRIN_CREDENTIAL_LEN
    call memcpy
.set:
    mov  byte [rel prin_system_secret_ready], 1
    call principal_system_scrub         ; a restored BS Y goes straight to v3
    test eax, eax
    jz   .ready
    call principal_record_persist
    test eax, eax
    jnz  .secret_fail
.ready:
    call principal_system_scrub
    xor  eax, eax
    jmp  .out
.secret_fail:
    mov  byte [rel prin_system_secret_ready], 0
    lea  rdi, [rel prin_system_secret]
    xor  esi, esi
    mov  edx, PRIN_CREDENTIAL_LEN
    call memset
.fail:
    mov  eax, -1
.out:
    call system_secret_discard          ; an untaken BS copy never outlives the decision
    call owner_password_discard         ; S1b-2c: likewise the owner store's password hand-off
    push rax
    call prin_credential_lock_release
    pop  rax
    ret

; principal_system_scrub (prin_credential_lock held) -> EAX 0 when this call
;   rewrote the record as v3 (Y removed from the RT variable), 1 when not
;   applicable, -1 when v3 persistence/readback failed (record state unverified). Applies once
;   per boot, only while this boot holds the BS copy and its verified manifest
;   said every slot is migration-aware (root 14:05 (b)); the manifest's
;   sequence is recorded in the v3 record.
principal_system_scrub:
    cmp  byte [rel prin_system_bs], 1
    jne  .na
    cmp  byte [rel prin_record_moved], 1
    je   .na
    cmp  byte [rel sysx_migration_aware], 1
    jne  .na
    cmp  byte [rel prin_sysx_scrub_tried], 1
    je   .na
    mov  byte [rel prin_sysx_scrub_tried], 1
    mov  rax, [rel sysx_manifest_seq]
    mov  [rel prin_moved_seq], rax
    mov  byte [rel prin_record_moved], 1
    call principal_record_persist
    test eax, eax
    jnz  .failed
    ; The unmapped-runtime QEMU fallback returns success without firmware I/O.
    ; Only the actual validated v3 readback earns the verified-success label.
    mov  byte [rel prin_sysx_scrub_result], 3
    cmp  byte [rel prin_sysx_rt_version], 3
    jne  .unverified
    mov  byte [rel prin_sysx_scrub_result], 1
    lea  rdi, [rel str_prin_sysx_scrub]
    jmp  .logged
.unverified:
    lea  rdi, [rel str_prin_sysx_scrub_unverified]
.logged:
    call serial_string
    xor  eax, eax
    ret
.failed:
    mov  byte [rel prin_sysx_scrub_result], 2
    mov  byte [rel prin_record_moved], 0
    mov  qword [rel prin_moved_seq], 0
    lea  rdi, [rel str_prin_sysx_scrub_failed]
    call serial_string
    mov  eax, -1
    ret
.na:
    mov  eax, 1
    ret

; principal_system_status_append: owner-readable observation via STATUS.
; No firmware access or secret bytes. The caller applies the owner-envelope
; and exact STATUS checks. SCRUB=0 not attempted, 1 verified success, 2 failed,
; 3 unverified (the unmapped-runtime QEMU success fallback);
; RT_VERSION is the last validated load / byte-exact write readback this boot,
; not a claim about changes another OS could make later. MOVED_SEQ=0 may mean
; a disagreement rather than a manifest-gated scrub; never invent a sequence.
principal_system_status_append:
    lea  rdi, [rel str_prin_sysx_status_bs]
    call udp_put_str
    movzx edi, byte [rel prin_system_bs]
    call udp_put_dec
    lea  rdi, [rel str_prin_sysx_status_version]
    call udp_put_str
    movzx edi, byte [rel prin_sysx_rt_version]
    call udp_put_dec
    lea  rdi, [rel str_prin_sysx_status_scrub]
    call udp_put_str
    movzx edi, byte [rel prin_sysx_scrub_result]
    call udp_put_dec
    lea  rdi, [rel str_prin_sysx_status_moved]
    call udp_put_str
    mov  rdi, [rel prin_moved_seq]
    call udp_put_dec
    lea  rdi, [rel str_prin_sysx_status_manifest]
    call udp_put_str
    mov  rdi, [rel sysx_manifest_seq]
    call udp_put_dec
    jmp  principal_login_status_append

; Exact owner-signed STATUS only, through principal_system_status_append's
; existing owner-envelope guard in command_udp. Never add these to AUTHSTAT,
; SESSIONINFO, LOCKSTATE, AUTHLOGIN, or unsigned STATUS. This is diagnostic
; observation, not a credential verdict. No values, lengths, hashes or keys.
; Stage: 0 none, 1 nonce, 2 ticket, 3 bind, 4 offer, 5 unlock, 6 admitted.
; Step is the existing password serial checkpoint, snapshotted for this login:
; 0 not entered/enrolled, 1 input, 2 TTL, 3 wall unavailable, 4 before issue,
; 5 invalid/expired wall window, 6 backoff, 7 PBKDF, 8 verifier KDF, 9 comparison,
; 10 persist, 11 session KDF, 12 replay floor, 13 seal, 14 DATA open, 15 2FA.
; A checkpoint names a boundary, never proves a wrong password. The nonce is
; the already-public, validated login suffix, or none; readers must match it.
principal_login_status_append:
    lea  rdi, [rel str_pr_login_stage]
    call udp_put_str
    movzx edi, byte [rel prin_login_stage]
    call udp_put_dec
    lea  rdi, [rel str_pr_login_step]
    call udp_put_str
    movzx edi, byte [rel prin_login_step]
    call udp_put_dec
    lea  rdi, [rel str_pr_login_nonce_status]
    call udp_put_str
    lea  rdi, [rel prin_login_nonce]
    cmp  byte [rdi], 0
    jne  .nonce
    lea  rdi, [rel str_pr_login_nonce_none]
.nonce:
    jmp  udp_put_str

; principal_enroll_password(RDI=password,RSI=len) -> 0/-1. The persistent
; v1 password material is {salt,iteration,verifier}. v2 additionally wraps the
; existing DATA key under the password-derived KEK for atomic reset; there is
; still one verifier and no retained plaintext password/master/KEK.
; The v2 wrapper lives in the same atomic Task2501 EFI record as the verifier.
; AEAD AAD binds it to the new password salt; wrong password/key/tag never
; releases the stable data-key. Enrollment without reset still writes v1.
principal_data_key_request:
    lea rax, [rel prin_wrap_req]
    lea rdx, [rel prin_owner_session_key]
    mov [rax + AEAD_KEY], rdx
    lea rdx, [rel prin_data_wrap]
    mov [rax + AEAD_NONCE], rdx
    lea rdx, [rel prin_password_salt]
    mov [rax + AEAD_AAD], rdx
    mov qword [rax + AEAD_AAD_LEN], 16
    lea rdx, [rel prin_rotation_key]
    mov [rax + AEAD_INPUT], rdx
    mov qword [rax + AEAD_INPUT_LEN], 32
    lea rdx, [rel prin_data_wrap + 16]
    mov [rax + AEAD_OUTPUT], rdx
    lea rdx, [rel prin_data_wrap + 48]
    mov [rax + AEAD_TAG], rdx
    mov rdi, rax
    ret

principal_seal_data_key:
    lea rdi, [rel prin_data_wrap]
    mov esi, 12
    call csprng_generate
    test eax, eax
    jnz .bad
    call principal_data_key_request
    jmp aes256_gcm_seal
.bad:
    mov eax, -1
    ret

principal_open_data_key:
    cmp byte [rel prin_data_wrap_ready], 1
    je .open
    xor eax, eax
    ret
.open:
    push rbx
    call principal_data_key_request
    mov rax, [rdi + AEAD_INPUT]
    mov rdx, [rdi + AEAD_OUTPUT]
    mov [rdi + AEAD_INPUT], rdx
    mov [rdi + AEAD_OUTPUT], rax
    call aes256_gcm_open
    mov ebx, eax
    test eax, eax
    jnz .wipe
    lea rdi, [rel prin_owner_session_key]
    lea rsi, [rel prin_rotation_key]
    mov edx, 32
    call memcpy
.wipe:
    lea rdi, [rel prin_rotation_key]
    xor esi, esi
    mov edx, 32
    call memset
    mov eax, ebx
    pop rbx
    ret

; Boot-only, no record writes: same seal/open routine, tag and wrong-key
; negatives, restored original wrapper/handle. No fixture can be invoked by wire.
principal_reset_key_kat:
    push rbx
    sub rsp, 136
    mov rdi, rsp
    lea rsi, [rel prin_data_wrap]
    mov edx, 64
    call memcpy
    lea rdi, [rsp + 64]
    lea rsi, [rel prin_owner_session_key]
    mov edx, 32
    call memcpy
    lea rdi, [rsp + 96]
    lea rsi, [rel prin_rotation_key]
    mov edx, 32
    call memcpy
    mov al, [rel prin_data_wrap_ready]
    mov [rsp + 128], al
    mov ebx, -1
    lea rdi, [rel prin_owner_session_key]
    mov esi, 0x5a
    mov edx, 32
    call memset
    lea rdi, [rel prin_rotation_key]
    mov esi, 0xa5
    mov edx, 32
    call memset
    ; Deterministic nonce only with this isolated known key. Production seal
    ; still requires CSPRNG success; this arithmetic KAT needs no live entropy.
    lea rdi, [rel prin_data_wrap]
    mov esi, 0x3c
    mov edx, 12
    call memset
    call principal_data_key_request
    call aes256_gcm_seal
    test eax, eax
    jnz .restore
    mov byte [rel prin_data_wrap_ready], 1
    xor byte [rel prin_data_wrap + 48], 1
    call principal_open_data_key
    test eax, eax
    jz .restore
    xor byte [rel prin_data_wrap + 48], 1
    xor byte [rel prin_owner_session_key], 1
    call principal_open_data_key
    test eax, eax
    jz .restore
    xor byte [rel prin_owner_session_key], 1
    call principal_open_data_key
    test eax, eax
    jnz .restore
    lea rdi, [rel prin_owner_session_key]
    mov ecx, 32
.bytes:
    cmp byte [rdi], 0xa5
    jne .restore
    inc rdi
    loop .bytes
    xor ebx, ebx
.restore:
    lea rdi, [rel prin_data_wrap]
    mov rsi, rsp
    mov edx, 64
    call memcpy
    lea rdi, [rel prin_owner_session_key]
    lea rsi, [rsp + 64]
    mov edx, 32
    call memcpy
    lea rdi, [rel prin_rotation_key]
    lea rsi, [rsp + 96]
    mov edx, 32
    call memcpy
    mov al, [rsp + 128]
    mov [rel prin_data_wrap_ready], al
    mov rdi, rsp
    xor esi, esi
    mov edx, 136
    call memset
    add rsp, 136
    mov eax, ebx
    pop rbx
    ret

; F3(B): historical remote/direct setters are permanently refused. The only
; setter is the request-provenance checked staged LOCAL entry below.
principal_enroll_password:
    mov eax, -2
    ret
principal_reset_password:
    mov eax, -2
    ret
principal_enroll_common:
    mov eax, -2
    ret

; c2a LOCAL request writer + exact record-hash-bound DATA wrap pair.
; Owned by sec/principal; same credential lock as AUTHLOGIN and hammer state.
PWN_SIZE equ 128
PWN_MAGIC equ 0x00315458454e5750       ; bytes PWNEXT1,0

; Read-only eligibility, not authority. The installed writer captured a genuine
; absent base pre-EBS; NONE is the only clean first-setup stage state. Rechecked
; under the credential lock by the dedicated entry, never by a remote request.
principal_first_owner_available:
    xor eax, eax
    cmp byte [rel ows_state], 2           ; OWS_UNOWNED, not UNKNOWN/CORRUPT/FAILED
    jne .out
    cmp qword [rel ows_generation], 0
    jne .out
    cmp byte [rel ows_selected], 0xFF
    jne .out
    cmp dword [rel ows_summary], 0
    jne .out
    cmp byte [rel ows_stage], 0           ; OWS_STG_NONE
    jne .out
    test byte [rel ows_planted], 0x70     ; stuck foreign variable / bad capture
    jnz .out
    cmp byte [rel prin_password_enrolled], 0
    jne .out
    cmp byte [rel prin_pw_authority], PRIN_PWA_RT
    jne .out
    cmp byte [rel prin_owner_boot_ready], 0
    jne .out
    cmp byte [rel ows_wr_ready], 1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .out
    cmp byte [rel pbm_try_media], 0
    jne .out
    cmp byte [rel reset_wipe_done], 0
    jne .out
    cmp qword [rel runtime_services], 0
    je .out
    cmp byte [rel session_locked], 1
    jne .out
    cmp qword [rel session_bound_pid], 0
    jne .out
    cmp qword [rel session_key_handle], 0
    jne .out
    cmp byte [rel session_pending_valid], 0
    jne .out
    cmp byte [rel command_auth_remote_active], 0
    jne .out
    cmp byte [rel session_injected_input], 0
    jne .out
    cmp qword [rel prin_active_pid], 0
    jne .out
    mov eax, 1
.out:
    ret

; Trusted local lock-surface entry only: RDI/RSI=private widget buffer/length,
; EDX=whole-buffer HUMAN proof, ECX=activation HUMAN proof (each exactly 1).
; These are native provenance results, never request principals or wire fields.
; No live principal/session/credential is created. The caller always wipes input.
principal_first_owner_stage:
    cmp edx, 1
    jne .refused
    cmp ecx, 1
    jne .refused
    mov rdx, rdi
    mov rcx, rsi
    xor edi, edi
    xor esi, esi
    xor r8d, r8d                         ; no fabricated OWNER request
    mov r9d, 1
    jmp principal_stage_password_common
.refused:
    mov eax, -2
    ret

; RDI=current orNULL,RSI=len,RDX=new,RCX=len,R8=request ->0 STAGED/<0.
; Caller scrubs the full console/wire arguments even when provenance rejects.
principal_stage_password:
    xor r9d, r9d
principal_stage_password_common:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    call prin_credential_lock_acquire
    call prin_stage_wipe
    mov ebx, -2
    cmp qword [rsp + 40], 1
    jne .request
    call principal_first_owner_available
    cmp eax, 1
    jne .out
    jmp .ready
.request:
    mov r8, [rsp + 32]
    test r8, r8
    jz .out
    cmp qword [r8 + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne .out
    cmp qword [r8 + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne .out
.ready:
    mov ebx, -3
    cmp byte [rel ows_wr_ready], 1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .out
    cmp byte [rel reset_wipe_done], 0
    jne .out
    cmp byte [rel prin_pw_authority], PRIN_PWA_LOCKED
    je .out
    mov ebx, -2
    cmp byte [rel prin_pw_authority], PRIN_PWA_STORE
    jne .password_state
    cmp byte [rel prin_password_enrolled], 1
    jne .out                             ; Q2 key-only STORE refuses
.password_state:
    mov ebx, -1
    mov rdi, [rsp + 16]
    mov rdx, [rsp + 24]
    test rdi, rdi
    jz .out
    test rdx, rdx
    jz .out
    cmp rdx, PRIN_PASSWORD_MAX
    ja .out
    mov [rel prin_stage_new_len], rdx
    mov rsi, rdi
    lea rdi, [rel prin_stage_new]
    call memcpy
    cmp byte [rel prin_password_enrolled], 1
    jne .first
    mov ebx, -4
    mov rsi, [rsp + 8]
    mov rdi, [rsp]
    test rdi, rdi
    jz .out
    test rsi, rsi
    jz .out
    cmp rsi, PRIN_PASSWORD_MAX
    ja .out
    mov [rel prin_stage_current_len], rsi
    mov rdx, rsi
    mov rsi, rdi
    lea rdi, [rel prin_stage_current]
    call memcpy
    call time_wall_now_s
    mov [rel prin_password_now], rax
    test rax, rax
    jz .bad_password
    cmp rax, [rel prin_password_backoff_until]
    jb .bad_password
    lea rdi, [rel prin_stage_check]
    lea rsi, [rel prin_password_iterations]
    mov edx, 4
    call memcpy
    lea rdi, [rel prin_stage_check + 4]
    lea rsi, [rel prin_password_salt]
    mov edx, 16
    call memcpy
    lea rdi, [rel prin_stage_current]
    mov rsi, [rel prin_stage_current_len]
    lea rdx, [rel prin_stage_check]
    lea rcx, [rel prin_stage_current_kek]
    call prin_stage_derive
    test eax, eax
    jnz .bad_password
    lea rdi, [rel prin_stage_check + 20]
    lea rsi, [rel prin_password_verifier]
    mov edx, 32
    call principal_ct_equal
    test eax, eax
    jz .bad_password
    ; Correct current password derives the key independently of ambient
    ; OWNER/PUSH authority. It does not reset hammer or change live session.
    lea rdi, [rel prin_stage_data_key]
    lea rsi, [rel prin_stage_current_kek]
    mov edx, 32
    call memcpy
    cmp byte [rel prin_data_wrap_ready], 1
    jne .replacement
    call prin_stage_open
    test eax, eax
    jnz .out
.replacement:
    mov byte [rel prin_stage_has_data], 1
    jmp .derive_new
.first:
    cmp qword [rsp + 8], 0
    jne .out                             ; no current password to verify
    call safe_write_records_empty
    cmp eax, 1
    je .derive_new
    test eax, eax
    js .out
    cmp byte [rel prin_system_secret_ready], 1
    jne .out
    lea rdi, [rel prin_system_secret]
    mov esi, 32
    call safe_write_preserve_system_records
    cmp eax, 1
    jne .out                             ; never legacy OWNER migration here
.derive_new:
    mov dword [rel prin_stage_password], 600000
    lea rdi, [rel prin_stage_password + 4]
    mov esi, 16
    call csprng_generate
    test eax, eax
    jnz .out
    lea rdi, [rel prin_stage_new]
    mov rsi, [rel prin_stage_new_len]
    lea rdx, [rel prin_stage_password]
    lea rcx, [rel prin_stage_new_kek]
    call prin_stage_derive
    test eax, eax
    jnz .out
    ; No credential lock acquisition/callback: latch before standby/stage effects.
    call session_shell_local_wipe ; synchronous before authority/store/workspace callbacks
    call wifi_profile_cancel
    call wifi_store_owner_change_begin
    lea rdi, [rel prin_stage_password]
    call owner_stage_prepare
    test eax, eax
    jnz .out
    call owner_stage_pending
    test eax, eax
    js .out
    mov r15d, eax                        ; 1 existing valid pending LOCAL stage
    mov r14d, -1                        ; protected wrap slot or none
    cmp byte [rel prin_stage_has_data], 1
    jne .commit
    call prin_stage_read_pair
    test eax, eax
    jnz .out
    test r15d, r15d
    jz .candidate_slot
    lea rdi, [rel ows_wr_pending_hash]
    mov rsi, [rel ows_generation]
    inc rsi
    call prin_stage_match_pair
    cmp eax, 1
    ja .out                             ; absent/mismatch/divergence not repaired
    mov r14d, eax
.candidate_slot:
    xor r13d, r13d
    cmp r14d, -1
    je .build_wrap
    mov r13d, r14d
    xor r13d, 1                         ; NEVER mutate pending-stage matched slot
.build_wrap:
    mov rax, PWN_MAGIC
    mov [rel prin_stage_candidate], rax
    mov dword [rel prin_stage_candidate + 8], 1
    mov dword [rel prin_stage_candidate + 12], PWN_SIZE
    mov rax, [rel ows_generation]
    inc rax
    mov [rel prin_stage_candidate + 16], rax
    lea rdi, [rel prin_stage_candidate + 24]
    lea rsi, [rel ows_wr_target_hash]
    mov edx, 32
    call memcpy
    call prin_stage_seal
    test eax, eax
    jnz .out
    lea rdi, [rel prin_stage_candidate]
    mov esi, 120
    call pbm_crc32
    mov [rel prin_stage_candidate + 120], eax
    mov edi, r13d
    call prin_stage_name
    lea rsi, [rel prin_stage_candidate]
    mov edx, PWN_SIZE
    call owner_writer_write             ; W2 verified standby before stage
    test eax, eax
    jnz .out
.commit:
    call owner_stage_commit
    test eax, eax
    jnz .out
    cmp r14d, -1
    je .hammer
    mov edi, r14d
    call prin_stage_name
    call owner_writer_delete            ; best-effort OLD wrap retirement only
.hammer:
    mov rax, [rel prin_password_failures]
    mov [rsp + 40], rax
    mov rax, [rel prin_password_backoff_until]
    mov [rsp + 48], rax
    mov qword [rel prin_password_failures], 0
    mov qword [rel prin_password_backoff_until], 0
    call principal_record_persist
    test eax, eax
    jz .success
    mov rax, [rsp + 40]
    mov [rel prin_password_failures], rax
    mov rax, [rsp + 48]
    mov [rel prin_password_backoff_until], rax
    mov ebx, -1
    jmp .out
.success:
    xor ebx, ebx
    jmp .out
.bad_password:
    inc qword [rel prin_password_failures]
    mov rcx, [rel prin_password_failures]
    cmp rcx, 8
    jbe .bounded
    mov ecx, 8
.bounded:
    mov rax, 1
    shl rax, cl
    add rax, [rel prin_password_now]
    mov [rel prin_password_backoff_until], rax
    call principal_record_persist
    mov ebx, -5
.out:
    call owner_writer_discard
    call prin_stage_wipe
    call prin_credential_lock_release
    mov eax, ebx
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Actual PBKDF2/HKDF derivation. RDI=password,RSI=len,RDX=pw52 with
; iterations/salt set,RCX=kek32 -> verifier at pw+20, KEK; master always wiped.
prin_stage_derive:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 16
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov eax, [r13]
    mov [rsp], rax
    lea rdi, [rel prin_stage_master]
    mov esi, 32
    mov rdx, rbx
    mov rcx, r12
    lea r8, [r13 + 4]
    mov r9d, 16
    call pbkdf2_sha256
    test eax, eax
    jnz .out
    lea rax, [r13 + 20]
    mov [rsp], rax
    lea rdi, [rel prin_stage_master]
    mov esi, 32
    lea rdx, [r13 + 4]
    mov ecx, 16
    lea r8, [rel prin_verify_domain]
    mov r9d, prin_verify_domain.len
    call principal_hkdf32
    test eax, eax
    jnz .out
    mov [rsp], r14
    lea rdi, [rel prin_stage_master]
    mov esi, 32
    lea rdx, [r13 + 4]
    mov ecx, 16
    lea r8, [rel prin_kek_domain]
    mov r9d, prin_kek_domain.len
    call principal_hkdf32
.out:
    mov ebx, eax
    lea rdi, [rel prin_stage_master]
    xor esi, esi
    mov edx, 32
    call memset
    mov eax, ebx
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

prin_stage_open:
    lea rax, [rel prin_stage_aead]
    lea rdx, [rel prin_stage_current_kek]
    mov [rax + AEAD_KEY], rdx
    lea rdx, [rel prin_data_wrap]
    mov [rax + AEAD_NONCE], rdx
    lea rdx, [rel prin_password_salt]
    mov [rax + AEAD_AAD], rdx
    mov qword [rax + AEAD_AAD_LEN], 16
    lea rdx, [rel prin_data_wrap + 16]
    mov [rax + AEAD_INPUT], rdx
    mov qword [rax + AEAD_INPUT_LEN], 32
    lea rdx, [rel prin_stage_data_key]
    mov [rax + AEAD_OUTPUT], rdx
    lea rdx, [rel prin_data_wrap + 48]
    mov [rax + AEAD_TAG], rdx
    mov rdi, rax
    jmp aes256_gcm_open

prin_stage_seal:
    sub rsp, 8
    lea rdi, [rel prin_stage_candidate + 56]
    mov esi, 12
    call csprng_generate
    test eax, eax
    jnz .out
    lea rax, [rel prin_stage_aead]
    lea rdx, [rel prin_stage_new_kek]
    mov [rax + AEAD_KEY], rdx
    lea rdx, [rel prin_stage_candidate + 56]
    mov [rax + AEAD_NONCE], rdx
    lea rdx, [rel prin_stage_password + 4]
    mov [rax + AEAD_AAD], rdx
    mov qword [rax + AEAD_AAD_LEN], 16
    lea rdx, [rel prin_stage_data_key]
    mov [rax + AEAD_INPUT], rdx
    mov qword [rax + AEAD_INPUT_LEN], 32
    lea rdx, [rel prin_stage_candidate + 72]
    mov [rax + AEAD_OUTPUT], rdx
    lea rdx, [rel prin_stage_candidate + 104]
    mov [rax + AEAD_TAG], rdx
    mov rdi, rax
    add rsp, 8
    jmp aes256_gcm_seal
.out:
    add rsp, 8
    ret

; EDI=0/1 -> RDI=CHAR16 fixed name. Callers validate index first.
prin_stage_name:
    test edi, edi
    lea rdi, [rel prin_wrap_name0]
    jz .out
    lea rdi, [rel prin_wrap_name1]
.out:
    ret

; Bounded read both variables; valid mask0..3, malformed absent treated as
; unusable, EFI uncertainty refuses whole operation. No writes or deletes.
prin_stage_read_pair:
    push rbx
    push r12
    sub rsp, 8
    mov byte [rel prin_stage_pair_mask], 0
    xor ebx, ebx
.loop:
    mov edi, ebx
    call prin_stage_name
    lea rsi, [rel prin_stage_pair]
    mov eax, ebx
    shl eax, 7
    add rsi, rax
    mov r12, rsi
    mov edx, PWN_SIZE
    call owner_writer_read
    cmp eax, 1
    je .next
    test eax, eax
    jnz .bad
    cmp qword [rel ows_wr_size], PWN_SIZE
    jne .next
    cmp dword [rel ows_wr_attrs], 7
    jne .next
    mov rax, PWN_MAGIC
    cmp [r12], rax
    jne .next
    cmp dword [r12 + 8], 1
    jne .next
    cmp dword [r12 + 12], PWN_SIZE
    jne .next
    cmp dword [r12 + 124], 0
    jne .next
    cmp dword [r12 + 68], 0              ; wrap reserved4
    jne .next
    mov rdi, r12
    mov esi, 120
    call pbm_crc32
    cmp eax, [r12 + 120]
    jne .next
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    or [rel prin_stage_pair_mask], al
.next:
    inc ebx
    cmp ebx, 2
    jb .loop
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; RDI=recordhash32,RSI=g ->0/1 matching slot,-1 no match,-2 divergent
; duplicate (identical or divergent). Both entries remain protected: refuse
; replacement/promotion without overwriting or deleting either.
prin_stage_match_pair:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14d, -1
    xor ebx, ebx
.loop:
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    test [rel prin_stage_pair_mask], al
    jz .next
    lea rdi, [rel prin_stage_pair]
    mov eax, ebx
    shl eax, 7
    add rdi, rax
    cmp [rdi + 16], r13
    jne .next
    add rdi, 24
    mov rsi, r12
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .next
    cmp r14d, -1
    jne .duplicate
    mov r14d, ebx
.next:
    inc ebx
    cmp ebx, 2
    jb .loop
    mov eax, r14d
    jmp .out
.duplicate:
    mov eax, -2                         ; fail closed, preserve both
.out:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Validated RT row + established sealed authority only. Exact gen/hash
; promotion, verified RT persistence BEFORE selected entry deletion. Errors
; retain entries for retry. Malformed RT load never invokes this path; its
; common fail-closed exit preserves pending entries and invents no hammer/Y.
principal_wrapnext_promote:
    push rbx
    push r12
    sub rsp, 8
    call prin_stage_wipe
    xor ebx, ebx
    cmp byte [rel ows_state], PRIN_OWS_LOADED
    jne .out
    cmp byte [rel ows_zbound], 1
    jne .out
    cmp byte [rel prin_pw_authority], PRIN_PWA_STORE
    jne .out
    call prin_stage_read_pair
    test eax, eax
    jnz .fail
    lea rdi, [rel ows_committed_hash]
    mov rsi, [rel ows_generation]
    call prin_stage_match_pair
    cmp eax, -1
    je .out                             ; unmatched/stale entries preserved
    cmp eax, 1
    ja .fail
    mov r12d, eax
    lea rsi, [rel prin_stage_pair + 56]
    shl eax, 7
    add rsi, rax
    lea rdi, [rel prin_data_wrap]
    mov edx, PRIN_WRAP_SIZE
    call memcpy
    mov byte [rel prin_data_wrap_ready], 1
    call principal_record_persist
    test eax, eax
    jnz .fail                           ; selected entry not removed on error
    mov edi, r12d
    call prin_stage_name
    call owner_writer_delete
    ; Failure to delete leaves an idempotent exact pair; loaded/persisted
    ; DATA_WRAP is already verified. Do not invent failure of promotion.
    jmp .out
.fail:
    mov ebx, -1
.out:
    call prin_stage_wipe
    call owner_writer_discard
    mov eax, ebx
    add rsp, 8
    pop r12
    pop rbx
    ret

prin_stage_wipe:
    lea rdi, [rel prin_stage_scratch]
    xor esi, esi
    mov edx, prin_stage_scratch_end - prin_stage_scratch
    jmp memset

%include "core/abi/wdata.inc"
%macro WDATA_sec_principal_stage 0
align 16, db 0
prin_stage_scratch:
prin_stage_current: times 128 db 0
prin_stage_new: times 128 db 0
prin_stage_check: times 52 db 0
prin_stage_password: times 52 db 0
prin_stage_master: times 32 db 0
prin_stage_current_kek: times 32 db 0
prin_stage_new_kek: times 32 db 0
prin_stage_data_key: times 32 db 0
prin_stage_pair: times PWN_SIZE * 2 db 0
prin_stage_candidate: times PWN_SIZE db 0
prin_stage_aead: times AEAD_REQ_SZ db 0
prin_stage_current_len: dq 0
prin_stage_new_len: dq 0
prin_stage_pair_mask: db 0
prin_stage_has_data: db 0
prin_stage_scratch_end:
%endmacro
WDATA_DEFER WDATA_sec_principal_stage
align 2, db 0
prin_wrap_name0: dw 'P','a','O','S','P','r','i','n','c','i','p','a','l','W','r','a','p','N','e','x','t','0',0
prin_wrap_name1: dw 'P','a','O','S','P','r','i','n','c','i','p','a','l','W','r','a','p','N','e','x','t','1',0
prin_stage_staged: db "AUTHENROLL STAGED gen=",0
prin_stage_restart: db " commits on restart",0
prin_stage_refused: db "AUTHENROLL REFUSED stage or password check failed",0
prin_stage_local_only: db "AUTHENROLL REFUSED password changes are local only until the confirm slice",0
prin_stage_not_ready: db "AUTHENROLL REFUSED owner changes need an installed boot or owner-store recovery",0
prin_stage_current_required: db "AUTHENROLL REFUSED current password required",0


; Fast boot KAT: primitive vector + explicit verifier/KEK domain divergence +
; all four method rows + a real SYSTEM_KEY bind. The production iteration word
; is checked for the Peter-ratified 600,000 value without spending it at boot.
principal_credentials_selftest:
    push rbx
    call pbkdf2_sha256_selftest
    test eax, eax
    jnz  .fail
    cmp  dword [rel prin_password_iterations], 600000
    jne  .fail
    lea  rdi, [rel pbkdf2_kat_actual]
    mov  esi, 32
    lea  rdx, [rel prin_kat_domain_salt]
    mov  ecx, 16
    lea  r8, [rel prin_verify_domain]
    mov  r9d, prin_verify_domain.len
    sub  rsp, 8
    lea  rax, [rel prin_kat_verifier]
    mov  [rsp], rax
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .fail
    lea  rdi, [rel pbkdf2_kat_actual]
    mov  esi, 32
    lea  rdx, [rel prin_kat_domain_salt]
    mov  ecx, 16
    lea  r8, [rel prin_kek_domain]
    mov  r9d, prin_kek_domain.len
    sub  rsp, 8
    lea  rax, [rel prin_kat_kek_input]
    mov  [rsp], rax
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .fail
    lea  rdi, [rel prin_kat_verifier]
    lea  rsi, [rel prin_kat_kek_input]
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .fail
    ; OWNER_RSA selects the sovereign principal but deliberately exposes no
    ; DATA handle when no password session exists.
    lea  rax, [rel prin_kat_owner_proof]
    mov  [rel prin_kat_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  qword [rel prin_kat_auth_ctx + AUTH_CTX_CRED_LEN], prin_kat_owner_proof.len
    mov  edi, AUTH_BIND_OWNER_RSA
    lea  rsi, [rel prin_kat_auth_ctx]
    call authenticate_bind
    cmp  rax, PRIN_OWNER
    jne  .fail
    test rdx, rdx
    jnz  .fail
    lea  rax, [rel prin_system_secret]
    mov  [rel prin_kat_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  qword [rel prin_kat_auth_ctx + AUTH_CTX_CRED_LEN], 32
    mov  qword [rel prin_kat_auth_ctx + AUTH_CTX_ASSERTED_PID], PRIN_OWNER
    mov  edi, AUTH_BIND_SYSTEM_KEY
    lea  rsi, [rel prin_kat_auth_ctx]
    call authenticate_bind
    cmp  rax, PRIN_SYSTEM
    jne  .fail
    cmp  rdi, PRIN_SYSTEM
    jne  .fail
    test rdx, rdx
    jz   .fail
    call principal_leave_system
    ; Later storage KATs exercise principal_credential through a bounded boot
    ; fixture. kvstore_selftest closes and wipes it on every exit path.
    lea  rdi, [rel prin_kat_kek_input]
    mov  esi, 32
    call principal_boot_fixture_begin
    test eax, eax
    jnz  .fail
    mov  edi, PRIN_OWNER
    call principal_credential
    test rax, rax
    jz   .fail_fixture
    lea  rdi, [rel str_auth2501_bind]
    call serial_string
    lea  rdi, [rel str_auth2501_method]
    call serial_string
    lea  rdi, [rel str_auth2501_pbkdf2]
    call serial_string
    lea  rdi, [rel str_auth2501_system]
    call serial_string
    mov  byte [rel prin_m_auth_bind], 1
    mov  byte [rel prin_m_auth_method], 1
    mov  byte [rel prin_m_auth_pbkdf2], 1
    mov  byte [rel prin_m_auth_system], 1
    xor  eax, eax
    jmp  .wipe
.fail_fixture:
    call principal_boot_fixture_close
.fail:
    mov  ebx, -1
    mov  eax, ebx
.wipe:
    lea  rdi, [rel prin_kat_verifier]
    xor  esi, esi
    mov  edx, 64
    push rax
    call memset
    pop  rax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; principal_declare — register principal plus credential verbs through the SAME
;   command_register_verb (additive, no registry-core edit). All ARGT_TEXT so
;   the raw arg token (pid + token / salt + cred) round-trips verbatim.
;   clobbers caller-saved.
; ---------------------------------------------------------------------------
principal_declare:
    lea  rdi, [rel str_verb_prinwrite]
    lea  rsi, [rel cmd_verb_prinwrite]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                              ; mutates the row store
    call command_register_verb
    lea  rdi, [rel str_verb_prinread]
    lea  rsi, [rel cmd_verb_prinread]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_prinswitch]
    lea  rsi, [rel cmd_verb_prinswitch]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_prinkdf]
    lea  rsi, [rel cmd_verb_prinkdf]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_authenroll]
    lea  rsi, [rel cmd_verb_authenroll]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; owner-signed enrollment mutation
    call command_register_verb
    lea  rdi, [rel str_verb_authlogin]
    lea  rsi, [rel cmd_verb_authlogin]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_authsys]
    lea  rsi, [rel cmd_verb_authsys]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; owner permits the live system proof
    call command_register_verb
    lea  rdi, [rel str_verb_authkvprobe]
    lea  rsi, [rel cmd_verb_authkvprobe]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    mov  r9d, 1                         ; operational-cap AI-hook fixture
    call command_register_verb
    ret

; AUTHENROLL <new> or AUTHENROLL <current> <new>; always scrub full args.
cmd_verb_authenroll:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, [rbx + REQ_ARG]
    xor r13d, r13d
    test r12, r12
    jz .parse_fail
.length:
    cmp r13, AUTH_MSG_MAX
    jae .parse_fail
    cmp byte [r12 + r13], 0
    je .parse
    inc r13
    jmp .length
.parse:
    test r13, r13
    jz .parse_fail
    xor eax, eax
.first:
    cmp rax, r13
    jae .single
    cmp byte [r12 + rax], ' '
    je .two
    inc rax
    jmp .first
.single:
    xor edi, edi
    xor esi, esi
    mov rdx, r12
    mov rcx, r13
    jmp .call
.two:
    mov rdi, r12
    mov rsi, rax
    lea rdx, [r12 + rax + 1]
    mov rcx, r13
    sub rcx, rax
    dec rcx
    xor eax, eax
.scan_new:
    cmp rax, rcx
    jae .call
    cmp byte [rdx + rax], ' '
    je .parse_fail
    inc rax
    jmp .scan_new
.call:
    mov r8, rbx
    call principal_stage_password
    jmp .scrub
.parse_fail:
    mov eax, -1
.scrub:
    push rax
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel str_pr_audit_enroll]
    mov ecx, str_pr_audit_enroll.len
    call principal_scrub_wire_secret
    pop r12
    call prin_out_reset
    test r12d, r12d
    jnz .fail
    lea rdi, [rel prin_stage_staged]
    call prin_out_str
    mov rdi, [rel ows_generation]
    inc rdi
    call prin_out_dec
    lea rdi, [rel prin_stage_restart]
    call prin_out_str
    jmp .reply
.fail:
    lea rdi, [rel prin_stage_refused]
    cmp r12d, -2
    jne .not_provenance
    lea rdi, [rel prin_stage_local_only]
.not_provenance:
    cmp r12d, -3
    jne .not_ready
    lea rdi, [rel prin_stage_not_ready]
.not_ready:
    cmp r12d, -4
    jne .reply_text
    lea rdi, [rel prin_stage_current_required]
.reply_text:
    call prin_out_str
.reply:
    call principal_publish_wire_reply
    pop r13
    pop r12
    pop rbx
    ret

; Local secret-widget ingress uses the SAME PASSWORD method, TTL, sequence,
; durable record and hammer state as AUTHLOGIN. Return only pid/handle, after
; wiping caller input and stack context; the GUI hands outputs to sec/session.
; RDI=transient input, RSI=length -> RAX=pid or 0, RDX=handle or 0.
principal_local_password:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    sub  rsp, AUTH_CTX_SIZE
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, AUTH_CTX_SIZE
    call memset
    mov  [rsp + AUTH_CTX_CREDENTIAL], r12
    mov  [rsp + AUTH_CTX_CRED_LEN], r13
    call time_wall_local_issue_s          ; a native window at now (ended after the bind)
    mov  [rsp + AUTH_CTX_ISSUED], rax
    add  rax, PRIN_AUTH_MAX_TTL
    mov  [rsp + AUTH_CTX_EXPIRES], rax
    ; The single GUI/UDP consumer serializes submissions. Start after both
    ; durable floors so local typing and signed wire attempts can alternate.
    mov  rax, [rel prin_password_last_sequence]
    cmp  rax, [rel command_auth_last_sequence]
    jae  .sequence
    mov  rax, [rel command_auth_last_sequence]
.sequence:
    add  rax, 1
    jc   .overflow
    mov  [rsp + AUTH_CTX_SEQUENCE], rax
    mov  edi, AUTH_BIND_PASSWORD
    ; A delivered login code can also be typed into the local secret field as
    ; push:<code32>. Reset approvals are never accepted as desktop logins.
%if !PAOS_PUBLIC_BUILD
    cmp r13, 37
    jne .method_ready
    cmp byte [rel pu_state], PU_PENDING
    jne .method_ready
    cmp dword [r12], 'push'
    jne .method_ready
    cmp byte [r12 + 4], ':'
    jne .method_ready
    cmp byte [rel pu_kind], PU_RESET
    je .overflow
    lea rax, [r12 + 5]
    mov [rsp + AUTH_CTX_CREDENTIAL], rax
    mov qword [rsp + AUTH_CTX_CRED_LEN], 32
    movzx eax, byte [rel pu_kind]
    mov [rsp + AUTH_CTX_AUDIT_REF], rax
    mov edi, AUTH_BIND_PUSH
%endif
.method_ready:
    mov  rsi, rsp
    call authenticate_bind
    mov  rbx, rax
    mov  r14, rdx
    jmp  .wipe
.overflow:
    xor  ebx, ebx
    xor  r14d, r14d
.wipe:
    call time_wall_local_issue_end
    mov  rdi, r12
    xor  esi, esi
    mov  rdx, r13
    cmp  rdx, PRIN_PASSWORD_MAX
    jbe  .bounded
    mov  edx, PRIN_PASSWORD_MAX
.bounded:
    call memset
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, AUTH_CTX_SIZE
    call memset
    add  rsp, AUTH_CTX_SIZE
    mov  rax, rbx
    mov  rdx, r14
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; AUTHLOGIN <password> — the signed AUTH1 permission ticket supplies the
; durable sequence/TTL; PASSWORD independently selects OWNER. No caller PID is
; accepted, and an unsigned/replayed datagram never reaches this handler.
; AUTHLOGIN is the EXPLICIT owner unlock over AUTH1 (owner ticket). Over SSH exec
; it is refused (spec 21.2.5, root 89528). Every outcome is audit-logged (UNLOCK ...).
cmd_verb_authlogin:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  rbx, rdi
    mov  [rel prin_login_rsp], rsi
    mov  byte [rel prin_login_refusal], 0
    ; Per-attempt observation, never consulted by authorization or replies.
    ; Reset before parsing: malformed input must not inherit a previous step.
    mov  byte [rel prin_login_stage], 1
    mov  byte [rel prin_login_step], 0
    mov  rax, [rbx + REQ_ARG]
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  rdi, rax
    call prin_token_len
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_CRED_LEN], rax
    mov  rdi, [rbx + REQ_ARG]
    add  rdi, rax
    call principal_login_nonce
    test eax, eax
    jz   .nonce_ok
    xor  r12d, r12d
    jmp  .scrub
.nonce_ok:
    mov  byte [rel prin_login_stage], 2
    call command_auth_owner_request
    cmp  eax, 1
    je   .owner_ticket
    cmp  eax, 2
    je   .ssh_owner
    mov  byte [rel prin_login_refusal], SESSION_UNLOCK_TICKET
    xor  r12d, r12d
    jmp  .scrub
.ssh_owner:
    ; Spec 21.2.5, root 89528: an SSH session never unlocks the console. Refused
    ; before any password work, so an SSH attempt spends and reveals nothing.
    mov  byte [rel prin_login_refusal], SESSION_UNLOCK_SSH
    xor  r12d, r12d
    jmp  .scrub
.owner_ticket:
    mov  rax, [rel udp_auth_ticket + AUTH_T_SEQ]
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_SEQUENCE], rax
    mov  rax, [rel udp_auth_ticket + AUTH_T_ISSUED]
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_ISSUED], rax
    mov  rax, [rel udp_auth_ticket + AUTH_T_EXPIRES]
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_EXPIRES], rax
.bind:
    mov  byte [rel prin_login_stage], 3
    mov  byte [rel prin_pw_fail_step], 0
    mov  edi, AUTH_BIND_PASSWORD
    lea  rsi, [rel prin_wire_auth_ctx]
    call authenticate_bind
    movzx ecx, byte [rel prin_pw_fail_step]
    mov  [rel prin_login_step], cl
    call time_wall_local_issue_end        ; keeps RAX/RDX: no-op on the owner-ticket path
    mov  r12, rax
    test rax, rax
    jnz  .bound
    mov  byte [rel prin_login_refusal], SESSION_UNLOCK_CRED
    jmp  .scrub
.bound:
    mov  byte [rel prin_login_stage], 4
    ; Hand only authenticate_bind's output-only pid/handle to the session owner.
    ; The password is scrubbed before this pending bind is consumed.
    mov  rdi, rax
    mov  rsi, rdx
    call session_shell_offer_bind
    test eax, eax
    jz   .scrub
    call principal_clear_bound
    xor  r12d, r12d
.scrub:
    call time_wall_local_issue_end        ; every exit, incl. the SSH sequence overflow (rc-sec N2)
    mov  qword [rel prin_wire_auth_ctx + AUTH_CTX_CREDENTIAL], 0
    mov  qword [rel prin_wire_auth_ctx + AUTH_CTX_CRED_LEN], 0
    mov  rdi, [rbx + REQ_ARG]
    call prin_token_len
    mov  rsi, rax
    mov  rdi, [rbx + REQ_ARG]
    lea  rdx, [rel str_pr_audit_login]
    mov  ecx, str_pr_audit_login.len
    call principal_scrub_wire_secret
    test r12, r12
    jz   .denied
    ; The ONE explicit owner-unlock grant, consumed by the session unlock core.
    mov  byte [rel prin_login_stage], 5
    mov  edi, SESSION_METHOD_AUTHLOGIN
    call session_shell_arm_explicit_unlock
    call session_shell_unlock
    test eax, eax
    jz   .unlocked
    call session_shell_lock
    jmp  .denied
.unlocked:
    mov  byte [rel prin_login_stage], 6
    call prin_out_reset
    lea  rdi, [rel str_pr_login_ok]
    call prin_out_str
    mov  rdi, r12
    call prin_out_dec
    lea  rdi, [rel str_pr_key_handle]
    call prin_out_str
    call principal_login_nonce_reply
%if !PAOS_PUBLIC_BUILD
    cmp byte [rel pu_fallback], 1
    jne .publish_login
    lea rdi, [rel pu_fallback_text]
    call prin_out_str
%endif
.publish_login:
    call principal_publish_wire_reply
    pop  r12
    pop  rbx
    ret
.denied:
    ; A refused login is a refusal on every projection (SSH exit 6); the UDP
    ; lean envelope does not branch on the code, so its bytes are unchanged.
    mov  rax, [rel prin_login_rsp]
    mov  qword [rax + RSP_CODE], CMDE_AUTHDENY
    movzx edi, byte [rel prin_login_refusal]
    test edi, edi
    jz   .denied_reply
    mov  esi, SESSION_METHOD_AUTHLOGIN
    call session_shell_audit_unlock
.denied_reply:
    call prin_out_reset
    cmp  byte [rel prin_login_refusal], SESSION_UNLOCK_SSH
    jne  .denied_password
    lea  rdi, [rel str_pr_login_ssh]
    call prin_out_str
    call principal_login_nonce_reply
    jmp  .publish_denied
.denied_password:
    lea  rdi, [rel str_pr_login_fail]
    call prin_out_str
    mov  rdi, [rel prin_password_failures]
    call prin_out_dec
    call principal_login_nonce_reply
%if !PAOS_PUBLIC_BUILD
    cmp byte [rel pu_state], 0
    je .publish_denied
    lea rdi, [rel pu_login_wait]
    call prin_out_str
%endif
.publish_denied:
    call principal_publish_wire_reply
    pop  r12
    pop  rbx
    ret

; Optional AUTHLOGIN suffix: exactly " nonce=" plus 32 lowercase hex digits.
; Only these bounded non-secret bytes survive input redaction. Legacy clients
; without a nonce retain their existing wire shape.
principal_login_nonce:
    mov  byte [rel prin_login_nonce], 0
    cmp  byte [rdi], 0
    je   .ok
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    cmp  dword [rdi], 'nonc'
    jne  .bad
    cmp  word [rdi + 4], 'e='
    jne  .bad
    add  rdi, 6
    xor  ecx, ecx
.validate:
    mov  al, [rdi + rcx]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .next
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
.next:
    inc  ecx
    cmp  ecx, 32
    jb   .validate
    cmp  byte [rdi + 32], 0
    jne  .bad
    mov  rsi, rdi
    lea  rdi, [rel prin_login_nonce]
    mov  ecx, 33
    cld
    rep  movsb
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

principal_login_nonce_reply:
    cmp  byte [rel prin_login_nonce], 0
    je   .out
    lea  rdi, [rel str_pr_nonce]
    call prin_out_str
    lea  rdi, [rel prin_login_nonce]
    call prin_out_str
.out:
    ret
str_pr_nonce: db " nonce=",0
prin_login_nonce: times 33 db 0

; AUTHSYS <asserted_pid> — owner-permitted live-wire proof that the machine-held
; SYSTEM_KEY binds pid=2 even when the caller asserts owner. It runs the exact
; KV header-builder (without committing) and the real AI-hook BOOT gate.
; The wire diagnostic itself is owner-permitted because the internal AI-hook
; operational positive control advances the shared durable replay floor.
cmd_verb_authsys:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    call principal_execution_snapshot
    mov  r12, rax
    mov  r13, rdx
    ; Capture the already-authenticated PASSWORD session handle before the
    ; SYSTEM_KEY bind changes the active principal. The KV witness consumes the
    ; handle but never receives password/master/verifier bytes.
    mov  edi, PRIN_OWNER
    call principal_credential
    test rax, rax
    jz   .fail
    mov  [rel prin_wire_owner_credential], rax
    mov  [rel prin_wire_owner_credential_len], rdx
    call principal_credentials_init
    test eax, eax
    jnz  .fail
    call principal_system_auth_credential
    test rax, rax
    jz   .fail
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_CRED_LEN], rdx
    mov  rdi, [rbx + REQ_ARG]
    call prin_parse_u64
    mov  [rel prin_wire_auth_ctx + AUTH_CTX_ASSERTED_PID], rax
    mov  edi, AUTH_BIND_SYSTEM_KEY
    lea  rsi, [rel prin_wire_auth_ctx]
    call authenticate_bind
    cmp  rax, PRIN_SYSTEM
    jne  .fail
    lea  rdi, [rel str_verb_authkvprobe]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  edi, eax
    xor  esi, esi
    call command_aihook_submit_authorized
    cmp  rdx, CMDE_OK
    jne  .fail
    cmp  rax, PRIN_SYSTEM
    jne  .fail
    lea  rdi, [rel str_verb_boot_probe]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  edi, eax
    lea  rsi, [rel str_pr_boot_probe_arg]
    call command_aihook_submit_authorized
    cmp  rdx, CMDE_AUTHDENY
    jne  .fail
    ; The diagnostic consumes the nested refusal and returns its own earned
    ; projection; do not let command_udp select the nested staging buffer.
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_refusal_ready], 0
    call prin_out_reset
    lea  rdi, [rel str_pr_system_bound]
    call prin_out_str
    mov  rdi, PRIN_SYSTEM
    call prin_out_dec
    lea  rdi, [rel str_pr_system_asserted]
    call prin_out_str
    mov  rdi, [rel prin_wire_auth_ctx + AUTH_CTX_ASSERTED_PID]
    call prin_out_dec
    lea  rdi, [rel str_pr_system_refused]
    call prin_out_str
    call principal_publish_wire_reply
    mov  qword [rel prin_wire_owner_credential], 0
    mov  qword [rel prin_wire_owner_credential_len], 0
    mov  rdi, r12
    mov  rsi, r13
    call principal_restore_execution
    pop  r13
    pop  r12
    pop  rbx
    ret

.fail:
    call prin_out_reset
    lea  rdi, [rel str_pr_system_fail]
    call prin_out_str
    call principal_publish_wire_reply
    mov  qword [rel prin_wire_owner_credential], 0
    mov  qword [rel prin_wire_owner_credential_len], 0
    mov  rdi, r12
    mov  rsi, r13
    call principal_restore_execution
    pop  r13
    pop  r12
    pop  rbx
    ret

; Protected in-process operational fixture. It is reached through the same
; system-authenticated AI-hook and command gate as native operational work,
; then exercises the real KV header + AEAD path without committing a record.
cmd_verb_authkvprobe:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call principal_current
    cmp  rax, PRIN_SYSTEM
    jne  .denied
    mov  rdi, [rel prin_wire_owner_credential]
    mov  rsi, [rel prin_wire_owner_credential_len]
    call kvstore_system_attribution_selftest
    cmp  eax, PRIN_SYSTEM
    jne  .denied
    mov  qword [rbx + RSP_VAL], PRIN_SYSTEM
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret
.denied:
    mov  qword [rbx + RSP_VAL], 0
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: PRINWRITE <pid> <token> — store a row tagged with pid carrying token.
;   NEGATIVE BARRIER (deterministic code): pid != OWNER => DENIED, no row written.
;   Reply "PRINWRITE ACK pid=N token=..." or "ERR cross_principal_write_denied".
; ---------------------------------------------------------------------------
cmd_verb_prinwrite:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rax, [rdi + REQ_ARG]               ; ptr to "<pid> <token>"
    mov  rdi, rax
    call prin_parse_u64                     ; RAX = pid, RDI advanced past digits
    mov  r14, rax                           ; r14 = requested pid
    call prin_skip_sp                       ; RDI -> token start
    mov  r15, rdi                           ; r15 = token ptr
    ; --- barrier: only the OWNER may write (v1 caller principal == OWNER) ---
    cmp  r14, PRIN_OWNER
    jne  .denied
    ; store the row: pid + token (copy until space/CR/LF/NUL, bounded)
    mov  [rel prin_row_pid], r14
    lea  rdi, [rel prin_row_token]
    mov  rsi, r15
    call prin_copy_token                    ; copies bounded token into the row
    mov  byte [rel prin_row_present], 1
    ; reply "PRINWRITE ACK pid=N token=..."
    call prin_out_reset
    lea  rdi, [rel str_pr_wr_ack]
    call prin_out_str
    mov  rdi, [rel prin_row_pid]
    call prin_out_dec
    lea  rdi, [rel str_pr_token]
    call prin_out_str
    lea  rdi, [rel prin_row_token]
    call prin_out_str
    mov  byte [rel prin_out_ready], 1
    jmp  .reply
.denied:
    call prin_out_reset
    lea  rdi, [rel str_pr_denied]
    call prin_out_str
    mov  byte [rel prin_out_ready], 1
.reply:
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; VERB: PRINREAD <pid> — per-principal read-back. If a row exists for pid,
;   reply "pid=N token=..." (the exact stored token + the pid). Otherwise
;   "pid=N no row" (a foreign/forged pid surfaces NO token).
; ---------------------------------------------------------------------------
cmd_verb_prinread:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rax, [rdi + REQ_ARG]
    mov  rdi, rax
    call prin_parse_u64                     ; RAX = requested pid
    mov  r14, rax
    call prin_out_reset
    lea  rdi, [rel str_pr_pid]
    call prin_out_str
    mov  rdi, r14
    call prin_out_dec
    ; row present AND pid matches the stored owner row?
    cmp  byte [rel prin_row_present], 1
    jne  .norow
    mov  rax, [rel prin_row_pid]
    cmp  rax, r14
    jne  .norow
    lea  rdi, [rel str_pr_token]
    call prin_out_str
    lea  rdi, [rel prin_row_token]
    call prin_out_str
    jmp  .reply
.norow:
    lea  rdi, [rel str_pr_norow]
    call prin_out_str
.reply:
    mov  byte [rel prin_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; VERB: PRINSWITCH — run the OWNER->OWNER paging-domain switch, report cr3.
;   Reply "SW=ok cr3_saved=0x.. cr3_restored=0x..".
; ---------------------------------------------------------------------------
cmd_verb_prinswitch:
    call cmd_handler_prologue
    push rdi
    push rsi
    call principal_switch
    call prin_out_reset
    lea  rdi, [rel str_pr_sw_ok]
    call prin_out_str
    mov  rdi, [rel prin_cr3_saved]
    call prin_out_hex
    lea  rdi, [rel str_pr_sw_rest]
    call prin_out_str
    mov  rdi, [rel prin_cr3_restored]
    call prin_out_hex
    mov  byte [rel prin_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; VERB: PRINKDF <salt_hex> <cred> — DERIVE a key via the KDF; reply "DK=<hex>".
;   A wrong cred yields a DIFFERENT derived key (never the owner key).
; ---------------------------------------------------------------------------
cmd_verb_prinkdf:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rax, [rdi + REQ_ARG]               ; "<salt_hex> <cred>"
    mov  rdi, rax
    lea  rsi, [rel prin_kdf_salt]
    call prin_parse_hexbytes                ; RAX = salt byte count, RDI past hex
    mov  r14, rax                           ; salt_len
    call prin_skip_sp                       ; RDI -> cred start
    mov  r15, rdi                           ; cred ptr
    mov  rdi, r15
    call prin_token_len                     ; RAX = cred length (to space/CR/NUL)
    mov  r13, rax                           ; cred_len
    ; derive: principal_derive(salt_ptr, salt_len, cred_ptr, cred_len, out, out_len)
    lea  rdi, [rel prin_kdf_salt]
    mov  rsi, r14
    mov  rdx, r15
    mov  rcx, r13
    lea  r8,  [rel prin_kdf_dk]
    mov  r9,  PRIN_DK_LEN
    call principal_derive
    ; reply "DK=<hex>"
    call prin_out_reset
    lea  rdi, [rel str_pr_dk]
    call prin_out_str
    lea  rdi, [rel prin_kdf_dk]
    mov  rsi, PRIN_DK_LEN
    call prin_out_hexbytes
    mov  byte [rel prin_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; arg-parse helpers (operate on RDI = token ptr; leave RDI past the consumed run)
; ---------------------------------------------------------------------------
; prin_parse_u64(RDI=ptr) -> RAX = leading decimal value (0 if none), RDI past digits.
prin_parse_u64:
    xor  eax, eax
.loop:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul rax, rax, 10
    add  rax, rcx
    inc  rdi
    jmp  .loop
.done:
    ret

; prin_skip_sp(RDI=ptr) -> RDI advanced past any run of spaces.
prin_skip_sp:
    cmp  byte [rdi], ' '
    jne  .done
    inc  rdi
    jmp  prin_skip_sp
.done:
    ret

; prin_token_len(RDI=ptr) -> RAX = bytes until space/CR/LF/NUL (RDI unchanged).
prin_token_len:
    xor  eax, eax
.loop:
    movzx ecx, byte [rdi + rax]
    test cl, cl
    jz   .done
    cmp  cl, ' '
    je   .done
    cmp  cl, 13
    je   .done
    cmp  cl, 10
    je   .done
    inc  eax
    jmp  .loop
.done:
    ret

; prin_copy_token(RDI=dst, RSI=src) — copy the token (to space/CR/LF/NUL),
;   bounded to PRIN_TOKEN_MAX-1, NUL-terminate. clobbers RAX,RCX.
prin_copy_token:
    xor  ecx, ecx
.loop:
    cmp  ecx, PRIN_TOKEN_MAX - 1
    jae  .done
    movzx eax, byte [rsi + rcx]
    test al, al
    jz   .done
    cmp  al, ' '
    je   .done
    cmp  al, 13
    je   .done
    cmp  al, 10
    je   .done
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .loop
.done:
    mov  byte [rdi + rcx], 0
    ret

; prin_parse_hexbytes(RDI=ptr, RSI=dst) -> RAX = byte count, RDI past hex run.
;   Parses pairs of hex nibbles into dst (bounded PRIN_SALT_MAX). An odd trailing
;   nibble is ignored. clobbers RAX,RCX,RDX,R8,R9.
prin_parse_hexbytes:
    xor  r8d, r8d                           ; byte count
.pair:
    cmp  r8d, PRIN_SALT_MAX
    jae  .done
    movzx ecx, byte [rdi]                    ; high nibble
    call prin_hexval                         ; RAX = nibble or -1
    cmp  eax, -1
    je   .done
    mov  edx, eax                            ; high
    movzx ecx, byte [rdi + 1]                ; low nibble
    call prin_hexval
    cmp  eax, -1
    je   .done
    shl  edx, 4
    or   edx, eax                            ; byte = (high<<4)|low
    mov  [rsi + r8], dl
    inc  r8d
    add  rdi, 2
    jmp  .pair
.done:
    mov  eax, r8d
    ret

; prin_hexval(ECX=ascii) -> EAX = 0..15 or -1. clobbers EAX.
prin_hexval:
    mov  eax, ecx
    sub  eax, '0'
    cmp  eax, 9
    jbe  .ok
    mov  eax, ecx
    or   eax, 0x20                           ; tolower
    sub  eax, 'a'
    cmp  eax, 5
    ja   .bad
    add  eax, 10
.ok:
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; staged-reply buffer helpers (mirror the gui_out_* / therm_out_* pattern)
; ---------------------------------------------------------------------------
prin_out_reset:
    lea  rax, [rel prin_out_buf]
    mov  [rel prin_out_cur], rax
    ret
; prin_out_str(RDI=cstr) — append NUL-terminated string at the cursor.
prin_out_str:
    mov  rsi, [rel prin_out_cur]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel prin_out_cur], rsi
    ret
; prin_out_dec(RDI=value) — append unsigned decimal via canonical fmt_dec (G1).
prin_out_dec:
    mov  rsi, [rel prin_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel prin_out_cur], rsi
    ret
; prin_out_hex(RDI=value) — append "0x" + lowercase hex via canonical fmt_hex (G1).
prin_out_hex:
    push rdi
    lea  rdi, [rel str_pr_0x]
    call prin_out_str
    pop  rdi
    mov  rsi, [rel prin_out_cur]
    push rsi
    xor  edx, edx
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel prin_out_cur], rsi
    ret
; prin_out_hexbytes(RDI=ptr, RSI=len) — append 2 lowercase hex per byte (no 0x).
prin_out_hexbytes:
    push rbx
    push r12
    push r13
    mov  r12, rdi                            ; src
    mov  r13, rsi                            ; len
    mov  rbx, [rel prin_out_cur]
    xor  ecx, ecx
.byte:
    cmp  rcx, r13
    jae  .done
    movzx eax, byte [r12 + rcx]
    mov  edx, eax
    shr  edx, 4                              ; high nibble
    lea  r8, [rel prin_hex_digits]
    movzx edx, byte [r8 + rdx]
    mov  [rbx], dl
    inc  rbx
    mov  edx, eax
    and  edx, 0x0F                           ; low nibble
    movzx edx, byte [r8 + rdx]
    mov  [rbx], dl
    inc  rbx
    inc  rcx
    jmp  .byte
.done:
    mov  byte [rbx], 0
    mov  [rel prin_out_cur], rbx
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; data (in-image, RW under our page tables) — defined here so command_udp.asm's
; udp_send_reply can reference prin_out_buf/prin_out_ready/prin_m_* (it is
; %included AFTER us).
; ---------------------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_sec_principal_0 0
align 8
prin_out_cur:      dq 0
prin_owner_id:     dq 0                       ; established at selftest (== OWNER)
prin_active_pid:   dq PRIN_OWNER              ; output of the last successful bind
prin_state_lock:   db 0
prin_credential_lock: db 0
prin_authz_table_ready: db 0
prin_authz_bind_ready:  db 0
prin_authz_lock_ready:  db 0
prin_password_rekey_result: db 0
prin_enroll_had_password: db 0
align 8
; Standing authority is DATA: {pid, cap_word}.  No cmp-chain encodes roles.
principal_cap_table:
    dq PRIN_OWNER,  PRIN_OWNER_CAPS
    dq PRIN_SYSTEM, PRIN_SYSTEM_CAPS
    dq PRIN_ADVISOR, PRIN_ADVISOR_CAPS
principal_cap_table_end:
%endmacro
WDATA_DEFER WDATA_sec_principal_0
PRIN_CAP_TABLE_ROWS equ ((principal_cap_table_end - principal_cap_table) / PRIN_CAP_ROW_SIZE)
%if PRIN_CAP_TABLE_ROWS != 3
    %error "principal capability table row drift"
%endif

; Credential-to-principal binding is independently DATA-driven. Each verified
; method selects its authoritative output principal from this table.
authenticate_bind_table:
    dq AUTH_BIND_OWNER_RSA, PRIN_OWNER
    dq AUTH_BIND_PASSWORD,  PRIN_OWNER
    dq AUTH_BIND_SYSTEM_KEY, PRIN_SYSTEM
    dq AUTH_BIND_ED25519,   PRIN_OWNER
%if !PAOS_PUBLIC_BUILD
    dq AUTH_BIND_PUSH,      PRIN_OWNER
%endif
authenticate_bind_table_end:
AUTH_BIND_TABLE_ROWS equ ((authenticate_bind_table_end - authenticate_bind_table) / AUTH_BIND_ROW_SIZE)
%if AUTH_BIND_TABLE_ROWS != (5 - PAOS_PUBLIC_BUILD)
    %error "Task2501 four rows plus Task2504 PUSH row required"
%endif

; Credential DATA. One salt/iteration/verifier, plus optional authenticated v2
; key wrapper. Password/master/KEK and plaintext DATA key remain RAM-only.
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_sec_principal_1 0
align 16
prin_password_salt:       times PRIN_PASSWORD_SALT_LEN db 0
prin_password_iterations: dd 600000
prin_password_verifier:   times PRIN_PASSWORD_VERIFIER_LEN db 0
prin_password_enrolled:   db 0
prin_rotation_requested:  db 0
prin_data_wrap_ready:     db 0
prin_data_wrap: times PRIN_WRAP_SIZE db 0
prin_rotation_key: times 32 db 0
prin_wrap_req: times AEAD_REQ_SZ db 0
prin_owner_session_ready: db 0
prin_owner_boot_ready:    db 0                 ; prin_owner_boot_key holds this boot's owner key
prin_system_secret_ready: db 0
prin_owner_keeps_present: db 0
prin_boot_fixture_allowed: db 1
prin_boot_fixture_active: db 0
prin_system_bs:           db 0                 ; slice 2: prin_system_secret came from the BS-only copy
prin_record_moved:        db 0                 ; slice 2: the record is (to be written as) v3
prin_system_lost:         db 0                 ; slice 2: v3 record and the BS copy gone
prin_sysx_scrub_tried:    db 0                 ; slice 2: one scrub attempt per boot
prin_sysx_scrub_result:   db 0                 ; 0 none, 1 verified, 2 failed, 3 unverified
prin_sysx_rt_version:     db 0                 ; last validated load / exact write readback
align 8
prin_moved_seq:           dq 0                 ; slice 2: v3 record's authorizing manifest sequence
prin_password_failures:   dq 0
prin_password_last_sequence: dq 0
prin_password_backoff_until: dq 0
prin_password_now:        dq 0
prin_pw_fail_step:        db 0                 ; last PASSWORD-bind check reached (serial diagnostic)
align 8
prin_owner_session_key:   times PRIN_CREDENTIAL_LEN db 0
prin_owner_boot_key:      times PRIN_CREDENTIAL_LEN db 0   ; P1: set by a password sign-in, wiped before power-off
prin_system_secret:       times PRIN_CREDENTIAL_LEN db 0
prin_password_master:     times 32 db 0
prin_password_check:      times 32 db 0
prin_password_copy:       times PRIN_PASSWORD_MAX db 0   ; RAM-only credential snapshot (wiped with scratch)
align 8
prin_password_copy_len:   dq 0
align 8
prin_record:              times PRIN_RECORD_SIZE db 0
prin_record_verify:       times PRIN_RECORD_SIZE db 0
prin_record_size:         dq PRIN_RECORD_SIZE
prin_record_verify_size:  dq PRIN_RECORD_SIZE
prin_record_attrs:        dd 0
prin_record_verify_attrs: dd 0

; 7268a9b4-3f8a-45a0-9f8d-1b73e9ac2501
prin_record_guid:
    dd 0x7268a9b4
    dw 0x3f8a,0x45a0
    db 0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x25,0x01
prin_record_name:
    dw 'P','a','O','S','P','r','i','n','c','i','p','a','l','C','r','e','d',0
str_prin_nvg_tag: db "principal_record_persist",0
str_prin_owner_not_zbound:  db "[PAOS64] owner record predates the owner stage key; the RT verifier stands [owner.store_not_zbound]",13,10,0
str_prin_owner_rt_ignored:  db "[PAOS64] owner store holds the password; the RT verifier differs and is ignored [owner.verifier_rt_ignored]",13,10,0
str_prin_sysx_disagree:     db "[PAOS64] system secret: RT record disagrees; BS copy kept, record moves [sec.sysx.disagree]",13,10,0
str_prin_sysx_lost:         db "[PAOS64] system secret: v3 record and no BS copy; new secret [sec.sysx.lost]",13,10,0
str_prin_sysx_restored:     db "[PAOS64] system secret: RT record absent; BS copy restored [sec.sysx.restored]",13,10,0
str_prin_sysx_scrub:        db "[PAOS64] system secret: RT record scrubbed (v3) [sec.sysx.scrub]",13,10,0
str_prin_sysx_scrub_failed: db "[PAOS64] system secret: RT scrub not verified [sec.sysx.scrub_failed]",13,10,0
str_prin_sysx_scrub_unverified: db "[PAOS64] system secret: RT scrub skipped firmware I/O [sec.sysx.scrub_unverified]",13,10,0
str_prin_sysx_status_bs:       db " SYSX_BS=",0
str_prin_sysx_status_version:  db " SYSX_RT_VERSION=",0
str_prin_sysx_status_scrub:    db " SYSX_SCRUB=",0
str_prin_sysx_status_moved:    db " SYSX_MOVED_SEQ=",0
str_prin_sysx_status_manifest: db " SYSX_MANIFEST_SEQ=",0

; Reserved elevation fields exist in AUTH_CTX at v1 and remain zero/unused.
prin_kat_auth_ctx:        times AUTH_CTX_SIZE db 0
prin_wire_auth_ctx:       times AUTH_CTX_SIZE db 0
prin_login_stage:         db 0          ; last AUTHLOGIN boundary (owner STATUS only)
prin_login_step:          db 0          ; snapshot, never another local/password attempt
prin_login_refusal:       db 0          ; AUTHLOGIN: SESSION_UNLOCK_* audit reason of a refusal
align 8
prin_login_rsp:           dq 0          ; AUTHLOGIN: the dispatcher's response envelope
prin_wire_owner_credential: dq 0
prin_wire_owner_credential_len: dq 0
prin_kat_verifier:        times 32 db 0
prin_kat_kek_input:       times 32 db 0
prin_kat_domain_salt:     db 0x20,0x25,0x08,0x26,0x50,0x61,0x4f,0x53
                          db 0x69,0x64,0x65,0x6e,0x74,0x69,0x74,0x79
prin_system_kat_secret:   times 32 db 0x5a
prin_kat_owner_proof:     db "AUTH1-owner-proof-kat"
.len equ $ - prin_kat_owner_proof
prin_boot_fixture_salt:   db "PaOS-boot-fixture-salt-v1"
.len equ $ - prin_boot_fixture_salt
prin_boot_fixture_domain: db "PaOS-boot-fixture-session-v1"
.len equ $ - prin_boot_fixture_domain
prin_verify_domain:       db "PaOS-auth-verify-v1"
.len equ $ - prin_verify_domain
prin_kek_domain:          db "PaOS-auth-kek-v1"
.len equ $ - prin_kek_domain
%if !PAOS_PUBLIC_BUILD
prin_push_handle_domain:  db "paos-push-handle-v1"
.len equ $ - prin_push_handle_domain
%endif

; --- the stored data ROW (header carries the owning-principal id field) ---
prin_row_pid:      dq 0                       ; owning-principal id (the tagged field)
prin_row_present:  db 0
align 8
prin_row_token:    times PRIN_TOKEN_MAX db 0
; --- paging-domain switch scratch ---
prin_cr3_saved:    dq 0
prin_cr3_restored: dq 0
; --- KDF working buffers ---
prin_kdf_salt:     times PRIN_SALT_MAX db 0
prin_kdf_dk:       times PRIN_DK_LEN   db 0
prin_dk_a:         times PRIN_DK_LEN   db 0   ; KAT determinism check
prin_dk_b:         times PRIN_DK_LEN   db 0
; --- KDF known-answer-test inputs (salt = 00 11 22 33 44 55 66 77) ---
prin_kat_salt:     db 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
%endmacro
WDATA_DEFER WDATA_sec_principal_1
PRIN_KAT_SALT_LEN  equ 8
; --- BOOTLOG ride-along flags (set by the selftest iff its seam held) ---
prin_m_owner:      db 0
prin_m_tagged:     db 0
prin_m_switch:     db 0
prin_m_kdf:        db 0
prin_m_auth_bind:  db 0
prin_m_auth_method: db 0
prin_m_auth_pbkdf2: db 0
prin_m_auth_system: db 0
prin_out_ready:    db 0                       ; a per-command reply line is staged in prin_out_buf
align 8
prin_out_buf:      times 640 db 0             ; bounded PUSHSTAT counters + nonce

prin_hex_digits:   db "0123456789abcdef"

; --- verb name strings (matched verbatim by command_lookup) ---
str_verb_prinwrite:  db "PRINWRITE", 0
str_verb_prinread:   db "PRINREAD", 0
str_verb_prinswitch: db "PRINSWITCH", 0
str_verb_prinkdf:    db "PRINKDF", 0
str_verb_authenroll: db "AUTHENROLL",0
str_verb_authlogin:  db "AUTHLOGIN",0
str_verb_authsys:    db "AUTHSYS",0
str_verb_authkvprobe: db "AUTHKVPROBE",0

; --- staged reply fragments ---
str_pr_wr_ack:     db "PRINWRITE ACK pid=", 0
str_pr_token:      db " token=", 0
str_pr_pid:        db "pid=", 0
str_pr_norow:      db " no row", 0
str_pr_denied:     db "ERR cross_principal_write_denied", 0
str_pr_sw_ok:      db "SW=ok cr3_saved=", 0
str_pr_sw_rest:    db " cr3_restored=", 0
str_pr_dk:         db "DK=", 0
str_pr_0x:         db "0x", 0
str_pr_enroll_ok:  db "AUTHENROLL OK record=salt,iter,verifier rekey=",0
str_pr_enroll_fresh: db "fresh",0
str_pr_enroll_migrated: db "migrated",0
str_pr_enroll_fail: db "AUTHENROLL REFUSED migration_or_persist_failed",0
str_pr_enroll_store: db "AUTHENROLL REFUSED owner_store_holds_password",0
str_pr_login_ok:   db "AUTHLOGIN OK pid=",0
str_pr_key_handle: db " key_handle=session",0
str_pr_login_stage: db " LOGIN_STAGE=",0
str_pr_login_step: db " LOGIN_STEP=",0
str_pr_login_nonce_status: db " LOGIN_NONCE=",0
str_pr_login_nonce_none: db "none",0
str_pr_login_fail: db "AUTHLOGIN REFUSED wrong_password failures=",0
str_pr_login_ssh:  db "AUTHLOGIN REFUSED ssh_never_unlocks",0
str_pr_pw_fail_step: db "[PAOS64] P2 principal: password bind refused step=",0
str_pr_system_bound: db "AUTHSYS BOUND pid=",0
str_pr_system_asserted: db " asserted_pid=",0
str_pr_system_refused: db " operational=ALLOWED boot=REFUSED reason=principal_capability_denied path=aihook kv_owner=2 kv_path=seal_open cross_pid=REFUSED owner_to_system=REFUSED",0
str_pr_system_fail: db "AUTHSYS REFUSED credential_unavailable",0
str_pr_audit_enroll: db "AUTHENROLL credential=<redacted>"
.len equ $ - str_pr_audit_enroll
str_pr_audit_login: db "AUTHLOGIN credential=<redacted>"
.len equ $ - str_pr_audit_login
; One-release compatibility input for pre-2501 DATA envelopes. It is never a
; principal credential source and is wiped immediately after empty-proof or a
; verified read-old/rewrap-new safe_write transaction.
prin_legacy_owner_migration_credential: db "PAOS-OWNER-CRED-v1"
.len equ $ - prin_legacy_owner_migration_credential
str_verb_boot_probe: db "BOOT",0
str_pr_boot_probe_arg: db "INVALID_SYSTEM_PROBE",0

; --- fixed boot KAT token stored in the row for the tagged-seam selftest ---
str_prin_boot_token: db "PRIN-BOOT-KAT-OWNER"
.len equ $ - str_prin_boot_token

; --- KDF KAT credential (paired with prin_kat_salt) ---
str_prin_kat_cred: db "paoskat"
.len equ $ - str_prin_kat_cred

; --- the four regression/BOOTLOG markers (exact strings per contract 1053) ---
str_prin_m_owner:  db "[PAOS64] P2 principal: OWNER established (id non-NULL) [principal.owner]", 13, 10, 0
str_prin_m_tagged: db "[PAOS64] P2 principal: task/log/row carry owning-principal field [principal.tagged]", 13, 10, 0
str_prin_m_switch: db "[PAOS64] P2 principal: paging-domain switch OWNER->OWNER PASS [principal.switch]", 13, 10, 0
str_prin_m_kdf:    db "[PAOS64] P2 principal: auth KDF derive KAT PASS [principal.kdf]", 13, 10, 0
str_auth2501_bind: db "[PAOS64] identity rung 2501: method-tagged authenticate_bind returns verifier-selected principal only [auth.seam.bind]",13,10,0
str_auth2501_method: db "[PAOS64] identity rung 2501: OWNER_RSA PASSWORD SYSTEM_KEY and ED25519 method rows present [auth.seam.method]",13,10,0
str_auth2501_pbkdf2: db "[PAOS64] identity rung 2501: PBKDF2-SHA256 600000 plus verifier/KEK domain separation KAT [auth.password.pbkdf2]",13,10,0
str_auth2501_system: db "[PAOS64] identity rung 2501: CSPRNG system credential binds PRIN_SYSTEM without owner key [auth.system.credential]",13,10,0

; S1b-2c owner-store password consumer state (zero-initialised: no file bytes).
; prin_owner_pw holds the sealed verifier for this boot (reset_wipe KEY_MATERIAL);
; prin_rt_pw is what the RT record said at load, written back unchanged by
; principal_record_persist while the store decides.
%macro WDATA_BSS_sec_principal_owner 0
alignb 16
prin_owner_pw:        resb PRIN_OWNER_PW_LEN
alignb 16
prin_rt_pw:           resb PRIN_OWNER_PW_LEN
prin_rt_pw_flag:      resb 1            ; the RT record's PASSWORD flag at load
prin_pw_authority:    resb 1            ; PRIN_PWA_*
prin_owner_pw_state:  resb 1            ; 0 not taken, 1 taken with OWR_LOCAL, 2 taken, none
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_principal_owner
