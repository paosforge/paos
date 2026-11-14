;; MODULE core/reset_wipe
%include "core/abi/build_profile.inc"
;; LAYER 1
;; EXPORTS reset_wipe_all, reset_wipe_halt, reset_wipe_done
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:sec
; ============================================================================
; core/reset_wipe.asm — SEC-pre-reset-wipe-hook (root 14:10, admin 14:11): the
; ONE pre-reset/handoff hook. A warm reset (firmware ResetSystem, the CF9 port)
; keeps DRAM, and what runs next may be another OS (BOOT WIN/LINUX) or anything
; a remote REBOOT lands on, so no long-lived key material may survive it.
;
; reset_wipe_all zeroes every long-lived key buffer of this image and clears
; the ready flag its consumers check. It is a POINT OF NO RETURN: some of these
; keys have consumers that do not check any flag (the SSH host signer uses its
; seed unconditionally), so PaOS must never resume after it. Every reset site
; that can return (ResetSystem and CF9 both ignored) ends in reset_wipe_halt
; instead of resuming. On every CPU: the hook first sets reset_wipe_done, so
; when another CPU ran it (a fatal fault on an AP, srcreview R2) the BSP main
; loop halts at its next pass (boot/header .halt) and principal_record_persist
; refuses meanwhile, so a zero verifier or SYSTEM secret never becomes durable. gauntlet_v2/tools/reset_wipe_lint.py (make lint) enforces that
; every reset/handoff site calls this first and holds the inventory: each
; RW_* line below names a label listed there with its reason, and a new
; key-material-named buffer fails the lint until it is classified.
;
; Fault safe: no call, no lock, no stack use beyond the saved registers, so a
; fatal exception (core/idt isr_common) and the TCO proof hang can run it.
; It references data owned by higher layers by address only (one image).
; ============================================================================

%macro RW_WIPE 2                        ; label, byte count
    lea  rdi, [rel %1]
    mov  ecx, %2
    rep  stosb
%endmacro
%macro RW_WIPE_RANGE 2                  ; first label, end label (exclusive)
    lea  rdi, [rel %1]
    mov  ecx, %2 - %1
    rep  stosb
%endmacro
%macro RW_WIPE_HEAP 2                   ; label of a heap pointer (0 = never allocated), byte count
    mov  rdi, [rel %1]
    test rdi, rdi
    jz   %%none
    mov  ecx, %2
    rep  stosb
%%none:
%endmacro
%macro RW_CLEAR 1                       ; a 1-byte ready / valid flag
    mov  byte [rel %1], 0
%endmacro

; reset_wipe_all — zero the image's long-lived key material and its ready
;   flags. Preserves every register and RFLAGS (DF is cleared inside only).
reset_wipe_all:
    pushfq
    push rax
    push rcx
    push rdi
    cld
    mov  byte [rel reset_wipe_done], 1  ; first: every other CPU stops trusting RAM keys
    xor  eax, eax
    ; the owner's DATA key, its boot copy and a staged 2FA copy (P1)
    RW_CLEAR session_local_unlock_seen
    RW_CLEAR prin_owner_session_ready
    RW_WIPE  prin_owner_session_key, PRIN_CREDENTIAL_LEN
    RW_CLEAR prin_owner_boot_ready
    RW_WIPE  prin_owner_boot_key, PRIN_CREDENTIAL_LEN
%if !PAOS_PUBLIC_BUILD
    RW_CLEAR pu_owner_staged
%endif
%if !PAOS_PUBLIC_BUILD
    RW_WIPE  pu_owner_stage, 32
%endif
    ; the SYSTEM (AI-operator) secret, the password verifier, and the two
    ; record buffers that hold plaintext copies of both
    RW_CLEAR prin_system_secret_ready
    RW_WIPE  prin_system_secret, PRIN_CREDENTIAL_LEN
    RW_WIPE  prin_password_verifier, PRIN_PASSWORD_VERIFIER_LEN
    RW_WIPE  prin_record, PRIN_RECORD_SIZE
    RW_WIPE  prin_record_verify, PRIN_RECORD_SIZE
    ; SEC slice 2: the BS-only copy of the SYSTEM secret until principal takes it
    RW_CLEAR sysx_secret_ready
    RW_WIPE  sysx_secret, 32
    ; A pre-EBS fault can interrupt the firmware read/migration before .wipe.
    RW_WIPE  sysx_secret_blob, SYSX_SIZE
    RW_WIPE  sysx_secret_verify, SYSX_SIZE
    RW_WIPE  sysx_secret_rt_record, PRIN_RECORD_SIZE
    ; owner identity S1b-1: the pre-EBS owner store pass (records hold the
    ; password verifier and owner key; the stage key derives from Y). Each is
    ; zeroed before the pass returns; a pre-EBS fault can interrupt that.
    RW_WIPE  ows_slot_buf, 2 * OWS_REC_SIZE
    RW_WIPE  ows_stage_buf, OWS_STAGE_SIZE
    RW_WIPE  ows_verify_buf, OWS_REC_SIZE
    RW_WIPE  ows_j_buf, OWS_J_SIZE
    RW_WIPE  ows_j_verify, OWS_J_SIZE
    RW_WIPE  ows_j_target, OWS_REC_SIZE
    RW_WIPE  ows_j_key, 32
    RW_WIPE  ows_j_digest, 32
    RW_WIPE  ows_stage_key, 32
    ; c2a retained public base/derived MAC and all per-request material.
    RW_CLEAR ows_wr_ready
    RW_WIPE  ows_wr_base, 512
    RW_WIPE  ows_wr_base_hash, 32
    RW_WIPE  ows_wr_zero_hash, 32
    RW_WIPE  ows_committed_hash, 32
    RW_WIPE  ows_wr_mac_key, 32
    RW_WIPE  ows_wr_stage, 608
    RW_WIPE  ows_wr_io, 608
    RW_WIPE  ows_wr_target_hash, 32
    RW_WIPE  ows_wr_pending_hash, 32
    RW_WIPE  ows_wr_digest, 32
    RW_WIPE  ows_wr_call_key, 32
    RW_WIPE_RANGE prin_stage_scratch, prin_stage_scratch_end
    RW_WIPE_RANGE ws_transient, ws_transient_end ; WiFi copied inputs/plaintext/key, including interrupted IO
    RW_WIPE_RANGE wfp_scratch, wfp_scratch_end
    RW_WIPE_RANGE wfp_intent, wfp_intent_end
    RW_CLEAR wfp_intent_active
    RW_WIPE_RANGE wfc_secret, wfc_secret_end ; native private grant/context; never changes DMA/RAM custody
    RW_WIPE_RANGE wfl_private, wfl_private_end ; private GUI draft/token/authority; preserve reentrant busy guard
    RW_CLEAR wfl_busy ; reset alone releases an interrupted outer GUI operation
    ; owner S1b-2c-0: the owner stage key Z and its pre-EBS buffers (zeroed when
    ; the owner store pass ends; a pre-EBS fault can interrupt that)
    RW_CLEAR osk_key_ready
    RW_CLEAR ig_key_ready
    RW_WIPE  osk_key, 32
    RW_WIPE  osk_blob, OSK_SIZE
    RW_WIPE  osk_verify, OSK_SIZE
    RW_WIPE  osk_tmp, 32
    ; S1b-2c: the committed record's password fields, handed from the pre-EBS
    ; pass to principal (taken or discarded once), and principal's copies
    RW_CLEAR ows_pw_ready
    RW_WIPE  ows_pw_handoff, OWS_PW_LEN
    RW_WIPE  prin_owner_pw, PRIN_OWNER_PW_LEN
    RW_WIPE  prin_rt_pw, PRIN_OWNER_PW_LEN
    ; RCQ-21: identities, bindings, plaintext records, key and AEAD request.
    RW_WIPE_RANGE vo_ident, vo_sector
    ; SEC-replay-record-mac S1: the pre-EBS read of PaOSPrincipalCred for its
    ; PASSWORD floor (v1/v2 records hold Y). Zeroed before the read returns.
    RW_WIPE  rpf_prin_buf, RPF_PRIN_MAX
    ; and its HKDF(Y) reseed key, held from pre-EBS to AUTHFLOOR while LOST
    RW_WIPE  rpf_reseed_key, 32
    RW_CLEAR rpf_key_ready
    ; the node signing identity's KEK
    RW_CLEAR nid_active_kek_valid
    RW_WIPE  nid_active_kek, 32
    ; the SSH host key seed (it IS the private key), the last KDF output and
    ; every connection's session keys (heap table)
    RW_CLEAR ssh_hostkey_ready
    RW_WIPE  ssh_host_seed, 32
    RW_WIPE  ssh_kdf_out, 32
    RW_WIPE_HEAP ssh_contexts_ptr, SSH_CTX_N * SSH_CTX_SIZE
    ; the last KEX's transcript (server or client): mpint(K), the exchange
    ; buffer (V_C..Q_S || K) and the KDF hash state; ssh_kex_scrub also zeroes
    ; them after each derivation (srcreview G1). The one-shot SHA-256 scratch
    ; holds the tail of the last hashed input (the exchange buffer ends in K).
    RW_WIPE  ssh_k_mpint, 37
    RW_WIPE  ssh_exchange_buf, SSH_EXCHANGE_CAP
    RW_WIPE  ssh_hash_ctx, S256_CTX_SZ
    RW_WIPE  sha256_one_ctx, S256_CTX_SZ
    RW_WIPE  sha256_work, 64 * 4
    ; the SSH client: identity seeds, known_hosts and identity-record MAC keys, the live session's
    ; region (context pointers, state, the ephemeral scalar), its parked copies
    ; (heap), and the session slots (heap: each a full SSH ctx with the traffic
    ; keys, shared secret and H, srcreview R1). Heap sizes are the allocators'
    ; own HEAP_ONCE_ACCESSOR expressions (reset_wipe_lint compares them).
    RW_CLEAR ssh_cli_id_ready
    RW_WIPE  ssh_cli_id_seed, 32
    RW_WIPE  ssh_cli_kh_key, 32
    RW_WIPE  ssh_cli_cid_seed, 32        ; RCQ-08: a derived client seed and the record MAC key
    RW_WIPE  ssh_cli_cid_key, 32         ; (each also wiped right after its own use)
    RW_WIPE_RANGE ssh_cli_region_begin, ssh_cli_region_end
    RW_WIPE_HEAP ssh_sess_save_ptr, SSH_SESS_MAX * SSH_CLI_REGION_SIZE
    RW_WIPE_HEAP ssh_cli_slots_ptr, SSH_SESS_MAX * SSH_CLI_SLOT_SIZE
    ; TLS: the private scalar through the finished keys (tls13_wipe_secrets' range)
    RW_WIPE_RANGE tls13_private, tls13_client_finished + 36
    ; the CSPRNG's DRBG state (later output must not be reconstructible)
    RW_CLEAR csprng_initialized
    RW_WIPE  csprng_k, 32
    RW_WIPE  csprng_v, 32
    ; the MACed preference records' HMAC keys (RCQ-17 clock zone, localization,
    ; RCQ-38 L2 keyboard layout): each is HKDF of the SYSTEM secret, so a
    ; recovered key forges a record that the next boot accepts
    RW_WIPE  clock_prefs_key, 32
    RW_WIPE  lang_prefs_key, 32
    RW_WIPE  kbd_prefs_key, 32
    RW_WIPE  idle_prefs_key, 32          ; RC-lock-screen: the idle lock record's HMAC key
    RW_WIPE  app_install_grants_mac_key, 32 ; the PaOSAppGrants record's HMAC key
    RW_WIPE  ig_owner_key, 32           ; that key bound to this boot's owner
    ; RC-history: the record key H (owner-derived), the settings MAC key, the AI
    ; question ticket and the one plaintext record / stripped URL scratch
    RW_CLEAR hist_key_ready
    RW_WIPE  hist_key, 32
    RW_WIPE  hist_cfg_key, 32
    RW_WIPE  hist_ai_ticket, 16
    RW_WIPE  hist_stage, 128
    RW_WIPE  hist_url_buf, 2048
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

; reset_wipe_halt — a reset after reset_wipe_all returned (firmware ResetSystem
;   ignored and CF9 not taken), or the BSP main loop after another CPU's wipe.
;   PaOS cannot resume with its keys gone (see the header), so it stops here;
;   the owner power-cycles the machine. It wipes once more first: between an
;   AP's wipe and this halt the BSP may have loaded keys again (credentials
;   init, a CSPRNG reseed, an SSH reconnect), and a warm reset keeps DRAM.
;   Never returns.
reset_wipe_halt:
    cli
    call reset_wipe_all                 ; again (idempotent): this CPU may have reloaded keys after another CPU's wipe (srcreview G3)
    lea  rdi, [rel str_reset_wipe_halt]
    call serial_string
    call serial_fault_flush             ; the CPU halts next: queued output reaches the wire
.stop:
    hlt
    jmp  .stop

reset_wipe_done: db 0                   ; 1 once any CPU ran reset_wipe_all (never cleared)
str_reset_wipe_halt: db "[PAOS64] reset returned after the key wipe: halted, power-cycle to continue [sec.reset.halt]", 13, 10, 0
