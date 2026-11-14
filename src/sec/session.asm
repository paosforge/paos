;; MODULE sec/session
;; LAYER 5
;; PURPOSE Sole owner of the login-bound session gate and workspace policy.
;; EXPORTS session_shell_prepare_local_request, session_shell_try_request_admit, session_shell_try_launch_arm, session_shell_try_launch_disarm, session_shell_init, session_shell_register_workspace_ops, session_shell_register_local_wipe, session_shell_local_wipe, session_shell_offer_bind, session_shell_unlock, session_shell_lock, session_shell_require_unlocked, session_shell_request_principal, session_shell_local_authority, session_shell_arm_explicit_unlock, session_shell_audit_unlock, session_idle_tick, session_injected_input, session_out_buf, session_out_ready
;; IMPORTS boot/boot_v2_handoff, core/time, core/lib/fmt, core/lib/str, sec/principal, sec/idle_prefs, svc/command, svc/command_auth, svc/command_audit, boot/serial, dev/input/ps2, svc/history, sec/wifi_profile, sec/wifi_store
;; OWNER saga:session_shell
; ============================================================================
; OWNER/SYSTEM sessions consume the output-only {principal, key-handle} from
; authenticate_bind. Public Try instead binds its distinct uncredentialed local
; principal with an epoch handle; it has no standing or remote authority. No
; credential bytes, verifier, or comparison path exists here. Lock commits the
; proven desktop document first, then clears the principal and transient handle
; before a later lock-screen rung
; is allowed to paint.
;
; GUI registers document operations downward through a runtime callback table;
; sec/session never reaches upward into window state. SLEEP M1 owns persistence
; mechanics later, so this rung exposes only offer/apply and rejects doubt.
; ============================================================================

SESSION_LOCKED       equ 1
SESSION_UNLOCKED     equ 0
SESSION_NONCE_MAX    equ 64
SESSION_OUT_SIZE     equ 512
SESSION_RESTORE_NONE equ 0
SESSION_RESTORE_RAM  equ 1
SESSION_RESTORE_DOC  equ 2

; Remote-unlock split (ADMIN 2026-09-30 06:22, ADOPTED). A request that arrived
; over a remote session (AUTH1 UDP/serial, SSH exec) carries its own authority
; and never unlocks the local console as a side effect. The ONLY remote unlock
; is an EXPLICIT authenticated owner unlock (AUTHLOGIN with the owner password,
; PUSHAUTH approve): the verb handler arms a one-shot grant immediately before
; it calls the unlock core, and the transition is audit-logged. Lab/dev builds
; additionally admit the machine-fixture bind of SESSIONPROBE (test-only).
SESSION_GRANT_NONE       equ 0
SESSION_GRANT_EXPLICIT   equ 1
SESSION_GRANT_FIXTURE    equ 2
SESSION_METHOD_NONE      equ 0
SESSION_METHOD_AUTHLOGIN equ 1
SESSION_METHOD_PUSHAUTH  equ 2
SESSION_METHOD_FIXTURE   equ 3
SESSION_METHOD_LOCAL     equ 4
; audit outcomes (session_shell_audit_unlock EDI)
SESSION_UNLOCK_EXPLICIT  equ 0         ; remote explicit owner unlock succeeded
SESSION_UNLOCK_CRED      equ 1         ; explicit attempt, credential refused
SESSION_UNLOCK_TICKET    equ 2         ; explicit attempt without owner authority
SESSION_UNLOCK_IMPLICIT  equ 3         ; a non-unlock remote path tried to unlock
SESSION_UNLOCK_TEST_ONLY equ 4         ; injected input / fixture: never a human
SESSION_UNLOCK_SSH       equ 5         ; AUTHLOGIN over SSH: never unlocks

session_shell_init:
    call session_shell_pointer_context_init
    call session_shell_declare
%if PAOS_SESSION_DEV_AUTOLOGIN
    mov  byte [rel session_boot_policy], 1
%else
    mov  byte [rel session_boot_policy], 0
%endif
    call session_shell_selftest
    test eax, eax
    jnz  .locked
    cmp  byte [rel pbm_try_media], 0
    je   .installed
    ; Try takes precedence over the lab fixture, including malformed flags.
    mov  byte [rel session_boot_policy], 0
    call session_shell_bind_try_local
    test eax, eax
    jnz  .locked
    ret
.installed:
%if PAOS_SESSION_DEV_AUTOLOGIN
    call session_shell_bind_system_fixture
    test eax, eax
    jnz  .locked
    ret
%endif
.locked:
    call session_shell_lock_core
    ; Preserve the existing boot-time manifest observation without exposing
    ; document-owned windows before a principal crosses the login gate.
    call session_shell_observe_locked_workspace
    ret

; Register an opaque read-only generation source for physical enqueue custody.
; The input layer never calls the session policy from an IRQ producer.
session_shell_pointer_context_init:
    lea  rdi, [rel session_authority]
    jmp  ps2_pointer_set_context_source

; Public Try is a local volatile desktop, not an authenticated owner login.
; The principal gate checks Manager Try, native origin and an empty execution
; principal. There is no restore callback and no reusable credential: the
; non-secret key-handle field carries only this local session's epoch token.
; Refusal does not erase an existing session or advance its epoch.
session_shell_bind_try_local:
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .bad
    cmp  qword [rel session_authority_epoch], -1
    je   .bad
    call principal_try_local_begin
    cmp  rax, PRIN_TRY
    jne  .bad
    call session_shell_local_wipe ; synchronous before authority/store/workspace callbacks
    call wifi_profile_cancel
    call wifi_store_wipe
    call session_shell_clear_pending
    inc  qword [rel session_authority_epoch]
    mov  rax, [rel session_authority_epoch]
    mov  [rel session_authority], rax
    mov  [rel session_key_handle], rax
    mov  qword [rel session_bound_pid], PRIN_TRY
    mov  byte [rel session_restore_source], SESSION_RESTORE_NONE
    mov  qword [rel session_workspace_pid], 0
    mov  byte [rel session_unlock_grant], SESSION_GRANT_NONE
    mov  byte [rel session_boot_policy], 2
    mov  byte [rel session_locked], SESSION_UNLOCKED
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; RDI=authenticate_bind pid, RSI=authenticate_bind key handle.
session_shell_offer_bind:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    mov  [rel session_pending_pid], rdi
    mov  [rel session_pending_handle], rsi
    mov  byte [rel session_pending_valid], 1
    xor  eax, eax
    ret
.bad:
    call session_shell_clear_pending
    mov  eax, -1
    ret

session_shell_clear_pending:
    mov  qword [rel session_pending_pid], 0
    mov  qword [rel session_pending_handle], 0
    mov  byte [rel session_pending_valid], 0
    ret

; Consume the one-shot bind and restore the desktop. An already-unlocked
; session is idempotent; a locked session without a fresh bind refuses.
session_shell_unlock:
    call session_shell_unlock_core
    test eax, eax
    jnz  .out
    call session_shell_restore_workspace
    xor  eax, eax
.out:
    ret

session_shell_unlock_core:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    je   .already
    ; PETER RULING 2026-09-29 + ADMIN 2026-09-30 06:22 (remote-unlock split):
    ; the ONE structural choke point for every unlock path. Inside a remote
    ; request (AUTH1 UDP/serial or SSH exec in flight, outside the post-reply
    ; presentation sync that consumes a locally typed lock-screen credential)
    ; only an explicitly armed owner unlock may proceed. Everything else is an
    ; implicit remote unlock: refused and audited.
    call session_shell_remote_context
    test eax, eax
    jz   .bind
    movzx eax, byte [rel session_unlock_grant]
    cmp  eax, SESSION_GRANT_EXPLICIT
    je   .bind
%if PAOS_PUBLICITY_LAB_PROFILE
    cmp  eax, SESSION_GRANT_FIXTURE
    je   .bind
%endif
    inc  qword [rel session_implicit_unlock_refused]
    mov  edi, SESSION_UNLOCK_IMPLICIT
    xor  esi, esi
    call session_shell_audit_unlock
    jmp  .bad
.bind:
    ; Tokens never repeat: at exhaustion the next bind fails closed.
    cmp  qword [rel session_authority_epoch], -1
    je   .bad
    cmp  byte [rel session_pending_valid], 1
    jne  .bad
    mov  r10, [rel session_pending_pid]
    mov  r11, [rel session_pending_handle]
    mov  rdi, r10
    call principal_credential
    test rax, rax
    jz   .bad
    cmp  rax, r11
    jne  .bad
    call principal_current
    cmp  rax, r10
    jne  .bad
    mov  [rel session_bound_pid], r10
    mov  [rel session_key_handle], r11
    call session_shell_clear_pending
    mov  byte [rel session_locked], SESSION_UNLOCKED
    inc  qword [rel session_authority_epoch]
    mov  rax, [rel session_authority_epoch]
    mov  [rel session_authority], rax
    call session_shell_local_wipe ; synchronous before authority/store/workspace callbacks
    call wifi_profile_cancel
    call wifi_store_wipe
    call session_shell_classify_unlock
    xor  eax, eax
    ret
.already:
    call session_shell_clear_pending
    mov  byte [rel session_unlock_grant], SESSION_GRANT_NONE
    mov  byte [rel session_unlock_local_proof], 0
    xor  eax, eax
    ret
.bad:
    call session_shell_clear_pending
    mov  byte [rel session_unlock_grant], SESSION_GRANT_NONE
    mov  byte [rel session_unlock_local_proof], 0
    mov  eax, -1
    ret

; EAX=1 while a remote request is being served (the ticket-bearing window of
; AUTH1 UDP/serial or SSH exec), except the transport's post-reply
; presentation sync, which only consumes a credential typed at the local lock
; screen. Boot KATs, the main loop and the local CLI run with EAX=0.
session_shell_remote_context:
    xor  eax, eax
    cmp  byte [rel command_auth_remote_active], 1
    jne  .out
    cmp  byte [rel command_session_sync_active], 1
    je   .out
    mov  eax, 1
.out:
    ret

; EDI=SESSION_METHOD_* — arm the one-shot explicit owner-unlock grant. Only an
; explicit-unlock verb handler calls this, after it has verified the request's
; owner authority, immediately before the unlock core consumes the grant.
session_shell_arm_explicit_unlock:
    mov  byte [rel session_unlock_grant], SESSION_GRANT_EXPLICIT
    mov  [rel session_unlock_method], dil
    ret

; A completed locked->unlocked transition: classify it for the audit ring and
; consume the grant and the injected-input taint. A local human unlock writes
; no record; a remote explicit unlock and every test-only unlock do.
session_shell_classify_unlock:
    movzx edx, byte [rel session_unlock_local_proof]
    mov  byte [rel session_unlock_local_proof], 0
    movzx eax, byte [rel session_unlock_grant]
    mov  byte [rel session_unlock_grant], SESSION_GRANT_NONE
    cmp  eax, SESSION_GRANT_EXPLICIT
    je   .explicit
    cmp  eax, SESSION_GRANT_FIXTURE
    je   .fixture
    cmp  byte [rel session_injected_input], 1
    jne  .local
    mov  byte [rel session_injected_input], 0
    inc  qword [rel session_test_only_unlocks]
    mov  edi, SESSION_UNLOCK_TEST_ONLY
    mov  esi, SESSION_METHOD_LOCAL
    jmp  session_shell_audit_unlock
.fixture:
    inc  qword [rel session_test_only_unlocks]
    mov  edi, SESSION_UNLOCK_TEST_ONLY
    mov  esi, SESSION_METHOD_FIXTURE
    jmp  session_shell_audit_unlock
.explicit:
    mov  byte [rel session_injected_input], 0
    inc  qword [rel session_explicit_unlocks]
    mov  edi, SESSION_UNLOCK_EXPLICIT
    movzx esi, byte [rel session_unlock_method]
    jmp  session_shell_audit_unlock
.local:
    ; Peter 87337: SSH reaches sealed data only after this. A password typed by hand at the
    ; lock screen, never autologin, a fixture, or anything remote: the core already refused any
    ; remote frame without a grant. The presentation sync of an SSH or UDP reply may be what
    ; consumes the typed password, so it still counts here.
    cmp  edx, 1
    jne  .done
    mov  byte [rel session_local_unlock_seen], 1
.done:
    ret

; session_shell_audit_unlock(EDI=SESSION_UNLOCK_*, ESI=SESSION_METHOD_*) —
; one bounded audit-ring record (<=71 chars):
;   UNLOCK explicit source=udp|ssh|serial principal=N method=authlogin|pushauth
;   UNLOCK refused source=.. principal=N method=.. reason=cred|ticket|implicit|ssh
;   UNLOCK test_only source=inject|udp|.. principal=N method=local|fixture
; No credential byte is ever formatted. Preserves RBX and R12-R15.
session_shell_audit_unlock:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    call session_shell_observe_unlock
    lea  r13, [rel session_audit_buf]
    lea  rdi, [rel str_sau_unlock]
    call session_audit_put
    lea  rdi, [rel str_sau_explicit]
    cmp  ebx, SESSION_UNLOCK_EXPLICIT
    je   .outcome
    lea  rdi, [rel str_sau_test_only]
    cmp  ebx, SESSION_UNLOCK_TEST_ONLY
    je   .outcome
    lea  rdi, [rel str_sau_refused]
.outcome:
    call session_audit_put
    lea  rdi, [rel str_sau_source]
    call session_audit_put
    ; source: an injected-input unlock names the injection, never a human
    lea  rdi, [rel str_sau_src_inject]
    cmp  r12d, SESSION_METHOD_LOCAL
    je   .source
    lea  rdi, [rel str_sau_src_local]
    cmp  byte [rel command_auth_remote_active], 1
    jne  .source
    lea  rdi, [rel str_sau_src_ssh]
    cmp  byte [rel command_auth_ssh_active], 1
    je   .source
    lea  rdi, [rel str_sau_src_serial]
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_SERIAL
    je   .source
    lea  rdi, [rel str_sau_src_udp]
.source:
    call session_audit_put
    lea  rdi, [rel str_sau_principal]
    call session_audit_put
    ; the in-flight request's own principal when there is one; else the
    ; session's bound principal (the local test-only case)
    mov  rdi, [rel session_bound_pid]
    cmp  byte [rel command_auth_remote_active], 1
    jne  .principal
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .principal
    mov  rdi, [rax + AUTH_T_PRINCIPAL]
.principal:
    mov  rsi, r13
    call fmt_dec
    add  r13, rax
    lea  rdi, [rel str_sau_method]
    call session_audit_put
    lea  rdi, [rel str_sau_m_authlogin]
    cmp  r12d, SESSION_METHOD_AUTHLOGIN
    je   .method
    lea  rdi, [rel str_sau_m_pushauth]
    cmp  r12d, SESSION_METHOD_PUSHAUTH
    je   .method
    lea  rdi, [rel str_sau_m_fixture]
    cmp  r12d, SESSION_METHOD_FIXTURE
    je   .method
    lea  rdi, [rel str_sau_m_local]
    cmp  r12d, SESSION_METHOD_LOCAL
    je   .method
    lea  rdi, [rel str_sau_m_none]
.method:
    call session_audit_put
    lea  rdi, [rel str_sau_r_cred]
    cmp  ebx, SESSION_UNLOCK_CRED
    je   .reason
    lea  rdi, [rel str_sau_r_ticket]
    cmp  ebx, SESSION_UNLOCK_TICKET
    je   .reason
    lea  rdi, [rel str_sau_r_ssh]
    cmp  ebx, SESSION_UNLOCK_SSH
    je   .reason
    lea  rdi, [rel str_sau_r_implicit]
    cmp  ebx, SESSION_UNLOCK_IMPLICIT
    jne  .log
.reason:
    call session_audit_put
.log:
    lea  rdi, [rel session_audit_buf]
    call audit_log_line
    pop  r13
    pop  r12
    pop  rbx
    ret

; Numeric observation of the native outcome, never parsed from its receipt.
; Provenance names input ingress only, never a human or an authenticated caller.
; No ticket/principal/credential is passed to the public/typed observation seam.
session_shell_observe_unlock:
    xor  edx, edx                        ; local/unknown, no human claim
    cmp  byte [rel session_injected_input], 0
    jne  .injected
    cmp  esi, SESSION_METHOD_FIXTURE
    je   .fixture
    cmp  byte [rel command_auth_remote_active], 1
    jne  .publish
    mov  edx, 2                         ; SSH connection context
    cmp  byte [rel command_auth_ssh_active], 1
    je   .publish
    mov  edx, 3                         ; serial transport context
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_SERIAL
    je   .publish
    mov  edx, 1                         ; UDP transport context
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_UDP
    je   .publish
    xor  edx, edx                        ; remote but unknown ingress
    jmp  .publish
.injected:
    mov  edx, 4                         ; injected, never human authentication
    jmp  .publish
.fixture:
    mov  edx, 5                         ; machine fixture, never human
.publish:
    cmp  edi, SESSION_UNLOCK_SSH        ; the typed row: no owner authority to unlock, ingress SSH
    jne  .typed
    mov  edi, SESSION_UNLOCK_TICKET
.typed:
    jmp  audit_sec_session_unlock

; RDI=cstr appended at R13 (bounded by the record buffer).
session_audit_put:
    lea  rax, [rel session_audit_buf + SESSION_AUDIT_MAX - 1]
.copy:
    cmp  r13, rax
    jae  .done
    mov  cl, [rdi]
    test cl, cl
    jz   .done
    mov  [r13], cl
    inc  r13
    inc  rdi
    jmp  .copy
.done:
    mov  byte [r13], 0
    ret

session_shell_lock:
    ; Revoke before the workspace callback can yield or observe pending intent.
    call session_shell_local_wipe ; synchronous before authority/store/workspace callbacks
    call wifi_profile_cancel
    call wifi_store_wipe
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   session_shell_lock_core
    call session_shell_workspace_commit
    call session_shell_lock_core
    ret

; Authority is cleared before this rung ever renders another surface.
session_shell_lock_core:
    ; Direct core callers must revoke too; repeated cancellation is harmless.
    call session_shell_local_wipe ; synchronous before authority/store/workspace callbacks
    call wifi_profile_cancel
    call wifi_store_wipe
    call session_shell_clear_pending
    call principal_clear_bound
    call history_on_lock                ; RC-history: H, the AI ticket and any plaintext record go with the key
    mov  qword [rel session_bound_pid], 0
    mov  qword [rel session_key_handle], 0
    mov  qword [rel session_authority], 0
    mov  qword [rel session_workspace_pid], 0
    mov  byte [rel session_restore_source], SESSION_RESTORE_NONE
    cmp  qword [rel session_authority_epoch], -1
    je   .epoch_done
    inc  qword [rel session_authority_epoch]
.epoch_done:
    mov  byte [rel session_locked], SESSION_LOCKED
    mov  byte [rel session_unlock_grant], SESSION_GRANT_NONE
    mov  byte [rel session_injected_input], 0
    ret

; BSP GUI enqueue/consume snapshot: RAX=local session PID, RDX=authority token,
; or 0/0 on refusal. Never borrow the active execution principal of a remote
; request. Call at enqueue and again before applying a deferred local action;
; both PID and token must match. Lock/rebind changes the existing session epoch.
; No yield/callback between this snapshot and the caller's bounded commit.
; Injected input and every remote frame (including presentation sync) refuse.
session_shell_local_authority:
    cmp  byte [rel command_auth_remote_active], 0
    jne  .bad
    cmp  byte [rel session_injected_input], 0
    jne  .bad
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .bad
    cmp  qword [rel session_key_handle], 0
    je   .bad
    mov  rax, [rel session_bound_pid]
    test rax, rax
    jz   .bad
    mov  rdx, [rel session_authority]
    test rdx, rdx
    jz   .bad
    cmp  rdx, [rel session_authority_epoch]
    jne  .bad
    ret
.bad:
    xor  eax, eax
    xor  edx, edx
    ret

; RDI=authority token -> EAX=0 valid / -1 stale or locked.
session_shell_authority_validate:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .bad
    test rdi, rdi
    jz   .bad
    cmp  rdi, [rel session_authority]
    jne  .bad
    cmp  rdi, [rel session_authority_epoch]
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Shared desktop/session gate for every GUI workspace verb. AUTH1 proves the
; remote caller's transport authority; this separately proves that a credential
; was bound into the current local login session.
; Inside a remote frame (session_shell_remote_context: not the post-reply
; presentation sync) the REQUEST's own authenticated principal must also be the
; bound one (RCQ-27 M1, root 15:58:31). The ambient principal is the local
; session's, so it never speaks for a remote request: a remote owner must not
; act in a SYSTEM-bound dev-autologin desktop, and a SYSTEM/AI request must not
; act in the owner's. Only the six ticket states that carry no authenticated
; principal (UNSIGNED, MALFORMED, WRONG_KEY, EXPIRED, RETIRED, WRONG_NODE), and
; no ticket at all, stay judged by session state alone: command_auth_authorize
; refuses every one of them before any non-public handler runs (public-floor
; handlers never call this gate), and the headless
; lock floor (command_session_name_allowed) asks this gate before authorize, so
; that request keeps authorize's own refusal reason. Every other state (VALID,
; CONSUMED, SSH, INJECTED, and any state added later) must name the bound PID:
; the default compares, it never admits. Nothing is written here; clobbers RAX
; and RDI only.
session_shell_require_unlocked:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .bad
    mov  rdi, [rel session_bound_pid]
    test rdi, rdi
    jz   .bad
    cmp  qword [rel session_key_handle], 0
    je   .bad
    call principal_current
    cmp  rax, rdi
    jne  .bad
    call session_shell_remote_context
    test eax, eax
    jz   .ok
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .ok
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_UNSIGNED
    je   .ok
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_MALFORMED
    je   .ok
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_WRONG_KEY
    je   .ok
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_EXPIRED
    je   .ok
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_RETIRED
    je   .ok
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_WRONG_NODE
    je   .ok
    cmp  [rax + AUTH_T_PRINCIPAL], rdi
    jne  .bad
.ok:
    xor  eax, eax
    ret
.bad:
    ; Desktop-surface refusal: the one registry dispatcher reads this back to
    ; give a remote caller a distinct non-OK code (CMDE_DESKTOP_LOCKED) while the
    ; handler's reply bytes stay exactly as they are.
    mov  byte [rel cmd_desktop_refused], 1
    mov  eax, -1
    ret

;
; session_shell_request_principal(RDI=req, or 0 for the in-flight frame) ->
; RAX = the principal acting in this frame; 0 = none (callers refuse).
; RCQ-16 F2 (rc-sec 9e24b1ef, root 18:14:29). The same source as the M1 gate
; above, never the ambient one: inside a remote frame it is the ticket's own
; AUTH_T_PRINCIPAL (the in-image aihook is a remote frame with a PRIN_SYSTEM
; ticket; an injected console line runs under its injector's INJECTED ticket).
; No ticket, or one of the six states that carry no authenticated principal,
; gives none. Outside a remote frame it is the request's REQ_PRINCIPAL (console
; requests are OWNER-only at the dispatcher; in-image callers name theirs);
; with RDI=0 it is the dispatcher's in-flight principal, and PRIN_OWNER when no
; request is being served at all (a local human action, boot, the demo), except
; a Try-bound desktop returns its actual local Try principal or no authority.
; Clobbers RAX only.
session_shell_request_principal:
    call session_shell_remote_context
    test eax, eax
    jnz  .remote
    test rdi, rdi
    jz   .frame
    mov  rax, [rdi + REQ_PRINCIPAL]
    ret
.frame:
    cmp  byte [rel cmd_in_dispatch], 1
    je   .dispatch
    cmp  qword [rel session_bound_pid], PRIN_TRY
    jne  .owner
    push rdx
    call session_shell_local_authority
    pop  rdx
    ret
.owner:
    mov  eax, PRIN_OWNER
    ret
.dispatch:
    mov  rax, [rel cmd_dispatch_last_principal]
.out:
    ret
.remote:
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .out
    push rcx
    mov  rcx, [rax + AUTH_T_STATE]
    cmp  rcx, AUTH_TS_UNSIGNED
    je   .none
    cmp  rcx, AUTH_TS_MALFORMED
    je   .none
    cmp  rcx, AUTH_TS_WRONG_KEY
    je   .none
    cmp  rcx, AUTH_TS_EXPIRED
    je   .none
    cmp  rcx, AUTH_TS_RETIRED
    je   .none
    cmp  rcx, AUTH_TS_WRONG_NODE
    je   .none
    mov  rax, [rax + AUTH_T_PRINCIPAL]
    pop  rcx
    ret
.none:
    xor  eax, eax
    pop  rcx
    ret

; Console and Terminal keep the established owner projection outside Try.
; In Try they carry only the actual local Try PID (or zero on failed origin),
; with zero request capability. The existing registry gate remains authoritative;
; this helper cannot create an OWNER request from a Try desktop. RDI=req.
session_shell_prepare_local_request:
    mov  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    mov  qword [rdi + REQ_CAP], -1
    cmp  qword [rel session_bound_pid], PRIN_TRY
    jne  .out
    push rdi
    call session_shell_local_authority
    pop  rdi
    mov  [rdi + REQ_PRINCIPAL], rax
    mov  qword [rdi + REQ_CAP], 0
.out:
    ret

; RCQ-29: the registry's admission of a console request naming the local Try
; PID. RDI=verb name, RSI=declared cap, RDX=destructive, RCX=request ->
; EAX=1 admitted, 0 refused. It needs zero request capability, the same
; unlocked, keyed, non-injected local Try login, and either the exact public
; query floor, the desktop element setter (whose handler admits Try only on
; the desktop host and its own slots), or the armed Start launch: exactly the
; request session_shell_try_launch_arm named, once, as FORMLOAD or RAISE by
; exact name. Nothing here projects OWNER or a cap. Clobbers caller-saved
; registers.
session_shell_try_request_admit:
    cmp  qword [rcx + REQ_CAP], 0
    jne  .bad
    push rdi
    push rsi
    push rdx
    call session_shell_local_authority
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  rax, PRIN_TRY
    jne  .bad
    cmp  rcx, [rel session_try_launch_req]   ; RCX kept by the accessor
    je   .launch                        ; the armed Start launch, exactly this request
    push rdi
    call command_auth_required_cap
    pop  rdi
    test rax, rax
    jz   .ok                            ; exact public-query floor
    lea  rsi, [rel str_session_try_setter]
    call strcmp
    test eax, eax
    jnz  .bad
.ok:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret
.launch:
    mov  qword [rel session_try_launch_req], 0   ; one shot, whatever the verb
    push rdi
    lea  rsi, [rel str_session_try_formload]
    call strcmp
    pop  rdi
    test eax, eax
    jz   .ok
    lea  rsi, [rel str_session_try_raise]
    call strcmp
    test eax, eax
    jz   .ok
    jmp  .bad

; RCQ-29: the naming picker's Start/registry activation from the local Try
; desktop. RDI = the exact request it is about to dispatch -> EAX=1 armed,
; 0 refused (the local login is not an unlocked, keyed, non-injected,
; non-remote Try login; this call arms nothing). The picker disarms on every
; exit, whatever the dispatch did. Keeps every register but RAX/RDX.
session_shell_try_launch_arm:
    push rdi
    call session_shell_local_authority
    pop  rdi
    cmp  rax, PRIN_TRY
    jne  .bad
    mov  [rel session_try_launch_req], rdi
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

session_shell_try_launch_disarm:
    mov  qword [rel session_try_launch_req], 0
    ret

; Native GUI registers its call-free secret eraser downward before opening a
; draft. No command/serial/PCFG route registers pointers. Absent GUI is safe:
; there can be no GUI draft before registration. The hook preserves the GUI
; outer busy guard, and must not call profile/store/transport/workspace APIs.
; RDI=runtime LEA of the synchronous local editor/private-range eraser.
session_shell_register_local_wipe:
    mov [rel session_local_wipe_op], rdi
    ret

session_shell_local_wipe:
    mov rax, [rel session_local_wipe_op]
    test rax, rax
    jz .done
    jmp rax
.done:
    ret

; GUI/session_restore registers its document operations downward. Static dq
; symbol pointers are forbidden in this image, so boot passes runtime LEAs.
; RDI=commit, RSI=restore, RDX=discard, RCX=kat, R8=lab probe,
; R9=locked-boot document observer.
session_shell_register_workspace_ops:
    mov  [rel session_workspace_commit_op], rdi
    mov  [rel session_workspace_restore_op], rsi
    mov  [rel session_workspace_discard_op], rdx
    mov  [rel session_workspace_kat_op], rcx
    mov  [rel session_workspace_probe_op], r8
    mov  [rel session_workspace_locked_observe_op], r9
    ret

session_shell_workspace_commit:
    cmp  qword [rel session_bound_pid], PRIN_TRY
    je   .bad
    mov  rax, [rel session_workspace_commit_op]
    test rax, rax
    jz   .bad
    call rax
    ret
.bad:
    mov  eax, -1
    ret

session_shell_discard_checkpoint:
    mov  rax, [rel session_workspace_discard_op]
    test rax, rax
    jz   .done
    call rax
.done:
    ret

session_shell_restore_workspace:
    cmp  qword [rel session_bound_pid], PRIN_TRY
    je   .clear
    mov  rax, [rel session_workspace_restore_op]
    test rax, rax
    jz   .done
    call rax
    cmp  eax, SESSION_RESTORE_RAM
    je   .record
    cmp  eax, SESSION_RESTORE_DOC
    jne  .clear
.record:
    mov  [rel session_restore_source], al
    mov  [rel session_workspace_pid], rdx
    ret
.clear:
    mov  byte [rel session_restore_source], SESSION_RESTORE_NONE
    mov  qword [rel session_workspace_pid], 0
.done:
    ret

session_shell_observe_locked_workspace:
    mov  rax, [rel session_workspace_locked_observe_op]
    test rax, rax
    jz   .done
    call rax
.done:
    ret

; SLEEP M1 reservation only; no sleep persistence mechanics live in this rung.
session_sleep_m1_offer:
    mov  byte [rel session_sleep_offer], 1
    ret

; RDI=1 is a future trustworthy checkpoint; every other value discards.
session_sleep_m1_apply:
    cmp  byte [rel session_sleep_offer], 1
    jne  .discard
    cmp  rdi, 1
    jne  .discard
    mov  byte [rel session_sleep_offer], 0
    mov  byte [rel session_last_doubt_discard], 0
    xor  eax, eax
    ret
.discard:
    mov  byte [rel session_sleep_offer], 0
    call session_shell_discard_checkpoint
    mov  byte [rel session_last_doubt_discard], 1
    mov  eax, -1
    ret

; Test/dev binding uses Task2501's machine-held credential without copying or
; projecting its bytes.
session_shell_bind_system_fixture:
    call principal_system_auth_credential
    test rax, rax
    jz   .bad
    mov  [rel session_kat_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  [rel session_kat_auth_ctx + AUTH_CTX_CRED_LEN], rdx
    mov  edi, AUTH_BIND_SYSTEM_KEY
    lea  rsi, [rel session_kat_auth_ctx]
    call authenticate_bind
    test rax, rax
    jz   .bad
    mov  rdi, rax
    mov  rsi, rdx
    call session_shell_offer_bind
    test eax, eax
    jnz  .bad
    ; Boot/dev-autologin binds run outside any remote request. A lab
    ; SESSIONPROBE reaches this remotely: its machine-fixture bind is a
    ; test-only unlock (compiled out of the shipped floor's unlock core).
    call session_shell_remote_context
    test eax, eax
    jz   .unlock
    mov  byte [rel session_unlock_grant], SESSION_GRANT_FIXTURE
.unlock:
    call session_shell_unlock
    ret
.bad:
    call session_shell_lock_core
    mov  eax, -1
    ret

; Real-transition KAT. It writes no disk and never exposes a credential.
session_shell_selftest:
    push r12
    mov  byte [rel session_workspace_kat_ok], 0
    mov  byte [rel session_sleep_kat_ok], 0
    call session_shell_lock_core
    ; Bind and consume through the same core gate while keeping boot-time
    ; disk/UI mutation outside the KAT.
    call principal_system_auth_credential
    test rax, rax
    jz   .fail
    mov  [rel session_kat_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  [rel session_kat_auth_ctx + AUTH_CTX_CRED_LEN], rdx
    mov  edi, AUTH_BIND_SYSTEM_KEY
    lea  rsi, [rel session_kat_auth_ctx]
    call authenticate_bind
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  rsi, rdx
    call session_shell_offer_bind
    test eax, eax
    jnz  .fail
    call session_shell_unlock_core
    test eax, eax
    jnz  .fail
    mov  r12, [rel session_authority]
    call session_shell_lock_core
    call principal_current
    test rax, rax
    jnz  .fail
    mov  edi, PRIN_SYSTEM
    call principal_credential
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call session_shell_authority_validate
    test eax, eax
    jz   .fail

    mov  rax, [rel session_workspace_kat_op]
    test rax, rax
    jz   .fail
    call rax
    test eax, eax
    jnz  .fail
    mov  byte [rel session_workspace_kat_ok], 1
    call session_sleep_m1_offer
    xor  edi, edi
    call session_sleep_m1_apply
    cmp  eax, -1
    jne  .fail
    cmp  byte [rel session_last_doubt_discard], 1
    jne  .fail
    mov  byte [rel session_sleep_kat_ok], 1
    lea  rdi, [rel str_session_gate_marker]
    call serial_string
    mov  byte [rel session_gate_kat_ok], 1
    xor  eax, eax
    pop  r12
    ret
.fail:
    call session_shell_lock_core
    mov  byte [rel session_gate_kat_ok], 0
    mov  byte [rel session_workspace_kat_ok], 0
    mov  byte [rel session_sleep_kat_ok], 0
    mov  eax, -1
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Registry verbs
; ---------------------------------------------------------------------------
session_shell_declare:
    lea  rdi, [rel str_verb_sessioninfo]
    lea  rsi, [rel cmd_verb_sessioninfo]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_sessionlock]
    lea  rsi, [rel cmd_verb_sessionlock]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    lea  rdi, [rel str_verb_sessionunlock]
    lea  rsi, [rel cmd_verb_sessionunlock]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    lea  rdi, [rel str_verb_idlelock]
    lea  rsi, [rel cmd_verb_idlelock]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; owner setting: a mutation
    call command_register_verb
%if !PAOS_PUBLIC_BUILD
    lea  rdi, [rel str_verb_labarm]
    lea  rsi, [rel cmd_verb_labarm]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
%endif
%if PAOS_PUBLICITY_LAB_PROFILE
    lea  rdi, [rel str_verb_sessionprobe]
    lea  rsi, [rel cmd_verb_sessionprobe]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; truthful: diagnostic drives mutations
    call command_register_verb
%endif
    ret

cmd_verb_sessioninfo:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    mov  rdi, [rdi + REQ_ARG]
    call session_nonce_valid
    test eax, eax
    jnz  .bad
    mov  [rel session_reply_nonce], rdi
    call session_out_reset
    lea  rdi, [rel str_session_locked]
    call session_out_str
    movzx edi, byte [rel session_locked]
    call session_out_dec
    lea  rdi, [rel str_session_principal]
    call session_out_str
    mov  rdi, [rel session_bound_pid]
    test rdi, rdi
    jz   .none
    call session_out_dec
    jmp  .rest
.none:
    lea  rdi, [rel str_session_none]
    call session_out_str
.rest:
    lea  rdi, [rel str_session_key]
    call session_out_str
    cmp  qword [rel session_key_handle], 0
    je   .key_none
    lea  rdi, [rel str_session_bound]
    jmp  .key_stage
.key_none:
    lea  rdi, [rel str_session_none]
.key_stage:
    call session_out_str
    lea  rdi, [rel str_session_restore]
    call session_out_str
    lea  rdi, [rel str_session_restore_source]
    call session_out_str
    movzx eax, byte [rel session_restore_source]
    cmp  eax, SESSION_RESTORE_RAM
    je   .restore_ram
    cmp  eax, SESSION_RESTORE_DOC
    je   .restore_doc
    lea  rdi, [rel str_session_none]
    jmp  .restore_stage
.restore_ram:
    lea  rdi, [rel str_session_ram]
    jmp  .restore_stage
.restore_doc:
    lea  rdi, [rel str_session_document]
.restore_stage:
    call session_out_str
    lea  rdi, [rel str_session_workspace_principal]
    call session_out_str
    mov  rdi, [rel session_workspace_pid]
    test rdi, rdi
    jz   .workspace_none
    call session_out_dec
    jmp  .workspace_stage
.workspace_none:
    lea  rdi, [rel str_session_none]
    call session_out_str
.workspace_stage:
    lea  rdi, [rel str_session_kat]
    call session_out_str
    cmp  byte [rel session_gate_kat_ok], 1
    jne  .kat_bad
    cmp  byte [rel session_workspace_kat_ok], 1
    jne  .kat_bad
    cmp  byte [rel session_sleep_kat_ok], 1
    jne  .kat_bad
    lea  rdi, [rel str_session_pass]
    jmp  .kat_stage
.kat_bad:
    lea  rdi, [rel str_session_fail]
.kat_stage:
    call session_out_str
    lea  rdi, [rel str_session_boot]
    call session_out_str
    cmp  byte [rel session_boot_policy], 2
    je   .try
    cmp  byte [rel session_boot_policy], 1
    je   .dev
    lea  rdi, [rel str_session_policy_off]
    jmp  .policy
.dev:
    lea  rdi, [rel str_session_policy_dev]
    jmp  .policy
.try:
    lea  rdi, [rel str_session_policy_try]
.policy:
    call session_out_str
    lea  rdi, [rel str_session_nonce]
    call session_out_str
    mov  rdi, [rel session_reply_nonce]
    call session_out_str
    jmp  .stage
.bad:
    call session_out_reset
    lea  rdi, [rel str_session_bad_nonce]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.stage:
    mov  byte [rel session_out_ready], 1
    pop  r13
    ret

; LABARM (root 89556): the lab stand-in for a hand-typed unlock, for machines with
; no real keyboard to reach. Signed AUTH1 owner only (never SSH), on an already
; unlocked session, compiled out of public builds and refused by release_profile.cut
; in a release. Evidence calls this lab-armed, never hand-typed.
cmd_verb_labarm:
%if !PAOS_PUBLIC_BUILD
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call session_out_reset
    call command_auth_owner_request
    cmp  eax, 1
    jne  .refuse
    cmp  byte [rel session_locked], 0
    jne  .refuse
    mov  byte [rel session_local_unlock_seen], 1
    lea  rdi, [rel str_labarm_ok]
    call audit_log_line
    lea  rdi, [rel str_labarm_ok]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.refuse:
    lea  rdi, [rel str_labarm_refused]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
.ready:
    mov  byte [rel session_out_ready], 1
    pop  r13
%endif
    ret

cmd_verb_sessionlock:
    call cmd_handler_prologue
    push rbx
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    call session_shell_lock
    mov  rdi, rbx
    lea  rsi, [rel str_session_discard_arg]
    call strcmp
    test eax, eax
    jnz  .ordinary
    call session_sleep_m1_offer
    xor  edi, edi                       ; doubt can never apply a RAM checkpoint
    call session_sleep_m1_apply
    call session_out_reset
    lea  rdi, [rel str_session_lock_discard_ok]
    call session_out_str
    jmp  .ready
.ordinary:
    call session_out_reset
    lea  rdi, [rel str_session_lock_ok]
    call session_out_str
.ready:
    mov  byte [rel session_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  rbx
    ret

cmd_verb_sessionunlock:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call session_shell_unlock
    push rax
    call session_out_reset
    pop  rax
    test eax, eax
    jnz  .bad
    lea  rdi, [rel str_session_unlock_ok]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .stage
.bad:
    lea  rdi, [rel str_session_unlock_bad]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.stage:
    mov  byte [rel session_out_ready], 1
    pop  r13
    ret

%if PAOS_PUBLICITY_LAB_PROFILE
cmd_verb_sessionprobe:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    call session_find_nonce
    test rax, rax
    jz   .bad_no_nonce
    mov  r12, rax
    mov  rdi, r12
    call session_nonce_valid
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    lea  rsi, [rel str_probe_clear]
    call session_prefix
    test eax, eax
    jnz  .workspace
    call session_probe_clear
    jmp  .stage
.workspace:
    mov  rdi, rbx
    lea  rsi, [rel str_probe_workspace]
    call session_prefix
    test eax, eax
    jnz  .sleep
    mov  rdi, r12
    call session_probe_workspace
    jmp  .stage
.sleep:
    mov  rdi, rbx
    lea  rsi, [rel str_probe_sleep]
    call session_prefix
    test eax, eax
    jnz  .bad
    call session_probe_sleep
    jmp  .stage
.bad_no_nonce:
    xor  r12d, r12d
.bad:
    call session_out_reset
    lea  rdi, [rel str_probe_bad]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.stage:
    test r12, r12
    jz   .ready
    lea  rdi, [rel str_session_nonce]
    call session_out_str
    mov  rdi, r12
    call session_out_str
.ready:
    mov  byte [rel session_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

session_probe_clear:
    push r12
    call session_shell_bind_system_fixture
    test eax, eax
    jnz  .bad
    mov  r12, [rel session_authority]
    call session_shell_lock
    mov  rdi, r12
    call session_shell_authority_validate
    test eax, eax
    jz   .bad
    call principal_current
    test rax, rax
    jnz  .bad
    mov  edi, PRIN_SYSTEM
    call principal_credential
    test rax, rax
    jnz  .bad
    call session_out_reset
    lea  rdi, [rel str_probe_clear_ok]
    call session_out_str
    xor  eax, eax
    pop  r12
    ret
.bad:
    call session_shell_lock_core
    call session_out_reset
    lea  rdi, [rel str_probe_clear_bad]
    call session_out_str
    mov  eax, -1
    pop  r12
    ret

; RDI=nonce. The GUI callback owns every window/document byte; this layer owns
; the bind and guarantees principal clearing on every exit.
session_probe_workspace:
    push r12
    mov  r12, rdi
    call session_shell_bind_system_fixture
    test eax, eax
    jnz  .bad
    mov  rax, [rel session_workspace_probe_op]
    test rax, rax
    jz   .bad
    mov  rdi, r12
    call rax
    test eax, eax
    jnz  .bad
    call principal_current
    cmp  rax, [rel session_bound_pid]
    jne  .bad
    call session_shell_lock_core
    call session_out_reset
    lea  rdi, [rel str_probe_workspace_ok]
    call session_out_str
    xor  eax, eax
    jmp  .out
.bad:
    call session_shell_lock_core
    call session_out_reset
    lea  rdi, [rel str_probe_workspace_bad]
    call session_out_str
    mov  eax, -1
.out:
    pop  r12
    ret

session_probe_sleep:
    call session_sleep_m1_offer
    xor  edi, edi
    call session_sleep_m1_apply
    cmp  eax, -1
    jne  .bad
    call session_out_reset
    lea  rdi, [rel str_probe_sleep_ok]
    call session_out_str
    xor  eax, eax
    ret
.bad:
    call session_out_reset
    lea  rdi, [rel str_probe_sleep_bad]
    call session_out_str
    mov  eax, -1
    ret
%endif

; ---------------------------------------------------------------------------
; Bounded text helpers
; ---------------------------------------------------------------------------
session_nonce_valid:
    mov  r10, rdi
    xor  ecx, ecx
.loop:
    movzx eax, byte [r10 + rcx]
    test al, al
    jz   .end
    cmp  al, 0x21
    jb   .bad
    cmp  al, 0x7e
    ja   .bad
    inc  ecx
    cmp  ecx, SESSION_NONCE_MAX
    jbe  .loop
.bad:
    mov  eax, -1
    ret
.end:
    test ecx, ecx
    jz   .bad
    xor  eax, eax
    mov  rdi, r10
    ret

session_find_nonce:
.scan:
    cmp  byte [rdi], 0
    je   .miss
    cmp  dword [rdi], 'nonc'
    jne  .next
    cmp  word [rdi + 4], 'e='
    je   .hit
.next:
    inc  rdi
    jmp  .scan
.hit:
    lea  rax, [rdi + 6]
    ret
.miss:
    xor  eax, eax
    ret

; RDI=text, RSI=prefix -> EAX=0 match / -1 no match.
session_prefix:
.loop:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    inc  rsi
    jmp  .loop
.yes:
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

session_out_reset:
    lea  rax, [rel session_out_buf]
    mov  [rel session_out_cur], rax
    mov  byte [rax], 0
    ret

session_out_str:
    mov  rsi, [rel session_out_cur]
    lea  r10, [rel session_out_buf + SESSION_OUT_SIZE - 1]
.copy:
    cmp  rsi, r10
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel session_out_cur], rsi
    ret

session_out_dec:
    mov  rsi, [rel session_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel session_out_cur], rsi
    ret

; ---------------------------------------------------------------------------
; RC-lock-screen idle lock (spec v0.49 21.2.2 item 1; root 2026-10-17
; 15:28:25 / 15:32:45). An unlocked OWNER session locks after
; session_idle_secs without human input: default 600, 0 = off, the owner sets
; off or 60..86400 with IDLELOCK. Presence is dev/input/ps2's
; ps2_human_input_events (physical key presses/releases, never a typematic
; repeat, and the native pointer ring), so injected keys and pointers (KBINJ,
; TERMFEED, HOOK, MOUSEINJ, PTRINJ), an AI, a remote session or a retiring
; device never hold a session open. Try (nothing to lock away) and a lab
; autologin SYSTEM session never idle-lock. Any tick that is not an unlocked
; owner session restarts the clock, so an unlock never locks at once. A clock
; behind the stamp restarts it; with no monotonic clock (tsc_khz 0, now 0)
; nothing ever expires. The lock is the ordinary session_shell_lock, then one
; audit line and a serial marker. The value is saved by sec/idle_prefs
; (saved=nvram), or applies this boot only when the store is absent (saved=boot)
; or failed (saved=failed).
; ---------------------------------------------------------------------------
SESSION_IDLE_DEFAULT equ 600
SESSION_IDLE_MIN     equ 60
SESSION_IDLE_MAX     equ 86400

; session_idle_expired(RDI=now_us >= RSI=last_us, EDX=secs) -> EAX 1 lock due.
; Pure. Off (0) never expires; the tick restarts a clock behind the stamp.
session_idle_expired:
    xor  eax, eax
    test edx, edx
    jz   .out
    sub  rdi, rsi
    mov  ecx, edx
    imul rcx, rcx, 1000000
    cmp  rdi, rcx
    setae al
.out:
    ret

; Main loop (boot/header), depth 0 after the input drains.
session_idle_tick:
    call time_monotonic_now_us          ; RAX = now, 0 = no clock
    mov  rcx, [rel ps2_human_input_events]
    cmp  rcx, [rel session_idle_seen]
    jne  .restart                       ; a hand was here
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .restart                       ; locked: the clock starts again at unlock
    cmp  qword [rel session_bound_pid], PRIN_OWNER
    jne  .restart                       ; Try / lab autologin: no owner idle lock
    cmp  rax, [rel session_idle_last_us]
    jb   .restart                       ; clock behind the stamp: start again
    mov  rdi, rax
    mov  rsi, [rel session_idle_last_us]
    mov  edx, [rel session_idle_secs]
    call session_idle_expired
    test eax, eax
    jz   .out
    call session_shell_lock             ; lock_screen_sync paints the sign-in surface
    inc  qword [rel session_idle_locks]
    call session_idle_audit
    lea  rdi, [rel str_session_idle_locked]
    jmp  serial_string                  ; the next tick sees locked and restarts
.restart:
    mov  [rel session_idle_seen], rcx
    mov  [rel session_idle_last_us], rax
.out:
    ret

; Restart the idle clock from now and the current presence count.
session_idle_restart:
    call time_monotonic_now_us
    mov  [rel session_idle_last_us], rax
    mov  rax, [rel ps2_human_input_events]
    mov  [rel session_idle_seen], rax
    ret

; One local receipt: "LOCK idle secs=<n> principal=owner".
session_idle_audit:
    push r13
    lea  r13, [rel session_audit_buf]
    lea  rdi, [rel str_sau_idle_lock]
    call session_audit_put
    mov  edi, [rel session_idle_secs]
    mov  rsi, r13
    call fmt_dec
    add  r13, rax
    lea  rdi, [rel str_sau_idle_owner]
    call session_audit_put
    lea  rdi, [rel session_audit_buf]
    call audit_log_line
    pop  r13
    ret

; RDI=argument -> EAX seconds (off = 0, else 60..86400 in at most six
; digits), or -1 for anything else.
session_idle_parse:
    push rdi
    lea  rsi, [rel str_idle_off]
    call strcmp
    pop  rdi
    test eax, eax
    jz   .off
    xor  eax, eax
    xor  ecx, ecx
.digit:
    movzx edx, byte [rdi]
    test edx, edx
    jz   .end
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    inc  ecx
    cmp  ecx, 6
    ja   .bad
    imul eax, eax, 10
    add  eax, edx
    inc  rdi
    jmp  .digit
.end:
    test ecx, ecx
    jz   .bad
    cmp  eax, SESSION_IDLE_MIN
    jb   .bad
    cmp  eax, SESSION_IDLE_MAX
    ja   .bad
    ret
.off:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; IDLELOCK [off|<seconds>]. Report and set are owner-only: an unlocked local
; OWNER console session (session_shell_local_authority: no injected input, no
; remote frame), or this request's own owner AUTH1 ticket / unrestricted owner
; SSH key (command_auth_owner_request). An AI (SYSTEM ticket, AIHOOK), Try,
; an unsigned caller or a restricted key is refused with nothing read or
; changed. A set restarts the idle clock.
cmd_verb_idlelock:
    call cmd_handler_prologue
    push rbx
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .deny
    jmp  .owner
.remote:
    call command_auth_owner_request     ; 1 own AUTH1 owner ticket, 2 owner SSH key
    test eax, eax
    jz   .deny
.owner:
    test rbx, rbx
    jz   .report
.ws:
    cmp  byte [rbx], ' '
    jne  .kind
    inc  rbx
    jmp  .ws
.kind:
    cmp  byte [rbx], 0
    je   .report
    mov  rdi, rbx
    call session_idle_parse
    cmp  eax, -1
    je   .bad
    mov  [rel session_idle_secs], eax
    call session_idle_restart
    call idle_prefs_save                ; saved for the next boot (sec/idle_prefs), or this boot only
.report:
    call session_out_reset
    lea  rdi, [rel str_idle_secs]
    call session_out_str
    mov  edi, [rel session_idle_secs]
    call session_out_dec
    lea  rdi, [rel str_idle_on]
    cmp  dword [rel session_idle_secs], 0
    jne  .state
    lea  rdi, [rel str_idle_state_off]
.state:
    call session_out_str
    lea  rdi, [rel str_idle_locks]
    call session_out_str
    mov  rdi, [rel session_idle_locks]
    call session_out_dec
    call idle_prefs_status              ; 0 saved, 1 this boot only, 2 the store failed
    lea  rdi, [rel str_idle_saved]
    test eax, eax
    jz   .saved
    lea  rdi, [rel str_idle_saved_boot]
    cmp  eax, 1
    je   .saved
    lea  rdi, [rel str_idle_saved_failed]
.saved:
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.deny:
    call session_out_reset
    lea  rdi, [rel str_idle_owner_only]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    jmp  .ready
.bad:
    call session_out_reset
    lea  rdi, [rel str_idle_bad]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.ready:
    mov  byte [rel session_out_ready], 1
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; State and strings
; ---------------------------------------------------------------------------
align 8
session_bound_pid:             dq 0
session_key_handle:            dq 0
session_pending_pid:           dq 0
session_pending_handle:        dq 0
session_authority:             dq 0
session_authority_epoch:       dq 1
session_workspace_pid:         dq 0
session_reply_nonce:           dq 0
session_out_cur:               dq 0
session_local_wipe_op:         dq 0
session_workspace_commit_op:   dq 0
session_workspace_restore_op:  dq 0
session_workspace_discard_op:  dq 0
session_workspace_kat_op:      dq 0
session_workspace_probe_op:    dq 0
session_workspace_locked_observe_op: dq 0
session_kat_auth_ctx:          times AUTH_CTX_SIZE db 0
session_locked:                db SESSION_LOCKED
session_pending_valid:         db 0
session_boot_policy:           db 0
session_sleep_offer:           db 0
session_gate_kat_ok:           db 0
session_workspace_kat_ok:      db 0
session_sleep_kat_ok:          db 0
session_last_doubt_discard:    db 0
session_restore_source:        db SESSION_RESTORE_NONE
session_out_ready:             db 0
session_unlock_grant:          db SESSION_GRANT_NONE   ; one-shot, consumed by the unlock core
session_unlock_method:         db SESSION_METHOD_NONE
session_unlock_local_proof:    db 0    ; one-shot from lock_screen_submit, consumed by the unlock core
session_local_unlock_seen:     db 0    ; RAM, this boot: never set by remote, injected or fixture input
session_injected_input:        db 0    ; lab: remote KBINJ/MOUSEINJ/PTRINJ reached the lock screen
align 8
session_explicit_unlocks:      dq 0
session_implicit_unlock_refused: dq 0
session_test_only_unlocks:     dq 0
session_idle_last_us:          dq 0
session_idle_seen:             dq 0
session_idle_locks:            dq 0
session_idle_secs:             dd SESSION_IDLE_DEFAULT
align 8
session_out_buf:               times SESSION_OUT_SIZE db 0
SESSION_AUDIT_MAX equ 72
session_audit_buf:             times SESSION_AUDIT_MAX + 8 db 0
align 8
session_try_launch_req:        dq 0    ; RCQ-29 one-shot armed Try Start launch request (0 = none)
str_sau_unlock:      db "UNLOCK ",0
str_sau_explicit:    db "explicit",0
str_sau_refused:     db "refused",0
str_sau_test_only:   db "test_only",0
str_sau_source:      db " source=",0
str_sau_src_udp:     db "udp",0
str_sau_src_ssh:     db "ssh",0
str_sau_src_serial:  db "serial",0
str_sau_src_local:   db "local",0
str_sau_src_inject:  db "inject",0
str_sau_principal:   db " principal=",0
str_sau_method:      db " method=",0
str_sau_m_authlogin: db "authlogin",0
str_sau_m_pushauth:  db "pushauth",0
str_sau_m_fixture:   db "fixture",0
str_sau_m_local:     db "local",0
str_sau_m_none:      db "none",0
str_sau_r_cred:      db " reason=cred",0
str_sau_r_ticket:    db " reason=ticket",0
str_sau_r_implicit:  db " reason=implicit",0
str_sau_r_ssh:       db " reason=ssh",0

str_verb_sessioninfo:    db "SESSIONINFO",0
str_verb_sessionlock:    db "SESSIONLOCK",0
%if !PAOS_PUBLIC_BUILD
str_verb_labarm:         db "LABARM",0
str_labarm_ok:           db "LABARM latch=lab_armed",0
str_labarm_refused:      db "LABARM REFUSED",0
%endif
str_verb_sessionunlock:  db "SESSIONUNLOCK",0
str_verb_sessionprobe:   db "SESSIONPROBE",0
str_session_locked:      db "locked=",0
str_session_try_setter:  db "WIDGETSET",0
str_session_try_formload: db "FORMLOAD",0
str_session_try_raise:   db "RAISE",0
str_session_principal:   db " principal=",0
str_session_key:         db " key_handle=",0
str_session_bound:       db "bound",0
str_session_none:        db "none",0
str_session_restore:     db " restore_class=always,fresh,never",0
str_session_restore_source: db " restore_source=",0
str_session_ram:         db "ram",0
str_session_document:    db "document",0
str_session_workspace_principal: db " workspace_principal=",0
str_session_kat:         db " gate_kat=",0
str_session_pass:        db "pass",0
str_session_fail:        db "fail",0
str_session_boot:        db " boot_policy=",0
str_session_policy_try:  db "volatile-local-try",0
str_session_policy_off:  db "default-off",0
str_session_policy_dev:  db "explicit-dev-autologin",0
str_session_nonce:       db " nonce=",0
str_session_bad_nonce:   db "SESSIONINFO REFUSED bad_nonce",0
str_session_lock_ok:     db "SESSIONLOCK locked=1 principal=none",0
str_verb_idlelock:       db "IDLELOCK",0
str_idle_off:            db "off",0
str_idle_secs:           db "IDLELOCK secs=",0
str_idle_on:             db " state=on",0
str_idle_state_off:      db " state=off",0
str_idle_locks:          db " locks=",0
str_idle_saved:          db " saved=nvram",0
str_idle_saved_boot:     db " saved=boot",0
str_idle_saved_failed:   db " saved=failed",0
str_idle_owner_only:     db "IDLELOCK REFUSED owner_only",0
str_idle_bad:            db "IDLELOCK REFUSED bad_value range=60..86400|off",0
str_sau_idle_lock:       db "LOCK idle secs=",0
str_sau_idle_owner:      db " principal=owner",0
str_session_idle_locked: db "[PAOS64] session: idle timeout - session locked [session.idle.locked]",13,10,0
str_session_lock_discard_ok: db "SESSIONLOCK locked=1 principal=none checkpoint=discarded",0
str_session_discard_arg: db "discard-on-doubt",0
str_session_unlock_ok:   db "SESSIONUNLOCK unlocked=1",0
str_session_unlock_bad:  db "SESSIONUNLOCK REFUSED bind_required",0
str_probe_clear:         db "clear-bound-principal ",0
str_probe_workspace:     db "workspace-document ",0
str_probe_sleep:         db "sleep-hook ",0
str_probe_bad:           db "SESSIONPROBE REFUSED bad_request",0
str_probe_clear_ok:      db "SESSIONPROBE principal_after=none key_handle_after=none stale_authority=refused",0
str_probe_clear_bad:     db "SESSIONPROBE principal_after=ERROR stale_authority=ERROR",0
str_probe_workspace_ok:  db "SESSIONPROBE doc_roundtrip=ok identity_roundtrip=ok restore_class=fresh",0
str_probe_workspace_bad: db "SESSIONPROBE doc_roundtrip=refused restore_class=none",0
str_probe_sleep_ok:      db "SESSIONPROBE offer=reserved discard_on_doubt=1",0
str_probe_sleep_bad:     db "SESSIONPROBE offer=ERROR discard_on_doubt=0",0
str_session_gate_marker:
    db "[PAOS64] session shell: bound login gate, lock clear and workspace restore KAT PASS [login.session.gate]",13,10,0
