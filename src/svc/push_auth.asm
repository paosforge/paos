;; MODULE svc/push_auth
;; LAYER 5
;; EXPORTS push_auth_init, push_auth_tick, push_auth_password_gate, push_auth_take, push_auth_cancel, push_auth_name_allowed, push_auth_stage_owner, push_auth_wipe_stage
;; IMPORTS core/lib/sha256, core/lib/fmt, core/lib/str, core/lib/mem, core/csprng, core/time, config/keep_config, data/config_store, net/notify_http, net/tls13, sec/principal, sec/session, svc/command, svc/command_auth, svc/command_audit, boot/serial
;; CAPS
;; OWNER saga:login_surfaces
; Task2504. One serialized, hashed, expiring challenge; no credential verifier.
; Endpoint and existing Task2501 data-key handle use the protected config record.
; Every wire mutation still traverses the signed owner AUTH1 authority boundary.
AUTH_BIND_PUSH equ 0x2504
PU_TTL_MS equ 60000
PU_2FA equ 1
PU_RESET equ 2
PU_PASSWORDLESS equ 3
PU_SENDING equ 1
PU_PENDING equ 2
; Public diagnostic terminal causes. They reveal only state-machine control
; flow, never endpoint material, codes, hashes, credentials or policy bytes.
PU_TERM_NONE equ 0
PU_TERM_EPOCH equ 1
PU_TERM_EXPIRED equ 2
PU_TERM_TRANSPORT equ 3
PU_TERM_CONSUMED equ 4
PU_TERM_ATTEMPTS equ 5

; One registry declaration, following WALLPAPER's public-query / gated-action
; shape. The previous metal run reached PUSHSTAT but not the four later
; unchecked registrations. Use one slot and measure its allocation/lookup;
; do not infer registration from the local challenge KAT or evict other verbs.
push_auth_init:
    cmp byte [rel pu_live], 1
    je .initialized
    mov byte [rel pu_live], 1
    call command_verb_count
    mov [rel pu_registry_before], eax
    lea rdi, [rel pu_verb]
    lea rsi, [rel cmd_push_auth]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    call command_register_verb
    cmp eax, -1
    je .registration_failed
    mov [rel pu_registry_slot], eax
    call command_verb_count
    mov [rel pu_registry_after], eax
    sub eax, [rel pu_registry_before]
    cmp eax, 1
    jne .registration_failed
    lea rdi, [rel pu_verb]
    call command_lookup
    cmp eax, [rel pu_registry_slot]
    jne .registration_failed
    mov byte [rel pu_registry_ok], 1
    call push_auth_selftest
    call keep_push_load
.initialized:
    ret
.registration_failed:
    lea rdi, [rel pu_registration_fail]
    call serial_string
    ret

; Availability while locked does not confer mutation authority.
push_auth_name_allowed:
    push rbx
    lea rsi, [rel pu_verb]
    call strcmp
    test eax, eax
    sete al
    movzx eax, al
    pop rbx
    ret

; RDI=argument string -> EAX=operation (1 status, 2 policy, 3 begin,
; 4 approve, 5 reset), RDX=operand pointer. Exact first tokens only.
; The returned pointer never extends past the terminating NUL.
pu_operation:
    lea rsi, [rel pu_operations]
    mov eax, 1
.next:
    mov r8, rdi
    mov r9, rsi
.compare:
    mov cl, [r9]
    test cl, cl
    jz .boundary
    cmp cl, [r8]
    jne .skip
    inc r8
    inc r9
    jmp .compare
.boundary:
    cmp byte [r8], 0
    je .found
    cmp byte [r8], ' '
    jne .skip
    inc r8
.found:
    mov rdx, r8
    ret
.skip:
    cmp byte [rsi], 0
    lea rsi, [rsi + 1]
    jne .skip
    inc eax
    cmp eax, 5
    jbe .next
    xor eax, eax
    xor edx, edx
    ret

; PUSHAUTH status [nonce] is the only public operation. Every other token,
; including malformed/unknown operations, earns the ordinary owner AUTH1
; capability before parsing secrets or changing policy/challenge state.
cmd_push_auth:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, [rbx + REQ_ARG]
    mov rdi, r13
    test rdi, rdi
    jz .authorize
    call pu_operation
    cmp eax, 1
    je .status
.authorize:
    mov rdi, CMD_AUTH_CAP_MUTATE
    lea rsi, [rel pu_verb]
    call command_auth_gate
    test eax, eax
    jnz .auth_refused
    ; Reread the request-owned argument after the durable authorization call.
    mov rdi, r13
    test rdi, rdi
    jz .bad
    call pu_operation
    mov r14d, eax
    mov [rbx + REQ_ARG], rdx
    mov rdi, rbx
    mov rsi, r12
    cmp r14d, 2
    je .policy
    cmp r14d, 3
    je .begin
    cmp r14d, 4
    je .approve
    cmp r14d, 5
    je .reset
.bad:
    lea rdi, [rel pu_denied]
    call pu_reply
    jmp .scrub
.policy:
    call cmd_push_policy
    jmp .scrub
.begin:
    call cmd_push_begin
    jmp .scrub
.approve:
    call cmd_push_approve
    jmp .scrub
.reset:
    call cmd_push_reset
.scrub:
    mov rdi, r13
    test rdi, rdi
    jz .restore
    call pu_scrub
    jmp .restore
.status:
    mov [rbx + REQ_ARG], rdx
    mov rdi, rbx
    mov rsi, r12
    call cmd_push_stat
    jmp .scrub
.auth_refused:
    mov qword [r12 + RSP_CODE], CMDE_AUTHDENY
    mov rax, CMD_AUTH_CAP_MUTATE
    mov [r12 + RSP_EXPECTED], rax
    lea rax, [rel command_auth_out_buf]
    mov [r12 + RSP_HINT], rax
    jmp .scrub
.restore:
    mov [rbx + REQ_ARG], r13
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

push_auth_cancel:
    mov byte [rel pu_state], 0
    mov byte [rel pu_kind], 0
    mov byte [rel pu_attempts], 0
    mov qword [rel pu_deadline], 0
    mov qword [rel pu_session_epoch], 0
    lea rdi, [rel pu_hash]
    xor esi, esi
    mov edx, 32
    call memset
    mov byte [rel pu_owner_staged], 0
    lea rdi, [rel pu_owner_stage]
    xor esi, esi
    mov edx, 32
    call memset
    call notify_http_cancel
    ret

; Transport failure cancels push-only authority. Only a successful real
; PASSWORD verification can use this fallback; failure itself never binds.
push_auth_fallback:
    mov byte [rel pu_terminal], PU_TERM_TRANSPORT
    mov al, [rel notify_http_state]
    mov [rel pu_last_notify_state], al
    mov al, [rel notify_http_tls_state]
    mov [rel pu_last_tls_state], al
    mov al, [rel notify_http_tls_error]
    mov [rel pu_last_tls_error], al
    mov al, [rel notify_http_fail_phase]
    mov [rel pu_last_notify_phase], al
    mov al, [rel notify_http_tcp_connected]
    mov [rel pu_last_tcp_connected], al
    mov al, [rel notify_http_tls_last_record]
    mov [rel pu_last_tls_record], al
    mov al, [rel notify_http_tls_last_handshake]
    mov [rel pu_last_tls_handshake], al
    mov eax, [rel notify_http_tls_records]
    mov [rel pu_last_tls_records], eax
    mov eax, [rel notify_http_tls_handshakes]
    mov [rel pu_last_tls_handshakes], eax
    lea rdi, [rel pu_event_fallback]
    call pu_audit_event
    call push_auth_cancel
    mov byte [rel pu_fallback], 1
    inc qword [rel pu_failure_count]
    ret

push_auth_tick:
    cmp byte [rel pu_state], 0
    je .out
    mov rax, [rel session_authority_epoch]
    cmp rax, [rel pu_session_epoch]
    je .epoch_ok
    mov byte [rel pu_terminal], PU_TERM_EPOCH
    jmp push_auth_cancel
.epoch_ok:
    call boot_ms_now
    cmp rax, [rel pu_deadline]
    jae .expired
    cmp byte [rel pu_state], PU_SENDING
    jne .out
    call notify_http_tick
    cmp byte [rel notify_http_state], 6
    je push_auth_fallback
    cmp byte [rel notify_http_state], 5
    jne .out
    call notify_http_cancel
    mov byte [rel pu_state], PU_PENDING
    inc qword [rel pu_delivered]
    lea rdi, [rel pu_event_delivered]
    call pu_audit_event
.out:
    ret
.expired:
    mov byte [rel pu_terminal], PU_TERM_EXPIRED
    inc qword [rel pu_expired]
    lea rdi, [rel pu_event_expired]
    call pu_audit_event
    jmp push_auth_cancel

; EDI=method. Only the PASSWORD-success path can select PU_2FA.
push_auth_issue:
    push rbx
    mov ebx, edi
    call push_auth_cancel
    ; A failure before notify_http_start (protected-config open, entropy or
    ; hashing) must not inherit the previous request's transport diagnosis.
    mov byte [rel notify_http_fail_phase], 0
    mov byte [rel notify_http_tls_state], 0
    mov byte [rel notify_http_tls_error], 0
    mov byte [rel notify_http_tcp_connected], 0
    mov byte [rel notify_http_tls_last_record], 0
    mov byte [rel notify_http_tls_last_handshake], 0
    mov dword [rel notify_http_tls_records], 0
    mov dword [rel notify_http_tls_handshakes], 0
    mov byte [rel pu_terminal], PU_TERM_NONE
    mov byte [rel pu_last_notify_state], 0
    mov byte [rel pu_last_tls_state], 0
    mov byte [rel pu_last_tls_error], 0
    mov byte [rel pu_last_notify_phase], 0
    mov byte [rel pu_last_tcp_connected], 0
    mov byte [rel pu_last_tls_record], 0
    mov byte [rel pu_last_tls_handshake], 0
    mov dword [rel pu_last_tls_records], 0
    mov dword [rel pu_last_tls_handshakes], 0
    cmp byte [rel prin_password_enrolled], 1
    jne .bad
    movzx eax, byte [rel keep_push_modes]
    lea ecx, [rbx - 1]
    bt eax, ecx
    jnc .bad
    call keep_push_open
    test eax, eax
    jnz .unreachable
    lea rdi, [rel pu_random]
    mov esi, 16
    call csprng_generate
    test eax, eax
    jnz .unreachable
    mov rdi, [rel pu_random]
    lea rsi, [rel pu_code]
    mov edx, 16
    call fmt_hex
    mov rdi, [rel pu_random + 8]
    lea rsi, [rel pu_code + 16]
    mov edx, 16
    call fmt_hex
    lea rdi, [rel pu_hash]
    lea rsi, [rel pu_code]
    mov edx, 32
    call sha256_hash
    test eax, eax
    jnz .unreachable
    call boot_ms_now
    add rax, PU_TTL_MS
    mov [rel pu_deadline], rax
    mov rax, [rel session_authority_epoch]
    mov [rel pu_session_epoch], rax
    mov [rel pu_kind], bl
    mov byte [rel pu_state], PU_SENDING
    mov byte [rel pu_fallback], 0
    inc qword [rel pu_issued]
    lea rdi, [rel pu_event_issued]
    call pu_audit_event
    lea rdi, [rel config_store_plain]
    lea rsi, [rel pu_code]
    mov edx, ebx
    call notify_http_start
    test eax, eax
    jnz .unreachable
    xor ebx, ebx
    jmp .wipe
.unreachable:
    call push_auth_fallback
.bad:
    mov ebx, -1
.wipe:
    call config_store_wipe
    lea rdi, [rel pu_random]
    xor esi, esi
    mov edx, 16
    call memset
    lea rdi, [rel pu_code]
    xor esi, esi
    mov edx, 33
    call memset
    mov eax, ebx
    pop rbx
    ret

; Called after PASSWORD verification/durable anti-hammer/KEK derivation,
; BEFORE publishing the principal or handle. 0=may bind; 1=pending/refused.
push_auth_password_gate:
    test byte [rel keep_push_modes], 1
    jz .allow
    cmp byte [rel pu_fallback], 1
    je .allow
    mov edi, PU_2FA
    call push_auth_issue
    test eax, eax
    jz .pending
    cmp byte [rel pu_fallback], 1
    je .allow
.pending:
    mov eax, 1
    ret
.allow:
    xor eax, eax
    ret

; push_auth_wipe_stage: drop a staged owner key without touching the challenge
; itself (principal_wipe_owner_boot_key, before every reset/handoff; root 14:10).
; A later approval of that challenge then binds authority only.
push_auth_wipe_stage:
    mov byte [rel pu_owner_staged], 0
    lea rdi, [rel pu_owner_stage]
    xor esi, esi
    mov edx, 32
    jmp memset

; RDI=owner key (32 B) after a correct PASSWORD that push_auth_password_gate
; just turned into a PU_2FA challenge. The challenge holds it until approval
; (push_auth_take hands it over once) or until push_auth_cancel wipes it:
; expiry, epoch change, fallback, consumption or a new issue.
push_auth_stage_owner:
    cmp byte [rel pu_state], 0
    je .out
    cmp byte [rel pu_kind], PU_2FA
    jne .out
    mov rsi, rdi
    lea rdi, [rel pu_owner_stage]
    mov edx, 32
    call memcpy
    mov byte [rel pu_owner_staged], 1
.out:
    ret

; RDI=AUTH_CTX, RSI=bounded 32-byte candidate output -> EAX=0 consumed / -1,
; EDX=1 when the candidate holds the owner key a PU_2FA challenge staged, else
; 0 with the candidate zeroed. SEC-owner-key-in-push-record (P1): the protected
; record no longer holds the owner's key (PC_HANDLE is one-way), so nothing is
; copied from it; it is still opened and validated as the policy in force.
; The caller deliberately holds no credential spinlock while this routine
; crosses audit, notification, AES/HKDF and UEFI config access; authenticate_bind
; installs and wipes the candidate under prin_credential_lock.
push_auth_take:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov rdi, r12
    xor esi, esi
    mov edx, 32
    call memset
    ; The consume below cancels the challenge, which wipes the stage: take it
    ; first, and wipe it again from the candidate on any refusal.
    xor r13d, r13d
    cmp byte [rel pu_owner_staged], 1
    jne .consume
    cmp byte [rel pu_kind], PU_2FA
    jne .consume
    movzx eax, byte [rbx + AUTH_CTX_AUDIT_REF]
    cmp eax, PU_2FA
    jne .consume
    mov rdi, r12
    lea rsi, [rel pu_owner_stage]
    mov edx, 32
    call memcpy
    mov r13d, 1
.consume:
    mov rdi, rbx
    call pu_consume_code
    test eax, eax
    jnz .bad
    call keep_push_open
    test eax, eax
    jnz .bad
    call config_store_wipe
    inc qword [rel pu_consumed]
    xor eax, eax
    mov edx, r13d
    jmp .out
.bad:
    call config_store_wipe
    mov rdi, r12
    xor esi, esi
    mov edx, 32
    call memset
    mov eax, -1
    xor edx, edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Shared production state-machine gate, also exercised without I/O at boot.
; RDI=ctx -> 0 consumed, -1 wrong/missing/method-mismatched/expired/replayed.
pu_consume_code:
    push rbx
    mov rbx, rdi
    cmp byte [rel pu_state], PU_PENDING
    jne .bad
    mov rax, [rel session_authority_epoch]
    cmp rax, [rel pu_session_epoch]
    jne .burn_bad
    call boot_ms_now
    cmp rax, [rel pu_deadline]
    jae .burn_bad
    movzx eax, byte [rel pu_kind]
    cmp [rbx + AUTH_CTX_AUDIT_REF], rax
    jne .attempt
    cmp qword [rbx + AUTH_CTX_CRED_LEN], 32
    jne .attempt
    mov rsi, [rbx + AUTH_CTX_CREDENTIAL]
    test rsi, rsi
    jz .attempt
    lea rdi, [rel pu_check]
    mov edx, 32
    call sha256_hash
    test eax, eax
    jnz .attempt
    lea rdi, [rel pu_check]
    lea rsi, [rel pu_hash]
    mov edx, 32
    call principal_ct_equal
    test eax, eax
    jz .attempt
    lea rdi, [rel pu_event_consumed]
    call pu_audit_event
    mov byte [rel pu_terminal], PU_TERM_CONSUMED
    call push_auth_cancel
    xor ebx, ebx
    jmp .wipe
.attempt:
    inc qword [rel pu_refused]
    lea rdi, [rel pu_event_refused]
    call pu_audit_event
    inc byte [rel pu_attempts]
    cmp byte [rel pu_attempts], 3
    jb .bad
    mov byte [rel pu_terminal], PU_TERM_ATTEMPTS
.burn_bad:
    call push_auth_cancel
.bad:
    mov ebx, -1
.wipe:
    lea rdi, [rel pu_check]
    xor esi, esi
    mov edx, 32
    call memset
    mov eax, ebx
    pop rbx
    ret

; Bounded audit receipt: event, method and monotonically issued challenge id.
; No code/hash input, credential or endpoint material can reach this formatter.
pu_audit_event:
    cmp byte [rel pu_live], 1
    jne .out
    push rbx
    mov rsi, rdi
    lea rdi, [rel pu_event_buf]
    mov edx, 80
    call strcpy_s
    lea rbx, [rel pu_event_buf]
    add rbx, rax
    mov rdi, rbx
    lea rsi, [rel pu_event_method]
    mov edx, 16
    call strcpy_s
    add rbx, rax
    movzx edi, byte [rel pu_kind]
    mov rsi, rbx
    call fmt_dec
    add rbx, rax
    mov rdi, rbx
    lea rsi, [rel pu_event_id]
    mov edx, 16
    call strcpy_s
    add rbx, rax
    mov rdi, [rel pu_issued]
    mov rsi, rbx
    call fmt_dec
    lea rdi, [rel pu_event_buf]
    call audit_log_line
    pop rbx
.out:
    ret

pu_reply:
    push rbx
    mov rbx, rdi
    call prin_out_reset
    mov rdi, rbx
    call prin_out_str
    call principal_publish_wire_reply
    pop rbx
    ret

cmd_push_stat:
    push rbx
    mov rbx, [rdi + REQ_ARG]
    mov byte [rel pu_stat_nonce], 0
    test rbx, rbx
    jz .nonce_ready
    mov rdi, rbx
    call strlen
    test eax, eax
    jz .nonce_ready
    cmp eax, 32
    jne .bad_nonce
    mov rdi, rbx
    lea rsi, [rel pu_nonce_bytes]
    mov edx, 16
    call pu_pin_parse
    test eax, eax
    jnz .bad_nonce
    lea rdi, [rel pu_stat_nonce]
    mov rsi, rbx
    mov edx, 33
    call strcpy_s
.nonce_ready:
    call push_auth_tick
    call prin_out_reset
    lea rdi, [rel pu_stat]
    call prin_out_str
    movzx edi, byte [rel keep_push_modes]
    call prin_out_dec
    lea rdi, [rel pu_stat_pending]
    call prin_out_str
    movzx edi, byte [rel pu_state]
    call prin_out_dec
    lea rdi, [rel pu_stat_method]
    call prin_out_str
    movzx edi, byte [rel pu_kind]
    call prin_out_dec
    lea rdi, [rel pu_stat_issued]
    call prin_out_str
    mov rdi, [rel pu_issued]
    call prin_out_dec
    lea rdi, [rel pu_stat_delivered]
    call prin_out_str
    mov rdi, [rel pu_delivered]
    call prin_out_dec
    lea rdi, [rel pu_stat_consumed]
    call prin_out_str
    mov rdi, [rel pu_consumed]
    call prin_out_dec
    lea rdi, [rel pu_stat_expired]
    call prin_out_str
    mov rdi, [rel pu_expired]
    call prin_out_dec
    lea rdi, [rel pu_stat_refused]
    call prin_out_str
    mov rdi, [rel pu_refused]
    call prin_out_dec
    lea rdi, [rel pu_stat_terminal]
    call prin_out_str
    movzx edi, byte [rel pu_terminal]
    call prin_out_dec
    lea rdi, [rel pu_stat_fallbacks]
    call prin_out_str
    mov rdi, [rel pu_failure_count]
    call prin_out_dec
    lea rdi, [rel pu_stat_notify]
    call prin_out_str
    movzx edi, byte [rel pu_last_notify_state]
    call prin_out_dec
    lea rdi, [rel pu_stat_tls]
    call prin_out_str
    movzx edi, byte [rel pu_last_tls_state]
    call prin_out_dec
    lea rdi, [rel pu_stat_tls_error]
    call prin_out_str
    movzx edi, byte [rel pu_last_tls_error]
    call prin_out_dec
    lea rdi, [rel pu_stat_notify_phase]
    call prin_out_str
    movzx edi, byte [rel pu_last_notify_phase]
    call prin_out_dec
    lea rdi, [rel pu_stat_tcp_connected]
    call prin_out_str
    movzx edi, byte [rel pu_last_tcp_connected]
    call prin_out_dec
    lea rdi, [rel pu_stat_tls_records]
    call prin_out_str
    mov edi, [rel pu_last_tls_records]
    call prin_out_dec
    lea rdi, [rel pu_stat_tls_handshakes]
    call prin_out_str
    mov edi, [rel pu_last_tls_handshakes]
    call prin_out_dec
    lea rdi, [rel pu_stat_tls_record]
    call prin_out_str
    movzx edi, byte [rel pu_last_tls_record]
    call prin_out_dec
    lea rdi, [rel pu_stat_tls_handshake]
    call prin_out_str
    movzx edi, byte [rel pu_last_tls_handshake]
    call prin_out_dec
    lea rdi, [rel pu_stat_policy]
    call prin_out_str
    mov rdi, [rel pu_policy_changes]
    call prin_out_dec
    lea rdi, [rel pu_stat_policy_step]
    call prin_out_str
    movzx edi, byte [rel pu_policy_step]
    call prin_out_dec
    lea rdi, [rel pu_stat_store_step]
    call prin_out_str
    movzx edi, byte [rel config_store_step]
    call prin_out_dec
    lea rdi, [rel pu_stat_rotations]
    call prin_out_str
    mov rdi, [rel pu_rotations]
    call prin_out_dec
    lea rdi, [rel pu_stat_markers]
    call prin_out_str
    movzx edi, byte [rel pu_kat_ok]
    call prin_out_dec
    lea rdi, [rel pu_stat_registry]
    call prin_out_str
    movzx edi, byte [rel pu_registry_ok]
    call prin_out_dec
    lea rdi, [rel pu_stat_registry_before]
    call prin_out_str
    mov edi, [rel pu_registry_before]
    call prin_out_dec
    lea rdi, [rel pu_stat_registry_after]
    call prin_out_str
    mov edi, [rel pu_registry_after]
    call prin_out_dec
    lea rdi, [rel pu_stat_auth_kat]
    call prin_out_str
    movzx edi, byte [rel prin_m_auth_system]
    shl edi, 1
    movzx eax, byte [rel prin_m_auth_pbkdf2]
    or edi, eax
    shl edi, 1
    movzx eax, byte [rel prin_m_auth_method]
    or edi, eax
    shl edi, 1
    movzx eax, byte [rel prin_m_auth_bind]
    or edi, eax
    call prin_out_dec
    lea rdi, [rel pu_stat_off]
    cmp byte [rel pu_fallback], 1
    jne .status
    lea rdi, [rel pu_fallback_text]
.status:
    call prin_out_str
    cmp byte [rel pu_stat_nonce], 0
    je .publish
    lea rdi, [rel pu_stat_nonce_text]
    call prin_out_str
    lea rdi, [rel pu_stat_nonce]
    call prin_out_str
.publish:
    call principal_publish_wire_reply
    pop rbx
    ret
.bad_nonce:
    lea rdi, [rel pu_denied]
    call pu_reply
    pop rbx
    ret

; PUSHAUTH policy off
; PUSHAUTH policy <mask:1..7> <ntfy|gotify> <port> <host> <path> <token|-> <leaf-sha256>
; Enable requires unlocked PASSWORD handle + owner AUTH1. Off is always an
; owner-signed recovery option. All arguments, including malformed ones, scrub.
cmd_push_policy:
    push rbx
    push r12
    mov rbx, rdi
    mov r12d, -1
    mov byte [rel pu_policy_step], 1
    lea rdi, [rel pu_policy_plain]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
    call command_auth_owner_request       ; SSH judged by its own ticket only
    test eax, eax
    jz .scrub
    mov byte [rel pu_policy_step], 2
    mov rdi, [rbx + REQ_ARG]
    lea rsi, [rel pu_off]
    call strcmp
    test eax, eax
    jz .save
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .scrub
    mov byte [rel pu_policy_step], 3
    cmp byte [rel prin_owner_session_ready], 1
    jne .scrub
    mov byte [rel pu_policy_step], 4
    cmp byte [rel prin_password_enrolled], 1
    jne .scrub
    mov byte [rel pu_policy_step], 5
    mov rdi, [rbx + REQ_ARG]
    call pu_policy_parse
    test eax, eax
    jnz .scrub
    ; PC_HANDLE: keep_push_save stamps the one-way handle, never the key (P1).
    lea rdi, [rel pu_policy_plain + PC_SALT]
    lea rsi, [rel prin_password_salt]
    mov edx, 16
    call memcpy
.save:
    mov byte [rel pu_policy_step], 6
    call push_auth_cancel
    lea rdi, [rel pu_policy_plain]
    call keep_push_save
    mov r12d, eax
    test eax, eax
    jnz .scrub
    mov byte [rel pu_fallback], 0
    inc qword [rel pu_policy_changes]
    mov byte [rel pu_policy_step], 0
.scrub:
    mov rdi, [rbx + REQ_ARG]
    call pu_scrub
    lea rdi, [rel pu_policy_plain]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
    lea rdi, [rel pu_policy_bad]
    test r12d, r12d
    jnz .reply
    lea rdi, [rel pu_policy_ok]
.reply:
    call pu_reply
    pop r12
    pop rbx
    ret

; RDI=cursor, RSI=destination, EDX=capacity -> RDI=next cursor, EAX=0/-1.
; Nonempty printable ASCII tokens: no HTTP header injection.
pu_token:
    push rbx
    mov rbx, rsi
    xor ecx, ecx
.loop:
    mov al, [rdi]
    cmp al, ' '
    je .end
    test al, al
    jz .end
    cmp al, 0x21
    jb .bad
    cmp al, 0x7e
    ja .bad
    inc ecx
    cmp ecx, edx
    jae .bad
    mov [rsi], al
    inc rsi
    inc rdi
    jmp .loop
.end:
    test ecx, ecx
    jz .bad
    mov byte [rsi], 0
    cmp byte [rdi], 0
    je .ok
    inc rdi
.ok:
    xor eax, eax
    pop rbx
    ret
.bad:
    mov byte [rbx], 0
    mov eax, -1
    pop rbx
    ret

pu_policy_parse:
    push rbx
    movzx eax, byte [rdi]
    sub eax, '1'
    cmp eax, 6
    ja .bad
    inc eax
    mov [rel pu_policy_plain + PC_MODES], al
    cmp byte [rdi + 1], ' '
    jne .bad
    add rdi, 2
    lea rsi, [rel pu_parse_token]
    mov edx, 16
    call pu_token
    test eax, eax
    jnz .bad
    mov rbx, rdi
    lea rdi, [rel pu_parse_token]
    lea rsi, [rel pu_ntfy]
    call strcmp
    mov byte [rel pu_policy_plain + PC_PROVIDER], 1
    test eax, eax
    jz .port
    lea rdi, [rel pu_parse_token]
    lea rsi, [rel pu_gotify]
    call strcmp
    test eax, eax
    jnz .bad
    mov byte [rel pu_policy_plain + PC_PROVIDER], 2
.port:
    mov rdi, rbx
    xor eax, eax
    xor ecx, ecx
.digit:
    movzx edx, byte [rdi]
    sub edx, '0'
    cmp edx, 9
    ja .port_done
    inc ecx
    cmp ecx, 5
    ja .bad
    imul eax, eax, 10
    add eax, edx
    cmp eax, 65535
    ja .bad
    inc rdi
    jmp .digit
.port_done:
    test eax, eax
    jz .bad
    cmp byte [rdi], ' '
    jne .bad
    inc rdi
    mov [rel pu_policy_plain + PC_PORT], ax
    lea rsi, [rel pu_policy_plain + PC_HOST]
    mov edx, 96
    call pu_token
    test eax, eax
    jnz .bad
    lea rsi, [rel pu_policy_plain + PC_HOST]
.host:
    mov al, [rsi]
    test al, al
    jz .path
    cmp al, '.'
    je .host_next
    cmp al, '-'
    je .host_next
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .host_next
    or al, 0x20
    cmp al, 'a'
    jb .bad
    cmp al, 'z'
    ja .bad
.host_next:
    inc rsi
    jmp .host
.path:
    lea rsi, [rel pu_policy_plain + PC_PATH]
    mov edx, 128
    call pu_token
    test eax, eax
    jnz .bad
    cmp byte [rel pu_policy_plain + PC_PATH], '/'
    jne .bad
    lea rsi, [rel pu_policy_plain + PC_PATH]
.path_byte:
    mov al, [rsi]
    test al, al
    jz .token
    cmp al, '?'
    je .bad
    cmp al, '#'
    je .bad
    inc rsi
    jmp .path_byte
.token:
    lea rsi, [rel pu_policy_plain + PC_TOKEN]
    mov edx, 128
    call pu_token
    test eax, eax
    jnz .bad
    cmp word [rel pu_policy_plain + PC_TOKEN], '-'
    jne .pin
    mov byte [rel pu_policy_plain + PC_TOKEN], 0
.pin:
    lea rsi, [rel pu_policy_plain + PC_PIN]
    mov edx, 32
    call pu_pin_parse
    test eax, eax
    jnz .bad
    cmp byte [rdi], 0
    jne .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, -1
    pop rbx
    ret

pu_pin_parse:
    xor r8d, r8d
.byte:
    xor r9d, r9d
    mov ecx, 2
.nibble:
    movzx eax, byte [rdi]
    sub eax, '0'
    cmp eax, 9
    jbe .hex
    movzx eax, byte [rdi]
    or eax, 0x20
    sub eax, 'a'
    cmp eax, 5
    ja .bad
    add eax, 10
.hex:
    shl r9d, 4
    or r9d, eax
    inc rdi
    dec ecx
    jnz .nibble
    mov [rsi + r8], r9b
    inc r8d
    cmp r8d, edx
    jb .byte
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

pu_scrub:
    push rbx
    mov rbx, rdi
    call strlen
    mov rsi, rax
    mov rdi, rbx
    lea rdx, [rel pu_audit]
    mov ecx, pu_audit.len
    call principal_scrub_wire_secret
    pop rbx
    ret

; PUSHAUTH begin reset|passwordless. Two-factor comes only from PASSWORD success.
cmd_push_begin:
    push rbx
    mov rbx, rdi
    call command_auth_owner_request       ; SSH judged by its own ticket only
    test eax, eax
    jz .bad
    mov rdi, [rbx + REQ_ARG]
    lea rsi, [rel pu_reset]
    call strcmp
    mov edi, PU_RESET
    test eax, eax
    jz .issue
    mov rdi, [rbx + REQ_ARG]
    lea rsi, [rel pu_passwordless]
    call strcmp
    test eax, eax
    jnz .bad
    mov edi, PU_PASSWORDLESS
.issue:
    call push_auth_issue
    test eax, eax
    jnz .bad
    lea rdi, [rel pu_wait]
    jmp .reply
.bad:
    lea rdi, [rel pu_denied]
    cmp byte [rel pu_fallback], 1
    jne .reply
    lea rdi, [rel pu_fallback_text]
.reply:
    call pu_reply
    pop rbx
    ret

; PUSHAUTH approve code32. Reset challenges cannot accidentally unlock.
; Approve is an EXPLICIT owner unlock of the local console over AUTH1, armed as
; the one explicit grant and audit-logged. Over SSH it is refused: an SSH session
; never unlocks the console (spec 21.2.5, root 89528).
cmd_push_approve:
    push rbx
    push r12
    mov rbx, rdi
    mov [rel pu_approve_rsp], rsi
    xor r12d, r12d
    call command_auth_owner_request       ; SSH judged by its own ticket only
    test eax, eax
    jz .ticket_refused
    cmp eax, 2
    je .ssh_refused
    cmp byte [rel pu_kind], PU_RESET
    je .scrub
    mov rdi, [rbx + REQ_ARG]
    call pu_bind_code
    mov r12, rax
    test rax, rax
    jz .code_refused
    mov rdi, rax
    mov rsi, rdx
    call session_shell_offer_bind
    test eax, eax
    jnz .clear
    ; Consume the output-only bind before command_udp's mandatory session sync.
    ; If left locked until push_auth_tick, lock_screen_sync clears this freshly
    ; bound principal first.  Use the authority-only core here: the dispatcher
    ; performs the ordinary presentation sync after the handler returns, while
    ; the workspace restore callback remains outside nested UDP dispatch.
    mov edi, SESSION_METHOD_PUSHAUTH
    call session_shell_arm_explicit_unlock
    call session_shell_unlock_core
    test eax, eax
    jz .scrub
.clear:
    call principal_clear_bound
    xor r12d, r12d
    jmp .scrub
.ticket_refused:
    mov edi, SESSION_UNLOCK_TICKET
    mov esi, SESSION_METHOD_PUSHAUTH
    call session_shell_audit_unlock
    jmp .scrub
.ssh_refused:
    mov edi, SESSION_UNLOCK_SSH
    mov esi, SESSION_METHOD_PUSHAUTH
    call session_shell_audit_unlock
    jmp .scrub
.code_refused:
    mov edi, SESSION_UNLOCK_CRED
    mov esi, SESSION_METHOD_PUSHAUTH
    call session_shell_audit_unlock
.scrub:
    mov rdi, [rbx + REQ_ARG]
    call pu_scrub
    lea rdi, [rel pu_denied]
    test r12, r12
    jz .denied
    lea rdi, [rel pu_approved]
    jmp .reply
.denied:
    ; refused approval: non-zero on every projection (SSH exit 6); the UDP
    ; lean envelope does not branch on the code
    mov rax, [rel pu_approve_rsp]
    mov qword [rax + RSP_CODE], CMDE_AUTHDENY
.reply:
    call pu_reply
    pop r12
    pop rbx
    ret

pu_bind_code:
    push rbx
    mov rbx, rdi
    call strlen
    cmp rax, 32
    jne .bad
    lea rdi, [rel pu_ctx]
    xor esi, esi
    mov edx, AUTH_CTX_SIZE
    call memset
    mov [rel pu_ctx + AUTH_CTX_CREDENTIAL], rbx
    mov qword [rel pu_ctx + AUTH_CTX_CRED_LEN], 32
    movzx eax, byte [rel pu_kind]
    mov [rel pu_ctx + AUTH_CTX_AUDIT_REF], rax
    mov edi, AUTH_BIND_PUSH
    lea rsi, [rel pu_ctx]
    call authenticate_bind
    mov qword [rel pu_ctx + AUTH_CTX_CREDENTIAL], 0
    pop rbx
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop rbx
    ret

; PUSHAUTH reset code32 new-password. F3(B)/Q5 refuses in every state,
; scrubs the request, and consumes no push approval or password authority.
cmd_push_reset:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    mov r12d, -2                       ; F3(B)/Q5: every remote reset refused
    jmp .scrub
.scrub:
    mov rdi, [rbx + REQ_ARG]
    call pu_scrub
    lea rdi, [rel pu_code]
    xor esi, esi
    mov edx, 33
    call memset
    mov qword [rel pu_reset_password], 0
    lea rdi, [rel pu_reset_bad]
    test r12d, r12d
    jnz .reply
    lea rdi, [rel pu_reset_ok]
.reply:
    call pu_reply
    add rsp, 8
    pop r12
    pop rbx
    ret

; Exercise the actual operation parser, including public-query prefix aliases
; that must never turn an action into an unsigned status query.
pu_operation_selftest:
    push rbx
    lea rbx, [rel pu_operation_cases]
.case:
    cmp byte [rbx], 255
    je .ok
    lea rdi, [rbx + 1]
    call pu_operation
    cmp al, [rbx]
    jne .bad
    test eax, eax
    jz .next
    ; The operand pointer must end at this token's NUL or just past its space.
    lea rdi, [rbx + 1]
.operand:
    cmp byte [rdi], 0
    je .check
    cmp byte [rdi], ' '
    je .space
    inc rdi
    jmp .operand
.space:
    inc rdi
.check:
    cmp rdx, rdi
    jne .bad
.next:
    inc rbx
.skip:
    cmp byte [rbx], 0
    lea rbx, [rbx + 1]
    jne .skip
    jmp .case
.ok:
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, -1
    pop rbx
    ret

; Local preflight runs the production parser/consume/TTL/replay/fallback gates.
; No firmware writes or network operations. Real flow receipts are required
; separately; a boot marker is never external-delivery evidence.
push_auth_selftest:
    push rbx
    cmp byte [rel pu_registry_ok], 1
    jne .bad
    call pu_operation_selftest
    test eax, eax
    jnz .bad
    cmp byte [rel keep_push_modes], 0
    jne .bad
    call push_auth_password_gate
    test eax, eax
    jnz .bad
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    cmp eax, -1
    jne .bad
    lea rdi, [rel pu_policy_kat]
    call pu_policy_parse
    test eax, eax
    jnz .bad
    cmp byte [rel pu_policy_plain + PC_MODES], 7
    jne .bad
    cmp byte [rel pu_policy_plain + PC_PROVIDER], 2
    jne .bad
    cmp word [rel pu_policy_plain + PC_PORT], 443
    jne .bad
    call principal_reset_key_kat
    test eax, eax
    jnz .bad
    call http_notify_selftest
    test eax, eax
    jnz .bad
    ; Every Task2504 marker also requires the encrypted application record to
    ; cross TLS's real TCP receive callback with the zero-success service ABI.
    call tls13_application_transition_kat
    test eax, eax
    jnz .bad
    ; Use each method tag against the actual production consumer. No live
    ; credential/policy row is replaced, and no network proof is inferred.
    mov ebx, PU_2FA
.method:
    lea rdi, [rel pu_hash]
    lea rsi, [rel pu_kat_code]
    mov edx, 32
    call sha256_hash
    test eax, eax
    jnz .bad
    mov byte [rel pu_state], PU_PENDING
    mov [rel pu_kind], bl
    mov rax, [rel session_authority_epoch]
    mov [rel pu_session_epoch], rax
    call boot_ms_now
    add rax, PU_TTL_MS
    mov [rel pu_deadline], rax
    ; Production lock-screen refresh clears transport identity after every
    ; locked query. Exercise that real callee: it must retain the challenge.
    ; Preserve the boot caller's principal/handle around the real clear call.
    sub rsp, 48
    mov rdi, rsp
    lea rsi, [rel prin_owner_session_key]
    mov edx, 32
    call memcpy
    movzx eax, byte [rel prin_owner_session_ready]
    mov [rsp + 32], rax
    mov rax, [rel prin_active_pid]
    mov [rsp + 40], rax
    call principal_clear_bound
    lea rdi, [rel prin_owner_session_key]
    mov rsi, rsp
    mov edx, 32
    call memcpy
    mov rax, [rsp + 32]
    mov [rel prin_owner_session_ready], al
    mov rax, [rsp + 40]
    mov [rel prin_active_pid], rax
    mov rdi, rsp
    xor esi, esi
    mov edx, 48
    call memset
    add rsp, 48
    cmp byte [rel pu_state], PU_PENDING
    jne .bad
    call push_auth_tick
    cmp byte [rel pu_state], PU_PENDING
    jne .bad
    lea rax, [rel pu_kat_wrong]
    mov [rel pu_ctx + AUTH_CTX_CREDENTIAL], rax
    mov qword [rel pu_ctx + AUTH_CTX_CRED_LEN], 32
    mov [rel pu_ctx + AUTH_CTX_AUDIT_REF], rbx
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    cmp eax, -1
    jne .bad
    cmp byte [rel pu_state], PU_PENDING
    jne .bad
    lea rax, [rel pu_kat_code]
    mov [rel pu_ctx + AUTH_CTX_CREDENTIAL], rax
    lea rax, [rbx + 1]
    mov [rel pu_ctx + AUTH_CTX_AUDIT_REF], rax
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    cmp eax, -1
    jne .bad
    cmp byte [rel pu_state], PU_PENDING
    jne .bad
    mov [rel pu_ctx + AUTH_CTX_AUDIT_REF], rbx
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    test eax, eax
    jnz .bad
    cmp byte [rel pu_state], 0
    jne .bad
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    cmp eax, -1
    jne .bad
    mov byte [rel pu_state], PU_PENDING
    mov [rel pu_kind], bl
    mov qword [rel pu_deadline], 0
    mov rax, [rel session_authority_epoch]
    mov [rel pu_session_epoch], rax
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    cmp eax, -1
    jne .bad
    cmp byte [rel pu_state], 0
    jne .bad
    ; A challenge from a previous lock/unlock epoch must fail even before
    ; the next poll. Then independently exercise the poll-side cancellation.
    mov byte [rel pu_state], PU_PENDING
    mov [rel pu_kind], bl
    mov rax, [rel session_authority_epoch]
    xor rax, 1
    mov [rel pu_session_epoch], rax
    call boot_ms_now
    add rax, PU_TTL_MS
    mov [rel pu_deadline], rax
    lea rdi, [rel pu_ctx]
    call pu_consume_code
    cmp eax, -1
    jne .bad
    cmp byte [rel pu_state], 0
    jne .bad
    mov byte [rel pu_state], PU_PENDING
    mov rax, [rel session_authority_epoch]
    xor rax, 1
    mov [rel pu_session_epoch], rax
    call push_auth_tick
    cmp byte [rel pu_state], 0
    jne .bad
    inc ebx
    cmp ebx, PU_PASSWORDLESS
    jbe .method
    mov byte [rel pu_state], PU_SENDING
    call push_auth_fallback
    cmp byte [rel pu_state], 0
    jne .bad
    cmp byte [rel pu_fallback], 1
    jne .bad
    mov byte [rel keep_push_modes], 1
    call push_auth_password_gate
    test eax, eax
    jnz .bad
    mov byte [rel keep_push_modes], 0
    mov byte [rel pu_fallback], 0
    mov byte [rel pu_terminal], PU_TERM_NONE
    mov byte [rel pu_last_notify_state], 0
    mov byte [rel pu_last_tls_state], 0
    mov byte [rel pu_last_tls_error], 0
    mov qword [rel pu_refused], 0
    mov qword [rel pu_failure_count], 0
    lea rdi, [rel pu_ctx]
    xor esi, esi
    mov edx, AUTH_CTX_SIZE
    call memset
    lea rdi, [rel pu_policy_plain]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
    lea rdi, [rel pu_marker_policy]
    call serial_string
    lea rdi, [rel pu_marker_2fa]
    call serial_string
    lea rdi, [rel pu_marker_reset]
    call serial_string
    lea rdi, [rel pu_marker_passwordless]
    call serial_string
    lea rdi, [rel pu_marker_failsafe]
    call serial_string
    mov byte [rel pu_kat_ok], 31
    pop rbx
    ret
.bad:
    mov byte [rel keep_push_modes], 0
    mov byte [rel pu_fallback], 0
    call push_auth_cancel
    mov byte [rel pu_terminal], PU_TERM_NONE
    mov byte [rel pu_last_notify_state], 0
    mov byte [rel pu_last_tls_state], 0
    mov byte [rel pu_last_tls_error], 0
    lea rdi, [rel pu_marker_fail]
    call serial_string
    pop rbx
    ret

pu_verb: db 'PUSHAUTH',0
pu_operations: db 'status',0,'policy',0,'begin',0,'approve',0,'reset',0
pu_operation_cases:
    db 1,'status',0, 1,'status abc',0
    db 2,'policy',0, 2,'policy off',0
    db 3,'begin reset',0, 4,'approve abc',0, 5,'reset abc def',0
    db 0,'',0, 0,'stat',0, 0,'statusx',0, 0,'statuspolicy off',0
    db 0,'STATUS',0, 0,' status',0, 0,'status',9,'policy off',0
    db 0,'policyx off',0, 0,'beginx reset',0, 0,'approvex abc',0
    db 0,'resetx abc def',0, 255
pu_registration_fail: db '[PAOS64] login R3: PUSHAUTH registry registration FAIL',13,10,0
pu_off: db 'off',0
pu_ntfy: db 'ntfy',0
pu_gotify: db 'gotify',0
pu_reset: db 'reset',0
pu_passwordless: db 'passwordless',0
pu_audit: db 'PUSH credential_and_endpoint=<redacted>'
.len equ $ - pu_audit
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_push_auth_0 0
pu_event_issued: db 'PUSH issued',0
pu_event_delivered: db 'PUSH delivered',0
pu_event_consumed: db 'PUSH consumed',0
pu_event_expired: db 'PUSH expired',0
pu_event_refused: db 'PUSH refused',0
pu_event_fallback: db 'PUSH fallback',0
pu_event_method: db ' method=',0
pu_event_id: db ' challenge=',0
pu_wait: db 'PUSH pending=delivery password_recovery=available',0
pu_login_wait: db ' push_approval_required pending=1',0
pu_denied: db 'PUSH REFUSED',0
pu_approved: db 'PUSH OK principal=1 consumed=1',0
pu_policy_ok: db 'PUSHPOLICY OK authenticated=1 endpoint=<protected>',0
pu_policy_bad: db 'PUSHPOLICY REFUSED',0
pu_reset_ok: db 'PUSHRESET OK credential_store=Task2501 consumed=1 policy=off',0
pu_reset_bad: db 'PUSHRESET REFUSED password changes are local only until the confirm slice',0
pu_stat: db 'PUSHSTAT modes=',0
pu_stat_pending: db ' pending=',0
pu_stat_method: db ' method=',0
pu_stat_issued: db ' issued=',0
pu_stat_delivered: db ' delivered=',0
pu_stat_consumed: db ' consumed=',0
pu_stat_expired: db ' expired=',0
pu_stat_refused: db ' refused=',0
pu_stat_terminal: db ' terminal=',0
pu_stat_fallbacks: db ' fallbacks=',0
pu_stat_notify: db ' notify_state=',0
pu_stat_tls: db ' tls_state=',0
pu_stat_tls_error: db ' tls_error=',0
pu_stat_notify_phase: db ' notify_phase=',0
pu_stat_tcp_connected: db ' tcp_connected=',0
pu_stat_tls_records: db ' tls_records=',0
pu_stat_tls_handshakes: db ' tls_handshakes=',0
pu_stat_tls_record: db ' tls_last_record=',0
pu_stat_tls_handshake: db ' tls_last_handshake=',0
pu_stat_policy: db ' policy_changes=',0
pu_stat_policy_step: db ' policy_step=',0
pu_stat_store_step: db ' store_step=',0
pu_stat_rotations: db ' rotations=',0
pu_stat_markers: db ' policy_kat=',0
pu_stat_registry: db ' registry_ok=',0
pu_stat_registry_before: db ' registry_before=',0
pu_stat_registry_after: db ' registry_after=',0
pu_stat_auth_kat: db ' auth_kat=',0
pu_stat_nonce_text: db ' nonce=',0
pu_stat_off: db ' credential_store=Task2501 password_recovery=available',0
pu_fallback_text: db ' push_unreachable_password_fallback pending=0 password_recovery=available',0
pu_marker_policy: db '[PAOS64] login R3: ntfy/gotify modes and endpoint default off [login.push.policy]',13,10,0
pu_marker_2fa: db '[PAOS64] login R3: password then single-use push approval binds through authenticate_bind [login.push.2fa]',13,10,0
pu_marker_reset: db '[PAOS64] login R3: one-time reset challenge updates the Task2501 record only [login.push.reset]',13,10,0
pu_marker_passwordless: db '[PAOS64] login R3: optional push approval is a method on the shared bind seam [login.push.passwordless]',13,10,0
pu_marker_failsafe: db '[PAOS64] login R3: external failure preserves explicit password fallback [login.push.failsafe]',13,10,0
pu_marker_fail: db '[PAOS64] login R3: policy/challenge preflight FAIL',13,10,0
pu_policy_kat: db '7 gotify 443 example.invalid /message - 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',0
pu_kat_code: db '0123456789abcdef0123456789abcdef',0
pu_kat_wrong: db 'fedcba9876543210fedcba9876543210',0
align 8
pu_deadline: dq 0
pu_session_epoch: dq 0
pu_issued: dq 0
pu_delivered: dq 0
pu_consumed: dq 0
pu_expired: dq 0
pu_refused: dq 0
pu_failure_count: dq 0
pu_policy_changes: dq 0
pu_rotations: dq 0
pu_reset_password: dq 0
pu_state: db 0
pu_kind: db 0
pu_attempts: db 0
pu_fallback: db 0
pu_terminal: db 0
pu_last_notify_state: db 0
pu_last_tls_state: db 0
pu_last_tls_error: db 0
pu_last_notify_phase: db 0
pu_last_tcp_connected: db 0
pu_last_tls_record: db 0
pu_last_tls_handshake: db 0
align 4
pu_last_tls_records: dd 0
pu_last_tls_handshakes: dd 0
pu_kat_ok: db 0
pu_live: db 0
pu_registry_ok: db 0
align 4
pu_registry_before: dd 0
pu_registry_after: dd 0
pu_registry_slot: dd -1
; Policy checkpoints: 0 saved, 1 ticket, 2 locked, 3 handle, 4 enrollment,
; 5 parser, 6 protected-store failure. No arguments or secrets are retained.
pu_policy_step: db 0
pu_event_buf: times 80 db 0
pu_hash: times 32 db 0
pu_owner_stage: times 32 db 0          ; P1: the owner key a correct password left for its PU_2FA challenge
pu_owner_staged: db 0
pu_check: times 32 db 0
pu_random: times 16 db 0
pu_code: times 33 db 0
pu_ctx: times AUTH_CTX_SIZE db 0
pu_approve_rsp: dq 0          ; approve: the dispatcher's response envelope
pu_parse_token: times 16 db 0
pu_stat_nonce: times 33 db 0
pu_nonce_bytes: times 16 db 0
pu_policy_plain: times PC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_svc_push_auth_0
