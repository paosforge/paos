;; MODULE svc/command_card
;; LAYER 5
;; EXPORTS card_declare, card_confirm, card_deny, card_rearm, card_tick, card_cancel, card_state, card_armed_us, card_surface_show_op, card_surface_close_op, card_surface_ok_op, card_out_buf, card_out_ready, command_dispatch_card, ai_web_taint_set, ai_web_taint_of, card_required_for
;; IMPORTS boot/serial, core/time, core/lib/str, sec/principal, sec/session, svc/command, svc/command_auth, svc/command_netcheck
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/command_card.asm -- RCQ-40 J2a: the owner action card (record, verbs, the
; one dispatch path, the web-taint bit). Design ai-evidence/RCQ-40/J2-card/
; DESIGN_J2_CARD.md (ba1dd804) with rc-sec's ack and bindings C1-C8
; (sec-evidence/RCQ-40-J2_CARD_DESIGN_ACK_20261010.md, ledger 02:58:01) and
; rc-sec's proposer precisions (02:40:43). Checklist G8 terms 1-9.
;
; The AI only PROPOSES. A card records exactly one native verb + its argument
; text, shown in full or refused. The effect runs only through card_confirm,
; which the card surface (J2b) calls for a bound local OWNER's HUMAN Confirm;
; there is no confirm verb. command_dispatch_card is the one writer of the
; dispatcher's proposer arm. The lab floor carries CARDPROBE (one serial line,
; no state) for the QEMU witness.
;
; RCQ-40 J6 (journey 1, root GRANT 09:04:47, PLAN 92ed0e26): the shipped floor
; carries exactly one act, NETCFG "DHCP ONCE <nonce>", and only while NETCHECK's
; own classify says no_lease (link up, no lease); Confirm re-observes and
; withdraws the card if that moved. A verb on card_verbs is card-only for every
; non-OWNER ticket (card_required_for, called from command_auth_authorize;
; checklist s3.2): the AI reaches it through a confirmed card or not at all.
;
; One card at a time; BSS only (a card never survives a reboot); BSP-only like
; the rest of dispatch state. Until J2b installs card_surface_*_op nothing is
; shown and nothing can be confirmed.
;
;   CARDPROPOSE <key16hex> <VERB> <seq> <policy> <label> --[ <args>]   (args only for a text verb)
;   CARDSTAT <key16hex>        proposer or local OWNER; else the unknown bytes
;   CARDCANCEL <key16hex>      proposer or local OWNER; else the unknown bytes
;   AITAINT [CLEAR]            CLEAR: a local OWNER console line only (Q3)
; ============================================================================

CARD_ARG_MAX           equ 192            ; term 1: shown in full or refused
CARD_TOK_MAX           equ 32
CARD_ARM_US            equ 750000         ; C7: Confirm is inert for 750 ms after show/re-arm
CARD_TTL_US            equ 120000000      ; term 7: 120 s
CARD_DENY_BACKOFF_US   equ 30000000       ; C6: a proposer waits 30 s after a Deny or a cancel
CARD_EXPIRE_BACKOFF_US equ 10000000       ; C6: and 10 s after an expiry or a system cancel
CARD_DENIED_MAX        equ 16             ; C6: verb+args the owner denied this boot
CARD_KEEP_US           equ 10000000       ; C5: an ended card stays its proposer's to read for 10 s
CARD_OUT_CAP           equ 160

CS_NONE      equ 0
CS_SHOWN     equ 1
CS_CONSUMED  equ 2                        ; set BEFORE dispatch (term 6)
CS_DENIED    equ 3
CS_EXPIRED   equ 4
CS_CANCELLED equ 5
CARD_VERB_SZ           equ 8              ; card_verbs entry: dd name - card_verbs, dd rule
CARD_RULE_NONE         equ 0
CARD_RULE_NETCFG_DHCP  equ 1              ; J6: "DHCP ONCE <1-16 lowercase hex>" + NETCHECK no_lease
CARD_NONCE_MAX         equ 16

card_declare:
    mov  byte [rel card_out_ready], 0
    ; cap 0, a text argument, not destructive; each handler scopes itself (the proposer, a local OWNER)
    lea  rdi, [rel str_card_v_propose]
    lea  rsi, [rel cmd_verb_cardpropose]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_card_v_stat]
    lea  rsi, [rel cmd_verb_cardstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_card_v_cancel]
    lea  rsi, [rel cmd_verb_cardcancel]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_card_v_aitaint]
    lea  rsi, [rel cmd_verb_aitaint]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
%if PAOS_PUBLICITY_LAB_PROFILE
    lea  rdi, [rel str_card_v_probe]
    lea  rsi, [rel cmd_verb_cardprobe]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
%endif
    ret

; ---------------------------------------------------------------------------
; CARDPROPOSE
; ---------------------------------------------------------------------------
cmd_verb_cardpropose:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13, rsi
    call card_refresh
    mov  rdi, r12
    call session_shell_request_principal  ; the ticket's principal, never argument text
    mov  rbx, rax
    test rbx, rbx
    jz   .no_principal
    cmp  rbx, PRIN_ADVISOR
    je   .no_principal
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .locked                          ; P5 (G7 refuses first; this is the card's own floor)
    mov  rdi, rbx
    call ai_web_taint_of
    test eax, eax
    jnz  .tainted                         ; term 9
    call time_monotonic_now_us
    mov  rbp, rax                         ; now
    cmp  rbx, [rel card_backoff_principal]
    jne  .parse
    cmp  rbp, [rel card_backoff_until]
    jb   .backoff                         ; C6
.parse:
    call card_parse_proposal              ; -> EAX 0 ok, 1 bad_arg, 2 bad_text, 3 not_card_verb
    cmp  eax, 1
    je   .bad_arg
    cmp  eax, 2
    je   .bad_text
    cmp  eax, 3
    je   .not_card_verb
    cmp  eax, 4
    je   .too_long
    cmp  eax, 5
    je   .precondition                    ; J6: the act fits only the fault it fixes
    mov  rdi, r12
    call card_local_owner_req             ; C6: only a LOCAL owner may re-raise what was denied (rc-sec F7:
    test eax, eax                         ; a remote or SSH OWNER ticket is any other proposer)
    jnz  .denied_ok
    mov  rdi, [rel card_new_verb]
    lea  rsi, [rel card_new_args]
    mov  edx, [rel card_new_len]
    call card_fnv
    call card_denied_has
    test eax, eax
    jnz  .denied_before
.denied_ok:
    cmp  byte [rel card_state], CS_NONE
    je   .install
    cmp  rbx, [rel card_proposer]
    jne  .foreign                         ; C5: no key oracle for another proposer's card
    mov  rax, [rel card_key]
    cmp  rax, [rel card_new_key]
    jne  .other_key
    mov  rdi, rbx
    call card_same_content
    test eax, eax
    jz   .key_conflict                    ; term 5
    mov  esi, 1                           ; same key, same content: DUP=1, nothing re-shown
    jmp  .answer
.other_key:
    cmp  byte [rel card_state], CS_SHOWN
    je   .busy                            ; one card at a time
.install:
    mov  rax, [rel card_new_key]
    mov  [rel card_key], rax
    mov  [rel card_proposer], rbx
    mov  rax, [rel card_new_verb]
    mov  [rel card_verb_id], rax
    mov  rax, [rel card_new_seq]
    mov  [rel card_seq], rax
    mov  al, [rel card_new_policy]
    mov  [rel card_policy], al
    mov  al, [rel card_new_label]
    mov  [rel card_label], al
    mov  al, [rel card_new_rule]
    mov  [rel card_rule], al
    mov  ecx, [rel card_new_len]
    mov  [rel card_args_len], ecx
    lea  rsi, [rel card_new_args]
    lea  rdi, [rel card_args]
    inc  ecx                              ; with its NUL
    rep  movsb
    mov  [rel card_shown_us], rbp
    mov  [rel card_armed_us], rbp
    lea  rax, [rbp + CARD_TTL_US]
    mov  [rel card_expires_us], rax
    mov  rax, [rel session_authority_epoch]
    mov  [rel card_epoch], rax            ; a lock/rebind cancels (C8)
    mov  qword [rel card_result], 0
    mov  byte [rel card_state], CS_SHOWN
    mov  rax, [rel card_surface_show_op]
    test rax, rax
    jz   .shown
    call rax
.shown:
    xor  esi, esi
.answer:
    mov  rdi, r13
    call card_answer_state
    jmp  .out
.foreign:
    ; the same bytes for any key: busy while shown, and for CARD_KEEP_US after the
    ; card ended, so its proposer's CARDSTAT still answers (srcreview J2a F2)
    cmp  byte [rel card_state], CS_SHOWN
    je   .busy
    mov  rax, [rel card_ended_us]
    add  rax, CARD_KEEP_US
    cmp  rbp, rax
    jb   .busy
    jmp  .install
.no_principal:
    lea  rdi, [rel str_card_r_principal]
    mov  esi, CMDE_AUTHDENY
    jmp  .refuse
.locked:
    lea  rdi, [rel str_card_r_locked]
    mov  esi, CMDE_AUTHDENY
    jmp  .refuse
.tainted:
    lea  rdi, [rel str_card_r_tainted]
    mov  esi, CMDE_AUTHDENY
    jmp  .refuse
.backoff:
    lea  rdi, [rel str_card_r_backoff]
    mov  esi, CMDE_AUTHDENY
    jmp  .refuse
.bad_arg:
    lea  rdi, [rel str_card_r_bad_arg]
    mov  esi, CMDE_BADARG
    jmp  .refuse
.bad_text:
    lea  rdi, [rel str_card_r_bad_text]
    mov  esi, CMDE_BADARG
    jmp  .refuse
.not_card_verb:
    lea  rdi, [rel str_card_r_not_card_verb]
    mov  esi, CMDE_BADARG
    jmp  .refuse
.too_long:
    lea  rdi, [rel str_card_r_too_long]
    mov  esi, CMDE_BADARG
    jmp  .refuse
.precondition:
    lea  rdi, [rel str_card_r_precondition]
    mov  esi, CMDE_AUTHDENY
    jmp  .refuse
.denied_before:
    lea  rdi, [rel str_card_r_denied_before]
    mov  esi, CMDE_AUTHDENY
    jmp  .refuse
.key_conflict:
    lea  rdi, [rel str_card_r_key_conflict]
    mov  esi, CMDE_BADARG
    jmp  .refuse
.busy:
    lea  rdi, [rel str_card_r_busy]
    mov  esi, CMDE_AUTHDENY
.refuse:
    mov  rdx, r13
    call card_answer_refused
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; CARDSTAT / CARDCANCEL: by key, for the proposer or a local OWNER only (C5).
; Everyone else gets exactly the bytes an unknown key gets.
; ---------------------------------------------------------------------------
cmd_verb_cardstat:
    xor  eax, eax
    jmp  card_keyed_verb
cmd_verb_cardcancel:
    mov  eax, 1
    jmp  card_keyed_verb                  ; explicit, so a call-graph census reaches the scope gate
card_keyed_verb:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  ebx, eax                         ; 1 = cancel
    mov  r12, rdi
    mov  r13, rsi
    call card_refresh
    mov  rsi, [r12 + REQ_ARG]
    test rsi, rsi
    jz   .bad
    call card_parse_hex16
    test edx, edx
    jnz  .bad
    cmp  byte [rsi], 0
    jne  .bad
    mov  [rel card_q_key], rax
    mov  rdi, r12
    call session_shell_request_principal
    cmp  rax, PRIN_ADVISOR
    je   .advisor                         ; refused, as everywhere (C5)
    cmp  byte [rel card_state], CS_NONE
    je   .unknown
    mov  rax, [rel card_q_key]
    cmp  rax, [rel card_key]
    jne  .unknown
    mov  rdi, r12
    call card_scope_ok
    test eax, eax
    jz   .unknown
    test ebx, ebx
    jz   .answer
    cmp  byte [rel card_state], CS_SHOWN
    jne  .answer
    mov  byte [rel card_state], CS_CANCELLED   ; term 7: the proposer (AI included) or the owner
    mov  edi, CARD_DENY_BACKOFF_US        ; rc-sec F3 (a): a withdrawn card is a fatigue cycle, as a Deny
    call card_end_with_backoff
    call card_surface_close
.answer:
    mov  rdi, r13
    xor  esi, esi
    call card_answer_state
    jmp  .out
.unknown:
    mov  rdi, r13
    call card_answer_unknown
    jmp  .out
.advisor:
    lea  rdi, [rel str_card_r_principal]
    mov  esi, CMDE_AUTHDENY
    mov  rdx, r13
    call card_answer_refused
    jmp  .out
.bad:
    lea  rdi, [rel str_card_r_bad_arg]
    mov  esi, CMDE_BADARG
    mov  rdx, r13
    call card_answer_refused
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; card_scope_ok(RDI = req) -> EAX 1 when the frame's principal proposed the card or is a bound local OWNER.
card_scope_ok:
    call session_shell_request_principal
    cmp  rax, [rel card_proposer]
    je   .yes
    cmp  rax, PRIN_OWNER
    jne  .no
    call session_shell_local_authority    ; local, unlocked, bound, keyed, not injected
    test rax, rax
    jz   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; AITAINT [CLEAR] (rc-sec Q3): the taint clears only on reboot or by a local
; OWNER console line: local authority (refuses remote, aihook, injected,
; locked), console source (never a card or HOOK re-dispatch), depth 1.
; ---------------------------------------------------------------------------
cmd_verb_aitaint:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .status
    cmp  byte [rbx], 0
    je   .status
    mov  rdi, rbx
    lea  rsi, [rel str_card_w_clear]
    call strcmp
    test eax, eax
    jnz  .bad
    mov  rdi, r12
    call card_local_owner_req
    test eax, eax
    jz   .refused
    mov  qword [rel ai_web_taint_mask], 0
    mov  byte [rel ai_web_taint_overflow], 0   ; web-taint-cap (SEC 121686, track B L67): the owner clear ends the >= 64 taint too
    lea  rdi, [rel str_card_taint_cleared_serial]
    call serial_string
    call card_out_reset
    lea  rdi, [rel str_card_taint_cleared]
    call card_out_str
    jmp  .ok
.status:
    call card_out_reset
    lea  rdi, [rel str_card_taint_mask]
    call card_out_str
    mov  rdi, [rel ai_web_taint_mask]
    call card_out_hex16
    cmp  byte [rel ai_web_taint_overflow], 0
    je   .ok
    lea  rdi, [rel str_card_taint_overflow]   ; web-taint-cap: shown only while set (the MASK= line is pinned)
    call card_out_str
.ok:
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  rax, [rel ai_web_taint_mask]
    mov  [r13 + RSP_VAL], rax
    mov  byte [rel card_out_ready], 1
    jmp  .out
.refused:
    lea  rdi, [rel str_card_r_local_owner]
    mov  esi, CMDE_AUTHDENY
    mov  rdx, r13
    call card_answer_refused
    jmp  .out
.bad:
    lea  rdi, [rel str_card_r_bad_arg]
    mov  esi, CMDE_BADARG
    mov  rdx, r13
    call card_answer_refused
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; card_local_owner_req(RDI = req) -> EAX 1 for a local OWNER console line (rc-sec Q3; F7 for the C6 exemption):
; console source (never a card or HOOK re-dispatch), depth 1, the OWNER principal, and local authority (refuses
; remote, aihook, injected, locked, unbound).
card_local_owner_req:
    push rbx
    mov  rbx, rdi
    cmp  qword [rbx + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .no
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .no
    call session_shell_request_principal  ; RDI = req
    cmp  rax, PRIN_OWNER
    jne  .no
    call session_shell_local_authority
    test rax, rax
    jz   .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

%if PAOS_PUBLICITY_LAB_PROFILE
; CARDPROBE (lab floor only, rc-sec Q4): a leaf; one fixed serial line, no state.
cmd_verb_cardprobe:
    call cmd_handler_prologue
    push rsi
    lea  rdi, [rel str_card_probe_serial]
    call serial_string
    call card_out_reset
    lea  rdi, [rel str_card_probe_ok]
    call card_out_str
    mov  byte [rel card_out_ready], 1
    pop  rsi
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
%endif

; ---------------------------------------------------------------------------
; The surface's entry points (J2b calls these; J2a has no surface).
; ---------------------------------------------------------------------------

; card_confirm(RDI = local pid, RSI = authority token) -> EAX 0 dispatched, 1 withdrawn (J6: the
;   rule's facts moved; a system cancel, the surface closed), -1 refused.
;   The caller (the card surface) has already required a HUMAN event with the
;   owner's own focus on Confirm (C1) or an armed physical press. Here: the
;   card is shown, the arm delay has passed (C7), the surface says Confirm is
;   still unobscured and on top (C8), and the local-authority snapshot taken at
;   the event still holds right now. The state is consumed BEFORE dispatch, so
;   a second Confirm or a re-entry finds it used (term 6).
card_confirm:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call card_refresh
    cmp  dword [rel cmd_dispatch_depth], 0
    jne  .refuse                          ; an input event, never inside a dispatch
    cmp  r12, PRIN_OWNER
    jne  .refuse                          ; a bound local OWNER only
    cmp  byte [rel card_state], CS_SHOWN
    jne  .refuse
    call time_monotonic_now_us
    mov  rcx, [rel card_armed_us]
    add  rcx, CARD_ARM_US
    cmp  rax, rcx
    jb   .refuse
    mov  rax, [rel card_surface_ok_op]
    test rax, rax
    jz   .refuse                          ; no surface, no Confirm
    call rax
    test eax, eax
    jnz  .refuse
    cmp  byte [rel card_state], CS_SHOWN
    jne  .refuse                          ; the surface's answer cannot have ended the card (srcreview F5)
    call session_shell_local_authority
    test rax, rax
    jz   .refuse
    cmp  rax, r12
    jne  .refuse
    cmp  rdx, r13
    jne  .refuse
    movzx edi, byte [rel card_rule]       ; J6: re-observe; the facts the card was raised on must still hold
    lea  rsi, [rel card_args]
    call card_rule_check
    test eax, eax
    jnz  .withdrawn
    mov  byte [rel card_state], CS_CONSUMED
    call card_mark_ended
    ; the request: by id, with a private copy of the shown text (C3: never re-tokenized)
    mov  ecx, [rel card_args_len]
    inc  ecx
    lea  rsi, [rel card_args]
    lea  rdi, [rel card_req_args]
    rep  movsb
    lea  rbx, [rel card_req]
    mov  rax, [rel card_verb_id]
    mov  [rbx + REQ_VERB], rax
    mov  qword [rbx + REQ_CAP], 0
    mov  rax, [rel card_key]
    mov  [rbx + REQ_IDEM], rax            ; the card key is the request key
    mov  qword [rbx + REQ_SEL], 0
    mov  rdi, [rel card_verb_id]
    call command_verb_argt
    xor  ecx, ecx
    cmp  eax, ARGT_TEXT
    jne  .arg
    lea  rcx, [rel card_req_args]
.arg:
    mov  [rbx + REQ_ARG], rcx
    mov  qword [rbx + REQ_SOURCE], CMD_SOURCE_CARD   ; C4: never CONSOLE
    mov  [rbx + REQ_PRINCIPAL], r12
    mov  rdi, rbx
    lea  rsi, [rel card_rsp]
    mov  rdx, [rel card_proposer]
    call command_dispatch_card
    mov  [rel card_result], rax
    call card_audit_confirm
    call card_surface_close
    xor  eax, eax
    jmp  .out
.withdrawn:
    call card_cancel                      ; a system cancel: the 10 s backoff, no denied_before (F3 b)
    mov  eax, 1
    jmp  .out
.refuse:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; card_deny: the owner's Deny. C6: the proposer backs off 30 s and this verb+args stays refused this boot.
card_deny:
    call card_refresh
    cmp  byte [rel card_state], CS_SHOWN
    jne  .out
    mov  byte [rel card_state], CS_DENIED
    call time_monotonic_now_us
    mov  [rel card_ended_us], rax
    add  rax, CARD_DENY_BACKOFF_US
    call card_backoff_set
    mov  rdi, [rel card_verb_id]
    lea  rsi, [rel card_args]
    mov  edx, [rel card_args_len]
    call card_fnv
    mov  ecx, [rel card_denied_n]
    and  ecx, CARD_DENIED_MAX - 1
    lea  rdx, [rel card_denied]
    mov  [rdx + rcx*8], rax
    inc  dword [rel card_denied_n]
    call card_surface_close
.out:
    ret

; card_rearm: C7: a rebuild, move, first unobscured paint or a new top window over Confirm restarts the delay.
card_rearm:
    cmp  byte [rel card_state], CS_SHOWN
    jne  .out
    call time_monotonic_now_us
    mov  [rel card_armed_us], rax
.out:
    ret

card_tick:
    jmp  card_refresh

; card_cancel: C8: a no_fit resolution change or a Safe/diagnostic profile entry ends a shown card (never revived).
card_cancel:
    cmp  byte [rel card_state], CS_SHOWN
    jne  .out
    mov  byte [rel card_state], CS_CANCELLED
    mov  edi, CARD_EXPIRE_BACKOFF_US      ; rc-sec F3 (b): no_fit/Safe is a system cancel, as an expiry
    call card_end_with_backoff
    jmp  card_surface_close
.out:
    ret

; command_dispatch_card(RDI = req, RSI = rsp, RDX = proposer) -> RAX = RSP_CODE.
;   THE one non-zero writer of cmd_card_proposer_arm (rc-sec 02:40:43 (3)); its
;   one caller is card_confirm. The depth-0 dispatch takes the arm into
;   cmd_dispatch_proposer and zeroes both on every exit; this clears again
;   after a refusal before the registry (the session gate).
command_dispatch_card:
    sub  rsp, 8
    mov  [rel cmd_card_proposer_arm], rdx
    call command_dispatch
    mov  qword [rel cmd_card_proposer_arm], 0
    mov  qword [rel cmd_dispatch_proposer], 0
    add  rsp, 8
    ret

; ---------------------------------------------------------------------------
; Web taint (term 9, rc-sec W1/Q3): one bit per principal. The planned RCQ-39
; Installed ADVISEFILE marks ADVISOR before reading untrusted VFS bytes.
; RCQ-39 S2 browser WEBDIGEST handover is still unimplemented and must do so too.
; CARDPROPOSE and effectful HOOK SET/INPUT/CANCEL refuse while the bit is set.
; web-taint-cap (SEC 121686 CALL 18fe1093; track B L67; SR-58 H4): a principal >= 64 has no
; bit. A set for one raises the sticky ai_web_taint_overflow flag, and of() for
; ANY principal >= 64 answers that flag: fail closed, never a silently dropped
; set. Principals below 64 keep their exact bit. Only the local-owner AITAINT
; CLEAR lowers the flag (with the mask).
; ---------------------------------------------------------------------------
ai_web_taint_set:                         ; RDI = principal
    cmp  rdi, 64
    jae  .overflow
    bts  qword [rel ai_web_taint_mask], rdi
    ret
.overflow:
    mov  byte [rel ai_web_taint_overflow], 1
    ret

ai_web_taint_of:                          ; RDI = principal -> EAX 1 tainted
    xor  eax, eax
    cmp  rdi, 64
    jae  .overflow
    bt   qword [rel ai_web_taint_mask], rdi
    setc al
    ret
.overflow:
    cmp  byte [rel ai_web_taint_overflow], 0
    setne al
    ret

; ---------------------------------------------------------------------------
; internals
; ---------------------------------------------------------------------------

; card_refresh: a shown card ends on a lock/rebind (epoch) or at its expiry.
card_refresh:
    cmp  byte [rel card_state], CS_SHOWN
    jne  .out
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel card_epoch]
    jne  .cancel
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .cancel
    call time_monotonic_now_us
    cmp  rax, [rel card_expires_us]
    jb   .out
    mov  byte [rel card_state], CS_EXPIRED
    mov  [rel card_ended_us], rax
    add  rax, CARD_EXPIRE_BACKOFF_US
    call card_backoff_set
    jmp  card_surface_close
.cancel:
    mov  byte [rel card_state], CS_CANCELLED   ; never hidden and revived (FA2-lock)
    mov  edi, CARD_EXPIRE_BACKOFF_US      ; rc-sec F3 (b): the AI cannot ride the lock edge
    call card_end_with_backoff
    jmp  card_surface_close
.out:
    ret

; card_mark_ended: the card left SHOWN now. Keeps every caller-saved register, so a
; transition site needs nothing around it.
card_mark_ended:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call time_monotonic_now_us
    mov  [rel card_ended_us], rax
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; card_end_with_backoff(EDI = backoff us): the card ended now; its proposer waits that long (C6). A cancel never
; enters denied_before (rc-sec F3 (c)): only the owner's Deny does.
card_end_with_backoff:
    push rdi
    call time_monotonic_now_us
    pop  rdi
    mov  [rel card_ended_us], rax
    add  rax, rdi
    jmp  card_backoff_set

card_backoff_set:                         ; RAX = until (us), for the card's proposer
    mov  [rel card_backoff_until], rax
    mov  rax, [rel card_proposer]
    mov  [rel card_backoff_principal], rax
    ret

card_surface_close:
    mov  rax, [rel card_surface_close_op]
    test rax, rax
    jz   .out
    jmp  rax
.out:
    ret

; card_same_content(RDI = principal) -> EAX 1 when the parsed proposal equals the record.
card_same_content:
    xor  eax, eax
    cmp  rdi, [rel card_proposer]
    jne  .out
    mov  rcx, [rel card_new_verb]
    cmp  rcx, [rel card_verb_id]
    jne  .out
    mov  rcx, [rel card_new_seq]
    cmp  rcx, [rel card_seq]
    jne  .out
    mov  cl, [rel card_new_policy]
    cmp  cl, [rel card_policy]
    jne  .out
    mov  cl, [rel card_new_label]
    cmp  cl, [rel card_label]
    jne  .out
    mov  ecx, [rel card_new_len]
    cmp  ecx, [rel card_args_len]
    jne  .out
    lea  rsi, [rel card_new_args]
    lea  rdi, [rel card_args]
    repe cmpsb
    jne  .out
    mov  eax, 1
.out:
    ret

; card_fnv(RDI = verb id, RSI = args, EDX = len) -> RAX = FNV-1a 64 over the id's 8 bytes then the args.
card_fnv:
    mov  rax, 0xcbf29ce484222325
    mov  r8, 0x100000001b3
    mov  r9d, edx
    mov  ecx, 8
.id:
    xor  al, dil
    imul rax, r8
    shr  rdi, 8
    dec  ecx
    jnz  .id
    test r9d, r9d
    jz   .out
.arg:
    xor  al, [rsi]
    imul rax, r8
    inc  rsi
    dec  r9d
    jnz  .arg
.out:
    ret

card_denied_has:                          ; RAX = hash -> EAX 1 when denied this boot
    mov  ecx, [rel card_denied_n]
    cmp  ecx, CARD_DENIED_MAX
    jbe  .scan
    mov  ecx, CARD_DENIED_MAX
.scan:
    lea  rdx, [rel card_denied]
.next:
    test ecx, ecx
    jz   .no
    dec  ecx
    cmp  rax, [rdx + rcx*8]
    jne  .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; card_parse_proposal: [r12 + REQ_ARG] -> card_new_*. EAX 0 ok, 1 bad_arg, 2 bad_text, 3 not_card_verb, 4 too_long.
card_parse_proposal:
    push rbx
    mov  rsi, [r12 + REQ_ARG]
    test rsi, rsi
    jz   .bad_arg
    call card_parse_hex16
    test edx, edx
    jnz  .bad_arg
    test rax, rax
    jz   .bad_arg
    mov  [rel card_new_key], rax
    call card_sep
    jnz  .bad_arg
    ; VERB: [A-Z0-9_]{1,31}
    lea  rdi, [rel card_tok]
    xor  ecx, ecx
.tok:
    movzx eax, byte [rsi]
    cmp  al, '_'
    je   .tok_ch
    cmp  al, '0'
    jb   .tok_end
    cmp  al, '9'
    jbe  .tok_ch
    cmp  al, 'A'
    jb   .tok_end
    cmp  al, 'Z'
    ja   .tok_end
.tok_ch:
    cmp  ecx, CARD_TOK_MAX - 1
    jae  .bad_arg
    mov  [rdi + rcx], al
    inc  ecx
    inc  rsi
    jmp  .tok
.tok_end:
    test ecx, ecx
    jz   .bad_arg
    mov  byte [rdi + rcx], 0
    call card_sep
    jnz  .bad_arg
    mov  rbx, rsi
    lea  rdi, [rel card_tok]
    call card_verb_find                   ; card_tok on card_verbs?
    test rax, rax
    jz   .not_card_verb
    mov  eax, [rax + 4]
    mov  [rel card_new_rule], al
    lea  rdi, [rel card_tok]
    call command_lookup
    cmp  rax, -1
    je   .not_card_verb
    mov  [rel card_new_verb], rax
    mov  rsi, rbx
    call card_parse_dec
    test edx, edx
    jnz  .bad_arg
    mov  [rel card_new_seq], rax
    call card_sep
    jnz  .bad_arg
    lea  rdi, [rel str_card_policies]
    call card_parse_word
    test edx, edx
    jnz  .bad_arg
    mov  [rel card_new_policy], al
    call card_sep
    jnz  .bad_arg
    lea  rdi, [rel str_card_labels]
    call card_parse_word
    test edx, edx
    jnz  .bad_arg
    mov  [rel card_new_label], al
    call card_sep
    jnz  .bad_arg
    cmp  word [rsi], '--'
    jne  .bad_arg
    add  rsi, 2
    lea  rdi, [rel card_new_args]
    xor  ecx, ecx
    xor  edx, edx                         ; previous byte was a space
    cmp  byte [rsi], 0
    je   .arg_end                         ; no argument text
    cmp  byte [rsi], ' '
    jne  .bad_arg
    inc  rsi                              ; one separator; a second space is the text's leading space (bad_text)
    cmp  byte [rsi], 0
    je   .bad_text                        ; "-- " then nothing: a trailing space
    ; args: printable ASCII, 1..192 B, no leading/trailing space, no run of spaces (C2)
.arg:
    movzx eax, byte [rsi + rcx]
    test eax, eax
    jz   .arg_end
    cmp  ecx, CARD_ARG_MAX
    jae  .too_long                        ; refused whole, never truncated
    cmp  al, 0x20
    jb   .bad_text
    cmp  al, 0x7e
    ja   .bad_text
    cmp  al, ' '
    jne  .arg_ch
    test ecx, ecx
    jz   .bad_text                        ; leading space
    test edx, edx
    jnz  .bad_text                        ; a run of spaces
.arg_ch:
    xor  edx, edx
    cmp  al, ' '
    sete dl
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .arg
.arg_end:
    test edx, edx
    jnz  .bad_text                        ; trailing space
    mov  byte [rdi + rcx], 0
    mov  [rel card_new_len], ecx
    ; the card dispatches what it shows (C3): a no-argument verb shows none, a text verb shows its whole argument
    mov  rdi, [rel card_new_verb]
    call command_verb_argt
    cmp  eax, ARGT_NONE
    je   .want_none
    cmp  eax, ARGT_TEXT
    jne  .not_card_verb
    cmp  dword [rel card_new_len], 0
    je   .bad_text
    jmp  .parsed
.want_none:
    cmp  dword [rel card_new_len], 0
    jne  .bad_arg
.parsed:
    movzx edi, byte [rel card_new_rule]
    lea  rsi, [rel card_new_args]
    call card_rule_check                  ; 0, 1 bad_arg or 5 precondition
    pop  rbx
    ret
.bad_arg:
    mov  eax, 1
    pop  rbx
    ret
.bad_text:
    mov  eax, 2
    pop  rbx
    ret
.not_card_verb:
    mov  eax, 3
    pop  rbx
    ret
.too_long:
    mov  eax, 4
    pop  rbx
    ret

card_sep:                                 ; exactly one ' ' at RSI; ZF set when present (RSI advanced)
    cmp  byte [rsi], ' '
    jne  .out
    inc  rsi
    cmp  byte [rsi], ' '
    je   .two
    cmp  al, al
.out:
    ret
.two:
    cmp  rsi, 0                           ; ZF clear (RSI is never 0 here)
    ret

; card_verb_find(RDI = verb name) -> RAX = its card_verbs entry, or 0.
card_verb_find:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    lea  rbx, [rel card_verbs]
.next:
    movsxd rsi, dword [rbx]
    test rsi, rsi
    jz   .no
    lea  rdi, [rel card_verbs]
    add  rsi, rdi
    mov  rdi, r12
    call strcmp
    test eax, eax
    jz   .yes
    add  rbx, CARD_VERB_SZ
    jmp  .next
.yes:
    mov  rax, rbx
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; card_required_for(RDI = ticket principal, RSI = verb name) -> EAX 1 when a
;   non-OWNER ticket asks for a verb a card carries (J6, checklist s3.2). The
;   card's own request is not a ticket (source CARD, the local OWNER), so a card
;   verb runs for anyone but the owner only through a confirmed card.
card_required_for:
    xor  eax, eax
    cmp  rdi, PRIN_OWNER
    je   .out
    sub  rsp, 8
    mov  rdi, rsi
    call card_verb_find
    add  rsp, 8
    test rax, rax
    setnz al
    movzx eax, al
.out:
    ret

; card_rule_check(EDI = rule, RSI = args) -> EAX 0 ok, 1 bad_arg, 5 precondition.
;   Run at propose, and again at Confirm (any nonzero there withdraws the card).
;   Command context only (rc-live's J3 contract): NETCHECK's collect takes the
;   DNS state lock, so never from an IRQ or under a dns_wire/netdev lock. The
;   Confirm caller (J2b's surface) inherits that rule.
card_rule_check:
    xor  eax, eax
    cmp  edi, CARD_RULE_NETCFG_DHCP
    je   card_rule_netcfg_dhcp
    ret

; card_rule_netcfg_dhcp(RSI = args): exactly "DHCP ONCE " + 1..16 lowercase hex
;   (the nonce NETCFG's hp_pfx form needs; STATIC, MEMBERS and any other form
;   are refused), and NETCHECK's own read-only classify says no_lease now.
card_rule_netcfg_dhcp:
    lea  rdi, [rel str_card_netcfg_dhcp]
.pfx:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .nonce
    cmp  al, [rsi]
    jne  .bad
    inc  rdi
    inc  rsi
    jmp  .pfx
.nonce:
    xor  ecx, ecx
.hex:
    movzx eax, byte [rsi + rcx]
    test eax, eax
    jz   .hex_end
    cmp  ecx, CARD_NONCE_MAX
    jae  .bad
    sub  eax, '0'
    cmp  eax, 9
    jbe  .hex_ok
    movzx eax, byte [rsi + rcx]
    sub  eax, 'a'
    cmp  eax, 5
    ja   .bad
.hex_ok:
    inc  ecx
    jmp  .hex
.hex_end:
    test ecx, ecx
    jz   .bad
    sub  rsp, 8
    call netcheck_collect                 ; read-only facts (no frame, lookup or driver call)
    call netcheck_classify
    add  rsp, 8
    cmp  byte [rel nc_check], NC_NO_LEASE
    jne  .pre
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret
.pre:
    mov  eax, 5
    ret

; card_parse_hex16(RSI) -> RAX value, EDX 0 ok; exactly 16 hex digits then ' ' or NUL. RSI advanced.
card_parse_hex16:
    xor  eax, eax
    mov  ecx, 16
.d:
    movzx edx, byte [rsi]
    sub  edx, '0'
    cmp  edx, 9
    jbe  .v
    movzx edx, byte [rsi]
    or   edx, 0x20
    sub  edx, 'a'
    cmp  edx, 5
    ja   .bad
    add  edx, 10
.v:
    shl  rax, 4
    or   rax, rdx
    inc  rsi
    dec  ecx
    jnz  .d
    cmp  byte [rsi], ' '
    je   .ok
    cmp  byte [rsi], 0
    jne  .bad
.ok:
    xor  edx, edx
    ret
.bad:
    mov  edx, -1
    ret

; card_parse_dec(RSI) -> RAX, EDX 0 ok; 1..20 digits without overflow, then ' ' or NUL. RSI advanced.
card_parse_dec:
    xor  eax, eax
    xor  ecx, ecx
.d:
    movzx edx, byte [rsi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .end
    mov  r8, 10
    push rdx
    mul  r8
    pop  rdx
    jc   .bad
    add  rax, rdx
    jc   .bad
    inc  rsi
    inc  ecx
    jmp  .d
.end:
    test ecx, ecx
    jz   .bad
    cmp  byte [rsi], ' '
    je   .ok
    cmp  byte [rsi], 0
    jne  .bad
.ok:
    xor  edx, edx
    ret
.bad:
    mov  edx, -1
    ret

; card_parse_word(RSI, RDI = NUL-separated words ending in an empty word) -> AL index, EDX 0 ok. RSI advanced.
card_parse_word:
    xor  ecx, ecx
.word:
    cmp  byte [rdi], 0
    je   .bad
    xor  r8d, r8d
.cmp:
    mov  al, [rdi + r8]
    test al, al
    jz   .word_end
    cmp  al, [rsi + r8]
    jne  .skip
    inc  r8d
    jmp  .cmp
.word_end:
    mov  al, [rsi + r8]
    cmp  al, ' '
    je   .hit
    test al, al
    jz   .hit
.skip:
    cmp  byte [rdi], 0
    lea  rdi, [rdi + 1]
    jne  .skip
    inc  ecx
    jmp  .word
.hit:
    add  rsi, r8
    mov  eax, ecx
    xor  edx, edx
    ret
.bad:
    mov  edx, -1
    ret

; replies ---------------------------------------------------------------------

card_answer_state:                        ; RDI = rsp, ESI = 1 for DUP -> "CARD KEY=<k> STATE=<s>[ DUP=1][ RESULT=<n>]"
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12d, esi
    call card_out_reset
    lea  rdi, [rel str_card_key]
    call card_out_str
    mov  rdi, [rel card_key]
    call card_out_hex16
    lea  rdi, [rel str_card_state]
    call card_out_str
    movzx eax, byte [rel card_state]
    lea  rdx, [rel card_state_words]
    movsxd rdi, dword [rdx + rax*4]
    add  rdi, rdx
    call card_out_str
    test r12d, r12d
    jz   .nodup
    lea  rdi, [rel str_card_dup]
    call card_out_str
.nodup:
    cmp  byte [rel card_state], CS_CONSUMED
    jne  .done
    lea  rdi, [rel str_card_result]
    call card_out_str
    mov  rdi, [rel card_result]
    call card_out_dec
.done:
    mov  qword [rbx + RSP_CODE], CMDE_OK
    movzx eax, byte [rel card_state]
    mov  [rbx + RSP_VAL], rax
    mov  byte [rel card_out_ready], 1
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

card_answer_unknown:                      ; RDI = rsp; the bytes for an unknown key and for another principal
    push rbx
    mov  rbx, rdi
    call card_out_reset
    lea  rdi, [rel str_card_key]
    call card_out_str
    mov  rdi, [rel card_q_key]
    call card_out_hex16
    lea  rdi, [rel str_card_unknown]
    call card_out_str
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  qword [rbx + RSP_VAL], 0
    mov  byte [rel card_out_ready], 1
    pop  rbx
    ret

card_answer_refused:                      ; RDI = reason, ESI = code, RDX = rsp
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    call card_out_reset
    lea  rdi, [rel str_card_refused]
    call card_out_str
    mov  rdi, rbx
    call card_out_str
    mov  [r13 + RSP_CODE], r12
    mov  [r13 + RSP_HINT], rbx
    mov  qword [r13 + RSP_VAL], 0
    mov  byte [rel card_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

; audit (C4): src=card proposer=<n> confirmed_by=local_owner, one serial line per Confirm.
card_audit_confirm:
    call card_out_reset
    lea  rdi, [rel str_card_audit]
    call card_out_str
    mov  rdi, [rel card_key]
    call card_out_hex16
    lea  rdi, [rel str_card_audit_verb]
    call card_out_str
    mov  rdi, [rel card_verb_id]
    call command_verb_name
    mov  rdi, rax
    call card_out_str
    lea  rdi, [rel str_card_audit_prop]
    call card_out_str
    mov  rdi, [rel card_proposer]
    call card_out_dec
    lea  rdi, [rel str_card_audit_tail]
    call card_out_str
    mov  rdi, [rel card_result]
    call card_out_dec
    lea  rdi, [rel str_card_crlf]
    call card_out_str
    lea  rdi, [rel card_out_buf]
    call serial_string
    mov  byte [rel card_out_ready], 0     ; the audit line is not a reply
    ret

card_out_reset:
    lea  rax, [rel card_out_buf]
    mov  [rel card_out_cur], rax
    mov  byte [rax], 0
    ret

card_out_str:                             ; RDI = cstr, bounded to the buffer
    mov  rsi, [rel card_out_cur]
    lea  rdx, [rel card_out_buf + CARD_OUT_CAP - 1]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rdx
    jae  .done
    mov  [rsi], al
    inc  rdi
    inc  rsi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel card_out_cur], rsi
    ret

card_out_hex16:                           ; RDI = value, 16 lowercase hex digits
    lea  rsi, [rel card_numbuf]
    mov  ecx, 16
.d:
    mov  eax, edi
    and  eax, 15
    lea  rdx, [rel str_card_hex]
    mov  al, [rdx + rax]
    mov  [rsi + rcx - 1], al
    shr  rdi, 4
    dec  ecx
    jnz  .d
    mov  byte [rsi + 16], 0
    mov  rdi, rsi
    jmp  card_out_str

card_out_dec:                             ; RDI = unsigned value
    lea  rsi, [rel card_numbuf + 23]
    mov  byte [rsi], 0
    mov  rax, rdi
    mov  r8, 10
.d:
    xor  edx, edx
    div  r8
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test rax, rax
    jnz  .d
    mov  rdi, rsi
    jmp  card_out_str

; data -------------------------------------------------------------------------
str_card_v_propose:     db "CARDPROPOSE",0
str_card_v_stat:        db "CARDSTAT",0
str_card_v_cancel:      db "CARDCANCEL",0
str_card_v_aitaint:     db "AITAINT",0
str_card_w_clear:       db "CLEAR",0
str_card_policies:      db "none",0,"refuse",0,"keepboth",0,"overwrite",0,0
str_card_labels:        db "none",0,"local",0,"cloud",0,0
str_card_key:           db "CARD KEY=",0
str_card_state:         db " STATE=",0
str_card_dup:           db " DUP=1",0
str_card_result:        db " RESULT=",0
str_card_unknown:       db " STATE=unknown",0
str_card_refused:       db "CARD REFUSED ",0
str_card_r_principal:   db "principal",0
str_card_r_locked:      db "locked",0
str_card_r_tainted:     db "refused:web_tainted",0
str_card_r_backoff:     db "backoff",0
str_card_r_bad_arg:     db "bad_arg",0
str_card_r_bad_text:    db "bad_text",0
str_card_r_not_card_verb: db "not_card_verb",0
str_card_r_too_long:    db "too_long",0
str_card_r_denied_before: db "denied_before",0
str_card_r_key_conflict: db "key_conflict",0
str_card_r_busy:        db "busy",0
str_card_r_precondition: db "precondition",0
str_card_v_netcfg:      db "NETCFG",0
str_card_netcfg_dhcp:   db "DHCP ONCE ",0
str_card_r_local_owner: db "local_owner_only",0
str_card_taint_mask:    db "AITAINT MASK=",0
str_card_taint_cleared: db "AITAINT CLEARED",0
str_card_taint_overflow: db " OVERFLOW=1",0
str_card_taint_cleared_serial: db "[PAOS64] aitaint.clear by=local_owner [card.taint.clear]",13,10,0
str_card_audit:         db "[PAOS64] card.confirm key=",0
str_card_audit_verb:    db " verb=",0
str_card_audit_prop:    db " src=card proposer=",0
str_card_audit_tail:    db " confirmed_by=local_owner result=",0
str_card_crlf:          db 13,10,0
str_card_hex:           db "0123456789abcdef"
str_card_w_none:        db "none",0
str_card_w_shown:       db "shown",0
str_card_w_consumed:    db "consumed",0
str_card_w_denied:      db "denied",0
str_card_w_expired:     db "expired",0
str_card_w_cancelled:   db "cancelled",0
%if PAOS_PUBLICITY_LAB_PROFILE
str_card_v_probe:       db "CARDPROBE",0
str_card_probe_ok:      db "CARDPROBE OK",0
str_card_probe_serial:  db "[PAOS64] cardprobe ran [card.probe]",13,10,0
%endif
; rel32 from each table (org 0 image: no absolute pointers; srcreview J2a F1)
align 4
card_state_words:       dd str_card_w_none - card_state_words, str_card_w_shown - card_state_words
                        dd str_card_w_consumed - card_state_words, str_card_w_denied - card_state_words
                        dd str_card_w_expired - card_state_words, str_card_w_cancelled - card_state_words
; The verbs a card may carry: LEAF verbs only (C3), each {name, rule}; a name of 0 ends the table.
; Every entry is card-only for a non-OWNER ticket (card_required_for).
card_verbs:
                        dd str_card_v_netcfg - card_verbs, CARD_RULE_NETCFG_DHCP   ; J6
%if PAOS_PUBLICITY_LAB_PROFILE
                        dd str_card_v_probe - card_verbs, CARD_RULE_NONE
%endif
                        dd 0
align 8
; The surface (J2b) installs these; 0 = no surface, so nothing is shown or confirmed.
card_surface_show_op:   dq 0
card_surface_close_op:  dq 0
card_surface_ok_op:     dq 0               ; -> EAX 0 when Confirm is unobscured and the card is on top (C8)

%include "core/abi/wdata.inc"
%macro WDATA_svc_command_card_0 0
alignb 8
card_key:               resq 1
card_proposer:          resq 1
card_verb_id:           resq 1
card_seq:               resq 1
card_shown_us:          resq 1
card_armed_us:          resq 1
card_expires_us:        resq 1
card_epoch:             resq 1
card_result:            resq 1
card_ended_us:          resq 1
card_backoff_until:     resq 1
card_backoff_principal: resq 1
card_q_key:             resq 1
card_new_key:           resq 1
card_new_verb:          resq 1
card_new_seq:           resq 1
card_out_cur:           resq 1
ai_web_taint_mask:      resq 1
card_denied:            resq CARD_DENIED_MAX
card_req:               resb REQ_SZ
card_rsp:               resb RSP_SZ
card_args_len:          resd 1
card_new_len:           resd 1
card_denied_n:          resd 1
card_state:             resb 1
card_policy:            resb 1
card_label:             resb 1
card_new_policy:        resb 1
card_new_label:         resb 1
card_rule:              resb 1
card_new_rule:          resb 1
card_out_ready:         resb 1
ai_web_taint_overflow:  resb 1           ; web-taint-cap: sticky taint for principals >= 64
card_tok:               resb CARD_TOK_MAX
card_numbuf:            resb 24
card_args:              resb CARD_ARG_MAX + 1
card_new_args:          resb CARD_ARG_MAX + 1
card_req_args:          resb CARD_ARG_MAX + 1
card_out_buf:           resb CARD_OUT_CAP
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_card_0
