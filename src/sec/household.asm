;; MODULE sec/household
;; LAYER 5
;; PURPOSE Household voice principal: owner marks, one admitted request, the one household dispatch path.
;; EXPORTS household_declare, household_submit, household_step, household_dispatch, household_retire, household_generation
;; IMPORTS boot/serial, core/lib/fmt, core/lib/sha256, core/lib/str, sec/keyprov, sec/session, svc/command, svc/command_audit, svc/command_auth
;; CAPS
;; OWNER saga:sec
; ============================================================================
; sec/household.asm -- RC-ssh-and-household-voice-locked-20261017 (root work
; order 15:37:25 item 2b). Design HOUSEHOLD_ABI_DESIGN.md with addendum r2
; (rc-sec guardian-floor-20261017 evidence; rc-ai DESIGN_RESPONSE 45fc5894).
;
; The household voice user is principal 5 (PRIN_HOUSEHOLD). It has no row in
; principal_cap_table, so principal_capabilities gives it the empty word, as
; for Try. It never holds an owner, SYSTEM or caller ticket: its one request
; runs as CMD_SOURCE_HOUSEHOLD / PRIN_HOUSEHOLD through household_dispatch,
; inside a remote frame with no ticket (command_auth_remote_begin(0), as the AI
; hook's public reads). The dispatcher then admits only the exact public-query
; floor, every nested request inherits that frame, and every local-authority
; check (session_shell_local_authority and the other remote_active readers)
; sees a non-local request. No dispatcher or session arm is added.
;
; Marks (HHMARK, owner-only) name native verbs. A row keeps the verb id and
; the SHA-256 of its live registry entry (handler, cap, argt, selk, destr and
; name), so a verb unregistered, rebound or re-described under the same name
; is a different identity and refuses as stale. Eligibility is an allowlist:
; a verb is household-eligible only on the exact public-query floor (cap 0,
; destr 0 and command_auth_required_cap 0); everything else, including any
; verb not yet classified, is the fixed deny class and no mark opens it.
; Feature owners widen it by adding a reviewed eligibility row here. There
; are no native recipes in the RC: a multi-step plan is a sequence of
; separately admitted requests, each of a marked verb.
;
; Entries for the voice service (internal; BSP; never from inside a dispatch,
; a remote frame or an injected line). One request is in flight at a time.
;   household_submit(RDI=verb name, RSI=args, RDX=args len)
;       -> EAX HH_*, RDX = request id (0 on refusal), R8 = generation
;   household_step(RDI=id, RSI=generation, EDX=HH_STEP_*) -> EAX HH_*
;       before queue admission, before each provider (compute) dispatch and
;       immediately before each result/action commit. COMPUTE needs the
;       mark's compute flag. Any refusal of the request in flight retires it.
;   household_dispatch(RDI=id, RSI=generation, RDX=rsp) -> EAX HH_*
;       revalidates, then dispatches the marked verb once with the native
;       copy of the admitted args; no yield between the check and the handler.
;   household_retire(RDI=id)            idempotent
;   household_generation -> RAX
; The generation moves on every mark change and at boot; lock and unlock never
; move it, and never promote the household to owner.
;
; This slice keeps marks for the running boot (saved=boot; empty at boot,
; which refuses everything). The persisted record and its Guardian spine
; class follow in the next slice; until then every decision is one audit
; receipt and one serial line.
;
;   HHMARK ADD <VERB> [COMPUTE] | HHMARK DEL <VERB> | HHMARK REVOKE
;   HHMARKS
; Both are owner-only: an unlocked local OWNER console session, or a UDP/SSH
; request carrying its own owner ticket (command_auth_owner_request). Every
; other source (AI hook, household, card, serial, internal) is refused first.
; ============================================================================

HH_OK           equ 0
HH_UNMARKED     equ 1
HH_DENY         equ 2
HH_STALE        equ 3
HH_COMPUTE      equ 4
HH_BUSY         equ 5
HH_BAD          equ 6

HH_STEP_QUEUE   equ 0
HH_STEP_COMPUTE equ 1
HH_STEP_COMMIT  equ 2

HH_ROWS         equ 12                 ; HHMARKS fits session_out_buf (512 B)
HH_ROW_SZ       equ 64
HHR_KIND        equ 0
HHR_FLAGS       equ 1
HHR_VERB        equ 4
HHR_DIGEST      equ 8
HHR_NAME        equ 40
HH_NAME_MAX     equ 23
HH_KIND_VERB    equ 1
HH_F_COMPUTE    equ 1
HH_ARG_MAX      equ 192
HH_DIG_HDR      equ 40                 ; handler, cap, argt, selk, destr

HHQ_FREE        equ 0
HHQ_ADMITTED    equ 1
HHQ_DISPATCHED  equ 2

%if HH_ROWS * (HH_NAME_MAX + 9) + 48 >= SESSION_OUT_SIZE   ; " " name "+compute" per row; header 48
    %error "HHMARKS reply exceeds session_out_buf"
%endif

household_declare:
    inc  qword [rel hh_generation]      ; a boot is a new generation
    lea  rdi, [rel str_hh_v_mark]
    lea  rsi, [rel cmd_verb_hhmark]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; owner setting: a mutation
    call command_register_verb
    lea  rdi, [rel str_hh_v_marks]
    lea  rsi, [rel cmd_verb_hhmarks]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    mov  r9d, 1                         ; a household profile: never public
    jmp  command_register_verb

; ---------------------------------------------------------------------------
; Entries for the voice service
; ---------------------------------------------------------------------------
household_submit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  ebx, HH_BUSY
    cmp  byte [rel hh_req_state], HHQ_FREE
    jne  .refuse                        ; the request in flight is untouched
    mov  ebx, HH_BAD
    call hh_context_ok
    test eax, eax
    jz   .refuse
    test r12, r12
    jz   .refuse
    cmp  r14, HH_ARG_MAX
    ja   .refuse
    test r14, r14
    jz   .find
    test r13, r13
    jz   .refuse
    xor  ecx, ecx
.scan:                                  ; printable ASCII only: no NUL, no control bytes
    movzx eax, byte [r13 + rcx]
    cmp  eax, 0x20
    jb   .refuse
    cmp  eax, 0x7E
    ja   .refuse
    inc  rcx
    cmp  rcx, r14
    jb   .scan
.find:
    mov  rdi, r12
    call hh_find                        ; EAX = row, or -1
    mov  ebx, HH_UNMARKED
    cmp  eax, -1
    je   .refuse
    mov  [rel hh_req_row], eax
    imul eax, eax, HH_ROW_SZ
    lea  r15, [rel hh_mark_table]
    add  r15, rax
    mov  eax, [r15 + HHR_VERB]
    mov  [rel hh_req_verb], eax
    lea  rsi, [r15 + HHR_DIGEST]
    lea  rdi, [rel hh_req_digest]
    mov  ecx, 32
    rep  movsb
    mov  ebx, HH_BAD
    mov  edi, [rel hh_req_verb]
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .checked
    cmp  eax, ARGT_NONE
    jne  .refuse                        ; a numeric argument is never taken from voice text
    test r14, r14
    jnz  .refuse
.checked:
    call hh_check
    mov  ebx, eax
    test eax, eax
    jnz  .refuse
    ; the native copy every later step and the dispatch use
    lea  rdi, [rel hh_req_args]
    mov  rsi, r13
    mov  rcx, r14
    rep  movsb
    mov  byte [rdi], 0
    mov  [rel hh_req_args_len], r14d
    inc  qword [rel hh_next_id]
    mov  rax, [rel hh_next_id]
    mov  [rel hh_req_id], rax
    mov  rax, [rel hh_generation]
    mov  [rel hh_req_gen], rax
    mov  byte [rel hh_req_state], HHQ_ADMITTED
    lea  rdi, [rel str_hh_admit]
    mov  rsi, r12
    call hh_receipt
    xor  eax, eax
    mov  rdx, [rel hh_req_id]
    mov  r8, [rel hh_req_gen]
    jmp  .out
.refuse:
    mov  edi, ebx
    mov  rsi, r12
    call hh_refuse_receipt
    mov  eax, ebx
    xor  edx, edx
    mov  r8, [rel hh_generation]
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

household_step:
    push rbx
    push r12
    mov  r12d, edx
    mov  ebx, HH_BAD
    call hh_is_current                  ; RDI = id
    test eax, eax
    jz   .refuse                        ; not the request in flight: nothing to retire
    mov  ebx, HH_STALE
    cmp  rsi, [rel hh_generation]
    jne  .retire
    cmp  rsi, [rel hh_req_gen]
    jne  .retire
    mov  ebx, HH_BAD
    cmp  r12d, HH_STEP_COMMIT
    ja   .retire
    call hh_check
    mov  ebx, eax
    test eax, eax
    jnz  .retire
    cmp  r12d, HH_STEP_COMPUTE
    jne  .ok
    mov  ebx, HH_COMPUTE
    mov  eax, [rel hh_req_row]
    imul eax, eax, HH_ROW_SZ
    lea  rcx, [rel hh_mark_table]
    test byte [rcx + rax + HHR_FLAGS], HH_F_COMPUTE
    jz   .retire                        ; COMPUTE is per marked item, never standing
.ok:
    xor  eax, eax
    jmp  .out
.retire:
    call hh_fail_current
.refuse:
    mov  eax, ebx
.out:
    pop  r12
    pop  rbx
    ret

household_dispatch:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  ebx, HH_BAD
    test r14, r14
    jz   .refuse
    cmp  byte [rel hh_req_state], HHQ_ADMITTED
    jne  .refuse                        ; one dispatch per admission
    cmp  r12, [rel hh_req_id]
    jne  .refuse
    call hh_context_ok
    test eax, eax
    jz   .retire
    mov  ebx, HH_STALE
    cmp  r13, [rel hh_generation]
    jne  .retire
    cmp  r13, [rel hh_req_gen]
    jne  .retire
    call hh_check
    mov  ebx, eax
    test eax, eax
    jnz  .retire
    ; From here to the handler nothing yields: the request is built from the
    ; native copies only.
    lea  rbx, [rel hh_req]
    mov  eax, [rel hh_req_verb]
    mov  [rbx + REQ_VERB], rax
    mov  qword [rbx + REQ_CAP], 0
    mov  [rbx + REQ_IDEM], r12
    mov  qword [rbx + REQ_SEL], 0
    xor  ecx, ecx
    cmp  dword [rel hh_req_args_len], 0
    je   .arg
    lea  rcx, [rel hh_req_args]
.arg:
    mov  [rbx + REQ_ARG], rcx
    mov  qword [rbx + REQ_SOURCE], CMD_SOURCE_HOUSEHOLD
    mov  qword [rbx + REQ_PRINCIPAL], PRIN_HOUSEHOLD
    mov  byte [rel hh_req_state], HHQ_DISPATCHED
    mov  byte [rel hh_frame_active], 1
    xor  edi, edi                       ; no ticket: the public-query floor only
    call command_auth_remote_begin
    mov  rdi, rbx
    mov  rsi, r14
    call command_dispatch
    mov  [rel hh_last_result], rax
    call command_auth_remote_end
    mov  byte [rel hh_frame_active], 0
    lea  rdi, [rel str_hh_dispatch]
    call hh_receipt_current
    xor  eax, eax
    jmp  .out
.retire:
    call hh_fail_current
.refuse:
    mov  eax, ebx
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

household_retire:
    call hh_is_current
    test eax, eax
    jz   .out
    call hh_clear
.out:
    ret

household_generation:
    mov  rax, [rel hh_generation]
    ret

; ---------------------------------------------------------------------------
; Checks
; ---------------------------------------------------------------------------

; hh_context_ok -> EAX 1 at depth 0, outside any remote frame or injected line.
hh_context_ok:
    xor  eax, eax
    cmp  dword [rel cmd_dispatch_depth], 0
    jne  .out
    cmp  byte [rel command_auth_remote_active], 0
    jne  .out
    cmp  qword [rel keyprov_active_taint], 0
    jne  .out
    mov  eax, 1
.out:
    ret

; hh_is_current(RDI=id) -> EAX 1 when it names the request in flight.
hh_is_current:
    xor  eax, eax
    cmp  byte [rel hh_req_state], HHQ_FREE
    je   .out
    test rdi, rdi
    jz   .out
    cmp  rdi, [rel hh_req_id]
    jne  .out
    mov  eax, 1
.out:
    ret

; hh_check -> EAX HH_OK, or why the admitted item no longer holds: the row is
; gone or now names another item (UNMARKED/STALE), the registry entry is not
; the identity marked (STALE), or the verb left the eligible class (DENY).
hh_check:
    push rbx
    mov  eax, [rel hh_req_row]
    cmp  eax, HH_ROWS
    jae  .unmarked
    imul eax, eax, HH_ROW_SZ
    lea  rbx, [rel hh_mark_table]
    add  rbx, rax
    cmp  byte [rbx + HHR_KIND], HH_KIND_VERB
    jne  .unmarked
    mov  eax, [rbx + HHR_VERB]
    cmp  eax, [rel hh_req_verb]
    jne  .stale
    lea  rdi, [rbx + HHR_DIGEST]
    lea  rsi, [rel hh_req_digest]
    call hh_eq32
    test eax, eax
    jz   .stale
    mov  edi, [rel hh_req_verb]
    lea  rsi, [rel hh_dig_live]
    call hh_live_digest
    test eax, eax
    jnz  .stale
    lea  rdi, [rel hh_dig_live]
    lea  rsi, [rel hh_req_digest]
    call hh_eq32
    test eax, eax
    jz   .stale
    mov  edi, [rel hh_req_verb]
    call hh_eligible
    test eax, eax
    jz   .deny
    xor  eax, eax
    jmp  .out
.unmarked:
    mov  eax, HH_UNMARKED
    jmp  .out
.stale:
    mov  eax, HH_STALE
    jmp  .out
.deny:
    mov  eax, HH_DENY
.out:
    pop  rbx
    ret

; hh_verb_entry(EDI=verb id) -> RAX = live registry entry, or 0 (out of range / vacant).
hh_verb_entry:
    mov  eax, edi
    cmp  eax, [rel verb_count]
    jae  .none
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rax, rcx
    cmp  qword [rax + VERB_NAME], 0
    je   .none
    ret
.none:
    xor  eax, eax
    ret

; hh_eligible(EDI=verb id) -> EAX 1 only on the exact public-query floor.
hh_eligible:
    push rbx
    call hh_verb_entry
    mov  rbx, rax
    xor  eax, eax
    test rbx, rbx
    jz   .out
    cmp  qword [rbx + VERB_CAP], 0
    jne  .out
    cmp  qword [rbx + VERB_DESTR], 0
    jne  .out
    mov  rdi, [rbx + VERB_NAME]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap      ; 0 = the exact public-query floor
    mov  rcx, rax
    xor  eax, eax
    test rcx, rcx
    jnz  .out
    mov  eax, 1
.out:
    pop  rbx
    ret

; hh_live_digest(EDI=verb id, RSI=out32) -> EAX 0, or -1 (vacant, out of range,
; or a name longer than a row holds). SHA-256 over handler, cap, argt, selk,
; destr and the name with its NUL.
hh_live_digest:
    push rbx
    push r12
    mov  r12, rsi
    call hh_verb_entry
    mov  rbx, rax
    test rbx, rbx
    jz   .bad
    lea  rdi, [rel hh_dig_buf]
    mov  rax, [rbx + VERB_HANDLER]
    mov  [rdi], rax
    mov  rax, [rbx + VERB_CAP]
    mov  [rdi + 8], rax
    mov  rax, [rbx + VERB_ARGT]
    mov  [rdi + 16], rax
    mov  rax, [rbx + VERB_SELK]
    mov  [rdi + 24], rax
    mov  rax, [rbx + VERB_DESTR]
    mov  [rdi + 32], rax
    mov  rsi, [rbx + VERB_NAME]
    xor  ecx, ecx
.name:
    movzx eax, byte [rsi + rcx]
    mov  [rdi + HH_DIG_HDR + rcx], al
    inc  ecx
    test eax, eax
    jz   .hash
    cmp  ecx, HH_NAME_MAX + 1
    jb   .name
    jmp  .bad
.hash:
    lea  edx, [rcx + HH_DIG_HDR]
    mov  rdi, r12
    lea  rsi, [rel hh_dig_buf]
    call sha256_hash
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; hh_eq32(RDI, RSI) -> EAX 1 when the 32 bytes are equal (constant time).
hh_eq32:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    mov  dl, [rdi + rcx]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 32
    jb   .loop
    test al, al
    setz al
    movzx eax, al
    ret

; hh_find(RDI=name) -> EAX = the marked row with that name, or -1.
hh_find:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.row:
    cmp  ebx, HH_ROWS
    jae  .none
    imul eax, ebx, HH_ROW_SZ
    lea  rsi, [rel hh_mark_table]
    add  rsi, rax
    cmp  byte [rsi + HHR_KIND], 0
    je   .next
    add  rsi, HHR_NAME
    mov  rdi, r12
    call strcmp
    test eax, eax
    jz   .found
.next:
    inc  ebx
    jmp  .row
.found:
    mov  eax, ebx
    jmp  .out
.none:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; hh_fail_current: a refusal of the request in flight retires it, with one receipt.
hh_fail_current:                        ; keeps RBX (the caller's status)
    lea  rdi, [rel str_hh_retire]
    call hh_receipt_current
    jmp  hh_clear

hh_clear:
    mov  byte [rel hh_req_state], HHQ_FREE
    mov  qword [rel hh_req_id], 0
    mov  dword [rel hh_req_args_len], 0
    lea  rdi, [rel hh_req_args]
    xor  eax, eax
    mov  ecx, HH_ARG_MAX + 1
    rep  stosb
    ret

; hh_owner_editor(RDI=req) -> EAX 1 for the owner's own request. Sources are
; an allowlist checked first: the local console (an unlocked, keyed, bound
; OWNER session with no injected input) or a UDP/SSH request judged by its
; own owner ticket. The AI hook, the household, a card, serial and internal
; callers never edit marks, whatever owner ticket is in flight.
hh_owner_editor:
    xor  eax, eax
    cmp  byte [rel hh_frame_active], 0
    jne  .out
    cmp  qword [rel keyprov_active_taint], 0
    jne  .out
    cmp  qword [rdi + REQ_PRINCIPAL], PRIN_HOUSEHOLD
    je   .out
    mov  rcx, [rdi + REQ_SOURCE]
    cmp  rcx, CMD_SOURCE_CONSOLE
    je   .console
    cmp  rcx, CMD_SOURCE_UDP
    je   .ticket
    cmp  rcx, CMD_SOURCE_SSH
    jne  .out
.ticket:
    call command_auth_owner_request     ; 1 own AUTH1 owner ticket, 2 owner SSH key
    test eax, eax
    setnz al
    movzx eax, al
    ret
.console:                               ; the dispatcher admits only OWNER (or an admitted Try) console requests
    call session_shell_local_authority  ; RAX = bound principal, RDX = token; 0/0 refused
    cmp  rax, PRIN_OWNER                ; (0/0 on any refusal: unlocked, keyed, bound, no injected input)
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
.out:
    ret

; ---------------------------------------------------------------------------
; HHMARK / HHMARKS
; ---------------------------------------------------------------------------
cmd_verb_hhmark:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    call hh_owner_editor
    test eax, eax
    jz   .deny
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .bad
    mov  rdi, rbx
    lea  rsi, [rel str_hh_w_revoke]
    call strcmp
    test eax, eax
    jz   .revoke
    mov  rdi, rbx
    lea  rsi, [rel str_hh_w_add]
    call hh_word
    test rax, rax
    jnz  .add
    mov  rdi, rbx
    lea  rsi, [rel str_hh_w_del]
    call hh_word
    test rax, rax
    jnz  .del
    jmp  .bad
.add:
    mov  rdi, rax
    call hh_take_name                   ; RAX = after the name (0 bad), hh_name = the name
    test rax, rax
    jz   .bad
    xor  r14d, r14d                     ; flags
    cmp  byte [rax], 0
    je   .add_resolve
    mov  rdi, rax
    lea  rsi, [rel str_hh_w_compute]
    call strcmp
    test eax, eax
    jnz  .bad
    mov  r14d, HH_F_COMPUTE
.add_resolve:
    lea  rdi, [rel hh_name]
    call command_lookup
    cmp  rax, -1
    je   .unknown
    mov  r15d, eax
    mov  edi, r15d
    call hh_eligible
    test eax, eax
    jz   .deny_class
    mov  edi, r15d
    lea  rsi, [rel hh_dig_live]
    call hh_live_digest
    test eax, eax
    jnz  .unknown
    lea  rdi, [rel hh_name]
    call hh_find
    cmp  eax, -1
    jne  .add_row                       ; a re-mark replaces the row (new identity, new generation)
    xor  eax, eax
.free:
    cmp  eax, HH_ROWS
    jae  .full
    imul ecx, eax, HH_ROW_SZ
    lea  rdx, [rel hh_mark_table]
    cmp  byte [rdx + rcx + HHR_KIND], 0
    je   .add_row
    inc  eax
    jmp  .free
.add_row:
    imul eax, eax, HH_ROW_SZ
    lea  rbx, [rel hh_mark_table]
    add  rbx, rax
    mov  byte [rbx + HHR_KIND], HH_KIND_VERB
    mov  [rbx + HHR_FLAGS], r14b
    mov  word [rbx + 2], 0
    mov  [rbx + HHR_VERB], r15d
    lea  rdi, [rbx + HHR_DIGEST]
    lea  rsi, [rel hh_dig_live]
    mov  ecx, 32
    rep  movsb
    lea  rdi, [rbx + HHR_NAME]
    xor  eax, eax
    mov  ecx, HH_NAME_MAX + 1
    rep  stosb
    lea  rdi, [rbx + HHR_NAME]
    lea  rsi, [rel hh_name]
.copy:
    lodsb
    stosb
    test al, al
    jnz  .copy
    lea  r14, [rel str_hh_mark_add]
    jmp  .changed
.del:
    mov  rdi, rax
    call hh_take_name
    test rax, rax
    jz   .bad
    cmp  byte [rax], 0
    jne  .bad
    lea  rdi, [rel hh_name]
    call hh_find
    cmp  eax, -1
    je   .unmarked
    imul eax, eax, HH_ROW_SZ
    lea  rdi, [rel hh_mark_table]
    add  rdi, rax
    xor  eax, eax
    mov  ecx, HH_ROW_SZ
    rep  stosb
    lea  r14, [rel str_hh_mark_del]
    jmp  .changed
.revoke:
    lea  rdi, [rel hh_mark_table]
    xor  eax, eax
    mov  ecx, HH_ROWS * HH_ROW_SZ
    rep  stosb
    mov  byte [rel hh_name], 0
    lea  r14, [rel str_hh_mark_revoke]
.changed:
    inc  qword [rel hh_generation]       ; every mark change retires work admitted before it
    mov  rdi, r14
    lea  rsi, [rel hh_name]
    call hh_receipt
    call hh_report
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.deny:
    lea  rdi, [rel str_hh_owner_only]
    mov  esi, CMDE_AUTHDENY
    jmp  .refused
.deny_class:
    lea  rdi, [rel str_hh_deny_class]
    mov  esi, CMDE_AUTHDENY
    jmp  .refused
.unknown:
    lea  rdi, [rel str_hh_unknown]
    mov  esi, CMDE_BADARG
    jmp  .refused
.unmarked:
    lea  rdi, [rel str_hh_not_marked]
    mov  esi, CMDE_BADARG
    jmp  .refused
.full:
    lea  rdi, [rel str_hh_full]
    mov  esi, CMDE_BADARG
    jmp  .refused
.bad:
    lea  rdi, [rel str_hh_bad]
    mov  esi, CMDE_BADARG
.refused:
    mov  [r13 + RSP_CODE], rsi
    push rdi
    call hh_out_reset
    pop  rdi
    call hh_out_str
    lea  rax, [rel session_out_buf]
    mov  [r13 + RSP_HINT], rax
.ready:
    mov  byte [rel session_out_ready], 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_hhmarks:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call hh_owner_editor
    test eax, eax
    jz   .deny
    call hh_report
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.deny:
    call hh_out_reset
    lea  rdi, [rel str_hh_owner_only]
    call hh_out_str
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel session_out_buf]
    mov  [r13 + RSP_HINT], rax
.ready:
    mov  byte [rel session_out_ready], 1
    pop  r13
    ret

; hh_report: "HHMARKS gen=<n> n=<k> saved=boot[ <VERB>[+compute]]..."
hh_report:
    push rbx
    push r12
    call hh_out_reset
    lea  rdi, [rel str_hh_report]
    call hh_out_str
    mov  rdi, [rel hh_generation]
    call hh_out_dec
    lea  rdi, [rel str_hh_report_n]
    call hh_out_str
    xor  ebx, ebx
    xor  r12d, r12d
.count:
    imul eax, ebx, HH_ROW_SZ
    lea  rcx, [rel hh_mark_table]
    cmp  byte [rcx + rax + HHR_KIND], 0
    je   .count_next
    inc  r12d
.count_next:
    inc  ebx
    cmp  ebx, HH_ROWS
    jb   .count
    mov  edi, r12d
    call hh_out_dec
    lea  rdi, [rel str_hh_report_saved]
    call hh_out_str
    xor  ebx, ebx
.row:
    imul eax, ebx, HH_ROW_SZ
    lea  r12, [rel hh_mark_table]
    add  r12, rax
    cmp  byte [r12 + HHR_KIND], 0
    je   .next
    lea  rdi, [rel str_hh_space]
    call hh_out_str
    lea  rdi, [r12 + HHR_NAME]
    call hh_out_str
    test byte [r12 + HHR_FLAGS], HH_F_COMPUTE
    jz   .next
    lea  rdi, [rel str_hh_plus_compute]
    call hh_out_str
.next:
    inc  ebx
    cmp  ebx, HH_ROWS
    jb   .row
    pop  r12
    pop  rbx
    ret

; hh_word(RDI=text, RSI=word) -> RAX = past "<word> " when the text starts with it, else 0.
hh_word:
.cmp:
    mov  al, [rsi]
    test al, al
    jz   .end
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  .cmp
.end:
    cmp  byte [rdi], ' '
    jne  .no
    lea  rax, [rdi + 1]
    ret
.no:
    xor  eax, eax
    ret

; hh_take_name(RDI=text) -> RAX = past the name and one separating space (0 if
; malformed); hh_name = the name: 1..23 of A-Z, 0-9, '_'.
hh_take_name:
    lea  rsi, [rel hh_name]
    xor  ecx, ecx
.ch:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .end
    cmp  eax, ' '
    je   .end
    cmp  eax, '_'
    je   .ok
    lea  edx, [rax - 'A']
    cmp  edx, 25
    jbe  .ok
    lea  edx, [rax - '0']
    cmp  edx, 9
    ja   .bad
.ok:
    cmp  ecx, HH_NAME_MAX
    jae  .bad
    mov  [rsi + rcx], al
    inc  ecx
    jmp  .ch
.end:
    test ecx, ecx
    jz   .bad
    mov  byte [rsi + rcx], 0
    lea  rax, [rdi + rcx]
    cmp  byte [rax], ' '
    jne  .out
    inc  rax
    cmp  byte [rax], 0
    je   .bad                           ; a trailing space with nothing after it
.out:
    ret
.bad:
    mov  byte [rsi], 0
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Receipts: one audit line and one serial line per decision.
; ---------------------------------------------------------------------------

; hh_receipt(RDI=prefix, RSI=item) -> "<prefix><item> gen=<n>"
hh_receipt:
    push rbx
    push r12
    mov  rbx, rsi
    lea  r12, [rel hh_audit_buf]
    call hh_audit_put
    mov  rdi, rbx
    call hh_audit_put_name
    lea  rdi, [rel str_hh_gen]
    call hh_audit_put
    mov  rdi, [rel hh_generation]
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    mov  byte [r12], 0
    pop  r12
    pop  rbx
    jmp  hh_receipt_emit

; hh_refuse_receipt(EDI=HH_* reason, RSI=item) -> "HH refuse item=<item> reason=<r> gen=<n>"
hh_refuse_receipt:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    mov  rbx, rsi
    lea  r12, [rel hh_audit_buf]
    lea  rdi, [rel str_hh_refuse]
    call hh_audit_put
    mov  rdi, rbx
    call hh_audit_put_name
    lea  rdi, [rel str_hh_reason]
    call hh_audit_put
    cmp  r13d, HH_BAD
    jbe  .known
    mov  r13d, HH_BAD
.known:
    lea  rdi, [rel str_hh_reasons]
.skip:
    test r13d, r13d
    jz   .put
.word:
    cmp  byte [rdi], 0
    lea  rdi, [rdi + 1]
    jne  .word
    dec  r13d
    jmp  .skip
.put:
    call hh_audit_put
    lea  rdi, [rel str_hh_gen]
    call hh_audit_put
    mov  rdi, [rel hh_generation]
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    mov  byte [r12], 0
    pop  r13
    pop  r12
    pop  rbx
    jmp  hh_receipt_emit

; hh_receipt_current(RDI=prefix) -> "<prefix><admitted item> id=<id> gen=<n>"
hh_receipt_current:
    push rbx
    push r12
    lea  r12, [rel hh_audit_buf]
    call hh_audit_put
    mov  eax, [rel hh_req_row]
    xor  edi, edi
    cmp  eax, HH_ROWS
    jae  .item
    imul eax, eax, HH_ROW_SZ
    lea  rdi, [rel hh_mark_table]
    lea  rdi, [rdi + rax + HHR_NAME]
.item:
    call hh_audit_put_name
    lea  rdi, [rel str_hh_id]
    call hh_audit_put
    mov  rdi, [rel hh_req_id]
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    lea  rdi, [rel str_hh_gen]
    call hh_audit_put
    mov  rdi, [rel hh_generation]
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    mov  byte [r12], 0
    pop  r12
    pop  rbx
    jmp  hh_receipt_emit

hh_receipt_emit:
    lea  rdi, [rel hh_audit_buf]
    call audit_log_line
    lea  rdi, [rel str_hh_serial]
    call serial_string
    lea  rdi, [rel hh_audit_buf]
    call serial_string
    lea  rdi, [rel str_hh_crlf]
    jmp  serial_string

; hh_audit_put(RDI=cstr) appends at R12, bounded to the receipt buffer.
hh_audit_put:
    lea  rcx, [rel hh_audit_buf + HH_AUDIT_MAX]
.c:
    cmp  r12, rcx
    jae  .out
    mov  al, [rdi]
    test al, al
    jz   .out
    mov  [r12], al
    inc  rdi
    inc  r12
    jmp  .c
.out:
    mov  byte [r12], 0
    ret

; hh_audit_put_name(RDI=item or 0): the item only when it is 1..23 name bytes, else "?".
hh_audit_put_name:
    test rdi, rdi
    jz   .unknown
    xor  ecx, ecx
.ch:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .end
    cmp  eax, '_'
    je   .ok
    lea  edx, [rax - 'A']
    cmp  edx, 25
    jbe  .ok
    lea  edx, [rax - '0']
    cmp  edx, 9
    ja   .unknown
.ok:
    inc  ecx
    cmp  ecx, HH_NAME_MAX
    jbe  .ch
    jmp  .unknown
.end:
    test ecx, ecx
    jz   .unknown
    jmp  hh_audit_put
.unknown:
    lea  rdi, [rel str_hh_q]
    jmp  hh_audit_put

hh_out_reset:
    lea  rax, [rel session_out_buf]
    mov  [rel hh_out_cur], rax
    mov  byte [rax], 0
    ret

; hh_out_str(RDI=cstr) appends to session_out_buf, bounded.
hh_out_str:
    mov  rsi, [rel hh_out_cur]
    lea  rcx, [rel session_out_buf + SESSION_OUT_SIZE - 1]
.c:
    cmp  rsi, rcx
    jae  .out
    mov  al, [rdi]
    test al, al
    jz   .out
    mov  [rsi], al
    inc  rdi
    inc  rsi
    jmp  .c
.out:
    mov  byte [rsi], 0
    mov  [rel hh_out_cur], rsi
    ret

hh_out_dec:
    lea  rsi, [rel hh_numbuf]
    call fmt_dec                        ; NUL-terminates
    lea  rdi, [rel hh_numbuf]
    jmp  hh_out_str

; ---------------------------------------------------------------------------
; State and strings
; ---------------------------------------------------------------------------
HH_AUDIT_MAX equ 96
str_hh_v_mark:        db "HHMARK",0
str_hh_v_marks:       db "HHMARKS",0
str_hh_w_add:         db "ADD",0
str_hh_w_del:         db "DEL",0
str_hh_w_revoke:      db "REVOKE",0
str_hh_w_compute:     db "COMPUTE",0
str_hh_report:        db "HHMARKS gen=",0
str_hh_report_n:      db " n=",0
str_hh_report_saved:  db " saved=boot",0
str_hh_space:         db " ",0
str_hh_plus_compute:  db "+compute",0
str_hh_owner_only:    db "HHMARK REFUSED owner_only",0
str_hh_deny_class:    db "HHMARK REFUSED deny_class",0
str_hh_unknown:       db "HHMARK REFUSED unknown_verb",0
str_hh_not_marked:    db "HHMARK REFUSED not_marked",0
str_hh_full:          db "HHMARK REFUSED full",0
str_hh_bad:           db "HHMARK REFUSED bad_arg",0
str_hh_admit:         db "HH admit item=",0
str_hh_dispatch:      db "HH dispatch item=",0
str_hh_retire:        db "HH retire item=",0
str_hh_refuse:        db "HH refuse item=",0
str_hh_mark_add:      db "HH mark add by=owner item=",0
str_hh_mark_del:      db "HH mark del by=owner item=",0
str_hh_mark_revoke:   db "HH mark revoke by=owner item=",0
str_hh_reason:        db " reason=",0
str_hh_reasons:       db "ok",0,"unmarked",0,"deny_class",0,"stale",0,"compute",0,"busy",0,"bad",0
str_hh_id:            db " id=",0
str_hh_gen:           db " gen=",0
str_hh_q:             db "?",0
str_hh_serial:        db "[PAOS64] ",0
str_hh_crlf:          db 13,10,0

%include "core/abi/wdata.inc"
%macro WDATA_sec_household_0 0
alignb 8
hh_generation:        resq 1
hh_next_id:           resq 1
hh_req_id:            resq 1
hh_req_gen:           resq 1
hh_last_result:       resq 1
hh_out_cur:           resq 1
hh_req:               resb REQ_SZ
hh_req_digest:        resb 32
hh_dig_live:          resb 32
hh_mark_table:        resb HH_ROWS * HH_ROW_SZ
hh_req_row:           resd 1
hh_req_verb:          resd 1
hh_req_args_len:      resd 1
hh_req_state:         resb 1
hh_frame_active:      resb 1
hh_name:              resb HH_NAME_MAX + 1
hh_numbuf:            resb 24
hh_dig_buf:           resb HH_DIG_HDR + HH_NAME_MAX + 1
hh_req_args:          resb HH_ARG_MAX + 1
hh_audit_buf:         resb HH_AUDIT_MAX + 48   ; a capped put can still take two decimals
%endmacro
WDATA_BSS_DEFER WDATA_sec_household_0
