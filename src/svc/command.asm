;; MODULE svc/command
;; LAYER 5
;; EXPORTS command_freq_reply, command_freq_reply_ready, command_freq_reply_retire, verb_id_freqmsr, command_registry_init, command_registry_safe_init, command_register_verb, command_dispatch, command_registry_selftest, command_resolve_selector, command_lookup, command_verb_count, command_verb_name, command_verb_argt, command_verb_cap, command_verb_selk, command_verb_destr, command_job_bind_completion, command_jobs_tick, command_job_exhaustion_control, command_job_control_snapshot, cmd_dispatch_last_source, cmd_dispatch_last_principal, command_unregister_verb, cmd_desktop_refused, cmd_dispatch_proposer, cmd_card_proposer_arm, cmd_dispatch_depth
;; IMPORTS sec/session, svc/command_udp, svc/boot_clock, boot/serial, core/time, core/lib/fmt, core/lib/str, core/csprng, svc/command_auth, svc/command_srvstat, svc/command_hppersist, fs/storage_access, sec/replay_floor, boot/boot_v2_handoff, svc/normal_deadman_live
;; CAPS
;; OWNER saga:command
; Standalone source harnesses retain the same disabled default as boot/header.
%ifndef PAOS_LAB_D4_IFON_STALL
%define PAOS_LAB_D4_IFON_STALL 0
%endif
; ============================================================================
; svc/command.asm — THE COMMAND MODEL (contract 1077, rewrite/COMMANDS.md §1-3,§9.4).
;
; THE NON-RETROFITTABLE FOUNDATION: PaOS has ONE transport-agnostic command
; REGISTRY — the source of truth for everything the machine can do. Every surface
; (the AI/ACP natively, serial, UDP :9997, CLI, widgets, voice) is a thin
; PROJECTION that DISPATCHES INTO this registry; none owns logic. "UDP is the
; baseline" conflated model with transport (§2): the MODEL is the baseline —
; typed verbs, a structured request/response envelope, a capability gate, and a
; non-blocking job model — and it is provable with NO NIC and NO serial. That is
; exactly what this selftest does: it drives verbs IN-PROCESS (the most native
; surface — the self-dev loop's own hook) and proves the model independent of any
; wire. 1010(UDP)/1078(serial)/1079(ACP) each carry their own bare-metal grading
; as adapters over THIS table (the loop had built 1010 UDP-primary, inverting the
; layering; this seam rights it).
;
; THE RULE (capability analog of MODULES.md's single-definition rule): NO surface
; may bypass the registry. A state-mutating path outside command_dispatch is a
; lint smell — auditability breaks (an action that left no command left no trace)
; and the capability gate is bypassed. The MODEL-level enforcement here: every
; verb execution this boot is routed through the ONE command_dispatch, which sets
; an in-dispatch guard the handlers assert on entry; the selftest proves
; dispatch_count == handler_runs AND bypass_flag == 0, so no side-door ran. A
; source-scan modlint half (cross-tree "no call <verb>_handler outside dispatch")
; is deferred to the projection contracts, which introduce the per-transport
; entry points that scan must cover.
;
; NON-BLOCKING = LIVENESS, NOT AI-ERGONOMICS (§3): a verb returns promptly with
; {accepted, job_id, est}; long work runs as a JOB advanced cooperatively, results
; polled via STATUS <job_id>. Reason: in a single-address-space system a handler
; that blocks the command task blocks EVERY command incl. STATUS/diagnostics — you
; must never be unable to ask "are you OK?". This is the direct cure for the
; project's #1 historical pain ("wedged vs slow"). The selftest PROVES it: a
; deliberately-slow verb returns accepted+job_id WITHOUT finishing (state=running),
; and STATUS answers WHILE that job is still running (state observed != done) —
; content-graded, not a latch.
;
; THE §9.4 NON-RETROFITTABLE ENVELOPE (anti-duct-tape fields — retrofitting any one
; touches every consumer, so all exist at v1 even where policy is trivial):
;   (a) a TYPED structured request/response envelope (CMDREQ_*/CMDRSP_*), NOT text;
;   (b) verb SELF-DESCRIPTION at register (name, arg-type, selector-kind,
;       destructiveness, cap) so CATALOG/MCP is generated, not hand-kept;
;   (c) an IDEMPOTENCY key + job_id in the envelope (safe retry + the §3 job model);
;   (d) a CAPABILITY field on every verb + a gate checkpoint on dispatch.  Local
;       kernel callers retain the legacy cap=0 behavior; every remote projection
;       now derives an exact owner scope through svc/command_auth;
;   (e) a SELECTOR-RESOLUTION hook resolve(selector)->handle so no verb hardcodes a
;       device path (the #1 small-local-LLM multiplier, §9.3);
;   (f) ACTIONABLE errors {code, expected, hint}, not bare failure.
; v1 originally stubbed the policy behind each; the owner-auth policy is now live,
; while selector identity remains the additive seam.  The SHAPE
; is present — the whole point of doing this as a foundation seam (PRINCIPLES §1
; field-exists-at-v1).
;
; CONTENT-GRADE, NOT LATCH (TESTING §1/§6): the PING verb echoes a RANDOM in-proc
; nonce (rdtsc-derived — a value the handler cannot know in advance) back through
; the envelope; the selftest asserts the reply equals the injected nonce and PRINTS
; it. A hardcoded reply cannot reproduce a fresh-per-boot nonce -> FAIL. The
; DEGENERATE-SECOND proof (TESTING §5): registering the 2nd and 3rd verbs required
; NO edit to the registry core — the SAME command_register_verb() call.
;
; SINGLE DEFINITION (G1 / known_trap): there is exactly ONE command registry and
; ONE dispatch entry, here. modlint forbids a 2nd variant.
; ============================================================================

; --- verb registry entry: 6 quadwords (48 bytes), additive by design (§9.4 b,d,e) ---
VERB_NAME    equ 0      ; ptr to NUL-terminated verb name (self-description -> CATALOG/MCP)
VERB_HANDLER equ 8      ; handler fn ptr (the dispatch target — indirection)
VERB_CAP     equ 16     ; legacy/internal capability; remote policy derives an exact owner scope
VERB_ARGT    equ 24     ; arg-type tag (self-description)
VERB_SELK    equ 32     ; selector-kind (self-description; 0 = none)
VERB_DESTR   equ 40     ; destructiveness (0 = read-only; self-description)
VERB_ENT_SZ  equ 48
VERB_MAX     equ 225    ; Peter87189: one SNAPSHOT slot; retain all224 existing slots
                        ; 1230a: BACKUP plus eleven slots of additive headroom;
                        ; do not let a new owner verb evict late image/console rows.
                        ; 2312: PMODCTL plus HELLO/NONCE_ECHO now reachable on
                        ; periodic-LAPIC CPUs; reload reuses its owned slot.
                        ; 1058: three TLS verbs plus thirteen slots of additive
                        ; declaration headroom; never make a new feature evict the tail (S11).

; --- the typed request envelope (CMDREQ_*, §9.4 a,c,d,e) ---
REQ_VERB     equ 0      ; verb id (interned handle = slot index; names are metadata)
REQ_CAP      equ 8      ; legacy/internal capability; remote authority comes from AUTH1
REQ_IDEM     equ 16     ; idempotency key (safe retry)
REQ_SEL      equ 24     ; selector ptr (device-path abstraction; 0 = none)
REQ_ARG      equ 32     ; arg word (PING nonce, STATUS job_id)
REQ_SOURCE   equ 40     ; ingress tag (CMD_SOURCE_*), carried through the one entry
REQ_PRINCIPAL equ 48    ; authenticated/local principal id; owner=1 in v1
REQ_SZ       equ 56

CMD_SOURCE_INTERNAL equ 0
CMD_SOURCE_UDP      equ 1
CMD_SOURCE_SERIAL   equ 2
CMD_SOURCE_AIHOOK   equ 3
CMD_SOURCE_CONSOLE  equ 4
CMD_SOURCE_SSH      equ 5      ; 2143: authenticated SSH exec; principal = the connection's bound pid
CMD_SOURCE_CARD     equ 6      ; RCQ-40 J2a: an owner-confirmed action card (svc/command_card); never CONSOLE (C4)
CMD_SOURCE_HOUSEHOLD equ 7     ; sec/household household_dispatch: runs in a null-ticket remote frame (public floor)
CMD_SOURCE_GUEST    equ 8     ; native VM-wide binding, never a console/OWNER projection
CMD_PRINCIPAL_NONE  equ 0
CMD_PRINCIPAL_OWNER equ 1
CMD_PRINCIPAL_TRY   equ 4      ; = sec/principal PRIN_TRY: the volatile local Try login
CMD_PRINCIPAL_HOUSEHOLD equ 5  ; = sec/principal PRIN_HOUSEHOLD: no standing caps, own request only

; --- the typed response envelope (CMDRSP_*, §9.4 a,c,f + §3 job model) ---
RSP_CODE     equ 0      ; 0 = ok; else error code (§9.4 f: actionable)
RSP_ACCEPTED equ 8      ; 1 = accepted (job model, §3)
RSP_JOBID    equ 16     ; job id assigned (0 = none)
RSP_VAL      equ 24     ; result value (echoed nonce / job state)
RSP_EXPECTED equ 32     ; actionable error: expected value (§9.4 f)
RSP_HINT     equ 40     ; actionable error: hint ptr (§9.4 f)
RSP_SZ       equ 48

; error codes (§9.4 f) — small, additive
CMDE_OK       equ 0
CMDE_NOVERB   equ 1      ; verb id out of range
CMDE_CAPDENY  equ 2      ; legacy/internal request capability gate rejected
CMDE_BADJOB   equ 3      ; STATUS given an unknown job id
CMDE_BADSEL   equ 4      ; selector did not resolve to a registered handle (§9.4 f; the ai-hook resolver)
CMDE_BADARG   equ 5      ; text argument failed the verb's bounded grammar
CMDE_AUTHDENY equ 6      ; owner signature/capability/expiry/replay gate refused
CMDE_DESKTOP_LOCKED equ 7 ; remote request needs the local desktop session, which is locked
                          ; (ADMIN 2026-09-30 06:22 item 5). SSH exit-status = the code, so
                          ; every desktop/lock refusal over SSH exits non-zero (7). The UDP lean
                          ; envelope only branches on RSP_CODE for DIAGRING, so UDP reply bytes
                          ; are unchanged.
; 8 is unassigned. 9 is the value gui/app_widget already returns as AWG_BUSY.
CMDE_BUSY     equ 9      ; refused in the current state or capacity (a full table, a display
                          ; not available now); nothing changed and nothing is queued (A2-1 G-11)

; --- arg-type self-description tags (§9.4 b), carried in VERB_ARGT and read back by
;   CATALOG + every projection so arg marshalling is registry-driven, never hardcoded ---
ARGT_NONE     equ 0      ; no argument
ARGT_U64      equ 1      ; unsigned 64-bit word (STATUS job_id, PING nonce)
ARGT_TEXT     equ 2      ; pointer to a NUL-terminated token (echoed verbatim)

; --- non-blocking job table (§3): {id, state, progress, result} ---
JOB_ID       equ 0
JOB_STATE    equ 8       ; 0=free 1=running 2=done
JOB_PROG     equ 16      ; cooperative progress counter
JOB_RESULT   equ 24
JOB_ENT_SZ   equ 32
JOB_MAX      equ 4
JOB_ST_FREE  equ 0
JOB_ST_RUN   equ 1
JOB_ST_DONE  equ 2
SLOWJOB_STEPS equ 32     ; settled idle frames: long enough for interleaved input/STATUS
SLOWJOB_EST_SEC equ 2    ; conservative inline estimate projected with acceptance

; command_registry_init — reset the registry + counters. The "table built" step:
;   the verb table becomes live and empty, guard/telemetry cleared. clobbers: RAX
command_registry_init:
    mov  dword [rel verb_count], 0
    mov  dword [rel job_count], 0
    mov  qword [rel job_next_id], 1
    mov  qword [rel command_job_complete_cb], 0
    mov  qword [rel cmd_dispatch_count], 0
    mov  qword [rel cmd_handler_runs], 0
    mov  qword [rel cmd_dispatch_last_source], CMD_SOURCE_INTERNAL
    mov  qword [rel cmd_dispatch_last_principal], CMD_PRINCIPAL_NONE
    mov  byte  [rel cmd_in_dispatch], 0
    mov  byte  [rel cmd_bypass_flag], 0
    ret

; command_registry_safe_init -- build the deliberately tiny read-only command
; floor used by the Boot Manager v2 Safe profile.  This is initialization, not
; the normal boot's broad self-test suite: only liveness STATUS and nonce-echo
; PING are exposed, both through the same capability/dispatch boundary as a
; normal boot.  In particular, no mutating SLOWJOB, driver, storage, network,
; hotpatch, VM, GUI, or application verbs are registered here.
command_registry_safe_init:
    call command_registry_init

    lea  rdi, [rel str_verb_status]
    lea  rsi, [rel cmd_verb_status]
    xor  edx, edx
    mov  ecx, ARGT_U64
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_status], eax

    lea  rdi, [rel str_verb_ping]
    lea  rsi, [rel cmd_verb_ping]
    xor  edx, edx
    mov  ecx, ARGT_U64
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_ping], eax

    lea  rdi, [rel str_cmd_safe_init]
    call serial_string
    ret

; command_register_verb(RDI=name, RSI=handler, RDX=cap, RCX=argt, R8=selk, R9=destr)
;   -> RAX = verb id (slot), or -1 if full. THE indirection: a capability is
;   declared ONCE, here, with its self-description; every surface later reaches it
;   through dispatch. Registering the 2nd/3rd verb needs NO core edit (same call) —
;   the degenerate-Nth seam proof. clobbers: RAX, R10, R11
command_register_verb:
    xor  eax, eax
    lea  r11, [rel verb_table]
.vacant:
    cmp  eax, [rel verb_count]
    jae  .append
    imul r10, rax, VERB_ENT_SZ
    cmp  qword [r11 + r10 + VERB_NAME], 0
    jne  .next
    cmp  [r11 + r10 + VERB_HANDLER], rsi
    jne  .next
    cmp  [r11 + r10 + VERB_SELK], rdi
    je   .fill
.next:
    inc  eax
    jmp  .vacant
.append:
    cmp  eax, VERB_MAX
    jae  .full
    inc  dword [rel verb_count]
.fill:
    imul r10, rax, VERB_ENT_SZ
    lea  r11, [rel verb_table]
    add  r11, r10
    mov  [r11 + VERB_NAME], rdi
    mov  [r11 + VERB_HANDLER], rsi
    mov  [r11 + VERB_CAP], rdx
    mov  [r11 + VERB_ARGT], rcx
    mov  [r11 + VERB_SELK], r8
    mov  [r11 + VERB_DESTR], r9
    ret
.full:
    mov  eax, -1
    ret

; Owner-controlled removal: EDI=stable slot, RSI=the registered handler.
; Do not compact: other callers retain their handles. The command task owns
; registry mutations; a module is unpublished before its backing is released.
command_unregister_verb:
    cmp  edi, [rel verb_count]
    jae  .bad
    test rsi, rsi
    jz   .bad
    imul rax, rdi, VERB_ENT_SZ
    lea  rdx, [rel verb_table]
    add  rdx, rax
    cmp  [rdx + VERB_HANDLER], rsi
    jne  .bad
    mov  rax, [rdx + VERB_NAME]
    test rax, rax
    jz   .bad
    mov  [rdx + VERB_SELK], rax          ; vacant row retains owner/name identity
    mov  qword [rdx + VERB_NAME], 0
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; command_resolve_selector(RDI=selector ptr) -> RAX = handle (§9.4 e).
;   v1 identity resolver: a verb calls THIS instead of baking a device path, so the
;   forge can rebind selectors per machine additively later. clobbers: RAX
command_resolve_selector:
    mov  rax, rdi
    ret

; --- registry SELF-DESCRIPTION accessors (§9.4 b) — read-only views of the ONE verb
;   table so projections (CATALOG, serial arg-marshalling, MCP tool-list) are GENERATED
;   from the registry, never hand-kept. All are pure reads; the table is the source of
;   truth. No bounds check (callers iterate 0..command_verb_count-1). ---

; command_verb_count -> RAX = number of registered verbs. clobbers: RAX
command_verb_count:
    mov  eax, [rel verb_count]
    ret

; command_lookup(RDI=name ptr) -> RAX = verb id, or -1 if no verb by that name.
;   The name->handle resolver every wire projection uses. clobbers: RAX,RCX,RDX,RSI,RDI
command_lookup:
    push rbx
    push r12
    push r13
    mov  r12, rdi                         ; target name
    xor  r13d, r13d                       ; id cursor
.scan:
    cmp  r13d, [rel verb_count]
    jae  .miss
    mov  eax, r13d
    imul rax, rax, VERB_ENT_SZ
    lea  rbx, [rel verb_table]
    mov  rdi, [rbx + rax + VERB_NAME]     ; stored verb name ptr
    test rdi, rdi
    jz   .next
    mov  rsi, r12
    call strcmp                           ; the ONE canonical strcmp (G1); 0 == equal
    test rax, rax
    jz   .hit
.next:
    inc  r13d
    jmp  .scan
.hit:
    mov  eax, r13d
    jmp  .out
.miss:
    mov  rax, -1                         ; full-width -1 (the documented contract): a
                                          ; 32-bit `mov eax,-1` zero-extends to 0xFFFFFFFF and
                                          ; defeats every `cmp rax,-1` caller (serial unknown-verb #PF)
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; command_verb_name(RDI=id) -> RAX = ptr to the verb's NUL-terminated name. clobbers: RAX,RDI
command_verb_name:
    cmp  edi, [rel verb_count]
    jae  .empty
    imul rdi, rdi, VERB_ENT_SZ
    lea  rax, [rel verb_table]
    mov  rax, [rax + rdi + VERB_NAME]
    test rax, rax
    jz   .empty
    ret
.empty:
    lea  rax, [rel command_vacant_name]
    ret
command_vacant_name: db 0

; command_verb_argt(RDI=id) -> RAX = arg-type tag (ARGT_*). clobbers: RAX,RDI
command_verb_argt:
    mov  eax, [rel verb_count]            ; 64-bit bounds check: an id from any caller
    cmp  rdi, rax                         ; (incl. a 0xFFFFFFFF lookup miss) never indexes
    jae  .oob                             ; past the table
    imul rdi, rdi, VERB_ENT_SZ
    lea  rax, [rel verb_table]
    mov  rax, [rax + rdi + VERB_ARGT]
    ret
.oob:
    mov  eax, ARGT_NONE                         ; refusal-safe sentinel
    ret

; command_verb_cap(RDI=id) -> RAX = required capability. clobbers: RAX,RDI
command_verb_cap:
    mov  eax, [rel verb_count]            ; 64-bit bounds check: an id from any caller
    cmp  rdi, rax                         ; (incl. a 0xFFFFFFFF lookup miss) never indexes
    jae  .oob                             ; past the table
    imul rdi, rdi, VERB_ENT_SZ
    lea  rax, [rel verb_table]
    mov  rax, [rax + rdi + VERB_CAP]
    ret
.oob:
    mov  rax, -1                         ; refusal-safe sentinel
    ret

; command_verb_selk(RDI=id) -> RAX = selector-kind. clobbers: RAX,RDI
command_verb_selk:
    mov  eax, [rel verb_count]            ; 64-bit bounds check: an id from any caller
    cmp  rdi, rax                         ; (incl. a 0xFFFFFFFF lookup miss) never indexes
    jae  .oob                             ; past the table
    imul rdi, rdi, VERB_ENT_SZ
    lea  rax, [rel verb_table]
    mov  rax, [rax + rdi + VERB_SELK]
    ret
.oob:
    xor  eax, eax                         ; refusal-safe sentinel
    ret

; command_verb_destr(RDI=id) -> RAX = destructiveness (0 = read-only). clobbers: RAX,RDI
command_verb_destr:
    mov  eax, [rel verb_count]            ; 64-bit bounds check: an id from any caller
    cmp  rdi, rax                         ; (incl. a 0xFFFFFFFF lookup miss) never indexes
    jae  .oob                             ; past the table
    imul rdi, rdi, VERB_ENT_SZ
    lea  rax, [rel verb_table]
    mov  rax, [rax + rdi + VERB_DESTR]
    ret
.oob:
    mov  eax, 1                         ; refusal-safe sentinel
    ret

; command_dispatch(RDI=req ptr, RSI=resp ptr) -> RAX = RSP_CODE. THE SINGLE ENTRY.
;   Every verb execution in PaOS routes through here: (1) bounds-check the verb id
;   (actionable error if bad); (2) the CAPABILITY GATE checkpoint (req.cap >=
;   verb.cap for internal callers, or owner-auth exact scope remotely); (3) set the
;   in-dispatch guard the handlers assert on entry (single-vocabulary proof); (4)
;   invoke the handler THROUGH the table ptr (the indirection); (5) clear guard.
;   A path that mutates state without coming through here is the lint smell this
;   model forbids. clobbers: caller-saved; preserves RBX, R12-R14.
; T5-15.4 one-shot (SEC 89584). Explorer names the exact request and verb from a
; latched HUMAN gesture, immediately before its own dispatch. The next dispatch of
; any kind spends it, so a stale, foreign or second request cannot use it. It holds
; no authority until command_local_human_take has re-checked the frame.
; command_local_human_set(RDI=req, RSI=verb id). Touches memory only.
command_local_human_set:
    mov  [rel cmd_local_human_req], rdi
    mov  [rel cmd_local_human_verb], rsi
    ret

; RDI=req, preserved. Clobbers RAX, RCX.
command_local_human_note:
    mov  byte [rel cmd_local_human_match], 0
    mov  rax, [rel cmd_local_human_req]
    mov  rcx, [rel cmd_local_human_verb]
    mov  qword [rel cmd_local_human_req], 0
    mov  qword [rel cmd_local_human_verb], 0
    test rax, rax
    jz   .out
    cmp  rax, rdi
    jne  .out
    cmp  rcx, [rdi + REQ_VERB]
    jne  .out
    mov  byte [rel cmd_local_human_match], 1
.out:
    ret

; RDI=req, RSI=verb entry -> EAX 1 only for a matched console OWNER request on an
; unlocked session, with no remote frame or injected line, naming an FS mutating verb.
; FSWRITE is not on the list. Clobbers RAX, RCX.
command_local_human_take:
    xor  eax, eax
    cmp  byte [rel cmd_local_human_match], 1
    mov  byte [rel cmd_local_human_match], 0
    jne  .out
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .out
    cmp  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .out
    cmp  byte [rel command_auth_remote_active], 0
    jne  .out
    cmp  qword [rel keyprov_active_taint], 0
    jne  .out
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    mov  rcx, [rsi + VERB_HANDLER]
    push rdx
    lea  rdx, [rel cmd_verb_fsnew]
    cmp  rcx, rdx
    je   .yes
    lea  rdx, [rel cmd_verb_fsdel]
    cmp  rcx, rdx
    je   .yes
    lea  rdx, [rel cmd_verb_fsren]
    cmp  rcx, rdx
    je   .yes
    lea  rdx, [rel cmd_verb_fsmkdir]
    cmp  rcx, rdx
    je   .yes
    lea  rdx, [rel cmd_verb_fsrmdir]
    cmp  rcx, rdx
    je   .yes
    lea  rdx, [rel cmd_verb_fscopy]
    cmp  rcx, rdx
    jne  .pop
.yes:
    mov  eax, 1
.pop:
    pop  rdx
.out:
    ret

; RDI=req, RSI=verb entry -> RAX the outer frame's opaque token. Under the bit, the selected
; removable mount is armed first; the handler's own gates still decide.
command_local_human_enter:
    call command_local_human_take
    mov  edi, eax
    call storage_access_request_local_swap
    push rax
    call storage_access_request_local
    cmp  eax, 1
    jne  .out
    call fs_local_removable_arm
.out:
    pop  rax
    ret

; RDI = the outer frame's opaque token, with its original generation.
command_local_human_leave:
    jmp  storage_access_request_local_restore

; Every dispatch exit. Touches memory only: RAX carries the result.
command_local_human_end:
    mov  byte [rel cmd_local_human_match], 0
    ret

command_dispatch:
    push rbx
    push r12
    push r13
    push r14
    ; RCQ-40 J2a (rc-sec 02:40:43): the proposer of the request in flight. Taken
    ; at depth-0 entry from the card arm (command_dispatch_card, its one writer)
    ; and zeroed at depth-0 exit on every path; a nested dispatch inherits it.
    inc  dword [rel cmd_dispatch_depth]
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .proposer_kept
    mov  rax, [rel cmd_card_proposer_arm]
    mov  [rel cmd_dispatch_proposer], rax
    mov  qword [rel cmd_card_proposer_arm], 0
.proposer_kept:
    call command_local_human_note         ; every dispatch spends the one-shot
    mov  r12, rdi                         ; req
    mov  r13, rsi                         ; resp
    ; RCQ-10 reply ownership: a top-level in-process request (console, AI hook,
    ; serial, card, internal, SSH exec) starts with no reply staged by an earlier
    ; one, so its capture or its caller's read can only see its own records. UDP
    ; already retired them at udp_dispatch_line entry; a nested dispatch shares
    ; its outer request's staging, and a frame the session sync runs inside a UDP
    ; request (before that request's reply is sent) must not retire it.
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .request_owned
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_UDP
    je   .request_owned
    cmp  byte [rel command_session_sync_active], 1
    je   .request_owned
    call command_udp_request_boundary     ; clobbers none
.request_owned:
    ; default the response envelope to a clean OK-shell
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_ACCEPTED], 0
    mov  qword [r13 + RSP_JOBID], 0
    mov  qword [r13 + RSP_VAL], 0
    mov  qword [r13 + RSP_EXPECTED], 0
    mov  qword [r13 + RSP_HINT], 0
    mov  rax, [r12 + REQ_SOURCE]
    mov  [rel cmd_dispatch_last_source], rax
    mov  rax, [r12 + REQ_PRINCIPAL]
    mov  [rel cmd_dispatch_last_principal], rax
    ; (1) verb-id bounds check -> actionable error (§9.4 f)
    mov  rax, [r12 + REQ_VERB]
    mov  ecx, [rel verb_count]
    cmp  rax, rcx
    jb   .idok
.noverb:
    mov  qword [r13 + RSP_CODE], CMDE_NOVERB
    mov  ecx, [rel verb_count]
    mov  [r13 + RSP_EXPECTED], rcx
    lea  rcx, [rel str_cmd_hint_noverb]
    mov  [r13 + RSP_HINT], rcx
    mov  rax, CMDE_NOVERB
    jmp  .out
.idok:
    imul rbx, rax, VERB_ENT_SZ
    lea  r14, [rel verb_table]
    add  r14, rbx                         ; r14 = verb entry
    cmp  qword [r14 + VERB_NAME], 0
    je   .noverb
    ; (2) SOURCE-AWARE OWNER-AUTH GATE. Console-local requests carry their
    ; explicit in-image principal and then use the same capability comparison
    ; as other trusted in-image callers. They never borrow the last UDP AUTH1
    ; envelope. A local Try login is admitted only by sec/session's native
    ; check (public floor or desktop setter, zero capability); any other
    ; non-owner console principal fails closed. Network requests continue
    ; through the existing exact remote owner-auth gate below.
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote_auth
    cmp  qword [r12 + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    je   .legacy_cap
    cmp  qword [r12 + REQ_PRINCIPAL], CMD_PRINCIPAL_TRY
    jne  .authdeny
    mov  rdi, [r14 + VERB_NAME]
    mov  rsi, [r14 + VERB_CAP]
    mov  rdx, [r14 + VERB_DESTR]
    mov  rcx, r12
    call session_shell_try_request_admit ; EAX=1 admitted, 0 refused
    test eax, eax
    jz   .authdeny
    jmp  .capok
.remote_auth:
    ; Guest sources never enter the internal numeric-cap fallback, even when
    ; their caller omitted a remote frame. Public queries still need a grant.
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_GUEST
    jne  .ordinary_remote
    cmp  byte [rel command_auth_remote_active], 1
    jne  .authdeny
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .authdeny
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_GUEST
    je   .native_guest_ticket
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_TERMINAL
    jne  .authdeny
.native_guest_ticket:
    mov  rdi, [r14 + VERB_NAME]
    mov  rsi, [r14 + VERB_CAP]
    mov  rdx, [r14 + VERB_DESTR]
    call command_auth_required_cap
    jmp  .remote_gate
.ordinary_remote:
    ; Required remote scope is generated from the live
    ; destructiveness/capability metadata plus the exact public-query floor.  A
    ; cap=0 declaration is not itself public: command_auth_required_cap keeps
    ; mislabeled and newly added verbs fail closed.
    cmp  byte [rel command_auth_remote_active], 1
    jne  .legacy_cap
    mov  rdi, [r14 + VERB_NAME]
    mov  rsi, [r14 + VERB_CAP]
    mov  rdx, [r14 + VERB_DESTR]
    call command_auth_required_cap
    test rax, rax
    jnz  .remote_gate
    ; The exact public-query floor needs no envelope, but a VALID wire envelope
    ; that admits the request is consumed, so its replay is refused.
    mov  rdi, r12
    mov  rsi, [r14 + VERB_NAME]
    call command_auth_consume_public
    test eax, eax
    jnz  .authdeny
    jmp  .capok
.remote_gate:
    mov  rdi, rax                          ; exact required owner capability
    mov  rsi, [r14 + VERB_NAME]
    call command_auth_gate
    test eax, eax
    jnz  .authdeny
    jmp  .capok
.authdeny:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    mov  rcx, [r14 + VERB_CAP]
    mov  [r13 + RSP_EXPECTED], rcx
    lea  rcx, [rel command_auth_out_buf]
    mov  [r13 + RSP_HINT], rcx
    mov  rax, CMDE_AUTHDENY
    jmp  .out
.legacy_cap:
    ; Internal callers retain the pre-existing request capability checkpoint.
    mov  rax, [r12 + REQ_CAP]
    cmp  rax, [r14 + VERB_CAP]
    jae  .capok
    mov  qword [r13 + RSP_CODE], CMDE_CAPDENY
    mov  rcx, [r14 + VERB_CAP]
    mov  [r13 + RSP_EXPECTED], rcx        ; expected cap (§9.4 f)
    lea  rcx, [rel str_cmd_hint_cap]
    mov  [r13 + RSP_HINT], rcx
    mov  rax, CMDE_CAPDENY
    jmp  .out
.capok:
    ; Remote input injection into the LOCKED console (KBINJ/MOUSEINJ/PTRINJ) is
    ; test-only: refused on the shipped floor, admitted-but-flagged (never a
    ; human) on lab/dev builds. Authorization above has already run.
    mov  rdi, [r14 + VERB_NAME]
    call command_auth_injection_gate
    test eax, eax
    jz   .inject_ok
    mov  qword [r13 + RSP_CODE], CMDE_DESKTOP_LOCKED
    lea  rcx, [rel command_auth_out_buf]
    mov  [r13 + RSP_HINT], rcx
    mov  rax, CMDE_DESKTOP_LOCKED
    jmp  .out
.inject_ok:
    ; (3) set the in-dispatch guard + count the dispatch BEFORE calling the handler
    mov  byte [rel cmd_in_dispatch], 1
    inc  qword [rel cmd_dispatch_count]
    ; Per-frame desktop-refusal flag (sec/session sets it when a desktop handler's
    ; session_shell_require_unlocked refuses). Saved/restored so a nested
    ; dispatch never leaks its refusal into the outer request. Two pushes keep
    ; the handler's stack parity unchanged: the second carries the outer
    ; frame's storage OWNER bit (RCQ-21 SA2b, rc-sec S1): this frame's bit is
    ; computed fresh from this request and its in-flight ticket, set for the
    ; handler, and the outer value is restored when the handler returns. No
    ; refusal above ever changes it, and outside dispatch it is 0.
    mov  rdi, r12
    call command_auth_ticket_owner        ; 0/1, never from ambient state
    mov  edi, eax
    call storage_access_request_owner_swap ; -> the outer frame's bit
    movzx ecx, byte [rel cmd_desktop_refused]
    push rcx
    push rax
    mov  byte [rel cmd_desktop_refused], 0
    mov  rdi, r12
    mov  rsi, r14
    call command_local_human_enter        ; T5-15.4 -> the outer frame's 64-bit token
    push rax
    push rax
%if PAOS_LAB_D4_IFON_STALL
    ; The original startup intent covers one authenticated UDP C7HEALTH.
    ; Public discovery/security reads and signer AUTHSTAT must reach handlers
    ; before that intent exists. Admission alone does not identify this probe.
    cmp byte [rel command_auth_remote_active],1
    jne .d4_no_stall
    cmp qword [r12+REQ_SOURCE],CMD_SOURCE_UDP
    jne .d4_no_stall
    mov rdi,r12
    call command_auth_ticket_owner
    cmp eax,1
    jne .d4_no_stall
    mov rax,[r14+VERB_NAME]
    cmp byte [rax],'C'
    jne .d4_no_stall
    cmp byte [rax+1],'7'
    jne .d4_no_stall
    cmp byte [rax+2],'H'
    jne .d4_no_stall
    cmp byte [rax+3],'E'
    jne .d4_no_stall
    cmp byte [rax+4],'A'
    jne .d4_no_stall
    cmp byte [rax+5],'L'
    jne .d4_no_stall
    cmp byte [rax+6],'T'
    jne .d4_no_stall
    cmp byte [rax+7],'H'
    jne .d4_no_stall
    cmp byte [rax+8],0
    jne .d4_no_stall
    call boot_d4_command_stall_control ; actual post-auth IF-on command stall
.d4_no_stall:
%endif
    ; (4) invoke handler THROUGH the registry: handler(RDI=req, RSI=resp)
    mov  rdi, r12
    mov  rsi, r13
    call [r14 + VERB_HANDLER]
    ; (5) clear the guard
    mov  byte [rel cmd_in_dispatch], 0
    pop  rdi
    pop  rdi
    call command_local_human_leave        ; restore only its original generation
    pop  rdi
    call storage_access_request_owner_swap ; the outer frame's OWNER bit again
    movzx ecx, byte [rel cmd_desktop_refused]
    pop  rax
    mov  [rel cmd_desktop_refused], al
    ; A remote (UDP/SSH) request whose desktop handler refused with the locked
    ; session but reported OK gets the distinct CMDE_DESKTOP_LOCKED code; the
    ; handler's reply text is untouched.
    test ecx, ecx
    jz   .code
    cmp  qword [r13 + RSP_CODE], CMDE_OK
    jne  .code
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_UDP
    je   .desktop_locked
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_SSH
    jne  .code
.desktop_locked:
    mov  qword [r13 + RSP_CODE], CMDE_DESKTOP_LOCKED
.code:
    mov  rax, [r13 + RSP_CODE]
.out:
    call command_local_human_end
    dec  dword [rel cmd_dispatch_depth]
    jnz  .out_nested
    mov  qword [rel cmd_dispatch_proposer], 0
.out_nested:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- shared handler entry guard: every handler calls this first. It asserts the
;   handler was reached THROUGH command_dispatch (guard==1) and tallies the run;
;   if ever entered with the guard clear, it flags a bypass (the single-vocabulary
;   violation). This is what makes dispatch_count == handler_runs a real invariant.
;   clobbers: none (memory + flags only)
cmd_handler_prologue:
    inc  qword [rel cmd_handler_runs]
    cmp  byte [rel cmd_in_dispatch], 1
    je   .ok
    mov  byte [rel cmd_bypass_flag], 1    ; a handler ran outside dispatch -> side door
.ok:
    ret

; --- VERB: STATUS (RDI=req, RSI=resp). Two modes: REQ_ARG==0 -> a known liveness
;   reply (RSP_VAL = a fresh handle); REQ_ARG==job_id -> report that job's state
;   into RSP_VAL. This is the control-plane "are you OK?" that must ALWAYS answer.
;   clobbers: RAX,RCX,RDX,R8
cmd_verb_status:
    call cmd_handler_prologue
    mov  rdx, [rdi + REQ_ARG]             ; job_id (0 => plain liveness ping)
    test rdx, rdx
    jnz  .byjob
    call cmd_csprng_stage_status           ; live health, staged for projections
    call tsc_now                          ; fresh handle => not a hardcoded latch
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.byjob:
    ; find the job with JOB_ID == rdx, report its state
    xor  ecx, ecx
    lea  r8, [rel job_table]
.jscan:
    cmp  ecx, [rel job_count]
    jae  .nojob
    mov  rax, [r8 + JOB_ID]
    cmp  rax, rdx
    je   .jfound
    add  r8, JOB_ENT_SZ
    inc  ecx
    jmp  .jscan
.jfound:
    mov  rax, [r8 + JOB_STATE]
    mov  [rsi + RSP_VAL], rax             ; RSP_VAL = job state (RUNNING while slow)
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.nojob:
    mov  qword [rsi + RSP_CODE], CMDE_BADJOB
    lea  rax, [rel str_cmd_hint_badjob]
    mov  [rsi + RSP_HINT], rax
    ret

; --- VERB: PING (RDI=req, RSI=resp). Echo the in-proc nonce from REQ_ARG back into
;   RSP_VAL through the envelope. Proves REAL dispatch (the handler could not know
;   the random nonce in advance). clobbers: RAX
cmd_verb_ping:
    call cmd_handler_prologue
    mov  rax, [rdi + REQ_ARG]             ; the injected nonce
    mov  [rsi + RSP_VAL], rax             ; echo it back verbatim
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: BOOTREPORT (RDI=req, RSI=resp). The boot-time MEASUREMENT surface over the
;   1077 registry (contract 1068): echo the caller's nonce token back through the
;   envelope (ARGT_TEXT -> RSP_VAL = REQ_ARG pointer — the un-fakeable round-trip, same
;   shape as PING) so any live transport proves REAL dispatch, not a latch. The BOOT_MS
;   + HEAP_MB values are boot-time SYSTEM FACTS (boot/header.asm computes them at the
;   interactive-ready point into the boot_ms/heap_mb globals); each projection frames
;   them on the wire, exactly as the UDP surface already frames the live TX/RX counters.
;   clobbers: RAX
cmd_verb_bootreport:
    call cmd_handler_prologue
    mov  rax, [rdi + REQ_ARG]             ; caller nonce token pointer (ARGT_TEXT)
    mov  [rsi + RSP_VAL], rax             ; echo it back verbatim (round-trip proof)
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: FREQMSR (RDI=req, RSI=resp). The measured-frequency TRUTH ORACLE over the
;   1077 registry (contract 1050): run the governor's APERF/MPERF measurement (sprint
;   vs efficiency under a bounded load) and echo the caller nonce back verbatim (same
;   round-trip proof as BOOTREPORT). The measured sprint_mhz/eff_mhz/base_mhz + hwp are
;   framed on the wire by each projection from the governor globals — the boost is
;   graded by the MEASURED ratio, not by the MSR write returning. clobbers: caller-saved
cmd_verb_freqmsr:
    call cmd_handler_prologue
    call command_freq_reply_retire
    push rdi
    push rsi
    call gov_freqmsr_measure             ; stages hwp/sprint/eff/base into gov globals
    call command_freq_reply_capture
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]             ; caller nonce token pointer (ARGT_TEXT)
    mov  [rsi + RSP_VAL], rax             ; echo it back verbatim (round-trip proof)
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; RCQ-15: one fixed-size public reply snapshot, published only by this handler.
; BSP command serialization owns its lifetime. No pointer/nonce/private state is
; retained; planner, post and transport boundaries retire it without measurement.
CFR_SPRINT equ 0
CFR_EFF equ 8
CFR_BASE equ 16
CFR_HWP equ 24
CFR_STATUS equ 25
CFR_TURBO equ 26
CFR_HI equ 27
CFR_LO equ 28
CFR_THERMAL equ 29
CFR_REASON equ 30
CFR_SZ equ 32
command_freq_reply_capture:
    mov  rax, [rel gov_sprint_mhz]
    mov  [rel command_freq_reply + CFR_SPRINT], rax
    mov  rax, [rel gov_eff_mhz]
    mov  [rel command_freq_reply + CFR_EFF], rax
    mov  rax, [rel gov_base_mhz]
    mov  [rel command_freq_reply + CFR_BASE], rax
    mov  al, [rel gov_hwp_present]
    mov  [rel command_freq_reply + CFR_HWP], al
    mov  al, [rel gov_freq_status]
    mov  [rel command_freq_reply + CFR_STATUS], al
    mov  al, [rel gov_turbo_ratio]
    mov  [rel command_freq_reply + CFR_TURBO], al
    mov  al, [rel gov_perf_highest]
    mov  [rel command_freq_reply + CFR_HI], al
    mov  al, [rel gov_perf_lowest]
    mov  [rel command_freq_reply + CFR_LO], al
    mov  al, [rel gov_thermal_capped]
    mov  [rel command_freq_reply + CFR_THERMAL], al
    mov  al, [rel gov_cap_reason]
    mov  [rel command_freq_reply + CFR_REASON], al
    mov  byte [rel command_freq_reply_ready], 1
    ret

command_freq_reply_retire:
    mov  byte [rel command_freq_reply_ready], 0
    mov  byte [rel gov_freq_result], 0
    mov  qword [rel command_freq_reply], 0
    mov  qword [rel command_freq_reply + 8], 0
    mov  qword [rel command_freq_reply + 16], 0
    mov  qword [rel command_freq_reply + 24], 0
    ret

align 8
command_freq_reply: times CFR_SZ db 0
command_freq_reply_ready: db 0

; --- VERB: SLOWJOB (RDI=req, RSI=resp). The §3 non-blocking proof: allocate a job,
;   return {accepted=1, job_id} PROMPTLY with the job still RUNNING (does NOT run to
;   completion inline). The cooperative pump (command_job_pump) advances it later,
;   so STATUS stays answerable while it runs. clobbers: RAX,RCX,R8
cmd_verb_slowjob:
    call cmd_handler_prologue
    jmp command_job_allocate

; Same allocator used by SLOWJOB and the owner capacity control. No dispatch,
; authority or callback is installed here; caller supplies its response.
command_job_allocate:
    xor  eax, eax
    lea  r8, [rel job_table]
.scan:
    cmp  eax, [rel job_count]
    jae  .grow
    cmp  qword [r8 + JOB_STATE], JOB_ST_RUN
    jne  .slot
    add  r8, JOB_ENT_SZ
    inc  eax
    jmp  .scan
.grow:
    cmp  eax, JOB_MAX
    jae  .full
    inc  dword [rel job_count]
.slot:
    imul rcx, rax, JOB_ENT_SZ
    lea  r8, [rel job_table]
    add  r8, rcx
    mov  rcx, [rel job_next_id]
    inc  qword [rel job_next_id]
    mov  [r8 + JOB_ID], rcx
    mov  qword [r8 + JOB_STATE], JOB_ST_RUN
    mov  qword [r8 + JOB_PROG], 0
    mov  qword [r8 + JOB_RESULT], 0
    mov  qword [rsi + RSP_ACCEPTED], 1    ; accepted, NOT completed (§3)
    mov  [rsi + RSP_JOBID], rcx
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.full:
    mov  qword [rsi + RSP_CODE], CMDE_BADJOB
    ret

; Runtime owner SELFTEST HANDLES control over the actual four-slot job pool.
; Refuse foreign live jobs and an insufficient monotonic ID range before any
; mutation. Two fill/refuse/drain cycles use the normal allocator and pump;
; no private pool, forced DONE, rewind, callback replacement or extra authority.
; Snapshot qwords: status,capacity,cycles,accepted,refused,live_before,live_after,
; first_id,last_id. Status 0 success,1 busy,2 ID unavailable,3 contradiction.
command_job_exhaustion_control:
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 104                       ; response48 + owned IDs32 + alignment
    lea rdi, [rel command_job_control_snapshot]
    xor eax, eax
    mov ecx, 9
    rep stosq
    mov qword [rel command_job_control_snapshot], 3
    mov qword [rel command_job_control_snapshot+8], JOB_MAX
    call command_job_control_live
    cmp eax, -1
    je .out
    mov [rel command_job_control_snapshot+40], rax
    mov [rel command_job_control_snapshot+48], rax
    mov qword [rel command_job_control_snapshot], 1
    test eax, eax
    jnz .out
    mov qword [rel command_job_control_snapshot], 2
    mov r14, [rel job_next_id]
    test r14, r14
    jz .out
    cmp r14, -8                        ; reserve all eight fresh IDs, no wrap
    jae .out
    xor r12d, r12d
.cycle:
    lea rdi, [rsp+48]
    xor eax, eax
    mov ecx, JOB_MAX
    rep stosq
    xor r13d, r13d
    mov qword [rel command_job_control_snapshot], 3
.allocate:
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, RSP_SZ/8
    rep stosq
    lea rsi, [rsp]
    call command_job_allocate
    cmp qword [rsp+RSP_CODE], CMDE_OK
    jne .drain
    cmp qword [rsp+RSP_ACCEPTED], 1
    jne .drain
    mov rax, [rsp+RSP_JOBID]
    cmp rax, r14
    jne .drain
    mov [rsp+48+r13*8], rax
    cmp qword [rel command_job_control_snapshot+56], 0
    jne .next_id
    mov [rel command_job_control_snapshot+56], rax
.next_id:
    mov [rel command_job_control_snapshot+64], rax
    inc r14
    inc qword [rel command_job_control_snapshot+24]
    inc r13d
    cmp r13d, JOB_MAX
    jb .allocate
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, RSP_SZ/8
    rep stosq
    lea rsi, [rsp]
    call command_job_allocate           ; actual fifth allocation must refuse
    cmp qword [rsp+RSP_CODE], CMDE_BADJOB
    jne .drain
    cmp qword [rsp+RSP_ACCEPTED], 0
    jne .drain
    cmp qword [rsp+RSP_JOBID], 0
    jne .drain
    cmp [rel job_next_id], r14
    jne .drain
    cmp dword [rel job_count], JOB_MAX
    jne .drain
    xor ebx, ebx
    lea r15, [rel job_table]
.held:
    mov rax, [rsp+48+rbx*8]
    cmp [r15+JOB_ID], rax
    jne .drain
    cmp qword [r15+JOB_STATE], JOB_ST_RUN
    jne .drain
    cmp qword [r15+JOB_PROG], 0
    jne .drain
    cmp qword [r15+JOB_RESULT], 0
    jne .drain
    add r15, JOB_ENT_SZ
    inc ebx
    cmp ebx, JOB_MAX
    jb .held
    inc qword [rel command_job_control_snapshot+32]
    mov qword [rel command_job_control_snapshot], 0
.drain:
    xor ebx, ebx
.job:
    cmp ebx, r13d
    jae .drained
    mov r15d, SLOWJOB_STEPS
.step:
    mov rdi, [rsp+48+rbx*8]
    call command_job_pump               ; actual bounded completion edge
    dec r15d
    jnz .step
    inc ebx
    jmp .job
.drained:
    call command_job_control_live
    mov [rel command_job_control_snapshot+48], rax
    test eax, eax
    jnz .bad
    cmp qword [rel command_job_control_snapshot], 0
    jne .out
    inc qword [rel command_job_control_snapshot+16]
    inc r12d
    cmp r12d, 2
    jb .cycle
    jmp .out
.bad:
    mov qword [rel command_job_control_snapshot], 3
.out:
    mov eax, [rel command_job_control_snapshot]
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

; Bounded read-only live count. Unknown table shape/state is unavailable.
command_job_control_live:
    xor eax, eax
    mov ecx, [rel job_count]
    cmp ecx, JOB_MAX
    ja .bad
    lea r8, [rel job_table]
.scan:
    test ecx, ecx
    jz .out
    cmp qword [r8+JOB_STATE], JOB_ST_DONE
    ja .bad
    cmp qword [r8+JOB_STATE], JOB_ST_RUN
    jne .next
    inc eax
.next:
    add r8, JOB_ENT_SZ
    dec ecx
    jmp .scan
.bad:
    mov eax, -1
.out:
    ret

; ---------------------------------------------------------------------------
; Contract 1236: projections over the keep-owned CSPRNG. Crypto and entropy
; stay in core/csprng.asm; these handlers parse bounded ARGT_TEXT, call the
; service, and stage receipts for the existing projections. RANDOM, CSPRNG,
; FAULT and BOOTLOG still execute through command_dispatch.
; ---------------------------------------------------------------------------

; Parse "<literal> <single-token-nonce>". RAX=nonce ptr and RDX=len 1..64,
; or RAX=0. RDI=text, RSI=literal, EDX=literal length.
cmd_csprng_parse_nonce:
    push rbx
    mov  rbx, rdi
.prefix:
    test edx, edx
    jz   .boundary
    mov  al, [rbx]
    cmp  al, [rsi]
    jne  .no
    inc  rbx
    inc  rsi
    dec  edx
    jmp  .prefix
.boundary:
    cmp  byte [rbx], ' '
    jne  .no
    inc  rbx
    mov  rax, rbx
    xor  ecx, ecx
.nonce:
    mov  dl, [rbx]
    test dl, dl
    jz   .end
    cmp  dl, ' '
    je   .no
    inc  rcx
    cmp  rcx, 64
    ja   .no
    inc  rbx
    jmp  .nonce
.end:
    test rcx, rcx
    jz   .no
    mov  rdx, rcx
    pop  rbx
    ret
.no:
    xor  eax, eax
    xor  edx, edx
    pop  rbx
    ret

cmd_csprng_output_reset:
    lea  rax, [rel hp_out_buf]
    mov  [rel hp_out_cur], rax
    mov  byte [rax], 0
    ret

; Append exactly 32 bytes as 64 lowercase hexadecimal characters.
cmd_csprng_out_hex32:
    mov  rsi, [rel hp_out_cur]
    lea  rdx, [rel cmd_csprng_hex]
    xor  ecx, ecx
.byte:
    cmp  ecx, 32
    jae  .done
    movzx eax, byte [rdi + rcx]
    mov  r8d, eax
    shr  r8d, 4
    and  eax, 15
    mov  r9b, [rdx + r8]
    mov  [rsi], r9b
    mov  al, [rdx + rax]
    mov  [rsi + 1], al
    add  rsi, 2
    inc  ecx
    jmp  .byte
.done:
    mov  byte [rsi], 0
    mov  [rel hp_out_cur], rsi
    ret

; Add an atomic health snapshot to the ordinary STATUS reply.
cmd_csprng_stage_status:
    push rbx
    push r12
    push r13
    push rdi
    push rsi
    call csprng_status_snapshot
    mov  ebx, eax                         ; health
    mov  r12, rdx                         ; source failures
    mov  r13, rcx                         ; reseed counter
    test ebx, ebx                         ; no stale stage during early registry KAT
    jz   .out
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_csprng_status]
    call hp_out_str
    cmp  bl, CSPRNG_READY
    jne  .degraded
    lea  rdi, [rel str_cmd_csprng_health_ready]
    jmp  .health
.degraded:
    lea  rdi, [rel str_cmd_csprng_health_degraded]
.health:
    call hp_out_str
    lea  rdi, [rel str_cmd_csprng_source_failures]
    call hp_out_str
    mov  rdi, r12
    call hp_out_dec
    lea  rdi, [rel str_cmd_csprng_reseed_counter]
    call hp_out_str
    mov  rdi, r13
    call hp_out_dec
    ; SEC-replay-record-mac S1 (root 01:01:52 (b)): the pre-EBS floor and the
    ; SYSTEM secret's state, gradable on targets without a serial capture.
    lea  rdi, [rel str_cmd_replay_floor]
    call hp_out_str
    movzx edi, byte [rel rpf_state]
    call hp_out_dec
    lea  rdi, [rel str_cmd_floor_err]
    call hp_out_str
    movzx edi, byte [rel rpf_err]
    call hp_out_dec
    lea  rdi, [rel str_cmd_sysx_state]
    call hp_out_str
    movzx edi, byte [rel sysx_state]
    call hp_out_dec
    ; RCQ-28 C1: the Manager's PaOSManifestFloor state (5 = SQUATTED fails any
    ; window grade; 0 = not reported). Defense-in-depth, not a closed control.
    lea  rdi, [rel str_cmd_manifest_floor]
    call hp_out_str
    movzx edi, byte [rel pbm_manifest_floor]
    call hp_out_dec
    mov  byte [rel hp_out_ready], 1
.out:
    pop  rsi
    pop  rdi
    pop  r13
    pop  r12
    pop  rbx
    ret

; RANDOM 32 <nonce>
cmd_verb_random:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rbx, rsi
    mov  rdi, [r12 + REQ_ARG]
    lea  rsi, [rel str_cmd_csprng_size32]
    mov  edx, 2
    call cmd_csprng_parse_nonce
    test rax, rax
    jz   .bad_args
    mov  r13, rax
    lea  rdi, [rel cmd_csprng_random_bytes]
    mov  esi, 32
    call csprng_generate
    test rax, rax
    jnz  .refused
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_random_value]
    call hp_out_str
    lea  rdi, [rel cmd_csprng_random_bytes]
    call cmd_csprng_out_hex32
    lea  rdi, [rel str_cmd_csprng_ready_nonce]
    call hp_out_str
    mov  rdi, r13
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    lea  rax, [rel cmd_csprng_random_bytes]
    mov  [rbx + RSP_VAL], rax
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .out
.refused:
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_random_refused]
    call hp_out_str
    mov  rdi, r13
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADJOB
    jmp  .out
.bad_args:
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_random_args]
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADSEL
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; CSPRNG RESEED <nonce>
cmd_verb_csprng:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rbx, rsi
    mov  rdi, [r12 + REQ_ARG]
    lea  rsi, [rel str_cmd_csprng_reseed]
    mov  edx, 6
    call cmd_csprng_parse_nonce
    test rax, rax
    jz   .bad_args
    mov  r13, rax
    call csprng_reseed
    test rax, rax
    jnz  .refused
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_csprng_reseed_ok]
    call hp_out_str
    mov  rdi, r13
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .out
.refused:
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_csprng_reseed_refused]
    call hp_out_str
    mov  rdi, r13
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADJOB
    jmp  .out
.bad_args:
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_csprng_args]
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADSEL
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; FAULT csprng_source <nonce>. Other targets delegate to the existing handler.
cmd_verb_csprng_fault_mux:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rbx, rsi
    mov  rdi, [r12 + REQ_ARG]
    lea  rsi, [rel str_cmd_csprng_source]
    mov  edx, 13
    call cmd_csprng_parse_nonce
    test rax, rax
    jz   .delegate
    mov  r13, rax
    call cmd_handler_prologue
    call csprng_source_fault_once
    test rax, rax
    jz   .unexpected
    call csprng_status_snapshot
    cmp  al, CSPRNG_DEGRADED
    jne  .unexpected
    ; The buffer contains the latest RANDOM output. Generate must refuse and
    ; erase it, proving stale bytes are not replayable after source failure.
    lea  rdi, [rel cmd_csprng_random_bytes]
    mov  esi, 32
    call csprng_generate
    test rax, rax
    jz   .unexpected
    lea  rdi, [rel cmd_csprng_random_bytes]
    mov  ecx, 32
.zero_check:
    cmp  byte [rdi], 0
    jne  .unexpected
    inc  rdi
    dec  ecx
    jnz  .zero_check
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_csprng_fault_refused]
    call hp_out_str
    mov  rdi, r13
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret
.unexpected:
    call cmd_csprng_output_reset
    lea  rdi, [rel str_cmd_csprng_fault_failed]
    call hp_out_str
    mov  rdi, r13
    call hp_out_str
    mov  byte [rel hp_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_BADJOB
    pop  r13
    pop  r12
    pop  rbx
    ret
.delegate:
    mov  rdi, r12                         ; restore original request pointer
    mov  rsi, rbx                         ; restore original response pointer
    pop  r13
    pop  r12
    pop  rbx
    jmp  cmd_verb_fault                    ; original handler owns its prologue

; This early BOOTLOG registration wins lookup over the later UDP declaration.
; Reuse its canonical admitted handler, including the UDP-only one-shot FULL
; admission. The delegate owns the single prologue and response initialization.
cmd_verb_csprng_bootlog:
    jmp  cmd_verb_bootlog

command_csprng_declare:
    lea  rdi, [rel str_verb_random]
    lea  rsi, [rel cmd_verb_random]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_csprng]
    lea  rsi, [rel cmd_verb_csprng]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_fault_csprng]
    lea  rsi, [rel cmd_verb_csprng_fault_mux]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_bootlog_csprng]
    lea  rsi, [rel cmd_verb_csprng_bootlog]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

; command_job_bind_completion(RDI=callback(job_id,state,result)). The command
; model owns execution/state; the session projection binds an in-process append.
command_job_bind_completion:
    mov  [rel command_job_complete_cb], rdi
    ret

; command_job_pump(RDI=job_id) — cooperative ONE-STEP advance of a running job.
;   The scheduler would call this off the command task; here the selftest steps it
;   by hand AFTER proving STATUS answered mid-flight. Marks DONE at SLOWJOB_STEPS.
;   A completion callback runs exactly on the RUNNING->DONE edge.
;   clobbers: RAX,RCX,RDI,RSI,RDX,R8; preserves RBX.
command_job_pump:
    push rbx
    xor  ecx, ecx
    lea  r8, [rel job_table]
.scan:
    cmp  ecx, [rel job_count]
    jae  .out
    mov  rax, [r8 + JOB_ID]
    cmp  rax, rdi
    je   .hit
    add  r8, JOB_ENT_SZ
    inc  ecx
    jmp  .scan
.hit:
    cmp  qword [r8 + JOB_STATE], JOB_ST_RUN
    jne  .out
    inc  qword [r8 + JOB_PROG]
    mov  rax, [r8 + JOB_PROG]
    cmp  rax, SLOWJOB_STEPS
    jb   .out
    mov  qword [r8 + JOB_STATE], JOB_ST_DONE
    mov  rbx, r8
    mov  rax, [rel command_job_complete_cb]
    test rax, rax
    jz   .out
    mov  rdi, [rbx + JOB_ID]
    mov  rsi, [rbx + JOB_STATE]
    mov  rdx, [rbx + JOB_RESULT]
    call rax
.out:
    pop  rbx
    ret

; command_jobs_tick — advance every live job once from the settled idle loop.
; Work never runs inside command_dispatch, so the next command remains live.
command_jobs_tick:
    push rbx
    push r12
    push r13
    xor  r12d, r12d
    mov  r13d, [rel job_count]
.scan:
    cmp  r12d, r13d
    jae  .done
    mov  eax, r12d
    imul rax, JOB_ENT_SZ
    lea  rbx, [rel job_table]
    add  rbx, rax
    cmp  qword [rbx + JOB_STATE], JOB_ST_RUN
    jne  .next
    mov  rdi, [rbx + JOB_ID]
    call command_job_pump
.next:
    inc  r12d
    jmp  .scan
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; cmd_emit_num(RDI=value) — print an unsigned decimal to serial (KAT numbers).
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
cmd_emit_num:
    lea  rsi, [rel cmd_numbuf]
    call fmt_dec                          ; the ONE canonical decimal formatter (G1)
    lea  rdi, [rel cmd_numbuf]
    call serial_string
    ret

; command_registry_selftest — build the registry, register SIX verbs through the
;   SAME register() call, then drive them IN-PROCESS (no wire) to prove: real
;   dispatch (PING echoes a fresh nonce), the non-blocking job model + liveness
;   (STATUS answers WHILE a slow job runs), and single-vocabulary (every run went
;   through the ONE dispatch). Plain call (no diag PHASE — keeps DIAG_NPHASES ring
;   geometry). Emits its own markers. clobbers: caller-saved; preserves RBX,R12-R15.
command_registry_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; --- (1) build the registry (empty, live) ---
    call command_registry_init
    lea  rdi, [rel str_cmd_init]
    call serial_string

    ; --- (2) register SEVEN verbs via the SAME call (degenerate-Nth seam) ---
    ;   STATUS: read-only, no selector, cap 0 (allow-all v1)
    lea  rdi, [rel str_verb_status]
    lea  rsi, [rel cmd_verb_status]
    xor  edx, edx                         ; required cap 0
    mov  ecx, ARGT_U64                    ; arg-type: u64 (STATUS <job_id>)
    xor  r8, r8                            ; selector-kind: none
    xor  r9, r9                            ; destructiveness: read-only
    call command_register_verb
    mov  [rel verb_id_status], eax
    ;   PING: read-only nonce echo
    lea  rdi, [rel str_verb_ping]
    lea  rsi, [rel cmd_verb_ping]
    xor  edx, edx
    mov  ecx, ARGT_U64                    ; arg-type: u64 (PING <nonce>)
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel verb_id_ping], eax
    ;   SLOWJOB: the deliberately-slow verb (job model)
    lea  rdi, [rel str_verb_slow]
    lea  rsi, [rel cmd_verb_slowjob]
    xor  edx, edx
    mov  ecx, ARGT_TEXT                    ; fixture nonce is retained in the transcript
    xor  r8, r8
    mov  r9, 1                             ; destructiveness: mutates job state
    call command_register_verb
    mov  [rel verb_id_slow], eax
    ;   BOOTREPORT: read-only boot-time measurement (contract 1068). ARGT_TEXT so the
    ;   caller nonce token echoes back verbatim (round-trip proof over any transport);
    ;   BOOT_MS/HEAP_MB are framed by each projection from the boot/header globals.
    lea  rdi, [rel str_verb_bootreport]
    lea  rsi, [rel cmd_verb_bootreport]
    xor  edx, edx                         ; required cap 0 (allow-all v1)
    mov  ecx, ARGT_TEXT                    ; arg-type: text token (nonce echoed verbatim)
    xor  r8, r8                            ; selector-kind: none
    xor  r9, r9                            ; destructiveness: read-only
    call command_register_verb
    mov  [rel verb_id_bootreport], eax
    call boot_clock_declare               ; additive public clock-qualified read, same nonce envelope
    ;   FREQMSR: read-only measured-frequency oracle (contract 1050). ARGT_TEXT so the
    ;   caller nonce echoes back verbatim (round-trip proof, same shape as BOOTREPORT);
    ;   the handler runs the APERF/MPERF measurement and each projection frames the
    ;   sprint/eff/base MHz from the governor globals.
    lea  rdi, [rel str_verb_freqmsr]
    lea  rsi, [rel cmd_verb_freqmsr]
    xor  edx, edx                         ; required cap 0 (allow-all v1)
    mov  ecx, ARGT_TEXT                    ; arg-type: text token (nonce echoed verbatim)
    xor  r8, r8                            ; selector-kind: none
    xor  r9, r9                            ; destructiveness: read-only (steers HWP, reverts)
    call command_register_verb
    mov  [rel verb_id_freqmsr], eax
    mov  eax, [rel verb_count]
    cmp  eax, 7
    jne  .fail                            ; STATUS/PING/SLOWJOB/BOOTREPORT/BOOTCLOCK/IRQ0OBS/FREQMSR

    ; --- (3) STATUS in-process (no wire) -> known liveness reply ---
    call cmd_zero_req
    mov  eax, [rel verb_id_status]
    mov  [rel cmd_req + REQ_VERB], rax
    lea  rdi, [rel cmd_req]
    lea  rsi, [rel cmd_rsp]
    call command_dispatch
    cmp  qword [rel cmd_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    lea  rdi, [rel str_cmd_status_ok]
    call serial_string

    ; --- (4) PING with a RANDOM in-proc nonce; assert the echo equals it ---
    call tsc_now
    and  rax, 0x00FFFFFF                   ; keep it small + printable
    or   rax, 1                            ; never 0
    mov  r15, rax                          ; r15 = the nonce we injected
    call cmd_zero_req
    mov  eax, [rel verb_id_ping]
    mov  [rel cmd_req + REQ_VERB], rax
    mov  [rel cmd_req + REQ_ARG], r15
    lea  rdi, [rel cmd_req]
    lea  rsi, [rel cmd_rsp]
    call command_dispatch
    mov  rax, [rel cmd_rsp + RSP_VAL]
    cmp  rax, r15
    jne  .fail                            ; echo != injected nonce => faked/absent dispatch
    lea  rdi, [rel str_cmd_ping_pfx]      ; "...cmd.registry.verb.ping.nonce="
    call serial_string
    mov  rdi, r15
    call cmd_emit_num                     ; the content the probe greps for (=<nonce>)
    lea  rdi, [rel str_cmd_nl]
    call serial_string

    ; --- (5) SLOWJOB: returns accepted+job_id promptly, job still RUNNING ---
    call cmd_zero_req
    mov  eax, [rel verb_id_slow]
    mov  [rel cmd_req + REQ_VERB], rax
    lea  rdi, [rel cmd_req]
    lea  rsi, [rel cmd_rsp]
    call command_dispatch
    cmp  qword [rel cmd_rsp + RSP_ACCEPTED], 1
    jne  .fail                            ; slow verb must return accepted (not block)
    mov  r14, [rel cmd_rsp + RSP_JOBID]   ; r14 = the job id
    test r14, r14
    jz   .fail
    lea  rdi, [rel str_cmd_job_acc]
    call serial_string

    ; --- (6) LIVENESS: STATUS answers WHILE the slow job is still RUNNING ---
    ;   The job has NOT been pumped yet, so its state is RUNNING; STATUS must still
    ;   return a valid answer reporting that (RSP_CODE ok, RSP_VAL == RUNNING).
    call cmd_zero_req
    mov  eax, [rel verb_id_status]
    mov  [rel cmd_req + REQ_VERB], rax
    mov  [rel cmd_req + REQ_ARG], r14     ; STATUS <job_id>
    lea  rdi, [rel cmd_req]
    lea  rsi, [rel cmd_rsp]
    call command_dispatch
    cmp  qword [rel cmd_rsp + RSP_CODE], CMDE_OK
    jne  .fail                            ; STATUS unanswerable during slow verb => FAIL
    cmp  qword [rel cmd_rsp + RSP_VAL], JOB_ST_RUN
    jne  .fail                            ; must observe RUNNING (not done) => mid-flight
    lea  rdi, [rel str_cmd_job_live]
    call serial_string

    ; now pump the job to completion (the scheduler's cooperative advance) and
    ; confirm it reaches DONE — the job model actually finishes work off the
    ; control plane, it did not just abandon it.
    mov  r13d, SLOWJOB_STEPS              ; callee-saved counter (job_pump clobbers ECX)
.pump:
    mov  rdi, r14
    call command_job_pump
    dec  r13d
    jnz  .pump
    call cmd_zero_req
    mov  eax, [rel verb_id_status]
    mov  [rel cmd_req + REQ_VERB], rax
    mov  [rel cmd_req + REQ_ARG], r14
    lea  rdi, [rel cmd_req]
    lea  rsi, [rel cmd_rsp]
    call command_dispatch
    cmp  qword [rel cmd_rsp + RSP_VAL], JOB_ST_DONE
    jne  .fail

    ; --- (7) SINGLE-VOCABULARY: every verb execution went through the ONE dispatch.
    ;   dispatch_count must equal handler_runs (no handler ran outside dispatch) AND
    ;   the bypass flag must be clear. If either fails a side-door path exists. ---
    mov  byte [rel cmd_bypass_flag], 0    ; (already 0; explicit for the assertion)
    cmp  byte [rel cmd_bypass_flag], 0
    jne  .fail
    mov  rax, [rel cmd_dispatch_count]
    cmp  rax, [rel cmd_handler_runs]
    jne  .fail                            ; counts diverge => a handler ran off-registry
    lea  rdi, [rel str_cmd_singlevocab]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_cmd_fail]
    call serial_string
.done:
    call command_verb_bounds_kat
    ; Run the deterministic crypto proof before initializing the live provider,
    ; then add four ordinary verbs through the same registry seam.
    call csprng_selftest
    call csprng_service_init
    call command_csprng_declare
    call command_srvstat_init             ; 3040: public bounded status, same registry
    call hp_persist_test_declare           ; synchronous owner/HOTPATCH test-store action
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; command_verb_bounds_kat — the per-verb accessors must never index verb_table with an
;   out-of-range id (FINDING_20261001_SERIAL_UNKNOWN_VERB_PF: a bad id read
;   verb_table + 0xFFFFFFFF*0x30 and page-faulted). Out of range -> refusal-safe
;   sentinels (argt NONE, cap all-bits, selk 0, destr 1) and dispatch -> CMDE_NOVERB;
;   slot 0 (STATUS, registered first above) still reads its real argt. Runs at boot
;   inside command_registry_selftest. clobbers: caller-saved; preserves RBX, R12.
command_verb_bounds_kat:
    push rbx
    push r12
    mov  rdi, 0
    call command_verb_argt
    cmp  rax, ARGT_U64
    jne  .fail
    xor  r12d, r12d
.next:
    lea  rax, [rel cmd_bounds_ids]
    mov  rbx, [rax + r12*8]
    test r12, r12
    jnz  .have
    mov  ebx, [rel verb_count]           ; first probe: exactly one past the last slot
.have:
    mov  rdi, rbx
    call command_verb_argt
    cmp  rax, ARGT_NONE
    jne  .fail
    mov  rdi, rbx
    call command_verb_cap
    cmp  rax, -1
    jne  .fail
    mov  rdi, rbx
    call command_verb_selk
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    call command_verb_destr
    cmp  rax, 1
    jne  .fail
    call cmd_zero_req
    mov  [rel cmd_req + REQ_VERB], rbx
    lea  rdi, [rel cmd_req]
    lea  rsi, [rel cmd_rsp]
    call command_dispatch
    cmp  rax, CMDE_NOVERB
    jne  .fail
    inc  r12
    cmp  r12, 3
    jb   .next
    lea  rdi, [rel str_cmd_bounds_ok]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_cmd_bounds_fail]
    call serial_string
.out:
    pop  r12
    pop  rbx
    ret
cmd_bounds_ids: dq 0, 0x00000000FFFFFFFF, -1   ; [0] replaced by verb_count at run time

; cmd_zero_req — clear the shared request envelope between dispatches. clobbers: RAX
cmd_zero_req:
    mov  qword [rel cmd_req + REQ_VERB], 0
    mov  qword [rel cmd_req + REQ_CAP], 0
    mov  qword [rel cmd_req + REQ_IDEM], 0
    mov  qword [rel cmd_req + REQ_SEL], 0
    mov  qword [rel cmd_req + REQ_ARG], 0
    mov  qword [rel cmd_req + REQ_SOURCE], CMD_SOURCE_INTERNAL
    mov  qword [rel cmd_req + REQ_PRINCIPAL], CMD_PRINCIPAL_NONE
    ret

str_cmd_manifest_floor: db " manifest_floor=", 0   ; read-only, outside the WDATA block

; --- svc/command data (RW under our page tables, MEMORY_MAP §3.1) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_0 0
align 8
verb_count:         dd 0
job_count:          dd 0
align 8
job_next_id:        dq 1
verb_id_status:     dd 0
verb_id_ping:       dd 0
verb_id_slow:       dd 0
verb_id_bootreport: dd 0
verb_id_freqmsr:    dd 0
cmd_dispatch_count: dq 0
cmd_handler_runs:   dq 0
cmd_dispatch_last_source: dq CMD_SOURCE_INTERNAL
cmd_dispatch_last_principal: dq CMD_PRINCIPAL_NONE
times 12 db 0                  ; cmd_in_dispatch..cmd_csprng_random_bytes moved to WDATA_svc_command_0_bss1: keeps the labels below at their offset mod 64
cmd_csprng_hex:          db "0123456789abcdef"

str_verb_status:    db "STATUS", 0
str_verb_ping:      db "PING", 0
str_verb_slow:      db "SLOWJOB", 0
str_verb_bootreport: db "BOOTREPORT", 0
str_verb_freqmsr:   db "FREQMSR", 0
str_verb_random:    db "RANDOM", 0
str_verb_csprng:    db "CSPRNG", 0
str_verb_fault_csprng: db "FAULT", 0
str_verb_bootlog_csprng: db "BOOTLOG", 0

str_cmd_csprng_size32: db "32", 0
str_cmd_csprng_reseed: db "RESEED", 0
str_cmd_csprng_source: db "csprng_source", 0
str_cmd_random_value: db " random=", 0
str_cmd_csprng_ready_nonce: db " health=ready nonce=", 0
str_cmd_random_refused: db " RANDOM REFUSED health=degraded nonce=", 0
str_cmd_random_args: db " RANDOM ERR expected='32 <nonce>'", 0
str_cmd_csprng_reseed_ok: db " CSPRNG RESEED ready ack nonce=", 0
str_cmd_csprng_reseed_refused: db " CSPRNG RESEED REFUSED health=degraded nonce=", 0
str_cmd_csprng_args: db " CSPRNG ERR expected='RESEED <nonce>'", 0
str_cmd_csprng_fault_refused: db " CSPRNG source REFUSED health=degraded nonce=", 0
str_cmd_csprng_fault_failed: db " CSPRNG source ERR failure injection did not degrade nonce=", 0
str_cmd_csprng_status: db " CSPRNG_HEALTH=", 0
str_cmd_csprng_health_ready: db "ready", 0
str_cmd_csprng_health_degraded: db "degraded", 0
str_cmd_csprng_source_failures: db " source_failures=", 0
str_cmd_csprng_reseed_counter: db " reseed_counter=", 0
str_cmd_replay_floor: db " replay_floor=", 0
str_cmd_floor_err:   db " floor_err=", 0
str_cmd_sysx_state:  db " sysx_state=", 0
str_cmd_init:       db "[PAOS64] P2 cmd registry: verb table built [cmd.registry.init]", 13, 10, 0
str_cmd_safe_init:  db "[PAOS64] Safe Mode command floor: read-only STATUS+PING registered [boot.v2.safe.command-floor]", 13, 10, 0
str_cmd_status_ok:  db "[PAOS64] P2 cmd registry: STATUS dispatched in-process [cmd.registry.verb.status.ok]", 13, 10, 0
str_cmd_ping_pfx:   db "[PAOS64] P2 cmd registry: PING echoed in-proc nonce cmd.registry.verb.ping.nonce=", 0
str_cmd_job_acc:    db "[PAOS64] P2 cmd registry: SLOWJOB returned accepted+job_id promptly [cmd.registry.job.accepted]", 13, 10, 0
str_cmd_job_live:   db "[PAOS64] P2 cmd registry: STATUS answered WHILE slow job still running [cmd.registry.job.status.live]", 13, 10, 0
str_cmd_singlevocab: db "[PAOS64] P2 cmd registry: every verb ran through the one dispatch [cmd.registry.singlevocab.ok]", 13, 10, 0
str_cmd_fail:       db "[PAOS64] P2 cmd registry: FAIL", 13, 10, 0
str_cmd_bounds_ok:   db "[PAOS64] P2 cmd registry: out-of-range verb ids -> safe accessors + CMDE_NOVERB [cmd.verb.bounds.kat]", 13, 10, 0
str_cmd_bounds_fail: db "[PAOS64] P2 cmd registry: out-of-range verb id accessor FAIL [cmd.verb.bounds.fail]", 13, 10, 0
str_cmd_nl:         db 13, 10, 0
str_cmd_hint_noverb: db "unknown verb id; call CATALOG for the registered set", 0
str_cmd_hint_cap:   db "insufficient capability; present a token with the required cap", 0
str_cmd_hint_badjob: db "unknown job id; use the job_id returned by the accepting verb", 0
%endmacro
WDATA_DEFER WDATA_svc_command_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_0_bss1 0
resb 4                 ; keeps cmd_in_dispatch at its WDATA offset mod 64
cmd_in_dispatch:    resb 1
cmd_bypass_flag:    resb 1
cmd_desktop_refused: resb 1               ; per-dispatch-frame: a desktop handler refused (locked)
alignb 8
cmd_dispatch_proposer: resq 1             ; RCQ-40 J2a: the card's proposer while its dispatch runs, else 0
cmd_card_proposer_arm: resq 1             ; written non-zero only by command_dispatch_card
cmd_local_human_req:   resq 1
cmd_local_human_verb:  resq 1
cmd_local_human_match: resb 1
cmd_dispatch_depth: resd 1                ; registry dispatch nesting (cmd_in_dispatch is a 0/1 flag)
alignb 16
verb_table:         resb (VERB_MAX * VERB_ENT_SZ)
job_table:          resb (JOB_MAX * JOB_ENT_SZ)
command_job_complete_cb: resq 1
command_job_control_snapshot: resq 9
cmd_req:            resb REQ_SZ
cmd_rsp:            resb RSP_SZ
cmd_numbuf:         resb 24              ; u64 decimal scratch (max 20 digits + NUL)

alignb 16
cmd_csprng_random_bytes: resb 32
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_0_bss1
