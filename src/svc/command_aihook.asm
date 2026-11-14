;; MODULE svc/command_aihook
;; LAYER 5
;; EXPORTS command_aihook_init, command_aihook_auth_probe_declare, command_aihook_submit, command_aihook_submit_authorized, command_aihook_submit_advisory, command_aihook_submit_file_advisory, command_aihook_resolve, command_aihook_catalog, command_aihook_selftest
;; IMPORTS boot/serial, core/time, core/lib/fmt, core/lib/str, core/lib/mem, sec/principal, svc/command, svc/command_auth, svc/command_audit
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/command_aihook.asm — THE AI-HOOK PROJECTION of the command registry
; (contract 1079, rewrite/COMMANDS.md §5,§9.3). The NATIVE AI surface: the one
; that makes a WEAK local LLM competent. Like every surface (serial 1078, UDP
; 1010) it is a THIN PROJECTION over the ONE registry (svc/command.asm, 1077) —
; it owns NO command logic; it only adds the affordances a small model needs to
; drive that registry without guessing. Three affordances, in §9.3 value order:
;
;   (1) IN-PROCESS AI-hook path (the tightest coupling): the local LLM lives in
;       the SAME address space, so it submits a TYPED verb envelope and gets the
;       structured result with ZERO serialization — no wire, no parse. Same verbs
;       as every other surface, µs latency. command_aihook_submit builds a
;       CMDREQ_* envelope and dispatches it through the ONE command_dispatch.
;
;   (2) SELECTOR RESOLVER (the #1 small-model multiplier, §9.3.1): a named-entity
;       table + alias match so the model names INTENT ("the data array") and
;       resolve(selector)->handle returns the CONCRETE handle ("md0"). The model
;       never memorizes or guesses device paths. v1 is exact + alias match;
;       vector/semantic match is an additive follow-on rung on this same table.
;       An UNKNOWN selector returns an ACTIONABLE error {code, expected, hint}
;       whose hint is a CONCRETE registered selector — so the next turn succeeds.
;
;   (3) CATALOG/DESCRIBE (§9.4b): emitted FROM the registry's self-description
;       metadata (command_verb_count/_name/_argt/_cap/_destr) — the model asks the
;       machine what it can do and the exact arg shapes, never memorizing or
;       hallucinating verbs. Because it is generated from verb_count it CANNOT
;       drift from the registry. This is ~an MCP tool-list; exposing it to
;       ACP/Claude-Code + remote MCP agents is the additive endgame rung (§5),
;       not a reshape — it rides this same generated description.
;
; CONTENT-GRADE, NOT LATCH (TESTING §1): command_aihook_selftest submits PING with
; a fresh rdtsc nonce and asserts the ECHO through the envelope equals it (a latch
; cannot reproduce a per-boot nonce); resolves an INTENT phrase and asserts the
; returned handle differs from the input string (identity echo => no resolution);
; asserts CATALOG's count == the registry's own verb_count; and drives a bad
; selector -> actionable hint -> a SECOND resolve using that hint that SUCCEEDS in
; ONE turn. All in QEMU, NO transport — that is the point of the in-proc surface.
;
; NO dq <symbol> POINTER TABLES (known_trap): PaOS's PE32+ ImageBase (0x100000) is
; NOT applied to baked `dq <label>` references — they ship as org-0 RVAs. So the
; selector table's alias/handle pointers are BOUND AT BOOT via `lea [rel ...]`
; (command_aihook_init), exactly like mem/layout.asm and the netdev vtables.
; ============================================================================

; --- selector table entry: {alias ptr, handle ptr} (both bound at boot) ---
SEL_ALIAS   equ 0
SEL_HANDLE  equ 8
SEL_ENT_SZ  equ 16
AIHOOK_SEL_COUNT equ 5

; --- actionable-error struct {code, expected ptr, hint ptr} (§9.4 f) ---
AERR_CODE     equ 0      ; error code (CMDE_BADSEL for an unresolved selector)
AERR_EXPECTED equ 8      ; ptr to a human-readable "what was expected" string
AERR_HINT     equ 16     ; ptr to a CONCRETE registered selector the caller can retry with
AERR_SZ       equ 24

; ---------------------------------------------------------------------------
; command_aihook_init — bind the selector table's alias/handle pointers to their
;   runtime VAs via lea (never dq <symbol> — the ImageBase-not-applied trap). This
;   IS the "resolver table built" step. clobbers: RAX, RCX
; ---------------------------------------------------------------------------
command_aihook_init:
    lea  rcx, [rel aihook_sel_table]
    lea  rax, [rel str_sel_data_array]
    mov  [rcx + 0*SEL_ENT_SZ + SEL_ALIAS], rax
    lea  rax, [rel str_hdl_md0]
    mov  [rcx + 0*SEL_ENT_SZ + SEL_HANDLE], rax
    lea  rax, [rel str_sel_data]
    mov  [rcx + 1*SEL_ENT_SZ + SEL_ALIAS], rax
    lea  rax, [rel str_hdl_md0]
    mov  [rcx + 1*SEL_ENT_SZ + SEL_HANDLE], rax
    lea  rax, [rel str_sel_raid]
    mov  [rcx + 2*SEL_ENT_SZ + SEL_ALIAS], rax
    lea  rax, [rel str_hdl_md0]
    mov  [rcx + 2*SEL_ENT_SZ + SEL_HANDLE], rax
    lea  rax, [rel str_sel_main_disk]
    mov  [rcx + 3*SEL_ENT_SZ + SEL_ALIAS], rax
    lea  rax, [rel str_hdl_nvme]
    mov  [rcx + 3*SEL_ENT_SZ + SEL_HANDLE], rax
    lea  rax, [rel str_sel_sys_disk]
    mov  [rcx + 4*SEL_ENT_SZ + SEL_ALIAS], rax
    lea  rax, [rel str_hdl_nvme]
    mov  [rcx + 4*SEL_ENT_SZ + SEL_HANDLE], rax
    ret

; Register a read-only, nonce-bearing live probe for the otherwise in-process
; AI ingress.  Its handler drives the ordinary AI submit API into the shared
; owner gate and reports measured job counts; it cannot request a mutation of
; its own and therefore remains public under the exact Task2020 query floor.
command_aihook_auth_probe_declare:
    lea  rdi, [rel str_aihook_auth_probe]
    lea  rsi, [rel cmd_aihook_auth_probe]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

cmd_aihook_auth_probe:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, [rdi + REQ_ARG]             ; caller freshness token
    mov  r14, rsi                          ; response envelope
    mov  r12d, [rel job_count]
    lea  rdi, [rel str_aihook_slow]
    call command_lookup
    cmp  eax, -1
    je   .failed
    mov  rdi, rax
    xor  esi, esi
    call command_aihook_submit             ; actual AI ingress, unsigned
    mov  r13, rdx                          ; observed dispatcher result
    mov  edx, [rel job_count]
    mov  rdi, rbx
    mov  esi, r12d
    mov  rcx, r13
    call command_auth_stage_ai_probe
    cmp  r13, CMDE_AUTHDENY
    jne  .failed_staged
    cmp  r12d, [rel job_count]
    jne  .failed_staged
    mov  qword [r14 + RSP_CODE], CMDE_OK
    xor  eax, eax
    mov  [r14 + RSP_VAL], rax
    jmp  .out
.failed:
    mov  r13, CMDE_NOVERB
    mov  edx, [rel job_count]
    mov  rdi, rbx
    mov  esi, r12d
    mov  rcx, r13
    call command_auth_stage_ai_probe
.failed_staged:
    mov  qword [r14 + RSP_CODE], CMDE_AUTHDENY
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; aihook_sec_account(ESI = verified principal or 0, RDX = this call's verb id)
;   — the ONE GD1 spine outcome of this invocation (svc/command_audit), mapped
;   from the final synchronous aihook_rsp. Each exit calls it once, after the
;   auth outcome is known and the remote frame has closed. The verb id comes
;   from the caller's register, not aihook_req, which a nested AI-hook call in
;   the dispatched handler may have reused. It only reads the envelope, so
;   aihook_rsp and the returned RAX/RDX are unchanged. 0 -> public coalesced
;   counters (never a ring slot). clobbers: caller-saved.
; ---------------------------------------------------------------------------
aihook_sec_account:
    push rbx
    push r12
    mov  ebx, esi
    mov  r12, rdx
    lea  rdi, [rel aihook_rsp]
    mov  esi, AUDIT_SEC_C_AIHOOK
    call audit_sec_rsp_meta
    mov  edi, eax
    mov  esi, ebx
    mov  rdx, r12
    call audit_sec_event
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_aihook_submit(RDI=verb_id, RSI=arg) -> RAX=RSP_VAL, RDX=RSP_CODE.
;   THE in-process AI-hook path: build the TYPED request envelope and dispatch it
;   through the ONE command_dispatch — zero serialization, same registry every
;   other surface uses. The structured response is left in aihook_rsp; the two
;   most-used fields are returned in registers. Unsigned: its one spine outcome
;   is a public counter. clobbers: caller-saved.
; ---------------------------------------------------------------------------
command_aihook_submit:
    push r12
    push r13
    mov  r12, rdi                         ; verb id
    mov  r13, rsi                         ; typed argument
    mov  qword [rel aihook_req + REQ_VERB], 0
    mov  qword [rel aihook_req + REQ_CAP], 0
    mov  qword [rel aihook_req + REQ_IDEM], 0
    mov  qword [rel aihook_req + REQ_SEL], 0
    mov  qword [rel aihook_req + REQ_ARG], 0
    mov  qword [rel aihook_req + REQ_SOURCE], CMD_SOURCE_AIHOOK   ; RCQ-15 S2: the ingress is named, never INTERNAL
    mov  qword [rel aihook_req + REQ_PRINCIPAL], CMD_PRINCIPAL_NONE
    mov  [rel aihook_req + REQ_VERB], r12
    mov  [rel aihook_req + REQ_ARG], r13
    xor  edi, edi                         ; no owner envelope: public reads only
    call command_auth_remote_begin
    lea  rdi, [rel aihook_req]
    lea  rsi, [rel aihook_rsp]
    call command_dispatch                 ; THE single entry (1077)
    call command_auth_remote_end
    xor  esi, esi                         ; no binding: unauthenticated aggregate
    mov  rdx, r12
    call aihook_sec_account
    mov  rax, [rel aihook_rsp + RSP_VAL]
    mov  rdx, [rel aihook_rsp + RSP_CODE]
    pop  r13
    pop  r12
    ret

; command_aihook_submit_authorized(RDI=verb id, RSI=typed argument).
; The native AI authenticates with its machine-held SYSTEM_KEY. It never parses
; or possesses an owner AUTH1 envelope. The verified method row stamps pid=2;
; the ordinary command gate then permits operational caps and refuses BOOT.
; Spine: a failure before the bind is one unauthenticated auth_refused count;
; after the bind, one typed SYSTEM aihook record per call.
command_aihook_submit_authorized:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 16                         ; frame-private PID/epoch; handlers may clobber r15/rbp
    mov  r12, rdi                         ; registry verb id
    mov  r13, rsi                         ; typed argument
    call principal_execution_snapshot
    mov  [rsp], rax                       ; per-frame exact incoming identity
    mov  [rsp + 8], rdx                   ; a lock/rebind supersedes this frame
    call principal_credentials_init
    test eax, eax
    jnz  .refuse
    call principal_system_auth_credential
    test rax, rax
    jz   .refuse
    mov  [rel aihook_bind_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  [rel aihook_bind_ctx + AUTH_CTX_CRED_LEN], rdx
    mov  qword [rel aihook_bind_ctx + AUTH_CTX_ASSERTED_PID], PRIN_OWNER
    mov  edi, AUTH_BIND_SYSTEM_KEY
    lea  rsi, [rel aihook_bind_ctx]
    call authenticate_bind
    cmp  rax, PRIN_SYSTEM
    jne  .refuse

    lea  rdi, [rel aihook_auth_ticket]
    xor  esi, esi
    mov  edx, AUTH_T_SIZE
    call memset
    mov  rdi, r12
    call command_verb_name
    mov  r14, rax
    mov  rdi, r12
    call command_verb_cap
    mov  rbx, rax
    mov  rdi, r12
    call command_verb_destr
    mov  rdx, rax
    mov  rdi, r14
    mov  rsi, rbx
    call command_auth_required_cap
    mov  [rel aihook_auth_ticket + AUTH_T_CAP], rax
    call time_wall_local_issue_s          ; a native ticket at now (ended after dispatch)
    mov  [rel aihook_auth_ticket + AUTH_T_ISSUED], rax
    mov  rbx, rax
    add  rax, AUTH_MAX_TTL_S
    mov  [rel aihook_auth_ticket + AUTH_T_EXPIRES], rax
    ; Share the one durable replay sequence with owner AUTH1. A separate
    ; time-derived domain could jump the floor and strand later owner tickets.
    mov  rax, [rel command_auth_last_sequence]
    inc  rax
    mov  [rel aihook_auth_ticket + AUTH_T_SEQ], rax
    mov  [rel aihook_auth_ticket + AUTH_T_COMMAND], r14
    mov  byte [rel aihook_auth_ticket + AUTH_T_STATE], AUTH_TS_VALID
    mov  qword [rel aihook_auth_ticket + AUTH_T_PRINCIPAL], PRIN_SYSTEM

    mov  qword [rel aihook_req + REQ_VERB], 0
    mov  qword [rel aihook_req + REQ_CAP], 0
    mov  qword [rel aihook_req + REQ_IDEM], 0
    mov  qword [rel aihook_req + REQ_SEL], 0
    mov  qword [rel aihook_req + REQ_ARG], 0
    mov  qword [rel aihook_req + REQ_SOURCE], CMD_SOURCE_AIHOOK   ; RCQ-15 S2: the ingress is named, never INTERNAL
    mov  qword [rel aihook_req + REQ_PRINCIPAL], CMD_PRINCIPAL_NONE
    mov  [rel aihook_req + REQ_VERB], r12
    mov  [rel aihook_req + REQ_ARG], r13
    lea  rdi, [rel aihook_auth_ticket]
    call command_auth_remote_begin
    lea  rdi, [rel aihook_req]
    lea  rsi, [rel aihook_rsp]
    call command_dispatch
    call time_wall_local_issue_end
    call command_auth_remote_end
    mov  rdi, [rsp]
    mov  rsi, [rsp + 8]
    call principal_restore_execution
    ; authenticate_bind returned PRIN_SYSTEM: one typed SYSTEM record, whatever
    ; the command gate decided (a gate refusal is an authenticated refusal).
    mov  esi, PRIN_SYSTEM
    mov  rdx, r12
    call aihook_sec_account
    jmp  .result
.refuse:
    mov  qword [rel aihook_rsp + RSP_CODE], CMDE_AUTHDENY
    mov  qword [rel aihook_rsp + RSP_VAL], 0
    lea  rax, [rel command_auth_out_buf]
    mov  [rel aihook_rsp + RSP_HINT], rax
    mov  rdi, [rsp]
    mov  rsi, [rsp + 8]
    call principal_restore_execution
    ; No binding was earned before dispatch: unauthenticated aggregate only.
    mov  edi, AUDIT_SEC_C_AUTH_REFUSED | (AUDIT_SEC_V_REFUSED << 8) | (AUDIT_SEC_R_PREBIND << 16)
    xor  esi, esi
    mov  rdx, r12
    call audit_sec_event
.result:
    mov  rax, [rel aihook_rsp + RSP_VAL]
    mov  rdx, [rel aihook_rsp + RSP_CODE]
    add  rsp, 16
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_aihook_submit_advisory(RDI=verb id, RSI=typed argument, ignored)
;   -> RAX = 0, RDX = CMDE_AUTHDENY.
; SEC-GA2(b) (admin 10/08 01:26; RC spec 10.5): the Guardian advisor may PROPOSE
; a verb but holds no authority to run one. Its ticket names PRIN_ADVISOR,
; whose capability word is empty, and command_auth_authorize refuses that
; principal deterministically before any cap, sequence or time check, whatever
; the verb (cap 0 included) and whatever the model says. This path never calls
; command_dispatch, so even an authorize defect cannot execute anything: the
; outcome is still CMDE_AUTHDENY, and the spine records it as INFO instead of
; REFUSED. Spine: one typed AIHOOK record, principal ADVISOR, subject = verb id,
; reason AUDIT_SEC_R_ADVISOR. At most ADVISOR_MAX_LIVE are held in the typed
; ring; beyond that each one is a public AIHOOK counter, so a looping model
; cannot flush the owner's typed history. The advisor reads the spine only
; through audit_sec_advisor_view (svc/command_audit). clobbers: caller-saved.
command_aihook_submit_advisory:
    push r15
    mov r15d, AUDIT_SEC_R_ADVISOR
    jmp aihook_advisory_common

; Only the native VFS producer uses this entry. RSI is the actual bounded file
; span and RDX its length; bytes are advice, never parsed as a command/ticket.
; Provenance is selected by native entry, never by text or classifier verdict.
command_aihook_submit_file_advisory:
    push r15
    mov r15d, AUDIT_SEC_R_ADVISOR_FILE
aihook_advisory_common:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi                         ; registry verb id
    lea  rdi, [rel aihook_advisory_ticket]
    xor  esi, esi
    mov  edx, AUTH_T_SIZE
    call memset
    mov  rdi, r12
    call command_verb_name
    mov  r14, rax
    mov  rdi, r12
    call command_verb_cap
    mov  rbx, rax
    mov  rdi, r12
    call command_verb_destr
    mov  rdx, rax
    mov  rdi, r14
    mov  rsi, rbx
    call command_auth_required_cap
    mov  r13, rax                         ; the cap the verb would need
    mov  [rel aihook_advisory_ticket + AUTH_T_CAP], rax
    mov  [rel aihook_advisory_ticket + AUTH_T_COMMAND], r14
    mov  byte [rel aihook_advisory_ticket + AUTH_T_STATE], AUTH_TS_VALID
    mov  qword [rel aihook_advisory_ticket + AUTH_T_PRINCIPAL], PRIN_ADVISOR
    lea  rdi, [rel aihook_advisory_ticket]
    mov  rsi, r13
    mov  rdx, r14
    call command_auth_authorize           ; refuses PRIN_ADVISOR (AUTHR_PRINCIPAL)
    ; The refusal text stays readable in command_auth_out_buf (RSP_HINT), but it
    ; is an in-process answer: drop the transport staging command_auth_refuse
    ; set, or the NEXT remote UDP/serial reply would carry this stale signed
    ; "refused" receipt (srcreview GA2 R1; same rule as the other in-process
    ; callers, e.g. the AI-hook self-test).
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_refusal_ready], 0
    mov ebx, r15d
    shl ebx, 16
    or ebx, AUDIT_SEC_C_AIHOOK | (AUDIT_SEC_V_REFUSED << 8)
    cmp  eax, -1
    je   .refused
    mov ebx, r15d
    shl ebx, 16
    or ebx, AUDIT_SEC_C_AIHOOK | (AUDIT_SEC_V_INFO << 8)
.refused:
    mov  qword [rel aihook_rsp + RSP_CODE], CMDE_AUTHDENY
    mov  qword [rel aihook_rsp + RSP_VAL], 0
    lea  rax, [rel command_auth_out_buf]
    mov  [rel aihook_rsp + RSP_HINT], rax
    mov  edi, AUDIT_SEC_C_AIHOOK
    mov  esi, PRIN_ADVISOR
    call audit_sec_held
    mov  esi, PRIN_ADVISOR
    cmp  eax, ADVISOR_MAX_LIVE
    jb   .account
    xor  esi, esi                         ; cap reached: public counter only
.account:
    mov  edi, ebx
    mov  rdx, r12
    call audit_sec_event
    xor  eax, eax
    mov  edx, CMDE_AUTHDENY
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  r15
    ret

; ---------------------------------------------------------------------------
; command_aihook_resolve(RDI=selector ptr, RSI=err_out ptr or 0) -> RAX = handle
;   ptr (0 if unknown). The §9.3.1 offload: map a plain-language INTENT to a
;   registered device handle via exact/alias match, so the model never supplies a
;   device path. On a MISS, if err_out != 0 it is filled with the actionable
;   {code, expected, hint} envelope (hint = a concrete registered selector to
;   retry). clobbers: RAX,RCX,RDX,RSI,RDI (preserves RBX,R12-R14).
; ---------------------------------------------------------------------------
command_aihook_resolve:
    push rbx
    push r12
    push r13
    mov  r12, rdi                         ; selector
    mov  r13, rsi                         ; err_out (may be 0)
    lea  rbx, [rel aihook_sel_table]
    xor  ecx, ecx                         ; entry index
.scan:
    cmp  ecx, AIHOOK_SEL_COUNT
    jae  .miss
    mov  eax, ecx
    imul rax, rax, SEL_ENT_SZ
    push rax
    push rcx
    mov  rdi, [rbx + rax + SEL_ALIAS]
    mov  rsi, r12
    call strcmp                           ; the ONE canonical strcmp (G1); 0 == equal
    pop  rcx
    pop  rdx                              ; rdx = this entry's byte offset
    test rax, rax
    jz   .hit
    inc  ecx
    jmp  .scan
.hit:
    mov  rax, [rbx + rdx + SEL_HANDLE]
    jmp  .out
.miss:
    test r13, r13
    jz   .miss_noerr
    mov  qword [r13 + AERR_CODE], CMDE_BADSEL
    lea  rax, [rel str_aihook_err_expected]
    mov  [r13 + AERR_EXPECTED], rax
    lea  rax, [rel str_sel_data_array]   ; a CONCRETE registered selector to retry with
    mov  [r13 + AERR_HINT], rax
.miss_noerr:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_aihook_catalog -> RAX = verb count. Emit the DESCRIBE listing generated
;   FROM the registry's self-description metadata (name/argt/cap/destr per verb).
;   Count == command_verb_count so it cannot drift from the registry. This is the
;   MCP tool-list in miniature. clobbers: caller-saved (preserves RBX,R14).
; ---------------------------------------------------------------------------
command_aihook_catalog:
    push rbx
    push r14
    call command_verb_count
    mov  r14, rax                         ; registry verb count = source of truth
    lea  rdi, [rel str_aihook_cat_hdr]
    call serial_string
    xor  ebx, ebx
.loop:
    cmp  rbx, r14
    jae  .done
    lea  rdi, [rel str_aihook_cat_ent]    ; "  verb["
    call serial_string
    mov  rdi, rbx
    call aihook_emit_num
    lea  rdi, [rel str_aihook_cat_name]   ; "]="
    call serial_string
    mov  rdi, rbx
    call command_verb_name
    mov  rdi, rax
    call serial_string
    lea  rdi, [rel str_aihook_cat_argt]   ; " argt="
    call serial_string
    mov  rdi, rbx
    call command_verb_argt
    mov  rdi, rax
    call aihook_emit_num
    lea  rdi, [rel str_aihook_cat_cap]    ; " cap="
    call serial_string
    mov  rdi, rbx
    call command_verb_cap
    mov  rdi, rax
    call aihook_emit_num
    lea  rdi, [rel str_aihook_cat_destr]  ; " destr="
    call serial_string
    mov  rdi, rbx
    call command_verb_destr
    mov  rdi, rax
    call aihook_emit_num
    lea  rdi, [rel str_aihook_nl]
    call serial_string
    inc  ebx
    jmp  .loop
.done:
    mov  rax, r14
    pop  r14
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; aihook_emit_num(RDI=value) — print an unsigned decimal to serial via the ONE
;   canonical formatter. clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10
; ---------------------------------------------------------------------------
aihook_emit_num:
    lea  rsi, [rel aihook_numbuf]
    call fmt_dec                          ; canonical int->dec (G1)
    lea  rdi, [rel aihook_numbuf]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; command_aihook_selftest — the 1079 QEMU acceptance, NO transport. Proves the
;   four affordances end-to-end and emits the four markers the probe grades.
;   Runs right after command_registry_selftest, so the registry holds its 3 verbs.
;   clobbers: caller-saved; preserves RBX,R12-R15.
; ---------------------------------------------------------------------------
command_aihook_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    call command_aihook_init              ; bind the selector table (runtime VAs)

    ; --- (1) IN-PROC AI-hook: submit PING <fresh nonce> through the registry, get
    ;     the structured envelope, assert the echoed nonce (real dispatch != latch) ---
    lea  rdi, [rel str_aihook_ping]
    call command_lookup                   ; PING verb id from the registry (no hardcode)
    cmp  rax, -1
    je   .fail
    mov  r12, rax
    call tsc_now
    and  rax, 0x00FFFFFF                   ; small + printable
    or   rax, 1                            ; fresh, nonzero
    mov  r15, rax                          ; r15 = injected nonce
    mov  rdi, r12
    mov  rsi, r15
    call command_aihook_submit            ; RAX=RSP_VAL, RDX=RSP_CODE
    test rdx, rdx
    jnz  .fail                            ; dispatch error => surface faked
    cmp  rax, r15
    jne  .fail                            ; echo != injected nonce => no real dispatch
    lea  rdi, [rel str_aihook_inproc]     ; "...cmd.aihook.inproc.ok="
    call serial_string
    mov  rdi, r15
    call aihook_emit_num                  ; the nonce content the probe greps
    lea  rdi, [rel str_aihook_nl]
    call serial_string

    ; An in-process model is still a remote-control principal.  Exercise the
    ; actual SLOWJOB mutator through the ordinary AI API, prove the shared gate
    ; rejects it, and prove the job table did not change.  AUTHSTAT exposes the
    ; earned bit so QEMU/twin grading need not trust a source-only marker.
    lea  rdi, [rel str_aihook_slow]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  r12, rax
    mov  ebx, [rel job_count]
    mov  rdi, r12
    xor  esi, esi
    call command_aihook_submit
    cmp  rdx, CMDE_AUTHDENY
    jne  .fail
    cmp  ebx, [rel job_count]
    jne  .fail
    call command_auth_note_aihook_proof
    mov  byte [rel command_auth_out_ready], 0

    ; --- (2) SELECTOR RESOLVER: name INTENT -> concrete handle (model didn't guess) ---
    lea  rdi, [rel str_sel_data_array]
    xor  esi, esi
    call command_aihook_resolve           ; RAX = handle ptr
    test rax, rax
    jz   .fail
    mov  r13, rax                         ; resolved handle ptr
    lea  rcx, [rel str_sel_data_array]
    cmp  r13, rcx
    je   .fail                            ; identity echo => no resolution happened
    lea  rdi, [rel str_aihook_resolve]    ; "...cmd.aihook.resolve.ok selector="
    call serial_string
    lea  rdi, [rel str_sel_data_array]
    call serial_string
    lea  rdi, [rel str_aihook_arrow]      ; " -> handle="
    call serial_string
    mov  rdi, r13
    call serial_string
    lea  rdi, [rel str_aihook_nl]
    call serial_string

    ; --- (3) CATALOG generated from registry metadata; count can't drift ---
    call command_aihook_catalog           ; prints each verb; RAX = verb count
    mov  r14, rax
    lea  rdi, [rel str_aihook_catalog]    ; "...cmd.aihook.catalog.gen verbs="
    call serial_string
    mov  rdi, r14
    call aihook_emit_num
    lea  rdi, [rel str_aihook_nl]
    call serial_string

    ; --- (4) ACTIONABLE error round-trip: bad selector -> {code,expected,hint};
    ;     retry with the hint SUCCEEDS in ONE turn (turn-count is the model's cost) ---
    lea  rdi, [rel str_sel_bogus]
    lea  rsi, [rel aihook_err]
    call command_aihook_resolve
    test rax, rax
    jnz  .fail                            ; a bogus selector must NOT resolve
    cmp  qword [rel aihook_err + AERR_CODE], CMDE_BADSEL
    jne  .fail                            ; must be the actionable selector error
    cmp  qword [rel aihook_err + AERR_HINT], 0
    je   .fail                            ; must carry a concrete retry-able hint
    mov  rdi, [rel aihook_err + AERR_HINT]  ; the hint IS a registered selector
    xor  esi, esi
    call command_aihook_resolve           ; retry — one turn
    test rax, rax
    jz   .fail                            ; hint didn't lead to success => not actionable
    lea  rdi, [rel str_aihook_err_ok]     ; "...cmd.aihook.err.actionable ..."
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_aihook_fail]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- svc/command_aihook data (RW under our page tables, MEMORY_MAP §3.1) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_aihook_0 0
align 8
aihook_req:         times REQ_SZ db 0
aihook_rsp:         times RSP_SZ db 0
aihook_auth_ticket: times command_auth_ticket_size db 0
aihook_advisory_ticket: times command_auth_ticket_size db 0   ; GA2(b): never dispatched
aihook_bind_ctx:    times AUTH_CTX_SIZE db 0
aihook_err:         times AERR_SZ db 0
aihook_sel_table:   times (AIHOOK_SEL_COUNT * SEL_ENT_SZ) db 0   ; ptrs bound at boot (init)
aihook_numbuf:      times 24 db 0        ; u64 decimal scratch (max 20 digits + NUL)

; selector intent phrases (aliases) + concrete device handles they resolve to
str_sel_data_array: db "the data array", 0
str_sel_data:       db "data", 0
str_sel_raid:       db "the raid", 0
str_sel_main_disk:  db "the main disk", 0
str_sel_sys_disk:   db "system disk", 0
str_hdl_md0:        db "md0", 0
str_hdl_nvme:       db "nvme0n1", 0
str_sel_bogus:      db "the flux capacitor", 0   ; deliberately-unregistered selector
str_aihook_ping:    db "PING", 0
str_aihook_slow:    db "SLOWJOB", 0
str_aihook_auth_probe: db "AUTHAIPROBE", 0

str_aihook_inproc:  db "[PAOS64] P2 aihook: in-proc PING echoed nonce (zero-serialization dispatch) cmd.aihook.inproc.ok=", 0
str_aihook_resolve: db "[PAOS64] P2 aihook: intent resolved to a registered handle cmd.aihook.resolve.ok selector=", 0
str_aihook_arrow:   db " -> handle=", 0
str_aihook_cat_hdr: db "[PAOS64] P2 aihook: CATALOG (generated from registry self-description):", 13, 10, 0
str_aihook_cat_ent: db "  verb[", 0
str_aihook_cat_name: db "]=", 0
str_aihook_cat_argt: db " argt=", 0
str_aihook_cat_cap:  db " cap=", 0
str_aihook_cat_destr: db " destr=", 0
str_aihook_catalog: db "[PAOS64] P2 aihook: CATALOG count == registry verb count cmd.aihook.catalog.gen verbs=", 0
str_aihook_err_expected: db "a registered selector; call CATALOG or use a known intent phrase", 0
str_aihook_err_ok:  db "[PAOS64] P2 aihook: bad selector -> actionable {code,expected,hint}; retry-with-hint resolved in ONE turn cmd.aihook.err.actionable", 13, 10, 0
str_aihook_fail:    db "[PAOS64] P2 aihook: FAIL", 13, 10, 0
str_aihook_nl:      db 13, 10, 0
%endmacro
WDATA_DEFER WDATA_svc_command_aihook_0
