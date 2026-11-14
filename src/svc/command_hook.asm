;; MODULE svc/command_hook
;; LAYER 5
;; EXPORTS command_hook_request_copy, command_hook_request_matches, command_hook_default_instance, command_hook_declare, command_hook_edge_register, command_hook_scrub, command_hook_refuse, command_hook_arg, command_hook_arg_reset, command_hook_arg_str, command_hook_arg_strn, command_hook_arg_dec, hook_p_op, command_hook_out_reset, command_hook_out_str, command_hook_out_strn, command_hook_out_dec, command_hook_out_ready, command_hook_out_buf, command_hook_word_eq, command_hook_after_word, command_hook_parse_dec, command_hook_request_owner
;; IMPORTS core/lib/fmt, core/lib/str, core/lib/mem, svc/command, svc/command_auth, svc/command_card, sec/session
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/command_hook.asm -- RCQ-15 typed AI hooks (RC spec 21.1, 21.2, 5.3).
;
; ONE registry verb, HOOK, is a typed namespace over every shipped interface
; edge. The registry is near capacity (272 rows, 254 used on a desktop boot),
; so an edge never costs a verb: edges register a descriptor here instead.
;
;   HOOK [LIST]                       static public catalog; pages if full reply cannot fit
;   HOOK CATALOG [unsigned cursor]     complete bounded catalog page; next= continues
;   HOOK DESCRIBE <edge>              the edge's typed schema (static, public)
;   HOOK GET|SET|INPUT|CANCEL <edge>[:<inst>] [args]
;                                     delegated to the edge's NATIVE verb
;   HOOK LIST <edge>                  the edge's instances (delegated)
;   HOOK OBSERVE <edge>[:<inst>] [args] [since=<hex>]
;                                     delegated GET, answered as a change witness
;   HOOK EVENTS [<since>]             bounded ring of hook mutation results
;
; HOOKS NEVER GRANT AUTHORITY. HOOK itself is on the exact public floor, so its
; outer dispatch consumes no owner ticket and runs no effect. Every edge
; operation is planned into the edge's own native verb and argument, then run
; through the ONE command_dispatch with the caller's own source, principal,
; capability and idempotency key copied unchanged. The native verb's session
; predicate, capability/owner gate (which consumes the caller's ticket exactly
; once) and handler checks all run exactly as if the caller had typed the
; native verb. Nothing here raises a principal, mints a ticket or calls a
; handler directly. An edge may be STRICTER than its native verb (an edge post
; filter can redact a secret or refuse a mis-targeted input), never looser, and
; a post filter runs only after the native gate has accepted the caller.
;
; Secrets: the hook layer never reads a secret. Edge post filters replace a
; secret-bearing native field with redacted=1 (the lock screen password's
; mask length included). HOOK is a transcript/audit secret verb, because its
; arguments may carry keystrokes or field text for the native verb.
;
; Not applicable is explicit: an op an edge does not support answers
; "hook na edge=<e> op=<OP>" with CMDE_BADARG and a hint to DESCRIBE, so a
; caller can tell "unsupported" from "refused" and from "failed".
; ============================================================================

HOOK_EDGE_MAX  equ 128          ; event indices remain byte-sized; discovery pages by bytes
HOOK_CAT_BYTES equ 768          ; complete entry bytes; room for header, cursor and footer
HOOK_LINE_MAX  equ 192          ; request text copied once, NUL-bounded
HOOK_ARG_MAX   equ 224          ; the native argument an edge plans
HOOK_OUT_MAX   equ 1024         ; retained budget for existing hook adapters/catalog
HOOK_OUT_CAP   equ 2048         ; actual staging: complete native CPU observation row
HOOK_EV_MAX    equ 16           ; event ring (power of two)
HOOK_EV_PAGE   equ 8            ; events per EVENTS reply
HOOK_EV_SZ     equ 16

; edge descriptor (owned by the edge module; pointer fields bound at its declare)
HE_NAME        equ 0            ; cstr edge name, e.g. "term"
HE_KIND        equ 8            ; cstr "app" | "widget" | "service"
HE_SCHEMA      equ 16           ; cstr DESCRIBE body (typed ops/fields)
HE_PLAN        equ 24           ; plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
HE_POST        equ 32           ; post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = hook reply staged; or 0
HE_OBUF        equ 40           ; the native verb's staged reply buffer (OBSERVE witness source)
HE_OREADY      equ 48           ; ptr to its ready byte
HE_WITNESS     equ 56           ; NUL-separated key list ("" ends); 0 = hash the whole reply
HE_SZ          equ 64

; op codes (index + 1 into str_hook_ops)
HOP_LIST       equ 1
HOP_DESCRIBE   equ 2
HOP_GET        equ 3
HOP_SET        equ 4
HOP_INPUT      equ 5
HOP_OBSERVE    equ 6
HOP_CANCEL     equ 7
HOP_EVENTS     equ 8
HOP_CATALOG    equ 9

; plan reasons (EDX when a plan returns 0)
HOOK_PLAN_NA       equ 1        ; the edge does not support this op
HOOK_PLAN_BADARG   equ 2        ; malformed instance or argument
HOOK_PLAN_NOEDGE   equ 3
HOOK_PLAN_NOVERB   equ 4        ; the native verb is not registered in this profile/phase
HOOK_PLAN_BADOP    equ 6
HOOK_PLAN_LONG     equ 7

; event record
HEV_SEQ        equ 0
HEV_EDGE       equ 8
HEV_OP         equ 9
HEV_CODE       equ 10
HEV_SOURCE     equ 11

; command_hook_declare -- register HOOK. Public exact spelling (command_auth_required_cap);
;   cap 0, read-only: its own effect is none.
command_hook_declare:
    lea  rdi, [rel str_verb_hook]
    lea  rsi, [rel cmd_verb_hook]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    jmp  command_register_verb

; command_hook_edge_register(RDI = descriptor) -> EAX = edge index, or -1 (full,
;   nameless, or a duplicate name). Edges are never removed.
command_hook_edge_register:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rax, [r12 + HE_NAME]
    test rax, rax
    jz   .bad
    cmp  qword [r12 + HE_PLAN], 0
    je   .bad
    xor  ebx, ebx
.dup:
    cmp  ebx, [rel hook_edge_count]
    jae  .add
    lea  rax, [rel hook_edges]
    mov  rax, [rax + rbx*8]
    mov  rdi, [rax + HE_NAME]
    mov  rsi, [r12 + HE_NAME]
    call strcmp
    test eax, eax
    jz   .bad
    inc  ebx
    jmp  .dup
.add:
    mov  eax, [rel hook_edge_count]
    cmp  eax, HOOK_EDGE_MAX
    jae  .bad
    lea  rcx, [rel hook_edges]
    mov  [rcx + rax*8], r12
    inc  dword [rel hook_edge_count]
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Shared parse. hook_parse(RSI = request text or 0) -> EAX = 0 parsed, else a
; HOOK_PLAN_* status. Fills hook_p_op, hook_p_edge (descriptor or 0),
; hook_p_edge_idx, hook_p_inst / hook_p_rest (pointers into hook_line, "" when
; absent) and hook_p_since / hook_p_has_since (OBSERVE's trailing since=<hex>).
; ---------------------------------------------------------------------------
hook_parse:
    push rbx
    push r12
    push r13
    mov  qword [rel hook_p_edge], 0
    mov  dword [rel hook_p_edge_idx], -1
    mov  qword [rel hook_p_since], 0
    mov  byte [rel hook_p_has_since], 0
    lea  rax, [rel hook_empty]
    mov  [rel hook_p_inst], rax
    mov  [rel hook_p_rest], rax
    mov  dword [rel hook_p_op], HOP_LIST
    ; copy the request text once (bounded; an over-long line is refused whole)
    lea  rdi, [rel hook_line]
    xor  ecx, ecx
    test rsi, rsi
    jz   .copied
.cp:
    mov  al, [rsi + rcx]
    test al, al
    jz   .copied
    cmp  ecx, HOOK_LINE_MAX - 1
    jae  .long
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .cp
.long:
    mov  byte [rdi], 0
    mov  eax, HOOK_PLAN_LONG
    jmp  .out
.copied:
    mov  byte [rdi + rcx], 0
    ; op
    lea  rdi, [rel hook_line]
    call hook_skip_sp
    cmp  byte [rax], 0
    je   .ok                              ; HOOK alone = HOOK LIST
    mov  r12, rax
    mov  rdi, rax
    call hook_split
    mov  r13, rax                         ; after the op
    lea  rbx, [rel str_hook_ops]
    mov  r8d, 1
.op:
    cmp  byte [rbx], 0
    je   .badop
    mov  rdi, r12
    mov  rsi, rbx
    push r8
    call command_hook_word_eq
    pop  r8
    test eax, eax
    jnz  .op_hit
.op_next:
    inc  rbx
    cmp  byte [rbx - 1], 0
    jne  .op_next
    inc  r8d
    jmp  .op
.badop:
    mov  eax, HOOK_PLAN_BADOP
    jmp  .out
.op_hit:
    mov  [rel hook_p_op], r8d
    ; EVENTS and CATALOG take their own decimal cursor, never an edge.
    cmp  r8d, HOP_EVENTS
    je   .cursor
    cmp  r8d, HOP_CATALOG
    jne  .edge
.cursor:
    mov  [rel hook_p_rest], r13
    jmp  .ok
.edge:
    cmp  byte [r13], 0
    jne  .edge_tok
    cmp  r8d, HOP_LIST
    je   .ok                              ; LIST with no edge = the catalog
    mov  eax, HOOK_PLAN_NOEDGE
    jmp  .out
.edge_tok:
    mov  r12, r13
    mov  rdi, r13
    call hook_split
    mov  r13, rax                         ; rest
    mov  [rel hook_p_rest], r13
    ; split "<edge>:<inst>"
    mov  rdi, r12
.colon:
    mov  al, [rdi]
    test al, al
    jz   .find
    cmp  al, ':'
    je   .cut
    inc  rdi
    jmp  .colon
.cut:
    mov  byte [rdi], 0
    inc  rdi
    mov  [rel hook_p_inst], rdi
.find:
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel hook_edge_count]
    jae  .noedge
    lea  rax, [rel hook_edges]
    mov  rax, [rax + rbx*8]
    push rax
    mov  rdi, [rax + HE_NAME]
    mov  rsi, r12
    call strcmp
    pop  rdx
    test eax, eax
    jz   .hit
    inc  ebx
    jmp  .scan
.noedge:
    mov  eax, HOOK_PLAN_NOEDGE
    jmp  .out
.hit:
    mov  [rel hook_p_edge], rdx
    mov  [rel hook_p_edge_idx], ebx
    cmp  dword [rel hook_p_op], HOP_OBSERVE
    jne  .ok
    ; OBSERVE: a trailing " since=<hex>" token is the hook's, not the edge's
    mov  rdi, r13
    xor  rsi, rsi                         ; last token start
.last:
    mov  al, [rdi]
    test al, al
    jz   .last_done
    cmp  al, ' '
    jne  .last_ch
    cmp  byte [rdi + 1], ' '
    je   .last_ch
    cmp  byte [rdi + 1], 0
    je   .last_ch
    lea  rsi, [rdi + 1]
.last_ch:
    inc  rdi
    jmp  .last
.last_done:
    test rsi, rsi
    jnz  .since_tok
    mov  rsi, r13                         ; the whole rest is one token
.since_tok:
    cmp  dword [rsi], 'sinc'
    jne  .ok
    cmp  word [rsi + 4], 'e='
    jne  .ok
    lea  rdi, [rsi + 6]
    push rsi
    call hook_parse_hex
    pop  rsi
    test edx, edx
    jz   .ok                              ; not hex: the edge sees it (and refuses it)
    mov  [rel hook_p_since], rax
    mov  byte [rel hook_p_has_since], 1
    mov  byte [rsi], 0                    ; cut it from the edge's rest
    cmp  rsi, r13
    je   .ok
    mov  byte [rsi - 1], 0
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hook_plan_edge -> RAX = registered native verb id, or -1 with EAX status in
;   hook_plan_status. Runs the edge's plan into command_hook_arg (OBSERVE plans
;   as GET). Pure: reads no state outside the edge's own planner.
;   An edge that will refuse an op it can only judge from live state (Terminal
;   keys for an unfocused window) still plans a harmless native read under the
;   SAME native verb and sets command_hook_refuse; its post filter answers the
;   refusal only after that verb's gate has accepted the caller.
hook_plan_edge:
    push rbx
    mov  rbx, [rel hook_p_edge]
    mov  dword [rel command_hook_refuse], 0
    call command_hook_arg_reset
    mov  edi, [rel hook_p_op]
    cmp  edi, HOP_OBSERVE
    jne  .plan
    mov  edi, HOP_GET
.plan:
    mov  [rel hook_p_plan_op], edi
    mov  rsi, [rel hook_p_inst]
    mov  rdx, [rel hook_p_rest]
    call [rbx + HE_PLAN]
    test rax, rax
    jnz  .named
    mov  eax, HOOK_PLAN_NA
    cmp  edx, HOOK_PLAN_BADARG
    jne  .fail
    mov  eax, HOOK_PLAN_BADARG
    jmp  .fail
.named:
    mov  [rel hook_p_verb_name], rax
    cmp  byte [rel hook_arg_overflow], 0
    je   .lookup
    mov  eax, HOOK_PLAN_LONG
    jmp  .fail
.lookup:
    mov  rdi, rax
    call command_lookup
    cmp  rax, -1
    jne  .found
    mov  eax, HOOK_PLAN_NOVERB
    jmp  .fail
.found:
    mov  dword [rel hook_plan_status], 0
    pop  rbx
    ret
.fail:
    mov  [rel hook_plan_status], eax
    mov  rax, -1
    pop  rbx
    ret

; hook_arg_value(RDI = verb id) -> RAX = the REQ_ARG the native verb's argt takes
hook_arg_value:
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .text
    cmp  eax, ARGT_U64
    je   .u64
    xor  eax, eax
    ret
.text:
    lea  rax, [rel command_hook_arg]
    ret
.u64:
    lea  rdi, [rel command_hook_arg]
    call command_hook_parse_dec
    ret

; Post filters may narrow typed exposure to the actual nested request owner.
; Never synthesize a request, principal, source or ticket. Native dispatch has
; already consumed the required capability; this checks only owner identity.
command_hook_request_owner:
    lea  rdi, [rel hook_req]
    jmp  command_auth_ticket_owner

; ---------------------------------------------------------------------------
; VERB: HOOK (RDI = req, RSI = rsp). See the module header.
; ---------------------------------------------------------------------------
cmd_verb_hook:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi                         ; the caller's request (never modified)
    mov  r13, rsi                         ; the response the native verb fills
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    mov  qword [r13 + RSP_HINT], 0
    cmp  byte [rel hook_busy], 0
    jne  .nested
    mov  byte [rel hook_busy], 1
    mov  rsi, [r12 + REQ_ARG]
    call hook_parse
    test eax, eax
    jnz  .parse_fail
    mov  eax, [rel hook_p_op]
    cmp  eax, HOP_EVENTS
    je   .events
    cmp  eax, HOP_CATALOG
    je   .catalog_page
    cmp  eax, HOP_DESCRIBE
    je   .describe
    cmp  qword [rel hook_p_edge], 0
    je   .catalog                         ; LIST without an edge
    ; Every effectful hook operation shares the same provenance refusal.
    cmp  dword [rel hook_p_op], HOP_SET
    je   .taint_check
    cmp  dword [rel hook_p_op], HOP_INPUT
    je   .taint_check
    cmp  dword [rel hook_p_op], HOP_CANCEL
    jne  .untainted
.taint_check:
    mov  rdi, r12
    call session_shell_request_principal  ; RCQ-40 J2 term 9: a principal that read web text sets nothing
    mov  rdi, rax
    call ai_web_taint_of
    test eax, eax
    jz   .untainted
    lea  rdi, [rel str_hook_web_tainted]
    lea  rsi, [rel str_hook_hint_tainted]
    mov  edx, CMDE_AUTHDENY
    jmp  .err
.untainted:
    ; ---- delegated edge operation ----
    call hook_plan_edge
    cmp  rax, -1
    je   .plan_fail
    mov  r14, rax                         ; native verb id
    mov  rbx, [rel hook_p_edge]
    mov  [rel hook_req + REQ_VERB], r14
    mov  rax, [r12 + REQ_CAP]
    mov  [rel hook_req + REQ_CAP], rax
    mov  rax, [r12 + REQ_IDEM]
    mov  [rel hook_req + REQ_IDEM], rax
    mov  qword [rel hook_req + REQ_SEL], 0
    mov  rax, [r12 + REQ_SOURCE]
    mov  [rel hook_req + REQ_SOURCE], rax
    mov  rax, [r12 + REQ_PRINCIPAL]
    mov  [rel hook_req + REQ_PRINCIPAL], rax
    mov  rdi, r14
    call hook_arg_value
    mov  [rel hook_req + REQ_ARG], rax
    inc  qword [rel hook_delegations]
    lea  rdi, [rel hook_req]
    mov  rsi, r13
    call command_dispatch                 ; THE one entry: the native gate runs here
    ; edge post filter (stricter only; the native gate has already decided)
    xor  r15d, r15d                       ; 1 = a hook reply is staged
    mov  rax, [rbx + HE_POST]
    test rax, rax
    jz   .posted
    mov  edi, [rel hook_p_plan_op]
    mov  rsi, [rel hook_p_inst]
    mov  rdx, [rel hook_p_rest]
    mov  rcx, r13
    call rax
    mov  r15d, eax
.posted:
    mov  eax, [rel hook_p_op]
    cmp  eax, HOP_OBSERVE
    je   .observe
    cmp  eax, HOP_SET
    je   .record
    cmp  eax, HOP_INPUT
    je   .record
    cmp  eax, HOP_CANCEL
    je   .record
    jmp  .delegated
.record:
    call hook_event_record
    jmp  .delegated
.observe:
    cmp  qword [r13 + RSP_CODE], CMDE_OK
    jne  .delegated                       ; a refusal passes through unchanged
    mov  rdi, rbx
    mov  esi, r15d
    call hook_witness                     ; RAX = witness over the edge's declared keys
    mov  rbp, rax
    mov  rax, [rbx + HE_OREADY]
    test rax, rax
    jz   .obs_stage
    mov  byte [rax], 0                    ; the witness replaces the native text
.obs_stage:
    call command_hook_out_reset
    lea  rdi, [rel str_hook_observe]
    call command_hook_out_str
    call hook_out_edge_inst
    lea  rdi, [rel str_hook_witness]
    call command_hook_out_str
    mov  rdi, rbp
    call hook_out_hex16
    lea  rdi, [rel str_hook_changed]
    call command_hook_out_str
    mov  edi, 1
    cmp  byte [rel hook_p_has_since], 0
    je   .obs_changed
    xor  edi, edi
    cmp  rbp, [rel hook_p_since]
    setne dil
.obs_changed:
    call command_hook_out_dec
    mov  byte [rel command_hook_out_ready], 1
    jmp  .delegated
.delegated:
    cmp  r15d, 0
    je   .done
    mov  byte [rel command_hook_out_ready], 1
    jmp  .done

    ; ---- hook-local answers ----
.catalog:
    ; Preserve the exact legacy reply only when every entry and footer fit.
    ; Count digits exactly (the table is bounded at128).
    mov  esi, HOOK_OUT_MAX - 1 - (str_hook_catalog_end - str_hook_catalog - 1) - (str_hook_cat_ops_end - str_hook_cat_ops - 1) - 1
    cmp  dword [rel hook_edge_count], 10
    jb   .cat_budget
    dec  esi
    cmp  dword [rel hook_edge_count], 100
    jb   .cat_budget
    dec  esi
.cat_budget:
    xor  edi, edi
    call hook_catalog_fit
    cmp  eax, [rel hook_edge_count]
    jne  .catalog_first
    xor  ebp, ebp                        ; legacy format
    mov  r15d, eax                       ; exclusive end
    call command_hook_out_reset
    lea  rdi, [rel str_hook_catalog]
    call command_hook_out_str
    mov  edi, [rel hook_edge_count]
    call command_hook_out_dec
    xor  ebx, ebx
.cat_edge:
    cmp  ebx, r15d
    jae  .cat_ops
    lea  rdi, [rel str_hook_sp]
    call command_hook_out_str
    lea  rax, [rel hook_edges]
    mov  r14, [rax + rbx*8]
    mov  rdi, [r14 + HE_NAME]
    call command_hook_out_str
    lea  rdi, [rel str_hook_colon]
    call command_hook_out_str
    mov  rdi, [r14 + HE_KIND]
    call command_hook_out_str
    inc  ebx
    jmp  .cat_edge
.cat_ops:
    lea  rdi, [rel str_hook_cat_ops]
    test ebp, ebp
    jz   .cat_footer
    lea  rdi, [rel str_hook_page_ops]
.cat_footer:
    call command_hook_out_str
    jmp  .stage_ok
.catalog_page:
    mov  rdi, [rel hook_p_rest]
    call hook_events_cursor              ; overflow-safe whole decimal argument
    test edx, edx
    jz   .catalog_badarg
    mov  ecx, [rel hook_edge_count]
    cmp  rax, rcx
    ja   .catalog_badarg
    mov  ebx, eax
    jmp  .catalog_build
.catalog_first:
    xor  ebx, ebx
.catalog_build:
    mov  edi, ebx
    mov  esi, HOOK_CAT_BYTES
    call hook_catalog_fit
    mov  r15d, eax
    cmp  ebx, eax
    jne  .catalog_header
    cmp  ebx, [rel hook_edge_count]
    jne  .catalog_badarg                 ; an oversized entry must never stall continuation
.catalog_header:
    mov  ebp, 1
    call command_hook_out_reset
    lea  rdi, [rel str_hook_page]
    call command_hook_out_str
    mov  edi, [rel hook_edge_count]
    call command_hook_out_dec
    lea  rdi, [rel str_hook_from]
    call command_hook_out_str
    mov  edi, ebx
    call command_hook_out_dec
    lea  rdi, [rel str_hook_next]
    call command_hook_out_str
    mov  edi, r15d
    call command_hook_out_dec
    lea  rdi, [rel str_hook_more]
    call command_hook_out_str
    xor  edi, edi
    cmp  r15d, [rel hook_edge_count]
    setb dil
    call command_hook_out_dec
    jmp  .cat_edge
.catalog_badarg:
    lea  rdi, [rel str_hook_bad_arg]
    lea  rsi, [rel str_hook_hint_catalog]
    mov  edx, CMDE_BADARG
    jmp  .err
.describe:
    cmp  qword [rel hook_p_edge], 0
    je   .noedge
    mov  rbx, [rel hook_p_edge]
    call command_hook_out_reset
    lea  rdi, [rel str_hook_describe]
    call command_hook_out_str
    mov  rdi, [rbx + HE_NAME]
    call command_hook_out_str
    lea  rdi, [rel str_hook_kind]
    call command_hook_out_str
    mov  rdi, [rbx + HE_KIND]
    call command_hook_out_str
    lea  rdi, [rel str_hook_sp]
    call command_hook_out_str
    mov  rdi, [rbx + HE_SCHEMA]
    call command_hook_out_str
    jmp  .stage_ok
.events:
    mov  rdi, r12
    call hook_owner_read
    cmp  eax, 1
    jne  .events_deny
    mov  rdi, [rel hook_p_rest]
    call hook_events_cursor
    test edx, edx
    jz   .events_badarg
    call hook_events_reply
    jmp  .stage_ok
.events_badarg:
    lea  rdi, [rel str_hook_bad_arg]
    lea  rsi, [rel str_hook_hint_events]
    mov  edx, CMDE_BADARG
    jmp  .err
.events_deny:
    test eax, eax
    jz   .events_owner_only
    ; the native gate refused: its AUTH_REFUSED text is the reply (no hook text staged)
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    mov  rax, CMD_AUTH_CAP_MUTATE
    mov  [r13 + RSP_EXPECTED], rax
    lea  rax, [rel command_auth_out_buf]
    mov  [r13 + RSP_HINT], rax
    jmp  .done
.events_owner_only:
    call command_hook_out_reset
    lea  rdi, [rel str_hook_owner_only]
    call command_hook_out_str
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_hook_hint_owner]
    mov  [r13 + RSP_HINT], rax
    jmp  .stage
.stage_ok:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.stage:
    mov  byte [rel command_hook_out_ready], 1
    jmp  .done

    ; ---- refusals the hook layer answers itself (static grammar only) ----
.parse_fail:
    cmp  eax, HOOK_PLAN_NOEDGE
    je   .noedge
    cmp  eax, HOOK_PLAN_LONG
    je   .long
    lea  rdi, [rel str_hook_bad_op]
    lea  rsi, [rel str_hook_hint_ops]
    mov  edx, CMDE_BADARG
    jmp  .err
.noedge:
    lea  rdi, [rel str_hook_no_edge]
    lea  rsi, [rel str_hook_hint_list]
    mov  edx, CMDE_BADSEL
    jmp  .err
.long:
    lea  rdi, [rel str_hook_too_long]
    lea  rsi, [rel str_hook_hint_long]
    mov  edx, CMDE_BADARG
    jmp  .err
.nested:
    call command_hook_out_reset
    lea  rdi, [rel str_hook_nested]
    call command_hook_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  byte [rel command_hook_out_ready], 1
    jmp  .out                             ; the outer HOOK still owns hook_busy
.plan_fail:
    mov  eax, [rel hook_plan_status]
    cmp  eax, HOOK_PLAN_NA
    je   .na
    cmp  eax, HOOK_PLAN_NOVERB
    je   .noverb
    cmp  eax, HOOK_PLAN_LONG
    je   .long
    call command_hook_out_reset
    lea  rdi, [rel str_hook_bad_arg]
    call command_hook_out_str
    call hook_out_edge_op
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hook_hint_describe]
    mov  [r13 + RSP_HINT], rax
    jmp  .stage
.na:
    call command_hook_out_reset
    lea  rdi, [rel str_hook_na]
    call command_hook_out_str
    call hook_out_edge_op
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hook_hint_describe]
    mov  [r13 + RSP_HINT], rax
    jmp  .stage
.noverb:
    call command_hook_out_reset
    lea  rdi, [rel str_hook_na]
    call command_hook_out_str
    call hook_out_edge_op
    lea  rdi, [rel str_hook_unregistered]
    call command_hook_out_str
    mov  rdi, [rel hook_p_verb_name]
    call command_hook_out_str
    mov  qword [r13 + RSP_CODE], CMDE_NOVERB
    lea  rax, [rel str_hook_hint_unregistered]
    mov  [r13 + RSP_HINT], rax
    jmp  .stage
.err:                                     ; RDI = text, RSI = hint, RDX = code
    mov  rbx, rdi
    mov  r14, rsi
    mov  r15, rdx
    call command_hook_out_reset           ; clobbers RAX only
    mov  rdi, rbx
    call command_hook_out_str
    mov  [r13 + RSP_CODE], r15
    mov  [r13 + RSP_HINT], r14
    jmp  .stage

.done:
    call command_hook_scrub
    mov  byte [rel hook_busy], 0
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; hook_catalog_fit(EDI=start, ESI=entry-byte budget) -> EAX=exclusive end.
; Never emit a partial descriptor. Static kernel strings are scanned only up
; to the remaining budget, including the leading space and name/kind colon.
; Preserves callee-saved registers; no native dispatch or authority reads.
hook_catalog_fit:
    mov  eax, edi
.entry:
    cmp  eax, [rel hook_edge_count]
    jae  .done
    cmp  esi, 2
    jb   .done
    lea  rdx, [rel hook_edges]
    mov  rdx, [rdx + rax*8]
    mov  rdi, [rdx + HE_NAME]
    mov  ecx, 2
.name:
    cmp  byte [rdi], 0
    je   .kind_start
    cmp  ecx, esi
    jae  .done
    inc  ecx
    inc  rdi
    jmp  .name
.kind_start:
    mov  rdi, [rdx + HE_KIND]
.kind:
    cmp  byte [rdi], 0
    je   .fit
    cmp  ecx, esi
    jae  .done
    inc  ecx
    inc  rdi
    jmp  .kind
.fit:
    sub  esi, ecx
    inc  eax
    jmp  .entry
.done:
    ret

; command_hook_scrub -- the planned native argument and the request copy may hold
;   keystrokes or field text: zero both. clobbers: RAX, RCX, RDX, RSI, RDI
command_hook_scrub:
    lea  rdi, [rel command_hook_arg]
    xor  esi, esi
    mov  edx, HOOK_ARG_MAX
    call memset
    lea  rdi, [rel hook_line]
    xor  esi, esi
    mov  edx, HOOK_LINE_MAX
    jmp  memset

; hook_owner_read(RDI = req) -> EAX 1 when the caller may read owner-only hook
;   state (the event ring): the console owner, an in-image kernel caller, or a
;   remote request that passes the native owner gate itself. HOOK is on the public
;   floor, so no outer gate ran: remote EVENTS calls command_auth_gate with the cap
;   an undeclared non-public read gets (MUTATE), exactly as the WALLPAPER handler
;   gates its non-public forms, and then needs the owner principal on that ticket.
;   EAX -1: the gate refused (an unsigned read answers the standard AUTH_REFUSED
;   naming the cap, from command_auth_out_buf); 0: authenticated but not the owner
;   (the SYSTEM AI and the advisor are not the owner).
hook_owner_read:
    cmp  byte [rel command_auth_remote_active], 1
    je   .remote
    mov  rax, [rdi + REQ_SOURCE]
    cmp  rax, CMD_SOURCE_INTERNAL
    je   .yes
    cmp  rax, CMD_SOURCE_CONSOLE
    jne  .no
    cmp  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .no
.yes:
    mov  eax, 1
    ret
.remote:
    mov  rdi, CMD_AUTH_CAP_MUTATE
    lea  rsi, [rel str_verb_hook]
    call command_auth_gate
    test eax, eax
    jnz  .gate_refused
    jmp  command_auth_owner_envelope      ; the consumed ticket's principal decides
.gate_refused:
    mov  eax, -1
    ret
.no:
    xor  eax, eax
    ret

; hook_event_record -- one bounded ring record for a SET/INPUT/CANCEL outcome
;   (accepted or refused). Values are never recorded: edge, op, code, source.
hook_event_record:
    ; a native-gate refusal (unsigned, wrong cap) is counted, never ringed: a
    ; stream of refused LAN lines must not flush the owner's history (srcreview F3)
    mov  rax, [r13 + RSP_CODE]
    cmp  rax, CMDE_AUTHDENY
    je   .refused
    cmp  rax, CMDE_CAPDENY
    je   .refused
    mov  rax, [rel hook_ev_next]
    inc  rax
    mov  [rel hook_ev_next], rax
    mov  rcx, rax
    and  ecx, HOOK_EV_MAX - 1
    shl  ecx, 4
    lea  rdx, [rel hook_ev_ring]
    add  rdx, rcx
    mov  [rdx + HEV_SEQ], rax
    mov  eax, [rel hook_p_edge_idx]
    mov  [rdx + HEV_EDGE], al
    mov  eax, [rel hook_p_op]
    mov  [rdx + HEV_OP], al
    mov  rax, [r13 + RSP_CODE]
    mov  [rdx + HEV_CODE], al
    mov  rax, [r12 + REQ_SOURCE]
    mov  [rdx + HEV_SOURCE], al
    ret
.refused:
    inc  qword [rel hook_ev_refused]
    ret

; hook_events_cursor(RDI = rest) -> RAX = whole unsigned decimal cursor,
;   EDX = 1 valid / 0 malformed or overflow. Empty/padded rest means zero.
;   Leading zeroes remain valid through the request line bound. This is kept
;   separate from command_hook_parse_dec, whose prefix ABI other edges use.
hook_events_cursor:
    call hook_skip_sp
    mov  rdi, rax
    xor  eax, eax
    mov  r8d, 10
    cmp  byte [rdi], 0
    je   .cursor_ok
.digit:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .cursor_end
    mul  r8
    test rdx, rdx
    jnz  .bad_cursor
    add  rax, rcx
    jc   .bad_cursor
    inc  rdi
    jmp  .digit
.bad_cursor:
    xor  edx, edx
    ret
.cursor_end:
    cmp  byte [rdi], 0
    je   .cursor_ok
    cmp  byte [rdi], ' '
    jne  .bad_cursor
.padding:
    inc  rdi
    cmp  byte [rdi], ' '
    je   .padding
    cmp  byte [rdi], 0
    jne  .bad_cursor
.cursor_ok:
    mov  edx, 1
    ret

; hook_events_reply(RAX = validated since) -- " hook events next=<seq> dropped=<n>
;   refused=<n> ev=<seq>:<edge>:<OP>:<code>...", oldest first, at most a page.
hook_events_reply:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rax                         ; since
    mov  r13, [rel hook_ev_next]          ; newest
    ; oldest still held
    mov  rbx, r13
    sub  rbx, HOOK_EV_MAX - 1
    cmp  r13, HOOK_EV_MAX
    jae  .have_oldest
    mov  ebx, 1
.have_oldest:
    call command_hook_out_reset
    lea  rdi, [rel str_hook_events]
    call command_hook_out_str
    mov  rdi, r13
    call command_hook_out_dec
    lea  rdi, [rel str_hook_dropped]
    call command_hook_out_str
    xor  edi, edi
    cmp  r12, r13
    jae  .drop                           ; a future cursor has lost no events
    lea  rax, [r12 + 1]
    cmp  rax, rbx
    jae  .drop
    mov  rdi, rbx
    sub  rdi, rax                         ; events after since that were overwritten
.drop:
    call command_hook_out_dec
    lea  rdi, [rel str_hook_refused]
    call command_hook_out_str
    mov  rdi, [rel hook_ev_refused]
    call command_hook_out_dec
    cmp  r12, r13
    jae  .done                           ; never wrap UINT64_MAX + 1 to history
    lea  rax, [r12 + 1]
    cmp  rax, rbx
    jae  .start
    mov  rax, rbx
.start:
    mov  rbx, rax                         ; first seq to print
    xor  r14d, r14d
.ev:
    cmp  rbx, r13
    ja   .done
    cmp  r14d, HOOK_EV_PAGE
    jae  .done
    mov  rcx, rbx
    and  ecx, HOOK_EV_MAX - 1
    shl  ecx, 4
    lea  r12, [rel hook_ev_ring]
    add  r12, rcx
    lea  rdi, [rel str_hook_ev]
    call command_hook_out_str
    mov  rdi, [r12 + HEV_SEQ]
    call command_hook_out_dec
    lea  rdi, [rel str_hook_colon]
    call command_hook_out_str
    movzx eax, byte [r12 + HEV_EDGE]
    lea  rcx, [rel hook_edges]
    mov  rax, [rcx + rax*8]
    mov  rdi, [rax + HE_NAME]
    call command_hook_out_str
    lea  rdi, [rel str_hook_colon]
    call command_hook_out_str
    movzx edi, byte [r12 + HEV_OP]
    call hook_op_name
    mov  rdi, rax
    call command_hook_out_str
    lea  rdi, [rel str_hook_colon]
    call command_hook_out_str
    movzx edi, byte [r12 + HEV_CODE]
    call command_hook_out_dec
    cmp  rbx, r13
    je   .done                           ; newest emitted, including UINT64_MAX
    inc  rbx
    inc  r14d
    jmp  .ev
.done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hook_witness(RDI = edge, ESI = 1 when the post filter staged the reply) -> RAX
;   FNV-1a 64 over "<key><value>" for each declared witness key, or over the whole
;   reply when the edge declares none. A missing key hashes as the bare key.
hook_witness:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    lea  r12, [rel command_hook_out_buf]
    test esi, esi
    jnz  .src
    mov  r12, [rbx + HE_OBUF]
    mov  rax, [rbx + HE_OREADY]
    test rax, rax
    jz   .empty
    cmp  byte [rax], 1
    je   .src
.empty:
    lea  r12, [rel hook_empty]
.src:
    mov  r14, 0xcbf29ce484222325          ; FNV-1a 64 offset basis
    mov  r13, [rbx + HE_WITNESS]
    test r13, r13
    jnz  .keys
    mov  rdi, r12
.all:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .done
    xor  r14, rax
    mov  rax, 0x100000001b3
    imul r14, rax
    inc  rdi
    jmp  .all
.keys:
    cmp  byte [r13], 0
    je   .done
    ; hash the key itself
    mov  rdi, r13
.key_b:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .key_find
    xor  r14, rax
    mov  rax, 0x100000001b3
    imul r14, rax
    inc  rdi
    jmp  .key_b
.key_find:
    mov  rdi, r12
    mov  rsi, r13
    call hook_find
    test rax, rax
    jz   .key_next
    mov  rdi, rax                         ; the value: to the next space/CR/LF/NUL
.val:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .key_next
    cmp  eax, ' '
    je   .key_next
    cmp  eax, 13
    je   .key_next
    cmp  eax, 10
    je   .key_next
    xor  r14, rax
    mov  rax, 0x100000001b3
    imul r14, rax
    inc  rdi
    jmp  .val
.key_next:
    inc  r13
    cmp  byte [r13 - 1], 0
    jne  .key_next
    jmp  .keys
.done:
    mov  rax, r14
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hook_find(RDI = haystack, RSI = needle) -> RAX = the byte after the first match, or 0
hook_find:
.h:
    cmp  byte [rdi], 0
    je   .no
    xor  ecx, ecx
.n:
    mov  al, [rsi + rcx]
    test al, al
    jz   .yes
    cmp  al, [rdi + rcx]
    jne  .next
    inc  ecx
    jmp  .n
.next:
    inc  rdi
    jmp  .h
.yes:
    lea  rax, [rdi + rcx]
    ret
.no:
    xor  eax, eax
    ret

; " edge=<name>[:<inst>]" into the hook reply
hook_out_edge_inst:
    lea  rdi, [rel str_hook_edge]
    call command_hook_out_str
    mov  rax, [rel hook_p_edge]
    mov  rdi, [rax + HE_NAME]
    call command_hook_out_str
    mov  rax, [rel hook_p_inst]
    cmp  byte [rax], 0
    je   .out
    lea  rdi, [rel str_hook_colon]
    call command_hook_out_str
    mov  rdi, [rel hook_p_inst]
    call command_hook_out_str
.out:
    ret

; " edge=<name> op=<OP>" into the hook reply
hook_out_edge_op:
    lea  rdi, [rel str_hook_edge]
    call command_hook_out_str
    mov  rax, [rel hook_p_edge]
    mov  rdi, [rax + HE_NAME]
    call command_hook_out_str
    lea  rdi, [rel str_hook_op]
    call command_hook_out_str
    mov  edi, [rel hook_p_op]
    call hook_op_name
    mov  rdi, rax
    jmp  command_hook_out_str

; hook_op_name(EDI = op code) -> RAX = its name in str_hook_ops ("?" if none)
hook_op_name:
    lea  rax, [rel str_hook_ops]
    dec  edi
    js   .unknown
.l:
    test edi, edi
    jz   .check
.skip:
    inc  rax
    cmp  byte [rax - 1], 0
    jne  .skip
    dec  edi
    jmp  .l
.check:
    cmp  byte [rax], 0
    jne  .out
.unknown:
    lea  rax, [rel str_hook_qm]
.out:
    ret

; ---------------------------------------------------------------------------
; small text helpers (exported for edge modules)
; ---------------------------------------------------------------------------

; command_hook_word_eq(RDI = token, RSI = upper-case word) -> EAX 1 iff equal
;   ignoring ASCII case. clobbers: RAX, RCX, RDX
command_hook_word_eq:
    xor  ecx, ecx
.l:
    mov  al, [rdi + rcx]
    mov  dl, [rsi + rcx]
    cmp  al, 'a'
    jb   .c
    cmp  al, 'z'
    ja   .c
    sub  al, 32
.c:
    cmp  al, dl
    jne  .no
    test al, al
    jz   .yes
    inc  ecx
    jmp  .l
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; command_hook_after_word(RDI = text, RSI = upper-case word) -> RAX = the text after the word and
;   ONE space (or at the NUL when the word ends the text); 0 when the text does
;   not start with exactly that word (ASCII case ignored). clobbers: RAX, RCX, RDX
command_hook_after_word:
    xor  ecx, ecx
.l:
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .end
    mov  al, [rdi + rcx]
    cmp  al, 'a'
    jb   .c
    cmp  al, 'z'
    ja   .c
    sub  al, 32
.c:
    cmp  al, dl
    jne  .no
    inc  ecx
    jmp  .l
.end:
    lea  rax, [rdi + rcx]
    cmp  byte [rax], 0
    je   .out
    cmp  byte [rax], ' '
    jne  .no
    inc  rax
.out:
    ret
.no:
    xor  eax, eax
    ret

; hook_skip_sp(RDI) -> RAX = first non-space byte
hook_skip_sp:
    mov  rax, rdi
.l:
    cmp  byte [rax], ' '
    jne  .out
    inc  rax
    jmp  .l
.out:
    ret

; hook_split(RDI = token start) -> RAX = next token (spaces skipped); the token is
;   NUL-terminated in place.
hook_split:
    mov  rax, rdi
.l:
    mov  cl, [rax]
    test cl, cl
    jz   .out
    cmp  cl, ' '
    je   .cut
    inc  rax
    jmp  .l
.cut:
    mov  byte [rax], 0
    inc  rax
    mov  rdi, rax
    jmp  hook_skip_sp
.out:
    ret

; command_hook_parse_dec(RDI) -> RAX = value of the leading decimal digits (0 if none),
;   RDX = digit count. At most 19 digits are read.
command_hook_parse_dec:
    xor  eax, eax
    xor  edx, edx
.l:
    movzx ecx, byte [rdi + rdx]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .out
    cmp  edx, 19
    jae  .out
    imul rax, rax, 10
    add  rax, rcx
    inc  edx
    jmp  .l
.out:
    ret

; hook_parse_hex(RDI) -> RAX = value, EDX = digit count (0 = not hex or > 16 digits
;   or trailing garbage). The whole token must be hex.
hook_parse_hex:
    xor  eax, eax
    xor  edx, edx
.l:
    movzx ecx, byte [rdi + rdx]
    test ecx, ecx
    jz   .end
    cmp  ecx, ' '
    je   .end
    cmp  ecx, '0'
    jb   .bad
    cmp  ecx, '9'
    jbe  .dig
    or   ecx, 0x20
    cmp  ecx, 'a'
    jb   .bad
    cmp  ecx, 'f'
    ja   .bad
    sub  ecx, 'a' - 10
    jmp  .acc
.dig:
    sub  ecx, '0'
.acc:
    cmp  edx, 16
    jae  .bad
    shl  rax, 4
    or   rax, rcx
    inc  edx
    jmp  .l
.end:
    ret
.bad:
    xor  edx, edx
    ret

command_hook_arg_reset:
    lea  rax, [rel command_hook_arg]
    mov  [rel hook_arg_cur], rax
    mov  byte [rel command_hook_arg], 0
    mov  byte [rel hook_arg_overflow], 0
    ret

; command_hook_arg_str(RDI = cstr): append to the planned native argument (bounded;
;   an overflow is latched and the plan is refused, never truncated silently)
command_hook_arg_str:
    mov  rax, [rel hook_arg_cur]
    lea  rdx, [rel command_hook_arg + HOOK_ARG_MAX - 1]
.l:
    mov  cl, [rdi]
    test cl, cl
    jz   .out
    cmp  rax, rdx
    jae  .over
    mov  [rax], cl
    inc  rax
    inc  rdi
    jmp  .l
.over:
    mov  byte [rel hook_arg_overflow], 1
.out:
    mov  byte [rax], 0
    mov  [rel hook_arg_cur], rax
    ret

; command_hook_arg_strn(RDI = text, ESI = at most this many bytes; a NUL ends it sooner): append to the
;   planned native argument, bounded and latched like command_hook_arg_str. clobbers: RAX, RCX, RDX, RSI, RDI
command_hook_arg_strn:
    mov  rax, [rel hook_arg_cur]
    lea  rdx, [rel command_hook_arg + HOOK_ARG_MAX - 1]
.l:
    test esi, esi
    jz   .out
    mov  cl, [rdi]
    test cl, cl
    jz   .out
    cmp  rax, rdx
    jae  .over
    mov  [rax], cl
    inc  rax
    inc  rdi
    dec  esi
    jmp  .l
.over:
    mov  byte [rel hook_arg_overflow], 1
.out:
    mov  byte [rax], 0
    mov  [rel hook_arg_cur], rax
    ret

command_hook_arg_dec:
    lea  rsi, [rel hook_num_buf]
    call fmt_dec
    lea  rdi, [rel hook_num_buf]
    jmp  command_hook_arg_str

command_hook_out_reset:
    lea  rax, [rel command_hook_out_buf]
    mov  [rel hook_out_cur], rax
    mov  byte [rel command_hook_out_buf], 0
    ret

; command_hook_out_str(RDI = cstr): append to the staged hook reply (bounded)
command_hook_out_str:
    mov  rax, [rel hook_out_cur]
    lea  rdx, [rel command_hook_out_buf + HOOK_OUT_CAP - 1]
.l:
    mov  cl, [rdi]
    test cl, cl
    jz   .out
    cmp  rax, rdx
    jae  .out
    mov  [rax], cl
    inc  rax
    inc  rdi
    jmp  .l
.out:
    mov  byte [rax], 0
    mov  [rel hook_out_cur], rax
    ret

; command_hook_out_strn(RDI = text, ESI = at most this many bytes; a NUL ends it sooner): append to the
;   staged hook reply, bounded like command_hook_out_str. clobbers: RAX, RCX, RDX, RSI, RDI
command_hook_out_strn:
    mov  rax, [rel hook_out_cur]
    lea  rdx, [rel command_hook_out_buf + HOOK_OUT_CAP - 1]
.l:
    test esi, esi
    jz   .out
    mov  cl, [rdi]
    test cl, cl
    jz   .out
    cmp  rax, rdx
    jae  .out
    mov  [rax], cl
    inc  rax
    inc  rdi
    dec  esi
    jmp  .l
.out:
    mov  byte [rax], 0
    mov  [rel hook_out_cur], rax
    ret

command_hook_out_dec:
    lea  rsi, [rel hook_num_buf]
    call fmt_dec
    lea  rdi, [rel hook_num_buf]
    jmp  command_hook_out_str

hook_out_hex16:
    lea  rsi, [rel hook_num_buf]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel hook_num_buf]
    jmp  command_hook_out_str


; RDI caller-owned REQ_SZ destination; internal serialized custody helper.
; No admission/authority and no persistent shared stage.
command_hook_request_copy:
    lea  rsi, [rel hook_req]
    mov  ecx, REQ_SZ / 8
.copy_word:
    mov  rax, [rsi + rcx * 8 - 8]
    mov  [rdi + rcx * 8 - 8], rax
    loop .copy_word
    ret

; RDI is a producer-owned REQ_SZ snapshot. Serialized request custody only;
; native dispatch remains the authority. Clobbers caller-saved registers.
command_hook_request_matches:
    lea  rsi, [rel hook_req]
    mov  ecx, REQ_SZ / 8
.next:
    mov  rax, [rdi + rcx * 8 - 8]
    cmp  rax, [rsi + rcx * 8 - 8]
    jne  .no
    loop .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; A singleton/page planner may supply its static canonical default instance for
; discovery of the observed identity. Explicit caller instances are untouched.
; RDI is a kernel-owned NUL string, valid for this serialized request lifetime.
command_hook_default_instance:
    mov  rax, [rel hook_p_inst]
    cmp  byte [rax], 0
    jne  .done
    mov  [rel hook_p_inst], rdi
.done:
    ret

; ---------------------------------------------------------------------------
str_verb_hook:          db "HOOK", 0
str_hook_ops:           db "LIST",0,"DESCRIBE",0,"GET",0,"SET",0,"INPUT",0,"OBSERVE",0,"CANCEL",0,"EVENTS",0,"CATALOG",0,0
str_hook_catalog:       db " hook v=1 edges=", 0
str_hook_catalog_end:
str_hook_cat_ops:       db " ops=LIST,DESCRIBE,GET,SET,INPUT,OBSERVE,CANCEL,EVENTS authority=native", 0
str_hook_cat_ops_end:
str_hook_page:          db " hook catalog v=1 edges=", 0
str_hook_from:          db " from=", 0
str_hook_next:          db " next=", 0
str_hook_more:          db " more=", 0
str_hook_page_ops:      db " ops=CATALOG,LIST,DESCRIBE,GET,SET,INPUT,OBSERVE,CANCEL,EVENTS authority=native", 0
str_hook_hint_catalog:  db "HOOK CATALOG [unsigned decimal cursor <= edge count]; entry must fit a page", 0
str_hook_describe:      db " hook describe edge=", 0
str_hook_kind:          db " kind=", 0
str_hook_observe:       db " hook observe", 0
str_hook_witness:       db " witness=", 0
str_hook_changed:       db " changed=", 0
str_hook_events:        db " hook events next=", 0
str_hook_dropped:       db " dropped=", 0
str_hook_refused:       db " refused=", 0
str_hook_ev:            db " ev=", 0
str_hook_edge:          db " edge=", 0
str_hook_op:            db " op=", 0
str_hook_sp:            db " ", 0
str_hook_colon:         db ":", 0
str_hook_qm:            db "?", 0
str_hook_na:            db " hook na", 0
str_hook_unregistered:  db " reason=unregistered verb=", 0
str_hook_bad_arg:       db " hook err=bad_arg", 0
str_hook_web_tainted:   db " hook err=refused:web_tainted", 0
str_hook_hint_tainted:  db "a reboot or a local owner AITAINT CLEAR ends the web taint", 0
str_hook_bad_op:        db " hook err=bad_op", 0
str_hook_no_edge:       db " hook err=unknown_edge", 0
str_hook_too_long:      db " hook err=too_long limit=191", 0   ; HOOK_LINE_MAX - 1 (pinned by test_rc_ai_hooks_host)
str_hook_nested:        db " hook err=nested", 0
str_hook_owner_only:    db " hook err=owner_only", 0
str_hook_hint_ops:      db "expected HOOK LIST|DESCRIBE|GET|SET|INPUT|OBSERVE|CANCEL|EVENTS", 0
str_hook_hint_list:     db "HOOK LIST names every edge", 0
str_hook_hint_long:     db "a hook request is at most 191 bytes", 0
str_hook_hint_describe: db "HOOK DESCRIBE <edge> lists its ops and argument types", 0
str_hook_hint_unregistered: db "the edge's native verb is not registered in this profile or boot phase", 0
str_hook_hint_owner:    db "hook events are owner-only: the console owner or an owner AUTH1 envelope", 0
str_hook_hint_events:   db "HOOK EVENTS [unsigned decimal since]", 0
hook_empty:             db 0

align 8
hook_edge_count:   dd 0
hook_p_op:         dd 0
hook_p_edge_idx:   dd -1
hook_p_plan_op:    dd 0
hook_plan_status:  dd 0
command_hook_refuse: dd 0                 ; edge-defined nonzero reason (see hook_plan_edge)
hook_p_edge:       dq 0
hook_p_inst:       dq 0
hook_p_rest:       dq 0
hook_p_since:      dq 0
hook_p_verb_name:  dq 0
hook_arg_cur:      dq 0
hook_out_cur:      dq 0
hook_ev_next:      dq 0                   ; the newest event's sequence (0 = none yet)
hook_ev_refused:   dq 0                   ; native-gate refusals (AUTHDENY/CAPDENY): counted, not ringed
hook_delegations:  dq 0
hook_edges:        times HOOK_EDGE_MAX dq 0
hook_req:          times 8 dq 0           ; REQ_SZ (56) rounded up
hook_ev_ring:      times (HOOK_EV_MAX * HOOK_EV_SZ) db 0
hook_num_buf:      times 24 db 0
hook_busy:         db 0
hook_p_has_since:  db 0
hook_arg_overflow: db 0
command_hook_out_ready: db 0
hook_line:         times HOOK_LINE_MAX db 0
command_hook_arg:  times HOOK_ARG_MAX db 0
command_hook_out_buf: times HOOK_OUT_CAP db 0
