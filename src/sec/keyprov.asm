;; MODULE sec/keyprov
;; LAYER 5
;; PURPOSE GA0-K keystroke provenance: a typed line carries where its keys came from, and an injected line runs as the injecting principal.
;; EXPORTS keyprov_inj_seq, keyprov_inject_scancode, keyprov_refuse_builtin, keyprov_line_note, keyprov_line_clear, keyprov_field_write, keyprov_field_take, keyprov_dispatch, keyprov_key_is_human, keyprov_line_owner_equivalent, keyprov_frame_bind, keyprov_refuse_ssh, keyprov_ctx, keyprov_field_ctx, keyprov_field_state, keyprov_active_taint, keyprov_lines_tainted, keyprov_lines_refused
;; IMPORTS svc/command, svc/command_auth, svc/command_audit, sec/principal, core/lib/fmt, core/lib/str
;; OWNER saga:sec
; ============================================================================
; Root ruling 2026-10-08 19:00 (ledger 6229): KBINJ / TERMFEED typing into an
; unlocked Console or Terminal ran the line as console OWNER. That let a SYSTEM
; ticket reach owner-only capabilities (HOTPATCH, PERSIST). Now:
;
;  * dev/input/ps2 stores an origin beside every scancode. The physical
;    producers are HUMAN; KBINJ and TERMFEED enqueue through
;    keyprov_inject_scancode, which binds the byte to a context slot holding
;    the injecting request's {principal, source, mask}.
;  * gui/input_route sets input_key_origin for the key it delivers. Each line
;    editor keeps a taint record and calls keyprov_line_note on every key the
;    line receives (the submitting Enter included). Console adoption of a
;    field another request wrote (WIDGETSET, CLIPGET) taints through
;    keyprov_field_write / keyprov_field_take.
;  * The editors dispatch through keyprov_dispatch. A clean line is unchanged.
;    A tethered line runs under a request-scoped AUTH_TS_INJECTED ticket as
;    the injecting principal, through the remote gate (principal caps & mask,
;    like an SSH-bound principal). An untethered line is refused on the
;    shipped floor. An owner-change verb is refused on any tainted line, on
;    every floor: injected input never completes an ownership change.
;  * One INJLINE row per tainted line goes to the command audit ring.
;
; Single writer: the BSP idle loop and the handlers it dispatches.
; ============================================================================

; taint record (one per line editor)
KT_STATE     equ 0                      ; KT_CLEAN / KT_TETHERED / KT_UNTETHERED
KT_PRINCIPAL equ 8
KT_SOURCE    equ 16
KT_MASK      equ 24
KT_SIZE      equ 32
KP_DISPATCH_TICKET_OFF equ KT_SIZE + 16
KP_DISPATCH_FRAME_SIZE equ KP_DISPATCH_TICKET_OFF + ((AUTH_T_SIZE + 15) & ~15)
KT_CLEAN      equ 0
KT_TETHERED   equ 1
KT_UNTETHERED equ 2

; injection context slot
KC_PRINCIPAL equ 0
KC_SOURCE    equ 8
KC_MASK      equ 16
KC_VALID     equ 24
KC_SIZE      equ 32
KP_SLOTS     equ 8                      ; = KO_SLOTS (dev/input/ps2); pinned by the host suite
KP_FIELD_MAX equ 128                    ; = WGT_MAX (gui/widget); pinned by the host suite
KP_FIELD_CTX equ 8                      ; writer contexts remembered at once
KP_FIELD_UNTETHERED equ 0xFF

; surfaces (the audit row names them)
KP_SURFACE_CONSOLE  equ 0
KP_SURFACE_TERMINAL equ 1
KP_SURFACE_CLI      equ 2
KP_SURFACE_SSH      equ 3                  ; a Terminal's live SSH session (SEC D1)

; keyprov_inject_scancode(RDI = the injecting request, AL = scancode)
;   -> EAX 1 queued / 0 dropped. The byte's context is the request's own
;   {REQ_PRINCIPAL, REQ_SOURCE} and the in-flight ticket's mask (an SSH key or
;   an injected line's, else -1). A request dispatched from a tainted line
;   already carries that line's principal and source, so injecting again
;   cannot launder a taint. With no request, or no free context slot, the
;   byte is dropped (EAX 0), never queued untethered; only a byte typed from a
;   lab untethered line is queued untethered. A slot is free when no queued
;   byte, no half-built key and no pending injected dead key (gui/input_route,
;   by address) refers to it. Preserves RBX, RSI, RDI and R8-R15.
keyprov_inject_scancode:
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    mov  r10b, al
    mov  rax, [rel keyprov_active_taint]
    test rax, rax
    jz   .context
    cmp  qword [rax + KT_STATE], KT_UNTETHERED
    jne  .context
    mov  dl, KO_UNTETHERED              ; typed from an untethered line (lab): stays untethered
    jmp  .enqueue
.context:
    test rdi, rdi
    jz   .drop                          ; no request: no principal to bind
.request:
    mov  r8, [rdi + REQ_PRINCIPAL]
    mov  r9, [rdi + REQ_SOURCE]
    mov  rsi, -1
    cmp  byte [rel command_auth_remote_active], 1
    jne  .mask_ready
    mov  rdx, [rel command_auth_remote_ticket]
    test rdx, rdx
    jz   .mask_ready
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_SSH
    je   .ticket_mask
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_INJECTED
    jne  .mask_ready
.ticket_mask:
    mov  rsi, [rdx + AUTH_T_CAP]
.mask_ready:
    ; (1) a slot already bound to this exact context
    lea  rdi, [rel keyprov_ctx]
    xor  ecx, ecx
.find:
    cmp  qword [rdi + KC_VALID], 1
    jne  .find_next
    cmp  [rdi + KC_PRINCIPAL], r8
    jne  .find_next
    cmp  [rdi + KC_SOURCE], r9
    jne  .find_next
    cmp  [rdi + KC_MASK], rsi
    je   .slot
.find_next:
    add  rdi, KC_SIZE
    inc  ecx
    cmp  ecx, KP_SLOTS
    jb   .find
    ; (2) a slot no queued byte and no half-built key holds
    lea  rdi, [rel keyprov_ctx]
    xor  ecx, ecx
.free:
    lea  rax, [rel kbd_slot_pending]
    cmp  byte [rax + rcx], 0
    jne  .free_next
    ; RCQ-38 L1 C1 (option A, rc-sec 12:57:55): the router's ONE other-class
    ; dead key holds the slot it came from while it is pending, so its mark can
    ; never be delivered under a rebound principal. Keyed on PENDING: the origin
    ; byte is not cleared on cancel. An untethered dead key pins nothing.
    cmp  dword [rel input_kbd_ctx_other + INPUT_KBD_PENDING], 0
    je   .last_origin
    movzx eax, byte [rel input_dead_origin_other]
    cmp  al, KO_UNTETHERED
    je   .last_origin
    test al, KO_INJECTED
    jz   .last_origin
    and  eax, KO_SLOTS - 1
    cmp  eax, ecx
    je   .free_next
.last_origin:
    movzx eax, byte [rel input_key_origin]
    cmp  al, KO_UNTETHERED
    je   .bind
    test al, KO_INJECTED
    jz   .bind
    and  eax, KO_SLOTS - 1
    cmp  eax, ecx
    je   .free_next
.bind:
    mov  [rdi + KC_PRINCIPAL], r8
    mov  [rdi + KC_SOURCE], r9
    mov  [rdi + KC_MASK], rsi
    mov  qword [rdi + KC_VALID], 1
    jmp  .slot
.free_next:
    add  rdi, KC_SIZE
    inc  ecx
    cmp  ecx, KP_SLOTS
    jb   .free
.drop:
    xor  eax, eax                       ; no slot: dropped, never queued untethered (root 19:34:46 R2)
    jmp  .out
.slot:
    inc  dword [rel keyprov_inj_seq]    ; decision windows close on it (SEC R2-3)
    mov  dl, cl
    or   dl, KO_INJECTED
.enqueue:
    mov  al, r10b
    call ps2_kbd_enqueue_origin
.out:
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; keyprov_line_note(RDI = taint record): fold the origin of the key being
; delivered (input_key_origin) into the line. HUMAN and INTERNAL keys leave it
; as it is; nothing but keyprov_line_clear cleans a line. Preserves all
; registers and flags' users (callers sit in key paths).
keyprov_line_note:
    push rax
    push rcx
    push rdx
    push rsi
    movzx eax, byte [rel input_key_origin]
    test al, KO_INJECTED
    jz   .out
    cmp  al, KO_UNTETHERED
    je   .untethered
    and  eax, KO_SLOTS - 1
    imul eax, eax, KC_SIZE
    lea  rsi, [rel keyprov_ctx]
    add  rsi, rax
    cmp  qword [rsi + KC_VALID], 1
    jne  .untethered
    call keyprov_merge_ctx
.out:
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret
.untethered:
    mov  qword [rdi + KT_STATE], KT_UNTETHERED
    jmp  .out

; keyprov_merge_ctx(RDI = taint, RSI = {principal, source, mask} at KC_*
; offsets): a clean line takes the context; the same context keeps it; any
; other context makes the line untethered. Clobbers RAX.
keyprov_merge_ctx:
    mov  rax, [rdi + KT_STATE]
    cmp  rax, KT_UNTETHERED
    je   .done
    cmp  rax, KT_TETHERED
    je   .compare
    mov  rax, [rsi + KC_PRINCIPAL]
    mov  [rdi + KT_PRINCIPAL], rax
    mov  rax, [rsi + KC_SOURCE]
    mov  [rdi + KT_SOURCE], rax
    mov  rax, [rsi + KC_MASK]
    mov  [rdi + KT_MASK], rax
    mov  qword [rdi + KT_STATE], KT_TETHERED
.done:
    ret
.compare:
    mov  rax, [rsi + KC_PRINCIPAL]
    cmp  [rdi + KT_PRINCIPAL], rax
    jne  .conflict
    mov  rax, [rsi + KC_SOURCE]
    cmp  [rdi + KT_SOURCE], rax
    jne  .conflict
    mov  rax, [rsi + KC_MASK]
    cmp  [rdi + KT_MASK], rax
    je   .done
.conflict:
    mov  qword [rdi + KT_STATE], KT_UNTETHERED
    ret

; keyprov_line_clear(RDI = taint record): the line was consumed or abandoned.
; Preserves all registers.
keyprov_line_clear:
    mov  qword [rdi + KT_STATE], KT_CLEAN
    mov  qword [rdi + KT_PRINCIPAL], 0
    mov  qword [rdi + KT_SOURCE], 0
    mov  qword [rdi + KT_MASK], 0
    ret

; keyprov_field_write(EDI = widget id): a request is writing this textfield's
; value outside its line editor (WIDGETSET, CLIPGET). Inside a remote request
; or a tainted line's dispatch the widget remembers that context (an index into
; keyprov_field_ctx, or KP_FIELD_UNTETHERED when the line was untethered or no
; context entry is free), for a line editor that later adopts the field
; (keyprov_field_take). Any other write (the local owner, an in-image caller)
; replaces the text and forgets it. Preserves all registers.
keyprov_field_write:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  edi, edi
    cmp  edi, KP_FIELD_MAX
    jae  .out                           ; not a widget slot: nothing can adopt it
    lea  r10, [rel keyprov_field_state]
    mov  rax, [rel keyprov_active_taint]
    test rax, rax
    jz   .remote
    cmp  qword [rax + KT_STATE], KT_CLEAN
    je   .remote
    cmp  qword [rax + KT_STATE], KT_TETHERED
    jne  .untethered
    mov  r8, [rax + KT_PRINCIPAL]
    mov  r9, [rax + KT_SOURCE]
    mov  rsi, [rax + KT_MASK]
    jmp  .context
.remote:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .forget
    mov  r8, [rel cmd_dispatch_last_principal]
    mov  r9, [rel cmd_dispatch_last_source]
    mov  rsi, -1
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .context
    cmp  qword [rax + AUTH_T_STATE], AUTH_TS_SSH
    jne  .context
    mov  rsi, [rax + AUTH_T_CAP]
.context:
    mov  byte [r10 + rdi], 0            ; this widget's old entry may be reused
    ; an entry holding this exact context, else one no widget refers to
    lea  rax, [rel keyprov_field_ctx]
    xor  ecx, ecx
.find:
    cmp  qword [rax + KC_VALID], 1
    jne  .find_next
    cmp  [rax + KC_PRINCIPAL], r8
    jne  .find_next
    cmp  [rax + KC_SOURCE], r9
    jne  .find_next
    cmp  [rax + KC_MASK], rsi
    je   .bound
.find_next:
    add  rax, KC_SIZE
    inc  ecx
    cmp  ecx, KP_FIELD_CTX
    jb   .find
    lea  rax, [rel keyprov_field_ctx]
    xor  ecx, ecx
.free:
    lea  edx, [ecx + 1]
    xor  r11d, r11d
.scan:
    cmp  [r10 + r11], dl
    je   .in_use
    inc  r11d
    cmp  r11d, KP_FIELD_MAX
    jb   .scan
    mov  [rax + KC_PRINCIPAL], r8
    mov  [rax + KC_SOURCE], r9
    mov  [rax + KC_MASK], rsi
    mov  qword [rax + KC_VALID], 1
    jmp  .bound
.in_use:
    add  rax, KC_SIZE
    inc  ecx
    cmp  ecx, KP_FIELD_CTX
    jb   .free
.untethered:                            ; no free entry, or an untethered writer: fails closed
    mov  byte [r10 + rdi], KP_FIELD_UNTETHERED
    jmp  .out
.bound:
    inc  ecx
    mov  [r10 + rdi], cl
    jmp  .out
.forget:
    mov  byte [r10 + rdi], 0
.out:
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

; keyprov_field_take(EDI = widget id, RSI = taint record): the line editor
; adopted this field's text. A remembered writer taints the line (consumed
; once). Preserves all registers.
keyprov_field_take:
    push rax
    push rcx
    push rdi
    push rsi
    mov  edi, edi
    cmp  edi, KP_FIELD_MAX
    jae  .out
    lea  rax, [rel keyprov_field_state]
    movzx ecx, byte [rax + rdi]
    mov  byte [rax + rdi], 0
    mov  rdi, rsi
    test ecx, ecx
    jz   .out
    cmp  ecx, KP_FIELD_CTX
    ja   .untethered
    dec  ecx
    imul ecx, ecx, KC_SIZE
    lea  rsi, [rel keyprov_field_ctx]
    add  rsi, rcx
    call keyprov_merge_ctx
    jmp  .out
.untethered:
    mov  qword [rdi + KT_STATE], KT_UNTETHERED
.out:
    pop  rsi
    pop  rdi
    pop  rcx
    pop  rax
    ret

; keyprov_key_is_human -> EAX 1 when the key being delivered came from a
; physical keyboard (IRQ1 / USB HID). Owner-change confirms require it, with
; wm_pointer_origin == WM_PTR_ORIGIN_HUMAN for a click (root 19:00 GA0-P
; condition). INTERNAL and injected keys are never human.
keyprov_key_is_human:
    xor  eax, eax
    cmp  byte [rel input_key_origin], KO_HUMAN
    sete al
    ret

; keyprov_line_owner_equivalent(RDI = taint record) -> EAX 1 when the line may
; act with the owner's authority outside the registry (Terminal power words,
; the ssh client): clean, or tethered to the OWNER principal with an
; unrestricted mask (the local owner's own KBINJ, a remote owner ticket).
keyprov_line_owner_equivalent:
    xor  eax, eax
    cmp  qword [rdi + KT_STATE], KT_CLEAN
    je   .yes
    cmp  qword [rdi + KT_STATE], KT_TETHERED
    jne  .out
    cmp  qword [rdi + KT_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .out
    cmp  qword [rdi + KT_MASK], -1
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; keyprov_frame_bind(RDI = a cleared taint record): SEC D1 (root 17:02:37). An
; injected POINTER event has no slot, so it is judged by the request in flight,
; bound exactly as keyprov_inject_scancode binds an injected byte: TETHERED to
; {principal, source} and the SSH or injected ticket's mask, else -1. Outside
; a dispatch there is no injector to bind (an injected gesture finished by a
; HUMAN event): UNTETHERED, which keyprov_line_owner_equivalent refuses.
; Inside an untethered line (lab floor) it stays UNTETHERED, as a key typed
; from that line does (keyprov_inject_scancode; srcreview F2 18:57:18).
; Preserves every register.
keyprov_frame_bind:
    push rax
    push rdx
    mov  qword [rdi + KT_STATE], KT_UNTETHERED
    mov  rax, [rel keyprov_active_taint]
    test rax, rax
    jz   .frame
    cmp  qword [rax + KT_STATE], KT_UNTETHERED
    je   .out
.frame:
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .out
    mov  qword [rdi + KT_STATE], KT_TETHERED
    mov  rax, [rel cmd_dispatch_last_principal]
    mov  [rdi + KT_PRINCIPAL], rax
    mov  rax, [rel cmd_dispatch_last_source]
    mov  [rdi + KT_SOURCE], rax
    mov  qword [rdi + KT_MASK], -1
    cmp  byte [rel command_auth_remote_active], 1
    jne  .out
    mov  rdx, [rel command_auth_remote_ticket]
    test rdx, rdx
    jz   .out
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_SSH
    je   .ticket_mask
    cmp  qword [rdx + AUTH_T_STATE], AUTH_TS_INJECTED
    jne  .out
.ticket_mask:
    mov  rax, [rdx + AUTH_T_CAP]
    mov  [rdi + KT_MASK], rax
.out:
    pop  rdx
    pop  rax
    ret

; keyprov_dispatch(RDI = req, RSI = resp, RDX = taint record, ECX = surface)
;   -> RAX as command_dispatch. The caller built req as a console-local OWNER
;   request. Clears the taint record (the line is consumed).
;   clean           -> command_dispatch, unchanged.
;   any taint       -> an owner-change verb is refused (every floor).
;   untethered      -> shipped: refused, nothing dispatched; lab: dispatched as
;                      built, the row says untethered.
;   tethered local  -> source CONSOLE: dispatched with the line's principal
;                      (an OWNER is the local owner's own injection).
;   tethered remote -> REQ_SOURCE/REQ_PRINCIPAL become the line's; the
;                      dispatch runs under a private stack ticket (AUTH_TS_INJECTED,
;                      CAP = mask) inside command_auth_remote_begin, and the
;                      surrounding remote context (a TERMFEED line runs nested
;                      in the TERMFEED request) is restored after.
keyprov_dispatch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, KP_DISPATCH_FRAME_SIZE     ; taint, outer context, PRIVATE aligned ticket
    mov  r12, rdi
    mov  r13, rsi
    mov  r15d, ecx
    ; copy the taint: a nested dispatch may reuse the caller's record
    mov  rax, [rdx + KT_STATE]
    mov  [rsp + KT_STATE], rax
    mov  rax, [rdx + KT_PRINCIPAL]
    mov  [rsp + KT_PRINCIPAL], rax
    mov  rax, [rdx + KT_SOURCE]
    mov  [rsp + KT_SOURCE], rax
    mov  rax, [rdx + KT_MASK]
    mov  [rsp + KT_MASK], rax
    mov  rdi, rdx
    call keyprov_line_clear
    cmp  qword [rsp + KT_STATE], KT_CLEAN
    jne  .tainted
    mov  rdi, r12
    mov  rsi, r13
    call command_dispatch
    jmp  .out
.tainted:
    inc  qword [rel keyprov_lines_tainted]
    ; injected input never completes an ownership change (root 19:00)
    mov  rdi, [r12 + REQ_VERB]
    call command_verb_name
    mov  rdi, rax
    call keyprov_owner_change_name
    test eax, eax
    jz   .not_owner_change
    lea  rbx, [rel str_kp_r_owner_change]
    mov  edx, 1                         ; native owner-change refusal
    jmp  .refuse
.not_owner_change:
    cmp  qword [rsp + KT_STATE], KT_TETHERED
    je   .tethered
%if PAOS_PUBLICITY_LAB_PROFILE
    lea  rbx, [rel str_kp_r_untethered]
    call keyprov_dispatch_tainted_local
    jmp  .audit
%else
    lea  rbx, [rel str_kp_r_untethered]
    mov  edx, 2                         ; native shipped-floor refusal
    jmp  .refuse
%endif
.tethered:
    lea  rbx, [rel str_kp_r_none]
    mov  rax, [rsp + KT_PRINCIPAL]
    mov  [r12 + REQ_PRINCIPAL], rax
    cmp  qword [rsp + KT_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote
    call keyprov_dispatch_tainted_local
    jmp  .audit
.remote:
    mov  rax, [rsp + KT_SOURCE]
    mov  [r12 + REQ_SOURCE], rax
    ; A nested injected dispatch must not overwrite the outer ticket. Each
    ; invocation owns these bytes until its saved context has been restored.
    lea  rdi, [rsp + KP_DISPATCH_TICKET_OFF]
    xor  eax, eax
    mov  ecx, AUTH_T_SIZE / 8
    cld
    rep  stosq
    mov  rax, [rsp + KT_MASK]
    mov  [rsp + KP_DISPATCH_TICKET_OFF + AUTH_T_CAP], rax
    mov  rax, [rsp + KT_SOURCE]
    mov  [rsp + KP_DISPATCH_TICKET_OFF + AUTH_T_SEQ], rax ; the original source (net_access_gate's service)
    mov  rax, [rsp + KT_PRINCIPAL]
    mov  [rsp + KP_DISPATCH_TICKET_OFF + AUTH_T_PRINCIPAL], rax
    mov  qword [rsp + KP_DISPATCH_TICKET_OFF + AUTH_T_STATE], AUTH_TS_INJECTED
    mov  rax, [rel command_auth_remote_ticket]
    mov  [rsp + KT_SIZE], rax
    movzx eax, byte [rel command_auth_remote_active]
    mov  [rsp + KT_SIZE + 8], rax
    lea  rdi, [rsp + KP_DISPATCH_TICKET_OFF]
    call command_auth_remote_begin
    call keyprov_dispatch_tainted_local
    mov  r14, rax
    cmp  qword [rsp + KT_SIZE + 8], 1
    jne  .remote_end
    mov  rdi, [rsp + KT_SIZE]
    call command_auth_remote_begin      ; the outer request's own context again
    jmp  .remote_done
.remote_end:
    call command_auth_remote_end
.remote_done:
    mov  rax, r14
    jmp  .audit
.refuse:
    mov  rdi, rsp                       ; copied, owned taint; caller was cleared
    mov  esi, r15d
    call keyprov_observe_refusal
    inc  qword [rel keyprov_lines_refused]
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    mov  qword [r13 + RSP_ACCEPTED], 0
    mov  qword [r13 + RSP_JOBID], 0
    mov  qword [r13 + RSP_VAL], 0
    mov  qword [r13 + RSP_EXPECTED], 0
    lea  rax, [rel str_kp_refused_hint]
    mov  [r13 + RSP_HINT], rax
    mov  eax, CMDE_AUTHDENY
.audit:
    mov  r14, rax
    mov  rdi, [r12 + REQ_VERB]
    call command_verb_name
    mov  rcx, rax
    lea  r8, [rel str_kp_res_dispatched]
    cmp  qword [r13 + RSP_CODE], CMDE_OK
    je   .res
    lea  r8, [rel str_kp_res_refused]
    cmp  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    je   .res
    lea  r8, [rel str_kp_res_error]
.res:
    mov  rdi, rsp
    mov  esi, r15d
    mov  rdx, rbx
    call keyprov_audit_line
    mov  rax, r14
.out:
    add  rsp, KP_DISPATCH_FRAME_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; keyprov_dispatch_tainted_local: command_dispatch(R12, R13) with
; keyprov_active_taint = the caller's local taint copy (at the caller's RSP), so
; a field written or a key injected by the dispatched verb keeps the line's
; context. The previous value is restored (nested lines). -> RAX.
keyprov_dispatch_tainted_local:
    mov  rax, [rel keyprov_active_taint]
    push rax
    lea  rax, [rsp + 16]
    mov  [rel keyprov_active_taint], rax
    mov  rdi, r12
    mov  rsi, r13
    call command_dispatch
    pop  rdx
    mov  [rel keyprov_active_taint], rdx
    ret

; keyprov_owner_change_name(RDI = verb name) -> EAX 1 when the verb changes
; who owns the box or how the owner authenticates. S1-S6 add their verbs.
keyprov_owner_change_name:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rel keyprov_owner_change_names]
.scan:
    cmp  byte [rsi], 0
    je   .no
    push rsi
    mov  rdi, rbx
    call strcmp
    pop  rsi
    test eax, eax
    jz   .yes
.skip:
    inc  rsi
    cmp  byte [rsi - 1], 0
    jne  .skip
    jmp  .scan
.yes:
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; keyprov_observe_refusal(RDI owned taint, ESI canonical surface, EDX reason).
; Trusted native choke points only; no parsing of text, reply or registry errors.
; Preserve every general caller register so INJLINE and editor state are unchanged.
; Numeric reason: 0x1000 | source<<8 | taint<<6 | surface<<3 | refusal.
; refusal: 1 owner-change,2 shipped untethered,3 builtin,4 live SSH,0 unknown.
; surface: 0 console,1 terminal,2 CLI,3 SSH,4 unknown. Taint: 0 clean,
; 1 tethered,2 untethered,3 unknown. Source ONLY for tethered: 1 console,
; 2 UDP,3 SSH,4 serial,5 other;0 no tether. Never copy principal/mask/input.
; SYSTEM in the typed spine identifies the observer, never the input's identity
; or proof of a physical human, attack, hardware isolation or SSH credentials.
keyprov_observe_refusal:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    cmp  edx, 4
    jbe  .reason
    xor  edx, edx
.reason:
    cmp  esi, KP_SURFACE_SSH
    jbe  .surface
    mov  esi, 4
.surface:
    shl  esi, 3
    or   edx, esi
    mov  rax, [rdi + KT_STATE]
    cmp  rax, KT_UNTETHERED
    jbe  .taint
    mov  eax, 3
.taint:
    mov  ecx, eax
    shl  ecx, 6
    or   edx, ecx
    cmp  eax, KT_TETHERED
    jne  .emit
    mov  rax, [rdi + KT_SOURCE]
    mov  ecx, 1
    cmp  rax, CMD_SOURCE_CONSOLE
    je   .source
    inc  ecx
    cmp  rax, CMD_SOURCE_UDP
    je   .source
    inc  ecx
    cmp  rax, CMD_SOURCE_SSH
    je   .source
    inc  ecx
    cmp  rax, CMD_SOURCE_SERIAL
    je   .source
    inc  ecx
.source:
    shl  ecx, 8
    or   edx, ecx
.emit:
    or   edx, 0x1000
    mov  edi, edx
    call audit_sec_keyprov_refusal
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

; keyprov_refuse_builtin(RDI = taint record, ESI = surface, RDX = the
; built-in's fixed name): a line editor refused a built-in that acts with the
; owner's authority outside the registry (keyprov_line_owner_equivalent was
; 0). Counts it and writes the INJLINE row. Clobbers caller-saved.
keyprov_refuse_builtin:
    push rdx
    mov  edx, 3
    call keyprov_observe_refusal
    pop  rdx
    inc  qword [rel keyprov_lines_tainted]
    inc  qword [rel keyprov_lines_refused]
    mov  rcx, rdx
    lea  rdx, [rel str_kp_r_builtin]
    lea  r8, [rel str_kp_res_refused]
    jmp  keyprov_audit_line

; keyprov_refuse_ssh(RDI = taint record, RCX = the input's fixed kind name):
; SEC D1. An input-driven send into a live SSH session was not owner-equivalent
; and was dropped: "INJLINE surface=ssh ... res=refused
; reason=not_owner_equivalent". No input bytes. Clobbers caller-saved.
keyprov_refuse_ssh:
    mov  esi, KP_SURFACE_SSH
    push rdx
    mov  edx, 4
    call keyprov_observe_refusal
    pop  rdx
    lea  rdx, [rel str_kp_r_not_owner_eq]
    lea  r8, [rel str_kp_res_refused]
    ; fall through

; keyprov_audit_line(RDI = taint copy, ESI = surface, RDX = reason cstr,
; RCX = verb name, R8 = " res=..." cstr):
; "INJLINE surface=S src=X principal=N verb=V res=R reason=Y". The verb is the
; registry's canonical name or a built-in's fixed name, never line bytes.
; Clobbers caller-saved.
keyprov_audit_line:
    push rbx
    push r14
    push r15
    sub  rsp, 32
    mov  rbx, rdi
    mov  r15d, esi
    mov  [rsp], rdx
    mov  [rsp + 8], rcx
    mov  [rsp + 16], r8
    lea  r14, [rel keyprov_audit_buf]
    lea  rdi, [rel str_kp_injline]
    call keyprov_audit_put
    lea  rdi, [rel str_kp_s_console]
    cmp  r15d, KP_SURFACE_CONSOLE
    je   .surface
    lea  rdi, [rel str_kp_s_terminal]
    cmp  r15d, KP_SURFACE_TERMINAL
    je   .surface
    lea  rdi, [rel str_kp_src_ssh]      ; "ssh"
    cmp  r15d, KP_SURFACE_SSH
    je   .surface
    lea  rdi, [rel str_kp_s_cli]
.surface:
    call keyprov_audit_put
    lea  rdi, [rel str_kp_src]
    call keyprov_audit_put
    lea  rdi, [rel str_kp_src_none]
    cmp  qword [rbx + KT_STATE], KT_TETHERED
    jne  .src
    mov  rax, [rbx + KT_SOURCE]
    lea  rdi, [rel str_kp_src_udp]
    cmp  rax, CMD_SOURCE_UDP
    je   .src
    lea  rdi, [rel str_kp_src_ssh]
    cmp  rax, CMD_SOURCE_SSH
    je   .src
    lea  rdi, [rel str_kp_src_serial]
    cmp  rax, CMD_SOURCE_SERIAL
    je   .src
    lea  rdi, [rel str_kp_src_console]
    cmp  rax, CMD_SOURCE_CONSOLE
    je   .src
    lea  rdi, [rel str_kp_src_other]
.src:
    call keyprov_audit_put
    lea  rdi, [rel str_kp_principal]
    call keyprov_audit_put
    xor  edi, edi
    cmp  qword [rbx + KT_STATE], KT_TETHERED
    jne  .principal
    mov  rdi, [rbx + KT_PRINCIPAL]
.principal:
    mov  rsi, r14
    call fmt_dec
    add  r14, rax
    lea  rdi, [rel str_kp_verb]
    call keyprov_audit_put
    mov  rdi, [rsp + 8]
    test rdi, rdi
    jz   .unknown
    cmp  byte [rdi], 0
    jne  .verb
.unknown:
    lea  rdi, [rel str_kp_unknown]
.verb:
    call keyprov_audit_put
    mov  rdi, [rsp + 16]
    call keyprov_audit_put
    lea  rdi, [rel str_kp_reason]
    call keyprov_audit_put
    mov  rdi, [rsp]
    call keyprov_audit_put
    mov  byte [r14], 0
    lea  rdi, [rel keyprov_audit_buf]
    call audit_log_line
    add  rsp, 32
    pop  r15
    pop  r14
    pop  rbx
    ret

; RDI = cstr appended at R14, bounded by keyprov_audit_buf. Clobbers RAX, RDX, RDI.
keyprov_audit_put:
    lea  rax, [rel keyprov_audit_buf + KP_AUDIT_MAX - 1]
.copy:
    cmp  r14, rax
    jae  .out
    mov  dl, [rdi]
    test dl, dl
    jz   .out
    mov  [r14], dl
    inc  r14
    inc  rdi
    jmp  .copy
.out:
    mov  byte [r14], 0
    ret

KP_AUDIT_MAX equ 160

keyprov_owner_change_names:
    db "AUTHENROLL",0,"SSHKEYADD",0,"SSHKEYDEL",0,"AUTHFLOOR",0,0

str_kp_injline:         db "INJLINE surface=",0
str_kp_s_console:       db "console",0
str_kp_s_terminal:      db "terminal",0
str_kp_s_cli:           db "cli",0
str_kp_src:             db " src=",0
str_kp_src_none:        db "none",0
str_kp_src_udp:         db "udp",0
str_kp_src_ssh:         db "ssh",0
str_kp_src_serial:      db "serial",0
str_kp_src_console:     db "console",0
str_kp_src_other:       db "other",0
str_kp_principal:       db " principal=",0
str_kp_verb:            db " verb=",0
str_kp_unknown:         db "?",0
str_kp_res_dispatched:  db " res=dispatched",0
str_kp_res_refused:     db " res=refused",0
str_kp_res_error:       db " res=error",0
str_kp_reason:          db " reason=",0
str_kp_r_none:          db "-",0
str_kp_r_untethered:    db "untethered",0
str_kp_r_owner_change:  db "owner_change",0
str_kp_r_builtin:       db "builtin",0
str_kp_r_not_owner_eq:  db "not_owner_equivalent",0
str_kp_refused_hint:    db "refused: an injected line runs only as its injecting principal (keyprov)",0

; ---- data ------------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_sec_keyprov_seq 0
keyprov_inj_seq:       dd 0            ; every injected scancode queued
%endmacro
WDATA_DEFER WDATA_sec_keyprov_seq
%macro WDATA_sec_keyprov 0
alignb 8
keyprov_ctx:           resb KP_SLOTS * KC_SIZE
keyprov_field_ctx:     resb KP_FIELD_CTX * KC_SIZE
keyprov_field_state:   resb KP_FIELD_MAX            ; per widget: 0, 1 + a keyprov_field_ctx index, or UNTETHERED
keyprov_active_taint:  resq 1                   ; the tainted line being dispatched, 0 none
keyprov_lines_tainted: resq 1
keyprov_lines_refused: resq 1
keyprov_audit_buf:     resb KP_AUDIT_MAX
%endmacro
WDATA_BSS_DEFER WDATA_sec_keyprov
