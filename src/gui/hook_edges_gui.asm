;; MODULE gui/hook_edges_gui
;; LAYER 6
;; EXPORTS hook_gui_edges_declare, hook_term_plan, hook_term_post, hook_wgt_plan, hook_wgt_post, hook_dpms_plan, hook_input_plan, hook_pointer_plan, hook_input_post, hook_pointer_post
;; IMPORTS svc/command, svc/command_hook, svc/command_cons, gui/terminal_app, gui/widget, gui/chat_app, gui/command_gui, sec/session
;; CAPS
;; OWNER saga:command
; ============================================================================
; gui/hook_edges_gui.asm -- RCQ-15 slice 1: the first three HOOK edges.
;
;   term     (app)      the Terminal window       native TERMFEED (destructive: owner)
;   widget   (widget)   any kit widget            native WIDGETLIST/GET/SET
;   dpms     (service)  the scanout power state   native DPMS (BLANK owner-only)
;   input    (service)  input counter snapshot   native INPUTSTAT (read-only)
;   pointer  (service)  cursor/button snapshot   native MOUSESTAT (read-only)
;
; Each edge only PLANS a native verb and argument; svc/command_hook dispatches
; it with the caller's own source, principal, capability and idempotency key,
; so the native gate decides. The post filters below run only after that gate
; returned CMDE_OK, and they only narrow the reply:
;   * term INPUT sends keys through the shared keyboard ring, which delivers to
;     the FOCUSED window. A key for an unfocused or locked desktop would reach
;     another window or the sign-in field, so the edge plans the same verb's
;     read (@VTSTAT) and answers not_focused / desktop_locked instead.
;   * widget GET of the secret (password) type answers redacted=1: the native
;     reply would carry its '*' mask, whose length is the password's length.
;   * widget LIST names instances only (no values) and pages at HGE_WGT_PAGE.
;   * widget SET refuses the action fields (open, action, input, spawn, close,
;     feed, minimize, restore) as not applicable: SET changes typed state, and
;     those fields run actions that slice 1 does not type.
; Identities: term:<WM slot> (live while the slot holds that Terminal),
; widget:<widget id>, dpms (one instance).
; ============================================================================

HGE_WGT_PAGE        equ 24          ; widget instances per HOOK LIST widget reply
HGE_REFUSE_UNFOCUSED equ 1          ; command_hook_refuse reasons (term INPUT)
HGE_REFUSE_LOCKED   equ 2
HGE_FIELD_MAX       equ 24          ; a redacted SET names at most this field token (with NUL)

; hook_gui_edges_declare -- bind the GUI descriptors (lea at init, ESSENCE S10)
;   and register them. clobbers: caller-saved.
hook_gui_edges_declare:
    push rbx
    lea  rbx, [rel hook_edge_term]
    lea  rax, [rel str_hge_term]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hge_kind_app]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hge_term_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_term_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_term_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel grid_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel grid_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hge_term_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_wgt]
    lea  rax, [rel str_hge_wgt]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hge_kind_widget]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hge_wgt_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_wgt_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_wgt_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel wgt_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel wgt_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; the whole reply
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_dpms]
    lea  rax, [rel str_hge_dpms]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hge_kind_service]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hge_dpms_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_dpms_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel gui_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel gui_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hge_dpms_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_input]
    lea  rax, [rel str_hio_input]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hge_kind_service]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hio_input_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_input_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_input_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel gui_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel gui_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; whole validated native snapshot
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_pointer]
    lea  rax, [rel str_hio_pointer]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hge_kind_service]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hio_pointer_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_pointer_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_pointer_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel gui_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel gui_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; whole validated native snapshot
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; shared planner helpers
; ---------------------------------------------------------------------------

; hge_dec_full(RDI = cstr) -> RAX = value, EDX = 1 when the WHOLE string is a
;   decimal number (1..19 digits), else 0. clobbers: RAX, RCX, RDX
hge_dec_full:
    call command_hook_parse_dec
    test edx, edx
    jz   .bad
    cmp  byte [rdi + rdx], 0
    jne  .bad
    mov  edx, 1
    ret
.bad:
    xor  edx, edx
    ret

; hge_has_space(RDI = cstr) -> EAX 1 when it holds a space (more than one token)
hge_has_space:
    xor  eax, eax
.l:
    mov  cl, [rdi]
    test cl, cl
    jz   .out
    cmp  cl, ' '
    je   .yes
    inc  rdi
    jmp  .l
.yes:
    mov  eax, 1
.out:
    ret

; hge_tok_is(RDI = token start, ending at ' ' or NUL; RSI = lower-case word)
;   -> EAX 1 iff the token is exactly the word. clobbers: RAX, RCX, RDX
hge_tok_is:
    xor  ecx, ecx
.l:
    mov  al, [rdi + rcx]
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .end
    cmp  al, dl
    jne  .no
    inc  ecx
    jmp  .l
.end:
    test al, al
    jz   .yes
    cmp  al, ' '
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; hge_tok_in(RDI = token, RSI = NUL-separated word list, "" ends) -> EAX 1 iff listed
hge_tok_in:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
.w:
    cmp  byte [r12], 0
    je   .no
    mov  rdi, rbx
    mov  rsi, r12
    call hge_tok_is
    test eax, eax
    jnz  .out
.skip:
    inc  r12
    cmp  byte [r12 - 1], 0
    jne  .skip
    jmp  .w
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; EDGE term -- plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
; ---------------------------------------------------------------------------
hook_term_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    cmp  ebx, HOP_LIST
    je   .list
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_INPUT
    je   .input
    mov  edx, HOOK_PLAN_NA
    jmp  .none
.list:
    cmp  byte [r12], 0
    jne  .bad
    cmp  byte [r13], 0
    jne  .bad
    lea  rax, [rel str_hge_verb_windows]
    jmp  .out
.get:
    cmp  byte [r13], 0
    jne  .bad
    mov  rdi, r12
    call hge_dec_full
    test edx, edx
    jz   .bad
    jmp  .stat
.input:
    mov  rdi, r12
    call hge_dec_full
    test edx, edx
    jz   .bad
    mov  rbx, rax                         ; the WM slot
    ; keys: one token of hex digits (never another TERMFEED sub-command)
    mov  rdi, r13
    cmp  byte [rdi], 0
    je   .bad
.hex:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .hex_ok
    cmp  eax, '0'
    jb   .bad
    cmp  eax, '9'
    jbe  .hex_next
    or   eax, 0x20
    cmp  eax, 'a'
    jb   .bad
    cmp  eax, 'f'
    ja   .bad
.hex_next:
    inc  rdi
    jmp  .hex
.hex_ok:
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .locked
    cmp  ebx, [rel wm_focus]
    jne  .unfocused
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hge_sub_key]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    lea  rax, [rel str_hge_verb_termfeed]
    jmp  .out
.locked:
    mov  dword [rel command_hook_refuse], HGE_REFUSE_LOCKED
    jmp  .stat
.unfocused:
    mov  dword [rel command_hook_refuse], HGE_REFUSE_UNFOCUSED
.stat:
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hge_sub_stat]
    call command_hook_arg_str
    lea  rax, [rel str_hge_verb_termfeed]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; term post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = hook reply staged
hook_term_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; a native refusal passes through untouched
    cmp  edi, HOP_LIST
    je   .list
    cmp  edi, HOP_INPUT
    jne  .none
    cmp  dword [rel command_hook_refuse], 0
    jne  .refuse
.none:
    xor  eax, eax
    ret
.refuse:
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    mov  r12, rsi
    mov  r13d, [rel command_hook_refuse]
    mov  byte [rel grid_out_ready], 0     ; the surrogate @VTSTAT is never the answer
    call command_hook_out_reset
    lea  rdi, [rel str_hge_err_unfocused]
    cmp  r13d, HGE_REFUSE_LOCKED
    jne  .reason
    lea  rdi, [rel str_hge_err_locked]
.reason:
    call command_hook_out_str
    mov  rdi, r12
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hge_hint_focus]
    cmp  r13d, HGE_REFUSE_LOCKED
    jne  .hint
    mov  qword [rbx + RSP_CODE], CMDE_DESKTOP_LOCKED
    lea  rax, [rel str_hge_hint_locked]
.hint:
    mov  [rbx + RSP_HINT], rax
    mov  eax, 1
    pop  r13
    pop  r12
    pop  rbx
    ret
.list:
    ; " hook list edge=term n=<k> term:<slot>..." -- the WINDOWS gate decided
    push rbx
    push r12
    push r13
    mov  byte [rel chat_out_ready], 0
    call command_hook_out_reset
    lea  rdi, [rel str_hge_list_term]
    call command_hook_out_str
    xor  ebx, ebx
    xor  r12d, r12d
.count:
    cmp  ebx, WM_MAX
    jae  .counted
    mov  edi, ebx
    call terminal_find_window
    cmp  eax, -1
    je   .count_next
    inc  r12d
.count_next:
    inc  ebx
    jmp  .count
.counted:
    mov  edi, r12d
    call command_hook_out_dec
    xor  ebx, ebx
.emit:
    cmp  ebx, WM_MAX
    jae  .listed
    mov  edi, ebx
    call terminal_find_window
    cmp  eax, -1
    je   .emit_next
    lea  rdi, [rel str_hge_item_term]
    call command_hook_out_str
    mov  edi, ebx
    call command_hook_out_dec
.emit_next:
    inc  ebx
    jmp  .emit
.listed:
    mov  eax, 1
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; EDGE widget
; ---------------------------------------------------------------------------
hook_wgt_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    cmp  ebx, HOP_LIST
    je   .list
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    jmp  .none
.list:
    cmp  byte [r12], 0
    jne  .bad
    mov  dword [rel hge_wgt_from], 0
    cmp  byte [r13], 0
    je   .list_ok
    mov  rdi, r13
    call hge_dec_full
    test edx, edx
    jz   .bad
    cmp  rax, WGT_MAX
    ja   .bad
    mov  [rel hge_wgt_from], eax
.list_ok:
    lea  rax, [rel str_hge_verb_wlist]
    jmp  .out
.get:
    cmp  byte [r13], 0
    je   .bad
    mov  rdi, r13
    call hge_has_space
    test eax, eax
    jnz  .bad
    lea  rax, [rel str_hge_verb_wget]
    jmp  .target
.set:
    cmp  byte [r13], 0
    je   .bad
    mov  rdi, r13
    lea  rsi, [rel str_hge_wgt_actions]
    call hge_tok_in
    test eax, eax
    jnz  .na
    lea  rax, [rel str_hge_verb_wset]
.target:
    mov  rbx, rax
    mov  rdi, r12
    call hge_dec_full
    test edx, edx
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hge_sp]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    mov  rax, rbx
    jmp  .out
.na:
    mov  edx, HOOK_PLAN_NA
    jmp  .none
.bad:
    mov  edx, HOOK_PLAN_BADARG
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; widget post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = hook reply staged
hook_wgt_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none
    cmp  edi, HOP_LIST
    je   .list
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
.none:
    xor  eax, eax
    ret
.set:
    ; native WIDGETSET answers len=WGI_VLEN, which for the secret type is the
    ; live password length (srcreview C1): every SET on that type is redacted,
    ; and the reply names the field token only, never the value
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, r12
    call command_hook_parse_dec
    cmp  eax, [rel wgt_count]
    jae  .set_pass
    mov  ebx, eax
    mov  edi, eax
    call wgt_slot_ptr
    mov  eax, [rax + WGI_TYPE]
    test eax, eax
    jz   .set_pass
    mov  edx, [rel wgt_secret_type]
    cmp  edx, -1
    je   .set_pass
    inc  edx
    cmp  eax, edx
    jne  .set_pass
    xor  ecx, ecx
    lea  rdx, [rel hge_field_buf]
.set_field:
    mov  al, [r13 + rcx]
    test al, al
    jz   .set_field_end
    cmp  al, ' '
    je   .set_field_end
    cmp  ecx, HGE_FIELD_MAX - 1
    jae  .set_field_end
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .set_field
.set_field_end:
    mov  byte [rdx + rcx], 0
    mov  byte [rel wgt_out_ready], 0
    call command_hook_out_reset
    lea  rdi, [rel str_hge_set_widget]
    call command_hook_out_str
    mov  edi, ebx
    call command_hook_out_dec
    lea  rdi, [rel str_hge_field]
    call command_hook_out_str
    lea  rdi, [rel hge_field_buf]
    call command_hook_out_str
    lea  rdi, [rel str_hge_redacted]
    call command_hook_out_str
    mov  byte [rel hge_field_buf], 0
    mov  eax, 1
    jmp  .set_out
.set_pass:
    xor  eax, eax
.set_out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.get:
    ; redact every field of the secret type but its static identity fields
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, r12
    call command_hook_parse_dec
    cmp  eax, [rel wgt_count]
    jae  .get_pass
    mov  ebx, eax
    mov  edi, eax
    call wgt_slot_ptr
    mov  eax, [rax + WGI_TYPE]
    test eax, eax
    jz   .get_pass
    mov  edx, [rel wgt_secret_type]
    cmp  edx, -1
    je   .get_pass
    inc  edx
    cmp  eax, edx
    jne  .get_pass
    mov  rdi, r13
    lea  rsi, [rel str_hge_wgt_public_fields]
    call hge_tok_in
    test eax, eax
    jnz  .get_pass
    mov  byte [rel wgt_out_ready], 0
    call command_hook_out_reset
    lea  rdi, [rel str_hge_get_widget]
    call command_hook_out_str
    mov  edi, ebx
    call command_hook_out_dec
    lea  rdi, [rel str_hge_field]
    call command_hook_out_str
    mov  rdi, r13
    call command_hook_out_str
    lea  rdi, [rel str_hge_redacted]
    call command_hook_out_str
    mov  eax, 1
    jmp  .get_out
.get_pass:
    xor  eax, eax
.get_out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.list:
    ; " hook list edge=widget n=<live> from=<id> widget:<id>:<type>:w<slot>... [next=<id>]"
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  byte [rel wgt_out_ready], 0
    call command_hook_out_reset
    lea  rdi, [rel str_hge_list_wgt]
    call command_hook_out_str
    xor  ebx, ebx
    xor  r12d, r12d
.wcount:
    cmp  ebx, [rel wgt_count]
    jae  .wcounted
    mov  edi, ebx
    call wgt_type_name_of
    test rax, rax
    jz   .wcount_next
    inc  r12d
.wcount_next:
    inc  ebx
    jmp  .wcount
.wcounted:
    mov  edi, r12d
    call command_hook_out_dec
    lea  rdi, [rel str_hge_from]
    call command_hook_out_str
    mov  edi, [rel hge_wgt_from]
    call command_hook_out_dec
    mov  ebx, [rel hge_wgt_from]
    xor  r12d, r12d                       ; emitted on this page
.wemit:
    cmp  ebx, [rel wgt_count]
    jae  .wlisted
    mov  edi, ebx
    call wgt_type_name_of
    test rax, rax
    jz   .wemit_next
    cmp  r12d, HGE_WGT_PAGE
    jae  .wmore
    mov  r14, rax
    lea  rdi, [rel str_hge_item_wgt]
    call command_hook_out_str
    mov  edi, ebx
    call command_hook_out_dec
    lea  rdi, [rel str_hge_colon]
    call command_hook_out_str
    mov  rdi, r14
    call command_hook_out_str
    lea  rdi, [rel str_hge_colon_w]
    call command_hook_out_str
    mov  edi, ebx
    call wgt_slot_ptr
    mov  edi, [rax + WGI_WIN]
    call command_hook_out_dec
    inc  r12d
.wemit_next:
    inc  ebx
    jmp  .wemit
.wmore:
    lea  rdi, [rel str_hge_next]
    call command_hook_out_str
    mov  edi, ebx
    call command_hook_out_dec
.wlisted:
    mov  eax, 1
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; EDGE dpms -- GET reports, SET 1 blanks (native: owner only), SET 0 wakes
; ---------------------------------------------------------------------------
hook_dpms_plan:
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: no ":<inst>"
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.get:
    cmp  byte [rdx], 0
    jne  .bad
    lea  rax, [rel str_hge_verb_dpms]
    ret
.set:
    cmp  byte [rdx], 0
    je   .bad
    cmp  byte [rdx + 1], 0
    jne  .bad
    lea  rdi, [rel str_hge_dpms_blank]
    cmp  byte [rdx], '1'
    je   .arg
    lea  rdi, [rel str_hge_dpms_wake]
    cmp  byte [rdx], '0'
    jne  .bad
.arg:
    push rdi
    call command_hook_arg_reset
    pop  rdi
    call command_hook_arg_str
    lea  rax, [rel str_hge_verb_dpms]
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
str_hge_term:          db "term", 0
str_hge_wgt:           db "widget", 0
str_hge_dpms:          db "dpms", 0
str_hge_kind_app:      db "app", 0
str_hge_kind_widget:   db "widget", 0
str_hge_kind_service:  db "service", 0
str_hge_term_schema:   db "inst=<wm_slot> list=WINDOWS(term:<slot>) get=TERMFEED@VTSTAT{COLS,TROWS,CUR,SSH,CAP,FOCUS,MODES,CRC} input=<hex set-1 scancodes>:TERMFEED@KEY(focused,unlocked) observe=COLS,TROWS,CUR,CAP,FOCUS,MODES,CRC set=na cancel=na", 0
str_hge_wgt_schema:    db "inst=<widget_id> list=WIDGETLIST([<from>] page=24,no values) get=<field>:WIDGETGET(census=lifetime,public role/label,state;content withheld;mutation unchecked;content=button text_hex,disabled/open bool or public label text_hex/read value,text or public textfield text_hex; textfield/read value,text,disabled,submits; textfield/builtin_set value,text,disabled (submits=u32 readonly; disabled=0|1) or registered toggle scalar/read value or registered slider/numeric scalar/read value,min,max,step, status/read value,text, progress/read value,max,text_mode,indeterminate,cadence,phase,ticks,job_id; progress/builtin_set value,max,text_mode,indeterminate,cadence,job_id (phase,ticks readonly; text_mode=none|percentage|value,indeterminate=0|1,cadence=1..10,value<=max,max>0,job_id=u64); supported fields only/authority unchecked;secret type redacted) set=<field> <value>:WIDGETSET(action fields na) observe=<field> input=na cancel=na", 0
str_hge_dpms_schema:   db "inst=none get=DPMS{blanked,idle_ms,timeout_ms,presents} set=1:DPMS BLANK(owner only)|0:DPMS WAKE observe=blanked list=na input=na cancel=na", 0
str_hge_term_witness:  db " COLS=",0," TROWS=",0," CUR=",0," CAP=",0," FOCUS=",0," MODES=",0," CRC=",0,0
str_hge_dpms_witness:  db " blanked=",0,0
str_hge_wgt_actions:   db "open",0,"action",0,"input",0,"spawn",0,"close",0,"feed",0,"minimize",0,"restore",0,0
str_hge_wgt_public_fields: db "role",0,"label",0,"intent",0,"intent_seq",0,"census",0,0
str_hge_verb_termfeed: db "TERMFEED", 0
str_hge_verb_windows:  db "WINDOWS", 0
str_hge_verb_wlist:    db "WIDGETLIST", 0
str_hge_verb_wget:     db "WIDGETGET", 0
str_hge_verb_wset:     db "WIDGETSET", 0
str_hge_verb_dpms:     db "DPMS", 0
str_hge_dpms_blank:    db "BLANK", 0
str_hge_dpms_wake:     db "WAKE", 0
str_hge_sub_stat:      db " @VTSTAT", 0
str_hge_sub_key:       db " @KEY ", 0
str_hge_sp:            db " ", 0
str_hge_colon:         db ":", 0
str_hge_colon_w:       db ":w", 0
str_hge_list_term:     db " hook list edge=term n=", 0
str_hge_item_term:     db " term:", 0
str_hge_list_wgt:      db " hook list edge=widget n=", 0
str_hge_from:          db " from=", 0
str_hge_next:          db " next=", 0
str_hge_item_wgt:      db " widget:", 0
str_hge_get_widget:    db " hook get edge=widget:", 0
str_hge_set_widget:    db " hook set edge=widget:", 0
str_hge_field:         db " field=", 0
str_hge_redacted:      db " redacted=1", 0
str_hge_err_unfocused: db " hook err=not_focused edge=term:", 0
str_hge_err_locked:    db " hook err=desktop_locked edge=term:", 0
str_hge_hint_focus:    db "keys go to the focused window: FOCUS <slot> first", 0
str_hge_hint_locked:   db "the desktop is locked: sign in first", 0

align 8
hook_edge_term:        times (HE_SZ / 8) dq 0
hook_edge_wgt:         times (HE_SZ / 8) dq 0
hook_edge_dpms:        times (HE_SZ / 8) dq 0
hge_wgt_from:          dd 0
hge_field_buf:         times HGE_FIELD_MAX db 0

; ---------------------------------------------------------------------------
; Read-only input/pointer: actual INPUTSTAT/MOUSESTAT, unchanged native authority.
; These are synchronous BSP snapshots, not physical routing/quiet-input proof.
; Validate every field and the exact producer end before copying. The common
; hook buffer holds 1024 bytes; larger native receipts refuse, never truncate.
; No native input producer or policy is called here.
HIO_NATIVE_MAX equ 1400
HIO_REPLY_MAX equ 1024

hook_input_plan:
    mov  r8b, 1
    jmp  hio_plan
hook_pointer_plan:
    mov  r8b, 2
hio_plan:
    push rdi
    push rsi
    push rdx
    push r8
    call hio_retire
    pop  r8
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  [rel hio_pending], r8b
    call command_hook_arg_reset
    lea  rax, [rel str_hio_verb_input]
    cmp  byte [rel hio_pending], 1
    je   .out
    lea  rax, [rel str_hio_verb_pointer]
.out:
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_input_post:
    mov  r8b, 1
    jmp  hio_post
hook_pointer_post:
    mov  r8b, 2
hio_post:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rcx
    mov  r13b, r8b
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  [rel hio_pending], r13b
    jne  .bad
    cmp  byte [rel gui_out_ready], 1
    jne  .bad
    lea  rdi, [rel gui_out_buf]
    xor  ecx, ecx
.scan:
    cmp  ecx, HIO_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .end
    inc  ecx
    jmp  .scan
.end:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel gui_out_cur]
    jne  .bad
    lea  r12, [rel hio_input_fields]
    cmp  r13b, 1
    je   .field
    lea  r12, [rel hio_pointer_fields]
.field:
    movzx r14d, byte [r12]
    inc  r12
    test r14d, r14d
    jz   .finish
    mov  rsi, r12
    call hio_literal
    test eax, eax
    jz   .bad
    mov  r12, rsi
    cmp  r14d, 6
    je   .hex
    cmp  r14d, 7
    jae  .list
    call hio_number
    test eax, eax
    jz   .bad
    jmp  .field
.hex:
    call hio_hex24
    test eax, eax
    jz   .bad
    jmp  .field
.list:
    mov  r9d, WM_MAX
.item:
    call hio_number
    test eax, eax
    jz   .bad
    dec  r9d
    jz   .field
    cmp  byte [rdi], ','
    jne  .bad
    inc  rdi
    jmp  .item
.finish:
    cmp  byte [rdi], 0
    jne  .bad
    call command_hook_out_reset
    lea  rdi, [rel gui_out_buf]
    call command_hook_out_str
    call hio_retire
    mov  eax, 1
    jmp  .out
.bad:
    call hio_retire
    call command_hook_out_reset
    lea  rdi, [rel str_hio_input_bad]
    cmp  r13b, 1
    je   .err
    lea  rdi, [rel str_hio_pointer_bad]
.err:
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_VAL], 0
    mov  byte [rel command_hook_out_ready], 1
    xor  eax, eax
    jmp  .out
.refused:
    call hio_retire                     ; retain native refusal code/hint
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

hio_retire:
    mov  byte [rel hio_pending], 0
    mov  byte [rel gui_out_ready], 0
    mov  qword [rel gui_out_cur], 0
    lea  rdi, [rel gui_out_buf]
    mov  ecx, HIO_NATIVE_MAX
    xor  eax, eax
    rep stosb
    ret

; Literal consumes its NUL in RSI, never consumes the receipt's delimiter.
hio_literal:
.l:
    lodsb
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    jmp  .l
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Actual renderer widths: 1=u32, 2=i32, 3=u8, 4=u64, 5=bool,
; 7=u64 list, 8=u32 list. No invented relations between sampled counters.
; R9 (array count) and callee-saved registers survive.
hio_number:
    xor  r8d, r8d
    cmp  r14d, 2
    jne  .unsigned
    cmp  byte [rdi], '-'
    jne  .unsigned
    inc  rdi
    mov  r8d, 1
    cmp  byte [rdi], '0'
    je   .no                           ; native never renders negative zero
.unsigned:
    call hio_decimal
    test eax, eax
    jz   .no
    cmp  r14d, 4
    je   .yes
    cmp  r14d, 7
    je   .yes
    mov  ecx, 0xffffffff
    cmp  r14d, 2
    jne  .byte
    mov  ecx, 0x7fffffff
    add  rcx, r8
    jmp  .bound
.byte:
    cmp  r14d, 3
    jne  .bool
    mov  ecx, 255
.bool:
    cmp  r14d, 5
    jne  .bound
    mov  ecx, 1
.bound:
    cmp  rdx, rcx
    ja   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Canonical unsigned decimal, carry checked through UINT64_MAX.
hio_decimal:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .start
    inc  rdi
    mov  eax, 1
    ret
.start:
    movzx eax, byte [rdi]
    sub  eax, '1'
    cmp  eax, 8
    ja   .no
.digit:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .yes
    mov  rcx, 1844674407370955161
    cmp  rdx, rcx
    ja   .no
    jne  .acc
    cmp  eax, 5
    ja   .no
.acc:
    imul rdx, rdx, 10
    add  rdx, rax
    inc  rdi
    jmp  .digit
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hio_hex24:
    cmp  word [rdi], '0x'
    jne  .no
    add  rdi, 2
    cmp  byte [rdi], '0'
    jne  .start
    inc  rdi
    mov  eax, 1
    ret
.start:
    xor  ecx, ecx
.digit:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .take
    movzx eax, byte [rdi]
    sub  eax, 'a'
    cmp  eax, 5
    ja   .end
.take:
    inc  ecx
    cmp  ecx, 6
    ja   .no
    inc  rdi
    jmp  .digit
.end:
    test ecx, ecx
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hio_input: db "input", 0
str_hio_pointer: db "pointer", 0
str_hio_verb_input: db "INPUTSTAT", 0
str_hio_verb_pointer: db "MOUSESTAT", 0
str_hio_input_schema: db "inst=none get=INPUTSTAT{cursor:u32[3],focus:u32/i32,ring:u8,counters:u64,delta:i32,settings:u32/u8,draw_tsc:u64[16],zorder:u32[16],hid_last_raw:hex24} observe=whole_validated_snapshot receipt=complete,canonical,max1023,synchronous list=na set=na input=na cancel=na physical_routing_quiet=captain_journey", 0
str_hio_pointer_schema: db "inst=none get=MOUSESTAT{x:u32,y:u32,btn:u32} observe=whole_validated_snapshot receipt=complete,canonical,synchronous list=na set=na input=na cancel=na physical_routing_quiet=captain_journey", 0
str_hio_input_bad: db " hook err=input_reply_incomplete", 0
str_hio_pointer_bad: db " hook err=pointer_reply_incomplete", 0
align 8
hook_edge_input: times (HE_SZ / 8) dq 0
hook_edge_pointer: times (HE_SZ / 8) dq 0
hio_pending: db 0
hio_pointer_fields:
    db 1, " x=", 0, 1, " y=", 0, 1, " btn=", 0, 0
hio_input_fields:
    db 1, " inputstat x=", 0
    db 1, " y=", 0
    db 1, " btn=", 0
    db 1, " wm_focus=", 0
    db 2, " focus_widget=", 0
    db 3, " last_intent=", 0
    db 3, " head=", 0
    db 3, " count=", 0
    db 4, " input.kbd.dropped=", 0
    db 4, " routed=", 0
    db 4, " submits=", 0
    db 4, " mouse_events=", 0
    db 2, " mouse_last_dx=", 0
    db 2, " mouse_last_dy=", 0
    db 1, " mouse_speed_pct=", 0
    db 3, " mouse_invert_y=", 0
    db 3, " mouse_swap_btn=", 0
    db 3, " hid_active=", 0
    db 4, " hid_mouse_reports=", 0
    db 4, " hid_poll_ticks=", 0
    db 5, " shadow=", 0
    db 3, " shadow_src=", 0
    db 4, " presents=", 0
    db 4, " present_px=", 0
    db 4, " present_tsc_last=", 0
    db 4, " present_tsc_max=", 0
    db 4, " move_tsc_last=", 0
    db 4, " move_tsc_max=", 0
    db 4, " tsc_khz=", 0
    db 4, " erase_tsc=", 0
    db 7, " draw_tsc=", 0
    db 4, " cursor_presents=", 0
    db 3, " cursor_shape=", 0
    db 3, " resize_edges=", 0
    db 8, " zorder=", 0
    db 4, " ptr_posted=", 0
    db 4, " ptr_pumped=", 0
    db 4, " ptr_dropped=", 0
    db 4, " pump_ticks=", 0
    db 6, " hid_last_raw=", 0
    db 4, " hid_refused_malformed=", 0
    db 4, " hid_refused_rollover=", 0
    db 4, " hid_refused_absolute=", 0
    db 4, " hid_refused_wrong_slot=", 0
    db 4, " hid_refused_stale=", 0
    db 4, " hid_refused_duplicate=", 0
    db 0
