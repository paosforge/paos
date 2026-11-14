;; MODULE gui/naming_picker
;; LAYER 6
;; EXPORTS naming_picker_item_at, naming_picker_dispatch_window, naming_picker_get_hook, naming_picker_set_hook, naming_picker_pointer_hook, naming_picker_text_for_list
;; IMPORTS gui/widget, gui/widget_listview, gui/window_mgmt, gui/form_loader, gui/summon_palette, gui/chat_app, svc/command, svc/command_auth, sec/principal, sec/session, core/lib/fmt, core/lib/str
;; CAPS CAP_GUI
;; OWNER saga:gui
;; Shared deterministic local naming projection. It reads the live window/form
;; registries on every query; the Summon consumer owns no copied catalogue.

NAMING_JSON_MAX equ 1088
NAMING_PAGE_ROWS equ 6
NAMING_ALIAS_END equ 0xFF                ; naming_form_aliases: no form has this index
NAMING_ROW_ESC_MAX equ 176              ; RCQ-38 L3a: one escaped row (a 39 B title = 157 B), 16n

; EDI=list widget, ESI=global item index -> EAX=1/0. On success the item
; scratch below names the exact live registry target.
naming_picker_item_at:
    ; Each lookup publishes one complete tagged union. Without clearing the
    ; opposite arm, a form found after a window could retain that window ID
    ; and activate the stale target instead of the live form registry entry.
    call naming_picker_clear_item
    cmp  edi, [rel summon_results_id]
    jne  .miss
    call wgt_slot_ptr
    mov  eax, [rax + WGI_BIND]
    cmp  eax, FORM_BIND_SUMMON_PINNED
    je   naming_picker_pinned_at
    cmp  eax, FORM_BIND_SUMMON_RECENTS
    je   naming_picker_recent_at
    cmp  eax, FORM_BIND_SUMMON_RESULTS
    je   naming_picker_results_at
.miss:
    xor  eax, eax
    ret

naming_picker_clear_item:
    mov  dword [rel naming_item_win], -1
    mov  dword [rel naming_item_form], -1
    mov  qword [rel naming_item_text], 0
    mov  qword [rel naming_item_target], 0
    ret

; EDI=form index -> publish a form item.
naming_picker_form_item:
    mov  [rel naming_item_form], edi
    call form_table_ptr
    mov  rcx, [rax + FORM_NAME]
    mov  [rel naming_item_text], rcx
    mov  [rel naming_item_target], rcx
    lea  rcx, [rel naming_kind_form]
    mov  [rel naming_item_kind], rcx
    mov  eax, 1
    ret

; EDI=window slot -> publish a window item.
naming_picker_window_item:
    mov  [rel naming_item_win], edi
    lea  rax, [rel wm_title]
    mov  rcx, [rax + rdi*8]
    test rcx, rcx
    jz   .miss
    mov  [rel naming_item_text], rcx
    lea  rsi, [rel naming_target_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    mov  [rel naming_item_target], rsi
    lea  rcx, [rel naming_kind_window]
    mov  [rel naming_item_kind], rcx
    mov  eax, 1
    ret
.miss:
    xor  eax, eax
    ret

; Dispatch the selected registry target through its existing public verb. This
; is shared by pointer, keyboard, and remote WIDGETSET activation; none may
; call a private window/form callback. A nested WIDGETSET keeps its authenticated
; source/principal and needs that principal to be OWNER exactly; physical input
; needs the bound local OWNER login (session_shell_local_authority), never the
; ambient principal_current. RCQ-29: the local Try desktop (its physical input,
; or its own console WIDGETSET) launches as itself: Try principal, console
; source, zero capability, never an OWNER projection; the registry's native
; Try admission takes it only through the one-shot launch the session arms for
; this exact request, while the local login is still that Try login. Try
; launches no power row and not the owner action card (form rows 17-21: the
; power confirmation, Restart / Shut down / Return to Windows, the card); the
; launcher's flags list them, but they act beyond the Try desktop.
%if FORM_RESTART_INDEX <= FORM_POWER_INDEX || FORM_SHUTDOWN_INDEX <= FORM_POWER_INDEX || FORM_WINDOWS_INDEX <= FORM_POWER_INDEX || FORM_RESTART_INDEX >= FORM_CARD_INDEX || FORM_SHUTDOWN_INDEX >= FORM_CARD_INDEX || FORM_WINDOWS_INDEX >= FORM_CARD_INDEX
%error "RCQ-29: the power rows moved out of the Try launch refusal range"
%endif
naming_picker_dispatch_item:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8                         ; keep the caller's stack parity
    xor  r15d, r15d                     ; 1 = Try launch
    movzx r14d, byte [rel cmd_in_dispatch]
    mov  ebx, [rel naming_item_win]
    cmp  ebx, 0
    jl   .form
    lea  r13, [rel naming_verb_raise]
    mov  r12, [rel naming_item_target]
    jmp  .identity
.form:
    mov  ebx, [rel naming_item_form]
    cmp  ebx, 0
    jl   .bad
    lea  r13, [rel naming_verb_formload]
    mov  rdi, [rel naming_item_target]
    lea  rsi, [rel naming_dispatch_arg]
    mov  ecx, 72
.form_copy:
    test ecx, ecx
    jz   .bad
    mov  al, [rdi]
    mov  [rsi], al
    inc  rdi
    inc  rsi
    dec  ecx
    test al, al
    jnz  .form_copy
    dec  rsi
    lea  rdi, [rel naming_focus_suffix]
.suffix_copy:
    mov  al, [rdi]
    mov  [rsi], al
    inc  rdi
    inc  rsi
    test al, al
    jnz  .suffix_copy
    mov  ebx, -1
    lea  r12, [rel naming_dispatch_arg]
.identity:
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .local_identity
    mov  rax, [rel cmd_dispatch_last_source]
    mov  [rel naming_dispatch_req + REQ_SOURCE], rax
    mov  rax, [rel cmd_dispatch_last_principal]
    cmp  rax, CMD_PRINCIPAL_OWNER
    jne  .nested_try
    mov  [rel naming_dispatch_req + REQ_PRINCIPAL], rax
    jmp  .request
.nested_try:
    cmp  rax, CMD_PRINCIPAL_TRY
    jne  .bad
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_CONSOLE
    jne  .bad                           ; only the Try desktop's own console WIDGETSET
    jmp  .try_identity
.local_identity:
    call session_shell_local_authority  ; RAX=login PID, RDX=token; 0/0 refused
    cmp  rax, PRIN_TRY
    je   .try_identity
    cmp  rax, PRIN_OWNER
    jne  .bad
    mov  qword [rel naming_dispatch_req + REQ_SOURCE], CMD_SOURCE_INTERNAL
    mov  qword [rel naming_dispatch_req + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jmp  .request
.try_identity:
    cmp  dword [rel naming_item_win], 0
    jge  .try_launch                    ; a raise: the window's slot owner gate decides
    mov  eax, [rel naming_item_form]
    sub  eax, FORM_POWER_INDEX
    cmp  eax, FORM_CARD_INDEX - FORM_POWER_INDEX
    jbe  .bad                           ; no power row or action card from Try
    cmp  dword [rel naming_item_form], FORM_EXPLORER_INDEX
    je   .bad                           ; nor Explorer: it lists internal disks
.try_launch:
    mov  qword [rel naming_dispatch_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    mov  qword [rel naming_dispatch_req + REQ_PRINCIPAL], CMD_PRINCIPAL_TRY
    mov  r15d, 1
.request:
    mov  rdi, r13
    call command_lookup
    cmp  eax, -1
    je   .bad
    mov  [rel naming_dispatch_req + REQ_VERB], rax
    mov  qword [rel naming_dispatch_req + REQ_CAP], -1
    mov  qword [rel naming_dispatch_req + REQ_IDEM], 0
    mov  qword [rel naming_dispatch_req + REQ_SEL], 0
    mov  [rel naming_dispatch_req + REQ_ARG], r12
    test r15d, r15d
    jz   .armed
    mov  qword [rel naming_dispatch_req + REQ_CAP], 0
    lea  rdi, [rel naming_dispatch_req]
    call session_shell_try_launch_arm   ; refuses unless the local login is still Try
    test eax, eax
    jz   .bad
.armed:
    ; WIDGETSET has already consumed and authorized its exact AUTH1 envelope.
    ; The delegated registry action retains that request's source/principal,
    ; but must not try to consume the same one-shot ticket a second time.
    mov  al, [rel command_auth_remote_active]
    mov  [rel naming_dispatch_remote_active], al
    test r14d, r14d
    jz   .dispatch
    mov  byte [rel command_auth_remote_active], 0
.dispatch:
    ; RAISE/FORMLOAD remain synchronous registered verbs. Defer their compositor
    ; calls while the registered action is live; the top-level idle seam performs
    ; one composed repaint after the command stack unwinds.
    call wmx_draw_defer_begin
    lea  rdi, [rel naming_dispatch_req]
    lea  rsi, [rel naming_dispatch_rsp]
    call command_dispatch
    push rax
    call wmx_draw_defer_end
    pop  rax
    mov  dl, [rel naming_dispatch_remote_active]
    mov  [rel command_auth_remote_active], dl
    test r14d, r14d
    jz   .dispatch_done
    mov  byte [rel cmd_in_dispatch], 1
.dispatch_done:
    ; The enclosing WIDGETSET owns the wire reply. The delegated verb still
    ; executes and audits normally, but its transport staging must not leak
    ; into the next request, including a refused activation.
    cmp  ebx, 0
    jl   .clear_form_reply
    mov  byte [rel chat_out_ready], 0
    jmp  .reply_cleared
.clear_form_reply:
    mov  byte [rel form_out_ready], 0
.reply_cleared:
    test eax, eax
    jnz  .bad
    cmp  ebx, 0
    jge  .ok
    cmp  dword [rel form_error], FORM_ERR_NONE
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    call session_shell_try_launch_disarm ; every exit; keeps RAX
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

naming_picker_dispatch_window:
    call naming_picker_clear_item
    call naming_picker_window_item
    test eax, eax
    jz   .bad
    jmp  naming_picker_dispatch_item
.bad:
    mov  eax, 1
    ret

naming_picker_form_live:
    ; EDI=index -> EAX=1 iff launcher metadata and a declaration are live.
    cmp  edi, FORM_COUNT
    jae  .no
    lea  rax, [rel form_launcher_flags]
    test byte [rax + rdi], FORM_LAUNCHABLE
    jz   .no
    cmp  edi, FORM_EXPLORER_INDEX
    jne  .declared
    push rdi                            ; no entry on a Try desktop (SEC to rule)
    call session_shell_local_authority
    pop  rdi
    cmp  rax, PRIN_TRY
    je   .no
.declared:
    push rdi
    call form_table_ptr
    pop  rdi
    cmp  qword [rax + FORM_LEN], 0
    je   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

naming_picker_pinned_at:
    push rbx
    push r12
    push r13
    mov  r12d, esi
    xor  ebx, ebx
    xor  r13d, r13d
.scan:
    cmp  ebx, FORM_COUNT
    jae  .miss
    lea  rax, [rel form_launcher_flags]
    test byte [rax + rbx], FORM_PINNED
    jz   .next
    mov  edi, ebx
    call naming_picker_form_live
    test eax, eax
    jz   .next
    cmp  r13d, r12d
    je   .hit
    inc  r13d
.next:
    inc  ebx
    jmp  .scan
.hit:
    mov  edi, ebx
    call naming_picker_form_item
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

naming_picker_recent_at:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, esi
    mov  r13, -1
    xor  r14d, r14d
.rank:
    xor  r15, r15
    mov  r11d, -1
    xor  ebx, ebx
.scan:
    cmp  ebx, WM_MAX
    jae  .rank_done
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbx*4]
    cmp  eax, WM_VISIBLE
    je   .state_ok
    cmp  eax, WM_MIN
    jne  .next
.state_ok:
    lea  rax, [rel wm_recent_seq]
    mov  rcx, [rax + rbx*8]
    test rcx, rcx
    je   .next
    cmp  rcx, r13
    jae  .next
    cmp  rcx, r15
    jbe  .next
    mov  r15, rcx
    mov  r11d, ebx
.next:
    inc  ebx
    jmp  .scan
.rank_done:
    cmp  r11d, -1
    je   .miss
    cmp  r14d, r12d
    je   .hit
    mov  r13, r15
    inc  r14d
    jmp  .rank
.hit:
    mov  edi, r11d
    call naming_picker_window_item
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ASCII fold for the palette search: A-Z -> a-z, '_' -> ' ' (form titles spell
; spaces as '_'). Folds the named 8-bit register in place.
%macro NAMING_FOLD 1
    cmp  %1, 'A'
    jb   %%case_done
    cmp  %1, 'Z'
    ja   %%case_done
    or   %1, 0x20
%%case_done:
    cmp  %1, '_'
    jne  %%done
    mov  %1, ' '
%%done:
%endmacro

; RDI=haystack (NUL-terminated), RSI=needle -> EAX=1 if the folded needle is a
; deterministic substring of the folded haystack; an empty needle never matches.
; Leaf: clobbers RAX, RCX, RDX, R8-R11 only.
naming_picker_contains:
    mov  rdx, -1
    ; fall through: an unbounded haystack still stops at its NUL
; RDI=haystack, RSI=needle, RDX=haystack byte bound -> EAX=1/0. The haystack
; ends at its NUL or after RDX bytes, whichever is first; RDI is not read when
; RDX=0 (a form without a declared title passes RDI=0, RDX=0).
naming_picker_contains_n:
    cmp  byte [rsi], 0
    je   .no
    mov  r8, rdi
    mov  r11, rdx
.start:
    test r11, r11
    jz   .no
    cmp  byte [r8], 0
    je   .no
    mov  r9, r8
    mov  r10, rsi
    mov  rcx, r11
.cmp:
    mov  al, [r10]
    test al, al
    jz   .yes
    test rcx, rcx
    jz   .no
    mov  dl, [r9]
    test dl, dl
    jz   .no
    NAMING_FOLD al
    NAMING_FOLD dl
    cmp  al, dl
    jne  .advance
    inc  r9
    inc  r10
    dec  rcx
    jmp  .cmp
.advance:
    inc  r8
    dec  r11
    jmp  .start
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; EDI=form index, RSI=query -> EAX=1 when the query is part of a name inside
; that form (T5-14.4, English-only). Same matcher as titles, so one form stays
; one result however many of its names match.
naming_picker_form_alias:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    lea  rbx, [rel naming_form_aliases]
.row:
    movzx eax, byte [rbx]
    cmp  eax, NAMING_ALIAS_END
    je   .miss
    inc  rbx
    cmp  eax, r12d
    jne  .skip
    mov  rdi, rbx
    mov  rsi, r13
    call naming_picker_contains
    test eax, eax
    jnz  .out
.skip:
    cmp  byte [rbx], 0
    lea  rbx, [rbx + 1]
    jne  .skip
    jmp  .row
.miss:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

naming_form_aliases:                    ; form index, name, NUL
    db FORM_SETTINGS_INDEX, "Time zone", 0
    db FORM_SETTINGS_INDEX, "Keyboard layout", 0
    db FORM_SETTINGS_INDEX, "Language", 0
    db FORM_APPS_INDEX, "Installed apps", 0
    db FORM_APPS_INDEX, "Coming to PaOS", 0
    db FORM_APPS_INDEX, "Roadmap", 0
    db NAMING_ALIAS_END

; EDI=form index -> RAX=its display name (the `title=` token of the declaration's
; `window` line, '_' displayed as a space), RDX=token length; RAX=0, RDX=0 when
; the row has no bound declaration or no title. Bounded by FORM_LEN: a runtime
; bound blob (form_netmon_bind) need not be NUL-terminated.
; Clobbers RAX, RCX, RDX, R8, R9.
naming_picker_form_title:
    call form_table_ptr
    mov  r8, [rax + FORM_BLOB_PTR]
    mov  r9, [rax + FORM_LEN]
    test r8, r8
    jz   .none
.line:
    cmp  r9, 7
    jb   .none
    cmp  dword [r8], 'wind'
    jne  .skip_line
    cmp  word [r8 + 4], 'ow'
    jne  .skip_line
    cmp  byte [r8 + 6], ' '
    jne  .skip_line
    add  r8, 6
    sub  r9, 6
.key:
    cmp  r9, 7
    jb   .none
    mov  al, [r8]
    test al, al
    jz   .none
    cmp  al, 10
    je   .none
    cmp  dword [r8], ' tit'
    jne  .key_next
    cmp  dword [r8 + 3], 'tle='
    jne  .key_next
    add  r8, 7
    sub  r9, 7
    mov  rax, r8
    xor  edx, edx
.tok:
    cmp  rdx, r9
    jae  .out
    cmp  byte [r8 + rdx], ' '
    jbe  .out
    inc  rdx
    jmp  .tok
.key_next:
    inc  r8
    dec  r9
    jmp  .key
.skip_line:
    test r9, r9
    jz   .none
    mov  al, [r8]
    inc  r8
    dec  r9
    test al, al
    jz   .none
    cmp  al, 10
    jne  .skip_line
    jmp  .line
.none:
    xor  eax, eax
    xor  edx, edx
.out:
    ret

; Exact matches collapse results to one item before substring projection.
naming_picker_find_exact:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.win:
    cmp  ebx, WM_MAX
    jae  .forms
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbx*4]
    cmp  eax, WM_VISIBLE
    je   .win_title
    cmp  eax, WM_MIN
    jne  .win_next
.win_title:
    lea  rax, [rel wm_title]
    mov  rdi, [rax + rbx*8]
    test rdi, rdi
    jz   .win_next
    mov  rsi, r12
    call strcmp
    test eax, eax
    jz   .win_hit
.win_next:
    inc  ebx
    jmp  .win
.win_hit:
    mov  edi, ebx
    call naming_picker_window_item
    jmp  .out
.forms:
    xor  ebx, ebx
.form_loop:
    cmp  ebx, FORM_COUNT
    jae  .miss
    mov  edi, ebx
    call naming_picker_form_live
    test eax, eax
    jz   .form_next
    mov  edi, ebx
    call form_table_ptr
    mov  rdi, [rax + FORM_NAME]
    mov  rsi, r12
    call strcmp
    test eax, eax
    jz   .form_hit
.form_next:
    inc  ebx
    jmp  .form_loop
.form_hit:
    mov  edi, ebx
    call naming_picker_form_item
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

naming_picker_results_at:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, esi
    mov  edi, [rel summon_query_id]
    call wgt_slot_ptr
    call wgt_tf_buf                     ; RCQ-38 L3c: the 255 B query (NUL-ended)
    mov  r13, rax
    cmp  byte [r13], 0
    je   .miss
    mov  rdi, r13
    call naming_picker_find_exact
    test eax, eax
    jz   .substring
    test r12d, r12d
    jnz  .miss
    jmp  .out
.substring:
    xor  ebx, ebx
    xor  r14d, r14d
.windows:
    cmp  ebx, WM_MAX
    jae  .forms
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbx*4]
    cmp  eax, WM_VISIBLE
    je   .match_window
    cmp  eax, WM_MIN
    jne  .win_next
.match_window:
    lea  rax, [rel wm_title]
    mov  rdi, [rax + rbx*8]
    test rdi, rdi
    jz   .win_next
    mov  rsi, r13
    call naming_picker_contains
    test eax, eax
    jz   .win_next
    cmp  r14d, r12d
    je   .win_hit
    inc  r14d
.win_next:
    inc  ebx
    jmp  .windows
.win_hit:
    mov  edi, ebx
    call naming_picker_window_item
    jmp  .out
.forms:
    xor  ebx, ebx
.form_loop:
    cmp  ebx, FORM_COUNT
    jae  .miss
    mov  edi, ebx
    call naming_picker_form_live
    test eax, eax
    jz   .form_next
    ; A Start entry matches by its id or by its display name (the declared
    ; window title); either way it is one result, so indexing stays per form.
    mov  edi, ebx
    call form_table_ptr
    mov  rdi, [rax + FORM_NAME]
    mov  rsi, r13
    call naming_picker_contains
    test eax, eax
    jnz  .form_match
    mov  edi, ebx
    call naming_picker_form_title
    mov  rdi, rax
    mov  rsi, r13
    call naming_picker_contains_n
    test eax, eax
    jnz  .form_match
    mov  edi, ebx
    mov  rsi, r13
    call naming_picker_form_alias
    test eax, eax
    jz   .form_next
.form_match:
    cmp  r14d, r12d
    je   .form_hit
    inc  r14d
.form_next:
    inc  ebx
    jmp  .form_loop
.form_hit:
    mov  edi, ebx
    call naming_picker_form_item
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; bounded JSON builder
naming_json_reset:
    lea  rax, [rel naming_json_buf]
    mov  [rel naming_json_cur], rax
    mov  byte [rax], 0
    mov  byte [rel naming_json_ok], 1
    ret
naming_json_puts:
    mov  rsi, [rel naming_json_cur]
    lea  rdx, [rel naming_json_buf + NAMING_JSON_MAX - 1]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel naming_json_cur], rsi
    cmp  byte [rdi], 0
    je   .out
    mov  byte [rel naming_json_ok], 0
.out:
    ret

naming_json_put_escaped:
    push rbx
    push r12
    push r13
    mov  r12, rdi
.loop:
    movzx ebx, byte [r12]
    test bl, bl
    jz   .done
    mov  r13, [rel naming_json_cur]
    lea  rax, [rel naming_json_buf + NAMING_JSON_MAX]
    sub  rax, r13
    cmp  bl, '"'
    je   .slash
    cmp  bl, 0x5C
    je   .slash
    cmp  bl, 0x20
    jb   .control
    cmp  rax, 2
    jb   .overflow
    mov  [r13], bl
    inc  r13
    jmp  .stored
.slash:
    cmp  rax, 3
    jb   .overflow
    mov  byte [r13], 0x5C
    mov  [r13 + 1], bl
    add  r13, 2
    jmp  .stored
.control:
    cmp  rax, 7
    jb   .overflow
    mov  byte [r13], 0x5C
    mov  byte [r13 + 1], 'u'
    mov  word [r13 + 2], '00'
    mov  eax, ebx
    shr  eax, 4
    and  eax, 15
    lea  rdx, [rel naming_json_hex]
    mov  al, [rdx + rax]
    mov  [r13 + 4], al
    mov  eax, ebx
    and  eax, 15
    mov  al, [rdx + rax]
    mov  [r13 + 5], al
    add  r13, 6
.stored:
    mov  byte [r13], 0
    mov  [rel naming_json_cur], r13
    inc  r12
    jmp  .loop
.overflow:
    mov  byte [rel naming_json_ok], 0
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

naming_json_put_dec:
    mov  rsi, [rel naming_json_cur]
    lea  rax, [rel naming_json_buf + NAMING_JSON_MAX - 24]
    cmp  rsi, rax
    jae  .overflow
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel naming_json_cur], rsi
.done:
    ret
.overflow:
    mov  byte [rel naming_json_ok], 0
    ret

naming_picker_build_json:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r15d, esi
    xor  r14d, r14d
.count:
    cmp  r14d, NAMING_PAGE_ROWS * 32
    jae  .counted
    mov  edi, r12d
    mov  esi, r14d
    call naming_picker_item_at
    test eax, eax
    jz   .counted
    inc  r14d
    jmp  .count
.counted:
    mov  eax, r14d
    add  eax, NAMING_PAGE_ROWS - 1
    xor  edx, edx
    mov  ecx, NAMING_PAGE_ROWS
    div  ecx
    test eax, eax
    jnz  .pages_ready
    mov  eax, 1
.pages_ready:
    mov  ebx, eax
    cmp  r15d, ebx
    jae  .bad_page
    call naming_json_reset
    lea  rdi, [rel naming_json_page]
    call naming_json_puts
    mov  edi, r15d
    call naming_json_put_dec
    lea  rdi, [rel naming_json_pages]
    call naming_json_puts
    mov  edi, ebx
    call naming_json_put_dec
    lea  rdi, [rel naming_json_items]
    call naming_json_puts
    mov  r13d, r15d
    imul r13d, NAMING_PAGE_ROWS
    mov  ebx, r13d
    add  ebx, NAMING_PAGE_ROWS
    cmp  ebx, r14d
    jbe  .row
    mov  ebx, r14d
.row:
    mov  ebp, ebx
.row_next:
    cmp  r13d, ebp
    jae  .finish
    mov  edi, r12d
    mov  esi, r13d
    call naming_picker_item_at
    test eax, eax
    jz   .finish
    mov  eax, r15d
    imul eax, NAMING_PAGE_ROWS
    cmp  r13d, eax
    jz   .no_comma
    lea  rdi, [rel naming_json_comma]
    call naming_json_puts
.no_comma:
    lea  rdi, [rel naming_json_i]
    call naming_json_puts
    mov  edi, r13d
    call naming_json_put_dec
    lea  rdi, [rel naming_json_kind]
    call naming_json_puts
    mov  rdi, [rel naming_item_kind]
    call naming_json_put_escaped
    lea  rdi, [rel naming_json_target]
    call naming_json_puts
    mov  rdi, [rel naming_item_target]
    call naming_json_put_escaped
    lea  rdi, [rel naming_json_text]
    call naming_json_puts
    mov  rdi, [rel naming_item_text]
    call naming_json_put_escaped
    lea  rdi, [rel naming_json_rect]
    call naming_json_puts
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  edi, [rbx + WGI_X]
    inc  edi
    call naming_json_put_dec
    lea  rdi, [rel naming_json_comma]
    call naming_json_puts
    mov  edi, r15d
    imul edi, NAMING_PAGE_ROWS
    neg  edi
    add  edi, r13d
    imul edi, 18
    add  edi, [rbx + WGI_Y]
    add  edi, 30
    call naming_json_put_dec
    lea  rdi, [rel naming_json_comma]
    call naming_json_puts
    mov  edi, [rbx + WGI_W]
    sub  edi, 2
    call naming_json_put_dec
    lea  rdi, [rel naming_json_comma]
    call naming_json_puts
    mov  edi, 18
    call naming_json_put_dec
    lea  rdi, [rel naming_json_endrow]
    call naming_json_puts
    inc  r13d
    jmp  .row_next
.finish:
    lea  rdi, [rel naming_json_tail]
    call naming_json_puts
    cmp  byte [rel naming_json_ok], 1
    jne  .bad_page
    lea  rax, [rel naming_json_buf]
    jmp  .out
.bad_page:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

naming_picker_get_hook:
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rsi
    cmp  edi, [rel summon_results_id]
    jne  .unhandled
.candidate:
    lea  rdi, [rel naming_field_items]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .items_zero
    cmp  byte [r13], 'i'
    jne  .selected_test
    cmp  byte [r13 + 1], 't'
    jne  .selected_test
    cmp  byte [r13 + 2], 'e'
    jne  .selected_test
    cmp  byte [r13 + 3], 'm'
    jne  .selected_test
    cmp  byte [r13 + 4], 's'
    jne  .selected_test
    cmp  byte [r13 + 5], '.'
    jne  .selected_test
    lea  rdi, [r13 + 6]
    call wgt_parse_dec
    test rcx, rcx
    jz   .unhandled
    cmp  byte [rdx], 0
    jne  .unhandled
    cmp  eax, 31
    ja   .unhandled
    mov  r14d, eax
    jmp  .items
.selected_test:
    lea  rdi, [rel naming_field_selected]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .selected
.unhandled:
    xor  eax, eax
    pop  r14
    pop  r13
    pop  r12
    ret
.items_zero:
    xor  r14d, r14d
.items:
    mov  edi, r12d
    mov  esi, r14d
    call naming_picker_build_json
    test rax, rax
    jz   .unhandled
    pop  r14
    pop  r13
    pop  r12
    ret
.selected:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_SEL_LO]
    lea  rsi, [rel naming_selected_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel naming_selected_buf]
    pop  r14
    pop  r13
    pop  r12
    ret

naming_picker_set_hook:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rdx
    cmp  edi, [rel summon_results_id]
    jne  .unhandled
.candidate:
    mov  rbx, rsi
    lea  rdi, [rel naming_field_selected]
    call strcmp
    test eax, eax
    jz   .selected
    mov  rdi, rbx
    lea  rsi, [rel str_wf_action]
    call strcmp
    test eax, eax
    jz   .action
.unhandled:
    mov  eax, -1
    jmp  .out
.selected:
    mov  rdi, r13
    call wgt_parse_dec
    test rcx, rcx
    jz   .bad
    cmp  byte [rdx], 0
    jne  .bad
    cmp  rax, 4095
    ja   .bad
    mov  ebx, eax
    mov  edi, r12d
    mov  esi, ebx
    call naming_picker_item_at
    test eax, eax
    jz   .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], ebx
    mov  dword [rax + WGI_INTENT], LV_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    call wmx_draw_all
    xor  eax, eax
    jmp  .out
.action:
    lea  rdi, [rel naming_action_activate]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jnz  .bad
    cmp  byte [rel summon_palette_open], 1
    jne  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  esi, [rax + WGI_SEL_LO]
    mov  edi, r12d
    call naming_picker_item_at
    test eax, eax
    jz   .bad
    ; Keep both the delegated verb and palette close free of full composition.
    ; naming_picker_dispatch_item nests this guard around command_dispatch.
    call wmx_draw_defer_begin
    mov  edi, [rel naming_item_win]
    cmp  edi, 0
    call naming_picker_dispatch_item
    test eax, eax
    jnz  .action_bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  dword [rax + WGI_INTENT], LV_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
.close:
    xor  edi, edi
    call summon_palette_set_open_direct
    push rax
    call wmx_draw_defer_end
    pop  rax
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.action_bad:
    call wmx_draw_defer_end
    jmp  .bad
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

naming_picker_pointer_hook:
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, edx
    cmp  edi, [rel summon_results_id]
    jne  .no
.candidate:
    mov  edi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jz   .no
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_Y]
    add  ecx, 30
    cmp  r13d, ecx
    jb   .yes
    sub  r13d, ecx
    mov  eax, r13d
    xor  edx, edx
    mov  ecx, 18
    div  ecx
    mov  r13d, eax
    mov  edi, r12d
    mov  esi, r13d
    call naming_picker_item_at
    test eax, eax
    jz   .yes
    mov  edi, r12d
    mov  esi, r13d
    mov  ecx, SUMMON_INTENT_POINTER
    call summon_palette_registry_select
    test eax, eax
    jnz  .yes
    mov  edi, r12d
    lea  rsi, [rel str_wf_action]
    lea  rdx, [rel naming_action_activate]
    mov  ecx, SUMMON_INTENT_POINTER
    call summon_palette_registry_set
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret

naming_picker_text_for_list:
    push rbx
    push r12
    mov  r12d, edi
    lea  rax, [rel naming_text_buf]
    mov  [rel naming_text_cur], rax
    mov  byte [rax], 0
    xor  ebx, ebx
.loop:
    cmp  ebx, 16
    jae  .done
    mov  edi, r12d
    mov  esi, ebx
    call naming_picker_item_at
    test eax, eax
    jz   .done
    test ebx, ebx
    jz   .text
    lea  rdi, [rel naming_text_comma]
    call naming_text_puts
.text:
    ; RCQ-38 L3a (rc-sec N1): a row can be another window's title (WINNEW /
    ; session restore store raw bytes), so every row is the escaped copy; the
    ; row entry also escapes ',', the separator the listview splits on.
    sub  rsp, NAMING_ROW_ESC_MAX
    mov  rsi, [rel naming_item_text]
    mov  rdi, rsp
    mov  edx, NAMING_ROW_ESC_MAX
    mov  ecx, NAMING_ROW_ESC_MAX
    call sec_text_escape_row
    call naming_text_puts
    add  rsp, NAMING_ROW_ESC_MAX
    inc  ebx
    jmp  .loop
.done:
    lea  rax, [rel naming_text_buf]
    pop  r12
    pop  rbx
    ret
naming_text_puts:
    mov  rsi, [rel naming_text_cur]
    lea  rdx, [rel naming_text_buf + 511]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel naming_text_cur], rsi
    ret

align 8
naming_item_kind: dq 0
naming_item_target: dq 0
naming_item_text: dq 0
naming_json_cur: dq 0
naming_text_cur: dq 0
naming_json_ok: db 0
naming_item_win: dd -1
naming_item_form: dd -1
naming_dispatch_remote_active: db 0
align 8
naming_dispatch_req: times REQ_SZ db 0
naming_dispatch_rsp: times RSP_SZ db 0
naming_target_buf: times 24 db 0
naming_selected_buf: times 24 db 0
naming_dispatch_arg: times 80 db 0
naming_json_buf: times NAMING_JSON_MAX db 0
naming_text_buf: times 512 db 0
naming_kind_window: db "window",0
naming_kind_form: db "form",0
naming_field_items: db "items",0
naming_field_items0: db "items.0",0
naming_field_selected: db "selected",0
naming_action_activate: db "activate",0
naming_verb_raise: db "RAISE",0
naming_verb_formload: db "FORMLOAD",0
naming_focus_suffix: db " focus=1",0
naming_text_comma: db ",",0
naming_json_page: db '{"page":',0
naming_json_pages: db ',"pages":',0
naming_json_items: db ',"items":[',0
naming_json_i: db '{"index":',0
naming_json_kind: db ',"kind":"',0
naming_json_target: db '","target":"',0
naming_json_text: db '","text":"',0
naming_json_rect: db '","rect":[',0
naming_json_comma: db ",",0
naming_json_endrow: db ']}',0
naming_json_tail: db ']}',0
naming_json_hex: db "0123456789ABCDEF"
