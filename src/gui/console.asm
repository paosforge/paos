;; MODULE gui/console
;; LAYER 6
;; PURPOSE Quiet text-first login and command-registry projection for Task2505.
;; EXPORTS headless_cli_declare, headless_cli_init, headless_cli_tick, headless_cli_key, headless_cli_sync, headless_cli_boot_report, headless_cli_active, headless_cli_state
;; IMPORTS config/keep_config, dev/input/ps2, gui/input_route, gui/widget_console_grid, gui/widget, gui/window, gui/console_app, gui/command_gui, gui/lock_screen, sec/principal, sec/session, svc/command, svc/command_auth, svc/command_cons, svc/command_udp, core/lib/fmt, core/lib/mem, core/lib/str, boot/gop, boot/header, boot/serial, sec/keyprov
;; CAPS
;; OWNER saga:login_surfaces
; The CLI owns no credential comparison and no command handlers. Keyboard bytes
; enter the existing translated input router, PASSWORD submission crosses
; principal_local_password -> authenticate_bind, and commands cross exactly one
; command_dispatch entry with the bound principal's authoritative capability word.

HCLI_USER       equ 0
HCLI_PASSWORD   equ 1
HCLI_SESSION    equ 2
HCLI_USER_MAX   equ 31
HCLI_LINE_MAX   equ 95
HCLI_LOG_MAX    equ 2048
HCLI_NONCE_MAX  equ 64
HCLI_INPUT_BUDGET equ 16

headless_cli_declare:
    lea  rdi, [rel str_hcli_loginmode]
    lea  rsi, [rel cmd_verb_loginmode]
    mov  rdx, CMD_AUTH_CAP_MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1                         ; status and mutation both require owner AUTH1
    call command_register_verb
    cmp  eax, -1
    je   .fail
    call headless_cli_selftest
    test eax, eax
    jnz  .fail
    ; LOGINMODE is the authenticated bootstrap from the default locked GUI
    ; target into CLI. Extend the existing lock-screen ingress here, after
    ; that surface has installed its floor; headless_cli_init replaces this
    ; adapter with the CLI-specific predicate on an actual CLI boot.
    lea  rax, [rel headless_cli_gui_command_allowed]
    mov  [rel command_session_allow_op], rax
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; Action-free policy/session KAT. The system credential exercises the same
; output-only authenticate_bind/session handoff without fabricating a password;
; the live CLI PASSWORD path below is separately content-graded on the target.
headless_cli_selftest:
    push rbx
    mov  byte [rel hcli_kat_ok], 0
    mov  byte [rel hcli_kat_fixture], 0
    call keep_presentation_selftest
    test eax, eax
    jnz  .fail
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    ja   .fail
    lea  rdi, [rel str_hcli_mode_marker]
    call serial_string
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .exercise_locked_bind
    ; Development autologin is already a live principal-bound session. Keep
    ; that policy intact instead of locking it merely to run this KAT.
    call session_shell_require_unlocked
    test eax, eax
    jnz  .fail_preserve
    mov  rdi, [rel session_bound_pid]
    call principal_capabilities
    test rax, rax
    jz   .fail_preserve
    jmp  .session_proven
.exercise_locked_bind:
    mov  byte [rel hcli_kat_fixture], 1
    call principal_system_auth_credential
    test rax, rax
    jz   .fail
    lea  rbx, [rel hcli_kat_auth_ctx]
    mov  [rbx + AUTH_CTX_CREDENTIAL], rax
    mov  [rbx + AUTH_CTX_CRED_LEN], rdx
    mov  edi, AUTH_BIND_SYSTEM_KEY
    mov  rsi, rbx
    call authenticate_bind
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  rsi, rdx
    call session_shell_offer_bind
    test eax, eax
    jnz  .fail
    call session_shell_unlock
    test eax, eax
    jnz  .fail
    call session_shell_require_unlocked
    test eax, eax
    jnz  .fail
    mov  rdi, [rel session_bound_pid]
    call principal_capabilities
    test rax, rax
    jz   .fail
.session_proven:
    lea  rdi, [rel str_hcli_auth_marker]
    call serial_string
    lea  rdi, [rel str_hcli_session_marker]
    call serial_string
    cmp  byte [rel hcli_kat_fixture], 1
    jne  .kat_ok
    ; Only the locked-fixture branch bound a transient system principal. An
    ; existing dev-autologin session must remain untouched.
    call session_shell_lock
.kat_ok:
    mov  byte [rel hcli_kat_ok], 1
    xor  eax, eax
    pop  rbx
    ret
.fail:
    cmp  byte [rel hcli_kat_fixture], 1
    jne  .fail_preserve
    call session_shell_lock
    mov  eax, -1
    pop  rbx
    ret
.fail_preserve:
    mov  eax, -1
    pop  rbx
    ret

headless_cli_init:
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .bad
    mov  byte [rel headless_cli_active], 1
    mov  byte [rel headless_cli_state], HCLI_USER
    mov  dword [rel hcli_user_len], 0
    mov  dword [rel hcli_secret_len], 0
    mov  dword [rel hcli_line_len], 0
    mov  dword [rel hcli_log_len], 0
    lea  rdi, [rel hcli_user]
    xor  esi, esi
    mov  edx, HCLI_USER_MAX + 1
    call memset
    lea  rdi, [rel hcli_secret]
    xor  esi, esi
    mov  edx, PRIN_PASSWORD_MAX
    call memset
    lea  rdi, [rel hcli_line]
    xor  esi, esi
    mov  edx, HCLI_LINE_MAX + 1
    call memset
    call session_shell_lock
    call console_grid_headless_configure
    call headless_cli_input_declare
    test eax, eax
    jnz  .bad
    lea  rax, [rel headless_cli_command_allowed]
    mov  [rel command_session_allow_op], rax
    lea  rax, [rel headless_cli_sync]
    mov  [rel command_session_sync_op], rax
    call headless_cli_render
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Keep the proven KBINJ producer available in CLI boots so native test input
; enters the exact IRQ/USB scancode ring and input router. These are the same
; handlers and registry metadata gui_declare uses; no private injection path.
headless_cli_input_declare:
    lea  rdi, [rel str_hcli_kbinj]
    lea  rsi, [rel cmd_verb_kbinj]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    cmp  eax, -1
    je   .fail
    lea  rdi, [rel str_hcli_kbdbuf]
    lea  rsi, [rel cmd_verb_kbdbuf]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    cmp  eax, -1
    je   .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; Reconcile a SESSIONLOCK/LOCK-style authority transition before any reply is
; observed. The password scratch and command line are cleared before repaint.
headless_cli_sync:
    cmp  byte [rel headless_cli_active], 1
    jne  .out
    call udp_boot_beacon_observe
    cmp  eax, [rel hcli_badge_seen]
    je   .authority
    mov  [rel hcli_badge_seen], eax
    call headless_cli_render
.authority:
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .out
    cmp  byte [rel headless_cli_state], HCLI_SESSION
    jne  .out
    call headless_cli_reset_login
.out:
    ret

headless_cli_tick:
    call headless_cli_input_tick
    call headless_cli_sync
    ret

; Consume the same bounded Set-1 ring as the GUI input router. This ports its
; proven translation table and modifier semantics; only the final consumer is
; swapped from a focused widget to the headless login/command line.
headless_cli_input_tick:
    push rbx
    push r12
    mov  r12d, HCLI_INPUT_BUDGET
.next:
    test r12d, r12d
    jz   .out
    call ps2_kbd_dequeue
    cmp  eax, -1
    je   .out
    dec  r12d
    mov  bl, al
    ; GA0-K: the key's origin, merged across an E0 prefix (as gui/input_route)
    movzx eax, byte [rel ps2_kbd_last_origin]
    cmp  byte [rel hcli_input_e0], 0
    je   .origin_set
    movzx edx, byte [rel input_key_origin]
    call ps2_kbd_origin_merge
.origin_set:
    mov  [rel input_key_origin], al
    cmp  byte [rel hcli_input_e0], 0
    jne  .extended
    cmp  bl, 0xe0
    jne  .ordinary
    mov  byte [rel hcli_input_e0], 1
    jmp  .next
.extended:
    mov  byte [rel hcli_input_e0], 0
    test bl, 0x80
    jnz  .next
    cmp  bl, 0x48
    je   .key_up
    cmp  bl, 0x50
    je   .key_down
    cmp  bl, 0x4b
    je   .key_left
    cmp  bl, 0x4d
    je   .key_right
    cmp  bl, 0x47
    je   .key_home
    cmp  bl, 0x4f
    je   .key_end
    jmp  .next
.ordinary:
    test bl, 0x80
    jnz  .release
    cmp  bl, 0x2a
    je   .shift_on
    cmp  bl, 0x36
    je   .shift_on
    cmp  bl, 0x1d
    je   .ctrl_on
    cmp  bl, 0x3a
    je   .caps
    cmp  bl, 0x0f
    je   .key_tab
    cmp  bl, 0x01
    je   .key_esc
    cmp  bl, 0x0e
    je   .key_backspace
    cmp  bl, 0x1c
    je   .key_enter
    movzx eax, bl
    cmp  eax, 0x59
    jae  .next
    test byte [rel hcli_input_mods], 1
    jnz  .shift_table
    lea  rdx, [rel hcli_us_plain]
    movzx eax, byte [rdx + rax]
    test al, al
    jz   .next
    test byte [rel hcli_input_caps], 1
    jz   .deliver
    cmp  al, 'a'
    jb   .deliver
    cmp  al, 'z'
    ja   .deliver
    sub  al, 32
    jmp  .deliver
.shift_table:
    lea  rdx, [rel hcli_us_shift]
    movzx eax, byte [rdx + rax]
    test al, al
    jz   .next
    test byte [rel hcli_input_caps], 1
    jz   .deliver
    cmp  al, 'A'
    jb   .deliver
    cmp  al, 'Z'
    ja   .deliver
    add  al, 32
    jmp  .deliver
.release:
    and  bl, 0x7f
    cmp  bl, 0x2a
    je   .shift_off
    cmp  bl, 0x36
    je   .shift_off
    cmp  bl, 0x1d
    je   .ctrl_off
    jmp  .next
.shift_on:
    or   byte [rel hcli_input_mods], 1
    jmp  .next
.ctrl_on:
    or   byte [rel hcli_input_mods], 2
    jmp  .next
.caps:
    xor  byte [rel hcli_input_caps], 1
    jmp  .next
.shift_off:
    and  byte [rel hcli_input_mods], 0xfe
    jmp  .next
.ctrl_off:
    and  byte [rel hcli_input_mods], 0xfd
    jmp  .next
.key_enter:
    mov  eax, GUI_KEY_ENTER
    jmp  .deliver
.key_backspace:
    mov  eax, GUI_KEY_BACKSPACE
    jmp  .deliver
.key_left:
    mov  eax, GUI_KEY_LEFT
    jmp  .deliver
.key_right:
    mov  eax, GUI_KEY_RIGHT
    jmp  .deliver
.key_home:
    mov  eax, GUI_KEY_HOME
    jmp  .deliver
.key_end:
    mov  eax, GUI_KEY_END
    jmp  .deliver
.key_up:
    mov  eax, GUI_KEY_UP
    jmp  .deliver
.key_down:
    mov  eax, GUI_KEY_DOWN
    jmp  .deliver
.key_tab:
    mov  eax, GUI_KEY_TAB
    jmp  .deliver
.key_esc:
    mov  eax, GUI_KEY_ESC
.deliver:
    mov  ebx, eax
    call headless_cli_key
    test eax, eax
    jz   .next
    inc  qword [rel input_kbd_routed]
    cmp  ebx, GUI_KEY_ENTER
    jne  .next
    inc  qword [rel input_kbd_submits]
    jmp  .next
.out:
    pop  r12
    pop  rbx
    ret

headless_cli_reset_login:
    mov  byte [rel headless_cli_state], HCLI_USER
    mov  byte [rel hcli_refused], 0
    mov  dword [rel hcli_user_len], 0
    mov  dword [rel hcli_secret_len], 0
    mov  dword [rel hcli_line_len], 0
    mov  dword [rel hcli_log_len], 0
    lea  rdi, [rel hcli_user]
    xor  esi, esi
    mov  edx, HCLI_USER_MAX + 1
    call memset
    lea  rdi, [rel hcli_secret]
    xor  esi, esi
    mov  edx, PRIN_PASSWORD_MAX
    call memset
    lea  rdi, [rel hcli_line_taint]     ; GA0-K: the line and its taint go together
    call keyprov_line_clear
    lea  rdi, [rel hcli_line]
    xor  esi, esi
    mov  edx, HCLI_LINE_MAX + 1
    call memset
    jmp  headless_cli_render

; EAX=translated GUI_KEY_* or printable ASCII. Returns EAX=1 when consumed.
headless_cli_key:
    cmp  byte [rel headless_cli_active], 1
    jne  .ignored
    push rdi                            ; GA0-K: every key the CLI receives folds its
    lea  rdi, [rel hcli_line_taint]     ; origin into the command line's taint
    call keyprov_line_note
    pop  rdi
    push rbx
    push r12
    push r13
    mov  ebx, eax
    cmp  byte [rel headless_cli_state], HCLI_SESSION
    je   .session
    cmp  ebx, GUI_KEY_ENTER
    je   .login_enter
    cmp  ebx, GUI_KEY_BACKSPACE
    je   .login_backspace
    cmp  ebx, GUI_KEY_TAB
    je   .login_tab
    cmp  ebx, 0x20
    jb   .handled
    cmp  ebx, 0x7e
    ja   .handled
    cmp  byte [rel headless_cli_state], HCLI_PASSWORD
    je   .password_char
    mov  eax, [rel hcli_user_len]
    cmp  eax, HCLI_USER_MAX
    jae  .handled
    lea  rdx, [rel hcli_user]
    mov  [rdx + rax], bl
    inc  eax
    mov  [rel hcli_user_len], eax
    mov  byte [rdx + rax], 0
    jmp  .paint
.password_char:
    mov  eax, [rel hcli_secret_len]
    cmp  eax, PRIN_PASSWORD_MAX
    jae  .handled
    lea  rdx, [rel hcli_secret]
    mov  [rdx + rax], bl
    inc  eax
    mov  [rel hcli_secret_len], eax
    jmp  .paint
.login_backspace:
    cmp  byte [rel headless_cli_state], HCLI_PASSWORD
    je   .password_backspace
    mov  eax, [rel hcli_user_len]
    test eax, eax
    jz   .handled
    dec  eax
    mov  [rel hcli_user_len], eax
    lea  rdx, [rel hcli_user]
    mov  byte [rdx + rax], 0
    jmp  .paint
.password_backspace:
    mov  eax, [rel hcli_secret_len]
    test eax, eax
    jz   .handled
    dec  eax
    mov  [rel hcli_secret_len], eax
    lea  rdx, [rel hcli_secret]
    mov  byte [rdx + rax], 0
    jmp  .paint
.login_tab:
    cmp  byte [rel headless_cli_state], HCLI_USER
    jne  .handled
    mov  byte [rel headless_cli_state], HCLI_PASSWORD
    jmp  .paint
.login_enter:
    cmp  byte [rel headless_cli_state], HCLI_PASSWORD
    je   .submit_password
    lea  rdi, [rel hcli_user]
    lea  rsi, [rel str_hcli_user_value]
    call strcmp
    test eax, eax
    jnz  .bad_user
    mov  byte [rel headless_cli_state], HCLI_PASSWORD
    jmp  .paint
.bad_user:
    mov  dword [rel hcli_user_len], 0
    mov  byte [rel hcli_user], 0
    mov  byte [rel hcli_refused], 1
    jmp  .paint
.submit_password:
    lea  rdi, [rel hcli_user]
    lea  rsi, [rel str_hcli_user_value]
    call strcmp
    mov  esi, [rel hcli_secret_len]
    test eax, eax
    jz   .user_ok
    xor  esi, esi
.user_ok:
    lea  rdi, [rel hcli_secret]
    call principal_local_password       ; wipes the entered secret on every result
    mov  r12, rax
    mov  r13, rdx
    mov  dword [rel hcli_secret_len], 0
    test r12, r12
    jz   .auth_refused
    mov  rdi, r12
    mov  rsi, r13
    call session_shell_offer_bind
    test eax, eax
    jnz  .auth_refused
    call session_shell_unlock
    test eax, eax
    jnz  .auth_refused
    mov  byte [rel headless_cli_state], HCLI_SESSION
    mov  byte [rel hcli_refused], 0
    lea  rdi, [rel str_hcli_welcome]
    call headless_log_append_cstr
    lea  rdi, [rel str_hcli_auth_marker]
    call serial_string
    lea  rdi, [rel str_hcli_session_marker]
    call serial_string
    jmp  .paint
.auth_refused:
    call session_shell_lock
    mov  byte [rel hcli_refused], 1
    mov  byte [rel headless_cli_state], HCLI_PASSWORD
    jmp  .paint
.session:
    cmp  ebx, GUI_KEY_ENTER
    je   .session_enter
    cmp  ebx, GUI_KEY_BACKSPACE
    je   .session_backspace
    cmp  ebx, 0x20
    jb   .handled
    cmp  ebx, 0x7e
    ja   .handled
    mov  eax, [rel hcli_line_len]
    cmp  eax, HCLI_LINE_MAX
    jae  .handled
    lea  rdx, [rel hcli_line]
    mov  [rdx + rax], bl
    inc  eax
    mov  [rel hcli_line_len], eax
    mov  byte [rdx + rax], 0
    jmp  .paint
.session_backspace:
    mov  eax, [rel hcli_line_len]
    test eax, eax
    jz   .handled
    dec  eax
    mov  [rel hcli_line_len], eax
    lea  rdx, [rel hcli_line]
    mov  byte [rdx + rax], 0
    jmp  .paint
.session_enter:
    cmp  dword [rel hcli_line_len], 0
    je   .handled
    lea  rdi, [rel str_hcli_prompt]
    call headless_log_append_cstr
    lea  rdi, [rel hcli_line]
    call cons_line_class
    cmp  eax, CONS_CLASS_SECRET
    jne  .echo_plain
    lea  rdi, [rel str_hcli_secret_line]
    jmp  .echo_line
.echo_plain:
    lea  rdi, [rel hcli_line]
.echo_line:
    call headless_log_append_cstr
    lea  rdi, [rel str_hcli_nl]
    call headless_log_append_cstr
    lea  rdi, [rel hcli_line]
    call headless_cli_dispatch_line
    lea  rdi, [rel hcli_line_taint]
    call keyprov_line_clear
    lea  rdi, [rel hcli_line]
    xor  esi, esi
    mov  edx, HCLI_LINE_MAX + 1
    call memset
    mov  dword [rel hcli_line_len], 0
    call headless_cli_sync
    jmp  .paint
.paint:
    call headless_cli_render
.handled:
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.ignored:
    xor  eax, eax
    ret

headless_cli_dispatch_line:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rdi
    call session_shell_require_unlocked
    test eax, eax
    jnz  .denied
    mov  rbx, r14
.find_space:
    cmp  byte [rbx], 0
    je   .no_arg
    cmp  byte [rbx], ' '
    je   .has_arg
    inc  rbx
    jmp  .find_space
.has_arg:
    mov  byte [rbx], 0
    inc  rbx
.arg_spaces:
    cmp  byte [rbx], ' '
    jne  .arg_ready
    inc  rbx
    jmp  .arg_spaces
.no_arg:
.arg_ready:
    mov  r15, rbx
    mov  r13, -1
    lea  rdi, [rel hcli_req]
    xor  esi, esi
    mov  edx, REQ_SZ
    call memset
    lea  rdi, [rel hcli_rsp]
    xor  esi, esi
    mov  edx, RSP_SZ
    call memset
    mov  rdi, [rel session_bound_pid]
    mov  [rel hcli_req + REQ_PRINCIPAL], rdi
    call principal_capabilities
    mov  [rel hcli_req + REQ_CAP], rax
    mov  qword [rel hcli_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    mov  rdi, r14
    call command_lookup
    cmp  eax, -1
    jne  .known
    call command_verb_count
    mov  [rel hcli_req + REQ_VERB], rax
    mov  [rel hcli_req + REQ_ARG], r15
    jmp  .dispatch
.known:
    mov  r13, rax
    mov  [rel hcli_req + REQ_VERB], rax
    mov  rdi, r13
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .text_arg
    mov  rdi, r15
    call console_parse_u64
    mov  [rel hcli_req + REQ_ARG], rax
    jmp  .dispatch
.text_arg:
    mov  [rel hcli_req + REQ_ARG], r15
.dispatch:
    lea  rdi, [rel hcli_req]
    lea  rsi, [rel hcli_rsp]
    lea  rdx, [rel hcli_line_taint]
    mov  ecx, KP_SURFACE_CLI
    call keyprov_dispatch               ; GA0-K: a tainted line runs as its injector
    mov  rdi, r14
    mov  rsi, r15
    lea  rdx, [rel hcli_rsp]
    call command_udp_capture_reply
    mov  rdi, rax
    mov  esi, edx
    call headless_log_append_bytes
    lea  rdi, [rel str_hcli_nl]
    call headless_log_append_cstr
    mov  rax, [rel hcli_rsp + RSP_CODE]
    jmp  .out
.denied:
    lea  rdi, [rel str_hcli_session_denied]
    call headless_log_append_cstr
    mov  eax, CMDE_AUTHDENY
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

headless_log_append_cstr:
    push rdi
    call strlen
    mov  esi, eax
    pop  rdi
    jmp  headless_log_append_bytes

; RDI=bytes, ESI=len. Bounded transcript reset is explicit; command/session
; authority is never retained in this view cache.
headless_log_append_bytes:
    push rbx
    cmp  esi, HCLI_LOG_MAX
    jbe  .bounded
    mov  esi, HCLI_LOG_MAX
.bounded:
    mov  ebx, [rel hcli_log_len]
    mov  eax, ebx
    add  eax, esi
    cmp  eax, HCLI_LOG_MAX
    jbe  .copy
    xor  ebx, ebx
.copy:
    lea  rdx, [rel hcli_log]
    add  rdx, rbx
    xor  ecx, ecx
.next:
    cmp  ecx, esi
    jae  .done
    mov  al, [rdi + rcx]
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .next
.done:
    add  ebx, esi
    mov  [rel hcli_log_len], ebx
    pop  rbx
    ret

headless_cli_render:
    push rbx
    ; The grid painter owns every visible cell and supplies its background.
    ; Keeping the CLI front-end on that seam preserves the GUI render law:
    ; presentation code never calls framebuffer primitives directly.
    call grid_clear
    lea  rdi, [rel str_hcli_machine]
    call headless_grid_append_cstr
    lea  rdi, [rel str_hcli_identity]
    call headless_grid_append_cstr
    cmp  byte [rel headless_cli_state], HCLI_SESSION
    je   .session
    lea  rdi, [rel str_hcli_user]
    call headless_grid_append_cstr
    lea  rdi, [rel hcli_user]
    mov  esi, [rel hcli_user_len]
    call grid_append
    lea  rdi, [rel str_hcli_password]
    call headless_grid_append_cstr
    mov  ecx, [rel hcli_secret_len]
.mask:
    test ecx, ecx
    jz   .login_status
    push rcx
    lea  rdi, [rel str_hcli_star]
    mov  esi, 1
    call grid_append
    pop  rcx
    dec  ecx
    jmp  .mask
.login_status:
    lea  rdi, [rel str_hcli_retry]
    cmp  byte [rel hcli_refused], 1
    je   .status
    lea  rdi, [rel str_hcli_login_help]
.status:
    call headless_grid_append_cstr
    jmp  .draw
.session:
    lea  rdi, [rel str_hcli_session]
    call headless_grid_append_cstr
    mov  rdi, [rel session_bound_pid]
    lea  rsi, [rel hcli_num]
    call fmt_dec
    lea  rdi, [rel hcli_num]
    mov  esi, eax
    call grid_append
    lea  rdi, [rel str_hcli_caps]
    call headless_grid_append_cstr
    mov  rdi, [rel session_bound_pid]
    call principal_capabilities
    mov  rdi, rax
    lea  rsi, [rel hcli_num]
    call fmt_dec
    lea  rdi, [rel hcli_num]
    mov  esi, eax
    call grid_append
    lea  rdi, [rel str_hcli_nl]
    call headless_grid_append_cstr
    lea  rdi, [rel hcli_log]
    mov  esi, [rel hcli_log_len]
    call grid_append
    lea  rdi, [rel str_hcli_prompt]
    call headless_grid_append_cstr
    lea  rdi, [rel hcli_line]
    mov  esi, [rel hcli_line_len]
    call grid_append
.draw:
    call console_grid_headless_draw
    pop  rbx
    ret

headless_grid_append_cstr:
    push rdi
    call strlen
    mov  esi, eax
    pop  rdi
    jmp  grid_append

; Locked CLI keeps the same narrow ingress principle as Task2502. Name matches
; grant no authority: LOGINMODE and every mutation still cross AUTH1/capability.
headless_cli_gui_command_allowed:
    cmp  dword [rdi], 'LOGI'
    jne  lock_screen_command_allowed
    cmp  dword [rdi + 4], 'NMOD'
    jne  lock_screen_command_allowed
    cmp  byte [rdi + 8], 'E'
    jne  lock_screen_command_allowed
    cmp  byte [rdi + 9], 0
    jne  lock_screen_command_allowed
    mov  eax, 1
    ret

headless_cli_command_allowed:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    je   .yes
    push rbx
    push r12
    mov  r12, rdi
    lea  rbx, [rel hcli_locked_names]
.scan:
    cmp  byte [rbx], 0
    je   .no
    mov  rdi, r12
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jz   .found
.next:
    cmp  byte [rbx], 0
    lea  rbx, [rbx + 1]
    jne  .next
    jmp  .scan
.no:
    pop  r12
    pop  rbx
    xor  eax, eax
    ret
.found:
    pop  r12
    pop  rbx
.yes:
    mov  eax, 1
    ret

cmd_verb_loginmode:
    call cmd_handler_prologue
    push r12
    push r13
    push r14
    mov  r12, [rdi + REQ_ARG]
    mov  r13, rsi
    xor  r14d, r14d                    ; 0=status, 1=gui, 2=cli
    test r12, r12
    jz   .bad
    cmp  dword [r12], 'stat'
    jne  .gui
    cmp  word [r12 + 4], 'us'
    jne  .bad
    cmp  byte [r12 + 6], ' '
    jne  .bad
    lea  r12, [r12 + 7]
    jmp  .validate
.gui:
    cmp  dword [r12], 'gui '
    jne  .cli
    lea  r12, [r12 + 4]
    mov  r14d, 1
    jmp  .validate
.cli:
    cmp  dword [r12], 'cli '
    jne  .bad
    lea  r12, [r12 + 4]
    mov  r14d, 2
.validate:
    mov  rdi, r12
    call hcli_nonce_valid
    test eax, eax
    jnz  .bad
    test r14d, r14d
    jz   .stage
    mov  edi, r14d
    dec  edi                            ; operation enum -> persistent target enum
    call keep_presentation_save
    test eax, eax
    jnz  .persist
.stage:
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  rdi, r12
    call headless_cli_stage_status
    jmp  .out
.persist:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rdi, [rel str_hcli_persist_fail]
    call headless_cli_stage_text
    jmp  .out
.bad:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rdi, [rel str_hcli_mode_bad]
    call headless_cli_stage_text
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

hcli_nonce_valid:
    xor  ecx, ecx
.next:
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .done
    cmp  al, 0x21
    jb   .bad
    cmp  al, 0x7e
    ja   .bad
    inc  ecx
    cmp  ecx, HCLI_NONCE_MAX
    jbe  .next
.bad:
    mov  eax, -1
    ret
.done:
    test ecx, ecx
    jz   .bad
    xor  eax, eax
    ret

headless_cli_stage_text:
    push rdi
    call grid_out_reset
    pop  rdi
    call grid_out_str
    mov  byte [rel grid_out_ready], 1
    ret

headless_cli_stage_status:
    push r12
    mov  r12, rdi
    call grid_out_reset
    lea  rdi, [rel str_hcli_mode_status]
    call grid_out_str
    lea  rdi, [rel str_hcli_target_gui]
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .target
    lea  rdi, [rel str_hcli_target_cli]
.target:
    call grid_out_str
    lea  rdi, [rel str_hcli_next]
    call grid_out_str
    lea  rdi, [rel str_hcli_target_gui]
    cmp  byte [rel keep_presentation_saved_target], PRESENTATION_CLI
    jne  .next_target
    lea  rdi, [rel str_hcli_target_cli]
.next_target:
    call grid_out_str
    lea  rdi, [rel str_hcli_screen]
    call grid_out_str
    lea  rdi, [rel str_hcli_screen_gui]
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .screen_ready
    lea  rdi, [rel str_hcli_screen_login]
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .screen_ready
    lea  rdi, [rel str_hcli_screen_session]
.screen_ready:
    call grid_out_str
    lea  rdi, [rel str_hcli_field]
    call grid_out_str
    lea  rdi, [rel str_hcli_field_user]
    cmp  byte [rel headless_cli_state], HCLI_PASSWORD
    jne  .field_ready
    lea  rdi, [rel str_hcli_field_password]
.field_ready:
    cmp  byte [rel headless_cli_state], HCLI_SESSION
    jne  .field_emit
    lea  rdi, [rel str_hcli_field_command]
.field_emit:
    call grid_out_str
    lea  rdi, [rel str_hcli_locked]
    call grid_out_str
    movzx edi, byte [rel session_locked]
    call grid_out_dec
    lea  rdi, [rel str_hcli_principal]
    call grid_out_str
    mov  rdi, [rel session_bound_pid]
    call grid_out_dec
    lea  rdi, [rel str_hcli_caps]
    call grid_out_str
    mov  rdi, [rel session_bound_pid]
    call principal_capabilities
    mov  rdi, rax
    call grid_out_dec
    lea  rdi, [rel str_hcli_desktop]
    call grid_out_str
    movzx edi, byte [rel lock_desktop_created]
    call grid_out_dec
    lea  rdi, [rel str_hcli_desktop_live]
    call grid_out_str
    xor  edi, edi
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .desktop_ready
    movzx edi, byte [rel lock_desktop_created]
.desktop_ready:
    call grid_out_dec
    lea  rdi, [rel str_hcli_cons_sessions]
    call grid_out_str
    call cons_session_count
    mov  edi, eax
    call grid_out_dec
    lea  rdi, [rel str_hcli_epoch]
    call grid_out_str
    mov  rdi, [rel session_authority_epoch]
    call grid_out_dec
    lea  rdi, [rel str_hcli_failures]
    call grid_out_str
    mov  rdi, [rel prin_password_failures]
    call grid_out_dec
    lea  rdi, [rel str_hcli_backoff]
    call grid_out_str
    mov  rdi, [rel prin_password_backoff_until]
    call grid_out_dec
    lea  rdi, [rel str_hcli_enrolled]
    call grid_out_str
    movzx edi, byte [rel prin_password_enrolled]
    call grid_out_dec
    lea  rdi, [rel str_hcli_boot]
    call grid_out_str
    mov  rdi, [rel boot_tsc_start]
    call grid_out_dec
    lea  rdi, [rel str_hcli_grid_cols]
    call grid_out_str
    mov  edi, [rel grid_cols]
    call grid_out_dec
    lea  rdi, [rel str_hcli_grid_rows]
    call grid_out_str
    mov  edi, [rel grid_rows]
    call grid_out_dec
    lea  rdi, [rel str_hcli_fields]
    call grid_out_str
    cmp  byte [rel hcli_kat_ok], 1
    jne  .marker_done
    lea  rdi, [rel str_hcli_marker_status]
    call grid_out_str
.marker_done:
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .nonce
    call headless_cli_stage_view         ; content-bearing readback of the owned grid
.nonce:
    lea  rdi, [rel str_hcli_nonce]
    call grid_out_str
    mov  rdi, r12
    call grid_out_str
    mov  byte [rel grid_out_ready], 1
    pop  r12
    ret

; Append the first eight rows of the actual cell plane. Trailing blanks are
; removed, internal blanks become underscores, and control bytes become dots;
; the password row therefore exposes only the already-rendered mask glyphs.
headless_cli_stage_view:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rdi, [rel str_hcli_view]
    call grid_out_str
    mov  r15d, [rel grid_rows]
    cmp  r15d, 8
    jbe  .rows_ready
    mov  r15d, 8
.rows_ready:
    xor  r12d, r12d
.row:
    test r12d, r12d
    jz   .find_tail
    mov  edi, '/'
    call grid_out_char
.find_tail:
    mov  r14d, [rel grid_cols]
.trim:
    test r14d, r14d
    jz   .next_row
    mov  eax, r12d
    imul eax, GRID_MAX_COLS
    add  eax, r14d
    dec  eax
    shl  eax, 1
    lea  rbx, [rel grid_visible_cells]
    movzx ecx, byte [rbx + rax]
    test cl, cl
    jz   .trim_one
    cmp  cl, ' '
    jne  .emit_row
.trim_one:
    dec  r14d
    jmp  .trim
.emit_row:
    xor  r13d, r13d
.cell:
    cmp  r13d, r14d
    jae  .next_row
    mov  eax, r12d
    imul eax, GRID_MAX_COLS
    add  eax, r13d
    shl  eax, 1
    movzx edi, byte [rbx + rax]
    cmp  dil, ' '
    jne  .printable
    mov  edi, '_'
    jmp  .put
.printable:
    cmp  dil, 0x21
    jb   .dot
    cmp  dil, 0x7e
    jbe  .put
.dot:
    mov  edi, '.'
.put:
    call grid_out_char
    inc  r13d
    jmp  .cell
.next_row:
    inc  r12d
    cmp  r12d, r15d
    jb   .row
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

headless_cli_boot_report:
    lea  rdi, [rel str_hcli_boot_report]
    call serial_string
    movzx edi, byte [rel keep_presentation_target]
    call serial_hex64
    lea  rdi, [rel str_hcli_boot_locked]
    call serial_string
    movzx edi, byte [rel session_locked]
    call serial_hex64
    lea  rdi, [rel str_hcli_boot_desktop]
    call serial_string
    movzx edi, byte [rel lock_desktop_created]
    call serial_hex64
    call serial_newline
    ret

hcli_locked_names:
    db "BOOTCLOCK",0                 ; public clock facts through the same locked floor
    db "PING",0,"STATUS",0,"LIVENESS",0,"BOOTLOG",0,"AUTHSTAT",0,"AUTHVERBS",0,"SECUREBOOT",0
    db "C2RECOVERY",0,"SESSIONINFO",0,"AUTHLOGIN",0,"AUTHENROLL",0,"SESSIONLOCK",0
    db "BOOT",0,"REBOOT",0,"MENU_QUERY",0,"SCAP",0,"SCAPSTAT",0,"SCAPGRANT",0
    db "LOGINMODE",0,"KBINJ",0,"HELP",0,"CATALOG",0,"R0STAT",0,0

str_hcli_loginmode: db "LOGINMODE",0
str_hcli_kbinj: db "KBINJ",0
str_hcli_kbdbuf: db "KBDBUF",0
str_hcli_user_value: db "user",0
str_hcli_machine: db "PaOS",10,0
str_hcli_identity: db "Sign in to your keep",10,10,0
str_hcli_user: db "User: ",0
str_hcli_password: db 10,"Password: ",0
str_hcli_login_help: db 10,10,"Enter signs in; Tab moves to password",0
str_hcli_retry: db 10,10,"Sign-in refused; wait and retry",0
str_hcli_session: db "CLI session principal=",0
str_hcli_caps: db " capabilities=",0
str_hcli_prompt: db "> ",0
str_hcli_nl: db 10,0
str_hcli_star: db '*',0
str_hcli_welcome: db "PaOS CLI - registered verbs are the command language",10,0
str_hcli_session_denied: db "ERR session authority required",10,0
str_hcli_mode_status: db "LOGINMODE target=",0
str_hcli_next: db " next=",0
str_hcli_target_gui: db "gui",0
str_hcli_target_cli: db "cli",0
str_hcli_screen: db " screen=",0
str_hcli_screen_gui: db "gui",0
str_hcli_screen_login: db "login",0
str_hcli_screen_session: db "session",0
str_hcli_field: db " field=",0
str_hcli_field_user: db "user",0
str_hcli_field_password: db "password",0
str_hcli_field_command: db "command",0
str_hcli_locked: db " locked=",0
str_hcli_principal: db " principal=",0
str_hcli_desktop: db " desktop_created=",0
str_hcli_desktop_live: db " desktop=",0
str_hcli_cons_sessions: db " console_sessions=",0
str_hcli_epoch: db " authority_epoch=",0
str_hcli_failures: db " failures=",0
str_hcli_backoff: db " backoff_until=",0
str_hcli_enrolled: db " enrolled=",0
str_hcli_boot: db " BOOT_SESSION=",0
str_hcli_grid_cols: db " grid_cols=",0
str_hcli_grid_rows: db " grid_rows=",0
str_hcli_fields: db " fields=machine,identity,user,password masked=1 credential_store=Task2501 registry=shared",0
str_hcli_marker_status: db " markers=login.cli.mode,login.cli.authenticate_bind,login.cli.session,login.cli.gui_default",0
str_hcli_view: db " view=",0
str_hcli_nonce: db " nonce=",0
str_hcli_persist_fail: db "LOGINMODE REFUSED persistence_failed",0
str_hcli_mode_bad: db "LOGINMODE REFUSED expected=status|gui|cli nonce",0
str_hcli_boot_report: db "[PAOS64] CLIBOOT target=",0
str_hcli_boot_locked: db " locked=",0
str_hcli_boot_desktop: db " desktop_created=",0
str_hcli_mode_marker: db "[PAOS64] login R4: late cli target skips desktop group after quiet core boot [login.cli.mode]",13,10,0
str_hcli_auth_marker: db "[PAOS64] login R4: local console credential uses Task2501 authenticate_bind [login.cli.authenticate_bind]",13,10,0
str_hcli_session_marker: db "[PAOS64] login R4: bound principal owns interactive registry session without desktop [login.cli.session]",13,10,0

align 8
headless_cli_active: db 0
headless_cli_state: db HCLI_USER
hcli_refused: db 0
hcli_kat_ok: db 0
hcli_kat_fixture: db 0
align 4
hcli_badge_seen: dd 0
hcli_user_len: dd 0
hcli_secret_len: dd 0
hcli_line_len: dd 0
hcli_log_len: dd 0
align 8
hcli_user: times (HCLI_USER_MAX + 1) db 0
hcli_secret: times PRIN_PASSWORD_MAX db 0
hcli_line: times (HCLI_LINE_MAX + 1) db 0
align 8
hcli_line_taint: times KT_SIZE db 0      ; GA0-K: sec/keyprov taint of hcli_line
hcli_log: times HCLI_LOG_MAX db 0
hcli_num: times 32 db 0
hcli_req: times REQ_SZ db 0
hcli_rsp: times RSP_SZ db 0
hcli_kat_auth_ctx: times AUTH_CTX_SIZE db 0
hcli_input_e0: db 0
hcli_input_mods: db 0
hcli_input_caps: db 0
align 16
hcli_us_plain:
    db 0,27,'1','2','3','4','5','6','7','8','9','0','-','=',8,9
    db 'q','w','e','r','t','y','u','i','o','p','[',']',13,0,'a','s'
    db 'd','f','g','h','j','k','l',';',39,'`',0,92,'z','x','c','v'
    db 'b','n','m',',','.','/',0,'*',0,' ',0,0,0,0,0,0
    db 0,0,0,0,0,0,0,'7','8','9','-','4','5','6','+','1'
    db '2','3','0','.',0,0,0,0,0
hcli_us_shift:
    db 0,27,'!','@','#','$','%','^','&','*','(',')','_','+',8,9
    db 'Q','W','E','R','T','Y','U','I','O','P','{','}',13,0,'A','S'
    db 'D','F','G','H','J','K','L',':',34,'~',0,'|','Z','X','C','V'
    db 'B','N','M','<','>','?',0,'*',0,' ',0,0,0,0,0,0
    db 0,0,0,0,0,0,0,'7','8','9','-','4','5','6','+','1'
    db '2','3','0','.',0,0,0,0,0

str_hcli_secret_line: db "<credential command redacted>",0
