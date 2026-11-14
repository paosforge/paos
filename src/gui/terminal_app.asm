;; MODULE gui/terminal_app
;; LAYER 6
;; EXPORTS terminal_terminal_launch_op, terminal_app_init, terminal_ui_launch, terminal_app_tick, terminal_key_hook, terminal_find_window, terminal_termfeed, terminal_ssh_sink, terminal_wheel, terminal_key_filter, terminal_wheel_hook, terminal_cmd_launch, terminal_cmd_termfeed, terminal_power_refusal
;; IMPORTS svc/command_shutdown, gui/interpreter_feed, hv/context_execution, gui/calendar, hv/vmx, sec/session, net/dns, svc/ssh_client, boot/serial, gui/window, gui/vt/vt_engine, core/heap, gui/widget, gui/window_mgmt, gui/wm_pointer, gui/input_route, gui/form_loader, gui/cadence_mark, svc/command, svc/command_auth, svc/command_cons, dev/input/ps2, core/time, gui/power_exec, core/lib/fmt, sec/keyprov
;; CAPS CAP_GUI
;; OWNER saga:msi_terminal_input_ux
;
; Peter 2026-09-29: '+ Terminal' and Start > Terminal launch a real terminal
; application, distinct from PaOS Console (which stays as it is). A Terminal
; window hosts one xterm-compatible VT (gui/vt/vt_engine.asm) drawn with the
; Unicode 8x16 font (gui/vt/vt_font.inc). It starts in a small local shell
; (help, clear, exit, PaOS registry commands, `ssh USER@HOST`); `ssh` attaches the
; VT to the SSH channel: remote bytes feed the VT, keys are encoded like
; xterm / Windows Terminal, capability-query replies go back on the channel
; (never into input), and the PTY size follows the window.
;
; Every byte the VT consumes (local shell output and remote data alike) is
; appended to a per-window capture ring first, so an evidence reader can
; replay the exact stream through a reference emulator and compare cells.
;
; Hub port (packet 0009, from the MSI spoke). The Terminal reaches the hub only
; through its existing seams:
;   * LAUNCH app_terminal: the LAUNCH row is extended in place exactly as
;     console_app does for app_console; every other app name tail-dispatches;
;   * TERMFEED <win> @RAW/@KEY/@VTSTAT/@VTCELLS/@VTROW/@VTCAP/@VTCAP64/@VTRZ:
;     the Terminal's own registry verb (destructive: owner-signed remotely),
;     replies staged in command_cons's grid_out channel;
;   * keys through the kit's wgt_key_filter (chained to the filter installed
;     before it), the wheel through ps2_pointer_set_wheel_hook (anything not
;     over a Terminal falls through to wm_pointer_wheel);
;   * the left button over the cells through the kit's typed pointer capture
;     (wgt_type_bind_capture on vt_view; 2026-10-06): selection, scrollbar and
;     xterm mouse reports get their press, drag and release from wm_pointer;
;   * glyphs through the kit's wgt_fill_rect (term_blit_mono*), one cadence
;     batch per direct repaint; the idle loop calls terminal_app_tick; the WM
;     close path retires the view widget, so each open creates a fresh one;
;   * wm_title is the window's identity ("Terminal", per instance buffer); a
;     program's OSC 0/2 title is the slot's app label (wm_app_title), as the
;     hub's tabbed windows do (MSI conflict map: hub wins on window titles).
; `ssh USER@HOST[:PORT]` resolves names natively and runs on svc/ssh_client.asm (hub packet 0014, which
; defines PAOS_TERMINAL_SSH; without that module gui/terminal_ssh_absent.inc
; keeps `ssh` truthful about its absence). SSHCLIKEY shows the client key as an
; authorized_keys line; the owner's SSHCLIKEY ENROLL / RESET keep it across
; restarts / replace it (RCQ-08). The hub router (gui/input_route.asm) decodes
; F1-F12, PgUp/PgDn and Insert to the GUI_KEY_* codes; the Terminal sends them
; as xterm sequences (term_key_map), Shift+PgUp/PgDn and Ctrl+Shift+Up/Down
; scroll the view, and Shift+Insert pastes.

%define PAOS_TERMINAL_GUEST 1

TERM_SSHCLIKEY_CAP equ 96              ; SSHCLIKEY's line (svc/ssh_client SSH_CLI_ID_TEXT_LEN + NUL fits)
TERM_MAX        equ 6                   ; 2026-09-29: 6 Terminals, each with its own ssh session (SSH_SESS_MAX)
TERM_BLIT_OVERLAY equ 0x8000             ; transparent marks: draw foreground only
TERM_MAXCOLS    equ 200
TERM_MAXROWS    equ 80
TERM_DEF_COLS   equ 100
TERM_DEF_ROWS   equ 30
TERM_CAP_SIZE   equ 262144              ; power of two
TERM_PROMPT_CELLS equ 8                 ; term_prompt_text's visible cells ("paos:~$ ")
; Private companion records leave every TI offset/size unchanged.
TD_VALID        equ 8
TD_LEN          equ 12
TD_POS          equ 16
TD_TEXT         equ 20
TD_TEXT_MAX     equ 255                 ; RCQ-38 L4: a draft holds what a history entry holds (TERM_HIST_W - 1)
TD_SIZE         equ 280                 ; owner qword + metadata + 256-byte draft, 8-aligned
TERM_LINE_MAX   equ 1020                ; RCQ-38 L4 (root Q1 18:16:22): a 255-byte UTF-8 name fits a command line
TERM_LINE_BUF   equ 1024                ; TI_LINE: TERM_LINE_MAX + NUL, 8-aligned
TERM_INSET_X    equ 8
TERM_INSET_TOP  equ 4
TERM_INSET_BOT  equ 8
TERM_DEFAULT_FG equ 0xcccccc
TERM_DEFAULT_BG equ 0x0c0c0c
TERM_RAW_MAX    equ 224                 ; @RAW bytes per request (UDP budget, as the console)
TERM_CELLS_MAX  equ 16
TERM_CAPRD_MAX  equ 200
TERM_CAP64_MAX  equ 360                 ; @VTCAP64: 480 base64 chars inside the trial reply
TERM_KEY_MAX    equ 64                  ; @KEY scancodes per request, routed 16 at a time
TERM_RZ_LOG     equ 8
TERM_SSH_CONNECT_US equ 20000000        ; dial + KEX + auth + shell must finish in 20 s
TERM_SSH_TCP_US equ 10000000            ; ... and the TCP handshake in 10 s
TERM_ARP_WAIT_US equ 3000000            ; an unknown host must answer ARP within 3 s
TERM_ARP_RETRY_US equ 400000
TERM_DNS_RETRY_US equ 100000
; Window-local destination, independent of reused TI records and SSH globals.
TS_VALID equ 0
TS_KIND equ 4                         ; 0 numeric, 1 DNS hostname
TS_PHASE equ 8                        ; 0 idle/attached, 1 DNS, 2 ARP, 3 lock notice
TS_PORT equ 12
TS_EPOCH equ 16
TS_TOTAL equ 24
TS_STARTED equ 32                     ; this intent started/joined a pending native query
TS_RAW equ 36                         ; full validated original command, never cut
TS_USER equ TS_RAW + 324
TERM_SSH_LOOKUP_HOST equ TS_USER + 64
TS_DIAL equ TERM_SSH_LOOKUP_HOST + 256              ; numeric USER@IP:PORT, at most85B with NUL
TERM_SSH_EXEC_CAP equ 768
TS_EXEC_LEN equ TS_DIAL + 96
TS_EXEC_USED equ TS_EXEC_LEN + 4
TS_EXEC_CMD equ TS_EXEC_LEN + 8
TS_EXEC_SESSION equ TS_EXEC_CMD + TERM_SSH_EXEC_CAP
TS_EXEC_STREAM equ TS_EXEC_CMD + TERM_SSH_EXEC_CAP + 4
TS_EXEC_TOKEN equ TS_EXEC_CMD + TERM_SSH_EXEC_CAP + 8
TS_SIZE equ (TS_EXEC_CMD + TERM_SSH_EXEC_CAP + 1 + 15) & ~15
TERM_SB_LINES   equ 1000                ; scrollback lines (6.4 MB, high arena only)
TERM_SB_W       equ 6                   ; the scrollbar strip right of the grid (Peter 2026-09-30)
TERM_SB_RESERVE equ 10                  ; grid width kept free for it, clear of the WM's 6-px resize band
TERM_SB_MIN     equ 16                  ; the thumb's minimum height
TERM_SB_TRACK   equ 0x303030
TERM_SB_THUMB   equ 0x8c8c8c
TERM_SB_ACTIVE  equ 0xd0d0d0

; instance record
TI_USED         equ 0
TI_SSH          equ 1                   ; 0 local shell, 1 SSH session, 2 resolving the host
TI_BLINK        equ 2                   ; cursor phase painted last
TI_SEL          equ 3                   ; selection: 0 none, 1 dragging, 2 made
TI_WIN          equ 4
TI_WID          equ 8
TI_COLS         equ 12
TI_ROWS         equ 16
TI_WCOLS        equ 20                  ; size last announced to the remote PTY
TI_WROWS        equ 24
TI_LINELEN      equ 28
TI_VT           equ 32
TI_ARENA        equ 40
TI_CAP          equ 48
TI_CAPTOT       equ 56
TI_CURX         equ 64                  ; cursor cell painted last
TI_CURY         equ 68
TI_RZN          equ 72                  ; resize count
TI_GEN          equ 76                  ; spare (spoke: wm_gen at open; the hub checks wm_title)
TI_DEADLINE     equ 80                  ; SSH: channel must be up by this monotonic us
TI_RISOFF       equ 88                  ; capture offset of the last ESC c (RIS) seen
TI_PREVB        equ 96                  ; last captured byte (RIS split across chunks)
TI_SB           equ 104                 ; scrollback ring (0 = none)
TI_VIEWOFF      equ 112                 ; lines scrolled back (0 = live screen)
TI_SBSEEN       equ 116                 ; VT.sb_total when the view was last anchored
TI_VIEWDRAWN    equ 120                 ; VIEWOFF last painted
TI_SESS         equ 124                 ; this window's ssh session (ssh_session_begin), -1 none
TI_NEXTTRY      equ 128                 ; SSH resolving: next dial retry (monotonic us)
TI_RZLOG        equ 136                 ; TERM_RZ_LOG x {u32 cap offset, u16 cols, u16 rows}
TI_LINE         equ TI_RZLOG + TERM_RZ_LOG * 8
TI_DIAL         equ TI_LINE + TERM_LINE_BUF ; this window's ssh target text (redials use it)
TI_DIALIP       equ TI_DIAL + 64        ; its IPv4 once parsed (ARP resolution)
TI_EDROW        equ TI_DIALIP + 8       ; local line: rows from the prompt's row down to the cursor (RCQ-38 L4)
TI_EDEND        equ TI_EDROW + 4        ; local line: rows from the prompt's row down to the drawn line's end
TI_SELAR        equ TI_DIALIP + 16      ; selection anchor row, col (view cells); = TI_EDEND + 4
TI_SELAC        equ TI_SELAR + 4
TI_SELBR        equ TI_SELAR + 8        ; selection end row, col
TI_SELBC        equ TI_SELAR + 12
TI_MREP         equ TI_SELAR + 16       ; 1 + the held button (0 left, 1 middle, 2 right) reported to the remote (xterm mouse); 0 none
TI_FOCUS        equ TI_SELAR + 17       ; focus last reported for DECSET 1004 (0 out, 1 in)
TI_CONFIRM      equ TI_SELAR + 18       ; local shell: a power command awaits y/N (its kind), 0 none
TI_SBDRAG       equ TI_SELAR + 19       ; 1 while the scrollbar thumb is dragged
TI_MCOL         equ TI_SELAR + 20       ; cell of the last reported mouse event
TI_MROW         equ TI_SELAR + 24
TI_LINEPOS      equ TI_SELAR + 28       ; local shell: caret within TI_LINE
TI_HISTN        equ TI_SELAR + 32       ; local shell history: lines kept (<= TERM_HIST_N)
TI_HISTI        equ TI_SELAR + 36       ; browsing: 0 = the new line, k = k-th newest
TI_HIST         equ TI_SELAR + 40       ; TERM_HIST_N x TERM_HIST_W, newest first
TERM_HIST_N     equ 50                  ; as the Windows console's default history
TERM_HIST_W     equ 256
; RCQ-38 L4: a line longer than TERM_HIST_W - 1 bytes runs but is not kept in
; history (counted in term_hist_skipped), and never cut; a draft holds the same.
%if TD_TEXT_MAX != TERM_HIST_W - 1 || TD_SIZE < TD_TEXT + TD_TEXT_MAX + 1 || TERM_LINE_BUF < TERM_LINE_MAX + 1
%error "Terminal line/draft/history bounds disagree"
%endif
TI_TITLE        equ TI_HIST + TERM_HIST_N * TERM_HIST_W   ; the window's title (OSC 0/2 or "Terminal")
TERM_TITLE_MAX  equ 40                  ; = WMX_TITLE_MAX
TI_ECHO_T0      equ TI_TITLE + TERM_TITLE_MAX   ; dq: a typed key went out at (us), 0 = none pending
TI_ECHO_N       equ TI_ECHO_T0 + 8      ; dd: keystroke -> first remote byte samples (SSH-10)
TI_ECHO_MAX     equ TI_ECHO_T0 + 12     ; dd: slowest, us
TI_ECHO_SUM     equ TI_ECHO_T0 + 16     ; dq: sum, us
TI_ECHO_B       equ TI_ECHO_T0 + 24     ; 6 x dd: <10, <25, <50, <100, <250, >=250 ms
TI_SBGRAB       equ TI_ECHO_B + 24      ; dd: pointer offset within the dragged thumb
TI_NAME         equ TI_SBGRAB + 8      ; "Terminal": the window's identity (wm_title), never renamed
TI_SIZE         equ TI_NAME + 16
TERM_SSH_KEY    equ 0                   ; term_ssh_input_ok: judge the key being delivered
TERM_SSH_EXEC_KEY equ 2                ; typed exec input/control, same key origin admission
TERM_SSH_PTR    equ 1                   ; ... the pointer event being delivered
TERM_CLIP_MAX   equ 8192                ; the Terminals' shared copy/paste buffer

; Hub: GUI_KEY_DELETE (0x10A) and GUI_KEY_PGUP/PGDN/INSERT/F1..F12 (0x10B..0x11B)
; are gui/widget.asm's one key-code table (MSI conflict map rule 6); the hub
; router decodes all of them (gui/input_route.asm).

%include "gui/terminal_guest.inc"

;; ---------------------------------------------------------------------------
;; terminal_app_init: register the vt_view widget type and own '+ Terminal'.
;; Runs after console_app_init (which binds the console as a fallback).
terminal_app_init:
    lea  rdi, [rel term_type_name]
    lea  rsi, [rel terminal_view_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel term_widget_set]
    lea  r8,  [rel term_widget_get]
    mov  r9, (64 << 32) | 64
    call wgt_type_register
    cmp  eax, -1
    je   .refused
    mov  [rel term_type_id], eax
    mov  edi, eax
    lea  rsi, [rel terminal_pointer_capture]
    call wgt_type_bind_capture          ; mouse selection, scrollbar and xterm mouse over the cells
    mov  edi, [rel term_type_id]
    call wgt_type_capture_buttons       ; middle/right presses too (reported only, never local)
    mov  edi, [rel term_type_id]
    call wgt_type_capture_motion        ; DECSET1003 also requests buttonless motion
    mov  edi, 0xfffd
    lea  rax, [rel vt_font_cps]
    mov  ecx, [rel vt_font_count]
    call term_bsearch
    mov  [rel term_fffd_index], eax
    call terminal_hub_seams             ; LAUNCH app_terminal, TERMFEED, keys, wheel
    lea  rdi, [rel term_ready_text]
    call serial_string
    ret
.refused:
    lea  rdi, [rel term_refused_text]
    call serial_string
    ret

term_widget_set:
    mov  eax, 1
    ret
term_widget_get:
    xor  eax, eax
    ret

;; First use is check-then-kmalloc without a lock: safe while every caller runs in the one GUI
;; context on the BSP (frame/app tick, never an interrupt handler). A caller on a second CPU or in
;; interrupt context could see 0 concurrently and allocate twice (one block leaks, two users see
;; different tables); such a caller would need a lock or a lock cmpxchg publish of the pointer. A
;; refusal is logged once (latch below; bb_fill_rect runs per frame); the next call still retries.
;; term_instances_base -> RAX = the instance table (TERM_MAX x TI_SIZE, zeroed), or 0 if the heap
;; refused. One kernel-heap allocation at first use; every user runs after PH_HEAP_INIT, and before it
;; kmalloc refuses, this returns 0 and the next call retries. The table used to be 80,880 zero bytes in
;; the image (PAYLOAD-dell-headroom, c655fbc21 method). Preserves every register except RAX.
term_instances_base:
    mov  rax, [rel term_instances_ptr]
    test rax, rax
    jnz  .have
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 8
    mov  edi, TERM_MAX * TI_SIZE
    call kmalloc
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  ecx, TERM_MAX * TI_SIZE
    push rax
    xor  eax, eax
    rep  stosb
    pop  rax
    mov  [rel term_instances_ptr], rax
    jmp  .done
.fail:
    cmp  byte [rel term_instances_refusal_logged], 0
    jne  .fail_quiet
    mov  byte [rel term_instances_refusal_logged], 1
    lea  rdi, [rel str_term_inst_alloc_fail]
    call serial_string
.fail_quiet:
    xor  eax, eax
.done:
    add  rsp, 8
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
.have:
    ret

;; term_inst_ptr(EDI = index) -> RAX, or 0 when the table could not be allocated
;; (every caller either follows a successful find or checks for 0). Clobbers RDX.
term_inst_ptr:
    call term_instances_base
    test rax, rax
    jz   .out
    mov  edx, edi
    imul edx, TI_SIZE
    add  rax, rdx
.out:
    ret

;; terminal_find_window(EDI = WM slot) -> EAX instance index or -1
terminal_find_window:
    call term_instances_base
    test rax, rax
    jz   .none                          ; no table: nothing is ours
    xor  ecx, ecx
.l:
    cmp  ecx, TERM_MAX
    jae  .none
    mov  eax, ecx
    imul eax, TI_SIZE
    mov  rdx, [rel term_instances_ptr]
    add  rdx, rax
    cmp  byte [rdx + TI_USED], 1
    jne  .n
    cmp  [rdx + TI_WIN], edi
    jne  .n
    cmp  edi, WM_MAX
    jae  .n
    lea  rax, [rel wm_title]            ; hub: a slot is ours while its identity is our buffer
    lea  r8, [rdx + TI_NAME]
    cmp  [rax + rdi*8], r8
    jne  .n                             ; the slot now holds another window
    mov  eax, ecx
    ret
.n:
    inc  ecx
    jmp  .l
.none:
    mov  eax, -1
    ret

;; term_find_widget(EDI = widget id) -> EAX instance index or -1
term_find_widget:
    call term_instances_base
    test rax, rax
    jz   .none                          ; no table: no widget is ours
    xor  ecx, ecx
.l:
    cmp  ecx, TERM_MAX
    jae  .none
    mov  eax, ecx
    imul eax, TI_SIZE
    mov  rdx, [rel term_instances_ptr]
    add  rdx, rax
    cmp  byte [rdx + TI_USED], 1
    jne  .n
    cmp  [rdx + TI_WID], edi
    jne  .n
    mov  eax, ecx
    ret
.n:
    inc  ecx
    jmp  .l
.none:
    mov  eax, -1
    ret

;; ---------------------------------------------------------------------------
;; terminal_ui_launch: the taskbar '+ Terminal' and Start > Terminal target.
;; -> EAX 0 opened, 1 refused (no free instance/window/memory)
terminal_ui_launch:
    call terminal_open
    cmp  eax, -1
    je   .refused
    xor  eax, eax
    ret
.refused:
    ; say why instead of doing nothing (catalogue TSK-05/ROB-04); the LAUNCH
    ; reply carries launch=ERR
    lea  rdi, [rel term_limit_notice]
    call serial_string
    mov  eax, 1
    ret

;; terminal_open -> EAX WM slot or -1
terminal_open:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8                       ; preserve ordinary nested SysV call alignment
    cmp  dword [rel term_type_id], -1
    je   .fail
    cmp  dword [rel wgt_alloc_next], -1
    jne  .fail                         ; never consume another form reservation
    ; Like the form/image loaders, choose a free interior slot before any heap
    ; or window side effect. Serialized BSP path: choosing marks nothing.
    mov  edi, 1
    call wgt_reserve_run
    cmp  eax, -1
    je   .fail
    mov  r14d, eax
    xor  ebx, ebx
.find:
    cmp  ebx, TERM_MAX
    jae  .fail
    mov  edi, ebx
    call term_inst_ptr
    test rax, rax
    jz   .fail                          ; heap refused the table: refuse the open
    cmp  byte [rax + TI_USED], 0
    je   .found
    inc  ebx
    jmp  .find
.found:
    mov  r12, rax
    ; the heaps are bump-only: an instance keeps its buffers across reopen
    cmp  qword [r12 + TI_CAP], 0
    jne  .have_mem
    ; A refused later allocation retains the earlier bump-only buffers.
    ; Retry only the missing stage instead of overwriting its owned pointer.
    cmp  qword [r12 + TI_VT], 0
    jne  .have_vt
    mov  edi, VT_size
    call term_alloc
    test rax, rax
    jz   .nomem
    mov  [r12 + TI_VT], rax
.have_vt:
    cmp  qword [r12 + TI_ARENA], 0
    jne  .have_arena
    mov  edi, TERM_MAXCOLS
    mov  esi, TERM_MAXROWS
    call vt_mem_required
    mov  rdi, rax
    call term_alloc
    test rax, rax
    jz   .nomem
    mov  [r12 + TI_ARENA], rax
.have_arena:
    mov  edi, TERM_CAP_SIZE
    call term_alloc
    test rax, rax
    jz   .nomem
    mov  [r12 + TI_CAP], rax
    mov  edi, (2 * TERM_SB_LINES + TERM_MAXROWS) * TERM_MAXCOLS * VT_CELL
    call kmalloc_model                  ; optional: no scrollback without the high arena
    mov  [r12 + TI_SB], rax
.have_mem:
    lea  rsi, [rel term_title]          ; "Terminal" until the program names it
    lea  rdi, [r12 + TI_TITLE]
    mov  ecx, 9
    cld
    rep  movsb
    lea  rsi, [rel term_title]
    lea  rdi, [r12 + TI_NAME]
    mov  ecx, 9
    rep  movsb
    lea  rdi, [r12 + TI_NAME]           ; hub: wm_title is the identity (WINTREE, WINCLOSE by name);
                                        ; the program's title is the app label (wm_app_title)
    mov  esi, 180
    mov  edx, 70
    mov  ecx, TERM_DEF_COLS * 8 + TERM_INSET_X * 2 + TERM_SB_RESERVE
    mov  r8d, TERM_DEF_ROWS * 16 + GUI_TITLE_H + TERM_INSET_TOP + TERM_INSET_BOT
    mov  r9d, WM_RESTORE_FRESH
    lea  r10, [rel term_title]           ; all copies, independent of caption/buffer
    call wmx_open_app_window
    cmp  eax, -1
    je   .fail
    mov  r13d, eax
    mov  [r12 + TI_WIN], eax
    mov  edi, [rel term_type_id]
    mov  esi, r13d
    mov  [rel wgt_alloc_next], r14d
    call wgt_create                     ; hub: the WM close path retires + recycles it
    mov  dword [rel wgt_alloc_next], -1 ; never lend a spent reservation
    cmp  eax, -1
    je   .close_fail
    mov  [r12 + TI_WID], eax
    mov  byte [r12 + TI_SSH], 0
    mov  dword [r12 + TI_SESS], -1
    mov  byte [r12 + TI_BLINK], 1
    call term_draft_forget              ; a reopened slot never inherits a draft
    push rdi
    call term_taint_rec                 ; ... nor a line taint (GA0-K)
    call keyprov_line_clear
    pop  rdi
    mov  byte [r12 + TI_CONFIRM], 0     ; no y/N inherited from the slot's previous window
    mov  dword [r12 + TI_LINELEN], 0
    mov  dword [r12 + TI_LINEPOS], 0
    mov  dword [r12 + TI_HISTN], 0      ; a new window starts a fresh history
    lea  rdi, [r12 + TI_ECHO_T0]        ; no echo-latency samples yet
    xor  eax, eax
    mov  ecx, 48
    rep  stosb
    mov  dword [r12 + TI_HISTI], 0
    mov  qword [r12 + TI_CAPTOT], 0
    mov  qword [r12 + TI_RISOFF], 0     ; the fresh VT is the power-on state
    mov  byte [r12 + TI_PREVB], 0
    mov  dword [r12 + TI_WCOLS], 0
    mov  dword [r12 + TI_WROWS], 0
    mov  dword [r12 + TI_RZN], 0
    mov  dword [r12 + TI_CURX], -1
    mov  dword [r12 + TI_CURY], -1
    call term_geometry                  ; -> ESI cols, EDX rows
    mov  [r12 + TI_COLS], esi
    mov  [r12 + TI_ROWS], edx
    mov  r8d, esi
    mov  r9d, edx
    mov  rdi, [r12 + TI_VT]
    mov  rsi, [r12 + TI_ARENA]
    mov  edx, TERM_MAXCOLS
    mov  ecx, TERM_MAXROWS
    call vt_init
    mov  rsi, [r12 + TI_SB]
    xor  edx, edx
    test rsi, rsi
    jz   .no_sb
    mov  edx, TERM_SB_LINES
.no_sb:
    mov  rdi, [r12 + TI_VT]
    call vt_set_scrollback
    mov  rsi, [r12 + TI_SB]
    test rsi, rsi
    jz   .default_reflow
    add  rsi, TERM_SB_LINES * TERM_MAXCOLS * VT_CELL
    mov  edx, (TERM_SB_LINES + TERM_MAXROWS) * TERM_MAXCOLS * VT_CELL
    mov  rdi, [r12 + TI_VT]
    call vt_set_reflow
.default_reflow:
    mov  dword [r12 + TI_VIEWOFF], 0
    mov  dword [r12 + TI_SBSEEN], 0
    mov  dword [r12 + TI_VIEWDRAWN], 0
    mov  dword [r12 + TI_MCOL], -1      ; no mouse report has been queued yet
    mov  dword [r12 + TI_MROW], -1
    mov  byte [r12 + TI_USED], 1
    call term_prompt                    ; opens clean at a prompt (Windows Terminal)
    ; hub: the view becomes this window's focused widget through the kit's own
    ; click-focus rule (wgt_focus_window would otherwise look for a textfield)
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    mov  esi, [rax + WGI_X]
    inc  esi
    mov  edx, [rax + WGI_Y]
    inc  edx
    mov  edi, r13d
    call wgt_focus_at
    mov  edi, r13d
    call wmx_raise_slot                 ; top of the z-order + keyboard focus + composite
    lea  rdi, [rel term_open_text]
    call serial_string
    mov  eax, r13d
    jmp  .out
.nomem:
    lea  rdi, [rel term_nomem_text]
    call serial_string
    jmp  .fail
.close_fail:
    mov  edi, r13d
    call wmx_close_slot
.fail:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; term_alloc(RDI = size) -> RAX or 0. A window's screens and capture ring
;; (~0.8 MiB) come from the large high arena when the boot has one, so a
;; Terminal never competes with drivers and services for the 16 MiB heap.
term_alloc:
    push rdi
    call kmalloc_model
    pop  rdi
    test rax, rax
    jnz  .out
    call kmalloc
.out:
    ret

;; term_geometry(R12 = instance): fit the view widget to the client area.
;; -> ESI cols, EDX rows (clamped to the VT maximum)
term_geometry:
    push rbx
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [r12 + TI_WIN]
    lea  rdx, [rel wm_x]
    mov  eax, [rdx + rcx*4]
    add  eax, TERM_INSET_X
    mov  [rbx + WGI_X], eax
    lea  rdx, [rel wm_y]
    mov  eax, [rdx + rcx*4]
    add  eax, GUI_TITLE_H + TERM_INSET_TOP
    mov  [rbx + WGI_Y], eax
    lea  rdx, [rel wm_w]
    mov  eax, [rdx + rcx*4]
    sub  eax, TERM_INSET_X * 2
    cmp  eax, 16
    jge  .w_ok
    mov  eax, 16
.w_ok:
    mov  [rbx + WGI_W], eax             ; the grid plus the scrollbar strip
    sub  eax, TERM_SB_RESERVE           ; the grid stops short of the strip
    cmp  eax, 8
    jge  .cols
    mov  eax, 8
.cols:
    shr  eax, 3
    cmp  eax, TERM_MAXCOLS
    jle  .c_ok
    mov  eax, TERM_MAXCOLS
.c_ok:
    mov  esi, eax
    lea  rdx, [rel wm_h]
    mov  eax, [rdx + rcx*4]
    sub  eax, GUI_TITLE_H + TERM_INSET_TOP + TERM_INSET_BOT
    cmp  eax, 32
    jge  .h_ok
    mov  eax, 32
.h_ok:
    mov  [rbx + WGI_H], eax
    shr  eax, 4
    cmp  eax, TERM_MAXROWS
    jle  .r_ok
    mov  eax, TERM_MAXROWS
.r_ok:
    mov  edx, eax
    pop  rbx
    ret

;; term_out(R12 = instance, RSI = bytes, EDX = length): capture, then feed.
term_out:
    push rbx
    push r13
    mov  rbx, rsi
    mov  r13d, edx
    cmp  byte [r12 + TI_SEL], 0
    je   .no_sel
    call term_sel_clear                 ; the screen moves under a selection: drop it
.no_sel:
    call term_capture
    mov  rdi, [r12 + TI_VT]
    mov  rsi, rbx
    mov  edx, r13d
    call context_vt_enter
    call interpreter_vt_feed
    call context_vt_exit
    pop  r13
    pop  rbx
    ret

;; term_out_cstr(R12, RSI = NUL-terminated)
term_out_cstr:
    push rsi
    mov  rdi, rsi
    call strlen
    pop  rsi
    mov  edx, eax
    jmp  term_out

; Snapshot only after the native local plan accepted this Terminal. The
; existing paste lifetime advances on release/detach/dial and survives reuse.
; No TI layout change, allocation, new authority, or new power executor.
term_power_return_bind:
    push rax
    push rcx
    push rdx
    mov [rel term_power_instance],r12
    call term_inst_index
    lea rdx,[rel term_paste_generations]
    mov rax,[rdx+rax*8]
    mov [rel term_power_generation],rax
    mov rax,[r12+TI_VT]
    mov [rel term_power_vt],rax
    mov eax,[r12+TI_WIN]
    mov [rel term_power_window],eax
    mov eax,[r12+TI_WID]
    mov [rel term_power_widget],eax
    pop rdx
    pop rcx
    pop rax
    ret

; RDI = actual reason returned by power_execute, never a guessed status.
; The original Linux cleanup locks the desktop before BOOT; retain the reason
; in that live Terminal even while LOCK_HIDDEN, for its next normal sign-in.
; Feeding the VT is not physical-visible proof. Public focused VTROW captures
; remain independent observations. Closed/reused/foreign instances get no text.
terminal_power_refusal:
    push rbx
    push r12
    mov rbx,rdi
    call command_power_return_terminal
    test rax,rax
    jz .out
    cmp rax,[rel term_power_instance]
    jne .out
    mov r12,rax
    mov rcx,[rel term_instances_ptr]
    test rcx,rcx
    jz .out
    sub rax,rcx
    jc .out
    cmp rax,TERM_MAX * TI_SIZE
    jae .out
    xor edx,edx
    mov ecx,TI_SIZE
    div rcx
    test edx,edx
    jnz .out
    lea rdx,[rel term_paste_generations]
    mov rax,[rdx+rax*8]
    cmp rax,[rel term_power_generation]
    jne .out
    cmp byte [r12+TI_USED],1
    jne .out
    cmp byte [r12+TI_SSH],0
    jne .out
    mov rax,[r12+TI_VT]
    test rax,rax
    jz .out
    cmp rax,[rel term_power_vt]
    jne .out
    mov eax,[r12+TI_WID]
    cmp eax,[rel term_power_widget]
    jne .out
    mov ecx,[r12+TI_WIN]
    cmp ecx,WM_MAX
    jae .out
    cmp ecx,[rel term_power_window]
    jne .out
    lea rdx,[rel wm_title]
    lea rax,[r12+TI_NAME]
    cmp [rdx+rcx*8],rax
    jne .out
    lea rdx,[rel wm_state]
    mov eax,[rdx+rcx*4]
    cmp eax,WM_VISIBLE
    je .feed
    cmp eax,WM_MIN
    je .feed
    cmp eax,LOCK_HIDDEN
    jne .out
.feed:
    mov rsi,rbx
    call term_out_cstr
    call term_prompt
.out:
    pop r12
    pop rbx
    ret

;; term_out_byte(R12, AL)
term_out_byte:
    mov  [rel term_echo], al
    lea  rsi, [rel term_echo]
    mov  edx, 1
    jmp  term_out

term_prompt:
    mov  dword [r12 + TI_EDROW], 0      ; RCQ-38 L4: a prompt starts the local line's first row
    mov  dword [r12 + TI_EDEND], 0
    lea  rsi, [rel term_prompt_text]
    jmp  term_out_cstr

;; term_capture(R12, RSI bytes, EDX length): append to the capture ring.
;; Every ESC c (RIS) is noted: a reader may replay from that full reset
;; instead of from the start of the stream.
term_capture:
    push rbx
    mov  rbx, [r12 + TI_CAP]
    test rbx, rbx
    jz   .out
    xor  ecx, ecx
.l:
    cmp  ecx, edx
    jae  .out
    mov  rax, [r12 + TI_CAPTOT]
    and  eax, TERM_CAP_SIZE - 1
    mov  r8b, [rsi + rcx]
    mov  [rbx + rax], r8b
    cmp  r8b, 'c'
    jne  .not_ris
    cmp  byte [r12 + TI_PREVB], 0x1b
    jne  .not_ris
    mov  rax, [r12 + TI_CAPTOT]
    dec  rax
    mov  [r12 + TI_RISOFF], rax
.not_ris:
    mov  [r12 + TI_PREVB], r8b
    inc  qword [r12 + TI_CAPTOT]
    inc  ecx
    jmp  .l
.out:
    pop  rbx
    ret

;; ---------------------------------------------------------------------------
;; Rendering
;; terminal_view_draw(EDI = widget id): called by the z-ordered compositor
terminal_view_draw:
    push r12
    call term_find_widget
    cmp  eax, -1
    je   .out
    mov  edi, eax
    call term_inst_ptr
    mov  r12, rax
    call term_refit
    mov  esi, 1
    call term_paint
.out:
    pop  r12
    ret

;; term_refit(R12): production primary reflow; publish PTY/log dimensions
;; only after accepted resize. Refusal leaves owned grid/anchors intact for retry.
term_refit:
    cld
    push rbx
    call term_geometry
    cmp  esi, [r12 + TI_COLS]
    jne  .resize
    cmp  edx, [r12 + TI_ROWS]
    jne  .resize
    mov  rax, [r12 + TI_VT]
    mov  dword [rax + VT.rf_pending], 0 ; window returned to the already-owned grid
    jmp  .guest
.resize:
    push rsi
    push rdx
    call term_reflow_prepare
    pop  rdx
    pop  rsi
    mov  rdi, [r12 + TI_VT]
    call vt_resize
    test eax, eax
    jz   .out
    call term_reflow_finish
    mov  rbx, [r12 + TI_VT]
    mov  esi, [rbx + VT.cols]
    mov  edx, [rbx + VT.rows]
    mov  [r12 + TI_COLS], esi
    mov  [r12 + TI_ROWS], edx
    mov  eax, [r12 + TI_RZN]
    inc  dword [r12 + TI_RZN]
    and  eax, TERM_RZ_LOG - 1
    lea  rcx, [r12 + TI_RZLOG + rax*8]
    mov  rax, [r12 + TI_CAPTOT]
    mov  [rcx], eax
    mov  [rcx + 4], si
    mov  [rcx + 6], dx
.guest:
%ifdef PAOS_TERMINAL_GUEST
    ; The native grid is accepted (or unchanged). Publish also on the first
    ; refit after attach; retries use this attachment's exact consumed START.
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .out
    cmp r12, [rel term_guest_instance]
    jne .out
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    mov edx, [r12 + TI_COLS]
    mov ecx, [r12 + TI_ROWS]
    call hv_terminal_resize
%endif
.out:
    pop  rbx
    ret

;; Caller anchors: absolute chronological history+primary row, zero-based col.
;; VT slots0/1 are its cursors; slots2/3 selection; slot4 scrolled view top.
term_reflow_prepare:
    mov  rbx, [r12 + TI_VT]
    lea  rdi, [rbx + VT.rf_points + 64]
    mov  ecx, 4
.clear:
    mov  qword [rdi], -1
    add  rdi, 32
    loop .clear
    bt   qword [rbx + VT.modes], VTM_ALT
    jc   .out
    mov  eax, [rbx + VT.sb_count]
    sub  eax, [r12 + TI_VIEWOFF]
    jb   .out
    mov  edx, eax
    cmp  dword [r12 + TI_VIEWOFF], 0
    je   .selection
    mov  [rbx + VT.rf_points + 128], rax
    mov  dword [rbx + VT.rf_points + 136], 0
.selection:
    cmp  byte [r12 + TI_SEL], 0
    je   .out
    mov  eax, [r12 + TI_SELAC]
    cmp  eax, [rbx + VT.cols]
    ja   .out
    mov  eax, [r12 + TI_SELBC]
    cmp  eax, [rbx + VT.cols]
    ja   .out
    mov  dword [rbx + VT.rf_points + 76], 0
    mov  dword [rbx + VT.rf_points + 108], 0
    mov  eax, [r12 + TI_SELAR]
    cmp  eax, [r12 + TI_SELBR]
    ja   .end_a
    jb   .end_b
    mov  eax, [r12 + TI_SELAC]
    cmp  eax, [r12 + TI_SELBC]
    ja   .end_a
.end_b:
    mov  eax, [rbx + VT.rf_points + 124]
    and  eax, 1
    inc  eax
    mov  [rbx + VT.rf_points + 108], eax
    jmp  .end_known
.end_a:
    mov  eax, [rbx + VT.rf_points + 92]
    and  eax, 1
    inc  eax
    mov  [rbx + VT.rf_points + 76], eax
.end_known:
    mov  eax, [r12 + TI_SELAR]
    add  rax, rdx
    mov  [rbx + VT.rf_points + 64], rax
    mov  eax, [r12 + TI_SELAC]
    mov  [rbx + VT.rf_points + 72], eax
    mov  eax, [r12 + TI_SELBR]
    add  rax, rdx
    mov  [rbx + VT.rf_points + 96], rax
    mov  eax, [r12 + TI_SELBC]
    mov  [rbx + VT.rf_points + 104], eax
.out:
    ret

term_reflow_finish:
    mov  rbx, [r12 + TI_VT]
    cmp  dword [rbx + VT.rf_done], 0
    je   .fixed
    bt   qword [rbx + VT.modes], VTM_ALT
    jc   .fixed
    xor  r8d, r8d                       ; view top initially follows live screen
    mov  rax, [rbx + VT.rf_screen]
    mov  r8, rax
    cmp  qword [rbx + VT.rf_points + 128], -1
    je   .selection
    mov  rcx, [rbx + VT.rf_points + 144]
    cmp  rcx, [rbx + VT.rf_oldest]
    jb   .view_evicted
    cmp  rcx, r8
    cmovb r8, rcx
    jmp  .selection
.view_evicted:
    mov  r8, [rbx + VT.rf_oldest]         ; nearest retained history, truthful eviction
.selection:
    cmp  byte [r12 + TI_SEL], 0
    je   .view
    mov  rcx, [rbx + VT.rf_points + 80]
    mov  rdx, [rbx + VT.rf_points + 112]
    cmp  rcx, -1
    je   .lost_selection
    cmp  rdx, -1
    je   .lost_selection
    cmp  rcx, [rbx + VT.rf_oldest]
    jb   .lost_selection
    cmp  rdx, [rbx + VT.rf_oldest]
    jb   .lost_selection
    cmp  rcx, r8
    cmovb r8, rcx
    cmp  rdx, r8
    cmovb r8, rdx
    sub  rcx, r8
    sub  rdx, r8
    mov  [r12 + TI_SELAR], ecx
    mov  [r12 + TI_SELBR], edx
    mov  eax, [rbx + VT.rf_points + 88]
    mov  ecx, [rbx + VT.cols]
    cmp  eax, ecx
    cmova eax, ecx
    mov  [r12 + TI_SELAC], eax
    mov  eax, [rbx + VT.rf_points + 120]
    cmp  eax, ecx
    cmova eax, ecx
    mov  [r12 + TI_SELBC], eax
    jmp  .view
.lost_selection:
    mov  byte [r12 + TI_SEL], 0
    mov  dword [rbx + VT.rf_points + 92], 0
    mov  dword [rbx + VT.rf_points + 124], 0
.view:
    mov  rax, [rbx + VT.rf_screen]
    sub  rax, r8
    mov  [r12 + TI_VIEWOFF], eax
    mov  eax, [rbx + VT.sb_total]
    mov  [r12 + TI_SBSEEN], eax
    mov  dword [r12 + TI_VIEWDRAWN], -1
    ret
.fixed:
    ; Fixed-grid growth retains cell coordinates. Truncation invalidates selection.
    mov  eax, [rbx + VT.cols]
    cmp  eax, [r12 + TI_COLS]
    jb   .fixed_clip
    mov  eax, [rbx + VT.rows]
    cmp  eax, [r12 + TI_ROWS]
    jae  .fixed_view
.fixed_clip:
    mov  byte [r12 + TI_SEL], 0
    mov  dword [rbx + VT.rf_points + 92], 0
    mov  dword [rbx + VT.rf_points + 124], 0
.fixed_view:
    mov  eax, [r12 + TI_VIEWOFF]
    cmp  eax, [rbx + VT.sb_count]
    jbe  .out
    mov  eax, [rbx + VT.sb_count]
    mov  [r12 + TI_VIEWOFF], eax
.out:
    ret

;; term_paint(R12 = instance, ESI = 1 whole view / 0 dirty rows + cursor)
term_paint:
    mov  rax, [r12 + TI_VT]
    cmp  dword [rax + VT.rf_pending], 0
    je   .ready
    ret                                ; never paint an old-width grid outside a resized widget
.ready:
    push rbx
    push r13
    push r14
    push r15
    mov  r15d, esi
    mov  r13, [r12 + TI_VT]
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    mov  rbx, rax
    ; screen-wide reverse video swaps the default colours
    mov  eax, TERM_DEFAULT_FG
    mov  ecx, TERM_DEFAULT_BG
    mov  rdx, [r13 + VT.modes]
    bt   rdx, VTM_DECSCNM
    jnc  .defaults
    xchg eax, ecx
.defaults:
    mov  [rel term_def_fg], eax
    mov  [rel term_def_bg], ecx
    ; the previously painted cursor cell and the new one are repainted
    mov  ecx, [r12 + TI_CURY]
    cmp  ecx, 128
    jae  .no_old
    bts  dword [r13 + VT.dirty], ecx
.no_old:
    mov  ecx, [r13 + VT.cy]
    cmp  ecx, 128
    jae  .no_new
    bts  dword [r13 + VT.dirty], ecx
.no_new:
    mov  eax, [r12 + TI_VIEWOFF]
    cmp  eax, [r12 + TI_VIEWDRAWN]
    jne  .whole_view
    test eax, eax
    jz   .view_same
.whole_view:
    mov  qword [r13 + VT.dirty], -1     ; every row moves with the view
    mov  qword [r13 + VT.dirty + 8], -1
    mov  [r12 + TI_VIEWDRAWN], eax
.view_same:
    test r15d, r15d
    jz   .rows
    push rbx
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, [rel term_def_bg]
    call wgt_fill_rect
    pop  rbx
.rows:
    xor  r14d, r14d
.row:
    cmp  r14d, [r13 + VT.rows]
    jge  .rows_done
    test r15d, r15d
    jnz  .paint_row
    cmp  r14d, 128
    jae  .next_row
    bt   dword [r13 + VT.dirty], r14d
    jnc  .next_row
.paint_row:
    mov  edi, r14d
    call term_paint_row
.next_row:
    inc  r14d
    jmp  .row
.rows_done:
    mov  qword [r13 + VT.dirty], 0
    mov  qword [r13 + VT.dirty + 8], 0
    call term_paint_cursor
    call term_paint_scrollbar
    test r15d, r15d
    jz   .out
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    call fb_damage_rect
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_sb_metrics(R12) -> EAX 1 when the scrollbar shows (scrollback exists,
;; main screen), R8D strip x, R9D strip y, R10D strip height, ECX thumb top
;; (relative to the strip), EDX thumb height. Clobbers RSI, RDI, R11.
term_sb_metrics:
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    add  r8d, [rax + WGI_W]
    sub  r8d, TERM_SB_W + 1             ; 3 px from the grid, 3 px from the resize band
    mov  r9d, [rax + WGI_Y]
    mov  r10d, [rax + WGI_H]
    xor  ecx, ecx
    xor  edx, edx
    mov  rsi, [r12 + TI_VT]
    xor  eax, eax
    mov  rdi, [rsi + VT.modes]
    bt   rdi, VTM_ALT
    jc   .out                           ; a full-screen program: no scrollback view
    mov  r11d, [rsi + VT.sb_count]
    test r11d, r11d
    jz   .out
    mov  edi, [rsi + VT.rows]
    mov  eax, r10d
    imul eax, edi                       ; height x screen rows
    add  edi, r11d                      ; ... over scrollback + screen rows
    xor  edx, edx
    div  edi
    cmp  eax, TERM_SB_MIN
    jge  .h_min
    mov  eax, TERM_SB_MIN
.h_min:
    cmp  eax, r10d
    jle  .h_max
    mov  eax, r10d
.h_max:
    push rax
    mov  ecx, r11d
    sub  ecx, [r12 + TI_VIEWOFF]        ; lines above the view's top
    jns  .above
    xor  ecx, ecx
.above:
    mov  eax, r10d
    sub  eax, [rsp]
    imul eax, ecx
    xor  edx, edx
    div  r11d
    mov  ecx, eax                       ; thumb top
    pop  rdx                            ; thumb height
    mov  eax, 1
.out:
    ret

;; term_paint_scrollbar(R12 instance): the track and thumb in the right inset
;; (Windows Terminal style); the background when there is nothing to scroll.
term_paint_scrollbar:
    push rbx
    push r14
    push r15
    call term_sb_metrics
    mov  r14d, ecx
    mov  r15d, edx
    push rax
    mov  ebx, [rel term_def_bg]
    test eax, eax
    jz   .track
    mov  ebx, TERM_SB_TRACK
.track:
    push r8
    push r9
    push r10
    mov  r11d, r10d
    mov  r10d, TERM_SB_W
    call wgt_fill_rect
    pop  r10
    pop  r9
    pop  r8
    pop  rax
    test eax, eax
    jz   .damage
    push r8
    push r9
    push r10
    add  r9d, r14d
    mov  r11d, r15d
    mov  r10d, TERM_SB_W
    mov  ebx, TERM_SB_THUMB
    cmp  byte [r12 + TI_SBDRAG], 1
    jne  .thumb
    mov  ebx, TERM_SB_ACTIVE
.thumb:
    call wgt_fill_rect
    pop  r10
    pop  r9
    pop  r8
.damage:
    mov  r11d, r10d
    mov  r10d, TERM_SB_W
    call fb_damage_rect
    pop  r15
    pop  r14
    pop  rbx
    ret

;; term_paint_row(EDI = row; R12 instance, RBX widget, R13 vt). While the view
;; is scrolled back, the top VIEWOFF rows show saved lines.
term_paint_row:
    push r14
    push r15
    push rbp
    mov  r14d, edi
    xor  ebp, ebp                       ; saved line (0 = screen row)
    mov  eax, [r12 + TI_VIEWOFF]
    cmp  r14d, eax
    jae  .live
    mov  esi, eax
    sub  esi, r14d                      ; back = VIEWOFF - row (1 = newest)
    mov  rdi, r13
    call vt_scrollback_line
    mov  rbp, rax
.live:
    xor  r15d, r15d
.col:
    cmp  r15d, [r13 + VT.cols]
    jge  .done
    test rbp, rbp
    jz   .screen_cell
    mov  eax, r15d
    imul rax, rax, VT_CELL
    add  rax, rbp
    jmp  .have_cell
.screen_cell:
    mov  rdi, r13
    mov  esi, r14d
    sub  esi, [r12 + TI_VIEWOFF]
    mov  edx, r15d
    call vt_cell_ptr
.have_cell:
    cmp  byte [rax + VTC_W], 0
    je   .next                          ; right half: drawn with its lead cell
    mov  r8d, r15d
    shl  r8d, 3
    add  r8d, [rbx + WGI_X]
    mov  r9d, r14d
    shl  r9d, 4
    add  r9d, [rbx + WGI_Y]
    push rax
    mov  edi, r14d
    mov  esi, r15d
    call term_sel_contains              ; EDX 1 = selected: drawn inverse
    pop  rax
    call term_draw_cell
.next:
    inc  r15d
    jmp  .col
.done:
    mov  r8d, [rbx + WGI_X]
    mov  r9d, r14d
    shl  r9d, 4
    add  r9d, [rbx + WGI_Y]
    mov  r10d, [r13 + VT.cols]
    shl  r10d, 3
    mov  r11d, 16
    call fb_damage_rect
    pop  rbp
    pop  r15
    pop  r14
    ret

;; cursor: the cell drawn inverse on the visible blink phase (DECTCEM set)
term_paint_cursor:
    mov  eax, [r13 + VT.cx]
    mov  [r12 + TI_CURX], eax
    mov  eax, [r13 + VT.cy]
    mov  [r12 + TI_CURY], eax
    cmp  dword [r12 + TI_VIEWOFF], 0
    jne  .out                           ; reviewing history: no live cursor
    mov  rax, [r13 + VT.modes]
    bt   rax, VTM_DECTCEM
    jnc  .out
    cmp  byte [r12 + TI_BLINK], 0
    je   .out
    mov  eax, [r13 + VT.cx]
    cmp  eax, [r13 + VT.cols]
    jae  .out
    mov  [rel term_cur_col], eax
    mov  rdi, r13
    mov  esi, [r13 + VT.cy]
    mov  edx, eax
    call vt_cell_ptr
    cmp  byte [rax + VTC_W], 0
    jne  .lead
    dec  dword [rel term_cur_col]       ; on a right half: the lead cell
    js   .out
    mov  rdi, r13
    mov  esi, [r13 + VT.cy]
    mov  edx, [rel term_cur_col]
    call vt_cell_ptr
.lead:
    mov  r8d, [rel term_cur_col]
    shl  r8d, 3
    add  r8d, [rbx + WGI_X]
    mov  r9d, [r13 + VT.cy]
    shl  r9d, 4
    add  r9d, [rbx + WGI_Y]
    mov  edx, 1
    call term_draw_cell
    mov  r10d, 16
    mov  r11d, 16
    call fb_damage_rect
.out:
    ret

;; term_draw_cell(RAX = cell, R8D = x, R9D = y, EDX = 1 cursor): preserves R8-R11
term_draw_cell:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rax
    mov  r15d, edx
    movzx r14d, word [r12 + VTC_FL]
    mov  edi, [r12 + VTC_CP]
    movzx esi, byte [r12 + VTC_W]
    mov  edx, r14d
    and  edx, VTF_BOLD
    call term_glyph                     ; RSI bitmap, EAX 1 narrow / 2 wide
    mov  rbp, rsi
    mov  r13d, eax
    mov  edi, [r12 + VTC_FG]
    mov  esi, [rel term_def_fg]
    mov  edx, r14d
    call term_resolve_colour
    mov  ebx, eax
    mov  edi, [r12 + VTC_BG]
    mov  esi, [rel term_def_bg]
    xor  edx, edx
    call term_resolve_colour
    mov  ecx, eax
    test r14d, VTF_REVERSE
    jz   .no_rev
    xchg ebx, ecx
.no_rev:
    test r15d, r15d
    jz   .no_cursor
    xchg ebx, ecx
.no_cursor:
    test r14d, VTF_DIM
    jz   .no_dim
    mov  eax, ebx                       ; halfway between fg and bg
    and  eax, 0xfefefe
    shr  eax, 1
    mov  edx, ecx
    and  edx, 0xfefefe
    shr  edx, 1
    add  eax, edx
    mov  ebx, eax
.no_dim:
    test r14d, VTF_CONCEAL
    jz   .no_conceal
    mov  ebx, ecx
.no_conceal:
    mov  rsi, rbp
    mov  edx, r14d
    cmp  byte [r12 + VTC_W], 2
    jne  .narrow
    cmp  r13d, 2
    je   .wide
    call term_blit_mono8x16             ; no wide bitmap: glyph + blank half
    add  r8d, 8
    lea  rsi, [rel term_blank_glyph]
    call term_blit_mono8x16
    sub  r8d, 8
    jmp  .marks
.wide:
    call term_blit_mono16x16
    jmp  .marks
.narrow:
    call term_blit_mono8x16
.marks:
    ; Base/background has been painted ONCE. Marks only add foreground pixels.
    xor  r15d, r15d
.mark_next:
    cmp  r15d, VT_MARK_MAX
    jae  .mark_loss
    mov  edi, [r12 + VTC_MARKS + r15*4]
    test edi, edi
    jz   .mark_loss
    inc  r15d
    push rcx
    call term_mark_glyph                ; RSI bitmap, EAX 0(no shape)/1/2
    pop  rcx
    test eax, eax
    jz   .mark_next
    mov  edx, r14d
    and  edx, VTF_ITALIC                ; base already supplies UL/strike
    or   edx, TERM_BLIT_OVERLAY
    cmp  eax, 2
    jne  .mark_narrow
    cmp  byte [r12 + VTC_W], 2
    jne  .mark_missing                  ; never paint outside a narrow base
    call term_blit_mono16x16
    jmp  .mark_next
.mark_missing:
    lea  rsi, [rel term_mark_missing_glyph]
.mark_narrow:
    call term_blit_mono8x16
    jmp  .mark_next
.mark_loss:
    test r14d, VTF_MARK_LOSS
    jz   .done
    lea  rsi, [rel term_mark_loss_glyph]
    mov  edx, TERM_BLIT_OVERLAY
    call term_blit_mono8x16
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

;; Mn/Me overlay font. Selectors and CGJ retain their scalars without ink;
;; this renderer does not implement variation shaping or grapheme joining.
;; Other missing marks get a small top-right box, never a substituted accent.
;; Preserves EBX foreground and R8-R11. Lookup table uses original Unifont bits.
term_mark_glyph:
    cmp  edi, 0x034f
    je   .invisible
    cmp  edi, 0x180b
    jb   .vs
    cmp  edi, 0x180d
    jbe  .invisible
    cmp  edi, 0x180f
    je   .invisible
.vs:
    cmp  edi, 0xfe00
    jb   .supp
    cmp  edi, 0xfe0f
    jbe  .invisible
.supp:
    cmp  edi, 0xe0100
    jb   .lookup
    cmp  edi, 0xe01ef
    jbe  .invisible
.lookup:
    lea  rax, [rel vt_font_mark_cps]
    mov  ecx, [rel vt_font_mark_count]
    call term_bsearch
    cmp  eax, -1
    je   .missing
    lea  rsi, [rel vt_font_mark_widths]
    movzx edx, byte [rsi + rax]
    imul rax, rax, 32
    lea  rsi, [rel vt_font_mark_glyphs]
    add  rsi, rax
    mov  eax, edx
    ret
.missing:
    lea  rsi, [rel term_mark_missing_glyph]
    mov  eax, 1
    ret
.invisible:
    xor  eax, eax
    ret

;; term_resolve_colour(EDI = cell colour, ESI = default rgb, EDX = flags) -> EAX rgb
;; Bold draws palette colours 0-7 as their bright variants (xterm boldColors,
;; Windows Terminal "bright"). Preserves everything but RAX/RDI.
term_resolve_colour:
    test edi, edi
    jnz  .set
    mov  eax, esi
    ret
.set:
    mov  eax, edi
    shr  eax, 24
    cmp  eax, 2
    je   .rgb
    and  edi, 0xff
    test edx, VTF_BOLD
    jz   .pal
    cmp  edi, 8
    jae  .pal
    add  edi, 8
.pal:
    push rcx
    push rdx
    push rsi
    push r8
    push r9
    push r10
    push r11
    call vt_palette_rgb
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdx
    pop  rcx
    ret
.rgb:
    mov  eax, edi
    and  eax, 0xffffff
    ret

;; term_glyph(EDI = cp, ESI = cell width, EDX = bold) -> RSI bitmap, EAX 1/2.
;; Clobbers RAX, RCX, RDX, RDI.
term_glyph:
    cmp  esi, 2
    jne  .narrow
    cmp  edi, 0x20
    jbe  .narrow                        ; blank/control cells never acquire a missing-glyph box
    cmp  edi, 0x7f
    jb   .wide_lookup
    cmp  edi, 0x9f
    jbe  .narrow                        ; DEL/C1 retain the existing narrow replacement path
.wide_lookup:
    lea  rax, [rel vt_font_wide_cps]
    mov  ecx, [rel vt_font_wide_count]
    call term_bsearch
    cmp  eax, -1
    je   .wide_missing
    shl  eax, 5
    lea  rsi, [rel vt_font_wide_glyphs]
    add  rsi, rax
    mov  eax, 2
    ret
.wide_missing:
    call ime_glyph                     ; existing embedded 16x16 subset, same MSB-first row layout
    test rax, rax
    jnz  .wide_fallback
    lea  rax, [rel term_wide_box_glyph]  ; honest visible degradation, still occupies two cells
.wide_fallback:
    mov  rsi, rax
    mov  eax, 2
    ret
.narrow:
    cmp  edi, 0x20
    ja   .ink
    lea  rsi, [rel term_blank_glyph]
    mov  eax, 1
    ret
.ink:
    test edx, edx
    jz   .regular
    lea  rax, [rel vt_font_bold_cps]
    mov  ecx, [rel vt_font_bold_count]
    call term_bsearch
    cmp  eax, -1
    je   .regular
    shl  eax, 4
    lea  rsi, [rel vt_font_bold_glyphs]
    add  rsi, rax
    mov  eax, 1
    ret
.regular:
    cmp  edi, 0x7e
    ja   .search
    lea  eax, [edi - 0x20]              ; ASCII is the table's contiguous head
    jmp  .have
.search:
    lea  rax, [rel vt_font_cps]
    mov  ecx, [rel vt_font_count]
    call term_bsearch
    cmp  eax, -1
    jne  .have
    mov  eax, [rel term_fffd_index]
.have:
    shl  eax, 4
    lea  rsi, [rel vt_font_glyphs]
    add  rsi, rax
    mov  eax, 1
    ret

;; term_bsearch(RAX = sorted u32 table, ECX = count, EDI = key) -> EAX index or -1.
;; Clobbers RCX, RDX; preserves EDI.
term_bsearch:
    push rbx
    mov  rbx, rax
    xor  edx, edx
.l:
    cmp  edx, ecx
    jae  .none
    lea  eax, [edx + ecx]
    shr  eax, 1
    cmp  edi, [rbx + rax*4]
    je   .hit
    jb   .left
    lea  edx, [eax + 1]
    jmp  .l
.left:
    mov  ecx, eax
    jmp  .l
.hit:
    pop  rbx
    ret
.none:
    mov  eax, -1
    pop  rbx
    ret

;; ---------------------------------------------------------------------------
;; terminal_app_tick: reap closed windows, SSH lifecycle + window-change,
;; cursor blink, repaint of what changed.
terminal_app_tick:
    push rbx
    push r12
%ifdef PAOS_TERMINAL_SSH
    call term_ssh_deadlines_tick        ; expiry is independent of paint/visibility
    call ssh_sessions_poll              ; 0014: queued sends, keepalives, ended sessions draining
%endif
    call time_monotonic_now_us
    xor  edx, edx
    mov  ecx, 530000                    ; xterm/Windows Terminal ~530 ms blink
    div  rcx
    xor  eax, 1
    and  eax, 1
    mov  [rel term_blink_now], al
    xor  ebx, ebx
.inst:
    cmp  ebx, TERM_MAX
    jae  .out
    mov  edi, ebx
    call term_inst_ptr
    mov  r12, rax
    test r12, r12
    jz   .out                           ; no table: no instance to tick
    cmp  byte [r12 + TI_USED], 1
    jne  .next
    mov  ecx, [r12 + TI_WIN]
    lea  rdx, [rel wm_title]
    lea  rax, [r12 + TI_NAME]
    cmp  [rdx + rcx*8], rax
    jne  .gone                          ; closed (and perhaps reused) since we opened it
    lea  rdx, [rel wm_state]
    mov  eax, [rdx + rcx*4]
    cmp  eax, WM_VISIBLE
    je   .alive
    cmp  eax, WM_MIN
    je   .parked
    cmp  eax, LOCK_HIDDEN               ; RCQ-22: hidden by a session lock, not closed --
    je   .parked                        ; no paint or user-input drain while parked
.gone:
    call term_release                   ; the user closed the window
    jmp  .next
.parked:
    cmp  eax, LOCK_HIDDEN
    jne  .parked_input
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .guest_lock_done
    call term_guest_leave               ; lock revokes attachment and unsent input
.guest_lock_done:
%endif
    call term_ssh_lookup_lock           ; local cancellation, never cancel shared DNS
%ifdef PAOS_TERMINAL_SSH
    call term_ssh_exec_lock             ; an exec's unsent stdin/control cannot outlive lock
%endif
.parked_input:
    cmp  byte [r12 + TI_SSH], 1
    jne  .next
    call term_flush_replies             ; internal query replies retry without new RX
    jmp  .next
.alive:
    call term_refit
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .guest_tick_done
    call term_guest_tick
.guest_tick_done:
%endif
    call term_title_sync
    call term_ssh_lookup_notice
    cmp  byte [r12 + TI_SSH], 2
    jne  .not_resolving
    call term_ssh_resolving_tick
    jmp  .paint
.not_resolving:
    cmp  byte [r12 + TI_SSH], 1
    jne  .paint
    call term_ssh_caller_expire         ; poll may have crossed a caller deadline
    cmp  byte [r12 + TI_SSH], 1
    jne  .paint
    call term_paste_drain               ; a long paste continues as the channel drains
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use                ; the client state below is this window's
    call term_ssh_observation_tick
    cmp  byte [rel ssh_cli_chan_closed], 1
    je   .closed
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .failed
    cmp  byte [rel ssh_cli_chan_ready], 1
    je   .winch
    call time_monotonic_now_us
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_TCP
    jne  .dial_budget
    cmp  rax, [r12 + TI_NEXTTRY]        ; the TCP handshake gets 10 s (catalogue SSH-08)
    jb   .ceiling_pending
    lea  rsi, [rel term_ssh_tcp_timeout]
    mov  edi, 1
    jmp  .detach_msg
.dial_budget:
    cmp  rax, [r12 + TI_DEADLINE]
    jb   .ceiling_pending
%ifdef PAOS_TERMINAL_SSH
    call ssh_cli_exec_pending
    test eax, eax
    jz   .ordinary_timeout
    lea  rsi, [rel term_ssh_exec_timeout_text]
    mov  edi, 2
    jmp  .detach_msg                     ; accepted command may have run without its ACK
.ordinary_timeout:
%endif
    lea  rsi, [rel term_ssh_timeout]
    mov  edi, 2
    jmp  .detach_msg
.failed:
    call term_ssh_fail_text
    mov  edi, 3
    jmp  .detach_msg
.closed:
    cmp  byte [rel ssh_cli_error], 0
    jne  .failed                        ; unknown failure codes are never clean exit0
%ifdef PAOS_TERMINAL_SSH
    cmp  dword [rel ssh_cli_request_failures], 0
    jne  .paint
    cmp  byte [rel ssh_cli_want_close], 1
    je   .paint                         ; ordered replies/echo must drain before teardown
%endif
    call term_ssh_completion_text        ; snapshot before detach wipes session outcome
    mov  edi, 5
.detach_msg:
    push rsi
    call term_ssh_observation_reason
    call term_ssh_detach
    call term_session_reset             ; leave the remote's alt screen/modes first
    pop  rsi
    call term_out_cstr
    call term_prompt
    jmp  .paint
.ceiling_pending:                       ; this pass tested the ceiling: not yet reached
    mov  rdi, rax
    call term_ssh_observation_pass
    jmp  .paint
.winch:
%ifdef PAOS_TERMINAL_SSH
    call ssh_cli_is_exec
    test eax, eax
    jnz  .paint                         ; no PTY resize/focus reports or stdin in exec mode
%endif
    call term_flush_replies             ; preserve whole replies across queue backpressure
    call term_focus_report
    mov  edi, [r12 + TI_COLS]
    mov  esi, [r12 + TI_ROWS]
    cmp  edi, [r12 + TI_WCOLS]
    jne  .send_winch
    cmp  esi, [r12 + TI_WROWS]
    je   .paint
.send_winch:
    call ssh_cli_send_window_change
    test eax, eax
    jnz  .paint                         ; channel not ready yet: retry next tick
    mov  eax, [r12 + TI_COLS]
    mov  [r12 + TI_WCOLS], eax
    mov  eax, [r12 + TI_ROWS]
    mov  [r12 + TI_WROWS], eax
.paint:
    call term_repaint_changes
.next:
    inc  ebx
    jmp  .inst
.out:
    pop  r12
    pop  rbx
    ret

;; Service existing attached callers before any SSH idle polling. Do not let a
;; minimized/lock-hidden window turn its dial into an unbounded pending caller.
;; This is a finite scan of native instances, not a wall-clock scheduler bound.
;; The original loaded session is restored; no visibility/input grant changes.
term_ssh_deadlines_tick:
%ifdef PAOS_TERMINAL_SSH
    push rbx
    push r12
    mov  eax, [rel ssh_sess_active]
    push rax
    xor  ebx, ebx
.each:
    mov  edi, ebx
    call term_inst_ptr
    mov  r12, rax
    test r12, r12
    jz   .done
    call term_ssh_caller_expire
    inc  ebx
    cmp  ebx, TERM_MAX
    jb   .each
.done:
    pop  rdi
    cmp  edi, TERM_MAX
    jae  .park
    call ssh_session_use
    jmp  .out
.park:
    call ssh_sess_park
.out:
    pop  r12
    pop  rbx
%endif
    ret

;; R12 live native instance. Reuse the actual 10/20s tests and detach hooks;
;; never clamp the actual clock or claim asynchronous transport retirement.
;; Failure/close/ready retain their original causes in the ordinary tick. No
;; remote input, window-change or query reply is sent by this service.
term_ssh_caller_expire:
%ifdef PAOS_TERMINAL_SSH
    cmp  byte [r12 + TI_USED], 1
    jne  .out
    cmp  byte [r12 + TI_SSH], 1
    jne  .out
    ; A closed/reused WM slot keeps the original release/cancel path, rather
    ; than being relabelled as an expired live window by this early pass.
    mov  ecx, [r12 + TI_WIN]
    cmp  ecx, 64
    jae  .out
    lea  rdx, [rel wm_title]
    lea  rax, [r12 + TI_NAME]
    cmp  [rdx + rcx*8], rax
    jne  .out
    lea  rdx, [rel wm_state]
    mov  eax, [rdx + rcx*4]
    cmp  eax, WM_VISIBLE
    je   .session
    cmp  eax, WM_MIN
    je   .session
    cmp  eax, LOCK_HIDDEN
    jne  .out
.session:
    mov  edi, [r12 + TI_SESS]
    cmp  edi, TERM_MAX
    jae  .out
    call ssh_session_use
    cmp  byte [rel ssh_cli_chan_closed], 1
    je   .out
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .out
    cmp  byte [rel ssh_cli_chan_ready], 1
    je   .out
    call term_ssh_observation_tick
    call time_monotonic_now_us
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_TCP
    jne  .channel
    cmp  rax, [r12 + TI_NEXTTRY]
    jb   .ceiling_pending
    lea  rsi, [rel term_ssh_tcp_timeout]
    mov  edi, 1
    jmp  .detach
.channel:
    cmp  rax, [r12 + TI_DEADLINE]
    jb   .ceiling_pending
    lea  rsi, [rel term_ssh_timeout]
    mov  edi, 2
    push rsi
    push rdi
    call ssh_cli_exec_pending
    pop  rdi
    pop  rsi
    test eax, eax
    jz   .detach
    lea  rsi, [rel term_ssh_exec_timeout_text]
.detach:
    push rsi
    call term_ssh_observation_reason
    call term_ssh_detach
    call term_session_reset
    pop  rsi
    call term_out_cstr
    call term_prompt
    jmp  .out
.ceiling_pending:                       ; this pass tested the ceiling: not yet reached
    mov  rdi, rax
    call term_ssh_observation_pass
.out:
%endif
    ret

;; term_repaint_changes(R12): paint when the VT, cursor or blink phase changed.
;; The top-most window paints its dirty rows directly (nothing covers it);
;; otherwise the one z-ordered compositor repaints the desktop.
term_repaint_changes:
    call term_view_anchor
    mov  rax, [r12 + TI_VT]
    mov  rcx, [rax + VT.dirty]
    or   rcx, [rax + VT.dirty + 8]
    mov  dl, [rel term_blink_now]
    cmp  dl, [r12 + TI_BLINK]
    je   .no_blink
    cmp  byte [rel dpms_blanked], 1     ; RCQ-27 L3: a blanked screen shows no blink
    je   .no_blink
    push rax
    call wmx_paint_top_slot             ; preserves RCX/RDX
    cmp  eax, [r12 + TI_WIN]
    pop  rax
    jne  .no_blink                      ; RCQ-27 L3: only the top terminal blinks (a covered one
    mov  [r12 + TI_BLINK], dl           ; would cost a full-desktop composite per phase)
    or   rcx, 1
.no_blink:
    mov  edx, [r12 + TI_VIEWOFF]
    cmp  edx, [r12 + TI_VIEWDRAWN]
    jne  .changed                       ; the view scrolled
    mov  edx, [rax + VT.cx]
    cmp  edx, [r12 + TI_CURX]
    jne  .changed
    mov  edx, [rax + VT.cy]
    cmp  edx, [r12 + TI_CURY]
    jne  .changed
    test rcx, rcx
    jnz  .changed
    ret
.changed:
    cmp  byte [rel calendar_open], 1
    je   .composite                   ; repaint the panel above Terminal output/blink
    call wmx_paint_top_slot             ; RCQ-16 F5-R1 L1: the window painted last
    cmp  eax, [r12 + TI_WIN]
    jne  .composite
    call ps2_cursor_hide
    CADENCE_BATCH_BEGIN                 ; hub: one present for the whole repaint
    xor  esi, esi
    call term_paint
    CADENCE_BATCH_END
    call ps2_cursor_show
    ret
.composite:
    jmp  wmx_draw_all

term_release:
%ifdef PAOS_TERMINAL_GUEST
    call term_guest_forget
%endif
    call term_ssh_lookup_invalidate
    call term_paste_retire              ; this window's pending bytes cannot survive reuse
    call term_draft_forget              ; exact window companion, registers preserved
    push rdi
    call term_taint_rec
    call keyprov_line_clear
    pop  rdi
    mov  byte [r12 + TI_USED], 0
    mov  byte [r12 + TI_CONFIRM], 0     ; a y/N left pending never outlives its window
    cmp  byte [r12 + TI_SSH], 2
    jne  .not_resolving
    mov  byte [r12 + TI_SSH], 0
.not_resolving:
    cmp  byte [r12 + TI_SSH], 1
    jne  .out
    call term_ssh_detach                ; ends the session: the remote shell ends with its window
.out:
    call term_ssh_observation_forget
    ret

;; term_view_anchor(R12): a scrolled-back view stays on the same history lines
;; while new ones are saved (Windows Terminal); the alternate screen has none.
term_view_anchor:
    mov  rax, [r12 + TI_VT]
    mov  ecx, [rax + VT.sb_total]
    mov  edx, ecx
    sub  edx, [r12 + TI_SBSEEN]
    mov  [r12 + TI_SBSEEN], ecx
    mov  rcx, [rax + VT.modes]
    bt   rcx, VTM_ALT
    jc   .live
    cmp  dword [r12 + TI_VIEWOFF], 0
    je   .out
    add  edx, [r12 + TI_VIEWOFF]
    cmp  edx, [rax + VT.sb_count]
    jbe  .set
    mov  edx, [rax + VT.sb_count]
.set:
    mov  [r12 + TI_VIEWOFF], edx
.out:
    ret
.live:
    mov  dword [r12 + TI_VIEWOFF], 0
    ret

;; term_view_key(R12, R13D = GUI key, R14D = VT mods) -> EAX 1 when the key
;; scrolled the view (Shift+PgUp/PgDn page, Ctrl+Shift+Up/Down line). Any other
;; key returns the view to the live screen first.
term_view_key:
    mov  rax, [r12 + TI_VT]
    mov  rcx, [rax + VT.modes]
    bt   rcx, VTM_ALT
    jc   .other
    mov  edx, [rax + VT.rows]
    dec  edx                            ; a page keeps one line of context
    cmp  r14d, 1                        ; Shift alone
    jne  .ctrl_shift
    cmp  r13d, GUI_KEY_PGUP
    je   .up
    cmp  r13d, GUI_KEY_PGDN
    je   .down
    jmp  .other
.ctrl_shift:
    cmp  r14d, 5                        ; Shift + Ctrl
    jne  .other
    mov  edx, 1
    cmp  r13d, GUI_KEY_UP
    je   .up
    cmp  r13d, GUI_KEY_DOWN
    je   .down
    jmp  .other
.up:
    add  edx, [r12 + TI_VIEWOFF]
    cmp  edx, [rax + VT.sb_count]
    jbe  .set
    mov  edx, [rax + VT.sb_count]
    jmp  .set
.down:
    mov  ecx, [r12 + TI_VIEWOFF]
    sub  ecx, edx
    jns  .down_ok
    xor  ecx, ecx
.down_ok:
    mov  edx, ecx
.set:
    mov  [r12 + TI_VIEWOFF], edx
    mov  eax, 1
    ret
.other:
    mov  dword [r12 + TI_VIEWOFF], 0
    xor  eax, eax
    ret

term_ssh_detach:
    call term_ssh_lookup_invalidate
    call term_paste_retire              ; a later session must not inherit pending input
    cmp  byte [r12 + TI_SSH], 1
    jne  .clear
    mov  edi, [r12 + TI_SESS]
    call ssh_session_end                ; CHANNEL_CLOSE, drain, free (ssh_sessions_poll)
.clear:
    mov  byte [r12 + TI_SSH], 0
    mov  dword [r12 + TI_LINELEN], 0
    mov  dword [r12 + TI_LINEPOS], 0
    mov  dword [r12 + TI_SESS], -1
    call term_ssh_observation_detached
    ret

;; term_session_reset(R12) — 2026-09-29 (Peter eval 3: "[ssh session closed]"
;; was drawn over Claude's full-screen menu). When a remote session ends for any
;; reason, leave the alternate screen (DECRST 1049 restores the main screen and
;; cursor, as xterm does), then undo every mode the remote may have left set:
;; DECSTR soft reset (SGR, DECCKM, DECOM, IRM, DECKPAM, autowrap, cursor shown,
;; charsets, margins), mouse reporting, focus events, bracketed paste and the
;; cursor shape. The bytes go through term_out, so the capture ring replays them.
term_session_reset:
    mov  rax, [r12 + TI_VT]
    mov  dword [rax + VT.titlelen], 0   ; the remote's title leaves with it
    mov  rcx, [rax + VT.modes]
    bt   rcx, VTM_ALT
    jnc  .modes
    lea  rsi, [rel term_leave_alt]
    call term_out_cstr
.modes:
    lea  rsi, [rel term_mode_reset]
    call term_out_cstr
    ret

;; ---------------------------------------------------------------------------
;; terminal_key_hook(EDI = focused WM slot, EAX = GUI key) -> EAX 1 consumed.
;; Called by gui_input_route before any other key consumer.
terminal_key_hook:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, eax
    call terminal_find_window
    cmp  eax, -1
    je   .not_ours
    mov  edi, eax
    call term_inst_ptr
    mov  r12, rax
    cmp  r13d, GUI_KEY_TEXT
    je   .text
    ; router mods (bit0 shift, bit1 ctrl, bit2 alt) -> VT mods (shift, alt, ctrl)
    movzx eax, byte [rel input_kbd_mods]
    xor  r14d, r14d
    test eax, 1
    jz   .m1
    or   r14d, 1
.m1:
    test eax, 4
    jz   .m2
    or   r14d, 2
.m2:
    test eax, 2
    jz   .m3
    or   r14d, 4
.m3:
    inc  qword [rel term_keys_routed]
    call term_clip_key                  ; Ctrl+Shift+C / Ctrl+C on a selection / Ctrl+Shift+V / Shift+Ins
    test eax, eax
    jnz  .consumed
    call term_view_key
    test eax, eax
    jnz  .consumed
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .guest_key_done
    call term_guest_key
    jmp .consumed
.guest_key_done:
%endif
    cmp  byte [r12 + TI_SSH], 2
    je   .consumed                      ; resolving the host: keys wait
    cmp  byte [r12 + TI_SSH], 1
    je   .remote
    mov  eax, r13d
    call term_local_key
    jmp  .consumed
.remote:
%ifdef PAOS_TERMINAL_SSH
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    call ssh_cli_is_exec
    test eax, eax
    jz   .shell_remote
    call term_ssh_exec_key
    jmp  .consumed
.shell_remote:
%endif
    xor  esi, esi                       ; TERM_SSH_KEY: SEC D1, before any byte
    call term_ssh_input_ok
    test eax, eax
    jz   .consumed                      ; dropped, never typed locally
    call term_encode_key                ; -> term_keybuf, EAX length
    test eax, eax
    jz   .consumed
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    ; An arrow/function/Alt key may encode several bytes. The byte queue drops
    ; overflow tails, so keep this key whole just like GUI_KEY_TEXT below.
    mov  edx, SSH_TXQ_CAP
    sub  edx, [rel ssh_cli_txq_len]
    jb   .consumed                      ; corrupt length must not wrap into room
    cmp  edx, eax
    jb   .consumed                      ; no encoded-key prefix sent
    lea  rdi, [rel term_keybuf]
    mov  esi, eax
    call ssh_cli_enqueue_input
    cmp  qword [r12 + TI_ECHO_T0], 0
    jne  .consumed                      ; an earlier key still waits for its echo
    call time_monotonic_now_us
    mov  [r12 + TI_ECHO_T0], rax
.consumed:
    mov  eax, 1
    jmp  .out
.text:
    ; RCQ-38 L4: text >= U+0080 (its UTF-8 in wgt_text_buf) types into the local
    ; line, or goes to a live SSH session whole after the SEC D1 gate judges the
    ; text event's own origin (rc-sec s1-s3: one refusal drops the whole payload,
    ; counted once). While the host resolves, text is dropped as keys are.
    inc  qword [rel term_keys_routed]
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .guest_text_done
    call term_guest_text
    jmp .consumed
.guest_text_done:
%endif
    cmp  byte [r12 + TI_SSH], 2
    je   .consumed                      ; resolving: text waits as keys do
    cmp  byte [r12 + TI_SSH], 1
    je   .text_remote
    xor  r14d, r14d                     ; no VT mods: text is never a chord
    mov  eax, r13d
    call term_local_key
    jmp  .consumed
.text_remote:
%ifdef PAOS_TERMINAL_SSH
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    call ssh_cli_is_exec
    test eax, eax
    jz   .shell_text
    lea  rdi, [rel wgt_text_buf]
    mov  esi, [rel wgt_text_len]
    call term_ssh_exec_text
    jmp  .consumed
.shell_text:
%endif
    xor  esi, esi                       ; TERM_SSH_KEY: SEC D1, before any byte of the text
    call term_ssh_input_ok
    test eax, eax
    jz   .consumed                      ; the whole text dropped, never typed locally
    mov  eax, [rel wgt_text_len]
    dec  eax
    cmp  eax, WGT_TEXT_CAP - 1
    jae  .consumed                      ; empty or longer than one payload
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    ; GUI_KEY_TEXT is one UTF-8 payload: the byte queue drops overflow tails,
    ; so admit the whole payload only after selecting this window's session.
    ; No poll/yield occurs between this check and enqueue on the GUI path.
    mov  eax, SSH_TXQ_CAP
    sub  eax, [rel ssh_cli_txq_len]
    jb   .text_full                    ; corrupt length must not wrap into room
    cmp  eax, [rel wgt_text_len]
    jb   .text_full
    lea  rdi, [rel wgt_text_buf]
    mov  esi, [rel wgt_text_len]
    call ssh_cli_enqueue_input          ; the exact UTF-8, once
    cmp  qword [r12 + TI_ECHO_T0], 0
    jne  .consumed                      ; an earlier send still waits for its echo
    call time_monotonic_now_us
    mov  [r12 + TI_ECHO_T0], rax
    jmp  .consumed
.text_full:
    inc  qword [rel term_text_refused]
    jmp  .consumed                      ; no prefix sent, no echo timer started
.not_ours:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; ---------------------------------------------------------------------------
;; 2026-09-29 (Peter's usage gate: copy/paste). Mouse selection over the
;; Terminal's cells (press, drag, release through the WM pointer capture), copy
;; with Ctrl+Shift+C (or Ctrl+C while a selection is shown, as Windows Terminal
;; does), paste with Ctrl+Shift+V or Shift+Insert (bracketed when the remote
;; asked for DECSET 2004; newlines are sent as CR). One clipboard is shared by
;; every Terminal window.

;; term_sel_order -> R8D/R9D start row/col, R10D/R11D end row/col (reading order)
term_sel_order:
    mov  r8d, [r12 + TI_SELAR]
    mov  r9d, [r12 + TI_SELAC]
    mov  r10d, [r12 + TI_SELBR]
    mov  r11d, [r12 + TI_SELBC]
    cmp  r8d, r10d
    jl   .ok
    jg   .swap
    cmp  r9d, r11d
    jle  .ok
.swap:
    xchg r8d, r10d
    xchg r9d, r11d
.ok:
    cmp  byte [r12 + TI_SEL], 0
    je   .done
    mov  rax, [r12 + TI_VT]
    mov  ecx, [rax + VT.rf_points + 124]
    cmp  r10d, [r12 + TI_SELAR]
    jne  .gap
    cmp  r11d, [r12 + TI_SELAC]
    jne  .gap
    mov  ecx, [rax + VT.rf_points + 92]
    cmp  r10d, [r12 + TI_SELBR]
    jne  .gap
    cmp  r11d, [r12 + TI_SELBC]
    jne  .gap
    or   ecx, [rax + VT.rf_points + 124]
.gap:
    test ecx, 1
    jz   .done
    dec  r11d                         ; exclusive boundary, including an empty last row
.done:
    ret

;; term_sel_contains(R12, EDI row, ESI col) -> EDX 1 when selected. Preserves R8-R11.
term_sel_contains:
    xor  edx, edx
    cmp  byte [r12 + TI_SEL], 0
    je   .out
    push r8
    push r9
    push r10
    push r11
    call term_sel_order
    cmp  edi, r8d
    jl   .no
    cmp  edi, r10d
    jg   .no
    cmp  edi, r8d
    jne  .after_start
    cmp  esi, r9d
    jl   .no
.after_start:
    cmp  edi, r10d
    jne  .yes
    cmp  esi, r11d
    jg   .no
.yes:
    mov  edx, 1
.no:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
.out:
    ret

;; term_sel_clear(R12): no selection; every row repaints
term_sel_clear:
    mov  byte [r12 + TI_SEL], 0
    push rax
    mov  rax, [r12 + TI_VT]
    mov  dword [rax + VT.rf_points + 92], 0
    mov  dword [rax + VT.rf_points + 124], 0
    mov  qword [rax + VT.dirty], -1
    mov  qword [rax + VT.dirty + 8], -1
    pop  rax
    mov  dword [r12 + TI_VIEWDRAWN], -1
    ret

;; terminal_pointer_capture(EDI widget, ESI x, EDX y, ECX 0 press / 1 drag /
;; 2 release / 3 buttonless motion, R8D button 0 left / 1 middle / 2 right) -> EAX 1 consumed. Bound
;; to the vt_view type by terminal_app_init (wgt_type_bind_capture, which also
;; opts in to middle/right); wm_pointer delivers the press, drag and release.
;; A middle/right press is taken only to report it to a remote that asked for
;; mouse events; otherwise it is declined (no selection, no scrollbar).
terminal_pointer_capture:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r8                             ; [rsp]: the button
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    call term_find_widget
    cmp  eax, -1
    je   .miss
    mov  edi, eax
    call term_inst_ptr
    mov  r12, rax
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  r15d, WGT_CAPTURE_MOTION
    je   .hover_grid
    cmp  dword [rsp], 0
    jne  .other_button                  ; middle/right: xterm reporting only
    ; the scrollbar (Peter 2026-09-30): a press on the thumb drags it, a press
    ; on the track pages; the drag owns its motion and release
    cmp  byte [r12 + TI_SBDRAG], 1
    je   .sb_dragging
    test r15d, r15d
    jnz  .grid
    call term_sb_metrics
    test eax, eax
    jz   .grid
    cmp  r13d, r8d
    jl   .grid
    mov  eax, r14d
    sub  eax, r9d                       ; y within the strip
    cmp  eax, ecx
    jl   .sb_page_up
    lea  esi, [rcx + rdx]
    cmp  eax, esi
    jge  .sb_page_down
    sub  eax, ecx
    mov  [r12 + TI_SBGRAB], eax
    mov  byte [r12 + TI_SBDRAG], 1
    jmp  .sb_changed
.sb_page_up:
    mov  rcx, [r12 + TI_VT]
    mov  eax, [rcx + VT.rows]
    dec  eax
    add  eax, [r12 + TI_VIEWOFF]
    cmp  eax, [rcx + VT.sb_count]
    jbe  .sb_set
    mov  eax, [rcx + VT.sb_count]
    jmp  .sb_set
.sb_page_down:
    mov  rcx, [r12 + TI_VT]
    mov  edx, [rcx + VT.rows]
    dec  edx
    mov  eax, [r12 + TI_VIEWOFF]
    sub  eax, edx
    jns  .sb_set
    xor  eax, eax
.sb_set:
    mov  [r12 + TI_VIEWOFF], eax
    inc  qword [rel term_sb_actions]
.sb_changed:
    mov  dword [r12 + TI_VIEWDRAWN], -1 ; repaint (thumb place and colour)
    jmp  .consumed
.sb_dragging:
    cmp  r15d, 2
    je   .sb_release
    call term_sb_metrics
    test eax, eax
    jz   .sb_release
    mov  eax, r14d
    sub  eax, r9d
    sub  eax, [r12 + TI_SBGRAB]         ; the thumb's new top
    mov  esi, r10d
    sub  esi, edx                       ; its travel
    test eax, eax
    jns  .sb_d1
    xor  eax, eax
.sb_d1:
    cmp  eax, esi
    jle  .sb_d2
    mov  eax, esi
.sb_d2:
    mov  rcx, [r12 + TI_VT]
    mov  ecx, [rcx + VT.sb_count]
    test esi, esi
    jz   .sb_changed                    ; the thumb fills the track: nothing to move
    imul eax, ecx
    xor  edx, edx
    div  esi                            ; lines above the view's top
    sub  ecx, eax
    jns  .sb_d3
    xor  ecx, ecx
.sb_d3:
    mov  [r12 + TI_VIEWOFF], ecx
    inc  qword [rel term_sb_actions]
    jmp  .sb_changed
.sb_release:
    mov  byte [r12 + TI_SBDRAG], 0
    jmp  .sb_changed
.hover_grid:
    ; A hover cannot use the drag clamp: the scrollbar and unused grid margin
    ; never become the last text cell. The kit already checked the widget rect.
    mov  eax, r13d
    sub  eax, [rbx + WGI_X]
    js   .miss
    mov  ecx, [r12 + TI_COLS]
    shl  ecx, 3
    cmp  eax, ecx
    jae  .miss
    mov  eax, r14d
    sub  eax, [rbx + WGI_Y]
    js   .miss
    mov  ecx, [r12 + TI_ROWS]
    shl  ecx, 4
    cmp  eax, ecx
    jae  .miss
.grid:
    ; pixel -> cell, clamped to the grid
    mov  eax, r13d
    sub  eax, [rbx + WGI_X]
    sar  eax, 3
    mov  ecx, [r12 + TI_COLS]
    dec  ecx
    call .clamp
    mov  r13d, eax
    mov  eax, r14d
    sub  eax, [rbx + WGI_Y]
    sar  eax, 4
    mov  ecx, [r12 + TI_ROWS]
    dec  ecx
    call .clamp
    mov  r14d, eax
    cmp  r15d, WGT_CAPTURE_MOTION
    je   .rep_hover
    ; xterm mouse reporting (catalogue TUI-10): a remote that set DECSET
    ; 1000/1002/1003 gets the button; Shift keeps local selection, as in
    ; Windows Terminal. A reported press owns its drag and release.
    test r15d, r15d
    jnz  .continuing
    mov  byte [r12 + TI_MREP], 0
    call term_mouse_wanted
    test eax, eax
    jz   .local_press
    cmp  byte [r12 + TI_SEL], 0
    je   .rep_press
    call term_sel_clear
.rep_press:
    mov  edi, [rsp]                     ; xterm Cb: 0 left, 1 middle, 2 right
    mov  ecx, 1
    call term_mouse_report_at
    test eax, eax                       ; SEC D1 nit (rc-input INFO-1): a refused
    jz   .consumed                      ; press holds no button for the remote
    mov  eax, [rsp]
    inc  eax
    mov  [r12 + TI_MREP], al            ; 1 + the reported button
    jmp  .consumed
.rep_hover:
    call term_mouse_wanted              ; attached SSH session, Shift stays local
    test eax, eax
    jz   .miss
    mov  rax, [r12 + TI_VT]
    test dword [rax + VT.modes], (1 << VTM_M1003)
    jz   .miss                          ; 1000/1002 never request buttonless motion
    cmp  r13d, [r12 + TI_MCOL]
    jne  .hover_report
    cmp  r14d, [r12 + TI_MROW]
    je   .consumed
.hover_report:
    mov  edi, 35                       ; motion (32) plus no button (3)
    mov  ecx, 1                        ; SGR motion ends with M, never release m
    call term_mouse_report_at          ; existing origin + atomic queue checks
    jmp  .out
.continuing:
    cmp  byte [r12 + TI_MREP], 0
    je   .local
    cmp  r15d, 2
    jne  .rep_drag
    movzx edi, byte [r12 + TI_MREP]
    dec  edi                            ; SGR releases name the button (classic: 3)
    mov  byte [r12 + TI_MREP], 0
    xor  ecx, ecx
    call term_mouse_report_at
    jmp  .consumed
.rep_drag:
    mov  rax, [r12 + TI_VT]
    mov  rax, [rax + VT.modes]
    test eax, (1 << VTM_M1002) | (1 << VTM_M1003)
    jz   .consumed
    cmp  r13d, [r12 + TI_MCOL]
    jne  .rep_motion
    cmp  r14d, [r12 + TI_MROW]
    je   .consumed                      ; same cell: xterm reports cell motion only
.rep_motion:
    movzx edi, byte [r12 + TI_MREP]
    add  edi, 32 - 1                    ; motion with that button held
    mov  ecx, 1
    call term_mouse_report_at
    jmp  .consumed
.local:
    cmp  r15d, 1
    je   .drag
    cmp  r15d, 2
    je   .release
.local_press:
    ; press: a new anchor (a plain click clears an old selection); a double
    ; click selects the word, a triple click the whole line (catalogue KBM-07)
    cmp  byte [r12 + TI_SEL], 0
    je   .multi
    call term_sel_clear
.multi:
    cmp  dword [rel wm_pointer_clicks], 2
    jb   .anchor
    call term_select_word_or_line
    jmp  .consumed
.anchor:
    mov  rax, [r12 + TI_VT]
    mov  dword [rax + VT.rf_points + 92], 0
    mov  dword [rax + VT.rf_points + 124], 0
    mov  [r12 + TI_SELAR], r14d
    mov  [r12 + TI_SELAC], r13d
    mov  [r12 + TI_SELBR], r14d
    mov  [r12 + TI_SELBC], r13d
    mov  byte [r12 + TI_SEL], 1
    jmp  .consumed
.drag:
    cmp  byte [r12 + TI_SEL], 1
    jne  .consumed
    cmp  dword [rel wm_pointer_clicks], 2
    jae  .consumed
    mov  [r12 + TI_SELBR], r14d
    mov  [r12 + TI_SELBC], r13d
    mov  rax, [r12 + TI_VT]
    mov  qword [rax + VT.dirty], -1
    mov  qword [rax + VT.dirty + 8], -1
    mov  dword [r12 + TI_VIEWDRAWN], -1
    jmp  .consumed
.release:
    cmp  byte [r12 + TI_SEL], 1
    jne  .consumed
    cmp  dword [rel wm_pointer_clicks], 2
    jae  .consumed                      ; the multi-click selection stands
    mov  [r12 + TI_SELBR], r14d
    mov  [r12 + TI_SELBC], r13d
    mov  eax, [r12 + TI_SELAR]
    cmp  eax, r14d
    jne  .made
    mov  eax, [r12 + TI_SELAC]
    cmp  eax, r13d
    jne  .made
    mov  byte [r12 + TI_SEL], 0         ; a click, not a selection
    jmp  .consumed
.made:
    mov  byte [r12 + TI_SEL], 2
    mov  rax, [r12 + TI_VT]
    mov  qword [rax + VT.dirty], -1
    mov  qword [rax + VT.dirty + 8], -1
    mov  dword [r12 + TI_VIEWDRAWN], -1
.other_button:
    ; the press is taken only when the remote wants mouse events; its drag and
    ; release follow the reported path above, never a local selection
    test r15d, r15d
    jnz  .other_follow
    call term_mouse_wanted
    test eax, eax
    jz   .miss
    jmp  .grid
.other_follow:
    cmp  byte [r12 + TI_MREP], 0
    je   .consumed
    jmp  .grid
.consumed:
    mov  eax, 1
    jmp  .out
.miss:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.clamp:                                 ; EAX into [0, ECX]
    test eax, eax
    jns  .c1
    xor  eax, eax
.c1:
    cmp  eax, ecx
    jle  .c2
    mov  eax, ecx
.c2:
    ret

;; term_mouse_wanted(R12) -> EAX 1 when mouse events go to the remote: an ssh
;; session whose program set DECSET 1000/1002/1003, and Shift is not held.
term_mouse_wanted:
    xor  eax, eax
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    je .remote
%endif
    cmp  byte [r12 + TI_SSH], 1
    jne  .out
.remote:
    test byte [rel input_kbd_mods], 1
    jnz  .out
    mov  rcx, [r12 + TI_VT]
    mov  rcx, [rcx + VT.modes]
    test ecx, (1 << VTM_M1000) | (1 << VTM_M1002) | (1 << VTM_M1003)
    jz   .out
    mov  eax, 1
.out:
    ret

;; term_mouse_report_at(R12, EDI button code (0 left, +32 motion, 64/65
;; wheel), R13D col, R14D row, ECX 1 press / 0 release): one xterm report,
;; SGR (DECSET 1006) or the classic ESC [ M form, with Alt/Ctrl modifiers.
;; -> EAX 1 sent, 0 refused by origin or queue capacity. Only a sent report moves the
;; drag dedupe cell (rc-input INFO-2).
term_mouse_report_at:
    push rbx
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .ssh_origin
    call term_guest_pointer_ok
    jmp .origin_checked
.ssh_origin:
%endif
    mov  esi, TERM_SSH_PTR              ; SEC D1: every report, whichever caller
    call term_ssh_input_ok
.origin_checked:
    test eax, eax
    jz   .refused
    movzx eax, byte [rel input_kbd_mods]
    test eax, 4
    jz   .no_alt
    or   edi, 8
.no_alt:
    test eax, 2
    jz   .no_ctrl
    or   edi, 16
.no_ctrl:
    lea  rbx, [rel term_mousebuf]
    mov  word [rbx], 0x5b1b             ; ESC [
    mov  rax, [r12 + TI_VT]
    mov  rax, [rax + VT.modes]
    bt   rax, VTM_M1006
    jc   .sgr
    test ecx, ecx
    jnz  .x_btn
    and  edi, ~3
    or   edi, 3                         ; classic release: button 3
.x_btn:
    mov  byte [rbx + 2], 'M'
    lea  eax, [rdi + 32]
    mov  [rbx + 3], al
    mov  eax, r13d
    add  eax, 33
    call .cap
    mov  [rbx + 4], al
    mov  eax, r14d
    add  eax, 33
    call .cap
    mov  [rbx + 5], al
    mov  esi, 6
    jmp  .send
.sgr:
    push rcx
    mov  byte [rbx + 2], '<'
    mov  esi, 3
    mov  eax, edi
    call .dec
    mov  byte [rbx + rsi], ';'
    inc  esi
    lea  eax, [r13 + 1]
    call .dec
    mov  byte [rbx + rsi], ';'
    inc  esi
    lea  eax, [r14 + 1]
    call .dec
    pop  rcx
    mov  al, 'm'
    test ecx, ecx
    jz   .sgr_end
    mov  al, 'M'
.sgr_end:
    mov  [rbx + rsi], al
    inc  esi
.send:
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .ssh_send
    mov ecx, esi
    mov rdx, rbx
    call term_guest_send
    test eax, eax
    jz .refused
    mov [r12 + TI_MCOL], r13d
    mov [r12 + TI_MROW], r14d
    inc qword [rel term_mouse_reports]
    jmp .refused
.ssh_send:
%endif
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    ; A mouse report is one escape sequence; never enqueue only its prefix.
    mov  eax, SSH_TXQ_CAP
    sub  eax, [rel ssh_cli_txq_len]
    jb   .full
    cmp  eax, esi
    jb   .full
    mov  [r12 + TI_MCOL], r13d
    mov  [r12 + TI_MROW], r14d
    inc  qword [rel term_mouse_reports]
    mov  rdi, rbx
    call ssh_cli_enqueue_input
    mov  eax, 1
    jmp  .refused
.full:
    xor  eax, eax                       ; caller must not latch an unsent press/drag
.refused:
    pop  rbx
    ret
.cap:                                   ; the classic form cannot say more than 255
    cmp  eax, 255
    jbe  .cap_ok
    mov  eax, 255
.cap_ok:
    ret
.dec:                                   ; EAX (< 100000) -> [RBX + RSI], ESI advanced
    push rdx
    push rcx
    push r8
    xor  r8d, r8d
    mov  ecx, 10
.dec_div:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    push rdx
    inc  r8d
    test eax, eax
    jnz  .dec_div
.dec_put:
    pop  rdx
    mov  [rbx + rsi], dl
    inc  esi
    dec  r8d
    jnz  .dec_put
    pop  r8
    pop  rcx
    pop  rdx
    ret

;; term_focus_report(R12): DECSET 1004 focus in/out, sent when the window's
;; focus changes while the remote asked for it.
term_focus_report:
    xor  eax, eax
    mov  ecx, [r12 + TI_WIN]
    cmp  ecx, [rel wm_focus]
    jne  .have
    mov  eax, 1
.have:
    cmp  al, [r12 + TI_FOCUS]
    je   .out
    mov  rcx, [r12 + TI_VT]
    mov  rcx, [rcx + VT.modes]
    bt   rcx, VTM_FOCUS
    jnc  .remember                      ; disabled mode still tracks current focus
    lea  rsi, [rel term_focus_out]
    test eax, eax
    jz   .send
    lea  rsi, [rel term_focus_in]
.send:
%ifdef PAOS_TERMINAL_GUEST
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .ssh_send
    push rax
    mov rdx, rsi
    mov ecx, 3
    call term_guest_try_send
    test eax, eax
    jz .defer
    pop rax
    jmp .remember
.ssh_send:
%endif
    push rax                           ; desired focus survives the byte enqueue
    push rsi
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    pop  rdi
    mov  ecx, SSH_TXQ_CAP
    sub  ecx, [rel ssh_cli_txq_len]
    jb   .defer
    cmp  ecx, 3
    jb   .defer                         ; no prefix, and retain the transition for retry
    mov  esi, 3
    call ssh_cli_enqueue_input
    pop  rax
.remember:
    mov  [r12 + TI_FOCUS], al
.out:
    ret
.defer:
    pop  rax
    ret

;; term_is_word_cell(RAX cell) -> ZF clear (EDX 1) when the cell belongs to a
;; word. Windows Terminal's default word delimiters end a word.
term_is_word_cell:
    mov  edx, [rax + VTC_CP]
    test edx, edx
    jz   .no
    cmp  edx, 0x2502
    je   .no
    cmp  edx, 0x80
    jae  .yes
    push rdi
    push rcx
    lea  rdi, [rel term_word_delims]
.scan:
    movzx ecx, byte [rdi]
    test ecx, ecx
    jz   .scan_yes
    cmp  ecx, edx
    je   .scan_no
    inc  rdi
    jmp  .scan
.scan_yes:
    pop  rcx
    pop  rdi
.yes:
    mov  edx, 1
    test edx, edx
    ret
.scan_no:
    pop  rcx
    pop  rdi
.no:
    xor  edx, edx
    test edx, edx
    ret

;; term_select_word_or_line(R12, R13D col, R14D row): wm_pointer_clicks 2
;; selects the word under the pointer, 3 the whole line; the selection is made
;; (TI_SEL 2) at once, ready for Ctrl+Shift+C.
term_select_word_or_line:
    mov  rax, [r12 + TI_VT]
    mov  dword [rax + VT.rf_points + 92], 0
    mov  dword [rax + VT.rf_points + 124], 0
    push rbx
    push r15
    mov  [r12 + TI_SELAR], r14d
    mov  [r12 + TI_SELBR], r14d
    cmp  dword [rel wm_pointer_clicks], 3
    jne  .word
    mov  dword [r12 + TI_SELAC], 0
    mov  eax, [r12 + TI_COLS]
    dec  eax
    mov  [r12 + TI_SELBC], eax
    jmp  .made
.word:
    mov  edi, r14d
    mov  esi, r13d
    call term_view_cell
    call term_is_word_cell
    jz   .single                        ; on a delimiter: that one cell
    mov  ebx, r13d
.left:
    test ebx, ebx
    jz   .left_done
    lea  esi, [rbx - 1]
    mov  edi, r14d
    call term_view_cell
    call term_is_word_cell
    jz   .left_done
    dec  ebx
    jmp  .left
.left_done:
    mov  [r12 + TI_SELAC], ebx
    mov  r15d, r13d
.right:
    lea  esi, [r15 + 1]
    cmp  esi, [r12 + TI_COLS]
    jae  .right_done
    mov  edi, r14d
    call term_view_cell
    call term_is_word_cell
    jz   .right_done
    inc  r15d
    jmp  .right
.right_done:
    mov  [r12 + TI_SELBC], r15d
    jmp  .made
.single:
    mov  [r12 + TI_SELAC], r13d
    mov  [r12 + TI_SELBC], r13d
.made:
    mov  byte [r12 + TI_SEL], 2
    mov  rax, [r12 + TI_VT]
    mov  qword [rax + VT.dirty], -1
    mov  qword [rax + VT.dirty + 8], -1
    mov  dword [r12 + TI_VIEWDRAWN], -1
    pop  r15
    pop  rbx
    ret

;; terminal_wheel(EDI slot, ESI notches (+ up), EDX x, ECX y) -> EAX 1 when a
;; Terminal took it (catalogue TRM-04). A remote that asked for mouse reports
;; gets wheel buttons 64/65; a full-screen program without them gets three
;; arrow keys per notch (xterm/Windows Terminal alternate scroll); otherwise
;; the view scrolls three lines per notch through the scrollback, and typing
;; snaps it back (term_view_key).
terminal_wheel:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, esi
    mov  r13d, edx
    mov  r14d, ecx
    call terminal_find_window
    cmp  eax, -1
    je   .miss
    mov  edi, eax
    call term_inst_ptr
    mov  r12, rax
    inc  qword [rel term_wheel_events]
    ; pixel -> cell (clamped), for reports
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    mov  ecx, r13d
    sub  ecx, [rax + WGI_X]
    sar  ecx, 3
    mov  edx, r14d
    sub  edx, [rax + WGI_Y]
    sar  edx, 4
    mov  eax, ecx
    mov  ecx, [r12 + TI_COLS]
    dec  ecx
    call .clamp
    mov  r13d, eax
    mov  eax, edx
    mov  ecx, [r12 + TI_ROWS]
    dec  ecx
    call .clamp
    mov  r14d, eax
    mov  r15d, ebx                      ; notches left
    call term_mouse_wanted
    test eax, eax
    jnz  .report
    mov  rax, [r12 + TI_VT]
    mov  rcx, [rax + VT.modes]
    bt   rcx, VTM_ALT
    jnc  .scroll
    test byte [rel input_kbd_mods], 1
    jnz  .scroll
    cmp  byte [r12 + TI_SSH], 1
    je   .arrows
.scroll:
    mov  eax, ebx
    imul eax, eax, 3
    add  eax, [r12 + TI_VIEWOFF]
    jns  .not_below
    xor  eax, eax
.not_below:
    mov  rcx, [r12 + TI_VT]
    cmp  eax, [rcx + VT.sb_count]
    jbe  .set
    mov  eax, [rcx + VT.sb_count]
.set:
    mov  [r12 + TI_VIEWOFF], eax
    jmp  .consumed
.report:
    mov  edi, 64
    test r15d, r15d
    jg   .report_one
    mov  edi, 65
.report_one:
    mov  ecx, 1
    call term_mouse_report_at
    test r15d, r15d
    jg   .report_up
    inc  r15d
    jmp  .report_more
.report_up:
    dec  r15d
.report_more:
    jnz  .report
    jmp  .consumed
.arrows:
    mov  esi, TERM_SSH_PTR              ; SEC D1: once for the whole wheel event
    call term_ssh_input_ok
    test eax, eax
    jz   .consumed
    mov  r13d, GUI_KEY_UP
    mov  eax, r15d
    test eax, eax
    jg   .arrow_count
    mov  r13d, GUI_KEY_DOWN
    neg  eax
.arrow_count:
    lea  r15d, [rax + rax*2]
    xor  r14d, r14d                     ; no modifiers
.arrow:
    call term_encode_key                ; honours DECCKM (ESC O A in application mode)
    test eax, eax
    jz   .consumed
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    mov  edx, SSH_TXQ_CAP
    sub  edx, [rel ssh_cli_txq_len]
    jb   .consumed                      ; invalid queue length has no room
    cmp  edx, eax
    jb   .consumed                      ; wheel arrows must remain whole
    lea  rdi, [rel term_keybuf]
    mov  esi, eax
    call ssh_cli_enqueue_input
    dec  r15d
    jnz  .arrow
.consumed:
    mov  eax, 1
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
.clamp:                                 ; EAX into [0, ECX]
    test eax, eax
    jns  .c1
    xor  eax, eax
.c1:
    cmp  eax, ecx
    jle  .c2
    mov  eax, ecx
.c2:
    ret

;; term_view_cell(R12, EDI view row, ESI col) -> RAX cell (screen or scrollback)
term_view_cell:
    push r13
    mov  r13, [r12 + TI_VT]
    mov  eax, [r12 + TI_VIEWOFF]
    cmp  edi, eax
    jae  .live
    push rsi
    mov  esi, eax
    sub  esi, edi
    mov  rdi, r13
    call vt_scrollback_line
    pop  rsi
    test rax, rax
    jz   .live_row0
    imul rsi, rsi, VT_CELL
    add  rax, rsi
    jmp  .out
.live_row0:
    xor  edi, edi
.live:
    sub  edi, [r12 + TI_VIEWOFF]
    mov  edx, esi
    mov  esi, edi
    mov  rdi, r13
    call vt_cell_ptr
.out:
    pop  r13
    ret

;; term_copy_selection(R12) -> the selected text in term_clip (UTF-8, LF lines).
;; A row the VT engine marked as soft-wrapped (VTC_WRAP on its last cell) joins
;; the next row: no LF and no trimming of typed spaces, only never-written
;; padding (codepoint 0, e.g. before a wide glyph that wrapped) is dropped.
term_copy_selection:
    push rbx
    push r13
    push r14
    push r15
    sub  rsp, 8                         ; [rsp]: clip length after the row's last written glyph
    call term_sel_order
    push r8
    push r9
    push r10
    push r11
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    mov  [rel term_sel_r0], r8d
    mov  [rel term_sel_c0], r9d
    mov  [rel term_sel_r1], r10d
    mov  [rel term_sel_c1], r11d
    mov  dword [rel term_clip_truncated], 0
    xor  ebx, ebx                       ; clip length
    mov  r13d, r8d                      ; row
.row:
    cmp  r13d, [rel term_sel_r1]
    jg   .done
    xor  r14d, r14d                     ; first column of this row
    cmp  r13d, [rel term_sel_r0]
    jne  .have_first
    mov  r14d, [rel term_sel_c0]
.have_first:
    mov  r15d, [r12 + TI_COLS]
    dec  r15d                           ; last column of this row
    cmp  r13d, [rel term_sel_r1]
    jne  .have_last
    mov  r15d, [rel term_sel_c1]
.have_last:
    mov  [rel term_sel_linestart], ebx
    mov  [rsp], ebx
.col:
    cmp  r14d, r15d
    jg   .eol
    cmp  ebx, TERM_CLIP_MAX
    jae  .truncated
    mov  edi, r13d
    mov  esi, r14d
    call term_view_cell
    inc  r14d
    cmp  byte [rax + VTC_W], 0
    je   .col                           ; right half of a wide character
    call term_copy_cell                ; whole base + marks, or no partial cell
    test eax, eax
    jz   .truncated
    test edx, edx
    jz   .col
    mov  [rsp], ebx
    jmp  .col
.eol:
    cmp  r13d, [rel term_sel_r1]
    je   .trim                          ; the selection ends in this row
    mov  edi, r13d
    mov  esi, [r12 + TI_COLS]
    dec  esi
    call term_view_cell
    cmp  byte [rax + VTC_WRAP], 0
    je   .trim
    mov  ebx, [rsp]                     ; soft wrap: continue on the next row
    jmp  .next_row
    ; trailing blanks of a row are not text
.trim:
    cmp  ebx, [rel term_sel_linestart]
    jbe  .trimmed
    lea  rax, [rel term_clip]
    cmp  byte [rax + rbx - 1], ' '
    jne  .trimmed
    dec  ebx
    jmp  .trim
.trimmed:
    cmp  r13d, [rel term_sel_r1]
    je   .next_row
    cmp  ebx, TERM_CLIP_MAX
    jae  .truncated
    lea  rax, [rel term_clip]
    mov  byte [rax + rbx], 10
    inc  ebx
.next_row:
    inc  r13d
    jmp  .row
.truncated:
    mov  dword [rel term_clip_truncated], 1
.done:
    mov  [rel term_clip_len], ebx
    inc  dword [rel term_clip_copies]
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_copy_cell(RAX cell, EBX clip length) -> EAX 1 copied / 0 full,
;; EDX original base (0 padding); EBX updated. Preflights the complete sequence.
;; All other callee-saved and row/column registers are preserved.
term_copy_cell:
    push r12
    push r13
    push r14
    push r15
    mov  r12, rax
    mov  r14d, [r12 + VTC_CP]
    mov  eax, r14d
    test eax, eax
    jnz  .base
    mov  eax, ' '
.base:
    mov  r13d, eax
    call term_utf8_len
    mov  r15d, eax
    xor  edx, edx
.size:
    cmp  edx, VT_MARK_MAX
    jae  .check
    mov  eax, [r12 + VTC_MARKS + rdx*4]
    test eax, eax
    jz   .check
    call term_utf8_len
    add  r15d, eax
    inc  edx
    jmp  .size
.check:
    mov  eax, TERM_CLIP_MAX
    sub  eax, ebx
    jb   .full
    cmp  r15d, eax
    ja   .full
    lea  rdi, [rel term_clip]
    add  rdi, rbx
    mov  eax, r13d
    call term_utf8_put
    add  ebx, eax
    xor  r15d, r15d
.put:
    cmp  r15d, VT_MARK_MAX
    jae  .ok
    mov  eax, [r12 + VTC_MARKS + r15*4]
    test eax, eax
    jz   .ok
    lea  rdi, [rel term_clip]
    add  rdi, rbx
    call term_utf8_put
    add  ebx, eax
    inc  r15d
    jmp  .put
.ok:
    mov  eax, 1
    jmp  .out
.full:
    xor  eax, eax
.out:
    mov  edx, r14d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

;; UTF8 scalar length, same valid-scalar domain as the VT decoder; keeps EDX.
term_utf8_len:
    cmp  eax, 0x80
    jb   .one
    cmp  eax, 0x800
    jb   .two
    cmp  eax, 0x10000
    jb   .three
    mov  eax, 4
    ret
.three:
    mov  eax, 3
    ret
.two:
    mov  eax, 2
    ret
.one:
    mov  eax, 1
    ret

;; term_utf8_put(RDI dst, EAX codepoint) -> EAX bytes written (1..4)
term_utf8_put:
    cmp  eax, 0x80
    jae  .two
    mov  [rdi], al
    mov  eax, 1
    ret
.two:
    cmp  eax, 0x800
    jae  .three
    mov  ecx, eax
    shr  ecx, 6
    or   cl, 0xc0
    mov  [rdi], cl
    and  al, 0x3f
    or   al, 0x80
    mov  [rdi + 1], al
    mov  eax, 2
    ret
.three:
    cmp  eax, 0x10000
    jae  .four
    mov  ecx, eax
    shr  ecx, 12
    or   cl, 0xe0
    mov  [rdi], cl
    mov  ecx, eax
    shr  ecx, 6
    and  cl, 0x3f
    or   cl, 0x80
    mov  [rdi + 1], cl
    and  al, 0x3f
    or   al, 0x80
    mov  [rdi + 2], al
    mov  eax, 3
    ret
.four:
    mov  ecx, eax
    shr  ecx, 18
    or   cl, 0xf0
    mov  [rdi], cl
    mov  ecx, eax
    shr  ecx, 12
    and  cl, 0x3f
    or   cl, 0x80
    mov  [rdi + 1], cl
    mov  ecx, eax
    shr  ecx, 6
    and  cl, 0x3f
    or   cl, 0x80
    mov  [rdi + 2], cl
    and  al, 0x3f
    or   al, 0x80
    mov  [rdi + 3], al
    mov  eax, 4
    ret

;; term_paste(R12): the shared clipboard into this window's session or shell
term_paste:
    push rbx
    push r13
    mov  ebx, [rel term_clip_len]
    test ebx, ebx
    jz   .out
    inc  dword [rel term_clip_pastes]
%ifdef PAOS_TERMINAL_GUEST
    cmp  byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne  .not_guest
    call term_guest_paste
    jmp  .out
.not_guest:
%endif
    cmp  byte [r12 + TI_SSH], 1
    je   .remote
    cmp  byte [r12 + TI_SSH], 0
    jne  .out                           ; resolving: nothing to type into
    ; The local shell edits text; LF submits, CR retains its key semantics.
    ; RCQ-22 (security): a paste is typing, never an answer. Before every item
    ; it stops, dropping the rest, once a pasted line raised the y/N power
    ; question, closed this window (exit) or started ssh: those states take
    ; real keys only. The window's TI_USED at paste start is the reference.
    movzx eax, byte [r12 + TI_USED]
    push rax
    push rax
    xor  r13d, r13d
.local:
    cmp  r13d, ebx
    jae  .local_done
    cmp  byte [r12 + TI_CONFIRM], 0
    jne  .local_done
    movzx eax, byte [r12 + TI_USED]
    cmp  eax, [rsp]
    jne  .local_done                    ; released (exit) during this paste
    cmp  byte [r12 + TI_SSH], 0
    jne  .local_done
    lea  rax, [rel term_clip]
    movzx eax, byte [rax + r13]
    cmp  al, 0x20
    jb   .local_control
    cmp  al, 0x7f
    jne  .local_text
.local_control:
    inc  r13d
    cmp  al, 10
    jne  .local_key
    mov  eax, GUI_KEY_ENTER
.local_key:
    call term_local_key
    jmp  .local
.local_done:
    add  rsp, 16
    jmp  .out
.local_text:
    ; An ASCII byte followed by ASCII/control/end is already a whole cluster.
    ; Avoid rescanning the remaining 8 KiB clipboard for each such byte. Keep
    ; an ASCII base with following non-ASCII marks on the Unicode path below.
    cmp  al, 0x7f
    ja   .local_cluster
    lea  edx, [r13 + 1]
    cmp  edx, ebx
    jae  .local_ascii
    lea  rcx, [rel term_clip]
    cmp  byte [rcx + rdx], 0x80
    jae  .local_cluster
.local_ascii:
    mov  eax, 1
    jmp  .local_payload
.local_cluster:
    ; The key path accepts ASCII only. Send one complete UTF-8 grapheme through
    ; the existing text editor instead: its capacity, validation and caret rules
    ; apply to the whole cluster. The remaining clipboard is validated by the
    ; Unicode primitive; invalid text or a cluster beyond the text-event bound
    ; stops this paste without inserting a partial cluster.
    lea  rdi, [rel term_clip]
    add  rdi, r13
    mov  esi, ebx
    sub  esi, r13d
    xor  edx, edx
    call ue_grapheme_next
    test rax, rax
    jle  .local_refused
    cmp  rax, WGT_TEXT_CAP - 1
    ja   .local_refused
.local_payload:
    mov  [rel wgt_text_len], eax
    mov  ecx, eax
    lea  rsi, [rel term_clip]
    add  rsi, r13
    add  r13d, eax
    lea  rdi, [rel wgt_text_buf]
    cld
    rep  movsb
    mov  eax, GUI_KEY_TEXT
    call term_local_key
    jmp  .local                        ; check confirmation and lifetime again
.local_refused:
    inc  qword [rel term_text_refused]
    jmp  .local_done
.remote:
    xor  esi, esi                       ; SEC D1: the key chord that STARTS the
    call term_ssh_input_ok              ; paste (the drain runs on later ticks)
    test eax, eax
    jz   .out
    cmp  dword [rel term_paste_inst], -1
    jne  .out                           ; keep the admitted frame and lifetime intact
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    mov  rdi, [r12 + TI_VT]
    lea  rsi, [rel term_paste_buf]
    call vt_paste_prefix                ; ESC[200~ when the remote asked for it
    mov  r13d, eax
    xor  ecx, ecx
.copy:
    cmp  ecx, ebx
    jae  .copied
    lea  rax, [rel term_clip]
    movzx eax, byte [rax + rcx]
    cmp  al, 10
    jne  .byte
    mov  al, 13                         ; newlines are typed as Enter
.byte:
    lea  rdx, [rel term_paste_buf]
    mov  [rdx + r13], al
    inc  r13d
    inc  ecx
    jmp  .copy
.copied:
    mov  rdi, [r12 + TI_VT]
    lea  rsi, [rel term_paste_buf]
    add  rsi, r13
    call vt_paste_suffix
    add  r13d, eax
    ; the input ring holds 1 KiB: the rest follows as the channel drains
    mov  [rel term_paste_len], r13d
    mov  dword [rel term_paste_off], 0
    call term_inst_index
    mov  [rel term_paste_inst], eax
    lea  rdx, [rel term_paste_generations]
    mov  rdx, [rdx + rax*8]
    mov  [rel term_paste_generation], rdx
    mov  edx, [r12 + TI_SESS]
    mov  [rel term_paste_session], edx
    call term_paste_drain
.out:
    pop  r13
    pop  rbx
    ret

;; term_inst_index(R12) -> EAX instance index
term_inst_index:
    mov  rax, r12
    mov  rcx, [rel term_instances_ptr]   ; R12 came from the table, so it exists
    sub  rax, rcx
    xor  edx, edx
    mov  ecx, TI_SIZE
    div  rcx
    ret

;; term_paste_drain(R12): move the pending paste into this window's session
;; as the input ring has room (called by the paste and every tick).
term_paste_drain:
    call term_inst_index
    cmp  eax, [rel term_paste_inst]
    jne  .out
    cmp  byte [r12 + TI_USED], 1
    jne  .drop
    cmp  byte [r12 + TI_SSH], 1
    jne  .drop
    lea  rdx, [rel term_paste_generations]
    mov  rdx, [rdx + rax*8]
    cmp  rdx, [rel term_paste_generation]
    jne  .drop
    mov  edi, [r12 + TI_SESS]
    cmp  edi, [rel term_paste_session]
    jne  .drop
    call ssh_session_use
    mov  esi, SSH_TXQ_CAP
    sub  esi, [rel ssh_cli_txq_len]
    jle  .out
    mov  eax, [rel term_paste_len]
    sub  eax, [rel term_paste_off]
    cmp  esi, eax
    jbe  .n
    mov  esi, eax
.n:
    lea  rdi, [rel term_paste_buf]
    mov  eax, [rel term_paste_off]
    add  rdi, rax
    add  [rel term_paste_off], esi
    call ssh_cli_enqueue_input
    mov  eax, [rel term_paste_off]
    cmp  eax, [rel term_paste_len]
    jb   .out
.drop:
    jmp  term_paste_forget
.out:
    ret

;; A Terminal-local lifetime, separate from recyclable WM/widget/SSH indexes.
;; Retire before release, detach or a new dial; never reset on instance reuse.
;; Eagerly forgetting its paste and VT replies also makes generation wrap harmless.
term_paste_retire:
    call term_inst_index
    lea  rdx, [rel term_paste_generations]
    inc  qword [rdx + rax*8]
    push rax
    call term_reply_forget              ; the same window/session lifetime owns VT replies
    pop  rax
    cmp  eax, [rel term_paste_inst]
    jne  .out
    jmp  term_paste_forget
.out:
    ret

term_paste_forget:
    mov  dword [rel term_paste_inst], -1
    mov  dword [rel term_paste_session], -1
    mov  qword [rel term_paste_generation], 0
    mov  dword [rel term_paste_len], 0
    mov  dword [rel term_paste_off], 0
    ret

;; term_ssh_input_ok(R12, ESI = TERM_SSH_KEY / TERM_SSH_PTR) -> EAX 1 when an
;; input-driven send may go into this window's live SSH session. SEC D1 (root
;; 17:02:37, rc-sec e32148eb): the session is the owner's identity, so a byte
;; goes only for a HUMAN or in-image INTERNAL event or an owner-equivalent
;; injector, judged per event by keyprov_line_owner_equivalent: a key by its own
;; origin, an injected pointer event by the request in flight. Otherwise EAX 0:
;; the caller drops it (never typed locally); it is counted, and the first of a
;; burst writes one line in the window and one INJLINE surface=ssh row, never
;; the bytes. A burst ends at the next sent byte or 1 s after its line.
;; term_focus_report and term_flush_replies stay ungated (fixed bytes; census);
;; TERMFEED @RAW drops the replies to its own bytes before the flush (C1).
;; Preserves RCX, RSI, RDI and the callee-saved registers (the callers' live
;; state); clobbers RAX, RDX, R8-R11.
term_ssh_input_ok:
    push rcx
    push rsi
    push rdi
    lea  rdi, [rel term_ssh_taint]
    call keyprov_line_clear
    lea  rcx, [rel term_ssh_v_key]
    cmp  esi, TERM_SSH_EXEC_KEY
    je   .key
    test esi, esi
    jnz  .pointer
.key:
    call keyprov_line_note              ; the key's own origin (HUMAN, INTERNAL: clean)
    jmp  .judge
.pointer:
    lea  rcx, [rel term_ssh_v_pointer]
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    je   .judge
    call keyprov_frame_bind             ; the injecting request, as for an injected byte
.judge:
    call keyprov_line_owner_equivalent
    test eax, eax
    jz   .refused
%ifdef PAOS_TERMINAL_SSH
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    call ssh_cli_is_exec
    test eax, eax
    jz   .allowed
    cmp  dword [rsp + 8], TERM_SSH_EXEC_KEY
    jne  .quiet                         ; ordinary paste/pointer/VT input stays closed in exec
.allowed:
    mov  eax, 1
%endif
    mov  byte [rel term_ssh_burst], 0   ; a sent byte ends the burst
    jmp  .out
.refused:
    inc  qword [rel term_ssh_input_refused]
    push rcx
    call time_monotonic_now_us
    pop  rcx
    cmp  byte [rel term_ssh_burst], 0
    je   .mark
    mov  rdx, rax
    sub  rdx, [rel term_ssh_burst_t0]
    cmp  rdx, 1000000
    jb   .quiet
.mark:
    mov  byte [rel term_ssh_burst], 1
    mov  [rel term_ssh_burst_t0], rax
    push rcx
    lea  rsi, [rel term_ssh_inj_text]
    call term_out_cstr
    pop  rcx
    lea  rdi, [rel term_ssh_taint]
    call keyprov_refuse_ssh             ; the row names the kind, never bytes
.quiet:
    xor  eax, eax
.out:
    pop  rdi
    pop  rsi
    pop  rcx
    ret

;; term_clip_key(R12, R13D key, R14D VT mods) -> EAX 1 consumed
term_clip_key:
    cmp  r13d, 0x03                     ; Ctrl+C (the router folds Ctrl into C0)
    jne  .not_c
    test r14d, 1
    jnz  .copy                          ; Ctrl+Shift+C
    cmp  byte [r12 + TI_SEL], 2
    jne  .no                            ; plain Ctrl+C without a selection: ^C
.copy:
    cmp  byte [r12 + TI_SEL], 2
    jne  .yes                           ; nothing selected: Ctrl+Shift+C does nothing
    call term_copy_selection
    call term_sel_clear
    jmp  .yes
.not_c:
    cmp  r13d, 0x16                     ; Ctrl+V
    jne  .not_v
    test r14d, 1
    jz   .no                            ; plain Ctrl+V: the literal-next byte
    jmp  .paste
.not_v:
    cmp  r13d, GUI_KEY_INSERT
    jne  .no
    test r14d, 1
    jz   .no
.paste:
    call term_paste
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

;; term_encode_key(R12, R13D = GUI key, R14D = VT mods) -> term_keybuf, EAX len
term_encode_key:
    mov  eax, r13d
    cmp  eax, 0x100
    jb   .char
    lea  rcx, [rel term_key_map]
.scan:
    movzx edx, word [rcx]
    test edx, edx
    jz   .none
    cmp  edx, eax
    je   .hit
    add  rcx, 4
    jmp  .scan
.hit:
    movzx esi, word [rcx + 2]
    mov  rdi, [r12 + TI_VT]
    mov  edx, r14d
    lea  rcx, [rel term_keybuf]
    jmp  vt_key_encode
.char:
    ; the router already folded Ctrl+letter into C0 codes; Alt adds the ESC
    ; prefix and Ctrl maps the xterm punctuation (Ctrl+Space/@ NUL, [ ESC,
    ; \ ] ^ _ and / to 1C..1F, ? DEL)
    mov  esi, eax
    mov  edx, r14d
    and  edx, 6
    cmp  esi, '/'
    jne  .char_enc
    test edx, 4
    jz   .char_enc
    mov  esi, '_'
.char_enc:
    mov  rdi, [r12 + TI_VT]
    lea  rcx, [rel term_keybuf]
    jmp  vt_char_encode
.none:
    xor  eax, eax
    ret

;; term_local_key(R12, EAX = GUI key): local shell line editing
;; (catalogue TRM-03): insert/delete anywhere on the line, Left/Right, Home/End
;; (and Ctrl+A/E), Delete, Ctrl+U/K, Up/Down history, Tab completes the
;; built-in commands, Ctrl+C abandons the line, Ctrl+L clears the screen.
;; R14D carries existing VT modifier bits; Ctrl (bit2) adds word movement/erase.
;; ASCII word = maximal run of non-space printable bytes: punctuation is part
;; of a word. Left/backspace skip left spaces then word; right/delete skip
;; current word then following spaces. Clipboard printable bytes are unchanged.
term_local_key:
    push rdi                            ; GA0-K: every key the local line receives
    call term_taint_rec                 ; (Enter, editing, y/N, a paste's bytes)
    call keyprov_line_note              ; folds its origin into the window's taint
    pop  rdi
    cmp  byte [r12 + TI_CONFIRM], 0
    jne  term_confirm_key
    cmp  dword [r12 + TI_LINELEN], TERM_LINE_MAX
    ja   .ignore                       ; corrupt length/caret: no read/write/output
    mov  ecx, [r12 + TI_LINEPOS]
    cmp  ecx, [r12 + TI_LINELEN]
    ja   .ignore
    cmp  eax, GUI_KEY_TEXT
    je   .text
    cmp  eax, GUI_KEY_ENTER
    je   .enter
    cmp  eax, GUI_KEY_BACKSPACE
    je   .bs
    cmp  eax, GUI_KEY_LEFT
    je   .left
    cmp  eax, GUI_KEY_RIGHT
    je   .right
    cmp  eax, GUI_KEY_HOME
    je   .home
    cmp  eax, 0x01
    je   .home
    cmp  eax, GUI_KEY_END
    je   .end
    cmp  eax, 0x05
    je   .end
    cmp  eax, GUI_KEY_DELETE
    je   .del
    cmp  eax, GUI_KEY_UP
    je   .older
    cmp  eax, GUI_KEY_DOWN
    je   .newer
    cmp  eax, GUI_KEY_TAB
    je   .tab
    cmp  eax, 0x15
    je   .kill_line
    cmp  eax, 0x0b
    je   .kill_eol
    cmp  eax, 0x03
    je   .ctrl_c
    cmp  eax, 0x04
    je   .ctrl_d
    cmp  eax, 0x0c
    je   .ctrl_l
    cmp  eax, 0x20
    jb   .ignore
    cmp  eax, 0x7e
    ja   .ignore
    mov  ecx, [r12 + TI_LINELEN]
    cmp  ecx, TERM_LINE_MAX
    jae  .ignore
    mov  edx, [r12 + TI_LINEPOS]
    cmp  edx, ecx
    je   .append
    ; insert: shift [pos, len) right by one
.shift_r:
    cmp  ecx, edx
    jbe  .shifted_r
    mov  r8b, [r12 + TI_LINE + rcx - 1]
    mov  [r12 + TI_LINE + rcx], r8b
    dec  ecx
    jmp  .shift_r
.shifted_r:
    mov  [r12 + TI_LINE + rdx], al
    inc  dword [r12 + TI_LINELEN]
    inc  edx
    call term_caret_settle              ; RCQ-38 L4: before a combining mark, after its cluster
    jmp  term_line_redraw
.text:
    ; RCQ-38 L4: wgt_text_buf's UTF-8 goes in at the caret whole or not at all,
    ; as L3b's field takes it: empty, invalid, a control or no room is refused and
    ; counted, and the line is untouched.
    mov  ecx, [rel wgt_text_len]
    lea  eax, [rcx - 1]
    cmp  eax, WGT_TEXT_CAP - 1
    jae  .text_refused
    add  ecx, [r12 + TI_LINELEN]
    cmp  ecx, TERM_LINE_MAX
    ja   .text_refused
    lea  rdi, [rel wgt_text_buf]
    mov  esi, [rel wgt_text_len]
    call ue_utf8_validate               ; SysV: caller-saved clobbered
    test eax, eax
    jz   .text_refused
    lea  rsi, [rel wgt_text_buf]
    mov  ecx, [rel wgt_text_len]
    call wgt_utf8_controls              ; no C0, DEL or C1 control
    jnz  .text_refused
    mov  r8d, [rel wgt_text_len]
    mov  ecx, [r12 + TI_LINELEN]
    mov  edx, [r12 + TI_LINEPOS]
    mov  eax, ecx
.text_shift:                            ; [caret, len) right by the payload
    cmp  eax, edx
    jbe  .text_copy
    dec  eax
    mov  r9b, [r12 + TI_LINE + rax]
    lea  r10d, [rax + r8]
    mov  [r12 + TI_LINE + r10], r9b
    jmp  .text_shift
.text_copy:
    lea  rsi, [rel wgt_text_buf]
    xor  eax, eax
.text_byte:
    mov  r9b, [rsi + rax]
    lea  r10d, [rdx + rax]
    mov  [r12 + TI_LINE + r10], r9b
    inc  eax
    cmp  eax, r8d
    jb   .text_byte
    add  ecx, r8d
    add  edx, r8d
    mov  [r12 + TI_LINELEN], ecx
    cmp  edx, ecx
    jne  .text_mid
    mov  [r12 + TI_LINEPOS], edx        ; at the end: echo the payload as .append echoes a
    lea  rsi, [rel wgt_text_buf]        ; byte (the VT wraps it forward), no redraw
    xor  eax, eax
.text_echo:
    push rax
    push rsi
    movzx eax, byte [rsi + rax]
    call term_out_byte
    pop  rsi
    pop  rax
    inc  eax
    cmp  eax, [rel wgt_text_len]
    jb   .text_echo
    jmp  term_line_rows
.text_mid:
    call term_caret_settle
    jmp  term_line_redraw
.text_refused:
    inc  qword [rel term_text_refused]
    ret
.corrupt:
    ; RCQ-38 L4: the line is not UTF-8 or the caret is inside a cluster (never
    ; by typing): clear it visibly rather than edit bytes blind.
    inc  qword [rel term_line_corrupt]
    mov  dword [r12 + TI_LINELEN], 0
    mov  dword [r12 + TI_LINEPOS], 0
    mov  byte [r12 + TI_LINE], 0
    jmp  term_line_redraw
.append:
    mov  [r12 + TI_LINE + rcx], al
    inc  dword [r12 + TI_LINELEN]
    inc  dword [r12 + TI_LINEPOS]
    call term_out_byte
    jmp  term_line_rows                 ; RCQ-38 L4: the echo may have wrapped
.ctrl_d:
    ; RCQ-22 readline parity: Ctrl+D on an empty line ends the shell (the same
    ; path as 'exit'); on a non-empty line it deletes the character under the
    ; caret (never a word, although Ctrl is held), and at the end it does nothing.
    cmp  dword [r12 + TI_LINELEN], 0
    jne  .del_char
    mov  edi, [r12 + TI_WIN]
    call wmx_close_slot
    jmp  term_release
.bs:
    test r14d, 4
    jnz  .word_bs
    mov  edx, [r12 + TI_LINEPOS]
    test edx, edx
    jz   .ignore
    xor  r8d, r8d
    call term_step                      ; RCQ-38 L4: one grapheme cluster
    js   .corrupt
    mov  edx, [r12 + TI_LINEPOS]
    mov  ecx, edx
    sub  ecx, eax
    cmp  ecx, 1
    jne  .erase_cluster                 ; wider than one byte: [boundary, caret)
    cmp  edx, [r12 + TI_LINELEN]
    jne  .bs_mid
    call term_one_row                   ; RCQ-38 L4: BS SP BS cannot go back over a row edge
    dec  dword [r12 + TI_LINELEN]
    dec  dword [r12 + TI_LINEPOS]
    test eax, eax
    jnz  term_line_redraw
    lea  rsi, [rel term_bs_text]
    jmp  term_out_cstr
.bs_mid:
    dec  dword [r12 + TI_LINEPOS]
    dec  edx
    jmp  .remove_at
.erase_cluster:                         ; EAX = the boundary before the caret EDX
    mov  ecx, edx
    mov  edx, eax
    jmp  .erase_word
.del:
    test r14d, 4
    jnz  .word_del
.del_char:
    mov  edx, [r12 + TI_LINEPOS]
    cmp  edx, [r12 + TI_LINELEN]
    jae  .ignore
    mov  r8d, 1
    call term_step                      ; RCQ-38 L4: one grapheme cluster
    js   .corrupt
    mov  edx, [r12 + TI_LINEPOS]
    mov  ecx, eax
    sub  eax, edx
    cmp  eax, 1
    jne  .erase_word                    ; wider than one byte: [caret, boundary)
.remove_at:                             ; drop TI_LINE[edx], shift the tail left
    mov  ecx, [r12 + TI_LINELEN]
    dec  ecx
.shift_l:
    cmp  edx, ecx
    jae  .shifted_l
    mov  r8b, [r12 + TI_LINE + rdx + 1]
    mov  [r12 + TI_LINE + rdx], r8b
    inc  edx
    jmp  .shift_l
.shifted_l:
    mov  [r12 + TI_LINELEN], ecx
.joined:                                ; RCQ-38 L4: a removal can join its two neighbours
    mov  edx, [r12 + TI_LINEPOS]        ; into one cluster (GB6-GB9b); the caret goes to
    xor  r8d, r8d                       ; that cluster's start
    call term_snap
    mov  [r12 + TI_LINEPOS], edx
    jmp  term_line_redraw
.left:
    test r14d, 4
    jnz  .word_left
    cmp  dword [r12 + TI_LINEPOS], 0
    je   .ignore
    xor  r8d, r8d
    call term_step                      ; RCQ-38 L4: one grapheme cluster
    js   .corrupt
    mov  ecx, [r12 + TI_LINEPOS]
    mov  [r12 + TI_LINEPOS], eax
    sub  ecx, eax
    cmp  ecx, 1
    jne  term_caret_move                ; a wider cluster: placed by row and column
    call term_one_row
    test eax, eax
    jnz  term_caret_move                ; RCQ-38 L4: CUB1 stops at column 0
    lea  rsi, [rel term_cub1]
    jmp  term_out_cstr
.right:
    test r14d, 4
    jnz  .word_right
    mov  edx, [r12 + TI_LINEPOS]
    cmp  edx, [r12 + TI_LINELEN]
    jae  .ignore
    mov  r8d, 1
    call term_step                      ; RCQ-38 L4: one grapheme cluster
    js   .corrupt
    mov  ecx, eax
    sub  ecx, [r12 + TI_LINEPOS]
    mov  [r12 + TI_LINEPOS], eax
    cmp  ecx, 1
    jne  term_caret_move
    call term_one_row
    test eax, eax
    jnz  term_caret_move                ; RCQ-38 L4: CUF1 stops at the last column
    lea  rsi, [rel term_cuf1]
    jmp  term_out_cstr
.home:
    mov  dword [r12 + TI_LINEPOS], 0
    jmp  term_line_redraw
.end:
    mov  eax, [r12 + TI_LINELEN]
    mov  [r12 + TI_LINEPOS], eax
    jmp  term_line_redraw
.kill_line:
    mov  dword [r12 + TI_LINELEN], 0
    mov  dword [r12 + TI_LINEPOS], 0
    jmp  term_line_redraw
.kill_eol:
    mov  eax, [r12 + TI_LINEPOS]
    mov  [r12 + TI_LINELEN], eax
    jmp  term_line_redraw
.history_bounds:
    ; This entry is called only by the two browsing branches below.
    cmp  dword [r12 + TI_HISTN], TERM_HIST_N
    ja   .bad_history
    mov  ecx, [r12 + TI_HISTI]
    cmp  ecx, [r12 + TI_HISTN]
    ja   .bad_history
    clc
    ret
.bad_history:
    stc
    ret
.older:
    call .history_bounds
    jc   .ignore
    mov  eax, [r12 + TI_HISTI]
    cmp  eax, [r12 + TI_HISTN]
    jae  .ignore
    test eax, eax
    jnz  .next_old
    cmp  dword [r12 + TI_LINELEN], TD_TEXT_MAX
    ja   .ignore                       ; RCQ-38 L4: a line longer than a draft stays as typed
    call term_draft_get
    test rax, rax
    jz   .ignore                       ; bounded companion capacity exhausted
    mov  ecx, [r12 + TI_LINELEN]
    mov  [rax + TD_LEN], ecx
    mov  edx, [r12 + TI_LINEPOS]
    mov  [rax + TD_POS], edx
    xor  edx, edx
.save_draft:
    cmp  edx, ecx
    jae  .saved_draft
    mov  r8b, [r12 + TI_LINE + rdx]
    mov  [rax + TD_TEXT + rdx], r8b
    inc  edx
    jmp  .save_draft
.saved_draft:
    mov  byte [rax + TD_TEXT + rdx], 0
    mov  dword [rax + TD_VALID], 1
    xor  eax, eax
.next_old:
    inc  eax
    jmp  .recall
.newer:
    call .history_bounds
    jc   .ignore
    mov  eax, [r12 + TI_HISTI]
    test eax, eax
    jz   .ignore
    dec  eax
    jnz  .recall
    call term_draft_get
    test rax, rax
    jz   .ignore
    cmp  dword [rax + TD_VALID], 1
    jne  .ignore
    mov  ecx, [rax + TD_LEN]
    cmp  ecx, TD_TEXT_MAX
    ja   .ignore
    mov  edx, [rax + TD_POS]
    cmp  edx, ecx
    ja   .ignore
    mov  [r12 + TI_LINELEN], ecx
    mov  [r12 + TI_LINEPOS], edx
    xor  edx, edx
.restore_draft:
    cmp  edx, ecx
    jae  .restored_draft
    mov  r8b, [rax + TD_TEXT + rdx]
    mov  [r12 + TI_LINE + rdx], r8b
    inc  edx
    jmp  .restore_draft
.restored_draft:
    mov  byte [r12 + TI_LINE + rdx], 0
    mov  dword [r12 + TI_HISTI], 0
    call term_draft_forget
    jmp  term_line_redraw
.recall:
    mov  [r12 + TI_HISTI], eax
    xor  ecx, ecx
    dec  eax
    imul eax, eax, TERM_HIST_W
    lea  rsi, [r12 + TI_HIST]
    add  rsi, rax
.copy_hist:
    mov  r8b, [rsi + rcx]
    test r8b, r8b
    jz   .recalled
    mov  [r12 + TI_LINE + rcx], r8b
    inc  ecx
    cmp  ecx, TERM_HIST_W - 1
    jb   .copy_hist
.recalled:
    mov  [r12 + TI_LINELEN], ecx
    mov  [r12 + TI_LINEPOS], ecx
    jmp  term_line_redraw
.word_left:
    call term_word_left
    xor  r8d, r8d
    call term_snap                      ; RCQ-38 L4: never inside a cluster
    mov  [r12 + TI_LINEPOS], edx
    jmp  term_line_redraw
.word_right:
    call term_word_right
    mov  r8d, 1
    call term_snap
    mov  [r12 + TI_LINEPOS], edx
    jmp  term_line_redraw
.word_bs:
    call term_word_left
    xor  r8d, r8d
    call term_snap
    mov  ecx, [r12 + TI_LINEPOS]
    jmp  .erase_word
.word_del:
    call term_word_right
    mov  r8d, 1
    call term_snap
    mov  ecx, edx
    mov  edx, [r12 + TI_LINEPOS]
.erase_word:                            ; remove validated [edx,ecx), once
    mov  r9d, ecx
    sub  r9d, edx
    jz   .ignore
    mov  [r12 + TI_LINEPOS], edx
    mov  r10d, [r12 + TI_LINELEN]
.erase_tail:
    cmp  ecx, r10d
    jae  .erased_word
    mov  r8b, [r12 + TI_LINE + rcx]
    mov  [r12 + TI_LINE + rdx], r8b
    inc  ecx
    inc  edx
    jmp  .erase_tail
.erased_word:
    sub  r10d, r9d
    mov  [r12 + TI_LINELEN], r10d
    mov  byte [r12 + TI_LINE + r10], 0
    jmp  .joined
.tab:
    call term_complete
    ret
.ctrl_c:
    call term_draft_forget
    push rdi
    call term_taint_rec                 ; an abandoned line takes its taint with it
    call keyprov_line_clear
    pop  rdi
    mov  dword [r12 + TI_LINELEN], 0
    mov  dword [r12 + TI_LINEPOS], 0
    mov  dword [r12 + TI_HISTI], 0
    lea  rsi, [rel term_ctrl_c_text]
    call term_out_cstr
    jmp  term_prompt
.ctrl_l:
    lea  rsi, [rel term_clear_text]
    call term_out_cstr
    mov  dword [r12 + TI_EDROW], 0      ; RCQ-38 L4: the clear homed the cursor, nothing
    mov  dword [r12 + TI_EDEND], 0      ; of the line is left on screen
    jmp  term_line_redraw
.enter:
    call term_draft_forget
    call term_taint_latch               ; GA0-K: this line's taint goes with it
    lea  rsi, [rel term_crlf]
    call term_out_cstr
    mov  ecx, [r12 + TI_LINELEN]
    mov  byte [r12 + TI_LINE + rcx], 0
    call term_hist_add
    mov  dword [r12 + TI_LINELEN], 0
    mov  dword [r12 + TI_LINEPOS], 0
    mov  dword [r12 + TI_HISTI], 0
    jmp  term_execute_line
.ignore:
    ret

;; term_line_redraw(R12): redraw the local line, caret at TI_LINEPOS.
;; RCQ-38 L4: a line can be longer than a row and the VT has no reverse wrap (CR
;; stays on the cursor's row, CUB stops at column 0). While the old and the new
;; line both end on the prompt's row it sends the bytes it always did: CR, the
;; prompt, the line, EL, CUB1 per cell after the caret. Otherwise it goes up
;; TI_EDROW rows to the prompt's row, CR, erases to the end of the screen (a
;; shorter line leaves no stale row; erasing first keeps a deferred wrap at the
;; line's end, which a CSI after it would drop), prints the prompt and the line,
;; and places the caret by row and column (term_caret_goto).
term_line_redraw:
    push rbx
    push r13
    push r14
    mov  edx, [r12 + TI_LINELEN]
    call term_line_at                   ; the new line's end
    mov  r13d, eax                      ; its row
    mov  r14d, ecx                      ; its column
    or   eax, edx                       ; a row below, or a wrap waiting on the last column
    or   eax, [r12 + TI_EDEND]          ; or the drawn line reaches below the prompt's row
    jnz  .rows
    lea  rsi, [rel term_cr]
    call term_out_cstr
    call term_prompt
    call term_line_out
    lea  rsi, [rel term_el]
    call term_out_cstr
    mov  edx, [r12 + TI_LINEPOS]
    call term_line_at
    mov  ebx, r14d
    sub  ebx, ecx                       ; cells after the caret
.back:
    test ebx, ebx
    jz   .out
    lea  rsi, [rel term_cub1]
    call term_out_cstr
    dec  ebx
    jmp  .back
.rows:
    mov  eax, [r12 + TI_EDROW]
    test eax, eax
    jz   .prompt_row
    mov  dl, 'A'
    call term_csi_n                     ; up to the prompt's row
.prompt_row:
    lea  rsi, [rel term_cr]
    call term_out_cstr
    lea  rsi, [rel term_ed]
    call term_out_cstr
    call term_prompt
    call term_line_out
    mov  [r12 + TI_EDROW], r13d
    mov  [r12 + TI_EDEND], r13d
    mov  edx, [r12 + TI_LINEPOS]
    cmp  edx, [r12 + TI_LINELEN]
    jae  .out                           ; the caret is the cursor after the line
    call term_line_at
    test edx, edx
    jnz  .out                           ; only zero-width scalars follow: the same cursor
    call term_caret_goto
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_line_out(R12): the line's TI_LINELEN bytes to the terminal. Keeps RBX.
term_line_out:
    push rbx
    xor  ebx, ebx
.byte:
    cmp  ebx, [r12 + TI_LINELEN]
    jae  .out
    movzx eax, byte [r12 + TI_LINE + rbx]
    call term_out_byte
    inc  ebx
    jmp  .byte
.out:
    pop  rbx
    ret

;; term_line_rows(R12): after an echo at the line's end, the cursor's row is the
;; line's last row (RCQ-38 L4). Clobbers caller-saved.
term_line_rows:
    mov  edx, [r12 + TI_LINELEN]
    call term_line_at
    mov  [r12 + TI_EDROW], eax
    mov  [r12 + TI_EDEND], eax
    ret

;; term_one_row(R12) -> EAX = 0 when the drawn line ends on the prompt's row
;; with no wrap waiting there (CUB1, CUF1 and BS SP BS stay inside the row),
;; else nonzero. RCQ-38 L4. Clobbers caller-saved.
term_one_row:
    mov  eax, [r12 + TI_EDEND]
    test eax, eax
    jnz  .out
    sub  rsp, 8
    mov  edx, [r12 + TI_LINELEN]
    call term_line_at
    add  rsp, 8
    or   eax, edx
.out:
    ret

;; term_caret_move(R12): the drawn line is unchanged; put the cursor on
;; TI_LINEPOS by row and column. A caret at the end of a line whose last glyph
;; filled the row waits for a deferred wrap no CSI can recreate: redraw then.
;; RCQ-38 L4. Clobbers caller-saved.
term_caret_move:
    sub  rsp, 8
    mov  edx, [r12 + TI_LINEPOS]
    call term_line_at
    add  rsp, 8
    test edx, edx
    jnz  term_line_redraw
    jmp  term_caret_goto

;; term_caret_goto(R12, EAX = row, ECX = column): CUU/CUD from TI_EDROW to the
;; row, CHA to the column; TI_EDROW = the row. RCQ-38 L4. Keeps RBX.
term_caret_goto:
    push rbx
    push r13
    push r14
    mov  r13d, eax
    mov  r14d, ecx
    sub  eax, [r12 + TI_EDROW]
    jz   .column
    mov  dl, 'B'
    jg   .vertical
    neg  eax
    mov  dl, 'A'
.vertical:
    call term_csi_n
.column:
    lea  eax, [r14 + 1]
    mov  dl, 'G'
    call term_csi_n
    mov  [r12 + TI_EDROW], r13d
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_csi_n(R12, EAX = n >= 1, DL = final byte): ESC [ n final. RCQ-38 L4.
term_csi_n:
    push rbx
    sub  rsp, 32                        ; ESC [ up to ten digits, final, NUL
    lea  rbx, [rsp + 30]
    mov  byte [rbx + 1], 0
    mov  [rbx], dl
    mov  ecx, 10
.digit:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    dec  rbx
    mov  [rbx], dl
    test eax, eax
    jnz  .digit
    mov  byte [rbx - 1], '['
    mov  byte [rbx - 2], 0x1b
    lea  rsi, [rbx - 2]
    call term_out_cstr
    add  rsp, 32
    pop  rbx
    ret

;; term_line_at(R12, EDX = byte offset) -> EAX row, ECX column of the first
;; glyph at or after the offset as the VT places it (rows from the prompt's
;; row; the prompt starts at column 0 and takes TERM_PROMPT_CELLS), EDX 0; when
;; no glyph follows, the cursor after the whole line and EDX = 1 if a wrap waits
;; on its last column. Mirrors vt_print_cp: a deferred wrap, a wide glyph that
;; does not fit the last column wraps it blank, a zero-width scalar takes no
;; cell, widths from vt_wcwidth (the VT's own table, not ue_cell_width).
;; RCQ-38 L4. Keeps RBX and R12-R15; clobbers caller-saved.
term_line_at:
    push rbx
    push r13
    push r14
    push r15
    sub  rsp, 24                        ; {scalar, bytes} of ue_utf8_decode; +8 wrap waits; +12 columns
    mov  r13d, edx
    xor  r14d, r14d                     ; column
    xor  r15d, r15d                     ; row
    mov  dword [rsp + 8], 0
    mov  eax, [r12 + TI_COLS]
    test eax, eax
    jnz  .columns
    inc  eax
.columns:
    mov  [rsp + 12], eax
    mov  ebx, -TERM_PROMPT_CELLS        ; the prompt's cells, then the line's bytes
.next:
    mov  dword [rsp + 4], 1             ; bytes this step takes
    test ebx, ebx
    js   .one_cell
    cmp  ebx, [r12 + TI_LINELEN]
    jae  .cursor
    cmp  byte [r12 + TI_LINE + rbx], 0x80
    jb   .one_cell                      ; printable ASCII (the line holds no controls)
    lea  rdi, [r12 + TI_LINE]
    mov  esi, [r12 + TI_LINELEN]
    mov  edx, ebx
    mov  rcx, rsp
    call ue_utf8_decode
    cmp  eax, 1
    jne  .one_byte                      ; undecodable: one byte, one cell (never by typing)
    mov  edi, [rsp]
    call vt_wcwidth
    test eax, eax
    jz   .step                          ; zero width: the VT neither stores nor advances
    jmp  .place
.one_byte:
    mov  dword [rsp + 4], 1
.one_cell:
    mov  eax, 1
.place:                                 ; EAX = 1 or 2 cells
    cmp  dword [rsp + 8], 0
    je   .no_wait
    mov  dword [rsp + 8], 0             ; the waiting wrap happens
    xor  r14d, r14d
    inc  r15d
.no_wait:
    cmp  eax, 2
    jne  .placed
    lea  ecx, [r14 + 1]
    cmp  ecx, [rsp + 12]
    jl   .placed
    xor  r14d, r14d                     ; wide on the last column: blank it, wrap
    inc  r15d
.placed:
    test ebx, ebx
    js   .advance
    cmp  ebx, r13d
    jae  .glyph                         ; the first glyph at or after the offset
.advance:
    add  r14d, eax
    cmp  r14d, [rsp + 12]
    jl   .step
    mov  r14d, [rsp + 12]
    dec  r14d                           ; on the last column the wrap waits
    mov  dword [rsp + 8], 1
.step:
    test ebx, ebx
    js   .prompt_step
    add  ebx, [rsp + 4]
    jmp  .next
.prompt_step:
    inc  ebx
    jmp  .next
.glyph:
    xor  edx, edx
    jmp  .out
.cursor:
    mov  edx, [rsp + 8]
.out:
    mov  eax, r15d
    mov  ecx, r14d
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_step(R12, R8D = 0 previous / 1 next) -> EAX = the grapheme boundary
;; before / after TI_LINEPOS, SF set (EAX -1) when TI_LINE is not UTF-8 or the
;; caret is inside a cluster. RCQ-38 L4. Clobbers caller-saved (SysV callee).
term_step:
    lea  rdi, [r12 + TI_LINE]
    mov  esi, [r12 + TI_LINELEN]
    mov  edx, [r12 + TI_LINEPOS]
    test r8d, r8d
    jnz  .next
    call ue_grapheme_prev
    jmp  .out
.next:
    call ue_grapheme_next
.out:
    test eax, eax
    ret

;; term_snap(R12, EDX = offset, R8D = 0 down / 1 up) -> EDX = the grapheme
;; boundary at or before (down) / at or after (up) the offset; unchanged when
;; TI_LINE is not UTF-8 (the next cluster step then clears it). Walks from 0
;; (<= TERM_LINE_MAX bytes). RCQ-38 L4. Keeps RBX and R12-R15.
term_snap:
    push rbx
    push r13
    push r14
    push r15
    mov  r13d, edx                      ; the offset
    mov  r14d, r8d
    test edx, edx
    jz   .keep                          ; the start
    cmp  edx, [r12 + TI_LINELEN]
    jae  .keep                          ; the end (a caret is never past it here)
    cmp  byte [r12 + TI_LINE + rdx - 1], 0x80
    jae  .walk_from_0
    cmp  byte [r12 + TI_LINE + rdx], 0x80
    jb   .keep                          ; between two ASCII bytes: always a boundary
.walk_from_0:
    xor  ebx, ebx                       ; a boundary (0 always is)
    xor  r15d, r15d                     ; the last boundary at or before the offset
.walk:
    cmp  ebx, r13d
    ja   .past
    mov  r15d, ebx
    je   .keep                          ; the offset is a boundary
    lea  rdi, [r12 + TI_LINE]
    mov  esi, [r12 + TI_LINELEN]
    mov  edx, ebx
    call ue_grapheme_next
    test eax, eax
    js   .keep                          ; not UTF-8: leave it
    cmp  eax, ebx
    je   .end                           ; the end of the line
    mov  ebx, eax
    jmp  .walk
.past:
    mov  edx, r15d
    test r14d, r14d
    jz   .out
    mov  edx, ebx
    jmp  .out
.end:
    mov  edx, ebx
    jmp  .out
.keep:
    mov  edx, r13d
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_caret_settle(R12, EDX = the caret after an insert) -> TI_LINEPOS: the
;; boundary at or after EDX (an insert before a combining mark joins its
;; cluster, a Prepend scalar joins what follows it). RCQ-38 L4. Clobbers
;; caller-saved.
term_caret_settle:
    mov  r8d, 1
    call term_snap
    mov  [r12 + TI_LINEPOS], edx
    ret

;; term_word_left/right: validated TI line/caret -> EDX boundary. Leaf,
;; bounded to TERM_LINE_MAX; punctuation remains in non-space ASCII words.
term_word_left:
    mov  edx, [r12 + TI_LINEPOS]
.spaces:
    test edx, edx
    jz   .out
    cmp  byte [r12 + TI_LINE + rdx - 1], ' '
    jne  .word
    dec  edx
    jmp  .spaces
.word:
    test edx, edx
    jz   .out
    cmp  byte [r12 + TI_LINE + rdx - 1], ' '
    je   .out
    dec  edx
    jmp  .word
.out:
    ret
term_word_right:
    mov  edx, [r12 + TI_LINEPOS]
    mov  ecx, [r12 + TI_LINELEN]
.word:
    cmp  edx, ecx
    jae  .out
    cmp  byte [r12 + TI_LINE + rdx], ' '
    je   .spaces
    inc  edx
    jmp  .word
.spaces:
    cmp  edx, ecx
    jae  .out
    cmp  byte [r12 + TI_LINE + rdx], ' '
    jne  .out
    inc  edx
    jmp  .spaces
.out:
    ret

;; Private fixed companion store keyed by the actual instance pointer. At most
;; TERM_MAX live windows; no TI layout change, heap, history-slot reuse or disk.
;; get -> RAX record or0; clobbers RAX/RCX/RDX. Valid drafts never evicted.
term_draft_get:
    lea  rdx, [rel term_drafts]
    mov  ecx, TERM_MAX
.find:
    cmp  [rdx], r12
    je   .hit
    add  rdx, TD_SIZE
    loop .find
    lea  rdx, [rel term_drafts]
    mov  ecx, TERM_MAX
.free:
    cmp  qword [rdx], 0
    je   .claim
    add  rdx, TD_SIZE
    loop .free
    xor  eax, eax
    ret
.claim:
    mov  [rdx], r12
.hit:
    mov  rax, rdx
    ret
;; Forget on return to draft, Enter, Ctrl+C, open/reopen and release. Preserve
;; all registers: callers' command/key/SSH arguments are unchanged.
term_draft_forget:
    push rax
    push rcx
    push rdx
    push rdi
    lea  rdi, [rel term_drafts]
    mov  ecx, TERM_MAX
.find:
    cmp  [rdi], r12
    je   .wipe
    add  rdi, TD_SIZE
    loop .find
    jmp  .out
.wipe:
    xor  eax, eax
    mov  ecx, TD_SIZE
    cld
    rep  stosb
.out:
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rax
    ret

;; term_hist_add(R12): remember the NUL-terminated TI_LINE (non-blank, not a
;; repeat of the newest entry), newest first
term_hist_add:
    cmp  dword [r12 + TI_LINELEN], 0
    je   .out
    cmp  dword [r12 + TI_LINELEN], TERM_HIST_W - 1
    jbe  .classify
    inc  qword [rel term_hist_skipped]  ; too long to keep whole, so not kept
    ret
.classify:
    ; Dispatch folds native names to upper case. Classify that same name before
    ; retaining raw arguments, without changing the editor's original line.
    ; Unknown names fail closed; the declared local shell words keep recall.
    push rbx
    sub  rsp, CONS_CLASS_VERB_MAX
    lea  rsi, [r12 + TI_LINE]
    mov  ecx, TERM_HIST_W
.lead:
    test ecx, ecx
    jz   .unsafe
    mov  al, [rsi]
    cmp  al, ' '
    je   .skip
    cmp  al, '/'
    jne  .verb
.skip:
    inc  rsi
    dec  ecx
    jmp  .lead
.verb:
    mov  edx, ecx
    xor  ecx, ecx
.token:
    cmp  ecx, edx
    jae  .unsafe
    mov  al, [rsi + rcx]
    test al, al
    jz   .token_end
    cmp  al, ' '
    je   .token_end
    jb   .unsafe
    cmp  ecx, CONS_CLASS_VERB_MAX - 1
    jae  .unsafe
    cmp  al, 'a'
    jb   .put
    cmp  al, 'z'
    ja   .put
    sub  al, 32
.put:
    mov  [rsp + rcx], al
    inc  ecx
    jmp  .token
.token_end:
    mov  byte [rsp + rcx], 0
    mov  rdi, rsp
    call cons_line_class
    cmp  eax, CONS_CLASS_SAFE
    je   .safe
    cmp  rdx, 1                         ; only unknown names may be local words
    jne  .unsafe
    lea  rbx, [rel term_complete_words]
.local_word:
    cmp  byte [rbx], 0
    je   .unsafe
    mov  rdi, rsp
    mov  rsi, rbx
    call term_word_eq
    test eax, eax
    jnz  .safe
.next_word:
    inc  rbx
    cmp  byte [rbx - 1], 0
    jne  .next_word
    jmp  .local_word
.unsafe:
    xor  eax, eax
    jmp  .checked
.safe:
    mov  eax, 1
.checked:
    add  rsp, CONS_CLASS_VERB_MAX
    pop  rbx
    test eax, eax
    jz   .out
.length:
.fits:
    cmp  dword [r12 + TI_HISTN], 0
    je   .push
    lea  rdi, [r12 + TI_LINE]
    lea  rsi, [r12 + TI_HIST]
    call strcmp
    test rax, rax
    jz   .out
.push:
    ; slide entries 0..N-2 down one (the oldest falls off)
    mov  ecx, TERM_HIST_N - 1
.slide:
    test ecx, ecx
    jz   .store
    mov  eax, ecx
    dec  eax
    imul eax, eax, TERM_HIST_W
    lea  rsi, [r12 + TI_HIST]
    add  rsi, rax
    lea  rdi, [rsi + TERM_HIST_W]
    push rcx
    mov  ecx, TERM_HIST_W
    cld
    rep  movsb
    pop  rcx
    dec  ecx
    jmp  .slide
.store:
    lea  rdi, [r12 + TI_HIST]
    lea  rsi, [r12 + TI_LINE]
    mov  ecx, TERM_HIST_W - 1
.copy:
    mov  al, [rsi]
    mov  [rdi], al
    test al, al
    jz   .count
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .copy
    mov  byte [rdi], 0
.count:
    cmp  dword [r12 + TI_HISTN], TERM_HIST_N
    jae  .out
    inc  dword [r12 + TI_HISTN]
.out:
    ret

;; term_hist_print(R12): read-only local history, oldest first. Even damaged
;; counts/slots cannot reach the next field or another window. Control bytes
;; are shown as '?' rather than fed to VT; bytes >= 0x80 are shown as typed only
;; when the entry is valid UTF-8 without a control (RCQ-38 L4), else as '?'.
term_hist_print:
    push rbx
    push r13
    push r14
    push r15
    mov  ebx, [r12 + TI_HISTN]
    cmp  ebx, TERM_HIST_N
    jbe  .entry
    mov  ebx, TERM_HIST_N
.entry:
    test ebx, ebx
    jz   .out
    dec  ebx
    imul eax, ebx, TERM_HIST_W
    lea  r13, [r12 + TI_HIST]
    add  r13, rax
    xor  ecx, ecx
.len:
    cmp  ecx, TERM_HIST_W - 1
    jae  .measured
    cmp  byte [r13 + rcx], 0
    je   .measured
    inc  ecx
    jmp  .len
.measured:
    push rcx
    mov  rdi, r13
    mov  esi, ecx
    call ue_utf8_validate               ; SysV
    pop  rcx
    mov  r15d, eax
    test eax, eax
    jz   .scan
    mov  rsi, r13
    call wgt_utf8_controls
    jz   .scan
    xor  r15d, r15d
.scan:
    xor  r14d, r14d
.byte:
    cmp  r14d, TERM_HIST_W - 1
    jae  .newline
    mov  al, [r13 + r14]
    test al, al
    jz   .newline
    cmp  al, 0x20
    jb   .unsafe
    cmp  al, 0x7f
    jb   .emit
    je   .unsafe
    test r15d, r15d
    jnz  .emit
.unsafe:
    mov  al, '?'
.emit:
    call term_out_byte
    inc  r14d
    jmp  .byte
.newline:
    lea  rsi, [rel term_crlf]
    call term_out_cstr
    jmp  .entry
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_complete(R12): complete one local command word from the shell words
;; and the live shared registry. ASCII case-insensitive, unique across both;
;; duplicate spellings (e.g. help / HELP) are one candidate. Never completes
;; arguments, dispatches, grants authority, or handles SSH/guest input. The
;; command task owns registry publication/retirement; no cache survives Tab.
term_complete:
    push rbx
    push r13
    push r14
    push r15
    sub  rsp, 8
    cmp  byte [r12 + TI_SSH], 0
    jne  .out                          ; SSH, DNS and guest bytes have another owner
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out                          ; no local edit while locked
    mov  eax, [r12 + TI_LINEPOS]
    cmp  eax, [r12 + TI_LINELEN]
    jne  .out
    test eax, eax
    jz   .out
    cmp  eax, TERM_LINE_MAX - 1
    jae  .out                          ; need a whole name, space and NUL
    call command_verb_count
    cmp  eax, VERB_MAX
    ja   .out                          ; malformed census never indexes the table
    mov  [rsp], eax                    ; one bounded registry census for this Tab
    xor  r13d, r13d                    ; unique candidate pointer
    xor  r15d, r15d                    ; candidate length
    lea  rbx, [rel term_complete_words]
.word:
    cmp  byte [rbx], 0
    je   .registry
    call .candidate
    test eax, eax
    jz   .out                          ; two different names: leave line intact
.skip:
    inc  rbx
    cmp  byte [rbx - 1], 0
    jne  .skip
    jmp  .word
.registry:
    xor  r14d, r14d
.verb:
    cmp  r14d, [rsp]
    jae  .decide
    mov  edi, r14d
    call command_verb_name             ; empty for a retired slot
    mov  rbx, rax
    call .candidate
    test eax, eax
    jz   .out
    inc  r14d
    jmp  .verb
.decide:
    test r13, r13
    jz   .out
    mov  ecx, [r12 + TI_LINELEN]
.append:
    cmp  ecx, r15d
    jae  .space
    mov  al, [r13 + rcx]
    mov  [r12 + TI_LINE + rcx], al
    inc  ecx
    jmp  .append
.space:
    mov  byte [r12 + TI_LINE + rcx], ' '
    inc  ecx
    mov  byte [r12 + TI_LINE + rcx], 0
    mov  [r12 + TI_LINELEN], ecx
    mov  [r12 + TI_LINEPOS], ecx
    call term_line_redraw
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; RBX candidate -> EAX 1 continue, 0 ambiguous. Validate its complete bounded
; printable token before touching the editor; an overlong/malformed registry
; name cannot leave a partly appended command or inject VT control bytes.
.candidate:
    test rbx, rbx
    jz   .continue
    xor  r8d, r8d
.length:
    cmp  r8d, TERM_LINE_MAX - 1
    jae  .continue
    mov  al, [rbx + r8]
    test al, al
    jz   .bounded
    cmp  al, 33
    jb   .continue
    cmp  al, 126
    ja   .continue
    inc  r8d
    jmp  .length
.bounded:
    cmp  r8d, [r12 + TI_LINELEN]
    jb   .continue
    xor  ecx, ecx
.prefix:
    cmp  ecx, [r12 + TI_LINELEN]
    jae  .match
    mov  al, [rbx + rcx]
    call .fold
    mov  dl, al
    mov  al, [r12 + TI_LINE + rcx]
    call .fold
    cmp  al, dl
    jne  .continue
    inc  ecx
    jmp  .prefix
.match:
    test r13, r13
    jz   .first
    cmp  r8d, r15d
    jne  .ambiguous
    xor  ecx, ecx
.same:
    cmp  ecx, r8d
    jae  .continue                     ; same word on both surfaces counts once
    mov  al, [rbx + rcx]
    call .fold
    mov  dl, al
    mov  al, [r13 + rcx]
    call .fold
    cmp  al, dl
    jne  .ambiguous
    inc  ecx
    jmp  .same
.first:
    mov  r13, rbx
    mov  r15d, r8d
.continue:
    mov  eax, 1
    ret
.ambiguous:
    xor  eax, eax
    ret
.fold:
    cmp  al, 'A'
    jb   .folded
    cmp  al, 'Z'
    ja   .folded
    add  al, 32
.folded:
    ret

;; term_execute_line(R12): run the NUL-terminated line at TI_LINE
term_execute_line:
    push rbx
    push r13
    lea  rbx, [r12 + TI_LINE]
.skip_ws:
    cmp  byte [rbx], ' '
    jne  .ws_done
    inc  rbx
    jmp  .skip_ws
.ws_done:
    cmp  byte [rbx], 0
    je   .prompt
    mov  r13, rbx
.verb_end:
    mov  al, [r13]
    test al, al
    jz   .no_arg
    cmp  al, ' '
    je   .has_arg
    inc  r13
    jmp  .verb_end
.has_arg:
    mov  byte [r13], 0
    inc  r13
.arg_ws:
    cmp  byte [r13], ' '
    jne  .classify
    inc  r13
    jmp  .arg_ws
.no_arg:
    lea  r13, [rel term_empty]
.classify:
    ; Peter 2026-09-30: reboot / shutdown / windows (a leading '/' is accepted
    ; too, as he typed it) leave PaOS after a y/N confirmation
    mov  rdi, rbx
    cmp  byte [rdi], '/'
    jne  .power_word
    inc  rdi
.power_word:
    push rdi
    lea  rsi, [rel term_cmd_windows]
    call term_word_eq
    pop  rdi
    mov  ecx, 1
    test eax, eax
    jnz  .power
    push rdi
    lea  rsi, [rel term_cmd_reboot]
    call term_word_eq
    pop  rdi
    mov  ecx, 2
    test eax, eax
    jnz  .power
    lea  rsi, [rel term_cmd_shutdown]
    call term_word_eq
    mov  ecx, 3
    test eax, eax
    jnz  .power
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_linux_return]
    call term_word_eq
    mov  ecx, 4                       ; nonactuating, pending signed Linux return
    test eax, eax
    jnz  .power
%ifdef PAOS_TERMINAL_GUEST
    mov rdi, rbx
    lea rsi, [rel term_cmd_guest]
    call term_word_eq
    test eax, eax
    jnz .guest
%endif
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_ssh]
    call term_word_eq
    test eax, eax
    jnz  .ssh
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_clear]
    call term_word_eq
    test eax, eax
    jnz  .clear
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_exit]
    call term_word_eq
    test eax, eax
    jnz  .exit
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_help]
    call term_word_eq
    test eax, eax
    jnz  .help
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_history]
    call term_word_eq
    test eax, eax
    jnz  .history
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_echo]
    call term_word_eq
    test eax, eax
    jnz  .echo
    mov  rdi, rbx                       ; registry verbs are upper case
.upper:
    mov  al, [rdi]
    test al, al
    jz   .upper_done
    cmp  al, 'a'
    jb   .upper_next
    cmp  al, 'z'
    ja   .upper_next
    sub  al, 32
    mov  [rdi], al
.upper_next:
    inc  rdi
    jmp  .upper
.upper_done:
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_ls]
    call term_word_eq
    test eax, eax
    jnz  .ls
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_stat]
    call term_word_eq
    test eax, eax
    jnz  .stat
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_sha256sum]
    call term_word_eq
    test eax, eax
    jnz  .sha256sum
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_mkdir]
    call term_word_eq
    test eax, eax
    jnz  .mkdir
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_rmdir]
    call term_word_eq
    test eax, eax
    jnz  .rmdir
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_rm]
    call term_word_eq
    test eax, eax
    jnz  .rm
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_mv]
    call term_word_eq
    test eax, eax
    jnz  .mv
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_cp]
    call term_word_eq
    test eax, eax
    jnz  .cp
    mov  rdi, rbx
    lea  rsi, [rel term_cmd_df]
    call term_word_eq
    test eax, eax
    jnz  .df
    ; RCQ-22 Linux names with no honest native mapping: refuse locally (never a
    ; registry request) and name the native verb. None is a registry verb name,
    ; so no native verb is shadowed ('ping' stays the native PING echo).
    lea  r8, [rel term_unmapped_words]
.unmapped_scan:
    cmp  byte [r8], 0
    je   .unmapped_none
    mov  rdi, rbx
    mov  rsi, r8
    call term_word_eq
.unmapped_word:
    inc  r8
    cmp  byte [r8 - 1], 0
    jne  .unmapped_word                 ; R8 = this word's refusal text
    test eax, eax
    jnz  .unmapped_hit
.unmapped_text:
    inc  r8
    cmp  byte [r8 - 1], 0
    jne  .unmapped_text
    jmp  .unmapped_scan
.unmapped_hit:
    mov  rsi, r8
    call term_out_cstr
    jmp  .prompt
.unmapped_none:
    mov  rdi, rbx
    jmp  .registry
.ls:
    lea  rdx, [rel term_cmd_ls]
    lea  rdi, [rel term_alias_fsls]
    jmp  .alias_path
.stat:
    lea  rdx, [rel term_cmd_stat]
    lea  rdi, [rel term_alias_fsstat]
    jmp  .alias_path
.sha256sum:
    lea  rdx, [rel term_cmd_sha256sum]
    lea  rdi, [rel term_alias_fshash]
    jmp  .alias_strict
.mkdir:
    lea  rdx, [rel term_cmd_mkdir]
    lea  rdi, [rel term_alias_fsmkdir]
    jmp  .alias_strict
.rmdir:
    lea  rdx, [rel term_cmd_rmdir]
    lea  rdi, [rel term_alias_fsrmdir]
    jmp  .alias_strict
.rm:
    lea  rdx, [rel term_cmd_rm]
    lea  rdi, [rel term_alias_fsdel]
.alias_strict:
    ; RCQ-22 file aliases (native <absolute-path> <16-hex nonce> verbs). Same
    ; absolute entrance, plus refuse before any request: no nonce token (no
    ; space, or a trailing one) and any flag-like " -" token, so 'rm -rf /x'
    ; or 'mkdir /a -p n' is never reinterpreted. Nonce/path validation, owner
    ; authority and the locked gate stay with the native verb.
    cmp  byte [r13], '/'
    jne  .alias_refuse
    mov  rsi, r13
    xor  ecx, ecx                       ; RCX = byte after the last space, 0 = none
.strict_scan:
    mov  al, [rsi]
    test al, al
    jz   .strict_end                    ; the line buffer is NUL-terminated
    cmp  al, ' '
    jne  .strict_next
    cmp  byte [rsi + 1], '-'
    je   .alias_refuse
    lea  rcx, [rsi + 1]
.strict_next:
    inc  rsi
    jmp  .strict_scan
.strict_end:
    test rcx, rcx
    jz   .alias_refuse
    cmp  byte [rcx], 0
    jne  .registry
    jmp  .alias_refuse
.mv:
    lea  rdx, [rel term_cmd_mv]
    lea  rdi, [rel term_alias_fsren]
    jmp  .alias_pair
.cp:
    lea  rdx, [rel term_cmd_cp]
    lea  rdi, [rel term_alias_fscopy]
.alias_pair:
    ; RCQ-22 two-path aliases (native <absolute-path> <absolute-path> <16-hex
    ; nonce>): both paths absolute, a third token, and the same flag refusal.
    ; FSCOPY starts a copy job (FSJOB/FSCANCEL); nothing here waits for it.
    cmp  byte [r13], '/'
    jne  .pair_refuse
    mov  rsi, r13
.pair_first:
    mov  al, [rsi]
    test al, al
    jz   .pair_refuse
    inc  rsi
    cmp  al, ' '
    jne  .pair_first
    cmp  byte [rsi], '/'                ; RSI = the second token
    jne  .pair_refuse
    mov  r8, rsi
    mov  rsi, r13
    xor  ecx, ecx                       ; RCX = byte after the last space
.pair_scan:
    mov  al, [rsi]
    test al, al
    jz   .pair_end
    cmp  al, ' '
    jne  .pair_next
    cmp  byte [rsi + 1], '-'
    je   .pair_refuse
    lea  rcx, [rsi + 1]
.pair_next:
    inc  rsi
    jmp  .pair_scan
.pair_end:
    cmp  rcx, r8                        ; the last token must follow the second path
    jbe  .pair_refuse
    cmp  byte [rcx], 0
    jne  .registry
.pair_refuse:
    mov  rsi, rdx
    call term_out_cstr
    lea  rsi, [rel term_alias_pair_error]
    call term_out_cstr
    jmp  .prompt
.df:
    ; RCQ-22: FSINFO's one token is the nonce (the selected volume, no path):
    ; refuse an empty tail, a flag, a path or a second token before a request.
    lea  rdi, [rel term_alias_fsinfo]
    mov  rsi, r13
    cmp  byte [rsi], 0
    je   .df_refuse
    cmp  byte [rsi], '-'
    je   .df_refuse
    cmp  byte [rsi], '/'
    je   .df_refuse
.df_scan:
    mov  al, [rsi]
    test al, al
    jz   .registry
    cmp  al, ' '
    je   .df_refuse
    inc  rsi
    jmp  .df_scan
.df_refuse:
    lea  rsi, [rel term_alias_df_error]
    call term_out_cstr
    jmp  .prompt
.alias_path:
    ; These native aliases promise an absolute path. Check only the entrance;
    ; keep the tail and native nonce/authority parser untouched. Direct FSSTAT
    ; retains its legacy bare-name semantics through .registry.
    cmp  byte [r13], '/'
    je   .registry
.alias_refuse:
    mov  rsi, rdx                       ; "<alias>: expected ..." for whichever alias
    call term_out_cstr
    lea  rsi, [rel term_alias_path_error]
    call term_out_cstr
    jmp  .prompt
.registry:
    ; Exact command-name aliases only: never grow the user's verb buffer or
    ; touch its native absolute-path/nonce tail. Same registry/owner request.
    mov  rsi, r13
    call term_run_command
    jmp  .prompt
%ifdef PAOS_TERMINAL_GUEST
.guest:
    lea rdi, [rel term_exec_taint]
    call keyprov_line_owner_equivalent
    lea rdx, [rel term_cmd_guest]
    test eax, eax
    jz .builtin_refused
    call term_guest_attach
    jmp .out
%endif
.ssh:
    lea  rdi, [rel term_exec_taint]     ; GA0-K: the ssh client uses the owner's identity
    call keyprov_line_owner_equivalent
    lea  rdx, [rel term_builtin_ssh]
    test eax, eax
    jz   .builtin_refused
    mov  rdi, r13
    lea  rsi, [r12 + TI_LINE + TERM_LINE_BUF]
    sub  rsi, rdi                       ; only the actual caller-owned remaining line extent
    call term_ssh_start_bounded
    jmp  .out
.builtin_refused:                       ; RDX = the built-in's fixed name (never line bytes)
    lea  rdi, [rel term_exec_taint]
    mov  esi, KP_SURFACE_TERMINAL
    call keyprov_refuse_builtin
    lea  rsi, [rel term_injected_refused]
    call term_out_cstr
    jmp  .prompt
.clear:
    lea  rsi, [rel term_clear_text]
    call term_out_cstr
    jmp  .prompt
.exit:
    mov  edi, [r12 + TI_WIN]
    call wmx_close_slot
    call term_release
    jmp  .out
.echo:
    mov  rsi, r13                       ; a shell's echo: the arguments, nothing else
    call term_out_cstr
    lea  rsi, [rel term_crlf]
    call term_out_cstr
    jmp  .prompt
.history:
    cmp  byte [r13], 0
    jne  .history_usage
    call term_hist_print
    jmp  .prompt
.history_usage:
    lea  rsi, [rel term_history_usage]
    call term_out_cstr
    jmp  .prompt
.help:
    ; One generated catalog supplies local words and live native documentation.
    ; Pass the user's operand through the existing guarded command path.
    lea  rdi, [rel term_registry_help]
    call command_lookup
    cmp  eax, -1
    je   .prompt
    lea  rdi, [rel term_registry_help]
    mov  rsi, r13
    call term_run_command
.prompt:
    call term_prompt
.out:
    push rdi
    lea  rdi, [rel term_exec_taint]     ; a line that dispatched nothing leaves no taint
    call keyprov_line_clear
    pop  rdi
    pop  r13
    pop  rbx
    ret
.power:
    push rcx
    lea  rdi, [rel term_exec_taint]     ; GA0-K: leaving PaOS is the owner's act
    call keyprov_line_owner_equivalent
    pop  rcx
    lea  rdx, [rel term_builtin_power]
    test eax, eax
    jz   .builtin_refused
    cmp  ecx, 4
    je   .linux_power
    mov  [r12 + TI_CONFIRM], cl
    mov  edi, ecx
    call power_question_text
    mov  rsi, rax
    call term_out_cstr                  ; the answer arrives in term_confirm_key
    jmp  .out
.linux_power:
    mov  rdi, r12                      ; only this Terminal may answer this prompt
    call command_power_return_local_begin
    test eax, eax
    jz   .linux_unavailable
    call term_power_return_bind          ; snapshot this actual Terminal lifetime
    mov  byte [r12 + TI_CONFIRM], 4
    lea  rsi, [rel term_linux_question]
    call term_out_cstr
    jmp  .out
.linux_unavailable:
    lea  rsi, [rel term_linux_unavailable]
    call term_out_cstr
    jmp  .prompt

;; term_confirm_key(R12, EAX = GUI key): the y/N answer to a power command.
;; 'y' confirms; anything else (Enter alone, n, Ctrl+C) cancels.
term_confirm_key:
    movzx ecx, byte [r12 + TI_CONFIRM]
    mov  byte [r12 + TI_CONFIRM], 0
    push rax
    push rcx
    call term_taint_rec                 ; GA0-K: the answer is a line of its own; an
    push rdi                            ; injected 'y' counts only from an
    call keyprov_line_owner_equivalent  ; owner-equivalent injector
    pop  rdi
    call keyprov_line_clear
    mov  edx, eax
    pop  rcx
    pop  rax
    cmp  ecx, 4
    je   .linux_answer
    test edx, edx
    jz   .no
    cmp  eax, 'y'
    je   .yes
    cmp  eax, 'Y'
    je   .yes
.no:
    lea  rsi, [rel term_power_no]
    call term_out_cstr
    jmp  term_prompt
.linux_answer:
    ; Keep the real key-origin distinction. An owner-injected answer may
    ; authorize the Terminal path, but can never be reported as human input.
    push rax
    push rdx
    call keyprov_key_is_human
    mov ecx,eax
    pop rdx
    pop rax
    xor esi,esi
    cmp eax,'y'
    je .linux_yes
    cmp eax,'Y'
    jne .linux_origin
.linux_yes:
    mov esi,1
.linux_origin:
    test edx,edx
    jz .linux_deliver
    mov edx,2
    test ecx,ecx
    jz .linux_deliver
    mov edx,1
.linux_deliver:
    mov rdi,r12
    push rsi
    call command_power_return_local_answer
    pop rsi
    test eax,eax
    jz .linux_refused
    test esi,esi
    jz .no
    lea rsi,[rel term_linux_waiting]
    call term_out_cstr
    jmp term_prompt
.linux_refused:
    lea rsi,[rel term_linux_unavailable]
    call term_out_cstr
    jmp term_prompt
.yes:
    push rcx
    lea  rsi, [rel term_power_yes]
    call term_out_cstr
    pop  rcx
    push rcx
    lea  rsi, [rel term_power_leaving]
    cmp  ecx, 3
    jne  .say
    lea  rsi, [rel term_power_off]
.say:
    call term_out_cstr
    pop  rdi
    call power_execute                  ; returns only when nothing happened: RAX = why
    mov  rsi, rax
    call term_out_cstr
    jmp  term_prompt

;; GA0-K line taint, one record per instance (a companion array: no TI change).
;; term_taint_rec(R12) -> RDI = this window's record. An instance pointer
;; outside the table gets a spare record forced UNTETHERED (fails closed).
;; Preserves every other register.
term_taint_rec:
    push rax
    push rdx
    mov  rax, r12
    sub  rax, [rel term_instances_ptr]
    jb   .spare
    xor  edx, edx
    mov  edi, TI_SIZE
    div  rdi
    test rdx, rdx
    jnz  .spare
    cmp  rax, TERM_MAX
    jae  .spare
    imul eax, eax, KT_SIZE
    lea  rdi, [rel term_taints]
    add  rdi, rax
    pop  rdx
    pop  rax
    ret
.spare:
    lea  rdi, [rel term_taint_spare]
    mov  qword [rdi + KT_STATE], KT_UNTETHERED
    pop  rdx
    pop  rax
    ret

;; term_taint_latch(R12): Enter. The window's taint moves to term_exec_taint
;; for term_execute_line (synchronous) and the window starts a clean line.
;; Preserves every register.
term_taint_latch:
    push rax
    push rcx
    push rsi
    push rdi
    call term_taint_rec
    mov  rsi, rdi
    lea  rdi, [rel term_exec_taint]
    mov  ecx, KT_SIZE / 8
.copy:
    mov  rax, [rsi]
    mov  [rdi], rax
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .copy
    sub  rsi, KT_SIZE
    mov  rdi, rsi
    call keyprov_line_clear
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rax
    ret

;; term_word_eq(RDI word, RSI lower-case keyword) -> EAX 1 equal (ASCII case-insensitive)
term_word_eq:
.l:
    mov  al, [rdi]
    mov  dl, [rsi]
    cmp  al, 'A'
    jb   .a
    cmp  al, 'Z'
    ja   .a
    add  al, 32
.a:
    cmp  al, dl
    jne  .no
    test al, al
    jz   .yes
    inc  rdi
    inc  rsi
    jmp  .l
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

;; term_run_command(R12, RDI verb, RSI argument): the owner command registry,
;; exactly as the Console submits it; the canonical reply text (LF -> CRLF)
;; is written to the terminal.
term_run_command:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rsi
    mov  qword [rel term_req + REQ_VERB], 0
    mov  qword [rel term_req + REQ_CAP], -1
    mov  qword [rel term_req + REQ_IDEM], 0
    mov  qword [rel term_req + REQ_SEL], 0
    mov  qword [rel term_req + REQ_ARG], 0
    mov  qword [rel term_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    lea  rdi, [rel term_req]
    call session_shell_prepare_local_request
    mov  rdi, rbx
    call command_lookup
    cmp  eax, -1
    jne  .known
    lea  rsi, [rel term_unknown_text]
    call term_out_cstr
    ; RCQ-22 Console parity: the registry's canonical NOVERB line (code,
    ; expected = registered verb count, hint) - its constants and hint text,
    ; without a dispatch, so an unknown word still reaches no registry request.
    call command_verb_count
    mov  esi, eax
    mov  edi, CMDE_NOVERB
    lea  rdx, [rel str_cmd_hint_noverb]
    call term_err_line
    jmp  .out
.known:
    mov  r14, rax
    mov  [rel term_req + REQ_VERB], rax
    mov  rdi, r14
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .text_arg
    mov  rdi, r13
    call console_parse_u64
    mov  [rel term_req + REQ_ARG], rax
    jmp  .dispatch
.text_arg:
    mov  [rel term_req + REQ_ARG], r13
.dispatch:
    call term_tx_begin                  ; RCQ-22 transcript: before the dispatch, as the Console
    push rax                            ; record
    push rdx                            ; session | secret << 32
    lea  rdi, [rel term_req]
    lea  rsi, [rel term_rsp]
    lea  rdx, [rel term_exec_taint]
    mov  ecx, KP_SURFACE_TERMINAL
    call keyprov_dispatch               ; GA0-K: a tainted line runs as its injector
    mov  rdi, rbx
    mov  rsi, r13
    lea  rdx, [rel term_rsp]
    call command_udp_capture_reply      ; RAX text, EDX length
    mov  rbx, rax
    mov  r13d, edx
    pop  rsi
    pop  rdi
    call term_tx_finish                 ; the same reply bytes the Console records
    ; RCQ-22 Console parity: the job/state suffix joins the reply line, so a
    ; trailing CRLF of the canonical reply is dropped (Console does the same).
    cmp  r13d, 2
    jb   .reply_bytes
    cmp  word [rbx + r13 - 2], 0x0a0d
    jne  .reply_bytes
    sub  r13d, 2
.reply_bytes:
    xor  r14d, r14d
.byte:
    cmp  r14d, r13d
    jae  .eol
    movzx eax, byte [rbx + r14]
    cmp  al, 10
    jne  .plain
    test r14d, r14d
    jz   .lf
    cmp  byte [rbx + r14 - 1], 13
    je   .plain
.lf:
    mov  al, 13
    call term_out_byte
    mov  al, 10
.plain:
    call term_out_byte
    inc  r14d
    jmp  .byte
.eol:
    cmp  qword [rel term_rsp + RSP_ACCEPTED], 1
    jne  .status_job
    cmp  qword [rel term_rsp + RSP_JOBID], 0
    je   .status_job
    lea  rsi, [rel term_job_accepted]   ; " accepted job=N est=S"
    call term_out_cstr
    mov  rdi, [rel term_rsp + RSP_JOBID]
    call term_out_dec
    lea  rsi, [rel term_job_est]
    call term_out_cstr
    mov  edi, SLOWJOB_EST_SEC
    call term_out_dec
    jmp  .reply_end
.status_job:                            ; "STATUS <job>": " state=running|done|N"
    mov  eax, [rel verb_id_status]
    cmp  [rel term_req + REQ_VERB], rax
    jne  .reply_end
    cmp  qword [rel term_rsp + RSP_CODE], CMDE_OK
    jne  .reply_end
    cmp  qword [rel term_req + REQ_ARG], 0
    je   .reply_end
    lea  rsi, [rel term_job_state]
    call term_out_cstr
    mov  rdi, [rel term_rsp + RSP_VAL]
    lea  rsi, [rel term_job_running]
    cmp  rdi, JOB_ST_RUN
    je   .state_word
    lea  rsi, [rel term_job_done]
    cmp  rdi, JOB_ST_DONE
    je   .state_word
    call term_out_dec
    jmp  .reply_end
.state_word:
    call term_out_cstr
.reply_end:
    lea  rsi, [rel term_crlf]
    call term_out_cstr
    mov  rdi, [rel term_rsp + RSP_CODE]
    test rdi, rdi
    jz   .out
    mov  rsi, [rel term_rsp + RSP_EXPECTED]
    mov  rdx, [rel term_rsp + RSP_HINT]
    call term_err_line
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_tx_begin(R12, RBX verb, R13 argument) -> RAX record/0, RDX session |
;; secret << 32 (term_run_command keeps both on its stack across the dispatch, so
;; no transcript state is shared between windows). RCQ-22 transcript parity:
;; each Terminal slot k records its native command lines in the cons session
;; "term<k>" (CONS_LIST / CONS_READ term<k> from=N, the Console's authority and
;; bounds). Only a registered verb reaches here: unknown words, local words and
;; anything typed into an SSH session are never recorded. A verb whose argument
;; or reply can carry a secret (cons_secret_verb: the UDP audit's credential
;; verbs and the cons secret table) is recorded as "<VERB> <redacted>" with a
;; redacted reply. A line over the record bound keeps its head + "...".
term_tx_begin:
    push rbx
    push r13
    push r14
    push r15
    xor  r15d, r15d                     ; secret flag
    lea  rdi, [rel term_tx_line]
    xor  r14d, r14d
.verb:
    mov  al, [rbx + r14]
    test al, al
    jz   .verb_end
    cmp  r14d, TERM_TX_MAX
    jae  .verb_end
    mov  [rdi + r14], al
    inc  r14d
    jmp  .verb
.verb_end:
    mov  byte [rdi + r14], 0
    mov  rdi, rbx
    call cons_secret_verb
    lea  rsi, [rel term_tx_redacted]    ; " <redacted>"
    test eax, eax
    jz   .plain
    mov  r15d, 1
    jmp  .tail
.plain:
    cmp  byte [r13], 0
    je   .name
    cmp  r14d, TERM_TX_MAX
    jae  .cut
    lea  rdi, [rel term_tx_line]
    mov  byte [rdi + r14], ' '
    inc  r14d
    mov  rsi, r13
.tail:
    lea  rdi, [rel term_tx_line]
.tail_byte:
    mov  al, [rsi]
    test al, al
    jz   .tail_end
    cmp  r14d, TERM_TX_MAX
    jae  .cut
    mov  [rdi + r14], al
    inc  r14d
    inc  rsi
    jmp  .tail_byte
.cut:
    lea  rdi, [rel term_tx_line]        ; bounded: the head, then "..."
    mov  r14d, TERM_TX_MAX - 3
.cut_back:                              ; RCQ-38 L4: the head ends on a scalar boundary
    test r14d, r14d
    jz   .cut_mark
    mov  al, [rdi + r14]
    and  al, 0xC0
    cmp  al, 0x80
    jne  .cut_mark
    dec  r14d
    jmp  .cut_back
.cut_mark:
    mov  dword [rdi + r14], '...'
    add  r14d, 3
.tail_end:
    mov  byte [rdi + r14], 0
.name:
    call term_inst_index                ; RAX = slot, 0 .. TERM_MAX - 1
    mov  r14d, eax
    add  al, '0'
    mov  [rel term_tx_name + 4], al
    lea  rdi, [rel term_tx_name]
    lea  rsi, [rel term_tx_line]
    call cons_local_begin               ; RAX record/0, EDX session/-1
    cmp  edx, -1
    jne  .out
    lea  rcx, [rel term_tx_noted]       ; no session: say so once per slot
    cmp  byte [rcx + r14], 0
    jne  .out
    mov  byte [rcx + r14], 1
    push rax
    push rdx
    lea  rsi, [rel term_tx_none_text]
    call term_out_cstr
    pop  rdx
    pop  rax
.out:
    mov  edx, edx                       ; session, zero-extended
    shl  r15, 32
    or   rdx, r15
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_tx_finish(RDI record/0, RSI session | secret << 32, RBX reply, R13D
;; length): close the record term_tx_begin opened for this same dispatch.
term_tx_finish:
    test rdi, rdi
    jz   .out
    mov  r9d, esi                       ; session
    mov  r10, rsi
    mov  rsi, rbx
    mov  edx, r13d
    shr  r10, 32
    jz   .reply
    lea  rsi, [rel term_tx_redacted_reply]
    mov  edx, term_tx_redacted_reply_end - term_tx_redacted_reply
.reply:
    mov  rcx, [rel term_rsp + RSP_CODE]
    xor  r8d, r8d
    cmp  qword [rel term_rsp + RSP_ACCEPTED], 1
    jne  .call
    mov  r8, [rel term_rsp + RSP_JOBID]
.call:
    jmp  cons_local_finish
.out:
    ret

;; term_err_line(R12, RDI code, RSI expected, RDX hint | 0): the Console's
;; actionable error line, "ERR code=C expected=E hint=H" + CRLF ("none" for 0).
term_err_line:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rsi
    mov  r14, rdx
    lea  rsi, [rel term_err_code]
    call term_out_cstr
    mov  rdi, rbx
    call term_out_dec
    lea  rsi, [rel term_err_expected]
    call term_out_cstr
    mov  rdi, r13
    call term_out_dec
    lea  rsi, [rel term_err_hint]
    call term_out_cstr
    mov  rsi, r14
    test rsi, rsi
    jnz  .hint
    lea  rsi, [rel term_err_none]
.hint:
    call term_out_cstr
    lea  rsi, [rel term_crlf]
    call term_out_cstr
    pop  r14
    pop  r13
    pop  rbx
    ret

;; term_out_dec(R12, RDI unsigned): decimal digits to the terminal.
term_out_dec:
    lea  rsi, [rel term_num_buf]
    call fmt_dec
    lea  rsi, [rel term_num_buf]
    jmp  term_out_cstr

;; term_ssh_start(R12, RDI = USER@HOST[:PORT] or legacy IP[:PORT] USER).
;; The existing GA0-K builtin gate remains the only command entry to this path.
%include "gui/terminal_ssh_observation.inc"
%include "gui/terminal_ssh_exec.inc"

term_ssh_start:
    mov  esi, 324                       ; legacy internal helper retains its old bound
term_ssh_start_bounded:
%ifndef PAOS_TERMINAL_SSH
    lea  rsi, [rel term_ssh_absent_text]
    call term_out_cstr
    jmp  term_prompt
%endif
    push rbx
    push r13
    mov  rbx, rdi
    mov  r13d, esi
    cmp  byte [r12 + TI_SSH], 0
    jne  .busy
    call term_paste_retire
    mov  rdi, rbx
    mov  esi, r13d
    call term_ssh_argument_extent
    test eax, eax
    jz   .bad
    mov  esi, eax
    mov  rdi, rbx
    call term_ssh_command_parse
    cmp  eax, -1
    je   .bad
    call term_ssh_lookup_ptr
    mov  rbx, rax
    lea  rsi, [rel term_ssh_connecting]
    call term_out_cstr
    lea  rsi, [rbx + TS_RAW]
    call term_out_cstr
    lea  rsi, [rel term_ssh_connecting_tail]
    call term_out_cstr
    cmp  dword [rbx + TS_KIND], 1
    jne  .numeric
    mov  byte [r12 + TI_SSH], 2
    mov  dword [r12 + TI_SESS], -1
    mov  dword [rbx + TS_PHASE], 1
    call time_monotonic_now_us
    add  rax, TERM_SSH_CONNECT_US
    mov  [rbx + TS_TOTAL], rax
    mov  [r12 + TI_DEADLINE], rax
    mov  qword [r12 + TI_NEXTTRY], 0
    lea  rsi, [rel term_ssh_dns_wait]
    call term_out_cstr
    jmp  .out                           ; native DNS APIs run only from the tick
.numeric:
    call term_ssh_dial
    test eax, eax
    jz   .out
    cmp  eax, -2
    jne  .failed
    call term_arp_request
    mov  byte [r12 + TI_SSH], 2
    call time_monotonic_now_us
    lea  rcx, [rax + TERM_ARP_RETRY_US]
    mov  [r12 + TI_NEXTTRY], rcx
    add  rax, TERM_ARP_WAIT_US
    mov  [r12 + TI_DEADLINE], rax
    jmp  .out
.bad:
    mov  eax, -1
.failed:
    call term_ssh_dial_error
    jmp  .out
.busy:
    lea  rsi, [rel term_ssh_busy]
    call term_out_cstr
    call term_prompt
.out:
    pop  r13
    pop  rbx
    ret

; RAX = window-local lookup record. No TI/shared structure or resolver changes.
term_ssh_lookup_ptr:
    call term_inst_index
    imul eax, eax, TS_SIZE
    lea  rdx, [rel term_ssh_lookups]
    add  rax, rdx
    ret

term_ssh_lookup_invalidate:
    call term_ssh_exec_forget
    call term_ssh_lookup_ptr
    mov  dword [rax + TS_VALID], 0
    mov  dword [rax + TS_PHASE], 0
    ret

; Parse bounded original text without mutating a loaded SSH session's user.
; Numeric-only tokens retain the existing numeric parser (including its rejects).
; New DNS tokens use ASCII LDH labels,1..63 chars, total<=253; no empty labels,
; leading/trailing hyphen/dot, whitespace, controls or implicit user/default host.
term_ssh_lookup_parse:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, rdi
    call term_ssh_lookup_ptr
    mov  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, TS_SIZE
    call memset
    xor  ecx, ecx
.copy:
    mov  al, [r13 + rcx]
    mov  [rbx + TS_RAW + rcx], al
    test al, al
    jz   .copied
    inc  ecx
    cmp  ecx, 323
    jb   .copy
    jmp  .bad                           ; no truncation into another valid destination
.copied:
    test ecx, ecx
    jz   .bad
    lea  r13, [rbx + TS_RAW]
    xor  r14d, r14d                     ; 1 USER@ prefix; 0 legacy numeric syntax
    xor  ecx, ecx
.at_scan:
    mov  al, [r13 + rcx]
    test al, al
    jz   .host_begin
    cmp  al, ' '
    je   .host_begin
    cmp  al, '@'
    je   .at
    inc  ecx
    cmp  ecx, 63
    jb   .at_scan
    jmp  .host_begin
.at:
    test ecx, ecx
    jz   .bad
    lea  rdi, [rbx + TS_USER]
    mov  rsi, r13
    mov  edx, ecx
    add  r13, rcx
    inc  r13
    call memcpy
    mov  r14d, 1
.host_begin:
    xor  r8d, r8d                      ; total hostname chars
    xor  r9d, r9d                      ; label chars
    mov  r10d, 1                       ; digits/dots only => existing IPv4 grammar
    xor  r11d, r11d
.host:
    movzx eax, byte [r13]
    test al, al
    jz   .host_end
    cmp  al, ':'
    je   .host_end
    cmp  al, ' '
    je   .host_end
    cmp  r8d, 253
    jae  .bad
    cmp  al, '.'
    je   .dot
    cmp  al, '-'
    je   .hyphen
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .char
    cmp  al, 'A'
    jb   .bad
    cmp  al, 'Z'
    jbe  .letter
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'z'
    ja   .bad
.letter:
    xor  r10d, r10d
    jmp  .char
.hyphen:
    test r9d, r9d
    jz   .bad
    xor  r10d, r10d
.char:
    inc  r9d
    cmp  r9d, 63
    ja   .bad
    jmp  .store
.dot:
    test r9d, r9d
    jz   .bad
    cmp  r11b, '-'
    je   .bad
    xor  r9d, r9d
.store:
    mov  [rbx + TERM_SSH_LOOKUP_HOST + r8], al
    mov  r11b, al
    inc  r8d
    inc  r13
    jmp  .host
.host_end:
    test r9d, r9d
    jz   .bad
    cmp  r11b, '-'
    je   .bad
    mov  dword [rbx + TS_PORT], 22
    cmp  byte [r13], ':'
    jne  .user
    inc  r13
    xor  r15d, r15d
    xor  ecx, ecx
.port:
    movzx eax, byte [r13]
    sub  eax, '0'
    cmp  eax, 9
    ja   .port_end
    inc  ecx
    cmp  ecx, 5
    ja   .bad
    imul r15d, r15d, 10
    add  r15d, eax
    cmp  r15d, 65535
    ja   .bad
    inc  r13
    jmp  .port
.port_end:
    test ecx, ecx
    jz   .bad
    test r15d, r15d
    jz   .bad
    mov  [rbx + TS_PORT], r15d
.user:
    test r14d, r14d
    jnz  .end
    test r10d, r10d
    jz   .bad                           ; legacy syntax remains numeric only
    cmp  byte [r13], ' '
    jne  .bad
    inc  r13
    xor  ecx, ecx
.legacy_user:
    mov  al, [r13]
    test al, al
    jz   .legacy_end
    cmp  al, ' '
    je   .bad
    cmp  ecx, 62
    jae  .bad
    mov  [rbx + TS_USER + rcx], al
    inc  r13
    inc  ecx
    jmp  .legacy_user
.legacy_end:
    test ecx, ecx
    jz   .bad
.end:
    cmp  byte [r13], 0
    jne  .bad
    test r10d, r10d
    jz   .dns
    lea  rdi, [rbx + TS_RAW]
    call strlen
    cmp  eax, 96
    jae  .bad
    mov  edx, eax
    inc  edx
    lea  rdi, [rbx + TS_DIAL]
    lea  rsi, [rbx + TS_RAW]
    call memcpy
    jmp  .publish
.dns:
    mov  dword [rbx + TS_KIND], 1
.publish:
    call term_inst_index
    lea  rdx, [rel term_paste_generations]
    mov  rax, [rdx + rax*8]
    mov  [rbx + TS_EPOCH], rax
    mov  dword [rbx + TS_VALID], 1
    mov  eax, [rbx + TS_KIND]
    jmp  .out
.bad:
    mov  dword [rbx + TS_VALID], 0
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; Check the actual window lifetime and visibility before any DNS work or dial.
term_ssh_lookup_current:
    cmp  dword [rbx + TS_VALID], 1
    jne  .no
    cmp  byte [r12 + TI_USED], 1
    jne  .no
    cmp  byte [r12 + TI_SSH], 2
    jne  .no
    call term_inst_index
    lea  rdx, [rel term_paste_generations]
    mov  rax, [rdx + rax*8]
    cmp  rax, [rbx + TS_EPOCH]
    jne  .no
    mov  ecx, [r12 + TI_WIN]
    lea  rdx, [rel wm_title]
    lea  rax, [r12 + TI_NAME]
    cmp  [rdx + rcx*8], rax
    jne  .no
    lea  rdx, [rel wm_state]
    cmp  dword [rdx + rcx*4], WM_VISIBLE
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

term_ssh_lookup_stale:
    call term_ssh_lookup_invalidate
    mov  byte [r12 + TI_SSH], 0
    ret

; Native resolver is shared. Abandon only our local intent; never reset/cancel it.
term_ssh_lookup_lock:
    cmp  byte [r12 + TI_SSH], 2
    jne  .out
    call term_ssh_lookup_ptr
    cmp  dword [rax + TS_KIND], 1
    jne  .out
    cmp  dword [rax + TS_VALID], 1
    jne  .out
    mov  dword [rax + TS_VALID], 0
    mov  dword [rax + TS_PHASE], 3
    mov  byte [r12 + TI_SSH], 0
    call term_ssh_exec_forget           ; lock revokes the unsent command as well as DNS intent
    call term_paste_retire
.out:
    ret

term_ssh_lookup_notice:
    call term_ssh_lookup_ptr
    cmp  dword [rax + TS_PHASE], 3
    jne  .out
    mov  dword [rax + TS_PHASE], 0
    lea  rsi, [rel term_ssh_dns_locked]
    call term_out_cstr
    call term_prompt
.out:
    ret

; Build only a numeric endpoint for the unchanged SSH owner/host-key path.
; RBX=record, EDI=wire IPv4. No DNS-derived trust or hostname pin is introduced.
term_ssh_lookup_build:
    push rbx
    push r13
    push r14
    push r15
    mov  r14, rbx
    mov  r13d, edi
    lea  rbx, [rbx + TS_DIAL]
    lea  rdi, [r14 + TS_USER]
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    mov  byte [rbx], '@'
    inc  rbx
    mov  r15d, 4
.oct:
    movzx edi, r13b
    mov  rsi, rbx
    call fmt_dec
    add  rbx, rax
    shr  r13d, 8
    dec  r15d
    jz   .port
    mov  byte [rbx], '.'
    inc  rbx
    jmp  .oct
.port:
    mov  byte [rbx], ':'
    inc  rbx
    mov  edi, [r14 + TS_PORT]
    mov  rsi, rbx
    call fmt_dec
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

term_ssh_lookup_deadline:
    call term_ssh_lookup_ptr
    cmp  dword [rax + TS_VALID], 1
    jne  .out
    cmp  dword [rax + TS_KIND], 1
    jne  .out
    mov  dword [rax + TS_PHASE], 0
    mov  rcx, [rax + TS_TOTAL]
    mov  [r12 + TI_DEADLINE], rcx
    cmp  rcx, [r12 + TI_NEXTTRY]
    jae  .out
    mov  [r12 + TI_NEXTTRY], rcx
.out:
    ret

term_ssh_lookup_tick:
    push rbx
    push r13
    call term_ssh_lookup_ptr
    mov  rbx, rax
    call term_ssh_lookup_current
    test eax, eax
    jz   .stale
    call time_monotonic_now_us
    mov  r13, rax
    cmp  rax, [rbx + TS_TOTAL]
    jae  .timeout
    lea  rdi, [rbx + TERM_SSH_LOOKUP_HOST]
    call dns_cache_get                   ; only this API promises EDX=address for A
    cmp  eax, DNS_LOOKUP_A
    je   .address
    cmp  eax, DNS_LOOKUP_NX
    je   .nx
    cmp  eax, DNS_LOOKUP_NODATA
    je   .nodata
    cmp  eax, DNS_LOOKUP_TIMEOUT
    jne  .pending
    cmp  dword [rbx + TS_STARTED], 0
    jne  .timeout                       ; current admitted/joined query failed
    jmp  .kick                          ; an older query timeout is not this intent
.pending:
    cmp  eax, DNS_LOOKUP_PENDING
    je   .joined
.kick:
    cmp  r13, [r12 + TI_NEXTTRY]
    jb   .out
    lea  rax, [r13 + TERM_DNS_RETRY_US]
    mov  [r12 + TI_NEXTTRY], rax
    lea  rdi, [rbx + TERM_SSH_LOOKUP_HOST]
    call dns_resolve_start               ; status only; never use its scratch EDX
    cmp  eax, DNS_LOOKUP_NX
    je   .nx
    cmp  eax, DNS_LOOKUP_NODATA
    je   .nodata
    cmp  eax, DNS_LOOKUP_TIMEOUT
    je   .timeout
    cmp  eax, DNS_LOOKUP_MISS
    je   .refused
    cmp  eax, DNS_LOOKUP_PENDING
    je   .joined
    jmp  .out                           ; A is re-read from cache on the next tick
.joined:
    mov  dword [rbx + TS_STARTED], 1
    jmp  .out
.address:
    test edx, edx
    jz   .refused
    cmp  edx, -1
    je   .refused
    mov  [r12 + TI_DIALIP], edx
    mov  edi, edx
    call term_ssh_lookup_build
    lea  rsi, [rel term_ssh_dns_resolved]
    call term_out_cstr
    lea  rsi, [rbx + TS_DIAL]
    call term_out_cstr
    lea  rsi, [rel term_ssh_dns_endpoint_tail]
    call term_out_cstr
    mov  dword [rbx + TS_PHASE], 2      ; DNS done; numeric endpoint is stable for ARP retries
    call term_ssh_dial
    test eax, eax
    jz   .out
    cmp  eax, -2
    jne  .dial_failed
    mov  byte [r12 + TI_SSH], 2
    call term_arp_request
    call time_monotonic_now_us
    lea  rcx, [rax + TERM_ARP_RETRY_US]
    mov  [r12 + TI_NEXTTRY], rcx
    add  rax, TERM_ARP_WAIT_US
    cmp  rax, [rbx + TS_TOTAL]
    jbe  .arp_deadline
    mov  rax, [rbx + TS_TOTAL]
.arp_deadline:
    mov  [r12 + TI_DEADLINE], rax
    jmp  .out
.dial_failed:
    call term_ssh_dial_error
    jmp  .out
.stale:
    call term_ssh_lookup_stale
    jmp  .out
.nx:
    lea  rsi, [rel term_ssh_dns_nx]
    jmp  .message
.nodata:
    lea  rsi, [rel term_ssh_dns_nodata]
    jmp  .message
.timeout:
    lea  rsi, [rel term_ssh_dns_timeout]
    jmp  .message
.refused:
    lea  rsi, [rel term_ssh_dns_refused]
.message:
    push rsi
    call term_ssh_lookup_invalidate
    mov  byte [r12 + TI_SSH], 0
    pop  rsi
    call term_out_cstr
    call term_prompt
.out:
    pop  r13
    pop  rbx
    ret

;; term_ssh_dial(R12) -> EAX: a new ssh session for this window dials TI_DIAL;
;; on 0 the window is attached to it. -4: every session is in use.
term_ssh_dial:
    push rbx
    call term_ssh_lookup_ptr
    mov  rbx, rax
    cmp  dword [rbx + TS_EXEC_USED], 0
    jne  .stale                         ; a consumed exec intent cannot redial as exec or shell
    cmp  dword [rbx + TS_VALID], 1
    jne  .legacy
    call term_inst_index
    lea  rdx, [rel term_paste_generations]
    mov  rax, [rdx + rax*8]
    cmp  rax, [rbx + TS_EPOCH]
    jne  .stale
    cmp  dword [rbx + TS_PHASE], 1
    je   .stale                          ; no dialing before a current A cache result
.legacy:
    call term_paste_retire              ; includes reconnects reusing the same session number
    call term_inst_index
    lea  rdx, [rel term_paste_generations]
    mov  rax, [rdx + rax*8]
    mov  [rbx + TS_EPOCH], rax
    call ssh_session_begin
    cmp  eax, -1
    je   .no_session
    mov  [r12 + TI_SESS], eax
    call term_ssh_observation_forget    ; a new actual dial retires prior public evidence
    lea  rdi, [r12 + TI_DIAL]
    cmp  dword [rbx + TS_VALID], 1
    jne  .arg
    lea  rdi, [rbx + TS_DIAL]
.arg:
    mov  esi, 1                         ; RCQ-08: every dial begins at the GA0-K gated ssh builtin
    call ssh_client_connect_start
    mov  ecx, [rel ssh_cli_target_ip]
    mov  [r12 + TI_DIALIP], ecx         ; ARP resolution keeps asking for it
    test eax, eax
    jz   .attached
    push rax
    call term_ssh_start_observation_record ; actual preconnect refusal before session_end
    mov  edi, [r12 + TI_SESS]
    call ssh_session_end                ; no connection: freed by the next poll
    mov  dword [r12 + TI_SESS], -1
    pop  rax
    jmp  .out
.no_session:
    mov  eax, -4
    jmp  .out
.attached:
    cmp  dword [rbx + TS_EXEC_LEN], 0
    je   .configured
    lea  rdi, [rbx + TS_EXEC_CMD]
    mov  esi, [rbx + TS_EXEC_LEN]
    cmp  dword [rbx + TS_EXEC_STREAM], 1
    jne  .exec_empty
    call ssh_cli_exec_configure_stream
    jmp  .exec_configured
.exec_empty:
    call ssh_cli_exec_configure
.exec_configured:
    test eax, eax
    jnz  .exec_refused
    call ssh_cli_exec_handle
    test rax, rax
    jz   .exec_refused
    mov  [rbx + TS_EXEC_TOKEN], rax
    mov  dword [rbx + TS_EXEC_USED], 1
    lea  rdi, [rbx + TS_EXEC_CMD]
    xor  esi, esi
    mov  edx, TERM_SSH_EXEC_CAP + 1
    call memset                         ; client now owns it; never replay after reconnect
    mov  eax, [r12 + TI_SESS]
    mov  [rbx + TS_EXEC_SESSION], eax
.configured:
    ; connect_start resets the PTY size; pty-req (sent later from the poll)
    ; must carry this window's grid and TERM=xterm-256color
    mov  eax, [r12 + TI_COLS]
    mov  [rel ssh_cli_term_cols], eax
    mov  [r12 + TI_WCOLS], eax
    mov  eax, [r12 + TI_ROWS]
    mov  [rel ssh_cli_term_rows], eax
    mov  [r12 + TI_WROWS], eax
    lea  rax, [rel terminal_ssh_sink]
    mov  [rel ssh_cli_data_sink], rax
    mov  byte [r12 + TI_SSH], 1
    inc  dword [rel term_ssh_sessions]
    call time_monotonic_now_us
    push rax                            ; actual caller budget origin for observation only
    lea  rcx, [rax + TERM_SSH_TCP_US]
    mov  [r12 + TI_NEXTTRY], rcx        ; TCP handshake budget (TI_NEXTTRY is free once dialled)
    add  rax, TERM_SSH_CONNECT_US
    mov  [r12 + TI_DEADLINE], rax
    call term_ssh_lookup_deadline
    mov edi, [r12 + TI_SESS]
    mov rsi, [r12 + TI_NEXTTRY]
    mov rdx, [r12 + TI_DEADLINE]
    mov rcx, [rsp]                       ; original sample; never start another D
    call ssh_session_bind_deadlines
    test eax, eax
    jnz .budget_refused
    pop  rdi
    call term_ssh_observation_begin
    xor  eax, eax
    jmp  .out
.budget_refused:
    add rsp, 8
.exec_refused:
    mov  edi, [r12 + TI_SESS]
    call ssh_session_end
    mov  dword [r12 + TI_SESS], -1
    mov  eax, -11
    jmp  .out
.stale:
    mov  eax, -1
.out:
    pop  rbx
    ret

;; term_title_sync(R12): catalogue TRM-07. The window (and so its taskbar
;; button) is titled by the program's OSC 0/2 title, printable ASCII up to 39
;; characters, or "Terminal" when none is set (the local shell, or after the
;; ssh session ended). Repaints only when the title changes. Hub: the title is
;; the slot's app label (wm_app_title, shown through wmx_label_ptr; the WM close
;; path clears it); wm_title keeps the identity "Terminal".
term_title_sync:
    push rbx
    mov  rax, [r12 + TI_VT]
    mov  ecx, [rax + VT.titlelen]
    lea  rsi, [rax + VT.title]
    lea  rdi, [rel term_title_new]
    xor  edx, edx
    xor  ebx, ebx
.scan:
    cmp  ebx, ecx
    jae  .scanned
    mov  al, [rsi + rbx]
    inc  ebx
    cmp  al, 0x20
    jb   .scan
    cmp  al, 0x7e
    ja   .scan
    cmp  al, ' '
    jne  .keep
    test edx, edx
    jz   .scan                          ; no leading blanks (Claude Code's "* Claude Code")
.keep:
    cmp  edx, TERM_TITLE_MAX - 1
    jae  .scanned
    mov  [rdi + rdx], al
    inc  edx
    jmp  .scan
.scanned:
    test edx, edx
    jz   .trimmed
    cmp  byte [rdi + rdx - 1], ' '
    jne  .trimmed
    dec  edx                            ; nor trailing ones
    jmp  .scanned
.trimmed:
    test edx, edx
    jnz  .named
    lea  rsi, [rel term_title]
.dflt:
    mov  al, [rsi + rdx]
    mov  [rdi + rdx], al
    test al, al
    jz   .compare
    inc  edx
    jmp  .dflt
.named:
    mov  byte [rdi + rdx], 0
.compare:
    lea  rsi, [r12 + TI_TITLE]
    call strcmp
    test rax, rax
    jz   .out
    lea  rsi, [rel term_title_new]
    lea  rdi, [r12 + TI_TITLE]
    mov  ecx, TERM_TITLE_MAX
    cld
    rep  movsb
    mov  ecx, [r12 + TI_WIN]
    lea  rax, [rel wm_app_title]
    lea  rdx, [r12 + TI_TITLE]
    mov  [rax + rcx*8], rdx
    inc  dword [rel term_title_changes]
    call wmx_draw_all                   ; title bar and taskbar button
.out:
    pop  rbx
    ret

;; term_ssh_fail_text -> RSI the message for ssh_cli_error (the loaded
;; session), RAX = the generic text (RSI == RAX: no specific reason)
term_ssh_fail_text:
    lea  rax, [rel term_ssh_failed_text]
    movzx ecx, byte [rel ssh_cli_error]
    lea  r9, [rel term_ssh_fail_table]
    mov  rdx, r9
.scan:
    mov  r8d, [rdx]
    test r8d, r8d
    jz   .generic
    cmp  r8d, ecx
    je   .hit
    add  rdx, 8
    jmp  .scan
.hit:
    movsxd rsi, dword [rdx + 4]
    add  rsi, r9
    ret
.generic:
    mov  rsi, rax
    ret

;; Snapshot the observed remote outcome while its session is still selected.
;; Fixed text uses canonical formatters; all remote bytes become printable ASCII
;; before passing through term_out/VT. Buffer bound: <128 fixed +64+160+32 +10.
term_ssh_completion_text:
%ifdef PAOS_TERMINAL_SSH
    push rbx
    lea  rbx, [rel term_ssh_completion_buf]
    cmp  dword [rel ssh_cli_exit_kind], 1
    je   .status
    cmp  dword [rel ssh_cli_exit_kind], 2
    je   .signal
    pop  rbx
%endif
    lea  rsi, [rel term_ssh_outcome_unknown]
    ret
%ifdef PAOS_TERMINAL_SSH
.status:
    lea  rdi, [rel term_ssh_outcome_status]
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    mov  edi, [rel ssh_cli_exit_status]  ; zero-extend uint32, including UINT32_MAX
    mov  rsi, rbx
    call fmt_dec
    add  rbx, rax
    jmp  .end
.signal:
    lea  rdi, [rel term_ssh_outcome_signal]
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    lea  rsi, [rel ssh_cli_exit_signal]
    mov  ecx, [rel ssh_cli_exit_signal_len]
    call term_ssh_safe_text
    lea  rdi, [rel term_ssh_outcome_core_no]
    cmp  dword [rel ssh_cli_exit_core], 0
    je   .core
    lea  rdi, [rel term_ssh_outcome_core_yes]
.core:
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    lea  rsi, [rel ssh_cli_exit_message]
    mov  ecx, [rel ssh_cli_exit_message_len]
    call term_ssh_safe_text
    lea  rdi, [rel term_ssh_outcome_language]
    mov  rsi, rbx
    call fmt_str
    add  rbx, rax
    lea  rsi, [rel ssh_cli_exit_language]
    mov  ecx, [rel ssh_cli_exit_language_len]
    call term_ssh_safe_text
.end:
    lea  rdi, [rel term_ssh_outcome_end]
    mov  rsi, rbx
    call fmt_str
    lea  rsi, [rel term_ssh_completion_buf]
    pop  rbx
    ret
%endif

;; RSI=bounded admitted bytes, ECX=len; RBX advances in the completion buffer.
;; Controls, DEL, non-ASCII and embedded NUL cannot act as terminal instructions.
term_ssh_safe_text:
    test ecx, ecx
    jz   .out
.loop:
    lodsb
    cmp  al, 32
    jb   .replace
    cmp  al, 126
    jbe  .put
.replace:
    mov  al, '?'
.put:
    mov  [rbx], al
    inc  rbx
    dec  ecx
    jnz  .loop
.out:
    ret

;; term_ssh_dial_error(R12, EAX = -1 bad address, -2 no ARP entry, -3 entropy,
;; -4 no free session, -5 TCB table full, -6 SYN not sent, -7 network down,
;; -8 could not open (TCB table full or SYN not sent: hub TCP gives no reason),
;; -9 not an owner session, -10 the client identity is refused (RCQ-08))
term_ssh_dial_error:
    mov  byte [r12 + TI_SSH], 0
    lea  rsi, [rel term_ssh_nosession]
    cmp  eax, -4
    je   .msg
    lea  rsi, [rel term_ssh_tcbfull]
    cmp  eax, -5
    je   .msg
    lea  rsi, [rel term_ssh_nosend]
    cmp  eax, -6
    je   .msg
    lea  rsi, [rel term_ssh_netdown]
    cmp  eax, -7
    je   .msg
    lea  rsi, [rel term_ssh_noopen]
    cmp  eax, -8
    je   .msg
    lea  rsi, [rel term_ssh_exec_local_refused]
    cmp  eax, -11
    je   .msg
    lea  rsi, [rel term_ssh_owner_only]
    cmp  eax, -9
    je   .msg
    lea  rsi, [rel term_ssh_unverified]
    cmp  eax, -10
    je   .msg
    lea  rsi, [rel term_ssh_noroute]
    cmp  eax, -2
    je   .msg
    lea  rsi, [rel term_ssh_badarg]
    cmp  eax, -1
    je   .msg
    lea  rsi, [rel term_ssh_entropy]
.msg:
    call term_out_cstr
    jmp  term_prompt

;; term_arp_request: one ARP request for the dial target from the primary
;; route's own address (best effort; the reply fills the ARP cache).
term_arp_request:
    lea  rdi, [rel term_route]
    call dns_wire_route_snapshot
    test rax, rax
    jnz  .out
    lea  rdi, [rel term_route + dns_route_snapshot.source_mac]
    mov  esi, [rel term_route + dns_route_snapshot.source_ip]
    mov  edx, [r12 + TI_DIALIP]
    lea  rcx, [rel term_arp_frame]
    mov  r8d, 64
    call udp4_arp_request
    inc  dword [rel term_arp_requests]
.out:
    ret

;; term_ssh_resolving_tick(R12): dial as soon as the ARP answer is cached;
;; re-ask every 400 ms; give up after 3 s
term_ssh_resolving_tick:
    push rbx
    call term_ssh_lookup_ptr
    mov  rbx, rax
    cmp  dword [rbx + TS_VALID], 1
    jne  .legacy
    call term_ssh_lookup_current
    test eax, eax
    jz   .stale
    cmp  dword [rbx + TS_PHASE], 1
    je   .dns
    pop  rbx
    jmp  term_ssh_arp_tick
.legacy:
    cmp  dword [rbx + TS_KIND], 1
    je   .stale
    pop  rbx
    jmp  term_ssh_arp_tick
.dns:
    pop  rbx
    jmp  term_ssh_lookup_tick
.stale:
    pop  rbx
    jmp  term_ssh_lookup_stale

term_ssh_arp_tick:
    call time_monotonic_now_us
    cmp  rax, [r12 + TI_DEADLINE]
    jae  .noroute
    mov  edi, [r12 + TI_DIALIP]
    call arp_cache_lookup
    test rax, rax
    jz   .waiting
    call term_ssh_dial
    test eax, eax
    jz   .out                           ; resolved and attached
    jmp  term_ssh_dial_error
.waiting:
    call time_monotonic_now_us
    cmp  rax, [r12 + TI_DEADLINE]
    jae  .noroute
    cmp  rax, [r12 + TI_NEXTTRY]
    jb   .out
    add  rax, TERM_ARP_RETRY_US
    mov  [r12 + TI_NEXTTRY], rax
    jmp  term_arp_request
.noroute:
    mov  eax, -2
    jmp  term_ssh_dial_error
.out:
    ret

;; terminal_ssh_sink(RDI data, ESI len): CHANNEL_DATA from ssh_cli_poll
terminal_ssh_sink:
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rdi
    mov  r14d, esi
    xor  ebx, ebx                       ; the window whose session is loaded now
.find:
    cmp  ebx, TERM_MAX
    jae  .out
    mov  edi, ebx
    call term_inst_ptr
    mov  r12, rax
    test r12, r12
    jz   .out                           ; no table: no session sink
    inc  ebx
    cmp  byte [r12 + TI_USED], 1
    jne  .find
    cmp  byte [r12 + TI_SSH], 1
    jne  .find
    mov  eax, [r12 + TI_SESS]
    cmp  eax, [rel ssh_sess_active]
    jne  .find
    call term_echo_sample
    call term_flush_replies             ; older admitted query answers keep their order
    call term_reply_bind                ; only this real remote-data path binds new answers
    mov  rsi, r13
    mov  edx, r14d
    call term_out
    call term_flush_replies
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; term_echo_sample(R12): the first remote bytes after a typed key close one
;; keystroke -> echo latency sample (catalogue SSH-10, measured inside PaOS: the
;; harness's own round trips on metal are ~0.1 s and would drown it).
term_echo_sample:
    mov  rcx, [r12 + TI_ECHO_T0]
    test rcx, rcx
    jz   .out
    push rcx
    call time_monotonic_now_us
    pop  rcx
    mov  qword [r12 + TI_ECHO_T0], 0
    sub  rax, rcx
    jb   .out
    mov  ecx, 0xFFFFFFFF                ; (a cmp imm32 would sign-extend to all-ones)
    cmp  rax, rcx
    jbe  .fits
    mov  eax, 0xFFFFFFFF
.fits:
    inc  dword [r12 + TI_ECHO_N]
    add  [r12 + TI_ECHO_SUM], rax
    cmp  eax, [r12 + TI_ECHO_MAX]
    jbe  .bucket
    mov  [r12 + TI_ECHO_MAX], eax
.bucket:
    xor  ecx, ecx
    cmp  eax, 10000
    jb   .count
    inc  ecx
    cmp  eax, 25000
    jb   .count
    inc  ecx
    cmp  eax, 50000
    jb   .count
    inc  ecx
    cmp  eax, 100000
    jb   .count
    inc  ecx
    cmp  eax, 250000
    jb   .count
    inc  ecx
.count:
    inc  dword [r12 + TI_ECHO_B + rcx*4]
.out:
    ret

;; Replies use the VT's bounded batch, not a second transport queue. Each
;; generated unit is complete; admitting the whole batch keeps its order and
;; prevents a user event from splitting a reply's escape sequence.
term_flush_replies:
    push rbx
    push r13
    mov  rbx, [r12 + TI_VT]
    mov  r13d, [rbx + VT.replylen]
    test r13d, r13d
    jz   .out
    cmp  r13d, VT_REPLYMAX
    ja   .drop
    cmp  byte [r12 + TI_USED], 1
    jne  .drop
    cmp  byte [r12 + TI_SSH], 1
    jne  .drop
    call term_inst_index
    lea  rdx, [rel term_reply_sessions]
    mov  edi, [r12 + TI_SESS]
    cmp  edi, [rdx + rax*4]
    jne  .drop
    lea  rdx, [rel term_paste_generations]
    mov  rcx, [rdx + rax*8]
    lea  rdx, [rel term_reply_generations]
    cmp  rcx, [rdx + rax*8]
    jne  .drop
    call ssh_session_use
    cmp  byte [rel ssh_cli_chan_closed], 1
    je   .drop
    cmp  byte [rel ssh_cli_state], SSH_CLI_ST_FAILED
    je   .drop
    cmp  byte [rel ssh_cli_chan_ready], 1
    jne  .out
    mov  eax, SSH_TXQ_CAP
    sub  eax, [rel ssh_cli_txq_len]
    jb   .out
    cmp  eax, r13d
    jb   .out
    lea  rdi, [rbx + VT.reply]
    mov  esi, r13d                       ; reload protected pointer/length after session use
    call ssh_cli_enqueue_input
    add  [rel term_reply_bytes], r13d     ; REPLIED counts bytes actually admitted
.drop:
    call term_reply_forget
.out:
    pop  r13
    pop  rbx
    ret

;; Bind only an empty batch, before real remote output generates replies.
term_reply_bind:
    mov  rax, [r12 + TI_VT]
    cmp  dword [rax + VT.replylen], 0
    jne  .out
    call term_inst_index
    lea  rdx, [rel term_reply_sessions]
    mov  ecx, [r12 + TI_SESS]
    mov  [rdx + rax*4], ecx
    lea  rdx, [rel term_paste_generations]
    mov  rcx, [rdx + rax*8]
    lea  rdx, [rel term_reply_generations]
    mov  [rdx + rax*8], rcx
.out:
    ret

term_reply_forget:
    mov  rcx, [r12 + TI_VT]
    test rcx, rcx
    jz   .identity
    mov  dword [rcx + VT.replylen], 0
.identity:
    call term_inst_index
    lea  rdx, [rel term_reply_sessions]
    mov  dword [rdx + rax*4], -1
    lea  rdx, [rel term_reply_generations]
    mov  qword [rdx + rax*8], 0
    ret

;; ---------------------------------------------------------------------------
;; terminal_termfeed(EDI = instance, EBX = WM slot, RSI = text after the window)
;; The TERMFEED evidence seam for a Terminal window. Replies are staged in
;; grid_out, starting like the console's (" TFEED=1 WIN=<w> RC=<rc>").
;;   @RAW <hex>                   bytes as if received from the remote (captured)
;;   @KEY <hex>                   Set-1 scancodes through the shared keyboard ring
;;   @SSHOBS                      actual dial/deadline/detach snapshot (read-only)
;;   @SSHDUE                      last pass before the caller ceiling (read-only)
;;   @VTSTAT                      geometry, cursor, modes, SSH, capture, screen CRC
;;   @VTCELLS <row> <col> <n>     cells cp:fg:bg:flags:width (hex), n <= 16
;;   @VTCAP <offset> <n>          capture-ring bytes (hex), n <= 200
;;   @VTRZ <i>                    resize log entry i: capture offset, cols, rows
;; -> EAX 0 ok, 4 malformed, 5 oversized
; Read-only current public ID for this Terminal slot. Existing predicates stay
; unchanged: no gui.read grant, window enumeration, content read or policy write.
term_public_window_id:
    push rbx
    push r12
    mov  r12d, edi
    xor  eax, eax
    cmp  edi, WM_MAX - 1              ; reserved lock/chrome slot is never public
    jae  .out
    cmp  dword [rel wm_state + (WM_MAX - 1)*4], WM_VISIBLE
    je   .out                        ; no desktop ID while lock surface is shown
    call wmx_window_id               ; original live/minimized stamped generation
    test eax, eax
    jz   .out
    mov  ebx, eax
    mov  edi, eax
    xor  esi, esi                    ; window only, never a widget/content read
    call wmx_history_target          ; current/public/no-history, unchanged
    cmp  eax, r12d
    jne  .withheld
    mov  eax, ebx
    jmp  .out
.withheld:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

terminal_termfeed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, ebx
    mov  r13, rsi
    call term_inst_ptr
    mov  r12, rax
    test rax, rax
    jnz  .have_inst
    mov  eax, 4                         ; no table: malformed request, nothing touched
    jmp  .out
.have_inst:
    call grid_out_reset
    lea  rdi, [rel term_str_tfeed]
    call grid_out_str
    mov  edi, r15d
    call grid_out_dec
    lea  rdi, [rel term_str_rc]
    call grid_out_str
    lea  rsi, [rel term_sub_raw]
    call .kw
    jnz  .raw
    lea  rsi, [rel term_sub_key]
    call .kw
    jnz  .key
    lea  rsi, [rel term_sub_sshobs]
    call .kw
    jnz  .sshobs
    lea  rsi, [rel term_sub_sshkeyobs]
    call .kw
    jnz  .sshkeyobs
    lea  rsi, [rel term_sub_sshstartobs]
    call .kw
    jnz  .sshstartobs
    lea  rsi, [rel term_sub_sshdue]
    call .kw
    jnz  .sshdue
    lea  rsi, [rel term_sub_stat]
    call .kw
    jnz  .stat
    lea  rsi, [rel term_sub_cells]
    call .kw
    jnz  .cells
    lea  rsi, [rel term_sub_row]
    call .kw
    jnz  .row
    lea  rsi, [rel term_sub_cap64]
    call .kw
    jnz  .cap64
    lea  rsi, [rel term_sub_cap]
    call .kw
    jnz  .cap
    lea  rsi, [rel term_sub_rz]
    call .kw
    jnz  .rz
    lea  rsi, [rel term_sub_clip]
    call .kw
    jnz  .clip
    jmp  .malformed
.kw:                                    ; RSI keyword -> ZF clear + RAX = past it
    mov  rdi, r13
    call term_prefix
    test eax, eax
    lea  rax, [r13 + rax]
    ret
.sshdue:
    mov  rdi, rax
    call term_ssh_due_observation_feed
    test eax, eax
    jnz  .malformed
    jmp  .ok
.sshstartobs:
    mov  rdi, rax
    call term_ssh_start_observation_feed
    test eax, eax
    jnz  .malformed
    jmp  .ok
.sshkeyobs:
    mov  rdi, rax
    call term_ssh_key_observation_feed
    test eax, eax
    jnz  .malformed
    jmp  .ok
.sshobs:
    mov  rdi, rax
    call term_ssh_observation_feed
    test eax, eax
    jnz  .malformed
    jmp  .ok
.raw:
    mov  rsi, rax
    mov  edx, TERM_RAW_MAX
    call term_hex_decode                ; -> EAX bytes in term_rawbuf, -1 bad, -2 big
    cmp  eax, -1
    je   .malformed
    cmp  eax, -2
    je   .oversized
    mov  r14d, eax
    mov  rax, [r12 + TI_VT]
    mov  ecx, [rax + VT.replylen]
    cmp  ecx, VT_REPLYMAX
    jbe  .raw_bound
    xor  ecx, ecx
    mov  [rax + VT.replylen], ecx
.raw_bound:
    push rcx                            ; retain earlier real remote answers
    lea  rsi, [rel term_rawbuf]
    mov  edx, r14d
    call term_out
    pop  rcx
    ; SEC D1 C1 (srcreview 18:57:18): these bytes come from the TERMFEED
    ; caller, not the remote. Any queries among them were the injector's, so
    ; their answers never go into a live SSH session as keystrokes. Dropped and
    ; counted with the refused input.
%ifdef PAOS_TERMINAL_GUEST
    cmp  byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne  .raw_not_guest
    call term_guest_raw_quarantine
    jmp  .raw_reply_done
.raw_not_guest:
%endif
    cmp  byte [r12 + TI_SSH], 1
    jne  .raw_replies
    mov  rax, [r12 + TI_VT]
    cmp  [rax + VT.replylen], ecx
    jbe  .raw_restore
    inc  qword [rel term_ssh_input_refused]
.raw_restore:
    mov  [rax + VT.replylen], ecx         ; injected answers never become pending input
.raw_replies:
    call term_flush_replies
.raw_reply_done:
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_raw]
    call grid_out_str
    mov  edi, r14d
    call grid_out_dec
    jmp  .ok
.key:
    mov  rsi, rax
    mov  edx, TERM_KEY_MAX
    call term_hex_decode
    cmp  eax, -1
    je   .malformed
    cmp  eax, -2
    je   .oversized
    test eax, eax
    jz   .malformed
    mov  r14d, eax
    mov  rbx, [rel term_keys_routed]
    xor  r13d, r13d
.key_push:
    cmp  r13d, r14d
    jae  .key_done
    lea  rcx, [rel term_rawbuf]
    movzx eax, byte [rcx + r13]
    mov  rdi, [rel term_feed_req]
    call keyprov_inject_scancode        ; GA0-K: origin INJECTED, bound to the request
    inc  r13d
    test r13d, 15
    jnz  .key_push
    call gui_input_route_tick           ; one router budget per 16 scancodes
    jmp  .key_push
.key_done:
    call gui_input_route_tick           ; deliver now: this reply describes the batch
    ; Enter can synchronously dispatch a command that uses grid_out too. Its
    ; display and transcript are consumed before routing returns; now rebuild
    ; the outer acknowledgement after every routing tick has finished.
    call grid_out_reset
    lea  rdi, [rel term_str_tfeed]
    call grid_out_str
    mov  edi, r15d
    call grid_out_dec
    lea  rdi, [rel term_str_rc]
    call grid_out_str
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_key]
    call grid_out_str
    mov  edi, r14d
    call grid_out_dec
    lea  rdi, [rel term_out_routed]
    call grid_out_str
    mov  rdi, [rel term_keys_routed]
    sub  rdi, rbx
    call grid_out_dec
    jmp  .ok
.stat:
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_stat]
    call grid_out_str
    mov  rbx, [r12 + TI_VT]
    mov  edi, [rbx + VT.cols]
    call grid_out_dec
    lea  rdi, [rel term_out_rows]
    call grid_out_str
    mov  edi, [rbx + VT.rows]
    call grid_out_dec
    lea  rdi, [rel term_out_cur]
    call grid_out_str
    mov  edi, [rbx + VT.cy]
    call grid_out_dec
    mov  dil, ','
    call grid_out_char
    mov  edi, [rbx + VT.cx]
    call grid_out_dec
    lea  rdi, [rel term_out_ssh]
    call grid_out_str
    movzx edi, byte [r12 + TI_SSH]
    call grid_out_dec
%ifdef PAOS_TERMINAL_GUEST
    call term_guest_stat
%endif
    lea  rdi, [rel term_out_public_id]
    call grid_out_str
    mov  edi, r15d
    call term_public_window_id
    mov  edi, eax
    call grid_out_dec
    lea  rdi, [rel term_out_chan]
    call grid_out_str
    xor  edi, edi
    cmp  byte [r12 + TI_SSH], 1
    jne  .chan_put
    mov  edi, [r12 + TI_SESS]
    call ssh_session_use
    movzx edi, byte [rel ssh_cli_chan_ready]
.chan_put:
    call grid_out_dec
    lea  rdi, [rel term_out_pty]
    call grid_out_str
    mov  edi, [r12 + TI_WCOLS]
    call grid_out_dec
    mov  dil, 'x'
    call grid_out_char
    mov  edi, [r12 + TI_WROWS]
    call grid_out_dec
    lea  rdi, [rel term_out_capn]
    call grid_out_str
    mov  rdi, [r12 + TI_CAPTOT]
    call grid_out_dec
    lea  rdi, [rel term_out_ris]
    call grid_out_str
    mov  rdi, [r12 + TI_RISOFF]
    call grid_out_dec
    lea  rdi, [rel term_out_rzn]
    call grid_out_str
    mov  edi, [r12 + TI_RZN]
    call grid_out_dec
    lea  rdi, [rel term_out_view]
    call grid_out_str
    mov  edi, [r12 + TI_VIEWOFF]
    call grid_out_dec
    lea  rdi, [rel term_out_sbn]
    call grid_out_str
    mov  edi, [rbx + VT.sb_count]
    call grid_out_dec
    call term_sb_metrics                ; SBAR=shown/thumb top/thumb height/dragging
    push rdx
    push rcx
    push rax
    lea  rdi, [rel term_out_sbar]
    call grid_out_str
    pop  rdi
    call grid_out_dec
    lea  rdi, [rel term_out_slash]
    call grid_out_str
    pop  rdi
    call grid_out_dec
    lea  rdi, [rel term_out_slash]
    call grid_out_str
    pop  rdi
    call grid_out_dec
    lea  rdi, [rel term_out_slash]
    call grid_out_str
    movzx edi, byte [r12 + TI_SBDRAG]
    call grid_out_dec
    lea  rdi, [rel term_out_sbact]
    call grid_out_str
    mov  rdi, [rel term_sb_actions]
    call grid_out_dec
    lea  rdi, [rel term_out_echo]       ; ECHO=n/sum_us/max_us/b<10/<25/<50/<100/<250/>=250 ms
    call grid_out_str
    mov  edi, [r12 + TI_ECHO_N]
    call grid_out_dec
    mov  dil, '/'
    call grid_out_char
    mov  rdi, [r12 + TI_ECHO_SUM]
    call grid_out_dec
    mov  dil, '/'
    call grid_out_char
    mov  edi, [r12 + TI_ECHO_MAX]
    call grid_out_dec
    xor  ecx, ecx
.echo_b:
    push rcx
    mov  dil, '/'
    call grid_out_char
    mov  rcx, [rsp]
    mov  edi, [r12 + TI_ECHO_B + rcx*4]
    call grid_out_dec
    pop  rcx
    inc  ecx
    cmp  ecx, 6
    jb   .echo_b
    lea  rdi, [rel term_out_focus]
    call grid_out_str
    xor  edi, edi
    cmp  r15d, [rel wm_focus]
    sete dil
    call grid_out_dec
    lea  rdi, [rel term_out_replies]
    call grid_out_str
    mov  edi, [rel term_reply_bytes]
    call grid_out_dec
    lea  rdi, [rel term_out_modes]
    call grid_out_str
    mov  edi, [rbx + VT.modes]
    call term_grid_out_hex32
    lea  rdi, [rel term_out_reflow]
    call grid_out_str
    mov  rdi, [rbx + VT.rf_dropped]
    call grid_out_dec
    mov  dil, ','
    call grid_out_char
    mov  rdi, [rbx + VT.rf_refused]
    call grid_out_dec
    lea  rdi, [rel term_out_marks]
    call grid_out_str
    mov  rdi, [rbx + VT.mark_overflow]
    call grid_out_dec
    mov  dil, ','
    call grid_out_char
    mov  rdi, [rbx + VT.mark_orphan]
    call grid_out_dec
    mov  dil, ','
    call grid_out_char
    mov  edi, [rel term_clip_truncated]
    call grid_out_dec
    lea  rdi, [rel term_out_org]
    call grid_out_str
    mov  edi, [r12 + TI_WID]
    call wgt_slot_ptr
    push rax
    mov  edi, [rax + WGI_X]
    call grid_out_dec
    mov  dil, ','
    call grid_out_char
    pop  rax
    mov  edi, [rax + WGI_Y]
    call grid_out_dec
    lea  rdi, [rel term_out_title]
    call grid_out_str
    mov  edi, [rbx + VT.titlelen]
    call grid_out_dec
    lea  rdi, [rel term_out_crc]
    call grid_out_str
    call term_screen_crc
    mov  edi, eax
    call term_grid_out_hex32
    lea  rdi, [rel term_out_wt]         ; the window title in hex (TRM-07)
    call grid_out_str
    xor  ecx, ecx
.wt:
    movzx edi, byte [r12 + TI_TITLE + rcx]
    test edi, edi
    jz   .ok
    push rcx
    call grid_out_hex_byte
    pop  rcx
    inc  ecx
    cmp  ecx, TERM_TITLE_MAX
    jb   .wt
    jmp  .ok
.cells:
    mov  rdi, rax
    call term_parse_dec
    mov  r14d, eax                      ; row
    call term_parse_dec
    mov  r15d, eax                      ; col
    call term_parse_dec
    cmp  eax, TERM_CELLS_MAX
    jbe  .n_ok
    mov  eax, TERM_CELLS_MAX
.n_ok:
    mov  r13d, eax
    mov  rbx, [r12 + TI_VT]
    cmp  r14d, [rbx + VT.rows]
    jae  .malformed
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_cells]
    call grid_out_str
.cell:
    test r13d, r13d
    jz   .ok
    cmp  r15d, [rbx + VT.cols]
    jae  .ok
    mov  rdi, rbx
    mov  esi, r14d
    mov  edx, r15d
    call vt_cell_ptr
    push rax
    mov  edi, [rax + VTC_CP]
    call term_out_hexc
    mov  dil, ':'
    call grid_out_char
    mov  rax, [rsp]
    mov  edi, [rax + VTC_FG]
    call term_out_hexc
    mov  dil, ':'
    call grid_out_char
    mov  rax, [rsp]
    mov  edi, [rax + VTC_BG]
    call term_out_hexc
    mov  dil, ':'
    call grid_out_char
    mov  rax, [rsp]
    movzx edi, word [rax + VTC_FL]
    call term_out_hexc
    mov  dil, ':'
    call grid_out_char
    pop  rax
    movzx edi, byte [rax + VTC_W]
    call term_out_hexc
    mov  dil, ','
    call grid_out_char
    inc  r15d
    dec  r13d
    jmp  .cell
.row:
    ; @VTROW <row>: one screen row as UTF-8 hex (the text a user reads, cp 0 as
    ; a space, trailing blanks trimmed) -- seven @VTCELLS reads in one (usage
    ; suite on metal, where every exchange costs ~0.1 s). MORE=1: truncated.
    mov  rdi, rax
    call term_parse_dec
    mov  r14d, eax
    mov  rbx, [r12 + TI_VT]
    cmp  r14d, [rbx + VT.rows]
    jae  .malformed
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_row]
    call grid_out_str
    xor  r15d, r15d                     ; column
    xor  r13d, r13d                     ; UTF-8 bytes
    mov  dword [rel term_row_keep], 0
    mov  byte [rel term_row_more], 0
.row_cell:
    cmp  r15d, [rbx + VT.cols]
    jae  .row_hex
    ; Match the painted viewport, including original scrollback rows.
    mov  edi, r14d
    mov  esi, r15d
    call term_view_cell
    inc  r15d
    mov  eax, [rax + VTC_CP]
    test eax, eax
    jnz  .row_enc
    mov  eax, ' '
.row_enc:
    cmp  r13d, TERM_ROW_MAX - 4
    jae  .row_more
    push rax
    lea  rdi, [rel term_rowbuf]
    add  rdi, r13
    call term_utf8_put
    add  r13d, eax
    pop  rax
    cmp  eax, ' '
    je   .row_cell
    mov  [rel term_row_keep], r13d
    jmp  .row_cell
.row_more:
    mov  byte [rel term_row_more], 1
.row_hex:
    xor  r15d, r15d
.row_hex_byte:
    cmp  r15d, [rel term_row_keep]
    jae  .row_tail
    lea  rax, [rel term_rowbuf]
    movzx edi, byte [rax + r15]
    call grid_out_hex_byte
    inc  r15d
    jmp  .row_hex_byte
.row_tail:
    lea  rdi, [rel term_out_more]
    call grid_out_str
    movzx edi, byte [rel term_row_more]
    call grid_out_dec
    jmp  .ok
.cap:
    mov  rdi, rax
    call term_parse_dec
    mov  r14d, eax                      ; absolute stream offset
    call term_parse_dec
    cmp  eax, TERM_CAPRD_MAX
    jbe  .capn_ok
    mov  eax, TERM_CAPRD_MAX
.capn_ok:
    mov  r13d, eax
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_cap]
    call grid_out_str
    mov  edi, r14d
    call grid_out_dec
    lea  rdi, [rel term_out_hex]
    call grid_out_str
    mov  rbx, [r12 + TI_CAP]
.capb:
    test r13d, r13d
    jz   .ok
    mov  eax, r14d
    cmp  rax, [r12 + TI_CAPTOT]
    jae  .ok
    mov  rcx, [r12 + TI_CAPTOT]
    sub  rcx, rax
    cmp  rcx, TERM_CAP_SIZE
    ja   .ok                            ; already overwritten
    and  eax, TERM_CAP_SIZE - 1
    movzx edi, byte [rbx + rax]
    call grid_out_hex_byte
    inc  r14d
    dec  r13d
    jmp  .capb
.cap64:
    ; the same ring bytes, base64 (RFC 4648) for a denser challenged reply
    mov  rdi, rax
    call term_parse_dec
    mov  r14d, eax                      ; absolute stream offset
    call term_parse_dec
    cmp  eax, TERM_CAP64_MAX
    jbe  .c64n_ok
    mov  eax, TERM_CAP64_MAX
.c64n_ok:
    ; clamp to the bytes still held in the ring
    mov  ecx, r14d
    mov  rdx, [r12 + TI_CAPTOT]
    cmp  rcx, rdx
    jae  .c64_empty
    sub  rdx, rcx
    cmp  rdx, TERM_CAP_SIZE
    ja   .c64_empty                     ; already overwritten
    cmp  rdx, rax
    jae  .c64_have
    mov  eax, edx
    jmp  .c64_have
.c64_empty:
    xor  eax, eax
.c64_have:
    mov  r13d, eax                      ; bytes to encode
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_cap]
    call grid_out_str
    mov  edi, r14d
    call grid_out_dec
    lea  rdi, [rel term_out_c64n]
    call grid_out_str
    mov  edi, r13d
    call grid_out_dec
    lea  rdi, [rel term_out_b64]
    call grid_out_str
    mov  rbx, [r12 + TI_CAP]
.c64_group:
    test r13d, r13d
    jz   .c64_zero_check
    ; gather up to 3 bytes into r15d (big-endian 24 bits), r10d = count
    xor  r15d, r15d
    xor  r10d, r10d
.c64_byte:
    shl  r15d, 8
    cmp  r10d, r13d
    jae  .c64_pad_byte
    mov  eax, r14d
    add  eax, r10d
    and  eax, TERM_CAP_SIZE - 1
    movzx eax, byte [rbx + rax]
    or   r15d, eax
.c64_pad_byte:
    inc  r10d
    cmp  r10d, 3
    jb   .c64_byte
    mov  r10d, r13d                     ; real bytes in this group (1..3)
    cmp  r10d, 3
    jbe  .c64_real
    mov  r10d, 3
.c64_real:
    mov  ecx, 18
    call .c64_sextet
    mov  ecx, 12
    call .c64_sextet
    mov  ecx, 6
    cmp  r10d, 2
    jb   .c64_pad2
    call .c64_sextet
    xor  ecx, ecx
    cmp  r10d, 3
    jb   .c64_pad1
    call .c64_sextet
    jmp  .c64_next
.c64_pad2:
    mov  edi, '='
    call grid_out_char
.c64_pad1:
    mov  edi, '='
    call grid_out_char
.c64_next:
    add  r14d, r10d
    sub  r13d, r10d
    jmp  .c64_group
.c64_zero_check:
    jmp  .ok
.c64_sextet:                            ; ECX = shift: emit alphabet[(r15d >> cl) & 63]
    mov  eax, r15d
    shr  eax, cl
    and  eax, 63
    lea  rdx, [rel term_b64_alphabet]
    movzx edi, byte [rdx + rax]
    push r10
    call grid_out_char
    pop  r10
    ret
.rz:
    mov  rdi, rax
    call term_parse_dec
    cmp  eax, TERM_RZ_LOG
    jae  .malformed
    lea  rbx, [r12 + TI_RZLOG + rax*8]
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_rz]
    call grid_out_str
    mov  edi, [rbx]
    call grid_out_dec
    lea  rdi, [rel term_out_rzsize]
    call grid_out_str
    movzx edi, word [rbx + 4]
    call grid_out_dec
    mov  dil, 'x'
    call grid_out_char
    movzx edi, word [rbx + 6]
    call grid_out_dec
    jmp  .ok
.clip:
    ; @CLIP <offset>: selection state and the shared clipboard (hex, <=160 B)
    mov  rdi, rax
    call term_parse_dec
    mov  r14d, eax
    xor  edi, edi
    call grid_out_dec
    lea  rdi, [rel term_out_sub_clip]
    call grid_out_str
    movzx edi, byte [r12 + TI_SEL]
    call grid_out_dec
    lea  rdi, [rel term_out_clip_len]
    call grid_out_str
    mov  edi, [rel term_clip_len]
    call grid_out_dec
    lea  rdi, [rel term_out_clip_copies]
    call grid_out_str
    mov  edi, [rel term_clip_copies]
    call grid_out_dec
    lea  rdi, [rel term_out_clip_pastes]
    call grid_out_str
    mov  edi, [rel term_clip_pastes]
    call grid_out_dec
    lea  rdi, [rel term_out_clip_hex]
    call grid_out_str
    lea  ebx, [r14d + 160]
    cmp  ebx, [rel term_clip_len]
    jbe  .clip_byte
    mov  ebx, [rel term_clip_len]
.clip_byte:
    cmp  r14d, ebx
    jae  .ok
    lea  rax, [rel term_clip]
    movzx eax, byte [rax + r14]
    push rax
    shr  eax, 4
    lea  rcx, [rel term_hexdigits]
    movzx edi, byte [rcx + rax]
    call grid_out_char
    pop  rax
    and  eax, 15
    lea  rcx, [rel term_hexdigits]
    movzx edi, byte [rcx + rax]
    call grid_out_char
    inc  r14d
    jmp  .clip_byte
.oversized:
    mov  eax, 5
    jmp  .refuse
.malformed:
    mov  eax, 4
.refuse:
    push rax
    call grid_out_reset
    lea  rdi, [rel term_str_tfeed]
    call grid_out_str
    mov  edi, r15d
    call grid_out_dec
    lea  rdi, [rel term_str_rc]
    call grid_out_str
    mov  edi, [rsp]
    call grid_out_dec
    pop  rax
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

;; term_prefix(RDI text, RSI keyword) -> EAX keyword length when text starts
;; with it and the next byte ends the word (NUL or space); else 0
term_prefix:
    xor  eax, eax
.l:
    mov  cl, [rsi + rax]
    test cl, cl
    jz   .end
    cmp  cl, [rdi + rax]
    jne  .no
    inc  eax
    jmp  .l
.end:
    mov  cl, [rdi + rax]
    test cl, cl
    jz   .yes
    cmp  cl, ' '
    jne  .no
    inc  eax                            ; consume the separating space
.yes:
    ret
.no:
    xor  eax, eax
    ret

;; term_hex_decode(RSI hex text, EDX max bytes) -> EAX count in term_rawbuf,
;; -1 malformed, -2 oversized
term_hex_decode:
    push rbx
    xor  ebx, ebx
.l:
    movzx edi, byte [rsi]
    test edi, edi
    jz   .done
    cmp  ebx, edx
    jae  .big
    call term_hexval
    cmp  eax, -1
    je   .bad
    mov  ecx, eax
    shl  ecx, 4
    movzx edi, byte [rsi + 1]
    call term_hexval
    cmp  eax, -1
    je   .bad
    or   eax, ecx
    lea  rcx, [rel term_rawbuf]
    mov  [rcx + rbx], al
    inc  ebx
    add  rsi, 2
    jmp  .l
.done:
    mov  eax, ebx
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret
.big:
    mov  eax, -2
    pop  rbx
    ret

term_hexval:
    cmp  edi, '0'
    jb   .bad
    cmp  edi, '9'
    jbe  .d
    or   edi, 0x20
    cmp  edi, 'a'
    jb   .bad
    cmp  edi, 'f'
    ja   .bad
    lea  eax, [edi - 'a' + 10]
    ret
.d:
    lea  eax, [edi - '0']
    ret
.bad:
    mov  eax, -1
    ret

;; term_parse_dec(RDI) -> EAX, RDI advanced past spaces and digits
term_parse_dec:
    xor  eax, eax
.ws:
    cmp  byte [rdi], ' '
    jne  .d
    inc  rdi
    jmp  .ws
.d:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul eax, eax, 10
    add  eax, ecx
    inc  rdi
    jmp  .d
.done:
    ret

;; term_out_hexc(EDI): lower-case hex without leading zeros ("0" for zero)
term_out_hexc:
    push rbx
    push r12
    mov  r12d, edi
    mov  ebx, 28
.skip:
    test ebx, ebx
    jz   .emit
    mov  eax, r12d
    mov  ecx, ebx
    shr  eax, cl
    test eax, 0xf
    jnz  .emit
    sub  ebx, 4
    jmp  .skip
.emit:
    mov  eax, r12d
    mov  ecx, ebx
    shr  eax, cl
    and  eax, 0xf
    lea  rcx, [rel term_hexdigits]
    movzx edi, byte [rcx + rax]
    call grid_out_char
    sub  ebx, 4
    jns  .emit
    pop  r12
    pop  rbx
    ret

;; term_screen_crc(R12) -> EAX: CRC-32 over the visible cells' 15 canonical
;; bytes each (cp, fg, bg, flags, width), row-major
term_screen_crc:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, [r12 + TI_VT]
    mov  ebx, 0xffffffff
    xor  r14d, r14d
.row:
    cmp  r14d, [r13 + VT.rows]
    jge  .done
    xor  r15d, r15d
.col:
    cmp  r15d, [r13 + VT.cols]
    jge  .next_row
    mov  rdi, r13
    mov  esi, r14d
    mov  edx, r15d
    call vt_cell_ptr
    mov  rsi, rax
    mov  ecx, 15
.byte:
    movzx eax, byte [rsi]
    xor  bl, al
    mov  edx, 8
.bit:
    shr  ebx, 1
    jnc  .nb
    xor  ebx, 0xedb88320
.nb:
    dec  edx
    jnz  .bit
    inc  rsi
    dec  ecx
    jnz  .byte
    inc  r15d
    jmp  .col
.next_row:
    inc  r14d
    jmp  .row
.done:
    mov  eax, ebx
    not  eax
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

;; ---------------------------------------------------------------------------
;; ---------------------------------------------------------------------------
;; Hub packet 0009: the hub kit has no mono-bitmap glyph blit (wgt_draw_glyph
;; renders only the kit's own font8x16 table), so the Terminal draws its Unicode
;; 8x16 / 16x16 glyphs through the kit's existing wgt_fill_rect: one cell
;; background, then one 1-px-high fill per run of set pixels in each row. The
;; contract and the pixels equal the MSI spoke's kit blits (same decorations,
;; same clip: skip a glyph crossing the screen edge or the taskbar). Callers
;; bracket a repaint in a cadence batch, so a screenful is one present.
;; term_blit_mono8x16(RSI = 16-byte bitmap, R8D x, R9D y, EBX fg, ECX bg,
;;   EDX flags: bit1 underline, bit2 italic, bit4 strike). Preserves all.
term_blit_mono8x16:
    push rax
    push rbx
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  eax, r8d
    add  eax, 8
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, 16 + TASKBAR_H
    cmp  eax, [rel fb_height]
    ja   .done
    mov  r15d, ebx                      ; fg
    test edx, TERM_BLIT_OVERLAY
    jnz  .foreground
    mov  ebx, ecx                       ; the cell background first
    mov  r10d, 8
    mov  r11d, 16
    call wgt_fill_rect
.foreground:
    mov  ebx, r15d
    mov  ebp, r8d                       ; cell origin
    mov  r15d, r9d
    mov  r11d, 1
    xor  r12d, r12d                     ; row
.row:
    movzx eax, byte [rsi + r12]
    test edx, 4
    jz   .no_ital
    cmp  r12d, 7
    jae  .no_ital
    shr  eax, 1                         ; lean the upper half right
.no_ital:
    cmp  r12d, 15
    jne  .no_ul
    test edx, 2
    jz   .no_ul
    mov  eax, 0xff
.no_ul:
    cmp  r12d, 8
    jne  .no_st
    test edx, 16
    jz   .no_st
    mov  eax, 0xff
.no_st:
    xor  r13d, r13d                     ; column, MSB = leftmost
.scan:
    cmp  r13d, 8
    jae  .next_row
    mov  edi, 7
    sub  edi, r13d
    bt   eax, edi
    jc   .run_start
    inc  r13d
    jmp  .scan
.run_start:
    mov  r14d, r13d
.run:
    inc  r13d
    cmp  r13d, 8
    jae  .emit
    mov  edi, 7
    sub  edi, r13d
    bt   eax, edi
    jc   .run
.emit:
    lea  r8d, [rbp + r14]
    lea  r9d, [r15 + r12]
    mov  r10d, r13d
    sub  r10d, r14d
    call wgt_fill_rect
    jmp  .scan
.next_row:
    inc  r12d
    cmp  r12d, 16
    jb   .row
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rbx
    pop  rax
    ret

;; term_blit_mono16x16(RSI = 32-byte bitmap, 2 bytes/row, MSB left): as above
;; (no italic for a wide glyph, as the spoke kit).
term_blit_mono16x16:
    push rax
    push rbx
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  eax, r8d
    add  eax, 16
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, 16 + TASKBAR_H
    cmp  eax, [rel fb_height]
    ja   .done
    mov  r15d, ebx
    test edx, TERM_BLIT_OVERLAY
    jnz  .foreground
    mov  ebx, ecx
    mov  r10d, 16
    mov  r11d, 16
    call wgt_fill_rect
.foreground:
    mov  ebx, r15d
    mov  ebp, r8d
    mov  r15d, r9d
    mov  r11d, 1
    xor  r12d, r12d
.row:
    movzx eax, byte [rsi + r12*2]
    shl  eax, 8
    movzx edi, byte [rsi + r12*2 + 1]
    or   eax, edi
    cmp  r12d, 15
    jne  .no_ul
    test edx, 2
    jz   .no_ul
    mov  eax, 0xffff
.no_ul:
    cmp  r12d, 8
    jne  .no_st
    test edx, 16
    jz   .no_st
    mov  eax, 0xffff
.no_st:
    xor  r13d, r13d
.scan:
    cmp  r13d, 16
    jae  .next_row
    mov  edi, 15
    sub  edi, r13d
    bt   eax, edi
    jc   .run_start
    inc  r13d
    jmp  .scan
.run_start:
    mov  r14d, r13d
.run:
    inc  r13d
    cmp  r13d, 16
    jae  .emit
    mov  edi, 15
    sub  edi, r13d
    bt   eax, edi
    jc   .run
.emit:
    lea  r8d, [rbp + r14]
    lea  r9d, [r15 + r12]
    mov  r10d, r13d
    sub  r10d, r14d
    call wgt_fill_rect
    jmp  .scan
.next_row:
    inc  r12d
    cmp  r12d, 16
    jb   .row
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rbx
    pop  rax
    ret

;; ===========================================================================
;; Hub seams (packet 0009). Everything below talks to the hub only through
;; interfaces it already has; nothing in the kit, router or registry changes.
;; ===========================================================================

;; terminal_hub_seams: called once from terminal_app_init (after console_app_init)
terminal_hub_seams:
    ; LAUNCH app_terminal: extend the LAUNCH row in place, exactly as console_app
    ; does for app_console; every other app name tail-dispatches to the handler
    ; that was there before (the Console's, then the form apps').
    lea  rdi, [rel term_str_launch]
    call command_lookup
    cmp  eax, -1
    je   .no_launch
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    add  rcx, rax
    mov  rax, [rcx + VERB_HANDLER]
    mov  [rel term_launch_fallback], rax
    lea  rax, [rel terminal_cmd_launch]
    mov  [rcx + VERB_HANDLER], rax
.no_launch:
    ; TERMFEED: the Terminal's own evidence verb. Destructive (it injects bytes
    ; and keys), so a remote caller needs an owner AUTH1 envelope.
    lea  rdi, [rel term_str_termfeed]
    lea  rsi, [rel terminal_cmd_termfeed]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
%ifdef PAOS_TERMINAL_SSH
    ; SSHCLIKEY (0014): the ssh client public key as an authorized_keys line;
    ; the private key never leaves PaOS. RCQ-08: ENROLL / RESET (the owner's
    ; only; they write PaOSSshClientId, so the row is destructive).
    lea  rdi, [rel term_str_sshclikey]
    lea  rsi, [rel terminal_cmd_sshclikey]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
%endif
    ; keys: chain the kit's filter (the lock screen installed one before us)
    mov  rax, [rel wgt_key_filter]
    mov  [rel term_key_filter_prev], rax
    lea  rax, [rel terminal_key_filter]
    mov  [rel wgt_key_filter], rax
    ; wheel: the window under the pointer; non-Terminal windows keep the WM rule
    lea  rdi, [rel terminal_wheel_hook]
    call ps2_pointer_set_wheel_hook
    ret

;; terminal_cmd_launch(RDI = req, RSI = rsp): LAUNCH app_terminal, else fallback
terminal_cmd_launch:
    cmp qword [rel terminal_terminal_launch_op],0
    je .ordinary
    push rdi
    push rsi
    call [rel terminal_terminal_launch_op]
    pop rsi
    pop rdi
    cmp eax,-1
    je .ordinary
    ret
.ordinary:
    call form_verb_unlocked             ; RCQ-16 F2b-1: refused under the lock, first
    test eax, eax
    jz   .unlocked
    ret
.unlocked:
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .fallback
    push rdi
    push rsi
    mov  rdi, rax
    lea  rsi, [rel term_str_app]
    call strcmp
    pop  rsi
    pop  rdi
    test rax, rax
    jnz  .fallback
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rsi
    call terminal_open                  ; -> EAX WM slot or -1
    mov  r13d, eax
    call form_out_reset
    cmp  r13d, -1
    je   .refused
    lea  rdi, [rel term_str_launch_ok]
    call form_out_put_str
    mov  edi, r13d
    call form_out_put_dec
    mov  [r12 + RSP_VAL], r13
    jmp  .stage
.refused:
    lea  rdi, [rel term_limit_notice]
    call serial_string
    lea  rdi, [rel term_str_launch_err]
    call form_out_put_str
    mov  qword [r12 + RSP_VAL], 0
.stage:
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    ret
.fallback:
    jmp  qword [rel term_launch_fallback]

%ifdef PAOS_TERMINAL_SSH
;; terminal_cmd_sshclikey(RDI = req, RSI = rsp): SSHCLIKEY [ENROLL | RESET].
;; Bare: "SSHCLIKEY ssh-ed25519 <base64> paos-client" (RSP_VAL 1), or
;; "SSHCLIKEY ERR no key" / "SSHCLIKEY ERR identity_unverified ..." (RSP_VAL 0).
;; RCQ-08 ENROLL (keep the key across restarts) and RESET (a new key) are the
;; owner's only: a clean console line, or a remote request's own consumed AUTH1
;; owner ticket (command_auth_owner_request 1). Never over SSH, from an injected
;; line, SYSTEM or the AI: "SSHCLIKEY REFUSED owner_only" (CMDE_AUTHDENY).
;; Success replies with the key's line, as bare SSHCLIKEY does.
terminal_cmd_sshclikey:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdi
    call form_out_reset
    mov  rbx, [r13 + REQ_ARG]
    test rbx, rbx
    jz   .show
    cmp  byte [rbx], 0
    je   .show
    mov  rdi, rbx
    lea  rsi, [rel term_str_sshclikey_enroll_word]
    call term_sshclikey_word
    test eax, eax
    jnz  .enroll
    mov  rdi, rbx
    lea  rsi, [rel term_str_sshclikey_reset_word]
    call term_sshclikey_word
    test eax, eax
    jz   .badarg
    mov  ebx, 1                         ; RESET
    jmp  .gate
.enroll:
    xor  ebx, ebx                       ; ENROLL
.gate:
    mov  rdi, r13
    call command_auth_ticket_owner      ; OWNER principal; a console line not injected
    test eax, eax
    jz   .not_owner
    cmp  qword [r13 + REQ_SOURCE], CMD_SOURCE_CONSOLE
    je   .owner
    call command_auth_owner_request     ; remote: only its own AUTH1 owner ticket (1), never SSH (2)
    cmp  eax, 1
    jne  .not_owner
.owner:
    mov  edi, ebx
    call ssh_cli_identity_enroll
    test eax, eax
    js   .enroll_failed
    test ebx, ebx
    jz   .show                          ; ENROLL retains the existing public reply
    lea  rdi, [rel term_str_sshclikey_reset_complete]
    call form_out_put_str              ; verified RESET: explain loss and reenrollment
    jmp  .show
.enroll_failed:
    cmp  eax, -2
    je   .write_failed
    lea  rdi, [rel term_str_sshclikey_enroll_refused]
    test ebx, ebx
    jz   .err_text
    lea  rdi, [rel term_str_sshclikey_reset_refused]
    jmp  .err_text
.write_failed:
    lea  rdi, [rel term_str_sshclikey_write_failed]
    jmp  .err_text
.badarg:
    lea  rdi, [rel term_str_sshclikey_usage]
    call form_out_put_str
    mov  qword [r12 + RSP_ACCEPTED], 0
    mov  qword [r12 + RSP_VAL], 0
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    jmp  .stage
.not_owner:
    lea  rdi, [rel term_str_sshclikey_owner_only]
    call form_out_put_str
    mov  qword [r12 + RSP_ACCEPTED], 0
    mov  qword [r12 + RSP_VAL], 0
    mov  qword [r12 + RSP_CODE], CMDE_AUTHDENY
    jmp  .stage
.show:
    lea  rdi, [rel term_sshclikey_buf]
    mov  esi, TERM_SSHCLIKEY_CAP
    call ssh_cli_identity_text
    test eax, eax
    js   .none
    lea  rdi, [rel term_str_sshclikey_ok]
    call form_out_put_str
    lea  rdi, [rel term_sshclikey_buf]
    call form_out_put_str
    mov  qword [r12 + RSP_ACCEPTED], 1
    mov  qword [r12 + RSP_VAL], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    jmp  .stage
.none:
    lea  rdi, [rel term_str_sshclikey_empty]
    cmp  eax, -4
    je   .err_text
    lea  rdi, [rel term_str_sshclikey_runtime]
    cmp  eax, -5
    je   .err_text
    lea  rdi, [rel term_str_sshclikey_err]
    cmp  eax, -2
    jne  .err_text
    lea  rdi, [rel term_str_sshclikey_unverified]
.err_text:
    call form_out_put_str
    mov  qword [r12 + RSP_ACCEPTED], 0
    mov  qword [r12 + RSP_VAL], 0
    mov  qword [r12 + RSP_CODE], CMDE_BADJOB
.stage:
    mov  byte [rel form_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

;; term_sshclikey_word(RDI = argument, RSI = upper-case word) -> EAX 1 when the
;; whole argument is that word in either case, else 0.
term_sshclikey_word:
.cmp:
    mov  al, [rdi]
    cmp  al, 'a'
    jb   .up
    cmp  al, 'z'
    ja   .up
    sub  al, 0x20
.up:
    cmp  al, [rsi]
    jne  .no
    test al, al
    jz   .yes
    inc  rdi
    inc  rsi
    jmp  .cmp
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
%endif

;; terminal_cmd_termfeed(RDI = req, RSI = rsp): TERMFEED <win> <sub>.
;; Reply " TFEED=1 WIN=<w> RC=<rc> ..." in grid_out: RC 0 executed (fields from
;; terminal_termfeed), 1 no live Terminal in that window, 4 malformed.
terminal_cmd_termfeed:
    call cmd_handler_prologue
    mov  [rel term_feed_entry_req], rdi ; read below, before anything can nest
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, [rdi + REQ_ARG]
    mov  ebx, -1
    test r13, r13
    jz   .malformed
    movzx eax, byte [r13]
    sub  eax, '0'
    cmp  eax, 9
    ja   .malformed
    mov  rdi, r13
    call term_parse_dec                 ; EAX window, RDI past it
    mov  ebx, eax
    cmp  byte [rdi], ' '
    jne  .malformed
    inc  rdi
    cmp  byte [rdi], 0
    je   .malformed
    mov  r13, rdi
    cmp  ebx, WM_MAX
    jae  .no_window
    mov  edi, ebx
    call terminal_find_window
    cmp  eax, -1
    je   .no_window
    mov  edi, eax
    mov  rsi, r13
    mov  rax, [rel term_feed_req]       ; GA0-K: @KEY bytes belong to this request's principal
    push rax                            ; (saved: a fed line may run TERMFEED again)
    mov  rax, [rel term_feed_entry_req]
    mov  [rel term_feed_req], rax
    call terminal_termfeed              ; reply staged in grid_out
    pop  rax
    mov  [rel term_feed_req], rax
    jmp  .stage
.no_window:
    mov  esi, 1
    jmp  .short
.malformed:
    mov  esi, 4
.short:
    push rsi
    call grid_out_reset
    lea  rdi, [rel term_str_tfeed]
    call grid_out_str
    mov  edi, ebx
    cmp  edi, -1
    jne  .win
    xor  edi, edi
.win:
    call grid_out_dec
    lea  rdi, [rel term_str_rc]
    call grid_out_str
    pop  rdi
    call grid_out_dec
.stage:
    mov  byte [rel grid_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 0
    pop  r13
    pop  r12
    pop  rbx
    ret

;; terminal_key_filter(EDI = focused widget id, EAX = translated key) -> EAX 1
;; consumed / 0 not: the kit's wgt_key_filter seam. A key for a Terminal's view
;; widget is the Terminal's; any other goes to the filter installed before it.
terminal_key_filter:
    push rdi
    push rax
    call term_find_widget               ; -> EAX instance or -1 (clobbers RCX, RDX)
    cmp  eax, -1
    je   .other
    mov  edi, eax
    call term_inst_ptr
    mov  edi, [rax + TI_WIN]
    pop  rax
    add  rsp, 8
    jmp  terminal_key_hook              ; EAX key, EDI WM slot -> EAX 1
.other:
    pop  rax
    pop  rdi
    mov  rdx, [rel term_key_filter_prev]
    test rdx, rdx
    jz   .none
    jmp  rdx
.none:
    xor  eax, eax
    ret

;; terminal_wheel_hook(EDI notches (+ up), ESI x, EDX y): ps2's wheel seam. The
;; window under the pointer takes it; a Terminal scrolls, others keep the WM rule.
;; A notch on the IME candidate window is no Terminal's: it goes straight to the
;; WM rule, which consumes it (RCQ-38 LOW01-R1).
terminal_wheel_hook:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  r13d, edx
    mov  edi, esi
    mov  esi, edx
    call ime_popup_hit                  ; preserves EDI/ESI
    test eax, eax
    jnz  .other
    call wm_pointer_top_slot
    cmp  eax, -1
    je   .other
    mov  edi, eax
    mov  esi, ebx
    mov  edx, r12d
    mov  ecx, r13d
    call terminal_wheel                 ; -> EAX 1 when a Terminal took it
    test eax, eax
    jnz  .done
.other:
    mov  edi, ebx
    mov  esi, r12d
    mov  edx, r13d
    pop  r13
    pop  r12
    pop  rbx
    jmp  wm_pointer_wheel
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

;; term_grid_out_hex32(EDI): exactly 8 lower-case hex digits into grid_out
term_grid_out_hex32:
    push rbx
    push r12
    mov  r12d, edi
    mov  ebx, 8
.next:
    dec  ebx
    lea  ecx, [rbx*4]
    mov  eax, r12d
    shr  eax, cl
    and  eax, 0xf
    lea  rcx, [rel term_hexdigits]
    movzx edi, byte [rcx + rax]
    call grid_out_char
    test ebx, ebx
    jnz  .next
    pop  r12
    pop  rbx
    ret

term_str_launch:     db "LAUNCH",0
term_str_app:        db "app_terminal",0
term_str_launch_ok:  db " launch=ok app=app_terminal idx=",0
term_str_launch_err: db " launch=ERR app=app_terminal",0
term_str_termfeed:   db "TERMFEED",0
term_str_sshclikey:  db "SSHCLIKEY",0
term_str_sshclikey_ok: db "SSHCLIKEY ",0
term_str_sshclikey_err: db "SSHCLIKEY ERR no key",0
term_str_sshclikey_empty: db "SSHCLIKEY ERR not_enrolled (empty store; owner ENROLL persists the public identity; no temporary key created)",0
term_str_sshclikey_runtime: db "SSHCLIKEY ERR storage_unavailable (restore supported runtime storage; no temporary key or enrollment)",0
term_str_sshclikey_unverified: db "SSHCLIKEY ERR identity_unverified (owner ENROLL attempts authenticated recovery; repair needs trusted generation history)",0
term_str_sshclikey_owner_only: db "SSHCLIKEY REFUSED owner_only (ENROLL and RESET: the console owner, or an owner-signed AUTH1 request; never SSH, an injected line, SYSTEM or the AI)",0
term_str_sshclikey_usage: db "SSHCLIKEY ERR usage: SSHCLIKEY [ENROLL | RESET]",0
term_str_sshclikey_enroll_refused: db "SSHCLIKEY ERR enroll_unavailable (runtime, owner secret or trusted generation unavailable; nothing written)",0
term_str_sshclikey_reset_refused: db "SSHCLIKEY ERR reset_unavailable (verified identity and unused generation required; nothing written)",0
term_str_sshclikey_write_failed: db "SSHCLIKEY ERR commit_unverified (identity refused; durable outcome uncertain)",0
term_str_sshclikey_reset_complete: db "SSHCLIKEY RESET complete: previous client identity replaced; install the following public key in remote authorized_keys before reconnecting; server pins retained; ",0
term_str_sshclikey_enroll_word: db "ENROLL",0
term_str_sshclikey_reset_word: db "RESET",0
term_str_tfeed:      db " TFEED=1 WIN=",0
term_str_rc:         db " RC=",0
term_ssh_absent_text: db "ssh: this PaOS build has no SSH client yet (the hub port of the MSI client is pending)",13,10,0

term_type_name:     db "vt_view", 0
term_title:         db "Terminal", 0
term_ready_text:    db "[PAOS64] terminal.app.ready (xterm-256color VT, Unicode 8x16 font)", 13, 10, 0
term_refused_text:  db "[PAOS64] terminal.app.refused (widget type table full)", 13, 10, 0
term_open_text:     db "[PAOS64] terminal.app.open", 13, 10, 0
term_nomem_text:    db "[PAOS64] terminal.app.refused (no memory for a Terminal window)", 13, 10, 0
term_prompt_text:   db 0x1b, "[1;32mpaos", 0x1b, "[0m:", 0x1b, "[1;34m~", 0x1b, "[0m$ ", 0
%ifdef PAOS_TERMINAL_SSH
term_help_text:     db "  ssh USER@HOST[:PORT]  SSH session (vim, htop, tmux, claude ...)", 13, 10
                    db "  ssh --exec USER@HOST[:PORT] -- COMMAND  no PTY/stdin, 768 printable ASCII bytes",13,10
                    db "  ssh --exec-stdin USER@HOST[:PORT] -- COMMAND  typed stdin, Enter=LF",13,10
                    db "    Ctrl+Shift+D: close stdin; X: INT; T: TERM; Q: local cancel (no PTY)",13,10
                    db "  sshclikey    the ssh client key (add it to the server's authorized_keys)", 13, 10
                    db "  sshclikey enroll | reset   keep that key across restarts | replace it (owner)", 13, 10
%else
term_help_text:     db "  ssh          not in this build yet (no SSH client)", 13, 10
%endif
                    db "  guest        attach to running Linux guest; Ctrl+] detaches",13,10
                    db "  clear        clear the screen", 13, 10
                    db "  echo TEXT    print TEXT", 13, 10
                    db "  history      list this window's local history (no arguments)", 13, 10
                    db "  Tab          unique local word or live registry name (case-insensitive; no arguments)",13,10
                    db "  ls <absolute-path> <16-hex nonce>    FSLS (native, no flags)", 13, 10
                    db "  stat <absolute-path> <16-hex nonce>  FSSTAT (native, no flags)", 13, 10
                    db "  sha256sum <absolute-path> <16-hex nonce>  FSHASH (native, no flags)", 13, 10
                    db "  mkdir <absolute-path> <16-hex nonce> FSMKDIR (owner verb, no flags)", 13, 10
                    db "  rmdir <absolute-path> <16-hex nonce> FSRMDIR (owner verb, no flags)", 13, 10
                    db "  rm <absolute-path> <16-hex nonce>    FSDEL (owner verb, no flags)", 13, 10
                    db "  mv <absolute-path> <absolute-path> <16-hex nonce>  FSREN (owner verb, no flags)", 13, 10
                    db "  cp <absolute-path> <absolute-path> <16-hex nonce>  FSCOPY: starts a copy job (owner verb, no flags)", 13, 10
                    db "  df <16-hex nonce>  FSINFO of the selected volume (no flags, no path)", 13, 10
                    db "  cat ps kill free uname ip ifconfig  not mapped; each names its native verb", 13, 10
                    db "  ping <number>  the native PING: echoes the number (no ICMP)", 13, 10
                    db "  exit         close this Terminal", 13, 10
                    db "  windows      return to Windows (asks first)", 13, 10
                    db "  reboot       restart the computer (asks first)", 13, 10
                    db "  shutdown     power off (asks first)", 13, 10
                    db "  linux-return confirm or cancel a pending signed return to Linux",13,10
                    db "  status, ...  any PaOS command (case-insensitive)", 13, 10, 0
term_crlf:          db 13, 10, 0
term_cr:            db 13, 0
term_el:            db 0x1b, "[K", 0
term_ed:            db 0x1b, "[J", 0      ; RCQ-38 L4: erase to the end of the screen
term_cub1:          db 0x1b, "[D", 0
term_cuf1:          db 0x1b, "[C", 0
term_complete_words: db "guest", 0, "ssh", 0, "clear", 0, "exit", 0, "help", 0, "history", 0, "echo", 0, "windows", 0, "reboot", 0, "shutdown", 0, "linux-return", 0
                    db "ls", 0, "stat", 0, "sha256sum", 0, "mkdir", 0, "rmdir", 0, "rm", 0, "mv", 0, "cp", 0, "df", 0, 0
term_cmd_guest: db "guest",0
term_cmd_history:   db "history", 0
term_history_usage: db "usage: history (no arguments)", 13, 10, 0
term_power_yes:     db "y", 13, 10, 0
term_cmd_linux_return: db "linux-return",0
term_linux_question: db "Confirm the pending signed return to Linux? [y/N] ",0
term_linux_waiting: db "y",13,10,"Confirmed; waiting for the signed Linux return.",13,10,0
term_linux_unavailable: db "No live Linux return plan; cancelled or expired. Nothing changed.",13,10,0
term_power_no:      db "n", 13, 10, "cancelled", 13, 10, 0
term_power_leaving: db "leaving PaOS ...", 13, 10, 0
term_power_off:     db "powering off ...", 13, 10, 0
term_bs_text:       db 8, " ", 8, 0
term_ctrl_c_text:   db "^C", 13, 10, 0
term_clear_text:    db 0x1b, "[H", 0x1b, "[2J", 0x1b, "[3J", 0
term_unknown_text:  db "unknown command (type 'help')", 13, 10, 0
term_builtin_ssh:   db "ssh",0
term_builtin_power: db "power",0
term_injected_refused: db "refused: an injected line cannot use the owner's ssh identity or power", 13, 10, 0
term_ssh_inj_text:  db 13, 10, "[injected input not sent to the SSH session]", 13, 10, 0
term_ssh_v_key:     db "key", 0
term_ssh_v_pointer: db "pointer", 0
TERM_TX_MAX         equ 94                  ; record text bytes: cons_record_begin takes < CONS_LINE_MAX - 1
%if TERM_TX_MAX > CONS_LINE_MAX - 2
%error "TERM_TX_MAX must stay below the cons record line bound (CONS_LINE_MAX - 1)"
%endif
term_tx_name:       db "term0", 0           ; byte 4 = the Terminal slot digit
term_tx_redacted:   db " <redacted>", 0
term_tx_redacted_reply: db "<redacted>"
term_tx_redacted_reply_end: db 0
term_tx_none_text:  db "[PAOS64] terminal.transcript none (no free CONS session; see CONS_LIST)", 13, 10, 0
term_registry_help: db "HELP", 0
term_job_accepted:  db " accepted job=", 0
term_job_est:       db " est=", 0
term_job_state:     db " state=", 0
term_job_running:   db "running", 0
term_job_done:      db "done", 0
term_err_code:      db "ERR code=", 0
term_err_expected:  db " expected=", 0
term_err_hint:      db " hint=", 0
term_err_none:      db "none", 0
term_ssh_dns_wait: db "[ssh: hostname lookup pending]",13,10,0
term_ssh_dns_resolved: db "[ssh: resolved endpoint ",0
term_ssh_dns_endpoint_tail: db "]",13,10,0
term_ssh_dns_nx: db "[ssh: hostname not found]",13,10,0
term_ssh_dns_nodata: db "[ssh: hostname has no IPv4 address]",13,10,0
term_ssh_dns_timeout: db "[ssh: hostname lookup timed out]",13,10,0
term_ssh_dns_refused: db "[ssh: hostname lookup refused (no usable IPv4 address)]",13,10,0
term_ssh_dns_locked: db "[ssh: hostname lookup cancelled by session lock]",13,10,0
term_ssh_connecting: db "ssh: connecting to ", 0
term_ssh_connecting_tail: db " (TERM=xterm-256color) ...",13,10
    db "[ssh: When connected, commands execute on the remote system.]",13,10
    db "[ssh: Files created by those commands are stored on that system.]",13,10
    db "[ssh: PaOS files are separate; this connection does not copy them.]",13,10,0
term_ssh_busy:      db "ssh: this window already runs an ssh session", 13, 10, 0
term_ssh_nosession: db "ssh: every ssh session is in use (close one first)", 13, 10, 0
term_ssh_outcome_unknown: db 13,10,"[ssh session closed; remote exit status unknown]",13,10,0
term_ssh_outcome_status: db 13,10,"[ssh: remote exit status ",0
term_ssh_outcome_signal: db 13,10,"[ssh: remote exit signal ",0
term_ssh_outcome_core_no: db "; core dumped=no; message=",0
term_ssh_outcome_core_yes: db "; core dumped=yes; message=",0
term_ssh_outcome_language: db "; language=",0
term_ssh_outcome_end: db "]",13,10,0
term_ssh_closed_text: db 13, 10, "[ssh session closed]", 13, 10, 0
align 4, db 0
term_clip_truncated: dd 0             ; latest copy stopped before an entire cell/newline
term_clip_len:      dd 0
term_paste_inst:    dd -1
term_paste_len:     dd 0
term_paste_off:     dd 0
term_paste_session: dd -1
align 8
term_paste_generation: dq 0
term_ssh_lookups: times TERM_MAX * TS_SIZE db 0
term_paste_generations: times TERM_MAX dq 0 ; outside the reused instance records
term_power_instance: dq 0
term_power_generation: dq 0
term_power_vt: dq 0
term_power_window: dd 0
term_power_widget: dd 0
term_clip_copies:   dd 0
term_clip_pastes:   dd 0
term_sel_r0:        dd 0
term_sel_c0:        dd 0
term_sel_r1:        dd 0
term_sel_c1:        dd 0
term_sel_linestart: dd 0
term_clip:          times TERM_CLIP_MAX db 0
term_paste_buf:     times TERM_CLIP_MAX + 16 db 0
term_leave_alt:     db 0x1b, "[?1049l", 0
term_mode_reset:    db 0x1b, "[!p", 0x1b, "[?1000l", 0x1b, "[?1002l", 0x1b, "[?1003l", 0x1b, "[?1006l"
                    db 0x1b, "[?1015l", 0x1b, "[?1004l", 0x1b, "[?2004l", 0x1b, "[?25h", 0x1b, "[0 q", 0
term_ssh_failed_text: db 13, 10, "[ssh: connection failed]", 13, 10, 0
term_ssh_tcp_timeout: db 13, 10, "[ssh: connection timed out (no answer from the host in 10 s)]", 13, 10, 0
term_ssh_unestablished_text: db 13, 10, "[ssh: connection could not be established]", 13, 10, 0
term_ssh_timedout_text: db 13, 10, "[ssh: connection timed out]", 13, 10, 0
term_ssh_reset_text: db 13, 10, "[ssh: connection reset by the host]", 13, 10, 0
term_ssh_lost_text: db 13, 10, "[ssh: connection lost]", 13, 10, 0
term_ssh_hostclosed_text: db 13, 10, "[ssh session closed by the host]", 13, 10, 0
term_ssh_silent_text: db 13, 10, "[ssh: connection lost (the host stopped answering)]", 13, 10, 0
term_ssh_auth_text: db 13, 10, "[ssh: authentication failed (the key was refused)]", 13, 10, 0
term_ssh_disc_text: db 13, 10, "[ssh: disconnected by the host]", 13, 10, 0
term_ssh_hostkey_text: db 13, 10, "[ssh: REFUSED: host key or stored trust rejected; inspect storage warnings and verify the host fingerprint independently; any trust replacement requires a separate owner action]", 13, 10, 0
term_ssh_ownerkey_text: db 13, 10, "[ssh: REFUSED: the client key signs only in the owner's session]", 13, 10, 0
term_ssh_idempty_text: db 13,10,"[ssh: REFUSED: client identity store empty; owner sshclikey enroll is required; no temporary key created]",13,10,0
term_ssh_idruntime_text: db 13,10,"[ssh: REFUSED: client identity storage unavailable; restore supported EFI runtime storage; no temporary key]",13,10,0
term_ssh_idrefused_text: db 13, 10, "[ssh: REFUSED: client identity unverified; owner sshclikey enroll attempts authenticated recovery; repair needs trusted generation history]", 13, 10, 0
align 8
term_ssh_pty_refused_text: db 13,10,"[ssh: PTY request refused by the host]",13,10,0
term_ssh_exec_refused_text: db 13,10,"[ssh: exec request refused by the host]",13,10,0
term_ssh_exec_timeout_text: db 13,10,"[ssh: exec acknowledgement timed out; remote outcome unknown]",13,10,0
term_ssh_exec_revoked_text: db 13,10,"[ssh: exec authorization or state changed; remote outcome unknown]",13,10,0
term_ssh_exec_uncertain_text: db 13,10,"[ssh: exec transport outcome unknown]",13,10,0
term_ssh_exec_local_refused: db "ssh: exec command refused before send",13,10,0
term_ssh_exec_full: db 13,10,"[ssh: stdin/control queue full; input not queued]",13,10,0
term_ssh_exec_closed: db 13,10,"[ssh: stdin closed; input not queued]",13,10,0
term_ssh_exec_control_refused: db 13,10,"[ssh: exec input/control refused for this session]",13,10,0
term_ssh_exec_close_queued: db 13,10,"[ssh: stdin close queued after admitted bytes]",13,10,0
term_ssh_exec_signal_queued: db 13,10,"[ssh: signal request queued; remote support/effect unconfirmed]",13,10,0
term_ssh_exec_cancelled: db 13,10,"[ssh: locally cancelled; remote outcome unknown]",13,10,0
term_ssh_shell_refused_text: db 13,10,"[ssh: shell request refused by the host]",13,10,0
align 8
term_ssh_fail_table:                    ; {u32 ssh_cli_error, i32 text - table} (no static pointers)
    dd 10, term_ssh_unestablished_text - term_ssh_fail_table
    dd 11, term_ssh_timedout_text - term_ssh_fail_table
    dd 12, term_ssh_reset_text - term_ssh_fail_table
    dd 13, term_ssh_lost_text - term_ssh_fail_table
    dd 14, term_ssh_hostclosed_text - term_ssh_fail_table
    dd 6,  term_ssh_silent_text - term_ssh_fail_table
    dd 9,  term_ssh_auth_text - term_ssh_fail_table
    dd 8,  term_ssh_disc_text - term_ssh_fail_table
    dd 15, term_ssh_hostkey_text - term_ssh_fail_table
    dd 16, term_ssh_ownerkey_text - term_ssh_fail_table
    dd 17, term_ssh_idrefused_text - term_ssh_fail_table
    dd 26, term_ssh_idempty_text - term_ssh_fail_table
    dd 27, term_ssh_idruntime_text - term_ssh_fail_table
    dd 19, term_ssh_pty_refused_text - term_ssh_fail_table
    dd 20, term_ssh_shell_refused_text - term_ssh_fail_table
    dd 22, term_ssh_exec_refused_text - term_ssh_fail_table
    dd 23, term_ssh_exec_timeout_text - term_ssh_fail_table
    dd 24, term_ssh_exec_revoked_text - term_ssh_fail_table
    dd 25, term_ssh_exec_uncertain_text - term_ssh_fail_table
    dd 0,  0
term_ssh_timeout:   db 13, 10, "[ssh: no answer from the host within 20 s]", 13, 10, 0
term_ssh_noroute:   db "ssh: no ARP answer from the host within 3 s (is it on this network?)", 13, 10, 0
term_ssh_badarg:    db "ssh: usage: ssh USER@HOST[:PORT] or ssh --exec USER@HOST[:PORT] -- COMMAND", 13, 10, 0
term_ssh_tcbfull:   db "ssh: every TCP connection slot is in use (close a session and retry)", 13, 10, 0
term_ssh_nosend:    db "ssh: the connection request could not be sent (network down?)", 13, 10, 0
term_ssh_netdown:   db "ssh: the network is not up", 13, 10, 0
term_ssh_noopen:    db "ssh: TCP could not open the connection (every slot in use, or the request was not sent)", 13, 10, 0
term_ssh_entropy:   db "ssh: the random-number source refused (no session keys)", 13, 10, 0
term_ssh_owner_only: db "ssh: REFUSED: the client key signs only in the owner's session", 13, 10, 0
term_ssh_unverified: db "ssh: REFUSED: client identity unverified; owner sshclikey enroll attempts authenticated recovery; repair needs trusted generation history", 13, 10, 0
term_cmd_ssh:       db "ssh", 0
term_cmd_clear:     db "clear", 0
term_cmd_exit:      db "exit", 0
term_cmd_help:      db "help", 0
term_cmd_echo:      db "echo", 0
term_cmd_ls:        db "ls", 0
term_cmd_stat:      db "stat", 0
term_alias_fsls:    db "FSLS", 0
term_alias_fsstat:  db "FSSTAT", 0
term_cmd_sha256sum: db "sha256sum", 0
term_cmd_mkdir:     db "mkdir", 0
term_cmd_rmdir:     db "rmdir", 0
term_cmd_rm:        db "rm", 0
term_alias_fshash:  db "FSHASH", 0
term_alias_fsmkdir: db "FSMKDIR", 0
term_alias_fsrmdir: db "FSRMDIR", 0
term_alias_fsdel:   db "FSDEL", 0
term_alias_path_error: db ": expected <absolute-path> <16-hex nonce> (native verb; no flags)", 13, 10, 0
; RCQ-22 Linux-name table (help text above is its user documentation):
;   ls stat sha256sum mkdir rmdir rm -> FSLS FSSTAT FSHASH FSMKDIR FSRMDIR FSDEL
;   mv cp -> FSREN FSCOPY (two absolute paths + nonce); df -> FSINFO (nonce)
;   reboot shutdown -> the local y/N power words; ping -> native PING (no alias)
;   cat ps kill free uname ip ifconfig -> refused locally, see term_unmapped_words
; Each alias is the native request byte-for-byte (same registry authority, same
; errors); no Linux flag or Linux-only behaviour is accepted.
term_cmd_mv:        db "mv", 0
term_cmd_cp:        db "cp", 0
term_cmd_df:        db "df", 0
term_alias_fsren:   db "FSREN", 0
term_alias_fscopy:  db "FSCOPY", 0
term_alias_fsinfo:  db "FSINFO", 0
term_alias_pair_error: db ": expected <absolute-path> <absolute-path> <16-hex nonce> (native verb; no flags)", 13, 10, 0
term_alias_df_error: db "df: expected <16-hex nonce> (native FSINFO of the selected volume; no flags, no path)", 13, 10, 0
term_unmapped_words: db "cat", 0, "cat: not mapped (no whole-file print); FSREAD <absolute-path> <offset> <length 1-256> <16-hex nonce> returns a hex window", 13, 10, 0
                    db "ps", 0, "ps: not mapped (PaOS has no processes); STATUS <job> reports a job's state", 13, 10, 0
                    db "kill", 0, "kill: not mapped (no processes or signals); FSCANCEL <job> <16-hex nonce> cancels a copy job", 13, 10, 0
                    db "free", 0, "free: not mapped to a native verb", 13, 10, 0
                    db "uname", 0, "uname: not mapped to a native verb", 13, 10, 0
                    db "ip", 0, "ip: not mapped; NETCFG MEMBERS (owner-signed UDP only) lists the network members", 13, 10, 0
                    db "ifconfig", 0, "ifconfig: not mapped; NETCFG MEMBERS (owner-signed UDP only) lists the network members", 13, 10, 0, 0
term_cmd_windows:   db "windows", 0
term_cmd_reboot:    db "reboot", 0
term_cmd_shutdown:  db "shutdown", 0
term_empty:         db 0
term_sub_raw:       db "@RAW", 0
term_sub_key:       db "@KEY", 0
term_sub_sshstartobs: db '@SSHSTARTOBS',0
term_sub_sshkeyobs: db '@SSHKEYOBS',0
term_sub_sshdue: db '@SSHDUE',0
term_sub_sshobs: db '@SSHOBS',0
term_sub_stat:      db "@VTSTAT", 0
term_sub_cells:     db "@VTCELLS", 0
term_sub_row:       db "@VTROW", 0
term_out_sub_row:   db " SUB=VTROW HEX=", 0
term_out_more:      db " MORE=", 0
TERM_ROW_MAX        equ 250             ; UTF-8 bytes per @VTROW reply (hex doubles it)
term_rowbuf:        times TERM_ROW_MAX db 0
align 4
term_row_keep:      dd 0
term_row_more:      db 0
term_sub_cap:       db "@VTCAP", 0
term_sub_cap64:     db "@VTCAP64", 0
term_sub_rz:        db "@VTRZ", 0
term_out_sub_raw:   db " SUB=RAW N=", 0
term_out_sub_key:   db " SUB=KEY KEYS=", 0
term_out_routed:    db " TROUTED=", 0
term_out_reflow: db " REFLOW=",0        ; evicted physical rows, atomic resize refusals
term_out_marks: db " MARKLOSS=", 0     ; overflow,orphan,latest clipboard truncation
term_out_public_id db " PUBLIC_ID=",0
term_out_sub_stat:  db " SUB=VTSTAT APP=terminal COLS=", 0
term_out_rows:      db " TROWS=", 0
term_out_cur:       db " CUR=", 0
term_out_ssh:       db " SSH=", 0
term_out_chan:      db " CHAN=", 0
term_out_pty:       db " PTY=", 0
term_out_capn:      db " CAP=", 0
term_out_rzn:       db " RZ=", 0
term_out_ris:       db " RIS=", 0
term_out_focus:     db " FOCUS=", 0
term_out_view:      db " VIEW=", 0
term_out_wt:        db " WT=", 0
term_out_echo:      db " ECHO=", 0
term_limit_notice:  db "No new Terminal: 6 are open (the limit). Close one first.", 0
term_title_new:     times TERM_TITLE_MAX db 0
align 4
term_title_changes: dd 0
term_out_sbn:       db " SBN=", 0
term_out_sbar:      db " SBAR=", 0
term_out_sbact:     db " SBACT=", 0
term_out_slash:     db "/", 0
term_out_replies:   db " REPLIED=", 0
term_out_modes:     db " MODES=", 0
term_out_org:       db " ORG=", 0
term_out_title:     db " TITLELEN=", 0
term_out_crc:       db " CRC=", 0
term_out_sub_cells: db " SUB=VTCELLS CELLS=", 0
term_out_sub_cap:   db " SUB=VTCAP OFF=", 0
term_out_hex:       db " HEX=", 0
term_out_c64n:      db " N=", 0
term_out_b64:       db " B64=", 0
term_b64_alphabet:  db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
term_out_sub_rz:    db " SUB=VTRZ OFF=", 0
term_out_sub_clip:  db " SUB=CLIP SEL=", 0
term_out_clip_len:  db " LEN=", 0
term_out_clip_copies: db " COPIES=", 0
term_out_clip_pastes: db " PASTES=", 0
term_out_clip_hex:  db " HEX=", 0
term_sub_clip:      db "@CLIP", 0
term_out_rzsize:    db " SIZE=", 0
term_hexdigits:     db "0123456789abcdef"
align 4
term_key_map:                           ; GUI key -> VT key
    dw GUI_KEY_ENTER, VTKEY_ENTER, GUI_KEY_TAB, VTKEY_TAB
    dw GUI_KEY_BACKSPACE, VTKEY_BACKSPACE, GUI_KEY_ESC, VTKEY_ESCAPE
    dw GUI_KEY_UP, VTKEY_UP, GUI_KEY_DOWN, VTKEY_DOWN
    dw GUI_KEY_LEFT, VTKEY_LEFT, GUI_KEY_RIGHT, VTKEY_RIGHT
    dw GUI_KEY_HOME, VTKEY_HOME, GUI_KEY_END, VTKEY_END
    dw GUI_KEY_PGUP, VTKEY_PGUP, GUI_KEY_PGDN, VTKEY_PGDN
    dw GUI_KEY_INSERT, VTKEY_INSERT, GUI_KEY_DELETE, VTKEY_DELETE
    dw GUI_KEY_F1 + 0, VTKEY_F1 + 0, GUI_KEY_F1 + 1, VTKEY_F1 + 1
    dw GUI_KEY_F1 + 2, VTKEY_F1 + 2, GUI_KEY_F1 + 3, VTKEY_F1 + 3
    dw GUI_KEY_F1 + 4, VTKEY_F1 + 4, GUI_KEY_F1 + 5, VTKEY_F1 + 5
    dw GUI_KEY_F1 + 6, VTKEY_F1 + 6, GUI_KEY_F1 + 7, VTKEY_F1 + 7
    dw GUI_KEY_F1 + 8, VTKEY_F1 + 8, GUI_KEY_F1 + 9, VTKEY_F1 + 9
    dw GUI_KEY_F1 + 10, VTKEY_F1 + 10, GUI_KEY_F1 + 11, VTKEY_F1 + 11
    dw 0, 0
; Transparent fallback: hollow top-right box = stored mark has no glyph.
term_mark_missing_glyph: db 0x0e,0x0a,0x0e
                        times 13 db 0
; Lower-right plus = cell mark capacity exceeded; copy contains retained prefix.
term_mark_loss_glyph: times 12 db 0
                     db 0x04,0x0e,0x04,0
term_blank_glyph:   times 16 db 0
; I4a missing wide glyph: hollow 14x12 box inside a 16x16 cell, 2 bytes/row, MSB left.
term_wide_box_glyph:
    times 2 db 0, 0
    db 0x7f, 0xfe
    times 10 db 0x40, 0x02
    db 0x7f, 0xfe
    times 2 db 0, 0
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Hub: the Terminal's hot writable state lives in the page-isolated WDATA region.
%macro WDATA_gui_terminal_app_0 0
align 8
term_sshclikey_buf: times TERM_SSHCLIKEY_CAP db 0
term_keys_routed:   dq 0
term_type_id:       dd -1
term_ssh_sessions:  dd 0
term_reply_bytes:   dd 0
term_reply_sessions: times TERM_MAX dd -1
align 8
term_reply_generations: times TERM_MAX dq 0
term_fffd_index:    dd 0
term_def_fg:        dd TERM_DEFAULT_FG
term_def_bg:        dd TERM_DEFAULT_BG
term_cur_col:       dd 0
term_blink_now:     db 1
term_echo:          db 0, 0
align 8
term_req:           times REQ_SZ db 0
term_rsp:           times RSP_SZ db 0
term_ssh_completion_buf: times 512 db 0 ; serialized close-time snapshot, before session wipe
term_num_buf:       times 24 db 0       ; term_out_dec (u64 <= 20 digits + NUL)
term_keybuf:        times 16 db 0
term_mousebuf:      times 32 db 0
term_focus_in:      db 27,'[I',0
term_focus_out:     db 27,'[O',0
term_word_delims:   db ' /\()"',39,'-.,:;<>~!@#$%^&*|+=[]{}?',0   ; Windows Terminal defaults
align 8
term_mouse_reports: dq 0                ; xterm mouse reports sent
term_wheel_events:  dq 0                ; wheel events a Terminal took
term_sb_actions:    dq 0                ; scrollbar presses and drags that moved a view
term_rawbuf:        times TERM_RAW_MAX + 8 db 0
term_route:         times 32 db 0
term_arp_frame:     times 64 db 0
term_arp_requests:  dd 0
align 8
term_tx_noted:      times TERM_MAX db 0  ; "no session" said once per slot
term_tx_line:       times TERM_TX_MAX + 1 db 0
align 16
term_instances_ptr: dq 0                ; -> heap table (term_instances_base); was 80,880 image bytes
term_instances_refusal_logged: db 0              ; heap refusal already logged (term_instances_base)
str_term_inst_alloc_fail: db "[term] instance table allocation refused; Terminal disabled", 13, 10, 0
align 8
term_drafts:        times (TERM_MAX * TD_SIZE) db 0
term_taints:        times (TERM_MAX * KT_SIZE) db 0   ; GA0-K: each window's line taint
term_taint_spare:   times KT_SIZE db 0
term_exec_taint:    times KT_SIZE db 0             ; the line term_execute_line is running
term_feed_req:      dq 0                           ; TERMFEED: the request whose @KEY bytes are queued
term_feed_entry_req: dq 0
terminal_terminal_launch_op: dq 0
term_launch_fallback: dq 0             ; the LAUNCH handler before app_terminal
term_key_filter_prev: dq 0             ; the kit key filter before the Terminal's
term_ssh_taint:     times KT_SIZE db 0  ; SEC D1: the event term_ssh_input_ok judges
term_ssh_input_refused: dq 0            ; input-driven sends dropped from a live SSH session
term_ssh_burst_t0:  dq 0                ; the open burst's line went out at (us)
term_ssh_burst:     db 0                ; 1 = a refusal burst is open
align 8
term_text_refused:  dq 0                ; text refused by the local line or a full SSH input queue
term_hist_skipped:  dq 0                ; RCQ-38 L4: lines run but too long for history
term_line_corrupt:  dq 0                ; RCQ-38 L4: a line found not UTF-8 or a caret inside a cluster, cleared
%endmacro
WDATA_DEFER WDATA_gui_terminal_app_0
%ifndef PAOS_TERMINAL_SSH
%include "gui/terminal_ssh_absent.inc"
%endif
%include "gui/vt/vt_engine.asm"
%include "gui/vt/vt_font.inc"
