;; MODULE gui/treecheck
;; LAYER 6
;; EXPORTS treecheck_declare, treecheck_selftest, treecheck_periodic_mismatch
;; IMPORTS boot/gop, boot/serial, core/cadence, gui/cadence_mark, gui/chat_app, gui/command_gui, gui/taskbar, gui/widget, gui/window, gui/window_mgmt, svc/command
;; CAPS
;; OWNER saga:gui_screen_capture
; Contract 2133: WINTREE's wm_*/wgt_tbl claims are checked against the live
; framebuffer using the painter's own GUI_TOK_* constants. This organ reports;
; it never paints or self-heals.

TC_K             equ 5
TC_PAGE_ROWS     equ 4
TC_TITLE_H       equ 6
TC_SKIP_TEXT     equ 1
TC_SKIP_WIDGET   equ 2
TC_SKIP_CURSOR   equ 4
TC_SKIP_DAMAGE   equ 8

; state; title {checked,mm,skip,x,y,have,want}; body {same}; reasons
TCR_STATE  equ 0
TCR_TC     equ 4
TCR_TM     equ 8
TCR_TS     equ 12
TCR_TX     equ 16
TCR_TY     equ 20
TCR_THAVE  equ 24
TCR_TWANT  equ 28
TCR_BC     equ 32
TCR_BM     equ 36
TCR_BS     equ 40
TCR_BX     equ 44
TCR_BY     equ 48
TCR_BHAVE  equ 52
TCR_BWANT  equ 56
TCR_REASON equ 60
TCR_SIZE   equ 64

treecheck_declare:
    push rbx
    lea  rdi, [rel tc_verb]
    lea  rsi, [rel tc_cmd]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .fail
    mov  rbx, [rel tsc_khz]
    imul rbx, rbx, 1000
    test rbx, rbx
    jnz  .period
    mov  rbx, 1000000
.period:
    lea  rdi, [rel tc_cad_id]
    xor  esi, esi
    mov  edx, 1
    mov  rcx, rbx
    lea  r8, [rel tc_tick]
    call cadence_register_named
    cmp  eax, -1
    je   .fail
    mov  [rel tc_cad_slot], eax
    call treecheck_selftest
    pop  rbx
    ret
.fail:
    mov  dword [rel tc_cad_slot], -1
    lea  rdi, [rel tc_fail]
    call serial_string
    pop  rbx
    ret

treecheck_selftest:
    push rbx
    lea  rdi, [rel tc_verb]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  eax, [rel tc_cad_slot]
    cmp  eax, -1
    je   .fail
    imul rax, rax, CAD_ENT_SZ
    lea  rbx, [rel cad_table]
    lea  rcx, [rel tc_tick]
    cmp  [rbx + rax + CAD_CTRL], rcx
    jne  .fail
    cmp  qword [rbx + rax + CAD_DECL_HZ], 1
    jne  .fail
    lea  rdi, [rel tc_marker]
    call serial_string
    pop  rbx
    ret
.fail:
    lea  rdi, [rel tc_fail]
    call serial_string
    pop  rbx
    ret

; One rotating registry window per cadence edge. RDI=cadence row.
tc_tick:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, [rel tc_rotate]
    xor  ebx, ebx
.find:
    cmp  ebx, WM_MAX
    jae  .done
    mov  eax, r13d
    inc  r13d
    cmp  r13d, WM_MAX
    jb   .nowrap
    xor  r13d, r13d
.nowrap:
    lea  rcx, [rel wm_state]
    mov  edx, [rcx + rax*4]
    cmp  edx, WM_VISIBLE
    je   .audit
    cmp  edx, WM_MIN
    je   .audit
    inc  ebx
    jmp  .find
.audit:
    mov  [rel tc_rotate], r13d
    mov  edi, eax
    call tc_run_one
    mov  eax, [rel tc_last_slot]
    shl  eax, 6
    lea  rbx, [rel tc_rows]
    add  rbx, rax
    mov  eax, [rbx + TCR_TM]
    add  eax, [rbx + TCR_BM]
    test eax, eax
    jz   .done
    add  [rel treecheck_periodic_mismatch], rax
    mov  qword [r12 + CAD_VITAL], 1
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; TREECHECK [1-based-page]. Walk first, serialize second.
tc_cmd:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  r14, [rdi + REQ_ARG]
    mov  r12d, 1
    cmp  byte [r14], 0
    je   .page
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r12d, eax
.page:
    call tc_run_all
    mov  eax, [rel tc_windows]
    add  eax, TC_PAGE_ROWS - 1
    xor  edx, edx
    mov  ecx, TC_PAGE_ROWS
    div  ecx
    mov  ebp, eax
    test ebp, ebp
    jnz  .pages
    mov  ebp, 1
.pages:
    call f1_out_reset
    cmp  r12d, 1
    jb   .bad
    cmp  r12d, ebp
    ja   .bad
    lea  rdi, [rel tc_head]
    call f1_put_str
    mov  edi, r12d
    call f1_put_dec
    lea  rdi, [rel tc_slash]
    call f1_put_str
    mov  edi, ebp
    call f1_put_dec
    lea  rdi, [rel tc_verdict]
    call f1_put_str
    lea  rdi, [rel tc_ok]
    cmp  dword [rel tc_mismatch], 0
    jne  .head_mm
    cmp  dword [rel tc_checked], 0
    jne  .put_head
    lea  rdi, [rel tc_vacuous]
    jmp  .put_head
.head_mm:
    lea  rdi, [rel tc_mm]
.put_head:
    call f1_put_str
    lea  rdi, [rel tc_windows_s]
    call f1_put_str
    mov  edi, [rel tc_windows]
    call f1_put_dec
    lea  rdi, [rel tc_checked_s]
    call f1_put_str
    mov  edi, [rel tc_checked]
    call f1_put_dec
    lea  rdi, [rel tc_mismatch_s]
    call f1_put_str
    mov  edi, [rel tc_mismatch]
    call f1_put_dec
    lea  rdi, [rel tc_skipped_s]
    call f1_put_str
    mov  edi, [rel tc_skipped]
    call f1_put_dec
    lea  rdi, [rel tc_periodic_s]
    call f1_put_str
    mov  rdi, [rel treecheck_periodic_mismatch]
    call f1_put_dec
    mov  eax, r12d
    dec  eax
    imul eax, TC_PAGE_ROWS
    mov  r15d, eax
    add  eax, TC_PAGE_ROWS
    mov  [rel tc_page_end], eax
    xor  ebp, ebp
    xor  ebx, ebx
.scan:
    cmp  ebp, WM_MAX
    jae  .ready
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbp*4]
    cmp  eax, WM_VISIBLE
    je   .live
    cmp  eax, WM_MIN
    jne  .next
.live:
    cmp  ebx, r15d
    jb   .ordinal
    cmp  ebx, [rel tc_page_end]
    jae  .ready
    mov  edi, ebp
    call tc_emit_row
.ordinal:
    inc  ebx
.next:
    inc  ebp
    jmp  .scan
.bad:
    lea  rdi, [rel tc_bad_page]
    call f1_put_str
.ready:
    mov  byte [rel f1_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r14
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

tc_emit_row:
    push rbx
    push r12
    mov  r12d, edi
    mov  eax, edi
    shl  eax, 6
    lea  rbx, [rel tc_rows]
    add  rbx, rax
    lea  rdi, [rel tc_row]
    call f1_put_str
    mov  edi, r12d
    call f1_put_dec
    lea  rdi, [rel tc_state_s]
    call f1_put_str
    lea  rdi, [rel tc_visible]
    cmp  dword [rbx + TCR_STATE], WM_MIN
    jne  .state
    lea  rdi, [rel tc_minimized]
.state:
    call f1_put_str
    cmp  dword [rbx + TCR_STATE], WM_MIN
    jne  .title
    lea  rdi, [rel tc_negative_s]
    call f1_put_str
    lea  rdi, [rel tc_ok]
    mov  eax, [rbx + TCR_TM]
    add  eax, [rbx + TCR_BM]
    jz   .neg
    lea  rdi, [rel tc_mm]
.neg:
    call f1_put_str
.title:
    lea  rdi, [rel tc_title_s]
    call f1_put_str
    lea  rdi, [rel tc_ok]
    cmp  dword [rbx + TCR_TM], 0
    je   .title_put
    lea  rdi, [rel tc_mm]
.title_put:
    call f1_put_str
    cmp  dword [rbx + TCR_TM], 0
    je   .title_counts
    lea  rdi, [rbx + TCR_TX]
    call tc_emit_first
.title_counts:
    lea  rdi, [rel tc_region_checked]
    call f1_put_str
    mov  edi, [rbx + TCR_TC]
    call f1_put_dec
    lea  rdi, [rel tc_region_skipped]
    call f1_put_str
    mov  edi, [rbx + TCR_TS]
    call f1_put_dec
    lea  rdi, [rel tc_bg_s]
    call f1_put_str
    lea  rdi, [rel tc_ok]
    cmp  dword [rbx + TCR_BM], 0
    je   .bg_put
    lea  rdi, [rel tc_mm]
.bg_put:
    call f1_put_str
    cmp  dword [rbx + TCR_BM], 0
    je   .bg_counts
    lea  rdi, [rbx + TCR_BX]
    call tc_emit_first
.bg_counts:
    lea  rdi, [rel tc_region_checked]
    call f1_put_str
    mov  edi, [rbx + TCR_BC]
    call f1_put_dec
    lea  rdi, [rel tc_region_skipped]
    call f1_put_str
    mov  edi, [rbx + TCR_BS]
    call f1_put_dec
    cmp  dword [rbx + TCR_REASON], 0
    je   .done
    lea  rdi, [rel tc_reason_s]
    call f1_put_str
    test dword [rbx + TCR_REASON], TC_SKIP_TEXT
    jz   .widget
    lea  rdi, [rel tc_reason_text]
    call f1_put_str
.widget:
    test dword [rbx + TCR_REASON], TC_SKIP_WIDGET
    jz   .cursor
    lea  rdi, [rel tc_reason_widget]
    call f1_put_str
.cursor:
    test dword [rbx + TCR_REASON], TC_SKIP_CURSOR
    jz   .damage
    lea  rdi, [rel tc_reason_cursor]
    call f1_put_str
.damage:
    test dword [rbx + TCR_REASON], TC_SKIP_DAMAGE
    jz   .done
    lea  rdi, [rel tc_reason_damage]
    call f1_put_str
.done:
    pop  r12
    pop  rbx
    ret

; RDI=&x,y,have,want.
tc_emit_first:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel tc_x_s]
    call f1_put_str
    mov  edi, [rbx]
    call f1_put_dec
    lea  rdi, [rel tc_y_s]
    call f1_put_str
    mov  edi, [rbx + 4]
    call f1_put_dec
    lea  rdi, [rel tc_have_s]
    call f1_put_str
    mov  edi, [rbx + 8]
    call f1_put_hex6
    lea  rdi, [rel tc_want_s]
    call f1_put_str
    mov  edi, [rbx + 12]
    call f1_put_hex6
    pop  rbx
    ret

tc_snapshot_tsc:
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel tc_walk_tsc], rax
    ret

tc_run_all:
    push rbx
    push r12
    call tc_snapshot_tsc
    mov  dword [rel tc_windows], 0
    mov  dword [rel tc_checked], 0
    mov  dword [rel tc_mismatch], 0
    mov  dword [rel tc_skipped], 0
    lea  rbx, [rel tc_rows]
    xor  eax, eax
    mov  ecx, WM_MAX * TCR_SIZE / 8
.zero:
    mov  [rbx], rax
    add  rbx, 8
    dec  ecx
    jnz  .zero
    xor  r12d, r12d
.walk:
    cmp  r12d, WM_MAX
    jae  .done
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .check
    cmp  eax, WM_MIN
    jne  .next
.check:
    inc  dword [rel tc_windows]
    mov  edi, r12d
    call tc_check_slot
.next:
    inc  r12d
    jmp  .walk
.done:
    pop  r12
    pop  rbx
    ret

tc_run_one:
    push rbx
    push r12
    mov  r12d, edi
    mov  [rel tc_last_slot], edi
    call tc_snapshot_tsc
    mov  eax, r12d
    shl  eax, 6
    lea  rbx, [rel tc_rows]
    add  rbx, rax
    xor  eax, eax
    mov  ecx, TCR_SIZE / 8
.zero:
    mov  [rbx], rax
    add  rbx, 8
    dec  ecx
    jnz  .zero
    mov  edi, r12d
    call tc_check_slot
    pop  r12
    pop  rbx
    ret

tc_check_slot:
    push r12
    mov  r12d, edi
    mov  eax, edi
    shl  eax, 6
    lea  rcx, [rel tc_rows]
    lea  rdx, [rel wm_state]
    mov  edx, [rdx + r12*4]
    mov  [rcx + rax + TCR_STATE], edx
    mov  edi, r12d
    xor  esi, esi
    call tc_check_region
    mov  edi, r12d
    mov  esi, 1
    call tc_check_region
    pop  r12
    ret

; EDI=slot, ESI=0 title/1 body. K=5: corners inset 2 plus center.
tc_check_region:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  [rel tc_current_slot], edi
    mov  [rel tc_current_region], esi
    mov  eax, edi
    lea  rcx, [rel wm_x]
    mov  r12d, [rcx + rax*4]
    add  r12d, GUI_CHROME_BORDER
    lea  rcx, [rel wm_w]
    mov  r14d, [rcx + rax*4]
    sub  r14d, GUI_CHROME_BORDER * 2
    lea  rcx, [rel wm_y]
    mov  r13d, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    mov  r15d, [rcx + rax*4]
    test esi, esi
    jnz  .body
    add  r13d, GUI_CHROME_BORDER
    mov  r15d, TC_TITLE_H
    jmp  .bounds
.body:
    add  r13d, GUI_TITLE_H
    sub  r15d, GUI_TITLE_H + GUI_CHROME_BORDER
.bounds:
    cmp  r14d, 5
    jb   .done
    cmp  r15d, 5
    jb   .done
    xor  ebp, ebp
.point:
    cmp  ebp, TC_K
    jae  .done
    mov  ebx, r12d
    mov  eax, r13d
    cmp  ebp, 4
    je   .center
    test ebp, 1
    jz   .left
    add  ebx, r14d
    sub  ebx, 3
    jmp  .vert
.left:
    add  ebx, 2
.vert:
    test ebp, 2
    jz   .top
    add  eax, r15d
    sub  eax, 3
    jmp  .sample
.top:
    add  eax, 2
    jmp  .sample
.center:
    mov  ecx, r14d
    shr  ecx, 1
    add  ebx, ecx
    mov  ecx, r15d
    shr  ecx, 1
    add  eax, ecx
.sample:
    mov  edi, ebx
    mov  esi, eax
    call tc_sample
    inc  ebp
    jmp  .point
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

tc_sample:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, esi
    mov  eax, [rel tc_current_slot]
    shl  eax, 6
    lea  r14, [rel tc_rows]
    add  r14, rax
    cmp  dword [rel tc_current_region], 0
    jne  .body
    add  r14, TCR_TC
    jmp  .classify
.body:
    add  r14, TCR_BC
.classify:
    mov  edi, r12d
    mov  esi, r13d
    call tc_expected
    test eax, eax
    jnz  .skip
    inc  dword [r14]
    inc  dword [rel tc_checked]
    mov  eax, [rel fb_stride]
    imul eax, r13d
    add  eax, r12d
    mov  rbx, [rel fb_base]
    mov  ecx, [rbx + rax*4]
    and  ecx, 0xFFFFFF
    cmp  ecx, edx
    je   .done
    cmp  dword [r14 + 4], 0
    jne  .count
    mov  [r14 + 12], r12d
    mov  [r14 + 16], r13d
    mov  [r14 + 20], ecx
    mov  [r14 + 24], edx
.count:
    inc  dword [r14 + 4]
    inc  dword [rel tc_mismatch]
    jmp  .done
.skip:
    inc  dword [r14 + 8]
    inc  dword [rel tc_skipped]
    mov  ecx, [rel tc_current_slot]
    shl  ecx, 6
    lea  rbx, [rel tc_rows]
    or   [rbx + rcx + TCR_REASON], eax
.done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=x,ESI=y -> EAX=0, EDX=want; or EAX=TC_SKIP_*.
; Paint order matches wmx_draw_all: ascending non-focus slots, focus last.
tc_expected:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    cmp  qword [rel fb_base], 0
    je   .damage_skip
    cmp  r12d, [rel fb_width]
    jae  .damage_skip
    cmp  r13d, [rel fb_height]
    jae  .damage_skip
    mov  eax, [rel gui_cursor_x]
    cmp  r12d, eax
    jb   .damage
    add  eax, 8
    cmp  r12d, eax
    jae  .damage
    mov  eax, [rel gui_cursor_y]
    cmp  r13d, eax
    jb   .damage
    add  eax, 12
    cmp  r13d, eax
    jb   .cursor_skip
.damage:
    mov  edi, r12d
    mov  esi, r13d
    call tc_damage_at
    test eax, eax
    jnz  .damage_skip
    mov  r14d, -1
    xor  r15d, r15d
.scan:
    cmp  r15d, WM_MAX
    jae  .focus
    cmp  r15d, [rel wm_focus]
    je   .next
    lea  rax, [rel wm_state]
    cmp  dword [rax + r15*4], WM_VISIBLE
    jne  .next
    mov  eax, r15d
    lea  rcx, [rel wm_x]
    mov  edx, [rcx + rax*4]
    cmp  r12d, edx
    jb   .next
    lea  rcx, [rel wm_w]
    add  edx, [rcx + rax*4]
    cmp  r12d, edx
    jae  .next
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    cmp  r13d, edx
    jb   .next
    lea  rcx, [rel wm_h]
    add  edx, [rcx + rax*4]
    cmp  r13d, edx
    jae  .next
    mov  r14d, r15d
.next:
    inc  r15d
    jmp  .scan
.focus:
    mov  r15d, [rel wm_focus]
    cmp  r15d, WM_MAX
    jae  .chosen
    lea  rax, [rel wm_state]
    cmp  dword [rax + r15*4], WM_VISIBLE
    jne  .chosen
    mov  eax, r15d
    lea  rcx, [rel wm_x]
    mov  edx, [rcx + rax*4]
    cmp  r12d, edx
    jb   .chosen
    lea  rcx, [rel wm_w]
    add  edx, [rcx + rax*4]
    cmp  r12d, edx
    jae  .chosen
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    cmp  r13d, edx
    jb   .chosen
    lea  rcx, [rel wm_h]
    add  edx, [rcx + rax*4]
    cmp  r13d, edx
    jae  .chosen
    mov  r14d, r15d
.chosen:
    cmp  r14d, -1
    jne  .window
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    cmp  r13d, eax
    jae  .widget_skip
    xor  eax, eax
    mov  edx, GUI_TOK_DESKTOP
    jmp  .out
.window:
    mov  eax, r14d
    lea  rcx, [rel wm_x]
    mov  ebx, [rcx + rax*4]
    lea  rcx, [rel wm_y]
    mov  ebp, [rcx + rax*4]
    lea  rcx, [rel wm_w]
    mov  r15d, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    mov  ecx, [rcx + rax*4]
    mov  edx, ebx
    add  edx, GUI_CHROME_BORDER
    cmp  r12d, edx
    jb   .border
    mov  edx, ebx
    add  edx, r15d
    sub  edx, GUI_CHROME_BORDER
    cmp  r12d, edx
    jae  .border
    mov  edx, ebp
    add  edx, GUI_CHROME_BORDER
    cmp  r13d, edx
    jb   .border
    mov  edx, ebp
    add  edx, ecx
    sub  edx, GUI_CHROME_BORDER
    cmp  r13d, edx
    jae  .border
    mov  edx, ebp
    add  edx, GUI_TITLE_H
    cmp  r13d, edx
    jae  .body
    ; button band is a non-flat chrome-control region
    mov  edx, ebp
    add  edx, GUI_CHROME_BUTTON_Y
    cmp  r13d, edx
    jb   .text
    add  edx, GUI_CHROME_BUTTON_H
    cmp  r13d, edx
    jae  .text
    mov  edx, ebx
    add  edx, r15d
    sub  edx, GUI_CHROME_BUTTON_W * 3 + GUI_CHROME_BUTTON_GAP * 2 + GUI_CHROME_BUTTON_RIGHT
    cmp  r12d, edx
    jb   .text
    mov  eax, ebx
    add  eax, r15d
    sub  eax, GUI_CHROME_BUTTON_RIGHT
    cmp  r12d, eax
    jb   .widget_skip
.text:
    ; D2: the strip's last row is the separator token.
    mov  edx, ebp
    add  edx, GUI_TITLE_H - 1
    cmp  r13d, edx
    je   .separator
    mov  edx, ebp
    add  edx, GUI_CHROME_TITLE_Y
    cmp  r13d, edx
    jb   .title_flat
    add  edx, GUI_CHROME_TITLE_CELL_H
    cmp  r13d, edx
    jae  .title_flat
    mov  edx, ebx
    add  edx, GUI_CHROME_TITLE_X
    cmp  r12d, edx
    jb   .title_flat
    mov  eax, r14d
    lea  rcx, [rel wm_title]
    mov  rcx, [rcx + rax*8]
    test rcx, rcx
    jz   .title_flat
    xor  eax, eax
.len:
    cmp  byte [rcx + rax], 0
    je   .len_ready
    inc  eax
    jmp  .len
.len_ready:
    push rax
    mov  eax, r15d
    sub  eax, GUI_CHROME_TITLE_RESERVE
    jns  .reserve_ok
    xor  eax, eax                       ; too narrow: no title cells
.reserve_ok:
    push rdx
    xor  edx, edx
    mov  edi, GUI_CHROME_TITLE_ADV
    div  edi
    pop  rdx
    mov  edi, eax
    pop  rax
    cmp  eax, edi
    jbe  .cells
    mov  eax, edi
.cells:
    imul eax, eax, GUI_CHROME_TITLE_ADV
    add  edx, eax
    cmp  r12d, edx
    jb   .text_skip
.title_flat:
    xor  eax, eax
    mov  edx, GUI_TOK_TITLE_UNFOCUSED
    cmp  r14d, [rel wm_focus]
    jne  .out
    mov  edx, GUI_TOK_TITLE_FOCUSED
    jmp  .out
.body:
    xor  ebp, ebp
.widgets:
    cmp  ebp, [rel wgt_count]
    jae  .body_flat
    mov  eax, ebp
    imul rax, rax, WGI_SZ
    lea  rcx, [rel wgt_tbl]
    add  rcx, rax
    cmp  dword [rcx + WGI_TYPE], 0
    je   .wnext
    cmp  dword [rcx + WGI_WIN], r14d
    jne  .wnext
    test dword [rcx + WGI_FLAGS], 1
    jz   .wnext
    mov  edx, [rcx + WGI_X]
    cmp  r12d, edx
    jb   .wnext
    add  edx, [rcx + WGI_W]
    cmp  r12d, edx
    jae  .wnext
    mov  edx, [rcx + WGI_Y]
    cmp  r13d, edx
    jb   .wnext
    add  edx, [rcx + WGI_H]
    cmp  r13d, edx
    jb   .widget_skip
.wnext:
    inc  ebp
    jmp  .widgets
.body_flat:
    xor  eax, eax
    mov  edx, GUI_TOK_WINDOW_BODY
    jmp  .out
.border:
    xor  eax, eax
    mov  edx, GUI_TOK_BORDER
    cmp  r14d, [rel wm_focus]
    jne  .out
    mov  edx, GUI_TOK_BORDER_FOCUSED
    jmp  .out
.separator:
    xor  eax, eax
    mov  edx, GUI_TOK_TITLE_SEPARATOR
    jmp  .out
.text_skip:
    mov  eax, TC_SKIP_TEXT
    jmp  .out
.widget_skip:
    mov  eax, TC_SKIP_WIDGET
    jmp  .out
.cursor_skip:
    mov  eax, TC_SKIP_CURSOR
    jmp  .out
.damage_skip:
    mov  eax, TC_SKIP_DAMAGE
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI=x,ESI=y -> EAX=1 if a post-snapshot damage rect covers this point.
tc_damage_at:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, edi
    mov  r14d, esi
    xor  ebx, ebx
    mov  r12d, [rel cadence_count]
    cmp  r12d, CADR_MAX
    jbe  .scan
    mov  r12d, CADR_MAX
.scan:
    cmp  ebx, r12d
    jae  .no
    mov  eax, ebx
    shl  eax, 5
    lea  rcx, [rel cadence_ring]
    add  rcx, rax
    mov  rax, [rel tc_walk_tsc]
    cmp  [rcx + CADR_TSC], rax
    jbe  .next
    movzx eax, word [rcx + CADR_W]
    test eax, eax
    jz   .next
    movzx edx, word [rcx + CADR_X]
    cmp  r13d, edx
    jb   .next
    add  edx, eax
    cmp  r13d, edx
    jae  .next
    movzx eax, word [rcx + CADR_H]
    test eax, eax
    jz   .next
    movzx edx, word [rcx + CADR_Y]
    cmp  r14d, edx
    jb   .next
    add  edx, eax
    cmp  r14d, edx
    jb   .yes
.next:
    inc  ebx
    jmp  .scan
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

align 8
tc_walk_tsc:                    dq 0
treecheck_periodic_mismatch:   dq 0
tc_windows:                    dd 0
tc_checked:                    dd 0
tc_mismatch:                   dd 0
tc_skipped:                    dd 0
tc_rotate:                     dd 0
tc_last_slot:                  dd 0
tc_cad_slot:                   dd -1
tc_current_slot:               dd 0
tc_current_region:             dd 0
tc_page_end:                   dd 0
align 8
tc_rows:                       times WM_MAX * TCR_SIZE db 0

tc_verb:             db "TREECHECK",0
tc_cad_id:           db "treecheck.pixel",0
tc_head:             db " TREECHECK v1 page=",0
tc_slash:            db "/",0
tc_verdict:          db " treecheck=",0
tc_ok:               db "ok",0
tc_mm:               db "MISMATCH",0
tc_vacuous:          db "ERR_vacuous",0
tc_windows_s:        db " windows=",0
tc_checked_s:        db " checked=",0
tc_mismatch_s:       db " mismatch=",0
tc_skipped_s:        db " skipped=",0
tc_periodic_s:       db " treecheck_periodic_mismatch=",0
tc_row:              db 10,"| w=",0
tc_state_s:          db " state=",0
tc_visible:          db "visible",0
tc_minimized:        db "minimized",0
tc_negative_s:       db " negative=",0
tc_title_s:          db " title=",0
tc_bg_s:             db " bg=",0
tc_region_checked:   db " checked=",0
tc_region_skipped:   db " skipped=",0
tc_reason_s:         db " reason=",0
tc_reason_text:      db "text,",0
tc_reason_widget:    db "widget,",0
tc_reason_cursor:    db "cursor,",0
tc_reason_damage:    db "damage_pending,",0
tc_x_s:              db " x=",0
tc_y_s:              db " y=",0
tc_have_s:           db " have=",0
tc_want_s:           db " want=",0
tc_bad_page:         db " TREECHECK=ERR_bad_page",0
tc_marker:           db "[PAOS64] M6 gui: tree-pixel audit armed (flat-claim K5, rotating tier1) [gui.tree.pixel]",13,10,0
tc_fail:             db "[PAOS64] M6 gui: tree-pixel audit registration FAILED",13,10,0
