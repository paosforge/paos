;; MODULE gui/ansi_interp
;; LAYER 6
;; EXPORTS ansi_grid_reset, ansi_grid_feed, ansi_grid_resize, ansi_grid_boot_kat, ansi_grid_kat_flags, ansi_parser_state, ansi_alt_active, ansi_cursor_visible, ansi_scroll_top, ansi_scroll_bottom
;; IMPORTS boot/serial, gui/widget_console_grid
;; CAPS
;; OWNER saga:text_sessions
; Contract 2155: bounded ANSI/VT mode over Task2150's existing console_grid.
; There is deliberately no renderer or second grid here: every operation lands
; in grid_visible_cells and console_grid_draw remains the sole pixel path.

ANSI_STATE_NORMAL   equ 0
ANSI_STATE_ESC      equ 1
ANSI_STATE_CSI      equ 2
ANSI_STATE_DISCARD  equ 3
ANSI_PARAM_MAX      equ 8
ANSI_PARAM_SAT      equ 9999
ANSI_CSI_MAX_BYTES  equ 32
ANSI_DEFAULT_ATTR   equ 0x07

ansi_grid_reset:
    mov  byte [rel grid_mode], 1
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    mov  byte [rel ansi_seq_len], 0
    mov  byte [rel ansi_param_count], 0
    mov  byte [rel ansi_param_have], 0
    mov  byte [rel ansi_private], 0
    mov  dword [rel ansi_param_value], 0
    mov  dword [rel ansi_cursor_x], 0
    mov  dword [rel ansi_cursor_y], 0
    mov  dword [rel ansi_saved_x], 0
    mov  dword [rel ansi_saved_y], 0
    mov  byte [rel ansi_fg], 7
    mov  byte [rel ansi_bg], 0
    mov  byte [rel ansi_bold], 0
    mov  byte [rel ansi_inverse], 0
    mov  byte [rel ansi_cursor_visible], 1
    mov  byte [rel ansi_alt_active], 0
    mov  dword [rel ansi_scroll_top], 0
    mov  eax, [rel grid_rows]
    test eax, eax
    jnz  .rows_ok
    mov  eax, 1
.rows_ok:
    dec  eax
    mov  [rel ansi_scroll_bottom], eax
    mov  eax, [rel grid_rows]
    mov  [rel ansi_prev_rows], eax
    lea  rdi, [rel grid_visible_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS
    mov  ax, (ANSI_DEFAULT_ATTR << 8) | ' '
    cld
    rep  stosw
    call ansi_cursor_apply
    mov  byte [rel grid_dirty], 1
    ret

ansi_grid_resize:
    call ansi_cursor_unmark
    mov  eax, [rel ansi_prev_rows]
    test eax, eax
    jz   .clamp_region
    dec  eax
    cmp  [rel ansi_scroll_bottom], eax
    jne  .clamp_region
    mov  eax, [rel grid_rows]
    dec  eax
    mov  [rel ansi_scroll_bottom], eax
.clamp_region:
    mov  eax, [rel grid_rows]
    mov  [rel ansi_prev_rows], eax
    dec  eax
    cmp  [rel ansi_scroll_bottom], eax
    jbe  .bottom_ok
    mov  [rel ansi_scroll_bottom], eax
.bottom_ok:
    mov  eax, [rel ansi_scroll_top]
    cmp  eax, [rel ansi_scroll_bottom]
    jb   .region_ok
    mov  dword [rel ansi_scroll_top], 0
.region_ok:
    mov  eax, [rel grid_cols]
    dec  eax
    cmp  [rel ansi_cursor_x], eax
    jbe  .x_ok
    mov  [rel ansi_cursor_x], eax
.x_ok:
    mov  eax, [rel grid_rows]
    dec  eax
    cmp  [rel ansi_cursor_y], eax
    jbe  .y_ok
    mov  [rel ansi_cursor_y], eax
.y_ok:
    call ansi_cursor_apply
    ret

ansi_grid_feed:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    xor  ebx, ebx
    call ansi_cursor_unmark
.next:
    cmp  rbx, r13
    jae  .done
    movzx edi, byte [r12 + rbx]
    call ansi_grid_putchar
    inc  rbx
    jmp  .next
.done:
    call ansi_cursor_apply
    mov  byte [rel grid_dirty], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

ansi_grid_putchar:
    movzx eax, byte [rel ansi_parser_state]
    cmp  eax, ANSI_STATE_ESC
    je   .esc
    cmp  eax, ANSI_STATE_CSI
    je   .csi
    cmp  eax, ANSI_STATE_DISCARD
    je   .discard
    cmp  edi, 0x1b
    je   .start_esc
    cmp  edi, 13
    je   ansi_carriage_return
    cmp  edi, 10
    je   ansi_linefeed
    cmp  edi, 8
    je   ansi_backspace
    cmp  edi, 9
    je   ansi_tab
    cmp  edi, 32
    jb   .ret
    cmp  edi, 126
    ja   .ret
    jmp  ansi_put_printable
.start_esc:
    mov  byte [rel ansi_parser_state], ANSI_STATE_ESC
    mov  byte [rel ansi_seq_len], 0
    ret
.esc:
    cmp  edi, 0x1b
    je   .start_esc
    cmp  edi, '['
    je   .start_csi
    cmp  edi, '7'
    je   .save
    cmp  edi, '8'
    je   .restore
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    ret
.save:
    mov  eax, [rel ansi_cursor_x]
    mov  [rel ansi_saved_x], eax
    mov  eax, [rel ansi_cursor_y]
    mov  [rel ansi_saved_y], eax
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    ret
.restore:
    call ansi_restore_cursor
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    ret
.start_csi:
    call ansi_csi_reset
    mov  byte [rel ansi_parser_state], ANSI_STATE_CSI
    ret
.csi:
    cmp  edi, 0x1b
    je   .start_esc
    inc  byte [rel ansi_seq_len]
    cmp  byte [rel ansi_seq_len], ANSI_CSI_MAX_BYTES
    jbe  .csi_bounded
    cmp  edi, 0x40
    jb   .csi_overlong
    cmp  edi, 0x7e
    ja   .csi_overlong
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    ret
.csi_overlong:
    mov  byte [rel ansi_parser_state], ANSI_STATE_DISCARD
    ret
.csi_bounded:
    cmp  edi, 0x40
    jae  .csi_final
    cmp  edi, '?'
    je   .csi_private
    cmp  edi, ';'
    je   .csi_separator
    cmp  edi, '0'
    jb   .csi_malformed
    cmp  edi, '9'
    ja   .csi_malformed
    mov  eax, [rel ansi_param_value]
    cmp  eax, ANSI_PARAM_SAT
    jae  .csi_digit_done
    imul eax, eax, 10
    sub  edi, '0'
    add  eax, edi
    cmp  eax, ANSI_PARAM_SAT
    jbe  .csi_store_digit
    mov  eax, ANSI_PARAM_SAT
.csi_store_digit:
    mov  [rel ansi_param_value], eax
.csi_digit_done:
    mov  byte [rel ansi_param_have], 1
    ret
.csi_private:
    cmp  byte [rel ansi_seq_len], 1
    jne  .csi_malformed
    mov  byte [rel ansi_private], 1
    ret
.csi_separator:
    call ansi_csi_end_param
    test eax, eax
    jnz  .csi_malformed
    ret
.csi_final:
    cmp  edi, 0x7e
    ja   .csi_malformed
    cmp  byte [rel ansi_param_have], 0
    jne  .csi_finish_param
    cmp  byte [rel ansi_param_count], 0
    je   .csi_execute
.csi_finish_param:
    push rdi
    call ansi_csi_end_param
    pop  rdi
    test eax, eax
    jnz  .csi_final_drop
.csi_execute:
    call ansi_csi_exec
.csi_final_drop:
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    ret
.csi_malformed:
    mov  byte [rel ansi_parser_state], ANSI_STATE_DISCARD
    ret
.discard:
    cmp  edi, 0x1b
    je   .start_esc
    cmp  edi, 0x40
    jb   .ret
    cmp  edi, 0x7e
    ja   .ret
    mov  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
.ret:
    ret

ansi_csi_reset:
    mov  byte [rel ansi_seq_len], 0
    mov  byte [rel ansi_param_count], 0
    mov  byte [rel ansi_param_have], 0
    mov  byte [rel ansi_private], 0
    mov  dword [rel ansi_param_value], 0
    lea  rdi, [rel ansi_params]
    mov  ecx, ANSI_PARAM_MAX
    xor  eax, eax
    cld
    rep  stosd
    ret

ansi_csi_end_param:
    movzx eax, byte [rel ansi_param_count]
    cmp  eax, ANSI_PARAM_MAX
    jae  .full
    mov  ecx, ANSI_PARAM_MAX - 1
    cmp  eax, ecx
    cmova eax, ecx                    ; constant 8-slot address bound
    lea  rdx, [rel ansi_params]
    mov  ecx, [rel ansi_param_value]
    mov  [rdx + rax*4], ecx
    inc  byte [rel ansi_param_count]
    mov  dword [rel ansi_param_value], 0
    mov  byte [rel ansi_param_have], 0
    xor  eax, eax
    ret
.full:
    mov  eax, 1
    ret

ansi_param_get:
    movzx eax, byte [rel ansi_param_count]
    cmp  edi, eax
    jae  .default
    lea  rdx, [rel ansi_params]
    mov  eax, ANSI_PARAM_MAX - 1
    cmp  edi, eax
    cmovb eax, edi                    ; preserve the caller's logical index
    mov  eax, [rdx + rax*4]
    test eax, eax
    jnz  .ret
    test esi, esi
    jnz  .default
.ret:
    ret
.default:
    mov  eax, esi
    ret

ansi_csi_exec:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    cmp  byte [rel ansi_private], 0
    jne  .private
    cmp  r12d, 'A'
    je   .up
    cmp  r12d, 'B'
    je   .down
    cmp  r12d, 'C'
    je   .right
    cmp  r12d, 'D'
    je   .left
    cmp  r12d, 'H'
    je   .position
    cmp  r12d, 'f'
    je   .position
    cmp  r12d, 'J'
    je   .erase_display
    cmp  r12d, 'K'
    je   .erase_line
    cmp  r12d, 'r'
    je   .scroll_region
    cmp  r12d, 'm'
    je   .sgr
    cmp  r12d, 's'
    je   .save
    cmp  r12d, 'u'
    je   .restore
    jmp  .done
.private:
    xor  edi, edi
    xor  esi, esi
    call ansi_param_get
    cmp  eax, 25
    je   .cursor_private
    cmp  eax, 1049
    je   .alt_private
    jmp  .done
.cursor_private:
    cmp  r12d, 'h'
    je   .cursor_show
    cmp  r12d, 'l'
    jne  .done
    mov  byte [rel ansi_cursor_visible], 0
    jmp  .done
.cursor_show:
    mov  byte [rel ansi_cursor_visible], 1
    jmp  .done
.alt_private:
    cmp  r12d, 'h'
    je   .alt_enter
    cmp  r12d, 'l'
    jne  .done
    call ansi_alt_exit
    jmp  .done
.alt_enter:
    call ansi_alt_enter
    jmp  .done
.up:
    xor  edi, edi
    mov  esi, 1
    call ansi_param_get
    cmp  eax, [rel ansi_cursor_y]
    jbe  .up_sub
    mov  dword [rel ansi_cursor_y], 0
    jmp  .done
.up_sub:
    sub  [rel ansi_cursor_y], eax
    jmp  .done
.down:
    xor  edi, edi
    mov  esi, 1
    call ansi_param_get
    add  eax, [rel ansi_cursor_y]
    mov  ecx, [rel grid_rows]
    dec  ecx
    cmp  eax, ecx
    jbe  .down_store
    mov  eax, ecx
.down_store:
    mov  [rel ansi_cursor_y], eax
    jmp  .done
.right:
    xor  edi, edi
    mov  esi, 1
    call ansi_param_get
    add  eax, [rel ansi_cursor_x]
    mov  ecx, [rel grid_cols]
    dec  ecx
    cmp  eax, ecx
    jbe  .right_store
    mov  eax, ecx
.right_store:
    mov  [rel ansi_cursor_x], eax
    jmp  .done
.left:
    xor  edi, edi
    mov  esi, 1
    call ansi_param_get
    cmp  eax, [rel ansi_cursor_x]
    jbe  .left_sub
    mov  dword [rel ansi_cursor_x], 0
    jmp  .done
.left_sub:
    sub  [rel ansi_cursor_x], eax
    jmp  .done
.position:
    xor  edi, edi
    mov  esi, 1
    call ansi_param_get
    dec  eax
    mov  ebx, eax
    mov  edi, 1
    mov  esi, 1
    call ansi_param_get
    dec  eax
    mov  ecx, [rel grid_rows]
    dec  ecx
    cmp  ebx, ecx
    jbe  .pos_row
    mov  ebx, ecx
.pos_row:
    mov  ecx, [rel grid_cols]
    dec  ecx
    cmp  eax, ecx
    jbe  .pos_col
    mov  eax, ecx
.pos_col:
    mov  [rel ansi_cursor_y], ebx
    mov  [rel ansi_cursor_x], eax
    jmp  .done
.erase_display:
    xor  edi, edi
    xor  esi, esi
    call ansi_param_get
    mov  edi, eax
    call ansi_erase_display
    jmp  .done
.erase_line:
    xor  edi, edi
    xor  esi, esi
    call ansi_param_get
    mov  edi, eax
    call ansi_erase_line
    jmp  .done
.scroll_region:
    xor  edi, edi
    mov  esi, 1
    call ansi_param_get
    mov  ebx, eax
    mov  edi, 1
    mov  esi, [rel grid_rows]
    call ansi_param_get
    mov  ecx, [rel grid_rows]
    cmp  ebx, 1
    jb   .done
    cmp  eax, ecx
    ja   .done
    cmp  ebx, eax
    jae  .done
    dec  ebx
    dec  eax
    mov  [rel ansi_scroll_top], ebx
    mov  [rel ansi_scroll_bottom], eax
    mov  dword [rel ansi_cursor_x], 0
    mov  dword [rel ansi_cursor_y], 0
    jmp  .done
.sgr:
    call ansi_apply_sgr
    jmp  .done
.save:
    mov  eax, [rel ansi_cursor_x]
    mov  [rel ansi_saved_x], eax
    mov  eax, [rel ansi_cursor_y]
    mov  [rel ansi_saved_y], eax
    jmp  .done
.restore:
    call ansi_restore_cursor
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

ansi_apply_sgr:
    push rbx
    push r12
    movzx r12d, byte [rel ansi_param_count]
    test r12d, r12d
    jnz  .loop_start
    xor  eax, eax
    call ansi_apply_sgr_one
    jmp  .done
.loop_start:
    xor  ebx, ebx
.loop:
    lea  rdx, [rel ansi_params]
    mov  eax, ANSI_PARAM_MAX - 1
    cmp  ebx, eax
    cmovb eax, ebx                    ; EBX remains the logical loop cursor
    mov  eax, [rdx + rax*4]
    call ansi_apply_sgr_one
    inc  ebx
    cmp  ebx, r12d
    jb   .loop
.done:
    pop  r12
    pop  rbx
    ret

ansi_apply_sgr_one:
    test eax, eax
    jz   .reset
    cmp  eax, 1
    je   .bold
    cmp  eax, 7
    je   .inverse
    cmp  eax, 30
    jb   .ret
    cmp  eax, 37
    jbe  .fg
    cmp  eax, 40
    jb   .ret
    cmp  eax, 47
    jbe  .bg
.ret:
    ret
.reset:
    mov  byte [rel ansi_fg], 7
    mov  byte [rel ansi_bg], 0
    mov  byte [rel ansi_bold], 0
    mov  byte [rel ansi_inverse], 0
    ret
.bold:
    mov  byte [rel ansi_bold], 1
    ret
.inverse:
    mov  byte [rel ansi_inverse], 1
    ret
.fg:
    sub  eax, 30
    mov  [rel ansi_fg], al
    ret
.bg:
    sub  eax, 40
    mov  [rel ansi_bg], al
    ret

ansi_current_attr:
    movzx eax, byte [rel ansi_fg]
    movzx ecx, byte [rel ansi_bg]
    cmp  byte [rel ansi_inverse], 0
    je   .ordered
    xchg eax, ecx
.ordered:
    and  eax, 7
    and  ecx, 7
    cmp  byte [rel ansi_bold], 0
    je   .no_bold
    or   eax, 8
.no_bold:
    shl  ecx, 4
    or   eax, ecx
    ret

ansi_cell_ptr:
    mov  eax, edi
    imul eax, GRID_MAX_COLS
    add  eax, esi
    shl  eax, 1
    lea  rdx, [rel grid_visible_cells]
    add  rax, rdx
    ret

ansi_cursor_unmark:
    cmp  byte [rel grid_mode], 1
    jne  .ret
    mov  edi, [rel ansi_cursor_y]
    cmp  edi, [rel grid_rows]
    jae  .ret
    mov  esi, [rel ansi_cursor_x]
    cmp  esi, [rel grid_cols]
    jae  .ret
    call ansi_cell_ptr
    and  byte [rax + 1], 0x7f
.ret:
    ret

ansi_cursor_apply:
    call ansi_cursor_unmark
    cmp  byte [rel ansi_cursor_visible], 1
    jne  .ret
    mov  edi, [rel ansi_cursor_y]
    cmp  edi, [rel grid_rows]
    jae  .ret
    mov  esi, [rel ansi_cursor_x]
    cmp  esi, [rel grid_cols]
    jae  .ret
    call ansi_cell_ptr
    or   byte [rax + 1], 0x80
    mov  eax, [rel ansi_cursor_y]
    mov  [rel grid_cursor_row], eax
    mov  eax, [rel ansi_cursor_x]
    mov  [rel grid_cursor_col], eax
.ret:
    ret

ansi_restore_cursor:
    mov  eax, [rel ansi_saved_x]
    mov  ecx, [rel grid_cols]
    dec  ecx
    cmp  eax, ecx
    jbe  .x
    mov  eax, ecx
.x:
    mov  [rel ansi_cursor_x], eax
    mov  eax, [rel ansi_saved_y]
    mov  ecx, [rel grid_rows]
    dec  ecx
    cmp  eax, ecx
    jbe  .y
    mov  eax, ecx
.y:
    mov  [rel ansi_cursor_y], eax
    ret

ansi_put_printable:
    push rbx
    mov  ebx, edi
    mov  edi, [rel ansi_cursor_y]
    mov  esi, [rel ansi_cursor_x]
    call ansi_cell_ptr
    mov  [rax], bl
    push rax
    call ansi_current_attr
    mov  ecx, eax
    pop  rax
    mov  [rax + 1], cl
    inc  dword [rel ansi_cursor_x]
    mov  eax, [rel grid_cols]
    cmp  [rel ansi_cursor_x], eax
    jb   .done
    mov  dword [rel ansi_cursor_x], 0
    call ansi_linefeed
.done:
    pop  rbx
    ret

ansi_carriage_return:
    mov  dword [rel ansi_cursor_x], 0
    ret
ansi_backspace:
    cmp  dword [rel ansi_cursor_x], 0
    je   .ret
    dec  dword [rel ansi_cursor_x]
.ret:
    ret
ansi_tab:
    mov  eax, [rel ansi_cursor_x]
    add  eax, 8
    and  eax, -8
    mov  ecx, [rel grid_cols]
    dec  ecx
    cmp  eax, ecx
    jbe  .store
    mov  eax, ecx
.store:
    mov  [rel ansi_cursor_x], eax
    ret

ansi_linefeed:
    mov  eax, [rel ansi_cursor_y]
    cmp  eax, [rel ansi_scroll_bottom]
    jne  .advance
    cmp  eax, [rel ansi_scroll_top]
    jb   .advance
    call ansi_scroll_region_up
    ret
.advance:
    inc  eax
    mov  ecx, [rel grid_rows]
    dec  ecx
    cmp  eax, ecx
    jbe  .store
    mov  eax, ecx
.store:
    mov  [rel ansi_cursor_y], eax
    ret

ansi_scroll_region_up:
    push rbx
    push r12
    call grid_ansi_capture_top_row
    mov  r12d, [rel ansi_scroll_top]
.row:
    cmp  r12d, [rel ansi_scroll_bottom]
    jae  .clear_bottom
    mov  edi, r12d
    xor  esi, esi
    call ansi_cell_ptr
    mov  rbx, rax
    lea  edi, [r12d + 1]
    xor  esi, esi
    call ansi_cell_ptr
    mov  rsi, rax
    mov  rdi, rbx
    mov  ecx, [rel grid_cols]
    cld
    rep  movsw
    inc  r12d
    jmp  .row
.clear_bottom:
    mov  edi, [rel ansi_scroll_bottom]
    xor  esi, esi
    mov  edx, [rel grid_cols]
    call ansi_fill_span
    pop  r12
    pop  rbx
    ret

ansi_fill_span:
    push rbx
    mov  ebx, edx
    call ansi_cell_ptr
    mov  rdi, rax
    call ansi_current_attr
    mov  ah, al
    mov  al, ' '
    mov  ecx, ebx
    cld
    rep  stosw
    pop  rbx
    ret

ansi_erase_line:
    push rbx
    mov  ebx, edi
    cmp  ebx, 1
    je   .start
    cmp  ebx, 2
    je   .whole
    cmp  ebx, 0
    jne  .done
    mov  edi, [rel ansi_cursor_y]
    mov  esi, [rel ansi_cursor_x]
    mov  edx, [rel grid_cols]
    sub  edx, esi
    call ansi_fill_span
    jmp  .done
.start:
    mov  edi, [rel ansi_cursor_y]
    xor  esi, esi
    mov  edx, [rel ansi_cursor_x]
    inc  edx
    call ansi_fill_span
    jmp  .done
.whole:
    mov  edi, [rel ansi_cursor_y]
    xor  esi, esi
    mov  edx, [rel grid_cols]
    call ansi_fill_span
.done:
    pop  rbx
    ret

ansi_erase_display:
    push rbx
    push r12
    mov  ebx, edi
    cmp  ebx, 1
    je   .start
    cmp  ebx, 2
    je   .whole
    cmp  ebx, 0
    jne  .done
    mov  edi, [rel ansi_cursor_y]
    mov  esi, [rel ansi_cursor_x]
    mov  edx, [rel grid_cols]
    sub  edx, esi
    call ansi_fill_span
    mov  r12d, [rel ansi_cursor_y]
    inc  r12d
.end_rows:
    cmp  r12d, [rel grid_rows]
    jae  .done
    mov  edi, r12d
    xor  esi, esi
    mov  edx, [rel grid_cols]
    call ansi_fill_span
    inc  r12d
    jmp  .end_rows
.start:
    xor  r12d, r12d
.start_rows:
    cmp  r12d, [rel ansi_cursor_y]
    jae  .start_cursor
    mov  edi, r12d
    xor  esi, esi
    mov  edx, [rel grid_cols]
    call ansi_fill_span
    inc  r12d
    jmp  .start_rows
.start_cursor:
    mov  edi, [rel ansi_cursor_y]
    xor  esi, esi
    mov  edx, [rel ansi_cursor_x]
    inc  edx
    call ansi_fill_span
    jmp  .done
.whole:
    xor  r12d, r12d
.whole_rows:
    cmp  r12d, [rel grid_rows]
    jae  .done
    mov  edi, r12d
    xor  esi, esi
    mov  edx, [rel grid_cols]
    call ansi_fill_span
    inc  r12d
    jmp  .whole_rows
.done:
    pop  r12
    pop  rbx
    ret

ansi_alt_enter:
    cmp  byte [rel ansi_alt_active], 1
    je   .ret
    lea  rsi, [rel grid_visible_cells]
    lea  rdi, [rel ansi_alt_saved_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS
    cld
    rep  movsw
    mov  eax, [rel ansi_cursor_x]
    mov  [rel ansi_alt_saved_x], eax
    mov  eax, [rel ansi_cursor_y]
    mov  [rel ansi_alt_saved_y], eax
    mov  eax, [rel ansi_scroll_top]
    mov  [rel ansi_alt_saved_top], eax
    mov  eax, [rel ansi_scroll_bottom]
    mov  [rel ansi_alt_saved_bottom], eax
    mov  al, [rel ansi_fg]
    mov  [rel ansi_alt_saved_fg], al
    mov  al, [rel ansi_bg]
    mov  [rel ansi_alt_saved_bg], al
    mov  al, [rel ansi_bold]
    mov  [rel ansi_alt_saved_bold], al
    mov  al, [rel ansi_inverse]
    mov  [rel ansi_alt_saved_inverse], al
    mov  al, [rel ansi_cursor_visible]
    mov  [rel ansi_alt_saved_cursor_visible], al
    lea  rdi, [rel grid_visible_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS
    mov  ax, (ANSI_DEFAULT_ATTR << 8) | ' '
    rep  stosw
    mov  dword [rel ansi_cursor_x], 0
    mov  dword [rel ansi_cursor_y], 0
    mov  dword [rel ansi_scroll_top], 0
    mov  eax, [rel grid_rows]
    dec  eax
    mov  [rel ansi_scroll_bottom], eax
    mov  byte [rel ansi_fg], 7
    mov  byte [rel ansi_bg], 0
    mov  byte [rel ansi_bold], 0
    mov  byte [rel ansi_inverse], 0
    mov  byte [rel ansi_cursor_visible], 1
    mov  byte [rel ansi_alt_active], 1
.ret:
    ret

ansi_alt_exit:
    cmp  byte [rel ansi_alt_active], 0
    je   .ret
    lea  rsi, [rel ansi_alt_saved_cells]
    lea  rdi, [rel grid_visible_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS
    cld
    rep  movsw
    mov  eax, [rel ansi_alt_saved_x]
    mov  [rel ansi_cursor_x], eax
    mov  eax, [rel ansi_alt_saved_y]
    mov  [rel ansi_cursor_y], eax
    mov  eax, [rel ansi_alt_saved_top]
    mov  [rel ansi_scroll_top], eax
    mov  eax, [rel ansi_alt_saved_bottom]
    mov  [rel ansi_scroll_bottom], eax
    mov  al, [rel ansi_alt_saved_fg]
    mov  [rel ansi_fg], al
    mov  al, [rel ansi_alt_saved_bg]
    mov  [rel ansi_bg], al
    mov  al, [rel ansi_alt_saved_bold]
    mov  [rel ansi_bold], al
    mov  al, [rel ansi_alt_saved_inverse]
    mov  [rel ansi_inverse], al
    mov  al, [rel ansi_alt_saved_cursor_visible]
    mov  [rel ansi_cursor_visible], al
    mov  byte [rel ansi_alt_active], 0
.ret:
    ret

; ----------------------- boot fixture KAT -----------------------
; Every recorded stream is replayed at every possible two-chunk boundary.
ansi_grid_boot_kat:
    push rbx
    push r12
    mov  byte [rel ansi_grid_kat_flags], 0
    lea  rdi, [rel ansi_kat_plain]
    mov  esi, ansi_kat_plain.len
    lea  rdx, [rel ansi_validate_plain]
    call ansi_kat_replay_splits
    test eax, eax
    jz   .cursor
    or   byte [rel ansi_grid_kat_flags], 0x01
.cursor:
    lea  rdi, [rel ansi_kat_cursor]
    mov  esi, ansi_kat_cursor.len
    lea  rdx, [rel ansi_validate_cursor]
    call ansi_kat_replay_splits
    test eax, eax
    jz   .sgr_scroll
    or   byte [rel ansi_grid_kat_flags], 0x02
.sgr_scroll:
    lea  rdi, [rel ansi_kat_sgr_scroll]
    mov  esi, ansi_kat_sgr_scroll.len
    lea  rdx, [rel ansi_validate_sgr_scroll]
    call ansi_kat_replay_splits
    test eax, eax
    jz   .alt
    or   byte [rel ansi_grid_kat_flags], 0x0c
.alt:
    lea  rdi, [rel ansi_kat_alt]
    mov  esi, ansi_kat_alt.len
    lea  rdx, [rel ansi_validate_alt]
    call ansi_kat_replay_splits
    test eax, eax
    jz   .malformed
    or   byte [rel ansi_grid_kat_flags], 0x10
.malformed:
    lea  rdi, [rel ansi_kat_malformed]
    mov  esi, ansi_kat_malformed.len
    lea  rdx, [rel ansi_validate_malformed]
    call ansi_kat_replay_splits
    test eax, eax
    jz   .all_splits
    or   byte [rel ansi_grid_kat_flags], 0x20
.all_splits:
    movzx eax, byte [rel ansi_grid_kat_flags]
    cmp  eax, 0x3f
    jne  .check_canaries
    or   byte [rel ansi_grid_kat_flags], 0x40
.check_canaries:
    mov  rax, 0x2155A11CE11CA55E
    cmp  [rel grid_cells_canary_lo], rax
    jne  .verdict
    mov  rax, 0xE55AC11EC11A5512
    cmp  [rel grid_cells_canary_hi], rax
    jne  .verdict
    mov  rax, 0x2155A17A11CA55E0
    cmp  [rel ansi_alt_canary_lo], rax
    jne  .verdict
    mov  rax, 0x0E55AC11A71A5512
    cmp  [rel ansi_alt_canary_hi], rax
    jne  .verdict
    or   byte [rel ansi_grid_kat_flags], 0x80
.verdict:
    cmp  byte [rel ansi_grid_kat_flags], 0xff
    jne  .fail
    lea  rdi, [rel str_ansi_kat_pass]
    call serial_string
    jmp  .live
.fail:
    lea  rdi, [rel str_ansi_kat_fail]
    call serial_string
    movzx edi, byte [rel ansi_grid_kat_flags]
    call serial_hex64
    call serial_newline
.live:
    ; Leave a production-parser fixture visible for CONSGRID + native pixels.
    call ansi_grid_reset
    lea  rdi, [rel ansi_live_head]
    mov  esi, ansi_live_head.len
    call ansi_grid_feed
    lea  rdi, [rel grid_nonce_buf]
    mov  esi, grid_nonce_buf.len
    call ansi_grid_feed
    lea  rdi, [rel ansi_live_color]
    mov  esi, ansi_live_color.len
    call ansi_grid_feed
    pop  r12
    pop  rbx
    ret

; RDI=stream, RSI=len, RDX=validator()->EAX boolean.
ansi_kat_replay_splits:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    xor  r15d, r15d
.split:
    call ansi_grid_reset
    mov  rdi, r12
    mov  rsi, r15
    call ansi_grid_feed
    lea  rdi, [r12 + r15]
    mov  rsi, r13
    sub  rsi, r15
    call ansi_grid_feed
    call r14
    test eax, eax
    jz   .fail
    inc  r15
    cmp  r15, r13
    jbe  .split
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=row, ESI=col -> AX={attr,glyph}, cursor flag removed from AH.
ansi_kat_cell:
    call ansi_cell_ptr
    mov  ax, [rax]
    and  ah, 0x7f
    ret

ansi_validate_plain:
    xor  edi, edi
    xor  esi, esi
    call ansi_kat_cell
    cmp  al, 'P'
    jne  .no
    cmp  ah, ANSI_DEFAULT_ATTR
    jne  .no
    mov  esi, 4
    call ansi_kat_cell
    cmp  al, 'N'
    jne  .no
    cmp  dword [rel ansi_cursor_x], 5
    jne  .no
    cmp  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

ansi_validate_cursor:
    xor  edi, edi
    xor  esi, esi
    call ansi_kat_cell
    cmp  al, 'A'
    jne  .no
    mov  esi, 3
    call ansi_kat_cell
    cmp  al, 'D'
    jne  .no
    mov  esi, 4
    call ansi_kat_cell
    cmp  al, 'Z'
    jne  .no
    mov  esi, 5
    call ansi_kat_cell
    cmp  al, ' '
    jne  .no
    mov  esi, 8
    call ansi_kat_cell
    cmp  al, 'T'
    jne  .no
    cmp  dword [rel ansi_cursor_x], 5
    jne  .no
    cmp  dword [rel ansi_cursor_y], 0
    jne  .no
    cmp  byte [rel ansi_cursor_visible], 1
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

ansi_validate_sgr_scroll:
    xor  edi, edi
    mov  esi, 1
    call ansi_kat_cell
    cmp  al, 'R'
    jne  .no
    cmp  ah, 0x01
    jne  .no
    mov  esi, 2
    call ansi_kat_cell
    cmp  al, 'B'
    jne  .no
    cmp  ah, 0x0c
    jne  .no
    mov  esi, 3
    call ansi_kat_cell
    cmp  al, 'I'
    jne  .no
    cmp  ah, 0x48
    jne  .no
    mov  edi, 1
    xor  esi, esi
    call ansi_kat_cell
    cmp  al, 'B'
    jne  .no
    mov  edi, 2
    xor  esi, esi
    call ansi_kat_cell
    cmp  al, 'C'
    jne  .no
    cmp  dword [rel ansi_scroll_top], 1
    jne  .no
    cmp  dword [rel ansi_scroll_bottom], 2
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

ansi_validate_alt:
    cmp  byte [rel ansi_alt_active], 0
    jne  .no
    cmp  dword [rel ansi_cursor_x], 3
    jne  .no
    cmp  dword [rel ansi_cursor_y], 2
    jne  .no
    cmp  byte [rel ansi_fg], 1
    jne  .no
    xor  edi, edi
    xor  esi, esi
    call ansi_kat_cell
    cmp  al, 'M'
    jne  .no
    mov  esi, 3
    call ansi_kat_cell
    cmp  al, 'N'
    jne  .no
    xor  r8d, r8d
.all:
    cmp  r8d, GRID_MAX_COLS * GRID_MAX_ROWS
    jae  .yes
    cmp  r8d, 4
    jb   .next
    lea  rdx, [rel grid_visible_cells]
    mov  ax, [rdx + r8*2]
    and  ah, 0x7f
    cmp  ax, (ANSI_DEFAULT_ATTR << 8) | ' '
    jne  .no
.next:
    inc  r8d
    jmp  .all
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

ansi_validate_malformed:
    cmp  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    jne  .no
    xor  edi, edi
    xor  esi, esi
    call ansi_kat_cell
    cmp  al, 'O'
    jne  .no
    mov  esi, 1
    call ansi_kat_cell
    cmp  al, 'K'
    jne  .no
    mov  esi, 2
    call ansi_kat_cell
    cmp  al, 'Z'
    jne  .no
    cmp  ah, ANSI_DEFAULT_ATTR
    jne  .no
    mov  esi, 3
    call ansi_kat_cell
    cmp  al, 'R'
    jne  .no
    cmp  ah, 0x01
    jne  .no
    mov  esi, 4
    call ansi_kat_cell
    cmp  al, 'U'
    jne  .no
    cmp  ah, 0x01
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Keep the shipped Task2155 state layout intact. Task2158 serializes these
; explicit field groups into each bounded instance record; source adjacency is
; no longer part of the instance ABI.
align 8
ansi_cursor_x:       dd 0
ansi_cursor_y:       dd 0
ansi_saved_x:        dd 0
ansi_saved_y:        dd 0
ansi_scroll_top:     dd 0
ansi_scroll_bottom:  dd 0
ansi_prev_rows:      dd 0
ansi_param_value:    dd 0
ansi_params:         times ANSI_PARAM_MAX dd 0
ansi_parser_state:   db ANSI_STATE_NORMAL
ansi_seq_len:        db 0
ansi_param_count:    db 0
ansi_param_have:     db 0
ansi_private:        db 0
ansi_fg:             db 7
ansi_bg:             db 0
ansi_bold:           db 0
ansi_inverse:        db 0
ansi_cursor_visible: db 1
ansi_alt_active:     db 0
ansi_grid_kat_flags: db 0
%if (ansi_grid_kat_flags - ansi_cursor_x) != GIS_ANSI_BYTES
    %error "Task2158 ANSI scalar record layout drift"
%endif

align 8
ansi_alt_saved_x:      dd 0
ansi_alt_saved_y:      dd 0
ansi_alt_saved_top:    dd 0
ansi_alt_saved_bottom: dd 0
ansi_alt_saved_fg:     db 7
ansi_alt_saved_bg:     db 0
ansi_alt_saved_bold:   db 0
ansi_alt_saved_inverse: db 0
ansi_alt_saved_cursor_visible: db 1
%if (ansi_alt_saved_cursor_visible - ansi_alt_saved_x + 1) != GIS_ALT_BYTES
    %error "Task2158 alternate-screen scalar record layout drift"
%endif
align 8
ansi_alt_canary_lo: dq 0x2155A17A11CA55E0
ansi_alt_saved_cells: times (GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES) db 0
ansi_alt_canary_hi: dq 0x0E55AC11A71A5512

ansi_kat_plain: db 'P','L','A','I','N'
.len equ $ - ansi_kat_plain
ansi_kat_cursor:
%include "gauntlet_v2/fixtures/ansi/cursor_erase.stream"
.len equ $ - ansi_kat_cursor
ansi_kat_sgr_scroll:
%include "gauntlet_v2/fixtures/ansi/sgr_scroll.stream"
.len equ $ - ansi_kat_sgr_scroll
ansi_kat_alt:
%include "gauntlet_v2/fixtures/ansi/alternate_screen.stream"
.len equ $ - ansi_kat_alt
ansi_kat_malformed:
%include "gauntlet_v2/fixtures/ansi/malformed_split.stream"
.len equ $ - ansi_kat_malformed

ansi_live_head: db 'ANSI terminal fixture',13,10
.len equ $ - ansi_live_head
ansi_live_color:
    db 13,0x1b,'[','3','1','m','R','E','D',0x1b,'[','0','m',' '
    db 0x1b,'[','4','4',';','3','7','m','B','L','U','E',0x1b,'[','0','m',' '
    db 0x1b,'[','7','m','I','N','V','E','R','S','E',0x1b,'[','0','m'
.len equ $ - ansi_live_color

str_ansi_kat_pass: db "[PAOS64] text sessions: bounded ANSI interpreter fixture KAT PASS [gui.ansi.interp]",13,10,0
str_ansi_kat_fail: db "[PAOS64] text sessions: bounded ANSI interpreter fixture KAT FAIL flags=",0
