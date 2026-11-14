;; Primary reflow is a bounded transaction. Read old screens/history, build a
;; complete output ring in disjoint caller-owned storage, then commit. No heap,
;; shared scratch or capture replay. A workspace shortfall or a cursor that
;; cannot coexist with the retained tail refuses without changing the grid.
VT_REFLOW_SB_MAX equ 4096

struc VTRF
 .stride: resq 1
 .cap: resq 1
 .wantcap: resq 1
 .oldcount: resq 1
 .last: resq 1
 .row: resq 1
 .src: resq 1
 .limit: resq 1
 .end: resq 1
 .soft: resq 1
 .col: resq 1
 .outrow: resq 1
 .outcol: resq 1
 .slot: resq 1
 .dst: resq 1
 .width: resq 1
 .step: resq 1
 .screen: resq 1
 .oldest: resq 1
 .total: resq 1
 .scratchend: resq 1
 .hidden: resq 1
 .oldgaps: resq 2
 .seen: resq 2
endstruc

;; RBX vt, R12D newcols, R13D newrows; preserves all callee-saved registers.
vt_primary_reflow_rbx:
    push rbp
    push r14
    push r15
    sub  rsp, VTRF_size
    mov  rbp, rsp
    cld
    mov  eax, [rbx + VT.rf_points + 92]
    mov  [rbp + VTRF.oldgaps], eax
    mov  eax, [rbx + VT.rf_points + 124]
    mov  [rbp + VTRF.oldgaps + 8], eax
    ; Dimensions and capacities are trusted only after bounded validation.
    mov  eax, [rbx + VT.maxcols]
    dec  eax
    cmp  eax, VT_MAX_COLS - 1
    ja   .refuse
    mov  eax, [rbx + VT.maxrows]
    dec  eax
    cmp  eax, VT_MAX_ROWS - 1
    ja   .refuse
    mov  eax, [rbx + VT.cols]
    test eax, eax
    jz   .refuse
    cmp  eax, [rbx + VT.maxcols]
    ja   .refuse
    mov  eax, [rbx + VT.rows]
    test eax, eax
    jz   .refuse
    cmp  eax, [rbx + VT.maxrows]
    ja   .refuse
    mov  eax, [rbx + VT.sb_lines]
    cmp  eax, VT_REFLOW_SB_MAX
    ja   .refuse
    mov  ecx, [rbx + VT.sb_count]
    cmp  ecx, eax
    ja   .refuse
    mov  [rbp + VTRF.oldcount], rcx
    mov  eax, [rbx + VT.maxcols]
    imul rax, VT_CELL
    mov  [rbp + VTRF.stride], rax
    mov  rcx, [rbx + VT.rf_base]
    test rcx, rcx
    jz   .refuse
    mov  rdx, [rbx + VT.rf_bytes]
    add  rdx, rcx
    jc   .refuse
    mov  [rbp + VTRF.scratchend], rdx
    mov  rax, [rbx + VT.rf_bytes]
    xor  edx, edx
    div  qword [rbp + VTRF.stride]
    test rax, rax
    jz   .refuse
    mov  ecx, [rbx + VT.sb_lines]
    add  ecx, r13d
    mov  [rbp + VTRF.wantcap], rcx
    cmp  rax, rcx
    cmova rax, rcx
    mov  [rbp + VTRF.cap], rax
    ; Reject source/context aliasing, including full64 end overflow.
    mov  rdi, rbx
    mov  esi, VT_size
    call vt_rf_disjoint
    jz   .refuse
    mov  eax, [rbx + VT.maxrows]
    imul rax, [rbp + VTRF.stride]
    mov  rsi, rax
    mov  rdi, [rbx + VT.cells]
    call vt_rf_disjoint
    jz   .refuse
    mov  rdi, [rbx + VT.cells + 8]
    call vt_rf_disjoint
    jz   .refuse
    mov  esi, [rbx + VT.maxrows]
    shl  rsi, 1
    mov  rdi, [rbx + VT.rowmap]
    call vt_rf_disjoint
    jz   .refuse
    mov  rdi, [rbx + VT.rowmap + 8]
    call vt_rf_disjoint
    jz   .refuse
    mov  esi, [rbx + VT.sb_lines]
    imul rsi, [rbp + VTRF.stride]
    test rsi, rsi
    jz   .sources_ok
    mov  rdi, [rbx + VT.sb_base]
    test rdi, rdi
    jz   .refuse
    call vt_rf_disjoint
    jz   .refuse
.sources_ok:
    cmp  dword [rbx + VT.sb_count], 0
    je   .history_head_ok
    mov  eax, [rbx + VT.sb_head]
    cmp  eax, [rbx + VT.sb_lines]
    jae  .refuse
.history_head_ok:
    xor  r9d, r9d
.map_set:
    mov  rdi, [rbx + VT.rowmap + r9*8]
    mov  qword [rbp + VTRF.seen], 0
    mov  qword [rbp + VTRF.seen + 8], 0
    xor  ecx, ecx
.check_map:
    movzx eax, word [rdi + rcx*2]
    cmp  eax, [rbx + VT.maxrows]
    jae  .refuse
    bts  qword [rbp + VTRF.seen], rax
    jc   .refuse
    inc  ecx
    cmp  ecx, [rbx + VT.maxrows]
    jb   .check_map
    inc  r9d
    cmp  r9d, 2
    jb   .map_set
    ; A primary cursor lives in the save slot while the alternate is showing.
    xor  eax, eax
    bt   qword [rbx + VT.modes], VTM_ALT
    setc al
    mov  [rbp + VTRF.hidden], rax
    mov  eax, [rbx + VT.cy]
    mov  ecx, [rbx + VT.cx]
    movzx edx, byte [rbx + VT.wrap]
    cmp  qword [rbp + VTRF.hidden], 0
    je   .cursor
    cmp  byte [rbx + VT.saved + VTSV_VALID], 0
    je   .cursor
    mov  eax, [rbx + VT.saved + VTSV_CY]
    mov  ecx, [rbx + VT.saved + VTSV_CX]
    movzx edx, byte [rbx + VT.saved + VTSV_WRAP]
.cursor:
    cmp  eax, [rbx + VT.rows]
    jae  .refuse
    cmp  ecx, [rbx + VT.cols]
    jae  .refuse
    add  rax, [rbp + VTRF.oldcount]
    test edx, edx
    jz   .cursor_no_wrap
    inc  ecx
.cursor_no_wrap:
    mov  [rbx + VT.rf_points], rax
    mov  [rbx + VT.rf_points + 8], ecx
    mov  qword [rbx + VT.rf_points + 32], -1
    cmp  byte [rbx + VT.saved + VTSV_VALID], 0
    je   .points
    mov  eax, [rbx + VT.saved + VTSV_CY]
    cmp  eax, [rbx + VT.rows]
    jae  .points
    add  rax, [rbp + VTRF.oldcount]
    mov  [rbx + VT.rf_points + 32], rax
    mov  ecx, [rbx + VT.saved + VTSV_CX]
    cmp  ecx, [rbx + VT.cols]
    jb   .saved_in_bounds
    mov  qword [rbx + VT.rf_points + 32], -1
    jmp  .points
.saved_in_bounds:
    cmp  byte [rbx + VT.saved + VTSV_WRAP], 0
    je   .saved_no_wrap
    inc  ecx
.saved_no_wrap:
    mov  [rbx + VT.rf_points + 40], ecx
.points:
    lea  rdi, [rbx + VT.rf_points]
    mov  ecx, 6
.clear_maps:
    mov  qword [rdi + 16], -1
    mov  dword [rdi + 28], 0
    add  rdi, 32
    loop .clear_maps
    ; Exclude never-written trailing primary rows, retain actual cursor/anchors.
    mov  eax, [rbx + VT.rows]
    dec  eax
    add  rax, [rbp + VTRF.oldcount]
    mov  [rbp + VTRF.row], rax
.find_last:
    call vt_rf_input_row
    call vt_rf_extent
    cmp  qword [rbp + VTRF.end], 0
    jne  .last_found
    xor  ecx, ecx
.anchor_last:
    lea  rdi, [rbx + VT.rf_points]
    mov  rax, [rdi + rcx]
    cmp  rax, [rbp + VTRF.row]
    je   .last_found
    add  ecx, 32
    cmp  ecx, 6 * 32
    jb   .anchor_last
    cmp  qword [rbp + VTRF.row], 0
    je   .last_found
    dec  qword [rbp + VTRF.row]
    jmp  .find_last
.last_found:
    mov  rax, [rbp + VTRF.row]
    mov  [rbp + VTRF.last], rax
    mov  qword [rbp + VTRF.row], 0
    mov  qword [rbp + VTRF.outrow], 0
    mov  qword [rbp + VTRF.outcol], 0
    mov  qword [rbp + VTRF.slot], 0
    call vt_rf_clear_output
.input_row:
    call vt_rf_input_row
    call vt_rf_extent
    ; Cursor padding is significant for caret position, not invented text.
    xor  ecx, ecx
.cursor_extent:
    lea  rdi, [rbx + VT.rf_points]
    mov  rax, [rbp + VTRF.row]
    cmp  [rdi + rcx], rax
    jne  .extent_next
    mov  eax, [rdi + rcx + 8]
    cmp  eax, [rbx + VT.cols]
    ja   .extent_next
    cmp  rax, [rbp + VTRF.end]
    jbe  .extent_next
    mov  [rbp + VTRF.end], rax
.extent_next:
    add  ecx, 32
    cmp  ecx, 64                   ; only actual/saved cursor, not selection padding
    jb   .cursor_extent
    mov  qword [rbp + VTRF.col], 0
.input_cell:
    mov  rax, [rbp + VTRF.col]
    cmp  rax, [rbp + VTRF.end]
    jae  .row_end
    imul rax, VT_CELL
    add  rax, [rbp + VTRF.src]
    mov  r14, rax
    mov  qword [rbp + VTRF.step], 1
    cmp  byte [r14 + VTC_W], 0
    je   .skip_cell                ; never duplicate a continuation
    cmp  byte [r14 + VTC_W], 2
    jne  .step_ready
    mov  qword [rbp + VTRF.step], 2
.step_ready:
    mov  edi, [r14 + VTC_CP]
    call vt_wcwidth
    cmp  eax, 2
    sete al
    movzx eax, al
    inc  eax
    cmp  r12d, 1
    jne  .width_ready
    mov  eax, 1                    ; preserve scalar+marks, restore width on grow
.width_ready:
    mov  [rbp + VTRF.width], rax
    add  rax, [rbp + VTRF.outcol]
    cmp  rax, r12
    jbe  .fits
    call vt_rf_soft_break
.fits:
    call vt_rf_map_cell
    mov  rax, [rbp + VTRF.outcol]
    imul rax, VT_CELL
    add  rax, [rbp + VTRF.dst]
    mov  rdi, rax
    mov  rsi, r14
    mov  ecx, VT_CELL / 8
    rep  movsq
    mov  rax, [rbp + VTRF.outcol]
    imul rax, VT_CELL
    add  rax, [rbp + VTRF.dst]
    mov  dl, [rbp + VTRF.width]
    mov  [rax + VTC_W], dl
    mov  byte [rax + VTC_WRAP], 0
    cmp  dl, 2
    jne  .cell_copied
    ; Reconstitute right half even after a one-column intermediate layout.
    mov  rdx, [rax]
    mov  [rax + VT_CELL], rdx
    mov  rdx, [rax + 8]
    mov  [rax + VT_CELL + 8], rdx
    mov  dword [rax + VT_CELL + VTC_CP], 0
    and  word [rax + VT_CELL + VTC_FL], ~VTF_MARK_LOSS
    mov  byte [rax + VT_CELL + VTC_W], 0
    mov  byte [rax + VT_CELL + VTC_WRAP], 0
    mov  qword [rax + VT_CELL + VTC_MARKS], 0
    mov  qword [rax + VT_CELL + VTC_MARKS + 8], 0
.cell_copied:
    mov  rax, [rbp + VTRF.width]
    add  [rbp + VTRF.outcol], rax
.skip_cell:
    mov  rax, [rbp + VTRF.step]
    add  [rbp + VTRF.col], rax
    jmp  .input_cell
.row_end:
    call vt_rf_map_end
    mov  rax, [rbp + VTRF.row]
    cmp  rax, [rbp + VTRF.last]
    jae  .built
    cmp  qword [rbp + VTRF.soft], 0
    jne  .next_input_row
    call vt_rf_next_output
.next_input_row:
    inc  qword [rbp + VTRF.row]
    jmp  .input_row
.built:
    mov  rax, [rbp + VTRF.outrow]
    inc  rax
    mov  [rbp + VTRF.total], rax
    cmp  rax, [rbp + VTRF.cap]
    jbe  .scratch_fits
    mov  rcx, [rbp + VTRF.cap]
    cmp  rcx, [rbp + VTRF.wantcap]
    jb   .refuse                    ; scratch shortage must never masquerade as eviction
.scratch_fits:
    xor  ecx, ecx
    cmp  rax, r13
    jbe  .screen_ready
    mov  rcx, rax
    sub  rcx, r13
.screen_ready:
    mov  [rbp + VTRF.screen], rcx
    mov  rdx, [rbx + VT.rf_points + 16]
    cmp  rdx, rcx
    jb   .refuse                    ; cannot put a live cursor in scrollback
    cmp  rdx, rax
    jae  .refuse
    xor  ecx, ecx
    cmp  rax, [rbp + VTRF.cap]
    jbe  .oldest_ready
    mov  rcx, rax
    sub  rcx, [rbp + VTRF.cap]
.oldest_ready:
    mov  [rbp + VTRF.oldest], rcx
    ; No source memory was mutated before this point. Commit retained history.
    mov  r15, rcx
    xor  r14d, r14d
.history:
    cmp  r15, [rbp + VTRF.screen]
    jae  .history_done
    mov  rax, r15
    call vt_rf_output_ptr
    mov  rsi, rax
    mov  rdi, r14
    imul rdi, [rbp + VTRF.stride]
    add  rdi, [rbx + VT.sb_base]
    call vt_rf_commit_row
    inc  r15
    inc  r14
    jmp  .history
.history_done:
    mov  [rbx + VT.sb_count], r14d
    mov  eax, r14d
    cmp  eax, [rbx + VT.sb_lines]
    jb   .head
    xor  eax, eax
.head:
    mov  [rbx + VT.sb_head], eax
    ; Primary row map becomes identity; hidden alternate storage is untouched.
    mov  rdi, [rbx + VT.rowmap]
    xor  ecx, ecx
.maps:
    mov  [rdi + rcx*2], cx
    inc  ecx
    cmp  ecx, [rbx + VT.maxrows]
    jb   .maps
    xor  r14d, r14d
.screen_rows:
    mov  rax, r14
    imul rax, [rbp + VTRF.stride]
    add  rax, [rbx + VT.cells]
    mov  rdi, rax
    mov  rsi, 0
    cmp  r14, r13
    jae  .blank_screen_row
    mov  rax, [rbp + VTRF.screen]
    add  rax, r14
    cmp  rax, [rbp + VTRF.total]
    jae  .blank_screen_row
    push rdi
    call vt_rf_output_ptr
    mov  rsi, rax
    pop  rdi
.blank_screen_row:
    call vt_rf_commit_row
    inc  r14d
    cmp  r14d, [rbx + VT.maxrows]
    jb   .screen_rows
    mov  rax, [rbp + VTRF.screen]
    mov  [rbx + VT.rf_screen], rax
    mov  rax, [rbp + VTRF.oldest]
    mov  [rbx + VT.rf_oldest], rax
    add  rax, [rbx + VT.rf_dropped]
    jnc  .drop_count
    mov  rax, -1
.drop_count:
    mov  [rbx + VT.rf_dropped], rax
    ; Map primary live/saved cursor, retaining pending right-margin semantics.
    mov  rax, [rbx + VT.rf_points + 16]
    sub  rax, [rbp + VTRF.screen]
    mov  ecx, [rbx + VT.rf_points + 24]
    xor  edx, edx
    cmp  ecx, r12d
    jb   .cursor_ready
    lea  ecx, [r12d - 1]
    mov  edx, 1
.cursor_ready:
    cmp  qword [rbp + VTRF.hidden], 0
    jne  .hidden_cursor
    mov  [rbx + VT.cy], eax
    mov  [rbx + VT.cx], ecx
    mov  [rbx + VT.wrap], dl
    jmp  .saved_cursor
.hidden_cursor:
    mov  [rbx + VT.saved + VTSV_CY], eax
    mov  [rbx + VT.saved + VTSV_CX], ecx
    mov  [rbx + VT.saved + VTSV_WRAP], dl
.saved_cursor:
    cmp  byte [rbx + VT.saved + VTSV_VALID], 0
    je   .success
    cmp  qword [rbp + VTRF.hidden], 0
    jne  .success
    mov  rax, [rbx + VT.rf_points + 48]
    sub  rax, [rbp + VTRF.screen]
    cmp  rax, r13
    jae  .saved_evicted
    mov  [rbx + VT.saved + VTSV_CY], eax
    mov  ecx, [rbx + VT.rf_points + 56]
    xor  edx, edx
    cmp  ecx, r12d
    jb   .saved_ready
    lea  ecx, [r12d - 1]
    mov  edx, 1
.saved_ready:
    mov  [rbx + VT.saved + VTSV_CX], ecx
    mov  [rbx + VT.saved + VTSV_WRAP], dl
    jmp  .success
.saved_evicted:
    mov  byte [rbx + VT.saved + VTSV_VALID], 0
.success:
    mov  dword [rbx + VT.rf_done], 1
    mov  eax, 1
    jmp  .out
.refuse:
    mov  eax, [rbp + VTRF.oldgaps]
    mov  [rbx + VT.rf_points + 92], eax
    mov  eax, [rbp + VTRF.oldgaps + 8]
    mov  [rbx + VT.rf_points + 124], eax
    cmp  qword [rbx + VT.rf_refused], -1
    je   .refused_counted
    inc  qword [rbx + VT.rf_refused]
.refused_counted:
    xor  eax, eax
.out:
    cld
    add  rsp, VTRF_size
    pop  r15
    pop  r14
    pop  rbp
    ret

;; ZF=1 overlap/overflow, ZF=0 disjoint. Preserve input range registers.
vt_rf_disjoint:
    test rdi, rdi
    jz   .bad
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    cmp  rdi, [rbp + VTRF.scratchend]
    jae  .good
    cmp  rax, [rbx + VT.rf_base]
    jbe  .good
.bad:
    xor  eax, eax
    ret
.good:
    mov  eax, 1
    test eax, eax
    ret

;; Source absolute row -> pointer and meaningful scan width. Primary only.
vt_rf_input_row:
    mov  rax, [rbp + VTRF.row]
    cmp  rax, [rbp + VTRF.oldcount]
    jae  .screen
    mov  esi, [rbp + VTRF.oldcount]
    sub  esi, eax
    mov  rdi, rbx
    call vt_scrollback_line
    mov  ecx, [rbx + VT.maxcols]     ; old saved rows may predate a width change
    jmp  .ready
.screen:
    sub  rax, [rbp + VTRF.oldcount]
    mov  rdx, [rbx + VT.rowmap]
    movzx eax, word [rdx + rax*2]
    imul rax, [rbp + VTRF.stride]
    add  rax, [rbx + VT.cells]
    mov  ecx, [rbx + VT.cols]
.ready:
    mov  [rbp + VTRF.src], rax
    mov  [rbp + VTRF.limit], rcx
    ret

;; Full32B lifetime, last written/style cell; wrap marks are row metadata.
vt_rf_extent:
    mov  rdi, [rbp + VTRF.src]
    xor  ecx, ecx
    xor  edx, edx
    mov  qword [rbp + VTRF.soft], 0
.scan:
    cmp  rcx, [rbp + VTRF.limit]
    jae  .done
    cmp  byte [rdi + VTC_WRAP], 0
    je   .content
    mov  qword [rbp + VTRF.soft], 1
.content:
    mov  eax, [rdi + VTC_CP]
    or   eax, [rdi + VTC_FG]
    or   eax, [rdi + VTC_BG]
    movzx r8d, word [rdi + VTC_FL]
    or   eax, r8d
    test eax, eax
    jz   .next
    lea  rdx, [rcx + 1]
.next:
    add  rdi, VT_CELL
    inc  ecx
    jmp  .scan
.done:
    mov  [rbp + VTRF.end], rdx
    ret

vt_rf_clear_output:
    mov  rax, [rbp + VTRF.slot]
    imul rax, [rbp + VTRF.stride]
    add  rax, [rbx + VT.rf_base]
    mov  [rbp + VTRF.dst], rax
    mov  rdi, rax
    mov  ecx, r12d
    shl  ecx, 2
    xor  eax, eax
    rep  stosq
    mov  rdi, [rbp + VTRF.dst]
    mov  ecx, r12d
.widths:
    mov  byte [rdi + VTC_W], 1
    add  rdi, VT_CELL
    loop .widths
    ret
vt_rf_soft_break:
    mov  rax, r12
    dec  rax
    imul rax, VT_CELL
    add  rax, [rbp + VTRF.dst]
    mov  byte [rax + VTC_WRAP], 1
vt_rf_next_output:
    inc  qword [rbp + VTRF.outrow]
    inc  qword [rbp + VTRF.slot]
    mov  rax, [rbp + VTRF.slot]
    cmp  rax, [rbp + VTRF.cap]
    jb   .slot
    mov  qword [rbp + VTRF.slot], 0
.slot:
    mov  qword [rbp + VTRF.outcol], 0
    jmp  vt_rf_clear_output

;; Before copying leader, map both its old cells to the same new leader.
vt_rf_map_cell:
    xor  ecx, ecx
    lea  rdi, [rbx + VT.rf_points]
.each:
    mov  rax, [rbp + VTRF.row]
    cmp  [rdi + rcx], rax
    jne  .next
    mov  edx, [rdi + rcx + 8]
    cmp  rdx, [rbp + VTRF.col]
    jb   .next
    mov  rax, [rbp + VTRF.col]
    add  rax, [rbp + VTRF.step]
    cmp  rdx, rax
    jae  .next
    mov  rax, [rbp + VTRF.outrow]
    mov  [rdi + rcx + 16], rax
    mov  eax, [rbp + VTRF.outcol]
    mov  [rdi + rcx + 24], eax
    cmp  dword [rdi + rcx + 12], 2     ; existing exclusive endpoint is a boundary
    jne  .next
    mov  dword [rdi + rcx + 28], 1
.next:
    add  ecx, 32
    cmp  ecx, 6 * 32
    jb   .each
    ret
vt_rf_map_end:
    xor  ecx, ecx
    lea  rdi, [rbx + VT.rf_points]
.each:
    mov  rax, [rbp + VTRF.row]
    cmp  [rdi + rcx], rax
    jne  .next
    mov  edx, [rdi + rcx + 8]
    cmp  rdx, [rbp + VTRF.end]
    jb   .next
    mov  rax, [rbp + VTRF.outrow]
    mov  [rdi + rcx + 16], rax
    mov  eax, [rbp + VTRF.outcol]
    mov  [rdi + rcx + 24], eax
    cmp  dword [rdi + rcx + 12], 0
    je   .next
    mov  dword [rdi + rcx + 28], 1     ; inclusive source padding ends BEFORE next text
.next:
    add  ecx, 32
    cmp  ecx, 6 * 32
    jb   .each
    ret

vt_rf_output_ptr:
    xor  edx, edx
    div  qword [rbp + VTRF.cap]
    imul rdx, [rbp + VTRF.stride]
    mov  rax, [rbx + VT.rf_base]
    add  rax, rdx
    ret

;; Clear complete destination row, copy only newcols from the built ring.
vt_rf_commit_row:
    push rdi
    push rsi
    mov  ecx, [rbx + VT.maxcols]
    shl  ecx, 2
    xor  eax, eax
    rep  stosq
    pop  rsi
    pop  rdi
    push rdi
    mov  ecx, [rbx + VT.maxcols]
.widths:
    mov  byte [rdi + VTC_W], 1
    add  rdi, VT_CELL
    loop .widths
    pop  rdi
    test rsi, rsi
    jz   .out
    mov  ecx, r12d
    shl  ecx, 2
    rep  movsq
.out:
    ret
