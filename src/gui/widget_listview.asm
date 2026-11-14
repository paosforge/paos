;; MODULE gui/widget_listview
;; LAYER 6
;; EXPORTS wgt_listview_draw, wgt_listview_set, wgt_listview_get, wgt_listview_overlay_draw, wgt_listview_pointer_press, wgt_listview_dropdown_press, wgt_listview_dropdown_kat, wgt_listview_modes_kat, wgt_listview_parse_parents, wgt_listview_type, wgt_listview_set_hook, wgt_listview_get_hook, wgt_listview_pointer_hook
;; IMPORTS core/unicode_edit, gui/widget, gui/window, gui/chat_app, gui/form_loader, gui/window_mgmt, gui/wm_pointer, core/lib/fmt, core/lib/str, boot/serial
;; CAPS
;; OWNER saga:gui_foundation_ladder

; The one bounded table/list view. Plain, dropdown, tree and radio are modes of
; this same type; pixels and semantic readback consume the same canonical state.
WGT_LIST_INDEX_MAX equ 4095
LV_MODE             equ WGI_RSVD       ; byte: 0=list, 1=dropdown
LV_OPEN             equ WGI_RSVD+1     ; byte: popup is live
LV_OVERLAY          equ WGI_EDITPAD    ; dd: declared overlay widget id + 1
LV_MODE_LIST        equ 0
LV_MODE_DROPDOWN    equ 1
LV_MODE_TREE        equ 2
LV_MODE_RADIO       equ 3
LV_PARENTS          equ WGI_MINVAL     ; qword: 4-bit parent indices, 15=root
LV_EXPANDED         equ WGI_MAXVAL     ; qword: expanded-node bit mask
LV_DISABLED         equ WGI_STEP       ; qword: disabled-choice bit mask
LV_TREE_ROOT        equ 15
LV_TREE_DEPTH_MAX   equ 4
LV_TREE_OPTIONS_MAX equ 15
LV_ROW_H            equ 24
LV_OPTIONS_MAX      equ 16
LV_INTENT_POINTER   equ 1
LV_INTENT_VERB_SET  equ 4
wgt_listview_draw:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  byte [rbx + LV_MODE], LV_MODE_DROPDOWN
    je   .dropdown
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_OUTLINE
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    inc  r8d
    mov  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r10d, [rbx + WGI_W]
    sub  r10d, 2
    mov  r11d, [rbx + WGI_H]
    sub  r11d, 2
    mov  ebx, GUI_TOK_WINDOW_BODY
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    inc  r8d
    mov  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r10d, [rbx + WGI_W]
    sub  r10d, 2
    mov  r11d, 22
    mov  ebx, GUI_TOK_SELECTION_MUTED
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    lea  rdi, [rbx + WGI_VAL]
    mov  r8d, [rbx + WGI_X]
    add  r8d, 6
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 4
    mov  r11d, [rbx + WGI_W]            ; RCQ-16 S2: the bound before EBX holds the colour
    sub  r11d, 12
    shr  r11d, 3
    mov  ebx, GUI_TOK_TITLE_TEXT
    mov  ecx, GUI_TOK_SELECTION_MUTED
    call fb_draw_str_n
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    je   .mode_rows
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    je   .mode_rows
    mov  edi, r12d
    call wgt_listview_draw_rows
    jmp  .out
.mode_rows:
    mov  edi, r12d
    call wgt_listview_draw_mode_rows
    jmp  .out
.dropdown:
    mov  edi, r12d
    call wgt_listview_draw_dropdown_closed
.out:
    pop  r12
    pop  rbx
    ret

; Render each comma-delimited live field as one visible row. The source pointer
; comes from the same binding builder WINTREE uses, so pixels and semantics
; cannot drift into separate sysprops/netmon snapshots. This remains a generic
; list presentation: later consumers can supply the same bounded row stream.
wgt_listview_draw_rows:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    call form_widget_tree_text_ptr
    test rax, rax
    jz   .out
    mov  r13, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  eax, [rax + WGI_H]
    sub  eax, 30
    jbe  .out
    xor  edx, edx
    mov  ecx, 18
    div  ecx
    mov  r15d, eax                    ; rows that fit below the header
    xor  r14d, r14d
.row:
    cmp  r14d, r15d
    jae  .out
    cmp  byte [r13], 0
    je   .out
    lea  rdi, [rel wgt_list_row_buf]
    xor  ecx, ecx
.copy:
    mov  al, [r13]
    test al, al
    jz   .emit
    cmp  al, ','
    je   .emit_advance
    cmp  ecx, 63
    jae  .skip_tail
    mov  [rdi + rcx], al
    inc  ecx
    inc  r13
    jmp  .copy
.skip_tail:
    inc  r13
    cmp  byte [r13], 0
    je   .emit
    cmp  byte [r13], ','
    jne  .skip_tail
.emit_advance:
    inc  r13
.emit:
    mov  byte [rdi + rcx], 0
    test ecx, ecx
    jz   .row_next
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  edx, [rbx + WGI_W]
    sub  edx, 12
    jbe  .row_next
    shr  edx, 3                      ; framebuffer's existing byte/glyph budget
    cmp  edx, 63
    jbe  .bounded
    mov  edx, 63
.bounded:
    ; Both scratch63 and the narrower framebuffer width can split a scalar.
    ; Trim in-place to a canonical complete prefix before either is rendered.
    lea  rdi, [rel wgt_list_row_buf]
    mov  rsi, rdi
    call ue_utf8_cstr_prefix
    test eax, eax
    jz   .row_next
    mov  r11d, eax                   ; framebuffer receives only complete scalars
    mov  r8d, [rbx + WGI_X]
    add  r8d, 6
    mov  r9d, r14d
    imul r9d, 18
    add  r9d, [rbx + WGI_Y]
    add  r9d, 30
    mov  ebx, GUI_TOK_LABEL_TEXT
    mov  ecx, GUI_TOK_WINDOW_BODY
    lea  rdi, [rel wgt_list_row_buf]
    call fb_draw_str_n
.row_next:
    inc  r14d
    jmp  .row
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=list id -> EAX bit mask of projected tree rows. A node is visible only
; when all of its ancestors are expanded. The walk is bounded even if live
; state is corrupted; validated setters never install such a state.
wgt_listview_visible_mask:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    call wgt_listview_option_count
    test eax, eax
    jz   .bad
    mov  r13d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r14, [rax + LV_PARENTS]
    mov  r15, [rax + LV_EXPANDED]
    xor  ebx, ebx
    xor  r8d, r8d
.node:
    cmp  r8d, r13d
    jae  .done
    mov  r9d, r8d
    xor  r10d, r10d
.ancestor:
    mov  ecx, r9d
    shl  ecx, 2
    mov  rax, r14
    shr  rax, cl
    and  eax, 15
    cmp  eax, LV_TREE_ROOT
    je   .visible
    cmp  eax, r13d
    jae  .bad
    bt   r15, rax
    jnc  .next
    mov  r9d, eax
    inc  r10d
    cmp  r10d, LV_TREE_DEPTH_MAX
    jbe  .ancestor
    jmp  .bad
.visible:
    bts  ebx, r8d
.next:
    inc  r8d
    jmp  .node
.done:
    mov  eax, ebx
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=list id, ESI=visible ordinal -> EAX=canonical option index or -1.
wgt_listview_visible_index:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    je   .tree
    mov  edi, r12d
    call wgt_listview_option_count
    cmp  r13d, eax
    jae  .miss
    mov  eax, r13d
    jmp  .out
.tree:
    mov  edi, r12d
    call wgt_listview_visible_mask
    mov  ebx, eax
    xor  ecx, ecx
    xor  edx, edx
.scan:
    cmp  ecx, LV_OPTIONS_MAX
    jae  .miss
    bt   ebx, ecx
    jnc  .next
    cmp  edx, r13d
    je   .found
    inc  edx
.next:
    inc  ecx
    jmp  .scan
.found:
    mov  eax, ecx
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=list id, ESI=canonical option index -> EAX=bounded tree depth.
wgt_listview_tree_depth:
    push rbx
    push r12
    mov  r12d, esi
    call wgt_slot_ptr
    mov  rbx, [rax + LV_PARENTS]
    xor  edx, edx
.walk:
    mov  ecx, r12d
    shl  ecx, 2
    mov  rax, rbx
    shr  rax, cl
    and  eax, 15
    cmp  eax, LV_TREE_ROOT
    je   .done
    mov  r12d, eax
    inc  edx
    cmp  edx, LV_TREE_DEPTH_MAX
    jbe  .walk
    xor  edx, edx
.done:
    mov  eax, edx
    pop  r12
    pop  rbx
    ret

; EDI=list id, ESI=canonical option index -> EAX=1 iff it owns a child.
wgt_listview_tree_has_child:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call wgt_listview_option_count
    mov  edx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, [rax + LV_PARENTS]
    xor  r8d, r8d
.scan:
    cmp  r8d, edx
    jae  .no
    mov  ecx, r8d
    shl  ecx, 2
    mov  rax, rbx
    shr  rax, cl
    and  eax, 15
    cmp  eax, r13d
    je   .yes
    inc  r8d
    jmp  .scan
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Tree and radio rows use the list's canonical text, selection and mode state.
wgt_listview_draw_mode_rows:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, edi
    call wgt_slot_ptr
    mov  eax, [rax + WGI_H]
    sub  eax, 30
    jbe  .out
    xor  edx, edx
    mov  ecx, 18
    div  ecx
    mov  r13d, eax
    xor  r14d, r14d
.row:
    cmp  r14d, r13d
    jae  .out
    mov  edi, r12d
    mov  esi, r14d
    call wgt_listview_visible_index
    cmp  eax, -1
    je   .out
    mov  r15d, eax
    mov  edi, r12d
    mov  esi, r15d
    call wgt_listview_copy_option
    test eax, eax
    jz   .out
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    je   .tree
    lea  rdi, [rel str_lv_radio_off]
    bt   qword [rax + LV_DISABLED], r15
    jc   .radio_disabled
    cmp  r15d, [rax + WGI_SEL_LO]
    jne  .prefix
    lea  rdi, [rel str_lv_radio_on]
    jmp  .prefix
.radio_disabled:
    lea  rdi, [rel str_lv_radio_disabled]
    jmp  .prefix
.tree:
    mov  edi, r12d
    mov  esi, r15d
    call wgt_listview_tree_depth
    mov  [rsp], eax
    mov  edi, r12d
    mov  esi, r15d
    call wgt_listview_tree_has_child
    lea  rdi, [rel str_lv_tree_leaf]
    test eax, eax
    jz   .tree_prefix
    mov  edi, r12d
    call wgt_slot_ptr
    lea  rdi, [rel str_lv_tree_closed]
    bt   qword [rax + LV_EXPANDED], r15
    jnc  .tree_prefix
    lea  rdi, [rel str_lv_tree_open]
.tree_prefix:
    mov  rsi, rdi
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, rsi
    mov  r8d, [rax + WGI_X]
    add  r8d, 6
    mov  ecx, [rsp]
    imul ecx, 12
    add  r8d, ecx
    jmp  .prefix_xy
.prefix:
    mov  rsi, rdi
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, rsi
    mov  r8d, [rax + WGI_X]
    add  r8d, 6
.prefix_xy:
    mov  r9d, r14d
    imul r9d, 18
    add  r9d, [rax + WGI_Y]
    add  r9d, 30
    mov  ebx, GUI_TOK_LABEL_TEXT
    mov  ecx, GUI_TOK_WINDOW_BODY
    mov  r11d, 3
    call fb_draw_str_n
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    add  r8d, 34
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    jne  .label_xy
    mov  ecx, [rsp]
    imul ecx, 12
    add  r8d, ecx
.label_xy:
    mov  r9d, r14d
    imul r9d, 18
    add  r9d, [rax + WGI_Y]
    add  r9d, 30
    mov  r11d, [rax + WGI_W]
    sub  r11d, 40
    shr  r11d, 3
    lea  rdi, [rel wgt_list_row_buf]
    mov  ebx, GUI_TOK_LABEL_TEXT
    mov  ecx, GUI_TOK_WINDOW_BODY
    call fb_draw_str_n
    inc  r14d
    jmp  .row
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_listview_set:
    jmp  wgt_listview_set_full

; Dedicated full implementation used by the registry. Kept separate from the
; small label above so RSI (field) remains stable across strcmp calls.
wgt_listview_set_full:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rsi
    mov  r14, rdx
    mov  rax, [rel wgt_listview_set_hook]
    test rax, rax
    jz   .builtin
    call rax
    cmp  eax, -1
    jne  .out
.builtin:
    lea  rdi, [rel str_lv_mode]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_mode
    lea  rdi, [rel str_lv_open]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_open
    lea  rdi, [rel str_lv_overlay]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_overlay
    lea  rdi, [rel str_lv_parents]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_parents
    lea  rdi, [rel str_lv_expanded]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_expanded
    lea  rdi, [rel str_lv_disabled]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_disabled
    lea  rdi, [rel str_lv_selection]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_sel
    lea  rdi, [rel str_lv_value]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_sel
    lea  rdi, [rel str_lv_scroll]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .set_scroll
    mov  edi, r12d
    mov  rsi, r13
    mov  rdx, r14
    call wgt_textfield_set
    jmp  .out
.set_mode:
    lea  rdi, [rel str_lv_dropdown]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .mode_dropdown
    lea  rdi, [rel str_lv_tree]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .mode_tree
    lea  rdi, [rel str_lv_radio]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jz   .mode_radio
    lea  rdi, [rel str_lv_list]
    mov  rsi, r14
    call strcmp
    test rax, rax
    jnz  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  byte [rax + LV_MODE], LV_MODE_LIST
    mov  byte [rax + LV_OPEN], 0
    jmp  .redraw_ok
.mode_tree:
    mov  edi, r12d
    call wgt_listview_option_count
    test eax, eax
    jz   .bad
    cmp  eax, LV_TREE_OPTIONS_MAX
    ja   .bad
    mov  ecx, eax
    shl  ecx, 2
    mov  rbx, 1
    shl  rbx, cl
    dec  rbx                         ; root parent in every live nibble
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + LV_PARENTS], rbx
    mov  qword [rax + LV_EXPANDED], 0
    mov  qword [rax + LV_DISABLED], 0
    mov  byte [rax + LV_MODE], LV_MODE_TREE
    mov  byte [rax + LV_OPEN], 0
    jmp  .redraw_ok
.mode_radio:
    mov  edi, r12d
    call wgt_listview_option_count
    test eax, eax
    jz   .bad
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  [rax + WGI_SEL_LO], ebx
    jae  .bad
    mov  qword [rax + LV_DISABLED], 0
    mov  byte [rax + LV_MODE], LV_MODE_RADIO
    mov  byte [rax + LV_OPEN], 0
    jmp  .redraw_ok
.mode_dropdown:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  esi, [rax + LV_OVERLAY]
    test esi, esi
    jz   .bad
    dec  esi
    mov  edi, r12d
    call wgt_listview_validate_overlay
    test eax, eax
    jz   .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    mov  byte [rax + LV_OPEN], 0
    jmp  .redraw_ok
.set_parents:
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    jne  .bad
    mov  edi, r12d
    call wgt_listview_option_count
    mov  edi, eax
    mov  rsi, r14
    call wgt_listview_parse_parents
    jc   .bad
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + LV_PARENTS], rbx
    mov  dword [rax + WGI_INTENT], LV_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    jmp  .redraw_ok
.set_expanded:
    mov  rdi, r14
    call wgt_listview_parse_dec
    jc   .bad
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    jne  .bad
    mov  edi, r12d
    call wgt_listview_option_count
    mov  ecx, eax
    mov  rax, rbx
    shr  rax, cl
    test rax, rax
    jnz  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + LV_EXPANDED], rbx
    mov  dword [rax + WGI_INTENT], LV_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    jmp  .redraw_ok
.set_disabled:
    mov  rdi, r14
    call wgt_listview_parse_dec
    jc   .bad
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    jne  .bad
    mov  edi, r12d
    call wgt_listview_option_count
    mov  ecx, eax
    mov  rax, rbx
    shr  rax, cl
    test rax, rax
    jnz  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_SEL_LO]
    bt   rbx, rcx
    jc   .bad
    mov  [rax + LV_DISABLED], rbx
    mov  dword [rax + WGI_INTENT], LV_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    jmp  .redraw_ok
.set_open:
    mov  rdi, r14
    call wgt_listview_parse_dec
    jc   .bad
    cmp  eax, 1
    ja   .bad
    mov  ebx, eax
    mov  esi, ebx
    mov  edi, r12d
    call wgt_listview_set_open
    test eax, eax
    jnz  .bad
    test ebx, ebx
    jz   .set_open_ok
    ; WIDGETSET is the agent control surface: announce an agent-opened popup
    ; through the host's attention bit without moving keyboard/window focus.
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, WM_MAX
    jae  .bad
    lea  rax, [rel wm_attn]
    mov  byte [rax + rcx], 1
    call wmx_draw_all
.set_open_ok:
    xor  eax, eax
    jmp  .out
.set_overlay:
    mov  rdi, r14
    call wgt_listview_parse_dec
    jc   .bad
    cmp  eax, WGT_MAX
    jae  .bad
    mov  ebx, eax
    mov  esi, eax
    mov  edi, r12d
    call wgt_listview_validate_overlay
    test eax, eax
    jz   .bad
    mov  edi, r12d
    call wgt_slot_ptr
    inc  ebx
    mov  [rax + LV_OVERLAY], ebx
    mov  byte [rax + LV_OPEN], 0
    jmp  .redraw_ok
.set_sel:
    mov  rdi, r14
    call wgt_listview_parse_dec
    jc   .bad
    cmp  rax, WGT_LIST_INDEX_MAX
    ja   .bad
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    je   .selection_bounded
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    je   .selection_bounded
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    jne  .selection_valid
.selection_bounded:
    mov  edi, r12d
    call wgt_listview_option_count
    test eax, eax
    jz   .bad
    cmp  ebx, eax
    jae  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    jne  .selection_valid
    bt   qword [rax + LV_DISABLED], rbx
    jc   .bad
.selection_valid:
    mov  [rax + WGI_SEL_LO], ebx
    mov  byte [rax + LV_OPEN], 0
    mov  dword [rax + WGI_INTENT], LV_INTENT_VERB_SET
    inc  qword [rax + WGI_INTENT_SEQ]
    jmp  .redraw_ok
.set_scroll:
    mov  rdi, r14
    call wgt_listview_parse_dec
    jc   .bad
    cmp  rax, WGT_LIST_INDEX_MAX
    ja   .bad
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + WGI_SCROLL], ebx
.redraw_ok:
    call wmx_draw_all
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_listview_get:
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    mov  rax, [rel wgt_listview_get_hook]
    test rax, rax
    jz   .builtin
    call rax
    test rax, rax
    jnz  .out
.builtin:
    lea  rdi, [rel str_lv_mode]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .mode
    lea  rdi, [rel str_lv_open]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .open
    lea  rdi, [rel str_lv_overlay]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .overlay
    lea  rdi, [rel str_lv_parents]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .parents
    lea  rdi, [rel str_lv_expanded]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .expanded
    lea  rdi, [rel str_lv_disabled]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .disabled
    lea  rdi, [rel str_lv_intent]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .intent
    lea  rdi, [rel str_lv_intent_seq]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .intent_seq
    lea  rdi, [rel str_lv_selection]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .selection
    lea  rdi, [rel str_lv_value]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .selection
    lea  rdi, [rel str_lv_scroll]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .scroll
    mov  edi, r12d
    mov  rsi, r13
    call wgt_textfield_get
    jmp  .out
.mode:
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    jne  .mode_tree_test
    lea  rax, [rel str_lv_dropdown]
    jmp  .out
.mode_tree_test:
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    jne  .mode_radio_test
    lea  rax, [rel str_lv_tree]
    jmp  .out
.mode_radio_test:
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    jne  .mode_list
    lea  rax, [rel str_lv_radio]
    jmp  .out
.mode_list:
    lea  rax, [rel str_lv_list]
    jmp  .out
.open:
    mov  edi, r12d
    call wgt_slot_ptr
    movzx edi, byte [rax + LV_OPEN]
    jmp  .number
.overlay:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + LV_OVERLAY]
    test edi, edi
    jz   .number
    dec  edi
    jmp  .number
.parents:
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    jne  .bad_field
    mov  edi, r12d
    call wgt_listview_format_parents
    jmp  .out
.expanded:
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_TREE
    jne  .bad_field
    mov  rdi, [rax + LV_EXPANDED]
    jmp  .number
.disabled:
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    jne  .bad_field
    mov  rdi, [rax + LV_DISABLED]
    jmp  .number
.intent:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_INTENT]
    jmp  .number
.intent_seq:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, [rax + WGI_INTENT_SEQ]
    jmp  .number
.selection:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_SEL_LO]
    jmp  .number
.scroll:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_SCROLL]
.number:
    lea  rsi, [rel wgt_list_num_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel wgt_list_num_buf]
    jmp  .out
.bad_field:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret

; EDI=id, ESI=pointer x, EDX=pointer y -> EAX=1 iff this list consumed press.
; Tree/radio clicks update the same state used by draw/readback and emit the
; common pointer intent. Disabled radio rows are strict atomic refusals.
wgt_listview_pointer_press:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, edx
    mov  r14d, esi
    mov  rax, [rel wgt_listview_pointer_hook]
    test rax, rax
    jz   .builtin
    call rax
    test eax, eax
    jnz  .out
.builtin:
    mov  edi, r12d
    mov  esi, r14d
    mov  edx, r13d
    call wgt_slot_ptr
    mov  rbx, rax
    xor  eax, eax
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rbx + WGI_TYPE], ecx
    jne  .out
    cmp  byte [rbx + LV_MODE], LV_MODE_DROPDOWN
    jne  .mode_rows
    movzx esi, byte [rbx + LV_OPEN]
    xor  esi, 1
    mov  edi, r12d
    call wgt_listview_set_open
    test eax, eax
    setz al
    movzx eax, al
    jmp  .out
.mode_rows:
    cmp  byte [rbx + LV_MODE], LV_MODE_TREE
    je   .row_hit
    cmp  byte [rbx + LV_MODE], LV_MODE_RADIO
    jne  .out
.row_hit:
    mov  eax, [rbx + WGI_Y]
    add  eax, 30
    cmp  r13d, eax
    jb   .refuse
    sub  r13d, eax
    mov  eax, r13d
    xor  edx, edx
    mov  ecx, 18
    div  ecx
    mov  r14d, eax
    mov  edi, r12d
    mov  esi, r14d
    call wgt_listview_visible_index
    cmp  eax, -1
    je   .refuse
    mov  r14d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  byte [rax + LV_MODE], LV_MODE_RADIO
    je   .radio
    mov  edi, r12d
    mov  esi, r14d
    call wgt_listview_tree_has_child
    test eax, eax
    jz   .record
    mov  edi, r12d
    call wgt_slot_ptr
    bt   qword [rax + LV_EXPANDED], r14
    jc   .collapse
    bts  qword [rax + LV_EXPANDED], r14
    jmp  .record
.collapse:
    btr  qword [rax + LV_EXPANDED], r14
    jmp  .record
.radio:
    bt   qword [rax + LV_DISABLED], r14
    jc   .refuse
.record:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], r14d
    mov  dword [rax + WGI_INTENT], LV_INTENT_POINTER
    inc  qword [rax + WGI_INTENT_SEQ]
    call wmx_draw_all
    mov  eax, 1
    jmp  .out
.refuse:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=x, ESI=y -> EAX=0 no live popup, 1 outside-close, 2 selection.
; This runs before window hit-testing because a sanctioned overlay may extend
; beyond its host. Outside-close changes only LV_OPEN, never selection/event.
wgt_listview_dropdown_press:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, [rel wgt_count]
    xor  r15d, r15d
.scan:
    test r14d, r14d
    jz   .outside
    dec  r14d
    mov  edi, r14d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rbx + WGI_TYPE], ecx
    jne  .scan
    cmp  byte [rbx + LV_MODE], LV_MODE_DROPDOWN
    jne  .scan
    cmp  byte [rbx + LV_OPEN], 1
    jne  .scan
    mov  ecx, [rbx + WGI_WIN]           ; RCQ-16 F5-R1/R2: a popup paint does not show
    call wgt_overlay_host_shown         ; (another window's, a minimised focused one's,
    jc   .scan                          ; any under the lock) takes no press
    mov  esi, [rbx + LV_OVERLAY]
    test esi, esi
    jz   .armed
    dec  esi
    mov  edi, r14d
    call wgt_listview_validate_overlay
    test eax, eax
    jz   .armed
    mov  edi, r14d
    call wgt_slot_ptr
    mov  ebx, [rax + LV_OVERLAY]
    dec  ebx
    mov  edi, ebx
    call wgt_slot_ptr
    call wgt_flyout_painted             ; F5-R2 (srcreview L-a): a popup that fails the
    jc   .scan                          ; paint rect gate takes no press and no outside close
    mov  r15d, 1
    cmp  r12d, [rax + WGI_X]
    jl   .scan
    mov  ecx, [rax + WGI_X]
    add  ecx, [rax + WGI_W]
    cmp  r12d, ecx
    jge  .scan
    cmp  r13d, [rax + WGI_Y]
    jl   .scan
    mov  ecx, [rax + WGI_Y]
    add  ecx, [rax + WGI_H]
    cmp  r13d, ecx
    jge  .scan
    mov  ecx, r13d
    sub  ecx, [rax + WGI_Y]
    mov  eax, ecx
    xor  edx, edx
    mov  ecx, LV_ROW_H
    div  ecx
    mov  ebx, eax
    mov  edi, r14d
    call wgt_listview_option_count
    test eax, eax
    jz   .outside
    cmp  ebx, eax
    jae  .outside
    mov  edi, r14d
    call wgt_slot_ptr
    mov  [rax + WGI_SEL_LO], ebx
    mov  byte [rax + LV_OPEN], 0
    mov  dword [rax + WGI_INTENT], LV_INTENT_POINTER
    inc  qword [rax + WGI_INTENT_SEQ]
    call wmx_draw_all
    mov  eax, 2
    jmp  .out
.armed:
    mov  r15d, 1
    jmp  .scan
.outside:
    test r15d, r15d
    jz   .none
    xor  r14d, r14d
.close_loop:
    cmp  r14d, [rel wgt_count]
    jae  .closed
    mov  edi, r14d
    call wgt_slot_ptr
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .close_next
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    jne  .close_next
    mov  byte [rax + LV_OPEN], 0
.close_next:
    inc  r14d
    jmp  .close_loop
.closed:
    call wmx_draw_all
    mov  eax, 1
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=overlay widget id. The declaration owns geometry/z/clip; the listview
; owns dropdown content and state. There is no second widget type or painter.
wgt_listview_overlay_draw:
    push r12
    push r13
    mov  r13d, edi
    xor  r12d, r12d
.scan:
    cmp  r12d, [rel wgt_count]
    jae  .out
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .next
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    jne  .next
    cmp  byte [rax + LV_OPEN], 1
    jne  .next
    mov  eax, [rax + LV_OVERLAY]
    test eax, eax
    jz   .next
    dec  eax
    cmp  eax, r13d
    jne  .next
    mov  edi, r12d
    mov  esi, r13d
    call wgt_listview_draw_popup
.next:
    inc  r12d
    jmp  .scan
.out:
    pop  r13
    pop  r12
    ret

wgt_listview_draw_dropdown_closed:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_OUTLINE
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    inc  r8d
    mov  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r10d, [rbx + WGI_W]
    sub  r10d, 2
    mov  r11d, [rbx + WGI_H]
    sub  r11d, 2
    mov  ebx, GUI_TOK_WINDOW_BODY
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  esi, [rax + WGI_SEL_LO]
    mov  edi, r12d
    call wgt_listview_copy_option
    test eax, eax
    jz   .arrow
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    add  r8d, 6
    mov  r9d, [rax + WGI_Y]
    add  r9d, 6
    mov  r11d, [rax + WGI_W]
    sub  r11d, 32
    shr  r11d, 3
    lea  rdi, [rel wgt_list_row_buf]
    mov  ebx, GUI_TOK_LABEL_TEXT
    mov  ecx, GUI_TOK_WINDOW_BODY
    call fb_draw_str_n
.arrow:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    add  r8d, [rax + WGI_W]
    sub  r8d, 18
    mov  r9d, [rax + WGI_Y]
    add  r9d, 6
    mov  r11d, 1
    lea  rdi, [rel str_lv_arrow]
    mov  ebx, GUI_TOK_LABEL_TEXT
    mov  ecx, GUI_TOK_WINDOW_BODY
    call fb_draw_str_n
    pop  r12
    pop  rbx
    ret

; EDI=list id, ESI=overlay id.
wgt_listview_draw_popup:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  edi, r13d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_OUTLINE
    call fb_fill_rect
    mov  edi, r12d
    call wgt_listview_option_count
    mov  r15d, eax
    mov  edi, r13d
    call wgt_slot_ptr
    mov  eax, [rax + WGI_H]
    xor  edx, edx
    mov  ecx, LV_ROW_H
    div  ecx
    cmp  r15d, eax
    cmova r15d, eax
    xor  r14d, r14d
.row:
    cmp  r14d, r15d
    jae  .out
    mov  edi, r13d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    inc  r8d
    mov  r9d, r14d
    imul r9d, LV_ROW_H
    add  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r10d, [rbx + WGI_W]
    sub  r10d, 2
    mov  r11d, LV_ROW_H-1
    mov  ebx, GUI_TOK_WINDOW_BODY
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  r14d, [rax + WGI_SEL_LO]
    jne  .fill
    mov  ebx, GUI_TOK_SELECTION_MUTED
.fill:
    call fb_fill_rect
    mov  edi, r12d
    mov  esi, r14d
    call wgt_listview_copy_option
    test eax, eax
    jz   .next
    mov  edi, r13d
    call wgt_slot_ptr
    mov  r8d, [rax + WGI_X]
    add  r8d, 6
    mov  r9d, r14d
    imul r9d, LV_ROW_H
    add  r9d, [rax + WGI_Y]
    add  r9d, 5
    mov  r11d, [rax + WGI_W]
    sub  r11d, 12
    shr  r11d, 3
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, GUI_TOK_WINDOW_BODY
    mov  ebx, GUI_TOK_LABEL_TEXT
    cmp  r14d, [rax + WGI_SEL_LO]
    jne  .text
    mov  ecx, GUI_TOK_SELECTION_MUTED
    mov  ebx, GUI_TOK_TITLE_TEXT        ; RCQ-16 S3: LABEL_TEXT is 4.02:1 on the 3:1 selection; white 6.48:1
.text:
    lea  rdi, [rel wgt_list_row_buf]
    call fb_draw_str_n
.next:
    inc  r14d
    jmp  .row
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=list id -> EAX=count, zero for malformed/empty option streams.
wgt_listview_option_count:
    call wgt_slot_ptr
    lea  rdx, [rax + WGI_VAL]
    xor  eax, eax
    xor  ecx, ecx
.scan:
    mov  r8b, [rdx]
    test r8b, r8b
    jz   .end
    cmp  r8b, ','
    je   .comma
    inc  ecx
    inc  rdx
    jmp  .scan
.comma:
    test ecx, ecx
    jz   .bad
    inc  eax
    cmp  eax, LV_OPTIONS_MAX
    jae  .bad
    xor  ecx, ecx
    inc  rdx
    jmp  .scan
.end:
    test ecx, ecx
    jz   .bad
    inc  eax
    cmp  eax, LV_OPTIONS_MAX
    jbe  .out
.bad:
    xor  eax, eax
.out:
    ret

; EDI=list id, ESI=option index -> EAX=1 and bounded row buffer, else zero.
wgt_listview_copy_option:
    push rbx
    call wgt_slot_ptr
    lea  rdx, [rax + WGI_VAL]
    xor  ebx, ebx
.seek:
    cmp  ebx, esi
    je   .copy_start
    mov  al, [rdx]
    test al, al
    jz   .bad
    inc  rdx
    cmp  al, ','
    jne  .seek
    inc  ebx
    jmp  .seek
.copy_start:
    lea  rdi, [rel wgt_list_row_buf]
    xor  ecx, ecx
.copy:
    mov  al, [rdx]
    test al, al
    jz   .done
    cmp  al, ','
    je   .done
    cmp  ecx, 63
    jae  .done
    mov  [rdi + rcx], al
    inc  ecx
    inc  rdx
    jmp  .copy
.done:
    mov  byte [rdi + rcx], 0
    test ecx, ecx
    setnz al
    movzx eax, al
    pop  rbx
    ret
.bad:
    mov  byte [rel wgt_list_row_buf], 0
    xor  eax, eax
    pop  rbx
    ret

; EDI=list id, ESI=overlay id -> EAX=1 iff it is a declared overlay in the
; same host. This is also the runtime refusal gate for agent rebinding.
wgt_listview_validate_overlay:
    push rbx
    push r12
    mov  r12d, edi
    xor  eax, eax
    cmp  esi, [rel wgt_count]
    jae  .out
    mov  edi, esi
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [rel wgt_overlay_type]
    inc  ecx
    cmp  [rbx + WGI_TYPE], ecx
    jne  .out
    cmp  dword [rbx + WGI_LAYER], 1
    jne  .out
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, [rbx + WGI_WIN]
    jne  .out
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

; EDI=option count (1..15), RSI=comma-separated parents using r for a root.
; Return RAX=packed nibbles/CF clear only after the complete vector validates.
; No widget state is touched on refusal.
wgt_listview_parse_parents:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    xor  r14d, r14d
    xor  r15d, r15d
    test r12d, r12d
    jz   .bad
    cmp  r12d, LV_TREE_OPTIONS_MAX
    ja   .bad
.token:
    cmp  r14d, r12d
    jae  .bad
    xor  ebx, ebx
    cmp  byte [r13], 'r'
    jne  .number
    mov  ebx, LV_TREE_ROOT
    inc  r13
    cmp  byte [r13], ','
    je   .store
    cmp  byte [r13], 0
    jne  .bad
    jmp  .store
.number:
    xor  r10d, r10d
.digit:
    movzx eax, byte [r13]
    cmp  al, ','
    je   .number_done
    test al, al
    jz   .number_done
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad
    imul ebx, ebx, 10
    add  ebx, eax
    cmp  ebx, LV_TREE_OPTIONS_MAX-1
    ja   .bad
    inc  r10d
    inc  r13
    jmp  .digit
.number_done:
    test r10d, r10d
    jz   .bad
    cmp  ebx, r12d
    jae  .bad
    cmp  ebx, r14d
    je   .bad
.store:
    mov  ecx, r14d
    shl  ecx, 2
    mov  rax, rbx
    shl  rax, cl
    or   r15, rax
    inc  r14d
    cmp  r14d, r12d
    je   .last
    cmp  byte [r13], ','
    jne  .bad
    inc  r13
    cmp  byte [r13], 0
    je   .bad
    jmp  .token
.last:
    cmp  byte [r13], 0
    jne  .bad
    xor  r14d, r14d
.validate_node:
    cmp  r14d, r12d
    jae  .good
    mov  r8d, r14d
    xor  r9d, r9d
.walk:
    mov  ecx, r8d
    shl  ecx, 2
    mov  rax, r15
    shr  rax, cl
    and  eax, 15
    cmp  eax, LV_TREE_ROOT
    je   .next_node
    cmp  eax, r12d
    jae  .bad
    mov  r8d, eax
    inc  r9d
    cmp  r9d, LV_TREE_DEPTH_MAX
    jbe  .walk
    jmp  .bad
.next_node:
    inc  r14d
    jmp  .validate_node
.good:
    mov  rax, r15
    clc
    jmp  .out
.bad:
    xor  eax, eax
    stc
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=list id -> canonical r/index parent vector in the shared state buffer.
wgt_listview_format_parents:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    call wgt_listview_option_count
    mov  r13d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r14, [rax + LV_PARENTS]
    lea  rbx, [rel wgt_list_state_buf]
    xor  r8d, r8d
    xor  r9d, r9d
.item:
    cmp  r8d, r13d
    jae  .done
    test r8d, r8d
    jz   .value
    mov  byte [rbx + r9], ','
    inc  r9d
.value:
    mov  ecx, r8d
    shl  ecx, 2
    mov  rax, r14
    shr  rax, cl
    and  eax, 15
    cmp  eax, LV_TREE_ROOT
    jne  .number
    mov  byte [rbx + r9], 'r'
    inc  r9d
    jmp  .next
.number:
    cmp  eax, 10
    jb   .ones
    mov  byte [rbx + r9], '1'
    inc  r9d
    sub  eax, 10
.ones:
    add  al, '0'
    mov  [rbx + r9], al
    inc  r9d
.next:
    inc  r8d
    jmp  .item
.done:
    mov  byte [rbx + r9], 0
    mov  rax, rbx
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_listview_parse_dec:
    call wgt_parse_dec
    test rcx, rcx
    jz   .bad
    cmp  byte [rdx], 0
    jne  .bad
    clc
    ret
.bad:
    stc
    ret

; EDI=list id, ESI=open 0/1 -> EAX status. Opening one dropdown closes every
; other popup but deliberately leaves focus and attention untouched.
wgt_listview_set_open:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    cmp  r13d, 1
    ja   .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .bad
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    jne  .bad
    mov  esi, [rax + LV_OVERLAY]
    test esi, esi
    jz   .bad
    dec  esi
    mov  edi, r12d
    call wgt_listview_validate_overlay
    test eax, eax
    jz   .bad
    xor  ebx, ebx
.close:
    cmp  ebx, [rel wgt_count]
    jae  .store
    mov  edi, ebx
    call wgt_slot_ptr
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .next
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    jne  .next
    mov  byte [rax + LV_OPEN], 0
.next:
    inc  ebx
    jmp  .close
.store:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + LV_OPEN], r13b
    call wmx_draw_all
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_listview_dropdown_close:
    call wgt_slot_ptr
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .done
    cmp  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    jne  .done
    mov  byte [rax + LV_OPEN], 0
.done:
    ret

; Boot KAT for canonical tree/radio state, pointer intent, and atomic hostile
; input refusal. It runs through the public set/get paths used by WIDGETSET.
wgt_listview_modes_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel wgt_count]
    mov  edi, [rel wgt_listview_type]
    cmp  edi, -1
    je   .fail
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  r13d, eax
    mov  edi, r13d
    lea  rsi, [rel str_lv_modes_options]
    call wgt_set_text
    mov  edi, r13d
    call wgt_slot_ptr
    mov  dword [rax + WGI_X], 32
    mov  dword [rax + WGI_Y], 100
    mov  dword [rax + WGI_W], 240
    mov  dword [rax + WGI_H], 174
    mov  edi, r13d
    lea  rsi, [rel str_lv_mode]
    lea  rdx, [rel str_lv_tree]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_parents]
    lea  rdx, [rel str_lv_parents_good]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_parents]
    call wgt_listview_get
    mov  rdi, rax
    lea  rsi, [rel str_lv_parents_good]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_expanded]
    lea  rdx, [rel str_lv_three]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    call wgt_listview_visible_mask
    cmp  eax, 0x77                    ; 0,1,2 plus independent roots 4,5,6
    jne  .fail
    mov  edi, r13d
    call wgt_slot_ptr
    mov  r14, [rax + LV_PARENTS]
    mov  r15, [rax + WGI_INTENT_SEQ]
    mov  edi, r13d
    lea  rsi, [rel str_lv_parents]
    lea  rdx, [rel str_lv_parents_cycle]
    call wgt_listview_set_full
    test eax, eax
    jz   .fail
    mov  edi, r13d
    call wgt_slot_ptr
    cmp  r14, [rax + LV_PARENTS]
    jne  .fail
    cmp  r15, [rax + WGI_INTENT_SEQ]
    jne  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_parents]
    lea  rdx, [rel str_lv_parents_deep]
    call wgt_listview_set_full
    test eax, eax
    jz   .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_parents]
    lea  rdx, [rel str_lv_parents_invalid]
    call wgt_listview_set_full
    test eax, eax
    jz   .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_mode]
    lea  rdx, [rel str_lv_radio]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_selection]
    lea  rdx, [rel str_lv_one]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_disabled]
    lea  rdx, [rel str_lv_four]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    call wgt_slot_ptr
    mov  r15, [rax + WGI_INTENT_SEQ]
    mov  edi, r13d
    lea  rsi, [rel str_lv_selection]
    lea  rdx, [rel str_lv_two]
    call wgt_listview_set_full
    test eax, eax
    jz   .fail
    mov  edi, r13d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .fail
    cmp  r15, [rax + WGI_INTENT_SEQ]
    jne  .fail
    mov  edi, r13d
    lea  rsi, [rel str_lv_selection]
    lea  rdx, [rel str_lv_two_selections]
    call wgt_listview_set_full
    test eax, eax
    jz   .fail
    mov  edi, r13d
    mov  esi, 40
    mov  edx, 167                     ; disabled visible row 2
    call wgt_listview_pointer_press
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    mov  esi, 40
    mov  edx, 149                     ; enabled visible row 1
    call wgt_listview_pointer_press
    test eax, eax
    jz   .fail
    mov  edi, r13d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .fail
    cmp  dword [rax + WGI_INTENT], LV_INTENT_POINTER
    jne  .fail
    lea  rdi, [rel str_lv_modes_marker]
    call serial_string
    xor  ebx, ebx
    jmp  .cleanup
.fail:
    mov  ebx, 1
.cleanup:
    mov  [rel wgt_count], r12d
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Boot KAT: real overlay-backed row selection, agent-open no-focus-steal,
; outside-close no-selection/no-event, and invalid overlay refusal.
wgt_listview_dropdown_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel wgt_count]
    mov  r13d, [rel wm_focus]
    ; Keep the additive tree/radio KAT independent from the older dropdown
    ; fixture.  A dropdown-only failure must not hide this mode's verdict.
    call wgt_listview_modes_kat
    test eax, eax
    jnz  .fail
    mov  edi, [rel wgt_overlay_type]
    cmp  edi, -1
    je   .fail
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  r14d, eax
    mov  edi, [rel wgt_listview_type]
    cmp  edi, -1
    je   .fail
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  r15d, eax
    mov  edi, r14d
    call wgt_slot_ptr
    mov  dword [rax + WGI_X], 100
    mov  dword [rax + WGI_Y], 100
    mov  dword [rax + WGI_W], 144
    mov  dword [rax + WGI_H], LV_ROW_H*3
    mov  dword [rax + WGI_LAYER], 1
    mov  edi, r15d
    lea  rsi, [rel str_lv_kat_options]
    call wgt_set_text
    mov  edi, r15d
    call wgt_slot_ptr
    mov  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    mov  byte [rax + LV_OPEN], 1
    mov  ecx, r14d
    inc  ecx
    mov  [rax + LV_OVERLAY], ecx
    mov  dword [rax + WGI_SEL_LO], 0
    mov  dword [rax + WGI_INTENT], 0
    mov  qword [rax + WGI_INTENT_SEQ], 0
    mov  dword [rel wm_pointer_last_btn_inj], 0 ; SEC-winmove (C2): the KAT injects; its own stream
    mov  byte [rel wm_pointer_mode], 0
    mov  edi, 104
    mov  esi, 128
    mov  edx, 1
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    cmp  eax, WM_PTR_INTENT_WIDGET
    jne  .fail
    mov  edi, r15d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .fail
    cmp  byte [rax + LV_OPEN], 0
    jne  .fail
    cmp  dword [rax + WGI_INTENT], LV_INTENT_POINTER
    jne  .fail
    cmp  qword [rax + WGI_INTENT_SEQ], 1
    jne  .fail
    mov  edi, 104
    mov  esi, 128
    xor  edx, edx
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    mov  edi, r15d
    lea  rsi, [rel str_lv_open]
    lea  rdx, [rel str_lv_one]
    call wgt_listview_set_full
    test eax, eax
    jnz  .fail
    cmp  r13d, [rel wm_focus]
    jne  .fail
    xor  edi, edi
    xor  esi, esi
    mov  edx, 1
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    cmp  eax, WM_PTR_INTENT_WIDGET
    jne  .fail
    mov  edi, r15d
    call wgt_slot_ptr
    cmp  byte [rax + LV_OPEN], 0
    jne  .fail
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .fail
    cmp  qword [rax + WGI_INTENT_SEQ], 1
    jne  .fail
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    mov  edi, r15d
    lea  rsi, [rel str_lv_overlay]
    lea  rdx, [rel str_lv_bad_overlay]
    call wgt_listview_set_full
    test eax, eax
    jz   .fail
    lea  rdi, [rel str_lv_marker]
    call serial_string
    xor  ebx, ebx
    jmp  .cleanup
.fail:
    mov  ebx, 1
.cleanup:
    mov  [rel wgt_count], r12d
    mov  [rel wm_focus], r13d
    mov  dword [rel wm_pointer_last_btn_inj], 0 ; SEC-winmove (C2): the KAT injects; its own stream
    mov  byte [rel wm_pointer_mode], 0
    mov  dword [rel wm_pointer_widget_id], -1
    call wmx_draw_all
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_widget_listview_0 0
str_lv_selection: db "selection",0
str_lv_scroll:    db "scroll",0
str_lv_value:     db "value",0
str_lv_mode:      db "mode",0
str_lv_open:      db "open",0
str_lv_overlay:   db "overlay",0
str_lv_parents:   db "parents",0
str_lv_expanded:  db "expanded",0
str_lv_disabled:  db "disabled",0
str_lv_intent:    db "intent",0
str_lv_intent_seq: db "intent_seq",0
str_lv_list:      db "list",0
str_lv_dropdown:  db "dropdown",0
str_lv_tree:      db "tree",0
str_lv_radio:     db "radio",0
str_lv_arrow:     db "v",0
str_lv_tree_closed: db "+  ",0
str_lv_tree_open: db "-  ",0
str_lv_tree_leaf: db "   ",0
str_lv_radio_off: db "( )",0
str_lv_radio_on: db "(*)",0
str_lv_radio_disabled: db "(-)",0
str_lv_one:       db "1",0
str_lv_two:       db "2",0
str_lv_three:     db "3",0
str_lv_four:      db "4",0
str_lv_two_selections: db "1,2",0
str_lv_bad_overlay: db "4095",0
str_lv_kat_options: db "One,Two,Three",0
; Seven options exercise the maximum accepted tree depth while retaining the
; established 31-byte canonical widget-text contract.
str_lv_modes_options: db "R,C,G,L,O,A,B",0
str_lv_parents_good: db "r,0,1,2,r,r,r",0
str_lv_parents_cycle: db "1,0,r,r,r,r,r",0
str_lv_parents_deep: db "r,0,1,2,3,4,r",0
str_lv_parents_invalid: db "r,7,r,r,r,r,r",0
str_lv_marker: db "[PAOS64] GUI kit: dropdown listview overlay-mode KAT PASS [gui.kit.dropdown_mode]",13,10,0
str_lv_modes_marker: db "[PAOS64] GUI kit: listview tree/radio mode KAT PASS [gui.kit.list_modes]",13,10,0
wgt_listview_type: dd -1
align 8
wgt_listview_set_hook: dq 0
wgt_listview_get_hook: dq 0
wgt_listview_pointer_hook: dq 0
wgt_list_num_buf: times 24 db 0
wgt_list_row_buf: times 64 db 0
wgt_list_state_buf: times 64 db 0
%endmacro
WDATA_DEFER WDATA_gui_widget_listview_0
