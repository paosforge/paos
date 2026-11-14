;; MODULE gui/widget_containers
;; LAYER 6
;; EXPORTS wgt_f2_register_types, wgt_containers_register, wgt_grid_cell
;; IMPORTS gui/widget, gui/widget_listview, gui/widget_progress, gui/widget_scalar_inputs, gui/form_loader, gui/window, boot/serial
;; CAPS
;; OWNER saga:gui_foundation_ladder

; Containers paint only their token-backed surface. The form loader owns the
; deterministic order layout, so row/col/status contain no private geometry.
; GK1-3 shares bounded grid geometry with the form planner below.
wgt_container_draw:
    push rbx
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_WINDOW_BODY
    call fb_fill_rect
    pop  rbx
    ret

wgt_status_draw:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_STATUS_BG
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    lea  rdi, [rbx + WGI_VAL]
    mov  r8d, [rbx + WGI_X]
    add  r8d, 5
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 4
    mov  r11d, [rbx + WGI_W]            ; RCQ-16 S2: the bound before EBX holds the colour
    sub  r11d, 10
    shr  r11d, 3
    mov  ebx, GUI_TOK_TITLE_TEXT
    mov  ecx, GUI_TOK_STATUS_BG
    call fb_draw_str_n
    pop  r12
    pop  rbx
    ret

wgt_f2_register_types:
    lea  rdi, [rel str_wt_listview]
    lea  rsi, [rel wgt_listview_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_listview_set_full]
    lea  r8,  [rel wgt_listview_get]
    mov  r9, (220 << 32) | 420
    call wgt_type_register
    cmp  eax, -1
    je   .fail
    mov  [rel wgt_listview_type], eax
    lea  rdi, [rel str_wt_progress]
    lea  rsi, [rel wgt_progress_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_progress_set]
    lea  r8,  [rel wgt_progress_get]
    ; WIDGETNEW uses the stock 300x200 WINNEW host unless a form overrides
    ; geometry.  Keep the default inside that host's 16px inset so the shared
    ; clip gate reaches the progress vtable instead of correctly refusing an
    ; off-window 320px bar. Declarative forms still replace WGI_W from data.
    mov  r9, (22 << 32) | 260
    call wgt_type_register
    lea  rdi, [rel str_wt_row]
    lea  rsi, [rel wgt_container_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8,  [rel wgt_label_get]
    mov  r9, (64 << 32) | 420
    call wgt_type_register
    lea  rdi, [rel str_wt_col]
    lea  rsi, [rel wgt_container_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8,  [rel wgt_label_get]
    mov  r9, (240 << 32) | 420
    call wgt_type_register
    lea  rdi, [rel str_wt_status]
    lea  rsi, [rel wgt_status_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8,  [rel wgt_label_get]
    mov  r9, (28 << 32) | 420
    call wgt_type_register
    ; GK1-1 appends four scalar controls after the original eight stock rows.
    call wgt_scalar_register_types
    test eax, eax
    jnz  .fail
    cmp  dword [rel wgt_type_count], 12
    jne  .fail
    lea  rdi, [rel str_wgt_f2_marker]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_wgt_f2_fail]
    call serial_string
    ret

str_wt_listview: db "listview",0
str_wt_progress: db "progress",0
str_wt_row:      db "row",0
str_wt_col:      db "col",0
str_wt_status:   db "status",0
str_wgt_f2_marker: db "[PAOS64] M6 widget: listview/progress/row/col/status registered through the vtable (8 types, no core edit) [ui.widget.kit.f2]",13,10,0
str_wgt_f2_fail: db "[PAOS64] M6 widget: F2 kit registration FAILED",13,10,0

; Append after the previously registered image/secret types; never renumber them.
wgt_containers_register:
    lea  rdi, [rel str_wt_grid]
    lea  rsi, [rel wgt_container_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8, [rel wgt_label_get]
    mov  r9, (120 << 32) | 240
    call wgt_type_register
    mov  [rel wgt_grid_type], eax
    lea  rdi, [rel str_wt_overlay]
    lea  rsi, [rel wgt_overlay_draw]
    lea  rdx, [rel wgt_overlay_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8, [rel wgt_label_get]
    mov  r9, (120 << 32) | 240
    call wgt_type_register
    mov  [rel wgt_overlay_type], eax
    ret

; An overlay is a transparent declaration/envelope, never a private painter.
wgt_overlay_draw:
    call wgt_listview_overlay_draw
    xor  eax, eax
    ret

wgt_overlay_hittest:
    xor  eax, eax
    ret

; EDI=width, ESI=height, EDX=rows, ECX=cols, R8D=ordinal.
; CF=0: R8D/R9D=cell origin, R10D/R11D=cell extent, all relative.
; Used by the form planner. Equal cells, stock FORM_SPACING, row-major,
; 1..8 rows/columns, remainder kept as trailing padding; no partial writes.
wgt_grid_cell:
    test edx, edx
    jz   .bad
    cmp  edx, 8
    ja   .bad
    test ecx, ecx
    jz   .bad
    cmp  ecx, 8
    ja   .bad
    mov  eax, edx
    imul eax, ecx
    cmp  r8d, eax
    jae  .bad
    push rbx
    push r12
    mov  ebx, edx
    mov  r12d, r8d
    lea  eax, [rcx + 1]
    imul eax, FORM_SPACING
    sub  edi, eax
    jbe  .pop_bad
    mov  eax, edi
    xor  edx, edx
    div  ecx
    test eax, eax
    jz   .pop_bad
    mov  r10d, eax
    lea  eax, [rbx + 1]
    imul eax, FORM_SPACING
    sub  esi, eax
    jbe  .pop_bad
    mov  eax, esi
    xor  edx, edx
    div  ebx
    test eax, eax
    jz   .pop_bad
    mov  r11d, eax
    mov  eax, r12d
    xor  edx, edx
    div  ecx
    lea  r8d, [r10d + FORM_SPACING]
    imul r8d, edx
    add  r8d, FORM_SPACING
    lea  r9d, [r11d + FORM_SPACING]
    imul r9d, eax
    add  r9d, FORM_SPACING
    pop  r12
    pop  rbx
    clc
    ret
.pop_bad:
    pop  r12
    pop  rbx
.bad:
    stc
    ret

wgt_grid_type: dd -1
wgt_overlay_type: dd -1
str_wt_grid: db "grid",0
str_wt_overlay: db "overlay",0
