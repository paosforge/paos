;; MODULE gui/widget_scalar_inputs
;; LAYER 6
;; EXPORTS wgt_scalar_register_types, wgt_scalar_key, wgt_scalar_pointer_press, wgt_scalar_pointer_drag, wgt_scalar_pointer_release, wgt_scalar_kat
;; IMPORTS gui/widget, gui/window, gui/form_loader, gui/wm_pointer, svc/command, gui/window_mgmt, gui/chat_app
;; CAPS
;; OWNER saga:gui_kit_wave2

WGT_INTENT_NONE          equ 0
WGT_INTENT_POINTER_PRESS equ 1
WGT_INTENT_POINTER_DRAG  equ 2
WGT_INTENT_POINTER_UP    equ 3
WGT_INTENT_VERB_SET      equ 4
WGT_INTENT_KEY           equ 5   ; RCQ-16 S4: a focused scalar's keyboard operation (wgt_scalar_key)

; Clamp and step-align RAX against RBX's shared scalar model, store the exact
; live value, and publish the slot-8 event in EDX.  All scalar mutation paths
; (pointer and WIDGETSET) converge here.
wgt_scalar_store_value:
    mov  r8d, edx
    cmp  rax, [rbx + WGI_MINVAL]
    jae  .not_low
    mov  rax, [rbx + WGI_MINVAL]
.not_low:
    cmp  rax, [rbx + WGI_MAXVAL]
    jbe  .bounded
    mov  rax, [rbx + WGI_MAXVAL]
.bounded:
    mov  rcx, [rbx + WGI_STEP]
    cmp  rcx, 1
    jbe  .store
    sub  rax, [rbx + WGI_MINVAL]
    xor  edx, edx
    div  rcx
    mul  rcx
    add  rax, [rbx + WGI_MINVAL]
.store:
    mov  [rbx + WGI_NUM], rax
    mov  [rbx + WGI_INTENT], r8d
    inc  qword [rbx + WGI_INTENT_SEQ]
    ret

; Strict unsigned scalar parser. Values are intentionally bounded to signed
; 31-bit so pointer interpolation cannot overflow its multiply.
wgt_scalar_parse_value:
    call wgt_parse_dec
    test rcx, rcx
    jz   .bad
    cmp  byte [rdx], 0
    jne  .bad
    cmp  rax, 0x7fffffff
    ja   .bad
    clc
    ret
.bad:
    stc
    ret

; Common WIDGETSET implementation for toggle/slider/numeric. Toggle exposes
; only value; slider/numeric expose the complete value/min/max/step model.
wgt_scalar_set:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  r14, rdx
    lea  rdi, [rel str_wf_disabled]     ; RCQ-16 S4: the kit's shared disabled field
    mov  rsi, r13
    call strcmp
    test rax, rax
    jnz  .not_disabled
    mov  edi, r12d
    mov  rsi, r14
    call wgt_set_disabled
    jmp  .out
.not_disabled:
    xor  r15d, r15d                    ; 0=value 1=min 2=max 3=step
    lea  rdi, [rel str_scalar_value]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .field_ok
    inc  r15d
    lea  rdi, [rel str_scalar_min]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .field_ok
    inc  r15d
    lea  rdi, [rel str_scalar_max]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .field_ok
    inc  r15d
    lea  rdi, [rel str_scalar_step]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jnz  .bad
.field_ok:
    mov  rdi, r14
    call wgt_scalar_parse_value
    jc   .bad
    mov  r14, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    cmp  eax, [rel wgt_scalar_toggle_type]
    jne  .not_toggle
    test r15d, r15d
    jnz  .bad
    test r14, r14
    setnz al
    movzx r14, al
.not_toggle:
    test r15d, r15d
    jz   .value
    cmp  r15d, 1
    je   .minimum
    cmp  r15d, 2
    je   .maximum
    test r14, r14
    jz   .bad
    mov  [rbx + WGI_STEP], r14
    jmp  .normalize
.minimum:
    cmp  r14, [rbx + WGI_MAXVAL]
    ja   .bad
    mov  [rbx + WGI_MINVAL], r14
    jmp  .normalize
.maximum:
    cmp  r14, [rbx + WGI_MINVAL]
    jb   .bad
    mov  [rbx + WGI_MAXVAL], r14
.normalize:
    mov  rax, [rbx + WGI_NUM]
    mov  edx, WGT_INTENT_VERB_SET
    call wgt_scalar_store_value
    jmp  .redraw
.value:
    mov  rax, r14
    mov  edx, WGT_INTENT_VERB_SET
    call wgt_scalar_store_value
.redraw:
    mov  edi, r12d
    call wgt_draw_id
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_scalar_get:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    lea  rdi, [rel str_scalar_value]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .value
    lea  rdi, [rel str_scalar_min]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .minimum
    lea  rdi, [rel str_scalar_max]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .maximum
    lea  rdi, [rel str_wf_disabled]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .disabled
    lea  rdi, [rel str_scalar_step]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jnz  .bad
    mov  rdi, [rbx + WGI_STEP]
    jmp  .format
.minimum:
    mov  rdi, [rbx + WGI_MINVAL]
    jmp  .format
.maximum:
    mov  rdi, [rbx + WGI_MAXVAL]
    jmp  .format
.disabled:
    mov  edi, r12d
    call wgt_get_disabled
    jmp  .out
.value:
    mov  rdi, [rbx + WGI_NUM]
.format:
    lea  rsi, [rel wgt_scalar_num_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel wgt_scalar_num_buf]
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_scalar_null_set:
    mov  eax, 1
    ret
wgt_scalar_null_get:
wgt_scalar_nohit:
    xor  eax, eax
    ret

; Small token-backed painters. They intentionally share only the established
; fill/text primitives; no scalar widget receives a private pixel path.
wgt_toggle_draw:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    call wgt_state_of                   ; RCQ-16 S4: hover / disabled / keyboard focus
    mov  r13d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, 36
    mov  r11d, [rbx + WGI_H]
    mov  eax, GUI_TOK_DISABLED_BORDER
    test r13d, WGT_ST_DISABLED
    jnz  .track
    cmp  qword [rbx + WGI_NUM], 0
    jne  .track_on
    mov  eax, GUI_TOK_FIELD_BORDER      ; RCQ-16: off track, 3.67:1 on the body
    test r13d, WGT_ST_HOT
    jz   .track
    mov  eax, GUI_TOK_TRACK_HOVER       ; RCQ-16 S4: the off track under the pointer
    jmp  .track
.track_on:
    mov  eax, GUI_TOK_SELECTION         ; on: the accent track, 4.32:1
    test r13d, WGT_ST_HOT
    jz   .track
    mov  eax, GUI_TOK_SELECTION_HOVER   ; RCQ-16 S4: the on track under the pointer
.track:
    mov  ebx, eax
    call wgt_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    add  r8d, 3
    cmp  qword [rbx + WGI_NUM], 0
    je   .knob
    add  r8d, 18
.knob:
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 3
    mov  r10d, 15
    mov  r11d, [rbx + WGI_H]
    sub  r11d, 6
    mov  ebx, GUI_TOK_TOGGLE_KNOB       ; RCQ-16: 5.3:1 / 4.53:1 on the off / on track
    test r13d, WGT_ST_DISABLED
    jz   .knob_colour
    mov  ebx, GUI_TOK_DISABLED_TEXT
.knob_colour:
    call wgt_fill_rect
    mov  edi, r12d
    call wgt_scalar_draw_label
    mov  edi, r12d
    call wgt_focus_ring_draw
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_slider_draw:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    call wgt_state_of                   ; RCQ-16 S4: hover / disabled / keyboard focus
    mov  r14d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  eax, [rbx + WGI_H]
    shr  eax, 1
    add  r9d, eax
    mov  r10d, [rbx + WGI_W]
    mov  r11d, 3
    mov  ebx, GUI_TOK_FIELD_BORDER      ; RCQ-16: the slider track, 3.67:1 on the body
    test r14d, WGT_ST_HOT
    jz   .track_disabled
    mov  ebx, GUI_TOK_TRACK_HOVER       ; RCQ-16 S4: the track under the pointer
.track_disabled:
    test r14d, WGT_ST_DISABLED
    jz   .track
    mov  ebx, GUI_TOK_DISABLED_BORDER
.track:
    call wgt_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  rcx, [rbx + WGI_MAXVAL]
    sub  rcx, [rbx + WGI_MINVAL]
    jz   .handle
    mov  rax, [rbx + WGI_NUM]
    sub  rax, [rbx + WGI_MINVAL]
    mov  edx, [rbx + WGI_W]
    dec  edx
    imul rax, rdx
    xor  edx, edx
    div  rcx
    mov  r13d, eax
    jmp  .paint_handle
.handle:
    xor  r13d, r13d
.paint_handle:
    mov  eax, [rbx + WGI_W]
    sub  eax, 5
    jns  .handle_max_ok
    xor  eax, eax
.handle_max_ok:
    cmp  r13d, eax
    jbe  .handle_bounded
    mov  r13d, eax
.handle_bounded:
    mov  r8d, [rbx + WGI_X]
    add  r8d, r13d
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, 5
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_SELECTION
    test r14d, WGT_ST_HOT
    jz   .handle_disabled
    mov  ebx, GUI_TOK_SELECTION_HOVER   ; RCQ-16 S4: the handle under the pointer
.handle_disabled:
    test r14d, WGT_ST_DISABLED
    jz   .handle_paint
    mov  ebx, GUI_TOK_DISABLED_TEXT
.handle_paint:
    call wgt_fill_rect
    mov  edi, r12d
    call wgt_focus_ring_draw
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_numeric_draw:
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
    call wgt_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  rdi, [rbx + WGI_NUM]
    lea  rsi, [rel wgt_scalar_num_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rdi, [rel wgt_scalar_num_buf]
    mov  r8d, [rbx + WGI_X]
    add  r8d, 8
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 5
    mov  r11d, [rbx + WGI_W]            ; RCQ-16 S2: the bound before EBX holds the colour
    sub  r11d, 16
    shr  r11d, 3
    mov  eax, GUI_TOK_TITLE_TEXT
    test dword [rbx + WGI_EDIT], WGT_EDIT_DISABLED
    jz   .value_colour
    mov  eax, GUI_TOK_DISABLED_TEXT     ; RCQ-16 S4: an inactive value
.value_colour:
    mov  ebx, eax
    mov  ecx, GUI_TOK_OUTLINE
    call wgt_draw_text
    mov  edi, r12d
    call wgt_scalar_draw_label
    mov  edi, r12d
    call wgt_focus_ring_draw
    pop  r12
    pop  rbx
    ret

wgt_separator_draw:
    push rbx
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    mov  ebx, GUI_TOK_OUTLINE
    call wgt_fill_rect
    pop  rbx
    ret

wgt_scalar_draw_label:
    push rbx
    call wgt_slot_ptr
    mov  rbx, rax
    mov  rdi, [rbx + WGI_LABEL]
    mov  r8d, [rbx + WGI_X]
    add  r8d, 44
    mov  r9d, [rbx + WGI_Y]
    add  r9d, 4
    mov  r11d, [rbx + WGI_W]            ; RCQ-16 S2: the bound before EBX holds the colour
    sub  r11d, 48
    shr  r11d, 3
    mov  eax, GUI_TOK_LABEL_TEXT
    test dword [rbx + WGI_EDIT], WGT_EDIT_DISABLED
    jz   .label_colour
    mov  eax, GUI_TOK_DISABLED_TEXT     ; RCQ-16 S4: an inactive control's label
.label_colour:
    mov  ebx, eax
    mov  ecx, GUI_TOK_WINDOW_BODY
    call wgt_draw_text
    pop  rbx
    ret

; Slider pointer mapping holds the captured widget id, not the hover target.
wgt_scalar_slider_at_x:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, esi
    sub  eax, [rbx + WGI_X]
    jns  .nonnegative
    xor  eax, eax
.nonnegative:
    mov  ecx, [rbx + WGI_W]
    dec  ecx
    jg   .width_ok
    mov  ecx, 1
.width_ok:
    cmp  eax, ecx
    jbe  .x_ok
    mov  eax, ecx
.x_ok:
    mov  rdx, [rbx + WGI_MAXVAL]
    sub  rdx, [rbx + WGI_MINVAL]
    imul rax, rdx
    xor  edx, edx
    div  rcx
    add  rax, [rbx + WGI_MINVAL]
    mov  edx, WGT_INTENT_POINTER_DRAG
    call wgt_scalar_store_value
    mov  edi, r12d
    call wgt_draw_id
    pop  r12
    pop  rbx
    ret

wgt_scalar_pointer_press:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call wgt_slot_ptr
    mov  rbx, rax
    xor  eax, eax
    test dword [rbx + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .out                           ; RCQ-16 S4: a disabled scalar takes no press (not captured)
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    cmp  eax, [rel wgt_scalar_toggle_type]
    je   .toggle
    cmp  eax, [rel wgt_scalar_slider_type]
    je   .slider
    cmp  eax, [rel wgt_scalar_numeric_type]
    je   .numeric
    xor  eax, eax
    jmp  .out
.toggle:
    mov  rax, [rbx + WGI_NUM]
    xor  eax, 1
    mov  edx, WGT_INTENT_POINTER_PRESS
    call wgt_scalar_store_value
    jmp  .draw
.slider:
    mov  edi, r12d
    mov  esi, r13d
    call wgt_scalar_slider_at_x
    mov  edi, r12d
    call wgt_slot_ptr
    mov  dword [rax + WGI_INTENT], WGT_INTENT_POINTER_PRESS
    jmp  .captured
.numeric:
    mov  eax, [rbx + WGI_X]
    mov  ecx, [rbx + WGI_W]
    shr  ecx, 1
    add  eax, ecx
    mov  ecx, eax
    mov  rax, [rbx + WGI_NUM]
    cmp  r13d, ecx
    jae  .increment
    mov  rcx, [rbx + WGI_STEP]
    mov  rdx, rax
    sub  rdx, [rbx + WGI_MINVAL]
    cmp  rdx, rcx
    jb   .at_min
    sub  rax, rcx
    jmp  .numeric_store
.at_min:
    mov  rax, [rbx + WGI_MINVAL]
    jmp  .numeric_store
.increment:
    add  rax, [rbx + WGI_STEP]
    jc   .at_max
    jmp  .numeric_store
.at_max:
    mov  rax, [rbx + WGI_MAXVAL]
.numeric_store:
    mov  edx, WGT_INTENT_POINTER_PRESS
    call wgt_scalar_store_value
.draw:
    mov  edi, r12d
    call wgt_draw_id
.captured:
    mov  [rel wgt_scalar_capture_id], r12d
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_scalar_key(EDI = id, EAX = GUI key) -> EAX 1 handled, 0 not this kind's
;   key. RCQ-16 S4: the keyboard operation of a focused scalar, through the
;   same clamped store as the pointer (intent WGT_INTENT_KEY): toggle Space or
;   Enter flips; slider and numeric Left/Down step down, Right/Up step up,
;   Home / End go to min / max. wgt_textfield_key refused a disabled control.
;   clobbers: caller-saved.
wgt_scalar_key:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, eax
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    cmp  eax, [rel wgt_scalar_toggle_type]
    je   .toggle
    cmp  eax, [rel wgt_scalar_slider_type]
    je   .ranged
    cmp  eax, [rel wgt_scalar_numeric_type]
    je   .ranged
    jmp  .no
.toggle:
    cmp  r13d, ' '
    je   .flip
    cmp  r13d, GUI_KEY_ENTER
    jne  .no
.flip:
    mov  rax, [rbx + WGI_NUM]
    xor  eax, 1
    jmp  .store
.ranged:
    mov  rax, [rbx + WGI_NUM]
    cmp  r13d, GUI_KEY_HOME
    je   .min
    cmp  r13d, GUI_KEY_END
    je   .max
    cmp  r13d, GUI_KEY_RIGHT
    je   .up
    cmp  r13d, GUI_KEY_UP
    je   .up
    cmp  r13d, GUI_KEY_LEFT
    je   .down
    cmp  r13d, GUI_KEY_DOWN
    jne  .no
.down:
    mov  rcx, [rbx + WGI_STEP]
    mov  rdx, rax
    sub  rdx, [rbx + WGI_MINVAL]
    cmp  rdx, rcx
    jb   .min
    sub  rax, rcx
    jmp  .store
.up:
    add  rax, [rbx + WGI_STEP]
    jnc  .store
.max:
    mov  rax, [rbx + WGI_MAXVAL]
    jmp  .store
.min:
    mov  rax, [rbx + WGI_MINVAL]
.store:
    mov  edx, WGT_INTENT_KEY
    call wgt_scalar_store_value
    mov  edi, r12d
    call wgt_draw_id
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; wgt_scalar_pointer_drag(EDI = captured id, ESI = x, EDX = y) -> EAX = 1, or 0
;   when the control was disabled mid-drag: the capture ends and nothing moves
;   (srcreview S4 F2; wm_pointer then leaves its capture mode).
wgt_scalar_pointer_drag:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    test dword [rbx + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .dropped
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    cmp  eax, [rel wgt_scalar_slider_type]
    jne  .captured
    mov  edi, r12d
    call wgt_scalar_slider_at_x
    jmp  .yes
.captured:
    mov  dword [rbx + WGI_INTENT], WGT_INTENT_POINTER_DRAG
    inc  qword [rbx + WGI_INTENT_SEQ]
.yes:
    mov  eax, 1
    pop  r12
    pop  rbx
    ret
.dropped:
    mov  dword [rel wgt_scalar_capture_id], -1
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

wgt_scalar_pointer_release:
    call wgt_slot_ptr
    mov  dword [rax + WGI_INTENT], WGT_INTENT_POINTER_UP
    inc  qword [rax + WGI_INTENT_SEQ]
    mov  dword [rel wgt_scalar_capture_id], -1
    mov  eax, 1
    ret

; The marker is earned by a real press/release through wm_pointer_event over a
; newest/topmost temporary toggle. wm_pointer_init invokes this after form
; selftests, and the fixture is removed before the shipped demo is composed.
wgt_scalar_kat:
    push rbx
    xor  ebx, ebx
    mov  edi, [rel wgt_scalar_toggle_type]
    cmp  edi, -1
    je   .fail
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  [rel wgt_scalar_kat_id], eax
    xor  edi, edi
    call wmx_raise_slot
    mov  edi, [rel wgt_scalar_kat_id]
    call wgt_slot_ptr
    mov  rbx, rax
    lea  rax, [rel wm_x]
    mov  eax, [rax]
    add  eax, WGT_PAD_X
    mov  [rbx + WGI_X], eax
    lea  rax, [rel wm_y]
    mov  eax, [rax]
    add  eax, WGT_PAD_Y
    mov  [rbx + WGI_Y], eax
    mov  dword [rbx + WGI_INTENT], WGT_INTENT_NONE
    mov  qword [rbx + WGI_INTENT_SEQ], 0
    mov  qword [rbx + WGI_NUM], 0
    mov  dword [rel wm_pointer_last_btn_inj], 0 ; SEC-winmove (C2): its own stream; the human's is never touched
    mov  byte [rel wm_pointer_mode], 0
    mov  edi, [rbx + WGI_X]
    add  edi, 4
    mov  esi, [rbx + WGI_Y]
    add  esi, 4
    mov  edx, 1
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    cmp  eax, WM_PTR_INTENT_WIDGET
    jne  .fail
    cmp  qword [rbx + WGI_NUM], 1
    jne  .fail
    cmp  dword [rbx + WGI_INTENT], WGT_INTENT_POINTER_PRESS
    jne  .fail
    mov  edi, [rbx + WGI_X]
    add  edi, 4
    mov  esi, [rbx + WGI_Y]
    add  esi, 4
    xor  edx, edx
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    cmp  eax, WM_PTR_INTENT_WIDGET
    jne  .fail
    mov  qword [rbx + WGI_NUM], 0
    mov  dword [rbx + WGI_INTENT], WGT_INTENT_NONE
    mov  qword [rbx + WGI_INTENT_SEQ], 0
    lea  rdi, [rel str_scalar_marker]
    call serial_string
    xor  eax, eax
    jmp  .cleanup
.fail:
    lea  rdi, [rel str_scalar_fail]
    call serial_string
    mov  eax, 1
.cleanup:
    push rax
    test rbx, rbx
    jz   .pointer_clean
    mov  dword [rbx + WGI_TYPE], 0
    mov  dword [rbx + WGI_FLAGS], 0
    dec  dword [rel wgt_count]
.pointer_clean:
    mov  dword [rel wgt_scalar_kat_id], -1
    mov  dword [rel wgt_scalar_capture_id], -1
    mov  dword [rel wm_pointer_widget_id], -1
    mov  dword [rel wm_pointer_last_btn_inj], 0 ; SEC-winmove (C2): its own stream; the human's is never touched
    mov  byte [rel wm_pointer_mode], 0
    pop  rax
    pop  rbx
    ret

; Probe-only negative fixture: locate sysprops, choose a guaranteed empty body
; point, traverse wm_pointer_event, and restore the pointer machine afterward.
cmd_verb_ptrinj:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rsi, [rdi + REQ_ARG]
    call wgt_arg_copy
    lea  rdi, [rel wgt_parse_buf]
    call wgt_tok_split
    mov  r12, rax
    lea  rsi, [rel str_ptr_body_empty]
    lea  rdi, [rel wgt_parse_buf]
    call strcmp
    test rax, rax
    jnz  .bad_arg
    mov  ebx, [rel form_active_slot + 3*4]
    cmp  ebx, WM_MAX
    jae  .no_form
    mov  eax, [rel wm_pointer_last_btn_inj]
    mov  [rel ptr_saved_btn], eax
    movzx eax, byte [rel wm_pointer_mode]
    mov  [rel ptr_saved_mode], al
    movzx eax, byte [rel wm_pointer_gesture_origin]
    mov  [rel ptr_saved_gorigin], al    ; a held HUMAN gesture comes back as the human's
    mov  eax, [rel wm_pointer_widget_id]
    mov  [rel ptr_saved_widget], eax
    mov  eax, [rel wm_focus]
    mov  [rel ptr_saved_focus], eax
    mov  dword [rel wm_pointer_last_btn_inj], 0 ; SEC-winmove (C2): its own stream; the human's is never touched
    mov  byte [rel wm_pointer_mode], 0
    mov  edi, ebx
    lea  rax, [rel wm_x]
    mov  edi, [rax + rdi*4]
    lea  rax, [rel wm_w]
    add  edi, [rax + rbx*4]
    sub  edi, 12
    lea  rax, [rel wm_y]
    mov  esi, [rax + rbx*4]
    lea  rax, [rel wm_h]
    add  esi, [rax + rbx*4]
    sub  esi, 12
    mov  [rel ptr_saved_x], edi
    mov  [rel ptr_saved_y], esi
    mov  edx, 1
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    mov  [rel ptr_saved_intent], eax     ; 2026-10-01: in memory, not RBX (painters clobber it)
    mov  edi, [rel ptr_saved_x]
    mov  esi, [rel ptr_saved_y]
    xor  edx, edx
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    mov  eax, [rel ptr_saved_btn]
    mov  [rel wm_pointer_last_btn_inj], eax
    movzx eax, byte [rel ptr_saved_mode]
    mov  [rel wm_pointer_mode], al
    movzx eax, byte [rel ptr_saved_gorigin]
    mov  [rel wm_pointer_gesture_origin], al
    mov  eax, [rel ptr_saved_widget]
    mov  [rel wm_pointer_widget_id], eax
    ; 2026-09-08 click-to-raise: the press may have raised the form window; put the
    ; previous focus back so the fixture leaves the desktop exactly as it found it.
    mov  eax, [rel ptr_saved_focus]
    cmp  eax, [rel wm_focus]
    je   .focus_kept
    cmp  eax, WM_MAX
    jae  .focus_kept
    mov  edi, eax
    call wmx_raise_slot
.focus_kept:
    call wgt_out_reset
    mov  ebx, [rel ptr_saved_intent]
    lea  rdi, [rel str_ptr_empty_ok]
    cmp  ebx, WM_PTR_INTENT_NONE
    je   .emit
    lea  rdi, [rel str_ptr_empty_raised]
    cmp  ebx, WM_PTR_INTENT_RAISE
    je   .emit
    lea  rdi, [rel str_ptr_empty_hit]
.emit:
    call wgt_out_str
    mov  rdi, r12
    call wgt_out_str
    jmp  .stage
.bad_arg:
    call wgt_out_reset
    lea  rdi, [rel str_ptr_bad_arg]
    call wgt_out_str
    jmp  .stage
.no_form:
    call wgt_out_reset
    lea  rdi, [rel str_ptr_no_form]
    call wgt_out_str
.stage:
    mov  byte [rel wgt_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    ret

; Contract 3367 registration is called after the existing eight stock types.
wgt_scalar_register_types:
    lea  rdi, [rel str_wt_toggle]
    lea  rsi, [rel wgt_toggle_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_scalar_set]
    lea  r8,  [rel wgt_scalar_get]
    mov  r9, (24 << 32) | 180
    call wgt_type_register
    cmp  eax, -1
    je   .fail
    mov  [rel wgt_scalar_toggle_type], eax
    lea  rdi, [rel str_wt_slider]
    lea  rsi, [rel wgt_slider_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_scalar_set]
    lea  r8,  [rel wgt_scalar_get]
    mov  r9, (24 << 32) | 452
    call wgt_type_register
    cmp  eax, -1
    je   .fail
    mov  [rel wgt_scalar_slider_type], eax
    lea  rdi, [rel str_wt_numeric]
    lea  rsi, [rel wgt_numeric_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_scalar_set]
    lea  r8,  [rel wgt_scalar_get]
    mov  r9, (26 << 32) | 180
    call wgt_type_register
    cmp  eax, -1
    je   .fail
    mov  [rel wgt_scalar_numeric_type], eax
    lea  rdi, [rel str_wt_separator]
    lea  rsi, [rel wgt_separator_draw]
    lea  rdx, [rel wgt_scalar_nohit]
    lea  rcx, [rel wgt_scalar_null_set]
    lea  r8,  [rel wgt_scalar_null_get]
    mov  r9, (2 << 32) | 452
    call wgt_type_register
    cmp  eax, -1
    je   .fail
    mov  [rel wgt_scalar_separator_type], eax
    lea  rdi, [rel str_verb_ptrinj]
    lea  rsi, [rel cmd_verb_ptrinj]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    cmp  eax, -1
    je   .fail
    xor  eax, eax
    ret
.fail:
    mov  dword [rel wgt_scalar_kat_id], -1
    mov  eax, 1
    ret

align 8
wgt_scalar_num_buf: times 24 db 0
wgt_scalar_toggle_type: dd -1
wgt_scalar_slider_type: dd -1
wgt_scalar_numeric_type: dd -1
wgt_scalar_separator_type: dd -1
wgt_scalar_capture_id: dd -1
wgt_scalar_kat_id: dd -1
ptr_saved_btn: dd 0
ptr_saved_widget: dd -1
ptr_saved_focus: dd -1
ptr_saved_intent: dd 0              ; the press's routing intent across the focus restore
ptr_saved_x: dd 0
ptr_saved_y: dd 0
ptr_saved_mode: db 0
ptr_saved_gorigin: db 0                 ; SEC-winmove (C2): wm_pointer_gesture_origin across the probe

str_wt_toggle: db "toggle",0
str_wt_slider: db "slider",0
str_wt_numeric: db "numeric",0
str_wt_separator: db "separator",0
str_scalar_value: db "value",0
str_scalar_min: db "min",0
str_scalar_max: db "max",0
str_scalar_step: db "step",0
str_verb_ptrinj: db "PTRINJ",0
str_ptr_body_empty: db "body_empty",0
str_ptr_empty_ok: db " PTRINJ=ERR_empty_body hit=0 ",0
str_ptr_empty_hit: db " PTRINJ=ERR_body_dispatched hit=1 ",0
str_ptr_empty_raised: db " PTRINJ=ERR_empty_body_raised hit=0 ",0
str_ptr_bad_arg: db " PTRINJ=ERR_bad_fixture",0
str_ptr_no_form: db " PTRINJ=ERR_sysprops_not_loaded",0
str_scalar_marker: db "[PAOS64] GUI kit: pointer body dispatch plus toggle/slider/numeric/separator KAT PASS [gui.kit.scalar_inputs]",13,10,0
str_scalar_fail: db "[PAOS64] GUI kit: pointer body dispatch plus scalar inputs KAT FAILED",13,10,0
