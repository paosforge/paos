;; MODULE gui/lock_screen_text
%include "core/abi/build_profile.inc"
;; LAYER 6
;; PURPOSE Paint fixed public lock-card records through the trusted catalog.
;; EXPORTS lock_card_owner_disclosure, lock_card_text_draw
;; IMPORTS gui/clock_paint, gui/lock_screen, gui/lock_identity, gui/widget, gui/l10n_paint, gui/res_pack_boot, gui/window, gui/chat_app, core/lib/str, sec/principal, boot/gop
;; CAPS
;; OWNER saga:login_surfaces
;; CONTEXT: bsp_only

; Stock label/button callback: R12 row, RDI already escaped/form-normalized
; native text, R8/R9 position, EBX foreground, ECX background, R11 max cells.
; Both the actual row address and exact native literal must match. A runtime
; value, another widget/window, the internal auth id, layout and secret editor
; retain the stock escaped path. Catalog bytes NEVER enter WGI_VAL.
; Preserves input registers except RAX and the single-line painter's R8.
lock_card_text_draw:
    push rdi
    push rsi
    push rdx
    push r10
    push r11
    push rbx
    push rcx
    push r13
    push r14
    cmp  dword [r12 + WGI_WIN], LOCK_SLOT
    jne  .native
    mov  r13, rdi
    call lock_identity_avatar_draw     ; exact avatar row and current public initial only
    test eax, eax
    jnz  .out
    lea  r14, [rel lock_card_text_records]
.next:
    mov  eax, [r14]
    cmp  eax, -1
    je   .native
    add  eax, [rel lock_widget_first]
    imul rax, rax, WGI_SZ
    lea  rdx, [rel wgt_tbl]
    add  rax, rdx
    cmp  r12, rax
    jne  .advance
    mov  rdi, r13
    lea  rsi, [rel lock_card_text_records]
    add  rsi, [r14 + 8]
    push rcx                           ; strcmp consumes CL
    call strcmp
    pop  rcx
    test eax, eax
    jz   .matched
.advance:
    add  r14, 16
    jmp  .next
.matched:
    ; Repaint the whole mapped label so a shorter translation/status cannot
    ; leave old glyphs, including its second wrapped row. Stock buttons have
    ; already painted their state-dependent fill, border and focus affordance.
    mov  eax, [r14]
    cmp  eax, 7
    je   .paint
    cmp  eax, 9
    je   .paint
    cmp  eax, 13
    je   .paint
    push rbx
    push r10
    push r11
    mov  ebx, ecx
    mov  r10d, [r12 + WGI_W]
    mov  r11d, [r12 + WGI_H]
    call wgt_fill_rect
    pop  r11
    pop  r10
    pop  rbx
.paint:
    mov  edi, [r14 + 4]
    lea  rsi, [rel lock_card_text_records]
    add  rsi, [r14 + 8]
    cmp  dword [r14], 8
    je   .wrap
    cmp  dword [r14], 2
    je   .center
    call l10n_paint
    jmp  .out
.center:
    call l10n_paint_center
    jmp  .out
.wrap:
    mov  r10d, [r12 + WGI_W]
    shr  r10d, 3
    mov  r11d, [r12 + WGI_H]
    shr  r11d, 4
    call l10n_paint_wrap
.out:
    pop  r14
    pop  r13
    pop  rcx
    pop  rbx
    pop  r11
    pop  r10
    pop  rdx
    pop  rsi
    pop  rdi
    ret
.native:
    pop  r14
    pop  r13
    pop  rcx
    pop  rbx
    pop  r11
    pop  r10
    pop  rdx
    pop  rsi
    pop  rdi
    call clock_paint_lock_mark
    jmp  fb_draw_str_n

; Fixed public disclosure; no inline widget buffer can truncate this text.
; A single logical line wraps in the clock band during first-owner setup.
lock_card_owner_disclosure:
    call principal_first_owner_available
    cmp eax, 1
    jne .out
    push rbx
    mov r8d, 12
    mov r9d, 12
    mov r10d, [rel fb_width]
    sub r10d, 24
    mov r11d, 64
    mov ebx, GUI_TOK_CONTROL_BG
    call wgt_fill_rect
    mov r8d, 20
    mov r9d, 20
    mov r10d, [rel fb_width]
    sub r10d, 40
    shr r10d, 3
    mov r11d, 3
    mov ebx, GUI_TOK_CONTROL_TEXT
    mov ecx, GUI_TOK_CONTROL_BG
    lea rsi, [rel prin_stage_disclosure]
    mov edi, L10N_ID_prin_stage_disclosure
    call l10n_paint_wrap
    pop rbx
.out:
    ret

; Fixed English anchors for the form's normalized public declarations.
str_lock_password_display: db "Password",0
str_lock_forgot_display: db "Forgot password?",0
str_lock_back_display: db "Back to sign-in",0
align 8
lock_card_text_records:
%macro LOCK_CARD_TEXT 2
    dd %1, L10N_ID_%2
    dq %2 - lock_card_text_records     ; image-relative, never a baked RVA pointer
%endmacro
    LOCK_CARD_TEXT 2, str_lock_owner_display
    LOCK_CARD_TEXT 2, str_lock_card_setup
    LOCK_CARD_TEXT 3, str_lock_password_display
    LOCK_CARD_TEXT 7, str_lock_signin
    LOCK_CARD_TEXT 7, str_lock_stage
    LOCK_CARD_TEXT 8, str_lock_prompt
%if !PAOS_PUBLIC_BUILD
    LOCK_CARD_TEXT 8, str_lock_prompt_files
%endif
    LOCK_CARD_TEXT 8, str_lock_retry
    LOCK_CARD_TEXT 8, str_lock_setup
    LOCK_CARD_TEXT 8, str_lock_change_not_applied
    LOCK_CARD_TEXT 8, str_lock_setup_not_applied
    LOCK_CARD_TEXT 8, str_lock_card_recovery
    LOCK_CARD_TEXT 9, str_lock_forgot_display
    LOCK_CARD_TEXT 13, str_lock_back_display
    dd -1, 0
    dq 0
%unmacro LOCK_CARD_TEXT 2

%include "gui/lock_identity.asm"
