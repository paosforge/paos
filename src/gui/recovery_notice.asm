;; MODULE gui/recovery_notice
;; LAYER 6
;; PURPOSE Present the accepted public fallback explanation in an ordinary window.
;; EXPORTS recovery_notice_init
;; IMPORTS svc/command_recovery_state, gui/form_loader, gui/widget, gui/window, gui/chat_app, gui/window_mgmt, gui/l10n_paint, sec/session, core/lib/str
;; OWNER saga:boot_recovery
;; CONTEXT: bsp_only

; Called once after the unlocked workspace is created/restored. This consumer
; has presentation authority only: closing it cannot acknowledge a failure,
; change a boot selection, publish health, or initiate recovery.
recovery_notice_init:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    cmp  byte [rel rn_attempted], 0
    jne  .out
    mov  byte [rel rn_attempted], 1
    call recovery_notice_get
    test eax, eax
    jz   .out
    cmp  eax, 7
    ja   .out
    dec  eax
    lea  rcx, [rel rn_message_ids]
    mov  eax, [rcx + rax*4]
    mov  [rel rn_message_id], eax
    mov  [rel rn_english], rdx
    mov  edi, FORM_RECOVERY_INDEX
    xor  esi, esi
    xor  edx, edx                    ; no focus transfer
    call form_load_index
    test eax, eax
    jnz  .out                       ; bounded attempt, never a retry loop
    cmp  ecx, WM_MAX
    jae  .out
    mov  [rel rn_slot], ecx
    lea  rdx, [rel wm_gen]
    mov  eax, [rdx + rcx*4]
    mov  [rel rn_generation], eax
    lea  rdx, [rel wgt_tbl]
    mov  eax, [rel wgt_count]
.find:
    test eax, eax
    jz   .out
    cmp  dword [rdx + WGI_TYPE], WGT_TYPE_LABEL    ; the form's one stock label
    jne  .next
    cmp  [rdx + WGI_WIN], ecx
    je   .bind
.next:
    add  rdx, WGI_SZ
    dec  eax
    jmp  .find
.bind:
    mov  [rel rn_row], rdx
    mov  rax, [rel wgt_text_paint_hook]
    mov  [rel rn_previous_paint], rax
    lea  rax, [rel recovery_notice_paint]
    mov  [rel wgt_text_paint_hook], rax
    mov  edi, [rel rn_slot]
    call wmx_draw_one
.out:
    ret

; Stock escaped label callback. Bind the exact row AND the WM generation;
; neither a later form in the same slot nor edited inline text is a notice.
; The trusted catalog is painted directly; no translation enters WGI_VAL.
recovery_notice_paint:
    push rdi
    push rsi
    push rdx
    push r10
    push r11
    push rbx
    push rcx
    cmp  r12, [rel rn_row]
    jne  .native
    cmp  dword [r12 + WGI_TYPE], WGT_TYPE_LABEL
    jne  .native
    mov  eax, [r12 + WGI_WIN]
    cmp  eax, [rel rn_slot]
    jne  .native
    cmp  eax, WM_MAX
    jae  .native
    lea  rdx, [rel wm_gen]
    mov  eax, [rdx + rax*4]
    cmp  eax, [rel rn_generation]
    jne  .native
    lea  rsi, [rel rn_placeholder]
    push rcx                         ; strcmp consumes CL
    call strcmp
    pop  rcx
    test eax, eax
    jnz  .native
    push rbx
    mov  ebx, ecx
    mov  r10d, [r12 + WGI_W]
    mov  r11d, [r12 + WGI_H]
    call wgt_fill_rect
    pop  rbx
    mov  edi, [rel rn_message_id]
    mov  rsi, [rel rn_english]
    mov  r10d, [r12 + WGI_W]
    shr  r10d, 3
    mov  r11d, [r12 + WGI_H]
    shr  r11d, 4
    call l10n_paint_wrap
    pop  rcx
    pop  rbx
    pop  r11
    pop  r10
    pop  rdx
    pop  rsi
    pop  rdi
    ret
.native:
    pop  rcx
    pop  rbx
    pop  r11
    pop  r10
    pop  rdx
    pop  rsi
    pop  rdi
    mov  rax, [rel rn_previous_paint]
    test rax, rax
    jnz  .chain
    jmp  fb_draw_str_n
.chain:
    jmp  rax

rn_placeholder: db "PaOS",0
rn_attempted: db 0
align 8
rn_english: dq 0
rn_row: dq 0
rn_previous_paint: dq 0
rn_slot: dd -1
rn_generation: dd 0
rn_message_id: dd 0

align 4
rn_message_ids:
    dd L10N_ID_c2rs_notice_interrupted, L10N_ID_c2rs_notice_safe
    dd L10N_ID_c2rs_notice_rollback, L10N_ID_c2rs_notice_check
    dd L10N_ID_c2rs_notice_state, L10N_ID_c2rs_notice_rescue
    dd L10N_ID_c2rs_notice_rescue_check
