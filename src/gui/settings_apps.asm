;; MODULE gui/settings_apps
;; LAYER 6
;; EXPORTS settings_apps_click, settings_apps_show, settings_apps_key, settings_apps_tick, settings_apps_remove_confirm_take, settings_apps_confirm_id
;; IMPORTS gui/widget, gui/form_loader, gui/window_mgmt, gui/start_programs, gui/app_remove, gui/lock_screen, svc/app_store, sec/session, sec/app_binding, core/smp, svc/command
;; CAPS CAP_GUI
;; OWNER rc-amd-claude
;; CONTEXT: bsp_only
; Settings > Apps: what is installed, then what is coming to PaOS by version
; (gui/forms/settings_apps.frm, T5-14). Native PaOS has no Roadmap window, so a
; coming row shows its Roadmap entry in this window. Read-only: a click writes
; only the entry line, so it needs no origin gate. Installed rows are the 0.1
; windows; Network Monitor is shown only while its form is bound, because the
; form comes with a module public builds and failed loads lack. Other rows stay
; fixed until a store can report real install state.
;
; Added apps: Remove and Share per authenticated app_store_list row. Both use
; the original physical confirmation and idle tick; Share destination logic is
; gui/settings_apps_share. Removal uses a confirm
; the owner must press by hand on this window as it stood. Nothing here removes
; anything: a confirmed press lets app_remove_begin take one confirmation for the
; exact row asked about, and only poll status 1 says Removed. No verb, guest or
; script reaches this. The list and begin read storage, so both run on the tick.

SA_W_NETMON     equ 8                   ; settings_apps.frm declaration order
SA_W_ROW0       equ 10
SA_ROWS         equ 6
SA_W_ENTRY      equ SA_W_ROW0 + SA_ROWS
SA_W_ADDED      equ SA_W_ENTRY + 1
SA_W_ADD0       equ SA_W_ADDED + 1
SA_ADD_ROWS     equ 8                   ; catalog slots, fs/app_store_layout.inc
SA_W_ASK        equ SA_W_ADD0 + SA_ADD_ROWS
SA_W_NAME1      equ SA_W_ASK + 1
SA_W_NAME2      equ SA_W_ASK + 2
SA_W_YES        equ SA_W_ASK + 3
SA_W_NO         equ SA_W_ASK + 4
SA_W_SHARE0     equ SA_W_NO + 1
SA_W_DEST       equ SA_W_SHARE0 + SA_ADD_ROWS
SA_W_DRIVE      equ SA_W_DEST + 1
SA_W_VOLUME     equ SA_W_DEST + 2
SA_W_DEVICE     equ SA_W_DEST + 3
SA_W_FILELABEL  equ SA_W_DEST + 4
SA_W_FILENAME   equ SA_W_DEST + 5
SA_W_HINT       equ SA_W_DEST + 6
SA_W_ACCOUNT    equ SA_W_HINT + 1
SA_W_COUNT      equ SA_W_ACCOUNT + 1

SA_ROW_BYTES    equ 256
SA_ROW_DISPLAY  equ 120                 ; display64, NUL inside
SA_IDLE         equ 0
SA_ASKING       equ 1
SA_CONFIRMED    equ 2                   ; pressed; the next tick calls begin
SA_DWELL_US     equ 400000              ; as the install card: not a press meant for what was there
SA_LABEL_NAME   equ 24                  ; "Remove " + this fits WGI_VAL_MAX

; settings_apps_click(EDI widget id) -> EAX 1 when it was a coming row. Needs
; sa_live. Clobbers caller-saved.
settings_apps_click:
    xor  eax, eax
    cmp  byte [rel sa_live], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out
    push rdi
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .existing
    cmp byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne .existing
    call sa_account_activate
    test eax,eax
    jnz .share_taken
.existing:
    mov edi,[rsp]
    call sas_click
    test eax, eax
    jnz .share_taken
    mov edi, [rsp]
    call sa_remove_click
.share_taken:
    pop  rdi
    test eax, eax
    jnz  .out
    xor  ecx, ecx
.find:
    lea  rax, [rel sa_ids + SA_W_ROW0*4]
    cmp  edi, [rax + rcx*4]
    je   .hit
    inc  ecx
    cmp  ecx, SA_ROWS
    jb   .find
    xor  eax, eax
.out:
    ret
.hit:
    lea  rsi, [rel sa_entries]
.skip:
    test ecx, ecx
    jz   .show
.skip_text:
    lodsb
    test al, al
    jnz  .skip_text
    dec  ecx
    jmp  .skip
.show:
    mov  edi, [rel sa_ids + SA_W_ENTRY*4]
    sub  rsp, 8
    call wgt_set_text
    add  rsp, 8
    mov  eax, 1
    ret

; settings_apps_show(): the window was just opened or raised. Needs sa_live.
; Clobbers caller-saved.
settings_apps_show:
    cmp  byte [rel sa_live], 1
    jne  .out
    sub  rsp, 8
    call sa_added_reset
    add  rsp, 8
    mov  edi, FORM_NETMON_INDEX
    sub  rsp, 8
    call form_table_ptr
    add  rsp, 8
    lea  rsi, [rel sa_netmon_name]
    cmp  qword [rax + FORM_LEN], 0
    jne  .put
    lea  rsi, [rel sa_netmon_absent]
.put:
    mov  edi, [rel sa_ids + SA_W_NETMON*4]
    jmp  wgt_set_text
.out:
    ret

; -> EAX the live confirm button's widget id for the pointer's arm row, else -1.
settings_apps_confirm_id:
    sub  rsp, 8
    call sp_apps_scan
    add  rsp, 8
    mov  eax, -1
    cmp  byte [rel sa_live], 1
    jne  .out
    mov  eax, [rel sa_ids + SA_W_YES*4]
.out:
    ret

; EDI widget id -> ECX row 0.. and EAX 1 when it is a listed row's Remove button.
sa_row_of:
    xor  ecx, ecx
.next:
    lea  rax, [rel sa_ids + SA_W_ADD0*4]
    cmp  edi, [rax + rcx*4]
    je   .hit
    inc  ecx
    cmp  ecx, SA_ADD_ROWS
    jb   .next
.no:
    xor  eax, eax
    ret
.hit:
    cmp  ecx, [rel sa_rows_n]
    jae  .no
    mov  eax, 1
    ret

; EDI widget id -> EAX 1 when the press was for Added apps. Only a human press
; and gesture count; any other press on Remove spends nothing and on the confirm
; ends the question. Cancel is never authority, so it takes any origin.
sa_remove_click:
    cmp  edi, [rel sa_ids + SA_W_NO*4]
    jne  .yes
    cmp  dword [rel sa_state], SA_ASKING
    jne  .taken
    call sa_cancel
    jmp  .taken
.yes:
    cmp  edi, [rel sa_ids + SA_W_YES*4]
    jne  .row
    cmp  dword [rel sa_state], SA_ASKING
    jne  .taken
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .refuse
    cmp  byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne  .refuse
    mov  esi, SP_ARM_APP_REMOVE
    call sp_arm_holds                   ; not steered onto Remove since the pointer left it
    test eax, eax
    jz   .refuse
    call sa_confirm_press
    jmp  .taken
.refuse:
    call sa_cancel
    jmp  .taken
.row:
    call sa_row_of
    test eax, eax
    jz   .other
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .taken
    cmp  byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne  .taken
    mov  edi, ecx
    call sa_ask
.taken:
    mov  eax, 1
    ret
.other:
    xor  eax, eax
    ret

; settings_apps_key(EDI focused widget, EAX key) -> EAX 1 when taken. An injected
; key may only cancel. Keyboard confirm also needs the window unchanged since the
; question: Tab off Cancel, then Enter or Space on the visibly focused button.
settings_apps_key:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, eax
    cmp  byte [rel sa_live], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    cmp  ebx, [rel wgt_count]
    jae  .no
    call sa_window
    mov  r8d, eax
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  [rax + WGI_WIN], r8d
    jne  .no
    cmp  byte [rel input_key_origin], KO_HUMAN
    je   .human
    cmp  dword [rel sa_state], SA_ASKING
    jne  .inj_row
    cmp  r12d, GUI_KEY_ESC
    jne  .taken                         ; nor an injected Tab onto the confirm
    call sa_cancel
    jmp  .taken
.inj_row:
    mov  edi, ebx
    call sa_row_of
    test eax, eax
    jnz  .taken
    jmp  .no
.human:
    cmp  r12d, GUI_KEY_ESC
    jne  .press
    cmp  dword [rel sa_state], SA_ASKING
    jne  .no
    call sa_cancel
    jmp  .taken
.press:
    cmp  r12d, GUI_KEY_ENTER
    je   .pressed
    cmp  r12d, ' '
    jne  .no
.pressed:
    cmp  ebx, [rel sa_ids + SA_W_NO*4]
    jne  .key_yes
    cmp  dword [rel sa_state], SA_ASKING
    jne  .no
    call sa_cancel
    jmp  .taken
.key_yes:
    cmp  ebx, [rel sa_ids + SA_W_YES*4]
    jne  .key_row
    cmp  dword [rel sa_state], SA_ASKING
    jne  .taken
    cmp  byte [rel wgt_focus_visible], 1
    jne  .taken
    call sa_unchanged
    test eax, eax
    jnz  .key_confirm
    call sa_cancel
    jmp  .taken
.key_confirm:
    call sa_confirm_press
    jmp  .taken
.key_row:
    mov  edi, ebx
    cmp edi,[rel sa_ids+SA_W_ACCOUNT*4]
    jne .account_key_ready
    cmp byte [rel wgt_focus_visible],1
    jne .taken
    cmp edi,[rel wgt_focus_id]
    jne .taken
.account_key_ready:
    call sa_account_activate
    test eax,eax
    jnz .taken
    mov edi,ebx
    call sas_activate
    test eax, eax
    jnz .taken
    mov edi, ebx
    call sa_row_of
    test eax, eax
    jz   .no
    mov  edi, ecx
    call sa_ask
.taken:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; HUMAN click/key entry only. This opens a question, never grants network access.
; Resolve the running instance from the original native binding, not app text or
; an install row. No deferred request survives a window/owner/instance change.
; The unchanged card independently re-reads the full VM/binding/window lifetime
; and still requires its own physical Tab/Enter approval and dwell.
sa_account_activate:
    cmp edi,[rel sa_ids+SA_W_ACCOUNT*4]
    jne .other
    push rbx
    sub rsp,128                         ; binding120 + original Settings slot
    mov ebx,edi
    cmp byte [rel sa_live],1
    jne .done
    cmp byte [rel session_locked],SESSION_LOCKED
    je .done
    cmp byte [rel cmd_in_dispatch],0
    jne .done
    cmp dword [rel cmd_dispatch_depth],0
    jne .done
    cmp byte [rel command_auth_remote_active],0
    jne .done
    cmp dword [rel sa_state],SA_IDLE
    jne .done
    cmp qword [rel sa_ticket],0
    jne .done
    call smp_current_logical
    test eax,eax
    jnz .done
    cmp ebx,[rel wgt_count]
    jae .done
    call sa_window
    cmp eax,WM_MAX
    jae .done
    mov [rsp+120],eax
    cmp eax,[rel wm_focus]
    jne .done
    lea rcx,[rel wm_state]
    cmp dword [rcx+rax*4],WM_VISIBLE
    jne .done
    mov edi,ebx
    call wgt_slot_ptr
    mov edx,[rsp+120]
    cmp [rax+WGI_WIN],edx
    jne .done
    cmp dword [rax+WGI_TYPE],WGT_TYPE_BUTTON
    jne .done
    test dword [rax+WGI_FLAGS],1
    jz .done
    mov rdi,rsp
    call app_binding_observe
    cmp eax,1
    jne .done
    cmp qword [rsp],1
    jne .done
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .done
    test rdx,rdx
    jz .done
    cmp [rsp+8],rax
    jne .done
    cmp [rsp+32],rdx
    jne .done
    mov rdi,[rsp+64]
    test rdi,rdi
    jz .done
    ; Replace this Settings window, preserving the original app's windows and
    ; VM. Its 47 widgets plus Mail's six leave no run for the 15-widget card in
    ; the bounded stock table. Ordinary WM closure retires only Settings' IDs.
    mov edi,[rsp+120]
    call wmx_close_slot
    mov ecx,[rsp+120]
    lea rax,[rel wm_state]
    cmp dword [rax+rcx*4],WM_CLOSED
    jne .done
    mov rdi,[rsp+64]
    call lock_screen_account_offer
.done:
    add rsp,128
    pop rbx
    mov eax,1                           ; this button was taken, even if refused
    ret
.other:
    xor eax,eax
    ret

; -> EAX the Apps window's slot, by its status widget.
sa_window:
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    sub  rsp, 8
    call wgt_slot_ptr
    add  rsp, 8
    mov  eax, [rax + WGI_WIN]
    ret

; EDI row: ask about exactly this row. The copy is what any later press means, so
; a refreshed list cannot retarget the question.
sa_ask:
    cmp  dword [rel sa_state], SA_IDLE
    jne  .out
    cmp  qword [rel sa_ticket], 0
    jne  .out
    push rbx
    mov  ebx, edi
    call sas_reset
    call sa_local_owner
    test rdx, rdx
    jz   .refused
    mov  [rel sa_epoch], rdx
    mov  eax, ebx
    shl  eax, 8
    lea  rsi, [rel sa_rows]
    add  rsi, rax
    lea  rdi, [rel sa_pick]
    mov  ecx, SA_ROW_BYTES/8
    cld
    rep  movsq
    cmp  byte [rel sa_pick + SA_ROW_DISPLAY + 63], 0
    jne  .refused
    call sa_window
    mov  [rel sa_slot], eax
    cmp  eax, [rel wm_focus]
    jne  .refused
    lea  rcx, [rel wm_gen]
    mov  edx, [rcx + rax*4]
    mov  [rel sa_gen], edx
    call sa_geometry
    mov  [rel sa_xy], rax
    mov  [rel sa_wh], rdx
    mov  rax, [rel fb_width]
    mov  [rel sa_fb], rax
    mov  eax, [rel wm_zcounter]
    mov  [rel sa_z], eax
    mov  eax, [rel sp_ptr_inj_seq]
    mov  [rel sa_inj], eax
    call time_monotonic_now_us
    test rax, rax
    jz   .refused
    mov  [rel sa_asked_us], rax
    mov  dword [rel sa_state], SA_ASKING
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    lea  rsi, [rel sa_s_ask]
    call wgt_set_text
    mov  edi, [rel sa_ids + SA_W_NAME1*4]
    lea  rsi, [rel sa_pick + SA_ROW_DISPLAY]
    call wgt_set_text
    lea  rdi, [rel sa_pick + SA_ROW_DISPLAY]
    call strlen
    lea  rsi, [rel sa_pick + SA_ROW_DISPLAY]
    mov  ecx, WGI_VAL_MAX
    cmp  eax, ecx
    cmovb ecx, eax
    add  rsi, rcx
    mov  edi, [rel sa_ids + SA_W_NAME2*4]
    call wgt_set_text
    mov  ebx, 1
    call sa_show_question
    mov  eax, [rel sa_ids + SA_W_NO*4]  ; the keyboard rests on Cancel
    mov  ecx, [rel sa_slot]
    lea  rdx, [rel wgt_focus_by_win]
    mov  [rdx + rcx*4], eax
    mov  [rel wgt_focus_id], eax
    call wmx_draw_all
    pop  rbx
    ret
.refused:
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    lea  rsi, [rel sa_s_not_removed]
    call wgt_set_text
    pop  rbx
.out:
    ret

; EBX 1 show, 0 hide the name lines and both confirm buttons.
sa_show_question:
    mov  edi, SA_W_NAME1
    call sa_flag
    mov  edi, SA_W_NAME2
    call sa_flag
    mov  edi, SA_W_YES
    call sa_flag
    mov  edi, SA_W_NO
    call sa_flag
    jmp sas_widgets

; EDI sa_ids index, EBX visible.
sa_flag:
    push r12
    mov r12d, edi
    call .one
    sub r12d, SA_W_ADD0
    cmp r12d, SA_ADD_ROWS
    jae .out
    lea edi, [r12 + SA_W_SHARE0]
    call .one
.out:
    pop r12
    ret
.one:
    mov eax, edi
    lea rcx, [rel sa_ids]
    mov edi, [rcx + rax*4]
    sub rsp, 8
    call wgt_slot_ptr
    add rsp, 8
    and dword [rax + WGI_FLAGS], ~1
    or [rax + WGI_FLAGS], ebx
    ret

; End the question. Clears the row, so nothing is left to take.
sa_cancel:
    push rbx
    mov  dword [rel sa_state], SA_IDLE
    call sas_reset
    call sa_forget_pick
    xor  ebx, ebx
    call sa_show_question
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    lea  rsi, [rel sa_s_not_removed]
    call wgt_set_text
    call wmx_draw_all
    pop  rbx
    ret

sa_forget_pick:
    lea  rdi, [rel sa_pick]
    xor  eax, eax
    mov  ecx, SA_ROW_BYTES/8
    cld
    rep  stosq
    mov  [rel sa_epoch], rax
    ret

; -> RAX x:y, RDX w:h of the asked window.
sa_geometry:
    mov  ecx, [rel sa_slot]
    lea  rdx, [rel wm_x]
    mov  eax, [rdx + rcx*4]
    shl  rax, 32
    lea  rdx, [rel wm_y]
    mov  edx, [rdx + rcx*4]
    or   rax, rdx
    lea  rdx, [rel wm_w]
    mov  edx, [rdx + rcx*4]
    shl  rdx, 32
    lea  r8, [rel wm_h]
    mov  r8d, [r8 + rcx*4]
    or   rdx, r8
    ret

; -> RDX the local owner's epoch, else 0.
sa_local_owner:
    sub  rsp, 8
    call session_shell_local_authority
    add  rsp, 8
    cmp  rax, PRIN_OWNER
    jne  .no
    ret
.no:
    xor  edx, edx
    ret

; -> EAX 1 while the same window generation is focused, shown and where it was,
; on the same screen, under the owner who was asked.
sa_window_same:
    mov  ecx, [rel sa_slot]
    cmp  ecx, [rel wm_focus]
    jne  .no
    lea  rax, [rel wm_gen]
    mov  edx, [rax + rcx*4]
    cmp  edx, [rel sa_gen]
    jne  .no
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .no
    call sa_geometry
    cmp  rax, [rel sa_xy]
    jne  .no
    cmp  rdx, [rel sa_wh]
    jne  .no
    mov  rax, [rel fb_width]
    cmp  rax, [rel sa_fb]
    jne  .no
    call sa_local_owner
    test rdx, rdx
    jz   .no
    cmp  rdx, [rel sa_epoch]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; -> EAX 1 while nothing was raised and no injected pointer came since sa_z/sa_inj.
sa_unchanged:
    mov  eax, [rel wm_zcounter]
    cmp  eax, [rel sa_z]
    jne  .no
    mov  eax, [rel sp_ptr_inj_seq]
    cmp  eax, [rel sa_inj]
    jne  .no
    jmp  sa_window_same
.no:
    xor  eax, eax
    ret

; A hand pressed the confirm. Too early is ignored; a changed window ends the
; question. From here to the take nothing may change.
sa_confirm_press:
    sub  rsp, 8
    call time_monotonic_now_us
    add  rsp, 8
    test rax, rax
    jz   .ignore
    sub  rax, [rel sa_asked_us]
    jb   .ignore
    cmp  rax, SA_DWELL_US
    jb   .ignore
    call sa_window_same
    test eax, eax
    jz   sa_cancel
    sub rsp, 8
    call sas_prepare
    add rsp, 8
    test eax, eax
    jz .ignore
    mov  eax, [rel wm_zcounter]
    mov  [rel sa_z], eax
    mov  eax, [rel sp_ptr_inj_seq]
    mov  [rel sa_inj], eax
    mov  dword [rel sa_state], SA_CONFIRMED
.ignore:
    ret

; settings_apps_remove_confirm_take(RDI row256, RSI owner epoch) -> EAX 1 once for
; the exact row a hand confirmed on this window, 0 otherwise. Every check runs
; before the confirmation is spent, and a refusal mints nothing.
settings_apps_remove_confirm_take:
    cmp byte [rel sas_mode], 0
    jne .no
    cmp  dword [rel sa_state], SA_CONFIRMED
    jne  .no
    test rsi, rsi
    jz   .no
    cmp  rsi, [rel sa_epoch]
    jne  .no
    test rdi, rdi
    jz   .no
    lea  rsi, [rel sa_pick]
    mov  ecx, SA_ROW_BYTES/8
    cld
    repe cmpsq
    jne  .no
    cmp  byte [rel sa_live], 1
    jne  .no
    sub  rsp, 8
    call sa_unchanged
    add  rsp, 8
    test eax, eax
    jz   .no
    mov  dword [rel sa_state], SA_IDLE
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; settings_apps_tick(): after sp_apps_scan. A ticket is polled whatever the window
; does; only poll 1 says Removed. The rest needs the live window and no lock.
settings_apps_tick:
    push rbx
    cmp  qword [rel sa_ticket], 0
    je   .window
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out
    call sa_poll
    jmp  .out
.window:
    cmp  byte [rel sa_live], 1
    jne  .gone
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .locked
    cmp  dword [rel sa_state], SA_CONFIRMED
    je   .begin
    cmp  dword [rel sa_state], SA_ASKING
    jne  .list
    call sa_window_same
    test eax, eax
    jz .question_changed
    call sas_tick
    jmp .out
.question_changed:
    call sa_cancel
    jmp  .out
.list:
    cmp  byte [rel sa_listing], 1
    jne  .out
    call sa_list_step
    jmp  .out
.begin:
    call sa_begin
    jmp  .out
.locked:
    cmp  dword [rel sa_state], SA_IDLE
    je   .out
    call sa_cancel
    jmp  .out
.gone:
    mov  dword [rel sa_state], SA_IDLE
    mov  byte [rel sa_listing], 0
    call sas_reset
    call sa_forget_pick
.out:
    pop  rbx
    ret

; The confirmed row goes to the coordinator, which takes the confirmation itself.
sa_begin:
    cmp byte [rel sas_mode], 1
    je sas_begin
    lea  rdi, [rel sa_pick]
    call app_remove_begin
    mov  ebx, eax
    mov  r8, rdx
    mov  dword [rel sa_state], SA_IDLE  ; a confirmation not taken is gone too
    push r8
    call sa_forget_pick
    pop  r8
    lea  rsi, [rel sa_s_not_removed]
    cmp  ebx, 1
    jne  .say
    mov  [rel sa_ticket], r8
    lea  rsi, [rel sa_s_removing]
.say:
    push rsi
    xor  ebx, ebx
    call sa_show_question
    pop  rsi
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    call wgt_set_text
    call wmx_draw_all
    cmp  qword [rel sa_ticket], 0
    jne  .out
    call sa_list_restart
.out:
    ret

sa_poll:
    mov  rdi, [rel sa_ticket]
    call app_remove_poll
    cmp  eax, 2
    je   .out
    lea  rsi, [rel sa_s_removed]
    cmp  eax, 1
    je   .ended
    lea  rsi, [rel sa_s_failed]
    cmp  eax, 3
    je   .ended
    lea  rsi, [rel sa_s_partial]
    cmp  eax, 4
    je   .ended
    lea  rsi, [rel sa_s_unknown]
.ended:
    mov  qword [rel sa_ticket], 0
    cmp  byte [rel sa_live], 1
    jne  .out
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    sub  rsp, 8
    call wgt_set_text
    call sa_list_restart
    add  rsp, 8
.out:
    ret

; The window was opened or raised: fresh words, then the list from the tick.
sa_added_reset:
    push rbx
    mov  dword [rel sa_state], SA_IDLE
    call sas_reset
    call sa_forget_pick
    xor  ebx, ebx
    call sa_show_question
    lea  rsi, [rel sa_s_empty]
    cmp  qword [rel sa_ticket], 0
    je   .say
    lea  rsi, [rel sa_s_removing]
.say:
    mov  edi, [rel sa_ids + SA_W_ASK*4]
    call wgt_set_text
    call sa_list_restart
    pop  rbx
    ret

sa_list_restart:
    push rbx
    mov  dword [rel sa_rows_n], 0
    mov  qword [rel sa_list_gen], 0
    mov  byte [rel sa_listing], 1
    xor  ebx, ebx
.hide:
    lea  edi, [rbx + SA_W_ADD0]
    push rbx
    xor  ebx, ebx
    call sa_flag
    pop  rbx
    inc  ebx
    cmp  ebx, SA_ADD_ROWS
    jb   .hide
    mov  edi, [rel sa_ids + SA_W_ADDED*4]
    lea  rsi, [rel sa_s_added_checking]
    call wgt_set_text
    pop  rbx
    ret

; One list call per tick. Unavailable and refused are never shown as no apps.
sa_list_step:
    mov  eax, [rel sa_rows_n]
    mov  edi, eax
    shl  eax, 8
    lea  rsi, [rel sa_rows]
    add  rsi, rax
    mov  edx, SA_ROW_BYTES
    mov  rcx, [rel sa_list_gen]
    call app_store_list
    cmp  eax, 1
    je   .row
    mov  byte [rel sa_listing], 0
    cmp  eax, 2
    jne  .unavailable
    lea  rsi, [rel sa_s_added]
    cmp  dword [rel sa_rows_n], 0
    jne  .say
    lea  rsi, [rel sa_s_added_none]
    jmp  .say
.unavailable:
    mov  dword [rel sa_rows_n], 0
    lea  rsi, [rel sa_s_added_unavailable]
    xor  ebx, ebx
.hide:                                  ; a part-read list offers no Remove
    lea  edi, [rbx + SA_W_ADD0]
    push rsi
    push rbx
    xor  ebx, ebx
    call sa_flag
    pop  rbx
    pop  rsi
    inc  ebx
    cmp  ebx, SA_ADD_ROWS
    jb   .hide
.say:
    mov  edi, [rel sa_ids + SA_W_ADDED*4]
    call wgt_set_text
    jmp  wmx_draw_all
.row:
    mov  [rel sa_list_gen], rdx
    mov  eax, [rel sa_rows_n]
    mov  ebx, eax
    shl  eax, 8
    lea  rsi, [rel sa_rows + SA_ROW_DISPLAY]
    add  rsi, rax
    mov  rax, 'Remove '
    mov  [rel sa_label], rax
    lea  rdi, [rel sa_label + 7]
    mov  ecx, SA_LABEL_NAME
.copy:
    lodsb
    test al, al
    jz   .copied
    stosb
    loop .copy
.copied:
    mov  byte [rdi], 0
    lea  rcx, [rel sa_ids + SA_W_ADD0*4]
    mov  edi, [rcx + rbx*4]
    lea  rsi, [rel sa_label]
    call wgt_set_text
    lea  edi, [rbx + SA_W_ADD0]
    mov  ebx, 1
    call sa_flag
    inc  dword [rel sa_rows_n]
    cmp  dword [rel sa_rows_n], SA_ADD_ROWS
    jb   .more
    mov  byte [rel sa_listing], 0
    lea  rsi, [rel sa_s_added]
    jmp  .say
.more:
    ret

sa_s_added:             db "Added apps", 0
sa_s_added_checking:    db "Added apps: checking", 0
sa_s_added_none:        db "Added apps: none", 0
sa_s_added_unavailable: db "Added apps: not available", 0
sa_s_empty:             db 0
sa_s_ask:               db "Remove this app?", 0
sa_s_not_removed:       db "Not removed", 0
sa_s_removing:          db "Removing", 0
sa_s_removed:           db "Removed", 0
sa_s_failed:            db "Could not remove this app", 0
sa_s_partial:           db "Removal did not finish", 0
sa_s_unknown:           db "Removal state unknown", 0

sa_netmon_name:   db "Network Monitor", 0
sa_netmon_absent: db 0
sa_entries:                             ; each at most WGI_VAL_MAX bytes
    db "Web browser: maybe in 0.1", 0
    db "Photos: coming in 0.2", 0
    db "Documents: coming in 0.2", 0
    db "Task Manager: coming in 0.2", 0
    db "Media Player: coming in 0.2", 0
    db "Email: 0.2 or later", 0

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_settings_apps 0
alignb 4
sa_ids:          resd SA_W_COUNT
sa_state:        resd 1
sa_rows_n:       resd 1
sa_slot:         resd 1
sa_gen:          resd 1
sa_z:            resd 1
sa_inj:          resd 1
alignb 8
sa_ticket:       resq 1
sa_list_gen:     resq 1
sa_epoch:        resq 1
sa_xy:           resq 1
sa_wh:           resq 1
sa_fb:           resq 1
sa_asked_us:     resq 1
sa_rows:         resb SA_ADD_ROWS * SA_ROW_BYTES
sa_pick:         resb SA_ROW_BYTES
sa_label:        resb 32
sa_listing:      resb 1
sa_live:         resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_settings_apps
