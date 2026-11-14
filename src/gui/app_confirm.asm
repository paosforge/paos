;; MODULE gui/app_confirm
;; LAYER 6
;; PURPOSE Native keyboard-human one-invocation approval surface; no executor.
;; EXPORTS app_confirm_init, app_confirm_tick
;; IMPORTS gui/calendar, sec/app_grants, sec/session, sec/principal, svc/command, gui/widget, gui/window_mgmt, gui/window, gui/wm_pointer, gui/start_programs, dev/input/ps2, boot/gop
;; OWNER saga:app_grants
; Existing native window/widgets only; no drawing primitives, guest text, pointer
; approval or command dispatch. Snapshot numbers/hash are exact bounded hex.
; Deny has initial keyboard focus. Native HUMAN Tab then HUMAN Enter/Space on
; Confirm, unoccluded and unchanged, is required. No automatic focus theft.
AC_LABELS equ 18
AC_COUNT equ (AC_LABELS + 3)
AC_DENY equ (AC_LABELS + 1)
AC_CONFIRM equ (AC_LABELS + 2)
AC_WIDTH equ 560
AC_HEIGHT equ 370

app_confirm_init:
    cmp byte [rel ac_live], 0
    jne .out
    mov rax, [rel wgt_key_filter]
    mov [rel ac_prev_filter], rax
    lea rax, [rel ac_key]
    mov [rel wgt_key_filter], rax
    mov rax, [rel wgt_click_hook]
    mov [rel ac_click_prev], rax
    lea rax, [rel ac_click]
    mov [rel wgt_click_hook], rax
    mov byte [rel ac_live], 1
.out:
    ret

; Native window identity, not slot alone. Closing uses the maintained closer.
ac_scan:
    mov eax, [rel ac_slot]
    cmp eax, WM_MAX
    jae .bad
    lea rcx, [rel wm_title]
    lea rdx, [rel ac_title]
    cmp [rcx + rax*8], rdx
    jne .bad
    lea rcx, [rel wm_owner]
    cmp qword [rcx + rax*8], WM_OWNER_CHROME
    jne .bad
    lea rcx, [rel wm_gen]
    mov edx, [rel ac_gen]
    cmp [rcx + rax*4], edx
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rax*4], WM_FREE
    je .bad
    cmp dword [rcx + rax*4], WM_CLOSED
    je .bad
    ret
.bad:
    mov eax, -1
    ret

ac_close:
    mov byte [rel ac_tab], 0
    mov byte [rel ac_answer], 0
    mov qword [rel ac_id], 0
    call ac_scan
    mov dword [rel ac_slot], -1
    cmp eax, -1
    je .out
    mov edi, eax
    call wmx_close_slot
.out:
    ret

; Refuse any cover, focus/size/position/display change since the human Tab.
; All shown overlays and intersecting desktop-host widgets paint after windows.
ac_ok:
    call ac_scan
    cmp eax, -1
    je .bad
    mov edx, eax
    cmp eax, [rel wm_focus]
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rdx*4], WM_VISIBLE
    jne .bad
    lea rcx, [rel wm_w]
    cmp dword [rcx + rdx*4], AC_WIDTH
    jne .bad
    lea rcx, [rel wm_h]
    cmp dword [rcx + rdx*4], AC_HEIGHT
    jne .bad
    lea rcx, [rel wm_x]
    mov r8d, [rcx + rdx*4]
    test r8d, r8d
    js .bad
    lea rcx, [rel wm_y]
    mov r9d, [rcx + rdx*4]
    test r9d, r9d
    js .bad
    lea r10d, [r8d + AC_WIDTH]
    lea r11d, [r9d + AC_HEIGHT]
    cmp r10d, [rel fb_width]
    jg .bad
    mov ecx, [rel fb_height]
    sub ecx, TASKBAR_H
    cmp r11d, ecx
    jg .bad
    mov ecx, r10d
    mov edx, r11d
    call calendar_overlaps
    test eax, eax
    jnz .bad

    xor ecx, ecx
    lea rdx, [rel wgt_tbl]
.loop:
    cmp ecx, [rel wgt_count]
    jae .yes
    cmp dword [rdx + WGI_TYPE], 0
    je .next
    test dword [rdx + WGI_FLAGS], 1
    jz .next
    mov rax, rdx                        ; the one predicate for paint, hover and press
    call wgt_row_shown                  ; an unfocused window's overlay paints nothing here
    jc .next
    cmp dword [rdx + WGI_LAYER], 1
    je .cover
    cmp dword [rdx + WGI_WIN], WGT_HOST_DESKTOP
    jne .next
.cover:
    mov eax, [rdx + WGI_X]
    cmp eax, r10d
    jge .next
    add eax, [rdx + WGI_W]
    cmp eax, r8d
    jle .next
    mov eax, [rdx + WGI_Y]
    cmp eax, r11d
    jge .next
    add eax, [rdx + WGI_H]
    cmp eax, r9d
    jg .bad
.next:
    add rdx, WGI_SZ
    inc ecx
    jmp .loop
.yes:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; Geometry is captured at Tab and rechecked at key AND idle effect boundary.
ac_geometry:
    mov edx, [rel ac_slot]
    lea rcx, [rel wm_x]
    mov eax, [rcx + rdx*4]
    shl rax, 32
    lea rcx, [rel wm_y]
    mov edx, [rcx + rdx*4]
    or rax, rdx
    mov edx, [rel fb_width]
    shl rdx, 32
    mov ecx, [rel fb_height]
    or rdx, rcx
    ret

; Key filter ABI EDI=focused widget,EAX=key. Preserve inputs on chain.
ac_key:
    cmp byte [rel input_key_origin], KO_HUMAN
    je .origin
    mov byte [rel ac_tab], 0
    mov byte [rel ac_answer], 0
.origin:
    push rdi
    push rax
    call ac_scan
    cmp eax, -1
    je .other
    mov ecx, eax
    mov edi, [rsp + 8]
    cmp edi, [rel wgt_count]
    jae .other
    push rcx
    call wgt_slot_ptr
    pop rcx
    cmp [rax + WGI_WIN], ecx
    jne .other
    pop rax
    pop rdi
    cmp byte [rel input_key_origin], KO_HUMAN
    jne .taken
    cmp eax, GUI_KEY_ESC
    je .deny
    cmp eax, GUI_KEY_TAB
    je .tab
    cmp eax, GUI_KEY_ENTER
    je .press
    cmp eax, ' '
    jne .taken
.press:
    cmp edi, [rel ac_ids + AC_DENY*4]
    je .deny
    cmp edi, [rel ac_ids + AC_CONFIRM*4]
    jne .taken
    cmp byte [rel ac_tab], 1
    jne .taken
    cmp byte [rel wgt_focus_visible], 1
    jne .taken
    mov eax, [rel sp_ptr_inj_seq]
    cmp eax, [rel ac_tab_inj]
    jne .disarm
    mov eax, [rel wm_zcounter]
    cmp eax, [rel ac_tab_z]
    jne .disarm
    call ac_ok
    test eax, eax
    jnz .disarm
    call ac_geometry
    cmp rax, [rel ac_tab_xy]
    jne .disarm
    cmp rdx, [rel ac_tab_fb]
    jne .disarm
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .disarm
    mov [rel ac_token], rdx
    mov byte [rel ac_answer], 1
    jmp .taken
.tab:
    call ac_ok
    test eax, eax
    jnz .disarm
    call ac_geometry
    mov [rel ac_tab_xy], rax
    mov [rel ac_tab_fb], rdx
    mov eax, [rel wm_zcounter]
    mov [rel ac_tab_z], eax
    mov eax, [rel sp_ptr_inj_seq]
    mov [rel ac_tab_inj], eax
    mov byte [rel ac_tab], 1
    mov byte [rel wgt_focus_visible], 1
    mov eax, [rel ac_ids + AC_CONFIRM*4]
    cmp eax, [rel wgt_focus_id]
    jne .focus
    mov eax, [rel ac_ids + AC_DENY*4]
.focus:
    mov [rel wgt_focus_id], eax
    mov ecx, [rel ac_slot]
    lea rdx, [rel wgt_focus_by_win]
    mov [rdx + rcx*4], eax
    call wmx_draw_all
    jmp .taken
.deny:
    mov byte [rel ac_answer], 2
    jmp .taken
.disarm:
    mov byte [rel ac_tab], 0
    mov byte [rel ac_answer], 0
.taken:
    mov eax, 1
    ret
.other:
    pop rax
    pop rdi
    mov rdx, [rel ac_prev_filter]
    test rdx, rdx
    jz .none
    jmp rdx
.none:
    xor eax, eax
    ret

; Every click spends keyboard arming; pointer Confirm has no approval path.
ac_click:
    mov byte [rel ac_tab], 0
    mov byte [rel ac_answer], 0
    cmp qword [rel ac_id], 0
    je .chain
    cmp edi, [rel ac_ids + AC_CONFIRM*4]
    je .out
    cmp edi, [rel ac_ids + AC_DENY*4]
    jne .chain
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .out                            ; an injected press never cancels the owner's card
    mov byte [rel ac_answer], 2
.out:
    ret
.chain:
    mov rax, [rel ac_click_prev]
    test rax, rax
    jz .out
    jmp rax

app_confirm_tick:
    cmp byte [rel ac_live], 1
    jne .out
    cmp byte [rel cmd_in_dispatch], 0
    jne .out
    call app_grants_pending
    test rax, rax
    jz ac_close
    cmp rax, [rel ac_id]
    jne ac_build
    call ac_scan
    cmp eax, -1
    je .cancel
    call ac_ok
    test eax, eax
    jnz .blur
    movzx eax, byte [rel ac_answer]
    mov byte [rel ac_answer], 0
    cmp eax, 2
    je .cancel
    cmp eax, 1
    jne .out
    mov byte [rel ac_tab], 0
    mov eax, [rel sp_ptr_inj_seq]
    cmp eax, [rel ac_tab_inj]
    jne .cancel
    mov eax, [rel wm_zcounter]
    cmp eax, [rel ac_tab_z]
    jne .cancel
    call ac_geometry
    cmp rax, [rel ac_tab_xy]
    jne .cancel
    cmp rdx, [rel ac_tab_fb]
    jne .cancel
    mov rdi, [rel ac_id]
    mov rsi, [rel ac_token]
    call app_grants_approve
    test eax, eax
    jz .cancel
    call app_grants_resume
    jmp ac_close
.blur:
    mov byte [rel ac_tab], 0
    mov byte [rel ac_answer], 0
.out:
    ret
.cancel:
    call app_grants_cancel
    jmp ac_close

; Build all labels while painting is suspended; first frame is fully labelled.
; RAX=id,RDX=frozen snapshot. Copy to private native display data before APIs.
ac_build:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rax
    mov rsi, rdx
    lea rdi, [rel ac_display]
    mov ecx, AG_DESC_SIZE/8
    rep movsq
    call ac_close
    mov [rel ac_id], r12
    mov r15d, [rel wm_focus]
    cmp dword [rel fb_width], AC_WIDTH
    jb .fail
    mov eax, [rel fb_height]
    sub eax, TASKBAR_H
    cmp eax, AC_HEIGHT
    jb .fail
    lea rdi, [rel ac_title]
    xor esi, esi
    xor edx, edx
    mov ecx, AC_WIDTH
    mov r8d, AC_HEIGHT
    xor r9d, r9d
    call wmx_open_window
    cmp eax, WM_MAX
    jae .fail
    mov r12d, eax
    mov [rel ac_slot], eax
    lea rcx, [rel wm_gen]
    mov eax, [rcx + r12*4]
    mov [rel ac_gen], eax
    lea rcx, [rel wm_owner]
    mov qword [rcx + r12*8], WM_OWNER_CHROME
    mov [rel wm_focus], r15d
    mov edi, AC_COUNT
    call wgt_reserve_run
    test eax, eax
    js .fail
    mov [rel wgt_alloc_next], eax
    inc byte [rel wgt_paint_suspended]
    xor ebx, ebx
.loop:
    mov edi, 2
    cmp ebx, AC_DENY
    jb .type
    xor edi, edi
.type:
    mov esi, r12d
    call wgt_create
    cmp eax, -1
    je .failed_widgets
    lea rcx, [rel ac_ids]
    mov [rcx + rbx*4], eax
    mov edi, eax
    call wgt_slot_ptr
    mov r13, rax
    mov dword [rax + WGI_FLAGS], 1
    mov dword [rax + WGI_EDIT], 0
    mov dword [rax + WGI_W], 268
    mov dword [rax + WGI_H], 22
    mov dword [rax + WGI_X], 8
    mov dword [rax + WGI_Y], 28
    cmp ebx, AC_LABELS
    jae .footer
    mov eax, ebx
    shr eax, 1
    imul eax, 26
    add eax, 28
    mov [r13 + WGI_Y], eax
    test bl, 1
    jz .label
    mov dword [r13 + WGI_X], 284
.label:
    mov edi, ebx
    call ac_format
    lea rsi, [rel ac_line]
    jmp .text
.footer:
    mov dword [r13 + WGI_Y], 280
    lea rsi, [rel ac_note]
    cmp ebx, AC_LABELS
    je .text
    mov dword [r13 + WGI_Y], 320
    lea rsi, [rel ac_deny]
    cmp ebx, AC_DENY
    je .text
    mov dword [r13 + WGI_X], 284
    lea rsi, [rel ac_confirm]
.text:
    lea rcx, [rel ac_ids]
    mov edi, [rcx + rbx*4]
    call wgt_set_text
    inc ebx
    cmp ebx, AC_COUNT
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next], -1
    mov eax, [rel ac_ids + AC_DENY*4]
    lea rcx, [rel wgt_focus_by_win]
    mov [rcx + r12*4], eax
    call wmx_draw_all
    jmp .out
.failed_widgets:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next], -1
.fail:
    call app_grants_cancel
    call ac_close
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; format(rowindex)->ac_line; trusted static label plus exact 16 hex digits.
ac_format:
    lea rdx, [rel ac_labels]
    mov rsi, [rdx + rdi*8]
    add rsi, rdx
    lea rdx, [rel ac_offsets]
    movzx eax, byte [rdx + rdi]
    lea rdx, [rel ac_display]
    mov r8, [rdx + rax]
    mov r9d, eax
    cmp eax, AG_D_HASH
    jb .number
    cmp eax, AG_D_OP
    jae .number
    bswap r8
.number:
    lea rdi, [rel ac_line]
.copy:
    lodsb
    test al, al
    jz .hex
    stosb
    jmp .copy
.hex:
    cmp r9d, AG_D_OP
    je .operation
    cmp r9d, AG_D_TIMEOUT
    je .decimal
    cmp r9d, AG_D_CURSOR
    je .decimal
    cmp r9d, AG_D_SEQ
    je .decimal
    mov ecx, 16
    lea rsi, [rel ac_hex]
.digit:
    rol r8, 4
    mov eax, r8d
    and eax, 15
    mov al, [rsi + rax]
    stosb
    loop .digit
    mov byte [rdi], 0
    ret
.operation:
    lea rdx, [rel ac_operations]
    mov rsi, [rdx + r8*8 - 8]
    add rsi, rdx
.op_copy:
    lodsb
    stosb
    test al, al
    jnz .op_copy
    ret
.decimal:
    mov rax, r8
    mov r10, rdi
    mov r11d, 10
.dec_digit:
    xor edx, edx
    div r11
    add dl, '0'
    mov [rdi], dl
    inc rdi
    test rax, rax
    jnz .dec_digit
    mov byte [rdi], 0
    dec rdi
.reverse:
    cmp r10, rdi
    jae .done
    mov al, [r10]
    mov dl, [rdi]
    mov [r10], dl
    mov [rdi], al
    inc r10
    dec rdi
    jmp .reverse
.done:
    ret

align 8
ac_operations: dq ac_status-ac_operations, ac_begin-ac_operations, ac_poll-ac_operations, ac_cancel-ac_operations
ac_status: db 'view waits.',0
ac_begin: db 'start waiting.',0
ac_poll: db 'check a wait.',0
ac_cancel: db 'stop waiting.',0
ac_title: db 'Allow this?',0
ac_note: db 'Once only; 30s. Tab then Enter',0
ac_deny: db 'Deny',0
ac_confirm: db 'Confirm once',0
ac_hex: db '0123456789abcdef'
ac_offsets: db 8,16,88,96,104,112,120,56,48,64,128,136,144,40,24,32,72,80
align 8
ac_labels: dq ac_label_0-ac_labels,ac_label_1-ac_labels,ac_label_2-ac_labels,ac_label_3-ac_labels,ac_label_4-ac_labels,ac_label_5-ac_labels,ac_label_6-ac_labels,ac_label_7-ac_labels,ac_label_8-ac_labels,ac_label_9-ac_labels,ac_label_10-ac_labels,ac_label_11-ac_labels,ac_label_12-ac_labels,ac_label_13-ac_labels,ac_label_14-ac_labels,ac_label_15-ac_labels,ac_label_16-ac_labels,ac_label_17-ac_labels
ac_label_0: db 'App principal: ',0
ac_label_1: db 'Instance: ',0
ac_label_2: db 'App hash 1: ',0
ac_label_3: db 'App hash 2: ',0
ac_label_4: db 'App hash 3: ',0
ac_label_5: db 'App hash 4: ',0
ac_label_6: db 'This app asks to ',0
ac_label_7: db 'Window: ',0
ac_label_8: db 'Window owner: ',0
ac_label_9: db 'Generation: ',0
ac_label_10: db 'Request: ',0
ac_label_11: db 'Cursor: ',0
ac_label_12: db 'Timeout ms: ',0
ac_label_13: db 'Epoch: ',0
ac_label_14: db 'Start: ',0
ac_label_15: db 'Retire: ',0
ac_label_16: db 'Reset: ',0
ac_label_17: db 'App instance: ',0

%include "core/abi/wdata.inc"
%macro WDATA_app_confirm 0
align 8
ac_prev_filter: dq 0
ac_click_prev: dq 0
ac_id: dq 0
ac_token: dq 0
ac_tab_xy: dq 0
ac_tab_fb: dq 0
ac_slot: dd -1
ac_gen: dd 0
ac_tab_z: dd 0
ac_tab_inj: dd 0
ac_ids: times AC_COUNT dd -1
ac_live: db 0
ac_tab: db 0
ac_answer: db 0
%endmacro
WDATA_DEFER WDATA_app_confirm
%macro WDATA_app_confirm_bss 0
ac_line: resb 32
ac_display: resb AG_DESC_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_app_confirm_bss
