;; MODULE gui/format_confirm
;; LAYER 6
;; PURPOSE Native removable partition format choice and one-use F1 decision.
;; EXPORTS format_confirm_init, format_confirm_offer, format_confirm_tick, format_confirm_wipe, format_confirm_retire
;; IMPORTS fs/format_job, gui/calendar, fs/fs_format, sec/session, sec/principal, core/smp, core/time, core/lib/mem, core/lib/fmt, svc/command, gui/widget, gui/window_mgmt, gui/window, gui/wm_pointer, gui/start_programs, dev/input/ps2, boot/gop
;; OWNER saga:fs
;; CONTEXT: bsp_only
; Format F4a: A3 human-input mechanism, separate native F1 decision and token.
; A HUMAN Tab to Confirm and Enter, plus a fresh owner password, publishes a
; one-use (F1 token, epoch, filesystem, label) decision only for the synchronous FS
; consumer. Every consume spends it, including refusals. No command getter,
; wire method, reusable password success or ambient SPECIAL capability.
FC4_COUNT equ 20
FC4_SECRET equ 11
FC4_DENY equ 18
FC4_CONFIRM equ 19
FC4_WIDTH equ 560
FC4_HEIGHT equ 500
FC4_STATUS equ 17
FC4_TTL_US equ 120000000
FC4_OP_FORMAT equ 1
FC4_KIND equ 12
FC4_LABEL equ 13

format_confirm_init:
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    cmp byte [rel fc4_initialized],0
    jne .out
    lea rdi,[rel format_confirm_wipe]
    call session_shell_register_format_wipe
    cmp eax,1
    jne .out
    lea rdi,[rel fc4_decision_consume]
    call fs_format_register_decision
    cmp eax,1
    jne .out
    mov rax,[rel wgt_key_filter]
    mov [rel fc4_prev_filter],rax
    lea rax,[rel fc4_key]
    mov [rel wgt_key_filter],rax
    mov rax,[rel wgt_click_hook]
    mov [rel fc4_click_prev],rax
    lea rax,[rel fc4_click]
    mov [rel wgt_click_hook],rax
    mov byte [rel fc4_initialized],1
.out:
    pop rbx
    ret

; Read-only offer: RDI=registered device, RSI=first LBA, RDX=sector count.
; Returns EAX=0 opened / -1 refused. F1 independently proves eligibility.
format_confirm_offer:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    call fc4_guard
    cmp eax,1
    jne .bad
    cmp byte [rel fc4_initialized],1
    jne .bad
    cmp byte [rel fc4_active],0
    jne .bad
    cmp dword [rel fc4_slot],-1
    jne .bad
    cmp dword [rel wgt_secret_owner],-1
    jne .bad
    mov [rel fc4_epoch],rdx
    mov rdi,rbx
    mov rsi,r12
    mov rdx,r13
    lea rcx,[rel fc4_snapshot]
    call fs_format_snapshot
    mov byte [rel fc4_kind],1
    mov dword [rel fc4_label],'PAOS'
    mov byte [rel fc4_label+4],0
    mov dword [rel fc4_label_len],4
    test eax,eax
    jnz .fail
    call fc4_snapshot_valid
    test eax,eax
    jnz .fail
    mov rdi,rbx
    mov rsi,r12
    mov rdx,r13
    call format_job_prepare
    test eax,eax
    jnz .fail
    call time_monotonic_now_us
    test rax,rax
    jz .fail
    add rax,FC4_TTL_US
    jc .fail
    mov [rel fc4_expires],rax
    call fc4_guard
    cmp eax,1
    jne .fail
    cmp rdx,[rel fc4_epoch]
    jne .fail
    call fc4_build
    test eax,eax
    jnz .fail
    mov byte [rel fc4_active],1
    call wmx_draw_all
    xor eax,eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    call fc4_close
.bad:
    mov eax,-1
    pop r13
    pop r12
    pop rbx
    ret

fc4_guard:
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,-1
    je .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    xor edx,edx
    ret

; Reject malformed provider facts before rendering; identity/media proof is FS's.
fc4_snapshot_valid:
    mov rax,[rel fc4_snapshot]
    or rax,[rel fc4_snapshot+8]
    jz .bad
    mov rax,[rel fc4_snapshot+48]
    test rax,rax
    jz .bad
    mov rdx,[rel fc4_snapshot+56]
    test rdx,rdx
    jz .bad
    cmp rdx,rax
    ja .bad
    movzx eax,byte [rel fc4_snapshot+64]
    dec eax
    cmp eax,1
    ja .bad
    cmp byte [rel fc4_snapshot+65],0
    je .bad
    cmp byte [rel fc4_snapshot+66],4
    ja .bad
    cmp byte [rel fc4_snapshot+68],2
    ja .bad
    lea rsi,[rel fc4_snapshot+69]
    mov ecx,27
.reserved:
    cmp byte [rsi],0
    jne .bad
    inc rsi
    loop .reserved
    mov rax,[rel fc4_snapshot+80]
    or rax,[rel fc4_snapshot+88]
    jnz .bad
    xor ecx,ecx
    lea rdx,[rel fc4_snapshot+16]
.name:
    mov al,[rdx+rcx]
    test al,al
    jz .pad
    cmp al,0x20
    jb .bad
    cmp al,0x7e
    ja .bad
    inc ecx
    cmp ecx,31
    jb .name
    cmp byte [rdx+rcx],0
    jne .bad
.pad:
    test ecx,ecx
    jz .bad
.zero:
    cmp byte [rdx+rcx],0
    jne .bad
    inc ecx
    cmp ecx,32
    jb .zero
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; Erase only our original private editor, preserving other cards' custody.
fc4_secret_clear:
    mov edi,[rel fc4_ids+FC4_SECRET*4]
    cmp edi,[rel wgt_secret_owner]
    jne .out
    call wgt_birth_lifetime
    lea rcx,[rel fc4_births]
    cmp rax,[rcx+FC4_SECRET*8]
    jne .out
    test rax,rax
    jz .out
    call wgt_secret_clear
.out:
    ret

; Session's synchronous eraser. Both native snapshots and the original editor
; are cleared before authority callbacks. No IO, workspace or paint.
format_confirm_wipe:
    call format_job_cancel
    mov byte [rel fc4_decision],0
    mov byte [rel fc4_active],0
    mov byte [rel fc4_tab],0
    mov byte [rel fc4_answer],0
    mov byte [rel fc4_done],0
    mov dword [rel fc4_job_phase],0
    mov qword [rel fc4_epoch],0
    mov byte [rel fc4_kind],0
    mov dword [rel fc4_label_len],0
    lea rdi,[rel fc4_label]
    xor eax,eax
    mov ecx,12
    rep stosb
    lea rdi,[rel fc4_frozen]
    mov ecx,24
    rep stosb
    call fc4_secret_clear
    call fs_format_cancel        ; FS memory-only native slot eraser
    lea rdi,[rel fc4_snapshot]
    xor eax,eax
    mov ecx,96
    rep stosb
    ret

; WM pre-retirement hook, before widgets are freed; no recursive close.
format_confirm_retire:
    push rbx
    mov ebx,edi
    call fc4_scan
    cmp eax,-1
    je .out
    cmp eax,ebx
    jne .out
    call format_confirm_wipe
    mov dword [rel fc4_slot],-1
.out:
    pop rbx
    ret

fc4_close:
    call format_confirm_wipe
    call fc4_scan
    mov dword [rel fc4_slot],-1
    cmp eax,-1
    je .out
    mov edi,eax
    call wmx_close_slot
.out:
    ret

fc4_scan:
    mov eax, [rel fc4_slot]
    cmp eax, WM_MAX
    jae .bad
    lea rcx, [rel wm_title]
    lea rdx, [rel fc4_title]
    cmp [rcx + rax*8], rdx
    jne .bad
    lea rcx, [rel wm_owner]
    cmp qword [rcx + rax*8], WM_OWNER_CHROME
    jne .bad
    lea rcx, [rel wm_gen]
    mov edx, [rel fc4_gen]
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

fc4_ok:
    call fc4_scan
    cmp eax, -1
    je .bad
    mov edx, eax
    cmp eax, [rel wm_focus]
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rdx*4], WM_VISIBLE
    jne .bad
    lea rcx, [rel wm_w]
    cmp dword [rcx + rdx*4], FC4_WIDTH
    jne .bad
    lea rcx, [rel wm_h]
    cmp dword [rcx + rdx*4], FC4_HEIGHT
    jne .bad
    lea rcx, [rel wm_x]
    mov r8d, [rcx + rdx*4]
    test r8d, r8d
    js .bad
    lea rcx, [rel wm_y]
    mov r9d, [rcx + rdx*4]
    test r9d, r9d
    js .bad
    lea r10d, [r8d + FC4_WIDTH]
    lea r11d, [r9d + FC4_HEIGHT]
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
fc4_geometry:
    mov edx, [rel fc4_slot]
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

fc4_widgets:
    push rbx
    xor ebx,ebx
.loop:
    lea rax,[rel fc4_ids]
    mov edi,[rax+rbx*4]
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    lea rcx,[rel fc4_births]
    cmp rax,[rcx+rbx*8]
    jne .bad
    lea rax,[rel fc4_ids]
    mov edi,[rax+rbx*4]
    call wgt_slot_ptr
    mov ecx,[rel fc4_slot]
    cmp [rax+WGI_WIN],ecx
    jne .bad
    cmp dword [rax+WGI_BIND],0
    jne .bad
    cmp dword [rax+WGI_FLAGS],1
    jne .bad
    cmp dword [rax+WGI_LAYER],0
    jne .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    lea rcx,[rel fc4_types]
    mov ecx,[rcx+rbx*4]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .bad
    ; Native card geometry is fixed: moves/resizes must never leave labels apart.
    lea rcx,[rel fc4_rects]
    mov edx,ebx
    shl edx,4
    add rcx,rdx
    mov rdx,[rax+WGI_X]
    cmp rdx,[rcx]
    jne .bad
    mov rdx,[rax+WGI_W]
    cmp rdx,[rcx+8]
    jne .bad
    cmp ebx,FC4_SECRET
    je .next
    lea rsi,[rax+WGI_VLEN]
    lea rdi,[rel fc4_texts]
    imul edx,ebx,44
    add rdi,rdx
    mov ecx,11
    cld
    repe cmpsd
    jne .bad
.next:
    inc ebx
    cmp ebx,FC4_COUNT
    jb .loop
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret


; Full gesture revalidation at Enter, before/after slow PBKDF and at FS consume.
fc4_gesture:
    call fc4_guard
    cmp eax,1
    jne .bad
    cmp rdx,[rel fc4_epoch]
    jne .bad
    cmp byte [rel fc4_active],1
    jne .bad
    cmp byte [rel fc4_done],0
    jne .bad
    cmp byte [rel fc4_tab],1
    jne .bad
    cmp byte [rel wgt_focus_visible],1
    jne .bad
    mov eax,[rel fc4_ids+FC4_CONFIRM*4]
    cmp eax,[rel wgt_focus_id]
    jne .bad
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel fc4_tab_inj]
    jne .bad
    mov eax,[rel wm_zcounter]
    cmp eax,[rel fc4_tab_z]
    jne .bad
    call fc4_ok
    test eax,eax
    jnz .bad
    call fc4_widgets
    cmp eax,1
    jne .bad
    call fc4_geometry
    cmp rax,[rel fc4_tab_xy]
    jne .bad
    cmp rdx,[rel fc4_tab_fb]
    jne .bad
    mov eax,[rel fc4_ids+FC4_SECRET*4]
    cmp eax,[rel wgt_secret_owner]
    jne .bad
    mov rax,[rel wgt_secret_revision]
    cmp rax,-1
    je .bad
    cmp rax,[rel fc4_revision]
    jne .bad
    call wgt_secret_human
    cmp eax,1
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel fc4_expires]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; FS consumes first, before probe. Even a bad ID or context spends the decision.
; RDI=snapshot_id16 -> EAX=0 success / -1 refusal. No reusable password grant.
; Immutable callback registered directly with F1; no adoption bridge or grant.
fc4_decision_consume:
    push rbx
    mov rbx,rdi
    movzx eax,byte [rel fc4_decision]
    mov byte [rel fc4_decision],0
    cmp eax,1
    jne .bad
    cmp byte [rel fc4_operation],FC4_OP_FORMAT
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,[rbx]
    cmp rax,[rel fc4_snapshot]
    jne .bad
    mov rax,[rbx+8]
    cmp rax,[rel fc4_snapshot+8]
    jne .bad
    call fc4_gesture
    cmp eax,1
    jne .bad
    mov al,[rel fc4_kind]
    cmp al,[rel fc4_frozen]
    jne .bad
    mov eax,[rel fc4_label_len]
    cmp eax,[rel fc4_frozen+4]
    jne .bad
    mov rax,[rel fc4_label]
    cmp rax,[rel fc4_frozen+8]
    jne .bad
    mov eax,[rel fc4_label+8]
    cmp eax,[rel fc4_frozen+16]
    jne .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; Physical keyboard only. Pointer Confirm and Space never authorize.
fc4_key:
    cmp byte [rel fc4_active],1
    jne .chain
    push rdi
    push rax
    cmp byte [rel input_key_origin],KO_HUMAN
    je .origin
    mov byte [rel fc4_answer],2
    mov byte [rel fc4_tab],0
    call fc4_secret_clear
.origin:
    call fc4_scan
    cmp eax,-1
    je .other
    mov ecx,eax
    mov edi,[rsp+8]
    cmp edi,[rel wgt_count]
    jae .other
    push rcx
    call wgt_slot_ptr
    pop rcx
    cmp [rax+WGI_WIN],ecx
    jne .other
    pop rax
    pop rdi
    cmp byte [rel input_key_origin],KO_HUMAN
    jne .taken
    cmp eax,GUI_KEY_ESC
    je .deny
    cmp eax,GUI_KEY_TAB
    je .tab
    cmp eax,GUI_KEY_ENTER
    je .enter
    cmp edi,[rel fc4_ids+FC4_KIND*4]
    je .choice
    cmp edi,[rel fc4_ids+FC4_LABEL*4]
    je .label_edit
    cmp edi,[rel fc4_ids+FC4_SECRET*4]
    jne .taken
    cmp byte [rel fc4_done],0
    jne .taken
    mov byte [rel fc4_tab],0
    mov byte [rel fc4_answer],0
    ; Consume raw input here: it never traverses another card's filter.
    call wgt_secret_key
    jmp .taken
.choice:
    cmp byte [rel fc4_done],0
    jne .taken
    cmp eax,GUI_KEY_LEFT
    je .previous
    cmp eax,GUI_KEY_RIGHT
    jne .taken
    mov dl,[rel fc4_kind]
    inc dl
    cmp dl,4
    jbe .set_kind
    mov dl,1
    jmp .set_kind
.previous:
    mov dl,[rel fc4_kind]
    dec dl
    jnz .set_kind
    mov dl,4
.set_kind:
    mov [rel fc4_kind],dl
    mov edi,FC4_KIND
    jmp .edited
.label_edit:
    cmp byte [rel fc4_done],0
    jne .taken
    mov ecx,[rel fc4_label_len]
    cmp eax,GUI_KEY_BACKSPACE
    je .backspace
    cmp al,' '
    je .letter_ok
    cmp al,'_'
    je .letter_ok
    cmp al,'-'
    je .letter_ok
    cmp al,'0'
    jb .taken
    cmp al,'9'
    jbe .letter_ok
    cmp al,'A'
    jb .taken
    cmp al,'Z'
    jbe .letter_ok
    cmp al,'a'
    jb .taken
    cmp al,'z'
    ja .taken
    sub al,32
.letter_ok:
    cmp ecx,11
    jae .taken
    lea rdx,[rel fc4_label]
    mov [rdx+rcx],al
    inc ecx
    mov byte [rdx+rcx],0
    jmp .label_length
.backspace:
    test ecx,ecx
    jz .taken
    dec ecx
    lea rdx,[rel fc4_label]
    mov byte [rdx+rcx],0
.label_length:
    mov [rel fc4_label_len],ecx
    mov edi,FC4_LABEL
.edited:
    ; Field update helper expects EDI=row and preserves every callee-saved reg.
    call fc4_field_refresh
    mov byte [rel fc4_tab],0
    mov byte [rel fc4_answer],0
    call fc4_secret_clear
    call wmx_draw_all
    jmp .taken
.enter:
    cmp edi,[rel fc4_ids+FC4_DENY*4]
    je .deny
    cmp edi,[rel fc4_ids+FC4_CONFIRM*4]
    jne .taken
    call fc4_gesture
    cmp eax,1
    jne .disarm
    mov byte [rel fc4_answer],1
    jmp .taken
.tab:
    cmp byte [rel fc4_done],0
    jne .taken
    call fc4_ok
    test eax,eax
    jnz .disarm
    call fc4_widgets
    cmp eax,1
    jne .disarm
    call fc4_geometry
    mov [rel fc4_tab_xy],rax
    mov [rel fc4_tab_fb],rdx
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel fc4_tab_inj],eax
    mov eax,[rel wm_zcounter]
    mov [rel fc4_tab_z],eax
    mov rax,[rel wgt_secret_revision]
    mov [rel fc4_revision],rax
    mov byte [rel fc4_answer],0
    mov byte [rel fc4_tab],1
    mov byte [rel wgt_focus_visible],1
    mov eax,[rel fc4_ids+FC4_KIND*4]
    mov ecx,[rel fc4_ids+FC4_DENY*4]
    cmp ecx,[rel wgt_focus_id]
    je .focus
    mov eax,[rel fc4_ids+FC4_LABEL*4]
    mov ecx,[rel fc4_ids+FC4_KIND*4]
    cmp ecx,[rel wgt_focus_id]
    je .focus
    mov eax,[rel fc4_ids+FC4_SECRET*4]
    mov ecx,[rel fc4_ids+FC4_LABEL*4]
    cmp ecx,[rel wgt_focus_id]
    je .focus
    mov eax,[rel fc4_ids+FC4_DENY*4]
    mov ecx,[rel fc4_ids+FC4_SECRET*4]
    cmp ecx,[rel wgt_focus_id]
    jne .focus
    mov al,[rel fc4_kind]
    mov [rel fc4_frozen],al
    mov eax,[rel fc4_label_len]
    mov [rel fc4_frozen+4],eax
    mov rax,[rel fc4_label]
    mov [rel fc4_frozen+8],rax
    mov eax,[rel fc4_label+8]
    mov [rel fc4_frozen+16],eax
    mov eax,[rel fc4_ids+FC4_CONFIRM*4]
.focus:
    mov [rel wgt_focus_id],eax
    mov ecx,[rel fc4_slot]
    lea rdx,[rel wgt_focus_by_win]
    mov [rdx+rcx*4],eax
    call wmx_draw_all
    jmp .taken
.deny:
    mov byte [rel fc4_answer],2
    call fc4_secret_clear
    jmp .taken
.disarm:
    mov byte [rel fc4_tab],0
    mov byte [rel fc4_answer],0
.taken:
    mov eax,1
    ret
.other:
    pop rax
    pop rdi
.chain:
    mov rdx,[rel fc4_prev_filter]
    test rdx,rdx
    jz .none
    jmp rdx
.none:
    xor eax,eax
    ret

; Every pointer press spends arming, never accepts Confirm. Only human Deny.
fc4_click:
    cmp byte [rel fc4_active],1
    jne .chain
    mov byte [rel fc4_tab],0
    mov byte [rel fc4_answer],0
    cmp edi,[rel fc4_ids+FC4_CONFIRM*4]
    je .out
    cmp edi,[rel fc4_ids+FC4_DENY*4]
    jne .chain
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .out
    mov byte [rel fc4_answer],2
.out:
    ret
.chain:
    mov rax,[rel fc4_click_prev]
    test rax,rax
    jz .out
    jmp rax

format_confirm_tick:
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    call format_job_tick
    cmp byte [rel fc4_initialized],1
    jne .out
    cmp dword [rel fc4_slot],-1
    je .out
    call fc4_guard
    cmp eax,1
    jne fc4_close
    cmp rdx,[rel fc4_epoch]
    jne fc4_close
    cmp byte [rel fc4_active],1
    jne fc4_close
    call fc4_ok
    test eax,eax
    jnz fc4_close
    call fc4_widgets
    cmp eax,1
    jne fc4_close
    cmp byte [rel fc4_done],1
    je .answer                       ; consumed choice; job has its own fixed deadline
    call time_monotonic_now_us
    test rax,rax
    jz fc4_close
    cmp rax,[rel fc4_expires]
    jae fc4_close
.answer:
    movzx eax,byte [rel fc4_answer]
    mov byte [rel fc4_answer],0
    cmp eax,2
    je fc4_close
    cmp byte [rel fc4_done],1
    je .observe
    cmp eax,1
    jne .out
    call fc4_gesture
    cmp eax,1
    jne fc4_close
    movzx edi,byte [rel fc4_kind]
    lea rsi,[rel fc4_label]
    mov edx,[rel fc4_label_len]
    call fs_format_label_valid
    test eax,eax
    jnz fc4_close
    lea rdi,[rel wgt_secret_bytes]
    mov esi,[rel wgt_secret_len]
    call principal_local_password_recheck
    cmp rax,PRIN_OWNER
    jne .password_refused
    call fc4_gesture
    cmp eax,1
    jne fc4_close
    mov byte [rel fc4_operation],FC4_OP_FORMAT
    mov byte [rel fc4_decision],1
    lea rdi,[rel fc4_snapshot]
    movzx esi,byte [rel fc4_kind]
    lea rdx,[rel fc4_label]
    mov ecx,[rel fc4_label_len]
    call fs_format_begin              ; F1 spends before every probe/refusal
    mov byte [rel fc4_decision],0
    test eax,eax
    jnz .format_refused
    lea rdi,[rel fc4_snapshot]
    movzx esi,byte [rel fc4_kind]
    lea rdx,[rel fc4_label]
    mov ecx,[rel fc4_label_len]
    call format_job_start
    test eax,eax
    jnz .format_refused
    lea rsi,[rel fc4_running]
    jmp .completed
.format_refused:
    lea rsi,[rel fc4_refused]
.completed:
    mov byte [rel fc4_done],1
    jmp .status
.observe:
    lea rdi,[rel fc4_end]
    mov esi,64
    call format_job_snapshot
    cmp eax,32
    jne .out
    mov eax,[rel fc4_end]
    cmp eax,[rel fc4_job_phase]
    je .out
    mov [rel fc4_job_phase],eax
    dec eax
    cmp eax,7
    ja .out
    imul eax,44
    lea rsi,[rel fc4_progress_text]
    add rsi,rax
    jmp .status
.password_refused:
    call fc4_guard
    cmp eax,1
    jne fc4_close
    cmp rdx,[rel fc4_epoch]
    jne fc4_close
    call fc4_ok
    test eax,eax
    jnz fc4_close
    call fc4_widgets
    cmp eax,1
    jne fc4_close
    lea rsi,[rel fc4_bad_password]
.status:
    push rsi
    call fc4_secret_clear
    pop rsi
    mov byte [rel fc4_tab],0
    mov edi,[rel fc4_ids+FC4_STATUS*4]
    call wgt_set_text
    ; Refresh the native frozen status row, preserving all other immutable text.
    mov edi,[rel fc4_ids+FC4_STATUS*4]
    call wgt_slot_ptr
    lea rsi,[rax+WGI_VLEN]
    lea rdi,[rel fc4_texts+FC4_STATUS*44]
    mov edx,44
    call memcpy
    mov eax,[rel fc4_ids+FC4_DENY*4]
    mov [rel wgt_focus_id],eax
    mov ecx,[rel fc4_slot]
    lea rdx,[rel wgt_focus_by_win]
    mov [rdx+rcx*4],eax
    call wmx_draw_all
.out:
    ret

fc4_build:
    push rbx
    push r12
    push r13
    cmp dword [rel fb_width],FC4_WIDTH
    jb .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    cmp eax,FC4_HEIGHT
    jb .bad
    mov eax,[rel wgt_secret_type]
    cmp eax,-1
    je .bad
    mov [rel fc4_types+FC4_SECRET*4],eax
    lea rdi,[rel fc4_title]
    xor esi,esi
    xor edx,edx
    mov ecx,FC4_WIDTH
    mov r8d,FC4_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .bad
    mov r12d,eax
    mov [rel fc4_slot],eax
    mov [rel wm_focus],eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+r12*4]
    mov [rel fc4_gen],eax
    lea rcx,[rel wm_owner]
    mov qword [rcx+r12*8],WM_OWNER_CHROME
    mov edi,FC4_COUNT
    call wgt_reserve_run
    test eax,eax
    js .bad
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    lea rcx,[rel fc4_types]
    mov edi,[rcx+rbx*4]
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .bad_widgets
    lea rcx,[rel fc4_ids]
    mov [rcx+rbx*4],eax
    mov edi,eax
    call wgt_birth_lifetime
    test rax,rax
    jz .bad_widgets
    lea rcx,[rel fc4_births]
    mov [rcx+rbx*8],rax
    lea rcx,[rel fc4_ids]
    mov edi,[rcx+rbx*4]
    call wgt_slot_ptr
    mov r13,rax
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_EDIT],WGT_EDIT_ASCII
    mov dword [rax+WGI_BIND],0
    mov dword [rax+WGI_LAYER],0
    mov dword [rax+WGI_X],8
    mov dword [rax+WGI_W],268
    mov dword [rax+WGI_H],24
    mov eax,ebx
    shr eax,1
    imul eax,36
    add eax,28
    mov [r13+WGI_Y],eax
    test bl,1
    jz .layout
    mov dword [r13+WGI_X],284
.layout:
    cmp ebx,12
    jb .format
    mov eax,ebx
    sub eax,12
    imul eax,26
    add eax,248
    mov [r13+WGI_Y],eax
    mov dword [r13+WGI_X],8
    mov dword [r13+WGI_W],544
    cmp ebx,FC4_STATUS
    jb .format
    mov dword [r13+WGI_Y],396
    je .format
    mov dword [r13+WGI_W],268
    mov dword [r13+WGI_H],32
    mov dword [r13+WGI_Y],444
    cmp ebx,FC4_CONFIRM
    jne .format
    mov dword [r13+WGI_X],284
.format:
    mov edi,ebx
    call fc4_format
    mov rsi,rax
    lea rcx,[rel fc4_ids]
    mov edi,[rcx+rbx*4]
    call wgt_set_text
    lea rdi,[rel fc4_rects]
    mov eax,ebx
    shl eax,4
    add rdi,rax
    lea rsi,[r13+WGI_X]
    mov edx,16
    call memcpy
    lea rdi,[rel fc4_texts]
    imul eax,ebx,44
    add rdi,rax
    lea rsi,[r13+WGI_VLEN]
    mov edx,44
    call memcpy
    inc ebx
    cmp ebx,FC4_COUNT
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    mov eax,[rel fc4_ids+FC4_DENY*4]
    mov [rel wgt_focus_id],eax
    lea rcx,[rel wgt_focus_by_win]
    mov [rcx+r12*4],eax
    mov byte [rel wgt_focus_visible],1
    xor eax,eax
    jmp .out
.bad_widgets:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; All display text is native and bounded to the kit's 31-byte inline limit.
fc4_field_refresh:
    push rbx
    mov ebx,edi
    call fc4_format
    mov rsi,rax
    lea rcx,[rel fc4_ids]
    mov edi,[rcx+rbx*4]
    call wgt_set_text
    lea rcx,[rel fc4_ids]
    mov edi,[rcx+rbx*4]
    call wgt_slot_ptr
    lea rsi,[rax+WGI_VLEN]
    lea rdi,[rel fc4_texts]
    imul edx,ebx,44
    add rdi,rdx
    mov edx,44
    call memcpy
    pop rbx
    ret

fc4_format:
    cmp edi,1
    jne .disk
    lea rax,[rel fc4_snapshot+16]
    ret
.disk:
    cmp edi,3
    jne .part
    mov rdi,[rel fc4_snapshot+48]
    jmp .decimal
.part:
    cmp edi,7
    jne .number
    mov rdi,[rel fc4_snapshot+56]
    jmp .decimal
.number:
    cmp edi,5
    jne .kind
    lea rax,[rel fc4_line]
    mov dword [rax],'GPT '
    cmp byte [rel fc4_snapshot+64],2
    je .gpt
    mov dword [rax],'MBR '
.gpt:
    movzx edi,byte [rel fc4_snapshot+65]
    lea rsi,[rel fc4_line+4]
    call fmt_dec
    lea rax,[rel fc4_line]
    ret
.kind:
    cmp edi,FC4_KIND
    jne .label
    movzx eax,byte [rel fc4_kind]
    dec eax
    cmp eax,3
    ja .static
    lea rdx,[rel fc4_kinds]
    mov rax,[rdx+rax*8]
    add rax,rdx
    ret
.label:
    cmp edi,FC4_LABEL
    jne .type
    lea rdi,[rel fc4_line]
    mov dword [rdi],'Labe'
    mov word [rdi+4],'l:'
    mov byte [rdi+6],' '
    add rdi,7
    lea rsi,[rel fc4_label]
    mov ecx,12
    rep movsb
    lea rax,[rel fc4_line]
    ret
.type:
    cmp edi,9
    jne .static
    cmp byte [rel fc4_snapshot+64],1
    jne .gpt_type
    movzx edi,byte [rel fc4_snapshot+67]
    jmp .decimal
.gpt_type:
    lea rax,[rel fc4_type_basic]
    cmp byte [rel fc4_snapshot+68],1
    je .out
    lea rax,[rel fc4_type_linux]
.out:
    ret
.decimal:
    lea rsi,[rel fc4_line]
    call fmt_dec
    lea rax,[rel fc4_line]
    ret
.static:
    lea rdx,[rel fc4_labels]
    mov rax,[rdx+rdi*8]
    add rax,rdx
    ret

fc4_title: db 'Format removable partition',0
fc4_device: db 'Device',0
fc4_disk: db 'Disk size (bytes)',0
fc4_partition: db 'Partition',0
fc4_size: db 'Partition size (bytes)',0
fc4_type: db 'Partition type (kept)',0
fc4_type_basic: db 'Basic Data',0
fc4_type_linux: db 'Linux filesystem',0
fc4_password: db 'Owner password',0
fc4_warning_1: db 'Erases ALL partition data.',0
fc4_warning_2: db 'Partition type is kept.',0
fc4_warning_3: db 'Tab: format, label, password.',0
fc4_note: db 'Then Tab, Enter to erase.',0
fc4_deny: db 'Deny',0
fc4_confirm: db 'Erase once',0
fc4_empty: db 0
fc4_bad_password: db 'Password refused. Try again.',0
fc4_running: db 'Queued. Deny to stop.',0
fc4_progress_text:
    db 'Queued. Deny to stop.',0
    times 22 db 0
    db 'Formatting. Deny to stop.',0
    times 18 db 0
    db 'Finishing. Deny to stop.',0
    times 19 db 0
    db 'Format completed.',0
    times 26 db 0
    db 'No format started.',0
    times 25 db 0
    db 'Uncertain. Check the device.',0
    times 15 db 0
    db 'Device quarantined. Stop use.',0
    times 14 db 0
    db 'Stopping. Device held.',0
    times 21 db 0
fc4_refused: db 'Not formatted. Try later.',0
fc4_fat32: db 'FAT32 (Left/Right to choose)',0
fc4_exfat: db 'exFAT (Left/Right to choose)',0
fc4_ntfs: db 'NTFS (Left/Right to choose)',0
fc4_ext4: db 'ext4 (Left/Right to choose)',0
align 8
fc4_kinds: dq fc4_fat32-fc4_kinds,fc4_exfat-fc4_kinds,fc4_ntfs-fc4_kinds,fc4_ext4-fc4_kinds
fc4_labels: dq fc4_device-fc4_labels,fc4_empty-fc4_labels,fc4_disk-fc4_labels,fc4_empty-fc4_labels,fc4_partition-fc4_labels,fc4_empty-fc4_labels,fc4_size-fc4_labels,fc4_empty-fc4_labels,fc4_type-fc4_labels,fc4_empty-fc4_labels,fc4_password-fc4_labels,fc4_empty-fc4_labels,fc4_empty-fc4_labels,fc4_empty-fc4_labels,fc4_warning_1-fc4_labels,fc4_warning_2-fc4_labels,fc4_warning_3-fc4_labels,fc4_note-fc4_labels,fc4_deny-fc4_labels,fc4_confirm-fc4_labels

%include "core/abi/wdata.inc"
%macro WDATA_format_confirm 0
align 8
fc4_prev_filter: dq 0
fc4_click_prev: dq 0
fc4_epoch: dq 0
fc4_expires: dq 0
fc4_tab_xy: dq 0
fc4_tab_fb: dq 0
fc4_revision: dq 0
fc4_slot: dd -1
fc4_gen: dd 0
fc4_tab_z: dd 0
fc4_tab_inj: dd 0
fc4_ids: times FC4_COUNT dd -1
fc4_births: times FC4_COUNT dq 0
fc4_types: dd 2,2,2,2,2,2,2,2,2,2,2,-1,0,1,2,2,2,2,0,0
fc4_initialized: db 0
fc4_active: db 0
fc4_tab: db 0
fc4_answer: db 0
fc4_job_phase: dd 0
fc4_done: db 0
fc4_decision: db 0
fc4_operation: db 0
fc4_kind: db 0
align 4
fc4_label_len: dd 0
%endmacro
WDATA_DEFER WDATA_format_confirm
%macro WDATA_format_confirm_bss 0
alignb 8
fc4_private:
fc4_frozen: resb 24
fc4_label: resb 12
fc4_snapshot: resb 96
fc4_end: resb 64
fc4_private_end:
fc4_line: resb 32
fc4_rects: resb FC4_COUNT*16
fc4_texts: resb FC4_COUNT*44
%endmacro
WDATA_BSS_DEFER WDATA_format_confirm_bss
