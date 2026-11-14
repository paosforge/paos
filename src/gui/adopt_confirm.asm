;; MODULE gui/adopt_confirm
;; LAYER 6
;; PURPOSE Native owner password and one-use local partition adoption decision.
;; EXPORTS adopt_confirm_init, adopt_confirm_offer, adopt_confirm_tick, adopt_confirm_wipe, adopt_confirm_retire
;; IMPORTS sec/adopt_decision, gui/calendar, fs/vol_owner, sec/session, sec/principal, core/smp, core/time, core/lib/mem, core/lib/fmt, svc/command, gui/widget, gui/window_mgmt, gui/window, gui/wm_pointer, gui/start_programs, dev/input/ps2, boot/gop
;; OWNER saga:fs
;; CONTEXT: bsp_only
; FS108103: display facts are a read-only native snapshot, never authority.
; A HUMAN Tab to Confirm and Enter, plus a fresh owner password, publishes a
; one-use (snapshot, epoch, ADOPT_LOCAL) decision only for the synchronous FS
; consumer. Every consume spends it, including refusals. No command getter,
; wire method, reusable password success or ambient SPECIAL capability.
AD3_COUNT equ 20
AD3_SECRET equ 11
AD3_DENY equ 18
AD3_CONFIRM equ 19
AD3_WIDTH equ 560
AD3_HEIGHT equ 500
AD3_STATUS equ 17
AD3_TTL_US equ 120000000
AD3_OP_ADOPT_LOCAL equ 1

adopt_confirm_init:
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    cmp byte [rel ad3_initialized],0
    jne .out
    lea rdi,[rel adopt_confirm_wipe]
    call session_shell_register_adopt_wipe
    cmp eax,1
    jne .out
    lea rdi,[rel ad3_decision_consume]
    call adopt_decision_register
    cmp eax,1
    jne .out
    mov rax,[rel wgt_key_filter]
    mov [rel ad3_prev_filter],rax
    lea rax,[rel ad3_key]
    mov [rel wgt_key_filter],rax
    mov rax,[rel wgt_click_hook]
    mov [rel ad3_click_prev],rax
    lea rax,[rel ad3_click]
    mov [rel wgt_click_hook],rax
    mov byte [rel ad3_initialized],1
.out:
    pop rbx
    ret

; Read-only offer from Explorer's pinned mount selection on idle BSP.
; EDI=mount -> EAX=0 opened, -1 refused. The FS snapshot proves eligibility.
adopt_confirm_offer:
    push rbx
    mov ebx,edi
    call ad3_guard
    cmp eax,1
    jne .bad
    cmp byte [rel ad3_initialized],1
    jne .bad
    cmp byte [rel ad3_active],0
    jne .bad
    cmp dword [rel ad3_slot],-1
    jne .bad
    cmp dword [rel wgt_secret_owner],-1
    jne .bad
    mov [rel ad3_epoch],rdx
    mov [rel ad3_mount],ebx
    lea rsi,[rel ad3_snapshot]
    mov edi,ebx
    call vol_owner_local_snapshot
    test eax,eax
    jnz .fail
    call ad3_snapshot_valid
    test eax,eax
    jnz .fail
    call time_monotonic_now_us
    test rax,rax
    jz .fail
    add rax,AD3_TTL_US
    jc .fail
    mov [rel ad3_expires],rax
    call ad3_guard
    cmp eax,1
    jne .fail
    cmp rdx,[rel ad3_epoch]
    jne .fail
    call ad3_build
    test eax,eax
    jnz .fail
    mov byte [rel ad3_active],1
    call wmx_draw_all
    xor eax,eax
    pop rbx
    ret
.fail:
    call ad3_close
.bad:
    mov eax,-1
    pop rbx
    ret

ad3_guard:
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
ad3_snapshot_valid:
    mov rax,[rel ad3_snapshot]
    or rax,[rel ad3_snapshot+8]
    jz .bad
    mov rax,[rel ad3_snapshot+48]
    test rax,rax
    jz .bad
    mov rdx,[rel ad3_snapshot+56]
    test rdx,rdx
    jz .bad
    cmp rdx,rax
    ja .bad
    movzx eax,byte [rel ad3_snapshot+64]
    dec eax
    cmp eax,1
    ja .bad
    cmp byte [rel ad3_snapshot+65],0
    je .bad
    cmp word [rel ad3_snapshot+66],0
    jne .bad
    mov rax,[rel ad3_snapshot+80]
    or rax,[rel ad3_snapshot+88]
    jnz .bad
    xor ecx,ecx
    lea rdx,[rel ad3_snapshot+16]
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
ad3_secret_clear:
    mov edi,[rel ad3_ids+AD3_SECRET*4]
    cmp edi,[rel wgt_secret_owner]
    jne .out
    call wgt_birth_lifetime
    lea rcx,[rel ad3_births]
    cmp rax,[rcx+AD3_SECRET*8]
    jne .out
    test rax,rax
    jz .out
    call wgt_secret_clear
.out:
    ret

; Session's synchronous eraser. Both native snapshots and the original editor
; are cleared before authority callbacks. No IO, workspace or paint.
adopt_confirm_wipe:
    mov byte [rel ad3_decision],0
    mov byte [rel ad3_active],0
    mov byte [rel ad3_tab],0
    mov byte [rel ad3_answer],0
    mov byte [rel ad3_done],0
    mov qword [rel ad3_epoch],0
    call ad3_secret_clear
    call vol_owner_local_cancel        ; FS memory-only native slot eraser
    lea rdi,[rel ad3_snapshot]
    xor eax,eax
    mov ecx,96
    rep stosb
    ret

; WM pre-retirement hook, before widgets are freed; no recursive close.
adopt_confirm_retire:
    push rbx
    mov ebx,edi
    call ad3_scan
    cmp eax,-1
    je .out
    cmp eax,ebx
    jne .out
    call adopt_confirm_wipe
    mov dword [rel ad3_slot],-1
.out:
    pop rbx
    ret

ad3_close:
    call adopt_confirm_wipe
    call ad3_scan
    mov dword [rel ad3_slot],-1
    cmp eax,-1
    je .out
    mov edi,eax
    call wmx_close_slot
.out:
    ret

ad3_scan:
    mov eax, [rel ad3_slot]
    cmp eax, WM_MAX
    jae .bad
    lea rcx, [rel wm_title]
    lea rdx, [rel ad3_title]
    cmp [rcx + rax*8], rdx
    jne .bad
    lea rcx, [rel wm_owner]
    cmp qword [rcx + rax*8], WM_OWNER_CHROME
    jne .bad
    lea rcx, [rel wm_gen]
    mov edx, [rel ad3_gen]
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

ad3_ok:
    call ad3_scan
    cmp eax, -1
    je .bad
    mov edx, eax
    cmp eax, [rel wm_focus]
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rdx*4], WM_VISIBLE
    jne .bad
    lea rcx, [rel wm_w]
    cmp dword [rcx + rdx*4], AD3_WIDTH
    jne .bad
    lea rcx, [rel wm_h]
    cmp dword [rcx + rdx*4], AD3_HEIGHT
    jne .bad
    lea rcx, [rel wm_x]
    mov r8d, [rcx + rdx*4]
    test r8d, r8d
    js .bad
    lea rcx, [rel wm_y]
    mov r9d, [rcx + rdx*4]
    test r9d, r9d
    js .bad
    lea r10d, [r8d + AD3_WIDTH]
    lea r11d, [r9d + AD3_HEIGHT]
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
ad3_geometry:
    mov edx, [rel ad3_slot]
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

ad3_widgets:
    push rbx
    xor ebx,ebx
.loop:
    lea rax,[rel ad3_ids]
    mov edi,[rax+rbx*4]
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    lea rcx,[rel ad3_births]
    cmp rax,[rcx+rbx*8]
    jne .bad
    lea rax,[rel ad3_ids]
    mov edi,[rax+rbx*4]
    call wgt_slot_ptr
    mov ecx,[rel ad3_slot]
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
    lea rcx,[rel ad3_types]
    mov ecx,[rcx+rbx*4]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .bad
    ; Native card geometry is fixed: moves/resizes must never leave labels apart.
    lea rcx,[rel ad3_rects]
    mov edx,ebx
    shl edx,4
    add rcx,rdx
    mov rdx,[rax+WGI_X]
    cmp rdx,[rcx]
    jne .bad
    mov rdx,[rax+WGI_W]
    cmp rdx,[rcx+8]
    jne .bad
    cmp ebx,AD3_SECRET
    je .next
    lea rsi,[rax+WGI_VLEN]
    lea rdi,[rel ad3_texts]
    imul edx,ebx,44
    add rdi,rdx
    mov ecx,11
    cld
    repe cmpsd
    jne .bad
.next:
    inc ebx
    cmp ebx,AD3_COUNT
    jb .loop
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret


; Full gesture revalidation at Enter, before/after slow PBKDF and at FS consume.
ad3_gesture:
    call ad3_guard
    cmp eax,1
    jne .bad
    cmp rdx,[rel ad3_epoch]
    jne .bad
    cmp byte [rel ad3_active],1
    jne .bad
    cmp byte [rel ad3_done],0
    jne .bad
    cmp byte [rel ad3_tab],1
    jne .bad
    cmp byte [rel wgt_focus_visible],1
    jne .bad
    mov eax,[rel ad3_ids+AD3_CONFIRM*4]
    cmp eax,[rel wgt_focus_id]
    jne .bad
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel ad3_tab_inj]
    jne .bad
    mov eax,[rel wm_zcounter]
    cmp eax,[rel ad3_tab_z]
    jne .bad
    call ad3_ok
    test eax,eax
    jnz .bad
    call ad3_widgets
    cmp eax,1
    jne .bad
    call ad3_geometry
    cmp rax,[rel ad3_tab_xy]
    jne .bad
    cmp rdx,[rel ad3_tab_fb]
    jne .bad
    mov eax,[rel ad3_ids+AD3_SECRET*4]
    cmp eax,[rel wgt_secret_owner]
    jne .bad
    mov rax,[rel wgt_secret_revision]
    cmp rax,-1
    je .bad
    cmp rax,[rel ad3_revision]
    jne .bad
    call wgt_secret_human
    cmp eax,1
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel ad3_expires]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; FS consumes first, before probe. Even a bad ID or context spends the decision.
; RDI=snapshot_id16 -> EAX=0 success / -1 refusal. No reusable password grant.
; Immutable callback from sec/adopt_decision; FS imports that module only.
ad3_decision_consume:
    push rbx
    mov rbx,rdi
    movzx eax,byte [rel ad3_decision]
    mov byte [rel ad3_decision],0
    cmp eax,1
    jne .bad
    cmp byte [rel ad3_operation],AD3_OP_ADOPT_LOCAL
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,[rbx]
    cmp rax,[rel ad3_snapshot]
    jne .bad
    mov rax,[rbx+8]
    cmp rax,[rel ad3_snapshot+8]
    jne .bad
    call ad3_gesture
    cmp eax,1
    jne .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; Physical keyboard only. Pointer Confirm and Space never authorize.
ad3_key:
    cmp byte [rel ad3_active],1
    jne .chain
    push rdi
    push rax
    cmp byte [rel input_key_origin],KO_HUMAN
    je .origin
    mov byte [rel ad3_answer],2
    mov byte [rel ad3_tab],0
    call ad3_secret_clear
.origin:
    call ad3_scan
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
    cmp edi,[rel ad3_ids+AD3_SECRET*4]
    jne .taken
    cmp byte [rel ad3_done],0
    jne .taken
    mov byte [rel ad3_tab],0
    mov byte [rel ad3_answer],0
    ; Consume raw input here: it never traverses another card's filter.
    call wgt_secret_key
    jmp .taken
.enter:
    cmp edi,[rel ad3_ids+AD3_DENY*4]
    je .deny
    cmp edi,[rel ad3_ids+AD3_CONFIRM*4]
    jne .taken
    call ad3_gesture
    cmp eax,1
    jne .disarm
    mov byte [rel ad3_answer],1
    jmp .taken
.tab:
    cmp byte [rel ad3_done],0
    jne .taken
    call ad3_ok
    test eax,eax
    jnz .disarm
    call ad3_widgets
    cmp eax,1
    jne .disarm
    call ad3_geometry
    mov [rel ad3_tab_xy],rax
    mov [rel ad3_tab_fb],rdx
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel ad3_tab_inj],eax
    mov eax,[rel wm_zcounter]
    mov [rel ad3_tab_z],eax
    mov rax,[rel wgt_secret_revision]
    mov [rel ad3_revision],rax
    mov byte [rel ad3_answer],0
    mov byte [rel ad3_tab],1
    mov byte [rel wgt_focus_visible],1
    mov eax,[rel ad3_ids+AD3_SECRET*4]
    cmp eax,[rel wgt_focus_id]
    jne .from_deny
    mov eax,[rel ad3_ids+AD3_CONFIRM*4]
    jmp .focus
.from_deny:
    mov ecx,[rel ad3_ids+AD3_CONFIRM*4]
    cmp ecx,[rel wgt_focus_id]
    jne .focus
    mov eax,[rel ad3_ids+AD3_DENY*4]
.focus:
    mov [rel wgt_focus_id],eax
    mov ecx,[rel ad3_slot]
    lea rdx,[rel wgt_focus_by_win]
    mov [rdx+rcx*4],eax
    call wmx_draw_all
    jmp .taken
.deny:
    mov byte [rel ad3_answer],2
    call ad3_secret_clear
    jmp .taken
.disarm:
    mov byte [rel ad3_tab],0
    mov byte [rel ad3_answer],0
.taken:
    mov eax,1
    ret
.other:
    pop rax
    pop rdi
.chain:
    mov rdx,[rel ad3_prev_filter]
    test rdx,rdx
    jz .none
    jmp rdx
.none:
    xor eax,eax
    ret

; Every pointer press spends arming, never accepts Confirm. Only human Deny.
ad3_click:
    cmp byte [rel ad3_active],1
    jne .chain
    mov byte [rel ad3_tab],0
    mov byte [rel ad3_answer],0
    cmp edi,[rel ad3_ids+AD3_CONFIRM*4]
    je .out
    cmp edi,[rel ad3_ids+AD3_DENY*4]
    jne .chain
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .out
    mov byte [rel ad3_answer],2
.out:
    ret
.chain:
    mov rax,[rel ad3_click_prev]
    test rax,rax
    jz .out
    jmp rax

adopt_confirm_tick:
    cmp byte [rel ad3_initialized],1
    jne .out
    cmp dword [rel ad3_slot],-1
    je .out
    call ad3_guard
    cmp eax,1
    jne ad3_close
    cmp rdx,[rel ad3_epoch]
    jne ad3_close
    cmp byte [rel ad3_active],1
    jne ad3_close
    call ad3_ok
    test eax,eax
    jnz ad3_close
    call ad3_widgets
    cmp eax,1
    jne ad3_close
    call time_monotonic_now_us
    test rax,rax
    jz ad3_close
    cmp rax,[rel ad3_expires]
    jae ad3_close
    movzx eax,byte [rel ad3_answer]
    mov byte [rel ad3_answer],0
    cmp eax,2
    je ad3_close
    cmp eax,1
    jne .out
    call ad3_gesture
    cmp eax,1
    jne ad3_close
    lea rdi,[rel wgt_secret_bytes]
    mov esi,[rel wgt_secret_len]
    call principal_local_password_recheck
    cmp rax,PRIN_OWNER
    jne .password_refused
    call ad3_gesture
    cmp eax,1
    jne ad3_close
    mov byte [rel ad3_operation],AD3_OP_ADOPT_LOCAL
    mov byte [rel ad3_decision],1
    mov edi,[rel ad3_mount]
    lea rsi,[rel ad3_snapshot]
    call vol_owner_local_adopt         ; consumes decision, then re-proves live FS
    mov byte [rel ad3_decision],0      ; clear even if provider refused before consume
    test eax,eax
    jnz .adopt_refused
    lea rsi,[rel ad3_success]
    jmp .completed
.adopt_refused:
    lea rsi,[rel ad3_refused]
.completed:
    mov byte [rel ad3_done],1
    jmp .status
.password_refused:
    call ad3_guard
    cmp eax,1
    jne ad3_close
    cmp rdx,[rel ad3_epoch]
    jne ad3_close
    call ad3_ok
    test eax,eax
    jnz ad3_close
    call ad3_widgets
    cmp eax,1
    jne ad3_close
    lea rsi,[rel ad3_bad_password]
.status:
    push rsi
    call ad3_secret_clear
    pop rsi
    mov byte [rel ad3_tab],0
    mov edi,[rel ad3_ids+AD3_STATUS*4]
    call wgt_set_text
    ; Refresh the native frozen status row, preserving all other immutable text.
    mov edi,[rel ad3_ids+AD3_STATUS*4]
    call wgt_slot_ptr
    lea rsi,[rax+WGI_VLEN]
    lea rdi,[rel ad3_texts+AD3_STATUS*44]
    mov edx,44
    call memcpy
    mov eax,[rel ad3_ids+AD3_DENY*4]
    mov [rel wgt_focus_id],eax
    mov ecx,[rel ad3_slot]
    lea rdx,[rel wgt_focus_by_win]
    mov [rdx+rcx*4],eax
    call wmx_draw_all
.out:
    ret

ad3_build:
    push rbx
    push r12
    push r13
    cmp dword [rel fb_width],AD3_WIDTH
    jb .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    cmp eax,AD3_HEIGHT
    jb .bad
    mov eax,[rel wgt_secret_type]
    cmp eax,-1
    je .bad
    mov [rel ad3_types+AD3_SECRET*4],eax
    lea rdi,[rel ad3_title]
    xor esi,esi
    xor edx,edx
    mov ecx,AD3_WIDTH
    mov r8d,AD3_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .bad
    mov r12d,eax
    mov [rel ad3_slot],eax
    mov [rel wm_focus],eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+r12*4]
    mov [rel ad3_gen],eax
    lea rcx,[rel wm_owner]
    mov qword [rcx+r12*8],WM_OWNER_CHROME
    mov edi,AD3_COUNT
    call wgt_reserve_run
    test eax,eax
    js .bad
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    lea rcx,[rel ad3_types]
    mov edi,[rcx+rbx*4]
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .bad_widgets
    lea rcx,[rel ad3_ids]
    mov [rcx+rbx*4],eax
    mov edi,eax
    call wgt_birth_lifetime
    test rax,rax
    jz .bad_widgets
    lea rcx,[rel ad3_births]
    mov [rcx+rbx*8],rax
    lea rcx,[rel ad3_ids]
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
    cmp ebx,AD3_STATUS
    jb .format
    mov dword [r13+WGI_Y],396
    je .format
    mov dword [r13+WGI_W],268
    mov dword [r13+WGI_H],32
    mov dword [r13+WGI_Y],444
    cmp ebx,AD3_CONFIRM
    jne .format
    mov dword [r13+WGI_X],284
.format:
    mov edi,ebx
    call ad3_format
    mov rsi,rax
    lea rcx,[rel ad3_ids]
    mov edi,[rcx+rbx*4]
    call wgt_set_text
    lea rdi,[rel ad3_rects]
    mov eax,ebx
    shl eax,4
    add rdi,rax
    lea rsi,[r13+WGI_X]
    mov edx,16
    call memcpy
    lea rdi,[rel ad3_texts]
    imul eax,ebx,44
    add rdi,rax
    lea rsi,[r13+WGI_VLEN]
    mov edx,44
    call memcpy
    inc ebx
    cmp ebx,AD3_COUNT
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    mov eax,[rel ad3_ids+AD3_DENY*4]
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
ad3_format:
    cmp edi,1
    jne .disk
    lea rax,[rel ad3_snapshot+16]
    ret
.disk:
    cmp edi,3
    jne .part
    mov rdi,[rel ad3_snapshot+48]
    jmp .decimal
.part:
    cmp edi,7
    jne .number
    mov rdi,[rel ad3_snapshot+56]
    jmp .decimal
.number:
    cmp edi,9
    je .label
    cmp edi,5
    jne .static
    lea rax,[rel ad3_line]
    mov dword [rax],'GPT '
    cmp byte [rel ad3_snapshot+64],2 ; FS VO_SCHEME_GPT (1 is MBR)
    je .gpt
    mov dword [rax],'MBR '
.gpt:
    movzx edi,byte [rel ad3_snapshot+65]
    lea rsi,[rel ad3_line+4]
    call fmt_dec
    lea rax,[rel ad3_line]
    ret
.label:
    lea rdi,[rel ad3_line]
    mov byte [rdi],'"'
    inc rdi
    lea rsi,[rel ad3_snapshot+68]
    mov ecx,11
.label_byte:
    lodsb
    cmp al,0x20
    jb .replace
    cmp al,0x7e
    jbe .label_store
.replace:
    mov al,'?'
.label_store:
    stosb
    loop .label_byte
    mov byte [rdi],'"'
    mov byte [rdi+1],0
    lea rax,[rel ad3_line]
    ret
.decimal:
    lea rsi,[rel ad3_line]
    call fmt_dec
    lea rax,[rel ad3_line]
    ret
.static:
    lea rdx,[rel ad3_labels]
    mov rax,[rdx+rdi*8]
    add rax,rdx
    ret

ad3_title: db 'Use for PaOS files',0
ad3_device: db 'Device',0
ad3_disk: db 'Disk size (bytes)',0
ad3_partition: db 'Partition',0
ad3_size: db 'Partition size (bytes)',0
ad3_label: db 'Volume label (media)',0
ad3_password: db 'Owner password',0
ad3_warning_1: db 'Files are not encrypted.',0
ad3_warning_2: db 'Other systems on this PC can',0
ad3_warning_3: db 'read and change these files.',0
ad3_warning_4: db 'A volume with files needs the',0
ad3_warning_5: db 'owner key.',0
ad3_note: db 'Tab, password, Tab, Enter.',0
ad3_deny: db 'Deny',0
ad3_confirm: db 'Use once',0
ad3_empty: db 0
ad3_bad_password: db 'Password refused. Try again.',0
ad3_success: db 'Ready for PaOS files.',0
ad3_refused: db 'Not adopted. Reopen to retry.',0
align 8
ad3_labels: dq ad3_device-ad3_labels,ad3_empty-ad3_labels,ad3_disk-ad3_labels,ad3_empty-ad3_labels,ad3_partition-ad3_labels,ad3_empty-ad3_labels,ad3_size-ad3_labels,ad3_empty-ad3_labels,ad3_label-ad3_labels,ad3_empty-ad3_labels,ad3_password-ad3_labels,ad3_empty-ad3_labels,ad3_warning_1-ad3_labels,ad3_warning_2-ad3_labels,ad3_warning_3-ad3_labels,ad3_warning_4-ad3_labels,ad3_warning_5-ad3_labels,ad3_note-ad3_labels,ad3_deny-ad3_labels,ad3_confirm-ad3_labels

%include "core/abi/wdata.inc"
%macro WDATA_adopt_confirm 0
align 8
ad3_prev_filter: dq 0
ad3_click_prev: dq 0
ad3_epoch: dq 0
ad3_expires: dq 0
ad3_tab_xy: dq 0
ad3_tab_fb: dq 0
ad3_revision: dq 0
ad3_slot: dd -1
ad3_gen: dd 0
ad3_mount: dd -1
ad3_tab_z: dd 0
ad3_tab_inj: dd 0
ad3_ids: times AD3_COUNT dd -1
ad3_births: times AD3_COUNT dq 0
ad3_types: dd 2,2,2,2,2,2,2,2,2,2,2,-1,2,2,2,2,2,2,0,0
ad3_initialized: db 0
ad3_active: db 0
ad3_tab: db 0
ad3_answer: db 0
ad3_done: db 0
ad3_decision: db 0
ad3_operation: db 0
%endmacro
WDATA_DEFER WDATA_adopt_confirm
%macro WDATA_adopt_confirm_bss 0
alignb 8
ad3_snapshot: resb 96
ad3_line: resb 32
ad3_rects: resb AD3_COUNT*16
ad3_texts: resb AD3_COUNT*44
%endmacro
WDATA_BSS_DEFER WDATA_adopt_confirm_bss
