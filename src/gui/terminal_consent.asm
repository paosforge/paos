;; MODULE gui/terminal_consent
;; LAYER 6
;; PURPOSE Native Terminal B consent, continuous read notice, exact physical approvals.
;; EXPORTS terminal_consent_configure, terminal_consent_init, terminal_consent_tick, terminal_consent_present, terminal_consent_visible, terminal_consent_draw, terminal_consent_press
;; IMPORTS gui/compose_job, gui/present_idle, gui/window_mgmt, gui/widget, gui/window, gui/taskbar, gui/wm_pointer, gui/calendar, gui/snapshot, gui/start_programs, sec/session, sec/principal, svc/command, svc/command_auth, dev/input/ps2, boot/gop, core/time
;; CAPS CAP_GUI
;; OWNER saga:live_terminal_consent
; Codex / rc-live-claude. No executor, policy store or guest-callable approval.
%include "gui/terminal_consent.inc"
TC_WIDTH equ 600
TC_HEIGHT equ 432
TC_ROWS equ 36                 ; 12 visual lines, 3 adjacent 24-byte labels
TC_LINES equ 132
TC_LINE_BYTES equ 73
TC_PREV equ 36
TC_NEXT equ 37
TC_DENY equ 38
TC_APPROVE equ 39
TC_REVOKE equ 40
TC_FIRST_SCOPE equ 41
TC_WIDGETS equ 47

; Native init only. All seven policy adapters are mandatory, copied once.
terminal_consent_configure:
    cmp byte [rel tc_configured],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    test rdi,rdi
    jz .bad
    mov rsi,rdi
    mov ecx,7
.check:
    cmp qword [rsi],0
    je .bad
    add rsi,8
    loop .check
    mov rsi,rdi
    lea rdi,[rel tc_callbacks]
    mov ecx,7
    cld
    rep movsq
    mov byte [rel tc_configured],1
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

terminal_consent_init:
    cmp byte [rel tc_initialized],0
    jne .out
    mov rax,[rel wgt_click_hook]
    mov [rel tc_prev_click],rax
    lea rax,[rel tc_click]
    mov [rel wgt_click_hook],rax
    mov rax,[rel wm_pointer_note_hook]
    mov [rel tc_prev_note],rax
    lea rax,[rel tc_pointer_note]
    mov [rel wm_pointer_note_hook],rax
    mov byte [rel tc_initialized],1
.out:
    ret

; Fresh native policy state; display caching never creates authority.
tc_refresh:
    cmp byte [rel tc_configured],1
    jne .bad
    cmp byte [rel tc_query_busy],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    mov byte [rel tc_query_busy],1
    lea rdi,[rel tc_state]
    xor eax,eax
    mov ecx,TC_STATE_BYTES/8
    rep stosq
    lea rdi,[rel tc_state]
    call [rel tc_callbacks+TC_CB_STATE]
    mov byte [rel tc_query_busy],0
    cmp eax,1
    jne .bad
    cmp qword [rel tc_state+TC_ST_VERSION],1
    jne .bad
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .bad
    cmp rax,[rel tc_state+TC_ST_SESSION]
    jne .bad
    cmp qword [rel tc_state+TC_ST_POLICY],0
    je .bad
    cmp qword [rel tc_state+TC_ST_COUNT],8
    ja .bad
    cmp qword [rel tc_state+TC_ST_SAVED],2
    ja .bad
    cmp qword [rel tc_state+40],0
    jne .bad
    cmp qword [rel tc_state+48],0
    jne .bad
    cmp qword [rel tc_state+56],0
    jne .bad
    mov eax,1
    ret
.bad:
    mov qword [rel tc_present_generation],0
    mov byte [rel tc_armed],0
    xor eax,eax
    ret

tc_display_ok:
    cmp qword [rel fb_base],0
    je .bad
    cmp dword [rel fb_width],192
    jb .bad
    cmp dword [rel fb_height],TASKBAR_H
    jb .bad
    cmp byte [rel dpms_blanked],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    mov rax,[rel fb_base]
    cmp rax,[rel fb_shadow_base]
    jne .yes
    cmp qword [rel fb_scanout_base],0
    je .bad
.yes:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Persistent notice, never a timer. Taskbar paint doesn't itself release bytes.
terminal_consent_draw:
    call tc_refresh
    test eax,eax
    jz .out
    call tc_display_ok
    test eax,eax
    jz .out
    lea rdi,[rel tc_tray_idle]
    cmp qword [rel tc_state+TC_ST_COUNT],0
    jne .reading
    ; Keep the original app/driver read notice visible while its timer lives.
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel snapshot_native_indicator_session]
    jne .idle
    call time_monotonic_now_us
    cmp rax,[rel snapshot_native_indicator_until]
    jb .out
.idle:
    lea rdi,[rel tc_tray_idle]
    jmp .paint
.reading:
    lea rdi,[rel tc_tray_read]
    call wmx_tray_notice_paint
    mov edi,2
    mov rsi,[rel tc_state+TC_ST_POLICY]
    jmp snapshot_visibility_draw
.paint:
    jmp wmx_tray_notice_paint
.out:
    ret

; Present before first read. Recheck generation after draw and scanout flush.
terminal_consent_present:
    push rbx
    push r12
    mov qword [rel tc_present_generation],0
    call tc_refresh
    test eax,eax
    jz .bad
    cmp qword [rel tc_state+TC_ST_COUNT],0
    je .bad
    mov rbx,[rel tc_state+TC_ST_POLICY]
    mov r12,[rel tc_state+TC_ST_SESSION]
    call tc_display_ok
    test eax,eax
    jz .bad
    call taskbar_draw_registry
    ; A queued registry draw is not evidence that the read notice is visible.
    ; Paint only this bounded security region before its synchronous copy.
    call terminal_consent_draw
    call fb_present_flush
    mov r8d,8
    mov r9d,[rel fb_height]
    sub r9d,TASKBAR_H-4
    mov r10d,80
    mov r11d,16
    call fb_present_rect
    call tc_refresh
    test eax,eax
    jz .bad
    cmp qword [rel tc_state+TC_ST_COUNT],0
    je .bad
    cmp rbx,[rel tc_state+TC_ST_POLICY]
    jne .bad
    cmp r12,[rel tc_state+TC_ST_SESSION]
    jne .bad
    call tc_display_ok
    test eax,eax
    jz .bad
    mov [rel tc_present_generation],rbx
    mov [rel tc_present_session],r12
    mov rax,[rel fb_width]           ; contiguous width/height
    mov [rel tc_present_geometry],rax
    mov rax,[rel fb_base]
    mov [rel tc_present_base],rax
    mov rax,[rel fb_scanout_base]
    mov [rel tc_present_scanout],rax
    call snapshot_visibility_scanout
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

terminal_consent_visible:
    call tc_refresh
    test eax,eax
    jz .out
    call tc_display_ok
    test eax,eax
    jz .out
    cmp qword [rel tc_state+TC_ST_COUNT],0
    je .bad
    mov rax,[rel tc_state+TC_ST_POLICY]
    cmp rax,[rel tc_present_generation]
    jne .bad
    mov rax,[rel tc_state+TC_ST_SESSION]
    cmp rax,[rel tc_present_session]
    jne .bad
    mov rax,[rel fb_width]
    cmp rax,[rel tc_present_geometry]
    jne .bad
    mov rax,[rel fb_base]
    cmp rax,[rel tc_present_base]
    jne .bad
    mov rax,[rel fb_scanout_base]
    cmp rax,[rel tc_present_scanout]
    jne .bad
    mov eax,1
    ret
.bad:
    mov qword [rel tc_present_generation],0
    mov byte [rel tc_armed],0
    xor eax,eax
.out:
    ret

; Indicator hit opens inspection only. Policy changes require own physical UI.
terminal_consent_press:
    sub edi,8
    cmp edi,80
    jae .no
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H-4
    sub esi,eax
    cmp esi,16
    jae .no
    cmp byte [rel tc_configured],1
    jne .no
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .yes
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .yes
    mov eax,[rel wm_focus]
    cmp eax,[rel tc_slot]
    je .open
    mov [rel tc_selected_slot],eax
    cmp eax,WM_MAX-1
    jae .open
    lea rcx,[rel wm_gen]
    mov eax,[rcx+rax*4]
    mov [rel tc_selected_generation],eax
.open:
    mov byte [rel tc_open_requested],1
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

tc_scan:
    mov eax,[rel tc_slot]
    cmp eax,WM_MAX
    jae .bad
    lea rcx,[rel wm_title]
    lea rdx,[rel tc_title]
    cmp [rcx+rax*8],rdx
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+rax*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_gen]
    mov edx,[rel tc_generation]
    cmp [rcx+rax*4],edx
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+rax*4],WM_FREE
    je .bad
    cmp dword [rcx+rax*4],WM_CLOSED
    je .bad
    ret
.bad:
    mov eax,-1
    ret

tc_close:
    mov byte [rel tc_page_credit_pending],0
    mov byte [rel tc_armed],0
    mov byte [rel tc_intent],0
    mov qword [rel tc_id],0
    mov byte [rel tc_mode],0
    lea rdi,[rel tc_frozen]
    xor eax,eax
    mov ecx,(TC_DESC_BYTES+TC_TEXT_BYTES)/8
    rep stosq
    lea rdi,[rel tc_scope]
    mov ecx,TC_SCOPE_BYTES+25+TC_LINES*TC_LINE_BYTES
    rep stosb
    call tc_scan
    mov dword [rel tc_slot],-1
    cmp eax,-1
    je .out
    mov edi,eax
    jmp wmx_close_slot
.out:
    ret

; ac_ok's existing native focus/full-cover predicate, maintained independently
; for this surface. Native chrome is not sufficient when hidden or occluded.
tc_safe:
    call tc_scan
    cmp eax, -1
    je .bad
    mov edx, eax
    cmp eax, [rel wm_focus]
    jne .bad
    lea rcx, [rel wm_state]
    cmp dword [rcx + rdx*4], WM_VISIBLE
    jne .bad
    lea rcx, [rel wm_w]
    cmp dword [rcx + rdx*4], TC_WIDTH
    jne .bad
    lea rcx, [rel wm_h]
    cmp dword [rcx + rdx*4], TC_HEIGHT
    jne .bad
    lea rcx, [rel wm_x]
    mov r8d, [rcx + rdx*4]
    test r8d, r8d
    js .bad
    lea rcx, [rel wm_y]
    mov r9d, [rcx + rdx*4]
    test r9d, r9d
    js .bad
    lea r10d, [r8d + TC_WIDTH]
    lea r11d, [r9d + TC_HEIGHT]
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


; Bind a physical outside-to-inside approach to exact pixels, screen and z-order.
; Called for EVERY pointer event, including injected/retired ones, before press.
tc_pointer_note:
    push rbx
    push r12
    push r13
    push r14
    mov r12d,edi
    mov r13d,esi
    mov r14d,edx
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    test r14d,1
    jnz .chain                    ; down never earns a new arm
    call tc_safe
    test eax,eax
    jnz .disarm
    mov eax,[rel tc_slot]
    lea rdx,[rel wm_x]
    mov eax,[rdx+rax*4]
    mov edx,[rel tc_slot]
    lea rcx,[rel wm_y]
    mov edx,[rcx+rdx*4]
    mov ecx,r12d
    sub ecx,eax
    cmp ecx,TC_WIDTH
    jae .arm
    mov ecx,r13d
    sub ecx,edx
    cmp ecx,TC_HEIGHT
    jb .chain                     ; physical hover inside keeps, never earns
.arm:
    shl rax,32
    or rax,rdx
    mov [rel tc_arm_xy],rax
    mov rax,[rel fb_width]
    mov [rel tc_arm_fb],rax
    mov eax,[rel wm_zcounter]
    mov [rel tc_arm_z],eax
    mov byte [rel tc_armed],1
    jmp .chain
.disarm:
    mov byte [rel tc_armed],0
    mov byte [rel tc_intent],0
.chain:
    mov rax,[rel tc_prev_note]
    test rax,rax
    jz .out
    mov edi,r12d
    mov esi,r13d
    mov edx,r14d
    call rax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Click hook only; keyboard defaults never call this hook. One event, one latch.
tc_click:
    push rbx
    mov ebx,edi
    call tc_scan
    cmp eax,-1
    je .chain
    cmp ebx,[rel wgt_count]
    jae .chain
    mov edi,ebx
    call wgt_slot_ptr
    mov ecx,[rel tc_slot]
    cmp [rax+WGI_WIN],ecx
    jne .chain
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    cmp byte [rel tc_armed],1
    jne .disarm
    mov byte [rel tc_armed],0       ; spend before any check/callback
    call tc_safe
    test eax,eax
    jnz .out
    call tc_geometry_current
    test eax,eax
    jz .out
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    mov [rel tc_owner_token],rdx
    lea rcx,[rel tc_ids]
    mov edx,TC_PREV
.find:
    cmp ebx,[rcx+rdx*4]
    je .found
    inc edx
    cmp edx,TC_WIDGETS
    jb .find
    jmp .out
.found:
    mov [rel tc_intent],dl        ; idle will recheck exact card and local token
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel tc_click_injection],eax
    jmp .out
.disarm:
    mov byte [rel tc_armed],0
    mov byte [rel tc_intent],0
    jmp .out
.chain:
    pop rbx
    mov rax,[rel tc_prev_click]
    test rax,rax
    jz .none
    jmp rax
.none:
    ret
.out:
    pop rbx
    ret

tc_geometry_current:
    mov eax,[rel tc_slot]
    lea rcx,[rel wm_x]
    mov eax,[rcx+rax*4]
    shl rax,32
    mov edx,[rel tc_slot]
    lea rcx,[rel wm_y]
    mov edx,[rcx+rdx*4]
    or rax,rdx
    cmp rax,[rel tc_arm_xy]
    jne .bad
    mov rax,[rel fb_width]
    cmp rax,[rel tc_arm_fb]
    jne .bad
    mov eax,[rel wm_zcounter]
    cmp eax,[rel tc_arm_z]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Whole descriptor/text are compared again before approval. No arguments read
; from a guest or mutable widget. Padding is checked, not silently truncated.
tc_pending:
    lea rdi,[rel tc_probe]
    xor eax,eax
    mov ecx,(TC_DESC_BYTES+TC_TEXT_BYTES)/8
    rep stosq
    lea rdi,[rel tc_probe]
    lea rsi,[rel tc_probe_text]
    mov edx,TC_TEXT_BYTES
    call [rel tc_callbacks+TC_CB_PENDING]
    test rax,rax
    jz .out
    cmp qword [rel tc_probe],1
    jne .bad
    mov rdx,[rel session_authority_epoch]
    cmp rdx,[rel tc_probe+40]
    jne .bad
    mov rdx,[rel tc_state+TC_ST_POLICY]
    cmp rdx,[rel tc_probe+48]
    jne .bad
    cmp qword [rel tc_probe+56],32
    jb .bad
    cmp qword [rel tc_probe+56],38
    ja .bad
    cmp qword [rel tc_probe+88],0
    jne .bad
    push rax
    call time_monotonic_now_us
    test rax,rax
    jz .expired
    cmp rax,[rel tc_probe+208]
    jae .expired
    pop rax
    lea rdx,[rel tc_probe_text]
    mov ecx,TC_TEXT_BYTES
    cmp byte [rdx],0
    je .bad
.text:
    cmp byte [rdx],0
    je .tail
    cmp byte [rdx],32
    jb .bad
    cmp byte [rdx],126
    ja .bad
    inc rdx
    loop .text
    jmp .bad
.tail:
    cmp byte [rdx],0
    jne .bad
    inc rdx
    loop .tail
.out:
    ret
.expired:
    pop rax
.bad:
    xor eax,eax
    ret

terminal_consent_tick:
    push rbx
    call tc_tick_inner
    pop rbx
    ret

tc_tick_inner:
    cmp byte [rel tc_initialized],1
    jne .out
    cmp byte [rel tc_configured],1
    jne .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    cmp byte [rel command_auth_remote_active],0
    jne .out
    call tc_refresh
    test eax,eax
    jz .retire
    call tc_page_presented
    cmp qword [rel tc_state+TC_ST_COUNT],0
    je .pending
    call terminal_consent_visible
    test eax,eax
    jnz .pending
    call terminal_consent_present
.pending:
    call tc_pending
    test rax,rax
    jz .no_pending
    cmp rax,[rel tc_id]
    jne .new_pending
    lea rsi,[rel tc_probe]
    lea rdi,[rel tc_frozen]
    mov ecx,(TC_DESC_BYTES+TC_TEXT_BYTES)/8
    repe cmpsq
    jne .cancel                  ; same id with changed bytes is never approved
    jmp .intent
.new_pending:
    mov [rel tc_new_id],rax
    call tc_close
    mov rax,[rel tc_new_id]
    mov [rel tc_id],rax
    mov byte [rel tc_mode],1
    lea rsi,[rel tc_probe]
    lea rdi,[rel tc_frozen]
    mov ecx,(TC_DESC_BYTES+TC_TEXT_BYTES)/8
    rep movsq
    lea rsi,[rel tc_frozen]
    call wgt_provider_pending
    call tc_action_lines
    call tc_build
    jmp .out
.no_pending:
    cmp byte [rel tc_mode],1
    je .retire
    cmp byte [rel tc_open_requested],0
    je .intent
    mov byte [rel tc_open_requested],0
    call tc_close
    call tc_inspect_lines
    call tc_build
    jmp .out
.intent:
    cmp byte [rel tc_intent],0
    je .scan_closed
    movzx ebx,byte [rel tc_intent]
    mov byte [rel tc_intent],0
    call tc_safe
    test eax,eax
    jnz .cancel
    call tc_geometry_current
    test eax,eax
    jz .cancel
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel tc_click_injection]
    jne .cancel
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .cancel
    cmp rdx,[rel tc_owner_token]
    jne .cancel
    cmp ebx,TC_PREV
    je .prev
    cmp ebx,TC_NEXT
    je .next
    cmp ebx,TC_DENY
    je .deny_action
    cmp ebx,TC_REVOKE
    je .revoke
    cmp ebx,TC_APPROVE
    je .approve
    cmp byte [rel tc_mode],1
    je .out
    sub ebx,TC_FIRST_SCOPE
    cmp ebx,5
    ja .out
    ; Capture current focus target before opening inspection, full raw lifetime.
    mov edi,ebx
    add edi,16
    mov esi,[rel tc_selected_slot]
    mov edx,[rel tc_selected_generation]
    lea rcx,[rel tc_scope]
    call [rel tc_callbacks+TC_CB_PREPARE]
    cmp eax,1
    jne .refused
    cmp qword [rel tc_scope],1
    jne .refused
    cmp qword [rel tc_scope+8],16
    jb .refused
    cmp qword [rel tc_scope+8],21
    ja .refused
    cmp qword [rel tc_scope+16],0
    je .refused
    mov byte [rel tc_mode],2
    mov byte [rel tc_page],0
    mov byte [rel tc_seen],0
    call tc_scope_lines
    jmp tc_render
.approve:
    cmp byte [rel tc_seen],7      ; every byte of canonical action was presented
    jne .out
    cmp byte [rel tc_mode],1
    je .approve_action
    cmp byte [rel tc_mode],2
    jne .out
    lea rdi,[rel tc_scope]
    mov rsi,[rel tc_owner_token]
    call [rel tc_callbacks+TC_CB_GRANT]
    call tc_result
    call tc_refresh
    call tc_inspect_lines
    mov byte [rel tc_mode],0
    jmp tc_render
.approve_action:
    ; tc_pending already matched full original descriptor/text this idle turn.
    mov rdi,[rel tc_id]
    mov rsi,[rel tc_owner_token]
    mov qword [rel tc_id],0       ; UI never reoffers/automatically retries
    call [rel tc_callbacks+TC_CB_APPROVE]
    mov edi,3                       ; actual callback failed; not a denial
    cmp eax,1
    jne .approval_observed
    mov edi,1                       ; original SEC resume completed successfully
.approval_observed:
    lea rsi,[rel tc_frozen]
    call wgt_provider_decision
    call tc_close
    jmp tc_scrub_probe
.deny_action:
    cmp byte [rel tc_mode],1
    jne .cancel
    mov rdi,[rel tc_id]
    test rdi,rdi
    jz .retire
    mov qword [rel tc_id],0
    call [rel tc_callbacks+TC_CB_DENY]
    mov edi,2                       ; exact guarded Deny and original callback completed
    lea rsi,[rel tc_frozen]
    call wgt_provider_decision
    jmp .retire
.revoke:
    mov qword [rel tc_present_generation],0
    call snapshot_retire
    mov rdi,[rel tc_owner_token]
    call [rel tc_callbacks+TC_CB_REVOKE]
    call tc_result
    call tc_close
    call tc_refresh
    call tc_inspect_lines
    call tc_build
    jmp .out
.prev:
    cmp byte [rel tc_page],0
    je .out
    dec byte [rel tc_page]
    jmp tc_render
.next:
    mov al,[rel tc_max_page]
    cmp byte [rel tc_page],al
    jae .out
    inc byte [rel tc_page]
    jmp tc_render
.refused:
    mov byte [rel tc_status],0
    jmp .out
.scan_closed:
    cmp dword [rel tc_slot],-1
    je .out
    call tc_scan
    cmp eax,-1
    je .cancel
    cmp byte [rel tc_mode],0
    jne .out
    mov rax,[rel tc_state+TC_ST_POLICY]
    cmp rax,[rel tc_inspect_generation]
    jne .refresh_inspect
    mov rax,[rel tc_state+TC_ST_SESSION]
    cmp rax,[rel tc_inspect_session]
    je .out
.refresh_inspect:
    mov byte [rel tc_page],0
    call tc_inspect_lines
    jmp tc_render
.out:
    ret
.cancel:
    mov rdi,[rel tc_id]
    test rdi,rdi
    jz .retire
    mov qword [rel tc_id],0
    call [rel tc_callbacks+TC_CB_DENY]
.retire:
    mov rdi,[rel tc_id]
    test rdi,rdi
    jz .clear_read
    mov qword [rel tc_id],0
    call [rel tc_callbacks+TC_CB_DENY]
.clear_read:
    call snapshot_retire
    call tc_close
tc_scrub_probe:
    lea rdi,[rel tc_probe]
    xor eax,eax
    mov ecx,(TC_DESC_BYTES+TC_TEXT_BYTES)/8
    rep stosq
    ret

; Status reflects callback result, never optimism about a firmware write.
tc_result:
    cmp eax,1
    je .save
    cmp eax,2
    je .save
    xor eax,eax
.save:
    mov [rel tc_status],al
    ret

; Fixed bounded native rows; no strings are pointers into guest memory.
tc_clear_lines:
    lea rdi,[rel tc_lines]
    xor eax,eax
    mov ecx,TC_LINES*TC_LINE_BYTES
    rep stosb
    ret

; RDI static prefix, R8 exact number, ESI line index -> static text +16hex.
tc_line_hex:
    mov rdx,rdi
    imul esi,TC_LINE_BYTES
    lea rdi,[rel tc_lines]
    add rdi,rsi
    mov rsi,rdx
.copy:
    lodsb
    test al,al
    jz .number
    stosb
    jmp .copy
.number:
    lea rsi,[rel tc_hex]
    mov ecx,16
.digit:
    rol r8,4
    mov eax,r8d
    and eax,15
    mov al,[rsi+rax]
    stosb
    loop .digit
    mov byte [rdi],0
    ret

tc_action_lines:
    mov byte [rel tc_max_page],2
    call tc_clear_lines
    push rbx
    xor ebx,ebx
.fields:
    lea rax,[rel tc_action_offsets]
    movzx eax,byte [rax+rbx]
    lea rdx,[rel tc_frozen]
    mov r8,[rdx+rax]
    lea rax,[rel tc_action_labels]
    mov rdi,[rax+rbx*8]
    add rdi,rax
    mov esi,ebx
    call tc_line_hex
    inc ebx
    cmp ebx,16
    jb .fields
    ; Exactly1023 bytes fit in15 rows of72; no silent display truncation.
    lea rsi,[rel tc_frozen_text]
    lea rdi,[rel tc_lines+16*TC_LINE_BYTES]
    mov edx,15
.row:
    mov ecx,72
.char:
    lodsb
    test al,al
    jz .done
    stosb
    loop .char
    inc rdi                        ; leave line's NUL
    dec edx
    jnz .row
.done:
    pop rbx
    ret

tc_scope_lines:
    mov byte [rel tc_max_page],2
    call tc_clear_lines
    push rbx
    xor ebx,ebx
.loop:
    lea rdx,[rel tc_scope]
    mov r8,[rdx+rbx*8]
    lea rax,[rel tc_scope_labels]
    mov rdi,[rax+rbx*8]
    add rdi,rax
    mov esi,ebx
    call tc_line_hex
    inc ebx
    cmp ebx,16
    jb .loop
    pop rbx
    ret

tc_inspect_lines:
    mov rax,[rel tc_state+TC_ST_POLICY]
    mov [rel tc_inspect_generation],rax
    mov rax,[rel tc_state+TC_ST_SESSION]
    mov [rel tc_inspect_session],rax
    call tc_clear_lines
    lea rdi,[rel tc_notice]
    mov r8,[rel tc_state+TC_ST_COUNT]
    xor esi,esi
    call tc_line_hex
    lea rdi,[rel tc_policy_label]
    mov r8,[rel tc_state+TC_ST_POLICY]
    mov esi,1
    call tc_line_hex
    lea rdi,[rel tc_session_label]
    mov r8,[rel tc_state+TC_ST_SESSION]
    mov esi,2
    call tc_line_hex
    lea rdi,[rel tc_status_unchanged]
    cmp byte [rel tc_status],3
    je .status
    lea rdi,[rel tc_status_failed]
    cmp byte [rel tc_status],0
    je .status
    lea rdi,[rel tc_status_saved]
    cmp byte [rel tc_status],1
    je .status
    lea rdi,[rel tc_status_session]
.status:
    mov r8,[rel tc_state+TC_ST_SAVED]
    mov esi,3
    call tc_line_hex
    push rbx
    push r12
    mov rax,[rel tc_state+TC_ST_COUNT]
    shl eax,4
    add eax,3
    xor edx,edx
    mov ecx,12
    div ecx
    mov [rel tc_max_page],al
    xor ebx,ebx
.loop:
    cmp rbx,[rel tc_state+TC_ST_COUNT]
    jae .done
    xor r12d,r12d
.fields:
    imul eax,ebx,TC_SCOPE_BYTES
    lea rdx,[rel tc_state+64]
    add rdx,rax
    mov r8,[rdx+r12*8]
    lea rax,[rel tc_scope_labels]
    mov rdi,[rax+r12*8]
    add rdi,rax
    mov esi,ebx
    shl esi,4
    lea esi,[rsi+r12+4]
    call tc_line_hex
    inc r12d
    cmp r12d,16
    jb .fields
    inc ebx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

; Allocate only standard window + label/button widgets. The first frame has
; complete trusted labels. Deny starts focused; no keyboard approval path.
tc_build:
    push rbx
    push r12
    cmp dword [rel fb_width],TC_WIDTH
    jb .fail
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    cmp eax,TC_HEIGHT
    jb .fail
    lea rdi,[rel tc_title]
    xor esi,esi
    xor edx,edx
    mov ecx,TC_WIDTH
    mov r8d,TC_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .fail
    mov r12d,eax
    mov [rel tc_slot],eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+r12*4]
    mov [rel tc_generation],eax
    lea rcx,[rel wm_owner]
    mov qword [rcx+r12*8],WM_OWNER_CHROME
    mov edi,TC_WIDGETS
    call wgt_reserve_run
    test eax,eax
    js .fail
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    mov edi,2
    cmp ebx,TC_ROWS
    jb .type
    xor edi,edi
.type:
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .failed_widgets
    lea rcx,[rel tc_ids]
    mov [rcx+rbx*4],eax
    mov edi,eax
    call wgt_slot_ptr
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_EDIT],0
    mov dword [rax+WGI_X],8
    mov dword [rax+WGI_W],584
    mov dword [rax+WGI_H],20
    mov r8,rax
    mov eax,ebx
    xor edx,edx
    mov ecx,3
    div ecx
    imul eax,22
    add eax,28
    mov [r8+WGI_Y],eax
    imul edx,192
    add edx,8
    mov [r8+WGI_X],edx
    mov dword [r8+WGI_W],192
    mov rax,r8
    cmp ebx,TC_ROWS
    jb .next
    mov dword [rax+WGI_H],24            ; stock button paint minimum (labels remain20)
    mov dword [rax+WGI_W],110
    mov edx,ebx
    sub edx,TC_ROWS
    mov ecx,edx
    and ecx,3
    imul ecx,146
    add ecx,8
    mov [rax+WGI_X],ecx
    shr edx,2
    imul edx,32
    add edx,304
    mov [rax+WGI_Y],edx
    lea rdx,[rel tc_buttons]
    mov ecx,ebx
    sub ecx,TC_ROWS
    mov rsi,[rdx+rcx*8]
    add rsi,rdx
    lea rdx,[rel tc_ids]
    mov edi,[rdx+rbx*4]
    call wgt_set_text
.next:
    inc ebx
    cmp ebx,TC_WIDGETS
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    mov eax,[rel tc_ids+TC_DENY*4]
    lea rcx,[rel wgt_focus_by_win]
    mov [rcx+r12*4],eax
    mov byte [rel tc_page],0
    mov byte [rel tc_seen],0
    call tc_render
    jmp .out
.failed_widgets:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.fail:
    mov rdi,[rel tc_id]
    test rdi,rdi
    jz .close
    call [rel tc_callbacks+TC_CB_DENY]
.close:
    call tc_close
.out:
    pop r12
    pop rbx
    ret

tc_render:
    mov byte [rel tc_page_credit_pending],0
    push rbx
    push r12
    mov byte [rel tc_armed],0
    mov byte [rel tc_intent],0
    xor ebx,ebx
    movzx r12d,byte [rel tc_page]
    imul r12d,12
.loop:
    mov eax,ebx
    xor edx,edx
    mov ecx,3
    div ecx
    add eax,r12d
    lea rsi,[rel tc_empty]
    cmp eax,TC_LINES
    jae .fragment
    imul eax,TC_LINE_BYTES
    imul edx,24
    add eax,edx
    lea rsi,[rel tc_lines]
    add rsi,rax
.fragment:
    lea rdi,[rel tc_fragment]
    mov ecx,24
.copy:
    lodsb
    stosb
    test al,al
    jz .text
    loop .copy
    mov byte [rdi],0
.text:
    lea rdx,[rel tc_ids]
    mov edi,[rdx+rbx*4]
    lea rsi,[rel tc_fragment]
    call wgt_set_text
    inc ebx
    cmp ebx,TC_ROWS
    jb .loop
    call wmx_draw_all
    cmp byte [rel fb_compose_live],0
    je .synchronous_boot
    ; A live draw only queues composition. Its old shadow is never an action
    ; page receipt, and a 600x432 synchronous copy would block the command loop.
    mov rax,[rel fb_compose_serial]
    mov [rel tc_page_before_serial],rax
    mov rax,[rel session_authority_epoch]
    mov [rel tc_page_authority],rax
    mov byte [rel tc_page_credit_pending],1
    jmp .out
.synchronous_boot:
    call fb_present_flush
    call tc_display_ok
    test eax,eax
    jz .out
    call tc_safe
    test eax,eax
    jnz .out
    mov r8d,[rel tc_slot]
    lea rax,[rel wm_x]
    mov r8d,[rax+r8*4]
    mov r9d,[rel tc_slot]
    lea rax,[rel wm_y]
    mov r9d,[rax+r9*4]
    mov r10d,TC_WIDTH
    mov r11d,TC_HEIGHT
    call fb_present_rect
    cmp byte [rel tc_mode],0
    je .out
    movzx ecx,byte [rel tc_page]
    mov eax,1
    shl eax,cl
    or [rel tc_seen],al
.out:
    pop r12
    pop rbx
    ret

 ; Called only from the ordinary idle consent tick, never a painter. The
; presenter serial exists only after the entire newly composed frame reached
; scanout. Revalidate the current composition context and consent geometry;
; an old serial, partial/abandoned job, new owner, or hidden page earns nothing.
tc_page_presented:
    cmp byte [rel tc_page_credit_pending],1
    jne .out
    cmp byte [rel tc_mode],0
    je .out
    cmp byte [rel fb_compose_pending],0
    jne .out
    cmp byte [rel fb_present_pending],0
    jne .out
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel tc_page_authority]
    jne .out
    mov rax,[rel fb_present_completed_serial]
    cmp rax,[rel tc_page_before_serial]
    jbe .out
    cmp rax,[rel fb_compose_serial]
    jne .out
    call fb_compose_context_current
    jc .out
    mov rax,[rel fb_surface_epoch]
    cmp rax,[rel fb_present_completed_surface_epoch]
    jne .out
    call tc_display_ok
    test eax,eax
    jz .out
    call tc_safe
    test eax,eax
    jnz .out
    movzx ecx,byte [rel tc_page]
    mov eax,1
    shl eax,cl
    or [rel tc_seen],al
    mov byte [rel tc_page_credit_pending],0
.out:
    ret

tc_title: db 'Terminal access',0
tc_tray_idle: db 'TERMINAL',0
tc_tray_read: db 'TERM READ',0
tc_empty: db 0
tc_notice: db 'Terminal can read; scopes: ',0
tc_policy_label: db 'Policy generation: ',0
tc_session_label: db 'Owner session: ',0
tc_status_unchanged: db 'Consent persistence status: ',0
tc_status_failed: db 'Last change refused; store status: ',0
tc_status_saved: db 'Last change saved; store status: ',0
tc_status_session: db 'Session only; store status: ',0
tc_scope_op: db 'Read kind (16..21): ',0
tc_target_label: db 'Exact target: ',0
tc_generation_label: db 'Full target generation: ',0
align 8
tc_scope_labels: dq tc_s0-tc_scope_labels,tc_scope_op-tc_scope_labels,tc_s2-tc_scope_labels,tc_target_label-tc_scope_labels,tc_generation_label-tc_scope_labels,tc_s5-tc_scope_labels,tc_s6-tc_scope_labels,tc_s7-tc_scope_labels,tc_s8-tc_scope_labels,tc_s9-tc_scope_labels,tc_s10-tc_scope_labels,tc_s11-tc_scope_labels,tc_s12-tc_scope_labels,tc_s13-tc_scope_labels,tc_s14-tc_scope_labels,tc_s15-tc_scope_labels
tc_s0: db 'Scope version: ',0
tc_s2: db 'Scope ID: ',0
tc_s5: db 'Reserved40 (must be zero): ',0
tc_s6: db 'Root identity word1: ',0
tc_s7: db 'Root identity word2: ',0
tc_s8: db 'Root identity word3: ',0
tc_s9: db 'Root identity word4: ',0
tc_s10: db 'Root identity word5: ',0
tc_s11: db 'Root identity word6: ',0
tc_s12: db 'Root identity word7: ',0
tc_s13: db 'Root identity word8: ',0
tc_s14: db 'Reserved112 (must be zero): ',0
tc_s15: db 'Reserved120 (must be zero): ',0
tc_hex: db '0123456789abcdef'
align 8
tc_buttons: dq tc_b_prev-tc_buttons,tc_b_next-tc_buttons,tc_b_deny-tc_buttons,tc_b_approve-tc_buttons,tc_b_revoke-tc_buttons,tc_b_desktop-tc_buttons,tc_b_active-tc_buttons,tc_b_window-tc_buttons,tc_b_ui-tc_buttons,tc_b_data-tc_buttons,tc_b_folder-tc_buttons
tc_b_prev: db 'Previous',0
tc_b_next: db 'Next',0
tc_b_deny: db 'Deny / Close',0
tc_b_approve: db 'Allow once/save',0
tc_b_revoke: db 'Revoke all',0
tc_b_desktop: db 'Desktop read',0
tc_b_active: db 'Active read',0
tc_b_window: db 'Window read',0
tc_b_ui: db 'UI hook read',0
tc_b_data: db 'DATA read',0
tc_b_folder: db 'Picked folder',0
align 8
tc_action_labels: dq tc_a_0-tc_action_labels,tc_a_1-tc_action_labels,tc_a_2-tc_action_labels,tc_a_3-tc_action_labels,tc_a_4-tc_action_labels,tc_a_5-tc_action_labels,tc_a_6-tc_action_labels,tc_a_7-tc_action_labels,tc_a_8-tc_action_labels,tc_a_9-tc_action_labels,tc_a_10-tc_action_labels,tc_a_11-tc_action_labels,tc_a_12-tc_action_labels,tc_a_13-tc_action_labels,tc_a_14-tc_action_labels,tc_a_15-tc_action_labels
tc_a_0: db 'Terminal principal: ',0
tc_a_1: db 'Binding: ',0
tc_a_2: db 'START: ',0
tc_a_3: db 'VM epoch: ',0
tc_a_4: db 'Owner epoch: ',0
tc_a_5: db 'Policy generation: ',0
tc_a_6: db 'Operation: ',0
tc_a_7: db 'Scope ID: ',0
tc_a_8: db 'Exact target: ',0
tc_a_9: db 'Full generation: ',0
tc_a_10: db 'Request sequence: ',0
tc_a_11: db 'Expires at (us): ',0
tc_a_12: db 'Argument SHA256 word1: ',0
tc_a_13: db 'Argument SHA256 word2: ',0
tc_a_14: db 'Argument SHA256 word3: ',0
tc_a_15: db 'Argument SHA256 word4: ',0
tc_action_offsets: db 8,16,24,32,40,48,56,64,72,80,200,208,104,112,120,128

%include "core/abi/wdata.inc"
%macro WDATA_terminal_consent 0
align 8
tc_page_before_serial: dq 0
tc_page_authority: dq 0
tc_page_credit_pending: db 0
align 8
tc_callbacks: times 7 dq 0
tc_prev_click: dq 0
tc_prev_note: dq 0
tc_id: dq 0
tc_new_id: dq 0
tc_owner_token: dq 0
tc_arm_xy: dq 0
tc_arm_fb: dq 0
tc_inspect_generation: dq 0
tc_inspect_session: dq 0
tc_present_generation: dq 0
tc_present_session: dq 0
tc_present_geometry: dq 0
tc_present_base: dq 0
tc_present_scanout: dq 0
tc_slot: dd -1
tc_generation: dd 0
tc_selected_slot: dd -1
tc_selected_generation: dd 0
tc_arm_z: dd 0
tc_click_injection: dd 0
tc_ids: times TC_WIDGETS dd -1
tc_configured: db 0
tc_initialized: db 0
tc_query_busy: db 0
tc_open_requested: db 0
tc_armed: db 0
tc_intent: db 0
tc_mode: db 0
tc_page: db 0
tc_max_page: db 2
tc_seen: db 0
tc_status: db 3
%endmacro
WDATA_DEFER WDATA_terminal_consent
%macro WDATA_terminal_consent_bss 0
alignb 8
tc_state: resb TC_STATE_BYTES
tc_probe: resb TC_DESC_BYTES
tc_probe_text: resb TC_TEXT_BYTES
tc_frozen: resb TC_DESC_BYTES
tc_frozen_text: resb TC_TEXT_BYTES
tc_scope: resb TC_SCOPE_BYTES
tc_fragment: resb 25
tc_lines: resb TC_LINES*TC_LINE_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_terminal_consent_bss
