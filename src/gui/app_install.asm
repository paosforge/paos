;; MODULE gui/app_install
;; LAYER 6
;; PURPOSE Owner install decision for one checked package candidate: offer, intent and checker.
;; EXPORTS app_install_declare, app_install_init, app_install_offer, app_install_tick, app_install_intent_check, app_install_intent_consume, app_install_store_descriptor, app_install_store_copy, app_install_store_execution_policy, cmd_verb_appinstall
;; IMPORTS gui/app_installed, gui/app_store_observe, gui/app_store_install, gui/app_package_card, gui/widget, gui/window_mgmt, gui/window, svc/app_package, svc/app_analysis, svc/command, sec/app_install_grants, sec/session, fs/vfs, core/heap, core/time, core/smp, dev/input/ps2, boot/gop
;; OWNER saga:app_package
;; CONTEXT: bsp_only
; Offering installs, grants and enrolls nothing. The owner's button freezes one
; intent; only a committed store result reaches app_install_grants_remember. No
; default key: Cancel holds focus and Enter/Space act only after a human Tab.
AIN_MAX equ 65536
AIN_PATH_MAX equ 255
AIN_BOUND_US equ 30000000
AIN_DWELL_US equ 400000
AIN_ORIGIN_FILE equ 1
AIN_FLAGS_UNSIGNED equ 1
AIN_FLAGS_SIGNED equ 3
AIN_ORIGIN_TERMINAL equ 2
AIN_PROFILE equ 2                      ; app_install_grants sharing candidate
AIN_SELECT_ALLOW equ 1
AIN_SELECT_ASK equ 2
AIN_LABELS equ 12
AIN_L_NAME equ 1
AIN_L_VERSION equ 2
AIN_L_AUTHOR equ 3
AIN_L_FROM equ 4
AIN_L_PERMS equ 5
AIN_L_NOTE equ 10
AIN_L_STATUS equ 11
AIN_ALLOW equ 12
AIN_ASK equ 13
AIN_CANCEL equ 14
AIN_DETAILS equ 15
AIN_EXEC equ 16
AIN_COUNT equ 17
AIN_WIDTH equ 560
AIN_HEIGHT equ 402
AIN_TOP equ 64                      ; below the desktop launcher entry, which ain_ok refuses to overlap
AIN_IDLE equ 0
AIN_DECIDING equ 1
AIN_FINISHED equ 2
AIN_ACT_ALLOW equ 1
AIN_ACT_ASK equ 2
AIN_ACT_CANCEL equ 3
AIN_ACT_DETAILS equ 4
AIN_ACT_EXEC equ 5
AIN_FILE_IDLE equ 0
AIN_FILE_QUEUED equ 1
AIN_FILE_SHOWN equ 2
AIN_FILE_REFUSED equ 3

app_install_declare:
    call app_store_observe_declare
    call app_installed_declare
    lea rdi,[rel ain_verb]
    lea rsi,[rel cmd_verb_appinstall]
    mov rdx,CMD_AUTH_CAP_EXTENSION
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb

; Runs after app binding is configured. Initialization is not owner approval.
app_install_init:
    cmp byte [rel ain_initialized],0
    jne .out
    mov rax,[rel wgt_key_filter]
    mov [rel ain_prev_filter],rax
    lea rax,[rel ain_key]
    mov [rel wgt_key_filter],rax
    mov rax,[rel wgt_click_hook]
    mov [rel ain_prev_click],rax
    lea rax,[rel ain_click]
    mov [rel wgt_click_hook],rax
    lea rax,[rel app_store_install]
    mov [rel app_install_store],rax      ; fixed authenticated provider, never guest-configured
    mov byte [rel ain_initialized],1
    jmp app_install_grants_init
.out:
    ret

; RDI bytes, RSI length, EDX origin from native code, never guest bytes. EAX1 only
; once the card shows. The candidate is a private copy; the caller scrubs its own.
app_install_offer:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov ebx,edx
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel cmd_in_dispatch],0
    jne .refuse
    cmp byte [rel ain_initialized],1
    jne .refuse
    cmp ebx,AIN_ORIGIN_FILE
    je .origin
    cmp ebx,AIN_ORIGIN_TERMINAL
    jne .refuse
.origin:
    cmp dword [rel ain_state],AIN_IDLE
    jne .refuse
    cmp dword [rel pkgcard_slot],-1
    jne .refuse
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .refuse
    cmp rdx,-1
    je .refuse
    ; Installation accepts valid sharing packages independently of execution
    ; approval. Signed content still passes the original complete verifier.
    cmp r13,44
    jb .refuse
    cmp dword [r12+40],AIN_FLAGS_UNSIGNED
    je .flags
    cmp dword [r12+40],AIN_FLAGS_SIGNED
    jne .refuse
.flags:
    mov [rel ain_epoch],rdx
    mov [rel ain_origin],ebx
    mov byte [rel ain_exec_selected],0
    mov rdi,r12
    mov rsi,r13
    call app_package_stage
    test rax,rax
    jz .refuse
    mov [rel ain_handle],rax
    mov rcx,[rel ap_resident]            ; the bytes verified, not the caller's
    cmp dword [rcx+40],AIN_FLAGS_UNSIGNED
    je .verified
    cmp dword [rcx+40],AIN_FLAGS_SIGNED
    jne .retire
.verified:
    mov rdi,rax
    call app_analysis_build
    cmp eax,1
    jne .retire
    mov rdi,[rel ain_handle]
    lea rsi,[rel ain_analysis]
    mov edx,192
    call app_analysis_descriptor
    cmp eax,1
    jne .retire
    mov rdi,[rel ain_handle]
    lea rsi,[rel ain_package]
    mov edx,704
    call app_package_descriptor
    cmp eax,1
    jne .retire
    mov rdi,[rel ain_handle]
    mov esi,AIN_PROFILE
    lea rdx,[rel ain_requested]
    mov ecx,4
    call app_install_grants_requested
    cmp eax,1
    jne .retire
    call ain_build
    cmp eax,1
    jne .retire
    mov dword [rel ain_state],AIN_DECIDING
    call wmx_draw_all
    mov eax,1
    jmp .out
.retire:
    call ain_close
.refuse:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

ain_scan:
    mov eax,[rel ain_slot]
    cmp eax,WM_MAX
    jae .bad
    lea rcx,[rel wm_title]
    lea rdx,[rel ain_title]
    cmp [rcx+rax*8],rdx
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+rax*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_gen]
    mov edx,[rel ain_gen]
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

; Everything but the store's own durable result ends here.
ain_close:
    call ain_intent_clear
    mov dword [rel ain_state],AIN_IDLE
    mov byte [rel ain_action],0
    mov byte [rel ain_armed],0
    mov byte [rel ain_tab],0
    cmp dword [rel pkgcard_slot],-1
    je .no_card
    call app_package_card_close
.no_card:
    call ain_scan
    mov dword [rel ain_slot],-1
    cmp eax,-1
    je .candidate
    mov edi,eax
    call wmx_close_slot
.candidate:
    call app_package_retire
    mov qword [rel ain_handle],0
    lea rdi,[rel ain_scrub_start]
    xor eax,eax
    mov ecx,(ain_scrub_end-ain_scrub_start)
    cld
    rep stosb
    ret

; Refuse any cover, focus, size, position or display change. Overlays and
; intersecting desktop-host widgets paint after windows.
ain_ok:
    call ain_scan
    cmp eax,-1
    je .bad
    mov edx,eax
    cmp eax,[rel wm_focus]
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+rdx*4],WM_VISIBLE
    jne .bad
    lea rcx,[rel wm_w]
    cmp dword [rcx+rdx*4],AIN_WIDTH
    jne .bad
    lea rcx,[rel wm_h]
    cmp dword [rcx+rdx*4],AIN_HEIGHT
    jne .bad
    lea rcx,[rel wm_x]
    mov r8d,[rcx+rdx*4]
    test r8d,r8d
    js .bad
    lea rcx,[rel wm_y]
    mov r9d,[rcx+rdx*4]
    test r9d,r9d
    js .bad
    lea r10d,[r8d+AIN_WIDTH]
    lea r11d,[r9d+AIN_HEIGHT]
    cmp r10d,[rel fb_width]
    jg .bad
    mov ecx,[rel fb_height]
    sub ecx,TASKBAR_H
    cmp r11d,ecx
    jg .bad
    xor ecx,ecx
    lea rdx,[rel wgt_tbl]
.loop:
    cmp ecx,[rel wgt_count]
    jae .yes
    cmp dword [rdx+WGI_TYPE],0
    je .next
    test dword [rdx+WGI_FLAGS],1
    jz .next
    mov rax,rdx                          ; Q 90205: the one predicate for paint, hover and press.
    call wgt_row_shown                   ; An unfocused window's closed menu paints nothing here.
    jc .next
    cmp dword [rdx+WGI_LAYER],1
    je .cover
    cmp dword [rdx+WGI_WIN],WGT_HOST_DESKTOP
    jne .next
.cover:
    mov eax,[rdx+WGI_X]
    cmp eax,r10d
    jge .next
    add eax,[rdx+WGI_W]
    cmp eax,r8d
    jle .next
    mov eax,[rdx+WGI_Y]
    cmp eax,r11d
    jge .next
    add eax,[rdx+WGI_H]
    cmp eax,r9d
    jg .bad
.next:
    add rdx,WGI_SZ
    inc ecx
    jmp .loop
.yes:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

ain_geometry:
    mov edx,[rel ain_slot]
    lea rcx,[rel wm_x]
    mov eax,[rcx+rdx*4]
    shl rax,32
    lea rcx,[rel wm_y]
    mov edx,[rcx+rdx*4]
    or rax,rdx
    mov edx,[rel fb_width]
    shl rdx,32
    mov ecx,[rel fb_height]
    or rdx,rcx
    ret

ain_snapshot:
    call ain_geometry
    mov [rel ain_arm_xy],rax
    mov [rel ain_arm_fb],rdx
    mov eax,[rel wm_zcounter]
    mov [rel ain_arm_z],eax
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel ain_arm_inj],eax
    ret

; EAX1 while the armed human decision still looks at the same unchanged window.
ain_unchanged:
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel ain_arm_inj]
    jne .bad
    mov eax,[rel wm_zcounter]
    cmp eax,[rel ain_arm_z]
    jne .bad
    call ain_ok
    cmp eax,1
    jne .bad
    call ain_geometry
    cmp rax,[rel ain_arm_xy]
    jne .bad
    cmp rdx,[rel ain_arm_fb]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Input from before the card opened, or a click meant for what was there, is refused.
ain_dwelled:
    cmp qword [rel ain_opened_us],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    sub rax,[rel ain_opened_us]
    jb .bad
    cmp rax,AIN_DWELL_US
    jb .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI widget id -> action in AL, zero if it is not an active decision button.
ain_action_for_id:
    xor eax,eax
    cmp dword [rel ain_state],AIN_DECIDING
    jne .cancel
    cmp edi,[rel ain_ids+AIN_ALLOW*4]
    jne .ask
    cmp dword [rel ain_origin],AIN_ORIGIN_FILE
    jne .out
    mov al,AIN_ACT_ALLOW
    ret
.ask:
    cmp edi,[rel ain_ids+AIN_ASK*4]
    jne .details
    mov al,AIN_ACT_ASK
    ret
.details:
    cmp edi,[rel ain_ids+AIN_EXEC*4]
    jne .disclosure
    mov rcx,[rel ap_resident]
    test rcx,rcx
    jz .out
    cmp dword [rcx+40],AIN_FLAGS_UNSIGNED
    jne .out
    mov al,AIN_ACT_EXEC
    ret
.disclosure:
    cmp edi,[rel ain_ids+AIN_DETAILS*4]
    jne .cancel
    mov al,AIN_ACT_DETAILS
    ret
.cancel:
    cmp edi,[rel ain_ids+AIN_CANCEL*4]
    jne .out
    mov al,AIN_ACT_CANCEL
.out:
    ret

; EDI id, AL action. Installing arms against the window as the human saw it.
ain_queue:
    cmp al,AIN_ACT_EXEC
    je .install
    cmp al,AIN_ACT_ALLOW
    je .install
    cmp al,AIN_ACT_ASK
    je .install
    mov [rel ain_action],al
    ret
.install:
    push rax
    call ain_ok
    mov ecx,eax
    pop rax
    cmp ecx,1
    jne ain_disarm
    mov [rel ain_action],al
    mov byte [rel ain_armed],1
    jmp ain_snapshot
ain_disarm:
    mov byte [rel ain_action],0
    mov byte [rel ain_armed],0
    mov byte [rel ain_tab],0
    ret

; Key filter ABI EDI=focused widget, EAX=key. Preserve inputs on chain.
ain_key:
    push rdi
    push rax
    call ain_scan
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
    je .human
    call ain_disarm
    jmp .taken
.human:
    cmp eax,GUI_KEY_ESC
    je .escape
    cmp eax,GUI_KEY_TAB
    je .tab
    cmp eax,GUI_KEY_ENTER
    je .press
    cmp eax,' '
    jne .taken
.press:
    cmp byte [rel ain_tab],1
    jne .taken
    cmp byte [rel wgt_focus_visible],1
    jne .taken
    push rdi
    call ain_dwelled
    pop rdi
    cmp eax,1
    jne .taken
    push rdi
    call ain_unchanged                  ; SRC R2-2: as the window stood at the Tab
    pop rdi
    cmp eax,1
    jne .disarm
    call ain_action_for_id
    test al,al
    jz .taken
    call ain_queue
    jmp .taken
.tab:
    push rdi
    call ain_dwelled
    pop rdi
    cmp eax,1
    jne .taken
    call ain_ok
    cmp eax,1
    jne .disarm
    call ain_snapshot
    mov byte [rel ain_tab],1
    mov byte [rel wgt_focus_visible],1
    call ain_focus_next
    call wmx_draw_all
    jmp .taken
.escape:
    mov byte [rel ain_action],AIN_ACT_CANCEL
    jmp .taken
.disarm:
    call ain_disarm
.taken:
    mov eax,1
    ret
.other:
    pop rax
    pop rdi
    mov rdx,[rel ain_prev_filter]
    test rdx,rdx
    jz .none
    jmp rdx
.none:
    xor eax,eax
    ret

; Cancel, then each live button in order. Origin 2 has no Allow button.
ain_focus_next:
    mov eax,[rel wgt_focus_id]
    cmp dword [rel ain_state],AIN_DECIDING
    jne .normal
    cmp eax,[rel ain_ids+AIN_CANCEL*4]
    jne .normal
    mov rdx,[rel ap_resident]
    test rdx,rdx
    jz .normal
    cmp dword [rdx+40],AIN_FLAGS_UNSIGNED
    jne .normal
    mov ecx,AIN_EXEC
    jmp .set
.normal:
    mov ecx,AIN_ASK
    cmp dword [rel ain_origin],AIN_ORIGIN_FILE
    jne .choose
    mov ecx,AIN_ALLOW
    cmp eax,[rel ain_ids+AIN_EXEC*4]
    je .set
    cmp eax,[rel ain_ids+AIN_CANCEL*4]
    je .set
    mov ecx,AIN_ASK
    cmp eax,[rel ain_ids+AIN_ALLOW*4]
    je .set
    mov ecx,AIN_DETAILS
    cmp eax,[rel ain_ids+AIN_ASK*4]
    je .set
    mov ecx,AIN_CANCEL
    jmp .set
.choose:
    cmp eax,[rel ain_ids+AIN_EXEC*4]
    je .set
    cmp eax,[rel ain_ids+AIN_CANCEL*4]
    je .set
    mov ecx,AIN_DETAILS
    cmp eax,[rel ain_ids+AIN_ASK*4]
    je .set
    mov ecx,AIN_CANCEL
.set:
    cmp dword [rel ain_state],AIN_DECIDING
    je .store
    mov ecx,AIN_CANCEL
.store:
    lea rdx,[rel ain_ids]
    mov eax,[rdx+rcx*4]
    mov [rel wgt_focus_id],eax
    mov ecx,[rel ain_slot]
    lea rdx,[rel wgt_focus_by_win]
    mov [rdx+rcx*4],eax
    ret

; Stock click hook, run from the press path: a human press on the visible unchanged card only.
ain_click:
    push rdi
    call ain_scan
    cmp eax,-1
    je .chain
    mov edi,[rsp]
    call ain_action_for_id
    test al,al
    jz .chain
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .disarm
    push rax
    call ain_dwelled
    mov ecx,eax
    pop rax
    cmp ecx,1
    jne .disarm
    mov edi,[rsp]
    call ain_queue
    jmp .done
.disarm:
    call ain_disarm
.done:
    pop rdi
    ret
.chain:
    pop rdi
    mov rax,[rel ain_prev_click]
    test rax,rax
    jz .out
    jmp rax
.out:
    ret

; Idle effects only. Any loss of the owner or the candidate closes the decision.
app_install_tick:
    call app_store_observe_tick
    call app_installed_tick
    call ain_file_tick
    cmp dword [rel ain_state],AIN_IDLE
    je .out
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    call ain_scan
    cmp eax,-1
    je .close
    call ain_widgets_current
    cmp eax,1
    jne .close
    ; SEC R2-3: an injector may have chosen what the owner is looking at. Closing can only deny.
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel ain_open_ptr_inj]
    jne .close
    mov eax,[rel keyprov_inj_seq]
    cmp eax,[rel ain_open_key_inj]
    jne .close
    call ain_slot_focused
    movzx eax,byte [rel ain_action]
    mov byte [rel ain_action],0
    cmp dword [rel ain_state],AIN_FINISHED
    je .finished
    push rax
    call ain_current
    mov ecx,eax
    pop rax
    cmp ecx,1
    jne .close
    cmp eax,AIN_ACT_CANCEL
    je .close
    cmp eax,AIN_ACT_DETAILS
    je .details
    cmp eax,AIN_ACT_EXEC
    je .execution
    cmp eax,AIN_ACT_ALLOW
    je .install
    cmp eax,AIN_ACT_ASK
    jne .out
.install:
    jmp ain_install
.execution:
    jmp ain_execution_choice
.details:
    mov rdi,[rel ain_handle]
    call app_package_card_open
    ret
.finished:
    push rax
    call session_shell_local_authority
    mov rcx,rax
    pop rax
    cmp rcx,PRIN_OWNER
    jne .close
    cmp rdx,[rel ain_epoch]
    jne .close
    cmp eax,AIN_ACT_CANCEL
    jne .out
.close:
    jmp ain_close
.out:
    ret

; A separate original physical choice. This does not install or grant app
; permissions. The following Install decision must start a fresh dwell/Tab.
ain_execution_choice:
    cmp byte [rel ain_armed],1
    jne .disarm
    mov byte [rel ain_armed],0
    call ain_unchanged
    cmp eax,1
    jne .disarm
    mov rax,[rel ap_resident]
    test rax,rax
    jz .disarm
    cmp dword [rax+40],AIN_FLAGS_UNSIGNED
    jne .disarm
    xor byte [rel ain_exec_selected],1
    lea rsi,[rel ain_text_exec]
    cmp byte [rel ain_exec_selected],0
    je .text
    lea rsi,[rel ain_text_exec_yes]
.text:
    mov edi,[rel ain_ids+AIN_EXEC*4]
    call wgt_set_text
    call ain_disarm
    call time_monotonic_now_us
    mov [rel ain_opened_us],rax
    jmp wmx_draw_all
.disarm:
    jmp ain_disarm

; The dwell and the Tab mean the owner has had this card in front of them. Any
; time away restarts both, so what closes over it cannot pass a press through.
ain_slot_focused:
    mov eax,[rel ain_slot]
    cmp eax,[rel wm_focus]
    je .out
    mov byte [rel ain_tab],0
    call time_monotonic_now_us
    mov [rel ain_opened_us],rax
.out:
    ret

ain_widgets_current:
    xor ecx,ecx
    lea r8,[rel ain_ids]
.loop:
    mov eax,[r8+rcx*4]
    cmp eax,[rel wgt_count]
    jae .bad
    imul rax,WGI_SZ
    lea rdx,[rel wgt_tbl]
    add rax,rdx
    mov edx,[rel ain_slot]
    cmp [rax+WGI_WIN],edx
    jne .bad
    mov edx,3
    cmp ecx,AIN_ALLOW
    jb .type
    mov edx,1
.type:
    cmp [rax+WGI_TYPE],edx
    jne .bad
    inc ecx
    cmp ecx,AIN_COUNT
    jb .loop
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EAX1 while the same owner and exact candidate stand. Checks trust live: the
; verifier retires its candidate when the author verdict changed under it.
ain_current:
    cmp qword [rel ain_handle],0
    je .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rel ain_epoch]
    jne .bad
    mov rdi,[rel ain_handle]
    lea rsi,[rel ain_now]
    mov edx,704
    call app_package_descriptor
    cmp eax,1
    jne .bad
    lea rsi,[rel ain_now+32]
    lea rdi,[rel ain_package+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    mov rax,[rel ain_now+80]
    cmp rax,[rel ain_package+80]
    jne .bad
    mov rdi,[rel ain_handle]
    lea rsi,[rel ain_analysis]
    call app_analysis_check
    cmp eax,1
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

ain_intent_clear:
    mov byte [rel ain_exec_selected],0
    mov qword [rel ain_intent],0
    ret

; EDI choice ALLOW1/ASK2 -> RAX intent id, 0 refused. Native origin rule: a
; Terminal-origin candidate can never carry ALLOW, whatever a card displayed.
ain_intent_build:
    mov qword [rel ain_intent],0
    cmp edi,AIN_SELECT_ALLOW
    je .choice
    cmp edi,AIN_SELECT_ASK
    jne .bad
.choice:
    xor ecx,ecx
    lea rsi,[rel ain_requested]
    lea rdx,[rel ain_selected]
.row:
    xor eax,eax
    cmp byte [rsi+rcx],0
    cmovne eax,edi
    mov [rdx+rcx],al
    cmp dword [rel ain_origin],AIN_ORIGIN_TERMINAL
    jne .next
    cmp al,AIN_SELECT_ALLOW
    je .bad
.next:
    inc ecx
    cmp ecx,4
    jb .row
    call ain_current
    cmp eax,1
    jne .bad
    mov rax,[rel ain_intent_serial]
    inc rax
    jz .bad
    mov [rel ain_intent_serial],rax
    mov [rel ain_intent],rax
    ret
.bad:
    mov dword [rel ain_selected],0
    xor eax,eax
    ret

; RDI intent id -> EAX1 exactly valid, 0 refuse. Repeatable: FS asks fresh before
; every physical effect. A failure ends the intent.
app_install_intent_check:
    push rbx
    mov rbx,rdi
    call smp_current_logical
    test eax,eax
    jnz .refuse
    test rbx,rbx
    jz .refuse
    cmp rbx,[rel ain_intent]
    jne .refuse
    cmp byte [rel cmd_in_dispatch],0
    jne .fail
    cmp dword [rel cmd_dispatch_depth],0
    jne .fail
    cmp dword [rel ain_state],AIN_DECIDING
    jne .fail
    call ain_current
    cmp eax,1
    jne .fail
    mov eax,1
    jmp .out
.fail:
    call ain_intent_clear
.refuse:
    xor eax,eax
.out:
    pop rbx
    ret

; Fixed native writer views of the exact still-current physical decision.
; No private candidate pointer escapes; caller owns mapped stable output bytes.
; descriptor(intent,out704,exact704) / copy(intent,out,exact whole length)->1/0.
; Only1 writes. These functions never manufacture or consume human intent.
app_install_store_descriptor:
    push r12
    mov r12,rsi
    cmp rdx,704
    jne .bad
    call ain_store_span
    test eax,eax
    jz .bad
    call app_install_intent_check
    cmp eax,1
    jne .bad
    mov rdi,[rel ain_handle]
    mov rsi,r12
    mov edx,704
    call app_package_descriptor
    pop r12
    ret
.bad:
    xor eax,eax
    pop r12
    ret
; RDI original intent -> RAX0 no choice,1 owner chose unsigned execution,
; -1 invalid. No caller flag/hash/receipt can supply the policy. The durable
; writer must check the copied bytes again and publish only after commit.
app_install_store_execution_policy:
    call app_install_intent_check
    cmp eax,1
    jne .bad
    movzx eax,byte [rel ain_exec_selected]
    test eax,eax
    jz .out
    cmp eax,1
    jne .bad
    mov rcx,[rel ap_resident]
    test rcx,rcx
    jz .bad
    cmp dword [rcx+40],AIN_FLAGS_UNSIGNED
    jne .bad
    mov eax,1
.out:
    ret
.bad:
    mov rax,-1
    ret

app_install_store_copy:
    push r12
    push r13
    mov r12,rsi
    mov r13,rdx
    test r13,r13
    jz .bad
    cmp r13,AIN_MAX
    ja .bad
    call ain_store_span
    test eax,eax
    jz .bad
    call app_install_intent_check
    cmp eax,1
    jne .bad
    cmp r13,[rel ap_length]
    jne .bad
    mov rdi,[rel ain_handle]
    xor esi,esi
    mov rdx,r12
    mov rcx,r13
    call app_package_copy
    pop r13
    pop r12
    ret
.bad:
    xor eax,eax
    pop r13
    pop r12
    ret
; RSI output,RDX length. Preserve intent RDI and output arguments.
ain_store_span:
    test rsi,rsi
    jz .no
    mov rax,rsi
    add rax,rdx
    jc .no
    lea rcx,[rel ain_private_data_end]
    cmp rsi,rcx
    jae .bss
    lea rcx,[rel ain_private_data_begin]
    cmp rax,rcx
    ja .no
.bss:
    lea rcx,[rel ain_private_bss_end]
    cmp rsi,rcx
    jae .yes
    lea rcx,[rel ain_private_bss_begin]
    cmp rax,rcx
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; RDI intent id -> EAX1 spent now, 0 never held or already spent. GUI consumes
; once when the complete store call ends, including an uncertain result.
app_install_intent_consume:
    test rdi,rdi
    jz .refuse
    cmp rdi,[rel ain_intent]
    jne .refuse
    mov qword [rel ain_intent],0
    mov byte [rel ain_exec_selected],0
    mov eax,1
    ret
.refuse:
    xor eax,eax
    ret

; Tail of app_install_tick. EAX action. The human decision meets the store here.
ain_install:
    push rbx
    mov ebx,eax
    cmp byte [rel ain_armed],1
    jne .disarm
    mov byte [rel ain_armed],0
    call ain_unchanged
    cmp eax,1
    jne .disarm
    mov rdi,[rel ain_handle]
    mov esi,AIN_PROFILE
    call app_install_grants_room
    cmp eax,1
    je .room
    lea rsi,[rel ain_text_failed]
    cmp eax,2
    jne .finish
    lea rsi,[rel ain_text_full]
    jmp .finish
.room:
    mov edi,AIN_SELECT_ALLOW
    cmp ebx,AIN_ACT_ALLOW
    je .build
    mov edi,AIN_SELECT_ASK
.build:
    call ain_intent_build
    test rax,rax
    jz .disarm
    mov rbx,rax
    xor eax,eax
    mov rdx,[rel app_install_store]
    test rdx,rdx
    jz .result
    mov rdi,rbx
    mov rsi,[rel ap_resident]
    mov rdx,[rel ap_length]
    call [rel app_install_store]
.result:
    mov rdi,rbx
    mov rbx,rax
    call app_install_intent_consume
    cmp rbx,1
    je .committed
    lea rsi,[rel ain_text_failed]
    cmp qword [rel app_install_store],0
    jne .not_saved
    lea rsi,[rel ain_text_no_store]
.not_saved:
    cmp rbx,2
    jne .finish
    lea rsi,[rel ain_text_uncertain]
    jmp .finish
.committed:
    call ain_current
    cmp eax,1
    jne .committed_no_grant
    mov rdi,[rel ain_handle]
    mov esi,AIN_PROFILE
    lea rdx,[rel ain_selected]
    mov rcx,[rel ain_epoch]
    lea r8,[rel ain_analysis]
    call app_install_grants_remember
    test rax,rax
    jz .committed_no_grant
    mov rdi,[rel ain_handle]
    mov esi,AIN_PROFILE
    mov rdx,[rel ain_epoch]
    lea rcx,[rel ain_analysis]
    call app_install_grants_save
    lea rsi,[rel ain_text_installed]
    cmp eax,1
    je .finish
    lea rsi,[rel ain_text_ram_grant]
    jmp .finish
.committed_no_grant:
    lea rsi,[rel ain_text_no_grant]
.finish:
    pop rbx
    jmp ain_finish
.disarm:
    call ain_disarm
    pop rbx
    ret

; RSI status text. Only Close stays live; the candidate is finished with.
ain_finish:
    mov edi,[rel ain_ids+AIN_L_STATUS*4]
    call wgt_set_text
    mov edi,[rel ain_ids+AIN_ALLOW*4]
    call wgt_slot_ptr
    and dword [rax+WGI_FLAGS],~1
    mov edi,[rel ain_ids+AIN_ASK*4]
    call wgt_slot_ptr
    and dword [rax+WGI_FLAGS],~1
    mov edi,[rel ain_ids+AIN_DETAILS*4]
    call wgt_slot_ptr
    and dword [rax+WGI_FLAGS],~1
    mov edi,[rel ain_ids+AIN_EXEC*4]
    call wgt_slot_ptr
    and dword [rax+WGI_FLAGS],~1
    mov edi,[rel ain_ids+AIN_CANCEL*4]
    lea rsi,[rel ain_text_close]
    call wgt_set_text
    mov dword [rel ain_state],AIN_FINISHED
    jmp wmx_draw_all

; Builds the window on the current focus: an offer never takes the keyboard.
ain_build:
    push rbx
    push r12
    push r13
    push r14
    cmp dword [rel fb_width],AIN_WIDTH
    jb .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    cmp eax,AIN_TOP+AIN_HEIGHT
    jb .bad
    mov r14d,[rel wm_focus]
    lea rdi,[rel ain_title]
    xor esi,esi
    mov edx,AIN_TOP
    mov ecx,AIN_WIDTH
    mov r8d,AIN_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .bad
    mov r12d,eax
    mov [rel ain_slot],eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+r12*4]
    mov [rel ain_gen],eax
    lea rcx,[rel wm_owner]
    mov qword [rcx+r12*8],WM_OWNER_CHROME
    mov [rel wm_focus],r14d
    mov edi,AIN_COUNT
    call wgt_reserve_run
    test eax,eax
    js .bad
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.widgets:
    mov edi,2
    cmp ebx,AIN_ALLOW
    jb .type
    xor edi,edi
.type:
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .bad_widgets
    lea rcx,[rel ain_ids]
    mov [rcx+rbx*4],eax
    mov edi,eax
    call wgt_slot_ptr
    mov r13,rax
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_LAYER],0          ; as af_build: a reused row may keep an overlay's layer
    mov dword [rax+WGI_EDIT],WGT_EDIT_ASCII
    mov dword [rax+WGI_X],8
    mov dword [rax+WGI_W],544
    mov dword [rax+WGI_H],18
    cmp ebx,AIN_ALLOW
    jae .button
    mov eax,ebx
    imul eax,22
    add eax,GUI_TITLE_H+4                ; below the title strip, SEC 90177
    mov [r13+WGI_Y],eax
    mov edi,ebx
    call ain_line_for
    jmp .next_widget
.button:
    mov dword [r13+WGI_Y],352
    mov dword [r13+WGI_H],30
    cmp ebx,AIN_EXEC
    jne .permissions
    mov dword [r13+WGI_Y],320
    lea rsi,[rel ain_text_exec]
    mov edx,8
    mov ecx,544
    jmp .place
.permissions:
    lea rsi,[rel ain_text_allow]
    mov edx,8
    mov ecx,160
    cmp ebx,AIN_ALLOW
    je .place
    lea rsi,[rel ain_text_ask]
    mov edx,176
    mov ecx,200
    cmp ebx,AIN_ASK
    je .place
    lea rsi,[rel ain_text_cancel]
    mov edx,384
    mov ecx,80
    cmp ebx,AIN_CANCEL
    je .place
    lea rsi,[rel ain_text_details]
    mov edx,472
.place:
    mov [r13+WGI_X],edx
    mov [r13+WGI_W],ecx
    lea rax,[rel ain_ids]
    mov edi,[rax+rbx*4]
    call wgt_set_text
    jmp .next_widget
.next_widget:
    lea rdx,[rel wm_x]                   ; widget rects are absolute, Q 90176
    mov eax,[rdx+r12*4]
    add [r13+WGI_X],eax
    lea rdx,[rel wm_y]
    mov eax,[rdx+r12*4]
    add [r13+WGI_Y],eax
    inc ebx
    cmp ebx,AIN_COUNT
    jb .widgets
    cmp dword [rel ain_origin],AIN_ORIGIN_FILE
    je .buttons_done
    mov edi,[rel ain_ids+AIN_ALLOW*4]
    call wgt_slot_ptr
    and dword [rax+WGI_FLAGS],~1        ; origin 2 has no such button at all
.buttons_done:
    mov rax,[rel ap_resident]
    cmp dword [rax+40],AIN_FLAGS_UNSIGNED
    je .execution_shown
    mov edi,[rel ain_ids+AIN_EXEC*4]
    call wgt_slot_ptr
    and dword [rax+WGI_FLAGS],~1
.execution_shown:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    mov eax,[rel ain_ids+AIN_CANCEL*4]
    lea rcx,[rel wgt_focus_by_win]
    mov [rcx+r12*4],eax
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    mov [rel ain_opened_us],rax
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel ain_open_ptr_inj],eax
    mov eax,[rel keyprov_inj_seq]
    mov [rel ain_open_key_inj],eax
    mov eax,1
    jmp .out
.bad_widgets:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; EDI label index. Sets that label's text and warning colour.
ain_line_for:
    push rbx
    push r12
    mov ebx,edi
    lea rdi,[rel ain_line]
    xor eax,eax
    mov ecx,5
    cld
    rep stosq
    lea rdi,[rel ain_line]
    cmp ebx,AIN_L_NAME
    je .name
    cmp ebx,AIN_L_VERSION
    je .version
    cmp ebx,AIN_L_AUTHOR
    je .author
    cmp ebx,AIN_L_FROM
    je .from
    lea eax,[rbx-AIN_L_PERMS]
    cmp eax,5
    jb .perm
    cmp ebx,AIN_L_NOTE
    je .note
    cmp ebx,AIN_L_STATUS
    je .ask_note
    test ebx,ebx
    jnz .emit
    lea rsi,[rel ain_text_head]
    call ain_copy_z
    jmp .emit
.name:
    lea rsi,[rel ain_text_name]
    call ain_copy_z
    lea rsi,[rel ain_package+192+256]
    mov ecx,96
    call ain_copy_field
    jmp .emit
.version:
    lea rsi,[rel ain_text_version]
    call ain_copy_z
    lea rsi,[rel ain_package+192+352]
    mov ecx,32
    call ain_copy_field
    jmp .emit
.author:
    lea rsi,[rel ain_text_unknown]
    cmp qword [rel ain_package+80],1
    jne .author_text
    lea rsi,[rel ain_text_enrolled]
.author_text:
    call ain_copy_z
    jmp .warn_unknown
.from:
    lea rsi,[rel ain_text_from_file]
    cmp dword [rel ain_origin],AIN_ORIGIN_FILE
    je .from_text
    lea rsi,[rel ain_text_from_terminal]
.from_text:
    call ain_copy_z
    jmp .emit
.perm:
    test eax,eax
    jnz .perm_row
    lea rsi,[rel ain_text_perm_none]
    cmp dword [rel ain_requested],0
    je .perm_text
    lea rsi,[rel ain_text_perm_head]
.perm_text:
    call ain_copy_z
    jmp .emit
.perm_row:
    dec eax
    lea rcx,[rel ain_requested]
    cmp byte [rcx+rax],0
    je .emit
    lea rcx,[rel ain_perm_rows]
    movsxd rax,dword [rcx+rax*4]
    lea rsi,[rcx+rax]
    call ain_copy_z
    jmp .emit
.note:
    cmp qword [rel ain_analysis+144],0
    je .emit
    lea rsi,[rel ain_text_note_unresolved]
    call ain_copy_z
    mov r12d,1
    jmp .emit_flag
.ask_note:
    lea rsi,[rel ain_text_note_ask]
    call ain_copy_z
    jmp .emit
.warn_unknown:
    xor r12d,r12d
    cmp qword [rel ain_package+80],1
    setne r12b
    jmp .emit_flag
.emit:
    xor r12d,r12d
.emit_flag:
    lea rax,[rel ain_ids]
    mov edi,[rax+rbx*4]
    call wgt_slot_ptr
    test r12d,r12d
    jz .plain
    or dword [rax+WGI_EDIT],WGT_EDIT_WARNING
.plain:
    lea rax,[rel ain_ids]
    mov edi,[rax+rbx*4]
    lea rsi,[rel ain_line]
    call wgt_set_text
    pop r12
    pop rbx
    ret

; RDI cursor. Copies NUL text, never past the 31 bytes a label holds.
ain_copy_z:
    lea rax,[rel ain_line+31]
.loop:
    cmp rdi,rax
    jae .out
    mov dl,[rsi]
    test dl,dl
    jz .out
    mov [rdi],dl
    inc rsi
    inc rdi
    jmp .loop
.out:
    ret

; RDI cursor, RSI verified printable field, ECX bound. A longer field ends in ...
; so a shortened name cannot pass as a complete one.
ain_copy_field:
    lea rax,[rel ain_line+31]
.loop:
    test ecx,ecx
    jz .out
    mov dl,[rsi]
    test dl,dl
    jz .out
    cmp rdi,rax
    jae .long
    mov [rdi],dl
    inc rsi
    inc rdi
    dec ecx
    jmp .loop
.long:
    mov dword [rax-3],0x002e2e2e
.out:
    ret

; Owner file source. The verb only queues; bytes are read at idle depth zero.
cmd_verb_appinstall:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov qword [r13+RSP_CODE],CMDE_AUTHDENY
    mov qword [r13+RSP_VAL],0
    cmp byte [rel cmd_in_dispatch],1
    jne .out
    cmp qword [r12+REQ_SOURCE],CMD_SOURCE_CONSOLE
    jne .out
    cmp qword [r12+REQ_PRINCIPAL],PRIN_OWNER
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    mov r8,rdx
    mov rbx,[r12+REQ_ARG]
    test rbx,rbx
    jz .badarg
    cmp byte [rbx],'/'
    je .path
    lea rsi,[rel ain_status_word]
    xor ecx,ecx
.status_word:
    mov al,[rsi+rcx]
    cmp al,[rbx+rcx]
    jne .badarg
    inc ecx
    test al,al
    jnz .status_word
    mov eax,[rel ain_file_status]
    mov [r13+RSP_VAL],rax
    mov qword [r13+RSP_CODE],CMDE_OK
    jmp .out
.path:
    cmp byte [rbx+1],0
    je .badarg
    xor ecx,ecx
.length:
    movzx eax,byte [rbx+rcx]
    test al,al
    jz .bounded
    cmp ecx,AIN_PATH_MAX
    jae .badarg
    cmp al,' '
    jb .badarg
    cmp al,'~'
    ja .badarg
    inc ecx
    jmp .length
.bounded:
    cmp byte [rel ain_file_pending],0
    jne .badarg
    mov [rel ain_file_epoch],r8
    mov [rel ain_file_length],ecx
    mov eax,[rel vfs_disk_handle]
    cmp eax,-1
    je .badarg
    mov [rel ain_file_mount],eax
    lea rdi,[rel ain_file_path]
    mov rsi,rbx
    inc ecx
    cld
    rep movsb
    call time_monotonic_now_us
    test rax,rax
    jz .badarg
    add rax,AIN_BOUND_US
    mov [rel ain_file_deadline],rax
    mov byte [rel ain_file_pending],1
    mov dword [rel ain_file_status],AIN_FILE_QUEUED
    mov qword [r13+RSP_CODE],CMDE_OK
    mov qword [r13+RSP_VAL],AIN_FILE_QUEUED
    jmp .out
.badarg:
    mov qword [r13+RSP_CODE],CMDE_BADARG
.out:
    pop r13
    pop r12
    pop rbx
    ret

ain_file_current:
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rel ain_file_epoch]
    jne .bad
    mov eax,[rel vfs_disk_handle]
    cmp eax,[rel ain_file_mount]
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel ain_file_deadline]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; One bounded read then the common offer. Reused storage keeps no payload.
ain_file_tick:
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp byte [rel ain_file_pending],1
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    mov byte [rel ain_file_pending],0
    mov dword [rel ain_file_status],AIN_FILE_REFUSED
    call ain_file_current
    cmp eax,1
    jne .done
    cmp qword [rel ain_file_bytes],0
    jne .allocated
    mov edi,AIN_MAX
    call kmalloc
    test rax,rax
    jz .done
    mov [rel ain_file_bytes],rax
.allocated:
    mov edi,[rel ain_file_mount]
    lea rsi,[rel ain_file_path]
    mov edx,[rel ain_file_length]
    lea rcx,[rel ain_file_stat]
    call vfs_stat_path
    test rax,rax
    jnz .done
    mov rax,[rel ain_file_stat+fs_stat.size]
    cmp rax,AIN_MAX
    ja .done
    mov [rel ain_file_size],rax
    mov edi,[rel ain_file_mount]
    lea rsi,[rel ain_file_path]
    mov edx,[rel ain_file_length]
    xor ecx,ecx
    mov r8,[rel ain_file_bytes]
    mov r9,rax
    call vfs_read_at_path
    cmp rax,[rel ain_file_size]
    jne .done
    call ain_file_current
    cmp eax,1
    jne .done
    mov rdi,[rel ain_file_bytes]
    mov rsi,[rel ain_file_size]
    mov edx,AIN_ORIGIN_FILE
    call app_install_offer
    cmp eax,1
    jne .done
    mov dword [rel ain_file_status],AIN_FILE_SHOWN
.done:
    lea rdi,[rel ain_file_path]
    xor eax,eax
    mov ecx,256/8
    cld
    rep stosq
    mov rdi,[rel ain_file_bytes]
    test rdi,rdi
    jz .out
    mov ecx,AIN_MAX/8
    rep stosq
.out:
    ret

ain_verb: db 'APPINSTALL',0
ain_status_word: db 'STATUS',0
ain_title: db 'Allow this?',0
ain_text_head: db 'You want to install this app.',0
ain_text_name: db 'Name: ',0
ain_text_version: db 'Version: ',0
ain_text_unknown: db 'Unknown author',0
ain_text_enrolled: db 'Enrolled signing key',0
ain_text_from_file: db 'From: file you chose',0
ain_text_from_terminal: db 'From: Linux Terminal on this PC',0
ain_text_perm_head: db 'This app asks for:',0
ain_text_perm_none: db 'This app asks for nothing',0
ain_text_note_ask: db 'Ask each time: no window text',0
ain_text_note_unresolved: db 'Unknown uses: see Details',0
ain_text_exec: db 'Allow unsigned app to run',0
ain_text_exec_yes: db 'Unsigned app run allowed',0
ain_text_allow: db 'Install and allow',0
ain_text_ask: db 'Install, ask each time',0
ain_text_cancel: db 'Cancel',0
ain_text_details: db 'Details',0
ain_text_close: db 'Close',0
ain_text_installed: db 'Installed',0
ain_text_failed: db 'Not installed',0
ain_text_no_store: db 'Not installed: no app storage',0
ain_text_full: db 'Not installed: 8 apps at most',0
ain_text_uncertain: db 'May have installed; no access',0
ain_text_no_grant: db 'Installed; no access granted',0
ain_text_ram_grant: db 'Installed; access until restart',0
ain_perm_status: db 'WAIT STATUS',0
ain_perm_begin: db 'WAIT BEGIN and own window text',0
ain_perm_poll: db 'WAIT POLL',0
ain_perm_cancel: db 'WAIT CANCEL',0
align 4, db 0
ain_perm_rows: dd ain_perm_status-ain_perm_rows,ain_perm_begin-ain_perm_rows,ain_perm_poll-ain_perm_rows,ain_perm_cancel-ain_perm_rows
%include "core/abi/wdata.inc"
%macro WDATA_app_install 0
align 8, db 0
ain_private_data_begin:
ain_prev_filter: dq 0
ain_prev_click: dq 0
app_install_store: dq 0                ; FS commit: RDI intent, RSI bytes, RDX length -> 1/0/2
ain_handle: dq 0
ain_epoch: dq 0
ain_intent: dq 0
ain_intent_serial: dq 0
ain_opened_us: dq 0
ain_arm_xy: dq 0
ain_arm_fb: dq 0
ain_file_bytes: dq 0
ain_file_size: dq 0
ain_file_epoch: dq 0
ain_file_deadline: dq 0
ain_slot: dd -1
ain_gen: dd 0
ain_state: dd AIN_IDLE
ain_origin: dd 0
ain_arm_z: dd 0
ain_arm_inj: dd 0
ain_open_ptr_inj: dd 0
ain_open_key_inj: dd 0
ain_file_status: dd AIN_FILE_IDLE
ain_file_length: dd 0
ain_file_mount: dd -1
ain_ids: times AIN_COUNT dd -1
ain_initialized: db 0
ain_action: db 0
ain_armed: db 0
ain_tab: db 0
ain_file_pending: db 0
ain_exec_selected: db 0
ain_private_data_end:
%endmacro
WDATA_DEFER WDATA_app_install
%macro WDATA_app_install_bss 0
alignb 8
ain_private_bss_begin:
ain_scrub_start:
ain_analysis: resb 192
ain_package: resb 704
ain_now: resb 704
ain_requested: resb 4
ain_selected: resb 4
ain_scrub_end:
ain_line: resb 40
ain_file_path: resb 256
ain_file_stat: resb fs_stat_size
ain_private_bss_end:
%endmacro
WDATA_BSS_DEFER WDATA_app_install_bss

%include "gui/app_store_observe.asm"
%include "gui/app_installed.asm"
