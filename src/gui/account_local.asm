;; MODULE gui/account_local
;; LAYER 6
;; PURPOSE Native owner account approval and original secret-editor custody.
;; EXPORTS account_local_consume, account_local_init, account_local_offer, account_local_tick, account_local_wipe, account_local_close, account_policy_copy
;; IMPORTS gui/app_account_sink, data/crypto_envelope, core/lib/hkdf_sha256, sec/principal, sec/account_secret, sec/session, sec/app_binding, hv/app_vm, svc/command, gui/widget, gui/window_mgmt, gui/window, gui/chat_app, sec/keyprov, core/smp, core/time, core/lib/mem, core/lib/fmt, dev/input/ps2, boot/gop
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Session-only native record. No guest/command getter or disk IO.
; Only the fixed native protected sink can receive the authenticated private frame.
ACL_COUNT equ 15
ACL_ACCOUNT equ 6
ACL_HOST equ 8
ACL_SECRET equ 10
ACL_ALLOW equ 12
ACL_CANCEL equ 13
ACL_WIDTH equ 620
ACL_HEIGHT equ 548
ACL_TOP equ 48
ACL_DWELL_US equ 400000

; Native composition only; the separate account eraser must never replace WiFi.
account_local_init:
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel acl_initialized],0
    jne .ok
    lea rdi,[rel account_local_wipe]
    call session_shell_register_account_wipe
    cmp eax,1
    jne .bad
    mov rax,[rel wgt_key_filter]
    mov [rel acl_prev_key],rax
    lea rax,[rel acl_key]
    mov [rel wgt_key_filter],rax
    mov rax,[rel wgt_click_hook]
    mov [rel acl_prev_click],rax
    lea rax,[rel acl_click]
    mov [rel wgt_click_hook],rax
    mov byte [rel acl_initialized],1
.ok:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; No authority supplied by request words: re-read both actual native providers.
; RDI actual numeric app instance. Opening the card authorizes nothing.
account_local_offer:
    push rbx
    push r12
    push r13
    mov r12,rdi
    call acl_guard
    cmp eax,1
    jne .bad
    cmp byte [rel acl_initialized],1
    jne .bad
    cmp byte [rel acl_busy],0
    jne .bad
    cmp byte [rel acp_busy],0
    jne .bad
    cmp qword [rel acl_generation],-2
    jae .bad
    ; Never take over another original private editor/draft.
    cmp dword [rel wgt_secret_owner],-1
    jne .bad
    test r12,r12
    jz .bad
    mov byte [rel acl_busy],1
    call account_local_wipe
    call acl_close
    mov [rel acl_instance],r12
    call session_shell_local_authority
    mov [rel acl_epoch],rdx
    mov rdi,r12
    lea rsi,[rel acl_vm]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .fail
    lea rdi,[rel acl_binding]
    call app_binding_observe
    cmp eax,1
    jne .fail
    call acl_current
    cmp eax,1
    jne .fail
    call acl_build
    cmp eax,1
    jne .fail
    mov byte [rel acl_draft],1
    call wmx_draw_all
    mov byte [rel acl_busy],0
    mov eax,1
    jmp .out
.fail:
    call account_local_wipe
    call acl_close
    mov byte [rel acl_busy],0
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

acl_guard:
    sub rsp,8
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
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret

; Stable original identity includes full VM descriptor and original binding
; window/raw-generation/form-birth/grant-generation, excluding only timestamp.
acl_current:
    push rbx
    call acl_guard
    cmp eax,1
    jne .bad
    cmp rdx,[rel acl_epoch]
    jne .bad
    mov rdi,[rel acl_instance]
    lea rsi,[rel acl_now_vm]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    lea rdi,[rel acl_now_vm]
    lea rsi,[rel acl_vm]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    lea rdi,[rel acl_now_binding]
    call app_binding_observe
    cmp eax,1
    jne .bad
    lea rdi,[rel acl_now_binding]
    lea rsi,[rel acl_binding]
    mov ecx,14
    repe cmpsq
    jne .bad
    cmp qword [rel acl_vm],1
    jne .bad
    cmp qword [rel acl_binding],1
    jne .bad
    cmp qword [rel acl_vm+48],PRIN_OWNER
    jne .bad
    mov rax,[rel acl_epoch]
    cmp rax,[rel acl_vm+40]
    jne .bad
    cmp rax,[rel acl_binding+32]
    jne .bad
    mov rax,[rel acl_instance]
    cmp rax,[rel acl_vm+56]
    jne .bad
    cmp rax,[rel acl_binding+64]
    jne .bad
    mov rax,[rel acl_vm+8]
    cmp rax,[rel acl_binding+8]
    jne .bad
    mov rax,[rel acl_vm+24]
    cmp rax,[rel acl_binding+16]
    jne .bad
    mov rax,[rel acl_vm+32]
    cmp rax,[rel acl_binding+24]
    jne .bad
    lea rdi,[rel acl_vm+64]
    lea rsi,[rel acl_binding+72]
    mov ecx,4
    repe cmpsq
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

acl_scan:
    mov eax,[rel acl_slot]
    cmp eax,WM_MAX
    jae .bad
    lea rcx,[rel wm_title]
    lea rdx,[rel acl_title]
    cmp [rcx+rax*8],rdx
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+rax*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_gen]
    mov edx,[rel acl_rawgen]
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

; All created rows retain their original nonreused birth, host and stock type.
acl_widgets:
    push rbx
    xor ebx,ebx
.loop:
    lea rax,[rel acl_ids]
    mov edi,[rax+rbx*4]
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    lea rcx,[rel acl_births]
    cmp rax,[rcx+rbx*8]
    jne .bad
    lea rax,[rel acl_ids]
    mov edi,[rax+rbx*4]
    call wgt_slot_ptr
    mov ecx,[rel acl_slot]
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
    lea rcx,[rel acl_types]
    mov ecx,[rcx+rbx*4]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .bad
    ; Native card geometry is fixed: moves/resizes must never leave labels apart.
    lea rcx,[rel acl_rects]
    mov edx,ebx
    shl edx,4
    add rcx,rdx
    mov rdx,[rax+WGI_X]
    cmp rdx,[rcx]
    jne .bad
    mov rdx,[rax+WGI_W]
    cmp rdx,[rcx+8]
    jne .bad
    cmp ebx,ACL_ACCOUNT
    je .next
    cmp ebx,ACL_HOST
    je .next
    cmp ebx,ACL_SECRET
    je .next
    lea rsi,[rax+WGI_VLEN]
    lea rdi,[rel acl_texts]
    imul edx,ebx,44
    add rdi,rdx
    mov ecx,11
    cld
    repe cmpsd
    jne .bad
.next:
    inc ebx
    cmp ebx,ACL_COUNT
    jb .loop
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; WM pre-retirement hook, before any row is freed. Only our exact draft window.
; The card's own successful close sets draft=0 before reaching WM, preserving
; the separately published encrypted account record. No recursive window close.
account_local_close:
    push rbx
    mov ebx,edi
    cmp byte [rel acl_draft],1
    jne .out
    call acl_scan
    cmp eax,-1
    je .out
    cmp eax,ebx
    jne .out
    call account_local_wipe
.out:
    pop rbx
    ret

acl_close:
    sub rsp,8
    call acl_erase_editor
    mov byte [rel acl_draft],0
    mov byte [rel acl_action],0
    mov byte [rel acl_tab],0
    call acl_scan
    mov dword [rel acl_slot],-1
    cmp eax,-1
    je .out
    mov edi,eax
    call wmx_close_slot
.out:
    add rsp,8
    ret

; Erase only this exact original secret row. Never erase a recycled/foreign draft.
acl_erase_editor:
    sub rsp,8
    cmp dword [rel acl_slot],-1
    je .out
    mov edi,[rel acl_ids+ACL_SECRET*4]
    cmp edi,[rel wgt_secret_owner]
    jne .out
    call wgt_birth_lifetime
    test rax,rax
    jz .out
    cmp rax,[rel acl_births+ACL_SECRET*8]
    jne .out
    call wgt_secret_clear
.out:
    add rsp,8
    ret

; Synchronous downward session eraser. No UI/provider/transport/storage callback.
; Counter survives erasure, so old TCP custody can never inherit reapproval.
account_local_wipe:
    sub rsp,8
    mov byte [rel acl_approved],0
    mov byte [rel acl_draft],0
    mov byte [rel acl_action],0
    mov byte [rel acl_tab],0
    cmp qword [rel acl_generation],-1
    je .counter
    inc qword [rel acl_generation]
.counter:
    call acl_erase_editor
    lea rdi,[rel acl_record]
    xor esi,esi
    mov edx,832
    call memset
    lea rdi,[rel acl_scope]
    xor esi,esi
    mov edx,132
    call memset
    lea rdi,[rel acl_host]
    xor esi,esi
    mov edx,256
    call memset
    mov qword [rel acl_queued_revision],0
    ; Synchronous account revocation erases any consumer plaintext as well.
    call acp_plain_wipe
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
    ; Approval/generation/plaintext are already invalid. No policy reentry,
    ; new OWNER admission or guest cooperation in this native containment hook.
    call app_account_recipient_revoke
%endif
    add rsp,8
    ret

; Native-only policy ABI. Supplied snapshot is a comparison, never authority.
; Valid native buffers are disjoint from module private ranges and each other.
account_policy_copy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14d,edx
    mov r15d,ecx
    test r13,r13
    jz .bad
    cmp r14d,256
    jne .bad
    mov rdi,r13
    xor esi,esi
    mov edx,256
    call memset
    test r12,r12
    jz .bad
    cmp r15d,993
    je .port
    cmp r15d,465
    jne .bad
.port:
    call acl_guard
    cmp eax,1
    jne .bad
    cmp byte [rel acl_busy],0
    jne .bad
    cmp byte [rel acl_approved],1
    jne .bad
    mov byte [rel acl_busy],1
    call acl_current
    cmp eax,1
    jne .retire
    mov rdi,r12
    lea rsi,[rel acl_vm]
    mov ecx,16
    cld
    repe cmpsq
    jne .unlock
.copy:
    mov rdi,r13
    lea rsi,[rel acl_host]
    mov edx,256
    call memcpy
    mov byte [rel acl_busy],0
    mov rdx,[rel acl_generation]
    mov eax,1
    jmp .out
.retire:
    call account_local_wipe
.unlock:
    mov byte [rel acl_busy],0
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; No pointer gesture authorizes a secret. Only explicit human Tab then Enter.
acl_click:
    push rbx
    mov ebx,edi
    call acl_scan
    cmp eax,-1
    je .chain
    mov edi,ebx
    cmp edi,[rel wgt_count]
    jae .chain
    mov ecx,eax
    call wgt_slot_ptr
    cmp [rax+WGI_WIN],ecx
    jne .chain
    mov byte [rel acl_tab],0
    mov byte [rel acl_action],0
    pop rbx
    ret
.chain:
    mov edi,ebx
    pop rbx
    mov rax,[rel acl_prev_click]
    test rax,rax
    jz .out
    jmp rax
.out:
    ret

acl_key:
    push rbx
    push r12
    push r13
    mov r12d,edi
    mov r13d,eax
    call acl_scan
    cmp eax,-1
    je .chain
    mov ebx,eax
    mov edi,r12d
    cmp edi,[rel wgt_count]
    jae .chain
    call wgt_slot_ptr
    cmp [rax+WGI_WIN],ebx
    jne .chain
    cmp byte [rel acl_draft],1
    jne .taken
    cmp byte [rel input_key_origin],KO_HUMAN
    jne .disarm
    call acl_guard
    cmp eax,1
    jne .disarm
    cmp r13d,GUI_KEY_ESC
    je .cancel
    cmp r13d,GUI_KEY_TAB
    je .tab
    cmp r13d,GUI_KEY_ENTER
    je .enter
    mov byte [rel acl_tab],0
    mov byte [rel acl_action],0
    cmp r12d,[rel acl_ids+ACL_ACCOUNT*4]
    je .pass
    cmp r12d,[rel acl_ids+ACL_HOST*4]
    je .pass
    cmp r12d,[rel acl_ids+ACL_SECRET*4]
    je .pass
    jmp .taken
.tab:
    call acl_ok
    cmp eax,1
    jne .disarm
    call acl_dwelled
    cmp eax,1
    jne .disarm
    mov ecx,ACL_ACCOUNT
    cmp r12d,[rel acl_ids+ACL_CANCEL*4]
    je .select
    mov ecx,ACL_HOST
    cmp r12d,[rel acl_ids+ACL_ACCOUNT*4]
    je .select
    mov ecx,ACL_SECRET
    cmp r12d,[rel acl_ids+ACL_HOST*4]
    je .select
    mov ecx,ACL_ALLOW
    cmp r12d,[rel acl_ids+ACL_SECRET*4]
    je .select
    mov ecx,ACL_CANCEL
.select:
    lea rax,[rel acl_ids]
    mov eax,[rax+rcx*4]
    mov [rel wgt_focus_id],eax
    mov edx,[rel acl_slot]
    lea rdi,[rel wgt_focus_by_win]
    mov [rdi+rdx*4],eax
    mov byte [rel wgt_focus_visible],1
    call acl_snapshot
    mov byte [rel acl_tab],1
    call wmx_draw_all
    jmp .taken
.enter:
    cmp r12d,[rel wgt_focus_id]
    jne .disarm
    cmp r12d,[rel acl_ids+ACL_CANCEL*4]
    je .cancel
    cmp r12d,[rel acl_ids+ACL_ALLOW*4]
    jne .taken
    cmp byte [rel acl_tab],1
    jne .taken
    cmp byte [rel wgt_focus_visible],1
    jne .disarm
    call acl_unchanged
    cmp eax,1
    jne .disarm
    call acl_current
    cmp eax,1
    jne .disarm
    call wgt_secret_human
    cmp eax,1
    jne .disarm
    mov eax,[rel acl_ids+ACL_SECRET*4]
    cmp eax,[rel wgt_secret_owner]
    jne .disarm
    mov rax,[rel wgt_secret_revision]
    test rax,rax
    jz .disarm
    cmp rax,-1
    je .disarm
    mov [rel acl_queued_revision],rax
    mov byte [rel acl_action],1
    mov byte [rel acl_tab],0
    jmp .taken
.cancel:
    mov byte [rel acl_action],2
    jmp .taken
.disarm:
    mov byte [rel acl_tab],0
    mov byte [rel acl_action],0
.taken:
    mov eax,1
    jmp .out
.pass:
    xor eax,eax
    jmp .out
.chain:
    mov edi,r12d
    mov eax,r13d
    mov rdx,[rel acl_prev_key]
    pop r13
    pop r12
    pop rbx
    test rdx,rdx
    jz .none
    jmp rdx
.none:
    xor eax,eax
    ret
.out:
    pop r13
    pop r12
    pop rbx
    ret

account_local_tick:
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    cmp byte [rel acp_busy],0
    jne .out
    cmp byte [rel acl_busy],0
    jne .out
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
    ; Both account locks are free; policy-triggered wipe may contain the exact
    ; original recipient without recursive policy or a second main-loop path.
    call app_account_recipient_tick
%endif
    mov byte [rel acl_busy],1
    cmp byte [rel acl_draft],1
    jne .not_draft
    call acl_current
    cmp eax,1
    jne .fail
    call acl_scan
    cmp eax,-1
    je .fail
    call acl_widgets
    cmp eax,1
    jne .fail
    mov bl,[rel acl_action]
    mov byte [rel acl_action],0          ; consume before any effect
    cmp bl,2
    je .fail
    cmp bl,1
    jne .unlock
    call acl_unchanged
    cmp eax,1
    jne .fail
    mov rax,[rel acl_queued_revision]
    cmp rax,[rel wgt_secret_revision]
    jne .fail
    mov eax,[rel acl_ids+ACL_SECRET*4]
    cmp eax,[rel wgt_secret_owner]
    jne .fail
    call wgt_secret_human
    cmp eax,1
    jne .fail
    call acl_public_fields
    cmp eax,1
    jne .fail
    lea rdi,[rel acl_record]
    mov esi,832
    lea rdx,[rel acl_scope]
    lea rcx,[rel wgt_secret_bytes]
    mov r8d,[rel wgt_secret_len]
    call account_secret_seal
    test eax,eax
    jnz .fail
    call acl_current
    cmp eax,1
    jne .fail
    call acl_unchanged
    cmp eax,1
    jne .fail
    mov rax,[rel acl_queued_revision]
    cmp rax,[rel wgt_secret_revision]
    jne .fail
    cmp qword [rel acl_generation],-2
    jae .fail
    inc qword [rel acl_generation]
    mov byte [rel acl_approved],1        ; publication last, only ciphertext
    call acl_close
    jmp .unlock
.not_draft:
    cmp byte [rel acl_approved],1
    jne .close
    call acl_current
    cmp eax,1
    je .unlock
.fail:
    call account_local_wipe
.close:
    call acl_close
.unlock:
    mov byte [rel acl_busy],0
.out:
    pop rbx
    ret

; Account is exact printable nonspace ASCII; DNS host is canonical lowercase.
; Both are entered into original public stock rows on the trusted card.
acl_public_fields:
    push rbx
    lea rdi,[rel acl_scope]
    xor esi,esi
    mov edx,132
    call memset
    lea rdi,[rel acl_scope]
    lea rsi,[rel acl_vm+64]
    mov edx,32
    call memcpy
    lea rdi,[rel acl_host]
    xor esi,esi
    mov edx,256
    call memset
    mov edi,[rel acl_ids+ACL_ACCOUNT*4]
    call wgt_slot_ptr
    mov ecx,[rax+WGI_VLEN]
    test ecx,ecx
    jz .bad
    cmp ecx,WGT_TEXTFIELD_VAL_MAX
    ja .bad
    cmp byte [rax+WGI_VAL+rcx],0
    jne .bad
    mov [rel acl_scope+32],ecx
    lea rsi,[rax+WGI_VAL]
    lea rdi,[rel acl_scope+36]
.account:
    lodsb
    cmp al,0x21
    jb .bad
    cmp al,0x7e
    ja .bad
    stosb
    loop .account
    mov edi,[rel acl_ids+ACL_HOST*4]
    call wgt_slot_ptr
    mov ecx,[rax+WGI_VLEN]
    test ecx,ecx
    jz .bad
    cmp ecx,WGT_TEXTFIELD_VAL_MAX
    ja .bad
    cmp byte [rax+WGI_VAL+rcx],0
    jne .bad
    lea rsi,[rax+WGI_VAL]
    lea rdi,[rel acl_host]
    xor edx,edx                       ; bytes since last dot
    xor ebx,ebx                       ; previous character
.host:
    lodsb
    cmp al,'.'
    je .dot
    cmp al,'-'
    je .hyphen
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .char
    cmp al,'a'
    jb .bad
    cmp al,'z'
    ja .bad
.char:
    inc edx
    jmp .store
.hyphen:
    test edx,edx
    jz .bad
    inc edx
    jmp .store
.dot:
    test edx,edx
    jz .bad
    cmp bl,'-'
    je .bad
    xor edx,edx
.store:
    mov bl,al
    stosb
    loop .host
    test edx,edx
    jz .bad
    cmp bl,'-'
    je .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

acl_ok:
    sub rsp,8
    call acl_widgets
    cmp eax,1
    jne .bad
    call acl_scan
    cmp eax,-1
    je .bad
    mov edx,eax
    cmp eax,[rel wm_focus]
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+rdx*4],WM_VISIBLE
    jne .bad
    lea rcx,[rel wm_w]
    cmp dword [rcx+rdx*4],ACL_WIDTH
    jne .bad
    lea rcx,[rel wm_h]
    cmp dword [rcx+rdx*4],ACL_HEIGHT
    jne .bad
    lea rcx,[rel wm_x]
    mov r8d,[rcx+rdx*4]
    cmp r8d,0
    jne .bad
    test r8d,r8d
    js .bad
    lea rcx,[rel wm_y]
    mov r9d,[rcx+rdx*4]
    cmp r9d,ACL_TOP
    jne .bad
    test r9d,r9d
    js .bad
    lea r10d,[r8d+ACL_WIDTH]
    lea r11d,[r9d+ACL_HEIGHT]
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
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret

acl_geometry:
    mov edx,[rel acl_slot]
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

acl_snapshot:
    sub rsp,8
    call acl_geometry
    mov [rel acl_arm_xy],rax
    mov [rel acl_arm_fb],rdx
    mov eax,[rel wm_zcounter]
    mov [rel acl_arm_z],eax
    mov eax,[rel sp_ptr_inj_seq]
    mov [rel acl_arm_inj],eax
    mov eax,[rel keyprov_inj_seq]
    mov [rel acl_arm_key],eax
    add rsp,8
    ret

; EAX1 while the armed human decision still looks at the same unchanged window.
acl_unchanged:
    sub rsp,8
    mov eax,[rel keyprov_inj_seq]
    cmp eax,[rel acl_arm_key]
    jne .bad
    mov eax,[rel sp_ptr_inj_seq]
    cmp eax,[rel acl_arm_inj]
    jne .bad
    mov eax,[rel wm_zcounter]
    cmp eax,[rel acl_arm_z]
    jne .bad
    call acl_ok
    cmp eax,1
    jne .bad
    call acl_geometry
    cmp rax,[rel acl_arm_xy]
    jne .bad
    cmp rdx,[rel acl_arm_fb]
    jne .bad
    mov eax,1
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret

; Input from before the card opened, or a click meant for what was there, is refused.
acl_dwelled:
    sub rsp,8
    cmp qword [rel acl_opened_us],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    sub rax,[rel acl_opened_us]
    jb .bad
    cmp rax,ACL_DWELL_US
    jb .bad
    mov eax,1
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret


acl_build:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp dword [rel fb_width],ACL_WIDTH
    jb .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    cmp eax,ACL_TOP+ACL_HEIGHT
    jb .bad
    mov eax,[rel wgt_secret_type]
    cmp eax,-1
    je .bad
    mov [rel acl_types+ACL_SECRET*4],eax
    lea rdi,[rel acl_title]
    xor esi,esi
    mov edx,ACL_TOP
    mov ecx,ACL_WIDTH
    mov r8d,ACL_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .bad
    mov r12d,eax
    mov [rel acl_slot],eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+r12*4]
    mov [rel acl_rawgen],eax
    lea rcx,[rel wm_owner]
    mov qword [rcx+r12*8],WM_OWNER_CHROME
    mov [rel wm_focus],r12d
    mov edi,ACL_COUNT
    call wgt_reserve_run
    test eax,eax
    js .bad
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.loop:
    lea rax,[rel acl_types]
    mov edi,[rax+rbx*4]
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .bad_widgets
    lea rcx,[rel acl_ids]
    mov [rcx+rbx*4],eax
    mov edi,eax
    call wgt_birth_lifetime
    test rax,rax
    jz .bad_widgets
    lea rcx,[rel acl_births]
    mov [rcx+rbx*8],rax
    lea rcx,[rel acl_ids]
    mov edi,[rcx+rbx*4]
    call wgt_slot_ptr
    mov r13,rax
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_LAYER],0
    mov dword [rax+WGI_BIND],0
    mov dword [rax+WGI_EDIT],WGT_EDIT_ASCII
    mov dword [rax+WGI_X],8
    mov dword [rax+WGI_W],604
    mov dword [rax+WGI_H],24
    mov eax,ebx
    imul eax,30
    add eax,ACL_TOP+GUI_TITLE_H+4
    mov [r13+WGI_Y],eax
    cmp ebx,ACL_ALLOW
    jb .label
    mov dword [r13+WGI_Y],ACL_TOP+430
    mov dword [r13+WGI_H],32
    cmp ebx,ACL_CANCEL
    ja .status
    mov dword [r13+WGI_W],290
    cmp ebx,ACL_ALLOW
    je .label
    mov dword [r13+WGI_X],312
    jmp .label
.status:
    mov dword [r13+WGI_Y],ACL_TOP+480
.label:
    cmp ebx,1
    jb .static
    cmp ebx,4
    ja .static
    lea rcx,[rel acl_vm+64-8]
    mov rdi,[rcx+rbx*8]
    bswap rdi
    lea rsi,[rel acl_line]
    mov edx,16
    call fmt_hex
    lea rsi,[rel acl_line]
    jmp .text
.static:
    ; Runtime LEAs, no absolute pointer table in the native image.
    lea rsi,[rel acl_head]
    test ebx,ebx
    jz .text
    lea rsi,[rel acl_account_label]
    cmp ebx,5
    je .text
    lea rsi,[rel acl_host_label]
    cmp ebx,7
    je .text
    lea rsi,[rel acl_secret_label]
    cmp ebx,9
    je .text
    lea rsi,[rel acl_ports_label]
    cmp ebx,11
    je .text
    lea rsi,[rel acl_allow_label]
    cmp ebx,ACL_ALLOW
    je .text
    lea rsi,[rel acl_cancel_label]
    cmp ebx,ACL_CANCEL
    je .text
    lea rsi,[rel acl_status_label]
    cmp ebx,14
    je .text
    lea rsi,[rel acl_empty]
.text:
    lea rax,[rel acl_ids]
    mov edi,[rax+rbx*4]
    call wgt_set_text
    ; Freeze the exact created geometry as well as the original row birth.
    lea rdi,[rel acl_rects]
    mov eax,ebx
    shl eax,4
    add rdi,rax
    lea rsi,[r13+WGI_X]
    mov edx,16
    call memcpy
    lea rdi,[rel acl_texts]
    imul eax,ebx,44
    add rdi,rax
    lea rsi,[r13+WGI_VLEN]
    mov edx,44
    call memcpy
    inc ebx
    cmp ebx,ACL_COUNT
    jb .loop
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    mov eax,[rel acl_ids+ACL_CANCEL*4]
    mov [rel wgt_focus_id],eax
    lea rcx,[rel wgt_focus_by_win]
    mov [rcx+r12*4],eax
    mov byte [rel wgt_focus_visible],1
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    mov [rel acl_opened_us],rax
    mov eax,1
    jmp .out
.bad_widgets:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Native closed original protected-worker exit only. No caller buffer, record,
; callback or asserted authority. Fixed VM sink is unsupported in legacy runtime.
; Its readiness implementation must prove the actual pinned isolation and original
; operation; these symbols are not guest commands. Policy callbacks remain usable
; while acp_busy excludes recursive consume and card offer/tick publication.
account_local_consume:
%ifndef APP_ACCOUNT_SINK_ABI_V2
    ; No protected producer linked: never open or expose a credential.
    xor eax,eax
    ret
%else
    push rbx
    push r12
    push r13
    call acl_guard
    cmp eax,1
    jne .denied
    cmp byte [rel acl_busy],0
    jne .denied
    cmp byte [rel acp_busy],0
    jne .denied
    mov byte [rel acp_busy],1
    call acp_scratch_wipe
    call acp_current
    cmp eax,1
    jne .clear
    lea rdi,[rel acp_context]
    mov esi,192
    call app_account_sink_ready
    cmp eax,1
    jne .clear
    call acp_context_valid
    cmp eax,1
    jne .retire
    ; Native operation IDs are globally monotonic/nonwrapping across workers.
    ; Burn before crypto/delivery; an ambiguous operation is never retried.
    mov rax,[rel acp_context+136]
    cmp rax,[rel acp_last_operation]
    jbe .retire
    mov [rel acp_last_operation],rax
    lea rdi,[rel acp_record]
    lea rsi,[rel acl_record]
    mov edx,832
    call memcpy
    ; Exact immutable header/schema/scope, not merely a matching row selector.
    cmp dword [rel acp_record],'ACS1'
    jne .retire
    cmp word [rel acp_record+4],1
    jne .retire
    cmp word [rel acp_record+6],832
    jne .retire
    mov rax,[rel acp_record+8]
    test rax,rax
    jz .retire
    cmp rax,-1
    je .retire
    cmp dword [rel acp_record+52],0
    jne .retire
    cmp qword [rel acp_record+56],0
    jne .retire
    lea rdi,[rel acp_record+16]
    lea rsi,[rel acl_scope]
    mov ecx,4
    cld
    repe cmpsq
    jne .retire
    mov ecx,[rel acp_record+48]
    cmp ecx,[rel acl_scope+32]
    jne .retire
    test ecx,ecx
    jz .retire
    cmp ecx,39
    ja .retire
    mov [rel acp_frame+4],ecx
    lea rdi,[rel acp_record+64]
    lea rsi,[rel acl_scope+36]
    mov ecx,12
    repe cmpsq
    jne .retire
    lea rsi,[rel acp_record+64]
    lea rdi,[rel acp_frame+16]
    mov ecx,[rel acp_frame+4]
.account:
    lodsb
    cmp al,0x21
    jb .retire
    cmp al,0x7e
    ja .retire
    cmp al,':'                         ; unsupported curl username delimiter
    je .retire
    stosb
    loop .account
    ; Canonical account padding cannot carry unauthenticated alternate names.
    lea rsi,[rel acp_record+64]
    mov eax,[rel acp_frame+4]
    add rsi,rax
    mov ecx,96
    sub ecx,eax
.account_padding:
    lodsb
    test al,al
    jnz .retire
    loop .account_padding
    mov dword [rel acp_frame],1
    lea rdi,[rel acp_frame+184]
    lea rsi,[rel acl_host]
    mov edx,256
    call memcpy
    lea rdi,[rel acp_info]
    lea rsi,[rel acp_domain]
    mov edx,acp_domain.len
    call memcpy
    lea rdi,[rel acp_info+acp_domain.len]
    lea rsi,[rel acp_record]
    mov edx,160
    call memcpy
    mov edi,PRIN_OWNER
    call principal_credential
    test rax,rax
    jz .retire
    cmp rdx,PRIN_CREDENTIAL_LEN
    jne .retire
    mov rdi,rax
    mov rsi,rdx
    lea rdx,[rel acp_record+16]
    mov ecx,32
    lea r8,[rel acp_info]
    mov r9d,acp_domain.len+160
    sub rsp,16
    lea rax,[rel acp_credential]
    mov [rsp],rax
    mov qword [rsp+8],32
    call hkdf_sha256_derive
    add rsp,16
    test eax,eax
    jnz .retire
    xor ebx,ebx
.chunk:
    imul eax,ebx,168
    lea r12,[rel acp_record+160]
    add r12,rax
    cmp dword [r12],'DSE2'
    jne .retire
    cmp dword [r12+4],1 | (56 << 24)
    jne .retire
    mov rdi,r12
    mov esi,PRIN_OWNER
    lea rdx,[rel acp_row]
    mov ecx,acp_row.len
    lea r8,[rel acp_chunk]
    mov r9d,56
    sub rsp,16
    lea rax,[rel acp_credential]
    mov [rsp],rax
    mov qword [rsp+8],32
    call data_crypto_open_record
    add rsp,16
    cmp rax,56
    jne .retire
    cmp dword [rel acp_chunk],'ASC1'
    jne .retire
    cmp [rel acp_chunk+4],ebx
    jne .retire
    mov rax,[rel acp_record+8]
    cmp [rel acp_chunk+8],rax
    jne .retire
    cmp dword [rel acp_chunk+20],0
    jne .retire
    mov eax,[rel acp_chunk+16]
    test eax,eax
    jz .retire
    cmp eax,128
    ja .retire
    test ebx,ebx
    jnz .same_length
    mov [rel acp_frame+8],eax
.same_length:
    cmp [rel acp_frame+8],eax
    jne .retire
    mov eax,ebx
    shl eax,5
    lea rdi,[rel acp_frame+56]
    add rdi,rax
    lea rsi,[rel acp_chunk+24]
    mov edx,32
    call memcpy
    inc ebx
    cmp ebx,4
    jb .chunk
    lea rsi,[rel acp_frame+56]
    xor edx,edx
.secret:
    lodsb
    cmp edx,[rel acp_frame+8]
    jae .padding
    cmp al,0x20
    jb .retire
    cmp al,0x7e
    ja .retire
    jmp .next
.padding:
    test al,al
    jnz .retire
.next:
    inc edx
    cmp edx,128
    jb .secret
    ; Original readiness must still be the very same retained native192 bytes.
    lea rdi,[rel acp_now]
    mov esi,192
    call app_account_sink_ready
    cmp eax,1
    jne .retire
    lea rdi,[rel acp_now]
    lea rsi,[rel acp_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .retire
    call acp_context_valid
    cmp eax,1
    jne .retire
    lea rdi,[rel acp_context]
    lea rsi,[rel acp_frame]
    mov edx,512
    call app_account_sink_write          ; consume-before-effect in fixed VM sink
    cmp eax,1
    jne .retire
    mov r13d,1
    jmp .wipe
.retire:
    lea rdi,[rel acp_context]
    call app_account_sink_retire         ; conditional exact-original cancellation
.clear:
    xor r13d,r13d
.wipe:
    call acp_scratch_wipe
    mov byte [rel acp_busy],0
    mov eax,r13d
    jmp .out
.denied:
    xor eax,eax                          ; do not wipe another consumer's scratch
.out:
    pop r13
    pop r12
    pop rbx
    ret
%endif

acp_current:
    sub rsp,8
    cmp byte [rel acl_approved],1
    jne .bad
    cmp byte [rel acl_draft],0
    jne .bad
    call acl_current
    cmp eax,1
    jne .retire
    mov rax,[rel acl_generation]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    mov eax,1
    add rsp,8
    ret
.retire:
    call account_local_wipe
.bad:
    xor eax,eax
    add rsp,8
    ret

acp_context_valid:
    sub rsp,8
    call acp_current
    cmp eax,1
    jne .bad
    lea rdi,[rel acp_context]
    lea rsi,[rel acl_vm]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    mov rax,[rel acl_generation]
    cmp [rel acp_context+144],rax
    jne .bad
    ; All native generations/identities have a finite nonzero nonwrap domain.
    lea rsi,[rel acp_context+128]
    mov ecx,3
.ids:
    lodsq
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    loop .ids
    mov rax,[rel acp_context+160]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp qword [rel acp_context+168],0
    jne .bad
    cmp qword [rel acp_context+176],0
    jne .bad
    cmp qword [rel acp_context+184],0
    jne .bad
    cmp dword [rel acp_context+152],1
    jne .send
    cmp dword [rel acp_context+156],993
    jne .bad
    jmp .ok
.send:
    cmp dword [rel acp_context+152],2
    jne .bad
    cmp dword [rel acp_context+156],465
    jne .bad
.ok:
    mov eax,1
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret

; Wipe contains neither callback nor exported plaintext. Context remains until
; exact-original cleanup; persistent replay floor is not reset by account wipe.
acp_plain_wipe:
    lea rdi,[rel acp_plain]
    xor esi,esi
    mov edx,acp_plain_end-acp_plain
    jmp memset
acp_scratch_wipe:
    lea rdi,[rel acp_scratch]
    xor esi,esi
    mov edx,acp_scratch_end-acp_scratch
    jmp memset

acp_domain: db 'PaOS/account-secret/v1'
.len equ $-acp_domain
acp_row: db 'account-secret-v1'
.len equ $-acp_row

acl_title: db 'PaOS account approval',0
acl_head: db 'Only this running app (SHA256):',0
acl_account_label: db 'Account (max 39 ASCII bytes)',0
acl_host_label: db 'Mail host (lowercase DNS name)',0
acl_secret_label: db 'PaOS private password',0
acl_ports_label: db 'IMAPS 993 + SMTPS 465 only',0
acl_allow_label: db 'Allow (Tab then Enter)',0
acl_cancel_label: db 'Cancel',0
acl_status_label: db 'Session only; no app secret read',0
acl_empty: db 0

%include "core/abi/wdata.inc"
%macro WDATA_gui_account_local 0
align 8
acl_generation: dq 0
acl_prev_key: dq 0
acl_prev_click: dq 0
acl_slot: dd -1
acl_rawgen: dd 0
acl_ids: times ACL_COUNT dd -1
acl_births: times ACL_COUNT dq 0
acl_types: dd 2,2,2,2,2,2,1,2,1,2,-1,2,0,0,2
acl_rects: times ACL_COUNT*16 db 0
acl_texts: times ACL_COUNT*44 db 0
acl_vm: times 128 db 0
acl_binding: times 120 db 0
acl_now_vm: times 128 db 0
acl_now_binding: times 120 db 0
acl_instance: dq 0
acl_epoch: dq 0
acl_opened_us: dq 0
acl_arm_xy: dq 0
acl_arm_fb: dq 0
acl_queued_revision: dq 0
acl_arm_z: dd 0
acl_arm_inj: dd 0
acl_arm_key: dd 0
acl_record: times 832 db 0
acl_scope: times 132 db 0
acl_host: times 256 db 0
acl_line: times 40 db 0
acl_initialized: db 0
acl_busy: db 0
acl_draft: db 0
acl_approved: db 0
acl_action: db 0
acl_tab: db 0
acp_busy: db 0
align 8
acp_last_operation: dq 0
acp_scratch:
acp_context: times 192 db 0
acp_now: times 192 db 0
acp_record: times 832 db 0
acp_info: times acp_domain.len+160 db 0
acp_plain:
acp_frame: times 512 db 0
acp_chunk: times 56 db 0
acp_credential: times 32 db 0
acp_plain_end:
acp_scratch_end:
%endmacro
WDATA_DEFER WDATA_gui_account_local
