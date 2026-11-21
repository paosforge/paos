;; MODULE gui/settings_terminal_network
;; LAYER 6
;; EXPORTS settings_terminal_network_loaded, settings_terminal_network_tick, settings_terminal_network_click, settings_terminal_network_key, settings_terminal_network_text_event, settings_terminal_network_rows, settings_terminal_network_pointer_note
;; IMPORTS gui/settings_terminal_network_consent, gui/widget, gui/summon_palette, gui/form_loader, gui/start_programs, gui/window, gui/wm_pointer, gui/input_route, sec/keyprov, sec/session, sec/terminal_network_store, sec/terminal_network_gate
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; Native RAM editor. Only Save captures original consent, then the BSP idle
; tick consumes it once. No command, guest or caller-selected consent tuple.
%include "core/abi/wdata.inc"

stn_cancel_gesture:
    mov byte [rel stn_pending],0
    mov byte [rel stnc_invalid],1
    mov dword [rel stnc_phase],0
    lea rdi,[rel stnc_original]
    xor eax,eax
    mov ecx,80
    cld
    rep stosb
    lea rdi,[rel stnc_candidate]
    mov ecx,4096
    rep stosb
    ret

settings_terminal_network_loaded:
    sub rsp,8
    call stnc_local
    test eax,eax
    jz .out
    call stn_cancel_gesture
    mov byte [rel stn_ready],0
    mov byte [rel stn_loaded],0
    mov dword [rel stnc_window],-1
    mov dword [rel stnc_save],-1
    mov byte [rel stnc_tainted],0
    lea rdi,[rel stnc_draft]
    xor eax,eax
    mov ecx,4096
    cld
    rep stosb
    mov dword [rel stnc_draft_count],0
    call stn_text_hook_install
    test eax,eax
    jz .out
    mov byte [rel stn_loaded],1
    mov rax,[rel stnc_build]
    cmp rax,-2
    jae .exhausted
    inc rax
    mov [rel stnc_build],rax
    jmp .out
.exhausted:
    mov qword [rel stnc_build],-1
    mov byte [rel stn_loaded],0
.out:
    add rsp,8
    ret

; Only the two built-in predecessors can be composed. Never hide an unknown
; callback behind a provider-allowlisted hook. Summon may install later: a
; lost observer spends pending consent and taints the editor before repair.
stn_text_hook_install:
    push rbx
    mov rbx,[rel wgt_textfield_event_hook2]
    lea rax,[rel settings_terminal_network_text_event]
    cmp rbx,rax
    jne .predecessor
    mov rbx,[rel stn_previous_text]
    test rbx,rbx
    jz .yes
    lea rax,[rel summon_palette_text_event]
    cmp rbx,rax
    je .yes
    jmp .no
.predecessor:
    test rbx,rbx
    jz .install
    lea rax,[rel summon_palette_text_event]
    cmp rbx,rax
    jne .no
.install:
    cmp byte [rel stn_ready],1
    jne .store
    call stn_cancel_gesture
    mov byte [rel stnc_tainted],1
.store:
    mov [rel stn_previous_text],rbx
    lea rax,[rel settings_terminal_network_text_event]
    mov [rel wgt_textfield_event_hook2],rax
.yes:
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; Binding is sampled from actual form/window/widgets, never supplied by guest.
stn_bind:
    push rbx
    mov edi,STNC_FORM
    mov esi,STNC_COUNT
    lea rdx,[rel stnc_ids]
    call sp_form_widgets_n
    cmp eax,STNC_COUNT
    jne .no
    cmp ecx,WM_MAX
    jae .no
    mov ebx,ecx
    mov [rel stnc_window],ebx
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    mov [rel stnc_window_gen],eax
    call session_shell_local_authority
    cmp rax,1
    jne .no
    test rdx,rdx
    jz .no
    mov [rel stnc_owner],rax
    mov [rel stnc_session],rdx
    mov rax,[rel stnc_build]
    mov [rel stnc_bound_build],rax
    mov edi,[rel stnc_ids+STNC_SAVE*4]
    mov [rel stnc_save],edi
    call wgt_slot_ptr
    mov rax,[rax+WGI_ID]
    mov [rel stnc_widget_id],rax
    mov edi,[rel stnc_save]
    call wgt_birth_lifetime
    mov [rel stnc_birth],rax
    call stnc_live
    test eax,eax
    jz .no
    mov edi,[rel stnc_ids+3*4]
    call wgt_textfield_long
    test eax,eax
    jnz .no
    mov edi,[rel stnc_ids+3*4]
    call wgt_slot_ptr
    call wgt_tf_buf
    cmp ecx,255
    jb .no
    call stn_entry_empty
    call terminal_network_store_load
    call stn_restore
    call stnc_live
    test eax,eax
    jz .no
    mov byte [rel stn_ready],1
    call stn_render
    mov eax,1
    pop rbx
    ret
.no:
    mov byte [rel stn_ready],0
    lea rsi,[rel stn_unavailable]
    call stn_status
    xor eax,eax
    pop rbx
    ret

; Read authenticated in-memory policy. Cancel never reopens a DATA file.
stn_restore:
    sub rsp,8
    lea rdi,[rel stnc_draft]
    xor eax,eax
    mov ecx,4096
    cld
    rep stosb
    mov dword [rel stnc_draft_count],0
    lea rdi,[rel stnc_draft]
    lea rsi,[rel stn_meta]
    call settings_terminal_network_policy_read
    test eax,eax
    jz .saved
    cmp eax,-3
    je .session
    cmp eax,1
    je .missing
    lea rsi,[rel stn_load_error]
    jmp .status
.saved:
    lea rsi,[rel stn_saved]
    jmp .count
.session:
    lea rsi,[rel stn_session]
.count:
    mov eax,[rel stn_meta]
    cmp eax,16
    ja .bad
    mov [rel stnc_draft_count],eax
    jmp .status
.bad:
    lea rsi,[rel stn_load_error]
    jmp .status
.missing:
    lea rsi,[rel stn_missing]
.status:
    call stn_status
    add rsp,8
    ret

stn_status:
    mov edi,[rel stnc_ids+4]
    jmp wgt_set_text

settings_terminal_network_tick:
    push rbx
    call stnc_local
    test eax,eax
    jz .out
    cmp byte [rel stn_loaded],0
    je .live
    mov byte [rel stn_loaded],0
    call stn_bind
    jmp .out
.live:
    cmp byte [rel stn_ready],1
    jne .out
    call stn_text_hook_install
    test eax,eax
    jz .teardown
    call stnc_live
    test eax,eax
    jz .lost
    cmp byte [rel stn_pending],1
    jne .out
    mov byte [rel stn_pending],0
    call settings_terminal_network_policy_save
    lea rsi,[rel stn_saved]
    test eax,eax
    jz .said
    lea rsi,[rel stn_session]
    cmp eax,-3
    je .said
    lea rsi,[rel stn_refused]
.said:
    call stn_status
    call stn_cancel_gesture
    jmp .out
.lost:
    call stn_cancel_gesture
    ; Focus loss spends the gesture. Keep a RAM draft only while the original
    ; owner/session and visible window generation remain current.
    cmp byte [rel session_locked],0
    jne .teardown
    cmp byte [rel pbm_try_media],0
    jne .teardown
    call session_shell_local_authority
    cmp rax,[rel stnc_owner]
    jne .teardown
    cmp rax,1
    jne .teardown
    cmp rdx,[rel stnc_session]
    jne .teardown
    mov ebx,[rel stnc_window]
    cmp ebx,WM_MAX
    jae .teardown
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    cmp eax,[rel stnc_window_gen]
    jne .teardown
    lea rax,[rel wm_state]
    cmp dword [rax+rbx*4],WM_VISIBLE
    jne .teardown
    lea rax,[rel wm_owner]
    mov rax,[rax+rbx*8]
    test rax,rax
    jz .teardown
    cmp rax,WM_OWNER_CHROME
    je .teardown
    cmp ebx,[rel wm_focus]
    jne .out
.teardown:
    call stn_cancel_gesture
    mov byte [rel stn_ready],0
    mov dword [rel stnc_window],-1
    mov dword [rel stnc_save],-1
    mov dword [rel stnc_draft_count],0
    lea rdi,[rel stnc_draft]
    xor eax,eax
    mov ecx,4096
    cld
    rep stosb
    mov byte [rel stn_rows],0
.out:
    pop rbx
    ret

; All editing gestures use actual current local input provenance as well.
stn_pointer_human:
    sub rsp,8
    call stnc_local
    test eax,eax
    jz .no
    cmp byte [rel stn_ready],1
    jne .no
    call stn_text_hook_install
    test eax,eax
    jz .no
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .no
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .no
    call stnc_live
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

settings_terminal_network_click:
    push rbx
    mov ebx,edi
    ; The Settings navigation row has no persistence or consent effect.
    mov edi,FORM_SETTINGS_INDEX
    mov esi,STP_W_COUNT
    lea rdx,[rel stn_nav_ids]
    call sp_form_widgets_n
    cmp eax,STP_W_COUNT
    jne .pane
    cmp ebx,[rel stn_nav_ids+STP_W_TERMINAL_NET*4]
    jne .pane
    call stnc_local
    test eax,eax
    jz .no
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .no
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .no
    mov edi,STNC_FORM
    call form_load_internal
    mov eax,1
    jmp .out
.pane:
    call stn_pointer_human
    test eax,eax
    jz .no
    cmp ebx,[rel stnc_save]
    jne .edit
    mov edi,ebx
    call stnc_capture_pointer
    test eax,eax
    jz .no
    mov byte [rel stn_pending],1
    jmp .yes
.edit:
    cmp byte [rel stn_pending],0
    jne .no
    cmp ebx,[rel stnc_ids+6*4]
    je .clear
    cmp ebx,[rel stnc_ids+8*4]
    je .cancel
    cmp byte [rel stnc_tainted],0
    jne .no
    cmp ebx,[rel stnc_ids+4*4]
    je .add
    cmp ebx,[rel stnc_ids+5*4]
    je .remove
    cmp ebx,[rel stnc_ids+2*4]
    je .select
    jmp .no
.clear:
    lea rdi,[rel stnc_draft]
    xor eax,eax
    mov ecx,4096
    cld
    rep stosb
    mov dword [rel stnc_draft_count],0
    mov byte [rel stnc_tainted],0
    call stn_entry_empty
    jmp .changed
.cancel:
    call stn_restore
    call stn_entry_empty
    jmp .changed
.add:
    call stn_add
    test eax,eax
    jz .no
    jmp .changed
.remove:
    call stn_selection
    jc .no
    mov ebx,eax
    shl ebx,8
    lea rdi,[rel stnc_draft]
    add rdi,rbx
    lea rsi,[rdi+256]
    mov ecx,4096-256
    sub ecx,ebx
    cld
    rep movsb
    xor eax,eax
    mov ecx,256
    rep stosb
    dec dword [rel stnc_draft_count]
    call stn_entry_empty
    jmp .changed
.select:
    call stn_selection
    jc .no
    shl eax,8
    lea rbx,[rel stnc_draft]
    add rbx,rax
    mov edi,[rel stnc_ids+3*4]
    call wgt_slot_ptr
    push rax
    call wgt_tf_buf
    mov rdi,rax
    lea rsi,[rbx+1]
    movzx ecx,byte [rbx]
    mov edx,ecx
    cld
    rep movsb
    mov byte [rdi],0
    pop rax
    mov [rax+WGI_VLEN],edx
    mov [rax+WGI_CARET],edx
    jmp .yes
.changed:
    call stn_render
    lea rsi,[rel stn_draft]
    call stn_status
.yes:
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

stn_entry_empty:
    sub rsp,8
    mov edi,[rel stnc_ids+3*4]
    call wgt_slot_ptr
    mov dword [rax+WGI_VLEN],0
    mov dword [rax+WGI_CARET],0
    call wgt_tf_buf
    mov byte [rax],0
    add rsp,8
    ret

stn_selection:
    sub rsp,8
    mov edi,[rel stnc_ids+2*4]
    call wgt_slot_ptr
    mov eax,[rax+WGI_SEL_LO]
    cmp eax,[rel stnc_draft_count]
    jae .no
    add rsp,8
    clc
    ret
.no:
    add rsp,8
    stc
    ret

stn_add:
    push rbx
    push r12
    push r13
    mov edi,[rel stnc_ids+3*4]
    call wgt_slot_ptr
    mov r12d,[rax+WGI_VLEN]
    cmp r12d,253
    ja .no
    test r12d,r12d
    jz .no
    call wgt_tf_buf
    cmp ecx,255
    jb .no
    mov rsi,rax
    lea rdi,[rel stn_canon]
    mov edx,r12d
    call terminal_network_host_canon
    cmp eax,r12d
    jne .no
    xor r13d,r13d
.search:
    cmp r13d,[rel stnc_draft_count]
    jae .insert
    mov ebx,r13d
    shl ebx,8
    lea rdi,[rel stnc_draft+1]
    add rdi,rbx
    lea rsi,[rel stn_canon]
.compare:
    mov al,[rsi]
    cmp al,[rdi]
    jb .insert
    ja .next
    test al,al
    jz .yes                       ; duplicate is a harmless RAM no-op
    inc rsi
    inc rdi
    jmp .compare
.next:
    inc r13d
    jmp .search
.insert:
    cmp dword [rel stnc_draft_count],16
    jae .no
    mov ebx,r13d
    shl ebx,8
    mov ecx,4096-256
    sub ecx,ebx
    jz .slot
    lea rsi,[rel stnc_draft+4096-257]
    lea rdi,[rel stnc_draft+4096-1]
    std
    rep movsb
    cld
.slot:
    lea rdi,[rel stnc_draft]
    add rdi,rbx
    mov [rdi],r12b
    inc rdi
    lea rsi,[rel stn_canon]
    mov ecx,255
    cld
    rep movsb
    inc dword [rel stnc_draft_count]
.yes:
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

settings_terminal_network_key:
    push rbx
    mov ebx,edi
    sub rsp,16
    mov [rsp],eax
    cmp byte [rel stn_ready],1
    jne .hook_checked
    call stn_text_hook_install
    test eax,eax
    jz .hook_refused
.hook_checked:
    mov eax,[rsp]
    add rsp,16
    cmp eax,GUI_KEY_ENTER
    jne .no
    cmp byte [rel input_key_origin],KO_HUMAN
    jne .no
    call input_modifiers_are_human
    test eax,eax
    jz .no
    call input_enter_is_typematic
    test eax,eax
    jnz .no
    cmp ebx,[rel wgt_focus_id]
    jne .no
    call stnc_local
    test eax,eax
    jz .no
    mov edi,FORM_SETTINGS_INDEX
    mov esi,STP_W_COUNT
    lea rdx,[rel stn_nav_ids]
    call sp_form_widgets_n
    cmp eax,STP_W_COUNT
    jne .pane
    cmp ebx,[rel stn_nav_ids+STP_W_TERMINAL_NET*4]
    jne .pane
    cmp ecx,[rel wm_focus]
    jne .no
    mov edi,STNC_FORM
    call form_load_internal
    mov eax,1
    pop rbx
    ret
.pane:
    cmp byte [rel stn_ready],1
    jne .no
    call stnc_live
    test eax,eax
    jz .no
    cmp ebx,[rel stnc_save]
    jne settings_terminal_network_click.edit
    mov edi,ebx
    mov eax,GUI_KEY_ENTER
    call stnc_capture_key
    test eax,eax
    jz .no
    mov byte [rel stn_pending],1
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret
.hook_refused:
    add rsp,16
    jmp .no

; The real editor invokes this for key edits, WIDGETSET and paste. A paste
; (key zero) is tainted even if its initiating Ctrl+V was physical.
settings_terminal_network_text_event:
    push rdi
    push rsi
    sub rsp,8
    cmp byte [rel stn_ready],1
    jne .chain
    cmp edi,[rel stnc_ids+3*4]
    jne .chain
    test esi,esi
    jz .taint
    cmp byte [rel input_key_origin],KO_HUMAN
    jne .taint
    call input_modifiers_are_human
    test eax,eax
    jnz .chain
.taint:
    mov byte [rel stnc_tainted],1
.chain:
    mov rax,[rel stn_previous_text]
    test rax,rax
    jz .out
    lea rdx,[rel summon_palette_text_event]
    cmp rax,rdx
    jne .out
    mov edi,[rsp+16]
    mov esi,[rsp+8]
    call rax
.out:
    add rsp,8
    pop rsi
    pop rdi
    ret

stn_render:
    push rbx
    lea rdi,[rel stn_rows]
    xor ebx,ebx
.next:
    cmp ebx,[rel stnc_draft_count]
    jae .end
    test ebx,ebx
    jz .name
    mov byte [rdi],','
    inc rdi
.name:
    mov eax,ebx
    shl eax,8
    lea rsi,[rel stnc_draft]
    add rsi,rax
    movzx ecx,byte [rsi]
    inc rsi
    cld
    rep movsb
    inc ebx
    jmp .next
.end:
    mov byte [rdi],0
    mov edi,[rel stnc_ids+2*4]
    call wgt_draw_id
    mov edi,[rel stnc_ids+3*4]
    call wgt_draw_id
    pop rbx
    ret

settings_terminal_network_rows:
    cmp byte [rel stn_ready],1
    jne .no
    cmp edi,[rel stnc_ids+2*4]
    jne .no
    sub rsp,8
    call stnc_local
    test eax,eax
    jz .bad
    call stnc_live
    test eax,eax
    jz .bad
    lea rax,[rel stn_rows]
    add rsp,8
    ret
.bad:
    add rsp,8
.no:
    xor eax,eax
    ret

; Called under the actual pointer-note hook with R12D/R13D coordinates.
settings_terminal_network_pointer_note:
    push rbx
    cmp byte [rel stn_ready],1
    jne .out
    call stnc_live
    test eax,eax
    jz .out
    mov ebx,STNC_ARM
    mov edi,[rel stnc_save]
    call sp_arm_note
.out:
    pop rbx
    ret

stn_saved: db 'Saved',0
stn_session: db 'Session only; Save unconfirmed',0
stn_missing: db 'No saved policy; default empty',0
stn_load_error: db 'Load error; Save to replace',0
stn_unavailable: db 'Unavailable',0
stn_refused: db 'Save refused; choose Save again',0
stn_draft: db 'Draft; choose Save to apply',0
%macro WDATA_gui_settings_terminal_network 0
align 8,db 0
stn_private_begin:
stn_previous_text: dq 0
stn_ready: db 0
stn_pending: db 0
stn_loaded: db 0
align 8,db 0
stn_meta: times 32 db 0
stn_nav_ids: times STP_W_COUNT dd -1
stn_canon: times 256 db 0
stn_rows: times 4097 db 0
stn_private_end:
%endmacro
WDATA_DEFER WDATA_gui_settings_terminal_network
