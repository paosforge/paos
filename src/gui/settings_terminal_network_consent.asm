;; MODULE gui/settings_terminal_network_consent
;; LAYER 6
;; EXPORTS settings_terminal_network_consent_take, settings_terminal_network_consent_current, settings_terminal_network_consent_finish
;; IMPORTS gui/widget, gui/window, gui/form_loader, gui/start_programs, gui/wm_pointer, gui/input_route, sec/keyprov, sec/session, boot/boot_v2_handoff, core/time, core/smp, core/lib/sha256, svc/command, svc/command_auth
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; Private pane custody. No public tuple/candidate constructor. Native pane
; build/teardown owns these private bindings and draft. Neither
; a supplied tuple nor a caller-selected widget creates a window or gesture.
%include "core/abi/wdata.inc"
STNC_FORM equ 34
STNC_COUNT equ 9
STNC_SAVE equ 7
STNC_ARM equ 24

stnc_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel command_auth_remote_active],0
    jne .no
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    setz al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

; Actual original native window/widget/owner facts, not a copied assertion.
stnc_live:
    push rbx
    cmp byte [rel session_locked],0
    jne .no
    cmp byte [rel pbm_try_media],0
    jne .no
    call session_shell_local_authority
    cmp rax,1
    jne .no
    cmp rax,[rel stnc_owner]
    jne .no
    test rdx,rdx
    jz .no
    cmp rdx,[rel stnc_session]
    jne .no
    mov ebx,[rel stnc_window]
    cmp ebx,WM_MAX
    jae .no
    cmp ebx,[rel wm_focus]
    jne .no
    lea rax,[rel wm_state]
    cmp dword [rax+rbx*4],WM_VISIBLE
    jne .no
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    cmp eax,[rel stnc_window_gen]
    jne .no
    lea rax,[rel wm_owner]
    mov rax,[rax+rbx*8]
    test rax,rax
    jz .no
    cmp rax,WM_OWNER_CHROME
    je .no
    mov rax,[rel stnc_build]
    test rax,rax
    jz .no
    cmp rax,-1
    je .no
    cmp rax,[rel stnc_bound_build]
    jne .no
    mov edi,STNC_FORM
    mov esi,STNC_COUNT
    lea rdx,[rel stnc_ids]
    call sp_form_widgets_n
    cmp eax,STNC_COUNT
    jne .no
    cmp ecx,ebx
    jne .no
    mov edi,[rel stnc_ids+STNC_SAVE*4]
    cmp edi,[rel stnc_save]
    jne .no
    cmp edi,[rel wgt_count]
    jae .no
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],WGT_TYPE_BUTTON
    jne .no
    test dword [rax+WGI_FLAGS],1
    jz .no
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .no
    mov rdx,[rax+WGI_ID]
    cmp rdx,[rel stnc_widget_id]
    jne .no
    mov edi,[rel stnc_save]
    call wgt_birth_lifetime
    test rax,rax
    jz .no
    cmp rax,[rel stnc_birth]
    jne .no
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

stnc_context:
    sub rsp,8
    cmp byte [rel stnc_invalid],0
    jne .bad
    call stnc_live
    test eax,eax
    jz .bad
    call boot_ms_now
    test rax,rax
    jz .bad
    cmp rax,[rel stnc_started]
    jb .bad
    cmp rax,[rel stnc_seen]
    jb .bad
    cmp rax,[rel stnc_original+24]
    jae .bad
    mov [rel stnc_seen],rax
    mov eax,1
    jmp .out
.bad:
    mov byte [rel stnc_invalid],1
    xor eax,eax
.out:
    add rsp,8
    ret

stnc_hash:
    sub rsp,8
    lea rdi,[rel stnc_digest]
    lea rsi,[rel stnc_candidate]
    mov edx,4096
    call sha256_hash
    add rsp,8
    ret

stnc_wipe_digest:
    lea rdi,[rel stnc_digest]
    xor eax,eax
    mov ecx,32
    cld
    rep stosb
    ret

; Private native pointer dispatch target for the pane. Never exported
; as a command/device/consent constructor. Both actual HUMAN origins and the
; original physical rectangle arm are necessary even for this private call.
; Called only by the native key filter while the delivered Enter provenance
; and typematic mark are live. It never manufactures a pointer arm.
stnc_capture_key:
    push rbx
    mov ebx,edi
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
    cmp byte [rel stnc_busy],0
    jne .no
    cmp dword [rel stnc_phase],0
    jne .no
    cmp ebx,[rel stnc_save]
    jne .no
    jmp stnc_capture_pointer.authorized
.no:
    xor eax,eax
    pop rbx
    ret

stnc_capture_pointer:
    push rbx
    mov ebx,edi
    call stnc_local
    test eax,eax
    jz .no
    cmp byte [rel stnc_busy],0
    jne .no
    cmp dword [rel stnc_phase],0
    jne .no
    cmp ebx,[rel stnc_save]
    jne .no
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .no
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .no
    mov edi,ebx
    mov esi,STNC_ARM
    call sp_arm_holds
    test eax,eax
    jz .no
.authorized:
    call stnc_live
    test eax,eax
    jz .no
    cmp byte [rel stnc_tainted],0
    jne .no
    cmp dword [rel stnc_draft_count],16
    ja .no
    mov rax,[rel stnc_generation]
    cmp rax,-2
    jae .no
    inc rax
    mov [rel stnc_generation],rax
    mov [rel stnc_original],rax
    call boot_ms_now
    test rax,rax
    jz .no
    cmp rax,[rel stnc_seen]
    jb .no
    mov [rel stnc_started],rax
    mov [rel stnc_seen],rax
    add rax,30000
    jc .no
    mov [rel stnc_original+24],rax
    mov rax,[rel stnc_owner]
    mov [rel stnc_original+8],rax
    mov rax,[rel stnc_session]
    mov [rel stnc_original+16],rax
    mov eax,[rel stnc_draft_count]
    mov [rel stnc_original+32],eax
    mov dword [rel stnc_original+36],1
    mov qword [rel stnc_original+72],0
    lea rdi,[rel stnc_candidate]
    lea rsi,[rel stnc_draft]
    mov ecx,4096
    cld
    rep movsb
    call stnc_hash
    lea rdi,[rel stnc_original+40]
    lea rsi,[rel stnc_digest]
    mov ecx,32
    cld
    rep movsb
    call stnc_wipe_digest
    mov byte [rel stnc_invalid],0
    mov dword [rel stnc_phase],1
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

stnc_span:
    test rdi,rdi
    jz .no
    mov rax,rdi
    add rax,rsi
    jc .no
    lea rdx,[rel stnc_private_end]
    cmp rdi,rdx
    jae .yes
    lea rdx,[rel stnc_private_begin]
    cmp rax,rdx
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; Native out80 + out4096, disjoint, mapped. One take only, no deadline renewal.
settings_terminal_network_consent_take:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    xor ebx,ebx
    call stnc_local
    test eax,eax
    jz .out
    cmp byte [rel stnc_busy],0
    jne .out
    mov rdi,r12
    mov esi,80
    call stnc_span
    test eax,eax
    jz .out
    mov rdi,r13
    mov esi,4096
    call stnc_span
    test eax,eax
    jz .out
    lea rax,[r12+80]
    cmp r13,rax
    jae .spans
    lea rax,[r13+4096]
    cmp r12,rax
    jb .out
.spans:
    cmp dword [rel stnc_phase],1
    jne .out
    mov byte [rel stnc_busy],1
    call stnc_context
    test eax,eax
    jz .leave
    mov dword [rel stnc_phase],2
    mov rdi,r12
    lea rsi,[rel stnc_original]
    mov ecx,80
    cld
    rep movsb
    mov rdi,r13
    lea rsi,[rel stnc_candidate]
    mov ecx,4096
    rep movsb
    call stnc_context
    test eax,eax
    jnz .yes
    mov rdi,r12
    xor eax,eax
    mov ecx,80
    cld
    rep stosb
    mov rdi,r13
    mov ecx,4096
    rep stosb
    mov dword [rel stnc_phase],3
    jmp .leave
.yes:
    mov ebx,1
.leave:
    mov byte [rel stnc_busy],0
.out:
    mov eax,ebx
    pop r13
    pop r12
    pop rbx
    ret

stnc_original_matches:
    mov esi,80
    sub rsp,8
    call stnc_span
    add rsp,8
    test eax,eax
    jz .out
    lea rsi,[rel stnc_original]
    mov ecx,80
    cld
    repe cmpsb
    sete al
    movzx eax,al
.out:
    ret

; Fixed per-effect check, original tuple is necessary but never sufficient.
settings_terminal_network_consent_current:
    push rbx
    mov rbx,rdi
    call stnc_local
    test eax,eax
    jz .no
    cmp byte [rel stnc_busy],0
    jne .no
    cmp dword [rel stnc_phase],2
    jne .no
    mov rdi,rbx
    call stnc_original_matches
    test eax,eax
    jz .no
    mov byte [rel stnc_busy],1
    call stnc_context
    test eax,eax
    jz .leave
    call stnc_hash
    lea rdi,[rel stnc_digest]
    lea rsi,[rel stnc_original+40]
    mov ecx,32
    cld
    repe cmpsb
    jne .bad
    call stnc_context
    jmp .leave
.bad:
    mov byte [rel stnc_invalid],1
    xor eax,eax
.leave:
    mov ebx,eax
    call stnc_wipe_digest
    mov byte [rel stnc_busy],0
    mov eax,ebx
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; Exact single-use retirement even expired, unfocused or logged out. No effect
; permission and no check that could revive the original. Foreign calls refuse.
settings_terminal_network_consent_finish:
    push rbx
    mov rbx,rdi
    call stnc_local
    test eax,eax
    jz .no
    cmp byte [rel stnc_busy],0
    jne .no
    cmp dword [rel stnc_phase],2
    jne .no
    mov rdi,rbx
    call stnc_original_matches
    test eax,eax
    jz .no
    mov dword [rel stnc_phase],3
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

%macro WDATA_gui_settings_terminal_network_consent 0
align 8,db 0
stnc_private_begin:
stnc_window: dd -1
stnc_save: dd -1
stnc_window_gen: dd 0
stnc_phase: dd 0
stnc_build: dq 0
stnc_bound_build: dq 0
stnc_owner: dq 0
stnc_session: dq 0
stnc_widget_id: dq 0
stnc_birth: dq 0
stnc_started: dq 0
stnc_seen: dq 0
stnc_generation: dq 0
stnc_draft_count: dd 0
stnc_busy: db 0
stnc_invalid: db 0
stnc_tainted: db 0
align 8,db 0
stnc_original: times 80 db 0
stnc_ids: times STNC_COUNT dd -1
stnc_draft: times 4096 db 0
stnc_candidate: times 4096 db 0
stnc_digest: times 32 db 0
stnc_private_end:
%endmacro
WDATA_DEFER WDATA_gui_settings_terminal_network_consent
