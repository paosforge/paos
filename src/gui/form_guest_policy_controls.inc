; Local physical-pointer controls for the existing guest-policy form.
; No command/guest mapping, deferred authority, guard clearing or native setter edit.
GP_OWNER_COUNT equ 7                 ; status, None, STATUS, BEGIN, POLL, CANCEL, Apply
GP_OWNER_SIZE equ 160                ; single last-success observation, never a ring

gp_owner_init:
    ; Boot form self-tests run before lock_screen_init replaces the hook root.
    ; Install only on the real desktop form load, like the existing About UI.
    cmp byte [rel lock_surface_ready],1
    jne .out
    cmp byte [rel gp_owner_hooked],0
    jne .out
    mov rax,[rel wgt_click_hook]
    mov [rel gp_owner_previous],rax
    lea rax,[rel gp_owner_click]
    mov [rel wgt_click_hook],rax
    mov byte [rel gp_owner_hooked],1
.out:
    ret

; Called only after the built-in form's entire new allocation is published.
; Loading a form records widget identity, never authority or a policy change.
gp_owner_loaded:
    push rbx
    push r12
    push r13
    mov byte [rel gp_owner_live],0
    mov byte [rel gp_owner_success],0
    mov byte [rel gp_owner_draft],0
    mov qword [rel gp_owner_mask],0
    mov byte [rel gp_ui_valid],0
    xor ebx,ebx
.clear:
    lea rax,[rel gp_owner_ids]
    mov dword [rax+rbx*4],-1
    inc ebx
    cmp ebx,GP_OWNER_COUNT
    jb .clear
    xor r12d,r12d
.scan:
    cmp r12d,[rel wgt_count]
    jae .complete
    mov edi,r12d
    call wgt_slot_ptr
    mov r13,rax
    mov ecx,[rel form_active_slot+FORM_GUEST_POLICY_INDEX*4]
    cmp [rax+WGI_WIN],ecx
    jne .next
    mov rdi,[rax+WGI_ID]
    test rdi,rdi
    jz .next
    xor ebx,ebx
.name:
    lea rsi,[rel gp_owner_names]
    imul eax,ebx,32
    add rsi,rax
    mov rdi,[r13+WGI_ID]
    call strcmp
    test eax,eax
    jz .found
    inc ebx
    cmp ebx,GP_OWNER_COUNT
    jb .name
    jmp .next
.found:
    lea rax,[rel gp_owner_ids]
    cmp dword [rax+rbx*4],-1
    jne .out                       ; duplicate native ID never authorizes
    mov [rax+rbx*4],r12d
    mov edi,r12d
    call wgt_birth_lifetime
    test rax,rax
    jz .out
    lea rcx,[rel gp_owner_births]
    mov [rcx+rbx*8],rax
.next:
    inc r12d
    jmp .scan
.complete:
    xor ebx,ebx
.all:
    lea rax,[rel gp_owner_ids]
    cmp dword [rax+rbx*4],-1
    je .out
    inc ebx
    cmp ebx,GP_OWNER_COUNT
    jb .all
    mov edi,[rel gp_owner_ids]
    call gp_ui_current
    test eax,eax
    jz .out
    mov [rel gp_owner_window],r8d
    mov [rel gp_owner_generation],r9d
    mov byte [rel gp_owner_live],1
    call gp_owner_init
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Current exact original allocation, visible chrome and all controls.
; Read-only, no ambient OWNER assumption. R12-R15/RBX preserved.
gp_owner_current:
    push rbx
    push r12
    cmp byte [rel gp_owner_live],1
    jne .bad
    mov edi,[rel gp_owner_ids]
    call gp_ui_current
    test eax,eax
    jz .bad
    cmp r8d,[rel gp_owner_window]
    jne .bad
    cmp r9d,[rel gp_owner_generation]
    jne .bad
    cmp r10,[rel gp_owner_births]
    jne .bad
    xor ebx,ebx
.next:
    inc ebx
    cmp ebx,GP_OWNER_COUNT
    jae .good
    lea rax,[rel gp_owner_ids]
    mov edi,[rax+rbx*4]
    mov r12d,edi
    call wgt_birth_lifetime
    lea rcx,[rel gp_owner_births]
    cmp rax,[rcx+rbx*8]
    jne .bad
    mov edi,r12d
    xor esi,esi
    call wgt_secret_hidden
    test eax,eax
    jnz .bad
    mov edi,r12d
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],WGT_TYPE_BUTTON
    jne .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    mov ecx,[rel gp_owner_window]
    cmp [rax+WGI_WIN],ecx
    jne .bad
    mov r12,rax
    test dword [rax+WGI_EDIT],WGT_EDIT_FORMTEXT
    jz .bad
    lea rsi,[rel gp_owner_none_label]
    cmp ebx,1
    je .label
    lea rsi,[rel gp_owner_apply_label]
    cmp ebx,6
    je .label
    lea ecx,[ebx-2]
    mov rax,[rel gp_owner_mask]
    shr rax,cl
    and eax,1
    shl eax,4
    imul edx,ecx,32
    add eax,edx
    lea rsi,[rel gp_owner_labels_data]
    add rsi,rax
.label:
    lea rdi,[r12+WGI_VAL]
    call strcmp
    test eax,eax
    jnz .bad
    mov rdi,[r12+WGI_ID]
    test rdi,rdi
    jz .bad
    lea rsi,[rel gp_owner_names]
    imul eax,ebx,32
    add rsi,rax
    call strcmp
    test eax,eax
    jnz .bad
    jmp .next
.good:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Chained only from the stock pointer hit path; not WIDGETSET/action or FORMLOAD.
gp_owner_click:
    push rbx
    mov ebx,edi
    call gp_owner_attempt
    test eax,eax
    jnz .out                       ; recognized control, including safe refusal
    mov rax,[rel gp_owner_previous]
    test rax,rax
    jz .out
    mov edi,ebx
    call rax
.out:
    pop rbx
    ret

; EDI actual hit widget. Return 0 unrelated, 1 recognized. No queued operation.
gp_owner_attempt:
    push rbx
    push r12
    push r13
    push r14
    mov r12d,edi
    mov ebx,1
.find:
    lea rax,[rel gp_owner_ids]
    cmp edi,[rax+rbx*4]
    je .control
    inc ebx
    cmp ebx,GP_OWNER_COUNT
    jb .find
    xor r14d,r14d
    jmp .out
.control:
    mov r14d,1
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    mov r13,rdx                    ; real keyed local session, no projection
    mov eax,[rel gp_owner_window]
    cmp eax,[rel wm_focus]
    jne .out
    cmp byte [rel gp_ui_busy],0
    jne .out
    cmp byte [rel gp_ui_valid],1
    jne .out
    call gp_owner_current
    test eax,eax
    jz .out
    ; The event acts on the last actually rendered original, never a fresh
    ; silent guest selection. Strict copy rechecks endpoint/START/VM/session.
    call gp_ui_endpoint
    test eax,eax
    jz .out
    lea rdx,[rel gp_owner_current_policy]
    mov ecx,128
    call guest_request_command_policy_copy
    test eax,eax
    jz .out
    lea rsi,[rel gp_owner_current_policy+8]
    lea rdi,[rel gp_ui_policy+8]
    mov ecx,11                     ; identity, generation, setting owner/time
    cld
    repe cmpsq
    jne .out
    cmp r13,[rel gp_owner_current_policy+40]
    jne .out
    cmp ebx,1
    je .none
    cmp byte [rel gp_owner_draft],1
    jne .new_draft
    cmp r13,[rel gp_owner_draft_session]
    jne .stale_draft
    mov rax,[rel session_key_handle]
    cmp rax,[rel gp_owner_draft_key]
    jne .stale_draft
    mov rax,[rel gp_owner_current_policy+48]
    cmp rax,[rel gp_owner_draft_generation]
    jne .stale_draft
    jmp .choice
.stale_draft:
    mov byte [rel gp_owner_draft],0
    mov qword [rel gp_owner_mask],0
    call gp_owner_labels
    jmp .draw
.new_draft:
    cmp ebx,6                      ; Apply requires actual local explicit choices
    je .out
    mov qword [rel gp_owner_mask],0
    mov [rel gp_owner_draft_session],r13
    mov rax,[rel session_key_handle]
    mov [rel gp_owner_draft_key],rax
    mov rax,[rel gp_owner_current_policy+48]
    mov [rel gp_owner_draft_generation],rax
    mov byte [rel gp_owner_draft],1
.choice:
    cmp ebx,6
    je .custom
    lea ecx,[ebx-2]
    mov eax,1
    shl eax,cl
    xor [rel gp_owner_mask],rax
    call gp_owner_labels
    jmp .draw
.none:
    xor r8d,r8d
    xor r9d,r9d
    jmp .set
.custom:
    mov r9,[rel gp_owner_mask]
    test r9,r9
    jz .out
    cmp r9,15
    ja .out
    mov r8d,2
.set:
    ; Copy actual native tuple to the strict setter's native input64.
    lea rsi,[rel gp_owner_current_policy+8]
    lea rdi,[rel gp_owner_input]
    mov ecx,5
    rep movsq
    mov [rel gp_owner_input+40],r8
    mov [rel gp_owner_input+48],r9
    mov qword [rel gp_owner_input+56],0
    ; Final UI/lifetime gate, then strict setter repeats genuine native OWNER,
    ; keyed session, BSP/idle/remote and exact current guest checks. Never yield.
    call gp_owner_current
    test eax,eax
    jz .out
    call gp_ui_endpoint
    test eax,eax
    jz .out
    lea rdx,[rel gp_owner_input]
    mov ecx,64
    call guest_request_command_policy_set
    test eax,eax
    jz .out
    mov byte [rel gp_owner_success],0
    mov byte [rel gp_owner_draft],0
    mov qword [rel gp_owner_mask],0
    ; Capture only successful native setting readback, not a synthetic result.
    call gp_ui_endpoint
    test eax,eax
    jz .labels
    lea rdx,[rel gp_owner_after]
    mov ecx,128
    call guest_request_command_policy_copy
    test eax,eax
    jz .labels
    mov rax,0x00a00001314f5047     ; GPO1 v1 size160
    mov [rel gp_owner_record],rax
    lea rsi,[rel gp_owner_after+8]
    lea rdi,[rel gp_owner_record+8]
    mov ecx,5
    rep movsq
    mov rax,[rel gp_owner_current_policy+48]
    mov [rel gp_owner_record+48],rax
    mov rax,[rel gp_owner_after+48]
    mov [rel gp_owner_record+56],rax
    mov rax,[rel gp_owner_after+56]
    mov [rel gp_owner_record+64],rax
    mov rax,[rel gp_owner_after+64]
    mov [rel gp_owner_record+72],rax
    mov rax,[rel gp_owner_after+88]
    mov [rel gp_owner_record+80],rax
    mov eax,[rel gp_owner_window]
    mov [rel gp_owner_record+88],rax
    mov eax,[rel gp_owner_generation]
    mov [rel gp_owner_record+96],rax
    mov eax,[rel gp_owner_ids]
    mov [rel gp_owner_record+104],rax
    mov rax,[rel gp_owner_births]
    mov [rel gp_owner_record+112],rax
    mov [rel gp_owner_record+120],r12
    lea rax,[rel gp_owner_births]
    mov rax,[rax+rbx*8]
    mov [rel gp_owner_record+128],rax
    mov qword [rel gp_owner_record+136],PRIN_OWNER
    mov qword [rel gp_owner_record+144],WM_PTR_ORIGIN_HUMAN
    mov qword [rel gp_owner_record+152],0
    mov byte [rel gp_owner_success],1
.labels:
    call gp_owner_labels
.draw:
    call wmx_draw_all              ; ordinary render resamples current native state
.out:
    mov eax,r14d
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Four selected labels reflect private local draft bits, never remote values.
gp_owner_labels:
    push rbx
    push r12
    mov ebx,2
.next:
    lea rax,[rel gp_owner_ids]
    mov edi,[rax+rbx*4]
    call wgt_slot_ptr
    mov r12,rax
    lea ecx,[ebx-2]
    mov rax,[rel gp_owner_mask]
    shr rax,cl
    and eax,1
    shl eax,4
    imul edx,ecx,32
    add eax,edx
    lea rsi,[rel gp_owner_labels_data]
    add rsi,rax
    lea rdi,[r12+WGI_VAL]
    xor ecx,ecx
.copy:
    lodsb
    stosb
    test al,al
    jz .length
    inc ecx
    jmp .copy
.length:
    mov [r12+WGI_VLEN],ecx
    inc ebx
    cmp ebx,6
    jb .next
    pop r12
    pop rbx
    ret

; Append an optional original last-success record to the existing scoped getter.
; No current matching native/UI pins means unavailable, never old authority.
gp_owner_append:
    lea rsi,[rel gp_owner_section]
    call gp_ui_put
    cmp byte [rel gp_owner_success],1
    jne .absent
    call gp_owner_current
    test eax,eax
    jz .absent
    lea rsi,[rel gp_owner_record+8]
    lea rdi,[rel gp_ui_policy+8]
    mov ecx,5
    repe cmpsq
    jne .absent
    mov rax,[rel gp_ui_policy+48]
    cmp rax,[rel gp_owner_record+56]
    jne .absent
    mov eax,[rel gp_ui_window]
    cmp rax,[rel gp_owner_record+88]
    jne .absent
    mov eax,[rel gp_ui_generation]
    cmp rax,[rel gp_owner_record+96]
    jne .absent
    mov rax,[rel gp_ui_birth]
    cmp rax,[rel gp_owner_record+112]
    jne .absent
    ; Compact public transition: original before/after generation, native
    ; change time and actual control id/birth. Identity and current setting
    ; are the same scoped GCS1 above; all private tuple/UI pins just matched.
    mov rax,0x00300001314f5047
    mov [rel gp_owner_wire],rax
    mov rax,[rel gp_owner_record+48]
    mov [rel gp_owner_wire+8],rax
    mov rax,[rel gp_owner_record+56]
    mov [rel gp_owner_wire+16],rax
    mov rax,[rel gp_owner_record+80]
    mov [rel gp_owner_wire+24],rax
    mov rax,[rel gp_owner_record+120]
    mov [rel gp_owner_wire+32],rax
    mov rax,[rel gp_owner_record+128]
    mov [rel gp_owner_wire+40],rax
    lea rsi,[rel gp_owner_wire]
    mov ecx,48
    jmp gp_ui_hex
.absent:
    lea rsi,[rel gp_ui_dash]
    jmp gp_ui_put

; Actual installed control birth/generation in the existing WINTREE offer.
gp_owner_tree_state:
    push rbx
    push r12
    mov r12d,edi
    mov ebx,1
.find:
    lea rax,[rel gp_owner_ids]
    cmp r12d,[rax+rbx*4]
    je .have
    inc ebx
    cmp ebx,GP_OWNER_COUNT
    jb .find
    jmp .out
.have:
    call gp_owner_current
    test eax,eax
    jz .out
    lea rdi,[rel gp_owner_tree_birth]
    call f1_put_str
    lea rax,[rel gp_owner_births]
    mov rdi,[rax+rbx*8]
    call f1_put_dec
    lea rdi,[rel gp_owner_tree_generation]
    call f1_put_str
    mov edi,[rel gp_owner_generation]
    call f1_put_dec
.out:
    pop r12
    pop rbx
    ret

%macro WDATA_gui_form_guest_policy_controls 0
gp_owner_names:
%macro GP_OWNER_NAME 1
%%start: db %1,0
    times 32-($-%%start) db 0
%endmacro
    GP_OWNER_NAME 'guest_policy_status'
    GP_OWNER_NAME 'policy_none'
    GP_OWNER_NAME 'wait_status'
    GP_OWNER_NAME 'wait_begin'
    GP_OWNER_NAME 'wait_poll'
    GP_OWNER_NAME 'wait_cancel'
    GP_OWNER_NAME 'policy_custom'
%unmacro GP_OWNER_NAME 1
gp_owner_labels_data:
%macro GP_OWNER_LABEL 1
%%start: db %1,0
    times 16-($-%%start) db 0
%endmacro
    GP_OWNER_LABEL 'STATUS:_off'
    GP_OWNER_LABEL 'STATUS:_on'
    GP_OWNER_LABEL 'BEGIN:_off'
    GP_OWNER_LABEL 'BEGIN:_on'
    GP_OWNER_LABEL 'POLL:_off'
    GP_OWNER_LABEL 'POLL:_on'
    GP_OWNER_LABEL 'CANCEL:_off'
    GP_OWNER_LABEL 'CANCEL:_on'
%unmacro GP_OWNER_LABEL 1
gp_owner_none_label: db 'Set_None',0
gp_owner_apply_label: db 'Apply_Custom',0
gp_owner_tree_birth: db ' guest_control_birth=',0
gp_owner_tree_generation: db ' guest_control_window_generation=',0
gp_owner_section: db 10,'local_hex=',0
align 8
gp_owner_previous: dq 0
gp_owner_ids: times GP_OWNER_COUNT dd -1
gp_owner_births: times GP_OWNER_COUNT dq 0
gp_owner_window: dd 0
gp_owner_generation: dd 0
gp_owner_mask: dq 0
gp_owner_draft_generation: dq 0
gp_owner_draft_session: dq 0
gp_owner_draft_key: dq 0
gp_owner_hooked: db 0
gp_owner_live: db 0
gp_owner_draft: db 0
gp_owner_success: db 0
align 8
gp_owner_input: times 64 db 0
gp_owner_current_policy: times 128 db 0
gp_owner_after: times 128 db 0
gp_owner_record: times GP_OWNER_SIZE db 0
gp_owner_wire: times 48 db 0
%endmacro
WDATA_DEFER WDATA_gui_form_guest_policy_controls
