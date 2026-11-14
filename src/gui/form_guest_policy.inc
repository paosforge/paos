; One read-only native guest policy status view. Ordinary stock listview paint
; and WINTREE use this same bounded renderer. No setter, command or grant.
; SEC owns the read-only observe APIs; ordinary copy/setter guards stay intact.
GP_VIEW_CAP equ 256
GP_OBS_CAP equ 1280

; Exact live built-in form, current chrome window generation and widget birth.
; EDI=widget -> EAX1, R8D window, R9D gen, R10 birth; otherwise0.
gp_ui_current:
    push rbx
    mov ebx,edi
    cmp edi,WGT_MAX
    jae .bad
    cmp byte [rel session_locked],SESSION_LOCKED
    je .bad
    xor esi,esi
    call wgt_secret_hidden
    test eax,eax
    jnz .bad
    mov edi,ebx
    call wgt_slot_ptr
    mov ecx,[rel wgt_listview_type]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    cmp dword [rax+WGI_BIND],FORM_BIND_GUEST_POLICY
    jne .bad
    mov r8d,[rax+WGI_WIN]
    cmp r8d,WM_MAX
    jae .bad
    cmp r8d,[rel form_active_slot+FORM_GUEST_POLICY_INDEX*4]
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+r8*4],WM_VISIBLE
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+r8*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_title]
    lea rdx,[rel form_titles+FORM_GUEST_POLICY_INDEX*FORM_TITLE_MAX]
    cmp [rcx+r8*8],rdx
    jne .bad
    lea rcx,[rel wm_gen]
    mov r9d,[rcx+r8*4]
    test r9d,r9d
    jz .bad
    mov edi,ebx
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    mov r10,rax
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

gp_ui_endpoint:
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel hv_linux_start_consumed]
    cmp esi,[rel hv_linux_start_gen]
    jne .bad
    test esi,esi
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

form_guest_policy_text:
    push rbx
    push r12
    push r13
    mov r12d,edi
    cmp byte [rel gp_ui_busy],0
    jne .recursive
    mov byte [rel gp_ui_busy],1
    mov byte [rel gp_ui_valid],0
    mov byte [rel gp_ui_receipt_valid],0
    call gp_ui_current
    test eax,eax
    jz .bad
    mov [rel gp_ui_window],r8d
    mov [rel gp_ui_generation],r9d
    mov [rel gp_ui_birth],r10
    call gp_ui_endpoint
    test eax,eax
    jz .bad
    lea rdx,[rel gp_ui_receipt]
    mov ecx,128
    call guest_request_receipt_observe
    mov [rel gp_ui_receipt_valid],al
    call gp_ui_endpoint
    test eax,eax
    jz .bad
    lea rdx,[rel gp_ui_policy]
    mov ecx,128
    call guest_request_command_policy_observe
    test eax,eax
    jz .bad
    cmp byte [rel gp_ui_receipt_valid],1
    jne .render
    ; Receipt and setting share an original guest lifetime and last sequence;
    ; the receipt grant generation is NEVER the setting generation.
    lea rsi,[rel gp_ui_receipt+8]
    lea rdi,[rel gp_ui_policy+8]
    mov ecx,5
    cld
    repe cmpsq
    jne .no_receipt
    mov rax,[rel gp_ui_policy+104]
    cmp rax,[rel gp_ui_receipt+48]
    jne .no_receipt
    mov rax,[rel gp_ui_policy+96]
    cmp rax,[rel gp_ui_receipt+120]
    jb .no_receipt
    cmp rax,[rel gp_ui_receipt+112]
    jae .no_receipt
    jmp .render
.no_receipt:
    mov byte [rel gp_ui_receipt_valid],0
.render:
    lea rdi,[rel gp_ui_view]
    mov esi,GP_VIEW_CAP
    call gp_ui_reset
    lea rsi,[rel gp_ui_policy_label]
    call gp_ui_put
    lea rsi,[rel gp_ui_none]
    cmp qword [rel gp_ui_policy+56],0
    je .mode
    cmp qword [rel gp_ui_policy+56],2
    jne .bad
    lea rsi,[rel gp_ui_custom]
.mode:
    call gp_ui_put
    lea rsi,[rel gp_ui_basic_mask]
    call gp_ui_put
    mov rdi,[rel gp_ui_policy+64]
    call gp_ui_dec
    lea rsi,[rel gp_ui_ceiling_label]
    call gp_ui_put
    mov rax,[rel gp_ui_policy+112]
    lea rsi,[rel gp_ui_unchecked]
    cmp rax,2
    je .ceiling
    lea rsi,[rel gp_ui_refused]
    test rax,rax
    jz .ceiling
    cmp rax,1
    jne .bad
    lea rsi,[rel gp_ui_passed]
.ceiling:
    call gp_ui_put
    lea rsi,[rel gp_ui_sequence_label]
    call gp_ui_put
    mov rdi,[rel gp_ui_policy+104]
    call gp_ui_dec
    lea rsi,[rel gp_ui_result_label]
    call gp_ui_put
    mov rdi,[rel gp_ui_receipt+96]
    call gp_ui_receipt_value
    lea rsi,[rel gp_ui_grant_label]
    call gp_ui_put
    mov rdi,[rel gp_ui_receipt+72]
    call gp_ui_receipt_value
    lea rsi,[rel gp_ui_authority]
    call gp_ui_put
    call gp_ui_finish
    test eax,eax
    jz .bad
    mov edi,r12d
    call gp_ui_current
    test eax,eax
    jz .bad
    cmp r8d,[rel gp_ui_window]
    jne .bad
    cmp r9d,[rel gp_ui_generation]
    jne .bad
    cmp r10,[rel gp_ui_birth]
    jne .bad
    call gp_ui_endpoint
    test eax,eax
    jz .bad
    call guest_request_command_policy_current
    test eax,eax
    jz .bad
    cmp rdx,[rel gp_ui_policy+48]
    jne .bad
    cmp byte [rel gp_ui_receipt_valid],1
    jne .good
    call time_monotonic_now_us
    cmp rax,[rel gp_ui_receipt+120]
    jb .bad
    cmp rax,[rel gp_ui_receipt+112]
    jae .bad
.good:
    mov byte [rel gp_ui_valid],1
    lea rax,[rel gp_ui_view]
    jmp .out
.bad:
    lea rax,[rel gp_ui_unavailable_view]
.out:
    mov byte [rel gp_ui_busy],0
    jmp .done
.recursive:
    ; Do not clear or reuse a recursive caller's ownership/snapshot.
    lea rax,[rel gp_ui_unavailable_view]
.done:
    pop r13
    pop r12
    pop rbx
    ret

gp_ui_receipt_value:
    cmp byte [rel gp_ui_receipt_valid],1
    je gp_ui_dec
    lea rsi,[rel gp_ui_unavailable]
    jmp gp_ui_put

; Typed getter retains actual renderer output and the exact native inputs.
; Only public scalars, never native addresses, keys or a reconstructed label.
form_guest_policy_observe:
    push rbx
    push r12
    push r13
    mov r12d,edi
    cmp byte [rel gp_ui_busy],0
    jne .bad
    call form_guest_policy_text
    cmp byte [rel gp_ui_valid],1
    jne .bad
    lea rdi,[rel gp_ui_observation]
    mov esi,GP_OBS_CAP
    call gp_ui_reset
    lea rsi,[rel gp_ui_header]
    call gp_ui_put
    mov edi,[rel gp_ui_window]
    call gp_ui_dec
    lea rsi,[rel gp_ui_gen_label]
    call gp_ui_put
    mov edi,[rel gp_ui_generation]
    call gp_ui_dec
    lea rsi,[rel gp_ui_birth_label]
    call gp_ui_put
    mov rdi,[rel gp_ui_birth]
    call gp_ui_dec
    lea rsi,[rel gp_ui_widget_label]
    call gp_ui_put
    mov edi,r12d
    call gp_ui_dec
    lea rsi,[rel gp_ui_view_label]
    call gp_ui_put
    lea rsi,[rel gp_ui_view]
    xor ecx,ecx
.count:
    cmp byte [rsi+rcx],0
    je .view
    inc ecx
    cmp ecx,GP_VIEW_CAP
    jae .bad
    jmp .count
.view:
    call gp_ui_hex
    lea rsi,[rel gp_ui_native_label]
    call gp_ui_put
    lea rsi,[rel gp_ui_policy]
    mov ecx,128
    call gp_ui_hex
    lea rsi,[rel gp_ui_receipt_label]
    call gp_ui_put
    cmp byte [rel gp_ui_receipt_valid],1
    jne .absent
    lea rsi,[rel gp_ui_receipt]
    mov ecx,128
    call gp_ui_hex
    jmp .finish
.absent:
    lea rsi,[rel gp_ui_dash]
    call gp_ui_put
.finish:
    call gp_owner_append
    ; Existing WGT_OUT_MAX=1152, including its stock getter id/field prefix.
    ; Refuse before staging; neither formatter nor transport may truncate success.
    mov rax,[rel gp_ui_cursor]
    lea rdx,[rel gp_ui_observation]
    sub rax,rdx
    cmp rax,1088
    jae .bad
    call gp_ui_finish
    test eax,eax
    jz .bad
    ; Serialization is non-yielding; recheck time and current native/UI pins.
    mov edi,r12d
    call gp_ui_current
    test eax,eax
    jz .bad
    cmp r8d,[rel gp_ui_window]
    jne .bad
    cmp r9d,[rel gp_ui_generation]
    jne .bad
    cmp r10,[rel gp_ui_birth]
    jne .bad
    call gp_ui_endpoint
    test eax,eax
    jz .bad
    call guest_request_command_policy_current
    test eax,eax
    jz .bad
    cmp rdx,[rel gp_ui_policy+48]
    jne .bad
    cmp byte [rel gp_ui_receipt_valid],1
    jne .good
    call time_monotonic_now_us
    cmp rax,[rel gp_ui_receipt+120]
    jb .bad
    cmp rax,[rel gp_ui_receipt+112]
    jae .bad
.good:
    lea rax,[rel gp_ui_observation]
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; WINTREE retains the generation/birth of the same actual bound render.
; These are joins only, never operation authority or a view supplied by caller.
gp_ui_tree_state:
    push rbx
    cmp byte [rel gp_ui_valid],1
    jne .out
    call gp_ui_current
    test eax,eax
    jz .out
    cmp r8d,[rel gp_ui_window]
    jne .out
    cmp r9d,[rel gp_ui_generation]
    jne .out
    cmp r10,[rel gp_ui_birth]
    jne .out
    call gp_ui_endpoint
    test eax,eax
    jz .out
    call guest_request_command_policy_current
    test eax,eax
    jz .out
    cmp rdx,[rel gp_ui_policy+48]
    jne .out
    lea rdi,[rel gp_ui_tree_policy]
    call f1_put_str
    mov rdi,[rel gp_ui_policy+48]
    call f1_put_dec
    lea rdi,[rel gp_ui_tree_window]
    call f1_put_str
    mov edi,[rel gp_ui_generation]
    call f1_put_dec
    lea rdi,[rel gp_ui_tree_birth]
    call f1_put_str
    mov rdi,[rel gp_ui_birth]
    call f1_put_dec
.out:
    pop rbx
    ret

; Bounded common formatter. Overflow refuses; no truncated observation success.
gp_ui_reset:
    mov [rel gp_ui_cursor],rdi
    lea rax,[rdi+rsi-1]
    mov [rel gp_ui_end],rax
    mov byte [rel gp_ui_overflow],0
    ret
gp_ui_byte:
    mov rdx,[rel gp_ui_cursor]
    cmp rdx,[rel gp_ui_end]
    jae .full
    mov [rdx],al
    inc rdx
    mov [rel gp_ui_cursor],rdx
    ret
.full:
    mov byte [rel gp_ui_overflow],1
    ret
gp_ui_put:
    mov al,[rsi]
    test al,al
    jz .out
    call gp_ui_byte
    inc rsi
    jmp gp_ui_put
.out:
    ret
gp_ui_dec:
    lea rsi,[rel gp_ui_number]
    call fmt_dec
    lea rsi,[rel gp_ui_number]
    mov byte [rsi+rax],0
    jmp gp_ui_put
gp_ui_hex:
    test ecx,ecx
    jz .out
    movzx r13d,byte [rsi]
    mov eax,r13d
    shr eax,4
    lea rdi,[rel gp_ui_digits]
    mov al,[rdi+rax]
    call gp_ui_byte
    mov eax,r13d
    and eax,15
    mov al,[rdi+rax]
    call gp_ui_byte
    inc rsi
    dec ecx
    jmp gp_ui_hex
.out:
    ret
gp_ui_finish:
    mov rdx,[rel gp_ui_cursor]
    mov byte [rdx],0
    movzx eax,byte [rel gp_ui_overflow]
    xor eax,1
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_form_guest_policy 0
gp_ui_tree_policy: db ' guest_policy_generation=',0
gp_ui_tree_window: db ' guest_window_generation=',0
gp_ui_tree_birth: db ' guest_widget_birth=',0
gp_ui_policy_label: db 'Policy: ',0
gp_ui_none: db 'None',0
gp_ui_custom: db 'Custom',0
gp_ui_basic_mask: db ',Basic: unavailable,Wait mask: ',0
gp_ui_ceiling_label: db ',Ceiling: ',0
gp_ui_refused: db 'refused',0
gp_ui_passed: db 'passed (not granted)',0
gp_ui_unchecked: db 'unchecked',0
gp_ui_sequence_label: db ',Sequence: ',0
gp_ui_result_label: db ',Result code: ',0
gp_ui_grant_label: db ',Grant generation: ',0
gp_ui_authority: db ',Authority: separate operation grant',0
gp_ui_unavailable: db 'unavailable',0
gp_ui_unavailable_view: db 'Policy: unavailable,Basic: unavailable,Wait mask: unavailable,Ceiling: unavailable,Sequence: unavailable,Result code: unavailable,Grant generation: unavailable,Authority: separate operation grant',0
gp_ui_header: db 'GPUI1 v=1 window=',0
gp_ui_gen_label: db ' generation=',0
gp_ui_birth_label: db ' birth=',0
gp_ui_widget_label: db ' widget=',0
gp_ui_view_label: db 10,'view_hex=',0
gp_ui_native_label: db 10,'policy_hex=',0
gp_ui_receipt_label: db 10,'receipt_hex=',0
gp_ui_dash: db '-',0
gp_ui_digits: db '0123456789abcdef'
align 8
gp_ui_cursor: dq 0
gp_ui_end: dq 0
gp_ui_birth: dq 0
gp_ui_window: dd 0
gp_ui_generation: dd 0
gp_ui_busy: db 0
gp_ui_valid: db 0
gp_ui_receipt_valid: db 0
gp_ui_overflow: db 0
gp_ui_number: times 24 db 0
gp_ui_view: times GP_VIEW_CAP db 0
gp_ui_observation: times GP_OBS_CAP db 0
align 8
gp_ui_policy: times 128 db 0
gp_ui_receipt: times 128 db 0

%endmacro
WDATA_DEFER WDATA_gui_form_guest_policy
