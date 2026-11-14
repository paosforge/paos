;; MODULE gui/app_widget
;; LAYER 6
;; PURPOSE Typed app-owned form and widget adapter through the existing guest route.
;; EXPORTS app_widget_observe, app_widget_init, app_widget_tick, app_widget_handle
;; IMPORTS gui/app_reader, hv/app_widget_transport, hv/guest_request, sec/app_binding, gui/chat_send, gui/widget, gui/widget_listview, gui/widget_chart, gui/widget_scalar_inputs, gui/widget_progress, gui/window_mgmt, core/lib/fmt, core/lib/sha256
;; CAPS CAP_GUI
;; OWNER saga:app_widget
;; CONTEXT: bsp_only
; Typed native adapter, never a command verb. Exact app-owned form identities
; come from app_binding; no caller window, event or click is treated as proof.
AWG_GET equ 1
AWG_SET equ 2
AWG_WINDOW equ 3
AWG_FORM_OPEN equ 4
AWG_FORM_FOCUS equ 5
AWG_SELECTION equ 6
AWG_READER_BEGIN equ 7
AWG_READER_APPEND equ 8
AWG_READER_COMMIT equ 9
AWG_READER_PAGE equ 10
AWG_ITEMS equ 11                        ; A1b: replace a stock list's items
AWG_PUSH equ 12                         ; A1b: append stock chart samples
AWG_F_WINDOW equ 16
AWG_F_RESERVED equ 24
AWG_F_LEN equ 32
AWG_F_NAME equ 40
AWG_F_VALUE equ 72
AWG_NAME_BYTES equ 32
AWG_VALUE_BYTES equ 256
AWG_R_WINDOW equ 16
AWG_R_LEN equ 24
AWG_R_VALUE equ 32
AWG_BUSY equ 9                          ; refused for now; nothing is queued
AWG_TICK_SETS equ 4
AWG_SPAN_SETS equ 16
AWG_SPAN_US equ 100000

app_widget_init:
    lea rdi,[rel app_widget_handle]
    jmp app_widget_transport_configure

; One desktop tick's SET budget. Unwired or starved ticks fail closed.
app_widget_tick:
    mov dword [rel awg_tick_sets],0
    ret

; RDI native frame328, RSI native reply288, RDX current binding48 -> EAX code.
; Called by the transport on the stopped app vCPU's exit, on the BSP. Each call
; rechecks authority here, at the point of the widget work.
app_widget_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov qword [rsp],0                 ; no policy resolution on early refusal
    mov qword [rsp+8],0               ; value kind: 0 = plain text widget
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    call smp_current_logical
    test eax,eax
    jnz .deny
    cmp byte [rel cmd_in_dispatch],0
    jne .deny
    cmp dword [rel cmd_dispatch_depth],0
    jne .deny
    cmp byte [rel command_auth_remote_active],0
    jne .deny
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .deny
    call gr_confirmation_blocked
    test eax,eax
    jnz .deny
    cmp dword [rbx],1
    jne .badarg
    mov eax,[rbx+4]
    dec eax
    cmp eax,AWG_PUSH-1
    ja .badarg
    cmp dword [rbx+4],AWG_FORM_OPEN
    je .form_open
    mov rdi,r13
    mov rsi,[rbx+AWG_F_WINDOW]
    call app_binding_widget_member       ; exact member + WAIT BEGIN ALLOW
    mov [rsp],rdx                       ; exact original policy receipt serial
    test rax,rax
    jz .deny
    mov r14,rax
    cmp dword [rbx+4],AWG_WINDOW
    je .window
    cmp [rbx+AWG_F_WINDOW],r14
    jne .deny
    cmp dword [rbx+4],AWG_READER_BEGIN
    jb .reserved
    cmp dword [rbx+4],AWG_READER_PAGE
    jbe .named                          ; reader ops carry their own operand
.reserved:
    cmp qword [rbx+AWG_F_RESERVED],0
    jne .badarg
    cmp dword [rbx+4],AWG_FORM_FOCUS
    je .form_focus
    cmp dword [rbx+4],AWG_SELECTION
    jne .named
    call awg_no_value
    test eax,eax
    jz .badarg
.named:
    ; A chat form's text is human intent on its way to a provider: neither
    ; direction is open to its guest. Native chat_send owns those widgets.
    movzx edi,r14b
    call chat_send_owns_window
    test eax,eax
    jnz .deny
    call awg_name_ok
    test eax,eax
    jz .badarg
    movzx edi,r14b
    lea rsi,[rbx+AWG_F_NAME]
    call awg_find
    cmp eax,-1
    je .deny
    mov r15d,eax
    mov edi,r15d
    call wgt_slot_ptr
    cmp dword [rbx+4],AWG_SELECTION
    je .selection
    cmp dword [rbx+4],AWG_ITEMS
    jae .data
    cmp dword [rbx+4],AWG_READER_BEGIN
    jae .reader
    mov rdi,rax
    call awg_plain_text
    test eax,eax
    jnz .typed
    mov edi,r15d
    call awg_value_kind                  ; stock toggle/slider/numeric/progress
    test eax,eax
    jz .deny
    mov [rsp+8],rax
.typed:
    cmp dword [rbx+4],AWG_SET
    je .set
    ; GET carries no value and returns the same bytes the type's reader gives.
    cmp qword [rbx+AWG_F_LEN],0
    jne .badarg
    lea rdi,[rbx+AWG_F_VALUE]
    mov ecx,AWG_VALUE_BYTES/8
    xor eax,eax
    repe scasq
    jne .badarg
    mov edi,r15d
    call wgt_slot_ptr
    mov ecx,[rax+WGI_TYPE]
    dec ecx
    imul rcx,rcx,WT_SZ
    lea rax,[rel wgt_types]
    mov rax,[rax+rcx+WT_GET]
    mov edi,r15d
    lea rsi,[rel str_wf_value]
    call rax
    test rax,rax
    jz .deny
    xor ecx,ecx
.get_copy:
    cmp ecx,AWG_VALUE_BYTES-1
    jae .get_done
    mov dl,[rax+rcx]
    test dl,dl
    jz .get_done
    mov [r12+AWG_R_VALUE+rcx],dl
    inc ecx
    jmp .get_copy
.get_done:
    mov [r12+AWG_R_LEN],rcx
    jmp .ok
.set:
    call chat_send_pending
    test rax,rax
    jnz .deny
    mov edi,r15d
    call wgt_slot_ptr
    cmp dword [rax+WGI_BIND],0           ; native live state owns this text
    jne .deny
    cmp r15d,[rel wgt_focus_id]          ; never rewrite under the human's typing
    je .busy
    cmp r15d,[rel wgt_press_id]          ; nor under a press in progress
    je .busy
    cmp qword [rsp+8],0
    je .set_display
    cmp r15d,[rel wgt_scalar_capture_id] ; nor under a live slider drag
    je .busy
.set_display:
    cmp byte [rel dpms_blanked],0        ; setting text paints
    jne .busy
    mov edi,r15d
    cmp qword [rsp+8],0
    jne .set_number
    call awg_value_ok
    jmp .set_checked
.set_number:
    mov esi,[rsp+8]
    call awg_number_ok
.set_checked:
    test eax,eax
    jz .badarg
    call awg_rate_ok
    test eax,eax
    jz .busy
    mov edi,r15d
    call wgt_slot_ptr
    mov ecx,[rax+WGI_TYPE]
    dec ecx
    imul rcx,rcx,WT_SZ
    lea rax,[rel wgt_types]
    mov rax,[rax+rcx+WT_SET]
    mov edi,r15d
    lea rsi,[rel str_wf_value]
    lea rdx,[rbx+AWG_F_VALUE]
    call rax
    test eax,eax
    jnz .badarg
    jmp .ok
.reader:
    mov ecx,[rel app_reader_type]
    cmp ecx,-1
    je .deny
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .deny
    test dword [rax+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .deny
    cmp dword [rax+WGI_BIND],0
    jne .deny
    cmp dword [rbx+4],AWG_READER_APPEND
    je .reader_append
    call awg_no_value
    test eax,eax
    jz .badarg
    mov rax,[rbx+AWG_F_RESERVED]
    cmp dword [rbx+4],AWG_READER_BEGIN
    jne .reader_other
    cmp rax,4096
    ja .badarg
    jmp .reader_ready
.reader_other:
    cmp dword [rbx+4],AWG_READER_COMMIT
    jne .reader_page
    test rax,rax
    jnz .badarg
    jmp .reader_ready
.reader_page:
    cmp rax,2
    ja .badarg
    jmp .reader_ready
.reader_append:
    mov rcx,[rbx+AWG_F_LEN]
    test rcx,rcx
    jz .badarg
    cmp rcx,AWG_VALUE_BYTES
    ja .badarg
    mov rax,[rbx+AWG_F_RESERVED]
    cmp rax,4096
    jae .badarg
    add rax,rcx
    cmp rax,4096
    ja .badarg
.reader_tail:
    cmp ecx,AWG_VALUE_BYTES
    jae .reader_ready
    cmp byte [rbx+AWG_F_VALUE+rcx],0
    jne .badarg
    inc ecx
    jmp .reader_tail
.reader_ready:
    cmp byte [rel dpms_blanked],0
    jne .busy
    call chat_send_pending
    test rax,rax
    jnz .deny
    call awg_rate_ok
    test eax,eax
    jz .busy
    mov edi,r15d
    mov esi,[rbx+4]
    mov rdx,[rbx+AWG_F_RESERVED]
    lea rcx,[rbx+AWG_F_VALUE]
    mov r8,[rbx+AWG_F_LEN]
    call app_reader_write
    test eax,eax
    jnz .badarg
    jmp .ok
.selection:
    mov ecx,[rel wgt_listview_type]
    cmp ecx,-1
    je .deny
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .deny
    test dword [rax+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .deny
    mov edi,[rax+WGI_SEL_LO]
    lea rsi,[r12+AWG_R_VALUE]
    call fmt_dec
    mov [r12+AWG_R_LEN],rax
    jmp .ok
.data:
    ; A1b list items / chart samples. Stock type only, never secret text or
    ; native live state. Same fences as text SET; the type leaf checks the whole
    ; value before the one rate charge and applies it only after.
    test dword [rax+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .deny
    cmp dword [rax+WGI_BIND],0           ; native live state owns this widget
    jne .deny
    mov ecx,[rel wgt_listview_type]
    cmp dword [rbx+4],AWG_ITEMS
    je .data_type
    mov ecx,[rel wgt_chart_type]
.data_type:
    cmp ecx,-1
    je .deny
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .deny
    call chat_send_pending
    test rax,rax
    jnz .deny                            ; data: a chat Send is pending
    cmp r15d,[rel wgt_focus_id]          ; the human is using this widget
    je .busy
    cmp r15d,[rel wgt_press_id]
    je .busy
    cmp byte [rel dpms_blanked],0        ; the effect paints
    jne .busy
    mov edx,WGT_TEXTFIELD_VAL_MAX        ; the list's inline option store
    cmp dword [rbx+4],AWG_ITEMS
    je .data_bound
    mov edx,AWG_VALUE_BYTES-1
.data_bound:
    call awg_data_ok
    test eax,eax
    jz .badarg
    xor edx,edx
    call awg_data_leaf
    test eax,eax
    jnz .data_refused
    call awg_rate_ok                     ; charged once, after the check
    test eax,eax
    jz .busy
    mov edx,1
    call awg_data_leaf
    test eax,eax
    jz .ok
.data_refused:
    cmp eax,1
    je .badarg
    cmp eax,3
    je .busy
    jmp .deny
.form_open:
    cmp qword [rbx+AWG_F_WINDOW],0
    jne .badarg
    cmp qword [rbx+AWG_F_RESERVED],0
    jne .badarg
    call awg_name_ok
    test eax,eax
    jz .badarg
    call awg_no_value
    test eax,eax
    jz .badarg
    cmp byte [rel dpms_blanked],0
    jne .busy
    mov rdi,r13
    lea rsi,[rbx+AWG_F_NAME]
    call app_binding_form_open
    mov [rsp],rdx
    test rax,rax
    jz .deny
    mov r14,rax
    jmp .reveal
.form_focus:
    cmp qword [rbx+AWG_F_LEN],0
    jne .badarg
    lea rdi,[rbx+AWG_F_NAME]
    mov ecx,(AWG_NAME_BYTES+AWG_VALUE_BYTES)/8
    xor eax,eax
    repe scasq
    jne .badarg
    cmp byte [rel dpms_blanked],0
    jne .busy
.reveal:
    call awg_reveal
    test eax,eax
    jz .deny
    jmp .ok
.window:
    lea rdi,[rbx+AWG_F_WINDOW]
    mov ecx,(AWG_F_VALUE+AWG_VALUE_BYTES-AWG_F_WINDOW)/8
    xor eax,eax
    repe scasq
    jne .badarg
.ok:
    mov [r12+AWG_R_WINDOW],r14
    xor eax,eax
    jmp .out
.busy:
    mov eax,AWG_BUSY
    jmp .out
.badarg:
    mov eax,CMDE_BADARG
    jmp .out
.deny:
    mov eax,CMDE_AUTHDENY
.out:
    mov rdi,[rsp]
    mov esi,[rbx+4]
    mov rdx,[rbx+8]
    mov ecx,eax
    call app_binding_widget_finish
    call awg_record
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; No keyboard transfer across applications. R13 actual admitted binding,
; R14 exact target. A current same-app focus may move through ordinary native
; raise (which still applies frame focus policy); other focus gets attention.
awg_reveal:
    push rbx
    movzx edi,r14b
    cmp edi,WM_MAX
    jae .bad
    lea rax,[rel wm_state]
    cmp dword [rax+rdi*4],WM_VISIBLE
    je .state_ok
    cmp dword [rax+rdi*4],WM_MIN
    jne .bad
.state_ok:
    mov ebx,[rel wm_focus]
    cmp ebx,WM_MAX
    jae .attention
    lea rax,[rel wm_owner]
    mov rax,[rax+rbx*8]
    cmp rax,[r13]
    jne .attention
    movzx edi,r14b
    call wmx_raise_slot
    mov eax,1
    pop rbx
    ret
.attention:
    movzx edi,r14b
    call wmx_reveal_slot
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RBX frame ->1 iff value length and the entire value area are zero.
awg_no_value:
    cmp qword [rbx+AWG_F_LEN],0
    jne .bad
    lea rdi,[rbx+AWG_F_VALUE]
    mov ecx,AWG_VALUE_BYTES/8
    xor eax,eax
    repe scasq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

 ; Passive last original typed request receipt. No text, endpoint or pointer
; survives: just fixed identities, operation/result, and bounded byte hashes.
; RBX frame328/R13 native binding48/EAX original handler result.
awg_record:
    push rax
    cmp qword [rel awg_serial],-1
    je .out
    lea rdi,[rel awg_identity]
    call app_binding_observe
    cmp eax,1
    jne .out
    mov rax,[r13]
    cmp [rel awg_identity+8],rax
    jne .out
    mov rax,[r13+24]
    cmp [rel awg_identity+16],rax
    jne .out
    mov rax,[r13+32]
    cmp [rel awg_identity+24],rax
    jne .out
    mov rax,[r13+40]
    cmp [rel awg_identity+32],rax
    jne .out
    lea rdi,[rel awg_target]
    lea rsi,[rel awg_identity+72]
    mov ecx,4
    rep movsq
    inc qword [rel awg_serial]
    mov qword [rel awg_receipt],1
    mov rax,[rel awg_serial]
    mov [rel awg_receipt+8],rax
    mov rax,[rel awg_identity+8]
    mov [rel awg_receipt+16],rax
    mov rax,[r13+8]
    mov [rel awg_receipt+24],rax
    lea rdi,[rel awg_receipt+32]
    lea rsi,[rel awg_identity+16]
    mov ecx,3
    rep movsq
    mov eax,[rbx+4]
    mov [rel awg_receipt+56],rax
    mov rax,[rbx+8]
    mov [rel awg_receipt+64],rax
    mov rax,[rbx+16]
    mov [rel awg_receipt+72],rax
    mov rax,[rsp]
    mov [rel awg_receipt+80],rax
    mov rax,[rel awg_identity+48]        ; actual primary full raw generation
    mov [rel awg_receipt+88],rax
    mov rax,[rel awg_identity+56]        ; actual primary reset generation
    mov [rel awg_receipt+96],rax
    lea rdi,[rel awg_receipt+104]
    lea rsi,[rbx+40]
    mov edx,32
    call sha256_hash
    lea rdi,[rel awg_receipt+136]
    lea rsi,[rbx+72]
    mov edx,256
    call sha256_hash
    mov rax,[rbx+32]
    mov [rel awg_receipt+168],rax
.out:
    pop rax
    ret

; Native owner capture: RDI target digest32, RSI output176. Caller zeroes.
; Epoch and target joins refuse old-app receipts; never grants access/effects.
app_widget_observe:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    cmp rdx,[rel awg_receipt+48]
    jne .out
    mov rdi,rbx
    lea rsi,[rel awg_target]
    mov ecx,4
    repe cmpsq
    jne .out
    mov rdi,r12
    lea rsi,[rel awg_receipt]
    mov ecx,22
    rep movsq
.out:
    pop r12
    pop rbx
    ret

; RBX frame. A name is 1..31 bytes, NUL ended, with nothing after the NUL.
awg_name_ok:
    xor ecx,ecx
.len:
    cmp ecx,AWG_NAME_BYTES
    jae .bad
    cmp byte [rbx+AWG_F_NAME+rcx],0
    je .end
    inc ecx
    jmp .len
.end:
    test ecx,ecx
    jz .bad
.rest:
    cmp ecx,AWG_NAME_BYTES
    jae .good
    cmp byte [rbx+AWG_F_NAME+rcx],0
    jne .bad
    inc ecx
    jmp .rest
.good:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI slot, RSI name -> EAX the one live widget with that id there, else -1.
awg_find:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r12d,edi
    mov r13,rsi
    xor ebx,ebx
    mov r14d,-1
.loop:
    cmp ebx,[rel wgt_count]
    jae .done
    cmp ebx,WGT_MAX
    jae .bad
    mov edi,ebx
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],0
    je .next
    cmp [rax+WGI_WIN],r12d
    jne .next
    mov rdi,[rax+WGI_ID]
    test rdi,rdi
    jz .next
    mov rsi,r13
    call strcmp
    test eax,eax
    jnz .next
    cmp r14d,-1
    jne .bad                             ; an ambiguous name reaches nothing
    mov r14d,ebx
.next:
    inc ebx
    jmp .loop
.bad:
    mov r14d,-1
.done:
    mov eax,r14d
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI slot pointer -> EAX1 only for a stock label, textfield or button that
; holds neither a secret nor native security text. Both directions.
awg_plain_text:
    push rbx
    mov rbx,rdi
    mov eax,[rbx+WGI_TYPE]
    cmp eax,WGT_TYPE_BUTTON
    je .type_ok
    cmp eax,WGT_TYPE_TEXTFIELD
    je .type_ok
    cmp eax,WGT_TYPE_LABEL
    jne .bad
.type_ok:
    test dword [rbx+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .bad
    mov rsi,[rbx+WGI_ROLE]
    test rsi,rsi
    jz .good
    lea rdi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jz .bad
.good:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; A1a. EDI widget -> EAX 1 toggle, 2 slider, 3 numeric, 4 progress, else 0.
; Only the stock row of that registered type, with its stock setter AND getter,
; and only outside the classes snapshot.asm withholds (native security text,
; role password) and outside native live state (WGI_BIND, progress job_id).
; Both directions. The field reached is always "value".
awg_value_kind:
    push rbx
    push r12
    sub rsp,8
    call wgt_slot_ptr
    mov rbx,rax
    mov eax,[rbx+WGI_TYPE]
    test eax,eax
    jz .bad
    dec eax                              ; registered vtable index
    cmp eax,WTYPE_MAX
    jae .bad
    imul ecx,eax,WT_SZ
    lea rdx,[rel wgt_types]
    add rdx,rcx
    lea r8,[rel wgt_scalar_set]
    lea r9,[rel wgt_scalar_get]
    mov r12d,1
    cmp eax,[rel wgt_scalar_toggle_type]
    je .stock
    mov r12d,2
    cmp eax,[rel wgt_scalar_slider_type]
    je .stock
    mov r12d,3
    cmp eax,[rel wgt_scalar_numeric_type]
    je .stock
    mov r12d,4
    cmp eax,PG_TYPE-1
    jne .bad
    cmp qword [rbx+PG_JOB],0             ; a job-bound bar shows native state
    jne .bad
    lea r8,[rel wgt_progress_set]
    lea r9,[rel wgt_progress_get]
.stock:
    cmp r8,[rdx+WT_SET]
    jne .bad
    cmp r9,[rdx+WT_GET]
    jne .bad
    test dword [rbx+WGI_EDIT],WGT_EDIT_SECTEXT ; withheld by snapshot too
    jnz .bad
    cmp dword [rbx+WGI_BIND],0           ; native live state owns this value
    jne .bad
    mov rsi,[rbx+WGI_ROLE]
    test rsi,rsi
    jz .good
    lea rdi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jz .bad
.good:
    mov eax,r12d
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RBX frame, EDI widget, ESI kind -> EAX1 for one canonical unsigned decimal
; (1..10 digits, no leading zero but "0", <= 2^31-1, nothing after it) that
; the stock store keeps exactly: a toggle 0 or 1, and every scalar within its
; own min..max and on its step. The stock progress setter itself refuses a
; value above max. Nothing is clamped, stepped or truncated.
awg_number_ok:
    push r12
    push r13
    push r14
    mov r12d,esi
    mov r13d,edi
    mov rcx,[rbx+AWG_F_LEN]              ; empty fails the first digit: its area is zero
    cmp rcx,10
    ja .bad
    mov edx,ecx
.tail:
    cmp edx,AWG_VALUE_BYTES
    jae .lead
    cmp byte [rbx+AWG_F_VALUE+rdx],0
    jne .bad
    inc edx
    jmp .tail
.lead:
    cmp rcx,1
    je .parse
    cmp byte [rbx+AWG_F_VALUE],'0'       ; canonical: one spelling per value
    je .bad
.parse:
    xor eax,eax
    xor edx,edx
.digit:
    movzx r8d,byte [rbx+AWG_F_VALUE+rdx]
    sub r8d,'0'
    cmp r8d,9
    ja .bad
    imul rax,rax,10
    add rax,r8
    inc edx
    cmp rdx,rcx
    jb .digit
    cmp rax,0x7fffffff
    ja .bad
    mov r14,rax
    cmp r12d,4
    je .good
    cmp r12d,1
    jne .range
    cmp r14,1                            ; a toggle is exactly off or on
    ja .bad
.range:
    mov edi,r13d
    call wgt_slot_ptr
    cmp r14,[rax+WGI_MINVAL]
    jb .bad
    cmp r14,[rax+WGI_MAXVAL]
    ja .bad
    mov rcx,[rax+WGI_STEP]
    cmp rcx,1
    jbe .good
    mov r8,rax
    mov rax,r14
    sub rax,[r8+WGI_MINVAL]
    xor edx,edx
    div rcx
    test rdx,rdx
    jnz .bad
.good:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    ret

; RBX frame, EDI widget -> EAX1 for exact-length printable UTF-8 within the
; widget's own bound. Too long refuses; nothing is ever truncated.
awg_value_ok:
    push r12
    mov r12,[rbx+AWG_F_LEN]
    cmp r12,AWG_VALUE_BYTES-1
    ja .bad
    call wgt_slot_ptr
    mov edx,WGI_VAL_MAX
    cmp dword [rax+WGI_TYPE],WGT_TYPE_TEXTFIELD
    jne .bound
    call wgt_tf_buf
    mov edx,ecx
.bound:
    cmp r12,rdx
    ja .bad
    xor ecx,ecx
.bytes:
    cmp rcx,r12
    jae .rest
    movzx eax,byte [rbx+AWG_F_VALUE+rcx]
    cmp eax,0x20                         ; NUL and every other control byte
    jb .bad
    cmp eax,0x7f
    je .bad
    inc ecx
    jmp .bytes
.rest:
    cmp ecx,AWG_VALUE_BYTES
    jae .utf8
    cmp byte [rbx+AWG_F_VALUE+rcx],0
    jne .bad
    inc ecx
    jmp .rest
.utf8:
    lea rdi,[rbx+AWG_F_VALUE]
    mov esi,r12d
    call ue_utf8_validate
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    ret

; RBX frame, R15 widget, EDX 0 check or 1 apply -> EAX the type leaf's code:
; 0 done, 1 malformed, 2 refused, 3 busy.
awg_data_leaf:
    mov edi,r15d
    lea rsi,[rbx+AWG_F_VALUE]
    cmp dword [rbx+4],AWG_ITEMS
    je wgt_listview_fill
    jmp wgt_chart_append

; RBX frame, EDX bound -> EAX1 iff 1..bound value bytes, none a control byte
; or DEL, a zero tail and valid UTF-8 (the text SET byte rule, nonempty).
awg_data_ok:
    mov rcx,[rbx+AWG_F_LEN]
    test rcx,rcx
    jz .none
    cmp rcx,rdx
    ja .none
    push r12
    mov r12,rcx
    xor ecx,ecx
.bytes:
    cmp rcx,r12
    jae .rest
    movzx eax,byte [rbx+AWG_F_VALUE+rcx]
    cmp eax,0x20                         ; data: NUL and every control byte
    jb .bad
    cmp eax,0x7f                         ; data: DEL
    je .bad
    inc ecx
    jmp .bytes
.rest:
    cmp ecx,AWG_VALUE_BYTES
    jae .utf8
    cmp byte [rbx+AWG_F_VALUE+rcx],0     ; data: zero tail
    jne .bad
    inc ecx
    jmp .rest
.utf8:
    lea rdi,[rbx+AWG_F_VALUE]
    mov esi,r12d
    call ue_utf8_validate                ; data: valid UTF-8
    pop r12
    ret
.bad:
    pop r12
.none:
    xor eax,eax
    ret

; R13 binding48 -> EAX1 and one SET charged, or EAX0. Limits per tick and per
; binding keep a guest from flooding repaint or starving input.
awg_rate_ok:
    cmp dword [rel awg_tick_sets],AWG_TICK_SETS
    jae .bad
    sub rsp,8
    call time_monotonic_now_us
    add rsp,8
    test rax,rax
    jz .bad
    mov rcx,[r13+8]
    cmp rcx,[rel awg_binding]
    jne .new_span
    mov rcx,rax
    sub rcx,[rel awg_span_start]
    jc .new_span
    cmp rcx,AWG_SPAN_US
    jae .new_span
    cmp dword [rel awg_span_sets],AWG_SPAN_SETS
    jae .bad
    jmp .charge
.new_span:
    mov rcx,[r13+8]
    mov [rel awg_binding],rcx
    mov [rel awg_span_start],rax
    mov dword [rel awg_span_sets],0
.charge:
    inc dword [rel awg_span_sets]
    inc dword [rel awg_tick_sets]
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_app_widget 0
alignb 8
awg_target: resb 32
awg_identity: resb 120
awg_receipt: resb 176
awg_serial: resq 1
awg_binding: resq 1
awg_span_start: resq 1
awg_span_sets: resd 1
awg_tick_sets: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_app_widget
