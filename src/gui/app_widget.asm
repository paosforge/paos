;; MODULE gui/app_widget
;; LAYER 6
;; PURPOSE Typed guest get/set of plain widget text in the app's own bound window.
;; EXPORTS app_widget_init, app_widget_tick, app_widget_handle
;; IMPORTS hv/app_widget_transport, hv/guest_request, sec/app_binding, gui/chat_send, gui/widget
;; CAPS CAP_GUI
;; OWNER saga:app_widget
;; CONTEXT: bsp_only
; Not a command verb and not WIDGETSET: no field, rect, focus, event or other
; window is reachable. The window comes from the native binding, never a guest.
AWG_GET equ 1
AWG_SET equ 2
AWG_WINDOW equ 3
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
    cmp eax,AWG_WINDOW-1
    ja .badarg
    mov rdi,r13
    call app_binding_widget_window       ; exact binding + WAIT BEGIN ALLOW
    test rax,rax
    jz .deny
    mov r14,rax
    cmp dword [rbx+4],AWG_WINDOW
    je .window
    cmp [rbx+AWG_F_WINDOW],r14
    jne .deny
    cmp qword [rbx+AWG_F_RESERVED],0
    jne .badarg
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
    mov rdi,rax
    call awg_plain_text
    test eax,eax
    jz .deny
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
    cmp byte [rel dpms_blanked],0        ; setting text paints
    jne .busy
    mov edi,r15d
    call awg_value_ok
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
    pop r15
    pop r14
    pop r13
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
awg_binding: resq 1
awg_span_start: resq 1
awg_span_sets: resd 1
awg_tick_sets: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_app_widget
