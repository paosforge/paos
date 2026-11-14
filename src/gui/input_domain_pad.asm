;; MODULE gui/input_domain_pad
;; LAYER 6
;; EXPORTS pingu_declare
;; IMPORTS hv/input_domain_command, hv/input_domain_bridge, hv/input_domain_consumer, gui/widget, gui/window_mgmt, gui/chat_app, boot/gop, sec/session, sec/principal
;; CAPS CAP_GUI
;; OWNER saga:input
; Explicit GUESTVM PIN1 SHOW gen: at most one native checked DOMAIN record,
; same CPU/owner/deadline as TAKE, plus a dedicated untrusted GUI pad. No key,
; pointer, focus, secret, shell, submit, clipboard, HID or HUMAN producer.
; One pad/START per boot. Closed/reused window or widget refuses before drain.
; No automatic activation/poll/guest entry. Native record remains byte-exact in
; the ordinary PIN1 hex reply; GUI state is not physical observation evidence.

pingu_declare:
    lea rax,[rel pingu_take]
    mov [rel pinj_gui_take_hook],rax
    ret

; RDI=gen, RSI=output, RDX=capacity. Called at the original stopped-vCPU
; serialized command boundary. No yield; every possible refusal before poll
; leaves the original complete reply available to TAKE or a corrected SHOW.
pingu_take:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .denied
    xor edi,edi
    call session_shell_request_principal
    cmp rax,PRIN_OWNER
    jne .denied
    mov rdi,r12
    call pinb_check
    test eax,eax
    jnz .out
    cmp dword [rel fb_width],400
    jb .invalid
    cmp dword [rel fb_height],260
    jb .invalid
    mov eax,[rel fb_width]
    cmp eax,[rel pinc_width]
    jne .stale
    mov eax,[rel fb_height]
    cmp eax,[rel pinc_height]
    jne .stale
    cmp byte [rel pingu_fault],0
    jne .failed
    cmp qword [rel pingu_gen],0
    je .create
    cmp r12,[rel pingu_gen]
    jne .stale
    mov rax,[rel pinc_epoch]
    cmp rax,[rel pingu_epoch]
    jne .stale
    mov rax,[rel pinc_session]
    cmp rax,[rel pingu_session]
    jne .stale
    jmp .custody
.create:
    cmp qword [rel pinc_sequence],0
    jne .stale                         ; no unknown prior Caps/GUI history
    mov dword [rel pingu_pointer],2     ; absence is not a pointer at (0,0)
    ; Lazy creation is opt-in. Allocation failure is sticky: no retry can
    ; silently create a second UI after a partial allocation.
    mov byte [rel pingu_fault],1
    lea rdi,[rel pingu_name]
    lea rsi,[rel pingu_draw]
    lea rdx,[rel pingu_noop]
    lea rcx,[rel pingu_noop]
    lea r8,[rel pingu_noop]
    mov r9,(72 << 32) | 300
    call wgt_type_register
    test eax,eax
    js .failed
    inc eax
    mov [rel pingu_type],eax
    lea rdi,[rel pingu_title]
    mov esi,32
    mov edx,48
    mov ecx,340
    mov r8d,180
    xor r9d,r9d
    call wmx_open_window
    test eax,eax
    js .failed
    mov [rel pingu_window],eax
    mov edi,eax
    call wmx_window_id
    test eax,eax
    jz .failed
    mov [rel pingu_window_id],eax
    mov edi,[rel pingu_type]
    dec edi
    mov esi,[rel pingu_window]
    call wgt_create
    test eax,eax
    js .failed
    mov [rel pingu_widget],eax
    mov edi,eax
    call wgt_slot_ptr
    mov rbx,rax
    mov ecx,[rel pingu_window]
    lea rdx,[rel wm_x]
    mov edx,[rdx+rcx*4]
    add edx,16
    mov [rbx+WGI_X],edx
    lea rdx,[rel wm_y]
    mov edx,[rdx+rcx*4]
    add edx,64
    mov [rbx+WGI_Y],edx
    mov [rel pingu_gen],r12
    mov rax,[rel pinc_epoch]
    mov [rel pingu_epoch],rax
    mov rax,[rel pinc_session]
    mov [rel pingu_session],rax
    ; Sequence zero admits no skipped key/Caps history.
    mov byte [rel pingu_fault],0
.custody:
    mov rax,[rel pinc_sequence]
    cmp rax,[rel pingu_sequence]
    jne .stale                         ; TAKE after SHOW cannot skip GUI history
    mov edi,[rel pingu_window]
    call wmx_window_id
    cmp eax,[rel pingu_window_id]
    jne .stale
    mov ecx,[rel pingu_window]
    lea rax,[rel wm_state]
    cmp dword [rax+rcx*4],WM_VISIBLE
    jne .stale
    mov edi,[rel pingu_widget]
    cmp edi,[rel wgt_count]
    jae .stale
    call wgt_slot_ptr
    mov edx,[rel pingu_type]
    cmp [rax+WGI_TYPE],edx
    jne .stale
    mov edx,[rel pingu_window]
    cmp [rax+WGI_WIN],edx
    jne .stale
    test dword [rax+WGI_FLAGS],1
    jz .stale
    cmp dword [rax+WGI_W],300
    jne .stale
    cmp dword [rax+WGI_H],72
    jne .stale
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    call pinb_poll                      ; actual native source/identity/TTL checks
    cmp eax,320
    jne .out
    mov rbx,r13
    ; Only this freshly consumed complete native record can edit the pad.
    mov eax,[rbx+6]
    and eax,0xffff
    mov [rel pingu_kind],eax
    mov rax,[rbx+32]
    mov [rel pingu_sequence],rax
    cmp word [rbx+6],3
    je .cancel
    cmp word [rbx+6],1
    jne .paint                         ; QUIET is not a release or attachment
    cmp dword [rbx+40],1
    jne .pointer
    lea r15,[rbx+64]
    mov r14d,[rbx+44]
.key:
    test r14d,r14d
    jz .paint
    cmp word [r15],1
    jne .key_next
    movzx ecx,word [r15+2]
    cmp ecx,255
    ja .key_next
    lea rdx,[rel pingu_keys]
    mov eax,[r15+4]
    test eax,eax
    jz .key_up
    bts [rdx],ecx
    cmp eax,2
    ja .key_next
    ; Ctrl/Alt/Meta never reach shell or app shortcuts. Shift/Caps only
    ; affect this pad's ASCII mapping, independent of physical layout state.
    test byte [rdx+3],32
    jnz .key_next
    test byte [rdx+12],2
    jnz .key_next
    test byte [rdx+7],1
    jnz .key_next
    test byte [rdx+12],16
    jnz .key_next
    test byte [rdx+15],32
    jnz .key_next
    test byte [rdx+15],64
    jnz .key_next
    cmp ecx,58
    je .caps
    cmp ecx,14
    je .backspace
    cmp ecx,58
    jae .key_next
    lea rdx,[rel pingu_plain]
    lea rsi,[rel pingu_keys]
    test byte [rsi+5],4
    jnz .shift
    test byte [rsi+6],64
    jz .lookup
.shift:
    lea rdx,[rel pingu_shift]
.lookup:
    movzx eax,byte [rdx+rcx]
    cmp al,'a'
    jb .upper
    cmp al,'z'
    ja .upper
    cmp byte [rel pingu_caps],0
    je .append
    sub al,32
    jmp .append
.upper:
    cmp al,'A'
    jb .append
    cmp al,'Z'
    ja .append
    cmp byte [rel pingu_caps],0
    je .append
    add al,32
.append:
    test al,al
    jz .key_next                       ; Enter/Tab/Escape are not submissions
    mov ecx,[rel pingu_length]
    cmp ecx,31
    jae .key_next
    lea rdx,[rel pingu_text]
    mov [rdx+rcx],al
    inc ecx
    mov byte [rdx+rcx],0
    mov [rel pingu_length],ecx
    jmp .key_next
.caps:
    cmp eax,1
    jne .key_next                      ; no repeat toggles
    xor byte [rel pingu_caps],1
    jmp .key_next
.backspace:
    mov ecx,[rel pingu_length]
    test ecx,ecx
    jz .key_next
    dec ecx
    mov [rel pingu_length],ecx
    lea rdx,[rel pingu_text]
    mov byte [rdx+rcx],0
    jmp .key_next
.key_up:
    btr [rdx],ecx
.key_next:
    add r15,8
    dec r14d
    jmp .key
.pointer:
    mov rax,[rbx+288]
    mov [rel pingu_xy],rax
    mov eax,[rbx+296]
    mov [rel pingu_buttons],eax
    mov eax,[rbx+304]                    ; 0 REL /1 ABS /2 not observed
    mov [rel pingu_pointer],eax
    jmp .paint
.cancel:
    mov dword [rel pingu_pointer],2
    mov dword [rel pingu_buttons],0
    mov qword [rel pingu_keys],0
    mov qword [rel pingu_keys+8],0
    mov qword [rel pingu_keys+16],0
    mov qword [rel pingu_keys+24],0
.paint:
    mov edi,[rel pingu_widget]
    call wgt_draw_id                    ; shared clipping/occlusion/composition
    mov eax,320                         ; raw record success != painted witness
    jmp .out
.denied: mov eax,-13
    jmp .out
.invalid: mov eax,-22
    jmp .out
.stale: mov eax,-116
    jmp .out
.failed: mov eax,-12
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Ordinary shared widget painter, one fixed 300x72 canvas. It paints only the
; one allocated widget, never clones created through public WIDGETNEW.
pingu_draw:
    cmp edi,[rel pingu_widget]
    jne pingu_noop
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne pingu_noop
    mov rax,[rel pinc_gen]
    test rax,rax
    jz pingu_noop
    cmp rax,[rel pingu_gen]
    jne pingu_noop
    cmp dword [rel pinc_state],PINC_LIVE
    je .live
    cmp dword [rel pinc_state],PINC_STOPPED
    jne pingu_noop
.live:
    cmp dword [rel pinc_width],0
    je pingu_noop
    cmp dword [rel pinc_height],0
    je pingu_noop
    push rbx
    push r12
    mov r12d,edi
    mov edi,[rel pingu_window]
    call wmx_window_id
    cmp eax,[rel pingu_window_id]
    jne .done
    mov rdi,[rel pinc_epoch]
    cmp rdi,[rel pingu_epoch]
    jne .done
    mov rdi,[rel pinc_session]
    cmp rdi,[rel pingu_session]
    jne .done
    mov edi,r12d
    call wgt_slot_ptr
    mov r12,rax
    cmp dword [r12+WGI_W],300
    jne .done
    cmp dword [r12+WGI_H],72
    jne .done
    mov r8d,[r12+WGI_X]
    mov r9d,[r12+WGI_Y]
    mov r10d,300
    mov r11d,72
    mov ebx,GUI_TOK_CONTROL_BG
    call wgt_fill_rect
    lea rdi,[rel pingu_title]
    cmp dword [rel pingu_kind],3
    jne .label
    lea rdi,[rel pingu_cancel]
.label:
    mov ecx,GUI_TOK_CONTROL_BG
    mov ebx,GUI_TOK_CONTROL_TEXT
    mov r8d,[r12+WGI_X]
    add r8d,4
    mov r9d,[r12+WGI_Y]
    add r9d,4
    mov r11d,32
    call wgt_draw_text
    lea rdi,[rel pingu_text]
    mov ecx,GUI_TOK_CONTROL_BG
    mov ebx,GUI_TOK_CONTROL_TEXT
    mov r8d,[r12+WGI_X]
    add r8d,4
    mov r9d,[r12+WGI_Y]
    add r9d,24
    mov r11d,31
    call wgt_draw_text
    cmp dword [rel pingu_pointer],2
    jae .done
    ; Full-screen native pointer is projected into an explicitly local pad;
    ; it cannot move or click the host cursor, widget, window or Guardian.
    mov eax,[rel pingu_xy]
    imul rax,288
    xor edx,edx
    mov ecx,[rel pinc_width]
    div rcx
    mov r8d,[r12+WGI_X]
    add r8d,eax
    add r8d,4
    push r8
    mov eax,[rel pingu_xy+4]
    imul rax,20
    xor edx,edx
    mov ecx,[rel pinc_height]
    div rcx
    mov r9d,[r12+WGI_Y]
    add r9d,eax
    add r9d,44
    pop r8
    mov r10d,4
    mov r11d,4
    mov ebx,GUI_TOK_CONTROL_TEXT
    cmp dword [rel pingu_buttons],0
    je .cursor
    mov ebx,GUI_TOK_SELECTION
.cursor:
    call wgt_fill_rect
.done:
    pop r12
    pop rbx
pingu_noop:
    xor eax,eax
    ret

pingu_name: db 'domainpad',0
pingu_title: db 'DOMAIN input (untrusted)',0
pingu_cancel: db 'DOMAIN input CANCELLED',0
; Linux evdev key codes1..57. No control/submit bytes in either map.
pingu_plain:
    db 0,0,'1234567890-=',0,0,'qwertyuiop[]',0,0,'asdfghjkl;',39,'`',0,92,'zxcvbnm,./',0,'*',0,' '
pingu_shift:
    db 0,0,'!@#$%^&*()_+',0,0,'QWERTYUIOP{}',0,0,'ASDFGHJKL:',34,'~',0,'|','ZXCVBNM<>?',0,'*',0,' '

%include "core/abi/wdata.inc"
%macro WDATA_gui_input_domain_pad 0
alignb 8
pingu_storage:
pingu_gen: resq 1
pingu_epoch: resq 1
pingu_session: resq 1
pingu_sequence: resq 1
pingu_keys: resb 32
pingu_text: resb 32
pingu_length: resd 1
pingu_xy: resd 2
pingu_buttons: resd 1
pingu_pointer: resd 1
pingu_kind: resd 1
pingu_type: resd 1
pingu_window: resd 1
pingu_window_id: resd 1
pingu_widget: resd 1
pingu_caps: resb 1
pingu_fault: resb 1
pingu_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_gui_input_domain_pad
