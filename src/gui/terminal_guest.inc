; Public `guest` builtin: attach to the already running Linux hvc0 shell.
; This never starts/stops a VM, assigns hardware or claims guest/Internet proof.
TERM_GUEST_MODE equ 3
TERM_GUEST_OFFER_KEY equ 0x0f           ; Ctrl+Shift+O: the router folds Ctrl+letter

term_guest_attach:
    cmp byte [r12 + TI_SSH], 0
    jne .bad
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .bad
    cmp byte [r13], 0
    jne .usage
    cmp qword [rel term_guest_instance], 0
    jne .bad                           ; old view retires before a new attachment
    mov esi, [rel hv_linux_start_consumed]
    mov rdi, r12
    push rsi
    call hv_terminal_attach
    pop rsi
    test eax, eax
    jz .bad
    mov [rel term_guest_generation], esi
    mov [rel term_guest_instance], r12
    mov qword [rel term_guest_rx], 0
    mov qword [rel term_guest_tx], 0
    call term_paste_retire
    mov rax, [r12 + TI_VT]
    mov dword [rax + VT.replylen], 0
    mov byte [r12 + TI_SSH], TERM_GUEST_MODE
    lea rsi, [rel term_guest_connected]
    jmp term_out_cstr
.usage:
    lea rsi, [rel term_guest_usage]
    jmp .say
.bad:
    lea rsi, [rel term_guest_unavailable]
.say:
    call term_out_cstr
    jmp term_prompt

; No queued key/paste survives lock. Reuse the same per-event provenance
; primitive as SSH, without selecting or modifying any SSH session.
term_guest_input_ok:
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .bad
    lea rdi, [rel term_ssh_taint]
    call keyprov_line_clear
    call keyprov_line_note
    call keyprov_line_owner_equivalent
    ret
.bad:
    xor eax, eax
    ret

; The pointer origin belongs to this routed event, independently of the last
; keyboard event. Keep the encoder's button/press registers intact.
term_guest_pointer_ok:
    push rcx
    push rdi
    push rsi
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .bad
    lea rdi, [rel term_ssh_taint]
    call keyprov_line_clear
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    je .judge
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_INJECTED
    jne .bad                           ; device retirement is not a human act
    call keyprov_frame_bind
.judge:
    call keyprov_line_owner_equivalent
    jmp .out
.bad:
    xor eax, eax
.out:
    pop rsi
    pop rdi
    pop rcx
    ret

term_guest_key:
    call term_guest_input_ok
    test eax, eax
    jz .out
    cmp r13d, 0x1d                     ; Ctrl+] leaves console attached guest running    cmp r13d, 0x1d                     ; Ctrl+] leaves console attached guest mode
    je term_guest_leave
    cmp r13d, TERM_GUEST_OFFER_KEY
    jne .plain
    test r14d, 1
    jnz term_guest_offer_key
.plain:
    call term_encode_key
    test eax, eax
    jz .out
    mov ecx, eax
    lea rdx, [rel term_keybuf]
    jmp term_guest_send
.out:
    ret

; hvc0 is the shell's own output, so printed text can never open a card. One key
; from the owner's hand arms one offer for this attachment, and again disarms it.
term_guest_offer_key:
    call keyprov_key_is_human
    test eax, eax
    jz .refused
    call input_modifiers_are_human
    test eax, eax
    jz .refused
    cmp byte [rel term_guest_offer], 1
    je .disarm
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    call gbr_arm
    cmp eax, 1
    jne .refused
    mov byte [rel term_guest_offer], 1
    lea rsi, [rel term_guest_offer_armed]
    jmp term_out_cstr
.disarm:
    call gbr_disarm
    mov byte [rel term_guest_offer], 0
    lea rsi, [rel term_guest_offer_off]
    jmp term_out_cstr
.refused:
    lea rsi, [rel term_guest_offer_refused]
    jmp term_out_cstr

; Hash-checked bytes go to the owner's card with the Terminal's origin, native
; here and never from the guest. The offer copies them; every end scrubs ours.
term_guest_offer_tick:
    cmp byte [rel term_guest_offer], 1
    jne .out
    call gbr_candidate
    test rax, rax
    jnz .candidate
    cmp byte [rel gbr_state], GBR_S_IDLE
    jne .out
    mov byte [rel term_guest_offer], 0
    lea rsi, [rel term_guest_offer_ended]
    jmp term_out_cstr
.candidate:
    mov rdi, rax
    mov esi, edx
    mov edx, AIN_ORIGIN_TERMINAL
    call app_install_offer
    push rax
    call gbr_disarm
    mov byte [rel term_guest_offer], 0
    pop rax
    lea rsi, [rel term_guest_offer_shown]
    cmp eax, 1
    je .say
    lea rsi, [rel term_guest_offer_refused]
.say:
    jmp term_out_cstr
.out:
    ret

term_guest_text:
    call term_guest_input_ok
    test eax, eax
    jz .out
    mov ecx, [rel wgt_text_len]
    test ecx, ecx
    jz .out
    cmp ecx, WGT_TEXT_CAP - 1
    ja .out
    lea rdx, [rel wgt_text_buf]
    jmp term_guest_send
.out:
    ret

; One complete paste, including optional bracket markers, fits the transport
; event. Larger pastes are visibly refused rather than split or retained.
term_guest_paste:
    push rbx
    push r13
    call term_guest_input_ok
    test eax, eax
    jz .out
    mov ebx, [rel term_clip_len]
    test ebx, ebx
    jz .out
    cmp ebx, 244                       ; reserve two six-byte bracket markers
    ja .pressure
    mov rdi, [r12 + TI_VT]
    lea rsi, [rel term_guest_paste_buf]
    call vt_paste_prefix
    mov r13d, eax
    xor ecx, ecx
.copy:
    lea rdx, [rel term_clip]
    mov al, [rdx + rcx]
    cmp al, 10
    jne .byte
    mov al, 13
.byte:
    lea rdx, [rel term_guest_paste_buf]
    mov [rdx + r13], al
    inc r13d
    inc ecx
    cmp ecx, ebx
    jb .copy
    mov rdi, [r12 + TI_VT]
    lea rsi, [rel term_guest_paste_buf]
    add rsi, r13
    call vt_paste_suffix
    lea ecx, [r13 + rax]
    lea rdx, [rel term_guest_paste_buf]
    call term_guest_send
    jmp .out
.pressure:
    lea rsi, [rel term_guest_paste_limit]
    call term_out_cstr
.out:
    pop r13
    pop rbx
    ret

; Exact whole input event or a visible refusal; no automatic replay/retry.
term_guest_send:
    call term_guest_try_send
    test eax, eax
    jnz .out
    lea rsi, [rel term_guest_pressure]
    call term_out_cstr
    xor eax, eax
.out:
    ret

; Quiet form for fixed focus transitions, which may retry on the next tick.
; EAX=1 only after complete transport acceptance, 0 otherwise.
term_guest_try_send:
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .refused
    cmp r12, [rel term_guest_instance]
    jne .refused
    push rcx
    push rdx
    call term_guest_flush_replies
    pop rdx
    pop rcx
    test eax, eax
    jz .refused
    mov esi, [rel term_guest_generation]
    mov rdi, r12
    push rcx
    call hv_terminal_write
    pop rcx
    test eax, eax
    jz .refused
    add [rel term_guest_tx], rcx
    mov eax, 1
    ret
.refused:
    xor eax, eax
    ret

; Actual guest output only. One bounded chunk per GUI tick; capture then VT.
; Hidden/minimized windows retain bounded transport output, not user input.
term_guest_tick:
    cmp r12, [rel term_guest_instance]
    jne .out
    call term_guest_offer_tick
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    call hv_terminal_status
    test eax, eax
    jz .ended
    call term_guest_flush_replies
    test eax, eax
    jz .out
    call term_focus_report
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    lea rdx, [rel term_guest_chunk]
    mov ecx, 256
    call hv_terminal_read
    test eax, eax
    js .ended
    jz .out
    add [rel term_guest_rx], rax
    push rax
    call term_echo_sample
    pop rdx
    lea rsi, [rel term_guest_chunk]
    jmp term_guest_output
.ended:
    call term_guest_forget
    call term_session_reset
    lea rsi, [rel term_guest_ended]
    call term_out_cstr
    jmp term_prompt
.out:
    ret

term_guest_output:
    call term_out
    jmp term_guest_flush_replies

; Real guest chunks alone generate this batch. Backpressure retains it until
; the next tick, before any later guest bytes. Lock/detach discards it. RAW's
; existing quarantine restores replylen and cannot bind a new reply batch.
term_guest_flush_replies:
    mov rax, [r12 + TI_VT]
    mov ecx, [rax + VT.replylen]
    test ecx, ecx
    jz .ready
    cmp ecx, VT_REPLYMAX
    ja .invalid
    cmp ecx, 256
    ja .invalid
    lea rdx, [rax + VT.reply]
    mov esi, [rel term_guest_generation]
    mov rdi, r12
    push rax
    push rcx
    call hv_terminal_write
    pop rcx
    test eax, eax
    pop rax
    jz .pending
    add [rel term_guest_tx], rcx
.drop:
    mov dword [rax + VT.replylen], 0
.ready:
    mov eax, 1
    ret
.pending:
    xor eax, eax
    ret
.invalid:
    mov dword [rax + VT.replylen], 0
    lea rsi, [rel term_guest_pressure]
    call term_out_cstr
    mov eax, 1
    ret

; ECX is the real pending reply length saved before diagnostic RAW output.
; Restore it without flushing: only real guest output may create a new batch.
term_guest_raw_quarantine:
    mov rax, [r12 + TI_VT]
    cmp [rax + VT.replylen], ecx
    jbe .restore
    inc qword [rel term_ssh_input_refused]
.restore:
    mov [rax + VT.replylen], ecx
    ret

term_guest_leave:
    call term_guest_forget
    call term_session_reset
    lea rsi, [rel term_guest_detached]
    call term_out_cstr
    jmp term_prompt

; Close/lock/explicit detach retires only this Terminal attachment. No STOP
; ACK or stopped-vCPU/DMA/reclaim witness is manufactured by closing a view.
term_guest_forget:
    cmp r12, [rel term_guest_instance]
    jne .out
    call gbr_disarm
    mov byte [rel term_guest_offer], 0
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    call hv_terminal_detach
    mov qword [rel term_guest_instance], 0
    mov dword [rel term_guest_generation], 0
    mov byte [r12 + TI_SSH], 0
    mov rax, [r12 + TI_VT]
    mov dword [rax + VT.replylen], 0
.out:
    ret

term_guest_stat:
    lea rdi, [rel term_guest_stat_gen]
    call grid_out_str
    xor edi, edi
    cmp r12, [rel term_guest_instance]
    jne .gen
    mov edi, [rel term_guest_generation]
.gen:
    call grid_out_dec
    lea rdi, [rel term_guest_stat_rx]
    call grid_out_str
    xor edi, edi
    cmp r12, [rel term_guest_instance]
    jne .rx
    mov rdi, [rel term_guest_rx]
.rx:
    call grid_out_dec
    lea rdi, [rel term_guest_stat_tx]
    call grid_out_str
    xor edi, edi
    cmp r12, [rel term_guest_instance]
    jne .tx
    mov rdi, [rel term_guest_tx]
.tx:
    jmp grid_out_dec

%include "core/abi/wdata.inc"
%macro WDATA_gui_terminal_guest 0
term_guest_connected: db "[guest console attached; Enter for prompt, Ctrl+] to detach, Ctrl+Shift+O to take an app]",13,10,0
term_guest_unavailable: db "guest: no available Linux shell console (running guest, ready transport and exclusive ownership required)",13,10,0
term_guest_usage: db "usage: guest (attach to the running Linux guest)",13,10,0
term_guest_offer_armed: db 13,10,"[app offer on for 2 minutes; print an app here. Ctrl+Shift+O cancels]",13,10,0
term_guest_offer_off: db 13,10,"[app offer off]",13,10,0
term_guest_offer_ended: db 13,10,"[app offer ended; no app received]",13,10,0
term_guest_offer_shown: db 13,10,"[app offer ended; see the install card]",13,10,0
term_guest_offer_refused: db 13,10,"[app offer refused]",13,10,0
term_guest_pressure: db 7,"[guest input refused; event was not queued]",13,10,0
term_guest_paste_limit: db 7,"[guest paste refused; maximum 244 bytes]",13,10,0
term_guest_ended: db 13,10,"[guest console ended or output overflowed; detached]",13,10,0
term_guest_detached: db 13,10,"[guest console detached; guest left running]",13,10,0
term_guest_stat_gen: db " GUEST_GEN=",0
term_guest_stat_rx: db " GUEST_RX=",0
term_guest_stat_tx: db " GUEST_TX=",0
%endmacro
WDATA_DEFER WDATA_gui_terminal_guest
%macro WDATA_BSS_gui_terminal_guest 0
alignb 8
term_guest_instance: resq 1
term_guest_rx: resq 1
term_guest_tx: resq 1
term_guest_generation: resd 1
term_guest_offer: resb 1
alignb 4
term_guest_chunk: resb 256
term_guest_paste_buf: resb 256
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_terminal_guest
