; Public `guest` builtin: attach to the already running Linux hvc0 shell.
; This never starts/stops a VM, assigns hardware or claims guest/Internet proof.
TERM_GUEST_MODE equ 3
TERM_GUEST_OFFER_KEY equ 0x0f           ; Ctrl+Shift+O: the router folds Ctrl+letter

; D5c (SEC 121684 S1-S3): PAOS_TERMINAL_TOOLS_GUEST picks the console behind
; `guest` at assemble time only, and this is its one default. 0, in every
; shipped and lab profile until the cutover unit, is the driver route,
; preprocessed exactly as before. 1 calls hv/tools_vm's tools_vm_terminal_*
; facade, which must be the real module (no stub). No verb, hook, config or
; runtime state selects a route. The cutover sets 1 and removes the driver
; route in one unit (S3).
%ifndef PAOS_TERMINAL_TOOLS_GUEST
%define PAOS_TERMINAL_TOOLS_GUEST 0
%endif
%if PAOS_TERMINAL_TOOLS_GUEST == 1
%define TERM_GUEST_TOOLS
%elif PAOS_TERMINAL_TOOLS_GUEST != 0
%error the tools-guest route selector must be 0 or 1 ; %error expands macro names
%endif

term_guest_attach:
    cmp byte [r12 + TI_SSH], 0
    jne .bad
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .bad
    cmp byte [r13], 0
    jne .usage
    cmp qword [rel term_guest_instance], 0
    jne .bad                           ; old view retires before a new attachment
%ifdef TERM_GUEST_TOOLS
    mov rdi, r12
    call tools_vm_terminal_attach       ; EAX the RUNNING instance's START /0
    test eax, eax
    jz .bad
    mov esi, eax
%else
    mov esi, [rel hv_linux_start_consumed]
    mov rdi, r12
    push rsi
    call hv_terminal_attach
    pop rsi
    test eax, eax
    jz .bad
%endif
    mov [rel term_guest_generation], esi
    mov [rel term_guest_instance], r12
    mov qword [rel term_guest_rx], 0
    mov qword [rel term_guest_tx], 0
    call term_paste_retire
    mov rax, [r12 + TI_VT]
    mov dword [rax + VT.replylen], 0
    mov byte [r12 + TI_SSH], TERM_GUEST_MODE
%ifdef TERM_GUEST_TOOLS
    lea rsi, [rel term_guest_connected_tools]
%else
    lea rsi, [rel term_guest_connected]
%endif
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
%ifdef TERM_GUEST_TOOLS
    ; Refused for good in 0.1 (SEC 121684 Q3): the tools VM is isolated from
    ; the app and driver VMs and has no guest bridge. Never gbr_arm.
    lea rsi, [rel term_guest_offer_refused]
    jmp term_out_cstr
%else
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
%endif

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

%include "gui/terminal_guest_paste.inc"

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
    cmp qword [rel term_guest_paste_instance], 0
    jne .refused
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
%ifdef TERM_GUEST_TOOLS
    call tools_vm_terminal_write
%else
    call hv_terminal_write
%endif
    pop rcx
    test eax, eax
    jz .refused
    add [rel term_guest_tx], rcx
    mov eax, 1
    ret
.refused:
    xor eax, eax
    ret

; Actual guest output only. At most 32 chunks/8192 bytes per GUI tick; capture
; then VT. Whole reply batches must clear before another chunk is consumed.
; Guest paste has a separate bounded, lifetime-bound input frame.
term_guest_tick:
    cmp r12, [rel term_guest_instance]
    je .attached
    ; A stale view may still receive its final tick after attachment retirement.
    jmp term_guest_paste_retire
.attached:
    call term_guest_offer_tick
    mov rdi, r12
    mov esi, [rel term_guest_generation]
%ifdef TERM_GUEST_TOOLS
    call tools_vm_terminal_status
    test eax, eax
    jz .ended
    ; SEC 121911 d2: a fresh binding and a guest device reset (Status 0) leave
    ; the console size 0x0, so publish the grid every tick; the same pair
    ; again changes nothing (Z4). A refusal here is the next status's to end.
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    mov edx, [r12 + TI_COLS]
    mov ecx, [r12 + TI_ROWS]
    call tools_vm_terminal_resize
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    call tools_vm_terminal_poll
%else
    call hv_terminal_status
    test eax, eax
    jz .ended
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    call hv_terminal_poll
%endif
    call term_guest_paste_drain
    test eax, eax
    jz .out
    call term_guest_flush_replies
    test eax, eax
    jz .out
    call term_focus_report
    push rbx
    mov ebx, 32
.read:
    mov rdi, r12
    mov esi, [rel term_guest_generation]
    lea rdx, [rel term_guest_chunk]
    mov ecx, 256
%ifdef TERM_GUEST_TOOLS
    call tools_vm_terminal_read
%else
    call hv_terminal_read
%endif
    test eax, eax
    js .read_ended
    jz .read_done
    add [rel term_guest_rx], rax
    push rax
    call term_echo_sample
    pop rdx
    lea rsi, [rel term_guest_chunk]
    call term_guest_output
    test eax, eax
    jz .read_done                       ; a pending VT reply precedes more output
    dec ebx
    jnz .read
.read_done:
    pop rbx
    ret
.read_ended:
    pop rbx
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
    cmp qword [rel term_guest_paste_instance], 0
    jne .pending
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
%ifdef TERM_GUEST_TOOLS
    call tools_vm_terminal_write
%else
    call hv_terminal_write
%endif
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
    call term_guest_paste_retire
    call gbr_disarm
    mov byte [rel term_guest_offer], 0
    mov rdi, r12
    mov esi, [rel term_guest_generation]
%ifdef TERM_GUEST_TOOLS
    call tools_vm_terminal_detach       ; close, lock, Ctrl+] and ended (SEC 121723)
%else
    call hv_terminal_detach
%endif
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
%ifdef TERM_GUEST_TOOLS
term_guest_connected_tools: db "[guest console attached; Enter for prompt, Ctrl+] to detach]",13,10,0
%endif
term_guest_unavailable: db "guest: no available Linux shell console (running guest, ready transport and exclusive ownership required)",13,10,0
term_guest_usage: db "usage: guest (attach to the running Linux guest)",13,10,0
term_guest_offer_armed: db 13,10,"[app offer on for 2 minutes; print an app here. Ctrl+Shift+O cancels]",13,10,0
term_guest_offer_off: db 13,10,"[app offer off]",13,10,0
term_guest_offer_ended: db 13,10,"[app offer ended; no app received]",13,10,0
term_guest_offer_shown: db 13,10,"[app offer ended; see the install card]",13,10,0
term_guest_offer_refused: db 13,10,"[app offer refused]",13,10,0
term_guest_pressure: db 7,"[guest input refused; event was not queued]",13,10,0
term_guest_paste_limit: db 7,"[guest paste refused; busy or maximum 8192 bytes]",13,10,0
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
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_terminal_guest
