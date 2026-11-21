; One owned guest frame. Only accepted whole transport chunks advance it.
; R12 is the actual Terminal instance; no clipboard/guest pointer is retained.
TERM_GUEST_PASTE_MAX equ TERM_CLIP_MAX + 12
TERM_GUEST_PASTE_CHUNKS equ 4

term_guest_paste:
    push rbx
    push r13
    cmp qword [rel term_guest_paste_instance], 0
    jne .pressure
    cmp dword [rel term_paste_inst], -1
    jne .pressure
    call term_guest_input_ok
    test eax, eax
    jz .out
    mov ebx, [rel term_clip_len]
    test ebx, ebx
    jz .out
    cmp ebx, TERM_CLIP_MAX
    ja .pressure
    ; Replies already generated precede the new frame. No input is admitted
    ; while an earlier reply is under transport pressure.
    call term_guest_flush_replies
    test eax, eax
    jz .pressure
    call session_shell_local_authority
    test rax, rax
    jz .out
    mov [rel term_guest_paste_publisher], rax
    mov rax, [rel session_authority_epoch]
    mov [rel term_guest_paste_epoch], rax
    call term_inst_index
    cmp eax, TERM_MAX
    jae .drop
    lea rdx, [rel term_paste_generations]
    mov rax, [rdx + rax*8]
    mov [rel term_guest_paste_lifetime], rax
    mov eax, [rel term_guest_generation]
    mov [rel term_guest_paste_start], eax
    mov [rel term_guest_paste_instance], r12
    call term_guest_paste_live
    test eax, eax
    jz .drop
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
    add eax, r13d
    mov [rel term_guest_paste_len], eax
    mov dword [rel term_guest_paste_off], 0
    jmp .out                          ; first bounded drain is the next tick
.drop:
    call term_guest_paste_forget
    jmp .out
.pressure:
    lea rsi, [rel term_guest_paste_limit]
    call term_out_cstr
.out:
    pop r13
    pop rbx
    ret

; Fresh native session, instance lifetime and consumed START on every chunk.
term_guest_paste_live:
    cmp [rel term_guest_paste_instance], r12
    jne .bad
    cmp [rel term_guest_instance], r12
    jne .bad
    cmp byte [r12 + TI_USED], 1
    jne .bad
    cmp byte [r12 + TI_SSH], TERM_GUEST_MODE
    jne .bad
    call session_shell_local_authority
    test rax, rax
    jz .bad
    cmp rax, [rel term_guest_paste_publisher]
    jne .bad
    mov rax, [rel session_authority_epoch]
    cmp rax, [rel term_guest_paste_epoch]
    jne .bad
    call term_inst_index
    cmp eax, TERM_MAX
    jae .bad
    lea rdx, [rel term_paste_generations]
    mov rax, [rdx + rax*8]
    cmp rax, [rel term_guest_paste_lifetime]
    jne .bad
    mov esi, [rel term_guest_paste_start]
    cmp esi, [rel term_guest_generation]
    jne .bad
    mov rdi, r12
%ifdef TERM_GUEST_TOOLS
    jmp tools_vm_terminal_status
%else
    jmp hv_terminal_status
%endif
.bad:
    xor eax, eax
    ret

; EAX=1 idle/complete, 0 pressure or cancellation. <=1024 bytes per GUI tick.
term_guest_paste_drain:
    cmp qword [rel term_guest_paste_instance], 0
    je .ready
    push rbx
    mov ebx, TERM_GUEST_PASTE_CHUNKS
.next:
    call term_guest_paste_live
    test eax, eax
    jz .drop
    mov ecx, [rel term_guest_paste_len]
    sub ecx, [rel term_guest_paste_off]
    jbe .drop
    cmp ecx, 256
    jbe .size
    mov ecx, 256
.size:
    lea rdx, [rel term_guest_paste_buf]
    mov eax, [rel term_guest_paste_off]
    add rdx, rax
    mov rdi, r12
    mov esi, [rel term_guest_paste_start]
    push rcx
%ifdef TERM_GUEST_TOOLS
    call tools_vm_terminal_write
%else
    call hv_terminal_write
%endif
    pop rcx
    test eax, eax
    jz .pending
    add [rel term_guest_paste_off], ecx
    add [rel term_guest_tx], rcx
    mov eax, [rel term_guest_paste_off]
    cmp eax, [rel term_guest_paste_len]
    jae .complete
    dec ebx
    jnz .next
.pending:
    pop rbx
    xor eax, eax
    ret
.drop:
    call term_guest_paste_forget
    jmp .pending
.complete:
    call term_guest_paste_forget
    pop rbx
.ready:
    mov eax, 1
    ret

term_guest_paste_retire:
    cmp [rel term_guest_paste_instance], r12
    jne .out
    jmp term_guest_paste_forget
.out:
    ret

term_guest_paste_forget:
    lea rdi, [rel term_guest_paste_buf]
    mov ecx, TERM_GUEST_PASTE_MAX
    xor eax, eax
    cld
    rep stosb
    mov qword [rel term_guest_paste_instance], 0
    mov qword [rel term_guest_paste_publisher], 0
    mov qword [rel term_guest_paste_epoch], 0
    mov qword [rel term_guest_paste_lifetime], 0
    mov dword [rel term_guest_paste_start], 0
    mov dword [rel term_guest_paste_len], 0
    mov dword [rel term_guest_paste_off], 0
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_terminal_guest_paste 0
alignb 8
term_guest_paste_instance: resq 1
term_guest_paste_publisher: resq 1
term_guest_paste_epoch: resq 1
term_guest_paste_lifetime: resq 1
term_guest_paste_start: resd 1
term_guest_paste_len: resd 1
term_guest_paste_off: resd 1
term_guest_paste_buf: resb TERM_GUEST_PASTE_MAX
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_terminal_guest_paste
