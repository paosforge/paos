; gui/netmon_fmt.inc - Network Monitor formatting, built into the keep in every
; profile (T5-21.1, Peter 87337: the native network provider is compiled in with
; the kernel; root 119679 route A, SEC 119690 D5 RETIRE). Formerly the signed
; external PMOD member EFI/PaOS/modules/netmon.pmd; instruction text unchanged.
; Included by gui/netmon_form.asm; called only through netmon_builtin_query.
; Pure PIC: RIP-relative literals only, no imports, no absolute pointers.
; Input is a bounded snapshot at RDI (state block):
; rx, tx, link, window (four qwords), followed by a 128-byte nonce/token at 32.
; At 160: operation (0=verb, 1=view, 2=tick, 3=reset, 4=bind name, 5=widget).
; At 168..199: previous counters and slew rates; 208: binding id.
; Operation 5 takes {binding id, widget maximum} at 216/224 and returns
; action 0=unbound/1=text/2=number at 208, clamped widget number at 200.
; 232..247 holds a bounded selected name, 248 opaque selected-handle identity.
; UINT64_MAX denotes unavailable rx/tx/link; never a valid zero sample.
; Private state at 768 holds the prior selection (outside the 256..767 output
; scratch span). RSI = output span (state+256); returns RAX=RSI, RDX=length.
; Clobbers RAX/RCX/RDX/RSI/RDI/R8/R9; preserves RBX/R12/R13 (pushed) and the rest.
; Maximum stack below the caller's return address: 3 pushes + 1 call + nm_dec's
; up to 20 digit pushes = 24 qwords (192 B).

nm_entry:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rsi
    cmp qword [r12+160], 5
    je .widget
    cmp qword [r12+160], 4
    je .bind
    cmp qword [r12+160], 3
    je .reset
    cmp qword [r12+160], 2
    je .tick
    cmp qword [r12+160], 1
    je .view
    lea rdi, [rel nm_rx]
    call nm_puts
    mov rax, [r12]
    call nm_sample
    lea rdi, [rel nm_tx]
    call nm_puts
    mov rax, [r12+8]
    call nm_sample
    lea rdi, [rel nm_link]
    call nm_puts
    mov rax, [r12+16]
    call nm_sample
    lea rdi, [rel nm_nic]
    call nm_puts
    call nm_name
    lea rdi, [rel nm_idx]
    call nm_puts
    mov rax, [r12+24]
    call nm_dec
    lea rdi, [rel nm_nonce]
    call nm_puts
    lea rdi, [r12+32]
    call nm_puts
.finish:
    mov byte [rbx], 0
    mov rax, r13
    mov rdx, rbx
    sub rdx, r13
    pop r13
    pop r12
    pop rbx
    ret
.reset:
    mov rax, [r12+248]
    mov [r12+768], rax
    cmp qword [r12], -1
    je .unavailable
    cmp qword [r12+8], -1
    je .unavailable
    mov rax, [r12]
    mov [r12+168], rax
    mov rax, [r12+8]
    mov [r12+176], rax
    mov qword [r12+184], 0
    mov qword [r12+192], 0
    cmp qword [r12+16], 1
    je .finish
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    jmp .finish
.tick:
    cmp qword [r12], -1
    je .unavailable_view
    cmp qword [r12+8], -1
    je .unavailable_view
    mov rax, [r12+248]
    cmp rax, [r12+768]
    jne .baseline_view
    cmp qword [r12+168], -1
    je .baseline_view
    cmp qword [r12+176], -1
    je .baseline_view
    cmp qword [r12+16], 1
    jne .baseline_view                  ; offline/unknown cannot create rates
    mov rdx, [r12]
    cmp rdx, [r12+168]
    jb .baseline_view                   ; reset/wrap cannot create unsigned spikes
    mov rdx, [r12+8]
    cmp rdx, [r12+176]
    jb .baseline_view
    ; Port form_netmon_tick's unsigned delta, ceiling and one-step slew.
    ; State lives in the disposable RW module page, never the RX member.
    mov rax, [r12]
    mov rdx, rax
    sub rax, [r12+168]
    mov [r12+168], rdx
    mov rcx, [r12+184]
    call nm_rate
    mov [r12+184], rax
    mov rax, [r12+8]
    mov rdx, rax
    sub rax, [r12+176]
    mov [r12+176], rdx
    mov rcx, [r12+192]
    call nm_rate
    mov [r12+192], rax
    jmp .view
.baseline_view:
    mov [r12+768], rax
    cmp qword [r12+16], 1
    je .baseline_online
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    mov qword [r12+184], 0
    mov qword [r12+192], 0
    jmp .view
.baseline_online:
    mov rax, [r12]
    mov [r12+168], rax
    mov rax, [r12+8]
    mov [r12+176], rax
    mov qword [r12+184], 0
    mov qword [r12+192], 0
    jmp .view
.unavailable_view:
    mov rax, [r12+248]
    mov [r12+768], rax
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    mov qword [r12+184], -1
    mov qword [r12+192], -1
    jmp .view
.unavailable:
    mov rax, [r12+248]
    mov [r12+768], rax
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    mov qword [r12+184], -1
    mov qword [r12+192], -1
    jmp .finish
.view:
    lea rdi, [rel nm_live_nic]
    call nm_puts
    call nm_name
    lea rdi, [rel nm_live_rx]
    call nm_puts
    mov rax, [r12]
    call nm_sample
    lea rdi, [rel nm_live_tx]
    call nm_puts
    mov rax, [r12+8]
    call nm_sample
    lea rdi, [rel nm_live_drops_link]
    call nm_puts
    mov rax, [r12+16]
    call nm_sample
    jmp .finish
.bind:
    mov qword [r12+208], 0
    lea rdi, [r12+32]
    lea rsi, [rel nm_bind_live]
    call nm_equal
    jz .bind_live
    lea rdi, [r12+32]
    lea rsi, [rel nm_bind_rx]
    call nm_equal
    jz .bind_rx
    lea rdi, [r12+32]
    lea rsi, [rel nm_bind_tx]
    call nm_equal
    jnz .finish
    mov qword [r12+208], 4
    jmp .finish
.bind_rx:
    mov qword [r12+208], 3
    jmp .finish
.bind_live:
    mov qword [r12+208], 2
    jmp .finish
.widget:
    mov qword [r12+208], 0
    cmp qword [r12+216], 2
    je .widget_text
    cmp qword [r12+216], 3
    je .widget_rx
    cmp qword [r12+216], 4
    jne .finish
    mov rax, [r12+192]
    jmp .widget_number
.widget_rx:
    mov rax, [r12+184]
.widget_number:
    cmp qword [r12+16], 1
    jne .finish
    cmp qword [r12], -1
    je .finish
    cmp qword [r12+8], -1
    je .finish
    cmp rax, -1
    je .finish
    mov rdx, [r12+248]
    cmp rdx, [r12+768]
    jne .finish                         ; selection changed before cadence baseline
    ; Preserve the shipped clamp against this widget's declared maximum.
    cmp rax, [r12+224]
    jbe .widget_store
    mov rax, [r12+224]
.widget_store:
    mov [r12+200], rax
    mov qword [r12+208], 2
    jmp .finish
.widget_text:
    mov qword [r12+208], 1
    jmp .view
nm_equal:
    mov al, [rdi]
    cmp al, [rsi]
    jne .out
    inc rdi
    inc rsi
    test al, al
    jnz nm_equal
.out:
    ret
nm_rate:
    cmp rax, 100
    jbe .bounded
    mov eax, 100
.bounded:
    cmp rax, rcx
    jb .decay
    lea rdx, [rcx+1]
    cmp rax, rdx
    jbe .out
    mov rax, rdx
    ret
.decay:
    test rcx, rcx
    jz .out
    lea rax, [rcx-1]
.out:
    ret
; Bound derives from four u64 decimal fields + literals + <=127 nonce bytes:
; fewer than 320 output bytes, in a dedicated 512-byte scratch span.
nm_puts:
    mov al, [rdi]
    test al, al
    jz .done
    mov [rbx], al
    inc rbx
    inc rdi
    jmp nm_puts
.done:
    ret
nm_dec:
    ; Port core/lib/fmt.asm's proven unsigned do-while/div/reverse sequence.
    ; RBX is the loader-provided non-NULL output span, already bounded above.
    mov r9d, 10
    xor r8d, r8d
.loop:
    xor edx, edx
    div r9
    add dl, '0'
    push rdx
    inc r8
    test rax, rax
    jnz .loop
.copy:
    pop rax
    mov [rbx], al
    inc rbx
    dec r8
    jnz .copy
    ret
; Render missing samples as text, never UINT64_MAX or fabricated zero.
nm_sample:
    cmp rax, -1
    jne nm_dec
    lea rdi, [rel nm_unavailable]
    jmp nm_puts
nm_name:
    lea rdi, [r12+232]
    cmp byte [rdi], 0
    jne nm_put_name
    lea rdi, [rel nm_unavailable]
    jmp nm_puts
nm_put_name:
    ; Name has its own limit even if a malformed snapshot lacks a terminator.
    mov ecx, 15
.loop:
    mov al, [rdi]
    test al, al
    jz .out
    mov [rbx], al
    inc rbx
    inc rdi
    dec ecx
    jnz .loop
.out:
    ret
nm_rx: db " netmon rx=",0
nm_tx: db " tx=",0
nm_link: db " link=",0
nm_nic: db " nic=",0
nm_idx: db " idx=",0
nm_unavailable: db "unavailable",0
nm_nonce: db " nonce=",0
nm_live_nic: db "nic=",0
nm_live_rx: db ",rx=",0
nm_live_tx: db ",tx=",0
nm_live_drops_link: db ",drops=unavailable,link=",0
nm_bind_live: db "netmon.live",0
nm_bind_rx: db "netmon.rx_rate",0
nm_bind_tx: db "netmon.tx_rate",0
nm_form: incbin "gui/forms/netmon.frm"
nm_form_end:
