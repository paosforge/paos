; R5 observational witness, called ONLY after a successful arm journal_commit.
; Emit actual PaOS Trial or R5 BOUND/CONSUMED PaOS/Rescue attempts.
; Both buffers are the real Flush + exact-read-verified journal copies. No
; state write, firmware call, acknowledgement, policy decision or main request.
; One TOTAL 100000-poll UART budget, including absent and midframe-stalled UART.
; An interrupted frame is missing evidence. Preserve all changed GPRs + flags.
r5_serial_journal_after_commit:
    pushfq
    push rax
    cmp r15b,1                         ; PaOS A/B or independent Rescue only
    jb .skip
    cmp r15b,3
    ja .skip
    mov rax,[rel selected_state_ptr]
    test rax,rax
    jz .skip
    cmp byte [rel selected_reason],PBM_REASON_TRIAL
    je .emit
    cmp dword [rax+264],0x31503552      ; actual CRC-covered R5P1 extension
    jne .skip
    cmp dword [rax+268],1              ; BOUND or CONSUMED, never inventory
    jb .skip
    cmp dword [rax+268],2
    ja .skip
.emit:
    call r5_serial_journal_witness
.skip:
    pop rax
    popfq
    ret

r5_serial_journal_witness:
    push rsi
    lea rsi,[rel journal_serial_witness_from_rsi.header]
    call journal_serial_witness_from_rsi
    pop rsi
    ret

; Shared observational entry: RSI -> caller-owned static NUL header.
; Emits that header + both actual journal buffers + CRLF. Same total bound
; and complete register/flags preservation; no R5 interpretation is implied.
journal_serial_witness_from_rsi:
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push r8
    push r9
    mov ebx,100000
.header_next:
    mov al,[rsi]
    test al,al
    jz .first
    call .put
    jc .done
    inc rsi
    jmp .header_next
.first:
    lea rsi,[rel state0]
    call .copy
    jc .done
    lea rsi,[rel state1]
    call .copy
    jc .done
    mov al,13
    call .put
    jc .done
    mov al,10
    call .put
.done:
    pop r9
    pop r8
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret
.copy:
    mov ecx,512
.byte:
    mov r9b,[rsi]
    mov al,r9b
    shr al,4
    call .nibble
    jc .copy_done
    mov al,r9b
    and al,15
    call .nibble
    jc .copy_done
    inc rsi
    dec ecx
    jnz .byte
    clc
.copy_done:
    ret
.nibble:
    cmp al,10
    jb .digit
    add al,'a'-10
    jmp .put
.digit:
    add al,'0'
.put:
    mov r8b,al
.wait:
    test ebx,ebx
    jz .exhausted
    dec ebx
    mov dx,0x3fd
    in al,dx
    test al,0x20
    jz .wait
    mov al,r8b
    mov dx,0x3f8
    out dx,al
    clc
    ret
.exhausted:
    stc
    ret
.header:
    db 13,10,'PAOS-R5-JOURNAL1 ARM 1024 ',0
