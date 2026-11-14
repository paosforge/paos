;; MODULE dev/net/ax88179b_codec
;; LAYER 3
;; EXPORTS ax88179b_rx_validate, ax88179b_rx_frame, ax88179b_rx_begin, ax88179b_rx_next, ax88179b_tx_header, ax88179b_tx_record
;; IMPORTS
;; CAPS
;; OWNER saga:net
; AX88179B/179A ordinary Ethernet packet format, not an attachment driver.
; Reference: ASIXElectronics/asix-usb-nic-linux-driver
; 42feb1252fe0669845a8d6714bcc77bfc19eea1d, ax88179a_772d.h:156..268,
; ax88179a_772d.c:3448..3550,3714..3784. Independent implementation.
; No USB controls, netdev registration, DMA ownership or legacy identity changes.
; The future backend must select non-PTP/non-preempt, untagged, ipalign=0 mode.

AX179B_FRAME_MIN equ 14
AX179B_FRAME_MAX equ 1514
AX179B_RX_MAX    equ 49152             ; vendor ordinary RX allocation: 48 KiB

; RDI=actual completed buffer, RSI=actual bytes (allocation covers those bytes).
; CF=0: RAX=descriptor count, RDX=descriptor-table byte offset.
; CF=1: RAX=RDX=0. All records are validated before any frame is exposed.
; Accept 8-byte data alignment and 0,16,... padding between table and footer.
; Reject unsupported VLAN/PTP/preempt metadata; network checksum hints ignored.
; Bad RxOk/drop records still consume their full validated data span.
; Preserves RDI,RSI and SysV callee-saved registers; other volatile GPRs clobbered.
ax88179b_rx_validate:
    test rdi, rdi
    jz .bad
    cmp rsi, 8
    jb .bad
    cmp rsi, AX179B_RX_MAX
    ja .bad
    mov rax, rdi
    add rax, rsi
    jc .bad
    mov r8, [rax - 8]
    mov r9d, r8d
    and r9d, 0x1fff
    jz .bad
    mov edx, r8d
    shr edx, 13
    test edx, 7
    jnz .bad
    lea r10, [rdx + r9 * 8]
    lea r11, [rsi - 8]
    sub r11, r10
    jc .bad
    test r11, 15
    jnz .bad
    lea r8, [rdi + rdx]
    xor ecx, ecx                     ; data cursor
    mov r10, r9
.entry:
    mov rax, [r8]
    test eax, 0x7400                 ; VLAN bit10 / unsupported preempt12..14
    jnz .bad
    mov r11, rax
    shr r11, 56                     ; PTP + unsupported preempt/reserved high bits
    jnz .bad
    shr eax, 16
    and eax, 0x7fff
    cmp eax, AX179B_FRAME_MIN
    jb .bad
    cmp eax, AX179B_FRAME_MAX
    ja .bad
    add eax, 7
    and eax, -8
    add rcx, rax
    cmp rcx, rdx
    ja .bad
    add r8, 8
    dec r10
    jnz .entry
    cmp rcx, rdx
    jne .bad
    mov rax, r9
    clc
    ret
.bad:
    xor eax, eax
    xor edx, edx
    stc
    ret

; RDI=completed buffer, RSI=actual bytes, RDX=zero-based descriptor index.
; CF=0: RAX=frame pointer, RDX=frame length; no bytes are copied or published.
; CF=1: RAX=RDX=0 for malformed aggregate, bad index, !RxOk or drop.
; Revalidates the WHOLE immutable aggregate before returning any frame pointer.
; Owner must retain buffer unchanged until consumption, and quiesce USB on exit.
ax88179b_rx_frame:
    push rbx
    mov rbx, rdx
    call ax88179b_rx_validate
    jc .bad
    cmp rbx, rax
    jae .bad
    lea r8, [rdi + rdx]
    mov rax, [r8 + rbx * 8]
    test eax, 0x800
    jz .bad
    bt eax, 31
    jc .bad
    shr eax, 16
    and eax, 0x7fff
    mov edx, eax
    xor ecx, ecx
    xor r9d, r9d
.advance:
    cmp r9, rbx
    je .found
    mov eax, [r8 + r9 * 8]
    shr eax, 16
    and eax, 0x7fff
    add eax, 7
    and eax, -8
    add rcx, rax
    inc r9
    jmp .advance
.found:
    lea rax, [rdi + rcx]
    pop rbx
    clc
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop rbx
    stc
    ret

; Validate-once receive iterator, independent of USB/backend ownership.
; RDI=immutable completed buffer, RSI=actual bytes, RDX=trusted writable 48B state.
; State must cover 48 bytes and be disjoint from the completed buffer.
; CF=0: RAX=descriptor count, RDX=table offset; initialized state contains:
; +0 buffer, +8 actual bytes, +16 table offset, +24 remaining descriptor count,
; +32 next data offset, +40 next descriptor offset. CF=1: RAX=RDX=0,
; state untouched. Only call next after successful begin (or on zeroed state).
; Buffer MUST remain unchanged through the last frame consumer, and its owner
; must quiesce USB before recycling it. State is trusted, exclusive caller memory;
; changing state or buffer concurrently invalidates the contract. No DMA custody
; is transferred. Preserves RDI,RSI and SysV nonvolatile registers, DF unchanged.
ax88179b_rx_begin:
    push rbx
    test rdx, rdx
    jz .bad
    mov r8, rdx
    add r8, 48
    jc .bad
    test rdi, rdi
    jz .bad
    cmp rsi, 8
    jb .bad
    cmp rsi, AX179B_RX_MAX
    ja .bad
    mov rax, rdi
    add rax, rsi
    jc .bad
    cmp rdx, rax
    jae .disjoint
    cmp rdi, r8
    jb .bad
.disjoint:
    mov rbx, rdx
    call ax88179b_rx_validate
    jc .bad
    mov [rbx], rdi
    mov [rbx + 8], rsi
    mov [rbx + 16], rdx
    mov [rbx + 24], rax
    mov qword [rbx + 32], 0
    mov [rbx + 40], rdx
    pop rbx
    clc
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop rbx
    stc
    ret

; RDI=trusted 48B state initialized by successful begin; same immutable buffer.
; CF=0: RAX=next RxOk/non-drop frame pointer, RDX=length (no copy/publish).
; CF=1: RAX=RDX=0 on exhaustion or malformed state; remaining count latched 0.
; Skipped descriptors consume their aligned data span. Whole validation occurs
; only in begin; next visits each record once, total O(count) aggregate delivery.
; Local bounds/metadata checks defend cursor mistakes; arbitrary forged pointers
; are not supported. Preserves RDI and SysV nonvolatile registers, DF unchanged.
ax88179b_rx_next:
    test rdi, rdi
    jz .bad_pointer
    mov rax, rdi
    add rax, 48
    jc .bad_pointer
    mov r11, [rdi + 24]
    test r11, r11
    jz .bad                          ; exhausted/zero state never reads the buffer
    cmp r11, 0x1fff
    ja .bad
    mov r8, [rdi]
    test r8, r8
    jz .bad
    mov rcx, [rdi + 8]
    cmp rcx, 8
    jb .bad
    cmp rcx, AX179B_RX_MAX
    ja .bad
    mov rax, r8
    add rax, rcx
    jc .bad
    sub rcx, 8                       ; exclusive descriptor limit: footer start
    mov rsi, [rdi + 16]
    test rsi, 7
    jnz .bad
    cmp rsi, rcx
    ja .bad
    mov r9, [rdi + 32]
    cmp r9, rsi
    ja .bad
    mov r10, [rdi + 40]
    cmp r10, rsi
    jb .bad
    test r10, 7
    jnz .bad
    lea rax, [r10 + r11 * 8]
    cmp rax, r10
    jb .bad
    sub rcx, rax
    jc .bad
    test rcx, 15
    jnz .bad
.entry:
    mov rax, [r8 + r10]              ; bounded table, including skipped records
    test eax, 0x7400
    jnz .bad
    mov rcx, rax
    shr rcx, 56
    jnz .bad
    mov edx, eax
    shr edx, 16
    and edx, 0x7fff
    cmp edx, AX179B_FRAME_MIN
    jb .bad
    cmp edx, AX179B_FRAME_MAX
    ja .bad
    lea rcx, [rdx + 7]
    and rcx, -8
    add rcx, r9
    cmp rcx, rsi
    ja .bad
    dec r11
    jnz .advance
    cmp rcx, rsi                     ; last record must end at descriptor table
    jne .bad
.advance:
    add r10, 8
    mov [rdi + 24], r11
    mov [rdi + 32], rcx
    mov [rdi + 40], r10
    test eax, 0x800
    jz .skip
    bt eax, 31
    jc .skip
    lea rax, [r8 + r9]
    clc
    ret
.skip:
    mov r9, rcx
    test r11, r11
    jnz .entry
.bad:
    mov qword [rdi + 24], 0
.bad_pointer:
    xor eax, eax
    xor edx, edx
    stc
    ret

; RDI=ordinary untagged Ethernet frame length (14..1514).
; CF=0: RAX=LE64 TX header; CF=1: RAX=0. No offload/VLAN/PTP flags.
; Low-level encoder: caller supplies padding, or uses tx_record below.
ax88179b_tx_header:
    cmp rdi, AX179B_FRAME_MIN
    jb .bad
    cmp rdi, AX179B_FRAME_MAX
    ja .bad
    mov rax, rdi
    mov rcx, rdi
    shr rcx, 8
    add rax, rcx
    mov rcx, rdi
    shr rcx, 16
    and ecx, 31
    add rax, rcx
    and eax, 127
    shl rax, 21
    or rax, rdi
    clc
    ret
.bad:
    xor eax, eax
    stc
    ret

; RDI=immutable Ethernet frame, RSI=actual bytes14..1514 (no FCS).
; RDX=trusted writable destination, RCX=destination allocation capacity.
; CF=0: RAX=complete USB record bytes, RDX=padded Ethernet length (no FCS).
; CF=1: RAX=RDX=0, destination untouched. No USB/DMA submission occurs.
; Pad short Ethernet frames to60 BEFORE header encoding; zero all padding.
; Header describes padded Ethernet length, excluding header/8B record alignment.
; Source must cover RSI; destination must cover RCX. Both stay stable/exclusive
; until return. Reject null/wrapping spans and source overlap with written record.
; Excess destination capacity is untouched; it may contain the source.
; Caller owns destination alignment required by USB/DMA and asynchronous lifetime.
; Preserves SysV callee-saved registers; volatile registers/flags clobbered, DF=0.
ax88179b_tx_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    test rdi, rdi
    jz .bad
    test rdx, rdx
    jz .bad
    cmp rsi, AX179B_FRAME_MIN
    jb .bad
    cmp rsi, AX179B_FRAME_MAX
    ja .bad
    mov rax, rdi
    add rax, rsi                     ; source end, exclusive
    jc .bad
    mov r8, rdx
    add r8, rcx                      ; refuse even unused capacity wrap
    jc .bad
    mov r15, rsi
    cmp r15, 60
    jae .padded
    mov r15d, 60
.padded:
    lea r14, [r15 + 15]              ; 8-byte header + align_up(payload,8)
    and r14, -8
    cmp rcx, r14
    jb .bad
    lea r8, [rdx + r14]              ; cannot wrap: record <= capacity
    cmp rdx, rax
    jae .disjoint                    ; destination begins after source end
    cmp rdi, r8
    jb .bad                          ; source begins before destination end
.disjoint:
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, r15
    call ax88179b_tx_header
    jc .bad                          ; no output before validated header
    mov [r13], rax
    mov rsi, rbx
    lea rdi, [r13 + 8]
    mov rcx, r12
    cld
    rep movsb                        ; exact source bytes, never padded reads
    mov rcx, r14
    sub rcx, 8
    sub rcx, r12
    xor eax, eax
    rep stosb                        ; Ethernet padding plus record padding
    mov rax, r14
    mov rdx, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    clc
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    cld
    stc
    ret
