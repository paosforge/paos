; Fast-boot firmware may leave USB unconnected for boot applications. Connect
; only PCI USB controllers, then all USB_IO devices, before the first
; gesture read. No console reset (which would discard a held/queued key).
;
; PCI pass, then USB discovery for up to three seconds after host connection.
; 128 handles per pass, at most 16 recursive ConnectController calls per phase;
; elapsed-TSC budget calibrated with Stall(1000 us).
; Check the budget between firmware calls. UEFI synchronous calls have no
; cancellation/timeout parameter: a single firmware call can exceed the budget.
; Calibration failure skips this best-effort step; existing input still works.
; One firmware handle-buffer allocation for extended input; no event creation,
; EFI-variable writes or policy changes.
menu_connect_usb_console:
    cmp  byte [rel menu_usb_done], 0
    jne  .return
    mov  byte [rel menu_usb_done], 1
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 128 * 8
    mov  r15, rsp                   ; bounded handle scratch, not resident data
    call menu_usb_ticks
    mov  r12, rax
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 32
    mov  ecx, 1000
    call [rax + 0xF8]               ; Stall
    PBM_FW_LEAVE 32
%ifdef PBM_DIAG_INPUT
    mov [rel menu_diag_calibration_status], rax
    mov byte [rel menu_diag_budget], 1
%endif
    test rax, rax
    jnz  .out
%ifdef PBM_DIAG_INPUT
    mov byte [rel menu_diag_budget], 2
%endif
    call menu_usb_ticks
    sub  rax, r12
    jz   .out
    imul rax, rax, 3000
    jo   .out
    mov  [rel menu_usb_budget_ticks], rax
    call menu_usb_ticks
    mov  [rel menu_usb_start_ticks], rax
%ifdef PBM_DIAG_INPUT
    mov byte [rel menu_diag_budget], 0
%endif
    xor  r12d, r12d                 ; PCI first, newly created USB_IO second
.phase:
%ifdef PBM_DIAG_INPUT
    mov byte [rel menu_diag_budget + 1], r12b
%endif
    call menu_usb_budget
    test eax, eax
    jz   .budget_end
    lea  rdx, [rel menu_usb_pci_guid]
    test r12d, r12d
    jz   .locate
    lea  rdx, [rel menu_usb_io_guid]
.locate:
    mov  qword [rel menu_usb_handle_bytes], 128 * 8
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 48
    mov  ecx, 2                    ; ByProtocol
    xor  r8d, r8d
    lea  r9, [rel menu_usb_handle_bytes]
    mov  r10, r15
    mov  [rsp + 32], r10
    call [rax + 0xB0]              ; LocateHandle, fixed caller-owned buffer
    PBM_FW_LEAVE 48
%ifdef PBM_DIAG_INPUT
    lea rdx, [rel menu_diag_locate]
    mov [rdx + r12 * 8], rax
%endif
    test rax, rax
    jnz  .locate_failed             ; retry only USB NOT_FOUND, never bad buffers
    mov  rax, [rel menu_usb_handle_bytes]
    cmp  rax, 128 * 8
    ja   .next_phase
    test al, 7
    jnz  .next_phase
%ifdef PBM_DIAG_INPUT
    mov rdx, rax
    shr rdx, 3
    lea rcx, [rel menu_diag_counts]
    mov [rcx + r12], dl
%endif
    test rax, rax
    jz   .empty
    xor  ebx, ebx
.handle:
    cmp  rbx, [rel menu_usb_handle_bytes]
    jae  .next_phase
    call menu_usb_budget
    test eax, eax
    jz   .budget_end
    mov  rax, r15
    mov  r14, [rax + rbx]
    add  ebx, 8
    test r14, r14
    jz   .handle
    mov  qword [rel menu_usb_protocol], 0
    lea  rdx, [rel menu_usb_pci_guid]
    test r12d, r12d
    jz   .protocol
    lea  rdx, [rel menu_usb_io_guid]
.protocol:
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 32
    mov  rcx, r14
    lea  r8, [rel menu_usb_protocol]
    call [rax + 0x98]              ; HandleProtocol
    PBM_FW_LEAVE 32
    test rax, rax
    jnz  .handle
    mov  r13, [rel menu_usb_protocol]
    test r13, r13
    jz   .handle
    call menu_usb_budget
    test eax, eax
    jz   .budget_end
    test r12d, r12d
    jnz  .keyboard
    PBM_FW_ENTER 48
    mov  rcx, r13
    xor  edx, edx                  ; EfiPciIoWidthUint8
    mov  r8d, 9                    ; ProgIF, SubClass, BaseClass
    mov  r9d, 3
    lea  r10, [rel menu_usb_descriptor]
    mov  [rsp + 32], r10
    call [r13 + 0x30]              ; Pci.Read
    PBM_FW_LEAVE 48
    test rax, rax
    jnz  .handle
    cmp  word [rel menu_usb_descriptor + 1], 0x0C03
    jne  .handle
    jmp  .connect
.keyboard:
    ; Bind every USB_IO device recursively, including composite keyboards.
.connect:
%ifdef PBM_DIAG_INPUT
    lea rdx, [rel menu_diag_counts + 6]
    inc byte [rdx + r12]
%endif
    call menu_usb_budget
    test eax, eax
    jz   .budget_end
    inc  byte [rel menu_usb_connect_calls]
%ifdef PBM_DIAG_INPUT
    lea rdx, [rel menu_diag_counts + 2]
    inc byte [rdx + r12]
%endif
    mov  rax, [rel boot_services]
    PBM_FW_ENTER 32
    mov  rcx, r14
    xor  edx, edx                  ; let firmware select installed drivers
    xor  r8d, r8d                  ; entire remaining device path
    mov  r9d, 1                    ; Recursive = TRUE
    call [rax + 0x108]             ; ConnectController, best effort
    PBM_FW_LEAVE 32
%ifdef PBM_DIAG_INPUT
    lea rdx, [rel menu_diag_connect_status]
    cmp qword [rdx + r12 * 8], -1
    je .diag_status
    cmp qword [rdx + r12 * 8], 0
    jne .diag_count
.diag_status:
    mov [rdx + r12 * 8], rax
.diag_count:
    test rax, rax
    jnz .diag_connected
    lea rdx, [rel menu_diag_counts + 4]
    inc byte [rdx + r12]
.diag_connected:
%endif
    jmp  .handle
.budget_end:
    test r12d, r12d
    jz .next_phase
    jmp .out
.locate_failed:
    mov rdx, 0x800000000000000E    ; EFI_NOT_FOUND
    cmp rax, rdx
    jne .next_phase
.empty:
    test r12d, r12d
    jz .next_phase
    cmp byte [rel menu_usb_waits], 60
    jae .out
    call menu_usb_budget
    test eax, eax
    jz .out
    inc byte [rel menu_usb_waits]
    mov rax, [rel boot_services]
    PBM_FW_ENTER 32
    mov ecx, 50000
    call [rax + 0xF8]              ; bounded device-enumeration progress
    PBM_FW_LEAVE 32
    test rax, rax
    jnz .out
    jmp .phase
.next_phase:
    test r12d, r12d
    jnz .out
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_usb_wait_report
%endif
    ; Host-controller connection can consume its own budget. USB discovery
    ; receives a fresh three seconds, independently of those firmware calls.
    call menu_usb_ticks
    mov [rel menu_usb_start_ticks], rax
    mov byte [rel menu_usb_connect_calls], 0
    inc  r12d
    cmp  r12d, 2
    jb   .phase
.out:
    call menu_cache_input_ex
%ifdef PBM_DIAG_INPUT
    PBM_INPUT_OBSERVE menu_diag_usb_report
%endif
    add  rsp, 128 * 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.return:
    ret

; Cache every SIMPLE_TEXT_INPUT_EX protocol after recursive USB binding.
; Retain its firmware pool while Manager/returning children need the menu;
; normal boot/reset reclaims boot-services memory. No key/reset/event here.
menu_cache_input_ex:
    push rbx
    push r12
    mov rax, [rel boot_services]
    test rax, rax
    jz .out
    cmp qword [rax + 0x138], 0       ; LocateHandleBuffer
    je .out
    PBM_FW_ENTER 48
    mov ecx, 2
    lea rdx, [rel menu_input_ex_guid]
    xor r8d, r8d
    lea r9, [rel menu_ex_count]
    lea r10, [rel menu_ex_inputs]
    mov [rsp + 32], r10
    call [rax + 0x138]
    PBM_FW_LEAVE 48
    test rax, rax
    jnz .clear
    cmp qword [rel menu_ex_inputs], 0
    je .clear
    xor ebx, ebx
.next:
    cmp rbx, [rel menu_ex_count]
    jae .out
    mov r12, [rel menu_ex_inputs]
    mov rcx, [r12 + rbx * 8]
    mov qword [r12 + rbx * 8], 0
    test rcx, rcx
    jz .advance
    lea rdx, [rel menu_input_ex_guid]
    lea r8, [r12 + rbx * 8]
    mov rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x98]                ; HandleProtocol
    PBM_FW_LEAVE 32
    test rax, rax
    jz .advance
    mov qword [r12 + rbx * 8], 0
.advance:
    inc rbx
    jmp .next
.clear:
    mov qword [rel menu_ex_count], 0
.out:
    pop r12
    pop rbx
    ret

menu_usb_budget:
    cmp  byte [rel menu_usb_connect_calls], 16
%ifdef PBM_DIAG_INPUT
    jae .count_expired
%else
    jae .expired
%endif
    call menu_usb_ticks
    sub  rax, [rel menu_usb_start_ticks]
    cmp  rax, [rel menu_usb_budget_ticks]
    jae  .expired
    mov  eax, 1
    ret
%ifdef PBM_DIAG_INPUT
.count_expired:
    mov byte [rel menu_diag_budget], 3
    jmp .expired_result
%endif
.expired:
%ifdef PBM_DIAG_INPUT
    mov byte [rel menu_diag_budget], 4
.expired_result:
%endif
    xor  eax, eax
    ret

menu_usb_ticks:
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    ret

; Emit in the PE's writable .data region, never beside executable instructions.
%macro PBM_USB_CONSOLE_DATA 0
align 8
menu_ex_count: dq 0
menu_ex_inputs: dq 0
menu_usb_start_ticks: dq 0
menu_usb_budget_ticks: dq 0
menu_usb_handle_bytes: dq 0
menu_usb_protocol: dq 0
menu_usb_done: db 0
menu_usb_connect_calls: db 0
menu_usb_waits: db 0
menu_usb_descriptor: times 9 db 0
align 4
menu_input_ex_guid: dd 0xdd9e7534
    dw 0x7762, 0x4698
    db 0x8c,0x14,0xf5,0x85,0x17,0xa6,0x25,0xaa
menu_usb_pci_guid: dd 0x4CF5B200
    dw 0x68B8, 0x4CA5
    db 0x9E,0xEC,0xB2,0x3E,0x3F,0x50,0x02,0x9A
menu_usb_io_guid: dd 0x2B2F68D6
    dw 0x0CD2, 0x44CF
    db 0x8E,0x8B,0xBB,0xA2,0x0B,0x1B,0x5B,0x75
%endmacro
