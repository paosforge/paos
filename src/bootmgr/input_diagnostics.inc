; Opt-in, observation-only serial and bounded GOP diagnostics. No firmware call, allocation,
; event, policy write or input read is introduced. Hook preserves flags and every
; register it uses, including the original firmware EFI_STATUS in RAX.
%macro PBM_INPUT_OBSERVE 1
    pushfq
    push rax
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    call %1
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rax
    popfq
%endmacro

; Three pairs: first early ReadKeyStroke, visible CheckEvent, visible read.
; Each pair is availability/call flags and raw EFI_STATUS. All-ones means no
; observation yet; flags 1=ST,2=ConIn,4=WaitForKey,8=BS,16=entered,
; 32=returned,64=extended input handles discovered. Read status is first EX
; attempt when EX exists, otherwise the original ConIn read.
; Emit at most entry+return for each pair. Missing prerequisites emit once.
; Exactly once at the PCI->USB boundary, before starting the fresh budget.
; Existing serial sink gives the late-attach qualifier an actual start boundary.
menu_diag_usb_wait_report:
    lea rdi, [rel menu_diag_wait_label]
    call serial_string
    ret

menu_diag_read_enter:
    mov ecx, 0
    jmp menu_diag_read
menu_diag_read_return:
    mov ecx, 1
    jmp menu_diag_read
menu_diag_read_missing:
    mov ecx, 2
menu_diag_read:
    lea rsi, [rel menu_diag_input]
    lea rdi, [rel menu_diag_early_label]
    cmp byte [rel menu_visible], 0
    je menu_diag_observe
    add rsi, 32
    lea rdi, [rel menu_diag_read_label]
    jmp menu_diag_observe
menu_diag_check_enter:
    mov ecx, 0
    jmp menu_diag_check
menu_diag_check_return:
    mov ecx, 1
    jmp menu_diag_check
menu_diag_check_missing:
    mov ecx, 2
menu_diag_check:
    lea rsi, [rel menu_diag_input + 16]
    lea rdi, [rel menu_diag_check_label]
menu_diag_observe:
    cmp ecx, 1
    je .returned
    cmp qword [rsi], -1
    jne .out
    xor edx, edx
    cmp ecx, 0
    jne .available
    mov edx, 16
.available:
    cmp qword [rel menu_ex_count], 0
    je .boot_services
    or edx, 64
.boot_services:
    ; Sample presence only, using exactly the guarded UEFI pointer offsets
    ; used by the input helpers. Do not call Reset/CheckEvent/ReadKeyStroke.
    cmp qword [rel boot_services], 0
    je .system
    or edx, 8
.system:
    mov rax, [rel system_table]
    test rax, rax
    jz .store
    or edx, 1
.conin:
    mov rax, [rax + 48]
    test rax, rax
    jz .store
    or edx, 2
    cmp qword [rax + 16], 0
    je .store
    or edx, 4
.store:
    mov [rsi], rdx
    jmp .emit
.returned:
    test byte [rsi], 16
    jz .out                       ; first observation was unavailable
    test byte [rsi], 32
    jnz .out
    or byte [rsi], 32
    mov [rsi + 8], rax
.emit:
    push rsi
    mov ecx, 2
    call menu_diag_emit
    pop rsi
    ; Map the cached pair to E/V/R row4/5/6, once per first observation.
    lea rax, [rel menu_diag_input]
    sub rsi, rax
    shr esi, 4
    add esi, 4
    call menu_diag_gop_row
.out:
    ret

menu_diag_usb_report:
    lea rsi, [rel menu_diag_usb]
    lea rdi, [rel menu_diag_usb_label]
    mov ecx, 7
    jmp menu_diag_emit
menu_diag_final:
    cmp byte [rel menu_diag_final_done], 0
    jne .out
    mov byte [rel menu_diag_final_done], 1
    lea rsi, [rel menu_diag_input]
    lea rdi, [rel menu_diag_final_label]
    mov ecx, 6
    call menu_diag_emit
    call menu_diag_gop_all
.out:
    ret
; Existing finite UART seam only. serial_string/hex64 preserve RCX; no firmware
; ABI boundary here. Caller hook preserves the registers and flags we use.
menu_diag_emit:
    call serial_string
.next:
    mov rdi, [rsi]
    call serial_hex64
    lea rdi, [rel menu_diag_space]
    call serial_string
    add rsi, 8
    loop .next
    lea rdi, [rel menu_diag_nl]
    jmp serial_string

; The initial hook is called only after the existing GOP/layout render settles.
; No new GOP lookup, mode change, firmware call or input operation. All seven
; rows live strictly above the menu; unavailable space leaves the menu intact.
menu_diag_gop_begin:
    mov byte [rel menu_diag_gop_ready], 0
    cmp byte [rel face_countdown_graphics], 1
    jne .out
    cmp qword [rel face_fb_base], 0
    je .out
    cmp dword [rel face_fb_format], 1
    ja .out
    mov eax, [rel face_fb_width]
    cmp [rel face_fb_stride], eax
    jb .out
    mov edx, [rel face_fb_height]
    cmp byte [rel face_compact], 0
    je .logical
    shl rax, 1
    shl rdx, 1
.logical:
    cmp rax, 711                    ; x8 +37 cells *19 logical pixels
    jb .out
    cmp rdx, 256                    ; y8 +6 steps *36 +32 pixels
    jb .out
    cmp dword [rel face_layout_y], 256
    jb .out
    ; The existing raster uses a 32-bit pixel index. Bound the entire top256
    ; physical rows conservatively, even when compact drawing uses only128.
    mov eax, [rel face_fb_stride]
    shl rax, 8
    mov edx, 0xffffffff
    cmp rax, rdx
    ja .out
    shl rax, 2
    add rax, [rel face_fb_base]
    jc .out
    mov byte [rel menu_diag_gop_ready], 1
    call menu_diag_gop_all
.out:
    ret

; At most one initial and one final whole panel; entry/return updates only
; their fixed pair row. No polling path calls this unless its cached pair
; actually changes. Caller hooks preserve every renderer-clobbered register.
menu_diag_gop_all:
    push rbx
    xor ebx, ebx
.next:
    mov esi, ebx
    call menu_diag_gop_row
    inc ebx
    cmp ebx, 7
    jb .next
    pop rbx
    ret

; ESI=row0..6. Full qwords are rendered as16 hex digits, never truncated.
; A 64-byte stack formatter avoids growing the nearly full writable section.
menu_diag_gop_row:
    ; External-prelaunch refusal can re-enter a console-only presentation.
    ; Never reuse a prior validated surface after graphics was disabled.
    cmp byte [rel face_countdown_graphics], 1
    jne .out
    cmp byte [rel menu_diag_gop_ready], 1
    jne .out
    cmp esi, 6
    ja .out
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 64
    mov ebx, esi
    lea r12, [rel menu_diag_gop_labels]
    mov al, [r12 + rbx]
    mov [rsp], al
    mov byte [rsp+1], ' '
    lea rdi, [rsp+2]
    lea r12, [rel menu_diag_usb]
    mov eax, ebx
    add eax, eax
    cmp ebx, 2
    jb .offset
    dec eax                         ; C starts at3; T holds only word5
.offset:
    lea r12, [r12+rax*8]
    mov r13d, 2
    cmp ebx, 3
    jne .word
    dec r13d
.word:
    mov rax, [r12]
    mov ecx, 16
.hex:
    rol rax, 4
    mov edx, eax
    and edx, 15
    add dl, '0'
    cmp dl, '9'
    jbe .digit
    add dl, 'a'-'9'-1
.digit:
    mov [rdi], dl
    inc rdi
    loop .hex
    add r12, 8
    cmp ebx, 1
    jne .advanced
    add r12, 24                     ; counts word2 pairs with budget word6
.advanced:
    dec r13d
    jz .terminated
    mov byte [rdi], ' '
    inc rdi
    jmp .word
.terminated:
    mov byte [rdi], 0
    mov edx, ebx
    imul edx, 36
    add edx, 8
    mov esi, 8
    mov rdi, rsp
    mov r8d, PBM_FACE_ATTR_WHITE
    xor r9d, r9d
    call face_fb_string
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
.out:
    ret

%macro PBM_INPUT_DIAG_DATA 0
align 8
menu_diag_usb:
menu_diag_locate: dq -1, -1
; bytes: PCI handles, USB handles, PCI attempts, USB attempts, PCI successes,
; USB successes, PCI selected, keyboard selected. Fixed bounds fit in a byte.
menu_diag_counts: dq 0
menu_diag_connect_status: dq -1, -1 ; first error, otherwise last success
menu_diag_calibration_status: dq -1
; low byte:0 complete,1 Stall error,2 invalid TSC calibration,3 call cap,4 time.
; next byte: last phase (0 PCI,1 USB), or FF before enumeration.
menu_diag_budget: dq 0xFF02
menu_diag_input: times 6 dq -1
menu_diag_final_done: db 0
menu_diag_gop_ready: db 0
menu_diag_gop_labels: db "LNCTEVR"
menu_diag_wait_label: db "[PBM] input.wait",13,10,0
menu_diag_usb_label: db "[PBM] input.usb ",0
menu_diag_early_label: db "[PBM] input.early ",0
menu_diag_check_label: db "[PBM] input.event ",0
menu_diag_read_label: db "[PBM] input.visible ",0
menu_diag_final_label: db "[PBM] input.final ",0
menu_diag_space: db " ",0
menu_diag_nl: db 13,10,0
%endmacro
