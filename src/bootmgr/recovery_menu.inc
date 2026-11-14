; Local recovery actions are offered only inside the already-visible, bounded
; Manager menu. Neither inspection nor cursor movement changes boot policy or
; journal bytes. The original six boot routes retain their existing validators.
menu_dispatch_key:
    push rbx
    mov  ebx, eax
    call menu_recovery_key
    test eax, eax
    jnz  .handled
    mov  eax, ebx
    call menu_apply_key
    pop  rbx
    ret
.handled:
    xor  eax, eax                     ; viewing details never accepts a boot
    pop  rbx
    ret

; EAX=key -> 1 consumed, 0 leave to existing trusted boot-route dispatch.
menu_recovery_key:
    cmp  byte [rel menu_visible], 1
    jne  .ignore
    cmp  eax, 'D'
    je   .details
    cmp  eax, 'd'
    je   .details
    cmp  byte [rel menu_recovery_visible], 1
    jne  .ignore
    cmp  eax, 0x10001
    je   .up
    cmp  eax, 0x10002
    je   .down
    cmp  eax, 13
    jne  .letter
    movzx eax, byte [rel menu_recovery_cursor]
.letter:
    cmp  eax, 27
    je   .back
    cmp  eax, 0x7F                    ; no low-byte aliases for Unicode input
    ja   .ignore
    or   al, 0x20
    cmp  al, 'b'
    je   .back
    cmp  al, 'x'
    je   .restart
    cmp  al, 'f'
    je   .firmware
.ignore:
    xor  eax, eax
    ret
.details:
    mov  byte [rel menu_recovery_visible], 1
    mov  byte [rel menu_recovery_cursor], 'b'
    mov  byte [rel menu_recovery_failed], 0
    call menu_recovery_supported
    mov  [rel menu_recovery_firmware], al
    jmp  .redraw
.back:
    mov  byte [rel menu_recovery_visible], 0
    call prepare_menu_console
    call menu_render_face
    jmp  .consumed
.up:
    mov  edi, -1
    jmp  .move
.down:
    mov  edi, 1
.move:
    ; Three fixed rows; unavailable firmware is skipped, never dispatched.
    movzx eax, byte [rel menu_recovery_cursor]
    mov  ecx, 0
    cmp  al, 'b'
    je   .index
    inc  ecx
    cmp  al, 'x'
    je   .index
    inc  ecx
.index:
    add  ecx, edi
    jns  .nonnegative
    mov  ecx, 2
.nonnegative:
    cmp  ecx, 3
    jb   .bounded
    xor  ecx, ecx
.bounded:
    cmp  ecx, 2
    jne  .cursor
    cmp  byte [rel menu_recovery_firmware], 1
    je   .cursor
    test edi, edi
    js   .skip_up
    xor  ecx, ecx
    jmp  .cursor
.skip_up:
    mov  ecx, 1
.cursor:
    lea  rdx, [rel recovery_keys]
    mov  al, [rdx + rcx]
    mov  [rel menu_recovery_cursor], al
    jmp  .redraw
.restart:
    call menu_recovery_reset
    jmp  .failed                    ; ResetSystem must not return
.firmware:
    cmp  byte [rel menu_recovery_firmware], 1
    jne  .consumed
    call menu_recovery_to_firmware
.failed:
    mov  byte [rel menu_recovery_failed], 1
.redraw:
    call menu_recovery_render
.consumed:
    mov  eax, 1
    ret

; Read only the standard UEFI capability, never infer support from a boot
; entry. No variable is written during rendering, discovery or normal timeout.
menu_recovery_supported:
    push rbx
    mov  rbx, [rel runtime_services]
    test rbx, rbx
    jz   .no
    cmp  qword [rbx + 0x48], 0
    je   .no
    cmp  qword [rbx + 0x58], 0
    je   .no
    cmp  qword [rbx + 0x68], 0
    je   .no
    lea  rcx, [rel recovery_supported_name]
    call menu_recovery_get_indications
    test rax, rax
    jnz  .no
    cmp  qword [rel recovery_var_size], 8
    jne  .no
    test byte [rel recovery_indications], 1
    setnz al
    movzx eax, al
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; RCX=one compiled standard variable name. RBX=runtime services.
menu_recovery_get_indications:
    mov  qword [rel recovery_var_size], 8
    mov  qword [rel recovery_indications], 0
    mov  dword [rel recovery_var_attributes], 0
    lea  rdx, [rel recovery_global_guid]
    lea  r8, [rel recovery_var_attributes]
    lea  r9, [rel recovery_var_size]
    PBM_FW_ENTER 40
    lea  rax, [rel recovery_indications]
    mov  [rsp + 32], rax
    call [rbx + 0x48]                  ; GetVariable
    PBM_FW_LEAVE 40
    ret

; Explicit F only: re-read capability, preserve other OsIndications bits, set
; BOOT_TO_FW_UI, then cold reset. Refusal/malformed data/SetVariable failure
; leaves the bounded menu usable and never falls through to another OS.
menu_recovery_to_firmware:
    push rbx
    call menu_recovery_supported
    test eax, eax
    jz   .out
    mov  rbx, [rel runtime_services]
    lea  rcx, [rel recovery_indications_name]
    call menu_recovery_get_indications
    mov  rdx, 0x800000000000000E         ; EFI_NOT_FOUND
    cmp  rax, rdx
    je   .absent
    test rax, rax
    jnz  .out
    cmp  qword [rel recovery_var_size], 8
    jne  .out
    cmp  dword [rel recovery_var_attributes], 7
    jne  .out
    jmp  .write
.absent:
    mov  qword [rel recovery_indications], 0
.write:
    or   qword [rel recovery_indications], 1
    lea  rcx, [rel recovery_indications_name]
    lea  rdx, [rel recovery_global_guid]
    mov  r8d, 7                        ; NV | BOOTSERVICE | RUNTIME
    mov  r9d, 8
    PBM_FW_ENTER 40
    lea  rax, [rel recovery_indications]
    mov  [rsp + 32], rax
    call [rbx + 0x58]                  ; SetVariable, this variable only
    PBM_FW_LEAVE 40
    test rax, rax
    jnz  .out
    call menu_recovery_reset
.out:
    pop  rbx
    ret

menu_recovery_reset:
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .out
    cmp  qword [rax + 0x68], 0
    je   .out
    xor  ecx, ecx                     ; EfiResetCold
    xor  edx, edx                     ; EFI_SUCCESS
    xor  r8d, r8d
    xor  r9d, r9d
    PBM_FW_ENTER 32
    call [rax + 0x68]                 ; ResetSystem; return is a failure
    PBM_FW_LEAVE 32
.out:
    ret

; Same compact/high-DPI geometry and countdown as the main face. Only compiled
; text and the selected reason are presented; no ESP reads or journal mutation.
menu_recovery_render:
    push rbx
    push r12
    push r13
    push r14
    push r15
    movzx eax, byte [rel selected_reason]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    lea  rcx, [rel recovery_hex]
    mov  al, [rcx + rax]
    mov  dl, [rcx + rdx]
    mov  [rel recovery_support_code + 19], al
    mov  [rel recovery_support_code + 20], dl
    cmp  byte [rel face_countdown_graphics], 1
    jne  .console
    call face_fb_clear
    jmp  .lines
.console:
    call prepare_menu_console
.lines:
    xor  r12d, r12d
    lea  rdi, [rel recovery_title]
    call menu_recovery_line
    call menu_reason_text
    call menu_recovery_line
    lea  rdi, [rel recovery_support_code]
    call menu_recovery_line
    lea  rdi, [rel recovery_back]
    call menu_recovery_line
    lea  rdi, [rel recovery_restart]
    call menu_recovery_line
    lea  rdi, [rel recovery_firmware_unavailable]
    cmp  byte [rel menu_recovery_firmware], 1
    jne  .firmware_line
    lea  rdi, [rel recovery_firmware]
.firmware_line:
    call menu_recovery_line
    lea  rdi, [rel recovery_controls]
    call menu_recovery_line
    lea  rdi, [rel recovery_english]
    cmp  byte [rel menu_recovery_failed], 1
    jne  .status
    lea  rdi, [rel recovery_refused]
.status:
    call menu_recovery_line
    cmp  byte [rel face_countdown_graphics], 1
    jne  .console_footer
    call menu_render_face_footer
    jmp  .out
.console_footer:
    call menu_countdown_bind_console
    call menu_render_console_countdown
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=in-image string; R12D=logical row. Shared output with focused action rows.
menu_recovery_line:
    cmp  byte [rel face_countdown_graphics], 1
    jne  .console
    mov  esi, [rel face_layout_x]
    add  esi, PBM_FACE_GLYPH_W
    imul edx, r12d, PBM_FACE_LINE_STEP
    add  edx, [rel face_layout_y]
    mov  r8d, PBM_FACE_ATTR_ENTRY
    xor  r9d, r9d
    cmp  r12d, 3
    jb   .plain
    cmp  r12d, 5
    ja   .plain
    mov  al, [rdi]
    or   al, 0x20
    cmp  al, [rel menu_recovery_cursor]
    jne  .plain
    call face_fb_selected_string
    jmp  .next
.plain:
    call face_fb_string
    jmp  .next
.console:
    push rdi
    cmp  r12d, 3
    jb   .text
    cmp  r12d, 5
    ja   .text
    mov  al, [rdi]
    or   al, 0x20
    cmp  al, [rel menu_recovery_cursor]
    jne  .text
    lea  rdi, [rel face_cursor_marker]
    call menu_console_output_ascii
.text:
    pop  rdi
    call menu_console_output_ascii
    lea  rdi, [rel face_console_newline]
    call menu_console_output_ascii
.next:
    inc  r12d
    ret

; The existing PE data section owns these bytes, including the short support
; code buffer. Never switch sections inside the Manager's manual PE layout.
%macro PBM_RECOVERY_MENU_DATA 0
menu_recovery_visible: db 0
menu_recovery_cursor: db 'b'
menu_recovery_firmware: db 0
menu_recovery_failed: db 0
recovery_keys: db 'bxf'
recovery_hex: db '0123456789ABCDEF'
recovery_title: db 'Boot details',0
recovery_support_code: db 'Support code: BV2-R00',0
recovery_back: db 'B - Back to boot menu',0
recovery_restart: db 'X - Restart',0
recovery_firmware: db 'F - Firmware settings',0
recovery_firmware_unavailable: db 'Firmware settings unavailable',0
recovery_controls: db 'Up/Down + Enter select; B back; X/F shortcuts',0
recovery_english: db 'English fallback',0
recovery_refused: db 'Firmware action failed; choose another option',0
align 8
recovery_var_size: dq 8
recovery_indications: dq 0
recovery_var_attributes: dd 0
recovery_global_guid: dd 0x8be4df61
                     dw 0x93ca,0x11d2
                     db 0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c
recovery_supported_name: dw 'O','s','I','n','d','i','c','a','t','i','o','n','s','S','u','p','p','o','r','t','e','d',0
recovery_indications_name: dw 'O','s','I','n','d','i','c','a','t','i','o','n','s',0
%endmacro
