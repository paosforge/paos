;; MODULE gui/liveness_panel
;; LAYER 6
;; EXPORTS gui_ladder_declare, gui_ladder_out_buf, gui_ladder_out_ready, liveness_panel_draw, liveness_panel_draw_beacon_nonce, liveness_panel_selftest
;; IMPORTS core/lib/crc32, core/lib/mem, boot/serial, boot/beacon, gui/window, svc/command, svc/command_udp
;; CAPS
;; OWNER saga:gui_foundation_ladder
; Task 2100 reserves the GUI ladder vocabulary as honest unsupported skeletons
; and supplies the PLV1 pixel witness.  Replies use one bounded staging buffer;
; command_udp consumes it through the same lean path as WIDGET*/RESINFO.

PLV1_DATA_X       equ 8
PLV1_DATA_Y       equ 8
PLV1_COLUMNS      equ 24
PLV1_ROWS         equ 8
PLV1_MODULE       equ 4
PLV1_RIGHT        equ PLV1_DATA_X + PLV1_COLUMNS * PLV1_MODULE
PLV1_BOTTOM       equ PLV1_DATA_Y + PLV1_ROWS * PLV1_MODULE
PLV1_FRAME_GAP    equ 2
PLV1_QUIET_GAP    equ 4
PLV1_QUIET_X      equ PLV1_DATA_X - PLV1_FRAME_GAP - PLV1_QUIET_GAP
PLV1_QUIET_Y      equ PLV1_DATA_Y - PLV1_FRAME_GAP - PLV1_QUIET_GAP
PLV1_QUIET_W      equ PLV1_RIGHT + PLV1_FRAME_GAP + PLV1_QUIET_GAP - PLV1_QUIET_X
PLV1_QUIET_H      equ PLV1_BOTTOM + PLV1_FRAME_GAP + PLV1_QUIET_GAP - PLV1_QUIET_Y
PLV1_PAYLOAD_LEN  equ 24
PLV1_BODY_LEN     equ 20

%if PLV1_QUIET_X != 2 || PLV1_QUIET_Y != 2 || PLV1_QUIET_W != 108 || PLV1_QUIET_H != 44
    %error "PLV1 quiet-zone geometry drift"
%endif
%if PLV1_RIGHT != 104 || PLV1_BOTTOM != 40 || PLV1_COLUMNS != 24 || PLV1_ROWS != 8
    %error "PLV1 data-matrix geometry drift"
%endif

%macro GUI_LADDER_REGISTER 3
    lea  rdi, [rel %1]
    lea  rsi, [rel %2]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, %3
    call command_register_verb
    or   ebx, eax
%endmacro

; Register once through the canonical registry.  The live cap/destructive
; metadata is consumed by Task2020's central gate; no UDP bypass participates.
gui_ladder_declare:
    push rbx
    xor  ebx, ebx
    GUI_LADDER_REGISTER str_verb_winchrome, cmd_verb_winchrome, 0
    GUI_LADDER_REGISTER str_verb_wintree,   cmd_verb_wintree,   0
    GUI_LADDER_REGISTER str_verb_taskbar,   cmd_verb_taskbar,   0
    GUI_LADDER_REGISTER str_verb_winattn,   cmd_verb_winattn,   1
    GUI_LADDER_REGISTER str_verb_formload,  cmd_verb_formload,  1
    GUI_LADDER_REGISTER str_verb_formlist,  cmd_verb_formlist,  0
    GUI_LADDER_REGISTER str_verb_forminfo,  cmd_verb_forminfo,  0
    GUI_LADDER_REGISTER str_verb_liveness,  cmd_verb_liveness,  1
    GUI_LADDER_REGISTER str_verb_cadence,   cmd_verb_cadence,   0
    test ebx, ebx
    js   .fail
    lea  rdi, [rel str_ladder_registered]
    call serial_string
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_ladder_register_fail]
    call serial_string
    pop  rbx
    ret

cmd_verb_winchrome:
    lea  rdx, [rel str_unsup_winchrome]
    jmp  gui_ladder_unsupported
cmd_verb_wintree:
    lea  rdx, [rel str_unsup_wintree]
    jmp  gui_ladder_unsupported
cmd_verb_taskbar:
    lea  rdx, [rel str_unsup_taskbar]
    jmp  gui_ladder_unsupported
cmd_verb_winattn:
    lea  rdx, [rel str_unsup_winattn]
    jmp  gui_ladder_unsupported
cmd_verb_formload:
    lea  rdx, [rel str_unsup_formload]
    jmp  gui_ladder_unsupported
cmd_verb_formlist:
    lea  rdx, [rel str_unsup_formlist]
    jmp  gui_ladder_unsupported
cmd_verb_forminfo:
    lea  rdx, [rel str_unsup_forminfo]
    jmp  gui_ladder_unsupported
cmd_verb_cadence:
    lea  rdx, [rel str_unsup_cadence]
    jmp  gui_ladder_unsupported

; Common bounded skeleton body. RDX points at one fixed reply string.
gui_ladder_unsupported:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx                       ; keep the selected fixed reply across calls
    call cmd_handler_prologue
    call gui_ladder_out_reset
    mov  rdi, r14
    call gui_ladder_put_str
    mov  byte [rel gui_ladder_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r14
    pop  r13
    pop  r12
    ret

; LIVENESS <32 hex>. Validation completes before any framebuffer call, so every
; malformed path has exactly zero pixel effects.  The 1094 badge overlaps the
; fixed PLV1 coordinates; it is dismissed only after its wire leg is marked,
; then the panel is painted into the now-settled desktop region.
cmd_verb_liveness:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad_nonce
    call liveness_parse_nonce
    test eax, eax
    jz   .bad_nonce
    cmp  byte [rel udp_beacon_dismissed], 1
    je   .draw
    cmp  byte [rel udp_beacon_marked], 1
    jne  .beacon_active
    mov  byte [rel udp_beacon_dismissed], 1
    call beacon_gop_dismiss
.draw:
    lea  rdi, [rel liveness_nonce_bin]
    call liveness_panel_draw
    test eax, eax
    jz   .no_framebuffer
    call gui_ladder_out_reset
    lea  rdi, [rel str_liveness_ok]
    call gui_ladder_put_str
    mov  rdi, [r12 + REQ_ARG]
    call gui_ladder_put_str
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.bad_nonce:
    call gui_ladder_out_reset
    lea  rdi, [rel str_liveness_bad]
    call gui_ladder_put_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .ready
.beacon_active:
    call gui_ladder_out_reset
    lea  rdi, [rel str_liveness_beacon]
    call gui_ladder_put_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .ready
.no_framebuffer:
    call gui_ladder_out_reset
    lea  rdi, [rel str_liveness_nofb]
    call gui_ladder_put_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.ready:
    mov  byte [rel gui_ladder_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    pop  r13
    pop  r12
    ret

; Parse exactly 32 hexadecimal characters into liveness_nonce_bin.
liveness_parse_nonce:
    xor  ecx, ecx
.byte:
    mov  al, [rdi + rcx*2]
    call liveness_hex_nibble
    jc   .bad
    shl  al, 4
    mov  dl, al
    mov  al, [rdi + rcx*2 + 1]
    call liveness_hex_nibble
    jc   .bad
    or   al, dl
    lea  r8, [rel liveness_nonce_bin]
    mov  [r8 + rcx], al
    inc  ecx
    cmp  ecx, 16
    jb   .byte
    cmp  byte [rdi + 32], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

liveness_hex_nibble:
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    clc
    ret
.digit:
    sub  al, '0'
    clc
    ret
.bad:
    stc
    ret

; Build bytes "PLV1" + nonce[16] + crc32(body)[4, big endian].
liveness_build_payload:
    lea  rax, [rel liveness_payload]
    mov  dword [rax], 'PLV1'
    mov  rcx, [rdi]
    mov  [rax + 4], rcx
    mov  rcx, [rdi + 8]
    mov  [rax + 12], rcx
    mov  rdi, rax
    mov  esi, PLV1_BODY_LEN
    call hotpatch_crc32
    bswap eax
    mov  [rel liveness_payload + PLV1_BODY_LEN], eax
    ret

; Draw the reference rectangle sequence using only fb_fill_rect.
; RDI=16-byte nonce, RAX=1 drawn / 0 no suitable framebuffer.
liveness_panel_draw_beacon_nonce:
    ; Task2302 boot wrapper: the wire beacon is a numeric 32-bit value printed
    ; as eight big-endian hex digits. Expand it to the final four bytes of the
    ; 16-byte PLV1 nonce (zero-pad left), then reuse the shipped renderer below.
    lea  rdi, [rel liveness_nonce_bin]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  eax, [rel boot_nonce]
    bswap eax
    mov  [rdi + 12], eax
    jmp  liveness_panel_draw

liveness_panel_draw:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .no
    cmp  dword [rel fb_width], PLV1_QUIET_X + PLV1_QUIET_W
    jb   .no
    cmp  dword [rel fb_height], PLV1_QUIET_Y + PLV1_QUIET_H
    jb   .no
    call liveness_build_payload

    mov  r8d, PLV1_QUIET_X
    mov  r9d, PLV1_QUIET_Y
    mov  r10d, PLV1_QUIET_W
    mov  r11d, PLV1_QUIET_H
    xor  ebx, ebx
    call fb_fill_rect

    mov  r8d, PLV1_DATA_X - PLV1_FRAME_GAP
    mov  r9d, PLV1_DATA_Y - PLV1_FRAME_GAP
    mov  r10d, PLV1_COLUMNS * PLV1_MODULE + PLV1_FRAME_GAP * 2
    mov  r11d, PLV1_ROWS * PLV1_MODULE + PLV1_FRAME_GAP * 2
    mov  ebx, 0x00FFFFFF
    call fb_fill_rect

    mov  r8d, PLV1_DATA_X - 1
    mov  r9d, PLV1_DATA_Y - 1
    mov  r10d, PLV1_COLUMNS * PLV1_MODULE + 2
    mov  r11d, PLV1_ROWS * PLV1_MODULE + 2
    xor  ebx, ebx
    call fb_fill_rect

    xor  r12d, r12d                    ; column
.column:
    lea  rax, [rel liveness_payload]
    movzx r14d, byte [rax + r12]
    mov  r15d, 0x80                    ; MSB is the top module
    xor  r13d, r13d                    ; row
.row:
    xor  ebx, ebx
    test r14b, r15b
    jz   .color
    mov  ebx, 0x00FFFFFF
.color:
    mov  r8d, r12d
    shl  r8d, 2
    add  r8d, PLV1_DATA_X
    mov  r9d, r13d
    shl  r9d, 2
    add  r9d, PLV1_DATA_Y
    mov  r10d, PLV1_MODULE
    mov  r11d, PLV1_MODULE
    call fb_fill_rect
    shr  r15d, 1
    inc  r13d
    cmp  r13d, PLV1_ROWS
    jb   .row
    inc  r12d
    cmp  r12d, PLV1_COLUMNS
    jb   .column
    sfence                              ; publish WC framebuffer stores before reply/capture
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Boot KAT: exact IEEE vector, exact 20-byte PLV1 body copy, big-endian CRC,
; and the same 24-column/MSB-first eight-row walk the painter uses.
liveness_panel_selftest:
    push rbx
    push r12
    push r13
    lea  rdi, [rel liveness_crc_kat]
    mov  esi, 9
    call hotpatch_crc32
    cmp  eax, 0xCBF43926
    jne  .fail
    lea  rdi, [rel liveness_fixed_nonce]
    call liveness_build_payload
    lea  rdi, [rel liveness_payload]
    lea  rsi, [rel liveness_kat_body]
    mov  edx, PLV1_BODY_LEN
    call memcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel liveness_kat_body]
    mov  esi, PLV1_BODY_LEN
    call hotpatch_crc32
    mov  r12d, eax
    mov  eax, [rel liveness_payload + PLV1_BODY_LEN]
    bswap eax
    cmp  eax, r12d
    jne  .fail
    xor  r13d, r13d
.kat_column:
    lea  rax, [rel liveness_payload]
    mov  bl, [rax + r13]
    mov  dl, bl
    xor  al, al
    mov  ecx, PLV1_ROWS
.kat_row:
    shl  al, 1
    test dl, 0x80
    jz   .kat_zero
    or   al, 1
.kat_zero:
    shl  dl, 1
    dec  ecx
    jnz  .kat_row
    cmp  al, bl
    jne  .fail
    inc  r13d
    cmp  r13d, PLV1_COLUMNS
    jb   .kat_column
    lea  rdi, [rel str_liveness_kat_ok]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_liveness_kat_fail]
    call serial_string
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

gui_ladder_out_reset:
    lea  rax, [rel gui_ladder_out_buf]
    mov  [rel gui_ladder_out_cur], rax
    mov  byte [rax], 0
    ret

; All callers append fixed strings or one already-validated 32-byte nonce.
gui_ladder_put_str:
    mov  rsi, [rel gui_ladder_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel gui_ladder_out_cur], rsi
    ret

align 8
gui_ladder_out_cur:   dq 0
gui_ladder_out_ready: db 0
align 8
gui_ladder_out_buf:   times 192 db 0
liveness_nonce_bin:   times 16 db 0
liveness_payload:     times PLV1_PAYLOAD_LEN db 0

str_verb_winchrome: db "WINCHROME", 0
str_verb_wintree:   db "WINTREE", 0
str_verb_taskbar:   db "TASKBAR", 0
str_verb_winattn:   db "WINATTN", 0
str_verb_formload:  db "FORMLOAD", 0
str_verb_formlist:  db "FORMLIST", 0
str_verb_forminfo:  db "FORMINFO", 0
str_verb_liveness:  db "LIVENESS", 0
str_verb_cadence:   db "CADENCE", 0

str_unsup_winchrome: db " WINCHROME=unsupported", 0
str_unsup_wintree:   db " WINTREE=unsupported", 0
str_unsup_taskbar:   db " TASKBAR=unsupported", 0
str_unsup_winattn:   db " WINATTN=unsupported", 0
str_unsup_formload:  db " FORMLOAD=unsupported", 0
str_unsup_formlist:  db " FORMLIST=unsupported", 0
str_unsup_forminfo:  db " FORMINFO=unsupported", 0
str_unsup_cadence:   db " CADENCE=unsupported", 0
str_liveness_ok:     db " liveness=ok nonce=", 0
str_liveness_bad:    db " liveness=ERR bad_nonce", 0
str_liveness_beacon: db " liveness=ERR beacon_active", 0
str_liveness_nofb:   db " liveness=ERR no_framebuffer", 0

liveness_crc_kat:     db "123456789"
liveness_fixed_nonce: db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
liveness_kat_body:    db "PLV1",0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15

str_ladder_registered: db "[PAOS64] M6 gui: ladder verbs WINCHROME/WINTREE/TASKBAR/WINATTN/FORMLOAD/FORMLIST/FORMINFO/LIVENESS registered (skeleton=unsupported) [gui.ladder.verbs.registered]",13,10,0
str_ladder_register_fail: db "[PAOS64] M6 gui: ladder verb registration FAILED",13,10,0
str_liveness_kat_ok: db "[PAOS64] M6 gui: PLV1 liveness panel KAT PASS (crc32 vector + 24x8 module layout byte-exact) [gui.liveness.panel.kat]",13,10,0
str_liveness_kat_fail: db "[PAOS64] M6 gui: PLV1 liveness panel KAT FAIL",13,10,0
