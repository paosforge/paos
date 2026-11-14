;; MODULE gui/lock_identity
;; LAYER 6
;; PURPOSE Public login-initial avatar; presentation never authenticates.
;; EXPORTS lock_identity_sync, lock_identity_avatar_draw
;; IMPORTS gui/lock_screen, gui/widget, gui/chat_app
;; CAPS
;; OWNER saga:login_surfaces

; Existing internal login is unchanged. Publish one bounded ASCII initial,
; uppercased, or '?' for an empty/unsupported login. No credential is read.
lock_identity_sync:
    push rdi
    push rsi
    mov  edi, [rel lock_widget_first]
    add  edi, 4
    call wgt_slot_ptr
    movzx eax, byte [rax + WGI_VAL]
    cmp  al, 'a'
    jb   .upper
    cmp  al, 'z'
    ja   .upper
    sub  al, 'a' - 'A'
.upper:
    cmp  al, 'A'
    jb   .digit
    cmp  al, 'Z'
    jbe  .publish
.digit:
    cmp  al, '0'
    jb   .unknown
    cmp  al, '9'
    jbe  .publish
.unknown:
    mov  al, '?'
.publish:
    mov  [rel lock_identity_initial], al
    mov  edi, [rel lock_widget_first]
    add  edi, 10
    lea  rsi, [rel lock_identity_initial]
    call wgt_set_text
    pop  rsi
    pop  rdi
    ret

; Text callback ABI: R12 row, RDI escaped text. Only the exact avatar row
; with its current one-character public initial is admitted. Runtime text,
; another host/row or another size retains the ordinary escaped label path.
; Return EAX 1 handled / 0 ordinary, preserve all other registers.
lock_identity_avatar_draw:
    push rbx
    push rbp
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r13
    push r14
    push r15
    mov  eax, [rel lock_widget_first]
    add  eax, 10
    imul rax, rax, WGI_SZ
    lea  rdx, [rel wgt_tbl]
    add  rax, rdx
    cmp  rax, r12
    jne  .ordinary
    cmp  dword [r12 + WGI_WIN], LOCK_SLOT
    jne  .ordinary
    cmp  dword [r12 + WGI_W], 88
    jne  .ordinary
    cmp  dword [r12 + WGI_H], 88
    jne  .ordinary
    mov  al, [rel lock_identity_initial]
    cmp  al, [rdi]
    jne  .ordinary
    cmp  byte [rdi + 1], 0
    jne  .ordinary
    xor  r15d, r15d
.row:
    lea  eax, [r15*2 - 87]
    imul eax, eax
    mov  ebp, eax
    xor  r14d, r14d
.outer:
    lea  eax, [r14*2 - 87]
    imul eax, eax
    add  eax, ebp
    cmp  eax, 88*88
    jbe  .outline
    inc  r14d
    cmp  r14d, 44
    jb   .outer
    jmp  .next_row
.outline:
    mov  ebx, 0x00EAF5F7
    call .span
.inner:
    lea  eax, [r14*2 - 87]
    imul eax, eax
    add  eax, ebp
    cmp  eax, 84*84
    jbe  .body
    inc  r14d
    cmp  r14d, 44
    jb   .inner
    jmp  .next_row
.body:
    mov  ebx, 0x001C7187
    call .span
.next_row:
    inc  r15d
    cmp  r15d, 88
    jb   .row
    ; Enlarge one admitted public initial from the existing native font.
    ; Only set bits paint; the circle remains visible behind the glyph.
    movzx eax, byte [rel lock_identity_initial]
    shl  eax, 4
    lea  r13, [rel font_8x16]
    add  r13, rax
    xor  r15d, r15d
.glyph_row:
    movzx ebp, byte [r13 + r15]
    xor  r14d, r14d
.glyph_bit:
    test ebp, 0x80
    jz   .glyph_next
    lea  r8d, [r14d + r14d*2 + 32]
    add  r8d, [r12 + WGI_X]
    lea  r9d, [r15d + r15d*2 + 20]
    add  r9d, [r12 + WGI_Y]
    mov  r10d, 3
    mov  r11d, 3
    mov  ebx, 0x00EAF5F7
    call wgt_fill_rect
.glyph_next:
    shl  ebp, 1
    inc  r14d
    cmp  r14d, 8
    jb   .glyph_bit
    inc  r15d
    cmp  r15d, 16
    jb   .glyph_row
    mov  eax, 1
    jmp  .out
.ordinary:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rbp
    pop  rbx
    ret
.span:
    mov  r8d, [r12 + WGI_X]
    add  r8d, r14d
    mov  r9d, [r12 + WGI_Y]
    add  r9d, r15d
    mov  r10d, 44
    sub  r10d, r14d
    shl  r10d, 1
    mov  r11d, 1
    jmp  wgt_fill_rect

%macro WDATA_gui_lock_identity_0 0
lock_identity_initial: db '?',0
%endmacro
WDATA_DEFER WDATA_gui_lock_identity_0
