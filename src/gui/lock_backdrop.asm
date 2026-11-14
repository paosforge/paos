;; MODULE gui/lock_backdrop
;; LAYER 6
;; PURPOSE Local photograph shadow for primary sign-in; contained expanded states.
;; EXPORTS lock_backdrop_register, lock_backdrop_draw, lock_card_contrast_set
;; IMPORTS gui/lock_screen, gui/widget, gui/widget_containers, boot/gop, sec/principal
;; CAPS
;; OWNER saga:login_surfaces

; Replace only the lock form's backing row through the ordinary type table.
; All existing widget indices, hit/focus paths and authentication stay intact.
lock_backdrop_register:
    lea  rdi, [rel str_lock_backdrop_type]
    lea  rsi, [rel lock_backdrop_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_label_set]
    lea  r8, [rel wgt_label_get]
    mov  r9, (286 << 32) | 360
    call wgt_type_register
    cmp  eax, -1
    je   .out
    push rax
    mov  edi, [rel lock_widget_first]
    inc  edi
    call wgt_slot_ptr
    pop  rcx
    mov  rdx, rax
    mov  eax, ecx
    inc  ecx                            ; WGI_TYPE is the registry index + 1
    mov  [rdx + WGI_TYPE], ecx
.out:
    ret

; Presentation backend for the accessibility control. Nonzero requests a
; contained high-contrast backing; no credential, session or submit state.
; The caller requests the normal full lock repaint after changing this value.
lock_card_contrast_set:
    test edi, edi
    setnz byte [rel lock_card_contrast]
    ret

lock_backdrop_contained:
    mov  eax, 1
    cmp  byte [rel lock_card_contrast], 0
    jne  .out
    cmp  byte [rel lock_card_help], 0
    jne  .out
    cmp  byte [rel lock_setup_staged], 0
    jne  .out
    ; The existing principal service returns 1 while first-owner setup is due.
    call principal_first_owner_available
.out:
    ret

; Ordinary widget draw ABI. Wallpaper precedes this row in each composition;
; secret/button partial repaints never run the shadow again. Work is bounded
; to the admitted logical 360x286 row; fb_present retains the normal 2x path.
lock_backdrop_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    call lock_backdrop_contained
    pop  rdi
    test eax, eax
    jnz  .panel
    call wgt_slot_ptr
    mov  r12, rax
    cmp  dword [r12 + WGI_W], 360
    jne  .out
    cmp  dword [r12 + WGI_H], 286
    jne  .out
    mov  r13, [rel fb_base]
    test r13, r13
    jz   .out
    mov  eax, [r12 + WGI_X]
    test eax, eax
    js   .out
    add  eax, 360
    cmp  eax, [rel fb_width]
    ja   .out
    mov  eax, [r12 + WGI_Y]
    test eax, eax
    js   .out
    add  eax, 286
    cmp  eax, [rel fb_height]
    ja   .out
    mov  eax, [rel fb_stride]
    cmp  eax, [rel fb_width]
    jb   .out
    mov  r14d, eax
    shl  r14, 2
    mov  eax, [r12 + WGI_Y]
    imul rax, r14
    add  r13, rax
    mov  eax, [r12 + WGI_X]
    lea  r13, [r13 + rax*4]
    xor  r15d, r15d
.row:
    ; Squared normalized radius: x/180 and y/143 in signed 8-bit fraction.
    mov  eax, r15d
    sub  eax, 143
    shl  eax, 8
    cdq
    mov  ecx, 143
    idiv ecx
    imul eax, eax
    mov  ebp, eax
    xor  ebx, ebx
.pixel:
    mov  eax, ebx
    sub  eax, 180
    shl  eax, 8
    cdq
    mov  ecx, 180
    idiv ecx
    imul eax, eax
    add  eax, ebp
    cmp  eax, 65536
    jae  .next
    ; Smooth radial falloff: retain 96/256 at the centre and exactly the
    ; original photograph outside the ellipse. Preserve GOP's reserved byte.
    imul eax, eax, 160
    shr  eax, 16
    lea  ecx, [rax + 96]
    mov  esi, [r13 + rbx*4]
    mov  eax, esi
    and  eax, 0x00FF00FF
    imul eax, ecx
    shr  eax, 8
    and  eax, 0x00FF00FF
    mov  edx, esi
    and  edx, 0x0000FF00
    imul edx, ecx
    shr  edx, 8
    and  edx, 0x0000FF00
    or   eax, edx
    and  esi, 0xFF000000
    or   eax, esi
    mov  [r13 + rbx*4], eax
.next:
    inc  ebx
    cmp  ebx, 360
    jb   .pixel
    add  r13, r14
    inc  r15d
    cmp  r15d, 286
    jb   .row
    jmp  .out
.panel:
    call wgt_container_draw
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

str_lock_backdrop_type: db "lock_backdrop",0
; Candidate-bound renderer identity for the native screenshot oracle.
str_lock_backdrop_abi: db "lock.backdrop.float.v1",0
%macro WDATA_gui_lock_backdrop_0 0
lock_card_contrast: db 0
%endmacro
WDATA_DEFER WDATA_gui_lock_backdrop_0
