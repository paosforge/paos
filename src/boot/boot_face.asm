;; MODULE boot/boot_face
;; LAYER 0
;; EXPORTS boot_face_paint, bf_font, bf_painted, bf_paints, bf_scale, bf_faults
;; IMPORTS boot/gop
;; CAPS
;; OWNER saga:boot
; T6-1 (root 120520): the public loading face renderer. PLACEHOLDER mark and
; neutral palette until Peter accepts the track B design in the VM (root 120449);
; the accepted mark replaces bf_mark and the BF_* colours, nothing else.
;
; One code path on all six machines and the VM (Peter 120442): GOP linear
; framebuffer only, 32 bpp, never Blt, ConOut, allocation, lock, wait or a mode
; change. bm_face_progress_run calls it once, right after gop_query's single
; SetMode, while the face owns the scanout (bm_face_owner=1); bm_face_refresh
; repaints the revalidated surface the same way. Grey levels only, so RGB and
; BGR (UEFI pixel formats 0/1) show the same image.
;
; SEC 120517 B4: the pixel format, the whole extent and each rectangle are
; checked before any store. Every store goes through bf_fill, which refuses a
; rectangle outside the validated width x height. A fault returns EAX=0 having
; stored nothing; the caller keeps today's static face (fault rule, 120442).
; Scale: s = clamp(min(w/800, h/600), 1, 4), integer; every element is centred
; on the real w x h, so any aspect ratio from 800x600 to 4K works.
%ifndef PAOS_VERSION_TEXT
%error "boot/boot_face: PAOS_VERSION_TEXT (build/version-identity.inc) is required"
%endif
BF_MIN_W        equ 800
BF_MIN_H        equ 600
BF_MAX_SCALE    equ 4
BF_MAX_PIXELS   equ 16777216              ; rows*stride ceiling (5K and below)
BF_BG           equ 0x00000000            ; placeholder palette, grey levels only
BF_MARK_FG      equ 0x00d8d8d8
BF_TEXT_FG      equ 0x00a0a0a0
BF_MARK_CELLS   equ 16                    ; bf_mark: 16 rows x 16 cells
BF_MARK_CELL    equ 4                     ; one mark cell = 4*s pixels square
BF_MARK_GAP     equ 24                    ; *s: mark bottom to the centred dots row
BF_TEXT_BOTTOM  equ 48                    ; *s: version glyph top above the bottom edge
BF_DOTS_H       equ 8                     ; boot/indicator BI_HEIGHT (its strip is centred)
BF_TEXT_MAX     equ 32
; The indicator clears its dots strip to 0 before each frame, so the face
; background must stay 0 until R7 gives both one shared background.
%if BF_BG != 0
    %error "boot/boot_face: BF_BG must match boot/indicator's cleared strip (0)"
%endif

; Paint the whole face on the GOP mode in force. Out: EAX=1 painted, 0 refused
; (no store made). ABI callee-saved registers preserved; RCX/RDX/RSI/RDI/R8-R11
; clobbered.
boot_face_paint:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    call bf_validate
    test eax, eax
    jz   .fault
    ; s = clamp(min(w/800, h/600), 1, 4); validation guarantees w>=800, h>=600
    mov  eax, [rel bf_w]
    xor  edx, edx
    mov  ecx, BF_MIN_W
    div  ecx
    mov  ebx, eax
    mov  eax, [rel bf_h]
    xor  edx, edx
    mov  ecx, BF_MIN_H
    div  ecx
    cmp  eax, ebx
    cmovb ebx, eax
    cmp  ebx, BF_MAX_SCALE
    jbe  .scale_ok
    mov  ebx, BF_MAX_SCALE
.scale_ok:
    mov  [rel bf_scale], bl
    ; 1. full-screen background (also covers gop_query's x=0 markers, G1)
    xor  esi, esi
    xor  edx, edx
    mov  ecx, [rel bf_w]
    mov  r8d, [rel bf_h]
    mov  r9d, BF_BG
    call bf_fill
    ; 2. the mark: centred, its bottom BF_MARK_GAP*s above the centred dots row
    imul ebp, ebx, BF_MARK_CELL           ; cell pixels
    imul r12d, ebp, BF_MARK_CELLS         ; mark pixels
    mov  eax, [rel bf_w]
    sub  eax, r12d
    shr  eax, 1
    mov  r13d, eax                        ; mark x
    mov  eax, [rel bf_h]
    sub  eax, BF_DOTS_H
    shr  eax, 1
    imul ecx, ebx, BF_MARK_GAP
    add  ecx, r12d
    sub  eax, ecx                         ; >= 0: h >= 600*s
    mov  r14d, eax                        ; mark y
    xor  r15d, r15d                       ; row
.mark_row:
    lea  rax, [rel bf_mark]
    movzx r11d, word [rax + r15*2]
    xor  r10d, r10d                       ; column, MSB first
.mark_col:
    mov  eax, 0x8000
    mov  ecx, r10d
    shr  eax, cl
    test r11d, eax
    jz   .mark_next
    mov  esi, r10d
    imul esi, ebp
    add  esi, r13d
    mov  edx, r15d
    imul edx, ebp
    add  edx, r14d
    mov  ecx, ebp
    mov  r8d, ebp
    mov  r9d, BF_MARK_FG
    push r10
    push r11
    call bf_fill
    pop  r11
    pop  r10
.mark_next:
    inc  r10d
    cmp  r10d, BF_MARK_CELLS
    jb   .mark_col
    inc  r15d
    cmp  r15d, BF_MARK_CELLS
    jb   .mark_row
    ; 3. the version (PAOS_VERSION_TEXT), centred, 8x16 Spleen cells at s
    lea  rax, [rel bf_version_end]
    lea  rcx, [rel bf_version]
    sub  rax, rcx                         ; characters
    imul eax, ebx
    shl  eax, 3                           ; text width = n*8*s
    cmp  eax, [rel bf_w]
    ja   .done                            ; cannot happen at w>=800 (n<=BF_TEXT_MAX)
    mov  ecx, [rel bf_w]
    sub  ecx, eax
    shr  ecx, 1
    mov  r13d, ecx                        ; cell x
    imul eax, ebx, BF_TEXT_BOTTOM
    mov  r14d, [rel bf_h]
    sub  r14d, eax                        ; text y
    lea  r12, [rel bf_version]
.char:
    lea  rax, [rel bf_version_end]
    cmp  r12, rax
    jae  .done
    movzx eax, byte [r12]
    call bf_glyph
    imul eax, ebx, 8
    add  r13d, eax
    inc  r12
    jmp  .char
.done:
    mov  byte [rel bf_painted], 1
    inc  qword [rel bf_paints]
    mov  eax, 1
    jmp  .out
.fault:
    inc  qword [rel bf_faults]
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EAX=ASCII, R13D=x, R14D=y, EBX=s. Unknown characters stay background.
; Clobbers RAX/RCX/RDX/RSI/RDI/R8-R11; keeps RBX/RBP/R12-R15.
bf_glyph:
    cmp  eax, '+'
    jb   .out
    cmp  eax, '9'
    jbe  .first_run
    cmp  eax, 'a'
    jb   .out
    cmp  eax, 'z'
    ja   .out
    sub  eax, 'a' - ('9' - '+' + 1)
    jmp  .cell
.first_run:
    sub  eax, '+'
.cell:
    shl  eax, 4
    push r15
    push rbp
    push r12
    lea  r12, [rel bf_font]
    add  r12, rax
    xor  r15d, r15d                       ; glyph row
.row:
    movzx ebp, byte [r12 + r15]
    xor  r10d, r10d
.col:
    mov  eax, 0x80
    mov  ecx, r10d
    shr  eax, cl
    test ebp, eax
    jz   .next
    mov  esi, r10d
    imul esi, ebx
    add  esi, r13d
    mov  edx, r15d
    imul edx, ebx
    add  edx, r14d
    mov  ecx, ebx
    mov  r8d, ebx
    mov  r9d, BF_TEXT_FG
    push r10
    sub  rsp, 8
    call bf_fill
    add  rsp, 8
    pop  r10
.next:
    inc  r10d
    cmp  r10d, 8
    jb   .col
    inc  r15d
    cmp  r15d, 16
    jb   .row
    pop  r12
    pop  rbp
    pop  r15
.out:
    ret

; The one store path. ESI=x, EDX=y, ECX=width, R8D=height, R9D=colour.
; Refuses (stores nothing) unless x+width <= w and y+height <= h of the
; validated surface. Clobbers RAX/RCX/RDX/RDI/R8/R11.
bf_fill:
    mov  eax, esi
    add  rax, rcx
    cmp  rax, [rel bf_w_q]
    ja   .refuse
    mov  eax, edx
    add  rax, r8
    cmp  rax, [rel bf_h_q]
    ja   .refuse
    test ecx, ecx
    jz   .out
    test r8d, r8d
    jz   .out
    mov  r11d, ecx
    mov  eax, edx
    imul rax, [rel bf_stride_q]
    mov  edx, esi
    add  rax, rdx
    shl  rax, 2
    add  rax, [rel bf_base]
    mov  rdx, [rel bf_stride_q]
    shl  rdx, 2
.row:
    mov  rdi, rax
    mov  ecx, r11d
    push rax
    mov  eax, r9d
    cld
    rep  stosd
    pop  rax
    add  rax, rdx
    dec  r8d
    jnz  .row
.out:
    ret
.refuse:
    inc  qword [rel bf_rect_refusals]
    ret

; Snapshot and check the GOP surface. EAX=1 admitted, else 0 and nothing kept.
bf_validate:
    mov  r8, [rel fb_base]
    test r8, r8
    jz   .no
    test r8b, 3
    jnz  .no
    cmp  dword [rel fb_bpp], 32
    jne  .no
    cmp  dword [rel fb_pixel_format], 1
    ja   .no                              ; 0 RGBx / 1 BGRx linear only
    mov  r9d, [rel fb_width]
    cmp  r9d, BF_MIN_W
    jb   .no
    mov  r10d, [rel fb_height]
    cmp  r10d, BF_MIN_H
    jb   .no
    mov  r11d, [rel fb_stride]
    cmp  r11d, r9d
    jb   .no
    mov  eax, r10d
    imul rax, r11                         ; uint32*uint32 fits uint64
    cmp  rax, BF_MAX_PIXELS
    ja   .no
    shl  rax, 2
    cmp  rax, [rel fb_size]
    ja   .no                              ; every row lies inside the GOP buffer
    mov  rcx, [rel fb_size]
    add  rcx, r8
    jc   .no
    mov  rdx, 0x0000800000000000
    cmp  rcx, rdx
    ja   .no
    lea  rax, [rel bf_state_start]
    lea  rdx, [rel bf_state_end]
    cmp  r8, rdx
    jae  .disjoint
    cmp  rax, rcx
    jb   .no                              ; never paint into our own state
.disjoint:
    mov  [rel bf_base], r8
    mov  [rel bf_w], r9d
    mov  [rel bf_h], r10d
    mov  [rel bf_w_q], r9
    mov  [rel bf_h_q], r10
    mov  [rel bf_stride_q], r11
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; PLACEHOLDER mark (root 120520): a ring with a centre disc, 16x16 cells, MSB left.
bf_mark:
    dw 0x0ff0,0x3ffc,0x700e,0x6006,0xc003,0xc3c3,0xc7e3,0xc7e3
    dw 0xc7e3,0xc7e3,0xc3c3,0xc003,0x6006,0x700e,0x3ffc,0x0ff0
bf_version: db "v", PAOS_VERSION_TEXT
bf_version_end:
%if bf_version_end - bf_version > BF_TEXT_MAX
    %error "boot/boot_face: version text longer than BF_TEXT_MAX"
%endif

; Spleen 8x16 2.1.0 glyphs, (c) 2018-2024 Frederic Cambus, BSD-2-Clause; see
; THIRD_PARTY_NOTICES.md and third_party/fonts/spleen/. Generated by
; tools/fonts/font_build.py (bootface.inc): U+002B..U+0039 then U+0061..U+007A.
align 16
bf_font:
    db 0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x7e,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00 ; U+002b
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00 ; U+002c
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+002d
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00 ; U+002e
    db 0x00,0x06,0x06,0x0c,0x0c,0x18,0x18,0x30,0x30,0x60,0x60,0xc0,0xc0,0x00,0x00,0x00 ; U+002f
    db 0x00,0x00,0x7c,0xc6,0xc6,0xce,0xde,0xf6,0xe6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0030
    db 0x00,0x00,0x18,0x38,0x78,0x58,0x18,0x18,0x18,0x18,0x18,0x7e,0x00,0x00,0x00,0x00 ; U+0031
    db 0x00,0x00,0x7c,0xc6,0x06,0x06,0x0c,0x18,0x30,0x60,0xc6,0xfe,0x00,0x00,0x00,0x00 ; U+0032
    db 0x00,0x00,0x7c,0xc6,0x06,0x06,0x3c,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0033
    db 0x00,0x00,0xc0,0xc0,0xcc,0xcc,0xcc,0xcc,0xfe,0x0c,0x0c,0x0c,0x00,0x00,0x00,0x00 ; U+0034
    db 0x00,0x00,0xfe,0xc6,0xc0,0xc0,0xfc,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0035
    db 0x00,0x00,0x7c,0xc6,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0036
    db 0x00,0x00,0xfe,0xc6,0x06,0x06,0x0c,0x18,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00 ; U+0037
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0x7c,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0038
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0039
    db 0x00,0x00,0x00,0x00,0x00,0x7c,0x06,0x7e,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0061
    db 0x00,0x00,0xc0,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xfc,0x00,0x00,0x00,0x00 ; U+0062
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc0,0xc0,0xc0,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+0063
    db 0x00,0x00,0x06,0x06,0x06,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0064
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xfe,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+0065
    db 0x00,0x00,0x1e,0x30,0x30,0x30,0x7c,0x30,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00 ; U+0066
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x06,0x06,0xfc,0x00 ; U+0067
    db 0x00,0x00,0xc0,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0068
    db 0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x1c,0x00,0x00,0x00,0x00 ; U+0069
    db 0x00,0x00,0x18,0x18,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x70,0x00 ; U+006a
    db 0x00,0x00,0xc0,0xc0,0xc0,0xcc,0xd8,0xf0,0xf0,0xd8,0xcc,0xc6,0x00,0x00,0x00,0x00 ; U+006b
    db 0x00,0x00,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x1c,0x00,0x00,0x00,0x00 ; U+006c
    db 0x00,0x00,0x00,0x00,0x00,0xec,0xd6,0xd6,0xd6,0xd6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+006d
    db 0x00,0x00,0x00,0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+006e
    db 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+006f
    db 0x00,0x00,0x00,0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xfc,0xc0,0xc0,0xc0,0x00 ; U+0070
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0x06,0x00 ; U+0071
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc0,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00 ; U+0072
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc0,0xc0,0x7c,0x06,0x06,0xfc,0x00,0x00,0x00,0x00 ; U+0073
    db 0x00,0x00,0x30,0x30,0x30,0x7c,0x30,0x30,0x30,0x30,0x30,0x1e,0x00,0x00,0x00,0x00 ; U+0074
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0075
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x10,0x00,0x00,0x00,0x00 ; U+0076
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xd6,0xd6,0xd6,0xd6,0x6e,0x00,0x00,0x00,0x00 ; U+0077
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0x6c,0x38,0x38,0x6c,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0078
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0xfc,0x00 ; U+0079
    db 0x00,0x00,0x00,0x00,0x00,0xfe,0x06,0x0c,0x18,0x30,0x60,0xfe,0x00,0x00,0x00,0x00 ; U+007a

%include "core/abi/wdata.inc"
%macro WDATA_boot_face_render 0
bf_state_start:
bf_painted: db 0
bf_scale: db 0
align 8
bf_base: dq 0
bf_w_q: dq 0
bf_h_q: dq 0
bf_stride_q: dq 0
bf_paints: dq 0
bf_faults: dq 0
bf_rect_refusals: dq 0
bf_w: dd 0
bf_h: dd 0
bf_state_end:
%endmacro
WDATA_DEFER WDATA_boot_face_render
