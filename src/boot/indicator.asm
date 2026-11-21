;; MODULE boot/indicator
;; LAYER 0
;; EXPORTS boot_indicator_bind, boot_indicator_tick
;; IMPORTS boot/gop, boot/boot_menu, boot/firmware_logo_draw
;; CAPS
;; OWNER saga:boot
; Normal boot's time-driven dots. BSP-only: bind before timer_init, then call
; tick only inside the PIC/BSP LAPIC interrupt's saved-register frame. Neither
; entry waits, allocates, calls firmware, changes modes or publishes health.
; The face_owner=2 retirement precedes every GUI/CLI scanout write: the CLI and
; lab paths retire at presentation selection (header); a public GUI boot retires
; at its first scanout write or scanout identity change (gui/window, lock
; release; T6-1 R6). Bind snapshots one low identity-mapped GOP allocation. Tick
; refuses a changed scanout mode/size/format, invalid/backwards clocks and
; post-retirement work before stores.
; Lab builds retain their existing milestone text and do not enable this painter.
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
BI_WIDTH equ 56
BI_HEIGHT equ 8
BI_MAX_PIXELS equ 16777216
BI_PHASE_MS equ 125

boot_indicator_bind:
%if !PAOS_PUBLICITY_LAB_PROFILE
    cmp  byte [rel bm_face_owner], 1
    jne  .out
    cmp  byte [rel bi_ready], 0
    jne  .out                         ; immutable once published
    mov  r8, [rel fb_base]
    test r8, r8
    jz   .out
    test r8b, 3
    jnz  .out
    cmp  dword [rel fb_bpp], 32
    jne  .out
    cmp  dword [rel fb_pixel_format], 1
    ja   .out
    mov  r9d, [rel fb_width]
    cmp  r9d, BI_WIDTH
    jb   .out
    mov  r10d, [rel fb_height]
    cmp  r10d, BI_HEIGHT
    jb   .out
    mov  r11d, [rel fb_stride]
    cmp  r11d, r9d
    jb   .out
    mov  eax, r10d
    imul rax, r11                     ; uint32 product fits uint64
    cmp  rax, BI_MAX_PIXELS
    ja   .out
    shl  rax, 2
    cmp  rax, [rel fb_size]
    ja   .out
    mov  rcx, [rel fb_size]
    add  rcx, r8
    jc   .out
    mov  rdx, 0x0000800000000000
    cmp  rcx, rdx
    ja   .out
    lea  rax, [rel bi_state_start]
    lea  rdx, [rel bi_state_end]
    cmp  r8, rdx
    jae  .disjoint
    cmp  rax, rcx
    jb   .out                         ; never paint into our own state
.disjoint:
    mov  [rel bi_base], r8
    mov  [rel bi_width], r9d
    mov  [rel bi_height], r10d
    mov  [rel bi_stride], r11d
    mov  rax, [rel fb_size]
    mov  [rel bi_size], rax
    mov  eax, [rel fb_pixel_format]
    mov  [rel bi_format], eax
    sub  r9d, BI_WIDTH
    shr  r9d, 1
    mov  [rel bi_x], r9d
    sub  r10d, BI_HEIGHT
    shr  r10d, 1
    cmp  dword [rel firmware_logo_drawn], 1
    jne  .y
    mov  eax, [rel firmware_logo_line_y]
    add  rax, BI_HEIGHT
    mov  ecx, [rel fb_height]
    cmp  rax, rcx
    ja   .out
    mov  r10d, [rel firmware_logo_line_y]
.y:
    mov  [rel bi_y], r10d
    mov  byte [rel bi_ready], 1        ; timer remains disabled at this boundary
.out:
%endif
    ret

; RDI=raw BSP TSC, RSI=ticks/ms. ABI callee-saved registers preserved.
; No timestamp is promoted to a readiness or clock-calibration claim. A changed
; supplied rate skips this tick instead of inventing an interval.
boot_indicator_tick:
%if !PAOS_PUBLICITY_LAB_PROFILE
    cmp  byte [rel bm_face_owner], 1
    jne  .out
    cmp  byte [rel bi_ready], 1
    jne  .out
    mov  rax, [rel bi_size]
    cmp  rax, [rel fb_size]
    jne  .out
    ; T6-1 R6: a public GUI boot keeps the face on the scanout through the GUI
    ; floor, so fb_base may now name the private back buffer (gui/window attach)
    ; or read 0 (parked, T5-9). The scanout itself is the bound snapshot until
    ; bm_face_retire, which every scanout writer/identity change calls first.
    ; The scanout mode is still checked in each legal state: 2x compose keeps it
    ; in fb_out_*, a parked surface reads 0, otherwise fb_* is the scanout mode.
    cmp  byte [rel fb_scale], 2
    jne  .unscaled
    mov  eax, [rel bi_width]
    cmp  eax, [rel fb_out_width]
    jne  .out
    mov  eax, [rel bi_height]
    cmp  eax, [rel fb_out_height]
    jne  .out
    mov  eax, [rel bi_stride]
    cmp  eax, [rel fb_out_stride]
    jne  .out
    jmp  .mode_ok
.unscaled:
    cmp  qword [rel fb_base], 0
    je   .mode_ok                     ; parked: only the snapshot remains
    mov  eax, [rel bi_width]
    cmp  eax, [rel fb_width]
    jne  .out
    mov  eax, [rel bi_height]
    cmp  eax, [rel fb_height]
    jne  .out
    mov  eax, [rel bi_stride]
    cmp  eax, [rel fb_stride]
    jne  .out
.mode_ok:
    mov  eax, [rel bi_format]
    cmp  eax, [rel fb_pixel_format]
    jne  .out
    cmp  dword [rel fb_bpp], 32
    jne  .out
    test rsi, rsi
    jz   .out
    mov  rax, rsi
    mov  ecx, BI_PHASE_MS
    mul  rcx
    test rdx, rdx
    jnz  .out
    mov  rcx, rax                     ; safe, nonzero phase interval
    cmp  byte [rel bi_started], 0
    jne  .elapsed
    mov  [rel bi_rate], rsi
    mov  [rel bi_origin], rdi
    mov  [rel bi_last], rdi
    mov  byte [rel bi_started], 1
    xor  eax, eax
    jmp  .paint
.elapsed:
    cmp  rsi, [rel bi_rate]
    jne  .out
    cmp  rdi, [rel bi_last]
    jb   .out
    mov  rax, rdi
    sub  rax, [rel bi_origin]
    jc   .out
    xor  edx, edx
    div  rcx
    mov  ecx, 3
    xor  edx, edx
    div  rcx
    mov  eax, edx                     ; absolute elapsed phase, no catch-up loop
    cmp  eax, [rel bi_phase]
    je   .out
    mov  [rel bi_last], rdi
.paint:
    mov  [rel bi_phase], eax
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebp, eax
    mov  r12, [rel bi_base]
    mov  r13d, [rel bi_stride]
    shl  r13, 2
    mov  eax, [rel bi_y]
    imul rax, r13
    add  r12, rax
    mov  eax, [rel bi_x]
    lea  r12, [r12 + rax*4]
    xor  r14d, r14d
.row:
    mov  rdi, r12
    mov  ecx, BI_WIDTH
    xor  eax, eax
    cld
    rep  stosd                       ; all56 pixels belong to the admitted strip
    lea  rax, [rel bi_circle]
    movzx ebx, byte [rax + r14]
    xor  r15d, r15d
.dot:
    mov  r10d, 0x00606060
    cmp  r15d, ebp
    jne  .color
    mov  r10d, 0x00ffffff
.color:
    imul eax, r15d, 20
    add  eax, 4
    lea  rdi, [r12 + rax*4]
    xor  ecx, ecx
.column:
    bt   ebx, ecx
    jnc  .next_column
    mov  [rdi + rcx*4], r10d
.next_column:
    inc  ecx
    cmp  ecx, 8
    jb   .column
    inc  r15d
    cmp  r15d, 3
    jb   .dot
    add  r12, r13
    inc  r14d
    cmp  r14d, BI_HEIGHT
    jb   .row
    inc  qword [rel bi_frames]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
.out:
%endif
    ret

bi_circle: db 0x3c,0x7e,0xff,0xff,0xff,0xff,0x7e,0x3c
%include "core/abi/wdata.inc"
%macro WDATA_boot_indicator 0
bi_state_start:
bi_ready: db 0
bi_started: db 0
align 8
bi_base: dq 0
bi_size: dq 0
bi_origin: dq 0
bi_last: dq 0
bi_rate: dq 0
bi_frames: dq 0
bi_width: dd 0
bi_height: dd 0
bi_stride: dd 0
bi_format: dd 0
bi_x: dd 0
bi_y: dd 0
bi_phase: dd 0
bi_state_end:
%endmacro
WDATA_DEFER WDATA_boot_indicator
