;; MODULE gui/calendar
;; LAYER 6
;; EXPORTS calendar_open, calendar_clock_hit, calendar_rect, calendar_hit, calendar_overlaps, calendar_toggle, calendar_close, calendar_pointer_press, calendar_other_press, calendar_escape, calendar_tick, calendar_layout
;; IMPORTS gui/window, gui/window_mgmt, gui/summon_palette, sec/session, dev/input/ps2, gui/widget_image
;; CAPS
;; OWNER saga:gui
; Read-only month flyout. Wall fields come from the taskbar's one local-time
; conversion; no timer, service, notification store or date-setting action.
CALENDAR_W equ 256
CALENDAR_H equ 240

; Same half-open rectangle as the painted clock. EDI/ESI preserved.
calendar_clock_hit:
    xor  eax, eax
    cmp  qword [rel fb_base], 0
    je   .out
    cmp  dword [rel fb_width], 104
    jl   .out
    cmp  dword [rel fb_height], TASKBAR_H
    jl   .out
    mov  ecx, [rel fb_width]
    sub  ecx, CLOCK_TRAY_XOFF
    cmp  edi, ecx
    jl   .out
    add  ecx, CLOCK_TRAY_W
    cmp  edi, ecx
    jge  .out
    mov  ecx, [rel fb_height]
    sub  ecx, TASKBAR_H - CLOCK_TRAY_YOFF
    cmp  esi, ecx
    jl   .out
    add  ecx, CLOCK_TRAY_H
    cmp  esi, ecx
    jge  .out
    inc  eax
.out:
    ret

; One visibility/geometry predicate for paint, hit and occlusion. No partial
; panel on a small framebuffer; the clock and the panel keep an 8px inset.
calendar_rect:
    xor  eax, eax
    cmp  byte [rel calendar_open], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    cmp  byte [rel summon_palette_open], 0
    jne  .out
    cmp  qword [rel fb_base], 0
    je   .out
    mov  r8d, [rel fb_width]
    sub  r8d, CALENDAR_W + 8
    js   .out
    mov  r9d, [rel fb_height]
    sub  r9d, TASKBAR_H + CALENDAR_H + 8
    js   .out
    mov  r10d, CALENDAR_W
    mov  r11d, CALENDAR_H
    inc  eax
.out:
    ret

; Rectangle overlap (R8/R9 left/top, ECX/EDX right/bottom), exclusive signed
; edges. Like ime_popup_overlaps, preserves all registers except RAX.
calendar_overlaps:
    push r8
    push r9
    push r10
    push r11
    call calendar_rect
    test eax, eax
    jz   .out
    xor  eax, eax
    cmp  ecx, r8d
    jle  .out
    cmp  edx, r9d
    jle  .out
    add  r10d, r8d
    cmp  [rsp + 24], r10d
    jge  .out
    add  r11d, r9d
    cmp  [rsp + 16], r11d
    jge  .out
    inc  eax
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    ret

; EDI/ESI point, preserves everything except RAX.
calendar_hit:
    push rcx
    push rdx
    push r8
    push r9
    mov  r8d, edi
    mov  r9d, esi
    lea  ecx, [rdi + 1]
    lea  edx, [rsi + 1]
    call calendar_overlaps
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    ret

calendar_today:
    call taskbar_read_wall
    cmp  byte [rel clock_wall_valid], 1
    jne  .out
    movzx eax, word [rel clock_year]
    mov  [rel calendar_year], eax
    movzx eax, byte [rel clock_month]
    mov  [rel calendar_month], eax
    mov  eax, [rel clock_day]
    mov  [rel calendar_day_seen], eax
.out:
    ret

calendar_toggle:
    cmp  byte [rel calendar_open], 0
    jne  calendar_close
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    call calendar_today
    cmp  byte [rel clock_wall_valid], 1
    jne  .out
    mov  byte [rel calendar_open], 1
    call calendar_rect
    test eax, eax
    jnz  .draw
    mov  byte [rel calendar_open], 0
    ret
.draw:
    call calendar_layout
    jmp  wmx_draw_all
.out:
    ret

calendar_close:
    cmp  byte [rel calendar_open], 0
    je   .out
    ; Capture the painted footprint before clearing the flag. A locked or
    ; hidden panel is already covered; do not erase the sign-in surface.
    call calendar_rect
    mov  byte [rel calendar_open], 0
    test eax, eax
    jz   .out
    push r8
    push r9
    push r10
    push r11
    call ps2_cursor_hide
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    call wallpaper_paint_rect
    call wmx_draw_all
.out:
    ret

calendar_escape:
calendar_other_press:
    cmp  byte [rel calendar_open], 0
    je   .no
    call calendar_close
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Runs before underlying press handlers. Outside-dismiss consumes that press.
; Inside, only previous/next month and Today act; dates remain read-only.
calendar_pointer_press:
    cmp  byte [rel calendar_open], 0
    je   .no
    call calendar_hit
    test eax, eax
    jz   .close
    call calendar_rect
    sub  edi, r8d
    sub  esi, r9d
    cmp  esi, 32
    jae  .footer
    cmp  edi, 32
    jb   .previous
    cmp  edi, CALENDAR_W - 32
    jae  .next
    jmp  .yes
.footer:
    cmp  esi, CALENDAR_H - 24
    jb   .yes
    call calendar_today
    jmp  .redraw
.previous:
    cmp  dword [rel calendar_month], 1
    jne  .decrement
    cmp  dword [rel calendar_year], 1970
    jbe  .yes
    dec  dword [rel calendar_year]
    mov  dword [rel calendar_month], 13
.decrement:
    dec  dword [rel calendar_month]
    jmp  .redraw
.next:
    cmp  dword [rel calendar_month], 12
    jne  .increment
    cmp  dword [rel calendar_year], 9999
    jae  .yes
    inc  dword [rel calendar_year]
    mov  dword [rel calendar_month], 0
.increment:
    inc  dword [rel calendar_month]
.redraw:
    call calendar_layout
    call wmx_draw_all
.yes:
    mov  eax, 1
    ret
.close:
    call calendar_close
    jmp  .yes
.no:
    xor  eax, eax
    ret

; Existing clock cadence calls after reading local wall. Repaint only on a
; day change; preserves a browsed month and moves today's marker at midnight.
calendar_tick:
    cmp  byte [rel calendar_open], 1
    jne  .out
    mov  eax, [rel clock_day]
    cmp  eax, [rel calendar_day_seen]
    je   .out
    mov  [rel calendar_day_seen], eax
    jmp  wmx_draw_all
.out:
    ret

; Gregorian month layout, Sunday first. No dependency on the host date or
; on clock_day for browsed months. Bounded to 11 month additions, 1970..9999.
calendar_layout:
    mov  r8d, [rel calendar_year]
    lea  eax, [r8 - 1]
    imul r9d, eax, 365
    mov  r10d, eax
    shr  eax, 2
    add  r9d, eax
    mov  eax, r10d
    xor  edx, edx
    mov  ecx, 100
    div  ecx
    sub  r9d, eax
    mov  eax, r10d
    xor  edx, edx
    mov  ecx, 400
    div  ecx
    add  r9d, eax
    sub  r9d, 719162                    ; days before 1970-01-01
    xor  r10d, r10d                     ; leap-day increment
    test r8d, 3
    jnz  .months
    mov  eax, r8d
    xor  edx, edx
    mov  ecx, 100
    div  ecx
    test edx, edx
    jnz  .leap
    mov  eax, r8d
    xor  edx, edx
    mov  ecx, 400
    div  ecx
    test edx, edx
    jnz  .months
.leap:
    inc  r10d
.months:
    lea  rsi, [rel clock_month_days]
    xor  ecx, ecx
    mov  r8d, [rel calendar_month]
    dec  r8d
.month:
    movzx eax, byte [rsi + rcx]
    cmp  ecx, 1
    jne  .length
    add  eax, r10d
.length:
    cmp  ecx, r8d
    je   .selected
    add  r9d, eax
    inc  ecx
    jmp  .month
.selected:
    mov  [rel calendar_days], eax
    lea  eax, [r9 + 4]                 ; 1970-01-01 was Thursday
    xor  edx, edx
    mov  ecx, 7
    div  ecx
    mov  [rel calendar_first], edx
    ret

align 4
calendar_year: dd 1970
calendar_month: dd 1
calendar_days: dd 31
calendar_first: dd 4
calendar_day_seen: dd -1
calendar_open: db 0
