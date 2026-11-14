;; MODULE gui/window_mgmt
;; LAYER 6
;; EXPORTS wmx_tray_notice_paint, wmx_owner_reset_op, wmx_selftest, wm_owner, wmx_owner_open, wmx_owner_clear, wmx_native_bind, wmx_native_arena, wmx_native_dispatch, wmx_native_restart, wm_native_slot, wm_native_stuck, wmx_native_leaked, wmx_principal_may_act, wmx_req_may_act, wmx_frame_may_focus, wmx_stage_locked, wmx_stage_denied, wm_app_title, wmx_label_ptr, wmx_caption_hover, wmx_caption_part_at, wm_chrome, wmx_declare, wmx_move_tsc_last, wmx_move_tsc_max, wmx_draw_tsc, wmx_erase_tsc, wmx_clear_boot_marks, wmx_clear_boot_marks_force, wmx_top_visible_slot, wmx_zstamp_top, wmx_set_geom_slot, wmx_draw_defer_begin, wmx_draw_defer_end, wmx_draw_flush_deferred, wmx_paint_top_slot, wm_gen, wm_no_history, wmx_window_id, wmx_set_no_history, wmx_history_target
;; IMPORTS gui/calendar, core/native_app, gui/guest_desktop, gui/wifi_local, boot/serial, boot/gop, gui/window, gui/widget, gui/widget_tabstrip, gui/widget_console_grid, gui/chat_app, gui/cadence_mark, gui/widget_image, gui/image_viewer, svc/command, dev/input/ps2, gui/lock_screen, sec/session, svc/history
;; CAPS
;; OWNER saga:gui

; 2122: all WM and session-restore callers use this shared erasure seam.
; Restore only the vacated rectangle; the caller paints surviving windows on top.
wm_erase_slot:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    ; Lift the direct-mode sprite BEFORE replacing its saved background.
    ; wmx_draw_all will show it after composition. The shadow path is a no-op.
    call ps2_cursor_hide
    mov  edi, [rsp + 32]               ; saved slot, before hide's caller clobbers
    call wmx_erase_overlays
    mov  edi, [rsp + 32]
    mov  eax, edi
    lea  rcx, [rel wm_x]
    mov  r8d, [rcx + rax*4]
    lea  rcx, [rel wm_y]
    mov  r9d, [rcx + rax*4]
    lea  rcx, [rel wm_w]
    mov  r10d, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    mov  r11d, [rcx + rax*4]
    movzx eax, word [rel cadence_region_current]
    push rax
    mov  [rel cadence_region_current], di
    call wallpaper_paint_rect
    pop  rax
    mov  [rel cadence_region_current], ax
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret
; ============================================================================
; gui/window_mgmt.asm — C-1064 desktop_window_mgmt: window management over the
; C16 compositor floor + C17 window TABLE. Adds the WM-geometry verbs the probe
; content-grades: RAISE (z-order), WINNEW/WINMOVE/WINRESIZE/WINGEOM (geometry),
; ALTTAB/FOCUSED (focus cycling). REUSES the C17 16→8-slot wm_* table + the
; chat staged-reply buffer (chat_out_buf/chat_out_ready) — no WM-core rewrite.
;
; What this proves (the SEAM, §3.11 grade-behavior-not-latch, NOT a marker latch):
;   1. MULTI-WINDOW: the compositor draws 2+ windows with z-order.
;   2. Z-ORDER: RAISE brings a window to the FRONT — a nonce-titled window raised
;      over a covering one becomes VISIBLE (bare-metal GLKVM frame OCRs the nonce
;      off the raised titlebar; the title text is drawn 2x black-on-white for a
;      legible capture). Boot self-check verifies wm_focus actually moved.
;   3. MOVE/RESIZE: WINGEOM read-back reflects the COMMANDED x/y/w/h (the geometry
;      really changed) — off-screen commands are CLAMPED (bounded, no crash).
;   4. ALT-TAB: focus cycles to the next visible window (wrap-around).
;
; The four earned markers (BOOTLOG-gated in command_udp.asm; each rides ONLY once
; wmx_selftest set its flag this boot — earned, no latch):
;   wm.multi_window   compositor has >=2 visible windows this boot
;   wm.zorder.raise   a raise moved wm_focus to the raised slot (verified)
;   wm.move_resize    a move+resize changed wm_x/wm_w to the commanded values
;   wm.alttab         an alt-tab cycled wm_focus to a different visible window
;
; A/B (slots 0,1) keep the C16 no-text paint EXACTLY (verify_gui samples their
; title bars at A(150,130)/B(380,225) — LOAD-BEARING); only NEW windows (slots
; >=3) and the chat tile draw title text, so the QEMU regression stays green.
; ============================================================================

WMX_TITLE_MAX equ 40                   ; per-slot title buffer (new windows)
WMX_TITLE_DISP_MAX equ 64              ; B3: painted-title scratch (wmx_title_display)
WMX_MIN_W     equ 80                   ; clamp floor: never a zero-area window
WMX_MIN_H     equ 60
; B4 (2026-09-30, usage suite CHR-08): the floor a USER resize drag honours. The
; three caption buttons (+ frame) and a 20 px title grab always fit, and the body
; keeps a usable height. Forms raise it with their declared min_w/min_h
; (wm_min_w/wm_min_h, set by form_load_index); verbs keep the WMX_MIN_* clamp.
WMX_USER_MIN_W equ GUI_CHROME_BUTTON_W * 3 + GUI_CHROME_BUTTON_GAP * 2 + GUI_CHROME_BUTTON_RIGHT + 21
WMX_USER_MIN_H equ GUI_TITLE_H + 60

; Verification panels use the same sanctioned L2 fill seam; no app or verb
; module gains a private primitive call site.
wmx_liveness_fill_rect:
    call fb_fill_rect
    ret
; ---------------------------------------------------------------------------
; wmx_draw_char_2x — render one 8x16 glyph at 2x (16x32) into the framebuffer.
;   r8d=x, r9d=y, edx=ascii, ebx=fg, ecx=bg. Each source pixel = a 2x2 block.
;   Preserves r8d/r9d/edx (chainable). Clips whole-cell if it crosses the edge.
; ---------------------------------------------------------------------------
wmx_draw_char_2x:
    push rax
    push rsi
    push rdi
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rcx
    push rbx
    mov  r14d, ebx                      ; fg
    mov  r15d, ecx                      ; bg
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done
    mov  eax, r8d
    add  eax, 16
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, 32
    cmp  eax, [rel fb_height]
    ja   .done
    movzx eax, dl
    shl  eax, 4
    lea  rsi, [rel font_8x16]
    add  rsi, rax                       ; rsi -> glyph rows
    xor  r10d, r10d                     ; sr = source row 0..15
.srow:
    cmp  r10d, 16
    jae  .done
    movzx r11d, byte [rsi + r10]        ; row bits, MSB = leftmost
    mov  r12d, r10d
    shl  r12d, 1
    add  r12d, r9d                      ; oy = y + sr*2
    xor  r13d, r13d                     ; bit = 0..7
.bit:
    cmp  r13d, 8
    jae  .nsrow
    mov  ebx, r15d                      ; default bg
    mov  eax, r11d
    mov  ecx, r13d
    shl  eax, cl                        ; MSB-first: after <<bit, test 0x80
    test al, 0x80
    jz   .havecolor
    mov  ebx, r14d                      ; fg
.havecolor:
    mov  edi, r13d
    shl  edi, 1
    add  edi, r8d                       ; ox = x + bit*2
    mov  eax, [rel fb_stride]
    imul eax, r12d
    add  eax, edi
    mov  rcx, [rel fb_base]
    lea  rcx, [rcx + rax*4]             ; &fb[oy*stride + ox]
    mov  [rcx], ebx
    mov  [rcx + 4], ebx                 ; (ox+1, oy)
    mov  eax, [rel fb_stride]
    lea  rcx, [rcx + rax*4]             ; down one row -> oy+1
    mov  [rcx], ebx
    mov  [rcx + 4], ebx                 ; (ox+1, oy+1)
    inc  r13d
    jmp  .bit
.nsrow:
    inc  r10d
    jmp  .srow
.done:
    mov  r10d, 16                       ; 2026-09-08: note the 2x cell for the back buffer present
    mov  r11d, 32
    call fb_damage_rect
    pop  rbx
    pop  rcx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  rdi
    pop  rsi
    pop  rax
    ret

; wmx_draw_str_2x — draw a NUL-terminated string at 2x, at most r11d chars.
;   rdi=cstr, r8d=x, r9d=y, ebx=fg, ecx=bg, r11d=max chars. x advances by 16/char.
wmx_draw_str_2x:
    cmp  byte [rel cadence_mark_level], 0
    jne  .cad_scan
    inc  dword [rel cadence_dropped]
    jmp  .cad_done
.cad_scan:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r10
    push r11
    xor  r10d, r10d
.cad_len:
    cmp  r10d, r11d
    jae  .cad_have_len
    cmp  byte [rdi + r10], 0
    je   .cad_have_len
    inc  r10d
    jmp  .cad_len
.cad_have_len:
    test r10d, r10d
    jz   .cad_restore
    movzx edi, word [rel cadence_region_current]
    mov  esi, CADE_DRAW
    mov  edx, r8d
    mov  eax, r9d
    shl  eax, 16
    or   edx, eax
    mov  ecx, r10d
    shl  ecx, 4                        ; 16 pixels per 2x glyph
    mov  eax, 32
    shl  eax, 16
    or   ecx, eax
    call cadence_mark
.cad_restore:
    pop  r11
    pop  r10
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  rax
.cad_done:
    push rdx
    push r11
    push r12
    mov  r12, rdi
.next:
    test r11d, r11d
    jz   .done
    movzx edx, byte [r12]
    test dl, dl
    jz   .done
    call wmx_draw_char_2x
    add  r8d, 16
    inc  r12
    dec  r11d
    jmp  .next
.done:
    pop  r12
    pop  r11
    pop  rdx
    ret

; ---------------------------------------------------------------------------
; wmx_paint_slot(edi=slot) — the ONE standard-chrome painter for all eight
; slots. Every color comes from theme_tokens.inc. Geometry is shared with
; WINCHROME and wm_pointer_event: border, title, min, max, close.
; ---------------------------------------------------------------------------
wmx_paint_slot:
    ; A fullscreen form has no movable/closable chrome. Its stock image and
    ; widget tree own every pixel; no private lock-screen painter exists.
    cmp  byte [rel lock_surface_ready], 1
    jne  .standard
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .lock_slot
    cmp  edi, LOCK_SLOT
    je   .lock_slot
    ret
.lock_slot:
    cmp  edi, LOCK_SLOT
    je   wgt_draw_window
.standard:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi                      ; slot
    push rax
    movzx eax, word [rel cadence_region_current]
    push rax
    mov  [rel cadence_region_current], r12w
    mov  eax, r12d
    lea  rcx, [rel wm_x]
    mov  r13d, [rcx + rax*4]            ; x
    lea  rcx, [rel wm_y]
    mov  r14d, [rcx + rax*4]            ; y
    lea  rcx, [rel wm_w]
    mov  r15d, [rcx + rax*4]            ; w
    lea  rcx, [rel wm_h]
    mov  ebp, [rcx + rax*4]             ; h

    ; D2 frame: one thin ring, accent when focused. The title strip, its
    ; separator row and the body are inset by GUI_CHROME_BORDER.
    mov  r8d, r13d
    mov  r9d, r14d
    mov  r10d, r15d
    mov  r11d, ebp
    ; A moved/restored window may cross the taskbar. Its frame/body can
    ; erase the clock cell that the taskbar deliberately preserves. Reuse
    ; the coverage leaf so the final taskbar pass restores cached glyphs.
    call tray_clock_rearm_if_covered
    mov  ebx, GUI_TOK_BORDER
    cmp  r12d, [rel wm_focus]
    jne  .frame_color
    mov  ebx, GUI_TOK_BORDER_FOCUSED
.frame_color:
    call fb_fill_rect

    ; title strip. Focus is a token choice, never an app choice.
    mov  r8d, r13d
    add  r8d, GUI_CHROME_BORDER
    mov  r9d, r14d
    add  r9d, GUI_CHROME_BORDER
    mov  r10d, r15d
    sub  r10d, GUI_CHROME_BORDER * 2
    mov  r11d, GUI_TITLE_H - GUI_CHROME_BORDER - 1
    mov  ebx, GUI_TOK_TITLE_UNFOCUSED
    cmp  r12d, [rel wm_focus]
    jne  .title_color
    mov  ebx, GUI_TOK_TITLE_FOCUSED
.title_color:
    call fb_fill_rect
    ; separator: the strip's last row.
    mov  r9d, r14d
    add  r9d, GUI_TITLE_H - 1
    mov  r11d, 1
    mov  ebx, GUI_TOK_TITLE_SEPARATOR
    call fb_fill_rect

    ; body below the title strip.
    mov  r8d, r13d
    add  r8d, GUI_CHROME_BORDER
    mov  r9d, r14d
    add  r9d, GUI_TITLE_H
    mov  r10d, r15d
    sub  r10d, GUI_CHROME_BORDER * 2
    mov  r11d, ebp
    sub  r11d, GUI_TITLE_H + GUI_CHROME_BORDER
    mov  ebx, GUI_TOK_WINDOW_BODY
    call fb_fill_rect

    ; Standard title glyphs. chrome=tabs windows draw their own tab strip
    ; (a widget) in the title band instead.
    lea  rcx, [rel wm_chrome]
    cmp  byte [rcx + r12], WM_CHROME_TABS
    je   .buttons
    mov  eax, r12d
    lea  rcx, [rel wm_title]
    mov  rdi, [rcx + rax*8]             ; title cstr
    test rdi, rdi
    jz   .buttons
    call wmx_title_display              ; B3: '_' paints as a space (form text has no spaces)
    mov  r8d, r13d
    add  r8d, GUI_CHROME_TITLE_X
    mov  r9d, r14d
    add  r9d, GUI_CHROME_TITLE_Y
    mov  ebx, GUI_TOK_TITLE_TEXT_UNFOCUSED
    mov  ecx, GUI_TOK_TITLE_UNFOCUSED
    cmp  r12d, [rel wm_focus]
    jne  .title_text
    mov  ebx, GUI_TOK_TITLE_TEXT
    mov  ecx, GUI_TOK_TITLE_FOCUSED
.title_text:
    mov  r11d, r15d
    sub  r11d, GUI_CHROME_TITLE_RESERVE
    jle  .buttons
    mov  eax, r11d
    xor  edx, edx
    mov  r10d, GUI_CHROME_TITLE_ADV
    div  r10d
    mov  r11d, eax
    call fb_draw_str_aa_n               ; D2 AA 9x19 title text

.buttons:
    ; Windows 11 caption buttons, flush right: close, maximize, minimize.
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, GUI_CHROME_BUTTON_W + GUI_CHROME_BUTTON_RIGHT
    mov  r9d, r14d
    add  r9d, GUI_CHROME_BUTTON_Y
    mov  esi, WMX_PART_CLOSE
    call wmx_paint_caption
    sub  r8d, GUI_CHROME_BUTTON_W + GUI_CHROME_BUTTON_GAP
    mov  esi, WMX_PART_MAX
    call wmx_paint_caption
    sub  r8d, GUI_CHROME_BUTTON_W + GUI_CHROME_BUTTON_GAP
    mov  esi, WMX_PART_MIN
    call wmx_paint_caption

    ; resize grip (2026-09-08, Peter: "I do not see a resize pointer"): three diagonal marks
    ; in the bottom-right corner name the WM_GRIP_PX zone the pointer test uses.
    mov  ebx, GUI_TOK_OUTLINE
    mov  r10d, 2
    mov  r11d, 2
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, 5
    mov  r9d, r14d
    add  r9d, ebp
    sub  r9d, 5
    call fb_fill_rect
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, 9
    mov  r9d, r14d
    add  r9d, ebp
    sub  r9d, 5
    call fb_fill_rect
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, 5
    mov  r9d, r14d
    add  r9d, ebp
    sub  r9d, 9
    call fb_fill_rect
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, 13
    mov  r9d, r14d
    add  r9d, ebp
    sub  r9d, 5
    call fb_fill_rect
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, 9
    mov  r9d, r14d
    add  r9d, ebp
    sub  r9d, 9
    call fb_fill_rect
    mov  r8d, r13d
    add  r8d, r15d
    sub  r8d, 5
    mov  r9d, r14d
    add  r9d, ebp
    sub  r9d, 13
    call fb_fill_rect

    ; Widgets are the only ordinary body renderer used by the F1 demo.
    mov  edi, r12d
    call wgt_draw_window
    pop  rax
    mov  [rel cadence_region_current], ax
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

WMX_PART_NONE  equ 0
WMX_PART_MIN   equ 1
WMX_PART_MAX   equ 2
WMX_PART_CLOSE equ 3

; wmx_paint_caption(r12d=slot, r8d/r9d=button origin, esi=part). One 46x38
; caption button: hover fill (grey; close red), then a 10 px glyph at the
; reference offsets (+18, min line at +19, max/close box at +15). Shared
; fb_fill_rect strokes only. Preserves r8..r11/ebx, clobbers eax/ecx/edx.
wmx_paint_caption:
    push rbx
    push r10
    push r11
    push rsi
    mov  ecx, GUI_TOK_CHROME_GLYPH_UNFOCUSED
    cmp  r12d, [rel wm_focus]
    jne  .hover_test
    mov  ecx, GUI_TOK_CHROME_GLYPH
.hover_test:
    cmp  r12d, [rel wmx_hover_slot]
    jne  .glyph
    movzx eax, byte [rel wmx_hover_part]
    cmp  eax, esi
    jne  .glyph
    mov  ebx, GUI_TOK_CAPTION_HOVER
    cmp  esi, WMX_PART_CLOSE
    jne  .fill
    mov  ebx, GUI_TOK_CLOSE_HOVER
    mov  ecx, GUI_TOK_CHROME_GLYPH
.fill:
    mov  r10d, GUI_CHROME_BUTTON_W
    mov  r11d, GUI_CHROME_BUTTON_H
    call fb_fill_rect
.glyph:
    mov  ebx, ecx
    push r8
    push r9
    add  r8d, 18
    cmp  esi, WMX_PART_MIN
    jne  .not_min
    add  r9d, 19
    mov  r10d, GUI_CHROME_GLYPH
    mov  r11d, 1
    call fb_fill_rect
    jmp  .done
.not_min:
    add  r9d, 15
    cmp  esi, WMX_PART_MAX
    jne  .close
    lea  rax, [rel wm_maximized]
    cmp  byte [rax + r12], 1
    je   .restore_glyph
    mov  r10d, GUI_CHROME_GLYPH         ; top
    mov  r11d, 1
    call fb_fill_rect
    add  r9d, GUI_CHROME_GLYPH - 1      ; bottom
    call fb_fill_rect
    sub  r9d, GUI_CHROME_GLYPH - 1
    mov  r10d, 1                        ; left
    mov  r11d, GUI_CHROME_GLYPH
    call fb_fill_rect
    add  r8d, GUI_CHROME_GLYPH - 1      ; right
    call fb_fill_rect
    jmp  .done
.restore_glyph:
    ; F-RESTOREGLYPH (2026-09-30, usage suite CHR-03): a maximized window's
    ; maximize button shows RESTORE (Windows 11): a front 8 px box at (0,+2) and
    ; the top + right edges of a back box offset (+2,-2), inside the 10 px glyph box.
    mov  r10d, GUI_CHROME_GLYPH - 2     ; back box top
    mov  r11d, 1
    add  r8d, 2
    call fb_fill_rect
    add  r8d, GUI_CHROME_GLYPH - 3      ; back box right
    mov  r10d, 1
    mov  r11d, GUI_CHROME_GLYPH - 2
    call fb_fill_rect
    sub  r8d, GUI_CHROME_GLYPH - 1      ; front box origin (0,+2)
    add  r9d, 2
    mov  r10d, GUI_CHROME_GLYPH - 2     ; front top
    mov  r11d, 1
    call fb_fill_rect
    add  r9d, GUI_CHROME_GLYPH - 3      ; front bottom
    call fb_fill_rect
    sub  r9d, GUI_CHROME_GLYPH - 3
    mov  r10d, 1                        ; front left
    mov  r11d, GUI_CHROME_GLYPH - 2
    call fb_fill_rect
    add  r8d, GUI_CHROME_GLYPH - 3      ; front right
    call fb_fill_rect
    jmp  .done
.close:
    ; two 1 px diagonals of the 10 px box
    mov  r10d, 1
    mov  r11d, 1
    xor  edx, edx
.x_loop:
    push r8
    add  r8d, edx
    call fb_fill_rect
    pop  r8
    push r8
    add  r8d, GUI_CHROME_GLYPH - 1
    sub  r8d, edx
    call fb_fill_rect
    pop  r8
    inc  r9d
    inc  edx
    cmp  edx, GUI_CHROME_GLYPH
    jb   .x_loop
.done:
    pop  r9
    pop  r8
    pop  rsi
    pop  r11
    pop  r10
    pop  rbx
    ret

; wmx_caption_part_at(EDI=slot or -1, ESI=x, EDX=y) -> EAX = WMX_PART_NONE/MIN/
; MAX/CLOSE. UI wave 2 B1: the ONE caption hit rule -- the same geometry the
; painter (wmx_paint_slot .buttons) and WINCHROME use; hover and press both
; call it, so the red close hover and the close press can never disagree.
; Clobbers RAX, RCX, RDX, R8, R9.
wmx_caption_part_at:
    xor  ecx, ecx                       ; part = none
    cmp  edi, WM_MAX
    jae  .out                           ; -1 / no slot
    mov  eax, edi
    lea  r8, [rel wm_y]
    mov  r9d, [r8 + rax*4]
    add  r9d, GUI_CHROME_BUTTON_Y
    cmp  edx, r9d
    jl   .out
    add  r9d, GUI_CHROME_BUTTON_H
    cmp  edx, r9d
    jge  .out
    lea  r8, [rel wm_x]
    mov  r9d, [r8 + rax*4]
    lea  r8, [rel wm_w]
    add  r9d, [r8 + rax*4]
    sub  r9d, GUI_CHROME_BUTTON_RIGHT   ; right edge of close
    cmp  esi, r9d
    jge  .out
    sub  r9d, GUI_CHROME_BUTTON_W * 3 + GUI_CHROME_BUTTON_GAP * 2
    mov  eax, esi
    sub  eax, r9d
    jl   .out
    xor  edx, edx
    mov  r8d, GUI_CHROME_BUTTON_W + GUI_CHROME_BUTTON_GAP
    div  r8d                            ; 0 min, 1 max, 2 close
    cmp  edx, GUI_CHROME_BUTTON_W
    jae  .out                           ; inside a (non-zero) gap
    lea  ecx, [eax + 1]
.out:
    mov  eax, ecx
    ret

; wmx_caption_hover(edi=top slot or -1, esi=x, edx=y): no-button motion. Find
; the caption button under the pointer (wmx_caption_part_at), record it and
; repaint the stack only when the hovered button changes. Clobbers caller-saved.
wmx_caption_hover:
    ; The locked fullscreen form owns every pixel: no caption hover there.
    cmp  byte [rel lock_surface_ready], 1
    jne  .live
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .live
    ret
.live:
    push rbx
    mov  ebx, edi
    call wmx_caption_part_at
    mov  ecx, eax
.update:
    mov  edi, ebx
    cmp  ecx, WMX_PART_NONE
    jne  .have
    mov  edi, -1
.have:
    mov  esi, ecx
    call wmx_hover_update
    test eax, eax
    jz   .out
    call wmx_draw_all
.out:
    pop  rbx
    ret

; wmx_hover_update(edi=slot or -1, esi=part) -> EAX=1 when the hovered caption
; changed (the caller repaints), 0 otherwise.
wmx_hover_update:
    xor  eax, eax
    cmp  edi, [rel wmx_hover_slot]
    jne  .changed
    movzx ecx, byte [rel wmx_hover_part]
    cmp  ecx, esi
    je   .out
.changed:
    mov  [rel wmx_hover_slot], edi
    mov  [rel wmx_hover_part], sil
    mov  eax, 1
.out:
    ret

; wmx_draw_one(edi=slot) — every slot takes the ONE chrome path. Chat retains
; only its temporary app-body callback; it no longer owns any chrome pixels.
wmx_draw_one:
    push rdi
    push r12
    push r13
    push r14
    push r15
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r15, rax                       ; 2026-09-08: per-slot draw cost -> wmx_draw_tsc[slot]
    call wmx_paint_slot
    mov  edi, [rsp + 32]
    call guest_desktop_draw_body        ; RCQ-23: the guest window's client area; no-op for other slots
%ifidn RCQ37_VIDEO_BUILT,1
    mov  edi, [rsp + 32]
    call video_player_body
%endif
    cmp  dword [rsp + 32], CHAT_SLOT
    jne  .done
    cmp  byte [rel chat_window_suppressed], 1
    je   .done                          ; F1 retired the chat tile (slot 2 stays reserved)
    call chat_draw_body
.done:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, r15
    mov  ecx, [rsp + 32]
    cmp  ecx, WM_MAX
    jae  .no_stamp
    lea  rdx, [rel wmx_draw_tsc]
    mov  [rdx + rcx*8], rax
.no_stamp:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    ret

; wmx_draw_all — repaint every VISIBLE slot in z-order: non-focused first (slot
;   order), then the focused slot LAST so focus = topmost (the raise). r12-safe
;   via wmx_draw_one; loop counter kept in r12.
; A registry verb may synchronously delegate to another registered verb. Such a
; chain is still running on the bounded command ingress stack, so it queues full
; composition for the top-level idle loop. State changes remain synchronous;
; framebuffer composition never grows with registry-dispatch depth.
wmx_draw_defer_begin:
    inc  byte [rel wmx_draw_defer_depth]
    ret

wmx_draw_defer_end:
    cmp  byte [rel wmx_draw_defer_depth], 0
    je   .bad
    dec  byte [rel wmx_draw_defer_depth]
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; Top-level idle seam. EAX=1 when a queued composition was performed, else 0.
wmx_draw_flush_deferred:
    cmp  byte [rel wmx_draw_defer_depth], 0
    jne  .none
    cmp  byte [rel wmx_draw_pending], 1
    jne  .none
    mov  byte [rel wmx_draw_pending], 0
    call wmx_draw_all
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

wmx_draw_all:
    cmp  byte [rel wmx_draw_defer_depth], 0
    je   .paint
    mov  byte [rel wmx_draw_pending], 1
    ret
.paint:
    push r12
    push r13
    push r14
    inc  byte [rel wgt_paint_depth]
    call ps2_cursor_hide                ; 2026-09-08: lift the sprite before repainting
    CADENCE_BATCH_BEGIN
    ; 2026-09-08 real z-order (Peter: "the first window jumps ahead of its stack"): paint the
    ; visible slots by ascending z stamp. Raise/open/alt-tab stamp the top; nothing else
    ; reorders, so a window keeps its place in the stack when another one is selected.
    ; A layer 0 desktop widget lies on the wallpaper, under every window. Not behind the lock.
    cmp  byte [rel lock_surface_ready], 1
    jne  .floor
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .floor_done
.floor:
    call wgt_draw_desktop
.floor_done:
    xor  r12d, r12d                     ; drawn mask
.pass:
    mov  r13d, -1                       ; best stamp (unsigned max)
    mov  r14d, WM_MAX                   ; best slot
    xor  ecx, ecx
.scan:
    cmp  ecx, WM_MAX
    jae  .scanned
    cmp  ecx, [rel wm_focus]
    je   .scan_next                    ; focused host is last within each pass
    bt   r12d, ecx
    jc   .scan_next
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .scan_next
    lea  rax, [rel wm_zstamp]
    mov  eax, [rax + rcx*4]
    cmp  eax, r13d
    jae  .scan_next                     ; equal stamps: lowest slot first
    mov  r13d, eax
    mov  r14d, ecx
.scan_next:
    inc  ecx
    jmp  .scan
.scanned:
    cmp  r14d, WM_MAX
    jae  .done
    bts  r12d, r14d
    mov  edi, r14d
    cmp  byte [rel wgt_overlay_pass], 1
    je   .overlay_slot
    call wmx_draw_one
    jmp  .pass
.overlay_slot:
    call wgt_draw_window
    jmp  .pass
.done:
    mov  edi, [rel wm_focus]
    cmp  edi, WM_MAX
    jae  .focused_done
    lea  rax, [rel wm_state]
    cmp  dword [rax + rdi*4], WM_VISIBLE
    jne  .focused_done
    cmp  byte [rel wgt_overlay_pass], 1
    je   .focused_overlay
    call wmx_draw_one
    jmp  .focused_done
.focused_overlay:
    call wgt_draw_window
.focused_done:
    ; GK1-3 z-order: windows (including focused), declared overlays in the
    ; same host z-order, taskbar, cursor. Never expose workspace overlays
    ; above the session lock surface.
    cmp  byte [rel lock_surface_ready], 1
    jne  .overlays
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no_taskbar
.overlays:
    cmp  byte [rel wgt_overlay_pass], 0
    jne  .overlay_done
    call wgt_has_overlay
    test eax, eax
    jz   .taskbar
    mov  byte [rel wgt_overlay_pass], 1
    xor  r12d, r12d
    jmp  .pass
.overlay_done:
    call wgt_draw_desktop
    mov  byte [rel wgt_overlay_pass], 0
.taskbar:
    call calendar_paint                 ; anchored month panel, over windows and overlays
    call ime_popup_paint                ; RCQ-38 I3b-1 (c): the IME candidate window, over every window and overlay
    call taskbar_draw_registry
.no_taskbar:
    mov  byte [rel wgt_overlay_pass], 0
    call ps2_cursor_show
    CADENCE_BATCH_END
    dec  byte [rel wgt_paint_depth]
    pop  r14
    pop  r13
    pop  r12
    ret

; Erase the declared escape area at the same lifecycle seam as its host.
; Move/minimize/close/session-hide all retain the usual surviving-window repaint.
wmx_erase_overlays:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    xor  r12d, r12d
.loop:
    cmp  r12d, [rel wgt_count]
    jae  .out
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .next
    cmp  [rax + WGI_WIN], r13d
    jne  .next
    cmp  dword [rax + WGI_LAYER], 1
    jne  .next
    mov  r8d, [rax + WGI_X]
    mov  r9d, [rax + WGI_Y]
    mov  r10d, [rax + WGI_W]
    mov  r11d, [rax + WGI_H]
    call wallpaper_paint_rect
.next:
    inc  r12d
    jmp  .loop
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; geometry op primitives (shared by the boot selftest + the UDP verbs)
; ---------------------------------------------------------------------------

; wmx_clamp_slot(edi=slot) — bounded geometry: w/h >= floor, origin on-screen.
;   fb_fill_rect already clips, so this only keeps the stored geometry sane
;   (a bad WINMOVE/WINRESIZE degrades to a clamped window, never a crash/wedge).
wmx_clamp_slot:
    mov  eax, edi
    lea  rcx, [rel wm_w]
    mov  edx, [rcx + rax*4]
    cmp  edx, WMX_MIN_W
    jge  .wok
    mov  dword [rcx + rax*4], WMX_MIN_W
.wok:
    lea  rcx, [rel wm_h]
    mov  edx, [rcx + rax*4]
    cmp  edx, WMX_MIN_H
    jge  .hok
    mov  dword [rcx + rax*4], WMX_MIN_H
.hok:
    mov  r8d, [rel fb_width]
    sub  r8d, WMX_MIN_W
    lea  rcx, [rel wm_x]
    mov  edx, [rcx + rax*4]
    test edx, edx
    jns  .xhigh
    mov  dword [rcx + rax*4], 0
    jmp  .xok
.xhigh:
    cmp  edx, r8d
    jbe  .xok
    mov  [rcx + rax*4], r8d
.xok:
    mov  r8d, [rel fb_height]
    sub  r8d, WMX_MIN_H
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    test edx, edx
    jns  .yhigh
    mov  dword [rcx + rax*4], 0
    jmp  .yok
.yhigh:
    cmp  edx, r8d
    jbe  .yok
    mov  [rcx + rax*4], r8d
.yok:
    ret

; wmx_raise_slot(edi=slot) — bring slot to front: ensure visible, focus it, redraw.
; wmx_zstamp_top(EDI=slot) — this slot becomes the top of the z-order. Clobbers RAX, RCX.
wmx_zstamp_top:
    inc  dword [rel wm_zcounter]
    mov  eax, [rel wm_zcounter]
    lea  rcx, [rel wm_zstamp]
    mov  [rcx + rdi*4], eax
    ret

; wmx_raise_stamp(EDI=slot) — a raise of the visible slot already on top moves nothing,
; so the counter stays and a press on the top card still matches its own snapshot (SEC
; 89575). A slot that is closed or minimized may hold an old top stamp, so it bumps, as
; does the first stamp of all. Clobbers RAX, RCX.
wmx_raise_stamp:
    mov  eax, [rel wm_zcounter]
    test eax, eax
    jz   .bump
    lea  rcx, [rel wm_zstamp]
    cmp  eax, [rcx + rdi*4]
    jne  .bump
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rdi*4], WM_VISIBLE
    jne  .bump
    ret
.bump:
    jmp  wmx_zstamp_top

; Shared session-only focus/launch order; palette owns no history ring.
wmx_record_recent:
    inc  qword [rel wm_recent_clock]
    lea  rax, [rel wm_recent_seq]
    mov  rcx, [rel wm_recent_clock]
    mov  [rax + rdi*8], rcx
    ret

; wmx_paint_top_slot -> EAX = the window wmx_draw_all paints last: the focused
;   window when it is visible, else wmx_top_visible_slot. A direct painter's
;   "nothing covers me" test (RCQ-16 F5-R1 L1): an agent-opened window can hold
;   the top stamp without focus, and wm_pointer_top_slot follows this order.
;   Preserves RBX/RCX/RDX.
wmx_paint_top_slot:
    mov  eax, [rel wm_focus]
    cmp  eax, WM_MAX
    jae  wmx_top_visible_slot
    push rcx
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rax*4], WM_VISIBLE
    pop  rcx
    jne  wmx_top_visible_slot
    ret

; wmx_top_visible_slot -> EAX = the visible slot with the highest z stamp, or WM_MAX.
wmx_top_visible_slot:
    push rbx
    push rcx
    push rdx
    mov  eax, WM_MAX
    xor  edx, edx
    xor  ecx, ecx
.tv_loop:
    cmp  ecx, WM_MAX
    jae  .tv_done
    lea  rbx, [rel wm_state]
    cmp  dword [rbx + rcx*4], WM_VISIBLE
    jne  .tv_next
    lea  rbx, [rel wm_zstamp]
    mov  ebx, [rbx + rcx*4]
    cmp  ebx, edx
    jb   .tv_next
    mov  edx, ebx
    mov  eax, ecx
.tv_next:
    inc  ecx
    jmp  .tv_loop
.tv_done:
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; wmx_bad_slot_refuse — (MSI spoke 386ee66f7, ported) a slot >= WM_MAX reached a
; window mutator (on the MSI: start_menu_toggle kept its slot in RBX across
; painters that leave 0x181818 there). Every wm_* array is indexed by the slot,
; so the call is counted and dropped instead of erasing/writing out of bounds.
; Tail-jumped to from the entry of wmx_move_slot/raise/minimize/close.
wmx_bad_slot_refuse:
    inc  dword [rel wmx_bad_slots]
    ret

; RCQ-16 F2 (rc-sec 9e24b1ef): per-slot owner principal. 0 = unowned: only
; PRIN_OWNER may act on it. WM_OWNER_CHROME (the lock form) = no request may
; act, PRIN_OWNER included. Any other value = the principal that opened it.
; Stamped at every open (wmx_owner_open: the opening frame's principal, or
; wmx_owner_clear where the window is the owner's own), cleared at every close.
; wmx_owner_open(EDI=slot) / wmx_owner_clear(EDI=slot): preserve every register.
wmx_owner_open:
    push rax
    push rdi
    xor  edi, edi
    call session_shell_request_principal ; RAX = this frame's principal, 0 = none
    pop  rdi
    jmp  wmx_owner_store
wmx_owner_clear:
    push rax
    xor  eax, eax
wmx_owner_store:
    cmp  edi, WM_MAX
    jae  .out
    push rax
    mov  rax, [rel wmx_owner_reset_op]   ; trusted observer preserves every register
    test rax, rax
    jz   .no_owner_observer
    call rax                           ; invalidate even when generation wraps
.no_owner_observer:
    pop  rax
    call wmx_native_unbind              ; RC-task-manager: a binding never outlives its window
    push rcx
    mov  ecx, edi
    push rdx
    lea  rdx, [rel wm_owner]
    mov  [rdx + rcx*8], rax
    ; RC-history r3: every open and close starts a new window identity (24-bit
    ; generation, never 0) and clears the no-history mark of the slot.
    lea  rdx, [rel wm_gen]
    mov  eax, [rdx + rcx*4]
    inc  eax
    and  eax, 0xFFFFFF
    jnz  .gen
    inc  eax
.gen:
    mov  [rdx + rcx*4], eax
    lea  rdx, [rel wm_no_history]
    mov  byte [rdx + rcx], 0
    pop  rdx
    pop  rcx
.out:
    pop  rax
    ret

; wmx_window_id(EDI = slot) -> EAX = slot | wm_gen << 8 for a shown or
; minimized window whose open was stamped, else 0. The id a history producer
; names (svc/history r3 §1); a reused slot never answers to an old id.
; Clobbers RAX, RCX, RDX.
wmx_window_id:
    xor  eax, eax
    cmp  edi, WM_MAX
    jae  .out
    mov  ecx, edi
    lea  rdx, [rel wm_state]
    mov  edx, [rdx + rcx*4]
    cmp  edx, WM_VISIBLE
    je   .live
    cmp  edx, WM_MIN
    jne  .out
.live:
    lea  rdx, [rel wm_gen]
    mov  eax, [rdx + rcx*4]
    shl  eax, 8
    jz   .out
    or   eax, ecx
.out:
    ret

; wmx_set_no_history(EDI = window id) -> EAX 0 / -1: the browser marks a
; bank-mode or private window at creation. The mark lives in the registry, is
; read only by svc/history, and is cleared only when the slot is reused.
; Clobbers RAX, RCX, RDX.
wmx_set_no_history:
    push rdi
    movzx edi, dil
    call wmx_window_id
    pop  rdi
    test eax, eax
    jz   .no
    cmp  eax, edi
    jne  .no
    movzx ecx, dil
    lea  rdx, [rel wm_no_history]
    mov  byte [rdx + rcx], 1
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; wmx_history_target(EDI = window id, ESI = widget id + 1 or 0) -> EAX = slot,
; or -1: svc/history's window check (r3 §1), registered by wmx_declare. The id's
; generation must be current, the window shown or minimized, unowned or
; PRIN_OWNER (chrome and other principals refuse) and not marked no-history. A
; named widget must be live, in that window, and not a secret field: the kit's
; secret type or role "password" (the secret-class half of wgt_secret_hidden,
; for every principal). Clobbers caller-saved.
wmx_history_target:
    movzx ecx, dil
    cmp  ecx, WM_MAX
    jae  .no
    mov  eax, edi
    shr  eax, 8
    jz   .no
    lea  rdx, [rel wm_gen]
    cmp  eax, [rdx + rcx*4]
    jne  .no
    lea  rdx, [rel wm_state]
    mov  eax, [rdx + rcx*4]
    cmp  eax, WM_VISIBLE
    je   .shown
    cmp  eax, WM_MIN
    jne  .no
.shown:
    lea  rdx, [rel wm_owner]
    mov  rax, [rdx + rcx*8]
    test rax, rax
    jz   .owned
    cmp  rax, PRIN_OWNER
    jne  .no
.owned:
    lea  rdx, [rel wm_no_history]
    cmp  byte [rdx + rcx], 0
    jne  .no
    test esi, esi
    jz   .slot
    lea  edi, [esi - 1]
    cmp  edi, [rel wgt_count]
    jae  .no
    push rcx
    call wgt_slot_ptr
    pop  rcx
    cmp  dword [rax + WGI_TYPE], 0
    je   .no
    cmp  [rax + WGI_WIN], ecx
    jne  .no
    mov  edx, [rel wgt_secret_type]
    inc  edx
    cmp  [rax + WGI_TYPE], edx
    je   .no
    mov  rdi, [rax + WGI_ROLE]
    test rdi, rdi
    jz   .slot
    push rcx
    lea  rsi, [rel str_wgt_role_password]
    call strcmp
    pop  rcx
    test eax, eax
    jz   .no
.slot:
    mov  eax, ecx
    ret
.no:
    mov  eax, -1
    ret

; wmx_principal_may_act(EDI=host slot or WGT_HOST_DESKTOP, RSI=principal) ->
; EAX 0 = may act, -1 = refused. In order: no principal -> refuse; a chrome
; slot -> refuse; PRIN_OWNER -> allow; the slot's own nonzero owner -> allow;
; else refuse. The unowned desktop host also admits the current local Try
; session, checked through its epoch/origin gate. Clobbers RAX only.
wmx_principal_may_act:
    test rsi, rsi
    jz   .no
    push rcx
    xor  ecx, ecx
    cmp  edi, WGT_HOST_DESKTOP
    je   .have
    ja   .no_pop
    mov  ecx, edi
    lea  rax, [rel wm_owner]
    mov  rcx, [rax + rcx*8]
.have:
    cmp  rcx, WM_OWNER_CHROME
    je   .no_pop
    cmp  rsi, PRIN_OWNER
    je   .yes
    cmp  rsi, PRIN_TRY
    jne  .slot_owner
    cmp  edi, WGT_HOST_DESKTOP
    jne  .slot_owner
    ; Desktop placement is local-only for Try, never an anonymous wire grant.
    push rdx
    call session_shell_local_authority
    pop  rdx
    cmp  rax, PRIN_TRY
    jne  .no_pop
    jmp  .yes
.slot_owner:
    cmp  rcx, rsi                       ; an unowned slot (0) never equals a principal
    jne  .no_pop
.yes:
    pop  rcx
    xor  eax, eax
    ret
.no_pop:
    pop  rcx
.no:
    mov  eax, -1
    ret

; RC-task-manager (spec 21.2.7 item 3; native ABI core/native_app, 9e477ced2): a
; window's native module binding is WM metadata, outside the module's arena, like
; its title, geometry, z-order and wm_owner. wm_native_slot -1 = no module.
; Only a dispatch that returns 0 lets the caller commit arena output; STUCK is
; latched per window and never retried here (root 16:27); a restart needs the
; window's own authority and keeps every piece of WM state.
;
; wmx_native_bind(EDI=wm slot, ESI=native slot, RDX=generation) -> EAX 0, -1 when
; the wm slot is out of range or already bound. Trusted app init only, right after
; native_app_register. Clobbers RAX.
wmx_native_bind:
    mov  edi, edi                       ; index with the 32-bit slot only
    cmp  edi, WM_MAX
    jae  .no
    push rcx
    lea  rax, [rel wm_native_slot]
    cmp  dword [rax + rdi*4], -1
    jne  .no_pop
    mov  [rax + rdi*4], esi
    lea  rax, [rel wm_native_gen]
    mov  [rax + rdi*8], rdx
    lea  rax, [rel wm_native_stuck]
    mov  byte [rax + rdi], 0
    pop  rcx
    xor  eax, eax
    ret
.no_pop:
    pop  rcx
.no:
    mov  eax, -1
    ret

; wmx_native_arena(EDI=wm slot) -> RAX = the bound module's arena (trusted input
; staging and, after a 0 dispatch only, output), 0 = unbound or refused.
; Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
wmx_native_arena:
    mov  edi, edi                       ; index with the 32-bit slot only
    cmp  edi, WM_MAX
    jae  .none
    lea  rax, [rel wm_native_slot]
    mov  ecx, [rax + rdi*4]
    cmp  ecx, -1
    je   .none
    lea  rax, [rel wm_native_gen]
    mov  rsi, [rax + rdi*8]
    push rsi
    mov  edi, ecx
    call native_app_query
    pop  rsi
    test rax, rax
    js   .none
    jz   .none                          ; a free record is a tombstone, never an arena
    cmp  rdx, rsi
    jne  .none                          ; the bound generation is no longer live
    mov  rax, r8
    ret
.none:
    xor  eax, eax
    ret

; wmx_native_dispatch(EDI=wm slot) -> EAX 0 completed (commit), 1 stuck (latched,
; nothing committed), negative = refused or unbound (nothing committed).
; Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
wmx_native_dispatch:
    mov  edi, edi                       ; index with the 32-bit slot only
    cmp  edi, WM_MAX
    jae  .unbound
    push rbx
    mov  ebx, edi
    lea  rax, [rel wm_native_slot]
    mov  edi, [rax + rbx*4]
    cmp  edi, -1
    je   .unbound_pop
    lea  rax, [rel wm_native_gen]
    mov  rsi, [rax + rbx*8]
    call native_app_dispatch
    cmp  rax, 1
    jne  .out
    lea  rcx, [rel wm_native_stuck]
    mov  byte [rcx + rbx], 1
.out:
    pop  rbx
    ret
.unbound_pop:
    pop  rbx
.unbound:
    mov  eax, -1
    ret

; wmx_native_restart(EDI=wm slot, RSI=principal) -> EAX 0 restarted, -1 refused:
; unbound, not stuck, wmx_principal_may_act refuses (only PRIN_OWNER or the
; window's own owner; never the lock chrome), or the ABI refuses (stale
; generation, context). The arena is zeroed by the ABI; title, geometry,
; z-order, owner and saved state stay. Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
wmx_native_restart:
    mov  edi, edi                       ; index with the 32-bit slot only
    cmp  edi, WM_MAX
    jae  .no
    push rbx
    mov  ebx, edi
    lea  rax, [rel wm_native_slot]
    cmp  dword [rax + rbx*4], -1
    je   .no_pop
    lea  rax, [rel wm_native_stuck]
    cmp  byte [rax + rbx], 1
    jne  .no_pop
    call wmx_principal_may_act          ; EDI = wm slot, RSI = principal
    test eax, eax
    jnz  .no_pop
    lea  rax, [rel wm_native_slot]
    mov  edi, [rax + rbx*4]
    lea  rax, [rel wm_native_gen]
    mov  rsi, [rax + rbx*8]
    call native_app_restart
    test rax, rax
    jnz  .no_pop
    lea  rax, [rel wm_native_gen]
    mov  [rax + rbx*8], rdx
    lea  rax, [rel wm_native_stuck]
    mov  byte [rax + rbx], 0
    pop  rbx
    xor  eax, eax
    ret
.no_pop:
    pop  rbx
.no:
    mov  eax, -1
    ret

; wmx_native_unbind(EDI=wm slot < WM_MAX): unregister and forget the window's
; module. A refused unregister (wrong context) still forgets it: the record is then
; unreachable and counted in wmx_native_leaked. Preserves every register.
wmx_native_unbind:
    push rax
    push rcx
    mov  ecx, edi
    lea  rax, [rel wm_native_slot]
    cmp  dword [rax + rcx*4], -1
    je   .out
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  edi, [rax + rcx*4]
    mov  dword [rax + rcx*4], -1
    lea  rax, [rel wm_native_stuck]
    mov  byte [rax + rcx], 0
    lea  rax, [rel wm_native_gen]
    mov  rsi, [rax + rcx*8]
    mov  qword [rax + rcx*8], 0
    call native_app_unregister
    test rax, rax
    jz   .unregistered
    inc  dword [rel wmx_native_leaked]
.unregistered:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
.out:
    pop  rcx
    pop  rax
    ret

; wmx_req_may_act(RDI=request, ESI=slot) -> EAX 0 = the request's own principal
; may act on the slot, -1 = refused (F2b-2: FOCUS/MAX/RAISE). Clobbers RAX, RDI,
; RSI.
wmx_req_may_act:
    call session_shell_request_principal
    mov  edi, esi
    mov  rsi, rax
    jmp  wmx_principal_may_act

; RCQ-16 F2b-2: keyboard focus requires OWNER or native local Try. EAX 0 = this
; frame may move wm_focus (an OWNER request, local Try, boot),
; -1 = it may not (any other principal, or none). Try requires the native
; local epoch/origin gate, including when a ticket happens to name its PID.
; A raise or an open in a refused frame still restacks; only the keyboard
; stays where the local session left it.
; Clobbers RAX only.
wmx_frame_may_focus:
    push rdi
    xor  edi, edi
    call session_shell_request_principal
    pop  rdi
    cmp  rax, PRIN_OWNER
    je   .out
    cmp  rax, PRIN_TRY
    jne  .no
    push rdx
    call session_shell_local_authority
    pop  rdx
    cmp  rax, PRIN_TRY
    jne  .no
.out:
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; wmx_stage_locked(RSI=response): the desktop-surface refusal reply. The one
; registry dispatcher turns cmd_desktop_refused into CMDE_DESKTOP_LOCKED.
; wmx_stage_denied(RSI=response): CMDE_AUTHDENY, nothing changed. Clobber
; caller-saved registers.
wmx_stage_locked:
    push rsi
    call chat_out_reset
    lea  rdi, [rel str_wmx_locked]      ; " session=locked"
    call chat_put_str
    pop  rsi
    mov  byte [rel chat_out_ready], 1
    mov  qword [rsi + RSP_CODE], CMDE_OK
    mov  qword [rsi + RSP_VAL], 0
    ret
wmx_stage_denied:
    push rsi
    call chat_out_reset
    lea  rdi, [rel str_wmx_denied]      ; " window=ERR denied"
    call chat_put_str
    pop  rsi
    mov  byte [rel chat_out_ready], 1
    mov  qword [rsi + RSP_CODE], CMDE_AUTHDENY
    mov  qword [rsi + RSP_VAL], 0
    ret

wmx_raise_slot:
    cmp  edi, WM_MAX
    jae  wmx_bad_slot_refuse
%ifdef IMAGE_VIEWER_BUILT
    push rdi
    call widget_image_rebind_window     ; decode/cache repair in normal context, never paint
    pop  rdi
%endif
    call wmx_frame_may_focus
    test eax, eax
    jnz  .restack
    mov  eax, [rel wm_focus]
    cmp  eax, edi
    je   .raise_set
    mov  [rel wm_prev_focus], eax
.raise_set:
    call wmx_raise_stamp                ; 2026-09-08: raising = top of the z-order
    lea  rcx, [rel wm_state]
    mov  dword [rcx + rdi*4], WM_VISIBLE
    mov  [rel wm_focus], edi
    call wmx_record_recent
    lea  rcx, [rel wm_attn]
    mov  byte [rcx + rdi], 0
    call wgt_focus_window
    call wmx_draw_all
    ret
.restack:
    ; F2b-2: a non-OWNER frame brings the window up but never takes the keyboard.
    call wmx_raise_stamp
    lea  rcx, [rel wm_state]
    mov  dword [rcx + rdi*4], WM_VISIBLE
    call wmx_draw_all
    ret

; wmx_move_slot(edi=slot, esi=x, edx=y) — erase old rect, set origin, clamp, redraw.
; wmx_geom_stamp_begin / _end — TSC around a pointer-driven move/resize (erase + repaint
; + present) -> wmx_move_tsc_last / wmx_move_tsc_max for INPUTSTAT (2026-09-08).
wmx_geom_stamp_begin:
    push rax
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel wmx_move_tsc_start], rax
    pop  rdx
    pop  rax
    ret
wmx_geom_stamp_end:
    push rax
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel wmx_move_tsc_start]
    mov  [rel wmx_move_tsc_last], rax
    cmp  rax, [rel wmx_move_tsc_max]
    jbe  .keep
    mov  [rel wmx_move_tsc_max], rax
.keep:
    pop  rdx
    pop  rax
    ret

wmx_move_slot:
    cmp  edi, WM_MAX
    jae  wmx_bad_slot_refuse
    cmp  byte [rel lock_surface_ready], 1
    jne  .ordinary
    cmp  edi, LOCK_SLOT
    jne  .ordinary
    ret
.ordinary:
    push r12
    push r13
    push r14
    call wmx_geom_stamp_begin
    CADENCE_BATCH_BEGIN
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel wmx_erase_tsc], rax
    mov  edi, r12d
    call wm_erase_slot                  ; clear the window's OLD footprint (no ghost)
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel wmx_erase_tsc]
    mov  [rel wmx_erase_tsc], rax       ; cycles the erase took
    lea  rcx, [rel wm_x]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_x], eax      ; 2026-09-08: remember the origin, shift widgets by the delta
    mov  [rcx + r12*4], r13d
    lea  rcx, [rel wm_y]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_y], eax
    mov  [rcx + r12*4], r14d
    mov  edi, r12d
    call wmx_clamp_slot
    lea  rcx, [rel wm_x]
    mov  esi, [rcx + r12*4]
    sub  esi, [rel wmx_geom_old_x]      ; dx after the clamp
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + r12*4]
    sub  edx, [rel wmx_geom_old_y]      ; dy
    mov  edi, r12d
    call wgt_shift_window               ; the form keeps its layout
    call wmx_draw_all
    CADENCE_BATCH_END
    call wmx_geom_stamp_end
    pop  r14
    pop  r13
    pop  r12
    ret

; wmx_resize_slot(edi=slot, esi=w, edx=h) — erase old rect, set size, clamp, redraw.
; wmx_set_geom_slot(EDI=slot, ESI=x, EDX=y, ECX=w, R8D=h) — 2026-09-08 edge/corner resize:
; erase the old footprint, apply the whole rectangle, clamp, shift widgets by the origin delta,
; anchor-resize them by the size delta, repaint (one batch, one present).
wmx_set_geom_slot:
    cmp  byte [rel lock_surface_ready], 1
    jne  .ordinary
    cmp  edi, LOCK_SLOT
    jne  .ordinary
    ret
.ordinary:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call wmx_geom_stamp_begin
    CADENCE_BATCH_BEGIN
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    mov  ebx, r8d
    mov  edi, r12d
    call wm_erase_slot
    lea  rcx, [rel wm_x]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_x], eax
    mov  [rcx + r12*4], r13d
    lea  rcx, [rel wm_y]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_y], eax
    mov  [rcx + r12*4], r14d
    lea  rcx, [rel wm_w]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_w], eax
    mov  [rcx + r12*4], r15d
    lea  rcx, [rel wm_h]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_h], eax
    mov  [rcx + r12*4], ebx
    mov  edi, r12d
    call wmx_clamp_slot
    lea  rcx, [rel wm_x]
    mov  esi, [rcx + r12*4]
    sub  esi, [rel wmx_geom_old_x]
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + r12*4]
    sub  edx, [rel wmx_geom_old_y]
    mov  edi, r12d
    call wgt_shift_window
    mov  edi, r12d
    mov  esi, [rel wmx_geom_old_w]
    mov  edx, [rel wmx_geom_old_h]
    call wgt_resize_window
    call wmx_draw_all
    CADENCE_BATCH_END
    call wmx_geom_stamp_end
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wmx_resize_slot:
    cmp  byte [rel lock_surface_ready], 1
    jne  .ordinary
    cmp  edi, LOCK_SLOT
    jne  .ordinary
    ret
.ordinary:
    push r12
    push r13
    push r14
    call wmx_geom_stamp_begin
    CADENCE_BATCH_BEGIN
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  edi, r12d
    call wm_erase_slot
    lea  rcx, [rel wm_w]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_w], eax
    mov  [rcx + r12*4], r13d
    lea  rcx, [rel wm_h]
    mov  eax, [rcx + r12*4]
    mov  [rel wmx_geom_old_h], eax
    mov  [rcx + r12*4], r14d
    mov  edi, r12d
    call wmx_clamp_slot
    mov  edi, r12d
    mov  esi, [rel wmx_geom_old_w]
    mov  edx, [rel wmx_geom_old_h]
    call wgt_resize_window              ; 2026-09-08: the content follows the frame
    call wmx_draw_all
    CADENCE_BATCH_END
    call wmx_geom_stamp_end
    pop  r14
    pop  r13
    pop  r12
    ret

; wmx_alttab_do — move focus to the next VISIBLE slot (wrap). No-op if none other.
; RCQ-17: at most WM_MAX probes. With no focused window (wm_focus >= WM_MAX,
; e.g. after minimizing/closing the last one) the lap starts before slot 0 and
; probes every slot once; with nothing visible it returns, focus unchanged
; (it used to spin forever in the idle-loop keyboard router).
wmx_alttab_do:
    push r12
    push r13
    mov  r12d, [rel wm_focus]
    mov  r13d, r12d
    mov  ecx, WM_MAX                    ; probes left: one per slot
    cmp  r12d, WM_MAX
    jb   .loop
    mov  r13d, -1                       ; no focus: the first probe is slot 0
.loop:
    dec  ecx
    js   .done                          ; every slot probed, none visible
    inc  r13d
    cmp  r13d, WM_MAX
    jb   .nowrap
    xor  r13d, r13d
.nowrap:
    cmp  r13d, r12d
    je   .done                          ; came full circle -> only one visible
    lea  rax, [rel wm_state]
    cmp  dword [rax + r13*4], WM_VISIBLE
    jne  .loop
    mov  [rel wm_prev_focus], r12d
    mov  [rel wm_focus], r13d
    mov  edi, r13d
    call wmx_zstamp_top                 ; alt-tab brings the window to the top
    mov  edi, r13d
    call wmx_record_recent              ; shared user-focus/session history
    lea  rax, [rel wm_attn]
    mov  byte [rax + r13], 0
    mov  edi, r13d
    call wgt_focus_window
    call wmx_draw_all
.done:
    pop  r13
    pop  r12
    ret

; wmx_find_free_slot -> eax = first reusable pool slot. CHAT_SLOT (2) is never
; pool: F1 suppresses the chat tile but chat verbs stay live, and SESSSAVE /
; session_clear_fresh_windows skip slot 2, so an app placed there would be
; overdrawn by chat_process and drop out of the session document (0.0.53 ROB-04
; A5; 0.0.54 burn-down item 2). The resident lock composition keeps LOCK_SLOT.
wmx_find_free_slot:
    cmp  byte [rel lock_surface_loading], 1
    jne  .ordinary
    mov  eax, LOCK_SLOT
    ret
.ordinary:
    xor  eax, eax
.loop:
    cmp  eax, WM_MAX
    jae  .none
    cmp  eax, CHAT_SLOT
    je   .next                          ; reserved for chat for the whole boot
    cmp  byte [rel lock_surface_ready], 1
    jne  .not_reserved
    cmp  eax, LOCK_SLOT
    je   .next
.not_reserved:
    lea  rcx, [rel wm_state]
    mov  edx, [rcx + rax*4]
    cmp  edx, WM_FREE
    je   .found
    cmp  edx, WM_CLOSED
    je   .found
.next:
    inc  eax
    jmp  .loop
.found:
    ; B4: a free slot carries no previous occupant's resize rules -- the generic
    ; user-resize floor, resizable; a form raises them after it opens.
    lea  rcx, [rel wm_min_w]
    mov  dword [rcx + rax*4], WMX_USER_MIN_W
    lea  rcx, [rel wm_min_h]
    mov  dword [rcx + rax*4], WMX_USER_MIN_H
    lea  rcx, [rel wm_resizable]
    mov  byte [rcx + rax], 1
    ret
.none:
    mov  eax, -1
    ret

; wmx_open_window(rdi=title, esi=x, edx=y, ecx=w, r8d=h, r9d=restore_class)
; -> eax=slot/-1. This is the ordinary API used by the F1 demo.
wmx_open_window:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15d, r8d
    push r9
    call wmx_find_free_slot
    cmp  eax, -1
    je   .open_out
    mov  edx, eax
    lea  rcx, [rel wm_title]
    mov  [rcx + rdx*8], rbx
    lea  rcx, [rel wm_x]
    mov  [rcx + rdx*4], r12d
    lea  rcx, [rel wm_y]
    mov  [rcx + rdx*4], r13d
    lea  rcx, [rel wm_w]
    mov  [rcx + rdx*4], r14d
    lea  rcx, [rel wm_h]
    mov  [rcx + rdx*4], r15d
    lea  rcx, [rel wm_state]
    mov  dword [rcx + rdx*4], WM_VISIBLE
    mov  edi, edx
    call wmx_owner_open                 ; F2: the opening frame's principal
    lea  rcx, [rel wm_restore_class]
    pop  r9
    mov  [rcx + rdx], r9b
    lea  rcx, [rel wm_attn]
    mov  byte [rcx + rdx], 0
    lea  rcx, [rel wm_chrome]
    mov  byte [rcx + rdx], WM_CHROME_STANDARD   ; a form may upgrade to tabs after open
    lea  rcx, [rel wm_maximized]
    mov  byte [rcx + rdx], 0
    call wmx_frame_may_focus            ; F2b-2: a non-OWNER open does not take the keyboard
    test eax, eax
    jnz  .open_unfocused
    mov  eax, [rel wm_focus]
    mov  [rel wm_prev_focus], eax
    mov  [rel wm_focus], edx
.open_unfocused:
    mov  edi, edx
    call wmx_zstamp_top                 ; a new window opens on top
    mov  edi, edx
    call wmx_record_recent              ; every registry-backed launch has one clock
    mov  edi, edx
    push rdx
    call wmx_clamp_slot
    pop  rax
    jmp  .open_done
.open_out:
    pop  r9
.open_done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Retire rung-0's A/B/chat visual scaffolding into the F1 slot model. Chat's
; slot remains reserved; its verb/data path stays live without a bespoke tile.
wmx_retire_floor_windows:
    xor  edi, edi
    call wm_erase_slot
    mov  edi, 1
    call wm_erase_slot
    mov  edi, CHAT_SLOT
    call wm_erase_slot
    lea  rax, [rel wm_state]
    mov  dword [rax + 0*4], WM_FREE
    mov  dword [rax + 1*4], WM_FREE
    mov  dword [rax + CHAT_SLOT*4], WM_CLOSED
    xor  eax, eax
    mov  [rel wm_owner + 0*8], rax      ; F2: freed slots carry no owner
    mov  [rel wm_owner + 1*8], rax
    mov  byte [rel chat_window_suppressed], 1
    xor  edi, edi
    call wgt_retire_window_widgets
    mov  edi, 1
    call wgt_retire_window_widgets
    ret

; Shared state transitions used by verbs and pointer routing.
wmx_minimize_slot:
    cmp  edi, WM_MAX
    jae  wmx_bad_slot_refuse
    cmp  byte [rel lock_surface_ready], 1
    jne  .ordinary
    cmp  edi, LOCK_SLOT
    jne  .ordinary
    ret
.ordinary:
    push r12
    CADENCE_BATCH_BEGIN
    mov  r12d, edi
    lea  rax, [rel wm_state]
    mov  dword [rax + r12*4], WM_MIN
    mov  edi, r12d
    call wm_erase_slot
    cmp  r12d, [rel wm_focus]
    jne  .min_draw
    mov  dword [rel wm_focus], WM_MAX
    call wmx_frame_may_focus            ; F2b-K1a: a non-OWNER request hands focus to nobody
    test eax, eax
    jnz  .min_none
    call wmx_top_visible_slot           ; 2026-09-08: focus falls to the window now on top
    cmp  eax, WM_MAX
    jae  .min_none
    mov  [rel wm_focus], eax
    lea  rcx, [rel wm_attn]
    mov  byte [rcx + rax], 0
    mov  edi, eax                       ; 0.0.52 re-cut: the keyboard widget follows wm_focus
    call wgt_focus_window
    jmp  .min_draw
.min_none:
    mov  edi, WM_MAX                    ; no window left: no keyboard widget either
    call wgt_focus_window
.min_draw:
    call wmx_draw_all
    CADENCE_BATCH_END
    pop  r12
    ret

wmx_close_slot:
    cmp  edi, WM_MAX
    jae  wmx_bad_slot_refuse
    cmp  byte [rel lock_surface_ready], 1
    jne  .ordinary
    cmp  edi, LOCK_SLOT
    je   .refuse_lock
.ordinary:
    push r12
    CADENCE_BATCH_BEGIN
    mov  r12d, edi
%ifdef WIFI_LOCAL_GUI_BUILT
    call wifi_local_close               ; wipe before retirement or slot reuse
    mov edi, r12d                      ; callback may clobber caller-saved operands
%endif
    lea  rax, [rel wm_state]
    mov  dword [rax + r12*4], WM_CLOSED
%ifidn RCQ37_VIDEO_BUILT,1
    call video_player_close_hook
%endif
    call wmx_owner_clear                ; F2: a reused slot never inherits an owner
    lea  rax, [rel wm_attn]
    mov  byte [rax + r12], 0
    mov  edi, r12d
    call wm_erase_slot
    mov  edi, r12d
    call grid_release_window            ; B18: a closed grid window returns its instance (before its widgets retire)
    mov  edi, r12d
%ifdef IMAGE_VIEWER_BUILT
    call image_viewer_close_hook        ; detach source/cache before widget IDs retire
    mov  edi, r12d
%endif
%ifdef TEXT_VIEW_BUILT
    call text_view_close_hook           ; T5-15: the document goes with its window
    mov  edi, r12d
%endif
    call wgt_retire_window_widgets      ; B7a: also compacts the freed tail of the widget table
    mov  edi, r12d
    call wgt_tabstrip_release_window    ; B7a: the tab-strip instance returns to its pool
    cmp  r12d, [rel wm_focus]
    jne  .close_draw
    mov  dword [rel wm_focus], WM_MAX
    call wmx_frame_may_focus            ; F2b-K1a: a non-OWNER request hands focus to nobody
    test eax, eax
    jnz  .close_none
    call wmx_top_visible_slot           ; 2026-09-08: focus falls to the window now on top
    cmp  eax, WM_MAX
    jae  .close_none
    mov  [rel wm_focus], eax
    lea  rcx, [rel wm_attn]
    mov  byte [rcx + rax], 0
    ; 0.0.52 re-cut (FINDING 2026-10-02): the keyboard widget follows wm_focus. Without this the
    ; global wgt_focus_id kept naming the closed window's (now retired) widget: after B18's boot
    ; retire the console had focus but no caret, and sess_focus_keyboard_owner saw an owner.
    mov  edi, eax
    call wgt_focus_window
    jmp  .close_draw
.close_none:
    mov  edi, WM_MAX                    ; no window left: no keyboard widget either
    call wgt_focus_window
.close_draw:
    call wmx_draw_all
    CADENCE_BATCH_END
    pop  r12
    ret
.refuse_lock:
    ret

; wmx_clear_boot_marks — 2026-09-08 (Peter: "weird artifacts in the upper left corner ...
; remove them"): the boot-time proofs (fb primitive swatch at 8,8; the double-buffer tile at
; 8,64 128x96; the 1094 beacon badge at 24,24 320x64) go on the first HUMAN pointer event or
; DESKCLEAN: backdrop over their union, then the windows back on top. Since boot audit item 3
; the compositor selftest restores its own tiles and the badge is never re-painted, so this is
; a backstop. Runs once; _force resets the latch (the verb).
wmx_clear_boot_marks_force:
    mov  byte [rel wmx_boot_marks_cleared], 0
wmx_clear_boot_marks:
    cmp  byte [rel wmx_boot_marks_cleared], 1
    je   .cleared
    mov  byte [rel wmx_boot_marks_cleared], 1
    push rbx
    push r8
    push r9
    push r10
    push r11
    CADENCE_BATCH_BEGIN
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r10d, 360
    mov  r11d, 176
    call wallpaper_paint_rect
    call wmx_draw_all
    CADENCE_BATCH_END
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbx
    lea  rdi, [rel str_wmx_boot_marks]
    call serial_string
.cleared:
    ret

wmx_toggle_max_slot:
    cmp  byte [rel lock_surface_ready], 1
    jne  .ordinary
    cmp  edi, LOCK_SLOT
    jne  .ordinary
    ret
.ordinary:
    push r12
    CADENCE_BATCH_BEGIN
    mov  r12d, edi
    lea  rax, [rel wm_x]
    mov  ecx, [rax + r12*4]
    mov  [rel wmx_geom_old_x], ecx      ; 2026-09-08: widgets follow the origin by delta (no re-stack)
    lea  rax, [rel wm_y]
    mov  ecx, [rax + r12*4]
    mov  [rel wmx_geom_old_y], ecx
    lea  rax, [rel wm_w]
    mov  ecx, [rax + r12*4]
    mov  [rel wmx_geom_old_w], ecx
    lea  rax, [rel wm_h]
    mov  ecx, [rax + r12*4]
    mov  [rel wmx_geom_old_h], ecx
    lea  rax, [rel wm_maximized]
    cmp  byte [rax + r12], 1
    je   .restore
    lea  rax, [rel wm_x]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_restore_x]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_y]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_restore_y]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_w]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_restore_w]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_h]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_restore_h]
    mov  [rdx + r12*4], ecx
    mov  edi, r12d
    call wm_erase_slot
    lea  rax, [rel wm_x]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel wm_y]
    mov  dword [rax + r12*4], 0
    lea  rax, [rel wm_w]
    mov  ecx, [rel fb_width]
    mov  [rax + r12*4], ecx
    lea  rax, [rel wm_h]
    mov  ecx, [rel fb_height]
    sub  ecx, TASKBAR_H
    mov  [rax + r12*4], ecx
    lea  rax, [rel wm_maximized]
    mov  byte [rax + r12], 1
    jmp  .max_draw
.restore:
    mov  edi, r12d
    call wm_erase_slot
    lea  rax, [rel wm_restore_x]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_x]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_restore_y]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_y]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_restore_w]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_w]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_restore_h]
    mov  ecx, [rax + r12*4]
    lea  rdx, [rel wm_h]
    mov  [rdx + r12*4], ecx
    lea  rax, [rel wm_maximized]
    mov  byte [rax + r12], 0
.max_draw:
    lea  rax, [rel wm_x]
    mov  esi, [rax + r12*4]
    sub  esi, [rel wmx_geom_old_x]
    lea  rax, [rel wm_y]
    mov  edx, [rax + r12*4]
    sub  edx, [rel wmx_geom_old_y]
    mov  edi, r12d
    call wgt_shift_window
    mov  edi, r12d
    mov  esi, [rel wmx_geom_old_w]
    mov  edx, [rel wmx_geom_old_h]
    call wgt_resize_window              ; maximize/restore: the content follows the frame
    call wmx_draw_all
    CADENCE_BATCH_END
    pop  r12
    ret

; The taskbar module is a registry consumer with zero draw calls; this L2
; painter owns its pixels beside the standard chrome painter.
; EDI=slot ESI=x EDX=y ECX=w R8D=h R9D=state(0 active,1 normal,2 min,3 attn).
; RCQ-16 S1: a state pill centred at the bottom tells the four states apart by
; width as well as colour (spec 5.4: state is not conveyed by colour alone).
wmx_paint_taskbar_button:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    mov  r12d, edi
    mov  ebx, GUI_TOK_TASKBAR_ACTIVE
    mov  r13d, GUI_TOK_TASKBAR_PILL_ACTIVE
    mov  r14d, GUI_TASKBAR_PILL_W_ACTIVE
    cmp  r9d, 0
    je   .tb_color
    mov  ebx, GUI_TOK_TASKBAR_NORMAL
    mov  r13d, GUI_TOK_TASKBAR_PILL
    mov  r14d, GUI_TASKBAR_PILL_W_NORMAL
    cmp  r9d, 1
    je   .tb_color
    mov  ebx, GUI_TOK_TASKBAR_MINIMIZED
    mov  r14d, GUI_TASKBAR_PILL_W_MIN
    cmp  r9d, 2
    je   .tb_color
    mov  ebx, GUI_TOK_TASKBAR_ATTENTION
    mov  r13d, GUI_TOK_TASKBAR_PILL_ATTENTION
    mov  r14d, GUI_TASKBAR_PILL_W_ATTENTION
.tb_color:
    mov  ebp, ebx
    mov  r8d, esi
    mov  r9d, edx
    mov  r10d, ecx
    mov  r11d, [rsp]
    call fb_fill_rect
    cmp  r10d, r14d                     ; a button narrower than its pill keeps no pill
    jb   .tb_label
    sub  r10d, r14d
    shr  r10d, 1
    add  r8d, r10d                      ; x + (w - pill_w) / 2
    add  r9d, r11d
    sub  r9d, GUI_TASKBAR_PILL_BOTTOM + GUI_TASKBAR_PILL_H
    mov  r10d, r14d
    mov  r11d, GUI_TASKBAR_PILL_H
    mov  ebx, r13d
    call fb_fill_rect
.tb_label:
    mov  r8d, [rsp + 24]
    add  r8d, 6
    mov  r9d, [rsp + 16]
    add  r9d, 7
    mov  ebx, GUI_TOK_TASKBAR_TEXT
    mov  ecx, ebp
    ; B3 (2026-09-30, usage suite TSK-01/CHR-05): the label shows as many 8 px
    ; cells as fit the button (6 px inset, 2 px right margin: 12 at the full
    ; 104 px -- the MSI suite's LABEL_CHARS), not a fixed 5, and '_' paints as
    ; a space like the title strip and the tab strip.
    mov  r11d, [rsp + 8]                ; button width
    sub  r11d, 8
    jle  .tb_done
    shr  r11d, 3
    mov  eax, r12d
    call wmx_label_ptr                  ; T4: an app-owned title (active tab) wins
    test rdi, rdi
    jz   .tb_done
    call wmx_title_display
    call fb_draw_str_n
.tb_done:
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; wmx_title_display(rdi=title cstr) -> rdi = wmx_title_disp, a copy for PAINTING
; with every '_' shown as a space (B3, 2026-09-30, usage suite CHR-05/TSK-01).
; Form text cannot hold spaces, so titles are declared as System_Properties; the
; stored title (wm_title, WINTREE/TASKBAR readouts, strcmp by title) keeps the
; declared bytes -- only the pixels change, the tab strip's ts_copy_title rule.
; RCQ-38 L3a (rc-sec N1): a title is a security surface (WINNEW and session
; restore store raw bytes), so the copy is sec_text_escape's: a byte outside
; printable ASCII, or '\', shows as '\xNN' on the title bar and the taskbar
; alike, never as Latin-1 or '?'. Reads at most WMX_TITLE_DISP_MAX-1 title
; bytes. Preserves every other register.
wmx_title_display:
    push rax
    push rcx
    push rdx
    push rsi
    mov  rsi, rdi
    lea  rdi, [rel wmx_title_disp]
    mov  edx, WMX_TITLE_DISP_MAX - 1
    mov  ecx, WMX_TITLE_DISP_MAX
    call sec_text_escape                ; EAX = bytes before the NUL
    xor  ecx, ecx
.td_space:
    cmp  ecx, eax
    jae  .td_end
    cmp  byte [rdi + rcx], '_'
    jne  .td_next
    mov  byte [rdi + rcx], ' '
.td_next:
    inc  ecx
    jmp  .td_space
.td_end:
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; wmx_label_ptr(EAX=slot < WM_MAX) -> RDI = the label the shell shows for the
;   slot: the app-owned title (T4, 2026-09-30 usage suite TAB-08: a tabbed
;   window's taskbar label follows its active tab) when set, else wm_title.
;   wm_title stays the window's identity (form single-instance pointer, WINTREE,
;   WINCLOSE by name). Preserves every register except RDI and flags.
wmx_label_ptr:
    push rcx
    lea  rcx, [rel wm_app_title]
    mov  rdi, [rcx + rax*8]
    test rdi, rdi
    jnz  .have
    lea  rcx, [rel wm_title]
    mov  rdi, [rcx + rax*8]
.have:
    pop  rcx
    ret

; Shared L2 notice TITLE painter, using the top80x16 of the security cell.
; RDI bounded native title cstr; caller owns visibility/policy/session gate.
; The lower Guardian alert count/quality line stays visible and unchanged.
; No app pixel path. Preserves callee-saved registers; attention theme tokens.
wmx_tray_notice_paint:
    push rbx
    push r12
    mov r12,rdi
    mov ebx,GUI_TOK_TASKBAR_ATTENTION
    mov r8d,8
    mov r9d,[rel fb_height]
    sub r9d,TASKBAR_H-4
    mov r10d,80
    mov r11d,16
    call fb_fill_rect
    mov ecx,GUI_TOK_TASKBAR_ATTENTION
    mov ebx,GUI_TOK_TASKBAR_TEXT
    mov r8d,12
    mov r9d,[rel fb_height]
    sub r9d,TASKBAR_H-4
    mov r11d,9
    mov rdi,r12
    call fb_draw_str_n
    pop r12
    pop rbx
    ret

wmx_clear_taskbar_buttons:
    xor  r8d, r8d
    mov  r9d, [rel fb_height]
    sub  r9d, TASKBAR_H
    mov  r10d, [rel fb_width]
    sub  r10d, 104                       ; preserve tray/clock cell
    mov  r11d, TASKBAR_H
    mov  ebx, GUI_TOK_TASKBAR_BG
    call fb_fill_rect
    ret

; wmx_store_title(rdi=argptr, esi=slot) -> rdi past the title token. Copies the
;   first token (up to space/NUL) into the slot's title buffer and points
;   wm_title[slot] at it (runtime lea — never a baked dq).
wmx_store_title:
    push rbx
    push r12
    push r13
    mov  r12d, esi                      ; slot
    mov  eax, r12d
    imul eax, WMX_TITLE_MAX
    lea  rbx, [rel wmx_titles]
    add  rbx, rax                       ; dest cursor
    mov  eax, r12d
    lea  rcx, [rel wm_title]
    mov  [rcx + rax*8], rbx             ; wm_title[slot] = dest
    mov  r13d, WMX_TITLE_MAX - 1        ; room
.cp:
    mov  al, [rdi]
    test al, al
    jz   .fin
    cmp  al, ' '
    je   .fin
    test r13d, r13d
    jz   .skip                          ; buffer full: advance but stop storing
    mov  [rbx], al
    inc  rbx
    dec  r13d
.skip:
    inc  rdi
    jmp  .cp
.fin:
    mov  byte [rbx], 0
    pop  r13
    pop  r12
    pop  rbx
    ret

; wmx_next_token_u32(rdi=ptr) -> rax = value, rdi past the number. Skips leading
;   spaces, then parses a decimal (reuses chat_parse_u32). clobbers rax,rcx,rdi.
wmx_next_token_u32:
.sk:
    cmp  byte [rdi], ' '
    jne  .p
    inc  rdi
    jmp  .sk
.p:
    call chat_parse_u32
    ret

; ---------------------------------------------------------------------------
; UDP verbs (registered through the ONE 1077 registry; replies staged into the
; shared chat_out_buf which command_udp frames on every reply).
; ---------------------------------------------------------------------------

; VERB: WINNEW <title> <x> <y> <w> <h> — open a titled window in a free slot,
;   focused (topmost). No free slot -> ERR. Off-screen geometry clamped.
cmd_verb_winnew:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi                       ; resp
    mov  r14, [rdi + REQ_ARG]           ; arg ptr
    call session_shell_require_unlocked ; F2b-1: no window opens under the lock
    test eax, eax
    jnz  .locked
    call wmx_find_free_slot
    cmp  eax, 0
    jl   .full
    mov  r12d, eax                      ; slot
    mov  rdi, r14
    mov  esi, r12d
    call wmx_store_title                ; rdi -> past title
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    lea  rcx, [rel wm_x]
    mov  [rcx + r12*4], eax
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    lea  rcx, [rel wm_y]
    mov  [rcx + r12*4], eax
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    lea  rcx, [rel wm_w]
    mov  [rcx + r12*4], eax
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    lea  rcx, [rel wm_h]
    mov  [rcx + r12*4], eax
    ; defaults if a size was omitted (0)
    lea  rcx, [rel wm_w]
    cmp  dword [rcx + r12*4], 0
    jne  .wnz
    mov  dword [rcx + r12*4], 300
.wnz:
    lea  rcx, [rel wm_h]
    cmp  dword [rcx + r12*4], 0
    jne  .hnz
    mov  dword [rcx + r12*4], 200
.hnz:
    lea  rcx, [rel wm_state]
    mov  dword [rcx + r12*4], WM_VISIBLE
    mov  edi, r12d
    call wmx_owner_open                 ; F2: WINNEW -> the requester's principal
    lea  rcx, [rel wm_restore_class]
    mov  byte [rcx + r12], WM_RESTORE_FRESH
    lea  rcx, [rel wm_attn]
    mov  byte [rcx + r12], 0
    lea  rcx, [rel wm_maximized]
    mov  byte [rcx + r12], 0
    mov  edi, r12d
    call wmx_clamp_slot
    ; Agent/verb-created windows open behind active human work (input
    ; arbitration law). RAISE/FOCUS is the explicit focus transition.
    call wmx_draw_all
    call chat_out_reset
    lea  rdi, [rel str_wn_ok]           ; " winnew=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    jmp  .stage
.full:
    call chat_out_reset
    lea  rdi, [rel str_wn_full]         ; " winnew=ERR no_free_slot"
    call chat_put_str
    jmp  .stage
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r14
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: RAISE GUEST — explicitly show the running graphical guest without START.
; The named guest resource is OWNER-only (it can allocate/focus a native slot).
; VERB: RAISE <idx> — bring a live window to the front of the z-order (+ focus,
;   for an OWNER request only: F2b-2). Refused under the lock (F2b-1) and on a
;   window the request's principal may not act on.
cmd_verb_raise:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, rdi                       ; the request
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    mov  rdi, [rbx + REQ_ARG]
.arg_space:
    cmp  byte [rdi], ' '
    jne  .arg
    inc  rdi
    jmp  .arg_space
.arg:
    cmp  byte [rdi], 'G'
    je   .guest
    cmp  byte [rdi], 'g'
    je   .guest
    call wmx_next_token_u32
    mov  r12d, eax
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .ok
    cmp  eax, WM_MIN
    je   .ok
    jmp  .bad
.ok:
    mov  rdi, rbx
    mov  esi, r12d
    call wmx_req_may_act
    test eax, eax
    jnz  .denied
    mov  edi, r12d
    call wmx_raise_slot
    call chat_out_reset
    lea  rdi, [rel str_rs_ok]           ; " raise=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    jmp  .stage
.guest:
    ; Exact bounded spelling. A malformed named argument must not become slot0.
    cmp  dword [rdi], 'GUES'
    jne  .bad
    cmp  word [rdi + 4], 'T'
    jne  .bad
    mov  rdi, rbx
    call session_shell_request_principal
    cmp  rax, PRIN_OWNER                    ; compare all64 bits of this request
    jne  .denied
    call guest_desktop_show
    mov  r12d, [rel gd_slot]
    push rax
    call chat_out_reset
    pop  rax
    lea  rdi, [rel str_rs_guest_unavailable]
    cmp  eax, 1
    je   .guest_text
    lea  rdi, [rel str_rs_guest_full]
    cmp  eax, 2
    je   .guest_text
    lea  rdi, [rel str_rs_guest_shown]
.guest_text:
    call chat_put_str
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_rs_bad]          ; " raise=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    jmp  .out
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out
.denied:
    mov  rsi, r13
    call wmx_stage_denied
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: WINMOVE <idx> <x> <y> — move a live window; closed/free idx -> ERR.
; SEC-winmove-no-owner-check (root 14:27:32): RAISE's gates. Under the lock
; " session=locked"; a slot the request's principal may not act on (chrome,
; or another principal's for a non-owner) " window=ERR denied", CMDE_AUTHDENY.
cmd_verb_winmove:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  rbx, rdi                       ; the request (SEC-winmove-no-owner-check)
    call session_shell_require_unlocked ; nothing moves or resizes under the lock (as RAISE / ALTTAB / WINNEW)
    test eax, eax
    jnz  .locked
    mov  r14, [rbx + REQ_ARG]
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r12d, eax                      ; idx
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r15d, eax                      ; x
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r14d, eax                      ; y
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .ok
    cmp  eax, WM_MIN
    je   .ok
    jmp  .bad
.ok:
    mov  rdi, rbx
    mov  esi, r12d
    call wmx_req_may_act                ; the RAISE check: chrome (the action card) never, the owner any other
    test eax, eax                       ; slot, any other principal only its own
    jnz  .denied
    mov  edi, r12d
    mov  esi, r15d
    mov  edx, r14d
    call wmx_move_slot
    call chat_out_reset
    lea  rdi, [rel str_wmv_ok]          ; " winmove=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_wg_x]
    call chat_put_str
    lea  rcx, [rel wm_x]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wg_y]
    call chat_put_str
    lea  rcx, [rel wm_y]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_wmv_bad]         ; " winmove=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    jmp  .out
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out
.denied:
    mov  rsi, r13
    call wmx_stage_denied
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: WINRESIZE <idx> <w> <h> — resize a live window; closed/free idx -> ERR.
; The same gates as WINMOVE (SEC-winmove-no-owner-check).
cmd_verb_winresize:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  rbx, rdi                       ; the request (SEC-winmove-no-owner-check)
    call session_shell_require_unlocked ; nothing moves or resizes under the lock (as RAISE / ALTTAB / WINNEW)
    test eax, eax
    jnz  .locked
    mov  r14, [rbx + REQ_ARG]
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r12d, eax                      ; idx
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r15d, eax                      ; w
    mov  r14, rdi
    mov  rdi, r14
    call wmx_next_token_u32
    mov  r14d, eax                      ; h
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .ok
    cmp  eax, WM_MIN
    je   .ok
    jmp  .bad
.ok:
    mov  rdi, rbx
    mov  esi, r12d
    call wmx_req_may_act                ; the RAISE check: chrome (the action card) never, the owner any other
    test eax, eax                       ; slot, any other principal only its own
    jnz  .denied
    mov  edi, r12d
    mov  esi, r15d
    mov  edx, r14d
    call wmx_resize_slot
    call chat_out_reset
    lea  rdi, [rel str_wrs_ok]          ; " winresize=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_wg_w]
    call chat_put_str
    lea  rcx, [rel wm_w]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wg_h]
    call chat_put_str
    lea  rcx, [rel wm_h]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_wrs_bad]         ; " winresize=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    jmp  .out
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out
.denied:
    mov  rsi, r13
    call wmx_stage_denied
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: WINGEOM <idx> — read back a window's geometry ("x=.. y=.. w=.. h=..").
;   Closed/free idx -> ERR. The content-grade for move/resize (not a latch).
cmd_verb_wingeom:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rdi, [rdi + REQ_ARG]
    call wmx_next_token_u32
    mov  r12d, eax
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_FREE
    je   .bad
    cmp  eax, WM_CLOSED
    je   .bad
    call chat_out_reset
    lea  rdi, [rel str_wg_x]            ; " x="
    call chat_put_str
    lea  rcx, [rel wm_x]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wg_y]            ; " y="
    call chat_put_str
    lea  rcx, [rel wm_y]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wg_w]            ; " w="
    call chat_put_str
    lea  rcx, [rel wm_w]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wg_h]            ; " h="
    call chat_put_str
    lea  rcx, [rel wm_h]
    mov  edi, [rcx + r12*4]
    call chat_put_dec
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_wg_bad]          ; " wingeom=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: ALTTAB — cycle focus to the next visible window.
cmd_verb_alttab:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    push rdi
    call session_shell_require_unlocked ; F2b-1: the lock keeps the keyboard
    pop  rdi
    test eax, eax
    jnz  .locked
    call wmx_frame_may_focus            ; F2b-2: it only moves the keyboard: OWNER only
    test eax, eax
    jnz  .denied
    call wmx_alttab_do
    call chat_out_reset
    lea  rdi, [rel str_at_ok]           ; " alttab=ok focused="
    call chat_put_str
    mov  edi, [rel wm_focus]
    call chat_put_dec
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    ret
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    pop  r13
    ret
.denied:
    mov  rsi, r13
    call wmx_stage_denied
    pop  r13
    ret

; VERB: FOCUSED — report the focused window and keyboard widget snapshot.
cmd_verb_focused:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    mov  edi, [rel wm_focus]
    call wgt_focus_window
    call chat_out_reset
    lea  rdi, [rel str_fc_pre]          ; " FOCUSED="
    call chat_put_str
    mov  edi, [rel wm_focus]
    call chat_put_dec
    lea  rdi, [rel str_fc_widget]
    call chat_put_str
    mov  edi, [rel wgt_focus_id]
    call chat_put_dec
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    ret

; ---------------------------------------------------------------------------
; wmx_declare — register the 7 WM-geometry verbs through the ONE registry.
; ---------------------------------------------------------------------------
wmx_declare:
    lea  rdi, [rel wmx_history_target]  ; RC-history r3: the store judges windows by this registry only
    call history_set_window_check
    lea  rdi, [rel str_verb_winnew]
    lea  rsi, [rel cmd_verb_winnew]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_raise]
    lea  rsi, [rel cmd_verb_raise]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_winmove]
    lea  rsi, [rel cmd_verb_winmove]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_winresize]
    lea  rsi, [rel cmd_verb_winresize]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_wingeom]
    lea  rsi, [rel cmd_verb_wingeom]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_alttab]
    lea  rsi, [rel cmd_verb_alttab]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_focused]
    lea  rsi, [rel cmd_verb_focused]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

; ---------------------------------------------------------------------------
; wmx_selftest — boot self-exercise that EARNS the 4 markers on a scratch slot,
;   then frees it (leaving the boot desktop = A/B/chat). Verifies each op's
;   effect on the wm_* table (focus moved / geometry changed) before emitting —
;   earned, no latch. No framebuffer -> honest skip. Runs after chat_app_init.
; ---------------------------------------------------------------------------
wmx_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .nofb
    ; (1) multi-window: count visible slots (A/B/chat = 3 at boot)
    xor  r12d, r12d
    xor  r13d, r13d                     ; count
.cnt:
    cmp  r12d, WM_MAX
    jae  .cntdone
    lea  rax, [rel wm_state]
    cmp  dword [rax + r12*4], WM_VISIBLE
    jne  .cntnext
    inc  r13d
.cntnext:
    inc  r12d
    jmp  .cnt
.cntdone:
    cmp  r13d, 2
    jl   .ops
    mov  byte [rel wm2_m_multi], 1
    lea  rdi, [rel str_wm2_multi]
    call serial_string
.ops:
    ; scratch slot for the raise/move/resize/alttab exercise
    call wmx_find_free_slot
    cmp  eax, 0
    jl   .cleanup_focus
    mov  r12d, eax                      ; scratch slot
    lea  rcx, [rel wm_x]
    mov  dword [rcx + r12*4], 720
    lea  rcx, [rel wm_y]
    mov  dword [rcx + r12*4], 430
    lea  rcx, [rel wm_w]
    mov  dword [rcx + r12*4], 160
    lea  rcx, [rel wm_h]
    mov  dword [rcx + r12*4], 120
    mov  eax, r12d
    lea  rcx, [rel wm_title]
    lea  rdx, [rel str_wm2_scratch]
    mov  [rcx + rax*8], rdx
    lea  rcx, [rel wm_state]
    mov  dword [rcx + r12*4], WM_VISIBLE
    mov  edi, r12d
    call wmx_owner_clear                ; F2: a boot selftest window is the owner's
    ; (2) z-order: focus something else, then RAISE scratch -> focus must move
    mov  dword [rel wm_focus], 0
    mov  edi, r12d
    call wmx_raise_slot
    mov  eax, [rel wm_focus]
    cmp  eax, r12d
    jne  .skip_z
    mov  byte [rel wm2_m_zorder], 1
    lea  rdi, [rel str_wm2_zorder]
    call serial_string
.skip_z:
    ; (3) move + resize -> wm_x/wm_w must match the commanded values
    mov  edi, r12d
    mov  esi, 700
    mov  edx, 440
    call wmx_move_slot
    mov  edi, r12d
    mov  esi, 200
    mov  edx, 150
    call wmx_resize_slot
    lea  rcx, [rel wm_x]
    cmp  dword [rcx + r12*4], 700
    jne  .skip_mr
    lea  rcx, [rel wm_w]
    cmp  dword [rcx + r12*4], 200
    jne  .skip_mr
    mov  byte [rel wm2_m_moveresize], 1
    lea  rdi, [rel str_wm2_mr]
    call serial_string
.skip_mr:
    ; (4) alt-tab from scratch -> focus must land on a different visible window
    mov  r13d, [rel wm_focus]
    call wmx_alttab_do
    mov  eax, [rel wm_focus]
    cmp  eax, r13d
    je   .skip_at
    mov  byte [rel wm2_m_alttab], 1
    lea  rdi, [rel str_wm2_at]
    call serial_string
.skip_at:
    ; free the scratch slot + erase its footprint (boot desktop = A/B/chat)
    lea  rcx, [rel wm_state]
    mov  dword [rcx + r12*4], WM_FREE
    mov  edi, r12d
    call wmx_owner_clear
    call wm_erase_slot
.cleanup_focus:
    mov  dword [rel wm_focus], CHAT_SLOT
    call wmx_draw_all
    jmp  .ret
.nofb:
    lea  rdi, [rel str_wm2_nofb]
    call serial_string
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; data
; ---------------------------------------------------------------------------
; verb names
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_window_mgmt_0 0
str_verb_winnew:    db "WINNEW", 0
str_verb_raise:     db "RAISE", 0
str_verb_winmove:   db "WINMOVE", 0
str_verb_winresize: db "WINRESIZE", 0
str_verb_wingeom:   db "WINGEOM", 0
str_verb_alttab:    db "ALTTAB", 0
str_wmx_locked:     db " session=locked", 0
str_wmx_denied:     db " window=ERR denied", 0
str_verb_focused:   db "FOCUSED", 0

; staged-reply fragments (into chat_out_buf)
str_wn_ok:      db " winnew=ok idx=", 0
str_wn_full:    db " winnew=ERR no_free_slot", 0
str_rs_ok:      db " raise=ok idx=", 0
str_rs_bad:     db " raise=ERR bad_idx", 0
str_rs_guest_shown: db " guest_window=shown",0
str_rs_guest_unavailable: db " guest_window=ERR unavailable",0
str_rs_guest_full: db " guest_window=ERR no_free_slot",0
str_wmv_ok:     db " winmove=ok idx=", 0
str_wmv_bad:    db " winmove=ERR bad_idx", 0
str_wrs_ok:     db " winresize=ok idx=", 0
str_wrs_bad:    db " winresize=ERR bad_idx", 0
str_wg_x:       db " x=", 0
str_wg_y:       db " y=", 0
str_wg_w:       db " w=", 0
str_wg_h:       db " h=", 0
str_wg_bad:     db " wingeom=ERR bad_idx", 0
str_at_ok:      db " alttab=ok focused=", 0
str_fc_pre:     db " FOCUSED=", 0
str_fc_widget:  db " widget=", 0

; scratch-window title (boot selftest)
str_wm2_scratch: db "wmtest", 0

; boot markers (serial; the BOOTLOG-gated UDP tokens are str_udp_wm2_* below)
str_wm2_multi:  db "[PAOS64] M6 wm: compositor >=2 visible windows [wm.multi_window]", 13, 10, 0
str_wm2_zorder: db "[PAOS64] M6 wm: RAISE moved focus to the raised slot [wm.zorder.raise]", 13, 10, 0
str_wm2_mr:     db "[PAOS64] M6 wm: WINMOVE+WINRESIZE changed geometry to commanded [wm.move_resize]", 13, 10, 0
str_wm2_at:     db "[PAOS64] M6 wm: ALTTAB cycled focus to another window [wm.alttab]", 13, 10, 0
str_wm2_nofb:   db "[PAOS64] M6 wm: no framebuffer (GOP absent), window-mgmt selftest skipped", 13, 10, 0

; BOOTLOG-gated tokens (framed by command_udp.asm on the BOOTLOG reply only)
str_udp_wm2_multi:  db " wm.multi_window", 0
str_udp_wm2_zorder: db " wm.zorder.raise", 0
str_udp_wm2_mr:     db " wm.move_resize", 0
str_udp_wm2_at:     db " wm.alttab", 0

; earned marker flags (set by wmx_selftest; read by command_udp's BOOTLOG block)
wm2_m_multi:      db 0
wm2_m_zorder:     db 0
wm2_m_moveresize: db 0
wm2_m_alttab:     db 0

; per-slot title buffers for NEW windows (runtime lea-filled wm_title ptrs)
align 8
align 8
wmx_move_tsc_start: dq 0                 ; TSC at the start of the current move/resize
wmx_erase_tsc:      dq 0                 ; cycles of the last old-footprint erase
wmx_draw_tsc:       times WM_MAX dq 0    ; cycles of the last wmx_draw_one per slot
wmx_move_tsc_last:  dq 0                 ; cycles the last pointer-driven move/resize took
wmx_move_tsc_max:   dq 0                 ; worst since boot (INPUTSET reset clears)
wmx_bad_slots:      dd 0                 ; out-of-range slots refused at a mutator entry
wm_recent_clock:    dq 0                 ; shared session-only focus/launch order
wm_recent_seq:      times WM_MAX dq 0
wmx_owner_reset_op: dq 0                ; trusted window-lifetime observer, no authority
wm_owner:           times WM_MAX dq 0    ; F2: per-slot owner principal (0 unowned, WM_OWNER_CHROME)
wm_native_gen:      times WM_MAX dq 0    ; RC-task-manager: bound native module generation
wm_native_slot:     times WM_MAX dd -1   ; bound native module slot, -1 = none (not a pointer table)
wmx_native_leaked:  dd 0                 ; unbinds whose unregister the ABI refused
wm_native_stuck:    times WM_MAX db 0    ; STUCK latched for this window (no auto-retry)
wm_gen:             times WM_MAX dd 0    ; RC-history r3: per-slot identity generation (bumped at every owner stamp)
wm_no_history:      times WM_MAX db 0    ; RC-history r3: the browser's no-history mark (bank mode, private)
wmx_draw_defer_depth: db 0                ; balanced by wmx_draw_defer_begin/end
wmx_draw_pending: db 0                    ; consumed once by the top-level idle loop
wmx_geom_old_x: dd 0                     ; origin before a move/maximize (widget delta shift)
wmx_geom_old_w: dd 0                     ; size before a resize/maximize (widget anchoring)
wmx_geom_old_h: dd 0
wmx_boot_marks_cleared: db 0             ; the boot proofs in the top-left corner are gone
str_wmx_boot_marks: db "[PAOS64] M6 gui: boot proofs retired from the desktop (first human pointer event / DESKCLEAN)", 13, 10, 0
wmx_geom_old_y: dd 0
wmx_hover_slot: dd -1
%endmacro
WDATA_DEFER WDATA_gui_window_mgmt_0
WM_CHROME_STANDARD equ 0
WM_OWNER_CHROME    equ -1               ; F2: wm_owner value no request may act on
WM_CHROME_TABS     equ 1
wm_chrome:      times WM_MAX db 0   ; per slot: WM_CHROME_*
wm_resizable:   times WM_MAX db 1   ; B4: per slot: 0 = the form declared resizable=0 (no resize border)
align 4
wm_min_w:       times WM_MAX dd WMX_USER_MIN_W  ; B4: per-slot user-resize floor (form min_w, >= WMX_USER_MIN_W)
wm_min_h:       times WM_MAX dd WMX_USER_MIN_H
wmx_hover_part: db 0
align 8
wmx_titles:     times (WM_MAX * WMX_TITLE_MAX) db 0
wm_app_title:   times WM_MAX dq 0       ; T4: per slot app-owned label cstr (0 = wm_title)
wmx_title_disp: times WMX_TITLE_DISP_MAX db 0   ; B3: '_' -> ' ' copy for the painters
