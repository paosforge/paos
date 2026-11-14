;; MODULE gui/chat_app
;; LAYER 6
;; EXPORTS chat_app_init, chat_app_tick, chat_declare, chat_process, fb_draw_char, fb_draw_str_n, sec_text_escape, sec_text_escape_row, fb_draw_scalar, fb_draw_wide16, wm_repaint_all, wm_zstamp, wm_zcounter, chat_out_buf, chat_out_ready
;; IMPORTS boot/serial, boot/gop, gui/window, gui/window_mgmt, gui/cadence_mark, svc/command, core/native_app, core/lib/fmt, core/lib/str
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/chat_app.asm — C17 (1017) desktop_chat_tile: the 2nd independent app
; window through the C16 compositor + a 1-turn local-model chat tile.
;
; What this module proves (the SEAM, DESKTOP.md degenerate-second test):
;   1. The WM supports 2+ app windows with focus/z-order/min/max/close — a
;      real WINDOW TABLE (state/geometry/title per slot) now backs the C16
;      painted floor, and the chat tile is the second app riding it.
;   2. Widget composition (DESKTOP.md §3.5): the chat tile is a WIDGET —
;      its own surface (window + REAL 8x16 glyph text, font PORTED from the
;      proven monolith) + its own function (1-turn Q->A) + its own network
;      verbs, independently summonable, no WM-core edit.
;   3. Local-model binding: the tile routes non-arithmetic queries to the
;      1061 cognition engine (cognition/gpt2_engine.asm) when a real model
;      is present (cog_model_present, QEMU numeric rung), and DEGRADES
;      HONESTLY to the built-in evaluator + "offline" status when the
;      327MB weights are absent (always true on bare metal until 1061b
;      lands the disk streamer) — offline widget, never a crash.
;
; 1-turn known-answer path (contract done_when: "reply text matching
; known-answer table"): the tile parses the first "<u32> + <u32>" in the
; query and answers "N+M=S" — so the probe's "What is 2+2?" earns a REAL
; computed "4", not a latch. The random probe nonce rides in the query and
; is reflected by CHAT_GETTEXT from the SAME chat_q_buf the window renders.
;
; Verbs (7, ARGT_TEXT, registered through the ONE 1077 registry — additive):
;   CHAT_SENDTEXT <text> -> run a 1-turn query ("chat send=ok len=N mode=M");
;                           oversize input (>CHAT_IN_MAX) -> "ERR BLOCKED"
;   CHAT_GETTEXT         -> " chat text: Q=<query> A=<answer> mode=<m>"
;   WINDOWS              -> one "WIN[i] title=T state=S" line per live slot
;   FOCUS/MIN/MAX/CLOSE <idx> -> WM ops on a slot ("<op>=ok idx=N ..." or
;                           "<op>=ERR bad_idx"); close of the chat slot arms
;                           the living-tile respawn (chat_app_tick, ~8s)
;
; Markers (BOOTLOG-gated in command_udp.asm — the token "chat_app" must not
; ride a WINDOWS reply, the probe greps case-insensitive "Chat" for absence
; after CLOSE):
;   desktop.chat_app.init         window table + chat tile drawn
;   desktop.chat_app.local_model  model seam probed (present | offline)
;   desktop.chat_app.1turn_ready  boot self-turn "2 + 2" -> "4" verified
;
; Window A/B geometry mirrors gui/window.asm EXACTLY (LOAD-BEARING: verify_gui
; samples their title bars at A(150,130)/B(380,225)); repaints reuse the same
; coords. The chat window (640,100 320x260) stays clear of both samples and
; fits 1024x768 (bare-metal GLKVM) and 1280x800 (QEMU).
; ============================================================================

CHAT_WIN_X   equ 640
CHAT_WIN_Y   equ 100
CHAT_WIN_W   equ 320
CHAT_WIN_H   equ 260
CHAT_IN_MAX  equ 200                   ; longest accepted CHAT_SENDTEXT text
CHAT_RESPAWN_MS equ 8000               ; living-tile respawn delay after CLOSE
; RC-task-manager: the chat module's arena record (chat_process / chat_native_entry)
CNA_Q        equ 0                      ; query, NUL-ended (CHAT_IN_MAX + 8)
CNA_MODEL    equ CHAT_IN_MAX + 8        ; in: cog_model_present
CNA_MODE     equ CNA_MODEL + 1          ; out: CHAT_MODE_*
CNA_ANS      equ CNA_MODEL + 8          ; out: "A+B=S" (CHAT_MODE_EVAL only)
CNA_SIZE     equ CNA_ANS + CHAT_ANS_MAX
CHAT_MODE_EVAL equ 1
CHAT_MODE_GPT2 equ 2
CHAT_MODE_OFF  equ 3

WM_MAX       equ 16                   ; G9 (burn-down 6, ADMIN 2026-10-02): was 8. A/B/chat reserved + LOCK_SLOT (= WM_MAX-1, lock_screen.asm); the rest free for NEW windows
WM_FREE      equ 0
WM_VISIBLE   equ 1
WM_MIN       equ 2
WM_CLOSED    equ 3
CHAT_SLOT    equ 2

CHAT_TXT_FG  equ 0x00E0E0E0            ; light text on the slate window body
CHAT_TTL_FG  equ 0x00FFFFFF            ; white title text on the title bar
CHAT_IN_BG   equ 0x00E0E0E0            ; light input-field strip
CHAT_IN_FG   equ 0x00101010            ; dark text in the input field

; ---------------------------------------------------------------------------
; fb_draw_char — render one 8x16 glyph into the linear framebuffer.
;   r8d=x, r9d=y, edx=ascii, ebx=fg BGRX, ecx=bg BGRX. Preserves all args.
;   Skips (clip) if the cell would cross the screen edge or fb is absent.
;   Renderer PORTED from the monolith's proven fb_char (M16), re-seamed onto
;   the rework's fb_base/fb_stride (direct present — the rework floor has no
;   full-screen back buffer; the double-buffer tile proof lives in window.asm).
; ---------------------------------------------------------------------------
fb_draw_char:
    push rax
    push rsi
    push rdi
    push r10
    push r11
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done                          ; no GOP -> nothing to draw (degrade)
    ; Solid cells are refused whole at every edge, before address arithmetic.
    test r8d, r8d
    js   .done
    test r9d, r9d
    js   .done
    mov  eax, r8d
    add  eax, 8
    cmp  eax, [rel fb_width]
    ja   .done                          ; right-edge clip
    mov  eax, r9d
    add  eax, 16
    cmp  eax, [rel fb_height]
    ja   .done                          ; bottom-edge clip
    ; glyph = font_8x16 + (ascii & 0x7F..0xFF) * 16 (blank >0x7F rows are 0)
    movzx eax, dl
    shl  eax, 4
    lea  rsi, [rel font_8x16]
    add  rsi, rax
    ; dst = fb_base + (y*stride + x)*4
    ; Coordinates and pitch are 32-bit inputs; retain the full pixel index.
    mov  eax, [rel fb_stride]
    mov  r10d, r9d
    imul rax, r10
    mov  r10d, r8d
    add  rax, r10
    mov  rdi, [rel fb_base]
    lea  rdi, [rdi + rax*4]
    mov  r10d, 16                       ; row counter
.row:
    movzx eax, byte [rsi]
    inc  rsi
    push rdi
    mov  r11d, 8                        ; pixel counter, MSB = leftmost
.px:
    test al, 0x80
    jz   .bg
    mov  [rdi], ebx                     ; fg pixel
    jmp  .nx
.bg:
    mov  [rdi], ecx                     ; bg pixel (solid cell: clean overdraw)
.nx:
    shl  al, 1
    add  rdi, 4
    dec  r11d
    jnz  .px
    pop  rdi
    mov  eax, [rel fb_stride]
    lea  rdi, [rdi + rax*4]             ; next row
    dec  r10d
    jnz  .row
    mov  r10d, 8                        ; 2026-09-08: note the cell for the back buffer present
    mov  r11d, 16
    call fb_damage_rect
.done:
    pop  r11
    pop  r10
    pop  rdi
    pop  rsi
    pop  rax
    ret

; ---------------------------------------------------------------------------
; fb_draw_scalar — fb_draw_char for one Unicode scalar: EDX = U+0000..U+017F
;   draws that scalar's own font_8x16 cell (U+0100..U+017F is font_8x16_ext_a,
;   contiguous at font_8x16 + 4096); a larger scalar draws nothing (the caller
;   boxes it). r8d=x, r9d=y, ebx=fg, ecx=bg. RCQ-38 L3b, the first reader of
;   Latin Extended-A. Preserves every register.
; ---------------------------------------------------------------------------
FONT8X16_SCALARS equ 0x180               ; gui/font8x16.inc: U+0000..U+017F, 16 B a cell (pinned by a row)
fb_draw_scalar:
    cmp  edx, FONT8X16_SCALARS
    jae  .out
    push rax
    push rsi
    push rdi
    push r10
    push r11
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done
    ; Solid cells are refused whole at every edge, before address arithmetic.
    test r8d, r8d
    js   .done
    test r9d, r9d
    js   .done
    mov  eax, r8d
    add  eax, 8
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, 16
    cmp  eax, [rel fb_height]
    ja   .done
    mov  eax, edx
    shl  eax, 4
    lea  rsi, [rel font_8x16]
    add  rsi, rax
    ; Coordinates and pitch are 32-bit inputs; retain the full pixel index.
    mov  eax, [rel fb_stride]
    mov  r10d, r9d
    imul rax, r10
    mov  r10d, r8d
    add  rax, r10
    mov  rdi, [rel fb_base]
    lea  rdi, [rdi + rax*4]
    mov  r10d, 16
.row:
    movzx eax, byte [rsi]
    inc  rsi
    push rdi
    mov  r11d, 8
.px:
    test al, 0x80
    jz   .bg
    mov  [rdi], ebx
    jmp  .nx
.bg:
    mov  [rdi], ecx
.nx:
    shl  al, 1
    add  rdi, 4
    dec  r11d
    jnz  .px
    pop  rdi
    mov  eax, [rel fb_stride]
    lea  rdi, [rdi + rax*4]
    dec  r10d
    jnz  .row
    mov  r10d, 8
    mov  r11d, 16
    call fb_damage_rect
.done:
    pop  r11
    pop  r10
    pop  rdi
    pop  rsi
    pop  rax
.out:
    ret

; ---------------------------------------------------------------------------
; fb_draw_wide16 — one 16x16 1bpp wide glyph: RSI = its 32 B bitmap (16 rows
;   of 2 bytes, MSB = leftmost pixel: the VT wide-cell layout), r8d=x, r9d=y,
;   ebx=fg, ecx=bg. Two 8 px cells; the whole glyph clips at the right/bottom
;   edge like fb_draw_char. RCQ-38 l10n L2: gui/l10n_paint's CJK cell, from
;   the embedded UI subset (gui/l10n_glyphs.inc). Preserves every register.
; ---------------------------------------------------------------------------
fb_draw_wide16:
    push rax
    push rsi
    push rdi
    push r10
    push r11
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done
    ; Solid cells are refused whole at every edge, before address arithmetic.
    test r8d, r8d
    js   .done
    test r9d, r9d
    js   .done
    mov  eax, r8d
    add  eax, 16
    cmp  eax, [rel fb_width]
    ja   .done
    mov  eax, r9d
    add  eax, 16
    cmp  eax, [rel fb_height]
    ja   .done
    ; Coordinates and pitch are 32-bit inputs; retain the full pixel index.
    mov  eax, [rel fb_stride]
    mov  r10d, r9d
    imul rax, r10
    mov  r10d, r8d
    add  rax, r10
    mov  rdi, [rel fb_base]
    lea  rdi, [rdi + rax*4]
    mov  r10d, 16
.row:
    movzx eax, word [rsi]
    xchg al, ah                         ; big-endian row: the first byte is the left half
    add  rsi, 2
    push rdi
    mov  r11d, 16
.px:
    test ax, 0x8000
    jz   .bg
    mov  [rdi], ebx
    jmp  .nx
.bg:
    mov  [rdi], ecx
.nx:
    shl  ax, 1
    add  rdi, 4
    dec  r11d
    jnz  .px
    pop  rdi
    mov  eax, [rel fb_stride]
    lea  rdi, [rdi + rax*4]
    dec  r10d
    jnz  .row
    mov  r10d, 16
    mov  r11d, 16
    call fb_damage_rect
.done:
    pop  r11
    pop  r10
    pop  rdi
    pop  rsi
    pop  rax
    ret

; ---------------------------------------------------------------------------
; fb_draw_str_n — draw a NUL-terminated string, at most r11d chars.
;   rdi=cstr, r8d=x, r9d=y, ebx=fg, ecx=bg, r11d=max chars.
;   Returns with r8d advanced past the drawn text (chainable), r11d spent.
; ---------------------------------------------------------------------------
fb_draw_str_n:
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
    shl  ecx, 3                        ; 8 pixels per 1x glyph
    mov  eax, 16
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
    push r12
    mov  r12, rdi
.next:
    test r11d, r11d
    jz   .done
    movzx edx, byte [r12]
    test dl, dl
    jz   .done
    call fb_draw_char
    add  r8d, 8
    inc  r12
    dec  r11d
    jmp  .next
.done:
    pop  r12
    pop  rdx
    ret

; ---------------------------------------------------------------------------
; sec_text_escape(RSI src, EDX src max bytes, RDI out, ECX out cap incl. NUL)
;   -> EAX bytes written before the NUL. rc-sec N1 (2026-10-10 10:56:48): THE
;   one escape every security text surface paints through (window titles on
;   the title bar, tab strip and taskbar; labels/buttons of chrome forms and of
;   the Power confirmation). 0x20..0x7E pass, except '\' (0x5C); every other
;   byte (C0, 7F, 80..FF incl. A0 NBSP and AD soft hyphen, each UTF-8 byte)
;   becomes the four cells '\xNN' (upper-case hex). So a surface never paints
;   such a byte blank, as Latin-1 or as '?', and a literal ASCII "\xA0" can
;   never look like an escaped NBSP. Stops at a NUL or after EDX bytes. A cut
;   lands only between whole units and ends in a visible '>'. NUL-terminates
;   whenever ECX >= 1. Preserves every register except RAX.
;   RULE (rc-sec 18:40:34 c4): any FUTURE chrome or confirmation text built
;   from runtime data (a device or volume label, an SSID, a file name in a
;   confirm) goes through this escape before it is painted. The census rows in
;   test_rcq38_l3a_sec_text_host (title readers, chrome stamp sites) name the
;   surfaces that do today.
; sec_text_escape_row: the same escape for a row of a ','-joined list (the
;   Summon list): ',' is a '\x2C' unit too, so a title holding ',' stays one
;   row and the pointer's row N stays item N (srcreview 19:21:29 C1).
; ---------------------------------------------------------------------------
sec_text_escape_row:
    push r11
    mov  r11d, ','
    jmp  sec_text_escape.body
sec_text_escape:
    push r11
    mov  r11d, -1                      ; no extra unit (EAX holds one byte)
.body:
    push rbx
    push rcx
    push rdx
    push rsi
    push r9
    push r10
    xor  ebx, ebx                      ; bytes written
    test ecx, ecx
    jz   .out                          ; no room even for the NUL
    lea  r9d, [rcx - 1]                ; room for text
.next:
    test edx, edx
    jz   .end
    movzx eax, byte [rsi]
    test eax, eax
    jz   .end
    mov  ecx, 4                        ; '\xNN'
    cmp  eax, '\'
    je   .fit
    cmp  eax, r11d                     ; the row entry's separator
    je   .fit
    cmp  eax, 0x20
    jb   .fit
    cmp  eax, 0x7E
    ja   .fit
    mov  ecx, 1
.fit:
    ; A unit must leave one byte for the '>' of a later cut; only the
    ; source's last unit may use that byte.
    lea  r10d, [rbx + rcx]
    cmp  r10d, r9d
    jb   .emit
    ja   .cut
    cmp  edx, 1
    je   .emit
    cmp  byte [rsi + 1], 0
    je   .emit
.cut:
    test r9d, r9d
    jz   .end                          ; cap 1: the empty string
    mov  byte [rdi + rbx], '>'
    inc  ebx
    jmp  .end
.emit:
    cmp  ecx, 1
    jne  .hex
    mov  [rdi + rbx], al
    inc  ebx
    jmp  .adv
.hex:
    mov  byte [rdi + rbx], '\'
    mov  byte [rdi + rbx + 1], 'x'
    mov  ecx, eax
    shr  ecx, 4
    add  ecx, '0'
    cmp  ecx, '9'
    jbe  .hi
    add  ecx, 'A' - '9' - 1
.hi:
    mov  [rdi + rbx + 2], cl
    and  eax, 0x0F
    add  eax, '0'
    cmp  eax, '9'
    jbe  .lo
    add  eax, 'A' - '9' - 1
.lo:
    mov  [rdi + rbx + 3], al
    add  ebx, 4
.adv:
    inc  rsi
    dec  edx
    jmp  .next
.end:
    mov  byte [rdi + rbx], 0
.out:
    mov  eax, ebx
    pop  r10
    pop  r9
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  r11
    ret

; ---------------------------------------------------------------------------
; chat_draw_window — compatibility wrapper: standard chrome is owned by the
; ONE wmx_paint_slot path; this module retains only its temporary app body.
; ---------------------------------------------------------------------------
chat_draw_window:
    push rdi
    CADENCE_BATCH_BEGIN
    mov  edi, CHAT_SLOT
    call wmx_paint_slot
    call chat_draw_body
    CADENCE_BATCH_END
    pop  rdi
    ret

chat_draw_body:
    push rbx
    push rcx
    push r8
    push r9
    push r11
    push r12
    push r13
    push r14
    push r15
    push rax
    movzx eax, word [rel cadence_region_current]
    push rax
    mov  word [rel cadence_region_current], CHAT_SLOT
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done
    ; Q line: "Q: " + query (first 34 chars — the full text is CHAT_GETTEXT's)
    mov  r8d, CHAT_WIN_X + 10
    mov  r9d, CHAT_WIN_Y + 56
    mov  ebx, CHAT_TXT_FG
    mov  ecx, WIN_BODY_COLOR
    mov  r11d, 37
    lea  rdi, [rel str_chat_qpre]
    call fb_draw_str_n
    lea  rdi, [rel chat_q_buf]
    call fb_draw_str_n
    ; A line: "A: " + answer
    mov  r8d, CHAT_WIN_X + 10
    mov  r9d, CHAT_WIN_Y + 80
    mov  r11d, 37
    lea  rdi, [rel str_chat_apre]
    call fb_draw_str_n
    lea  rdi, [rel chat_ans_buf]
    call fb_draw_str_n
    ; model-status line
    mov  r8d, CHAT_WIN_X + 10
    mov  r9d, CHAT_WIN_Y + 104
    mov  r11d, 37
    lea  rdi, [rel str_chat_mpre]
    call fb_draw_str_n
    mov  rdi, [rel chat_mode_ptr]
    call fb_draw_str_n
    ; input field strip near the bottom of the body
    mov  r8d, CHAT_WIN_X + 8
    mov  r9d, CHAT_WIN_Y + CHAT_WIN_H - 40
    mov  r10d, CHAT_WIN_W - 16
    mov  r11d, 24
    mov  ebx, CHAT_IN_BG
    call fb_fill_rect
    ; "> " + query tail inside the input field
    mov  r8d, CHAT_WIN_X + 12
    mov  r9d, CHAT_WIN_Y + CHAT_WIN_H - 36
    mov  ebx, CHAT_IN_FG
    mov  ecx, CHAT_IN_BG
    mov  r11d, 36
    lea  rdi, [rel str_chat_prompt]
    call fb_draw_str_n
    lea  rdi, [rel chat_q_buf]
    call fb_draw_str_n
.done:
    pop  rax
    mov  [rel cadence_region_current], ax
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r9
    pop  r8
    pop  rcx
    pop  rbx
    ret

; wm_erase_slot(edi=idx) — fill the slot's rect with the desktop backdrop.
wm_erase_slot:
    cmp  edi, WM_MAX                    ; (MSI spoke 386ee66f7) never erase an out-of-range slot
    jae  .bad_slot
    push rbx
    push r8
    push r9
    push r10
    push r11
    push rax
    movzx eax, word [rel cadence_region_current]
    push rax
    mov  [rel cadence_region_current], di
    mov  eax, edi
    lea  rcx, [rel wm_x]
    mov  r8d, [rcx + rax*4]
    lea  rcx, [rel wm_y]
    mov  r9d, [rcx + rax*4]
    lea  rcx, [rel wm_w]
    mov  r10d, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    mov  r11d, [rcx + rax*4]
    mov  ebx, DESKTOP_COLOR
    call fb_fill_rect
    pop  rax
    mov  [rel cadence_region_current], ax
    pop  rax
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbx
    ret
.bad_slot:
    ret

; Compatibility entry for older chat/resolution callers. The A/B bespoke
; painters are retired: every slot now reaches the one standard painter via
; wmx_draw_all -> wmx_draw_one -> wmx_paint_slot.
wm_repaint_all:
    jmp  wmx_draw_all

; ---------------------------------------------------------------------------
; chat_parse_u32(RDI=ptr) -> RAX = leading decimal value, RDI past the digits.
; ---------------------------------------------------------------------------
chat_parse_u32:
    xor  eax, eax
.loop:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul eax, eax, 10
    add  eax, ecx
    inc  rdi
    jmp  .loop
.done:
    ret

; ---------------------------------------------------------------------------
; chat_process(RDI=query cstr) — the ONE 1-turn path (boot selftest, verbs):
;   copy the query (bounded), answer via (a) the built-in evaluator (first
;   "<u32> + <u32>" -> "N+M=S"), else (b) the 1061 local model when present
;   (v1 single-turn: the boot-KAT argmax, same reuse MODELRUN v1 documents),
;   else (c) the honest offline notice. Then redraw the tile if visible.
;   RC-task-manager (spec 21.2.7): the evaluator is the tile's native module,
;   run under the core/native_app watchdog through the WM binding of CHAT_SLOT.
;   Trusted code stages the query, and commits the module's answer only after a
;   dispatch that returned 0. A stuck or refused module answers honestly and
;   never runs inline. The boot selftest alone (chat_boot_inline: before the
;   lease timer is calibrated and before any desktop) calls the entry inline.
; ---------------------------------------------------------------------------

chat_process:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    ; bounded copy query -> chat_q_buf (the tile's Q: line)
    lea  rdi, [rel chat_q_buf]
    mov  rsi, r12
    mov  ecx, CHAT_IN_MAX
.qcopy:
    test ecx, ecx
    jz   .qdone
    mov  al, [rsi]
    test al, al
    jz   .qdone
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .qcopy
.qdone:
    mov  byte [rdi], 0
    cmp  byte [rel chat_boot_inline], 1
    je   .boot
    mov  edi, CHAT_SLOT
    call wmx_native_arena
    test rax, rax
    jnz  .have_arena
    lea  rdi, [rel chat_native_entry]   ; first turn, or after a close: bind the module
    call native_app_register
    test rax, rax
    js   .refused
    push rax                            ; native slot
    push rdx                            ; its generation
    mov  edi, CHAT_SLOT
    mov  esi, eax
    call wmx_native_bind
    pop  rsi
    pop  rdi
    test eax, eax
    jz   .bound
    call native_app_unregister          ; srcreview 53367 F2: no WM binding holds it, so free the record now
    jmp  .refused                       ; (same context as the register above: the ABI cannot refuse it)
.bound:
    mov  edi, CHAT_SLOT
    call wmx_native_arena
    test rax, rax
    jz   .refused
.have_arena:
    mov  rbx, rax
    call chat_native_stage
    mov  edi, CHAT_SLOT
    call wmx_native_dispatch
    test eax, eax
    jz   .commit
    cmp  eax, 1
    je   .stuck
    jmp  .refused
.boot:
    lea  rbx, [rel chat_boot_arena]
    call chat_native_stage
    mov  rdi, rbx
    mov  esi, CNA_SIZE
    call chat_native_entry
.commit:
    movzx eax, byte [rbx + CNA_MODE]
    cmp  eax, CHAT_MODE_EVAL
    je   .eval
    cmp  eax, CHAT_MODE_GPT2
    je   .gpt2
    cmp  eax, CHAT_MODE_OFF
    jne  .refused                       ; anything else from the arena is no answer
    call chat_ans_reset
    lea  rdi, [rel str_chat_offa]       ; "model offline (eval-only tile)"
    call chat_ans_str
    lea  rax, [rel str_mode_off]
    jmp  .answered
.eval:
    call chat_ans_reset
    mov  byte [rbx + CNA_ANS + CHAT_ANS_MAX - 1], 0
    lea  rdi, [rbx + CNA_ANS]
    call chat_ans_str
    lea  rax, [rel str_mode_eval]
    jmp  .answered
.gpt2:
    call chat_ans_reset
    lea  rdi, [rel str_chat_gpt2a]      ; "gpt2 1-turn ref token="
    call chat_ans_str
    mov  edi, [rel cog_kat_argmax]
    call chat_ans_dec
    lea  rax, [rel str_mode_gpt2]
    jmp  .answered
.stuck:
    call chat_ans_reset
    lea  rdi, [rel str_chat_stuck]
    call chat_ans_str
    lea  rax, [rel str_mode_stuck]
    jmp  .answered
.refused:
    call chat_ans_reset
    lea  rdi, [rel str_chat_refused]
    call chat_ans_str
    lea  rax, [rel str_mode_refused]
.answered:
    mov  [rel chat_mode_ptr], rax
    cmp  dword [rel wm_state + CHAT_SLOT*4], WM_VISIBLE
    jne  .ret
    call chat_draw_window
.ret:
    pop  r13
    pop  r12
    pop  rbx
    ret

; chat_native_stage(RBX=arena): trusted input staging. Clobbers RAX, RCX, RSI, RDI.
chat_native_stage:
    lea  rdi, [rbx + CNA_Q]
    lea  rsi, [rel chat_q_buf]
    mov  ecx, CHAT_IN_MAX + 8
    cld
    rep  movsb
    mov  byte [rbx + CNA_Q + CHAT_IN_MAX], 0
    movzx eax, byte [rel cog_model_present]
    mov  [rbx + CNA_MODEL], al
    mov  byte [rbx + CNA_MODE], 0
    mov  byte [rbx + CNA_ANS], 0
    ret

; chat_native_entry(RDI=arena, RSI=size): the tile's native module. Pure: it
;   reads and writes only its arena and calls nothing outside this module
;   (chat_parse_u32 and chat_native_dec touch registers only). Returns 0.
chat_native_entry:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  byte [rbx + CNA_Q + CHAT_IN_MAX], 0 ; the scan never leaves the arena
    mov  byte [rbx + CNA_ANS], 0
    ; --- (a) evaluator: scan for the first "<u32> + <u32>" ---
    lea  r13, [rbx + CNA_Q]
.scan:
    movzx eax, byte [r13]
    test al, al
    jz   .no_arith
    sub  eax, '0'
    cmp  eax, 9
    jbe  .num
    inc  r13
    jmp  .scan
.num:
    mov  rdi, r13
    call chat_parse_u32
    mov  r14d, eax                      ; A
    mov  r13, rdi                       ; resume point (past digits: progress)
.sp1:
    cmp  byte [rdi], ' '
    jne  .plus
    inc  rdi
    jmp  .sp1
.plus:
    cmp  byte [rdi], '+'
    jne  .scan                          ; not "A +" -> keep scanning from r13
    inc  rdi
.sp2:
    cmp  byte [rdi], ' '
    jne  .b
    inc  rdi
    jmp  .sp2
.b:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .scan                          ; "A + <non-digit>" -> keep scanning
    call chat_parse_u32
    mov  r15d, eax                      ; B
    ; answer "A+B=S"
    lea  rsi, [rbx + CNA_ANS]
    mov  edi, r14d
    call chat_native_dec
    mov  byte [rsi], '+'
    inc  rsi
    mov  edi, r15d
    call chat_native_dec
    mov  byte [rsi], '='
    inc  rsi
    lea  edi, [r14 + r15]               ; S = A + B
    call chat_native_dec
    mov  byte [rsi], 0
    mov  byte [rbx + CNA_MODE], CHAT_MODE_EVAL
    jmp  .out
.no_arith:
    ; --- (b) local model / (c) offline: trusted code words these ---
    mov  byte [rbx + CNA_MODE], CHAT_MODE_OFF
    cmp  byte [rbx + CNA_MODEL], 1
    jne  .out
    mov  byte [rbx + CNA_MODE], CHAT_MODE_GPT2
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    xor  eax, eax
    ret

; chat_native_dec(EDI=u32, RSI=dest) -> RSI past the decimal digits (no NUL).
;   Clobbers RAX, RCX, RDX, R8.
chat_native_dec:
    mov  eax, edi
    mov  ecx, 10
    xor  r8d, r8d
.div:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    push rdx
    inc  r8d
    test eax, eax
    jnz  .div
.emit:
    pop  rax
    mov  [rsi], al
    inc  rsi
    dec  r8d
    jnz  .emit
    ret

; ---------------------------------------------------------------------------
; chat_app_init — populate the window table (A/B already painted by the C16
;   floor + the chat tile), draw the tile, emit the three earned markers, and
;   run the boot 1-turn selftest THROUGH chat_process (the same path the verbs
;   hit). No framebuffer -> honest skip (no table, no markers, verbs degrade).
;   Called from boot/header.asm right after gui_compositor_selftest.
; ---------------------------------------------------------------------------
chat_app_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rax, [rel str_mode_off]        ; mode ptr valid before ANY verb runs
    mov  [rel chat_mode_ptr], rax
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .nofb
    ; --- window table: slot 0 = A, slot 1 = B (the C16 floor pair), 2 = chat.
    ;     Titles filled at RUNTIME via lea (a static `dq symbol` bakes the RVA,
    ;     not the VA — the monolith's populate_*_runtime_ptrs lesson). ---
    lea  rbx, [rel wm_state]
    mov  dword [rbx + 0*4], WM_VISIBLE
    mov  dword [rbx + 1*4], WM_VISIBLE
    mov  dword [rbx + CHAT_SLOT*4], WM_VISIBLE
    push rdi                            ; RC-history: the boot windows are the owner's own and carry a
    xor  edi, edi                       ; window generation (wmx_owner_clear preserves every register)
    call wmx_owner_clear
    mov  edi, 1
    call wmx_owner_clear
    mov  edi, CHAT_SLOT
    call wmx_owner_clear
    pop  rdi
    lea  rbx, [rel wm_x]
    mov  dword [rbx + 0*4], 100
    mov  dword [rbx + 1*4], 320
    mov  dword [rbx + CHAT_SLOT*4], CHAT_WIN_X
    lea  rbx, [rel wm_y]
    mov  dword [rbx + 0*4], 100
    mov  dword [rbx + 1*4], 190
    mov  dword [rbx + CHAT_SLOT*4], CHAT_WIN_Y
    lea  rbx, [rel wm_w]
    mov  dword [rbx + 0*4], 360
    mov  dword [rbx + 1*4], 280
    mov  dword [rbx + CHAT_SLOT*4], CHAT_WIN_W
    lea  rbx, [rel wm_h]
    mov  dword [rbx + 0*4], 260
    mov  dword [rbx + 1*4], 200
    mov  dword [rbx + CHAT_SLOT*4], CHAT_WIN_H
    lea  rbx, [rel wm_title]
    lea  rax, [rel str_title_a]
    mov  [rbx + 0*8], rax
    lea  rax, [rel str_title_b]
    mov  [rbx + 1*8], rax
    lea  rax, [rel str_chat_title]
    mov  [rbx + CHAT_SLOT*8], rax
    mov  dword [rel wm_focus], CHAT_SLOT
    ; --- draw the tile (A/B are already on-screen from the C16 selftest) ---
    call chat_draw_window
    lea  rdi, [rel str_m_init]
    call serial_string
    mov  byte [rel chat_m_init], 1
    ; --- model seam: present (1061 engine + real PXG2 weights) or offline ---
    cmp  byte [rel cog_model_present], 1
    je   .m_gpt2
    lea  rdi, [rel str_m_model_off]
    call serial_string
    jmp  .m_done
.m_gpt2:
    lea  rdi, [rel str_m_model_gpt2]
    call serial_string
.m_done:
    mov  byte [rel chat_m_model], 1
    ; --- boot 1-turn selftest through the REAL path; the marker is EARNED
    ;     only if the evaluator actually answered "...=4" ---
    lea  rdi, [rel str_chat_selfq]
    mov  byte [rel chat_boot_inline], 1 ; before calibration and any desktop: inline
    call chat_process
    mov  byte [rel chat_boot_inline], 0
    lea  rdi, [rel chat_ans_buf]
.vscan:
    mov  al, [rdi]
    test al, al
    jz   .vfail
    cmp  al, '='
    je   .veq
    inc  rdi
    jmp  .vscan
.veq:
    cmp  byte [rdi + 1], '4'
    jne  .vfail
    lea  rdi, [rel str_m_turn]
    call serial_string
    mov  byte [rel chat_m_turn], 1
    jmp  .ret
.vfail:
    lea  rdi, [rel str_turn_fail]
    call serial_string
    jmp  .ret
.nofb:
    lea  rdi, [rel str_chat_nofb]
    call serial_string
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; chat_app_tick — living-tile respawn: a CLOSEd chat slot comes back on its
;   own after CHAT_RESPAWN_MS (DESKTOP.md living icons — the widget persists).
;   Called from the boot/header.asm idle loop; cheap no-op while not closed.
; ---------------------------------------------------------------------------
chat_app_tick:
    cmp  byte [rel chat_window_suppressed], 1
    je   .ret
    cmp  dword [rel wm_state + CHAT_SLOT*4], WM_CLOSED
    jne  .ret
    call boot_ms_now                    ; RAX = ms since boot (clobbers RAX,RCX,RDX)
    mov  rcx, [rel chat_closed_ms]
    add  rcx, CHAT_RESPAWN_MS
    cmp  rax, rcx
    jb   .ret
    mov  dword [rel wm_state + CHAT_SLOT*4], WM_VISIBLE
    mov  edi, CHAT_SLOT                 ; RC-history: a respawned chat window is a new window
    call wmx_owner_clear
    call chat_draw_window
    lea  rdi, [rel str_chat_respawn]
    call serial_string
.ret:
    ret

; ---------------------------------------------------------------------------
; chat_declare — register the 7 verbs through the ONE command_register_verb
;   (additive, no registry-core edit; same shape as thermal/resilience).
; ---------------------------------------------------------------------------
chat_declare:
    lea  rdi, [rel str_verb_csend]
    lea  rsi, [rel cmd_verb_chat_send]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                          ; mutates chat state
    call command_register_verb
    lea  rdi, [rel str_verb_cget]
    lea  rsi, [rel cmd_verb_chat_get]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_windows]
    lea  rsi, [rel cmd_verb_windows]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_focus]
    lea  rsi, [rel cmd_verb_focus]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_min]
    lea  rsi, [rel cmd_verb_min]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_max]
    lea  rsi, [rel cmd_verb_max]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_close]
    lea  rsi, [rel cmd_verb_close]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    ret

; --- VERB: CHAT_SENDTEXT <text> — bounded 1-turn query. Oversize -> BLOCKED
;     (the negative gate: a >CHAT_IN_MAX text earns an explicit ERR, no crash). ---
cmd_verb_chat_send:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi                       ; resp
    mov  r12, [rdi + REQ_ARG]           ; query text ptr
    mov  rdi, r12
    call strlen                         ; RAX = len (preserves RDI)
    mov  rbx, rax
    cmp  rax, CHAT_IN_MAX
    ja   .blocked
    mov  rdi, r12
    call chat_process
    call chat_out_reset
    lea  rdi, [rel str_cs_ok]           ; " chat send=ok len="
    call chat_put_str
    mov  edi, ebx
    call chat_put_dec
    lea  rdi, [rel str_cs_mode]         ; " mode="
    call chat_put_str
    mov  rdi, [rel chat_mode_ptr]
    call chat_put_str
    jmp  .stage
.blocked:
    call chat_out_reset
    lea  rdi, [rel str_cs_blocked]      ; " chat send=ERR BLOCKED oversize len="
    call chat_put_str
    mov  rdi, rbx
    call chat_put_dec
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- VERB: CHAT_GETTEXT — reflect the RENDERED turn (query incl. the caller's
;     nonce + the computed answer) from the SAME buffers the window draws. ---
cmd_verb_chat_get:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r13, rsi
    mov  r12, [rdi + REQ_ARG]
    call chat_out_reset
    lea  rdi, [rel str_cg_pre]          ; " chat text: Q="
    call chat_put_str
    lea  rdi, [rel chat_q_buf]
    call chat_put_str
    lea  rdi, [rel str_cg_a]            ; " A="
    call chat_put_str
    lea  rdi, [rel chat_ans_buf]
    call chat_put_str
    lea  rdi, [rel str_cs_mode]         ; " mode="
    call chat_put_str
    mov  rdi, [rel chat_mode_ptr]
    call chat_put_str
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    pop  r13
    pop  r12
    ret

; --- VERB: WINDOWS — one "WIN[i] title=T state=S" line per non-closed slot
;     (newline-separated so a line-counting client sees one line per window). ---
cmd_verb_windows:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    call chat_out_reset
    lea  rdi, [rel str_verb_windows]     ; deterministic lean snapshot header
    call chat_put_str
    xor  r12d, r12d
.loop:
    cmp  r12d, WM_MAX
    jae  .done
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .emit
    cmp  eax, WM_MIN
    je   .emit
    jmp  .next
.emit:
    lea  rdi, [rel str_w_nl]            ; "\nWIN["
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_w_title]         ; "] title="
    call chat_put_str
    lea  rax, [rel wm_title]
    mov  rdi, [rax + r12*8]
    call chat_put_str
    lea  rdi, [rel str_w_state]         ; " state="
    call chat_put_str
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_MIN
    je   .st_min
    lea  rdi, [rel str_w_vis]
    jmp  .st_put
.st_min:
    lea  rdi, [rel str_w_min]
.st_put:
    call chat_put_str
.next:
    inc  r12d
    jmp  .loop
.done:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], rbx
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- shared idx fetch: RDI=req -> RAX = idx, carry-free validation done by
;     callers (bad idx = >= WM_MAX or a FREE slot). ---
chat_req_idx:
    mov  rdi, [rdi + REQ_ARG]
    call chat_parse_u32
    ret

; --- VERB: FOCUS <idx> — raise + focus a live window. ---
cmd_verb_focus:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r13 + RSP_VAL], rbx           ; 2026-10-01: before the painters clobber RBX
    push rdi
    call session_shell_require_unlocked ; F2b-1: nothing takes the keyboard under the lock
    pop  rdi
    test eax, eax
    jnz  .locked
    push rdi
    call chat_req_idx
    mov  r12d, eax
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .ok
    cmp  eax, WM_MIN
    jne  .bad
.ok:
    mov  rdi, [rsp]                     ; F2b-2: the request's principal may act on the slot
    mov  esi, r12d
    call wmx_req_may_act
    test eax, eax
    jnz  .denied
    mov  edi, r12d
    call wmx_raise_slot
    call chat_out_reset
    lea  rdi, [rel str_f_ok]            ; " focus=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_f_bad]           ; " focus=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
.popreq:
    add  rsp, 8                         ; the request
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.denied:
    mov  rsi, r13
    call wmx_stage_denied
    jmp  .popreq
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out

; --- VERB: MIN <idx> — minimize (erase; the table keeps the slot, WINDOWS
;     reports state=minimized). Idempotent on an already-minimized slot.
;     SEC-winmove (C) (root 14:51:31): MAX's gates, the lock first, then the
;     request's principal may act on the slot. ---
cmd_verb_min:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r13 + RSP_VAL], rbx           ; 2026-10-01: before the painters clobber RBX
    push rdi
    call session_shell_require_unlocked ; nothing minimizes under the lock (as MAX)
    pop  rdi
    test eax, eax
    jnz  .locked
    push rdi
    call chat_req_idx
    mov  r12d, eax
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  ecx, [rax + r12*4]
    cmp  ecx, WM_VISIBLE
    je   .do
    cmp  ecx, WM_MIN
    je   .reply                          ; already minimized -> ok (idempotent)
    jmp  .bad
.do:
    mov  rdi, [rsp]                     ; the request's principal may act on the slot (as MAX)
    mov  esi, r12d
    call wmx_req_may_act
    test eax, eax
    jnz  .denied
    mov  edi, r12d
    call wmx_minimize_slot
.reply:
    call chat_out_reset
    lea  rdi, [rel str_mn_ok]           ; " min=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_mn_state]        ; " state=minimized"
    call chat_put_str
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_mn_bad]          ; " min=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
.popreq:
    add  rsp, 8                         ; the request
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.denied:
    mov  rsi, r13
    call wmx_stage_denied
    jmp  .popreq
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out

; --- VERB: MAX <idx> — restore a minimized (or repaint a visible) window. ---
cmd_verb_max:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r13 + RSP_VAL], rbx           ; 2026-10-01: before the painters clobber RBX
    push rdi
    call session_shell_require_unlocked ; F2b-1: nothing takes the keyboard under the lock
    pop  rdi
    test eax, eax
    jnz  .locked
    push rdi
    call chat_req_idx
    mov  r12d, eax
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  ecx, [rax + r12*4]
    cmp  ecx, WM_VISIBLE
    je   .do
    cmp  ecx, WM_MIN
    jne  .bad
.do:
    mov  rdi, [rsp]                     ; F2b-2: the request's principal may act on the slot
    mov  esi, r12d
    call wmx_req_may_act
    test eax, eax
    jnz  .denied
    mov  edi, r12d
    call wmx_raise_slot
    call chat_out_reset
    lea  rdi, [rel str_mx_ok]           ; " max=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_mx_state]        ; " state=restored"
    call chat_put_str
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_mx_bad]          ; " max=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
.popreq:
    add  rsp, 8                         ; the request
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.denied:
    mov  rsi, r13
    call wmx_stage_denied
    jmp  .popreq
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out

; --- VERB: CLOSE <idx> — close a window (slot -> CLOSED, gone from WINDOWS,
;     desktop repainted). Closing the chat slot arms the living-tile respawn.
;     SEC-winmove (C) (root 14:51:31): MAX's gates, as MIN. ---
cmd_verb_close:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r13 + RSP_VAL], rbx           ; 2026-10-01: before the painters clobber RBX
    push rdi
    call session_shell_require_unlocked ; SEC-winmove (C): nothing closes under the lock (as MAX)
    pop  rdi
    test eax, eax
    jnz  .locked
    push rdi
    call chat_req_idx
    mov  r12d, eax
    cmp  r12d, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  ecx, [rax + r12*4]
    cmp  ecx, WM_FREE
    je   .bad
    cmp  ecx, WM_CLOSED
    je   .reply                          ; already closed -> ok (idempotent)
    mov  rdi, [rsp]                     ; the request's principal may act on the slot (as MAX)
    mov  esi, r12d
    call wmx_req_may_act
    test eax, eax
    jnz  .denied
    mov  edi, r12d
    call wmx_close_slot
    cmp  r12d, CHAT_SLOT
    jne  .reply
    call boot_ms_now                     ; arm the respawn clock
    mov  [rel chat_closed_ms], rax
.reply:
    call chat_out_reset
    lea  rdi, [rel str_cl_ok]           ; " close=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_cl_closed]       ; " closed"
    call chat_put_str
    jmp  .stage
.bad:
    call chat_out_reset
    lea  rdi, [rel str_cl_bad]          ; " close=ERR bad_idx"
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
.popreq:
    add  rsp, 8                         ; the request
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.denied:
    mov  rsi, r13
    call wmx_stage_denied
    jmp  .popreq
.locked:
    mov  rsi, r13
    call wmx_stage_locked
    jmp  .out

; ---------------------------------------------------------------------------
; staged-reply + answer-buffer cursor helpers (mirror the therm/cog pattern)
; ---------------------------------------------------------------------------
chat_out_reset:
    lea  rax, [rel chat_out_buf]
    mov  [rel chat_out_cur], rax
    mov  byte [rel chat_out_buf], 0
    ret
chat_put_str:                           ; RDI = cstr (bounded by CHAT_OUT_MAX)
    mov  rsi, [rel chat_out_cur]
    lea  rax, [rel chat_out_buf + CHAT_OUT_MAX - 2]
.cp:
    cmp  rsi, rax
    jae  .done
    mov  cl, [rdi]
    test cl, cl
    jz   .done
    mov  [rsi], cl
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel chat_out_cur], rsi
    ret
chat_put_dec:                           ; RDI = value
    mov  rsi, [rel chat_out_cur]
    lea  rax, [rel chat_out_buf + CHAT_OUT_MAX - 24]
    cmp  rsi, rax
    jae  .skip
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel chat_out_cur], rsi
.skip:
    ret
chat_ans_reset:
    lea  rax, [rel chat_ans_buf]
    mov  [rel chat_ans_cur], rax
    mov  byte [rel chat_ans_buf], 0
    ret
chat_ans_str:                           ; RDI = cstr (bounded)
    mov  rsi, [rel chat_ans_cur]
    lea  rax, [rel chat_ans_buf + CHAT_ANS_MAX - 2]
.cp:
    cmp  rsi, rax
    jae  .done
    mov  cl, [rdi]
    test cl, cl
    jz   .done
    mov  [rsi], cl
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel chat_ans_cur], rsi
    ret
chat_ans_dec:                           ; RDI = value
    mov  rsi, [rel chat_ans_cur]
    lea  rax, [rel chat_ans_buf + CHAT_ANS_MAX - 24]
    cmp  rsi, rax
    jae  .skip
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel chat_ans_cur], rsi
.skip:
    ret

; ---------------------------------------------------------------------------
; data (in-image, RW under our page tables). command_udp.asm frames
; chat_out_buf/chat_out_ready and the three chat_m_* flags (BOOTLOG-gated).
; ---------------------------------------------------------------------------
CHAT_OUT_MAX equ 640
CHAT_ANS_MAX equ 160

align 8
chat_out_cur:   dq 0
chat_ans_cur:   dq 0
chat_closed_ms: dq 0
chat_mode_ptr:  dq 0                    ; runtime lea-filled (never a static dq symbol)
wm_state:       times WM_MAX dd 0
wm_x:           times WM_MAX dd 0
wm_y:           times WM_MAX dd 0
wm_w:           times WM_MAX dd 0
wm_h:           times WM_MAX dd 0
wm_restore_x:   times WM_MAX dd 0
wm_restore_y:   times WM_MAX dd 0
wm_restore_w:   times WM_MAX dd 0
wm_restore_h:   times WM_MAX dd 0
align 8
wm_title:       times WM_MAX dq 0       ; runtime lea-filled title ptrs
wm_focus:       dd 0
wm_prev_focus:  dd WM_MAX                ; previous topmost slot for close/min fallback
wm_zstamp:      times WM_MAX dd 0        ; 2026-09-08 z-order: higher = nearer the top (raise/open/alt-tab stamp)
wm_zcounter:    dd 0
wm_attn:        times WM_MAX db 0
wm_restore_class: times WM_MAX db WM_RESTORE_FRESH
wm_maximized:   times WM_MAX db 0
chat_m_init:    db 0
chat_m_model:   db 0
chat_m_turn:    db 0
chat_out_ready: db 0
chat_window_suppressed: db 0            ; F1 keeps chat verbs but reserves slot 2 off-desktop
chat_q_buf:     times (CHAT_IN_MAX + 8) db 0
chat_boot_inline: db 0                 ; 1 only around chat_app_init's selftest
chat_boot_arena: times CNA_SIZE db 0   ; that selftest's arena (never a module's)
chat_ans_buf:   times CHAT_ANS_MAX db 0
chat_out_buf:   times CHAT_OUT_MAX db 0

; --- verb names ---
str_verb_csend:   db "CHAT_SENDTEXT", 0
str_verb_cget:    db "CHAT_GETTEXT", 0
str_verb_windows: db "WINDOWS", 0
str_verb_focus:   db "FOCUS", 0
str_verb_min:     db "MIN", 0
str_verb_max:     db "MAX", 0
str_verb_close:   db "CLOSE", 0

; --- window titles + tile text ---
str_title_a:      db "Monitor", 0
str_title_b:      db "Netmon", 0
str_chat_title:   db "Chat", 0
str_floor_linkup:   db "NIC link: up", 0     ; 1322: honest floor-window body line
str_floor_linkdown: db "NIC link: down", 0
str_chat_qpre:    db "Q: ", 0
str_chat_apre:    db "A: ", 0
str_chat_mpre:    db "model: ", 0
str_chat_prompt:  db "> ", 0
str_chat_selfq:   db "selftest: what is 2 + 2 ?", 0
str_chat_plus:    db "+", 0
str_chat_eq:      db "=", 0
str_chat_gpt2a:   db "gpt2 1-turn ref token=", 0
str_chat_offa:    db "model offline (eval-only tile)", 0
str_mode_eval:    db "eval", 0
str_mode_gpt2:    db "gpt2", 0
str_mode_off:     db "offline", 0
str_mode_stuck:   db "stuck", 0
str_mode_refused: db "refused", 0
str_chat_stuck:   db "app not responding", 0
str_chat_refused: db "app unavailable", 0

; --- staged reply fragments ---
str_cs_ok:        db " chat send=ok len=", 0
str_cs_mode:      db " mode=", 0
str_cs_blocked:   db " chat send=ERR BLOCKED oversize len=", 0
str_cg_pre:       db " chat text: Q=", 0
str_cg_a:         db " A=", 0
str_w_nl:         db 10, "WIN[", 0
str_w_title:      db "] title=", 0
str_w_state:      db " state=", 0
str_w_vis:        db "visible", 0
str_w_min:        db "minimized", 0
str_f_ok:         db " focus=ok idx=", 0
str_f_bad:        db " focus=ERR bad_idx", 0
str_mn_ok:        db " min=ok idx=", 0
str_mn_state:     db " state=minimized", 0
str_mn_bad:       db " min=ERR bad_idx", 0
str_mx_ok:        db " max=ok idx=", 0
str_mx_state:     db " state=restored", 0
str_mx_bad:       db " max=ERR bad_idx", 0
str_cl_ok:        db " close=ok idx=", 0
str_cl_closed:    db " closed", 0
str_cl_bad:       db " close=ERR bad_idx", 0

; --- boot markers (serial; the BOOTLOG-gated UDP tokens live in command_udp) ---
str_m_init:       db "[PAOS64] M6 chat: 2nd-app chat tile window up @640,100 320x260 [desktop.chat_app.init]", 13, 10, 0
str_m_model_off:  db "[PAOS64] M6 chat: local-model seam bound model=offline eval-fallback [desktop.chat_app.local_model]", 13, 10, 0
str_m_model_gpt2: db "[PAOS64] M6 chat: local-model seam bound model=gpt2 present [desktop.chat_app.local_model]", 13, 10, 0
str_m_turn:       db "[PAOS64] M6 chat: boot 1-turn selftest answered 2+2=4 [desktop.chat_app.1turn_ready]", 13, 10, 0
str_turn_fail:    db "[PAOS64] M6 chat: boot 1-turn selftest FAILED (no =4 answer)", 13, 10, 0
str_chat_nofb:    db "[PAOS64] M6 chat: no framebuffer (GOP absent), chat tile skipped", 13, 10, 0
str_chat_respawn: db "[PAOS64] M6 chat: living-tile respawned after close", 13, 10, 0

; --- the ported 8x16 VGA font (M16: proven monolith table, verbatim) ---
%include "gui/font8x16.inc"
