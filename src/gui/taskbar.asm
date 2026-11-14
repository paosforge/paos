;; MODULE gui/taskbar
%include "core/abi/build_profile.inc"
;; LAYER 6
;; EXPORTS taskbar_cluster_rect, taskbar_draw_registry, taskbar_pointer_press, f1_cmd_verb_taskbar, f1_cmd_verb_winattn, taskbar_attention_tick, f1_out_reset, f1_put_str, f1_put_dec, f1_put_hex6, f1_put_escaped, f1_out_buf, f1_out_ready
;; IMPORTS gui/calendar, gui/window, gui/input_route, gui/chat_app, gui/window_mgmt, gui/wm_pointer, gui/cadence_mark, gui/guardian_indicator, core/lib/fmt, dev/power/ec_power, gui/terminal_consent
;; CAPS
;; OWNER saga:gui_foundation_ladder

; F1 owns a full-datagram reply buffer.  Rung 0 remains byte-stable and keeps
; its small skeleton/liveness buffer; these local aliases let the F1 bodies use
; the same staging shape without overwriting the PLV1 witness state.
%define gui_ladder_out_reset   f1_out_reset
%define gui_ladder_put_str     f1_put_str
%define gui_ladder_put_dec     f1_put_dec
%define gui_ladder_put_escaped f1_put_escaped
%define gui_ladder_out_ready   f1_out_ready
%define gui_ladder_out_buf     f1_out_buf

f1_out_reset:
    lea  rax, [rel f1_out_buf]
    mov  [rel f1_out_cur], rax
    mov  byte [rel f1_out_ready], 0
    mov  byte [rax], 0
    ret

; Append a NUL-terminated string while reserving the final byte for NUL.
f1_put_str:
    mov  rsi, [rel f1_out_cur]
    lea  rdx, [rel f1_out_buf + 1471]
.copy:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel f1_out_cur], rsi
    ret

f1_put_dec:
    mov  rsi, [rel f1_out_cur]
    lea  rax, [rel f1_out_buf + 1448]
    cmp  rsi, rax
    jae  .done
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel f1_out_cur], rsi
.done:
    ret

; Append the low 24 bits as exactly six uppercase RRGGBB digits. WINCHROME
; uses this over the same GUI_TOK_* constants the painter consumes, so token
; read-back cannot drift into a second hand-kept color table.
f1_put_hex6:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    mov  r12d, 20
.nibble:
    mov  eax, r13d
    mov  ecx, r12d
    shr  eax, cl
    and  eax, 15
    lea  rbx, [rel f1_hex]
    mov  al, [rbx + rax]
    mov  [rel f1_char_buf], al
    mov  byte [rel f1_char_buf + 1], 0
    lea  rdi, [rel f1_char_buf]
    call f1_put_str
    sub  r12d, 4
    jns  .nibble
    pop  r13
    pop  r12
    pop  rbx
    ret

; UTF-8 byte serialization: space/newline/% and every high byte are %XX.
f1_put_escaped:
    push rbx
    push r12
    mov  r12, rdi
.loop:
    movzx ebx, byte [r12]
    test bl, bl
    jz   .done
    cmp  bl, ' '
    je   .escape
    cmp  bl, 10
    je   .escape
    cmp  bl, 13
    je   .escape
    cmp  bl, '%'
    je   .escape
    test bl, 0x80
    jnz  .escape
    mov  byte [rel f1_char_buf], bl
    mov  byte [rel f1_char_buf + 1], 0
    lea  rdi, [rel f1_char_buf]
    call f1_put_str
    jmp  .next
.escape:
    mov  byte [rel f1_pct_buf], '%'
    mov  eax, ebx
    shr  eax, 4
    and  eax, 15
    lea  rcx, [rel f1_hex]
    mov  al, [rcx + rax]
    mov  [rel f1_pct_buf + 1], al
    mov  eax, ebx
    and  eax, 15
    mov  al, [rcx + rax]
    mov  [rel f1_pct_buf + 2], al
    mov  byte [rel f1_pct_buf + 3], 0
    lea  rdi, [rel f1_pct_buf]
    call f1_put_str
.next:
    inc  r12
    jmp  .loop
.done:
    pop  r12
    pop  rbx
    ret

TB_X0        equ 8
TB_Y_INSET   equ 4
TB_PITCH     equ 112
TB_BUTTON_W  equ 104
TB_BUTTON_H  equ 30
TB_START_W   equ 40
TB_START_GAP equ 8
TB_TRAY_RESERVE equ 104
TB_TRAY_RESERVE_BAT equ 184             ; RCQ-27: + the Dell battery cell left of the clock (BAT_CELL_XOFF + 8)
TB_TRAY_IME  equ IME_CELL_W + 8          ; RCQ-38 I3b-1 (b): + the IME mode cell (gui/window), only while it shows

; Live registry windows plus Start form one centered launch cluster.
taskbar_cluster_rect:
    xor  r9d, r9d
    xor  eax, eax
.count:
    cmp  eax, WM_MAX
    jae  .sized
    lea  rdx, [rel wm_state]
    mov  edx, [rdx + rax*4]
    cmp  edx, WM_VISIBLE
    je   .live
    cmp  edx, WM_MIN
    jne  .next
.live:
    inc  r9d
.next:
    inc  eax
    jmp  .count
.sized:
    mov  r10d, TB_PITCH
    mov  ecx, r9d
    imul ecx, r10d
    add  ecx, TB_START_W + TB_START_GAP
    mov  eax, [rel fb_width]
    mov  edx, TB_TRAY_RESERVE * 2
    cmp  byte [rel ecp_active], 1
    jne  .reserve                       ; every target without the Dell battery cell: unchanged
    mov  edx, TB_TRAY_RESERVE_BAT * 2
.reserve:
    cmp  dword [rel input_ime_tray], 0
    je   .reserved                      ; the IME method OFF (or no IME): unchanged
    add  edx, TB_TRAY_IME * 2
.reserved:
    sub  eax, edx
    cmp  eax, TB_START_W + TB_START_GAP
    jae  .have_max
    mov  eax, [rel fb_width]
.have_max:
    cmp  ecx, eax
    jbe  .center
    test r9d, r9d
    jz   .center
    sub  eax, TB_START_W + TB_START_GAP
    xor  edx, edx
    div  r9d
    mov  r10d, eax
    cmp  r10d, 16
    jae  .rewidth
    mov  r10d, 16
.rewidth:
    mov  ecx, r9d
    imul ecx, r10d
    add  ecx, TB_START_W + TB_START_GAP
.center:
    mov  esi, [rel fb_width]
    sub  esi, ecx
    shr  esi, 1
    mov  edx, [rel fb_height]
    sub  edx, TASKBAR_H - TB_Y_INSET
    mov  r8d, TB_BUTTON_H
    ret

; EDI=slot -> eax=1 and ESI=x EDX=y ECX=w R8D=h R9D=ordinal, else eax=0.
taskbar_rect_for_slot:
    push rbx
    push r10
    push r11
    mov  r10d, edi
    xor  r9d, r9d
    xor  r11d, r11d
.scan:
    cmp  r11d, WM_MAX
    jae  .miss
    lea  rax, [rel wm_state]
    mov  ebx, [rax + r11*4]
    cmp  ebx, WM_VISIBLE
    je   .live
    cmp  ebx, WM_MIN
    jne  .next
.live:
    cmp  r11d, r10d
    je   .hit
    inc  r9d
.next:
    inc  r11d
    jmp  .scan
.hit:
    push r9
    call taskbar_cluster_rect
    mov  eax, r10d
    pop  r9
    imul r9d, eax
    add  esi, TB_START_W + TB_START_GAP
    add  esi, r9d
    mov  ecx, eax
    sub  ecx, 8
    cmp  ecx, TB_BUTTON_W
    jbe  .width_ok
    mov  ecx, TB_BUTTON_W
.width_ok:
    mov  eax, 1
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r11
    pop  r10
    pop  rbx
    ret

; Query the wm registry and ask the ONE L2 painter to render each button.
taskbar_draw_registry:
    push r12
    ; One honest cadence record per registry repaint (Task 2135 repaint-damage oracle):
    ; the attention tick otherwise publishes 1 + 2*windows TASKBAR-region DRAW rows with
    ; sub-millisecond gaps.  The clock cell keeps its own exact batch (drawn after END).
    push rax
    movzx eax, word [rel cadence_region_current]
    push rax
    mov  word [rel cadence_region_current], CADR_REGION_TASKBAR
    CADENCE_BATCH_BEGIN
    call wmx_clear_taskbar_buttons      ; the ONE TASKBAR-region heartbeat row per tick
    mov  word [rel cadence_region_current], CADR_REGION_TASKBAR_BTN
    call summon_palette_taskbar_draw
%if !PAOS_PUBLIC_BUILD
    call guardian_indicator_taskbar_draw    ; SEC-GA0-lite: left-tray security alert cell
%endif
    call snapshot_indicator_draw           ; owner-visible screen read, including PUBLIC
    call terminal_consent_draw              ; continuous current-grant notice, including PUBLIC
    call taskbar_battery_paint              ; RCQ-27 POWER-04: Dell battery cell (gui/window; inert elsewhere)
    call taskbar_ime_paint                  ; RCQ-38 I3b-1 (b): the IME mode cell (gui/window; nothing while OFF)
    xor  r12d, r12d
.loop:
    cmp  r12d, WM_MAX
    jae  .done
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .draw
    cmp  eax, WM_MIN
    jne  .next
.draw:
    mov  r9d, 1                         ; normal
    cmp  eax, WM_MIN
    jne  .attn
    mov  r9d, 2                         ; minimized
.attn:
    lea  rcx, [rel wm_attn]
    cmp  byte [rcx + r12], 1
    jne  .active
    mov  r9d, 1                         ; pulse low phase = normal token
    cmp  byte [rel taskbar_pulse_phase], 0
    je   .active
    mov  r9d, 3                         ; pulse high phase = attention token
.active:
    cmp  r12d, [rel wm_focus]
    jne  .rect
    cmp  eax, WM_VISIBLE
    jne  .rect
    xor  r9d, r9d                       ; active
.rect:
    mov  edi, r12d
    push r9
    call taskbar_rect_for_slot
    pop  r9
    test eax, eax
    jz   .next
    mov  edi, r12d
    call wmx_paint_taskbar_button
.next:
    inc  r12d
    jmp  .loop
.done:
    CADENCE_BATCH_END
    pop  rax
    mov  [rel cadence_region_current], ax
    pop  rax
    call taskbar_draw_clock_glyphs      ; preserve the 1321 tray/clock cell (its own exact batch)
    pop  r12
    ret

; taskbar_battery_append — the TASKBAR text token for host/QEMU/metal checks, only
;   with the Dell EC backend: " BAT line1=<text> line2=<text|->". clobbers: caller-saved.
taskbar_battery_append:
    cmp  byte [rel ecp_active], 1
    jne  .out
    call taskbar_battery_text
    lea  rdi, [rel str_tb_bat_l1]
    call f1_put_str
    lea  rdi, [rel bat_line1]
    call f1_put_escaped
    lea  rdi, [rel str_tb_bat_l2]
    call f1_put_str
    lea  rdi, [rel bat_line2]
    cmp  byte [rdi], 0
    jne  .l2
    lea  rdi, [rel str_tb_bat_none]
.l2:
    call f1_put_escaped
.out:
    ret

; taskbar_ime_append — RCQ-38 I3b-1 (b), the IME mode query: while the method is not OFF,
;   " IME mode=<ja|zh-Hans> dict=<absent|bound> cell=<x>,<y>,<w>,<h|->" (root 16:01:48 (2)(a):
;   it says when no dictionary is bound); nothing while OFF, so the reply is the one without
;   the IME. clobbers: caller-saved.
taskbar_ime_append:
    mov  eax, [rel input_ime_tray]
    test eax, eax
    jz   .done
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, eax
    lea  rdi, [rel str_tb_ime_mode]
    call f1_put_str
    mov  eax, r14d
    and  eax, ~INPUT_IME_TRAY_NODICT
    lea  rdi, [rel str_tbv_ime_zh]
    cmp  eax, IME_GLYPH_ZH
    je   .mode
    lea  rdi, [rel str_tbv_ime_ja]
.mode:
    call f1_put_str
    lea  rdi, [rel str_tb_ime_bound]
    test r14d, INPUT_IME_TRAY_NODICT
    jz   .dict
    lea  rdi, [rel str_tb_ime_absent]
.dict:
    call f1_put_str
    lea  rdi, [rel str_tb_ime_cell]
    call f1_put_str
    call taskbar_ime_cell
    test eax, eax
    jz   .no_cell
    mov  ebx, r9d
    mov  r12d, r10d
    mov  r13d, r11d
    mov  edi, r8d
    call f1_put_dec
    lea  rdi, [rel str_comma]
    call f1_put_str
    mov  edi, ebx
    call f1_put_dec
    lea  rdi, [rel str_comma]
    call f1_put_str
    mov  edi, r12d
    call f1_put_dec
    lea  rdi, [rel str_comma]
    call f1_put_str
    mov  edi, r13d
    call f1_put_dec
    jmp  .out
.no_cell:
    lea  rdi, [rel str_tb_bat_none]
    call f1_put_str
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.done:
    ret

; Existing 1-second clock cadence calls this; no private timer exists.
; RCQ-27 L3: a blanked screen shows no pulse; the strip is repainted on the first
; tick after the wake (the wake itself re-presents the back buffer).
taskbar_attention_tick:
    cmp  byte [rel dpms_blanked], 1
    je   .out
    xor  byte [rel taskbar_pulse_phase], 1
    call taskbar_draw_registry
.out:
    ret

; EDI=x ESI=y -> eax=1 if a taskbar button consumed the press.
taskbar_pointer_press:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call calendar_clock_hit
    test eax, eax
    jz   .start
    call calendar_toggle
    jmp  .yes
.start:
    mov  edi,r12d
    mov  esi,r13d
    call terminal_consent_press
    test eax,eax
    jnz  .yes
    mov  edi, r12d
    mov  esi, r13d
    call summon_palette_taskbar_press
    test eax, eax
    jnz  .yes
    mov  edi, r12d
    mov  esi, r13d
%if !PAOS_PUBLIC_BUILD
    call guardian_indicator_taskbar_press   ; SEC-GA0-lite: owner-local acknowledge
    test eax, eax
    jnz  .yes
%endif
    xor  ebx, ebx
.hit_loop:
    cmp  ebx, WM_MAX
    jae  .no
    mov  edi, ebx
    call taskbar_rect_for_slot
    test eax, eax
    jz   .hit_next
    cmp  r12d, esi
    jl   .hit_next
    mov  eax, esi
    add  eax, ecx
    cmp  r12d, eax
    jge  .hit_next
    cmp  r13d, edx
    jl   .hit_next
    mov  eax, edx
    add  eax, r8d
    cmp  r13d, eax
    jge  .hit_next
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbx*4]
    cmp  ebx, [rel wm_focus]
    jne  .restore
    cmp  eax, WM_VISIBLE
    jne  .restore
    mov  edi, ebx
    call wm_pointer_act_ok              ; SEC-winmove (B): an injected click minimizes only what its frame may act on
    test eax, eax
    jnz  .yes                           ; refused: the press is consumed, nothing changes
    mov  edi, ebx
    call wmx_minimize_slot
    jmp  .yes
.restore:
    mov  edi, ebx
    call wmx_raise_slot
.yes:
    mov  eax, 1
    jmp  .out
.hit_next:
    inc  ebx
    jmp  .hit_loop
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; TASKBAR -> one row derived from the live window registry (no private list).
f1_cmd_verb_taskbar:
    call cmd_handler_prologue
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  r14, [rdi + REQ_ARG]
    call gui_ladder_out_reset
    lea  rdi, [rel str_tb_head]
    call gui_ladder_put_str
    xor  r12d, r12d
    xor  r15d, r15d
.count:
    cmp  r12d, WM_MAX
    jae  .count_done
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .count_live
    cmp  eax, WM_MIN
    jne  .count_next
.count_live:
    inc  r15d
.count_next:
    inc  r12d
    jmp  .count
.count_done:
    mov  edi, r15d
    call gui_ladder_put_dec
    xor  r12d, r12d
    xor  r15d, r15d
.emit_loop:
    cmp  r12d, WM_MAX
    jae  .ready
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .emit
    cmp  eax, WM_MIN
    jne  .emit_next
.emit:
    lea  rdi, [rel str_tb_ent]
    call gui_ladder_put_str
    mov  edi, r15d
    call gui_ladder_put_dec
    lea  rdi, [rel str_tb_win]
    call gui_ladder_put_str
    mov  edi, r12d
    call gui_ladder_put_dec
    lea  rdi, [rel str_tb_state]
    call gui_ladder_put_str
    lea  rdi, [rel str_tb_normal]
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + r12*4], WM_MIN
    jne  .emit_attn
    lea  rdi, [rel str_tb_min]
.emit_attn:
    lea  rcx, [rel wm_attn]
    cmp  byte [rcx + r12], 1
    jne  .emit_active
    lea  rdi, [rel str_tb_attn]
.emit_active:
    cmp  r12d, [rel wm_focus]
    jne  .state_put
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + r12*4], WM_VISIBLE
    jne  .state_put
    lea  rdi, [rel str_tb_active]
.state_put:
    call gui_ladder_put_str
    lea  rdi, [rel str_tb_rect]
    call gui_ladder_put_str
    mov  edi, r12d
    call taskbar_rect_for_slot
    push r8
    push rcx
    push rdx
    push rsi
    pop  rdi
    call gui_ladder_put_dec
    lea  rdi, [rel str_comma]
    call gui_ladder_put_str
    pop  rdi
    call gui_ladder_put_dec
    lea  rdi, [rel str_comma]
    call gui_ladder_put_str
    pop  rdi
    call gui_ladder_put_dec
    lea  rdi, [rel str_comma]
    call gui_ladder_put_str
    pop  rdi
    call gui_ladder_put_dec
    lea  rdi, [rel str_tb_title]
    call gui_ladder_put_str
    mov  eax, r12d
    call wmx_label_ptr                  ; T4: the label the button shows (app-owned title wins)
    call gui_ladder_put_escaped
    inc  r15d
.emit_next:
    inc  r12d
    jmp  .emit_loop
.ready:
    call summon_palette_taskbar_append
%if !PAOS_PUBLIC_BUILD
    call guardian_indicator_taskbar_append  ; SEC-GA0-lite: " GUARD new=.. total=.."
%endif
    call taskbar_battery_append             ; RCQ-27 POWER-04: " BAT line1=.. line2=.." (Dell only)
    call taskbar_ime_append                 ; RCQ-38 I3b-1 (b): " IME mode=.. dict=.." (only while not OFF)
    mov  byte [rel gui_ladder_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r14
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

f1_cmd_verb_winattn:
    call cmd_handler_prologue
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  r12, [rdi + REQ_ARG]
    mov  rdi, r12
    call wmx_next_token_u32
    mov  r14d, eax
    call wmx_next_token_u32
    mov  r15d, eax
    call gui_ladder_out_reset
    cmp  r14d, WM_MAX
    jae  .attn_bad
    lea  rcx, [rel wm_state]
    mov  ecx, [rcx + r14*4]
    cmp  ecx, WM_VISIBLE
    je   .attn_live
    cmp  ecx, WM_MIN
    jne  .attn_bad
.attn_live:
    cmp  r15d, 1
    ja   .attn_bad
    lea  rcx, [rel wm_attn]
    mov  [rcx + r14], r15b
    call taskbar_draw_registry
    lea  rdi, [rel str_attn_ok]
    call gui_ladder_put_str
    mov  edi, r14d
    call gui_ladder_put_dec
    lea  rdi, [rel str_attn_val]
    call gui_ladder_put_str
    mov  edi, r15d
    call gui_ladder_put_dec
    jmp  .attn_ready
.attn_bad:
    lea  rdi, [rel str_attn_bad]
    call gui_ladder_put_str
.attn_ready:
    mov  byte [rel gui_ladder_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

taskbar_pulse_phase: db 0
str_tb_head:   db " TASKBAR n=",0
str_tb_ent:    db " TB[",0
str_tb_win:    db "] win=",0
str_tb_state:  db " state=",0
str_tb_active: db "active",0
str_tb_normal: db "normal",0
str_tb_min:    db "minimized",0
str_tb_attn:   db "attention",0
str_tb_rect:   db " rect=",0
str_tb_title:  db " title=",0
str_tb_bat_l1:   db " BAT line1=", 0
str_tb_bat_l2:   db " line2=", 0
str_tb_bat_none: db "-", 0
str_tb_ime_mode:   db " IME mode=", 0
str_tbv_ime_ja:    db "ja", 0
str_tbv_ime_zh:    db "zh-Hans", 0
str_tb_ime_bound:  db " dict=bound", 0
str_tb_ime_absent: db " dict=absent", 0
str_tb_ime_cell:   db " cell=", 0
str_comma:     db ",",0
str_attn_ok:   db " WINATTN winattn=ok idx=",0
str_attn_val:  db " value=",0
; Same one-token negative grammar as the inherited unsupported skeletons.
str_attn_bad:  db " WINATTN=ERR_bad_idx_or_value",0

align 8
f1_out_cur:   dq 0
f1_out_ready: db 0
align 8
f1_out_buf:   times 1472 db 0
f1_char_buf:  times 2 db 0
f1_pct_buf:   times 4 db 0
f1_hex:       db "0123456789ABCDEF"

%undef gui_ladder_out_reset
%undef gui_ladder_put_str
%undef gui_ladder_put_dec
%undef gui_ladder_put_escaped
%undef gui_ladder_out_ready
%undef gui_ladder_out_buf
