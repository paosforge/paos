;; MODULE gui/guardian_indicator
;; LAYER 6
;; EXPORTS guardian_indicator_taskbar_draw, guardian_indicator_taskbar_press, guardian_indicator_taskbar_append, guardian_indicator_pointer_note
;; IMPORTS gui/window, gui/chat_app, gui/taskbar, gui/wm_pointer, svc/guardian_alert, sec/session, sec/principal, dev/input/ps2
;; CAPS CAP_GUI
;; OWNER saga:sec
; ============================================================================
; gui/guardian_indicator.asm — SEC-GA0-lite, the truthful local owner alert
; (RC spec 10.5). Admin ruling 10/08 01:57 (option C): this module is on the
; painter allowlist as a security witness instrument, on the liveness_panel
; PLV1 precedent, under these conditions:
;   - it paints ONLY inside its fixed left-tray cell (GI_X, fb_height -
;     TASKBAR_H + GI_YOFF, GI_W x GI_H) with fb_fill_rect / fb_draw_str_n;
;   - theme-token colours only; fixed text "GUARD" over "ok", "<n> new"
;     or "unknown" when unseen observations are only a lower bound;
;     no panel, overlay, window or WINTREE presence;
;   - the security logic lives in svc/guardian_alert (the data seam);
;   - a press only acknowledges, and only an owner-local physical press counts:
;     the event's origin must be WM_PTR_ORIGIN_HUMAN (the ps2_pointer_post ring:
;     PS/2 IRQ12, USB HID, I2C HID), never MOUSEINJ or another injected event,
;     and the session must be unlocked;
;   - and the cursor must have reached the cell by physical motion. MOUSEINJ
;     also writes the cursor position and button state, and later physical
;     reports build on them (srcreview GA0 R1: an injected release mid-drag,
;     or an injected hover before an unmoved click). So any injected event
;     DISARMS the cell, and only a physical event with the cursor OUTSIDE the
;     cell re-arms it. A press inside the cell counts only while armed, i.e.
;     the owner steered the cursor in from outside after the last injection.
;     The arm is bound to the screen geometry it was earned at: a remote RESSET
;     moves the cell (it sits at fb_height - 36), so a press after any width or
;     height change is refused until the owner steers in again (srcreview R-A).
;     Disarmed at boot; the first physical motion outside the cell arms it;
;   - inspection is `AUDIT sec` in the local console.
; TASKBAR (the F1 text verb) gains one token for host/QEMU checks:
;   " GUARD new=<n> total=<t> owner_seq=<s|none> owner_verb=<v|none>
;     cell=<x>,<y>,<w>,<h>"
; Every taskbar draw already sits behind lock_screen's session gate.
; ============================================================================

GI_X          equ 8                    ; inside the left tray reserve (taskbar TB_TRAY_RESERVE = 104)
GI_YOFF       equ 4                    ; same inset as the clock cell
GI_W          equ 80
GI_H          equ 32
GI_NEW_CAP    equ 9999                 ; "9999+ new" still fits the 10-cell line

; guardian_indicator_taskbar_draw — paint the cell. Called inside
;   taskbar_draw_registry's TASKBAR batch, after the clear. fb absent or too
;   small: nothing. clobbers: caller-saved.
guardian_indicator_taskbar_draw:
    cmp  qword [rel fb_base], 0
    je   .done
    cmp  dword [rel fb_width], GI_X + GI_W + 104
    jl   .done
    cmp  dword [rel fb_height], TASKBAR_H
    jl   .done
    push rbx
    push r12
    sub  rsp, 16
    call guardian_alert_count_quality
    mov  [rsp], rax
    call guardian_alert_counts
    mov  r12, rax                       ; new
    mov  ebx, GUI_TOK_TASKBAR_ACTIVE
    test byte [rsp], 1
    jnz  .attention
    test r12, r12
    jz   .bg
.attention:
    mov  ebx, GUI_TOK_TASKBAR_ATTENTION
.bg:
    mov  r8d, GI_X
    mov  r9d, [rel fb_height]
    sub  r9d, TASKBAR_H - GI_YOFF
    mov  r10d, GI_W
    mov  r11d, GI_H
    call fb_fill_rect
    mov  ecx, ebx                       ; text background = cell background
    mov  ebx, GUI_TOK_TASKBAR_TEXT
    push rcx
    mov  r8d, GI_X + 4
    mov  r9d, [rel fb_height]
    sub  r9d, TASKBAR_H - GI_YOFF
    mov  r11d, 9
    lea  rdi, [rel str_gi_title]
    call fb_draw_str_n
    test byte [rsp + 8], 1              ; background word is above quality
    jnz  .unknown
    mov  rdi, r12
    call gi_status_text                 ; exact unseen count
    jmp  .status
.unknown:
    lea  rdi, [rel str_gi_unknown]
.status:
    pop  rcx
    mov  ebx, GUI_TOK_TASKBAR_TEXT
    mov  r8d, GI_X + 4
    mov  r9d, [rel fb_height]
    sub  r9d, TASKBAR_H - GI_YOFF - 16
    mov  r11d, 10
    call fb_draw_str_n
    add  rsp, 16
    pop  r12
    pop  rbx
.done:
    ret

; gi_status_text(RDI = new count) -> RDI = NUL-terminated status in gi_text.
;   clobbers: RAX, RDX, RSI, R8-R10 (fmt_dec).
gi_status_text:
    lea  rsi, [rel gi_text]
    test rdi, rdi
    jnz  .count
    mov  dword [rsi], 'ok'             ; "ok" NUL NUL
    mov  rdi, rsi
    ret
.count:
    push rbx
    mov  rbx, rdi
    cmp  rdi, GI_NEW_CAP
    jbe  .dec
    mov  edi, GI_NEW_CAP
.dec:
    call fmt_dec                        ; RAX = digits written at gi_text
    lea  rsi, [rel gi_text]
    add  rsi, rax
    cmp  rbx, GI_NEW_CAP
    jbe  .suffix
    mov  byte [rsi], '+'
    inc  rsi
.suffix:
    mov  dword [rsi], ' new'
    mov  byte [rsi + 4], 0
    lea  rdi, [rel gi_text]
    pop  rbx
    ret

; gi_in_cell(EDI = x, ESI = y) -> EAX = 1 inside the cell, else 0. clobbers: EAX.
gi_in_cell:
    cmp  edi, GI_X
    jl   .no
    cmp  edi, GI_X + GI_W
    jge  .no
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H - GI_YOFF
    cmp  esi, eax
    jl   .no
    add  eax, GI_H
    cmp  esi, eax
    jge  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; guardian_indicator_pointer_note(EDI = x, ESI = y) — called by wm_pointer_event
;   for EVERY pointer event, after wm_pointer_origin is set and before any
;   dispatch (see header): injected -> disarm; physical and outside the cell ->
;   arm only with the current native owner session and queued report token.
;   Physical inside the cell cannot earn a new arm (only an inside press can
;   acknowledge, so arming on outside events never affects the same event).
;   clobbers: EAX.
guardian_indicator_pointer_note:
    push rdx                            ; preserve the pointer ingress register contract
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .disarm
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .disarm
    cmp  rdx, [rel ps2_pointer_context]
    jne  .disarm                        ; queued before a lock/rebind, or no report
    cmp  rdx, [rel gi_armed_authority]
    je   .cell
    mov  byte [rel gi_armed], 0
.cell:
    call gi_in_cell
    test eax, eax
    jnz  .done
    mov  qword [rel gi_armed_pid], PRIN_OWNER
    mov  [rel gi_armed_authority], rdx
    mov  byte [rel gi_armed], 1
    mov  eax, [rel fb_width]
    mov  [rel gi_armed_w], eax
    mov  eax, [rel fb_height]
    mov  [rel gi_armed_h], eax
    jmp  .done
.disarm:
    mov  byte [rel gi_armed], 0
.done:
    pop  rdx
    ret

; guardian_indicator_taskbar_press(EDI = x, ESI = y) -> EAX = 1 if the cell took
;   the press (acknowledged). Owner-local physical input only (see header).
guardian_indicator_taskbar_press:
    cmp  byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne  .no                            ; MOUSEINJ / injected: never acknowledges
    cmp  byte [rel gi_armed], 1
    jne  .no                            ; not steered in physically since the last injection
    mov  eax, [rel fb_width]
    cmp  eax, [rel gi_armed_w]
    jne  .no                            ; the screen changed under the arm (RESSET moves the cell)
    mov  eax, [rel fb_height]
    cmp  eax, [rel gi_armed_h]
    jne  .no
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no
    call gi_in_cell
    test eax, eax
    jz   .no
    mov  rdi, [rel gi_armed_pid]
    mov  rsi, [rel gi_armed_authority]
    cmp  rsi, [rel ps2_pointer_context]
    jne  .no
    call guardian_alert_acknowledge_local
    test eax, eax
    jz   .no
    call taskbar_draw_registry          ; repaint (lock-gated wrapper)
    mov  eax, 1
    ret
.no:
    mov  byte [rel gi_armed], 0
    xor  eax, eax
    ret

; guardian_indicator_taskbar_append — the TASKBAR text token (see header).
guardian_indicator_taskbar_append:
    push rbx
    push r12
    lea  rdi, [rel str_gi_tb_new]
    call f1_put_str
    call guardian_alert_count_quality
    push rax
    call guardian_alert_counts
    mov  rbx, rdx
    mov  rdi, rax
    call f1_put_dec
    lea  rdi, [rel str_gi_tb_total]
    call f1_put_str
    mov  rdi, rbx
    call f1_put_dec
    pop  r12
    test r12d, r12d
    jz   .quality_done
    lea  rdi, [rel str_gi_tb_new_lower]
    call f1_put_str
    mov  edi, r12d
    and  edi, 1
    call f1_put_dec
    lea  rdi, [rel str_gi_tb_total_lower]
    call f1_put_str
    mov  edi, r12d
    shr  edi, 1
    and  edi, 1
    call f1_put_dec
.quality_done:
    call guardian_alert_iommu_status
    mov  rbx, rcx
    mov  r12, rdx
    mov  rdi, rax
    push rdi
    lea  rdi, [rel str_gi_native]
    call f1_put_str
    pop  rdi
    call f1_put_dec
    lea  rdi, [rel str_gi_native_drop]
    call f1_put_str
    mov  rdi, r12
    call f1_put_dec
    lea  rdi, [rel str_gi_native_fold]
    call f1_put_str
    mov  rdi, rbx
    call f1_put_dec
    call guardian_alert_hid_status
    mov  rbx, rcx
    mov  r12, rdx
    push rax
    lea  rdi, [rel str_gi_hid]
    call f1_put_str
    pop  rdi
    call f1_put_dec
    lea  rdi, [rel str_gi_hid_drop]
    call f1_put_str
    mov  rdi, r12
    call f1_put_dec
    lea  rdi, [rel str_gi_hid_fold]
    call f1_put_str
    mov  rdi, rbx
    call f1_put_dec
    call guardian_alert_arp_status
    mov  rbx, rcx
    mov  r12, rdx
    push rax
    lea  rdi, [rel str_gi_arp]
    call f1_put_str
    pop  rdi
    call f1_put_dec
    lea  rdi, [rel str_gi_arp_drop]
    call f1_put_str
    mov  rdi, r12
    call f1_put_dec
    lea  rdi, [rel str_gi_arp_fold]
    call f1_put_str
    mov  rdi, rbx
    call f1_put_dec
    call guardian_alert_cap_status
    mov  rbx, rax
    mov  r12, rdx
    lea  rdi, [rel str_gi_cap]
    call f1_put_str
    mov  rdi, rbx
    call f1_put_dec
    lea  rdi, [rel str_gi_cap_new]
    call f1_put_str
    mov  rdi, r12
    call f1_put_dec
    call guardian_alert_airlock_status
    mov  rbx, rax
    mov  r12, rdx
    lea  rdi, [rel str_gi_airlock]
    call f1_put_str
    mov  rdi, rbx
    call f1_put_dec
    lea  rdi, [rel str_gi_airlock_new]
    call f1_put_str
    mov  rdi, r12
    call f1_put_dec
    lea  rdi, [rel str_gi_tb_oseq]
    call f1_put_str
    call guardian_alert_owner_last
    test eax, eax
    jnz  .owner
    lea  rdi, [rel str_gi_none]
    call f1_put_str
    lea  rdi, [rel str_gi_tb_overb]
    call f1_put_str
    lea  rdi, [rel str_gi_none]
    call f1_put_str
    jmp  .cell
.owner:
    mov  r12d, ecx
    mov  rdi, rdx
    call f1_put_dec
    lea  rdi, [rel str_gi_tb_overb]
    call f1_put_str
    mov  edi, r12d
    call f1_put_dec
.cell:
    lea  rdi, [rel str_gi_tb_cell]
    call f1_put_str
    mov  edi, GI_X
    call f1_put_dec
    lea  rdi, [rel str_gi_comma]
    call f1_put_str
    mov  edi, [rel fb_height]
    sub  edi, TASKBAR_H - GI_YOFF
    call f1_put_dec
    lea  rdi, [rel str_gi_comma]
    call f1_put_str
    mov  edi, GI_W
    call f1_put_dec
    lea  rdi, [rel str_gi_comma]
    call f1_put_str
    mov  edi, GI_H
    call f1_put_dec
    pop  r12
    pop  rbx
    ret

gi_text:         times 24 db 0
align 4
gi_armed_w:      dd 0                   ; fb_width / fb_height when the arm was earned
gi_armed_h:      dd 0
gi_armed:        db 0                   ; a physical event outside the cell since the last injected one
str_gi_native: db " native_faults=", 0
str_gi_native_drop: db " native_queue_dropped=", 0
str_gi_native_fold: db " native_summary_only=", 0
str_gi_title:    db "GUARD", 0
str_gi_tb_new:   db " GUARD new=", 0
str_gi_tb_total: db " total=", 0
str_gi_tb_oseq:  db " owner_seq=", 0
str_gi_tb_overb: db " owner_verb=", 0
str_gi_tb_cell:  db " cell=", 0
str_gi_none:     db "none", 0
str_gi_comma:    db ",", 0

; Optional TASKBAR fields: omitted when both counts are exact (legacy text).
str_gi_unknown: db "unknown", 0
str_gi_tb_new_lower: db " new_lower_bound=", 0
str_gi_tb_total_lower: db " total_lower_bound=", 0

str_gi_hid: db " hid_observed_refusals=", 0
str_gi_hid_drop: db " hid_queue_dropped=", 0
str_gi_hid_fold: db " hid_summary_only=", 0

str_gi_arp: db " arp_observed_refusals=", 0
str_gi_arp_drop: db " arp_queue_dropped=", 0
str_gi_arp_fold: db " arp_summary_only=", 0

str_gi_cap: db " software_cap_denied=", 0
str_gi_cap_new: db " software_cap_new=", 0

str_gi_airlock: db " airlock_refused=", 0
str_gi_airlock_new: db " airlock_new=", 0

align 8
gi_armed_pid: dq 0
gi_armed_authority: dq 0
