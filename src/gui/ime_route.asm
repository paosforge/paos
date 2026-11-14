;; MODULE gui/ime_route
;; LAYER 6
;; EXPORTS ime_route_init, imr_dropped
;; IMPORTS gui/input_route, gui/ime_core, gui/ime_view, gui/ime_dict_absent, gui/lock_screen, gui/widget, gui/window, core/lib/str, gui/window_mgmt, gui/summon_palette, core/unicode_edit, dev/input/ps2, sec/session
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
;
; RCQ-38 I3b-1 (PLAN_I3B_IME_WIRING bfeb7084, root 15:25 RULING_I3B_IME_1525): the IME in the desktop's key path.
; gui/input_route calls these through input_ime_ops (ime_route_init fills it after the router's boot KAT):
;
;   stage  At .deliver, after the lock assert, before the modal hook, the menu and the field. Only while the method
;          is not OFF, for the target the ordinary path would deliver to (imr_target): unlocked, no Summon palette, the
;          focused window's focused widget a textfield that is neither disabled nor ASCII-only nor role "password". The
;          kit's secret type is another widget type and the lock screen is locked, so all three secret surfaces bypass
;          (rc-sec 10:37:44 (c)); so do the Terminal and its SSH line, which are no textfield (root Q3: I3b-2).
;          ime_key PASSes any key that is not KO_HUMAN with its state untouched, so an injected key types Latin and
;          every commit is the owner's (s3).
;   pump   A commit is held here and released as GUI_KEY_TEXT chunks, each <= WGT_TEXT_CAP and cut on a grapheme
;          boundary, origin KO_HUMAN, before any later key of the same pass; each takes the router's own path (lock
;          assert, modal hook, filters, field). Before EACH chunk the target is re-qualified (the same widget, no
;          session change, still an IME textfield); a failure drops the rest, counts it in imr_dropped and cancels.
;          It is never redirected (root Q4). A key ime_key PASSed with a commit follows the commit.
;   toggle Ctrl+Space from the owner's hand (RCQ-51; Win+Space is the AI key's chord now), only while imr_target
;          qualifies: OFF -> ja -> zh-Hans -> OFF, a method whose bind refuses skipped. Anywhere else (the Terminal,
;          whose Ctrl+Space is NUL, a password or secret field, the sign-in surface, the Summon palette) it changes
;          nothing and the router delivers the key as before.
;   reset  Every dead-key cancel (focus, widget or z change, a layout change, a session or lock change) cancels the
;          composition. When session_authority_epoch or session_locked moved since the IME last looked, the method
;          is also turned OFF (root Q1 (a)); the stage looks too. A cancel never commits (rc-sec 10:37:44).
;   tray   After a toggle or a session OFF, input_ime_tray follows the method (plan item 6): 0 while OFF, so the
;          taskbar is exactly as without the IME; else ime_view_mode's scalar, with INPUT_IME_TRAY_NODICT while
;          ime_dict_bound is 0, so the cell and the TASKBAR verb say "no dict" (root 16:01:48 (2)(a)). A change
;          repaints the taskbar through lock_screen's gate (nothing while locked).
;   popup  After every ime_key action, input_ime_pop follows the IME (plan item 5): while CONVERTING, ime_view_build's
;          window for the field (anchored to the field's painted rect, its border included, in the work area, so
;          it never covers the field or the taskbar), its rows as pre-measured scalars; after Space with no
;          candidate list, one notice line:
;          "no dictionary" while ime_dict_bound is 0 (root 16:01:48 (2)(a)), else "unavailable" or "no candidates".
;          Every cancel hides it. A change repaints the desktop, never under the lock; gui/window paints it.

%ifndef IME_DICT_LINKED                 ; root 16:01:48 (2)(b): exactly one dictionary (gui/ime_dict_absent's header)
%fatal "IME_BUILT 1 links no IME dictionary: gui/ime_dict_absent (or I1) goes before gui/ime_route"
%endif

IMR_GUI_KEYS        equ 9               ; imr_keymap rows
IMR_CELL_W          equ 8               ; the desktop's text cell (font8x16)
IMR_CELL_H          equ 16
IMR_NOTICE_W        equ (INPUT_IME_POP_NOTICE + 2) * IMR_CELL_W ; gui/window's notice line and a cell either side
IMR_NOTICE_H        equ IMR_CELL_H + 2 * INPUT_IME_POP_PADY

; ime_route_init(): the method starts OFF; install the router's IME seam. Clobbers caller-saved.
ime_route_init:
    sub  rsp, 8
    xor  edi, edi
    call ime_set_method                 ; OFF (I2 prints nothing for OFF)
    lea  rax, [rel imr_stage]
    mov  [rel input_ime_ops + INPUT_IME_STAGE], rax
    lea  rax, [rel imr_pump]
    mov  [rel input_ime_ops + INPUT_IME_PUMP], rax
    lea  rax, [rel imr_toggle]
    mov  [rel input_ime_ops + INPUT_IME_TOGGLE], rax
    lea  rax, [rel imr_reset]
    mov  [rel input_ime_ops + INPUT_IME_RESET], rax
    call imr_session_seen
    add  rsp, 8
    ret

; imr_session_seen(): note the session state the method was chosen under. Clobbers RAX.
imr_session_seen:
    mov  rax, [rel session_authority_epoch]
    mov  [rel imr_epoch], rax
    mov  al, [rel session_locked]
    mov  [rel imr_locked], al
    ret

; imr_session_check(): a session or lock change since imr_session_seen turns the method OFF (with a cancel).
; Clobbers caller-saved.
imr_session_check:
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel imr_epoch]
    jne  .changed
    mov  al, [rel session_locked]
    cmp  al, [rel imr_locked]
    je   .out
.changed:
    sub  rsp, 8
    call imr_session_seen
    call imr_cancel
    xor  edi, edi
    call ime_set_method
    call imr_publish
    add  rsp, 8
.out:
    ret

; imr_publish(): input_ime_tray from the method and the dictionary; a change repaints the taskbar. Clobbers
; caller-saved.
imr_publish:
    sub  rsp, 8
    call ime_conv_info                  ; ECX state | flags << 8 | method << 16
    shr  ecx, 16
    xor  eax, eax
    test ecx, ecx
    jz   .have                          ; OFF: no cell
    call ime_view_mode
    cmp  byte [rel ime_dict_bound], 0
    jne  .have
    or   eax, INPUT_IME_TRAY_NODICT
.have:
    cmp  eax, [rel input_ime_tray]
    je   .out
    mov  [rel input_ime_tray], eax
    call taskbar_draw_registry          ; lock-gated: nothing while the session is locked
.out:
    add  rsp, 8
    ret

; imr_popup(EDI target, -1 none): input_ime_pop from the IME's state for that field; a change (shown before or now)
;   repaints the desktop while unlocked. Every publish starts from a window with no rows (rc-sec SEC-3, root 19:08:50):
;   a hidden window or a notice keeps no candidate text. Clobbers caller-saved.
imr_popup:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel input_ime_pop + INPUT_IME_POP_KIND] ; shown before
    mov  dword [rel input_ime_pop + INPUT_IME_POP_KIND], 0
    mov  ebx, edi
    lea  rdi, [rel input_ime_pop + INPUT_IME_POP_ROWS] ; ROWS, SEL, MARKS and every row
    mov  ecx, INPUT_IME_POP_SIZE - INPUT_IME_POP_ROWS
    xor  eax, eax
    rep  stosb
    mov  edi, ebx
    cmp  edi, -1
    je   .publish
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_WIN]
    mov  [rel input_ime_pop + INPUT_IME_POP_WIN], ecx
    mov  r13d, [rax + WGI_X]            ; the anchor: the field's painted rect
    mov  r14d, [rax + WGI_Y]
    dec  r14d                           ; its border is 1 px proud on every side, so above ends at y-1
    mov  r15d, [rax + WGI_H]
    add  r15d, 2                        ; and below starts at y+h+1
    mov  r8d, [rel fb_height]
    sub  r8d, TASKBAR_H                 ; the work area
    jle  .publish
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, [rel fb_width]
    mov  r9d, IMR_CELL_W | (IMR_CELL_H << 16)
    call ime_view_build
    cmp  eax, IMV_SHOWN
    je   .cands
    mov  ebx, INPUT_IME_POP_NOCANDS
    cmp  eax, IMV_NO_CANDIDATES
    je   .notice
    cmp  eax, IMV_UNAVAILABLE
    jne  .publish                       ; not converting, or no room: none
    mov  ebx, INPUT_IME_POP_UNAVAIL
    cmp  byte [rel ime_dict_bound], 0
    jne  .notice
    mov  ebx, INPUT_IME_POP_NODICT
.notice:                                ; one line, placed as ime_view_build places its window
    mov  ecx, [rel fb_width]
    sub  ecx, IMR_NOTICE_W              ; the rightmost x
    jl   .publish
    mov  eax, r13d
    cmp  eax, ecx
    cmovg eax, ecx
    xor  ecx, ecx
    test eax, eax
    cmovs eax, ecx
    mov  [rel input_ime_pop + INPUT_IME_POP_X], eax
    mov  ecx, [rel fb_height]
    sub  ecx, TASKBAR_H + IMR_NOTICE_H  ; the lowest y
    jl   .publish
    lea  eax, [r14 + r15]               ; below the field
    cmp  eax, ecx
    jle  .notice_y
    mov  eax, r14d
    sub  eax, IMR_NOTICE_H              ; above it
    jns  .notice_y
    mov  eax, ecx                       ; bottom-aligned
.notice_y:
    cmp  eax, ecx
    cmovg eax, ecx
    xor  ecx, ecx
    test eax, eax
    cmovs eax, ecx
    mov  [rel input_ime_pop + INPUT_IME_POP_Y], eax
    mov  dword [rel input_ime_pop + INPUT_IME_POP_W], IMR_NOTICE_W
    mov  dword [rel input_ime_pop + INPUT_IME_POP_H], IMR_NOTICE_H
    xor  eax, eax
    mov  [rel input_ime_pop + INPUT_IME_POP_ROWS], eax
    mov  [rel input_ime_pop + INPUT_IME_POP_SEL], eax
    mov  [rel input_ime_pop + INPUT_IME_POP_MARKS], eax
    mov  [rel input_ime_pop + INPUT_IME_POP_KIND], ebx
    jmp  .publish
.cands:
    lea  rdi, [rel imr_view]
    call ime_view_get
    lea  rbx, [rel imr_view]
    mov  eax, [rbx + IMV_X]
    mov  [rel input_ime_pop + INPUT_IME_POP_X], eax
    mov  eax, [rbx + IMV_Y]
    mov  [rel input_ime_pop + INPUT_IME_POP_Y], eax
    mov  eax, [rbx + IMV_W]
    mov  [rel input_ime_pop + INPUT_IME_POP_W], eax
    mov  eax, [rbx + IMV_H]
    mov  [rel input_ime_pop + INPUT_IME_POP_H], eax
    mov  eax, [rbx + IMV_SELROW]
    mov  [rel input_ime_pop + INPUT_IME_POP_SEL], eax
    mov  eax, [rbx + IMV_MARKS]
    mov  [rel input_ime_pop + INPUT_IME_POP_MARKS], eax
    mov  r13d, [rbx + IMV_ROWS]         ; <= IMV_PAGE
    xor  r14d, r14d
.row:
    cmp  r14d, r13d
    jae  .rows_done
    mov  edi, [rel imr_view + IMV_FIRST]
    add  edi, r14d
    lea  rsi, [rel imr_surf]
    call ime_cand_get
    test eax, eax
    jnz  .publish                       ; cannot happen: the view just read it; none rather than a partial window
    lea  rax, [rel imr_view]
    mov  esi, [rax + IMV_ROW0 + r14*8]  ; the bytes the view shows
    movzx edx, word [rax + IMV_ROW0 + r14*8 + 6]
    mov  edi, r14d
    call imr_row
    inc  r14d
    jmp  .row
.rows_done:
    mov  [rel input_ime_pop + INPUT_IME_POP_ROWS], r13d
    mov  dword [rel input_ime_pop + INPUT_IME_POP_KIND], INPUT_IME_POP_CANDS
.publish:
    mov  eax, [rel input_ime_pop + INPUT_IME_POP_KIND]
    or   eax, r12d
    jz   .out                           ; hidden before and now: nothing to repaint
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out                           ; the unlock repaints everything
    call wmx_draw_all
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; imr_row(EDI row, ESI the bytes shown of imr_surf, EDX the view's row flags): that row of input_ime_pop, one entry
;   per scalar of 1 or 2 cells (a width-0 mark paints nothing; a C0, DEL or C1 control is U+FFFD, which paints
;   boxed), then the cut mark '>' when the view cut it.
;   Clobbers caller-saved.
imr_row:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8                         ; ue_utf8_decode's {scalar, bytes}
    imul eax, edi, INPUT_IME_POP_ROW_SIZE
    lea  rbx, [rel input_ime_pop + INPUT_IME_POP_ROW0]
    add  rbx, rax
    mov  r12d, esi
    mov  r13d, edx
    xor  r14d, r14d                     ; the byte offset
    mov  dword [rbx], 0
.next:
    cmp  r14d, r12d
    jae  .mark
    lea  rdi, [rel imr_surf]
    mov  esi, r12d
    mov  edx, r14d
    mov  rcx, rsp
    call ue_utf8_decode
    cmp  eax, 1
    jne  .mark                          ; the view stopped there too
    add  r14d, [rsp + 4]
    mov  edi, [rsp]
    call ue_cell_width
    test eax, eax
    jle  .next
    mov  ecx, [rsp]
    cmp  ecx, 0x20
    jb   .control
    cmp  ecx, 0x7F
    jb   .entry
    cmp  ecx, 0xA0
    jae  .entry
.control:                               ; C0, DEL, C1 from a shard: the boxed placeholder, never a control cell
    mov  dword [rsp], 0xFFFD
.entry:
    mov  ecx, [rbx]
    cmp  ecx, INPUT_IME_POP_CELLS
    jae  .out                           ; cannot happen: the view's cells are <= IMV_COLS
    shl  eax, 24
    or   eax, [rsp]
    mov  [rbx + 4 + rcx*4], eax
    inc  dword [rbx]
    jmp  .next
.mark:
    test r13d, IMV_ROW_CUT
    jz   .out
    mov  ecx, [rbx]
    cmp  ecx, INPUT_IME_POP_CELLS
    jae  .out
    mov  dword [rbx + 4 + rcx*4], '>' | (1 << 24)
    inc  dword [rbx]
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; imr_target() -> EAX the widget the router's ordinary path delivers to when it may take the IME, else -1.
; Clobbers caller-saved.
imr_target:
    push rbx
    mov  ebx, -1
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .out
    cmp  byte [rel summon_palette_open], 1
    je   .out                           ; the one modal keyboard owner keeps its keys
    pushfq
    cli
    mov  edi, [rel wm_focus]
    mov  eax, -1
    cmp  edi, WM_MAX
    jae  .snap
    call wgt_focus_window               ; the router's own focus snapshot
.snap:
    popfq
    test eax, eax
    js   .out
    mov  ebx, eax
    mov  edi, eax
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_TEXTFIELD
    jne  .none
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED | WGT_EDIT_ASCII
    jnz  .none
    mov  rdi, [rax + WGI_ROLE]          ; a stock textfield with role "password" is secret-class too
    test rdi, rdi                       ;   (wgt_secret_hidden's rule): no IME in it
    jz   .out
    lea  rsi, [rel str_wgt_role_password]
    call strcmp
    test eax, eax
    jnz  .out
.none:
    mov  ebx, -1
.out:
    mov  eax, ebx
    pop  rbx
    ret

; imr_map(EDI router key) -> EAX the ime_key key, 0 = not an IME key (it goes on untouched). Printable ASCII and a
; layout's scalar map to themselves (Space is 32, digits pick a candidate); controls and Ctrl+letter do not.
imr_map:
    mov  eax, edi
    cmp  eax, 0x20
    jb   .none
    cmp  eax, 0x7F
    jb   .out
    je   .none
    cmp  eax, GUI_KEY_TEXT
    je   .text
    lea  rcx, [rel imr_keymap]
    mov  edx, IMR_GUI_KEYS
.row:
    cmp  eax, [rcx]
    je   .hit
    add  rcx, 8
    dec  edx
    jnz  .row
.none:
    xor  eax, eax
.out:
    ret
.hit:
    mov  eax, [rcx + 4]
    ret
.text:
    mov  eax, [rel input_ime_lq_scalar]
    ret

; imr_stage(EDI router key) -> EAX 1 the IME took it (or holds it behind its commit), 0 deliver it on. Clobbers
; caller-saved.
imr_stage:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    xor  r13d, r13d
    cmp  byte [rel imr_bypass], 0
    jne  .released                      ; the pump's own key: never judged twice
    call imr_session_check
    call ime_conv_info                  ; only reads: ECX state | flags << 8 | method << 16
    shr  ecx, 16
    test ecx, ecx
    jz   .out                           ; OFF: exactly the path without the IME
    call imr_target
    mov  r12d, eax
    call input_layout_focus_check       ; a focus change since the router's last stamp cancels first
    mov  eax, [rel imr_to]
    test eax, eax
    jz   .fresh
    lea  ecx, [r12 + 1]
    cmp  eax, ecx
    je   .fresh
    call imr_cancel                     ; another target, or none: the composition is not carried over
.fresh:
    cmp  r12d, -1
    je   .out
    mov  edi, ebx
    call imr_map
    test eax, eax
    jz   .out
    mov  edi, eax
    movzx esi, byte [rel input_key_origin]
    call ime_key
    test eax, eax
    jz   .out                           ; PASS: not the owner's hand, or nothing to do
    mov  r13d, eax
    lea  eax, [r12 + 1]
    mov  [rel imr_to], eax
    test r13d, IME_A_COMMIT
    jz   .no_commit
    mov  edi, r12d
    call imr_take
.no_commit:
    test r13d, IME_A_PREEDIT
    jz   .no_preedit
    mov  edi, r12d
    call imr_show
.no_preedit:
    mov  edi, r12d
    call imr_popup                      ; the candidate window follows every action
    test r13d, IME_A_CONSUMED
    jnz  .took
    cmp  dword [rel imr_n], 0
    je   .pass
    mov  [rel imr_after], ebx           ; PASSed with a commit: the key goes after the commit
    mov  eax, [rel input_ime_lq_scalar]
    mov  [rel imr_after_scalar], eax
    mov  al, [rel input_key_origin]
    mov  [rel imr_after_origin], al
    mov  byte [rel imr_after_live], 1
.took:
    mov  r13d, 1
    jmp  .out
.pass:
    xor  r13d, r13d
    jmp  .out
.released:
    mov  byte [rel imr_bypass], 0
.out:
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret

; imr_take(EDI target): hold the IME's commit for the pump. The pump drains a commit before the router reaches the
; stage again, so none is held here already. Clobbers caller-saved.
imr_take:
    push rbx
    mov  ebx, edi
    cmp  dword [rel imr_n], 0
    jne  .out
    lea  rdi, [rel imr_buf]
    mov  esi, IMR_COMMIT_CAP
    call ime_commit_take
    test eax, eax
    jle  .out
    mov  [rel imr_n], eax
    mov  dword [rel imr_off], 0
    mov  [rel imr_commit_to], ebx
    mov  rax, [rel session_authority_epoch]
    mov  [rel imr_commit_epoch], rax
.out:
    pop  rbx
    ret

; imr_show(EDI target): the IME's pre-edit at the field's caret through L3b's seam (length 0 clears it). A field
; that refuses it (no longer focused, ...) shows nothing. Clobbers caller-saved.
imr_show:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel imr_pre]
    mov  esi, WGT_TEXT_CAP
    call ime_preedit                    ; EAX bytes, EDX the caret
    test eax, eax
    jns  .have
    xor  eax, eax                       ; cannot happen: WGT_TEXT_CAP is I2's IME_VIEW_CAP
    xor  edx, edx
.have:
    mov  ecx, edx
    mov  edx, eax
    lea  rsi, [rel imr_pre]
    mov  edi, ebx
    call wgt_textfield_preedit
    pop  rbx
    ret

; imr_cancel(): discard the composition, the field's pre-edit, any commit not yet released (counted), and its
; deferred literal key. The method stays. Clobbers caller-saved.
imr_cancel:
    sub  rsp, 8
    mov  byte [rel imr_after_live], 0   ; the literal behind a commit belongs to the cancelled context too
    call ime_cancel
    mov  edi, -1
    call imr_popup                      ; hidden
    mov  eax, [rel imr_n]
    sub  eax, [rel imr_off]
    add  [rel imr_dropped], rax
    xor  eax, eax
    mov  [rel imr_n], eax
    mov  [rel imr_off], eax
    mov  byte [rel imr_reshow], 0
    mov  eax, [rel imr_to]
    test eax, eax
    jz   .out
    mov  dword [rel imr_to], 0
    lea  edi, [rax - 1]
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
    call wgt_textfield_preedit          ; length 0: cleared if that field still shows it
.out:
    add  rsp, 8
    ret

; imr_pump() -> EAX the next key to deliver: a GUI_KEY_TEXT chunk of the held commit (wgt_text_buf/len), then the
; key ime_key PASSed behind it, only while its original field/session still qualifies; -1 none.
; Sets input_key_origin. Clobbers caller-saved.
imr_pump:
    push rbx
    push r12
    push r13
    mov  byte [rel imr_bypass], 0       ; a released key the lock assert dropped leaves no stale mark
    cmp  byte [rel imr_reshow], 0
    je   .chunks
    mov  byte [rel imr_reshow], 0       ; the last chunk replaced the field's pre-edit: zh keeps a remainder
    mov  edi, [rel imr_commit_to]
    call imr_show
.chunks:
    cmp  dword [rel imr_n], 0
    jne  .chunk
    cmp  byte [rel imr_after_live], 0
    jne  .after
    mov  eax, -1
    jmp  .out
.chunk:
    call imr_target
    cmp  eax, [rel imr_commit_to]
    jne  .drop
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel imr_commit_epoch]
    jne  .drop
    mov  ebx, [rel imr_off]             ; chunk start
    mov  r12d, ebx                      ; its end so far
.walk:
    lea  rdi, [rel imr_buf]
    mov  esi, [rel imr_n]
    mov  edx, r12d
    call ue_grapheme_next
    test rax, rax
    js   .drop                          ; not UTF-8: cannot happen, I2 commits valid UTF-8
    cmp  eax, r12d
    je   .cut                           ; the end of the commit
    mov  ecx, eax
    sub  ecx, ebx
    cmp  ecx, WGT_TEXT_CAP - 1         ; consumers admit 1..195 B (SEC C3(a))
    ja   .cut
    mov  r12d, eax
    jmp  .walk
.cut:
    mov  ecx, r12d
    sub  ecx, ebx
    jz   .drop                          ; one grapheme over the consumer cap
    mov  [rel wgt_text_len], ecx
    lea  rdi, [rel wgt_text_buf]
    lea  rsi, [rel imr_buf]
    add  rsi, rbx
    rep  movsb
    mov  [rel imr_off], r12d
    cmp  r12d, [rel imr_n]
    jb   .give
    xor  eax, eax
    mov  [rel imr_n], eax
    mov  [rel imr_off], eax
    mov  byte [rel imr_reshow], 1
.give:
    mov  byte [rel input_key_origin], KO_HUMAN
    mov  byte [rel imr_bypass], 1
    mov  eax, GUI_KEY_TEXT
    jmp  .out
.drop:
    call imr_cancel                     ; counts the rest; the composition is gone
    jmp  .chunks
.after:
    call input_layout_focus_check       ; focus/widget/z changes cancel the queued literal with the composition
    cmp  byte [rel imr_after_live], 0
    je   .chunks
    call imr_target
    cmp  eax, [rel imr_commit_to]
    jne  .drop
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel imr_commit_epoch]
    jne  .drop
    mov  byte [rel imr_after_live], 0
    mov  byte [rel imr_bypass], 1
    mov  al, [rel imr_after_origin]
    mov  [rel input_key_origin], al
    cmp  al, KO_HUMAN
    je   .after_noted
    inc  dword [rel input_other_origin_seq]
.after_noted:
    mov  eax, [rel imr_after]
    cmp  eax, GUI_KEY_TEXT
    jne  .out
    mov  edi, [rel imr_after_scalar]    ; the chunks reused wgt_text_buf: encode the key's scalar again
    lea  rsi, [rel wgt_text_buf]
    mov  edx, WGT_TEXT_CAP
    call ue_utf8_encode
    test eax, eax
    jle  .lost
    mov  [rel wgt_text_len], eax
    mov  eax, GUI_KEY_TEXT
    jmp  .out
.lost:
    lock inc qword [rel input_text_dropped]
    mov  byte [rel imr_bypass], 0
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; imr_toggle() -> EAX 1 toggled, 0 no IME target (nothing changed): Ctrl+Space (RCQ-51). OFF -> ja -> zh-Hans -> OFF;
; a method whose ime_set_method refuses is skipped (I2's marker names it). Clobbers caller-saved.
imr_toggle:
    push rbx
    call imr_target
    test eax, eax
    js   .refuse                        ; not an IME textfield: the key is the field's (Terminal: NUL)
    call imr_cancel
    call ime_conv_info
    shr  ecx, 16
    movzx ebx, cl
.step:
    inc  ebx
    cmp  ebx, IME_M_ZH
    ja   .off
    mov  edi, ebx
    call ime_set_method
    test eax, eax
    jnz  .step
    jmp  .done
.off:
    xor  edi, edi
    call ime_set_method
.done:
    call imr_publish
    mov  eax, 1
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    pop  rbx
    ret

; imr_reset(): the router's dead-key cancel. Clobbers caller-saved.
imr_reset:
    sub  rsp, 8
    call imr_cancel
    call imr_session_check
    add  rsp, 8
    ret

align 4
imr_keymap:                             ; router key -> ime_key key
    dd GUI_KEY_BACKSPACE, IME_K_BACKSPACE
    dd GUI_KEY_ENTER,     IME_K_ENTER
    dd GUI_KEY_ESC,       IME_K_ESCAPE
    dd GUI_KEY_UP,        IME_K_UP
    dd GUI_KEY_DOWN,      IME_K_DOWN
    dd GUI_KEY_LEFT,      IME_K_LEFT
    dd GUI_KEY_RIGHT,     IME_K_RIGHT
    dd GUI_KEY_PGUP,      IME_K_PGUP
    dd GUI_KEY_PGDN,      IME_K_PGDN
imr_keymap_end:

IMR_COMMIT_CAP      equ 384             ; = ime_core's IME_COMMIT_CAP (census-pinned)

%macro WDATA_gui_ime_route 0
alignb 8
imr_dropped:         resq 1              ; commit bytes dropped: a chunk's target stopped qualifying, or a cancel
imr_commit_epoch:    resq 1              ; session_authority_epoch when the commit was taken
imr_n:               resd 1              ; the held commit's bytes in imr_buf (0 none)
imr_off:             resd 1              ; released so far
imr_commit_to:       resd 1              ; the widget the commit was made in
imr_to:              resd 1              ; id + 1 of the composition's field, 0 none
imr_after:           resd 1              ; the key ime_key PASSed behind its commit
imr_after_scalar:    resd 1
imr_after_live:      resb 1
imr_after_origin:    resb 1
imr_reshow:          resb 1              ; the last chunk went: show the remaining pre-edit again
imr_bypass:          resb 1              ; the key at the stage is the pump's own
imr_locked:          resb 1              ; session_locked when the method was last allowed
alignb 8
imr_epoch:           resq 1              ; session_authority_epoch then
alignb 8
imr_buf:             resb IMR_COMMIT_CAP
imr_pre:             resb WGT_TEXT_CAP
alignb 8
imr_view:            resb IMV_SIZE       ; ime_view_get's copy, for input_ime_pop
imr_surf:            resb IMV_SURF_CAP   ; one candidate's surface
%endmacro
WDATA_BSS_DEFER WDATA_gui_ime_route
