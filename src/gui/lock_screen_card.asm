;; MODULE gui/lock_screen_card
;; LAYER 6
;; PURPOSE Responsive stock-kit sign-in card; presentation never authenticates.
;; EXPORTS lock_card_layout, lock_card_state, lock_card_click, lock_card_help_key, lock_card_clock_tick
;; IMPORTS gui/lock_screen, gui/lock_identity, gui/widget, gui/window, gui/window_mgmt, boot/gop, sec/principal
;; OWNER saga:login_surfaces

; Node 4 retains the internal authentication identifier for the unchanged
; principal path. It is hidden and never in the Tab ring. Visible name is
; deliberately Owner until an owner-configured display-name service exists.
; Absolute placement from the current mode avoids accumulated resize deltas.
lock_card_layout:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel fb_width]
    sub  r12d, 360
    sar  r12d, 1
    mov  r13d, [rel fb_height]
    sub  r13d, 286
    sar  r13d, 1
    add  r13d, 40
    cmp  r13d, 116
    jge  .bottom
    mov  r13d, 116
.bottom:
    mov  eax, [rel fb_height]
    sub  eax, 320
    cmp  r13d, eax
    jle  .top
    mov  r13d, eax
.top:
    cmp  r13d, 12
    jge  .place
    mov  r13d, 12
.place:
    lea  r14, [rel lock_card_rects]
    mov  r15d, 1
.next:
    mov  edi, [rel lock_widget_first]
    add  edi, r15d
    call wgt_slot_ptr
    mov  ecx, [r14]
    add  ecx, r12d
    mov  [rax + WGI_X], ecx
    mov  ecx, [r14 + 4]
    add  ecx, r13d
    mov  [rax + WGI_Y], ecx
    mov  ecx, [r14 + 8]
    mov  [rax + WGI_W], ecx
    mov  ecx, [r14 + 12]
    mov  [rax + WGI_H], ecx
    add  r14, 16
    inc  r15d
    cmp  r15d, LOCK_FORM_WIDGETS
    jb   .next
    ; The action is still node 7: unchanged activation/name/authority. Pair
    ; it with the masked field so a standalone field refresh restores it.
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    call wgt_slot_ptr
    or   dword [rax + WGI_EDIT], WGT_EDIT_INSET_ACTION
    lea  ecx, [rdi + 2]                ; action id + 1
    mov  [rax + WGI_EDITPAD], ecx
    inc  edi
    call wgt_slot_ptr
    or   dword [rax + WGI_EDIT], WGT_EDIT_ARROW
    mov  edi, [rel lock_widget_first]
    add  edi, 9
    call wgt_slot_ptr
    or   dword [rax + WGI_EDIT], WGT_EDIT_HELP_ICON
    ; The clock row sits 100 px above the card and never displaces sign-in:
    ; it shows whenever the clamped card top leaves it on screen (top >= 116,
    ; so any height >= 436; Bee's 800x600 included). Unseeded time is never
    ; invented.
    call taskbar_read_wall
    xor  ebx, ebx
    cmp  r13d, 116
    jl   .clock
    cmp  byte [rel clock_wall_valid], 1
    jne  .clock
    mov  ebx, 1
.clock:
    mov  edi, [rel lock_widget_first]
    add  edi, 11
    call wgt_slot_ptr
    mov  [rax + WGI_FLAGS], ebx
    inc  edi
    call wgt_slot_ptr
    mov  [rax + WGI_FLAGS], ebx
    test ebx, ebx
    jz   .identity
    call taskbar_format_clock
    call lock_card_clock_text
    mov  edi, [rel lock_widget_first]
    add  edi, 11
    lea  rsi, [rel lock_clock_text]
    call wgt_set_text
    mov  edi, [rel lock_widget_first]
    add  edi, 12
    lea  rsi, [rel clock_date_str]
    call wgt_set_text
.identity:
    mov  edi, [rel lock_widget_first]
    add  edi, 4
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Called at a real relock epoch, alongside the existing native setup label.
; Does not manufacture a verification code state or a new authentication API.
lock_card_state:
    mov  byte [rel lock_card_help], 0
    mov  edi, [rel lock_widget_first]
    add  edi, 2
    lea  rsi, [rel str_lock_owner_display]
    call principal_first_owner_available
    cmp  byte [rel lock_setup_staged], 1
    je   .setup_title
    cmp  eax, 1
    jne  .title
.setup_title:
    lea  rsi, [rel str_lock_card_setup]
.title:
    call wgt_set_text
    mov  edi, [rel lock_widget_first]
    add  edi, 13
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 0
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 1
    inc  edi
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 1
    mov  edi, [rel lock_widget_first]
    add  edi, 9
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 1
    call principal_first_owner_available
    cmp  byte [rel lock_setup_staged], 1
    je   .hide_forgot
    cmp  eax, 1
    jne  .out
.hide_forgot:
    mov  edi, [rel lock_widget_first]
    add  edi, 9
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 0
.out:
    call lock_identity_sync
    ret

; EDI widget id -> EAX 1 handled, 0 normal lock action. A guidance page
; clears the transient secret and cancels any pending activation; it can
; never stage an owner, offer a principal or unlock. This release has no
; password recovery route, and the page says so (root 90461).
lock_card_click:
    mov  eax, edi
    sub  eax, [rel lock_widget_first]
    cmp  byte [rel lock_card_help], 1
    jne  .normal
    cmp  eax, 13
    je   .back
    jmp  .handled
.normal:
    cmp  eax, 9
    jne  .not_handled
    cmp  byte [rel lock_setup_staged], 1
    je   .handled
    call principal_first_owner_available
    cmp  eax, 1
    je   .handled
    call wgt_secret_clear
    mov  byte [rel lock_submit_pending], 0
    mov  byte [rel lock_submit_human], 0
    mov  byte [rel lock_card_help], 1
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 0
    inc  edi
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 0
    mov  edi, [rel lock_widget_first]
    add  edi, 9
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 0
    mov  edi, [rel lock_widget_first]
    add  edi, 13
    call wgt_slot_ptr
    mov  dword [rax + WGI_FLAGS], 1
    mov  [rel wgt_focus_id], edi
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], edi
    mov  edi, [rel lock_widget_first]
    add  edi, 8
    lea  rsi, [rel str_lock_card_recovery]
    call wgt_set_text
    jmp  .paint
.back:
    call wgt_secret_clear
    mov  byte [rel lock_submit_pending], 0
    mov  byte [rel lock_submit_human], 0
    call lock_card_state
    mov  edi, [rel lock_widget_first]
    add  edi, 8
    call lock_prompt_text
    call wgt_set_text
    mov  edi, [rel lock_widget_first]
    add  edi, 6
    mov  [rel wgt_focus_id], edi
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], edi
.paint:
    call lock_screen_paint
.handled:
    mov  eax, 1
    ret
.not_handled:
    xor  eax, eax
    ret

; EAX key, only while help is shown. Enter/Esc return to the masked field;
; Tab stays on the only visible action and selects its keyboard focus ring.
; Printable keys cannot reach the hidden editor or submit path.
lock_card_help_key:
    cmp  eax, GUI_KEY_TAB
    je   .tab
    cmp  eax, GUI_KEY_ENTER
    je   .back
    cmp  eax, GUI_KEY_ESC
    jne  .out
.back:
    mov  edi, [rel lock_widget_first]
    add  edi, 13
    call lock_card_click
    jmp  .out
.tab:
    mov  byte [rel wgt_tab_reverse], 0
    mov  byte [rel wgt_focus_visible], 1
    mov  edi, [rel lock_widget_first]
    add  edi, 13
    mov  [rel wgt_focus_id], edi
    mov  [rel wgt_focus_by_win + LOCK_SLOT*4], edi
    mov  edi, LOCK_SLOT
    call wmx_draw_one
    call fb_present_all
.out:
    mov  eax, 1
    ret

; The tray's sync predicate and marker glyph, in one 8x16 cell left of the
; time: '~' until an NTP sample has set the wall, a blank cell after, so the
; time never moves. The locked card must not show an estimate as exact.
lock_card_clock_text:
    mov  al, ' '
    cmp  byte [rel time_wall_source], TIME_SRC_NTP
    je   .mark
    mov  al, [rel clock_unsynced_str]
.mark:
    mov  [rel lock_clock_text], al
    mov  rax, [rel clock_str]             ; eight time glyphs
    mov  [rel lock_clock_text + 1], rax
    mov  byte [rel lock_clock_text + 9], 0
    ret

; Locked branch of the attention cadence. The tray tick only wakes DPMS while
; locked, so without this the card kept its first time and marker. Repaint
; the sign-in surface once when the shown time, date or marker would change.
lock_card_clock_tick:
    cmp  byte [rel dpms_blanked], 1
    je   .out
    cmp  byte [rel lock_composition_ok], 1
    jne  .out
    cmp  byte [rel fb_present_boot_hold], 0
    jne  .out
    cmp  qword [rel fb_base], 0
    je   .out
    cmp  dword [rel fb_height], 436       ; below this the card top leaves no clock row
    jb   .out
    push rbx
    push r12
    push r13
    push r14
    push r15
    call taskbar_read_wall
    cmp  byte [rel clock_wall_valid], 1
    jne  .done
    mov  edi, [rel lock_widget_first]
    add  edi, 11
    call wgt_slot_ptr
    test dword [rax + WGI_FLAGS], 1
    jz   .paint                           ; a wall became valid while locked
    mov  r12, rax                         ; taskbar_format_clock uses BL
    call taskbar_format_clock
    call lock_card_clock_text
    lea  rdi, [r12 + WGI_VAL]
    lea  rsi, [rel lock_clock_text]
    mov  ecx, 10
    repe cmpsb
    jne  .paint
    mov  edi, [rel lock_widget_first]
    add  edi, 12
    call wgt_slot_ptr
    lea  rdi, [rax + WGI_VAL]
    lea  rsi, [rel clock_date_str]
    mov  ecx, 11
    repe cmpsb
    je   .done
.paint:
    call lock_screen_paint
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

lock_card_rects:
    dd 0,0,360,286                     ; card (stock container)
    dd 20,106,320,24                   ; centered public owner / setup title
    dd 20,142,240,20                   ; Password
    dd 20,20,0,0                       ; hidden internal id; no paint/hit
    dd 292,142,48,20                   ; independent keyboard layout
    dd 20,167,320,32                   ; masked input
    dd 304,170,32,26                   ; inset Sign in / native stage arrow
    dd 20,202,320,40                   ; status, never entered secret
    dd 192,242,32,28                   ; Account help: same public name/action, native question icon
    dd 136,12,88,88                    ; centered login-initial avatar
    dd 0,-100,360,32                   ; canonical clock, if room/valid
    dd 0,-50,360,20                    ; canonical date
    dd 20,242,320,28                   ; Back to sign-in (help only)
str_lock_owner_display: db "Owner",0
str_lock_card_setup: db "Set up PaOS",0
str_lock_card_recovery: db "Password cannot be recovered",0
%macro WDATA_gui_lock_screen_card_0 0
lock_card_help: db 0
lock_clock_text: db "~00:00 AM", 0      ; sync marker cell + eight time glyphs
%endmacro
WDATA_DEFER WDATA_gui_lock_screen_card_0
