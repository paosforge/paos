;; MODULE gui/demo_three_windows
;; LAYER 6
;; EXPORTS demo_three_windows_init, demo_three_windows_retire
;; IMPORTS boot/serial, gui/window_mgmt, gui/form_loader, gui/widget, gui/widget_console_grid
;; CAPS
;; OWNER saga:gui_foundation_ladder
; F1 (2110): three-window demo composed exclusively through WM/widget APIs.
; This file intentionally has zero calls to any render primitive.
demo_three_windows_init:
    call wmx_retire_floor_windows
    call demo_click_install             ; B18: the demo-only Action callback (kit click-hook chain)
    xor  edi, edi                       ; demo_a.frm
    mov  edx, 1                         ; boot proof intentionally focuses in order
    call form_load_internal
    test eax, eax
    jnz  .fail
    mov  [rel demo_slots + 0], ecx      ; B18: remembered for the retire after the routing KAT
    mov  edi, 1                         ; demo_b.frm
    mov  edx, 1
    call form_load_internal
    test eax, eax
    jnz  .fail
    mov  [rel demo_slots + 4], ecx
    mov  edi, 2                         ; demo_c.frm
    mov  edx, 1
    call form_load_internal
    test eax, eax
    jnz  .fail
    mov  [rel demo_slots + 8], ecx
    lea  rdi, [rel str_chrome_marker]
    call serial_string
    lea  rdi, [rel str_taskbar_marker]
    call serial_string
    lea  rdi, [rel str_demo_marker]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_demo_fail]
    call serial_string
.out:
    ret
; ---------------------------------------------------------------------------
; B18 (burn-down 6, ADMIN 2026-10-02): the boot-proof demo is composed (the three markers
; above stay earned), then RETIRED before the desktop is handed to the user, and a
; demo-only Action callback makes Action_A/B/C visibly respond. The form key on_click
; stays accepted-but-inert (gui/form_loader.asm); general form-button verb dispatch is
; its own widget-kit backlog item. The callback rides the kit's ONE click hook
; (wgt_click_hook, chained like lock_screen / start_programs), so it also serves a
; demo form re-opened later by FORMLOAD (usage rows APP-04 / WIN-02).
; ---------------------------------------------------------------------------

; demo_three_windows_retire — close the three boot-proof demo windows. Called at the
; END of lock_screen_desktop_start (after gui_input_route_init + its KAT and the app
; inits). A slot that no longer holds a live window is skipped.
demo_three_windows_retire:
    push rbx
    xor  ebx, ebx
.next:
    cmp  ebx, 3
    jae  .done
    lea  rax, [rel demo_slots]
    mov  edi, [rax + rbx*4]
    cmp  edi, WM_MAX
    jae  .skip
    lea  rax, [rel wm_state]
    cmp  dword [rax + rdi*4], WM_FREE
    je   .skip
    cmp  dword [rax + rdi*4], WM_CLOSED
    je   .skip
    push rbx                          ; the painters under wmx_close_slot leave RBX dirty
    push rbx                          ; (test_gui_rbx_liveness); the pair keeps RSP 16-aligned
    call wmx_close_slot
    pop  rbx
    pop  rbx
.skip:
    lea  rax, [rel demo_slots]
    mov  dword [rax + rbx*4], -1
    inc  ebx
    jmp  .next
.done:
    call grid_window_b_retire          ; ADMIN ruling (2): PaOS-ANSI-B is the same boot-proof class
    lea  rdi, [rel str_demo_retired]
    call serial_string
    pop  rbx
    ret

; demo_click_install — join the kit's click-hook chain (previous hook kept).
demo_click_install:
    cmp  byte [rel demo_click_installed], 0
    jne  .out
    mov  byte [rel demo_click_installed], 1
    mov  rax, [rel wgt_click_hook]
    mov  [rel demo_click_prev], rax
    lea  rax, [rel demo_action_click]
    mov  [rel wgt_click_hook], rax
.out:
    ret

; demo_action_click(EDI = hit widget id) — for a demo button "action_<x>" (x = a..c),
; set its window's label "label_<x>" to "Action_<X> pressed <n>" (n = 1..9, cycling).
; Then always continue down the chain with EDI unchanged.
demo_action_click:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, [rax + WGI_ID]
    test rbx, rbx
    jz   .chain
    lea  rsi, [rel str_demo_action_pfx] ; "action_"
    xor  ecx, ecx
.pfx:
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .pfx_ok
    cmp  dl, [rbx + rcx]
    jne  .chain
    inc  ecx
    jmp  .pfx
.pfx_ok:
    movzx r13d, byte [rbx + 7]          ; the letter
    cmp  r13d, 'a'
    jb   .chain
    cmp  r13d, 'c'
    ja   .chain
    cmp  byte [rbx + 8], 0
    jne  .chain
    mov  r14d, [rax + WGI_WIN]          ; the button's window
    ; find "label_<x>" in the same window
    lea  rax, [rel str_demo_label_pfx]  ; "label_"
    mov  ecx, [rax]
    mov  [rel demo_name_buf], ecx
    mov  cx, [rax + 4]
    mov  [rel demo_name_buf + 4], cx
    mov  [rel demo_name_buf + 6], r13b
    mov  byte [rel demo_name_buf + 7], 0
    xor  ebx, ebx
.find:
    cmp  ebx, WGT_MAX
    jae  .chain
    mov  edi, ebx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .find_next
    cmp  [rax + WGI_WIN], r14d
    jne  .find_next
    mov  rsi, [rax + WGI_ID]
    test rsi, rsi
    jz   .find_next
    lea  rdi, [rel demo_name_buf]
    xor  ecx, ecx
.cmp:
    mov  dl, [rdi + rcx]
    cmp  dl, [rsi + rcx]
    jne  .find_next
    test dl, dl
    jz   .found
    inc  ecx
    cmp  ecx, 8
    jb   .cmp
    jmp  .find_next
.find_next:
    inc  ebx
    jmp  .find
.found:
    ; "Action_<X> pressed <n>"
    movzx eax, byte [rel demo_press_count]
    inc  eax
    cmp  eax, 9
    jbe  .count_ok
    mov  eax, 1
.count_ok:
    mov  [rel demo_press_count], al
    lea  rsi, [rel str_demo_status_tpl]
    lea  rdi, [rel demo_status_buf]
    xor  ecx, ecx
.tpl:
    mov  dl, [rsi + rcx]
    mov  [rdi + rcx], dl
    inc  ecx
    test dl, dl
    jnz  .tpl
    mov  edx, r13d
    sub  edx, 'a' - 'A'
    mov  [rdi + 7], dl                  ; Action_<X>
    add  al, '0'
    mov  [rdi + 17], al                 ; ... pressed <n>
    mov  edi, ebx
    lea  rsi, [rel demo_status_buf]
    call wgt_set_text
.chain:
    mov  edi, r12d
    mov  rax, [rel demo_click_prev]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    test rax, rax
    jz   .out
    jmp  rax
.out:
    ret

str_demo_action_pfx: db "action_", 0
str_demo_label_pfx:  db "label_", 0
str_demo_status_tpl: db "Action_? pressed ?", 0   ; [7] = letter, [17] = count
str_demo_retired: db "[PAOS64] M6 gui: boot-proof windows (Demo_A/B/C + PaOS-ANSI-B) retired before the desktop hand-off (B18)",13,10,0
align 8
demo_click_prev:      dq 0
demo_slots:           dd -1, -1, -1
demo_status_buf:      times 24 db 0
demo_name_buf:        times 8 db 0
demo_press_count:     db 0
demo_click_installed: db 0

str_chrome_marker: db "[PAOS64] M6 wm: ONE chrome painter for all slots (title glyphs + min/max/close boxes, token-driven) [wm.chrome.standard]",13,10,0
str_taskbar_marker: db "[PAOS64] M6 wm: taskbar renders one button per live window from the registry (active/normal/minimized/attention) [wm.taskbar.buttons]",13,10,0
str_demo_marker: db "[PAOS64] M6 gui: 3-window demo composed from the kit (3 pool windows, widgets, zero demo draw calls) [gui.demo.three_windows]",13,10,0
str_demo_fail: db "[PAOS64] M6 gui: 3-window demo composition FAILED",13,10,0
