;; MODULE gui/image_viewer
;; LAYER 6
;; EXPORTS image_viewer_open, image_viewer_close_hook
;; IMPORTS gui/widget, gui/widget_image, gui/window, gui/window_mgmt, gui/img/img_source, gui/img/img_cache, gui/img/img_core, svc/command
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; Creator: Codex / rc-resource-claude. Native view-only disk image window.
; Same bounded owner/session/file identity and BMP/PNG/JPEG/still-GIF grammar
; as img_source_acquire. No filename-extension trust, FSSEL, writes or new codec.
; EDI=explicit mount, RSI=absolute counted path, EDX=length -> EAX=0/1.
; Normal serialized BSP Explorer/backend context, never paint/AP/IRQ/reentry.
; Source + decoded cache must be current BEFORE any image pixels are published.
image_viewer_open:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    xor  ebp, ebp
    mov  r12d, -1                      ; no window until decode succeeds
    cmp  dword [rel wgt_alloc_next], -1 ; do not borrow an active form reservation
    jne  .fail
    cmp  dword [rel image_type_id], -1
    je   .fail
    call img_source_acquire
    test rax, rax
    jz   .fail
    mov  rbp, rax
    ; Fit the complete window above the taskbar; very small displays refuse.
    mov  eax, [rel fb_width]
    mov  ecx, 640
    cmp  eax, ecx
    cmova eax, ecx
    cmp  eax, WMX_USER_MIN_W
    jb   .fail
    mov  [rsp], eax                    ; window width
    sub  eax, 32
    mov  r14d, eax                     ; viewport width
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H
    jbe  .fail
    mov  ecx, 480
    cmp  eax, ecx
    cmova eax, ecx
    cmp  eax, WMX_USER_MIN_H
    jb   .fail
    mov  [rsp + 4], eax                ; window height
    sub  eax, WGT_PAD_Y + 16
    mov  r15d, eax                     ; viewport height
    mov  rdi, [rbp + IMG_ASSET_PTR]
    mov  rsi, [rbp + IMG_ASSET_LEN]
    call img_probe
    test eax, eax
    jnz  .fail
    mov  [rsp + 16], ecx               ; natural dimensions
    mov  [rsp + 20], edx
    mov  esi, r14d
    mov  r8d, r15d
    call widget_image_contain_size     ; no upscaling, preserves aspect ratio
    mov  r14d, esi                     ; exact cache key
    mov  r15d, edx
    mov  rdi, rbp
    call img_cache_bind
    test eax, eax
    jnz  .fail
    mov  rdi, rbp
    call img_source_current
    test eax, eax
    jnz  .fail
    mov  edi, 1
    call wgt_reserve_run
    cmp  eax, -1
    je   .fail
    mov  [rsp + 12], eax
    mov  eax, [rel wm_focus]
    mov  [rsp + 8], eax
    lea  rdi, [rbp + ISS_PATH]          ; owned stable filename is the caption
    xor  esi, esi
    xor  edx, edx
    mov  ecx, [rsp]
    mov  r8d, [rsp + 4]
    mov  r9d, WM_RESTORE_NEVER          ; runtime snapshot, no persistence claim
    call wmx_open_window
    cmp  eax, -1
    je   .fail
    mov  r12d, eax
    lea  rdx, [rel wm_state]
    mov  dword [rdx + r12*4], WM_MIN    ; no paint while widget is materialized
    mov  eax, [rsp + 12]
    mov  [rel wgt_alloc_next], eax
    inc  byte [rel wgt_paint_suspended]
    mov  edi, [rel image_type_id]
    mov  esi, r12d
    call wgt_create
    dec  byte [rel wgt_paint_suspended]
    mov  dword [rel wgt_alloc_next], -1
    cmp  eax, -1
    je   .rollback
    mov  r13d, eax
    mov  rdi, rbp
    call img_source_current            ; last check before transferring ownership
    test eax, eax
    jnz  .rollback
    mov  edi, r13d
    call wgt_slot_ptr
    mov  rbx, rax
    lea  rdx, [rel wm_x]
    mov  eax, [rdx + r12*4]
    add  eax, 16
    mov  [rbx + WGI_X], eax
    lea  rdx, [rel wm_y]
    mov  eax, [rdx + r12*4]
    add  eax, WGT_PAD_Y
    mov  [rbx + WGI_Y], eax
    mov  eax, [rsp]
    sub  eax, 32
    mov  [rbx + WGI_W], eax
    mov  eax, [rsp + 4]
    sub  eax, WGT_PAD_Y + 16
    mov  [rbx + WGI_H], eax
    mov  edi, r13d
    call widget_image_state_ptr
    mov  [rax + WIS_SRC], rbp
    mov  dword [rax + WIS_FIT], WIMG_FIT_CONTAIN
    mov  dword [rax + WIS_LOAD], WIMG_LOAD_OK
    mov  byte [rax + WIS_REBIND], 0
    mov  ecx, [rsp + 16]
    mov  [rax + WIS_NW], ecx
    mov  ecx, [rsp + 20]
    mov  [rax + WIS_NH], ecx
    mov  [rax + WIS_OUTW], r14d
    mov  [rax + WIS_OUTH], r15d
    xor  ebp, ebp                      ; now retained by the live widget
    mov  edi, r12d
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .agent
    call wmx_raise_slot                ; local Explorer click follows WM focus rules
    jmp  .ok
.agent:
    lea  rax, [rel wm_state]
    mov  dword [rax + r12*4], WM_VISIBLE
    mov  eax, [rsp + 8]
    mov  [rel wm_focus], eax            ; remote/backend open never steals focus
    lea  rax, [rel wm_attn]
    mov  byte [rax + r12], 1
    call wmx_draw_all
.ok:
    xor  eax, eax
    jmp  .out
.rollback:
    mov  edi, r12d
    call wmx_close_slot
    mov  eax, [rsp + 8]
    mov  [rel wm_focus], eax
    mov  edi, eax
    call wgt_focus_window
.fail:
    test rbp, rbp
    jz   .failed
    mov  rdi, rbp
    call img_source_retire
.failed:
    mov  eax, 1
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI=closing window. Called by the ordinary WM closer before widget IDs retire.
; Clear image references BEFORE retiring owned slots/cache keys. Embedded rows
; are accepted by retire as a no-op. Non-image widgets and other windows survive.
image_viewer_close_hook:
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
    cmp  [rax + WGI_WIN], r13d
    jne  .next
    mov  ecx, [rel image_type_id]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .next
    mov  edi, r12d
    call widget_image_state_ptr
    mov  rbx, [rax + WIS_SRC]
    mov  qword [rax + WIS_SRC], 0
    mov  dword [rax + WIS_LOAD], WIMG_LOAD_MISSING
    mov  byte [rax + WIS_REBIND], 0
    test rbx, rbx
    jz   .next
    mov  rdi, rbx
    call img_source_retire
.next:
    inc  r12d
    jmp  .loop
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
