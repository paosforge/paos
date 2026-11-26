;; MODULE gui/lock_ssh_notice
;; LAYER 6
;; EXPORTS lock_ssh_notice_discard, lock_ssh_notice_draw, lock_ssh_notice_commit, lock_ssh_notice_tick
;; IMPORTS gui/compose_idle, gui/compose_job, gui/lock_screen, gui/lock_fade, gui/window, gui/widget, boot/gop, sec/session, svc/ssh, core/time, core/lib/mem, core/lib/fmt
;; CAPS
;; OWNER saga:login_surfaces
; Public identity only. One bounded rotating notice over the composed lock frame;
; never input, focus, authentication, local-unlock or authorization state.
%macro SSH_NOTICE_SAVE 0
    push rax
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro
%macro SSH_NOTICE_RESTORE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro
lock_ssh_notice_ready:
    xor  eax, eax
    cmp  byte [rel session_locked], SESSION_LOCKED
    jne  .out
    cmp  byte [rel lock_composition_ok], 1
    jne  .out
    cmp  byte [rel dpms_blanked], 0
    jne  .out
    cmp  byte [rel fb_present_boot_hold], 0
    jne  .out
    cmp  word [rel lock_fade_alpha], 256
    jne  .out
    cmp  qword [rel fb_base], 0
    je   .out
    cmp  dword [rel fb_width], 640
    jb   .out
    cmp  dword [rel fb_height], 480
    jb   .out
    mov  eax, 1
.out:
    ret

lock_ssh_notice_draw:
    SSH_NOTICE_SAVE
    ; An idle frame re-enters this painter once per clipped tile. Select the
    ; public identity and both text lines once, before the first operation.
    ; Never mix connection rotation or retirement across one scene. The live
    ; serial is checked again by ssh_presence_present after completed scanout.
    cmp byte [rel fb_compose_clip_active],0
    je .sample
    mov rax,[rel fb_compose_serial]
    cmp rax,[rel lock_ssh_sample_serial]
    jne .new_sample
.resume:
    cmp byte [rel lock_ssh_sample_valid],1
    jne .out
    jmp .raster
.new_sample:
    mov [rel lock_ssh_sample_serial],rax
.sample:
    mov byte [rel lock_ssh_sample_valid],0
    mov  qword [rel lock_ssh_pending_serial], 0
    call lock_ssh_notice_ready
    test eax, eax
    jz   .out
    xor  ebx, ebx
    xor  r12d, r12d
.count:
    mov  edi, ebx
    call ssh_presence_connection
    test rax, rax
    jz   .next_count
    inc  r12d
.next_count:
    inc  ebx
    cmp  ebx, SSH_CTX_N
    jb   .count
    ; Clock-selected rotation covers every actual live context, not just one
    ; enrolled slot. No context/TCB ownership is transferred to this painter.
    call time_monotonic_now_us
    xor  edx, edx
    mov  ecx, 2000000
    div  rcx
    xor  edx, edx
    test r12d, r12d
    jz   .empty
    div  r12
    mov  r13d, edx
    xor  ebx, ebx
.find:
    mov  edi, ebx
    call ssh_presence_connection
    test rax, rax
    jz   .next_find
    test r13d, r13d
    jz   .selected
    dec  r13d
.next_find:
    inc  ebx
    cmp  ebx, SSH_CTX_N
    jb   .find
    jmp  .empty
.selected:
    mov  r14, rax
    mov  [rel lock_ssh_pending_index], ebx
    mov  rax, [r14 + SSH_C_REC_SERIAL]
    mov  [rel lock_ssh_pending_serial], rax
    mov  rdi, r14
    lea  rsi, [rel lock_ssh_text]
    call ssh_presence_line
    jmp  .paint
.empty:
    lea  rdi, [rel lock_ssh_text]
    xor  esi, esi
    mov  edx, 72
    call memset
    lea  rdi, [rel lock_ssh_text]
    lea  rsi, [rel str_lock_ssh_empty]
    mov  edx, str_lock_ssh_empty.len
    call memcpy
.paint:
    lea  rdi, [rel lock_ssh_count_text]
    lea  rsi, [rel str_lock_ssh_count]
    mov  edx, str_lock_ssh_count.len
    call memcpy
    mov  edi, r12d
    lea  rsi, [rel lock_ssh_count_text + str_lock_ssh_count.len]
    call fmt_dec
    lea  rdi, [rel lock_ssh_count_text + str_lock_ssh_count.len]
    add  rdi, rax
    lea  rsi, [rel str_lock_ssh_rotate]
    mov  edx, str_lock_ssh_rotate.len
    call memcpy
    mov  rax, [rel fb_present_count]
    mov  [rel lock_ssh_pending_frame], rax
    mov byte [rel lock_ssh_sample_valid],1
.raster:
    ; Use the existing kit seams; the closed painter set owns the raster calls.
    mov  ebx, GUI_TOK_TASKBAR_BG
    mov  r8d, 8
    mov  r9d, 8
    mov  r10d, 608
    mov  r11d, 40
    call wgt_fill_rect
    mov  ebx, GUI_TOK_TASKBAR_TEXT
    mov  ecx, GUI_TOK_TASKBAR_BG
    mov  r8d, 16
    mov  r9d, 12
    mov  r11d, 72
    lea  rdi, [rel lock_ssh_text]
    call wgt_draw_text
    lea  rdi, [rel lock_ssh_count_text]
    mov  ebx, GUI_TOK_TASKBAR_TEXT
    mov  ecx, GUI_TOK_TASKBAR_BG
    mov  r8d, 16
    mov  r9d, 30
    mov  r11d, 72
    call wgt_draw_text
.out:
    SSH_NOTICE_RESTORE
    ret

; Called after a whole-frame or periodic notice present returns. A suppressed copy
; cannot mint display telemetry. Raw native presentation is not a metal photo.
lock_ssh_notice_commit:
    ; A queued or partially copied notice has no completed-display credit.
    cmp byte [rel fb_present_pending], 0
    jne .deferred
    SSH_NOTICE_SAVE
    cmp  qword [rel lock_ssh_pending_serial], 0
    je   .out
    call lock_ssh_notice_ready
    test eax, eax
    jz   .out
    mov  rax, [rel fb_present_count]
    cmp  rax, [rel lock_ssh_pending_frame]
    jbe  .out
    mov  r12, rax
    call time_monotonic_now_us
    mov  rcx, rax
    mov  rdx, r12
    mov  rsi, [rel lock_ssh_pending_serial]
    mov  edi, [rel lock_ssh_pending_index]
    call ssh_presence_present
.out:
    mov  qword [rel lock_ssh_pending_serial], 0
    SSH_NOTICE_RESTORE
.deferred:
    ret

lock_ssh_notice_discard:
    mov qword [rel lock_ssh_pending_serial], 0
    mov byte [rel lock_ssh_sample_valid],0
    ret

; Refresh only the notice's rectangle at the periodic edge. A whole-frame copy
; here used to precede the card clock's own full repaint in the same callback.
; Batch its glyph damage so there is one completed notice publication, with the
; same post-copy receipt as the whole-frame seam.
lock_ssh_notice_tick:
    SSH_NOTICE_SAVE
    call lock_ssh_notice_ready
    test eax, eax
    jz   .out
    call time_monotonic_now_us
    mov  rdx, rax
    sub  rax, [rel lock_ssh_last_tick]
    cmp  rax, 1000000
    jb   .out
    mov  [rel lock_ssh_last_tick], rdx
    call fb_compose_defer_periodic
    jc .out
    CADENCE_BATCH_BEGIN
    call lock_ssh_notice_draw
    CADENCE_BATCH_END
    call lock_ssh_notice_commit
.out:
    SSH_NOTICE_RESTORE
    ret

align 8
lock_ssh_sample_serial: dq -1
lock_ssh_pending_serial: dq 0
lock_ssh_pending_frame: dq 0
lock_ssh_last_tick: dq 0
lock_ssh_pending_index: dd 0
lock_ssh_sample_valid: db 0
lock_ssh_text: times 72 db 0
lock_ssh_count_text: times 72 db 0
str_lock_ssh_empty: db "No remote SSH sessions",0
.len equ $ - str_lock_ssh_empty
str_lock_ssh_count: db "Remote SSH sessions: "
.len equ $ - str_lock_ssh_count
str_lock_ssh_rotate: db " (rotating)",0
.len equ $ - str_lock_ssh_rotate
