;; MODULE gui/present_idle
;; LAYER 6
;; EXPORTS fb_present_idle_progress, fb_present_completed_surface_epoch, fb_present_completed_serial, fb_blank_request, fb_blank_idle_poll, fb_present_live_start, fb_present_idle_poll, fb_present_queue_frame
;; IMPORTS gui/compose_job, sec/session, gui/window, gui/lock_ssh_notice, gui/clock_paint, boot/gop, core/reset_wipe, gui/lock_fade
;; CAPS
;; OWNER saga:gui
; Whole-frame scanout copies are idle work, never part of a command's presentation
; callback. The original presenter remains the sole gated pixel writer. Each
; idle turn presents at most eight rows and 800 logical pixels, then returns to the command
; loop. Boot/KAT publication stays synchronous until the live handoff.
;
; A separate dirty union accumulates while a job drains: a periodic full paint
; must not restart the active job at row zero and starve the bottom of a screen.
; No private/stale pixels or framebuffer pointers are retained. Each slice reads
; the current composed shadow through the original sign-in and DPMS gates.
; CF=1 hands the blank to idle work; boot retains its original synchronous
; black fill. No arbitrary destination or count is supplied by a caller.
fb_blank_request:
    cmp byte [rel fb_compose_live],0
    je .boot
    mov byte [rel fb_blank_pending],1
    mov qword [rel fb_blank_cursor],0
    mov qword [rel fb_blank_base],0
    stc
    ret
.boot:
    clc
    ret

; Direct black scanout is not a completed GUI frame or a visibility receipt.
; Validate the current physical extent before every <=800-pixel turn. A new
; mode, base, authority or surface restarts the cursor; waking cancels it.
fb_blank_idle_poll:
    pushfq
    push rax
    push rcx
    push rdx
    push rdi
    cmp byte [rel reset_wipe_done],0
    jne .cancel
    cmp byte [rel dpms_blanked],1
    jne .cancel
    cmp byte [rel fb_blank_pending],1
    jne .out
    mov rdi,[rel fb_scanout_base]
    test rdi,rdi
    jz .out
    mov ecx,[rel fb_stride]
    mov edx,[rel fb_height]
    cmp byte [rel fb_scale],1
    je .extent
    cmp byte [rel fb_scale],2
    jne .out
    mov ecx,[rel fb_out_stride]
    mov edx,[rel fb_out_height]
.extent:
    test ecx,ecx
    jle .out
    test edx,edx
    jle .out
    imul rcx,rdx
    mov rax,rcx
    shr rax,62
    jnz .out
    mov rax,rcx
    shl rax,2
    cmp rax,[rel fb_size]
    ja .out
    cmp rdi,[rel fb_blank_base]
    jne .restart
    cmp rcx,[rel fb_blank_pixels]
    jne .restart
    mov rax,[rel fb_surface_epoch]
    cmp rax,[rel fb_blank_epoch]
    jne .restart
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel fb_blank_authority]
    je .slice
.restart:
    mov [rel fb_blank_base],rdi
    mov [rel fb_blank_pixels],rcx
    mov rax,[rel fb_surface_epoch]
    mov [rel fb_blank_epoch],rax
    mov rax,[rel session_authority_epoch]
    mov [rel fb_blank_authority],rax
    mov qword [rel fb_blank_cursor],0
.slice:
    mov rax,[rel fb_blank_cursor]
    cmp rax,rcx
    jae .cancel
    lea rdi,[rdi+rax*4]
    sub rcx,rax
    cmp rcx,800
    jbe .copy
    mov ecx,800
.copy:
    add [rel fb_blank_cursor],rcx
    call dpms_fill_black
    mov rax,[rel fb_blank_cursor]
    cmp rax,[rel fb_blank_pixels]
    jb .out
.cancel:
    mov byte [rel fb_blank_pending],0
.out:
    pop rdi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

fb_present_live_start:
    ; Preserve the first input-live frame, BG6 and exact boot-fade reporting.
    ; Input-live release may activate this while the boot fade is in progress.
    ; Fade copies use the same bounded consumer; boot-only KATs stay held.
    cmp  byte [rel fb_present_boot_hold], 0
    jne  .out
    push rax
    lea  rax, [rel fb_present_idle_queue]
    mov  [rel fb_present_defer_op], rax
    pop  rax
.out:
    ret

; The idle compositor completed a new whole shadow. Abandon a partially copied
; older shadow and queue every pixel of the newly composed frame. The ordinary
; presenter still owns lock, consent, DPMS and actual visibility checks.
fb_present_queue_frame:
    mov byte [rel fb_idle_active],0
    mov byte [rel fb_idle_dirty],0
    xor r8d,r8d
    xor r9d,r9d
    mov r10d,[rel fb_width]
    mov r11d,[rel fb_height]
    jmp fb_present_idle_queue

; Already clipped r8=x, r9=y, r10=width, r11=height. Queued raster damage or a whole frame exceeding the idle pixel/row budget.
fb_present_idle_queue:
    add  r10d, r8d
    add  r11d, r9d
    cmp  byte [rel fb_idle_dirty], 0
    jne  .merge
    mov  [rel fb_idle_x0], r8d
    mov  [rel fb_idle_y0], r9d
    mov  [rel fb_idle_x1], r10d
    mov  [rel fb_idle_y1], r11d
    mov  byte [rel fb_idle_dirty], 1
    jmp  .pending
.merge:
    cmp  r8d, [rel fb_idle_x0]
    jge  .y0
    mov  [rel fb_idle_x0], r8d
.y0:
    cmp  r9d, [rel fb_idle_y0]
    jge  .x1
    mov  [rel fb_idle_y0], r9d
.x1:
    cmp  r10d, [rel fb_idle_x1]
    jle  .y1
    mov  [rel fb_idle_x1], r10d
.y1:
    cmp  r11d, [rel fb_idle_y1]
    jle  .pending
    mov  [rel fb_idle_y1], r11d
.pending:
    mov  byte [rel fb_present_pending], 1
    ret

; Called after UDP service and before the guest turn, with no painter, batch,
; transport or authentication frame on the stack. Preserves every register.
fb_present_idle_poll:
    mov byte [rel fb_idle_progress],0
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    cmp  byte [rel reset_wipe_done], 0
    jne  .out
    cmp  byte [rel fb_compose_pending], 0
    jne  .out                            ; never publish a half-composed shadow
    cmp  byte [rel fb_idle_active], 0
    jne  .slice
    cmp  byte [rel fb_idle_dirty], 0
    je   .out
    mov  eax, [rel fb_idle_x0]
    mov  [rel fb_idle_job_x0], eax
    mov  [rel fb_idle_job_x], eax
    mov  eax, [rel fb_idle_y0]
    mov  [rel fb_idle_job_y], eax
    mov  [rel fb_idle_job_y0], eax
    mov  eax, [rel fb_idle_x1]
    mov  [rel fb_idle_job_x1], eax
    mov  eax, [rel fb_idle_y1]
    mov  [rel fb_idle_job_y1], eax
    mov  rax, [rel fb_present_count]
    mov  [rel fb_idle_job_present_before], rax
    mov  rax, [rel fb_surface_epoch]
    mov  [rel fb_idle_job_epoch], rax
    mov rax,[rel fb_compose_serial]
    mov [rel fb_idle_job_compose_serial],rax
    mov  byte [rel fb_idle_dirty], 0
    mov  byte [rel fb_idle_active], 1
.slice:
    mov  r8d, [rel fb_idle_job_x]
    mov  r9d, [rel fb_idle_job_y]
    mov  r10d, [rel fb_idle_job_x1]
    sub  r10d, r8d
    mov  r11d, [rel fb_idle_job_y1]
    sub  r11d, r9d
    ; A resized/detached surface cannot turn old geometry into display credit.
    cmp  r8d, [rel fb_width]
    jae  .abandon
    cmp  r9d, [rel fb_height]
    jae  .abandon
    mov  eax, [rel fb_idle_job_x1]
    cmp  eax, [rel fb_width]
    ja   .abandon
    mov  eax, [rel fb_idle_job_y1]
    cmp  eax, [rel fb_height]
    ja   .abandon
    ; Bound pixels as well as rows: eight rows of a very wide mode must
    ; not become an unbounded turn. Every horizontal tile in a band uses
    ; the height computed from the ORIGINAL job width, including its tail.
    mov eax, [rel fb_idle_job_x1]
    sub eax, [rel fb_idle_job_x0]
    mov ecx, eax
    mov eax, 800
    xor edx, edx
    div ecx
    test eax, eax
    jnz .rows_nonzero
    inc eax
.rows_nonzero:
    cmp eax, 8
    jbe .rows_ready
    mov eax, 8
.rows_ready:
    cmp r11d, eax
    cmova r11d, eax
    mov eax, 800
    cmp r10d, eax
    cmova r10d, eax
    mov  rax, [rel fb_present_count]
    push rax
    call fb_present_rect                 ; <=8 rows and 800 pixels: no recursive queue
    pop  rax
    cmp  rax, [rel fb_present_count]
    je   .out                            ; withheld/blanked: no progress or receipt
    mov byte [rel fb_idle_progress],1
    add [rel fb_idle_job_x], r10d
    mov eax, [rel fb_idle_job_x1]
    cmp [rel fb_idle_job_x], eax
    jb .out
    mov eax, [rel fb_idle_job_x0]
    mov [rel fb_idle_job_x], eax
    add  [rel fb_idle_job_y], r11d
    mov  eax, [rel fb_idle_job_y1]
    cmp  [rel fb_idle_job_y], eax
    jb   .out
    mov  byte [rel fb_idle_active], 0
    cmp  byte [rel fb_idle_dirty], 0
    jne  .out                            ; newer shadow damage still owes a copy
    mov  byte [rel fb_present_pending], 0
    ; Small slices do not cover a whole 8x16 clock cell. The completed job may
    ; report its original rectangle only if its composed generation stayed
    ; unchanged throughout the copy. A redrawn marker must wait for its new job.
    mov  rax, [rel fb_idle_job_epoch]
    cmp  rax, [rel fb_surface_epoch]
    jne  .notice
    mov r8d, [rel fb_idle_job_x0]
    mov r10d, [rel fb_idle_job_x1]
    sub r10d, r8d
    mov  r9d, [rel fb_idle_job_y0]
    mov  r11d, [rel fb_idle_job_y1]
    sub  r11d, r9d
    call clock_paint_present
    ; Boot publication is credited only after a complete, unchanged final
    ; frame, never on a slice or while the fade still owes exact pixels.
    cmp byte [rel lock_fade_active], 0
    jne .notice
    mov rax, [rel fb_idle_job_present_before]
    call lock_bg6_stamp
    call lock_screen_boot_release
.notice:
    call lock_ssh_notice_commit           ; only after all owed pixels reached scanout
    ; A security page may consume this receipt only for a complete current
    ; composition, copied in full without an intervening surface change.
    mov rax,[rel fb_idle_job_epoch]
    cmp rax,[rel fb_surface_epoch]
    jne .out
    mov rax,[rel fb_idle_job_compose_serial]
    test rax,rax
    jz .out
    cmp rax,[rel fb_compose_serial]
    jne .out
    call fb_compose_context_current
    jc .out
    cmp dword [rel fb_idle_job_x0],0
    jne .out
    cmp dword [rel fb_idle_job_y0],0
    jne .out
    mov eax,[rel fb_width]
    cmp eax,[rel fb_idle_job_x1]
    jne .out
    mov eax,[rel fb_height]
    cmp eax,[rel fb_idle_job_y1]
    jne .out
    mov rax,[rel fb_idle_job_compose_serial]
    mov [rel fb_present_completed_serial],rax
    mov rax,[rel fb_idle_job_epoch]
    mov [rel fb_present_completed_surface_epoch],rax
    jmp  .out
.abandon:
    mov  byte [rel fb_idle_active], 0
    mov  byte [rel fb_idle_dirty], 0
    mov  byte [rel fb_present_pending], 0
    call lock_ssh_notice_discard          ; an incomplete frame earns no receipt
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop rcx
    pop  rax
    ret

; EAX=1 only if the immediately preceding bounded scanout turn copied pixels.
; The BSP uses this after the full service sweep to avoid a voluntary timer
; sleep between runnable tiles. Pending alone is insufficient: lock, DPMS,
; reset and invalid surfaces may withhold a job indefinitely. This grants no
; visibility or completion receipt and never changes the per-turn copy budget.
fb_present_idle_progress:
    movzx eax,byte [rel fb_idle_progress]
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_present_idle 0
align 4
fb_idle_x0: dd 0
fb_idle_y0: dd 0
fb_idle_x1: dd 0
fb_idle_y1: dd 0
fb_idle_job_x0: dd 0
fb_idle_job_x: dd 0
fb_idle_job_y: dd 0
fb_idle_job_y0: dd 0
fb_idle_job_x1: dd 0
fb_idle_job_y1: dd 0
align 8
fb_present_completed_surface_epoch: dq 0
fb_present_completed_serial: dq 0
fb_idle_job_compose_serial: dq 0
fb_idle_job_epoch: dq 0
fb_idle_job_present_before: dq 0
fb_idle_progress: db 0
fb_idle_dirty: db 0
fb_idle_active: db 0
fb_blank_pending: db 0
align 8
fb_blank_cursor: dq 0
fb_blank_base: dq 0
fb_blank_pixels: dq 0
fb_blank_epoch: dq 0
fb_blank_authority: dq 0

%endmacro
WDATA_DEFER WDATA_gui_present_idle
