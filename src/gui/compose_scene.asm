;; MODULE gui/compose_scene
;; LAYER 6
;; EXPORTS fb_compose_scene, fb_compose_frame_ready
;; IMPORTS gui/console, gui/widget_console_grid, gui/compose_job, gui/lock_screen, gui/window, gui/window_mgmt, gui/widget_image, gui/present_idle, sec/session
;; CAPS
;; OWNER saga:gui
; One canonical scene, re-entered only by the idle owner with its bounded tile
; active. Logical geometry, authority and window state remain owned by their
; ordinary command/input paths; no stale painter stack or arguments are saved.
fb_compose_scene:
    cmp byte [rel headless_cli_active],1
    je console_grid_headless_draw
    cmp byte [rel session_locked],SESSION_LOCKED
    jne .workspace
    jmp lock_screen_paint
.workspace:
    xor r8d,r8d
    xor r9d,r9d
    mov r10d,[rel fb_width]
    mov r11d,[rel fb_height]
    call wallpaper_paint_rect
    call wmx_draw_all
    ret

; A completed shadow only queues a new complete copy. It is not a present,
; sign-in frame, clock record or SSH-notice receipt.
fb_compose_frame_ready:
    jmp fb_present_queue_frame
