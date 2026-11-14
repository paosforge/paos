;; MODULE gui/command_idle_service
;; LAYER 6
;; EXPORTS command_idle_service_tick
;; IMPORTS svc/command, gui/cadence_mark, gui/lock_screen, sec/session, config/keep_config
;; CAPS
;; OWNER saga:command_idle_service
; T5-11: settled idle work owns no Console/Terminal window or input authority.
; Called once at the common continuation after either presentation's input.
; The command model advances already admitted jobs and records completion; this
; service neither submits commands nor borrows a session/principal capability.
command_idle_service_tick:
    cmp dword [rel cmd_dispatch_depth], 0
    jne .out
    call command_jobs_tick
    ; Retain the old GUI-only calibration eligibility and its eight settled
    ; runtime opportunities. The instrument still owns its 2ms ceiling and all
    ; measurement state. Locked/CLI/pre-desktop frames consume no retry budget.
    cmp byte [rel keep_presentation_target], PRESENTATION_GUI
    jne .out
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .out
    cmp byte [rel lock_desktop_created], 1
    jne .out
    cmp byte [rel flk_crc_calibrated], 1
    je .out
    cmp byte [rel command_idle_crc_retry_left], 0
    je .out
    dec byte [rel command_idle_crc_retry_left]
    call flk_crc_calibrate
.out:
    ret

%macro WDATA_gui_command_idle_service 0
command_idle_crc_retry_left: db 8
%endmacro
WDATA_DEFER WDATA_gui_command_idle_service
