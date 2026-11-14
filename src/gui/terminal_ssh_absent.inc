; ============================================================================
; gui/terminal_ssh_absent.inc — the Terminal's view of the outbound SSH client
; while the hub has none (hub packet 0009).
;
; The MSI spoke's Terminal binds a window to svc/ssh.asm's CLIENT half (Task3494:
; ssh_session_begin / ssh_client_connect_start / ssh_cli_enqueue_input ...). The
; hub carries the SSH server only. Until the client is ported (PAOS_TERMINAL_SSH),
; this file declares that surface as UNAVAILABLE so the Terminal assembles
; unchanged: no session can begin, so `ssh` answers term_ssh_absent_text and no
; window ever leaves the local shell (TI_SSH stays 0). Nothing here touches the
; network. Remove this include when the client lands.
; ============================================================================
SSH_CLI_ST_IDLE   equ 0
SSH_CLI_ST_TCP    equ 1
SSH_CLI_ST_FAILED equ 9
SSH_TXQ_CAP       equ 1024       ; the client's input ring (the Terminal bounds a paste by it)

; ssh_session_begin() -> EAX = -1: no session (no client in this build)
ssh_session_begin:
    mov  eax, -1
    ret
; ssh_client_connect_start(RDI = target, ESI = owner) -> EAX < 0: refused
ssh_client_connect_start:
    mov  eax, -1
    ret
; the per-session calls are unreachable without a session; harmless if reached
ssh_session_use:
ssh_session_end:
ssh_cli_send_window_change:
ssh_cli_enqueue_input:
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_gui_terminal_ssh_absent_0 0
ssh_cli_state:        db SSH_CLI_ST_IDLE
ssh_cli_error:        db 0
ssh_cli_chan_ready:   db 0
ssh_cli_chan_closed:  db 0
align 4, db 0
ssh_cli_target_ip:    dd 0
ssh_cli_term_cols:    dd 80
ssh_cli_term_rows:    dd 24
ssh_cli_txq_len:      dd 0
ssh_sess_active:      dd -1
align 8, db 0
ssh_cli_data_sink:    dq 0
%endmacro
WDATA_DEFER WDATA_gui_terminal_ssh_absent_0
