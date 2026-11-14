;; MODULE gui/guest_media_owner_private
;; LAYER 6
;; EXPORTS media_guest_storage_acquire, media_guest_transport_begin, media_guest_transport_out_turn, media_guest_transport_stop_after_pmh, media_guest_start, media_guest_stop, media_guest_poll, media_guest_register_verb
;; IMPORTS core/heap, core/time, media/pmr1_host_private, hv/vmx, hv/vm_profile, fs/vfs, sec/session, gui/window_mgmt, gui/video_player_private, gui/guest_media_producer_private, svc/command, boot/serial
;; CAPS
;; OWNER rc-vm
; RCQ-37 G3b owner: the sole cooperative native owner of one media guest. Built
; only with RCQ37_VIDEO_BUILT=1 and RCQ37_GUEST_MEDIA_BUILT=1; the GUESTMEDIA
; qualification verb also needs the lab profile. Nothing is allocated at boot.
; START (local verb) admits, binds PMH and hvc0, then launches the guest; the
; idle turn runs PMH, READ, W1 and teardown in bounded steps. No private W1
; offset is read: W1 is reached through its scalar API and the producer seam.
%include "hv/guest_media_contract.inc"
%if RCQ37_MEDIA_PROFILE

; One retained allocation per boot, including an attempted/refused allocation.
; The owner validates local authority, file/profile and VMX before calling.
; It never calls acquire concurrently, and never treats a returned context as
; a live/OPEN PMH session: pmr1h_init/config and W1 admission remain separate.
MG_FLOOR       equ 0x400000
MG_FRAMES      equ (pmh_size + 15) & ~15
MG_PCM         equ MG_FRAMES + 3 * PMH_NATIVE_SLOT
MG_OUT         equ MG_PCM + PMH_PCM_SLOTS * PMH_PCM_SLOT
MG_EVENTS      equ MG_OUT + PMH_OUT_CAP
MG_READ        equ MG_EVENTS + PMH_EV_CAP * 16  ; one READ's file bytes (PMH_READ_MAX)
MG_META        equ MG_READ + PMH_READ_MAX       ; native W1/VFS call records (below)
MG_POOL_BYTES  equ (MG_META + 512 + 15) & ~15
MG_M_OPEN      equ MG_META                      ; OPEN128
MG_M_CLOCK     equ MG_META + 128                ; CLOCK192
MG_M_STATUS    equ MG_META + 320                ; STATUS32
MG_M_STAT      equ MG_META + 352                ; fs_stat

; -> RAX=retained PMH context or 0; EDX=kmalloc_floor refusal cause (0 success).
; A failed attempt never advances the heap and is never retried. Success leaves
; the atomic post-allocation 4 MiB floor. No kfree/rewind/reallocation on STOP.
; Reuse returns the same context without modifying its session/leases/counters;
; the owner must first finish close, bounded native scrub and PMH re-init.
media_guest_storage_acquire:
    cmp  byte [rel mg_quarantined], 0
    jne  .pinned
    mov  rax, [rel mg_pool]
    test rax, rax
    jnz  .ready
    cmp  byte [rel mg_pool_attempted], 0
    jne  .refused
    mov  byte [rel mg_pool_attempted], 1
    mov  edi, MG_POOL_BYTES
    mov  esi, MG_FLOOR
    sub  rsp, 8
    call kmalloc_floor
    add  rsp, 8
    test rax, rax
    jz   .failed
    mov  [rel mg_pool], rax
    ; Only the small PMH context is cleared here. Source slots are unpublished
    ; until G3a has copied and validated a complete frame/PCM packet. Future
    ; close/reuse scrubs all slots in bounded owner turns, never in this entry.
    mov  r8, rax
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, pmh_size
    cld
    rep  stosb
    lea  rax, [r8 + MG_FRAMES]
    mov  [r8 + pmh.native], rax
    add  rax, PMH_NATIVE_SLOT
    mov  [r8 + pmh.native + 8], rax
    add  rax, PMH_NATIVE_SLOT
    mov  [r8 + pmh.native + 16], rax
    lea  rax, [r8 + MG_PCM]
    mov  [r8 + pmh.pcmbuf], rax
    mov  rax, r8
.ready:
    xor  edx, edx
    ret
.failed:
    mov  [rel mg_pool_cause], esi
.refused:
    mov  edx, [rel mg_pool_cause]
    xor  eax, eax
    ret
.pinned:
    mov  edx, MG_R_PINNED
    xor  eax, eax
    ret

; Called only after PMH init + reviewed W1 admission + successful console bind.
; Reopen begins a new transport after close/scrub; no guest action here.
media_guest_transport_begin:
    cmp  qword [rel mg_pool], 0
    je   .bad
    mov  byte [rel mg_transport_stopping], 0
    mov  dword [rel mg_out_len], 0
    mov  dword [rel mg_out_pos], 0
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; One owner-turn output action, at most 256 B delivered. PMH's drain moves all
; whole records into this retained host staging buffer; an RX refusal keeps
; the identical bytes/position for the next turn. No record is taken twice.
; -> EAX=1 delivered, 0 idle/backpressure/stopping, -1 native invariant refused.
media_guest_transport_out_turn:
    push rbx
    push r12
    push r13
    mov  rbx, [rel mg_pool]
    test rbx, rbx
    jz   .idle
    cmp  byte [rel mg_transport_stopping], 0
    jne  .discard
    cmp  dword [rel mg_out_len], 0
    jne  .pending
    mov  rdi, rbx
    lea  rsi, [rbx + MG_OUT]
    call pmr1h_out_take
    cmp  eax, PMH_OUT_CAP
    ja   .bad
    mov  [rel mg_out_len], eax
    mov  dword [rel mg_out_pos], 0
.pending:
    mov  r12d, [rel mg_out_len]
    mov  r13d, [rel mg_out_pos]
    sub  r12d, r13d
    jb   .bad
    jz   .idle
    cmp  r12d, 256
    jbe  .chunk
    mov  r12d, 256
.chunk:
    lea  rdi, [rbx + MG_OUT + r13]
    mov  esi, r12d
    call hv_vcon_rx_bytes
    cmp  eax, 1
    jne  .idle                             ; preserve the pending host bytes on backpressure
    add  r13d, r12d
    mov  [rel mg_out_pos], r13d
    cmp  r13d, [rel mg_out_len]
    jne  .sent
    mov  dword [rel mg_out_len], 0
    mov  dword [rel mg_out_pos], 0
.sent:
    mov  eax, 1
    jmp  .out
.discard:
    mov  dword [rel mg_out_len], 0
    mov  dword [rel mg_out_pos], 0
    mov  rdi, rbx
    lea  rsi, [rbx + MG_OUT]
    call pmr1h_out_take                     ; CLOSED still allows drain; never sent to guest
.idle:
    xor  eax, eax
    jmp  .out
.bad:
    mov  byte [rel mg_transport_stopping], 1
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Teardown helper AFTER W1 leases drained and PMH CONTROL STOP succeeded.
; Drop staged + still-queued output before window scrub/guest STOP/unbind.
media_guest_transport_stop_after_pmh:
    mov  byte [rel mg_transport_stopping], 1
    sub  rsp, 8
    call hv_vcon_pmr_stop
    add  rsp, 8
    jmp  media_guest_transport_out_turn

; ---- lifecycle ----------------------------------------------------------------------------------------------
; The owner is cooperative and single-instance: START runs in the local verb's
; frame, everything else in media_guest_poll's top-level idle turn. Neither
; yields. RUN performs one bounded action per subsystem; CLOSE follows the PMR1
; REPLY teardown order: admission + console discard, guest STOP, W1 drain by
; the real ACK, then the window and the native pool are zeroed in bounded
; steps, and the console is unbound last. The window is zeroed AFTER the guest
; has stopped (REPLY: block re-entry first), never while a vCPU can write it.
MG_IDLE        equ 0
MG_RUN         equ 1
MG_CLOSE       equ 2
MG_QUARANTINE  equ 3                            ; native pool and producer lease retained until reboot
MG_ADMIT       equ 0                            ; CLOSE steps
MG_DRAIN       equ 1
MG_WINDOW      equ 2
MG_POOLZ       equ 3
MG_DONE        equ 4
MG_R_STOPPED   equ 1                            ; reasons (mg_reason_names order)
MG_R_GUEST_EXIT equ 2
MG_R_ARTIFACT  equ 3
MG_R_BUSY      equ 4
MG_R_RAIL      equ 5
MG_R_AUTHORITY equ 6
MG_R_SURFACE   equ 7
MG_R_MEMORY    equ 8
MG_R_RECORD    equ 9
MG_R_CLOSED    equ 10
MG_R_TIMEOUT   equ 11
MG_R_PMH       equ 12                           ; PMH's own reason, rendered by pmr1h_render
MG_R_PINNED    equ 13
MGF_HELLO      equ 1 << 0                       ; OPEN record owed to the guest
MGF_W1_WANT    equ 1 << 1                       ; OPEN_OK seen: W1 OPEN owed
MGF_W1_OPEN    equ 1 << 2                       ; W1 is ours (opened by this session)
MGF_EOF_SEEN   equ 1 << 3
MGF_EOF_SENT   equ 1 << 4
MGF_ANCHOR     equ 1 << 5                       ; media clock anchored on the first accepted frame
MGF_WINDOW     equ 1 << 6                       ; mg_slot was opened by this session
MGF_PMR        equ 1 << 7                       ; hvc0 is bound to PMH
MGF_HELLO_SEEN equ 1 << 8
MG_CHUNK       equ 0x4000                       ; bytes zeroed per CLOSE turn
MG_WIN_W       equ 640 + 2 * GUI_CHROME_BORDER
MG_WIN_H       equ 360 + GUI_TITLE_H + GUI_CHROME_BORDER
MG_WIN_Y       equ 48
MG_OPEN_US     equ 10000000                     ; PMH: OPEN_OK within 10 s of HELLO
MG_HELLO_US    equ 120000000                    ; the guest must say HELLO within 120 s of launch
MG_DRAIN_US    equ 5000000                      ; constant 5 s grace; no caller input
MG_LEAD_NS     equ 100000000                    ; first frame is shown 100 ms after its acceptance
MG_VALID_NS    equ 4000000                      ; one CLOCK192 snapshot is valid for 4 ms
MG_WIDTH_NS    equ 21000000                     ; snapshot validity + one 60 Hz present (< W1's 25 ms)
MG_DATA_OK     equ 0
MG_DATA_EOF    equ 1
MG_DATA_IO     equ 2

; media_guest_start(RDI=8.3 path text, ESI=its length) -> EAX=0 started, else
; MG_R_* (nothing launched; anything taken after the window opened is undone).
; Order: local authority + W1 idle, file, profile, storage, VMX select, window,
; PMH config/init, console bind, guest launch.
media_guest_start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  ebx, MG_R_PINNED
    cmp  byte [rel mg_quarantined], 0
    jne  .refuse
    mov  ebx, MG_R_BUSY
    cmp  byte [rel mg_state], MG_IDLE
    jne  .refuse
    mov  ebx, MG_R_AUTHORITY
    call session_shell_local_authority
    test rax, rax
    jz   .refuse
    mov  [rel mg_pid], rax
    mov  [rel mg_token], rdx
    mov  rax, [rel session_authority_epoch]
    test rax, rax
    jz   .refuse
    mov  [rel mg_auth_epoch], rax
    mov  ebx, MG_R_BUSY
    lea  rdi, [rel mg_w1_status]
    call video_player_status
    test eax, eax
    jnz  .refuse
    mov  eax, [rel mg_w1_status + 4]
    test eax, eax
    jz   .w1_idle
    cmp  eax, 2                            ; ZERO_READY
    jne  .refuse
.w1_idle:
    mov  rax, [rel mg_session_seq]
    inc  rax
    jz   .refuse                           ; session identities never wrap
    mov  ebx, MG_R_ARTIFACT
    mov  rdi, r12
    mov  esi, r13d
    call vfs_path_to_name11
    test eax, eax
    jnz  .refuse
    cmp  dword [rel vfs_disk_handle], -1
    je   .refuse
    mov  rax, [rel vfs_path_name]
    mov  [rel mg_name11], rax
    mov  eax, [rel vfs_path_name + 7]
    mov  [rel mg_name11 + 7], eax
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel mg_name11]
    lea  rdx, [rel mg_stat]
    call vfs_stat
    test rax, rax
    jnz  .refuse
    mov  rax, [rel mg_stat]
    test rax, rax
    jz   .refuse
    mov  [rel mg_file_size], rax
    mov  ebx, MG_R_RAIL
    lea  rdi, [rel str_mg_profile]
    call vm_profile_find
    test rax, rax
    jz   .refuse
    mov  r14, rax
    mov  ebx, MG_R_MEMORY
    call media_guest_storage_acquire
    test rax, rax
    jz   .refuse
    mov  r15, rax
    mov  rdi, r14
    call hv_media_guest_select
    mov  ebx, edx
    test rax, rax
    jz   .refuse
    mov  [rel mg_window_hva], rax
    mov  ebx, MG_R_SURFACE
    mov  esi, [rel fb_width]
    sub  esi, MG_WIN_W
    sar  esi, 1
    jns  .x_ok
    xor  esi, esi
.x_ok:
    lea  rdi, [rel str_mg_title]
    mov  edx, MG_WIN_Y
    mov  ecx, MG_WIN_W
    mov  r8d, MG_WIN_H
    mov  r9d, WM_RESTORE_NEVER
    call wmx_open_window
    cmp  eax, -1
    je   .refuse_selected
    mov  [rel mg_slot], eax
    mov  dword [rel mg_flags], MGF_WINDOW
    lea  rcx, [rel wm_owner]
    mov  rcx, [rcx + rax*8]
    mov  [rel mg_wowner], rcx
    mov  ebx, MG_R_AUTHORITY
    test rcx, rcx
    jz   .rollback
    ; PMH configuration: this session's identity, the final window mapping and
    ; the owner's retained native slots. pmr1h_init validates every bound.
    mov  rax, [rel mg_session_seq]
    inc  rax
    mov  [rel mg_session_seq], rax         ; consumed even when setup fails
    mov  [r15 + pmh.session], rax
    mov  eax, [rel hv_linux_start_gen]
    inc  eax                               ; the generation hv_media_guest_launch publishes
    mov  [rel mg_gen], eax
    mov  [r15 + pmh.vm_gen], rax
    mov  rax, [rel mg_file_size]
    mov  [r15 + pmh.file_size], rax
    mov  rax, [rel mg_window_hva]
    mov  [r15 + pmh.window], rax
    lea  rax, [r15 + MG_FRAMES]
    mov  [r15 + pmh.native], rax
    add  rax, PMH_NATIVE_SLOT
    mov  [r15 + pmh.native + 8], rax
    add  rax, PMH_NATIVE_SLOT
    mov  [r15 + pmh.native + 16], rax
    lea  rax, [r15 + MG_PCM]
    mov  [r15 + pmh.pcmbuf], rax
    mov  qword [r15 + pmh.deadline], MG_OPEN_US
    mov  dword [r15 + pmh.pcm_rate], 48000
    mov  dword [r15 + pmh.pcm_ch], 2
    mov  dword [r15 + pmh.max_src_w], 1280
    mov  dword [r15 + pmh.max_src_h], 720
    mov  dword [r15 + pmh.max_fps_num], 30
    mov  dword [r15 + pmh.max_fps_den], 1
    mov  dword [r15 + pmh.quantum], 4096
    mov  dword [r15 + pmh.rec_cap], 8
    mov  dword [r15 + pmh.probe_max], 256
    mov  dword [r15 + pmh.cfg_rsvd], 0
    mov  ebx, MG_R_RECORD
    mov  rdi, r15
    call pmr1h_init
    test eax, eax
    jnz  .rollback
    mov  ebx, MG_R_BUSY
    mov  rdi, r15
    call hv_vcon_pmr_bind
    test eax, eax
    jnz  .rollback
    or   dword [rel mg_flags], MGF_PMR
    call media_guest_transport_begin
    xor  eax, eax
    mov  [rel mg_fifo_n], eax
    mov  [rel mg_pcm_next], eax
    mov  [rel mg_frames], rax
    mov  [rel mg_pcm], rax
    mov  [rel mg_reads], rax
    mov  [rel mg_cursor], rax
    mov  [rel mg_clock_ms], rax
    mov  [rel mg_reason], eax
    mov  byte [rel mg_line], 0
    call hv_media_guest_launch
    test edx, edx
    jnz  .rollback
    mov  r12d, eax
    call time_monotonic_now_us
    mov  [rel mg_launch_us], rax
    mov  byte [rel mg_step], MG_ADMIT
    mov  byte [rel mg_state], MG_RUN
    xor  eax, eax
    cmp  r12d, [rel mg_gen]
    je   .out
    mov  edi, MG_R_BUSY                    ; queued under another generation: full teardown
    call mg_close
    mov  eax, MG_R_BUSY
    jmp  .out
.rollback:
    test dword [rel mg_flags], MGF_PMR
    jz   .rollback_window
    call hv_vcon_pmr_unbind
.rollback_window:
    call mg_window_ours
    test eax, eax
    jz   .rollback_done
    mov  edi, [rel mg_slot]
    call wmx_close_slot
.rollback_done:
    mov  dword [rel mg_flags], 0
.refuse_selected:
    ; RC-speed-reserve: this call's select pinned the span and nothing launched; only
    ; this path returns it (a refused second START never touches the live session's).
    mov  qword [rel mg_window_hva], 0
    call hv_media_window_release
.refuse:
    mov  edi, ebx
    call mg_note
    mov  eax, ebx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; media_guest_stop -> EAX=0 teardown admitted, else MG_R_*. Only the local
; principal that started this session may stop it through the verb.
media_guest_stop:
    cmp  byte [rel mg_state], MG_RUN
    jne  .closed
    sub  rsp, 8
    call session_shell_local_authority
    add  rsp, 8
    test rax, rax
    jz   .authority
    cmp  rax, [rel mg_pid]
    jne  .authority
    mov  edi, MG_R_STOPPED
    call mg_close
    xor  eax, eax
    ret
.authority:
    mov  eax, MG_R_AUTHORITY
    ret
.closed:
    mov  eax, MG_R_CLOSED
    ret

; Top-level idle turn, after video_player_poll. Idle costs two compares.
media_guest_poll:
    cmp  byte [rel mg_state], MG_RUN
    je   mg_run_turn
    cmp  byte [rel mg_state], MG_CLOSE
    je   mg_close_turn
    ret

; mg_close(EDI=reason): the first reason wins; admission closes at once.
mg_close:
    cmp  byte [rel mg_state], MG_RUN
    jne  .out
    mov  byte [rel mg_state], MG_CLOSE
    mov  byte [rel mg_step], MG_ADMIT
    jmp  mg_note
.out:
    ret

; mg_note(EDI=reason): render mg_line ("media.guest reason=...", numbers and
; fixed strings only) and emit it once on serial.
mg_note:
    push rbx
    mov  [rel mg_reason], edi
    cmp  edi, MG_R_PMH
    jne  .own
    mov  rdi, [rel mg_pool]
    lea  rsi, [rel mg_line]
    call pmr1h_render
    cmp  eax, 127
    jbe  .terminate
    mov  eax, 127
.terminate:
    lea  rcx, [rel mg_line]
    mov  byte [rcx + rax], 0
    jmp  .emit
.own:
    lea  rbx, [rel mg_line]
    lea  rsi, [rel str_mg_reason]
    call .copy
    mov  eax, [rel mg_reason]
    dec  eax
    cmp  eax, MG_R_PINNED - 1
    jbe  .named
    mov  eax, MG_R_RECORD - 1
.named:
    imul eax, eax, 24
    lea  rsi, [rel mg_reason_names]
    add  rsi, rax
    call .copy
    mov  byte [rbx], 0
.emit:
    lea  rdi, [rel str_mg_serial]
    call serial_string
    lea  rdi, [rel mg_line]
    call serial_string
    lea  rdi, [rel str_mg_crlf]
    call serial_string
    pop  rbx
    ret
.copy:                                     ; RSI=cstr -> appended at RBX
    mov  al, [rsi]
    test al, al
    jz   .copied
    mov  [rbx], al
    inc  rbx
    inc  rsi
    jmp  .copy
.copied:
    ret

; -> EAX=1 while mg_slot still holds this session's window (open, minimized or
; hidden by the lock, with our title and the owner captured at open).
mg_window_ours:
    xor  eax, eax
    test dword [rel mg_flags], MGF_WINDOW
    jz   .out
    mov  ecx, [rel mg_slot]
    cmp  ecx, WM_MAX
    jae  .out
    lea  rdx, [rel wm_state]
    mov  edx, [rdx + rcx*4]
    cmp  edx, WM_VISIBLE
    je   .title
    cmp  edx, WM_MIN
    je   .title
    cmp  edx, LOCK_HIDDEN
    jne  .out
.title:
    lea  rdx, [rel wm_title]
    mov  rdx, [rdx + rcx*8]
    lea  r8, [rel str_mg_title]
    cmp  rdx, r8
    jne  .out
    lea  rdx, [rel wm_owner]
    mov  rdx, [rdx + rcx*8]
    cmp  rdx, [rel mg_wowner]
    jne  .out
    mov  eax, 1
.out:
    ret

; ---- RUN --------------------------------------------------------------------------------------------------------
mg_run_turn:
    push rbx
    mov  rbx, [rel mg_pool]
    call mg_stop_check
    test eax, eax
    jnz  .close
    call hv_vcon_pmr_retry
    call time_monotonic_now_us
    mov  rdi, rbx
    mov  rsi, rax
    call pmr1h_turn
    call mg_events
    test eax, eax
    jnz  .close
    call mg_w1_step
    test eax, eax
    jnz  .close
    call mg_clock
    call mg_read
    call mg_credits
    call media_guest_transport_out_turn
    cmp  eax, -1
    jne  .out
    mov  eax, MG_R_RECORD
.close:
    mov  edi, eax
    call mg_close
.out:
    pop  rbx
    ret

; RBX=ctx -> EAX=0 live, else the reason this session must close.
mg_stop_check:
    mov  eax, MG_R_AUTHORITY               ; lock/unlock moved the session authority: close, W1 open or not
    mov  rcx, [rel session_authority_epoch]
    cmp  rcx, [rel mg_auth_epoch]
    jne  .out
    mov  eax, MG_R_RECORD
    cmp  byte [rel hv_vcon_pmr_fault], 0
    jne  .out
    mov  eax, MG_R_PMH
    cmp  dword [rbx + pmh.state], PMH_S_CLOSED
    je   .out
    cmp  byte [rel hv_linux_run_req], 0
    jne  .alive
    cmp  byte [rel hv_linux_start_active], 0
    jne  .alive
    cmp  byte [rel hv_linux_running], 0
    jne  .alive
    mov  eax, MG_R_BUSY                    ; our request was never consumed
    mov  ecx, [rel hv_linux_start_consumed]
    cmp  ecx, [rel mg_gen]
    jne  .out
    mov  eax, MG_R_ARTIFACT                ; a loader/boot rung failed
    cmp  byte [rel hv_linux_load_err], 0
    jne  .out
    mov  eax, MG_R_GUEST_EXIT
    jmp  .out
.alive:
    mov  eax, MG_R_BUSY                    ; a resident guest of another generation
    mov  cl, [rel hv_linux_running]
    or   cl, [rel hv_linux_start_active]
    jz   .w1
    mov  ecx, [rel hv_linux_start_consumed]
    cmp  ecx, [rel mg_gen]
    jne  .out
.w1:
    test dword [rel mg_flags], MGF_W1_OPEN
    jz   .window
    lea  rdi, [rel mg_w1_status]
    call video_player_status
    mov  ecx, eax
    mov  eax, MG_R_CLOSED                  ; W1 closed (window, lock or fault)
    test ecx, ecx
    jnz  .out
    cmp  dword [rel mg_w1_status + 4], 3
    jne  .out
.window:
    test dword [rel mg_flags], MGF_WINDOW
    jz   .hello
    call mg_window_ours
    test eax, eax
    jnz  .hello
    and  dword [rel mg_flags], ~MGF_WINDOW
    mov  eax, MG_R_CLOSED
    jmp  .out
.hello:
    xor  eax, eax
    test dword [rel mg_flags], MGF_HELLO_SEEN
    jnz  .out
    call time_monotonic_now_us
    sub  rax, [rel mg_launch_us]
    cmp  rax, MG_HELLO_US
    mov  eax, 0
    jbe  .out
    mov  eax, MG_R_TIMEOUT
.out:
    ret

; RBX=ctx. Drain every PMH event of this turn -> EAX=0, or a close reason.
mg_events:
    push r12
    push r13
    push r14
    mov  rdi, rbx
    lea  rsi, [rbx + MG_EVENTS]
    call pmr1h_ev_take
    mov  r13d, eax
    mov  eax, MG_R_RECORD
    cmp  r13d, PMH_EV_CAP * 16
    ja   .out
    xor  r12d, r12d
.next:
    cmp  r12d, r13d
    jae  .open
    lea  r14, [rbx + MG_EVENTS + r12]
    add  r12d, 16
    mov  eax, [r14]
    cmp  eax, PMH_EV_HELLO
    je   .hello
    cmp  eax, PMH_EV_OPEN
    je   .opened
    cmp  eax, PMH_EV_FRAME
    je   .frame
    cmp  eax, PMH_EV_PCM
    je   .pcm
    cmp  eax, PMH_EV_EOF
    jne  .next                             ; READ is served by flag; PMH frees drops itself
    or   dword [rel mg_flags], MGF_EOF_SEEN
    jmp  .next
.hello:
    or   dword [rel mg_flags], MGF_HELLO | MGF_HELLO_SEEN
    jmp  .next
.opened:
    or   dword [rel mg_flags], MGF_W1_WANT
    jmp  .next
.frame:
    mov  ecx, [rel mg_fifo_n]
    mov  eax, MG_R_RECORD
    cmp  ecx, PMH_FRAME_SLOTS
    jae  .out                              ; PMH never holds more than its 3 native slots
    mov  rax, [r14 + 8]
    lea  rdx, [rel mg_fifo]
    mov  [rdx + rcx*4], eax
    inc  dword [rel mg_fifo_n]
    inc  qword [rel mg_frames]
    jmp  .next
.pcm:
    mov  rdi, rbx                          ; null sink: every packet returns at once
    mov  esi, [r14 + 8]
    call pmr1h_pcm_release
    inc  qword [rel mg_pcm]
    jmp  .next
.open:
    test dword [rel mg_flags], MGF_HELLO
    jz   .done
    mov  rdi, rbx
    call pmr1h_open_record
    test eax, eax
    jnz  .done                             ; busy: retry next turn
    and  dword [rel mg_flags], ~MGF_HELLO
.done:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; RBX=ctx. At most one W1 action -> EAX=0, or a close reason.
mg_w1_step:
    mov  eax, [rel mg_flags]
    test eax, MGF_W1_WANT
    jz   .producer
    test eax, MGF_W1_OPEN
    jz   mg_w1_open
.producer:
    movzx eax, byte [rel mgp_state]
    cmp  eax, 3
    jae  .release
    cmp  eax, 2
    je   .retry
    cmp  eax, 1
    jne  .idle
    cmp  dword [rel mg_fifo_n], 0
    jne  .frame
    mov  eax, [rel mg_flags]
    and  eax, MGF_EOF_SEEN | MGF_EOF_SENT
    cmp  eax, MGF_EOF_SEEN
    jne  .idle
    mov  edi, 5                            ; W1 EOF after the last frame was ACKed
    xor  esi, esi
    call media_guest_producer_control
    test eax, eax
    jz   .eof_sent                         ; only W1's own acceptance records EOF
    cmp  eax, 2
    je   .idle
    cmp  eax, 11
    je   .idle
    cmp  eax, 3
    je   .authority
    mov  eax, MG_R_RECORD                  ; refused without W1 (shape, counter wrap) or by W1
    ret
.eof_sent:
    or   dword [rel mg_flags], MGF_EOF_SENT
    jmp  .idle
.release:
    call media_guest_producer_release
    test eax, eax
    jz   .idle
    cmp  eax, 2
    je   .idle
    mov  eax, MG_R_RECORD                  ; an ACKed slot PMH will not take back
    ret
.retry:
    call media_guest_producer_retry
    jmp  .accepted
.frame:
    mov  edi, [rel mg_fifo]
    call media_guest_producer_frame
    cmp  byte [rel mgp_state], 2
    jb   .accepted                         ; refused before staging: the slot stays queued
    mov  ecx, [rel mg_fifo + 4]            ; staged or leased: pop the FIFO head
    mov  [rel mg_fifo], ecx
    mov  ecx, [rel mg_fifo + 8]
    mov  [rel mg_fifo + 4], ecx
    dec  dword [rel mg_fifo_n]
.accepted:
    test eax, eax
    jz   .anchor
    cmp  eax, 2
    je   .idle
    cmp  eax, 11
    je   .idle
    cmp  eax, 3
    je   .authority
    mov  eax, MG_R_RECORD
    ret
.anchor:
    test dword [rel mg_flags], MGF_ANCHOR
    jnz  .idle
    cmp  byte [rel mgp_state], 3
    jne  .idle
    call mg_anchor
.idle:
    xor  eax, eax
    ret
.authority:
    mov  eax, MG_R_AUTHORITY
    ret

; RBX=ctx. W1 OPEN at OPEN_OK with the guest's admitted output size, then the
; producer binds to W1's identity receipt -> EAX=0 (or retry), else a reason.
mg_w1_open:
    lea  rdi, [rbx + MG_M_OPEN]
    xor  eax, eax
    mov  ecx, 16
    cld
    rep  stosq
    lea  rdi, [rbx + MG_M_OPEN]
    mov  dword [rdi], 1
    mov  dword [rdi + 4], 128
    mov  rax, [rel mg_pid]
    mov  [rdi + 8], rax
    mov  rax, [rel mg_auth_epoch]
    mov  [rdi + 16], rax
    mov  eax, [rel mg_slot]
    mov  [rdi + 24], eax
    mov  eax, [rbx + pmh.out_w]
    mov  [rdi + 28], eax
    mov  eax, [rbx + pmh.out_h]
    mov  [rdi + 32], eax
    mov  rax, [rel mg_wowner]
    mov  [rdi + 40], rax
    mov  rax, [rel mg_token]
    mov  [rdi + 48], rax
    mov  rax, [rel tsc_khz]
    imul rax, rax, 33                      ; one 30 fps period in TSC ticks
    test rax, rax
    jnz  .period
    mov  eax, 33
.period:
    mov  [rdi + 56], rax
    call video_player_open
    cmp  eax, 1
    je   .retry                            ; INITIALIZING: W1 clears its pool first
    cmp  eax, 2
    je   .retry
    test eax, eax
    jnz  .refused
    or   dword [rel mg_flags], MGF_W1_OPEN
    mov  rdi, rbx
    call media_guest_producer_bind
    test eax, eax
    jnz  .closed
.retry:
    xor  eax, eax
    ret
.refused:
    mov  ecx, eax
    mov  eax, MG_R_AUTHORITY
    cmp  ecx, 3
    je   .out
    mov  eax, MG_R_SURFACE
    cmp  ecx, 9
    je   .out
    mov  eax, MG_R_MEMORY
    sub  ecx, 5
    cmp  ecx, 3
    jbe  .out
.closed:
    mov  eax, MG_R_CLOSED
.out:
    ret

; Anchor the media clock on the first W1-accepted frame: its pts in ns (W1's
; own floor conversion, pts * tb_num * 1e9 / tb_den) is shown MG_LEAD_NS after
; now. An unrepresentable pts leaves the session unanchored (W1 holds frames).
mg_anchor:
    push rbx
    mov  ebx, [rel mgp_frame + 100]        ; tb_den
    test ebx, ebx
    jz   .out
    mov  rax, [rel mgp_frame + 80]         ; pts
    xor  edx, edx
    div  rbx                               ; q = pts / den, r = pts % den
    mov  r8, rdx
    mov  ecx, [rel mgp_frame + 96]         ; tb_num
    mul  rcx
    jc   .out
    mov  r9d, 1000000000
    mul  r9
    jc   .out
    mov  r10, rax                          ; q * num * 1e9
    mov  rax, r8
    mul  rcx                               ; r * num < 2^40
    mul  r9                                ; < 2^70, and the quotient < num * 1e9
    div  rbx
    add  rax, r10
    jc   .out
    js   .out
    mov  [rel mg_anchor_media], rax
    call boot_ms_now
    imul rax, rax, 1000000
    jo   .out
    add  rax, MG_LEAD_NS
    jo   .out
    mov  [rel mg_anchor_host], rax
    or   dword [rel mg_flags], MGF_ANCHOR
.out:
    pop  rbx
    ret

; RBX=ctx. At most one CLOCK192 VIDEO_ONLY snapshot per millisecond once the
; clock is anchored: [a, b] is the media interval at W1's own boot_ms clock.
mg_clock:
    test dword [rel mg_flags], MGF_ANCHOR
    jz   .out
    cmp  byte [rel mgp_state], 0
    je   .out
    call boot_ms_now
    cmp  rax, [rel mg_clock_ms]
    je   .out
    mov  [rel mg_clock_ms], rax
    imul r8, rax, 1000000                  ; now in ns
    jo   .out
    mov  r9, r8
    sub  r9, [rel mg_anchor_host]
    jo   .out
    add  r9, [rel mg_anchor_media]         ; a
    jo   .out
    mov  r10, r9
    add  r10, MG_WIDTH_NS                  ; b
    jo   .out
    mov  r11, [rel mg_clock_seq]
    inc  r11
    jz   .out
    mov  [rel mg_clock_seq], r11
    lea  rdi, [rbx + MG_M_CLOCK]
    xor  eax, eax
    mov  ecx, 24
    cld
    rep  stosq
    lea  rdi, [rbx + MG_M_CLOCK]
    mov  dword [rdi], 1
    mov  dword [rdi + 4], 4                ; VIDEO_ONLY
    mov  qword [rdi + 8], 1
    mov  rax, [rel mgp_identity + 8]
    mov  [rdi + 16], rax
    mov  [rdi + 56], rax
    mov  rax, [rel mgp_identity + 16]
    mov  [rdi + 24], rax
    mov  [rdi + 64], rax
    mov  [rdi + 48], r11
    mov  [rdi + 88], r11
    mov  [rdi + 96], r8
    add  r8, MG_VALID_NS
    mov  [rdi + 104], r8
    mov  [rdi + 112], r9
    mov  [rdi + 120], r10
    call video_player_clock
.out:
    ret

; RBX=ctx. Serve the outstanding READ from the file: at most PMH_READ_MAX bytes
; read into the owner's buffer, n = min(len, size - off); n = 0 is EOF and a
; short or failed read is IO_ERROR with no payload. A past-epoch READ is
; answered empty and PMH marks it CANCELLED. Busy output retries next turn.
mg_read:
    push r12
    push r13
    test dword [rbx + pmh.flags], PMH_F_READ
    jz   .out
    cmp  dword [rbx + pmh.state], PMH_S_CLOSED
    je   .out
    xor  r12d, r12d                        ; status
    xor  r13d, r13d                        ; payload bytes
    mov  rax, [rbx + pmh.read_epoch]
    cmp  rax, [rbx + pmh.epoch]
    jne  .reply
    mov  rax, [rbx + pmh.file_size]
    sub  rax, [rbx + pmh.read_off]
    jb   .io
    mov  ecx, [rbx + pmh.read_len]
    cmp  rax, rcx
    jae  .bounded
    mov  ecx, eax
.bounded:
    mov  r12d, MG_DATA_EOF
    test ecx, ecx
    jz   .reply
    cmp  ecx, PMH_READ_MAX
    ja   .io
    mov  r13d, ecx
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel mg_name11]
    mov  rdx, [rbx + pmh.read_off]
    lea  rcx, [rbx + MG_READ]
    mov  r8d, r13d
    call vfs_read_at
    xor  r12d, r12d
    cmp  rax, r13
    je   .reply
.io:
    mov  r12d, MG_DATA_IO
    xor  r13d, r13d
.reply:
    mov  rdi, rbx
    mov  esi, r12d
    lea  rdx, [rbx + MG_READ]
    mov  ecx, r13d
    call pmr1h_data_reply
    test eax, eax
    js   .out
    inc  qword [rel mg_reads]
.out:
    pop  r13
    pop  r12
    ret

; RBX=ctx. Credits only while W1 is ours and the producer is bound: one frame
; credit (PMH reserves its native slot) until EOF, one PCM credit per turn.
mg_credits:
    test dword [rel mg_flags], MGF_W1_OPEN
    jz   .out
    cmp  byte [rel mgp_state], 0
    je   .out
    test dword [rel mg_flags], MGF_EOF_SEEN
    jnz  .out
    mov  rdi, rbx
    call pmr1h_grant_frame
    cmp  dword [rbx + pmh.audio], 0
    je   .out
    mov  esi, [rel mg_pcm_next]
    lea  eax, [rsi + 1]
    and  eax, PMH_PCM_SLOTS - 1
    mov  [rel mg_pcm_next], eax
    mov  rdi, rbx
    call pmr1h_grant_pcm
.out:
    ret

; ---- CLOSE ------------------------------------------------------------------------------------------------------
mg_close_turn:
    push rbx
    mov  rbx, [rel mg_pool]
    movzx eax, byte [rel mg_step]
    cmp  eax, MG_ADMIT
    je   .admit
    cmp  eax, MG_DRAIN
    je   .drain
    cmp  eax, MG_WINDOW
    je   .window
    cmp  eax, MG_POOLZ
    je   .pool
    jmp  .done
.admit:
    ; 1. Close admission: no byte reaches or leaves PMH from here on.
    test dword [rel mg_flags], MGF_PMR
    jz   .guest
    call media_guest_transport_stop_after_pmh
.guest:
    ; 2. Guest STOP: cancel a queued START, stop a resident vCPU at its next exit.
    mov  byte [rel hv_linux_run_req], 0
    call mg_halt_guest
    ; 3. W1: drop a staged frame, then CLOSE (EOF_TEARDOWN after EOF) W1 if it
    ;    is ours. Without a bound producer, closing our window closes W1.
    cmp  byte [rel mgp_state], 2
    jne  .w1
    call media_guest_producer_drop
.w1:
    test dword [rel mg_flags], MGF_W1_OPEN
    jz   .native
    call mg_w1_live
    test eax, eax
    jz   .native
    cmp  byte [rel mgp_state], 0
    je   .w1_window
    mov  edi, 4
    test dword [rel mg_flags], MGF_EOF_SENT
    jz   .w1_close
    mov  edi, 8
.w1_close:
    xor  esi, esi
    call media_guest_producer_control
    call mg_w1_live
    test eax, eax
    jz   .native
.w1_window:
    call mg_window_ours
    test eax, eax
    jz   .native
    and  dword [rel mg_flags], ~MGF_WINDOW
    mov  edi, [rel mg_slot]
    call wmx_close_slot                    ; W1's close hook moves ACTIVE to DRAIN
.native:
    ; 4. Queued frames and held PCM go back to PMH by identity.
    mov  ecx, [rel mg_fifo_n]
    test ecx, ecx
    jz   .pcm
    dec  ecx
    mov  [rel mg_fifo_n], ecx
    lea  rax, [rel mg_fifo]
    mov  esi, [rax + rcx*4]
    mov  rdi, rbx
    call pmr1h_native_release
    jmp  .native
.pcm:
    mov  eax, [rbx + pmh.pcm_held]
    bsf  esi, eax
    jz   .admitted
    mov  rdi, rbx
    call pmr1h_pcm_release
    test eax, eax
    jz   .pcm
.admitted:
    call time_monotonic_now_us
    mov  [rel mg_drain_us], rax
    mov  byte [rel mg_step], MG_DRAIN
    jmp  .out
.drain:
    ; Wait for the vCPU to leave VMX, then retire W1's source by the real ACK.
    mov  byte [rel hv_linux_run_req], 0
    call mg_halt_guest
    test eax, eax
    jnz  .out
    movzx eax, byte [rel mgp_state]
    cmp  eax, 2
    jne  .drain_ack
    call media_guest_producer_drop
    jmp  .drain_check
.drain_ack:
    cmp  eax, 3
    jb   .drain_check
    call media_guest_producer_release      ; W1 publishes the release while draining
.drain_check:
    cmp  byte [rel mgp_state], 1
    ja   .lease_wait
    call media_guest_producer_unbind
    test eax, eax
    jnz  .out                              ; the producer refuses while W1 holds a lease
    mov  qword [rel mg_cursor], 0
    mov  byte [rel mg_step], MG_WINDOW
    jmp  .out
.lease_wait:
    call time_monotonic_now_us
    sub  rax, [rel mg_drain_us]
    cmp  rax, MG_DRAIN_US
    jb   .out                              ; keep the real ACK path throughout the grace
    ; mg_halt_guest above confirmed the one vCPU is neither loading nor in
    ; VMX. Keep every native source byte, producer tuple and lease intact.
    ; W1 is CPU-only here; console unbind changes no device translation.
    mov  byte [rel mg_quarantined], 1
    mov  qword [rel mg_cursor], 0
    mov  byte [rel mg_step], MG_WINDOW
    jmp  .out
.window:
    ; The stopped guest's 4 MiB MEDIA window, through the still-owned mapping.
    mov  rdi, [rel mg_window_hva]
    test rdi, rdi
    jz   .window_done
    add  rdi, [rel mg_cursor]
    xor  eax, eax
    mov  ecx, MG_CHUNK / 8
    cld
    rep  stosq
    add  qword [rel mg_cursor], MG_CHUNK
    cmp  qword [rel mg_cursor], VP_MEDIA_WINDOW
    jb   .out
.window_done:
    mov  qword [rel mg_cursor], 0
    mov  qword [rel mg_window_hva], 0      ; scrubbed: released exactly once
    call hv_media_window_release           ; RC-speed-reserve: the span may go back
    cmp  byte [rel mg_quarantined], 0
    jne  .quarantine_done                  ; never scrub or recycle a still-leased native pool
    mov  byte [rel mg_step], MG_POOLZ
    jmp  .out
.pool:
    ; The native pool: slots, PCM, staging and records first, PMH context last.
    mov  rax, [rel mg_cursor]
    mov  edx, MG_POOL_BYTES - MG_FRAMES
    cmp  rax, rdx
    jae  .pool_ctx
    lea  rdi, [rbx + MG_FRAMES + rax]
    sub  rdx, rax
    jmp  .pool_zero
.pool_ctx:
    sub  rax, rdx
    lea  rdi, [rbx + rax]
    mov  edx, MG_FRAMES
    sub  rdx, rax
.pool_zero:
    mov  ecx, MG_CHUNK
    cmp  rdx, rcx
    jae  .pool_store
    mov  ecx, edx
.pool_store:
    add  [rel mg_cursor], rcx
    xor  eax, eax
    cld
    rep  stosb
    cmp  qword [rel mg_cursor], MG_POOL_BYTES
    jb   .out
    sfence
    mov  byte [rel mg_step], MG_DONE
    jmp  .out
.quarantine_done:
    test dword [rel mg_flags], MGF_PMR
    jz   .quarantine_window
    call hv_vcon_pmr_unbind                ; byte-protocol console only, no DMA-map operation
.quarantine_window:
    call mg_window_ours
    test eax, eax
    jz   .quarantine_end
    mov  edi, [rel mg_slot]
    call wmx_close_slot
.quarantine_end:
    mov  byte [rel mg_state], MG_QUARANTINE ; no more owner turns, including no late-ACK reuse
    mov  edi, MG_R_PINNED
    call mg_note
    jmp  .out
.done:
    ; Console unbind last, then the window if it is still ours.
    test dword [rel mg_flags], MGF_PMR
    jz   .done_window
    call hv_vcon_pmr_unbind
.done_window:
    call mg_window_ours
    test eax, eax
    jz   .idle
    mov  edi, [rel mg_slot]
    call wmx_close_slot
.idle:
    xor  eax, eax
    mov  [rel mg_flags], eax
    mov  [rel mg_fifo_n], eax
    mov  [rel mg_cursor], rax
    mov  [rel mg_window_hva], rax
    mov  [rel mg_anchor_media], rax
    mov  [rel mg_anchor_host], rax
    mov  byte [rel mg_step], MG_ADMIT
    mov  byte [rel mg_state], MG_IDLE
.out:
    pop  rbx
    ret

; -> EAX=1 while the vCPU still runs or loads (stop re-asserted: a START that
; was loading resets stop_req before it runs), 0 once it has left VMX.
mg_halt_guest:
    xor  eax, eax
    cmp  byte [rel hv_linux_running], 0
    jne  .stop
    cmp  byte [rel hv_linux_start_active], 0
    jne  .stop
    cmp  byte [rel hv_linux_vmx_live], 0
    je   .out                             ; media profile has exactly one resident vCPU
.stop:
    mov  byte [rel hv_linux_stop_req], 1
    mov  eax, 1
.out:
    ret

; -> EAX=1 while W1 is ACTIVE (state 3).
mg_w1_live:
    sub  rsp, 8
    lea  rdi, [rel mg_w1_status]
    call video_player_status
    add  rsp, 8
    test eax, eax
    jnz  .no
    cmp  dword [rel mg_w1_status + 4], 3
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---- GUESTMEDIA (lab qualification verb) -------------------------------------------------------------------------
; Registered only in a lab-profile image. START needs the local principal;
; STOP needs the principal that started; STATUS is numbers and fixed strings.
; Direct assembler invocations keep the shipped posture (svc/command_auth.asm).
%ifndef PAOS_PUBLICITY_LAB_PROFILE
    %define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
media_guest_register_verb:
%if PAOS_PUBLICITY_LAB_PROFILE
    sub  rsp, 8
    lea  rdi, [rel str_verb_guestmedia]
    lea  rsi, [rel cmd_verb_guestmedia]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1                            ; mutating
    call command_register_verb
    add  rsp, 8
%endif
    ret

%if PAOS_PUBLICITY_LAB_PROFILE
cmd_verb_guestmedia:
    push rbx
    push r12
    push r13
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    call hv_out_reset
    test rbx, rbx
    jz   .render
    mov  rdi, rbx
    lea  rsi, [rel str_mg_start]
    call hv_tok_is
    test al, al
    jnz  .start
    mov  rdi, rbx
    lea  rsi, [rel str_mg_stop]
    call hv_tok_is
    test al, al
    jz   .render                           ; STATUS (or anything else) only reports
    call media_guest_stop
    jmp  .render
.start:
    lea  rdi, [rbx + 5]
    call hv_skip_spaces
    mov  r13, rax
    xor  esi, esi
.length:
    mov  al, [r13 + rsi]
    test al, al
    jz   .measured
    cmp  al, ' '
    je   .measured
    cmp  al, 13
    je   .measured
    cmp  al, 10
    je   .measured
    inc  esi
    cmp  esi, 14                           ; vfs_path_to_name11 refuses > 13
    jb   .length
.measured:
    mov  rdi, r13
    call media_guest_start
.render:
    lea  rdi, [rel str_mg_status_state]
    call hv_out_str
    movzx eax, byte [rel mg_state]
    call hv_out_dec
    lea  rdi, [rel str_mg_status_step]
    call hv_out_str
    movzx eax, byte [rel mg_step]
    call hv_out_dec
    lea  rdi, [rel str_mg_status_frames]
    call hv_out_str
    mov  eax, [rel mg_frames]
    call hv_out_dec
    lea  rdi, [rel str_mg_status_pcm]
    call hv_out_str
    mov  eax, [rel mg_pcm]
    call hv_out_dec
    lea  rdi, [rel str_mg_status_reads]
    call hv_out_str
    mov  eax, [rel mg_reads]
    call hv_out_dec
    cmp  byte [rel mg_quarantined], 0
    je   .lease_pin
    lea  rdi, [rel str_mg_status_quarantined]
    call hv_out_str
    jmp  .unpinned
.lease_pin:
    cmp  byte [rel mg_state], MG_CLOSE      ; root ruling G3b-SEC-5 (a): CLOSE held in DRAIN by W1's lease is named;
    jne  .unpinned                         ; reboot clears a lease that never returns
    cmp  byte [rel mg_step], MG_DRAIN
    jne  .unpinned
    cmp  byte [rel mgp_state], 1
    jbe  .unpinned
    lea  rdi, [rel str_mg_status_pinned]
    call hv_out_str
.unpinned:
    lea  rdi, [rel str_mg_space]
    call hv_out_str
    lea  rdi, [rel mg_line]
    call hv_out_str
    mov  byte [rel hv_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

str_verb_guestmedia: db 'GUESTMEDIA', 0
str_mg_start: db 'START', 0
str_mg_stop: db 'STOP', 0
str_mg_status_state: db ' GUESTMEDIA state=', 0
str_mg_status_step: db ' step=', 0
str_mg_status_frames: db ' frames=', 0
str_mg_status_pcm: db ' pcm=', 0
str_mg_status_reads: db ' reads=', 0
str_mg_space: db ' ', 0
str_mg_status_pinned: db ' pinned=w1_lease', 0
str_mg_status_quarantined: db ' pinned=w1_lease quarantine=native_pool', 0
%endif

str_mg_profile: db 'media', 0
str_mg_title: db 'Media guest', 0
str_mg_reason: db 'media.guest reason=', 0
str_mg_serial: db '[PAOS64] ', 0
str_mg_crlf: db 13, 10, 0
%macro MG_REASON_NAME 1
%%name: db %1, 0
    times 24 - ($ - %%name) db 0
%endmacro
mg_reason_names:                           ; 24 B each, MG_R_STOPPED..MG_R_TIMEOUT
    MG_REASON_NAME 'stopped'
    MG_REASON_NAME 'guest_exit'
    MG_REASON_NAME 'artifact'
    MG_REASON_NAME 'busy'
    MG_REASON_NAME 'rail_unavailable'
    MG_REASON_NAME 'authority'
    MG_REASON_NAME 'surface'
    MG_REASON_NAME 'memory'
    MG_REASON_NAME 'record'
    MG_REASON_NAME 'closed'
    MG_REASON_NAME 'timeout'
    MG_REASON_NAME 'pmh'                      ; MG_R_PMH renders through pmr1h_render instead
    MG_REASON_NAME 'pinned'

%include "core/abi/wdata.inc"
%macro WDATA_gui_guest_media_owner 0
align 8
mg_pool: dq 0
mg_pool_cause: dd 0
mg_out_len: dd 0
mg_out_pos: dd 0
mg_pool_attempted: db 0
mg_transport_stopping: db 0
align 8
mg_session_seq: dq 0
mg_pid: dq 0
mg_token: dq 0
mg_auth_epoch: dq 0
mg_wowner: dq 0
mg_window_hva: dq 0
mg_file_size: dq 0
mg_launch_us: dq 0
mg_drain_us: dq 0
mg_anchor_media: dq 0
mg_anchor_host: dq 0
mg_clock_seq: dq 0
mg_clock_ms: dq 0
mg_frames: dq 0
mg_pcm: dq 0
mg_reads: dq 0
mg_cursor: dq 0
mg_stat: times 16 db 0
mg_w1_status: times 32 db 0
mg_flags: dd 0
mg_reason: dd 0
mg_gen: dd 0
mg_slot: dd 0
mg_fifo: times 4 dd 0
mg_fifo_n: dd 0
mg_pcm_next: dd 0
mg_name11: times 12 db 0
mg_state: db 0
mg_step: db 0
mg_quarantined: db 0                       ; permanent; no reset path other than boot
mg_line: times 128 db 0
%endmacro
WDATA_DEFER WDATA_gui_guest_media_owner
%endif
