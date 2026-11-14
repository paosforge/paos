;; MODULE media/pmr1_host_private
;; LAYER 4
;; EXPORTS pmr1h_init, pmr1h_rx, pmr1h_turn, pmr1h_out_take, pmr1h_ev_take, pmr1h_record, pmr1h_open_record, pmr1h_grant_frame, pmr1h_grant_pcm, pmr1h_native_release, pmr1h_pcm_release, pmr1h_control, pmr1h_clock, pmr1h_data_reply, pmr1h_render, pmr1h_build_hex
;; IMPORTS core/lib/crc32
;; CAPS
;; OWNER rc-vm
; RCQ-37 G3a PRIVATE UNWIRED: the native PMR1 host session (PMR1.md de6a41edb, model pmr1.py). Included by no image
; build; G3b wires it (console framer feed, owner task, S2b/S2a/snd callbacks) under its own grant.
; The guest is untrusted (rc-sec S1-S8): records are framed from host-copied console bytes; a payload is read from the
; MEDIA window exactly once, at a host-computed slot address, into host memory, and every check after that reads the
; host copy only (copy, then validate; the CRC is tear detection, never authentication). No pointer, address, wall
; clock or TSC is ever written to the guest. The context is caller memory (pmh_size bytes, 8-aligned): the owner fills
; the config block, pmr1h_init checks it and zeroes the session. SysV ABI on every entry; DF is cleared.
; Returns: >= 0 an outcome/count; -1..-8 the session stopped with that reason (it is CLOSED from then on);
; -32 busy (out queue or event queue full, nothing changed); -33 invalid host call (nothing changed).

PMH_R_RECORD        equ 1
PMH_R_GENERATION    equ 2
PMH_R_PTS           equ 3
PMH_R_CRC           equ 4
PMH_R_OPEN_REFUSED  equ 5
PMH_R_GUEST_ERROR   equ 6
PMH_R_OPEN_DEADLINE equ 7                   ; srcreview F13
PMH_R_PROFILE       equ 8                   ; a config outside its bounds (quantum, record cap, ...)
PMH_BUSY            equ 32
PMH_INVAL           equ 33

; outcomes (pmr1h_record / event codes)
PMH_EV_HELLO        equ 1
PMH_EV_OPEN         equ 2
PMH_EV_READ         equ 3
PMH_EV_STALE_READ   equ 4
PMH_EV_FRAME        equ 5                   ; arg = native slot (READY/held until pmr1h_native_release)
PMH_EV_CRC_DROP     equ 6
PMH_EV_PCM          equ 7                   ; arg = packet index (held until pmr1h_pcm_release)
PMH_EV_ACK          equ 8
PMH_EV_EOF          equ 9
PMH_EV_STALE        equ 10
PMH_EV_REVOKED      equ 11                  ; a frame whose epoch ended during its copy: discarded at publication
PMH_PENDING         equ 0x40                ; a FRAME/PCM was admitted; its copy runs in the next owner turns

PMH_S_WAIT_HELLO    equ 0
PMH_S_WAIT_OPEN     equ 1
PMH_S_OPEN          equ 2
PMH_S_CLOSED        equ 3

PMH_F_PAUSED        equ 1 << 0
PMH_F_FIRST         equ 1 << 1              ; the next frame is the epoch's first (DISCONT allowed)
PMH_F_EOF           equ 1 << 2              ; EOF seen: terminal for this epoch
PMH_F_STALE         equ 1 << 3              ; between a SEEK and its ACK: the stale budget is live
PMH_F_TB            equ 1 << 4
PMH_F_LPTS          equ 1 << 5
PMH_F_PSEQ          equ 1 << 6
PMH_F_PNEXT         equ 1 << 7
PMH_F_CREDIT        equ 1 << 8              ; a frame credit is outstanding
PMH_F_READ          equ 1 << 9              ; a READ is outstanding
PMH_F_CTL           equ 1 << 10             ; a CONTROL is unacknowledged
PMH_F_SYNC          equ 1 << 11             ; the framer has seen HELLO

PMH_T_HELLO         equ 0x0001
PMH_T_OPEN_OK       equ 0x0002
PMH_T_OPEN_REFUSE   equ 0x0003
PMH_T_FRAME         equ 0x0010
PMH_T_PCM           equ 0x0011
PMH_T_READ          equ 0x0020
PMH_T_ACK           equ 0x0030
PMH_T_EOF           equ 0x0031
PMH_T_ERROR         equ 0x003F
PMH_T_OPEN          equ 0x0101
PMH_T_CONTROL       equ 0x0102
PMH_T_CLOCK         equ 0x0110
PMH_T_CREDIT        equ 0x0111
PMH_T_DATA          equ 0x0120

PMH_MAGIC           equ 0x31524D50          ; 'PMR1'
PMH_PTS_LIMIT       equ 1 << 47
PMH_TB_LIMIT        equ 1 << 20
PMH_FRAME_SLOTS     equ 3
PMH_FRAME_SLOT      equ 0x100000
PMH_PCM_SLOTS       equ 16
PMH_PCM_SLOT        equ 0x1000
PMH_PCM_BASE        equ 0x300000
PMH_INGRESS         equ 0x340000
PMH_INGRESS_BYTES   equ 0x40000
PMH_READ_MAX        equ 0x10000
PMH_NATIVE_SLOT     equ 640 * 360 * 4       ; 921,600: the native WRITING slot
PMH_BGRX            equ 0x34325258
PMH_QUANTUM_MAX     equ 65536               ; absolute ceiling (PMR1 sec. 6); never grown at run time
PMH_REC_CAP_MAX     equ 64
PMH_DEADLINE_MIN    equ 100000              ; srcreview F3: the OPEN_OK deadline, in us (now = time_monotonic_now_us)
PMH_DEADLINE_MAX    equ 600000000           ;   100 ms .. 10 min
PMH_PROBE_MAX       equ 4096                ;   probe READs before OPEN_OK: 1 .. 4096 (x 64 KiB = 256 MiB)
PMH_PRE_HELLO       equ 4096
PMH_CRC_RUN         equ 3
PMH_EV_CAP          equ 128
PMH_OUT_CAP         equ 2048
PMH_RX_CAP          equ 8192
PMH_REC_MAX         equ 136

struc pmh
 ; ---- config: written by the owner before pmr1h_init; the module only reads it
 .session:    resq 1
 .vm_gen:     resq 1
 .file_size:  resq 1
 .window:     resq 1                        ; host mapping of the 4 MiB MEDIA window
 .native:     resq 3                        ; the 3 native frame slots (PMH_NATIVE_SLOT bytes each)
 .pcmbuf:     resq 1                        ; 16 native PCM packets (PMH_PCM_SLOT bytes each)
 .deadline:   resq 1                        ; F13: OPEN_OK within this many us of HELLO (F3: 100 ms .. 10 min)
 .pcm_rate:   resd 1
 .pcm_ch:     resd 1
 .max_src_w:  resd 1
 .max_src_h:  resd 1
 .max_fps_num: resd 1
 .max_fps_den: resd 1
 .quantum:    resd 1                        ; bytes copied per owner turn: 4..65536, a multiple of 4
 .rec_cap:    resd 1                        ; records processed per owner turn: 1..64 (rc-sec S2)
 .probe_max:  resd 1                        ; F13: probe READs before OPEN_OK (F3: 1 .. 4096)
 .cfg_rsvd:   resd 1
 ; ---- session: zeroed by pmr1h_init
 .state:      resd 1
 .reason:     resd 1
 .greason:    resd 1                        ; the guest's numeric reason (OPEN_REFUSE / ERROR)
 .flags:      resd 1
 .stream:     resd 1
 .audio:      resd 1
 .out_w:      resd 1
 .out_h:      resd 1
 .tb_num:     resd 1
 .tb_den:     resd 1
 .crc_run:    resd 1
 .probes:     resd 1
 .fc_slot:    resd 1                        ; the outstanding frame credit: window slot ...
 .fc_native:  resd 1                        ; ... and the native slot reserved for it
 .pcm_mask:   resd 1                        ; PCM credits outstanding
 .pcm_held:   resd 1                        ; native PCM packets not yet released
 .ctl_op:     resd 1
 .read_len:   resd 1
 .allow:      resd 4                        ; stale budget fixed at the SEEK: FRAME, PCM, EOF, READ
 .nstate:     resb 4                        ; native slot: 0 free, 1 WRITING, 2 held (READY/FRONT)
 .rx_len:     resd 1
 .rx_pos:     resd 1
 .discarded:  resd 1
 .out_len:    resd 1
 .ev_len:     resd 1
 .job_kind:   resd 1                        ; 0 none, PMH_T_FRAME, PMH_T_PCM
 .job_slot:   resd 1
 .job_len:    resd 1
 .job_done:   resd 1
 .job_crc:    resd 1
 .job_want:   resd 1
 .now:        resq 1
 .hello_time: resq 1
 .epoch:      resq 1
 .last_pts:   resq 1
 .last_fseq:  resq 1
 .epoch_fseq: resq 1
 .fcompl:     resq 1
 .pcompl:     resq 1
 .pseq:       resq 1
 .pnext:      resq 1
 .pframes:    resq 1
 .clock_seq:  resq 1
 .last_rid:   resq 1
 .read_rid:   resq 1
 .read_off:   resq 1
 .read_epoch: resq 1
 .ctl_count:  resq 1
 .ctl_seq:    resq 1
 .ctl_epoch:  resq 1
 .fc_gen:     resq 1
 .fc_epoch:   resq 1
 .job_src:    resq 1
 .job_dst:    resq 1
 .job_epoch:  resq 1
 .job_pts:    resq 1                        ; frame: its pts; PCM: first_pts + frames
 .job_frames: resq 1
 .cnt_stale:  resq 1
 .cnt_crc:    resq 1
 .cnt_frames: resq 1
 .cnt_pcm:    resq 1
 .fgens:      resq PMH_FRAME_SLOTS
 .pgens:      resq PMH_PCM_SLOTS
 .pc_gen:     resq PMH_PCM_SLOTS
 .pc_epoch:   resq PMH_PCM_SLOTS
 .build:      resb 16
 .rec:        resb PMH_REC_MAX              ; the record being processed (a host copy)
 .job_desc:   resb 128
 .pub_desc:   resb PMH_FRAME_SLOTS * 128    ; the published descriptor of each held native slot
 .pcm_desc:   resb PMH_PCM_SLOTS * 96
 .ev:         resb PMH_EV_CAP * 16          ; {u32 code, u32 slot, u64 arg}
 .out:        resb PMH_OUT_CAP              ; host->guest records, drained by the owner
 .rx:         resb PMH_RX_CAP               ; console bytes not yet framed
endstruc

; every public entry saves the same frame and leaves through pmh_ret
%macro PMH_ENTER 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    cld
    mov  rbx, rdi
%endmacro

; srcreview F2: the one state test of every host request (rx, open_record, grant_*, control, clock, data_reply):
; after the stop each refuses -33 and changes nothing
%macro PMH_REQUEST 0
    PMH_ENTER
    cmp  dword [rbx + pmh.state], PMH_S_CLOSED
    je   pmh_inval
%endmacro

; ---- init, rx, turn ------------------------------------------------------------------------------------------
; pmr1h_init(RDI=ctx) -> 0, or -PMH_R_PROFILE (the context is then CLOSED)
pmr1h_init:
    PMH_ENTER
    lea  rdi, [rbx + pmh.state]
    mov  ecx, pmh_size - pmh.state
    xor  eax, eax
    rep  stosb
    mov  eax, [rbx + pmh.quantum]
    lea  ecx, [rax - 4]
    cmp  ecx, PMH_QUANTUM_MAX - 4
    ja   .bad
    test al, 3
    jnz  .bad
    mov  eax, [rbx + pmh.rec_cap]
    dec  eax
    cmp  eax, PMH_REC_CAP_MAX - 1
    ja   .bad
    mov  eax, [rbx + pmh.pcm_ch]
    dec  eax
    cmp  eax, 1
    ja   .bad
    mov  eax, [rbx + pmh.probe_max]         ; srcreview F3: both F13 limits inside a stated range
    dec  eax
    cmp  eax, PMH_PROBE_MAX - 1
    ja   .bad
    mov  rax, [rbx + pmh.deadline]
    sub  rax, PMH_DEADLINE_MIN
    cmp  rax, PMH_DEADLINE_MAX - PMH_DEADLINE_MIN
    ja   .bad
    xor  eax, eax
    cmp  [rbx + pmh.pcm_rate], eax
    je   .bad
    cmp  [rbx + pmh.max_src_w], eax
    je   .bad
    cmp  [rbx + pmh.max_src_h], eax
    je   .bad
    cmp  [rbx + pmh.max_fps_num], eax
    je   .bad
    cmp  [rbx + pmh.max_fps_den], eax
    je   .bad
    lea  rsi, [rbx + pmh.window]
    mov  ecx, 5                             ; window, native[3], pcmbuf
.ptr:
    cmp  [rsi], rax
    je   .bad
    add  rsi, 8
    dec  ecx
    jnz  .ptr
    mov  qword [rbx + pmh.epoch], 1
    mov  dword [rbx + pmh.flags], PMH_F_FIRST
    jmp  pmh_ret
.bad:
    mov  eax, PMH_R_PROFILE
    call pmh_fault
    jmp  pmh_ret

; pmr1h_rx(RDI=ctx, RSI=bytes, EDX=len) -> bytes accepted (the rest stays with the caller: backpressure), -33 after
; the stop
pmr1h_rx:
    PMH_REQUEST
    mov  r12, rsi
    mov  r13d, edx
    call pmh_compact
    mov  ecx, PMH_RX_CAP
    sub  ecx, [rbx + pmh.rx_len]
    cmp  ecx, r13d
    cmova ecx, r13d
    mov  eax, ecx
    mov  edi, [rbx + pmh.rx_len]
    add  [rbx + pmh.rx_len], ecx
    lea  rdi, [rbx + pmh.rx + rdi]
    mov  rsi, r12
    rep  movsb
    jmp  pmh_ret

; pmr1h_turn(RDI=ctx, RSI=now in us) -> 1 work done, 0 idle, -32 events not drained, -reason stopped.
; One owner turn: either one copy step of at most `quantum` bytes, or at most `rec_cap` records framed and processed.
pmr1h_turn:
    PMH_ENTER
    mov  [rbx + pmh.now], rsi
    call pmh_closed
    jnz  pmh_ret
    cmp  dword [rbx + pmh.state], PMH_S_WAIT_OPEN
    jne  .live
    mov  rax, rsi
    sub  rax, [rbx + pmh.hello_time]
    cmp  rax, [rbx + pmh.deadline]
    jbe  .live
    mov  eax, PMH_R_OPEN_DEADLINE          ; F13: no OPEN_OK in time
    call pmh_fault
    jmp  pmh_ret
.live:
    mov  eax, [rbx + pmh.rec_cap]
    add  eax, 1
    add  eax, [rbx + pmh.ev_len]
    cmp  eax, PMH_EV_CAP
    ja   .busy
    cmp  dword [rbx + pmh.job_kind], 0
    je   .records
    call pmh_copy_step
    test eax, eax
    js   pmh_ret
    mov  eax, 1
    jmp  pmh_ret
.records:
    xor  r14d, r14d                         ; records this turn
.next:
    cmp  r14d, [rbx + pmh.rec_cap]
    jae  .done
    call pmh_frame_next
    test eax, eax
    js   pmh_ret
    jz   .done
    mov  ecx, eax
    call pmh_record
    test eax, eax
    js   pmh_ret
    inc  r14d
    cmp  dword [rbx + pmh.job_kind], 0      ; FIFO: nothing after a FRAME/PCM until it is published
    je   .next
.done:
    call pmh_compact
    xor  eax, eax
    test r14d, r14d
    setnz al
    jmp  pmh_ret
.busy:
    mov  eax, -PMH_BUSY
    jmp  pmh_ret

; pmr1h_record(RDI=ctx, RSI=record, EDX=len) -> outcome, PMH_PENDING, or -reason: one whole record, as the framer
; would hand it over (the owner and the suite's differential use this; the turn uses the same path).
pmr1h_record:
    PMH_ENTER
    call pmh_closed
    jnz  pmh_ret
    mov  eax, -PMH_BUSY
    cmp  dword [rbx + pmh.ev_len], PMH_EV_CAP - 1
    jae  pmh_ret
    cmp  dword [rbx + pmh.job_kind], 0
    jne  pmh_ret                            ; a copy is still running: the record waits (FIFO)
    cmp  edx, PMH_REC_MAX
    ja   .bad
    cmp  edx, 8
    jb   .bad
    mov  ecx, edx
    lea  rdi, [rbx + pmh.rec]
    rep  movsb
    mov  ecx, edx
    call pmh_record
    jmp  pmh_ret
.bad:
    mov  eax, PMH_R_RECORD
    call pmh_fault
    jmp  pmh_ret

; pmr1h_out_take(RDI=ctx, RSI=buf >= 2048 B) -> bytes of whole host->guest records moved out (the queue is empty)
pmr1h_out_take:
    PMH_ENTER
    mov  ecx, [rbx + pmh.out_len]
    mov  dword [rbx + pmh.out_len], 0
    lea  rdx, [rbx + pmh.out]
    jmp  pmh_take

; pmr1h_ev_take(RDI=ctx, RSI=buf >= 2048 B) -> bytes of events moved out, 16 B each {u32 code, u32 slot, u64 arg}
pmr1h_ev_take:
    PMH_ENTER
    mov  ecx, [rbx + pmh.ev_len]
    mov  dword [rbx + pmh.ev_len], 0
    shl  ecx, 4
    lea  rdx, [rbx + pmh.ev]
pmh_take:
    mov  rdi, rsi
    mov  rsi, rdx
    mov  eax, ecx
    rep  movsb
    jmp  pmh_ret

pmh_ret:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---- internal: state helpers (RBX = ctx) ---------------------------------------------------------------------
; ZF=0 and EAX = -PMH_R_RECORD when the session is closed (a record after the stop is 'record'; the stop reason stays)
pmh_closed:
    cmp  dword [rbx + pmh.state], PMH_S_CLOSED
    je   .closed
    xor  eax, eax                           ; ZF=1
    ret
.closed:
    mov  eax, -PMH_R_RECORD
    test eax, eax
    ret

; EAX = reason -> the session stops: CLOSED, reason kept, any copy abandoned, no READ or CONTROL left outstanding.
; Returns EAX = -reason. After the stop every host request refuses -33 (PMH_REQUEST, srcreview F2), turn and record
; give -record; the drains (out_take, ev_take), the releases and render/build_hex stay available for teardown.
pmh_fault:
    mov  dword [rbx + pmh.state], PMH_S_CLOSED
    mov  [rbx + pmh.reason], eax
    mov  dword [rbx + pmh.job_kind], 0
    and  dword [rbx + pmh.flags], ~(PMH_F_READ | PMH_F_CTL)
    neg  eax
    ret

; push an event: EDX = code, ECX = slot/arg32, R8 = arg64 (the caller guaranteed room)
pmh_event:
    mov  eax, [rbx + pmh.ev_len]
    inc  dword [rbx + pmh.ev_len]
    shl  eax, 4
    mov  [rbx + pmh.ev + rax], edx
    mov  [rbx + pmh.ev + rax + 4], ecx
    mov  [rbx + pmh.ev + rax + 8], r8
    mov  eax, edx
    ret

; move unframed console bytes to the front of rx
pmh_compact:
    mov  ecx, [rbx + pmh.rx_len]
    mov  esi, [rbx + pmh.rx_pos]
    sub  ecx, esi
    mov  [rbx + pmh.rx_len], ecx
    mov  dword [rbx + pmh.rx_pos], 0
    lea  rsi, [rbx + pmh.rx + rsi]
    lea  rdi, [rbx + pmh.rx]
    rep  movsb
    ret

; reserve a zeroed host->guest record: EDX = type, ECX = length -> RAX = its body (header written), or 0 when the
; out queue has no room (nothing changed). Clobbers RCX, RDX, RDI.
pmh_out:
    mov  eax, [rbx + pmh.out_len]
    lea  edi, [rax + rcx]
    cmp  edi, PMH_OUT_CAP
    ja   .full
    mov  [rbx + pmh.out_len], edi
    lea  rdi, [rbx + pmh.out + rax]
    push rdi
    push rcx
    xor  eax, eax
    rep  stosb
    pop  rcx
    pop  rdi
    mov  dword [rdi], PMH_MAGIC
    mov  [rdi + 4], dx
    mov  [rdi + 6], cx
    lea  rax, [rdi + 8]
    mov  rcx, [rbx + pmh.session]
    mov  [rax], rcx
    mov  rcx, [rbx + pmh.vm_gen]
    mov  [rax + 8], rcx
    ret
.full:
    xor  eax, eax
    ret

; ---- internal: the framer (PMR1 sec. 1: pre-HELLO skip <= 4096 B, no resynchronisation after HELLO) ------------
; -> EAX = length of the record now in ctx.rec, 0 when none is complete, or -reason
pmh_frame_next:
    mov  r8d, [rbx + pmh.rx_pos]
    mov  r9d, [rbx + pmh.rx_len]
    test dword [rbx + pmh.flags], PMH_F_SYNC
    jnz  .synced
    mov  rdx, 0x0020000131524D50            ; 'PMR1', HELLO, 32
    mov  ecx, r8d
.scan:
    lea  eax, [rcx + 8]
    cmp  eax, r9d
    ja   .none
    cmp  [rbx + pmh.rx + rcx], rdx
    je   .found
    inc  ecx
    jmp  .scan
.none:
    lea  eax, [r8 + 7]                      ; keep the last 7 bytes (a header may straddle the next chunk)
    cmp  r9d, eax
    jbe  .wait
    lea  ecx, [r9 - 7]
.found:
    mov  eax, ecx
    sub  eax, r8d
    add  [rbx + pmh.discarded], eax
    mov  [rbx + pmh.rx_pos], ecx
    mov  r8d, ecx
    cmp  dword [rbx + pmh.discarded], PMH_PRE_HELLO
    ja   .bad
    lea  eax, [rcx + 8]
    cmp  eax, r9d
    ja   .wait                              ; not found: only the tail is kept
    cmp  [rbx + pmh.rx + rcx], rdx
    jne  .wait
    or   dword [rbx + pmh.flags], PMH_F_SYNC
.synced:
    mov  eax, r9d
    sub  eax, r8d
    cmp  eax, 8
    jb   .wait
    cmp  dword [rbx + pmh.rx + r8], PMH_MAGIC
    jne  .bad
    movzx edi, word [rbx + pmh.rx + r8 + 4]
    call pmh_guest_size
    test ecx, ecx
    jz   .bad
    cmp  cx, [rbx + pmh.rx + r8 + 6]
    jne  .bad
    cmp  eax, ecx
    jb   .wait
    add  [rbx + pmh.rx_pos], ecx
    lea  rsi, [rbx + pmh.rx + r8]
    lea  rdi, [rbx + pmh.rec]
    mov  eax, ecx
    rep  movsb
    ret
.wait:
    xor  eax, eax
    ret
.bad:
    mov  eax, PMH_R_RECORD
    jmp  pmh_fault

; EDI = type -> ECX = the exact size of that GUEST record type, 0 for any other type. Clobbers RSI, RDX.
pmh_guest_size:
    lea  rsi, [rel pmh_sizes]
    xor  ecx, ecx
.next:
    movzx edx, word [rsi]
    test edx, edx
    jz   .out
    add  rsi, 4
    cmp  edx, edi
    jne  .next
    movzx ecx, word [rsi - 2]
.out:
    ret

; ---- internal: one record in ctx.rec (ECX = its length) -> outcome / PMH_PENDING / -reason ---------------------
pmh_record:
    lea  rbp, [rbx + pmh.rec + 8]           ; RBP = body (host copy)
    cmp  dword [rbx + pmh.rec], PMH_MAGIC
    jne  pmh_rec_bad
    movzx edi, word [rbx + pmh.rec + 4]
    mov  r12d, ecx
    call pmh_guest_size
    test ecx, ecx
    jz   pmh_rec_bad
    cmp  cx, [rbx + pmh.rec + 6]
    jne  pmh_rec_bad
    cmp  ecx, r12d
    jne  pmh_rec_bad
    mov  r12d, edi                          ; R12D = type
    mov  eax, [rbx + pmh.state]
    cmp  eax, PMH_S_WAIT_HELLO
    jne  .not_hello
    cmp  r12d, PMH_T_HELLO
    jne  pmh_rec_bad
    cmp  qword [rbp], 1                     ; proto 1, flags 0
    jne  pmh_rec_bad
    mov  rax, [rbp + 8]
    mov  [rbx + pmh.build], rax
    mov  rax, [rbp + 16]
    mov  [rbx + pmh.build + 8], rax
    mov  rax, [rbx + pmh.now]
    mov  [rbx + pmh.hello_time], rax
    mov  dword [rbx + pmh.state], PMH_S_WAIT_OPEN
    mov  edx, PMH_EV_HELLO
    jmp  pmh_ev0
.not_hello:
    cmp  eax, PMH_S_WAIT_OPEN
    jne  .opened
    cmp  r12d, PMH_T_READ
    je   pmh_read
    cmp  r12d, PMH_T_OPEN_REFUSE
    je   pmh_refuse
    cmp  r12d, PMH_T_OPEN_OK
    jne  pmh_rec_bad
    jmp  pmh_open_ok
.opened:
    cmp  r12d, PMH_T_FRAME
    je   pmh_frame
    cmp  r12d, PMH_T_PCM
    je   pmh_pcm
    cmp  r12d, PMH_T_READ
    je   pmh_read
    cmp  r12d, PMH_T_ACK
    je   pmh_ack
    cmp  r12d, PMH_T_EOF
    je   pmh_eof
    cmp  r12d, PMH_T_ERROR
    jne  pmh_rec_bad
    ; ERROR
    call pmh_ids
    jnz  pmh_gen_bad
    mov  eax, PMH_R_GUEST_ERROR
.guest_stop:
    cmp  dword [rbp + 20], 0
    jne  pmh_rec_bad
    mov  ecx, [rbp + 16]
    mov  [rbx + pmh.greason], ecx
    jmp  pmh_fault

pmh_refuse:
    call pmh_ids
    jnz  pmh_gen_bad
    mov  eax, PMH_R_OPEN_REFUSED
    jmp  pmh_record.guest_stop

pmh_rec_bad:
    mov  eax, PMH_R_RECORD
    jmp  pmh_fault
pmh_gen_bad:
    mov  eax, PMH_R_GENERATION
    jmp  pmh_fault
pmh_pts_bad:
    mov  eax, PMH_R_PTS
    jmp  pmh_fault

; an event with no argument: EDX = code
pmh_ev0:
    xor  ecx, ecx
    xor  r8d, r8d
    jmp  pmh_event

; body session/vm_gen (at RBP+0/+8) against the session -> ZF=1 when both match
pmh_ids:
    mov  rax, [rbp]
    cmp  rax, [rbx + pmh.session]
    jne  .out
    mov  rax, [rbp + 8]
    cmp  rax, [rbx + pmh.vm_gen]
.out:
    ret

; RAX = a record's epoch, EDI = budget index (0 FRAME, 1 PCM, 2 EOF, 3 READ) -> 1 current, 0 stale (dropped, the
; budget and the counter moved, nothing else), or the session stops 'record' (returns -1 to the caller's caller via
; the fault path: the caller checks for a negative EAX)
pmh_epoch:
    mov  rdx, [rbx + pmh.epoch]
    cmp  rax, rdx
    je   .current
    ja   .bad                               ; a future epoch
    test dword [rbx + pmh.flags], PMH_F_STALE
    jz   .bad
    dec  rdx
    cmp  rax, rdx
    jne  .bad                               ; two epochs back
    cmp  dword [rbx + pmh.allow + rdi*4], 0
    je   .bad                               ; beyond what was in flight at the SEEK
    dec  dword [rbx + pmh.allow + rdi*4]
    inc  qword [rbx + pmh.cnt_stale]
    xor  eax, eax
    ret
.current:
    mov  eax, 1
    ret
.bad:
    mov  eax, PMH_R_RECORD
    jmp  pmh_fault

; ---- OPEN_OK (WAIT_OPEN) -------------------------------------------------------------------------------------
pmh_open_ok:
    call pmh_ids
    jnz  pmh_gen_bad
    mov  eax, [rbp + 20]                    ; codec 1 VP9, 2 AV1
    dec  eax
    cmp  eax, 1
    ja   pmh_rec_bad
    cmp  dword [rbp + 48], 2                ; audio 0..2
    ja   pmh_rec_bad
    test dword [rbp + 52], ~1               ; flags: SCALED only
    jnz  pmh_rec_bad
    cmp  dword [rbp + 16], 0                ; stream
    je   pmh_rec_bad
    mov  eax, [rbp + 24]                    ; 0 < src_w <= max, 0 < src_h <= max
    dec  eax
    mov  ecx, [rbx + pmh.max_src_w]
    dec  ecx
    cmp  eax, ecx
    ja   pmh_rec_bad
    mov  eax, [rbp + 28]
    dec  eax
    mov  ecx, [rbx + pmh.max_src_h]
    dec  ecx
    cmp  eax, ecx
    ja   pmh_rec_bad
    mov  eax, [rbp + 32]                    ; 16 <= out_w <= 640, even
    test al, 1
    jnz  pmh_rec_bad
    sub  eax, 16
    cmp  eax, 640 - 16
    ja   pmh_rec_bad
    mov  eax, [rbp + 36]                    ; 16 <= out_h <= 360, even
    test al, 1
    jnz  pmh_rec_bad
    sub  eax, 16
    cmp  eax, 360 - 16
    ja   pmh_rec_bad
    mov  eax, [rbp + 40]                    ; fps num/den nonzero, num*max_den <= max_num*den (u32*u32 in u64)
    test eax, eax
    jz   pmh_rec_bad
    mov  ecx, [rbp + 44]
    test ecx, ecx
    jz   pmh_rec_bad
    mov  edx, [rbx + pmh.max_fps_den]
    imul rax, rdx
    mov  edx, [rbx + pmh.max_fps_num]
    imul rcx, rdx
    cmp  rax, rcx
    ja   pmh_rec_bad
    mov  eax, [rbp + 16]
    mov  [rbx + pmh.stream], eax
    mov  rax, [rbp + 32]
    mov  [rbx + pmh.out_w], rax             ; out_w, out_h
    mov  eax, [rbp + 48]
    mov  [rbx + pmh.audio], eax
    mov  dword [rbx + pmh.state], PMH_S_OPEN
    mov  edx, PMH_EV_OPEN
    jmp  pmh_ev0

; ---- READ (WAIT_OPEN probes and OPEN) ----------------------------------------------------------------------------
pmh_read:
    call pmh_ids
    jnz  pmh_gen_bad
    cmp  dword [rbp + 44], 0
    jne  pmh_rec_bad
    mov  rax, [rbp + 16]
    mov  edi, 3
    call pmh_epoch
    test eax, eax
    js   .out
    mov  r13d, eax                          ; 1 current, 0 stale
    test dword [rbx + pmh.flags], PMH_F_READ
    jnz  pmh_rec_bad
    mov  rax, [rbx + pmh.last_rid]
    inc  rax
    jz   pmh_rec_bad                        ; ids never wrap
    cmp  rax, [rbp + 24]
    jne  pmh_rec_bad
    mov  ecx, [rbp + 40]                    ; 0 < len <= 65536
    lea  edx, [rcx - 1]
    cmp  edx, PMH_READ_MAX - 1
    ja   pmh_rec_bad
    mov  rdx, [rbp + 32]
    cmp  rdx, [rbx + pmh.file_size]
    ja   pmh_rec_bad
    cmp  dword [rbx + pmh.state], PMH_S_WAIT_OPEN
    jne  .counted
    mov  edi, [rbx + pmh.probes]            ; F13: a bounded number of probe READs before OPEN_OK
    cmp  edi, [rbx + pmh.probe_max]
    jae  .deadline
    inc  dword [rbx + pmh.probes]
.counted:
    mov  [rbx + pmh.last_rid], rax
    mov  [rbx + pmh.read_rid], rax
    mov  [rbx + pmh.read_off], rdx
    mov  [rbx + pmh.read_len], ecx
    mov  rax, [rbp + 16]
    mov  [rbx + pmh.read_epoch], rax
    or   dword [rbx + pmh.flags], PMH_F_READ
    mov  edx, PMH_EV_STALE_READ
    sub  edx, r13d                          ; current -> PMH_EV_READ
    mov  r8, [rbx + pmh.read_rid]
    xor  ecx, ecx
    jmp  pmh_event
.deadline:
    mov  eax, PMH_R_OPEN_DEADLINE
    jmp  pmh_fault
.out:
    ret

; ---- ACK / EOF -----------------------------------------------------------------------------------------------
pmh_ack:
    call pmh_ids
    jnz  pmh_gen_bad
    test dword [rbx + pmh.flags], PMH_F_CTL
    jz   pmh_rec_bad
    mov  rax, [rbp + 24]
    cmp  rax, [rbx + pmh.ctl_seq]
    jne  pmh_rec_bad
    mov  rax, [rbp + 16]
    cmp  rax, [rbx + pmh.ctl_epoch]
    jne  pmh_rec_bad
    and  dword [rbx + pmh.flags], ~PMH_F_CTL
    cmp  dword [rbx + pmh.ctl_op], 3        ; SEEK: the guest is in the new epoch now
    jne  .ev
    and  dword [rbx + pmh.flags], ~PMH_F_STALE
.ev:
    mov  edx, PMH_EV_ACK
    jmp  pmh_ev0

pmh_eof:
    call pmh_ids
    jnz  pmh_gen_bad
    mov  rax, [rbp + 16]
    mov  edi, 2
    call pmh_epoch
    test eax, eax
    js   .out
    jz   pmh_stale
    test dword [rbx + pmh.flags], PMH_F_EOF
    jnz  pmh_rec_bad                        ; terminal for its epoch
    mov  rax, [rbp + 24]
    cmp  rax, [rbx + pmh.epoch_fseq]
    jne  pmh_rec_bad
    mov  rax, [rbp + 32]
    cmp  rax, [rbx + pmh.pframes]
    jne  pmh_rec_bad
    or   dword [rbx + pmh.flags], PMH_F_EOF
    mov  edx, PMH_EV_EOF
    jmp  pmh_ev0
.out:
    ret

pmh_stale:
    mov  edx, PMH_EV_STALE
    jmp  pmh_ev0

; ---- FRAME (sec. 4): every check on the host copy, before the window is read ------------------------------------
pmh_frame:
    cmp  dword [rbp], 0x00800001            ; version 1, size 128
    jne  pmh_rec_bad
    test dword [rbp + 4], ~7                ; SCALED | KEY | DISCONT
    jnz  pmh_rec_bad
    cmp  dword [rbp + 20], 0
    jne  pmh_rec_bad
    cmp  dword [rbp + 124], 0
    jne  pmh_rec_bad
    mov  rax, [rbp + 8]
    cmp  rax, [rbx + pmh.session]
    jne  pmh_gen_bad
    mov  rax, [rbp + 24]
    cmp  rax, [rbx + pmh.vm_gen]
    jne  pmh_gen_bad
    mov  eax, [rbp + 16]
    cmp  eax, [rbx + pmh.stream]
    jne  pmh_rec_bad
    mov  rax, [rbp + 32]
    xor  edi, edi
    call pmh_epoch
    test eax, eax
    js   .out
    jz   pmh_stale                          ; dropped before any copy; nothing else moves
    test dword [rbx + pmh.flags], PMH_F_EOF
    jnz  pmh_rec_bad
    test dword [rbx + pmh.flags], PMH_F_CREDIT
    jz   pmh_gen_bad
    mov  rax, [rbp + 48]                    ; grant id: the whole u64 is compared
    mov  ecx, [rbx + pmh.fc_slot]
    cmp  rax, rcx
    jne  pmh_gen_bad
    mov  rax, [rbp + 56]
    cmp  rax, [rbx + pmh.fc_gen]
    jne  pmh_gen_bad
    mov  rax, [rbp + 32]
    cmp  rax, [rbx + pmh.fc_epoch]
    jne  pmh_gen_bad
    mov  rax, [rbp + 64]                    ; width, height = the admitted output
    cmp  rax, [rbx + pmh.out_w]
    jne  pmh_rec_bad
    mov  eax, [rbp + 64]
    shl  eax, 2                             ; width <= 640: no wrap
    cmp  eax, [rbp + 72]
    jne  pmh_rec_bad
    cmp  dword [rbp + 76], PMH_BGRX
    jne  pmh_rec_bad
    cmp  dword [rbp + 80], PMH_FRAME_SLOT
    jne  pmh_rec_bad
    mov  ecx, [rbp + 68]
    imul eax, ecx                           ; stride*height <= 2560*360
    cmp  eax, [rbp + 84]
    jne  pmh_rec_bad
    cmp  eax, PMH_NATIVE_SLOT
    ja   pmh_rec_bad
    mov  rax, [rbp + 88]                    ; 0 <= pts < 2^47 (read as u64)
    mov  rcx, PMH_PTS_LIMIT
    cmp  rax, rcx
    jae  pmh_pts_bad
    mov  rax, [rbp + 96]                    ; 0 < duration < 2^32
    test rax, rax
    jz   pmh_pts_bad
    shr  rax, 32
    jnz  pmh_pts_bad
    mov  eax, [rbp + 104]
    mov  ecx, [rbp + 108]
    call pmh_tb_ok
    jnz  pmh_pts_bad
    test dword [rbx + pmh.flags], PMH_F_TB
    jz   .set_tb
    cmp  eax, [rbx + pmh.tb_num]
    jne  pmh_pts_bad
    cmp  ecx, [rbx + pmh.tb_den]
    jne  pmh_pts_bad
    jmp  .tb_done
.set_tb:
    mov  [rbx + pmh.tb_num], eax
    mov  [rbx + pmh.tb_den], ecx
    or   dword [rbx + pmh.flags], PMH_F_TB
.tb_done:
    test dword [rbx + pmh.flags], PMH_F_LPTS
    jz   .pts_ok
    mov  rax, [rbp + 88]
    cmp  rax, [rbx + pmh.last_pts]
    jbe  pmh_pts_bad
.pts_ok:
    mov  rax, [rbp + 40]
    cmp  rax, [rbx + pmh.last_fseq]
    jbe  pmh_rec_bad
    mov  rax, [rbx + pmh.fcompl]
    inc  rax
    jz   pmh_rec_bad                        ; never wraps
    cmp  rax, [rbp + 112]
    jne  pmh_rec_bad
    test dword [rbp + 4], 4
    jz   .admit
    test dword [rbx + pmh.flags], PMH_F_FIRST
    jz   pmh_rec_bad                        ; DISCONT only on an epoch's first frame
.admit:
    ; the credit is spent either way; the sequences move now (as the model)
    and  dword [rbx + pmh.flags], ~PMH_F_CREDIT
    mov  [rbx + pmh.fcompl], rax
    mov  rax, [rbp + 40]
    mov  [rbx + pmh.last_fseq], rax
    mov  [rbx + pmh.epoch_fseq], rax
    mov  rax, [rbp + 88]
    mov  [rbx + pmh.job_pts], rax
    mov  ecx, [rbx + pmh.fc_native]
    mov  [rbx + pmh.job_slot], ecx
    mov  rax, [rbx + pmh.native + rcx*8]
    mov  [rbx + pmh.job_dst], rax
    mov  eax, [rbx + pmh.fc_slot]
    shl  eax, 20                            ; slot * 1 MiB: the only window address of a frame
    mov  [rbx + pmh.job_src], rax
    mov  eax, [rbp + 84]
    mov  ecx, [rbp + 120]
    mov  edx, 128
    mov  r9d, 120
    mov  r8d, PMH_T_FRAME
    jmp  pmh_stage
.out:
    ret

; ECX:EAX = tb_den:tb_num -> ZF=1 when 1 <= num <= den <= 2^20
pmh_tb_ok:
    test eax, eax
    jz   .no
    cmp  eax, ecx
    ja   .no
    cmp  ecx, PMH_TB_LIMIT
    ja   .no
    cmp  eax, eax
    ret
.no:
    test esp, esp                           ; ZF=0 (RSP is never 0)
    ret

; stage a copy job: R8D = kind, EAX = payload length, ECX = the guest's CRC, RBP+.. = descriptor (EDX bytes, CRC at
; R9 inside it). The CRC state starts over the descriptor with its CRC word zeroed (host copy), and carries on over
; the payload as the copy turns copy it.
pmh_stage:
    mov  [rbx + pmh.job_kind], r8d
    mov  [rbx + pmh.job_len], eax
    mov  dword [rbx + pmh.job_done], 0
    mov  [rbx + pmh.job_want], ecx
    mov  rax, [rbx + pmh.epoch]
    mov  [rbx + pmh.job_epoch], rax
    lea  rdi, [rbx + pmh.job_desc]
    mov  rsi, rbp
    cmp  r8d, PMH_T_PCM
    jne  .copy
    add  rsi, 24                            ; PCM: the CRC covers the 96 B descriptor, not the grant prefix
.copy:
    mov  ecx, edx
    rep  movsb
    mov  dword [rbx + pmh.job_desc + r9], 0
    xor  edi, edi
    lea  rsi, [rbx + pmh.job_desc]
    call crc32_update
    mov  [rbx + pmh.job_crc], eax
    mov  eax, [rbp + 120]                   ; restore the guest's CRC in the kept descriptor copy
    cmp  dword [rbx + pmh.job_kind], PMH_T_PCM
    jne  .keep
    mov  eax, [rbp + 24 + 80]
.keep:
    mov  [rbx + pmh.job_desc + r9], eax
    mov  eax, PMH_PENDING
    ret

; ---- PCM (sec. 5) ------------------------------------------------------------------------------------------
pmh_pcm:
    cmp  dword [rbp + 4], 0                 ; prefix reserved words
    jne  pmh_rec_bad
    cmp  dword [rbp + 20], 0
    jne  pmh_rec_bad
    cmp  dword [rbp + 24], 0x00600001       ; version 1, size 96
    jne  pmh_rec_bad
    cmp  dword [rbp + 28], 0                ; no PCM flag is defined
    jne  pmh_rec_bad
    cmp  word [rbp + 86], 0
    jne  pmh_rec_bad
    cmp  dword [rbp + 116], 0
    jne  pmh_rec_bad
    mov  rax, [rbp + 32]
    cmp  rax, [rbx + pmh.session]
    jne  pmh_gen_bad
    mov  rax, [rbp + 40]
    cmp  rax, [rbx + pmh.vm_gen]
    jne  pmh_gen_bad
    mov  eax, [rbp + 72]
    cmp  eax, [rbx + pmh.stream]
    jne  pmh_rec_bad
    mov  rax, [rbp + 48]
    mov  edi, 1
    call pmh_epoch
    test eax, eax
    js   .out
    jz   pmh_stale
    test dword [rbx + pmh.flags], PMH_F_EOF
    jnz  pmh_rec_bad
    mov  ecx, [rbp]                         ; packet index < 16, credited, generation, epoch, capacity
    cmp  ecx, PMH_PCM_SLOTS
    jae  pmh_gen_bad
    bt   dword [rbx + pmh.pcm_mask], ecx
    jnc  pmh_gen_bad
    bt   dword [rbx + pmh.pcm_held], ecx    ; srcreview F1: never into a packet the mixer still holds
    jc   pmh_gen_bad
    mov  rax, [rbp + 8]
    cmp  rax, [rbx + pmh.pc_gen + rcx*8]
    jne  pmh_gen_bad
    mov  rax, [rbp + 48]
    cmp  rax, [rbx + pmh.pc_epoch + rcx*8]
    jne  pmh_gen_bad
    cmp  dword [rbp + 16], PMH_PCM_SLOT
    jne  pmh_gen_bad
    cmp  dword [rbp + 76], 1                ; S16LE at the host's rate and channel count
    jne  pmh_rec_bad
    mov  eax, [rbp + 80]
    cmp  eax, [rbx + pmh.pcm_rate]
    jne  pmh_rec_bad
    movzx eax, word [rbp + 84]
    cmp  eax, [rbx + pmh.pcm_ch]
    jne  pmh_rec_bad
    mov  eax, [rbp + 88]                    ; 0 < frames <= 4096 BEFORE frames*ch*2
    lea  edx, [rax - 1]
    cmp  edx, PMH_PCM_SLOT - 1
    ja   pmh_rec_bad
    imul eax, [rbx + pmh.pcm_ch]
    add  eax, eax
    cmp  eax, [rbp + 92]
    jne  pmh_rec_bad
    cmp  eax, PMH_PCM_SLOT
    ja   pmh_rec_bad
    cmp  dword [rbp + 108], 1               ; timebase 1/rate
    jne  pmh_pts_bad
    mov  eax, [rbp + 112]
    cmp  eax, [rbx + pmh.pcm_rate]
    jne  pmh_pts_bad
    xor  eax, eax                           ; packet_seq: 0 first, then +1 (never wraps)
    test dword [rbx + pmh.flags], PMH_F_PSEQ
    jz   .seq
    mov  rax, [rbx + pmh.pseq]
    inc  rax
    jz   pmh_rec_bad
.seq:
    cmp  rax, [rbp + 56]
    jne  pmh_rec_bad
    mov  rax, [rbx + pmh.pcompl]
    inc  rax
    jz   pmh_rec_bad
    cmp  rax, [rbp + 96]
    jne  pmh_rec_bad
    mov  rdx, PMH_PTS_LIMIT                 ; first_pts < 2^47 and first_pts + frames < 2^47
    mov  rax, [rbp + 64]
    cmp  rax, rdx
    jae  pmh_pts_bad
    mov  r10d, [rbp + 88]
    add  rax, r10
    cmp  rax, rdx
    jae  pmh_pts_bad
    test dword [rbx + pmh.flags], PMH_F_PNEXT
    jz   .admit
    mov  rdx, [rbp + 64]
    cmp  rdx, [rbx + pmh.pnext]
    jne  pmh_pts_bad
.admit:
    mov  [rbx + pmh.job_pts], rax           ; first_pts + frames
    mov  [rbx + pmh.job_frames], r10
    mov  ecx, [rbp]
    btr  dword [rbx + pmh.pcm_mask], ecx    ; the credit is spent either way
    mov  rax, [rbp + 96]
    mov  [rbx + pmh.pcompl], rax
    mov  rax, [rbp + 56]
    mov  [rbx + pmh.pseq], rax
    or   dword [rbx + pmh.flags], PMH_F_PSEQ
    mov  [rbx + pmh.job_slot], ecx
    mov  eax, ecx
    shl  eax, 12
    mov  rdx, [rbx + pmh.pcmbuf]
    add  rdx, rax
    mov  [rbx + pmh.job_dst], rdx
    add  eax, PMH_PCM_BASE
    mov  [rbx + pmh.job_src], rax
    mov  eax, [rbp + 92]
    mov  ecx, [rbp + 24 + 80]
    mov  edx, 96
    mov  r9d, 80
    mov  r8d, PMH_T_PCM
    jmp  pmh_stage
.out:
    ret

; ---- the copy turn ---------------------------------------------------------------------------------------------
; one step: at most `quantum` bytes from the window slot into the host copy, the CRC carried over the HOST bytes;
; at the end the publication revalidates the epoch, then checks the CRC.
pmh_copy_step:
    mov  r12d, [rbx + pmh.job_done]
    mov  r13d, [rbx + pmh.job_len]
    sub  r13d, r12d
    cmp  r13d, [rbx + pmh.quantum]
    jbe  .n
    mov  r13d, [rbx + pmh.quantum]
.n:
    mov  rsi, [rbx + pmh.window]            ; window + slot/packet offset + done: host-computed only
    add  rsi, [rbx + pmh.job_src]
    add  rsi, r12
    mov  r14, [rbx + pmh.job_dst]
    add  r14, r12
    mov  rdi, r14
    mov  ecx, r13d
    rep  movsb                              ; the one read of these window bytes
    mov  edi, [rbx + pmh.job_crc]
    mov  rsi, r14
    mov  edx, r13d
    call crc32_update                       ; over the host copy
    mov  [rbx + pmh.job_crc], eax
    cmp  dword [rbx + pmh.job_kind], PMH_T_FRAME
    jne  .advance
    mov  ecx, r13d                          ; F6: X = 0xFF in the host copy, after the CRC
    shr  ecx, 2
    jz   .advance
    lea  rdi, [r14 + 3]
.x:
    mov  byte [rdi], 0xFF
    add  rdi, 4
    dec  ecx
    jnz  .x
.advance:
    add  r12d, r13d
    mov  [rbx + pmh.job_done], r12d
    cmp  r12d, [rbx + pmh.job_len]
    jb   .more
    ; publication
    mov  ecx, [rbx + pmh.job_slot]
    mov  edx, [rbx + pmh.job_kind]
    mov  dword [rbx + pmh.job_kind], 0
    cmp  edx, PMH_T_PCM
    je   .pcm
    mov  rax, [rbx + pmh.job_epoch]
    cmp  rax, [rbx + pmh.epoch]
    jne  .revoked
    mov  eax, [rbx + pmh.job_crc]
    cmp  eax, [rbx + pmh.job_want]
    jne  .drop
    mov  dword [rbx + pmh.crc_run], 0
    mov  rax, [rbx + pmh.job_pts]
    mov  [rbx + pmh.last_pts], rax
    or   dword [rbx + pmh.flags], PMH_F_LPTS
    and  dword [rbx + pmh.flags], ~PMH_F_FIRST
    inc  qword [rbx + pmh.cnt_frames]
    mov  byte [rbx + pmh.nstate + rcx], 2   ; WRITING -> held (READY)
    mov  eax, ecx
    shl  eax, 7
    lea  rdi, [rbx + pmh.pub_desc + rax]
    lea  rsi, [rbx + pmh.job_desc]
    push rcx
    mov  ecx, 128
    rep  movsb
    pop  rcx
    mov  edx, PMH_EV_FRAME
    mov  r8, rcx
    jmp  pmh_event
.revoked:
    mov  byte [rbx + pmh.nstate + rcx], 0   ; revoked by the SEEK: the WRITING slot is freed by identity
    mov  edx, PMH_EV_REVOKED
    jmp  .ev
.drop:
    mov  byte [rbx + pmh.nstate + rcx], 0   ; the WRITING slot is freed by identity
    inc  qword [rbx + pmh.cnt_crc]
    inc  dword [rbx + pmh.crc_run]
    cmp  dword [rbx + pmh.crc_run], PMH_CRC_RUN
    jae  .crc_stop
    mov  edx, PMH_EV_CRC_DROP
.ev:
    mov  r8, rcx
    jmp  pmh_event
.pcm:
    mov  rax, [rbx + pmh.job_epoch]         ; a SEEK during the copy revokes the packet too (nothing published)
    cmp  rax, [rbx + pmh.epoch]
    mov  edx, PMH_EV_REVOKED
    jne  .ev
    mov  eax, [rbx + pmh.job_crc]
    cmp  eax, [rbx + pmh.job_want]
    jne  .pcm_bad
    mov  rax, [rbx + pmh.job_pts]
    mov  [rbx + pmh.pnext], rax
    or   dword [rbx + pmh.flags], PMH_F_PNEXT
    mov  rax, [rbx + pmh.job_frames]
    add  [rbx + pmh.pframes], rax
    inc  qword [rbx + pmh.cnt_pcm]
    bts  dword [rbx + pmh.pcm_held], ecx
    imul eax, ecx, 96
    lea  rdi, [rbx + pmh.pcm_desc + rax]
    lea  rsi, [rbx + pmh.job_desc]
    push rcx
    mov  ecx, 96
    rep  movsb
    pop  rcx
    mov  edx, PMH_EV_PCM
    mov  r8, rcx
    jmp  pmh_event
.pcm_bad:
    inc  qword [rbx + pmh.cnt_crc]          ; audio is never dropped silently
.crc_stop:
    mov  eax, PMH_R_CRC
    jmp  pmh_fault
.more:
    xor  eax, eax
    ret

; ---- host -> guest -------------------------------------------------------------------------------------------
; pmr1h_open_record(RDI=ctx) -> 0 / -32
pmr1h_open_record:
    PMH_REQUEST
    mov  edx, PMH_T_OPEN
    mov  ecx, 64
    call pmh_out
    test rax, rax
    jz   pmh_busy
    mov  rcx, [rbx + pmh.file_size]
    mov  [rax + 16], rcx
    mov  dword [rax + 24], 640
    mov  dword [rax + 28], 360
    mov  rcx, [rbx + pmh.max_src_w]         ; max_src_w, max_src_h
    mov  [rax + 32], rcx
    mov  rcx, [rbx + pmh.max_fps_num]       ; max_fps_num, max_fps_den
    mov  [rax + 40], rcx
    mov  ecx, [rbx + pmh.pcm_rate]
    mov  [rax + 48], ecx
    mov  ecx, [rbx + pmh.pcm_ch]
    mov  [rax + 52], cx
    mov  word [rax + 54], 1                 ; S16LE
    xor  eax, eax
    jmp  pmh_ret

pmh_busy:
    mov  eax, -PMH_BUSY
    jmp  pmh_ret
pmh_inval:
    mov  eax, -PMH_INVAL
    jmp  pmh_ret

; ZF=1 when credits may be issued: OPEN, not paused, no unacknowledged CONTROL
pmh_may_credit:
    cmp  dword [rbx + pmh.state], PMH_S_OPEN
    jne  .out
    test dword [rbx + pmh.flags], PMH_F_PAUSED | PMH_F_CTL
.out:
    ret

; pmr1h_grant_frame(RDI=ctx) -> 1 granted, 0 none possible, -32, -33 after the stop, -reason. At most one frame
; credit, and only after a native WRITING slot is reserved by identity (F12): FRONT + READY + WRITING <= 3.
pmr1h_grant_frame:
    PMH_REQUEST
    xor  eax, eax
    call pmh_may_credit
    jnz  pmh_ret
    test dword [rbx + pmh.flags], PMH_F_CREDIT
    jnz  .none
    xor  r12d, r12d                         ; a free native slot
.free:
    cmp  byte [rbx + pmh.nstate + r12], 0
    je   .slot
    inc  r12d
    cmp  r12d, 3
    jb   .free
.none:
    xor  eax, eax
    jmp  pmh_ret
.slot:
    xor  r13d, r13d                         ; the window slot with the lowest generation (first on a tie)
    mov  ecx, 1
.min:
    mov  rax, [rbx + pmh.fgens + rcx*8]
    cmp  rax, [rbx + pmh.fgens + r13*8]
    cmovb r13d, ecx
    inc  ecx
    cmp  ecx, 3
    jb   .min
    mov  rax, [rbx + pmh.fgens + r13*8]
    inc  rax
    jz   .exhausted
    mov  edx, PMH_T_CREDIT
    mov  ecx, 48
    call pmh_out
    test rax, rax
    jz   pmh_busy
    inc  qword [rbx + pmh.fgens + r13*8]
    mov  rcx, [rbx + pmh.fgens + r13*8]
    mov  byte [rbx + pmh.nstate + r12], 1   ; the native WRITING reservation
    mov  [rbx + pmh.fc_native], r12d
    mov  [rbx + pmh.fc_slot], r13d
    mov  [rbx + pmh.fc_gen], rcx
    mov  [rax + 32], rcx
    mov  rcx, [rbx + pmh.epoch]
    mov  [rbx + pmh.fc_epoch], rcx
    mov  [rax + 16], rcx
    mov  dword [rax + 24], 1                ; CREDIT_FRAME
    mov  [rax + 28], r13d
    or   dword [rbx + pmh.flags], PMH_F_CREDIT
    mov  eax, 1
    jmp  pmh_ret
.exhausted:
    mov  eax, PMH_R_GENERATION
    call pmh_fault
    jmp  pmh_ret

; pmr1h_grant_pcm(RDI=ctx, ESI=index) -> 1, -32, -33 (index out, credit already out, packet in flight or still held,
; or no credit allowed now), -reason
pmr1h_grant_pcm:
    PMH_REQUEST
    mov  r12d, esi
    cmp  r12d, PMH_PCM_SLOTS
    jae  pmh_inval
    bt   dword [rbx + pmh.pcm_mask], r12d
    jc   pmh_inval
    bt   dword [rbx + pmh.pcm_held], r12d
    jc   pmh_inval
    cmp  dword [rbx + pmh.job_kind], PMH_T_PCM   ; srcreview F1: the packet whose copy is pending is neither credited
    jne  .free                                  ; nor held, but in flight: no second credit for it
    cmp  [rbx + pmh.job_slot], r12d
    je   pmh_inval
.free:
    call pmh_may_credit
    jnz  pmh_inval
    mov  rax, [rbx + pmh.pgens + r12*8]
    inc  rax
    jz   .exhausted
    mov  edx, PMH_T_CREDIT
    mov  ecx, 48
    call pmh_out
    test rax, rax
    jz   pmh_busy
    inc  qword [rbx + pmh.pgens + r12*8]
    mov  rcx, [rbx + pmh.pgens + r12*8]
    mov  [rbx + pmh.pc_gen + r12*8], rcx
    mov  [rax + 32], rcx
    mov  rcx, [rbx + pmh.epoch]
    mov  [rbx + pmh.pc_epoch + r12*8], rcx
    mov  [rax + 16], rcx
    mov  dword [rax + 24], 2                ; CREDIT_PCM
    mov  [rax + 28], r12d
    bts  dword [rbx + pmh.pcm_mask], r12d
    mov  eax, 1
    jmp  pmh_ret
.exhausted:
    mov  eax, PMH_R_GENERATION
    call pmh_fault
    jmp  pmh_ret

; pmr1h_native_release(RDI=ctx, ESI=native slot) -> 0, or -33 unless that slot is held (srcreview F12: release by
; identity; a WRITING slot is freed only by its credit's spend or revocation)
pmr1h_native_release:
    PMH_ENTER
    mov  esi, esi
    cmp  esi, 3
    jae  pmh_inval
    cmp  byte [rbx + pmh.nstate + rsi], 2
    jne  pmh_inval
    mov  byte [rbx + pmh.nstate + rsi], 0
    xor  eax, eax
    jmp  pmh_ret

; pmr1h_pcm_release(RDI=ctx, ESI=index) -> 0, or -33 unless that packet is held
pmr1h_pcm_release:
    PMH_ENTER
    cmp  esi, PMH_PCM_SLOTS
    jae  pmh_inval
    btr  dword [rbx + pmh.pcm_held], esi
    jnc  pmh_inval
    xor  eax, eax
    jmp  pmh_ret

; pmr1h_control(RDI=ctx, ESI=op 1 PLAY 2 PAUSE 3 SEEK 4 STOP, RDX=seek_pts, ECX=seek_tb_num, R8D=seek_tb_den)
; -> 0, -32, -33 (a control unacknowledged, an unknown op, or a SEEK target outside the native bounds)
pmr1h_control:
    PMH_REQUEST
    test dword [rbx + pmh.flags], PMH_F_CTL
    jnz  pmh_inval
    lea  eax, [rsi - 1]
    cmp  eax, 3
    ja   pmh_inval
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    mov  r15d, r8d
    cmp  r12d, 3
    jne  .checked
    mov  rax, PMH_PTS_LIMIT
    cmp  r13, rax
    jae  pmh_inval
    mov  eax, r14d
    mov  ecx, r15d
    call pmh_tb_ok
    jnz  pmh_inval
    mov  rax, [rbx + pmh.epoch]
    inc  rax
    jz   pmh_inval
.checked:
    mov  rax, [rbx + pmh.ctl_count]
    inc  rax
    jz   pmh_inval
    mov  edx, PMH_T_CONTROL
    mov  ecx, 64
    call pmh_out
    test rax, rax
    jz   pmh_busy
    mov  rbp, rax
    inc  qword [rbx + pmh.ctl_count]
    cmp  r12d, 3
    jne  .mode
    ; SEEK: fix the stale budget at the revocation, raise the epoch, revoke every credit
    mov  eax, [rbx + pmh.flags]
    mov  ecx, eax
    shr  ecx, 8                             ; PMH_F_CREDIT -> bit 0
    and  ecx, 1
    mov  [rbx + pmh.allow], ecx
    popcnt ecx, [rbx + pmh.pcm_mask]
    mov  [rbx + pmh.allow + 4], ecx
    mov  dword [rbx + pmh.allow + 8], 1
    mov  ecx, eax
    shr  ecx, 9                             ; PMH_F_READ -> bit 0
    and  ecx, 1
    xor  ecx, 1
    mov  [rbx + pmh.allow + 12], ecx
    test eax, PMH_F_CREDIT
    jz   .revoked
    mov  ecx, [rbx + pmh.fc_native]
    mov  byte [rbx + pmh.nstate + rcx], 0   ; the reserved WRITING slot, by identity
.revoked:
    and  eax, ~(PMH_F_CREDIT | PMH_F_PNEXT | PMH_F_PSEQ | PMH_F_LPTS | PMH_F_EOF)
    or   eax, PMH_F_STALE | PMH_F_FIRST
    mov  [rbx + pmh.flags], eax
    inc  qword [rbx + pmh.epoch]
    xor  eax, eax
    mov  [rbx + pmh.pcm_mask], eax
    mov  [rbx + pmh.pframes], rax
    mov  [rbx + pmh.fcompl], rax
    mov  [rbx + pmh.pcompl], rax
    mov  [rbx + pmh.epoch_fseq], rax
.mode:
    cmp  r12d, 1
    jne  .stop
    and  dword [rbx + pmh.flags], ~PMH_F_PAUSED
.stop:
    cmp  r12d, 2
    je   .pause
    cmp  r12d, 4
    jne  .record
.pause:
    or   dword [rbx + pmh.flags], PMH_F_PAUSED
.record:
    mov  rax, [rbx + pmh.ctl_count]
    mov  [rbx + pmh.ctl_seq], rax
    mov  [rbp + 24], rax
    mov  rax, [rbx + pmh.epoch]
    mov  [rbx + pmh.ctl_epoch], rax
    mov  [rbp + 16], rax
    mov  [rbx + pmh.ctl_op], r12d
    or   dword [rbx + pmh.flags], PMH_F_CTL
    mov  [rbp + 32], r12d
    mov  [rbp + 40], r13
    mov  [rbp + 48], r14d
    mov  [rbp + 52], r15d
    xor  eax, eax
    jmp  pmh_ret

; pmr1h_clock(RDI=ctx, ESI=state 1..9, EDX=tb_num, ECX=tb_den, R8=played_lo, R9=played_hi) -> 0, -32, -33, -reason
pmr1h_clock:
    PMH_REQUEST
    cmp  dword [rbx + pmh.state], PMH_S_OPEN
    jne  pmh_inval
    lea  eax, [rsi - 1]
    cmp  eax, 8
    ja   pmh_inval
    mov  r12d, esi
    mov  eax, edx
    mov  r13d, edx
    mov  r14d, ecx
    call pmh_tb_ok
    jnz  pmh_inval
    cmp  r8, r9
    ja   pmh_inval
    mov  rax, PMH_PTS_LIMIT
    cmp  r9, rax
    jae  pmh_inval
    mov  rax, [rbx + pmh.clock_seq]
    inc  rax
    jz   .exhausted
    mov  r15, r8
    mov  rbp, r9
    mov  edx, PMH_T_CLOCK
    mov  ecx, 72
    call pmh_out
    test rax, rax
    jz   pmh_busy
    inc  qword [rbx + pmh.clock_seq]
    mov  rcx, [rbx + pmh.epoch]
    mov  [rax + 16], rcx
    mov  rcx, [rbx + pmh.clock_seq]
    mov  [rax + 24], rcx
    mov  ecx, [rbx + pmh.stream]
    mov  [rax + 32], ecx
    mov  [rax + 36], r12d
    mov  [rax + 40], r13d
    mov  [rax + 44], r14d
    mov  [rax + 48], r15
    mov  [rax + 56], rbp
    xor  eax, eax
    jmp  pmh_ret
.exhausted:
    mov  eax, PMH_R_RECORD
    call pmh_fault
    jmp  pmh_ret

; pmr1h_data_reply(RDI=ctx, ESI=status, RDX=payload (host memory: the media owner's VFS buffer), ECX=len) ->
; bytes written to the ingress area, -32, -33. The payload is served as at most min(len, file_size - offset); its CRC
; is taken over the HOST buffer (the ingress area is never read back). A READ of a past epoch is CANCELLED, empty.
pmr1h_data_reply:
    PMH_REQUEST
    test dword [rbx + pmh.flags], PMH_F_READ
    jz   pmh_inval
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    mov  eax, [rbx + pmh.read_len]
    cmp  r14d, eax
    ja   pmh_inval
    mov  rax, [rbx + pmh.file_size]
    sub  rax, [rbx + pmh.read_off]          ; offset <= file_size (READ rule)
    cmp  r14, rax
    ja   pmh_inval
    mov  edx, PMH_T_DATA
    mov  ecx, 64
    call pmh_out
    test rax, rax
    jz   pmh_busy
    mov  rbp, rax
    and  dword [rbx + pmh.flags], ~PMH_F_READ
    mov  rax, [rbx + pmh.read_epoch]
    cmp  rax, [rbx + pmh.epoch]
    je   .serve
    mov  r12d, 3                            ; DATA_CANCELLED
    xor  r14d, r14d
.serve:
    mov  rdi, [rbx + pmh.window]
    add  rdi, PMH_INGRESS
    mov  rsi, r13
    mov  ecx, r14d
    rep  movsb
    xor  edi, edi
    mov  rsi, r13
    mov  edx, r14d
    call crc32_update
    mov  [rbp + 48], eax
    mov  rax, [rbx + pmh.read_epoch]
    mov  [rbp + 16], rax
    mov  rax, [rbx + pmh.read_rid]
    mov  [rbp + 24], rax
    mov  rax, [rbx + pmh.read_off]
    mov  [rbp + 32], rax
    mov  [rbp + 40], r14d
    mov  [rbp + 44], r12d
    mov  eax, r14d
    jmp  pmh_ret

; ---- visibility (sec. 7, rc-sec S5): numbers and fixed strings only, never guest text ----------------------------
; pmr1h_render(RDI=ctx, RSI=buf >= 96 B) -> length of "media.guest reason=<r>" [" guest=<name|unknown(n)>"]
pmr1h_render:
    PMH_ENTER
    mov  rdi, rsi
    mov  r12, rsi
    lea  rsi, [rel pmh_str_prefix]
    mov  ecx, pmh_str_prefix_len
    rep  movsb
    mov  eax, [rbx + pmh.reason]
    lea  rsi, [rel pmh_host_reasons]
    mov  ecx, PMH_R_PROFILE
    call pmh_name
    mov  eax, [rbx + pmh.reason]
    sub  eax, PMH_R_OPEN_REFUSED
    cmp  eax, 1
    ja   .len
    lea  rsi, [rel pmh_str_guest]
    mov  ecx, pmh_str_guest_len
    rep  movsb
    mov  eax, [rbx + pmh.greason]
    lea  rsi, [rel pmh_guest_reasons]
    mov  ecx, 8
    call pmh_name
.len:
    mov  rax, rdi
    sub  rax, r12
    jmp  pmh_ret

; EAX = code, RSI = a table of ECX rel32 entries (code 1..ECX) each pointing at {u8 len, text}; RDI = output.
; A known code writes its name; any other writes "unknown(<decimal>)".
pmh_name:
    lea  edx, [rax - 1]
    cmp  edx, ecx
    jae  .unknown
    movsxd rdx, dword [rsi + rdx*4]
    add  rsi, rdx
    movzx ecx, byte [rsi]
    inc  rsi
    rep  movsb
    ret
.unknown:
    mov  r8d, eax
    lea  rsi, [rel pmh_str_unknown]
    mov  ecx, 8
    rep  movsb
    mov  eax, r8d
    xor  ecx, ecx
    mov  r9d, 10
.div:
    xor  edx, edx
    div  r9d
    add  dl, '0'
    push rdx
    inc  ecx
    test eax, eax
    jnz  .div
.out:
    pop  rax
    stosb
    dec  ecx
    jnz  .out
    mov  al, ')'
    stosb
    ret

; pmr1h_build_hex(RDI=ctx, RSI=buf >= 32 B) -> 32: HELLO build[16] as lowercase hex (never raw)
pmr1h_build_hex:
    PMH_ENTER
    mov  rdi, rsi
    lea  rsi, [rbx + pmh.build]
    lea  r8, [rel pmh_hex]
    mov  ecx, 16
.byte:
    movzx eax, byte [rsi]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    mov  al, [r8 + rax]
    stosb
    mov  al, [r8 + rdx]
    stosb
    inc  rsi
    dec  ecx
    jnz  .byte
    mov  eax, 32
    jmp  pmh_ret

; ---- tables: no absolute pointers (org-0 image): sizes by value, strings by rel32 offset -----------------------
pmh_sizes:
    dw PMH_T_HELLO, 32, PMH_T_OPEN_OK, 64, PMH_T_OPEN_REFUSE, 32, PMH_T_FRAME, 136, PMH_T_PCM, 128
    dw PMH_T_READ, 56, PMH_T_ACK, 40, PMH_T_EOF, 48, PMH_T_ERROR, 32, 0, 0
pmh_hex:
    db "0123456789abcdef"
pmh_str_prefix:
    db "media.guest reason="
pmh_str_prefix_len equ $ - pmh_str_prefix
pmh_str_guest:
    db " guest="
pmh_str_guest_len equ $ - pmh_str_guest
pmh_str_unknown:
    db "unknown("
%macro PMH_STR 1
    db %%end - %%text
%%text:
    db %1
%%end:
%endmacro
pmh_host_reasons:
    dd pmh_hr1 - pmh_host_reasons, pmh_hr2 - pmh_host_reasons, pmh_hr3 - pmh_host_reasons, pmh_hr4 - pmh_host_reasons
    dd pmh_hr5 - pmh_host_reasons, pmh_hr6 - pmh_host_reasons, pmh_hr7 - pmh_host_reasons, pmh_hr8 - pmh_host_reasons
pmh_hr1: PMH_STR "record"
pmh_hr2: PMH_STR "generation"
pmh_hr3: PMH_STR "pts"
pmh_hr4: PMH_STR "crc"
pmh_hr5: PMH_STR "open_refused"
pmh_hr6: PMH_STR "guest_error"
pmh_hr7: PMH_STR "open_deadline"
pmh_hr8: PMH_STR "profile"
pmh_guest_reasons:
    dd pmh_gr1 - pmh_guest_reasons, pmh_gr2 - pmh_guest_reasons, pmh_gr3 - pmh_guest_reasons
    dd pmh_gr4 - pmh_guest_reasons, pmh_gr5 - pmh_guest_reasons, pmh_gr6 - pmh_guest_reasons
    dd pmh_gr7 - pmh_guest_reasons, pmh_gr8 - pmh_guest_reasons
pmh_gr1: PMH_STR "codec_policy"
pmh_gr2: PMH_STR "source_too_large"
pmh_gr3: PMH_STR "container"
pmh_gr4: PMH_STR "decode"
pmh_gr5: PMH_STR "io"
pmh_gr6: PMH_STR "protocol"
pmh_gr7: PMH_STR "internal"
pmh_gr8: PMH_STR "audio_format"
