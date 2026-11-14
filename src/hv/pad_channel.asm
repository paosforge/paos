;; MODULE hv/pad_channel
;; LAYER 5
;; EXPORTS padc_render_stat, padc_prepare, padc_cmdline_text, padc_send, padc_receive, padc_uart_byte, padc_pump, padc_state_zero, padc_clock, padc_bound, padc_phase
;; IMPORTS hv/audio_domain, hv/audio_sound, hv/audio_playback, hv/pci_assign, hv/vmx, hv/vm_profile, core/csprng, boot/serial
;; CAPS extension
;; OWNER saga:audio
; RCQ-36 V1: the VM owner's private PAD1 channel (audio_domain_native.md).
;
; A profile selecting VP_DEV_PADCHAN gives the guest's virtio console (hvc0)
; to the PAD1 service and nothing else: the kernel console stays on ttyS0, the
; host injects no text lines (hv_vcon_rx_line refuses while bound), and every
; completed TX snapshot goes to padn_receive instead of the CDP, surface or
; text receivers. One binding per accepted START generation:
;
;   prepare  (stopped vCPU, hv_linux_prepare) fresh launch epoch, CSPRNG
;            session, padn_bind(gen, epoch, session, padc_send); the guest is
;            told both on its command line in the launch ABI of
;            gauntlet_v2/docs/audio_domain_launch.md: paos.pad=<16 hex>:<16 hex>
;            plus the explicit pad.channel/playback/capture/capture_channels/
;            mixer words. The base command line keeps console=ttyS0 and names
;            no console=hvc*.
;   ready    the launch init prints "PAD_SERVICE_READY epoch=<decimal>" on
;            ttyS0 once hvc0 is raw; it counts only when followed by a space or
;            end of line. Nothing is sent before it: cooked-tty echo would be
;            hostile bytes.
;   OPEN     one duplex OPEN (directions 3). A valid success attaches the
;            ABI-v2 adapter (pads_attach); a valid refusal is terminal for
;            this launch (the service exits).
;   service  padc_pump runs pads_step once per clean exit; never a vCPU spin.
;   play     (RCQ-36 V2) with a host HDA function assigned to this START
;            (pcia_playback_source), the attach also begins the finite player
;            on its owned tone (padp_begin_attached, no second OPEN), and the
;            pump runs padp_step instead of pads_step; DRAIN0+STOP0 is logged
;            once. It plays through the guest's own card 0, the assigned HDA.
;   stop     after the vCPU has actually stopped: pads_detach, padn_retire.
;
; A fault (uncertain send, hostile reply, deadline, admission miss) asks the
; owning launch to stop cooperatively; there is no reopen within a START. The
; epoch high-water survives retirement. PaOS itself never prints the session;
; it is a launch-binding identity on the guest command line, not a secret, and
; the guest's own console may echo it.
; Serialized by the VM owner at stopped-vCPU boundaries; no function yields.

PADC_IDLE      equ 0
PADC_BOUND     equ 1                    ; waiting for the guest ready line
PADC_OPENING   equ 2                    ; OPEN queued or in flight
PADC_ATTACHED  equ 3                    ; sound adapter registered
PADC_REFUSED   equ 4                    ; valid OPEN/attach refusal, terminal
PADC_FAULT     equ 5                    ; binding poisoned, launch stop requested

PADC_OPEN_DIRS equ 3                    ; playback | capture
PADC_OPEN_DIRS_HDA equ 1                ; RCQ-36 V2: playback; QEMU's and the player's assigned HDA path
PADC_MARK_MAX  equ 48                   ; "PAD_SERVICE_READY epoch=" + 20 digits
PADC_CMD_MAX   equ 224                  ; the fragment below with two 16-hex ids

; ---------------------------------------------------------------------------
; padc_prepare -> EAX 0 bound, -1 refused (no binding, nothing published).
; Called once per accepted START with the vCPU stopped, before the command
; line is composed. The generation is the accepted START generation.
; ---------------------------------------------------------------------------
padc_prepare:
    push rbx
    cmp  byte [rel padc_bound], 0
    jne  .refused
    mov  ebx, [rel hv_linux_start_consumed]
    test ebx, ebx
    jz   .refused
    mov  rax, [rel padc_epoch_hw]
    inc  rax
    jz   .refused                         ; never wrap the launch epoch
    mov  [rel padc_epoch], rax
    lea  rdi, [rel padc_session]
    mov  esi, 8
    call csprng_generate
    test eax, eax
    jnz  .scrub
    mov  rdx, [rel padc_session]
    test rdx, rdx
    jz   .scrub
    mov  edi, ebx
    mov  rsi, [rel padc_epoch]
    lea  rcx, [rel padc_send]
    call padn_bind
    test eax, eax
    jnz  .bind_refused
    mov  rax, [rel padc_epoch]
    mov  [rel padc_epoch_hw], rax
    mov  [rel padc_gen], rbx
    ; Ready marker and command-line fragment from the bound identity.
    lea  rdi, [rel padc_marker]
    lea  rsi, [rel str_padc_ready]
    mov  ecx, str_padc_ready_len
    cld
    rep  movsb
    mov  rax, [rel padc_epoch]
    call padc_dec
    mov  byte [rdi], 0
    lea  rax, [rel padc_marker]
    sub  rdi, rax
    mov  [rel padc_mark_len], edi
    lea  rdi, [rel padc_cmdline]
    lea  rsi, [rel str_padc_cmdline]
    mov  ecx, str_padc_cmdline_len
    rep  movsb
    mov  rax, [rel padc_epoch]
    call padc_hex16
    mov  byte [rdi], ':'
    inc  rdi
    mov  rax, [rel padc_session]
    call padc_hex16
    lea  rsi, [rel str_padc_cmdline_tail]
    mov  ecx, str_padc_cmdline_tail_len    ; includes the terminator
    mov  byte [rel padc_dirs], PADC_OPEN_DIRS
    test dword [rel vm_profile_dev_mask], VP_DEV_PCIHDA   ; RCQ-36 V2: the assigned HDA guest is playback-only
    jz   .tail
    lea  rsi, [rel str_padc_cmdline_tail_hda]
    mov  ecx, str_padc_cmdline_tail_hda_len
    mov  byte [rel padc_dirs], PADC_OPEN_DIRS_HDA
.tail:
    rep  movsb
    mov  dword [rel padc_match], 0
    mov  byte [rel padc_ready], 0
    mov  dword [rel padc_err], 0
    mov  dword [rel padc_phase], PADC_BOUND
    mov  byte [rel padc_bound], 1
    lea  rdi, [rel str_padc_bound]
    call serial_string
    mov  rdi, rbx
    call serial_hex64
    lea  rdi, [rel str_padc_k_epoch]
    call serial_string
    mov  rdi, [rel padc_epoch]
    call serial_hex64
    lea  rdi, [rel str_padc_nl]
    call serial_string
    xor  eax, eax
    pop  rbx
    ret
.bind_refused:
    mov  [rel padc_err], eax
.scrub:
    mov  qword [rel padc_session], 0
    mov  qword [rel padc_epoch], 0
.refused:
    mov  eax, -1
    pop  rbx
    ret

; RAX=unsigned value, RDI=cursor -> 1..20 decimal digits, RDI advanced.
; Clobbers RAX, RCX, RDX, RSI.
padc_dec:
    lea  rsi, [rel padc_digits + 20]
    mov  ecx, 10
.digit:
    xor  edx, edx
    div  rcx
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test rax, rax
    jnz  .digit
.copy:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rdi
    inc  rsi
    lea  rax, [rel padc_digits + 20]
    cmp  rsi, rax
    jb   .copy
    ret

; RAX=value, RDI=cursor -> exactly 16 lowercase hex digits, RDI advanced.
; Clobbers RAX, RCX, RDX.
padc_hex16:
    mov  ecx, 16
.nibble:
    rol  rax, 4
    mov  edx, eax
    and  edx, 15
    cmp  edx, 10
    jb   .num
    add  edx, 'a' - '0' - 10
.num:
    add  edx, '0'
    mov  [rdi], dl
    inc  rdi
    dec  ecx
    jnz  .nibble
    ret

; -> RAX = the bound command-line fragment, or 0 when unbound. Clobbers only RAX.
padc_cmdline_text:
    xor  eax, eax
    cmp  byte [rel padc_bound], 1
    jne  .out
    lea  rax, [rel padc_cmdline]
.out:
    ret

; Trusted PAD1 send callback: RDI=private bytes, ESI=1..256 -> EAX 1 whole chunk
; queued to the guest, 0 nothing transferred (backpressure), -1 when the
; channel is not this binding's live launch (fails the binding at once).
padc_send:
    cmp  byte [rel padc_bound], 1
    jne  .stale
    cmp  dword [rel padc_phase], PADC_OPENING
    je   .phase_ok
    cmp  dword [rel padc_phase], PADC_ATTACHED
    jne  .stale
.phase_ok:
    mov  eax, [rel hv_linux_start_consumed]
    cmp  rax, [rel padc_gen]
    jne  .stale
    cmp  byte [rel hv_linux_running], 1
    jne  .stale
    test dword [rel vm_profile_live_devices], VP_DEV_PADCHAN
    jz   .stale
    jmp  hv_vcon_rx_bytes                 ; 1 whole chunk / 0 definitely nothing
.stale:
    mov  eax, -1
    ret

; ECX=completed private TX snapshot length in hv_vcon_txbuf. Called by the
; console walker before used-ring release; preserves every register.
padc_receive:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    cmp  byte [rel padc_bound], 1
    jne  .out
    mov  [rel padc_rx_len], ecx
    inc  qword [rel padc_rx_snapshots]
    call boot_ms_now
    mov  rsi, rax
    mov  rdi, [rel padc_gen]
    lea  rdx, [rel hv_vcon_txbuf]
    mov  ecx, [rel padc_rx_len]
    call padn_receive
    test eax, eax
    jns  .out
    call padc_fail
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; AL=one guest UART byte (hv_linux_console_char). Preserves every register.
; Matches the exact ready marker for this binding's epoch, then one
; terminator (space, CR or LF) so a longer epoch never counts; at most once.
padc_uart_byte:
    cmp  byte [rel padc_bound], 1
    jne  .out
    cmp  byte [rel padc_ready], 0
    jne  .out
    push rcx
    push rdx
    mov  ecx, [rel padc_match]
    cmp  ecx, [rel padc_mark_len]
    jae  .terminator
    lea  rdx, [rel padc_marker]
    cmp  al, [rdx + rcx]
    jne  .restart
    inc  ecx
    jmp  .store
.terminator:
    cmp  al, ' '
    je   .ready
    cmp  al, 13
    je   .ready
    cmp  al, 10
    jne  .restart
.ready:
    mov  byte [rel padc_ready], 1
    xor  ecx, ecx
    jmp  .store
.restart:
    xor  ecx, ecx
    cmp  al, 'P'                          ; 'P' occurs only first in the marker
    jne  .store
    inc  ecx
.store:
    mov  [rel padc_match], ecx
    pop  rdx
    pop  rcx
.out:
    ret

; Clean-exit service opportunity. Never enters or spins a vCPU.
padc_pump:
    cmp  byte [rel padc_bound], 1
    jne  .idle
    push rbx
    push r12
    sub  rsp, 8
    call boot_ms_now
    mov  r12, rax
    mov  eax, [rel padc_phase]
    cmp  eax, PADC_BOUND
    je   .bound
    cmp  eax, PADC_OPENING
    je   .opening
    cmp  eax, PADC_ATTACHED
    jne  .out
    cmp  byte [rel padc_play], 0
    jne  .player
    mov  rdi, [rel padc_gen]
    call pads_step
    test rax, rax
    jns  .out
    mov  eax, -5
    call padc_fail
    jmp  .out
.player:
    mov  rdi, [rel padc_gen]
    call padp_step                        ; instead of pads_step while the player owns it
    test rax, rax
    js   .play_fault
    jz   .out
    cmp  byte [rel padc_play], 2
    je   .out
    mov  byte [rel padc_play], 2          ; DRAIN0 + STOP0: logged once
    lea  rdi, [rel str_padc_played]
    call serial_string
    jmp  .out
.play_fault:
    mov  eax, -7
    call padc_fail
    jmp  .out
.bound:
    cmp  byte [rel padc_ready], 1
    jne  .out
    lea  rdi, [rel str_padc_ready_seen]
    cmp  byte [rel padc_dirs], PADC_OPEN_DIRS
    je   .seen
    lea  rdi, [rel str_padc_ready_seen_hda]
.seen:
    call serial_string
    mov  rdi, [rel padc_gen]
    mov  esi, 1                           ; OPEN
    xor  edx, edx
    xor  ecx, ecx
    movzx r8d, byte [rel padc_dirs]       ; this binding's directions (prepare)
    mov  r9, r12
    call padn_request
    test eax, eax
    jnz  .fault
    mov  dword [rel padc_phase], PADC_OPENING
.opening:
    mov  rdi, [rel padc_gen]
    mov  rsi, r12
    call padn_pump
    test eax, eax
    js   .fault
    mov  rdi, [rel padc_gen]
    mov  rsi, r12
    lea  rdx, [rel padc_reply]
    call padn_take
    test eax, eax
    js   .fault
    jz   .out
    mov  ebx, [rel padc_reply + 48]       ; validated reply status
    lea  rdi, [rel padc_reply]
    mov  ecx, PADN_MAX
    xor  eax, eax
    cld
    rep  stosb
    test ebx, ebx
    jnz  .open_refused
    mov  rdi, [rel padc_gen]
    mov  rsi, [rel padc_session]
    lea  rdx, [rel padc_clock]
    call pads_attach
    test rax, rax
    jnz  .attach_refused
    mov  dword [rel padc_phase], PADC_ATTACHED
    mov  byte [rel padc_attached], 1      ; detach owed even after a later fault
    lea  rdi, [rel str_padc_attached]
    call serial_string
    call pcia_playback_source             ; RCQ-36 V2: 0 unless a host HDA is assigned
    test rax, rax
    jz   .out
    mov  rcx, rax
    mov  r8d, edx
    mov  rdi, [rel padc_gen]
    mov  rsi, [rel padc_session]
    lea  rdx, [rel padc_clock]
    call padp_begin_attached              ; joins this OPEN and attach; no second OPEN
    test rax, rax
    jnz  .play_refused
    mov  byte [rel padc_play], 1
    lea  rdi, [rel str_padc_playing]
    call serial_string
    jmp  .out
.play_refused:
    mov  eax, -6
    call padc_fail
    jmp  .out
.attach_refused:
    mov  dword [rel padc_err], -1
    mov  dword [rel padc_phase], PADC_REFUSED
    lea  rdi, [rel str_padc_attach_refused]
    call serial_string
    jmp  .out
.open_refused:
    mov  [rel padc_err], ebx
    mov  dword [rel padc_phase], PADC_REFUSED
    lea  rdi, [rel str_padc_open_refused]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_padc_nl]
    call serial_string
    jmp  .out
.fault:
    call padc_fail
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
.idle:
    ret

; EAX=negative cause. Poisoned for the rest of this START; ask the owning
; launch to stop at its next clean exit. Teardown happens in padc_state_zero.
padc_fail:
    cmp  dword [rel padc_phase], PADC_FAULT
    je   .out
    mov  [rel padc_err], eax
    mov  dword [rel padc_phase], PADC_FAULT
    mov  byte [rel hv_linux_stop_req], 1
    push rdi
    lea  rdi, [rel str_padc_fault]
    call serial_string
    movsxd rdi, dword [rel padc_err]
    call serial_hex64
    lea  rdi, [rel str_padc_nl]
    call serial_string
    pop  rdi
.out:
    ret

; Trusted no-argument clock for the sound adapter: the PAD1 monotonic boot ms.
padc_clock:
    jmp  boot_ms_now

; Revocation before every admitted START and after the vCPU has actually
; stopped (hv_guest_linux_start). Detach, then retire; keep the epoch high-water.
padc_state_zero:
    cmp  byte [rel padc_bound], 1
    jne  .clear
    push rbx
    mov  rbx, [rel padc_gen]
    cmp  byte [rel padc_play], 0
    je   .no_player
    mov  rdi, rbx
    call padp_retire                      ; RCQ-36 V2: after the actual stop, before detach
.no_player:
    cmp  byte [rel padc_attached], 1
    jne  .retire
    mov  rdi, rbx
    call pads_detach                      ; deregisters even a failed adapter
.retire:
    mov  rdi, rbx
    call padn_retire
    lea  rdi, [rel str_padc_retired]
    call serial_string
    mov  rdi, rbx
    call serial_hex64
    lea  rdi, [rel str_padc_nl]
    call serial_string
    pop  rbx
.clear:
    push rdi
    push rcx
    pushfq
    cld
    lea  rdi, [rel padc_private]
    mov  ecx, padc_private_end - padc_private
    xor  eax, eax
    rep  stosb
    popfq
    pop  rcx
    pop  rdi
    ret

str_padc_ready:          db "PAD_SERVICE_READY epoch="
str_padc_ready_len       equ $ - str_padc_ready
str_padc_cmdline:        db " virtio_mmio.device=4K@0xD0000000:5 paos.pad="
str_padc_cmdline_len     equ $ - str_padc_cmdline
str_padc_cmdline_tail:   db " pad.channel=/dev/hvc0 pad.playback=/dev/snd/pcmC0D0p pad.capture=/dev/snd/pcmC0D0c"
                         db " pad.capture_channels=2 pad.mixer=none", 0
str_padc_cmdline_tail_len equ $ - str_padc_cmdline_tail
; RCQ-36 V2 audio-hda: no capture node is opened (the guest init runs --playback-only), and the
; assigned codec is unmuted by AUDHINIT's /pad-mixer before the transport opens.
str_padc_cmdline_tail_hda: db " pad.channel=/dev/hvc0 pad.playback=/dev/snd/pcmC0D0p pad.capture=none"
                         db " pad.capture_channels=2 pad.mixer=/pad-mixer", 0
str_padc_cmdline_tail_hda_len equ $ - str_padc_cmdline_tail_hda
%if str_padc_cmdline_tail_hda_len > str_padc_cmdline_tail_len
    %error "the audio-hda PAD1 tail must fit where the duplex tail does"
%endif
%if str_padc_cmdline_len + 33 + str_padc_cmdline_tail_len > PADC_CMD_MAX
    %error "PAD1 command-line fragment exceeds padc_cmdline"
%endif
str_padc_bound:          db "[PAOS64] PAD channel bound gen=", 0
str_padc_k_epoch:        db " epoch=", 0
str_padc_ready_seen:     db "[PAOS64] PAD channel guest ready; OPEN directions=3", 13, 10, 0
str_padc_ready_seen_hda: db "[PAOS64] PAD channel guest ready; OPEN directions=1", 13, 10, 0
str_padc_attached:       db "[PAOS64] PAD channel OPEN ok; sound adapter attached", 13, 10, 0
str_padc_attach_refused: db "[PAOS64] PAD channel OPEN ok; sound adapter refused attach", 13, 10, 0
str_padc_open_refused:   db "[PAOS64] PAD channel OPEN refused status=", 0
str_padc_fault:          db "[PAOS64] PAD channel fault err=", 0
str_padc_retired:        db "[PAOS64] PAD channel retired gen=", 0
str_padc_playing:        db "[PAOS64] PAD channel playing the owned tone through the assigned HDA", 13, 10, 0
str_padc_played:         db "[PAOS64] PAD channel playback DRAIN0 STOP0", 13, 10, 0
str_padc_nl:             db 13, 10, 0

; Read-only UDP observation. Errors use their unsigned u32 bit pattern.
padc_render_stat:
    lea  rdi, [rel str_padc_obs_pad_gen]
    call hv_out_str
    mov  eax, [rel padc_gen]
    call hv_out_dec
    lea  rdi, [rel str_padc_obs_pad_bound]
    call hv_out_str
    movzx eax, byte [rel padc_bound]
    call hv_out_dec
    lea  rdi, [rel str_padc_obs_pad_phase]
    call hv_out_str
    mov  eax, [rel padc_phase]
    call hv_out_dec
    lea  rdi, [rel str_padc_obs_pad_ready]
    call hv_out_str
    movzx eax, byte [rel padc_ready]
    call hv_out_dec
    lea  rdi, [rel str_padc_obs_pad_dirs]
    call hv_out_str
    movzx eax, byte [rel padc_dirs]
    call hv_out_dec
    lea  rdi, [rel str_padc_obs_pad_play]
    call hv_out_str
    movzx eax, byte [rel padc_play]
    call hv_out_dec
    lea  rdi, [rel str_padc_obs_pad_err]
    call hv_out_str
    mov  eax, [rel padc_err]
    call hv_out_dec
    ret

str_padc_obs_pad_gen: db " pad_gen=", 0
str_padc_obs_pad_bound: db " pad_bound=", 0
str_padc_obs_pad_phase: db " pad_phase=", 0
str_padc_obs_pad_ready: db " pad_ready=", 0
str_padc_obs_pad_dirs: db " pad_dirs=", 0
str_padc_obs_pad_play: db " pad_play=", 0
str_padc_obs_pad_err: db " pad_err=", 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_pad_channel 0
alignb 8
padc_epoch_hw:     resq 1                ; per-boot launch epoch high-water, never cleared
padc_private:
padc_gen:          resq 1
padc_epoch:        resq 1
padc_session:      resq 1
padc_rx_snapshots: resq 1
padc_phase:        resd 1
padc_err:          resd 1
padc_match:        resd 1
padc_rx_len:       resd 1
padc_bound:        resb 1
padc_ready:        resb 1
padc_attached:     resb 1
padc_mark_len:     resd 1
padc_marker:       resb PADC_MARK_MAX + 1
padc_digits:       resb 20
padc_cmdline:      resb PADC_CMD_MAX
alignb 8
padc_reply:        resb PADN_MAX
padc_play:         resb 1                ; RCQ-36 V2: 0 none, 1 player owns the adapter, 2 completed
padc_dirs:         resb 1                ; RCQ-36 V2: this binding's OPEN directions (3, or 1 for audio-hda)
padc_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_pad_channel
