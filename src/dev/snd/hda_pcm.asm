;; MODULE dev/snd/hda_pcm
;; LAYER 3
;; EXPORTS hda_pcm_begin, hda_pcm_start, hda_pcm_service, hda_pcm_drain, hda_pcm_halt, hda_pcm_retire, hda_pcm_enable_cyclic, hda_pcm_prime_cyclic
;; IMPORTS boot/native_driver_gate, dev/snd/hda_output, dev/snd/hda_route_program, dev/snd/hda_session, core/dma
;; CAPS mmio dma
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_PCM_POWER 0
 cmp qword [rel hda_pcm_power_gate],0
 je %%admit
 push rdi
 push rsi
 push rdx
 push rcx
 push r8
 push r9
 push r10
 push r11
 sub rsp,8
 call [rel hda_pcm_power_gate]
 add rsp,8
 pop r11
 pop r10
 pop r9
 pop r8
 pop rcx
 pop rdx
 pop rsi
 pop rdi
 test rax,rax
 jz %%admit
 mov rax,-1
 ret
%%admit:
%endmacro

;
; Controller-owned PCM content lifecycle and private ABI-v2 snd_ops adapter.
; sample_format0/1 keeps packed S16LE;2 admits packed S24LE (3bytes/sample).
; HDA24 DMA uses32bit left-justified containers with low8bits zero; mono
; duplicates into stereo. Stream/route/queue geometry must agree throughout.
; No second sound core, allocation, attach, registration, IRQ/boot call or free.
; Classic hda_playback/boot_chime sequence supplies the four-period layout;
; keep RC's verified RUN/SRST transitions, NOT Classic's read-only LPIB write.
; Intel HDA rev1.0a 3.3.35-40,3.6.1-3 is field authority:
; https://www.intel.com/content/dam/www/public/us/en/documents/product-specifications/high-definition-audio-specification.pdf
;
; Default conservative STOP/RESET refill mode: up to two
; 4KiB data periods, remaining space silent. Copy ONLY at verified HDAO_READY
; after stream reset; no live or unverified-stop period writes. Observed data
; completion stops the stream, verifies RUN0, resets it, then refills the next
; batch. All queued/unconfirmed data retained on cancellation/uncertainty.
; DMA position is ambiguous across wraps. Each batch starts at0; require known
; strictly advancing sample clock and total elapsed < (CBL-FIFOS)/byte_rate,
; stable equal LPIB/DPL observations, monotone positions and a bounded rate/FIFO
; envelope. BCIS confirms a crossed period, never counts wraps. Missing/stale
; evidence earns no invented frames; finite deadline/polls stop/refuse. Counts
; describe qualified complete link/DMA frames, NEVER audible presentation.
; snd_status.timestamp=UINT64_MAX explicitly unavailable. No measurement PASS.
;
; Trusted controller driver supplies completed current route program, verified
; prepared output, preallocated/tagged/mapped/pinned buffers and DID3 map serial.
; EVERY content operation and start/service checks actual dma_domain_live_receipt(1)
; and exact serial (no caller boolean substitutes for enforcing IOMMU). Graph
; MMIO must be output MMIO. Saved output pointers/config cannot change. All
; spans checked nonwrapping/disjoint; serialized driver callbacks and calls,
; no concurrent IRQ/ring/stream user or reentry. External reset revokes epoch.
; clock(arg,out_ticks*)->0 known/nonzero failure; calibrated Hz1..1e9, monotone.
; Freeze/regression/unknown/overflow refuse. Caller must service inside guard
; deadlines; a missed deadline may already have repeated hardware samples and
; is explicit uncertainty, never consumption credit or a storage-release grant.
;
; S16LE mono/stereo44.1/48/96k input. Mono duplicates exactly into the completed
; stereo route/output format; no rate change. Software queue stores stereo
; frames, power-of-two4096..65536 bytes. One stream per increasing graph epoch
; (1..65535), unique driver-assigned backend_id1..65535. snd_ops handle is
; backend_id<<32 | epoch<<16 |1; never dereferenced. No same-epoch reopen.
; self is embedded .device; caller may bind it without global registration.
; open exact parameters, submit accepted frame prefix/0 full/-1 refusal;
; queue/accepted counters publish only after complete copy. Partial frame input
; refuses unchanged. Unity-only volume; mixer owns other gain. close schedules
; halt and invalidates handle immediately; owner drives service to STOPPED.
; recover refuses; external owner handles verified recovery. Retire only after
; verified stop; sticky graph PCM claim stays until new graph epoch. No buffers
; freed, mappings detached, or live DMA rebound, including failed stop/reset.
;
; enable_cyclic(ctx,epoch,2049..96000frames)->0/-1: explicit already-open mono
; 44100/48000 finite mode; same ownership/receipt guards, no new hardware grant.
; The cyclic implementation below documents bounded retired-period writes.
; prime_cyclic(ctx,epoch)->1 pending/0 all4 initial periods/-1 refused:
; optional one stopped-output fill before start. No RUN or retirement credit.
; begin(ctx,epoch)->0/-1. start/drain/halt(ctx,epoch)->1 scheduled/0 empty/-1.
; service(ctx,epoch)->1 progress/0 idle or drained/-1 failed. retire->0/-1.
; Repeated halt during cancellation observes the same pending operation; it
; cannot renew stop polls/deadline or revive FAILED. DRAINED still needs RUN0.
; Begin inputs immutable through retirement. Context fresh or retired and newer
; epoch. All work finite: submit<=65536 input bytes, fill<=8192 data+16384 zero,
; one output transition per service; poll_limit1..4096. SysV GPR/RSP, DF0, no FP.

HDPCM_IDLE equ 1
HDPCM_FILL equ 2
HDPCM_START equ 3
HDPCM_RUN equ 4
HDPCM_STOP equ 5
HDPCM_PREPARE equ 6
HDPCM_DRAINED equ 7
HDPCM_FAILED equ 8
HDPCM_RETIRED equ 9
struc hda_pcm
 .graph: resq 1
 .program: resq 1
 .output: resq 1
 .queue: resq 1
 .queue_bytes: resq 1
 .map_serial: resq 1
 .clock_fn: resq 1
 .clock_arg: resq 1
 .clock_hz: resq 1
 .rate: resd 1
 .channels: resd 1
 .backend_id: resd 1
 .poll_limit: resd 1
 .epoch: resq 1
 .handle: resq 1
 .accepted_frames: resq 1
 .consumed_frames: resq 1
 .last_now: resq 1
 .run_start: resq 1
 .run_ticks: resq 1
 .observed_now: resq 1
 .phase: resd 1
 .error: resd 1
 .opened: resd 1
 .started: resd 1
 .draining: resd 1
 .canceled: resd 1
 .head: resd 1
 .tail: resd 1
 .queued: resd 1
 .batch_bytes: resd 1
 .batch_accounted: resd 1
 .last_pos: resd 1
 .raw_pos: resd 1
 .underruns: resd 1
 .overruns: resd 1
 .starved: resd 1
 .polls: resd 1
 .fifo: resd 1
 .frame_bytes: resd 1
 .sample_format: resd 1          ; 0 legacy S16, 1 explicit S16, 2 packed S24LE
 .session: resq 1
 .signature: resb 96             ;output pointers+timeout and fixed config
 .spans: resb 160                ;ten stable start/end pairs
 .device: resb dev_size
 .ops: resb snd_ops_size
 .info: resb snd_info_size
 .prime_ready: resd 1            ;formerly unused padding; initial4-fill handoff only
 .cyclic: resq 1                 ; explicit finite mono file extension only
 .cyclic_frames: resq 1
 .cyclic_written: resq 1
 .cyclic_fill: resq 1            ; absolute next4096-byte period to publish
 .cyclic_total: resq 1           ; observed bytes, never derived from time
 .cyclic_sample: resq 1
 .cyclic_pos: resq 1
 .cyclic_guard: resq 1
 ; Private diagnostic tail. First position rejection survives halt/retire;
 ; cleared only by fully admitted begin. No clock callback or MMIO reread.
 .sample_entry_now: resq 1
 .sample_last_pos: resq 1
 .failure_reason: resq 1
 .failure_epoch: resq 1
 .failure_raw_pos: resq 1
 .failure_last_pos: resq 1
 .failure_entry_now: resq 1
 .failure_now: resq 1
 .failure_observed_now: resq 1
 .failure_run_start: resq 1
 .failure_run_ticks: resq 1
 .failure_clock_hz: resq 1
 .failure_rate: resq 1
 .failure_fifo: resq 1
 .failure_frame_bytes: resq 1
 .failure_batch_bytes: resq 1
 .failure_batch_accounted: resq 1
 .failure_consumed_frames: resq 1
 .failure_output_state: resq 1
 .failure_cyclic: resq 1
 ; First exact timeout snapshot; pure retained scalars, no fresh MMIO or grant.
 .timeout_reason: resq 1
 .timeout_epoch: resq 1
 .timeout_phase: resq 1
 .timeout_now: resq 1
 .timeout_observed_now: resq 1
 .timeout_run_start: resq 1
 .timeout_run_ticks: resq 1
 .timeout_clock_hz: resq 1
 .timeout_polls: resq 1
 .timeout_poll_limit: resq 1
 .timeout_output_state: resq 1
 .timeout_output_error: resq 1
 .timeout_batch_bytes: resq 1
 .timeout_batch_accounted: resq 1
 .timeout_consumed_frames: resq 1
 .timeout_queued: resq 1
 .timeout_last_pos: resq 1
 .timeout_raw_pos: resq 1
 .timeout_cyclic: resq 1
 .timeout_lpib_first: resq 1
 .timeout_lpib_last: resq 1
 .timeout_observation_count: resq 1
 .timeout_mismatch_count: resq 1
 .timeout_observation_now: resq 1
 .timeout_frame_bytes: resq 1
 .observation_lpib_first: resq 1
 .observation_lpib_last: resq 1
 .observation_count: resq 1
 .observation_mismatch_count: resq 1
 .observation_now: resq 1

 ; First PCM timeout controller snapshot, sampled before failure requests RUN0.
 ; Device addresses are admitted IOVAs, never CPU pointers or new DMA grants.
 .controller_valid: resq 1
 .controller_reason: resq 1
 .controller_epoch: resq 1
 .controller_map_serial: resq 1
 .controller_sd_index: resq 1
 .controller_gcap: resq 1
 .controller_gctl: resq 1
 .controller_dplbase: resq 1
 .controller_dpubase: resq 1
 .controller_sd_control: resq 1
 .controller_sd_status: resq 1
 .controller_lpib: resq 1
 .controller_dpl: resq 1
 .controller_cbl: resq 1
 .controller_lvi: resq 1
 .controller_format: resq 1
 .controller_bdpl: resq 1
 .controller_bdpu: resq 1
 .controller_position_dma: resq 1
 .controller_bdl_dma: resq 1
 .controller_pcm_dma: resq 1
 .controller_position_bytes: resq 1
 .controller_bdl_bytes: resq 1
 .controller_pcm_bytes: resq 1
 .controller_fifo: resq 1
 ; Service-clock samples for the latest RUN, retained through cleanup. The
 ; existing begin clears this tail; no new clock call, poll or deadline.
 .run_write_sample: resq 1
 .run_ack_sample: resq 1
 .run_valid: resq 1               ;bit0 write issued,bit1 RUN/FIFO observed

endstruc

%macro HDPCM_SPAN 3
 mov rax,%1
 mov rdx,%2
 lea rdi,[rsp+%3]
 call hdpcm_span
 jnc %%ok
 mov edx,1+(%3/16)
 jmp .bad
%%ok:
%endmacro

; begin returns RDX=0 on success, stable private refusal code on failure.
; Diagnostics change no refused context, DMA buffer or MMIO register.
hda_pcm_begin:
    NATIVE_DRIVER_REFUSE 7
 mov edx,11                      ; optional power hook refusal
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,176
 mov r12,rdi
 mov rbp,rsi
 HDPCM_SPAN r12,hda_pcm_size,0
 cmp dword [r12+hda_pcm.phase],0
 je .fresh
 cmp dword [r12+hda_pcm.phase],HDPCM_RETIRED
 jne .refuse_4097
 cmp rbp,[r12+hda_pcm.epoch]
 jbe .refuse_4098
.fresh:
 mov rax,rbp
 dec rax
 cmp rax,65534
 ja .refuse_4099
 mov eax,[r12+hda_pcm.backend_id]
 dec eax
 cmp eax,65534
 ja .refuse_4100
 mov eax,[r12+hda_pcm.channels]
 dec eax
 cmp eax,1
 ja .refuse_4101
 mov eax,[r12+hda_pcm.rate]
 cmp eax,44100
 je .rate
 cmp eax,48000
 je .rate
 cmp eax,96000
 jne .refuse_4102
.rate:
 cmp dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
 ja .refuse_4103
 mov eax,[r12+hda_pcm.poll_limit]
 dec eax
 cmp eax,4095
 ja .refuse_4104
 cmp qword [r12+hda_pcm.map_serial],0
 je .refuse_4105
 cmp qword [r12+hda_pcm.clock_fn],0
 je .refuse_4106
 mov rax,[r12+hda_pcm.clock_hz]
 dec rax
 cmp rax,999999999
 ja .refuse_4107
 mov rax,[r12+hda_pcm.queue_bytes]
 cmp rax,4096
 jb .refuse_4108
 cmp rax,65536
 ja .refuse_4109
 lea rdx,[rax-1]
 test rax,rdx
 jnz .refuse_4110
 mov rbx,[r12+hda_pcm.graph]
 mov r13,[r12+hda_pcm.output]
 mov r14,[r12+hda_pcm.program]
 HDPCM_SPAN r13,hda_output_size,16
 HDPCM_SPAN [r12+hda_pcm.queue],[r12+hda_pcm.queue_bytes],32
 HDPCM_SPAN [r13+hda_output.bdl],64,48
 HDPCM_SPAN [r13+hda_output.pcm],16384,64
 HDPCM_SPAN [r13+hda_output.position],256,80
 HDPCM_SPAN r14,hda_route_program_size,96
 HDPCM_SPAN [r13+hda_output.mmio],4096,112
 HDPCM_SPAN rbx,hda_graph_size,128
 HDPCM_SPAN [rbx+hda_graph.owner],hda_graph_lease_size,144
 mov rdi,rsp
 call hdpcm_disjoint
 jc .refuse_4111
 ; Validate all ten spans against graph transport/rings/inventory (MMIO and
 ; graph/lease themselves already represented once in the ten-span table).
 mov rdi,rsp
 call hdpcm_graph_spans
 jc .refuse_4112
 cmp qword [rbx+hda_graph.pcm_owner],0
 jne .refuse_4113
 ; Capture can coexist with an already bound output owner. A new output
 ; binding cannot validate capture's private spans; bind it before input.
 cmp qword [rbx+hda_graph.input_owner],0
 jne .refuse_4114
 cmp [r14+hda_route_program.graph],rbx
 jne .refuse_4115
 cmp [r14+hda_route_program.epoch],rbp
 jne .refuse_4116
 cmp dword [r14+hda_route_program.phase],HDAP_READY
 jne .refuse_4117
 mov rdi,rbx
 mov rsi,r14
 mov rdx,rbp
 call hda_graph_command_check
 test rax,rax
 jnz .refuse_4118
 cmp dword [rbx+hda_graph.command_ready],1
 jne .refuse_4119
 mov rax,[r13+hda_output.mmio]
 cmp rax,[rbx+hda_graph.mmio]
 jne .refuse_4120
 cmp dword [r13+hda_output.mmio_bytes],4096
 jne .refuse_4121
 cmp dword [r13+hda_output.bdl_bytes],64
 jne .refuse_4122
 cmp dword [r13+hda_output.pcm_bytes],16384
 jne .refuse_4123
 cmp dword [r13+hda_output.position_bytes],256
 jne .refuse_4124
 mov eax,4
 cmp dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
 jne .dma_width
 mov eax,8
.dma_width:
 cmp [r13+hda_output.frame_bytes],eax
 jne .refuse_4125
 cmp dword [r13+hda_output.sd_index],30
 jae .refuse_4126
 mov eax,0x811                   ; Classic96k: 48kHz base x2, S16 stereo
 cmp dword [r12+hda_pcm.rate],96000
 je .format
 mov eax,0x11
 cmp dword [r12+hda_pcm.rate],48000
 je .format
 or eax,0x4000
.format:
 cmp dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
 jne .format_width
 or eax,0x20                    ; BITS=3, packed input expanded to 32bit containers
.format_width:
 cmp [r13+hda_output.format],eax
 jne .refuse_4127
 cmp [r14+hda_route_program.saved_format],eax
 jne .refuse_4128
 cmp [r14+hda_route_program.format],eax
 jne .refuse_4129
 mov eax,[r13+hda_output.tag]
 cmp eax,[r14+hda_route_program.saved_tag]
 jne .refuse_4130
 cmp eax,[r14+hda_route_program.tag]
 jne .refuse_4131
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .refuse_4132
 mov edi,1
 call dma_domain_live_receipt
 cmp eax,1
 jne .refuse_4133
 cmp rdx,[r12+hda_pcm.map_serial]
 jne .refuse_4134
 ; Capture known initial time without mutating a refused context.
 mov rdi,[r12+hda_pcm.clock_arg]
 lea rsi,[rsp+160]
 mov qword [rsi],-1
 call [r12+hda_pcm.clock_fn]
 test rax,rax
 jnz .refuse_4135
 cmp qword [rsp+160],-1
 je .refuse_4136
 mov rdi,rbx
 mov rsi,r14
 mov rdx,rbp
 call hda_graph_command_check
 test rax,rax
 jnz .refuse_4137
 cmp qword [rbx+hda_graph.pcm_owner],0
 jne .refuse_4138
 ; Fresh output snapshot and actual stopped registers precede any DMA copy.
 call hdpcm_registers
 test eax,eax
 jnz .bad                       ; preserve exact prepared-register RDX code
 test byte [r8],3
 jnz .refuse_4140
 movzx eax,word [r8+0x10]
 test eax,eax
 jz .refuse_4141
 cmp eax,4096
 ja .refuse_4142
 mov [rsp+168],eax
 mov ecx,16384
 sub ecx,eax
 mov rax,[r12+hda_pcm.clock_hz]
 imul rax,rcx
 xor edx,edx
 mov ecx,[r12+hda_pcm.rate]
 imul ecx,[r13+hda_output.frame_bytes]
 div rcx
 test rax,rax
 jz .refuse_4143
 mov r14,rax
 mov rax,[r12+hda_pcm.clock_hz]
 shl rax,12
 xor edx,edx
 div rcx
 cmp qword [r13+hda_output.timeout],0
 jle .refuse_4144
 cmp [r13+hda_output.timeout],rax
 jae .refuse_4145
 mov rax,[rsp+160]
 add rax,[r13+hda_output.timeout]
 jc .refuse_4146
 ; All admission complete; publish no global registration or DMA action.
 lea rdi,[r12+hda_pcm.epoch]
 xor eax,eax
 mov ecx,(hda_pcm.signature-hda_pcm.epoch)/8
 rep stosq
 mov [r12+hda_pcm.epoch],rbp
 mov [r12+hda_pcm.run_ticks],r14
 mov rax,[rsp+160]
 mov [r12+hda_pcm.last_now],rax
 mov eax,[rsp+168]
 mov [r12+hda_pcm.fifo],eax
 mov ecx,2
 test dword [r13+hda_output.format],0x20
 jz .input_width
 mov ecx,3
 mov dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
.input_width:
 mov eax,[r12+hda_pcm.channels]
 imul eax,ecx
 mov [r12+hda_pcm.frame_bytes],eax
 mov eax,[r12+hda_pcm.backend_id]
 shl rax,32
 mov rdx,rbp
 shl rdx,16
 or rax,rdx
 or rax,1
 mov [r12+hda_pcm.handle],rax
 lea rdi,[r12+hda_pcm.signature]
 mov rsi,r13
 mov ecx,8
 rep movsq
 lea rsi,[r13+hda_output.mmio_bytes]
 mov ecx,4
 rep movsq
 lea rdi,[r12+hda_pcm.spans]
 mov rsi,rsp
 mov ecx,20
 rep movsq
 lea rdi,[r12+hda_pcm.device]
 xor eax,eax
 mov ecx,(hda_pcm_size-hda_pcm.device)/8
 rep stosq
 lea rax,[r12+hda_pcm.ops]
 mov [r12+hda_pcm.device+dev.ops],rax
 lea rax,[r12+hda_pcm.info]
 mov [r12+hda_pcm.device+dev.info],rax
 mov [r12+hda_pcm.device+dev.priv],r12
 mov dword [r12+hda_pcm.device+dev.health],HEALTH_OK
 mov dword [r12+hda_pcm.device+dev.class],CLASS_SOUND
 mov dword [r12+hda_pcm.device+dev.prio],PRIO_NATIVE_EXPERIMENTAL
%macro HDPCM_OP 2
 lea rax,[rel %2]
 mov [r12+hda_pcm.ops+snd_ops.%1],rax
%endmacro
 HDPCM_OP open,hdpcm_open
 HDPCM_OP submit,hdpcm_submit
 HDPCM_OP position,hdpcm_position
 HDPCM_OP status,hdpcm_status
 HDPCM_OP set_volume,hdpcm_volume
 HDPCM_OP close,hdpcm_close
 HDPCM_OP recover,hdpcm_recover
 mov eax,SNDFMT_S16LE
 cmp dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
 jne .advertise
 mov eax,SNDFMT_S24LE
.advertise:
 mov [r12+hda_pcm.info+snd_info.formats],eax
 mov eax,[r12+hda_pcm.channels]
 mov [r12+hda_pcm.info+snd_info.max_chan],eax
 mov dword [r12+hda_pcm.phase],HDPCM_IDLE
 mov [rbx+hda_graph.pcm_owner],r12
 mov dword [rbx+hda_graph.pcm_quiescent],1
 xor edx,edx                    ; admitted, no refusal
 xor eax,eax
 jmp .out
.refuse_4097:
 mov edx,4097
 jmp .bad
.refuse_4098:
 mov edx,4098
 jmp .bad
.refuse_4099:
 mov edx,4099
 jmp .bad
.refuse_4100:
 mov edx,4100
 jmp .bad
.refuse_4101:
 mov edx,4101
 jmp .bad
.refuse_4102:
 mov edx,4102
 jmp .bad
.refuse_4103:
 mov edx,4103
 jmp .bad
.refuse_4104:
 mov edx,4104
 jmp .bad
.refuse_4105:
 mov edx,4105
 jmp .bad
.refuse_4106:
 mov edx,4106
 jmp .bad
.refuse_4107:
 mov edx,4107
 jmp .bad
.refuse_4108:
 mov edx,4108
 jmp .bad
.refuse_4109:
 mov edx,4109
 jmp .bad
.refuse_4110:
 mov edx,4110
 jmp .bad
.refuse_4111:
 mov edx,4111
 jmp .bad
.refuse_4112:
 mov edx,4112
 jmp .bad
.refuse_4113:
 mov edx,4113
 jmp .bad
.refuse_4114:
 mov edx,4114
 jmp .bad
.refuse_4115:
 mov edx,4115
 jmp .bad
.refuse_4116:
 mov edx,4116
 jmp .bad
.refuse_4117:
 mov edx,4117
 jmp .bad
.refuse_4118:
 mov edx,4118
 jmp .bad
.refuse_4119:
 mov edx,4119
 jmp .bad
.refuse_4120:
 mov edx,4120
 jmp .bad
.refuse_4121:
 mov edx,4121
 jmp .bad
.refuse_4122:
 mov edx,4122
 jmp .bad
.refuse_4123:
 mov edx,4123
 jmp .bad
.refuse_4124:
 mov edx,4124
 jmp .bad
.refuse_4125:
 mov edx,4125
 jmp .bad
.refuse_4126:
 mov edx,4126
 jmp .bad
.refuse_4127:
 mov edx,4127
 jmp .bad
.refuse_4128:
 mov edx,4128
 jmp .bad
.refuse_4129:
 mov edx,4129
 jmp .bad
.refuse_4130:
 mov edx,4130
 jmp .bad
.refuse_4131:
 mov edx,4131
 jmp .bad
.refuse_4132:
 mov edx,4132
 jmp .bad
.refuse_4133:
 mov edx,4133
 jmp .bad
.refuse_4134:
 mov edx,4134
 jmp .bad
.refuse_4135:
 mov edx,4135
 jmp .bad
.refuse_4136:
 mov edx,4136
 jmp .bad
.refuse_4137:
 mov edx,4137
 jmp .bad
.refuse_4138:
 mov edx,4138
 jmp .bad
.refuse_4140:
 mov edx,4140
 jmp .bad
.refuse_4141:
 mov edx,4141
 jmp .bad
.refuse_4142:
 mov edx,4142
 jmp .bad
.refuse_4143:
 mov edx,4143
 jmp .bad
.refuse_4144:
 mov edx,4144
 jmp .bad
.refuse_4145:
 mov edx,4145
 jmp .bad
.refuse_4146:
 mov edx,4146
 jmp .bad
.bad:
 mov rax,-1
.out:
 add rsp,176
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Identity and snapshot only; suitable for stop after route/receipt revocation.
; R12=context, returns0/-1, establishes RBX=graph,R13=output. No MMIO.
hdpcm_owned:
 push r14
 mov rbx,[r12+hda_pcm.graph]
 mov r13,[r12+hda_pcm.output]
 mov rax,[r13+hda_output.pci_id]
 cmp rax,[r13+hda_output.bound_pci_id]
 jne .bad                       ; source identity cannot change after bind
 mov rdi,rbx
 mov rsi,[r12+hda_pcm.epoch]
 call hda_graph_owner_check
 test rax,rax
 jnz .bad
 cmp [rbx+hda_graph.pcm_owner],r12
 jne .bad
 lea r14,[r12+hda_pcm.signature]
 xor ecx,ecx
.prefix:
 mov rax,[r13+rcx]
 cmp rax,[r14+rcx]
 jne .bad
 add ecx,8
 cmp ecx,64
 jb .prefix
 xor ecx,ecx
.config:
 mov rax,[r13+hda_output.mmio_bytes+rcx]
 cmp rax,[r14+64+rcx]
 jne .bad
 add ecx,8
 cmp ecx,32
 jb .config
 ; Width selection is part of the owned snapshot, including stop/cleanup.
 mov eax,SNDFMT_S16LE
 test dword [r13+hda_output.format],0x20
 jz .owned_width
 mov eax,SNDFMT_S24LE
.owned_width:
 cmp [r12+hda_pcm.info+snd_info.formats],eax
 jne .bad
 mov edx,[r12+hda_pcm.sample_format]
 cmp eax,SNDFMT_S24LE
 je .owned_s24
 cmp edx,SNDFMT_S16LE
 ja .bad
 jmp .owned_input
.owned_s24:
 cmp edx,SNDFMT_S24LE
 jne .bad
.owned_input:
 inc eax                         ; S16=2 bytes/sample, S24=3
 imul eax,[r12+hda_pcm.channels]
 cmp [r12+hda_pcm.frame_bytes],eax
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r14
 ret

hdpcm_guard:
 sub rsp,8
 call hdpcm_owned
 test rax,rax
 jnz .bad
 mov rdi,rbx
 mov rsi,[r12+hda_pcm.program]
 mov rdx,[r12+hda_pcm.epoch]
 call hda_graph_command_check
 test rax,rax
 jnz .bad
 cmp dword [rbx+hda_graph.command_ready],1
 jne .bad
 mov rax,[r12+hda_pcm.program]
 cmp [rax+hda_route_program.graph],rbx
 jne .bad
 mov rdx,[r12+hda_pcm.epoch]
 cmp [rax+hda_route_program.epoch],rdx
 jne .bad
 cmp dword [rax+hda_route_program.phase],HDAP_READY
 jne .bad
 mov edx,[r13+hda_output.format]
 cmp [rax+hda_route_program.format],edx
 jne .bad
 cmp [rax+hda_route_program.saved_format],edx
 jne .bad
 mov edx,[r13+hda_output.tag]
 cmp [rax+hda_route_program.tag],edx
 jne .bad
 cmp [rax+hda_route_program.saved_tag],edx
 jne .bad
 mov edi,1
 call dma_domain_live_receipt
 cmp eax,1
 jne .bad
 cmp rdx,[r12+hda_pcm.map_serial]
 jne .bad
 call hdpcm_owned                 ;receipt callbacks cannot transfer ownership
 test rax,rax
 jnz .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 ret

hdpcm_clock:
 sub rsp,8
 mov rdi,[r12+hda_pcm.clock_arg]
 lea rsi,[r12+hda_pcm.observed_now]
 mov qword [rsi],-1
 call [r12+hda_pcm.clock_fn]
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_pcm.observed_now]
 cmp rax,-1
 je .bad
 cmp rax,[r12+hda_pcm.last_now]
 jb .bad
 mov [r12+hda_pcm.last_now],rax
 call hdpcm_owned
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 ret

hda_pcm_start:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_IDLE
 jne .bad
 cmp dword [r12+hda_pcm.opened],1
 jne .bad
 call hdpcm_guard
 test rax,rax
 jnz .fault
 mov dword [r12+hda_pcm.started],1
 cmp dword [r12+hda_pcm.prime_ready],1
 je .fill                       ; prepared finite tail may have consumed the queue
 cmp dword [r12+hda_pcm.queued],0
 je .empty
.fill:
 mov dword [r12+hda_pcm.phase],HDPCM_FILL
 mov eax,1
 jmp .out
.empty:
 xor eax,eax
 jmp .out
.fault:
 mov esi,1
 call hdpcm_fail
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_pcm_drain:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 cmp dword [r12+hda_pcm.opened],1
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_DRAINED
 jae .bad
 call hdpcm_guard
 test rax,rax
 jnz .bad
 mov dword [r12+hda_pcm.draining],1
 mov dword [r12+hda_pcm.started],1
 mov eax,1
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_pcm_halt:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_RETIRED
 jae .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_DRAINED
 jne .request
 call hdpcm_owned
 test rax,rax
 jnz .bad
 cmp dword [r13+hda_output.state],HDAO_STOPPED
 jne .bad
 call hdpcm_sd
 test byte [r8],3
 jnz .bad
 xor eax,eax
 jmp .out
.request:
 ; File preparation may defer service for longer than the output stop timeout.
 ; Validate custody before sampling time; use a fresh halt deadline. A broken
 ; clock still requests the owned stop, with its original uncertainty retained.
 call hdpcm_owned
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_FAILED
 je .bad
 cmp dword [r12+hda_pcm.canceled],1
 jne .cancel
 cmp dword [r12+hda_pcm.phase],HDPCM_STOP
 je .pending
 cmp dword [r12+hda_pcm.phase],HDPCM_PREPARE
 je .pending
 jmp .bad
.cancel:
 mov dword [r12+hda_pcm.canceled],1
 call hdpcm_clock
 test rax,rax
 jnz .clock_fault
 xor esi,esi
 jmp .halt
.clock_fault:
 mov esi,2
.halt:
 call hdpcm_fail
 cmp dword [r12+hda_pcm.phase],HDPCM_FAILED
 je .bad
.pending:
 mov eax,1
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_pcm_service:
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_FAILED
 jae .bad
 mov rbp,[r12+hda_pcm.last_now]
 call hdpcm_owned
 test rax,rax
 jnz .owner
 call hdpcm_clock
 test rax,rax
 jnz .clock
 cmp dword [r12+hda_pcm.canceled],0
 jne .dispatch
 cmp dword [r12+hda_pcm.error],0
 jne .dispatch
 call hdpcm_guard
 test rax,rax
 jnz .owner
.dispatch:
 mov eax,[r12+hda_pcm.phase]
 cmp eax,HDPCM_IDLE
 je .idle
 cmp eax,HDPCM_FILL
 je .fill
 cmp eax,HDPCM_START
 je .start
 cmp eax,HDPCM_RUN
 je .run
 cmp eax,HDPCM_STOP
 je .stop
 cmp eax,HDPCM_PREPARE
 je .prepare
 cmp eax,HDPCM_DRAINED
 je .stable
 jmp .state
.idle:
 cmp dword [r12+hda_pcm.started],0
 je .stable
 cmp dword [r12+hda_pcm.queued],0
 jne .schedule_fill
 cmp dword [r12+hda_pcm.draining],0
 jne .begin_stop
 cmp dword [r12+hda_pcm.starved],0
 jne .stable
 mov dword [r12+hda_pcm.starved],1
 cmp dword [r12+hda_pcm.underruns],-1
 je .stable
 inc dword [r12+hda_pcm.underruns]
 jmp .stable
.schedule_fill:
 mov dword [r12+hda_pcm.phase],HDPCM_FILL
 jmp .yield
.fill:
 cmp qword [r12+hda_pcm.cyclic],0
 je .batch_fill
 cmp dword [r12+hda_pcm.prime_ready],1
 je .prepared_cyclic            ; only an actual completed preparation skips fills
 call hdpcm_cyclic_prime
 cmp eax,-2
 je .yield
 test eax,eax
 js .position
 jz .yield
 jmp .cyclic_primed
.prepared_cyclic:
 cmp qword [r12+hda_pcm.cyclic_fill],4
 jne .position
 call hdpcm_prime_count
 test eax,eax
 jnz .position
 mov dword [r12+hda_pcm.prime_ready],0
.cyclic_primed:
 mov dword [r12+hda_pcm.phase],HDPCM_START
 jmp .yield
.batch_fill:
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .state
 call hdpcm_registers
 test eax,eax
 jnz .state
 test byte [r8],3
 jnz .state
 mov eax,[r12+hda_pcm.queued]
 mov ecx,[r13+hda_output.frame_bytes]
 dec ecx
 test eax,ecx
 jnz .state
 cmp rax,[r12+hda_pcm.queue_bytes]
 ja .state
 test eax,eax
 jz .empty_batch
 cmp eax,8192
 jbe .size
 mov eax,8192
.size:
 mov r14d,eax
 mov ebp,[r12+hda_pcm.head]
 cmp rbp,[r12+hda_pcm.queue_bytes]
 jae .state
 test ebp,ecx
 jnz .state
 ; No callback/yield in the finite copy, only reset-verified stopped periods.
 mov rdi,[r13+hda_output.pcm]
 xor eax,eax
 mov ecx,4096
 rep stosd
 mov rdi,[r13+hda_output.pcm]
 mov r8,[r12+hda_pcm.queue]
 mov r9,[r12+hda_pcm.queue_bytes]
 dec r9d
 mov ecx,r14d
 shr ecx,2
.copy:
 mov eax,[r8+rbp]
 mov [rdi],eax
 add rdi,4
 add ebp,4
 and ebp,r9d
 dec ecx
 jnz .copy
 sfence
 mov [r12+hda_pcm.head],ebp
 sub [r12+hda_pcm.queued],r14d
 mov [r12+hda_pcm.batch_bytes],r14d
 mov dword [r12+hda_pcm.batch_accounted],0
 mov dword [r12+hda_pcm.last_pos],0
 mov dword [r12+hda_pcm.polls],0
 mov dword [r12+hda_pcm.starved],0
 mov dword [r12+hda_pcm.phase],HDPCM_START
 jmp .yield
.empty_batch:
 mov dword [r12+hda_pcm.phase],HDPCM_IDLE
 jmp .idle
.start:
 inc dword [r12+hda_pcm.polls]
 mov eax,[r12+hda_pcm.polls]
 cmp eax,[r12+hda_pcm.poll_limit]
 ja .timeout1
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .starting
 call hdpcm_registers
 test eax,eax
 jnz .state
 mov dword [rbx+hda_graph.pcm_quiescent],0
 mov rax,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.run_start],rax
 mov [r12+hda_pcm.cyclic_sample],rax ; includes actual RUN-write startup interval
 mov rdi,r13
 mov rsi,rax
 call hda_output_start
 test rax,rax
 js .output
 mov rax,[r12+hda_pcm.run_start]
 mov [r12+hda_pcm.run_write_sample],rax
 mov qword [r12+hda_pcm.run_ack_sample],0
 mov qword [r12+hda_pcm.run_valid],1
 jmp .yield
.starting:
 cmp dword [r13+hda_output.state],HDAO_STARTING
 jne .state
 call hdpcm_run_bound
 test eax,eax
 jnz .timeout2
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_service
 test rax,rax
 js .output
 cmp dword [r13+hda_output.state],HDAO_RUNNING
 jne .yield
 mov dword [r12+hda_pcm.polls],0
 mov rax,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.run_ack_sample],rax
 mov qword [r12+hda_pcm.run_valid],3
 mov dword [r12+hda_pcm.phase],HDPCM_RUN
 ; Keep the actual RUN-write time, not the later RUNNING observation: DMA
 ; can advance throughout startup. Initial guarded position includes it.
 jmp .yield
.run:
 mov rax,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.sample_entry_now],rax
 mov eax,[r12+hda_pcm.last_pos]
 mov [r12+hda_pcm.sample_last_pos],rax
 cmp qword [r12+hda_pcm.cyclic],0
 je .batch_run
 call hdpcm_cyclic_run
 test rax,rax
 js .position
 jz .yield
 mov dword [r12+hda_pcm.draining],1
 jmp .begin_stop
.batch_run:
 ; Zero elapsed/frozen sampling cannot qualify advancing raw DMA observations.
 cmp rbp,[r12+hda_pcm.last_now]
 jae .clock
 call hdpcm_run_bound
 test eax,eax
 jnz .timeout3
 inc dword [r12+hda_pcm.polls]
 mov eax,[r12+hda_pcm.polls]
 cmp eax,[r12+hda_pcm.poll_limit]
 ja .timeout4
 call hdpcm_registers
 test eax,eax
 jnz .state
 mov r14d,[r8+4]                  ;LPIB before position-buffer observation
 mov rdi,r13
 lea rsi,[r12+hda_pcm.raw_pos]
 call hda_output_position
 test rax,rax
 js .output
 call hdpcm_sd
 ; Retain the observations already required by the old equality checks.
 ; No additional MMIO read, modulo inference or accepted-frame mutation.
 mov [r12+hda_pcm.observation_lpib_first],r14
 mov eax,[r8+4]
 mov [r12+hda_pcm.observation_lpib_last],rax
 mov rcx,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.observation_now],rcx
 cmp qword [r12+hda_pcm.observation_count],-1
 je .observed
 inc qword [r12+hda_pcm.observation_count]
.observed:
 mov ecx,[r12+hda_pcm.raw_pos]
 cmp r14d,eax
 jne .mismatched
 cmp r14d,ecx
 je .positions
.mismatched:
 cmp qword [r12+hda_pcm.observation_mismatch_count],-1
 je .positions
 inc qword [r12+hda_pcm.observation_mismatch_count]
.positions:
 ; DPL updates periodically, independently of LPIB (Intel HDA 3.3.32): Beelink
 ; 204 showed DPL 32 B behind LPIB on every sample, so equality never held.
 ; As hda_input: validate ALL three before their minimum, the conservative
 ; DMA-visible prefix; neither a bad ring offset nor an in-poll wrap may hide
 ; in it, and a DPL ahead of LPIB never credits past LPIB.
 cmp r14d,16384
 jae .position_ring                ;no wrap accepted in this guarded batch
 cmp ecx,16384
 jae .position_ring
 cmp eax,16384
 jae .position_ring
 cmp eax,r14d
 jb .position_regress              ;LPIB moved backwards inside one poll
 cmp r14d,[r12+hda_pcm.last_pos]
 jb .position_regress              ;raw LPIB behind the accepted position
 cmp r14d,ecx
 cmova r14d,ecx                    ;min(LPIB first, DPL); LPIB last >= first
 cmp r14d,[r12+hda_pcm.last_pos]
 jb .position_regress
 ; Bracket the coherent DMA observation. Entry time predates MMIO reads and
 ; can falsely reject valid progress after preemption. The trailing sample
 ; must still precede a possible ring wrap and retain the original authority.
 call hdpcm_clock
 test rax,rax
 jnz .clock
 call hdpcm_guard
 test rax,rax
 jnz .owner
 call hdpcm_run_bound
 test rax,rax
 jnz .timeout5
 call hdpcm_registers
 test eax,eax
 jnz .output
 cmp dword [r13+hda_output.state],HDAO_RUNNING
 jne .output
 test byte [r8],1
 jnz .output
 test byte [r8],2
 jz .output
 ; FIFO may report a bounded jump; raw position cannot outrun calibrated time.
 mov rax,[r12+hda_pcm.last_now]
 sub rax,[r12+hda_pcm.run_start]
 mov ecx,[r12+hda_pcm.rate]
 imul ecx,[r13+hda_output.frame_bytes]
 imul rax,rcx
 mov ecx,[r12+hda_pcm.fifo]
 imul rcx,[r12+hda_pcm.clock_hz]
 add rax,rcx
 mov edx,r14d
 imul rdx,[r12+hda_pcm.clock_hz]
 cmp rdx,rax
 ja .position_envelope
 mov eax,r14d
 shr eax,12
 mov edx,[r12+hda_pcm.last_pos]
 shr edx,12
 cmp eax,edx
 je .account
 test byte [r8+3],4
 jz .yield                        ;BCIS never becomes an inferred wrap counter
.account:
 mov [r12+hda_pcm.last_pos],r14d
 mov eax,r14d
 cmp eax,[r12+hda_pcm.batch_bytes]
 jbe .actual
 mov eax,[r12+hda_pcm.batch_bytes]
.actual:
 xor edx,edx
 div dword [r13+hda_output.frame_bytes]
 mov edx,eax
 sub edx,[r12+hda_pcm.batch_accounted]
 jc .position_account
 mov rcx,[r12+hda_pcm.consumed_frames]
 add rcx,rdx
 jc .position_overflow
 js .position_signed
 mov [r12+hda_pcm.batch_accounted],eax
 mov [r12+hda_pcm.consumed_frames],rcx
 cmp r14d,[r12+hda_pcm.batch_bytes]
 jae .begin_stop
 ; BCIS marks the boundary LPIB crossed and hda_output_service W1C-clears it.
 ; While the selected prefix still trails LPIB across that boundary, leave it
 ; set: it is the only corroboration of the prefix's own crossing next poll.
 mov eax,[r12+hda_pcm.observation_lpib_last]
 shr eax,12
 mov edx,r14d
 shr edx,12
 cmp eax,edx
 je .service
 call hdpcm_registers              ;fault/stream checks still run this poll
 test eax,eax
 jnz .output
 jmp .yield
.service:
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_service
 test rax,rax
 js .output
 jmp .yield
.begin_stop:
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_halt
 test rax,rax
 js .output
 mov dword [r12+hda_pcm.polls],0
 mov dword [r12+hda_pcm.phase],HDPCM_STOP
 jmp .yield
.stop:
 inc dword [r12+hda_pcm.polls]
 mov eax,[r12+hda_pcm.polls]
 cmp eax,[r12+hda_pcm.poll_limit]
 ja .uncertain
 cmp dword [r13+hda_output.state],HDAO_HALTING
 jne .state
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_service
 test rax,rax
 js .uncertain
 cmp dword [r13+hda_output.state],HDAO_STOPPED
 jne .yield
 call hdpcm_sd
 test byte [r8],3
 jnz .uncertain
 mov dword [rbx+hda_graph.pcm_quiescent],1
 mov dword [r12+hda_pcm.polls],0
 cmp dword [r12+hda_pcm.error],0
 jne .failed
 cmp dword [r12+hda_pcm.canceled],0
 jne .drained
 mov dword [r12+hda_pcm.batch_bytes],0
 mov dword [r12+hda_pcm.batch_accounted],0
 cmp dword [r12+hda_pcm.draining],0
 je .reset_next
 cmp dword [r12+hda_pcm.queued],0
 je .drained
.reset_next:
 mov dword [r12+hda_pcm.phase],HDPCM_PREPARE
 jmp .yield
.prepare:
 inc dword [r12+hda_pcm.polls]
 mov eax,[r12+hda_pcm.polls]
 cmp eax,[r12+hda_pcm.poll_limit]
 ja .uncertain
 mov eax,[r13+hda_output.state]
 cmp eax,HDAO_STOPPED
 jne .preparing
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_prepare
 test rax,rax
 js .uncertain
 jmp .yield
.preparing:
 cmp eax,HDAO_STOPPING
 jb .state
 cmp eax,HDAO_RESET_CLEAR
 ja .state
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_service
 test rax,rax
 js .uncertain
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .yield
 cmp dword [r12+hda_pcm.canceled],0
 jne .begin_stop
 cmp dword [r12+hda_pcm.error],0
 jne .begin_stop
 mov dword [r12+hda_pcm.phase],HDPCM_IDLE
 mov dword [r12+hda_pcm.polls],0
 jmp .yield
.drained:
 mov dword [r12+hda_pcm.phase],HDPCM_DRAINED
.stable:
 xor eax,eax
 jmp .out
.owner:
 mov esi,1
 jmp .fault
.clock:
 mov esi,2
 jmp .fault
.timeout1:
 mov esi,1
 jmp .timeout_record
.timeout2:
 mov esi,2
 jmp .timeout_record
.timeout3:
 mov esi,3
 jmp .timeout_record
.timeout4:
 mov esi,4
 jmp .timeout_record
.timeout5:
 mov esi,5
.timeout_record:
 call hdpcm_timeout_failure
 mov esi,3
 jmp .fault
.state:
 mov esi,4
 jmp .fault
.position_ring:
 mov esi,1
 jmp .position_record
.position_regress:
 mov esi,2
 jmp .position_record
.position_envelope:
 mov esi,3
 jmp .position_record
.position_account:
 mov esi,4
 jmp .position_record
.position_overflow:
 mov esi,5
 jmp .position_record
.position_signed:
 mov esi,6
 jmp .position_record
.position:
 mov esi,7                       ; cyclic validator rejected, reason opaque
.position_record:
 call hdpcm_position_failure
 mov esi,5
 jmp .fault
.output:
 mov esi,6
.fault:
 call hdpcm_fail
 jmp .bad
.uncertain:
 mov dword [r12+hda_pcm.error],7
.failed:
 mov dword [r12+hda_pcm.device+dev.health],HEALTH_DEAD
 mov dword [r12+hda_pcm.phase],HDPCM_FAILED
.bad:
 mov rax,-1
 jmp .out
.yield:
 mov eax,1
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Record only existing context values at the exact rejection branch, before
; halt/cleanup can resample clocks/positions. This record never grants credit.
; reason1 ring limit,2 regression,3 time envelope,4 accounting underflow,
; 5 unsigned consumed overflow,6 signed overflow,7 cyclic validator failure.
hdpcm_position_failure:
 cmp qword [r12+hda_pcm.failure_reason],0
 jne .out
 mov rax,[r12+hda_pcm.epoch]
 mov [r12+hda_pcm.failure_epoch],rax
 mov eax,[r12+hda_pcm.raw_pos]
 mov [r12+hda_pcm.failure_raw_pos],rax
 mov rax,[r12+hda_pcm.sample_last_pos]
 mov [r12+hda_pcm.failure_last_pos],rax
 mov rax,[r12+hda_pcm.sample_entry_now]
 mov [r12+hda_pcm.failure_entry_now],rax
 mov rax,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.failure_now],rax
 mov rax,[r12+hda_pcm.observed_now]
 mov [r12+hda_pcm.failure_observed_now],rax
 mov rax,[r12+hda_pcm.run_start]
 mov [r12+hda_pcm.failure_run_start],rax
 mov rax,[r12+hda_pcm.run_ticks]
 mov [r12+hda_pcm.failure_run_ticks],rax
 mov rax,[r12+hda_pcm.clock_hz]
 mov [r12+hda_pcm.failure_clock_hz],rax
 mov eax,[r12+hda_pcm.rate]
 mov [r12+hda_pcm.failure_rate],rax
 mov eax,[r12+hda_pcm.fifo]
 mov [r12+hda_pcm.failure_fifo],rax
 mov eax,[r13+hda_output.frame_bytes]
 mov [r12+hda_pcm.failure_frame_bytes],rax
 mov eax,[r12+hda_pcm.batch_bytes]
 mov [r12+hda_pcm.failure_batch_bytes],rax
 mov eax,[r12+hda_pcm.batch_accounted]
 mov [r12+hda_pcm.failure_batch_accounted],rax
 mov rax,[r12+hda_pcm.consumed_frames]
 mov [r12+hda_pcm.failure_consumed_frames],rax
 mov eax,[r13+hda_output.state]
 mov [r12+hda_pcm.failure_output_state],rax
 mov rax,[r12+hda_pcm.cyclic]
 mov [r12+hda_pcm.failure_cyclic],rax
 mov [r12+hda_pcm.failure_reason],rsi ; publish last; never replace first
.out:
 ret

; Exact timeout site:1 START poll cap,2 START elapsed bound,3 RUN entry
; elapsed bound,4 RUN poll cap,5 trailing observation elapsed bound. Cached
; positions are diagnostic observations only and may predate the timeout.
hdpcm_timeout_failure:
 cmp qword [r12+hda_pcm.timeout_reason],0
 jne .out
 mov rax,[r12+hda_pcm.epoch]
 mov [r12+hda_pcm.timeout_epoch],rax
 mov eax,[r12+hda_pcm.phase]
 mov [r12+hda_pcm.timeout_phase],rax
 mov rax,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.timeout_now],rax
 mov rax,[r12+hda_pcm.observed_now]
 mov [r12+hda_pcm.timeout_observed_now],rax
 mov rax,[r12+hda_pcm.run_start]
 mov [r12+hda_pcm.timeout_run_start],rax
 mov rax,[r12+hda_pcm.run_ticks]
 mov [r12+hda_pcm.timeout_run_ticks],rax
 mov rax,[r12+hda_pcm.clock_hz]
 mov [r12+hda_pcm.timeout_clock_hz],rax
 mov eax,[r12+hda_pcm.polls]
 mov [r12+hda_pcm.timeout_polls],rax
 mov eax,[r12+hda_pcm.poll_limit]
 mov [r12+hda_pcm.timeout_poll_limit],rax
 mov eax,[r13+hda_output.state]
 mov [r12+hda_pcm.timeout_output_state],rax
 mov eax,[r13+hda_output.error]
 mov [r12+hda_pcm.timeout_output_error],rax
 mov eax,[r12+hda_pcm.batch_bytes]
 mov [r12+hda_pcm.timeout_batch_bytes],rax
 mov eax,[r12+hda_pcm.batch_accounted]
 mov [r12+hda_pcm.timeout_batch_accounted],rax
 mov rax,[r12+hda_pcm.consumed_frames]
 mov [r12+hda_pcm.timeout_consumed_frames],rax
 mov eax,[r12+hda_pcm.queued]
 mov [r12+hda_pcm.timeout_queued],rax
 mov eax,[r12+hda_pcm.last_pos]
 mov [r12+hda_pcm.timeout_last_pos],rax
 mov eax,[r12+hda_pcm.raw_pos]
 mov [r12+hda_pcm.timeout_raw_pos],rax
 mov rax,[r12+hda_pcm.cyclic]
 mov [r12+hda_pcm.timeout_cyclic],rax
 mov rax,[r12+hda_pcm.observation_lpib_first]
 mov [r12+hda_pcm.timeout_lpib_first],rax
 mov rax,[r12+hda_pcm.observation_lpib_last]
 mov [r12+hda_pcm.timeout_lpib_last],rax
 mov rax,[r12+hda_pcm.observation_count]
 mov [r12+hda_pcm.timeout_observation_count],rax
 mov rax,[r12+hda_pcm.observation_mismatch_count]
 mov [r12+hda_pcm.timeout_mismatch_count],rax
 mov rax,[r12+hda_pcm.observation_now]
 mov [r12+hda_pcm.timeout_observation_now],rax
 mov eax,[r13+hda_output.frame_bytes]
 mov [r12+hda_pcm.timeout_frame_bytes],rax
 ; Service has already revalidated owner, output snapshot and DID3 receipt.
 ; No callback, service transition, MMIO write or allocation in this snapshot.
 ; All reads are within admitted pinned MMIO/position spans; no fresh clock.
 call hdpcm_sd
 mov r9,[r13+hda_output.mmio]
 mov [r12+hda_pcm.controller_reason],rsi
 mov rax,[r12+hda_pcm.epoch]
 mov [r12+hda_pcm.controller_epoch],rax
 mov rax,[r12+hda_pcm.map_serial]
 mov [r12+hda_pcm.controller_map_serial],rax
 mov eax,[r13+hda_output.sd_index]
 mov [r12+hda_pcm.controller_sd_index],rax
 movzx eax,word [r9]
 mov [r12+hda_pcm.controller_gcap],rax
 mov eax,[r9+8]
 mov [r12+hda_pcm.controller_gctl],rax
 mov eax,[r9+0x70]
 mov [r12+hda_pcm.controller_dplbase],rax
 mov eax,[r9+0x74]
 mov [r12+hda_pcm.controller_dpubase],rax
 mov eax,[r8]
 and eax,0xffffff
 mov [r12+hda_pcm.controller_sd_control],rax
 movzx eax,byte [r8+3]
 mov [r12+hda_pcm.controller_sd_status],rax
 mov eax,[r8+4]
 mov [r12+hda_pcm.controller_lpib],rax
 mov eax,[r13+hda_output.sd_index]
 mov r10,[r13+hda_output.position]
 mov eax,[r10+rax*8]
 mov [r12+hda_pcm.controller_dpl],rax
 mov eax,[r8+8]
 mov [r12+hda_pcm.controller_cbl],rax
 movzx eax,word [r8+12]
 mov [r12+hda_pcm.controller_lvi],rax
 movzx eax,word [r8+0x12]
 mov [r12+hda_pcm.controller_format],rax
 mov eax,[r8+0x18]
 mov [r12+hda_pcm.controller_bdpl],rax
 mov eax,[r8+0x1c]
 mov [r12+hda_pcm.controller_bdpu],rax
 mov rax,[r13+hda_output.position_dma]
 mov [r12+hda_pcm.controller_position_dma],rax
 mov rax,[r13+hda_output.bdl_dma]
 mov [r12+hda_pcm.controller_bdl_dma],rax
 mov rax,[r13+hda_output.pcm_dma]
 mov [r12+hda_pcm.controller_pcm_dma],rax
 mov eax,[r13+hda_output.position_bytes]
 mov [r12+hda_pcm.controller_position_bytes],rax
 mov eax,[r13+hda_output.bdl_bytes]
 mov [r12+hda_pcm.controller_bdl_bytes],rax
 mov eax,[r13+hda_output.pcm_bytes]
 mov [r12+hda_pcm.controller_pcm_bytes],rax
 movzx eax,word [r8+0x10]
 mov [r12+hda_pcm.controller_fifo],rax
 mov qword [r12+hda_pcm.controller_valid],1 ; publish complete snapshot last
 mov [r12+hda_pcm.timeout_reason],rsi
.out:
 ret

; Absolute known elapsed bound, no modulo unwrapping or time-derived consumption.
hdpcm_run_bound:
 mov rax,[r12+hda_pcm.last_now]
 sub rax,[r12+hda_pcm.run_start]
 jc .bad
 cmp rax,[r12+hda_pcm.run_ticks]
 jae .bad
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret

; Revoke immediately, request only our own stream stop. No free/reset/rebind.
hdpcm_fail:
 push rbp
 mov ebp,esi
 cmp dword [r12+hda_pcm.error],0
 jne .preserve
 mov [r12+hda_pcm.error],ebp
.preserve:
 mov dword [r12+hda_pcm.device+dev.health],HEALTH_DEAD
 call hdpcm_owned
 test rax,rax
 jnz .uncertain
 mov eax,[r13+hda_output.state]
 cmp eax,HDAO_HALTING
 je .stop
 cmp eax,HDAO_READY
 jb .preparing
 cmp eax,HDAO_RUNNING
 ja .uncertain
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_halt
 test rax,rax
 js .uncertain
.stop:
 mov dword [r12+hda_pcm.phase],HDPCM_STOP
 mov dword [r12+hda_pcm.polls],0
 jmp .out
.preparing:
 cmp eax,HDAO_STOPPING
 jb .uncertain
 mov dword [r12+hda_pcm.phase],HDPCM_PREPARE
 jmp .out
.uncertain:
 mov dword [r12+hda_pcm.phase],HDPCM_FAILED
.out:
 mov rax,-1
 pop rbp
 ret

hda_pcm_retire:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 mov eax,[r12+hda_pcm.phase]
 cmp eax,HDPCM_DRAINED
 je .check
 cmp eax,HDPCM_FAILED
 jne .bad
.check:
 call hdpcm_owned
 test rax,rax
 jnz .bad
 cmp dword [r13+hda_output.state],HDAO_STOPPED
 jne .bad
 call hdpcm_sd
 test byte [r8],3
 jnz .bad
 cmp dword [rbx+hda_graph.pcm_quiescent],1
 jne .bad
 mov dword [r12+hda_pcm.opened],0
 mov dword [r12+hda_pcm.device+dev.health],HEALTH_DEAD
 mov dword [r12+hda_pcm.phase],HDPCM_RETIRED
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

; Only immutable prepared register/BDL configuration. No hardware writes.
hdpcm_sd:
 mov eax,[r13+hda_output.sd_index]
 shl eax,5
 mov r8,[r13+hda_output.mmio]
 lea r8,[r8+rax+0x80]
 ret
hdpcm_registers:
 sub rsp,8
 call hdpcm_sd
 test byte [r8+3],0x18
 jnz .refuse_8193
 cmp dword [r8+8],16384
 jne .refuse_8194
 cmp word [r8+12],3
 jne .refuse_8195
 mov eax,[r13+hda_output.format]
 cmp [r8+0x12],ax
 jne .refuse_8196
 mov eax,[r13+hda_output.tag]
 shl eax,4
 ; SDnCTL bit18 (byte2 bit2) is implementation-dependent RW or RO.
 ; A controller may retain TP1 after our TP0 write. It is not part of
 ; STRM: compare the exact tag, DIR0 and STRIPE0, allowing either TP.
 ; Intel HDA rev1.0a section3.3.35, Table34.
 movzx ecx,byte [r8+2]
 and cl,0xFB
 cmp cl,al
 jne .refuse_8197
 mov rax,[r13+hda_output.bdl_dma]
 cmp [r8+0x18],eax
 jne .refuse_8198
 shr rax,32
 cmp [r8+0x1c],eax
 jne .refuse_8199
 mov r9,[r13+hda_output.mmio]
 mov rax,[r13+hda_output.position_dma]
 or eax,1
 cmp [r9+0x70],eax
 jne .refuse_8200
 mov rax,[r13+hda_output.position_dma]
 shr rax,32
 cmp [r9+0x74],eax
 jne .refuse_8201
 mov r9,[r13+hda_output.bdl]
 mov rax,[r13+hda_output.pcm_dma]
 mov ecx,4
.bdl:
 cmp [r9],rax
 jne .refuse_8202
 cmp dword [r9+8],4096
 jne .refuse_8203
 cmp dword [r9+12],1
 jne .refuse_8204
 add r9,16
 add rax,4096
 dec ecx
 jnz .bdl
 xor edx,edx
 xor eax,eax
 add rsp,8
 ret
.refuse_8193:
 mov edx,8193
 jmp .bad
.refuse_8194:
 mov edx,8194
 jmp .bad
.refuse_8195:
 mov edx,8195
 jmp .bad
.refuse_8196:
 mov edx,8196
 jmp .bad
.refuse_8197:
 mov edx,8197
 jmp .bad
.refuse_8198:
 mov edx,8198
 jmp .bad
.refuse_8199:
 mov edx,8199
 jmp .bad
.refuse_8200:
 mov edx,8200
 jmp .bad
.refuse_8201:
 mov edx,8201
 jmp .bad
.refuse_8202:
 mov edx,8202
 jmp .bad
.refuse_8203:
 mov edx,8203
 jmp .bad
.refuse_8204:
 mov edx,8204
 jmp .bad
.bad:
 mov eax,-1
 add rsp,8
 ret

; ABI resolve is bounded and never dereferences a stream handle.
hdpcm_resolve:
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_pcm.device]
 cmp rdi,rax
 jne .bad
 cmp rsi,[r12+hda_pcm.handle]
 jne .bad
 cmp dword [r12+hda_pcm.opened],1
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_DRAINED
 ja .bad
 sub rsp,8
 call hdpcm_guard
 test rax,rax
 jz .guarded
 mov esi,1
 call hdpcm_fail
.guarded:
 add rsp,8
 ret
.bad:
 mov rax,-1
 ret

hdpcm_open:
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,[rdi+dev.priv]
 mov rbp,rsi
 mov r14,rdx
 lea rax,[r12+hda_pcm.device]
 cmp rdi,rax
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_IDLE
 jne .bad
 cmp dword [r12+hda_pcm.opened],0
 jne .bad
 cmp qword [r12+hda_pcm.session],0
 jne .bad                        ;one open per increasing owner epoch
 call hdpcm_guard
 test rax,rax
 jnz .bad
 mov rsi,rbp
 mov edx,snd_stream_params_size
 call hdpcm_buffer_separate
 jc .bad
 mov rsi,r14
 mov edx,8
 call hdpcm_buffer_separate
 jc .bad
 lea rax,[rbp+snd_stream_params_size]
 cmp r14,rax
 jae .params
 lea rax,[r14+8]
 cmp rbp,rax
 jb .bad
.params:
 mov eax,[rbp+snd_stream_params.rate]
 cmp eax,[r12+hda_pcm.rate]
 jne .bad
 mov eax,[rbp+snd_stream_params.channels]
 cmp eax,[r12+hda_pcm.channels]
 jne .bad
 mov eax,[r12+hda_pcm.info+snd_info.formats]
 cmp [rbp+snd_stream_params.format],eax
 jne .bad
 cmp dword [rbp+snd_stream_params.direction],SND_DIR_PLAY
 jne .bad
 cmp dword [rbp+snd_stream_params.latency_class],SND_LATENCY_BULK
 ja .bad
 cmp dword [rbp+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 jne .bad
 mov rax,[rbp+snd_stream_params.session_group]
 test rax,rax
 jz .bad
 mov [r12+hda_pcm.session],rax
 mov dword [r12+hda_pcm.opened],1
 mov rax,[r12+hda_pcm.handle]
 mov [r14],rax
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

hdpcm_submit:
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 mov rbp,rdx
 mov r14,rcx
 call hdpcm_resolve
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_pcm.draining],0
 jne .bad
 cmp dword [r12+hda_pcm.canceled],0
 jne .bad
 cmp r14,65536
 ja .bad
 mov rax,r14
 xor edx,edx
 mov ecx,[r12+hda_pcm.frame_bytes]
 div rcx
 test edx,edx
 jnz .bad
 test r14,r14
 jz .zero
 mov rsi,rbp
 mov rdx,r14
 call hdpcm_buffer_separate
 jc .bad
 mov eax,[r12+hda_pcm.queued]
 mov edx,[r13+hda_output.frame_bytes]
 dec edx
 test eax,edx
 jnz .bad
 cmp rax,[r12+hda_pcm.queue_bytes]
 ja .bad
 mov ecx,[r12+hda_pcm.tail]
 test ecx,edx
 jnz .bad
 cmp rcx,[r12+hda_pcm.queue_bytes]
 jae .bad
 mov r15,[r12+hda_pcm.queue_bytes]
 sub r15,rax
 mov rax,r15
 xor edx,edx
 mov ecx,[r13+hda_output.frame_bytes]
 div rcx
 mov r15,rax                     ;free complete DMA frame slots
 mov rax,r14
 xor edx,edx
 mov ecx,[r12+hda_pcm.frame_bytes]
 div rcx
 cmp r15,rax
 jbe .capacity
 mov r15,rax
.capacity:
 cmp qword [r12+hda_pcm.cyclic],0
 je .finite_capacity
 mov rax,[r12+hda_pcm.cyclic_frames]
 sub rax,[r12+hda_pcm.accepted_frames]
 jc .bad
 cmp r15,rax
 cmova r15,rax                   ; finite accepted prefix cannot exceed file
.finite_capacity:
 mov rax,[r12+hda_pcm.accepted_frames]
 add rax,r15
 jc .bad
 js .bad
 mov [rsp],rax
 mov ecx,[r12+hda_pcm.frame_bytes]
 mov rax,r15
 imul rax,rcx
 mov [rsp+8],rax
 test r15,r15
 jz .publish
 mov r8,[r12+hda_pcm.queue]
 mov r9d,[r12+hda_pcm.tail]
 mov r10,[r12+hda_pcm.queue_bytes]
 dec r10d
 mov rcx,r15
.copy:
 cmp dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
 je .copy_s24
 cmp dword [r12+hda_pcm.channels],1
 jne .stereo
 movzx eax,word [rbp]
 mov edx,eax
 shl edx,16
 or eax,edx
 add rbp,2
 jmp .store
.stereo:
 mov eax,[rbp]
 add rbp,4
.store:
 mov [r8+r9],eax
 add r9d,4
 jmp .copied
.copy_s24:
 ; Exactly three input bytes: no fourth-byte overread at a caller boundary.
 movzx eax,word [rbp]
 movzx edx,byte [rbp+2]
 shl edx,16
 or eax,edx
 shl eax,8                       ; HDA32 container: signed24 in high bits, zero LSB
 mov [r8+r9],eax
 add rbp,3
 cmp dword [r12+hda_pcm.channels],1
 je .s24_right
 movzx eax,word [rbp]
 movzx edx,byte [rbp+2]
 shl edx,16
 or eax,edx
 shl eax,8
 add rbp,3
.s24_right:
 mov [r8+r9+4],eax               ; mono repeats the complete signed24 sample
 add r9d,8
.copied:
 and r9d,r10d
 dec rcx
 jnz .copy
 mov [r12+hda_pcm.tail],r9d
.publish:
 imul r15d,[r13+hda_output.frame_bytes]
 add [r12+hda_pcm.queued],r15d
 mov rax,[rsp]
 mov [r12+hda_pcm.accepted_frames],rax
 mov rax,[rsp+8]
 cmp rax,r14
 je .out
 cmp dword [r12+hda_pcm.overruns],-1
 je .out
 inc dword [r12+hda_pcm.overruns]
 jmp .out
.zero:
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

hdpcm_position:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 call hdpcm_resolve
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_pcm.consumed_frames]
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret
hdpcm_status:
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 sub rsp,8
 mov rbp,rdx
 call hdpcm_resolve
 test rax,rax
 jnz .bad
 mov rsi,rbp
 mov edx,snd_status_size
 call hdpcm_buffer_separate
 jc .bad
 mov rax,[r12+hda_pcm.consumed_frames]
 mov [rbp+snd_status.frames],rax
 mov qword [rbp+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 mov eax,SND_STATE_IDLE
 cmp dword [r12+hda_pcm.phase],HDPCM_START
 jb .state
 cmp dword [r12+hda_pcm.phase],HDPCM_RUN
 ja .state
 mov eax,SND_STATE_RUNNING
.state:
 mov [rbp+snd_status.state],eax
 mov eax,[r12+hda_pcm.underruns]
 add eax,[r12+hda_pcm.overruns]
 jnc .xruns
 mov eax,-1
.xruns:
 mov [rbp+snd_status.xruns],eax
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdpcm_volume:
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 sub rsp,8
 mov rbp,rdx
 call hdpcm_resolve
 test rax,rax
 jnz .bad
 cmp rbp,0x7fff
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdpcm_close:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 call hdpcm_resolve
 test rax,rax
 jnz .bad
 mov dword [r12+hda_pcm.opened],0
 mov rdi,r12
 mov rsi,[r12+hda_pcm.epoch]
 call hda_pcm_halt
 test rax,rax
 js .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret
hdpcm_recover:
 mov rax,-1
 ret

; Nonwrapping span helpers and bounded disjoint comparisons. Mappedness is a
; driver obligation. No pointer from a PCM user is dereferenced before checks.
hdpcm_span:
 test rax,rax
 jz .bad
 test rdx,rdx
 jz .bad
 mov [rdi],rax
 add rax,rdx
 jc .bad
 mov [rdi+8],rax
 clc
 ret
.bad:
 stc
 ret
hdpcm_disjoint:
 xor ecx,ecx
.outer:
 mov r8,[rdi+rcx]
 mov r9,[rdi+rcx+8]
 lea edx,[rcx+16]
.inner:
 cmp edx,160
 jae .next
 cmp r8,[rdi+rdx+8]
 jae .skip
 cmp [rdi+rdx],r9
 jb .bad
.skip:
 add edx,16
 jmp .inner
.next:
 add ecx,16
 cmp ecx,160
 jb .outer
 clc
 ret
.bad:
 stc
 ret
%macro HDPCM_GRAPH_SPAN 2
 mov r8,%1
 mov r9,%2
 test r9,r9
 jz %%done
 add r9,r8
 jc .bad
 cmp r10,r9
 jae %%done
 cmp r8,r11
 jb .bad
%%done:
%endmacro
; RBX=validated graph, R10=start R11=end. Graph MMIO/lease/context checked in
; local table instead, so full4096 MMIO can be checked without self-alias.
hdpcm_graph_external:
 HDPCM_GRAPH_SPAN [rbx+hda_graph.transport],hda_transport_size
 HDPCM_GRAPH_SPAN [rbx+hda_graph.corb],1024
 HDPCM_GRAPH_SPAN [rbx+hda_graph.rirb],2048
 mov ecx,[rbx+hda_graph.codec_cap]
 shl ecx,5
 HDPCM_GRAPH_SPAN [rbx+hda_graph.codecs],rcx
 mov ecx,[rbx+hda_graph.group_cap]
 imul ecx,ecx,hda_group_info_size
 HDPCM_GRAPH_SPAN [rbx+hda_graph.groups],rcx
 mov ecx,[rbx+hda_graph.widget_cap]
 shl ecx,5
 HDPCM_GRAPH_SPAN [rbx+hda_graph.widgets],rcx
 mov ecx,[rbx+hda_graph.edge_cap]
 imul ecx,ecx,hda_route_edge_size
 HDPCM_GRAPH_SPAN [rbx+hda_graph.edges],rcx
 clc
 ret
.bad:
 stc
 ret
hdpcm_graph_spans:
 push rbp
 push r14
 sub rsp,8
 mov rbp,rdi
 xor r14d,r14d
.loop:
 mov r10,[rbp+r14]
 mov r11,[rbp+r14+8]
 call hdpcm_graph_external
 jc .bad
 add r14d,16
 cmp r14d,160
 jb .loop
 clc
 jmp .out
.bad:
 stc
.out:
 add rsp,8
 pop r14
 pop rbp
 ret
; RSI=buffer,RDX=size. Validate against all DMA/owner/source spans, including
; context itself. Zero-length submit bypasses this helper and never reads buf.
hdpcm_buffer_separate:
 mov r10,rsi
 mov r11,rsi
 test rsi,rsi
 jz .bad
 add r11,rdx
 jc .bad
 lea rdi,[r12+hda_pcm.spans]
 xor ecx,ecx
.loop:
 cmp r10,[rdi+rcx+8]
 jae .skip
 cmp [rdi+rcx],r11
 jb .bad
.skip:
 add ecx,16
 cmp ecx,160
 jb .loop
 jmp hdpcm_graph_external
.bad:
 stc
 ret

; Explicit finite cyclic extension of the SAME owned PCM stream. Default
; diagnostic STOP/RESET refill is unchanged. No allocation, new MMIO binding,
; controller reset, DMA grant or fabricated stop/retirement receipt.
; Four4096B periods, one retired period copied per service. Stable equal
; LPIB/DPL plus strict calibrated sampling deadline disambiguate one modulo
; advance. BCIS only corroborates a crossed period. Time bounds observations;
; it never supplies missing frames. A two-period distance protects live writes
; from the current period and FIFO prefetch. Missed guards revoke/stop normally.
; Only already-open mono44100/48000 S16 streams with2049..96000 finite frames.
hda_pcm_enable_cyclic:
 HDA_PCM_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov rbp,rdx
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 call hdpcm_guard
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_IDLE
 jne .bad
 cmp dword [r12+hda_pcm.opened],1
 jne .bad
 cmp dword [r12+hda_pcm.started],0
 jne .bad
 cmp dword [r12+hda_pcm.queued],0
 jne .bad
 cmp qword [r12+hda_pcm.cyclic],0
 jne .bad
 cmp dword [r12+hda_pcm.sample_format],SNDFMT_S24LE
 je .bad                         ; finite mono cyclic extension remains S16 only
 cmp dword [r12+hda_pcm.channels],1
 jne .bad
 cmp dword [r12+hda_pcm.rate],44100
 je .cyclic_rate
 cmp dword [r12+hda_pcm.rate],48000
 jne .bad
.cyclic_rate:
 cmp qword [r12+hda_pcm.queue_bytes],16384
 jb .bad
 cmp dword [r12+hda_pcm.fifo],2048
 ja .bad
 cmp rbp,2049
 jb .bad
 cmp rbp,96000
 ja .bad
 mov eax,4096
 sub eax,[r12+hda_pcm.fifo]
 imul rax,[r12+hda_pcm.clock_hz]
 xor edx,edx
 mov ecx,[r12+hda_pcm.rate]
 shl ecx,2                      ; actual stereo DMA bytes/second
 div rcx
 test rax,rax
 jz .bad
 mov [r12+hda_pcm.cyclic_guard],rax
 mov [r12+hda_pcm.cyclic_frames],rbp
 mov qword [r12+hda_pcm.cyclic],1
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; R12/R13 retain actual guarded PCM/output. One full period transaction;
; -2 backpressure publishes NOTHING,0 filled,-1 corrupt finite state.
hdpcm_cyclic_fill:
 push r15
 sub rsp,32
 mov rax,[r12+hda_pcm.cyclic_frames]
 cmp rax,2049
 jb .bad
 cmp rax,96000
 ja .bad
 sub rax,[r12+hda_pcm.cyclic_written]
 jc .bad
 cmp rax,1024
 jbe .amount
 mov eax,1024
.amount:
 shl eax,2
 mov [rsp],rax                  ; known data bytes, remaining period is silence
 mov ecx,[r12+hda_pcm.queued]
 test ecx,3
 jnz .bad
 cmp rcx,[r12+hda_pcm.queue_bytes]
 ja .bad
 cmp rcx,rax
 jb .pending                    ; never publish underflow silence as real data
 mov r15d,[r12+hda_pcm.head]
 test r15d,3
 jnz .bad
 cmp r15,[r12+hda_pcm.queue_bytes]
 jae .bad
 mov rax,[r12+hda_pcm.cyclic_fill]
 cmp rax,97                     ; ceil96000/1024 plus ring-sized silent tail
 ja .bad
 and eax,3
 shl eax,12
 add rax,[r13+hda_output.pcm]
 mov [rsp+8],rax
 mov rdi,rax
 xor eax,eax
 mov ecx,1024
 rep stosd
 mov rdi,[rsp+8]
 mov r8,[r12+hda_pcm.queue]
 mov r9,[r12+hda_pcm.queue_bytes]
 dec r9d
 mov rcx,[rsp]
 shr ecx,2
 jz .publish
.copy:
 mov eax,[r8+r15]
 mov [rdi],eax
 add rdi,4
 add r15d,4
 and r15d,r9d
 dec ecx
 jnz .copy
.publish:
 sfence
 mov [r12+hda_pcm.head],r15d
 mov eax,[rsp]
 sub [r12+hda_pcm.queued],eax
 shr eax,2
 add [r12+hda_pcm.cyclic_written],rax
 inc qword [r12+hda_pcm.cyclic_fill]
 xor eax,eax
 jmp .out
.pending: mov rax,-2
 jmp .out
.bad: mov rax,-1
.out:
 add rsp,32
 pop r15
 ret

; Optional initial preparation, still HDPCM_IDLE/unstarted. The same guarded
; stopped-output copy runs once per call. No new lease, timer, RUN or credit.
hda_pcm_prime_cyclic:
 HDA_PCM_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_pcm.epoch]
 jne .bad
 cmp dword [r12+hda_pcm.phase],HDPCM_IDLE
 jne .bad
 cmp dword [r12+hda_pcm.opened],1
 jne .bad
 cmp dword [r12+hda_pcm.started],0
 jne .bad
 cmp dword [r12+hda_pcm.draining],0
 jne .bad
 cmp dword [r12+hda_pcm.canceled],0
 jne .bad
 cmp dword [r12+hda_pcm.error],0
 jne .bad
 cmp qword [r12+hda_pcm.cyclic],1
 jne .bad
 cmp qword [r12+hda_pcm.cyclic_fill],4
 ja .bad
 call hdpcm_guard
 test rax,rax
 jnz .bad
 call hdpcm_clock
 test rax,rax
 jnz .bad
 call hdpcm_guard               ; callbacks may revoke custody
 test rax,rax
 jnz .bad
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .bad
 call hdpcm_registers
 test eax,eax
 jnz .bad
 test byte [r8],3
 jnz .bad
 cmp qword [r12+hda_pcm.cyclic_fill],4
 je .already_done
 cmp dword [r12+hda_pcm.prime_ready],0
 jne .bad
 call hdpcm_cyclic_prime
 cmp rax,-2
 je .pending                   ; backpressure publishes nothing
 test rax,rax
 js .bad
 jnz .mark_done
.pending:
 mov eax,1
 jmp .out
.mark_done:
 call hdpcm_prime_count
 test eax,eax
 jnz .bad
 mov dword [r12+hda_pcm.prime_ready],1
 jmp .done
.already_done:
 cmp dword [r12+hda_pcm.prime_ready],1
 jne .bad
 call hdpcm_prime_count
 test eax,eax
 jnz .bad
.done:
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hdpcm_prime_count:              ; exact initial real-data frames, including short finite tails
 mov rax,[r12+hda_pcm.cyclic_frames]
 cmp rax,2049
 jb .bad
 cmp rax,96000
 ja .bad
 mov edx,4096
 cmp rax,rdx
 cmova rax,rdx
 cmp [r12+hda_pcm.cyclic_written],rax
 jne .bad
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret

hdpcm_cyclic_prime:
 sub rsp,8
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .bad
 call hdpcm_registers
 test eax,eax
 jnz .bad
 test byte [r8],3
 jnz .bad
 cmp qword [r12+hda_pcm.cyclic_fill],4
 jae .bad
 call hdpcm_cyclic_fill
 test rax,rax
 js .out
 cmp qword [r12+hda_pcm.cyclic_fill],4
 sete al
 movzx eax,al
 jmp .out
.bad: mov rax,-1
.out: add rsp,8
 ret

hdpcm_cyclic_run:
 push r15
 sub rsp,32
 cmp qword [r12+hda_pcm.cyclic],1
 jne .bad
 mov rax,[r12+hda_pcm.last_now]
 sub rax,[r12+hda_pcm.cyclic_sample]
 jbe .bad
 cmp rax,[r12+hda_pcm.cyclic_guard]
 jae .bad                       ; no hidden full ring or late refill allowed
 call hdpcm_registers
 test eax,eax
 jnz .bad
 mov r14d,[r8+4]
 mov rdi,r13
 lea rsi,[r12+hda_pcm.raw_pos]
 call hda_output_position
 test rax,rax
 js .bad
 call hdpcm_sd
 mov eax,[r8+4]                 ; LPIB after the position-buffer read
 mov ecx,[r12+hda_pcm.raw_pos]
 cmp r14d,16384
 ja .bad
 cmp eax,16384
 ja .bad
 cmp ecx,16384
 ja .bad                        ; inclusive CBL denotes the same wrap boundary
 ; As in batch mode, entry time predates the MMIO reads. A preemption there
 ; must not make real progress appear faster than the link. Keep the raw
 ; samples across callbacks; revalidate authority and the stream before any
 ; credit/refill. The trailing time must still fit the original sample guard.
 mov [rsp+16],rax               ; LPIB last, before callbacks clobber scratch
 mov [rsp+24],rcx               ; DPL, not a later replacement observation
 call hdpcm_clock
 test rax,rax
 jnz .bad
 call hdpcm_guard
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_pcm.last_now]
 sub rax,[r12+hda_pcm.cyclic_sample]
 jbe .bad
 cmp rax,[r12+hda_pcm.cyclic_guard]
 jae .bad                       ; preemption cannot extend the refill deadline
 call hdpcm_registers
 test eax,eax
 jnz .bad
 cmp dword [r13+hda_output.state],HDAO_RUNNING
 jne .bad
 test byte [r8],1
 jnz .bad
 test byte [r8],2
 jz .bad
 mov eax,[rsp+16]
 mov ecx,[rsp+24]
 ; DPL updates periodically, independently of LPIB (Intel HDA 3.3.32). The
 ; batch rule in ring terms: the conservative prefix is the observation
 ; furthest behind cyclic_pos. Compare forward distances, never raw offsets,
 ; which a wrap between the samples would invert.
 mov edx,[r12+hda_pcm.cyclic_pos]
 sub r14d,edx
 and r14d,16383
 sub eax,edx
 and eax,16383
 sub ecx,edx
 and ecx,16383
 cmp eax,r14d
 jb .bad                        ; LPIB moved backwards inside one poll
 mov [rsp+8],rax                ; LPIB last forward distance
 ; Every raw sample, not only the minimum, must fit the known-time + FIFO
 ; envelope. A sample behind cyclic_pos (a backward LPIB or DPL) reads as a
 ; near-full-ring forward distance and is refused here, before the minimum
 ; could select another sample and hide it. FIFO <= 2048 and cyclic_guard
 ; keep a real advance far below a ring.
 mov r9,[r12+hda_pcm.last_now]
 sub r9,[r12+hda_pcm.run_start]
 jc .bad
 mov r10d,[r12+hda_pcm.rate]
 shl r10,2
 imul r9,r10
 mov r10d,[r12+hda_pcm.fifo]
 imul r10,[r12+hda_pcm.clock_hz]
 add r9,r10
 mov r10d,r14d
 call .envelope
 jc .bad
 mov r10,[rsp+8]
 call .envelope
 jc .bad
 mov r10d,ecx
 call .envelope
 jc .bad
 cmp r14d,ecx
 cmova r14d,ecx                 ; min(LPIB first, DPL) forward distance
 mov r15d,r14d
 add r14d,edx
 and r14d,16383                 ; the selected ring offset
 add r15,[r12+hda_pcm.cyclic_total]
 jc .bad
 mov rax,[rsp+8]
 add rax,[r12+hda_pcm.cyclic_total]
 mov [rsp+8],rax                ; LPIB last in data-total terms
 mov rax,[r12+hda_pcm.last_now]
 sub rax,[r12+hda_pcm.run_start]
 jc .bad
 mov ecx,[r12+hda_pcm.rate]
 shl rcx,2
 imul rax,rcx
 mov [rsp],rax
 mov rcx,r15
 imul rcx,[r12+hda_pcm.clock_hz]
 mov edx,[r12+hda_pcm.fifo]
 imul rdx,[r12+hda_pcm.clock_hz]
 lea rax,[rax+rdx]
 cmp rcx,rax
 ja .bad                        ; raw data cannot outrun known time + FIFO
 lea rax,[rcx+rdx*2]
 cmp rax,[rsp]
 jb .bad                        ; stale observations cannot hide repeated wraps
 mov rax,r15
 shr rax,12
 mov rcx,[r12+hda_pcm.cyclic_total]
 shr rcx,12
 mov [rsp+16],rcx                ; prior credited period; raw LPIB scratch is spent
 cmp rax,rcx
 je .observed
 test byte [r8+3],4
 jz .pending                    ; BCIS corroborates, never counts wraps
.observed:
 mov rcx,[r12+hda_pcm.cyclic_fill]
 sub rcx,rax
 jc .bad
 cmp rcx,2
 jb .bad                        ; current + next/FIFO periods are untouchable
 cmp rcx,4
 ja .bad
 mov [r12+hda_pcm.cyclic_pos],r14
 mov [r12+hda_pcm.cyclic_total],r15
 mov rax,[r12+hda_pcm.last_now]
 mov [r12+hda_pcm.cyclic_sample],rax
 shr r15,2
 cmp r15,[r12+hda_pcm.cyclic_frames]
 jb .credit
 mov r15,[r12+hda_pcm.cyclic_frames]
.credit:
 mov [r12+hda_pcm.consumed_frames],r15
 cmp r15,[r12+hda_pcm.cyclic_frames]
 jb .refill
 ; Keep the owned silent tail running for one admitted FIFO depth beyond
 ; the last data frame. No extra real-frame credit or presentation assertion.
 mov rax,[r12+hda_pcm.cyclic_frames]
 shl rax,2
 mov edx,[r12+hda_pcm.fifo]
 add rax,rdx
 cmp [r12+hda_pcm.cyclic_total],rax
 jae .complete
.refill:
 cmp rcx,3
 ja .service
 call hdpcm_cyclic_fill
 cmp eax,-2
 je .service                    ; bounded queue backpressure, guard still runs
 test rax,rax
 js .bad
 ; Check the elapsed safety margin again after the bounded copy. A preempted
 ; late operation earns no success/retirement grant and uses ordinary halt.
 call hdpcm_clock
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_pcm.last_now]
 sub rax,[r12+hda_pcm.cyclic_sample]
 cmp rax,[r12+hda_pcm.cyclic_guard]
 jae .bad
.service:
 ; As the batch: no BCIS acknowledgement while the credited prefix trails
 ; LPIB across a period boundary; its own crossing still needs that BCIS.
 ; Also leave BCIS alone when this observation credited no new period. DMA
 ; can cross after the raw reads, before hda_output_service samples status:
 ; clearing that new completion would lose the next crossing's corroboration.
 mov rax,[rsp+8]
 shr rax,12
 mov rcx,[r12+hda_pcm.cyclic_total]
 shr rcx,12
 cmp rax,rcx
 je .acknowledge
 call hdpcm_registers           ; fault/stream checks still run this poll
 test eax,eax
 jnz .bad
 jmp .pending
.acknowledge:
 cmp rcx,[rsp+16]
 jbe .pending                    ; only acknowledge a newly observed period
 mov rdi,r13
 mov rsi,[r12+hda_pcm.last_now]
 call hda_output_service
 test rax,rax
 js .bad
.pending: xor eax,eax
 jmp .out
.complete: mov eax,1
 jmp .out
.bad: mov rax,-1
.out:
 add rsp,32
 pop r15
 ret
; R10 = forward distance, R9 = time+FIFO bound (clock units). CF=1: outside.
.envelope:
 add r10,[r12+hda_pcm.cyclic_total]
 jc .outside
 imul r10,[r12+hda_pcm.clock_hz]
 jo .outside
 cmp r9,r10
 ret                            ; CF=1 when r10 > r9
.outside:
 stc
 ret

%macro WDATA_hda_pcm_power 0
 align 8
hda_pcm_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_pcm_power
%else
 section .data
 WDATA_hda_pcm_power
 section .text
%endif
