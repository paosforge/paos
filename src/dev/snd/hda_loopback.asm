;; MODULE dev/snd/hda_loopback
;; LAYER 3
;; EXPORTS hda_loopback_select48, hda_loopback_select_output48, hda_loopback_select_output, hda_loopback_run_output, hda_loopback_begin, hda_loopback_step, hda_loopback_select, hda_loopback_run, hda_loopback_run_pcm, hda_loopback_run_pcm_stream, hda_loopback_cancel, hda_loopback_release
;; IMPORTS dev/snd/hda_pcm, dev/snd/hda_backend, dev/snd/hda_session, dev/snd/hda_transport, core/dma
;; CAPS mmio dma
;; OWNER rc-codex-av
; Explicit controller-owned finite native corpus/capture coordinator. No PCI,
; allocation, registration or boot action here; the native owner adapter supplies
; these exact pinned contexts. Whole-controller serialized calls, actual DID3
; receipt and graph/route/map epochs remain mandatory. No memory is freed.
; Corpus ID1 is exact low-volume1024-frame mono44.1k data from the one reference
; generator. Input is one verified stopped2048-frame batch, not seamless capture.
; Corpus ID3 repeats that vector in ONE88200-frame/two-second cyclic playback;
; paired input captures only its first2048 frames, then stays stopped.
; Corpus ID4 uses explicit paired48k selection and96000 output frames. The
; same immutable burst vector plays faster (523*48000/44100 Hz); no resampling.
; Pin senses are attributed real CORB/RIRB queries, not software booleans. Unknown
; sense state, digital endpoints or speaker default type never admit RUN. Pins
; without detection explicitly publish known=2/sense=0; no jack is claimed.
; The owner must explicitly confirm self-loop/patch policy before RUN. Software
; cannot infer actual cable routing or authorize MSI speaker playback.
; Each step performs one bounded child operation or one retained query operation.
; No controller reset while streams are active; backend owns stop/reset/retire.
; begin(ctx,epoch), step(ctx,epoch), cancel/release(ctx,epoch):0/1/2 or-1.
; select(ctx,epoch,selection32*) and run(ctx,epoch,fixture1/3/4,wiring1/2) explicit.
; select_output keeps four input words zero; run_output(fixture1,intent1)
; uses only the selected analog output. Paired RUN never admits that mode.
; SysV GPR/RSP/DF0, no FP. Inputs stay pinned/immutable until verified retirement.

HLB_GRAPH equ 1
HLB_FEED equ 0                   ; explicit file/corpus3 owner opened the stream
HLB_PINS equ 2
HLB_DISCOVERED equ 3
HLB_CONFIGURE equ 4
HLB_READY equ 5
HLB_INPUT equ 6
HLB_PLAY equ 7
HLB_DRAIN equ 8
HLB_CLEANUP equ 9
HLB_DONE equ 10
HLB_FAILED equ 11
HLB_UNCERTAIN equ 12
HLB_RELEASED equ 13
HLB_PIN_CAP equ 256
struc hda_loopback_pin
 .codec: resd 1
 .group: resd 1
 .nid: resd 1
 .caps: resd 1
 .pin_caps: resd 1
 .config: resd 1
 .sense: resd 1
 .known: resd 1                 ;0 unknown,1 attributed sense,2 detection unsupported
 .query: resd 1
 .reserved: resd 3
endstruc
struc hda_loopback
 .backend: resq 1
 .pins: resq 1
 .recording: resq 1
 .epoch: resq 1
 .snapshot: resq 3
 .phase: resd 1
 .error: resd 1
 .pin_count: resd 1
 .widget_index: resd 1
 .query_state: resd 1
 .query_command: resd 1
 .query_response: resd 1
 .query_row: resd 1
 .query_trigger: resd 1
 .query_polls: resd 1
 .deadline: resq 1
 .query_deadline: resq 1
 .last_now: resq 1
 .selection: resd 8
 .output_row: resd 1
 .input_row: resd 1
 .handle: resq 1
 .device: resq 1
 .captured_frames: resq 1
 .played_frames: resq 1
 .started: resd 1
 .copied: resd 1
 .wiring: resd 1
 .successful: resd 1
 .steps: resq 1
 .params: resb snd_stream_params_size
 .pad: resq 1
 .mute_index: resd 1
 .mute_state: resd 1
 .muted: resd 1
 .mute_pad: resd 1
 .play_pcm: resq 1               ; caller-owned stable PCM, until retirement
 .play_frames: resq 1
 .play_cursor: resq 1            ; actual whole frames accepted by snd_ops
 .streaming: resd 1              ;1 cyclic file,2 paired corpus,3 output-only corpus
 .stream_turn: resd 1
 .output_only: resd 1            ; explicit PINOUT, no input ownership
 .output_pad: resd 1
endstruc
%macro HLB_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov rbp,rsi
 mov rbx,[r12+hda_loopback.backend]
%endmacro
%macro HLB_LEAVE 0
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro
%macro HLB_BACKEND 1
 mov rdi,rbx
 mov rsi,rbp
 call %1
%endmacro

; Validate each additional span against every backend/graph/DMA span BEFORE
; backend begin can bind DPLBASE or touch any DMA byte. Trusted mappings required.
hlb_separate:
 ; RSI=start,RDI=end; preserve subject throughout fixed explicit span checks.
%macro HLB_EXCLUDE 2
 mov rax,%1
 mov rdx,%2
 test rdx,rdx
 jz %%done
 test rax,rax
 jz .bad
 add rdx,rax
 jc .bad
 cmp rsi,rdx
 jae %%done
 cmp rax,rdi
 jb .bad
%%done:
%endmacro
 HLB_EXCLUDE rbx,hda_backend_size
 mov r13,[rbx+hda_backend.graph]
 HLB_EXCLUDE r13,hda_graph_size
 mov r14,[rbx+hda_backend.program]
 HLB_EXCLUDE r14,hda_route_program_size
 mov r14,[rbx+hda_backend.output]
 HLB_EXCLUDE r14,hda_output_size
 HLB_EXCLUDE [r14+hda_output.mmio],4096
 HLB_EXCLUDE [r14+hda_output.bdl],64
 HLB_EXCLUDE [r14+hda_output.pcm],16384
 HLB_EXCLUDE [r14+hda_output.position],256
 mov r14,[rbx+hda_backend.pcm]
 HLB_EXCLUDE r14,hda_pcm_size
 HLB_EXCLUDE [r14+hda_pcm.queue],[r14+hda_pcm.queue_bytes]
 mov r14,[rbx+hda_backend.input]
 test r14,r14
 jz .bad
 HLB_EXCLUDE r14,hda_input_size
 HLB_EXCLUDE [r14+hda_input.bdl],64
 HLB_EXCLUDE [r14+hda_input.pcm],16384
 HLB_EXCLUDE [r14+hda_input.queue],8192
 mov r14,[r13+hda_graph.owner]
 HLB_EXCLUDE r14,hda_graph_lease_size
 mov r14,[r14+hda_graph_lease.transport]
 HLB_EXCLUDE r14,hda_transport_size
 HLB_EXCLUDE [r14+hda_transport.corb],1024
 HLB_EXCLUDE [r14+hda_transport.rirb],2048
 mov edx,[r13+hda_graph.codec_cap]
 cmp edx,15
 ja .bad
 shl edx,5
 HLB_EXCLUDE [r13+hda_graph.codecs],rdx
 mov edx,[r13+hda_graph.group_cap]
 cmp edx,1905
 ja .bad
 imul edx,24
 HLB_EXCLUDE [r13+hda_graph.groups],rdx
 mov edx,[r13+hda_graph.widget_cap]
 cmp edx,1905
 ja .bad
 shl edx,5
 HLB_EXCLUDE [r13+hda_graph.widgets],rdx
 mov edx,[r13+hda_graph.edge_cap]
 cmp edx,2048
 ja .bad
 imul edx,24
 HLB_EXCLUDE [r13+hda_graph.edges],rdx
 clc
 ret
.bad:
 stc
 ret

hda_loopback_begin:
 HLB_ENTER
 sub rsp,48
 cmp dword [r12+hda_loopback.phase],0
 jne .bad
 mov rax,rbp
 dec rax
 cmp rax,65534
 ja .bad
 mov [rsp],r12
 mov qword [rsp+8],hda_loopback_size
 mov rax,[r12+hda_loopback.pins]
 mov [rsp+16],rax
 mov qword [rsp+24],HLB_PIN_CAP*hda_loopback_pin_size
 mov rax,[r12+hda_loopback.recording]
 mov [rsp+32],rax
 mov qword [rsp+40],8192
 xor ecx,ecx
.spans:
 mov rsi,[rsp+rcx]
 test rsi,rsi
 jz .bad
 mov rdi,[rsp+rcx+8]
 add rdi,rsi
 jc .bad
 mov rax,rdi
 dec rax
 shr rax,47
 jnz .bad
 push rcx
 call hlb_separate
 pop rcx
 jc .bad
 mov [rsp+rcx+8],rdi
 add ecx,16
 cmp ecx,48
 jb .spans
 mov rax,[rsp]
 cmp rax,[rsp+24]
 jae .pair1
 mov rax,[rsp+16]
 cmp rax,[rsp+8]
 jb .bad
.pair1:
 mov rax,[rsp]
 cmp rax,[rsp+40]
 jae .pair2
 mov rax,[rsp+32]
 cmp rax,[rsp+8]
 jb .bad
.pair2:
 mov rax,[rsp+16]
 cmp rax,[rsp+40]
 jae .valid
 mov rax,[rsp+32]
 cmp rax,[rsp+24]
 jb .bad
.valid:
 ; This finite rail requires exact mono corpus output and one2048-frame input.
 mov rax,[rbx+hda_backend.pcm]
 cmp dword [rax+hda_pcm.rate],44100
 jne .bad
 cmp dword [rax+hda_pcm.channels],1
 jne .bad
 mov rax,[rbx+hda_backend.input]
 cmp dword [rax+hda_input.batch_frames],2048
 jne .bad
 cmp dword [rax+hda_input.rate],44100
 jne .bad
 HLB_BACKEND hda_backend_discover_begin
 test rax,rax
 jnz .bad
 mov [r12+hda_loopback.epoch],rbp
 mov rsi,r12
 lea rdi,[r12+hda_loopback.snapshot]
 mov ecx,3
 rep movsq
 mov dword [r12+hda_loopback.phase],HLB_GRAPH
 mov rax,-1
 mov [r12+hda_loopback.output_row],eax
 mov [r12+hda_loopback.input_row],eax
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,48
 HLB_LEAVE

hlb_identity:
 cmp rbp,[r12+hda_loopback.epoch]
 jne .bad
 lea rsi,[r12+hda_loopback.snapshot]
 mov rdi,r12
 mov ecx,3
 repe cmpsq
 jne .bad
 cmp rbp,[rbx+hda_backend.epoch]
 jne .bad
 mov rdi,[rbx+hda_backend.graph]
 mov rsi,rbp
 jmp hda_graph_owner_check
.bad:
 mov rax,-1
 ret
hlb_clock:
 push rbx
 mov r13,[rbx+hda_backend.graph]
 mov rdi,[r13+hda_graph.clock_arg]
 lea rsi,[r12+hda_loopback.last_now]
 mov r14,[rsi]
 call [r13+hda_graph.clock_fn]
 test eax,eax
 jnz .bad
 cmp [r12+hda_loopback.last_now],r14
 jb .bad
 xor eax,eax
 pop rbx
 ret
.bad:
 mov rax,-1
 pop rbx
 ret

hda_loopback_step:
 HLB_ENTER
 cmp rbp,[r12+hda_loopback.epoch]
 jne .stale
 mov eax,[r12+hda_loopback.phase]
 cmp eax,HLB_DONE
 jae .terminal
 call hlb_identity
 test rax,rax
 jnz .lost
 mov eax,[r12+hda_loopback.phase]
 cmp eax,HLB_CLEANUP
 je .cleanup
 cmp eax,HLB_DONE
 jae .terminal
 cmp eax,HLB_DISCOVERED
 je .idle_inventory
 cmp eax,HLB_READY
 je .idle_ready
 call hlb_clock
 test rax,rax
 jnz .fault
 inc qword [r12+hda_loopback.steps]
 cmp qword [r12+hda_loopback.steps],100000
 ja .fault
 mov rax,[r12+hda_loopback.last_now]
 cmp qword [r12+hda_loopback.deadline],0
 jne .timed
 add rax,5000000
 jc .fault
 mov [r12+hda_loopback.deadline],rax
.timed:
 mov rax,[r12+hda_loopback.last_now]
 cmp rax,[r12+hda_loopback.deadline]
 jae .fault
 mov eax,[r12+hda_loopback.phase]
 cmp eax,HLB_FEED
 je .feed
 cmp eax,HLB_GRAPH
 je .graph
 cmp eax,HLB_PINS
 je .pins
 cmp eax,HLB_CONFIGURE
 je .configure
 cmp eax,HLB_INPUT
 je .input
 cmp eax,HLB_PLAY
 je .play
 cmp eax,HLB_DRAIN
 je .drain
 jmp .fault
.feed:
 ; ONE <=1024-frame native submission per owner turn. Already-open handle;
 ; Short diagnostic queues the complete file; cyclic mode primes4096 frames
 ; before one output start, then alternates bounded feed and backend service.
 HLB_BACKEND hda_backend_device
 cmp rax,[r12+hda_loopback.device]
 jne .fault
 test rax,rax
 jz .fault
 cmp dword [r12+hda_loopback.streaming],0
 je .feed_remaining
 mov rcx,[r12+hda_loopback.play_frames]
 cmp rcx,4096
 jbe .prime_target
 mov ecx,4096
.prime_target:
 cmp [r12+hda_loopback.play_cursor],rcx
 jae .feed_done
.feed_remaining:
 mov rcx,[r12+hda_loopback.play_frames]
 sub rcx,[r12+hda_loopback.play_cursor]
 jc .fault
 jz .feed_done
 cmp rcx,1024
 jbe .feed_size
 mov ecx,1024
.feed_size:
 shl rcx,1
 mov r13,rcx
 mov rdx,[r12+hda_loopback.play_cursor]
 shl rdx,1
 add rdx,[r12+hda_loopback.play_pcm]
 mov rdi,rax
 mov rsi,[r12+hda_loopback.handle]
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.submit]
 test rax,rax
 js .yield                      ; refusal accepts NO bytes; bounded deadline
 cmp rax,r13
 ja .fault                      ; uncertain acceptance is never retried
 test al,1
 jnz .fault
 shr rax,1
 add [r12+hda_loopback.play_cursor],rax
 jmp .yield
.feed_done:
 ; Refresh the selected physical routes before activating either stream.
 mov dword [r12+hda_loopback.phase],HLB_INPUT
 jmp .yield
.graph:
 HLB_BACKEND hda_backend_step
 cmp rax,3
 jne .child
 mov dword [r12+hda_loopback.phase],HLB_PINS
 jmp .yield
.pins:
 call hlb_pin_step
 test rax,rax
 js .fault
 cmp eax,2
 jne .yield
 mov dword [r12+hda_loopback.phase],HLB_DISCOVERED
.idle_inventory:
 HLB_BACKEND hda_backend_discovery_check
 test rax,rax
 jnz .fault
 call hlb_clock
 test rax,rax
 jnz .fault
.inventory:
 mov eax,3
 jmp .out
.configure:
 cmp dword [r12+hda_loopback.muted],1
 je .configure_backend
 call hlb_mute_step
 test rax,rax
 js .fault
 cmp eax,2
 jne .yield
 mov dword [r12+hda_loopback.muted],1
 jmp .yield
.configure_backend:
 HLB_BACKEND hda_backend_step
 test rax,rax
 js .fault
 cmp dword [rbx+hda_backend.phase],HDAB_READY
 jne .yield
 cmp dword [r12+hda_loopback.output_only],1
 jne .configure_paired
 cmp dword [rbx+hda_backend.input_state],6
 jne .fault
 jmp .configured
.configure_paired:
 cmp dword [rbx+hda_backend.input_state],3
 jne .yield
.configured:
 mov dword [r12+hda_loopback.phase],HLB_READY
.idle_ready:
 HLB_BACKEND hda_backend_device
 test rax,rax
 jz .fault
 call hlb_clock
 test rax,rax
 jnz .fault
.ready:
 mov eax,4
 jmp .out
.input:
 ; started0/1 refreshes selected senses;2 admits the finite input;4 waits
 ; for its existing RUN acknowledgement;5 has primed cyclic output while
 ; both streams were stopped;3 means output was started. Do not
 ; spend any of the bounded input window on pre-start sense transactions.
 mov eax,[r12+hda_loopback.started]
 cmp eax,4
 je .input_running
 cmp eax,5
 je .begin_input
 cmp eax,2
 je .start_input
 test eax,eax
 jz .refresh
 cmp dword [r12+hda_loopback.output_only],1
 je .start_output
.refresh:
 inc dword [r12+hda_loopback.started]
 mov ecx,[r12+hda_loopback.output_row]
 cmp eax,0
 je .sense_row
 mov ecx,[r12+hda_loopback.input_row]
.sense_row:
 mov [r12+hda_loopback.query_row],ecx
 mov dword [r12+hda_loopback.query_state],0
 mov dword [r12+hda_loopback.query_trigger],0
 mov dword [r12+hda_loopback.phase],HLB_PLAY
 jmp .yield
.start_input:
 cmp dword [r12+hda_loopback.streaming],1
 je .start_output
 cmp dword [r12+hda_loopback.streaming],2
 jne .begin_input
 ; Prepare the same four stopped-output periods BEFORE consuming the finite
 ; first2048 ADC window. One period per owner turn, original deadline intact.
 HLB_BACKEND hda_backend_prime_cyclic
 test rax,rax
 js .fault
 jnz .yield
 mov dword [r12+hda_loopback.started],5
 jmp .yield
.begin_input:
 HLB_BACKEND hda_backend_input_start
 test rax,rax
 js .fault
 mov dword [r12+hda_loopback.started],4
 jmp .yield
.input_running:
 HLB_BACKEND hda_backend_step
 test rax,rax
 js .fault
 mov r13,[rbx+hda_backend.input]
 cmp dword [r13+hda_input.stream_phase],HDI_RUNNING
 jne .yield
.start_output:
 HLB_BACKEND hda_backend_start
 test rax,rax
 js .fault
 mov dword [r12+hda_loopback.started],3
 mov dword [r12+hda_loopback.phase],HLB_PLAY
 jmp .yield
.play:
 cmp dword [r12+hda_loopback.started],3
 je .playing
 call hlb_sense_step
 test rax,rax
 js .fault
 cmp eax,2
 jne .yield
 call hlb_selected_present
 test eax,eax
 jnz .fault
 mov dword [r12+hda_loopback.phase],HLB_INPUT
 jmp .yield
.playing:
 cmp dword [r12+hda_loopback.streaming],0
 jne .stream_playing
 cmp dword [r12+hda_loopback.output_only],1
 je .stream_eof
 HLB_BACKEND hda_backend_step
 test rax,rax
 js .fault
 mov r13,[rbx+hda_backend.input]
 cmp dword [r13+hda_input.stream_phase],HDI_BATCH
 jne .yield
 mov rdi,rbx
 mov rsi,rbp
 mov rdx,[r12+hda_loopback.recording]
 mov ecx,2048
 call hda_backend_input_take
 test rax,rax
 js .fault
 mov [r12+hda_loopback.captured_frames],rax
 cmp eax,2048
 jne .fault
 HLB_BACKEND hda_backend_drain
 test rax,rax
 js .fault
 mov dword [r12+hda_loopback.phase],HLB_DRAIN
 jmp .yield
.stream_playing:
 cmp dword [r12+hda_loopback.streaming],2
 jne .stream_input_ok
 cmp dword [rbx+hda_backend.input_state],3
 jne .fault
.stream_input_ok:
 ; Service an issued RUN before another feed turn. The backend also gives
 ; that pending acknowledgment its next child turn; otherwise the two
 ; alternations can defer a5ms primitive wait across four owner turns.
 ; This changes no deadline, position evidence or frame-credit rule.
 mov r13,[rbx+hda_backend.output]
 cmp dword [r13+hda_output.state],HDAO_STARTING
 je .stream_service
 ; One bounded vtable submit OR existing backend operation, same open handle.
 ; Queue fullness accepts0 without advancing; native PCM services retired
 ; periods while the complete immutable finite source stays pinned.
 xor dword [r12+hda_loopback.stream_turn],1
 cmp dword [r12+hda_loopback.stream_turn],0
 je .stream_service
 mov rcx,[r12+hda_loopback.play_frames]
 sub rcx,[r12+hda_loopback.play_cursor]
 jc .fault
 jz .stream_eof
 cmp rcx,1024
 jbe .stream_size
 mov ecx,1024
.stream_size:
 shl rcx,1
 mov r13,rcx
 HLB_BACKEND hda_backend_device
 test rax,rax
 jz .fault
 cmp rax,[r12+hda_loopback.device]
 jne .fault
 mov rdx,[r12+hda_loopback.play_cursor]
 shl rdx,1
 add rdx,[r12+hda_loopback.play_pcm]
 mov rcx,r13
 mov rdi,rax
 mov rsi,[r12+hda_loopback.handle]
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.submit]
 test rax,rax
 js .yield
 cmp rax,r13
 ja .fault
 test al,1
 jnz .fault
 shr rax,1
 add [r12+hda_loopback.play_cursor],rax
 jmp .yield
.stream_eof:
 HLB_BACKEND hda_backend_drain
 test rax,rax
 js .fault
 mov dword [r12+hda_loopback.phase],HLB_DRAIN
 jmp .yield
.stream_service:
 HLB_BACKEND hda_backend_step
 test rax,rax
 js .fault
 cmp dword [r12+hda_loopback.streaming],2
 jne .yield
 cmp qword [r12+hda_loopback.captured_frames],0
 jne .yield
 mov r13,[rbx+hda_backend.input]
 cmp dword [r13+hda_input.stream_phase],HDI_BATCH
 jne .yield
 mov rdi,rbx
 mov rsi,rbp
 mov rdx,[r12+hda_loopback.recording]
 mov ecx,2048
 call hda_backend_input_take
 cmp rax,2048
 jne .fault
 mov [r12+hda_loopback.captured_frames],rax
 jmp .yield
.drain:
 HLB_BACKEND hda_backend_step
 test rax,rax
 js .fault
 mov r13,[rbx+hda_backend.pcm]
 cmp dword [r13+hda_pcm.phase],HDPCM_DRAINED
 jne .yield
 mov rax,[r13+hda_pcm.consumed_frames]
 mov [r12+hda_loopback.played_frames],rax
 mov rcx,LB_FIXTURE_FRAMES
 cmp qword [r12+hda_loopback.play_pcm],0
 je .drain_count
 mov rcx,[r12+hda_loopback.play_frames]
.drain_count:
 cmp rax,rcx
 jne .fault
 cmp dword [r12+hda_loopback.streaming],2
 jne .capture_complete
 cmp qword [r12+hda_loopback.captured_frames],2048
 jne .fault
.capture_complete:
 mov dword [r12+hda_loopback.successful],1
 jmp .halt
.child:
 test rax,rax
 js .fault
.yield:
 mov eax,1
 jmp .out
.fault:
 mov dword [r12+hda_loopback.error],1
 mov dword [r12+hda_loopback.successful],0
.halt:
 HLB_BACKEND hda_backend_halt
 test rax,rax
 js .lost
 mov dword [r12+hda_loopback.phase],HLB_CLEANUP
 jmp .yield
.cleanup:
 HLB_BACKEND hda_backend_step
 cmp dword [rbx+hda_backend.phase],HDAB_UNCERTAIN
 je .lost
 test rax,rax
 js .yield                      ; only bounded existing HALT cleanup may continue
 cmp dword [rbx+hda_backend.phase],HDAB_STOPPED
 jne .yield
 HLB_BACKEND hda_backend_retire
 test rax,rax
 js .lost
 mov dword [r12+hda_loopback.phase],HLB_FAILED
 cmp dword [r12+hda_loopback.successful],1
 jne .terminal
 mov dword [r12+hda_loopback.phase],HLB_DONE
.terminal:
 mov eax,2
 jmp .out
.stale:
 mov rax,-1
 jmp .out
.lost:
 ; No rebind/free/foreign reset. Exact old storage remains pinned.
 mov dword [r12+hda_loopback.phase],HLB_UNCERTAIN
 mov rax,-1
.out:
 HLB_LEAVE

; Inventory production rows, including UNKNOWN senses. No guessed pin role.
hlb_pin_step:
 push rbx
 cmp dword [r12+hda_loopback.query_state],0
 jne .sense
 mov r13,[rbx+hda_backend.graph]
 mov ecx,[r12+hda_loopback.widget_index]
 cmp ecx,[r13+hda_graph.public_widget_count]
 jae .done
 mov rax,[r13+hda_graph.widgets]
 shl ecx,5
 add rax,rcx
 inc dword [r12+hda_loopback.widget_index]
 mov ecx,[rax+hda_widget_info.caps]
 shr ecx,20
 and ecx,15
 cmp ecx,4
 jne .yield
 mov ecx,[r12+hda_loopback.pin_count]
 cmp ecx,HLB_PIN_CAP
 jae .bad
 imul edx,ecx,hda_loopback_pin_size
 mov rdi,[r12+hda_loopback.pins]
 add rdi,rdx
 mov rsi,rax
 push rcx
 mov ecx,6
 rep movsd
 pop rcx
 mov [r12+hda_loopback.query_row],ecx
 inc dword [r12+hda_loopback.pin_count]
 mov dword [r12+hda_loopback.query_state],1
.sense:
 call hlb_sense_step
 cmp eax,2
 jne .out
 mov dword [r12+hda_loopback.query_state],0
.yield:
 mov eax,1
.out:
 pop rbx
 ret
.done:
 mov eax,2
 pop rbx
 ret
.bad:
 mov rax,-1
 pop rbx
 ret

; One fixed GET_PIN_SENSE per selected row, retained across busy/pending. No
; raw verb API. Trigger-required pins issue fixed SET_PIN_SENSE, retain its
; acknowledgement and then GET_PIN_SENSE. No duplicate trigger after timeout.
hlb_sense_step:
 push rbx
 mov ecx,[r12+hda_loopback.query_row]
 cmp ecx,[r12+hda_loopback.pin_count]
 jae .bad
 imul ecx,hda_loopback_pin_size
 mov r14,[r12+hda_loopback.pins]
 add r14,rcx
 test dword [r14+hda_loopback_pin.pin_caps],4
 jz .unsupported

 cmp dword [r12+hda_loopback.phase],HLB_PINS
 jne .active_check
 HLB_BACKEND hda_backend_discovery_check
 jmp .checked
.active_check:
 HLB_BACKEND hda_backend_device
 test rax,rax
 jz .bad
.checked:
 test rax,rax
 js .bad
 mov r13,[rbx+hda_backend.graph]
 mov rdi,[r13+hda_graph.transport]
 cmp dword [r12+hda_loopback.query_state],2
 je .take
 cmp dword [rdi+hda_transport.pending],0
 jne .bad                       ; no foreign or abandoned command adoption
 mov eax,[r14+hda_loopback_pin.codec]
 shl eax,28
 mov ecx,[r14+hda_loopback_pin.nid]
 shl ecx,20
 or eax,ecx
 test dword [r14+hda_loopback_pin.pin_caps],2
 jz .get_sense
 cmp dword [r12+hda_loopback.query_trigger],0
 jne .get_sense
 or eax,0x70900
 jmp .queue
.get_sense:
 or eax,0xf0900
.queue:
 mov [r12+hda_loopback.query_command],eax
 mov esi,eax
 call hda_corb_queue
 test rax,rax
 js .bad
 test eax,eax
 jnz .yield
 mov dword [r12+hda_loopback.query_state],2
 mov dword [r12+hda_loopback.query_polls],0
 mov rax,[r12+hda_loopback.last_now]
 add rax,50000
 jc .bad
 mov [r12+hda_loopback.query_deadline],rax
 jmp .yield
.take:
 inc dword [r12+hda_loopback.query_polls]
 cmp dword [r12+hda_loopback.query_polls],4096
 ja .bad
 mov rax,[r12+hda_loopback.last_now]
 cmp rax,[r12+hda_loopback.query_deadline]
 jae .bad
 lea rsi,[r12+hda_loopback.query_response]
 call hda_rirb_take
 test rax,rax
 js .bad
 test eax,eax
 jnz .yield
 mov eax,[r12+hda_loopback.query_command]
 and eax,0xfffff
 cmp eax,0x70900
 jne .sense_reply
 cmp dword [r12+hda_loopback.query_response],0
 jne .bad
 mov dword [r12+hda_loopback.query_trigger],1
 mov dword [r12+hda_loopback.query_state],1
 jmp .yield
.sense_reply:
 mov eax,[r12+hda_loopback.query_response]
 mov [r14+hda_loopback_pin.sense],eax
 mov dword [r12+hda_loopback.query_trigger],0
 mov dword [r14+hda_loopback_pin.known],1
 mov dword [r12+hda_loopback.query_state],0
 mov eax,2
 pop rbx
 ret
.unsupported:
 ; Actual graph capability lacks presence detect. Do not issue unsupported
 ; verbs or turn this into a sensed/present jack; retain the distinction.
 mov dword [r14+hda_loopback_pin.sense],0
 mov dword [r14+hda_loopback_pin.known],2
 mov dword [r12+hda_loopback.query_state],0
 mov eax,2
 pop rbx
 ret
.yield:
 mov eax,1
 pop rbx
 ret
.bad:
 mov rax,-1
 pop rbx
 ret

 ; A selected DAC may feed more than one pin. Before programming/starting it,
 ; disable EVERY other analog output pin with an attributed SET0+GET0 readback.
 ; This includes speakers and unknown unselected device types. Never infer that
 ; a selected headphone pin alone mutes a firmware-enabled speaker path.
hlb_mute_step:
 push rbx
 HLB_BACKEND hda_backend_discovery_check
 test rax,rax
 jnz .bad
 mov eax,[r12+hda_loopback.mute_index]
 cmp eax,[r12+hda_loopback.pin_count]
 jae .done
 imul eax,hda_loopback_pin_size
 mov r14,[r12+hda_loopback.pins]
 add r14,rax
 test dword [r14+hda_loopback_pin.caps],0x200
 jnz .next
 test dword [r14+hda_loopback_pin.pin_caps],0x10
 jz .next
 mov eax,[r12+hda_loopback.mute_index]
 cmp eax,[r12+hda_loopback.output_row]
 je .next
 mov r13,[rbx+hda_backend.graph]
 mov rdi,[r13+hda_graph.transport]
 mov eax,[r12+hda_loopback.mute_state]
 test eax,1
 jnz .take
 cmp dword [rdi+hda_transport.pending],0
 jne .bad
 mov eax,[r14+hda_loopback_pin.codec]
 shl eax,28
 mov ecx,[r14+hda_loopback_pin.nid]
 shl ecx,20
 or eax,ecx
 cmp dword [r12+hda_loopback.mute_state],2
 je .get
 or eax,0x70700
 jmp .queue
.get:
 or eax,0xf0700
.queue:
 mov esi,eax
 call hda_corb_queue
 test rax,rax
 js .bad
 test eax,eax
 jnz .yield
 inc dword [r12+hda_loopback.mute_state]
 mov dword [r12+hda_loopback.query_polls],0
 mov rax,[r12+hda_loopback.last_now]
 add rax,50000
 jc .bad
 mov [r12+hda_loopback.query_deadline],rax
 jmp .yield
.take:
 inc dword [r12+hda_loopback.query_polls]
 cmp dword [r12+hda_loopback.query_polls],4096
 ja .bad
 mov rax,[r12+hda_loopback.last_now]
 cmp rax,[r12+hda_loopback.query_deadline]
 jae .bad
 lea rsi,[r12+hda_loopback.query_response]
 call hda_rirb_take
 test rax,rax
 js .bad
 test eax,eax
 jnz .yield
 cmp dword [r12+hda_loopback.query_response],0
 jne .bad                         ; SET reserved reply0 and verified GET_CTL0
 cmp dword [r12+hda_loopback.mute_state],3
 je .next
 mov dword [r12+hda_loopback.mute_state],2
 jmp .yield
.next:
 mov dword [r12+hda_loopback.mute_state],0
 inc dword [r12+hda_loopback.mute_index]
.yield:
 mov eax,1
 pop rbx
 ret
.done:
 mov eax,2
 pop rbx
 ret
.bad:
 mov rax,-1
 pop rbx
 ret

; rdi=actual pin row,0 ready/-1 unknown, absent or inconsistent.
; A non-detecting pin is usable only with explicit unsupported state and zero
; sense. A detecting pin still needs an attributed present GET_PIN_SENSE reply.
hlb_pin_sense_ready:
 test dword [rdi+hda_loopback_pin.pin_caps],4
 jz .unsupported
 cmp dword [rdi+hda_loopback_pin.known],1
 jne .bad
 test dword [rdi+hda_loopback_pin.sense],0x80000000
 jz .bad
 xor eax,eax
 ret
.unsupported:
 cmp dword [rdi+hda_loopback_pin.known],2
 jne .bad
 cmp dword [rdi+hda_loopback_pin.sense],0
 jne .bad
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

hlb_selected_present:
 mov ecx,[r12+hda_loopback.output_row]
 cmp ecx,[r12+hda_loopback.pin_count]
 jae .bad
 imul ecx,hda_loopback_pin_size
 mov r13,[r12+hda_loopback.pins]
 add r13,rcx
 test dword [r13+hda_loopback_pin.pin_caps],0x10
 jz .bad
 mov eax,[r13+hda_loopback_pin.config]
 shr eax,30
 cmp eax,1
 je .bad
 test dword [r13+hda_loopback_pin.caps],0x200
 jnz .bad
 mov eax,[r13+hda_loopback_pin.config]
 shr eax,20
 and eax,15
 cmp eax,1
 je .fixed_speaker
 cmp eax,0                       ; external lineout/headphone still needs sense
 je .output_sense
 cmp eax,2
 jne .bad
.output_sense:
 mov rdi,r13
 call hlb_pin_sense_ready
 test rax,rax
 jnz .bad
 jmp .output_ok
.fixed_speaker:
 ; Explicit output-only fixed speakers have no jack insertion to detect.
 ; Keep complete attributed sense state, but do not require its presence bit.
 ; Duplex selection and external/disconnected/both speaker ports stay refused.
 cmp dword [r12+hda_loopback.output_only],1
 jne .bad
 mov eax,[r13+hda_loopback_pin.config]
 shr eax,30
 cmp eax,2
 jne .bad
 test dword [r13+hda_loopback_pin.pin_caps],4
 jz .output_sense                ; unsupported state2/zero is still required
 cmp dword [r13+hda_loopback_pin.known],1
 jne .bad
.output_ok:
 cmp dword [r12+hda_loopback.output_only],1
 je .ok
 mov ecx,[r12+hda_loopback.input_row]
 cmp ecx,[r12+hda_loopback.pin_count]
 jae .bad
 imul ecx,hda_loopback_pin_size
 mov r14,[r12+hda_loopback.pins]
 add r14,rcx
 mov rdi,r14
 call hlb_pin_sense_ready
 test rax,rax
 jnz .bad
 test dword [r14+hda_loopback_pin.pin_caps],0x20
 jz .bad
 mov eax,[r14+hda_loopback_pin.config]
 shr eax,30
 cmp eax,1
 je .bad
 test dword [r14+hda_loopback_pin.caps],0x200
 jnz .bad
 mov eax,[r14+hda_loopback_pin.config]
 shr eax,20
 and eax,15
 cmp eax,8
 je .ok
 cmp eax,10
 jne .bad
.ok:
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

hda_loopback_select:
 xor r9d,r9d
 jmp hlb_select
hda_loopback_select_output:
 mov r9d,1
 jmp hlb_select
hda_loopback_select_output48:
 mov r9d,2
 jmp hlb_select
hda_loopback_select48:
 mov r9d,3
hlb_select:
 HLB_ENTER
 sub rsp,80
 mov [rsp],rdx
 mov [rsp+56],r9d
 mov eax,[r12+hda_loopback.output_only]
 mov [rsp+60],eax
 lea rsi,[r12+hda_loopback.selection]
 lea rdi,[rsp+16]
 mov ecx,5
 rep movsq
 call hlb_identity
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_loopback.phase],HLB_DISCOVERED
 jne .bad
 ; Copy bounded numeric selection only after checking complete source span.
 mov rsi,[rsp]
 test rsi,rsi
 jz .bad
 lea rax,[rsi+32]
 cmp rax,rsi
 jb .bad
 mov rdx,rax
 dec rdx
 shr rdx,47
 jnz .bad
 ; Selection cannot alias this coordinator or its pin/capture storage.
 lea rdi,[r12+hda_loopback_size]
 cmp rsi,rdi
 jae .copy
 cmp r12,rax
 jb .bad
.copy:
 mov rdi,rax
 call hlb_separate
 jc .bad
 mov rsi,[rsp]
 mov rax,[r12+hda_loopback.pins]
 lea rdx,[rax+HLB_PIN_CAP*hda_loopback_pin_size]
 cmp rsi,rdx
 jae .capture_span
 lea rdx,[rsi+32]
 cmp rax,rdx
 jb .bad
.capture_span:
 mov rax,[r12+hda_loopback.recording]
 lea rdx,[rax+8192]
 cmp rsi,rdx
 jae .copy_ok
 lea rdx,[rsi+32]
 cmp rax,rdx
 jb .bad
.copy_ok:
 lea rdi,[r12+hda_loopback.selection]
 mov ecx,8
 rep movsd
 xor eax,eax
 cmp dword [rsp+56],3
 je .output_mode
 cmp dword [rsp+56],0
 setne al
.output_mode:
 mov [r12+hda_loopback.output_only],eax
 cmp eax,1
 jne .fields_ok
 mov rax,[r12+hda_loopback.selection+16]
 or rax,[r12+hda_loopback.selection+24]
 jnz .bad
.fields_ok:
 mov dword [r12+hda_loopback.output_row],-1
 mov dword [r12+hda_loopback.input_row],-1
 xor ecx,ecx
.find:
 cmp ecx,[r12+hda_loopback.pin_count]
 jae .found
 imul edx,ecx,hda_loopback_pin_size
 mov r13,[r12+hda_loopback.pins]
 add r13,rdx
 mov eax,[r13+hda_loopback_pin.codec]
 cmp eax,[r12+hda_loopback.selection]
 jne .next
 mov eax,[r13+hda_loopback_pin.group]
 cmp eax,[r12+hda_loopback.selection+4]
 jne .next
 mov eax,[r13+hda_loopback_pin.nid]
 cmp eax,[r12+hda_loopback.selection+8]
 jne .in
 mov [r12+hda_loopback.output_row],ecx
.in:
 cmp eax,[r12+hda_loopback.selection+16]
 jne .next
 mov [r12+hda_loopback.input_row],ecx
.next:
 inc ecx
 jmp .find
.found:
 call hlb_selected_present
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_loopback.output_only],1
 je .route
 ; Actual captured input VRef/analog capabilities, before any route SET.
 mov eax,[r14+hda_loopback_pin.pin_caps]
 test eax,0x01000080
 jnz .bad
 mov ecx,[r12+hda_loopback.selection+28]
 cmp ecx,5
 ja .bad
 cmp ecx,3
 je .bad
 test ecx,ecx
 jnz .vref
 test eax,0xff00
 jz .vref_ok
.vref:
 add ecx,8
 bt eax,ecx
 jnc .bad
.vref_ok:
 mov eax,[r14+hda_loopback_pin.config]
 shr eax,20
 and eax,15
 cmp eax,8
 jne .route
 cmp dword [r12+hda_loopback.selection+28],0
 jne .bad
.route:
 mov rdi,rbx
 mov rsi,rbp
 lea rdx,[r12+hda_loopback.selection]
 cmp dword [r12+hda_loopback.output_only],1
 jne .paired_select
 cmp dword [rsp+56],2
 je .select48
 call hda_backend_select_output
 jmp .selected
.select48:
 call hda_backend_select_output48
 jmp .selected
.paired_select:
 cmp dword [rsp+56],3
 je .paired48
 call hda_backend_select
 jmp .selected
.paired48:
 call hda_backend_select48
.selected:
 test rax,rax
 jnz .bad
 mov qword [r12+hda_loopback.deadline],0
 mov qword [r12+hda_loopback.steps],0
 mov dword [r12+hda_loopback.phase],HLB_CONFIGURE
 xor eax,eax
 jmp .out
.bad:
 lea rsi,[rsp+16]
 lea rdi,[r12+hda_loopback.selection]
 mov ecx,5
 rep movsq
 mov eax,[rsp+60]
 mov [r12+hda_loopback.output_only],eax
 mov rax,-1
.out:
 add rsp,80
 HLB_LEAVE

hda_loopback_run:
 cmp edx,4
 je hlb_run_sustained48
 cmp edx,3
 je hlb_run_sustained
 xor r8d,r8d
 jmp hlb_run
; Owner-only corpus3 keeps one opened PCM stream across all ring wraps.
hlb_run_sustained:
 mov rax,[rdi+hda_loopback.backend]
 mov rax,[rax+hda_backend.pcm]
 cmp dword [rax+hda_pcm.rate],44100
 jne hlb_run_sustained_refuse
 mov r8d,ecx
 lea rdx,[rel lb_sustained_pcm]
 mov ecx,88200
 mov r9d,2
 jmp hlb_run_pcm
hlb_run_sustained48:
 mov rax,[rdi+hda_loopback.backend]
 mov rax,[rax+hda_backend.pcm]
 cmp dword [rax+hda_pcm.rate],48000
 jne hlb_run_sustained_refuse
 mov r8d,ecx
 lea rdx,[rel lb_sustained48_pcm]
 mov ecx,96000
 mov r9d,2
 jmp hlb_run_pcm
hlb_run_sustained_refuse:
 mov rax,-1
 ret
; Explicit output intent1. Immutable corpus3/4 reuses the cyclic PCM engine;
; admission below checks the output-only owner and exact selected rate.
hda_loopback_run_output:
 cmp ecx,1
 jne hlb_run_output_refuse
 cmp edx,3
 je hlb_run_output_sustained
 cmp edx,4
 je hlb_run_output_sustained48
 mov r8d,1
 jmp hlb_run
hlb_run_output_sustained:
 lea rdx,[rel lb_sustained_pcm]
 mov ecx,88200
 jmp hlb_run_output_stream
hlb_run_output_sustained48:
 lea rdx,[rel lb_sustained48_pcm]
 mov ecx,96000
hlb_run_output_stream:
 mov r8d,1
 mov r9d,3
 jmp hlb_run_pcm
hlb_run_output_refuse:
 mov rax,-1
 ret
hlb_run:
 HLB_ENTER
 sub rsp,16
 mov [rsp],edx
 mov [rsp+4],ecx
 mov [rsp+8],r8d
 call hlb_identity
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_loopback.phase],HLB_READY
 jne .bad
 mov eax,[rsp+8]
 cmp eax,[r12+hda_loopback.output_only]
 jne .bad
 mov edx,1
 mov rax,[rbx+hda_backend.pcm]
 cmp dword [rax+hda_pcm.rate],48000
 jne .fixture_check
 cmp dword [r12+hda_loopback.output_only],1
 jne .bad
 mov edx,2                       ; same immutable PCM vector at48k
.fixture_check:
 cmp [rsp],edx
 jne .bad
 mov eax,[rsp+4]
 dec eax
 cmp eax,1
 ja .bad                        ; explicit self-loop/line-in patch intent
 call hlb_selected_present
 test rax,rax
 jnz .bad
 HLB_BACKEND hda_backend_device
 test rax,rax
 jz .bad
 mov [r12+hda_loopback.device],rax
 lea rdi,[r12+hda_loopback.params]
 xor eax,eax
 mov ecx,snd_stream_params_size/4
 rep stosd
 mov rax,[rbx+hda_backend.pcm]
 mov eax,[rax+hda_pcm.rate]
 mov [r12+hda_loopback.params+snd_stream_params.rate],eax
 mov dword [r12+hda_loopback.params+snd_stream_params.format],1
 mov dword [r12+hda_loopback.params+snd_stream_params.channels],1
 mov dword [r12+hda_loopback.params+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 mov [r12+hda_loopback.params+snd_stream_params.session_group],rbp
 mov rdi,[r12+hda_loopback.device]
 lea rsi,[r12+hda_loopback.params]
 lea rdx,[r12+hda_loopback.handle]
 xor ecx,ecx
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.open]
 test rax,rax
 js .run_fault
 mov rdi,[r12+hda_loopback.device]
 mov rsi,[r12+hda_loopback.handle]
 lea rdx,[rel lb_fixture_pcm]
 mov ecx,LB_FIXTURE_FRAMES*2
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.submit]
 cmp rax,LB_FIXTURE_FRAMES*2
 jne .run_fault                 ; no partial corpus or duplicate retry
 ; Input stays configured/stopped until both selected senses are fresh.
 mov eax,[rsp+4]
 mov [r12+hda_loopback.wiring],eax
 mov qword [r12+hda_loopback.deadline],0
 mov qword [r12+hda_loopback.steps],0
 mov dword [r12+hda_loopback.phase],HLB_INPUT
 xor eax,eax
 jmp .out
.run_fault:
 mov dword [r12+hda_loopback.error],3
 HLB_BACKEND hda_backend_halt
 mov dword [r12+hda_loopback.phase],HLB_CLEANUP
 test rax,rax
 jns .bad
 mov dword [r12+hda_loopback.phase],HLB_UNCERTAIN
.bad:
 mov rax,-1
.out:
 add rsp,16
 HLB_LEAVE

; Actual native file consumer handoff: RDI=owner RSI=epoch RDX=stable mono
; S16LE44.1k PCM RCX=1..2048 frames R8D=explicit wiring1/2. The file owner
; validates current source/session before this call and EVERY feeding turn.
; No caller pointers on the wire. This API opens an exclusive existing backend
; stream once, then HLB_FEED submits bounded prefixes through its real vtable.
hda_loopback_run_pcm:
 xor r9d,r9d
 jmp hlb_run_pcm
hda_loopback_run_pcm_stream:
 mov r9d,1
hlb_run_pcm:
 HLB_ENTER
 sub rsp,32
 mov [rsp],rdx
 mov [rsp+8],rcx
 mov [rsp+16],r8d
 mov [rsp+24],r9d
 call hlb_identity
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_loopback.phase],HLB_READY
 jne .bad
 mov rax,[rsp+8]
 dec rax
 cmp dword [rsp+24],0
 jne .stream_length
 cmp rax,2047
 ja .bad
 jmp .length_ok
.stream_length:
 cmp rax,2048
 jb .bad
 cmp rax,95999
 ja .bad
.length_ok:
 cmp dword [rsp+24],3
 je .output_mode
 cmp dword [rsp+24],2
 jne .mode_ok
 cmp dword [r12+hda_loopback.output_only],0
 jne .bad
 cmp dword [rbx+hda_backend.input_state],3
 jne .bad
 jmp .mode_ok
.output_mode:
 cmp dword [r12+hda_loopback.output_only],1
 jne .bad
 cmp dword [rbx+hda_backend.input_state],6
 jne .bad
 cmp dword [rsp+16],1
 jne .bad
.mode_ok:
 ; File consumers retain their original44.1k contract. Immutable output-only
 ; profiles must match their selected rate; paired profiles also match input.
 mov rax,[rbx+hda_backend.pcm]
 cmp dword [rsp+24],3
 je .output_rate
 cmp dword [rsp+24],2
 je .paired_rate
 cmp dword [rax+hda_pcm.rate],44100
 jne .bad
 jmp .rate_ok
.paired_rate:
 mov edx,[rax+hda_pcm.rate]
 mov rax,[rbx+hda_backend.input]
 cmp [rax+hda_input.rate],edx
 jne .bad
 jmp .rate_ok
.output_rate:
 mov edx,44100
 cmp qword [rsp+8],88200
 je .output_rate_check
 cmp qword [rsp+8],96000
 jne .bad
 mov edx,48000
.output_rate_check:
 cmp [rax+hda_pcm.rate],edx
 jne .bad
.rate_ok:
 mov eax,[rsp+16]
 dec eax
 cmp eax,1
 ja .bad
 mov rsi,[rsp]
 test rsi,rsi
 jz .bad
 test sil,1
 jnz .bad
 mov rdi,[rsp+8]
 shl rdi,1
 add rdi,rsi
 jc .bad
 mov rax,rdi
 dec rax
 shr rax,47
 jnz .bad
 ; Complete source must not alias owner, inventory, capture or any DMA/control.
 mov rax,r12
 lea rdx,[r12+hda_loopback_size]
 cmp rsi,rdx
 jae .owner_ok
 cmp rax,rdi
 jb .bad
.owner_ok:
 mov rax,[r12+hda_loopback.pins]
 lea rdx,[rax+HLB_PIN_CAP*hda_loopback_pin_size]
 cmp rsi,rdx
 jae .pins_ok
 cmp rax,rdi
 jb .bad
.pins_ok:
 mov rax,[r12+hda_loopback.recording]
 lea rdx,[rax+8192]
 cmp rsi,rdx
 jae .record_ok
 cmp rax,rdi
 jb .bad
.record_ok:
 call hlb_separate
 jc .bad
 call hlb_selected_present
 test rax,rax
 jnz .bad
 HLB_BACKEND hda_backend_device
 test rax,rax
 jz .bad
 mov [r12+hda_loopback.device],rax
 lea rdi,[r12+hda_loopback.params]
 xor eax,eax
 mov ecx,snd_stream_params_size/4
 rep stosd
 mov rax,[rbx+hda_backend.pcm]
 mov eax,[rax+hda_pcm.rate]
 mov [r12+hda_loopback.params+snd_stream_params.rate],eax
 mov dword [r12+hda_loopback.params+snd_stream_params.format],1
 mov dword [r12+hda_loopback.params+snd_stream_params.channels],1
 mov dword [r12+hda_loopback.params+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 mov [r12+hda_loopback.params+snd_stream_params.session_group],rbp
 mov rdi,[r12+hda_loopback.device]
 lea rsi,[r12+hda_loopback.params]
 lea rdx,[r12+hda_loopback.handle]
 xor ecx,ecx
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.open]
 test rax,rax
 js .run_fault
 cmp dword [rsp+24],0
 je .mode_bound
 mov rdi,[rbx+hda_backend.pcm]
 mov rsi,rbp
 mov rdx,[rsp+8]
 call hda_pcm_enable_cyclic
 test rax,rax
 js .run_fault
.mode_bound:
 mov eax,[rsp+24]
 mov [r12+hda_loopback.streaming],eax
 mov rax,[rsp]
 mov [r12+hda_loopback.play_pcm],rax
 mov rax,[rsp+8]
 mov [r12+hda_loopback.play_frames],rax
 mov qword [r12+hda_loopback.play_cursor],0
 mov eax,[rsp+16]
 mov [r12+hda_loopback.wiring],eax
 mov qword [r12+hda_loopback.deadline],0
 mov qword [r12+hda_loopback.steps],0
 mov dword [r12+hda_loopback.phase],HLB_FEED
 xor eax,eax
 jmp .out
.run_fault:
 mov dword [r12+hda_loopback.error],3
 HLB_BACKEND hda_backend_halt
 mov dword [r12+hda_loopback.phase],HLB_CLEANUP
 test rax,rax
 jns .bad
 mov dword [r12+hda_loopback.phase],HLB_UNCERTAIN
.bad:
 mov rax,-1
.out:
 add rsp,32
 HLB_LEAVE

hda_loopback_cancel:
 HLB_ENTER
 call hlb_identity
 test rax,rax
 jnz .bad
 mov dword [r12+hda_loopback.successful],0
 mov dword [r12+hda_loopback.error],2
 HLB_BACKEND hda_backend_halt
 test rax,rax
 js .bad
 mov dword [r12+hda_loopback.phase],HLB_CLEANUP
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 HLB_LEAVE
hda_loopback_release:
 HLB_ENTER
 cmp rbp,[r12+hda_loopback.epoch]
 jne .bad
 mov eax,[r12+hda_loopback.phase]
 cmp eax,HLB_DONE
 je .check
 cmp eax,HLB_FAILED
 jne .bad
.check:
 cmp dword [rbx+hda_backend.phase],HDAB_RETIRED
 jne .bad
 mov dword [r12+hda_loopback.phase],HLB_RELEASED
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 HLB_LEAVE
%unmacro HLB_EXCLUDE 2
%include "dev/snd/hda_loopback_fixture.inc"
