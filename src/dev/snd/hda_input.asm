;; MODULE dev/snd/hda_input
;; LAYER 3
;; EXPORTS hda_input_begin, hda_input_step, hda_input_start, hda_input_take, hda_input_stop, hda_input_retire, hda_input_batch_check
;; IMPORTS boot/native_driver_gate, dev/snd/hda_input_route, dev/snd/hda_route_program, dev/snd/hda_session, dev/snd/hda_pcm, core/dma
;; CAPS mmio dma
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_INPUT_POWER 0
 cmp qword [rel hda_input_power_gate],0
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
 call [rel hda_input_power_gate]
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
; Private analogue microphone/line-in input, no registration/PCI/attach/alloc.
; Input edges are ADC->selector/mixer->physical pin. Uses accepted bounded
; script emission primitives, explicit capability inheritance, input amps and
; input PinCtl (never the output route or output readiness). Intel HDA rev1.0a
; 7.2.3.2-3,7.3.3.2/7-8/10-13,7.3.4.6-12 and 3.3.35-40/3.6.1-3:
; https://www.intel.com/content/dam/www/public/us/en/documents/product-specifications/high-definition-audio-specification.pdf
; Existing Classic/RC four-period BDL/control layout retained, no read-only
; LPIB write. No Linux driver implementation input. Dynamic multi-SDI assignment
; remains unsupported; keep existing codec SDI binding, input stream tag routes
; data transparently. Strict attributed transport retains its primary-CAD limits.
;
; Context begins with the existing private hda_route_program script layout;
; only explicit script helpers reuse that prefix. Input planner/readiness and
; engine are independent. All required queries before ANY SET. Exact ADC
; channel count1/2; direct/one selector/one mixer; no digital/proc/stripe/ext
; channels. Caller explicitly chooses VRef0/1/2/4/5 from actual supported bits
; (Line In requires0); no voltage guessed from node type. Unity Offset gain,
; mono left only/stereo both, ADC/pin input amp index0, mixer expanded index.
; Multi-input mixer requires mute-capable input amps and <=16 entries. Preserve
; completed disjoint output route; overlapping widgets/tag refuse. Shared AFG
; already D0 is queried, not reprogrammed. Current enforcing DID3 receipt and
; exact nonzero serial checked for all active work/copy/start. No identity DMA.
;
; Caller prebinds global position buffer before graph/command DMA; this client
; VERIFYs DPLBASE/DPUBASE and NEVER replaces them or resets another stream.
; Input SD index is explicit <GCAP.ISS; input indices precede outputs. Caller
; owns full controller, stable tagged/pinned mapped DMA buffers/epoch, clock Hz
; and serialized calls/IRQs. Unknown running streams refuse; one represented
; output PCM owner may remain running, with disjoint VAs/IOVAs/tag. No CRST or
; global flush. Graph reset waits until both PCM output and input are quiescent.
;
; begin(ctx,epoch)->0/-1, step->1 yield/2 ready or batch readable/-1 failure.
; start(ctx,epoch)->1 scheduled/-1. take(ctx,epoch,dst,max_frames)->actual
; whole frames/0 drained/-1. stop->1 pending/0 verified stopped/-1.
; Stop retries retain the original pending phase/deadline/poll budget; FAILED
; cannot be revived. retire->0 software only/-1.
; Explicit private calls only; no automatic boot/hardware activity. Fresh
; context or strictly newer epoch after retirement. One sticky input claim per
; graph epoch. Inputs immutable, mappedness trusted; spans checked full64.
;
; Bounded stopped batch: target1..2048 frames, <=8192 bytes in four4KiB ring.
; Before RUN, verify reset set/clear, configure own descriptor, wait input
; FIFORDY. Record zero initial LPIB/DPL and calibrated elapsed bound below
; (16384-FIFOS)/byte_rate. Stable equal LPIB/DPL, monotone position, rate/FIFO
; envelope and BCIS crossing evidence qualify complete bytes. Never unwrap
; modulo position or infer audible time. At target clear RUN, VERIFY stop and
; SRST1, then copy only qualified prefix to the software queue. Reset FIFO may
; discard unconfirmed tail; it never becomes published capture. No ring reads
; while live or unverified-stop; no overwriting an unread queue (backpressure).
; Cancel/fault revokes input readiness immediately and preserves buffers/queue;
; uncertain stop/reset retains claim/mappings and needs owner recovery. No DMA
; free, fullRC/platform/audio/acoustic/timing success claim. Polls<=4096 even
; frozen clock, finite script and batch deadlines, SysV GPR/RSP/DF0, no FP.

HDI_IDLE equ 0
HDI_STOP equ 1
HDI_RESET_SET equ 2
HDI_RESET_CLEAR equ 3
HDI_FIFO equ 4
HDI_STARTING equ 5
HDI_RUNNING equ 6
HDI_HALTING equ 7
HDI_DRAIN_RESET equ 8
HDI_BATCH equ 9
HDI_STOPPED equ 10
HDI_FAILED equ 11
HDI_RETIRED equ 12
struc hda_input
 .program: resb hda_route_program_size
 .route: resb hda_input_route_size
 .bdl: resq 1
 .bdl_dma: resq 1
 .pcm: resq 1
 .pcm_dma: resq 1
 .position: resq 1
 .position_dma: resq 1
 .queue: resq 1
 .queue_bytes: resq 1
 .map_serial: resq 1
 .clock_hz: resq 1
 .rate: resd 1
 .vref: resd 1
 .sd_index: resd 1
 .batch_frames: resd 1
 .stream_phase: resd 1
 .stream_error: resd 1
 .operation: resd 1                ;0 capture,1 cancel/fault
 .stream_polls: resd 1
 .state_deadline: resq 1
 .run_start: resq 1
 .run_ticks: resq 1
 .captured_frames: resq 1
 .taken_frames: resq 1
 .fifo: resd 1
 .frame_bytes: resd 1
 .target_bytes: resd 1
 .last_pos: resd 1
 .qualified: resd 1
 .ready_bytes: resd 1
 .read_offset: resd 1
 .retired: resd 1
 .fg_now: resd 1
 .power_now: resd 3
 .spans: resb 160
 .config: resb 176                ;route72, DMA/config96, exact graph pointer
 ; First position rejection: diagnostic only, never grants capture credit.
 .failure_reason: resq 1
 .failure_epoch: resq 1
 .failure_phase: resq 1
 .failure_now: resq 1
 .failure_run_start: resq 1
 .failure_run_ticks: resq 1
 .failure_clock_hz: resq 1
 .failure_rate: resq 1
 .failure_fifo: resq 1
 .failure_frame_bytes: resq 1
 .failure_target_bytes: resq 1
 .failure_last_pos: resq 1
 .failure_qualified: resq 1
 .failure_captured_frames: resq 1
 .failure_taken_frames: resq 1
 .failure_ready_bytes: resq 1
 .failure_read_offset: resq 1
 .failure_raw_pos: resq 1
 .failure_raw_dpl: resq 1
 .failure_raw_valid: resq 1
 .failure_polls: resq 1
 .failure_deadline: resq 1
 .failure_sd_control: resq 1
 .failure_sd_status: resq 1
 ; Latest RUNNING observation, independent of the first failure record.
 ; valid: bit0 LPIB1, bit1 DPL, bit2 LPIB2; SD CTL/STS sampled before them.
 ; Retained through cleanup/retire; cleared by an admitted begin only.
 .observation_count: resq 1
 .observation_now: resq 1
 .observation_lpib_first: resq 1
 .observation_dpl: resq 1
 .observation_lpib_last: resq 1
 .observation_selected: resq 1
 .observation_valid: resq 1
 .observation_sd_control: resq 1
 .observation_sd_status: resq 1
 .observation_zero_count: resq 1
 .observation_mismatch_count: resq 1
 ; Existing clock samples at the latest RUN write and first verified RUN/FIFO
 ; acknowledgement. Not hardware timestamps or analogue/DAC latency.
 .run_write_sample: resq 1
 .run_ack_sample: resq 1
 .run_valid: resq 1               ;bit0 write issued,bit1 RUN/FIFO observed
endstruc
%macro HDI_EMIT 5
 mov esi,%1
 mov edx,%2
 mov ecx,%3
 mov r8d,%4
 mov r9d,%5
 call hda_program_emit
 test eax,eax
 jnz .bad
%endmacro
%macro HDI_QUERY 3
 HDI_EMIT %1,(0xF0000|%2),0,0,%3
%endmacro
%macro HDI_SPAN 3
 mov rax,%1
 mov rdx,%2
 lea rdi,[rsp+%3]
 call hdi_span
 jc .bad
%endmacro

hda_input_begin:
    NATIVE_DRIVER_REFUSE 7
 HDA_INPUT_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,176
 mov r12,rdi
 mov rbp,rsi
 HDI_SPAN r12,hda_input_size,0
 cmp dword [r12+hda_route_program.phase],0
 je .fresh
 cmp dword [r12+hda_input.retired],1
 jne .bad
 cmp rbp,[r12+hda_route_program.epoch]
 jbe .bad
.fresh:
 test rbp,rbp
 jz .bad
 mov rbx,[r12+hda_route_program.graph]
 HDI_SPAN rbx,hda_graph_size,96
 HDI_SPAN [rbx+hda_graph.owner],hda_graph_lease_size,112
 HDI_SPAN [rbx+hda_graph.mmio],4096,64
 HDI_SPAN [r12+hda_input.bdl],64,16
 HDI_SPAN [r12+hda_input.pcm],16384,32
 HDI_SPAN [r12+hda_input.queue],8192,48
 HDI_SPAN [r12+hda_input.position],256,80
 mov edx,[rbx+hda_graph.widget_cap]
 shl edx,5
 HDI_SPAN [rbx+hda_graph.widgets],rdx,128
 mov edx,[rbx+hda_graph.edge_cap]
 imul edx,edx,hda_route_edge_size
 HDI_SPAN [rbx+hda_graph.edges],rdx,144
 mov rdi,rsp
 call hdi_disjoint
 jc .bad
 ; All locals checked against remaining graph transport/codec/group spans.
 mov rdi,rsp
 call hdi_external_spans
 jc .bad
 cmp qword [r12+hda_input.queue_bytes],8192
 jne .bad
 mov rax,[r12+hda_input.clock_hz]
 dec rax
 cmp rax,999999999
 ja .bad
 mov eax,[r12+hda_input.batch_frames]
 dec eax
 cmp eax,2047
 ja .bad
 mov eax,[r12+hda_input.vref]
 cmp eax,5
 ja .bad
 cmp eax,3
 je .bad
 mov eax,[r12+hda_input.route+hda_input_route.channels]
 dec eax
 cmp eax,1
 ja .bad
 mov eax,[r12+hda_route_program.tag]
 dec eax
 cmp eax,14
 ja .bad
 mov eax,[r12+hda_input.rate]
 cmp eax,48000
 je .rate
 cmp eax,44100
 je .rate
 cmp eax,96000
 jne .bad
.rate:
 mov eax,[r12+hda_input.route+hda_input_route.channels]
 dec eax
 or eax,0x10
 cmp dword [r12+hda_input.rate],96000
 jne .base_rate
 or eax,0x800                    ; 48kHz base x2, S16 mono/stereo
 jmp .format
.base_rate:
 cmp dword [r12+hda_input.rate],48000
 je .format
 or eax,0x4000
.format:
 cmp eax,[r12+hda_route_program.format]
 jne .bad
 mov rax,[rbx+hda_graph.widgets]
 cmp [r12+hda_input.route+hda_input_route.widgets],rax
 jne .bad
 mov eax,[rbx+hda_graph.public_widget_count]
 cmp [r12+hda_input.route+hda_input_route.widget_count],rax
 jne .bad
 mov rax,[rbx+hda_graph.edges]
 cmp [r12+hda_input.route+hda_input_route.edges],rax
 jne .bad
 mov eax,[rbx+hda_graph.public_edge_count]
 cmp [r12+hda_input.route+hda_input_route.edge_count],rax
 jne .bad
 mov rdi,rbx
 mov rsi,rbp
 call hda_graph_owner_check
 test rax,rax
 jnz .bad
 cmp dword [rbx+hda_graph.phase],HDAGS_DONE
 jne .bad
 call hdi_dma_validate
 test eax,eax
 jnz .bad
 call hdi_receipt
 test eax,eax
 jnz .bad
 lea rdi,[r12+hda_input.route]
 call hda_input_route_plan
 test rax,rax
 jnz .bad
 call hdi_output_disjoint
 test eax,eax
 jnz .bad
 mov rdi,rbx
 mov rsi,r12
 mov edx,hda_input_size
 mov rcx,rbp
 call hda_graph_input_claim
 test rax,rax
 jnz .bad
 ; Preserve caller configuration and selected input plan. Clear only internals.
 lea rdi,[r12+hda_route_program.phase]
 xor eax,eax
 mov ecx,(hda_route_program_size-hda_route_program.phase)/8
 rep stosq
 lea rdi,[r12+hda_input.stream_phase]
 mov ecx,(hda_input_size-hda_input.stream_phase)/8
 rep stosq
 mov [r12+hda_route_program.epoch],rbp
 mov eax,[r12+hda_route_program.format]
 mov [r12+hda_route_program.saved_format],eax
 mov eax,[r12+hda_route_program.tag]
 mov [r12+hda_route_program.saved_tag],eax
 mov eax,[r12+hda_input.route+hda_input_route.codec]
 mov [r12+hda_route_program.saved_codec],eax
 mov eax,[r12+hda_input.route+hda_input_route.group]
 mov [r12+hda_route_program.saved_group],eax
 mov eax,[r12+hda_input.route+hda_input_route.channels]
 shl eax,1
 mov [r12+hda_input.frame_bytes],eax
 imul eax,[r12+hda_input.batch_frames]
 mov [r12+hda_input.target_bytes],eax
 lea rdi,[r12+hda_input.spans]
 mov rsi,rsp
 mov ecx,20
 rep movsq
 lea rdi,[r12+hda_input.config]
 lea rsi,[r12+hda_input.route]
 mov ecx,9
 rep movsq
 lea rsi,[r12+hda_input.bdl]
 mov ecx,12
 rep movsq
 mov rax,[r12+hda_route_program.graph]
 mov [rdi],rax
 call hdi_nodes
 test eax,eax
 jnz .claimed_fail
 call hda_program_quirk
 mov [r12+hda_route_program.pad],eax
 call hdi_queries
 test eax,eax
 jnz .claimed_fail
 call hda_program_clock
 test eax,eax
 jnz .claimed_fail
 call hdi_owned
 test eax,eax
 jnz .claimed_fail
 mov rax,[r12+hda_route_program.last_now]
 add rax,[rbx+hda_graph.session_timeout]
 jc .claimed_fail
 mov [r12+hda_route_program.deadline],rax
 mov dword [r12+hda_route_program.phase],HDAP_QUERY
 xor eax,eax
 jmp .out
.claimed_fail:
 mov esi,1
 call hdi_fail
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

; Same exact graph/codec/AFG selection, with immutable full inventory validation.
hdi_nodes:
 push r13
 push r14
 sub rsp,8
 lea r13,[r12+hda_route_program.nodes]
 mov eax,[r12+hda_input.route+hda_input_route.adc]
 mov [r13+hda_program_node.nid],eax
 mov eax,[r12+hda_input.route+hda_input_route.middle]
 mov [r13+hda_program_node_size+hda_program_node.nid],eax
 mov eax,[r12+hda_input.route+hda_input_route.pin]
 mov [r13+2*hda_program_node_size+hda_program_node.nid],eax
 xor r14d,r14d
.node:
 cmp dword [r13+hda_program_node.nid],0
 je .next
 mov rdi,[rbx+hda_graph.widgets]
 mov ecx,[rbx+hda_graph.public_widget_count]
.widget:
 mov eax,[r12+hda_route_program.saved_codec]
 cmp [rdi+hda_widget_info.codec],eax
 jne .next_widget
 mov eax,[r12+hda_route_program.saved_group]
 cmp [rdi+hda_widget_info.group],eax
 jne .next_widget
 mov eax,[r13+hda_program_node.nid]
 cmp [rdi+hda_widget_info.nid],eax
 je .found
.next_widget:
 add rdi,hda_widget_info_size
 dec ecx
 jnz .widget
 jmp .bad
.found:
 mov eax,[rdi+hda_widget_info.caps]
 test eax,0xE260
 jnz .bad
 mov [r13+hda_program_node.caps],eax
 cmp r14d,2
 jne .edges
 mov eax,[rdi+hda_widget_info.pin_caps]
 mov [r12+hda_route_program.pin_caps],eax
 mov eax,[rdi+hda_widget_info.config]
 mov [r12+hda_route_program.eapd],eax ;query-only exact config snapshot
.edges:
 mov rdi,[rbx+hda_graph.edges]
 mov ecx,[rbx+hda_graph.public_edge_count]
 test ecx,ecx
 jz .next
.edge:
 mov eax,[r12+hda_route_program.saved_codec]
 cmp [rdi+hda_route_edge.codec],eax
 jne .next_edge
 mov eax,[r12+hda_route_program.saved_group]
 cmp [rdi+hda_route_edge.group],eax
 jne .next_edge
 mov eax,[r13+hda_program_node.nid]
 cmp [rdi+hda_route_edge.node],eax
 jne .next_edge
 inc dword [r13+hda_program_node.connections]
.next_edge:
 add rdi,hda_route_edge_size
 dec ecx
 jnz .edge
.next:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .node
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 pop r14
 pop r13
 ret

hdi_queries:
 push r13
 push r14
 sub rsp,8
 ; HDA7.3.4.4: exact AudioNodeType1 in bits7:0; optional UnSolCap is bit8.
 HDI_EMIT [r12+hda_route_program.saved_group],0xF0005,0xFFFFFEFF,1,0
 HDI_QUERY [r12+hda_route_program.saved_group],15,hda_route_program.fg_power
 HDI_EMIT [r12+hda_route_program.saved_group],0xF0500,0,0,hda_input.fg_now
 mov esi,[r12+hda_route_program.saved_group]
 test dword [r12+hda_route_program.nodes+hda_program_node.caps],16
 jz .format
 mov esi,[r12+hda_route_program.nodes+hda_program_node.nid]
.format:
 mov r14d,esi
 HDI_QUERY r14d,10,hda_route_program.pcm
 HDI_QUERY r14d,11,hda_route_program.streams
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],0xF000C,0xFFFFFFFF,[r12+hda_route_program.pin_caps],0
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],0xF1C00,0xFFFFFFFF,[r12+hda_route_program.eapd],0
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.node:
 cmp dword [r13+hda_program_node.nid],0
 je .next
 HDI_EMIT [r13+hda_program_node.nid],0xF0009,0xFFFFFFFF,[r13+hda_program_node.caps],0
 test dword [r13+hda_program_node.caps],0x400
 jz .amps
 mov eax,r13d
 sub eax,r12d
 add eax,hda_program_node.power
 HDI_QUERY [r13+hda_program_node.nid],15,eax
 lea eax,[r14*4+hda_input.power_now]
 HDI_EMIT [r13+hda_program_node.nid],0xF0500,0,0,eax
.amps:
 ; Input amp on ADC, pin, mixer. Selector InAmp is not a defined path control.
 cmp r14d,1
 jne .input
 cmp dword [r12+hda_input.route+hda_input_route.kind],1
 jne .output
.input:
 test dword [r13+hda_program_node.caps],2
 jz .output
 mov esi,[r12+hda_route_program.saved_group]
 test dword [r13+hda_program_node.caps],8
 jz .input_source
 mov esi,[r13+hda_program_node.nid]
.input_source:
 mov eax,r13d
 sub eax,r12d
 add eax,hda_program_node.amp_in
 HDI_QUERY esi,13,eax
.output:
 ; Intermediate widget output amp feeds downstream ADC. Pin/DAC output amps
 ; are irrelevant to analogue input and are never borrowed from output setup.
 cmp r14d,1
 jne .next
 test dword [r13+hda_program_node.caps],4
 jz .next
 mov esi,[r12+hda_route_program.saved_group]
 test dword [r13+hda_program_node.caps],8
 jz .out_source
 mov esi,[r13+hda_program_node.nid]
.out_source:
 mov eax,r13d
 sub eax,r12d
 add eax,hda_program_node.amp_out
 HDI_QUERY esi,18,eax
.next:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .node
 call hda_program_quirk_queries
 test eax,eax
 jnz .bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 pop r14
 pop r13
 ret

hdi_build:
 push rbx
 push rbp
 push r13
 push r14
 sub rsp,8
 cmp dword [r12+hda_route_program.pad],1
 jne .generic_power_caps
 mov esi,1
 call hda_program_fixed_caps
 test eax,eax
 jnz .bad
 cmp dword [r12+hda_input.route+hda_input_route.kind],0
 jne .bad
 cmp dword [r12+hda_input.route+hda_input_route.channels],2
 jne .bad
 jmp .power_caps_valid
.generic_power_caps:
 mov eax,[r12+hda_route_program.fg_power]
 test eax,1
 jz .bad
 test eax,0x1FFFFFE0
 jnz .bad
.power_caps_valid:
 mov eax,[r12+hda_route_program.streams]
 test eax,1
 jz .bad
 test eax,0xFFFFFFF8
 jnz .bad
 mov eax,[r12+hda_route_program.pcm]
 test eax,0xFFE0F000
 jnz .bad
 mov edx,0x20100                 ; exact S16 +96kHz capability bit8
 cmp dword [r12+hda_input.rate],96000
 je .pcm
 mov edx,0x20040
 cmp dword [r12+hda_input.rate],44100
 jne .pcm
 mov edx,0x20020
.pcm:
 and eax,edx
 cmp eax,edx
 jne .bad
 mov eax,[r12+hda_route_program.pin_caps]
 test eax,0x20
 jz .bad
 test eax,0x01000080
 jnz .bad
 mov ecx,[r12+hda_input.vref]
 test ecx,ecx
 jnz .vref_support
 test eax,0xFF00
 jz .vref_ok                    ;no VRef generator, Hi-Z is the only operation
.vref_support:
 add ecx,8
 bt eax,ecx
 jnc .bad
.vref_ok:
 mov eax,[r12+hda_route_program.eapd]
 shr eax,20
 and eax,15
 cmp eax,8
 jne .mic
 cmp dword [r12+hda_input.vref],0
 jne .bad
.mic:
 mov eax,[r12+hda_input.vref]
 or eax,0x20
 mov [r12+hda_route_program.pin_ctl],eax
 cmp dword [r12+hda_route_program.pad],1
 jne .fg_status
 cmp dword [r12+hda_input.fg_now],0
 jne .bad
 jmp .widgets
.fg_status:
 mov eax,[r12+hda_input.fg_now]
 mov edx,[r12+hda_route_program.fg_power]
 call hdi_power_status
 jc .bad
 ; Do not disturb a completed output route's shared AFG power state.
 cmp qword [rbx+hda_graph.command_owner],0
 je .widgets
 mov rdi,[rbx+hda_graph.command_owner]
 mov edx,[r12+hda_route_program.saved_codec]
 cmp [rdi+hda_route_program.route+hda_route_context.codec],edx
 jne .widgets
 mov edx,[r12+hda_route_program.saved_group]
 cmp [rdi+hda_route_program.route+hda_route_context.group],edx
 jne .widgets
 test eax,0x4FF
 jnz .bad
.widgets:
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.validate:
 cmp dword [r13+hda_program_node.nid],0
 je .next_validate
 test dword [r13+hda_program_node.caps],0x400
 jz .amps
 mov eax,[r13+hda_program_node.power]
 test eax,eax
 jnz .power_caps
 mov eax,[r12+hda_route_program.fg_power]
.power_caps:
 test eax,1
 jz .bad
 test eax,0x1FFFFFE0
 jnz .bad
 mov edx,eax
 mov ecx,[r12+hda_route_program.fg_power]
 and ecx,0x80000000             ;AFG EPSS applies to each widget
 or edx,ecx
 mov eax,[r12+r14*4+hda_input.power_now]
 call hdi_power_status
 jc .bad
.amps:
 cmp r14d,1
 jne .input_caps
 cmp dword [r12+hda_input.route+hda_input_route.kind],1
 jne .output_caps
 cmp dword [r13+hda_program_node.connections],16
 ja .bad
 test dword [r13+hda_program_node.caps],2
 jnz .input_caps
 cmp dword [r13+hda_program_node.connections],1
 ja .bad
 jmp .output_caps
.input_caps:
 test dword [r13+hda_program_node.caps],2
 jz .output_caps
 mov eax,[r13+hda_program_node.amp_in]
 call hda_program_amp_caps
 jc .bad
 cmp r14d,1
 jne .output_caps
 cmp dword [r13+hda_program_node.connections],1
 jbe .output_caps
 test eax,0x80000000
 jz .bad
.output_caps:
 cmp r14d,1
 jne .next_validate
 test dword [r13+hda_program_node.caps],4
 jz .next_validate
 mov eax,[r13+hda_program_node.amp_out]
 call hda_program_amp_caps
 jc .bad
.next_validate:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .validate
 mov dword [r12+hda_route_program.count],0
 mov dword [r12+hda_route_program.cursor],0
 mov eax,[r12+hda_input.fg_now]
 test eax,0x4FF
 jz .widget_power
 mov esi,[r12+hda_route_program.saved_group]
 call hda_program_power
 test eax,eax
 jnz .bad
.widget_power:
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.power:
 cmp dword [r13+hda_program_node.nid],0
 je .next_power
 test dword [r13+hda_program_node.caps],0x400
 jz .next_power
 test dword [r12+r14*4+hda_input.power_now],0x4FF
 jz .next_power
 mov esi,[r13+hda_program_node.nid]
 call hda_program_power
 test eax,eax
 jnz .bad
.next_power:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .power
 cmp dword [r12+hda_route_program.pad],1
 jne .disable_pin
 mov esi,[r12+hda_route_program.nodes+hda_program_node.nid]
 xor edi,edi
 mov edx,0x4000
 mov ebx,0xCA
 call hdi_amp
 test eax,eax
 jnz .bad
 jmp .pin_disabled
.disable_pin:
 ; Keep the input pin disabled while its upstream ADC path is configured.
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],0x70700,0xFFFFFFFF,0,0
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],0xF0700,0xFFFFFFFF,0,0
 .pin_disabled:
 cmp dword [r12+hda_route_program.nodes+hda_program_node.connections],1
 jbe .middle_select
 mov esi,[r12+hda_input.route+hda_input_route.adc]
 mov edi,[r12+hda_input.route+hda_input_route.adc_index]
 call hda_program_selector
 test eax,eax
 jnz .bad
.middle_select:
 cmp dword [r12+hda_input.route+hda_input_route.kind],2
 jne .converter
 cmp dword [r12+hda_route_program.nodes+hda_program_node_size+hda_program_node.connections],1
 jbe .converter
 mov esi,[r12+hda_input.route+hda_input_route.middle]
 mov edi,[r12+hda_input.route+hda_input_route.middle_index]
 call hda_program_selector
 test eax,eax
 jnz .bad
.converter:
 mov edx,[r12+hda_route_program.saved_format]
 or edx,0x20000
 HDI_EMIT [r12+hda_input.route+hda_input_route.adc],edx,0xFFFFFFFF,0,0
 HDI_EMIT [r12+hda_input.route+hda_input_route.adc],0xA0000,0xFFFFFFFF,[r12+hda_route_program.saved_format],0
 mov edx,[r12+hda_route_program.saved_tag]
 shl edx,4
 or edx,0x70600
 HDI_EMIT [r12+hda_input.route+hda_input_route.adc],edx,0xFFFFFFFF,0,0
 mov r8d,[r12+hda_route_program.saved_tag]
 shl r8d,4
 HDI_EMIT [r12+hda_input.route+hda_input_route.adc],0xF0600,0xFFFFFFFF,r8d,0
 cmp dword [r12+hda_route_program.pad],1
 jne .amp_setup
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],0xF0700,0xFFFFFFFF,0x20,0
 mov esi,[r12+hda_route_program.nodes+hda_program_node.nid]
 xor edi,edi
 mov edx,0x4000
 mov ebx,0x4A
 call hdi_amp
 test eax,eax
 jnz .bad
 jmp .ok
.amp_setup:
 ; Actual input/output amp directions, mono left or stereo both.
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.amp_node:
 cmp dword [r13+hda_program_node.nid],0
 je .next_amp
 cmp r14d,1
 jne .single_input
 cmp dword [r12+hda_input.route+hda_input_route.kind],1
 jne .amp_output
 test dword [r13+hda_program_node.caps],2
 jz .amp_output
 xor ebp,ebp
.mixer_input:
 mov ebx,[r13+hda_program_node.amp_in]
 and ebx,127
 cmp ebp,[r12+hda_input.route+hda_input_route.middle_index]
 je .gain
 or ebx,0x80
.gain:
 mov esi,[r13+hda_program_node.nid]
 mov edi,ebp
 mov edx,0x4000
 call hdi_amp
 test eax,eax
 jnz .bad
 inc ebp
 cmp ebp,[r13+hda_program_node.connections]
 jb .mixer_input
 jmp .amp_output
.single_input:
 test dword [r13+hda_program_node.caps],2
 jz .amp_output
 mov ebx,[r13+hda_program_node.amp_in]
 and ebx,127
 mov esi,[r13+hda_program_node.nid]
 xor edi,edi                      ;ADC/pin input index is ignored: use0
 mov edx,0x4000
 call hdi_amp
 test eax,eax
 jnz .bad
.amp_output:
 cmp r14d,1
 jne .next_amp
 test dword [r13+hda_program_node.caps],4
 jz .next_amp
 mov ebx,[r13+hda_program_node.amp_out]
 and ebx,127
 mov esi,[r13+hda_program_node.nid]
 xor edi,edi
 mov edx,0x8000
 call hdi_amp
 test eax,eax
 jnz .bad
.next_amp:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .amp_node
 mov edx,[r12+hda_route_program.pin_ctl]
 or edx,0x70700
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],edx,0xFFFFFFFF,0,0
 HDI_EMIT [r12+hda_input.route+hda_input_route.pin],0xF0700,0xFFFFFFFF,[r12+hda_route_program.pin_ctl],0
 HDI_EMIT [r12+hda_route_program.saved_group],0xF0500,0xFFFFFDFF,0,0
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.final_power:
 cmp dword [r13+hda_program_node.nid],0
 je .final_next
 test dword [r13+hda_program_node.caps],0x400
 jz .final_next
 HDI_EMIT [r13+hda_program_node.nid],0xF0500,0xFFFFFDFF,0,0
.final_next:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .final_power
.ok:
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 pop r14
 pop r13
 pop rbp
 pop rbx
 ret

; Input-specific mono/stereo amp command sequence, verified channel semantics.
hdi_power_status:
 test eax,0xFFFFF900
 jnz .bad
 test eax,0x400
 jz .state
 test edx,0x80000000
 jz .bad
.state:
 mov ecx,eax
 and ecx,15
 cmp ecx,4
 ja .bad
 bt edx,ecx
 jnc .bad
 mov ecx,eax
 shr ecx,4
 and ecx,15
 cmp ecx,4
 ja .bad
 bt edx,ecx
 jnc .bad
 clc
 ret
.bad:
 stc
 ret

hdi_amp:
 push rbp
 push r13
 push r14
 mov ebp,esi
 mov r13d,edi
 mov r14d,edx
 shl edi,8
 or edx,edi
 or edx,ebx
 or edx,0x32000
 cmp dword [r12+hda_input.route+hda_input_route.channels],2
 jne .set
 or edx,0x1000
.set:
 HDI_EMIT ebp,edx,0xFFFFFFFF,0,0
 mov edx,r13d
 cmp r14d,0x8000
 jne .left
 or edx,0x8000
.left:
 or edx,0xB2000
 HDI_EMIT ebp,edx,0xFFFFFFFF,ebx,0
 cmp dword [r12+hda_input.route+hda_input_route.channels],2
 jne .ok
 mov edx,r13d
 cmp r14d,0x8000
 jne .right
 or edx,0x8000
.right:
 or edx,0xB0000
 HDI_EMIT ebp,edx,0xFFFFFFFF,ebx,0
.ok:
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 pop r14
 pop r13
 pop rbp
 ret

; Exact retained transport/script runner ported from accepted output client.
hdi_program_step:
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .refuse
 mov rdi,[r12+hda_route_program.graph]
 mov rsi,r12
 mov rdx,[r12+hda_route_program.epoch]
 call hda_graph_input_check
 test rax,rax
 jnz .ownership
 mov rbx,[r12+hda_route_program.graph]
 mov eax,[r12+hda_route_program.format]
 cmp eax,[r12+hda_route_program.saved_format]
 jne .source
 mov eax,[r12+hda_route_program.tag]
 cmp eax,[r12+hda_route_program.saved_tag]
 jne .source
 cmp dword [r12+hda_route_program.phase],HDAP_READY
 je .ready
 mov eax,[r12+hda_route_program.phase]
 dec eax
 cmp eax,1
 ja .source
 inc dword [r12+hda_route_program.steps]
 mov eax,[r12+hda_route_program.steps]
 cmp eax,[rbx+hda_graph.step_limit]
 ja .timeout
 call hda_program_clock
 test eax,eax
 jnz .clock
 mov rax,[r12+hda_route_program.last_now]
 cmp rax,[r12+hda_route_program.deadline]
 jae .timeout
 mov rdi,rbx
 mov rsi,r12
 mov rdx,[r12+hda_route_program.epoch]
 call hda_graph_input_check
 test rax,rax
 jnz .ownership
 mov eax,[r12+hda_route_program.cursor]
 cmp eax,HDAP_MAX
 jae .source
 mov edx,[r12+hda_route_program.count]
 cmp edx,HDAP_MAX
 ja .source
 cmp eax,edx
 ja .source
 je .finish
 shl eax,4
 lea r13,[r12+rax+hda_route_program.script]
 cmp dword [r12+hda_route_program.request],0
 je .next
 mov eax,[r12+hda_route_program.cursor]
 cmp eax,[r12+hda_route_program.request_cursor]
 jne .source
 mov eax,[r12+hda_route_program.phase]
 cmp eax,[r12+hda_route_program.request_phase]
 jne .source
 mov eax,[r13]
 cmp eax,[r12+hda_route_program.command]
 jne .source
 mov rax,[r12+hda_route_program.last_now]
 cmp rax,[r12+hda_route_program.command_deadline]
 jae .timeout
 inc dword [r12+hda_route_program.polls]
 mov eax,[r12+hda_route_program.polls]
 cmp eax,[rbx+hda_graph.poll_limit]
 ja .timeout
 mov rdi,[rbx+hda_graph.transport]
 cmp dword [r12+hda_route_program.request],1
 je .queue
 cmp dword [r12+hda_route_program.request],2
 jne .source
 cmp dword [rdi+hda_transport.pending],1
 jne .source
 mov eax,[r12+hda_route_program.saved_codec]
 cmp [rdi+hda_transport.codec],eax
 jne .source
 lea rsi,[r12+hda_route_program.response]
 call hda_rirb_take
 test rax,rax
 js .transport
 jnz .yield
 mov eax,[r12+hda_route_program.response]
 mov edx,[r13+12]
 cmp edx,-1
 je .power
 test edx,edx
 jz .verify
 ; Only internally generated aligned fact destinations in the fact/node area.
 cmp edx,hda_input.fg_now
 jb .prefix_fact
 cmp edx,hda_input.power_now+12
 jae .source
 jmp .store_fact
.prefix_fact:
 cmp edx,hda_route_program.fg_power
 jb .source
 cmp edx,hda_route_program.script
 jae .source
.store_fact:
 test edx,3
 jnz .source
 mov [r12+rdx],eax
 jmp .advance
.verify:
 and eax,[r13+4]
 cmp eax,[r13+8]
 jne .response
.advance:
 mov dword [r12+hda_route_program.request],0
 inc dword [r12+hda_route_program.cursor]
 jmp .yield
.power:
 ; Initial D0 acquisition may report EPSS SettingsReset from an earlier reset.
 ; GET clears this sticky report; require a fresh clear D0 response before SETs.
 ; Final post-program power verification remains strict (including bit10).
 test eax,0xFFFFF90F             ;allow ClockStopOK, SettingsReset, PSAct only
 jnz .response
 test eax,0x400
 jz .power_actual
 test dword [r12+hda_route_program.fg_power],0x80000000
 jnz .power_retry              ;AFG EPSS applies to all its widgets
 mov edx,[r12+hda_route_program.command]
 shr edx,20
 and edx,255
 lea rcx,[r12+hda_route_program.nodes]
 mov esi,3
.power_epss:
 cmp edx,[rcx+hda_program_node.nid]
 jne .power_next
 test dword [rcx+hda_program_node.power],0x80000000
 jz .response
 jmp .power_retry
.power_next:
 add rcx,hda_program_node_size
 dec esi
 jnz .power_epss
 jmp .response                  ;unadvertised reset bit is not a valid status
.power_actual:
 test eax,0xF0
 jz .advance
.power_retry:
 mov dword [r12+hda_route_program.request],1 ;same GET, same deadline/polls
 jmp .yield
.queue:
 cmp dword [rdi+hda_transport.pending],0
 jne .source
 mov esi,[r12+hda_route_program.command]
 call hda_corb_queue
 test rax,rax
 js .transport
 jnz .yield
 mov dword [r12+hda_route_program.request],2
 jmp .yield
.next:
 mov rdi,[rbx+hda_graph.transport]
 cmp dword [rdi+hda_transport.pending],0
 jne .source
 mov eax,[r13]
 mov [r12+hda_route_program.command],eax
 mov eax,[r12+hda_route_program.cursor]
 mov [r12+hda_route_program.request_cursor],eax
 mov eax,[r12+hda_route_program.phase]
 mov [r12+hda_route_program.request_phase],eax
 mov rax,[r12+hda_route_program.last_now]
 add rax,[rbx+hda_graph.command_timeout]
 jc .clock
 mov [r12+hda_route_program.command_deadline],rax
 mov dword [r12+hda_route_program.polls],0
 mov dword [r12+hda_route_program.request],1
 jmp .yield
.finish:
 cmp dword [r12+hda_route_program.request],0
 jne .source
 mov rax,[rbx+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .source
 cmp dword [r12+hda_route_program.phase],HDAP_QUERY
 jne .publish
 call hdi_build
 test eax,eax
 jnz .capability
 mov dword [r12+hda_route_program.phase],HDAP_PROGRAM
 jmp .yield
.publish:
 mov dword [r12+hda_route_program.phase],HDAP_READY
 mov dword [rbx+hda_graph.input_ready],1
.ready:
 cmp dword [rbx+hda_graph.input_ready],1
 jne .source
 mov eax,2
 jmp .out
.yield:
 mov eax,1
 jmp .out
.ownership:
 mov esi,2
 jmp .fail
.clock:
 mov esi,3
 jmp .fail
.timeout:
 mov esi,4
 jmp .fail
.source:
 mov esi,5
 jmp .fail
.transport:
 mov esi,6
 jmp .fail
.response:
 mov esi,7
 jmp .fail
.capability:
 mov esi,8
.fail:
 call hdi_fail
.refuse:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret


; Identity-only guard remains usable to stop our input after route revocation.
hdi_owned:
 sub rsp,8
 call hdi_bound
 test eax,eax
 jnz .bad
 mov rbx,[r12+hda_route_program.graph]
 mov rdi,rbx
 mov rsi,[r12+hda_route_program.epoch]
 call hda_graph_owner_check
 test rax,rax
 jnz .bad
 cmp [rbx+hda_graph.input_owner],r12
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 ret
hdi_bound:
 mov rax,[r12+hda_route_program.graph]
 cmp rax,[r12+hda_input.config+168]
 jne .bad
 lea r8,[r12+hda_input.route]
 lea r9,[r12+hda_input.config]
 mov ecx,9
.route:
 mov rax,[r8]
 cmp rax,[r9]
 jne .bad
 add r8,8
 add r9,8
 dec ecx
 jnz .route
 lea r8,[r12+hda_input.bdl]
 mov ecx,12
.config:
 mov rax,[r8]
 cmp rax,[r9]
 jne .bad
 add r8,8
 add r9,8
 dec ecx
 jnz .config
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret
hdi_receipt:
 sub rsp,8
 mov edi,1
 call dma_domain_live_receipt
 cmp eax,1
 jne .bad
 test rdx,rdx
 jz .bad
 cmp rdx,[r12+hda_input.map_serial]
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret
hdi_guard:
 sub rsp,8
 call hdi_owned
 test eax,eax
 jnz .bad
 mov rdi,rbx
 mov rsi,r12
 mov rdx,[r12+hda_route_program.epoch]
 call hda_graph_input_check
 test eax,eax
 jnz .bad
 mov rax,[rbx+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .bad                       ;stream work starts after completed input verbs
 mov eax,[r12+hda_route_program.format]
 cmp eax,[r12+hda_route_program.saved_format]
 jne .bad
 mov eax,[r12+hda_route_program.tag]
 cmp eax,[r12+hda_route_program.saved_tag]
 jne .bad
 call hdi_receipt
 test eax,eax
 jnz .bad
 call hdi_owned
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 ret
hdi_sd:
 mov eax,[r12+hda_input.sd_index]
 shl eax,5
 mov r8,[rbx+hda_graph.mmio]
 lea r8,[r8+rax+0x80]
 ret

; Physical/VA binding check; no global DPLBASE write or identity-DMA fallback.
hdi_dma_validate:
 push r13
 push r14
 sub rsp,56
 mov r8,[rbx+hda_graph.mmio]
 movzx eax,word [r8]
 mov r14d,eax
 and eax,6
 cmp eax,6
 je .bad
 mov eax,r14d
 shr eax,8
 and eax,15
 cmp [r12+hda_input.sd_index],eax
 jae .bad
 mov r13d,eax
 mov eax,r14d
 shr eax,12
 and eax,15
 add r13d,eax
 mov eax,r14d
 shr eax,3
 and eax,31
 add r13d,eax
 cmp r13d,30
 ja .bad
 call hdi_sd
 test byte [r8],3
 jnz .bad
 mov r8,[rbx+hda_graph.mmio]
 mov rax,[r12+hda_input.position_dma]
 or eax,1
 cmp [r8+0x70],eax
 jne .bad
 mov rax,[r12+hda_input.position_dma]
 shr rax,32
 cmp [r8+0x74],eax
 jne .bad
 mov rax,[r12+hda_input.bdl_dma]
 mov edx,64
 mov rdi,rsp
 call hdi_iova
 jc .bad
 mov rax,[r12+hda_input.pcm_dma]
 mov edx,16384
 lea rdi,[rsp+16]
 call hdi_iova
 jc .bad
 mov rax,[r12+hda_input.position_dma]
 mov edx,256
 lea rdi,[rsp+32]
 call hdi_iova
 jc .bad
 mov rdi,rsp
 mov esi,48
 call hdi_pairs
 jc .bad
 test r14d,1
 jnz .width_ok
 xor ecx,ecx
.width:
 mov rax,[rsp+rcx+8]
 dec rax
 shr rax,32
 jnz .bad
 add ecx,16
 cmp ecx,48
 jb .width
.width_ok:
 ; Existing output storage cannot alias new input DMA. Shared position buffer
 ; is intentional and must use the same VA and IOVA; only our SD slot changes.
 mov r9,[rbx+hda_graph.pcm_owner]
 test r9,r9
 jz .streams
 mov r10,[r9+hda_pcm.output]
 mov rax,[r12+hda_input.position]
 cmp rax,[r10+hda_output.position]
 jne .bad
 mov rax,[r12+hda_input.position_dma]
 cmp rax,[r10+hda_output.position_dma]
 jne .bad
 mov rax,[r10+hda_output.bdl_dma]
 lea rdx,[rax+64]
 call hdi_iova_output_separate
 jc .bad
 mov rax,[r10+hda_output.pcm_dma]
 lea rdx,[rax+16384]
 call hdi_iova_output_separate
 jc .bad
.streams:
 mov r8,[rbx+hda_graph.mmio]
 xor ecx,ecx
.stream:
 mov eax,ecx
 shl eax,5
 lea r11,[r8+rax+0x80]
 cmp ecx,[r12+hda_input.sd_index]
 je .next
 test byte [r11],2
 jz .next
 ; Only one represented, independently owned output may be live.
 test r9,r9
 jz .bad
 mov r10,[r9+hda_pcm.output]
 cmp ecx,[r10+hda_output.sd_index]
 jne .bad
 movzx eax,byte [r11+2]
 shr eax,4
 cmp eax,[r12+hda_route_program.tag]
 je .bad
.next:
 inc ecx
 cmp ecx,r13d
 jb .stream
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,56
 pop r14
 pop r13
 ret
; RAX/EDX incoming IOVA/bytes. Keep half-open end, reject wrapping/alignment.
hdi_iova:
 test rax,127
 jnz .bad
 jmp hdi_span
.bad:
 stc
 ret
; Compare an output IOVA range against input BDL/PCM ranges (position shared).
hdi_iova_output_separate:
 mov rsi,[r12+hda_input.bdl_dma]
 lea rdi,[rsi+64]
 cmp rax,rdi
 jae .pcm
 cmp rsi,rdx
 jb .bad
.pcm:
 mov rsi,[r12+hda_input.pcm_dma]
 lea rdi,[rsi+16384]
 cmp rax,rdi
 jae .ok
 cmp rsi,rdx
 jb .bad
.ok:
 clc
 ret
.bad:
 stc
 ret

; Both new route nodes and private storage must be disjoint from output state.
hdi_output_disjoint:
 push rbp
 push r13
 push r14
 mov r13,[rbx+hda_graph.command_owner]
 test r13,r13
 jz .ok
 mov eax,[r12+hda_input.route+hda_input_route.codec]
 cmp eax,[r13+hda_route_program.route+hda_route_context.codec]
 jne .tag
 mov eax,[r12+hda_input.route+hda_input_route.group]
 cmp eax,[r13+hda_route_program.route+hda_route_context.group]
 jne .tag
 xor ebp,ebp
.node:
 mov eax,[r12+rbp+hda_input.route+hda_input_route.adc]
 test eax,eax
 jz .next
 cmp eax,[r13+hda_route_program.route+hda_route_context.pin]
 je .bad
 cmp eax,[r13+hda_route_program.route+hda_route_context.dac]
 je .bad
 cmp eax,[r13+hda_route_program.route+hda_route_context.middle]
 je .bad
.next:
 ; ADC/pin/middle are contiguous at offsets40,44,48 in input plan.
 add ebp,4
 cmp ebp,12
 jb .node
.tag:
 mov eax,[r12+hda_route_program.tag]
 cmp eax,[r13+hda_route_program.saved_tag]
 je .bad
.ok:
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 pop r14
 pop r13
 pop rbp
 ret

; Revoke input only; queued/global command uncertainty revokes whole graph.
; Stop/reset ONLY the owned input SD. Mappings/other stream state stay pinned.
hdi_fail:
 push rbp
 mov ebp,esi
 cmp dword [r12+hda_route_program.error],0
 jne .program_error
 mov [r12+hda_route_program.error],ebp
.program_error:
 cmp dword [r12+hda_input.stream_error],0
 jne .preserve
 mov [r12+hda_input.stream_error],ebp
.preserve:
 mov dword [r12+hda_route_program.phase],HDAP_FAILED
 mov dword [r12+hda_input.operation],1
 mov rbx,[r12+hda_route_program.graph]
 cmp [rbx+hda_graph.input_owner],r12
 jne .identity
 mov rax,[r12+hda_route_program.epoch]
 cmp [rbx+hda_graph.epoch],rax
 jne .identity
 mov dword [rbx+hda_graph.input_ready],0
.identity:
 call hdi_owned
 test eax,eax
 jnz .lost
 mov dword [rbx+hda_graph.input_ready],0
 mov rax,[rbx+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .global
 cmp dword [rax+hda_transport.fault],0
 je .local
.global:
 mov rdi,rbx
 mov rsi,[r12+hda_route_program.epoch]
 call hda_graph_cancel
.local:
 cmp dword [r12+hda_input.stream_phase],HDI_IDLE
 je .inactive                    ;capability refusal: no stream mutation
 call hdi_sd
 and byte [r8],0xFD
 mov dword [rbx+hda_graph.input_quiescent],0
 mov dword [r12+hda_input.stream_phase],HDI_HALTING
 mov dword [r12+hda_input.stream_polls],0
 call hdi_deadline
 test eax,eax
 jnz .lost
 jmp .out
.inactive:
 mov dword [r12+hda_input.stream_phase],HDI_FAILED
 jmp .out
.lost:
 mov dword [r12+hda_input.stream_phase],HDI_FAILED
.out:
 mov rax,-1
 pop rbp
 ret
hdi_deadline:
 mov rax,[r12+hda_route_program.last_now]
 add rax,[rbx+hda_graph.command_timeout]
 jc .bad
 mov [r12+hda_input.state_deadline],rax
 mov dword [r12+hda_input.stream_polls],0
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret

hda_input_start:
 HDA_INPUT_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .bad
 cmp dword [r12+hda_input.retired],0
 jne .bad
 cmp dword [r12+hda_route_program.phase],HDAP_READY
 jne .bad
 cmp dword [r12+hda_input.ready_bytes],0
 jne .bad
 mov eax,[r12+hda_input.stream_phase]
 cmp eax,HDI_IDLE
 je .check
 cmp eax,HDI_BATCH
 jne .bad
.check:
 call hdi_guard
 test eax,eax
 jnz .fault
 cmp dword [rbx+hda_graph.input_ready],1
 jne .bad
 call hda_program_clock
 test eax,eax
 jnz .fault
 call hdi_owned
 test eax,eax
 jnz .bad
 mov dword [r12+hda_input.operation],0
 mov dword [r12+hda_input.qualified],0
 mov dword [r12+hda_input.last_pos],0
 mov dword [r12+hda_input.read_offset],0
 call hdi_sd
 and byte [r8],0xFD
 mov dword [rbx+hda_graph.input_quiescent],0
 mov dword [r12+hda_input.stream_phase],HDI_STOP
 call hdi_deadline
 test eax,eax
 jnz .bad
 mov eax,1
 jmp .out
.fault:
 mov esi,1
 call hdi_fail
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_input_step:
 HDA_INPUT_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .bad
 cmp dword [r12+hda_input.retired],0
 jne .bad
 mov eax,[r12+hda_route_program.phase]
 cmp eax,HDAP_QUERY
 je .program
 cmp eax,HDAP_PROGRAM
 je .program
 mov ebp,[r12+hda_input.stream_phase]
 cmp ebp,HDI_FAILED
 jae .bad
 mov r14,[r12+hda_route_program.last_now]
 call hdi_owned
 test eax,eax
 jnz .owner
 call hda_program_clock
 test eax,eax
 jnz .clock
 call hdi_owned
 test eax,eax
 jnz .owner
 cmp dword [r12+hda_input.operation],0
 jne .dispatch
 call hdi_guard
 test eax,eax
 jnz .owner
 cmp dword [rbx+hda_graph.input_ready],1
 jne .owner
.dispatch:
 cmp ebp,HDI_IDLE
 je .ready
 cmp ebp,HDI_BATCH
 je .ready
 cmp ebp,HDI_STOPPED
 je .bad
 inc dword [r12+hda_input.stream_polls]
 mov eax,[r12+hda_input.stream_polls]
 cmp eax,[rbx+hda_graph.poll_limit]
 ja .uncertain_polls
 cmp ebp,HDI_RUNNING
 je .run
 mov rax,[r12+hda_route_program.last_now]
 cmp rax,[r12+hda_input.state_deadline]
 jae .uncertain_deadline
 call hdi_sd
 cmp ebp,HDI_STOP
 je .stopping
 cmp ebp,HDI_RESET_SET
 je .reset_set
 cmp ebp,HDI_RESET_CLEAR
 je .reset_clear
 cmp ebp,HDI_FIFO
 je .fifo
 cmp ebp,HDI_STARTING
 je .starting
 cmp ebp,HDI_HALTING
 je .halting
 cmp ebp,HDI_DRAIN_RESET
 je .drain_reset
 jmp .uncertain_state
.program:
 call hdi_owned
 test eax,eax
 jnz .owner
 mov rdi,r12
 call hdi_program_step
 jmp .out
.stopping:
 test byte [r8],2
 jnz .yield
 or byte [r8],1
 mov dword [r12+hda_input.stream_phase],HDI_RESET_SET
 call hdi_deadline
 test eax,eax
 jnz .uncertain
 jmp .yield
.reset_set:
 test byte [r8],1
 jz .yield
 and byte [r8],0xFE
 mov dword [r12+hda_input.stream_phase],HDI_RESET_CLEAR
 call hdi_deadline
 test eax,eax
 jnz .uncertain
 jmp .yield
.reset_clear:
 test byte [r8],1
 jnz .yield
 test byte [r8],2
 jnz .uncertain_run
 ; Own BDL/stream registers only, global position binding remains untouched.
 mov rdi,[r12+hda_input.bdl]
 mov rax,[r12+hda_input.pcm_dma]
 mov ecx,4
.bdl:
 mov [rdi],rax
 mov dword [rdi+8],4096
 mov dword [rdi+12],1
 add rax,4096
 add rdi,16
 dec ecx
 jnz .bdl
 sfence
 mov eax,[r12+hda_route_program.saved_format]
 mov [r8+0x12],ax
 mov dword [r8+8],16384
 mov word [r8+12],3
 mov rax,[r12+hda_input.bdl_dma]
 mov [r8+0x18],eax
 shr rax,32
 mov [r8+0x1C],eax
 mov eax,[r12+hda_route_program.saved_tag]
 shl eax,4
 mov [r8+2],al
 mov byte [r8+3],0x1C
 mov eax,[r12+hda_input.sd_index]
 mov rdi,[r12+hda_input.position]
 mov dword [rdi+rax*8],0
 mov rdi,[rbx+hda_graph.mmio]
 mov ecx,[rdi+0x38]
 btr ecx,eax
 mov [rdi+0x38],ecx
 mov dword [r12+hda_input.stream_phase],HDI_FIFO
 call hdi_deadline
 test eax,eax
 jnz .uncertain
 jmp .yield
.fifo:
 test byte [r8+3],0x18
 jnz .dma_fault
 ; FIFORDY can remain clear until RUN lets the input descriptor engine load.
 ; Validate the initial positions and static FIFO bound before requesting RUN;
 ; readiness is acknowledged in STARTING, with the original run clock intact.
 mov r13d,[r8+4]
 test r13d,r13d
 jnz .position_fifo_lpib
 mov eax,[r12+hda_input.sd_index]
 mov rdi,[r12+hda_input.position]
 mov r13d,[rdi+rax*8]
 test r13d,r13d
 jnz .position_fifo_dpl
 movzx eax,word [r8+0x10]
 test eax,eax
 jz .dma_fault
 cmp eax,4096
 ja .dma_fault
 mov [r12+hda_input.fifo],eax
 mov ecx,16384
 sub ecx,eax
 mov rax,[r12+hda_input.clock_hz]
 imul rax,rcx
 mov ecx,[r12+hda_input.rate]
 imul ecx,[r12+hda_input.frame_bytes]
 xor edx,edx
 div rcx
 test rax,rax
 jz .clock
 mov [r12+hda_input.run_ticks],rax
 mov rax,[r12+hda_route_program.last_now]
 mov [r12+hda_input.run_start],rax
 mov [r12+hda_input.run_write_sample],rax
 mov qword [r12+hda_input.run_ack_sample],0
 mov qword [r12+hda_input.run_valid],1
 or byte [r8],2
 mov dword [r12+hda_input.stream_phase],HDI_STARTING
 call hdi_deadline
 test eax,eax
 jnz .uncertain
 jmp .yield
.starting:
 test byte [r8+3],0x18
 jnz .dma_fault
 test byte [r8],1
 jnz .dma_fault
 test byte [r8],2
 jz .yield
 test byte [r8+3],0x20
 jz .yield
 mov rax,[r12+hda_route_program.last_now]
 mov [r12+hda_input.run_ack_sample],rax
 mov qword [r12+hda_input.run_valid],3
 mov dword [r12+hda_input.stream_phase],HDI_RUNNING
 mov dword [r12+hda_input.stream_polls],0
 jmp .yield
.run:
 cmp r14,[r12+hda_route_program.last_now]
 jae .clock
 mov rax,[r12+hda_route_program.last_now]
 sub rax,[r12+hda_input.run_start]
 jc .clock
 cmp rax,[r12+hda_input.run_ticks]
 jae .position_entry_bound
 call hdi_sd
 inc qword [r12+hda_input.observation_count]
 mov rax,[r12+hda_route_program.last_now]
 mov [r12+hda_input.observation_now],rax
 xor eax,eax
 mov [r12+hda_input.observation_valid],rax
 mov [r12+hda_input.observation_selected],rax
 mov [r12+hda_input.observation_lpib_first],rax
 mov [r12+hda_input.observation_dpl],rax
 mov [r12+hda_input.observation_lpib_last],rax
 mov eax,[r8]                     ;owned SD CTL24/STS8, no W1C write
 mov ecx,eax
 shr eax,24
 and ecx,0xFFFFFF
 mov [r12+hda_input.observation_sd_status],rax
 mov [r12+hda_input.observation_sd_control],rcx
 test al,0x18
 jnz .dma_fault
 test cl,1
 jnz .dma_fault
 test cl,2
 jz .dma_fault
 mov r13d,[r8+4]
 mov [r12+hda_input.observation_lpib_first],r13
 mov qword [r12+hda_input.observation_valid],1
 mov ecx,[r12+hda_input.sd_index]
 mov rdi,[r12+hda_input.position]
 lfence
 mov edx,[rdi+rcx*8]
 mov [r12+hda_input.observation_dpl],rdx
 mov qword [r12+hda_input.observation_valid],3
 mov r9d,[r8+4]
 mov [r12+hda_input.observation_lpib_last],r9
 mov qword [r12+hda_input.observation_valid],7
 cmp r13d,edx
 jne .position_mismatch
 cmp r13d,r9d
 je .position_counts
.position_mismatch:
 inc qword [r12+hda_input.observation_mismatch_count]
.position_counts:
 mov eax,r13d
 or eax,edx
 or eax,r9d
 jnz .position_range
 inc qword [r12+hda_input.observation_zero_count]
.position_range:
 ; DPL updates periodically, independently of LPIB (Intel HDA 3.3.32).
 ; Within the entry/trailing no-wrap interval, their minimum is a
 ; conservative DMA-visible prefix. Validate ALL operands before min:
 ; neither a bad ring offset nor an in-poll wrap may be hidden by it.
 cmp r13d,16384
 jae .position_ring
 cmp edx,16384
 jae .position_ring
 cmp r9d,16384
 jae .position_ring
 cmp r9d,r13d
 jb .position_regress
 cmp r13d,edx
 cmova r13d,edx
 cmp r13d,r9d
 cmova r13d,r9d
 mov [r12+hda_input.observation_selected],r13
 cmp r13d,[r12+hda_input.last_pos]
 jb .position_regress
 ; Position was observed after the entry clock. Bound it with a trailing
 ; timestamp, then recheck authority and no-wrap time before granting data.
 call hda_program_clock
 test eax,eax
 jnz .clock
 call hdi_guard
 test eax,eax
 jnz .owner
 mov rax,[r12+hda_route_program.last_now]
 sub rax,[r12+hda_input.run_start]
 jc .clock
 cmp rax,[r12+hda_input.run_ticks]
 jae .position_trailing_bound
 call hdi_sd
 test byte [r8+3],0x18
 jnz .dma_fault
 test byte [r8],1
 jnz .dma_fault
 test byte [r8],2
 jz .dma_fault
 mov ecx,[r12+hda_input.rate]
 imul ecx,[r12+hda_input.frame_bytes]
 mov rax,[r12+hda_route_program.last_now]
 sub rax,[r12+hda_input.run_start]
 imul rax,rcx
 mov ecx,[r12+hda_input.fifo]
 imul rcx,[r12+hda_input.clock_hz]
 add rax,rcx
 mov edx,r13d
 imul rdx,[r12+hda_input.clock_hz]
 cmp rdx,rax
 ja .position_envelope
 mov eax,r13d
 shr eax,12
 mov edx,[r12+hda_input.last_pos]
 shr edx,12
 cmp eax,edx
 je .qualified
 test byte [r8+3],4
 jz .yield
.qualified:
 mov [r12+hda_input.last_pos],r13d
 cmp r13d,[r12+hda_input.target_bytes]
 jb .ack
 mov eax,[r12+hda_input.target_bytes]
 mov [r12+hda_input.qualified],eax
 and byte [r8],0xFD
 mov dword [r12+hda_input.stream_phase],HDI_HALTING
 call hdi_deadline
 test eax,eax
 jnz .uncertain
 jmp .yield
.ack:
 test byte [r8+3],4
 jz .yield
 mov byte [r8+3],4
 jmp .yield
.halting:
 test byte [r8],2
 jnz .yield
 or byte [r8],1
 mov dword [r12+hda_input.stream_phase],HDI_DRAIN_RESET
 call hdi_deadline
 test eax,eax
 jnz .uncertain
 jmp .yield
.drain_reset:
 test byte [r8],1
 jz .yield
 test byte [r8],2
 jnz .uncertain
 mov dword [rbx+hda_graph.input_quiescent],1
 cmp dword [r12+hda_input.operation],0
 jne .stopped
 cmp dword [r12+hda_input.qualified],0
 je .position_empty
 cmp dword [r12+hda_input.ready_bytes],0
 jne .dma_fault
 call hdi_receipt
 test eax,eax
 jnz .owner
 call hdi_owned
 test eax,eax
 jnz .owner
 ; Only now are producer writes revoked and a complete prefix qualified.
 mov ecx,[r12+hda_input.qualified]
 cmp ecx,[r12+hda_input.target_bytes]
 jne .position_length
 cmp ecx,8192
 ja .position_limit
 mov eax,[r12+hda_input.batch_frames]
 add rax,[r12+hda_input.captured_frames]
 jc .position_overflow
 js .position_signed
 mov r14,rax
 mov rsi,[r12+hda_input.pcm]
 mov rdi,[r12+hda_input.queue]
 rep movsb
 mov [r12+hda_input.captured_frames],r14
 mov eax,[r12+hda_input.qualified]
 mov [r12+hda_input.ready_bytes],eax ;atomic publication after complete byte copy
 mov dword [r12+hda_input.read_offset],0
 mov dword [r12+hda_input.stream_phase],HDI_BATCH
 jmp .ready
.stopped:
 mov dword [r12+hda_input.stream_phase],HDI_STOPPED
 jmp .bad
.ready:
 mov eax,2
 jmp .out
.yield:
 mov eax,1
 jmp .out
.owner:
 mov esi,1
 jmp .fault
.clock:
 mov esi,2
 jmp .fault
.dma_fault:
 mov esi,3
 jmp .fault
.position_fifo_lpib:
 mov esi,1
 jmp .position_record
.position_fifo_dpl:
 mov esi,2
 jmp .position_record
.position_entry_bound:
 mov esi,3
 jmp .position_record
.position_ring:
 mov esi,4
 jmp .position_record
.position_regress:
 mov esi,5
 jmp .position_record
.position_trailing_bound:
 mov esi,6
 jmp .position_record
.position_envelope:
 mov esi,7
 jmp .position_record
.position_empty:
 mov esi,8
 jmp .position_record
.position_length:
 mov esi,9
 jmp .position_record
.position_limit:
 mov esi,10
 jmp .position_record
.position_overflow:
 mov esi,11
 jmp .position_record
.position_signed:
 mov esi,12
 jmp .position_record
.position_record:
 call hdi_position_failure
 mov esi,4
.fault:
 call hdi_fail
 jmp .bad
.uncertain_polls:
 mov esi,13
 jmp .uncertain_record
.uncertain_deadline:
 mov esi,14
 jmp .uncertain_record
.uncertain_state:
 mov esi,15
 jmp .uncertain_record
.uncertain_run:
 mov esi,16
 jmp .uncertain_record
.uncertain:                       ; failed construction of next deadline
 mov esi,17
.uncertain_record:
 call hdi_sd
 cmp qword [r12+hda_input.failure_reason],0
 jne .uncertain_stop
 ; Snapshot only the owned mapped SD, before the existing stop request.
 ; Read control bytes separately from RW1C status; no write/ack added.
 movzx eax,word [r8]
 movzx edx,byte [r8+2]
 shl edx,16
 or eax,edx
 mov [r12+hda_input.failure_sd_control],rax
 movzx eax,byte [r8+3]
 mov [r12+hda_input.failure_sd_status],rax
 call hdi_position_failure
.uncertain_stop:
 call hdi_sd
 and byte [r8],0xFD             ;request own stop; no acknowledgment/free credit
 mov dword [rbx+hda_graph.input_ready],0
 mov dword [r12+hda_input.stream_error],5
 mov dword [r12+hda_input.stream_phase],HDI_FAILED
.bad:
 mov rax,-1
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; First rejection snapshot of existing context and the rejected raw operand.
; No new clock reads or changed credit/bounds/stop/reset behavior.
; Position paths add no MMIO reads; uncertainty records owned SD CTL/STS once.
; reason1/2 FIFO nonzero LPIB/DPL,3 entry no-wrap bound,4 ring,5 regression,
; 6 trailing no-wrap bound,7 rate/FIFO envelope,8 missing qualified prefix,
; 9 wrong qualified length,10 length above queue,11 unsigned/12 signed total.
; reasons13 poll limit,14 deadline elapsed,15 unknown pending phase,
; 16 RUN set after reset clear,17 next deadline overflow.
; raw_valid:0 no observed operand,1 LPIB only,2 DPL only,3 both sampled.
; Survives fault/cleanup/retire; cleared only by an admitted begin.
hdi_position_failure:
 cmp qword [r12+hda_input.failure_reason],0
 jne .out
 xor eax,eax
 mov [r12+hda_input.failure_raw_pos],rax
 mov [r12+hda_input.failure_raw_dpl],rax
 mov [r12+hda_input.failure_raw_valid],rax
 cmp esi,1
 je .lpib
 cmp esi,2
 je .dpl
 cmp esi,4
 jb .snapshot
 cmp esi,7
 ja .snapshot
 mov rax,[r12+hda_input.observation_lpib_first]
 mov [r12+hda_input.failure_raw_pos],rax
 mov rax,[r12+hda_input.observation_dpl]
 mov [r12+hda_input.failure_raw_dpl],rax
 mov qword [r12+hda_input.failure_raw_valid],3
 jmp .snapshot
.lpib:
 mov eax,r13d
 mov [r12+hda_input.failure_raw_pos],rax
 mov qword [r12+hda_input.failure_raw_valid],1
 jmp .snapshot
.dpl:
 mov eax,r13d
 mov [r12+hda_input.failure_raw_dpl],rax
 mov qword [r12+hda_input.failure_raw_valid],2
.snapshot:
 mov rax,[r12+hda_route_program.epoch]
 mov [r12+hda_input.failure_epoch],rax
 mov eax,[r12+hda_input.stream_phase]
 mov [r12+hda_input.failure_phase],rax
 mov rax,[r12+hda_route_program.last_now]
 mov [r12+hda_input.failure_now],rax
 mov rax,[r12+hda_input.run_start]
 mov [r12+hda_input.failure_run_start],rax
 mov rax,[r12+hda_input.run_ticks]
 mov [r12+hda_input.failure_run_ticks],rax
 mov rax,[r12+hda_input.clock_hz]
 mov [r12+hda_input.failure_clock_hz],rax
 mov eax,[r12+hda_input.rate]
 mov [r12+hda_input.failure_rate],rax
 mov eax,[r12+hda_input.fifo]
 mov [r12+hda_input.failure_fifo],rax
 mov eax,[r12+hda_input.frame_bytes]
 mov [r12+hda_input.failure_frame_bytes],rax
 mov eax,[r12+hda_input.target_bytes]
 mov [r12+hda_input.failure_target_bytes],rax
 mov eax,[r12+hda_input.last_pos]
 mov [r12+hda_input.failure_last_pos],rax
 mov eax,[r12+hda_input.qualified]
 mov [r12+hda_input.failure_qualified],rax
 mov rax,[r12+hda_input.captured_frames]
 mov [r12+hda_input.failure_captured_frames],rax
 mov rax,[r12+hda_input.taken_frames]
 mov [r12+hda_input.failure_taken_frames],rax
 mov eax,[r12+hda_input.ready_bytes]
 mov [r12+hda_input.failure_ready_bytes],rax
 mov eax,[r12+hda_input.read_offset]
 mov [r12+hda_input.failure_read_offset],rax
 mov eax,[r12+hda_input.stream_polls]
 mov [r12+hda_input.failure_polls],rax
 mov rax,[r12+hda_input.state_deadline]
 mov [r12+hda_input.failure_deadline],rax
 mov [r12+hda_input.failure_reason],rsi ;publish last, preserve first
.out:
 ret

; Write-free stopped-batch/span admission for the sound adapter. Same current
; ownership/config/receipt and RUN0/SRST1 required as take; no samples consumed.
; (ctx,epoch,external,bytes) ->0/-1. Stable mapped trusted external span.
hda_input_batch_check:
 HDA_INPUT_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov rbp,rdx
 mov r14,rcx
 cmp rsi,[r12+hda_route_program.epoch]
 jne .bad
 cmp dword [r12+hda_input.stream_phase],HDI_BATCH
 jne .bad
 cmp dword [r12+hda_input.retired],0
 jne .bad
 cmp dword [r12+hda_input.operation],0
 jne .bad
 call hdi_guard
 test eax,eax
 jnz .bad
 cmp dword [rbx+hda_graph.input_ready],1
 jne .bad
 cmp dword [rbx+hda_graph.input_quiescent],1
 jne .bad
 call hdi_sd
 movzx eax,byte [r8]
 and eax,3
 cmp eax,1
 jne .bad
 test r14,r14
 jz .bad
 mov rsi,rbp
 mov rdx,r14
 call hdi_buffer_separate
 jc .bad
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

hda_input_take:
 HDA_INPUT_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov rbp,rdx
 mov r14,rcx
 cmp rsi,[r12+hda_route_program.epoch]
 jne .bad
 cmp dword [r12+hda_input.stream_phase],HDI_BATCH
 jne .bad
 cmp dword [r12+hda_input.retired],0
 jne .bad
 cmp r14,2048
 ja .bad
 call hdi_guard
 test eax,eax
 jnz .fault
 cmp dword [rbx+hda_graph.input_ready],1
 jne .bad
 call hdi_sd
 movzx eax,byte [r8]
 and eax,3
 cmp eax,1
 jne .bad
 mov eax,[r12+hda_input.ready_bytes]
 cmp eax,8192
 ja .bad
 mov ecx,[r12+hda_input.frame_bytes]
 xor edx,edx
 div ecx
 test edx,edx
 jnz .bad
 cmp r14,rax
 cmova r14,rax
 test r14,r14
 jz .zero
 mov rdx,r14
 imul rdx,rcx
 mov rsi,rbp
 call hdi_buffer_separate
 jc .bad
 mov eax,[r12+hda_input.read_offset]
 cmp eax,8192
 ja .bad
 lea r13,[rax+rdx]
 cmp r13,8192
 ja .bad
 mov rax,[r12+hda_input.taken_frames]
 add rax,r14
 jc .bad
 js .bad
 push rax
 mov rsi,[r12+hda_input.queue]
 mov ecx,[r12+hda_input.read_offset]
 add rsi,rcx
 mov rdi,rbp
 mov rcx,rdx
 rep movsb
 pop rax
 mov [r12+hda_input.taken_frames],rax
 mov [r12+hda_input.read_offset],r13d
 sub [r12+hda_input.ready_bytes],edx
 mov rax,r14
 jmp .out
.zero:
 xor eax,eax
 jmp .out
.fault:
 mov esi,1
 call hdi_fail
.bad:
 mov rax,-1
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

hda_input_stop:
 HDA_INPUT_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .bad
 cmp dword [r12+hda_input.retired],0
 jne .bad
 call hdi_owned
 test eax,eax
 jnz .bad
 ; A repeated cancellation is observation only. In particular, never move an
 ; acknowledged RUN0/SRST request back to HALTING or renew a finite deadline.
 ; Identity/config remain mandatory even after route/DID3 readiness revocation.
 cmp dword [r12+hda_input.operation],1
 jne .request
 mov eax,[r12+hda_input.stream_phase]
 cmp eax,HDI_HALTING
 je .pending
 cmp eax,HDI_DRAIN_RESET
 je .pending
 cmp eax,HDI_STOPPED
 jne .bad
 cmp dword [rbx+hda_graph.input_quiescent],1
 jne .bad
 call hdi_sd
 movzx eax,byte [r8]
 and eax,3
 cmp eax,1
 jne .bad
 xor eax,eax
 jmp .out
.request:
 cmp dword [r12+hda_input.stream_phase],HDI_FAILED
 jae .bad
 call hda_program_clock
 test eax,eax
 jnz .clock
 xor esi,esi
 call hdi_fail
.pending:
 mov eax,1
 jmp .out
.clock:
 mov esi,2
 call hdi_fail
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret
hda_input_retire:
 HDA_INPUT_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .bad
 cmp dword [r12+hda_input.stream_phase],HDI_STOPPED
 jne .bad
 call hdi_owned
 test eax,eax
 jnz .bad
 cmp dword [rbx+hda_graph.input_quiescent],1
 jne .bad
 call hdi_sd
 movzx eax,byte [r8]
 and eax,3
 cmp eax,1
 jne .bad
 mov dword [r12+hda_input.retired],1
 mov dword [r12+hda_input.stream_phase],HDI_RETIRED
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hdi_span:
 test rdx,rdx
 jz .empty
 test rax,rax
 jz .bad
 mov [rdi],rax
 add rax,rdx
 jc .bad
 mov [rdi+8],rax
 clc
 ret
.empty:
 mov qword [rdi],0
 mov qword [rdi+8],0
 clc
 ret
.bad:
 stc
 ret
hdi_disjoint:
 mov esi,160
hdi_pairs:
 xor ecx,ecx
.outer:
 mov r8,[rdi+rcx]
 mov r9,[rdi+rcx+8]
 cmp r8,r9
 je .next
 lea edx,[rcx+16]
.inner:
 cmp edx,esi
 jae .next
 mov r10,[rdi+rdx]
 mov r11,[rdi+rdx+8]
 cmp r10,r11
 je .skip
 cmp r8,r11
 jae .skip
 cmp r10,r9
 jb .bad
.skip:
 add edx,16
 jmp .inner
.next:
 add ecx,16
 cmp ecx,esi
 jb .outer
 clc
 ret
.bad:
 stc
 ret
%macro HDI_EXT 2
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
hdi_graph_external:
 HDI_EXT [rbx+hda_graph.transport],hda_transport_size
 HDI_EXT [rbx+hda_graph.corb],1024
 HDI_EXT [rbx+hda_graph.rirb],2048
 mov ecx,[rbx+hda_graph.codec_cap]
 shl ecx,5
 HDI_EXT [rbx+hda_graph.codecs],rcx
 mov ecx,[rbx+hda_graph.group_cap]
 imul ecx,ecx,hda_group_info_size
 HDI_EXT [rbx+hda_graph.groups],rcx
 clc
 ret
.bad:
 stc
 ret
hdi_external_spans:
 push rbp
 push r13
 push r14
 mov rbp,rdi
 xor r14d,r14d
.loop:
 mov r10,[rbp+r14]
 mov r11,[rbp+r14+8]
 call hdi_graph_external
 jc .bad
 cmp r14d,64
 jae .next
 mov r13,[rbx+hda_graph.command_owner]
 test r13,r13
 jz .pcm
 mov r8,r13
 mov r9,hda_route_program_size
 add r9,r8
 cmp r10,r9
 jae .pcm
 cmp r8,r11
 jb .bad
.pcm:
 mov r13,[rbx+hda_graph.pcm_owner]
 test r13,r13
 jz .next
 xor edx,edx
.old_span:
 mov r8,[r13+rdx+hda_pcm.spans]
 mov r9,[r13+rdx+hda_pcm.spans+8]
 cmp r10,r9
 jae .old_next
 cmp r8,r11
 jb .bad
.old_next:
 add edx,16
 cmp edx,160
 jb .old_span
.next:
 add r14d,16
 cmp r14d,160
 jb .loop
 clc
 jmp .out
.bad:
 stc
.out:
 pop r14
 pop r13
 pop rbp
 ret
hdi_buffer_separate:
 mov r10,rsi
 mov r11,rsi
 test rsi,rsi
 jz .bad
 add r11,rdx
 jc .bad
 lea rdi,[r12+hda_input.spans]
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
 push rdx
 call hdi_graph_external
 jc .external_bad
 call hdi_output_span_separate
 pop rdx
 ret
.external_bad:
 pop rdx
.bad:
 stc
 ret

; R10/R11 buffer range, disjoint from every represented output-owned span.
hdi_output_span_separate:
 mov rsi,[rbx+hda_graph.command_owner]
 test rsi,rsi
 jz .pcm
 mov r8,rsi
 lea r9,[rsi+hda_route_program_size]
 cmp r10,r9
 jae .pcm
 cmp r8,r11
 jb .bad
.pcm:
 mov rsi,[rbx+hda_graph.pcm_owner]
 test rsi,rsi
 jz .ok
 xor edi,edi
.span:
 mov r8,[rsi+rdi+hda_pcm.spans]
 mov r9,[rsi+rdi+hda_pcm.spans+8]
 cmp r10,r9
 jae .next
 cmp r8,r11
 jb .bad
.next:
 add edi,16
 cmp edi,160
 jb .span
.ok:
 clc
 ret
.bad:
 stc
 ret

%macro WDATA_hda_input_power 0
 align 8
hda_input_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_input_power
%else
 section .data
 WDATA_hda_input_power
 section .text
%endif
