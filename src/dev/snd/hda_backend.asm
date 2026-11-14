;; MODULE dev/snd/hda_backend
;; LAYER 3
;; EXPORTS hda_backend_census_identity, hda_backend_select48, hda_backend_select_output48, hda_backend_select_output, hda_backend_discover_begin, hda_backend_discovery_check, hda_backend_select, hda_backend_begin, hda_backend_step, hda_backend_start, hda_backend_drain, hda_backend_halt, hda_backend_retire, hda_backend_device, hda_backend_register, hda_backend_deregister, hda_backend_input_start, hda_backend_input_take, hda_backend_input_batch, hda_backend_prime_cyclic
;; IMPORTS boot/native_driver_gate, dev/snd/hda_input_route, dev/snd/hda_session, dev/snd/hda_route_program, dev/snd/hda_output, dev/snd/hda_pcm, dev/snd/hda_input, core/dma, snd/core
;; CAPS mmio dma
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_BACKEND_POWER 0-1 -1
 cmp qword [rel hda_backend_power_gate],0
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
 call [rel hda_backend_power_gate]
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
 mov rax,%1
 ret
%%admit:
%endmacro

;
; Trusted controller-owned cooperative production composition. See
; docs/HDA_COOPERATIVE_BACKEND.md for stable caller inputs and reset contract.
; No boot activation, attach, PCI, allocation, IRQ, mapping or free operation.
; Actual enforcing DID3 receipt required before FIRST output bind and every
; admission/service. Stop after receipt loss uses identity, never a replacement
; receipt. Epoch/immutable-span loss revokes without foreign MMIO. Uncertainty
; keeps ALL storage pinned. Private child states are not public readiness.
;
; begin(ctx,epoch)->0/-1; step->1 work/2 ready/0 stopped/-1 uncertainty.
; start/drain/halt->primitive scheduling status; retire->0/-1. device returns
; guarded snddev* or0. Registration is explicit and uses the sole sound core.
; Optional input_start/take use exact input primitive ABI (take is FRAMES).
; Output vtable remains playback only; capture availability is independent.
; Each step calls at most one child step/transition. No unbounded polling.
; SysV GPR/RSP, DF0. Caller serializes all calls and callbacks, including core.

HDAB_DEFER_SELECTION equ 0x40000000
HDAB_GRAPH equ 1
HDAB_PREPARE equ 2
HDAB_PROGRAM equ 3
HDAB_PCM equ 4
HDAB_READY equ 5
HDAB_HALT equ 6
HDAB_STOPPED equ 7
HDAB_UNCERTAIN equ 8
HDAB_RETIRED equ 9
; input_state:0 absent,1 needs begin,2 programming,3 ready,4 failed,5 retired,6 explicitly disabled.
struc hda_backend
 .graph: resq 1
 .program: resq 1
 .output: resq 1
 .pcm: resq 1
 .input: resq 1
 .map_serial: resq 1
 .epoch: resq 1
 .phase: resd 1
 .error: resd 1
 .registered: resd 1
 .graph_begun: resd 1
 .output_bound: resd 1
 .pcm_bound: resd 1
 .input_state: resd 1
 .input_cleanup_polls: resd 1
 .input_halted: resd 1
 .output_halted: resd 1
 .turn: resd 1
 .polls: resd 1
 .last_now: resq 1
 .observed_now: resq 1
 .deadline: resq 1
 .saved: resb 576
 .spans: resb 352
 .device: resb dev_size
 .ops: resb snd_ops_size
 .info: resb snd_info_size
 .info_pad: resd 1
 .pcm_begin_refusal equ .info_pad ; retained private admission code; same layout
endstruc

%macro HDAB_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov rbp,rsi
%endmacro
%macro HDAB_LEAVE 0
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro
%macro HDAB_SPAN 3
 mov rax,%1
 mov rdx,%2
 lea rdi,[r12+hda_backend.spans+%3*16]
 call hdab_span
 jc .bad
%endmacro
%macro HDAB_CHILD 2
 mov rdi,[r12+hda_backend.%1]
 mov rsi,[r12+hda_backend.epoch]
 call %2
%endmacro

; Discovery-only entry shares exact begin/bind/graph acquisition. No separate
; transport owner, output programming or readiness. Metadata placeholders may
; be selected only through the guarded select API below after graph publication.
hda_backend_discover_begin:
    NATIVE_DRIVER_REFUSE 7
 HDA_BACKEND_POWER
 push rbx
 mov rbx,rdi
 call hda_backend_begin
 test rax,rax
 jnz .out
 mov dword [rbx+hda_backend.error],HDAB_DEFER_SELECTION
.out:
 pop rbx
 ret

; Identity+receipt/config check for this exclusive pre-program read-only client.
; Pending transport belongs to the caller's retained fixed query; not readiness.
hda_backend_discovery_check:
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 cmp dword [r12+hda_backend.phase],HDAB_PREPARE
 jne .bad
 cmp dword [r12+hda_backend.error],HDAB_DEFER_SELECTION
 je .state_ok
 cmp dword [r12+hda_backend.error],0
 jne .bad
.state_ok:
 call hdab_owned
 test eax,eax
 jnz .bad
 call hdab_receipt
 test eax,eax
 jnz .bad
 cmp dword [rbx+hda_graph.phase],HDAGS_DONE
 jne .bad
 cmp qword [rbx+hda_graph.command_owner],0
 jne .bad
 cmp qword [rbx+hda_graph.input_owner],0
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE

; select(ctx,epoch,numeric_selection32*) ->0 selected/-1 unchanged refusal.
; u32 codec,AFG,outpin,DAC,inpin,ADC,input_channels,VRef. The actual controller
; owner checks physical pin presence/type first. This API independently replans
; both analog paths, verifies the same exclusive discovery/receipt/epoch and
; refuses selection aliases. It changes only saved route inputs, not hardware.
hda_backend_select:
 xor r9d,r9d
 jmp hdab_select
; Same retained input storage and protected spans, but never program or start
; that input. All four input selection words MUST be zero. Private state6 is
; fixed by this explicit deferred-selection transition before device admission.
hda_backend_select_output:
 mov r9d,1
 jmp hdab_select
; Explicit finite S16 mono48k profile. Reconfigure only still-BOUND output
; and not-yet-begun PCM at the existing deferred-selection commit boundary.
hda_backend_select_output48:
 mov r9d,2
 jmp hdab_select
; Explicit paired48k; both still-unbegun routes change at one commit boundary.
hda_backend_select48:
 mov r9d,3
hdab_select:
 HDA_BACKEND_POWER
 HDAB_ENTER
 sub rsp,176
 mov [rsp+144],rdx
 mov [rsp+152],r9d
 cmp dword [r12+hda_backend.error],HDAB_DEFER_SELECTION
 jne .bad
 mov rdi,r12
 mov rsi,rbp
 call hda_backend_discovery_check
 test rax,rax
 jnz .bad
 mov rbx,[r12+hda_backend.graph]
 mov rax,[rbx+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .bad
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 mov r13,[r12+hda_backend.output]
 cmp dword [r13+hda_output.state],HDAO_BOUND
 jne .bad
 mov r14,[r12+hda_backend.pcm]
 cmp dword [r14+hda_pcm.phase],0
 jne .bad
 cmp dword [rsp+152],2
 jb .rate_valid
 cmp dword [r14+hda_pcm.rate],44100
 jne .bad
 cmp dword [r14+hda_pcm.channels],1
 jne .bad
 cmp dword [r14+hda_pcm.sample_format],1
 ja .bad
 cmp dword [r13+hda_output.format],0x4011
 jne .bad
 mov rax,[r12+hda_backend.program]
 cmp dword [rax+hda_route_program.format],0x4011
 jne .bad
.rate_valid:
 mov rax,[r12+hda_backend.input]
 test rax,rax
 jz .bad
 cmp dword [rax+hda_route_program.phase],0
 jne .bad
 cmp dword [rsp+152],3
 jne .input_rate_valid
 cmp dword [rax+hda_input.rate],44100
 jne .bad
 cmp dword [rax+hda_input.stream_phase],0
 jne .bad
.input_rate_valid:
 mov rsi,[rsp+144]
 test rsi,rsi
 jz .bad
 test sil,3
 jnz .bad
 lea r8,[rsi+32]
 cmp r8,rsi
 jb .bad
 mov rax,r8
 dec rax
 shr rax,47
 jnz .bad
 xor ecx,ecx
.separate:
 mov rax,[r12+hda_backend.spans+rcx]
 mov rdx,[r12+hda_backend.spans+rcx+8]
 test rdx,rdx
 jz .next
 cmp rsi,rdx
 jae .next
 cmp rax,r8
 jb .bad
.next:
 add ecx,16
 cmp ecx,352
 jb .separate
 cmp dword [rsp+152],3
 je .paired_fields
 cmp dword [rsp+152],0
 je .paired_fields
 mov rax,[rsi+16]
 or rax,[rsi+24]
 jnz .bad
 jmp .plan
.paired_fields:
 mov eax,[rsi+24]
 dec eax
 cmp eax,1
 ja .bad
 mov eax,[rsi+28]
 cmp eax,5
 ja .bad
 cmp eax,3
 je .bad
.plan:
 ; Construct disjoint temporary planner views; caller numeric selection stays RO.
 mov rdi,rsp
 xor eax,eax
 mov ecx,136/8
 rep stosq
 mov rdi,rsp
 call hdab_view
 mov rsi,[rsp+144]
 mov rax,[rsi]
 mov [rsp+32],rax
 mov rax,[rsi+8]
 mov [rsp+40],rax
 mov rdi,rsp
 call hda_route_plan
 test rax,rax
 jnz .bad
 cmp dword [rsp+152],3
 je .plan_input
 cmp dword [rsp+152],0
 jne .commit
.plan_input:
 lea rdi,[rsp+64]
 call hdab_view
 mov rsi,[rsp+144]
 mov rax,[rsi]
 mov [rsp+64+32],rax
 mov eax,[rsi+20]
 mov [rsp+64+40],eax
 mov eax,[rsi+16]
 mov [rsp+64+44],eax
 mov eax,[rsi+24]
 mov [rsp+64+64],eax
 lea rdi,[rsp+64]
 call hda_input_route_plan
 test rax,rax
 jnz .bad
.commit:
 ; No fallible operation remains. Commit numeric configuration atomically and
 ; refresh the coordinator's immutable snapshot at this explicit transition.
 mov rdx,[r12+hda_backend.program]
 mov rax,[rsp+32]
 mov [rdx+hda_route_program.route+32],rax
 mov rax,[rsp+40]
 mov [rdx+hda_route_program.route+40],rax
 cmp dword [rsp+152],3
 je .commit_paired48
 cmp dword [rsp+152],0
 je .commit_input
 mov dword [r12+hda_backend.input_state],6
 cmp dword [rsp+152],2
 jne .selected
 ; Every refusal is above; no MMIO, reset or live stream can occur here.
 mov dword [r14+hda_pcm.rate],48000
 mov dword [r13+hda_output.format],0x11
 mov dword [rdx+hda_route_program.format],0x11
 jmp .selected
.commit_paired48:
 mov dword [r14+hda_pcm.rate],48000
 mov dword [r13+hda_output.format],0x11
 mov dword [rdx+hda_route_program.format],0x11
 mov rdx,[r12+hda_backend.input]
 mov dword [rdx+hda_input.rate],48000
.commit_input:
 mov rdx,[r12+hda_backend.input]
 mov rax,[rsp+64+32]
 mov [rdx+hda_input.route+32],rax
 mov rax,[rsp+64+40]
 mov [rdx+hda_input.route+40],rax
 mov eax,[rsp+64+64]
 mov [rdx+hda_input.route+64],eax
 dec eax
 or eax,0x10
 cmp dword [rdx+hda_input.rate],96000
 jne .input_base_rate
 or eax,0x800
 jmp .format
.input_base_rate:
 cmp dword [rdx+hda_input.rate],44100
 jne .format
 or eax,0x4000
.format:
 mov [rdx+hda_route_program.format],eax
 mov rsi,[rsp+144]
 mov eax,[rsi+28]
 mov [rdx+hda_input.vref],eax
.selected:
 mov dword [r12+hda_backend.error],0
 call hdab_save
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,176
 HDAB_LEAVE

hda_backend_begin:
    NATIVE_DRIVER_REFUSE 7
 HDA_BACKEND_POWER
 HDAB_ENTER
 test r12,r12
 jz .bad
 mov rax,r12
 add rax,hda_backend_size
 jc .bad
 ; Single-use context: a fresh context and strictly newer graph epoch are
 ; required for restart. Old registered device/handles can never be revived.
 cmp dword [r12+hda_backend.phase],0
 jne .bad
 mov rax,rbp
 dec rax
 cmp rax,65534
 ja .bad
 mov rbx,[r12+hda_backend.graph]
 mov r13,[r12+hda_backend.output]
 mov r14,[r12+hda_backend.pcm]
 HDAB_SPAN r12,hda_backend_size,0
 HDAB_SPAN rbx,hda_graph_size,1
 HDAB_SPAN [rbx+hda_graph.owner],hda_graph_lease_size,2
 mov rax,[rbx+hda_graph.owner]
 mov rax,[rax+hda_graph_lease.transport]
 HDAB_SPAN rax,hda_transport_size,3
 mov rax,[r12+hda_backend.spans+3*16]
 HDAB_SPAN [rax+hda_transport.corb],1024,4
 mov rax,[r12+hda_backend.spans+3*16]
 HDAB_SPAN [rax+hda_transport.rirb],2048,5
 mov rax,[r12+hda_backend.spans+3*16]
 HDAB_SPAN [rax+hda_transport.mmio],4096,6
 mov edx,[rbx+hda_graph.codec_cap]
 cmp edx,15
 ja .bad
 shl edx,5
 HDAB_SPAN [rbx+hda_graph.codecs],rdx,7
 mov edx,[rbx+hda_graph.group_cap]
 cmp edx,1905
 ja .bad
 imul edx,24
 HDAB_SPAN [rbx+hda_graph.groups],rdx,8
 mov edx,[rbx+hda_graph.widget_cap]
 cmp edx,1905
 ja .bad
 shl edx,5
 HDAB_SPAN [rbx+hda_graph.widgets],rdx,9
 mov edx,[rbx+hda_graph.edge_cap]
 cmp edx,2048
 ja .bad
 imul edx,24
 HDAB_SPAN [rbx+hda_graph.edges],rdx,10
 HDAB_SPAN [r12+hda_backend.program],hda_route_program_size,11
 HDAB_SPAN r13,hda_output_size,12
 HDAB_SPAN r14,hda_pcm_size,13
 HDAB_SPAN [r14+hda_pcm.queue],[r14+hda_pcm.queue_bytes],14
 HDAB_SPAN [r13+hda_output.bdl],64,15
 HDAB_SPAN [r13+hda_output.pcm],16384,16
 HDAB_SPAN [r13+hda_output.position],256,17
 mov rax,[r12+hda_backend.input]
 test rax,rax
 jz .no_input
 HDAB_SPAN rax,hda_input_size,18
 mov rax,[r12+hda_backend.input]
 HDAB_SPAN [rax+hda_input.bdl],64,19
 mov rax,[r12+hda_backend.input]
 HDAB_SPAN [rax+hda_input.pcm],16384,20
 mov rax,[r12+hda_backend.input]
 HDAB_SPAN [rax+hda_input.queue],8192,21
 mov rax,[r12+hda_backend.input]
 mov rdx,[rax+hda_input.position]
 cmp rdx,[r13+hda_output.position]
 jne .bad
 mov rdx,[rax+hda_input.position_dma]
 cmp rdx,[r13+hda_output.position_dma]
 jne .bad
 cmp [rax+hda_route_program.graph],rbx
 jne .bad
 mov rdx,[rax+hda_input.map_serial]
 cmp rdx,[r12+hda_backend.map_serial]
 jne .bad
 jmp .pairs
.no_input:
 lea rdi,[r12+hda_backend.spans+18*16]
 xor eax,eax
 mov ecx,8
 rep stosq
.pairs:
 lea rdi,[r12+hda_backend.spans]
 call hdab_disjoint
 jc .bad
 cmp qword [r12+hda_backend.map_serial],0
 je .bad
 mov eax,[rbx+hda_graph.phase]
 test eax,eax
 jz .fresh_graph
 cmp eax,HDAGS_RETIRED
 jne .bad
.fresh_graph:
 cmp rbp,[rbx+hda_graph.epoch]
 jbe .bad
 cmp dword [r13+hda_output.state],0
 jne .bad
 cmp dword [r14+hda_pcm.phase],0
 jne .bad
 cmp [r14+hda_pcm.graph],rbx
 jne .bad
 cmp [r14+hda_pcm.output],r13
 jne .bad
 mov rax,[r12+hda_backend.program]
 cmp [r14+hda_pcm.program],rax
 jne .bad
 cmp [rax+hda_route_program.graph],rbx
 jne .bad
 cmp dword [rax+hda_route_program.phase],0
 jne .bad
 mov rdx,[r14+hda_pcm.map_serial]
 cmp rdx,[r12+hda_backend.map_serial]
 jne .bad
 mov rdx,[rbx+hda_graph.clock_fn]
 test rdx,rdx
 jz .bad
 cmp rdx,[r14+hda_pcm.clock_fn]
 jne .bad
 mov rdx,[rbx+hda_graph.clock_arg]
 cmp rdx,[r14+hda_pcm.clock_arg]
 jne .bad
 mov rdx,[r12+hda_backend.spans+6*16]
 cmp [r13+hda_output.mmio],rdx
 jne .bad
 mov [r12+hda_backend.epoch],rbp
 call hdab_save
 call hdab_owned
 test eax,eax
 jnz .bad
 call hdab_receipt
 test eax,eax
 jnz .bad
 cmp dword [r14+hda_pcm.sample_format],SNDFMT_S24LE
 ja .bad
 ; No live streams/rings may be rebound by this actual primitive. It checks
 ; GCAP, spans/IOVA width, all SD RUN bits, CORB/RIRB DMA and full output sizes.
 mov rdi,r13
 mov esi,[r14+hda_pcm.rate]
 mov edx,2
 mov rax,[r12+hda_backend.program]
 mov ecx,[rax+hda_route_program.tag]
 cmp dword [r14+hda_pcm.sample_format],SNDFMT_S24LE
 je .bind_s24
 call hda_output_bind
 jmp .bound_width
.bind_s24:
 call hda_output_bind_s24
.bound_width:
 test eax,eax
 jnz .uncertain
 mov dword [r12+hda_backend.output_bound],1
 call hdab_save
 HDAB_CHILD graph,hda_graph_begin
 test eax,eax
 jnz .uncertain
 mov dword [r12+hda_backend.graph_begun],1
 mov dword [r12+hda_backend.phase],HDAB_GRAPH
 mov eax,0
 jmp .out
.uncertain:
 mov dword [r12+hda_backend.phase],HDAB_UNCERTAIN
 mov dword [r12+hda_backend.error],1
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE

; Fixed configuration snapshot. Never use a changed pointer for cleanup.
hdab_save:
 mov rbx,[r12+hda_backend.graph]
 mov r13,[r12+hda_backend.output]
 mov r14,[r12+hda_backend.pcm]
 mov r8,[rbx+hda_graph.owner]
 mov r9,[r8+hda_graph_lease.transport]
 mov r10,[r12+hda_backend.program]
 mov r11,[r12+hda_backend.input]
 lea rsi,[r12+0]
 lea rdi,[r12+hda_backend.saved+0]
 mov ecx,12
 rep movsd
 lea rsi,[rbx+0]
 lea rdi,[r12+hda_backend.saved+48]
 mov ecx,30
 rep movsd
 lea rsi,[r8+0]
 lea rdi,[r12+hda_backend.saved+168]
 mov ecx,6
 rep movsd
 lea rsi,[r9+0]
 lea rdi,[r12+hda_backend.saved+192]
 mov ecx,6
 rep movsd
 lea rsi,[r13+0]
 lea rdi,[r12+hda_backend.saved+216]
 mov ecx,16
 rep movsd
 lea rsi,[r13+hda_output.mmio_bytes]
 lea rdi,[r12+hda_backend.saved+280]
 mov ecx,8
 rep movsd
 lea rsi,[r14+0]
 lea rdi,[r12+hda_backend.saved+312]
 mov ecx,22
 rep movsd
 lea rsi,[r10+0]
 lea rdi,[r12+hda_backend.saved+400]
 mov ecx,2
 rep movsd
 lea rsi,[r10+hda_route_program.format]
 lea rdi,[r12+hda_backend.saved+408]
 mov ecx,2
 rep movsd
 lea rsi,[r10+hda_route_program.route+hda_route_context.codec]
 lea rdi,[r12+hda_backend.saved+416]
 mov ecx,4
 rep movsd
 test r11,r11
 jz .done
 lea rsi,[r11+0]
 lea rdi,[r12+hda_backend.saved+432]
 mov ecx,2
 rep movsd
 lea rsi,[r11+hda_route_program.format]
 lea rdi,[r12+hda_backend.saved+440]
 mov ecx,2
 rep movsd
 lea rsi,[r11+hda_input.route+hda_input_route.codec]
 lea rdi,[r12+hda_backend.saved+448]
 mov ecx,4
 rep movsd
 lea rsi,[r11+hda_input.route+hda_input_route.channels]
 lea rdi,[r12+hda_backend.saved+464]
 mov ecx,2
 rep movsd
 lea rsi,[r11+hda_input.bdl]
 lea rdi,[r12+hda_backend.saved+472]
 mov ecx,24
 rep movsd
.done:
 xor eax,eax
 ret
hdab_match:
 lea rdi,[r12+hda_backend.saved]
 mov rsi,r12
 mov ecx,6
 repe cmpsq
 jne .bad
 mov rbx,[r12+hda_backend.graph]
 mov r13,[r12+hda_backend.output]
 mov r14,[r12+hda_backend.pcm]
 mov r8,[rbx+hda_graph.owner]
 mov r9,[r8+hda_graph_lease.transport]
 mov r10,[r12+hda_backend.program]
 mov r11,[r12+hda_backend.input]
 lea rsi,[r12+0]
 lea rdi,[r12+hda_backend.saved+0]
 mov ecx,12
 repe cmpsd
 jne .bad
 lea rsi,[rbx+0]
 lea rdi,[r12+hda_backend.saved+48]
 mov ecx,30
 repe cmpsd
 jne .bad
 lea rsi,[r8+0]
 lea rdi,[r12+hda_backend.saved+168]
 mov ecx,6
 repe cmpsd
 jne .bad
 lea rsi,[r9+0]
 lea rdi,[r12+hda_backend.saved+192]
 mov ecx,6
 repe cmpsd
 jne .bad
 lea rsi,[r13+0]
 lea rdi,[r12+hda_backend.saved+216]
 mov ecx,16
 repe cmpsd
 jne .bad
 lea rsi,[r13+hda_output.mmio_bytes]
 lea rdi,[r12+hda_backend.saved+280]
 mov ecx,8
 repe cmpsd
 jne .bad
 lea rsi,[r14+0]
 lea rdi,[r12+hda_backend.saved+312]
 mov ecx,22
 repe cmpsd
 jne .bad
 lea rsi,[r10+0]
 lea rdi,[r12+hda_backend.saved+400]
 mov ecx,2
 repe cmpsd
 jne .bad
 lea rsi,[r10+hda_route_program.format]
 lea rdi,[r12+hda_backend.saved+408]
 mov ecx,2
 repe cmpsd
 jne .bad
 lea rsi,[r10+hda_route_program.route+hda_route_context.codec]
 lea rdi,[r12+hda_backend.saved+416]
 mov ecx,4
 repe cmpsd
 jne .bad
 test r11,r11
 jz .done
 lea rsi,[r11+0]
 lea rdi,[r12+hda_backend.saved+432]
 mov ecx,2
 repe cmpsd
 jne .bad
 lea rsi,[r11+hda_route_program.format]
 lea rdi,[r12+hda_backend.saved+440]
 mov ecx,2
 repe cmpsd
 jne .bad
 lea rsi,[r11+hda_input.route+hda_input_route.codec]
 lea rdi,[r12+hda_backend.saved+448]
 mov ecx,4
 repe cmpsd
 jne .bad
 lea rsi,[r11+hda_input.route+hda_input_route.channels]
 lea rdi,[r12+hda_backend.saved+464]
 mov ecx,2
 repe cmpsd
 jne .bad
 lea rsi,[r11+hda_input.bdl]
 lea rdi,[r12+hda_backend.saved+472]
 mov ecx,24
 repe cmpsd
 jne .bad
.done:
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret

; Identity/config only: permits canonical halt after receipt/route revocation.
hdab_owned:
 sub rsp,8
 call hdab_match
 test eax,eax
 jnz .out
 mov rax,[rbx+hda_graph.owner]
 cmp [rax+hda_graph_lease.holder],rbx
 jne .bad
 mov rdx,[r12+hda_backend.epoch]
 cmp [rax+hda_graph_lease.epoch],rdx
 jne .bad
 cmp dword [r12+hda_backend.graph_begun],0
 je .ok
 mov rdi,rbx
 mov rsi,rdx
 call hda_graph_owner_check
 jmp .out
.ok:
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret
hdab_receipt:
 sub rsp,8
 mov edi,1
 call dma_domain_live_receipt
 cmp eax,1
 jne .bad
 cmp rdx,[r12+hda_backend.map_serial]
 jne .bad
 call hdab_owned                 ; callback may revoke controller ownership
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret
hdab_clock:
 sub rsp,8
 mov rdi,[rbx+hda_graph.clock_arg]
 lea rsi,[r12+hda_backend.observed_now]
 mov qword [rsi],-1
 call [rbx+hda_graph.clock_fn]
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_backend.observed_now]
 cmp rax,-1
 je .bad
 cmp rax,[r12+hda_backend.last_now]
 jb .bad
 mov [r12+hda_backend.last_now],rax
 call hdab_owned
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret
; Return0 means public output admission is actually current. No MMIO writes.
hdab_admit:
 sub rsp,8
 cmp dword [r12+hda_backend.phase],HDAB_READY
 jne .bad
 call hdab_owned
 test eax,eax
 jnz .bad
 call hdab_receipt
 test eax,eax
 jnz .bad
 cmp dword [rbx+hda_graph.phase],HDAGS_DONE
 jne .bad
 cmp dword [rbx+hda_graph.command_ready],1
 jne .bad
 mov rax,[r12+hda_backend.program]
 cmp [rbx+hda_graph.command_owner],rax
 jne .bad
 cmp dword [rax+hda_route_program.phase],HDAP_READY
 jne .bad
 mov rax,[r12+hda_backend.epoch]
 mov rdx,[r12+hda_backend.program]
 cmp [rdx+hda_route_program.epoch],rax
 jne .bad
 cmp [r14+hda_pcm.epoch],rax
 jne .bad
 cmp [rbx+hda_graph.pcm_owner],r14
 jne .bad
 cmp dword [r14+hda_pcm.canceled],0
 jne .bad
 cmp dword [r14+hda_pcm.error],0
 jne .bad
 cmp dword [r14+hda_pcm.phase],HDPCM_FAILED
 jae .bad
 ; Current controller-global position binding is immutable even during
 ; stream reset/refill. Never replace it behind another stream owner.
 mov r8,[r13+hda_output.mmio]
 mov rax,[r13+hda_output.position_dma]
 or eax,1
 cmp [r8+0x70],eax
 jne .bad
 mov rax,[r13+hda_output.position_dma]
 shr rax,32
 cmp [r8+0x74],eax
 jne .bad
 test byte [r8+HDAT_RIRBSTS],4
 jnz .bad
 mov rax,[rbx+hda_graph.transport]
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 mov eax,[r13+hda_output.state]
 cmp eax,HDAO_STOPPING
 jb .bad
 cmp eax,HDAO_FAILED
 jae .bad
 cmp eax,HDAO_READY
 jae .prepared_registers
 ; Normal stopped refill resets its SD; its registers are provisional until
 ; HDAO_READY. The bound PCM primitive owns this exact transition.
 cmp dword [r14+hda_pcm.phase],HDPCM_PREPARE
 jne .bad
 jmp .ok
.prepared_registers:
 mov r9d,eax
 mov ecx,[r13+hda_output.sd_index]
 shl ecx,5
 lea r8,[r8+rcx+0x80]
 test byte [r8+3],0x18
 jnz .bad
 test byte [r8],1
 jnz .bad
 cmp r9d,HDAO_READY
 je .stopped_register
 cmp r9d,HDAO_STOPPED
 je .stopped_register
 cmp r9d,HDAO_HALTING
 je .stream_registers
 test byte [r8],2
 jz .bad
 jmp .stream_registers
.stopped_register:
 test byte [r8],2
 jnz .bad
.stream_registers:
 cmp dword [r8+8],16384
 jne .bad
 cmp word [r8+12],3
 jne .bad
 mov ecx,[r13+hda_output.format]
 cmp [r8+0x12],cx
 jne .bad
 mov ecx,[r13+hda_output.tag]
 shl ecx,4
 ; Match PCM's prepared-register guard: TP may be read-only1.
 ; Keep STRM, DIR0 and STRIPE0 exact (Intel HDA Table34).
 movzx edx,byte [r8+2]
 and dl,0xFB
 cmp dl,cl
 jne .bad
 mov rcx,[r13+hda_output.bdl_dma]
 cmp [r8+0x18],ecx
 jne .bad
 shr rcx,32
 cmp [r8+0x1c],ecx
 jne .bad
.ok:
 xor eax,eax
 jmp .out
.bad:
 cmp dword [r12+hda_backend.phase],HDAB_READY
 jne .error
 call hdab_revoke
.error:
 mov eax,-1
.out:
 add rsp,8
 ret

hda_backend_step:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 mov eax,[r12+hda_backend.phase]
 cmp eax,HDAB_GRAPH
 jb .bad
 cmp eax,HDAB_UNCERTAIN
 jae .bad
 call hdab_owned
 test eax,eax
 jnz .uncertain
 cmp dword [r12+hda_backend.phase],HDAB_STOPPED
 je .stopped
 cmp dword [r12+hda_backend.phase],HDAB_HALT
 je .cleanup
 call hdab_receipt
 test eax,eax
 jnz .fault
 mov eax,[r12+hda_backend.phase]
 cmp eax,HDAB_GRAPH
 je .graph
 cmp eax,HDAB_PREPARE
 je .prepare
 cmp eax,HDAB_PROGRAM
 je .program
 cmp eax,HDAB_PCM
 je .pcm
 cmp eax,HDAB_READY
 je .ready
 jmp .fault
.graph:
 HDAB_CHILD graph,hda_graph_step
 cmp rax,2
 je .graph_done
 test rax,rax
 js .fault
 jmp .yield
.graph_done:
 mov dword [r12+hda_backend.phase],HDAB_PREPARE
 mov dword [r12+hda_backend.polls],0
 jmp .yield
.prepare:
 cmp dword [r12+hda_backend.error],HDAB_DEFER_SELECTION
 je .discovered
 cmp dword [r13+hda_output.state],HDAO_BOUND
 jne .preparing
 call hdab_clock
 test eax,eax
 jnz .fault
 mov rdi,r13
 mov rsi,[r12+hda_backend.last_now]
 call hda_output_prepare
 test rax,rax
 js .fault
 jmp .yield
.preparing:
 inc dword [r12+hda_backend.polls]
 mov eax,[r12+hda_backend.polls]
 cmp eax,[rbx+hda_graph.poll_limit]
 ja .fault
 call hdab_clock
 test eax,eax
 jnz .fault
 mov rdi,r13
 mov rsi,[r12+hda_backend.last_now]
 call hda_output_service
 test rax,rax
 js .fault
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .yield
 ; Populate exact published graph view, keep caller-selected scope/endpoints.
 mov rdi,[r12+hda_backend.program]
 add rdi,hda_route_program.route
 call hdab_view
 mov dword [r12+hda_backend.phase],HDAB_PROGRAM
 jmp .yield
.program:
 mov rax,[r12+hda_backend.program]
 cmp dword [rax+hda_route_program.phase],0
 jne .program_tick
 HDAB_CHILD program,hda_route_program_begin
 test rax,rax
 js .fault
 jmp .yield
.program_tick:
 HDAB_CHILD program,hda_route_program_step
 test rax,rax
 js .fault
 cmp rax,2
 jne .yield
 mov dword [r12+hda_backend.phase],HDAB_PCM
 jmp .yield
.pcm:
 HDAB_CHILD pcm,hda_pcm_begin
 test rax,rax
 jns .pcm_admitted
 mov [r12+hda_backend.pcm_begin_refusal],edx
 jmp .fault
.pcm_admitted:
 mov dword [r12+hda_backend.pcm_bound],1
 call hdab_publish
 cmp qword [r12+hda_backend.input],0
 je .no_input
 cmp dword [r12+hda_backend.input_state],6
 je .no_input
 mov dword [r12+hda_backend.input_state],1
.no_input:
 mov dword [r12+hda_backend.phase],HDAB_READY
 jmp .ready_result
.ready:
 call hdab_admit
 test eax,eax
 jnz .fault
 ; A pending output RUN acknowledgment gets this one child turn before the
 ; ordinary input/output alternation. Never multiply its fixed5ms wait by
 ; child fairness; PCM still checks the original RUN time and all DMA bounds.
 cmp dword [r13+hda_output.state],HDAO_STARTING
 je .output_tick
 ; Fair one-child service otherwise. No second child or polling loop.
 xor dword [r12+hda_backend.turn],1
 cmp dword [r12+hda_backend.turn],0
 je .output_tick
 mov eax,[r12+hda_backend.input_state]
 cmp eax,1
 je .input_begin
 cmp eax,2
 je .input_tick
 cmp eax,3
 je .input_tick
 cmp eax,4
 je .input_cleanup
.output_tick:
 HDAB_CHILD pcm,hda_pcm_service
 test rax,rax
 js .fault
 jmp .ready_result
.input_begin:
 mov rdi,[r12+hda_backend.input]
 add rdi,hda_input.route
 call hdab_view
 HDAB_CHILD input,hda_input_begin
 test rax,rax
 js .input_failed
 mov dword [r12+hda_backend.input_state],2
 jmp .ready_result
.input_tick:
 HDAB_CHILD input,hda_input_step
 test rax,rax
 js .input_failed
 mov rax,[r12+hda_backend.input]
 cmp dword [rax+hda_route_program.phase],HDAP_READY
 jne .ready_result
 cmp dword [rbx+hda_graph.input_ready],1
 jne .ready_result
 mov dword [r12+hda_backend.input_state],3
 jmp .ready_result
.input_cleanup:
 inc dword [r12+hda_backend.input_cleanup_polls]
 mov eax,[r12+hda_backend.input_cleanup_polls]
 cmp eax,[rbx+hda_graph.poll_limit]
 ja .fault
 mov rax,[r12+hda_backend.input]
 cmp [rbx+hda_graph.input_owner],rax
 jne .output_tick
 cmp dword [rax+hda_input.stream_phase],HDI_STOPPED
 je .input_retire
 cmp dword [rax+hda_input.stream_phase],HDI_FAILED
 jne .input_tick
 cmp dword [rbx+hda_graph.input_quiescent],1
 jne .fault
 jmp .output_tick
.input_retire:
 HDAB_CHILD input,hda_input_retire
 test rax,rax
 js .fault
 mov dword [r12+hda_backend.input_state],5
 jmp .ready_result
.input_failed:
 mov dword [r12+hda_backend.input_state],4
 ; Benign unsupported input never destroys independently ready output.
 cmp dword [rbx+hda_graph.phase],HDAGS_DONE
 jne .fault
 jmp .ready_result
.ready_result:
 mov eax,2
 jmp .out
.fault:
 mov dword [r12+hda_backend.error],2
 call hdab_revoke
 jmp .bad                      ; subsequent steps drive canonical cleanup
.cleanup:
 call hdab_cleanup
 jmp .out
.uncertain:
 mov dword [r12+hda_backend.phase],HDAB_UNCERTAIN
 mov dword [r12+hda_backend.device+dev.health],HEALTH_DEAD
 mov dword [r12+hda_backend.error],3
.bad:
 mov rax,-1
 jmp .out
.stopped:
 xor eax,eax
 jmp .out
.discovered:
 mov eax,3                      ; inventory only; device() still refuses
 jmp .out
.yield:
 mov eax,1
.out:
 HDAB_LEAVE

hdab_view:
 mov rax,[rbx+hda_graph.widgets]
 mov [rdi],rax
 mov eax,[rbx+hda_graph.public_widget_count]
 mov [rdi+8],rax
 mov rax,[rbx+hda_graph.edges]
 mov [rdi+16],rax
 mov eax,[rbx+hda_graph.public_edge_count]
 mov [rdi+24],rax
 ret
hdab_publish:
 lea rdi,[r12+hda_backend.device]
 xor eax,eax
 mov ecx,(hda_backend_size-hda_backend.device)/4
 rep stosd
 lea rax,[r12+hda_backend.ops]
 mov [r12+hda_backend.device+dev.ops],rax
 lea rax,[r12+hda_backend.info]
 mov [r12+hda_backend.device+dev.info],rax
 mov [r12+hda_backend.device+dev.priv],r12
 mov dword [r12+hda_backend.device+dev.class],CLASS_SOUND
 mov dword [r12+hda_backend.device+dev.prio],PRIO_NATIVE_EXPERIMENTAL
 mov dword [r12+hda_backend.device+dev.health],HEALTH_OK
 lea rax,[rel hdab_name]
 mov [r12+hda_backend.info+snd_info.name],rax
 mov eax,[r14+hda_pcm.info+snd_info.formats]
 mov [r12+hda_backend.info+snd_info.formats],eax
 mov eax,[r14+hda_pcm.channels]
 mov [r12+hda_backend.info+snd_info.max_chan],eax
 lea rax,[rel hdab_open]
 mov [r12+hda_backend.ops+snd_ops.open],rax
 lea rax,[rel hdab_submit]
 mov [r12+hda_backend.ops+snd_ops.submit],rax
 lea rax,[rel hdab_position]
 mov [r12+hda_backend.ops+snd_ops.position],rax
 lea rax,[rel hdab_status]
 mov [r12+hda_backend.ops+snd_ops.status],rax
 lea rax,[rel hdab_set_volume]
 mov [r12+hda_backend.ops+snd_ops.set_volume],rax
 lea rax,[rel hdab_close]
 mov [r12+hda_backend.ops+snd_ops.close],rax
 lea rax,[rel hdab_recover]
 mov [r12+hda_backend.ops+snd_ops.recover],rax
 ret
hda_backend_prime_cyclic:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 HDAB_CHILD pcm,hda_pcm_prime_cyclic
 call hdab_pcm_result
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE

hda_backend_start:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 cmp dword [r14+hda_pcm.started],0
 jne .bad
 HDAB_CHILD pcm,hda_pcm_start
 call hdab_pcm_result
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE
hda_backend_drain:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 HDAB_CHILD pcm,hda_pcm_drain
 call hdab_pcm_result
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE
hda_backend_input_start:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 cmp dword [r12+hda_backend.input_state],3
 jne .bad
 HDAB_CHILD input,hda_input_start
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE
; (ctx,epoch,external,bytes) -> stopped input* or0. No sample consumption;
; full external-span exclusion covers both streams and all graph/DMA data.
; Existing hdab_admit may revoke a failed backend through its normal lifecycle.
hda_backend_input_batch:
 HDA_BACKEND_POWER 0
 HDAB_ENTER
 sub rsp,16
 mov [rsp],rdx
 mov [rsp+8],rcx
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 cmp dword [r12+hda_backend.input_state],3
 jne .bad
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 call hdab_buffer
 jc .bad
 mov rdi,[r12+hda_backend.input]
 mov rsi,rbp
 mov rdx,[rsp]
 mov rcx,[rsp+8]
 call hda_input_batch_check
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_backend.input]
 jmp .out
.bad:
 xor eax,eax
.out:
 add rsp,16
 HDAB_LEAVE

hda_backend_input_take:
 HDA_BACKEND_POWER
 HDAB_ENTER
 sub rsp,16
 mov [rsp],rdx
 mov [rsp+8],rcx
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 cmp dword [r12+hda_backend.input_state],3
 jne .bad
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 cmp rdx,2048
 ja .bad
 mov rax,[r12+hda_backend.input]
 mov ecx,[rax+hda_input.frame_bytes]
 imul rdx,rcx
 call hdab_buffer
 jc .bad
 mov rdi,[r12+hda_backend.input]
 mov rsi,rbp
 mov rdx,[rsp]
 mov rcx,[rsp+8]
 call hda_input_take
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,16
 HDAB_LEAVE

hdab_revoke:
 cmp dword [r12+hda_backend.phase],HDAB_HALT
 jae .dead
 mov dword [r12+hda_backend.polls],0
.already:
 mov dword [r12+hda_backend.phase],HDAB_HALT
.dead:
 mov dword [r12+hda_backend.device+dev.health],HEALTH_DEAD
 ret

; A child can fail after public admission (for example, its independent DMA
; receipt check can refuse). Publish that recorded failure before returning
; the original child result. Caller mistakes that leave PCM healthy do not
; revoke the device. No new MMIO, clock read or recovery attempt is needed.
hdab_pcm_result:
 cmp dword [r14+hda_pcm.error],0
 jne .failed
 cmp dword [r14+hda_pcm.device+dev.health],HEALTH_DEAD
 jne .out
.failed:
 push rax
 call hdab_revoke
 pop rax
.out:
 ret
hda_backend_halt:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 mov eax,[r12+hda_backend.phase]
 cmp eax,HDAB_GRAPH
 jb .bad
 cmp eax,HDAB_STOPPED
 ja .bad
 call hdab_owned
 test eax,eax
 jnz .lost
 cmp dword [r12+hda_backend.phase],HDAB_STOPPED
 je .zero
 call hdab_revoke
 mov eax,1
 jmp .out
.lost:
 mov dword [r12+hda_backend.device+dev.health],HEALTH_DEAD
 mov dword [r12+hda_backend.phase],HDAB_UNCERTAIN
.bad:
 mov rax,-1
 jmp .out
.zero:
 xor eax,eax
.out:
 HDAB_LEAVE

; One bounded child operation per call. Children retire before graph reset:
; their own stop/identity/SD readback is still available at that boundary.
; A failure remains sticky; no zeroed structs, released DMA or fake quiescence.
hdab_cleanup:
 sub rsp,8
 inc dword [r12+hda_backend.polls]
 cmp dword [r12+hda_backend.polls],16384
 ja .uncertain
 ; Request output stop BEFORE waiting on input. A stuck input must not
 ; leave another owned stream running while the coordinator is uncertain.
 cmp dword [r12+hda_backend.pcm_bound],0
 je .early_raw
 cmp dword [r12+hda_backend.output_halted],0
 jne .early_done
 mov dword [r12+hda_backend.output_halted],1
 HDAB_CHILD pcm,hda_pcm_halt
 jmp .yield
.early_raw:
 mov eax,[r13+hda_output.state]
 cmp eax,HDAO_READY
 je .early_stop
 cmp eax,HDAO_STARTING
 je .early_stop
 cmp eax,HDAO_RUNNING
 jne .early_done
.early_stop:
 call hdab_clock
 test eax,eax
 jnz .uncertain
 mov rdi,r13
 mov rsi,[r12+hda_backend.last_now]
 call hda_output_halt
 test rax,rax
 js .uncertain
 jmp .yield
.early_done:
 ; Request BOTH owned stops before waiting on either acknowledgement. An
 ; output timeout must not leave input DMA running in a pinned uncertain owner.
 mov rax,[r12+hda_backend.input]
 test rax,rax
 jz .output_ack
 cmp [rbx+hda_graph.input_owner],rax
 jne .output_ack
 cmp dword [r12+hda_backend.input_halted],0
 jne .output_ack
 cmp dword [rax+hda_input.stream_phase],HDI_FAILED
 je .output_ack
 mov dword [r12+hda_backend.input_halted],1
 HDAB_CHILD input,hda_input_stop
 jmp .yield
.output_ack:
 ; Once output stop is requested, acknowledge it before lengthy input codec
 ; restoration. Otherwise a normal 1ms cadence can exceed its 5ms deadline
 ; despite RUN already being clear. One child operation per turn still holds;
 ; no retirement or graph reset is admitted until BOTH owners are quiescent.
 cmp dword [r12+hda_backend.pcm_bound],0
 je .input_cleanup
 cmp dword [r14+hda_pcm.phase],HDPCM_STOP
 jne .input_cleanup
 HDAB_CHILD pcm,hda_pcm_service
 cmp dword [r14+hda_pcm.phase],HDPCM_FAILED
 jne .yield
 ; A content fault stays FAILED even after its actual stop is acknowledged.
 ; Only the PCM owner's verified STOPPED/quiescent result permits the normal
 ; cleanup to continue to retire(), which independently checks RUN/SRST0.
 ; Unverified or failed stops remain uncertain with all storage retained.
 cmp dword [r13+hda_output.state],HDAO_STOPPED
 jne .uncertain
 cmp dword [rbx+hda_graph.pcm_quiescent],1
 jne .uncertain
 jmp .yield
.input_cleanup:
 ; Optional input may have failed before touching the SD; verified graph
 ; reset is its eventual cleanup boundary. Never claim input_retire then.
 mov rax,[r12+hda_backend.input]
 test rax,rax
 jz .output
 cmp [rbx+hda_graph.input_owner],rax
 jne .output
 cmp dword [r12+hda_backend.input_state],5
 je .output
 cmp dword [rax+hda_input.stream_phase],HDI_FAILED
 jne .input_live
 cmp dword [rbx+hda_graph.input_quiescent],1
 jne .uncertain
 jmp .output
.input_live:
 cmp dword [r12+hda_backend.input_halted],0
 jne .input_stopping
 mov dword [r12+hda_backend.input_halted],1
 HDAB_CHILD input,hda_input_stop
 jmp .yield
.input_stopping:
 cmp dword [rax+hda_input.stream_phase],HDI_STOPPED
 je .input_retire
 HDAB_CHILD input,hda_input_step
 mov rdx,[r12+hda_backend.input]
 cmp dword [rdx+hda_input.stream_phase],HDI_FAILED
 je .uncertain
 jmp .yield
.input_retire:
 HDAB_CHILD input,hda_input_retire
 test rax,rax
 js .uncertain
 mov dword [r12+hda_backend.input_state],5
 jmp .yield
.output:
 cmp dword [r12+hda_backend.pcm_bound],0
 je .raw_output
 cmp dword [r14+hda_pcm.phase],HDPCM_RETIRED
 je .graph
 cmp dword [r12+hda_backend.output_halted],0
 jne .pcm_stopping
 mov dword [r12+hda_backend.output_halted],1
 HDAB_CHILD pcm,hda_pcm_halt
 jmp .yield
.pcm_stopping:
 cmp dword [r13+hda_output.state],HDAO_STOPPED
 je .pcm_retire
 cmp dword [r14+hda_pcm.phase],HDPCM_FAILED
 je .uncertain
 HDAB_CHILD pcm,hda_pcm_service
 jmp .yield
.pcm_retire:
 HDAB_CHILD pcm,hda_pcm_retire
 test rax,rax
 js .uncertain
 jmp .yield
.raw_output:
 call hdab_clock
 test eax,eax
 jnz .uncertain
 mov eax,[r13+hda_output.state]
 cmp eax,HDAO_STOPPED
 je .graph
 cmp eax,HDAO_BOUND
 je .graph                      ; bind checked all RUN0 and rings stopped
 cmp eax,HDAO_FAILED
 jae .uncertain
 cmp eax,HDAO_READY
 je .raw_halt
 cmp eax,HDAO_STARTING
 je .raw_halt
 cmp eax,HDAO_RUNNING
 je .raw_halt
 mov rdi,r13
 mov rsi,[r12+hda_backend.last_now]
 call hda_output_service
 test rax,rax
 js .uncertain
 jmp .yield
.raw_halt:
 mov rdi,r13
 mov rsi,[r12+hda_backend.last_now]
 call hda_output_halt
 test rax,rax
 js .uncertain
 jmp .yield
.graph:
 cmp dword [r12+hda_backend.graph_begun],1
 jne .uncertain
 cmp dword [rbx+hda_graph.phase],HDAGS_FAILED
 je .clean
 cmp dword [rbx+hda_graph.phase],HDAGS_CLEANUP
 je .graph_tick
 HDAB_CHILD graph,hda_graph_cancel
 test rax,rax
 js .uncertain
 jmp .yield
.graph_tick:
 HDAB_CHILD graph,hda_graph_step
 jmp .yield
.clean:
 cmp dword [rbx+hda_graph.clean],1
 jne .uncertain
 mov dword [r12+hda_backend.phase],HDAB_STOPPED
 xor eax,eax
 jmp .out
.uncertain:
 mov dword [r12+hda_backend.phase],HDAB_UNCERTAIN
 mov rax,-1
 jmp .out
.yield:
 mov eax,1
.out:
 add rsp,8
 ret

hda_backend_retire:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 cmp dword [r12+hda_backend.phase],HDAB_STOPPED
 jne .bad
 cmp dword [r12+hda_backend.registered],0
 jne .bad
 call hdab_owned
 test eax,eax
 jnz .bad
 HDAB_CHILD graph,hda_graph_retire
 test rax,rax
 js .bad
 mov dword [r12+hda_backend.phase],HDAB_RETIRED
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE

; C3 selected registry device -> cached controller PCI ID, or0 unknown.
; Pure cooperative-owner observation: no admission/power callback, controller
; read, register/unregister or epoch transition. EDX=1 identifies HDA ops.
hda_backend_census_identity:
 xor edx,edx
 mov rax,[rdi+dev.ops]
 test rax,rax
 jz .none
 lea rcx,[rel hdab_open]
 cmp [rax+snd_ops.open],rcx
 jne .none
 mov edx,1
 mov rax,[rdi+dev.priv]
 test rax,rax
 jz .none
 lea rcx,[rax+hda_backend.device]
 cmp rdi,rcx
 jne .none
 cmp dword [rax+hda_backend.registered],1
 jne .none
 cmp dword [rax+hda_backend.output_bound],1
 jne .none
 mov rcx,[rax+hda_backend.output]
 test rcx,rcx
 jz .none
 cmp qword [rcx+hda_output.mmio],0
 je .none
 mov rax,[rcx+hda_output.bound_pci_id]
 shr rax,32
 jnz .none
 mov eax,[rcx+hda_output.bound_pci_id]
 ret
.none:
 xor eax,eax
 ret

hda_backend_device:
 HDA_BACKEND_POWER 0
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .stale
 call hdab_admit
 test eax,eax
 jnz .none
 lea rax,[r12+hda_backend.device]
 jmp .out
.none:
.stale:
 xor eax,eax
.out:
 HDAB_LEAVE
hda_backend_register:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 cmp dword [r12+hda_backend.registered],0
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 lea rdi,[r12+hda_backend.device]
 call snd_register
 test rax,rax
 jnz .bad
 mov dword [r12+hda_backend.registered],1
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE
hda_backend_deregister:
 HDA_BACKEND_POWER
 HDAB_ENTER
 cmp rbp,[r12+hda_backend.epoch]
 jne .bad
 cmp dword [r12+hda_backend.registered],1
 jne .bad
 ; Does not access MMIO: unlink remains possible after ownership is lost.
 lea rdi,[r12+hda_backend.device]
 call snd_deregister
 test rax,rax
 jnz .bad
 mov dword [r12+hda_backend.registered],0
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 HDAB_LEAVE

; Guarded ABI-v2 playback adapter. Child vtable performs its full params,
; buffers, handle, receipt, current register/binding and content validation.
; The coordinator additionally excludes its own full context from buffers.
hdab_open:
 HDA_BACKEND_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 mov rsi,[rsp]
 mov edx,snd_stream_params_size
 call hdab_buffer
 jc .bad
 mov rsi,[rsp+8]
 mov edx,8
 call hdab_buffer
 jc .bad
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.open]
 call hdab_pcm_result
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdab_submit:
 HDA_BACKEND_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 mov rsi,[rsp+8]
 mov rdx,[rsp+16]
 call hdab_buffer
 jc .bad
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.submit]
 call hdab_pcm_result
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdab_position:
 HDA_BACKEND_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.position]
 call hdab_pcm_result
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdab_status:
 HDA_BACKEND_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 mov rsi,[rsp+8]
 mov edx,snd_status_size
 call hdab_buffer
 jc .bad
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.status]
 call hdab_pcm_result
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdab_set_volume:
 HDA_BACKEND_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.set_volume]
 call hdab_pcm_result
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdab_close:
 HDA_BACKEND_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.close]
 call hdab_pcm_result
 test rax,rax
 jnz .out
 call hdab_revoke
 xor eax,eax
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
hdab_recover:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,32
 mov [rsp],rsi
 mov [rsp+8],rdx
 mov [rsp+16],rcx
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_backend.device]
 cmp rdi,rax
 jne .bad
 call hdab_admit
 test eax,eax
 jnz .revoke
 lea rdi,[r14+hda_pcm.device]
 mov rsi,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov rax,[r14+hda_pcm.device+dev.ops]
 call [rax+snd_ops.recover]
 call hdab_pcm_result
 jmp .out
.revoke:
 call hdab_revoke
.bad:
 mov rax,-1
.out:
 add rsp,32
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Full64 span checks, empty graph capacity spans allowed. Every writable or
; DMA CPU span disjoint, except explicitly identical shared position buffer.
hdab_span:
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
hdab_disjoint:
 xor ecx,ecx
.outer:
 mov r8,[rdi+rcx]
 mov r9,[rdi+rcx+8]
 cmp r8,r9
 je .next
 lea edx,[rcx+16]
.inner:
 cmp edx,352
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
 cmp ecx,352
 jb .outer
 clc
 ret
.bad:
 stc
 ret
hdab_buffer:
 test rdx,rdx
 jz .ok
 test rsi,rsi
 jz .bad
 mov rax,rsi
 add rax,rdx
 jc .bad
 cmp rax,r12
 jbe .ok
 lea rdx,[r12+hda_backend_size]
 cmp rsi,rdx
 jb .bad
.ok:
 clc
 ret
.bad:
 stc
 ret

hdab_name: db "HDA cooperative analog PCM",0

%macro WDATA_hda_backend_power 0
 align 8
hda_backend_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_backend_power
%else
 section .data
 WDATA_hda_backend_power
 section .text
%endif
