;; MODULE dev/snd/hda_route_program
;; LAYER 3
;; EXPORTS hda_route_program_begin, hda_route_program_step, hda_route_program_cancel, hda_program_emit, hda_program_clock, hda_program_power, hda_program_selector, hda_program_amp_caps, hda_program_quirk, hda_program_quirk_queries, hda_program_fixed_caps
;; IMPORTS dev/snd/hda_session, dev/snd/hda_transport
;; CAPS mmio dma
;; OWNER rc-codex-av
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_ROUTE_PROGRAM_POWER 0
 cmp qword [rel hda_route_program_power_gate],0
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
 call [rel hda_route_program_power_gate]
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
; Cooperative codec programming, NOT a registered sound backend or DMA grant.
; Port Classic hda_set_connsel/hda_enable_output_pins and converter setup from
; Classic 0cabd75f8653ae3f8778ad0af51469a4f20adf25. Field authority: Intel HDA
; rev1.0a 7.3.3.2,7.3.3.7-8/10-11/13/16 and 7.3.4.4/6-10/12.
; https://www.intel.com/content/dam/www/public/us/en/documents/product-specifications/high-definition-audio-specification.pdf
; Query every required capability before ANY SET. Format/amp override bits
; choose widget vs AFG defaults; zero amp caps legitimately mean fixed unity.
; Scope: existing planner's stereo analog direct/one selector/one mixer paths,
; S16 stereo 44100/48000/96000, channel0, stream tags1..15. Processing/stripe widgets
; and digital pins/converters refuse. Exact acquired/fresh codec identity selects
; the documented QEMU duplex quirk below; no caller quirk request. Mixer input
; isolation requires actual mute-capable input amps when more than one input;
; >16 mixer inputs refuse (GET input index is low4, SET index is bits11:8).
; Unity uses amp Offset, not maximum gain. Output amps index0, mixer input amps
; selected expanded index; selectors have connection select, never mixer SET701.
;
; Caller supplies graph*, format=0x11/0x4011/0x811, tag and route64 view (graph's exact
; published spans/counts plus codec/AFG/pin/DAC). Begin replans rather than trusting
; output indices. Context is caller-owned stable mapped writable memory disjoint
; from every graph/lease/transport/ring/inventory span. Inputs immutable while
; active. Calls serialized with whole controller owner; no IRQ/other ring users.
; Any external controller/link reset must invalidate the owner epoch; a silent
; reset between commands cannot be identified from RAM-only transport state.
; begin(ctx,epoch)->0/-1. step(ctx,epoch)->1 yield/2 program-ready/-1 revoked.
; cancel(ctx,epoch)->-1 revoked. Fresh context or strictly newer graph epoch only.
; Program-ready is graph.command_ready AND matching command_owner/epoch/DONE;
; step rechecks this gate. Reading ctx.phase alone is NEVER a readiness API.
; Graph cancel/fault revokes the gate immediately. Claim persists until graph
; reset/retirement; uncertainty schedules graph cleanup, never frees mappings,
; changes domains or resets another owner. Owner must drive graph cleanup after
; failure/cancel, retain all DMA/mapping/reset responsibilities on cleanup failure.
; A successful codec SET/readback says nothing about DMA RUN, output or acoustics.
;
; All queries precede powers/SETs. Generic FG D0 and optional widget D0 are verified
; first; pin output is disabled while routes/format/tag/amps are programmed,
; enabled last, then power status checked again. The exact fixed-pin QEMU codec
; instead verifies converter mute before setup and unmute last; it has no PM.
; SET acknowledgments must be0.
; D0 GET permits transitional PSAct but requires PSSet0, no error/settings-reset
; or reserved bits. Repeated GETs share deadline/poll budget. All other required
; readbacks are exact including reserved zeros. Busy never discards a command.
; One bounded next/queue/take operation per step, <=256 script commands,
; <=4096 command polls and <=1000000 overall steps even frozen clock. Callback
; clock is graph owner's known monotonic clock; overflow/regression/unknown fail.
; No allocation/global mutable data/FP; SysV nonvolatile GPR/RSP, DF0.

; Private script helpers operate on the hda_route_program prefix in R12.
; They retain existing bounds/ABI; no controller registration or ready grant.
HDAP_QUERY equ 1
HDAP_PROGRAM equ 2
HDAP_READY equ 3
HDAP_FAILED equ 4
HDAP_MAX equ 256
struc hda_program_node
 .nid: resd 1
 .caps: resd 1
 .power: resd 1
 .amp_out: resd 1
 .amp_in: resd 1
 .connections: resd 1
endstruc
struc hda_route_program
 .graph: resq 1
 .epoch: resq 1
 .format: resd 1
 .tag: resd 1
 .route: resb hda_route_context_size
 .phase: resd 1
 .error: resd 1
 .request: resd 1                 ;0 none,1 retained,2 queued
 .command: resd 1
 .response: resd 1
 .cursor: resd 1
 .count: resd 1
 .request_cursor: resd 1
 .polls: resd 1
 .steps: resd 1
 .last_now: resq 1
 .deadline: resq 1
 .command_deadline: resq 1
 .observed_now: resq 1
 .saved_format: resd 1
 .saved_tag: resd 1
 .saved_codec: resd 1
 .saved_group: resd 1
 .fg_power: resd 1
 .pcm: resd 1
 .streams: resd 1
 .pin_caps: resd 1
 .eapd: resd 1
 .pin_ctl: resd 1
 .request_phase: resd 1
 .pad: resd 1                     ;derived quirk0 generic,1 QEMU duplex,2 QEMU output fixed pins
 .nodes: resb 3*hda_program_node_size ;DAC,middle(optional),pin
 .script: resb HDAP_MAX*16          ;packedverb,mask,value,destination
 ; Configuration-time GETs accepted by the existing exact verifier. Valid bits
 ; distinguish absent hardware from a real raw0 (fixed unity). No extra verbs.
 .readback_valid: resd 1
 .readback_values: resd 12          ;DAC L/R,middle out L/R,pin L/R,mixer in L/R,
                                  ;pin control,EAPD,converter format,stream tag
 .readback_reserved: resd 3
endstruc

%macro HDAP_EMIT 6
 mov esi,%1
 mov edx,%2
 mov ecx,%3
 mov r8d,%4
 mov r9d,%5
 call hdap_emit
 test eax,eax
 jnz %6
%endmacro
%macro HDAP_QUERY_PARAM 3
 HDAP_EMIT %1,(0xF0000|%2),0,0,%3,.bad
%endmacro

hda_route_program_begin:
 HDA_ROUTE_PROGRAM_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,16
 mov r12,rdi
 mov rbp,rsi
 test r12,r12
 jz .refuse
 mov rax,r12
 add rax,hda_route_program_size
 jc .refuse
 cmp dword [r12+hda_route_program.phase],0
 je .fresh
 cmp dword [r12+hda_route_program.phase],HDAP_READY
 je .reuse
 cmp dword [r12+hda_route_program.phase],HDAP_FAILED
 jne .refuse
.reuse:
 cmp rbp,[r12+hda_route_program.epoch]
 jbe .refuse
.fresh:
 mov eax,[r12+hda_route_program.format]
 and eax,0xFFFFFFDF               ; allow only S16/S24 variants below
 cmp eax,0x11
 je .format
 cmp eax,0x4011
 je .format
 cmp eax,0x811
 jne .refuse
.format:
 mov eax,[r12+hda_route_program.tag]
 dec eax
 cmp eax,14
 ja .refuse
 mov rbx,[r12+hda_route_program.graph]
 test rbx,rbx
 jz .refuse
 ; Claim checks the ENTIRE program span before any internal/context mutation.
 mov rdi,rbx
 mov rsi,r12
 mov edx,hda_route_program_size
 mov rcx,rbp
 call hda_graph_command_claim
 test rax,rax
 jnz .refuse
 mov [r12+hda_route_program.epoch],rbp
 mov rdi,rbx
 lea rsi,[r12+hda_route_program.route]
 mov rdx,rbp
 call hda_graph_plan
 test rax,rax
 jnz .invalid
 lea rdi,[r12+hda_route_program.phase]
 xor eax,eax
 mov ecx,(hda_route_program_size-hda_route_program.phase)/8
 rep stosq
 mov eax,[r12+hda_route_program.format]
 mov [r12+hda_route_program.saved_format],eax
 mov eax,[r12+hda_route_program.tag]
 mov [r12+hda_route_program.saved_tag],eax
 mov eax,[r12+hda_route_program.route+hda_route_context.codec]
 mov [r12+hda_route_program.saved_codec],eax
 mov eax,[r12+hda_route_program.route+hda_route_context.group]
 mov [r12+hda_route_program.saved_group],eax
 mov dword [r12+hda_route_program.phase],HDAP_QUERY
 ; Snapshot the three exact selected widgets and expanded list cardinalities.
 lea r13,[r12+hda_route_program.nodes]
 mov eax,[r12+hda_route_program.route+hda_route_context.dac]
 mov [r13+hda_program_node.nid],eax
 mov eax,[r12+hda_route_program.route+hda_route_context.middle]
 mov [r13+hda_program_node_size+hda_program_node.nid],eax
 mov eax,[r12+hda_route_program.route+hda_route_context.pin]
 mov [r13+2*hda_program_node_size+hda_program_node.nid],eax
 xor r14d,r14d
.node:
 cmp dword [r13+hda_program_node.nid],0
 je .next_node
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
 jmp .invalid
.found:
 mov eax,[rdi+hda_widget_info.caps]
 test eax,0x260                  ;digital, processing or stripe unsupported
 jnz .invalid
 mov [r13+hda_program_node.caps],eax
 mov rdi,[rbx+hda_graph.edges]
 mov ecx,[rbx+hda_graph.public_edge_count]
 test ecx,ecx
 jz .next_node
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
.next_node:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .node
 call hda_program_quirk
 mov [r12+hda_route_program.pad],eax
 call hdap_queries
 test eax,eax
 jnz .invalid
 call hdap_clock
 test eax,eax
 jnz .invalid
 mov rax,[r12+hda_route_program.last_now]
 add rax,[rbx+hda_graph.session_timeout]
 jc .invalid
 mov [r12+hda_route_program.deadline],rax
 mov rdi,rbx
 mov rsi,r12
 mov rdx,rbp
 call hda_graph_command_check
 test rax,rax
 jnz .invalid
 xor eax,eax
 jmp .out
.invalid:
 mov esi,1
 call hdap_fail
.refuse:
 mov rax,-1
.out:
 add rsp,16
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Exactly one bounded operation, with immutable pending source and attribution.
hda_route_program_step:
 HDA_ROUTE_PROGRAM_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .refuse
 mov rdi,[r12+hda_route_program.graph]
 mov rsi,r12
 mov rdx,[r12+hda_route_program.epoch]
 call hda_graph_command_check
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
 call hdap_clock
 test eax,eax
 jnz .clock
 mov rax,[r12+hda_route_program.last_now]
 cmp rax,[r12+hda_route_program.deadline]
 jae .timeout
 mov rdi,rbx
 mov rsi,r12
 mov rdx,[r12+hda_route_program.epoch]
 call hda_graph_command_check
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
 cmp edx,hda_route_program.fg_power
 jb .source
 cmp edx,hda_route_program.script
 jae .source
 test edx,3
 jnz .source
 mov [r12+rdx],eax
 jmp .advance
.verify:
 and eax,[r13+4]
 cmp eax,[r13+8]
 jne .response
.advance:
 call hdap_retain_readback
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
 call hdap_build
 test eax,eax
 jnz .capability
 mov dword [r12+hda_route_program.phase],HDAP_PROGRAM
 jmp .yield
.publish:
 mov dword [r12+hda_route_program.phase],HDAP_READY
 mov dword [rbx+hda_graph.command_ready],1
.ready:
 cmp dword [rbx+hda_graph.command_ready],1
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
 call hdap_fail
.refuse:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_route_program_cancel:
 HDA_ROUTE_PROGRAM_POWER
 push r12
 mov r12,rdi
 cmp rsi,[r12+hda_route_program.epoch]
 jne .out
 mov esi,9
 call hdap_fail
.out:
 mov rax,-1
 pop r12
 ret

; Called only after the existing attributed response verifier accepted this
; script command. Private volatile-only helper: no queue, pointer chase or MMIO.
; Later accepted GETs replace earlier values (pin disable before final enable).
; The snapshot remains historical through failure/cleanup; phase/error qualify it.
hdap_retain_readback:
 cmp dword [r12+hda_route_program.phase],HDAP_PROGRAM
 jne .out
 mov eax,[r12+hda_route_program.command]
 mov edx,eax
 shr edx,20
 and edx,255                     ;selected node in this program's saved codec
 and eax,0xFFFFF
 cmp eax,0xBA000
 je .amp_left
 cmp eax,0xB8000
 je .amp_right
 cmp eax,0xF0700
 je .pin_control
 cmp eax,0xF0C00
 je .eapd
 cmp eax,0xA0000
 je .format
 cmp eax,0xF0600
 je .tag
 ; Only the selected mixer's expanded input; isolated other inputs excluded.
 mov ecx,eax
 and ecx,15
 cmp ecx,[r12+hda_route_program.route+hda_route_context.middle_index]
 jne .out
 and eax,0xFFFF0
 cmp eax,0xB2000
 je .input_left
 cmp eax,0xB0000
 jne .out
 mov ecx,7
 jmp .input
.input_left:
 mov ecx,6
.input:
 cmp dword [r12+hda_route_program.route+hda_route_context.kind],1
 jne .out
 cmp edx,[r12+hda_route_program.nodes+hda_program_node_size+hda_program_node.nid]
 jne .out
 jmp .store
.amp_left:
 xor ecx,ecx
 jmp .output
.amp_right:
 mov ecx,1
.output:
 cmp edx,[r12+hda_route_program.nodes+hda_program_node.nid]
 je .store
 add ecx,2
 cmp edx,[r12+hda_route_program.nodes+hda_program_node_size+hda_program_node.nid]
 je .store
 add ecx,2
 cmp edx,[r12+hda_route_program.nodes+2*hda_program_node_size+hda_program_node.nid]
 je .store
 ret
.pin_control:
 mov ecx,8
 jmp .pin
.eapd:
 mov ecx,9
.pin:
 cmp edx,[r12+hda_route_program.route+hda_route_context.pin]
 je .store
 ret
.format:
 mov ecx,10
 jmp .converter
.tag:
 mov ecx,11
.converter:
 cmp edx,[r12+hda_route_program.route+hda_route_context.dac]
 jne .out
.store:
 mov eax,[r12+hda_route_program.response]
 mov [r12+rcx*4+hda_route_program.readback_values],eax
 bts dword [r12+hda_route_program.readback_valid],ecx
.out:
 ret

; Failure clears only our current graph claim. graph_cancel verifies exact owner
; identity before any reset scheduling; no reset callback or MMIO here.
hdap_fail:
 push rbx
 mov [r12+hda_route_program.error],esi
 mov dword [r12+hda_route_program.phase],HDAP_FAILED
 mov rbx,[r12+hda_route_program.graph]
 cmp [rbx+hda_graph.command_owner],r12
 jne .out
 mov rsi,[r12+hda_route_program.epoch]
 cmp [rbx+hda_graph.epoch],rsi
 jne .out
 mov dword [rbx+hda_graph.command_ready],0
 mov rdi,rbx
 call hda_graph_cancel
.out:
 mov rax,-1
 pop rbx
 ret

hda_program_clock:
hdap_clock:
 sub rsp,8
 mov rax,[r12+hda_route_program.graph]
 mov rdi,[rax+hda_graph.clock_arg]
 lea rsi,[r12+hda_route_program.observed_now]
 mov qword [rsi],-1
 call [rax+hda_graph.clock_fn]
 test rax,rax
 jnz .bad
 mov rax,[r12+hda_route_program.observed_now]
 cmp rax,-1
 je .bad
 cmp rax,[r12+hda_route_program.last_now]
 jb .bad
 mov [r12+hda_route_program.last_now],rax
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret

; Emit one bounded script entry. Uses volatile regs only; R12=context.
; ESI=NID EDX=verb ECX=mask R8D=expected R9D=destination (0 verify,-1 D0).
hda_program_emit:
hdap_emit:
 mov eax,[r12+hda_route_program.count]
 cmp eax,HDAP_MAX
 jae .bad
 shl eax,4
 lea r10,[r12+rax+hda_route_program.script]
 mov eax,[r12+hda_route_program.saved_codec]
 shl eax,28
 shl esi,20
 or edx,esi
 or edx,eax
 mov [r10],edx
 mov [r10+4],ecx
 mov [r10+8],r8d
 mov [r10+12],r9d
 inc dword [r12+hda_route_program.count]
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret

hdap_queries:
 push r13
 push r14
 sub rsp,8
 ; HDA7.3.4.4: exact AudioNodeType1 in bits7:0; optional UnSolCap is bit8.
 HDAP_EMIT [r12+hda_route_program.saved_group],0xF0005,0xFFFFFEFF,1,0,.bad
 HDAP_QUERY_PARAM [r12+hda_route_program.saved_group],0x0F,hda_route_program.fg_power
 ; Converter format overrides query the converter; otherwise AFG defaults.
 mov esi,[r12+hda_route_program.saved_group]
 test dword [r12+hda_route_program.nodes+hda_program_node.caps],0x10
 jz .format
 mov esi,[r12+hda_route_program.nodes+hda_program_node.nid]
.format:
 mov r14d,esi
 HDAP_QUERY_PARAM r14d,0x0A,hda_route_program.pcm
 HDAP_QUERY_PARAM r14d,0x0B,hda_route_program.streams
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0xF000C,0,0,hda_route_program.pin_caps,.bad
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.node:
 cmp dword [r13+hda_program_node.nid],0
 je .next
 HDAP_EMIT [r13+hda_program_node.nid],0xF0009,0xFFFFFFFF,[r13+hda_program_node.caps],0,.bad
 test dword [r13+hda_program_node.caps],0x400
 jz .amps
 mov eax,r13d
 sub eax,r12d
 add eax,hda_program_node.power
 HDAP_QUERY_PARAM [r13+hda_program_node.nid],0x0F,eax
.amps:
 test dword [r13+hda_program_node.caps],4
 jz .input
 mov esi,[r12+hda_route_program.saved_group]
 test dword [r13+hda_program_node.caps],8
 jz .output_source
 mov esi,[r13+hda_program_node.nid]
.output_source:
 mov eax,r13d
 sub eax,r12d
 add eax,hda_program_node.amp_out
 HDAP_QUERY_PARAM esi,0x12,eax
.input:
 ; InAmpPresent is relevant to mixer playback inputs, not selector/DAC input.
 cmp r14d,1
 jne .next
 cmp dword [r12+hda_route_program.route+hda_route_context.kind],1
 jne .next
 test dword [r13+hda_program_node.caps],2
 jz .next
 mov esi,[r12+hda_route_program.saved_group]
 test dword [r13+hda_program_node.caps],8
 jz .input_source
 mov esi,[r13+hda_program_node.nid]
.input_source:
 mov eax,r13d
 sub eax,r12d
 add eax,hda_program_node.amp_in
 HDAP_QUERY_PARAM esi,0x0D,eax
.next:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .node
 ; EAPD support is from already captured immutable pin capability, fresh value
 ; must match it before build. Only query optional control on reported support.
 mov rax,[r12+hda_route_program.route+hda_route_context.widgets]
 mov ecx,[r12+hda_route_program.route+hda_route_context.widget_count]
.pin:
 mov edx,[r12+hda_route_program.saved_codec]
 cmp [rax+hda_widget_info.codec],edx
 jne .pin_next
 mov edx,[r12+hda_route_program.saved_group]
 cmp [rax+hda_widget_info.group],edx
 jne .pin_next
 mov edx,[r12+hda_route_program.route+hda_route_context.pin]
 cmp [rax+hda_widget_info.nid],edx
 je .pin_found
.pin_next:
 add rax,hda_widget_info_size
 dec ecx
 jnz .pin
 jmp .bad
.pin_found:
 ; Make fresh pin caps exact, so an optional EAPD capability cannot appear late.
 mov edx,[rax+hda_widget_info.pin_caps]
 mov [r12+hda_route_program.pin_caps],edx
 ; Pin-cap query was entry4 (FGtype,power,PCM,formats,pincaps).
 mov dword [r12+hda_route_program.script+4*16+4],0xFFFFFFFF
 mov [r12+hda_route_program.script+4*16+8],edx
 mov dword [r12+hda_route_program.script+4*16+12],0
 test edx,0x10000
 jz .ok
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0xF0C00,0,0,hda_route_program.eapd,.bad
.ok:
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

; Validate ALL facts before emitting any SET, then build a bounded exact script.
hdap_build:
 push rbx
 push r13
 push r14
 cmp dword [r12+hda_route_program.pad],1
 je .fixed_power_caps
 cmp dword [r12+hda_route_program.pad],2
 jne .generic_power_caps
.fixed_power_caps:
 xor esi,esi
 call hda_program_fixed_caps
 test eax,eax
 jnz .bad
 cmp dword [r12+hda_route_program.route+hda_route_context.kind],0
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
 mov edx,0x20040
 mov ecx,[r12+hda_route_program.saved_format]
 and ecx,0xFFFFFFDF
 cmp ecx,0x4011
 je .pcm_44k1
 cmp ecx,0x811
 jne .pcm
 mov edx,0x20100                 ; 16bit +96kHz (PCM capability rate bit8)
 jmp .pcm
.pcm_44k1:
 mov edx,0x20020
.pcm:
 test dword [r12+hda_route_program.saved_format],0x20
 jz .pcm_width
 xor edx,0xA0000                   ; require24bit capability, not16bit
.pcm_width:
 and eax,edx
 cmp eax,edx
 jne .bad
 mov eax,[r12+hda_route_program.pin_caps]
 test eax,0x10
 jz .bad
 test eax,0x01000080             ;DP/HDMI independently excluded
 jnz .bad
 mov edx,0x40
 test eax,8
 jz .pin_ctl
 or edx,0x80
.pin_ctl:
 mov [r12+hda_route_program.pin_ctl],edx
 test dword [r12+hda_route_program.eapd],0xFFFFFFF8
 jnz .bad
 or dword [r12+hda_route_program.eapd],2
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.validate:
 cmp dword [r13+hda_program_node.nid],0
 je .next_validate
 test dword [r13+hda_program_node.caps],0x400
 jz .amp_validate
 mov eax,[r13+hda_program_node.power]
 test eax,eax
 jnz .power_caps
 mov eax,[r12+hda_route_program.fg_power] ;widget0 inherits AFG states per spec
.power_caps:
 test eax,1
 jz .bad
 test eax,0x1FFFFFE0
 jnz .bad
.amp_validate:
 test dword [r13+hda_program_node.caps],4
 jz .mixer
 mov eax,[r13+hda_program_node.amp_out]
 call hdap_amp_caps
 jc .bad
.mixer:
 cmp r14d,1
 jne .next_validate
 cmp dword [r12+hda_route_program.route+hda_route_context.kind],1
 jne .next_validate
 mov eax,[r13+hda_program_node.connections]
 test eax,eax
 jz .bad
 cmp eax,16
 ja .bad
 test dword [r13+hda_program_node.caps],2
 jnz .input_caps
 cmp eax,1
 ja .bad
 jmp .next_validate
.input_caps:
 mov eax,[r13+hda_program_node.amp_in]
 call hdap_amp_caps
 jc .bad
 cmp dword [r13+hda_program_node.connections],1
 jbe .next_validate
 test eax,0x80000000
 jz .bad
.next_validate:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .validate
 mov dword [r12+hda_route_program.count],0
 mov dword [r12+hda_route_program.cursor],0
 ; QEMU fixed pins are isolated by verified converter L/R mute before setup.
 cmp dword [r12+hda_route_program.pad],1
 je .fixed_isolate
 cmp dword [r12+hda_route_program.pad],2
 jne .fg_power
.fixed_isolate:
 mov esi,[r12+hda_route_program.nodes+hda_program_node.nid]
 xor edi,edi
 mov edx,0x8000
 mov ebx,0xCA
 call hdap_amp
 test eax,eax
 jnz .bad
 jmp .pin_disabled
.fg_power:
 ; FG first, then DAC, middle, pin D0 with capability-gated power controls.
 mov esi,[r12+hda_route_program.saved_group]
 call hdap_power
 test eax,eax
 jnz .bad
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.power:
 cmp dword [r13+hda_program_node.nid],0
 je .next_power
 test dword [r13+hda_program_node.caps],0x400
 jz .next_power
 mov esi,[r13+hda_program_node.nid]
 call hdap_power
 test eax,eax
 jnz .bad
.next_power:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .power
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0x70700,0xFFFFFFFF,0,0,.bad
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0xF0700,0xFFFFFFFF,0,0,.bad
 .pin_disabled:
 ; Pin selector only with >1 expanded input. A single hardwired input has no701.
 cmp dword [r12+hda_route_program.nodes+2*hda_program_node_size+hda_program_node.connections],1
 jbe .middle
 mov esi,[r12+hda_route_program.route+hda_route_context.pin]
 mov edi,[r12+hda_route_program.route+hda_route_context.pin_index]
 call hdap_selector
 test eax,eax
 jnz .bad
.middle:
 cmp dword [r12+hda_route_program.route+hda_route_context.kind],2
 jne .converter
 cmp dword [r12+hda_route_program.nodes+hda_program_node_size+hda_program_node.connections],1
 jbe .converter
 mov esi,[r12+hda_route_program.route+hda_route_context.middle]
 mov edi,[r12+hda_route_program.route+hda_route_context.middle_index]
 call hdap_selector
 test eax,eax
 jnz .bad
.converter:
 mov edx,[r12+hda_route_program.saved_format]
 or edx,0x20000
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.dac],edx,0xFFFFFFFF,0,0,.bad
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.dac],0xA0000,0xFFFFFFFF,[r12+hda_route_program.saved_format],0,.bad
 mov edx,[r12+hda_route_program.saved_tag]
 shl edx,4
 or edx,0x70600
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.dac],edx,0xFFFFFFFF,0,0,.bad
 mov r8d,[r12+hda_route_program.saved_tag]
 shl r8d,4
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.dac],0xF0600,0xFFFFFFFF,r8d,0,.bad
 ; Mute unselected mixer inputs, then enable the selected one at actual unity.
 cmp dword [r12+hda_route_program.route+hda_route_context.kind],1
 jne .outputs
 lea r13,[r12+hda_route_program.nodes+hda_program_node_size]
 test dword [r13+hda_program_node.caps],2
 jz .outputs
 xor r14d,r14d
.input:
 mov ebx,[r13+hda_program_node.amp_in]
 and ebx,0x7F
 cmp r14d,[r12+hda_route_program.route+hda_route_context.middle_index]
 je .input_gain
 or ebx,0x80
.input_gain:
 mov esi,[r13+hda_program_node.nid]
 mov edi,r14d
 mov edx,0x4000
 call hdap_amp
 test eax,eax
 jnz .bad
 inc r14d
 cmp r14d,[r13+hda_program_node.connections]
 jb .input
.outputs:
 cmp dword [r12+hda_route_program.pad],1
 je .enable
 cmp dword [r12+hda_route_program.pad],2
 je .enable
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.output:
 cmp dword [r13+hda_program_node.nid],0
 je .next_output
 test dword [r13+hda_program_node.caps],4
 jz .next_output
 mov ebx,[r13+hda_program_node.amp_out]
 and ebx,0x7F
 mov esi,[r13+hda_program_node.nid]
 xor edi,edi
 mov edx,0x8000
 call hdap_amp
 test eax,eax
 jnz .bad
.next_output:
 add r13,hda_program_node_size
 inc r14d
 cmp r14d,3
 jb .output
 test dword [r12+hda_route_program.pin_caps],0x10000
 jz .enable
 mov edx,[r12+hda_route_program.eapd]
 or edx,0x70C00
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],edx,0xFFFFFFFF,0,0,.bad
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0xF0C00,0xFFFFFFFF,[r12+hda_route_program.eapd],0,.bad
.enable:
 cmp dword [r12+hda_route_program.pad],1
 je .fixed_enable
 cmp dword [r12+hda_route_program.pad],2
 jne .enable_pin
.fixed_enable:
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0xF0700,0xFFFFFFFF,0x40,0,.bad
 mov esi,[r12+hda_route_program.nodes+hda_program_node.nid]
 xor edi,edi
 mov edx,0x8000
 mov ebx,0x4A
 call hdap_amp
 test eax,eax
 jnz .bad
 jmp .ok
.enable_pin:
 mov edx,[r12+hda_route_program.pin_ctl]
 or edx,0x70700
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],edx,0xFFFFFFFF,0,0,.bad
 HDAP_EMIT [r12+hda_route_program.route+hda_route_context.pin],0xF0700,0xFFFFFFFF,[r12+hda_route_program.pin_ctl],0,.bad
 ; Re-read powered nodes after all programming: no lost-settings false ready.
 HDAP_EMIT [r12+hda_route_program.saved_group],0xF0500,0xFFFFFDFF,0,0,.bad
 lea r13,[r12+hda_route_program.nodes]
 xor r14d,r14d
.final_power:
 cmp dword [r13+hda_program_node.nid],0
 je .next_final
 test dword [r13+hda_program_node.caps],0x400
 jz .next_final
 HDAP_EMIT [r13+hda_program_node.nid],0xF0500,0xFFFFFDFF,0,0,.bad
.next_final:
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
 pop r14
 pop r13
 pop rbx
 ret

; Reserved bits clear, unity offset within supported gain index range.
hda_program_amp_caps:
hdap_amp_caps:
 test eax,0x7F808080
 jnz .bad
 mov edx,eax
 and edx,0x7F
 mov ecx,eax
 shr ecx,8
 and ecx,0x7F
 cmp edx,ecx
 ja .bad
 clc
 ret
.bad:
 stc
 ret

hda_program_power:
hdap_power:
 push rbx
 mov ebx,esi
 HDAP_EMIT ebx,0x70500,0xFFFFFFFF,0,0,.bad
 HDAP_EMIT ebx,0xF0500,0,0,-1,.bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 pop rbx
 ret
hda_program_selector:
hdap_selector:
 push rbx
 push rbp
 sub rsp,8
 mov ebx,esi
 mov ebp,edi
 mov edx,edi
 or edx,0x70100
 HDAP_EMIT ebx,edx,0xFFFFFFFF,0,0,.bad
 HDAP_EMIT ebx,0xF0100,0xFFFFFFFF,ebp,0,.bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 pop rbp
 pop rbx
 ret
; ESI=node,EDI=inputindex (0 for output),EDX=direction,EBX=gain/mute.
hdap_amp:
 push rbp
 push r13
 push r14
 mov ebp,esi
 mov r13d,edi
 mov r14d,edx
 shl edi,8
 or edx,edi
 or edx,ebx
 or edx,0x33000                ;SET amp, both left/right
 HDAP_EMIT ebp,edx,0xFFFFFFFF,0,0,.bad
 ; GET uses direction bit15 and input index LOW4, left bit13.
 mov edx,r13d
 cmp r14d,0x8000
 jne .get_left
 or edx,0x8000
.get_left:
 or edx,0xB2000
 HDAP_EMIT ebp,edx,0xFFFFFFFF,ebx,0,.bad
 mov edx,r13d
 cmp r14d,0x8000
 jne .get_right
 or edx,0x8000
.get_right:
 or edx,0xB0000
 HDAP_EMIT ebp,edx,0xFFFFFFFF,ebx,0,.bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 pop r14
 pop r13
 pop rbp
 ret

%macro WDATA_hda_route_program_power 0
 align 8
hda_route_program_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_route_program_power
%else
 section .data
 WDATA_hda_route_program_power
 section .text
%endif


; Exact QEMU hda-duplex / hda-output mixer models. Bounded acquired codec
; inventory chooses model0x22 (duplex) or0x12 (output); caller cannot request
; a quirk. QEMU8.2.2 hda-codec-common.h/hda-codec.c root/FG facts are
; re-read and verified before any SET:
; revision1.0.1.1, no PM; fixed pin controls; converter amps implement mute.
; No-mixer models0x21/0x11 and unknown identities keep the generic strict path.
; R12 is trusted claimed program prefix. Volatile GPRs only; no graph writes.
hda_program_quirk:
 mov r10,[r12+hda_route_program.graph]
 mov ecx,[r10+hda_graph.discovery+hda_discovery.codec_count]
 test ecx,ecx
 jz .none
 cmp ecx,15
 ja .none
 cmp ecx,[r10+hda_graph.codec_cap]
 ja .none
 mov r10,[r10+hda_graph.codecs]
 mov edx,[r12+hda_route_program.saved_codec]
.loop:
 cmp [r10+hda_codec_info.address],edx
 je .found
 add r10,hda_codec_info_size
 dec ecx
 jnz .loop
.none:
 xor eax,eax
 ret
.found:
 mov r11d,1
 cmp dword [r10+hda_codec_info.vendor],0x1AF40022
 je .model
 mov r11d,2
 cmp dword [r10+hda_codec_info.vendor],0x1AF40012
 jne .none
.model:
 cmp dword [r10+hda_codec_info.revision],0x00100101
 jne .none
 cmp dword [r10+hda_codec_info.group_start],1
 jne .none
 cmp dword [r10+hda_codec_info.group_count],1
 jne .none
 cmp dword [r10+hda_codec_info.audio_groups],1
 jne .none
 cmp dword [r12+hda_route_program.saved_group],1
 jne .none
 mov eax,r11d
 ret

hda_program_quirk_queries:
 sub rsp,8
 cmp dword [r12+hda_route_program.pad],2
 je .output
 cmp dword [r12+hda_route_program.pad],1
 jne .ok
 HDAP_EMIT 0,0xF0000,0xFFFFFFFF,0x1AF40022,0,.bad
 HDAP_EMIT 0,0xF0002,0xFFFFFFFF,0x00100101,0,.bad
 HDAP_EMIT 0,0xF0004,0xFFFFFFFF,0x00010001,0,.bad
 HDAP_EMIT 1,0xF0004,0xFFFFFFFF,0x00020004,0,.bad
 jmp .ok
.output:
 HDAP_EMIT 0,0xF0000,0xFFFFFFFF,0x1AF40012,0,.bad
 HDAP_EMIT 0,0xF0002,0xFFFFFFFF,0x00100101,0,.bad
 HDAP_EMIT 0,0xF0004,0xFFFFFFFF,0x00010001,0,.bad
 HDAP_EMIT 1,0xF0004,0xFFFFFFFF,0x00020002,0,.bad
.ok:
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret

; Strict entire selected direct path before the first SET. ESI0 out /1 in.
; These actual caps stay retained, including fg_power0; no invented D0 fact.
hda_program_fixed_caps:
 cmp dword [r12+hda_route_program.fg_power],0
 jne .bad
 cmp dword [r12+hda_route_program.pcm],0x201FC
 jne .bad
 cmp dword [r12+hda_route_program.streams],1
 jne .bad
 cmp dword [r12+hda_route_program.nodes+hda_program_node_size+hda_program_node.nid],0
 jne .bad
 lea r10,[r12+hda_route_program.nodes]
 lea r11,[r10+2*hda_program_node_size]
 test esi,esi
 jnz .input
 cmp dword [r10+hda_program_node.nid],2
 jne .bad
 cmp dword [r10+hda_program_node.caps],0x1D
 jne .bad
 cmp dword [r10+hda_program_node.connections],0
 jne .bad
 cmp dword [r10+hda_program_node.amp_out],0x80034A4A
 jne .bad
 cmp dword [r11+hda_program_node.nid],3
 jne .bad
 cmp dword [r11+hda_program_node.caps],0x400101
 jne .bad
 cmp dword [r11+hda_program_node.connections],1
 jne .bad
 cmp dword [r12+hda_route_program.pin_caps],0x10
 jne .bad
 jmp .ok
.input:
 cmp dword [r12+hda_route_program.pad],1
 jne .bad                           ; output-only model cannot supply an ADC
 cmp dword [r10+hda_program_node.nid],4
 jne .bad
 cmp dword [r10+hda_program_node.caps],0x10011B
 jne .bad
 cmp dword [r10+hda_program_node.connections],1
 jne .bad
 cmp dword [r10+hda_program_node.amp_in],0x80034A4A
 jne .bad
 cmp dword [r11+hda_program_node.nid],5
 jne .bad
 cmp dword [r11+hda_program_node.caps],0x400001
 jne .bad
 cmp dword [r11+hda_program_node.connections],0
 jne .bad
 cmp dword [r12+hda_route_program.pin_caps],0x20
 jne .bad
.ok:
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret
