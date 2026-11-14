;; MODULE dev/snd/hda_session
;; LAYER 3
;; EXPORTS hda_graph_begin, hda_graph_step, hda_graph_cancel, hda_graph_retire, hda_graph_plan, hda_graph_command_claim, hda_graph_command_check, hda_graph_owner_check, hda_graph_input_claim, hda_graph_input_check
;; IMPORTS boot/native_driver_gate, dev/snd/hda_transport, dev/snd/hda_codec, dev/snd/hda_binding, dev/snd/hda_capture, dev/snd/hda_route
;; CAPS mmio dma
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_SESSION_POWER 0
 cmp qword [rel hda_session_power_gate],0
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
 call [rel hda_session_power_gate]
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
; Private controller-owner acquisition session, not a sound backend. Compose
; actual binding/reset/discovery, attributed CORB/RIRB, and long/range capture.
; No SET verbs, stream start, registration, allocation or global mutable state.
; Existing QEMU-only diagnostic and DMA/IOMMU guards are untouched. This software
; lease is NOT a DMA-domain receipt, hardware identity or permission grant.
; A production caller must already own/bind/map the whole controller and retain
; enforcing IOMMU receipts/mapping epochs, stable pinned DMA buffers and exclusive
; serialized access. IRQ/other command users must not access these rings.
;
; Owner preclaims lease.holder=this context with a nonzero increasing epoch and
; a stable transport*. Begin refuses live contexts/pending commands. Inputs0..119
; and all buffer pointers/capacities stay immutable until retirement. All ten
; accessed spans are checked disjoint/nonwrapping; mappedness is the trusted
; driver's responsibility. Context/lease/transport are writable; buffers pinned.
; clock(arg,out_u64*) ->0 known, nonzero unknown/error; monotonic ticks, no reentry.
; reset(arg) is the SAME cooperative verified reset/drain contract as binding:
; 0 verified,1 pending,-1 failure, bounded work/deadline, preserve SysV; never
; replace controller/buffers, never allocate/reenter. Success resets software
; cursors/pending/fault and drains RIRB. This cannot prove physical reset from RAM.
; Cleanup retains ownership and mappings on reset failure; nothing is freed.
; Retirement releases software holder only after verified reset/drain. Buffers
; remain pinned: no hardware DMA-stop/free qualification is implied.
;
; hda_graph_begin(RDI=context944,RSI=epoch) ->0 initialized/-1 inert refusal.
; hda_graph_step(RDI=context,RSI=epoch) ->1 yield/2 complete/-1 failed/refused.
; hda_graph_cancel(RDI=context,RSI=epoch) ->1 cleanup scheduled/-1 refused.
; hda_graph_retire(RDI=context,RSI=epoch) ->0 released/-1 refused.
; hda_graph_plan(RDI=context,RSI=route64*,RDX=epoch) ->actual planner status.
; Stale caller epoch refuses unchanged. Lost ownership revokes without touching
; another owner's MMIO/reset. Other faults immediately revoke all counts, then
; step drives bounded cleanup; FAILED clean0 needs controller-owner recovery.
; Never abandon a retained command on busy or feed un-attributed responses.
; Only queued DISCOVERY/CAPTURE secondary response timeouts may schedule binding
; skip; verified reset precedes committed skip/restart. Busy/session/global faults
; are fatal. All rows/inventory are provisional until phase DONE and public counts
; publish together. Embedded counts alone are NOT a publication interface.
; One next/queue/take/reset operation per step. RIRB take<=256 entries; codec walk,
; capture and planner retain their finite bounds. Command polls<=4096, session
; steps<=1000000, cleanup polls<=4096 even with frozen clock. Unknown/overflow/
; regressing clocks fail closed. Plan is acquisition-only, not playback readiness.
; Plan buffer must be separate trusted writable memory, disjoint from owner/session
; and transport/rings; its graph pointers/counts must match the published graph.
; SysV nonvolatile GPRs/RSP and DF0 ABI. No memory can be released by this API.

HDAGS_DISCOVER equ 1
HDAGS_CAPTURE equ 2
HDAGS_CLEANUP equ 3
HDAGS_DONE equ 4
HDAGS_FAILED equ 5
HDAGS_RETIRED equ 6

struc hda_graph_lease
 .holder: resq 1
 .epoch: resq 1
 .transport: resq 1
endstruc
struc hda_graph
 .owner: resq 1
 .reset_fn: resq 1
 .reset_arg: resq 1
 .clock_fn: resq 1
 .clock_arg: resq 1
 .codecs: resq 1
 .groups: resq 1
 .widgets: resq 1
 .edges: resq 1
 .command_timeout: resq 1
 .session_timeout: resq 1
 .codec_cap: resd 1
 .group_cap: resd 1
 .widget_cap: resd 1
 .edge_cap: resd 1
 .poll_limit: resd 1
 .step_limit: resd 1
 .statests: resd 1
 .primary: resd 1
 .epoch: resq 1
 .transport: resq 1
 .mmio: resq 1
 .corb: resq 1
 .rirb: resq 1
 .last_now: resq 1
 .deadline: resq 1
 .command_deadline: resq 1
 .command: resd 1
 .response: resd 1
 .phase: resd 1
 .request_state: resd 1           ;0 none,1 retained/unsubmitted,2 queued
 .request_phase: resd 1
 .source_pad: resd 1
 .source: resq 1                  ;discovery phase or capture widget index
 .request_offset: resd 1
 .command_polls: resd 1
 .steps: resd 1
 .reset_polls: resd 1
 .error: resd 1                   ;1 input,2 clock,3 timeout,4 transport,5 codec,
 .clean: resd 1                   ;6 capture,7 cancel,8 ownership,9 bound,10 reset
 .public_widget_count: resd 1
 .public_edge_count: resd 1
 .observed_now: resq 1
 .binding: resb hda_binding_size
 .discovery: resb hda_discovery_size
 .capture: resb hda_capture_size
 .command_owner: resq 1           ;one post-acquisition programming context
 .command_ready: resd 1           ;revoked by EVERY graph cancellation/fault
 .command_pad: resd 1
 .pcm_owner: resq 1               ;sticky PCM claim until a new graph epoch
 .pcm_quiescent: resd 1           ;verified stream stop; not DMA-free permission
 .pcm_pad: resd 1
 .input_owner: resq 1
 .input_ready: resd 1
 .input_quiescent: resd 1
endstruc

%macro HDAGS_SPAN 3
 mov rax,%1
 mov rdx,%2
 lea rdi,[rsp+%3]
 call hdags_span
 jc .refuse
%endmacro

hda_graph_begin:
    NATIVE_DRIVER_REFUSE 7
 HDA_SESSION_POWER
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,184                     ;ten spans, clock result, scratch
 mov r12,rdi
 mov rbp,rsi
 HDAGS_SPAN r12,hda_graph_size,0
 cmp dword [r12+hda_graph.phase],0
 je .fresh
 cmp dword [r12+hda_graph.phase],HDAGS_RETIRED
 jne .refuse
.fresh:
 test rbp,rbp
 jz .refuse
 cmp rbp,[r12+hda_graph.epoch]
 jbe .refuse
 mov r13,[r12+hda_graph.owner]
 HDAGS_SPAN r13,hda_graph_lease_size,16
 cmp [r13+hda_graph_lease.holder],r12
 jne .refuse
 cmp [r13+hda_graph_lease.epoch],rbp
 jne .refuse
 mov rbx,[r13+hda_graph_lease.transport]
 HDAGS_SPAN rbx,hda_transport_size,32
 cmp dword [rbx+hda_transport.pending],0
 jne .refuse
 cmp dword [rbx+hda_transport.fault],0
 jne .refuse
 cmp qword [r12+hda_graph.reset_fn],0
 je .refuse
 cmp qword [r12+hda_graph.clock_fn],0
 je .refuse
 cmp qword [r12+hda_graph.command_timeout],0
 je .refuse
 cmp qword [r12+hda_graph.session_timeout],0
 je .refuse
 mov eax,[r12+hda_graph.poll_limit]
 dec eax
 cmp eax,4095
 ja .refuse
 mov eax,[r12+hda_graph.step_limit]
 dec eax
 cmp eax,999999
 ja .refuse
 mov ecx,[r12+hda_graph.primary]
 cmp ecx,15
 jae .refuse
 mov eax,[r12+hda_graph.statests]
 test eax,0xFFFF8000
 jnz .refuse
 bt eax,ecx
 jnc .refuse
 mov edx,[r12+hda_graph.codec_cap]
 cmp edx,15
 ja .refuse
 shl edx,5
 HDAGS_SPAN [r12+hda_graph.codecs],rdx,48
 mov edx,[r12+hda_graph.group_cap]
 cmp edx,1905
 ja .refuse
 imul edx,edx,hda_group_info_size
 HDAGS_SPAN [r12+hda_graph.groups],rdx,64
 mov edx,[r12+hda_graph.widget_cap]
 cmp edx,1905
 ja .refuse
 shl edx,5
 HDAGS_SPAN [r12+hda_graph.widgets],rdx,80
 mov edx,[r12+hda_graph.edge_cap]
 cmp edx,2048
 ja .refuse
 imul edx,edx,hda_route_edge_size
 HDAGS_SPAN [r12+hda_graph.edges],rdx,96
 HDAGS_SPAN [rbx+hda_transport.mmio],128,112
 HDAGS_SPAN [rbx+hda_transport.corb],1024,128
 HDAGS_SPAN [rbx+hda_transport.rirb],2048,144
 mov rdi,rsp
 call hdags_disjoint
 jc .refuse
 mov rdi,[r12+hda_graph.clock_arg]
 lea rsi,[rsp+160]
 mov qword [rsi],-1
 call [r12+hda_graph.clock_fn]
 test rax,rax
 jnz .refuse
 mov r14,[rsp+160]
 cmp r14,-1
 je .refuse
 mov r15,r14
 add r15,[r12+hda_graph.session_timeout]
 jc .refuse
 mov rax,r14
 add rax,[r12+hda_graph.command_timeout]
 jc .refuse
 ; No external callback may transfer/replace ownership behind begin.
 cmp [r13+hda_graph_lease.holder],r12
 jne .refuse
 cmp [r13+hda_graph_lease.epoch],rbp
 jne .refuse
 cmp [r13+hda_graph_lease.transport],rbx
 jne .refuse
 cmp dword [rbx+hda_transport.pending],0
 jne .refuse
 cmp dword [rbx+hda_transport.fault],0
 jne .refuse
 mov rax,[rbx+hda_transport.mmio]
 cmp rax,[rsp+112]
 jne .refuse
 mov rax,[rbx+hda_transport.corb]
 cmp rax,[rsp+128]
 jne .refuse
 mov rax,[rbx+hda_transport.rirb]
 cmp rax,[rsp+144]
 jne .refuse
 lea rdi,[r12+hda_graph.epoch]
 xor eax,eax
 mov ecx,(hda_graph_size-hda_graph.epoch)/8
 rep stosq
 mov [r12+hda_graph.epoch],rbp
 mov [r12+hda_graph.transport],rbx
 mov rax,[rbx+hda_transport.mmio]
 mov [r12+hda_graph.mmio],rax
 mov rax,[rbx+hda_transport.corb]
 mov [r12+hda_graph.corb],rax
 mov rax,[rbx+hda_transport.rirb]
 mov [r12+hda_graph.rirb],rax
 mov [r12+hda_graph.last_now],r14
 mov [r12+hda_graph.deadline],r15
 lea rdi,[r12+hda_graph.discovery]
 mov rax,[r12+hda_graph.codecs]
 mov [rdi+hda_discovery.codecs],rax
 mov rax,[r12+hda_graph.groups]
 mov [rdi+hda_discovery.groups],rax
 mov rax,[r12+hda_graph.widgets]
 mov [rdi+hda_discovery.widgets],rax
 mov eax,[r12+hda_graph.codec_cap]
 mov [rdi+hda_discovery.codec_cap],eax
 mov eax,[r12+hda_graph.group_cap]
 mov [rdi+hda_discovery.group_cap],eax
 mov eax,[r12+hda_graph.widget_cap]
 mov [rdi+hda_discovery.widget_cap],eax
 mov [r12+hda_graph.binding+hda_binding.discovery],rdi
 lea rax,[rel hdags_checked_reset]
 mov [r12+hda_graph.binding+hda_binding.reset_fn],rax
 mov [r12+hda_graph.binding+hda_binding.reset_arg],r12
 mov rax,[r12+hda_graph.widgets]
 mov [r12+hda_graph.capture+hda_capture.widgets],rax
 mov rax,[r12+hda_graph.edges]
 mov [r12+hda_graph.capture+hda_capture.edges],rax
 mov eax,[r12+hda_graph.edge_cap]
 mov [r12+hda_graph.capture+hda_capture.edge_capacity],rax
 lea rdi,[r12+hda_graph.binding]
 mov esi,[r12+hda_graph.statests]
 mov edx,[r12+hda_graph.primary]
 call hda_binding_begin
 test rax,rax
 jnz .refuse
 mov dword [r12+hda_graph.phase],HDAGS_DISCOVER
 xor eax,eax
 jmp .out
.refuse:
 mov rax,-1
.out:
 add rsp,184
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

hda_graph_step:
 HDA_SESSION_POWER
 push rbx
 push rbp
 push r12
 mov r12,rdi
 mov rbp,rsi
 cmp rbp,[r12+hda_graph.epoch]
 jne .refuse
 cmp dword [r12+hda_graph.phase],0
 je .refuse
 cmp dword [r12+hda_graph.phase],HDAGS_RETIRED
 jae .refuse
 call hdags_identity
 test rax,rax
 jnz .lost
 cmp dword [r12+hda_graph.phase],HDAGS_FAILED
 je .refuse
 cmp dword [r12+hda_graph.phase],HDAGS_CLEANUP
 je .cleanup
 mov rbx,[r12+hda_graph.transport]
 cmp dword [rbx+hda_transport.fault],0
 jne .transport_error
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .transport_error
 cmp dword [r12+hda_graph.phase],HDAGS_DONE
 je .done
 inc dword [r12+hda_graph.steps]
 mov eax,[r12+hda_graph.steps]
 cmp eax,[r12+hda_graph.step_limit]
 ja .bound
 mov rdi,[r12+hda_graph.clock_arg]
 lea rsi,[r12+hda_graph.observed_now]
 mov qword [rsi],-1
 call [r12+hda_graph.clock_fn]
 test rax,rax
 jnz .clock_error
 mov rdi,r12
 mov rsi,rbp
 call hdags_identity
 test rax,rax
 jnz .lost
 mov rax,[r12+hda_graph.observed_now]
 cmp rax,-1
 je .clock_error
 cmp rax,[r12+hda_graph.last_now]
 jb .clock_error
 mov [r12+hda_graph.last_now],rax
 cmp rax,[r12+hda_graph.deadline]
 jae .fatal_timeout
 cmp dword [r12+hda_graph.request_state],0
 je .next
 cmp dword [r12+hda_graph.request_state],2
 ja .transport_error
 inc dword [r12+hda_graph.command_polls]
 mov edx,[r12+hda_graph.command_polls]
 cmp edx,[r12+hda_graph.poll_limit]
 ja .command_timeout
 cmp rax,[r12+hda_graph.command_deadline]
 jae .command_timeout
 mov rdi,r12
 call hdags_source
 test rax,rax
 jnz .transport_error
 cmp dword [r12+hda_graph.request_state],1
 je .queue
 cmp dword [rbx+hda_transport.pending],1
 jne .transport_error
 mov eax,[r12+hda_graph.command]
 shr eax,28
 cmp eax,[rbx+hda_transport.codec]
 jne .transport_error
 mov rdi,rbx
 lea rsi,[r12+hda_graph.response]
 call hda_rirb_take
 test rax,rax
 js .transport_error
 jnz .yield
 mov dword [r12+hda_graph.request_state],0
 cmp dword [r12+hda_graph.request_phase],HDAGS_DISCOVER
 jne .capture_reply
 lea rdi,[r12+hda_graph.binding]
 mov esi,[r12+hda_graph.response]
 call hda_binding_reply
 test rax,rax
 js .codec_error
 cmp eax,HDB_RESETTING
 je .restarting
 jmp .yield
.capture_reply:
 lea rdi,[r12+hda_graph.capture]
 mov esi,[r12+hda_graph.response]
 call hda_capture_reply
 test rax,rax
 js .capture_error
 jmp .yield
.queue:
 cmp dword [rbx+hda_transport.pending],0
 jne .transport_error
 mov rdi,rbx
 mov esi,[r12+hda_graph.command]
 call hda_corb_queue
 test rax,rax
 js .transport_error
 jnz .yield                      ;retain exact command/source/deadline
 mov dword [r12+hda_graph.request_state],2
 jmp .yield
.next:
 ; Only verified binding reset may own an old timed-out pending command.
 cmp dword [r12+hda_graph.binding+hda_binding.stage],HDB_RESET
 je .binding_next
 cmp dword [rbx+hda_transport.pending],0
 jne .transport_error
 cmp dword [r12+hda_graph.phase],HDAGS_CAPTURE
 je .capture_next
.binding_next:
 lea rdi,[r12+hda_graph.binding]
 lea rsi,[r12+hda_graph.command]
 call hda_binding_next
 test rax,rax
 js .codec_error
 cmp eax,HDB_RESETTING
 je .yield
 cmp eax,HDAC_DONE
 je .start_capture
 test eax,eax
 jnz .transport_error            ;WAIT without owned request is inconsistent
 mov eax,[r12+hda_graph.discovery+hda_discovery.phase]
 mov [r12+hda_graph.source],rax
 jmp .retained
.capture_next:
 lea rdi,[r12+hda_graph.capture]
 lea rsi,[r12+hda_graph.command]
 call hda_capture_next
 test rax,rax
 js .capture_error
 cmp eax,2
 je .complete
 test eax,eax
 jnz .transport_error
 mov rax,[r12+hda_graph.capture+hda_capture.widget_index]
 mov [r12+hda_graph.source],rax
 mov eax,[r12+hda_graph.capture+hda_capture.offset]
 mov [r12+hda_graph.request_offset],eax
.retained:
 mov eax,[r12+hda_graph.phase]
 mov [r12+hda_graph.request_phase],eax
 mov rax,[r12+hda_graph.last_now]
 add rax,[r12+hda_graph.command_timeout]
 jc .clock_error
 mov [r12+hda_graph.command_deadline],rax
 mov dword [r12+hda_graph.command_polls],0
 mov dword [r12+hda_graph.request_state],1
 jmp .yield
.start_capture:
 mov eax,[r12+hda_graph.discovery+hda_discovery.widget_count]
 mov [r12+hda_graph.capture+hda_capture.widget_count],rax
 lea rdi,[r12+hda_graph.capture]
 call hda_capture_begin
 test rax,rax
 js .capture_error
 mov dword [r12+hda_graph.phase],HDAGS_CAPTURE
 jmp .yield
.complete:
 mov eax,[r12+hda_graph.discovery+hda_discovery.widget_count]
 mov [r12+hda_graph.public_widget_count],eax
 mov eax,[r12+hda_graph.capture+hda_capture.edge_count]
 mov [r12+hda_graph.public_edge_count],eax
 mov dword [r12+hda_graph.phase],HDAGS_DONE
.done:
 cmp dword [rbx+hda_transport.pending],0
 jne .transport_error
 mov eax,2
 jmp .out
.command_timeout:
 cmp dword [r12+hda_graph.request_state],2
 jne .fatal_timeout              ;CORB stall is not a codec-response timeout
 cmp dword [rbx+hda_transport.pending],1
 jne .transport_error
 cmp dword [rbx+hda_transport.fault],0
 jne .transport_error
 mov eax,[r12+hda_graph.command]
 shr eax,28
 cmp eax,[rbx+hda_transport.codec]
 jne .transport_error
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .transport_error
 mov rdi,r12
 call hdags_source
 test rax,rax
 jnz .transport_error
 lea rdi,[r12+hda_graph.binding]
 cmp dword [r12+hda_graph.request_phase],HDAGS_CAPTURE
 je .capture_timeout
 mov esi,1
 call hda_binding_abort
 jmp .timeout_result
.capture_timeout:
 mov esi,[r12+hda_graph.command]
 shr esi,28
 call hda_binding_capture_timeout
.timeout_result:
 cmp eax,HDB_RESETTING
 jne .fatal_timeout
.restarting:
 lea rdi,[r12+hda_graph.capture]
 call hda_capture_abort
 mov dword [r12+hda_graph.public_widget_count],0
 mov dword [r12+hda_graph.public_edge_count],0
 mov dword [r12+hda_graph.request_state],0
 mov dword [r12+hda_graph.phase],HDAGS_DISCOVER
 jmp .yield
.cleanup:
 inc dword [r12+hda_graph.reset_polls]
 mov eax,[r12+hda_graph.reset_polls]
 cmp eax,[r12+hda_graph.poll_limit]
 ja .reset_failed
 mov rdi,r12
 call hdags_checked_reset
 test rax,rax
 jz .clean
 cmp rax,1
 je .yield
.reset_failed:
 mov dword [r12+hda_graph.phase],HDAGS_FAILED
 mov rax,-1
 jmp .out
.clean:
 mov dword [r12+hda_graph.clean],1
 mov dword [r12+hda_graph.phase],HDAGS_FAILED
 mov rax,-1
 jmp .out
.clock_error:
 mov esi,2
 jmp .fail
.fatal_timeout:
 mov esi,3
 jmp .fail
.transport_error:
 mov esi,4
 jmp .fail
.codec_error:
 mov esi,5
 jmp .fail
.capture_error:
 mov esi,6
 jmp .fail
.bound:
 mov esi,9
.fail:
 mov rdi,r12
 call hdags_fail
 jmp .out
.lost:
 mov rdi,r12
 mov esi,8
 call hdags_fail
 mov dword [r12+hda_graph.phase],HDAGS_FAILED ;never reset another owner
.refuse:
 mov rax,-1
 jmp .out
.yield:
 mov eax,1
.out:
 pop r12
 pop rbp
 pop rbx
 ret

hda_graph_cancel:
 HDA_SESSION_POWER
 push r12
 mov r12,rdi
 cmp rsi,[r12+hda_graph.epoch]
 jne .refuse
 cmp dword [r12+hda_graph.phase],0
 je .refuse
 cmp dword [r12+hda_graph.phase],HDAGS_FAILED
 jae .refuse
 call hdags_identity
 test rax,rax
 jnz .lost
 cmp dword [r12+hda_graph.phase],HDAGS_CLEANUP
 je .pending
 mov rdi,r12
 mov esi,7
 call hdags_fail
 jmp .out
.lost:
 mov rdi,r12
 mov esi,8
 call hdags_fail
 mov dword [r12+hda_graph.phase],HDAGS_FAILED
.refuse:
 mov rax,-1
 jmp .out
.pending:
 mov eax,1
.out:
 pop r12
 ret

hda_graph_retire:
 HDA_SESSION_POWER
 push r12
 mov r12,rdi
 cmp rsi,[r12+hda_graph.epoch]
 jne .refuse
 cmp dword [r12+hda_graph.phase],HDAGS_FAILED
 jne .refuse
 cmp dword [r12+hda_graph.clean],1
 jne .refuse
 call hdags_identity
 test rax,rax
 jnz .refuse
 mov rax,[r12+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .refuse
 cmp dword [rax+hda_transport.fault],0
 jne .refuse
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .refuse
 mov rax,[r12+hda_graph.owner]
 mov qword [rax+hda_graph_lease.holder],0
 mov dword [r12+hda_graph.phase],HDAGS_RETIRED
 xor eax,eax
 jmp .out
.refuse:
 mov rax,-1
.out:
 pop r12
 ret

hda_graph_plan:
 HDA_SESSION_POWER
 push rbx
 push r12
 sub rsp,8
 mov r12,rdi
 mov rbx,rsi
 cmp rdx,[r12+hda_graph.epoch]
 jne .refuse
 cmp dword [r12+hda_graph.phase],HDAGS_DONE
 jne .refuse
 mov rsi,rdx
 call hdags_identity
 test rax,rax
 jnz .lost
 mov rax,[r12+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .fault
 cmp dword [rax+hda_transport.fault],0
 jne .fault
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .fault
 test rbx,rbx
 jz .refuse
 mov rax,rbx
 add rax,hda_route_context_size
 jc .refuse
 lea rcx,[r12+hda_graph_size]
 cmp rbx,rcx
 jae .disjoint
 cmp r12,rax
 jb .refuse
.disjoint:
 mov rdi,r12
 mov rsi,rbx
 mov rdx,rax
 call hdags_plan_separate
 jc .refuse
 mov rax,[rbx+hda_route_context.widgets]
 cmp rax,[r12+hda_graph.widgets]
 jne .refuse
 mov eax,[r12+hda_graph.public_widget_count]
 cmp [rbx+hda_route_context.widget_count],rax
 jne .refuse
 mov rax,[rbx+hda_route_context.edges]
 cmp rax,[r12+hda_graph.edges]
 jne .refuse
 mov eax,[r12+hda_graph.public_edge_count]
 cmp [rbx+hda_route_context.edge_count],rax
 jne .refuse
 mov rdi,rbx
 call hda_route_plan
 jmp .out
.fault:
 mov esi,4
 jmp .revoke
.lost:
 mov esi,8
.revoke:
 mov rdi,r12
 call hdags_fail
 cmp dword [r12+hda_graph.error],8
 jne .refuse
 mov dword [r12+hda_graph.phase],HDAGS_FAILED
.refuse:
 mov rax,-1
.out:
 add rsp,8
 pop r12
 pop rbx
 ret

; Private epoch/controller check: no MMIO and no state changes.
hdags_identity:
 test rsi,rsi
 jz .bad
 cmp rsi,[rdi+hda_graph.epoch]
 jne .bad
 mov r8,[rdi+hda_graph.owner]
 cmp [r8+hda_graph_lease.holder],rdi
 jne .bad
 cmp [r8+hda_graph_lease.epoch],rsi
 jne .bad
 mov r9,[rdi+hda_graph.transport]
 cmp [r8+hda_graph_lease.transport],r9
 jne .bad
 mov rax,[rdi+hda_graph.mmio]
 cmp [r9+hda_transport.mmio],rax
 jne .bad
 mov rax,[rdi+hda_graph.corb]
 cmp [r9+hda_transport.corb],rax
 jne .bad
 mov rax,[rdi+hda_graph.rirb]
 cmp [r9+hda_transport.rirb],rax
 jne .bad
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

; Retained command source must remain exactly the pending child phase.
hdags_source:
 mov eax,[rdi+hda_graph.phase]
 cmp eax,[rdi+hda_graph.request_phase]
 jne .bad
 cmp eax,HDAGS_DISCOVER
 jne .capture
 cmp dword [rdi+hda_graph.binding+hda_binding.stage],HDB_WALK
 jne .bad
 cmp dword [rdi+hda_graph.discovery+hda_discovery.waiting],1
 jne .bad
 mov eax,[rdi+hda_graph.discovery+hda_discovery.phase]
 cmp rax,[rdi+hda_graph.source]
 jne .bad
 mov eax,[rdi+hda_graph.binding+hda_binding.last_verb]
 cmp eax,[rdi+hda_graph.command]
 jne .bad
 xor eax,eax
 ret
.capture:
 cmp eax,HDAGS_CAPTURE
 jne .bad
 cmp dword [rdi+hda_graph.capture+hda_capture.phase],1
 jne .bad
 cmp dword [rdi+hda_graph.capture+hda_capture.waiting],1
 jne .bad
 mov rax,[rdi+hda_graph.capture+hda_capture.widget_index]
 cmp rax,[rdi+hda_graph.source]
 jne .bad
 shl rax,5
 add rax,[rdi+hda_graph.widgets]
 mov edx,[rax+hda_widget_info.codec]
 shl edx,28
 mov ecx,[rax+hda_widget_info.nid]
 shl ecx,20
 or edx,ecx
 or edx,0xF0200
 mov eax,[rdi+hda_graph.capture+hda_capture.offset]
 cmp eax,[rdi+hda_graph.request_offset]
 jne .bad
 or edx,eax
 cmp edx,[rdi+hda_graph.command]
 jne .bad
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

; Shared binding callback wrapper; keeps controller/buffers/epoch unchanged.
hdags_checked_reset:
 push r12
 mov r12,rdi
 mov rsi,[r12+hda_graph.epoch]
 call hdags_identity
 test rax,rax
 jnz .bad
 ; A graph fault may revoke codec readiness while PCM is live. Never invoke
 ; the controller reset owner until the PCM client verifies its stream stop.
 cmp qword [r12+hda_graph.pcm_owner],0
 je .quiescent
 cmp dword [r12+hda_graph.pcm_quiescent],1
 jne .pending                    ;bounded graph cleanup waits for PCM owner
.quiescent:
 cmp qword [r12+hda_graph.input_owner],0
 je .input_quiescent
 cmp dword [r12+hda_graph.input_quiescent],1
 jne .pending
.input_quiescent:
 mov rdi,[r12+hda_graph.reset_arg]
 call [r12+hda_graph.reset_fn]
 push rax
 sub rsp,8
 mov rdi,r12
 mov rsi,[r12+hda_graph.epoch]
 call hdags_identity
 add rsp,8
 pop rdx
 test rax,rax
 jnz .bad
 cmp rdx,1
 je .pending
 test rdx,rdx
 jnz .bad
 mov r8,[r12+hda_graph.transport]
 cmp dword [r8+hda_transport.pending],0
 jne .bad
 cmp dword [r8+hda_transport.fault],0
 jne .bad
 cmp dword [r8+hda_transport.corb_wp],0
 jne .bad
 cmp dword [r8+hda_transport.rirb_rp],0
 jne .bad
 mov r8,[r12+hda_graph.mmio]
 test byte [r8+HDAT_RIRBSTS],4
 jnz .bad
 test word [r8+HDAT_RIRBWP],0x80FF
 jnz .bad
 test word [r8+HDAT_CORBWP],0xFF
 jnz .bad
 xor eax,eax
 jmp .out
.pending:
 mov eax,1
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r12
 ret

; Revoke immediately, retain mappings/lease, then cooperatively reset/drain.
hdags_fail:
 push rbx
 mov rbx,rdi
 mov dword [rbx+hda_graph.command_ready],0
 mov dword [rbx+hda_graph.input_ready],0
 cmp dword [rbx+hda_graph.error],0
 jne .preserve
 mov [rbx+hda_graph.error],esi
.preserve:
 mov dword [rbx+hda_graph.public_widget_count],0
 mov dword [rbx+hda_graph.public_edge_count],0
 mov dword [rbx+hda_graph.request_state],0
 mov dword [rbx+hda_graph.clean],0
 mov dword [rbx+hda_graph.reset_polls],0
 mov dword [rbx+hda_graph.phase],HDAGS_CLEANUP
 lea rdi,[rbx+hda_graph.binding]
 mov esi,2
 call hda_binding_abort
 lea rdi,[rbx+hda_graph.capture]
 call hda_capture_abort
 mov eax,1
 pop rbx
 ret

; RAX=start,RDX=bytes,RDI=pair. Empty spans ignore unused poison pointer.
hdags_span:
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

; Post-acquisition command lease. Caller serializes the whole controller. The
; claim persists through readiness/failure until graph reset/retirement; a new
; transaction requires a new graph epoch. No transfer, allocation or DMA grant.
; claim(graph,context,context_bytes,epoch)->0/-1; check(graph,context,epoch)->0/-1.
; While claimed, drive the command client, not graph_step. graph_cancel remains
; legal and immediately revokes command_ready; cleanup remains graph-owned.
hda_graph_command_claim:
 HDA_SESSION_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 mov rbx,rsi
 mov r13,rdx
 mov rsi,rcx
 call hdags_identity
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_graph.phase],HDAGS_DONE
 jne .bad
 ; Input owns the next command client. Existing completed output may coexist,
 ; but a new output program cannot begin after the sticky input claim.
 cmp qword [r12+hda_graph.input_owner],0
 jne .bad
 cmp qword [r12+hda_graph.command_owner],0
 jne .bad
 test rbx,rbx
 jz .bad
 test r13,r13
 jz .bad
 mov rdx,rbx
 add rdx,r13
 jc .bad
 lea rax,[r12+hda_graph_size]
 cmp rbx,rax
 jae .separate
 cmp r12,rdx
 jb .bad
.separate:
 mov rdi,r12
 mov rsi,rbx
 call hdags_plan_separate
 jc .bad
 mov rax,[r12+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .bad
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .bad
 mov [r12+hda_graph.command_owner],rbx
 mov dword [r12+hda_graph.command_ready],0
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_graph_command_check:
 push rbx
 push r12
 sub rsp,8
 mov r12,rdi
 mov rbx,rsi
 mov rsi,rdx
 call hdags_identity
 test rax,rax
 jnz .bad
 cmp [r12+hda_graph.command_owner],rbx
 jne .bad
 cmp dword [r12+hda_graph.phase],HDAGS_DONE
 jne .bad
 mov rax,[r12+hda_graph.transport]
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 pop r12
 pop rbx
 ret

; Identity-only check permits the PCM client to halt its own stream after a
; graph/route fault. Does not access MMIO or confer route/receipt readiness.
hda_graph_owner_check:
 jmp hdags_identity
hdags_disjoint:
 xor ecx,ecx
.outer:
 mov r8,[rdi+rcx]
 mov r9,[rdi+rcx+8]
 cmp r8,r9
 je .next_outer
 lea edx,[rcx+16]
.inner:
 cmp edx,160
 jae .next_outer
 mov r10,[rdi+rdx]
 mov r11,[rdi+rdx+8]
 cmp r10,r11
 je .next_inner
 cmp r8,r11
 jae .next_inner
 cmp r10,r9
 jb .bad
.next_inner:
 add edx,16
 jmp .inner
.next_outer:
 add ecx,16
 cmp ecx,160
 jb .outer
 clc
 ret
.bad:
 stc
 ret

%macro HDAGS_PLAN_SPAN 2
 mov r8,%1
 mov r9,%2
 test r9,r9
 jz %%skip
 add r9,r8
 cmp r10,r9
 jae %%skip
 cmp r8,r11
 jb .bad
%%skip:
%endmacro
; RDI=session,RSI=plan,RDX=plan end. All session spans validated at begin.
hdags_plan_separate:
 mov r10,rsi
 mov r11,rdx
 HDAGS_PLAN_SPAN [rdi+hda_graph.owner],hda_graph_lease_size
 HDAGS_PLAN_SPAN [rdi+hda_graph.transport],hda_transport_size
 HDAGS_PLAN_SPAN [rdi+hda_graph.mmio],128
 HDAGS_PLAN_SPAN [rdi+hda_graph.corb],1024
 HDAGS_PLAN_SPAN [rdi+hda_graph.rirb],2048
 mov ecx,[rdi+hda_graph.codec_cap]
 shl ecx,5
 HDAGS_PLAN_SPAN [rdi+hda_graph.codecs],rcx
 mov ecx,[rdi+hda_graph.group_cap]
 imul ecx,ecx,hda_group_info_size
 HDAGS_PLAN_SPAN [rdi+hda_graph.groups],rcx
 mov ecx,[rdi+hda_graph.widget_cap]
 shl ecx,5
 HDAGS_PLAN_SPAN [rdi+hda_graph.widgets],rcx
 mov ecx,[rdi+hda_graph.edge_cap]
 imul ecx,ecx,hda_route_edge_size
 HDAGS_PLAN_SPAN [rdi+hda_graph.edges],rcx
 clc
 ret
.bad:
 stc
 ret

; Independent input transaction over the same serialized controller owner.
hda_graph_input_claim:
 HDA_SESSION_POWER
 push rbx
 push r12
 push r13
 mov r12,rdi
 mov rbx,rsi
 mov r13,rdx
 mov rsi,rcx
 call hdags_identity
 test rax,rax
 jnz .bad
 cmp dword [r12+hda_graph.phase],HDAGS_DONE
 jne .bad
 cmp qword [r12+hda_graph.command_owner],0
 je .output_idle
 cmp dword [r12+hda_graph.command_ready],1
 jne .bad
.output_idle:
 cmp qword [r12+hda_graph.input_owner],0
 jne .bad
 test rbx,rbx
 jz .bad
 test r13,r13
 jz .bad
 mov rdx,rbx
 add rdx,r13
 jc .bad
 lea rax,[r12+hda_graph_size]
 cmp rbx,rax
 jae .separate
 cmp r12,rdx
 jb .bad
.separate:
 mov rdi,r12
 mov rsi,rbx
 call hdags_plan_separate
 jc .bad
 mov rax,[r12+hda_graph.transport]
 cmp dword [rax+hda_transport.pending],0
 jne .bad
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .bad
 mov dword [r12+hda_graph.input_quiescent],1
 mov [r12+hda_graph.input_owner],rbx
 mov dword [r12+hda_graph.input_ready],0
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hda_graph_input_check:
 push rbx
 push r12
 sub rsp,8
 mov r12,rdi
 mov rbx,rsi
 mov rsi,rdx
 call hdags_identity
 test rax,rax
 jnz .bad
 cmp [r12+hda_graph.input_owner],rbx
 jne .bad
 cmp dword [r12+hda_graph.phase],HDAGS_DONE
 jne .bad
 mov rax,[r12+hda_graph.transport]
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 mov rax,[r12+hda_graph.mmio]
 test byte [rax+HDAT_RIRBSTS],4
 jnz .bad
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,8
 pop r12
 pop rbx
 ret

%macro WDATA_hda_session_power 0
 align 8
hda_session_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_session_power
%else
 section .data
 WDATA_hda_session_power
 section .text
%endif
