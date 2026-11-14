;; MODULE svc/reinit_power_hda
;; LAYER 5
;; EXPORTS reinit_power_hda_register, reinit_power_hda_admit
;; IMPORTS svc/reinit_power, dev/snd/hda_backend, dev/snd/hda_transport, dev/snd/hda_session, dev/snd/hda_output, dev/snd/hda_pcm, dev/snd/hda_input, dev/snd/hda_route_program, core/lib/mem
;; CAPS mmio dma
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Explicit sole native-controller attachment; polling, retained-power IDLE only.
; No boot activation, PCI/power/reset, allocation, free, registry or replacement
; receipt. All contexts, declarations, generation word and DMA stay pinned.
; Open/started playback, capture batches, pending commands and IRQ-enabled
; controllers refuse STOP without effects. Never tear down an epoch to fake resume.
; Intel HDA1.0a §§3.3.14/22/29/32/35,4.4,4.5.4: read back actual engine stop.
%include "core/abi/driver_power.inc"

; stage:0 fenced/no effects,1 command-stop posted,2 position-stop posted,
; 3 PAUSED,4 restore posted/VERIFY,5 verified. One write group per step.
%macro HP_ENTER 0
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
%endmacro
%macro HP_LEAVE 0
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 cld
 ret
%endmacro
%macro HP_HOOKS 1
 %1 hda_transport_power_gate
 %1 hda_session_power_gate
 %1 hda_route_program_power_gate
 %1 hda_output_power_gate
 %1 hda_pcm_power_gate
 %1 hda_input_power_gate
 %1 hda_backend_power_gate
%endmacro
%macro HP_HOOK_CHECK 1
 lea rax,[rel reinit_power_hda_gate]
 cmp [rel %1],rax
 jne .bad
%endmacro
%macro HP_HOOK_EMPTY 1
 cmp qword [rel %1],0
 jne .bad
%endmacro
%macro HP_HOOK_SET 1
 lea rax,[rel reinit_power_hda_gate]
 mov [rel %1],rax
%endmacro

; R12=backend, RBX=graph, R13=output,R14=PCM on success. RAM identity first;
; no MMIO, even on an ownership/configuration/generation change.
reinit_power_hda_identity:
 sub rsp,8
 mov r12,[rel hdpw_driver+dp_driver.owner]
 test r12,r12
 jz .bad
 mov rax,[rel hdpw_driver+dp_driver.generation_ptr]
 mov rdx,[rel hdpw_driver+dp_driver.generation]
 cmp [rax],rdx
 jne .bad
 mov rax,[rel hdpw_epoch]
 cmp [r12+hda_backend.epoch],rax
 jne .bad
 lea rsi,[r12+hda_backend.saved]
 lea rdi,[rel hdpw_saved]
 mov edx,576
 call memcmp
 test eax,eax
 jnz .bad
 call hdab_owned
 test eax,eax
 jnz .bad
 cmp qword [rel hdpw_context],0
 je .good
 HP_HOOKS HP_HOOK_CHECK
.good:
 xor eax,eax
 jmp .out
.bad:
 mov rax,DP_CHANGED
.out:
 add rsp,8
 ret

; Every actual mutating native entry is fenced before touching its context.
; Private VERIFY owns only one attributed transport request, never other work.
reinit_power_hda_gate:
 HP_ENTER
 mov r15,rdi
 call reinit_power_hda_identity
 test rax,rax
 jnz .out
 cmp byte [rel hdpw_internal],1
 jne .ordinary
 cmp r15,[rbx+hda_graph.transport]
 jne .bad
 mov rax,[rel hdpw_context]
 cmp dword [rax+dp_context.phase],DP_VERIFY
 jne .bad
 cmp byte [rax+dp_context.busy],1
 jne .bad
 mov rdx,[rel hdpw_token]
 cmp [rax+dp_context.token],rdx
 jne .bad
 cmp dword [rel hdpw_stage],4
 jne .bad
 xor eax,eax
 jmp .out
.ordinary:
 ; Attachment never grants another native context this controller's lifetime.
 cmp r15,r12
 je .member
 cmp r15,rbx
 je .member
 cmp r15,r13
 je .member
 cmp r15,r14
 je .member
 cmp r15,[rbx+hda_graph.transport]
 je .member
 cmp r15,[r12+hda_backend.program]
 je .member
 cmp r15,[r12+hda_backend.input]
 je .member
 lea rax,[r12+hda_backend.device]
 cmp r15,rax
 je .member
 lea rax,[r14+hda_pcm.device]
 cmp r15,rax
 jne .bad
.member:
 mov rdi,[rel hdpw_context]
 mov rsi,[rdi+dp_context.token]
 mov rdx,r12
 mov rcx,[rel hdpw_driver+dp_driver.generation]
 call reinit_power_admit
 jmp .out
.bad:
 mov rax,DP_CHANGED
.out:
 HP_LEAVE

; Public exact issued-token admission for the trusted controller caller.
; RDI=attached context, RSI=issued token. Existing owner/generation are pinned.
reinit_power_hda_admit:
 HP_ENTER
 mov rbp,rdi
 mov r15,rsi
 cmp rbp,[rel hdpw_context]
 jne .bad
 test rbp,rbp
 jz .bad
 call reinit_power_hda_identity
 test rax,rax
 jnz .out
 mov rdi,rbp
 mov rsi,r15
 mov rdx,r12
 mov rcx,[rel hdpw_driver+dp_driver.generation]
 call reinit_power_admit
 jmp .out
.bad:
 mov rax,DP_CHANGED
.out:
 HP_LEAVE

; Check the native software subset. No active work is discarded or rewritten.
reinit_power_hda_idle:
 xor r9d,r9d
reinit_power_hda_idle_pending:
 cmp dword [r12+hda_backend.phase],HDAB_READY
 jne .bad
 cmp dword [r14+hda_pcm.phase],HDPCM_IDLE
 jne .bad
 cmp dword [r14+hda_pcm.opened],0
 jne .bad
 cmp dword [r14+hda_pcm.started],0
 jne .bad
 cmp qword [r14+hda_pcm.session],0
 jne .bad
 cmp dword [r14+hda_pcm.queued],0
 jne .bad
 cmp dword [r13+hda_output.state],HDAO_READY
 jne .bad
 cmp dword [rbx+hda_graph.phase],HDAGS_DONE
 jne .bad
 cmp dword [rbx+hda_graph.command_ready],1
 jne .bad
 mov rax,[r12+hda_backend.program]
 cmp [rbx+hda_graph.command_owner],rax
 jne .bad
 cmp dword [rax+hda_route_program.phase],HDAP_READY
 jne .bad
 cmp dword [rax+hda_route_program.request],0
 jne .bad
 mov rax,[r12+hda_backend.input]
 test rax,rax
 jz .transport
 cmp dword [r12+hda_backend.input_state],3
 jne .bad
 cmp [rbx+hda_graph.input_owner],rax
 jne .bad
 cmp dword [rbx+hda_graph.input_ready],1
 jne .bad
 cmp dword [rax+hda_route_program.phase],HDAP_READY
 jne .bad
 cmp dword [rax+hda_route_program.request],0
 jne .bad
 cmp dword [rax+hda_input.stream_phase],HDI_IDLE
 jne .bad
 cmp dword [rax+hda_input.ready_bytes],0
 jne .bad
.transport:
 mov rax,[rbx+hda_graph.transport]
 cmp [rax+hda_transport.pending],r9d
 jne .bad
 cmp dword [rax+hda_transport.fault],0
 jne .bad
 xor eax,eax
 ret
.bad:
 mov rax,DP_UNSUPPORTED
 ret

; Stable native controller state, never a reset/reinitialization recipe.
; Exact saved GCAP/GCTL, ring bases/sizes, RINTCNT, SSYNC, SD descriptors.
; R15=MMIO. Read supported registers at their architectural widths.
reinit_power_hda_retained:
 mov r15,[r13+hda_output.mmio]
 mov ax,[r15]
 cmp ax,[rel hdpw_gcap]
 jne .bad
 mov eax,[r15+8]
 cmp eax,1                            ; link remains up, unsolicited disabled
 jne .bad
 cmp dword [r15+0x20],0               ; polling only, no installed IRQ work
 jne .bad
 cmp dword [r15+0x38],0
 jne .bad
 test word [r15+0x68],1               ; no immediate command in flight
 jnz .bad
 test byte [r15+0x4d],1
 jnz .bad
 test byte [r15+0x5d],4
 jnz .bad
 mov eax,[r15+0x40]
 cmp eax,[rel hdpw_corb_base]
 jne .bad
 mov eax,[r15+0x44]
 cmp eax,[rel hdpw_corb_base+4]
 jne .bad
 mov eax,[r15+0x50]
 cmp eax,[rel hdpw_rirb_base]
 jne .bad
 mov eax,[r15+0x54]
 cmp eax,[rel hdpw_rirb_base+4]
 jne .bad
 mov al,[r15+0x4e]
 cmp al,[rel hdpw_corb_size]
 jne .bad
 mov al,[r15+0x5e]
 cmp al,[rel hdpw_rirb_size]
 jne .bad
 mov ax,[r15+0x5a]
 cmp ax,[rel hdpw_rintcnt]
 jne .bad
 mov eax,[r15+0x74]
 cmp eax,[rel hdpw_position+4]
 jne .bad
 mov eax,[r15+0x70]
 and eax,~1
 mov edx,[rel hdpw_position]
 and edx,~1
 cmp eax,edx
 jne .bad
 ; All represented controller streams must remain idle with IRQ enables clear.
 xor ecx,ecx
.stream:
 mov eax,ecx
 shl eax,5
 test byte [r15+rax+0x80],0x1f
 jnz .bad
 inc ecx
 cmp ecx,[rel hdpw_streams]
 jb .stream
 lea rdi,[r15+0x80]
 lea rsi,[rel hdpw_sd]
 mov edx,[rel hdpw_streams]
 shl edx,5
 sub rsp,8
 call memcmp
 add rsp,8
 test eax,eax
 jnz .bad
 xor eax,eax
 ret
.bad:
 mov rax,DP_FAILED
 ret

; No unconsumed native command or asynchronous response may be hidden by stop.
reinit_power_hda_empty:
 mov r8,[rbx+hda_graph.transport]
 cmp dword [r8+hda_transport.pending],0
 jne .bad
 mov eax,[r8+hda_transport.corb_wp]
 cmp eax,255
 ja .bad
 cmp [r15+0x48],ax
 jne .bad
 cmp [r15+0x4a],ax
 jne .bad
 mov eax,[r8+hda_transport.rirb_rp]
 cmp eax,255
 ja .bad
 cmp [r15+0x58],ax
 jne .bad
 xor eax,eax
 ret
.bad:
 mov rax,DP_FAILED
 ret

; Exact original enforcing DID3 serial, followed by RAM identity revalidation.
reinit_power_hda_receipt:
 sub rsp,8
 call hdab_receipt
 test eax,eax
 jnz .bad
 call reinit_power_hda_identity
 jmp .out
.bad:
 mov rax,DP_CHANGED
.out:
 add rsp,8
 ret

; Capture ONLY actual GET readbacks from the completed native route script.
; Retain command/mask/expected/kind; SETs and provisional fact queries never run.
; RDI=program. Bounded two scripts <=512 entries, all bytes copied to our sidecar.
reinit_power_hda_queries:
 mov ecx,[rdi+hda_route_program.count]
 test ecx,ecx
 jz .bad
 cmp ecx,HDAP_MAX
 ja .bad
 lea rsi,[rdi+hda_route_program.script]
.next:
 mov eax,[rsi]
 and eax,0xf0000
 cmp eax,0xf0000
 je .get
 cmp eax,0xa0000
 je .get
 cmp eax,0xb0000
 jne .skip
.get:
 mov eax,[rsi+12]
 test eax,eax
 jz .copy
 cmp eax,-1
 jne .skip
.copy:
 ; The same GET can verify an intermediate disabled pin and its final enabled
 ; value. Only the LAST native readback describes the retained useful route.
 xor r9d,r9d
 lea r8,[rel hdpw_queries]
.find:
 cmp r9d,[rel hdpw_query_count]
 jae .append
 mov eax,r9d
 shl eax,4
 mov edx,[rsi]
 cmp [r8+rax],edx
 je .store
 inc r9d
 jmp .find
.append:
 mov eax,[rel hdpw_query_count]
 cmp eax,512
 jae .bad
 inc dword [rel hdpw_query_count]
 shl eax,4
.store:
 mov rdx,[rsi]
 mov [r8+rax],rdx
 mov rdx,[rsi+8]
 mov [r8+rax+8],rdx
.skip:
 add rsi,16
 dec ecx
 jnz .next
 xor eax,eax
 ret
.bad:
 mov rax,DP_UNSUPPORTED
 ret

; register(RDI=initialized dp_context, RSI=current native backend,
; RDX=pinned controller-owned full64 generation word, RCX=expected nonzero).
; Single attachment, no detach/rebind. Existing graph lease/epoch also pinned.
reinit_power_hda_register:
 HP_ENTER
 mov r15,rdi
 mov r12,rsi
 mov rbp,rdx
 cmp qword [rel hdpw_context],0
 jne .bad
 test r15,r15
 jz .bad
 test r12,r12
 jz .bad
 test rbp,rbp
 jz .bad
 test rcx,rcx
 jz .bad
 cmp [rbp],rcx
 jne .bad
 cmp dword [r15+dp_context.version],DP_VERSION
 jne .bad
 cmp dword [r15+dp_context.state],DP_RUNNING
 jne .bad
 HP_HOOKS HP_HOOK_EMPTY
 mov [rel hdpw_driver+dp_driver.owner],r12
 mov [rel hdpw_driver+dp_driver.generation_ptr],rbp
 mov [rel hdpw_driver+dp_driver.generation],rcx
 ; WDATA is org0: publish the live trusted callback, never an image offset.
 lea rax,[rel reinit_power_hda_callback]
 mov [rel hdpw_driver+dp_driver.callback],rax
 mov rax,[r12+hda_backend.epoch]
 mov [rel hdpw_epoch],rax
 lea rsi,[r12+hda_backend.saved]
 lea rdi,[rel hdpw_saved]
 mov edx,576
 call memcpy
 call reinit_power_hda_identity
 test rax,rax
 jnz .bad
 call hdab_admit
 test eax,eax
 jnz .bad
 call reinit_power_hda_idle
 test rax,rax
 jnz .bad
 mov r8,[r13+hda_output.mmio]
 cmp dword [r8+8],1
 jne .bad
 cmp byte [r8+0x4c],2
 jne .bad
 cmp byte [r8+0x5c],2
 jne .bad
 mov ax,[r8]
 mov [rel hdpw_gcap],ax
 movzx eax,ax
 mov ecx,eax
 shr ecx,8
 and ecx,15
 mov edx,eax
 shr edx,12
 and edx,15
 add ecx,edx
 shr eax,3
 and eax,31
 add ecx,eax
 test ecx,ecx
 jz .bad
 cmp ecx,30
 ja .bad
 mov [rel hdpw_streams],ecx
 mov eax,[r8+0x40]
 mov edx,[r8+0x44]
 shl rdx,32
 or rax,rdx
 test rax,rax
 jz .bad
 test al,127
 jnz .bad
 mov [rel hdpw_corb_base],rax
 mov edx,[r8+0x50]
 mov r9d,[r8+0x54]
 shl r9,32
 or rdx,r9
 test rdx,rdx
 jz .bad
 test dl,127
 jnz .bad
 cmp rax,rdx
 je .bad
 mov [rel hdpw_rirb_base],rdx
 mov al,[r8+0x4e]
 mov [rel hdpw_corb_size],al
 and al,3
 cmp al,2
 jne .bad
 mov al,[r8+0x5e]
 mov [rel hdpw_rirb_size],al
 and al,3
 cmp al,2
 jne .bad
 mov ax,[r8+0x5a]
 mov [rel hdpw_rintcnt],ax
 mov eax,[r8+0x70]
 mov edx,[r8+0x74]
 shl rdx,32
 or rax,rdx
 mov [rel hdpw_position],rax
 ; Snapshot defined stream descriptor window only, read-only.
 lea rsi,[r8+0x80]
 lea rdi,[rel hdpw_sd]
 mov edx,ecx
 shl edx,5
 call memcpy
 mov rbp,r15                       ; retain plan across retained/MMIO helper
 call reinit_power_hda_retained
 test rax,rax
 jnz .bad
 call reinit_power_hda_empty
 test rax,rax
 jnz .bad
 mov dword [rel hdpw_query_count],0
 mov rdi,[r12+hda_backend.program]
 call reinit_power_hda_queries
 test rax,rax
 jnz .bad
 mov rdi,[r12+hda_backend.input]
 test rdi,rdi
 jz .queries_done
 call reinit_power_hda_queries
 test rax,rax
 jnz .bad
.queries_done:
 cmp dword [rel hdpw_query_count],0
 je .bad
 mov rdi,rbp
 lea rsi,[rel hdpw_driver]
 call reinit_power_register
 test rax,rax
 jnz .out
 ; No callback/reentry between declaration acceptance and gate publication.
 mov [rel hdpw_context],rbp
 HP_HOOKS HP_HOOK_SET
 xor eax,eax
 jmp .out
.bad:
 mov rax,DP_UNSUPPORTED
.out:
 HP_LEAVE

; Callback uses exact immutable owner, context, full64 generation and operation
; token; after any changed identity there are NO writes to foreign MMIO.
reinit_power_hda_callback:
 HP_ENTER
 cmp rdi,[rel hdpw_driver+dp_driver.owner]
 jne .changed
 cmp rcx,[rel hdpw_context]
 jne .changed
 test rcx,rcx
 jz .changed
 cmp r8,[rel hdpw_driver+dp_driver.generation]
 jne .changed
 cmp byte [rcx+dp_context.busy],1
 jne .changed
 cmp esi,[rcx+dp_context.phase]
 jne .changed
 cmp rdx,[rcx+dp_context.token]
 jne .changed
 mov ebp,esi
 mov r15,rdx
 call reinit_power_hda_identity
 test rax,rax
 jnz .changed
 cmp ebp,DP_FENCE
 je .fence
 cmp r15,[rel hdpw_token]
 jne .changed
 cmp ebp,DP_STOP
 je .stop
 cmp ebp,DP_RESTORE
 je .restore
 cmp ebp,DP_VERIFY
 je .verify
 jmp .changed
.fence:
 cmp r15,[rel hdpw_token]
 jbe .changed
 mov [rel hdpw_token],r15
 mov dword [rel hdpw_stage],0
 mov dword [rel hdpw_cursor],0
 mov dword [rel hdpw_request],0
 mov dword [rel hdpw_polls],0
 mov edx,DP_ACK_FENCED
 xor eax,eax
 jmp .out
.stop:
 cmp dword [rel hdpw_stage],0
 jne .stop_readback
 call reinit_power_hda_idle
 test rax,rax
 jnz .unsupported
 call reinit_power_hda_receipt
 test rax,rax
 jnz .changed
 call reinit_power_hda_retained
 test rax,rax
 jnz .unsupported
 call reinit_power_hda_empty
 test rax,rax
 jnz .unsupported
 cmp byte [r15+0x4c],2
 jne .unsupported
 cmp byte [r15+0x5c],2
 jne .unsupported
 mov eax,[r15+0x70]
 cmp eax,[rel hdpw_position]
 jne .unsupported
 mov dword [rel hdpw_stage],1        ; uncertainty begins BEFORE first HW store
 mov byte [r15+0x4c],0
 mov byte [r15+0x5c],0
 jmp .pending                      ; never acknowledge posted stores as stop
.stop_readback:
 cmp dword [rel hdpw_stage],1
 je .command_readback
 cmp dword [rel hdpw_stage],2
 jne .failed
.command_readback:
 call reinit_power_hda_receipt
 test rax,rax
 jnz .changed
 call reinit_power_hda_retained
 test rax,rax
 jnz .failed
 call reinit_power_hda_empty
 test rax,rax
 jnz .failed
 cmp byte [r15+0x4c],0
 jne .pending
 cmp byte [r15+0x5c],0
 jne .pending
 cmp dword [rel hdpw_stage],1
 jne .position_readback
 ; Position base/enable is touched only after BOTH command engines read STOP.
 mov dword [rel hdpw_stage],2
 and dword [r15+0x70],~1
 jmp .pending
.position_readback:
 test byte [r15+0x70],1
 jnz .pending
 mov dword [rel hdpw_stage],3
 mov edx,DP_ACK_FENCED|DP_ACK_DRAINED|DP_ACK_IRQ_STOPPED|DP_ACK_DMA_STOPPED
 xor eax,eax
 jmp .out
.restore:
 cmp dword [rel hdpw_stage],3
 jne .restore_readback
 call reinit_power_hda_receipt
 test rax,rax
 jnz .changed
 call reinit_power_hda_idle
 test rax,rax
 jnz .failed
 call reinit_power_hda_retained
 test rax,rax
 jnz .failed
 call reinit_power_hda_empty
 test rax,rax
 jnz .failed
 cmp byte [r15+0x4c],0
 jne .failed
 cmp byte [r15+0x5c],0
 jne .failed
 test byte [r15+0x70],1
 jnz .failed
 mov dword [rel hdpw_stage],4
 mov eax,[rel hdpw_position]
 mov [r15+0x70],eax
 mov byte [r15+0x5c],2              ; responses before outbound commands
 mov byte [r15+0x4c],2
 jmp .pending
.restore_readback:
 cmp dword [rel hdpw_stage],4
 jne .failed
 call reinit_power_hda_retained
 test rax,rax
 jnz .failed
 call reinit_power_hda_empty
 test rax,rax
 jnz .failed
 call reinit_power_hda_running_regs
 test rax,rax
 jnz .pending
 mov edx,DP_ACK_FENCED
 xor eax,eax
 jmp .out
.verify:
 cmp dword [rel hdpw_stage],0
 je .refused_verify                ; STOP refused without an effect
 cmp dword [rel hdpw_stage],4
 jne .failed
 call reinit_power_hda_receipt
 test rax,rax
 jnz .changed
 call reinit_power_hda_idle_verify
 test rax,rax
 jnz .failed
 call reinit_power_hda_retained
 test rax,rax
 jnz .failed
 call reinit_power_hda_running_regs
 test rax,rax
 jnz .failed
 inc dword [rel hdpw_polls]
 cmp dword [rel hdpw_polls],4096
 ja .failed
 mov eax,[rel hdpw_cursor]
 cmp eax,[rel hdpw_query_count]
 jae .verified
 shl eax,4
 lea rbp,[rel hdpw_queries]
 add rbp,rax
 mov rdi,[rbx+hda_graph.transport]
 cmp dword [rel hdpw_request],0
 jne .take
 call reinit_power_hda_empty
 test rax,rax
 jnz .failed
 mov rdi,[rbx+hda_graph.transport]
 mov esi,[rbp]
 mov byte [rel hdpw_internal],1
 call hda_corb_queue
 mov byte [rel hdpw_internal],0
 test rax,rax
 js .failed
 jnz .pending
 mov dword [rel hdpw_request],1
 jmp .pending
.take:
 cmp dword [rdi+hda_transport.pending],1
 jne .failed
 mov eax,[rbp]
 shr eax,28
 cmp [rdi+hda_transport.codec],eax
 jne .failed
 lea rsi,[rel hdpw_response]
 mov byte [rel hdpw_internal],1
 call hda_rirb_take
 mov byte [rel hdpw_internal],0
 test rax,rax
 js .failed
 jnz .pending
 mov eax,[rel hdpw_response]
 cmp dword [rbp+12],-1
 je .power
 and eax,[rbp+4]
 cmp eax,[rbp+8]
 jne .failed
 jmp .next
.power:
 test eax,~0x200                    ; actual D0, no error/settings-reset
 jnz .failed
.next:
 mov dword [rel hdpw_request],0
 inc dword [rel hdpw_cursor]
 jmp .pending
.verified:
 call reinit_power_hda_empty
 test rax,rax
 jnz .failed
 call hdab_admit                    ; original usable PCM/route/receipt guards
 test eax,eax
 jnz .failed
 mov dword [rel hdpw_stage],5
 jmp .ready
.refused_verify:
 call reinit_power_hda_receipt
 test rax,rax
 jnz .changed
 call hdab_admit                    ; still-original active/idle capability
 test eax,eax
 jnz .failed
.ready:
 mov edx,DP_ACK_FENCED|DP_ACK_READY
 xor eax,eax
 jmp .out
.changed:
 mov rax,DP_CHANGED
 jmp .error
.unsupported:
 mov rax,DP_UNSUPPORTED
 jmp .error
.failed:
 mov rax,DP_FAILED
.error:
 xor edx,edx
 jmp .out
.pending:
 mov eax,DP_PENDING
 xor edx,edx
.out:
 HP_LEAVE

; During VERIFY the adapter's attributed request is the only permitted pending
; command; all other idle obligations still hold. Don't edit native flags.
reinit_power_hda_idle_verify:
 mov r9d,[rel hdpw_request]
 cmp r9d,1
 ja .bad
 jmp reinit_power_hda_idle_pending
.bad:
 mov rax,DP_FAILED
 ret
reinit_power_hda_running_regs:
 cmp byte [r15+0x4c],2
 jne .bad
 cmp byte [r15+0x5c],2
 jne .bad
 mov eax,[r15+0x70]
 cmp eax,[rel hdpw_position]
 jne .bad
 xor eax,eax
 ret
.bad:
 mov rax,DP_FAILED
 ret

%macro WDATA_svc_reinit_power_hda 0
 align 8
hdpw_context: dq 0
hdpw_epoch: dq 0
hdpw_token: dq 0
hdpw_driver:
 dd DP_VERSION,DP_AUDIO
 dq 0,0,0,0                        ; callback is set with LEA at registration
 dd 0,DP_CAP_IRQ|DP_CAP_DMA
hdpw_stage: dd 0
hdpw_streams: dd 0
hdpw_query_count: dd 0
hdpw_cursor: dd 0
hdpw_request: dd 0
hdpw_response: dd 0
hdpw_polls: dd 0
hdpw_internal: db 0
hdpw_corb_size: db 0
hdpw_rirb_size: db 0
 align 2
hdpw_gcap: dw 0
hdpw_rintcnt: dw 0
 align 8
hdpw_corb_base: dq 0
hdpw_rirb_base: dq 0
hdpw_position: dq 0
hdpw_saved: times 576 db 0
hdpw_sd: times 960 db 0
hdpw_queries: times 8192 db 0
%endmacro
WDATA_DEFER WDATA_svc_reinit_power_hda
