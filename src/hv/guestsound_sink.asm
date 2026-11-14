;; MODULE hv/guestsound_sink
;; LAYER 5
;; EXPORTS guestsound_sink_begin, guestsound_sink_service, guestsound_sink_cancel, guestsound_sink_finish
;; IMPORTS hv/guestsound, hv/guest_power, snd/mix_submit, media/pcm_stream, core/lib/mem
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Explicit, already-open, exclusively owned ABI-v2 native playback sink.
; No discover/open/start/drain/close, DMA or clock. All pointers are trusted,
; stable mapped CPU spans, serialized by their native owner on the resident BSP.
; The owner increments binding.epoch on ANY native lifetime/identity change and
; guarantees the stream is empty at begin (IDLE alone cannot prove that).
; Submit must copy/consume its accepted prefix before return, as mix_submit.
; Keep the ENTIRE context pinned until finish accepts actual owner quiescence.
; ABI-v2 supplies neither an epoch nor generic drain/quiescence: the owner must
; obtain them from its real backend lifecycle, never from this adapter's counts.
; Receipt is an owner assertion of observed quiescence, not an authentication
; token. No automatic polling, stop receipt, period conversion or audible credit.
; SysV preserved GPRs/RSP and caller DF. Return -1 refusal/fault/cancellation;
; service0 no accepted frames,1 accepted prefix,2 all frames observed retired.
; finish0 success,1 aborted. Neither service2 nor IDLE completes guest TX.

struc gs_sink_binding
 .device: resq 1
 .handle: resq 1
 .epoch: resq 1
 .rate: resd 1
 .format: resd 1
 .channels: resd 1
 .direction: resd 1
 .gain: resd 1
 .reserved: resd 1
endstruc
struc gs_sink_receipt
 .version: resd 1                 ;1
 .kind: resd 1                    ;2: actual quiescence of saved native epoch
 .device: resq 1
 .handle: resq 1
 .epoch: resq 1
 .generation: resq 1
 .ticket: resq 1
 .accepted: resq 1                ;exact adapter accepted whole frames
 .retired: resq 1                 ;observed absolute native frame cursor
 .abort: resd 1                   ;0 success,1 cancelled/uncertain cleanup
 .reserved: resd 1
endstruc
struc gs_sink
 .version: resd 1                 ;1, all other bytes initially zero
 .state: resd 1                   ;0 empty,1 active,2 cancel,3 fault,4 done,5 abort
 .binding: resq 1
 .saved: resb gs_sink_binding_size
 .ops: resq 1
 .info: resq 1
 .priv: resq 1
 .submit: resq 1
 .position: resq 1
 .status: resq 1
 .baseline: resq 1
 .last: resq 1
 .total: resq 1
 .generation: resq 1
 .ticket: resq 1
 .sink: resb snd_mix_sink_size
 .block: resb snd_mix_block_size
 .stream: resb snd_mix_stream_size
 .status_buf: resb snd_status_size
 .feeder: resb media_pcm_stream_size
 .pcm: resb 4096
 .ring: resb 16384
 .output: resb 4096
endstruc

%macro GSS_ENTER 0
 pushfq
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 mov rbx,rdi
 mov r12,rsi
%endmacro
%macro GSS_LEAVE 0
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 popfq
 ret
%endmacro

; Valid CPU span outside the guest reservation, device-private state and ctx.
gss_external:
 sub rsp,8
 call guestsound_native_span
 add rsp,8
 test eax,eax
 jz .out
 lea rdx,[rbx+gs_sink_size]
 cmp rdi,rdx
 jae .out
 lea rdx,[rdi+rsi]
 cmp rbx,rdx
 jae .out
 xor eax,eax
.out:
 ret
gss_context:
 mov rdi,rbx
 mov esi,gs_sink_size
 sub rsp,8
 call guestsound_native_span
 add rsp,8
 test eax,eax
 jz .out
 test bl,7
 jnz .bad
 cmp dword [rbx+gs_sink.version],1
 je .out
.bad:
 xor eax,eax
.out:
 ret

; Saved stable mapped binding/device/vtable identity, checked before EVERY op.
gss_binding:
 mov rdi,[rbx+gs_sink.binding]
 lea rsi,[rbx+gs_sink.saved]
 mov ecx,gs_sink_binding_size/8
 repe cmpsq
 jne .bad
 mov rdi,[rbx+gs_sink.saved+gs_sink_binding.device]
 cmp dword [rdi+dev.class],CLASS_SOUND
 jne .bad
 cmp dword [rdi+dev.health],HEALTH_OK
 jne .bad
 mov rax,[rbx+gs_sink.ops]
 cmp [rdi+dev.ops],rax
 jne .bad
 mov rdx,[rbx+gs_sink.info]
 cmp [rdi+dev.info],rdx
 jne .bad
 mov rdx,[rbx+gs_sink.priv]
 cmp [rdi+dev.priv],rdx
 jne .bad
 mov rdx,[rbx+gs_sink.submit]
 cmp [rax+snd_ops.submit],rdx
 jne .bad
 mov rdx,[rbx+gs_sink.position]
 cmp [rax+snd_ops.position],rdx
 jne .bad
 mov rdx,[rbx+gs_sink.status]
 cmp [rax+snd_ops.status],rdx
 jne .bad
 mov eax,1
 ret
.bad:
 xor eax,eax
 ret
gss_authority:
 sub rsp,8
 call gss_binding
 test eax,eax
 jz .out
 cmp dword [rel gs_status],15
 jne .no
 lea rdi,[rbx+gs_sink.feeder]
 call guestsound_native_current
 jmp .out
.no:
 xor eax,eax
.out:
 add rsp,8
 ret

guestsound_sink_begin:
 HV_POWER_WORK guestsound_sink_begin, -1, hv_guest_power_io_admit
 GSS_ENTER
 call gss_context
 test eax,eax
 jz .bad
 ; Caller initializes version only; no old custody can be silently reset.
 cmp dword [rbx+gs_sink.state],0
 jne .bad
 lea rdi,[rbx+8]
 mov ecx,(gs_sink_size-8)/8
 xor eax,eax
 repe scasq
 jne .bad
 mov rdi,r12
 mov esi,gs_sink_binding_size
 call gss_external
 test eax,eax
 jz .bad
 cmp qword [r12+gs_sink_binding.handle],0
 je .bad
 cmp qword [r12+gs_sink_binding.epoch],0
 je .bad
 cmp dword [r12+gs_sink_binding.rate],48000
 jne .bad
 cmp dword [r12+gs_sink_binding.format],SNDFMT_S16LE
 jne .bad
 cmp dword [r12+gs_sink_binding.channels],2
 jne .bad
 cmp dword [r12+gs_sink_binding.direction],SND_DIR_PLAY
 jne .bad
 cmp dword [r12+gs_sink_binding.gain],32768
 ja .bad
 cmp dword [r12+gs_sink_binding.reserved],0
 jne .bad
 mov r13,[r12+gs_sink_binding.device]
 mov rdi,r13
 mov esi,dev_size
 call gss_external
 test eax,eax
 jz .bad
 cmp dword [r13+dev.class],CLASS_SOUND
 jne .bad
 cmp dword [r13+dev.health],HEALTH_OK
 jne .bad
 mov r14,[r13+dev.ops]
 mov rdi,r14
 mov esi,snd_ops_size
 call gss_external
 test eax,eax
 jz .bad
 mov rdi,[r13+dev.info]
 mov esi,snd_info_size
 call gss_external
 test eax,eax
 jz .bad
 cmp qword [r14+snd_ops.submit],0
 je .bad
 cmp qword [r14+snd_ops.position],0
 je .bad
 cmp qword [r14+snd_ops.status],0
 je .bad
 call guestsound_current
 test eax,eax
 jz .bad
 cmp dword [rel gs_stream],3
 jne .bad
 cmp dword [rel gs_status],15
 jne .bad
 cmp byte [rel gs_pending],1
 jne .bad
 cmp byte [rel gs_offered],0
 jne .bad
 mov dword [rbx+gs_sink.state],3 ; provisional failure retains storage
 mov [rbx+gs_sink.binding],r12
 lea rdi,[rbx+gs_sink.saved]
 mov rsi,r12
 mov ecx,gs_sink_binding_size/8
 rep movsq
 mov [rbx+gs_sink.ops],r14
 mov rax,[r13+dev.info]
 mov [rbx+gs_sink.info],rax
 mov rax,[r13+dev.priv]
 mov [rbx+gs_sink.priv],rax
 mov rax,[r14+snd_ops.submit]
 mov [rbx+gs_sink.submit],rax
 mov rax,[r14+snd_ops.position]
 mov [rbx+gs_sink.position],rax
 mov rax,[r14+snd_ops.status]
 mov [rbx+gs_sink.status],rax
 mov eax,[rel hv_linux_start_gen]
 mov [rbx+gs_sink.generation],rax
 mov rax,[rel gs_ticket]
 mov [rbx+gs_sink.ticket],rax
 ; Query actual empty-stream baseline. IDLE is necessary, never quiescence.
 call gss_binding
 test eax,eax
 jz .bad
 mov rdi,r13
 mov rsi,[r12+gs_sink_binding.handle]
 lea rdx,[rbx+gs_sink.status_buf]
 call [rbx+gs_sink.status]
 test rax,rax
 jnz .bad
 cmp dword [rbx+gs_sink.status_buf+snd_status.state],SND_STATE_IDLE
 jne .bad
 call gss_binding
 test eax,eax
 jz .bad
 mov rdi,r13
 mov rsi,[r12+gs_sink_binding.handle]
 call [rbx+gs_sink.position]
 test rax,rax
 js .bad
 cmp rax,[rbx+gs_sink.status_buf+snd_status.frames]
 jne .bad
 mov [rbx+gs_sink.baseline],rax
 mov [rbx+gs_sink.last],rax
 mov ecx,[rel gs_pcm_bytes]
 shr ecx,2
 mov [rbx+gs_sink.total],rcx
 add rax,rcx
 jc .bad
 js .bad
 ; Existing offer does the canonical private->native mixer copy and validates
 ; the real feeder. This adapter never services its ring or invents grants.
 lea rbp,[rbx+gs_sink.feeder]
 mov dword [rbp+media_pcm_stream.version],1
 mov rax,[rbx+gs_sink.generation]
 mov [rbp+media_pcm_stream.generation],rax
 mov rax,[rbx+gs_sink.ticket]
 mov [rbp+media_pcm_stream.epoch],rax
 lea rax,[rbx+gs_sink.pcm]
 mov [rbp+media_pcm_stream.pcm],rax
 mov qword [rbp+media_pcm_stream.capacity],4096
 mov eax,[rel gs_pcm_bytes]
 mov [rbp+media_pcm_stream.bytes],rax
 mov [rbp+media_pcm_stream.frames],rcx
 lea rax,[rbx+gs_sink.ring]
 mov [rbp+media_pcm_stream.ring],rax
 mov qword [rbp+media_pcm_stream.ring_bytes],16384
 mov dword [rbp+media_pcm_stream.rate],48000
 mov dword [rbp+media_pcm_stream.channels],2
 mov dword [rbp+media_pcm_stream.frame_bytes],4
 mov dword [rbp+media_pcm_stream.format],1
 call gss_binding
 test eax,eax
 jz .bad
 mov rdi,rbp
 call guestsound_offer
 test rax,rax
 jnz .bad
 ; Accepted-frame staging and exact unaccepted suffix use existing mix_submit.
 lea rbp,[rbx+gs_sink.sink]
 mov [rbp+snd_mix_sink.device],r13
 mov rax,[r12+gs_sink_binding.handle]
 mov [rbp+snd_mix_sink.handle],rax
 mov dword [rbp+snd_mix_sink.rate],48000
 mov dword [rbp+snd_mix_sink.channels],2
 lea rbp,[rbx+gs_sink.block]
 lea rax,[rbx+gs_sink.output]
 mov [rbp+snd_mix_block.dst],rax
 mov qword [rbp+snd_mix_block.dst_bytes],4096
 lea rax,[rbx+gs_sink.stream]
 mov [rbp+snd_mix_block.streams],rax
 mov dword [rbp+snd_mix_block.stream_count],1
 mov dword [rbp+snd_mix_block.channels],2
 mov dword [rbp+snd_mix_block.rate],48000
 lea rbp,[rbx+gs_sink.stream]
 lea rax,[rbx+gs_sink.pcm]
 mov [rbp+snd_mix_stream.pcm],rax
 mov rax,[rbx+gs_sink.total]
 mov [rbp+snd_mix_stream.frames],rax
 mov eax,[r12+gs_sink_binding.gain]
 mov [rbp+snd_mix_stream.gain],eax
 mov dword [rbp+snd_mix_stream.rate],48000
 mov dword [rbp+snd_mix_stream.channels],2
 call gss_authority
 cmp eax,1
 jne .bad
 mov dword [rbx+gs_sink.state],1
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 GSS_LEAVE

guestsound_sink_service:
 GSS_ENTER
 call gss_context
 test eax,eax
 jz .bad
 cmp dword [rbx+gs_sink.state],1
 jne .bad
 HV_POWER_CHECK hv_guest_power_io_admit, .cancel
 cmp qword [rel hv_guest_power_inflight],64
 jae .cancel
 inc qword [rel hv_guest_power_inflight]
 call gss_service
 dec qword [rel hv_guest_power_inflight]
 jmp .out
.cancel:
 mov dword [rbx+gs_sink.state],2
.bad:
 mov rax,-1
.out:
 GSS_LEAVE

; One status, one position and at most one <=4096-byte submission per call.
gss_service:
 sub rsp,8
 call gss_authority
 cmp eax,1
 jne .cancel
 mov rdi,[rbx+gs_sink.saved+gs_sink_binding.device]
 mov rsi,[rbx+gs_sink.saved+gs_sink_binding.handle]
 lea rdx,[rbx+gs_sink.status_buf]
 call [rbx+gs_sink.status]
 test rax,rax
 jnz .fault
 mov eax,[rbx+gs_sink.status_buf+snd_status.state]
 dec eax
 cmp eax,1
 ja .fault
 mov rax,[rbx+gs_sink.status_buf+snd_status.frames]
 cmp rax,[rbx+gs_sink.last]
 jb .fault
 call gss_authority
 cmp eax,1
 jne .cancel
 mov rdi,[rbx+gs_sink.saved+gs_sink_binding.device]
 mov rsi,[rbx+gs_sink.saved+gs_sink_binding.handle]
 call [rbx+gs_sink.position]
 test rax,rax
 js .fault
 cmp rax,[rbx+gs_sink.status_buf+snd_status.frames]
 jb .fault
 mov rdx,[rbx+gs_sink.baseline]
 add rdx,[rbx+gs_sink.sink+snd_mix_sink.accepted_frames]
 jc .fault
 cmp rax,rdx
 ja .fault
 mov [rbx+gs_sink.last],rax
 call gss_authority
 cmp eax,1
 jne .cancel
 mov rax,[rbx+gs_sink.sink+snd_mix_sink.accepted_frames]
 mov rcx,[rbx+gs_sink.total]
 sub rcx,rax
 jc .fault
 jnz .submit
 mov rax,[rbx+gs_sink.baseline]
 add rax,[rbx+gs_sink.total]
 cmp rax,[rbx+gs_sink.last]
 jne .zero
 mov eax,2
 jmp .out
.submit:
 mov [rbx+gs_sink.block+snd_mix_block.frames],rcx
 lea rdi,[rbx+gs_sink.sink]
 lea rsi,[rbx+gs_sink.block]
 call snd_mix_submit
 mov rbp,rax
 cmp rax,-6                       ; backend refusal accepts NO bytes
 je .post
 test rax,rax
 js .fault
.post:
 call gss_authority
 cmp eax,1
 jne .cancel
 test rbp,rbp
 jle .zero
 mov eax,1
 jmp .out
.zero:
 xor eax,eax
 jmp .out
.fault:
 mov dword [rbx+gs_sink.state],3
 jmp .bad
.cancel:
 mov dword [rbx+gs_sink.state],2
.bad:
 mov rax,-1
.out:
 add rsp,8
 ret

guestsound_sink_cancel:
 GSS_ENTER
 call gss_context
 test eax,eax
 jz .bad
 cmp dword [rbx+gs_sink.state],1
 jne .bad
 mov dword [rbx+gs_sink.state],2
 xor eax,eax
 jmp .out
.bad:
 mov rax,-1
.out:
 GSS_LEAVE

; Caller supplies a stable mapped receipt AFTER its real backend proves the
; saved epoch quiescent. Abort is valid even after identity/admission loss:
; no old backend dereference, guest write, or automatic retry then. Faulted
; uncertain submit counts are not proof of progress; only an ABORT can release.
guestsound_sink_finish:
 GSS_ENTER
 call gss_context
 test eax,eax
 jz .bad
 mov eax,[rbx+gs_sink.state]
 dec eax
 cmp eax,2
 ja .bad
 mov rdi,r12
 mov esi,gs_sink_receipt_size
 call gss_external
 test eax,eax
 jz .bad
 cmp dword [r12+gs_sink_receipt.version],1
 jne .bad
 cmp dword [r12+gs_sink_receipt.kind],2
 jne .bad
 cmp dword [r12+gs_sink_receipt.reserved],0
 jne .bad
 lea rdi,[r12+gs_sink_receipt.device]
 lea rsi,[rbx+gs_sink.saved]
 mov ecx,3
 repe cmpsq
 jne .bad
 mov rax,[rbx+gs_sink.generation]
 cmp [r12+gs_sink_receipt.generation],rax
 jne .bad
 mov rax,[rbx+gs_sink.ticket]
 cmp [r12+gs_sink_receipt.ticket],rax
 jne .bad
 mov rax,[rbx+gs_sink.sink+snd_mix_sink.accepted_frames]
 cmp [r12+gs_sink_receipt.accepted],rax
 jne .bad
 cmp dword [r12+gs_sink_receipt.abort],1
 je .abort
 cmp dword [r12+gs_sink_receipt.abort],0
 jne .bad
 cmp dword [rbx+gs_sink.state],1
 jne .bad
 cmp rax,[rbx+gs_sink.total]
 jne .bad
 add rax,[rbx+gs_sink.baseline]
 jc .bad
 cmp rax,[rbx+gs_sink.last]
 jne .bad
 cmp rax,[r12+gs_sink_receipt.retired]
 jne .bad
 HV_POWER_CHECK hv_guest_power_io_admit, .denied
 cmp qword [rel hv_guest_power_inflight],64
 jae .denied
 inc qword [rel hv_guest_power_inflight]
 call gss_authority
 cmp eax,1
 jne .lost
 mov eax,0x8000
 push rbx                         ; private completion clobbers RBX/R12..R15
 push r12
 call guestsound_finish_tx        ; no media-period retirement is fabricated
 pop r12
 pop rbx
 dec qword [rel hv_guest_power_inflight]
 mov dword [rbx+gs_sink.state],4
 xor ebp,ebp
 jmp .scrub
.lost:
 dec qword [rel hv_guest_power_inflight]
.denied:
 mov dword [rbx+gs_sink.state],2
 jmp .bad
.abort:
 mov dword [rbx+gs_sink.state],5
 mov ebp,1
.scrub:
 lea rdi,[rbx+gs_sink.feeder]
 mov ecx,(gs_sink_size-gs_sink.feeder)/8
 xor eax,eax
 rep stosq                        ; only AFTER owner-proved quiescence
 mov eax,ebp
 jmp .out
.bad:
 mov rax,-1
.out:
 GSS_LEAVE

%unmacro GSS_ENTER 0
%unmacro GSS_LEAVE 0
