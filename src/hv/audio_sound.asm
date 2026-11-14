;; MODULE hv/audio_sound
;; LAYER 5
;; EXPORTS pads_attach, pads_step, pads_detach, pads_drain, pads_device
;; IMPORTS hv/audio_domain, snd/core
;; CAPS extension
;; OWNER saga:audio
; ABI-v2 adapter for one VM-owned PAD1 domain. One handle per opened direction;
; separate private queues, no ABI change. The owner still serializes receive,
; adapter and native lifecycle. A nonblocking entry gate rejects reentry/races.
; Only pads_step issues requests/pumps/takes: one <=256B chunk, one reply and
; one next request per opportunity. Ready directions alternate transactions.
; Unknown I/O or shared protocol failure scrubs BOTH queues and never retries.
; Logical close seals only that direction; playback drains accepted PCM before
; closing while capture continues. Last close needs STOP0. No reopen this epoch.
; Actual VM/channel stop must precede detach, and native retirement is separate.
; Same trusted monotonic ms as PAD1 receive; no presentation clock claim.
; Each admitted queue has an absolute2000ms budget, including arbitration and
; EAGAIN. Playback backend drain gets a fresh budget after the final PLAY ack;
; close-drain keeps its original close budget. Capture never renews on EAGAIN.
; Playback Q15 unity32767 is bit exact; gain changes only future admissions.

struc pads_stream
 .handle: resq 1
 .deadline: resq 1
 .frames: resq 1
 .pcm: resq 1
 .gain: resd 1
 .state: resd 1                    ;0 unused,1 live,2 closing,3 closed,4 released
 .length: resd 1
 .offset: resd 1
 .wanted: resd 1                   ;capture request bytes, zero if no request
 .drain: resd 1                    ;playback:0 open,1 sealed,2 backend,3 drained
 .xruns: resd 1
 .reserved: resd 1
endstruc

%macro PADS_RETURN 0
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro
%macro PADS_ENTER 0-1 -11
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 lock bts dword [rel pads_gate],0
 jnc %%entered
 mov rax,%1
 PADS_RETURN
%%entered:
%endmacro
%macro PADS_LEAVE 0
 mov dword [rel pads_gate],0
 PADS_RETURN
%endmacro

; Trusted mapped caller spans only. Reject wrap and either private owner's data.
pads_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 lea rdx,[rel pads_storage_end]
 cmp rdi,rdx
 jae .native
 lea rdx,[rel pads_storage]
 cmp rax,rdx
 ja .bad
.native:
 lea rdx,[rel padn_storage_end]
 cmp rdi,rdx
 jae .ok
 lea rdx,[rel padn_storage]
 cmp rax,rdx
 ja .bad
.ok: clc
 ret
.bad: stc
 ret

; RBX=stream. No caller pointer retained; scrub this direction only.
pads_scrub_stream:
 push rdi
 push rcx
 mov rdi,[rbx+pads_stream.pcm]
 mov ecx,4096
 xor eax,eax
 cld
 rep stosb
 mov dword [rbx+pads_stream.length],0
 mov dword [rbx+pads_stream.offset],0
 mov dword [rbx+pads_stream.wanted],0
 pop rcx
 pop rdi
 ret
pads_scrub_reply:
 lea rdi,[rel pads_reply]
 mov ecx,4160
 xor eax,eax
 cld
 rep stosb
 ret
pads_scrub:
 push rbx
 lea rbx,[rel pads_play]
 call pads_scrub_stream
 lea rbx,[rel pads_cap]
 call pads_scrub_stream
 call pads_scrub_reply
 pop rbx
 ret
pads_fail:
 mov dword [rel pads_phase],4
 mov dword [rel pads_dev+dev.health],HEALTH_DEAD
 mov dword [rel pads_play+pads_stream.xruns],1
 mov dword [rel pads_cap+pads_stream.xruns],1
 sub rsp,8
 call pads_scrub
 add rsp,8
 mov rax,-5
 ret

; Exact validated OPEN/session, not launch authority. No automatic activation.
pads_attach:
 PADS_ENTER
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 cmp dword [rel pads_registered],0
 jne .bad
 test r14,r14
 jz .bad
 test r13,r13
 jz .bad
 call r14
 cmp rax,-2001
 ja .bad
 mov r15,rax
 mov rdi,r12
 mov rsi,rax
 lea rdx,[rel pads_context]
 call padn_context
 test eax,eax
 jnz .bad
 cmp [rel pads_context+8],r13
 jne .bad
 cmp dword [rel pads_context+16],PADN_IDLE
 jne .bad
 cmp dword [rel pads_context+20],0
 je .bad
 cmp qword [rel pads_context+24],0
 jne .bad
 mov [rel pads_generation],r12
 mov [rel pads_session],r13
 mov eax,[rel pads_context+20]
 mov [rel pads_directions],eax
 mov [rel pads_clock],r14
 mov [rel pads_now],r15
 mov dword [rel pads_phase],1
 mov dword [rel pads_work],0
 mov dword [rel pads_turn],0
 lea rdi,[rel pads_play]
 mov ecx,pads_stream_size*2
 xor eax,eax
 cld
 rep stosb
 lea rax,[rel pads_pcm]
 mov [rel pads_play+pads_stream.pcm],rax
 lea rax,[rel pads_capture_pcm]
 mov [rel pads_cap+pads_stream.pcm],rax
 mov dword [rel pads_play+pads_stream.gain],32767
 mov dword [rel pads_cap+pads_stream.gain],32767
 call pads_scrub
 lea rbx,[rel pads_ops]
 lea rax,[rel pads_open]
 mov [rbx+snd_ops.open],rax
 lea rax,[rel pads_submit]
 mov [rbx+snd_ops.submit],rax
 lea rax,[rel pads_position]
 mov [rbx+snd_ops.position],rax
 lea rax,[rel pads_status]
 mov [rbx+snd_ops.status],rax
 lea rax,[rel pads_volume]
 mov [rbx+snd_ops.set_volume],rax
 lea rax,[rel pads_close]
 mov [rbx+snd_ops.close],rax
 lea rax,[rel pads_recover]
 mov [rbx+snd_ops.recover],rax
 lea rdi,[rel pads_dev]
 mov [rdi+dev.ops],rbx
 lea rax,[rel pads_info]
 mov [rdi+dev.info],rax
 mov [rdi+dev.priv],rdi
 mov dword [rdi+dev.prio],PRIO_DOMAIN+1
 mov dword [rdi+dev.health],HEALTH_OK
 mov dword [rdi+dev.class],CLASS_SOUND
 mov dword [rdi+dev.flags],0
 mov qword [rdi+dev.next],0
 lea rax,[rel pads_name]
 mov [rdi+dev.name],rax
 mov [rel pads_info+snd_info.name],rax
 mov dword [rel pads_info+snd_info.formats],SNDFMT_S16LE
 mov dword [rel pads_info+snd_info.max_chan],2
 mov dword [rel pads_info+snd_info.rates],0
 call snd_register
 test eax,eax
 jnz .bad
 mov dword [rel pads_registered],1
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE

; Admission validates shared native ownership, clock, then independent budgets.
pads_guard:
 push rbx
 cmp dword [rel pads_registered],1
 jne .bad
 cmp dword [rel pads_phase],4
 je .bad
 call [rel pads_clock]
 cmp rax,-2001
 ja .fault
 cmp rax,[rel pads_now]
 jb .fault
 mov [rel pads_now],rax
 mov rsi,rax
 mov rdi,[rel pads_generation]
 lea rdx,[rel pads_context]
 call padn_context
 test eax,eax
 jnz .fault
 mov rax,[rel pads_session]
 cmp [rel pads_context+8],rax
 jne .fault
 cmp dword [rel pads_context+24],0
 jne .fault
 mov eax,[rel pads_play+pads_stream.drain]
 cmp eax,2
 setae al
 movzx eax,al
 cmp eax,[rel pads_context+28]
 jne .fault
 cmp dword [rel pads_phase],3
 je .stopped
 cmp dword [rel pads_work],0
 jne .pending
 cmp dword [rel pads_context+16],PADN_IDLE
 jne .fault
 jmp .directions
.pending:
 mov eax,[rel pads_context+16]
 cmp eax,PADN_TX
 jb .fault
 cmp eax,PADN_READY
 ja .fault
.directions:
 mov eax,[rel pads_directions]
 cmp eax,[rel pads_context+20]
 jne .fault
 mov rax,[rel pads_now]
 cmp dword [rel pads_phase],2
 jne .play_budget
 cmp rax,[rel pads_stop_deadline]
 jae .fault
 jmp .ok
.play_budget:
 cmp dword [rel pads_play+pads_stream.length],0
 jne .check_play
 mov ecx,[rel pads_play+pads_stream.drain]
 cmp ecx,1
 je .check_play
 cmp ecx,2
 jne .capture_budget
.check_play:
 cmp rax,[rel pads_play+pads_stream.deadline]
 jae .fault
.capture_budget:
 cmp dword [rel pads_cap+pads_stream.wanted],0
 jne .check_capture
 cmp dword [rel pads_work],3
 jne .ok
.check_capture:
 cmp rax,[rel pads_cap+pads_stream.deadline]
 jae .fault
 jmp .ok
.stopped:
 cmp dword [rel pads_context+16],PADN_STOPPED
 jne .fault
.ok: xor eax,eax
 pop rbx
 ret
.fault: call pads_fail
.bad: mov rax,-1
 pop rbx
 ret

; Resolve opaque handles by exact comparison before clocks or other mutation.
; RBX selects that direction; never dereference caller-provided handle bits.
pads_resolve:
 lea rax,[rel pads_dev]
 cmp rdi,rax
 jne .bad
 lea rbx,[rel pads_play]
 cmp rsi,[rbx+pads_stream.handle]
 je .found
 lea rbx,[rel pads_cap]
 cmp rsi,[rbx+pads_stream.handle]
 jne .bad
.found:
 cmp dword [rbx+pads_stream.state],1
 jb .bad
 cmp dword [rbx+pads_stream.state],3
 ja .bad
 jmp pads_guard
.bad: mov rax,-1
 ret
pads_device:
 PADS_ENTER 0                      ;nullable pointer API, never an error pointer
 cmp rdi,[rel pads_generation]
 jne .none
 cmp rsi,[rel pads_session]
 jne .none
 call pads_guard
 test rax,rax
 jnz .none
 cmp dword [rel pads_phase],1
 jne .none
 lea rax,[rel pads_dev]
 jmp .out
.none: xor eax,eax
.out: PADS_LEAVE

pads_open:
 PADS_ENTER
 mov r12,rsi
 mov r13,rdx
 lea rax,[rel pads_dev]
 cmp rdi,rax
 jne .bad
 call pads_guard
 test rax,rax
 jnz .bad
 cmp dword [rel pads_phase],1
 jne .bad
 mov rdi,r12
 mov esi,snd_stream_params_size
 call pads_span
 jc .bad
 mov rdi,r13
 mov esi,8
 call pads_span
 jc .bad
 cmp dword [r12+snd_stream_params.rate],48000
 jne .bad
 cmp dword [r12+snd_stream_params.format],SNDFMT_S16LE
 jne .bad
 cmp dword [r12+snd_stream_params.channels],2
 jne .bad
 cmp dword [r12+snd_stream_params.latency_class],SND_LATENCY_BULK
 ja .bad
 cmp dword [r12+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 jne .bad
 mov rax,[r12+snd_stream_params.session_group]
 cmp rax,[rel pads_session]
 jne .bad
 mov ecx,[r12+snd_stream_params.direction]
 cmp ecx,1
 ja .bad
 mov eax,1
 shl eax,cl
 test [rel pads_directions],eax
 jz .bad
 lea rbx,[rel pads_play]
 test ecx,ecx
 jz .stream
 lea rbx,[rel pads_cap]
.stream:
 cmp dword [rbx+pads_stream.state],0
 jne .bad
 mov rax,[rel pads_handle_counter]
 mov rdx,0x0000ffffffffffff
 cmp rax,rdx
 jae .bad
 inc rax
 mov [rel pads_handle_counter],rax
 mov rdx,0xad01000000000000
 or rax,rdx
 mov [rbx+pads_stream.handle],rax
 mov [r13],rax
 mov dword [rbx+pads_stream.state],1
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE

; Queue admission/copy only: never issue PAD1 here, even during opposite work.
pads_submit:
 PADS_ENTER
 mov r12,rdx
 mov r13,rcx
 call pads_resolve
 test rax,rax
 jnz .bad
 cmp dword [rel pads_phase],1
 jne .bad
 cmp dword [rbx+pads_stream.state],1
 jne .bad
 cmp dword [rbx+pads_stream.drain],0
 jne .bad
 test r13,r13
 jz .zero
 test r13,3
 jnz .bad
 mov rdi,r12
 mov rsi,r13
 call pads_span
 jc .bad
 cmp r13,4096
 jbe .bounded
 mov r13d,4096
.bounded:
 lea rax,[rel pads_cap]
 cmp rbx,rax
 je .capture
 cmp dword [rbx+pads_stream.length],0
 jne .zero
 mov rsi,r12
 mov rdi,[rbx+pads_stream.pcm]
 mov rcx,r13
 cld
 rep movsb
 mov edx,[rbx+pads_stream.gain]
 cmp edx,32767
 je .scaled
 mov rdi,[rbx+pads_stream.pcm]
 mov rcx,r13
 shr rcx,1
.scale:
 movsx eax,word [rdi]
 imul eax,edx
 sar eax,15
 mov [rdi],ax
 add rdi,2
 loop .scale
.scaled:
 mov [rbx+pads_stream.length],r13d
 mov dword [rbx+pads_stream.offset],0
 mov rax,[rel pads_now]
 add rax,2000
 mov [rbx+pads_stream.deadline],rax
 mov rax,r13
 jmp .out
.capture:
 mov eax,[rbx+pads_stream.length]
 test eax,eax
 jz .want
 cmp r13,rax
 cmova r13,rax
 mov rsi,[rbx+pads_stream.pcm]
 mov edx,[rbx+pads_stream.offset]
 add rsi,rdx
 mov rdi,r12
 mov rcx,r13
 cld
 rep movsb
 mov rdi,[rbx+pads_stream.pcm]
 add rdi,rdx
 mov rcx,r13
 xor eax,eax
 rep stosb
 add [rbx+pads_stream.offset],r13d
 sub [rbx+pads_stream.length],r13d
 mov rax,r13
 jmp .out
.want:
 cmp dword [rbx+pads_stream.wanted],0
 jne .zero
 mov [rbx+pads_stream.wanted],r13d
 mov rax,[rel pads_now]
 add rax,2000
 mov [rbx+pads_stream.deadline],rax
.zero: xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE

; Playback-only extension, ABI-v2 vtable unchanged. Capture remains serviceable.
pads_drain:
 PADS_ENTER
 call pads_resolve
 test rax,rax
 jnz .bad
 cmp dword [rel pads_phase],1
 jne .bad
 lea rax,[rel pads_play]
 cmp rbx,rax
 jne .bad
 cmp dword [rbx+pads_stream.state],1
 jne .bad
 cmp dword [rbx+pads_stream.drain],3
 je .done
 cmp dword [rbx+pads_stream.drain],0
 jne .pending
 mov dword [rbx+pads_stream.drain],1
 cmp dword [rbx+pads_stream.length],0
 jne .pending
 mov rax,[rel pads_now]
 add rax,2000
 mov [rbx+pads_stream.deadline],rax
.pending: mov rax,-11
 jmp .out
.done: xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE
pads_position:
 mov rax,-1
 ret
pads_status:
 PADS_ENTER
 mov r12,rdx
 call pads_resolve
 test rax,rax
 jnz .bad
 mov rdi,r12
 mov esi,snd_status_size
 call pads_span
 jc .bad
 xor eax,eax
 lea rcx,[rel pads_cap]
 cmp rbx,rcx
 jne .frames
 mov rax,[rbx+pads_stream.frames]
.frames:
 mov [r12+snd_status.frames],rax
 mov qword [r12+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 mov eax,SND_STATE_RUNNING
 cmp dword [rbx+pads_stream.state],3
 jne .state
 mov eax,SND_STATE_CLOSED
.state:
 mov [r12+snd_status.state],eax
 mov eax,[rbx+pads_stream.xruns]
 mov [r12+snd_status.xruns],eax
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE
pads_volume:
 PADS_ENTER
 mov r12,rdx
 call pads_resolve
 test rax,rax
 jnz .bad
 cmp dword [rel pads_phase],1
 jne .bad
 cmp dword [rbx+pads_stream.state],1
 jne .bad
 cmp r12,32767
 ja .bad
 lea rax,[rel pads_cap]
 cmp rbx,rax
 jne .play
 cmp r12,32767
 jne .bad
 jmp .zero
.play: mov [rbx+pads_stream.gain],r12d
.zero: xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE
pads_recover:
 mov rax,-1
 ret

; First close is logical: drain playback, or discard capture's validated reply.
; Last live close switches to the old terminal STOP handshake for BOTH handles.
pads_close:
 PADS_ENTER
 call pads_resolve
 test rax,rax
 jnz .bad
 cmp dword [rbx+pads_stream.state],3
 je .closed
 cmp dword [rbx+pads_stream.state],2
 je .pending
 mov r12d,[rbx+pads_stream.length]
 or r12d,[rbx+pads_stream.drain]    ;remember whether a PLAY budget is active
 mov dword [rbx+pads_stream.state],2
 call pads_scrub_stream
 cmp dword [rel pads_play+pads_stream.state],1
 je .logical
 cmp dword [rel pads_cap+pads_stream.state],1
 je .logical
 mov dword [rel pads_phase],2
 mov dword [rel pads_dev+dev.health],HEALTH_DEGRADED
 call pads_scrub
 mov rax,[rel pads_now]
 add rax,2000
 mov [rel pads_stop_deadline],rax
 jmp .pending
.logical:
 lea rax,[rel pads_play]
 cmp rbx,rax
 jne .pending
 cmp dword [rbx+pads_stream.drain],3
 je .pending
 cmp dword [rbx+pads_stream.drain],0
 jne .close_budget
 mov dword [rbx+pads_stream.drain],1
.close_budget:
 ; Do not renew an already sealed drain/queue's earlier deadline.
 mov rax,[rel pads_now]
 add rax,2000
 test r12d,r12d
 jz .set_budget                   ;an old completed queue's deadline is inert
 cmp rax,[rbx+pads_stream.deadline]
 jae .pending
.set_budget: mov [rbx+pads_stream.deadline],rax
.pending: mov rax,-11
 jmp .out
.closed:
 mov dword [rbx+pads_stream.state],4
 mov qword [rbx+pads_stream.handle],0
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE

; Local completion only after that direction's outstanding request is consumed.
pads_finish_closing:
 cmp dword [rel pads_phase],1
 jne .out
 cmp dword [rel pads_cap+pads_stream.state],2
 jne .play
 cmp dword [rel pads_work],3
 je .play
 mov dword [rel pads_cap+pads_stream.state],3
.play:
 cmp dword [rel pads_play+pads_stream.state],2
 jne .out
 cmp dword [rel pads_play+pads_stream.drain],3
 jne .out
 cmp dword [rel pads_work],2
 je .out
 cmp dword [rel pads_work],4
 je .out
 mov dword [rel pads_play+pads_stream.state],3
.out: ret

; One exclusive bounded pump, one validated reply, one next fair request.
pads_step:
 PADS_ENTER
 cmp rdi,[rel pads_generation]
 jne .bad
 call pads_guard
 test rax,rax
 jnz .bad
 cmp dword [rel pads_phase],3
 je .zero
 mov rdi,[rel pads_generation]
 mov rsi,[rel pads_now]
 call padn_pump
 test eax,eax
 js .fault
 mov rdi,[rel pads_generation]
 mov rsi,[rel pads_now]
 lea rdx,[rel pads_reply]
 call padn_take
 test eax,eax
 js .fault
 jz .schedule
 mov ebp,[rel pads_work]
 test ebp,ebp
 jz .fault
 movzx eax,word [rel pads_reply+6]
 and eax,0x7fff
 cmp eax,ebp
 jne .fault
 mov eax,[rel pads_reply+48]
 test eax,eax
 jz .validated
 cmp ebp,5
 je .fault
 cmp eax,11
 jne .fault
.validated:
 mov dword [rel pads_work],0
 cmp ebp,5
 je .stopped
 cmp dword [rel pads_phase],2
 je .erase
 cmp ebp,4
 je .drain_reply
 cmp ebp,3
 je .capture_reply
 cmp ebp,2
 jne .fault
 lea rbx,[rel pads_play]
 cmp dword [rbx+pads_stream.state],2
 je .erase
 mov ecx,[rel pads_reply+40]
 shl ecx,2
 cmp ecx,[rbx+pads_stream.length]
 ja .fault
 mov rdi,[rbx+pads_stream.pcm]
 mov eax,[rbx+pads_stream.offset]
 add rdi,rax
 mov edx,ecx
 xor eax,eax
 cld
 rep stosb
 add [rbx+pads_stream.offset],edx
 sub [rbx+pads_stream.length],edx
 jnz .erase
 cmp dword [rbx+pads_stream.drain],1
 jne .erase
 mov rax,[rel pads_now]
 add rax,2000
 mov [rbx+pads_stream.deadline],rax
 jmp .erase
.drain_reply:
 cmp dword [rel pads_play+pads_stream.drain],2
 jne .fault
 cmp dword [rel pads_reply+48],0
 jne .erase
 mov dword [rel pads_play+pads_stream.drain],3
 jmp .erase
.capture_reply:
 lea rbx,[rel pads_cap]
 cmp dword [rbx+pads_stream.state],2
 je .erase
 mov ecx,[rel pads_reply+40]
 test ecx,ecx
 jz .erase                         ;EAGAIN/zero keeps original wanted+deadline
 mov eax,ecx
 add [rbx+pads_stream.frames],rax
 jc .fault
 shl ecx,2
 cmp ecx,[rbx+pads_stream.wanted]
 ja .fault
 mov dword [rbx+pads_stream.wanted],0
 mov [rbx+pads_stream.length],ecx
 mov dword [rbx+pads_stream.offset],0
 mov rdi,[rbx+pads_stream.pcm]
 lea rsi,[rel pads_reply+64]
 cld
 rep movsb
.erase: call pads_scrub_reply
.schedule:
 call pads_finish_closing
 cmp dword [rel pads_work],0
 jne .zero
 cmp dword [rel pads_phase],2
 je .stop
 cmp dword [rel pads_turn],0
 je .try_play
 call pads_choose_capture
 test esi,esi
 jnz .queue
.try_play:
 call pads_choose_play
 test esi,esi
 jnz .queue
 call pads_choose_capture
 test esi,esi
 jz .zero
 jmp .queue
.stop:
 mov esi,5
 xor edx,edx
 xor ecx,ecx
.queue:
 mov ebp,esi
 mov rdi,[rel pads_generation]
 xor r8d,r8d
 mov r9,[rel pads_now]
 call padn_request
 test eax,eax
 jnz .fault
 mov [rel pads_work],ebp
 cmp ebp,3
 sete al
 xor al,1
 movzx eax,al
 mov [rel pads_turn],eax
.zero: xor eax,eax
 jmp .out
.stopped:
 mov dword [rel pads_phase],3
 mov dword [rel pads_dev+dev.health],HEALTH_DEAD
 cmp dword [rel pads_play+pads_stream.state],1
 jb .stop_capture
 cmp dword [rel pads_play+pads_stream.state],2
 ja .stop_capture
 mov dword [rel pads_play+pads_stream.state],3
.stop_capture:
 cmp dword [rel pads_cap+pads_stream.state],1
 jb .scrub_stopped
 cmp dword [rel pads_cap+pads_stream.state],2
 ja .scrub_stopped
 mov dword [rel pads_cap+pads_stream.state],3
.scrub_stopped:
 call pads_scrub
 jmp .zero
.fault: call pads_fail
.bad: mov rax,-1
.out: PADS_LEAVE

; Return ESI=op (or0), EDX=frames, RCX=owned PCM. Never request here.
pads_choose_play:
 xor esi,esi
 xor edx,edx
 xor ecx,ecx
 cmp dword [rel pads_play+pads_stream.length],0
 je .drain
 mov esi,2
 mov edx,[rel pads_play+pads_stream.length]
 shr edx,2
 lea rcx,[rel pads_pcm]
 mov eax,[rel pads_play+pads_stream.offset]
 add rcx,rax
 ret
.drain:
 mov eax,[rel pads_play+pads_stream.drain]
 cmp eax,1
 je .ready
 cmp eax,2
 jne .out
.ready:
 mov dword [rel pads_play+pads_stream.drain],2
 mov esi,4
.out: ret
pads_choose_capture:
 xor esi,esi
 xor edx,edx
 xor ecx,ecx
 cmp dword [rel pads_cap+pads_stream.state],1
 jne .out
 mov edx,[rel pads_cap+pads_stream.wanted]
 test edx,edx
 jz .out
 shr edx,2
 mov esi,3
.out: ret

; Actual-stop owner only. Entry gate covers deregistration and erasure too.
pads_detach:
 PADS_ENTER
 cmp dword [rel pads_registered],1
 jne .bad
 cmp rdi,[rel pads_generation]
 jne .bad
 mov dword [rel pads_dev+dev.health],HEALTH_DEAD
 lea rdi,[rel pads_dev]
 call snd_deregister
 test rax,rax
 jnz .bad
 lea rdi,[rel pads_private]
 mov ecx,pads_storage_end-pads_private
 xor eax,eax
 cld
 rep stosb
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: PADS_LEAVE

pads_name: db 'Linux PCM domain',0
%include "core/abi/wdata.inc"
%macro WDATA_hv_audio_sound 0
alignb 8
pads_storage:
pads_handle_counter: resq 1             ;nonwrapping, survives actual-stop detach
pads_gate: resd 1                       ;held across all public adapter callbacks
alignb 8
pads_private:
pads_generation: resq 1
pads_session: resq 1
pads_clock: resq 1
pads_now: resq 1
pads_stop_deadline: resq 1
pads_registered: resd 1
pads_directions: resd 1
pads_phase: resd 1                      ;1 running,2 terminal close,3 STOP0,4 fault
pads_work: resd 1                       ;one exclusive PAD1 op,0 if idle
pads_turn: resd 1                       ;next ready preference:0 playback,1 capture
alignb 8
pads_play: resb pads_stream_size
pads_cap: resb pads_stream_size
pads_context: resb 32
alignb 8
pads_dev: resb dev_size
pads_ops: resb snd_ops_size
pads_info: resb snd_info_size
alignb 8
pads_pcm: resb 4096
pads_reply: resb 4160
pads_capture_pcm: resb 4096
pads_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_audio_sound
