;; MODULE media/hda_owner_private
;; LAYER 4
;; EXPORTS media_hda_owner_begin, media_hda_owner_turn, media_hda_owner_spawn
;; IMPORTS media/wav_producer, media/pcm_stream, core/sched
;; CAPS
;; OWNER rc-codex-av
; S5a PRIVATE UNWIRED. Injected certificates are NOT hardware evidence.
; Stable mapped serialized caller spans; no MMIO/IRQ/mapping/allocator action.
; ctx256/event256. 0 progress,1 wait,2 stop,3 start request,4 halt request;
; -1 malformed span, -2 identity/phase, -6 pinned failure. See owned ABI docs.
struc media_hda_owner
 .version: resd 1
 .phase: resd 1                    ; IDLE0 LOAD1 PRIME2 STARTING3 PLAY4
 .controller: resq 1               ; STOPPING5 DRAINREF6 QUIESCED7 RELEASED8 POISON9
 .generation: resq 1
 .epoch: resq 1
 .producer: resq 1
 .consumer: resq 1
 .arena: resq 1
 .arena_bytes: resq 1
 .iova: resq 1
 .address_bits: resq 1
 .event: resq 1
 .sd_index: resq 1
 .tag: resq 1
 .bound_controller: resq 1
 .last_generation: resq 1
 .last_epoch: resq 1
 .turns: resq 1
 .calls: resq 1
 .fills: resq 1
 .last_time: resq 1
 .last_retired: resq 1
 .pinned: resq 1
 .task_id: resq 1
 .action: resq 1                   ; 0 none,1 START,2 HALT,3 UNMAP
 .error: resq 1
 .maxcopy: resq 1
 .last_position: resq 1
 .cancelled: resq 1                ; cancel/discard attempted once; READY immutable
 .reserved: resq 4
endstruc
struc media_hda_owner_event
 .controller: resq 1
 .generation: resq 1
 .epoch: resq 1
 .now: resq 1
 .copy_end: resq 1
 .deadline: resq 1
 .rlo: resq 1
 .rhi: resq 1
 .rhi_end: resq 1
 .certified: resq 1                ; injected entire-window certificate, exactly1
 .position: resq 1                 ; raw0..CBL, no retirement inference
 .lpib: resq 1
 .sd_index: resq 1
 .cbl: resq 1
 .tag: resq 1
 .health: resq 1                   ; RUN1 SRST2 FIFOE4 DESE8
 .engines: resq 1                  ; stopped ALL streams/CORB/RIRB/position:15
 .irq_closed: resq 1
 .refs: resq 1
 .deferred: resq 1
 .unmap: resq 1                    ; pending0, completed1, failed2
 .failed: resq 1
 .cancel: resq 1
 .bcis: resq 1                     ; ignored: never a completion receipt
 .reserved: resq 8
endstruc
%define H(x) [rbx+media_hda_owner. %+ x]
%define E(x) [r12+media_hda_owner_event. %+ x]
%macro HO_ENTER 0
 push rbx
 push r12
 push r13
 sub rsp,48                       ; one grant48 or receipt40, no heap
 mov rbx,rdi
 call ho_validate
 test eax,eax
 jnz ho_exit
%endmacro
media_hda_owner_begin:             ; RDI=fully configured owner, EMPTY producer
 HO_ENTER
 mov eax,H(phase)
 test eax,eax
 jz .identity
 cmp eax,8
 jne ho_stale
.identity:
 mov rax,H(controller)
 test rax,rax
 jz ho_stale
 cmp qword H(bound_controller),0
 je .first
 cmp rax,H(bound_controller)
 jne ho_stale
.first:
 mov rax,H(generation)
 test rax,rax
 jz ho_stale
 cmp rax,-1
 je ho_stale
 cmp rax,H(last_generation)
 jbe ho_stale
 mov rdx,H(epoch)
 test rdx,rdx
 jz ho_stale
 cmp rdx,-1
 je ho_stale
 cmp rdx,H(last_epoch)
 jbe ho_stale
 mov rdi,H(producer)
 cmp rax,[rdi+media_wav_producer.generation]
 jne ho_stale
 cmp rdx,[rdi+media_wav_producer.epoch]
 jne ho_stale
 cmp dword [rdi+media_wav_producer.phase],0
 jne ho_stale
 mov rax,H(controller)
 mov H(bound_controller),rax
 mov rax,H(generation)
 mov H(last_generation),rax
 mov rax,H(epoch)
 mov H(last_epoch),rax
 mov qword H(turns),0
 mov qword H(calls),0              ; even producer begin runs on the task
 mov qword H(fills),0
 mov qword H(last_time),0
 mov qword H(last_retired),0
 mov qword H(last_position),-1
 mov qword H(pinned),1
 mov qword H(action),0
 mov qword H(error),0
 mov qword H(maxcopy),0
 mov qword H(cancelled),0
 mov dword H(phase),1
 xor eax,eax
 jmp ho_exit
media_hda_owner_turn:              ; exactly one owner task turn
 HO_ENTER
 mov r12,H(event)
 mov rax,E(controller)
 cmp rax,H(bound_controller)
 jne ho_stale
 cmp rax,H(controller)
 jne ho_stale
 mov rax,E(generation)
 cmp rax,H(last_generation)
 jne ho_stale
 cmp rax,H(generation)
 jne ho_stale
 mov rax,E(epoch)
 cmp rax,H(last_epoch)
 jne ho_stale
 cmp rax,H(epoch)
 jne ho_stale
 mov eax,H(phase)
 cmp eax,9
 je ho_poison_repeat
 test eax,eax
 jz ho_wait
 cmp eax,8
 je ho_wait
 cmp qword H(turns),65536
 jae ho_poison
 inc qword H(turns)
 cmp eax,5
 jae .teardown
 cmp eax,1
 jne .live_generation
 cmp qword H(calls),0
 jne .live_generation
 mov rdi,H(consumer)
 xor eax,eax
 mov ecx,24
 rep stosq                        ; task owns fresh metadata even on early abort
.live_generation:
 cmp qword E(failed),0
 jne ho_stop
 cmp qword E(cancel),0
 jne ho_stop
 mov rax,E(now)
 test rax,rax
 jz ho_stop
 cmp rax,H(last_time)
 jb ho_stop
 mov H(last_time),rax
 cmp dword H(phase),1
 je .load
 cmp dword H(phase),2
 je .prime
 ; Selected raw slot/configuration and health are checked, never unwrapped.
 cmp qword E(cbl),16384
 jne ho_stop
 mov rax,E(sd_index)
 cmp rax,H(sd_index)
 jne ho_stop
 mov rax,E(tag)
 cmp rax,H(tag)
 jne ho_stop
 mov r13,E(position)
 cmp r13,16384
 ja ho_stop
 cmp qword E(lpib),16384
 ja ho_stop
 cmp r13,16384
 jne .position
 xor r13d,r13d
.position:
 cmp dword H(phase),3
 je .starting
 cmp qword E(health),1
 jne ho_stop
 cmp qword E(certified),1
 jne ho_stop
 mov rax,E(copy_end)
 cmp rax,E(now)
 jb ho_stop
 cmp rax,E(deadline)
 jae ho_stop
 mov rax,E(rlo)
 cmp rax,H(last_retired)
 jb ho_stop
 cmp rax,E(rhi)
 ja ho_stop
 mov rdx,E(rhi)
 cmp rdx,E(rhi_end)
 ja ho_stop
 cmp r13,H(last_position)
 je ho_wait                       ; stale/equal sample creates NO retirement
 mov rdi,H(consumer)
 mov rdx,[rdi+media_pcm_stream.next]
 cmp rax,rdx
 ja ho_stop
 cmp dword [rdi+media_pcm_stream.phase],3
 jne .feed
 cmp rax,[rdi+media_pcm_stream.last_audio]
 ja .retire_eof                   ; folded new R, before any fill
.feed:
 cmp E(rhi_end),rdx
 jae .unsafe_window
 sub rdx,3
 cmp rax,rdx
 jb ho_wait
 ; The SAME certificate covers the complete copy/fence window.
 mov H(last_position),r13
 mov H(last_retired),rax
 mov qword [rsp+32],1
 jmp .grant
.unsafe_window:
 mov qword [rsp+24],3             ; possible underrun -> fault, no fill
 cmp rax,rdx
 jne .retire
 mov qword [rsp+24],1             ; proven R==s -> consumer UNDERRUN
 jmp .retire
.retire_eof:
 mov qword [rsp+24],0
.retire:
 mov [rsp+16],rax
 mov rax,H(generation)
 mov [rsp],rax
 mov rax,H(epoch)
 mov [rsp+8],rax
 mov qword [rsp+32],0
 mov rsi,rsp
 call media_pcm_stream_retire
 cmp rax,2
 jne ho_stop
 jmp ho_stopping
.starting:
 cmp qword E(health),0
 je ho_wait
 cmp qword E(health),1
 jne ho_stop
 mov H(last_position),r13
 mov dword H(phase),4
 mov qword H(action),0
 xor eax,eax
 jmp ho_exit
.load:
 cmp qword H(calls),304
 jae ho_stop
 cmp qword H(calls),0
 je .load_begin
 mov rdi,H(producer)
 mov rsi,H(generation)
 mov rdx,H(epoch)
 inc qword H(calls)
 call media_wav_producer_step      ; ONE call, never a decode-until-ready loop
 test rax,rax
 js ho_stop
 jz ho_exit
 cmp rax,1
 jne ho_stop
 mov r13,H(producer)
 cmp dword [r13+media_wav_producer.phase],3
 jne ho_stop
 mov rax,H(generation)
 cmp rax,[r13+media_wav_producer.generation]
 jne ho_stop
 mov rax,H(epoch)
 cmp rax,[r13+media_wav_producer.epoch]
 jne ho_stop
 cmp qword [r13+media_wav_producer.integrity],0
 jne ho_stop
 mov rax,[r13+media_wav_producer.frames]
 test rax,rax
 jz ho_stop
 mov ecx,[r13+media_wav_producer.channels]
 lea edx,[rcx-1]
 cmp edx,1
 ja ho_stop
 shl ecx,1
 mul rcx
 test rdx,rdx
 jnz ho_stop
 cmp rax,[r13+media_wav_producer.bytes]
 jne ho_stop
 cmp rax,[r13+media_wav_producer.cursor]
 jne ho_stop
 cmp rax,[r13+media_wav_producer.capacity]
 ja ho_stop
 cmp dword [r13+media_wav_producer.bits],16
 je .input_bits
 cmp dword [r13+media_wav_producer.bits],24
 jne ho_stop
.input_bits:                       ; producer bits describes INPUT, PCM is S16
 mov rdi,H(consumer)
 xor eax,eax
 mov ecx,24
 rep stosq
 mov rdi,H(consumer)
 mov dword [rdi+media_pcm_stream.version],1
 mov rax,H(generation)
 mov [rdi+media_pcm_stream.generation],rax
 mov rax,H(epoch)
 mov [rdi+media_pcm_stream.epoch],rax
 mov rax,[r13+media_wav_producer.pcm]
 mov [rdi+media_pcm_stream.pcm],rax
 mov rax,[r13+media_wav_producer.capacity]
 mov [rdi+media_pcm_stream.capacity],rax
 mov rax,[r13+media_wav_producer.bytes]
 mov [rdi+media_pcm_stream.bytes],rax
 mov rax,[r13+media_wav_producer.frames]
 mov [rdi+media_pcm_stream.frames],rax
 mov rax,H(arena)
 add rax,16384
 mov [rdi+media_pcm_stream.ring],rax
 mov qword [rdi+media_pcm_stream.ring_bytes],16384
 mov eax,[r13+media_wav_producer.rate]
 mov [rdi+media_pcm_stream.rate],eax
 mov eax,[r13+media_wav_producer.channels]
 mov [rdi+media_pcm_stream.channels],eax
 shl eax,1
 mov [rdi+media_pcm_stream.frame_bytes],eax
 mov dword [rdi+media_pcm_stream.format],1
 call media_pcm_stream_begin
 test rax,rax
 jnz ho_stop
 mov dword H(phase),2
 jmp ho_exit
.load_begin:
 mov rdi,H(producer)
 mov rsi,H(generation)
 mov rdx,H(epoch)
 inc qword H(calls)
 call media_wav_producer_begin     ; the first of <=304 task turns
 test rax,rax
 jnz ho_stop
 jmp ho_exit
.prime:
 cmp qword E(health),0
 jne ho_stop
 mov qword [rsp+32],0
 xor eax,eax
.grant:
 mov [rsp+16],rax
 mov rax,H(generation)
 mov [rsp],rax
 mov rdi,H(consumer)
 mov rax,[rdi+media_pcm_stream.next]
 mov [rsp+8],rax
 and eax,3
 mov [rsp+36],eax
 mov rax,H(epoch)
 mov [rsp+24],rax
 mov qword [rsp+40],0
 mov rsi,rsp
 call media_pcm_stream_service     ; ONE <=4096B fill, accepted sfence
 test rax,rax
 js ho_stop
 cmp rax,2
 je ho_stopping
 cmp rax,0
 jne ho_exit
 inc qword H(fills)
 mov qword H(maxcopy),4096
 cmp dword H(phase),2
 jne ho_exit
 mov rdi,H(consumer)
 cmp qword [rdi+media_pcm_stream.primed],4
 jne ho_exit
 mov dword H(phase),3
 mov qword H(action),1
 mov eax,3                        ; start is a request, NOT a RUN write
 jmp ho_exit
.teardown:
 cmp qword E(failed),0
 jne ho_poison
 cmp eax,5
 jne .teardown_engines
 cmp qword H(cancelled),0
 jne .teardown_engines
 mov rdi,H(producer)
 mov rsi,H(generation)
 mov rdx,H(epoch)
 call media_wav_producer_cancel    ; separate turn from a failed decode call
 mov qword H(cancelled),1
.teardown_engines:
 mov eax,H(phase)
 cmp eax,7
 je .unmap
 cmp qword E(engines),15
 jne ho_wait
 cmp qword E(health),0
 jne ho_wait
 cmp eax,5
 jne .refs
 mov dword H(phase),6
 mov qword H(action),0
 xor eax,eax
 jmp ho_exit
.refs:
 cmp qword E(irq_closed),1
 jne ho_wait
 cmp qword E(refs),0
 jne ho_wait
 cmp qword E(deferred),0
 jne ho_wait
 mov rdi,H(consumer)
 cmp dword [rdi+media_pcm_stream.phase],0
 je .quiesced                    ; no consumer was admitted on LOAD failure
 mov rax,H(generation)
 mov [rsp],rax
 mov rax,H(epoch)
 mov [rsp+8],rax
 mov rax,[rdi+media_pcm_stream.retired]
 mov [rsp+16],rax
 mov qword [rsp+24],2
 mov qword [rsp+32],0
 mov rsi,rsp
 call media_pcm_stream_release
 test rax,rax
 jnz ho_poison
.quiesced:
 mov dword H(phase),7
 mov qword H(action),3
 xor eax,eax
 jmp ho_exit
.unmap:
 cmp qword E(engines),15
 jne ho_poison
 cmp qword E(health),0
 jne ho_poison
 cmp qword E(irq_closed),1
 jne ho_poison
 mov rax,E(refs)
 or rax,E(deferred)
 jnz ho_poison
 cmp qword E(unmap),0
 je ho_wait
 cmp qword E(unmap),1
 jne ho_poison
 mov qword H(pinned),0
 mov qword H(action),0
 mov dword H(phase),8
 xor eax,eax
 jmp ho_exit
ho_stop:
 xor r13d,r13d
 jmp ho_discard
ho_poison:
 mov r13d,1
ho_discard:
 mov qword H(error),1
 test r13d,r13d
 jz .consumer
 cmp qword H(cancelled),0
 jne .consumer
 mov rdi,H(producer)
 mov rsi,H(generation)
 mov rdx,H(epoch)
 call media_wav_producer_cancel
 mov qword H(cancelled),1
.consumer:
 mov rdi,H(consumer)
 cmp dword [rdi+media_pcm_stream.phase],0
 je ho_discard_done
 mov rsi,H(generation)
 mov rdx,H(epoch)
 call media_pcm_stream_cancel
ho_discard_done:
 test r13d,r13d
 jnz ho_set_poison
ho_stopping:
 mov dword H(phase),5
 mov qword H(action),2
 mov eax,4
 jmp ho_exit
ho_set_poison:
 mov dword H(phase),9
 mov qword H(action),2
ho_poison_repeat:
 mov rax,-6
 jmp ho_exit
ho_stale: mov rax,-2
 jmp ho_exit
ho_wait: mov eax,1
ho_exit:
 add rsp,48
 pop r13
 pop r12
 pop rbx
 ret
; Validate exactly seven stable spans, then all21 full-span pairs. No dereference
; of producer until its span is validated. No writes to caller storage.
ho_validate:
 sub rsp,112
 mov rax,rbx
 test al,7
 jnz .bad
 test rax,rax
 jz .bad
 add rax,256
 jc .bad
 cmp dword H(version),1
 jne .bad
 cmp dword H(phase),9
 ja .bad
 mov rax,H(sd_index)
 cmp rax,29
 ja .bad
 mov rax,H(tag)
 dec rax
 cmp rax,14
 ja .bad
 mov rax,H(arena)
 test rax,4095
 jnz .bad
 cmp qword H(arena_bytes),32768
 jne .bad
 mov rax,H(iova)
 test rax,rax
 jz .bad
 test rax,4095
 jnz .bad
 add rax,32768
 jc .bad
 cmp qword H(address_bits),64
 je .width
 cmp qword H(address_bits),32
 jne .bad
 mov rdx,0x100000000
 cmp rax,rdx
 ja .bad
.width:
 lea rsi,[rbx+media_hda_owner.reserved]
 mov ecx,4
.reserved:
 cmp qword [rsi],0
 jne .bad
 add rsi,8
 loop .reserved
 mov [rsp],rbx
 mov qword [rsp+8],256
 mov rax,H(producer)
 mov [rsp+16],rax
 mov qword [rsp+24],192
 mov rax,H(consumer)
 mov [rsp+32],rax
 mov qword [rsp+40],192
 mov rax,H(event)
 mov [rsp+48],rax
 mov qword [rsp+56],256
 mov rax,H(arena)
 mov [rsp+64],rax
 mov qword [rsp+72],32768
 xor ecx,ecx
.first:
 mov rax,[rsp+rcx]
 test rax,rax
 jz .bad
 test al,7
 jnz .bad
 add rax,[rsp+rcx+8]
 jc .bad
 add ecx,16
 cmp ecx,80
 jb .first
 mov rdi,H(producer)
 mov rax,[rdi+media_wav_producer.src]
 mov [rsp+80],rax
 mov rax,[rdi+media_wav_producer.src_bytes]
 mov [rsp+88],rax
 mov rax,[rdi+media_wav_producer.pcm]
 mov [rsp+96],rax
 mov rax,[rdi+media_wav_producer.capacity]
 mov [rsp+104],rax
.remaining:
 mov rax,[rsp+rcx]
 test rax,rax
 jz .bad
 cmp qword [rsp+rcx+8],0
 je .bad
 add rax,[rsp+rcx+8]
 jc .bad
 add ecx,16
 cmp ecx,112
 jb .remaining
 xor ecx,ecx
.outer:
 mov r8,[rsp+rcx]
 mov r9,r8
 add r9,[rsp+rcx+8]
 lea edx,[rcx+16]
.inner:
 cmp edx,112
 jae .next
 mov r10,[rsp+rdx]
 mov r11,r10
 add r11,[rsp+rdx+8]
 cmp r8,r11
 jae .apart
 cmp r10,r9
 jb .bad
.apart:
 add edx,16
 jmp .inner
.next:
 add ecx,16
 cmp ecx,112
 jb .outer
 mov rax,H(event)
 lea rsi,[rax+media_hda_owner_event.reserved]
 mov ecx,8
.event_reserved:
 cmp qword [rsi],0
 jne .bad
 add rsi,8
 loop .event_reserved
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out:
 add rsp,112
 ret
; One boot-lifetime singleton. sched_spawn initializes argument GPRs to zero;
; task entry therefore obtains its stable context from this private slot.
; Spawn failure clears only our claim. No source work occurs on spawn's stack.
media_hda_owner_spawn:
 push rbx
 mov rbx,rdi
 call ho_validate
 test rax,rax
 jnz .return
 mov rdi,rbx
 xor eax,eax
 lock cmpxchg [rel ho_task_owner],rdi
 jne .busy
 lea rdi,[rel ho_task_entry]
 call sched_spawn
 test eax,eax
 js .failed
 mov H(task_id),rax
 pop rbx
 ret
.failed:
 mov qword [rel ho_task_owner],0
.busy:
 mov rax,-2
.return:
 pop rbx
 ret
ho_task_entry:
 sub rsp,8
.loop:
 mov rdi,[rel ho_task_owner]
 call media_hda_owner_turn
 call sched_yield                  ; one producer/fill per actual yield turn
 jmp .loop
section .data
align 8
ho_task_owner: dq 0                ; 8 static bytes, never DMA; unwired
section .text
%undef H
%undef E
