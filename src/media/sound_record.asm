;; MODULE media/sound_record
;; LAYER 4
;; EXPORTS media_sound_record_step
;; IMPORTS snd/mixer, media/wav_record
;; CAPS
;; OWNER rc-codex-av
;
; One bounded sound ABI-v2 CAPTURE -> mixer -> WAV memory sink opportunity.
; RDI=owned aligned8344B route, RSI=generation,RDX=epoch,RCX=request1..1024
; frames. RAX=definite recorded frames,0 pending,-1 invalid,-2 unsupported,
; -3 capacity,-4 limit,-5 latched uncertain consumption,-6 backend refusal.
; No discovery/open/close, VM routing, device authority, file I/O or clock.
; Owner supplies an already-open S16LE CAPTURE handle whose rate and channel
; count exactly match the recorder (44100/48000/96000 Hz, mono/stereo) and serializes
; route, recorder, sound adapter and VM lifecycle. Device/vtable and operands
; remain stable mapped trusted kernel-owned spans, mutually disjoint. Backend
; submit follows ABI v2: capture copies returned bytes before returning; zero
; means pending, negative consumes no bytes. No caller pointer is retained.
; The same generation/epoch binds a begun WAV recorder. A mono microphone is
; already duplicated by the Linux service; this consumer adds no channel claim.
; Gain/mute use the existing mixer once on a definite capture prefix. Raw and
; mixed scratch are erased after every backend call. Invalid positive counts
; or a downstream failure latch state1: consumed samples cannot be replayed.
; WAV header publication remains explicit media_wav_record_finish after the
; owner stops further steps; finish does not STOP a backend or terminate a VM.
; RSP/callee-saved GPRs preserved; DF0 required. No static state/allocation.

struc media_sound_record
 .version: resd 1
 .state: resd 1
 .generation: resq 1
 .epoch: resq 1
 .device: resq 1
 .handle: resq 1
 .recorder: resq 1
 .gain: resd 1
 .muted: resd 1
 .frames: resq 1
 .raw: resb 4096
 .mixed: resb 4096
 .stream: resb snd_mix_stream_size
 .block: resb snd_mix_block_size
endstruc

; Nonempty lower-canonical span RDI,R9 -> RAX=end or CF; no dereference.
mcr_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,r9
 jc .bad
 mov r10,0x0000800000000000
 cmp rax,r10
 ja .bad
 clc
 ret
.bad:
 stc
 ret

%macro MCR_DISJOINT 4
 cmp %1,%4
 jae %%ok
 cmp %3,%2
 jb mcr_bad
%%ok:
%endmacro

media_sound_record_step:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 test r12,7
 jnz mcr_bad
 mov r9d,media_sound_record_size
 call mcr_span
 jc mcr_bad
 mov rbx,rax
 cmp dword [r12+media_sound_record.version],1
 jne mcr_bad
 cmp dword [r12+media_sound_record.state],0
 jne mcr_fault
 test r13,r13
 jz mcr_unsupported
 test r14,r14
 jz mcr_unsupported
 cmp r13,[r12+media_sound_record.generation]
 jne mcr_unsupported
 cmp r14,[r12+media_sound_record.epoch]
 jne mcr_unsupported
 cmp dword [r12+media_sound_record.gain],32768
 ja mcr_unsupported
 cmp dword [r12+media_sound_record.muted],1
 ja mcr_unsupported
 test r15,r15
 jz mcr_bad
 cmp r15,1024
 ja mcr_limit
 mov rax,[r12+media_sound_record.frames]
 add rax,r15
 jc mcr_limit
 cmp qword [r12+media_sound_record.handle],0
 je mcr_bad
 mov rbp,[r12+media_sound_record.recorder]
 mov rdi,rbp
 mov r9d,media_wav_record_size
 call mcr_span
 jc mcr_bad
 MCR_DISJOINT rbp,rax,r12,rbx
 mov rdi,[rbp+media_wav_record.dst]
 mov r9,[rbp+media_wav_record.capacity]
 call mcr_span
 jc mcr_bad
 MCR_DISJOINT rdi,rax,r12,rbx
 ; Shared recorder validator checks phase/identity/format/capacity and all its
 ; spans BEFORE consuming capture. Serial owner keeps this preflight stable.
 mov rdi,rbp
 mov rsi,r13
 mov rdx,r14
 lea rcx,[r12+media_sound_record.mixed]
 mov r8,r15
 call media_wav_record_check_append
 test rax,rax
 js mcr_out
 ; Device and table must be external to route/recorder/full output. Ownership
 ; and capture direction come from the caller's actual open and VM lifecycle.
 mov rdi,[r12+media_sound_record.device]
 mov r9d,dev_size
 call mcr_external
 jc mcr_bad
 cmp dword [rdi+dev.class],CLASS_SOUND
 jne mcr_unsupported
 cmp dword [rdi+dev.health],HEALTH_OK
 jne mcr_unsupported
 cmp qword [rdi+dev.info],0
 je mcr_bad
 mov rdi,[rdi+dev.ops]
 mov r9d,snd_ops_size
 call mcr_external
 jc mcr_bad
 mov rax,[rdi+snd_ops.submit]
 test rax,rax
 jz mcr_bad
 mov [rsp],rax
 ; Recorder preflight already validated rate/channels. Keep exact frame bytes
 ; across the trusted backend callback; capacity is still <=4096 bytes.
 mov eax,[rbp+media_wav_record.channels]
 add eax,eax
 mov [rsp+8],rax
 imul rax,r15
 mov [rsp+16],rax
 mov rdi,[r12+media_sound_record.device]
 mov rsi,[r12+media_sound_record.handle]
 lea rdx,[r12+media_sound_record.raw]
 mov rcx,[rsp+16]
 call [rsp]
 test rax,rax
 js mcr_refused
 jz mcr_empty
 cmp rax,[rsp+16]
 ja mcr_poison
 mov rdx,[rsp+8]
 dec rdx
 test rax,rdx
 jnz mcr_poison
 xor edx,edx
 div qword [rsp+8]
 mov r15,rax
 lea rdi,[r12+media_sound_record.stream]
 lea rax,[r12+media_sound_record.raw]
 mov [rdi+snd_mix_stream.pcm],rax
 mov [rdi+snd_mix_stream.frames],r15
 mov qword [rdi+snd_mix_stream.cursor],0
 mov eax,[r12+media_sound_record.gain]
 mov [rdi+snd_mix_stream.gain],eax
 mov eax,[r12+media_sound_record.muted]
 mov [rdi+snd_mix_stream.flags],eax
 mov eax,[rbp+media_wav_record.rate]
 mov [rdi+snd_mix_stream.rate],eax
 mov eax,[rbp+media_wav_record.channels]
 mov [rdi+snd_mix_stream.channels],eax
 lea rax,[r12+media_sound_record.block]
 mov [rax+snd_mix_block.streams],rdi
 lea rdx,[r12+media_sound_record.mixed]
 mov [rax+snd_mix_block.dst],rdx
 mov qword [rax+snd_mix_block.dst_bytes],4096
 mov dword [rax+snd_mix_block.stream_count],1
 mov edx,[rbp+media_wav_record.channels]
 mov [rax+snd_mix_block.channels],edx
 mov [rax+snd_mix_block.frames],r15
 mov edx,[rbp+media_wav_record.rate]
 mov [rax+snd_mix_block.rate],edx
 mov dword [rax+snd_mix_block.reserved],0
 mov rdi,rax
 call snd_mix_s16
 test rax,rax
 js mcr_poison
 mov rdi,rbp
 mov rsi,r13
 mov rdx,r14
 lea rcx,[r12+media_sound_record.mixed]
 mov r8,r15
 call media_wav_record_append
 cmp rax,r15
 jne mcr_poison
 add [r12+media_sound_record.frames],r15
 mov rax,r15
 jmp mcr_scrub
mcr_poison:
 mov dword [r12+media_sound_record.state],1
 mov rax,-5
 jmp mcr_scrub
mcr_refused:
 mov rax,-6
 jmp mcr_scrub
mcr_empty:
 xor eax,eax
mcr_scrub:
 mov rdx,rax
 lea rdi,[r12+media_sound_record.raw]
 mov ecx,(media_sound_record_size-media_sound_record.raw)/8
 xor eax,eax
 rep stosq
 mov rax,rdx
 jmp mcr_out
mcr_bad:
 mov rax,-1
 jmp mcr_out
mcr_unsupported:
 mov rax,-2
 jmp mcr_out
mcr_limit:
 mov rax,-4
 jmp mcr_out
mcr_fault:
 mov rax,-5
mcr_out:
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Check device/vtable spans against route/recorder/output. RDI preserved.
mcr_external:
 call mcr_span
 jc .bad
 cmp rdi,rbx
 jae .recorder
 cmp r12,rax
 jb .bad
.recorder:
 lea rdx,[rbp+media_wav_record_size]
 cmp rdi,rdx
 jae .dst
 cmp rbp,rax
 jb .bad
.dst:
 mov rdx,[rbp+media_wav_record.dst]
 mov r10,rdx
 add r10,[rbp+media_wav_record.capacity]
 cmp rdi,r10
 jae .ok
 cmp rdx,rax
 jb .bad
.ok:
 clc
 ret
.bad:
 stc
 ret
