;; MODULE media/opus_playback
;; LAYER 4
;; EXPORTS media_opus_playback_turn
;; IMPORTS media/opus_producer, snd/resample
;; CAPS
;; OWNER rc-codex-av
; Native HDA file consumer's private preparation, used by command_opus_playback.
; Trusted exclusively owned, mapped, zero-initialized context, serialized BSP.
; The embedded producer is configured by the owner before the first turn.
; One producer frame OR one <=1024-frame resample operation per turn. Every
; live turn obtains a CURRENT producer receipt, including after preparation.
; Mono/stereo short files: ceil(decoded_frames*44100/48000)<=2048, nonempty.
; Stereo is explicitly downmixed after conversion: floor((L+R)/64), including
; the fixed /32 gain. Both channels use the same rational resampler phase.
; 0 pending, 1 prepared/current source, -1 terminal refusal; never retry faults.
; State/PCM/source and the 96KiB decoder stack stay pinned through HDA retirement.
; RDI=ctx RSI=expected generation RDX=expected epoch. SysV GPRs, DF0.
struc media_opus_playback
 .producer: resb 192
 .phase: resq 1                 ;0 begin,1 decode,2 resample,3 prepared,4 fault
 .frames: resq 1
 .native_cursor: resq 1
 .resampler: resb 80
 .pcm: resb 4096
 .stereo: resb 4096             ;one <=1024-frame interleaved conversion
 .stack: resb 98304
endstruc
media_opus_playback_turn:
 push rbx
 push rbp
 push r12
 mov rbx,rdi
 mov rbp,rsi
 mov r12,rdx
 cld
 cmp rbp,[rbx+media_opus_producer.generation]
 jne .bad
 cmp r12,[rbx+media_opus_producer.epoch]
 jne .bad
 cmp qword [rbx+media_opus_playback.phase],4
 jae .bad
 cmp qword [rbx+media_opus_playback.phase],0
 jne .step
 ; A private stack is required by accepted native CELT/SILK. Switch only for
 ; this synchronous bounded call; no scheduler yield or callback on this stack.
 lea rax,[rel media_opus_producer_begin]
 jmp .decode
.step:
 lea rax,[rel media_opus_producer_step]
.decode:
 mov rdi,rbx
 mov rsi,rbp
 mov rdx,r12
 mov rbp,rsp
 lea rsp,[rbx+media_opus_playback.stack+98304]
 and rsp,-16
 call rax
 mov rsp,rbp
 test rax,rax
 js .fault
 cmp qword [rbx+media_opus_playback.phase],0
 jne .live
 test rax,rax
 jnz .fault
 inc qword [rbx+media_opus_playback.phase]
 jmp .pending
.live:
 test rax,rax
 jz .pending
 cmp eax,1
 jne .fault
 cmp qword [rbx+media_opus_playback.phase],3
 je .ready
 cmp qword [rbx+media_opus_playback.phase],2
 je .resample
 mov eax,[rbx+media_opus_producer.channels]
 dec eax
 cmp eax,1
 ja .fault
 cmp dword [rbx+media_opus_producer.rate],48000
 jne .fault
 mov rax,[rbx+media_opus_producer.frames]
 test rax,rax
 jz .fault
 imul rax,44100
 add rax,47999
 xor edx,edx
 mov ecx,48000
 div rcx
 cmp rax,2048
 ja .fault
 mov [rbx+media_opus_playback.frames],rax
 lea rdi,[rbx+media_opus_playback.resampler]
 mov rax,[rbx+media_opus_producer.pcm]
 mov [rdi+snd_resample_context.src],rax
 mov rax,[rbx+media_opus_producer.frames]
 mov [rdi+snd_resample_context.src_frames],rax
 mov dword [rdi+snd_resample_context.in_rate],48000
 mov dword [rdi+snd_resample_context.out_rate],44100
 mov eax,[rbx+media_opus_producer.channels]
 mov [rdi+snd_resample_context.channels],eax
 mov qword [rbx+media_opus_playback.phase],2
 jmp .pending
.resample:
 lea rdi,[rbx+media_opus_playback.resampler]
 mov rax,[rbx+media_opus_playback.native_cursor]
 mov r12,rax
 mov rcx,[rbx+media_opus_playback.frames]
 sub rcx,rax
 cmp rcx,1024
 jbe .request
 mov ecx,1024
.request:
 lea rdx,[rbx+media_opus_playback.pcm+rax*2]
 cmp dword [rdi+snd_resample_context.channels],2
 jne .destination
 lea rdx,[rbx+media_opus_playback.stereo]
.destination:
 mov [rdi+snd_resample_context.dst],rdx
 mov [rdi+snd_resample_context.request],rcx
 shl rcx,1
 cmp dword [rdi+snd_resample_context.channels],2
 jne .bytes
 shl rcx,1
.bytes:
 mov [rdi+snd_resample_context.dst_bytes],rcx
 call snd_resample_s16
 test rax,rax
 js .fault
 test rax,rax
 jz .fault
 ; Fixed -30dB gain for this explicit physical loopback/file journey. No wire
 ; amplitude parameter. Signed Q15 floor agrees with the maintained mixer.
 lea rdi,[rbx+media_opus_playback.pcm+r12*2]
 mov rcx,rax
 cmp dword [rbx+media_opus_playback.resampler+snd_resample_context.channels],2
 jne .attenuate
 lea rsi,[rbx+media_opus_playback.stereo]
.downmix:
 movsx edx,word [rsi]
 movsx r8d,word [rsi+2]
 add edx,r8d                   ;signed32 sum cannot overflow for two S16
 sar edx,6                     ;floor(mean/32), preserving negative rounding
 mov [rdi],dx
 add rsi,4
 add rdi,2
 loop .downmix
 jmp .converted
.attenuate:
 movsx edx,word [rdi]
 sar edx,5
 mov [rdi],dx
 add rdi,2
 loop .attenuate
.converted:
 add r12,rax
 mov [rbx+media_opus_playback.native_cursor],r12
 lea rdi,[rbx+media_opus_playback.resampler]
 cmp r12,[rbx+media_opus_playback.frames]
 jne .pending
 mov rax,[rdi+snd_resample_context.cursor]
 cmp rax,[rdi+snd_resample_context.src_frames]
 jne .fault
 mov qword [rbx+media_opus_playback.phase],3
.ready:
 mov eax,1
 jmp .out
.fault:
 mov qword [rbx+media_opus_playback.phase],4
.bad:
 mov rax,-1
 jmp .out
.pending:
 xor eax,eax
.out:
 pop r12
 pop rbp
 pop rbx
 ret
