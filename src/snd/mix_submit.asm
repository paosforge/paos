;; MODULE snd/mix_submit
;; LAYER 4
;; EXPORTS snd_mix_submit
;; IMPORTS snd/mixer, core/lib/mem
;; CAPS
;; OWNER rc-codex-av
;
; Mixed PCM -> existing ABI-v2 snd_ops.submit. Caller holds an already-open
; S16 stream matching rate/channels, keeps its trusted device/vtable stable,
; and owns all mixer operands. Caller serializes lifecycle/calls; driver state cannot
; alias mixer operands or this sink. Submit consumes/copies its accepted input
; before returning; the output block may be reused on the next call.
;
; snd_mix_submit(RDI=sink40,RSI=mix_block48) -> RAX accepted whole frames,
; or mixer -1..-4, -5 latched protocol fault, -6 backend refusal, -7 unavailable.
; Original mixer operands are validated before private cursor staging. The
; mixer writes PCM but only private cursors. A whole-frame prefix accepted by
; the backend advances public cursors by min(accepted,remaining) and increments
; accepted_frames; zero/negative acceptance preserves all progress. Output PCM
; may change after successful mixing even if the backend refuses it.
; Oversized/unaligned positive acceptance is uncertain device progress: latch
; state=1, leave public cursors/accounting unchanged and require caller recovery
; and explicit sink reinitialization before another submission. Never retry it
; automatically. Backend contract: a negative result accepts no bytes.
; No allocation, open/close, registration, device discovery or hardware proof.
; SysV preserved GPRs/RSP; DF=0 ABI. Stable mapped ownership is caller-supplied.

struc snd_mix_sink
 .device: resq 1
 .handle: resq 1
 .rate: resd 1
 .channels: resd 1
 .state: resd 1
 .reserved: resd 1
 .accepted_frames: resq 1
endstruc

; The common validator bounds table size to8*40=320 and block size to48.
SND_SUBMIT_STACK equ 408
SND_SUBMIT_TABLE equ snd_mix_block_size
SND_SUBMIT_REQUEST equ 376
SND_SUBMIT_OP equ 384

%macro SND_SUBMIT_DISJOINT 4
 cmp %1,%4
 jae %%ok
 cmp %3,%2
 jb snd_submit_bad
%%ok:
%endmacro

snd_mix_submit:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,SND_SUBMIT_STACK
 mov r12,rdi
 mov r13,rsi
 test r12,r12
 jz snd_submit_bad
 mov rbx,r12
 add rbx,snd_mix_sink_size
 jc snd_submit_bad
 cmp dword [r12+snd_mix_sink.state],0
 jne snd_submit_fault
 cmp dword [r12+snd_mix_sink.reserved],0
 jne snd_submit_unsupported
 cmp qword [r12+snd_mix_sink.handle],0
 je snd_submit_bad
 mov rdi,r13
 call snd_mix_validate
 test rax,rax
 js snd_submit_out
 lea rax,[r13+snd_mix_block_size]
 SND_SUBMIT_DISJOINT r12,rbx,r13,rax
 mov eax,[r13+snd_mix_block.rate]
 cmp eax,[r12+snd_mix_sink.rate]
 jne snd_submit_unsupported
 mov ebp,[r13+snd_mix_block.channels]
 cmp ebp,[r12+snd_mix_sink.channels]
 jne snd_submit_unsupported
 shl ebp,1
 mov rax,[r13+snd_mix_block.frames]
 mov rdx,rax
 add rax,[r12+snd_mix_sink.accepted_frames]
 jc snd_submit_limit
 imul rdx,rbp
 mov [rsp+SND_SUBMIT_REQUEST],rdx
 mov rsi,[r13+snd_mix_block.dst]
 mov rdx,rsi
 add rdx,[r13+snd_mix_block.dst_bytes]
 SND_SUBMIT_DISJOINT r12,rbx,rsi,rdx
 mov r14,[r13+snd_mix_block.streams]
 mov r15d,[r13+snd_mix_block.stream_count]
 test r15,r15
 jz .sink_spans_ok
 imul rax,r15,snd_mix_stream_size
 add rax,r14
 SND_SUBMIT_DISJOINT r12,rbx,r14,rax
 mov rdi,r14
 mov rcx,r15
.source:
 mov rdx,[rdi+snd_mix_stream.frames]
 imul rdx,rbp
 test rdx,rdx
 jz .next_source
 mov rsi,[rdi+snd_mix_stream.pcm]
 add rdx,rsi
 SND_SUBMIT_DISJOINT r12,rbx,rsi,rdx
.next_source:
 add rdi,snd_mix_stream_size
 loop .source
.sink_spans_ok:
 mov rdi,[r12+snd_mix_sink.device]
 test rdi,rdi
 jz snd_submit_unavailable
 mov rax,rdi
 add rax,dev_size
 jc snd_submit_unavailable
 cmp dword [rdi+dev.class],CLASS_SOUND
 jne snd_submit_unavailable
 cmp dword [rdi+dev.health],HEALTH_OK
 jne snd_submit_unavailable
 cmp qword [rdi+dev.info],0
 je snd_submit_unavailable
 mov rax,[rdi+dev.ops]
 test rax,rax
 jz snd_submit_unavailable
 mov rdx,rax
 add rdx,snd_ops_size
 jc snd_submit_unavailable
 mov rax,[rax+snd_ops.submit]
 test rax,rax
 jz snd_submit_unavailable
 mov [rsp+SND_SUBMIT_OP],rax
 mov rdi,rsp
 mov rsi,r13
 mov edx,snd_mix_block_size
 call memcpy
 lea rdi,[rsp+SND_SUBMIT_TABLE]
 mov rsi,r14
 imul rdx,r15,snd_mix_stream_size
 call memcpy
 lea rax,[rsp+SND_SUBMIT_TABLE]
 mov [rsp+snd_mix_block.streams],rax
 mov rdi,rsp
 call snd_mix_s16
 test rax,rax
 js snd_submit_out
 mov rdi,[r12+snd_mix_sink.device]
 mov rsi,[r12+snd_mix_sink.handle]
 mov rdx,[r13+snd_mix_block.dst]
 mov rcx,[rsp+SND_SUBMIT_REQUEST]
 call [rsp+SND_SUBMIT_OP]
 test rax,rax
 js snd_submit_refused
 cmp rax,[rsp+SND_SUBMIT_REQUEST]
 ja snd_submit_protocol
 xor edx,edx
 div rbp
 test rdx,rdx
 jnz snd_submit_protocol
 mov rbx,rax                       ; trusted whole accepted frames
 mov rdi,r14
 mov rcx,r15
 test rcx,rcx
 jz .account
.advance:
 mov rax,[rdi+snd_mix_stream.frames]
 sub rax,[rdi+snd_mix_stream.cursor]
 cmp rax,rbx
 cmova rax,rbx
 add [rdi+snd_mix_stream.cursor],rax
 add rdi,snd_mix_stream_size
 loop .advance
.account:
 add [r12+snd_mix_sink.accepted_frames],rbx
 mov rax,rbx
 jmp snd_submit_out
snd_submit_protocol:
 mov dword [r12+snd_mix_sink.state],1
snd_submit_fault:
 mov rax,-5
 jmp snd_submit_out
snd_submit_refused:
 mov rax,-6
 jmp snd_submit_out
snd_submit_unavailable:
 mov rax,-7
 jmp snd_submit_out
snd_submit_bad:
 mov rax,-1
 jmp snd_submit_out
snd_submit_unsupported:
 mov rax,-2
 jmp snd_submit_out
snd_submit_limit:
 mov rax,-4
snd_submit_out:
 add rsp,SND_SUBMIT_STACK
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%unmacro SND_SUBMIT_DISJOINT 4
