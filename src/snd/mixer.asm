;; MODULE snd/mixer
;; LAYER 4
;; EXPORTS snd_mix_s16, snd_mix_validate
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Native, backend-independent PCM block mixer. Classic PaOS paos.asm
; audio_3d tone scaling (signed multiply/arithmetic shift) and
; dsp_biquad_process S16 clamp are reused; Q15 and multi-stream accumulation
; are RC additions. No Classic global state, device I/O or allocation.
;
; Trusted stable mapped caller-owned context, stream table, source and output
; spans, serialized for this call. Source PCM may be shared by streams, but
; must be disjoint from context/table/output. Context/table/output are pairwise
; disjoint. No input or output changes on refusal. A successful call writes
; exactly frames*channels S16 samples and advances each cursor by the lesser
; of requested and remaining frames, including muted streams (time advances).
; Exhausted streams contribute silence. Gain is 0..32768 inclusive (unity).
; Each signed product is floor-shifted by 15, then summed and clamped ONCE.
; All streams must match the block's rate and channels; no resampling here.
; SysV preserved GPRs/RSP; no floating point, shared state or locks. RAX=0
; success, -1 invalid span/alias/cursor, -2 unsupported metadata, -3 capacity,
; -4 work limit. Mappings/ownership are caller guarantees, not authenticated.
; snd_mix_validate(RDI=block) returns the same admission status without writing
; PCM or cursors. It shares the complete validator with snd_mix_s16.

SND_MIX_MAX_STREAMS equ 8
SND_MIX_MAX_FRAMES equ 1024
SND_MIX_MAX_BYTES equ 16777216
SND_MIX_MUTED equ 1

struc snd_mix_stream
 .pcm: resq 1
 .frames: resq 1
 .cursor: resq 1
 .gain: resd 1
 .flags: resd 1
 .rate: resd 1
 .channels: resd 1
endstruc

struc snd_mix_block
 .dst: resq 1
 .dst_bytes: resq 1
 .streams: resq 1
 .stream_count: resd 1
 .channels: resd 1
 .frames: resq 1
 .rate: resd 1
 .reserved: resd 1
endstruc

snd_mix_s16:
 xor r9d,r9d
 jmp snd_mix_enter
snd_mix_validate:
 mov r9d,1
snd_mix_enter:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 mov r12,rdi
 test r12,r12
 jz snd_mix_bad
 mov rax,r12
 add rax,snd_mix_block_size
 jc snd_mix_bad
 mov [rsp],rax                     ; context end
 cmp dword [r12+snd_mix_block.reserved],0
 jne snd_mix_unsupported
 mov eax,[r12+snd_mix_block.rate]
 cmp eax,44100
 je .rate_ok
 cmp eax,48000
 je .rate_ok
 cmp eax,96000
 jne snd_mix_unsupported
.rate_ok:
 mov ebp,[r12+snd_mix_block.channels]
 lea eax,[rbp-1]
 cmp eax,1
 ja snd_mix_unsupported
 shl ebp,1                         ; bytes per frame
 mov rax,[r12+snd_mix_block.frames]
 test rax,rax
 jz snd_mix_bad
 cmp rax,SND_MIX_MAX_FRAMES
 ja snd_mix_limit
 imul rax,rbp
 mov rdx,[r12+snd_mix_block.dst_bytes]
 cmp rdx,rax
 jb snd_mix_capacity
 cmp rdx,SND_MIX_MAX_BYTES
 ja snd_mix_limit
 mov r15,[r12+snd_mix_block.dst]
 test r15,r15
 jz snd_mix_bad
 mov rax,r15
 add rax,rdx
 jc snd_mix_bad
 mov [rsp+8],rax                   ; full output capacity end
 cmp r15,[rsp]
 jae .dst_context_ok
 cmp r12,rax
 jb snd_mix_bad
.dst_context_ok:
 mov eax,[r12+snd_mix_block.stream_count]
 cmp eax,SND_MIX_MAX_STREAMS
 ja snd_mix_limit
 mov r13,[r12+snd_mix_block.streams]
 mov r14,r13
 test eax,eax
 jz .validated                     ; zero streams generates silence
 test r13,r13
 jz snd_mix_bad
 imul eax,eax,snd_mix_stream_size
 add r14,rax
 jc snd_mix_bad
 cmp r13,[rsp]
 jae .table_context_ok
 cmp r12,r14
 jb snd_mix_bad
.table_context_ok:
 cmp r13,[rsp+8]
 jae .table_dst_ok
 cmp r15,r14
 jb snd_mix_bad
.table_dst_ok:
 mov rbx,r13
.validate_stream:
 mov eax,[rbx+snd_mix_stream.rate]
 cmp eax,[r12+snd_mix_block.rate]
 jne snd_mix_unsupported
 mov eax,[rbx+snd_mix_stream.channels]
 cmp eax,[r12+snd_mix_block.channels]
 jne snd_mix_unsupported
 cmp dword [rbx+snd_mix_stream.gain],32768
 ja snd_mix_unsupported
 cmp dword [rbx+snd_mix_stream.flags],SND_MIX_MUTED
 ja snd_mix_unsupported
 mov rax,[rbx+snd_mix_stream.frames]
 cmp [rbx+snd_mix_stream.cursor],rax
 ja snd_mix_bad
 ; Bound the product before multiplying so source spans cannot wrap.
 cmp rax,SND_MIX_MAX_BYTES/2
 ja snd_mix_limit
 imul rax,rbp
 cmp rax,SND_MIX_MAX_BYTES
 ja snd_mix_limit
 test rax,rax
 jz .stream_ok                     ; empty PCM needs no mapping
 mov rsi,[rbx+snd_mix_stream.pcm]
 test rsi,rsi
 jz snd_mix_bad
 mov rdx,rsi
 add rdx,rax
 jc snd_mix_bad
 cmp rsi,[rsp]
 jae .source_context_ok
 cmp r12,rdx
 jb snd_mix_bad
.source_context_ok:
 cmp rsi,r14
 jae .source_table_ok
 cmp r13,rdx
 jb snd_mix_bad
.source_table_ok:
 cmp rsi,[rsp+8]
 jae .stream_ok
 cmp r15,rdx
 jb snd_mix_bad
.stream_ok:
 add rbx,snd_mix_stream_size
 cmp rbx,r14
 jb .validate_stream
.validated:
 test r9d,r9d
 jnz .done
 mov rax,[r12+snd_mix_block.frames]
 mov ecx,[r12+snd_mix_block.channels]
 imul rax,rcx
 mov [rsp+16],rax                  ; total output samples, <=2048
 xor r8d,r8d
.sample:
 xor r10d,r10d                     ; wide sum; clamp after ALL streams
 mov rbx,r13
.stream:
 cmp rbx,r14
 jae .clamp
 test dword [rbx+snd_mix_stream.flags],SND_MIX_MUTED
 jnz .next_stream
 mov rax,[rbx+snd_mix_stream.frames]
 sub rax,[rbx+snd_mix_stream.cursor]
 imul rax,rcx
 cmp r8,rax
 jae .next_stream
 mov rax,[rbx+snd_mix_stream.cursor]
 imul rax,rcx
 add rax,r8
 mov rsi,[rbx+snd_mix_stream.pcm]
 movsx rax,word [rsi+rax*2]
 mov edx,[rbx+snd_mix_stream.gain]
 imul rax,rdx
 sar rax,15
 add r10,rax
.next_stream:
 add rbx,snd_mix_stream_size
 jmp .stream
.clamp:
 cmp r10,32767
 jle .low
 mov r10d,32767
.low:
 cmp r10,-32768
 jge .store
 mov r10,-32768
.store:
 mov [r15+r8*2],r10w
 inc r8
 cmp r8,[rsp+16]
 jb .sample
 mov rbx,r13
.advance:
 cmp rbx,r14
 jae .done
 mov rax,[rbx+snd_mix_stream.frames]
 sub rax,[rbx+snd_mix_stream.cursor]
 mov rdx,[r12+snd_mix_block.frames]
 cmp rax,rdx
 cmova rax,rdx
 add [rbx+snd_mix_stream.cursor],rax
 add rbx,snd_mix_stream_size
 jmp .advance
.done:
 xor eax,eax
 jmp snd_mix_out
snd_mix_bad:
 mov rax,-1
 jmp snd_mix_out
snd_mix_unsupported:
 mov rax,-2
 jmp snd_mix_out
snd_mix_capacity:
 mov rax,-3
 jmp snd_mix_out
snd_mix_limit:
 mov rax,-4
snd_mix_out:
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
