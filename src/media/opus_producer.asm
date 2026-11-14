;; MODULE media/opus_producer
;; LAYER 4
;; EXPORTS media_opus_producer_begin, media_opus_producer_step, media_opus_producer_cancel
;; IMPORTS media_ogg_opus_parse, media_opus_frame_decode, media_opus_silk_decode
;; CAPS
;; OWNER rc-codex-av
;
; Private bounded Ogg/Opus file producer; native caller: opus_playback/OPUSPLAY.
; Context192; workspace869120. Standalone callers retain the same custody ABI.
; Each entry RDI=ctx,RSI=expected generation,RDX=expected epoch. 0 progress,
; 1 READY/current custody receipt,2 cancelled; -1 invalid,-2 phase/identity/
; unsupported,-3 capacity,-4 quota,-5 actual native decoder refusal.
; All negative calls preserve context/source/public PCM/public decoder state;
; workspace may be dirty: cancel/discard after ANY negative, never reuse it.
; PCM/state remain private until the final frame and complete source validation.
; One native frame per step. Begin scans<=307200 bytes; each live call compares
; that many original bytes, then bounded decode/copy. No allocator/I/O/globals.
; Five full truthful mapped stable lower-canonical disjoint spans, serialized;
; context/work/state align8,PCM align2. Caller supplies>=96KiB private stack.
; Phase alone is not a receipt: only a current return1 admits a PCM handoff.
; State must remain private under this producer's custody until handoff.
; Output S16LE48k original Head channels; input rate retained as metadata.
; Gain polynomial/rounding adapted from pinned Xiph Opus1.5.2 mathops.h and
; opus_decoder.c. Copyright/conditions: LICENSES/XIPH_OPUS_OGG.txt.
; /* Copyright (c) 2010 Xiph.Org Foundation, Skype Limited
;    Written by Jean-Marc Valin and Koen Vos */
; /*
;    Redistribution and use in source and binary forms, with or without
;    modification, are permitted provided that the following conditions
;    are met:
;
;    - Redistributions of source code must retain the above copyright
;    notice, this list of conditions and the following disclaimer.
;
;    - Redistributions in binary form must reproduce the above copyright
;    notice, this list of conditions and the following disclaimer in the
;    documentation and/or other materials provided with the distribution.
;
;    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;    ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
;    OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
;    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
;    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
; */
;
; /* Copyright (c) 2002-2008 Jean-Marc Valin
;    Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
; /**
;    @file mathops.h
;    @brief Various math functions
; */
; /*
;    Redistribution and use in source and binary forms, with or without
;    modification, are permitted provided that the following conditions
;    are met:
;
;    - Redistributions of source code must retain the above copyright
;    notice, this list of conditions and the following disclaimer.
;
;    - Redistributions in binary form must reproduce the above copyright
;    notice, this list of conditions and the following disclaimer in the
;    documentation and/or other materials provided with the distribution.
;
;    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;    ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
;    OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
;    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
;    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
; */

struc media_opus_producer
 .version: resd 1
 .phase: resd 1                    ; EMPTY0 DECODING1 READY2 CANCELLED3
 .generation: resq 1
 .epoch: resq 1
 .src: resq 1
 .src_bytes: resq 1
 .pcm: resq 1
 .capacity: resq 1
 .workspace: resq 1
 .workspace_bytes: resq 1
 .state: resq 1
 .state_bytes: resq 1
 .frames: resq 1
 .bytes: resq 1
 .rate: resd 1
 .channels: resd 1
 .input_rate: resd 1
 .serial: resd 1
 .preskip: resq 1
 .initial_granule: resq 1
 .final_granule: resq 1
 .decoded: resq 1
 .integrity: resq 1
 .reserved: resq 4
endstruc
OPW_SOURCE equ 256
OPW_RESULT equ 307456
OPW_SCRATCH equ 323968
OPW_STATE equ 647680
OPW_FRAMEPCM equ 665472
OPW_PCM equ 676992
OPW_CONFIG equ 868992
OPW_BYTES equ 869120
%define OP(x) [rbx+media_opus_producer. %+ x]
ogpr_span:
 test rdi,rdi
 jz .bad
 test rsi,rsi
 jz .bad
 test rdi,rdx
 jnz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret
media_opus_producer_begin:
 xor eax,eax
 jmp ogpr_enter
media_opus_producer_step:
 mov eax,1
 jmp ogpr_enter
media_opus_producer_cancel:
 mov eax,2
ogpr_enter:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,184
 mov rbp,rsp
 mov [rbp],rax
 mov [rbp+8],rsi
 mov [rbp+16],rdx
 mov rbx,rdi
 mov esi,192
 mov edx,7
 lea r8,[rbp+32]
 call ogpr_span
 test rax,rax
 jnz .bad
 cmp dword OP(version),1
 jne .bad
 cmp dword OP(phase),3
 ja .bad
 mov rax,OP(generation)
 test rax,rax
 jz .bad
 cmp rax,[rbp+8]
 jne .identity
 mov rax,OP(epoch)
 test rax,rax
 jz .bad
 cmp rax,[rbp+16]
 jne .identity
 mov rax,[rbx+160]
 or rax,[rbx+168]
 or rax,[rbx+176]
 or rax,[rbx+184]
 jnz .bad
 mov r13,OP(src)
 mov rdi,r13
 mov rsi,OP(src_bytes)
 cmp rsi,27
 jb .bad
 cmp rsi,307200
 ja .quota
 xor edx,edx
 lea r8,[rbp+48]
 call ogpr_span
 test rax,rax
 jnz .bad
 mov r14,OP(pcm)
 mov rdi,r14
 mov rsi,OP(capacity)
 cmp rsi,2
 jb .capacity
 cmp rsi,192000
 ja .quota
 mov edx,1
 lea r8,[rbp+64]
 call ogpr_span
 test rax,rax
 jnz .bad
 mov r12,OP(workspace)
 mov rdi,r12
 mov rsi,OP(workspace_bytes)
 cmp rsi,OPW_BYTES
 jb .capacity
 cmp rsi,1048576
 ja .quota
 mov edx,7
 lea r8,[rbp+80]
 call ogpr_span
 test rax,rax
 jnz .bad
 mov r15,OP(state)
 mov rdi,r15
 mov rsi,OP(state_bytes)
 cmp rsi,9120
 jb .capacity
 cmp rsi,65536
 ja .quota
 mov edx,7
 lea r8,[rbp+96]
 call ogpr_span
 test rax,rax
 jnz .bad
 xor ecx,ecx
.pair_a:
 lea edx,[ecx+16]
.pair_b:
 mov rax,[rbp+32+rcx]
 cmp rax,[rbp+40+rdx]
 jae .pair_next
 mov rax,[rbp+32+rdx]
 cmp rax,[rbp+40+rcx]
 jb .bad
.pair_next:
 add edx,16
 cmp edx,80
 jb .pair_b
 add ecx,16
 cmp ecx,64
 jb .pair_a
 cmp qword [rbp],0
 je .begin
 cmp dword OP(phase),0
 je .identity
 cmp dword [r12+192],0x3150474f
 jne .identity
 ; Compare the complete bound context and exact original encoded bytes, not
 ; only a mutable pointer, cheap token, CRC or a prefix of either span.
 mov rdi,rbx
 mov rsi,r12
 mov ecx,192
 repe cmpsb
 jne .identity
 mov rdi,r13
 lea rsi,[r12+OPW_SOURCE]
 mov rcx,OP(src_bytes)
 repe cmpsb
 jne .identity
 cmp qword [rbp],2
 je .cancel
 cmp dword OP(phase),3
 je .cancelled
 cmp dword OP(phase),2
 je .already_ready
 jmp .step
.begin:
 cmp dword OP(phase),0
 jne .identity
 lea rdi,[rbx+88]
 mov ecx,13
.fresh:
 cmp qword [rdi],0
 jne .bad
 add rdi,8
 loop .fresh
 mov rsi,r13
 lea rdi,[r12+OPW_SOURCE]
 mov rcx,OP(src_bytes)
 rep movsb
 ; The complete demuxer and its packet parser see the actual immutable file.
 lea rdi,[r12+OPW_CONFIG]
 lea rax,[r12+OPW_SOURCE]
 stosq
 mov rax,OP(src_bytes)
 stosq
 lea rax,[r12+OPW_RESULT]
 stosq
 mov eax,16512
 stosq
 lea rax,[r12+OPW_SCRATCH]
 stosq
 mov eax,323712
 stosq
 xor eax,eax
 stosq
 stosq
 lea rdi,[r12+OPW_CONFIG]
 call media_ogg_opus_parse
 test rax,rax
 jnz .done
 mov rax,[r12+OPW_RESULT+8]
 imul rax,8672
 add rax,448
 cmp qword [r12+OPW_RESULT+104],0
 je .min_state
 mov eax,9120
.min_state:
 cmp rax,OP(state_bytes)
 ja .capacity
 mov rax,[r12+OPW_RESULT+88]
 imul rax,[r12+OPW_RESULT+8]
 shl rax,1
 cmp rax,OP(capacity)
 ja .capacity
 ; Fresh complete native state; the decoder's histories are not reset per
 ; packet and coded-channel changes do not change original output channels.
 lea rdi,[r12+OPW_STATE]
 xor eax,eax
 mov ecx,17792/8
 rep stosq
 cmp qword [r12+OPW_RESULT+104],0
 jne .fresh_ready            ; SILK uses all-zero fresh state9120
 mov qword [r12+OPW_STATE],0x31465243
 mov rax,[r12+OPW_RESULT+8]
 mov [r12+OPW_STATE+384],rax
 lea rdi,[r12+OPW_STATE+100]
 mov ax,-28672
 mov ecx,84
 rep stosw
.fresh_ready:
 mov qword [r12+200],0          ; packet index
 mov qword [r12+208],0          ; selected normal-frame index
 mov qword [r12+216],0          ; all decoded samples per output channel
 mov qword [r12+224],0          ; privately copied bytes
 mov dword [r12+192],0x3150474f
 mov dword OP(phase),1
 call .snapshot
 xor eax,eax
 jmp .done
.step:
 mov rax,[r12+200]
 cmp rax,[r12+OPW_RESULT+56]
 jae .identity
 shl rax,5
 lea rdx,[r12+OPW_RESULT+128+rax]
 mov [rbp+112],rdx
 lea rdi,[r12+OPW_CONFIG]
 mov rax,[rdx]
 lea rax,[r12+OPW_SCRATCH+rax]
 stosq
 mov rax,[rdx+8]
 stosq
 lea rax,[r12+OPW_STATE]
 stosq
 mov rax,[r12+OPW_RESULT+8]
 imul rax,8672
 add rax,448
 cmp qword [r12+OPW_RESULT+104],0
 je .frame_state
 mov eax,9120
.frame_state:
 stosq
 lea rax,[r12+OPW_FRAMEPCM]
 stosq
 mov eax,11520
 stosq
 mov rax,[r12+OPW_RESULT+8]
 stosq
 mov eax,1
 stosq
 xor eax,eax
 stosq
 mov rax,[r12+208]
 stosq
 lea rdi,[r12+OPW_CONFIG]
 cmp qword [r12+OPW_RESULT+104],0
 jne .silk_decode
 call media_opus_frame_decode
 jmp .decoded_frame
.silk_decode:
 call media_opus_silk_decode
.decoded_frame:
 test rax,rax
 js .decode_error
 mov [rbp+120],rax
 ; Apply exactly the output gain to private samples, leaving decode state
 ; independent of Head gain and all pre-skip/end-trim samples decoded.
 mov esi,eax
 imul esi,[r12+OPW_RESULT+8]
 mov rdx,[r12+OPW_RESULT+32]
 lea rdi,[r12+OPW_FRAMEPCM]
 call ogpr_gain
 mov rax,[r12+216]
 mov rcx,rax
 add rcx,[rbp+120]
 mov [rbp+128],rcx
 mov rdx,[r12+OPW_RESULT+16]    ; keep [pre-skip, finalGP-initialGP)
 cmp rax,rdx
 cmovb rax,rdx
 mov rdx,[r12+OPW_RESULT+80]
 sub rdx,[r12+OPW_RESULT+72]
 cmp rcx,rdx
 cmova rcx,rdx
 cmp rcx,rax
 jbe .no_copy
 sub rcx,rax
 sub rax,[r12+216]
 imul rax,[r12+OPW_RESULT+8]
 shl rax,1
 lea rsi,[r12+OPW_FRAMEPCM+rax]
 imul rcx,[r12+OPW_RESULT+8]
 shl rcx,1
 mov rax,[r12+224]
 add [r12+224],rcx
 lea rdi,[r12+OPW_PCM+rax]
 rep movsb
.no_copy:
 mov rax,[rbp+128]
 mov [r12+216],rax
 inc qword [r12+208]
 mov rdx,[rbp+112]
 mov rax,[r12+208]
 cmp rax,[rdx+24]
 jb .progress
 mov qword [r12+208],0
 inc qword [r12+200]
 mov rax,[r12+200]
 cmp rax,[r12+OPW_RESULT+56]
 jb .progress
 ; Only this final, fully validated step publishes PCM/state and READY.
 mov rdi,r14
 lea rsi,[r12+OPW_PCM]
 mov rcx,[r12+224]
 rep movsb
 mov rdi,r15
 lea rsi,[r12+OPW_STATE]
 mov rax,[r12+OPW_RESULT+8]
 imul rax,8672
 add rax,448
 cmp qword [r12+OPW_RESULT+104],0
 je .publish_state
 mov eax,9120
.publish_state:
 mov rcx,rax
 rep movsb
 mov rax,[r12+OPW_RESULT+88]
 mov OP(frames),rax
 mov rax,[r12+224]
 mov OP(bytes),rax
 mov dword OP(rate),48000
 mov eax,[r12+OPW_RESULT+8]
 mov OP(channels),eax
 mov eax,[r12+OPW_RESULT+24]
 mov OP(input_rate),eax
 mov eax,[r12+OPW_RESULT+40]
 mov OP(serial),eax
 mov rax,[r12+OPW_RESULT+16]
 mov OP(preskip),rax
 mov rax,[r12+OPW_RESULT+72]
 mov OP(initial_granule),rax
 mov rax,[r12+OPW_RESULT+80]
 mov OP(final_granule),rax
 mov rax,[r12+216]
 mov OP(decoded),rax
 mov qword OP(integrity),1
 mov dword OP(phase),2
 call .snapshot
.already_ready:
 mov eax,1
 jmp .done
.progress:
 xor eax,eax
 jmp .done
.cancel:
 cmp dword OP(phase),2
 je .identity                   ; READY belongs to the caller's handoff
 mov dword OP(phase),3
 call .snapshot
.cancelled:
 mov eax,2
 jmp .done
.snapshot:
 mov rdi,r12
 mov rsi,rbx
 mov ecx,192/8
 rep movsq
 ret
.bad:
 mov rax,-1
 jmp .done
.identity:
 mov rax,-2
 jmp .done
.capacity:
 mov rax,-3
 jmp .done
.quota:
 mov rax,-4
 jmp .done
.decode_error:
 mov rax,-5
.done:
 mov rsp,rbp
 add rsp,184
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 cld
 ret

; EDI private PCM*,ESI scalar count,EDX signed Head Q7.8 dB. Exact fixed Opus
; mathops celt_exp2 and opus_decoder MULT16_32_P16/SATURATE(x,32767).
ogpr_gain:
 test edx,edx
 jz .done
 mov r8,rdi
 mov r9d,esi
 imul eax,edx,21771
 add eax,16384
 sar eax,15
 mov r10d,eax
 sar r10d,10
 cmp r10d,14
 jg .large
 cmp r10d,-15
 jl .zero
 and eax,1023
 shl eax,4
 mov edi,eax
 imul eax,edi,10204
 sar eax,15
 add eax,14819
 imul eax,edi
 sar eax,15
 add eax,22804
 imul eax,edi
 sar eax,15
 add eax,16383
 lea ecx,[r10+2]
 test ecx,ecx
 js .right
 shl eax,cl
 jmp .gain
.right:
 neg ecx
 sar eax,cl
 jmp .gain
.large:
 mov eax,0x7f000000
 jmp .gain
.zero:
 xor eax,eax
.gain:
 mov r10d,eax
.samples:
 test r9d,r9d
 jz .done
 movsx rax,word [r8]
 imul rax,r10
 add rax,32768
 sar rax,16
 mov edx,32767
 cmp rax,rdx
 cmovg rax,rdx
 mov edx,-32767
 cmp eax,edx
 cmovl eax,edx
 mov [r8],ax
 add r8,2
 dec r9d
 jmp .samples
.done:
 ret
