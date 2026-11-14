;; MODULE snd/resample
;; LAYER 4
;; EXPORTS snd_resample_s16
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Caller-owned S16 mono/stereo linear sample-rate conversion from native MP3
; rates 8000/11025/12000/16000/22050/24000/32000/44100/48000 and PCM96000
; to44100/48000/96000. No new MP3 decoding rate is implied.
; Classic audio_hda_play_wav has no resampler; this RC seam is
; new integer DSP. Exact rational phase avoids block-boundary clock drift.
; This interpolation primitive has no anti-alias filter; it is not a claim
; of final resampling quality or device playback qualification.
;
; snd_resample_s16(RDI=context80) -> RAX=produced frames (0..request), or
; -1 invalid span/alias/state, -2 unsupported metadata, -3 output capacity,
; -4 work limit. Caller guarantees stable mapped serialized full spans.
; Context/source/output are pairwise disjoint. On refusal all unchanged.
; On success only cursor/phase/produced and exact produced PCM are changed.
; cursor is a source-frame index, phase a numerator with denominator out_rate.
; At each output time interpolate a + floor((b-a)*phase/out_rate), then
; advance by in_rate/out_rate exactly. Last-frame interpolation holds the
; endpoint; EOF is cursor=src_frames,phase=0 and repeats produce zero frames.
; The whole source stays available between calls. An initial cursor/phase
; of zero produces ceil(src_frames*out_rate/in_rate) output frames at EOF.
; No allocation, shared state, FP, device I/O or input-buffer replacement.
; SysV RBX/RBP/R12-R15/RSP preserved; volatile GPRs/flags clobbered, DF untouched.

SND_RESAMPLE_MAX_BYTES equ 16777216
SND_RESAMPLE_MAX_FRAMES equ 1024

struc snd_resample_context
 .src: resq 1
 .src_frames: resq 1
 .dst: resq 1
 .dst_bytes: resq 1
 .in_rate: resd 1
 .out_rate: resd 1
 .channels: resd 1
 .reserved: resd 1
 .cursor: resq 1
 .phase: resq 1
 .request: resq 1
 .produced: resq 1
endstruc

snd_resample_s16:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 mov r12,rdi
 test r12,r12
 jz snd_resample_bad
 mov rax,r12
 add rax,snd_resample_context_size
 jc snd_resample_bad
 mov [rsp],rax                     ; context end
 cmp dword [r12+snd_resample_context.reserved],0
 jne snd_resample_unsupported
 mov eax,[r12+snd_resample_context.in_rate]
 cmp eax,8000
 je .input_rate_ok
 cmp eax,11025
 je .input_rate_ok
 cmp eax,12000
 je .input_rate_ok
 cmp eax,16000
 je .input_rate_ok
 cmp eax,22050
 je .input_rate_ok
 cmp eax,24000
 je .input_rate_ok
 cmp eax,32000
 je .input_rate_ok
 cmp eax,44100
 je .input_rate_ok
 cmp eax,48000
 je .input_rate_ok
 cmp eax,96000
 jne snd_resample_unsupported
.input_rate_ok:
 mov r10d,[r12+snd_resample_context.out_rate]
 cmp r10d,44100
 je .output_rate_ok
 cmp r10d,48000
 je .output_rate_ok
 cmp r10d,96000
 jne snd_resample_unsupported
.output_rate_ok:
 mov r8d,[r12+snd_resample_context.channels]
 lea eax,[r8-1]
 cmp eax,1
 ja snd_resample_unsupported
 shl r8d,1                         ; bytes per source/output frame
 mov r15,[r12+snd_resample_context.cursor]
 mov rbp,[r12+snd_resample_context.phase]
 cmp rbp,r10
 jae snd_resample_bad
 mov rax,[r12+snd_resample_context.src_frames]
 cmp r15,rax
 ja snd_resample_bad
 jne .state_ok
 test rbp,rbp
 jnz snd_resample_bad
.state_ok:
 cmp rax,SND_RESAMPLE_MAX_BYTES/2
 ja snd_resample_limit
 imul rax,r8
 cmp rax,SND_RESAMPLE_MAX_BYTES
 ja snd_resample_limit
 mov [rsp+8],rax                   ; full source bytes
 mov rax,[r12+snd_resample_context.request]
 test rax,rax
 jz snd_resample_bad
 cmp rax,SND_RESAMPLE_MAX_FRAMES
 ja snd_resample_limit
 imul rax,r8
 mov rdx,[r12+snd_resample_context.dst_bytes]
 cmp rdx,rax
 jb snd_resample_capacity
 cmp rdx,SND_RESAMPLE_MAX_BYTES
 ja snd_resample_limit
 mov r14,[r12+snd_resample_context.dst]
 test r14,r14
 jz snd_resample_bad
 mov rax,r14
 add rax,rdx
 jc snd_resample_bad
 mov [rsp+16],rax                  ; full output capacity end
 cmp r14,[rsp]
 jae .dst_context_ok
 cmp r12,rax
 jb snd_resample_bad
.dst_context_ok:
 mov r13,[r12+snd_resample_context.src]
 cmp qword [rsp+8],0
 je .validated                     ; empty input needs no mapping
 test r13,r13
 jz snd_resample_bad
 mov rdx,r13
 add rdx,[rsp+8]
 jc snd_resample_bad
 cmp r13,[rsp]
 jae .src_context_ok
 cmp r12,rdx
 jb snd_resample_bad
.src_context_ok:
 cmp r13,[rsp+16]
 jae .validated
 cmp r14,rdx
 jb snd_resample_bad
.validated:
 xor ebx,ebx                       ; produced frames this block
.frame:
 cmp rbx,[r12+snd_resample_context.request]
 jae .publish
 cmp r15,[r12+snd_resample_context.src_frames]
 jae .publish
 mov rax,r15
 imul rax,r8
 lea rsi,[r13+rax]
 lea r9,[rsi+r8]
 lea rax,[r15+1]
 cmp rax,[r12+snd_resample_context.src_frames]
 cmovae r9,rsi                     ; last sample is held, never overread
 mov rax,rbx
 imul rax,r8
 lea rdi,[r14+rax]
 xor r11d,r11d
.channel:
 movsx eax,word [r9+r11*2]
 movsx edx,word [rsi+r11*2]
 sub eax,edx
 cdqe
 imul rax,rbp
 cqo
 idiv r10                         ; exact signed interpolation fraction
 test rdx,rdx
 jns .floor_ok
 dec rax                          ; IDIV truncates; negative remainder floors
.floor_ok:
 movsx edx,word [rsi+r11*2]
 add eax,edx                      ; convex interpolation stays in S16 range
 mov [rdi+r11*2],ax
 inc r11d
 cmp r11d,[r12+snd_resample_context.channels]
 jb .channel
 mov eax,[r12+snd_resample_context.in_rate]
 add rax,rbp
 xor edx,edx
 div r10
 add r15,rax
 mov rbp,rdx
 mov rax,[r12+snd_resample_context.src_frames]
 cmp r15,rax
 jb .next_frame
 mov r15,rax
 xor ebp,ebp                      ; canonical EOF state, including downsample
.next_frame:
 inc rbx
 jmp .frame
.publish:
 mov [r12+snd_resample_context.cursor],r15
 mov [r12+snd_resample_context.phase],rbp
 mov [r12+snd_resample_context.produced],rbx
 mov rax,rbx
 jmp snd_resample_out
snd_resample_bad:
 mov rax,-1
 jmp snd_resample_out
snd_resample_unsupported:
 mov rax,-2
 jmp snd_resample_out
snd_resample_capacity:
 mov rax,-3
 jmp snd_resample_out
snd_resample_limit:
 mov rax,-4
snd_resample_out:
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
