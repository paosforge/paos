;; MODULE media/pcm_decode
;; LAYER 4
;; EXPORTS media_pcm_decode
;; IMPORTS media_wav_decode, media_flac_decode
;; CAPS
;; OWNER rc-codex-av
;
; Private UNWIRED owned interleaved S16LE seam; accepted backends unchanged.
; Trusted mapped stable serialized context/full source/dst/scratch extents.
; No allocation/global/borrowed result, format sniffing, failure fallback or I/O.
; Common staging validates every result BEFORE any public dst/context write.
; SysV RBX/RBP/R12..R15/RSP preserved, volatile GPRs/flags clobbered, DF=0 ABI.

PCM_DECODE_MAX_BYTES equ 16*1024*1024
PCM_DECODE_STACK equ 136            ; backend union96 + metadata32 + alignment8
PCM_DECODE_WAV equ 1
PCM_DECODE_FLAC equ 2

struc media_pcm_context
 .format: resd 1
 .flags: resd 1                      ; reserved, must0
 .src: resq 1
 .src_bytes: resq 1
 .dst: resq 1
 .dst_bytes: resq 1
 .scratch: resq 1
 .scratch_bytes: resq 1
 .max_frames: resq 1                 ; FLAC encoded-frame quota; ignored for WAV
 .bit_budget: resq 1                 ; FLAC encoded-bit quota; ignored for WAV
 .rate: resd 1                       ; outputs72..103 only after complete success
 .channels: resd 1
 .frames: resq 1
 .bytes: resq 1
 .integrity: resq 1                  ; WAV0; FLAC1 CRC /3 CRC+nonzero MD5
endstruc
%define P(x) [rbp+media_pcm_context. %+ x]
%define B(x) [r12+media_flac_decode_ctx. %+ x]
%define V(x) [r12+media_wav_context. %+ x]
%define O(x) [r12+96+x]

; RDI=context104, RAX0 complete success. -1 invalid/signature/result, -2 format
; or unchanged WAV unsupported, -3 common capacity/WAV capacity, -4 limits.
; Backend refusals propagate exactly, including FLAC invalid/short capacity -1.
; FULL declared spans are pairwise disjoint/nonwrapping; exact adjacency valid.
; src<=16MiB; dst1..16MiB (FLAC still<=4MiB). WAV scratch>=dstcap, FLAC
; scratch>=2*dstcap+393344. On refusal context/src/dst unchanged; scratch dirty
; permitted. Stale metadata does not authorize this call. No concurrent publish.
media_pcm_decode:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,PCM_DECODE_STACK
 mov r12,rsp
 test rdi,rdi
 jz pcmp_invalid
 mov rbp,rdi
 mov rax,rdi
 add rax,media_pcm_context_size
 jc pcmp_invalid
 mov rdi,r12
 xor eax,eax
 mov ecx,16
 rep stosq
 cmp dword P(flags),0
 jne pcmp_unsupported
 mov eax,P(format)
 cmp eax,PCM_DECODE_WAV
 je .format_ok
 cmp eax,PCM_DECODE_FLAC
 jne pcmp_unsupported
.format_ok:
 mov r13,P(src)
 mov r14,P(scratch)
 mov r15,P(dst_bytes)
 test r15,r15
 jz pcmp_capacity
 cmp r15,PCM_DECODE_MAX_BYTES
 ja pcmp_limit
 mov rdx,P(src_bytes)
 cmp rdx,4
 jb pcmp_invalid
 cmp rdx,PCM_DECODE_MAX_BYTES
 ja pcmp_limit
 mov rsi,r13
 call pcmp_span
 mov rsi,P(dst)
 mov rdx,r15
 call pcmp_span
 mov rsi,r14
 mov rdx,P(scratch_bytes)
 call pcmp_span
 mov rsi,r13
 mov rdx,P(src_bytes)
 mov r8,P(dst)
 mov r9,r15
 call pcmp_pair
 mov r8,r14
 mov r9,P(scratch_bytes)
 call pcmp_pair
 mov rsi,P(dst)
 mov rdx,r15
 call pcmp_pair
 mov rax,r15
 cmp dword P(format),PCM_DECODE_WAV
 je .work_bound
 add rax,r15
 add rax,FLACD_WORK_BYTES
.work_bound:
 cmp P(scratch_bytes),rax
 jb pcmp_capacity
 cmp dword P(format),PCM_DECODE_WAV
 je .wav
.flac:
 cmp dword [r13],'fLaC'
 jne pcmp_invalid
 mov B(src),r13
 mov rax,P(src_bytes)
 mov B(src_bytes),rax
 mov B(dst),r14
 mov B(dst_bytes),r15
 lea rax,[r14+r15]
 mov B(scratch),rax
 mov rax,P(scratch_bytes)
 sub rax,r15
 mov B(scratch_bytes),rax
 mov rax,P(max_frames)
 mov B(max_frames),rax
 mov rax,P(bit_budget)
 mov B(bit_budget),rax
 mov rdi,r12
 call media_flac_decode
 test rax,rax
 jnz pcmp_exit                      ; no fallback or stale result publication
 mov eax,B(rate)
 mov O(0),eax
 mov eax,B(channels)
 mov O(4),eax
 mov rax,B(frames)
 mov O(8),rax
 mov rax,B(bytes)
 mov O(16),rax
 mov rax,B(md5_verified)
 cmp rax,1
 ja pcmp_invalid
 lea rax,[rax*2+1]
 mov O(24),rax
 jmp .validate_result
.wav:
 cmp qword P(src_bytes),12
 jb pcmp_invalid
 cmp dword [r13],'RIFF'
 jne pcmp_invalid
 cmp dword [r13+8],'WAVE'
 jne pcmp_invalid
 mov V(src),r13
 mov rax,P(src_bytes)
 mov V(src_bytes),rax
 mov V(dst),r14
 mov V(dst_bytes),r15
 mov rdi,r12
 call media_wav_decode
 test rax,rax
 jnz pcmp_exit
 mov eax,V(rate)
 cmp eax,8000
 jb pcmp_invalid
 mov O(0),eax
 mov eax,V(channels)
 mov O(4),eax
 mov rax,V(frames)
 mov O(8),rax
 mov rax,V(pcm_bytes)
 mov O(16),rax
 mov qword O(24),0
.validate_result:
 cmp dword O(0),1
 jb pcmp_invalid
 cmp dword O(0),192000
 ja pcmp_invalid
 mov eax,O(4)
 cmp eax,1
 jb pcmp_invalid
 cmp eax,2
 ja pcmp_invalid
 mov rcx,O(8)
 test rcx,rcx
 jz pcmp_invalid
 mul rcx                            ; u64 frames*channels, fail on full product
 test rdx,rdx
 jnz pcmp_invalid
 add rax,rax
 jc pcmp_invalid
 cmp rax,O(16)
 jne pcmp_invalid
 cmp rax,r15
 ja pcmp_capacity
 ; Private complete staging is now validated. Only this block publishes.
 mov rdi,P(dst)
 mov rsi,r14
 mov rcx,O(16)
 rep movsb
 mov rax,O(0)
 mov P(rate),rax                     ; rate+channels pair
 mov rax,O(8)
 mov P(frames),rax
 mov rax,O(16)
 mov P(bytes),rax
 mov rax,O(24)
 mov P(integrity),rax
 xor eax,eax
pcmp_exit:
 mov rsp,r12
 add rsp,PCM_DECODE_STACK
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
pcmp_invalid:
 mov rax,-1
 jmp pcmp_exit
pcmp_unsupported:
 mov rax,-2
 jmp pcmp_exit
pcmp_capacity:
 mov rax,-3
 jmp pcmp_exit
pcmp_limit:
 mov rax,-4
 jmp pcmp_exit

; Internal admission helpers never write a public context/buffer on refusal.
pcmp_span:
 test rsi,rsi
 jz pcmp_invalid
 test rdx,rdx
 jz pcmp_invalid
 mov rax,rsi
 add rax,rdx
 jc pcmp_invalid
 lea rcx,[rbp+media_pcm_context_size]
 cmp rsi,rcx
 jae .ok
 cmp rbp,rax
 jb pcmp_invalid
.ok: ret
pcmp_pair:
 lea rax,[r8+r9]
 cmp rsi,rax
 jae .ok
 lea rax,[rsi+rdx]
 cmp r8,rax
 jb pcmp_invalid
.ok: ret
%undef P
%undef B
%undef V
%undef O
